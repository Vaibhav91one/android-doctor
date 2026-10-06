//! Ramdisks: format detection, decompression and `cpio` (newc) extraction.
//!
//! The cpio "newc" format is the Linux initramfs one (documented in the kernel's
//! `Documentation/driver-api/early-userspace/buffer-format.rst`); the compression formats are
//! gzip, bzip2, xz, zstd and the two lz4 variants Android uses. Written from those descriptions
//! and checked against `bsdtar` and the standard compression tools.
use crate::detect::refuse_blocking_file;
use crate::treeout::{Sink, clean_path, prepare_staging, publish};
use anyhow::{Context, Result, anyhow, bail, ensure};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::path::Path;

const CPIO_HEADER_LEN: usize = 110;
const MAX_NAME: u32 = 4096;
const MAX_ENTRIES: usize = 1_000_000;
/// Decompressed bytes accepted from one ramdisk, so a small hostile file cannot fill the disk.
pub const MAX_DECOMPRESSED: u64 = 2 << 30;
/// Property files are small; larger ones are not read for properties.
pub(crate) const MAX_PROP_FILE: u64 = 1 << 20;
const LEGACY_LZ4_MAGIC: u32 = 0x184C_2102;
const LEGACY_LZ4_BLOCK: usize = 8 << 20;
const SYMLINK_DEPTH: usize = 8;
/// Properties worth reporting when auditing a device's debug and ADB exposure.
pub(crate) const REPORTED_PROPS: [&str; 6] = [
    "ro.secure",
    "ro.adb.secure",
    "ro.debuggable",
    "persist.sys.usb.config",
    "service.adb.root",
    "persist.service.adb.enable",
];

#[derive(Debug, PartialEq, Clone, Copy)]
pub enum Compression {
    None,
    Gzip,
    Bzip2,
    Xz,
    Zstd,
    Lz4Frame,
    Lz4Legacy,
}

impl Compression {
    pub fn id(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::Gzip => "gzip",
            Self::Bzip2 => "bzip2",
            Self::Xz => "xz",
            Self::Zstd => "zstd",
            Self::Lz4Frame => "lz4",
            Self::Lz4Legacy => "lz4-legacy",
        }
    }
}

/// The compression of a ramdisk from its first bytes (`None` is a plain cpio archive).
pub fn compression_of(head: &[u8]) -> Option<Compression> {
    let at0 = |m: &[u8]| head.starts_with(m);
    Some(if at0(&[0x1F, 0x8B, 0x08]) {
        Compression::Gzip
    } else if at0(b"BZh") && head.get(3).is_some_and(|b| (b'1'..=b'9').contains(b)) {
        Compression::Bzip2
    } else if at0(&[0xFD, b'7', b'z', b'X', b'Z', 0x00]) {
        Compression::Xz
    } else if at0(&[0x28, 0xB5, 0x2F, 0xFD]) {
        Compression::Zstd
    } else if at0(&[0x04, 0x22, 0x4D, 0x18]) {
        Compression::Lz4Frame
    } else if at0(&LEGACY_LZ4_MAGIC.to_le_bytes()) {
        Compression::Lz4Legacy
    } else if at0(b"070701") || at0(b"070702") {
        Compression::None
    } else {
        return None;
    })
}

/// Shannon entropy in bits per byte.
pub fn entropy(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }
    let mut counts = [0u64; 256];
    for &b in data {
        counts[b as usize] += 1;
    }
    let n = data.len() as f64;
    counts
        .iter()
        .filter(|&&c| c > 0)
        .map(|&c| c as f64 / n)
        .map(|p| -p * p.log2())
        .sum()
}

/// Entropy above which data with no known magic is called "high entropy" (encrypted or in an
/// unknown compressed format). Real ciphertext and good compression sit near 7.99.
const HIGH_ENTROPY: f64 = 7.9;
/// Fewer bytes than this say nothing about entropy.
const MIN_ENTROPY_SAMPLE: usize = 4096;

/// What a boot-image section looks like, from its first bytes: `(id, description)`.
pub fn classify_section(head: &[u8]) -> (&'static str, String) {
    if let Some(c) = compression_of(head) {
        return match c {
            Compression::None => ("cpio", "cpio archive (uncompressed)".into()),
            other => (other.id(), format!("{} compressed data", other.id())),
        };
    }
    if head.starts_with(&[0xD0, 0x0D, 0xFE, 0xED]) {
        return ("dtb", "device tree blob".into());
    }
    if head.len() >= 0x3C && &head[0x38..0x3C] == b"ARMd" {
        return ("arm64-image", "ARM64 kernel image".into());
    }
    if head.starts_with(b"@AML") {
        return (
            "aml-container",
            "Amlogic container (@AML); secure-boot images are encrypted".into(),
        );
    }
    if head.len() >= MIN_ENTROPY_SAMPLE {
        let h = entropy(head);
        if h >= HIGH_ENTROPY {
            return (
                "unknown-high-entropy",
                format!(
                    "no known format; entropy {h:.2} bits/byte, so encrypted or compressed in an unknown way"
                ),
            );
        }
    }
    ("unknown", "no known format".into())
}

/// Reader for the legacy lz4 format (`lz4 -l`): magic, then blocks of `u32 size` + data.
struct LegacyLz4<R: Read> {
    inner: R,
    buf: Vec<u8>,
    pos: usize,
    started: bool,
}

impl<R: Read> Read for LegacyLz4<R> {
    fn read(&mut self, out: &mut [u8]) -> std::io::Result<usize> {
        while self.pos >= self.buf.len() {
            let mut word = [0u8; 4];
            let mut got = 0;
            while got < 4 {
                let n = self.inner.read(&mut word[got..])?;
                if n == 0 {
                    break;
                }
                got += n;
            }
            if got == 0 {
                return Ok(0);
            }
            if got < 4 {
                return Err(std::io::Error::other(
                    "lz4: file ends inside a block header",
                ));
            }
            let value = u32::from_le_bytes(word);
            if value == LEGACY_LZ4_MAGIC {
                self.started = true;
                continue; // magic at the start, or between concatenated streams
            }
            if !self.started {
                return Err(std::io::Error::other("lz4: bad magic"));
            }
            let size = value as usize;
            if size == 0 || size > LEGACY_LZ4_BLOCK + LEGACY_LZ4_BLOCK / 255 + 16 {
                return Err(std::io::Error::other(format!(
                    "lz4: block of {size} bytes is not valid"
                )));
            }
            let mut block = vec![0u8; size];
            self.inner
                .read_exact(&mut block)
                .map_err(|_| std::io::Error::other("lz4: file ends inside a block"))?;
            let mut plain = vec![0u8; LEGACY_LZ4_BLOCK];
            let n = lz4_flex::block::decompress_into(&block, &mut plain)
                .map_err(|e| std::io::Error::other(format!("lz4: {e}")))?;
            plain.truncate(n);
            self.buf = plain;
            self.pos = 0;
        }
        let n = out.len().min(self.buf.len() - self.pos);
        out[..n].copy_from_slice(&self.buf[self.pos..self.pos + n]);
        self.pos += n;
        Ok(n)
    }
}

/// What an image holds when it is gzip-wrapped, with `true`; any other input comes back
/// unchanged with `false`. Some vendors ship `dt.img` gzip-compressed (#114). Bounded, so a
/// gzip bomb cannot exhaust memory.
pub(crate) fn unwrap_gzip(data: Vec<u8>) -> Result<(Vec<u8>, bool)> {
    const CAP: u64 = 256 << 20;
    if !data.starts_with(&[0x1F, 0x8B, 0x08]) {
        return Ok((data, false));
    }
    let mut out = Vec::new();
    flate2::read::MultiGzDecoder::new(data.as_slice())
        .take(CAP + 1)
        .read_to_end(&mut out)
        .context("decompressing the gzip-wrapped image")?;
    ensure!(
        out.len() as u64 <= CAP,
        "gzip-wrapped image expands past {} MiB",
        CAP >> 20
    );
    Ok((out, true))
}

/// Wrap `r` in the decoder for `c`.
pub(crate) fn decoder<'a, R: Read + 'a>(c: Compression, r: R) -> Result<Box<dyn Read + 'a>> {
    Ok(match c {
        Compression::None => Box::new(r),
        Compression::Gzip => Box::new(flate2::read::MultiGzDecoder::new(r)),
        Compression::Bzip2 => Box::new(bzip2::read::MultiBzDecoder::new(r)),
        Compression::Xz => Box::new(lzma_rust2::XzReader::new(r, true)),
        Compression::Zstd => {
            Box::new(ruzstd::decoding::StreamingDecoder::new(r).map_err(|e| anyhow!("zstd: {e}"))?)
        }
        Compression::Lz4Frame => Box::new(lz4_flex::frame::FrameDecoder::new(r)),
        Compression::Lz4Legacy => Box::new(LegacyLz4 {
            inner: r,
            buf: Vec::new(),
            pos: 0,
            started: false,
        }),
    })
}

#[derive(Debug, PartialEq, Clone, Copy)]
pub enum Kind {
    File,
    Dir,
    Symlink,
    CharDevice,
    BlockDevice,
    Fifo,
    Socket,
}

impl Kind {
    fn from_mode(mode: u32) -> Option<Kind> {
        Some(match mode & 0o170000 {
            0o100000 => Kind::File,
            0o040000 => Kind::Dir,
            0o120000 => Kind::Symlink,
            0o020000 => Kind::CharDevice,
            0o060000 => Kind::BlockDevice,
            0o010000 => Kind::Fifo,
            0o140000 => Kind::Socket,
            _ => return None,
        })
    }

    fn name(self) -> &'static str {
        match self {
            Kind::File => "file",
            Kind::Dir => "dir",
            Kind::Symlink => "symlink",
            Kind::CharDevice => "char",
            Kind::BlockDevice => "block",
            Kind::Fifo => "fifo",
            Kind::Socket => "socket",
        }
    }
}

#[derive(Debug, Clone)]
pub struct Entry {
    pub path: String,
    pub kind: Kind,
    pub mode: u32,
    pub uid: u32,
    pub gid: u32,
    pub size: u64,
    pub mtime: u32,
    pub link: Option<String>,
    pub sha256: Option<String>,
    inode: (u32, u32, u32),
}

/// What a hardlink group (entries sharing an inode) is known to hold so far.
#[derive(Default)]
struct LinkGroup {
    /// The entry that carried the data: its path, size, sha256 and (small files) text.
    data: Option<LinkData>,
    /// Entries seen before the data: `(index in entries, mode)`.
    pending: Vec<(usize, u32)>,
}

struct LinkData {
    path: String,
    size: u64,
    sha: String,
    text: Option<String>,
}

/// SHA-256 of no bytes: what an empty file hashes to.
const EMPTY_SHA256: &str = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

/// Everything learned from reading one cpio archive.
#[derive(Debug)]
pub struct Report {
    pub compression: Compression,
    pub entries: Vec<Entry>,
    /// Reported property -> `[(file, value)]`, for every property file found.
    pub properties: BTreeMap<String, Vec<(String, String)>>,
}

fn hex8(b: &[u8]) -> Result<u32> {
    let s = std::str::from_utf8(b).map_err(|_| anyhow!("cpio header is not ASCII hex"))?;
    ensure!(
        s.bytes().all(|c| c.is_ascii_hexdigit()),
        "cpio header field {s:?} is not hex"
    );
    Ok(u32::from_str_radix(s, 16)?)
}

fn skip<R: Read>(r: &mut R, n: u64) -> Result<()> {
    let copied = std::io::copy(&mut r.by_ref().take(n), &mut std::io::sink())?;
    ensure!(copied == n, "archive ends early");
    Ok(())
}

fn pad4(n: u64) -> u64 {
    (4 - n % 4) % 4
}

fn parse_props(text: &str, file: &str, out: &mut BTreeMap<String, Vec<(String, String)>>) {
    for line in text.lines() {
        let Some((k, v)) = line.split_once('=') else {
            continue;
        };
        let k = k.trim();
        if REPORTED_PROPS.contains(&k) {
            let list = out.entry(k.to_string()).or_default();
            let item = (file.to_string(), v.trim().to_string());
            if !list.contains(&item) {
                list.push(item);
            }
        }
    }
}

pub(crate) fn is_prop_file(path: &str) -> bool {
    let base = path.rsplit('/').next().unwrap_or(path);
    base == "prop.default" || base.ends_with(".prop")
}

/// Resolve `path` through symlinks recorded in the archive (up to `SYMLINK_DEPTH`).
fn resolve(path: &str, links: &HashMap<String, String>) -> Option<String> {
    let mut cur = path.to_string();
    for _ in 0..SYMLINK_DEPTH {
        let Some(target) = links.get(&cur) else {
            return Some(cur);
        };
        let joined = if target.starts_with('/') {
            target.clone()
        } else {
            let dir = cur.rsplit_once('/').map_or("", |(d, _)| d);
            format!("{dir}/{target}")
        };
        let mut stack: Vec<&str> = Vec::new();
        for part in joined.split('/') {
            match part {
                "" | "." => {}
                ".." => {
                    stack.pop()?;
                }
                p => stack.push(p),
            }
        }
        cur = stack.join("/");
    }
    None
}

/// Read one or more concatenated cpio archives from `r`. With `out` set, regular files and
/// directories are written under it (symlinks, devices, fifos and sockets are never created,
/// only recorded).
fn read_cpio<R: Read>(mut r: R, compression: Compression, out: Option<&Path>) -> Result<Report> {
    let mut entries: Vec<Entry> = Vec::new();
    let mut links: HashMap<String, String> = HashMap::new();
    let mut hard: HashMap<(u32, u32, u32), LinkGroup> = HashMap::new();
    let mut prop_texts: Vec<(String, String)> = Vec::new();
    let mut sink = out.map(Sink::new);
    let mut header = [0u8; CPIO_HEADER_LEN];
    loop {
        // between archives there can be zero padding; end of input here is a clean stop
        let mut first = [0u8; 1];
        loop {
            if r.read(&mut first)? == 0 {
                // names of a hardlink group that never got any data are empty files
                for group in hard.values() {
                    for &(idx, mode) in &group.pending {
                        entries[idx].sha256 = Some(EMPTY_SHA256.to_string());
                        if let Some(s) = sink.as_mut() {
                            s.empty_file(&entries[idx].path, mode)?;
                        }
                    }
                }
                return finish(compression, entries, links, prop_texts);
            }
            if first[0] != 0 {
                break;
            }
        }
        header[0] = first[0];
        r.read_exact(&mut header[1..])
            .context("cpio ends inside an entry header")?;
        ensure!(
            &header[..6] == b"070701" || &header[..6] == b"070702",
            "not a cpio newc archive (bad entry magic {:?})",
            String::from_utf8_lossy(&header[..6])
        );
        let f = |i: usize| hex8(&header[6 + 8 * i..6 + 8 * i + 8]);
        let (ino, mode, uid, gid, nlink, mtime, size) =
            (f(0)?, f(1)?, f(2)?, f(3)?, f(4)?, f(5)?, f(6)? as u64);
        let (dev_major, dev_minor, namesize) = (f(7)?, f(8)?, f(11)?);
        ensure!(
            (1..=MAX_NAME).contains(&namesize),
            "entry name of {namesize} bytes is not valid"
        );
        let mut name = vec![0u8; namesize as usize];
        r.read_exact(&mut name).context("cpio ends inside a name")?;
        skip(&mut r, pad4(CPIO_HEADER_LEN as u64 + namesize as u64))?;
        ensure!(name.last() == Some(&0), "entry name is not NUL-terminated");
        name.pop();
        let raw = String::from_utf8_lossy(&name).into_owned();
        if raw == "TRAILER!!!" {
            skip(&mut r, size + pad4(size))?;
            continue;
        }
        ensure!(
            entries.len() < MAX_ENTRIES,
            "more than {MAX_ENTRIES} entries"
        );
        let kind = Kind::from_mode(mode)
            .with_context(|| format!("{raw:?}: unknown file type in mode {mode:#o}"))?;
        let path = clean_path(&raw).with_context(|| format!("entry {raw:?}"))?;
        let mut e = Entry {
            path,
            kind,
            mode,
            uid,
            gid,
            size,
            mtime,
            link: None,
            sha256: None,
            inode: (dev_major, dev_minor, ino),
        };
        let mut data = (&mut r).take(size);
        match kind {
            Kind::Symlink => {
                ensure!(
                    size <= MAX_NAME as u64,
                    "symlink target of {size} bytes is not valid"
                );
                let mut t = Vec::new();
                data.read_to_end(&mut t)?;
                let target = String::from_utf8_lossy(&t).into_owned();
                links.insert(e.path.clone(), target.clone());
                if let Some(s) = sink.as_mut() {
                    s.note_symlink(&e.path)?;
                }
                e.link = Some(target);
            }
            Kind::File => {
                let linked = nlink > 1;
                let idx = entries.len();
                if linked && size == 0 {
                    // a name of a hardlink group: it holds the group's data, which may come later
                    let group = hard.entry(e.inode).or_default();
                    match &group.data {
                        Some(d) => {
                            e.size = d.size;
                            e.sha256 = Some(d.sha.clone());
                            if is_prop_file(&e.path)
                                && let Some(t) = &d.text
                            {
                                prop_texts.push((e.path.clone(), t.clone()));
                            }
                            if let Some(s) = sink.as_mut() {
                                s.copy_file(&d.path, &e.path, e.mode)?;
                            }
                        }
                        None => group.pending.push((idx, e.mode)),
                    }
                } else {
                    let keep = size <= MAX_PROP_FILE && (is_prop_file(&e.path) || linked);
                    let mut hasher = Sha256::new();
                    let mut buf = Vec::new();
                    let mut tee = Tee {
                        inner: &mut data,
                        hasher: &mut hasher,
                        keep: keep.then_some(&mut buf),
                    };
                    match sink.as_mut() {
                        Some(s) => s.write_file(&e.path, e.mode, &mut tee)?,
                        None => {
                            std::io::copy(&mut tee, &mut std::io::sink())?;
                        }
                    }
                    let sha: String = hasher
                        .finalize()
                        .iter()
                        .map(|b| format!("{b:02x}"))
                        .collect();
                    e.sha256 = Some(sha.clone());
                    let text = (keep && !buf.is_empty())
                        .then(|| String::from_utf8_lossy(&buf).into_owned());
                    if is_prop_file(&e.path)
                        && let Some(t) = &text
                    {
                        prop_texts.push((e.path.clone(), t.clone()));
                    }
                    if linked {
                        let group = hard.entry(e.inode).or_default();
                        ensure!(
                            group.data.is_none(),
                            "{} and {} are hardlinks of one inode and both carry data",
                            group.data.as_ref().map_or("", |d| d.path.as_str()),
                            e.path
                        );
                        for (i, mode) in std::mem::take(&mut group.pending) {
                            entries[i].size = size;
                            entries[i].sha256 = Some(sha.clone());
                            if is_prop_file(&entries[i].path)
                                && let Some(t) = &text
                            {
                                prop_texts.push((entries[i].path.clone(), t.clone()));
                            }
                            if let Some(s) = sink.as_mut() {
                                s.copy_file(&e.path, &entries[i].path, mode)?;
                            }
                        }
                        group.data = Some(LinkData {
                            path: e.path.clone(),
                            size,
                            sha,
                            text,
                        });
                    }
                }
            }
            Kind::Dir => {
                std::io::copy(&mut data, &mut std::io::sink())?;
                if !e.path.is_empty()
                    && let Some(s) = sink.as_mut()
                {
                    s.make_parents(&e.path)?;
                    s.add_dir(&e.path)?;
                }
            }
            _ => {
                std::io::copy(&mut data, &mut std::io::sink())?;
            }
        }
        ensure!(
            data.limit() == 0,
            "{}: archive ends inside the file data",
            e.path
        );
        skip(&mut r, pad4(size))?;
        if !e.path.is_empty() {
            entries.push(e);
        }
    }
}

struct Tee<'a, R: Read> {
    inner: &'a mut R,
    hasher: &'a mut Sha256,
    keep: Option<&'a mut Vec<u8>>,
}

impl<R: Read> Read for Tee<'_, R> {
    fn read(&mut self, b: &mut [u8]) -> std::io::Result<usize> {
        let n = self.inner.read(b)?;
        self.hasher.update(&b[..n]);
        if let Some(k) = self.keep.as_deref_mut() {
            k.extend_from_slice(&b[..n]);
        }
        Ok(n)
    }
}

fn finish(
    compression: Compression,
    entries: Vec<Entry>,
    links: HashMap<String, String>,
    prop_texts: Vec<(String, String)>,
) -> Result<Report> {
    let texts: HashMap<&str, &str> = prop_texts
        .iter()
        .map(|(p, t)| (p.as_str(), t.as_str()))
        .collect();
    let mut properties = BTreeMap::new();
    let mut done = BTreeSet::new();
    let candidates = entries
        .iter()
        .filter(|e| matches!(e.kind, Kind::File | Kind::Symlink) && is_prop_file(&e.path));
    for e in candidates {
        let Some(real) = resolve(&e.path, &links) else {
            continue;
        };
        if !done.insert(real.clone()) {
            continue;
        }
        if let Some(text) = texts.get(real.as_str()) {
            parse_props(text, &real, &mut properties);
        }
    }
    Ok(Report {
        compression,
        entries,
        properties,
    })
}

/// Passes data through but fails, with a clear message, once more than `left` bytes were read.
struct Capped<R: Read> {
    inner: R,
    left: u64,
    cap: u64,
}

impl<R: Read> Read for Capped<R> {
    fn read(&mut self, b: &mut [u8]) -> std::io::Result<usize> {
        let n = self.inner.read(b)?;
        if n as u64 > self.left {
            return Err(std::io::Error::other(format!(
                "the decompressed ramdisk is larger than the {}-byte limit",
                self.cap
            )));
        }
        self.left -= n as u64;
        Ok(n)
    }
}

/// Read a ramdisk (possibly compressed) from `source`, optionally extracting it into `out`.
pub fn read_ramdisk<R: Read>(source: R, out: Option<&Path>) -> Result<Report> {
    read_ramdisk_capped(source, out, MAX_DECOMPRESSED)
}

fn read_ramdisk_capped<R: Read>(mut source: R, out: Option<&Path>, cap: u64) -> Result<Report> {
    let mut head = vec![0u8; 65536];
    let mut got = 0;
    while got < head.len() {
        let n = source.read(&mut head[got..])?;
        if n == 0 {
            break;
        }
        got += n;
    }
    head.truncate(got);
    let Some(c) = compression_of(&head) else {
        let (id, why) = classify_section(&head);
        bail!("the ramdisk is not a compressed or plain cpio archive: {why} [{id}]");
    };
    let chained = std::io::Cursor::new(head).chain(source);
    let plain = Capped {
        inner: decoder(c, chained)?,
        left: cap,
        cap,
    };
    read_cpio(plain, c, out).with_context(|| format!("reading the {} ramdisk", c.id()))
}

impl Report {
    pub fn to_json(&self) -> Value {
        let files = self.entries.iter().filter(|e| e.kind == Kind::File).count();
        let entries: Vec<Value> = self
            .entries
            .iter()
            .map(|e| {
                json!({
                    "path": e.path,
                    "type": e.kind.name(),
                    "mode": e.mode & 0o7777,
                    "uid": e.uid,
                    "gid": e.gid,
                    "size": e.size,
                    "mtime": e.mtime,
                    "link": e.link,
                    "sha256": e.sha256,
                })
            })
            .collect();
        let mut properties = serde_json::Map::new();
        for (key, found) in &self.properties {
            let list: Vec<Value> = found
                .iter()
                .map(|(file, value)| json!({"file": file, "value": value}))
                .collect();
            properties.insert(key.clone(), Value::Array(list));
        }
        json!({
            "compression": self.compression.id(),
            "entries": entries,
            "summary": {"entries": self.entries.len(), "files": files},
            "properties": properties,
        })
    }

    pub fn to_text(&self, list: bool) -> String {
        let count = |k: Kind| self.entries.iter().filter(|e| e.kind == k).count();
        let mut lines = vec![
            format!("compression  {}", self.compression.id()),
            format!(
                "entries      {} ({} files, {} directories, {} symlinks)",
                self.entries.len(),
                count(Kind::File),
                count(Kind::Dir),
                count(Kind::Symlink)
            ),
        ];
        if self.properties.is_empty() {
            lines.push(
                "properties   none of the reported ADB/debug properties were found".to_string(),
            );
        } else {
            lines.push("properties:".to_string());
            for (k, v) in &self.properties {
                for (file, val) in v {
                    lines.push(format!("  {k}={val}  ({file})"));
                }
            }
        }
        if list {
            lines.push("entries:".to_string());
            for e in &self.entries {
                let to = e
                    .link
                    .as_ref()
                    .map_or(String::new(), |l| format!(" -> {l}"));
                lines.push(format!(
                    "  {:<7} {:04o} {:>5} {:>5} {:>10}  {}{to}",
                    e.kind.name(),
                    e.mode & 0o7777,
                    e.uid,
                    e.gid,
                    e.size,
                    e.path
                ));
            }
        }
        lines.join("\n")
    }
}

/// Where the ramdisk bytes of `input` live: a boot or vendor boot image gives one stream per
/// ramdisk, any other file is itself a ramdisk.
/// A ramdisk to read: its name and, for a boot image, its `(offset, size)` in the file.
type Located = (String, Option<(u64, u64)>);

fn ramdisks_of(input: &Path) -> Result<Vec<Located>> {
    let mut head = Vec::new();
    File::open(input)
        .with_context(|| format!("opening {}", input.display()))?
        .take(8)
        .read_to_end(&mut head)?;
    if head.starts_with(b"ANDROID!") || head.starts_with(b"VNDRBOOT") {
        let image = crate::bootimg::read(input)?;
        let found: Vec<_> = image
            .sections
            .iter()
            .filter(|s| s.name == "ramdisk" || s.name.starts_with("vendor_ramdisk"))
            .map(|s| (s.name.clone(), Some((s.offset, s.size))))
            .collect();
        ensure!(!found.is_empty(), "the image has no ramdisk");
        return Ok(found);
    }
    Ok(vec![("ramdisk".to_string(), None)])
}

/// The result for one ramdisk of an input.
pub struct Found {
    pub name: String,
    pub report: Result<Report>,
}

/// Read every ramdisk of `input`. With `out`, each is extracted under `out/<name>/files` with a
/// `manifest.json` beside it; the whole directory appears at once, or not at all.
pub fn read_input(input: &Path, out: Option<&Path>) -> Result<Vec<Found>> {
    refuse_blocking_file(input)?;
    ensure!(!input.is_dir(), "{} is a directory", input.display());
    let parts = ramdisks_of(input)?;
    let staging = match out {
        Some(dir) => Some(prepare_staging(dir)?),
        None => None,
    };
    let mut found = Vec::new();
    let mut all_ok = true;
    for (name, span) in parts {
        let mut f = File::open(input)?;
        let source: Box<dyn Read> = match span {
            Some((offset, size)) => {
                f.seek(SeekFrom::Start(offset))?;
                Box::new(f.take(size))
            }
            None => Box::new(f),
        };
        let dest = staging.as_ref().map(|s| s.join(&name).join("files"));
        if let Some(d) = &dest {
            std::fs::create_dir_all(d)?;
        }
        let report = read_ramdisk(source, dest.as_deref());
        if report.is_err() {
            all_ok = false;
        }
        if let (Ok(r), Some(s)) = (&report, &staging) {
            let m = serde_json::to_string_pretty(&r.to_json())?;
            std::fs::write(s.join(&name).join("manifest.json"), m)?;
        }
        found.push(Found { name, report });
    }
    if let (Some(staging), Some(out)) = (staging, out) {
        if all_ok {
            publish(&staging, out)?;
        } else {
            let _ = std::fs::remove_dir_all(&staging);
        }
    }
    Ok(found)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::treeout::staging_path;
    use std::io::Write;
    use std::path::PathBuf;

    /// One entry for the in-test cpio builder.
    #[derive(Clone)]
    struct E {
        name: String,
        mode: u32,
        uid: u32,
        gid: u32,
        data: Vec<u8>,
        ino: u32,
        nlink: u32,
    }

    fn file(name: &str, data: &[u8]) -> E {
        E {
            name: name.into(),
            mode: 0o100644,
            uid: 0,
            gid: 0,
            data: data.to_vec(),
            ino: 0,
            nlink: 1,
        }
    }

    fn folder(name: &str) -> E {
        E {
            name: name.into(),
            mode: 0o040755,
            uid: 0,
            gid: 0,
            data: vec![],
            ino: 0,
            nlink: 2,
        }
    }

    fn link(name: &str, target: &str) -> E {
        E {
            name: name.into(),
            mode: 0o120777,
            uid: 0,
            gid: 0,
            data: target.as_bytes().to_vec(),
            ino: 0,
            nlink: 1,
        }
    }

    fn hex(v: u32) -> String {
        format!("{v:08x}")
    }

    fn entry_bytes(e: &E, ino: u32) -> Vec<u8> {
        let mut b = Vec::new();
        b.extend(b"070701");
        for v in [
            if e.ino != 0 { e.ino } else { ino },
            e.mode,
            e.uid,
            e.gid,
            e.nlink,
            1_600_000_000,
            e.data.len() as u32,
            0,
            1,
            0,
            0,
            e.name.len() as u32 + 1,
            0,
        ] {
            b.extend(hex(v).bytes());
        }
        b.extend(e.name.as_bytes());
        b.push(0);
        while b.len() % 4 != 0 {
            b.push(0);
        }
        b.extend(&e.data);
        while b.len() % 4 != 0 {
            b.push(0);
        }
        b
    }

    fn cpio(entries: &[E]) -> Vec<u8> {
        let mut out = Vec::new();
        for (i, e) in entries.iter().enumerate() {
            out.extend(entry_bytes(e, i as u32 + 1));
        }
        out.extend(entry_bytes(
            &E {
                name: "TRAILER!!!".into(),
                mode: 0,
                uid: 0,
                gid: 0,
                data: vec![],
                ino: 0,
                nlink: 1,
            },
            0,
        ));
        out
    }

    fn compress(c: Compression, data: &[u8]) -> Vec<u8> {
        match c {
            Compression::None => data.to_vec(),
            Compression::Gzip => {
                let mut e =
                    flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
                e.write_all(data).unwrap();
                e.finish().unwrap()
            }
            Compression::Bzip2 => {
                let mut e = bzip2::write::BzEncoder::new(Vec::new(), bzip2::Compression::default());
                e.write_all(data).unwrap();
                e.finish().unwrap()
            }
            Compression::Xz => {
                let mut w =
                    lzma_rust2::XzWriter::new(Vec::new(), lzma_rust2::XzOptions::with_preset(1))
                        .unwrap();
                w.write_all(data).unwrap();
                w.finish().unwrap()
            }
            Compression::Zstd => {
                ruzstd::encoding::compress_to_vec(data, ruzstd::encoding::CompressionLevel::Fastest)
            }
            Compression::Lz4Frame => {
                let mut e = lz4_flex::frame::FrameEncoder::new(Vec::new());
                e.write_all(data).unwrap();
                e.finish().unwrap()
            }
            Compression::Lz4Legacy => {
                let mut out = LEGACY_LZ4_MAGIC.to_le_bytes().to_vec();
                for chunk in data.chunks(1 << 16) {
                    let block = lz4_flex::block::compress(chunk);
                    out.extend((block.len() as u32).to_le_bytes());
                    out.extend(block);
                }
                out
            }
        }
    }

    const ALL: [Compression; 7] = [
        Compression::None,
        Compression::Gzip,
        Compression::Bzip2,
        Compression::Xz,
        Compression::Zstd,
        Compression::Lz4Frame,
        Compression::Lz4Legacy,
    ];

    fn data(n: usize, seed: u8) -> Vec<u8> {
        (0..n)
            .map(|i| seed.wrapping_add((i * 7 % 251) as u8))
            .collect()
    }

    fn sample() -> Vec<E> {
        let mut v = vec![folder("etc"), folder("sbin")];
        // sizes 0..=9 and names of several lengths exercise every padding case
        for n in 0..=9 {
            v.push(file(&format!("f{}", "x".repeat(n)), &data(n, n as u8)));
        }
        v.push(file("etc/big", &data(200_000, 9)));
        v.push(file("sbin/init", b"#!/bin/sh\n"));
        v.push(link("init", "/sbin/init"));
        v.push(E {
            name: "dev-null".into(),
            mode: 0o020666,
            uid: 0,
            gid: 0,
            data: vec![],
            ino: 0,
            nlink: 1,
        });
        v.push(E {
            name: "pipe".into(),
            mode: 0o010600,
            uid: 0,
            gid: 0,
            data: vec![],
            ino: 0,
            nlink: 1,
        });
        v
    }

    fn read(bytes: &[u8]) -> Result<Report> {
        read_ramdisk(bytes, None)
    }

    fn by_path<'a>(r: &'a Report, p: &str) -> &'a Entry {
        r.entries
            .iter()
            .find(|e| e.path == p)
            .unwrap_or_else(|| panic!("no {p}"))
    }

    fn sha(b: &[u8]) -> String {
        Sha256::digest(b)
            .iter()
            .map(|x| format!("{x:02x}"))
            .collect()
    }

    #[test]
    fn every_compression_gives_the_same_entries() {
        let archive = cpio(&sample());
        for c in ALL {
            let r = read(&compress(c, &archive)).unwrap_or_else(|e| panic!("{}: {e:#}", c.id()));
            assert_eq!(r.compression, c, "{}", c.id());
            assert_eq!(r.entries.len(), 2 + 10 + 1 + 1 + 1 + 2, "{}", c.id());
            assert_eq!(by_path(&r, "etc/big").size, 200_000);
            assert_eq!(
                by_path(&r, "etc/big").sha256.as_deref(),
                Some(sha(&data(200_000, 9)).as_str()),
                "{}",
                c.id()
            );
            assert_eq!(by_path(&r, "init").link.as_deref(), Some("/sbin/init"));
            assert_eq!(by_path(&r, "init").kind, Kind::Symlink);
            assert_eq!(by_path(&r, "dev-null").kind, Kind::CharDevice);
            assert_eq!(by_path(&r, "pipe").kind, Kind::Fifo);
            assert_eq!(by_path(&r, "etc").kind, Kind::Dir);
        }
    }

    #[test]
    fn padding_is_right_for_every_name_and_data_length() {
        let mut entries = Vec::new();
        for n in 0..=12usize {
            for m in 0..=9usize {
                entries.push(file(
                    &format!("{}{}", "n".repeat(n + 1), m),
                    &data(m, (n * 10 + m) as u8),
                ));
            }
        }
        let r = read(&cpio(&entries)).unwrap();
        assert_eq!(r.entries.len(), entries.len());
        for e in &entries {
            let got = by_path(&r, &e.name);
            assert_eq!(got.size, e.data.len() as u64, "{}", e.name);
            assert_eq!(
                got.sha256.as_deref(),
                Some(sha(&e.data).as_str()),
                "{}",
                e.name
            );
        }
    }

    #[test]
    fn compression_is_detected_from_the_magic_bytes() {
        for c in ALL {
            let packed = compress(c, &cpio(&[file("a", b"x")]));
            assert_eq!(compression_of(&packed), Some(c), "{}", c.id());
        }
        assert_eq!(compression_of(b"BZh0"), None);
        assert_eq!(compression_of(b"BZhx"), None);
        assert_eq!(
            compression_of(b"070702 crc archive"),
            Some(Compression::None)
        );
        assert_eq!(compression_of(b"07070"), None);
        assert_eq!(compression_of(&[]), None);
        assert_eq!(compression_of(&[0x1F, 0x8B, 0x07]), None);
    }

    #[test]
    fn section_classification_covers_every_format() {
        let id = |b: &[u8]| classify_section(b).0;
        assert_eq!(id(&[0x1F, 0x8B, 0x08, 0]), "gzip");
        assert_eq!(id(b"070701"), "cpio");
        assert_eq!(id(&[0xD0, 0x0D, 0xFE, 0xED, 0, 0]), "dtb");
        assert_eq!(id(b"@AML\x04\0\0\0"), "aml-container");
        let mut arm = vec![0u8; 0x40];
        arm[0x38..0x3C].copy_from_slice(b"ARMd");
        assert_eq!(id(&arm), "arm64-image");
        assert_eq!(id(&[0u8; 8192]), "unknown");
        assert_eq!(id(&[1, 2, 3]), "unknown");
        // random-looking data of a useful size is "high entropy"; the same bytes cut short are not judged
        let noise: Vec<u8> = (0..8192u32)
            .map(|i| (i.wrapping_mul(2654435761) >> 13) as u8)
            .collect();
        assert_eq!(id(&noise), "unknown-high-entropy");
        assert_eq!(id(&noise[..4000]), "unknown");
        let (_, why) = classify_section(&noise);
        assert!(
            why.contains("entropy") && why.contains("encrypted"),
            "{why}"
        );
    }

    #[test]
    fn entropy_values() {
        assert_eq!(entropy(&[]), 0.0);
        assert_eq!(entropy(&[7u8; 100]), 0.0);
        let uniform: Vec<u8> = (0..=255u8).collect();
        assert!((entropy(&uniform) - 8.0).abs() < 1e-9);
        assert!((entropy(&[0u8, 1].repeat(50)) - 1.0).abs() < 1e-9);
    }

    #[test]
    fn an_unrecognised_ramdisk_gets_an_honest_explanation() {
        let noise: Vec<u8> = (0..70_000u32)
            .map(|i| (i.wrapping_mul(2654435761) >> 13) as u8)
            .collect();
        let e = format!("{:#}", read(&noise).unwrap_err());
        assert!(
            e.contains("not a compressed or plain cpio")
                && e.contains("entropy")
                && e.contains("encrypted"),
            "{e}"
        );
        let e = format!("{:#}", read(&[0u8; 100]).unwrap_err());
        assert!(e.contains("no known format"), "{e}");
        assert!(read(&[]).is_err());
    }

    #[test]
    fn properties_are_found_through_symlinks_and_deduplicated() {
        let props = b"ro.secure=1\nro.adb.secure=0\n ro.debuggable = 1 \nro.build.id=XYZ\n# comment\npersist.sys.usb.config=adb\nnot a property\nservice.adb.root=1\n";
        let archive = cpio(&[
            file("prop.default", props),
            link("default.prop", "prop.default"),
            folder("system"),
            folder("system/etc"),
            link("system/etc/prop.default", "/prop.default"),
        ]);
        let r = read(&archive).unwrap();
        let get = |k: &str| {
            r.properties.get(k).map(|v| {
                v.iter()
                    .map(|(f, val)| format!("{val}@{f}"))
                    .collect::<Vec<_>>()
            })
        };
        assert_eq!(
            get("ro.secure"),
            Some(vec!["1@prop.default".into()]),
            "three names, one file, one report"
        );
        assert_eq!(get("ro.adb.secure"), Some(vec!["0@prop.default".into()]));
        assert_eq!(
            get("ro.debuggable"),
            Some(vec!["1@prop.default".into()]),
            "spaces around key and value are trimmed"
        );
        assert_eq!(
            get("persist.sys.usb.config"),
            Some(vec!["adb@prop.default".into()])
        );
        assert_eq!(get("service.adb.root"), Some(vec!["1@prop.default".into()]));
        assert!(
            !r.properties.contains_key("ro.build.id"),
            "only the audit properties are reported"
        );
    }

    #[test]
    fn different_property_files_are_all_reported() {
        let archive = cpio(&[
            file("default.prop", b"ro.debuggable=0\n"),
            folder("vendor"),
            file("vendor/build.prop", b"ro.debuggable=1\nro.secure=1\n"),
            file("x.prop", b"ro.debuggable=1\n"),
            file("notprops.txt", b"ro.debuggable=1\n"),
        ]);
        let r = read(&archive).unwrap();
        let v: Vec<_> = r.properties["ro.debuggable"]
            .iter()
            .map(|(f, v)| format!("{f}={v}"))
            .collect();
        assert_eq!(
            v,
            ["default.prop=0", "vendor/build.prop=1", "x.prop=1"],
            "{v:?}"
        );
        assert_eq!(r.properties["ro.secure"].len(), 1);
    }

    #[test]
    fn symlink_chains_cycles_and_escapes_are_handled() {
        let links = |pairs: &[(&str, &str)]| {
            pairs
                .iter()
                .map(|(a, b)| (a.to_string(), b.to_string()))
                .collect::<HashMap<_, _>>()
        };
        assert_eq!(
            resolve("a", &links(&[("a", "b"), ("b", "c")])),
            Some("c".into())
        );
        assert_eq!(resolve("d/a", &links(&[("d/a", "../x")])), Some("x".into()));
        assert_eq!(
            resolve("d/a", &links(&[("d/a", "/abs/y")])),
            Some("abs/y".into())
        );
        assert_eq!(
            resolve("d/a", &links(&[("d/a", "./z")])),
            Some("d/z".into())
        );
        assert_eq!(
            resolve("a", &links(&[("a", "b"), ("b", "a")])),
            None,
            "a cycle ends"
        );
        assert_eq!(
            resolve("a", &links(&[("a", "../../../x")])),
            None,
            "cannot climb above the root"
        );
        let chain: Vec<(String, String)> = (0..20)
            .map(|i| (format!("l{i}"), format!("l{}", i + 1)))
            .collect();
        let m: HashMap<String, String> = chain.into_iter().collect();
        assert_eq!(
            resolve("l0", &m),
            None,
            "chains longer than the depth limit stop"
        );
        assert_eq!(resolve("plain", &HashMap::new()), Some("plain".into()));
        // and end to end: a cyclic prop symlink does not hang or report anything
        let r = read(&cpio(&[link("default.prop", "default.prop")])).unwrap();
        assert!(r.properties.is_empty());
    }

    #[test]
    fn hostile_paths_are_rejected() {
        for bad in [
            "../evil",
            "/abs",
            "a/../../b",
            "a/./../../c",
            "..",
            "x/../..",
        ] {
            let e = format!("{:#}", read(&cpio(&[file(bad, b"x")])).unwrap_err());
            assert!(
                e.contains("climbs out") || e.contains("absolute"),
                "{bad}: {e}"
            );
        }
        assert_eq!(clean_path("./a/./b//c").unwrap(), "a/b/c");
        assert_eq!(clean_path(".").unwrap(), "");
        assert!(clean_path("").is_err());
        assert!(clean_path("a\0b").is_err());
        let r = read(&cpio(&[folder("."), file("./a/b", b"x")])).unwrap();
        assert_eq!(
            r.entries.len(),
            1,
            "the root entry is not listed; ./ is stripped"
        );
        assert_eq!(r.entries[0].path, "a/b");
    }

    #[test]
    fn malformed_archives_are_errors_never_panics() {
        let good = cpio(&sample());
        assert!(read(&good).is_ok());
        // Every cut of a small archive must fail, except where an archive may legitimately end:
        // before the first entry and at an entry boundary (the kernel's own loader accepts that too).
        let small = cpio(&[
            folder("d"),
            file("d/f", b"hello"),
            link("l", "d/f"),
            file("z", b""),
        ]);
        let mut boundaries = vec![0usize];
        let mut at = 0;
        for e in [
            folder("d"),
            file("d/f", b"hello"),
            link("l", "d/f"),
            file("z", b""),
        ] {
            at += entry_bytes(&e, 1).len();
            boundaries.push(at);
        }
        assert_eq!(boundaries.len(), 5);
        for cut in 0..small.len() {
            let r = read(&small[..cut]);
            if boundaries.contains(&cut) {
                continue; // may end cleanly; just must not panic
            }
            assert!(
                r.is_err(),
                "a cut at {cut} of {} should be an error",
                small.len()
            );
        }
        assert!(
            read(&small[..boundaries[2]]).is_ok(),
            "ending at an entry boundary is a valid, if trailer-less, archive"
        );
        for cut in [50usize, 109, 115, 200] {
            assert!(read(&good[..cut]).is_err(), "cut at {cut}");
        }
        let patch = |at: usize, bytes: &[u8]| {
            let mut b = good.clone();
            b[at..at + bytes.len()].copy_from_slice(bytes);
            b
        };
        let e = |b: Vec<u8>| format!("{:#}", read(&b).unwrap_err());
        assert!(
            e(patch(0, b"070703")).contains("bad entry magic")
                || e(patch(0, b"070703")).contains("not a")
        );
        assert!(e(patch(6, b"zzzzzzzz")).contains("not hex"));
        assert!(e(patch(6 + 8 * 11, b"00000000")).contains("name of 0 bytes"));
        assert!(e(patch(6 + 8 * 11, b"ffffffff")).contains("is not valid"));
        assert!(e(patch(6 + 8, b"0000f000")).contains("unknown file type"));
        assert!(
            e(patch(6 + 8 * 6, b"7fffffff")).contains("ends"),
            "a file size beyond the archive"
        );
        let mut trailing = good.clone();
        trailing.extend(b"garbage after the trailer");
        assert!(read(&trailing).is_err());
    }

    #[test]
    fn concatenated_archives_and_zero_padding_are_read() {
        let a = cpio(&[file("one", b"1")]);
        let b = cpio(&[file("two", b"22")]);
        let mut both = a.clone();
        both.extend(vec![0u8; 512 - a.len() % 512]);
        both.extend(&b);
        let r = read(&both).unwrap();
        let names: Vec<_> = r.entries.iter().map(|e| e.path.as_str()).collect();
        assert_eq!(names, ["one", "two"]);
        let mut gz = compress(Compression::Gzip, &a);
        gz.extend(compress(Compression::Gzip, &b));
        let r = read(&gz).unwrap();
        assert_eq!(r.entries.len(), 2, "several gzip members form one stream");
    }

    #[test]
    fn the_decompression_cap_is_an_explicit_error() {
        let big = cpio(&[file("zeros", &vec![0u8; 3_000_000])]);
        for c in [
            Compression::Gzip,
            Compression::Xz,
            Compression::Zstd,
            Compression::Bzip2,
            Compression::Lz4Frame,
        ] {
            let packed = compress(c, &big);
            assert!(
                packed.len() < 100_000,
                "{} bomb is small ({} bytes)",
                c.id(),
                packed.len()
            );
            let e = format!(
                "{:#}",
                read_ramdisk_capped(&packed[..], None, 1_000_000).unwrap_err()
            );
            assert!(
                e.contains("larger than the 1000000-byte limit"),
                "{}: {e}",
                c.id()
            );
            assert!(
                read_ramdisk_capped(&packed[..], None, 4_000_000).is_ok(),
                "{} within the cap",
                c.id()
            );
        }
    }

    #[test]
    fn legacy_lz4_edge_cases() {
        let archive = cpio(&[file("a", &data(300_000, 3))]);
        let good = compress(Compression::Lz4Legacy, &archive);
        assert_eq!(read(&good).unwrap().entries[0].size, 300_000);
        let mut two = good.clone();
        two.extend(compress(Compression::Lz4Legacy, &cpio(&[file("b", b"b")])));
        assert_eq!(
            read(&two).unwrap().entries.len(),
            2,
            "a second magic starts the next stream"
        );
        let e = |b: &[u8]| format!("{:#}", read(b).unwrap_err());
        let mut zero_block = LEGACY_LZ4_MAGIC.to_le_bytes().to_vec();
        zero_block.extend(0u32.to_le_bytes());
        assert!(e(&zero_block).contains("not valid"));
        let mut huge = LEGACY_LZ4_MAGIC.to_le_bytes().to_vec();
        huge.extend(u32::MAX.to_le_bytes());
        assert!(e(&huge).contains("not valid"));
        assert!(
            e(&good[..good.len() - 7]).contains("lz4")
                || e(&good[..good.len() - 7]).contains("archive")
        );
        let mut garbage_block = LEGACY_LZ4_MAGIC.to_le_bytes().to_vec();
        garbage_block.extend(16u32.to_le_bytes());
        garbage_block.extend([0xFFu8; 16]);
        assert!(e(&garbage_block).contains("lz4"));
        assert!(e(&good[..6]).contains("lz4") || e(&good[..6]).contains("ends"));
    }

    fn scratch(tag: &str) -> crate::testutil::Scratch {
        crate::testutil::Scratch::new(&format!("rd-{tag}"))
    }

    fn write_input(dir: &Path, name: &str, bytes: &[u8]) -> PathBuf {
        let p = dir.join(name);
        std::fs::write(&p, bytes).unwrap();
        p
    }

    fn tree(dir: &Path) -> Vec<String> {
        fn walk(d: &Path, base: &Path, out: &mut Vec<String>) {
            let mut items: Vec<_> = std::fs::read_dir(d).unwrap().map(|e| e.unwrap()).collect();
            items.sort_by_key(|e| e.file_name());
            for e in items {
                let p = e.path();
                let rel = p.strip_prefix(base).unwrap().to_string_lossy().into_owned();
                if e.file_type().unwrap().is_dir() {
                    out.push(format!("{rel}/"));
                    walk(&p, base, out);
                } else {
                    out.push(rel);
                }
            }
        }
        let mut v = Vec::new();
        walk(dir, dir, &mut v);
        v
    }

    #[test]
    fn extraction_writes_files_and_dirs_but_never_symlinks_or_devices() {
        let dir = scratch("extract");
        let input = write_input(
            &dir,
            "rd.gz",
            &compress(Compression::Gzip, &cpio(&sample())),
        );
        let out = dir.join("out");
        let found = read_input(&input, Some(&out)).unwrap();
        assert_eq!(found.len(), 1);
        found[0].report.as_ref().unwrap();
        let files = out.join("ramdisk/files");
        assert_eq!(
            std::fs::read(files.join("etc/big")).unwrap(),
            data(200_000, 9)
        );
        assert_eq!(
            std::fs::read(files.join("sbin/init")).unwrap(),
            b"#!/bin/sh\n"
        );
        assert_eq!(std::fs::read(files.join("fxxxxx")).unwrap(), data(5, 5));
        let all = tree(&files);
        assert!(
            !all.contains(&"init".to_string()),
            "symlinks are not created: {all:?}"
        );
        assert!(
            !all.contains(&"dev-null".to_string()) && !all.contains(&"pipe".to_string()),
            "{all:?}"
        );
        let manifest: Value =
            serde_json::from_slice(&std::fs::read(out.join("ramdisk/manifest.json")).unwrap())
                .unwrap();
        let init = manifest["entries"]
            .as_array()
            .unwrap()
            .iter()
            .find(|e| e["path"] == "init")
            .unwrap();
        assert_eq!(init["type"], "symlink");
        assert_eq!(init["link"], "/sbin/init");
        assert!(
            !dir.join("out.part").exists(),
            "the staging directory is gone"
        );
    }

    #[cfg(unix)]
    #[test]
    fn permissions_are_applied_and_special_bits_are_dropped() {
        use std::os::unix::fs::PermissionsExt;
        let dir = scratch("modes");
        let mut suid = file("su", b"x");
        suid.mode = 0o104755;
        let mut ro = file("ro", b"y");
        ro.mode = 0o100400;
        let mut exec = file("sh", b"z");
        exec.mode = 0o100755;
        let input = write_input(&dir, "rd", &cpio(&[suid, ro, exec]));
        let out = dir.join("out");
        read_input(&input, Some(&out)).unwrap();
        let mode = |n: &str| {
            std::fs::metadata(out.join("ramdisk/files").join(n))
                .unwrap()
                .permissions()
                .mode()
                & 0o7777
        };
        assert_eq!(mode("su"), 0o755, "setuid dropped on disk");
        assert_eq!(mode("ro"), 0o400);
        assert_eq!(mode("sh"), 0o755);
        let m: Value =
            serde_json::from_slice(&std::fs::read(out.join("ramdisk/manifest.json")).unwrap())
                .unwrap();
        let su = m["entries"]
            .as_array()
            .unwrap()
            .iter()
            .find(|e| e["path"] == "su")
            .unwrap();
        assert_eq!(su["mode"], 0o4755, "the manifest keeps the real mode");
    }

    #[test]
    fn extraction_refuses_conflicts_and_cleans_up() {
        let dir = scratch("conflicts");
        let cases: Vec<(&str, Vec<E>, &str)> = vec![
            (
                "file then dir",
                vec![file("a", b"1"), file("a/b", b"2")],
                "is a file but",
            ),
            (
                "dir and file",
                vec![folder("a"), file("a", b"2")],
                "both a file and a directory",
            ),
            (
                "case",
                vec![file("README", b"1"), file("readme", b"2")],
                "differs only by case",
            ),
            (
                "case dir",
                vec![folder("Etc"), file("etc/x", b"2")],
                "differs only by case",
            ),
        ];
        for (name, entries, want) in cases {
            let input = write_input(&dir, "rd", &cpio(&entries));
            let out = dir.join(format!("out-{}", name.replace(' ', "-")));
            let found = read_input(&input, Some(&out)).unwrap();
            let e = format!("{:#}", found[0].report.as_ref().unwrap_err());
            assert!(e.contains(want), "{name}: {e}");
            assert!(!out.exists(), "{name}: nothing is published after an error");
            assert!(!staging_path(&out).exists(), "{name}: staging removed");
        }
    }

    #[test]
    fn a_path_listed_twice_keeps_the_later_content() {
        let dir = scratch("dupes");
        let input = write_input(
            &dir,
            "rd",
            &cpio(&[
                file("a", b"first"),
                folder("d"),
                folder("d"),
                file("a", b"second!"),
            ]),
        );
        let out = dir.join("out");
        read_input(&input, Some(&out)).unwrap();
        assert_eq!(
            std::fs::read(out.join("ramdisk/files/a")).unwrap(),
            b"second!"
        );
    }

    #[test]
    fn hardlinks_share_their_data() {
        let dir = scratch("hard");
        let mut a = file("bin/a", b"");
        let mut b = file("bin/b", b"");
        let mut c = file("bin/c", b"shared content");
        for e in [&mut a, &mut b, &mut c] {
            e.ino = 77;
            e.nlink = 3;
        }
        let input = write_input(&dir, "rd", &cpio(&[self::folder("bin"), a, b, c]));
        let out = dir.join("out");
        read_input(&input, Some(&out)).unwrap();
        for n in ["a", "b", "c"] {
            assert_eq!(
                std::fs::read(out.join("ramdisk/files/bin").join(n)).unwrap(),
                b"shared content",
                "bin/{n}"
            );
        }
    }

    fn linked(name: &str, data: &[u8], ino: u32, nlink: u32) -> E {
        E {
            ino,
            nlink,
            ..file(name, data)
        }
    }

    #[test]
    fn hardlink_data_may_come_first_last_or_in_the_middle() {
        let orders: [(&str, [bool; 3]); 3] = [
            ("data first", [true, false, false]),
            ("data last", [false, false, true]),
            ("data in the middle", [false, true, false]),
        ];
        for (label, has_data) in orders {
            let entries: Vec<E> = ["a", "b", "c"]
                .iter()
                .zip(has_data)
                .map(|(n, d)| linked(n, if d { b"shared!" } else { b"" }, 9, 3))
                .collect();
            let archive = cpio(&entries);
            // listing alone: every name reports the group's size and hash
            let r = read(&archive).unwrap();
            for e in &r.entries {
                assert_eq!(e.size, 7, "{label}: size of {}", e.path);
                assert_eq!(
                    e.sha256.as_deref(),
                    Some(sha(b"shared!").as_str()),
                    "{label}: sha of {}",
                    e.path
                );
            }
            // extraction: every name holds the data
            let dir = scratch("hardorder");
            let input = write_input(&dir, "rd", &archive);
            let out = dir.join(format!("out-{}", label.replace(' ', "-")));
            read_input(&input, Some(&out)).unwrap();
            for n in ["a", "b", "c"] {
                assert_eq!(
                    std::fs::read(out.join("ramdisk/files").join(n)).unwrap(),
                    b"shared!",
                    "{label}: {n}"
                );
            }
        }
    }

    #[test]
    fn a_hardlink_group_that_never_carries_data_gives_empty_files() {
        let archive = cpio(&[
            linked("a", b"", 5, 2),
            folder("d"),
            linked("d/b", b"", 5, 2),
        ]);
        let r = read(&archive).unwrap();
        for p in ["a", "d/b"] {
            assert_eq!(by_path(&r, p).size, 0);
            assert_eq!(by_path(&r, p).sha256.as_deref(), Some(EMPTY_SHA256), "{p}");
        }
        assert_eq!(
            EMPTY_SHA256,
            sha(b""),
            "the constant is the hash of nothing"
        );
        let dir = scratch("hardempty");
        let input = write_input(&dir, "rd", &archive);
        let out = dir.join("out");
        read_input(&input, Some(&out)).unwrap();
        for p in ["a", "d/b"] {
            assert_eq!(
                std::fs::read(out.join("ramdisk/files").join(p)).unwrap(),
                b"",
                "{p}"
            );
        }
    }

    #[test]
    fn only_entries_with_the_same_inode_and_device_share_data() {
        let mut other_dev = entry_bytes(&linked("far", b"", 9, 2), 1);
        other_dev[70..78].copy_from_slice(b"00000002"); // field 8 of the header: 6 + 8 * 8 // device minor 2: a different file system
        let mut archive = Vec::new();
        archive.extend(entry_bytes(&linked("near", b"first", 9, 2), 1)); // device minor 1
        archive.extend(other_dev);
        archive.extend(entry_bytes(&linked("lone", b"", 9, 1), 1)); // nlink 1: just an empty file
        archive.extend(entry_bytes(&linked("other-inode", b"", 10, 2), 1));
        archive.extend(entry_bytes(
            &E {
                name: "TRAILER!!!".into(),
                mode: 0,
                ..file("t", b"")
            },
            0,
        ));
        let r = read(&archive).unwrap();
        assert_eq!(by_path(&r, "near").size, 5);
        assert_eq!(
            by_path(&r, "far").size,
            0,
            "another device is another group"
        );
        assert_eq!(by_path(&r, "lone").size, 0);
        assert_eq!(by_path(&r, "other-inode").size, 0);
        let dir = scratch("hardkeys");
        let input = write_input(&dir, "rd", &archive);
        let out = dir.join("out");
        read_input(&input, Some(&out)).unwrap();
        let read_file = |n: &str| std::fs::read(out.join("ramdisk/files").join(n)).unwrap();
        assert_eq!(read_file("near"), b"first");
        assert_eq!(read_file("far"), b"");
        assert_eq!(read_file("lone"), b"");
        assert_eq!(read_file("other-inode"), b"");
    }

    #[test]
    fn two_entries_of_one_inode_that_both_carry_data_are_refused() {
        let archive = cpio(&[linked("a", b"one", 3, 2), linked("b", b"two", 3, 2)]);
        let e = format!("{:#}", read(&archive).unwrap_err());
        assert!(
            e.contains("both carry data") && e.contains('a') && e.contains('b'),
            "{e}"
        );
    }

    #[test]
    fn property_files_are_read_through_a_hardlink_name() {
        for order in [[true, false], [false, true]] {
            let props = b"ro.debuggable=1\nro.secure=0\n";
            let names = ["system/etc/data", "default.prop"];
            let archive = cpio(&[
                folder("system"),
                folder("system/etc"),
                linked(names[0], if order[0] { props } else { b"" }, 21, 2),
                linked(names[1], if order[1] { props } else { b"" }, 21, 2),
            ]);
            let r = read(&archive).unwrap();
            assert_eq!(
                r.properties["ro.debuggable"],
                vec![("default.prop".to_string(), "1".to_string())],
                "order {order:?}"
            );
            assert_eq!(r.properties["ro.secure"][0].1, "0");
        }
    }

    #[cfg(unix)]
    #[test]
    fn hardlink_names_keep_their_own_modes_and_get_their_parent_directories() {
        use std::os::unix::fs::PermissionsExt;
        let mut a = linked("x/deep/a", b"", 4, 2);
        a.mode = 0o100755;
        let mut b = linked("y/b", b"data", 4, 2);
        b.mode = 0o100640;
        let dir = scratch("hardmode");
        let input = write_input(&dir, "rd", &cpio(&[a, b]));
        let out = dir.join("out");
        read_input(&input, Some(&out)).unwrap();
        let files = out.join("ramdisk/files");
        assert_eq!(std::fs::read(files.join("x/deep/a")).unwrap(), b"data");
        let mode = |p: &str| {
            std::fs::metadata(files.join(p))
                .unwrap()
                .permissions()
                .mode()
                & 0o777
        };
        assert_eq!(mode("x/deep/a"), 0o755);
        assert_eq!(mode("y/b"), 0o640);
        // an empty linked name keeps its mode too
        let mut e = linked("e", b"", 6, 2);
        e.mode = 0o100700;
        let input = write_input(&dir, "rd2", &cpio(&[e]));
        let out2 = dir.join("out2");
        read_input(&input, Some(&out2)).unwrap();
        assert_eq!(
            std::fs::metadata(out2.join("ramdisk/files/e"))
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o700
        );
    }

    #[cfg(unix)]
    #[test]
    fn empty_linked_names_get_their_parents_and_special_bits_are_dropped_everywhere() {
        use std::os::unix::fs::PermissionsExt;
        let mut e1 = linked("q/r/e1", b"", 31, 2);
        let mut e2 = linked("q/r/e2", b"", 31, 2);
        e1.mode = 0o104755;
        e2.mode = 0o102750;
        let dir = scratch("emptyparents");
        let input = write_input(&dir, "rd", &cpio(&[e1, e2]));
        let out = dir.join("out");
        read_input(&input, Some(&out)).unwrap(); // no directory entries: parents must be made
        let mode = |p: &str| {
            std::fs::metadata(out.join("ramdisk/files").join(p))
                .unwrap()
                .permissions()
                .mode()
                & 0o7777
        };
        assert_eq!(
            mode("q/r/e1"),
            0o755,
            "setuid dropped on an empty linked name"
        );
        assert_eq!(mode("q/r/e2"), 0o750, "setgid dropped");
        // and on a copied linked name
        let mut data = linked("src", b"x", 32, 2);
        let mut copy = linked("dst", b"", 32, 2);
        data.mode = 0o104755;
        copy.mode = 0o101777; // sticky
        let input = write_input(&dir, "rd2", &cpio(&[copy, data]));
        let out2 = dir.join("out2");
        read_input(&input, Some(&out2)).unwrap();
        let mode2 = |p: &str| {
            std::fs::metadata(out2.join("ramdisk/files").join(p))
                .unwrap()
                .permissions()
                .mode()
                & 0o7777
        };
        assert_eq!(mode2("dst"), 0o777);
        assert_eq!(mode2("src"), 0o755);
    }

    #[test]
    fn output_directory_rules() {
        let dir = scratch("outdir");
        let input = write_input(&dir, "rd", &cpio(&[file("a", b"1")]));
        let out = dir.join("out");
        std::fs::create_dir_all(&out).unwrap();
        read_input(&input, Some(&out)).unwrap();
        assert!(
            out.join("ramdisk/files/a").exists(),
            "an existing empty directory is fine"
        );
        let e = read_input(&input, Some(&out)).err().unwrap().to_string();
        assert!(e.contains("already exists and is not empty"), "{e}");
        assert_eq!(
            std::fs::read(out.join("ramdisk/files/a")).unwrap(),
            b"1",
            "existing output is untouched"
        );
        assert!(
            !staging_path(&out).exists(),
            "no staging directory is made for a refused run"
        );
        let file_out = dir.join("plain");
        std::fs::write(&file_out, b"x").unwrap();
        assert!(
            read_input(&input, Some(&file_out))
                .err()
                .unwrap()
                .to_string()
                .contains("not a directory")
        );
        // a stale staging directory from a crashed run is replaced
        let out2 = dir.join("out2");
        std::fs::create_dir_all(staging_path(&out2).join("junk")).unwrap();
        read_input(&input, Some(&out2)).unwrap();
        assert!(!staging_path(&out2).exists() && out2.join("ramdisk/files/a").exists());
    }

    #[cfg(unix)]
    #[test]
    fn a_planted_symlink_as_the_staging_name_is_not_followed() {
        use std::os::unix::fs::symlink;
        let dir = scratch("stagelink");
        let input = write_input(&dir, "rd", &cpio(&[file("a", b"1")]));
        let victim = dir.join("victim");
        std::fs::create_dir(&victim).unwrap();
        std::fs::write(victim.join("keep"), b"precious").unwrap();
        let out = dir.join("out");
        symlink(&victim, staging_path(&out)).unwrap();
        read_input(&input, Some(&out)).unwrap();
        assert_eq!(
            std::fs::read(victim.join("keep")).unwrap(),
            b"precious",
            "the link target is untouched"
        );
        assert!(victim.join("keep").exists());
        assert!(out.join("ramdisk/files/a").exists());
    }

    /// A minimal boot image v3 whose ramdisk section is `ramdisk` (kernel size 0).
    fn boot_v3(ramdisk: &[u8]) -> Vec<u8> {
        let mut h = vec![0u8; 4096];
        h[..8].copy_from_slice(b"ANDROID!");
        h[12..16].copy_from_slice(&(ramdisk.len() as u32).to_le_bytes());
        h[20..24].copy_from_slice(&1580u32.to_le_bytes());
        h[40..44].copy_from_slice(&3u32.to_le_bytes());
        h.extend(ramdisk);
        h.resize(h.len().div_ceil(4096) * 4096, 0);
        h
    }

    #[test]
    fn a_boot_image_ramdisk_is_found_and_read() {
        let dir = scratch("bootimg");
        let img = write_input(
            &dir,
            "boot.img",
            &boot_v3(&compress(
                Compression::Gzip,
                &cpio(&[file("default.prop", b"ro.debuggable=1\n")]),
            )),
        );
        let found = read_input(&img, None).unwrap();
        assert_eq!(found[0].name, "ramdisk");
        let r = found[0].report.as_ref().unwrap();
        assert_eq!(r.properties["ro.debuggable"][0].1, "1");
        let none = write_input(&dir, "noramdisk.img", &boot_v3(&[]));
        assert!(
            read_input(&none, None)
                .err()
                .unwrap()
                .to_string()
                .contains("no ramdisk")
        );
        let enc: Vec<u8> = (0..70_000u32)
            .map(|i| (i.wrapping_mul(2654435761) >> 13) as u8)
            .collect();
        let encimg = write_input(&dir, "enc.img", &boot_v3(&enc));
        let found = read_input(&encimg, None).unwrap();
        assert!(format!("{:#}", found[0].report.as_ref().unwrap_err()).contains("encrypted"));
    }

    #[test]
    fn inputs_that_are_not_files_are_refused() {
        let dir = scratch("inputs");
        assert!(
            read_input(&dir, None)
                .err()
                .unwrap()
                .to_string()
                .contains("directory")
        );
        assert!(read_input(&dir.join("missing"), None).is_err());
        #[cfg(unix)]
        {
            let fifo = dir.join("pipe");
            assert!(
                std::process::Command::new("mkfifo")
                    .arg(&fifo)
                    .status()
                    .unwrap()
                    .success()
            );
            let (tx, rx) = std::sync::mpsc::channel();
            std::thread::spawn(move || {
                let _ = tx.send(read_input(&fifo, None).err().map(|e| e.to_string()));
            });
            let msg = rx
                .recv_timeout(std::time::Duration::from_secs(20))
                .expect("ramdisk blocked on a FIFO");
            assert!(msg.unwrap().contains("FIFO or socket"));
        }
    }

    #[test]
    fn near_miss_magics_are_not_taken_for_a_format() {
        for (m, what) in [
            (
                &[0xFDu8, b'7', b'z', b'X', b'Z', 0x01][..],
                "xz with a wrong last byte",
            ),
            (&[0x28, 0xB5, 0x2F, 0xFE][..], "zstd with a wrong last byte"),
            (
                &[0x04, 0x22, 0x4D, 0x19][..],
                "lz4 frame with a wrong last byte",
            ),
            (
                &[0x02, 0x21, 0x4C, 0x19][..],
                "legacy lz4 with a wrong last byte",
            ),
            (&[0x1F, 0x8B, 0x09][..], "gzip with another method"),
            (b"070700", "cpio with another magic"),
        ] {
            assert_eq!(compression_of(m), None, "{what}");
        }
        let id = |b: &[u8]| classify_section(b).0;
        assert_eq!(
            id(&[0xD0, 0x0D, 0xFE, 0xEE, 0, 0]),
            "unknown",
            "dtb with a wrong last byte"
        );
        assert_eq!(
            id(&[0xD0, 0x0D, 0xFE]),
            "unknown",
            "dtb needs all four bytes"
        );
        // the literal bytes of the real formats
        assert_eq!(
            compression_of(&[0x02, 0x21, 0x4C, 0x18]),
            Some(Compression::Lz4Legacy)
        );
        assert_eq!(
            compression_of(&[0xFD, 0x37, 0x7A, 0x58, 0x5A, 0x00]),
            Some(Compression::Xz)
        );
        assert_eq!(
            compression_of(&[0x28, 0xB5, 0x2F, 0xFD]),
            Some(Compression::Zstd)
        );
        assert_eq!(
            compression_of(&[0x04, 0x22, 0x4D, 0x18]),
            Some(Compression::Lz4Frame)
        );
        assert_eq!(id(&[0xD0, 0x0D, 0xFE, 0xED]), "dtb");
        assert_eq!(LEGACY_LZ4_MAGIC, 0x184C2102);
    }

    #[test]
    fn the_limits_are_the_documented_values() {
        assert_eq!(MAX_DECOMPRESSED, 2 << 30);
        assert_eq!(MAX_NAME, 4096);
        assert_eq!(MAX_PROP_FILE, 1 << 20);
        assert_eq!(MAX_ENTRIES, 1_000_000);
    }

    #[test]
    fn entropy_threshold_separates_noise_from_structured_data() {
        let id = |b: &[u8]| classify_section(b).0;
        // 128 equally likely byte values: exactly 7 bits per byte, below the threshold
        let structured: Vec<u8> = (0..8192u32)
            .map(|i| ((i.wrapping_mul(2654435761) >> 13) as u8) & 0x7F)
            .collect();
        assert!(
            (6.9..7.1).contains(&entropy(&structured)),
            "{}",
            entropy(&structured)
        );
        assert_eq!(id(&structured), "unknown");
        let text: Vec<u8> = b"the quick brown fox jumps over the lazy dog "
            .iter()
            .cycle()
            .take(8192)
            .copied()
            .collect();
        assert_eq!(id(&text), "unknown");
        // 255 values: about 7.99 bits per byte, above it
        let noise: Vec<u8> = (0..8192u32)
            .map(|i| (i.wrapping_mul(2654435761) >> 13) as u8)
            .collect();
        assert!(entropy(&noise) > 7.9, "{}", entropy(&noise));
        assert_eq!(id(&noise), "unknown-high-entropy");
        assert_eq!(id(&noise[..MIN_ENTROPY_SAMPLE - 1]), "unknown");
        assert_eq!(id(&noise[..MIN_ENTROPY_SAMPLE]), "unknown-high-entropy");
    }

    #[test]
    fn concatenated_bzip2_streams_form_one_archive() {
        let mut bz = compress(Compression::Bzip2, &cpio(&[file("a", b"1")]));
        bz.extend(compress(Compression::Bzip2, &cpio(&[file("b", b"22")])));
        let r = read(&bz).unwrap();
        let names: Vec<_> = r.entries.iter().map(|e| e.path.as_str()).collect();
        assert_eq!(names, ["a", "b"]);
    }

    #[test]
    fn header_and_name_corruption_is_reported_precisely() {
        let first = entry_bytes(&file("one", b"1"), 1);
        let two = cpio(&[file("one", b"1"), file("two", b"2")]);
        let e = |b: &[u8]| format!("{:#}", read(b).unwrap_err());
        // the magic of the SECOND entry is wrong (the first one decides the compression)
        let mut bad = two.clone();
        bad[first.len()..first.len() + 6].copy_from_slice(b"070799");
        assert!(e(&bad).contains("bad entry magic"), "{}", e(&bad));
        // non-hex digits in a field of the second entry
        let mut bad = two.clone();
        bad[first.len() + 6..first.len() + 10].copy_from_slice(b"zzzz");
        assert!(e(&bad).contains("is not hex"), "{}", e(&bad));
        // a name whose last byte is not NUL
        let mut bad = two.clone();
        let name_at = first.len() + CPIO_HEADER_LEN;
        bad[name_at + 3] = b'x'; // "two\0" -> "twox"
        assert!(e(&bad).contains("not NUL-terminated"), "{}", e(&bad));
        // a name longer than the limit (the literal 4096)
        let mut bad = two.clone();
        bad[6 + 8 * 11..6 + 8 * 12].copy_from_slice(b"00001001"); // 4097
        assert!(e(&bad).contains("is not valid"), "{}", e(&bad));
        let mut ok_len = two.clone();
        ok_len[6 + 8 * 11..6 + 8 * 12].copy_from_slice(b"00001000"); // 4096: passes the length check
        assert!(!e(&ok_len).contains("is not valid"), "{}", e(&ok_len));
        // a path with an embedded NUL
        let nul = E {
            name: "a\0b".into(),
            ..file("x", b"")
        };
        let msg = e(&cpio(&[nul]));
        assert!(msg.contains("NUL"), "{msg}");
    }

    #[test]
    fn data_and_symlink_size_problems_are_reported_precisely() {
        let e = |b: &[u8]| format!("{:#}", read(b).unwrap_err());
        // the archive stops in the middle of a file's data
        let full = cpio(&[file("f", &data(100, 1)), file("g", b"2")]);
        let cut = 110 + 2 + 50; // header + "f\0" + padding + part of the data
        assert!(
            e(&full[..cut]).contains("ends inside the file data"),
            "{}",
            e(&full[..cut])
        );
        // a symlink whose target is larger than a path can be
        let big = link("l", &"t".repeat(5000));
        assert!(e(&cpio(&[big])).contains("symlink target of 5000 bytes is not valid"));
        let ok = link("l", &"t".repeat(4096));
        assert_eq!(
            read(&cpio(&[ok])).unwrap().entries[0]
                .link
                .as_ref()
                .map(String::len),
            Some(4096)
        );
    }

    #[test]
    fn a_property_file_over_the_size_cap_is_not_read() {
        let mut big = b"ro.debuggable=1\n".to_vec();
        big.resize(MAX_PROP_FILE as usize + 1, b'#');
        let r = read(&cpio(&[file("big.prop", &big)])).unwrap();
        assert!(r.properties.is_empty(), "files over the cap are skipped");
        let mut ok = b"ro.debuggable=1\n".to_vec();
        ok.resize(MAX_PROP_FILE as usize, b'#');
        let r = read(&cpio(&[file("big.prop", &ok)])).unwrap();
        assert_eq!(r.properties["ro.debuggable"][0].1, "1");
    }

    #[test]
    fn a_property_repeated_in_one_file_is_reported_once() {
        let r = read(&cpio(&[file(
            "default.prop",
            b"ro.secure=1\nro.secure=1\nro.secure=0\n",
        )]))
        .unwrap();
        let v: Vec<_> = r.properties["ro.secure"]
            .iter()
            .map(|(_, v)| v.as_str())
            .collect();
        assert_eq!(
            v,
            ["1", "0"],
            "equal repeats collapse, a different value is kept"
        );
    }

    #[test]
    fn the_cap_allows_exactly_its_size_and_no_more() {
        let archive = cpio(&[file("a", &data(1000, 1))]);
        let plain_len = archive.len() as u64;
        assert!(
            read_ramdisk_capped(&archive[..], None, plain_len).is_ok(),
            "exactly the size is fine"
        );
        let e = format!(
            "{:#}",
            read_ramdisk_capped(&archive[..], None, plain_len - 1).unwrap_err()
        );
        assert!(e.contains("larger than"), "{e}");
        let gz = compress(Compression::Gzip, &archive);
        assert!(read_ramdisk_capped(&gz[..], None, plain_len).is_ok());
        assert!(read_ramdisk_capped(&gz[..], None, plain_len - 1).is_err());
    }

    #[test]
    fn a_path_below_a_symlink_is_refused_when_extracting() {
        let dir = scratch("belowlink");
        let evil = cpio(&[link("link", "/etc"), file("link/passwd", b"pwn")]);
        let input = write_input(&dir, "rd", &evil);
        let out = dir.join("out");
        let found = read_input(&input, Some(&out)).unwrap();
        let e = format!("{:#}", found[0].report.as_ref().unwrap_err());
        assert!(e.contains("goes through the symlink link"), "{e}");
        assert!(!out.exists(), "nothing is published");
        // a path and a symlink with the same name
        let clash = cpio(&[file("x", b"1"), link("x", "y")]);
        let input = write_input(&dir, "rd2", &clash);
        let found = read_input(&input, Some(&dir.join("out2"))).unwrap();
        assert!(
            format!("{:#}", found[0].report.as_ref().unwrap_err())
                .contains("both a file or directory and a symlink")
        );
        let clash = cpio(&[link("x", "y"), file("x", b"1")]);
        let input = write_input(&dir, "rd3", &clash);
        let found = read_input(&input, Some(&dir.join("out3"))).unwrap();
        assert!(
            format!("{:#}", found[0].report.as_ref().unwrap_err())
                .contains("both a symlink and something else")
        );
        // listing alone (no extraction) does not mind
        assert!(read(&evil).is_ok());
    }

    /// A minimal vendor boot image v3 holding `ramdisk` as its vendor ramdisk.
    fn vendor_v3(ramdisk: &[u8]) -> Vec<u8> {
        let mut h = vec![0u8; 4096];
        h[..8].copy_from_slice(b"VNDRBOOT");
        h[8..12].copy_from_slice(&3u32.to_le_bytes());
        h[12..16].copy_from_slice(&4096u32.to_le_bytes());
        h[24..28].copy_from_slice(&(ramdisk.len() as u32).to_le_bytes());
        h[2096..2100].copy_from_slice(&2112u32.to_le_bytes());
        h.extend(ramdisk);
        h.resize(h.len().div_ceil(4096) * 4096, 0);
        h
    }

    #[test]
    fn a_vendor_boot_ramdisk_is_found_and_extracted_under_its_own_name() {
        let dir = scratch("vendor");
        let img = write_input(
            &dir,
            "vendor_boot.img",
            &vendor_v3(&compress(
                Compression::Lz4Frame,
                &cpio(&[file("lib/modules/x.ko", b"module")]),
            )),
        );
        let found = read_input(&img, None).unwrap();
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].name, "vendor_ramdisk");
        assert_eq!(
            found[0].report.as_ref().unwrap().compression,
            Compression::Lz4Frame
        );
        let out = dir.join("out");
        read_input(&img, Some(&out)).unwrap();
        assert_eq!(
            std::fs::read(out.join("vendor_ramdisk/files/lib/modules/x.ko")).unwrap(),
            b"module"
        );
    }

    #[test]
    fn a_directory_input_names_the_problem() {
        let dir = scratch("dirinput");
        let e = read_input(&dir, None).err().unwrap().to_string();
        assert!(e.ends_with("is a directory"), "{e}");
    }

    #[test]
    fn text_and_json_output() {
        let archive = cpio(&[
            file("prop.default", b"ro.secure=1\nro.debuggable=0\n"),
            link("default.prop", "prop.default"),
            folder("d"),
        ]);
        let r = read(&compress(Compression::Gzip, &archive)).unwrap();
        let text = r.to_text(false);
        assert!(
            text.contains("compression  gzip")
                && text.contains("entries      3 (1 files, 1 directories, 1 symlinks)"),
            "{text}"
        );
        assert!(
            text.contains("ro.secure=1  (prop.default)")
                && text.contains("ro.debuggable=0  (prop.default)"),
            "{text}"
        );
        assert!(!text.contains("entries:"), "the entry list is opt-in");
        let long = r.to_text(true);
        assert!(
            long.contains("entries:")
                && long.contains("default.prop -> prop.default")
                && long.contains("symlink"),
            "{long}"
        );
        let j = r.to_json();
        assert_eq!(j["compression"], "gzip");
        assert_eq!(j["summary"]["files"], 1);
        assert_eq!(j["properties"]["ro.secure"][0]["value"], "1");
        assert_eq!(j["entries"][1]["link"], "prop.default");
        let none = read(&cpio(&[file("a", b"x")])).unwrap().to_text(false);
        assert!(
            none.contains("none of the reported ADB/debug properties"),
            "{none}"
        );
    }
}
