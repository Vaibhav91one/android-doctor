//! Read-only reader for ext2, ext3 and ext4 images, and extraction of their files.
//!
//! Written from the on-disk format (the Linux kernel's ext4 documentation) and checked against
//! `7z`, the `ext4-view` and `ext4` crates and an independent scanner on real Android images. Unlike
//! the crates it reads extended attributes (SELinux labels, file capabilities) and treats the
//! whole image as hostile: every offset and length is checked against the image size, every
//! allocation is bounded, and walks have depth, entry, loop and size limits.
use crate::detect::refuse_blocking_file;
use crate::tree::{
    COPY_CHUNK, Entry, Kind, MAX_DEPTH, MAX_ENTRIES, MAX_FILE_BYTES, MAX_PATH, MAX_SYMLINK,
    TreeSource, check_cat,
};
use crate::treeout::{Collisions, short};
use anyhow::{Context, Result, bail, ensure};
use sha2::{Digest, Sha256};
use std::collections::HashSet;
use std::fs::File;
use std::io::{Seek, SeekFrom, Write};
use std::path::Path;

const EXT_MAGIC: u16 = 0xEF53;
const MIN_BLOCK: u64 = 1024;
const MAX_BLOCK: u64 = 65536;
const MAX_GROUPS: u64 = 1 << 20;
const MAX_EXTENT_DEPTH: u16 = 5;
const MAX_TREE_NODES: usize = 1 << 20;
const MAX_RUNS: usize = 1 << 21;
const MAX_XATTRS: usize = 4096;
const MAX_XATTR_VALUE: usize = 1 << 20;
const XATTR_MAGIC: u32 = 0xEA02_0000;

const INCOMPAT_COMPRESSION: u32 = 0x1;
const INCOMPAT_JOURNAL_DEV: u32 = 0x8;
const INCOMPAT_META_BG: u32 = 0x10;
const INCOMPAT_64BIT: u32 = 0x80;
const INODE_EXTENTS: u32 = 0x8_0000;
const INODE_INLINE_DATA: u32 = 0x1000_0000;
const INODE_ENCRYPT: u32 = 0x800;

/// Where the image bytes come from.
pub(crate) enum Source {
    File(File),
    #[cfg(test)]
    Mem(Vec<u8>),
}

impl Source {
    pub(crate) fn len(&self) -> Result<u64> {
        Ok(match self {
            Source::File(f) => f.metadata()?.len(),
            #[cfg(test)]
            Source::Mem(v) => v.len() as u64,
        })
    }

    pub(crate) fn read_at(&self, off: u64, buf: &mut [u8]) -> std::io::Result<()> {
        match self {
            #[cfg(test)]
            Source::Mem(v) => {
                let end = off
                    .checked_add(buf.len() as u64)
                    .filter(|e| *e <= v.len() as u64)
                    .ok_or_else(|| std::io::Error::other("read past the end of the image"))?;
                buf.copy_from_slice(&v[off as usize..end as usize]);
                Ok(())
            }
            #[cfg(unix)]
            Source::File(f) => std::os::unix::fs::FileExt::read_exact_at(f, buf, off),
            #[cfg(windows)]
            Source::File(f) => {
                let mut done = 0;
                while done < buf.len() {
                    let n = std::os::windows::fs::FileExt::seek_read(
                        f,
                        &mut buf[done..],
                        off + done as u64,
                    )?;
                    if n == 0 {
                        return Err(std::io::ErrorKind::UnexpectedEof.into());
                    }
                    done += n;
                }
                Ok(())
            }
        }
    }
}

pub(crate) fn le16(b: &[u8], at: usize) -> u16 {
    u16::from_le_bytes([b[at], b[at + 1]])
}

pub(crate) fn le32(b: &[u8], at: usize) -> u32 {
    u32::from_le_bytes([b[at], b[at + 1], b[at + 2], b[at + 3]])
}

/// One stretch of a file: `blocks` logical blocks from `lblk`, stored at `pblk` (`None` = zeros).
#[derive(Debug, Clone, Copy, PartialEq)]
struct Run {
    lblk: u64,
    blocks: u64,
    pblk: Option<u64>,
}

#[derive(Debug, Clone)]
pub struct Inode {
    pub ino: u32,
    pub mode: u16,
    pub uid: u32,
    pub gid: u32,
    pub size: u64,
    pub mtime: i64,
    pub links: u16,
    flags: u32,
    block: [u8; 60],
    file_acl: u64,
    /// The bytes after the 128-byte core (extra fields and in-inode xattrs).
    tail: Vec<u8>,
    extra_isize: usize,
}

pub struct Fs {
    src: Source,
    len: u64,
    bs: u64,
    inode_size: u64,
    inodes: u32,
    inodes_per_group: u32,
    blocks: u64,
    itables: Vec<u64>,
}

fn xattr_prefix(index: u8) -> Option<&'static str> {
    Some(match index {
        1 => "user.",
        2 => "system.posix_acl_access",
        3 => "system.posix_acl_default",
        4 => "trusted.",
        6 => "security.",
        7 => "system.",
        8 => "system.richacl",
        _ => return None,
    })
}

pub(crate) fn xattr_text(v: &[u8]) -> String {
    let trimmed = {
        let mut end = v.len();
        while end > 0 && v[end - 1] == 0 {
            end -= 1;
        }
        &v[..end]
    };
    match std::str::from_utf8(trimmed) {
        Ok(s) if !s.is_empty() && !s.chars().any(char::is_control) => s.to_string(),
        _ => format!(
            "hex:{}",
            v.iter().map(|b| format!("{b:02x}")).collect::<String>()
        ),
    }
}

/// A directory entry name as text; bytes that are not UTF-8 become `%XX`.
pub(crate) fn name_string(mut b: &[u8]) -> String {
    let mut out = String::new();
    loop {
        match std::str::from_utf8(b) {
            Ok(s) => {
                out.push_str(s);
                return out;
            }
            Err(e) => {
                let (good, rest) = b.split_at(e.valid_up_to());
                out.push_str(std::str::from_utf8(good).unwrap_or(""));
                let bad = e.error_len().unwrap_or(rest.len());
                for byte in &rest[..bad] {
                    out.push_str(&format!("%{byte:02X}"));
                }
                b = &rest[bad..];
            }
        }
    }
}

fn parse_xattrs(
    region: &[u8],
    first: usize,
    base: usize,
    out: &mut Vec<(String, Vec<u8>)>,
) -> Result<()> {
    let mut p = first;
    let mut count = 0;
    while p + 4 <= region.len() && le32(region, p) != 0 {
        count += 1;
        ensure!(
            count <= MAX_XATTRS,
            "more than {MAX_XATTRS} extended attributes"
        );
        ensure!(
            p + 16 <= region.len(),
            "an extended attribute entry runs past its area"
        );
        let (name_len, index) = (region[p] as usize, region[p + 1]);
        let (offs, inum, size) = (
            le16(region, p + 2) as usize,
            le32(region, p + 4),
            le32(region, p + 8) as usize,
        );
        let name_end = p + 16 + name_len;
        ensure!(
            name_end <= region.len(),
            "an extended attribute name runs past its area"
        );
        ensure!(
            inum == 0,
            "an extended attribute stored in its own inode is not supported"
        );
        ensure!(
            size <= MAX_XATTR_VALUE,
            "an extended attribute value of {size} bytes is over the limit"
        );
        let value_at = base + offs;
        ensure!(
            value_at + size <= region.len(),
            "an extended attribute value runs past its area"
        );
        let suffix = name_string(&region[p + 16..name_end]);
        let name = match xattr_prefix(index) {
            Some(prefix) if prefix.ends_with('.') => format!("{prefix}{suffix}"),
            Some(full) => full.to_string(),
            None => format!("unknown{index}.{suffix}"),
        };
        out.push((name, region[value_at..value_at + size].to_vec()));
        p += (16 + name_len + 3) & !3;
    }
    Ok(())
}

impl Fs {
    pub fn open(path: &Path) -> Result<Fs> {
        refuse_blocking_file(path)?;
        ensure!(
            !path.is_dir(),
            "{} is a directory, not an image",
            path.display()
        );
        let f = File::open(path).with_context(|| format!("opening {}", path.display()))?;
        Fs::new(Source::File(f))
    }

    #[cfg(test)]
    pub fn from_bytes(image: Vec<u8>) -> Result<Fs> {
        Fs::new(Source::Mem(image))
    }

    fn new(src: Source) -> Result<Fs> {
        let len = src.len()?;
        ensure!(len >= 2048, "too short to be an ext filesystem");
        let mut sb = vec![0u8; 1024];
        src.read_at(1024, &mut sb)
            .context("reading the superblock")?;
        ensure!(
            le16(&sb, 56) == EXT_MAGIC,
            "not an ext2/3/4 filesystem: bad magic"
        );
        let log = le32(&sb, 24) as u64;
        ensure!(log <= 6, "unsupported block size (log {log})");
        let bs = MIN_BLOCK << log;
        ensure!(
            (MIN_BLOCK..=MAX_BLOCK).contains(&bs),
            "unsupported block size {bs}"
        );
        let incompat = le32(&sb, 96);
        ensure!(
            incompat & INCOMPAT_COMPRESSION == 0,
            "compressed ext filesystems are not supported"
        );
        ensure!(
            incompat & INCOMPAT_JOURNAL_DEV == 0,
            "an ext journal device holds no files"
        );
        ensure!(
            incompat & INCOMPAT_META_BG == 0,
            "the meta_bg layout is not supported"
        );
        let blocks_per_group = le32(&sb, 32) as u64;
        let inodes_per_group = le32(&sb, 40);
        let inodes = le32(&sb, 0);
        ensure!(
            blocks_per_group > 0 && inodes_per_group > 0 && inodes > 0,
            "the superblock has zero group sizes"
        );
        ensure!(
            blocks_per_group <= 8 * bs,
            "{blocks_per_group} blocks per group does not fit a bitmap"
        );
        let rev = le32(&sb, 76);
        let inode_size = if rev == 0 { 128 } else { le16(&sb, 88) as u64 };
        ensure!(
            (128..=bs).contains(&inode_size) && inode_size.is_power_of_two(),
            "unsupported inode size {inode_size}"
        );
        let first_data_block = le32(&sb, 20) as u64;
        let mut blocks = le32(&sb, 4) as u64;
        let desc_size = if incompat & INCOMPAT_64BIT != 0 {
            blocks |= (le32(&sb, 336) as u64) << 32;
            let d = le16(&sb, 254) as u64;
            ensure!(
                (64..=1024).contains(&d) && d.is_power_of_two(),
                "unsupported group descriptor size {d}"
            );
            d
        } else {
            32
        };
        ensure!(
            blocks > first_data_block,
            "the superblock claims no data blocks"
        );
        let groups = (blocks - first_data_block).div_ceil(blocks_per_group);
        ensure!(
            groups <= MAX_GROUPS,
            "{groups} block groups is over the limit"
        );
        ensure!(
            (inodes as u64).div_ceil(inodes_per_group as u64) <= groups,
            "the superblock has more inodes than its groups hold"
        );
        let gdt = (first_data_block + 1) * bs;
        ensure!(
            gdt + groups * desc_size <= len,
            "the group descriptor table runs past the end of the image"
        );
        let mut raw = vec![0u8; (groups * desc_size) as usize];
        src.read_at(gdt, &mut raw)
            .context("reading the group descriptors")?;
        let itables = (0..groups as usize)
            .map(|g| {
                let d = &raw[g * desc_size as usize..];
                let mut t = le32(d, 8) as u64;
                if desc_size >= 64 {
                    t |= (le32(d, 0x28) as u64) << 32;
                }
                t
            })
            .collect();
        Ok(Fs {
            src,
            len,
            bs,
            inode_size,
            inodes,
            inodes_per_group,
            blocks,
            itables,
        })
    }

    fn read_exact(&self, off: u64, n: usize) -> Result<Vec<u8>> {
        let end = off.checked_add(n as u64).context("offset overflows")?;
        ensure!(
            end <= self.len,
            "read at {off} (+{n}) is past the end of the image ({} bytes)",
            self.len
        );
        let mut buf = vec![0u8; n];
        self.src
            .read_at(off, &mut buf)
            .with_context(|| format!("reading {n} bytes at {off}"))?;
        Ok(buf)
    }

    fn block(&self, n: u64) -> Result<Vec<u8>> {
        ensure!(
            n < self.blocks,
            "block {n} is beyond the filesystem ({} blocks)",
            self.blocks
        );
        self.read_exact(n * self.bs, self.bs as usize)
    }

    pub fn inode(&self, ino: u32) -> Result<Inode> {
        ensure!(
            ino >= 1 && ino <= self.inodes,
            "inode {ino} is out of range (1..={})",
            self.inodes
        );
        let idx = (ino - 1) as u64;
        let group = (idx / self.inodes_per_group as u64) as usize;
        ensure!(
            group < self.itables.len(),
            "inode {ino} is in group {group}, which does not exist"
        );
        let at = self.itables[group]
            .checked_mul(self.bs)
            .and_then(|t| t.checked_add((idx % self.inodes_per_group as u64) * self.inode_size))
            .with_context(|| format!("inode {ino} location overflows"))?;
        let raw = self
            .read_exact(at, self.inode_size as usize)
            .with_context(|| format!("reading inode {ino}"))?;
        let mode = le16(&raw, 0);
        let (mut uid, mut gid) = (le16(&raw, 2) as u32, le16(&raw, 24) as u32);
        uid |= (le16(&raw, 120) as u32) << 16;
        gid |= (le16(&raw, 122) as u32) << 16;
        let mut size = le32(&raw, 4) as u64;
        if mode & 0o170000 == 0o100000 {
            size |= (le32(&raw, 108) as u64) << 32;
        }
        let extra_isize = if self.inode_size > 128 {
            le16(&raw, 128) as usize
        } else {
            0
        };
        let mut mtime = le32(&raw, 16) as i64;
        if extra_isize >= 16 && self.inode_size >= 148 {
            mtime += ((le32(&raw, 140) & 3) as i64) << 32;
        }
        let mut block = [0u8; 60];
        block.copy_from_slice(&raw[40..100]);
        Ok(Inode {
            ino,
            mode,
            uid,
            gid,
            size,
            mtime,
            links: le16(&raw, 26),
            flags: le32(&raw, 32),
            block,
            file_acl: le32(&raw, 104) as u64 | ((le16(&raw, 118) as u64) << 32),
            tail: raw[128..].to_vec(),
            extra_isize,
        })
    }

    fn check_data_run(&self, pblk: u64, blocks: u64) -> Result<()> {
        let end = pblk.checked_add(blocks).context("extent end overflows")?;
        ensure!(
            end <= self.blocks,
            "blocks {pblk}..{end} are beyond the filesystem ({} blocks)",
            self.blocks
        );
        ensure!(
            end * self.bs <= self.len,
            "blocks {pblk}..{end} lie past the end of the image"
        );
        Ok(())
    }

    fn extent_runs(
        &self,
        node: &[u8],
        depth_left: Option<u16>,
        runs: &mut Vec<Run>,
        visited: &mut usize,
    ) -> Result<()> {
        ensure!(node.len() >= 12, "an extent node is too short");
        ensure!(
            le16(node, 0) == 0xF30A,
            "bad extent node magic {:#06x}",
            le16(node, 0)
        );
        let (entries, max, depth) = (
            le16(node, 2) as usize,
            le16(node, 4) as usize,
            le16(node, 6),
        );
        ensure!(
            depth <= MAX_EXTENT_DEPTH,
            "extent tree is {depth} levels deep"
        );
        if let Some(expect) = depth_left {
            ensure!(depth == expect, "extent tree depth is inconsistent");
        }
        ensure!(
            entries <= max && 12 + entries * 12 <= node.len(),
            "an extent node claims {entries} entries"
        );
        *visited += 1;
        ensure!(*visited <= MAX_TREE_NODES, "extent tree has too many nodes");
        for i in 0..entries {
            let e = &node[12 + i * 12..24 + i * 12];
            if depth == 0 {
                let (lblk, raw_len) = (le32(e, 0) as u64, le16(e, 4) as u64);
                let pblk = le32(e, 8) as u64 | ((le16(e, 6) as u64) << 32);
                let (len, written) = if raw_len > 32768 {
                    (raw_len - 32768, false)
                } else {
                    (raw_len, true)
                };
                if len == 0 {
                    continue;
                }
                if let Some(last) = runs.last() {
                    ensure!(
                        lblk >= last.lblk + last.blocks,
                        "extents are out of order or overlap at block {lblk}"
                    );
                }
                if written {
                    self.check_data_run(pblk, len)?;
                }
                ensure!(
                    runs.len() < MAX_RUNS,
                    "file has more than {MAX_RUNS} extents"
                );
                runs.push(Run {
                    lblk,
                    blocks: len,
                    pblk: written.then_some(pblk),
                });
            } else {
                let leaf = le32(e, 4) as u64 | ((le16(e, 8) as u64) << 32);
                let child = self.block(leaf).context("reading an extent tree node")?;
                self.extent_runs(&child, Some(depth - 1), runs, visited)?;
            }
        }
        Ok(())
    }

    fn map_pointers(
        &self,
        level: u32,
        blockno: u64,
        nblocks: u64,
        at: &mut u64,
        runs: &mut Vec<Run>,
        reads: &mut usize,
    ) -> Result<()> {
        *reads += 1;
        ensure!(
            *reads <= MAX_TREE_NODES,
            "block map has too many indirect blocks"
        );
        let data = self.block(blockno).context("reading an indirect block")?;
        let per = (self.bs / 4) as usize;
        let span = (self.bs / 4).pow(level - 1);
        for i in 0..per {
            if *at >= nblocks {
                break;
            }
            let p = le32(&data, i * 4) as u64;
            if p == 0 {
                *at = (*at + span).min(nblocks.max(*at));
                continue;
            }
            if level == 1 {
                self.push_block(p, *at, runs)?;
                *at += 1;
            } else {
                self.map_pointers(level - 1, p, nblocks, at, runs, reads)?;
            }
        }
        Ok(())
    }

    fn push_block(&self, p: u64, lblk: u64, runs: &mut Vec<Run>) -> Result<()> {
        self.check_data_run(p, 1)?;
        if let Some(last) = runs.last_mut()
            && last.pblk.is_some_and(|b| b + last.blocks == p)
            && last.lblk + last.blocks == lblk
        {
            last.blocks += 1;
            return Ok(());
        }
        ensure!(
            runs.len() < MAX_RUNS,
            "file has more than {MAX_RUNS} extents"
        );
        runs.push(Run {
            lblk,
            blocks: 1,
            pblk: Some(p),
        });
        Ok(())
    }

    fn runs(&self, inode: &Inode) -> Result<Vec<Run>> {
        ensure!(
            inode.flags & INODE_INLINE_DATA == 0,
            "inline_data files are not supported"
        );
        ensure!(
            inode.flags & INODE_ENCRYPT == 0,
            "encrypted files are not supported"
        );
        let mut runs = Vec::new();
        if inode.flags & INODE_EXTENTS != 0 {
            let mut visited = 0;
            self.extent_runs(&inode.block, None, &mut runs, &mut visited)?;
            return Ok(runs);
        }
        let nblocks = inode.size.div_ceil(self.bs);
        let mut at = 0u64;
        for i in 0..12usize {
            if at >= nblocks {
                return Ok(runs);
            }
            let p = le32(&inode.block, i * 4) as u64;
            if p != 0 {
                self.push_block(p, at, &mut runs)?;
            }
            at += 1;
        }
        let mut reads = 0;
        for (i, level) in [(12usize, 1u32), (13, 2), (14, 3)] {
            if at >= nblocks {
                break;
            }
            let p = le32(&inode.block, i * 4) as u64;
            let span = (self.bs / 4).pow(level);
            if p == 0 {
                at += span;
                continue;
            }
            self.map_pointers(level, p, nblocks, &mut at, &mut runs, &mut reads)?;
        }
        Ok(runs)
    }

    /// Write the file's logical contents to `out` (holes stay holes) and return their SHA-256.
    /// `out` must be empty; `budget` is reduced by the logical size.
    fn copy_data(&self, inode: &Inode, out: &mut File, budget: &mut u64) -> Result<String> {
        ensure!(
            inode.size <= MAX_FILE_BYTES,
            "a file of {} bytes is over the {MAX_FILE_BYTES}-byte limit",
            inode.size
        );
        ensure!(
            inode.size <= *budget,
            "the files add up to more than the {}-byte limit",
            *budget
        );
        *budget -= inode.size;
        let runs = if inode.size == 0 {
            Vec::new()
        } else {
            self.runs(inode)?
        };
        let mut hasher = Sha256::new();
        let zeros = vec![0u8; COPY_CHUNK];
        let feed_zeros = |h: &mut Sha256, mut n: u64| {
            while n > 0 {
                let k = n.min(COPY_CHUNK as u64) as usize;
                h.update(&zeros[..k]);
                n -= k as u64;
            }
        };
        let mut at = 0u64; // bytes hashed so far
        let mut buf = vec![0u8; COPY_CHUNK];
        for run in runs {
            let start = run.lblk * self.bs;
            if start >= inode.size {
                break;
            }
            ensure!(start >= at, "file blocks overlap at byte {start}");
            feed_zeros(&mut hasher, start - at);
            let bytes = (run.blocks * self.bs).min(inode.size - start);
            match run.pblk {
                None => feed_zeros(&mut hasher, bytes),
                Some(p) => {
                    out.seek(SeekFrom::Start(start))?;
                    let (mut done, base) = (0u64, p * self.bs);
                    while done < bytes {
                        let n = (bytes - done).min(COPY_CHUNK as u64) as usize;
                        self.src
                            .read_at(base + done, &mut buf[..n])
                            .context("reading file data")?;
                        out.write_all(&buf[..n])?;
                        hasher.update(&buf[..n]);
                        done += n as u64;
                    }
                }
            }
            at = start + bytes;
        }
        feed_zeros(&mut hasher, inode.size - at);
        out.set_len(inode.size)?;
        Ok(hasher
            .finalize()
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect())
    }

    /// The directory entries of `dir` as `(name, inode number)`, without `.` and `..`.
    fn dir_entries(&self, dir: &Inode) -> Result<Vec<(String, u32)>> {
        let runs = self.runs(dir)?;
        let mut out = Vec::new();
        let bs = self.bs as usize;
        for run in runs {
            let Some(pblk) = run.pblk else { continue };
            for k in 0..run.blocks {
                if (run.lblk + k) * self.bs >= dir.size {
                    return Ok(out);
                }
                let data = self.block(pblk + k)?;
                let mut p = 0;
                while p + 8 <= bs {
                    let (ino, raw_len) = (le32(&data, p), le16(&data, p + 4) as usize);
                    let name_len = data[p + 6] as usize;
                    let rec = if raw_len == 0 || raw_len == 65535 {
                        bs
                    } else {
                        (raw_len & 0xFFFC) | ((raw_len & 3) << 16)
                    };
                    ensure!(
                        rec >= 8 && rec % 4 == 0 && p + rec <= bs && 8 + name_len <= rec,
                        "a directory entry has an invalid length {rec}"
                    );
                    if ino != 0 {
                        let name = &data[p + 8..p + 8 + name_len];
                        if name != b"." && name != b".." {
                            ensure!(
                                !name.is_empty() && !name.contains(&b'/') && !name.contains(&0),
                                "a directory entry has an invalid name"
                            );
                            ensure!(
                                out.len() < MAX_ENTRIES,
                                "a directory has more than {MAX_ENTRIES} entries"
                            );
                            out.push((name_string(name), ino));
                        }
                    }
                    p += rec;
                }
            }
        }
        Ok(out)
    }

    fn xattrs_of(&self, inode: &Inode) -> Result<Vec<(String, String)>> {
        let mut raw = Vec::new();
        let start = inode.extra_isize;
        if self.inode_size > 128
            && 128 + start + 4 <= self.inode_size as usize
            && start <= inode.tail.len()
        {
            let region = &inode.tail[start..];
            if region.len() >= 4 && le32(region, 0) == XATTR_MAGIC {
                parse_xattrs(region, 4, 4, &mut raw)?;
            }
        }
        if inode.file_acl != 0 {
            let blk = self
                .block(inode.file_acl)
                .context("reading the extended attribute block")?;
            if le32(&blk, 0) == XATTR_MAGIC {
                parse_xattrs(&blk, 32, 0, &mut raw)?;
            }
        }
        raw.sort_by(|a, b| a.0.cmp(&b.0));
        Ok(raw.into_iter().map(|(k, v)| (k, xattr_text(&v))).collect())
    }

    fn symlink_target(&self, inode: &Inode) -> Result<String> {
        ensure!(
            inode.size <= MAX_SYMLINK,
            "a symlink target of {} bytes is not valid",
            inode.size
        );
        let n = inode.size as usize;
        if inode.flags & (INODE_EXTENTS | INODE_INLINE_DATA) == 0 && n < 60 {
            return Ok(name_string(&inode.block[..n]));
        }
        ensure!(
            inode.flags & INODE_INLINE_DATA == 0,
            "inline_data symlinks are not supported"
        );
        let mut bytes = Vec::with_capacity(n);
        for run in self.runs(inode)? {
            let Some(p) = run.pblk else {
                bail!("a symlink target has a hole")
            };
            for k in 0..run.blocks {
                if bytes.len() >= n {
                    break;
                }
                bytes.extend(self.block(p + k)?);
            }
        }
        ensure!(
            bytes.len() >= n,
            "a symlink target is shorter than its size"
        );
        bytes.truncate(n);
        Ok(name_string(&bytes))
    }

    fn entry_of(&self, path: String, inode: &Inode, kind: Kind) -> Result<Entry> {
        let rdev = matches!(kind, Kind::CharDevice | Kind::BlockDevice).then(|| {
            let (b0, b1) = (le32(&inode.block, 0), le32(&inode.block, 4));
            if b0 != 0 {
                ((b0 >> 8) & 0xFF, b0 & 0xFF)
            } else {
                ((b1 & 0xFFF00) >> 8, (b1 & 0xFF) | ((b1 >> 12) & 0xFFF00))
            }
        });
        Ok(Entry {
            path,
            kind,
            mode: inode.mode as u32 & 0o7777,
            uid: inode.uid,
            gid: inode.gid,
            size: if kind == Kind::File { inode.size } else { 0 },
            mtime: inode.mtime,
            ino: inode.ino as u64,
            nlink: inode.links as u32,
            link: if kind == Kind::Symlink {
                Some(self.symlink_target(inode)?)
            } else {
                None
            },
            rdev,
            xattrs: self.xattrs_of(inode)?,
            sha256: None,
            extracted_as: None,
        })
    }

    /// Resolve `path` to its entry without following symlinks ("" or "/" is the root).
    pub fn lookup(&self, path: &str) -> Result<(Entry, Inode)> {
        let mut inode = self.inode(2).context("reading the root directory")?;
        let mut at = String::new();
        for part in path.split('/').filter(|p| !p.is_empty() && *p != ".") {
            ensure!(part != "..", "paths containing .. are not accepted");
            let here = if at.is_empty() {
                "/".to_string()
            } else {
                format!("/{at}")
            };
            ensure!(
                Kind::from_mode(inode.mode) == Some(Kind::Dir),
                "{} is not a directory (symlinks are not followed)",
                short(&here)
            );
            let found = self
                .dir_entries(&inode)?
                .into_iter()
                .find(|(n, _)| n == part);
            let (_, ino) =
                found.with_context(|| format!("{} not found in {}", short(part), short(&here)))?;
            inode = self.inode(ino)?;
            at = if at.is_empty() {
                part.to_string()
            } else {
                format!("{at}/{part}")
            };
        }
        let kind = Kind::from_mode(inode.mode)
            .with_context(|| format!("unknown file type in mode {:#o}", inode.mode))?;
        Ok((self.entry_of(at, &inode, kind)?, inode))
    }

    /// The entries of the directory at `path` (not recursive), or the entry itself for a file.
    pub fn list_dir(&self, path: &str) -> Result<Vec<(Entry, Inode)>> {
        let (entry, inode) = self.lookup(path)?;
        if entry.kind != Kind::Dir {
            return Ok(vec![(entry, inode)]);
        }
        let mut children = self.dir_entries(&inode)?;
        children.sort();
        children
            .into_iter()
            .map(|(name, ino)| {
                let child = self.inode(ino)?;
                let kind = Kind::from_mode(child.mode)
                    .with_context(|| format!("{}: unknown file type", short(&name)))?;
                let p = if entry.path.is_empty() {
                    name
                } else {
                    format!("{}/{name}", entry.path)
                };
                Ok((self.entry_of(p, &child, kind)?, child))
            })
            .collect()
    }

    /// Write a regular file's contents to `out` (holes as zeros).
    pub fn cat(&self, inode: &Inode, out: &mut dyn Write) -> Result<()> {
        ensure!(
            Kind::from_mode(inode.mode) == Some(Kind::File),
            "not a regular file"
        );
        ensure!(
            inode.size <= MAX_FILE_BYTES,
            "a file of {} bytes is over the {MAX_FILE_BYTES}-byte limit",
            inode.size
        );
        let runs = if inode.size == 0 {
            Vec::new()
        } else {
            self.runs(inode)?
        };
        let zeros = vec![0u8; COPY_CHUNK];
        let zero_fill = |out: &mut dyn Write, mut n: u64| -> Result<()> {
            while n > 0 {
                let k = n.min(COPY_CHUNK as u64) as usize;
                out.write_all(&zeros[..k])?;
                n -= k as u64;
            }
            Ok(())
        };
        let (mut at, mut buf) = (0u64, vec![0u8; COPY_CHUNK]);
        for run in runs {
            let start = run.lblk * self.bs;
            if start >= inode.size {
                break;
            }
            ensure!(start >= at, "file blocks overlap at byte {start}");
            zero_fill(out, start - at)?;
            let bytes = (run.blocks * self.bs).min(inode.size - start);
            match run.pblk {
                None => zero_fill(out, bytes)?,
                Some(p) => {
                    let (mut done, base) = (0u64, p * self.bs);
                    while done < bytes {
                        let n = (bytes - done).min(COPY_CHUNK as u64) as usize;
                        self.src
                            .read_at(base + done, &mut buf[..n])
                            .context("reading file data")?;
                        out.write_all(&buf[..n])?;
                        done += n as u64;
                    }
                }
            }
            at = start + bytes;
        }
        zero_fill(out, inode.size - at)
    }

    /// Every entry of the tree below the root (not the root itself), sorted by path. No file
    /// contents are read.
    pub fn entries(&self) -> Result<Vec<(Entry, Inode)>> {
        let root = self.inode(2).context("reading the root directory")?;
        ensure!(
            Kind::from_mode(root.mode) == Some(Kind::Dir),
            "inode 2 is not a directory"
        );
        let mut out: Vec<(Entry, Inode)> = Vec::new();
        let mut seen_dirs: HashSet<u32> = HashSet::from([2]);
        let mut stack = vec![(root, String::new(), 0usize)];
        while let Some((dir, prefix, depth)) = stack.pop() {
            ensure!(
                depth < MAX_DEPTH,
                "directories are nested more than {MAX_DEPTH} deep"
            );
            let mut children = self
                .dir_entries(&dir)
                .with_context(|| format!("reading directory {}", short(&format!("/{prefix}"))))?;
            children.sort();
            for (name, ino) in children {
                let path = if prefix.is_empty() {
                    name
                } else {
                    format!("{prefix}/{name}")
                };
                ensure!(
                    path.len() <= MAX_PATH,
                    "a path is longer than {MAX_PATH} bytes"
                );
                ensure!(
                    out.len() < MAX_ENTRIES,
                    "the image has more than {MAX_ENTRIES} entries"
                );
                let inode = self
                    .inode(ino)
                    .with_context(|| format!("entry {}", short(&path)))?;
                ensure!(
                    inode.mode != 0 && inode.links != 0,
                    "{} points to an unused inode ({ino})",
                    short(&path)
                );
                let kind = Kind::from_mode(inode.mode).with_context(|| {
                    format!(
                        "{}: unknown file type in mode {:#o}",
                        short(&path),
                        inode.mode
                    )
                })?;
                if kind == Kind::Dir {
                    ensure!(
                        seen_dirs.insert(ino),
                        "directory inode {ino} is reachable twice ({}): a loop",
                        short(&path)
                    );
                    stack.push((inode.clone(), path.clone(), depth + 1));
                }
                let entry = self
                    .entry_of(path.clone(), &inode, kind)
                    .with_context(|| format!("entry {}", short(&path)))?;
                out.push((entry, inode));
            }
        }
        out.sort_by(|a, b| a.0.path.cmp(&b.0.path));
        Ok(out)
    }
}

impl Fs {
    /// Extract the tree under `out_dir/files` with `manifest.json` beside it, all or nothing.
    pub fn extract(&self, out_dir: &Path, collisions: Option<Collisions>) -> Result<Vec<Entry>> {
        crate::tree::extract(self, out_dir, collisions)
    }
}

impl TreeSource for Fs {
    type Node = Inode;

    fn image_len(&self) -> u64 {
        self.len
    }

    fn entries(&self) -> Result<Vec<(Entry, Inode)>> {
        Fs::entries(self)
    }

    fn copy_data(&self, node: &Inode, out: &mut File, budget: &mut u64) -> Result<String> {
        Fs::copy_data(self, node, out, budget)
    }

    fn list_dir(&self, path: &str) -> Result<Vec<Entry>> {
        Ok(Fs::list_dir(self, path)?
            .into_iter()
            .map(|(e, _)| e)
            .collect())
    }

    fn cat_path(&self, path: &str, out: &mut dyn Write) -> Result<()> {
        let (entry, inode) = self.lookup(path)?;
        check_cat(&entry)?;
        self.cat(&inode, out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tree::manifest;
    use crate::treeout::host_collisions;
    use serde_json::{Value, json};

    const BS: usize = 1024;
    const BLOCKS: usize = 512;
    const ITABLE: usize = 5;

    /// A tiny single-group ext image built by hand (1 KiB blocks).
    struct Img {
        img: Vec<u8>,
        isz: usize,
        next: usize,
        extents: bool,
    }

    fn put16(b: &mut [u8], at: usize, v: u16) {
        b[at..at + 2].copy_from_slice(&v.to_le_bytes());
    }
    fn put32(b: &mut [u8], at: usize, v: u32) {
        b[at..at + 4].copy_from_slice(&v.to_le_bytes());
    }

    impl Img {
        fn new(isz: usize, extents: bool) -> Img {
            let mut img = vec![0u8; BLOCKS * BS];
            let sb = &mut img[1024..2048];
            put32(sb, 0, 64); // inodes
            put32(sb, 4, BLOCKS as u32);
            put32(sb, 20, 1); // first data block
            put32(sb, 32, 8192); // blocks per group
            put32(sb, 40, 64); // inodes per group
            put16(sb, 56, 0xEF53);
            put32(sb, 76, 1);
            put16(sb, 88, isz as u16);
            put32(sb, 96, 0x2 | if extents { 0x40 } else { 0 });
            put32(&mut img, 2048 + 8, ITABLE as u32);
            let next = ITABLE + 64 * isz / BS + 1;
            Img {
                img,
                isz,
                next,
                extents,
            }
        }

        fn alloc(&mut self, data: &[u8]) -> Vec<u32> {
            let mut out = Vec::new();
            for chunk in data.chunks(BS) {
                let b = self.next;
                self.next += 1;
                self.img[b * BS..b * BS + chunk.len()].copy_from_slice(chunk);
                out.push(b as u32);
            }
            out
        }

        fn inode(
            &mut self,
            ino: u32,
            mode: u16,
            size: u64,
            links: u16,
            flags: u32,
            block: [u8; 60],
        ) {
            let at = ITABLE * BS + (ino as usize - 1) * self.isz;
            let r = &mut self.img[at..at + self.isz];
            put16(r, 0, mode);
            put32(r, 4, size as u32);
            put32(r, 16, 1_000_000);
            put16(r, 26, links);
            put32(r, 32, flags);
            r[40..100].copy_from_slice(&block);
            put32(r, 108, (size >> 32) as u32);
            if self.isz > 128 {
                put16(r, 128, 32);
            }
        }

        fn raw(&mut self, ino: u32) -> &mut [u8] {
            let at = ITABLE * BS + (ino as usize - 1) * self.isz;
            &mut self.img[at..at + self.isz]
        }

        /// A block map or extent list for `blocks` (logical block i -> physical; 0 = hole).
        fn mapping(&mut self, blocks: &[u32]) -> ([u8; 60], u32) {
            let mut b = [0u8; 60];
            if self.extents {
                put16(&mut b, 0, 0xF30A);
                let mut n = 0;
                let mut i = 0;
                while i < blocks.len() {
                    if blocks[i] == 0 {
                        i += 1;
                        continue;
                    }
                    let mut j = i;
                    while j + 1 < blocks.len() && blocks[j + 1] == blocks[j] + 1 {
                        j += 1;
                    }
                    let e = 12 + n * 12;
                    put32(&mut b, e, i as u32);
                    put16(&mut b, e + 4, (j - i + 1) as u16);
                    put32(&mut b, e + 8, blocks[i]);
                    n += 1;
                    i = j + 1;
                }
                put16(&mut b, 2, n as u16);
                put16(&mut b, 4, 4);
                (b, INODE_EXTENTS)
            } else {
                for (i, p) in blocks.iter().take(12).enumerate() {
                    put32(&mut b, i * 4, *p);
                }
                if blocks.len() > 12 {
                    let mut ind = vec![0u8; BS];
                    for (i, p) in blocks[12..].iter().enumerate() {
                        put32(&mut ind, i * 4, *p);
                    }
                    let at = self.alloc(&ind)[0];
                    put32(&mut b, 48, at);
                }
                (b, 0)
            }
        }

        fn file(&mut self, ino: u32, mode: u16, data: &[u8], links: u16) {
            let mut blocks = self.alloc(data);
            if data.is_empty() {
                blocks.clear();
            }
            let (b, f) = self.mapping(&blocks);
            self.inode(ino, 0o100000 | mode, data.len() as u64, links, f, b);
        }

        fn dir(&mut self, ino: u32, parent: u32, entries: &[(&str, u32, u8)]) {
            let mut all: Vec<(&str, u32, u8)> = vec![(".", ino, 2), ("..", parent, 2)];
            all.extend_from_slice(entries);
            let mut data = vec![0u8; BS];
            let mut p = 0;
            for (i, (name, n, t)) in all.iter().enumerate() {
                let need = (8 + name.len() + 3) & !3;
                let rec = if i + 1 == all.len() { BS - p } else { need };
                put32(&mut data, p, *n);
                put16(&mut data, p + 4, rec as u16);
                data[p + 6] = name.len() as u8;
                data[p + 7] = *t;
                data[p + 8..p + 8 + name.len()].copy_from_slice(name.as_bytes());
                p += rec;
            }
            let blocks = self.alloc(&data);
            let (b, f) = self.mapping(&blocks);
            self.inode(ino, 0o040755, BS as u64, 2, f, b);
        }

        fn symlink(&mut self, ino: u32, target: &str) {
            if target.len() < 60 {
                let mut b = [0u8; 60];
                b[..target.len()].copy_from_slice(target.as_bytes());
                self.inode(ino, 0o120777, target.len() as u64, 1, 0, b);
            } else {
                let blocks = self.alloc(target.as_bytes());
                let (b, f) = self.mapping(&blocks);
                self.inode(ino, 0o120777, target.len() as u64, 1, f, b);
            }
        }

        /// Attach an in-inode attribute (needs 256-byte inodes).
        fn ibody_xattr(&mut self, ino: u32, index: u8, name: &str, value: &[u8]) {
            let start = 128 + 32;
            let isz = self.isz;
            let r = self.raw(ino);
            put32(r, start, XATTR_MAGIC);
            let region = start + 4;
            let off = (isz - region) - ((value.len() + 3) & !3); // value at the end of the inode
            r[region] = name.len() as u8;
            r[region + 1] = index;
            put16(r, region + 2, off as u16);
            put32(r, region + 8, value.len() as u32);
            r[region + 16..region + 16 + name.len()].copy_from_slice(name.as_bytes());
            r[region + off..region + off + value.len()].copy_from_slice(value);
        }

        fn block_xattr(&mut self, ino: u32, index: u8, name: &str, value: &[u8]) {
            let mut b = vec![0u8; BS];
            put32(&mut b, 0, XATTR_MAGIC);
            put32(&mut b, 4, 1);
            put32(&mut b, 8, 1);
            b[32] = name.len() as u8;
            b[33] = index;
            put16(&mut b, 34, 900);
            put32(&mut b, 40, value.len() as u32);
            b[48..48 + name.len()].copy_from_slice(name.as_bytes());
            b[900..900 + value.len()].copy_from_slice(value);
            let at = self.alloc(&b)[0];
            put32(self.raw(ino), 104, at);
        }

        fn fs(&self) -> Fs {
            Fs::from_bytes(self.img.clone()).unwrap()
        }
    }

    /// root: a (file), d/ (dir with b, c), hard (link to a), s (fast link), l (slow link), empty
    fn sample(isz: usize, extents: bool) -> Img {
        let mut m = Img::new(isz, extents);
        m.file(11, 0o644, b"hello\n", 2);
        m.dir(12, 2, &[("b", 13, 1), ("c", 14, 1)]);
        m.file(13, 0o600, &vec![7u8; 5000], 1);
        let mut with_hole = vec![1u8; 20 * BS];
        with_hole[3 * BS..6 * BS].fill(0);
        // block 3..6 stay zero on disk by being holes
        let mut blocks = m.alloc(&with_hole);
        for b in &mut blocks[3..6] {
            *b = 0;
        }
        let (map, f) = m.mapping(&blocks);
        m.inode(14, 0o100644, with_hole.len() as u64, 1, f, map);
        m.symlink(15, "a");
        m.symlink(16, &"x".repeat(100));
        m.file(17, 0o444, b"", 1);
        m.dir(
            2,
            2,
            &[
                ("a", 11, 1),
                ("d", 12, 2),
                ("hard", 11, 1),
                ("s", 15, 7),
                ("l", 16, 7),
                ("empty", 17, 1),
            ],
        );
        m
    }

    fn scratch(tag: &str) -> crate::testutil::Scratch {
        crate::testutil::Scratch::new(&format!("ext4-{tag}"))
    }

    fn sha(b: &[u8]) -> String {
        Sha256::digest(b)
            .iter()
            .map(|x| format!("{x:02x}"))
            .collect()
    }

    fn by_path<'a>(v: &'a [(Entry, Inode)], p: &str) -> &'a Entry {
        &v.iter()
            .find(|(e, _)| e.path == p)
            .unwrap_or_else(|| panic!("no {p}"))
            .0
    }

    fn check_tree(isz: usize, extents: bool) {
        let m = sample(isz, extents);
        let fs = m.fs();
        let list = fs.entries().unwrap();
        let paths: Vec<_> = list.iter().map(|(e, _)| e.path.as_str()).collect();
        assert_eq!(paths, ["a", "d", "d/b", "d/c", "empty", "hard", "l", "s"]);
        assert_eq!(by_path(&list, "s").link.as_deref(), Some("a"));
        assert_eq!(
            by_path(&list, "l").link.as_deref(),
            Some("x".repeat(100).as_str())
        );
        assert_eq!(by_path(&list, "d").kind, Kind::Dir);
        assert_eq!(by_path(&list, "a").nlink, 2);
        assert_eq!(by_path(&list, "d/b").mode, 0o600);
        assert_eq!(by_path(&list, "d/c").size, 20 * BS as u64);

        let dir = scratch(&format!("tree{isz}{extents}"));
        let out = dir.join("out");
        let entries = fs.extract(&out, Some(Collisions::Allow)).unwrap();
        let files = out.join("files");
        assert_eq!(std::fs::read(files.join("a")).unwrap(), b"hello\n");
        assert_eq!(std::fs::read(files.join("hard")).unwrap(), b"hello\n");
        assert_eq!(std::fs::read(files.join("d/b")).unwrap(), vec![7u8; 5000]);
        let mut want = vec![1u8; 20 * BS];
        want[3 * BS..6 * BS].fill(0);
        assert_eq!(
            std::fs::read(files.join("d/c")).unwrap(),
            want,
            "holes read as zeros"
        );
        assert_eq!(std::fs::read(files.join("empty")).unwrap(), b"");
        assert!(
            files.join("s").symlink_metadata().is_err(),
            "symlinks are recorded, never created"
        );
        let e = |p: &str| entries.iter().find(|e| e.path == p).unwrap();
        assert_eq!(e("a").sha256.as_deref(), Some(sha(b"hello\n").as_str()));
        assert_eq!(e("hard").sha256, e("a").sha256);
        assert_eq!(e("d/c").sha256.as_deref(), Some(sha(&want).as_str()));
        assert_eq!(e("empty").sha256.as_deref(), Some(sha(b"").as_str()));
        let manifest: Value =
            serde_json::from_slice(&std::fs::read(out.join("manifest.json")).unwrap()).unwrap();
        assert_eq!(manifest["summary"]["entries"], 8);
        assert_eq!(manifest["summary"]["by_type"]["symlink"], 2);
    }

    #[test]
    fn classic_block_map_256_byte_inodes() {
        check_tree(256, false);
    }

    #[test]
    fn classic_block_map_128_byte_inodes() {
        check_tree(128, false);
    }

    #[test]
    fn extents_256_byte_inodes() {
        check_tree(256, true);
    }

    #[test]
    fn extents_128_byte_inodes() {
        check_tree(128, true);
    }

    #[cfg(unix)]
    #[test]
    fn hardlinks_share_content_and_zero_mode_files_stay_readable() {
        use std::os::unix::fs::PermissionsExt;
        let mut m = Img::new(256, true);
        m.file(11, 0o000, b"x", 1);
        m.dir(2, 2, &[("z", 11, 1)]);
        let dir = scratch("zeromode");
        m.fs()
            .extract(&dir.join("out"), Some(Collisions::Allow))
            .unwrap();
        let p = dir.join("out/files/z");
        assert_eq!(
            std::fs::metadata(&p).unwrap().permissions().mode() & 0o777,
            0o600
        );
        let man: Value =
            serde_json::from_slice(&std::fs::read(dir.join("out/manifest.json")).unwrap()).unwrap();
        assert_eq!(
            man["entries"][0]["mode"], 0,
            "the manifest keeps the real mode"
        );
    }

    #[test]
    fn xattrs_from_the_inode_and_from_a_block() {
        let mut m = sample(256, true);
        m.ibody_xattr(11, 6, "selinux", b"u:object_r:system_file:s0\0");
        m.block_xattr(13, 6, "capability", &[1, 0, 0, 2, 0, 0, 0, 0]);
        m.block_xattr(14, 1, "note", b"hi");
        let list = m.fs().entries().unwrap();
        assert_eq!(
            by_path(&list, "a").xattrs,
            [(
                "security.selinux".to_string(),
                "u:object_r:system_file:s0".to_string()
            )]
        );
        assert_eq!(
            by_path(&list, "d/b").xattrs,
            [(
                "security.capability".to_string(),
                "hex:0100000200000000".to_string()
            )]
        );
        assert_eq!(
            by_path(&list, "d/c").xattrs,
            [("user.note".to_string(), "hi".to_string())]
        );
        assert!(
            by_path(&list, "hard").xattrs.len() == 1,
            "a hardlink name shows its inode's attributes"
        );
    }

    #[test]
    fn a_128_byte_inode_has_no_in_inode_attributes_and_does_not_panic() {
        let m = sample(128, false);
        assert!(
            m.fs()
                .entries()
                .unwrap()
                .iter()
                .all(|(e, _)| e.xattrs.is_empty())
        );
    }

    #[test]
    fn case_collisions_follow_the_policy() {
        let mut m = Img::new(256, true);
        m.file(11, 0o644, b"one", 1);
        m.file(12, 0o644, b"two", 1);
        m.dir(2, 2, &[("Name", 11, 1), ("name", 12, 1)]);
        let dir = scratch("case");
        let e = m
            .fs()
            .extract(&dir.join("rename"), Some(Collisions::Rename))
            .unwrap();
        let second = e.iter().find(|e| e.path == "name").unwrap();
        assert_eq!(second.extracted_as.as_deref(), Some("name~case2"));
        assert_eq!(
            std::fs::read(dir.join("rename/files/Name")).unwrap(),
            b"one"
        );
        assert_eq!(
            std::fs::read(dir.join("rename/files/name~case2")).unwrap(),
            b"two"
        );
        let err = format!(
            "{:#}",
            m.fs()
                .extract(&dir.join("reject"), Some(Collisions::Reject))
                .unwrap_err()
        );
        assert!(err.contains("differs only by case"), "{err}");
        assert!(!dir.join("reject").exists(), "all or nothing");
        if host_collisions(&dir) == Collisions::Allow {
            m.fs()
                .extract(&dir.join("allow"), Some(Collisions::Allow))
                .unwrap();
            assert_eq!(std::fs::read(dir.join("allow/files/name")).unwrap(), b"two");
        }
    }

    #[test]
    fn a_directory_that_contains_itself_is_a_loop() {
        let mut m = sample(256, true);
        m.dir(12, 2, &[("again", 12, 2)]);
        let e = format!("{:#}", m.fs().entries().unwrap_err());
        assert!(e.contains("loop"), "{e}");
    }

    #[test]
    fn refuses_bad_images_clearly() {
        let good = sample(256, true).img;
        let mut bad_magic = good.clone();
        bad_magic[1024 + 56] = 0;
        assert!(format!("{:#}", Fs::from_bytes(bad_magic).err().unwrap()).contains("bad magic"));
        assert!(Fs::from_bytes(good[..1500].to_vec()).is_err());
        assert!(Fs::from_bytes(Vec::new()).is_err());
        let mut huge_bs = good.clone();
        put32(&mut huge_bs, 1024 + 24, 30);
        assert!(Fs::from_bytes(huge_bs).is_err());
        let mut meta_bg = good.clone();
        put32(&mut meta_bg, 1024 + 96, 0x10);
        assert!(format!("{:#}", Fs::from_bytes(meta_bg).err().unwrap()).contains("meta_bg"));
        let mut zero = good.clone();
        put32(&mut zero, 1024 + 40, 0);
        assert!(Fs::from_bytes(zero).is_err());
        let mut tail_cut = good;
        tail_cut.truncate(100 * BS); // the group table is fine but data blocks are gone
        let fs = Fs::from_bytes(tail_cut).unwrap();
        assert!(fs.entries().is_err() || fs.entries().is_ok());
    }

    #[test]
    fn an_extent_past_the_image_or_out_of_order_is_an_error() {
        let mut m = sample(256, true);
        let r = m.raw(13);
        put32(r, 40 + 12 + 8, 100_000); // physical block far beyond the filesystem
        assert!(m.fs().entries().is_ok(), "listing reads no file data");
        let dir = scratch("badextent");
        let e = format!(
            "{:#}",
            m.fs()
                .extract(&dir.join("o"), Some(Collisions::Allow))
                .unwrap_err()
        );
        assert!(e.contains("beyond the filesystem"), "{e}");
        assert!(!dir.join("o").exists() && !dir.join("o.part").exists());
    }

    #[test]
    fn an_absurd_file_size_is_refused_without_reading() {
        let mut m = sample(256, true);
        put32(m.raw(13), 108, 0x100); // 1 TiB
        let dir = scratch("bigfile");
        let e = format!(
            "{:#}",
            m.fs()
                .extract(&dir.join("o"), Some(Collisions::Allow))
                .unwrap_err()
        );
        assert!(e.contains("limit"), "{e}");
    }

    #[test]
    fn corrupting_any_metadata_byte_never_panics_or_hangs() {
        let m = sample(256, true);
        let m2 = sample(128, false);
        let (mut ok, mut err) = (0, 0);
        let mut sink = tempfile_like();
        for base in [&m.img, &m2.img] {
            let isz = if std::ptr::eq(base, &m.img) { 256 } else { 128 };
            let itable = ITABLE * BS;
            let data = (ITABLE + 64 * isz / BS + 1) * BS;
            // superblock fields, the first group descriptor, the first 20 inodes, and the data
            // blocks of the root and `d` directories
            let spots = (1024..1180)
                .chain(2048..2080)
                .chain(itable..itable + 20 * isz)
                .chain(data..data + 4 * BS);
            for at in spots {
                for v in [0x00u8, 0xFF] {
                    if base[at] == v {
                        continue;
                    }
                    let mut img = base.clone();
                    img[at] = v;
                    match Fs::from_bytes(img).and_then(|f| {
                        let list = f.entries()?;
                        let mut budget = 1 << 24;
                        for (e, i) in &list {
                            if e.kind == Kind::File {
                                sink.set_len(0)?;
                                f.copy_data(i, &mut sink, &mut budget)?;
                            }
                        }
                        Ok(())
                    }) {
                        Ok(()) => ok += 1,
                        Err(_) => err += 1,
                    }
                }
            }
        }
        assert!(
            ok > 1000 && err > 200,
            "both outcomes expected, got ok={ok} err={err}"
        );
    }

    /// An extent-mapped regular file with hand-written leaf entries `(lblk, raw_len, pblk)`.
    fn extent_file(m: &mut Img, ino: u32, size: u64, entries: &[(u32, u16, u32)]) {
        let mut b = [0u8; 60];
        put16(&mut b, 0, 0xF30A);
        put16(&mut b, 2, entries.len() as u16);
        put16(&mut b, 4, 4);
        for (i, (l, n, p)) in entries.iter().enumerate() {
            put32(&mut b, 12 + i * 12, *l);
            put16(&mut b, 12 + i * 12 + 4, *n);
            put32(&mut b, 12 + i * 12 + 8, *p);
        }
        m.inode(ino, 0o100644, size, 1, INODE_EXTENTS, b);
    }

    fn extract_err(m: &Img, tag: &str) -> String {
        let dir = scratch(tag);
        format!(
            "{:#}",
            m.fs()
                .extract(&dir.join("o"), Some(Collisions::Allow))
                .unwrap_err()
        )
    }

    fn one_file(m: &mut Img, ino: u32, name: &'static str) {
        m.dir(2, 2, &[(name, ino, 1)]);
    }

    #[test]
    fn owner_ids_use_the_high_halves() {
        let mut m = sample(256, true);
        let r = m.raw(11);
        put16(r, 2, 0x1234);
        put16(r, 120, 0x0001);
        put16(r, 24, 0x5678);
        put16(r, 122, 0x0002);
        let list = m.fs().entries().unwrap();
        assert_eq!(by_path(&list, "a").uid, 0x1_1234);
        assert_eq!(by_path(&list, "a").gid, 0x2_5678);
    }

    #[test]
    fn a_file_with_a_trailing_hole_keeps_its_length_and_hash() {
        let mut m = Img::new(256, true);
        let at = m.alloc(b"head")[0];
        extent_file(&mut m, 11, 3 * BS as u64 + 10, &[(0, 1, at)]); // blocks 1..3 and the tail are a hole
        one_file(&mut m, 11, "f");
        let dir = scratch("trailhole");
        let e = m
            .fs()
            .extract(&dir.join("o"), Some(Collisions::Allow))
            .unwrap();
        let mut want = vec![0u8; 3 * BS + 10];
        want[..4].copy_from_slice(b"head");
        let got = std::fs::read(dir.join("o/files/f")).unwrap();
        assert_eq!(got.len(), want.len());
        assert_eq!(got, want);
        assert_eq!(e[0].sha256.as_deref(), Some(sha(&want).as_str()));
    }

    #[test]
    fn unwritten_extents_read_as_zeros_even_when_the_blocks_hold_data() {
        let mut m = Img::new(256, true);
        let at = m.alloc(&vec![9u8; 2 * BS])[0];
        // length 32768 + 2 marks the extent as allocated but never written
        extent_file(&mut m, 11, 2 * BS as u64, &[(0, 32770, at)]);
        one_file(&mut m, 11, "f");
        let dir = scratch("unwritten");
        let e = m
            .fs()
            .extract(&dir.join("o"), Some(Collisions::Allow))
            .unwrap();
        assert_eq!(
            std::fs::read(dir.join("o/files/f")).unwrap(),
            vec![0u8; 2 * BS]
        );
        assert_eq!(
            e[0].sha256.as_deref(),
            Some(sha(&vec![0u8; 2 * BS]).as_str())
        );
    }

    #[test]
    fn overlapping_or_unordered_extents_are_refused() {
        let mut m = Img::new(256, true);
        let at = m.alloc(&vec![1u8; 4 * BS])[0];
        extent_file(&mut m, 11, 4 * BS as u64, &[(0, 2, at), (1, 2, at + 1)]);
        one_file(&mut m, 11, "f");
        assert!(extract_err(&m, "overlap").contains("out of order or overlap"));
    }

    #[test]
    fn a_two_level_extent_tree_is_followed_and_bad_trees_are_refused() {
        let mut m = Img::new(256, true);
        let d0 = m.alloc(b"first")[0];
        let d1 = m.alloc(b"second")[0];
        let mut leaf = vec![0u8; BS];
        put16(&mut leaf, 0, 0xF30A);
        put16(&mut leaf, 2, 2);
        put16(&mut leaf, 4, 84);
        put32(&mut leaf, 12, 0);
        put16(&mut leaf, 16, 1);
        put32(&mut leaf, 20, d0);
        put32(&mut leaf, 24, 1);
        put16(&mut leaf, 28, 1);
        put32(&mut leaf, 32, d1);
        let leaf_at = m.alloc(&leaf)[0];
        let mut b = [0u8; 60];
        put16(&mut b, 0, 0xF30A);
        put16(&mut b, 2, 1);
        put16(&mut b, 4, 4);
        put16(&mut b, 6, 1); // depth 1: one index entry
        put32(&mut b, 12 + 4, leaf_at);
        m.inode(11, 0o100644, BS as u64 + 6, 1, INODE_EXTENTS, b);
        one_file(&mut m, 11, "f");
        let dir = scratch("depth1");
        m.fs()
            .extract(&dir.join("o"), Some(Collisions::Allow))
            .unwrap();
        let got = std::fs::read(dir.join("o/files/f")).unwrap();
        assert_eq!(&got[..5], b"first");
        assert_eq!(&got[BS..], b"second");

        let mut deep = Img::new(256, true);
        let mut hdr = [0u8; 60];
        put16(&mut hdr, 0, 0xF30A);
        put16(&mut hdr, 4, 4);
        put16(&mut hdr, 6, 9); // far too deep
        deep.inode(11, 0o100644, 10, 1, INODE_EXTENTS, hdr);
        one_file(&mut deep, 11, "f");
        assert!(extract_err(&deep, "toodeep").contains("levels deep"));

        let mut magic = Img::new(256, true);
        let mut hdr = [0u8; 60];
        put16(&mut hdr, 0, 0xBEEF);
        magic.inode(11, 0o100644, 10, 1, INODE_EXTENTS, hdr);
        one_file(&mut magic, 11, "f");
        assert!(extract_err(&magic, "badmagic").contains("bad extent node magic"));
    }

    #[test]
    fn data_beyond_a_truncated_image_is_an_error() {
        let mut m = Img::new(256, true);
        let at = m.alloc(&vec![1u8; 2 * BS])[0];
        extent_file(&mut m, 11, 2 * BS as u64, &[(0, 2, at)]);
        one_file(&mut m, 11, "f");
        let mut cut = m.img.clone();
        cut.truncate((at as usize + 1) * BS); // the superblock still claims 512 blocks
        let fs = Fs::from_bytes(cut).unwrap();
        let dir = scratch("cut");
        let e = format!(
            "{:#}",
            fs.extract(&dir.join("o"), Some(Collisions::Allow))
                .unwrap_err()
        );
        assert!(e.contains("past the end of the image"), "{e}");
    }

    #[test]
    fn directory_entries_that_point_nowhere_or_are_malformed_are_refused() {
        let mut m = sample(256, true);
        m.dir(2, 2, &[("ghost", 40, 1)]); // inode 40 was never written
        assert!(format!("{:#}", m.fs().entries().unwrap_err()).contains("unused inode"));
        let mut m = sample(256, true);
        m.dir(2, 2, &[("a/b", 11, 1)]);
        assert!(format!("{:#}", m.fs().entries().unwrap_err()).contains("invalid name"));
        let mut m = sample(256, true);
        let blk = m.next - 1; // the root directory's block was allocated last
        let at = (blk * BS) + 12; // first entry after "." is at 12
        put16(&mut m.img, at + 4, 2); // record length 2: impossible
        assert!(format!("{:#}", m.fs().entries().unwrap_err()).contains("invalid length"));
    }

    #[test]
    fn a_60_byte_symlink_is_read_from_its_block_not_the_inode() {
        let mut m = Img::new(256, false);
        let target = "t".repeat(60);
        m.symlink(11, &target);
        m.symlink(12, &"u".repeat(59));
        m.dir(2, 2, &[("long", 11, 7), ("short", 12, 7)]);
        let list = m.fs().entries().unwrap();
        assert_eq!(
            by_path(&list, "long").link.as_deref(),
            Some(target.as_str())
        );
        assert_eq!(
            by_path(&list, "short").link.as_deref().map(str::len),
            Some(59)
        );
    }

    #[test]
    fn extended_attribute_damage_is_reported_and_unknown_blocks_are_ignored() {
        let mut m = sample(256, true);
        m.ibody_xattr(11, 6, "selinux", b"label");
        put32(m.raw(11), 128 + 32 + 4 + 4, 5); // value stored in another inode: unsupported
        assert!(format!("{:#}", m.fs().entries().unwrap_err()).contains("its own inode"));
        let mut m = sample(256, true);
        m.ibody_xattr(11, 6, "selinux", b"label");
        put16(m.raw(11), 128 + 32 + 4 + 2, 5000); // value offset beyond the inode
        assert!(format!("{:#}", m.fs().entries().unwrap_err()).contains("runs past its area"));
        let mut m = sample(256, true);
        let junk = m.alloc(&vec![0x55u8; BS])[0]; // not an xattr block: no magic
        put32(m.raw(11), 104, junk);
        let list = m.fs().entries().unwrap();
        assert!(by_path(&list, "a").xattrs.is_empty());
    }

    #[test]
    fn device_numbers_are_decoded_for_both_encodings() {
        let mut m = Img::new(256, false);
        let mut old = [0u8; 60];
        put32(&mut old, 0, (4 << 8) | 7); // old encoding: major 4, minor 7
        m.inode(11, 0o020600, 0, 1, 0, old);
        let mut new = [0u8; 60];
        put32(&mut new, 4, (1000 << 8) | 5 | (3 << 20)); // new encoding
        m.inode(12, 0o060600, 0, 1, 0, new);
        m.dir(2, 2, &[("c", 11, 3), ("b", 12, 4)]);
        let list = m.fs().entries().unwrap();
        assert_eq!(by_path(&list, "c").rdev, Some((4, 7)));
        assert_eq!(by_path(&list, "b").rdev, Some((1000, 5 | (3 << 8))));
        let man = manifest(&list.iter().map(|(e, _)| e.clone()).collect::<Vec<_>>());
        assert_eq!(man["entries"][1]["rdev"], json!([4, 7]));
    }

    #[test]
    fn size_limits_are_enforced_per_file_and_in_total() {
        let m = sample(256, true);
        let fs = m.fs();
        let list = fs.entries().unwrap();
        let inode = &list.iter().find(|(e, _)| e.path == "d/b").unwrap().1; // 5000 bytes
        let mut f = tempfile_like();
        let mut budget = 6000;
        fs.copy_data(inode, &mut f, &mut budget).unwrap();
        assert_eq!(budget, 1000, "the size is taken from the budget");
        let e = format!(
            "{:#}",
            fs.copy_data(inode, &mut f, &mut budget).unwrap_err()
        );
        assert!(e.contains("add up to more than"), "{e}");
        let mut big = u64::MAX;
        let mut huge = inode.clone();
        huge.size = MAX_FILE_BYTES + 1;
        let e = format!("{:#}", fs.copy_data(&huge, &mut f, &mut big).unwrap_err());
        assert!(e.contains("-byte limit") && e.contains("a file of"), "{e}");
    }

    #[test]
    fn group_table_and_64bit_descriptors_are_checked() {
        let good = sample(256, true).img;
        let mut many = good.clone();
        put32(&mut many, 1024 + 4, 1 << 31); // blocks: far more groups than the image holds
        assert!(format!("{:#}", Fs::from_bytes(many).err().unwrap()).contains("past the end"));
        let mut wide = good;
        put32(&mut wide, 1024 + 96, 0x2 | 0x40 | 0x80); // 64bit
        put16(&mut wide, 1024 + 254, 64);
        put32(&mut wide, 2048 + 0x28, 1); // inode table high word: 4 GiB away
        let fs = Fs::from_bytes(wide).unwrap();
        assert!(
            fs.entries().is_err(),
            "the high word moves the table out of the image"
        );
    }

    #[test]
    fn three_case_variants_get_numbered_names() {
        let mut m = Img::new(256, true);
        for (i, n) in [("Aa", 11), ("aA", 12), ("AA", 13)]
            .iter()
            .map(|(n, i)| (i, n))
        {
            m.file(*i, 0o644, n.as_bytes(), 1);
        }
        m.dir(2, 2, &[("Aa", 11, 1), ("aA", 12, 1), ("AA", 13, 1)]);
        let dir = scratch("case3");
        let e = m
            .fs()
            .extract(&dir.join("o"), Some(Collisions::Rename))
            .unwrap();
        let names: Vec<_> = e
            .iter()
            .map(|e| e.extracted_as.clone().unwrap_or(e.path.clone()))
            .collect();
        assert_eq!(names, ["AA", "Aa~case2", "aA~case3"]);
        assert_eq!(
            host_collisions(&dir.join("does-not-exist")),
            Collisions::Rename
        );
    }

    #[cfg(unix)]
    #[test]
    fn hardlinked_names_are_one_file_on_disk() {
        use std::os::unix::fs::MetadataExt;
        let m = sample(256, true);
        let dir = scratch("hl");
        m.fs()
            .extract(&dir.join("o"), Some(Collisions::Allow))
            .unwrap();
        let a = std::fs::metadata(dir.join("o/files/a")).unwrap();
        let h = std::fs::metadata(dir.join("o/files/hard")).unwrap();
        assert_eq!((a.ino(), a.nlink()), (h.ino(), 2));
    }

    fn cat_bytes(fs: &Fs, path: &str) -> Vec<u8> {
        let (_, inode) = fs.lookup(path).unwrap();
        let mut out = Vec::new();
        fs.cat(&inode, &mut out).unwrap();
        out
    }

    #[test]
    fn lookup_resolves_paths_without_following_symlinks() {
        for (isz, ext) in [(256, true), (128, false)] {
            let fs = sample(isz, ext).fs();
            for p in ["a", "/a", "a/", "./a", "//a", "d/b", "/d//b/"] {
                assert!(fs.lookup(p).is_ok(), "{p}");
            }
            assert_eq!(fs.lookup("d/b").unwrap().0.path, "d/b");
            assert_eq!(fs.lookup("/").unwrap().0.kind, Kind::Dir);
            assert_eq!(fs.lookup("").unwrap().0.path, "");
            assert_eq!(fs.lookup("s").unwrap().0.kind, Kind::Symlink);
            let e = |p: &str| format!("{:#}", fs.lookup(p).unwrap_err());
            assert!(e("nope").contains("not found"), "{}", e("nope"));
            assert!(e("d/nope").contains("not found in /d"));
            assert!(e("a/x").contains("not a directory"));
            assert!(e("s/x").contains("symlinks are not followed"));
            assert!(e("d/../a").contains("not accepted"));
        }
    }

    #[test]
    fn list_dir_lists_one_level_or_the_file_itself() {
        let fs = sample(256, true).fs();
        let names = |p: &str| {
            fs.list_dir(p)
                .unwrap()
                .into_iter()
                .map(|(e, _)| e.path)
                .collect::<Vec<_>>()
        };
        assert_eq!(names("/"), ["a", "d", "empty", "hard", "l", "s"]);
        assert_eq!(names("d"), ["d/b", "d/c"]);
        assert_eq!(names("d/"), ["d/b", "d/c"]);
        assert_eq!(names("a"), ["a"], "a file lists as itself");
        let root = fs.list_dir("/").unwrap();
        assert_eq!(
            root.iter()
                .find(|(e, _)| e.path == "s")
                .unwrap()
                .0
                .link
                .as_deref(),
            Some("a")
        );
        assert!(fs.list_dir("zzz").is_err());
    }

    #[test]
    fn cat_returns_the_exact_bytes_including_holes() {
        for (isz, ext) in [(256, true), (128, false)] {
            let fs = sample(isz, ext).fs();
            assert_eq!(cat_bytes(&fs, "a"), b"hello\n");
            assert_eq!(cat_bytes(&fs, "hard"), b"hello\n");
            assert_eq!(cat_bytes(&fs, "d/b"), vec![7u8; 5000]);
            assert_eq!(cat_bytes(&fs, "empty"), b"");
            let mut want = vec![1u8; 20 * BS];
            want[3 * BS..6 * BS].fill(0);
            assert_eq!(cat_bytes(&fs, "d/c"), want);
        }
    }

    #[test]
    fn cat_handles_trailing_holes_unwritten_extents_and_refuses_non_files() {
        let mut m = Img::new(256, true);
        let at = m.alloc(b"head")[0];
        extent_file(&mut m, 11, 3 * BS as u64 + 10, &[(0, 1, at)]);
        let at2 = m.alloc(&vec![9u8; 2 * BS])[0];
        extent_file(&mut m, 12, 2 * BS as u64, &[(0, 32770, at2)]);
        m.dir(2, 2, &[("f", 11, 1), ("u", 12, 1)]);
        let fs = m.fs();
        let mut want = vec![0u8; 3 * BS + 10];
        want[..4].copy_from_slice(b"head");
        assert_eq!(cat_bytes(&fs, "f"), want);
        assert_eq!(
            cat_bytes(&fs, "u"),
            vec![0u8; 2 * BS],
            "unwritten extents are zeros"
        );
        let (_, dir) = fs.lookup("/").unwrap();
        assert!(
            format!("{:#}", fs.cat(&dir, &mut Vec::new()).unwrap_err())
                .contains("not a regular file")
        );
        let (_, mut big) = fs.lookup("f").unwrap();
        big.size = MAX_FILE_BYTES + 1;
        assert!(
            format!("{:#}", fs.cat(&big, &mut Vec::new()).unwrap_err()).contains("-byte limit")
        );
    }

    #[test]
    fn cat_stops_cleanly_when_the_reader_goes_away() {
        struct Closed;
        impl Write for Closed {
            fn write(&mut self, _: &[u8]) -> std::io::Result<usize> {
                Err(std::io::ErrorKind::BrokenPipe.into())
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }
        let fs = sample(256, true).fs();
        let (_, inode) = fs.lookup("d/b").unwrap();
        let e = fs.cat(&inode, &mut Closed).unwrap_err();
        assert!(
            e.downcast_ref::<std::io::Error>()
                .is_some_and(|e| e.kind() == std::io::ErrorKind::BrokenPipe)
        );
    }

    #[test]
    fn extract_trees_writes_each_ext_image_and_leaves_other_images_alone() {
        use crate::extract::extract_trees;
        let dir = scratch("trees");
        let sys = dir.join("system.img");
        std::fs::write(&sys, sample(256, true).img).unwrap();
        let vend = dir.join("vendor.img");
        std::fs::write(&vend, sample(128, false).img).unwrap();
        let boot = dir.join("boot.img");
        std::fs::write(&boot, vec![0x42u8; 4096]).unwrap();
        let ero = dir.join("odm.img");
        let root = fs_erofs::mkfs::Node::Dir {
            mode: 0o040755,
            entries: [(
                "f".to_string(),
                fs_erofs::mkfs::Node::File {
                    mode: 0o100644,
                    data: b"from erofs".to_vec(),
                    meta: Default::default(),
                    xattrs: vec![],
                },
            )]
            .into(),
            meta: Default::default(),
            xattrs: vec![],
        };
        std::fs::write(&ero, fs_erofs::mkfs::build_image(root, 12).unwrap()).unwrap();
        let broken = dir.join("product.img");
        let mut bad = std::fs::read(&ero).unwrap();
        bad[1024 + 12] = 99; // a block size no erofs image has
        std::fs::write(&broken, &bad).unwrap();
        let images = [sys.as_path(), vend.as_path(), boot.as_path(), ero.as_path()];
        let out = dir.join("files");
        extract_trees(&images, &out, &crate::extract::ExtractOptions::default()).unwrap();
        assert_eq!(
            std::fs::read(out.join("system/files/d/b")).unwrap(),
            vec![7u8; 5000]
        );
        assert_eq!(
            std::fs::read(out.join("vendor/files/a")).unwrap(),
            b"hello\n"
        );
        assert!(
            out.join("system/manifest.json").is_file()
                && out.join("vendor/manifest.json").is_file()
        );
        assert_eq!(
            std::fs::read(out.join("odm/files/f")).unwrap(),
            b"from erofs",
            "erofs images get a tree too"
        );
        assert!(
            !out.join("boot").exists(),
            "no tree for images without a file system"
        );
        let e = format!(
            "{:#}",
            extract_trees(
                &[broken.as_path()],
                &dir.join("b"),
                &crate::extract::ExtractOptions::default()
            )
            .unwrap_err()
        );
        assert!(e.contains("not a readable erofs image"), "{e}");
        assert!(
            !dir.join("b/product").exists(),
            "a failed tree leaves nothing"
        );
        // a second run refuses to merge into an existing tree, --force replaces it
        let e = format!(
            "{:#}",
            extract_trees(&images, &out, &crate::extract::ExtractOptions::default()).unwrap_err()
        );
        assert!(e.contains("not empty"), "{e}");
        std::fs::write(out.join("system/files/stale"), b"x").unwrap();
        extract_trees(
            &images,
            &out,
            &crate::extract::ExtractOptions {
                force: true,
                ..Default::default()
            },
        )
        .unwrap();
        assert!(!out.join("system/files/stale").exists());
        assert_eq!(
            std::fs::read(out.join("system/files/a")).unwrap(),
            b"hello\n"
        );
    }

    fn tempfile_like() -> File {
        let g = crate::testutil::Scratch::new("ext4-sink");
        File::options()
            .read(true)
            .write(true)
            .create(true)
            .truncate(true)
            .open(g.join("x"))
            .unwrap()
    }
}
