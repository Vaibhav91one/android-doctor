//! OEM full-firmware wrappers that unwrap into partition images: Huawei `UPDATE.APP`, LG
//! `.kdz`/`.dz`, Sony `.sin`, plus two containers that are only named (Coolpad `.cpb`, Nokia
//! `.nb0`). Each reader is written from the public on-disk layout, documented at the top of its
//! module; none of it is derived from the GPL reference tools.
//!
//! This module is the shared plumbing: sniffing, the item list, safe name handling and the
//! `.part`-then-rename writer. A payload that is an Android sparse image is expanded on the way
//! out, so the existing pipeline (ext4/erofs/lp readers) sees a plain image.
use crate::extract::{ExtractOptions, create_part};
use crate::sparse;
use anyhow::{Context, Result, bail};
use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};

/// Hostile-input bound on the number of images one container may declare.
pub(crate) const MAX_ITEMS: usize = 1024;
/// Largest single output image we will write (16 GiB).
pub(crate) const MAX_IMAGE_BYTES: u64 = 1 << 34;

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Kind {
    HuaweiApp,
    LgKdz,
    LgDz,
    SonySin,
    CoolpadCpb,
    NokiaNb0,
}

impl Kind {
    pub fn id(self) -> &'static str {
        match self {
            Kind::HuaweiApp => "huawei-update-app",
            Kind::LgKdz => "lg-kdz",
            Kind::LgDz => "lg-dz",
            Kind::SonySin => "sony-sin",
            Kind::CoolpadCpb => "coolpad-cpb",
            Kind::NokiaNb0 => "nokia-nb0",
        }
    }

    pub fn description(self) -> &'static str {
        match self {
            Kind::HuaweiApp => "Huawei UPDATE.APP firmware container",
            Kind::LgKdz => "LG KDZ firmware container",
            Kind::LgDz => "LG DZ firmware container (zlib partition chunks)",
            Kind::SonySin => "Sony .sin firmware image",
            Kind::CoolpadCpb => {
                "Coolpad .cpb firmware container (recognized but unsupported, often encrypted)"
            }
            Kind::NokiaNb0 => "Nokia NB0 firmware container (recognized but unsupported)",
        }
    }

    /// The kind a stable `identify` id stands for.
    pub fn from_id(id: &str) -> Option<Kind> {
        [
            Kind::HuaweiApp,
            Kind::LgKdz,
            Kind::LgDz,
            Kind::SonySin,
            Kind::CoolpadCpb,
            Kind::NokiaNb0,
        ]
        .into_iter()
        .find(|k| k.id() == id)
    }
}

/// Containers recognised by file extension alone (no usable magic).
pub fn kind_by_extension(path: &Path) -> Option<Kind> {
    let ext = path.extension()?.to_str()?.to_ascii_lowercase();
    match ext.as_str() {
        "sin" => Some(Kind::SonySin),
        "cpb" => Some(Kind::CoolpadCpb),
        "nb0" => Some(Kind::NokiaNb0),
        _ => None,
    }
}

/// What `path` is, if it is one of the OEM containers: magic first, then extension. Only regular
/// files are opened, so a FIFO never blocks a caller.
pub fn detect(path: &Path) -> Option<Kind> {
    if !std::fs::metadata(path).ok()?.is_file() {
        return None;
    }
    let mut head = Vec::with_capacity(16);
    File::open(path)
        .ok()?
        .take(16)
        .read_to_end(&mut head)
        .ok()?;
    match crate::detect::sniff(&head) {
        Some(known) => Kind::from_id(known.id),
        None => kind_by_extension(path),
    }
}

/// One image a container would produce.
pub(crate) struct Item {
    /// Output file name, always ending in `.img`.
    pub name: String,
    /// Size of the written image in bytes (a sparse payload counts its expanded size).
    pub size: u64,
    pub src: Src,
}

pub(crate) enum Src {
    /// A byte range of the container, copied (sparse payloads are expanded).
    Range { offset: u64, len: u64 },
    /// LG DZ chunks, inflated into place.
    Chunks(Vec<crate::lgkdz::Chunk>),
}

/// A partition name from a fixed-width, NUL-padded field: ASCII letters, digits and `._-` only.
pub(crate) fn clean_name(raw: &[u8]) -> Result<String> {
    let cut = raw.iter().position(|&b| b == 0).unwrap_or(raw.len());
    let s = std::str::from_utf8(&raw[..cut]).unwrap_or("");
    let ok = !s.is_empty()
        && s.len() <= 64
        && !s.starts_with('.')
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'));
    if !ok {
        bail!("unsafe or empty partition name {:?}", &raw[..cut.min(32)]);
    }
    Ok(s.to_ascii_lowercase())
}

pub(crate) fn le32(b: &[u8], at: usize) -> u32 {
    u32::from_le_bytes(b[at..at + 4].try_into().unwrap())
}

pub(crate) fn le64(b: &[u8], at: usize) -> u64 {
    u64::from_le_bytes(b[at..at + 8].try_into().unwrap())
}

pub(crate) fn read_at(f: &mut File, at: u64, buf: &mut [u8]) -> Result<()> {
    f.seek(SeekFrom::Start(at))?;
    f.read_exact(buf)
        .with_context(|| format!("container ends early (reading {} bytes at {at})", buf.len()))
}

/// A range item, sized by its expanded length when the bytes are an Android sparse image.
pub(crate) fn range_item(
    f: &mut File,
    name: String,
    offset: u64,
    len: u64,
    file_len: u64,
) -> Result<Item> {
    if offset.checked_add(len).is_none_or(|end| end > file_len) {
        bail!("{name}: range {offset}+{len} lies outside the {file_len} byte container");
    }
    let mut size = len;
    if len >= 4 {
        let mut head = [0u8; 4];
        read_at(f, offset, &mut head)?;
        if head == [0x3A, 0xFF, 0x26, 0xED] {
            f.seek(SeekFrom::Start(offset))?;
            size = sparse::read_header(&mut f.by_ref().take(len))
                .with_context(|| format!("{name}: bad sparse payload"))?
                .image_bytes();
        }
    }
    if size > MAX_IMAGE_BYTES {
        bail!("{name}: image of {size} bytes exceeds the {MAX_IMAGE_BYTES} byte limit");
    }
    Ok(Item {
        name,
        size,
        src: Src::Range { offset, len },
    })
}

fn unsupported(kind: Kind, tool: &str) -> anyhow::Error {
    anyhow::anyhow!(
        "{}: recognized but unsupported - no clean-room reader exists for this container; unwrap it with {tool}, then run android-doctor on the partition images",
        kind.id()
    )
}

fn parse(kind: Kind, path: &Path) -> Result<Vec<Item>> {
    let mut f = File::open(path).with_context(|| format!("opening {}", path.display()))?;
    let len = f.metadata()?.len();
    let items = match kind {
        Kind::HuaweiApp => crate::huawei::parse(&mut f, len)?,
        Kind::LgKdz => crate::lgkdz::parse_kdz(&mut f, len)?,
        Kind::LgDz => crate::lgkdz::parse_dz(&mut f, 0, len)?,
        Kind::SonySin => crate::sonysin::parse(&mut f, len, path)?,
        Kind::CoolpadCpb => {
            return Err(unsupported(
                kind,
                "the vendor's flashing tool or a Coolpad CPB unpacker (CPB files are often encrypted)",
            ));
        }
        Kind::NokiaNb0 => {
            return Err(unsupported(kind, "a dedicated NB0 unpacker"));
        }
    };
    let mut seen = std::collections::HashSet::new();
    for it in &items {
        if !seen.insert(it.name.as_str()) {
            bail!("{}: duplicate image name {}", kind.id(), it.name);
        }
    }
    Ok(items)
}

/// Items after `--only` (names without `.img`); an unknown name is an error.
fn selected(kind: Kind, path: &Path, opts: &ExtractOptions) -> Result<Vec<Item>> {
    let mut items = parse(kind, path)?;
    if let Some(only) = &opts.only {
        let stem = |n: &str| n.strip_suffix(".img").unwrap_or(n).to_string();
        let avail: Vec<String> = items.iter().map(|i| stem(&i.name)).collect();
        if let Some(bad) = only.iter().find(|o| !avail.contains(o)) {
            bail!("unknown name {bad:?}; available: {}", avail.join(", "));
        }
        items.retain(|i| only.contains(&stem(&i.name)));
    }
    Ok(items)
}

/// What `extract` would write, `(name, size)` sorted by name.
pub fn list(kind: Kind, input: &Path, opts: &ExtractOptions) -> Result<Vec<(String, u64)>> {
    let mut out: Vec<_> = selected(kind, input, opts)?
        .into_iter()
        .map(|i| (i.name, i.size))
        .collect();
    out.sort_unstable();
    Ok(out)
}

/// Partition names (without `.img`).
pub fn partition_names(kind: Kind, input: &Path) -> Result<Vec<String>> {
    let mut names: Vec<String> = parse(kind, input)?
        .into_iter()
        .map(|i| i.name.trim_end_matches(".img").to_string())
        .collect();
    names.sort_unstable();
    Ok(names)
}

/// Unwrap the container into `out_dir`. Each image is written under `.part` and renamed on
/// success, so a failed run never leaves a plausible-looking partial image.
pub fn extract(
    kind: Kind,
    input: &Path,
    out_dir: &Path,
    opts: &ExtractOptions,
) -> Result<Vec<PathBuf>> {
    let items = selected(kind, input, opts)?;
    std::fs::create_dir_all(out_dir)?;
    if kind == Kind::SonySin
        && !opts.quiet
        && let Some(Item {
            src: Src::Range { offset, .. },
            ..
        }) = items.first()
    {
        eprintln!(
            "note: sony-sin: skipped {offset} bytes of header (hash table and signature blocks); they are not verified, so the image is not proven authentic"
        );
    }
    if !opts.force {
        for it in &items {
            if out_dir.join(&it.name).symlink_metadata().is_ok() {
                bail!(
                    "{} already exists in {}; pass --force to overwrite",
                    it.name,
                    out_dir.display()
                );
            }
        }
    }
    let file = File::open(input).with_context(|| format!("opening {}", input.display()))?;
    let mut paths = Vec::new();
    for it in &items {
        let final_path = out_dir.join(&it.name);
        let tmp = out_dir.join(format!("{}.part", it.name));
        let written = (|| -> Result<()> {
            let mut out = create_part(&tmp)?;
            match &it.src {
                Src::Range { offset, len } => write_range(&file, *offset, *len, &mut out),
                Src::Chunks(chunks) => crate::lgkdz::write_chunks(&file, chunks, &mut out),
            }
        })();
        if let Err(e) = written {
            let _ = std::fs::remove_file(&tmp);
            return Err(e.context(format!("extracting {}", it.name)));
        }
        std::fs::rename(&tmp, &final_path)?;
        paths.push(final_path);
    }
    paths.sort_unstable();
    Ok(paths)
}

fn write_range(file: &File, offset: u64, len: u64, out: &mut File) -> Result<()> {
    let mut r = file.try_clone()?;
    r.seek(SeekFrom::Start(offset))?;
    let mut head = [0u8; 4];
    let is_sparse = len >= 4 && r.read_exact(&mut head).is_ok() && head == [0x3A, 0xFF, 0x26, 0xED];
    r.seek(SeekFrom::Start(offset))?;
    let mut r = r.take(len);
    if is_sparse {
        sparse::unsparse(vec![r], out)?;
    } else {
        let n = std::io::copy(&mut r, out)?;
        if n != len {
            bail!("container ends early: wanted {len} bytes, got {n}");
        }
    }
    Ok(())
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::testutil::Scratch;

    /// Two tiny fake partitions, one of them an Android sparse image of one RAW block.
    pub(crate) fn fake_parts() -> Vec<(&'static str, Vec<u8>)> {
        let mut sparse = Vec::new();
        sparse.extend_from_slice(&0xED26_FF3Au32.to_le_bytes());
        sparse.extend_from_slice(&[1, 0, 0, 0]); // major 1, minor 0
        sparse.extend_from_slice(&28u16.to_le_bytes());
        sparse.extend_from_slice(&12u16.to_le_bytes());
        sparse.extend_from_slice(&4096u32.to_le_bytes()); // blk_sz
        sparse.extend_from_slice(&1u32.to_le_bytes()); // total_blks
        sparse.extend_from_slice(&1u32.to_le_bytes()); // total_chunks
        sparse.extend_from_slice(&0u32.to_le_bytes()); // checksum
        sparse.extend_from_slice(&0xCAC1u16.to_le_bytes()); // RAW
        sparse.extend_from_slice(&[0, 0]);
        sparse.extend_from_slice(&1u32.to_le_bytes());
        sparse.extend_from_slice(&(12u32 + 4096).to_le_bytes());
        sparse.extend_from_slice(&[0x5A; 4096]);
        vec![("boot", vec![0xB0; 100]), ("system", sparse)]
    }

    /// The images `fake_parts` must unwrap to (the sparse one expanded).
    pub(crate) fn expected(name: &str) -> Vec<u8> {
        match name {
            "boot" => vec![0xB0; 100],
            _ => vec![0x5A; 4096],
        }
    }

    #[test]
    fn names_are_sanitised() {
        assert_eq!(clean_name(b"SYSTEM\0\0\0").unwrap(), "system");
        assert!(clean_name(b"").is_err());
        assert!(clean_name(b"../x").is_err());
        assert!(clean_name(b"a/b").is_err());
        assert!(clean_name(b".hid").is_err());
    }

    #[test]
    fn cpb_and_nb0_are_named_but_refused_cleanly() {
        let d = Scratch::new("oem-unsupported");
        for (file, id) in [("a.cpb", "coolpad-cpb"), ("a.nb0", "nokia-nb0")] {
            let p = d.join(file);
            std::fs::write(&p, b"whatever").unwrap();
            let kind = detect(&p).unwrap();
            assert_eq!(kind.id(), id);
            let e = extract(kind, &p, &d.join("out"), &ExtractOptions::default()).unwrap_err();
            assert!(e.to_string().contains("recognized but unsupported"), "{e}");
            assert!(list(kind, &p, &ExtractOptions::default()).is_err());
        }
    }

    /// Set `ANDROID_DOCTOR_WRITE_FIXTURES=<dir>` to leave the synthetic containers on disk for a
    /// manual `identify`/`extract` run; without it this test only checks they build.
    #[test]
    fn synthetic_fixtures_can_be_written_for_a_manual_run() {
        let scratch = Scratch::new("oem-fixtures");
        let dir = std::env::var_os("ANDROID_DOCTOR_WRITE_FIXTURES")
            .map(PathBuf::from)
            .unwrap_or_else(|| scratch.to_path_buf());
        std::fs::create_dir_all(&dir).unwrap();
        let parts = fake_parts();
        crate::huawei::build_for_test(&dir.join("UPDATE.APP"), &parts);
        let raw = [("boot", expected("boot")), ("system", expected("system"))];
        crate::lgkdz::build_kdz_for_test(&dir.join("fw.kdz"), &raw);
        crate::lgkdz::build_dz_for_test(&dir.join("fw.dz"), &raw);
        crate::sonysin::build_for_test(&dir.join("system_X-FLASH-ALL-1234.sin"), &parts[1].1);
        std::fs::write(dir.join("fw.cpb"), b"CPB?").unwrap();
        std::fs::write(dir.join("fw.nb0"), b"NB0?").unwrap();
    }
}
