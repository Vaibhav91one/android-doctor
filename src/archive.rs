//! Archive handlers for the tar family: plain tar, Samsung `.tar.md5`, and tar wrapped in
//! gzip, bzip2, xz, lz4-frame, lz4-legacy or zstd. Detection of these kinds lives in
//! `detect`; this module extracts them safely. Every member path is cleaned by
//! `treeout::clean_path`, so absolute paths, `..` and NUL bytes are rejected, and symlinks,
//! devices, fifos and sockets are refused.
use crate::detect;
use crate::ramdisk::{Compression, compression_of, decoder};
use crate::treeout::{Sink, clean_path, host_collisions, prepare_staging, publish};
use anyhow::{Context, Result, anyhow, bail, ensure};
use md5::{Digest, Md5};
use std::fs::File;
use std::io::{BufReader, Read};
use std::path::Path;
use tar::Archive;

const TAR_USTAR_OFF: usize = 257;
const TAR_USTAR_MAGIC: &[u8] = b"ustar";
const SNIFF_LEN: usize = 512;

/// The on-disk shape of an archive this module can unpack.
#[allow(dead_code)]
pub(crate) enum Kind {
    Tar,
    Compressed(Compression),
    TarMd5,
}

fn is_tar_head(head: &[u8]) -> bool {
    head.len() >= TAR_USTAR_OFF + TAR_USTAR_MAGIC.len()
        && &head[TAR_USTAR_OFF..TAR_USTAR_OFF + TAR_USTAR_MAGIC.len()] == TAR_USTAR_MAGIC
}

pub(crate) fn kind_of(head: &[u8]) -> Option<Kind> {
    if is_tar_head(head) {
        return Some(Kind::Tar);
    }
    compression_of(head).map(Kind::Compressed)
}

/// True when `r`, decompressed with `c`, starts with a tar header.
///
/// A compression magic does not make a tar: a gzip `dt.img` is a gzip of an Amlogic container,
/// and handing that to the tar reader fails with "numeric field was not a number" and stops
/// the run (#114). Only the first block is decoded, so this is cheap on a large update.
pub(crate) fn compressed_holds_tar(c: Compression, r: impl Read) -> bool {
    let Ok(mut d) = decoder(c, BufReader::new(r)) else {
        return false;
    };
    let mut block = [0u8; SNIFF_LEN];
    let mut got = 0;
    while got < block.len() {
        match d.read(&mut block[got..]) {
            Ok(0) | Err(_) => break,
            Ok(n) => got += n,
        }
    }
    is_tar_head(&block[..got])
}

/// True when the file at `path` (whose first bytes are `head`) is a tar, or a compressed tar.
pub(crate) fn holds_tar(path: &Path, head: &[u8]) -> bool {
    is_tar_head(head)
        || compression_of(head)
            .is_some_and(|c| File::open(path).is_ok_and(|f| compressed_holds_tar(c, f)))
}

fn first_bytes(path: &Path, n: usize) -> Result<Vec<u8>> {
    detect::refuse_blocking_file(path)?;
    let mut buf = vec![0u8; n];
    let mut f = File::open(path).with_context(|| format!("opening {}", path.display()))?;
    let got = f.read(&mut buf)?;
    buf.truncate(got);
    Ok(buf)
}

/// Split a Samsung `.tar.md5`: the tar bytes plus the hash from the trailing `<hex>  -` line.
fn split_md5(data: &[u8]) -> Result<(Vec<u8>, String)> {
    // A tar is padded to a block boundary with NULs, so the md5 line is the trailing run of
    // printable ASCII; it is not separated from the tar by a newline.
    let end = data
        .iter()
        .rposition(|&c| c > 0x20)
        .map(|i| i + 1)
        .unwrap_or(0);
    let split = data[..end]
        .iter()
        .rposition(|&c| !(0x20..=0x7e).contains(&c))
        .map(|i| i + 1)
        .unwrap_or(0);
    let line = std::str::from_utf8(&data[split..])
        .context("tar.md5 trailing line is not valid UTF-8")?
        .trim();
    let parts: Vec<&str> = line.split_whitespace().collect();
    ensure!(
        parts.len() == 3 && parts[1] == "-" && parts[2] == "-",
        "tar.md5 trailing line is not the expected \"<md5>  - -\" format"
    );
    Ok((data[..split].to_vec(), parts[0].to_ascii_lowercase()))
}

fn verify_md5(data: &[u8], expected: &str) -> Result<()> {
    let computed: String = Md5::digest(data)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    ensure!(
        computed == expected.to_lowercase(),
        "MD5 mismatch: the file says {expected}, the contents hash to {computed}"
    );
    Ok(())
}

/// Extract `input` into `out_dir`. Works on plain tar, a compressed tar, and a Samsung
/// `.tar.md5` (whose hash is verified before anything is written).
pub(crate) fn extract(input: &Path, out_dir: &Path) -> Result<()> {
    let head = first_bytes(input, SNIFF_LEN)?;
    if is_tar_head(&head) {
        if input.extension().and_then(|e| e.to_str()) == Some("md5") {
            return extract_tar_md5(input, out_dir);
        }
        return extract_stream(out_dir, BufReader::new(File::open(input)?));
    }
    if let Some(c) = compression_of(&head) {
        let f = BufReader::new(File::open(input)?);
        return extract_stream(out_dir, decoder(c, f)?);
    }
    bail!("{} is not a tar or compressed-tar archive", input.display())
}

/// A `.tar.md5` is the tar bytes followed by a `<md5>  - -\n` line; check it, then extract.
fn extract_tar_md5(input: &Path, out_dir: &Path) -> Result<()> {
    let data = std::fs::read(input).with_context(|| format!("reading {}", input.display()))?;
    let (tar_bytes, hash) = split_md5(&data)?;
    verify_md5(&tar_bytes, &hash)?;
    let staging = prepare_staging(out_dir)?;
    let result = unpack(Box::new(BufReader::new(tar_bytes.as_slice())), &staging);
    if result.is_ok() {
        publish(&staging, out_dir)?;
    } else {
        let _ = std::fs::remove_dir_all(&staging);
    }
    result
}

/// Unpack `reader` as a tar into `out_dir`, staging through `<out_dir>.part`.
fn extract_stream(out_dir: &Path, reader: impl Read) -> Result<()> {
    let staging = prepare_staging(out_dir)?;
    let result = unpack(reader, &staging);
    if result.is_ok() {
        publish(&staging, out_dir)?;
    } else {
        let _ = std::fs::remove_dir_all(&staging);
    }
    result
}

fn unpack(mut reader: impl Read, staging: &Path) -> Result<()> {
    let files = staging.join("files");
    std::fs::create_dir_all(&files)?;
    let mut sink = Sink::with_collisions(&files, host_collisions(&files));
    let mut ar = Archive::new(&mut reader);
    for entry in ar.entries()? {
        let mut entry = entry?;
        extract_entry(&mut entry, &mut sink)?;
    }
    Ok(())
}

/// Write one tar entry through the sink, refusing anything that is not a regular file or
/// a directory: symlinks and hard links are recorded but never created, and devices, fifos
/// and sockets are refused outright.
fn extract_entry(entry: &mut tar::Entry<impl Read>, sink: &mut Sink) -> Result<()> {
    let path = entry.path()?;
    let raw = path
        .to_str()
        .ok_or_else(|| anyhow!("tar entry has a non-UTF-8 path"))?;
    let name = clean_path(raw).with_context(|| format!("tar entry {raw:?}"))?;
    let kind = entry.header().entry_type();
    if kind.is_dir() {
        sink.add_dir(&name)?;
        return Ok(());
    }
    if kind.is_symlink() || kind.is_hard_link() {
        // Recorded so nothing can later be written through them; never created.
        sink.note_symlink(&name)?;
        return Ok(());
    }
    if kind.is_character_special() || kind.is_block_special() || kind.is_fifo() {
        bail!("tar entry {name:?} is a device or fifo, which is never created");
    }
    if kind.is_file() || kind.is_contiguous() {
        let mode = entry.header().mode().unwrap_or(0o644);
        sink.write_file(&name, mode, &mut *entry)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::Scratch;
    use flate2::{Compression as Gz, write::GzEncoder};

    /// Two partition images, enough to tell the extraction apart from a copy.
    const BOOT: &[u8] = b"BOOT-IMAGE-BYTES";
    const SYSTEM: &[u8] = b"SYSTEM-IMAGE-BYTES";

    /// A tar holding `boot.img` and `system.img` at the top level, as a JioSTB update has.
    fn sample_tar() -> Vec<u8> {
        let mut b = tar::Builder::new(Vec::new());
        for (name, body) in [("boot.img", BOOT), ("system.img", SYSTEM)] {
            let mut h = tar::Header::new_gnu();
            h.set_size(body.len() as u64);
            h.set_mode(0o644);
            h.set_cksum();
            b.append_data(&mut h, name, body).unwrap();
        }
        b.into_inner().unwrap()
    }

    fn gzip(data: &[u8]) -> Vec<u8> {
        let mut e = GzEncoder::new(Vec::new(), Gz::default());
        std::io::Write::write_all(&mut e, data).unwrap();
        e.finish().unwrap()
    }

    fn md5_hex(data: &[u8]) -> String {
        Md5::digest(data)
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect()
    }

    /// Extract `src` into `out` and return the two extracted files.
    fn run(src: &Path, out: &Path) -> Result<()> {
        extract(src, out)
    }

    #[test]
    fn a_plain_tar_round_trips() {
        let s = Scratch::new("arc-tar");
        let src = s.join("payload.tar");
        std::fs::write(&src, sample_tar()).unwrap();
        let out = s.join("out");
        run(&src, &out).unwrap();
        assert_eq!(std::fs::read(out.join("files/boot.img")).unwrap(), BOOT);
        assert_eq!(std::fs::read(out.join("files/system.img")).unwrap(), SYSTEM);
    }

    #[test]
    fn a_gzip_wrapped_tar_round_trips() {
        let s = Scratch::new("arc-targz");
        let src = s.join("payload.tar.gz");
        std::fs::write(&src, gzip(&sample_tar())).unwrap();
        let out = s.join("out");
        run(&src, &out).unwrap();
        assert_eq!(std::fs::read(out.join("files/boot.img")).unwrap(), BOOT);
    }

    #[test]
    fn a_jios_tb_tar_md5_is_verified_then_extracted() {
        let s = Scratch::new("arc-tarmd5");
        let tar = sample_tar();
        let mut blob = tar.clone();
        blob.extend_from_slice(format!("{}  - -\n", md5_hex(&tar)).as_bytes());
        let src = s.join("SUPER.tar.md5");
        std::fs::write(&src, &blob).unwrap();
        let out = s.join("out");
        run(&src, &out).unwrap();
        assert_eq!(std::fs::read(out.join("files/boot.img")).unwrap(), BOOT);
        assert_eq!(std::fs::read(out.join("files/system.img")).unwrap(), SYSTEM);
    }

    #[test]
    fn a_tar_md5_that_does_not_match_is_refused() {
        let s = Scratch::new("arc-badmd5");
        let mut blob = sample_tar();
        blob.extend_from_slice(b"00000000000000000000000000000000  - -\n");
        let src = s.join("SUPER.tar.md5");
        std::fs::write(&src, &blob).unwrap();
        let out = s.join("out");
        let e = run(&src, &out).unwrap_err().to_string();
        assert!(e.contains("MD5 mismatch"), "{e}");
        assert!(
            !out.exists(),
            "nothing is published when the hash does not match"
        );
    }

    /// An entry that tries to escape the output directory is refused, and nothing is published.
    /// The header is written by hand because `tar::Builder` refuses to create such a path.
    #[test]
    fn an_entry_that_climbs_out_is_refused() {
        let s = Scratch::new("arc-traversal");
        let body = b"escaped";
        let mut header = tar::Header::new_gnu();
        header.set_size(body.len() as u64);
        header.set_mode(0o644);
        header.set_entry_type(tar::EntryType::Regular);
        header.set_cksum();
        let name = b"../evil";
        header.as_old_mut().name[..name.len()].copy_from_slice(name);
        header.set_cksum();
        let mut tar_bytes = header.as_bytes().to_vec();
        tar_bytes.extend_from_slice(body);
        tar_bytes.resize(10240, 0);
        tar_bytes[257..262].copy_from_slice(b"ustar");
        let src = s.join("evil.tar");
        std::fs::write(&src, &tar_bytes).unwrap();
        let out = s.join("out");
        let e = format!("{:#}", run(&src, &out).unwrap_err());
        assert!(e.contains("climbs out"), "{e}");
        assert!(!out.exists(), "nothing is published when an entry escapes");
        assert!(
            !s.join("evil").exists(),
            "nothing was written outside the output directory"
        );
    }

    #[test]
    fn a_device_entry_is_refused() {
        let s = Scratch::new("arc-device");
        let mut b = tar::Builder::new(Vec::new());
        let mut h = tar::Header::new_gnu();
        h.set_size(0);
        h.set_mode(0o644);
        h.set_entry_type(tar::EntryType::Char);
        let _ = h.set_device_major(1);
        let _ = h.set_device_minor(3);
        h.set_path("dev/null").unwrap();
        h.set_cksum();
        b.append(&h, std::io::empty()).unwrap();
        let mut tar_bytes = b.into_inner().unwrap();
        tar_bytes[257..262].copy_from_slice(b"ustar");
        let src = s.join("dev.tar");
        std::fs::write(&src, &tar_bytes).unwrap();
        let out = s.join("out");
        let e = run(&src, &out).unwrap_err().to_string();
        assert!(e.contains("device") || e.contains("fifo"), "{e}");
        assert!(!out.exists());
    }

    #[test]
    fn a_failed_extraction_leaves_no_staging_directory() {
        let s = Scratch::new("arc-staging");
        let src = s.join("payload.tar");
        std::fs::write(&src, sample_tar()).unwrap();
        let out = s.join("out");
        std::fs::create_dir_all(&out).unwrap();
        std::fs::write(out.join("in-the-way"), b"x").unwrap();
        assert!(run(&src, &out).is_err());
        assert!(
            !s.join("out.part").exists(),
            "the staging directory is cleaned up"
        );
    }
}
