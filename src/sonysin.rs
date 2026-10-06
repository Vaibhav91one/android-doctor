//! Sony `.sin` firmware image, read from its public on-disk layout (header version 3).
//!
//! A `.sin` holds one partition: a header carrying the hash table and signature blocks, then the
//! payload, which is an ext4 image or an Android sparse image (Sony kernel/boot payloads are raw
//! images too).
//!
//! | offset | size | meaning                                                                |
//! |--------|------|------------------------------------------------------------------------|
//! | 0x00   | 4    | magic `03 'S' 'I' 'N'`                                                 |
//! | 0x04   | 4    | header length, `u32` big-endian: offset from byte 0 to the payload     |
//! | 0x08   | ...  | hash table and signature/certificate blocks, up to the header length   |
//!
//! Everything between byte 8 and the header length is authentication data. It is **skipped, not
//! verified**: extract says so, and never claims the payload is authentic. The payload is written
//! as `<file stem>.img`; an Android sparse payload is expanded by the shared writer so the
//! ext4/erofs readers see a plain image. A payload that is itself wrapped in a compression format
//! is refused by name rather than guessed at. Other header versions are not handled.
//!
//! Validated against spec-built synthetic fixtures only (see the tests), not real firmware.
use crate::oem::{Item, clean_name, range_item, read_at};
use anyhow::{Result, bail};
use std::fs::File;
use std::path::Path;

pub(crate) const MAGIC: [u8; 4] = [0x03, b'S', b'I', b'N'];

pub(crate) fn parse(f: &mut File, file_len: u64, path: &Path) -> Result<Vec<Item>> {
    let mut h = [0u8; 8];
    if file_len < 8 {
        bail!("sony-sin: too short for a header");
    }
    read_at(f, 0, &mut h)?;
    if h[..4] != MAGIC {
        bail!(
            "sony-sin: unrecognised header version (only version 3, magic 03 'S' 'I' 'N', is supported)"
        );
    }
    // big-endian, unlike every other length in the supported containers
    let header_len = u32::from_be_bytes(h[4..8].try_into().unwrap()) as u64;
    if header_len < 8 || header_len >= file_len {
        bail!("sony-sin: header length {header_len} leaves no payload in a {file_len} byte file");
    }
    let mut head = [0u8; 16];
    let n = (file_len - header_len).min(16) as usize;
    read_at(f, header_len, &mut head[..n])?;
    if let Some(wrapped) = crate::detect::sniff(&head[..n])
        && matches!(
            wrapped.id,
            "gzip" | "xz" | "bzip2" | "lz4" | "lz4-legacy" | "zstd" | "zip"
        )
    {
        bail!(
            "sony-sin: the payload is wrapped in {} and is not supported",
            wrapped.id
        );
    }
    let stem: String = path
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or("sin")
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-') {
                c
            } else {
                '_'
            }
        })
        .collect();
    let name = format!("{}.img", clean_name(stem.as_bytes())?);
    Ok(vec![range_item(
        f,
        name,
        header_len,
        file_len - header_len,
        file_len,
    )?])
}

/// Build a synthetic version-3 `.sin` around `payload` (test fixture).
#[cfg(test)]
pub(crate) fn build_for_test(path: &Path, payload: &[u8]) {
    let auth = [0xA5u8; 40]; // stands in for the hash table and signature blocks
    let header_len = 8 + auth.len();
    let mut out = Vec::new();
    out.extend_from_slice(&MAGIC);
    out.extend_from_slice(&(header_len as u32).to_be_bytes());
    out.extend_from_slice(&auth);
    out.extend_from_slice(payload);
    std::fs::write(path, out).unwrap();
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::extract::ExtractOptions;
    use crate::oem::tests::{expected, fake_parts};
    use crate::oem::{Kind, detect, extract, list};
    use crate::testutil::Scratch;

    #[test]
    fn a_sparse_payload_is_expanded_for_the_existing_pipeline() {
        let d = Scratch::new("sin-sparse");
        let sin = d.join("system_X-FLASH-ALL-1234.sin");
        build_for_test(&sin, &fake_parts()[1].1);
        assert_eq!(detect(&sin), Some(Kind::SonySin));
        assert_eq!(crate::detect::identify_path(&sin).unwrap().id, "sony-sin");
        let opts = ExtractOptions::default();
        assert_eq!(
            list(Kind::SonySin, &sin, &opts).unwrap(),
            [("system_x-flash-all-1234.img".to_string(), 4096)]
        );
        let out = d.join("out");
        extract(Kind::SonySin, &sin, &out, &opts).unwrap();
        assert_eq!(
            std::fs::read(out.join("system_x-flash-all-1234.img")).unwrap(),
            expected("system")
        );
    }

    #[test]
    fn an_ext4_payload_is_copied_through_and_still_identified() {
        let d = Scratch::new("sin-ext4");
        let mut ext4 = vec![0u8; 4096];
        ext4[1024 + 0x38..1024 + 0x3A].copy_from_slice(&0xEF53u16.to_le_bytes());
        ext4[1024 + 0x60..1024 + 0x64].copy_from_slice(&0x40u32.to_le_bytes()); // extents => ext4
        let sin = d.join("userdata.sin");
        build_for_test(&sin, &ext4);
        let out = d.join("out");
        let paths = extract(Kind::SonySin, &sin, &out, &ExtractOptions::default()).unwrap();
        assert_eq!(std::fs::read(&paths[0]).unwrap(), ext4);
        assert!(crate::detect::filesystem_of_file(&paths[0]).is_some());
    }

    #[test]
    fn unprocessable_or_malformed_input_is_refused_by_name() {
        let d = Scratch::new("sin-bad");
        let opts = ExtractOptions::default();
        let try_bytes = |n: &str, b: &[u8]| {
            let p = d.join(n);
            std::fs::write(&p, b).unwrap();
            extract(Kind::SonySin, &p, &d.join(format!("o-{n}")), &opts)
        };
        // another header version, named by extension only
        let e = try_bytes("v2.sin", b"\x02SIN\0\0\0\x08payload").unwrap_err();
        assert!(e.to_string().contains("unrecognised header version"), "{e}");
        // header length pointing past the file
        let mut b = MAGIC.to_vec();
        b.extend_from_slice(&1000u32.to_be_bytes());
        b.extend_from_slice(&[0; 20]);
        assert!(try_bytes("long.sin", &b).is_err());
        // header length below the fixed part
        let mut b = MAGIC.to_vec();
        b.extend_from_slice(&3u32.to_be_bytes());
        b.extend_from_slice(&[0; 20]);
        assert!(try_bytes("short.sin", &b).is_err());
        // a compressed payload we cannot process
        let mut b = MAGIC.to_vec();
        b.extend_from_slice(&8u32.to_be_bytes());
        b.extend_from_slice(&[0x1F, 0x8B, 0x08, 0, 0, 0, 0, 0]);
        let e = try_bytes("gz.sin", &b).unwrap_err();
        assert!(e.to_string().contains("not supported"), "{e}");
        // a sparse payload whose header is truncated
        let mut b = MAGIC.to_vec();
        b.extend_from_slice(&8u32.to_be_bytes());
        b.extend_from_slice(&[0x3A, 0xFF, 0x26, 0xED, 1, 0]);
        assert!(try_bytes("sp.sin", &b).is_err());
        // an unrelated file with a .sin name
        assert!(try_bytes("junk.sin", b"hello").is_err());
    }
}
