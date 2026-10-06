//! LG `.kdz` / `.dz` firmware containers, read from their public on-disk layout.
//!
//! Two layers. A **KDZ** is a flat bundle of files; the one that matters is a **DZ**, which holds
//! the partitions as zlib-compressed chunks.
//!
//! ## KDZ (little-endian)
//!
//! | offset | size | meaning                                                  |
//! |--------|------|----------------------------------------------------------|
//! | 0x00   | 8    | magic `24 05 00 00 38 31 25 80` (the "v2" header)         |
//! | 0x08   | 272 each | file records, ended by a record with an empty name   |
//!
//! A file record is `name[256]` (NUL padded), `size` (`u64`), `offset` (`u64`, absolute). The
//! other header variant (magic `28 05 00 00 34 31 25 80`) is recognised but refused by name.
//!
//! ## DZ (little-endian)
//!
//! A 512-byte file header, then `chunk_count` chunks, each a 512-byte chunk header immediately
//! followed by `data_size` bytes of zlib data.
//!
//! File header: `32 96 18 74` magic, then version words, the device and version strings, and at
//! `0xC0` the chunk count (`u32`). Chunk header: `30 12 95 78` magic; `slice_idx` (`u32`);
//! `name[32]` (the partition); at `0x28` `target_size` (`u32`, inflated bytes); `0x2C`
//! `data_size` (`u32`, compressed bytes); `0x30` an MD5 (not verified); `0x40` `start_sector`;
//! `0x44` `sector_count`; `0x48` `part_start_sector` (all `u32`, 512-byte sectors).
//!
//! A partition is every chunk with the same name; each chunk is inflated to
//! `(start_sector - part_start_sector) * 512` in the output image and must inflate to exactly
//! `target_size` bytes. Partitions come out as `<name>.img`.
//!
//! Validated against spec-built synthetic fixtures only (see the tests), not real firmware.
use crate::oem::{Item, MAX_IMAGE_BYTES, MAX_ITEMS, Src, clean_name, le32, le64, read_at};
use anyhow::{Context, Result, bail};
use std::fs::File;
use std::io::{Read, Seek, SeekFrom};

pub(crate) const KDZ_MAGIC: [u8; 8] = [0x24, 0x05, 0x00, 0x00, 0x38, 0x31, 0x25, 0x80];
pub(crate) const KDZ_V1_MAGIC: [u8; 8] = [0x28, 0x05, 0x00, 0x00, 0x34, 0x31, 0x25, 0x80];
pub(crate) const DZ_MAGIC: [u8; 4] = [0x32, 0x96, 0x18, 0x74];
const CHUNK_MAGIC: [u8; 4] = [0x30, 0x12, 0x95, 0x78];
const KDZ_RECORD: usize = 272;
const KDZ_MAX_RECORDS: usize = 64;
const DZ_HDR: usize = 512;
const SECTOR: u64 = 512;

/// One zlib chunk of a partition.
pub(crate) struct Chunk {
    data_at: u64,
    data_size: u64,
    target_size: u64,
    out_offset: u64,
}

pub(crate) fn parse_kdz(f: &mut File, file_len: u64) -> Result<Vec<Item>> {
    let mut magic = [0u8; 8];
    read_at(f, 0, &mut magic)?;
    if magic == KDZ_V1_MAGIC {
        bail!("lg-kdz: the v1 KDZ header variant is recognized but not supported");
    }
    if magic != KDZ_MAGIC {
        bail!("lg-kdz: bad magic");
    }
    let mut dz = None;
    for i in 0..KDZ_MAX_RECORDS {
        let at = 8 + (i * KDZ_RECORD) as u64;
        if at + KDZ_RECORD as u64 > file_len {
            bail!("lg-kdz: file table runs past the end of the file");
        }
        let mut rec = [0u8; KDZ_RECORD];
        read_at(f, at, &mut rec)?;
        let cut = rec[..256].iter().position(|&b| b == 0).unwrap_or(256);
        if cut == 0 {
            break;
        }
        let name = String::from_utf8_lossy(&rec[..cut]).to_ascii_lowercase();
        let (size, offset) = (le64(&rec, 256), le64(&rec, 264));
        if offset.checked_add(size).is_none_or(|end| end > file_len) {
            bail!("lg-kdz: entry {name:?} lies outside the file");
        }
        if name.ends_with(".dz") {
            if dz.is_some() {
                bail!("lg-kdz: more than one .dz entry");
            }
            dz = Some((offset, size));
        }
    }
    let Some((offset, size)) = dz else {
        bail!("lg-kdz: no .dz entry in the file table");
    };
    parse_dz(f, offset, size)
}

/// Parse the DZ that occupies `region_len` bytes at `base`.
pub(crate) fn parse_dz(f: &mut File, base: u64, region_len: u64) -> Result<Vec<Item>> {
    if region_len < DZ_HDR as u64 {
        bail!("lg-dz: too short for a DZ header");
    }
    let mut h = [0u8; DZ_HDR];
    read_at(f, base, &mut h)?;
    if h[..4] != DZ_MAGIC {
        bail!("lg-dz: bad magic");
    }
    let count = le32(&h, 0xC0) as usize;
    if count == 0 || count > MAX_ITEMS * 64 {
        bail!("lg-dz: implausible chunk count {count}");
    }
    let end = base + region_len;
    let mut pos = base + DZ_HDR as u64;
    let mut parts: Vec<(String, Vec<Chunk>)> = Vec::new();
    for _ in 0..count {
        if pos + DZ_HDR as u64 > end {
            bail!("lg-dz: chunk table runs past the end of the data");
        }
        read_at(f, pos, &mut h)?;
        if h[..4] != CHUNK_MAGIC {
            bail!("lg-dz: bad chunk magic at offset {pos}");
        }
        let name = clean_name(&h[8..40])?;
        let (target, data) = (le32(&h, 0x28) as u64, le32(&h, 0x2C) as u64);
        let (start, part_start) = (le32(&h, 0x40) as u64, le32(&h, 0x48) as u64);
        let data_at = pos + DZ_HDR as u64;
        if data_at + data > end {
            bail!("lg-dz: chunk data for {name} runs past the end of the file");
        }
        let Some(rel) = start.checked_sub(part_start) else {
            bail!("lg-dz: chunk of {name} starts before its partition");
        };
        let out_offset = rel * SECTOR;
        if out_offset + target > MAX_IMAGE_BYTES {
            bail!("lg-dz: {name} would exceed the {MAX_IMAGE_BYTES} byte image limit");
        }
        let chunk = Chunk {
            data_at,
            data_size: data,
            target_size: target,
            out_offset,
        };
        match parts.iter_mut().find(|(n, _)| *n == name) {
            Some((_, v)) => v.push(chunk),
            None => parts.push((name, vec![chunk])),
        }
        if parts.len() > MAX_ITEMS {
            bail!("lg-dz: more than {MAX_ITEMS} partitions");
        }
        pos = data_at + data;
    }
    Ok(parts
        .into_iter()
        .map(|(name, chunks)| Item {
            name: format!("{name}.img"),
            size: chunks
                .iter()
                .map(|c| c.out_offset + c.target_size)
                .max()
                .unwrap_or(0),
            src: Src::Chunks(chunks),
        })
        .collect())
}

/// Inflate every chunk of one partition into `out`.
pub(crate) fn write_chunks(file: &File, chunks: &[Chunk], out: &mut File) -> Result<()> {
    for c in chunks {
        let mut src = file.try_clone()?;
        src.seek(SeekFrom::Start(c.data_at))?;
        let mut z = flate2::read::ZlibDecoder::new(src.take(c.data_size)).take(c.target_size + 1);
        out.seek(SeekFrom::Start(c.out_offset))?;
        let n = std::io::copy(&mut z, out).context("inflating a DZ chunk")?;
        if n != c.target_size {
            bail!(
                "a DZ chunk inflated to {n} bytes, its header says {}",
                c.target_size
            );
        }
    }
    Ok(())
}

/// Build a synthetic DZ from the layout above (test fixture). Partitions of 4096 bytes or more
/// are split into two chunks so concatenation is exercised.
#[cfg(test)]
pub(crate) fn dz_bytes_for_test(parts: &[(&str, Vec<u8>)]) -> Vec<u8> {
    use flate2::{Compression, write::ZlibEncoder};
    use std::io::Write;
    let mut chunks: Vec<(Vec<u8>, Vec<u8>)> = Vec::new(); // (header, data)
    let mut idx = 0u32;
    for (pi, (name, data)) in parts.iter().enumerate() {
        let part_start = 1000 * (pi as u32 + 1);
        let split = if data.len() >= 4096 {
            data.len() / 2
        } else {
            data.len()
        };
        let pieces: Vec<&[u8]> = if split == data.len() {
            vec![data]
        } else {
            vec![&data[..split], &data[split..]]
        };
        let mut done = 0usize;
        for piece in pieces {
            let mut z = ZlibEncoder::new(Vec::new(), Compression::default());
            z.write_all(piece).unwrap();
            let comp = z.finish().unwrap();
            let mut h = vec![0u8; DZ_HDR];
            h[..4].copy_from_slice(&CHUNK_MAGIC);
            h[4..8].copy_from_slice(&idx.to_le_bytes());
            h[8..8 + name.len()].copy_from_slice(name.as_bytes());
            h[0x28..0x2C].copy_from_slice(&(piece.len() as u32).to_le_bytes());
            h[0x2C..0x30].copy_from_slice(&(comp.len() as u32).to_le_bytes());
            let start = part_start + (done as u64 / SECTOR) as u32;
            h[0x40..0x44].copy_from_slice(&start.to_le_bytes());
            h[0x44..0x48].copy_from_slice(&(piece.len().div_ceil(512) as u32).to_le_bytes());
            h[0x48..0x4C].copy_from_slice(&part_start.to_le_bytes());
            chunks.push((h, comp));
            done += piece.len();
            idx += 1;
        }
    }
    let mut out = vec![0u8; DZ_HDR];
    out[..4].copy_from_slice(&DZ_MAGIC);
    out[4..8].copy_from_slice(&2u32.to_le_bytes());
    out[16..24].copy_from_slice(b"LG-TEST\0");
    out[0xC0..0xC4].copy_from_slice(&(chunks.len() as u32).to_le_bytes());
    for (h, d) in chunks {
        out.extend_from_slice(&h);
        out.extend_from_slice(&d);
    }
    out
}

#[cfg(test)]
pub(crate) fn build_dz_for_test(path: &std::path::Path, parts: &[(&str, Vec<u8>)]) {
    std::fs::write(path, dz_bytes_for_test(parts)).unwrap();
}

/// A synthetic KDZ wrapping the DZ plus an unrelated file (test fixture).
#[cfg(test)]
pub(crate) fn build_kdz_for_test(path: &std::path::Path, parts: &[(&str, Vec<u8>)]) {
    let dz = dz_bytes_for_test(parts);
    let other = b"not a partition".to_vec();
    let table_end = 8 + 3 * KDZ_RECORD as u64;
    let other_at = table_end.next_multiple_of(0x1000);
    let dz_at = (other_at + other.len() as u64).next_multiple_of(0x1000);
    let mut out = vec![0u8; table_end as usize];
    out[..8].copy_from_slice(&KDZ_MAGIC);
    for (i, (name, size, at)) in [
        ("LGUP_Common.dll", other.len() as u64, other_at),
        ("fw_test.dz", dz.len() as u64, dz_at),
    ]
    .iter()
    .enumerate()
    {
        let r = 8 + i * KDZ_RECORD;
        out[r..r + name.len()].copy_from_slice(name.as_bytes());
        out[r + 256..r + 264].copy_from_slice(&size.to_le_bytes());
        out[r + 264..r + 272].copy_from_slice(&at.to_le_bytes());
    }
    out.resize(other_at as usize, 0);
    out.extend_from_slice(&other);
    out.resize(dz_at as usize, 0);
    out.extend_from_slice(&dz);
    std::fs::write(path, out).unwrap();
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::extract::ExtractOptions;
    use crate::oem::tests::expected;
    use crate::oem::{Kind, detect, extract, list};
    use crate::testutil::Scratch;

    fn raw_parts() -> Vec<(&'static str, Vec<u8>)> {
        vec![("boot", expected("boot")), ("system", expected("system"))]
    }

    #[test]
    fn a_dz_unwraps_chunks_into_partitions() {
        let d = Scratch::new("lg-dz");
        let dz = d.join("fw.dz");
        build_dz_for_test(&dz, &raw_parts());
        assert_eq!(detect(&dz), Some(Kind::LgDz));
        assert_eq!(crate::detect::identify_path(&dz).unwrap().id, "lg-dz");
        let opts = ExtractOptions::default();
        assert_eq!(
            list(Kind::LgDz, &dz, &opts).unwrap(),
            [
                ("boot.img".to_string(), 100),
                ("system.img".to_string(), 4096)
            ]
        );
        let out = d.join("out");
        extract(Kind::LgDz, &dz, &out, &opts).unwrap();
        assert_eq!(
            std::fs::read(out.join("boot.img")).unwrap(),
            expected("boot")
        );
        assert_eq!(
            std::fs::read(out.join("system.img")).unwrap(),
            expected("system"),
            "two chunks of one partition are placed back to back"
        );
    }

    #[test]
    fn a_kdz_is_unwrapped_through_its_dz_entry() {
        let d = Scratch::new("lg-kdz");
        let kdz = d.join("fw.kdz");
        build_kdz_for_test(&kdz, &raw_parts());
        assert_eq!(detect(&kdz), Some(Kind::LgKdz));
        assert_eq!(crate::detect::identify_path(&kdz).unwrap().id, "lg-kdz");
        let out = d.join("out");
        let r = crate::extract::extract_all_noted(&kdz, &out, &ExtractOptions::default()).unwrap();
        assert_eq!(r.done.len(), 2);
        assert_eq!(
            std::fs::read(out.join("boot.img")).unwrap(),
            expected("boot")
        );
        assert_eq!(
            std::fs::read(out.join("system.img")).unwrap(),
            expected("system")
        );
        assert_eq!(
            crate::extract::partition_names(&kdz).unwrap(),
            ["boot", "system"]
        );
    }

    #[test]
    fn corrupt_input_is_refused_not_guessed() {
        let d = Scratch::new("lg-bad");
        let good = dz_bytes_for_test(&raw_parts());
        let opts = ExtractOptions::default();
        let try_dz = |n: &str, b: &[u8]| {
            let p = d.join(format!("{n}.dz"));
            std::fs::write(&p, b).unwrap();
            extract(Kind::LgDz, &p, &d.join(format!("o-{n}")), &opts)
        };
        assert!(try_dz("trunc", &good[..700]).is_err());
        let mut b = good.clone();
        b[0xC0..0xC4].copy_from_slice(&u32::MAX.to_le_bytes());
        assert!(try_dz("count", &b).is_err());
        let mut b = good.clone();
        b[512..516].copy_from_slice(b"xxxx"); // first chunk magic
        assert!(try_dz("chunkmagic", &b).is_err());
        let mut b = good.clone();
        b[512 + 0x28..512 + 0x2C].copy_from_slice(&7u32.to_le_bytes()); // wrong target size
        assert!(try_dz("target", &b).is_err());
        let mut b = good.clone();
        let data_at = 1024;
        b[data_at + 2] ^= 0xFF; // corrupt zlib stream
        assert!(try_dz("zlib", &b).is_err());
        let mut b = good.clone();
        b[512 + 8..512 + 12].copy_from_slice(b"../x"); // traversal name
        assert!(try_dz("name", &b).is_err());
        assert!(!d.join("o-zlib").join("boot.img.part").exists());
        // the v1 KDZ header is named, not guessed at
        let p = d.join("v1.kdz");
        let mut v1 = KDZ_V1_MAGIC.to_vec();
        v1.resize(4096, 0);
        std::fs::write(&p, v1).unwrap();
        let e = extract(Kind::LgKdz, &p, &d.join("o-v1"), &opts).unwrap_err();
        assert!(e.to_string().contains("not supported"), "{e}");
    }
}
