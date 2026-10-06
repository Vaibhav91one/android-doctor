//! Nokia `.nb0` firmware container, read from its documented on-disk layout.
//!
//! All integers are little-endian. A `.nb0` has no magic number, so it is recognised by file
//! extension and the header is then validated strictly: a file that does not fit is refused, never
//! half-parsed.
//!
//! | offset            | size | meaning                                                  |
//! |-------------------|------|----------------------------------------------------------|
//! | 0x00              | 4    | entry count `n` (1..=1024)                               |
//! | 0x04 + 48*i       | 4    | entry `i` offset of its blob from byte 0 of the file     |
//! | 0x08 + 48*i       | 4    | entry `i` length of its blob                             |
//! | 0x0C + 48*i       | 8    | flags / reserved (ignored)                               |
//! | 0x14 + 48*i       | 32   | entry `i` name, NUL padded                               |
//!
//! The blobs follow the table. Each is written as `<name>.img` (a name that already ends in
//! `.img` is not doubled); an Android sparse blob is expanded by the shared writer.
//!
//! Caveat: the layout follows the simple public description (count, fixed-size entry table, raw
//! blobs), not real firmware. It is validated against spec-built synthetic fixtures only (see the
//! tests). Variants with a different entry size are refused by the bounds checks, not guessed at.
use crate::oem::{Item, MAX_ITEMS, clean_name, le32, range_item, read_at};
use anyhow::{Result, bail};
use std::fs::File;

const ENTRY: u64 = 48;

pub(crate) fn parse(f: &mut File, file_len: u64) -> Result<Vec<Item>> {
    if file_len < 4 {
        bail!("nokia-nb0: too short for a header");
    }
    let mut c = [0u8; 4];
    read_at(f, 0, &mut c)?;
    let count = u32::from_le_bytes(c) as u64;
    if count == 0 || count > MAX_ITEMS as u64 {
        bail!("nokia-nb0: implausible entry count {count}; not an NB0 container");
    }
    let table_end = 4 + count * ENTRY;
    if table_end > file_len {
        bail!("nokia-nb0: entry table ({count} entries) runs past the {file_len} byte file");
    }
    let mut table = vec![0u8; (count * ENTRY) as usize];
    read_at(f, 4, &mut table)?;
    let mut items = Vec::with_capacity(count as usize);
    for i in 0..count as usize {
        let e = &table[i * ENTRY as usize..][..ENTRY as usize];
        let (offset, len) = (le32(e, 0) as u64, le32(e, 4) as u64);
        let mut name = clean_name(&e[16..48])?;
        if offset < table_end {
            bail!("nokia-nb0: {name}: blob offset {offset} lies inside the header");
        }
        if !name.ends_with(".img") {
            name.push_str(".img");
        }
        items.push(range_item(f, name, offset, len, file_len)?);
    }
    Ok(items)
}

/// Build a synthetic `.nb0` holding `parts` (test fixture).
#[cfg(test)]
pub(crate) fn build_for_test(path: &std::path::Path, parts: &[(&str, Vec<u8>)]) {
    let mut out = Vec::new();
    out.extend_from_slice(&(parts.len() as u32).to_le_bytes());
    let mut at = 4 + parts.len() as u32 * ENTRY as u32;
    for (name, data) in parts {
        out.extend_from_slice(&at.to_le_bytes());
        out.extend_from_slice(&(data.len() as u32).to_le_bytes());
        out.extend_from_slice(&[0u8; 8]);
        let mut n = [0u8; 32];
        n[..name.len()].copy_from_slice(name.as_bytes());
        out.extend_from_slice(&n);
        at += data.len() as u32;
    }
    for (_, data) in parts {
        out.extend_from_slice(data);
    }
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
    fn lists_and_extracts_both_partitions() {
        let d = Scratch::new("nb0-ok");
        let nb0 = d.join("fw.nb0");
        build_for_test(&nb0, &fake_parts());
        assert_eq!(detect(&nb0), Some(Kind::NokiaNb0));
        let opts = ExtractOptions::default();
        assert_eq!(
            list(Kind::NokiaNb0, &nb0, &opts).unwrap(),
            [
                ("boot.img".to_string(), 100),
                ("system.img".to_string(), 4096)
            ]
        );
        let out = d.join("out");
        extract(Kind::NokiaNb0, &nb0, &out, &opts).unwrap();
        for n in ["boot", "system"] {
            assert_eq!(
                std::fs::read(out.join(format!("{n}.img"))).unwrap(),
                expected(n)
            );
        }
    }

    #[test]
    fn a_name_already_ending_in_img_is_not_doubled() {
        let d = Scratch::new("nb0-img");
        let nb0 = d.join("fw.nb0");
        build_for_test(&nb0, &[("boot.img", vec![1; 8])]);
        let l = list(Kind::NokiaNb0, &nb0, &ExtractOptions::default()).unwrap();
        assert_eq!(l, [("boot.img".to_string(), 8)]);
    }

    #[test]
    fn hostile_input_is_refused_without_panic() {
        let d = Scratch::new("nb0-bad");
        let opts = ExtractOptions::default();
        let good = d.join("good.nb0");
        build_for_test(&good, &fake_parts());
        let good = std::fs::read(&good).unwrap();
        let mut cases: Vec<(String, Vec<u8>)> = vec![
            ("empty".into(), vec![]),
            ("junk".into(), b"hello world".to_vec()),
            ("zero".into(), vec![0; 64]),
            ("huge".into(), u32::MAX.to_le_bytes().to_vec()),
        ];
        // every truncation of a valid file (the last blob is cut, so each must be refused)
        for n in 0..good.len() - 1 {
            cases.push((format!("cut{n}"), good[..n].to_vec()));
        }
        // blob past the end, blob inside the header, hostile name
        let mut b = good.clone();
        b[4..8].copy_from_slice(&u32::MAX.to_le_bytes());
        cases.push(("offset-oob".into(), b));
        let mut b = good.clone();
        b[4..8].copy_from_slice(&0u32.to_le_bytes());
        cases.push(("offset-in-header".into(), b));
        let mut b = good.clone();
        b[4 + 16..4 + 19].copy_from_slice(b"../");
        cases.push(("name".into(), b));
        for (n, bytes) in cases {
            let p = d.join(format!("{n}.nb0"));
            std::fs::write(&p, &bytes).unwrap();
            let r = extract(Kind::NokiaNb0, &p, &d.join(format!("o-{n}")), &opts);
            assert!(r.is_err(), "{n} was accepted");
        }
    }
}
