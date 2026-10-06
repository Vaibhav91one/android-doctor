//! Huawei `UPDATE.APP` full-firmware container, read from its public on-disk layout.
//!
//! The file is a sequence of records. Each record is a header followed by one partition image,
//! and the next record starts at the next 4-byte boundary:
//!
//! | offset | size | meaning                                                          |
//! |--------|------|------------------------------------------------------------------|
//! | 0x00   | 4    | magic `55 AA 5A A5`                                              |
//! | 0x04   | 4    | header length, `u32` LE: offset from the record start to the data |
//! | 0x08   | 4    | format/unknown word                                              |
//! | 0x0C   | 8    | hardware (product) id, ASCII                                     |
//! | 0x14   | 4    | file sequence number, `u32` LE                                   |
//! | 0x18   | 4    | file (image) size in bytes, `u32` LE                             |
//! | 0x1C   | 16   | date, ASCII                                                      |
//! | 0x2C   | 16   | time, ASCII                                                      |
//! | 0x3C   | 16   | partition name, ASCII, NUL padded (`SYSTEM`, `BOOT`, ...)        |
//! | 0x4C   | 2    | header CRC                                                       |
//! | 0x4E   | 2    | block size the per-block CRC table was computed with             |
//! | 0x50   | 2    | reserved                                                         |
//!
//! The fixed part is 82 bytes; the header length field also covers the per-block CRC table that
//! follows it, so the image is read from `record + header length`, never from a fixed offset.
//! The CRC fields are not verified: the container carries no hash we could trust for authenticity.
//! Partition names are lower-cased and written as `<name>.img`; an Android sparse payload is
//! expanded by the shared writer.
//!
//! Validated against spec-built synthetic fixtures only (see the tests), not real firmware.
use crate::oem::{Item, MAX_ITEMS, clean_name, le32, range_item, read_at};
use anyhow::{Result, bail};
use std::fs::File;

pub(crate) const MAGIC: [u8; 4] = [0x55, 0xAA, 0x5A, 0xA5];
const FIXED_LEN: usize = 82;
const NAME_AT: usize = 0x3C;
const NAME_LEN: usize = 16;

pub(crate) fn parse(f: &mut File, file_len: u64) -> Result<Vec<Item>> {
    let mut items = Vec::new();
    let mut pos = 0u64;
    while pos + FIXED_LEN as u64 <= file_len {
        let mut h = [0u8; FIXED_LEN];
        read_at(f, pos, &mut h)?;
        if h[..4] != MAGIC {
            // Zero padding after the last record is fine; anything else is not an UPDATE.APP.
            if !items.is_empty() && h.iter().all(|&b| b == 0) {
                break;
            }
            bail!("huawei-update-app: bad record magic at offset {pos}");
        }
        if items.len() >= MAX_ITEMS {
            bail!("huawei-update-app: more than {MAX_ITEMS} records");
        }
        let hdr_len = le32(&h, 4) as u64;
        let size = le32(&h, 0x18) as u64;
        if hdr_len < FIXED_LEN as u64 {
            bail!(
                "huawei-update-app: record at {pos} has header length {hdr_len}, below the {FIXED_LEN} byte minimum"
            );
        }
        let name = format!("{}.img", clean_name(&h[NAME_AT..NAME_AT + NAME_LEN])?);
        let data_at = pos + hdr_len;
        items.push(range_item(f, name, data_at, size, file_len)?);
        pos = (data_at + size + 3) & !3;
    }
    if items.is_empty() {
        bail!("huawei-update-app: no records");
    }
    Ok(items)
}

/// Build a synthetic UPDATE.APP from the layout above (test fixture).
#[cfg(test)]
pub(crate) fn build_for_test(path: &std::path::Path, parts: &[(&str, Vec<u8>)]) {
    let mut out = Vec::new();
    for (i, (name, data)) in parts.iter().enumerate() {
        let crc_table = [0xEE; 6]; // stands in for the per-block CRC table
        let hdr_len = FIXED_LEN + crc_table.len();
        let mut h = vec![0u8; FIXED_LEN];
        h[..4].copy_from_slice(&MAGIC);
        h[4..8].copy_from_slice(&(hdr_len as u32).to_le_bytes());
        h[0x0C..0x0C + 6].copy_from_slice(b"HWTEST");
        h[0x14..0x18].copy_from_slice(&(i as u32).to_le_bytes());
        h[0x18..0x1C].copy_from_slice(&(data.len() as u32).to_le_bytes());
        h[0x1C..0x1C + 8].copy_from_slice(b"20260101");
        h[0x2C..0x2C + 6].copy_from_slice(b"120000");
        let upper = name.to_ascii_uppercase();
        h[NAME_AT..NAME_AT + upper.len()].copy_from_slice(upper.as_bytes());
        h[0x4E..0x50].copy_from_slice(&4096u16.to_le_bytes());
        out.extend_from_slice(&h);
        out.extend_from_slice(&crc_table);
        out.extend_from_slice(data);
        while out.len() % 4 != 0 {
            out.push(0);
        }
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
    fn unwraps_to_the_partition_images() {
        let d = Scratch::new("huawei-ok");
        let app = d.join("UPDATE.APP");
        // an odd-sized image forces the 4-byte padding between records
        let mut parts = fake_parts();
        parts.insert(0, ("cust", vec![7u8; 33]));
        build_for_test(&app, &parts);
        assert_eq!(detect(&app), Some(Kind::HuaweiApp));
        let opts = ExtractOptions::default();
        assert_eq!(
            list(Kind::HuaweiApp, &app, &opts).unwrap(),
            [
                ("boot.img".to_string(), 100),
                ("cust.img".to_string(), 33),
                ("system.img".to_string(), 4096)
            ]
        );
        let out = d.join("out");
        let paths = extract(Kind::HuaweiApp, &app, &out, &opts).unwrap();
        assert_eq!(paths.len(), 3);
        assert_eq!(std::fs::read(out.join("cust.img")).unwrap(), vec![7u8; 33]);
        assert_eq!(
            std::fs::read(out.join("boot.img")).unwrap(),
            expected("boot")
        );
        assert_eq!(
            std::fs::read(out.join("system.img")).unwrap(),
            expected("system"),
            "the sparse payload is expanded"
        );
    }

    #[test]
    fn identify_names_it_by_magic_whatever_the_file_is_called() {
        let d = Scratch::new("huawei-id");
        for name in ["UPDATE.APP", "renamed.bin"] {
            let p = d.join(name);
            build_for_test(&p, &fake_parts());
            let id = crate::detect::identify_path(&p).unwrap();
            assert_eq!(id.id, "huawei-update-app");
        }
    }

    #[test]
    fn extract_all_routes_through_the_shared_entry_points() {
        let d = Scratch::new("huawei-route");
        let app = d.join("UPDATE.APP");
        build_for_test(&app, &fake_parts());
        let r = crate::extract::extract_all_noted(&app, &d.join("o"), &ExtractOptions::default())
            .unwrap();
        assert_eq!(r.done.len(), 2);
        assert_eq!(
            crate::extract::partition_names(&app).unwrap(),
            ["boot", "system"]
        );
        assert_eq!(
            crate::extract::list_images(&app, &ExtractOptions::default())
                .unwrap()
                .len(),
            2
        );
    }

    #[test]
    fn only_selects_and_unknown_names_fail() {
        let d = Scratch::new("huawei-only");
        let app = d.join("UPDATE.APP");
        build_for_test(&app, &fake_parts());
        let mut opts = ExtractOptions {
            only: Some(vec!["boot".into()]),
            ..Default::default()
        };
        assert_eq!(
            extract(Kind::HuaweiApp, &app, &d.join("o"), &opts)
                .unwrap()
                .len(),
            1
        );
        opts.only = Some(vec!["nope".into()]);
        assert!(extract(Kind::HuaweiApp, &app, &d.join("o2"), &opts).is_err());
    }

    #[test]
    fn corrupt_containers_are_refused_not_guessed() {
        let d = Scratch::new("huawei-bad");
        let app = d.join("UPDATE.APP");
        build_for_test(&app, &fake_parts());
        let good = std::fs::read(&app).unwrap();
        let opts = ExtractOptions::default();
        let try_bytes = |name: &str, b: &[u8]| {
            let p = d.join(name);
            std::fs::write(&p, b).unwrap();
            extract(Kind::HuaweiApp, &p, &d.join(format!("o-{name}")), &opts)
        };
        // truncated inside the first image
        assert!(try_bytes("trunc", &good[..120]).is_err());
        // header length below the fixed part
        let mut b = good.clone();
        b[4..8].copy_from_slice(&10u32.to_le_bytes());
        assert!(try_bytes("hl", &b).is_err());
        // image size past the end of the file
        let mut b = good.clone();
        b[0x18..0x1C].copy_from_slice(&u32::MAX.to_le_bytes());
        assert!(try_bytes("size", &b).is_err());
        // a path-traversal partition name
        let mut b = good.clone();
        b[NAME_AT..NAME_AT + 4].copy_from_slice(b"../x");
        assert!(try_bytes("name", &b).is_err());
        // junk where the second record's magic should be
        let mut b = good.clone();
        let second = (82 + 6 + 100 + 3) & !3;
        b[second..second + 4].copy_from_slice(b"junk");
        assert!(try_bytes("junk", &b).is_err());
        // a failed run leaves no partial files
        assert!(!d.join("o-trunc").join("boot.img.part").exists());
    }
}
