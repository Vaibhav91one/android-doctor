//! Recognise firmware files and filesystems by their magic bytes (never by file name).
use anyhow::{Context, Result};
use std::fmt;
use std::fs::File;
use std::io::Read;
use std::path::Path;

/// Bytes needed from the start of an image to recognise the supported filesystems
/// (the ext superblock feature flags end at offset 1128).
pub const HEAD_LEN: usize = 1128;

const EXT_MAGIC: u16 = 0xEF53;
const EROFS_MAGIC: u32 = 0xE0F5_E1E2;
/// `s_feature_compat`: has_journal.
const COMPAT_HAS_JOURNAL: u32 = 0x4;
/// `s_feature_incompat` bits that only ext4 knows: extents, 64bit, mmp, flex_bg, ea_inode,
/// dirdata, csum_seed, largedir, inline_data, encrypt, casefold.
const INCOMPAT_EXT4: u32 =
    0x40 | 0x80 | 0x100 | 0x200 | 0x400 | 0x1000 | 0x2000 | 0x4000 | 0x8000 | 0x10000 | 0x20000;
/// `s_feature_ro_compat` bits that only ext4 knows: huge_file, gdt_csum, dir_nlink, extra_isize,
/// quota, bigalloc, metadata_csum, project, verity.
const RO_COMPAT_EXT4: u32 = 0x8 | 0x10 | 0x20 | 0x40 | 0x100 | 0x200 | 0x400 | 0x2000 | 0x8000;

#[derive(Debug, PartialEq, Clone, Copy)]
pub enum Filesystem {
    Ext2,
    Ext3,
    Ext4,
    Erofs,
}

impl fmt::Display for Filesystem {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str(match self {
            Self::Ext2 => "ext2",
            Self::Ext3 => "ext3",
            Self::Ext4 => "ext4",
            Self::Erofs => "erofs",
        })
    }
}

fn le16(b: &[u8], at: usize) -> u16 {
    u16::from_le_bytes([b[at], b[at + 1]])
}

fn le32(b: &[u8], at: usize) -> u32 {
    u32::from_le_bytes([b[at], b[at + 1], b[at + 2], b[at + 3]])
}

/// Recognise a filesystem from the first `HEAD_LEN` bytes of an image. Same rule as e2fsprogs'
/// blkid: any ext4-only feature means ext4, else a journal means ext3, else ext2.
pub fn filesystem(head: &[u8]) -> Option<Filesystem> {
    if head.len() >= 1024 + 4 && le32(head, 1024) == EROFS_MAGIC {
        return Some(Filesystem::Erofs);
    }
    if head.len() < HEAD_LEN || le16(head, 1024 + 0x38) != EXT_MAGIC {
        return None;
    }
    let (compat, incompat, ro_compat) = (
        le32(head, 1024 + 0x5C),
        le32(head, 1024 + 0x60),
        le32(head, 1024 + 0x64),
    );
    Some(
        if incompat & INCOMPAT_EXT4 != 0 || ro_compat & RO_COMPAT_EXT4 != 0 {
            Filesystem::Ext4
        } else if compat & COMPAT_HAS_JOURNAL != 0 {
            Filesystem::Ext3
        } else {
            Filesystem::Ext2
        },
    )
}

/// Bytes read from the start of a file to identify it (the LP geometry sits at offset 4096).
pub const SNIFF_LEN: usize = 4100;

const LP_GEOMETRY_MAGIC: [u8; 4] = *b"gDla"; // 0x616c4467, little-endian, at offset 4096

/// What a file is, by magic bytes. `id` is stable (used in `--json`), `description` is for people.
#[derive(Debug, PartialEq, Clone)]
pub struct Identified {
    pub id: &'static str,
    pub description: String,
}

fn found(id: &'static str, description: &str) -> Option<Identified> {
    Some(Identified {
        id,
        description: description.to_string(),
    })
}

/// Identify a file from its first `SNIFF_LEN` bytes. Magic at offset 0 is checked first, then
/// the formats whose magic sits deeper (tar at 257, filesystems at 1024, LP at 4096).
/// Zip contents are not looked at here, see `identify_path`.
pub fn sniff(head: &[u8]) -> Option<Identified> {
    let at0 = |magic: &[u8]| head.starts_with(magic);
    if at0(b"PK\x03\x04") || at0(b"PK\x05\x06") {
        return found("zip", "zip archive");
    }
    if at0(b"CrAU") {
        return found("payload-bin", "A/B update payload (CrAU)");
    }
    if at0(b"ANDROID!") {
        return found("boot-image", "Android boot image");
    }
    if at0(b"VNDRBOOT") {
        return found("vendor-boot", "Android vendor boot image");
    }
    if at0(b"AVB0") {
        return found("avb-vbmeta", "AVB vbmeta image");
    }
    if at0(&[0x3A, 0xFF, 0x26, 0xED]) {
        return found("android-sparse", "Android sparse image");
    }
    if at0(&[0xD7, 0xB7, 0xAB, 0x1E]) {
        return found("dtbo", "Android dtbo table");
    }
    if at0(b"OPPOENCRYPT!") {
        return found("ozip", "Oppo ozip (encrypted zip)");
    }
    if at0(&[0x1F, 0x8B, 0x08]) {
        return found("gzip", "gzip compressed data");
    }
    if at0(&[0xFD, b'7', b'z', b'X', b'Z', 0x00]) {
        return found("xz", "xz compressed data");
    }
    if at0(b"BZh") && head.get(3).is_some_and(|b| (b'1'..=b'9').contains(b)) {
        return found("bzip2", "bzip2 compressed data");
    }
    if at0(&[0x04, 0x22, 0x4D, 0x18]) {
        return found("lz4", "lz4 compressed data (frame)");
    }
    if at0(&[0x02, 0x21, 0x4C, 0x18]) {
        return found("lz4-legacy", "lz4 compressed data (legacy format)");
    }
    if at0(b"070701") || at0(b"070702") {
        return found("cpio", "cpio archive (newc)");
    }
    if at0(b"@AML") {
        return found(
            "aml-container",
            "Amlogic container (secure-boot images are encrypted)",
        );
    }
    if at0(&[0x28, 0xB5, 0x2F, 0xFD]) {
        return found("zstd", "zstd compressed data");
    }
    if head.len() >= 262 && &head[257..262] == b"ustar" {
        return found("tar", "tar archive");
    }
    if let Some(fs) = filesystem(head) {
        let id = match fs {
            Filesystem::Ext2 => "ext2",
            Filesystem::Ext3 => "ext3",
            Filesystem::Ext4 => "ext4",
            Filesystem::Erofs => "erofs",
        };
        return found(id, &format!("{fs} filesystem"));
    }
    if head.len() >= 4100 && head[4096..4100] == LP_GEOMETRY_MAGIC {
        return found("lp-super", "Android super image (dynamic partitions)");
    }
    None
}

/// Opening a FIFO blocks until someone writes to it, and a socket cannot be read as a file, so
/// both are refused up front. Regular files and block/character devices are fine.
pub(crate) fn refuse_blocking_file(path: &Path) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::FileTypeExt;
        let kind = std::fs::metadata(path)
            .with_context(|| format!("opening {}", path.display()))?
            .file_type();
        if kind.is_fifo() || kind.is_socket() {
            anyhow::bail!("{} is a FIFO or socket, not a file", path.display());
        }
    }
    let _ = path;
    Ok(())
}

/// Identify a file or directory. A zip is opened to tell block OTAs (`*.transfer.list` at the
/// top level) and A/B OTAs (`payload.bin`) from ordinary archives; a directory is a block OTA
/// when it holds transfer lists.
pub fn identify_path(path: &Path) -> Result<Identified> {
    if path.is_dir() {
        let has_lists = std::fs::read_dir(path)?
            .filter_map(|e| e.ok())
            .any(|e| e.file_name().to_string_lossy().ends_with(".transfer.list"));
        return Ok(if has_lists {
            Identified {
                id: "block-ota-dir",
                description: "directory holding a block OTA".into(),
            }
        } else {
            Identified {
                id: "directory",
                description: "directory".into(),
            }
        });
    }
    refuse_blocking_file(path)?;
    let mut head = Vec::with_capacity(SNIFF_LEN);
    File::open(path)
        .with_context(|| format!("opening {}", path.display()))?
        .take(SNIFF_LEN as u64)
        .read_to_end(&mut head)
        .with_context(|| format!("reading {}", path.display()))?;
    let identified = sniff(&head).unwrap_or(Identified {
        id: "unknown",
        description: "unknown format".into(),
    });
    if identified.id != "zip" {
        return Ok(identified);
    }
    let names = File::open(path)
        .map_err(anyhow::Error::from)
        .and_then(|f| Ok(zip::ZipArchive::new(f)?))
        .map(|z| z.file_names().map(String::from).collect::<Vec<_>>());
    Ok(match names {
        Ok(names) if names.iter().any(|n| n == "payload.bin") => Identified {
            id: "ab-ota-zip",
            description: "zip: A/B OTA (payload.bin)".into(),
        },
        Ok(names)
            if names
                .iter()
                .any(|n| !n.contains('/') && n.ends_with(".transfer.list")) =>
        {
            Identified {
                id: "block-ota-zip",
                description: "zip: block OTA (*.transfer.list)".into(),
            }
        }
        Ok(_) => identified,
        Err(e) => Identified {
            id: "zip",
            description: format!("zip archive (entries unreadable: {e})"),
        },
    })
}

/// `filesystem()` for a file on disk; unreadable or short files are simply unrecognised.
pub fn filesystem_of_file(path: &Path) -> Option<Filesystem> {
    let mut head = Vec::with_capacity(HEAD_LEN);
    File::open(path)
        .ok()?
        .take(HEAD_LEN as u64)
        .read_to_end(&mut head)
        .ok()?;
    filesystem(&head)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ext(compat: u32, incompat: u32, ro_compat: u32) -> Vec<u8> {
        let mut b = vec![0u8; HEAD_LEN];
        b[1024 + 0x38..1024 + 0x3A].copy_from_slice(&EXT_MAGIC.to_le_bytes());
        b[1024 + 0x5C..1024 + 0x60].copy_from_slice(&compat.to_le_bytes());
        b[1024 + 0x60..1024 + 0x64].copy_from_slice(&incompat.to_le_bytes());
        b[1024 + 0x64..1024 + 0x68].copy_from_slice(&ro_compat.to_le_bytes());
        b
    }

    #[test]
    fn ext_family_is_told_apart_by_feature_flags() {
        assert_eq!(filesystem(&ext(0, 0, 0)), Some(Filesystem::Ext2));
        assert_eq!(filesystem(&ext(0x38, 0x2, 0x3)), Some(Filesystem::Ext2));
        assert_eq!(
            filesystem(&ext(COMPAT_HAS_JOURNAL, 0x2, 0x3)),
            Some(Filesystem::Ext3)
        );
        // the flags of a real Android system image: filetype + extents + flex_bg, huge_file etc.
        assert_eq!(filesystem(&ext(0x38, 0x242, 0x7b)), Some(Filesystem::Ext4));
        assert_eq!(
            filesystem(&ext(0, 0x40, 0)),
            Some(Filesystem::Ext4),
            "extents alone"
        );
        assert_eq!(
            filesystem(&ext(0, 0, 0x400)),
            Some(Filesystem::Ext4),
            "metadata_csum alone"
        );
        assert_eq!(
            filesystem(&ext(COMPAT_HAS_JOURNAL, 0x40, 0)),
            Some(Filesystem::Ext4),
            "journal does not demote ext4"
        );
    }

    #[test]
    fn every_ext4_feature_bit_alone_makes_ext4_and_classic_bits_do_not() {
        for bit in [
            0x40, 0x80, 0x100, 0x200, 0x400, 0x1000, 0x2000, 0x4000, 0x8000, 0x10000, 0x20000,
        ] {
            assert_eq!(
                filesystem(&ext(0, bit, 0)),
                Some(Filesystem::Ext4),
                "incompat {bit:#x}"
            );
        }
        for bit in [0x8, 0x10, 0x20, 0x40, 0x100, 0x200, 0x400, 0x2000, 0x8000] {
            assert_eq!(
                filesystem(&ext(0, 0, bit)),
                Some(Filesystem::Ext4),
                "ro_compat {bit:#x}"
            );
        }
        // features that already existed in ext2/ext3: filetype, recover, meta_bg; sparse_super, large_file
        for bit in [0x2, 0x4, 0x10] {
            assert_eq!(
                filesystem(&ext(0, bit, 0)),
                Some(Filesystem::Ext2),
                "incompat {bit:#x}"
            );
        }
        for bit in [0x1, 0x2] {
            assert_eq!(
                filesystem(&ext(0, 0, bit)),
                Some(Filesystem::Ext2),
                "ro_compat {bit:#x}"
            );
        }
        for compat in [0x8, 0x10, 0x20] {
            assert_eq!(
                filesystem(&ext(compat, 0, 0)),
                Some(Filesystem::Ext2),
                "compat {compat:#x}"
            );
        }
    }

    #[test]
    fn no_input_length_can_panic() {
        let mut erofs = vec![0u8; HEAD_LEN];
        erofs[1024..1028].copy_from_slice(&EROFS_MAGIC.to_le_bytes());
        let ext4 = ext(0, 0x40, 0);
        for n in 0..=HEAD_LEN + 8 {
            let mut padded_erofs = erofs.clone();
            padded_erofs.resize(n.max(HEAD_LEN), 0);
            let _ = filesystem(&erofs[..n.min(HEAD_LEN)]);
            let _ = filesystem(&ext4[..n.min(HEAD_LEN)]);
            let _ = filesystem(&padded_erofs[..n]);
        }
        // exact boundaries: erofs needs 1028 bytes, ext needs HEAD_LEN
        assert_eq!(filesystem(&erofs[..1027]), None);
        assert_eq!(filesystem(&erofs[..1028]), Some(Filesystem::Erofs));
        assert_eq!(filesystem(&ext4[..HEAD_LEN - 1]), None);
        assert_eq!(filesystem(&ext4), Some(Filesystem::Ext4));
    }

    #[test]
    fn the_journal_flag_is_0x4_and_ext_attr_0x8_is_not_a_journal() {
        assert_eq!(filesystem(&ext(0x4, 0, 0)), Some(Filesystem::Ext3));
        assert_eq!(filesystem(&ext(0x8, 0, 0)), Some(Filesystem::Ext2));
        // flags of the real Android images: ext_attr + resize_inode + dir_index, no journal
        assert_eq!(filesystem(&ext(0x38, 0, 0)), Some(Filesystem::Ext2));
    }

    #[test]
    fn erofs_is_recognised_by_its_magic_at_1024() {
        let mut b = vec![0u8; HEAD_LEN];
        b[1024..1028].copy_from_slice(&EROFS_MAGIC.to_le_bytes());
        assert_eq!(filesystem(&b), Some(Filesystem::Erofs));
        assert_eq!(
            filesystem(&b[..1028]),
            Some(Filesystem::Erofs),
            "needs only the magic"
        );
        assert_eq!(
            &b[1024..1028],
            [0xe2, 0xe1, 0xf5, 0xe0],
            "byte order as seen in a real image"
        );
    }

    #[test]
    fn anything_else_is_not_recognised() {
        assert_eq!(filesystem(&[]), None);
        assert_eq!(filesystem(&vec![0u8; HEAD_LEN]), None);
        assert_eq!(
            filesystem(&ext(0, 0, 0)[..HEAD_LEN - 1]),
            None,
            "too short for the feature flags"
        );
        let mut wrong_place = vec![0u8; HEAD_LEN];
        wrong_place[100..102].copy_from_slice(&EXT_MAGIC.to_le_bytes());
        assert_eq!(filesystem(&wrong_place), None);
        let mut boot = vec![0u8; HEAD_LEN];
        boot[..8].copy_from_slice(b"ANDROID!");
        assert_eq!(filesystem(&boot), None);
    }

    #[test]
    fn files_on_disk_are_read_from_the_start_and_short_files_are_fine() {
        let dir =
            std::env::temp_dir().join(format!("android-doctor-detect-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let mut image = ext(0, 0x40, 0);
        image.extend(vec![0xAB; 8192]); // data after the header must not matter
        std::fs::write(dir.join("a.img"), &image).unwrap();
        std::fs::write(dir.join("tiny.img"), b"hi").unwrap();
        assert_eq!(
            filesystem_of_file(&dir.join("a.img")),
            Some(Filesystem::Ext4)
        );
        assert_eq!(filesystem_of_file(&dir.join("tiny.img")), None);
        assert_eq!(filesystem_of_file(&dir.join("missing.img")), None);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    fn head_with(at: usize, magic: &[u8]) -> Vec<u8> {
        // a little longer than SNIFF_LEN so a magic can be probed just past the expected offset
        let mut b = vec![0u8; SNIFF_LEN + 8];
        b[at..at + magic.len()].copy_from_slice(magic);
        b
    }

    fn id_of(head: &[u8]) -> &'static str {
        sniff(head).map_or("none", |i| i.id)
    }

    #[test]
    fn every_magic_maps_to_its_id() {
        let table: &[(usize, &[u8], &str)] = &[
            (0, b"PK\x03\x04", "zip"),
            (0, b"PK\x05\x06", "zip"),
            (0, b"CrAU", "payload-bin"),
            (0, b"ANDROID!", "boot-image"),
            (0, b"VNDRBOOT", "vendor-boot"),
            (0, b"AVB0", "avb-vbmeta"),
            (0, &[0x3A, 0xFF, 0x26, 0xED], "android-sparse"),
            (0, &[0xD7, 0xB7, 0xAB, 0x1E], "dtbo"),
            (0, b"OPPOENCRYPT!", "ozip"),
            (0, &[0x1F, 0x8B, 0x08], "gzip"),
            (0, &[0xFD, b'7', b'z', b'X', b'Z', 0x00], "xz"),
            (0, b"BZh9", "bzip2"),
            (0, b"BZh1", "bzip2"),
            (0, &[0x04, 0x22, 0x4D, 0x18], "lz4"),
            (0, &[0x28, 0xB5, 0x2F, 0xFD], "zstd"),
            (257, b"ustar", "tar"),
            (4096, b"gDla", "lp-super"),
        ];
        for (at, magic, id) in table {
            assert_eq!(id_of(&head_with(*at, magic)), *id, "{id} at {at}");
        }
    }

    #[test]
    fn near_misses_are_not_recognised() {
        for (at, magic) in [
            (0usize, &b"PK\x03\x05"[..]),
            (0, b"CrAV"),
            (0, b"ANDROID?"),
            (0, b"BZh0"),
            (0, b"BZhx"),
            (0, &[0x1F, 0x8B, 0x07]),
            (0, &[0xFD, b'7', b'z', b'X', b'Z', 0x01]),
            (1, b"CrAU"),
            (256, b"ustar"),
            (258, b"ustar"),
            (4095, b"gDla"),
            (4097, b"gDla"),
        ] {
            assert_eq!(id_of(&head_with(at, magic)), "none", "{magic:?} at {at}");
        }
        assert!(sniff(&[]).is_none());
        assert!(sniff(&vec![0u8; SNIFF_LEN]).is_none());
    }

    #[test]
    fn cpio_legacy_lz4_and_amlogic_magics() {
        assert_eq!(id_of(&head_with(0, b"070701")), "cpio");
        assert_eq!(id_of(&head_with(0, b"070702")), "cpio");
        assert_eq!(
            id_of(&head_with(0, &[0x02, 0x21, 0x4C, 0x18])),
            "lz4-legacy"
        );
        assert_eq!(id_of(&head_with(0, b"@AML")), "aml-container");
        for (m, what) in [
            (&b"070703"[..], "cpio"),
            (&[0x02, 0x21, 0x4C, 0x19][..], "lz4-legacy"),
            (&b"@AMX"[..], "amlogic"),
            (&b"07070"[..], "short cpio"),
        ] {
            assert_eq!(id_of(&head_with(0, m)), "none", "{what} near miss");
        }
        assert_eq!(id_of(&head_with(1, b"@AML")), "none", "only at the start");
    }

    #[test]
    fn filesystems_keep_their_specific_ids() {
        assert_eq!(id_of(&ext(0x38, 0x242, 0x7b)), "ext4");
        assert_eq!(id_of(&ext(0, 0, 0)), "ext2");
        assert_eq!(id_of(&ext(COMPAT_HAS_JOURNAL, 0x2, 0x3)), "ext3");
        let mut e = vec![0u8; SNIFF_LEN];
        e[1024..1028].copy_from_slice(&EROFS_MAGIC.to_le_bytes());
        assert_eq!(id_of(&e), "erofs");
    }

    #[test]
    fn no_input_length_makes_sniff_panic() {
        let mut full = head_with(4096, b"gDla");
        full[257..262].copy_from_slice(b"ustar");
        for n in 0..=SNIFF_LEN + 4 {
            let _ = sniff(&full[..n.min(full.len())]);
        }
        assert_eq!(
            id_of(&full[..4099]),
            "tar",
            "lp needs all 4100 bytes; tar needs 262"
        );
        assert_eq!(id_of(&full[..261]), "none");
        assert_eq!(id_of(&head_with(4096, b"gDla")[..4099]), "none");
        assert_eq!(id_of(&head_with(4096, b"gDla")[..SNIFF_LEN]), "lp-super");
    }

    fn scratch(tag: &str) -> std::path::PathBuf {
        let dir =
            std::env::temp_dir().join(format!("android-doctor-id-{}-{tag}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn write_zip(path: &Path, names: &[&str]) {
        let mut w = zip::ZipWriter::new(File::create(path).unwrap());
        for n in names {
            w.start_file(*n, zip::write::SimpleFileOptions::default())
                .unwrap();
            std::io::Write::write_all(&mut w, b"x").unwrap();
        }
        w.finish().unwrap();
    }

    #[test]
    fn zips_are_told_apart_by_their_contents() {
        let dir = scratch("zips");
        let cases: &[(&str, &[&str], &str)] = &[
            (
                "block.zip",
                &[
                    "META-INF/com/android/metadata",
                    "system.transfer.list",
                    "system.new.dat.br",
                ],
                "block-ota-zip",
            ),
            (
                "ab.zip",
                &["payload.bin", "payload_properties.txt"],
                "ab-ota-zip",
            ),
            (
                "both.zip",
                &["payload.bin", "system.transfer.list"],
                "ab-ota-zip",
            ),
            ("plain.zip", &["readme.txt", "docs/x.pdf"], "zip"),
            ("nested.zip", &["sub/system.transfer.list"], "zip"),
            (
                "lookalike.zip",
                &["system.transfer.list.bak", "my_payload.bin"],
                "zip",
            ),
        ];
        for (file, names, id) in cases {
            write_zip(&dir.join(file), names);
            assert_eq!(identify_path(&dir.join(file)).unwrap().id, *id, "{file}");
        }
        // an empty zip has only the end-of-central-directory record
        write_zip(&dir.join("empty.zip"), &[]);
        assert_eq!(identify_path(&dir.join("empty.zip")).unwrap().id, "zip");
    }

    #[test]
    fn a_damaged_zip_is_still_a_zip_with_a_note() {
        let dir = scratch("badzip");
        std::fs::write(dir.join("bad.zip"), b"PK\x03\x04 and then garbage").unwrap();
        let i = identify_path(&dir.join("bad.zip")).unwrap();
        assert_eq!(i.id, "zip");
        assert!(i.description.contains("unreadable"), "{}", i.description);
    }

    #[test]
    fn directories_and_files_on_disk() {
        let dir = scratch("paths");
        let ota = dir.join("ota");
        std::fs::create_dir(&ota).unwrap();
        assert_eq!(identify_path(&ota).unwrap().id, "directory");
        std::fs::write(ota.join("system.transfer.list"), b"4\n").unwrap();
        assert_eq!(identify_path(&ota).unwrap().id, "block-ota-dir");
        std::fs::write(dir.join("boot.img"), head_with(0, b"ANDROID!")).unwrap();
        assert_eq!(
            identify_path(&dir.join("boot.img")).unwrap().id,
            "boot-image"
        );
        std::fs::write(dir.join("random.bin"), b"hello").unwrap();
        assert_eq!(
            identify_path(&dir.join("random.bin")).unwrap().id,
            "unknown"
        );
        std::fs::write(dir.join("empty"), b"").unwrap();
        assert_eq!(identify_path(&dir.join("empty")).unwrap().id, "unknown");
        let e = identify_path(&dir.join("missing")).unwrap_err();
        assert!(e.to_string().contains("opening"), "{e}");
    }

    #[cfg(unix)]
    #[test]
    fn a_fifo_is_refused_at_once_instead_of_blocking() {
        let dir = scratch("fifo");
        let fifo = dir.join("pipe");
        let made = std::process::Command::new("mkfifo")
            .arg(&fifo)
            .status()
            .unwrap();
        assert!(made.success());
        let (tx, rx) = std::sync::mpsc::channel();
        let path = fifo.clone();
        std::thread::spawn(move || {
            let _ = tx.send(identify_path(&path).map_err(|e| e.to_string()));
        });
        let res = rx
            .recv_timeout(std::time::Duration::from_secs(20))
            .expect("identify blocked on a FIFO");
        assert!(res.unwrap_err().contains("FIFO or socket"));
    }

    #[cfg(unix)]
    #[test]
    fn a_unix_socket_is_refused_with_the_same_clear_message() {
        let dir = scratch("sock");
        let sock = dir.join("s");
        let _listener = std::os::unix::net::UnixListener::bind(&sock).unwrap();
        let e = identify_path(&sock).unwrap_err();
        assert!(e.to_string().contains("FIFO or socket"), "{e}");
    }

    #[cfg(unix)]
    #[test]
    fn character_devices_and_missing_paths_still_behave() {
        // /dev/null reads as empty: unknown, not an error and not a hang
        assert_eq!(identify_path(Path::new("/dev/null")).unwrap().id, "unknown");
        let e = identify_path(Path::new("/definitely/not/here")).unwrap_err();
        assert!(e.to_string().contains("opening"), "{e}");
    }

    #[test]
    fn the_name_never_matters_only_the_bytes() {
        let dir = scratch("names");
        std::fs::write(dir.join("system.img"), head_with(0, &[0x1F, 0x8B, 0x08])).unwrap();
        std::fs::write(dir.join("firmware.zip"), b"not a zip at all").unwrap();
        assert_eq!(identify_path(&dir.join("system.img")).unwrap().id, "gzip");
        assert_eq!(
            identify_path(&dir.join("firmware.zip")).unwrap().id,
            "unknown"
        );
    }
}
