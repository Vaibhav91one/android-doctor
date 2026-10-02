//! Recognise filesystems by their on-disk magic (more formats arrive with the identify command).
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
}
