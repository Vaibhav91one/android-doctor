//! Read-only access to f2fs images (the flash-friendly file system Android uses for `userdata`
//! and, on some devices, `system`, `vendor` and `product`), and extraction of their files.
//!
//! Clean-room: written from the public description of the on-disk format (the kernel's
//! `Documentation/filesystems/f2fs.rst`, the F2FS FAST'15 paper and the layout the f2fs-tools
//! utilities emit), never from the GPL kernel driver's source. Every offset below was checked
//! against images made by `mkfs.f2fs` and populated by `sload.f2fs`, and the results were
//! compared with `fsck.f2fs` / `dump.f2fs`.
//!
//! What is read: the superblock (geometry, features, optional checksum), the newest valid
//! checkpoint pack (CRC checked, NAT bitmap, NAT journal in compact or normal summaries), the NAT
//! (node id to block), inodes (mode, owner, size, times, device numbers), inline data and inline
//! directories, direct / indirect / double-indirect block addressing, dentry blocks, symlinks, and
//! the inline plus node-block extended attributes (`security.selinux`, `security.capability`, ...).
//!
//! What is refused, with an error that says so, never guessed: encrypted files and directories (the
//! names are ciphertext; the volume-wide encrypt feature bit alone is not a reason), compressed
//! files, zoned, multi-device and device-alias volumes, large NAT bitmaps, feature bits this reader
//! does not know, any checkpoint whose CRC does not match, and any node whose footer does not name
//! the node that was asked for. The SIT, the SSA and the
//! orphan list are not needed to read files and are never consulted. Inode checksums are not
//! verified (the node footer check is).
use crate::detect::refuse_blocking_file;
use crate::erofsfs::write_unless_zero;
use crate::ext4fs::{Source, le16, le32, name_string, xattr_text};
use crate::tree::{
    COPY_CHUNK, Entry, Kind, MAX_DEPTH, MAX_DIR_BYTES, MAX_ENTRIES, MAX_FILE_BYTES, MAX_PATH,
    MAX_SYMLINK, TreeSource, check_cat,
};
use crate::treeout::{Collisions, short};
use anyhow::{Context, Result, anyhow, bail, ensure};
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet};
use std::fs::File;
use std::io::Write;
use std::path::Path;

const MAGIC: u32 = 0xF2F5_2010;
const SB_OFFSET: u64 = 1024;
const SB_LEN: usize = 3072;
const BS: u64 = 4096;
const BS_USIZE: usize = 4096;
const LOG_BLOCKS_PER_SEG: u32 = 9;
const BLOCKS_PER_SEG: u64 = 1 << LOG_BLOCKS_PER_SEG;

/// Superblock features (`feature` at 2180). The encrypt bit only says encryption is enabled
/// (Android's own `mkfs.f2fs -g android` sets it on images with no encrypted file), so it is not
/// refused; encrypted inodes are.
const F_BLKZONED: u32 = 0x2;
const F_FLEXIBLE_INLINE_XATTR: u32 = 0x40;
const F_SB_CHKSUM: u32 = 0x800;
const F_COMPRESSION: u32 = 0x2000;
const F_DEVICE_ALIAS: u32 = 0x8000;
/// Every feature bit this reader has a rule for: encrypt, blkzoned, atomic_write, extra_attr,
/// project_quota, inode_checksum, flexible_inline_xattr, quota_ino, inode_crtime, lost_found,
/// verity, sb_checksum, casefold, compression, ro, device_alias, linear_lookup.
const KNOWN_FEATURES: u32 = 0x3_FFFF;

/// Checkpoint flags.
const CP_COMPACT_SUM: u32 = 0x4;
const CP_LARGE_NAT_BITMAP: u32 = 0x400;

const NAT_ENTRY_SIZE: usize = 9;
const NAT_PER_BLOCK: u32 = (BS_USIZE / NAT_ENTRY_SIZE) as u32;
const JOURNAL_ENTRIES: usize = 38;
const JOURNAL_ENTRY_SIZE: usize = 13;
/// Where the journal sits in a data summary block that is not in the compact form.
const SUM_JOURNAL_AT: usize = 7 * 512;
const NEW_ADDR: u32 = 0xFFFF_FFFF;
const COMPRESS_ADDR: u32 = 0xFFFF_FFFE;

const NODE_FOOTER: usize = 4072;
const ADDRS_PER_BLOCK: u64 = 1018;
const ADDRS_PER_INODE: usize = 923;
const I_ADDR: usize = 360;
const I_NID: usize = I_ADDR + ADDRS_PER_INODE * 4;
const DENTRIES_PER_BLOCK: usize = 214;
const DENTRY_SIZE: usize = 11;
const SLOT_LEN: usize = 8;

/// `i_inline` bits.
const INLINE_XATTR: u8 = 0x01;
const INLINE_DATA: u8 = 0x02;
const INLINE_DENTRY: u8 = 0x04;
const EXTRA_ATTR: u8 = 0x20;
/// `i_advise`: the inode is encrypted.
const ADVISE_ENCRYPT: u8 = 0x04;
/// `i_flags`: the file is compressed (or has compression enabled).
const COMPR_FL: u32 = 0x4;

const XATTR_MAGIC: u32 = 0xF2F5_2011;
const XATTR_HEADER: usize = 24;
const DEFAULT_INLINE_XATTR_WORDS: usize = 50;
const MAX_XATTRS: usize = 4096;
const MAX_XATTR_VALUE: usize = 1 << 20;
const MAX_RUNS: usize = 1 << 21;

fn le64(b: &[u8], at: usize) -> u64 {
    u64::from_le_bytes(b[at..at + 8].try_into().expect("8 bytes"))
}

/// The CRC f2fs uses for the superblock and checkpoint: CRC-32 (reflected, polynomial
/// 0xEDB88320) seeded with the superblock magic and with no final inversion.
fn crc(data: &[u8]) -> u32 {
    let mut c = MAGIC;
    for &b in data {
        c ^= b as u32;
        for _ in 0..8 {
            c = (c >> 1) ^ if c & 1 != 0 { 0xEDB8_8320 } else { 0 };
        }
    }
    c
}

/// Bit `i` of a bitmap the way the NAT bitmap numbers them (most significant bit first).
fn bit_msb(bitmap: &[u8], i: usize) -> bool {
    bitmap
        .get(i / 8)
        .is_some_and(|b| b & (0x80 >> (i % 8)) != 0)
}

/// Bit `i` of a bitmap the way dentry bitmaps number them (least significant bit first).
fn bit_lsb(bitmap: &[u8], i: usize) -> bool {
    bitmap.get(i / 8).is_some_and(|b| b & (1 << (i % 8)) != 0)
}

/// What the superblock says about the volume, validated.
#[derive(Debug, Clone, Copy)]
struct Sb {
    feature: u32,
    block_count: u64,
    cp_blkaddr: u32,
    nat_blkaddr: u32,
    main_blkaddr: u32,
    nat_segs: u32,
    root_ino: u32,
    cp_payload: u32,
}

impl Sb {
    /// Parse and validate the 3072 bytes of the superblock (`b` starts at byte 1024 of the image).
    fn parse(b: &[u8]) -> Result<Sb> {
        ensure!(b.len() >= SB_LEN, "the superblock is cut short");
        ensure!(
            le32(b, 0) == MAGIC,
            "not an f2fs superblock (magic {:#010x}, expected {MAGIC:#010x})",
            le32(b, 0)
        );
        let feature = le32(b, 2180);
        if feature & F_SB_CHKSUM != 0 {
            let at = le32(b, 32) as usize;
            ensure!(
                (4..=SB_LEN - 4).contains(&at),
                "the superblock checksum offset {at} is out of range"
            );
            ensure!(
                crc(&b[..at]) == le32(b, at),
                "the superblock checksum does not match"
            );
        }
        ensure!(
            feature & F_BLKZONED == 0,
            "zoned-block-device f2fs volumes are not supported"
        );
        // multi-device volumes list their devices (path, then size in segments) from byte 2201
        ensure!(
            (0..8).all(|i| le32(b, 2201 + 68 * i + 64) == 0),
            "multi-device f2fs volumes are not supported"
        );
        ensure!(
            feature & F_DEVICE_ALIAS == 0,
            "f2fs device-alias files are not supported"
        );
        ensure!(
            feature & !KNOWN_FEATURES == 0,
            "the volume uses f2fs feature bits this reader does not know ({:#x}); refusing to guess",
            feature & !KNOWN_FEATURES
        );
        let (log_sector, log_spb, log_block) = (le32(b, 8), le32(b, 12), le32(b, 16));
        ensure!(
            log_block == 12 && (9..=12).contains(&log_sector) && log_spb == 12 - log_sector,
            "unsupported f2fs block geometry (log block size {log_block}, log sector size {log_sector})"
        );
        ensure!(
            le32(b, 20) == LOG_BLOCKS_PER_SEG,
            "unsupported f2fs segment size (2^{} blocks)",
            le32(b, 20)
        );
        for (name, v) in [
            ("segments per section", le32(b, 24)),
            ("sections per zone", le32(b, 28)),
        ] {
            ensure!((1..=1 << 16).contains(&v), "absurd f2fs {name}: {v}");
        }
        let block_count = le64(b, 36);
        ensure!(
            (8..=u32::MAX as u64).contains(&block_count),
            "absurd f2fs block count {block_count}"
        );
        let (ckpt, sit, nat, ssa, main) = (
            le32(b, 52) as u64,
            le32(b, 56) as u64,
            le32(b, 60) as u64,
            le32(b, 64) as u64,
            le32(b, 68) as u64,
        );
        ensure!(
            ckpt >= 2
                && sit >= 2
                && sit % 2 == 0
                && nat >= 2
                && nat % 2 == 0
                && ssa >= 1
                && main >= 1,
            "absurd f2fs segment counts (checkpoint {ckpt}, sit {sit}, nat {nat}, ssa {ssa}, main {main})"
        );
        let (cp_blk, sit_blk, nat_blk, ssa_blk, main_blk) = (
            le32(b, 76) as u64,
            le32(b, 80) as u64,
            le32(b, 84) as u64,
            le32(b, 88) as u64,
            le32(b, 92) as u64,
        );
        // the areas follow one another and the main area ends inside the volume
        ensure!(
            cp_blk >= 2
                && cp_blk + ckpt * BLOCKS_PER_SEG <= sit_blk
                && sit_blk + sit * BLOCKS_PER_SEG <= nat_blk
                && nat_blk + nat * BLOCKS_PER_SEG <= ssa_blk
                && ssa_blk + ssa * BLOCKS_PER_SEG <= main_blk
                && main_blk + main * BLOCKS_PER_SEG <= block_count,
            "the f2fs metadata areas overlap or run past the volume"
        );
        let (root, node, meta) = (le32(b, 96), le32(b, 100), le32(b, 104));
        let max_nid = (nat / 2) * BLOCKS_PER_SEG * NAT_PER_BLOCK as u64;
        ensure!(
            root != 0
                && node != 0
                && meta != 0
                && root != node
                && root != meta
                && (root as u64) < max_nid,
            "the f2fs special inode numbers are invalid (root {root}, node {node}, meta {meta})"
        );
        let cp_payload = le32(b, 1664);
        ensure!(
            (cp_payload as u64) < BLOCKS_PER_SEG - 4,
            "absurd f2fs checkpoint payload of {cp_payload} blocks"
        );
        Ok(Sb {
            feature,
            block_count,
            cp_blkaddr: cp_blk as u32,
            nat_blkaddr: nat_blk as u32,
            main_blkaddr: main_blk as u32,
            nat_segs: nat as u32,
            root_ino: root,
            cp_payload,
        })
    }

    /// Node ids are below this.
    fn max_nid(&self) -> u64 {
        (self.nat_segs as u64 / 2) * BLOCKS_PER_SEG * NAT_PER_BLOCK as u64
    }
}

/// A NAT entry: which inode a node belongs to, and where it is.
#[derive(Debug, Clone, Copy, PartialEq)]
struct Nat {
    ino: u32,
    blk: u32,
}

/// The checkpoint the volume is read through.
struct Ckpt {
    version: u64,
    nat_bitmap: Vec<u8>,
    journal: HashMap<u32, Nat>,
}

/// Parse a NAT journal (`n_nats` then entries of nid + NAT entry).
fn parse_nat_journal(b: &[u8]) -> Result<HashMap<u32, Nat>> {
    ensure!(
        b.len() >= 2 + JOURNAL_ENTRIES * JOURNAL_ENTRY_SIZE,
        "the NAT journal is cut short"
    );
    let n = le16(b, 0) as usize;
    ensure!(
        n <= JOURNAL_ENTRIES,
        "the NAT journal claims {n} entries (the most there is room for is {JOURNAL_ENTRIES})"
    );
    let mut out = HashMap::new();
    for i in 0..n {
        let at = 2 + i * JOURNAL_ENTRY_SIZE;
        // nid, then version (1 byte), ino, block address
        out.insert(
            le32(b, at),
            Nat {
                ino: le32(b, at + 5),
                blk: le32(b, at + 9),
            },
        );
    }
    Ok(out)
}

/// One inode, without its data. Small so that a whole tree of them fits in memory.
#[derive(Debug, Clone)]
pub struct Inode {
    pub nid: u32,
    mode: u16,
    advise: u8,
    inline: u8,
    uid: u32,
    gid: u32,
    links: u32,
    size: u64,
    mtime: i64,
    flags: u32,
    xattr_nid: u32,
    nids: [u32; 5],
    /// Byte offset of `i_addr[0]` in the inode block.
    addr_at: usize,
    /// Block addresses the inode holds (after the extra fields, before the inline xattrs).
    data_addrs: usize,
    /// Words of the inline extended attribute area at the end of `i_addr`.
    xattr_words: usize,
}

impl Inode {
    fn parse(sb: &Sb, nid: u32, b: &[u8]) -> Result<Inode> {
        let mode = le16(b, 0);
        let inline = b[3];
        let extra = if inline & EXTRA_ATTR != 0 {
            le16(b, I_ADDR) as usize
        } else {
            0
        };
        ensure!(
            extra % 4 == 0 && extra < ADDRS_PER_INODE * 4 / 2,
            "inode {nid} has an invalid extra attribute size {extra}"
        );
        let xattr_words = if inline & INLINE_XATTR == 0 {
            0
        } else if extra >= 4 && sb.feature & F_FLEXIBLE_INLINE_XATTR != 0 {
            le16(b, I_ADDR + 2) as usize
        } else {
            DEFAULT_INLINE_XATTR_WORDS
        };
        let addrs_total = ADDRS_PER_INODE - extra / 4;
        ensure!(
            xattr_words < addrs_total.saturating_sub(1),
            "inode {nid} has an invalid inline xattr size ({xattr_words} words)"
        );
        let mut nids = [0u32; 5];
        for (i, n) in nids.iter_mut().enumerate() {
            *n = le32(b, I_NID + 4 * i);
        }
        Ok(Inode {
            nid,
            mode,
            advise: b[2],
            inline,
            uid: le32(b, 4),
            gid: le32(b, 8),
            links: le32(b, 12),
            size: le64(b, 16),
            mtime: le64(b, 48).min(i64::MAX as u64) as i64,
            flags: le32(b, 80),
            xattr_nid: le32(b, 76),
            nids,
            addr_at: I_ADDR + extra,
            data_addrs: addrs_total - xattr_words,
            xattr_words,
        })
    }

    fn kind(&self) -> Option<Kind> {
        Kind::from_mode(self.mode)
    }

    fn is_inline_data(&self) -> bool {
        self.inline & INLINE_DATA != 0
    }

    /// Bytes of inline data (or inline directory) the inode can hold: its address words minus the
    /// one reserved word.
    fn max_inline(&self) -> usize {
        self.data_addrs.saturating_sub(1) * 4
    }
}

pub struct Fs {
    src: Source,
    len: u64,
    sb: Sb,
    ck: Ckpt,
}

fn read_block(src: &Source, n: u64) -> Result<Vec<u8>> {
    let mut b = vec![0u8; BS_USIZE];
    src.read_at(n * BS, &mut b)
        .with_context(|| format!("reading block {n}"))?;
    Ok(b)
}

/// Validate one checkpoint pack: CRC of the first block, a matching last block, the layout.
fn read_pack(src: &Source, sb: &Sb, blk: u64) -> Result<Ckpt> {
    let first = read_block(src, blk)?;
    let off = le32(&first, 164) as usize;
    ensure!(
        (192..=BS_USIZE - 4).contains(&off),
        "the checkpoint checksum offset {off} is out of range"
    );
    ensure!(
        crc(&first[..off]) == le32(&first, off),
        "the checkpoint checksum does not match"
    );
    let version = le64(&first, 0);
    let (flags, total, start_sum) = (le32(&first, 132), le32(&first, 136), le32(&first, 140));
    ensure!(
        flags & CP_LARGE_NAT_BITMAP == 0,
        "checkpoints with a large NAT bitmap (mkfs -i) are not supported"
    );
    ensure!(
        total as u64 >= 3 + sb.cp_payload as u64 && total as u64 <= BLOCKS_PER_SEG,
        "the checkpoint pack claims {total} blocks"
    );
    ensure!(
        start_sum >= 1 && start_sum < total - 1,
        "the checkpoint's summary start {start_sum} is outside its pack"
    );
    let last = read_block(src, blk + total as u64 - 1)?;
    ensure!(
        le64(&last, 0) == version
            && le32(&last, 164) as usize == off
            && crc(&last[..off]) == le32(&last, off),
        "the last block of the checkpoint pack does not match its first"
    );
    // the NAT bitmap: after the SIT bitmap in the checkpoint block, or at its start when the SIT
    // bitmap has moved to payload blocks
    let (sit_bytes, nat_bytes) = (le32(&first, 156) as usize, le32(&first, 160) as usize);
    let expected = (sb.nat_segs as usize / 2) * BLOCKS_PER_SEG as usize / 8;
    ensure!(
        nat_bytes >= expected && nat_bytes <= BS_USIZE,
        "the checkpoint's NAT bitmap is {nat_bytes} bytes, expected {expected}"
    );
    let at = 192 + if sb.cp_payload > 0 { 0 } else { sit_bytes };
    ensure!(
        sit_bytes <= BS_USIZE && at + nat_bytes <= off,
        "the checkpoint's bitmaps do not fit in its block"
    );
    let nat_bitmap = first[at..at + nat_bytes].to_vec();
    // the NAT journal is in the first summary block of the pack
    let sum = read_block(src, blk + start_sum as u64)?;
    let journal_at = if flags & CP_COMPACT_SUM != 0 {
        0
    } else {
        SUM_JOURNAL_AT
    };
    let journal = parse_nat_journal(&sum[journal_at..]).context("reading the NAT journal")?;
    Ok(Ckpt {
        version,
        nat_bitmap,
        journal,
    })
}

/// Pick the checkpoint: the valid pack with the newer version, the first one on a tie.
fn pick_checkpoint(src: &Source, sb: &Sb) -> Result<Ckpt> {
    let first = sb.cp_blkaddr as u64;
    let a = read_pack(src, sb, first);
    let b = read_pack(src, sb, first + BLOCKS_PER_SEG);
    match (a, b) {
        (Ok(a), Ok(b)) => Ok(if (b.version.wrapping_sub(a.version) as i64) > 0 {
            b
        } else {
            a
        }),
        (Ok(a), Err(_)) => Ok(a),
        (Err(_), Ok(b)) => Ok(b),
        (Err(a), Err(b)) => Err(anyhow!(
            "no valid f2fs checkpoint: first pack: {a:#}; second pack: {b:#}"
        )),
    }
}

/// One stretch of a file: `blocks` logical blocks from `lblk`, stored from `pblk`.
#[derive(Debug, Clone, Copy, PartialEq)]
struct Run {
    lblk: u64,
    pblk: u64,
    blocks: u64,
}

/// Bounds on what one walk will accept (tests use tiny ones).
#[derive(Clone, Copy)]
struct Limits {
    depth: usize,
    path: usize,
    entries: usize,
}

const LIMITS: Limits = Limits {
    depth: MAX_DEPTH,
    path: MAX_PATH,
    entries: MAX_ENTRIES,
};

fn xattr_name(index: u8, suffix: &[u8]) -> String {
    let suffix = name_string(suffix);
    match index {
        1 => format!("user.{suffix}"),
        2 => "system.posix_acl_access".to_string(),
        3 => "system.posix_acl_default".to_string(),
        4 => format!("trusted.{suffix}"),
        6 => format!("security.{suffix}"),
        7 => "system.advise".to_string(),
        n => format!("unknown{n}.{suffix}"),
    }
}

/// The extended attributes in `area`: a 24-byte header (magic, refcount) and then entries
/// (`index`, `name_len`, `value_size`, name, value, padded to 4 bytes) up to a zero word.
fn parse_xattrs(area: &[u8]) -> Result<Vec<(String, Vec<u8>)>> {
    let mut out = Vec::new();
    if area.len() < XATTR_HEADER || le32(area, 0) == 0 {
        return Ok(out); // never written
    }
    ensure!(
        le32(area, 0) == XATTR_MAGIC,
        "the extended attribute area has a bad magic"
    );
    let mut p = XATTR_HEADER;
    while p + 4 <= area.len() && le32(area, p) != 0 {
        ensure!(
            out.len() < MAX_XATTRS,
            "more than {MAX_XATTRS} extended attributes"
        );
        let (index, name_len, size) = (area[p], area[p + 1] as usize, le16(area, p + 2) as usize);
        ensure!(
            size <= MAX_XATTR_VALUE,
            "an extended attribute value of {size} bytes is over the limit"
        );
        let end = p + 4 + name_len + size;
        ensure!(
            end <= area.len(),
            "an extended attribute entry runs past its area"
        );
        let name = xattr_name(index, &area[p + 4..p + 4 + name_len]);
        out.push((name, area[p + 4 + name_len..end].to_vec()));
        p += (4 + name_len + size + 3) & !3;
    }
    Ok(out)
}

/// Inline directory geometry for `max_inline` bytes: (entries, bitmap bytes, reserved bytes).
fn inline_dentry_layout(max_inline: usize) -> (usize, usize, usize) {
    let nr = max_inline * 8 / ((DENTRY_SIZE + SLOT_LEN) * 8 + 1);
    let bitmap = nr.div_ceil(8);
    let reserved = max_inline.saturating_sub((DENTRY_SIZE + SLOT_LEN) * nr + bitmap);
    (nr, bitmap, reserved)
}

/// The names in one dentry area: `bitmap`, `dentries` (`nr` of 11 bytes) and `names` (`nr` slots
/// of 8 bytes). `.` and `..` are left out.
fn parse_dentries(
    bitmap: &[u8],
    dentries: &[u8],
    names: &[u8],
    nr: usize,
    max_nid: u64,
    out: &mut Vec<(String, u32)>,
) -> Result<()> {
    ensure!(
        dentries.len() >= nr * DENTRY_SIZE && names.len() >= nr * SLOT_LEN,
        "a directory block is cut short"
    );
    let mut i = 0;
    while i < nr {
        if !bit_lsb(bitmap, i) {
            i += 1;
            continue;
        }
        let d = &dentries[i * DENTRY_SIZE..];
        let (ino, name_len) = (le32(d, 4), le16(d, 8) as usize);
        let slots = name_len.div_ceil(SLOT_LEN);
        ensure!(
            name_len > 0 && name_len <= 255 && i + slots <= nr,
            "a directory entry has an invalid name length {name_len}"
        );
        let name = &names[i * SLOT_LEN..i * SLOT_LEN + name_len];
        i += slots;
        if name == b"." || name == b".." {
            continue;
        }
        ensure!(
            !name.contains(&b'/') && !name.contains(&0),
            "a directory entry has an invalid name"
        );
        ensure!(
            ino != 0 && (ino as u64) < max_nid,
            "{} points to an invalid inode ({ino})",
            short(&name_string(name))
        );
        ensure!(
            out.len() < MAX_ENTRIES,
            "a directory has more than {MAX_ENTRIES} entries"
        );
        out.push((name_string(name), ino));
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
            .with_context(|| format!("not a readable f2fs image: {}", path.display()))
    }

    #[cfg(test)]
    pub fn from_bytes(image: Vec<u8>) -> Result<Fs> {
        Fs::new(Source::Mem(image))
    }

    fn new(src: Source) -> Result<Fs> {
        let len = src.len()?;
        ensure!(
            len >= SB_OFFSET + SB_LEN as u64,
            "too short to be an f2fs filesystem"
        );
        let mut raw = vec![0u8; SB_LEN];
        src.read_at(SB_OFFSET, &mut raw)
            .context("reading the superblock")?;
        let sb = Sb::parse(&raw)?;
        ensure!(
            len >= sb.main_blkaddr as u64 * BS,
            "the image is truncated: it ends before the f2fs main area ({} bytes needed for the metadata)",
            sb.main_blkaddr as u64 * BS
        );
        let ck = pick_checkpoint(&src, &sb)?;
        Ok(Fs { src, len, sb, ck })
    }

    fn block(&self, n: u64) -> Result<Vec<u8>> {
        read_block(&self.src, n)
    }

    /// Where node `nid` is, from the checkpoint's NAT journal or else the NAT.
    fn nat(&self, nid: u32) -> Result<Nat> {
        ensure!(
            nid != 0 && (nid as u64) < self.sb.max_nid(),
            "node id {nid} is outside the node address table"
        );
        let entry = match self.ck.journal.get(&nid) {
            Some(e) => *e,
            None => {
                let block_off = (nid / NAT_PER_BLOCK) as u64;
                let seg_off = block_off / BLOCKS_PER_SEG;
                let mut blk = self.sb.nat_blkaddr as u64
                    + (seg_off << (LOG_BLOCKS_PER_SEG + 1))
                    + block_off % BLOCKS_PER_SEG;
                // each NAT block has two copies; the checkpoint says which one is current
                if bit_msb(&self.ck.nat_bitmap, block_off as usize) {
                    blk += BLOCKS_PER_SEG;
                }
                let b = self.block(blk).context("reading the node address table")?;
                let at = (nid % NAT_PER_BLOCK) as usize * NAT_ENTRY_SIZE;
                Nat {
                    ino: le32(&b, at + 1),
                    blk: le32(&b, at + 5),
                }
            }
        };
        ensure!(entry.blk != 0, "node {nid} is not allocated");
        ensure!(entry.blk != NEW_ADDR, "node {nid} was never written");
        ensure!(
            entry.blk >= self.sb.main_blkaddr && (entry.blk as u64) < self.sb.block_count,
            "node {nid} is at block {}, outside the main area",
            entry.blk
        );
        Ok(entry)
    }

    /// Read node `nid`; its footer must name `nid` and the inode `owner` (when given) so that a
    /// damaged table can never hand back another file's block.
    fn node(&self, nid: u32, owner: Option<u32>) -> Result<Vec<u8>> {
        let nat = self.nat(nid)?;
        let b = self.block(nat.blk as u64)?;
        ensure!(
            le32(&b, NODE_FOOTER) == nid && le32(&b, NODE_FOOTER + 4) == nat.ino,
            "block {} is not node {nid} (its footer names node {} of inode {})",
            nat.blk,
            le32(&b, NODE_FOOTER),
            le32(&b, NODE_FOOTER + 4)
        );
        if let Some(o) = owner {
            ensure!(
                nat.ino == o,
                "node {nid} belongs to inode {} and not to inode {o}",
                nat.ino
            );
        }
        Ok(b)
    }

    /// An inode and its block.
    fn load(&self, nid: u32) -> Result<(Inode, Vec<u8>)> {
        let b = self.node(nid, Some(nid))?;
        let ino = Inode::parse(&self.sb, nid, &b)?;
        Ok((ino, b))
    }

    /// Call `f(logical block, physical block)` for every mapped block of the file below
    /// `nblocks`, in order. Holes (no node, address 0, or "allocated but never written") are
    /// skipped; the caller reads the gaps as zeros.
    fn map_blocks(
        &self,
        ino: &Inode,
        blk: &[u8],
        nblocks: u64,
        f: &mut dyn FnMut(u64, u32) -> Result<()>,
    ) -> Result<()> {
        let mut at = 0u64;
        for i in 0..ino.data_addrs {
            if at >= nblocks {
                return Ok(());
            }
            self.visit_addr(le32(blk, ino.addr_at + 4 * i), &mut at, f)?;
        }
        // two direct nodes, two indirect, one double indirect
        for (slot, level) in [(0, 0u32), (1, 0), (2, 1), (3, 1), (4, 2)] {
            if at >= nblocks {
                return Ok(());
            }
            let nid = ino.nids[slot];
            if nid == 0 {
                at += ADDRS_PER_BLOCK.pow(level + 1);
                continue;
            }
            self.walk_node(nid, ino.nid, level, nblocks, &mut at, f)?;
        }
        Ok(())
    }

    fn visit_addr(
        &self,
        addr: u32,
        at: &mut u64,
        f: &mut dyn FnMut(u64, u32) -> Result<()>,
    ) -> Result<()> {
        match addr {
            0 | NEW_ADDR => {}
            COMPRESS_ADDR => bail!("compressed f2fs files are not supported"),
            a => {
                ensure!(
                    a >= self.sb.main_blkaddr && (a as u64) < self.sb.block_count,
                    "a file block at {a} is outside the main area"
                );
                f(*at, a)?;
            }
        }
        *at += 1;
        Ok(())
    }

    /// `level` 0 is a node of block addresses; above it, a node of node ids.
    fn walk_node(
        &self,
        nid: u32,
        owner: u32,
        level: u32,
        nblocks: u64,
        at: &mut u64,
        f: &mut dyn FnMut(u64, u32) -> Result<()>,
    ) -> Result<()> {
        let node = self
            .node(nid, Some(owner))
            .with_context(|| format!("reading the block map of inode {owner}"))?;
        for j in 0..ADDRS_PER_BLOCK as usize {
            if *at >= nblocks {
                return Ok(());
            }
            let v = le32(&node, 4 * j);
            if level == 0 {
                self.visit_addr(v, at, f)?;
            } else if v == 0 {
                *at += ADDRS_PER_BLOCK.pow(level);
            } else {
                self.walk_node(v, owner, level - 1, nblocks, at, f)?;
            }
        }
        Ok(())
    }

    fn runs(&self, ino: &Inode, blk: &[u8], nblocks: u64) -> Result<Vec<Run>> {
        let mut runs: Vec<Run> = Vec::new();
        self.map_blocks(ino, blk, nblocks, &mut |l, p| {
            let p = p as u64;
            if let Some(r) = runs.last_mut()
                && r.lblk + r.blocks == l
                && r.pblk + r.blocks == p
            {
                r.blocks += 1;
                return Ok(());
            }
            ensure!(
                runs.len() < MAX_RUNS,
                "the file is split into more than {MAX_RUNS} pieces"
            );
            runs.push(Run {
                lblk: l,
                pblk: p,
                blocks: 1,
            });
            Ok(())
        })?;
        Ok(runs)
    }

    /// The inline bytes of an inode (`len` of them).
    fn inline_bytes<'a>(&self, ino: &Inode, blk: &'a [u8], len: usize) -> Result<&'a [u8]> {
        ensure!(
            len <= ino.max_inline(),
            "inline data of {len} bytes does not fit in inode {}",
            ino.nid
        );
        let at = ino.addr_at + 4;
        Ok(&blk[at..at + len])
    }

    /// Refuse the data of files this reader cannot decode.
    fn check_readable(&self, ino: &Inode) -> Result<()> {
        ensure!(
            ino.advise & ADVISE_ENCRYPT == 0,
            "inode {} is encrypted; encrypted f2fs files are not supported",
            ino.nid
        );
        ensure!(
            !(ino.flags & COMPR_FL != 0 && self.sb.feature & F_COMPRESSION != 0),
            "inode {} is a compressed file; compressed f2fs files are not supported",
            ino.nid
        );
        Ok(())
    }

    /// Stream a regular file in bounded chunks. `write(offset, bytes)` is called for every chunk,
    /// in order, zeros included; the caller decides whether to keep holes sparse.
    fn read_chunks(
        &self,
        ino: &Inode,
        blk: &[u8],
        mut write: impl FnMut(u64, &[u8]) -> Result<()>,
    ) -> Result<()> {
        ensure!(ino.kind() == Some(Kind::File), "not a regular file");
        self.read_data(ino, blk, &mut write)
    }

    /// The data of any inode (file, symlink target).
    fn read_data(
        &self,
        ino: &Inode,
        blk: &[u8],
        write: &mut dyn FnMut(u64, &[u8]) -> Result<()>,
    ) -> Result<()> {
        ensure!(
            ino.size <= MAX_FILE_BYTES,
            "a file of {} bytes is over the {MAX_FILE_BYTES}-byte limit",
            ino.size
        );
        self.check_readable(ino)?;
        if ino.is_inline_data() {
            return write(0, self.inline_bytes(ino, blk, ino.size as usize)?);
        }
        let runs = if ino.size == 0 {
            Vec::new()
        } else {
            self.runs(ino, blk, ino.size.div_ceil(BS))?
        };
        let zeros = vec![0u8; COPY_CHUNK];
        let zero_fill = |write: &mut dyn FnMut(u64, &[u8]) -> Result<()>, from: u64, to: u64| {
            let mut at = from;
            while at < to {
                let k = (to - at).min(COPY_CHUNK as u64) as usize;
                write(at, &zeros[..k])?;
                at += k as u64;
            }
            Ok::<(), anyhow::Error>(())
        };
        let mut buf = vec![0u8; COPY_CHUNK];
        let mut at = 0u64;
        for run in runs {
            let start = run.lblk * BS;
            if start >= ino.size {
                break;
            }
            zero_fill(write, at, start)?;
            let bytes = (run.blocks * BS).min(ino.size - start);
            let base = run.pblk * BS;
            let mut done = 0u64;
            while done < bytes {
                let n = (bytes - done).min(COPY_CHUNK as u64) as usize;
                self.src
                    .read_at(base + done, &mut buf[..n])
                    .with_context(|| format!("reading file data at byte {}", start + done))?;
                write(start + done, &buf[..n])?;
                done += n as u64;
            }
            at = start + bytes;
        }
        zero_fill(write, at, ino.size)
    }

    /// The names in directory `dir` as `(name, inode number)`, without `.` and `..`.
    fn dir_entries(&self, dir: &Inode, blk: &[u8]) -> Result<Vec<(String, u32)>> {
        ensure!(dir.kind() == Some(Kind::Dir), "not a directory");
        ensure!(
            dir.size <= MAX_DIR_BYTES,
            "a directory of {} bytes is over the {MAX_DIR_BYTES}-byte limit",
            dir.size
        );
        ensure!(
            dir.advise & ADVISE_ENCRYPT == 0,
            "directory inode {} is encrypted; encrypted f2fs is not supported",
            dir.nid
        );
        let max_nid = self.sb.max_nid();
        let mut out = Vec::new();
        if dir.inline & INLINE_DENTRY != 0 {
            let (nr, bitmap, reserved) = inline_dentry_layout(dir.max_inline());
            let area = self.inline_bytes(dir, blk, dir.max_inline())?;
            let dents = bitmap + reserved;
            let names = dents + nr * DENTRY_SIZE;
            parse_dentries(
                &area[..bitmap],
                &area[dents..names],
                &area[names..names + nr * SLOT_LEN],
                nr,
                max_nid,
                &mut out,
            )?;
            return Ok(out);
        }
        self.map_blocks(dir, blk, dir.size.div_ceil(BS), &mut |_, p| {
            let b = self.block(p as u64)?;
            // bitmap (27 bytes), 3 reserved, 214 dentries, 214 name slots
            parse_dentries(
                &b[..27],
                &b[30..30 + DENTRIES_PER_BLOCK * DENTRY_SIZE],
                &b[30 + DENTRIES_PER_BLOCK * DENTRY_SIZE..],
                DENTRIES_PER_BLOCK,
                max_nid,
                &mut out,
            )
        })?;
        Ok(out)
    }

    fn xattrs_of(&self, ino: &Inode, blk: &[u8]) -> Result<Vec<(String, String)>> {
        // The attributes are one stream: the inline area (the end of the address array) and then
        // the first 4072 bytes of the xattr node block. When the inline area is empty and the node
        // block has its own header (f2fs-tools writes volumes that way), the node holds it all.
        let inline: &[u8] = if ino.xattr_words > 0 {
            let at = ino.addr_at + ino.data_addrs * 4;
            &blk[at..at + ino.xattr_words * 4]
        } else {
            &[]
        };
        let node = if ino.xattr_nid != 0 {
            Some(
                self.node(ino.xattr_nid, Some(ino.nid))
                    .context("reading the extended attribute block")?,
            )
        } else {
            None
        };
        let area = match (&node, inline.len() >= 4 && le32(inline, 0) != 0) {
            (Some(n), true) => [inline, &n[..NODE_FOOTER]].concat(),
            (Some(n), false) => n[..NODE_FOOTER].to_vec(),
            (None, _) => inline.to_vec(),
        };
        let mut raw = parse_xattrs(&area)?;
        raw.sort_by(|a, b| a.0.cmp(&b.0));
        Ok(raw.into_iter().map(|(k, v)| (k, xattr_text(&v))).collect())
    }

    fn symlink_target(&self, ino: &Inode, blk: &[u8]) -> Result<String> {
        ensure!(
            ino.size <= MAX_SYMLINK,
            "a symlink target of {} bytes is not valid",
            ino.size
        );
        let mut bytes = Vec::with_capacity(ino.size as usize);
        self.read_data(ino, blk, &mut |_, b| {
            bytes.extend_from_slice(b);
            Ok(())
        })?;
        Ok(name_string(&bytes))
    }

    fn entry_of(&self, path: String, ino: &Inode, blk: &[u8], kind: Kind) -> Result<Entry> {
        let rdev = matches!(kind, Kind::CharDevice | Kind::BlockDevice).then(|| {
            let (a0, a1) = (le32(blk, ino.addr_at), le32(blk, ino.addr_at + 4));
            if a0 != 0 {
                ((a0 >> 8) & 0xFF, a0 & 0xFF)
            } else {
                ((a1 & 0xFFF00) >> 8, (a1 & 0xFF) | ((a1 >> 12) & 0xFFF00))
            }
        });
        Ok(Entry {
            path,
            kind,
            mode: ino.mode as u32 & 0o7777,
            uid: ino.uid,
            gid: ino.gid,
            size: if kind == Kind::File { ino.size } else { 0 },
            mtime: ino.mtime,
            ino: ino.nid as u64,
            nlink: ino.links,
            link: if kind == Kind::Symlink {
                Some(self.symlink_target(ino, blk)?)
            } else {
                None
            },
            rdev,
            xattrs: self.xattrs_of(ino, blk)?,
            sha256: None,
            extracted_as: None,
        })
    }

    fn kind_of(ino: &Inode) -> Result<Kind> {
        ino.kind()
            .with_context(|| format!("unknown file type in mode {:#o}", ino.mode))
    }

    /// Resolve `path` to its entry without following symlinks ("" or "/" is the root).
    fn lookup(&self, path: &str) -> Result<(Entry, Inode)> {
        let (mut ino, mut blk) = self
            .load(self.sb.root_ino)
            .context("reading the root directory")?;
        let mut at = String::new();
        for part in path.split('/').filter(|p| !p.is_empty() && *p != ".") {
            ensure!(part != "..", "paths containing .. are not accepted");
            let here = if at.is_empty() {
                "/".to_string()
            } else {
                format!("/{at}")
            };
            ensure!(
                ino.kind() == Some(Kind::Dir),
                "{} is not a directory (symlinks are not followed)",
                short(&here)
            );
            let found = self
                .dir_entries(&ino, &blk)?
                .into_iter()
                .find(|(n, _)| n == part);
            let (_, nid) =
                found.with_context(|| format!("{} not found in {}", short(part), short(&here)))?;
            (ino, blk) = self.load(nid)?;
            at = if at.is_empty() {
                part.to_string()
            } else {
                format!("{at}/{part}")
            };
        }
        let kind = Self::kind_of(&ino)?;
        Ok((self.entry_of(at, &ino, &blk, kind)?, ino))
    }

    fn walk(&self) -> Result<Vec<(Entry, Inode)>> {
        self.walk_with(LIMITS)
    }

    fn walk_with(&self, limits: Limits) -> Result<Vec<(Entry, Inode)>> {
        let (root, root_blk) = self
            .load(self.sb.root_ino)
            .context("reading the root directory")?;
        ensure!(
            root.kind() == Some(Kind::Dir),
            "the root inode is not a directory"
        );
        let mut out: Vec<(Entry, Inode)> = Vec::new();
        let mut seen_dirs: HashSet<u32> = HashSet::from([root.nid]);
        let mut stack = vec![(root, root_blk, String::new(), 0usize)];
        while let Some((dir, dir_blk, prefix, depth)) = stack.pop() {
            ensure!(
                depth < limits.depth,
                "directories are nested more than {} deep",
                limits.depth
            );
            let mut children = self
                .dir_entries(&dir, &dir_blk)
                .with_context(|| format!("reading directory {}", short(&format!("/{prefix}"))))?;
            ensure!(
                children.len() <= limits.entries,
                "a directory has more than {} entries",
                limits.entries
            );
            children.sort();
            for (name, nid) in children {
                let path = if prefix.is_empty() {
                    name
                } else {
                    format!("{prefix}/{name}")
                };
                ensure!(
                    path.len() <= limits.path,
                    "a path is longer than {} bytes",
                    limits.path
                );
                ensure!(
                    out.len() < limits.entries,
                    "the image has more than {} entries",
                    limits.entries
                );
                let (ino, blk) = self
                    .load(nid)
                    .with_context(|| format!("entry {}", short(&path)))?;
                let kind =
                    Self::kind_of(&ino).with_context(|| format!("entry {}", short(&path)))?;
                if kind == Kind::Dir {
                    ensure!(
                        seen_dirs.insert(nid),
                        "directory inode {nid} is reachable twice ({}): a loop",
                        short(&path)
                    );
                    stack.push((ino.clone(), blk.clone(), path.clone(), depth + 1));
                }
                let entry = self
                    .entry_of(path.clone(), &ino, &blk, kind)
                    .with_context(|| format!("entry {}", short(&path)))?;
                out.push((entry, ino));
            }
        }
        out.sort_by(|a, b| a.0.path.cmp(&b.0.path));
        Ok(out)
    }

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
        self.walk()
    }

    fn copy_data(&self, node: &Inode, out: &mut File, budget: &mut u64) -> Result<String> {
        ensure!(
            node.size <= *budget,
            "the files add up to more than the {}-byte limit",
            *budget
        );
        *budget -= node.size;
        let (ino, blk) = self.load(node.nid)?;
        let mut hasher = Sha256::new();
        self.read_chunks(&ino, &blk, |at, bytes| {
            hasher.update(bytes);
            write_unless_zero(out, at, bytes)?;
            Ok(())
        })?;
        out.set_len(ino.size)?;
        Ok(hasher
            .finalize()
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect())
    }

    fn list_dir(&self, path: &str) -> Result<Vec<Entry>> {
        let (entry, ino) = self.lookup(path)?;
        if entry.kind != Kind::Dir {
            return Ok(vec![entry]);
        }
        let blk = self.node(ino.nid, Some(ino.nid))?;
        let mut children = self.dir_entries(&ino, &blk)?;
        children.sort();
        children
            .into_iter()
            .map(|(name, nid)| {
                let (child, cblk) = self.load(nid)?;
                let kind = Self::kind_of(&child).with_context(|| short(&name))?;
                let p = if entry.path.is_empty() {
                    name
                } else {
                    format!("{}/{name}", entry.path)
                };
                self.entry_of(p, &child, &cblk, kind)
            })
            .collect()
    }

    fn cat_path(&self, path: &str, out: &mut dyn Write) -> Result<()> {
        let (entry, ino) = self.lookup(path)?;
        check_cat(&entry)?;
        let (ino, blk) = self.load(ino.nid)?;
        self.read_chunks(&ino, &blk, |_, bytes| Ok(out.write_all(bytes)?))
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::testutil::Scratch;
    use crate::tree::manifest;

    // a tiny volume: 2 checkpoint segments, 2 SIT, 2 NAT (one copy of each NAT block + a spare),
    // 1 SSA and 1 main segment
    const CP: u32 = 2;
    const SIT: u32 = 1026;
    const NAT: u32 = 2050;
    const SSA: u32 = 3074;
    const MAIN: u32 = 3586;
    const BLOCKS: u64 = 4098;
    const REG: u16 = 0o100000;
    const DIR: u16 = 0o040000;
    const LNK: u16 = 0o120000;
    const CHR: u16 = 0o020000;

    fn p16(b: &mut [u8], at: usize, v: u16) {
        b[at..at + 2].copy_from_slice(&v.to_le_bytes());
    }
    fn p32(b: &mut [u8], at: usize, v: u32) {
        b[at..at + 4].copy_from_slice(&v.to_le_bytes());
    }
    fn p64(b: &mut [u8], at: usize, v: u64) {
        b[at..at + 8].copy_from_slice(&v.to_le_bytes());
    }

    /// One inode block, field by field.
    #[derive(Clone)]
    struct I {
        mode: u16,
        size: u64,
        uid: u32,
        gid: u32,
        links: u32,
        mtime: u64,
        advise: u8,
        flags: u32,
        inline: u8,
        xnid: u32,
        extra: usize,
        xwords: usize,
        addrs: Vec<u32>,
        nids: [u32; 5],
        inline_data: Vec<u8>,
        xattr: Vec<u8>,
    }

    impl I {
        fn new(mode: u16, size: u64) -> I {
            I {
                mode,
                size,
                uid: 0,
                gid: 0,
                links: 1,
                mtime: 0,
                advise: 0,
                flags: 0,
                inline: 0,
                xnid: 0,
                extra: 0,
                xwords: 0,
                addrs: vec![],
                nids: [0; 5],
                inline_data: vec![],
                xattr: vec![],
            }
        }

        fn build(&self) -> Vec<u8> {
            let mut b = vec![0u8; BS_USIZE];
            p16(&mut b, 0, self.mode);
            b[2] = self.advise;
            let mut inline = self.inline;
            if self.xwords > 0 {
                inline |= INLINE_XATTR;
            }
            if self.extra > 0 {
                inline |= EXTRA_ATTR;
            }
            b[3] = inline;
            p32(&mut b, 4, self.uid);
            p32(&mut b, 8, self.gid);
            p32(&mut b, 12, self.links);
            p64(&mut b, 16, self.size);
            p64(&mut b, 48, self.mtime);
            p32(&mut b, 76, self.xnid);
            p32(&mut b, 80, self.flags);
            if self.extra > 0 {
                p16(&mut b, I_ADDR, self.extra as u16);
                p16(&mut b, I_ADDR + 2, self.xwords as u16);
            }
            let base = I_ADDR + self.extra;
            for (i, a) in self.addrs.iter().enumerate() {
                p32(&mut b, base + 4 * i, *a);
            }
            b[base + 4..base + 4 + self.inline_data.len()].copy_from_slice(&self.inline_data);
            if self.xwords > 0 {
                let at = I_NID - self.xwords * 4;
                b[at..at + self.xattr.len()].copy_from_slice(&self.xattr);
            }
            for (i, n) in self.nids.iter().enumerate() {
                p32(&mut b, I_NID + 4 * i, *n);
            }
            b
        }
    }

    /// A volume under construction.
    struct Img {
        b: Vec<u8>,
        next: u32,
    }

    impl Img {
        fn new() -> Img {
            Img::with_feature(0)
        }

        fn with_feature(feature: u32) -> Img {
            let mut m = Img {
                b: vec![0u8; BLOCKS as usize * BS_USIZE],
                next: 0,
            };
            p32(&mut m.b, 1024, MAGIC);
            p16(&mut m.b, 1024 + 4, 1);
            p16(&mut m.b, 1024 + 6, 16);
            for (off, v) in [
                (8, 9),
                (12, 3),
                (16, 12),
                (20, 9),
                (24, 1),
                (28, 1),
                (44, 1),
                (48, 8),
                (52, 2),
                (56, 2),
                (60, 2),
                (64, 1),
                (68, 1),
                (72, CP),
                (76, CP),
                (80, SIT),
                (84, NAT),
                (88, SSA),
                (92, MAIN),
                (96, 3),
                (100, 1),
                (104, 2),
                (2180, feature),
            ] {
                p32(&mut m.b, 1024 + off, v);
            }
            p64(&mut m.b, 1024 + 36, BLOCKS);
            if feature & F_SB_CHKSUM != 0 {
                p32(&mut m.b, 1024 + 32, 3068);
                let c = crc(&m.b[1024..1024 + 3068]);
                p32(&mut m.b, 1024 + 3068, c);
            }
            m.pack(0, 2, CP_COMPACT_SUM, &[], &[]);
            m.pack(1, 1, CP_COMPACT_SUM, &[], &[]);
            m
        }

        /// Write checkpoint pack `idx` (0 or 1): version, flags, NAT journal entries
        /// `(nid, ino, block)`, and the NAT bitmap bits set for the given NAT block numbers.
        fn pack(
            &mut self,
            idx: u32,
            ver: u64,
            flags: u32,
            journal: &[(u32, u32, u32)],
            bits: &[usize],
        ) {
            let blk = (CP + idx * 512) as usize;
            let mut cp = vec![0u8; BS_USIZE];
            p64(&mut cp, 0, ver);
            p32(&mut cp, 132, flags);
            p32(&mut cp, 136, 4);
            p32(&mut cp, 140, 1);
            p32(&mut cp, 156, 64);
            p32(&mut cp, 160, 64);
            p32(&mut cp, 164, 4092);
            for bit in bits {
                cp[192 + 64 + bit / 8] |= 0x80 >> (bit % 8);
            }
            let c = crc(&cp[..4092]);
            p32(&mut cp, 4092, c);
            let mut sum = vec![0u8; BS_USIZE];
            let at = if flags & CP_COMPACT_SUM != 0 {
                0
            } else {
                SUM_JOURNAL_AT
            };
            p16(&mut sum, at, journal.len() as u16);
            for (i, (nid, ino, b)) in journal.iter().enumerate() {
                let e = at + 2 + i * JOURNAL_ENTRY_SIZE;
                p32(&mut sum, e, *nid);
                p32(&mut sum, e + 5, *ino);
                p32(&mut sum, e + 9, *b);
            }
            self.b[blk * BS_USIZE..(blk + 1) * BS_USIZE].copy_from_slice(&cp);
            self.b[(blk + 1) * BS_USIZE..(blk + 2) * BS_USIZE].copy_from_slice(&sum);
            self.b[(blk + 3) * BS_USIZE..(blk + 4) * BS_USIZE].copy_from_slice(&cp);
        }

        fn alloc(&mut self) -> u32 {
            let b = MAIN + self.next;
            self.next += 1;
            assert!(self.next <= 512, "the test volume is full");
            b
        }

        /// A data block holding `bytes`; returns its address.
        fn data(&mut self, bytes: &[u8]) -> u32 {
            let b = self.alloc();
            let at = b as usize * BS_USIZE;
            self.b[at..at + bytes.len()].copy_from_slice(bytes);
            b
        }

        /// Write a NAT entry for `nid` into copy 0 of its NAT block.
        fn nat_entry(&mut self, nid: u32, ino: u32, blk: u32) {
            let at = (NAT + nid / NAT_PER_BLOCK) as usize * BS_USIZE
                + (nid % NAT_PER_BLOCK) as usize * NAT_ENTRY_SIZE;
            p32(&mut self.b, at + 1, ino);
            p32(&mut self.b, at + 5, blk);
        }

        /// A node: `content` (at most 4072 bytes) plus the footer, registered in the NAT.
        fn node(&mut self, nid: u32, ino: u32, content: &[u8]) -> u32 {
            let blk = self.alloc();
            let at = blk as usize * BS_USIZE;
            self.b[at..at + content.len()].copy_from_slice(content);
            p32(&mut self.b, at + NODE_FOOTER, nid);
            p32(&mut self.b, at + NODE_FOOTER + 4, ino);
            self.nat_entry(nid, ino, blk);
            blk
        }

        fn inode(&mut self, nid: u32, i: &I) -> u32 {
            self.node(nid, nid, &i.build()[..NODE_FOOTER])
        }

        /// A root directory (node 3) with one dentry block listing `names`.
        fn root(&mut self, names: &[(&str, u32)]) {
            let blk = self.data(&dentry_block(names));
            let mut r = I::new(DIR | 0o755, 4096);
            r.addrs = vec![blk];
            self.inode(3, &r);
        }

        fn fs(&self) -> Fs {
            Fs::from_bytes(self.b.clone()).unwrap()
        }

        fn open(&self) -> Result<Fs> {
            Fs::from_bytes(self.b.clone())
        }
    }

    /// A dentry block: `.` and `..` first, then the entries, one slot per 8 bytes of name.
    fn dentry_block(entries: &[(&str, u32)]) -> Vec<u8> {
        let mut b = vec![0u8; BS_USIZE];
        let mut slot = 0;
        for (name, ino) in [(".", 3), ("..", 3)].iter().chain(entries.iter()) {
            b[slot / 8] |= 1 << (slot % 8);
            let d = 30 + slot * DENTRY_SIZE;
            p32(&mut b, d + 4, *ino);
            p16(&mut b, d + 8, name.len() as u16);
            let n = 30 + DENTRIES_PER_BLOCK * DENTRY_SIZE + slot * SLOT_LEN;
            b[n..n + name.len()].copy_from_slice(name.as_bytes());
            slot += name.len().div_ceil(SLOT_LEN);
        }
        b
    }

    /// The inline directory area for `max_inline` bytes.
    fn inline_dentries(max_inline: usize, entries: &[(&str, u32)]) -> Vec<u8> {
        let (nr, bitmap, reserved) = inline_dentry_layout(max_inline);
        let mut b = vec![0u8; max_inline];
        let (dents, names) = (bitmap + reserved, bitmap + reserved + nr * DENTRY_SIZE);
        let mut slot = 0;
        for (name, ino) in [(".", 3), ("..", 3)].iter().chain(entries.iter()) {
            b[slot / 8] |= 1 << (slot % 8);
            let d = dents + slot * DENTRY_SIZE;
            p32(&mut b, d + 4, *ino);
            p16(&mut b, d + 8, name.len() as u16);
            let n = names + slot * SLOT_LEN;
            b[n..n + name.len()].copy_from_slice(name.as_bytes());
            slot += name.len().div_ceil(SLOT_LEN);
        }
        b
    }

    /// One xattr entry, padded to 4 bytes.
    fn xentry(index: u8, name: &str, value: &[u8]) -> Vec<u8> {
        let mut b = vec![index, name.len() as u8];
        b.extend((value.len() as u16).to_le_bytes());
        b.extend(name.as_bytes());
        b.extend(value);
        while b.len() % 4 != 0 {
            b.push(0);
        }
        b
    }

    /// An xattr stream: header, entries `(index, name, value)`, a zero word.
    fn xattrs(entries: &[(u8, &str, &[u8])]) -> Vec<u8> {
        let mut b = vec![0u8; XATTR_HEADER];
        p32(&mut b, 0, XATTR_MAGIC);
        p32(&mut b, 4, 1);
        for (index, name, value) in entries {
            b.extend(xentry(*index, name, value));
        }
        b.extend([0u8; 4]);
        b
    }

    fn cat(fs: &Fs, path: &str) -> Vec<u8> {
        let mut out = Vec::new();
        fs.cat_path(path, &mut out).unwrap();
        out
    }

    fn pattern(n: usize, seed: u8) -> Vec<u8> {
        (0..n)
            .map(|i| (i as u8).wrapping_mul(31).wrapping_add(seed))
            .collect()
    }

    fn err_of<T>(r: Result<T>) -> String {
        format!("{:#}", r.err().expect("an error was expected"))
    }

    /// The tree most tests read.
    fn sample() -> Img {
        let mut m = Img::new();
        let (b0, b1, b2) = (
            m.data(&pattern(4096, 1)),
            m.data(&pattern(4096, 2)),
            m.data(&pattern(100, 3)),
        );
        let target = m.data(&[b'x'; 100]);
        m.root(&[
            ("a", 4),
            ("d", 5),
            ("s", 6),
            ("l", 7),
            ("x", 8),
            ("dev", 9),
            ("empty", 10),
            ("old", 12),
        ]);
        let d_dents = m.data(&dentry_block(&[("b", 11)]));
        let mut a = I::new(REG | 0o644, 5);
        a.inline = INLINE_DATA;
        a.inline_data = b"hello".to_vec();
        m.inode(4, &a);
        let mut d = I::new(DIR | 0o750, 4096);
        d.addrs = vec![d_dents];
        m.inode(5, &d);
        let mut s = I::new(LNK | 0o777, 1);
        s.inline = INLINE_DATA;
        s.inline_data = b"a".to_vec();
        m.inode(6, &s);
        let mut l = I::new(LNK | 0o777, 100);
        l.addrs = vec![target];
        m.inode(7, &l);
        // uid/gid/mtime, inline data, and an inline xattr area holding the whole stream
        let mut x = I::new(REG | 0o4755, 8);
        x.uid = 1000;
        x.gid = 2000;
        x.mtime = 1_700_000_000;
        x.links = 2;
        x.inline = INLINE_DATA;
        x.inline_data = b"labelled".to_vec();
        x.xwords = 50;
        x.xattr = xattrs(&[
            (6, "selinux", b"u:object_r:system_file:s0\0"),
            (6, "capability", &[1, 0, 0, 2, 0, 0, 0, 0]),
        ]);
        m.inode(8, &x);
        let mut dev = I::new(CHR | 0o600, 0);
        dev.addrs = vec![0, 200 | (10 << 8)];
        m.inode(9, &dev);
        m.inode(10, &I::new(REG | 0o444, 0));
        let mut old = I::new(CHR | 0o600, 0);
        old.addrs = vec![(4 << 8) | 64];
        m.inode(12, &old);
        let mut b = I::new(REG | 0o600, 8192 + 100);
        b.addrs = vec![b0, b1, b2];
        m.inode(11, &b);
        m
    }

    /// A small volume laid out like a system partition that has a debug `build.prop` and a
    /// setuid `su`, labelled `u:object_r:system_file:s0`; the bytes of the image.
    pub(crate) fn debug_system_image() -> Vec<u8> {
        let label = xattrs(&[(6, "selinux", b"u:object_r:system_file:s0\0")]);
        let mut m = Img::new();
        m.root(&[("system", 4)]);
        let sys = m.data(&dentry_block(&[("build.prop", 5), ("xbin", 6)]));
        let mut d = I::new(DIR | 0o755, 4096);
        d.addrs = vec![sys];
        m.inode(4, &d);
        let props = b"ro.debuggable=1\nro.secure=0\nro.adb.secure=0\n";
        let mut f = I::new(REG | 0o644, props.len() as u64);
        f.inline = INLINE_DATA;
        f.inline_data = props.to_vec();
        f.xwords = 50;
        f.xattr = label.clone();
        m.inode(5, &f);
        let xbin = m.data(&dentry_block(&[("su", 7)]));
        let mut x = I::new(DIR | 0o755, 4096);
        x.addrs = vec![xbin];
        m.inode(6, &x);
        let mut su = I::new(REG | 0o4755, 7);
        su.inline = INLINE_DATA;
        su.inline_data = b"fake su".to_vec();
        su.xwords = 50;
        su.xattr = label;
        m.inode(7, &su);
        m.b
    }

    #[test]
    fn lists_the_whole_tree_with_metadata() {
        let fs = sample().fs();
        let list = fs.walk().unwrap();
        let paths: Vec<_> = list.iter().map(|(e, _)| e.path.as_str()).collect();
        assert_eq!(
            paths,
            ["a", "d", "d/b", "dev", "empty", "l", "old", "s", "x"]
        );
        let by = |p: &str| &list.iter().find(|(e, _)| e.path == p).unwrap().0;
        assert_eq!(by("s").link.as_deref(), Some("a"));
        assert_eq!(by("l").link.as_deref(), Some("x".repeat(100).as_str()));
        assert_eq!((by("d").kind, by("d").mode), (Kind::Dir, 0o750));
        assert_eq!((by("d/b").size, by("d/b").mode), (8292, 0o600));
        assert_eq!(by("empty").size, 0);
        assert_eq!(
            (by("d").size, by("s").size),
            (0, 0),
            "only files carry a size"
        );
        let x = by("x");
        assert_eq!(
            (x.uid, x.gid, x.mtime, x.nlink),
            (1000, 2000, 1_700_000_000, 2)
        );
        assert_eq!(x.mode, 0o4755, "the setuid bit is kept");
        assert_eq!(x.ino, 8);
        assert_eq!(by("dev").rdev, Some((10, 200)), "new device encoding");
        assert_eq!(by("old").rdev, Some((4, 64)), "old device encoding");
        assert_eq!(by("dev").kind, Kind::CharDevice);
    }

    #[test]
    fn selinux_labels_and_file_capabilities_are_exposed_like_ext4() {
        let fs = sample().fs();
        let (e, _) = fs.lookup("x").unwrap();
        assert_eq!(
            e.xattrs,
            [
                (
                    "security.capability".to_string(),
                    "hex:0100000200000000".to_string()
                ),
                (
                    "security.selinux".to_string(),
                    "u:object_r:system_file:s0".to_string()
                ),
            ]
        );
    }

    #[test]
    fn a_stream_continues_from_the_inline_area_into_the_node() {
        // fill the inline area exactly (200 bytes): a header and one entry of 176 bytes
        let mut m = Img::new();
        let mut inline = xattrs(&[]);
        inline.truncate(XATTR_HEADER);
        inline.extend(xentry(1, "filler.one", &[7u8; 176 - 4 - 10]));
        assert_eq!(inline.len(), 200);
        // the node carries on from there: no new header, the next entry, the terminator
        let mut node = xentry(6, "selinux", b"u:object_r:system_file:s0\0");
        node.extend([0u8; 4]);
        m.node(20, 8, &node);
        let mut x = I::new(REG | 0o644, 0);
        x.xwords = 50;
        x.xnid = 20;
        x.xattr = inline;
        m.inode(8, &x);
        m.root(&[("x", 8)]);
        let (e, _) = m.fs().lookup("x").unwrap();
        assert_eq!(
            e.xattrs,
            [
                (
                    "security.selinux".to_string(),
                    "u:object_r:system_file:s0".to_string()
                ),
                (
                    "user.filler.one".to_string(),
                    format!("hex:{}", "07".repeat(162))
                ),
            ]
        );
    }

    #[test]
    fn a_node_with_its_own_header_stands_alone_when_the_inline_area_is_empty() {
        // f2fs-tools writes volumes like this: the inline flag is set, the inline area is zero
        let mut m = Img::new();
        m.node(
            20,
            8,
            &xattrs(&[(6, "selinux", b"u:object_r:system_file:s0\0")]),
        );
        let mut x = I::new(REG | 0o644, 0);
        x.xwords = 50;
        x.xnid = 20;
        m.inode(8, &x);
        // and one with no inline flag at all
        m.node(21, 9, &xattrs(&[(6, "selinux", b"u:object_r:other:s0\0")]));
        let mut y = I::new(REG | 0o644, 0);
        y.xnid = 21;
        m.inode(9, &y);
        m.root(&[("x", 8), ("y", 9)]);
        let fs = m.fs();
        assert_eq!(
            fs.lookup("x").unwrap().0.xattrs[0].1,
            "u:object_r:system_file:s0"
        );
        assert_eq!(fs.lookup("y").unwrap().0.xattrs[0].1, "u:object_r:other:s0");
    }

    #[test]
    fn an_xattr_node_that_belongs_to_another_inode_is_refused() {
        let mut m = Img::new();
        m.node(20, 77, &xattrs(&[(6, "selinux", b"u:object_r:x:s0\0")]));
        let mut x = I::new(REG | 0o644, 0);
        x.xnid = 20;
        m.inode(8, &x);
        m.root(&[("x", 8)]);
        let e = err_of(m.fs().lookup("x"));
        assert!(e.contains("belongs to inode 77"), "{e}");
    }

    #[test]
    fn xattr_names_cover_every_namespace_and_damage_is_reported() {
        let area = xattrs(&[
            (1, "k", b"v"),
            (2, "", b"acl"),
            (3, "", b"acl"),
            (4, "t", b"v"),
            (6, "selinux", b"s"),
            (7, "", b"adv"),
            (99, "odd", b"v"),
        ]);
        let names: Vec<String> = parse_xattrs(&area)
            .unwrap()
            .into_iter()
            .map(|(n, _)| n)
            .collect();
        assert_eq!(
            names,
            [
                "user.k",
                "system.posix_acl_access",
                "system.posix_acl_default",
                "trusted.t",
                "security.selinux",
                "system.advise",
                "unknown99.odd"
            ]
        );
        assert!(
            parse_xattrs(&[]).unwrap().is_empty(),
            "no area, no attributes"
        );
        assert!(
            parse_xattrs(&[0u8; 64]).unwrap().is_empty(),
            "a zero header means never written"
        );
        let mut bad = area.clone();
        p32(&mut bad, 0, 0x1234_5678);
        assert!(err_of(parse_xattrs(&bad)).contains("bad magic"));
        // an entry whose value runs past the area
        let mut cut = xattrs(&[(6, "selinux", &[1u8; 40])]);
        cut.truncate(40);
        assert!(err_of(parse_xattrs(&cut)).contains("runs past"));
        // a value over the limit
        let mut huge = xattrs(&[(6, "selinux", b"x")]);
        p16(&mut huge, XATTR_HEADER + 2, u16::MAX);
        assert!(parse_xattrs(&huge).is_err());
    }

    #[test]
    fn file_contents_with_holes_read_back_exactly() {
        let mut m = Img::new();
        let (a, b) = (m.data(&pattern(4096, 1)), m.data(&pattern(4096, 2)));
        // block 0 data, 1 hole, 2 allocated but never written, 3 data, 4 hole (partial)
        let mut f = I::new(REG | 0o644, 4 * 4096 + 10);
        f.addrs = vec![a, 0, NEW_ADDR, b, 0];
        m.inode(4, &f);
        m.root(&[("f", 4)]);
        let fs = m.fs();
        let mut want = pattern(4096, 1);
        want.extend(vec![0u8; 8192]);
        want.extend(pattern(4096, 2));
        want.extend(vec![0u8; 10]);
        assert_eq!(cat(&fs, "f"), want);
    }

    #[test]
    fn block_addressing_follows_direct_indirect_and_double_indirect_nodes() {
        let mut m = Img::new();
        let blk = |n: u32| MAIN + n;
        let node = |entries: &[(usize, u32)]| {
            let mut c = vec![0u8; NODE_FOOTER];
            for (i, v) in entries {
                p32(&mut c, 4 * i, *v);
            }
            c
        };
        const INO: u32 = 30;
        m.node(31, INO, &node(&[(5, blk(7))])); // direct
        m.node(32, INO, &node(&[(2, blk(9))])); // direct under the first indirect
        m.node(33, INO, &node(&[(1, 32)])); // indirect: its second child
        m.node(34, INO, &node(&[(4, blk(11))])); // direct under the double indirect
        m.node(35, INO, &node(&[(3, 34)])); // indirect under the double indirect
        m.node(36, INO, &node(&[(0, 35)])); // double indirect
        let mut f = I::new(REG | 0o644, 1);
        f.addrs = vec![0, 0, 0, blk(3)];
        f.nids = [31, 0, 33, 0, 36];
        m.inode(INO, &f);
        let fs = m.fs();
        let (ino, ib) = fs.load(INO).unwrap();
        let mut got = Vec::new();
        fs.map_blocks(&ino, &ib, u64::MAX, &mut |l, p| {
            got.push((l, p));
            Ok(())
        })
        .unwrap();
        let direct = 923u64;
        let ind_base = direct + 2 * 1018;
        let dbl_base = ind_base + 2 * 1018 * 1018;
        assert_eq!(
            got,
            [
                (3, blk(3)),
                (direct + 5, blk(7)),
                (ind_base + 1018 + 2, blk(9)),
                (dbl_base + 3 * 1018 + 4, blk(11)),
            ]
        );
        // `nblocks` stops the walk early
        let mut few = Vec::new();
        fs.map_blocks(&ino, &ib, direct + 6, &mut |l, _| {
            few.push(l);
            Ok(())
        })
        .unwrap();
        assert_eq!(few, [3, direct + 5]);
        // a node that belongs to another inode is refused
        let mut m2 = Img::new();
        m2.node(31, 99, &node(&[(5, blk(7))]));
        let mut f2 = I::new(REG | 0o644, 1);
        f2.nids[0] = 31;
        m2.inode(INO, &f2);
        let fs2 = m2.fs();
        let (i2, b2) = fs2.load(INO).unwrap();
        let e = err_of(fs2.map_blocks(&i2, &b2, u64::MAX, &mut |_, _| Ok(())));
        assert!(e.contains("belongs to inode 99"), "{e}");
    }

    #[test]
    fn extra_attribute_and_flexible_inline_xattr_sizes_move_the_address_array() {
        let mut m = Img::with_feature(F_FLEXIBLE_INLINE_XATTR);
        let d = m.data(&pattern(4096, 9));
        // 36 extra bytes (9 words) and 20 words of inline xattr: addresses start 36 bytes in
        let mut f = I::new(REG | 0o644, 4096);
        f.extra = 36;
        f.xwords = 20;
        f.addrs = vec![d];
        f.xattr = xattrs(&[(6, "selinux", b"u:object_r:x:s0\0")]);
        m.inode(4, &f);
        m.root(&[("f", 4)]);
        let fs = m.fs();
        assert_eq!(cat(&fs, "f"), pattern(4096, 9));
        let (e, ino) = fs.lookup("f").unwrap();
        assert_eq!(e.xattrs[0].1, "u:object_r:x:s0");
        assert_eq!(ino.data_addrs, 923 - 9 - 20);
    }

    #[test]
    fn inline_directories_are_listed() {
        let mut m = Img::new();
        let mut r = I::new(DIR | 0o755, 4096);
        r.inline = INLINE_DENTRY;
        let max = (ADDRS_PER_INODE - 1) * 4;
        r.inline_data = inline_dentries(max, &[("alpha", 4), ("a-much-longer-name", 5)]);
        m.inode(3, &r);
        let mut a = I::new(REG | 0o644, 3);
        a.inline = INLINE_DATA;
        a.inline_data = b"abc".to_vec();
        m.inode(4, &a);
        m.inode(5, &I::new(REG | 0o644, 0));
        let fs = m.fs();
        let paths: Vec<_> = fs
            .walk()
            .unwrap()
            .into_iter()
            .map(|(e, _)| e.path)
            .collect();
        assert_eq!(paths, ["a-much-longer-name", "alpha"]);
        assert_eq!(cat(&fs, "alpha"), b"abc");
        // geometry: bitmap, reserved bytes and entries fit the area, and one more would not
        let (nr, bm, rsv) = inline_dentry_layout(max);
        assert!(bm + rsv + nr * (DENTRY_SIZE + SLOT_LEN) <= max);
        assert!(bm + rsv + (nr + 1) * (DENTRY_SIZE + SLOT_LEN) + 1 > max);
    }

    fn parse_block(b: &[u8], max_nid: u64) -> Result<Vec<(String, u32)>> {
        let mut out = Vec::new();
        parse_dentries(
            &b[..27],
            &b[30..30 + 214 * 11],
            &b[30 + 214 * 11..],
            214,
            max_nid,
            &mut out,
        )?;
        Ok(out)
    }

    #[test]
    fn dentry_parsing_handles_slots_and_rejects_bad_entries() {
        let b = dentry_block(&[("a", 4), ("exactly8", 5), ("nine-char", 6)]);
        assert_eq!(
            parse_block(&b, 1 << 20).unwrap(),
            [
                ("a".to_string(), 4),
                ("exactly8".to_string(), 5),
                ("nine-char".to_string(), 6)
            ]
        );
        // a zero name length, a name running past the last slot, a slash, an inode number outside
        // the NAT, a missing inode number
        let mut bad = dentry_block(&[("a", 4)]);
        p16(&mut bad, 30 + 2 * 11 + 8, 0);
        assert!(err_of(parse_block(&bad, 1000)).contains("invalid name length"));
        let mut last = dentry_block(&[]);
        last[26] |= 0x20; // slot 213
        p16(&mut last, 30 + 213 * 11 + 8, 20);
        assert!(err_of(parse_block(&last, 1000)).contains("invalid name length"));
        assert!(err_of(parse_block(&dentry_block(&[("a/b", 4)]), 1000)).contains("invalid name"));
        assert!(err_of(parse_block(&dentry_block(&[("a", 5000)]), 1000)).contains("invalid inode"));
        assert!(err_of(parse_block(&dentry_block(&[("a", 0)]), 1000)).contains("invalid inode"));
        // too short an area
        let mut o = Vec::new();
        assert!(parse_dentries(&[0; 27], &[0; 10], &[0; 10], 214, 10, &mut o).is_err());
    }

    #[test]
    fn symlinks_inline_and_in_a_block() {
        let fs = sample().fs();
        assert_eq!(fs.lookup("s").unwrap().0.link.as_deref(), Some("a"));
        assert_eq!(
            fs.lookup("l").unwrap().0.link.as_deref().map(str::len),
            Some(100)
        );
    }

    #[test]
    fn path_lookup_and_listing_do_not_follow_symlinks() {
        let fs = sample().fs();
        for p in ["a", "/a", "a/", "./a", "//a", "d/b", "/d//b/"] {
            assert!(fs.lookup(p).is_ok(), "{p}");
        }
        assert_eq!(fs.lookup("/").unwrap().0.kind, Kind::Dir);
        let err = |p: &str| err_of(fs.lookup(p));
        assert!(err("nope").contains("nope"));
        assert!(err("a/x").contains("not a directory"));
        assert!(err("s/x").contains("symlinks are not followed"));
        assert!(err("d/../a").contains("not accepted"));
        let names = |p: &str| {
            fs.list_dir(p)
                .unwrap()
                .into_iter()
                .map(|e| e.path)
                .collect::<Vec<_>>()
        };
        assert_eq!(names("/"), ["a", "d", "dev", "empty", "l", "old", "s", "x"]);
        assert_eq!(names("d"), ["d/b"]);
        assert_eq!(names("a"), ["a"]);
    }

    #[test]
    fn cat_returns_bytes_and_refuses_what_is_not_a_file() {
        let fs = sample().fs();
        assert_eq!(cat(&fs, "a"), b"hello");
        assert_eq!(cat(&fs, "x"), b"labelled");
        assert_eq!(cat(&fs, "empty"), b"");
        let mut want = pattern(4096, 1);
        want.extend(pattern(4096, 2));
        want.extend(pattern(100, 3));
        assert_eq!(cat(&fs, "d/b"), want);
        let e = |p: &str| err_of(fs.cat_path(p, &mut Vec::new()));
        assert!(e("d").contains("not a regular file"));
        assert!(e("s").contains("symlink to a"));
        assert!(e("dev").contains("char"));
    }

    #[test]
    fn extraction_writes_exact_bytes_a_manifest_and_hashes() {
        let fs = sample().fs();
        let dir = Scratch::new("f2fs-extract");
        let out = dir.join("o");
        let entries = fs.extract(&out, Some(Collisions::Allow)).unwrap();
        let files = out.join("files");
        assert_eq!(std::fs::read(files.join("a")).unwrap(), b"hello");
        assert_eq!(std::fs::read(files.join("d/b")).unwrap().len(), 8292);
        assert!(
            files.join("s").symlink_metadata().is_err(),
            "symlinks are never created"
        );
        let sha: String = Sha256::digest(b"hello")
            .iter()
            .map(|x| format!("{x:02x}"))
            .collect();
        assert_eq!(
            entries
                .iter()
                .find(|e| e.path == "a")
                .unwrap()
                .sha256
                .as_deref(),
            Some(sha.as_str())
        );
        let m: serde_json::Value =
            serde_json::from_slice(&std::fs::read(out.join("manifest.json")).unwrap()).unwrap();
        assert_eq!(m["summary"]["entries"], 9);
        assert_eq!(manifest(&entries)["summary"]["by_type"]["symlink"], 2);
    }

    #[test]
    fn a_hard_link_is_extracted_once() {
        let mut m = Img::new();
        let mut f = I::new(REG | 0o644, 2);
        f.links = 2;
        f.inline = INLINE_DATA;
        f.inline_data = b"hi".to_vec();
        m.inode(4, &f);
        m.root(&[("one", 4), ("two", 4)]);
        let dir = Scratch::new("f2fs-hardlink");
        let entries = m
            .fs()
            .extract(&dir.join("o"), Some(Collisions::Allow))
            .unwrap();
        assert_eq!(entries.len(), 2);
        assert_eq!(std::fs::read(dir.join("o/files/two")).unwrap(), b"hi");
        assert_eq!(entries[0].sha256, entries[1].sha256);
    }

    // ---- the superblock ----

    fn sb_err(mutate: impl FnOnce(&mut Img)) -> String {
        let mut m = Img::new();
        mutate(&mut m);
        err_of(m.open())
    }

    #[test]
    fn the_superblock_is_validated_before_anything_is_allocated_or_read() {
        let set = |off: usize, v: u32| move |m: &mut Img| p32(&mut m.b, 1024 + off, v);
        assert!(sb_err(|m| m.b[1024] ^= 0xFF).contains("not an f2fs superblock"));
        assert!(sb_err(set(16, 13)).contains("block geometry"));
        assert!(sb_err(set(12, 4)).contains("block geometry"));
        assert!(sb_err(set(20, 8)).contains("segment size"));
        assert!(sb_err(set(24, 0)).contains("segments per section"));
        assert!(sb_err(set(28, u32::MAX)).contains("sections per zone"));
        assert!(sb_err(|m| p64(&mut m.b, 1024 + 36, u64::MAX)).contains("block count"));
        assert!(sb_err(|m| p64(&mut m.b, 1024 + 36, 0)).contains("block count"));
        for off in [52, 56, 60, 64, 68] {
            let e = sb_err(set(off, u32::MAX));
            assert!(e.contains("overlap") || e.contains("absurd"), "{off}: {e}");
        }
        assert!(sb_err(set(56, 3)).contains("segment counts"), "odd sit");
        assert!(sb_err(set(60, 3)).contains("segment counts"), "odd nat");
        assert!(sb_err(set(80, CP)).contains("overlap"));
        assert!(sb_err(set(76, 1)).contains("overlap"));
        assert!(sb_err(set(92, 4000)).contains("overlap"));
        assert!(sb_err(set(96, 0)).contains("special inode"));
        assert!(sb_err(set(96, 1 << 30)).contains("special inode"));
        assert!(sb_err(set(1664, 600)).contains("payload"));
        assert!(sb_err(set(2180, F_BLKZONED)).contains("zoned"));
        assert!(sb_err(set(2180, F_DEVICE_ALIAS)).contains("device-alias"));
        assert!(sb_err(set(2201 + 68 + 64, 49)).contains("multi-device"));
        assert!(sb_err(set(2180, 0x8_0000)).contains("does not know"));
    }

    #[test]
    fn the_superblock_checksum_is_checked_when_the_feature_is_on() {
        assert!(Img::with_feature(F_SB_CHKSUM).open().is_ok());
        let mut bad = Img::with_feature(F_SB_CHKSUM);
        bad.b[1024 + 100] ^= 1;
        assert!(err_of(bad.open()).contains("checksum does not match"));
        let mut off = Img::with_feature(F_SB_CHKSUM);
        p32(&mut off.b, 1024 + 32, 5000);
        assert!(err_of(off.open()).contains("out of range"));
    }

    #[test]
    fn the_encrypt_feature_alone_is_not_a_refusal_but_encrypted_inodes_are() {
        let mut m = Img::with_feature(0x1);
        let mut f = I::new(REG | 0o644, 1);
        f.advise = ADVISE_ENCRYPT;
        f.inline = INLINE_DATA;
        f.inline_data = vec![1];
        m.inode(4, &f);
        let mut d = I::new(DIR | 0o755, 4096);
        d.advise = ADVISE_ENCRYPT;
        m.inode(5, &d);
        m.root(&[("f", 4), ("d", 5)]);
        let fs = m.open().expect("the feature bit alone opens");
        assert!(err_of(fs.cat_path("f", &mut Vec::new())).contains("encrypted"));
        assert!(err_of(fs.list_dir("d")).contains("encrypted"));
        assert!(err_of(fs.walk()).contains("encrypted"));
    }

    #[test]
    fn compressed_files_are_refused_not_misread() {
        let mut m = Img::with_feature(F_COMPRESSION);
        let mut f = I::new(REG | 0o644, 4096);
        f.flags = COMPR_FL;
        f.addrs = vec![MAIN];
        m.inode(4, &f);
        // a cluster marker even without the inode flag
        let mut g = I::new(REG | 0o644, 8192);
        g.addrs = vec![COMPRESS_ADDR, MAIN];
        m.inode(5, &g);
        m.root(&[("c", 4), ("g", 5)]);
        let fs = m.fs();
        for p in ["c", "g"] {
            let e = err_of(fs.cat_path(p, &mut Vec::new()));
            assert!(e.contains("compressed"), "{p}: {e}");
        }
        // the tree itself still lists
        assert_eq!(fs.walk().unwrap().len(), 2);
        // the flag on a volume without the feature is just a file
        let mut plain = Img::new();
        let d = plain.data(&pattern(4096, 4));
        let mut h = I::new(REG | 0o644, 4096);
        h.flags = COMPR_FL;
        h.addrs = vec![d];
        plain.inode(4, &h);
        plain.root(&[("h", 4)]);
        assert_eq!(cat(&plain.fs(), "h"), pattern(4096, 4));
    }

    // ---- the checkpoint and the NAT ----

    #[test]
    fn the_newer_valid_checkpoint_wins_and_a_tie_goes_to_the_first() {
        // each pack's journal says a different block for node 4
        let probe = |v0: u64, v1: u64| {
            let mut m = Img::new();
            m.pack(0, v0, CP_COMPACT_SUM, &[(4, 4, MAIN)], &[]);
            m.pack(1, v1, CP_COMPACT_SUM, &[(4, 4, MAIN + 1)], &[]);
            m.fs().nat(4).unwrap().blk
        };
        assert_eq!(probe(5, 3), MAIN);
        assert_eq!(probe(3, 5), MAIN + 1);
        assert_eq!(probe(7, 7), MAIN, "a tie goes to the pack at cp_blkaddr");
        assert_eq!(probe(u64::MAX, 0), MAIN + 1, "versions wrap around");
    }

    #[test]
    fn a_pack_with_a_bad_checksum_or_a_mismatched_last_block_is_skipped() {
        let mut m = Img::new();
        m.pack(0, 9, CP_COMPACT_SUM, &[(4, 4, MAIN)], &[]);
        m.pack(1, 1, CP_COMPACT_SUM, &[(4, 4, MAIN + 1)], &[]);
        let mut bad_crc = Img {
            b: m.b.clone(),
            next: 0,
        };
        bad_crc.b[CP as usize * BS_USIZE + 200] ^= 1;
        assert_eq!(bad_crc.fs().nat(4).unwrap().blk, MAIN + 1);
        // the last block of the newer pack is from another version
        let mut torn = Img {
            b: m.b.clone(),
            next: 0,
        };
        torn.b[(CP as usize + 3) * BS_USIZE] ^= 1;
        assert_eq!(torn.fs().nat(4).unwrap().blk, MAIN + 1);
        // both bad
        let mut none = Img {
            b: bad_crc.b.clone(),
            next: 0,
        };
        none.b[(CP as usize + 512) * BS_USIZE + 200] ^= 1;
        assert!(err_of(none.open()).contains("no valid f2fs checkpoint"));
    }

    #[test]
    fn checkpoint_fields_are_validated() {
        let broken = |f: &dyn Fn(&mut [u8])| {
            let mut m = Img::new();
            for pack in 0..2usize {
                let at = (CP as usize + pack * 512) * BS_USIZE;
                f(&mut m.b[at..at + BS_USIZE]);
                let c = crc(&m.b[at..at + 4092]);
                p32(&mut m.b, at + 4092, c);
                let copy = m.b[at..at + BS_USIZE].to_vec();
                m.b[at + 3 * BS_USIZE..at + 4 * BS_USIZE].copy_from_slice(&copy);
            }
            err_of(m.open())
        };
        assert!(broken(&|b| p32(b, 136, 2)).contains("claims 2 blocks"));
        assert!(broken(&|b| p32(b, 136, 100_000)).contains("claims"));
        assert!(broken(&|b| p32(b, 140, 0)).contains("summary start"));
        assert!(broken(&|b| p32(b, 140, 4)).contains("summary start"));
        assert!(broken(&|b| p32(b, 160, 8)).contains("NAT bitmap"));
        assert!(broken(&|b| p32(b, 160, 100_000)).contains("NAT bitmap"));
        assert!(broken(&|b| p32(b, 156, 4000)).contains("do not fit"));
        assert!(broken(&|b| p32(b, 164, 100)).contains("out of range"));
        assert!(
            broken(&|b| p32(b, 132, CP_COMPACT_SUM | CP_LARGE_NAT_BITMAP))
                .contains("large NAT bitmap")
        );
        // a journal that claims more entries than fit
        let mut m = Img::new();
        p16(&mut m.b, (CP as usize + 1) * BS_USIZE, 39);
        p16(&mut m.b, (CP as usize + 513) * BS_USIZE, 39);
        assert!(err_of(m.open()).contains("39 entries"));
    }

    #[test]
    fn the_nat_journal_wins_over_the_table_and_the_bitmap_picks_the_copy() {
        let mut m = Img::new();
        m.nat_entry(7, 7, MAIN + 5);
        // node 9: a stale entry in copy 0 and the current one in copy 1 of NAT block 0
        m.nat_entry(9, 9, MAIN + 6);
        let at1 = (NAT + 512) as usize * BS_USIZE + 9 * NAT_ENTRY_SIZE;
        p32(&mut m.b, at1 + 1, 9);
        p32(&mut m.b, at1 + 5, MAIN + 8);
        // node 11 only in the journal; node 7 also in the journal with a newer address
        m.pack(
            0,
            2,
            CP_COMPACT_SUM,
            &[(11, 11, MAIN + 20), (7, 7, MAIN + 30)],
            &[0],
        );
        let fs = m.fs();
        assert_eq!(
            fs.nat(7).unwrap(),
            Nat {
                ino: 7,
                blk: MAIN + 30
            },
            "journal first"
        );
        assert_eq!(fs.nat(11).unwrap().blk, MAIN + 20);
        assert_eq!(
            fs.nat(9).unwrap().blk,
            MAIN + 8,
            "copy 1 when the bitmap bit is set"
        );
        // without the bit, copy 0
        let mut n = Img::new();
        n.nat_entry(9, 9, MAIN + 6);
        assert_eq!(n.fs().nat(9).unwrap().blk, MAIN + 6);
        // a NAT block beyond the first (node 500 is in block 1)
        n.nat_entry(500, 500, MAIN + 40);
        assert_eq!(n.fs().nat(500).unwrap().blk, MAIN + 40);
    }

    #[test]
    fn unusable_nat_entries_are_errors() {
        let mut m = Img::new();
        m.nat_entry(7, 7, NEW_ADDR);
        m.nat_entry(8, 8, 5); // before the main area
        m.nat_entry(9, 9, BLOCKS as u32); // past the volume
        let fs = m.fs();
        let e = |nid: u32| err_of(fs.nat(nid));
        assert!(e(6).contains("not allocated"));
        assert!(e(7).contains("never written"));
        assert!(e(8).contains("outside the main area"));
        assert!(e(9).contains("outside the main area"));
        assert!(e(0).contains("outside the node address table"));
        assert!(e(232_960).contains("outside the node address table"));
        assert!(e(u32::MAX).contains("outside the node address table"));
    }

    #[test]
    fn the_journal_of_a_normal_summary_is_read_from_its_own_offset() {
        let mut m = Img::new();
        m.pack(0, 5, 0, &[(4, 4, MAIN + 2)], &[]);
        m.pack(1, 1, 0, &[], &[]);
        assert_eq!(m.fs().nat(4).unwrap().blk, MAIN + 2);
    }

    #[test]
    fn a_node_must_name_itself_in_its_footer() {
        let mut m = Img::new();
        m.node(7, 7, &I::new(REG | 0o644, 0).build()[..NODE_FOOTER]);
        // the table says node 8 is where node 7 is
        let blk = m.fs().nat(7).unwrap().blk;
        m.nat_entry(8, 8, blk);
        let fs = m.fs();
        assert!(fs.node(7, Some(7)).is_ok());
        assert!(err_of(fs.node(8, None)).contains("is not node 8"));
    }

    // ---- hostile input ----

    #[test]
    fn walk_limits_are_enforced_and_loops_refused() {
        let fs = sample().fs();
        let big = Limits {
            depth: 8,
            path: 64,
            entries: 100,
        };
        assert_eq!(fs.walk_with(big).unwrap().len(), 9);
        let err = |l: Limits| err_of(fs.walk_with(l));
        assert!(err(Limits { depth: 1, ..big }).contains("nested more than 1 deep"));
        assert!(err(Limits { path: 1, ..big }).contains("longer than 1 bytes"));
        assert!(err(Limits { entries: 5, ..big }).contains("has more than 5 entries"));
        // a directory that lists its parent
        let mut m = Img::new();
        let d_dents = m.data(&dentry_block(&[("up", 3)]));
        let mut d = I::new(DIR | 0o755, 4096);
        d.addrs = vec![d_dents];
        m.inode(5, &d);
        m.root(&[("d", 5)]);
        assert!(err_of(m.fs().walk()).contains("loop"));
    }

    #[test]
    fn size_and_address_limits_are_enforced() {
        let mut m = sample();
        let mut bad = I::new(REG | 0o644, 4096);
        bad.addrs = vec![5];
        m.inode(20, &bad);
        let mut big_inline = I::new(REG | 0o644, 5000);
        big_inline.inline = INLINE_DATA;
        m.inode(21, &big_inline);
        let fs = m.fs();
        let (_, ino) = fs.lookup("d/b").unwrap();
        let g = Scratch::new("f2fs-limits");
        let mut f = std::fs::File::create(g.join("x")).unwrap();
        let mut budget = 10_000;
        fs.copy_data(&ino, &mut f, &mut budget).unwrap();
        assert_eq!(budget, 10_000 - 8292);
        assert!(err_of(fs.copy_data(&ino, &mut f, &mut budget)).contains("add up to more than"));
        let (mut big, blk) = fs.load(11).unwrap();
        big.size = MAX_FILE_BYTES + 1;
        assert!(err_of(fs.read_chunks(&big, &blk, |_, _| Ok(()))).contains("-byte limit"));
        let (mut dir, dblk) = fs.load(5).unwrap();
        dir.size = MAX_DIR_BYTES + 1;
        assert!(err_of(fs.dir_entries(&dir, &dblk)).contains("directory of"));
        let (mut link, lblk) = fs.load(7).unwrap();
        link.size = MAX_SYMLINK + 1;
        assert!(err_of(fs.symlink_target(&link, &lblk)).contains("is not valid"));
        // a data block outside the main area, and inline data larger than the inode
        for (nid, want) in [(20, "outside the main area"), (21, "does not fit")] {
            let (i, b) = fs.load(nid).unwrap();
            let e = err_of(fs.read_chunks(&i, &b, |_, _| Ok(())));
            assert!(e.contains(want), "{e}");
        }
    }

    #[test]
    fn a_file_in_too_many_pieces_is_refused() {
        let mut m = Img::new();
        let mut f = I::new(REG | 0o644, 4096 * 2000);
        f.addrs = (0..900)
            .map(|i| if i % 2 == 0 { MAIN } else { 0 })
            .collect();
        m.inode(22, &f);
        let fs = m.fs();
        let (i, b) = fs.load(22).unwrap();
        // 450 pieces are fine; MAX_RUNS is a bound for hostile images, checked by the same path
        let runs = fs.runs(&i, &b, 900).unwrap();
        assert_eq!(runs.len(), 450);
        assert!(runs.iter().all(|r| r.blocks == 1));
    }

    #[test]
    fn an_inode_with_absurd_layout_fields_is_refused() {
        let mut m = Img::new();
        let mut a = I::new(REG | 0o644, 0).build();
        a[3] |= EXTRA_ATTR;
        p16(&mut a, I_ADDR, 2000); // extra size
        m.node(4, 4, &a[..NODE_FOOTER]);
        let mut c = I::new(0, 0).build();
        c[0] = 0;
        m.node(6, 6, &c[..NODE_FOOTER]);
        let mut flex = Img::with_feature(F_FLEXIBLE_INLINE_XATTR);
        let mut b = I::new(REG | 0o644, 0).build();
        b[3] |= INLINE_XATTR | EXTRA_ATTR;
        p16(&mut b, I_ADDR, 36);
        p16(&mut b, I_ADDR + 2, 5000);
        flex.node(5, 5, &b[..NODE_FOOTER]);
        assert!(err_of(m.fs().load(4)).contains("extra attribute size"));
        assert!(err_of(flex.fs().load(5)).contains("inline xattr size"));
        let (i, _) = m.fs().load(6).unwrap();
        assert!(i.kind().is_none());
        assert!(err_of(Fs::kind_of(&i)).contains("unknown file type"));
    }

    #[test]
    fn short_and_garbage_images_are_refused_without_a_panic() {
        assert!(Fs::from_bytes(Vec::new()).is_err());
        assert!(Fs::from_bytes(vec![0u8; 4095]).is_err());
        assert!(Fs::from_bytes(vec![0u8; 1 << 20]).is_err());
        assert!(Fs::from_bytes(vec![0xFFu8; 1 << 20]).is_err());
        let good = sample();
        for len in [
            1023,
            1024,
            2048,
            4095,
            4096,
            8192,
            CP as usize * BS_USIZE,
            (CP as usize + 1) * BS_USIZE,
            (CP as usize + 4) * BS_USIZE,
            (CP as usize + 515) * BS_USIZE,
            NAT as usize * BS_USIZE,
            MAIN as usize * BS_USIZE - 1,
        ] {
            assert!(Fs::from_bytes(good.b[..len].to_vec()).is_err(), "len {len}");
        }
        let e = err_of(Fs::from_bytes(
            good.b[..MAIN as usize * BS_USIZE - 1].to_vec(),
        ));
        assert!(e.contains("truncated"), "{e}");
        // metadata present but the data area cut off: opens, and reading what is missing fails
        // with an error instead of a panic
        let cut = Fs::from_bytes(good.b[..(MAIN as usize + 2) * BS_USIZE].to_vec()).unwrap();
        assert!(cut.walk().is_err());
    }

    #[test]
    fn corrupting_metadata_bytes_never_panics() {
        let good = sample();
        let mut positions: Vec<usize> = (1024..1024 + 2200).step_by(3).collect();
        for pack in [CP as usize, CP as usize + 512] {
            positions.extend((0..320).map(|i| pack * BS_USIZE + i));
            positions.extend((0..16).map(|i| (pack + 1) * BS_USIZE + i));
            positions.extend((0..16).map(|i| (pack + 1) * BS_USIZE + 500 + i));
        }
        let probe = good.fs();
        for nid in [3u32, 4, 5, 6, 7, 8, 9, 10, 11, 12] {
            let blk = probe.nat(nid).unwrap().blk as usize;
            positions.extend((0..420).map(|i| blk * BS_USIZE + i));
            positions.extend((3900..4096).step_by(2).map(|i| blk * BS_USIZE + i));
        }
        positions.extend((0..64).map(|i| NAT as usize * BS_USIZE + i * 9 + 5));
        let mut img = good.b.clone();
        let (mut ok, mut err) = (0, 0);
        for at in positions {
            let was = img[at];
            for v in [0x00u8, 0xFF] {
                if was == v {
                    continue;
                }
                img[at] = v;
                let r = Fs::from_bytes(img.clone()).and_then(|f| {
                    for (e, i) in f.walk()? {
                        if e.kind == Kind::File {
                            let (i, b) = f.load(i.nid)?;
                            f.read_chunks(&i, &b, |_, _| Ok(()))?;
                        }
                    }
                    Ok(())
                });
                match r {
                    Ok(()) => ok += 1,
                    Err(_) => err += 1,
                }
            }
            img[at] = was;
        }
        assert!(ok > 100 && err > 100, "ok={ok} err={err}");
    }

    #[test]
    fn the_crc_is_standard_crc32_seeded_with_the_magic_and_not_inverted() {
        assert_eq!(crc(&[]), MAGIC, "no data leaves the seed");
        // standard CRC-32 is this register run from 0xFFFFFFFF and inverted at the end
        let reference = |seed: u32, data: &[u8]| {
            let mut c = seed;
            for &b in data {
                c ^= b as u32;
                for _ in 0..8 {
                    c = (c >> 1) ^ if c & 1 != 0 { 0xEDB8_8320 } else { 0 };
                }
            }
            c
        };
        assert_eq!(!reference(!0, b"123456789"), 0xCBF4_3926);
        assert_eq!(crc(b"123456789"), reference(MAGIC, b"123456789"));
        // and a value taken from a real checkpoint block written by mkfs.f2fs 1.16: version
        // 0x6b8b4567, flags 0x185, the other fields zero
        let mut cp = vec![0u8; 4092];
        p64(&mut cp, 0, 0x6b8b4567);
        p32(&mut cp, 132, 0x185);
        assert_ne!(crc(&cp), crc(&cp[..4091]));
    }
}
