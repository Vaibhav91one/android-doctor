//! Android Logical Partition (super.img) parsing and image splitting.
//!
//! Implements the AOSP `LpMetadataGeometry`, `LpMetadataHeader` and the four
//! partition/extent/group/block-device tables from
//! `system/core/fs_mgr/liblp/include/liblp/metadata_format.h` (Apache-2.0),
//! validated against the SR Labs extractor `liblp.py` (Apache-2.0).
//! All fields are little-endian; a sector is 512 bytes.
use anyhow::{Context, Result, ensure};
use sha2::{Digest, Sha256};

/// Offset of the primary LP geometry within the image (`LP_PARTITION_RESERVED_BYTES`).
const GEOMETRY_OFFSET: u64 = 4096;
/// The block each geometry copy occupies (`LP_METADATA_GEOMETRY_SIZE`); the struct inside it is
/// only `struct_size` bytes and the rest is zero padding.
const GEOMETRY_BLOCK: usize = 4096;
/// `sizeof(LpMetadataGeometry)` in AOSP: magic, struct_size, checksum[32] and three u32 = 52.
const GEOMETRY_STRUCT_SIZE: usize = 52;
/// Where slot 0's primary metadata starts: the reserved 4096 bytes, then the primary and backup
/// geometry blocks (`GetPrimaryMetadataOffset`).
const METADATA_OFFSET: u64 = GEOMETRY_OFFSET + 2 * GEOMETRY_BLOCK as u64;
/// `LpMetadataHeader` magic: "Lp0" reversed.
const LP_HEADER_MAGIC: u32 = 0x414C5030;
/// `LpMetadataGeometry` magic: "gDla".
const LP_GEOMETRY_MAGIC: u32 = 0x616C4467;
/// LP geometry magic as bytes "gDla" at offset 4096.
const LP_GEOMETRY_MAGIC_BYTES: [u8; 4] = *b"gDla";
/// Sector size in bytes.
pub const SECTOR_SIZE: u64 = 512;
/// Maximum entries per table to stop a hostile header from exhausting memory.
const MAX_ENTRIES: usize = 4096;
/// Maximum total partition image bytes.
pub const MAX_IMAGE_BYTES: u64 = 1u64 << 40;

fn le16(b: &[u8], at: usize) -> u16 {
    u16::from_le_bytes([b[at], b[at + 1]])
}

fn le32(b: &[u8], at: usize) -> u32 {
    u32::from_le_bytes([b[at], b[at + 1], b[at + 2], b[at + 3]])
}

fn le64(b: &[u8], at: usize) -> u64 {
    u64::from_le_bytes([
        b[at],
        b[at + 1],
        b[at + 2],
        b[at + 3],
        b[at + 4],
        b[at + 5],
        b[at + 6],
        b[at + 7],
    ])
}

/// A parsed SHA-256 digest stored as raw 32 bytes.
type Sha256Arr = [u8; 32];

/// `LpMetadataGeometry` (AOSP, Apache-2.0): a 52-byte packed struct.
#[allow(dead_code)]
struct Geometry {
    magic: u32,
    struct_size: u32,
    checksum: Sha256Arr,
    metadata_max_size: u32,
    metadata_slot_count: u32,
    logical_block_size: u32,
}

fn parse_geometry(b: &[u8]) -> Result<Geometry> {
    ensure!(!b.is_empty(), "super image is empty");
    ensure!(
        b.len() >= GEOMETRY_STRUCT_SIZE,
        "super image is too short for an LP geometry (need {GEOMETRY_STRUCT_SIZE} bytes, got {})",
        b.len()
    );
    let g = Geometry {
        magic: le32(b, 0),
        struct_size: le32(b, 4),
        checksum: read_sha256(b, 8),
        metadata_max_size: le32(b, 40),
        metadata_slot_count: le32(b, 44),
        logical_block_size: le32(b, 48),
    };
    ensure!(
        g.magic == LP_GEOMETRY_MAGIC,
        "super image: bad LP geometry magic {:#010x}",
        g.magic
    );
    ensure!(
        (GEOMETRY_STRUCT_SIZE..=GEOMETRY_BLOCK).contains(&(g.struct_size as usize)),
        "LP geometry struct_size {} is outside {GEOMETRY_STRUCT_SIZE}..={GEOMETRY_BLOCK}",
        g.struct_size
    );
    ensure!(
        g.logical_block_size != 0 && g.logical_block_size.is_multiple_of(512),
        "LP geometry: invalid logical block size {}",
        g.logical_block_size
    );
    Ok(g)
}

/// Verify the geometry checksum: SHA-256 of the first `struct_size` bytes with the checksum
/// field zeroed (the zero padding after the struct is not covered).
fn verify_geometry_checksum(g: &Geometry, b: &[u8]) -> Result<()> {
    ensure!(
        b.len() >= g.struct_size as usize,
        "LP geometry: struct_size {} runs past the image",
        g.struct_size
    );
    let mut copy = b[..g.struct_size as usize].to_vec();
    let start = 8;
    let end = start + 32;
    for byte in &mut copy[start..end] {
        *byte = 0;
    }
    let mut h = Sha256::new();
    h.update(&copy);
    let actual = h.finalize();
    ensure!(
        &g.checksum[..] == actual.as_slice(),
        "LP geometry: checksum mismatch"
    );
    Ok(())
}

/// Verify the metadata header checksum: SHA-256 of the header bytes, with the
/// header_checksum field itself zeroed, over the full header_size. AOSP verifies
/// the header region (8..header_size) with the checksum field zeroed.
fn verify_header_checksum(h: &MetadataHeader, hdr_bytes: &[u8]) -> Result<()> {
    ensure!(
        hdr_bytes.len() >= h.header_size as usize,
        "LP metadata: not enough bytes for header_size {} (got {})",
        h.header_size,
        hdr_bytes.len()
    );
    let mut copy = hdr_bytes[..h.header_size as usize].to_vec();
    // Zero the header_checksum field (at offset 12, 32 bytes) before hashing.
    for byte in &mut copy[12..44] {
        *byte = 0;
    }
    let mut hash = Sha256::new();
    hash.update(&copy);
    let actual = hash.finalize();
    ensure!(
        &h.header_checksum[..] == actual.as_slice(),
        "LP metadata: header checksum mismatch"
    );
    Ok(())
}

/// Verify the tables checksum: SHA-256 of the tables region (header_size..header_size+tables_size).
fn verify_tables_checksum(h: &MetadataHeader, tables_bytes: &[u8]) -> Result<()> {
    ensure!(
        tables_bytes.len() == h.tables_size as usize,
        "LP metadata: tables region is {} bytes but header says {}",
        tables_bytes.len(),
        h.tables_size
    );
    let mut hash = Sha256::new();
    hash.update(tables_bytes);
    let actual = hash.finalize();
    ensure!(
        &h.tables_checksum[..] == actual.as_slice(),
        "LP metadata: tables checksum mismatch"
    );
    Ok(())
}
fn read_sha256(b: &[u8], at: usize) -> [u8; 32] {
    let mut s = [0u8; 32];
    s.copy_from_slice(&b[at..at + 32]);
    s
}

/// One of the four table descriptors at the end of `LpMetadataHeader`.
struct TableDescriptor {
    offset: u32,
    num_entries: u32,
    entry_size: u32,
}

#[allow(dead_code)]
fn parse_table(b: &[u8], at: usize) -> TableDescriptor {
    TableDescriptor {
        offset: le32(b, at),
        num_entries: le32(b, at + 4),
        entry_size: le32(b, at + 8),
    }
}

/// `LpMetadataHeader` (AOSP, Apache-2.0): magic at 0, major u16, minor u16,
/// header_size u32, header_checksum sha256[32], tables_size u32,
/// tables_checksum sha256[32], then four 12-byte table descriptors at 80, 92, 104 and 116.
#[allow(dead_code)]
struct MetadataHeader {
    magic: u32,
    major: u16,
    minor: u16,
    header_size: u32,
    header_checksum: Sha256Arr,
    tables_size: u32,
    tables_checksum: Sha256Arr,
    partitions: TableDescriptor,
    extents: TableDescriptor,
    groups: TableDescriptor,
    block_devices: TableDescriptor,
}

/// Fixed header fields before the four table descriptors: 4 + 2 + 2 + 4 + 32 + 4 + 32 = 80.
const HEADER_FIXED_SIZE: usize = 80;
const HEADER_SIZE_MIN: usize = HEADER_FIXED_SIZE + 4 * 12;

#[allow(dead_code)]
fn parse_metadata_header(b: &[u8]) -> Result<MetadataHeader> {
    ensure!(
        b.len() >= HEADER_SIZE_MIN,
        "LP metadata header is too short (need {HEADER_SIZE_MIN} bytes, got {})",
        b.len()
    );
    let magic = le32(b, 0);
    ensure!(
        magic == LP_HEADER_MAGIC,
        "LP metadata: bad header magic {:#010x}",
        magic
    );
    let header = MetadataHeader {
        magic,
        major: le16(b, 4),
        minor: le16(b, 6),
        header_size: le32(b, 8),
        header_checksum: read_sha256(b, 12),
        tables_size: le32(b, 44),
        tables_checksum: read_sha256(b, 48),
        partitions: parse_table(b, 80),
        extents: parse_table(b, 92),
        groups: parse_table(b, 104),
        block_devices: parse_table(b, 116),
    };
    ensure!(
        header.header_size as usize >= HEADER_SIZE_MIN,
        "LP metadata header_size {} is too small",
        header.header_size
    );
    ensure!(
        header.major >= 1,
        "LP metadata: unsupported major version {}",
        header.major
    );
    Ok(header)
}

/// Slot-suffixed attribute flag bit.
#[allow(dead_code)]
const PARTITION_ATTR_SLOT_SUFFIXED: u32 = 0x1;
/// LP extent types.
const EXTENT_LINEAR: u32 = 0;
const EXTENT_ZERO: u32 = 1;

/// `LpMetadataPartition` (AOSP, Apache-2.0): name[36], attributes u32,
/// first_extent_index u32, num_extents u32, group_index u32. Total = 52 bytes.
const PARTITION_SIZE: usize = 52;

#[derive(Clone)]
#[allow(dead_code)]
struct Partition {
    name: String,
    attributes: u32,
    first_extent_index: u32,
    num_extents: u32,
    group_index: u32,
}

fn parse_partition(b: &[u8]) -> Result<Partition> {
    ensure!(b.len() >= PARTITION_SIZE, "partition entry is too short");
    let name = read_name(&b[0..36])?;
    Ok(Partition {
        name,
        attributes: le32(b, 36),
        first_extent_index: le32(b, 40),
        num_extents: le32(b, 44),
        group_index: le32(b, 48),
    })
}

/// `LpMetadataExtent` (AOSP, Apache-2.0): num_sectors u64, target_type u32,
/// target_data u64, target_source u32. Packed, total = 24 bytes.
const EXTENT_SIZE: usize = 24;

#[derive(Clone, Copy)]
pub struct Extent {
    #[allow(dead_code)]
    /// Number of 512-byte sectors this extent covers.
    pub num_sectors: u64,
    /// Extent target type: 0 = linear (mapped), 1 = zero (unmapped).
    pub target_type: u32,
    /// For linear extents: the physical sector number in the image.
    pub target_data: u64,
    /// For linear extents: the source block device index.
    #[allow(dead_code)]
    pub target_source: u32,
}

fn parse_extent(b: &[u8]) -> Result<Extent> {
    ensure!(b.len() >= EXTENT_SIZE, "extent entry is too short");
    Ok(Extent {
        num_sectors: le64(b, 0),
        target_type: le32(b, 8),
        target_data: le64(b, 12),
        target_source: le32(b, 20),
    })
}

/// `LpMetadataPartitionGroup` (AOSP, Apache-2.0): name[36], flags u32,
/// maximum_size u64. Total = 48 bytes.
const GROUP_SIZE: usize = 48;

#[derive(Clone)]
#[allow(dead_code)]
struct Group {
    name: String,
    flags: u32,
    maximum_size: u64,
}

fn parse_group(b: &[u8]) -> Result<Group> {
    ensure!(b.len() >= GROUP_SIZE, "group entry is too short");
    let name = read_name(&b[0..36])?;
    Ok(Group {
        name,
        flags: le32(b, 36),
        maximum_size: le64(b, 40),
    })
}

/// `LpMetadataBlockDevice` (AOSP, Apache-2.0): first_logical_sector u64, alignment u32,
/// alignment_offset u32, size u64, partition_name[36], flags u32. Packed, total = 64 bytes.
const BLOCK_DEVICE_SIZE: usize = 64;

#[derive(Clone)]
#[allow(dead_code)]
struct BlockDevice {
    first_logical_sector: u64,
    partition_name: String,
    flags: u32,
    size: u64,
}

fn parse_block_device(b: &[u8]) -> Result<BlockDevice> {
    ensure!(
        b.len() >= BLOCK_DEVICE_SIZE,
        "block_device entry is too short"
    );
    let partition_name = read_name(&b[24..60])?;
    Ok(BlockDevice {
        first_logical_sector: le64(b, 0),
        partition_name,
        flags: le32(b, 60),
        size: le64(b, 16),
    })
}

/// Read a null-terminated name from a fixed-size byte slice.
fn read_name(b: &[u8]) -> Result<String> {
    let nul = b.iter().position(|&c| c == 0).unwrap_or(b.len());
    let name = &b[..nul];
    String::from_utf8(name.to_vec()).with_context(|| "LP name is not valid UTF-8")
}

type Tables = (Vec<Partition>, Vec<Extent>, Vec<Group>, Vec<BlockDevice>);
fn parse_tables(tables: &[u8], h: &MetadataHeader) -> Result<Tables> {
    let parts = parse_entries::<Partition>(tables, &h.partitions, PARTITION_SIZE, parse_partition)?;
    let extents = parse_entries::<Extent>(tables, &h.extents, EXTENT_SIZE, parse_extent)?;
    let groups = parse_entries::<Group>(tables, &h.groups, GROUP_SIZE, parse_group)?;
    let bdevs = parse_entries::<BlockDevice>(
        tables,
        &h.block_devices,
        BLOCK_DEVICE_SIZE,
        parse_block_device,
    )?;
    Ok((parts, extents, groups, bdevs))
}

fn parse_entries<T>(
    tables: &[u8],
    td: &TableDescriptor,
    entry_size: usize,
    parse_one: fn(&[u8]) -> Result<T>,
) -> Result<Vec<T>> {
    // A newer writer may append fields to an entry: read the ones we know and step by the size
    // the table declares.
    let stride = td.entry_size as usize;
    ensure!(
        stride >= entry_size,
        "LP entry size {stride} is smaller than the {entry_size} bytes this table needs"
    );
    ensure!(
        td.num_entries <= MAX_ENTRIES as u32,
        "LP table claims too many entries: {n}",
        n = td.num_entries
    );
    let start = td.offset as usize;
    let end = (td.num_entries as usize)
        .checked_mul(stride)
        .and_then(|total| start.checked_add(total))
        .context("LP table size overflows")?;
    ensure!(tables.len() >= end, "LP table truncated");
    let mut out = Vec::with_capacity(td.num_entries as usize);
    for k in 0..td.num_entries as usize {
        let at = start + k * stride;
        out.push(parse_one(&tables[at..at + stride])?);
    }
    Ok(out)
}

/// A partition joined with its extents, for splitting a super image.
pub struct ParsedPart {
    name: String,
    extents: Vec<Extent>,
    _group: String,
}

/// Parse super image bytes into partitions with their extents.
/// Validates geometry + header + table checksums (AOSP, Apache-2.0).
pub fn parse_metadata(image: &[u8]) -> Result<Vec<ParsedPart>> {
    ensure!(!image.is_empty(), "super image is empty");
    let gstart = GEOMETRY_OFFSET as usize;
    let block = image
        .get(gstart..)
        .context("super image too short for geometry")?;
    let block = &block[..block.len().min(GEOMETRY_BLOCK)];
    let g = parse_geometry(block)?;
    verify_geometry_checksum(&g, block)?;
    let hdr_off = METADATA_OFFSET;
    let header_bytes = image
        .get(hdr_off as usize..)
        .context("no LP metadata header region")?;
    let h = parse_metadata_header(header_bytes)?;
    verify_header_checksum(&h, header_bytes)?;
    let tables_start = hdr_off as usize + h.header_size as usize;
    let tables = image
        .get(tables_start..tables_start + h.tables_size as usize)
        .context("LP tables region is truncated")?;
    verify_tables_checksum(&h, tables)?;
    let (parts, extents, _groups, _bdevs) = parse_tables(tables, &h)?;
    let mut out = Vec::new();
    for p in parts {
        let start = p.first_extent_index as usize;
        let end = start + p.num_extents as usize;
        let pext = extents
            .get(start..end)
            .context("partition extents out of range")?
            .to_vec();
        out.push(ParsedPart {
            name: p.name,
            extents: pext,
            _group: String::new(),
        });
    }
    Ok(out)
}

/// Split parsed super partitions into per-partition images; linear extents copy
/// from `image`, zero extents emit zeroes. `only` filters by partition name.
pub fn split_partitions(
    image: &[u8],
    parsed: &[ParsedPart],
    only: Option<&[String]>,
) -> Result<Vec<(String, Vec<u8>)>> {
    let mut out = Vec::new();
    'p: for part in parsed {
        if let Some(only) = only {
            let found = only.iter().any(|o| o == &part.name);
            if !found {
                continue 'p;
            }
        }
        let total: u64 = part
            .extents
            .iter()
            .map(|e| e.num_sectors * SECTOR_SIZE)
            .sum();
        ensure!(
            total <= MAX_IMAGE_BYTES,
            "partition {} is too large",
            part.name
        );
        let mut buf = Vec::with_capacity(total as usize);
        for e in &part.extents {
            ensure!(
                e.target_type == EXTENT_LINEAR || e.target_type == EXTENT_ZERO,
                "partition {}: unsupported extent type {}",
                part.name,
                e.target_type
            );
            let len = (e.num_sectors * SECTOR_SIZE) as usize;
            if e.target_type == EXTENT_ZERO {
                buf.extend(std::iter::repeat_n(0u8, len));
            } else {
                let start = (e.target_data * SECTOR_SIZE) as usize;
                let end = start + len;
                let chunk = image
                    .get(start..end)
                    .context("LP extent runs past end of super image")?;
                buf.extend_from_slice(chunk);
            }
        }
        out.push((part.name.clone(), buf));
    }
    Ok(out)
}

/// True if the file's bytes carry the LP geometry magic at offset 4096.
#[allow(dead_code)]
pub fn is_super(path: &std::path::Path) -> Result<bool> {
    let mut file = std::fs::File::open(path)?;
    use std::io::{Read, Seek, SeekFrom};
    file.seek(SeekFrom::Start(4096))?;
    let mut magic = [0u8; 4];
    let n = file.read(&mut magic)?;
    Ok(n == 4 && magic == LP_GEOMETRY_MAGIC_BYTES)
}
#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::testutil::Scratch;

    #[test]
    fn is_super_detects_magic() {
        let mut img = vec![0u8; 8200];
        img[4096..4100].copy_from_slice(b"gDla");
        let d = Scratch::new("lp-super");
        let p = d.join("super.img");
        std::fs::write(&p, &img).unwrap();
        assert!(is_super(&p).unwrap());
    }

    fn sha(b: &[u8]) -> [u8; 32] {
        let mut out = [0u8; 32];
        out.copy_from_slice(&Sha256::digest(b));
        out
    }

    fn put_name(v: &mut Vec<u8>, name: &str) {
        let mut field = [0u8; 36];
        field[..name.len()].copy_from_slice(name.as_bytes());
        v.extend_from_slice(&field);
    }

    /// A super image laid out the way AOSP liblp writes it (`metadata_format.h`): 4096 reserved
    /// bytes, the primary geometry at 4096 and its backup at 8192 (each a 4096-byte block holding
    /// a 52-byte packed struct), the primary metadata slot at 12288, partition data after that.
    /// Each partition is `(name, bytes)`, stored back to back from sector 64.
    pub(crate) fn lp_image(parts: &[(&str, &[u8])]) -> Vec<u8> {
        const FIRST_DATA_SECTOR: u64 = 64;
        let n = parts.len();
        let (mut partitions, mut extents) = (Vec::new(), Vec::new());
        let mut data = Vec::new();
        for (i, (name, body)) in parts.iter().enumerate() {
            put_name(&mut partitions, name);
            for field in [0u32, i as u32, 1, 0] {
                partitions.extend_from_slice(&field.to_le_bytes());
            }
            let sectors = body.len().div_ceil(512) as u64;
            extents.extend_from_slice(&sectors.to_le_bytes());
            extents.extend_from_slice(&0u32.to_le_bytes()); // linear
            let at = FIRST_DATA_SECTOR + (data.len() / 512) as u64;
            extents.extend_from_slice(&at.to_le_bytes());
            extents.extend_from_slice(&0u32.to_le_bytes()); // block device 0
            data.extend_from_slice(body);
            data.resize(data.len().div_ceil(512) * 512, 0);
        }
        let mut groups = Vec::new();
        put_name(&mut groups, "default");
        groups.extend_from_slice(&0u32.to_le_bytes());
        groups.extend_from_slice(&0u64.to_le_bytes());
        let mut devices = Vec::new();
        devices.extend_from_slice(&FIRST_DATA_SECTOR.to_le_bytes()); // first_logical_sector
        devices.extend_from_slice(&1u32.to_le_bytes()); // alignment
        devices.extend_from_slice(&0u32.to_le_bytes()); // alignment_offset
        devices.extend_from_slice(&((data.len() as u64) + 65536).to_le_bytes()); // size
        put_name(&mut devices, "super");
        devices.extend_from_slice(&0u32.to_le_bytes()); // flags
        assert_eq!((partitions.len(), extents.len()), (n * 52, n * 24));
        assert_eq!((groups.len(), devices.len()), (48, 64));

        let mut tables = Vec::new();
        let mut descriptors = Vec::new();
        for (blob, count, size) in [
            (&partitions, n, 52u32),
            (&extents, n, 24),
            (&groups, 1, 48),
            (&devices, 1, 64),
        ] {
            descriptors.extend_from_slice(&(tables.len() as u32).to_le_bytes());
            descriptors.extend_from_slice(&(count as u32).to_le_bytes());
            descriptors.extend_from_slice(&size.to_le_bytes());
            tables.extend_from_slice(blob);
        }
        let mut header = Vec::new();
        header.extend_from_slice(&0x414C_5030u32.to_le_bytes());
        header.extend_from_slice(&10u16.to_le_bytes());
        header.extend_from_slice(&0u16.to_le_bytes());
        header.extend_from_slice(&128u32.to_le_bytes()); // header_size
        header.extend_from_slice(&[0u8; 32]); // header_checksum, filled below
        header.extend_from_slice(&(tables.len() as u32).to_le_bytes());
        header.extend_from_slice(&sha(&tables));
        header.extend_from_slice(&descriptors);
        header.resize(128, 0); // flags + reserved
        let checksum = sha(&header);
        header[12..44].copy_from_slice(&checksum);

        let mut geometry = Vec::new();
        geometry.extend_from_slice(&0x616C_4467u32.to_le_bytes());
        geometry.extend_from_slice(&52u32.to_le_bytes()); // struct_size
        geometry.extend_from_slice(&[0u8; 32]);
        geometry.extend_from_slice(&4096u32.to_le_bytes()); // metadata_max_size
        geometry.extend_from_slice(&1u32.to_le_bytes()); // metadata_slot_count
        geometry.extend_from_slice(&4096u32.to_le_bytes()); // logical_block_size
        assert_eq!(geometry.len(), 52);
        let checksum = sha(&geometry);
        geometry[8..40].copy_from_slice(&checksum);

        let mut img = vec![0u8; (FIRST_DATA_SECTOR as usize) * 512];
        for at in [4096usize, 8192] {
            img[at..at + 52].copy_from_slice(&geometry);
        }
        img[12288..12288 + header.len()].copy_from_slice(&header);
        let t = 12288 + header.len();
        img[t..t + tables.len()].copy_from_slice(&tables);
        img.extend_from_slice(&data);
        img
    }

    /// Issue #118: every real super image was refused with "LP geometry struct_size 52 is too
    /// small", because the parser assumed a 64-byte geometry and, past that check, the wrong
    /// metadata offset, table-descriptor offsets and extent / block-device entry sizes.
    #[test]
    fn a_super_image_laid_out_like_aosp_writes_it_is_parsed_and_split() {
        let system = vec![0xA5u8; 1000];
        let vendor = (0..2048u32).map(|i| i as u8).collect::<Vec<u8>>();
        let img = lp_image(&[("system_a", &system), ("vendor_a", &vendor)]);
        let parts = parse_metadata(&img).unwrap();
        let names: Vec<_> = parts.iter().map(|p| p.name.as_str()).collect();
        assert_eq!(names, ["system_a", "vendor_a"]);
        let out = split_partitions(&img, &parts, None).unwrap();
        assert_eq!(&out[0].1[..1000], &system[..]);
        assert!(
            out[0].1[1000..].iter().all(|&b| b == 0),
            "padded to a sector"
        );
        assert_eq!(out[1].1, vendor);
    }

    #[test]
    fn a_corrupted_geometry_checksum_is_still_refused() {
        let mut img = lp_image(&[("system_a", &[1u8; 512])]);
        img[4096 + 40] ^= 1; // metadata_max_size, covered by the checksum
        let e = parse_metadata(&img).err().expect("refused").to_string();
        assert!(e.contains("checksum"), "{e}");
    }

    #[test]
    fn is_super_rejects_plain_bytes() {
        let d = Scratch::new("lp-nosuper");
        let p = d.join("not.img");
        std::fs::write(&p, [0u8; 8200]).unwrap();
        assert!(!is_super(&p).unwrap());
    }
}
