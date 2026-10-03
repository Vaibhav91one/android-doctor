//! Spreadtrum/MediaTek `.pac` container.
//! Format adapted from the SR Labs PacHandler
//! (<https://github.com/srlabs/extractor>, Apache-2.0), which is cited in
//! THIRD_PARTY.md.
//!
//! A `.pac` file is a flat binary container.  After a 60-byte header the file table begins
//! at offset 60 and each entry is 2580 bytes apart.  Within one entry:
//!
//! | offset  | size  | meaning                        |
//! |---------|-------|--------------------------------|
//! | 0x00    | 64 B  | file name, UTF-16LE (NUL-pad)  |
//! | 0x400   | 4 B   | data length, `u32` little-endian |
//! | 0x40C   | 4 B   | data offset, `u32` little-endian |
//!
//! Entries whose data offset is 0 are empty (end-of-table).  All other entries are
//! extracted verbatim; the SR Labs handler only keeps system.img / boot.img / recovery.img,
//! but we extract every declared file.
use crate::extract::{ExtractOptions, create_part};
use anyhow::{Context, Result, bail};
use std::fs::File;
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

// ── Format constants (SR Labs PacHandler, Apache-2.0) ──────────────────────────

/// Stride between the start of one file-table entry and the next.
pub(crate) const ENTRY_SIZE: usize = 2580;
/// First byte offset of the file table (equal to `HEADER_LEN`).
pub(crate) const TABLE_START: usize = 60;
/// Last+1 byte offset the SR Labs handler scans while building its table.
const TABLE_END: usize = 69721;
/// File name field inside an entry: first 64 bytes at offset 0, UTF-16LE.
const NAME_LEN: usize = 0x40;
/// Offset of the 4-byte LE data-length field within an entry.
const LEN_AT: usize = 0x400;
/// Offset of the 4-byte LE data-offset field within an entry.
const START_AT: usize = 0x40C;

/// Largest single file we are willing to extract (1 GiB).
const MAX_FILE_BYTES: u64 = 1 << 30;
/// Largest output path for a single file name.
const MAX_NAME_CHARS: usize = 256;

// ── Public API ─────────────────────────────────────────────────────────────────

/// A single file entry parsed from the PAC file table.
pub struct Entry {
    /// File name without any path component.
    pub name: String,
    /// Offset of the file data within the `.pac` file (relative to byte 0).
    pub offset: u64,
    /// Length of the file data in bytes.
    pub length: u64,
}

/// Return true when `path` looks like a PAC file (by extension and a quick structural
/// probe: a 64-byte region with at least one non-zero byte where the name field should be).
/// This mirrors the SR Labs PacHandler, which identifies `.pac` files by extension.
/// No real firmware is read here — the check is purely structural and safe for any input.
pub fn is_pac(input: &Path) -> bool {
    let Some(ext) = input.extension().and_then(|e| e.to_str()) else {
        return false;
    };
    if !ext.eq_ignore_ascii_case("pac") {
        return false;
    }
    // A real PAC has a file-table entry at offset 60 with a non-empty name.
    // Reading 64 bytes is cheap and rules out most non-PAC files.
    let Ok(mut f) = File::open(input) else {
        return false;
    };
    let mut name_bytes = [0u8; NAME_LEN];
    if f.seek(SeekFrom::Start(TABLE_START as u64)).is_err() {
        return false;
    }
    if f.read_exact(&mut name_bytes).is_err() {
        return false;
    }
    // At least one byte must be non-zero (a name is stored as UTF-16LE).
    name_bytes.iter().any(|&b| b != 0)
}

// — Internal helpers —

/// Decode the UTF-16LE name from a 64-byte field, stripping NUL bytes.
/// The name is stored NUL-padded, so we cut at the first NUL pair.
fn decode_name(field: &[u8]) -> Result<String> {
    let units = field.len() / 2;
    let u16s: Vec<u16> = (0..units)
        .map(|i| u16::from_le_bytes([field[i * 2], field[i * 2 + 1]]))
        .collect();
    let cut = u16s.iter().position(|&u| u == 0).unwrap_or(u16s.len());
    String::from_utf16(&u16s[..cut]).with_context(|| "invalid UTF-16 in PAC entry name")
}

/// Validate that a name is safe for writing to disk (no path separators, no `..`, etc.).
fn is_safe_name(name: &str) -> bool {
    !name.is_empty()
        && !name.contains('/')
        && !name.contains('\\')
        && !name.contains("..")
        && name.chars().all(|c| !c.is_control() && c != ':')
}

/// Read the file table from `input`.
/// Returns the list of entries with their data offset and length.
/// Only entries with a non-zero data offset and that fit within the file are returned.
/// Adapted from the SR Labs PacHandler loop: for pos in range(60, 69721, 2580).
fn read_table(input: &Path) -> Result<Vec<Entry>> {
    let mut f = File::open(input).with_context(|| format!("opening {}", input.display()))?;
    let file_size = f.metadata()?.len();
    let mut entries = Vec::new();
    let mut need = vec![0u8; ENTRY_SIZE];
    // Iterate entries at the fixed cadence used by the SR Labs PacHandler.
    let mut pos = TABLE_START;
    while pos + ENTRY_SIZE <= TABLE_END {
        if pos as u64 + ENTRY_SIZE as u64 > file_size {
            break;
        }
        f.seek(SeekFrom::Start(pos as u64))?;
        f.read_exact(&mut need)?;
        let length = u32::from_le_bytes(need[LEN_AT..LEN_AT + 4].try_into().unwrap()) as u64;
        let start_pos = u32::from_le_bytes(need[START_AT..START_AT + 4].try_into().unwrap()) as u64;
        // start_pos == 0 marks an unused / end-of-table entry (SR Labs convention).
        if start_pos == 0 {
            pos += ENTRY_SIZE;
            continue;
        }
        // Skip entries that point past EOF.
        if start_pos
            .checked_add(length)
            .is_some_and(|end| end > file_size)
        {
            pos += ENTRY_SIZE;
            continue;
        }
        if length > MAX_FILE_BYTES {
            bail!(
                "PAC entry claims {} bytes for {}, exceeds the {} byte limit",
                length,
                input.display(),
                MAX_FILE_BYTES
            );
        }
        let name = decode_name(&need[..NAME_LEN])?;
        if !is_safe_name(&name) {
            bail!("unsafe PAC file name {name:?}");
        }
        if name.len() > MAX_NAME_CHARS {
            bail!("PAC file name is too long ({name})");
        }
        entries.push(Entry {
            name: name.clone(),
            offset: start_pos,
            length,
        });
        pos += ENTRY_SIZE;
    }
    Ok(entries)
}

/// What `extract` would write from a PAC file, with sizes in bytes.
/// Returns the filtered, sorted list of (name, size).  Applies `--only`.
pub fn list(input: &Path, opts: &ExtractOptions) -> Result<Vec<(String, u64)>> {
    let entries = read_table(input)?;
    let only = opts.only.as_ref();
    let mut out: Vec<(String, u64)> = entries
        .into_iter()
        .filter(|e| only.is_none_or(|o| o.iter().any(|name| name == &e.name)))
        .map(|e| (e.name, e.length))
        .collect();
    out.sort_unstable_by(|a, b| a.0.cmp(&b.0));
    Ok(out)
}

/// Extract every file declared in the PAC table into `out_dir`.
/// Returns the paths of the extracted files, sorted by name.
/// Files are written under a `.part` temporary name and renamed on success,
/// so a failed run never leaves a plausible-looking partial file.
pub fn extract(input: &Path, out_dir: &Path, opts: &ExtractOptions) -> Result<Vec<PathBuf>> {
    let entries = read_table(input)?;
    let only = opts.only.as_ref();
    std::fs::create_dir_all(out_dir)?;
    // Refuse to overwrite unless --force (same rule as block OTAs).
    if !opts.force {
        for e in &entries {
            if only.is_some_and(|o| !o.iter().any(|n| n == &e.name)) {
                continue;
            }
            if out_dir.join(&e.name).symlink_metadata().is_ok() {
                bail!(
                    "{} already exists in {}; pass --force to overwrite",
                    e.name,
                    out_dir.display()
                );
            }
        }
    }
    let mut paths = Vec::new();
    let mut file = File::open(input).with_context(|| format!("opening {}", input.display()))?;
    for entry in &entries {
        if only.is_some_and(|o| !o.iter().any(|n| n == &entry.name)) {
            continue;
        }
        let final_path = out_dir.join(&entry.name);
        let tmp_path = out_dir.join(format!("{}.part", entry.name));
        let copy = (|| -> Result<()> {
            let mut out = create_part(&tmp_path)?;
            file.seek(SeekFrom::Start(entry.offset))?;
            let remaining = entry.length as usize;
            let mut buf = vec![0u8; 64 * 1024];
            let mut left = remaining;
            while left > 0 {
                let n = left.min(buf.len());
                file.read_exact(&mut buf[..n])?;
                out.write_all(&buf[..n])?;
                left -= n;
            }
            Ok(())
        })();
        if let Err(e) = copy {
            let _ = std::fs::remove_file(&tmp_path);
            return Err(e.context(format!("extracting {}", entry.name)));
        }
        std::fs::rename(&tmp_path, &final_path)?;
        paths.push(final_path);
    }
    paths.sort_unstable();
    Ok(paths)
}

// — Test helpers (shared with other test modules, e.g. detect.rs) —

#[cfg(test)]
pub(crate) fn make_entry(name: &str, data_offset: u64, data_len: u64) -> Vec<u8> {
    let mut entry = vec![0u8; ENTRY_SIZE];
    // Encode the name as UTF-16LE code units, each taking 2 bytes LE.
    for (i, c) in name.chars().enumerate() {
        let u = c as u16;
        let idx = i * 2;
        if idx + 1 >= NAME_LEN {
            break;
        }
        entry[idx] = (u & 0xff) as u8;
        entry[idx + 1] = (u >> 8) as u8;
    }
    entry[LEN_AT..LEN_AT + 4].copy_from_slice(&(data_len as u32).to_le_bytes());
    entry[START_AT..START_AT + 4].copy_from_slice(&(data_offset as u32).to_le_bytes());
    entry
}

#[cfg(test)]
pub(crate) fn build_pac_for_test(path: &Path) -> PathBuf {
    build_pac(path, &[("system".to_string(), vec![0xAA; 16])]);
    path.to_path_buf()
}

#[cfg(test)]
fn build_pac(path: &Path, files: &[(String, Vec<u8>)]) {
    let n = files.len();
    // Data region starts right after the last table slot we use.
    let table_end = TABLE_START + n * ENTRY_SIZE;
    let data_start = table_end as u64;
    let mut f = std::fs::File::create(path).unwrap();
    // Header: 60 zero bytes.
    f.write_all(&[0u8; TABLE_START]).unwrap();
    let mut data_offset = data_start;
    for (name, data) in files {
        let entry = make_entry(name, data_offset, data.len() as u64);
        f.write_all(&entry).unwrap();
        data_offset += data.len() as u64;
    }
    // Write the actual file data at the end.
    for (_, data) in files {
        f.write_all(data).unwrap();
    }
    f.flush().unwrap();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decode_name_strips_nul_padding() {
        let mut field = vec![0u8; NAME_LEN];
        // "hi" as UTF-16LE
        field[0] = b'h';
        field[2] = b'i';
        let result = decode_name(&field).unwrap();
        assert_eq!(result, "hi");
    }

    #[test]
    fn build_pac_for_test_creates_valid_pac() {
        use crate::testutil::Scratch;
        let dir = Scratch::new(&format!("pac-test-{}", std::process::id()));
        let path = dir.join("test.pac");
        let returned = build_pac_for_test(&path);
        assert_eq!(returned, path);
        assert!(path.exists());
        // The file should be identified as pac
        assert!(is_pac(&path));
    }
}
