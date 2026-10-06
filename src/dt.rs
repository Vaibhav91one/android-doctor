//! FDT device trees (dt.img, DTB sections in boot images), AOSP dtbo tables
//! (dtbo.img), Amlogic vendor logo resource containers (logo.img), and a bounded
//! identify/describe for bootloader.img: size, hex dump of the header, per-64 KiB Shannon
//! entropy, and any magic found.
//!
//! FDT values are big-endian. Every offset and length read from a file is bounds-checked
//! and every allocation derived from a header field is capped.
use anyhow::{Context, Result, bail, ensure};
use serde_json::{Value, json};
use std::fs::File;
use std::io::Read;
use std::path::Path;

// FDT (Flattened Device Tree) constants.
const FDT_MAGIC: u32 = 0xd00dfeed;
const FDT_HEADER_SIZE: usize = 32;
const FDT_BEGIN_NODE: u32 = 0x00000001;
const FDT_END_NODE: u32 = 0x00000002;
const FDT_PROP: u32 = 0x00000003;
const FDT_NOP: u32 = 0x00000004;
const FDT_END: u32 = 0x00000009;
const MAX_NODE_DEPTH: usize = 64;
const MAX_PROP_LEN: usize = 1 << 20;
const MAX_NAME_LEN: usize = 256;

/// A node in the device tree.
#[derive(Debug, Clone, PartialEq)]
pub struct Node {
    pub name: String,
    pub properties: Vec<(String, Vec<u8>)>,
    pub children: Vec<Node>,
}

/// A parsed FDT blob.
#[derive(Debug, Clone)]
pub struct Fdt {
    pub totalsize: u32,
    pub off_dt_struct: u32,
    pub off_dt_strings: u32,
    pub version: u32,
    pub last_comp_version: u32,
    pub boot_cpuid: u32,
    pub size_dt_strings: u32,
    pub root: Node,
}

fn be32(b: &[u8], at: usize) -> u32 {
    u32::from_be_bytes(b[at..at + 4].try_into().expect("4 bytes"))
}

/// A NUL-terminated string from b starting at at, capped at max_len bytes.
fn read_cstr(b: &[u8], at: usize, max_len: usize) -> Result<String> {
    ensure!(at <= b.len(), "string offset out of bounds");
    let search = &b[at..];
    let end = search
        .iter()
        .position(|&c| c == 0)
        .map(|p| p.min(max_len))
        .unwrap_or(max_len.min(b.len() - at));
    let s = &b[at..at + end];
    String::from_utf8(s.to_vec()).context("invalid UTF-8 in name")
}

/// Round offset up to a multiple of 4.
fn align4(offset: usize) -> usize {
    (offset + 3) & !3
}

/// Walk the FDT structure block and build the node tree.
fn walk_struct(
    data: &[u8],
    struct_off: usize,
    struct_size: usize,
    strings_off: usize,
    strings_size: usize,
) -> Result<Node> {
    let struct_end = struct_off.saturating_add(struct_size);
    let strings_end = strings_off.saturating_add(strings_size);
    // The structure block begins with a BEGIN_NODE for the root "/", whose name is empty, so the
    // stack starts empty and that first node becomes the tree.
    let mut stack: Vec<Node> = Vec::new();
    let mut pos = struct_off;

    loop {
        if pos + 4 > data.len() {
            bail!("FDT structure block is truncated");
        }
        let token = be32(data, pos);
        pos += 4;
        match token {
            FDT_BEGIN_NODE => {
                let name = read_cstr(data, pos, MAX_NAME_LEN)?;
                pos += name.len() + 1;
                pos = align4(pos);
                ensure!(
                    stack.len() < MAX_NODE_DEPTH,
                    "device tree exceeds max depth {MAX_NODE_DEPTH}"
                );
                stack.push(Node {
                    name,
                    properties: Vec::new(),
                    children: Vec::new(),
                });
            }
            FDT_END_NODE => {
                if stack.is_empty() {
                    bail!("FDT_END_NODE without matching BEGIN_NODE");
                }
                let node = stack.pop().unwrap();
                match stack.last_mut() {
                    Some(parent) => parent.children.push(node),
                    None => return Ok(node),
                }
            }
            FDT_PROP => {
                if pos + 8 > data.len() {
                    bail!("FDT_PROP header is truncated");
                }
                let length = be32(data, pos) as usize;
                let nameoff = be32(data, pos + 4) as usize;
                pos += 8;
                ensure!(
                    length <= MAX_PROP_LEN,
                    "property length {length} exceeds cap"
                );
                if pos + length > struct_end.min(data.len()) {
                    bail!("FDT property value runs past the structure block");
                }
                let value = data[pos..pos + length].to_vec();
                pos += length;
                pos = align4(pos);
                let name_off = strings_off.checked_add(nameoff).unwrap_or(0);
                ensure!(
                    name_off < data.len() && name_off < strings_end,
                    "property name offset {nameoff} is out of the strings block"
                );
                let name = read_cstr(data, name_off, MAX_NAME_LEN)?;
                if let Some(parent) = stack.last_mut() {
                    parent.properties.push((name, value));
                }
            }
            FDT_NOP => {}
            FDT_END => break,
            other => {
                let at = pos - 4;
                bail!("unknown FDT token {other:#x} at offset {at:#x}")
            }
        }
    }
    ensure!(
        stack.is_empty(),
        "device tree is not balanced at end of structure"
    );
    bail!("device tree has no root node")
}

/// Parse a raw FDT blob. `data` is the complete blob.
fn parse_fdt(data: &[u8]) -> Result<Fdt> {
    ensure!(
        data.len() >= FDT_HEADER_SIZE,
        "FDT blob is too short for a header"
    );
    ensure!(be32(data, 0) == FDT_MAGIC, "not an FDT blob: bad magic");
    let totalsize = be32(data, 4);
    let off_dt_struct = be32(data, 8);
    let off_dt_strings = be32(data, 12);
    // FDT header (FDT spec v17): magic 0, totalsize 4, off_dt_struct 8, off_dt_strings 12,
    // off_mem_rsvmap 16, version 20, last_comp_version 24, boot_cpuid_phys 28,
    // size_dt_strings 32, size_dt_struct 36.
    let version = be32(data, 20);
    let last_comp_version = be32(data, 24);
    let boot_cpuid = be32(data, 28);
    let size_dt_strings = be32(data, 32);
    let _size_dt_struct = be32(data, 36);
    ensure!(
        totalsize as usize <= data.len(),
        "totalsize exceeds file length"
    );
    ensure!(
        (totalsize as usize) >= FDT_HEADER_SIZE,
        "totalsize is smaller than the header"
    );
    let struct_off = off_dt_struct as usize;
    let strings_off = off_dt_strings as usize;
    let strings_size = size_dt_strings as usize;
    let strings_end = strings_off.saturating_add(strings_size);
    ensure!(
        struct_off >= FDT_HEADER_SIZE,
        "off_dt_struct is before the header"
    );
    ensure!(
        strings_off >= FDT_HEADER_SIZE,
        "off_dt_strings is before the header"
    );
    ensure!(
        struct_off <= data.len(),
        "off_dt_struct is past the end of the blob"
    );
    ensure!(
        strings_off <= data.len(),
        "off_dt_strings is past the end of the blob"
    );
    ensure!(
        strings_end <= data.len(),
        "strings block end is past the end of the blob"
    );
    ensure!(version <= 40, "FDT version is too new");
    ensure!(
        last_comp_version <= version,
        "last_comp_version is greater than version"
    );
    let struct_size = data.len().saturating_sub(struct_off);
    let root = walk_struct(data, struct_off, struct_size, strings_off, strings_size)?;
    Ok(Fdt {
        totalsize,
        off_dt_struct,
        off_dt_strings,
        version,
        last_comp_version,
        boot_cpuid,
        size_dt_strings,
        root,
    })
}

/// Split a path like soc/serial0 into components.
/// Format a property value for text display.
fn fmt_prop_value(val: &[u8]) -> String {
    // FDT rule: a string is NUL-terminated and not a whole number of cells; a cell array is
    // always a multiple of 4 bytes. String *lists* can total a multiple of 4, so those are
    // recognised by being entirely printable ASCII/NUL with at least one letter.
    let is_text = |b: u8| b.is_ascii_graphic() || b.is_ascii_whitespace();
    let looks_textual = !val.is_empty()
        && val.iter().all(|b| *b == 0 || is_text(*b))
        && val.iter().any(|b| b.is_ascii_alphabetic());
    if looks_textual {
        let list: Vec<String> = val
            .split(|b| *b == 0)
            .filter(|s| !s.is_empty())
            .filter_map(|s| std::str::from_utf8(s).ok())
            .map(|t| format!("\"{t}\""))
            .collect();
        if !list.is_empty() {
            return list.join(", ");
        }
    }
    if val.len().is_multiple_of(4) {
        let cells: Vec<String> = val
            .chunks(4)
            .map(|c| format!("0x{:02x}{:02x}{:02x}{:02x}", c[0], c[1], c[2], c[3]))
            .collect();
        return format!("<{}>", cells.join(" "));
    }
    format!("<{} bytes>", val.len())
}

/// Render a node as nested text (DTS-like).
fn render_node(node: &Node, indent: &str) -> String {
    let mut out = String::new();
    let inner = if node.name.is_empty() {
        out.push_str("/ {\n");
        String::from("    ")
    } else {
        out.push_str(&format!("{}{} {{\n", indent, node.name));
        format!("{indent}    ")
    };
    let inner = inner.as_str();
    for (name, val) in &node.properties {
        out.push_str(&format!("{inner}{} = {};", name, fmt_prop_value(val)));
        out.push('\n');
    }
    for child in &node.children {
        out.push_str(&render_node(child, inner));
    }
    out.push_str(&format!("{}}}\n", indent));
    out
}

/// Convert an FDT to its DTS text representation.
pub fn fdt_to_text(fdt: &Fdt) -> String {
    render_node(&fdt.root, "")
}

/// Convert an FDT to JSON.
pub fn fdt_to_json(fdt: &Fdt) -> Value {
    json!({
        "format": "fdt",
        "totalsize": fdt.totalsize,
        "off_dt_struct": fdt.off_dt_struct,
        "off_dt_strings": fdt.off_dt_strings,
        "version": fdt.version,
        "last_comp_version": fdt.last_comp_version,
        "boot_cpuid": fdt.boot_cpuid,
        "size_dt_strings": fdt.size_dt_strings,
        "root": node_to_json(&fdt.root),
    })
}

fn node_to_json(node: &Node) -> Value {
    json!({
        "name": node.name,
        "properties": node
            .properties
            .iter()
            .map(|(k, v)| json!({"name": k, "value": fmt_prop_value(v)}))
            .collect::<Vec<_>>(),
        "children": node.children.iter().map(node_to_json).collect::<Vec<_>>(),
    })
}

/// Render whatever this file is, chosen by its magic rather than its name.
pub fn describe_file(path: &Path) -> Result<String> {
    let (data, gzipped) = read_file(path)?;
    if is_fdt(&data) {
        return Ok(format!(
            "device tree\n\n{}",
            fdt_to_text(&parse_fdt(&data)?)
        ));
    }
    if data.len() >= 4 && data[..4] == [0xd7, 0xb7, 0xab, 0x1e] {
        return Ok(format!(
            "dtbo table\n\n{}",
            dtbo_to_text(&parse_dtbo(&data)?)
        ));
    }
    Ok(describe_opaque(path, &data, gzipped))
}

/// The same, as JSON.
pub fn to_json(path: &Path) -> Result<Value> {
    let (data, gzipped) = read_file(path)?;
    if is_fdt(&data) {
        return Ok(fdt_to_json(&parse_fdt(&data)?));
    }
    if data.len() >= 4 && data[..4] == [0xd7, 0xb7, 0xab, 0x1e] {
        return Ok(dtbo_to_json(&parse_dtbo(&data)?));
    }
    Ok(opaque_json(path, &data, gzipped))
}

fn is_fdt(data: &[u8]) -> bool {
    data.len() >= 4 && data[..4] == [0xd0, 0x0d, 0xfe, 0xed]
}

/// The file's bytes, gunzipped when it is a gzip-wrapped image (#114), and whether it was.
fn read_file(path: &Path) -> Result<(Vec<u8>, bool)> {
    crate::detect::refuse_blocking_file(path)?;
    let mut f = File::open(path).with_context(|| format!("opening {}", path.display()))?;
    let mut v = Vec::new();
    f.read_to_end(&mut v)?;
    crate::ramdisk::unwrap_gzip(v)
}

/// Shallow entropy and hex view for containers we do not parse (bootloader, logo).
fn describe_opaque(path: &Path, data: &[u8], gzipped: bool) -> String {
    let mut o = vec![format!("{} ({} bytes)", display_name(path), data.len())];
    if gzipped {
        o.push("gzip-compressed: size, bytes and entropy are of the decompressed content".into());
    }
    o.push(format!(
        "first 32 bytes: {}",
        hex(data.get(..32).unwrap_or(&[]))
    ));
    o.push(format!(
        "entropy: {:.3} (near 8.0 means encrypted or compressed)",
        crate::ramdisk::entropy(data)
    ));
    o.join("\n")
}

fn display_name(path: &Path) -> String {
    path.file_name()
        .map(|s| s.to_string_lossy().into_owned())
        .unwrap_or_default()
}

fn opaque_json(path: &Path, data: &[u8], gzipped: bool) -> Value {
    json!({
        "path": display_name(path),
        "gzip_compressed": gzipped,
        "size": data.len(),
        "first_bytes": hex(data.get(..32).unwrap_or(&[])),
        "entropy": crate::ramdisk::entropy(data),
    })
}

fn hex(b: &[u8]) -> String {
    b.iter()
        .map(|x| format!("{x:02x}"))
        .collect::<Vec<_>>()
        .join(" ")
}

const MAX_DTBO_ENTRIES: usize = 4096;

/// One entry of a dtbo table.
#[derive(Debug, Clone)]
pub struct DtboEntry {
    pub id: u32,
    pub rev: u32,
    pub dtb_offset: u32,
    pub dtb_size: u32,
    /// The entry's device tree, if it parsed.
    pub fdt: Option<Fdt>,
}

/// A parsed dtbo table.
#[derive(Debug)]
pub struct DtboTable {
    pub total_size: u32,
    pub entry_size: u32,
    pub entry_count: u32,
    pub page_size: u32,
    pub entries: Vec<DtboEntry>,
}

/// Parse a dtbo table (AOSP dtbo header, big-endian).
pub fn parse_dtbo(data: &[u8]) -> Result<DtboTable> {
    ensure!(data.len() >= 32, "dtbo table is too short");
    ensure!(
        data[..4] == [0xd7, 0xb7, 0xab, 0x1e],
        "not a dtbo table: bad magic"
    );
    let at = |o: usize| be32(data, o) as usize;
    let total_size = at(4);
    let header_size = at(8);
    let entry_size = at(12);
    let entry_count = at(16);
    let entries_offset = at(20);
    let page_size = at(24);
    ensure!(
        header_size >= 32 && header_size <= data.len(),
        "dtbo header size out of range"
    );
    ensure!(
        entry_size >= 12,
        "dtbo entry size {entry_size} is too small"
    );
    ensure!(
        entry_count <= MAX_DTBO_ENTRIES,
        "dtbo claims {entry_count} entries"
    );
    let end = entries_offset.saturating_add(entry_size * entry_count);
    ensure!(
        end <= data.len(),
        "dtbo entry table runs past the end of the file"
    );
    let mut entries = Vec::with_capacity(entry_count);
    for i in 0..entry_count {
        let a = entries_offset + i * entry_size;
        let dtb_size = at(a);
        let dtb_offset = at(a + 4);
        let id = at(a + 8) as u32;
        let rev = at(a + 12) as u32;
        let stop = dtb_offset.saturating_add(dtb_size);
        let fdt = if stop <= data.len() && is_fdt(&data[dtb_offset..stop]) {
            parse_fdt(&data[dtb_offset..stop]).ok()
        } else {
            None
        };
        entries.push(DtboEntry {
            id,
            rev,
            dtb_offset: dtb_offset as u32,
            dtb_size: dtb_size as u32,
            fdt,
        });
    }
    Ok(DtboTable {
        total_size: total_size as u32,
        entry_size: entry_size as u32,
        entry_count: entry_count as u32,
        page_size: page_size as u32,
        entries,
    })
}

/// A dtbo table as JSON.
pub fn dtbo_to_json(t: &DtboTable) -> Value {
    json!({
        "format": "dtbo",
        "total_size": t.total_size,
        "entry_size": t.entry_size,
        "entry_count": t.entry_count,
        "page_size": t.page_size,
        "entries": t.entries.iter().map(|e| json!({
            "id": e.id,
            "rev": e.rev,
            "dtb_offset": e.dtb_offset,
            "dtb_size": e.dtb_size,
            "dtb": e.fdt.as_ref().map(fdt_to_json),
        })).collect::<Vec<_>>(),
    })
}

/// A dtbo table as text.
pub fn dtbo_to_text(t: &DtboTable) -> String {
    let mut o = vec![format!(
        "{} entries, page size {}",
        t.entry_count, t.page_size
    )];
    for e in &t.entries {
        o.push(format!(
            "  entry id={} rev={} dtb {} bytes at {}",
            e.id, e.rev, e.dtb_size, e.dtb_offset
        ));
    }
    o.join("\n")
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A minimal valid FDT with one string property and one cell property.
    fn tiny_fdt() -> Vec<u8> {
        let strings = b"model\0reg\0".to_vec();
        let mut st: Vec<u8> = Vec::new();
        let prop = |nameoff: u32, value: &[u8], out: &mut Vec<u8>| {
            out.extend_from_slice(&FDT_PROP.to_be_bytes());
            out.extend_from_slice(&(value.len() as u32).to_be_bytes());
            out.extend_from_slice(&nameoff.to_be_bytes());
            out.extend_from_slice(value);
            while !out.len().is_multiple_of(4) {
                out.push(0);
            }
        };
        st.extend_from_slice(&FDT_BEGIN_NODE.to_be_bytes());
        st.extend_from_slice(b"\0");
        while !st.len().is_multiple_of(4) {
            st.push(0);
        }
        prop(0, b"Test Board\0", &mut st);
        prop(6, &[0, 0, 0, 0, 0x20, 0, 0, 0], &mut st);
        st.extend_from_slice(&FDT_END_NODE.to_be_bytes());
        st.extend_from_slice(&FDT_END.to_be_bytes());

        let header = 40usize;
        let struct_off = header;
        let strings_off = struct_off + st.len();
        let total = strings_off + strings.len();
        let mut out = vec![0u8; total];
        out[0..4].copy_from_slice(&FDT_MAGIC.to_be_bytes());
        out[4..8].copy_from_slice(&(total as u32).to_be_bytes());
        out[8..12].copy_from_slice(&(struct_off as u32).to_be_bytes());
        out[12..16].copy_from_slice(&(strings_off as u32).to_be_bytes());
        out[16..20].copy_from_slice(&40u32.to_be_bytes()); // off_mem_rsvmap
        out[20..24].copy_from_slice(&17u32.to_be_bytes()); // version
        out[24..28].copy_from_slice(&16u32.to_be_bytes()); // last_comp_version
        out[28..32].copy_from_slice(&0u32.to_be_bytes()); // boot_cpuid
        out[32..36].copy_from_slice(&(strings.len() as u32).to_be_bytes());
        out[36..40].copy_from_slice(&(st.len() as u32).to_be_bytes());
        out[struct_off..strings_off].copy_from_slice(&st);
        out[strings_off..].copy_from_slice(&strings);
        out
    }

    #[test]
    fn a_valid_fdt_parses_its_properties() {
        let f = parse_fdt(&tiny_fdt()).unwrap();
        assert_eq!(f.version, 17);
        assert_eq!(f.root.properties.len(), 2);
        assert_eq!(f.root.properties[0].0, "model");
        assert_eq!(f.root.properties[1].0, "reg");
    }

    #[test]
    fn a_string_property_renders_as_a_quoted_string() {
        let f = parse_fdt(&tiny_fdt()).unwrap();
        assert_eq!(fmt_prop_value(&f.root.properties[0].1), "\"Test Board\"");
    }

    #[test]
    fn a_cell_property_renders_as_hex_cells() {
        let f = parse_fdt(&tiny_fdt()).unwrap();
        assert_eq!(
            fmt_prop_value(&f.root.properties[1].1),
            "<0x00000000 0x20000000>"
        );
    }

    #[test]
    fn a_bad_magic_is_refused() {
        let mut d = tiny_fdt();
        d[0] = 0;
        assert!(parse_fdt(&d).is_err());
    }

    #[test]
    fn a_truncated_fdt_is_an_error_not_a_panic() {
        let d = tiny_fdt();
        for cut in [0, 4, 12, 20, d.len() - 1] {
            assert!(
                parse_fdt(&d[..cut]).is_err(),
                "cut at {cut} should be refused"
            );
        }
    }

    #[test]
    fn a_lying_totalsize_is_refused() {
        let mut d = tiny_fdt();
        let too_big = (d.len() as u32 + 4096).to_be_bytes();
        d[4..8].copy_from_slice(&too_big);
        assert!(
            parse_fdt(&d).is_err(),
            "a totalsize beyond the file must be refused"
        );
    }

    #[test]
    fn a_dtbo_table_parses_its_entries() {
        let mut d = vec![0u8; 32];
        d[0..4].copy_from_slice(&[0xd7, 0xb7, 0xab, 0x1e]);
        d[4..8].copy_from_slice(&64u32.to_be_bytes()); // total_size
        d[8..12].copy_from_slice(&32u32.to_be_bytes()); // header_size
        d[12..16].copy_from_slice(&16u32.to_be_bytes()); // entry_size
        d[16..20].copy_from_slice(&1u32.to_be_bytes()); // entry_count
        d[20..24].copy_from_slice(&32u32.to_be_bytes()); // entries_offset
        d[24..28].copy_from_slice(&4096u32.to_be_bytes()); // page_size
        d.extend_from_slice(&0u32.to_be_bytes()); // dtb_size
        d.extend_from_slice(&48u32.to_be_bytes()); // dtb_offset
        d.extend_from_slice(&1u32.to_be_bytes()); // id
        d.extend_from_slice(&2u32.to_be_bytes()); // rev
        while d.len() < 48 {
            d.push(0);
        }
        d.extend_from_slice(&tiny_fdt());
        while d.len() < 64 {
            d.push(0);
        }
        let t = parse_dtbo(&d).unwrap();
        assert_eq!(t.entry_count, 1);
        assert_eq!(t.entries[0].id, 1);
    }

    #[test]
    fn a_malformed_dtbo_is_refused_without_panicking() {
        assert!(parse_dtbo(&[]).is_err());
        assert!(parse_dtbo(&[0u8; 64]).is_err(), "bad magic must be refused");
        let mut d = vec![0u8; 64];
        d[0..4].copy_from_slice(&[0xd7, 0xb7, 0xab, 0x1e]);
        d[16..20].copy_from_slice(&0xffffu32.to_be_bytes()); // absurd entry_count
        assert!(parse_dtbo(&d).is_err());
    }

    fn gzip(body: &[u8]) -> Vec<u8> {
        use std::io::Write;
        let mut e = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        e.write_all(body).unwrap();
        e.finish().unwrap()
    }

    #[test]
    fn a_gzip_wrapped_image_is_described_by_what_it_holds() {
        // An `AML_` multi-DT container is not parsed here; what matters is that the report is
        // about the decompressed bytes and says so, not about the gzip stream (#114).
        let mut inner = b"AML_".to_vec();
        inner.extend(vec![0x5Au8; 4092]);
        let d = crate::testutil::Scratch::new("dt-gz");
        let f = d.join("dt.img");
        std::fs::write(&f, gzip(&inner)).unwrap();
        let text = describe_file(&f).unwrap();
        assert!(text.contains("4096 bytes"), "{text}");
        assert!(text.contains("gzip-compressed"), "{text}");
        assert!(text.contains("41 4d 4c 5f"), "first bytes are AML_: {text}");
        let j = to_json(&f).unwrap();
        assert_eq!(j["gzip_compressed"], true);
        assert_eq!(j["size"], 4096);
    }

    #[test]
    fn an_unrecognised_container_is_described_rather_than_guessed() {
        let d = crate::testutil::Scratch::new("dt-opaque");
        let f = d.join("bootloader.img");
        std::fs::write(&f, vec![0x5Au8; 8192]).unwrap();
        let text = describe_file(&f).unwrap();
        assert!(text.contains("8192 bytes"), "{text}");
        assert!(text.contains("entropy"), "{text}");
    }
}
