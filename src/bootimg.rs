//! Android boot images (header versions 0 to 4) and vendor boot images (versions 3 and 4).
//!
//! Written from the AOSP `bootimg.h` header definitions (Apache-2.0); checked against AOSP's own
//! `unpack_bootimg.py` and `mkbootimg.py`. Every offset is computed in checked `u64` arithmetic
//! and every section must lie inside the file.
use crate::detect::refuse_blocking_file;
use crate::extract::create_part;
use anyhow::{Context, Result, bail, ensure};
use serde_json::{Map, Value, json};
use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};

const BOOT_MAGIC: &[u8; 8] = b"ANDROID!";
const VENDOR_MAGIC: &[u8; 8] = b"VNDRBOOT";
/// Enough to hold the largest header (vendor boot v4 is 2128 bytes).
const HEAD_LEN: usize = 4096;
/// Boot image v3 and v4 always use 4096-byte pages.
const V3_PAGE_SIZE: u32 = 4096;
const MAX_TABLE_ENTRIES: u32 = 4096;
/// Smallest vendor ramdisk table entry: size, offset, type, name[32], board_id[16].
const MIN_TABLE_ENTRY: u32 = 4 + 4 + 4 + 32 + 64;

#[derive(Debug, Clone, PartialEq)]
pub struct Section {
    pub name: String,
    pub offset: u64,
    pub size: u64,
}

#[derive(Debug)]
pub struct Image {
    /// Ordered `(key, value)` pairs describing the header; rendered as text or JSON.
    pub info: Vec<(String, Value)>,
    pub sections: Vec<Section>,
}

fn le32(b: &[u8], at: usize) -> u32 {
    u32::from_le_bytes(b[at..at + 4].try_into().expect("4 bytes"))
}

fn le64(b: &[u8], at: usize) -> u64 {
    u64::from_le_bytes(b[at..at + 8].try_into().expect("8 bytes"))
}

/// Text up to the first NUL.
fn cstr(b: &[u8]) -> String {
    let end = b.iter().position(|&c| c == 0).unwrap_or(b.len());
    String::from_utf8_lossy(&b[..end]).into_owned()
}

fn pages(size: u64, page: u64) -> u64 {
    size.div_ceil(page)
}

/// `a * page`, refusing overflow.
fn at_page(n: u64, page: u64) -> Result<u64> {
    n.checked_mul(page).context("image layout overflows")
}

fn check_page_size(page: u32) -> Result<u64> {
    ensure!(
        page.is_power_of_two() && (512..=(1 << 20)).contains(&page),
        "unsupported page size {page}"
    );
    Ok(page as u64)
}

/// `os_version` packs A.B.C into the high 21 bits and the patch level (year, month) into the low 11.
fn decode_os_version(v: u32) -> (Option<String>, Option<String>) {
    let (version, patch) = (v >> 11, v & 0x7ff);
    let os = (version != 0).then(|| {
        format!(
            "{}.{}.{}",
            version >> 14,
            (version >> 7) & 0x7f,
            version & 0x7f
        )
    });
    let level = (patch != 0).then(|| format!("{:04}-{:02}", (patch >> 4) + 2000, patch & 0xf));
    (os, level)
}

fn hex(v: u64, width: usize) -> String {
    format!("{v:#0width$x}")
}

fn push(info: &mut Vec<(String, Value)>, key: &str, value: impl Into<Value>) {
    info.push((key.to_string(), value.into()));
}

fn section(name: &str, offset: u64, size: u64) -> Section {
    Section {
        name: name.to_string(),
        offset,
        size,
    }
}

/// Parse the header of a boot or vendor boot image of `file_len` bytes. `head` holds up to the
/// first 4096 bytes of the file; `read_at` fetches table entries that live further in.
pub fn parse<F>(head: &[u8], file_len: u64, mut read_at: F) -> Result<Image>
where
    F: FnMut(u64, usize) -> Result<Vec<u8>>,
{
    ensure!(head.len() >= 12, "too short to be a boot image");
    let image = if &head[..8] == BOOT_MAGIC {
        parse_boot(head)?
    } else if &head[..8] == VENDOR_MAGIC {
        parse_vendor(head, &mut read_at)?
    } else {
        bail!("not a boot image: bad magic");
    };
    for s in &image.sections {
        let end = s
            .offset
            .checked_add(s.size)
            .context("section end overflows")?;
        ensure!(
            end <= file_len,
            "{} (offset {}, {} bytes) runs past the end of the file ({file_len} bytes)",
            s.name,
            s.offset,
            s.size
        );
    }
    Ok(image)
}

fn need(head: &[u8], n: usize, what: &str) -> Result<()> {
    ensure!(
        head.len() >= n,
        "file ends inside the {what} header (needs {n} bytes)"
    );
    Ok(())
}

fn parse_boot(head: &[u8]) -> Result<Image> {
    need(head, 48, "boot image")?;
    let version = le32(head, 40);
    ensure!(
        version <= 4,
        "unsupported boot image header version {version}"
    );
    let mut info = Vec::new();
    push(&mut info, "kind", "boot");
    push(&mut info, "header_version", version);
    let mut sections = Vec::new();
    let (kernel, ramdisk, second, page, os);
    let (mut recovery_dtbo, mut recovery_dtbo_offset, mut dtb, mut signature) =
        (0u64, 0u64, 0u64, 0u64);
    if version < 3 {
        need(head, 1632, "boot image")?;
        kernel = le32(head, 8) as u64;
        ramdisk = le32(head, 16) as u64;
        second = le32(head, 24) as u64;
        page = check_page_size(le32(head, 36))?;
        os = le32(head, 44);
        push(&mut info, "page_size", page);
        push(&mut info, "kernel_size", kernel);
        push(&mut info, "kernel_load_address", le32(head, 12));
        push(&mut info, "ramdisk_size", ramdisk);
        push(&mut info, "ramdisk_load_address", le32(head, 20));
        push(&mut info, "second_size", second);
        push(&mut info, "second_load_address", le32(head, 28));
        push(&mut info, "tags_load_address", le32(head, 32));
        push(&mut info, "product_name", cstr(&head[48..64]));
        push(&mut info, "cmdline", cstr(&head[64..576]));
        push(&mut info, "extra_cmdline", cstr(&head[608..1632]));
        if version >= 1 {
            need(head, 1648, "boot image v1")?;
            recovery_dtbo = le32(head, 1632) as u64;
            recovery_dtbo_offset = le64(head, 1636);
            push(&mut info, "recovery_dtbo_size", recovery_dtbo);
            push(&mut info, "recovery_dtbo_offset", recovery_dtbo_offset);
            push(&mut info, "header_size", le32(head, 1644));
        }
        if version == 2 {
            need(head, 1660, "boot image v2")?;
            dtb = le32(head, 1648) as u64;
            push(&mut info, "dtb_size", dtb);
            push(&mut info, "dtb_load_address", le64(head, 1652));
        }
    } else {
        need(head, 44 + 1536, "boot image v3")?;
        kernel = le32(head, 8) as u64;
        ramdisk = le32(head, 12) as u64;
        second = 0;
        page = V3_PAGE_SIZE as u64;
        os = le32(head, 16);
        push(&mut info, "page_size", page);
        push(&mut info, "kernel_size", kernel);
        push(&mut info, "ramdisk_size", ramdisk);
        push(&mut info, "header_size", le32(head, 20));
        push(&mut info, "cmdline", cstr(&head[44..44 + 1536]));
        if version == 4 {
            need(head, 44 + 1536 + 4, "boot image v4")?;
            signature = le32(head, 44 + 1536) as u64;
            push(&mut info, "boot_signature_size", signature);
        }
    }
    let (os_version, patch_level) = decode_os_version(os);
    push(
        &mut info,
        "os_version",
        os_version.map_or(Value::Null, Value::from),
    );
    push(
        &mut info,
        "os_patch_level",
        patch_level.map_or(Value::Null, Value::from),
    );

    let kernel_pages = pages(kernel, page);
    let ramdisk_pages = pages(ramdisk, page);
    let second_pages = pages(second, page);
    let dtbo_pages = pages(recovery_dtbo, page);
    sections.push(section("kernel", page, kernel));
    let ramdisk_at = at_page(1 + kernel_pages, page)?;
    sections.push(section("ramdisk", ramdisk_at, ramdisk));
    if second > 0 {
        sections.push(section(
            "second",
            at_page(1 + kernel_pages + ramdisk_pages, page)?,
            second,
        ));
    }
    if recovery_dtbo > 0 {
        sections.push(section(
            "recovery_dtbo",
            recovery_dtbo_offset,
            recovery_dtbo,
        ));
    }
    if dtb > 0 {
        let at = at_page(
            1 + kernel_pages + ramdisk_pages + second_pages + dtbo_pages,
            page,
        )?;
        sections.push(section("dtb", at, dtb));
    }
    if signature > 0 {
        sections.push(section(
            "boot_signature",
            at_page(1 + kernel_pages + ramdisk_pages, page)?,
            signature,
        ));
    }
    sections.retain(|s| s.size > 0);
    Ok(Image { info, sections })
}

fn parse_vendor<F>(head: &[u8], read_at: &mut F) -> Result<Image>
where
    F: FnMut(u64, usize) -> Result<Vec<u8>>,
{
    need(head, 2112, "vendor boot")?;
    let version = le32(head, 8);
    ensure!(
        (3..=4).contains(&version),
        "unsupported vendor boot header version {version}"
    );
    let page = check_page_size(le32(head, 12))?;
    let ramdisk_size = le32(head, 24) as u64;
    let header_size = le32(head, 2096) as u64;
    let dtb = le32(head, 2100) as u64;
    let mut info = Vec::new();
    push(&mut info, "kind", "vendor_boot");
    push(&mut info, "header_version", version);
    push(&mut info, "page_size", page);
    push(&mut info, "kernel_load_address", le32(head, 16));
    push(&mut info, "ramdisk_load_address", le32(head, 20));
    push(&mut info, "vendor_ramdisk_size", ramdisk_size);
    push(&mut info, "cmdline", cstr(&head[28..2076]));
    push(&mut info, "tags_load_address", le32(head, 2076));
    push(&mut info, "product_name", cstr(&head[2080..2096]));
    push(&mut info, "header_size", header_size);
    push(&mut info, "dtb_size", dtb);
    push(&mut info, "dtb_load_address", le64(head, 2104));

    let header_pages = pages(header_size, page);
    let ramdisk_pages = pages(ramdisk_size, page);
    let dtb_pages = pages(dtb, page);
    let base = at_page(header_pages, page)?;
    let mut sections = Vec::new();
    if version == 3 {
        sections.push(section("vendor_ramdisk", base, ramdisk_size));
    } else {
        need(head, 2128, "vendor boot v4")?;
        let table_size = le32(head, 2112) as u64;
        let entries = le32(head, 2116);
        let entry_size = le32(head, 2120);
        let bootconfig = le32(head, 2124) as u64;
        ensure!(
            entries <= MAX_TABLE_ENTRIES,
            "vendor ramdisk table has {entries} entries, over the limit of {MAX_TABLE_ENTRIES}"
        );
        ensure!(
            entries == 0 || entry_size >= MIN_TABLE_ENTRY,
            "vendor ramdisk table entries are {entry_size} bytes, too small"
        );
        push(&mut info, "vendor_ramdisk_table_size", table_size);
        push(&mut info, "vendor_bootconfig_size", bootconfig);
        let table_at = at_page(header_pages + ramdisk_pages + dtb_pages, page)?;
        let mut table = Vec::new();
        for i in 0..entries {
            let at = table_at
                .checked_add(entry_size as u64 * i as u64)
                .context("vendor ramdisk table offset overflows")?;
            let e = read_at(at, MIN_TABLE_ENTRY as usize)
                .with_context(|| format!("reading vendor ramdisk table entry {i}"))?;
            let (size, offset) = (le32(&e, 0) as u64, le32(&e, 4) as u64);
            let file_name = format!("vendor_ramdisk{i:02}");
            table.push(json!({
                "file": file_name,
                "size": size,
                "offset": offset,
                "type": le32(&e, 8),
                "name": cstr(&e[12..44]),
                "board_id": (0..16).map(|k| le32(&e, 44 + 4 * k)).collect::<Vec<_>>(),
            }));
            sections.push(section(
                &file_name,
                base.checked_add(offset)
                    .context("ramdisk offset overflows")?,
                size,
            ));
        }
        push(&mut info, "vendor_ramdisk_table", Value::Array(table));
        let table_pages = pages(table_size, page);
        sections.push(section(
            "bootconfig",
            at_page(header_pages + ramdisk_pages + dtb_pages + table_pages, page)?,
            bootconfig,
        ));
    }
    sections.push(section(
        "dtb",
        at_page(header_pages + ramdisk_pages, page)?,
        dtb,
    ));
    sections.retain(|s| s.size > 0);
    Ok(Image { info, sections })
}

/// Open `path`, parse it and return the image.
pub fn read(path: &Path) -> Result<Image> {
    refuse_blocking_file(path)?;
    ensure!(
        !path.is_dir(),
        "{} is a directory, not a boot image",
        path.display()
    );
    let mut f = File::open(path).with_context(|| format!("opening {}", path.display()))?;
    let len = f.metadata()?.len();
    let mut head = Vec::with_capacity(HEAD_LEN);
    f.try_clone()?
        .take(HEAD_LEN as u64)
        .read_to_end(&mut head)?;
    parse(&head, len, |at, n| {
        let mut buf = vec![0u8; n];
        f.seek(SeekFrom::Start(at))?;
        f.read_exact(&mut buf)
            .context("file ends inside the table")?;
        Ok(buf)
    })
}

/// Write each section of `image` (read from `input`) into `out_dir` as a file named after it.
/// All-or-nothing: existing files are refused unless `force`, and a failure removes every
/// `.part` file.
pub fn write_sections(
    input: &Path,
    image: &Image,
    out_dir: &Path,
    force: bool,
) -> Result<Vec<PathBuf>> {
    if !force {
        let existing: Vec<&str> = image
            .sections
            .iter()
            .map(|s| s.name.as_str())
            .filter(|n| out_dir.join(n).symlink_metadata().is_ok())
            .collect();
        ensure!(
            existing.is_empty(),
            "{} already exist in {}; pass --force to overwrite",
            existing.join(", "),
            out_dir.display()
        );
    }
    std::fs::create_dir_all(out_dir)?;
    let part = |name: &str| out_dir.join(format!("{name}.part"));
    let done = (|| -> Result<Vec<PathBuf>> {
        let mut src = File::open(input)?;
        for s in &image.sections {
            src.seek(SeekFrom::Start(s.offset))?;
            let mut out = create_part(&part(&s.name))?;
            let copied = std::io::copy(&mut (&mut src).take(s.size), &mut out)?;
            ensure!(
                copied == s.size,
                "{} is shorter than its header says",
                s.name
            );
        }
        let mut paths = Vec::new();
        for s in &image.sections {
            let final_path = out_dir.join(&s.name);
            std::fs::rename(part(&s.name), &final_path)?;
            paths.push(final_path);
        }
        Ok(paths)
    })();
    if done.is_err() {
        for s in &image.sections {
            let _ = std::fs::remove_file(part(&s.name));
        }
    }
    done
}

/// The info as a JSON object, with the sections appended.
pub fn to_json(image: &Image) -> Value {
    let mut map = Map::new();
    for (k, v) in &image.info {
        map.insert(k.clone(), v.clone());
    }
    map.insert(
        "sections".into(),
        Value::Array(
            image
                .sections
                .iter()
                .map(|s| json!({"name": s.name, "offset": s.offset, "size": s.size}))
                .collect(),
        ),
    );
    Value::Object(map)
}

/// Aligned `key  value` lines (addresses in hex), then one line per section.
pub fn to_text(image: &Image) -> String {
    let width = image
        .info
        .iter()
        .filter(|(_, v)| !v.is_array())
        .map(|(k, _)| k.len())
        .max()
        .unwrap_or(0);
    let mut lines = Vec::new();
    for (k, v) in &image.info {
        let shown = match v {
            Value::Null => "none".to_string(),
            Value::String(s) => s.clone(),
            Value::Array(entries) => {
                lines.push(format!("{k}:"));
                for e in entries {
                    lines.push(format!(
                        "  {}  size {}  offset {}  type {:#x}  name {:?}",
                        e["file"].as_str().unwrap_or(""),
                        e["size"],
                        e["offset"],
                        e["type"].as_u64().unwrap_or(0),
                        e["name"].as_str().unwrap_or("")
                    ));
                }
                continue;
            }
            Value::Number(n) if k.ends_with("_address") => hex(n.as_u64().unwrap_or(0), 10),
            other => other.to_string(),
        };
        lines.push(format!("{k:<width$}  {shown}"));
    }
    lines.push("sections:".to_string());
    for s in &image.sections {
        lines.push(format!(
            "  {:<16} offset {:<10} size {}",
            s.name, s.offset, s.size
        ));
    }
    lines.join("\n")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn put32(b: &mut [u8], at: usize, v: u32) {
        b[at..at + 4].copy_from_slice(&v.to_le_bytes());
    }

    fn put64(b: &mut [u8], at: usize, v: u64) {
        b[at..at + 8].copy_from_slice(&v.to_le_bytes());
    }

    fn put_str(b: &mut [u8], at: usize, s: &str) {
        b[at..at + s.len()].copy_from_slice(s.as_bytes());
    }

    /// Data for a section: a recognisable pattern per section.
    fn data(tag: u8, n: usize) -> Vec<u8> {
        (0..n).map(|i| tag.wrapping_add((i % 251) as u8)).collect()
    }

    fn pad_to(img: &mut Vec<u8>, page: usize) {
        let len = img.len().div_ceil(page) * page;
        img.resize(len, 0);
    }

    struct Boot {
        version: u32,
        page: usize,
        kernel: usize,
        ramdisk: usize,
        second: usize,
        dtbo: usize,
        dtb: usize,
        signature: usize,
        os: u32,
    }

    impl Boot {
        fn new(version: u32) -> Self {
            let page = if version >= 3 { 4096 } else { 2048 };
            Boot {
                version,
                page,
                kernel: 5000,
                ramdisk: 3000,
                second: 0,
                dtbo: 0,
                dtb: 0,
                signature: 0,
                os: (11 << 25) | (2 << 18) | (3 << 11) | (23 * 16 + 5),
            }
        }

        fn build(&self) -> Vec<u8> {
            let mut h = vec![0u8; self.page.max(4096)];
            h[..8].copy_from_slice(b"ANDROID!");
            let (version, page) = (self.version, self.page);
            if version < 3 {
                put32(&mut h, 8, self.kernel as u32);
                put32(&mut h, 12, 0x1080000);
                put32(&mut h, 16, self.ramdisk as u32);
                put32(&mut h, 20, 0x1000000);
                put32(&mut h, 24, self.second as u32);
                put32(&mut h, 28, 0xf00000);
                put32(&mut h, 32, 0x100);
                put32(&mut h, 36, page as u32);
                put32(&mut h, 40, version);
                put32(&mut h, 44, self.os);
                put_str(&mut h, 48, "prod");
                put_str(&mut h, 64, "console=ttyS0 root=/dev/ram0");
                put_str(&mut h, 608, "extra=1");
                if version >= 1 {
                    put32(&mut h, 1632, self.dtbo as u32);
                    put32(&mut h, 1644, if version == 1 { 1648 } else { 1660 });
                }
                if version == 2 {
                    put32(&mut h, 1648, self.dtb as u32);
                    put64(&mut h, 1652, 0x1f00000);
                }
            } else {
                put32(&mut h, 8, self.kernel as u32);
                put32(&mut h, 12, self.ramdisk as u32);
                put32(&mut h, 16, self.os);
                put32(&mut h, 20, if version == 3 { 1580 } else { 1584 });
                put32(&mut h, 40, version);
                put_str(&mut h, 44, "console=ttyS0 buildvariant=user");
                if version == 4 {
                    put32(&mut h, 44 + 1536, self.signature as u32);
                }
            }
            h.truncate(page);
            let mut img = h;
            for (tag, n) in [(1u8, self.kernel), (2, self.ramdisk)] {
                img.extend(data(tag, n));
                pad_to(&mut img, page);
            }
            if version < 3 {
                img.extend(data(3, self.second));
                pad_to(&mut img, page);
                if version >= 1 {
                    let off = img.len() as u64;
                    put64(&mut img, 1636, off);
                    img.extend(data(4, self.dtbo));
                    pad_to(&mut img, page);
                }
                if version == 2 {
                    img.extend(data(5, self.dtb));
                    pad_to(&mut img, page);
                }
            } else if version == 4 {
                img.extend(data(6, self.signature));
                pad_to(&mut img, page);
            }
            img
        }
    }

    fn parse_bytes(img: &[u8]) -> Result<Image> {
        parse(
            &img[..img.len().min(HEAD_LEN)],
            img.len() as u64,
            |at, n| {
                let at = at as usize;
                ensure!(at + n <= img.len(), "file ends inside the table");
                Ok(img[at..at + n].to_vec())
            },
        )
    }

    fn get<'a>(i: &'a Image, key: &str) -> &'a Value {
        &i.info
            .iter()
            .find(|(k, _)| k == key)
            .unwrap_or_else(|| panic!("no {key}"))
            .1
    }

    fn sec(i: &Image, name: &str) -> Option<(u64, u64)> {
        i.sections
            .iter()
            .find(|s| s.name == name)
            .map(|s| (s.offset, s.size))
    }

    fn slice_of(img: &[u8], i: &Image, name: &str) -> Vec<u8> {
        let (o, n) = sec(i, name).unwrap_or_else(|| panic!("no section {name}"));
        img[o as usize..(o + n) as usize].to_vec()
    }

    #[test]
    fn every_boot_header_version_finds_every_section() {
        for version in 0..=4u32 {
            let mut b = Boot::new(version);
            if version < 3 {
                b.second = 1500;
            }
            if (1..3).contains(&version) {
                b.dtbo = 900;
            }
            if version == 2 {
                b.dtb = 700;
            }
            if version == 4 {
                b.signature = 1200;
            }
            let img = b.build();
            let i = parse_bytes(&img).unwrap_or_else(|e| panic!("v{version}: {e:#}"));
            assert_eq!(get(&i, "header_version"), version as u64, "v{version}");
            assert_eq!(
                slice_of(&img, &i, "kernel"),
                data(1, 5000),
                "v{version} kernel"
            );
            assert_eq!(
                slice_of(&img, &i, "ramdisk"),
                data(2, 3000),
                "v{version} ramdisk"
            );
            if version < 3 {
                assert_eq!(
                    slice_of(&img, &i, "second"),
                    data(3, 1500),
                    "v{version} second"
                );
            } else {
                assert!(sec(&i, "second").is_none(), "v{version} has no second");
            }
            if (1..3).contains(&version) {
                assert_eq!(
                    slice_of(&img, &i, "recovery_dtbo"),
                    data(4, 900),
                    "v{version} dtbo"
                );
            }
            if version == 2 {
                assert_eq!(slice_of(&img, &i, "dtb"), data(5, 700));
            }
            if version == 4 {
                assert_eq!(slice_of(&img, &i, "boot_signature"), data(6, 1200));
            }
        }
    }

    #[test]
    fn header_values_are_decoded() {
        let img = Boot::new(1).build();
        let i = parse_bytes(&img).unwrap();
        assert_eq!(get(&i, "page_size"), 2048u64);
        assert_eq!(get(&i, "kernel_load_address"), 0x1080000u64);
        assert_eq!(get(&i, "ramdisk_load_address"), 0x1000000u64);
        assert_eq!(get(&i, "second_load_address"), 0xf00000u64);
        assert_eq!(get(&i, "tags_load_address"), 0x100u64);
        assert_eq!(get(&i, "product_name"), "prod");
        assert_eq!(get(&i, "cmdline"), "console=ttyS0 root=/dev/ram0");
        assert_eq!(get(&i, "extra_cmdline"), "extra=1");
        assert_eq!(get(&i, "header_size"), 1648u64);
        let v3 = parse_bytes(&Boot::new(3).build()).unwrap();
        assert_eq!(get(&v3, "cmdline"), "console=ttyS0 buildvariant=user");
        assert_eq!(get(&v3, "header_size"), 1580u64);
        assert_eq!(get(&v3, "page_size"), 4096u64, "v3 pages are always 4096");
    }

    #[test]
    fn os_version_and_patch_level_decode_like_aosp() {
        // 11.2.3, patch 2023-05
        let v = (11u32 << 25) | (2 << 18) | (3 << 11) | (((2023 - 2000) << 4) | 5);
        assert_eq!(
            decode_os_version(v),
            (Some("11.2.3".into()), Some("2023-05".into()))
        );
        // the stock STB value seen on a real image: Android 9, patch 2020-12
        assert_eq!(
            decode_os_version(0x1200_014c),
            (Some("9.0.0".into()), Some("2020-12".into()))
        );
        assert_eq!(decode_os_version(0), (None, None));
        assert_eq!(decode_os_version(1 << 11), (Some("0.0.1".into()), None));
        assert_eq!(decode_os_version(0x01), (None, Some("2000-01".into())));
        assert_eq!(decode_os_version(0x10), (None, Some("2001-00".into())));
        assert_eq!(decode_os_version(u32::MAX).0, Some("127.127.127".into()));
    }

    #[test]
    fn v3_and_v4_headers_decode_the_os_version_from_their_own_field() {
        for version in [3u32, 4] {
            let i = parse_bytes(&Boot::new(version).build()).unwrap();
            assert_eq!(get(&i, "os_version"), "11.2.3", "v{version}");
            assert_eq!(get(&i, "os_patch_level"), "2023-05", "v{version}");
        }
        let mut b = Boot::new(3);
        b.os = 0;
        let i = parse_bytes(&b.build()).unwrap();
        assert!(get(&i, "os_version").is_null() && get(&i, "os_patch_level").is_null());
    }

    #[test]
    fn the_vendor_table_entry_limit_is_the_literal_4096() {
        let v = Vendor {
            version: 4,
            page: 4096,
            ramdisk: 0,
            dtb: 100,
            entries: vec![(100, 1, "a")],
            bootconfig: 10,
        };
        let mut img = v.build();
        put32(&mut img, 2116, 5000);
        let e = format!("{:#}", parse_bytes(&img).unwrap_err());
        assert!(
            e.contains("5000 entries") && e.contains("limit of 4096"),
            "{e}"
        );
        let mut at_limit = v.build();
        put32(&mut at_limit, 2116, 4096);
        let e = format!("{:#}", parse_bytes(&at_limit).unwrap_err());
        assert!(
            !e.contains("limit"),
            "exactly 4096 is allowed to get further: {e}"
        );
    }

    #[test]
    fn a_vendor_table_longer_than_one_page_pushes_the_bootconfig_back() {
        // 40 entries * 108 bytes = 4320 bytes = 2 pages of 4096
        let entries: Vec<(usize, u32, &'static str)> =
            (0..40).map(|_| (100usize, 1u32, "e")).collect();
        let v = Vendor {
            version: 4,
            page: 4096,
            ramdisk: 0,
            dtb: 100,
            entries,
            bootconfig: 77,
        };
        let img = v.build();
        let i = parse_bytes(&img).unwrap();
        assert_eq!(get(&i, "vendor_ramdisk_table_size"), 4320u64);
        assert_eq!(slice_of(&img, &i, "bootconfig"), data(8, 77));
        let ramdisk_pages = (40 * 100usize).div_ceil(4096) as u64;
        let (at, _) = sec(&i, "bootconfig").unwrap();
        assert_eq!(
            at,
            4096 * (1 + ramdisk_pages + 1 + 2),
            "header + ramdisk + dtb + 2 table pages"
        );
        assert_eq!(slice_of(&img, &i, "vendor_ramdisk39"), data(10 + 39, 100));
    }

    #[test]
    fn sections_that_overflow_or_run_off_the_file_are_named_in_the_error() {
        let mut img = Boot::new(1).build();
        put32(&mut img, 1632, 10);
        put64(&mut img, 1636, u64::MAX - 2);
        let e = format!("{:#}", parse_bytes(&img).unwrap_err());
        assert!(e.contains("section end overflows"), "{e}");
        let mut img = Boot::new(1).build();
        put32(&mut img, 1632, 10);
        put64(&mut img, 1636, 1 << 40);
        let e = format!("{:#}", parse_bytes(&img).unwrap_err());
        assert!(
            e.contains("recovery_dtbo") && e.contains("runs past the end"),
            "{e}"
        );
    }

    #[test]
    fn sections_with_no_data_are_omitted_and_pages_are_respected() {
        let mut b = Boot::new(1);
        b.ramdisk = 0;
        b.page = 4096;
        let img = b.build();
        let i = parse_bytes(&img).unwrap();
        assert!(
            sec(&i, "ramdisk").is_none()
                && sec(&i, "second").is_none()
                && sec(&i, "recovery_dtbo").is_none()
        );
        assert_eq!(sec(&i, "kernel"), Some((4096, 5000)));
        // a ramdisk starts on the next page boundary after the kernel
        let mut b = Boot::new(0);
        b.kernel = 2049;
        let i = parse_bytes(&b.build()).unwrap();
        assert_eq!(sec(&i, "ramdisk"), Some((2048 + 4096, 3000)));
        b.kernel = 2048;
        assert_eq!(
            sec(&parse_bytes(&b.build()).unwrap(), "ramdisk"),
            Some((2048 + 2048, 3000))
        );
    }

    #[test]
    fn bad_boot_headers_are_rejected_with_a_reason() {
        let good = Boot::new(2).build();
        let patch = |at: usize, v: u32| {
            let mut b = good.clone();
            put32(&mut b, at, v);
            b
        };
        let e = |img: Vec<u8>| format!("{:#}", parse_bytes(&img).unwrap_err());
        assert!(e(patch(40, 5)).contains("unsupported boot image header version 5"));
        assert!(e(patch(40, u32::MAX)).contains("unsupported boot image header version"));
        assert!(e(patch(36, 0)).contains("unsupported page size 0"));
        assert!(e(patch(36, 3000)).contains("unsupported page size 3000"));
        assert!(e(patch(36, 1 << 30)).contains("unsupported page size"));
        assert!(e(patch(8, u32::MAX)).contains("runs past the end"));
        assert!(e(patch(16, u32::MAX)).contains("runs past the end"));
        assert!(e(good[..30].to_vec()).contains("header"));
        assert!(e(good[..1000].to_vec()).contains("header"));
        assert!(e(b"ANDROID?".iter().copied().chain([0u8; 4096]).collect()).contains("bad magic"));
        assert!(e(vec![]).contains("too short"));
        let v3 = Boot::new(3).build();
        assert!(e(v3[..500].to_vec()).contains("header"));
        let v4 = Boot::new(4).build();
        let mut cut = v4.clone();
        cut.truncate(44 + 1536 + 2);
        assert!(e(cut).contains("header"));
    }

    #[test]
    fn a_section_that_runs_past_the_file_is_an_error_at_every_cut() {
        let mut b = Boot::new(2);
        b.second = 1000;
        b.dtbo = 600;
        b.dtb = 500;
        let img = b.build();
        assert!(parse_bytes(&img).is_ok());
        let last_data = img.iter().rposition(|&x| x != 0).unwrap();
        for cut in [last_data, last_data - 100, 6000, 4097, 2049] {
            assert!(
                parse_bytes(&img[..cut]).is_err(),
                "cut at {cut} of {}",
                img.len()
            );
        }
    }

    #[test]
    fn huge_sizes_cannot_overflow_the_layout() {
        let mut img = Boot::new(2).build();
        put32(&mut img, 8, u32::MAX);
        put32(&mut img, 16, u32::MAX);
        put32(&mut img, 24, u32::MAX);
        put32(&mut img, 1632, u32::MAX);
        put64(&mut img, 1636, u64::MAX - 10);
        put32(&mut img, 1648, u32::MAX);
        let e = format!("{:#}", parse_bytes(&img).unwrap_err());
        assert!(e.contains("past the end") || e.contains("overflow"), "{e}");
    }

    struct Vendor {
        version: u32,
        page: usize,
        ramdisk: usize,
        dtb: usize,
        entries: Vec<(usize, u32, &'static str)>, // (size, type, name) for v4
        bootconfig: usize,
    }

    impl Vendor {
        fn build(&self) -> Vec<u8> {
            let page = self.page;
            let mut h = vec![0u8; page.max(4096)];
            h[..8].copy_from_slice(b"VNDRBOOT");
            put32(&mut h, 8, self.version);
            put32(&mut h, 12, page as u32);
            put32(&mut h, 16, 0x8000);
            put32(&mut h, 20, 0x1000000);
            put_str(&mut h, 28, "androidboot.x=1");
            put32(&mut h, 2076, 0x100);
            put_str(&mut h, 2080, "vb");
            let header_size = if self.version == 3 { 2112 } else { 2128 };
            put32(&mut h, 2096, header_size);
            put32(&mut h, 2100, self.dtb as u32);
            put64(&mut h, 2104, 0x1f00000);
            let total: usize = if self.version == 3 {
                self.ramdisk
            } else {
                self.entries.iter().map(|e| e.0).sum()
            };
            put32(&mut h, 24, total as u32);
            let entry_size = 108usize;
            if self.version == 4 {
                put32(&mut h, 2112, (self.entries.len() * entry_size) as u32);
                put32(&mut h, 2116, self.entries.len() as u32);
                put32(&mut h, 2120, entry_size as u32);
                put32(&mut h, 2124, self.bootconfig as u32);
            }
            h.truncate(page.max(header_size as usize).div_ceil(page) * page);
            let mut img = h;
            let mut ramdisk = Vec::new();
            let mut table = Vec::new();
            if self.version == 3 {
                ramdisk = data(1, self.ramdisk);
            } else {
                for (i, (size, ty, name)) in self.entries.iter().enumerate() {
                    let mut e = vec![0u8; entry_size];
                    put32(&mut e, 0, *size as u32);
                    put32(&mut e, 4, ramdisk.len() as u32);
                    put32(&mut e, 8, *ty);
                    put_str(&mut e, 12, name);
                    put32(&mut e, 44, 0xB0 + i as u32);
                    table.extend(e);
                    ramdisk.extend(data(10 + i as u8, *size));
                }
            }
            img.extend(&ramdisk);
            pad_to(&mut img, page);
            img.extend(data(7, self.dtb));
            pad_to(&mut img, page);
            img.extend(&table);
            pad_to(&mut img, page);
            img.extend(data(8, self.bootconfig));
            pad_to(&mut img, page);
            img
        }
    }

    #[test]
    fn vendor_boot_v3_has_one_ramdisk_and_a_dtb() {
        let v = Vendor {
            version: 3,
            page: 4096,
            ramdisk: 9000,
            dtb: 1500,
            entries: vec![],
            bootconfig: 0,
        };
        let img = v.build();
        let i = parse_bytes(&img).unwrap();
        assert_eq!(get(&i, "kind"), "vendor_boot");
        assert_eq!(get(&i, "header_version"), 3u64);
        assert_eq!(get(&i, "cmdline"), "androidboot.x=1");
        assert_eq!(get(&i, "product_name"), "vb");
        assert_eq!(get(&i, "tags_load_address"), 0x100u64);
        assert_eq!(slice_of(&img, &i, "vendor_ramdisk"), data(1, 9000));
        assert_eq!(slice_of(&img, &i, "dtb"), data(7, 1500));
        assert_eq!(i.sections.len(), 2);
    }

    #[test]
    fn vendor_boot_v4_has_a_table_of_ramdisks_and_a_bootconfig() {
        let v = Vendor {
            version: 4,
            page: 4096,
            ramdisk: 0,
            dtb: 800,
            entries: vec![
                (5000, 1, "platform"),
                (300, 3, "dlkm"),
                (7000, 2, "recovery"),
            ],
            bootconfig: 250,
        };
        let img = v.build();
        let i = parse_bytes(&img).unwrap();
        assert_eq!(slice_of(&img, &i, "vendor_ramdisk00"), data(10, 5000));
        assert_eq!(slice_of(&img, &i, "vendor_ramdisk01"), data(11, 300));
        assert_eq!(slice_of(&img, &i, "vendor_ramdisk02"), data(12, 7000));
        assert_eq!(slice_of(&img, &i, "dtb"), data(7, 800));
        assert_eq!(slice_of(&img, &i, "bootconfig"), data(8, 250));
        let table = get(&i, "vendor_ramdisk_table").as_array().unwrap();
        assert_eq!(table.len(), 3);
        assert_eq!(table[1]["name"], "dlkm");
        assert_eq!(table[1]["type"], 3);
        assert_eq!(table[2]["offset"], 5300);
        assert_eq!(table[0]["board_id"][0], 0xB0);
        assert_eq!(table[0]["file"], "vendor_ramdisk00");
    }

    #[test]
    fn vendor_boot_page_sizes_other_than_4096_work() {
        for page in [2048usize, 8192, 16384] {
            let v = Vendor {
                version: 4,
                page,
                ramdisk: 0,
                dtb: 100,
                entries: vec![(3000, 1, "a")],
                bootconfig: 64,
            };
            let img = v.build();
            let i = parse_bytes(&img).unwrap_or_else(|e| panic!("page {page}: {e:#}"));
            assert_eq!(
                slice_of(&img, &i, "vendor_ramdisk00"),
                data(10, 3000),
                "page {page}"
            );
            assert_eq!(slice_of(&img, &i, "bootconfig"), data(8, 64), "page {page}");
            assert_eq!(slice_of(&img, &i, "dtb"), data(7, 100), "page {page}");
        }
    }

    #[test]
    fn hostile_vendor_tables_are_rejected() {
        let v = Vendor {
            version: 4,
            page: 4096,
            ramdisk: 0,
            dtb: 100,
            entries: vec![(100, 1, "a"), (100, 1, "b")],
            bootconfig: 10,
        };
        let good = v.build();
        assert!(parse_bytes(&good).is_ok());
        let e = |img: Vec<u8>| format!("{:#}", parse_bytes(&img).unwrap_err());
        let patch = |at: usize, val: u32| {
            let mut b = good.clone();
            put32(&mut b, at, val);
            b
        };
        assert!(e(patch(2116, MAX_TABLE_ENTRIES + 1)).contains("over the limit"));
        assert!(e(patch(2116, u32::MAX)).contains("over the limit"));
        assert!(e(patch(2120, 50)).contains("too small"));
        assert!(e(patch(2120, u32::MAX)).contains("table"));
        assert!(e(patch(8, 2)).contains("unsupported vendor boot header version 2"));
        assert!(e(patch(8, 5)).contains("unsupported vendor boot header version 5"));
        assert!(e(patch(12, 0)).contains("unsupported page size"));
        let huge = e(patch(24, u32::MAX));
        assert!(
            huge.contains("reading vendor ramdisk table entry 0"),
            "{huge}"
        );
        assert!(e(good[..1000].to_vec()).contains("header"));
        assert!(e(good[..2120].to_vec()).contains("header"));
        let mut offset_bomb = good.clone();
        let table_at = 4096 * 3; // header page, ramdisk page, dtb page
        put32(&mut offset_bomb, table_at + 4, u32::MAX);
        assert!(e(offset_bomb).contains("past the end"));
        let mut zero_entries = good.clone();
        put32(&mut zero_entries, 2116, 0);
        put32(&mut zero_entries, 2120, 0);
        assert!(
            parse_bytes(&zero_entries).is_ok(),
            "an empty table is valid"
        );
    }

    #[test]
    fn no_truncation_of_any_image_panics() {
        let mut b = Boot::new(2);
        b.second = 500;
        b.dtbo = 300;
        b.dtb = 200;
        let boot = b.build();
        let vendor = Vendor {
            version: 4,
            page: 4096,
            ramdisk: 0,
            dtb: 100,
            entries: vec![(100, 1, "a")],
            bootconfig: 10,
        }
        .build();
        for img in [boot, vendor] {
            for cut in (0..img.len()).step_by(37).chain(0..70) {
                let _ = parse_bytes(&img[..cut]);
            }
        }
    }

    fn scratch(tag: &str) -> PathBuf {
        let dir =
            std::env::temp_dir().join(format!("android-doctor-boot-{}-{tag}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn names(dir: &Path) -> Vec<String> {
        let mut v: Vec<String> = std::fs::read_dir(dir)
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        v.sort();
        v
    }

    #[test]
    fn writing_sections_produces_the_right_files_and_refuses_to_overwrite() {
        let mut b = Boot::new(1);
        b.second = 800;
        b.dtbo = 100;
        let img = b.build();
        let dir = scratch("write");
        let input = dir.join("boot.img");
        std::fs::write(&input, &img).unwrap();
        let image = read(&input).unwrap();
        let out = dir.join("out");
        let paths = write_sections(&input, &image, &out, false).unwrap();
        assert_eq!(
            names(&out),
            ["kernel", "ramdisk", "recovery_dtbo", "second"]
        );
        assert_eq!(paths.len(), 4);
        assert_eq!(std::fs::read(out.join("kernel")).unwrap(), data(1, 5000));
        assert_eq!(std::fs::read(out.join("second")).unwrap(), data(3, 800));
        std::fs::write(out.join("kernel"), b"mine").unwrap();
        let e = write_sections(&input, &image, &out, false)
            .unwrap_err()
            .to_string();
        assert!(e.contains("kernel") && e.contains("--force"), "{e}");
        assert_eq!(
            std::fs::read(out.join("kernel")).unwrap(),
            b"mine",
            "a refused run changes nothing"
        );
        write_sections(&input, &image, &out, true).unwrap();
        assert_eq!(std::fs::read(out.join("kernel")).unwrap(), data(1, 5000));
        assert!(names(&out).iter().all(|n| !n.ends_with(".part")));
    }

    #[cfg(unix)]
    #[test]
    fn planted_symlinks_are_not_written_through() {
        use std::os::unix::fs::symlink;
        let img = Boot::new(0).build();
        let dir = scratch("sym");
        let input = dir.join("boot.img");
        std::fs::write(&input, &img).unwrap();
        let image = read(&input).unwrap();
        let out = dir.join("out");
        std::fs::create_dir_all(&out).unwrap();
        let victim = dir.join("victim");
        symlink(&victim, out.join("kernel.part")).unwrap();
        write_sections(&input, &image, &out, false).unwrap();
        assert!(!victim.exists());
        symlink(dir.join("nowhere"), out.join("ramdisk2")).unwrap();
        std::fs::remove_file(out.join("ramdisk")).unwrap();
        symlink(dir.join("nowhere2"), out.join("ramdisk")).unwrap();
        let e = write_sections(&input, &image, &out, false)
            .unwrap_err()
            .to_string();
        assert!(e.contains("ramdisk") && e.contains("--force"), "{e}");
    }

    #[test]
    fn a_failed_write_leaves_no_part_files() {
        let img = Boot::new(0).build();
        let dir = scratch("fail");
        let input = dir.join("boot.img");
        std::fs::write(&input, &img).unwrap();
        let image = read(&input).unwrap();
        // cut the file after parsing: the copy must notice and clean up
        std::fs::write(&input, &img[..img.len() - 5000]).unwrap();
        let out = dir.join("out");
        assert!(write_sections(&input, &image, &out, false).is_err());
        assert!(names(&out).is_empty(), "{:?}", names(&out));
    }

    #[cfg(unix)]
    #[test]
    fn a_fifo_is_refused_at_once_instead_of_blocking() {
        let dir = scratch("fifo");
        let fifo = dir.join("pipe");
        assert!(
            std::process::Command::new("mkfifo")
                .arg(&fifo)
                .status()
                .unwrap()
                .success()
        );
        let (tx, rx) = std::sync::mpsc::channel();
        let path = fifo.clone();
        std::thread::spawn(move || {
            let _ = tx.send(read(&path).map(|_| ()).map_err(|e| format!("{e:#}")));
        });
        let res = rx
            .recv_timeout(std::time::Duration::from_secs(20))
            .expect("unpack blocked on a FIFO");
        assert!(res.unwrap_err().contains("FIFO or socket"));
    }

    #[test]
    fn a_directory_and_a_missing_path_get_clear_errors() {
        let dir = scratch("dirs");
        let e = read(&dir).unwrap_err().to_string();
        assert!(e.contains("is a directory"), "{e}");
        let e = format!("{:#}", read(&dir.join("missing")).unwrap_err());
        assert!(e.contains("opening") || e.contains("No such file"), "{e}");
        std::fs::write(dir.join("empty"), b"").unwrap();
        assert!(
            read(&dir.join("empty"))
                .unwrap_err()
                .to_string()
                .contains("too short")
        );
    }

    #[test]
    fn text_and_json_rendering() {
        let mut b = Boot::new(2);
        b.dtb = 100;
        let i = parse_bytes(&b.build()).unwrap();
        let text = to_text(&i);
        assert!(
            text.contains("header_version  2") || text.contains("header_version"),
            "{text}"
        );
        assert!(
            text.lines()
                .any(|l| l.starts_with("kernel_load_address") && l.ends_with("  0x01080000")),
            "{text}"
        );
        assert!(text.contains("os_version"), "{text}");
        assert!(
            text.contains("sections:") && text.contains("kernel") && text.contains("dtb"),
            "{text}"
        );
        let j = to_json(&i);
        assert_eq!(j["header_version"], 2);
        assert_eq!(j["sections"][0]["name"], "kernel");
        assert_eq!(j["sections"][0]["offset"], 2048);
        assert_eq!(j["os_version"], "11.2.3");
        let none = to_text(
            &parse_bytes(&{
                let mut b = Boot::new(0);
                b.os = 0;
                b.build()
            })
            .unwrap(),
        );
        assert!(
            none.contains("os_version") && none.contains("none"),
            "{none}"
        );
        let v = Vendor {
            version: 4,
            page: 4096,
            ramdisk: 0,
            dtb: 10,
            entries: vec![(10, 1, "x")],
            bootconfig: 4,
        };
        let t = to_text(&parse_bytes(&v.build()).unwrap());
        assert!(
            t.contains("vendor_ramdisk_table:") && t.contains("vendor_ramdisk00"),
            "{t}"
        );
    }
}
