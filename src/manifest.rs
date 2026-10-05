//! Qualcomm `rawprogram*.xml` and MediaTek `scatter.txt` flash manifests.
//!
//! Both describe which image file belongs at which offset on the flash. This module parses
//! them and cross-checks them against the image files actually present, because a manifest
//! referencing a missing image - or an image no manifest mentions - is exactly the kind of
//! silent gap that makes a firmware set untrustworthy.
use anyhow::{Context, Result, ensure};
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

/// One partition as described by a manifest.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Partition {
    pub label: String,
    /// The image file this partition is flashed from, if the manifest names one.
    pub filename: Option<String>,
    pub start_sector: u64,
    pub num_sectors: u64,
    pub sparse: bool,
}

/// Which manifest dialect was parsed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    Rawprogram,
    Scatter,
}

impl Kind {
    pub fn name(self) -> &'static str {
        match self {
            Kind::Rawprogram => "rawprogram.xml",
            Kind::Scatter => "scatter.txt",
        }
    }
}

/// A parsed manifest plus what it implies about the directory it sits in.
#[derive(Debug, Clone)]
pub struct Manifest {
    pub kind: Kind,
    pub sector_size: u64,
    pub partitions: Vec<Partition>,
    /// Manifests reference files that are not present.
    pub missing_images: Vec<String>,
    /// Image files present that no partition references.
    pub unreferenced_images: Vec<String>,
}

/// Find and parse whichever manifest is present in `dir`.
pub fn read(dir: &Path, sector_size: u64) -> Result<Manifest> {
    if let Some(xml) = find(dir, "rawprogram", ".xml") {
        let text = std::fs::read_to_string(&xml)?;
        return build(Kind::Rawprogram, dir, &text, sector_size);
    }
    let scatter = dir.join("scatter.txt");
    if scatter.is_file() {
        let text = std::fs::read_to_string(&scatter)?;
        return build(Kind::Scatter, dir, &text, sector_size);
    }
    anyhow::bail!(
        "no rawprogram*.xml or scatter.txt found in {}",
        dir.display()
    );
}

/// The first file in `dir` whose name starts with `prefix` and ends with `suffix`.
fn find(dir: &Path, prefix: &str, suffix: &str) -> Option<PathBuf> {
    let mut hits: Vec<PathBuf> = std::fs::read_dir(dir)
        .ok()?
        .filter_map(|e| e.ok())
        .map(|e| e.path())
        .filter(|p| {
            let n = p.file_name().and_then(|s| s.to_str()).unwrap_or_default();
            n.starts_with(prefix) && n.ends_with(suffix)
        })
        .collect();
    hits.sort();
    hits.into_iter().next()
}

fn build(kind: Kind, dir: &Path, text: &str, sector_size: u64) -> Result<Manifest> {
    let partitions = match kind {
        Kind::Rawprogram => parse_rawprogram(text)?,
        Kind::Scatter => parse_scatter(text)?,
    };
    let referenced: BTreeSet<String> = partitions
        .iter()
        .filter_map(|p| p.filename.clone())
        .collect();
    let missing_images: Vec<String> = referenced
        .iter()
        .filter(|f| !dir.join(f).is_file())
        .cloned()
        .collect();
    let mut unreferenced_images: Vec<String> = std::fs::read_dir(dir)?
        .filter_map(|e| e.ok())
        .filter(|e| e.file_type().map(|t| t.is_file()).unwrap_or(false))
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .filter(|n| is_image_name(n))
        .filter(|n| !referenced.contains(n))
        .collect();
    unreferenced_images.sort();
    Ok(Manifest {
        kind,
        sector_size,
        partitions,
        missing_images,
        unreferenced_images,
    })
}

fn is_image_name(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    [".img", ".raw", ".bin"].iter().any(|e| lower.ends_with(e))
}

/// Parse a MediaTek `scatter.txt`.
///
/// Lines are `<name> start_sector size [NAND] [FILE] [type]`, with `#` comments and
/// blank lines skipped.
pub fn parse_scatter(text: &str) -> Result<Vec<Partition>> {
    let mut out = Vec::new();
    for (n, line) in text.lines().enumerate() {
        let line = line.split('#').next().unwrap_or("").trim();
        if line.is_empty() {
            continue;
        }
        let parts: Vec<&str> = line.split_whitespace().collect();
        ensure!(
            parts.len() >= 3,
            "scatter.txt line {}: expected at least 3 fields",
            n + 1
        );
        let start_sector = parts[1]
            .parse::<u64>()
            .with_context(|| format!("scatter.txt line {}: bad start sector", n + 1))?;
        let num_sectors = parts[2]
            .parse::<u64>()
            .with_context(|| format!("scatter.txt line {}: bad sector count", n + 1))?;
        // A file is named by its extension; NAND and type markers are not files.
        let filename = parts
            .iter()
            .skip(3)
            .find(|p| is_image_name(p))
            .map(|p| (*p).to_string());
        let sparse = line.to_ascii_uppercase().contains("SPARSE");
        out.push(Partition {
            label: parts[0].to_string(),
            filename,
            start_sector,
            num_sectors,
            sparse,
        });
    }
    Ok(out)
}

// ---------------------------------------------------------------------------
// rawprogram*.xml
// ---------------------------------------------------------------------------

/// Parse a Qualcomm `rawprogram*.xml`.
///
/// The <program> element shape is fixed and well known (AOSP rawprogram.xml, Apache-2.0), so a
/// targeted scanner is used rather than pulling in a full XML dependency. It tolerates any
/// attribute order, arbitrary whitespace, XML comments and both quoting styles, and reports a
/// clear error on malformed input rather than panicking.
pub fn parse_rawprogram(text: &str) -> Result<Vec<Partition>> {
    let stripped = strip_comments(text);
    ensure!(
        stripped.contains("<program"),
        "no <program> elements: this does not look like a rawprogram.xml"
    );
    let mut out = Vec::new();
    let mut at = 0usize;
    while let Some(start) = stripped[at..].find("<program") {
        let tag_start = at + start;
        let after = tag_start + "<program".len();
        // Reject <programX> by requiring whitespace or '>' next.
        let next = stripped[after..].chars().next();
        ensure!(
            next.is_none_or(|c| c.is_whitespace() || c == '>' || c == '/'),
            "malformed <program element at byte {tag_start}"
        );
        let tag_end = match stripped[tag_start..].find('>') {
            Some(i) => tag_start + i,
            None => anyhow::bail!("unterminated <program element at byte {tag_start}"),
        };
        let attrs = &stripped[after..tag_end];
        let num_sectors = attr(attrs, "num_sectors")?
            .parse::<u64>()
            .context("bad num_sectors")?;
        let start_sector = attr(attrs, "start_sector")?
            .parse::<u64>()
            .context("bad start_sector")?;
        let label = attr(attrs, "label")?.to_string();
        let filename = match attr(attrs, "filename") {
            Ok(f) => Some(f.to_string()),
            Err(_) => None,
        };
        let sparse = attr(attrs, "sparse")
            .map(|v| v.eq_ignore_ascii_case("true") || v == "1")
            .unwrap_or(false);
        out.push(Partition {
            label,
            filename,
            start_sector,
            num_sectors,
            sparse,
        });
        at = tag_end + 1;
    }
    ensure!(
        !out.is_empty(),
        "rawprogram.xml contains no <program> elements"
    );
    Ok(out)
}

/// Remove XML comments so a commented-out partition is not parsed.
fn strip_comments(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut rest = text;
    while let Some(start) = rest.find("<!--") {
        out.push_str(&rest[..start]);
        match rest[start + 4..].find("-->") {
            Some(end) => rest = &rest[start + 4 + end + 3..],
            None => return out,
        }
    }
    out.push_str(rest);
    out
}

/// One attribute value out of a start tag, tolerating either quote style.
fn attr<'a>(tag: &'a str, name: &str) -> Result<&'a str> {
    let mut search = tag;
    loop {
        let at = match search.find(name) {
            Some(i) => i,
            None => anyhow::bail!("<program> has no {name} attribute"),
        };
        let before_ok = at == 0
            || tag[..at]
                .chars()
                .next_back()
                .is_none_or(|c| c.is_whitespace());
        let after = &search[at + name.len()..];
        let trimmed = after.trim_start();
        let value = if let Some(rest) = trimmed.strip_prefix('=') {
            let rest = rest.trim_start();
            let quote = rest.chars().next().filter(|c| *c == '"' || *c == '\'');
            match quote {
                Some(q) => rest[1..].split(q).next().unwrap_or_default(),
                None => rest.split_whitespace().next().unwrap_or_default(),
            }
        } else {
            // Name matched but it was not an attribute (e.g. inside another name).
            search = &search[at + name.len()..];
            continue;
        };
        if before_ok && !value.is_empty() {
            return Ok(value);
        }
        search = &search[at + name.len()..];
    }
}

/// Human-readable rendering of a manifest.
pub fn to_text(m: &Manifest) -> String {
    let mut o = Vec::new();
    o.push(format!(
        "{}: {} partitions, sector size {}",
        m.kind.name(),
        m.partitions.len(),
        m.sector_size
    ));
    let width = m
        .partitions
        .iter()
        .map(|p| p.label.len())
        .max()
        .unwrap_or(6);
    for p in &m.partitions {
        let mut line = format!(
            "  {:width$}  sector {:>10}  {:>10} sectors  {:>12} bytes",
            p.label,
            p.start_sector,
            p.num_sectors,
            p.num_sectors * m.sector_size,
            width = width
        );
        if let Some(f) = &p.filename {
            line.push_str(&format!("  {f}"));
        }
        if p.sparse {
            line.push_str("  [sparse: needs unsparsing before it can be read]");
        }
        o.push(line);
    }
    if !m.missing_images.is_empty() {
        o.push(format!(
            "missing images ({}): {}",
            m.missing_images.len(),
            m.missing_images.join(", ")
        ));
    }
    if !m.unreferenced_images.is_empty() {
        o.push(format!(
            "unreferenced images ({}): {}",
            m.unreferenced_images.len(),
            m.unreferenced_images.join(", ")
        ));
    }
    if m.missing_images.is_empty() && m.unreferenced_images.is_empty() {
        o.push("every manifest image is present and every image is referenced".to_string());
    }
    o.join("\n")
}

#[cfg(test)]
mod tests {
    use super::*;

    const XML: &str = r#"<?xml version="1.0" encoding="utf-8"?>
<!-- a commented-out partition: <program start_sector="0" num_sectors="0" filename="no.img"/> -->
<data>
  <program SECTOR_SIZE_IN_BYTES="4096"
           start_sector="1024" num_sectors="2048"
           filename="boot.img" label="boot" sparse="false"/>
  <program start_sector='3072' num_sectors='512' filename='system.img' label='system' sparse='true'/>
</data>"#;

    #[test]
    fn a_rawprogram_file_parses_to_its_partitions() {
        let p = parse_rawprogram(XML).unwrap();
        assert_eq!(p.len(), 2);
        assert_eq!(p[0].label, "boot");
        assert_eq!(p[0].start_sector, 1024);
        assert_eq!(p[0].num_sectors, 2048);
        assert_eq!(p[0].filename.as_deref(), Some("boot.img"));
        assert!(!p[0].sparse);
        assert_eq!(p[1].label, "system");
        assert!(p[1].sparse, "sparse=true must be honoured");
        assert_eq!(p[1].filename.as_deref(), Some("system.img"));
    }

    #[test]
    fn attribute_order_and_quoting_do_not_matter() {
        let a = parse_rawprogram(
            r#"<program label="x" filename="x.img" num_sectors="8" start_sector="4"/>"#,
        )
        .unwrap();
        let b = parse_rawprogram(
            r#"<program start_sector='4' num_sectors='8' filename='x.img' label='x'/>"#,
        )
        .unwrap();
        assert_eq!(a, b);
    }

    #[test]
    fn a_commented_out_partition_is_not_parsed() {
        let p = parse_rawprogram(XML).unwrap();
        assert!(p.iter().all(|x| x.filename.as_deref() != Some("no.img")));
    }

    #[test]
    fn malformed_xml_is_an_error_not_a_panic() {
        assert!(parse_rawprogram("not xml at all").is_err());
        assert!(parse_rawprogram(r#"<program start_sector="1""#).is_err());
        assert!(parse_rawprogram(r#"<program filename="x.img"/>"#).is_err());
    }

    #[test]
    fn a_scatter_file_parses_with_comments_and_blank_lines() {
        let text = "# header\n\nboot 1024 2048\n# a note\nsystem 3072 512 NAND\n  \n";
        let p = parse_scatter(text).unwrap();
        assert_eq!(p.len(), 2);
        assert_eq!(p[0].label, "boot");
        assert_eq!(p[0].start_sector, 1024);
        assert_eq!(p[0].num_sectors, 2048);
        assert_eq!(p[1].label, "system");
        assert!(
            p[1].filename.is_none(),
            "scatter names no separate image file"
        );
    }
    #[test]
    fn a_sparse_scatter_marker_is_reported() {
        let p = parse_scatter("boot 0 100 boot.img SPARSE").unwrap();
        assert!(p[0].sparse);
    }

    #[test]
    fn a_malformed_scatter_line_is_an_error_not_a_panic() {
        assert!(parse_scatter("boot 0").is_err());
        assert!(parse_scatter("boot notanumber 100").is_err());
    }

    #[test]
    fn a_missing_image_is_reported_rather_than_skipped() {
        let d = crate::testutil::Scratch::new("man-missing");
        std::fs::write(d.join("rawprogram.xml"), XML).unwrap();
        std::fs::write(d.join("boot.img"), b"x").unwrap();
        // system.img is referenced but absent.
        let m = read(&d, 4096).unwrap();
        assert_eq!(m.missing_images, vec!["system.img".to_string()]);
    }

    #[test]
    fn an_unreferenced_image_is_reported() {
        let d = crate::testutil::Scratch::new("man-unref");
        std::fs::write(d.join("rawprogram.xml"), XML).unwrap();
        std::fs::write(d.join("boot.img"), b"x").unwrap();
        std::fs::write(d.join("system.img"), b"x").unwrap();
        std::fs::write(d.join("stray.img"), b"x").unwrap();
        let m = read(&d, 4096).unwrap();
        assert!(m.missing_images.is_empty());
        assert_eq!(m.unreferenced_images, vec!["stray.img".to_string()]);
    }

    #[test]
    fn a_directory_with_no_manifest_is_a_clear_error() {
        let d = crate::testutil::Scratch::new("man-none");
        assert!(read(&d, 4096).is_err());
    }
}
