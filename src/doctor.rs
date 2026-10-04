//! `doctor`: a deterministic health scan of an OTA or firmware directory.
//!
//! Findings are either `security` or `quality`. A rule that cannot evaluate emits a finding
//! saying so - it never silently passes. That property is the point of this command: SR Labs
//! extractor logged "Ignoring file ... since no handler matches" for two partitions, returned
//! half the firmware, and exited 0.

use anyhow::Result;
use std::path::Path;

/// One thing worth telling the user about the firmware.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Finding {
    pub id: String,
    pub category: String,
    pub severity: String,
    pub subject: String,
    pub message: String,
    pub remedy: Option<String>,
}

/// Files a block OTA legitimately ships that are neither partitions nor partition data. These are
/// looked at, understood, and deliberately not extracted: reporting them as failures would make
/// the tool fail on every real update.
const KNOWN_OTA_FILES: &[&str] = &["cert.pem", "payload_properties.txt"];

/// Suffixes of OTA scaffolding. These arrive named after the partition they belong to
/// (`system.patch.dat`, `vendor.inf`), so they must be matched as suffixes, not names.
const KNOWN_OTA_SUFFIXES: &[&str] = &[
    ".patch.dat",
    ".patch.dat.br",
    ".inf",
    ".properties",
    ".signature",
    ".signature1",
    ".signature2",
    ".rsa",
    ".dsa",
];

/// Directories that ship inside an OTA and hold signing metadata rather than partitions.
const KNOWN_OTA_DIRS: &[&str] = &["META-INF"];

/// Helper scripts some vendors include alongside the images (e.g. `sdat2img.py`).
const KNOWN_OTA_SCRIPTS: &[&str] = &["sdat2img.py", "sdat2img.sh", "extractor.sh"];

/// True when `name` is recognised OTA scaffolding: something we looked at on purpose and
/// deliberately did not extract, as opposed to a file we simply have no handler for.
fn is_known_scaffolding(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    if KNOWN_OTA_FILES.iter().any(|f| lower == *f) {
        return true;
    }
    if KNOWN_OTA_SUFFIXES.iter().any(|e| lower.ends_with(e)) {
        return true;
    }
    if lower.ends_with(".transfer.list") || lower.contains(".new.dat") {
        return true;
    }
    if KNOWN_OTA_SCRIPTS.iter().any(|f| lower == *f) {
        return true;
    }
    let first = lower.split('/').next().unwrap_or(&lower);
    KNOWN_OTA_DIRS.contains(&first)
}

/// R2: unhandled_input - flag top-level files not belonging to any known partition type.
pub fn unhandled_input(dir: &Path) -> Result<Vec<Finding>> {
    let mut findings = Vec::new();
    let entries = std::fs::read_dir(dir)?;
    for entry in entries {
        let entry = entry?;
        // Only regular files can be "unhandled input". A directory such as META-INF is part
        // of the OTA container, not something we failed to classify.
        if !entry.file_type().map(|t| t.is_file()).unwrap_or(false) {
            continue;
        }
        let name = entry.file_name().to_string_lossy().into_owned();
        if is_known_scaffolding(&name) {
            continue;
        }
        // *.img are partition images, not unhandled.
        if name.to_ascii_lowercase().ends_with(".img") {
            continue;
        }
        findings.push(Finding {
            id: "unhandled_input".to_string(),
            category: "security".to_string(),
            severity: "warn".to_string(),
            subject: name,
            message: "no handler for this file; it will not be extracted".to_string(),
            remedy: Some("inspect it manually".to_string()),
        });
    }
    Ok(findings)
}

/// Scan `dir` and return every finding.
pub fn scan(dir: &Path) -> Result<Vec<Finding>> {
    let mut findings = Vec::new();
    findings.extend(partition_coverage(dir)?);
    findings.extend(unhandled_input(dir)?);
    findings.extend(avb_signature(dir)?);
    Ok(findings)
}

/// The partition images expected at the top level of an unpacked block OTA.
const EXPECTED_PARTITIONS: &[&str] = &["system", "vendor", "boot"];

/// R1: partition_coverage - check that expected top-level images are present.
pub fn partition_coverage(dir: &Path) -> Result<Vec<Finding>> {
    // A partition counts as present if it is either an extracted .img OR still encoded as
    // <name>.transfer.list + <name>.new.dat - which is what an unpacked OTA directory looks like.
    let mut names: Vec<String> = Vec::new();
    for entry in std::fs::read_dir(dir)? {
        let entry = entry?;
        // Only regular files can be "unhandled input"; a directory such as META-INF is
        // part of the OTA container, not something we failed to classify.
        let is_file = entry.file_type().map(|t| t.is_file()).unwrap_or(false);
        if !is_file {
            continue;
        }
        let name = entry.file_name().to_string_lossy().into_owned();
        let lower = name.to_ascii_lowercase();
        if lower.ends_with(".img") {
            names.push(name);
        } else if let Some(stem) = name.strip_suffix(".transfer.list") {
            names.push(format!("{stem}.img"));
        }
    }

    let mut findings = Vec::new();
    if names.is_empty() {
        findings.push(Finding {
            id: "partition_coverage".to_string(),
            category: "quality".to_string(),
            severity: "error".to_string(),
            subject: "images".to_string(),
            message: "this does not look like an unpacked firmware: no .img files found"
                .to_string(),
            remedy: Some("extract or point doctor at the OTA directory".to_string()),
        });
        return Ok(findings);
    }

    for expected in EXPECTED_PARTITIONS {
        let wanted = format!("{expected}.img");
        let present = names.iter().any(|n| n.eq_ignore_ascii_case(&wanted));
        if !present {
            findings.push(Finding {
                id: "partition_coverage".to_string(),
                category: "quality".to_string(),
                severity: "warn".to_string(),
                subject: wanted,
                message: format!("expected partition image {expected} is missing"),
                remedy: Some(format!(
                    "ensure {expected}.img is present; the device may not boot without it"
                )),
            });
        }
    }
    Ok(findings)
}

/// R3: avb_signature - inspect vbmeta.img signature status if present.
pub fn avb_signature(dir: &Path) -> Result<Vec<Finding>> {
    use crate::avb::{SignatureStatus, read_input};
    let path = dir.join("vbmeta.img");
    if !path.is_file() {
        // No vbmeta.img — this rule cannot evaluate, emit an "unknown" finding
        // rather than silently passing.
        return Ok(vec![Finding {
            id: "avb_signature".to_string(),
            category: "security".to_string(),
            severity: "info".to_string(),
            subject: "vbmeta.img".to_string(),
            message: "no vbmeta.img found; AVB signature not checked".to_string(),
            remedy: Some("point doctor at a directory containing vbmeta.img".to_string()),
        }]);
    }

    let meta = match read_input(&path, None) {
        Ok(m) => m,
        Err(e) => {
            return Ok(vec![Finding {
                id: "avb_signature".to_string(),
                category: "security".to_string(),
                severity: "info".to_string(),
                subject: "vbmeta.img".to_string(),
                message: format!("could not read vbmeta.img: {e:#}"),
                remedy: Some("inspect it manually".to_string()),
            }]);
        }
    };

    let (severity, message, remedy) = match meta.signature_verified {
        SignatureStatus::Valid => (
            "info".to_string(),
            "AVB signature verified".to_string(),
            None,
        ),
        SignatureStatus::Invalid => (
            "error".to_string(),
            "signature does not verify — image may be tampered or corrupted".to_string(),
            Some("reflash from a known-good source and re-extract vbmeta.img".to_string()),
        ),
        SignatureStatus::Absent => (
            "warn".to_string(),
            "image is unsigned; verified boot proves nothing".to_string(),
            Some(
                "sign the vbmeta image or accept that the device enforces no verified boot"
                    .to_string(),
            ),
        ),
        SignatureStatus::Unsupported(n) => (
            "warn".to_string(),
            format!("AVB algorithm {n} is not checked — signature status unknown"),
            Some("use a tool that supports this AVB algorithm to verify the signature".to_string()),
        ),
    };

    Ok(vec![Finding {
        id: "avb_signature".to_string(),
        category: "security".to_string(),
        severity,
        subject: "vbmeta.img".to_string(),
        message,
        remedy,
    }])
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::Scratch;

    fn fresh_dir(tag: &str) -> Scratch {
        Scratch::new(&format!("doctor-{tag}"))
    }

    fn write_files(dir: &std::path::Path, files: &[(&str, &[u8])]) {
        for (name, body) in files {
            std::fs::write(dir.join(name), body).unwrap();
        }
    }

    #[test]
    fn coverage_with_expected_images_has_no_error_severity() {
        let dir = fresh_dir("coverage-ok");
        write_files(
            &dir,
            &[
                ("system.img", b"system"),
                ("vendor.img", b"vendor"),
                ("boot.img", b"boot"),
            ],
        );
        let findings = scan(&dir).unwrap();
        assert!(
            !findings.iter().any(|f| f.severity == "error"),
            "should not produce an error for a complete set of images: {:?}",
            findings
        );
    }

    #[test]
    fn unhandled_input_fires_for_unknown_files() {
        let dir = fresh_dir("mystery");
        write_files(&dir, &[("mystery.bin", b"unknown")]);
        let findings = unhandled_input(&dir).unwrap();
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].id, "unhandled_input");
        assert_eq!(findings[0].severity, "warn");
        assert_eq!(findings[0].subject, "mystery.bin");
    }

    #[test]
    fn no_images_at_all_is_an_error() {
        let dir = fresh_dir("no-images");
        write_files(&dir, &[("readme.txt", b"hello")]);
        let findings = partition_coverage(&dir).unwrap();
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].id, "partition_coverage");
        assert_eq!(findings[0].severity, "error");
        assert!(findings[0].message.contains("no .img files"));
    }

    /// Regression: an unpacked OTA directory holds system.transfer.list + system.new.dat.br,
    /// not system.img. Coverage must not report those partitions as missing.
    #[test]
    fn transfer_list_partitions_count_as_present() {
        let d = Scratch::new("doc-tl");
        for f in [
            "system.transfer.list",
            "system.new.dat.br",
            "vendor.transfer.list",
            "vendor.new.dat.br",
            "boot.img",
        ] {
            std::fs::write(d.join(f), b"x").unwrap();
        }
        let findings = partition_coverage(&d).unwrap();
        assert!(
            !findings.iter().any(|f| f.message.contains("system")),
            "system is present as a transfer list: {findings:?}"
        );
        assert!(
            !findings.iter().any(|f| f.severity == "error"),
            "a normal unpacked OTA is not an error: {findings:?}"
        );
    }

    /// Regression: META-INF is a directory in the OTA, not an unhandled file.
    #[test]
    fn directories_are_not_unhandled_input() {
        let d = Scratch::new("doc-dir");
        std::fs::create_dir(d.join("META-INF")).unwrap();
        std::fs::write(d.join("boot.img"), b"x").unwrap();
        let findings = unhandled_input(&d).unwrap();
        assert!(
            findings.is_empty(),
            "directories must not be flagged: {findings:?}"
        );
    }

    #[test]
    fn scan_emits_findings_when_no_vbmeta_present() {
        let dir = fresh_dir("no-vbmeta");
        write_files(
            &dir,
            &[
                ("system.img", b"system"),
                ("vendor.img", b"vendor"),
                ("boot.img", b"boot"),
            ],
        );
        let findings = scan(&dir).unwrap();
        // R3 cannot evaluate — there is no vbmeta.img — so it must emit a finding
        // rather than silently passing.
        assert!(
            findings
                .iter()
                .any(|f| f.id == "avb_signature" && f.severity == "info"),
            "scan must emit an 'unknown' finding when a rule cannot evaluate: {:?}",
            findings
        );
    }
}
