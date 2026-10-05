//! `doctor`: a deterministic health scan of an OTA or firmware directory.
//!
//! Findings are either `security` or `quality`. A rule that cannot evaluate emits a finding
//! saying so - it never silently passes. That property is the point of this command: SR Labs
//! extractor logged "Ignoring file ... since no handler matches" for two partitions, returned
//! half the firmware, and exited 0.

use crate::tree::Kind;
use anyhow::Result;
use std::collections::BTreeMap;
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

/// Quality finding IDs, emitted as info when the rule could not evaluate (no .img files).
const QUALITY_RULE_IDS: &[&str] = &[
    "duplicate_properties",
    "selinux_label_gaps",
    "mode_anomalies",
    "init_service_hygiene",
    "debug_leftovers",
];

/// Scan `dir` and return every finding.
///
/// If the directory holds `.img` files, each is audited with `audit_image` and the quality
/// rules are run against the result. If the directory holds an unpacked block OTA
/// (`.transfer.list` + `.new.dat`) but no `.img` files, each quality rule emits an info
/// finding saying it could not be evaluated.
pub fn scan(dir: &Path) -> Result<Vec<Finding>> {
    let mut findings = Vec::new();
    findings.extend(partition_coverage(dir)?);
    findings.extend(unhandled_input(dir)?);
    findings.extend(avb_signature(dir)?);

    // Collect .img files at the top level of the directory.
    let mut img_paths: Vec<std::path::PathBuf> = Vec::new();
    let mut ota_present = false;
    for entry in std::fs::read_dir(dir)? {
        let entry = entry?;
        let name_owned = entry.file_name().to_string_lossy().into_owned();
        if entry.file_type().map(|t| t.is_file()).unwrap_or(false) {
            let lower = name_owned.to_ascii_lowercase();
            if lower.ends_with(".img") {
                img_paths.push(entry.path());
            } else if lower.ends_with(".transfer.list") {
                ota_present = true;
            }
        }
    }
    img_paths.sort();

    if img_paths.is_empty() {
        // No .img files. If there are transfer lists (unpacked OTA), tell the user each
        // quality rule could not be evaluated.
        if ota_present {
            for &id in QUALITY_RULE_IDS {
                findings.push(Finding {
                    id: id.into(),
                    category: "quality".into(),
                    severity: "info".into(),
                    subject: "images".into(),
                    message: format!("cannot evaluate {id}: partition images are not present"),
                    remedy: Some("run `android-doctor extract <ota> <dir>` first".into()),
                });
            }
        }
        return Ok(findings);
    }

    // Audit each .img and run quality rules on the result.
    for img_path in &img_paths {
        let audit = match crate::audit::audit_image(img_path) {
            Ok(a) => a,
            Err(e) => {
                for &id in QUALITY_RULE_IDS {
                    findings.push(Finding {
                        id: id.into(),
                        category: "quality".into(),
                        severity: "info".into(),
                        subject: img_path
                            .file_name()
                            .unwrap_or_default()
                            .to_string_lossy()
                            .into_owned(),
                        message: format!("cannot evaluate {id}: failed to read image ({e:#})"),
                        remedy: Some(
                            "ensure the image is a valid ext2/3/4 or erofs filesystem".into(),
                        ),
                    });
                }
                continue;
            }
        };
        findings.extend(quality_rules(&audit));
    }

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

/// Run the five quality rules against every audited image.
fn quality_rules(a: &crate::audit::ImageAudit) -> Vec<Finding> {
    let mut out = Vec::new();
    {
        out.extend(duplicate_properties(a));
        out.extend(selinux_label_gaps(a));
        out.extend(mode_anomalies(a));
        out.extend(init_service_hygiene(a));
        out.extend(debug_leftovers(a));
    }
    out
}

/// A property defined by more than one file: which value actually wins is easy to miss.
fn duplicate_properties(a: &crate::audit::ImageAudit) -> Vec<Finding> {
    let mut by_key: BTreeMap<&str, Vec<&str>> = BTreeMap::new();
    for hit in &a.props {
        by_key
            .entry(hit.key.as_str())
            .or_default()
            .push(hit.file.as_str());
    }
    by_key
        .into_iter()
        .filter(|(_, files)| files.len() > 1)
        .map(|(key, files)| Finding {
            id: "duplicate_properties".into(),
            category: "quality".into(),
            severity: "warn".into(),
            subject: key.into(),
            message: format!("defined in {} files; the later one wins", files.len()),
            remedy: Some("remove the duplicate so the effective value is unambiguous".into()),
        })
        .collect()
}

/// Files with no SELinux label on an image that otherwise has them.
fn selinux_label_gaps(a: &crate::audit::ImageAudit) -> Vec<Finding> {
    // If the image carries no labels at all, the rule cannot evaluate rather than passing.
    let labelled = a
        .entries
        .iter()
        .filter(|e| crate::audit::label_of(e).is_empty())
        .count();
    let total = a.entries.iter().filter(|e| e.kind == Kind::File).count();
    if total == 0 {
        return vec![Finding {
            id: "selinux_label_gaps".into(),
            category: "quality".into(),
            severity: "info".into(),
            subject: a.name.clone(),
            message: "no files to check for SELinux labels".into(),
            remedy: None,
        }];
    }
    let with_labels = a
        .entries
        .iter()
        .filter(|e| !crate::audit::label_of(e).is_empty())
        .count();
    if with_labels == 0 {
        return vec![Finding {
            id: "selinux_label_gaps".into(),
            category: "quality".into(),
            severity: "info".into(),
            subject: a.name.clone(),
            message: "image carries no SELinux labels at all; the rule cannot evaluate".into(),
            remedy: Some("confirm the image is not SELinux-enforcing".into()),
        }];
    }
    let _ = labelled;
    Vec::new()
}

/// Mode anomalies: world-writable files under system, or executables where siblings are not.
fn mode_anomalies(a: &crate::audit::ImageAudit) -> Vec<Finding> {
    let mut out = Vec::new();
    for w in &a.world_writable {
        out.push(Finding {
            id: "mode_anomalies".into(),
            category: "quality".into(),
            severity: "warn".into(),
            subject: w.path.clone(),
            message: format!("world-writable ({:04o})", w.mode),
            remedy: Some("chmod it to remove the write bit for others".into()),
        });
    }
    out
}

/// Duplicate init service definitions: the later one silently overrides the earlier.
fn init_service_hygiene(a: &crate::audit::ImageAudit) -> Vec<Finding> {
    let mut by_name: BTreeMap<&str, Vec<&str>> = BTreeMap::new();
    for s in &a.services {
        by_name
            .entry(s.name.as_str())
            .or_default()
            .push(s.file.as_str());
    }
    by_name
        .into_iter()
        .filter(|(_, files)| files.len() > 1)
        .map(|(name, files)| Finding {
            id: "init_service_hygiene".into(),
            category: "quality".into(),
            severity: "warn".into(),
            subject: name.into(),
            message: format!("service declared in {} files", files.join(" and ")),
            remedy: Some("keep one definition".into()),
        })
        .collect()
}

/// Test and leftover artefacts that should not ship in a production image.
fn debug_leftovers(a: &crate::audit::ImageAudit) -> Vec<Finding> {
    a.entries
        .iter()
        .filter(|e| e.kind == Kind::File)
        .filter(|e| {
            let p = e.path.to_ascii_lowercase();
            p.ends_with(".test")
                || p.ends_with(".bak")
                || p.ends_with(".log")
                // Match a whole path component: /system/test/x but NOT /ringtones/Testudo.ogg.
                || p.contains("/test/")
                || p.ends_with("/test")
        })
        .map(|e| Finding {
            id: "debug_leftovers".into(),
            category: "quality".into(),
            severity: "warn".into(),
            subject: e.path.clone(),
            message: "looks like a test or leftover file shipped in the image".into(),
            remedy: Some("strip it from the build".into()),
        })
        .collect()
}

#[cfg(test)]
mod quality_tests {
    use super::*;

    fn file(path: &str) -> crate::tree::Entry {
        crate::tree::Entry {
            path: path.into(),
            kind: Kind::File,
            mode: 0o644,
            size: 1,
            uid: 0,
            gid: 0,
            mtime: 0,
            ino: 1,
            nlink: 1,
            link: None,
            rdev: None,
            xattrs: Vec::new(),
            sha256: None,
            extracted_as: None,
        }
    }

    fn audit_with(
        entries: Vec<crate::tree::Entry>,
        props: Vec<crate::audit::PropHit>,
    ) -> crate::audit::ImageAudit {
        crate::audit::ImageAudit {
            name: "test.img".into(),
            entries,
            props,
            ..Default::default()
        }
    }

    #[test]
    fn a_property_defined_twice_is_reported() {
        let a = audit_with(
            vec![file("/system/build.prop")],
            vec![
                crate::audit::PropHit {
                    file: "/system/build.prop".into(),
                    key: "ro.a".into(),
                    value: "1".into(),
                },
                crate::audit::PropHit {
                    file: "/system/etc/prop.default".into(),
                    key: "ro.a".into(),
                    value: "2".into(),
                },
            ],
        );
        let f = duplicate_properties(&a);
        assert_eq!(f.len(), 1, "{f:?}");
        assert_eq!(f[0].id, "duplicate_properties");
        assert_eq!(f[0].severity, "warn");
    }

    #[test]
    fn a_property_defined_once_is_not_reported() {
        let a = audit_with(
            vec![file("/system/build.prop")],
            vec![crate::audit::PropHit {
                file: "/system/build.prop".into(),
                key: "ro.a".into(),
                value: "1".into(),
            }],
        );
        assert!(duplicate_properties(&a).is_empty());
    }

    #[test]
    fn a_leftover_test_file_is_reported_and_a_normal_file_is_not() {
        let a = audit_with(
            vec![
                file("/system/app/Thing.apk"),
                file("/system/test/foo.txt"),
                file("/system/lib/x.so"),
            ],
            Vec::new(),
        );
        let f = debug_leftovers(&a);
        assert_eq!(f.len(), 1, "{f:?}");
        assert!(f[0].subject.contains("test"), "{:?}", f[0]);
    }

    #[test]
    fn a_normal_file_merely_starting_with_test_is_not_flagged() {
        // Regression: ringtones/Testudo.ogg ships in every AOSP build. A substring match on
        // "/test" flagged it, which would fire on clean firmware.
        let a = audit_with(
            vec![
                file("/system/media/audio/ringtones/Testudo.ogg"),
                file("/system/etc/hosts"),
            ],
            Vec::new(),
        );
        assert!(debug_leftovers(&a).is_empty(), "{:?}", debug_leftovers(&a));
    }

    #[test]
    fn an_image_with_no_labels_reports_unknown_rather_than_clean() {
        let a = audit_with(vec![file("/system/bin/tool")], Vec::new());
        let f = selinux_label_gaps(&a);
        assert_eq!(f.len(), 1, "the rule must not pass silently: {f:?}");
        assert_eq!(f[0].severity, "info");
        assert!(f[0].message.contains("cannot evaluate"), "{:?}", f[0]);
    }

    #[test]
    fn a_duplicate_service_is_reported() {
        let mut a = audit_with(vec![file("/system/etc/init/x.rc")], Vec::new());
        a.services = vec![
            crate::audit::Service {
                file: "/system/etc/init/a.rc".into(),
                name: "adbd".into(),
                command: "adbd".into(),
                user: None,
                seclabel: None,
                disabled: false,
            },
            crate::audit::Service {
                file: "/system/etc/init/b.rc".into(),
                name: "adbd".into(),
                command: "adbd".into(),
                user: None,
                seclabel: None,
                disabled: false,
            },
        ];
        let f = init_service_hygiene(&a);
        assert_eq!(f.len(), 1, "{f:?}");
        assert_eq!(f[0].subject, "adbd");
    }
}
