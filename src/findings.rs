//! The shared reporting layer.
//!
//! `audit` and `doctor scan` produce two different finding types with two different severity
//! models. Both convert into [`Finding`] here, and everything that reports on findings (the
//! health [`score`], the `--baseline` diff, SARIF, the terminal digest, the `--json` rows) reads
//! only this type, so there is one definition of "how bad", "the same finding" and "how healthy".
//!
//! # Severity scale
//!
//! One ascending scale, `info < warn < medium < high < error`:
//!
//! | source                                  | unified  |
//! | --------------------------------------- | -------- |
//! | doctor `error` (firmware unusable or tampered) | `error`  |
//! | audit `High`, content hit `high`        | `high`   |
//! | audit `Medium`, content hit `medium`    | `medium` |
//! | audit `Warn`, doctor `warn`             | `warn`   |
//! | audit `Info`, doctor `info`, other hits | `info`   |
//!
//! # Fingerprint
//!
//! `sha256(rule \0 scope \0 subject \0 key)`, first 16 hex digits. `scope` is the image name
//! (file stem) when the finding is inside an image, `subject` is the path or name inside it
//! (leading `/` and `./` removed, `\` turned into `/`), and `key` separates findings that share a
//! subject (an init service name, a property key, the text of a content hit). The message, counts,
//! ordering, timestamps and any host path are never part of it, so a re-scan of the same firmware
//! from another directory, or after an unrelated image changed, yields the same fingerprints.

use crate::audit::{self, ImageAudit};
use crate::doctor;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Severity {
    Info,
    Warn,
    Medium,
    High,
    Error,
}

impl Severity {
    pub fn name(self) -> &'static str {
        match self {
            Severity::Info => "info",
            Severity::Warn => "warn",
            Severity::Medium => "medium",
            Severity::High => "high",
            Severity::Error => "error",
        }
    }

    /// Doctor and content-hit severities are strings. Unknown text is the lowest severity.
    fn from_name(s: &str) -> Self {
        match s {
            "error" => Severity::Error,
            "high" => Severity::High,
            "medium" => Severity::Medium,
            "warn" => Severity::Warn,
            _ => Severity::Info,
        }
    }

    fn from_audit(s: audit::Severity) -> Self {
        match s {
            audit::Severity::High => Severity::High,
            audit::Severity::Medium => Severity::Medium,
            audit::Severity::Warn => Severity::Warn,
            audit::Severity::Info => Severity::Info,
        }
    }

    /// Points a rule costs the health score. `info` is free.
    fn weight(self) -> u32 {
        match self {
            Severity::Error => 20,
            Severity::High => 10,
            Severity::Medium => 5,
            Severity::Warn => 2,
            Severity::Info => 0,
        }
    }

    fn sarif_level(self) -> &'static str {
        match self {
            Severity::Error | Severity::High => "error",
            Severity::Medium | Severity::Warn => "warning",
            Severity::Info => "note",
        }
    }
}

/// One finding on the unified model.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Finding {
    pub rule: String,
    /// `security` or `quality`.
    pub category: String,
    pub severity: Severity,
    /// Image the finding is in (file stem); empty for directory-level findings.
    pub scope: String,
    /// Path or name inside the image (or file name in the scanned directory), as the tool printed it.
    pub subject: String,
    /// Separates findings with the same rule and subject. Part of the fingerprint only.
    pub key: String,
    pub message: String,
    pub remedy: Option<String>,
    /// The rule did not run (it says "cannot evaluate"). Never a pass: it costs score points
    /// and a baseline never suppresses it.
    pub gap: bool,
    /// `scope/subject` when the finding names a file a SARIF consumer could open.
    pub uri: Option<String>,
    pub fingerprint: String,
}

fn norm_subject(s: &str) -> String {
    let s = s.trim().replace('\\', "/");
    let mut s = s.as_str();
    while let Some(rest) = s.strip_prefix("./").or_else(|| s.strip_prefix('/')) {
        s = rest;
    }
    s.to_string()
}

fn fingerprint(rule: &str, scope: &str, subject: &str, key: &str) -> String {
    let mut h = Sha256::new();
    for part in [rule, scope, &norm_subject(subject), key] {
        h.update(part.as_bytes());
        h.update([0]);
    }
    h.finalize()[..8]
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

impl Finding {
    /// Fill in the derived fields. `located` says the subject is a file path.
    fn seal(mut self, located: bool) -> Self {
        self.fingerprint = fingerprint(&self.rule, &self.scope, &self.subject, &self.key);
        let subject = norm_subject(&self.subject);
        self.uri = (located && !subject.is_empty()).then(|| {
            if self.scope.is_empty() {
                subject
            } else {
                format!("{}/{subject}", self.scope)
            }
        });
        self
    }

    /// One row of the `--json` output. Superset of the original `doctor scan --json` row.
    pub fn to_json(&self) -> Value {
        let mut v = json!({
            "id": self.rule,
            "category": self.category,
            "severity": self.severity.name(),
            "subject": self.subject,
            "message": self.message,
            "remedy": self.remedy,
            "fingerprint": self.fingerprint,
        });
        if !self.scope.is_empty() {
            v["image"] = json!(self.scope);
        }
        v
    }
}

/// Rules whose audit summary finding is replaced by one finding per content hit.
const CONTENT_RULES: &[&str] = &[
    "hardcoded_credentials",
    "cloud_credentials",
    "debug_endpoints",
    "content-indicator",
];

/// Convert audit results. Content hits become one finding each (with their path); the audit's own
/// one-line content summary is dropped so nothing is counted twice.
pub fn from_audit(audits: &[ImageAudit]) -> Vec<Finding> {
    let mut out = Vec::new();
    for a in audits {
        for (f, (subject, key)) in a.findings.iter().zip(&a.finding_keys) {
            if CONTENT_RULES.contains(&f.rule) {
                continue;
            }
            out.push(
                Finding {
                    rule: f.rule.to_string(),
                    category: "security".into(),
                    severity: Severity::from_audit(f.severity),
                    scope: a.name.clone(),
                    subject: subject.clone(),
                    key: key.clone(),
                    message: f.detail.clone(),
                    remedy: help(f.rule).map(|h| h.remedy.to_string()),
                    gap: false,
                    uri: None,
                    fingerprint: String::new(),
                }
                .seal(!subject.is_empty()),
            );
        }
        for c in &a.content_findings {
            out.push(
                Finding {
                    rule: c.rule.clone(),
                    category: "security".into(),
                    severity: Severity::from_name(&c.severity),
                    scope: a.name.clone(),
                    subject: c.path.clone(),
                    key: c.detail.clone(),
                    message: c.detail.clone(),
                    remedy: help(&c.rule).map(|h| h.remedy.to_string()),
                    gap: false,
                    uri: None,
                    fingerprint: String::new(),
                }
                .seal(true),
            );
        }
    }
    out
}

/// Convert doctor results (see `doctor::scan_scoped`).
pub fn from_doctor(scoped: Vec<(doctor::Finding, Option<String>)>) -> Vec<Finding> {
    scoped
        .into_iter()
        .map(|(f, scope)| {
            let gap = doctor::is_gap(&f);
            // Which subjects are files: in-image paths for these two rules, and top-level files
            // for the rest, except the "images" placeholder and a partition that is missing.
            let located = match (f.id.as_str(), scope.is_some()) {
                ("mode_anomalies" | "debug_leftovers", _) => true,
                ("unhandled_input" | "avb_signature", _) => true,
                ("partition_coverage", _) => false,
                (_, false) => gap && f.subject.ends_with(".img"),
                _ => false,
            };
            Finding {
                rule: f.id,
                category: f.category,
                severity: Severity::from_name(&f.severity),
                scope: scope.unwrap_or_default(),
                subject: f.subject,
                key: String::new(),
                message: f.message,
                remedy: f.remedy,
                gap,
                uri: None,
                fingerprint: String::new(),
            }
            .seal(located)
        })
        .collect()
}

// ---------------------------------------------------------------------------
// Rule catalogue (SARIF rule help, audit remedies)
// ---------------------------------------------------------------------------

pub struct Help {
    pub short: &'static str,
    pub remedy: &'static str,
    pub severity: Severity,
}

/// What each rule means and how to fix it. Doctor findings carry their own remedy; this feeds the
/// SARIF `rules` table and gives the audit rules (which have none of their own) a remedy.
pub fn help(rule: &str) -> Option<Help> {
    use Severity::*;
    let (short, remedy, severity) = match rule {
        "debuggable-build" => (
            "Build is debuggable: adbd runs as root",
            "Ship a user build with ro.debuggable=0",
            High,
        ),
        "insecure-adb" => (
            "ro.secure=0: adbd keeps root",
            "Set ro.secure=1 in the shipped build",
            High,
        ),
        "adb-unauthenticated" => (
            "ro.adb.secure=0: ADB connections need no authorization",
            "Set ro.adb.secure=1",
            High,
        ),
        "adb-root" => (
            "service.adb.root=1 starts adbd as root",
            "Remove service.adb.root from the build properties",
            High,
        ),
        "test-keys" => (
            "Image is signed with the public AOSP test keys",
            "Re-sign the release with a private release key",
            Medium,
        ),
        "debug-build-type" => (
            "Build type is userdebug or eng",
            "Ship a build with ro.build.type=user",
            Medium,
        ),
        "adb-by-default" => (
            "ADB is enabled by default",
            "Drop adb from persist.sys.usb.config and persist.service.adb.enable",
            Medium,
        ),
        "su-binary" => (
            "A su binary ships in the image",
            "Remove the su binary and its SELinux domain",
            High,
        ),
        "writable-setuid" => (
            "A setuid/setgid file is writable by group or others",
            "chmod the file to remove group and other write bits",
            High,
        ),
        "world-writable" => (
            "Regular files are world-writable",
            "chmod the files to remove the write bit for others",
            Medium,
        ),
        "adbd-service" => (
            "adbd is declared as an init service",
            "Confirm adbd is only started by an authorised trigger",
            Medium,
        ),
        "su-service" => (
            "An init service runs in the su SELinux domain",
            "Remove the service or move it out of the su domain",
            High,
        ),
        "shell-service" => (
            "An init service runs a shell or in the shell domain",
            "Remove the service or confine it to a dedicated domain",
            Medium,
        ),
        "setuid-files" => (
            "The image contains setuid/setgid files",
            "Review each setuid file and drop the bit where it is not needed",
            Info,
        ),
        "file-capabilities" => (
            "Files carry file capabilities",
            "Review each capability grant",
            Info,
        ),
        "hardcoded_credentials" => (
            "A private key is embedded in the image",
            "Remove the key from the image and rotate it",
            High,
        ),
        "cloud_credentials" => (
            "A cloud access key is embedded in the image",
            "Remove the credential from the image and revoke it",
            High,
        ),
        "debug_endpoints" => (
            "A debug endpoint is referenced in the image",
            "Remove the debug hook from production firmware",
            Medium,
        ),
        "content-indicator" => (
            "A security indicator was found in a file's bytes",
            "Inspect the file",
            Info,
        ),
        "partition_coverage" => (
            "An expected partition image is missing",
            "Make sure system, vendor and boot images are all present",
            Warn,
        ),
        "unhandled_input" => (
            "A file has no handler and will not be extracted",
            "Inspect it manually",
            Warn,
        ),
        "avb_signature" => (
            "Android Verified Boot signature status",
            "Sign the vbmeta image with a trusted key, or point doctor at a directory holding vbmeta.img",
            Warn,
        ),
        "duplicate_properties" => (
            "A property is defined in more than one file",
            "Remove the duplicate so the effective value is unambiguous",
            Warn,
        ),
        "selinux_label_gaps" => (
            "Files have no SELinux label",
            "Relabel the image, or confirm it is not SELinux-enforcing",
            Warn,
        ),
        "mode_anomalies" => (
            "A file has an unexpected mode",
            "chmod it to remove the write bit for others",
            Warn,
        ),
        "init_service_hygiene" => (
            "An init service is declared more than once",
            "Keep one definition",
            Warn,
        ),
        "debug_leftovers" => (
            "A test or leftover artefact ships in the image",
            "Remove the file from the production image",
            Warn,
        ),
        _ => return None,
    };
    Some(Help {
        short,
        remedy,
        severity,
    })
}

// ---------------------------------------------------------------------------
// Score
// ---------------------------------------------------------------------------

/// Points a rule that could not evaluate costs, once per rule however many images it missed.
const GAP_WEIGHT: u32 = 3;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Score {
    pub value: u32,
    pub label: &'static str,
    pub gaps: usize,
}

impl Score {
    pub fn to_json(&self) -> Value {
        json!({"value": self.value, "label": self.label, "coverage_gaps": self.gaps})
    }
}

/// The 0-100 health score, a pure function of the findings.
///
/// `100 - penalty`, floored at 0, where findings are grouped by rule and each group costs its
/// worst severity's weight (error 20, high 10, medium 5, warn 2, info 0) for the first finding
/// plus a quarter of that for each further one, capped at twice the weight, so one noisy rule
/// cannot sink the score alone. A rule that could not run (a coverage gap) costs a flat 3 however
/// many images it missed, so a scan whose rules could not run never reaches 100. Labels: 90+ `good`, 60+ `needs work`, else `critical`; a `good`
/// score with gaps is `incomplete`.
pub fn score(findings: &[Finding]) -> Score {
    let mut groups: BTreeMap<(&str, bool), (Severity, u32)> = BTreeMap::new();
    for f in findings {
        let g = groups.entry((&f.rule, f.gap)).or_insert((f.severity, 0));
        g.0 = g.0.max(f.severity);
        g.1 += 1;
    }
    let quarters: u32 = groups
        .iter()
        .map(|((_, gap), (sev, n))| {
            if *gap {
                return 4 * GAP_WEIGHT;
            }
            let w = sev.weight();
            (4 * w + (n - 1) * w).min(8 * w)
        })
        .sum();
    let value = 100u32.saturating_sub(quarters.div_ceil(4));
    let gaps = findings.iter().filter(|f| f.gap).count();
    let label = match value {
        90.. if gaps > 0 => "incomplete",
        90.. => "good",
        60.. => "needs work",
        _ => "critical",
    };
    Score { value, label, gaps }
}

// ---------------------------------------------------------------------------
// Flat text
// ---------------------------------------------------------------------------

/// The flat findings list; the same lines `doctor scan` has always printed.
pub fn render_flat(findings: &[Finding]) -> String {
    let mut lines = Vec::new();
    for f in findings {
        lines.push(format!(
            "{} {} {}: {}: {}",
            f.severity.name(),
            f.category,
            f.rule,
            f.subject,
            f.message
        ));
        if let Some(r) = &f.remedy {
            lines.push(format!("    └ {r}"));
        }
    }
    lines.join("\n")
}

// ---------------------------------------------------------------------------
// SARIF 2.1.0
// ---------------------------------------------------------------------------

/// Percent-encode a relative path for use as a URI reference. `/` stays, as do the RFC 3986
/// unreserved characters.
fn uri_encode(path: &str) -> String {
    let mut out = String::new();
    for b in path.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' | b'/' => {
                out.push(b as char)
            }
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

/// SARIF 2.1.0 for `findings`. `score` is the health score of the whole scan; `baselined` marks
/// every result `baselineState: "new"` (the list was already filtered against a baseline).
pub fn to_sarif(findings: &[Finding], score: &Score, baselined: bool) -> Value {
    let mut ids: BTreeSet<&str> = BTreeSet::new();
    ids.extend(findings.iter().map(|f| f.rule.as_str()));
    ids.extend(KNOWN_RULES.iter().copied());
    let ids: Vec<&str> = ids.into_iter().collect();
    let index: BTreeMap<&str, usize> = ids.iter().enumerate().map(|(i, r)| (*r, i)).collect();

    let rules: Vec<Value> = ids
        .iter()
        .map(|id| {
            // A rule the catalogue does not know (it should not happen) still gets help from the
            // first finding that names it.
            let seen = findings.iter().find(|f| f.rule == *id);
            let (short, remedy, level) = match help(id) {
                Some(h) => (
                    h.short.to_string(),
                    h.remedy.to_string(),
                    h.severity.sarif_level(),
                ),
                None => (
                    seen.map_or_else(|| id.to_string(), |f| f.message.clone()),
                    seen.and_then(|f| f.remedy.clone()).unwrap_or_default(),
                    seen.map_or("note", |f| f.severity.sarif_level()),
                ),
            };
            let mut rule = json!({
                "id": id,
                "name": id,
                "shortDescription": {"text": short},
                "fullDescription": {"text": short},
                "defaultConfiguration": {"level": level},
            });
            if !remedy.is_empty() {
                rule["help"] = json!({"text": remedy});
            }
            rule
        })
        .collect();

    let results: Vec<Value> = findings
        .iter()
        .map(|f| {
            let mut r = json!({
                "ruleId": f.rule,
                "ruleIndex": index[f.rule.as_str()],
                "level": f.severity.sarif_level(),
                "message": {"text": if f.message.is_empty() { &f.rule } else { &f.message }},
                "partialFingerprints": {"androidDoctorFinding/v1": f.fingerprint},
                "properties": {
                    "severity": f.severity.name(),
                    "category": f.category,
                    "coverageGap": f.gap,
                },
            });
            if let Some(uri) = &f.uri {
                r["locations"] = json!([{
                    "physicalLocation": {"artifactLocation": {"uri": uri_encode(uri)}}
                }]);
            }
            if baselined {
                r["baselineState"] = json!("new");
            }
            r
        })
        .collect();

    json!({
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {
                "name": "android-doctor",
                "version": env!("CARGO_PKG_VERSION"),
                "informationUri": "https://github.com/Vaibhav91one/android-doctor",
                "rules": rules,
            }},
            "results": results,
            "properties": {"score": score.to_json()},
        }],
    })
}

/// Every rule id the tool can emit, so the SARIF rules table is complete even for a clean run.
const KNOWN_RULES: &[&str] = &[
    "debuggable-build",
    "insecure-adb",
    "adb-unauthenticated",
    "adb-root",
    "test-keys",
    "debug-build-type",
    "adb-by-default",
    "su-binary",
    "writable-setuid",
    "world-writable",
    "adbd-service",
    "su-service",
    "shell-service",
    "setuid-files",
    "file-capabilities",
    "hardcoded_credentials",
    "cloud_credentials",
    "debug_endpoints",
    "partition_coverage",
    "unhandled_input",
    "avb_signature",
    "duplicate_properties",
    "selinux_label_gaps",
    "mode_anomalies",
    "init_service_hygiene",
    "debug_leftovers",
];

#[cfg(test)]
mod tests {
    use super::*;

    fn f(rule: &str, sev: Severity, scope: &str, subject: &str) -> Finding {
        Finding {
            rule: rule.into(),
            category: "security".into(),
            severity: sev,
            scope: scope.into(),
            subject: subject.into(),
            key: String::new(),
            message: format!("{rule} msg"),
            remedy: Some("fix it".into()),
            gap: false,
            uri: None,
            fingerprint: String::new(),
        }
        .seal(!subject.is_empty())
    }

    fn gap(rule: &str) -> Finding {
        let mut g = f(rule, Severity::Info, "", "images");
        g.gap = true;
        g.uri = None;
        g
    }

    #[test]
    fn severity_scale_orders_and_maps() {
        assert!(Severity::Error > Severity::High && Severity::High > Severity::Medium);
        assert!(Severity::Medium > Severity::Warn && Severity::Warn > Severity::Info);
        assert_eq!(Severity::from_name("error"), Severity::Error);
        assert_eq!(Severity::from_name("nonsense"), Severity::Info);
        assert_eq!(Severity::from_audit(audit::Severity::High), Severity::High);
        assert_eq!(Severity::Error.sarif_level(), "error");
        assert_eq!(Severity::High.sarif_level(), "error");
        assert_eq!(Severity::Medium.sarif_level(), "warning");
        assert_eq!(Severity::Warn.sarif_level(), "warning");
        assert_eq!(Severity::Info.sarif_level(), "note");
    }

    #[test]
    fn fingerprint_ignores_message_slashes_and_order_but_not_scope_or_key() {
        let a = f("su-binary", Severity::High, "system", "/xbin/su");
        let mut b = f("su-binary", Severity::High, "system", "xbin/su");
        b.message = "different words".into();
        assert_eq!(a.fingerprint, b.fingerprint);
        assert_eq!(a.fingerprint.len(), 16);
        let other_image = f("su-binary", Severity::High, "vendor", "xbin/su");
        assert_ne!(a.fingerprint, other_image.fingerprint);
        let mut keyed = a.clone();
        keyed.key = "x".into();
        keyed = keyed.seal(true);
        assert_ne!(a.fingerprint, keyed.fingerprint);
        // backslashes and ./ normalise too
        assert_eq!(
            fingerprint("r", "s", ".\\a\\b", ""),
            fingerprint("r", "s", "a/b", "")
        );
    }

    #[test]
    fn uri_is_scope_slash_path_and_percent_encoded_in_sarif() {
        let a = f("su-binary", Severity::High, "system", "/my dir/su");
        assert_eq!(a.uri.as_deref(), Some("system/my dir/su"));
        assert_eq!(uri_encode("system/my dir/su#1"), "system/my%20dir/su%231");
        assert_eq!(f("x", Severity::Info, "", "").uri, None);
    }

    #[test]
    fn score_is_100_only_when_clean_and_never_negative() {
        assert_eq!(score(&[]).value, 100);
        assert_eq!(score(&[]).label, "good");
        let one_high = score(&[f("a", Severity::High, "i", "p")]);
        assert_eq!((one_high.value, one_high.label), (90, "good"));
        let many: Vec<_> = (0..40)
            .map(|i| f(&format!("r{i}"), Severity::Error, "i", "p"))
            .collect();
        assert_eq!(score(&many).value, 0);
        assert_eq!(score(&many).label, "critical");
    }

    #[test]
    fn a_noisy_rule_is_capped_and_a_gap_blocks_100() {
        // 100 findings of one medium rule cost at most 2x its weight (10), not 500
        let noisy: Vec<_> = (0..100)
            .map(|i| f("world-writable", Severity::Medium, "i", &format!("p{i}")))
            .collect();
        assert_eq!(score(&noisy).value, 90);
        // first finding full price, second a quarter: 5 + 1.25 -> ceil 7
        let two = score(&noisy[..2]);
        assert_eq!(two.value, 93);
        // info is free, a gap is not
        let info = score(&[f("setuid-files", Severity::Info, "i", "")]);
        assert_eq!(info.value, 100);
        let g = score(&[gap("avb_signature")]);
        assert_eq!((g.value, g.label, g.gaps), (97, "incomplete", 1));
    }

    #[test]
    fn score_does_not_depend_on_order() {
        let mut v = vec![
            f("a", Severity::High, "i", "1"),
            f("b", Severity::Warn, "i", "2"),
            f("a", Severity::Medium, "i", "3"),
            gap("c"),
        ];
        let s1 = score(&v);
        v.reverse();
        assert_eq!(s1, score(&v));
    }

    #[test]
    fn flat_text_matches_the_original_doctor_lines() {
        let mut a = f("avb_signature", Severity::Warn, "", "vbmeta.img");
        a.category = "security".into();
        a.message = "image is unsigned".into();
        a.remedy = Some("sign it".into());
        assert_eq!(
            render_flat(&[a]),
            "warn security avb_signature: vbmeta.img: image is unsigned\n    └ sign it"
        );
    }

    /// The SARIF 2.1.0 properties this emitter relies on, per the spec's required-property rules.
    #[test]
    fn sarif_carries_every_required_2_1_0_property() {
        let list = vec![
            f("su-binary", Severity::High, "system", "xbin/su"),
            gap("avb_signature"),
        ];
        let s = score(&list);
        let v = to_sarif(&list, &s, true);
        assert_eq!(v["version"], "2.1.0");
        assert!(
            v["$schema"]
                .as_str()
                .unwrap()
                .ends_with("sarif-schema-2.1.0.json")
        );
        let runs = v["runs"].as_array().unwrap();
        assert_eq!(runs.len(), 1);
        let driver = &runs[0]["tool"]["driver"];
        assert_eq!(driver["name"], "android-doctor");
        assert_eq!(driver["version"], env!("CARGO_PKG_VERSION"));
        assert!(
            driver["informationUri"]
                .as_str()
                .unwrap()
                .starts_with("https://")
        );
        let rules = driver["rules"].as_array().unwrap();
        let ids: Vec<&str> = rules.iter().map(|r| r["id"].as_str().unwrap()).collect();
        let mut sorted = ids.clone();
        sorted.sort();
        sorted.dedup();
        assert_eq!(ids, sorted, "rule ids unique");
        let su = rules.iter().find(|r| r["id"] == "su-binary").unwrap();
        assert!(su["help"]["text"].as_str().unwrap().contains("su binary"));
        for r in rules {
            assert!(r["shortDescription"]["text"].is_string());
            assert!(
                ["error", "warning", "note"]
                    .contains(&r["defaultConfiguration"]["level"].as_str().unwrap())
            );
        }
        let results = runs[0]["results"].as_array().unwrap();
        assert_eq!(results.len(), 2);
        for r in results {
            // result.message is required; ruleId must resolve to the rules table
            assert!(r["message"]["text"].is_string());
            let idx = r["ruleIndex"].as_u64().unwrap() as usize;
            assert_eq!(rules[idx]["id"], r["ruleId"]);
            assert_eq!(r["baselineState"], "new");
            assert!(r["partialFingerprints"]["androidDoctorFinding/v1"].is_string());
        }
        assert_eq!(results[0]["level"], "error");
        assert_eq!(results[1]["level"], "note");
        let loc = &results[0]["locations"][0]["physicalLocation"]["artifactLocation"];
        assert_eq!(loc["uri"], "system/xbin/su");
        assert!(
            results[1].get("locations").is_none(),
            "no location rather than a fake one"
        );
        assert_eq!(runs[0]["properties"]["score"]["value"], 87);
        assert_eq!(runs[0]["properties"]["score"]["coverage_gaps"], 1);
        // no null where the schema wants a string
        assert!(!serde_json::to_string(&v).unwrap().contains("null"));
    }
}
