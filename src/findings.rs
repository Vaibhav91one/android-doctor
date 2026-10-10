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

use crate::audit::ImageAudit;
use crate::doctor;
use doctor_core::{BaselineState, Location, LocationKind, Score};
use serde_json::{Value, json};
use std::collections::{BTreeMap, BTreeSet};

pub use doctor_core::Severity;

/// Parse a `--fail-on` value: the doctor/1 names, plus the old `error` and `warn` as aliases.
pub fn parse_fail_on(s: &str) -> Result<Severity, String> {
    Severity::parse_legacy(s)
        .ok_or_else(|| format!("expected one of critical, high, medium, low, info (got {s:?})"))
}

/// Doctor and content-hit severities are strings. Unknown text is the lowest severity.
fn from_name(s: &str) -> Severity {
    Severity::parse_legacy(s).unwrap_or(Severity::Info)
}

/// Points a rule costs the health score. `info` is free.
fn weight(s: Severity) -> u32 {
    match s {
        Severity::Critical => 20,
        Severity::High => 10,
        Severity::Medium => 5,
        Severity::Low => 2,
        Severity::Info => 0,
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
    /// `new` or `unchanged`; set only when a `--baseline` was given.
    pub baseline_state: Option<BaselineState>,
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
    let mut buf = Vec::new();
    for part in [rule, scope, &norm_subject(subject), key] {
        buf.extend_from_slice(part.as_bytes());
        buf.push(0);
    }
    doctor_core::fingerprint(&buf)
}

impl Finding {
    /// Fill in the derived fields. `located` says the subject is a file path.
    pub(crate) fn seal(mut self, located: bool) -> Self {
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

    /// One doctor/1 finding. `subject` and `image` are extra keys kept from the old rows.
    pub fn to_core(&self) -> doctor_core::Finding {
        let location = if let Some(uri) = &self.uri {
            Location::new(LocationKind::File, uri.clone())
        } else if !self.scope.is_empty() || !self.subject.is_empty() {
            let r = [self.scope.as_str(), self.subject.as_str()]
                .iter()
                .filter(|p| !p.is_empty())
                .copied()
                .collect::<Vec<_>>()
                .join("/");
            Location::new(LocationKind::Image, r)
        } else {
            Location::new(LocationKind::None, "")
        };
        let mut extra = serde_json::Map::new();
        extra.insert("subject".into(), json!(self.subject));
        if !self.scope.is_empty() {
            extra.insert("image".into(), json!(self.scope));
        }
        doctor_core::Finding {
            id: self.rule.clone(),
            fingerprint: self.fingerprint.clone(),
            severity: self.severity,
            confidence: None,
            category: self.category.clone(),
            message: self.message.clone(),
            location,
            evidence: Vec::new(),
            remedy: self.remedy.clone(),
            baseline_state: self.baseline_state,
            extra,
        }
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
                    severity: f.severity.unified(),
                    scope: a.name.clone(),
                    subject: subject.clone(),
                    key: key.clone(),
                    message: f.detail.clone(),
                    remedy: help(f.rule).map(|h| h.remedy.to_string()),
                    gap: false,
                    uri: None,
                    fingerprint: String::new(),
                    baseline_state: None,
                }
                .seal(!subject.is_empty()),
            );
        }
        for c in &a.content_findings {
            out.push(
                Finding {
                    rule: c.rule.clone(),
                    category: "security".into(),
                    severity: from_name(&c.severity),
                    scope: a.name.clone(),
                    subject: c.path.clone(),
                    key: c.detail.clone(),
                    message: c.detail.clone(),
                    remedy: help(&c.rule).map(|h| h.remedy.to_string()),
                    gap: false,
                    uri: None,
                    fingerprint: String::new(),
                    baseline_state: None,
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
                severity: from_name(&f.severity),
                scope: scope.unwrap_or_default(),
                subject: f.subject,
                key: String::new(),
                message: f.message,
                remedy: f.remedy,
                gap,
                uri: None,
                fingerprint: String::new(),
                baseline_state: None,
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
        "apk-exported-component" => (
            "An APK exports an activity, service or receiver with no permission",
            "Set android:exported=\"false\", or guard it with a signature-level android:permission",
            Medium,
        ),
        "apk-exported-provider" => (
            "An APK exports a content provider with no permission",
            "Set android:exported=\"false\", or require a signature-level permission (or separate read and write permissions)",
            High,
        ),
        "apk-debuggable" => (
            "An APK is marked android:debuggable",
            "Remove android:debuggable from the release manifest",
            High,
        ),
        "apk-cleartext-traffic" => (
            "An APK sets android:usesCleartextTraffic=true",
            "Remove the attribute and use HTTPS, or scope cleartext to specific domains in a network security config",
            Medium,
        ),
        "apk-shared-user-id" => (
            "An APK uses android:sharedUserId",
            "Drop sharedUserId (deprecated since API 29) unless the apps are meant to share a uid",
            Medium,
        ),
        "apk-allow-backup" => (
            "An APK sets android:allowBackup=true",
            "Set android:allowBackup=\"false\" or restrict it with backup rules",
            Info,
        ),
        "apk-test-only" => (
            "An APK is marked android:testOnly",
            "Build the shipped APK without android:testOnly",
            Medium,
        ),
        "elf-no-pie" => (
            "A native executable is not position-independent (ET_EXEC): no ASLR",
            "Build with -fPIE -pie so the loader can randomise its base",
            High,
        ),
        "elf-exec-stack" => (
            "The stack is executable (PT_GNU_STACK has X, or is missing)",
            "Link with -z noexecstack and mark assembly with .note.GNU-stack",
            Medium,
        ),
        "elf-no-relro" => (
            "No RELRO: the GOT stays writable after relocation",
            "Link with -Wl,-z,relro",
            Medium,
        ),
        "elf-partial-relro" => (
            "Partial RELRO: RELRO is set but relocations are lazy",
            "Link with -Wl,-z,relro,-z,now for full RELRO",
            Low,
        ),
        "elf-no-canary" => (
            "No stack canary (__stack_chk_fail not imported; heuristic)",
            "Build with -fstack-protector-strong",
            Low,
        ),
        "elf-no-fortify" => (
            "No FORTIFY_SOURCE _chk wrappers (heuristic)",
            "Build with -D_FORTIFY_SOURCE=2 at -O1 or higher",
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
        "apk-v1-only-signing" => (
            "An APK is signed with signature scheme v1 only",
            "Re-sign with APK Signature Scheme v2 or v3",
            Medium,
        ),
        "apk-debug-signing-cert" => (
            "An APK is signed with a debug or AOSP test key",
            "Re-sign with a private release key",
            High,
        ),
        "apk-cert-expired" => (
            "An APK signing certificate has expired (host clock)",
            "Re-sign with a certificate that is valid, or confirm the platform ignores expiry",
            Medium,
        ),
        "apk-cert-not-yet-valid" => (
            "An APK signing certificate is not yet valid (host clock)",
            "Check the certificate dates and the host clock",
            Medium,
        ),
        "partition_coverage" => (
            "An expected partition image is missing",
            "Make sure system, vendor and boot images are all present",
            Low,
        ),
        "unhandled_input" => (
            "A file has no handler and will not be extracted",
            "Inspect it manually",
            Low,
        ),
        "avb_signature" => (
            "Android Verified Boot signature status",
            "Sign the vbmeta image with a trusted key, or point doctor at a directory holding vbmeta.img",
            Low,
        ),
        "duplicate_properties" => (
            "A property is defined in more than one file",
            "Remove the duplicate so the effective value is unambiguous",
            Low,
        ),
        "selinux_label_gaps" => (
            "Files have no SELinux label",
            "Relabel the image, or confirm it is not SELinux-enforcing",
            Low,
        ),
        "mode_anomalies" => (
            "A file has an unexpected mode",
            "chmod it to remove the write bit for others",
            Low,
        ),
        "init_service_hygiene" => (
            "An init service is declared more than once",
            "Keep one definition",
            Low,
        ),
        "debug_leftovers" => (
            "A test or leftover artefact ships in the image",
            "Remove the file from the production image",
            Low,
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

/// The 0-100 health score (model `android/1`), a pure function of the findings.
///
/// `100 - penalty`, floored at 0, where findings are grouped by rule and each group costs its
/// worst severity's weight (error 20, high 10, medium 5, warn 2, info 0) for the first finding
/// plus a quarter of that for each further one, capped at twice the weight, so one noisy rule
/// cannot sink the score alone. A rule that could not run (a coverage gap) costs a flat 3 however
/// many images it missed, so a scan whose rules could not run never reaches 100. Labels: 90+ `good`, 60+ `needs work`, else `critical`; a `good`
/// score with gaps is `incomplete`.
pub fn score(findings: &[Finding]) -> Score {
    score_of(
        findings
            .iter()
            .map(|f| (f.rule.as_str(), f.severity, f.gap)),
    )
}

/// [`score`] over doctor/1 findings (`gap` says which could not evaluate).
pub fn score_core(
    findings: &[doctor_core::Finding],
    gap: &dyn Fn(&doctor_core::Finding) -> bool,
) -> Score {
    score_of(findings.iter().map(|f| (f.id.as_str(), f.severity, gap(f))))
}

fn score_of<'a>(findings: impl Iterator<Item = (&'a str, Severity, bool)>) -> Score {
    let mut groups: BTreeMap<(&str, bool), (Severity, u32)> = BTreeMap::new();
    let mut gaps = 0;
    for (rule, severity, gap) in findings {
        let g = groups.entry((rule, gap)).or_insert((severity, 0));
        g.0 = g.0.max(severity);
        g.1 += 1;
        gaps += usize::from(gap);
    }
    let quarters: u32 = groups
        .iter()
        .map(|((_, gap), (sev, n))| {
            if *gap {
                return 4 * GAP_WEIGHT;
            }
            let w = weight(*sev);
            (4 * w + (n - 1) * w).min(8 * w)
        })
        .sum();
    let value = 100u32.saturating_sub(quarters.div_ceil(4));
    Score::new(value as u8, "android/1", gaps)
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
                "partialFingerprints": doctor_core::sarif::partial_fingerprints(&f.fingerprint),
                "properties": {
                    "severity": f.severity.as_str(),
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
                "informationUri": "https://github.com/doctor-labs/android-doctor",
                "rules": rules,
            }},
            "results": results,
            "properties": {"score": score},
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
    "elf-no-pie",
    "elf-exec-stack",
    "elf-no-relro",
    "elf-partial-relro",
    "elf-no-canary",
    "elf-no-fortify",
    "apk-exported-component",
    "apk-exported-provider",
    "apk-debuggable",
    "apk-cleartext-traffic",
    "apk-shared-user-id",
    "apk-allow-backup",
    "apk-test-only",
    "hardcoded_credentials",
    "cloud_credentials",
    "debug_endpoints",
    "apk-v1-only-signing",
    "apk-debug-signing-cert",
    "apk-cert-expired",
    "apk-cert-not-yet-valid",
    "partition_coverage",
    "unhandled_input",
    "avb_signature",
    "duplicate_properties",
    "selinux_label_gaps",
    "mode_anomalies",
    "init_service_hygiene",
    "debug_leftovers",
    "diff-new-setuid",
    "diff-new-capability",
    "diff-root-service",
    "diff-sepolicy-changed",
    "diff-prop-changed",
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
            baseline_state: None,
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
        assert!(Severity::Critical > Severity::High && Severity::High > Severity::Medium);
        assert!(Severity::Medium > Severity::Low && Severity::Low > Severity::Info);
        assert_eq!(from_name("error"), Severity::Critical);
        assert_eq!(from_name("critical"), Severity::Critical);
        assert_eq!(from_name("nonsense"), Severity::Info);
        assert_eq!(crate::audit::Severity::High.unified(), Severity::High);
        assert_eq!(Severity::Critical.sarif_level(), "error");
        assert_eq!(Severity::High.sarif_level(), "error");
        assert_eq!(Severity::Medium.sarif_level(), "warning");
        assert_eq!(Severity::Low.sarif_level(), "note");
        assert_eq!(Severity::Critical.as_str(), "critical");
        assert_eq!(Severity::Low.as_str(), "low");
        assert_eq!(parse_fail_on("warn"), Ok(Severity::Low));
        assert_eq!(parse_fail_on("critical"), Ok(Severity::Critical));
        assert!(parse_fail_on("none").is_err());
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
        assert_eq!((one_high.value, one_high.label.as_str()), (90, "good"));
        let many: Vec<_> = (0..40)
            .map(|i| f(&format!("r{i}"), Severity::Critical, "i", "p"))
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
        assert_eq!(
            (g.value, g.label.as_str(), g.coverage_gaps),
            (97, "incomplete", 1)
        );
    }

    #[test]
    fn score_does_not_depend_on_order() {
        let mut v = vec![
            f("a", Severity::High, "i", "1"),
            f("b", Severity::Low, "i", "2"),
            f("a", Severity::Medium, "i", "3"),
            gap("c"),
        ];
        let s1 = score(&v);
        v.reverse();
        assert_eq!(s1, score(&v));
    }

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
            assert!(r["partialFingerprints"]["doctorFinding/v1"].is_string());
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
