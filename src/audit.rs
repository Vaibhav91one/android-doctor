//! `audit`: the security posture of firmware images, read straight from their file systems.
//!
//! For every image (ext2/3/4 or erofs) it reports the build and ADB properties (every file that
//! sets one, init order is not simulated), setuid/setgid files, file capabilities, `su` binaries,
//! world-writable files, and the services declared in init `.rc` files (adbd and anything running
//! as root or in a shell or `su` SELinux domain), then turns what it found into findings with a
//! severity. It only reads: nothing is extracted or executed.
use crate::apk::{ApkAudit, audit_apk_bytes};
use crate::content::{Hit as ContentHit, MAX_SCAN_FILE_BYTES, MAX_SCAN_TOTAL_BYTES, scan_bytes};
use crate::ramdisk::{MAX_PROP_FILE, REPORTED_PROPS, is_prop_file};
use crate::term::{Renderer, Severity as TermSeverity, Style};
use crate::tree::{Entry, Kind, Tree};
use anyhow::{Context, Result};
use serde_json::{Value, json};
use std::collections::BTreeSet;
use std::path::Path;

/// Properties kept besides the ADB ones.
const BUILD_PROPS: [&str; 5] = [
    "ro.build.type",
    "ro.build.tags",
    "ro.build.fingerprint",
    "ro.build.version.release",
    "ro.build.version.security_patch",
];
const SU_DIRS: [&str; 4] = ["bin", "xbin", "sbin", "su"];
/// Most APKs we will open per image. A hostile image can hold tens of thousands.
const MAX_APK_COUNT: usize = 2_000;
/// Total bytes we will read out of APKs per image.
const MAX_APK_TOTAL_BYTES: u64 = 256 * 1024 * 1024;

/// Most text files (properties and init scripts) and bytes of them one image may make us read.
const MAX_TEXT_FILES: usize = 50_000;
const MAX_TEXT_BYTES: u64 = 256 << 20;
/// How many items of one list the text report prints before pointing at `--json`.
const TEXT_LIST_CAP: usize = 25;

#[derive(Debug, Clone, Copy, PartialEq, PartialOrd, Eq, Ord)]
pub enum Severity {
    High,
    Medium,
    Warn,
    Info,
}

impl Severity {
    pub fn name(self) -> &'static str {
        match self {
            Severity::High => "high",
            Severity::Medium => "medium",
            Severity::Warn => "warn",
            Severity::Info => "info",
        }
    }

    /// Map `audit::Severity` to the terminal colour severity.
    fn to_term(self) -> TermSeverity {
        match self {
            Severity::High => TermSeverity::Error,
            Severity::Medium | Severity::Warn => TermSeverity::Warn,
            Severity::Info => TermSeverity::Info,
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct Finding {
    pub severity: Severity,
    pub rule: &'static str,
    pub detail: String,
}

#[derive(Debug, Clone, PartialEq)]
pub struct PropHit {
    pub file: String,
    pub key: String,
    pub value: String,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Special {
    pub path: String,
    pub mode: u32,
    pub uid: u32,
    pub gid: u32,
    pub label: String,
}

#[derive(Debug, Clone, PartialEq, Default)]
pub struct Service {
    pub file: String,
    pub name: String,
    pub command: String,
    pub user: Option<String>,
    pub seclabel: Option<String>,
    pub disabled: bool,
}

#[derive(Debug, Clone, Default)]
pub struct ImageAudit {
    pub name: String,
    pub entries: Vec<Entry>,
    pub props: Vec<PropHit>,
    pub setuid: Vec<Special>,
    pub capabilities: Vec<(String, String)>,
    pub world_writable: Vec<Special>,
    pub su: Vec<String>,
    pub services: Vec<Service>,
    pub findings: Vec<Finding>,
    /// For each entry of `findings`, the same index: the in-image path or name it is about
    /// (empty when it is about the whole image) and a discriminator for findings that share a
    /// subject. These feed the stable fingerprint in `findings.rs`; they are not printed.
    pub finding_keys: Vec<(String, String)>,
    pub content_findings: Vec<ContentHit>,
    pub content_bytes_scanned: u64,
    /// One entry per APK found in the image, with its package name and signers.
    pub apks: Vec<ApkAudit>,
}

pub(crate) fn label_of(e: &Entry) -> String {
    e.xattrs
        .iter()
        .find(|(k, _)| k == "security.selinux")
        .map(|(_, v)| v.clone())
        .unwrap_or_default()
}

fn special(e: &Entry) -> Special {
    Special {
        path: e.path.clone(),
        mode: e.mode,
        uid: e.uid,
        gid: e.gid,
        label: label_of(e),
    }
}

fn parse_props(text: &str, file: &str, out: &mut Vec<PropHit>) {
    for line in text.lines() {
        let Some((k, v)) = line.split_once('=') else {
            continue;
        };
        let k = k.trim();
        if REPORTED_PROPS.contains(&k) || BUILD_PROPS.contains(&k) {
            let hit = PropHit {
                file: file.to_string(),
                key: k.to_string(),
                value: v.trim().to_string(),
            };
            if !out.contains(&hit) {
                out.push(hit);
            }
        }
    }
}

/// The `service` blocks of one init `.rc` file. A block runs from its `service` line to the next
/// `service`, `on` or `import` line; `\` continues a line.
pub fn parse_services(text: &str, file: &str) -> Vec<Service> {
    let mut lines: Vec<String> = Vec::new();
    let mut carry = String::new();
    for raw in text.lines() {
        let l = raw.trim();
        if let Some(head) = l.strip_suffix('\\') {
            carry.push_str(head);
            carry.push(' ');
            continue;
        }
        carry.push_str(l);
        lines.push(std::mem::take(&mut carry));
    }
    let mut out: Vec<Service> = Vec::new();
    let mut open = false;
    for l in lines {
        if l.is_empty() || l.starts_with('#') {
            continue;
        }
        let mut words = l.split_whitespace();
        match words.next() {
            Some("service") => {
                let name = words.next().unwrap_or("").to_string();
                let command = words.collect::<Vec<_>>().join(" ");
                out.push(Service {
                    file: file.to_string(),
                    name,
                    command,
                    ..Default::default()
                });
                open = true;
            }
            Some("on" | "import") => open = false,
            Some(opt) if open => {
                let svc = out.last_mut().expect("a service is open");
                match opt {
                    "user" => svc.user = words.next().map(str::to_string),
                    "seclabel" => svc.seclabel = words.next().map(str::to_string),
                    "disabled" => svc.disabled = true,
                    _ => {}
                }
            }
            _ => {}
        }
    }
    out
}

fn is_su_name(e: &Entry) -> bool {
    let mut parts = e.path.rsplit('/');
    let base = parts.next().unwrap_or("");
    base == "su" && (e.path == "su" || parts.any(|d| SU_DIRS.contains(&d)))
}

fn has_domain(label: &str, domain: &str) -> bool {
    label.split(':').nth(2) == Some(domain)
}

/// Audit one image's entries. `read` returns the contents of a regular file by path.
pub fn analyse(
    name: &str,
    entries: &[Entry],
    read: &mut dyn FnMut(&str) -> Result<Vec<u8>>,
) -> Result<ImageAudit> {
    analyse_with(name, entries, read, MAX_TEXT_FILES, MAX_TEXT_BYTES)
}

fn analyse_with(
    name: &str,
    entries: &[Entry],
    read: &mut dyn FnMut(&str) -> Result<Vec<u8>>,
    max_files: usize,
    max_bytes: u64,
) -> Result<ImageAudit> {
    let (mut files_read, mut bytes_read) = (0usize, 0u64);
    let mut apk_bytes: u64 = 0;
    let mut a = ImageAudit {
        name: name.to_string(),
        entries: entries.to_vec(),
        ..Default::default()
    };
    for e in entries {
        let label = label_of(e);
        if is_su_name(e) || has_domain(&label, "su_exec") || has_domain(&label, "su") {
            a.su.push(e.path.clone());
        }
        if e.kind != Kind::File {
            continue;
        }
        // APKs: read the package name and signing certificates. Bounded like the text
        // scan, and a malformed APK is reported rather than skipped silently.
        if e.path.to_ascii_lowercase().ends_with(".apk")
            && a.apks.len() < MAX_APK_COUNT
            && e.size <= crate::apk::MAX_APK_BYTES
            && apk_bytes + e.size <= MAX_APK_TOTAL_BYTES
            && let Ok(bytes) = read(&e.path)
        {
            apk_bytes += bytes.len() as u64;
            a.apks
                .push(audit_apk_bytes(std::path::Path::new(&e.path), &bytes));
        }
        if e.mode & 0o6000 != 0 {
            a.setuid.push(special(e));
        }
        if e.mode & 0o002 != 0 {
            a.world_writable.push(special(e));
        }
        if let Some((_, v)) = e.xattrs.iter().find(|(k, _)| k == "security.capability") {
            a.capabilities.push((e.path.clone(), v.clone()));
        }
        let wants_text =
            e.size <= MAX_PROP_FILE && (is_prop_file(&e.path) || e.path.ends_with(".rc"));
        if wants_text {
            files_read += 1;
            bytes_read += e.size;
            anyhow::ensure!(
                files_read <= max_files && bytes_read <= max_bytes,
                "{name} has more than {max_files} property and init files or {max_bytes} bytes of them: refusing to read them all"
            );
            let bytes = read(&e.path).with_context(|| format!("reading {}", e.path))?;
            let text = String::from_utf8_lossy(&bytes);
            if is_prop_file(&e.path) {
                parse_props(&text, &e.path, &mut a.props);
            } else {
                a.services.extend(parse_services(&text, &e.path));
            }
        }
    }
    let (hits, scanned) = scan_content(entries, read);
    a.content_findings = hits;
    a.content_bytes_scanned = scanned;
    let (f, keys) = findings(&a).into_iter().unzip();
    a.findings = f;
    a.finding_keys = keys;
    Ok(a)
}

fn prop_values<'a>(a: &'a ImageAudit, key: &str) -> Vec<&'a PropHit> {
    a.props.iter().filter(|p| p.key == key).collect()
}

/// Walk every regular file under MAX_SCAN_FILE_BYTES, reading at most that many
/// bytes per file, and scan it for indicators. Returns de-duplicated hits and the
/// total bytes read.
fn scan_content(
    entries: &[Entry],
    read: &mut dyn FnMut(&str) -> Result<Vec<u8>>,
) -> (Vec<ContentHit>, u64) {
    let mut hits = Vec::new();
    let mut scanned: u64 = 0;
    let mut budget = MAX_SCAN_TOTAL_BYTES;
    for e in entries {
        if e.kind != Kind::File || e.size == 0 || e.size > MAX_SCAN_FILE_BYTES {
            continue;
        }
        if budget == 0 {
            break;
        }
        let bytes = match read(&e.path) {
            Ok(b) => b,
            Err(_) => continue,
        };
        scanned += bytes.len() as u64;
        budget = budget.saturating_sub(bytes.len() as u64);
        for hit in scan_bytes(&e.path, &bytes) {
            if !hits.contains(&hit) {
                hits.push(hit);
            }
        }
    }
    (hits, scanned)
}

/// Every finding with its (subject, key), sorted worst first.
fn findings(a: &ImageAudit) -> Vec<(Finding, (String, String))> {
    let mut f = Vec::new();
    let mut add = |severity, rule, detail: String, subject: &str, key: &str| {
        f.push((
            Finding {
                severity,
                rule,
                detail,
            },
            (subject.to_string(), key.to_string()),
        ))
    };
    for p in prop_values(a, "ro.debuggable") {
        if p.value == "1" {
            add(
                Severity::High,
                "debuggable-build",
                format!("ro.debuggable=1 in {}: adbd runs as root", p.file),
                &p.file,
                "",
            );
        }
    }
    for p in prop_values(a, "ro.secure") {
        if p.value == "0" {
            add(
                Severity::High,
                "insecure-adb",
                format!("ro.secure=0 in {}: adbd keeps root", p.file),
                &p.file,
                "",
            );
        }
    }
    for p in prop_values(a, "ro.adb.secure") {
        if p.value == "0" {
            add(
                Severity::High,
                "adb-unauthenticated",
                format!(
                    "ro.adb.secure=0 in {}: ADB connections need no authorization",
                    p.file
                ),
                &p.file,
                "",
            );
        }
    }
    for p in prop_values(a, "service.adb.root") {
        if p.value == "1" {
            add(
                Severity::High,
                "adb-root",
                format!("service.adb.root=1 in {}", p.file),
                &p.file,
                "",
            );
        }
    }
    for p in prop_values(a, "ro.build.tags") {
        if p.value.contains("test-keys") {
            add(
                Severity::Medium,
                "test-keys",
                format!(
                    "ro.build.tags={} in {}: signed with public test keys",
                    p.value, p.file
                ),
                &p.file,
                "",
            );
        }
    }
    for p in prop_values(a, "ro.build.type") {
        if p.value == "userdebug" || p.value == "eng" {
            add(
                Severity::Medium,
                "debug-build-type",
                format!("ro.build.type={} in {}", p.value, p.file),
                &p.file,
                "",
            );
        }
    }
    for p in prop_values(a, "persist.sys.usb.config") {
        if p.value.split(',').any(|m| m == "adb") {
            add(
                Severity::Medium,
                "adb-by-default",
                format!(
                    "persist.sys.usb.config={} in {}: adb enabled by default",
                    p.value, p.file
                ),
                &p.file,
                "persist.sys.usb.config",
            );
        }
    }
    for p in prop_values(a, "persist.service.adb.enable") {
        if p.value == "1" {
            add(
                Severity::Medium,
                "adb-by-default",
                format!("persist.service.adb.enable=1 in {}", p.file),
                &p.file,
                "persist.service.adb.enable",
            );
        }
    }
    for path in &a.su {
        add(
            Severity::High,
            "su-binary",
            format!("/{path} looks like a su binary"),
            path,
            "",
        );
    }
    for s in &a.setuid {
        if s.mode & 0o022 != 0 {
            add(
                Severity::High,
                "writable-setuid",
                format!(
                    "/{} is setuid/setgid ({:04o}) and writable by group or others",
                    s.path, s.mode
                ),
                &s.path,
                "",
            );
        }
    }
    if !a.world_writable.is_empty() {
        add(
            Severity::Medium,
            "world-writable",
            format!(
                "{} regular files are world-writable",
                a.world_writable.len()
            ),
            "",
            "",
        );
    }
    for s in &a.services {
        let su_domain = s.seclabel.as_deref().is_some_and(|l| has_domain(l, "su"));
        let shell_domain = s
            .seclabel
            .as_deref()
            .is_some_and(|l| has_domain(l, "shell"));
        let shell_binary = s
            .command
            .split_whitespace()
            .next()
            .is_some_and(|c| c.ends_with("/sh"));
        if s.name == "adbd" {
            add(
                if s.disabled {
                    Severity::Info
                } else {
                    Severity::Medium
                },
                "adbd-service",
                format!(
                    "adbd declared in {} ({}{})",
                    s.file,
                    if s.disabled {
                        "disabled: started by property triggers"
                    } else {
                        "starts at boot"
                    },
                    s.seclabel
                        .as_deref()
                        .map(|l| format!(", seclabel {l}"))
                        .unwrap_or_default()
                ),
                &s.file,
                &s.name,
            );
        } else if su_domain {
            add(
                Severity::High,
                "su-service",
                format!("service {} in {} runs in the su domain", s.name, s.file),
                &s.file,
                &s.name,
            );
        } else if shell_domain || shell_binary {
            let why = if shell_domain {
                "in the shell SELinux domain"
            } else {
                "a shell binary"
            };
            add(
                if s.disabled {
                    Severity::Info
                } else {
                    Severity::Medium
                },
                "shell-service",
                format!(
                    "service {} in {} runs {why} ({}; {})",
                    s.name,
                    s.file,
                    s.command,
                    if s.disabled {
                        "disabled: started on demand"
                    } else {
                        "starts at boot"
                    }
                ),
                &s.file,
                &s.name,
            );
        }
    }
    if !a.setuid.is_empty() {
        add(
            Severity::Info,
            "setuid-files",
            format!("{} setuid/setgid files", a.setuid.len()),
            "",
            "",
        );
    }
    if !a.capabilities.is_empty() {
        add(
            Severity::Info,
            "file-capabilities",
            format!("{} files carry file capabilities", a.capabilities.len()),
            "",
            "",
        );
    }
    if !a.content_findings.is_empty() {
        let rule = match a.content_findings[0].rule.as_str() {
            "hardcoded_credentials" => "hardcoded_credentials",
            "cloud_credentials" => "cloud_credentials",
            "debug_endpoints" => "debug_endpoints",
            _ => "content-indicator",
        };
        let sev = match a.content_findings[0].severity.as_str() {
            "high" => Severity::High,
            "medium" => Severity::Medium,
            _ => Severity::Info,
        };
        add(
            sev,
            rule,
            format!(
                "{} content finding(s) across image (scanned {} bytes)",
                a.content_findings.len(),
                a.content_bytes_scanned
            ),
            "",
            "",
        );
    }
    // APK manifests: one finding per rule per APK, keyed by severity because the exported
    // rules can fire at two levels in the same APK.
    for info in a.apks.iter().filter_map(|x| x.info.as_ref()) {
        for i in info.issues() {
            add(
                i.severity,
                i.rule,
                format!("{}: {}", info.path, i.detail),
                &info.path,
                i.severity.name(),
            );
        }
    }
    f.sort_by_key(|x| x.0.severity);
    f
}

/// One line on how ADB is configured, from all the images' properties.
pub fn adb_summary(audits: &[ImageAudit]) -> String {
    let get = |key: &str| -> Vec<String> {
        let mut v: BTreeSet<String> = BTreeSet::new();
        for a in audits {
            v.extend(prop_values(a, key).iter().map(|p| p.value.clone()));
        }
        v.into_iter().collect()
    };
    let show = |v: Vec<String>| {
        if v.is_empty() {
            "not set".to_string()
        } else {
            v.join("/")
        }
    };
    let (secure, adb_secure, debuggable) =
        (get("ro.secure"), get("ro.adb.secure"), get("ro.debuggable"));
    let verdict = if debuggable.iter().any(|v| v == "1") || secure.iter().any(|v| v == "0") {
        "adbd can run as root"
    } else if adb_secure.iter().any(|v| v == "0") {
        "ADB needs no authorization"
    } else if secure.is_empty() && adb_secure.is_empty() && debuggable.is_empty() {
        "no ADB properties found"
    } else {
        "ADB needs authorization and does not run as root"
    };
    format!(
        "ADB: ro.secure={} ro.adb.secure={} ro.debuggable={} usb={}: {verdict}",
        show(secure),
        show(adb_secure),
        show(debuggable),
        show(get("persist.sys.usb.config"))
    )
}

/// The images to audit: files are taken as given; in a directory, every `*.img` that holds a file
/// system we can read (the others, such as `boot.img`, are skipped).
pub fn image_list(paths: &[std::path::PathBuf]) -> Result<Vec<std::path::PathBuf>> {
    let mut out = Vec::new();
    for p in paths {
        if p.is_dir() {
            let mut found: Vec<_> = std::fs::read_dir(p)
                .with_context(|| format!("reading {}", p.display()))?
                .filter_map(|e| e.ok().map(|e| e.path()))
                .filter(|f| {
                    f.extension().is_some_and(|x| x == "img")
                        && f.is_file()
                        && crate::detect::filesystem_of_file(f).is_some()
                })
                .collect();
            found.sort();
            out.extend(found);
        } else {
            out.push(p.clone());
        }
    }
    anyhow::ensure!(
        !out.is_empty(),
        "no images with a readable file system found"
    );
    Ok(out)
}

pub fn audit_image(path: &Path) -> Result<ImageAudit> {
    let tree = Tree::open(path)?;
    let entries = tree.entries()?;
    let name = path
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or("image")
        .to_string();
    let a = analyse(&name, &entries, &mut |p| {
        let mut buf = Vec::new();
        tree.cat_path(p, &mut buf)?;
        Ok(buf)
    })?;
    Ok(a)
}

/// One APK as JSON: package, versions, signers, or the error that stopped parsing.
fn apk_json(a: &ApkAudit) -> Value {
    let Some(info) = &a.info else {
        return json!({ "error": a.error });
    };
    let m = &info.manifest;
    json!({
        "path": info.path,
        "package": info.package_name,
        "version_code": info.version_code,
        "version_name": info.version_name,
        "aosp_test_key": info.has_test_key(),
        "manifest": {
            "target_sdk": m.target_sdk,
            "shared_user_id": m.shared_user_id,
            "debuggable": m.debuggable,
            "uses_cleartext_traffic": m.uses_cleartext_traffic,
            "network_security_config": m.has_network_security_config,
            "allow_backup": m.allow_backup,
            "test_only": m.test_only,
            "application_permission": m.app_permission,
            "components": m.components.iter().map(|c| json!({
                "kind": c.kind, "name": c.name, "exported": c.exported,
                "guarded": c.guarded, "intent_filter": c.has_intent_filter,
            })).collect::<Vec<Value>>(),
        },
        "issues": info.issues().iter().map(|i| json!({
            "severity": i.severity.name(), "rule": i.rule, "detail": i.detail,
        })).collect::<Vec<Value>>(),
        "signers": info.signers.iter().map(|s| json!({
            "scheme": s.scheme,
            "cert_sha256": s.cert_sha256,
            "subject_cn": s.subject_cn,
            "is_aosp_test_key": s.is_aosp_test_key,
        })).collect::<Vec<Value>>(),
    })
}

fn special_json(s: &Special) -> Value {
    json!({"path": s.path, "mode": s.mode, "uid": s.uid, "gid": s.gid, "label": s.label})
}

pub fn to_json(audits: &[ImageAudit]) -> Value {
    json!({
        "adb": adb_summary(audits),
        "images": audits.iter().map(|a| json!({
            "name": a.name,
            "entries": a.entries.len(),
            "properties": a.props.iter().map(|p| json!({"file": p.file, "key": p.key, "value": p.value})).collect::<Vec<_>>(),
            "setuid_files": a.setuid.iter().map(special_json).collect::<Vec<_>>(),
            "file_capabilities": a.capabilities.iter().map(|(p, v)| json!({"path": p, "value": v})).collect::<Vec<_>>(),
            "world_writable_files": a.world_writable.iter().map(special_json).collect::<Vec<_>>(),
            "su_binaries": a.su,
            "services": a.services.iter().map(|s| json!({
                "file": s.file, "name": s.name, "command": s.command, "user": s.user,
                "seclabel": s.seclabel, "disabled": s.disabled,
            })).collect::<Vec<_>>(),
            "findings": a.findings.iter().map(|f| json!({
                "severity": f.severity.name(), "rule": f.rule, "detail": f.detail,
            })).collect::<Vec<_>>(),
            "content_findings": a.content_findings.iter().map(|f| json!({
                "severity": f.severity, "rule": f.rule, "detail": f.detail,
            })).collect::<Vec<_>>(),
            "content_bytes_scanned": a.content_bytes_scanned,
            "apks": a.apks.iter().map(apk_json).collect::<Vec<Value>>(),
        })).collect::<Vec<_>>(),
    })
}

fn capped<T>(items: &[T], show: impl Fn(&T) -> String) -> Vec<String> {
    let mut v: Vec<String> = items
        .iter()
        .take(TEXT_LIST_CAP)
        .map(|i| format!("  {}", show(i)))
        .collect();
    if items.len() > TEXT_LIST_CAP {
        v.push(format!(
            "  ... and {} more (use --json)",
            items.len() - TEXT_LIST_CAP
        ));
    }
    v
}

pub fn to_text(audits: &[ImageAudit], no_color: bool) -> String {
    let r = Renderer::new(Style::detect(no_color));
    let mut o = vec![adb_summary(audits)];
    for a in audits {
        o.push(String::new());
        o.push(format!("== {} ({} entries)", a.name, a.entries.len()));
        for f in &a.findings {
            let label = r.severity(f.severity.to_term(), f.severity.name());
            o.push(format!("[{label}] {}: {}", f.rule, f.detail));
        }
        if a.findings.is_empty() {
            o.push("no findings".to_string());
        }
        if !a.apks.is_empty() {
            let unreadable = a.apks.iter().filter(|x| x.info.is_none()).count();
            o.push(format!(
                "APKs: {} found{}",
                a.apks.len(),
                if unreadable > 0 {
                    format!(", {unreadable} unreadable")
                } else {
                    String::new()
                }
            ));
            o.extend(capped(&a.apks, |x| match &x.info {
                Some(i) => {
                    let test_key = if i.has_test_key() {
                        "  [AOSP TEST KEY]"
                    } else {
                        ""
                    };
                    let n = i.issues().len();
                    let issues = if n > 0 {
                        format!("  [{n} manifest issue(s)]")
                    } else {
                        String::new()
                    };
                    format!(
                        "{}  {}  {}{test_key}{issues}",
                        i.path,
                        i.package_name,
                        i.signers.len()
                    )
                }
                None => format!("unreadable: {}", x.error.as_deref().unwrap_or("unknown")),
            }));
        }
        if !a.props.is_empty() {
            o.push("properties:".to_string());
            o.extend(capped(&a.props, |p| {
                format!("{}={}  ({})", p.key, p.value, p.file)
            }));
        }
        if !a.setuid.is_empty() {
            o.push("setuid/setgid files:".to_string());
            o.extend(capped(&a.setuid, |s| {
                format!("{:04o} {}:{} /{} {}", s.mode, s.uid, s.gid, s.path, s.label)
            }));
        }
        if !a.capabilities.is_empty() {
            o.push("file capabilities:".to_string());
            o.extend(capped(&a.capabilities, |(p, v)| format!("/{p} {v}")));
        }
        if !a.services.is_empty() {
            let risky: Vec<&Service> = a
                .services
                .iter()
                .filter(|s| {
                    s.name == "adbd" || s.user.as_deref() == Some("root") && s.seclabel.is_some()
                })
                .collect();
            o.push(format!(
                "services: {} declared, {} shown (adbd and root services with a seclabel)",
                a.services.len(),
                risky.len()
            ));
            o.extend(capped(&risky, |s| {
                format!(
                    "{} user={} seclabel={} {} ({})",
                    s.name,
                    s.user.as_deref().unwrap_or("-"),
                    s.seclabel.as_deref().unwrap_or("-"),
                    if s.disabled {
                        "disabled"
                    } else {
                        "starts at boot"
                    },
                    s.file
                )
            }));
        }
        if !a.content_findings.is_empty() {
            o.push(format!(
                "content findings ({} found, {} bytes scanned):",
                a.content_findings.len(),
                a.content_bytes_scanned
            ));
            o.extend(capped(&a.content_findings, |c| {
                format!("  [{}] {} {}: {}", c.severity, c.rule, c.path, c.detail)
            }));
        }
    }
    o.join("\n")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(path: &str, kind: Kind, mode: u32, size: u64) -> Entry {
        Entry {
            path: path.to_string(),
            kind,
            mode,
            uid: 0,
            gid: 0,
            size,
            mtime: 0,
            ino: 1,
            nlink: 1,
            link: None,
            rdev: None,
            xattrs: vec![],
            sha256: None,
            extracted_as: None,
        }
    }

    fn file(path: &str, mode: u32) -> Entry {
        entry(path, Kind::File, mode, 10)
    }

    fn labelled(mut e: Entry, label: &str) -> Entry {
        e.xattrs.push(("security.selinux".into(), label.into()));
        e
    }

    fn run(entries: Vec<Entry>, files: &[(&str, &str)]) -> ImageAudit {
        let files: Vec<(String, String)> = files
            .iter()
            .map(|(p, c)| (p.to_string(), c.to_string()))
            .collect();
        analyse("t", &entries, &mut |p| {
            files
                .iter()
                .find(|(q, _)| q == p)
                .map(|(_, c)| c.clone().into_bytes())
                .ok_or_else(|| anyhow::anyhow!("no such file {p}"))
        })
        .unwrap()
    }

    fn rules(a: &ImageAudit) -> Vec<&'static str> {
        a.findings.iter().map(|f| f.rule).collect()
    }

    #[test]
    fn a_locked_build_has_no_findings_but_a_clear_adb_summary() {
        let a = run(
            vec![
                file("system/etc/prop.default", 0o644),
                file("system/build.prop", 0o600),
            ],
            &[
                (
                    "system/etc/prop.default",
                    "ro.secure=1\nro.adb.secure=1\nro.debuggable=0\npersist.sys.usb.config=none\n",
                ),
                (
                    "system/build.prop",
                    "ro.build.type=user\nro.build.tags=release-keys\nro.build.version.release=9\n# ro.debuggable=1\nother=1\n",
                ),
            ],
        );
        assert!(a.findings.is_empty(), "{:?}", a.findings);
        assert_eq!(a.props.len(), 7);
        let s = adb_summary(&[a]);
        assert!(
            s.contains("ro.secure=1 ro.adb.secure=1 ro.debuggable=0 usb=none"),
            "{s}"
        );
        assert!(
            s.ends_with("ADB needs authorization and does not run as root"),
            "{s}"
        );
    }

    #[test]
    fn risky_properties_become_findings_with_the_file_named() {
        let a = run(
            vec![
                file("default.prop", 0o644),
                file("system/build.prop", 0o644),
            ],
            &[
                (
                    "default.prop",
                    "ro.debuggable=1\nro.secure=0\nro.adb.secure=0\nservice.adb.root=1\npersist.sys.usb.config=mtp,adb\npersist.service.adb.enable=1\n",
                ),
                (
                    "system/build.prop",
                    "ro.build.type=userdebug\nro.build.tags=dev-keys,test-keys\n",
                ),
            ],
        );
        let r = rules(&a);
        for want in [
            "debuggable-build",
            "insecure-adb",
            "adb-unauthenticated",
            "adb-root",
            "adb-by-default",
            "debug-build-type",
            "test-keys",
        ] {
            assert!(r.contains(&want), "{want} in {r:?}");
        }
        assert_eq!(r.iter().filter(|x| **x == "adb-by-default").count(), 2);
        assert_eq!(
            a.findings[0].severity,
            Severity::High,
            "high findings come first"
        );
        assert!(
            a.findings
                .iter()
                .any(|f| f.detail.contains("in default.prop"))
        );
        assert!(adb_summary(&[a]).ends_with("adbd can run as root"));
        let eng = run(
            vec![file("a.prop", 0o644)],
            &[("a.prop", "ro.build.type=eng\n")],
        );
        assert_eq!(rules(&eng), ["debug-build-type"]);
        let m = run(
            vec![file("a.prop", 0o644)],
            &[("a.prop", "persist.sys.usb.config=mtp\nro.adb.secure=1\n")],
        );
        assert!(m.findings.is_empty(), "mtp alone is not adb");
        let lone = run(
            vec![file("a.prop", 0o644)],
            &[("a.prop", "ro.adb.secure=0\n")],
        );
        assert!(adb_summary(&[lone]).ends_with("ADB needs no authorization"));
    }

    #[test]
    fn no_properties_is_reported_as_unknown_not_as_secure() {
        let a = run(vec![file("etc/x.conf", 0o644)], &[]);
        assert!(adb_summary(&[a]).ends_with("no ADB properties found"));
    }

    #[test]
    fn su_binaries_are_found_by_name_directory_and_label() {
        let a = run(
            vec![
                file("system/xbin/su", 0o4755),
                file("sbin/su", 0o755),
                entry("system/bin/su", Kind::Symlink, 0o777, 0),
                file("system/bin/sudo", 0o755),
                file("data/su", 0o755),
                file("system/lib/su", 0o644),
                labelled(file("system/bin/daemonsu", 0o755), "u:object_r:su_exec:s0"),
                labelled(file("system/etc/x", 0o644), "u:object_r:su:s0"),
                labelled(file("system/etc/y", 0o644), "u:object_r:system_file:s0"),
            ],
            &[],
        );
        let mut su = a.su.clone();
        su.sort();
        assert_eq!(
            su,
            [
                "sbin/su",
                "system/bin/daemonsu",
                "system/bin/su",
                "system/etc/x",
                "system/xbin/su"
            ]
        );
        assert_eq!(rules(&a).iter().filter(|r| **r == "su-binary").count(), 5);
        let top = run(vec![file("su", 0o755)], &[]);
        assert_eq!(top.su, ["su"]);
    }

    #[test]
    fn setuid_files_world_writable_files_and_capabilities_are_listed() {
        let mut ping = file("system/bin/ping", 0o4755);
        ping.xattrs
            .push(("security.capability".into(), "hex:01000002".into()));
        let a = run(
            vec![
                ping,
                file("system/bin/sg", 0o2755),
                file("system/bin/bad", 0o4777),
                file("system/etc/open", 0o666),
                entry("system/dir", Kind::Dir, 0o4777, 0),
                entry("system/link", Kind::Symlink, 0o4777, 0),
                file("system/etc/plain", 0o644),
            ],
            &[],
        );
        let mut su: Vec<_> = a.setuid.iter().map(|s| s.path.as_str()).collect();
        su.sort();
        assert_eq!(
            su,
            ["system/bin/bad", "system/bin/ping", "system/bin/sg"],
            "directories and symlinks are not files"
        );
        assert_eq!(
            a.world_writable
                .iter()
                .map(|s| s.path.as_str())
                .collect::<Vec<_>>(),
            ["system/bin/bad", "system/etc/open"]
        );
        assert_eq!(
            a.capabilities,
            [("system/bin/ping".to_string(), "hex:01000002".to_string())]
        );
        let r = rules(&a);
        assert_eq!(r.iter().filter(|x| **x == "writable-setuid").count(), 1);
        assert!(
            r.contains(&"world-writable")
                && r.contains(&"setuid-files")
                && r.contains(&"file-capabilities")
        );
        let w = a
            .findings
            .iter()
            .find(|f| f.rule == "writable-setuid")
            .unwrap();
        assert!(
            w.detail.contains("system/bin/bad") && w.detail.contains("4777"),
            "{}",
            w.detail
        );
    }

    #[test]
    fn the_write_bits_are_told_apart() {
        let a = run(
            vec![
                file("etc/group_only", 0o620),
                file("etc/other_only", 0o602),
                file("etc/sticky_dir_file", 0o1644),
                file("bin/s_group", 0o4775),
                file("bin/s_other", 0o4757),
                file("bin/s_clean", 0o4755),
                file("bin/s_owner_only", 0o4700),
            ],
            &[],
        );
        let ww: Vec<_> = a.world_writable.iter().map(|s| s.path.as_str()).collect();
        assert_eq!(
            ww,
            ["etc/other_only", "bin/s_other"],
            "only the other-write bit makes a file world-writable"
        );
        let bad: Vec<_> = a
            .findings
            .iter()
            .filter(|f| f.rule == "writable-setuid")
            .map(|f| f.detail.clone())
            .collect();
        assert_eq!(bad.len(), 2, "{bad:?}");
        assert!(
            bad.iter().any(|d| d.contains("bin/s_group"))
                && bad.iter().any(|d| d.contains("bin/s_other"))
        );
        assert!(
            !bad.iter()
                .any(|d| d.contains("s_clean") || d.contains("s_owner_only"))
        );
    }

    const RC: &str = "\
# comment
import /init.usb.rc

service adbd /system/bin/adbd --root_seclabel=u:r:su:s0
    class core
    socket adbd stream 660 system system
    disabled
    seclabel u:r:adbd:s0

on boot
    setprop sys.x 1
    user nobody

service rootshell /system/bin/sh -c \\
    echo hi
    user root
    seclabel u:r:shell:s0

service backdoor /vendor/bin/bd
    user root
    seclabel u:r:su:s0
    oneshot

service plain /system/bin/plain
    user system
";

    #[test]
    fn init_services_are_parsed_with_their_options() {
        let s = parse_services(RC, "init.rc");
        let names: Vec<_> = s.iter().map(|x| x.name.as_str()).collect();
        assert_eq!(names, ["adbd", "rootshell", "backdoor", "plain"]);
        assert_eq!(s[0].command, "/system/bin/adbd --root_seclabel=u:r:su:s0");
        assert!(
            s[0].disabled && s[0].seclabel.as_deref() == Some("u:r:adbd:s0") && s[0].user.is_none()
        );
        assert_eq!(
            s[1].command, "/system/bin/sh -c echo hi",
            "backslash continues the line"
        );
        assert_eq!((s[1].user.as_deref(), s[1].disabled), (Some("root"), false));
        assert_eq!(s[2].seclabel.as_deref(), Some("u:r:su:s0"));
        assert_eq!(s[3].user.as_deref(), Some("system"));
        assert!(s.iter().all(|x| x.file == "init.rc"));
        assert!(
            s[1].user.as_deref() == Some("root"),
            "options after `on boot` (user nobody) are not attached to rootshell"
        );
        assert_eq!(parse_services("", "x"), vec![]);
        assert_eq!(parse_services("service\n", "x")[0].name, "");
    }

    #[test]
    fn service_findings_distinguish_adbd_su_and_shell() {
        let a = run(vec![file("init.rc", 0o750)], &[("init.rc", RC)]);
        let by = |rule: &str| {
            a.findings
                .iter()
                .filter(|f| f.rule == rule)
                .collect::<Vec<_>>()
        };
        assert_eq!(by("adbd-service").len(), 1);
        assert_eq!(
            by("adbd-service")[0].severity,
            Severity::Info,
            "a disabled adbd is only informational"
        );
        assert!(by("adbd-service")[0].detail.contains("disabled"));
        assert_eq!(by("su-service").len(), 1);
        assert!(by("su-service")[0].detail.contains("backdoor"));
        assert_eq!(by("shell-service").len(), 1);
        assert!(by("shell-service")[0].detail.contains("rootshell"));
        assert!(
            by("shell-service")[0]
                .detail
                .contains("shell SELinux domain")
        );
        assert_eq!(by("shell-service")[0].severity, Severity::Medium);
        let at_boot = run(
            vec![file("a.rc", 0o644)],
            &[("a.rc", "service adbd /system/bin/adbd\n    class core\n")],
        );
        assert_eq!(at_boot.findings[0].severity, Severity::Medium);
        assert!(at_boot.findings[0].detail.contains("starts at boot"));
        let by_path = run(
            vec![file("a.rc", 0o644)],
            &[("a.rc", "service x /system/bin/sh\n")],
        );
        assert_eq!(rules(&by_path), ["shell-service"]);
        assert!(by_path.findings[0].detail.contains("a shell binary"));
        assert_eq!(by_path.findings[0].severity, Severity::Medium);
        let idle = run(
            vec![file("a.rc", 0o644)],
            &[(
                "a.rc",
                "service y /vendor/bin/y.sh\n    user root\n    seclabel u:r:shell:s0\n    disabled\n",
            )],
        );
        assert_eq!(
            idle.findings[0].severity,
            Severity::Info,
            "a disabled shell service is only informational"
        );
        assert!(idle.findings[0].detail.contains("started on demand"));
        let script = run(
            vec![file("a.rc", 0o644)],
            &[("a.rc", "service z /system/bin/do_thing.sh\n")],
        );
        assert!(
            script.findings.is_empty(),
            "a script name alone is not a shell service"
        );
    }

    #[test]
    fn only_small_text_files_are_read() {
        let mut calls = Vec::new();
        let entries = vec![
            file("system/build.prop", 0o644),
            file("system/bin/app", 0o755),
            entry("system/big.prop", Kind::File, 0o644, MAX_PROP_FILE + 1),
            entry("system/link.prop", Kind::Symlink, 0o777, 0),
            entry("system/dir.rc", Kind::Dir, 0o755, 0),
            file("system/etc/init/x.rc", 0o644),
        ];
        analyse("t", &entries, &mut |p| {
            calls.push(p.to_string());
            Ok(Vec::new())
        })
        .unwrap();
        // analyse_with reads prop/rc files; scan_content reads all small files
        assert_eq!(calls.len(), 6);
        assert!(calls.contains(&"system/build.prop".to_string()));
        assert!(calls.contains(&"system/etc/init/x.rc".to_string()));
        assert!(calls.contains(&"system/bin/app".to_string()));
        assert!(calls.contains(&"system/big.prop".to_string()));
    }

    #[test]
    fn the_number_and_size_of_text_files_read_is_bounded() {
        let entries: Vec<Entry> = (0..5)
            .map(|i| entry(&format!("a{i}.prop"), Kind::File, 0o644, 100))
            .collect();
        let ok = |files, bytes| analyse_with("t", &entries, &mut |_| Ok(Vec::new()), files, bytes);
        assert!(ok(5, 500).is_ok(), "exactly at both limits is fine");
        let e = format!("{:#}", ok(4, 500).unwrap_err());
        assert!(e.contains("more than 4 property and init files"), "{e}");
        let e = format!("{:#}", ok(5, 499).unwrap_err());
        assert!(e.contains("499 bytes"), "{e}");
        // files over the per-file cap are never read by text parsing, so they do not count
        // (scan_content reads them but does not count them against the text-file budget)
        let big = vec![entry("x.prop", Kind::File, 0o644, MAX_PROP_FILE + 1)];
        assert!(analyse_with("t", &big, &mut |_| Ok(Vec::new()), 0, 0).is_ok());
    }

    #[test]
    fn a_read_error_names_the_file() {
        let entries = vec![file("system/build.prop", 0o644)];
        let e = analyse("t", &entries, &mut |_| anyhow::bail!("boom")).unwrap_err();
        assert!(
            format!("{e:#}").contains("reading system/build.prop"),
            "{e:#}"
        );
    }

    #[test]
    fn a_property_set_twice_is_listed_for_each_file_once() {
        let a = run(
            vec![
                file("default.prop", 0o644),
                file("system/build.prop", 0o644),
            ],
            &[
                ("default.prop", "ro.secure=1\nro.secure=1\n"),
                ("system/build.prop", "ro.secure=0\n"),
            ],
        );
        assert_eq!(a.props.len(), 2);
        assert_eq!(
            rules(&a),
            ["insecure-adb"],
            "a risky value in any file is flagged"
        );
    }

    #[test]
    fn json_and_text_carry_everything() {
        let a = run(
            vec![
                file("init.rc", 0o644),
                file("default.prop", 0o644),
                file("system/xbin/su", 0o4755),
            ],
            &[("init.rc", RC), ("default.prop", "ro.debuggable=1\n")],
        );
        let j = to_json(std::slice::from_ref(&a));
        assert!(j["adb"].as_str().unwrap().contains("adbd can run as root"));
        let im = &j["images"][0];
        assert_eq!(im["name"], "t");
        assert_eq!(im["setuid_files"][0]["path"], "system/xbin/su");
        assert_eq!(im["services"].as_array().unwrap().len(), 4);
        assert_eq!(im["su_binaries"][0], "system/xbin/su");
        assert!(
            im["findings"]
                .as_array()
                .unwrap()
                .iter()
                .any(|f| f["rule"] == "debuggable-build" && f["severity"] == "high")
        );
        let t = to_text(&[a], true);
        for want in [
            "ADB:",
            "== t (3 entries)",
            "[high] debuggable-build",
            "properties:",
            "setuid/setgid files:",
            "services: 4 declared, 3 shown",
        ] {
            assert!(t.contains(want), "{want} in {t}");
        }
        assert!(to_text(&[run(vec![], &[])], true).contains("no findings"));
    }

    #[test]
    fn content_findings_are_collected() {
        let key = "BEGIN RSA PRIVATE KEY verysecret";
        let a = run(
            vec![file("secrets/key.pem", 0o644)],
            &[("secrets/key.pem", key)],
        );
        assert_eq!(a.content_findings.len(), 1);
        assert_eq!(a.content_findings[0].rule, "hardcoded_credentials");
        assert_eq!(a.content_findings[0].severity, "high");
        assert!(
            a.content_findings[0]
                .detail
                .contains("BEGIN RSA PRIVATE KEY")
        );
        assert!(a.content_bytes_scanned > 0);
        assert!(rules(&a).contains(&"hardcoded_credentials"));
        let j = to_json(std::slice::from_ref(&a));
        assert_eq!(
            j["images"][0]["content_findings"].as_array().unwrap().len(),
            1
        );
        assert!(j["images"][0]["content_bytes_scanned"].as_u64().unwrap() > 0);
        let t = to_text(&[a], true);
        assert!(t.contains("hardcoded_credentials"));
        assert!(t.contains("content findings"));
    }

    #[test]
    fn long_lists_are_capped_in_text_and_complete_in_json() {
        let entries: Vec<Entry> = (0..40)
            .map(|i| file(&format!("bin/s{i}"), 0o4755))
            .collect();
        let a = run(entries, &[]);
        let t = to_text(std::slice::from_ref(&a), true);
        assert!(t.contains("... and 15 more (use --json)"), "{t}");
        assert_eq!(
            to_json(&[a])["images"][0]["setuid_files"]
                .as_array()
                .unwrap()
                .len(),
            40
        );
    }

    #[cfg(unix)]
    #[test]
    fn every_tree_command_refuses_a_fifo_at_once_instead_of_blocking() {
        let d = crate::testutil::Scratch::new("audit-fifo");
        let fifo = d.join("pipe");
        assert!(
            std::process::Command::new("mkfifo")
                .arg(&fifo)
                .status()
                .unwrap()
                .success()
        );
        let (tx, rx) = std::sync::mpsc::channel();
        let p = fifo.clone();
        std::thread::spawn(move || {
            let tree = Tree::open(&p).err().map(|e| format!("{e:#}"));
            let audit = audit_image(&p).err().map(|e| format!("{e:#}"));
            let found = image_list(std::slice::from_ref(&p.parent().unwrap().to_path_buf()))
                .err()
                .map(|e| format!("{e:#}"));
            let _ = tx.send((tree, audit, found, crate::detect::filesystem_of_file(&p)));
        });
        let (tree, audit, found, fs) = rx
            .recv_timeout(std::time::Duration::from_secs(20))
            .expect("a command blocked on a FIFO");
        assert!(tree.unwrap().contains("FIFO or socket"));
        assert!(audit.unwrap().contains("FIFO or socket"));
        assert!(
            found.unwrap().contains("no images"),
            "a FIFO in a directory is skipped"
        );
        assert_eq!(fs, None);
    }

    #[test]
    fn images_are_collected_from_files_and_directories() {
        let d = crate::testutil::Scratch::new("audit-images");
        let mut ext = vec![0u8; 4096];
        ext[1024 + 0x38..1024 + 0x3A].copy_from_slice(&0xEF53u16.to_le_bytes());
        std::fs::write(d.join("system.img"), &ext).unwrap();
        std::fs::write(d.join("boot.img"), vec![7u8; 4096]).unwrap();
        std::fs::write(d.join("notes.txt"), b"x").unwrap();
        let got = image_list(std::slice::from_ref(&d)).unwrap();
        assert_eq!(
            got,
            [d.join("system.img")],
            "only readable file systems, only .img"
        );
        let explicit = image_list(&[d.join("boot.img")]).unwrap();
        assert_eq!(
            explicit,
            [d.join("boot.img")],
            "a named file is taken as given"
        );
        let empty = crate::testutil::Scratch::new("audit-empty");
        assert!(
            format!(
                "{:#}",
                image_list(std::slice::from_ref(&*empty)).unwrap_err()
            )
            .contains("no images")
        );
        assert!(
            image_list(&[d.join("missing")]).is_ok(),
            "a missing file fails later with a clear open error"
        );
        assert!(audit_image(&d.join("missing")).is_err());
    }

    #[test]
    fn an_f2fs_image_is_read_and_audited_like_any_other() {
        let d = crate::testutil::Scratch::new("audit-f2fs");
        std::fs::write(
            d.join("system.img"),
            crate::f2fsfs::tests::debug_system_image(),
        )
        .unwrap();
        assert_eq!(
            crate::detect::filesystem_of_file(&d.join("system.img")),
            Some(crate::detect::Filesystem::F2fs)
        );
        let a = audit_image(&d.join("system.img")).unwrap();
        let rules: Vec<String> = a.findings.iter().map(|f| f.rule.to_string()).collect();
        for want in [
            "debuggable-build",
            "insecure-adb",
            "su-binary",
            "setuid-files",
        ] {
            assert!(
                rules.iter().any(|r| *r == want),
                "{want} missing from {rules:?}"
            );
        }
        assert_eq!(a.setuid[0].label, "u:object_r:system_file:s0");
        assert_eq!(a.entries.len(), 4);
    }

    #[test]
    fn apk_manifest_issues_become_findings_json_and_remedies() {
        let mut m = crate::apk::ManifestAttrs {
            debuggable: Some(true),
            allow_backup: Some(true),
            shared_user_id: Some("android.uid.system".into()),
            ..Default::default()
        };
        m.components.push(crate::apk::Component {
            kind: "provider".into(),
            name: ".P".into(),
            exported: Some(true),
            ..Default::default()
        });
        let info = crate::apk::ApkInfo {
            path: "system/app/X/X.apk".into(),
            manifest: m,
            ..Default::default()
        };
        let a = ImageAudit {
            name: "system".into(),
            apks: vec![ApkAudit {
                info: Some(info),
                error: None,
            }],
            ..Default::default()
        };
        let fs = findings(&a);
        let got: Vec<(&str, &str)> = fs
            .iter()
            .map(|(f, _)| (f.rule, f.severity.name()))
            .collect();
        for want in [
            ("apk-exported-provider", "high"),
            ("apk-debuggable", "high"),
            ("apk-shared-user-id", "medium"),
            ("apk-allow-backup", "info"),
        ] {
            assert!(got.contains(&want), "{want:?} missing from {got:?}");
        }
        assert!(
            fs.iter()
                .all(|(f, (subj, _))| !f.rule.starts_with("apk-") || subj == "system/app/X/X.apk")
        );
        for (f, _) in &fs {
            assert!(
                crate::findings::help(f.rule).is_some(),
                "no help for {}",
                f.rule
            );
        }
        let j = apk_json(&a.apks[0]);
        assert_eq!(j["manifest"]["debuggable"], true);
        assert_eq!(j["issues"].as_array().unwrap().len(), 4);
    }
}
