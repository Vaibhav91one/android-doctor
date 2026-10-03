//! `audit`: the security posture of firmware images, read straight from their file systems.
//!
//! For every image (ext2/3/4 or erofs) it reports the build and ADB properties (every file that
//! sets one, init order is not simulated), setuid/setgid files, file capabilities, `su` binaries,
//! world-writable files, and the services declared in init `.rc` files (adbd and anything running
//! as root or in a shell or `su` SELinux domain), then turns what it found into findings with a
//! severity. It only reads: nothing is extracted or executed.
use crate::ramdisk::{MAX_PROP_FILE, REPORTED_PROPS, is_prop_file};
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
/// Most text files (properties and init scripts) and bytes of them one image may make us read.
const MAX_TEXT_FILES: usize = 50_000;
const MAX_TEXT_BYTES: u64 = 256 << 20;
/// How many items of one list the text report prints before pointing at `--json`.
const TEXT_LIST_CAP: usize = 25;

#[derive(Debug, Clone, Copy, PartialEq, PartialOrd, Eq, Ord)]
pub enum Severity {
    High,
    Medium,
    Info,
}

impl Severity {
    fn name(self) -> &'static str {
        match self {
            Severity::High => "high",
            Severity::Medium => "medium",
            Severity::Info => "info",
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
    pub entries: usize,
    pub props: Vec<PropHit>,
    pub setuid: Vec<Special>,
    pub capabilities: Vec<(String, String)>,
    pub world_writable: Vec<Special>,
    pub su: Vec<String>,
    pub services: Vec<Service>,
    pub findings: Vec<Finding>,
}

fn label_of(e: &Entry) -> String {
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
    let mut a = ImageAudit {
        name: name.to_string(),
        entries: entries.len(),
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
    a.findings = findings(&a);
    Ok(a)
}

fn prop_values<'a>(a: &'a ImageAudit, key: &str) -> Vec<&'a PropHit> {
    a.props.iter().filter(|p| p.key == key).collect()
}

fn findings(a: &ImageAudit) -> Vec<Finding> {
    let mut f = Vec::new();
    let mut add = |severity, rule, detail: String| {
        f.push(Finding {
            severity,
            rule,
            detail,
        })
    };
    for p in prop_values(a, "ro.debuggable") {
        if p.value == "1" {
            add(
                Severity::High,
                "debuggable-build",
                format!("ro.debuggable=1 in {}: adbd runs as root", p.file),
            );
        }
    }
    for p in prop_values(a, "ro.secure") {
        if p.value == "0" {
            add(
                Severity::High,
                "insecure-adb",
                format!("ro.secure=0 in {}: adbd keeps root", p.file),
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
            );
        }
    }
    for p in prop_values(a, "service.adb.root") {
        if p.value == "1" {
            add(
                Severity::High,
                "adb-root",
                format!("service.adb.root=1 in {}", p.file),
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
            );
        }
    }
    for p in prop_values(a, "ro.build.type") {
        if p.value == "userdebug" || p.value == "eng" {
            add(
                Severity::Medium,
                "debug-build-type",
                format!("ro.build.type={} in {}", p.value, p.file),
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
            );
        }
    }
    for p in prop_values(a, "persist.service.adb.enable") {
        if p.value == "1" {
            add(
                Severity::Medium,
                "adb-by-default",
                format!("persist.service.adb.enable=1 in {}", p.file),
            );
        }
    }
    for path in &a.su {
        add(
            Severity::High,
            "su-binary",
            format!("/{path} looks like a su binary"),
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
            );
        } else if su_domain {
            add(
                Severity::High,
                "su-service",
                format!("service {} in {} runs in the su domain", s.name, s.file),
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
            );
        }
    }
    if !a.setuid.is_empty() {
        add(
            Severity::Info,
            "setuid-files",
            format!("{} setuid/setgid files", a.setuid.len()),
        );
    }
    if !a.capabilities.is_empty() {
        add(
            Severity::Info,
            "file-capabilities",
            format!("{} files carry file capabilities", a.capabilities.len()),
        );
    }
    f.sort_by_key(|x| x.severity);
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
    analyse(&name, &entries, &mut |p| {
        let mut buf = Vec::new();
        tree.cat_path(p, &mut buf)?;
        Ok(buf)
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
            "entries": a.entries,
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

pub fn to_text(audits: &[ImageAudit]) -> String {
    let mut o = vec![adb_summary(audits)];
    for a in audits {
        o.push(String::new());
        o.push(format!("== {} ({} entries)", a.name, a.entries));
        for f in &a.findings {
            o.push(format!("[{}] {}: {}", f.severity.name(), f.rule, f.detail));
        }
        if a.findings.is_empty() {
            o.push("no findings".to_string());
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
        assert_eq!(calls, ["system/build.prop", "system/etc/init/x.rc"]);
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
        // files over the per-file cap are never read, so they do not count
        let big = vec![entry("x.prop", Kind::File, 0o644, MAX_PROP_FILE + 1)];
        assert!(analyse_with("t", &big, &mut |_| unreachable!(), 0, 0).is_ok());
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
        let t = to_text(&[a]);
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
        assert!(to_text(&[run(vec![], &[])]).contains("no findings"));
    }

    #[test]
    fn long_lists_are_capped_in_text_and_complete_in_json() {
        let entries: Vec<Entry> = (0..40)
            .map(|i| file(&format!("bin/s{i}"), 0o4755))
            .collect();
        let a = run(entries, &[]);
        let t = to_text(std::slice::from_ref(&a));
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
    fn f2fs_is_detected_and_refused_with_a_clear_message() {
        let d = crate::testutil::Scratch::new("audit-f2fs");
        let mut f2fs = vec![0u8; 1128];
        f2fs[0x170..0x170 + 4].copy_from_slice(&0xF2F52011u32.to_le_bytes());
        std::fs::write(d.join("system.img"), &f2fs).unwrap();
        let e = audit_image(&d.join("system.img")).unwrap_err();
        let msg = format!("{e:#}");
        assert!(msg.contains("f2fs is not supported"), "{msg}");
    }
}
