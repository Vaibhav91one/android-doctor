//! `diff`: compare two firmware builds at the file-system level. Each image is read with the
//! same readers as `audit` (ext2/3/4, erofs, f2fs) and audited; the two trees are then compared by
//! path and SHA-256, along with modes, owners, SELinux labels, file capabilities, build and ADB
//! properties and init services. What got worse becomes findings (rules `diff-*`) so the diff
//! gates CI like `audit`; the raw file-level changes go under `data`. Nothing is extracted.
use crate::audit::{self, ImageAudit, Service};
use crate::findings::{self, Finding, Severity};
use crate::term::sanitize;
use crate::tree::{Entry, Kind, Tree};
use anyhow::{Context, Result};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

/// Statuses a file change can have (`--only` takes these).
pub const STATUSES: [&str; 4] = ["added", "removed", "modified", "metadata"];
/// How many changes per image the text report lists before pointing at `--json`.
const TEXT_CAP: usize = 25;

struct HashW(Sha256);

impl std::io::Write for HashW {
    fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
        self.0.update(b);
        Ok(b.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// Audit one image and fill in the SHA-256 of every regular file.
fn load(name: &str, path: &Path) -> Result<ImageAudit> {
    let tree = Tree::open(path)?;
    let entries = tree.entries()?;
    let mut a = audit::analyse(name, &entries, &mut |p| {
        let mut buf = Vec::new();
        tree.cat_path(p, &mut buf)?;
        Ok(buf)
    })?;
    for e in a.entries.iter_mut().filter(|e| e.kind == Kind::File) {
        let mut h = HashW(Sha256::new());
        tree.cat_path(&e.path, &mut h)
            .with_context(|| format!("hashing {}", e.path))?;
        e.sha256 = Some(h.0.finalize().iter().map(|b| format!("{b:02x}")).collect());
    }
    Ok(a)
}

fn stem(p: &Path) -> String {
    p.file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or("image")
        .to_string()
}

/// Pair the inputs: two image files, or two directories of images matched by file stem (an image
/// on one side only is compared against an empty tree).
type Pair = (String, Option<PathBuf>, Option<PathBuf>);

fn pairs(old: &Path, new: &Path) -> Result<Vec<Pair>> {
    match (old.is_dir(), new.is_dir()) {
        (false, false) => Ok(vec![(
            stem(new),
            Some(old.to_path_buf()),
            Some(new.to_path_buf()),
        )]),
        (true, true) => {
            let list = |d: &Path| -> Result<BTreeMap<String, PathBuf>> {
                Ok(audit::image_list(&[d.to_path_buf()])?
                    .into_iter()
                    .map(|p| (stem(&p), p))
                    .collect())
            };
            let (o, n) = (list(old)?, list(new)?);
            let names: BTreeSet<&String> = o.keys().chain(n.keys()).collect();
            Ok(names
                .into_iter()
                .map(|k| (k.clone(), o.get(k).cloned(), n.get(k).cloned()))
                .collect())
        }
        _ => anyhow::bail!("give two image files or two directories of images, not one of each"),
    }
}

pub struct Change {
    path: String,
    status: &'static str,
    old: Option<Value>,
    new: Option<Value>,
}

pub struct ImageDiff {
    name: String,
    /// `both`, `added` (image only in the new build) or `removed`.
    presence: &'static str,
    changes: Vec<Change>,
    unchanged: usize,
    props: Vec<Value>,
    services: Vec<Value>,
}

fn side(e: &Entry) -> Value {
    json!({
        "kind": e.kind.name(), "size": e.size, "sha256": e.sha256, "link": e.link,
        "mode": format!("{:04o}", e.mode & 0o7777), "uid": e.uid, "gid": e.gid,
        "label": audit::label_of(e),
        "capability": e.xattrs.iter().find(|(k, _)| k == "security.capability").map(|(_, v)| v),
    })
}

fn same_content(a: &Entry, b: &Entry) -> bool {
    a.kind == b.kind
        && match a.kind {
            Kind::File => a.sha256 == b.sha256,
            Kind::Symlink => a.link == b.link,
            Kind::Dir => true,
            _ => a.rdev == b.rdev,
        }
}

fn same_meta(a: &Entry, b: &Entry) -> bool {
    side(a)["mode"] == side(b)["mode"]
        && (a.uid, a.gid) == (b.uid, b.gid)
        && audit::label_of(a) == audit::label_of(b)
        && side(a)["capability"] == side(b)["capability"]
}

fn diff_files(old: &ImageAudit, new: &ImageAudit) -> (Vec<Change>, usize) {
    let map = |a: &ImageAudit| -> BTreeMap<String, Entry> {
        a.entries
            .iter()
            .map(|e| (e.path.clone(), e.clone()))
            .collect()
    };
    let (o, n) = (map(old), map(new));
    let paths: BTreeSet<&String> = o.keys().chain(n.keys()).collect();
    let (mut out, mut unchanged) = (Vec::new(), 0);
    for p in paths {
        let (a, b) = (o.get(p), n.get(p));
        let status = match (a, b) {
            // A directory appearing or vanishing says nothing its files do not.
            (None, Some(e)) | (Some(e), None) if e.kind == Kind::Dir => continue,
            (None, Some(_)) => "added",
            (Some(_), None) => "removed",
            (Some(a), Some(b)) if !same_content(a, b) => "modified",
            (Some(a), Some(b)) if !same_meta(a, b) => "metadata",
            (Some(e), _) => {
                unchanged += usize::from(e.kind != Kind::Dir);
                continue;
            }
            _ => continue,
        };
        out.push(Change {
            path: p.clone(),
            status,
            old: a.map(side),
            new: b.map(side),
        });
    }
    (out, unchanged)
}

fn is_root(s: &Service) -> bool {
    s.user.as_deref().is_none_or(|u| u == "root")
}

fn diff_services(old: &ImageAudit, new: &ImageAudit) -> Vec<Value> {
    let key = |s: &Service| (s.file.clone(), s.name.clone());
    let o: BTreeMap<_, _> = old.services.iter().map(|s| (key(s), s)).collect();
    let n: BTreeMap<_, _> = new.services.iter().map(|s| (key(s), s)).collect();
    let show = |s: &Service| json!({"command": s.command, "user": s.user, "seclabel": s.seclabel, "disabled": s.disabled});
    let mut out = Vec::new();
    for k in o.keys().chain(n.keys()).collect::<BTreeSet<_>>() {
        let (a, b) = (o.get(k), n.get(k));
        let status = match (a, b) {
            (None, Some(_)) => "added",
            (Some(_), None) => "removed",
            (Some(a), Some(b)) if show(a) != show(b) => "changed",
            _ => continue,
        };
        out.push(json!({"file": k.0, "name": k.1, "status": status,
            "old": a.map(|s| show(s)), "new": b.map(|s| show(s))}));
    }
    out
}

fn diff_props(old: &ImageAudit, new: &ImageAudit) -> Vec<Value> {
    let m = |a: &ImageAudit| -> BTreeMap<(String, String), String> {
        a.props
            .iter()
            .map(|p| ((p.file.clone(), p.key.clone()), p.value.clone()))
            .collect()
    };
    let (o, n) = (m(old), m(new));
    o.keys()
        .chain(n.keys())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .filter(|k| o.get(*k) != n.get(*k))
        .map(|k| json!({"file": k.0, "key": k.1, "old": o.get(k), "new": n.get(k)}))
        .collect()
}

fn is_sepolicy(path: &str) -> bool {
    let p = path.to_ascii_lowercase();
    p.contains("sepolicy")
        || p.contains("etc/selinux/")
        || [
            "file_contexts",
            "property_contexts",
            "service_contexts",
            "seapp_contexts",
        ]
        .iter()
        .any(|n| p.ends_with(n))
}

/// What the new build does worse than the old one.
fn security_findings(old: &ImageAudit, new: &ImageAudit, d: &ImageDiff) -> Vec<Finding> {
    let mut out = Vec::new();
    let mut add = |rule: String,
                   severity,
                   subject: &str,
                   key: &str,
                   message: String,
                   remedy: Option<String>| {
        out.push(
            Finding {
                rule,
                category: "security".into(),
                severity,
                scope: new.name.clone(),
                subject: subject.to_string(),
                key: key.to_string(),
                message,
                remedy,
                gap: false,
                uri: None,
                fingerprint: String::new(),
                baseline_state: None,
            }
            .seal(!subject.is_empty()),
        )
    };
    // Every audit finding about a path or name that the old build did not have.
    let known: BTreeSet<(&str, &str, &str)> = old
        .findings
        .iter()
        .zip(&old.finding_keys)
        .map(|(f, (s, k))| (f.rule, s.as_str(), k.as_str()))
        .collect();
    for (f, (s, k)) in new.findings.iter().zip(&new.finding_keys) {
        if s.is_empty() || f.severity == audit::Severity::Info || known.contains(&(f.rule, s, k)) {
            continue;
        }
        add(
            format!("diff-{}", f.rule),
            Severity::from_audit(f.severity),
            s,
            k,
            format!("new in this build: {}", f.detail),
            findings::help(f.rule).map(|h| h.remedy.to_string()),
        );
    }
    let old_setuid: BTreeSet<&str> = old.setuid.iter().map(|s| s.path.as_str()).collect();
    for s in new
        .setuid
        .iter()
        .filter(|s| !old_setuid.contains(s.path.as_str()))
    {
        add(
            "diff-new-setuid".into(),
            Severity::High,
            &s.path,
            "",
            format!(
                "/{} is newly setuid/setgid ({:04o}, uid {})",
                s.path,
                s.mode & 0o7777,
                s.uid
            ),
            Some("Drop the setuid bit, or confirm the file needs it".into()),
        );
    }
    let old_caps: BTreeSet<&(String, String)> = old.capabilities.iter().collect();
    for c in new.capabilities.iter().filter(|c| !old_caps.contains(c)) {
        add(
            "diff-new-capability".into(),
            Severity::Medium,
            &c.0,
            &c.1,
            format!("/{} has new or changed file capabilities ({})", c.0, c.1),
            Some("Grant only the capabilities the binary needs".into()),
        );
    }
    for v in &d.services {
        let (Some(file), Some(name)) = (v["file"].as_str(), v["name"].as_str()) else {
            continue;
        };
        let Some(s) = new
            .services
            .iter()
            .find(|s| s.file == file && s.name == name)
        else {
            continue;
        };
        let was_root = old
            .services
            .iter()
            .find(|o| o.file == file && o.name == name)
            .is_some_and(is_root);
        if is_root(s) && !was_root {
            add(
                "diff-root-service".into(),
                if s.disabled {
                    Severity::Warn
                } else {
                    Severity::Medium
                },
                file,
                name,
                format!("service {name} in {file} now runs as root ({})", s.command),
                Some("Give the service its own user and SELinux domain".into()),
            );
        }
    }
    for c in d
        .changes
        .iter()
        .filter(|c| c.status != "removed" && c.status != "metadata")
    {
        if is_sepolicy(&c.path) {
            let h = c
                .new
                .as_ref()
                .and_then(|n| n["sha256"].as_str())
                .unwrap_or("");
            add(
                "diff-sepolicy-changed".into(),
                Severity::Medium,
                &c.path,
                h,
                format!("SELinux policy file /{} was {}", c.path, c.status),
                Some("Review the policy change before shipping".into()),
            );
        }
    }
    for p in &d.props {
        let (file, key) = (
            p["file"].as_str().unwrap_or(""),
            p["key"].as_str().unwrap_or(""),
        );
        let show = |v: &Value| v.as_str().unwrap_or("(unset)").to_string();
        let (o, n) = (show(&p["old"]), show(&p["new"]));
        add(
            "diff-prop-changed".into(),
            Severity::Info,
            file,
            &format!("{key}={n}"),
            format!("{key} in {file}: {o} -> {n}"),
            None,
        );
    }
    out
}

pub struct Outcome {
    pub findings: Vec<Finding>,
    pub images: Vec<ImageDiff>,
}

pub fn run(old: &Path, new: &Path) -> Result<Outcome> {
    let (mut all, mut images) = (Vec::new(), Vec::new());
    for (name, o, n) in pairs(old, new)? {
        let empty = || ImageAudit {
            name: name.clone(),
            ..Default::default()
        };
        let a = match &o {
            Some(p) => load(&name, p).with_context(|| format!("reading {}", p.display()))?,
            None => empty(),
        };
        let b = match &n {
            Some(p) => load(&name, p).with_context(|| format!("reading {}", p.display()))?,
            None => empty(),
        };
        let (changes, unchanged) = diff_files(&a, &b);
        let d = ImageDiff {
            name: name.clone(),
            presence: match (&o, &n) {
                (Some(_), Some(_)) => "both",
                (None, _) => "added",
                _ => "removed",
            },
            changes,
            unchanged,
            props: diff_props(&a, &b),
            services: diff_services(&a, &b),
        };
        all.extend(security_findings(&a, &b, &d));
        images.push(d);
    }
    Ok(Outcome {
        findings: all,
        images,
    })
}

fn keep<'a>(d: &'a ImageDiff, only: &'a [String]) -> impl Iterator<Item = &'a Change> {
    d.changes
        .iter()
        .filter(move |c| only.is_empty() || only.iter().any(|o| o == c.status))
}

pub fn to_json(images: &[ImageDiff], only: &[String]) -> Value {
    json!({ "images": images.iter().map(|d| {
        let count = |s: &str| d.changes.iter().filter(|c| c.status == s).count();
        json!({
            "name": d.name,
            "presence": d.presence,
            "counts": {"added": count("added"), "removed": count("removed"),
                "modified": count("modified"), "metadata": count("metadata"),
                "unchanged": d.unchanged},
            "files": keep(d, only).map(|c| json!({
                "path": c.path, "status": c.status, "old": c.old, "new": c.new,
            })).collect::<Vec<_>>(),
            "properties": d.props,
            "services": d.services,
        })
    }).collect::<Vec<_>>() })
}

pub fn to_text(images: &[ImageDiff], only: &[String]) -> String {
    let mut lines = Vec::new();
    for d in images {
        let count = |s: &str| d.changes.iter().filter(|c| c.status == s).count();
        lines.push(format!(
            "{} ({}): {} added, {} removed, {} modified, {} metadata-only, {} unchanged",
            sanitize(&d.name),
            d.presence,
            count("added"),
            count("removed"),
            count("modified"),
            count("metadata"),
            d.unchanged
        ));
        let shown: Vec<_> = keep(d, only).collect();
        for c in shown.iter().take(TEXT_CAP) {
            lines.push(format!("  {:<8} /{}", c.status, sanitize(&c.path)));
        }
        if shown.len() > TEXT_CAP {
            lines.push(format!(
                "  ... {} more (see --json)",
                shown.len() - TEXT_CAP
            ));
        }
    }
    lines.join("\n")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sepolicy_paths_are_recognised() {
        assert!(is_sepolicy("system/etc/selinux/plat_sepolicy.cil"));
        assert!(is_sepolicy("vendor/etc/selinux/vendor_file_contexts"));
        assert!(!is_sepolicy("system/etc/hosts"));
    }
}
