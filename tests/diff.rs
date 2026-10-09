//! End-to-end tests for `diff`: two small generated erofs builds that differ in known ways.

use fs_erofs::mkfs::{Node, NodeMeta, build_image};
use std::collections::BTreeMap;
use std::io::{Read, Write};
use std::path::PathBuf;
use std::process::Command;

struct Scratch(PathBuf);

impl Scratch {
    fn new(tag: &str) -> Self {
        let dir = std::env::temp_dir().join(format!("ad-diff-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        Self(dir)
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn file(mode: u16, data: &[u8]) -> Node {
    Node::File {
        mode: 0o100000 | mode,
        data: data.to_vec(),
        meta: NodeMeta::default(),
        xattrs: vec![],
    }
}

fn dir(entries: Vec<(&str, Node)>) -> Node {
    Node::Dir {
        mode: 0o040755,
        entries: entries
            .into_iter()
            .map(|(n, v)| (n.to_string(), v))
            .collect::<BTreeMap<_, _>>(),
        meta: NodeMeta::default(),
        xattrs: vec![],
    }
}

fn old_image() -> Vec<u8> {
    build_image(
        dir(vec![
            ("build.prop", file(0o644, b"ro.secure=1\nro.debuggable=0\n")),
            ("gone.txt", file(0o644, b"bye")),
            (
                "bin",
                dir(vec![
                    ("tool", file(0o755, b"version one")),
                    ("same", file(0o755, b"same")),
                    ("perm", file(0o644, b"perm")),
                ]),
            ),
            (
                "etc",
                dir(vec![
                    (
                        "init",
                        dir(vec![(
                            "a.rc",
                            file(0o644, b"service foo /bin/foo\n    user system\n"),
                        )]),
                    ),
                    (
                        "selinux",
                        dir(vec![("plat_sepolicy.cil", file(0o644, b"(allow a b)"))]),
                    ),
                ]),
            ),
        ]),
        12,
    )
    .unwrap()
}

fn new_image() -> Vec<u8> {
    build_image(
        dir(vec![
            ("build.prop", file(0o644, b"ro.secure=0\nro.debuggable=1\n")),
            ("added.txt", file(0o644, b"new")),
            ("evil\u{1b}[31mname.txt", file(0o644, b"x")),
            (
                "bin",
                dir(vec![
                    ("tool", file(0o755, b"version two")),
                    ("same", file(0o755, b"same")),
                    ("perm", file(0o755, b"perm")),
                    ("helper", file(0o4755, b"suid")),
                ]),
            ),
            ("xbin", dir(vec![("su", file(0o755, b"#!/bin/sh\n"))])),
            (
                "etc",
                dir(vec![
                    (
                        "init",
                        dir(vec![(
                            "a.rc",
                            file(
                                0o644,
                                b"service foo /bin/foo\n    user system\nservice bar /bin/bar\n",
                            ),
                        )]),
                    ),
                    (
                        "selinux",
                        dir(vec![("plat_sepolicy.cil", file(0o644, b"(allow a c)"))]),
                    ),
                ]),
            ),
        ]),
        12,
    )
    .unwrap()
}

struct Out {
    code: i32,
    stdout: String,
}

fn run(args: &[&std::ffi::OsStr]) -> Out {
    let out = Command::new(env!("CARGO_BIN_EXE_android-doctor"))
        .args(args)
        .env("NO_COLOR", "1")
        .output()
        .unwrap();
    Out {
        code: out.status.code().unwrap(),
        stdout: String::from_utf8_lossy(&out.stdout).into_owned(),
    }
}

fn setup(tag: &str) -> (Scratch, PathBuf, PathBuf) {
    let d = Scratch::new(tag);
    let (o, n) = (d.0.join("old.img"), d.0.join("new.img"));
    std::fs::write(&o, old_image()).unwrap();
    std::fs::write(&n, new_image()).unwrap();
    (d, o, n)
}

fn diff_json(o: &PathBuf, n: &PathBuf, extra: &[&str]) -> (i32, serde_json::Value) {
    let mut a: Vec<&std::ffi::OsStr> =
        vec!["diff".as_ref(), o.as_ref(), n.as_ref(), "--json".as_ref()];
    a.extend(extra.iter().map(|s| std::ffi::OsStr::new(*s)));
    let r = run(&a);
    let v = serde_json::from_str(&r.stdout).unwrap_or_else(|e| panic!("{e}: {}", r.stdout));
    (r.code, v)
}

fn statuses(v: &serde_json::Value) -> BTreeMap<String, String> {
    v["data"]["images"][0]["files"]
        .as_array()
        .unwrap()
        .iter()
        .map(|f| {
            (
                f["path"].as_str().unwrap().to_string(),
                f["status"].as_str().unwrap().to_string(),
            )
        })
        .collect()
}

#[test]
fn every_known_difference_is_reported_and_the_envelope_conforms() {
    let (_d, o, n) = setup("main");
    let (code, v) = diff_json(&o, &n, &[]);
    // A new setuid file, su binary and ro.secure=0 are high: the default gate is high.
    assert_eq!(code, 1);
    assert_eq!(v["exit_code"], 1);
    assert_eq!(v["schema"], "doctor/1");
    assert_eq!(v["tool"], "android-doctor");
    for k in ["version", "score", "findings", "data"] {
        assert!(v.get(k).is_some(), "{k}");
    }

    let s = statuses(&v);
    assert_eq!(s["added.txt"], "added");
    assert_eq!(s["gone.txt"], "removed");
    assert_eq!(s["bin/tool"], "modified");
    assert_eq!(s["bin/perm"], "metadata");
    assert_eq!(s["bin/helper"], "added");
    assert_eq!(s["etc/selinux/plat_sepolicy.cil"], "modified");
    assert_eq!(s["build.prop"], "modified");
    assert!(
        !s.contains_key("bin/same"),
        "unchanged files are only counted"
    );
    assert_eq!(v["data"]["images"][0]["counts"]["unchanged"], 1);
    let tool = v["data"]["images"][0]["files"]
        .as_array()
        .unwrap()
        .iter()
        .find(|f| f["path"] == "bin/tool")
        .unwrap();
    assert_ne!(tool["old"]["sha256"], tool["new"]["sha256"]);
    assert_eq!(tool["new"]["sha256"].as_str().unwrap().len(), 64);

    let rows = v["findings"].as_array().unwrap();
    let ids: Vec<&str> = rows.iter().map(|f| f["id"].as_str().unwrap()).collect();
    for want in [
        "diff-new-setuid",
        "diff-su-binary",
        "diff-insecure-adb",
        "diff-debuggable-build",
        "diff-root-service",
        "diff-sepolicy-changed",
        "diff-prop-changed",
    ] {
        assert!(ids.contains(&want), "{want} in {ids:?}");
    }
    assert!(!ids.contains(&"diff-new-capability"));
    let svc = rows
        .iter()
        .find(|f| f["id"] == "diff-root-service")
        .unwrap();
    assert_eq!(svc["subject"], "etc/init/a.rc");
    assert!(svc["message"].as_str().unwrap().contains("bar"));
    assert_eq!(v["data"]["images"][0]["services"][0]["name"], "bar");
    for f in rows {
        for k in [
            "id",
            "fingerprint",
            "severity",
            "category",
            "message",
            "location",
            "remedy",
        ] {
            assert!(f.get(k).is_some(), "{k} in {f}");
        }
        assert!(
            ["critical", "high", "medium", "low", "info"]
                .contains(&f["severity"].as_str().unwrap())
        );
        assert!(["file", "image", "none"].contains(&f["location"]["kind"].as_str().unwrap()));
        let fp = f["fingerprint"].as_str().unwrap();
        assert!(
            fp.len() == 16
                && fp
                    .bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        );
    }
    let (_, again) = diff_json(&o, &n, &[]);
    assert_eq!(v, again, "two runs give the same output");
}

#[test]
fn an_identical_pair_is_clean_and_exits_0() {
    let (_d, o, _) = setup("same");
    let (code, v) = diff_json(&o, &o, &[]);
    assert_eq!(code, 0);
    assert!(v["findings"].as_array().unwrap().is_empty());
    assert!(
        v["data"]["images"][0]["files"]
            .as_array()
            .unwrap()
            .is_empty()
    );
}

#[test]
fn only_filters_the_file_list_but_not_the_findings() {
    let (_d, o, n) = setup("only");
    let (_, all) = diff_json(&o, &n, &[]);
    let (_, v) = diff_json(&o, &n, &["--only", "removed,metadata"]);
    let s = statuses(&v);
    assert_eq!(s.len(), 2, "{s:?}");
    assert_eq!(v["findings"], all["findings"]);
    let bad = run(&[
        "diff".as_ref(),
        o.as_ref(),
        n.as_ref(),
        "--only".as_ref(),
        "nope".as_ref(),
    ]);
    assert_eq!(bad.code, 2);
}

#[test]
fn baseline_and_fail_on_follow_the_exit_code_contract() {
    let (d, o, n) = setup("gate");
    let base = d.0.join("base.json");
    // Against its own envelope nothing is new: exit 0.
    let (_, v) = diff_json(&o, &n, &[]);
    std::fs::write(&base, v.to_string()).unwrap();
    let r = run(&[
        "diff".as_ref(),
        o.as_ref(),
        n.as_ref(),
        "--json".as_ref(),
        "--baseline".as_ref(),
        base.as_ref(),
    ]);
    assert_eq!(r.code, 0);
    // Against an empty baseline everything is new: exit 3.
    std::fs::write(&base, "[]").unwrap();
    let r = run(&[
        "diff".as_ref(),
        o.as_ref(),
        n.as_ref(),
        "--json".as_ref(),
        "--baseline".as_ref(),
        base.as_ref(),
    ]);
    assert_eq!(r.code, 3);
    assert_eq!(
        serde_json::from_str::<serde_json::Value>(&r.stdout).unwrap()["exit_code"],
        3
    );
    // Raising the threshold above everything found lets it pass.
    let r = run(&[
        "diff".as_ref(),
        o.as_ref(),
        n.as_ref(),
        "--json".as_ref(),
        "--fail-on".as_ref(),
        "critical".as_ref(),
    ]);
    assert_eq!(r.code, 0);
    // Two different kinds of input is a usage error.
    let r = run(&["diff".as_ref(), o.as_ref(), d.0.as_ref()]);
    assert_eq!(r.code, 2);
}

#[test]
fn directories_of_images_pair_by_name_and_human_output_is_sanitized() {
    let (d, ..) = setup("dirs");
    let (a, b) = (d.0.join("a"), d.0.join("b"));
    std::fs::create_dir_all(&a).unwrap();
    std::fs::create_dir_all(&b).unwrap();
    std::fs::write(a.join("system.img"), old_image()).unwrap();
    std::fs::write(b.join("system.img"), new_image()).unwrap();
    std::fs::write(b.join("vendor.img"), old_image()).unwrap();
    let (_, v) = diff_json(&a, &b, &[]);
    let imgs = v["data"]["images"].as_array().unwrap();
    assert_eq!(imgs.len(), 2);
    assert_eq!(imgs[0]["name"], "system");
    assert_eq!(imgs[0]["presence"], "both");
    assert_eq!(imgs[1]["name"], "vendor");
    assert_eq!(imgs[1]["presence"], "added");
    let t = run(&["diff".as_ref(), a.as_ref(), b.as_ref()]);
    assert!(t.stdout.contains("added.txt"), "{}", t.stdout);
    assert!(t.stdout.contains("evil"), "{}", t.stdout);
    assert!(!t.stdout.contains('\u{1b}'), "an ESC reached the terminal");
}

#[test]
fn mcp_returns_the_cli_envelope_unchanged() {
    let (_d, o, n) = setup("mcp");
    let cli = run(&[
        "diff".as_ref(),
        o.as_ref(),
        n.as_ref(),
        "--fail-on".as_ref(),
        "low".as_ref(),
        "--json".as_ref(),
    ]);
    let call = serde_json::json!({"jsonrpc":"2.0","id":1,"method":"tools/call","params":{
        "name":"diff","arguments":{"old":o.to_str().unwrap(),"new":n.to_str().unwrap(),"fail_on":"low"}}});
    let mut child = Command::new(env!("CARGO_BIN_EXE_android-doctor"))
        .arg("mcp")
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .spawn()
        .unwrap();
    writeln!(child.stdin.take().unwrap(), "{call}").unwrap();
    let mut out = String::new();
    child
        .stdout
        .take()
        .unwrap()
        .read_to_string(&mut out)
        .unwrap();
    child.wait().unwrap();
    let r: serde_json::Value = serde_json::from_str(&out).unwrap();
    assert_eq!(r["result"]["isError"], false, "{out}");
    assert_eq!(
        r["result"]["content"][0]["text"]
            .as_str()
            .unwrap()
            .trim_end(),
        cli.stdout.trim_end()
    );
}
