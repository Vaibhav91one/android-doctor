//! End-to-end tests for `--sarif`, `--baseline` and `--score` on `audit` and `doctor scan`.
//!
//! Each test builds a small firmware directory from generated erofs images (no real firmware)
//! and runs the built binary on it, asserting stdout, stderr and the exit code.

use fs_erofs::mkfs::{Node, NodeMeta, build_image};
use std::collections::BTreeMap;
use std::path::PathBuf;
use std::process::Command;

struct Scratch(PathBuf);

impl Scratch {
    fn new(tag: &str) -> Self {
        let dir = std::env::temp_dir().join(format!("ad-report-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        Self(dir)
    }
}

impl std::ops::Deref for Scratch {
    type Target = PathBuf;
    fn deref(&self) -> &PathBuf {
        &self.0
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

/// An erofs image with a debuggable build.prop, a su binary and a leftover log.
fn system_image(extra_su: bool) -> Vec<u8> {
    let mut entries = vec![
        (
            "build.prop",
            file(
                0o644,
                b"ro.debuggable=1\nro.secure=0\nro.build.tags=release-keys\n",
            ),
        ),
        ("etc", dir(vec![("old.log", file(0o644, b"log"))])),
        ("xbin", dir(vec![("su", file(0o755, b"#!/bin/sh\n"))])),
    ];
    if extra_su {
        entries.push(("sbin", dir(vec![("su", file(0o755, b"#!/bin/sh\n"))])));
    }
    build_image(dir(entries), 12).unwrap()
}

fn vendor_image() -> Vec<u8> {
    build_image(dir(vec![("build.prop", file(0o644, b"ro.secure=1\n"))]), 12).unwrap()
}

/// system.img, vendor.img, boot.img and one file doctor has no handler for. No vbmeta.img, so
/// the AVB rule cannot evaluate.
fn firmware(tag: &str) -> Scratch {
    let d = Scratch::new(tag);
    std::fs::write(d.join("system.img"), system_image(false)).unwrap();
    std::fs::write(d.join("vendor.img"), vendor_image()).unwrap();
    let mut boot = vec![0u8; 1680];
    boot[..8].copy_from_slice(b"ANDROID!");
    std::fs::write(d.join("boot.img"), boot).unwrap();
    std::fs::write(d.join("mystery.bin"), b"??").unwrap();
    d
}

struct Out {
    code: i32,
    stdout: String,
    stderr: String,
}

macro_rules! run {
    ($($x:expr),* $(,)?) => {
        run_os(&[$(AsRef::<std::ffi::OsStr>::as_ref(&$x)),*])
    };
}

fn run_os(args: &[&std::ffi::OsStr]) -> Out {
    let out = Command::new(env!("CARGO_BIN_EXE_android-doctor"))
        .args(args)
        .env("NO_COLOR", "1")
        .output()
        .expect("spawn android-doctor");
    Out {
        code: out.status.code().expect("exit code"),
        stdout: String::from_utf8_lossy(&out.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&out.stderr).into_owned(),
    }
}

fn json(text: &str) -> serde_json::Value {
    serde_json::from_str(text).unwrap_or_else(|e| panic!("not JSON ({e}): {text}"))
}

// --- --sarif ---------------------------------------------------------------------------------

/// The required properties of SARIF 2.1.0 that the output relies on.
fn assert_valid_sarif(doc: &serde_json::Value) -> &Vec<serde_json::Value> {
    assert_eq!(doc["version"], "2.1.0");
    assert!(
        doc["$schema"]
            .as_str()
            .unwrap()
            .contains("sarif-schema-2.1.0")
    );
    let run = &doc["runs"][0];
    let driver = &run["tool"]["driver"];
    assert_eq!(driver["name"], "android-doctor");
    assert!(driver["version"].is_string() && driver["informationUri"].is_string());
    let rules = driver["rules"].as_array().unwrap();
    let results = run["results"].as_array().unwrap();
    for r in results {
        assert!(r["message"]["text"].is_string());
        assert!(["error", "warning", "note"].contains(&r["level"].as_str().unwrap()));
        let idx = r["ruleIndex"].as_u64().unwrap() as usize;
        assert_eq!(
            rules[idx]["id"], r["ruleId"],
            "ruleId resolves in driver.rules"
        );
        assert!(r["partialFingerprints"]["androidDoctorFinding/v1"].is_string());
        for l in r["locations"].as_array().into_iter().flatten() {
            let uri = l["physicalLocation"]["artifactLocation"]["uri"]
                .as_str()
                .unwrap();
            assert!(
                !uri.starts_with('/') && !uri.contains("ad-report"),
                "relative: {uri}"
            );
        }
    }
    let score = &run["properties"]["score"]["value"];
    assert!(score.as_u64().unwrap() <= 100);
    results
}

#[test]
fn audit_writes_sarif_with_locations_inside_the_image() {
    let d = firmware("sarif-audit");
    let sarif = d.join("out.sarif");
    let o = run!("audit", d.join("system.img"), "--sarif", sarif);
    assert_eq!(o.code, 0, "{}", o.stderr);
    // the normal text output is still printed
    assert!(o.stdout.contains("debuggable-build"), "{}", o.stdout);
    let doc = json(&std::fs::read_to_string(&sarif).unwrap());
    let results = assert_valid_sarif(&doc);
    let dbg = results
        .iter()
        .find(|r| r["ruleId"] == "debuggable-build")
        .unwrap();
    assert_eq!(dbg["level"], "error");
    assert_eq!(
        dbg["locations"][0]["physicalLocation"]["artifactLocation"]["uri"],
        "system/build.prop"
    );
    let su = results.iter().find(|r| r["ruleId"] == "su-binary").unwrap();
    assert_eq!(
        su["locations"][0]["physicalLocation"]["artifactLocation"]["uri"],
        "system/xbin/su"
    );
    // a rule's help text comes from its remedy
    let rules = doc["runs"][0]["tool"]["driver"]["rules"]
        .as_array()
        .unwrap();
    let rule = rules
        .iter()
        .find(|r| r["id"] == "debuggable-build")
        .unwrap();
    assert!(
        rule["help"]["text"]
            .as_str()
            .unwrap()
            .contains("ro.debuggable=0")
    );
}

#[test]
fn doctor_scan_writes_sarif_with_a_score_and_relative_locations() {
    let d = firmware("sarif-doctor");
    let sarif = d.join("out.sarif");
    let o = run!("doctor", "scan", d.as_path(), "--sarif", sarif);
    assert_eq!(o.code, 0, "{}", o.stderr);
    let doc = json(&std::fs::read_to_string(&sarif).unwrap());
    let results = assert_valid_sarif(&doc);
    let m = results
        .iter()
        .find(|r| r["ruleId"] == "unhandled_input")
        .unwrap();
    assert_eq!(m["level"], "warning");
    assert_eq!(
        m["locations"][0]["physicalLocation"]["artifactLocation"]["uri"],
        "mystery.bin"
    );
    let log = results
        .iter()
        .find(|r| r["ruleId"] == "debug_leftovers" && r["level"] == "warning")
        .unwrap();
    assert_eq!(
        log["locations"][0]["physicalLocation"]["artifactLocation"]["uri"],
        "system/etc/old.log"
    );
    // vbmeta.img is absent: the rule did not run, which SARIF carries as a note, not silence
    let avb = results
        .iter()
        .find(|r| r["ruleId"] == "avb_signature")
        .unwrap();
    assert_eq!(avb["level"], "note");
    assert_eq!(avb["properties"]["coverageGap"], true);
    assert!(
        doc["runs"][0]["properties"]["score"]["value"]
            .as_u64()
            .unwrap()
            < 100
    );
}

#[test]
fn sarif_to_an_unwritable_path_is_an_error() {
    let d = firmware("sarif-bad");
    let o = run!(
        "doctor",
        "scan",
        d.as_path(),
        "--sarif",
        d.join("no/such/dir/x.sarif")
    );
    assert_eq!(o.code, 1);
    assert!(o.stderr.contains("cannot write SARIF"), "{}", o.stderr);
}

// --- --score ---------------------------------------------------------------------------------

#[test]
fn piped_doctor_output_is_still_the_flat_list_and_json_rows_keep_their_keys() {
    let d = firmware("flat");
    let o = run!("doctor", "scan", d.as_path());
    assert_eq!(o.code, 0);
    assert!(
        o.stdout
            .contains("warn security unhandled_input: mystery.bin: no handler for this file"),
        "{}",
        o.stdout
    );
    assert!(!o.stdout.contains("Next steps"), "no digest when piped");
    let o = run!("doctor", "scan", d.as_path(), "--json");
    let rows = json(&o.stdout);
    let row = &rows.as_array().unwrap()[0];
    for k in ["id", "category", "severity", "subject", "message", "remedy"] {
        assert!(row.get(k).is_some(), "{k} kept");
    }
    assert!(row["fingerprint"].is_string());
}

// --- --baseline and exit codes ----------------------------------------------------------------
