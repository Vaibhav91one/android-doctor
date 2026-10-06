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
fn score_prints_only_the_number() {
    let d = firmware("score");
    for o in [
        run!("doctor", "scan", d.as_path(), "--score"),
        run!("audit", d.join("system.img"), "--score"),
    ] {
        assert_eq!(o.code, 0, "{}", o.stderr);
        let n: u32 = o
            .stdout
            .trim()
            .parse()
            .unwrap_or_else(|_| panic!("{:?}", o.stdout));
        assert!(n < 100, "findings and a coverage gap must not score 100");
        assert_eq!(o.stdout, format!("{n}\n"), "nothing but the number");
    }
}

#[test]
fn a_scan_with_nothing_evaluated_never_scores_a_clean_hundred() {
    // an unpacked block OTA: no .img files, so every quality rule emits "cannot evaluate"
    let d = Scratch::new("score-gaps");
    for f in [
        "system.transfer.list",
        "system.new.dat",
        "vendor.transfer.list",
        "boot.img",
    ] {
        std::fs::write(d.join(f), b"x").unwrap();
    }
    let o = run!("doctor", "scan", d.as_path(), "--score");
    let n: u32 = o.stdout.trim().parse().unwrap();
    assert!(n < 90, "six rules did not run, score was {n}");
}

#[test]
fn score_conflicts_with_json_and_json_gains_a_score_for_audit() {
    let d = firmware("score-json");
    let o = run!("audit", d.join("system.img"), "--score", "--json");
    assert_eq!(o.code, 2, "clap usage error");
    let o = run!("audit", d.join("system.img"), "--json");
    let v = json(&o.stdout);
    assert!(v["score"]["value"].as_u64().unwrap() <= 100);
    assert!(v["score"]["label"].is_string());
    // original keys are all still there
    assert!(v["adb"].is_string() && v["images"].is_array());
    assert!(v["findings"][0]["fingerprint"].is_string());
}

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

#[test]
fn doctor_baseline_reports_only_new_findings_and_exits_3() {
    let d = firmware("baseline-doctor");
    let meta = Scratch::new("meta-a");
    let base = meta.join("baseline.json");
    let first = run!("doctor", "scan", d.as_path(), "--json");
    assert_eq!(first.code, 0);
    std::fs::write(&base, &first.stdout).unwrap();

    // nothing changed: nothing new, exit 0, the known ones are counted
    let same = run!("doctor", "scan", d.as_path(), "--baseline", base);
    assert_eq!(same.code, 0, "{}{}", same.stdout, same.stderr);
    assert!(
        same.stdout.contains("2 suppressed as known, 0 new"),
        "{}",
        same.stdout
    );
    assert!(!same.stdout.contains("mystery.bin"), "{}", same.stdout);

    // a new unhandled file: only it is reported, and the exit code says so
    std::fs::write(d.join("extra.dat"), b"x").unwrap();
    let new = run!("doctor", "scan", d.as_path(), "--baseline", base);
    assert_eq!(new.code, 3, "{}{}", new.stdout, new.stderr);
    assert!(new.stdout.contains("extra.dat"), "{}", new.stdout);
    assert!(!new.stdout.contains("mystery.bin"), "{}", new.stdout);
    assert!(new.stderr.contains("1 new finding"), "{}", new.stderr);

    // the baseline works from another directory: a copy of the firmware at a different path
    let copy = Scratch::new("baseline-doctor-copy");
    for e in std::fs::read_dir(&*d).unwrap() {
        let e = e.unwrap();
        if e.file_name() != "extra.dat" && e.file_name() != "baseline.json" {
            std::fs::copy(e.path(), copy.join(e.file_name())).unwrap();
        }
    }
    let moved = run!("doctor", "scan", copy.as_path(), "--baseline", base);
    assert_eq!(
        moved.code, 0,
        "fingerprints must not depend on the host path: {}",
        moved.stdout
    );
}

#[test]
fn audit_baseline_reports_only_new_findings_and_exits_3() {
    let d = firmware("baseline-audit");
    let sys = d.join("system.img");
    let base = d.join("baseline.json");
    let first = run!("audit", sys, "--json");
    assert_eq!(first.code, 0);
    std::fs::write(&base, &first.stdout).unwrap();
    let same = run!("audit", sys, "--baseline", base);
    assert_eq!(same.code, 0, "{}{}", same.stdout, same.stderr);
    assert!(same.stdout.contains("no new findings"), "{}", same.stdout);

    std::fs::write(&sys, system_image(true)).unwrap(); // adds /sbin/su
    let new = run!("audit", sys, "--baseline", base, "--json");
    assert_eq!(new.code, 3, "{}{}", new.stdout, new.stderr);
    let v = json(&new.stdout);
    let rows = v["findings"].as_array().unwrap();
    assert_eq!(rows.len(), 1, "{rows:?}");
    assert_eq!(rows[0]["id"], "su-binary");
    assert_eq!(rows[0]["subject"], "sbin/su");
    // the score is for the whole scan, not just the new part
    assert!(v["score"]["value"].as_u64().unwrap() < 90);
    assert!(new.stderr.contains("suppressed as known"), "{}", new.stderr);
}

#[test]
fn a_bad_baseline_is_a_clear_error_not_a_silent_pass() {
    let d = firmware("baseline-bad");
    let sys = d.join("system.img");
    let missing = d.join("nope.json");
    let foreign = d.join("foreign.json");
    std::fs::write(&foreign, br#"{"hello": "world"}"#).unwrap();
    let junk = d.join("junk.json");
    std::fs::write(&junk, b"not json").unwrap();
    let old = d.join("old.json");
    std::fs::write(&old, br#"[{"id":"x","severity":"warn"}]"#).unwrap();
    for (file, want) in [
        (&missing, "cannot read baseline"),
        (&foreign, "not an android-doctor report"),
        (&junk, "not valid JSON"),
        (&old, "no fingerprint"),
    ] {
        for o in [
            run!("audit", sys, "--baseline", file),
            run!("doctor", "scan", d.as_path(), "--baseline", file),
        ] {
            assert_eq!(o.code, 1, "{}", o.stderr);
            assert!(o.stderr.contains(want), "want {want:?} in {}", o.stderr);
            assert!(
                o.stdout.is_empty(),
                "no report on a baseline error: {}",
                o.stdout
            );
        }
    }
}

#[test]
fn exit_code_precedence_error_severity_beats_new_findings_and_known_errors_do_not_fail() {
    // no images at all: partition_coverage is an error finding (exit 1, as before)
    let d = Scratch::new("exit-codes");
    std::fs::write(d.join("readme.txt"), b"hello").unwrap();
    let plain = run!("doctor", "scan", d.as_path());
    assert_eq!(plain.code, 1, "{}", plain.stderr);
    assert!(plain.stderr.contains("severity error"));

    // record it, then re-run against it: the error is known, so exit 0
    let meta = Scratch::new("meta-c");
    let base = meta.join("baseline.json");
    let rec = run!("doctor", "scan", d.as_path(), "--json");
    assert_eq!(rec.code, 1, "--json still fails on an error finding");
    std::fs::write(&base, &rec.stdout).unwrap();
    std::fs::remove_file(d.join("readme.txt")).unwrap();
    std::fs::write(d.join("readme.txt"), b"hello").unwrap();
    let known = run!("doctor", "scan", d.as_path(), "--baseline", base);
    assert_eq!(known.code, 0, "{}{}", known.stdout, known.stderr);

    // a baseline that does not have the error: it is new AND an error, so 1 wins over 3
    let empty = meta.join("empty.json");
    std::fs::write(&empty, b"[]").unwrap();
    let both = run!("doctor", "scan", d.as_path(), "--baseline", empty);
    assert_eq!(both.code, 1, "{}{}", both.stdout, both.stderr);

    // a new non-error finding is 3
    let w = firmware("exit-codes-warn");
    let o = run!("doctor", "scan", w.as_path(), "--baseline", empty);
    assert_eq!(o.code, 3, "{}{}", o.stdout, o.stderr);

    // a usage error is clap's 2
    assert_eq!(run!("doctor", "scan", w.as_path(), "--baseline").code, 2);
}

#[test]
fn coverage_gaps_are_never_suppressed_by_a_baseline_and_never_gate() {
    let d = firmware("gaps");
    let meta = Scratch::new("meta-d");
    let base = meta.join("baseline.json");
    let first = run!("doctor", "scan", d.as_path(), "--json");
    std::fs::write(&base, &first.stdout).unwrap();
    let o = run!("doctor", "scan", d.as_path(), "--baseline", base);
    assert_eq!(o.code, 0);
    // the AVB rule did not run; a baseline cannot vouch for that, so it is still listed
    assert!(o.stdout.contains("avb_signature"), "{}", o.stdout);
}
