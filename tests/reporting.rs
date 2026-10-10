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
        assert!(r["partialFingerprints"]["doctorFinding/v1"].is_string());
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
    assert_eq!(m["level"], "note");
    assert_eq!(
        m["locations"][0]["physicalLocation"]["artifactLocation"]["uri"],
        "mystery.bin"
    );
    let log = results
        .iter()
        .find(|r| {
            r["ruleId"] == "debug_leftovers"
                && r["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
                    == "system/etc/old.log"
        })
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
    assert_eq!(o.code, 2);
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
    assert!(v["data"]["adb"].is_string() && v["data"]["images"].is_array());
    assert_eq!(v["score"]["model"], "android/1");
    assert!(v["findings"][0]["fingerprint"].is_string());
}

#[test]
fn piped_doctor_output_is_the_plain_face_and_json_rows_keep_their_keys() {
    let d = firmware("flat");
    let o = run!("doctor", "scan", d.as_path());
    assert_eq!(o.code, 0);
    // piped: the plain face, one line per finding
    let line = o
        .stdout
        .lines()
        .find(|l| l.contains("unhandled_input"))
        .unwrap_or_default();
    assert!(
        line.starts_with("low")
            && line.contains("mystery.bin")
            && line.contains("no handler for this file"),
        "{}",
        o.stdout
    );
    assert!(!o.stdout.contains('╭'), "no boxed report when piped");
    let o = run!("doctor", "scan", d.as_path(), "--json");
    let rows = json(&o.stdout);
    let row = &rows["findings"].as_array().unwrap()[0];
    for k in [
        "id", "category", "severity", "location", "message", "remedy", "subject",
    ] {
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
    assert_eq!(
        v["baseline"],
        serde_json::json!({"new": 1, "unchanged": 3, "fixed": 0})
    );
    let rows: Vec<_> = v["findings"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|r| r["baseline_state"] == "new")
        .collect();
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
            assert_eq!(o.code, 2, "{}", o.stderr);
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
fn exit_codes_follow_fail_on_and_baseline() {
    // no images at all: partition_coverage is a critical finding, doctor scan fails on it
    let d = Scratch::new("exit-codes");
    std::fs::write(d.join("readme.txt"), b"hello").unwrap();
    let plain = run!("doctor", "scan", d.as_path());
    assert_eq!(plain.code, 1, "{}", plain.stderr);
    assert!(plain.stderr.contains("critical"), "{}", plain.stderr);
    // the envelope carries the real exit code
    let rec = run!("doctor", "scan", d.as_path(), "--json");
    assert_eq!(rec.code, 1, "--json still fails on a critical finding");
    assert_eq!(json(&rec.stdout)["exit_code"], 1);
    // raising the bar is a pass (the critical one is below nothing), lowering never hides it
    assert_eq!(
        run!("doctor", "scan", d.as_path(), "--fail-on", "info").code,
        1
    );

    // record it, then re-run against it: known, so exit 0
    let meta = Scratch::new("meta-c");
    let base = meta.join("baseline.json");
    std::fs::write(&base, &rec.stdout).unwrap();
    let known = run!("doctor", "scan", d.as_path(), "--baseline", base);
    assert_eq!(known.code, 0, "{}{}", known.stdout, known.stderr);

    // an empty baseline: the critical finding is new, which is 3 (3 beats 1)
    let empty = meta.join("empty.json");
    std::fs::write(&empty, b"[]").unwrap();
    let both = run!("doctor", "scan", d.as_path(), "--baseline", empty);
    assert_eq!(both.code, 3, "{}{}", both.stdout, both.stderr);

    // a new low finding gates at the default baseline level, but not above --fail-on high
    let w = firmware("exit-codes-warn");
    assert_eq!(
        run!("doctor", "scan", w.as_path(), "--baseline", empty).code,
        3
    );
    let o = run!(
        "doctor",
        "scan",
        w.as_path(),
        "--baseline",
        empty,
        "--fail-on",
        "high"
    );
    assert_eq!(o.code, 0, "{}{}", o.stdout, o.stderr);
    // audit never fails without --fail-on, and does with it
    assert_eq!(run!("audit", w.join("system.img")).code, 0);
    assert_eq!(
        run!("audit", w.join("system.img"), "--fail-on", "high").code,
        1
    );
    assert_eq!(
        run!("audit", w.join("system.img"), "--fail-on", "critical").code,
        0
    );
    // old names still parse; a bad one and a missing file are 2
    assert_eq!(
        run!("audit", w.join("system.img"), "--fail-on", "warn").code,
        1
    );
    assert_eq!(
        run!("audit", w.join("system.img"), "--fail-on", "bogus").code,
        2
    );
    assert_eq!(run!("audit", w.join("nope.img")).code, 2);
    assert_eq!(run!("doctor", "scan", w.as_path(), "--baseline").code, 2);
}

/// doctor/1 section 9.
#[test]
fn json_conforms_to_the_doctor_1_envelope() {
    let d = firmware("conformance");
    let sys = d.join("system.img");
    for args in [
        vec![
            "doctor".as_ref(),
            "scan".as_ref(),
            d.as_os_str(),
            "--json".as_ref(),
        ],
        vec!["audit".as_ref(), sys.as_os_str(), "--json".as_ref()],
    ] {
        let a = run_os(&args);
        let v = json(&a.stdout);
        for k in [
            "schema",
            "tool",
            "version",
            "exit_code",
            "score",
            "findings",
            "data",
        ] {
            assert!(v.get(k).is_some(), "{k}");
        }
        assert_eq!(v["schema"], "doctor/1");
        assert_eq!(v["tool"], "android-doctor");
        assert_eq!(v["exit_code"], a.code);
        assert!(
            v["score"]["model"]
                .as_str()
                .unwrap()
                .starts_with("android/")
        );
        let rows = v["findings"].as_array().unwrap();
        assert!(!rows.is_empty());
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
            assert!(
                [
                    "file",
                    "flow",
                    "frame",
                    "image",
                    "card-path",
                    "device",
                    "service",
                    "none"
                ]
                .contains(&f["location"]["kind"].as_str().unwrap())
            );
            let fp = f["fingerprint"].as_str().unwrap();
            assert!(
                fp.len() == 16
                    && fp
                        .bytes()
                        .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
            );
            assert!(f.get("baseline_state").is_none());
        }
        let b = run_os(&args);
        let w = json(&b.stdout);
        assert_eq!(v["findings"], w["findings"]);
        assert_eq!(v["score"], w["score"]);
    }
}

/// doctor/1 section 7: the MCP reply is the CLI's stdout, byte for byte.
#[test]
fn mcp_returns_the_cli_envelope_unchanged() {
    use std::io::{Read, Write};
    let d = firmware("mcp");
    let base = d.join("b.json");
    std::fs::write(&base, b"[]").unwrap();
    let cli = run!(
        "doctor",
        "scan",
        d.as_path(),
        "--baseline",
        base,
        "--fail-on",
        "low",
        "--json"
    );
    let call = serde_json::json!({"jsonrpc":"2.0","id":1,"method":"tools/call","params":{
        "name":"doctor","arguments":{"path":d.to_str().unwrap(),"baseline":base.to_str().unwrap(),"fail_on":"low"}}});
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
    let r = json(&out);
    assert_eq!(r["result"]["isError"], false, "{out}");
    assert_eq!(
        r["result"]["content"][0]["text"]
            .as_str()
            .unwrap()
            .trim_end(),
        cli.stdout.trim_end()
    );
    assert_eq!(json(&cli.stdout)["exit_code"], 3);
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
