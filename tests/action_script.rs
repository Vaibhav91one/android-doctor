//! Unit tests for scripts/android-doctor-action.sh (the body of action.yml): version pinning,
//! runner targets, the fail-on gate and the outputs, driven with a stub binary so no firmware
//! or network is needed. Skipped (loudly) without bash or jq.

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

fn script() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("scripts/android-doctor-action.sh")
}

fn have(tool: &str) -> bool {
    Command::new(tool).arg("--version").output().is_ok()
}

fn tools() -> bool {
    let ok = have("bash") && have("jq");
    if !ok {
        eprintln!("ACTION SCRIPT TESTS SKIPPED: bash and jq are required");
    }
    ok
}

/// Run one bash snippet with the script's functions loaded.
fn sourced(snippet: &str) -> Output {
    Command::new("bash")
        .arg("-c")
        .arg(format!("source '{}'; {snippet}", script().display()))
        .output()
        .unwrap()
}

fn out(o: &Output) -> String {
    String::from_utf8_lossy(&o.stdout).trim().to_string()
}

#[test]
fn version_comes_from_the_input_or_a_release_tag_never_latest() {
    if !tools() {
        return;
    }
    assert_eq!(out(&sourced("resolve_version 0.2.0 main")), "0.2.0");
    assert_eq!(out(&sourced("resolve_version v0.2.0 ''")), "0.2.0");
    assert_eq!(out(&sourced("resolve_version '' v1.4.2")), "1.4.2");
    assert_eq!(
        out(&sourced("resolve_version '' v1.0.0-rc.1")),
        "1.0.0-rc.1"
    );
    for bad in ["''", "main", "latest", "abc123def", "v1.2"] {
        let o = sourced(&format!("resolve_version '' {bad}"));
        assert_eq!(o.status.code(), Some(2), "{bad}");
        assert!(String::from_utf8_lossy(&o.stderr).contains("never assumed"));
    }
}

#[test]
fn runner_targets_match_the_release_assets_and_others_are_refused() {
    if !tools() {
        return;
    }
    for (os, arch, want) in [
        ("Linux", "x86_64", "x86_64-unknown-linux-gnu"),
        ("Darwin", "arm64", "aarch64-apple-darwin"),
        ("Darwin", "x86_64", "x86_64-apple-darwin"),
    ] {
        assert_eq!(out(&sourced(&format!("target_for {os} {arch}"))), want);
    }
    for (os, arch) in [
        ("Linux", "aarch64"),
        ("Windows_NT", "x86_64"),
        ("Darwin", "ppc"),
    ] {
        assert!(!sourced(&format!("target_for {os} {arch}")).status.success());
    }
}

/// A stub `android-doctor` that ignores its input and prints `json` for --json, writing a SARIF
/// with `score`; it exits `rc`.
fn stub(dir: &Path, json: &str, rc: i32) -> PathBuf {
    let bin = dir.join("android-doctor");
    std::fs::write(
        &bin,
        format!(
            "#!/usr/bin/env bash\n\
             [ \"$1\" = --version ] && {{ echo 'android-doctor stub'; exit 0; }}\n\
             while [ $# -gt 0 ]; do [ \"$1\" = --sarif ] && sarif=$2; shift; done\n\
             echo '{{\"runs\":[{{\"properties\":{{\"score\":{{\"value\":77,\"label\":\"needs work\"}}}}}}]}}' > \"$sarif\"\n\
             echo '{json}'\n\
             echo 'baseline b.json: 2 suppressed as known, 1 new' >&2\n\
             exit {rc}\n"
        ),
    )
    .unwrap();
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(&bin, std::fs::Permissions::from_mode(0o755)).unwrap();
    bin
}

struct Run {
    status: i32,
    outputs: String,
    summary: String,
}

fn run_action(tag: &str, json: &str, rc: i32, env: &[(&str, &str)]) -> Run {
    let dir = std::env::temp_dir().join(format!("ad-action-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let bin = stub(&dir, json, rc);
    let gh_out = dir.join("gh_output");
    let gh_sum = dir.join("gh_summary");
    let o = Command::new("bash")
        .arg(script())
        .env("AD_BINARY", &bin)
        .env("AD_PATH", "fw")
        .env("AD_OUT", dir.join("out"))
        .env("GITHUB_OUTPUT", &gh_out)
        .env("GITHUB_STEP_SUMMARY", &gh_sum)
        .envs(env.iter().copied())
        .output()
        .unwrap();
    let read = |p: &Path| std::fs::read_to_string(p).unwrap_or_default();
    let r = Run {
        status: o.status.code().unwrap(),
        outputs: read(&gh_out),
        summary: read(&gh_sum),
    };
    let _ = std::fs::remove_dir_all(&dir);
    r
}

const ROWS: &str = r#"[{"id":"debuggable-build","severity":"high","subject":"system","message":"ro.debuggable=1"},{"id":"x","severity":"warn","subject":"boot","message":"m"},{"id":"y","severity":"info","subject":"vendor","message":"m"}]"#;

#[test]
fn fail_on_gates_on_the_reported_severities() {
    if !tools() {
        return;
    }
    for (fail_on, want) in [("error", 0), ("high", 1), ("warn", 1), ("none", 0)] {
        let r = run_action("failon", ROWS, 0, &[("AD_FAIL_ON", fail_on)]);
        assert_eq!(r.status, want, "fail-on {fail_on}");
        assert!(r.outputs.contains(&format!("status={want}")));
    }
}

#[test]
fn outputs_and_summary_carry_the_score_counts_and_top_findings() {
    if !tools() {
        return;
    }
    let r = run_action("summary", ROWS, 0, &[("AD_FAIL_ON", "high")]);
    assert!(r.outputs.contains("score=77\n") && r.outputs.contains("sarif="));
    assert!(r.summary.contains("**77/100 (needs work)**"));
    assert!(r.summary.contains("| high | 1 |") && r.summary.contains("| warn | 1 |"));
    assert!(
        r.summary
            .contains("- **high** `debuggable-build` system: ro.debuggable=1")
    );
    assert!(r.summary.contains("failed with exit 1"));
}

#[test]
fn a_baseline_gates_with_exit_3_and_reports_the_split() {
    if !tools() {
        return;
    }
    let r = run_action(
        "baseline",
        ROWS,
        3,
        &[("AD_FAIL_ON", "high"), ("AD_BASELINE", "b.json")],
    );
    assert_eq!(r.status, 3);
    assert!(r.summary.contains("2 suppressed as known, 1 new"));
    let r = run_action("baseline-clean", "[]", 0, &[("AD_BASELINE", "b.json")]);
    assert_eq!(r.status, 0);
    assert!(r.summary.contains("- none"));
}

#[test]
fn a_tool_failure_without_a_report_keeps_its_status() {
    if !tools() {
        return;
    }
    let r = run_action("toolfail", "", 1, &[]);
    assert_eq!(r.status, 1);
    assert!(r.summary.contains("no report (exit 1)"));
    let r = run_action("badflag", "", 2, &[]);
    assert_eq!(r.status, 2);
}

#[test]
fn bad_inputs_are_refused_before_anything_runs() {
    if !tools() {
        return;
    }
    for env in [
        [("AD_FAIL_ON", "critical")],
        [("AD_COMMAND", "extract")],
        [("AD_BINARY", "/nonexistent/android-doctor")],
    ] {
        let r = run_action("badinput", ROWS, 0, &env);
        assert_eq!(r.status, 2, "{env:?}");
    }
}
