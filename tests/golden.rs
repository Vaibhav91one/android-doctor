//! Golden snapshots of the machine-readable surface (decision 1 of the doctor-kit migration:
//! machine output stays byte-identical). Covered: `--json` envelopes and SARIF of every findings
//! command, `--help` texts, the MCP stdio transcript, install file bodies (skill, `.mdc`,
//! AGENTS.md block markers, CI workflow), `fix --print`, and exit codes (incl. 3 for baseline).
//! Human terminal text (digest, flat list) is NOT snapshotted: it is allowed to change.
//!
//! Goldens live in tests/golden/ and are compared byte for byte. `UPDATE_GOLDENS=1 cargo test
//! --test golden` rewrites them; review the diff before committing.
//!
//! Normalisation (the only one): the per-run scratch directory (also its canonical form) becomes
//! `<TMP>` and the crate version becomes `<VERSION>`, so goldens survive temp names and releases.
//! Fixtures are generated in-process (erofs builder, no mke2fs) plus the plain `ota-blocks`
//! corpus case, so nothing depends on the host's tools or clock.

use fs_erofs::mkfs::{Node, NodeMeta, build_image};
use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

/// The binary under test. `AD_GOLDEN_BIN=/path/to/older/android-doctor cargo test --test golden`
/// replays the goldens against another build, to prove a refactor kept the behaviour.
fn bin() -> String {
    std::env::var("AD_GOLDEN_BIN").unwrap_or_else(|_| env!("CARGO_BIN_EXE_android-doctor").into())
}

struct Scratch(PathBuf);
impl Scratch {
    fn new(tag: &str) -> Self {
        let dir = std::env::temp_dir().join(format!("ad-golden-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        Self(std::fs::canonicalize(dir).unwrap())
    }
    /// A path under the scratch root, parent directories created.
    fn p(&self, rel: &str) -> PathBuf {
        let p = self.0.join(rel);
        std::fs::create_dir_all(p.parent().unwrap()).unwrap();
        p
    }
}
impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// Replace the scratch root and the version; see the module doc. Scanned fixtures live in
/// `<TMP>/fw`, `<TMP>/diff`, `<TMP>/ota-blocks`; baselines and SARIF go to `<TMP>/meta`, so
/// they are never scanned themselves.
fn norm(s: &str, tmp: &Path) -> String {
    s.replace(tmp.to_str().unwrap(), "<TMP>")
        .replace(env!("CARGO_PKG_VERSION"), "<VERSION>")
}

/// Compare `actual` with tests/golden/`name` byte for byte (or rewrite it under UPDATE_GOLDENS).
fn golden(name: &str, actual: &str) {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/golden")
        .join(name);
    if std::env::var_os("UPDATE_GOLDENS").is_some() {
        std::fs::write(&path, actual).unwrap();
        return;
    }
    let want = std::fs::read(&path)
        .unwrap_or_else(|_| panic!("missing golden {name}; run with UPDATE_GOLDENS=1"));
    assert!(
        want == actual.as_bytes(),
        "golden {name} differs; if intended, run UPDATE_GOLDENS=1 cargo test --test golden\n--- want\n{}\n--- got\n{actual}",
        String::from_utf8_lossy(&want)
    );
}

/// Run the binary; snapshot stdout as `<name>.out`, record the exit code in `codes`.
fn case(
    codes: &mut String,
    tmp: &Scratch,
    name: &str,
    args: &[&dyn AsRef<std::ffi::OsStr>],
) -> String {
    let out = Command::new(bin())
        .args(args.iter().map(|a| a.as_ref()))
        .env("NO_COLOR", "1")
        .env("COLUMNS", "100")
        .output()
        .unwrap();
    let stdout = norm(&String::from_utf8_lossy(&out.stdout), &tmp.0);
    golden(&format!("{name}.out"), &stdout);
    writeln!(codes, "{name}\t{}", out.status.code().unwrap()).unwrap();
    stdout
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
fn img(n: Node) -> Vec<u8> {
    build_image(n, 12).unwrap()
}

/// system.img (debuggable, su, leftover log), vendor.img, boot.img, an unhandled file; no vbmeta,
/// so the AVB rule cannot evaluate (a coverage gap).
fn firmware(tag: &str) -> Scratch {
    let d = Scratch::new(tag);
    let system = dir(vec![
        (
            "build.prop",
            file(
                0o644,
                b"ro.debuggable=1\nro.secure=0\nro.build.tags=release-keys\n",
            ),
        ),
        ("etc", dir(vec![("old.log", file(0o644, b"log"))])),
        ("xbin", dir(vec![("su", file(0o755, b"#!/bin/sh\n"))])),
    ]);
    std::fs::write(d.p("fw/system.img"), img(system)).unwrap();
    std::fs::write(
        d.p("fw/vendor.img"),
        img(dir(vec![("build.prop", file(0o644, b"ro.secure=1\n"))])),
    )
    .unwrap();
    let mut boot = vec![0u8; 1680];
    boot[..8].copy_from_slice(b"ANDROID!");
    std::fs::write(d.p("fw/boot.img"), boot).unwrap();
    std::fs::write(d.p("fw/mystery.bin"), b"??").unwrap();
    d
}

fn old_new(d: &Scratch) {
    let old = dir(vec![
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
    ]);
    let new = dir(vec![
        ("build.prop", file(0o644, b"ro.secure=0\nro.debuggable=1\n")),
        ("added.txt", file(0o644, b"new")),
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
    ]);
    std::fs::write(d.p("diff/old.img"), img(old)).unwrap();
    std::fs::write(d.p("diff/new.img"), img(new)).unwrap();
}

fn corpus_ota(d: &Scratch) -> PathBuf {
    let dst = d.p("ota-blocks");
    std::fs::create_dir_all(&dst).unwrap();
    let src = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/corpus/trees/ota-blocks");
    for e in std::fs::read_dir(src).unwrap() {
        let e = e.unwrap();
        std::fs::copy(e.path(), dst.join(e.file_name())).unwrap();
    }
    dst
}

/// The matrix for one findings command: json, sarif, score, fail-on, and every baseline outcome.
/// `base` is the command prefix (`audit X` / `doctor scan D` / `diff A B`).
fn findings_matrix(
    codes: &mut String,
    t: &Scratch,
    tag: &str,
    base: &[&dyn AsRef<std::ffi::OsStr>],
    score: bool,
) {
    let sarif = t.p(&format!("meta/{tag}.sarif"));
    let run = |codes: &mut String, name: &str, extra: &[&dyn AsRef<std::ffi::OsStr>]| {
        let mut a: Vec<&dyn AsRef<std::ffi::OsStr>> = base.to_vec();
        a.extend_from_slice(extra);
        case(codes, t, &format!("{tag}-{name}"), &a)
    };
    let json = run(codes, "json", &[&"--json"]);
    run(
        codes,
        "json-fail-on-low",
        &[&"--json", &"--fail-on", &"low"],
    );
    run(
        codes,
        "json-fail-on-info",
        &[&"--json", &"--fail-on", &"info"],
    );
    run(
        codes,
        "json-fail-on-critical",
        &[&"--json", &"--fail-on", &"critical"],
    );
    run(codes, "json-sarif", &[&"--json", &"--sarif", &sarif]);
    golden(
        &format!("{tag}.sarif"),
        &norm(&std::fs::read_to_string(&sarif).unwrap(), &t.0),
    );
    if score {
        run(codes, "score", &[&"--score"]);
    }
    // baseline: empty (everything new, exit 3), itself (nothing new, exit 0)
    let empty = t.p(&format!("meta/{tag}-empty-baseline.json"));
    std::fs::write(&empty, "[]").unwrap();
    run(
        codes,
        "baseline-empty-json",
        &[&"--json", &"--baseline", &empty],
    );
    let sarif2 = t.p(&format!("meta/{tag}-b.sarif"));
    run(
        codes,
        "baseline-empty-sarif",
        &[&"--json", &"--baseline", &empty, &"--sarif", &sarif2],
    );
    golden(
        &format!("{tag}-baseline.sarif"),
        &norm(&std::fs::read_to_string(&sarif2).unwrap(), &t.0),
    );
    let own = t.p(&format!("meta/{tag}-own-baseline.json"));
    std::fs::write(
        &own,
        json.replace("<TMP>", t.0.to_str().unwrap())
            .replace("<VERSION>", env!("CARGO_PKG_VERSION")),
    )
    .unwrap();
    run(
        codes,
        "baseline-own-json",
        &[&"--json", &"--baseline", &own],
    );
    let bad = t.p(&format!("meta/{tag}-bad-baseline.json"));
    std::fs::write(&bad, "not json").unwrap();
    run(codes, "baseline-bad", &[&"--json", &"--baseline", &bad]);
}

#[test]
fn findings_commands() {
    let t = firmware("find");
    old_new(&t);
    let ota = corpus_ota(&t);
    let mut codes = String::new();
    let (sys, fw, old, new) = (
        t.p("fw/system.img"),
        t.0.clone(),
        t.p("diff/old.img"),
        t.p("diff/new.img"),
    );
    findings_matrix(&mut codes, &t, "audit", &[&"audit", &sys], true);
    findings_matrix(
        &mut codes,
        &t,
        "doctor-scan",
        &[&"doctor", &"scan", &fw],
        true,
    );
    findings_matrix(&mut codes, &t, "diff", &[&"diff", &old, &new], false);
    findings_matrix(
        &mut codes,
        &t,
        "doctor-scan-ota",
        &[&"doctor", &"scan", &ota],
        true,
    );
    // usage and input errors: exit 2, nothing on stdout worth pinning beyond that
    case(
        &mut codes,
        &t,
        "error-missing-path",
        &[&"doctor", &"scan", &t.p("nope")],
    );
    case(
        &mut codes,
        &t,
        "error-score-and-json",
        &[&"audit", &sys, &"--score", &"--json"],
    );
    case(&mut codes, &t, "fix-print", &[&"fix", &"--print", &ota]);
    golden("findings.exit", &codes);
}

/// Run the binary and snapshot exit code, stdout and stderr together (for cases whose stderr text
/// is part of the behaviour being pinned) as one `<name>.out` section appended to `acc`.
fn case_all(acc: &mut String, tmp: &Scratch, name: &str, args: &[&dyn AsRef<std::ffi::OsStr>]) {
    let out = Command::new(bin())
        .args(args.iter().map(|a| a.as_ref()))
        .env("NO_COLOR", "1")
        .env("COLUMNS", "100")
        .output()
        .unwrap();
    writeln!(
        acc,
        "=== {name} (exit {})\n--- stdout\n{}--- stderr\n{}",
        out.status.code().unwrap(),
        norm(&String::from_utf8_lossy(&out.stdout), &tmp.0),
        norm(&String::from_utf8_lossy(&out.stderr), &tmp.0)
    )
    .unwrap();
}

/// Which baseline files are accepted, and the exact words of the refusals (decision 6: the tool
/// keeps its own baseline parsing: no `schema` requirement, no size cap).
#[test]
fn baseline_variants() {
    let t = firmware("baseline-variants");
    let fw = t.0.join("fw");
    let json = Command::new(bin())
        .args(["doctor", "scan"])
        .arg(&fw)
        .arg("--json")
        .output()
        .unwrap();
    let env: serde_json::Value = serde_json::from_slice(&json.stdout).unwrap();
    let rows = env["findings"].clone();
    let mut acc = String::new();
    let cases: Vec<(&str, String)> = vec![
        (
            "object-without-schema",
            serde_json::json!({"findings": rows}).to_string(),
        ),
        ("bare-array", rows.to_string()),
        (
            "other-schema-name",
            serde_json::json!({"schema": "other/9", "findings": rows}).to_string(),
        ),
        ("empty-array", "[]".into()),
        ("empty-findings", r#"{"findings":[]}"#.into()),
        ("no-findings-key", r#"{"hello":"world"}"#.into()),
        (
            "row-without-fingerprint",
            r#"[{"id":"x","severity":"warn"}]"#.into(),
        ),
        ("scalar", "42".into()),
        ("not-json", "not json".into()),
    ];
    for (name, body) in cases {
        let f = t.p(&format!("meta/{name}.json"));
        std::fs::write(&f, body).unwrap();
        case_all(
            &mut acc,
            &t,
            &format!("doctor-scan {name}"),
            &[&"doctor", &"scan", &fw, &"--baseline", &f, &"--json"],
        );
    }
    case_all(
        &mut acc,
        &t,
        "doctor-scan missing-file",
        &[
            &"doctor",
            &"scan",
            &fw,
            &"--baseline",
            &t.p("meta/nope.json"),
        ],
    );
    // the human views under a baseline: nothing new, and only the new one
    let own = t.p("meta/own.json");
    std::fs::write(&own, &json.stdout).unwrap();
    case_all(
        &mut acc,
        &t,
        "doctor-scan human-all-known",
        &[&"doctor", &"scan", &fw, &"--baseline", &own],
    );
    case_all(
        &mut acc,
        &t,
        "audit human-baseline-empty",
        &[
            &"audit",
            &t.p("fw/system.img"),
            &"--baseline",
            &t.p("meta/empty-array.json"),
        ],
    );
    case_all(
        &mut acc,
        &t,
        "audit never-gates-without-flags",
        &[&"audit", &t.p("fw/system.img"), &"--score"],
    );
    golden("baseline-variants.out", &acc);
}

fn show(acc: &mut String, label: &str, path: &Path, tmp: &Scratch) {
    let body = match std::fs::symlink_metadata(path) {
        Ok(m) if m.file_type().is_symlink() => "(a symlink)".to_string(),
        Ok(_) => norm(&std::fs::read_to_string(path).unwrap(), &tmp.0),
        Err(_) => "(missing)".to_string(),
    };
    writeln!(acc, "--- {label}\n{body}").unwrap();
}

/// `ci install` over existing files, links and dirs; the exact refusal words and what survives.
#[test]
fn ci_install_overwrite_cases() {
    use std::os::unix::fs::symlink;
    let t = Scratch::new("ci-cases");
    let mut acc = String::new();
    let p = t.p("proj/x");
    let proj = p.parent().unwrap().to_path_buf();
    let wf = proj.join(".github/workflows/android-doctor.yml");
    let ci = |acc: &mut String, name: &str, extra: &[&str]| {
        let mut a: Vec<&dyn AsRef<std::ffi::OsStr>> = vec![&"ci", &"install", &"--dir", &proj];
        a.extend(extra.iter().map(|e| e as &dyn AsRef<std::ffi::OsStr>));
        case_all(acc, &t, name, &a);
    };
    ci(&mut acc, "fresh", &["--path", "out/fw"]);
    show(&mut acc, "file", &wf, &t);
    ci(&mut acc, "again-identical", &["--path", "out/fw"]);
    std::fs::write(&wf, "mine\n").unwrap();
    ci(&mut acc, "existing-differs", &[]);
    show(&mut acc, "file", &wf, &t);
    ci(&mut acc, "force", &["--force", "--fail-on", "high"]);
    show(&mut acc, "file", &wf, &t);
    // the workflow is a symlink to a file elsewhere
    let victim = t.p("outside/victim");
    std::fs::write(&victim, "keep\n").unwrap();
    std::fs::remove_file(&wf).unwrap();
    symlink(&victim, &wf).unwrap();
    ci(&mut acc, "symlink-no-force", &[]);
    show(&mut acc, "victim", &victim, &t);
    ci(&mut acc, "symlink-force", &["--force"]);
    show(&mut acc, "victim", &victim, &t);
    show(&mut acc, "file", &wf, &t);
    // .github itself is a link out of the project
    let p2 = t.p("proj2/x");
    let proj2 = p2.parent().unwrap().to_path_buf();
    symlink(t.p("outside/x").parent().unwrap(), proj2.join(".github")).unwrap();
    case_all(
        &mut acc,
        &t,
        "github-dir-is-a-link",
        &[&"ci", &"install", &"--dir", &proj2, &"--force"],
    );
    writeln!(
        acc,
        "--- outside holds: {:?}",
        std::fs::read_dir(t.p("outside/x").parent().unwrap())
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .collect::<std::collections::BTreeSet<_>>()
    )
    .unwrap();
    golden("ci-install-cases.out", &acc);
}

/// The AGENTS.md block is merged byte for byte whatever the file looked like before.
#[test]
fn agents_md_block_merges() {
    let t = Scratch::new("agents-md");
    let home = t.p("home/x").parent().unwrap().to_path_buf();
    let mut acc = String::new();
    let begin = "<!-- android-doctor:begin (managed; re-run `android-doctor doctor install`) -->";
    let end = "<!-- android-doctor:end -->";
    let existing = [
        ("absent", None),
        ("empty", Some(String::new())),
        ("one-newline", Some("# mine\n".to_string())),
        ("no-newline", Some("# mine".to_string())),
        ("blank-lines", Some("# mine\n\n\n".to_string())),
        (
            "stale-block-then-text",
            Some(format!("top\n{begin}\nold\n{end}\n\n\nbottom\n")),
        ),
        ("block-at-end", Some(format!("top\n\n{begin}\nold\n{end}"))),
    ];
    for (name, content) in existing {
        let proj = t.p(&format!("{name}/x")).parent().unwrap().to_path_buf();
        if let Some(c) = content {
            std::fs::write(proj.join("AGENTS.md"), c).unwrap();
        }
        for round in ["first", "second"] {
            let o = Command::new(bin())
                .args(["doctor", "install", "--agent", "codex"])
                .env("HOME", &home)
                .current_dir(&proj)
                .output()
                .unwrap();
            writeln!(
                acc,
                "=== {name} {round} (exit {})",
                o.status.code().unwrap()
            )
            .unwrap();
            show(&mut acc, "AGENTS.md", &proj.join("AGENTS.md"), &t);
        }
    }
    golden("agents-md-cases.out", &acc);
}

/// The doctor/1 contract: a command that cannot run exits 2 with the one-line error and nothing
/// on stdout (kept fix: `unpack`, `amlogic` and `report` used to leave through the runtime with 1).
#[test]
fn error_paths_exit_2() {
    let t = firmware("errors");
    let gone = t.p("nope.img");
    let mut acc = String::new();
    for args in [
        vec!["unpack"],
        vec!["amlogic"],
        vec!["report"],
        vec!["identify"],
        vec!["info"],
        vec!["ls"],
        vec!["cat"],
        vec!["vbmeta"],
        vec!["audit"],
        vec!["doctor", "scan"],
        vec!["dt"],
        vec!["ramdisk"],
        vec!["files"],
        vec!["hash-tree"],
        vec!["fix"],
    ] {
        let mut a: Vec<&dyn AsRef<std::ffi::OsStr>> = args
            .iter()
            .map(|x| x as &dyn AsRef<std::ffi::OsStr>)
            .collect();
        a.push(&gone);
        if args == ["cat"] {
            a.push(&"/etc/hosts");
        }
        case_all(&mut acc, &t, &args.join(" "), &a);
    }
    // a usage error is clap's 2; --help is 0
    case_all(&mut acc, &t, "usage", &[&"audit"]);
    case_all(&mut acc, &t, "unknown-command", &[&"frobnicate"]);
    golden("error-paths.out", &acc);
}

/// `shell` browses image -> directory -> file lazily, with the findings next to it.
#[test]
fn shell_browses_the_firmware() {
    let t = firmware("shell");
    let fw = t.p("fw");
    let mut acc = String::new();
    case_all(
        &mut acc,
        &t,
        "shell-tree",
        &[
            &"shell",
            &fw,
            &"-c",
            &"ls; cd images; ls; cd system; ls; cd etc; ls; cat old.log; pwd; cd /; cd security; ls",
        ],
    );
    case_all(
        &mut acc,
        &t,
        "shell-json",
        &[
            &"shell",
            &t.p("fw/system.img"),
            &"--json",
            &"-c",
            &"cd images; ls; info",
        ],
    );
    case_all(
        &mut acc,
        &t,
        "shell-missing",
        &[&"shell", &t.p("nope"), &"-c", &"ls"],
    );
    golden("shell-tree.out", &acc);
}

#[test]
fn help_texts() {
    let t = Scratch::new("help");
    let mut codes = String::new();
    let subs = [
        "extract",
        "info",
        "amlogic",
        "dt",
        "partitions",
        "unpack",
        "ls",
        "cat",
        "audit",
        "diff",
        "vbmeta",
        "ramdisk",
        "files",
        "unsparse",
        "identify",
        "report",
        "hash-tree",
        "doctor",
        "fix",
        "ci",
        "mcp",
    ];
    case(&mut codes, &t, "help-root", &[&"--help"]);
    for s in subs {
        case(&mut codes, &t, &format!("help-{s}"), &[&s, &"--help"]);
    }
    for (a, b) in [("doctor", "scan"), ("doctor", "install"), ("ci", "install")] {
        case(
            &mut codes,
            &t,
            &format!("help-{a}-{b}"),
            &[&a, &b, &"--help"],
        );
    }
    golden("help.exit", &codes);
}

#[test]
fn mcp_transcript() {
    let t = firmware("mcp");
    old_new(&t);
    let (fw, old, new) = (
        t.0.to_str().unwrap().to_string(),
        t.p("diff/old.img"),
        t.p("diff/new.img"),
    );
    let reqs = [
        serde_json::json!({"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"golden","version":"1"}}}),
        serde_json::json!({"jsonrpc":"2.0","method":"notifications/initialized"}),
        serde_json::json!({"jsonrpc":"2.0","id":2,"method":"tools/list"}),
        serde_json::json!({"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"doctor","arguments":{"path":fw,"fail_on":"low"}}}),
        serde_json::json!({"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"audit","arguments":{"paths":[t.p("fw/system.img")]}}}),
        serde_json::json!({"jsonrpc":"2.0","id":5,"method":"tools/call","params":{"name":"diff","arguments":{"old":old,"new":new}}}),
        serde_json::json!({"jsonrpc":"2.0","id":6,"method":"tools/call","params":{"name":"nope","arguments":{}}}),
        serde_json::json!({"jsonrpc":"2.0","id":7,"method":"nope/method"}),
    ];
    let mut child = Command::new(bin())
        .arg("mcp")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    let mut stdin = child.stdin.take().unwrap();
    for r in &reqs {
        writeln!(stdin, "{r}").unwrap();
    }
    drop(stdin);
    let mut out = String::new();
    child
        .stdout
        .take()
        .unwrap()
        .read_to_string(&mut out)
        .unwrap();
    child.wait().unwrap();
    golden("mcp-transcript.out", &norm(&out, &t.0));
}

/// Protocol edges and failing tools. `ping` and -32600 are the contract fixes kept from the kit;
/// the rest are the first server's exact answers.
#[test]
fn mcp_contract() {
    let t = firmware("mcp-contract");
    let gone = t.p("nope.img").display().to_string();
    let lines = [
        r#"{"jsonrpc":"2.0","id":1,"method":"ping"}"#.to_string(),
        r#"{"jsonrpc":"2.0","id":2}"#.to_string(),
        r#"{"jsonrpc":"2.0","id":{"a":1},"method":"tools/list"}"#.to_string(),
        r#"[1,2]"#.to_string(),
        r#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#.to_string(),
        "".to_string(),
        "   ".to_string(),
        "not json".to_string(),
        r#"{"jsonrpc":"2.0","id":3,"method":"nope/method"}"#.to_string(),
        r#"{"jsonrpc":"2.0","id":4,"method":"initialize","params":{"protocolVersion":"2099-01-01"}}"#.to_string(),
        r#"{"jsonrpc":"2.0","id":5,"method":"tools/call","params":{"name":"nope","arguments":{}}}"#.to_string(),
        r#"{"jsonrpc":"2.0","id":6,"method":"tools/call","params":{"name":"identify","arguments":{}}}"#.to_string(),
        r#"{"jsonrpc":"2.0","id":7,"method":"tools/call","params":{"name":"identify","arguments":{"path":"a","baseline":"b"}}}"#.to_string(),
        r#"{"jsonrpc":"2.0","id":8,"method":"tools/call","params":{"name":"diff","arguments":{"old":"a"}}}"#.to_string(),
        serde_json::json!({"jsonrpc":"2.0","id":9,"method":"tools/call","params":{"name":"audit","arguments":{"paths":[gone]}}}).to_string(),
        serde_json::json!({"jsonrpc":"2.0","id":10,"method":"tools/call","params":{"name":"doctor","arguments":{"path":gone}}}).to_string(),
        serde_json::json!({"jsonrpc":"2.0","id":11,"method":"tools/call","params":{"name":"doctor","arguments":{"path":t.p("fw").display().to_string(),"baseline":t.p("nobase.json").display().to_string()}}}).to_string(),
    ];
    let mut child = Command::new(bin())
        .arg("mcp")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let mut stdin = child.stdin.take().unwrap();
    for l in &lines {
        writeln!(stdin, "{l}").unwrap();
    }
    drop(stdin);
    let mut out = String::new();
    child
        .stdout
        .take()
        .unwrap()
        .read_to_string(&mut out)
        .unwrap();
    child.wait().unwrap();
    golden("mcp-contract.out", &norm(&out, &t.0));
}

#[test]
fn install_bodies() {
    let t = Scratch::new("install");
    let mut codes = String::new();
    let mut files = String::new();
    case(
        &mut codes,
        &t,
        "doctor-install-print-only",
        &[&"doctor", &"install", &"--print-only"],
    );
    case(
        &mut codes,
        &t,
        "ci-install-print",
        &[&"ci", &"install", &"--print"],
    );
    case(
        &mut codes,
        &t,
        "ci-install-print-opts",
        &[
            &"ci",
            &"install",
            &"--print",
            &"--path",
            &"out/fw",
            &"--fail-on",
            &"high",
        ],
    );
    // run installs with HOME and cwd inside the scratch dir; AGENTS.md pre-exists to pin the markers
    let home = t.p("home");
    let proj = t.p("proj");
    std::fs::create_dir_all(&home).unwrap();
    std::fs::create_dir_all(&proj).unwrap();
    std::fs::write(proj.join("AGENTS.md"), "# mine\n").unwrap();
    let o = Command::new(bin())
        .args(["doctor", "install"])
        .env("HOME", &home)
        .output()
        .unwrap();
    writeln!(codes, "doctor-install-list\t{}", o.status.code().unwrap()).unwrap();
    golden(
        "doctor-install-list.out",
        &norm(&String::from_utf8_lossy(&o.stdout), &t.0),
    );
    for agent in ["claude-code", "cursor", "codex", "opencode"] {
        let o = Command::new(bin())
            .args(["doctor", "install", "--agent", agent])
            .env("HOME", &home)
            .current_dir(&proj)
            .output()
            .unwrap();
        writeln!(codes, "install-{agent}\t{}", o.status.code().unwrap()).unwrap();
        golden(
            &format!("install-{agent}.out"),
            &norm(&String::from_utf8_lossy(&o.stdout), &t.0),
        );
    }
    // run twice: idempotent block upsert
    Command::new(bin())
        .args(["doctor", "install", "--agent", "codex"])
        .env("HOME", &home)
        .current_dir(&proj)
        .output()
        .unwrap();
    let o = Command::new(bin())
        .args(["ci", "install", "--dir"])
        .arg(&proj)
        .output()
        .unwrap();
    writeln!(codes, "ci-install\t{}", o.status.code().unwrap()).unwrap();
    // every file written, path relative to the scratch dir, in sorted order
    fn walk(d: &Path, out: &mut Vec<PathBuf>) {
        let mut es: Vec<_> = std::fs::read_dir(d)
            .unwrap()
            .map(|e| e.unwrap().path())
            .collect();
        es.sort();
        for p in es {
            if p.is_dir() {
                walk(&p, out)
            } else {
                out.push(p)
            }
        }
    }
    let mut all = vec![];
    walk(&t.0, &mut all);
    for p in all {
        let rel = p.strip_prefix(&t.0).unwrap().display().to_string();
        writeln!(
            files,
            "=== {rel}\n{}",
            norm(&String::from_utf8_lossy(&std::fs::read(&p).unwrap()), &t.0)
        )
        .unwrap();
    }
    golden("install-files.out", &files);
    golden("install.exit", &codes);
}
