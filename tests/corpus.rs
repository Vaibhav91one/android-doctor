//! Corpus/precision gate (issue #109). See docs/precision.md.
//!
//! Firmware images are generated from the source trees under tests/corpus/trees/<case>/ with
//! `mke2fs -d` and `mkfs.erofs`, then `audit --json` and `doctor scan --json` are run on them
//! and the findings (id, severity, subject) are compared with tests/corpus/expected/<case>.json.
//! Any lost or added finding fails the test. `UPDATE_CORPUS=1` rewrites the snapshots.
//!
//! Without the two mkfs tools the tests skip loudly, except when `CI` is set, where a missing
//! tool is a hard failure so the gate cannot silently turn off.

use serde_json::{Value, json};
use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, UNIX_EPOCH};

const UUID: &str = "11111111-2222-4333-8444-555555555555";
const MKE2FS_CONF: &str = "[defaults]\n\tbase_features = sparse_super,large_file,filetype,resize_inode,dir_index,ext_attr\n\tdefault_mntopts = acl,user_xattr\n\tblocksize = 4096\n\tinode_size = 256\n\tinode_ratio = 16384\n[fs_types]\n\text4 = {\n\t\tfeatures = has_journal,extent,huge_file,flex_bg,metadata_csum,64bit,dir_nlink,extra_isize\n\t}\n";

fn root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/corpus")
}

fn find_tool(env_var: &str, name: &str) -> Option<PathBuf> {
    if let Some(p) = std::env::var_os(env_var) {
        return Some(PathBuf::from(p));
    }
    let extra = [
        "/opt/homebrew/opt/e2fsprogs/sbin",
        "/usr/local/opt/e2fsprogs/sbin",
        "/sbin",
        "/usr/sbin",
    ];
    let path = std::env::var_os("PATH").unwrap_or_default();
    std::env::split_paths(&path)
        .chain(extra.iter().map(PathBuf::from))
        .map(|d| d.join(name))
        .find(|p| p.is_file())
}

/// The two mkfs tools, or None after a loud notice (a panic under CI).
fn tools() -> Option<(PathBuf, PathBuf)> {
    let e2 = find_tool("MKE2FS", "mke2fs");
    let er = find_tool("MKFS_EROFS", "mkfs.erofs");
    if let (Some(a), Some(b)) = (e2, er) {
        return Some((a, b));
    }
    let msg = "mke2fs and/or mkfs.erofs not found (install e2fsprogs and erofs-utils, or set MKE2FS / MKFS_EROFS)";
    if std::env::var_os("CORPUS_REQUIRED").is_some() {
        panic!("corpus gate cannot run in CI: {msg}");
    }
    eprintln!("CORPUS GATE SKIPPED: {msg}");
    None
}

fn cases() -> Vec<String> {
    let mut v: Vec<String> = fs::read_dir(root().join("trees"))
        .unwrap()
        .map(|e| e.unwrap())
        .filter(|e| e.path().is_dir())
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .collect();
    v.sort();
    v
}

fn copy_tree(src: &Path, dst: &Path) {
    fs::create_dir_all(dst).unwrap();
    let mut entries: Vec<_> = fs::read_dir(src).unwrap().map(|e| e.unwrap()).collect();
    entries.sort_by_key(|e| e.file_name());
    for e in entries {
        let to = dst.join(e.file_name());
        if e.path().is_dir() {
            copy_tree(&e.path(), &to);
        } else {
            fs::copy(e.path(), &to).unwrap();
        }
        let mode = if e.path().is_dir() { 0o755 } else { 0o644 };
        set_mode(&to, mode);
    }
}

fn set_mode(p: &Path, mode: u32) {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(p, fs::Permissions::from_mode(mode)).unwrap();
}

/// Pin every mtime to the epoch, children before parents.
fn pin_times(p: &Path) {
    if p.is_dir() {
        for e in fs::read_dir(p).unwrap() {
            pin_times(&e.unwrap().path());
        }
    }
    fs::File::open(p)
        .unwrap()
        .set_modified(UNIX_EPOCH + Duration::from_secs(0))
        .unwrap();
}

fn run(cmd: &mut Command) {
    let out = cmd.output().unwrap_or_else(|e| panic!("{cmd:?}: {e}"));
    assert!(
        out.status.success(),
        "{cmd:?} failed: {}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
}

/// Build the case into `out`: `NAME.ext4` / `NAME.erofs` source dirs become `NAME.img`, and
/// everything else is copied as-is. Returns true when at least one filesystem image was built.
fn build_case(case: &str, out: &Path, (mke2fs, erofs): &(PathBuf, PathBuf)) -> bool {
    let src = root().join("trees").join(case);
    let work = out.with_extension("src");
    let _ = fs::remove_dir_all(&work);
    copy_tree(&src, &work);
    pin_times(&work);
    let modes = work.join("modes.txt");
    if modes.is_file() {
        for line in fs::read_to_string(&modes).unwrap().lines() {
            let (m, p) = line.split_once(' ').expect("modes.txt: `<octal> <path>`");
            set_mode(
                &work.join(p),
                u32::from_str_radix(m, 8).expect("octal mode"),
            );
        }
        fs::remove_file(&modes).unwrap();
    }
    fs::create_dir_all(out).unwrap();
    let conf = out.with_extension("mke2fs.conf");
    fs::write(&conf, MKE2FS_CONF).unwrap();
    let mut built = false;
    let mut names: Vec<_> = fs::read_dir(&work).unwrap().map(|e| e.unwrap()).collect();
    names.sort_by_key(|e| e.file_name());
    for e in names {
        let name = e.file_name().to_string_lossy().into_owned();
        let (stem, fs_kind) = match name.rsplit_once('.') {
            Some((s, k @ ("ext4" | "erofs"))) if e.path().is_dir() => (s, k),
            _ => {
                if e.path().is_dir() {
                    copy_tree(&e.path(), &out.join(&name));
                } else {
                    fs::copy(e.path(), out.join(&name)).unwrap();
                }
                continue;
            }
        };
        let img = out.join(format!("{stem}.img"));
        built = true;
        if fs_kind == "ext4" {
            let f = fs::File::create(&img).unwrap();
            f.set_len(4 << 20).unwrap();
            drop(f);
            run(Command::new(mke2fs)
                .env("MKE2FS_CONFIG", &conf)
                .env("E2FSPROGS_FAKE_TIME", "0")
                .env("SOURCE_DATE_EPOCH", "0")
                .args(["-q", "-F", "-t", "ext4", "-O", "^has_journal", "-m", "0"])
                .args(["-L", "corpus", "-U", UUID])
                .args(["-E", &format!("hash_seed={UUID},root_owner=0:0,nodiscard")])
                .arg("-d")
                .arg(e.path())
                .arg(&img));
            pin_ext4_times(&img);
        } else {
            run(Command::new(erofs)
                .env("SOURCE_DATE_EPOCH", "0")
                .args(["-U", UUID, "-T0", "--all-root"])
                .arg(&img)
                .arg(e.path()));
        }
    }
    built
}

/// crc32c (Castagnoli) as ext4 uses it: caller-chosen seed, no final inversion.
fn crc32c(mut crc: u32, data: &[u8]) -> u32 {
    for &b in data {
        crc ^= u32::from(b);
        for _ in 0..8 {
            crc = (crc >> 1) ^ (0x82F6_3B78 & (!(crc & 1)).wrapping_add(1));
        }
    }
    crc
}

fn le32(d: &[u8], o: usize) -> usize {
    u32::from_le_bytes(d[o..o + 4].try_into().unwrap()) as usize
}

/// mke2fs older than 1.47.1 stamps the superblock and every inode with the wall clock whatever
/// the environment says. Zero those times and redo the metadata_csum checksums that cover them
/// (the pinned mke2fs.conf always enables metadata_csum).
fn pin_ext4_times(img: &Path) {
    let mut d = fs::read(img).unwrap();
    let sb = &mut d[1024..2048];
    for off in [0x2C, 0x30, 0x40, 0x108] {
        sb[off..off + 4].fill(0);
    }
    let sum = crc32c(!0, &sb[..0x3FC]);
    sb[0x3FC..0x400].copy_from_slice(&sum.to_le_bytes());
    let sb = d[1024..2048].to_vec();
    let block = 1024usize << le32(&sb, 0x18);
    let (blocks, per_group, first) = (le32(&sb, 4), le32(&sb, 0x20), le32(&sb, 0x14));
    let (ipg, isz) = (
        le32(&sb, 0x28),
        usize::from(u16::from_le_bytes([sb[0x58], sb[0x59]])),
    );
    let desc = if le32(&sb, 0x60) & 0x80 != 0 { 64 } else { 32 }; // INCOMPAT_64BIT
    let seed = crc32c(!0, &sb[0x68..0x78]);
    for g in 0..(blocks - first).div_ceil(per_group) {
        let gd = (first + 1) * block + g * desc;
        let table = le32(&d, gd + 8) * block;
        for i in 0..ipg {
            let at = table + i * isz;
            if d[at..at + isz].iter().all(|&b| b == 0) {
                continue;
            }
            let ino = (g * ipg + i + 1) as u32;
            d[at + 8..at + 20].fill(0); // atime, ctime, mtime
            d[at + 0x84..at + 0x98].fill(0); // extra time bits, crtime
            d[at + 0x7C..at + 0x7E].fill(0);
            // the high half only exists when i_extra_isize reaches it
            let hi = u16::from_le_bytes([d[at + 0x80], d[at + 0x81]]) >= 4;
            d[at + 0x82..at + 0x84].fill(0);
            let mut c = crc32c(seed, &ino.to_le_bytes());
            c = crc32c(c, &d[at + 0x64..at + 0x68]);
            c = crc32c(c, &d[at..at + isz]);
            d[at + 0x7C..at + 0x7E].copy_from_slice(&(c as u16).to_le_bytes());
            if hi {
                d[at + 0x82..at + 0x84].copy_from_slice(&((c >> 16) as u16).to_le_bytes());
            }
        }
    }
    fs::write(img, d).unwrap();
}

fn bin_json(args: &[&str], dir: &Path) -> Value {
    let out = Command::new(env!("CARGO_BIN_EXE_android-doctor"))
        .args(args)
        .arg(dir)
        .output()
        .unwrap();
    // `doctor scan` exits non-zero when a finding has severity error; stdout is still JSON.
    serde_json::from_slice(&out.stdout).unwrap_or_else(|e| {
        panic!(
            "{args:?} did not print JSON ({e}): {}{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        )
    })
}

fn row(id: &str, severity: &str, subject: &str) -> String {
    format!("{id}\t{severity}\t{subject}")
}

/// Findings as sorted (id, severity, subject) rows, from the stable keys only so fields added
/// to the JSON later do not break the gate.
fn observed(out: &Path, built: bool) -> (Vec<String>, Vec<String>) {
    let mut audit = Vec::new();
    if built {
        let v = bin_json(&["audit", "--json"], out);
        for img in v["images"].as_array().unwrap() {
            let name = Path::new(img["name"].as_str().unwrap())
                .file_name()
                .unwrap()
                .to_string_lossy()
                .into_owned();
            for f in img["findings"].as_array().unwrap() {
                audit.push(row(
                    f["rule"].as_str().unwrap(),
                    f["severity"].as_str().unwrap(),
                    &name,
                ));
            }
        }
    }
    let v = bin_json(&["doctor", "scan", "--json"], out);
    let doctor = v
        .as_array()
        .unwrap()
        .iter()
        .map(|f| {
            row(
                f["id"].as_str().unwrap(),
                f["severity"].as_str().unwrap(),
                f["subject"].as_str().unwrap(),
            )
        })
        .collect();
    audit.sort();
    let mut doctor: Vec<String> = doctor;
    doctor.sort();
    (audit, doctor)
}

fn to_snapshot(rows: &[String]) -> Value {
    Value::Array(
        rows.iter()
            .map(|r| {
                let p: Vec<&str> = r.split('\t').collect();
                json!({"id": p[0], "severity": p[1], "subject": p[2]})
            })
            .collect(),
    )
}

fn from_snapshot(v: &Value) -> Vec<String> {
    let mut rows: Vec<String> = v
        .as_array()
        .unwrap()
        .iter()
        .map(|f| {
            row(
                f["id"].as_str().unwrap(),
                f["severity"].as_str().unwrap(),
                f["subject"].as_str().unwrap(),
            )
        })
        .collect();
    rows.sort();
    rows
}

fn diff(label: &str, want: &[String], got: &[String]) -> String {
    let (w, g): (BTreeSet<_>, BTreeSet<_>) = (want.iter().collect(), got.iter().collect());
    let mut out = String::new();
    for r in w.difference(&g) {
        out += &format!("  - LOST   {label}: {}\n", r.replace('\t', "  "));
    }
    for r in g.difference(&w) {
        out += &format!("  + ADDED  {label}: {}\n", r.replace('\t', "  "));
    }
    if out.is_empty() && want != got {
        out = format!(
            "  ~ {label}: duplicate findings changed ({} -> {})\n",
            want.len(),
            got.len()
        );
    }
    out
}

fn sha256(p: &Path) -> String {
    let o = Command::new("shasum")
        .args(["-a", "256"])
        .arg(p)
        .output()
        .unwrap();
    String::from_utf8_lossy(&o.stdout)
        .split_whitespace()
        .next()
        .unwrap()
        .to_string()
}

fn scratch(tag: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("ad-corpus-{tag}-{}", std::process::id()));
    let _ = fs::remove_dir_all(&d);
    fs::create_dir_all(&d).unwrap();
    d
}

#[test]
fn findings_match_the_committed_snapshots() {
    let Some(t) = tools() else { return };
    let update = std::env::var_os("UPDATE_CORPUS").is_some();
    let tmp = scratch("run");
    let mut report = String::new();
    for case in cases() {
        let out = tmp.join(&case);
        let built = build_case(&case, &out, &t);
        let (audit, doctor) = observed(&out, built);
        let snap = root().join("expected").join(format!("{case}.json"));
        if update {
            let doc = json!({"audit": to_snapshot(&audit), "doctor": to_snapshot(&doctor)});
            fs::write(&snap, serde_json::to_string_pretty(&doc).unwrap() + "\n").unwrap();
            continue;
        }
        let Ok(text) = fs::read_to_string(&snap) else {
            report +=
                &format!("{case}: no snapshot; run UPDATE_CORPUS=1 cargo test --test corpus\n");
            continue;
        };
        let want: Value = serde_json::from_str(&text).unwrap();
        let d = diff("audit", &from_snapshot(&want["audit"]), &audit)
            + &diff("doctor", &from_snapshot(&want["doctor"]), &doctor);
        if !d.is_empty() {
            report += &format!("{case}:\n{d}");
        }
    }
    let _ = fs::remove_dir_all(&tmp);
    assert!(
        report.is_empty(),
        "corpus drift (see docs/precision.md; UPDATE_CORPUS=1 accepts an intended change):\n{report}"
    );
}

#[test]
fn clean_firmware_raises_nothing_above_info() {
    let Some(t) = tools() else { return };
    let tmp = scratch("clean");
    let out = tmp.join("clean");
    let built = build_case("clean", &out, &t);
    let (audit, doctor) = observed(&out, built);
    let _ = fs::remove_dir_all(&tmp);
    assert!(audit.is_empty(), "clean audit must be silent: {audit:?}");
    let loud: Vec<_> = doctor.iter().filter(|r| !r.contains("\tinfo\t")).collect();
    assert!(
        loud.is_empty(),
        "clean doctor scan must only say info: {loud:?}"
    );
}

#[test]
fn two_builds_are_byte_identical() {
    let Some(t) = tools() else { return };
    let tmp = scratch("det");
    let mut bad = String::new();
    for case in cases() {
        let (a, b) = (tmp.join(format!("{case}-a")), tmp.join(format!("{case}-b")));
        build_case(&case, &a, &t);
        // a build stamped with the wall clock would differ across a second boundary
        std::thread::sleep(Duration::from_millis(1100));
        build_case(&case, &b, &t);
        let mut imgs: Vec<_> = fs::read_dir(&a)
            .unwrap()
            .map(|e| e.unwrap().file_name())
            .filter(|n| n.to_string_lossy().ends_with(".img"))
            .collect();
        imgs.sort();
        for n in imgs {
            let (x, y) = (sha256(&a.join(&n)), sha256(&b.join(&n)));
            if x != y {
                let (da, db) = (fs::read(a.join(&n)).unwrap(), fs::read(b.join(&n)).unwrap());
                let at: Vec<String> = (0..da.len().min(db.len()))
                    .filter(|&i| da[i] != db[i])
                    .take(8)
                    .map(|i| format!("{i:#x}"))
                    .collect();
                bad += &format!(
                    "{case}/{}: {x} != {y} (first differing offsets {at:?})\n",
                    n.to_string_lossy()
                );
            }
        }
    }
    let _ = fs::remove_dir_all(&tmp);
    assert!(bad.is_empty(), "image builds are not deterministic:\n{bad}");
}
