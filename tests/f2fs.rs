//! The clean-room f2fs reader (issue #128) against REAL images: volumes formatted by
//! `mkfs.f2fs` and populated by `sload.f2fs` (f2fs-tools), read back through the built binary
//! with `ls`, `cat`, `files` and `audit`.
//!
//! The tools come from, in order: the environment (`F2FS_MKFS`, `F2FS_SLOAD`), `PATH` (also
//! Android's `make_f2fs` from the SDK's platform-tools, which formats but cannot populate), and
//! as a last resort a throwaway Linux container (Apple's `container` CLI, Ubuntu 24.04 with
//! `apt-get install f2fs-tools`). Without any of them the tests skip loudly, except when
//! `F2FS_REQUIRED` is set (CI does), where a missing tool is a hard failure so the gate cannot
//! silently turn off.
//!
//! The images are byte-for-byte reproducible (fixed uuid, `-r`, `-T`), and one of the tests
//! builds the same volume twice to prove it.

use serde_json::Value;
use sha2::{Digest, Sha256};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::OnceLock;

const UUID: &str = "11111111-2222-3333-4444-555555555555";
const STAMP: &str = "1700000000";
const SKIPPED: &str = "F2FS TESTS SKIPPED";

const FILE_CONTEXTS: &str = "/system(/.*)?  u:object_r:system_file:s0\n\
/system/bin(/.*)?  u:object_r:system_bin:s0\n\
/system/etc/hello\\.txt  u:object_r:hello_exec:s0\n";

const BUILD_PROP: &str = "ro.build.type=userdebug\nro.build.tags=test-keys\nro.secure=0\nro.debuggable=1\nro.adb.secure=0\nservice.adb.root=1\npersist.sys.usb.config=mtp,adb\n";

/// How each image is formatted: name and `mkfs.f2fs` options. `droid` is what Android's own build
/// uses (`-g android`, which also turns on the encrypt feature bit); `ext` has the inode extra
/// attributes, checksums, quota, verity and crtime.
const PROFILES: [(&str, &str); 3] = [
    ("plain", ""),
    ("droid", "-g android"),
    (
        "ext",
        "-O extra_attr,inode_checksum,sb_checksum,project_quota,inode_crtime,lost_found,verity,quota",
    ),
];

fn bin() -> &'static str {
    env!("CARGO_BIN_EXE_android-doctor")
}

/// Deterministic pseudo-random bytes.
fn det(n: usize, seed: &str) -> Vec<u8> {
    let mut out = Vec::with_capacity(n + 32);
    let mut i = 0u32;
    while out.len() < n {
        out.extend(Sha256::digest(format!("{seed}{i}").as_bytes()));
        i += 1;
    }
    out.truncate(n);
    out
}

fn sha(b: &[u8]) -> String {
    Sha256::digest(b)
        .iter()
        .map(|x| format!("{x:02x}"))
        .collect()
}

const BIG: usize = 13 * 1024 * 1024 + 123;

/// The source tree every image is built from.
fn write_tree(root: &Path) {
    use std::os::unix::fs::{PermissionsExt, symlink};
    let w = |p: &str, data: &[u8], mode: u32| {
        let f = root.join(p);
        fs::create_dir_all(f.parent().unwrap()).unwrap();
        fs::write(&f, data).unwrap();
        fs::set_permissions(&f, fs::Permissions::from_mode(mode)).unwrap();
    };
    w("system/build.prop", BUILD_PROP.as_bytes(), 0o644);
    w("system/etc/hello.txt", b"hello f2fs\n", 0o644);
    w("system/etc/empty", b"", 0o644);
    w("system/bin/app", &det(100_000, "app"), 0o755);
    w("system/lib/libbig.so", &det(BIG, "big"), 0o644);
    for i in 0..300 {
        w(
            &format!("system/many/file_{i:04}.txt"),
            format!("file {i}\n").as_bytes(),
            0o644,
        );
    }
    w("system/xbin/su", b"fake su\n", 0o4755);
    w("system/bin/rootsh", b"x\n", 0o4777);
    w("system/bin/ping", b"y\n", 0o4755);
    w("system/data/shared.txt", b"z\n", 0o666);
    symlink("app", root.join("system/bin/app-link")).unwrap();
    symlink("/system/etc/hello.txt", root.join("system/etc/hello-link")).unwrap();
    symlink(
        format!("/system/{}target", "long/".repeat(30)),
        root.join("system/lib/long-link"),
    )
    .unwrap();
    fs::hard_link(
        root.join("system/bin/app"),
        root.join("system/bin/app-hard"),
    )
    .unwrap();
}

/// The shell that formats and populates every image; runs where the tools are (here or in the
/// container). `W` is the work directory.
fn script(mkfs: &str, sload: &str) -> String {
    let build = |name: &str, opts: &str, out: &str| {
        format!(
            "rm -f {out}.img; truncate -s 256M {out}.img\n\
             {mkfs} -f -l TESTVOL -U {UUID} -r -T {STAMP} {opts} {out}.img >{out}.mkfs.log 2>&1\n\
             {sload} -f tree -s file_contexts -T {STAMP} -t / {out}.img >{out}.sload.log 2>&1\n\
             echo built {name}\n"
        )
    };
    let mut s = String::from("set -e\ncd \"$W\"\n");
    for (name, opts) in PROFILES {
        s += &build(name, opts, name);
    }
    // the same volume again, after the clock has moved on
    s += "sleep 2\n";
    s += &build("plain", "", "plain-again");
    // a volume spread over two devices (formatted only: it is refused, never read)
    s += &format!(
        "rm -f multi.img multi2.img; truncate -s 100M multi.img; truncate -s 100M multi2.img\n\
         {mkfs} -f -c multi2.img multi.img >multi.mkfs.log 2>&1\n"
    );
    s
}

struct Built {
    dir: PathBuf,
}

impl Built {
    fn image(&self, name: &str) -> PathBuf {
        self.dir.join(format!("{name}.img"))
    }
}

fn find_tool(env_var: &str, names: &[&str]) -> Option<PathBuf> {
    if let Some(p) = std::env::var_os(env_var) {
        return Some(PathBuf::from(p));
    }
    let path = std::env::var_os("PATH").unwrap_or_default();
    let mut dirs: Vec<PathBuf> = std::env::split_paths(&path).collect();
    for root in [
        std::env::var_os("ANDROID_HOME"),
        std::env::var_os("ANDROID_SDK_ROOT"),
    ]
    .into_iter()
    .flatten()
    {
        dirs.push(PathBuf::from(root).join("platform-tools"));
    }
    if let Some(home) = std::env::var_os("HOME") {
        let home = PathBuf::from(home);
        dirs.push(home.join("Library/Android/sdk/platform-tools"));
        dirs.push(home.join("Android/Sdk/platform-tools"));
    }
    dirs.extend(["/sbin", "/usr/sbin", "/usr/local/sbin"].map(PathBuf::from));
    names
        .iter()
        .flat_map(|n| dirs.iter().map(move |d| d.join(n)))
        .find(|p| p.is_file())
}

fn mkfs_tool() -> Option<PathBuf> {
    find_tool("F2FS_MKFS", &["mkfs.f2fs", "make_f2fs"])
}

fn run_checked(cmd: &mut Command) -> Output {
    let out = cmd.output().unwrap_or_else(|e| panic!("{cmd:?}: {e}"));
    assert!(
        out.status.success(),
        "{cmd:?} failed: {}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    out
}

/// Build every image, with native tools if both are there, else in a container.
fn build_all() -> Result<Built, String> {
    let dir = std::env::temp_dir().join(format!("ad-f2fs-{}", std::process::id()));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).unwrap();
    write_tree(&dir.join("tree"));
    fs::write(dir.join("file_contexts"), FILE_CONTEXTS).unwrap();
    let native = (
        mkfs_tool(),
        find_tool("F2FS_SLOAD", &["sload.f2fs", "sload_f2fs"]),
    );
    if let (Some(mkfs), Some(sload)) = native {
        fs::write(
            dir.join("build.sh"),
            script(&mkfs.display().to_string(), &sload.display().to_string()),
        )
        .unwrap();
        run_checked(Command::new("sh").arg(dir.join("build.sh")).env("W", &dir));
        return Ok(Built { dir });
    }
    // no native pair: a throwaway Ubuntu container with the same f2fs-tools CI installs
    if Command::new("container")
        .arg("--version")
        .output()
        .is_ok_and(|o| o.status.success())
    {
        let sh = format!(
            "apt-get update >/dev/null 2>&1 && apt-get install -y f2fs-tools >/dev/null 2>&1\n{}",
            script("mkfs.f2fs", "sload.f2fs")
        );
        fs::write(dir.join("build.sh"), sh).unwrap();
        let out = Command::new("container")
            .args(["run", "--rm", "-e", "W=/w", "-v"])
            .arg(format!("{}:/w", dir.display()))
            .args(["ubuntu:24.04", "sh", "/w/build.sh"])
            .output()
            .map_err(|e| format!("container: {e}"))?;
        if out.status.success() && dir.join("plain.img").is_file() {
            return Ok(Built { dir });
        }
        return Err(format!(
            "the container build failed: {}",
            String::from_utf8_lossy(&out.stderr)
        ));
    }
    Err("mkfs.f2fs and sload.f2fs not found (install f2fs-tools, or set F2FS_MKFS / F2FS_SLOAD), and no `container` CLI to fall back to".into())
}

/// The images, or None after a loud notice (a panic when F2FS_REQUIRED is set).
fn images() -> Option<&'static Built> {
    static BUILT: OnceLock<Option<Built>> = OnceLock::new();
    BUILT
        .get_or_init(|| match build_all() {
            Ok(b) => Some(b),
            Err(why) => {
                if std::env::var_os("F2FS_REQUIRED").is_some() {
                    panic!("the f2fs gate cannot run in CI: {why}");
                }
                eprintln!("{SKIPPED}: {why}");
                None
            }
        })
        .as_ref()
}

fn ad(args: &[&str]) -> Output {
    Command::new(bin()).args(args).output().unwrap()
}

fn ad_ok(args: &[&str]) -> Vec<u8> {
    let o = ad(args);
    assert!(
        o.status.success(),
        "{args:?}: {}{}",
        String::from_utf8_lossy(&o.stdout),
        String::from_utf8_lossy(&o.stderr)
    );
    o.stdout
}

fn p(path: &Path) -> &str {
    path.to_str().unwrap()
}

fn entries(img: &Path) -> Vec<Value> {
    let v: Value = serde_json::from_slice(&ad_ok(&["files", "--json", p(img)])).unwrap();
    v["entries"].as_array().unwrap().clone()
}

fn entry<'a>(all: &'a [Value], path: &str) -> &'a Value {
    all.iter()
        .find(|e| e["path"] == path)
        .unwrap_or_else(|| panic!("{path} is not in the image"))
}

#[test]
fn ls_cat_and_files_read_a_real_f2fs_image() {
    let Some(b) = images() else { return };
    for (name, _) in PROFILES {
        let img = b.image(name);
        // ls: the directory level, with the SELinux label
        let out = String::from_utf8(ad_ok(&["ls", p(&img), "/system/etc"])).unwrap();
        println!("--- {name}: ls /system/etc\n{out}");
        for want in [
            "empty",
            "hello-link",
            "hello.txt",
            "u:object_r:hello_exec:s0",
        ] {
            assert!(out.contains(want), "{name}: {want} missing from\n{out}");
        }
        // cat: exact bytes, inline data and a file that needs indirect node blocks
        assert_eq!(
            ad_ok(&["cat", p(&img), "/system/etc/hello.txt"]),
            b"hello f2fs\n"
        );
        assert_eq!(ad_ok(&["cat", p(&img), "/system/etc/empty"]), b"");
        assert_eq!(
            ad_ok(&["cat", p(&img), "/system/bin/app"]),
            det(100_000, "app")
        );
        let big = ad_ok(&["cat", p(&img), "/system/lib/libbig.so"]);
        assert_eq!(big.len(), BIG, "{name}");
        assert_eq!(
            sha(&big),
            sha(&det(BIG, "big")),
            "{name}: the 13 MiB file differs"
        );
        let o = ad(&["cat", p(&img), "/system/bin/app-link"]);
        assert!(!o.status.success());
        assert!(String::from_utf8_lossy(&o.stderr).contains("symlink to app"));
        // files: the whole tree
        let all = entries(&img);
        let many = all
            .iter()
            .filter(|e| e["path"].as_str().unwrap().starts_with("system/many/"))
            .count();
        assert_eq!(
            many, 300,
            "{name}: a directory spanning several dentry blocks"
        );
        assert_eq!(entry(&all, "system/bin/app-link")["link"], "app");
        assert_eq!(entry(&all, "system/bin/app-link")["type"], "symlink");
        assert_eq!(
            entry(&all, "system/lib/long-link")["link"],
            format!("/system/{}target", "long/".repeat(30)).as_str()
        );
        assert_eq!(
            entry(&all, "system/etc/hello-link")["link"],
            "/system/etc/hello.txt"
        );
        assert_eq!(entry(&all, "system/bin/app")["nlink"], 2, "hard link");
        assert_eq!(entry(&all, "system/bin/app-hard")["nlink"], 2);
        assert_eq!(
            entry(&all, "system/bin/app")["inode"],
            entry(&all, "system/bin/app-hard")["inode"]
        );
        assert_eq!(entry(&all, "system/bin/app")["mode"], 0o755);
        assert_eq!(entry(&all, "system/xbin/su")["mode"], 0o4755);
        assert_eq!(entry(&all, "system/bin/rootsh")["mode"], 0o4777);
        assert_eq!(entry(&all, "system/data/shared.txt")["mode"], 0o666);
        assert_eq!(entry(&all, "system/lib/libbig.so")["size"], BIG);
        assert_eq!(
            entry(&all, "system/etc/hello.txt")["mtime"],
            STAMP.parse::<i64>().unwrap()
        );
        let label = |path: &str| {
            entry(&all, path)["xattrs"]["security.selinux"]
                .as_str()
                .unwrap()
                .to_string()
        };
        assert_eq!(label("system/etc/hello.txt"), "u:object_r:hello_exec:s0");
        assert_eq!(label("system/bin/app"), "u:object_r:system_bin:s0");
        assert_eq!(label("system/lib/libbig.so"), "u:object_r:system_file:s0");
        assert_eq!(
            label("system/many/file_0123.txt"),
            "u:object_r:system_file:s0"
        );
    }
}

#[test]
fn files_extracts_every_file_byte_for_byte() {
    let Some(b) = images() else { return };
    let img = b.image("ext");
    let out = b.dir.join("extracted");
    let _ = fs::remove_dir_all(&out);
    ad_ok(&["files", p(&img), "-o", p(&out)]);
    let (src, got) = (b.dir.join("tree"), out.join("files"));
    let mut checked = 0;
    let mut stack = vec![src.clone()];
    while let Some(d) = stack.pop() {
        for e in fs::read_dir(&d).unwrap() {
            let e = e.unwrap();
            let t = e.file_type().unwrap();
            let rel = e.path().strip_prefix(&src).unwrap().to_path_buf();
            if t.is_dir() {
                stack.push(e.path());
            } else if t.is_file() {
                assert_eq!(
                    fs::read(e.path()).unwrap(),
                    fs::read(got.join(&rel)).unwrap(),
                    "{rel:?}"
                );
                checked += 1;
            }
        }
    }
    assert_eq!(checked, 310, "every regular file was compared");
    let m: Value = serde_json::from_slice(&fs::read(out.join("manifest.json")).unwrap()).unwrap();
    assert_eq!(m["summary"]["by_type"]["symlink"], 3);
    let big = m["entries"]
        .as_array()
        .unwrap()
        .iter()
        .find(|e| e["path"] == "system/lib/libbig.so")
        .unwrap();
    assert_eq!(big["sha256"], sha(&det(BIG, "big")).as_str());
}

#[test]
fn audit_produces_the_same_findings_as_on_the_other_file_systems() {
    let Some(b) = images() else { return };
    // the same tree the corpus gate audits as ext4 and erofs (debug-props + perms)
    let want = [
        "adb-by-default",
        "adb-root",
        "adb-unauthenticated",
        "debug-build-type",
        "debuggable-build",
        "insecure-adb",
        "setuid-files",
        "su-binary",
        "test-keys",
        "world-writable",
        "writable-setuid",
    ];
    for (name, _) in PROFILES {
        let img = b.image(name);
        let text = String::from_utf8(ad_ok(&["audit", p(&img)])).unwrap();
        println!("--- {name}: audit\n{text}");
        let v: Value = serde_json::from_slice(&ad_ok(&["audit", "--json", p(&img)])).unwrap();
        let image = &v["images"][0];
        let mut got: Vec<String> = image["findings"]
            .as_array()
            .unwrap()
            .iter()
            .map(|f| f["rule"].as_str().unwrap().to_string())
            .collect();
        got.sort();
        assert_eq!(got, want, "{name}");
        // the labels reach the audit: the setuid list shows them
        assert!(
            text.contains("4755 0:0 /system/xbin/su u:object_r:system_file:s0"),
            "{text}"
        );
        assert!(
            text.contains("4755 0:0 /system/bin/ping u:object_r:system_bin:s0"),
            "{text}"
        );
    }
}

#[test]
fn building_the_same_volume_twice_gives_identical_bytes() {
    let Some(b) = images() else { return };
    let (x, y) = (
        fs::read(b.image("plain")).unwrap(),
        fs::read(b.image("plain-again")).unwrap(),
    );
    assert_eq!(x.len(), y.len());
    assert!(
        x == y,
        "the image is not reproducible (first differing byte {:?})",
        x.iter().zip(&y).position(|(a, b)| a != b)
    );
}

#[test]
fn an_empty_volume_from_the_formatter_lists_as_empty() {
    // needs only mkfs.f2fs (or Android's make_f2fs), no sload
    let Some(mkfs) = mkfs_tool() else {
        if std::env::var_os("F2FS_REQUIRED").is_some() {
            panic!("the f2fs gate cannot run in CI: no mkfs.f2fs");
        }
        eprintln!("{SKIPPED}: no mkfs.f2fs or make_f2fs found");
        return;
    };
    let dir = std::env::temp_dir().join(format!("ad-f2fs-empty-{}", std::process::id()));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).unwrap();
    let img = dir.join("empty.img");
    fs::File::create(&img).unwrap().set_len(64 << 20).unwrap();
    run_checked(
        Command::new(mkfs)
            .args(["-f", "-l", "EMPTY", "-r", "-T", STAMP])
            .arg(&img),
    );
    assert!(entries(&img).is_empty());
    let out = String::from_utf8(ad_ok(&["ls", p(&img), "/"])).unwrap();
    assert_eq!(out.trim(), "");
    let o = ad(&["cat", p(&img), "/nothing"]);
    assert!(!o.status.success());
    assert!(String::from_utf8_lossy(&o.stderr).contains("not found"));
    let v: Value = serde_json::from_slice(&ad_ok(&["audit", "--json", p(&img)])).unwrap();
    assert_eq!(v["images"][0]["findings"].as_array().unwrap().len(), 0);
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn a_multi_device_volume_is_refused_with_a_clear_error() {
    let Some(b) = images() else { return };
    let img = b.image("multi");
    let o = ad(&["files", p(&img)]);
    assert_eq!(o.status.code(), Some(1));
    let err = String::from_utf8_lossy(&o.stderr);
    assert!(
        err.contains("multi-device f2fs volumes are not supported"),
        "{err}"
    );
    assert_eq!(ad(&["audit", p(&img)]).status.code(), Some(1));
}

#[test]
fn damaged_real_images_are_refused_never_crashed_on() {
    let Some(b) = images() else { return };
    use std::io::{Read, Seek, SeekFrom, Write};
    let work = b.dir.join("damaged.img");
    fs::copy(b.image("ext"), &work).unwrap();
    // superblock, both checkpoint packs, the node address table, and a spread through the
    // metadata and the first node segments
    let mut spots: Vec<u64> = vec![1024, 1030, 1100, 2180, 3068, 2_097_350, 4_194_500];
    spots.extend((0..60).map(|i| 6_300_000 + i * 131_071));
    let mut refused = 0;
    for at in spots {
        let mut f = fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(&work)
            .unwrap();
        let mut was = [0u8; 1];
        f.seek(SeekFrom::Start(at)).unwrap();
        f.read_exact(&mut was).unwrap();
        for v in [was[0] ^ 0xFF, 0x00] {
            f.seek(SeekFrom::Start(at)).unwrap();
            f.write_all(&[v]).unwrap();
            f.flush().unwrap();
            let o = ad(&["files", p(&work)]);
            // a clean exit (0) or a clean refusal (1): a panic is 101 and a signal has no code
            assert!(
                matches!(o.status.code(), Some(0) | Some(1)),
                "byte {at} set to {v:#x}: {:?} {}",
                o.status,
                String::from_utf8_lossy(&o.stderr)
            );
            if o.status.code() == Some(1) {
                refused += 1;
            }
        }
        f.seek(SeekFrom::Start(at)).unwrap();
        f.write_all(&was).unwrap();
    }
    assert!(
        refused > 3,
        "some of the damage must have been caught ({refused})"
    );
    // truncated at awkward places
    let full = fs::read(b.image("ext")).unwrap();
    for len in [0usize, 1000, 4096, 1 << 20, 2 << 20, 3 << 20, 17 << 20] {
        fs::write(&work, &full[..len]).unwrap();
        let o = ad(&["files", p(&work)]);
        assert!(
            matches!(o.status.code(), Some(0) | Some(1)),
            "len {len}: {:?}",
            o.status
        );
    }
}
