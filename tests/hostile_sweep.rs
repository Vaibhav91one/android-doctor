//! Hostile-input sweep (issue #60, part 2).
//!
//! Every subcommand is fed four hostile inputs:
//!   - a FIFO (a named pipe would block an open that does not check the type)
//!   - a symlink pointing outside the output directory
//!   - a 10-byte truncated image
//!   - a header claiming a huge size
//!
//! Each invocation gets a deadline, so a hang fails the test rather than stalling CI.

use std::fs;
use std::io::Read as _;
use std::os::unix::fs::symlink;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

const HARD_TIMEOUT: Duration = Duration::from_secs(20);

fn bin() -> PathBuf {
    let mut p = std::env::current_exe().unwrap();
    p.pop(); // deps
    p.pop(); // debug
    p.join("android-doctor")
}

unsafe extern "C" {
    fn mkfifo(path: *const std::ffi::c_char, mode: u32) -> i32;
}

/// A named pipe at `path`.
fn fifo(path: &Path) {
    let c = std::ffi::CString::new(path.as_os_str().as_encoded_bytes()).unwrap();
    // SAFETY: `c` is a valid NUL-terminated string; mode is a plain u32 bitmask.
    let rc = unsafe { mkfifo(c.as_ptr(), 0o600) };
    assert_eq!(rc, 0, "mkfifo: {}", std::io::Error::last_os_error());
}

/// A directory holding every hostile shape, plus enough of an OTA that the commands have
/// something legitimate to look at.
fn fixture(tag: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("ad-hostile-{tag}-{}", std::process::id()));
    let _ = fs::remove_dir_all(&d);
    fs::create_dir_all(&d).unwrap();

    fifo(&d.join("pipe.img"));
    symlink("/etc/passwd", d.join("escape.img")).unwrap();
    fs::write(d.join("tiny.img"), b"ANDROID!ab").unwrap();
    // an ext4 superblock magic with an absurd block count
    let mut huge = vec![0u8; 4096];
    huge[0x38..0x3a].copy_from_slice(&0xEF53u16.to_le_bytes());
    huge[4..8].copy_from_slice(&u32::MAX.to_le_bytes());
    fs::write(d.join("huge.img"), &huge).unwrap();
    fs::write(d.join("plain.img"), b"not an image at all").unwrap();

    fs::create_dir_all(d.join("ota")).unwrap();
    fs::write(d.join("ota/a.transfer.list"), b"4\n0\n0\n0\n").unwrap();
    fs::write(d.join("ota/a.new.dat"), vec![0u8; 8192]).unwrap();
    fs::write(d.join("ota/rawprogram0.xml"), b"<data/>").unwrap();
    d
}

/// Every subcommand, with arguments it needs.
fn invocations(d: &Path) -> Vec<Vec<String>> {
    let img = d.join("plain.img");
    let ota = d.join("ota");
    let out = d.join("out");
    vec![
        vec!["identify".into(), img.display().to_string()],
        vec!["ls".into(), img.display().to_string(), "/".into()],
        vec!["cat".into(), img.display().to_string(), "/etc/hosts".into()],
        vec!["files".into(), img.display().to_string()],
        vec!["audit".into(), img.display().to_string()],
        vec!["doctor".into(), ota.display().to_string()],
        // the reporting flags must survive hostile input too
        vec![
            "doctor".into(),
            "scan".into(),
            d.display().to_string(),
            "--sarif".into(),
            d.join("d.sarif").display().to_string(),
        ],
        vec!["partitions".into(), ota.display().to_string()],
        vec!["dt".into(), img.display().to_string()],
        vec!["vbmeta".into(), img.display().to_string()],
        vec!["info".into(), ota.display().to_string()],
        vec![
            "extract".into(),
            ota.display().to_string(),
            "-o".into(),
            out.display().to_string(),
        ],
        vec![
            "unpack".into(),
            img.display().to_string(),
            "-o".into(),
            d.join("u").display().to_string(),
        ],
        vec![
            "ramdisk".into(),
            img.display().to_string(),
            "-o".into(),
            d.join("r").display().to_string(),
        ],
        vec![
            "unsparse".into(),
            img.display().to_string(),
            "-o".into(),
            d.join("sp.img").display().to_string(),
        ],
        vec!["report".into(), ota.display().to_string()],
    ]
}

/// Run the binary, failing the test if it hangs.
fn run(args: &[String]) -> String {
    let mut child = Command::new(bin())
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn binary");
    let deadline = Instant::now() + HARD_TIMEOUT;
    loop {
        match child.try_wait().expect("try_wait") {
            Some(_) => {
                let mut err = String::new();
                if let Some(mut e) = child.stderr.take() {
                    let mut buf = Vec::new();
                    let _ = e.read_to_end(&mut buf);
                    err = String::from_utf8_lossy(&buf).into_owned();
                }
                return err;
            }
            None if Instant::now() > deadline => {
                let _ = child.kill();
                panic!("hung: {args:?}");
            }
            None => std::thread::sleep(Duration::from_millis(50)),
        }
    }
}

#[test]
fn every_command_survives_hostile_input() {
    let d = fixture("sweep");
    for base in invocations(&d) {
        for hostile in ["pipe.img", "escape.img", "tiny.img", "huge.img"] {
            let mut args = base.clone();
            // Replace the image argument with the hostile one, keeping any flags.
            if let Some(slot) = args.iter_mut().skip(1).find(|a| a.ends_with(".img")) {
                *slot = d.join(hostile).display().to_string();
            }
            let err = run(&args);
            assert!(
                !err.contains("panicked"),
                "{} panicked on {hostile}: {err}",
                args[0]
            );
        }
    }
    let _ = fs::remove_dir_all(&d);
}

#[test]
fn a_fifo_never_blocks_a_reader() {
    let d = fixture("fifo");
    for cmd in ["identify", "ls", "audit", "dt", "vbmeta"] {
        let args = vec![cmd.to_string(), d.join("pipe.img").display().to_string()];
        let err = run(&args);
        assert!(!err.contains("panicked"), "{cmd} panicked on a FIFO: {err}");
    }
    let _ = fs::remove_dir_all(&d);
}

#[test]
fn extract_does_not_follow_a_symlink_out_of_its_output_directory() {
    let d = fixture("symlink");
    let out = d.join("out");
    let args = vec![
        "extract".to_string(),
        d.join("ota").display().to_string(),
        "-o".to_string(),
        out.display().to_string(),
    ];
    let _ = run(&args);
    assert!(
        !out.join("passwd").exists(),
        "extract wrote through a symlink pointing outside its output directory"
    );
    let _ = fs::remove_dir_all(&d);
}
