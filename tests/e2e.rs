//! End-to-end test: build synthetic fixtures (no real firmware) and run the
//! released binary against them to prove it works.
//!
//! This runs in CI via `cargo test`. Cargo sets the
//! `CARGO_BIN_EXE_android-doctor` environment variable for integration tests,
//! pointing to the freshly compiled `android-doctor` binary.

use std::io::Write;
use std::process::Command;

/// A temporary directory that is deleted when dropped.
struct Scratch(std::path::PathBuf);

impl Scratch {
    fn new(tag: &str) -> Self {
        let dir = std::env::temp_dir().join(format!("ad-e2e-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        Self(dir)
    }
}

impl std::ops::Deref for Scratch {
    type Target = std::path::PathBuf;
    fn deref(&self) -> &std::path::PathBuf {
        &self.0
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// Build three synthetic fixtures — a gzip file, a tar archive, and a boot image
/// stub — and verify that `android-doctor identify --json` classifies each
/// correctly.
#[test]
fn binary_identifies_synthetic_fixtures() {
    let dir = Scratch::new("identify");

    // 1. A gzip file: compress some bytes with flate2.
    let gz_path = dir.join("kernel.gz");
    {
        let f = std::fs::File::create(&gz_path).unwrap();
        let mut enc = flate2::write::GzEncoder::new(f, flate2::Compression::default());
        enc.write_all(b"synthetic ramdisk payload").unwrap();
        enc.finish().unwrap();
    }

    // 2. A tar archive containing a single small file.
    let tar_path = dir.join("archive.tar");
    {
        let f = std::fs::File::create(&tar_path).unwrap();
        let mut arc = tar::Builder::new(f);
        let content = b"hello from synthetic tar";
        let mut header = tar::Header::new_gnu();
        header.set_path("greeting.txt").unwrap();
        header.set_size(content.len() as u64);
        header.set_mode(0o644);
        header.set_mtime(0);
        arc.append(&header, &content[..]).unwrap();
        arc.into_inner().unwrap();
    }

    // 3. A boot image stub: the ANDROID! magic at offset 0.
    let boot_path = dir.join("boot.img");
    let mut boot = vec![0u8; 1680];
    boot[..8].copy_from_slice(b"ANDROID!");
    std::fs::write(&boot_path, &boot).unwrap();

    // Run the binary with `identify --json` on all three fixtures.
    let exe = env!("CARGO_BIN_EXE_android-doctor");
    let out = Command::new(exe)
        .args(["identify", "--json"])
        .args([&gz_path, &tar_path, &boot_path])
        .output()
        .expect("failed to spawn android-doctor");
    assert!(
        out.status.success(),
        "identify exited with {}: {}",
        out.status,
        String::from_utf8_lossy(&out.stderr)
    );

    let json: Vec<serde_json::Value> =
        serde_json::from_slice(&out.stdout).expect("identify --json is valid JSON");
    assert_eq!(json.len(), 3, "expected three identified files");

    let ids: Vec<String> = json
        .iter()
        .map(|v| v["id"].as_str().unwrap().to_string())
        .collect();
    assert!(
        ids.contains(&"gzip".to_string()),
        "gzip not found in {ids:?}"
    );
    assert!(ids.contains(&"tar".to_string()), "tar not found in {ids:?}");
    assert!(
        ids.contains(&"boot-image".to_string()),
        "boot-image not found in {ids:?}"
    );
}
