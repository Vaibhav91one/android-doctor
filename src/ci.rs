//! `ci install`: write a GitHub Actions workflow that runs this repository's action on pull
//! requests, pinned to this binary's own version so CI gates with the tool the operator ran locally.

use anyhow::{Result, bail};
use doctor_kit::install::{Overwrite, put_safe};
use std::path::{Path, PathBuf};

/// Where the workflow goes, relative to the project root.
const WORKFLOW: [&str; 3] = [".github", "workflows", "android-doctor.yml"];

/// The `--fail-on` levels the action accepts (`error` and `warn` are the pre-0.4 names).
pub const FAIL_ON: [&str; 7] = ["critical", "high", "medium", "low", "none", "error", "warn"];

/// The workflow for `path` and `fail_on`, pinned to `version`.
pub fn workflow(version: &str, path: &str, fail_on: &str) -> Result<String> {
    if !FAIL_ON.contains(&fail_on) {
        bail!("--fail-on must be one of {}", FAIL_ON.join(", "));
    }
    if path.trim().is_empty() || path.chars().any(char::is_control) || path.contains("${{") {
        bail!(
            "--path must be a plain path: no newline, control character or ${{{{ }}}} expression"
        );
    }
    // Single-quoted YAML: the only escape is a doubled quote.
    let path = path.replace('\'', "''");
    Ok(format!(
        "\
# Written by `android-doctor ci install`. Pinned to android-doctor {version}; re-run with --force to repin.
name: android-doctor

on:
  pull_request:
  workflow_dispatch:

permissions:
  contents: read
  # Uploads the SARIF report to code scanning; fork pull requests cannot, and the action skips the upload there.
  security-events: write

jobs:
  android-doctor:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: doctor-labs/android-doctor@v{version}
        with:
          version: {version}
          # The firmware directory to scan, relative to the repository root. Edit it to match your layout.
          path: '{path}'
          command: doctor scan
          fail-on: {fail_on}
"
    ))
}

/// Write `text` as `dir/.github/workflows/android-doctor.yml`, never through a symlink. An
/// existing workflow that differs is an error unless `force` (identical content is a no-op).
pub fn write(dir: &Path, text: &str, force: bool) -> Result<PathBuf> {
    let overwrite = if force {
        Overwrite::Always
    } else {
        Overwrite::RefuseDifferent
    };
    put_safe(dir, &WORKFLOW, text, overwrite).map_err(|e| anyhow::anyhow!(e))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::Scratch;

    const V: &str = env!("CARGO_PKG_VERSION");

    /// No YAML crate is a dependency, so pin the exact structure: the top-level keys, the pin
    /// twice, the permissions and the baked flags, with spaces-only indentation.
    #[test]
    fn the_workflow_has_the_exact_expected_structure() {
        let text = workflow("1.2.3", "fw/out", "high").unwrap();
        assert!(!text.contains('\t'));
        let body: Vec<&str> = text
            .lines()
            .filter(|l| !l.trim_start().starts_with('#'))
            .collect();
        let want = "\
name: android-doctor

on:
  pull_request:
  workflow_dispatch:

permissions:
  contents: read
  security-events: write

jobs:
  android-doctor:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: doctor-labs/android-doctor@v1.2.3
        with:
          version: 1.2.3
          path: 'fw/out'
          command: doctor scan
          fail-on: high";
        assert_eq!(body.join("\n"), want);
        assert!(text.ends_with('\n'));
    }

    #[test]
    fn a_quote_in_the_path_is_escaped_and_hostile_values_are_refused() {
        assert!(
            workflow(V, "it's", "critical")
                .unwrap()
                .contains("path: 'it''s'")
        );
        for bad in ["", "  ", "a\nb", "a\rb", "${{ secrets.X }}"] {
            assert!(workflow(V, bad, "critical").is_err(), "{bad:?}");
        }
        assert!(workflow(V, "fw", "bogus").is_err());
    }

    #[test]
    fn write_creates_dirs_refuses_to_overwrite_and_force_replaces() {
        let s = Scratch::new("ci-write");
        let p = write(&s, "one\n", false).unwrap();
        assert!(p.ends_with(".github/workflows/android-doctor.yml"));
        assert_eq!(std::fs::read_to_string(&p).unwrap(), "one\n");
        assert_eq!(
            write(&s, "one\n", false).unwrap(),
            p,
            "identical is a no-op"
        );
        let err = write(&s, "two\n", false).unwrap_err().to_string();
        assert!(
            err.contains("exists and differs") && err.contains("--force"),
            "{err}"
        );
        assert_eq!(std::fs::read_to_string(&p).unwrap(), "one\n");
        write(&s, "two\n", true).unwrap();
        assert_eq!(std::fs::read_to_string(&p).unwrap(), "two\n");
    }

    #[test]
    fn nothing_is_written_through_a_symlink() {
        use std::os::unix::fs::symlink;
        let s = Scratch::new("ci-symlink");
        let outside = Scratch::new("ci-symlink-outside");
        // .github is a link out of the project
        let proj = s.join("a");
        std::fs::create_dir(&proj).unwrap();
        symlink(&*outside, proj.join(".github")).unwrap();
        assert!(write(&proj, "x\n", true).is_err());
        assert!(std::fs::read_dir(&*outside).unwrap().next().is_none());
        // the workflow file itself is a link: refused, and --force unlinks it instead of following it
        let proj = s.join("b");
        std::fs::create_dir_all(proj.join(".github/workflows")).unwrap();
        let victim = outside.join("victim");
        std::fs::write(&victim, "keep\n").unwrap();
        symlink(&victim, proj.join(".github/workflows/android-doctor.yml")).unwrap();
        assert!(write(&proj, "x\n", false).is_err());
        assert!(
            write(&proj, "new\n", true).is_err(),
            "even --force refuses a link"
        );
        assert_eq!(std::fs::read_to_string(&victim).unwrap(), "keep\n");
    }
}
