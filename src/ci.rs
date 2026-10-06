//! `ci install`: write a GitHub Actions workflow that runs this repository's action on pull
//! requests, pinned to this binary's own version so CI gates with the tool the operator ran locally.

use anyhow::{Context, Result, bail};
use std::path::{Path, PathBuf};

/// Where the workflow goes, relative to the project root.
const WORKFLOW: [&str; 3] = [".github", "workflows", "android-doctor.yml"];

/// The `--fail-on` levels the action accepts.
pub const FAIL_ON: [&str; 5] = ["error", "high", "medium", "warn", "none"];

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
      - uses: Vaibhav91one/android-doctor@v{version}
        with:
          version: {version}
          # The firmware directory to scan, relative to the repository root. Edit it to match your layout.
          path: '{path}'
          command: doctor scan
          fail-on: {fail_on}
"
    ))
}

/// Create `dir/<parts...>` one directory at a time, refusing a symlink anywhere below `dir`.
fn create_dirs(dir: &Path, parts: &[&str]) -> Result<PathBuf> {
    let mut cur = dir.to_path_buf();
    for part in parts {
        cur.push(part);
        match cur.symlink_metadata() {
            Ok(m) if m.file_type().is_dir() => {}
            Ok(_) => bail!(
                "{} is not a plain directory (a symlink or a file); refusing to write through it",
                cur.display()
            ),
            Err(_) => {
                std::fs::create_dir(&cur).with_context(|| format!("creating {}", cur.display()))?
            }
        }
    }
    Ok(cur)
}

/// Write `text` as `dir/.github/workflows/android-doctor.yml`.
///
/// An existing file (or symlink) there is an error unless `force`; with `force` it is removed
/// first (a symlink is unlinked, never followed) and the new file is created exclusively, so
/// nothing is ever written through a link.
pub fn write(dir: &Path, text: &str, force: bool) -> Result<PathBuf> {
    use std::io::Write;
    let parent = create_dirs(dir, &WORKFLOW[..2])?;
    let dest = parent.join(WORKFLOW[2]);
    if dest.symlink_metadata().is_ok() {
        if !force {
            bail!(
                "{} already exists; use --force to replace it",
                dest.display()
            );
        }
        std::fs::remove_file(&dest).with_context(|| format!("replacing {}", dest.display()))?;
    }
    let mut f =
        std::fs::File::create_new(&dest).with_context(|| format!("writing {}", dest.display()))?;
    f.write_all(text.as_bytes())
        .with_context(|| format!("writing {}", dest.display()))?;
    Ok(dest)
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
      - uses: Vaibhav91one/android-doctor@v1.2.3
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
            workflow(V, "it's", "error")
                .unwrap()
                .contains("path: 'it''s'")
        );
        for bad in ["", "  ", "a\nb", "a\rb", "${{ secrets.X }}"] {
            assert!(workflow(V, bad, "error").is_err(), "{bad:?}");
        }
        assert!(workflow(V, "fw", "critical").is_err());
    }

    #[test]
    fn write_creates_dirs_refuses_to_overwrite_and_force_replaces() {
        let s = Scratch::new("ci-write");
        let p = write(&s, "one\n", false).unwrap();
        assert!(p.ends_with(".github/workflows/android-doctor.yml"));
        assert_eq!(std::fs::read_to_string(&p).unwrap(), "one\n");
        let err = write(&s, "two\n", false).unwrap_err().to_string();
        assert!(
            err.contains("already exists") && err.contains("--force"),
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
        write(&proj, "new\n", true).unwrap();
        assert_eq!(std::fs::read_to_string(&victim).unwrap(), "keep\n");
        let dest = proj.join(".github/workflows/android-doctor.yml");
        assert!(!dest.symlink_metadata().unwrap().file_type().is_symlink());
        assert_eq!(std::fs::read_to_string(dest).unwrap(), "new\n");
    }
}
