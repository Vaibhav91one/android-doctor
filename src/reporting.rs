//! The reporting tail shared by `audit` and `doctor scan`: `--baseline`, SARIF output, the output
//! views and the exit status. The finding model itself lives in `findings.rs`.

use crate::findings::{self, Finding, Severity};
use std::path::PathBuf;

/// Exit status when `--baseline` finds something new.
pub const EXIT_NEW_FINDINGS: i32 = 3;

/// Returned when a `--baseline` run found something new; `main` turns it into exit code 3.
#[derive(Debug)]
pub struct NewFindings(pub usize);

impl std::fmt::Display for NewFindings {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} new finding(s) not in the baseline", self.0)
    }
}

impl std::error::Error for NewFindings {}

/// Reporting flags shared by `audit` and `doctor scan`.
#[derive(clap::Args, Clone, Default)]
pub struct ReportArgs {
    /// Also write the findings as SARIF 2.1.0 to FILE
    #[arg(long, value_name = "FILE")]
    pub sarif: Option<PathBuf>,
    /// Report only findings that are not in FILE, a previous `--json` report; exit 3 if there
    /// are new ones
    #[arg(long, value_name = "FILE")]
    pub baseline: Option<PathBuf>,
}

/// What differs between `audit` and `doctor scan`.
pub struct Emit {
    pub json: bool,
    /// Findings of severity `error` make the command fail (doctor), not just report (audit).
    pub fail_on_error: bool,
}

/// Filter against the baseline, write SARIF, print the chosen view, and decide the exit.
///
/// Exit status, first match wins: a hard error (unreadable input, baseline or SARIF target) is 1;
/// a reported finding of severity `error` is 1 (doctor only, as before); a new finding above
/// `info` under `--baseline` is 3; otherwise 0. `--baseline` filters before the `error` check, so
/// a known error does not fail the run.
pub fn emit(
    e: Emit,
    args: &ReportArgs,
    all: Vec<Finding>,
    json_text: impl FnOnce(&[Finding]) -> anyhow::Result<String>,
    flat_text: impl FnOnce(&[Finding]) -> String,
) -> anyhow::Result<()> {
    // The score is the health of the whole scan, whatever a baseline hides from the listing.
    let score = findings::score(&all);
    let baseline = args
        .baseline
        .as_deref()
        .map(findings::read_baseline)
        .transpose()?;
    let (shown, suppressed) = match &baseline {
        Some(b) => {
            let d = b.diff(all);
            (d.new, d.suppressed)
        }
        None => (all, 0),
    };
    if let Some(path) = &args.sarif {
        let doc = findings::to_sarif(&shown, &score, baseline.is_some());
        std::fs::write(path, serde_json::to_string_pretty(&doc)?)
            .map_err(|err| anyhow::anyhow!("cannot write SARIF to {}: {err}", path.display()))?;
    }
    // Coverage gaps are always listed (a baseline cannot vouch for a rule that did not run), so
    // they are counted apart from the new findings.
    let gaps = shown.iter().filter(|f| f.gap).count();
    let new = shown.len() - gaps;
    let note = baseline.as_ref().map(|b| {
        let listed = match gaps {
            0 => String::new(),
            n => format!(", {n} coverage gap(s) listed"),
        };
        format!(
            "baseline {}: {suppressed} suppressed as known, {new} new{listed}",
            b.path
        )
    });
    if e.json {
        crate::print_out(&json_text(&shown)?)?;
        // stdout is the machine-readable report, so the baseline summary goes to stderr.
        if let Some(n) = &note {
            eprintln!("{n}");
        }
    } else {
        let mut text = flat_text(&shown);
        if let Some(n) = &note {
            if shown.is_empty() {
                text = "no new findings".to_string();
            }
            text.push_str(&format!("\n{n}"));
        }
        crate::print_out(&text)?;
    }
    if e.fail_on_error && shown.iter().any(|f| f.severity == Severity::Error) {
        anyhow::bail!("one or more findings have severity error");
    }
    if baseline.is_some() && findings::gates(&shown) {
        return Err(NewFindings(new).into());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_findings_displays_a_count() {
        assert_eq!(
            NewFindings(2).to_string(),
            "2 new finding(s) not in the baseline"
        );
    }
}
