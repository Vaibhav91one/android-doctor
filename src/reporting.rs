//! The reporting tail shared by `audit` and `doctor scan`: health score, `--baseline`, `--sarif`,
//! the output views and the exit status. The finding model itself lives in `findings.rs`.

use crate::findings::{self, Finding, Score, Severity};
use crate::term;
use std::io::IsTerminal;
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
    /// Print only the 0-100 health score
    #[arg(long, conflicts_with = "json")]
    pub score: bool,
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
    pub title: String,
    /// The command line to repeat, without flags (for "Next steps").
    pub command: String,
    pub json: bool,
    /// Findings of severity `error` make the command fail (doctor), not just report (audit).
    pub fail_on_error: bool,
    pub no_color: bool,
}

/// Single-quote a word for a shell when it has anything but safe characters.
pub fn shell_quote(s: &str) -> String {
    let safe = |c: char| c.is_ascii_alphanumeric() || "_./-:+=@,".contains(c);
    if !s.is_empty() && s.chars().all(safe) {
        s.to_string()
    } else {
        format!("'{}'", s.replace('\'', "'\\''"))
    }
}

/// The exact commands the digest points at.
pub fn next_steps(command: &str, baselined: bool) -> Vec<String> {
    if baselined {
        vec![
            format!("{command} --json > baseline.json"),
            format!("{command} --sarif report.sarif"),
        ]
    } else {
        vec![
            format!("{command} --json > baseline.json"),
            format!("{command} --baseline baseline.json"),
        ]
    }
}

/// Score, filter against the baseline, write SARIF, print the chosen view, and decide the exit.
///
/// Exit status, first match wins: a hard error (unreadable input, baseline or SARIF target) is 1;
/// a reported finding of severity `error` is 1 (doctor only, as before); a new finding above
/// `info` under `--baseline` is 3; otherwise 0. `--baseline` filters before the `error` check, so
/// a known error does not fail the run.
pub fn emit(
    e: Emit,
    args: &ReportArgs,
    all: Vec<Finding>,
    json_text: impl FnOnce(&[Finding], &Score) -> anyhow::Result<String>,
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
    if args.score {
        crate::print_out(&score.value.to_string())?;
    } else if e.json {
        crate::print_out(&json_text(&shown, &score)?)?;
    } else if std::io::stdout().is_terminal() && args.sarif.is_none() {
        let next = next_steps(&e.command, baseline.is_some());
        let r = term::Renderer::new(term::Style::detect(e.no_color));
        let mut text = findings::render_digest(&e.title, &shown, &score, &next, r);
        if let Some(n) = &note {
            text.push_str(&format!("\n{n}"));
        }
        crate::print_out(&text)?;
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
    // stdout is the machine-readable report here, so the baseline summary goes to stderr.
    if (args.score || e.json)
        && let Some(n) = &note
    {
        eprintln!("{n}");
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
    fn shell_quote_leaves_safe_words_and_quotes_the_rest() {
        assert_eq!(shell_quote("out/fw-1.2"), "out/fw-1.2");
        assert_eq!(shell_quote("my fw"), "'my fw'");
        assert_eq!(shell_quote("it's"), "'it'\\''s'");
        assert_eq!(shell_quote(""), "''");
    }

    #[test]
    fn next_steps_name_the_baseline_commands() {
        let n = next_steps("android-doctor doctor scan fw", false);
        assert!(n[0].contains("--json > baseline.json"));
        assert!(n[1].contains("--baseline baseline.json"));
        let n = next_steps("android-doctor doctor scan fw", true);
        assert!(n[1].contains("--sarif report.sarif"));
    }

    #[test]
    fn new_findings_displays_a_count() {
        assert_eq!(
            NewFindings(2).to_string(),
            "2 new finding(s) not in the baseline"
        );
    }
}
