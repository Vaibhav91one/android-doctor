//! The reporting tail shared by `audit` and `doctor scan`: health score, `--baseline`, `--sarif`,
//! the output views and the exit status. The finding model itself lives in `findings.rs`.

use crate::findings::{self, Finding, Severity};
use crate::term;
use std::io::IsTerminal;
use std::path::PathBuf;

/// Exit status when `--baseline` finds something new.
pub const EXIT_NEW_FINDINGS: i32 = 3;

/// A run that completed but whose gate failed. `main` prints the message and exits with `code`:
/// 1 for a finding at or above `--fail-on`, 3 for a new one under `--baseline`.
#[derive(Debug)]
pub struct Gate {
    pub code: i32,
    pub message: String,
}

impl std::fmt::Display for Gate {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for Gate {}

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
    /// Exit 1 when a finding is at or above this severity (critical, high, medium, low, info);
    /// with --baseline, exit 3 when a new one is. Default: critical for `doctor scan`, never for
    /// `audit`; with --baseline, low for both
    #[arg(long, value_name = "SEVERITY", value_parser = Severity::parse)]
    pub fail_on: Option<Severity>,
}

/// What differs between `audit` and `doctor scan`.
pub struct Emit {
    pub title: String,
    /// The command line to repeat, without flags (for "Next steps").
    pub command: String,
    pub json: bool,
    /// The `--fail-on` threshold when none is given and there is no baseline (None = never fail).
    pub fail_default: Option<Severity>,
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

/// Score, mark findings against the baseline, write SARIF, print the chosen view, and decide
/// the exit.
///
/// Exit status (doctor/1): a hard error (unreadable input, baseline or SARIF target) is 2 and
/// prints no report. Otherwise, without `--baseline`, 1 if a finding is at or above the
/// `--fail-on` threshold; with it, 3 if a *new* finding is, else 0. `--json` prints every
/// finding (with `baseline_state` under a baseline); the text views list only the new ones.
pub fn emit(
    e: Emit,
    args: &ReportArgs,
    all: Vec<Finding>,
    data: impl FnOnce() -> serde_json::Value,
    flat_text: impl FnOnce(&[Finding]) -> String,
) -> anyhow::Result<()> {
    // The score is the health of the whole scan, whatever a baseline hides from the listing.
    let score = findings::score(&all);
    let baseline = args
        .baseline
        .as_deref()
        .map(findings::read_baseline)
        .transpose()?;
    let diff = baseline.as_ref().map(|b| b.diff(all.clone()));
    let (shown, suppressed) = match &diff {
        Some(d) => (
            d.all
                .iter()
                .filter(|f| f.baseline_state == Some("new"))
                .cloned()
                .collect(),
            d.unchanged,
        ),
        None => (all.clone(), 0),
    };
    let (min, gated) = if diff.is_some() {
        let min = args.fail_on.unwrap_or(Severity::Warn);
        (Some(min), findings::gates(&shown, min, true))
    } else {
        let min = args.fail_on.or(e.fail_default);
        (min, min.is_some_and(|m| findings::gates(&shown, m, false)))
    };
    let new = shown.iter().filter(|f| !f.gap).count();
    let exit = match (gated, diff.is_some()) {
        (false, _) => 0,
        (true, true) => EXIT_NEW_FINDINGS,
        (true, false) => 1,
    };
    if let Some(path) = &args.sarif {
        let doc = findings::to_sarif(&shown, &score, baseline.is_some());
        std::fs::write(path, serde_json::to_string_pretty(&doc)?)
            .map_err(|err| anyhow::anyhow!("cannot write SARIF to {}: {err}", path.display()))?;
    }
    // Coverage gaps are always listed (a baseline cannot vouch for a rule that did not run), so
    // they are counted apart from the new findings.
    let gaps = shown.iter().filter(|f| f.gap).count();
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
        let v = findings::envelope(
            exit,
            &score,
            diff.as_ref().map_or(&all, |d| &d.all),
            diff.as_ref(),
            data(),
        );
        crate::print_out(&serde_json::to_string_pretty(&v)?)?;
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
    match (exit, min) {
        (0, _) => Ok(()),
        (c, Some(m)) if c == EXIT_NEW_FINDINGS => Err(Gate {
            code: c,
            message: format!(
                "{new} new finding(s) at or above {} not in the baseline",
                m.name()
            ),
        }
        .into()),
        (c, m) => Err(Gate {
            code: c,
            message: format!(
                "one or more findings are at or above {}",
                m.map_or("the threshold", Severity::name)
            ),
        }
        .into()),
    }
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
    fn a_gate_displays_its_message() {
        let g = Gate {
            code: 3,
            message: "x".into(),
        };
        assert_eq!(g.to_string(), "x");
    }
}
