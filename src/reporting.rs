//! The reporting tail shared by `audit` and `doctor scan`: health score, `--baseline`, `--sarif`,
//! the output views and the exit status. The finding model itself lives in `findings.rs`.

use crate::findings::{self, Finding, Severity};
use crate::kit::{AndroidDoctor, Report};
use clap::ValueEnum;
use doctor_core::{Envelope, ExitCode, Finding as CoreFinding};
use doctor_kit::Face;
use doctor_kit::output::{Color, FinishOpts, OutputArgs, finish_with, preflight, report_failure};
use std::io::IsTerminal;
use std::path::PathBuf;

/// A run that completed but whose gate failed. `main` prints the message and exits with `code`:
/// 1 for a finding at or above `--fail-on`, 3 for a new one under `--baseline`.
#[derive(Debug)]
pub struct Gate {
    pub code: ExitCode,
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
    #[arg(long, value_name = "SEVERITY", value_parser = findings::parse_fail_on)]
    pub fail_on: Option<Severity>,
    /// Layout of the human output: plain, rich or compact (default: rich on a terminal, plain
    /// when piped)
    #[arg(long, value_name = "FACE", value_parser = ["plain", "rich", "compact"])]
    pub face: Option<String>,
    /// Colours of the human output: mono, clinical or contrast
    #[arg(long, value_name = "NAME")]
    pub theme: Option<String>,
}

/// What differs between `audit`, `doctor scan` and `diff`.
pub struct Emit {
    pub json: bool,
    /// The `--fail-on` threshold when none is given and there is no baseline (None = never fail).
    pub fail_default: Option<Severity>,
    pub no_color: bool,
    /// The command's own text (the per-image report, the file changes) replaces the face when
    /// piped without `--face`; when false it is printed ahead of the face.
    pub domain_replaces_face: bool,
}

/// Score, mark findings against the baseline, write SARIF, print the chosen view, and decide
/// the exit, all through doctor-kit's `finish_with`.
///
/// Exit status (doctor/1): a hard error (unreadable input, baseline or SARIF target) is 2 and
/// prints no report. Otherwise, without `--baseline`, 1 if a finding is at or above the
/// `--fail-on` threshold; with it, 3 if a *new* finding is, else 0. `--json` prints every
/// finding (with `baseline_state` under a baseline); the human views list only the new ones.
pub fn emit(
    e: Emit,
    args: &ReportArgs,
    all: Vec<Finding>,
    data: impl FnOnce() -> serde_json::Value,
    domain: impl FnOnce() -> Option<String>,
) -> anyhow::Result<()> {
    // The score is the health of the whole scan, whatever a baseline hides from the listing.
    let score = findings::score(&all);
    let mut rows: Vec<CoreFinding> = all.iter().map(Finding::to_core).collect();
    CoreFinding::sort(&mut rows);
    let mut env = Envelope::new(
        "android-doctor",
        env!("CARGO_PKG_VERSION"),
        0,
        score,
        rows,
        serde_json::json!({}),
    );
    let baselined = args.baseline.is_some();
    let machine = e.json || args.score;
    // Under a baseline the default threshold is `low`; without one, audit never fails by default.
    let min = if baselined {
        Some(args.fail_on.unwrap_or(Severity::Low))
    } else {
        args.fail_on.or(e.fail_default)
    };
    let tty = std::io::stdout().is_terminal();
    let o = OutputArgs {
        json: e.json,
        score: args.score,
        headless: false,
        face: args
            .face
            .as_deref()
            .and_then(|f| Face::from_str(f, false).ok())
            .unwrap_or(if tty { Face::Rich } else { Face::Plain }),
        theme: args.theme.clone(),
        theme_file: None,
        color: if e.no_color {
            Color::Never
        } else {
            Color::Auto
        },
        sarif: args.sarif.clone(),
        baseline: args.baseline.clone(),
        fail_on: min.unwrap_or(Severity::Critical),
        theme_root: None,
    };
    let d = AndroidDoctor {
        gaps: all
            .iter()
            .filter(|f| f.gap)
            .map(|f| f.fingerprint.clone())
            .collect(),
        report: Some(Report {
            domain: if machine { None } else { domain() },
            all,
            baseline_path: args.baseline.clone(),
            machine,
            domain_replaces_face: e.domain_replaces_face,
            face_explicit: args.face.is_some(),
            no_color: e.no_color,
        }),
        new_findings: Default::default(),
        subject: None,
    };
    if e.json {
        env.data = data();
    }
    let pre = match preflight(&d, &o) {
        Ok(p) => p,
        Err(f) => return Err(failed(report_failure(&d, &f))),
    };
    let code = finish_with(
        &d,
        pre,
        Ok(env),
        &o,
        &FinishOpts {
            never_fail: min.is_none(),
        },
    );
    match (code, min) {
        (0, _) => Ok(()),
        (3, Some(m)) => Err(Gate {
            code: ExitCode::NewFindings,
            message: format!(
                "{} new finding(s) at or above {} not in the baseline",
                d.new_findings.get(),
                m.as_str()
            ),
        }
        .into()),
        (1, m) => Err(Gate {
            code: ExitCode::Findings,
            message: format!(
                "one or more findings are at or above {}",
                m.map_or("the threshold", Severity::as_str)
            ),
        }
        .into()),
        // the kit already printed what went wrong
        (c, _) => Err(failed(c)),
    }
}

/// A run that failed after the kit reported the reason: exit with `code`, print nothing more.
fn failed(code: u8) -> anyhow::Error {
    Gate {
        code: if code == 2 {
            ExitCode::Error
        } else {
            ExitCode::Findings
        },
        message: String::new(),
    }
    .into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_gate_displays_its_message() {
        let g = Gate {
            code: ExitCode::NewFindings,
            message: "x".into(),
        };
        assert_eq!(g.to_string(), "x");
    }
}
