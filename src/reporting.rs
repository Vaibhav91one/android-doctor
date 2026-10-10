//! The reporting tail shared by `audit` and `doctor scan`: health score, `--baseline`, `--sarif`,
//! the output views and the exit status. The finding model itself lives in `findings.rs`.

use crate::findings::{self, Finding, Severity};
use crate::kit::AndroidDoctor;
use crate::term;
use clap::ValueEnum;
use doctor_core::{BaselineState, Envelope, ExitCode, Finding as CoreFinding};
use doctor_kit::{Doctor, Face, Theme, baseline};
use std::collections::HashSet;
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

/// Control and bidi characters of hostile firmware must not reach a terminal.
fn clean_for_terminal(f: &mut CoreFinding) {
    f.id = term::sanitize(&f.id);
    f.category = term::sanitize(&f.category);
    f.message = term::sanitize(&f.message);
    f.remedy = f.remedy.as_deref().map(term::sanitize);
    f.location.reference = term::sanitize(&f.location.reference);
}

/// Score, mark findings against the baseline, write SARIF, print the chosen view, and decide
/// the exit.
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
    let d = AndroidDoctor::with_gaps(
        all.iter()
            .filter(|f| f.gap)
            .map(|f| f.fingerprint.clone())
            .collect(),
    );
    let saved = args
        .baseline
        .as_deref()
        .map(|p| baseline::load_for(&d, p))
        .transpose()
        .map_err(|f| anyhow::anyhow!(f.to_string()))?;
    // The score is the health of the whole scan, whatever a baseline hides from the listing.
    let score = findings::score(&all);
    let mut rows: Vec<CoreFinding> = all.iter().map(Finding::to_core).collect();
    CoreFinding::sort(&mut rows);
    let mut env = Envelope::new(
        d.name(),
        d.version(),
        0,
        score.clone(),
        rows,
        serde_json::json!({}),
    );
    let counts = saved.as_ref().map(|s| baseline::apply(&d, &mut env, s));
    let (min, code) = match &counts {
        Some(_) => {
            let min = args.fail_on.unwrap_or(Severity::Low);
            (Some(min), baseline::gate(&d, &env, min, true))
        }
        None => {
            let min = args.fail_on.or(e.fail_default);
            (min, min.map_or(0, |m| baseline::gate(&d, &env, m, false)))
        }
    };
    env.exit_code = code;
    let exit = match (code, counts.is_some()) {
        (0, _) => ExitCode::Ok,
        (_, true) => ExitCode::NewFindings,
        (_, false) => ExitCode::Findings,
    };
    let shown_rows: Vec<CoreFinding> = env
        .findings
        .iter()
        .filter(|f| counts.is_none() || f.baseline_state == Some(BaselineState::New))
        .cloned()
        .collect();
    let shown: Vec<Finding> = {
        let keep: HashSet<&str> = shown_rows.iter().map(|f| f.fingerprint.as_str()).collect();
        all.iter()
            .filter(|f| keep.contains(f.fingerprint.as_str()))
            .cloned()
            .collect()
    };
    let new = shown.iter().filter(|f| !f.gap).count();
    if let Some(path) = &args.sarif {
        let doc = findings::to_sarif(&shown, &score, counts.is_some());
        std::fs::write(path, serde_json::to_string_pretty(&doc)?)
            .map_err(|err| anyhow::anyhow!("cannot write SARIF to {}: {err}", path.display()))?;
    }
    // Coverage gaps are always listed (a baseline cannot vouch for a rule that did not run), so
    // they are counted apart from the new findings.
    let gaps = shown.iter().filter(|f| f.gap).count();
    let note = counts.map(|c| {
        let listed = match gaps {
            0 => String::new(),
            n => format!(", {n} coverage gap(s) listed"),
        };
        format!(
            "baseline {}: {} suppressed as known, {new} new{listed}",
            args.baseline
                .as_deref()
                .map_or_else(String::new, |p| p.display().to_string()),
            c.unchanged
        )
    });
    if args.score {
        crate::print_out(&score.value.to_string())?;
    } else if e.json {
        env.data = data();
        crate::print_out(d.render_json(&env).trim_end())?;
    } else {
        let tty = std::io::stdout().is_terminal();
        let face_text = || -> anyhow::Result<String> {
            let mut view = env.clone();
            view.findings = shown_rows.clone();
            view.findings.iter_mut().for_each(clean_for_terminal);
            let mut theme = match &args.theme {
                Some(n) => Theme::by_name(n).ok_or_else(|| {
                    anyhow::anyhow!("unknown theme {n:?}: use mono, clinical or contrast")
                })?,
                None => d.theme(),
            };
            theme.enabled = term::Style::detect(e.no_color).color();
            let face = args
                .face
                .as_deref()
                .and_then(|f| Face::from_str(f, false).ok())
                .unwrap_or(if tty { Face::Rich } else { Face::Plain });
            Ok(doctor_kit::face::render(face, &view, &theme))
        };
        let mut text = match domain() {
            Some(t) if e.domain_replaces_face && !tty && args.face.is_none() => t,
            Some(t) if !e.domain_replaces_face => format!("{t}\n{}", face_text()?.trim_end()),
            _ => face_text()?.trim_end().to_string(),
        };
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
        (ExitCode::Ok, _) => Ok(()),
        (c, Some(m)) if c == ExitCode::NewFindings => Err(Gate {
            code: c,
            message: format!(
                "{new} new finding(s) at or above {} not in the baseline",
                m.as_str()
            ),
        }
        .into()),
        (c, m) => Err(Gate {
            code: c,
            message: format!(
                "one or more findings are at or above {}",
                m.map_or("the threshold", Severity::as_str)
            ),
        }
        .into()),
    }
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
