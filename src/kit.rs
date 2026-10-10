//! android-doctor as a doctor-kit `Doctor`: the identity, the baseline parsing, the human report
//! and the JSON/SARIF rendering the shared kit pipeline (`finish_with`) calls. The domain stays
//! here: the rules and the findings are produced by `audit`, `doctor` and `fwdiff`.

use crate::findings;
use crate::term::{Renderer, Style};
use anyhow::Context;
use doctor_kit::baseline::Saved;
use doctor_kit::doctor_core::{BaselineState, Envelope, Finding};
use doctor_kit::{Check, Doctor, Face, ScanFailure, TargetKind, Theme};
use serde_json::Value;
use std::cell::Cell;
use std::collections::HashSet;
use std::io::IsTerminal;
use std::path::{Path, PathBuf};

/// What one `audit` / `doctor scan` / `diff` run needs to present its result.
pub struct Report {
    /// The findings in scan order (SARIF lists them in this order).
    pub all: Vec<findings::Finding>,
    pub baseline_path: Option<PathBuf>,
    /// `--json` or `--score`: stdout is the machine report, the baseline note goes to stderr.
    pub machine: bool,
    /// The command's own text (per-image report, file changes).
    pub domain: Option<String>,
    /// It replaces the face when piped without `--face`; otherwise it precedes the face.
    pub domain_replaces_face: bool,
    pub face_explicit: bool,
    pub no_color: bool,
}

#[derive(Default)]
pub struct AndroidDoctor {
    /// Fingerprints of the findings that say a rule did not run. A baseline never vouches for one.
    pub gaps: HashSet<String>,
    pub report: Option<Report>,
    /// New (non-gap) findings under a baseline, for the gate message.
    pub new_findings: Cell<usize>,
}

impl AndroidDoctor {
    /// The findings a human sees: all of them, or only the new ones under a baseline.
    fn shown(env: &Envelope) -> Vec<Finding> {
        let baselined = env.baseline.is_some();
        env.findings
            .iter()
            .filter(|f| !baselined || f.baseline_state == Some(BaselineState::New))
            .cloned()
            .collect()
    }

    /// `baseline FILE: N suppressed as known, M new[, K coverage gap(s) listed]`
    fn note(&self, env: &Envelope) -> Option<String> {
        let counts = env.baseline?;
        let path = self.report.as_ref()?.baseline_path.as_deref()?;
        let shown = Self::shown(env);
        let gaps = shown.iter().filter(|f| self.is_gap(f)).count();
        let listed = match gaps {
            0 => String::new(),
            n => format!(", {n} coverage gap(s) listed"),
        };
        Some(format!(
            "baseline {}: {} suppressed as known, {} new{listed}",
            path.display(),
            counts.unchanged,
            shown.len() - gaps
        ))
    }
}

/// A previous `--json` report, reduced to its fingerprints: a doctor/1 envelope (an object with a
/// `findings` array), or the pre-0.4 bare array. Anything else is an error, never an empty
/// baseline: a mistyped or wrong file silently disabling the gate would be worse than failing.
fn read_baseline(path: &Path) -> anyhow::Result<Saved> {
    let shown = path.display();
    let text =
        std::fs::read_to_string(path).with_context(|| format!("cannot read baseline {shown}"))?;
    let doc: Value = serde_json::from_str(&text)
        .with_context(|| format!("baseline {shown} is not valid JSON"))?;
    let rows = match &doc {
        Value::Array(a) => Some(a),
        Value::Object(o) => o.get("findings").and_then(Value::as_array),
        _ => None,
    };
    let Some(rows) = rows else {
        anyhow::bail!(
            "baseline {shown} is not an android-doctor report: expected the output of \
             `doctor scan --json` or `audit --json`"
        );
    };
    let mut fingerprints = HashSet::new();
    for (i, row) in rows.iter().enumerate() {
        let Some(fp) = row.get("fingerprint").and_then(Value::as_str) else {
            anyhow::bail!(
                "baseline {shown} is not an android-doctor report: finding {} has no \
                 fingerprint (was it written by an older version?)",
                i + 1
            );
        };
        fingerprints.insert(fp.to_string());
    }
    Ok(Saved { fingerprints, doc })
}

impl Doctor for AndroidDoctor {
    fn name(&self) -> &str {
        "android-doctor"
    }
    fn version(&self) -> &str {
        env!("CARGO_PKG_VERSION")
    }
    fn about(&self) -> &str {
        "Extract and audit Android OTA/ROM images"
    }
    fn categories(&self) -> Vec<&'static str> {
        vec!["security", "quality"]
    }
    fn checks(&self) -> Vec<Box<dyn Check>> {
        vec![]
    }
    /// The subject is an image, a directory of images or two builds, chosen by the command.
    fn target(&self) -> TargetKind {
        TargetKind::Detached
    }
    fn is_gap(&self, f: &Finding) -> bool {
        self.gaps.contains(&f.fingerprint)
    }
    /// `ci install` refuses to touch any existing workflow unless `--force`.
    fn ci_overwrite(&self) -> doctor_kit::install::Overwrite {
        doctor_kit::install::Overwrite::Never
    }
    /// Sorted keys, as `doctor_core::Envelope::to_value` writes them: the output of every release.
    fn render_json(&self, env: &Envelope) -> String {
        serde_json::to_string_pretty(&env.to_value()).expect("an envelope is JSON") + "\n"
    }
    /// The tool's own SARIF (rule help, locations, `baselineState`), in scan order and without a
    /// trailing newline, as every release wrote it.
    fn render_sarif(&self, env: &Envelope) -> String {
        let baselined = env.baseline.is_some();
        let keep: HashSet<String> = Self::shown(env)
            .into_iter()
            .map(|f| f.fingerprint)
            .collect();
        let all = self.report.as_ref().map_or(&[][..], |r| &r.all[..]);
        let shown: Vec<findings::Finding> = all
            .iter()
            .filter(|f| keep.contains(&f.fingerprint))
            .cloned()
            .collect();
        serde_json::to_string_pretty(&findings::to_sarif(&shown, &env.score, baselined))
            .expect("SARIF is JSON")
    }
    /// The old parsing and error wording, no size cap; the error is rendered as every error is.
    fn load_baseline(&self, path: &Path) -> Result<Saved, ScanFailure> {
        let no_color = self.report.as_ref().is_some_and(|r| r.no_color);
        read_baseline(path)
            .map_err(|e| ScanFailure::plain(Renderer::new(Style::detect(no_color)).error(&e)))
    }
    /// Counts the new findings for the gate message and, when stdout is machine output, prints the
    /// baseline summary to stderr.
    fn baseline_hook(&self, _saved: &Value, env: &mut Envelope) -> Result<(), ScanFailure> {
        let shown = Self::shown(env);
        self.new_findings
            .set(shown.iter().filter(|f| !self.is_gap(f)).count());
        if self.report.as_ref().is_some_and(|r| r.machine)
            && let Some(n) = self.note(env)
        {
            eprintln!("{n}");
        }
        Ok(())
    }
    /// `audit` keeps its per-image report when piped without `--face`; `diff` keeps its file
    /// changes ahead of the face; under a baseline only the new findings are listed.
    fn render_human(&self, env: &Envelope, face: &Face, theme: &Theme) -> Option<String> {
        let r = self.report.as_ref()?;
        let shown = Self::shown(env);
        let mut view = env.clone();
        view.findings = shown.clone();
        let face_text = || doctor_kit::face::render(*face, &view, theme);
        let tty = std::io::stdout().is_terminal();
        let mut text = match &r.domain {
            Some(t) if r.domain_replaces_face && !tty && !r.face_explicit => t.clone(),
            Some(t) if !r.domain_replaces_face => format!("{t}\n{}", face_text().trim_end()),
            _ => face_text().trim_end().to_string(),
        };
        if let Some(n) = self.note(env) {
            if shown.is_empty() {
                text = "no new findings".to_string();
            }
            text.push_str(&format!("\n{n}"));
        }
        Some(text + "\n")
    }
}
