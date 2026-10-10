//! android-doctor as a doctor-kit `Doctor`: the identity, the scan the shell and explorer run,
//! the baseline hooks and the JSON rendering the shared kit code needs. The domain stays here:
//! the rules and the findings are produced by `audit`, `doctor` and `fwdiff`.

use crate::{audit, doctor, findings};
use doctor_kit::baseline::BaselineError;
use doctor_kit::doctor_core::{Envelope, Finding, Score};
use doctor_kit::{Check, Collected, Ctx, Doctor, ScanFailure, TargetKind};
use std::cell::RefCell;
use std::collections::HashSet;
use std::path::PathBuf;

#[derive(Default)]
pub struct AndroidDoctor {
    /// Fingerprints of the findings that say a rule did not run. A baseline never vouches for one.
    pub gaps: RefCell<HashSet<String>>,
    /// What `shell` and `explore` look at: a firmware directory or one image.
    pub subject: Option<PathBuf>,
}

impl AndroidDoctor {
    pub fn with_gaps(gaps: HashSet<String>) -> Self {
        AndroidDoctor {
            gaps: RefCell::new(gaps),
            subject: None,
        }
    }

    /// The scan context of the interactive commands: nothing is walked, the root is the subject.
    #[cfg(any(feature = "shell", feature = "explore"))]
    pub fn ctx(&self) -> Ctx {
        let mut ctx = Ctx::detached(
            doctor_kit::Config::default(),
            doctor_kit::doctor_core::Severity::Critical,
        );
        if let Some(s) = &self.subject {
            ctx.root = s.clone();
        }
        ctx
    }
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
    fn mcp_tools(&self) -> Option<Vec<doctor_kit::McpTool>> {
        Some(crate::mcp::tools())
    }
    fn is_gap(&self, f: &Finding) -> bool {
        self.gaps.borrow().contains(&f.fingerprint)
    }
    fn score(&self, findings: &[Finding], _: &Ctx) -> Option<Score> {
        Some(findings::score_core(findings, &|f| self.is_gap(f)))
    }
    /// A directory gets the `doctor scan` health scan, an image gets the `audit` rules.
    fn collect(&self, _: &Ctx) -> Result<Collected, ScanFailure> {
        let subject = self
            .subject
            .as_deref()
            .ok_or_else(|| ScanFailure::new("no firmware directory or image given"))?;
        let found = if subject.is_dir() {
            doctor::scan_scoped(subject).map(findings::from_doctor)
        } else {
            audit::audit_image(subject).map(|a| findings::from_audit(&[a]))
        }
        .map_err(|e| ScanFailure::new(format!("{e:#}")))?;
        let gaps = found.iter().filter(|f| f.gap).count();
        self.gaps.borrow_mut().extend(
            found
                .iter()
                .filter(|f| f.gap)
                .map(|f| f.fingerprint.clone()),
        );
        Ok(Collected {
            findings: found.iter().map(findings::Finding::to_core).collect(),
            data: serde_json::json!({}),
            gaps,
        })
    }
    /// Sorted keys, as `doctor_core::Envelope::to_value` writes them: the output of every release.
    fn render_json(&self, env: &Envelope) -> String {
        serde_json::to_string_pretty(&env.to_value()).expect("an envelope is JSON") + "\n"
    }
    fn baseline_message(&self, e: &BaselineError) -> String {
        match e {
            BaselineError::Unreadable { path, err } => {
                format!("cannot read baseline {path}: {err}")
            }
            BaselineError::TooLarge { path, max } => {
                format!("baseline {path} is larger than {max} bytes")
            }
            BaselineError::NotJson { path, err } => {
                format!("baseline {path} is not valid JSON: {err}")
            }
            BaselineError::NotDoctor1 { path } => format!(
                "baseline {path} is not an android-doctor report: expected the output of \
                 `doctor scan --json` or `audit --json` (a doctor/1 envelope whose findings all \
                 carry a fingerprint; an older version wrote reports with no fingerprint)"
            ),
            BaselineError::Other(m) => m.clone(),
        }
    }
}
