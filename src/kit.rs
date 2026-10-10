//! android-doctor as a doctor-kit `Doctor`: the identity, the baseline hooks and the JSON
//! rendering the shared kit code (baseline, faces, MCP, shell) needs. The domain stays here: the
//! rules and the findings are produced by `audit`, `doctor` and `fwdiff`.

use doctor_kit::baseline::BaselineError;
use doctor_kit::doctor_core::{Envelope, Finding};
use doctor_kit::{Check, Doctor, TargetKind};
use std::collections::HashSet;

pub struct AndroidDoctor {
    /// Fingerprints of the findings that say a rule did not run. A baseline never vouches for one.
    pub gaps: HashSet<String>,
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
        self.gaps.contains(&f.fingerprint)
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
