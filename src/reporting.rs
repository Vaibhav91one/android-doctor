//! The reporting tail shared by `audit` and `doctor scan`: SARIF output, the output views and the
//! exit status. The finding model itself lives in `findings.rs`.

use crate::findings::{self, Finding, Severity};
use std::path::PathBuf;

/// Reporting flags shared by `audit` and `doctor scan`.
#[derive(clap::Args, Clone, Default)]
pub struct ReportArgs {
    /// Also write the findings as SARIF 2.1.0 to FILE
    #[arg(long, value_name = "FILE")]
    pub sarif: Option<PathBuf>,
}

/// What differs between `audit` and `doctor scan`.
pub struct Emit {
    pub json: bool,
    /// Findings of severity `error` make the command fail (doctor), not just report (audit).
    pub fail_on_error: bool,
}

/// Write SARIF if asked, print the chosen view, and decide the exit.
///
/// A reported finding of severity `error` fails the command (doctor only, as before).
pub fn emit(
    e: Emit,
    args: &ReportArgs,
    all: Vec<Finding>,
    json_text: impl FnOnce(&[Finding]) -> anyhow::Result<String>,
    flat_text: impl FnOnce(&[Finding]) -> String,
) -> anyhow::Result<()> {
    if let Some(path) = &args.sarif {
        let doc = findings::to_sarif(&all, &findings::score(&all), false);
        std::fs::write(path, serde_json::to_string_pretty(&doc)?)
            .map_err(|err| anyhow::anyhow!("cannot write SARIF to {}: {err}", path.display()))?;
    }
    let text = if e.json {
        json_text(&all)?
    } else {
        flat_text(&all)
    };
    crate::print_out(&text)?;
    if e.fail_on_error && all.iter().any(|f| f.severity == Severity::Error) {
        anyhow::bail!("one or more findings have severity error");
    }
    Ok(())
}
