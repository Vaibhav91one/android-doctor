//! Shared terminal presentation: colour detection, human-readable sizes, aligned
//! columns, severity styling, and unified error rendering.
//!
//! Colour is enabled only when stdout is a terminal, the `NO_COLOR` environment variable
//! is unset, and `--no-color` was not passed.  When colour is off every method below
//! emits plain text, so piped or CI output stays parseable and byte-identical to the
//! uncoloured baseline.
//!
//! `--verbose` traces (formats detected, handlers, timings) go to stderr so they never
//! contaminate the stdout stream.
use anyhow::Error;
use std::io::IsTerminal;

/// Whether colour (and other terminal escapes) should be emitted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Style {
    color: bool,
}

impl Style {
    /// Detect colour support once at program start. Colour is on when:
    /// - `--no-color` was not passed, **and**
    /// - `NO_COLOR` is unset, **and**
    /// - stdout or stderr is a terminal.
    pub fn detect(no_color: bool) -> Self {
        let stdout_tty = std::io::stdout().is_terminal();
        let stderr_tty = std::io::stderr().is_terminal();
        let no_color_env = std::env::var_os("NO_COLOR").is_some();
        let color = !no_color && !no_color_env && (stdout_tty || stderr_tty);
        Style { color }
    }

    /// Force colour on or off (used by tests).
    pub fn fixed(color: bool) -> Self {
        Style { color }
    }

    pub fn color(self) -> bool {
        self.color
    }

    /// Wrap `s` in the given ANSI colour code when colour is enabled, otherwise return `s`
    /// unchanged so piped output has no escape sequences.
    pub fn colorize(self, code: &str, s: &str) -> String {
        if self.color {
            format!("\x1b[{code}m{s}\x1b[0m")
        } else {
            s.to_string()
        }
    }
}

// ---------------------------------------------------------------------------
// Human-readable byte sizes
// ---------------------------------------------------------------------------

/// Format a byte count as a human-readable string: `1234567` → `1.2 MiB`.
/// Uses binary units (1024-based).  Values under 1024 B are shown as `N bytes`.
pub fn human_size(bytes: u64) -> String {
    const UNITS: &[(&str, u64)] = &[
        ("TiB", 1 << 40),
        ("GiB", 1 << 30),
        ("MiB", 1 << 20),
        ("KiB", 1 << 10),
    ];
    if bytes < 1024 {
        return format!("{bytes} bytes");
    }
    for (unit, threshold) in UNITS {
        if bytes >= *threshold {
            let val = bytes as f64 / *threshold as f64;
            let s = format!("{val:.1}");
            return format!("{} {}", s.trim_end_matches(".0"), unit);
        }
    }
    format!("{bytes} bytes")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_human_size() {
        assert_eq!(human_size(0), "0 bytes");
        assert_eq!(human_size(1), "1 bytes");
        assert_eq!(human_size(1023), "1023 bytes");
        assert_eq!(human_size(1024), "1 KiB");
        assert_eq!(human_size(1536), "1.5 KiB");
        assert_eq!(human_size(1048576), "1 MiB");
        assert_eq!(human_size(1073741824), "1 GiB");
        assert_eq!(human_size(1099511627776), "1 TiB");
    }
}