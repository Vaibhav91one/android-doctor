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

    /// Force colour on or off. Tests need this; nothing else should.
    #[cfg(test)]
    pub fn fixed(color: bool) -> Self {
        Style { color }
    }

    /// Whether colour will be emitted. Callers use this to decide whether to build a
    /// plain-text or coloured string at all, instead of styling and stripping later.
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

// ---------------------------------------------------------------------------
// Severity styling and the shared renderer
// ---------------------------------------------------------------------------

/// How serious a finding is. Ordered so `max` gives the worst of a set.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Severity {
    Info,
    Warn,
    Error,
}

impl Severity {
    /// The lowercase label used in JSON and in the left-hand column of text output.
    pub fn label(self) -> &'static str {
        match self {
            Severity::Info => "info",
            Severity::Warn => "warn",
            Severity::Error => "error",
        }
    }

    /// A colour code suited to this severity.
    fn code(self) -> &'static str {
        match self {
            Severity::Info => "36",  // cyan
            Severity::Warn => "33",  // yellow
            Severity::Error => "31", // red
        }
    }
}

impl std::fmt::Display for Severity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.label())
    }
}

/// Everything that prints: colour decisions, sizing, severity styling and error layout.
#[derive(Debug, Clone, Copy)]
pub struct Renderer {
    pub style: Style,
}

impl Renderer {
    pub fn new(style: Style) -> Self {
        Renderer { style }
    }

    /// Colour `s` according to `severity`.
    pub fn severity(self, sev: Severity, s: &str) -> String {
        self.style.colorize(sev.code(), s)
    }

    /// Render an error the same way from every command: a one-line headline, then the
    /// cause chain indented beneath it. Chains longer than [`MAX_CAUSES`] lines are
    /// truncated so a pathological error cannot flood the terminal.
    pub fn error(self, err: &Error) -> String {
        const MAX_CAUSES: usize = 6;
        let mut out = self.style.colorize("1;31", &err.to_string());
        let mut causes: Vec<String> = err.chain().skip(1).map(|c| c.to_string()).collect();
        if causes.len() > MAX_CAUSES {
            causes.truncate(MAX_CAUSES);
            causes.push(format!(
                "... and {} more",
                err.chain().count() - 1 - MAX_CAUSES
            ));
        }
        for cause in causes {
            out.push_str(&format!("\n  caused by: {cause}"));
        }
        out
    }
}

/// Make text from the analysed target safe to print: control characters (ESC included), bidi
/// controls, zero-width characters and line/paragraph separators become spaces. Every human
/// renderer and the fix prompt go through this one helper (doctor/1 section 8).
pub fn sanitize(s: &str) -> String {
    s.chars()
        .map(|c| {
            if c.is_control()
                || matches!(c, '\u{200b}'..='\u{200f}' | '\u{2028}'..='\u{202e}'
                    | '\u{2060}'..='\u{2069}' | '\u{feff}')
            {
                ' '
            } else {
                c
            }
        })
        .collect()
}

/// Strip ANSI escape sequences, so a caller can measure or compare plain text.
#[cfg(test)]
pub fn strip_ansi(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut chars = s.chars();
    while let Some(c) = chars.next() {
        if c == '\x1b' {
            for c2 in chars.by_ref() {
                if c2 == 'm' {
                    break;
                }
            }
        } else {
            out.push(c);
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn human_sizes_are_binary_and_trim_trailing_zeros() {
        assert_eq!(human_size(0), "0 bytes");
        assert_eq!(human_size(1023), "1023 bytes");
        assert_eq!(human_size(1024), "1 KiB");
        assert_eq!(human_size(1536), "1.5 KiB");
        assert_eq!(human_size(1048576), "1 MiB");
        assert_eq!(human_size(1073741824), "1 GiB");
    }

    #[test]
    fn colour_off_emits_no_escape_sequences() {
        let s = Style::fixed(false);
        assert!(!s.color());
        let r = Renderer::new(s);
        assert_eq!(r.severity(Severity::Error, "boom"), "boom");
        assert_eq!(r.error(&anyhow::anyhow!("boom")), "boom");
    }

    #[test]
    fn colour_on_wraps_and_strips_cleanly() {
        let r = Renderer::new(Style::fixed(true));
        let painted = r.severity(Severity::Error, "boom");
        assert!(painted.contains("\x1b["));
        assert_eq!(strip_ansi(&painted), "boom");
    }

    #[test]
    fn severity_orders_from_info_to_error() {
        assert!(Severity::Error > Severity::Warn);
        assert!(Severity::Warn > Severity::Info);
        assert_eq!(Severity::Warn.to_string(), "warn");
    }

    #[test]
    fn an_error_renders_its_cause_chain_indented() {
        let r = Renderer::new(Style::fixed(false));
        let err = anyhow::anyhow!("outer").context("middle").context("inner");
        let text = r.error(&err);
        assert!(text.starts_with("inner"), "{text}");
        assert!(text.contains("  caused by: middle"), "{text}");
        assert!(text.contains("  caused by: outer"), "{text}");
    }
}
