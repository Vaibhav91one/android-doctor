//! Staleness verdict for an OTA, from its build metadata.
use crate::info::Metadata;
use anyhow::{Context, Result, bail};
use serde_json::json;
use std::time::{SystemTime, UNIX_EPOCH};

/// Newest API level this tool knows about (Android 16). Bump when a new Android release ships.
const LATEST_KNOWN_SDK: u32 = 36;
const STALE_DAYS: i64 = 90;
const VERY_STALE_DAYS: i64 = 365;

#[derive(Debug, PartialEq, Clone, Copy)]
pub enum Verdict {
    Ok,
    Stale,
    VeryStale,
}

impl Verdict {
    fn label(self) -> &'static str {
        match self {
            Self::Ok => "ok",
            Self::Stale => "stale",
            Self::VeryStale => "very stale",
        }
    }

    fn from_age(days: i64) -> Self {
        match days {
            d if d > VERY_STALE_DAYS => Self::VeryStale,
            d if d > STALE_DAYS => Self::Stale,
            _ => Self::Ok,
        }
    }
}

#[derive(Debug, PartialEq)]
pub struct Report {
    pub device: Option<String>,
    pub build: Option<String>,
    pub sdk: Option<u32>,
    pub patch_level: Option<String>,
    pub patch_age_days: Option<i64>,
    pub verdict: Option<Verdict>,
    pub partitions: Vec<String>,
}

fn days_in_month(y: i64, m: i64) -> i64 {
    match m {
        2 if y % 4 == 0 && (y % 100 != 0 || y % 400 == 0) => 29,
        2 => 28,
        4 | 6 | 9 | 11 => 30,
        _ => 31,
    }
}

/// Days since 1970-01-01 for a proleptic Gregorian date (Howard Hinnant's algorithm).
fn days_from_civil(y: i64, m: i64, d: i64) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let doy = (153 * (if m > 2 { m - 3 } else { m + 9 }) + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146097 + doe - 719468
}

/// Parse `YYYY-MM-DD` (or `YYYY-MM`, taken as the 1st) into days since the epoch.
fn parse_patch_level(s: &str) -> Result<i64> {
    let parts: Vec<i64> = s
        .split('-')
        .map(|p| match p.bytes().all(|b| b.is_ascii_digit()) {
            true => p.parse::<i64>().map_err(|e| e.to_string()),
            false => Err(format!("{p:?} is not a plain number")),
        })
        .collect::<Result<_, _>>()
        .map_err(|e| anyhow::anyhow!("bad security patch level {s:?}: {e}"))?;
    let (y, m, d) = match parts[..] {
        [y, m] => (y, m, 1),
        [y, m, d] => (y, m, d),
        _ => bail!("bad security patch level {s:?}"),
    };
    if !(1..=12).contains(&m) || d < 1 || d > days_in_month(y, m) || !(1970..=9999).contains(&y) {
        bail!("bad security patch level {s:?}");
    }
    Ok(days_from_civil(y, m, d))
}

/// Today's date in UTC as days since the epoch (a patch age can differ by a day from local time).
pub fn today_days() -> i64 {
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs());
    (secs / 86400) as i64
}

fn android_name(sdk: u32) -> Option<&'static str> {
    Some(match sdk {
        21 => "5.0",
        22 => "5.1",
        23 => "6.0",
        24 => "7.0",
        25 => "7.1",
        26 => "8.0",
        27 => "8.1",
        28 => "9",
        29 => "10",
        30 => "11",
        31 => "12",
        32 => "12L",
        33 => "13",
        34 => "14",
        35 => "15",
        36 => "16",
        _ => return None,
    })
}

pub fn analyze(meta: &Metadata, partitions: Vec<String>, today: i64) -> Result<Report> {
    let get = |k: &str| meta.get(k).cloned();
    let sdk = match meta.get("post-sdk-level") {
        Some(v) => Some(
            v.parse()
                .with_context(|| format!("bad post-sdk-level {v:?}"))?,
        ),
        None => None,
    };
    let patch_level = get("post-security-patch-level");
    let patch_age_days = match &patch_level {
        Some(p) => Some(today - parse_patch_level(p)?),
        None => None,
    };
    Ok(Report {
        device: get("pre-device"),
        build: get("post-build"),
        sdk,
        verdict: patch_age_days.map(Verdict::from_age),
        patch_level,
        patch_age_days,
        partitions,
    })
}

fn android_line(sdk: u32) -> String {
    let name = android_name(sdk).map_or(String::new(), |n| format!("Android {n}, "));
    let behind = LATEST_KNOWN_SDK.saturating_sub(sdk);
    format!("{name}SDK {sdk} ({behind} API levels behind latest known, {LATEST_KNOWN_SDK})")
}

pub fn render(r: &Report, as_json: bool) -> Result<String> {
    if as_json {
        return Ok(serde_json::to_string_pretty(&json!({
            "device": r.device,
            "build": r.build,
            "sdk": r.sdk,
            "android": r.sdk.and_then(android_name),
            "patch_level": r.patch_level,
            "patch_age_days": r.patch_age_days,
            "verdict": r.verdict.map(Verdict::label),
            "partitions": r.partitions,
        }))?);
    }
    let unknown = || "unknown".to_string();
    let rows = [
        ("device", r.device.clone().unwrap_or_else(unknown)),
        ("build", r.build.clone().unwrap_or_else(unknown)),
        ("android", r.sdk.map_or_else(unknown, android_line)),
        (
            "patch level",
            match (&r.patch_level, r.patch_age_days) {
                (Some(p), Some(age)) if age < 0 => format!("{p} (in the future)"),
                (Some(p), Some(age)) => format!("{p} ({age} days old)"),
                _ => unknown(),
            },
        ),
        (
            "verdict",
            r.verdict.map_or_else(
                || "unknown (no security patch level)".into(),
                |v| v.label().to_uppercase(),
            ),
        ),
        (
            "partitions",
            if r.partitions.is_empty() {
                "none found (not a block OTA)".to_string()
            } else {
                r.partitions.join(", ")
            },
        ),
    ];
    Ok(rows
        .iter()
        .map(|(k, v)| format!("{k:<12}{v}"))
        .collect::<Vec<_>>()
        .join("\n"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::info;

    // 2026-10-03, so a patch of 2020-12-01 is 2132 days old
    const TODAY: i64 = 20729;

    fn meta(text: &str) -> Metadata {
        info::parse(text)
    }

    #[test]
    fn days_from_civil_matches_known_dates() {
        assert_eq!(days_from_civil(1970, 1, 1), 0);
        assert_eq!(days_from_civil(1969, 12, 31), -1);
        assert_eq!(days_from_civil(2000, 3, 1), 11017);
        assert_eq!(days_from_civil(2020, 2, 29), 18321);
        assert_eq!(days_from_civil(2020, 12, 1), 18597);
        assert_eq!(days_from_civil(2024, 2, 29), 19782);
        assert_eq!(days_from_civil(2026, 10, 3), TODAY);
    }

    #[test]
    fn patch_level_accepts_day_and_month_forms_and_rejects_junk() {
        assert_eq!(parse_patch_level("2020-12-01").unwrap(), 18597);
        assert_eq!(parse_patch_level("2020-12").unwrap(), 18597);
        // real leap days are valid, and Feb 29 really is the day before Mar 1
        for good in ["2024-02-29", "2000-02-29", "2021-04-30", "2021-01-31"] {
            assert!(parse_patch_level(good).is_ok(), "{good:?}");
        }
        assert_eq!(
            parse_patch_level("2024-03-01").unwrap() - parse_patch_level("2024-02-29").unwrap(),
            1
        );
        for bad in [
            "",
            "abc",
            "2020",
            "2020-13-01",
            "2020-00-01",
            "2020-12-32",
            "2020-12-00",
            "1969-12-31",
            "2020-12-01-05",
            "2021-02-30",
            "2021-02-31",
            "2023-02-29",
            "2100-02-29",
            "2021-04-31",
            "2021-06-31",
            "2021-09-31",
            "2021-11-31",
            "2020-+12-01",
            "2020-12-+1",
            "-2020-12-01",
        ] {
            assert!(
                parse_patch_level(bad).is_err(),
                "{bad:?} should be rejected"
            );
        }
    }

    #[test]
    fn verdict_thresholds_are_exact() {
        assert_eq!(Verdict::from_age(-30), Verdict::Ok);
        assert_eq!(Verdict::from_age(90), Verdict::Ok);
        assert_eq!(Verdict::from_age(91), Verdict::Stale);
        assert_eq!(Verdict::from_age(365), Verdict::Stale);
        assert_eq!(Verdict::from_age(366), Verdict::VeryStale);
    }

    #[test]
    fn analyze_reads_metadata_and_computes_age() {
        let m = meta(
            "pre-device=dev\npost-build=Acme/dev:9/1\npost-sdk-level=28\npost-security-patch-level=2020-12-01\n",
        );
        let r = analyze(&m, vec!["system".into()], TODAY).unwrap();
        assert_eq!(r.device.as_deref(), Some("dev"));
        assert_eq!(r.sdk, Some(28));
        assert_eq!(r.patch_age_days, Some(2132));
        assert_eq!(r.verdict, Some(Verdict::VeryStale));
        assert_eq!(r.partitions, ["system"]);
    }

    #[test]
    fn missing_fields_are_unknown_not_errors_but_malformed_ones_are() {
        let r = analyze(&meta("ota-type=BLOCK\n"), vec![], TODAY).unwrap();
        assert_eq!((r.sdk, r.patch_age_days, r.verdict), (None, None, None));
        assert!(analyze(&meta("post-sdk-level=x\n"), vec![], TODAY).is_err());
        assert!(analyze(&meta("post-security-patch-level=nope\n"), vec![], TODAY).is_err());
    }

    #[test]
    fn text_report_has_every_row_and_the_verdict() {
        let m = meta("pre-device=dev\npost-sdk-level=28\npost-security-patch-level=2020-12-01\n");
        let text = render(
            &analyze(&m, vec!["system".into(), "vendor".into()], TODAY).unwrap(),
            false,
        )
        .unwrap();
        assert!(text.contains("device      dev"), "{text}");
        assert!(
            text.contains("Android 9, SDK 28 (8 API levels behind latest known, 36)"),
            "{text}"
        );
        assert!(text.contains("2020-12-01 (2132 days old)"), "{text}");
        assert!(text.contains("verdict     VERY STALE"), "{text}");
        assert!(text.contains("system, vendor"), "{text}");
        let none = render(&analyze(&meta("x=y\n"), vec![], TODAY).unwrap(), false).unwrap();
        assert!(
            none.contains("unknown (no security patch level)") && none.contains("none found"),
            "{none}"
        );
    }

    #[test]
    fn json_report_has_machine_readable_fields() {
        let m = meta("post-sdk-level=28\npost-security-patch-level=2026-09-01\n");
        let out = render(&analyze(&m, vec!["system".into()], TODAY).unwrap(), true).unwrap();
        let v: serde_json::Value = serde_json::from_str(&out).unwrap();
        assert_eq!(v["verdict"], "ok");
        assert_eq!(v["patch_age_days"], 32);
        assert_eq!(v["android"], "9");
        assert_eq!(v["partitions"][0], "system");
        assert!(v["device"].is_null());
    }

    #[test]
    fn future_patch_level_is_reported_as_such_not_as_negative_age() {
        let m = meta("post-security-patch-level=2030-01-01\n");
        let text = render(&analyze(&m, vec![], TODAY).unwrap(), false).unwrap();
        assert!(text.contains("2030-01-01 (in the future)"), "{text}");
        assert!(!text.contains("days old"), "{text}");
    }

    #[test]
    fn unknown_sdk_has_no_android_name_and_never_underflows() {
        assert_eq!(android_name(99), None);
        assert!(android_line(99).starts_with("SDK 99 (0 API levels behind"));
    }
}
