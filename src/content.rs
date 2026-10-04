//! Streaming content scanning for firmware security indicators.
/// Skip files larger than this (2 MiB).
pub const MAX_SCAN_FILE_BYTES: u64 = 2 * 1024 * 1024;
/// Stop scanning after this many total bytes across all files (64 MiB).
pub const MAX_SCAN_TOTAL_BYTES: u64 = 64 * 1024 * 1024;

/// One indicator found inside a file's bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Hit {
    pub rule: String,
    pub severity: String,
    pub path: String,
    pub detail: String,
}

const PRIVATE_KEY_MARKERS: [&str; 4] = [
    "BEGIN RSA PRIVATE KEY",
    "BEGIN EC PRIVATE KEY",
    "BEGIN OPENSSH PRIVATE KEY",
    "BEGIN PRIVATE KEY",
];
const DEBUG_MARKERS: [&str; 2] = ["adb tcpip", "jtag"];

pub fn scan_bytes(path: &str, buf: &[u8]) -> Vec<Hit> {
    let mut out = Vec::new();
    for marker in PRIVATE_KEY_MARKERS {
        if contains(buf, marker.as_bytes()) {
            out.push(Hit {
                rule: "hardcoded_credentials".into(),
                severity: "high".into(),
                path: path.into(),
                detail: format!("contains {marker}"),
            });
        }
    }
    for m in aws_access_key_ids(buf) {
        out.push(Hit {
            rule: "cloud_credentials".into(),
            severity: "high".into(),
            path: path.into(),
            detail: format!("AWS access key id {m}"),
        });
    }
    for d in debug_endpoints(buf) {
        out.push(Hit {
            rule: "debug_endpoints".into(),
            severity: "medium".into(),
            path: path.into(),
            detail: d,
        });
    }
    out
}

fn aws_access_key_ids(buf: &[u8]) -> Vec<String> {
    let mut out = Vec::new();
    if buf.len() < 20 {
        return out;
    }
    for i in 0..=(buf.len() - 4) {
        if i + 20 > buf.len() {
            break;
        }
        if &buf[i..i + 4] == b"AKIA"
            && is_aws_key(&buf[i..i + 20])
            && let Ok(s) = std::str::from_utf8(&buf[i..i + 20])
        {
            out.push(s.to_string());
        }
    }
    out
}

fn is_aws_key(w: &[u8]) -> bool {
    if w.len() != 20 || &w[0..4] != b"AKIA" {
        return false;
    }
    w[4..]
        .iter()
        .all(|&b| b.is_ascii_uppercase() || b.is_ascii_digit())
}

fn debug_endpoints(buf: &[u8]) -> Vec<String> {
    let mut out = Vec::new();
    for marker in DEBUG_MARKERS {
        if contains(buf, marker.as_bytes()) {
            out.push(format!("debug interface marker: {marker}"));
        }
    }
    out
}

fn contains(hay: &[u8], needle: &[u8]) -> bool {
    if needle.is_empty() || hay.len() < needle.len() {
        return false;
    }
    hay.windows(needle.len()).any(|w| w == needle)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hardcoded_credentials_fires_on_private_key_markers_and_not_on_clean_text() {
        let clean = b"just a normal binary, nothing to see here";
        assert!(
            scan_bytes("x", clean).is_empty(),
            "clean text: {:?}",
            scan_bytes("x", clean)
        );

        for marker in [
            "BEGIN RSA PRIVATE KEY",
            "BEGIN EC PRIVATE KEY",
            "BEGIN OPENSSH PRIVATE KEY",
            "BEGIN PRIVATE KEY",
        ] {
            let buf = format!("some bytes {} more bytes", marker).into_bytes();
            let hits = scan_bytes("secret", &buf);
            let hc: Vec<_> = hits
                .iter()
                .filter(|h| h.rule == "hardcoded_credentials")
                .collect();
            assert_eq!(hc.len(), 1, "marker {} should fire", marker);
            assert_eq!(hc[0].detail, format!("contains {}", marker));
            assert_eq!(hc[0].severity, "high");
            assert_eq!(hc[0].path, "secret");
        }
    }

    #[test]
    fn cloud_credentials_fires_on_aws_key_id_and_not_on_short_or_lowercase() {
        let buf = b"endpoint=https://s3.amazonaws.com/AKIAIOSFODNN7EXAMPLE";
        let hits = scan_bytes("creds", buf);
        let cc: Vec<_> = hits
            .iter()
            .filter(|h| h.rule == "cloud_credentials")
            .collect();
        assert_eq!(cc.len(), 1);
        assert_eq!(cc[0].detail, "AWS access key id AKIAIOSFODNN7EXAMPLE");
        assert_eq!(cc[0].severity, "high");

        let lower = b"akiaiosfodnn7example is not a real key";
        assert!(
            scan_bytes("x", lower)
                .iter()
                .all(|h| h.rule != "cloud_credentials")
        );

        let short = b"AKIAIOSFODNN7";
        assert!(
            scan_bytes("x", short)
                .iter()
                .all(|h| h.rule != "cloud_credentials")
        );

        assert!(scan_bytes("x", b"hello world").is_empty());
    }

    #[test]
    fn debug_endpoints_fires_on_adb_tcpip_and_jtag_but_not_on_clean_text() {
        let clean = b"system property ro.secure=1";
        assert!(
            scan_bytes("x", clean).is_empty(),
            "clean: {:?}",
            scan_bytes("x", clean)
        );

        let hits = scan_bytes("diag", b"ro.debuggable=1 and adb tcpip 5555");
        let de: Vec<_> = hits
            .iter()
            .filter(|h| h.rule == "debug_endpoints")
            .collect();
        assert_eq!(de.len(), 1);
        assert_eq!(de[0].severity, "medium");
        assert!(de[0].detail.contains("adb tcpip"));

        let hits2 = scan_bytes("jtagfile", b"jtag enable");
        let de2: Vec<_> = hits2
            .iter()
            .filter(|h| h.rule == "debug_endpoints")
            .collect();
        assert_eq!(de2.len(), 1);
        assert!(de2[0].detail.contains("jtag"));
    }

    #[test]
    fn multiple_rules_fire_independently() {
        let buf = b"BEGIN RSA PRIVATE KEY here and AKIAIOSFODNN7EXAMPLE and adb tcpip";
        let hits = scan_bytes("multi", buf);
        let rules: Vec<_> = hits.iter().map(|h| h.rule.as_str()).collect();
        assert!(rules.contains(&"hardcoded_credentials"));
        assert!(rules.contains(&"cloud_credentials"));
        assert!(rules.contains(&"debug_endpoints"));
        assert_eq!(hits.len(), 3);
    }
}
