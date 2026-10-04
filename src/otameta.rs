//! What an OTA package says about itself beyond `metadata`: a summary of its `updater-script` (which
//! devices and builds it accepts, which partitions it writes and how) and its signing certificate
//! (`META-INF/com/android/otacert`, PEM or DER X.509).
//!
//! The certificate is read with a small bounds-checked DER reader (ITU-T X.690, RFC 5280); the
//! signature itself is not verified. Everything read is size-capped and nothing is executed.
use crate::detect::refuse_blocking_file;
use anyhow::{Context, Result, bail, ensure};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::fs::File;
use std::io::Read;
use std::path::Path;

const SCRIPT_PATH: &str = "META-INF/com/google/android/updater-script";
const CERT_PATH: &str = "META-INF/com/android/otacert";
/// Real scripts are a few KiB and certificates about 1 KiB; the caps bound what a hostile package costs.
const MAX_SCRIPT_BYTES: u64 = 1 << 20;
const MAX_CERT_BYTES: u64 = 1 << 16;
const MAX_STATEMENTS: usize = 200_000;
const MAX_NAME_ITEMS: usize = 64;
/// How far past a function name a call's arguments are looked for. Real calls are under 200 bytes;
/// the window keeps a hostile script of millions of `getprop(` from costing quadratic time.
const CALL_WINDOW: usize = 4096;
/// Most items of one kind a summary keeps.
const MAX_ITEMS: usize = 10_000;

/// One OTA file by its path inside the zip or directory; `None` when the package has no such file.
pub fn read_member(input: &Path, rel: &str, cap: u64) -> Result<Option<Vec<u8>>> {
    refuse_blocking_file(input)?;
    let mut buf = Vec::new();
    if input.is_dir() {
        let p = input.join(rel);
        let Ok(md) = std::fs::metadata(&p) else {
            return Ok(None);
        };
        if !md.is_file() {
            return Ok(None);
        }
        refuse_blocking_file(&p)?;
        File::open(&p)
            .with_context(|| format!("reading {}", p.display()))?
            .take(cap + 1)
            .read_to_end(&mut buf)?;
    } else {
        let f = File::open(input).with_context(|| format!("opening {}", input.display()))?;
        let mut zip = zip::ZipArchive::new(f).context("not a valid zip file")?;
        let Ok(entry) = zip.by_name(rel) else {
            return Ok(None);
        };
        entry.take(cap + 1).read_to_end(&mut buf)?;
    }
    ensure!(buf.len() as u64 <= cap, "{rel} is larger than {cap} bytes");
    Ok(Some(buf))
}

// ---------------------------------------------------------------- updater-script

#[derive(Debug, Clone, PartialEq)]
pub struct Check {
    pub property: String,
    /// `==` or `!=`
    pub op: String,
    pub value: String,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Write {
    /// `block image` (block_image_update), `raw image` (package_extract_file to a block device),
    /// or the helper that wrote it (`write_dtb_image`, ...).
    pub how: String,
    pub target: String,
    pub source: String,
}

#[derive(Debug, Clone, PartialEq, Default)]
pub struct Script {
    pub checks: Vec<Check>,
    pub writes: Vec<Write>,
    pub bootloader_env: Vec<(String, String)>,
    pub abort_codes: Vec<String>,
    pub statements: usize,
    /// Uses apply_patch, range_sha1 or block_image_verify: the package needs the previous build.
    pub incremental: bool,
}

/// `s` cut to at most `CALL_WINDOW` bytes, on a character boundary.
fn window(s: &str) -> &str {
    let mut end = s.len().min(CALL_WINDOW);
    while !s.is_char_boundary(end) {
        end -= 1;
    }
    &s[..end]
}

/// The double-quoted strings of `s` with their end offsets (`\"` and `\\` are unescaped).
fn quoted(s: &str) -> Vec<(String, usize)> {
    let b = s.as_bytes();
    let (mut out, mut i) = (Vec::new(), 0);
    while i < b.len() {
        if b[i] != b'"' {
            i += 1;
            continue;
        }
        let mut v = Vec::new();
        i += 1;
        while i < b.len() && b[i] != b'"' {
            if b[i] == b'\\' && i + 1 < b.len() {
                i += 1;
            }
            v.push(b[i]);
            i += 1;
        }
        out.push((
            String::from_utf8_lossy(&v).into_owned(),
            (i + 1).min(b.len()),
        ));
        i += 1;
    }
    out
}

/// Statements end at `;` outside quotes; `#` starts a comment line.
fn statements(text: &str) -> Vec<String> {
    let (mut out, mut cur, mut in_q, mut esc) = (Vec::new(), String::new(), false, false);
    for line in text.lines() {
        if !in_q && line.trim_start().starts_with('#') {
            continue;
        }
        for c in line.chars() {
            if in_q {
                cur.push(c);
                if esc {
                    esc = false;
                } else if c == '\\' {
                    esc = true;
                } else if c == '"' {
                    in_q = false;
                }
            } else if c == '"' {
                in_q = true;
                cur.push(c);
            } else if c == ';' {
                out.push(std::mem::take(&mut cur));
            } else {
                cur.push(c);
            }
        }
        cur.push('\n');
    }
    if !cur.trim().is_empty() {
        out.push(cur);
    }
    out
}

fn first_quote_after(s: &str, from: usize) -> Option<String> {
    quoted(window(&s[from..]))
        .into_iter()
        .next()
        .map(|(v, _)| v)
}

pub fn summarise_script(text: &str) -> Script {
    let mut sc = Script::default();
    for raw in statements(text).into_iter().take(MAX_STATEMENTS) {
        let st = raw.trim();
        if st.is_empty() {
            continue;
        }
        sc.statements += 1;
        // getprop("key") == "value" / != "value"
        let mut at = 0;
        while let Some(p) = st[at..].find("getprop(") {
            let start = at + p + "getprop(".len();
            at = start;
            let Some(prop) = first_quote_after(st, start) else {
                continue;
            };
            let Some(close) = window(&st[start..]).find(')') else {
                continue;
            };
            let rest = window(&st[start + close + 1..]).trim_start();
            let op = if rest.starts_with("==") {
                "=="
            } else if rest.starts_with("!=") {
                "!="
            } else {
                continue;
            };
            let after = &rest[2..];
            if after.trim_start().starts_with('"')
                && sc.checks.len() < MAX_ITEMS
                && let Some(value) = first_quote_after(after, 0)
            {
                sc.checks.push(Check {
                    property: prop,
                    op: op.to_string(),
                    value,
                });
            }
        }
        if let Some(p) = st.find("block_image_update(") {
            let q = quoted(window(&st[p..]));
            if let Some((target, _)) = q.first() {
                let source = q.get(2).map(|(v, _)| v.clone()).unwrap_or_default();
                sc.writes.push(Write {
                    how: "block image".into(),
                    target: target.clone(),
                    source,
                });
            }
        }
        let mut from = 0;
        while let Some(p) = st[from..].find("package_extract_file(") {
            let start = from + p;
            from = start + 1;
            let q = quoted(window(&st[start..]));
            // the second string must be the call's own second argument: only a comma between them
            let between = window(&st[start + q.first().map_or(0, |f| f.1)..]).trim_start();
            let second_arg = between
                .strip_prefix(',')
                .is_some_and(|r| r.trim_start().starts_with('"'));
            if q.len() >= 2
                && second_arg
                && q[1].0.starts_with("/dev/")
                && sc.writes.len() < MAX_ITEMS
            {
                sc.writes.push(Write {
                    how: "raw image".into(),
                    target: q[1].0.clone(),
                    source: q[0].0.clone(),
                });
            }
        }
        if let Some(p) = st.find("write_") {
            let name: String = st[p..]
                .chars()
                .take_while(|c| c.is_ascii_alphanumeric() || *c == '_')
                .collect();
            if name.ends_with("_image") && st[p + name.len()..].starts_with('(') {
                let source = first_quote_after(st, p).unwrap_or_default();
                sc.writes.push(Write {
                    how: name.clone(),
                    target: name
                        .trim_start_matches("write_")
                        .trim_end_matches("_image")
                        .to_string(),
                    source,
                });
            }
        }
        if let Some(p) = st.find("set_bootloader_env(") {
            let q = quoted(window(&st[p..]));
            if q.len() >= 2 && sc.bootloader_env.len() < MAX_ITEMS {
                sc.bootloader_env.push((q[0].0.clone(), q[1].0.clone()));
            }
        }
        if let Some(p) = st.find("abort(")
            && let Some(msg) = first_quote_after(st, p)
        {
            let code: String = msg.chars().take_while(|c| *c != ':').collect();
            if code.len() <= 8
                && code.starts_with('E')
                && code[1..].chars().all(|c| c.is_ascii_digit())
                && !sc.abort_codes.contains(&code)
            {
                sc.abort_codes.push(code);
            }
        }
        if [
            "apply_patch(",
            "range_sha1(",
            "block_image_verify(",
            "apply_patch_check(",
        ]
        .iter()
        .any(|k| st.contains(k))
        {
            sc.incremental = true;
        }
    }
    sc
}

// ---------------------------------------------------------------- certificate

#[derive(Debug, Clone, PartialEq)]
pub struct Certificate {
    pub subject: String,
    pub issuer: String,
    pub serial: String,
    pub not_before: String,
    pub not_after: String,
    pub signature_algorithm: String,
    pub key_algorithm: String,
    pub key_bits: Option<u32>,
    pub self_signed: bool,
    pub sha256: String,
}

struct Der<'a> {
    b: &'a [u8],
    p: usize,
}

impl<'a> Der<'a> {
    /// Next element as `(tag, content)`.
    fn next(&mut self) -> Result<(u8, &'a [u8])> {
        ensure!(self.p + 2 <= self.b.len(), "truncated DER element");
        let tag = self.b[self.p];
        ensure!(tag & 0x1f != 0x1f, "multi-byte DER tags are not supported");
        let l0 = self.b[self.p + 1] as usize;
        let (len, hdr) = if l0 < 0x80 {
            (l0, 2)
        } else {
            let n = l0 & 0x7f;
            ensure!((1..=4).contains(&n), "unsupported DER length form");
            ensure!(self.p + 2 + n <= self.b.len(), "truncated DER length");
            let len = self.b[self.p + 2..self.p + 2 + n]
                .iter()
                .fold(0usize, |a, x| (a << 8) | *x as usize);
            (len, 2 + n)
        };
        let end = (self.p + hdr)
            .checked_add(len)
            .filter(|e| *e <= self.b.len());
        let end = end.context("a DER element runs past its parent")?;
        let content = &self.b[self.p + hdr..end];
        self.p = end;
        Ok((tag, content))
    }

    fn done(&self) -> bool {
        self.p >= self.b.len()
    }

    fn expect(&mut self, tag: u8, what: &str) -> Result<&'a [u8]> {
        let (t, c) = self.next()?;
        ensure!(
            t == tag,
            "expected {what} (tag {tag:#04x}), found tag {t:#04x}"
        );
        Ok(c)
    }
}

fn oid_text(b: &[u8]) -> String {
    let mut parts: Vec<u64> = Vec::new();
    let mut v: u64 = 0;
    for x in b {
        v = (v << 7) | (*x & 0x7f) as u64;
        if x & 0x80 == 0 {
            if parts.is_empty() {
                let (a, c) = if v < 80 {
                    (v / 40, v % 40)
                } else {
                    (2, v - 80)
                };
                parts.extend([a, c]);
            } else {
                parts.push(v);
            }
            v = 0;
        } else if v > (u64::MAX >> 8) {
            break;
        }
    }
    parts
        .iter()
        .map(u64::to_string)
        .collect::<Vec<_>>()
        .join(".")
}

fn name_of_oid(oid: &str) -> String {
    match oid {
        "2.5.4.3" => "CN",
        "2.5.4.6" => "C",
        "2.5.4.7" => "L",
        "2.5.4.8" => "ST",
        "2.5.4.10" => "O",
        "2.5.4.11" => "OU",
        "2.5.4.5" => "serialNumber",
        "1.2.840.113549.1.9.1" => "emailAddress",
        "0.9.2342.19200300.100.1.25" => "DC",
        other => other,
    }
    .to_string()
}

fn signature_name(oid: &str) -> String {
    match oid {
        "1.2.840.113549.1.1.4" => "md5WithRSAEncryption",
        "1.2.840.113549.1.1.5" => "sha1WithRSAEncryption",
        "1.2.840.113549.1.1.11" => "sha256WithRSAEncryption",
        "1.2.840.113549.1.1.12" => "sha384WithRSAEncryption",
        "1.2.840.113549.1.1.13" => "sha512WithRSAEncryption",
        "1.2.840.10045.4.1" => "ecdsa-with-SHA1",
        "1.2.840.10045.4.3.2" => "ecdsa-with-SHA256",
        "1.2.840.10045.4.3.3" => "ecdsa-with-SHA384",
        "1.2.840.10045.4.3.4" => "ecdsa-with-SHA512",
        "1.3.101.112" => "ED25519",
        other => other,
    }
    .to_string()
}

/// `C=CN, ST=...`: the relative distinguished names in order, as `openssl x509 -subject` prints them.
fn parse_name(content: &[u8]) -> Result<String> {
    let mut parts = Vec::new();
    let mut outer = Der { b: content, p: 0 };
    while !outer.done() {
        ensure!(
            parts.len() < MAX_NAME_ITEMS,
            "a certificate name has too many parts"
        );
        let set = outer.expect(0x31, "a name component set")?;
        let mut inner = Der { b: set, p: 0 };
        while !inner.done() {
            let atv = inner.expect(0x30, "a name attribute")?;
            let mut a = Der { b: atv, p: 0 };
            let oid = oid_text(a.expect(0x06, "an attribute OID")?);
            let (_, v) = a.next()?;
            parts.push(format!(
                "{}={}",
                name_of_oid(&oid),
                String::from_utf8_lossy(v)
            ));
        }
    }
    Ok(parts.join(", "))
}

fn parse_time(tag: u8, c: &[u8]) -> Result<String> {
    let s = std::str::from_utf8(c).context("a certificate date is not text")?;
    ensure!(
        s.ends_with('Z') && s[..s.len() - 1].bytes().all(|b| b.is_ascii_digit()),
        "unsupported certificate date {s:?}"
    );
    let d = &s[..s.len() - 1];
    let (year, rest) = match (tag, d.len()) {
        (0x17, 12) => {
            let yy: u32 = d[..2].parse()?;
            (if yy < 50 { 2000 + yy } else { 1900 + yy }, &d[2..])
        }
        (0x18, 14) => (d[..4].parse()?, &d[4..]),
        _ => bail!("unsupported certificate date {s:?}"),
    };
    let f = |i: usize| rest[i..i + 2].parse::<u32>();
    let (mo, da, h, mi, se) = (f(0)?, f(2)?, f(4)?, f(6)?, f(8)?);
    ensure!(
        (1..=12).contains(&mo) && (1..=31).contains(&da) && h < 24 && mi < 60 && se < 61,
        "impossible certificate date {s:?}"
    );
    Ok(format!("{year:04}-{mo:02}-{da:02}T{h:02}:{mi:02}:{se:02}Z"))
}

fn bit_length(int: &[u8]) -> u32 {
    let n = int.iter().position(|b| *b != 0).unwrap_or(int.len());
    let rest = &int[n..];
    match rest.first() {
        None => 0,
        Some(f) => (rest.len() as u32 - 1) * 8 + (8 - f.leading_zeros()),
    }
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02X}")).collect()
}

pub fn parse_certificate(der: &[u8]) -> Result<Certificate> {
    let mut top = Der { b: der, p: 0 };
    let cert = top.expect(0x30, "a certificate")?;
    ensure!(top.done(), "trailing bytes after the certificate");
    let mut c = Der { b: cert, p: 0 };
    let tbs = c.expect(0x30, "the certificate body")?;
    let sig_alg = c.expect(0x30, "the signature algorithm")?;
    let mut t = Der { b: tbs, p: 0 };
    let (mut tag, mut item) = t.next()?;
    if tag == 0xa0 {
        (tag, item) = t.next()?; // skip the explicit version
    }
    ensure!(tag == 0x02, "expected the serial number");
    ensure!(
        !item.is_empty() && item.len() <= 32,
        "the serial number has an impossible length"
    );
    let serial = hex(if item.len() > 1 && item[0] == 0 {
        &item[1..]
    } else {
        item
    });
    t.expect(0x30, "the inner signature algorithm")?;
    let issuer = parse_name(t.expect(0x30, "the issuer")?)?;
    let validity = t.expect(0x30, "the validity")?;
    let mut v = Der { b: validity, p: 0 };
    let (t1, b1) = v.next()?;
    let (t2, b2) = v.next()?;
    let (not_before, not_after) = (parse_time(t1, b1)?, parse_time(t2, b2)?);
    let subject = parse_name(t.expect(0x30, "the subject")?)?;
    let spki = t.expect(0x30, "the public key info")?;
    let mut s = Der { b: spki, p: 0 };
    let alg = s.expect(0x30, "the key algorithm")?;
    let bits = s.expect(0x03, "the public key")?;
    let mut a = Der { b: alg, p: 0 };
    let key_oid = oid_text(a.expect(0x06, "the key algorithm OID")?);
    let (key_algorithm, key_bits) = match key_oid.as_str() {
        "1.2.840.113549.1.1.1" => {
            ensure!(bits.len() > 1, "an empty RSA key");
            let mut k = Der {
                b: &bits[1..],
                p: 0,
            };
            let seq = k.expect(0x30, "the RSA key")?;
            let mut kk = Der { b: seq, p: 0 };
            (
                "rsaEncryption".to_string(),
                Some(bit_length(kk.expect(0x02, "the RSA modulus")?)),
            )
        }
        "1.2.840.10045.2.1" => {
            let curve = oid_text(a.expect(0x06, "the curve OID")?);
            match curve.as_str() {
                "1.2.840.10045.3.1.7" => ("id-ecPublicKey (prime256v1)".to_string(), Some(256)),
                "1.3.132.0.34" => ("id-ecPublicKey (secp384r1)".to_string(), Some(384)),
                "1.3.132.0.35" => ("id-ecPublicKey (secp521r1)".to_string(), Some(521)),
                other => (format!("id-ecPublicKey ({other})"), None),
            }
        }
        "1.3.101.112" => ("ED25519".to_string(), Some(256)),
        other => (other.to_string(), None),
    };
    let mut sa = Der { b: sig_alg, p: 0 };
    let signature_algorithm = signature_name(&oid_text(sa.expect(0x06, "the signature OID")?));
    Ok(Certificate {
        self_signed: subject == issuer,
        subject,
        issuer,
        serial,
        not_before,
        not_after,
        signature_algorithm,
        key_algorithm,
        key_bits,
        sha256: hex(&Sha256::digest(der)),
    })
}

fn base64(s: &str) -> Result<Vec<u8>> {
    let (mut out, mut acc, mut n) = (Vec::new(), 0u32, 0);
    for c in s.bytes().filter(|c| !c.is_ascii_whitespace()) {
        let v = match c {
            b'A'..=b'Z' => c - b'A',
            b'a'..=b'z' => c - b'a' + 26,
            b'0'..=b'9' => c - b'0' + 52,
            b'+' => 62,
            b'/' => 63,
            b'=' => break,
            _ => bail!("not valid base64"),
        };
        acc = (acc << 6) | v as u32;
        n += 6;
        if n >= 8 {
            n -= 8;
            out.push((acc >> n) as u8);
            acc &= (1 << n) - 1;
        }
    }
    Ok(out)
}

/// PEM (`-----BEGIN CERTIFICATE-----`) or raw DER.
pub fn read_certificate(bytes: &[u8]) -> Result<Certificate> {
    if let Ok(text) = std::str::from_utf8(bytes)
        && let Some(start) = text.find("-----BEGIN CERTIFICATE-----")
    {
        let body = &text[start + 27..];
        let end = body
            .find("-----END CERTIFICATE-----")
            .context("the PEM certificate has no end line")?;
        return parse_certificate(&base64(&body[..end])?);
    }
    parse_certificate(bytes)
}

/// Days from 1970-01-01 for a proleptic Gregorian date (Hinnant's algorithm).
fn days_from_civil(y: i64, m: i64, d: i64) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let doy = (153 * (m + if m > 2 { -3 } else { 9 }) + 2) / 5 + d - 1;
    era * 146_097 + yoe * 365 + yoe / 4 - yoe / 100 + doy - 719_468
}

/// Unix seconds of an ISO time produced by `parse_time`.
pub fn unix_of(iso: &str) -> Option<i64> {
    let n = |a: usize, b: usize| iso.get(a..b)?.parse::<i64>().ok();
    Some(
        days_from_civil(n(0, 4)?, n(5, 7)?, n(8, 10)?) * 86_400
            + n(11, 13)? * 3600
            + n(14, 16)? * 60
            + n(17, 19)?,
    )
}

impl Certificate {
    /// Concerns about the certificate at `now` (Unix seconds).
    pub fn concerns(&self, now: i64) -> Vec<String> {
        let mut out = Vec::new();
        if unix_of(&self.not_after).is_some_and(|t| t < now) {
            out.push(format!("expired on {}", self.not_after));
        }
        if unix_of(&self.not_before).is_some_and(|t| t > now) {
            out.push(format!("not valid before {}", self.not_before));
        }
        let sig = self.signature_algorithm.to_lowercase();
        if sig.starts_with("md5") || sig.contains("sha1") {
            out.push(format!(
                "weak signature algorithm {}",
                self.signature_algorithm
            ));
        }
        if self.key_algorithm == "rsaEncryption" && self.key_bits.is_some_and(|b| b < 2048) {
            out.push(format!(
                "RSA key of only {} bits",
                self.key_bits.unwrap_or(0)
            ));
        }
        out
    }
}

// ---------------------------------------------------------------- report

#[derive(Debug, Default)]
pub struct Details {
    pub script: Option<Script>,
    pub certificate: Option<Certificate>,
    pub certificate_error: Option<String>,
}

pub fn read_details(input: &Path) -> Result<Details> {
    let script = read_member(input, SCRIPT_PATH, MAX_SCRIPT_BYTES)?
        .map(|b| summarise_script(&String::from_utf8_lossy(&b)));
    let mut d = Details {
        script,
        ..Default::default()
    };
    if let Some(bytes) = read_member(input, CERT_PATH, MAX_CERT_BYTES)? {
        match read_certificate(&bytes) {
            Ok(c) => d.certificate = Some(c),
            Err(e) => d.certificate_error = Some(format!("{e:#}")),
        }
    }
    Ok(d)
}

impl Details {
    pub fn to_json(&self, now: i64) -> Value {
        json!({
            "updater_script": self.script.as_ref().map(|s| json!({
                "statements": s.statements,
                "incremental": s.incremental,
                "device_checks": s.checks.iter().map(|c| json!({"property": c.property, "op": c.op, "value": c.value})).collect::<Vec<_>>(),
                "writes": s.writes.iter().map(|w| json!({"how": w.how, "target": w.target, "source": w.source})).collect::<Vec<_>>(),
                "bootloader_env": s.bootloader_env.iter().map(|(k, v)| json!({"key": k, "value": v})).collect::<Vec<_>>(),
                "abort_codes": s.abort_codes,
            })),
            "certificate": self.certificate.as_ref().map(|c| json!({
                "subject": c.subject, "issuer": c.issuer, "serial": c.serial,
                "not_before": c.not_before, "not_after": c.not_after,
                "signature_algorithm": c.signature_algorithm, "key_algorithm": c.key_algorithm,
                "key_bits": c.key_bits, "self_signed": c.self_signed, "sha256": c.sha256,
                "concerns": c.concerns(now),
            })),
            "certificate_error": self.certificate_error,
        })
    }

    pub fn to_text(&self, now: i64) -> String {
        let mut o = Vec::new();
        match &self.script {
            None => o.push("updater-script: not in the package".to_string()),
            Some(s) => {
                o.push(format!(
                    "updater-script: {} statements{}",
                    s.statements,
                    if s.incremental {
                        ", incremental (needs the previous build)"
                    } else {
                        ", full package"
                    }
                ));
                for c in &s.checks {
                    o.push(format!("  requires {} {} {:?}", c.property, c.op, c.value));
                }
                for w in &s.writes {
                    o.push(format!("  writes {} -> {} ({})", w.source, w.target, w.how));
                }
                for (k, v) in &s.bootloader_env {
                    o.push(format!("  sets bootloader env {k}={v}"));
                }
                if !s.abort_codes.is_empty() {
                    o.push(format!("  abort codes: {}", s.abort_codes.join(", ")));
                }
            }
        }
        match (&self.certificate, &self.certificate_error) {
            (Some(c), _) => {
                o.push("signing certificate:".to_string());
                o.push(format!("  subject    {}", c.subject));
                o.push(format!(
                    "  issuer     {}{}",
                    c.issuer,
                    if c.self_signed { " (self-signed)" } else { "" }
                ));
                o.push(format!("  serial     {}", c.serial));
                o.push(format!("  valid      {} to {}", c.not_before, c.not_after));
                o.push(format!(
                    "  key        {}{}, signed with {}",
                    c.key_algorithm,
                    c.key_bits.map(|b| format!(" {b} bits")).unwrap_or_default(),
                    c.signature_algorithm
                ));
                o.push(format!("  sha256     {}", c.sha256));
                for w in c.concerns(now) {
                    o.push(format!("  concern    {w}"));
                }
            }
            (None, Some(e)) => o.push(format!("signing certificate: unreadable ({e})")),
            (None, None) => o.push("signing certificate: not in the package".to_string()),
        }
        o.join("\n")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const RSA_PEM: &str = "-----BEGIN CERTIFICATE-----
MIIEFTCCAv2gAwIBAgIUeg73jOdcl9dBVhSu47Bb0jiltgUwDQYJKoZIhvcNAQEL
BQAwgZkxCzAJBgNVBAYTAlVTMRMwEQYDVQQIDApUZXN0IFN0YXRlMRIwEAYDVQQH
DAlUZXN0IENpdHkxFDASBgNVBAoMC0V4YW1wbGUgT3JnMREwDwYDVQQLDAhGaXJt
d2FyZTEYMBYGA1UEAwwPRXhhbXBsZSBUZXN0IENBMR4wHAYJKoZIhvcNAQkBFg9j
YUBleGFtcGxlLnRlc3QwHhcNMjYxMDAzMDg0NTM4WhcNMzYwOTMwMDg0NTM4WjCB
mTELMAkGA1UEBhMCVVMxEzARBgNVBAgMClRlc3QgU3RhdGUxEjAQBgNVBAcMCVRl
c3QgQ2l0eTEUMBIGA1UECgwLRXhhbXBsZSBPcmcxETAPBgNVBAsMCEZpcm13YXJl
MRgwFgYDVQQDDA9FeGFtcGxlIFRlc3QgQ0ExHjAcBgkqhkiG9w0BCQEWD2NhQGV4
YW1wbGUudGVzdDCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBALCs9Exi
aKR4opFwNG3XPjS7KbL8wdH79ZtZZ+TB9ORkq8YjvjN/Lu2lKo6pb+MZcq50iUWC
CgA0T/IREHgr5U+i4mqrxNvqaCd2B5U3eg4jbnAbRw5kovrGjeQKcdca3lboGOFD
2rcA3qZ6Mh0RvCHxIgRiWPcurQDblVRV5l+oag7VdEUA9aYvOgYOnbIvGR/DrD9c
dWHtANpmCA4N1tyU48SwVXO99i4kC7y3KbTl7ElCFhH3LSI4UATtDI3bdB90cxsc
m/Tsg1/vnYZ0gWXbMr58IeMkabhoyminKIl7ZP4u31k6MKP3LU1cVUZoMk4vCJzj
8oUmJwSFaHdh6ScCAwEAAaNTMFEwHQYDVR0OBBYEFPmvzmwHAyr2kSP7J4AMJbKN
eEyCMB8GA1UdIwQYMBaAFPmvzmwHAyr2kSP7J4AMJbKNeEyCMA8GA1UdEwEB/wQF
MAMBAf8wDQYJKoZIhvcNAQELBQADggEBAJstE3YEOGQGs/ww86m/freiD6f6pmEW
twMrFvoishI3t6IY73lLIDC/yB5M0/DqG9pxxRfaI2hDS2XNvcHBRTQnaAktFuit
C+V3ay/GY7FY97Arw21XoiLU3sqyTiKxdoFfMJgKXsum8jZtKCC+rqFHenvOoTmu
LM5pQmpUuXnDGfrVpqgnih9pQw1pNOK9FrXWSDVCVWUWlJumf6Pbwiwyqj/PB2EL
tSCHRV348wg3gB7LOM1b2OaacwHMzyV//JQvphMpKNGLY3mzkDD4iFjqtgwYcp0B
t97C+SC+TICOPa/y1IXpIhNd6iezIJYkW9s45OG8qgUe2ww3iUQaBsk=
-----END CERTIFICATE-----";
    const EC_PEM: &str = "-----BEGIN CERTIFICATE-----
MIIBujCCAV+gAwIBAgIUJCkJj1olGS7jNyW45KmAQme+DMAwCgYIKoZIzj0EAwIw
MjEaMBgGA1UEAwwRRXhhbXBsZSBFQyBTaWduZXIxFDASBgNVBAoMC0V4YW1wbGUg
T3JnMB4XDTI2MTAwMzA4NDUzOFoXDTI3MTAwMzA4NDUzOFowMjEaMBgGA1UEAwwR
RXhhbXBsZSBFQyBTaWduZXIxFDASBgNVBAoMC0V4YW1wbGUgT3JnMFkwEwYHKoZI
zj0CAQYIKoZIzj0DAQcDQgAElVZ7VzEMF6N3I6sSfw5GNYfW9bBKZs7dT6/WiqAC
NTTDddDPpelO3vKrzZC0owREK/xAuKn8SG7fUpKQ116LCaNTMFEwHQYDVR0OBBYE
FOC322t5spkE3rPTragPdwkSl7geMB8GA1UdIwQYMBaAFOC322t5spkE3rPTragP
dwkSl7geMA8GA1UdEwEB/wQFMAMBAf8wCgYIKoZIzj0EAwIDSQAwRgIhALNNFKkA
GYgAoGDVZ0ee25LesNhq3rYFDDbP75JQtNnoAiEA9cIip1VhNX7LGvycJ/ndmBcS
B6xCM29vWkMoW8nuW98=
-----END CERTIFICATE-----";
    const WEAK_PEM: &str = "-----BEGIN CERTIFICATE-----
MIICNDCCAZ2gAwIBAgIUKJgJfnRrBMTw6wjLsAIIqScF9o4wDQYJKoZIhvcNAQEF
BQAwLDEUMBIGA1UEAwwLV2VhayBMZWdhY3kxFDASBgNVBAoMC0V4YW1wbGUgT3Jn
MB4XDTI2MTAwMzA4NDUzOFoXDTI3MDExMTA4NDUzOFowLDEUMBIGA1UEAwwLV2Vh
ayBMZWdhY3kxFDASBgNVBAoMC0V4YW1wbGUgT3JnMIGfMA0GCSqGSIb3DQEBAQUA
A4GNADCBiQKBgQDUYBHHCMdVSgTovJ7BrI2jZFHV7iLPcA0ZPCr5Tw2Wv1zSzmXa
AGT+TDLywPqOyH+9+W9K0CyyfjCiJ/dRDkAeUug+7ICq6EG0iA2/W+n8A2o6cMqk
nSqMw5UlhX//tYeaYHH8heaw14RwUPouO1SIxel7aGGvrpuIrYJdzGw8IQIDAQAB
o1MwUTAdBgNVHQ4EFgQUlLKyBUh8abhK5CKswDlVbpraEy4wHwYDVR0jBBgwFoAU
lLKyBUh8abhK5CKswDlVbpraEy4wDwYDVR0TAQH/BAUwAwEB/zANBgkqhkiG9w0B
AQUFAAOBgQCuq0YYlUuK4V6vtwi0PE3u4cYVfN8BAhaKiN0pqT19s7tSuNx1PTvT
rDpmMf+RjbX181/NKURRdFIAhSGT/nBApDGtqRoVqFI2Fv+vwQjKJQhWl8/FTLEl
nyfV/SbtScCWMXEeo+Eh3v1oQVS4Wgs9O7694sAOvkit3gzIKsejFw==
-----END CERTIFICATE-----";

    const SCRIPT: &str = r#"getprop("ro.product.device") == "acme" || abort("E3004: This package is for \"acme\" devices; this is a \"" + getprop("ro.product.device") + "\".");
# a comment; with a semicolon
if ota_zip_check() == "1" then
set_bootloader_env("upgrade_step", "3");
write_dtb_image(package_extract_file("dt.img"));
package_extract_file("recovery.img", "/dev/block/recovery");
write_bootloader_image(package_extract_file("bootloader.img"));
else
ui_print("Target: Acme/acme/acme:9/1.0/1:user/release-keys");
block_image_update("/dev/block/system", package_extract_file("system.transfer.list"), "system.new.dat.br", "system.patch.dat") ||
  abort("E1001: Failed to update system image.");
block_image_update("/dev/block/vendor", package_extract_file("vendor.transfer.list"), "vendor.new.dat.br", "vendor.patch.dat") ||
  abort("E2001: Failed to update vendor image.");
package_extract_file("boot.img", "/dev/block/boot");
endif;
"#;

    #[test]
    fn the_updater_script_is_summarised() {
        let s = summarise_script(SCRIPT);
        assert_eq!(
            s.checks,
            [Check {
                property: "ro.product.device".into(),
                op: "==".into(),
                value: "acme".into()
            }]
        );
        let w = |how: &str, target: &str, source: &str| Write {
            how: how.into(),
            target: target.into(),
            source: source.into(),
        };
        assert_eq!(
            s.writes,
            [
                w("write_dtb_image", "dtb", "dt.img"),
                w("raw image", "/dev/block/recovery", "recovery.img"),
                w("write_bootloader_image", "bootloader", "bootloader.img"),
                w("block image", "/dev/block/system", "system.new.dat.br"),
                w("block image", "/dev/block/vendor", "vendor.new.dat.br"),
                w("raw image", "/dev/block/boot", "boot.img"),
            ]
        );
        assert_eq!(
            s.bootloader_env,
            [("upgrade_step".to_string(), "3".to_string())]
        );
        assert_eq!(s.abort_codes, ["E3004", "E1001", "E2001"]);
        assert!(!s.incremental);
        assert!(s.statements >= 9, "{}", s.statements);
    }

    #[test]
    fn checks_need_a_getprop_comparison_with_a_quoted_value() {
        let s = summarise_script(
            r#"getprop("a.b") == "x" || getprop("c.d") != "y" || getprop("e.f") == other || getprop("g.h") > "z";
               assert(getprop("ro.build.fingerprint") == "Acme/a/a:9/1/1:user/release-keys");"#,
        );
        let got: Vec<_> = s
            .checks
            .iter()
            .map(|c| (c.property.as_str(), c.op.as_str(), c.value.as_str()))
            .collect();
        assert_eq!(
            got,
            [
                ("a.b", "==", "x"),
                ("c.d", "!=", "y"),
                (
                    "ro.build.fingerprint",
                    "==",
                    "Acme/a/a:9/1/1:user/release-keys"
                )
            ]
        );
    }

    #[test]
    fn a_raw_write_needs_its_own_second_argument() {
        let s = summarise_script(
            r#"package_extract_file("a.img", "/dev/block/a");
               package_extract_file("b.img"); ui_print("/dev/block/not_a_target");
               x(package_extract_file("c.img"), "/dev/block/c");
               package_extract_file("d.img",
                  "/dev/block/d");"#,
        );
        let got: Vec<_> = s
            .writes
            .iter()
            .map(|w| (w.source.as_str(), w.target.as_str()))
            .collect();
        assert_eq!(got, [("a.img", "/dev/block/a"), ("d.img", "/dev/block/d")]);
    }

    #[test]
    fn a_raw_write_target_must_be_a_device_path() {
        let s = summarise_script(
            r#"package_extract_file("ok.img", "/dev/block/ok");
               package_extract_file("x.img", "not_a_device");
               package_extract_file("y.img", "/devish/nope");"#,
        );
        let got: Vec<_> = s
            .writes
            .iter()
            .map(|w| (w.source.as_str(), w.target.as_str()))
            .collect();
        assert_eq!(got, [("ok.img", "/dev/block/ok")]);
    }

    #[test]
    fn escaped_quotes_and_backslashes_inside_strings_are_unescaped_not_terminators() {
        let s = summarise_script(
            r#"package_extract_file("a\"b.img", "/dev/block/a");
               package_extract_file("c\\d.img", "/dev/block/c");"#,
        );
        let got: Vec<_> = s
            .writes
            .iter()
            .map(|w| (w.source.as_str(), w.target.as_str()))
            .collect();
        assert_eq!(
            got,
            [("a\"b.img", "/dev/block/a"), ("c\\d.img", "/dev/block/c")]
        );
    }

    #[test]
    fn incremental_scripts_are_recognised() {
        for call in [
            "apply_patch(\"x\", \"y\", 1)",
            "range_sha1(\"/dev/block/system\", \"2,0,1\")",
            "block_image_verify(\"/dev/block/system\", x)",
            "apply_patch_check(\"x\")",
        ] {
            assert!(summarise_script(&format!("{call};")).incremental, "{call}");
        }
        assert!(!summarise_script("ui_print(\"apply_patch is not a call\");").incremental);
    }

    #[test]
    fn quotes_comments_and_odd_scripts_do_not_confuse_the_reader() {
        assert_eq!(
            quoted(r#"a "b\"c" d "e""#)
                .iter()
                .map(|(v, _)| v.as_str())
                .collect::<Vec<_>>(),
            ["b\"c", "e"]
        );
        assert_eq!(quoted("\"unterminated").len(), 1);
        let st = statements("a(\"x;y\");\n# skipped; text\nb();");
        assert_eq!(st.len(), 2);
        assert!(st[0].contains("x;y"));
        let empty = summarise_script("");
        assert_eq!(
            (empty.statements, empty.writes.len(), empty.checks.len()),
            (0, 0, 0)
        );
        let junk = summarise_script(
            "\"\"\"((( ;;; getprop( ; package_extract_file( ; write_ ; abort( ; block_image_update(",
        );
        assert!(junk.writes.is_empty() && junk.checks.is_empty());
        let not_code = summarise_script("abort(\"hello: world\"); abort(\"E9999999999: long\");");
        assert!(
            not_code.abort_codes.is_empty(),
            "only short E-numbers are error codes"
        );
    }

    #[test]
    fn a_hostile_script_cannot_make_the_scan_quadratic() {
        for call in [
            "getprop(\"a\") == \"b\" || ",
            "package_extract_file(\"a\", ",
            "getprop(",
            "block_image_update(\"/dev/x\", ",
        ] {
            let script = format!("{};", call.repeat(40_000));
            let s = summarise_script(&script);
            assert!(
                s.checks.len() <= MAX_ITEMS && s.writes.len() <= MAX_ITEMS,
                "{call}"
            );
        }
        // Complexity: a genuine O(n^2) regression would make the large input take far
        // longer than a small one relative to its size.
        //
        // Note on the threshold: the input grows exactly 40x, so a *linear* implementation
        // produces a ratio of about 40x. Asserting strictly below 40x would therefore fail
        // correct code and only pass by accident, when fixed per-run overhead inflates the
        // smaller measurement. The ceiling below sits between the two regimes:
        //
        //     linear     ~40x
        //     quadratic ~1600x
        //     asserted   <200x   (5x headroom over linear, 8x below quadratic)
        //
        // so a real complexity regression is caught while ordinary timing jitter is not.
        let probe: &str = "getprop(\"a\") == \"b\" || ";
        let small = format!("{};", probe.repeat(1_000));
        let large = format!("{};", probe.repeat(40_000));
        // The smallest measurement is the most robust under scheduler noise, so run the
        // small case a few times and keep its minimum.
        let mut small_elapsed = std::time::Duration::MAX;
        for _ in 0..3 {
            let t = std::time::Instant::now();
            summarise_script(&small);
            small_elapsed = small_elapsed.min(t.elapsed());
        }
        let t1 = std::time::Instant::now();
        summarise_script(&large);
        let large_elapsed = t1.elapsed();
        let ratio = large_elapsed.as_secs_f64() / small_elapsed.as_secs_f64().max(1e-6);
        assert!(
            ratio < 200.0,
            "scan scaling is super-linear: small {small_elapsed:?} vs large {large_elapsed:?}, \
             ratio {:.1}x for an input that grew 40x (linear ~40x, quadratic ~1600x)",
            ratio
        );
    }

    #[test]
    fn the_number_of_items_kept_is_bounded() {
        let many = format!("{};", "getprop(\"a\") == \"b\" || ".repeat(MAX_ITEMS + 500));
        assert_eq!(summarise_script(&many).checks.len(), MAX_ITEMS);
        let writes = "package_extract_file(\"a\", \"/dev/b\"); ".repeat(MAX_ITEMS + 500);
        assert_eq!(summarise_script(&writes).writes.len(), MAX_ITEMS);
        let envs = "set_bootloader_env(\"k\", \"v\"); ".repeat(MAX_ITEMS + 500);
        assert_eq!(summarise_script(&envs).bootloader_env.len(), MAX_ITEMS);
    }

    #[test]
    fn an_argument_window_never_splits_a_character() {
        let long = format!("{}é", "x".repeat(CALL_WINDOW - 1));
        assert_eq!(window(&long).len(), CALL_WINDOW - 1);
        assert_eq!(window("short"), "short");
        let ok = summarise_script(&format!(
            "block_image_update(\"/dev/{}\");",
            "é".repeat(3000)
        ));
        assert!(ok.writes.is_empty() || ok.writes[0].target.starts_with("/dev/"));
    }

    #[test]
    fn the_script_statement_count_is_bounded() {
        let many = "a();".repeat(MAX_STATEMENTS + 50);
        assert_eq!(summarise_script(&many).statements, MAX_STATEMENTS);
    }

    #[test]
    fn an_rsa_certificate_is_read_completely() {
        let c = read_certificate(RSA_PEM.as_bytes()).unwrap();
        assert_eq!(
            c.subject,
            "C=US, ST=Test State, L=Test City, O=Example Org, OU=Firmware, CN=Example Test CA, emailAddress=ca@example.test"
        );
        assert_eq!(c.issuer, c.subject);
        assert!(c.self_signed);
        assert_eq!(c.serial, "7A0EF78CE75C97D7415614AEE3B05BD238A5B605");
        assert_eq!(
            (c.not_before.as_str(), c.not_after.as_str()),
            ("2026-10-03T08:45:38Z", "2036-09-30T08:45:38Z")
        );
        assert_eq!(
            (
                c.signature_algorithm.as_str(),
                c.key_algorithm.as_str(),
                c.key_bits
            ),
            ("sha256WithRSAEncryption", "rsaEncryption", Some(2048))
        );
        assert_eq!(
            c.sha256,
            "0FFF7FE7609A6F01080B47AA217B6ADA1C0AA5EE34D63331 94439A99E036CAFA".replace(' ', "")
        );
    }

    #[test]
    fn an_ec_certificate_and_a_weak_one_are_read_and_flagged() {
        let ec = read_certificate(EC_PEM.as_bytes()).unwrap();
        assert_eq!(ec.subject, "CN=Example EC Signer, O=Example Org");
        assert_eq!(
            (
                ec.signature_algorithm.as_str(),
                ec.key_algorithm.as_str(),
                ec.key_bits
            ),
            (
                "ecdsa-with-SHA256",
                "id-ecPublicKey (prime256v1)",
                Some(256)
            )
        );
        assert_eq!(ec.serial, "2429098F5A25192EE33725B8E4A9804267BE0CC0");
        assert!(
            ec.concerns(unix_of("2027-01-01T00:00:00Z").unwrap())
                .is_empty()
        );
        let weak = read_certificate(WEAK_PEM.as_bytes()).unwrap();
        assert_eq!(
            (weak.signature_algorithm.as_str(), weak.key_bits),
            ("sha1WithRSAEncryption", Some(1024))
        );
        assert_eq!(weak.not_after, "2027-01-11T08:45:38Z");
        let c = weak.concerns(unix_of("2026-12-01T00:00:00Z").unwrap());
        assert_eq!(c.len(), 2, "{c:?}");
        assert!(
            c.iter()
                .any(|x| x.contains("weak signature algorithm sha1WithRSAEncryption"))
                && c.iter().any(|x| x.contains("1024 bits"))
        );
        let late = ec.concerns(unix_of("2027-10-04T00:00:00Z").unwrap());
        assert_eq!(late, ["expired on 2027-10-03T08:45:38Z"]);
        let early = ec.concerns(unix_of("2026-01-01T00:00:00Z").unwrap());
        assert_eq!(early, ["not valid before 2026-10-03T08:45:38Z"]);
    }

    #[test]
    fn pem_and_der_inputs_give_the_same_certificate() {
        let der = base64(
            &RSA_PEM
                .lines()
                .filter(|l| !l.starts_with("-----"))
                .collect::<String>(),
        )
        .unwrap();
        assert_eq!(
            read_certificate(&der).unwrap(),
            read_certificate(RSA_PEM.as_bytes()).unwrap()
        );
        let padded = format!("junk before\n{}\ntrailing text", RSA_PEM);
        assert_eq!(
            read_certificate(padded.as_bytes()).unwrap().serial,
            "7A0EF78CE75C97D7415614AEE3B05BD238A5B605"
        );
        let cut = RSA_PEM.replace("-----END CERTIFICATE-----", "");
        assert!(
            format!("{:#}", read_certificate(cut.as_bytes()).unwrap_err()).contains("no end line")
        );
        assert!(
            read_certificate(b"-----BEGIN CERTIFICATE-----\n!!!\n-----END CERTIFICATE-----")
                .is_err()
        );
        assert!(read_certificate(b"").is_err());
        assert!(read_certificate(b"not a certificate").is_err());
        let mut trailing = der.clone();
        trailing.push(0);
        assert!(format!("{:#}", parse_certificate(&trailing).unwrap_err()).contains("trailing"));
    }

    #[test]
    fn every_truncation_and_many_byte_flips_of_a_certificate_are_errors_not_panics() {
        for pem in [RSA_PEM, EC_PEM, WEAK_PEM] {
            let der = base64(
                &pem.lines()
                    .filter(|l| !l.starts_with("-----"))
                    .collect::<String>(),
            )
            .unwrap();
            for n in 0..der.len() {
                assert!(parse_certificate(&der[..n]).is_err(), "cut at {n}");
            }
            let (mut ok, mut err) = (0, 0);
            for at in 0..der.len().min(400) {
                for v in [0x00u8, 0xFF, 0x30, 0x80] {
                    let mut w = der.clone();
                    w[at] = v;
                    match parse_certificate(&w) {
                        Ok(_) => ok += 1,
                        Err(_) => err += 1,
                    }
                }
            }
            assert!(err > 100 && ok > 10, "ok={ok} err={err}");
        }
    }

    #[test]
    fn der_lengths_are_checked() {
        let mut d = Der {
            b: &[0x30, 0x84, 0xFF, 0xFF, 0xFF, 0xFF, 0x00],
            p: 0,
        };
        assert!(format!("{:#}", d.next().unwrap_err()).contains("runs past"));
        assert!(
            Der {
                b: &[0x30, 0x85, 1, 2, 3, 4, 5],
                p: 0
            }
            .next()
            .is_err(),
            "five length bytes"
        );
        assert!(
            Der {
                b: &[0x30, 0x80, 0, 0],
                p: 0
            }
            .next()
            .is_err(),
            "indefinite length"
        );
        assert!(
            Der {
                b: &[0x1f, 0x01, 0x00],
                p: 0
            }
            .next()
            .is_err(),
            "multi-byte tag"
        );
        assert!(Der { b: &[0x30], p: 0 }.next().is_err());
        let (t, c) = Der {
            b: &[0x04, 0x81, 0x02, 9, 8, 7],
            p: 0,
        }
        .next()
        .unwrap();
        assert_eq!(
            (t, c),
            (0x04, &[9u8, 8][..]),
            "long form length, extra bytes left alone"
        );
    }

    #[test]
    fn dates_oids_and_helpers() {
        assert_eq!(
            parse_time(0x17, b"490101000000Z").unwrap(),
            "2049-01-01T00:00:00Z"
        );
        assert_eq!(
            parse_time(0x17, b"500101000000Z").unwrap(),
            "1950-01-01T00:00:00Z"
        );
        assert_eq!(
            parse_time(0x18, b"20460101123456Z").unwrap(),
            "2046-01-01T12:34:56Z"
        );
        for bad in [
            (0x17, &b"4901010000Z"[..]),
            (0x17, b"491301000000Z"),
            (0x18, b"20460101123456"),
            (0x19, b"x"),
            (0x17, b"4a0101000000Z"),
            (0x17, b"490101250000Z"),
        ] {
            assert!(parse_time(bad.0, bad.1).is_err(), "{:?}", bad.1);
        }
        assert_eq!(unix_of("1970-01-01T00:00:00Z"), Some(0));
        assert_eq!(unix_of("2000-03-01T00:00:00Z"), Some(951_868_800));
        assert_eq!(unix_of("2024-02-29T12:00:01Z"), Some(1_709_208_001));
        assert_eq!(unix_of("garbage"), None);
        assert_eq!(
            oid_text(&[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0b]),
            "1.2.840.113549.1.1.11"
        );
        assert_eq!(oid_text(&[0x55, 0x04, 0x03]), "2.5.4.3");
        assert_eq!(
            oid_text(&[0x88, 0x37, 0x03]),
            "2.999.3",
            "first arc 2 with a large second arc"
        );
        assert_eq!(bit_length(&[0, 0, 0x80]), 8);
        assert_eq!(bit_length(&[0x01, 0x00]), 9);
        assert_eq!(bit_length(&[]), 0);
        assert_eq!(bit_length(&[0, 0]), 0);
        assert_eq!(name_of_oid("2.5.4.3"), "CN");
        assert_eq!(name_of_oid("9.9.9"), "9.9.9");
        assert_eq!(signature_name("1.3.101.112"), "ED25519");
        assert_eq!(base64("QUJD").unwrap(), b"ABC");
        assert_eq!(base64("QUJDRA==").unwrap(), b"ABCD");
        assert!(base64("QU*D").is_err());
    }

    fn scratch(tag: &str) -> std::path::PathBuf {
        let d = std::env::temp_dir().join(format!("ad-otameta-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    fn package_dir(tag: &str) -> std::path::PathBuf {
        let d = scratch(tag);
        std::fs::create_dir_all(d.join("META-INF/com/google/android")).unwrap();
        std::fs::create_dir_all(d.join("META-INF/com/android")).unwrap();
        std::fs::write(d.join(SCRIPT_PATH), SCRIPT).unwrap();
        std::fs::write(d.join(CERT_PATH), RSA_PEM).unwrap();
        d
    }

    #[test]
    fn details_come_from_a_directory_and_from_a_zip() {
        use std::io::Write as _;
        let d = package_dir("dir");
        let from_dir = read_details(&d).unwrap();
        assert_eq!(from_dir.script.as_ref().unwrap().writes.len(), 6);
        assert_eq!(from_dir.certificate.as_ref().unwrap().key_bits, Some(2048));
        let zp = scratch("zip").join("ota.zip");
        let mut w = zip::ZipWriter::new(std::fs::File::create(&zp).unwrap());
        for (n, b) in [(SCRIPT_PATH, SCRIPT), (CERT_PATH, RSA_PEM)] {
            w.start_file(n, zip::write::SimpleFileOptions::default())
                .unwrap();
            w.write_all(b.as_bytes()).unwrap();
        }
        w.finish().unwrap();
        let from_zip = read_details(&zp).unwrap();
        assert_eq!(from_zip.certificate, from_dir.certificate);
        assert_eq!(from_zip.script, from_dir.script);
    }

    #[test]
    fn missing_unreadable_and_oversized_members_are_handled() {
        let d = scratch("missing");
        let none = read_details(&d).unwrap();
        assert!(
            none.script.is_none() && none.certificate.is_none() && none.certificate_error.is_none()
        );
        assert!(
            none.to_text(0)
                .contains("updater-script: not in the package")
        );
        assert!(
            none.to_text(0)
                .contains("signing certificate: not in the package")
        );
        let bad = package_dir("badcert");
        std::fs::write(
            bad.join(CERT_PATH),
            b"-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----",
        )
        .unwrap();
        let r = read_details(&bad).unwrap();
        assert!(r.certificate.is_none() && r.certificate_error.is_some());
        assert!(r.to_text(0).contains("unreadable"));
        assert!(r.to_json(0)["certificate_error"].is_string());
        std::fs::write(
            bad.join(SCRIPT_PATH),
            vec![b'a'; MAX_SCRIPT_BYTES as usize + 1],
        )
        .unwrap();
        assert!(format!("{:#}", read_details(&bad).unwrap_err()).contains("larger than"));
        assert!(read_details(&d.join("nope.zip")).is_err());
        let notzip = d.join("x.zip");
        std::fs::write(&notzip, b"not a zip").unwrap();
        assert!(read_details(&notzip).is_err());
        // a directory standing where the script should be is "not there", not an error
        let odd = package_dir("odd");
        std::fs::remove_file(odd.join(SCRIPT_PATH)).unwrap();
        std::fs::create_dir(odd.join(SCRIPT_PATH)).unwrap();
        assert!(read_details(&odd).unwrap().script.is_none());
    }

    #[cfg(unix)]
    #[test]
    fn a_fifo_never_blocks_a_read() {
        let d = package_dir("fifo");
        std::fs::remove_file(d.join(CERT_PATH)).unwrap();
        assert!(
            std::process::Command::new("mkfifo")
                .arg(d.join(CERT_PATH))
                .status()
                .unwrap()
                .success()
        );
        let top = scratch("fifo-top").join("pipe");
        assert!(
            std::process::Command::new("mkfifo")
                .arg(&top)
                .status()
                .unwrap()
                .success()
        );
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let member = read_details(&d)
                .map(|x| x.certificate.is_none())
                .map_err(|e| format!("{e:#}"));
            let input = read_details(&top).map(|_| ()).map_err(|e| format!("{e:#}"));
            let _ = tx.send((member, input));
        });
        let (member, input) = rx
            .recv_timeout(std::time::Duration::from_secs(20))
            .expect("blocked on a FIFO");
        assert_eq!(
            member,
            Ok(true),
            "a FIFO standing where the certificate should be counts as absent"
        );
        assert!(
            input.unwrap_err().contains("FIFO or socket"),
            "a FIFO as the package itself is refused"
        );
    }

    #[test]
    fn text_and_json_carry_everything() {
        let d = read_details(&package_dir("render")).unwrap();
        let now = unix_of("2027-01-01T00:00:00Z").unwrap();
        let t = d.to_text(now);
        for want in [
            "updater-script:",
            "full package",
            "requires ro.product.device == \"acme\"",
            "writes system.new.dat.br -> /dev/block/system (block image)",
            "writes recovery.img -> /dev/block/recovery (raw image)",
            "sets bootloader env upgrade_step=3",
            "abort codes: E3004, E1001, E2001",
            "signing certificate:",
            "(self-signed)",
            "rsaEncryption 2048 bits, signed with sha256WithRSAEncryption",
            "serial     7A0EF78CE75C97D7415614AEE3B05BD238A5B605",
        ] {
            assert!(t.contains(want), "{want} in\n{t}");
        }
        assert!(!t.contains("concern"), "{t}");
        let j = d.to_json(now);
        assert_eq!(j["certificate"]["key_bits"], 2048);
        assert_eq!(j["certificate"]["self_signed"], true);
        assert_eq!(j["updater_script"]["incremental"], false);
        assert_eq!(j["updater_script"]["device_checks"][0]["value"], "acme");
        assert_eq!(j["updater_script"]["writes"].as_array().unwrap().len(), 6);
        let expired = d.to_text(unix_of("2040-01-01T00:00:00Z").unwrap());
        assert!(
            expired.contains("concern    expired on 2036-09-30T08:45:38Z"),
            "{expired}"
        );
        let inc = Details {
            script: Some(summarise_script("apply_patch(\"a\");")),
            ..Default::default()
        };
        assert!(
            inc.to_text(0)
                .contains("incremental (needs the previous build)")
        );
    }
}
