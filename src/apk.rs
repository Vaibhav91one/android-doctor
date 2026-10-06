//! APK inspection: package name and version from the binary AndroidManifest,
//! and signing certificates from the v1 (META-INF PKCS#7), v2 and v3 signing blocks.
//!
//! Formats follow the AOSP definitions (Apache-2.0): the binary XML layout from
//! `ResourceTypes.h`, the APK Signature Scheme v2/v3 from `apk_signature_scheme.h`,
//! and PKCS#7 (RFC 5652) for the v1 META-INF certs. All paths and sizes are bounds-checked.

use anyhow::{Context, Result, bail, ensure};
use sha2::{Digest, Sha256};
use std::io::{Cursor, Read};
use std::path::Path;
use zip::ZipArchive;

/// AOSP public test-key certificate subject CNs (Apache-2.0, AOSP test keys).
const AOSP_TEST_KEY_SUBJECTS: &[&str] =
    &["Android", "platform", "shared", "testkey", "media", "root"];

/// Maximum APK size we will read into memory (10 MB).
pub const MAX_APK_BYTES: u64 = 10 * 1024 * 1024;
/// Maximum size of a single entry inside an APK zip (5 MB).
const MAX_ENTRY_BYTES: usize = 5 * 1024 * 1024;

// --- Public types ---

/// A signer found in the v1 META-INF area (PKCS#7) or the v2/v3 signing block.
#[derive(Debug, Clone, PartialEq)]
pub struct Signer {
    /// "v1", "v2", or "v3" -- which signing scheme this signer belongs to.
    pub scheme: &'static str,
    /// SHA-256 hex of the signer X.509 certificate.
    pub cert_sha256: String,
    /// The certificate subject CN, for display.
    pub subject_cn: Option<String>,
    /// Whether the cert subject matches a known AOSP public test key.
    pub is_aosp_test_key: bool,
    /// Whether the cert subject is the Android SDK debug keystore ("CN=Android Debug").
    pub is_debug_cert: bool,
    /// Certificate validity window as Unix seconds (notBefore, notAfter), when it parsed.
    pub not_before: Option<i64>,
    pub not_after: Option<i64>,
}

/// The auditable contents of one APK.
#[derive(Debug, Clone, Default)]
pub struct ApkInfo {
    pub path: String,
    pub package_name: String,
    pub version_code: Option<String>,
    pub version_name: Option<String>,
    pub signers: Vec<Signer>,
}

impl ApkInfo {
    pub fn has_test_key(&self) -> bool {
        self.signers.iter().any(|s| s.is_aosp_test_key)
    }

    /// Weak signing posture, as `(rule, detail)`. `now` is Unix seconds from the host clock
    /// (firmware has no trusted clock), so certificate dates are judged against it.
    pub fn posture(&self, now: i64) -> Vec<(&'static str, String)> {
        let mut out = Vec::new();
        let has = |v: &str| self.signers.iter().any(|s| s.scheme == v);
        if has("v1") && !has("v2") && !has("v3") {
            out.push((
                "apk-v1-only-signing",
                "signed with APK Signature Scheme v1 only (no v2/v3): exposed to Janus-class tampering on older platforms".to_string(),
            ));
        }
        for s in &self.signers {
            let cn = s.subject_cn.as_deref().unwrap_or("");
            if s.is_debug_cert || s.is_aosp_test_key {
                let what = if s.is_debug_cert {
                    "the Android debug keystore certificate"
                } else {
                    "a known AOSP test/platform key"
                };
                out.push((
                    "apk-debug-signing-cert",
                    format!("signer (CN={cn}) is {what}"),
                ));
            }
            if let Some(na) = s.not_after.filter(|&na| na < now) {
                out.push((
                    "apk-cert-expired",
                    format!(
                        "signer (CN={cn}) expired {} (as of {}, host clock; firmware has no trusted clock)",
                        ymd(na),
                        ymd(now)
                    ),
                ));
            }
            if let Some(nb) = s.not_before.filter(|&nb| nb > now) {
                out.push((
                    "apk-cert-not-yet-valid",
                    format!(
                        "signer (CN={cn}) is not valid before {} (as of {}, host clock)",
                        ymd(nb),
                        ymd(now)
                    ),
                ));
            }
        }
        // The same cert usually signs both v1 and v2: report each finding once.
        let mut seen = Vec::new();
        out.retain(|p| {
            let new = !seen.contains(p);
            seen.push(p.clone());
            new
        });
        out
    }
}

/// Days since 1970-01-01 for a civil date (Howard Hinnant's algorithm).
fn days_from_civil(y: i64, m: i64, d: i64) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let doy = (153 * (if m > 2 { m - 3 } else { m + 9 }) + 2) / 5 + d - 1;
    era * 146097 + yoe * 365 + yoe / 4 - yoe / 100 + doy - 719468
}

/// `YYYY-MM-DD` for Unix seconds (inverse of `days_from_civil`).
pub fn ymd(secs: i64) -> String {
    let z = secs.div_euclid(86400) + 719468;
    let era = z.div_euclid(146097);
    let doe = z - era * 146097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + i64::from(m <= 2);
    format!("{y:04}-{m:02}-{d:02}")
}

/// One APK audit result: the parsed info plus any error encountered.
#[derive(Debug, Clone, Default)]
pub struct ApkAudit {
    pub info: Option<ApkInfo>,
    pub error: Option<String>,
}

/// Parsed attributes from a binary AndroidManifest.xml.
#[derive(Debug, Clone, Default)]
pub struct ManifestAttrs {
    pub package_name: String,
    pub version_code: Option<String>,
    pub version_name: Option<String>,
}

// --- Binary helpers ---

fn le16(data: &[u8], off: usize) -> Result<u16> {
    ensure!(off + 2 <= data.len(), "le16: truncated at {off}");
    Ok(u16::from_le_bytes([data[off], data[off + 1]]))
}

fn le32(data: &[u8], off: usize) -> Result<u32> {
    ensure!(off + 4 <= data.len(), "le32: truncated at {off}");
    Ok(u32::from_le_bytes([
        data[off],
        data[off + 1],
        data[off + 2],
        data[off + 3],
    ]))
}

#[allow(dead_code)]
fn le64(data: &[u8], off: usize) -> Result<u64> {
    ensure!(off + 8 <= data.len(), "le64: truncated at {off}");
    Ok(u64::from_le_bytes([
        data[off],
        data[off + 1],
        data[off + 2],
        data[off + 3],
        data[off + 4],
        data[off + 5],
        data[off + 6],
        data[off + 7],
    ]))
}

/// Parse the string pool that begins a binary XML document.
fn parse_string_pool(data: &[u8]) -> Result<(Vec<String>, usize)> {
    // RES_STRING_POOL_TYPE (AOSP ResourceTypes.h, Apache-2.0).
    let chunk_type = le16(data, 0)?;
    ensure!(
        chunk_type == 0x0001,
        "string pool: expected RES_STRING_POOL_TYPE 0x0001, got {chunk_type:#06x}"
    );
    let header_size = le16(data, 2)? as usize;
    let chunk_size = le32(data, 4)? as usize;
    ensure!(chunk_size <= data.len(), "string pool: chunk too large");
    let str_count = le32(data, 8)? as usize;
    let strings_start = le32(data, 20)? as usize;
    ensure!(
        strings_start <= chunk_size,
        "string pool: strings start past chunk"
    );
    let mut offsets = Vec::with_capacity(str_count);
    for i in 0..str_count {
        let off = header_size + 4 * i;
        ensure!(off + 4 <= data.len(), "string pool: offset entry truncated");
        offsets.push(le32(data, off)? as usize);
    }
    let mut strings = Vec::with_capacity(str_count);
    for off in offsets {
        let (s, _) = read_utf16(data, strings_start + off)?;
        strings.push(s);
    }
    Ok((strings, strings_start))
}

/// Read a UTF-16LE string from data at offset start.
fn read_utf16(data: &[u8], start: usize) -> Result<(String, usize)> {
    ensure!(start + 2 <= data.len(), "utf16: truncated");
    let char_len = le16(data, start)? as usize;
    let mut s = String::with_capacity(char_len);
    let mut pos = start + 2;
    for _ in 0..char_len {
        // A hostile or merely odd pool can claim more units than the chunk holds; stop at
        // what is actually there rather than failing the whole manifest.
        if pos + 2 > data.len() {
            break;
        }
        let ch = le16(data, pos)? as u16;
        pos += 2;
        if let Some(c) = char::from_u32(ch as u32) {
            s.push(c);
        }
    }
    // Each entry is followed by a terminating 0x0000 (AOSP ResourceTypes.h).
    if pos + 2 <= data.len() {
        pos += 2;
    }
    Ok((s, pos - start))
}

/// An attribute entry in a start tag.
struct Attr {
    name_idx: usize,
    value: String,
}

/// Size of ResXMLTree_node: ResChunk_header (8) + lineNumber (4) + comment (4).
const ATTR_EXT_BASE: usize = 16;

fn parse_start_tag(
    data: &[u8],
    chunk_off: usize,
    strings: &[String],
) -> Result<(String, Vec<Attr>)> {
    let chunk = &data[chunk_off..];
    ensure!(chunk.len() >= 32, "start tag: chunk too small");
    // ResXMLTree_attrExt (AOSP ResourceTypes.h, Apache-2.0) begins ATTR_EXT_BASE bytes into
    // the chunk and is laid out ns, name, attributeStart, attributeSize, attributeCount.
    let name_idx = le32(chunk, ATTR_EXT_BASE + 4)? as usize;
    let name = strings.get(name_idx).cloned().unwrap_or_default();
    let attr_start = le16(chunk, ATTR_EXT_BASE + 8)? as usize;
    let attr_size = le16(chunk, ATTR_EXT_BASE + 10)? as usize;
    let attr_count = le16(chunk, ATTR_EXT_BASE + 12)? as usize;
    // ResXMLTree_attribute is exactly 20 bytes, optionally followed by a typed value
    // (AOSP ResourceTypes.h).
    ensure!(attr_size >= 20, "start tag: attr entry too small");
    let mut attrs = Vec::with_capacity(attr_count);
    // ResXMLTree_attrExt (AOSP ResourceTypes.h): attributeStart is relative to the start
    // of the attrExt, which begins 16 bytes into the chunk (after the ResXMLTree_node header).
    let mut pos = ATTR_EXT_BASE + attr_start;
    for _ in 0..attr_count {
        ensure!(pos + attr_size <= chunk.len(), "start tag: attr past chunk");
        let nm_idx = le32(chunk, pos + 4)? as usize;
        let raw_val_off = le32(chunk, pos + 8)? as usize;
        let value = if raw_val_off == 0xFFFFFFFF {
            // Res_value (AOSP ResourceTypes.h): size u16, res0 u8, dataType u8, data u32.
            let dt = chunk[pos + 15];
            format_typed_value(dt, &chunk[pos + 16..pos + 20])?
        } else {
            // AOSP ResXMLTree_attribute.rawValue is an INDEX into the string pool, not a
            // byte offset (verified against a real APK), so resolve through the pool.
            strings.get(raw_val_off).cloned().unwrap_or_default()
        };
        attrs.push(Attr {
            name_idx: nm_idx,
            value,
        });
        pos += attr_size;
    }
    Ok((name, attrs))
}

fn format_typed_value(data_type: u8, data: &[u8]) -> Result<String> {
    ensure!(data.len() >= 4, "typed value: data too short");
    match data_type {
        0x01 => Ok("(string)".to_string()),
        0x10 => Ok(le32(data, 0)?.to_string()),
        0x11 => Ok(format!("0x{:X}", le32(data, 0)?)),
        0x12 => Ok(le32(data, 0)?.to_string()),
        _ => Ok(format!("(type {})", data_type)),
    }
}

pub(crate) fn parse_manifest(data: &[u8]) -> Result<ManifestAttrs> {
    ensure!(!data.is_empty(), "manifest: empty");
    // A binary XML file begins with the RES_XML_TYPE (0x0003) header; the string pool is
    // the first chunk after that 8-byte header (AOSP ResourceTypes.h, Apache-2.0).
    let file_type = le16(data, 0)?;
    ensure!(
        file_type == 0x0003,
        "manifest: expected RES_XML_TYPE 0x0003, got {file_type:#06x}"
    );
    // ResXMLTree_header: type u16, headerSize u16, size u32 (AOSP ResourceTypes.h).
    let xml_header = le16(data, 2)? as usize;
    ensure!(
        xml_header >= 8 && xml_header <= data.len(),
        "manifest: bad xml header"
    );
    // parse_string_pool returns offsets relative to the pool chunk; rebase onto the
    // whole buffer so parse_start_tag can index them directly.
    let (pool, pool_strings_start) = parse_string_pool(&data[xml_header..])?;
    let _strings_start = xml_header + pool_strings_start;
    let pool_chunk_size = le32(&data[xml_header..], 4)? as usize;
    let mut result = ManifestAttrs::default();
    let mut pos = xml_header + pool_chunk_size;
    while pos + 8 <= data.len() {
        let ct = le16(data, pos)?;
        let cs = le32(data, pos + 4)? as usize;
        ensure!(pos + cs <= data.len(), "manifest: chunk extends past end");
        if ct == 0x0102 {
            let (tag_name, attrs) = parse_start_tag(data, pos, &pool)?;
            if tag_name == "manifest" {
                for a in &attrs {
                    let aname = pool.get(a.name_idx).map(|s| s.as_str());
                    match aname {
                        Some("package") => result.package_name = a.value.clone(),
                        Some("versionCode") => result.version_code = Some(a.value.clone()),
                        Some("versionName") => result.version_name = Some(a.value.clone()),
                        _ => {}
                    }
                }
            }
        }
        pos += cs;
    }
    Ok(result)
}

// --- Minimal ASN.1/DER reader ---
// Only what we need to walk PKCS#7 / X.509 (RFC 5652 / 5280).

struct Der<'a> {
    tag: u8,
    payload: &'a [u8],
}

fn der_len(data: &[u8]) -> Result<(usize, usize)> {
    ensure!(!data.is_empty(), "der_len: empty");
    let first = data[0];
    if first & 0x80 == 0 {
        return Ok((first as usize, 1));
    }
    let n = (first & 0x7F) as usize;
    ensure!(n != 0 && n <= 4, "der_len: invalid long form {n}");
    ensure!(data.len() > n, "der_len: truncated");
    let mut len = 0usize;
    for i in 0..n {
        len = (len << 8) | data[1 + i] as usize;
    }
    Ok((len, 1 + n))
}

fn der_one<'a>(data: &'a [u8]) -> Result<(Der<'a>, usize)> {
    ensure!(!data.is_empty(), "der: empty");
    let tag = data[0];
    let (len, n) = der_len(&data[1..])?;
    let hdr = 1 + n;
    ensure!(data.len() >= hdr + len, "der: element truncated");
    let payload = &data[hdr..hdr + len];
    Ok((Der { tag, payload }, hdr + len))
}

struct DerIter<'a> {
    data: &'a [u8],
}
impl<'a> DerIter<'a> {
    fn new(data: &'a [u8]) -> Self {
        Self { data }
    }
}
impl<'a> Iterator for DerIter<'a> {
    type Item = Der<'a>;
    fn next(&mut self) -> Option<Der<'a>> {
        if self.data.is_empty() {
            return None;
        }
        let (d, n) = der_one(self.data).ok()?;
        self.data = &self.data[n..];
        Some(d)
    }
}

/// Parse an X.509 Time (UTCTime 0x17 or GeneralizedTime 0x18, in Zulu) to Unix seconds.
fn parse_time(d: &Der) -> Option<i64> {
    let s = std::str::from_utf8(d.payload).ok()?;
    let (year, rest) = match d.tag {
        0x17 => {
            let yy: i64 = s.get(0..2)?.parse().ok()?;
            (if yy >= 50 { 1900 + yy } else { 2000 + yy }, s.get(2..)?)
        }
        0x18 => (s.get(0..4)?.parse().ok()?, s.get(4..)?),
        _ => return None,
    };
    let num = |r: std::ops::Range<usize>| -> Option<i64> {
        let t = rest.get(r)?;
        t.bytes()
            .all(|b| b.is_ascii_digit())
            .then(|| t.parse().ok())?
    };
    let (mo, day, h, mi) = (num(0..2)?, num(2..4)?, num(4..6)?, num(6..8)?);
    let sec = num(8..10).unwrap_or(0);
    if !(1..=12).contains(&mo) || !(1..=31).contains(&day) || h > 23 || mi > 59 || sec > 60 {
        return None;
    }
    Some(days_from_civil(year, mo, day) * 86400 + h * 3600 + mi * 60 + sec)
}

/// Read (notBefore, notAfter) from a Certificate. Accepts the full DER Certificate (v2/v3) or
/// just its body, the TBSCertificate + algorithm + signature items (the v1 path).
fn cert_validity(cert: &[u8]) -> Option<(i64, i64)> {
    let (first, _) = der_one(cert).ok()?;
    let tbs = match DerIter::new(first.payload).next() {
        Some(inner) if inner.tag == 0x30 => inner,
        _ => first,
    };
    let mut f = DerIter::new(tbs.payload).peekable();
    if f.peek()?.tag == 0xA0 {
        f.next(); // [0] version
    }
    // serial, signature algorithm, issuer, then validity
    let validity = f.nth(3)?;
    let mut t = DerIter::new(validity.payload);
    Some((parse_time(&t.next()?)?, parse_time(&t.next()?)?))
}

/// Debug flag and validity window for one certificate.
fn cert_meta(cert: &[u8], cn: Option<&str>) -> (bool, Option<i64>, Option<i64>) {
    let v = cert_validity(cert);
    let debug = cn.is_some_and(|c| c.eq_ignore_ascii_case("Android Debug"));
    (debug, v.map(|v| v.0), v.map(|v| v.1))
}

/// Extract the CN from an X.509 certificate.
///
/// Walks the DER tree looking for the commonName attribute OID (2.5.4.3, encoded
/// `55 04 03`) and returns the printable string that follows it. A positional walk of
/// Name/RDN would depend on field ordering; searching for the OID does not.
fn extract_cn_from_cert(cert_body: &[u8]) -> Option<String> {
    find_cn(cert_body, 0)
}

/// Depth-first search for a CN attribute, bounded so a hostile certificate cannot
/// make this expensive.
fn find_cn(buf: &[u8], depth: usize) -> Option<String> {
    const MAX_DEPTH: usize = 12;
    if depth > MAX_DEPTH {
        return None;
    }
    let mut at = 0usize;
    while at + 2 <= buf.len() {
        let tag = buf[at];
        if tag & 0x1F == 0x1F {
            return None; // high-tag-number form: not something we need to walk into
        }
        let (len, hdr) = match der_len(&buf[at + 1..]) {
            Ok(v) => v,
            Err(_) => return None,
        };
        let body = at + 1 + hdr;
        let end = body.checked_add(len)?;
        if end > buf.len() {
            return None;
        }
        // An AttributeTypeAndValue is SEQUENCE { OID, value }. Recognize it structurally.
        if tag == 0x06 && buf[body..end] == [0x55, 0x04, 0x03] && end < buf.len() {
            let vt = buf[end];
            let (vlen, vhdr) = der_len(&buf[end + 1..]).ok()?;
            let vstart = end + 1 + vhdr;
            if (vt & 0x1F) == 0x0C || vt == 0x13 || vt == 0x16 {
                // UTF8String, PrintableString, IA5String
                return Some(String::from_utf8_lossy(&buf[vstart..vstart + vlen]).into_owned());
            }
            if vt == 0x1E {
                // BMPString: UTF-16BE
                let raw = &buf[vstart..vstart + vlen];
                let mut units: Vec<u16> = Vec::with_capacity(raw.len() / 2);
                let mut i = 0;
                while i + 1 < raw.len() {
                    units.push(u16::from_be_bytes([raw[i], raw[i + 1]]));
                    i += 2;
                }
                return String::from_utf16(&units).ok();
            }
        }
        if tag & 0x20 != 0 {
            // Constructed: descend.
            if let Some(found) = find_cn(&buf[body..end], depth + 1) {
                return Some(found);
            }
        }
        at = end;
    }
    None
}

/// Decode a DER length starting at `at`, returning (value, bytes consumed including tag-len).
/// (CN, SHA-256 hex, certificate bytes) for one PKCS#7 certificate.
type P7Cert = (String, Option<String>, Vec<u8>);

/// Extract signer certificates from PKCS#7 SignedData.
fn extract_pkcs7_certs(p7_der: &[u8]) -> Result<Vec<P7Cert>> {
    let ci = der_one(p7_der)?.0;
    ensure!((ci.tag & 0x1F) == 0x10, "pkcs7: not a SEQUENCE");
    let mut ci_fields = DerIter::new(ci.payload);
    let _ = ci_fields.next(); // contentType OID
    let content = ci_fields.next();
    let content = match content {
        Some(d) if (d.tag & 0x1F) == 0x00 && (d.tag & 0x80) != 0 => d, // [0] context
        _ => bail!("pkcs7: content not at [0]"),
    };
    let (sd, _) = der_one(content.payload)?;
    ensure!((sd.tag & 0x1F) == 0x10, "pkcs7: signed data not SEQUENCE");
    // SignedData fields are version, digestAlgorithms, encapContentInfo and then optionally
    // certificates and crls. encapContentInfo is absent in many signatures, so find the
    // certificates SET by shape rather than by position.
    // certificates is [0] IMPLICIT SET OF Certificate, so its DER tag is 0xA0. Matching a
    // plain SET (0x31) finds digestAlgorithms instead, which is a few bytes long.
    let mut certs = None;
    for f in DerIter::new(sd.payload) {
        if f.tag == 0xA0 {
            certs = Some(f);
            break;
        }
    }
    let mut result = Vec::new();
    if let Some(certs_set) = certs {
        // SET
        for cert_wrapped in DerIter::new(certs_set.payload) {
            let cert_der = if cert_wrapped.tag == 0xA0 {
                der_one(cert_wrapped.payload)?.0.payload
            } else if (cert_wrapped.tag & 0x1F) == 0x10 {
                cert_wrapped.payload
            } else {
                continue;
            };
            let cn = extract_cn_from_cert(cert_der);
            let digest = Sha256::digest(cert_der)
                .iter()
                .map(|b| format!("{:02x}", b))
                .collect::<String>();
            result.push((cn.unwrap_or_default(), Some(digest), cert_der.to_vec()));
        }
    }
    Ok(result)
}

// --- APK Signature Scheme v2/v3 signing block (AOSP apk_signature_scheme.h) ---
//
// The signing block sits between the zip entries and the End Of Central Directory
// record. It is bracketed by the 16-byte magic below (as a "footer" right before the
// EOCD and again as the "header" at the start of the block) plus uint64 block-size
// fields. Inside are length-prefixed entries tagged by their 32-bit ID:
//   0x7109871a == APK Signature Scheme v2 block
//   0x7109871b == APK Signature Scheme v3 block
// (AOSP, Apache-2.0.)
const V2_BLOCK_ID: u32 = 0x7109871a;
const V3_BLOCK_ID: u32 = 0x7109871b;
/// The zip End Of Central Directory record signature (AOSP, Apache-2.0).
const EOCD_SIG: u32 = 0x06054b50;
const EOCD_MIN_SIZE: usize = 22;

// --- Entry points ---

/// Read one APK from `path` and audit it.
///
/// Never executes anything: the APK is only read as a ZIP, its binary AndroidManifest.xml is
/// parsed, and its v1 META-INF certificates are decoded. An unreadable or malformed APK
/// comes back as `ApkAudit::error`, never a panic and never a silent skip.
/// Audit an in-memory APK.
pub fn audit_apk_bytes(path: &Path, bytes: &[u8]) -> ApkAudit {
    let r = (|| -> Result<ApkInfo> {
        let mut zip = ZipArchive::new(Cursor::new(bytes)).context("not a valid zip")?;
        let attrs = match read_entry(&mut zip, "AndroidManifest.xml") {
            Some(b) => parse_manifest(&b).ok(),
            None => None,
        };
        let mut signers = Vec::new();
        let names: Vec<String> = zip.file_names().map(String::from).collect();
        for name in names {
            let upper = name.to_ascii_uppercase();
            if !(upper.starts_with("META-INF/")
                && (upper.ends_with(".RSA") || upper.ends_with(".DSA") || upper.ends_with(".EC")))
            {
                continue;
            }
            let Some(der) = read_entry(&mut zip, &name) else {
                continue;
            };
            let Ok(certs) = extract_pkcs7_certs(&der) else {
                continue;
            };
            for (cn, sha, cert) in certs {
                let (is_debug_cert, not_before, not_after) = cert_meta(&cert, Some(&cn));
                signers.push(Signer {
                    scheme: "v1",
                    cert_sha256: sha.unwrap_or_default(),
                    subject_cn: Some(cn.clone()),
                    is_aosp_test_key: AOSP_TEST_KEY_SUBJECTS.iter().any(|t| cn.contains(t)),
                    is_debug_cert,
                    not_before,
                    not_after,
                });
            }
        }
        signers.extend(v2_signers(bytes));
        Ok(ApkInfo {
            path: path.display().to_string(),
            package_name: attrs
                .as_ref()
                .map(|a| a.package_name.clone())
                .unwrap_or_default(),
            version_code: attrs.as_ref().and_then(|a| a.version_code.clone()),
            version_name: attrs.as_ref().and_then(|a| a.version_name.clone()),
            signers,
        })
    })();
    match r {
        Ok(info) => ApkAudit {
            info: Some(info),
            error: None,
        },
        Err(e) => ApkAudit {
            info: None,
            error: Some(format!("{e:#}")),
        },
    }
}

/// Read one entry out of the archive, refusing anything over the per-entry limit.
fn read_entry(zip: &mut ZipArchive<Cursor<&[u8]>>, name: &str) -> Option<Vec<u8>> {
    let f = zip.by_name(name).ok()?;
    if f.size() as usize > MAX_ENTRY_BYTES {
        return None;
    }
    let mut buf = Vec::new();
    f.take(MAX_ENTRY_BYTES as u64).read_to_end(&mut buf).ok()?;
    Some(buf)
}

/// Find the APK Signing Block and return the signed-data bytes it certifies.
///
/// Layout (AOSP apk_signature_scheme.h, Apache-2.0):
///
///   ... zip entries ... | uint64 size of block | pairs | uint64 size of block |
///   16-byte magic | zip EOCD
///
/// Each pair is `uint64 length` followed by `uint32 id` and that many bytes of value.
/// The signed data the signers cover is the concatenation of the three EOCD-present
/// regions, so we recover it by locating the block and slicing around it.
fn v2_signers(bytes: &[u8]) -> Vec<Signer> {
    let Some(block) = signing_block(bytes) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for (id, value) in block {
        let scheme = match id {
            V2_BLOCK_ID => "v2",
            V3_BLOCK_ID => "v3",
            _ => continue,
        };
        for s in signers_in_block(value) {
            out.push(Signer { scheme, ..s });
        }
    }
    out
}

/// The signing block pairs: (block id, value bytes).
fn signing_block(bytes: &[u8]) -> Option<Vec<(u32, &[u8])>> {
    if bytes.len() < EOCD_MIN_SIZE + 2 * 8 + MAGIC_LEN {
        return None;
    }
    // The block sits immediately before the zip central directory (not before the EOCD):
    //   entries | size | pairs | size | magic | central directory | EOCD
    // The EOCD can carry a trailing comment, so find it by scanning back from the end.
    let tail = bytes.len().saturating_sub(EOCD_MIN_SIZE + 0xFFFF);
    let eocd = (tail..=bytes.len() - EOCD_MIN_SIZE)
        .rev()
        .find(|&i| le32(bytes, i).ok() == Some(EOCD_SIG))?;
    let cd_off = le32(bytes, eocd + 16).ok()? as usize;
    if cd_off > eocd {
        return None;
    }
    let magic_at = cd_off.checked_sub(MAGIC_LEN)?;
    if bytes[magic_at..magic_at + MAGIC_LEN] != MAGIC {
        return None;
    }
    let size_at = magic_at.checked_sub(8)?;
    // The block size counts the pairs plus the trailing size field and magic (24 bytes).
    let block_size = le64(bytes, size_at).ok()? as usize;
    if block_size < 24 {
        return None;
    }
    let block_start = size_at.checked_sub(block_size - 24)?.checked_sub(8)?;
    let mut out = Vec::new();
    let mut at = block_start + 8; // skip the leading size field
    let end = size_at;
    while at + 12 <= end {
        let len = le64(bytes, at).ok()? as usize;
        if len < 4 || at.checked_add(8 + len).is_none_or(|e| e > end) {
            break;
        }
        let id = le32(bytes, at + 8).ok()?;
        let vstart = at + 12;
        let vend = vstart + len - 4;
        out.push((id, &bytes[vstart..vend]));
        at += 8 + len;
    }
    Some(out)
}

/// Extract signers from one v2/v3 block value: a length-prefixed sequence of length-prefixed
/// signers.
fn signers_in_block(value: &[u8]) -> Vec<Signer> {
    let mut out = Vec::new();
    let Some(seq) = lp(value, &mut 0) else {
        return out;
    };
    let mut at = 0;
    while let Some(signer) = lp(seq, &mut at) {
        out.extend(signer_from(signer));
    }
    out
}

/// A uint32-length-prefixed field at `*at`, advancing past it.
fn lp<'a>(data: &'a [u8], at: &mut usize) -> Option<&'a [u8]> {
    let len = le32(data, *at).ok()? as usize;
    let end = (*at).checked_add(4)?.checked_add(len)?;
    let out = data.get(*at + 4..end)?;
    *at = end;
    Some(out)
}

/// One v2/v3 signer: `signed data | signatures | public key`, each length-prefixed. The signed
/// data holds `digests | certificates | ...`, and the first certificate is the signer's own.
fn signer_from(signer: &[u8]) -> Option<Signer> {
    let signed = lp(signer, &mut 0)?;
    let mut at = 0;
    lp(signed, &mut at)?; // digests
    let certs = lp(signed, &mut at)?;
    let der = lp(certs, &mut 0)?;
    let cn = extract_cn_from_cert(der);
    let (is_debug_cert, not_before, not_after) = cert_meta(der, cn.as_deref());
    Some(Signer {
        scheme: "v2",
        cert_sha256: Sha256::digest(der)
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect(),
        is_aosp_test_key: cn
            .as_deref()
            .is_some_and(|c| AOSP_TEST_KEY_SUBJECTS.iter().any(|t| c.contains(t))),
        subject_cn: cn,
        is_debug_cert,
        not_before,
        not_after,
    })
}

/// The 16-byte APK Signing Block magic (AOSP, Apache-2.0).
const MAGIC: [u8; 16] = *b"APK Sig Block 42";
const MAGIC_LEN: usize = 16;

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    /// Build a minimal but real APK: a ZIP holding a binary AndroidManifest.xml and a
    /// META-INF signature entry.
    fn apk_bytes(with_manifest: bool) -> Vec<u8> {
        let mut w = zip::ZipWriter::new(Cursor::new(Vec::new()));
        let opt = zip::write::SimpleFileOptions::default();
        if with_manifest {
            w.start_file("AndroidManifest.xml", opt).unwrap();
            w.write_all(b"\x03\x00\x08\x00 fake binary manifest")
                .unwrap();
        }
        w.start_file("META-INF/CERT.RSA", opt).unwrap();
        w.write_all(b"\x30\x82 not really pkcs7").unwrap();
        w.finish().unwrap().into_inner()
    }

    #[test]
    fn an_apk_is_parsed_rather_than_reported_unreadable() {
        let a = audit_apk_bytes(std::path::Path::new("/system/app/X.apk"), &apk_bytes(true));
        assert!(a.error.is_none(), "{:?}", a.error);
        let info = a.info.expect("info");
        assert_eq!(info.path, "/system/app/X.apk");
    }

    #[test]
    fn an_apk_with_no_manifest_still_parses_without_error() {
        let a = audit_apk_bytes(std::path::Path::new("/x.apk"), &apk_bytes(false));
        assert!(a.error.is_none(), "{:?}", a.error);
        assert!(a.info.expect("info").package_name.is_empty());
    }

    #[test]
    fn a_file_that_is_not_a_zip_is_reported_not_panicked_on() {
        let a = audit_apk_bytes(std::path::Path::new("/x.apk"), b"definitely not a zip");
        assert!(a.info.is_none());
        assert!(a.error.is_some(), "an unreadable apk must say so");
    }

    #[test]
    fn a_malformed_certificate_does_not_panic_and_yields_no_signers() {
        let a = audit_apk_bytes(std::path::Path::new("/x.apk"), &apk_bytes(true));
        let info = a.info.expect("info");
        assert!(
            info.signers.is_empty(),
            "garbage DER must not become a signer"
        );
    }

    // --- signing posture fixtures: synthetic APKs, DER certs and signing blocks built here ---

    const NOW: i64 = 1_800_000_000; // 2027-01-15

    fn der(tag: u8, body: &[u8]) -> Vec<u8> {
        let mut v = vec![tag];
        match body.len() {
            n if n < 128 => v.push(n as u8),
            n => v.extend([0x82, (n >> 8) as u8, n as u8]),
        }
        v.extend(body);
        v
    }

    /// A DER X.509 Certificate with the given CN and UTCTime validity ("YYMMDDHHMMSSZ").
    fn cert(cn: &str, nb: &str, na: &str) -> Vec<u8> {
        let name = der(
            0x30,
            &der(
                0x31,
                &der(
                    0x30,
                    &[der(0x06, &[0x55, 0x04, 0x03]), der(0x0C, cn.as_bytes())].concat(),
                ),
            ),
        );
        let alg = der(0x30, &der(0x06, &[0x2A, 0x03]));
        let tbs = der(
            0x30,
            &[
                der(0xA0, &der(0x02, &[2])),
                der(0x02, &[1]),
                alg.clone(),
                name.clone(),
                der(
                    0x30,
                    &[der(0x17, nb.as_bytes()), der(0x17, na.as_bytes())].concat(),
                ),
                name,
                der(0x30, &[]),
            ]
            .concat(),
        );
        der(0x30, &[tbs, alg, der(0x03, &[0, 0])].concat())
    }

    /// PKCS#7 SignedData carrying `cert` (the shape `extract_pkcs7_certs` walks).
    fn pkcs7(cert: &[u8]) -> Vec<u8> {
        let sd = der(
            0x30,
            &[
                der(0x02, &[1]),
                der(0x31, &[]),
                der(0x30, &der(0x06, &[0x2A])),
                der(0xA0, cert),
            ]
            .concat(),
        );
        der(0x30, &[der(0x06, &[0x2A]), der(0xA0, &sd)].concat())
    }

    fn lp32(b: &[u8]) -> Vec<u8> {
        [&(b.len() as u32).to_le_bytes()[..], b].concat()
    }

    /// An APK zip. `v1` adds a META-INF/CERT.RSA; `v2` inserts a v2 signing block before the
    /// central directory, as a real signer does.
    fn signed_apk(v1: Option<&[u8]>, v2: Option<&[u8]>) -> Vec<u8> {
        let mut w = zip::ZipWriter::new(Cursor::new(Vec::new()));
        let opt = zip::write::SimpleFileOptions::default();
        w.start_file("AndroidManifest.xml", opt).unwrap();
        w.write_all(b"x").unwrap();
        if let Some(c) = v1 {
            w.start_file("META-INF/CERT.RSA", opt).unwrap();
            w.write_all(&pkcs7(c)).unwrap();
        }
        let mut z = w.finish().unwrap().into_inner();
        let Some(c) = v2 else { return z };
        let signed = [lp32(&[]), lp32(&lp32(c)), lp32(&[])].concat();
        let signer = [lp32(&signed), lp32(&[]), lp32(&[])].concat();
        let value = lp32(&lp32(&signer));
        let pair = [
            &(4 + value.len() as u64).to_le_bytes()[..],
            &V2_BLOCK_ID.to_le_bytes(),
            &value,
        ]
        .concat();
        let size = (pair.len() + 24) as u64;
        let block = [&size.to_le_bytes()[..], &pair, &size.to_le_bytes(), &MAGIC].concat();
        let eocd = z.len() - EOCD_MIN_SIZE;
        let cd = u32::from_le_bytes(z[eocd + 16..eocd + 20].try_into().unwrap()) as usize;
        z.splice(cd..cd, block.iter().copied());
        let eocd = z.len() - EOCD_MIN_SIZE;
        z[eocd + 16..eocd + 20].copy_from_slice(&((cd + block.len()) as u32).to_le_bytes());
        z
    }

    fn rules_for(bytes: &[u8]) -> Vec<&'static str> {
        let a = audit_apk_bytes(Path::new("/system/app/X.apk"), bytes);
        assert!(a.error.is_none(), "{:?}", a.error);
        a.info.unwrap().posture(NOW).iter().map(|p| p.0).collect()
    }

    const OK_NB: &str = "200101000000Z";
    const OK_NA: &str = "400101000000Z";

    #[test]
    fn a_v1_only_apk_is_flagged() {
        let c = cert("Acme Release", OK_NB, OK_NA);
        assert_eq!(
            rules_for(&signed_apk(Some(&c), None)),
            ["apk-v1-only-signing"]
        );
    }

    #[test]
    fn a_v2_signed_apk_is_not_v1_only_and_a_clean_one_has_no_findings() {
        let c = cert("Acme Release", OK_NB, OK_NA);
        // v2 alone, and v1+v2 (the usual shape), are both fine.
        assert!(rules_for(&signed_apk(None, Some(&c))).is_empty());
        assert!(rules_for(&signed_apk(Some(&c), Some(&c))).is_empty());
        let info = audit_apk_bytes(Path::new("/x.apk"), &signed_apk(None, Some(&c)))
            .info
            .unwrap();
        assert_eq!(info.signers.len(), 1);
        assert_eq!(info.signers[0].scheme, "v2");
        assert_eq!(info.signers[0].subject_cn.as_deref(), Some("Acme Release"));
    }

    #[test]
    fn the_android_debug_cert_is_flagged_for_both_schemes() {
        let c = cert("Android Debug", OK_NB, OK_NA);
        assert_eq!(
            rules_for(&signed_apk(None, Some(&c))),
            ["apk-debug-signing-cert"]
        );
        assert_eq!(
            rules_for(&signed_apk(Some(&c), None)),
            ["apk-v1-only-signing", "apk-debug-signing-cert"]
        );
        let info = audit_apk_bytes(Path::new("/x.apk"), &signed_apk(None, Some(&c)))
            .info
            .unwrap();
        assert!(info.signers[0].is_debug_cert);
    }

    #[test]
    fn an_aosp_test_key_is_flagged_as_a_weak_signing_cert() {
        let c = cert("testkey", OK_NB, OK_NA);
        assert_eq!(
            rules_for(&signed_apk(None, Some(&c))),
            ["apk-debug-signing-cert"]
        );
    }

    #[test]
    fn an_expired_certificate_is_flagged_against_the_given_clock() {
        let c = cert("Acme Release", OK_NB, "210101000000Z");
        let apk = signed_apk(None, Some(&c));
        assert_eq!(rules_for(&apk), ["apk-cert-expired"]);
        let info = audit_apk_bytes(Path::new("/x.apk"), &apk).info.unwrap();
        let detail = &info.posture(NOW)[0].1;
        assert!(detail.contains("expired 2021-01-01"), "{detail}");
        assert!(detail.contains("as of 2027-01-15"), "{detail}");
        assert!(detail.contains("no trusted clock"), "{detail}");
        // Before expiry the same APK is clean.
        assert!(info.posture(1_600_000_000).is_empty());
    }

    #[test]
    fn a_certificate_not_yet_valid_is_flagged() {
        let c = cert("Acme Release", "490101000000Z", "491231000000Z");
        assert_eq!(
            rules_for(&signed_apk(None, Some(&c))),
            ["apk-cert-not-yet-valid"]
        );
    }

    #[test]
    fn validity_times_parse_both_encodings_and_reject_junk() {
        let t = |tag: u8, s: &str| {
            parse_time(&Der {
                tag,
                payload: s.as_bytes(),
            })
        };
        assert_eq!(t(0x17, "210101000000Z"), Some(1_609_459_200));
        assert_eq!(t(0x17, "2101010000Z"), Some(1_609_459_200)); // no seconds
        assert_eq!(t(0x18, "20210101000000Z"), Some(1_609_459_200));
        assert_eq!(t(0x17, "500101000000Z"), Some(-631_152_000)); // YY>=50 -> 19YY
        assert_eq!(t(0x17, "21ab01000000Z"), None);
        assert_eq!(t(0x17, "211301000000Z"), None);
        assert_eq!(t(0x17, "2"), None);
        assert_eq!(ymd(1_609_459_200), "2021-01-01");
        assert_eq!(ymd(0), "1970-01-01");
    }

    #[test]
    fn a_truncated_or_corrupt_signing_block_never_panics() {
        let c = cert("Acme Release", OK_NB, OK_NA);
        let apk = signed_apk(Some(&c), Some(&c));
        for n in (0..apk.len()).step_by(3) {
            if let Some(i) = audit_apk_bytes(Path::new("/x.apk"), &apk[..n]).info {
                let _ = i.posture(NOW);
            }
        }
        // Flip every byte in turn: still no panic.
        for i in 0..apk.len() {
            let mut b = apk.clone();
            b[i] ^= 0xFF;
            if let Some(info) = audit_apk_bytes(Path::new("/x.apk"), &b).info {
                let _ = info.posture(NOW);
            }
        }
    }
}
