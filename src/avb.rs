//! Android Verified Boot (AVB) `vbmeta` inspection: the header, the public key, every descriptor,
//! the authentication digest, the RSA signature over the header and auxiliary block, and (with a
//! directory of images) the hash of each hashed partition.
//!
//! Layout from AOSP libavb (`avb_vbmeta_image.h`, `avb_descriptor.h`, `avb_footer.h`, Apache-2.0)
//! and checked against AOSP's `avbtool info_image`. The authentication digest is checked, the RSA
//! signature is verified with the embedded public key (PKCS#1 v1.5), and partition hashes are checked.
//! All integers are big-endian.
use crate::detect::refuse_blocking_file;
use anyhow::{Context, Result, bail, ensure};
use rsa::RsaPublicKey;
use rsa::pkcs1v15::Pkcs1v15Sign;
use serde_json::{Value, json};
use sha2::{Digest, Sha256, Sha512};
use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::path::Path;

#[cfg(test)]
use rand::rngs::OsRng;
#[cfg(test)]
use rsa::RsaPrivateKey;
#[cfg(test)]
use rsa::traits::PublicKeyParts;

const HEADER_LEN: usize = 256;
const FOOTER_LEN: usize = 64;
/// No real vbmeta block comes close to this; it bounds what a hostile image can make us read.
const MAX_VBMETA: u64 = 16 << 20;
const MAX_DESCRIPTORS: usize = 100_000;
const CHUNK: usize = 1 << 20;

const TAG_PROPERTY: u64 = 0;
const TAG_HASHTREE: u64 = 1;
const TAG_HASH: u64 = 2;
const TAG_KERNEL_CMDLINE: u64 = 3;
const TAG_CHAIN_PARTITION: u64 = 4;

const FLAG_HASHTREE_DISABLED: u32 = 1;
const FLAG_VERIFICATION_DISABLED: u32 = 2;
/// Not in the AVB spec enum, but used by some vendors/avbtool to mark an
/// unlocked device that permits rollback of the anti-rollback index.
const FLAG_ALLOW_ROLLBACK: u32 = 4;

#[derive(Debug, Clone, PartialEq)]
pub enum Descriptor {
    Property {
        key: String,
        value: String,
    },
    Hash(HashDescriptor),
    Hashtree(HashtreeDescriptor),
    KernelCmdline {
        flags: u32,
        text: String,
    },
    ChainPartition {
        partition: String,
        rollback_index_location: u32,
        public_key_sha256: String,
    },
    Unknown {
        tag: u64,
        len: u64,
    },
}

#[derive(Debug, Clone, PartialEq)]
pub struct HashDescriptor {
    pub partition: String,
    pub algorithm: String,
    pub image_size: u64,
    pub salt: Vec<u8>,
    pub digest: Vec<u8>,
    pub flags: u32,
}

#[derive(Debug, Clone, PartialEq)]
pub struct HashtreeDescriptor {
    pub partition: String,
    pub algorithm: String,
    pub version: u32,
    pub image_size: u64,
    pub tree_offset: u64,
    pub tree_size: u64,
    pub data_block_size: u32,
    pub hash_block_size: u32,
    pub fec_num_roots: u32,
    pub fec_offset: u64,
    pub fec_size: u64,
    pub salt: Vec<u8>,
    pub root_digest: Vec<u8>,
    pub flags: u32,
}

/// The `AvbFooter` at the end of a partition image that carries its vbmeta (boot, dtbo, ...).
#[derive(Debug, Clone, PartialEq)]
pub struct Footer {
    pub version: (u32, u32),
    pub original_image_size: u64,
    pub vbmeta_offset: u64,
    pub vbmeta_size: u64,
}

/// Result of checking the vbmeta RSA signature.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SignatureStatus {
    /// The signature verified successfully.
    Valid,
    /// The signature is present but does not verify (tampered or corrupted data).
    Invalid,
    /// Algorithm NONE (0): no signature is present.
    Absent,
    /// The algorithm is not supported (e.g. ECDSA, or an unknown id). The signature
    /// is left unchecked — this is NOT a failure.
    Unsupported(u32),
}

#[derive(Debug, Clone)]
pub struct Vbmeta {
    pub libavb: (u32, u32),
    pub algorithm: u32,
    pub rollback_index: u64,
    pub flags: u32,
    pub rollback_index_location: u32,
    pub release: String,
    pub auth_size: u64,
    pub aux_size: u64,
    pub signature_len: u64,
    pub public_key_bits: Option<u32>,
    pub public_key_sha256: Option<String>,
    pub public_key_metadata_len: u64,
    /// `Some(true)` if the hash in the authentication block matches, `None` for algorithm NONE.
    pub digest_ok: Option<bool>,
    /// Whether the RSA signature over the header + auxiliary block verifies with the
    /// embedded public key. See `SignatureStatus`.
    pub signature_verified: SignatureStatus,
    pub descriptors: Vec<Descriptor>,
    pub footer: Option<Footer>,
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn text(b: &[u8]) -> String {
    String::from_utf8_lossy(b).into_owned()
}

fn algorithm_name(a: u32) -> String {
    match a {
        0 => "NONE".into(),
        1 => "SHA256_RSA2048".into(),
        2 => "SHA256_RSA4096".into(),
        3 => "SHA256_RSA8192".into(),
        4 => "SHA512_RSA2048".into(),
        5 => "SHA512_RSA4096".into(),
        6 => "SHA512_RSA8192".into(),
        n => format!("unknown({n})"),
    }
}

/// `sizeof(AvbRSAPublicKeyHeader)`: `key_num_bits` and `n0inv`, both big-endian u32.
const AVB_KEY_HEADER_LEN: usize = 8;

/// Which digest the authentication block uses for an algorithm type.
fn auth_hash(algorithm: u32, data: &[u8]) -> Option<Vec<u8>> {
    match algorithm {
        1..=3 => Some(Sha256::digest(data).to_vec()),
        4..=6 => Some(Sha512::digest(data).to_vec()),
        _ => None,
    }
}

/// The RSA key size in bits for a given algorithm type.
fn algorithm_key_bits(algorithm: u32) -> Option<usize> {
    match algorithm {
        1 | 4 => Some(2048),
        2 | 5 => Some(4096),
        3 | 6 => Some(8192),
        _ => None,
    }
}

/// PKCS#1 v1.5 DigestInfo prefix for SHA-256.
fn pkcs1v15_sha256_prefix() -> Vec<u8> {
    vec![
        0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01,
        0x05, 0x00, 0x04, 0x20,
    ]
}

/// PKCS#1 v1.5 DigestInfo prefix for SHA-512.
fn pkcs1v15_sha512_prefix() -> Vec<u8> {
    vec![
        0x30, 0x51, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03,
        0x05, 0x00, 0x04, 0x40,
    ]
}

/// Verify an RSA signature against the signed data (header + auxiliary block).
///
/// The public key blob in the auxiliary block is libavb's `AvbRSAPublicKeyHeader`: a 4-byte
/// big-endian key size in bits and a 4-byte `n0inv` (Montgomery constant, unused here), then
/// the big-endian RSA modulus padded to that size, then `rr` (also unused). The exponent is
/// always 65537 (0x10001) per AVB convention. The signature uses PKCS#1 v1.5 padding with
/// the hash algorithm determined by the AVB algorithm type.
fn verify_rsa_signature(
    algorithm: u32,
    key: &[u8],
    signature: &[u8],
    signed: &[u8],
) -> SignatureStatus {
    let key_bits = match algorithm_key_bits(algorithm) {
        Some(k) => k,
        None => return SignatureStatus::Unsupported(algorithm),
    };
    let key_bytes = key_bits / 8;

    // The key blob must contain at least the 8-byte header plus the modulus.
    if key.len() < AVB_KEY_HEADER_LEN + key_bytes {
        return SignatureStatus::Invalid;
    }

    // Read the key size from the blob and verify it matches the algorithm.
    let blob_bits = be32(key, 0) as usize;
    if blob_bits != key_bits {
        return SignatureStatus::Invalid;
    }

    // Extract the RSA modulus (n).
    let modulus = &key[AVB_KEY_HEADER_LEN..AVB_KEY_HEADER_LEN + key_bytes];

    // AVB always uses the standard RSA public exponent 65537 (0x10001).
    let exponent = rsa::BigUint::from_bytes_be(&65537u64.to_be_bytes());
    let n = rsa::BigUint::from_bytes_be(modulus);

    // Build the RSA public key. For >4096-bit keys (RSA-8192) we bypass the
    // default size check, since the crate caps RsaPublicKey::new at 4096 bits.
    let pubkey = if key_bits <= 4096 {
        match RsaPublicKey::new(n, exponent) {
            Ok(k) => k,
            Err(_) => return SignatureStatus::Invalid,
        }
    } else {
        RsaPublicKey::new_unchecked(n, exponent)
    };

    // Compute the raw hash that was signed.
    let digest = match auth_hash(algorithm, signed) {
        Some(d) => d,
        None => return SignatureStatus::Invalid,
    };

    // PKCS#1 v1.5 with the standard DigestInfo prefix for the matching hash.
    let (prefix, hash_len) = match algorithm {
        1..=3 => (pkcs1v15_sha256_prefix(), 32),
        4..=6 => (pkcs1v15_sha512_prefix(), 64),
        _ => return SignatureStatus::Invalid,
    };

    let scheme = Pkcs1v15Sign {
        hash_len: Some(hash_len),
        prefix: prefix.into_boxed_slice(),
    };

    if pubkey.verify(scheme, &digest, signature).is_ok() {
        SignatureStatus::Valid
    } else {
        SignatureStatus::Invalid
    }
}

/// Read a PEM-encoded RSA public key from a file, returning the key for
/// external verification. Supports both PKCS#1 (`BEGIN RSA PUBLIC KEY`) and
/// PKCS#8 / SubjectPublicKeyInfo (`BEGIN PUBLIC KEY`) formats.
pub fn read_key(path: &Path) -> Result<RsaPublicKey> {
    refuse_blocking_file(path)?;
    ensure!(
        !path.is_dir(),
        "{} is a directory, not a key file",
        path.display()
    );
    let mut f = File::open(path).with_context(|| format!("opening {}", path.display()))?;
    let mut pem = String::new();
    f.read_to_string(&mut pem)?;
    // Try PKCS#8 / SubjectPublicKeyInfo first (BEGIN PUBLIC KEY), then PKCS#1 (BEGIN RSA PUBLIC KEY).
    rsa::pkcs8::DecodePublicKey::from_public_key_pem(&pem)
        .or_else(|_| rsa::pkcs1::DecodeRsaPublicKey::from_pkcs1_pem(&pem))
        .with_context(|| "invalid PEM RSA public key")
}

/// Verify an RSA signature using an externally supplied public key instead of
/// the key embedded in the vbmeta image.
fn verify_with_external_key(
    algorithm: u32,
    pubkey: &RsaPublicKey,
    signature: &[u8],
    signed: &[u8],
) -> SignatureStatus {
    // Determine the hash algorithm from the AVB algorithm type.
    let (prefix, hash_len) = match algorithm {
        1..=3 => (pkcs1v15_sha256_prefix(), 32),
        4..=6 => (pkcs1v15_sha512_prefix(), 64),
        _ => return SignatureStatus::Unsupported(algorithm),
    };
    let digest = match auth_hash(algorithm, signed) {
        Some(d) => d,
        None => return SignatureStatus::Invalid,
    };
    let scheme = Pkcs1v15Sign {
        hash_len: Some(hash_len),
        prefix: prefix.into_boxed_slice(),
    };
    if pubkey.verify(scheme, &digest, signature).is_ok() {
        SignatureStatus::Valid
    } else {
        SignatureStatus::Invalid
    }
}

fn flag_names(flags: u32) -> String {
    let mut n = Vec::new();
    if flags & FLAG_HASHTREE_DISABLED != 0 {
        n.push("HASHTREE_DISABLED");
    }
    if flags & FLAG_VERIFICATION_DISABLED != 0 {
        n.push("VERIFICATION_DISABLED");
    }
    if flags & FLAG_ALLOW_ROLLBACK != 0 {
        n.push("ALLOW_ROLLBACK");
    }
    if flags & !(FLAG_HASHTREE_DISABLED | FLAG_VERIFICATION_DISABLED | FLAG_ALLOW_ROLLBACK) != 0 {
        n.push("unknown bits");
    }
    if n.is_empty() {
        "none".into()
    } else {
        n.join(", ")
    }
}

struct Cur<'a> {
    b: &'a [u8],
    p: usize,
}

impl<'a> Cur<'a> {
    fn take(&mut self, n: u64) -> Result<&'a [u8]> {
        let n = usize::try_from(n).ok();
        let end = n
            .and_then(|n| self.p.checked_add(n))
            .filter(|e| *e <= self.b.len());
        let end = end.context("a descriptor field runs past the end of its descriptor")?;
        let s = &self.b[self.p..end];
        self.p = end;
        Ok(s)
    }

    fn u32(&mut self) -> Result<u32> {
        Ok(u32::from_be_bytes(
            self.take(4)?.try_into().expect("4 bytes"),
        ))
    }

    fn u64(&mut self) -> Result<u64> {
        Ok(u64::from_be_bytes(
            self.take(8)?.try_into().expect("8 bytes"),
        ))
    }
}

fn be32(b: &[u8], at: usize) -> u32 {
    u32::from_be_bytes(b[at..at + 4].try_into().expect("4 bytes"))
}

fn be64(b: &[u8], at: usize) -> u64 {
    u64::from_be_bytes(b[at..at + 8].try_into().expect("8 bytes"))
}

/// `region[offset..offset + size]`, or an error naming the field.
fn range<'a>(region: &'a [u8], offset: u64, size: u64, what: &str) -> Result<&'a [u8]> {
    let end = offset
        .checked_add(size)
        .filter(|e| *e <= region.len() as u64);
    let end = end.with_context(|| {
        format!("the {what} (offset {offset}, size {size}) lies outside its block")
    })?;
    Ok(&region[offset as usize..end as usize])
}

fn algorithm_field(b: &[u8]) -> String {
    let end = b.iter().position(|c| *c == 0).unwrap_or(b.len());
    text(&b[..end])
}

fn parse_descriptor(tag: u64, body: &[u8]) -> Result<Descriptor> {
    let mut c = Cur { b: body, p: 0 };
    Ok(match tag {
        TAG_PROPERTY => {
            let (klen, vlen) = (c.u64()?, c.u64()?);
            let key = text(c.take(klen)?);
            ensure!(c.take(1)? == [0], "a property key is not NUL-terminated");
            let value = text(c.take(vlen)?);
            ensure!(c.take(1)? == [0], "a property value is not NUL-terminated");
            Descriptor::Property { key, value }
        }
        TAG_HASH => {
            let image_size = c.u64()?;
            let algorithm = algorithm_field(c.take(32)?);
            let (name_len, salt_len, digest_len, flags) = (c.u32()?, c.u32()?, c.u32()?, c.u32()?);
            c.take(60)?;
            let partition = text(c.take(name_len as u64)?);
            let salt = c.take(salt_len as u64)?.to_vec();
            let digest = c.take(digest_len as u64)?.to_vec();
            Descriptor::Hash(HashDescriptor {
                partition,
                algorithm,
                image_size,
                salt,
                digest,
                flags,
            })
        }
        TAG_HASHTREE => {
            let version = c.u32()?;
            let (image_size, tree_offset, tree_size) = (c.u64()?, c.u64()?, c.u64()?);
            let (data_block_size, hash_block_size, fec_num_roots) = (c.u32()?, c.u32()?, c.u32()?);
            let (fec_offset, fec_size) = (c.u64()?, c.u64()?);
            let algorithm = algorithm_field(c.take(32)?);
            let (name_len, salt_len, root_len, flags) = (c.u32()?, c.u32()?, c.u32()?, c.u32()?);
            c.take(60)?;
            let partition = text(c.take(name_len as u64)?);
            let salt = c.take(salt_len as u64)?.to_vec();
            let root_digest = c.take(root_len as u64)?.to_vec();
            Descriptor::Hashtree(HashtreeDescriptor {
                partition,
                algorithm,
                version,
                image_size,
                tree_offset,
                tree_size,
                data_block_size,
                hash_block_size,
                fec_num_roots,
                fec_offset,
                fec_size,
                salt,
                root_digest,
                flags,
            })
        }
        TAG_KERNEL_CMDLINE => {
            let flags = c.u32()?;
            let len = c.u32()?;
            Descriptor::KernelCmdline {
                flags,
                text: text(c.take(len as u64)?),
            }
        }
        TAG_CHAIN_PARTITION => {
            let rollback_index_location = c.u32()?;
            let (name_len, key_len) = (c.u32()?, c.u32()?);
            c.take(64)?;
            let partition = text(c.take(name_len as u64)?);
            let key = c.take(key_len as u64)?;
            Descriptor::ChainPartition {
                partition,
                rollback_index_location,
                public_key_sha256: hex(&Sha256::digest(key)),
            }
        }
        other => Descriptor::Unknown {
            tag: other,
            len: body.len() as u64,
        },
    })
}

/// Total size (header + authentication + auxiliary) the header at the start of `head` claims.
fn block_len(head: &[u8]) -> Result<u64> {
    ensure!(head.len() >= HEADER_LEN, "too short for a vbmeta header");
    ensure!(&head[..4] == b"AVB0", "not a vbmeta block: bad magic");
    let total = (HEADER_LEN as u64)
        .checked_add(be64(head, 12))
        .and_then(|t| t.checked_add(be64(head, 20)))
        .context("the vbmeta block size overflows")?;
    ensure!(
        total <= MAX_VBMETA,
        "the vbmeta block claims {total} bytes, over the {MAX_VBMETA}-byte limit"
    );
    Ok(total)
}

pub fn parse(data: &[u8], external_key: Option<&RsaPublicKey>) -> Result<Vbmeta> {
    let total = block_len(data)?;
    ensure!(
        total <= data.len() as u64,
        "the vbmeta block claims {total} bytes but only {} are present",
        data.len()
    );
    let (auth_size, aux_size) = (be64(data, 12), be64(data, 20));
    let algorithm = be32(data, 28);
    let auth = &data[HEADER_LEN..HEADER_LEN + auth_size as usize];
    let aux = &data[HEADER_LEN + auth_size as usize..total as usize];

    let hash = range(auth, be64(data, 32), be64(data, 40), "authentication hash")?;
    let signature = range(auth, be64(data, 48), be64(data, 56), "signature")?;
    let key = range(aux, be64(data, 64), be64(data, 72), "public key")?;
    let metadata = range(aux, be64(data, 80), be64(data, 88), "public key metadata")?;
    let descs = range(aux, be64(data, 96), be64(data, 104), "descriptor area")?;

    // the hash covers the header followed by the auxiliary block
    let mut signed = data[..HEADER_LEN].to_vec();
    signed.extend_from_slice(aux);
    let digest_ok = auth_hash(algorithm, &signed).map(|d| d == hash);
    let signature_verified = if algorithm == 0 {
        SignatureStatus::Absent
    } else if let Some(ext_key) = external_key {
        verify_with_external_key(algorithm, ext_key, signature, &signed)
    } else {
        verify_rsa_signature(algorithm, key, signature, &signed)
    };

    let mut descriptors = Vec::new();
    let mut p = 0usize;
    while p < descs.len() {
        ensure!(
            descriptors.len() < MAX_DESCRIPTORS,
            "more than {MAX_DESCRIPTORS} descriptors"
        );
        ensure!(
            p + 16 <= descs.len(),
            "a descriptor header runs past the descriptor area"
        );
        let (tag, n) = (be64(descs, p), be64(descs, p + 8));
        ensure!(
            n % 8 == 0,
            "a descriptor length ({n}) is not a multiple of 8"
        );
        let end = (p as u64 + 16)
            .checked_add(n)
            .filter(|e| *e <= descs.len() as u64);
        let end = end.context("a descriptor runs past the descriptor area")? as usize;
        descriptors.push(
            parse_descriptor(tag, &descs[p + 16..end])
                .with_context(|| format!("descriptor {} (tag {tag})", descriptors.len()))?,
        );
        p = end;
    }

    let public_key_bits = (key.len() >= 4).then(|| be32(key, 0));
    Ok(Vbmeta {
        libavb: (be32(data, 4), be32(data, 8)),
        algorithm,
        rollback_index: be64(data, 112),
        flags: be32(data, 120),
        rollback_index_location: be32(data, 124),
        release: algorithm_field(&data[128..176]),
        auth_size,
        aux_size,
        signature_len: signature.len() as u64,
        public_key_bits,
        public_key_sha256: (!key.is_empty()).then(|| hex(&Sha256::digest(key))),
        public_key_metadata_len: metadata.len() as u64,
        digest_ok,
        signature_verified,
        descriptors,
        footer: None,
    })
}

fn parse_footer(b: &[u8]) -> Option<Footer> {
    (b.len() == FOOTER_LEN && &b[..4] == b"AVBf").then(|| Footer {
        version: (be32(b, 4), be32(b, 8)),
        original_image_size: be64(b, 12),
        vbmeta_offset: be64(b, 20),
        vbmeta_size: be64(b, 28),
    })
}

/// Read the vbmeta of a `vbmeta.img`-style file or of a partition image with an AVB footer.
pub fn read_input(path: &Path, external_key: Option<&RsaPublicKey>) -> Result<Vbmeta> {
    refuse_blocking_file(path)?;
    ensure!(
        !path.is_dir(),
        "{} is a directory, not an image",
        path.display()
    );
    let mut f = File::open(path).with_context(|| format!("opening {}", path.display()))?;
    let len = f.metadata()?.len();
    let mut head = vec![0u8; HEADER_LEN.min(len as usize)];
    f.read_exact(&mut head)?;
    if head.starts_with(b"AVB0") {
        let total = block_len(&head)?.min(len);
        let mut data = vec![0u8; total as usize];
        f.seek(SeekFrom::Start(0))?;
        f.read_exact(&mut data)?;
        return parse(&data, external_key);
    }
    ensure!(
        len >= FOOTER_LEN as u64,
        "not an AVB image: no vbmeta header and too short for a footer"
    );
    let mut tail = vec![0u8; FOOTER_LEN];
    f.seek(SeekFrom::Start(len - FOOTER_LEN as u64))?;
    f.read_exact(&mut tail)?;
    let Some(footer) = parse_footer(&tail) else {
        bail!("not an AVB image: no vbmeta header at the start and no AVB footer at the end")
    };
    ensure!(
        footer.vbmeta_size <= MAX_VBMETA
            && footer
                .vbmeta_offset
                .checked_add(footer.vbmeta_size)
                .is_some_and(|e| e <= len - FOOTER_LEN as u64),
        "the AVB footer points outside the image (offset {}, size {})",
        footer.vbmeta_offset,
        footer.vbmeta_size
    );
    let mut data = vec![0u8; footer.vbmeta_size as usize];
    f.seek(SeekFrom::Start(footer.vbmeta_offset))?;
    f.read_exact(&mut data)?;
    let mut meta =
        parse(&data, external_key).context("reading the vbmeta block the footer points to")?;
    meta.footer = Some(footer);
    Ok(meta)
}

#[derive(Debug, Clone, PartialEq)]
pub enum Check {
    Ok,
    Mismatch,
    Missing,
    Unsupported(String),
}

/// Result of interpreting the vbmeta rollback index.
///
/// The rollback index protects against downgrades: the device stores the highest
/// value it has seen and refuses to boot an image with a lower index. An index of
/// zero on a production image is suspicious because it usually means the image was
/// built before anti-rollback was enabled, or the vendor never set a meaningful
/// value. The interpretation never claims "secure" — it only flags when the index
/// looks older than expected.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RollbackIndexInterpretation {
    pub detail: String,
    pub severity: crate::audit::Severity,
}

impl RollbackIndexInterpretation {
    fn to_text(&self) -> String {
        format!("{} [{}]", self.detail, self.severity.name())
    }
}

/// A named security state derived from the vbmeta image flags.
///
/// Each variant maps to a bit in AVB_VBMETA_IMAGE_FLAGS (see avb_vbmeta_image.h)
/// plus the vendor ALLOW_ROLLBACK flag. The raw hex is always reported alongside
/// so an analyst can see both the machine-readable value and the interpretation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SecurityState {
    /// AVB_VBMETA_IMAGE_FLAGS_HASHTREE_DISABLED (bit 0, 0x01): hash-tree
    /// verification is disabled. dm-verity is not enforced.
    HashtreeDisabled,
    /// AVB_VBMETA_IMAGE_FLAGS_VERIFICATION_DISABLED (bit 1, 0x02): AVB
    /// verification is disabled and descriptors are not parsed. This is
    /// equivalent to a disabled secure boot.
    VerificationDisabled,
    /// AVB_VBMETA_IMAGE_FLAGS_ALLOW_ROLLBACK (bit 2, 0x04): the device is
    /// unlocked and the anti-rollback index may move backwards.
    UnlockedDevice,
}

impl SecurityState {
    /// The AVB flag constant name.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::HashtreeDisabled => "HASHTREE_DISABLED",
            Self::VerificationDisabled => "VERIFICATION_DISABLED",
            Self::UnlockedDevice => "UNLOCKED_DEVICE",
        }
    }

    /// A short human-readable explanation of what the state means for security.
    pub fn explanation(&self) -> &'static str {
        match self {
            Self::HashtreeDisabled => "hash-tree verification is disabled (dm-verity not enforced)",
            Self::VerificationDisabled => {
                "AVB verification is disabled, descriptors are not parsed (secure boot off)"
            }
            Self::UnlockedDevice => "device is unlocked; rollback index may move backwards",
        }
    }
}

/// Hash each hash-descriptor partition found as `<dir>/<partition>.img` and compare with the digest.
pub fn verify_images(meta: &Vbmeta, dir: &Path) -> Result<Vec<(String, Check)>> {
    let mut out = Vec::new();
    for d in &meta.descriptors {
        let Descriptor::Hash(h) = d else { continue };
        let safe = !h.partition.is_empty()
            && h.partition
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-');
        let path = dir.join(format!("{}.img", h.partition));
        let result = if !safe || !path.is_file() {
            Check::Missing
        } else {
            match h.algorithm.as_str() {
                "sha256" => hash_file::<Sha256>(&path, h)?,
                "sha512" => hash_file::<Sha512>(&path, h)?,
                other => Check::Unsupported(format!("hash algorithm {other:?}")),
            }
        };
        out.push((h.partition.clone(), result));
    }
    Ok(out)
}

fn hash_file<D: Digest>(path: &Path, h: &HashDescriptor) -> Result<Check> {
    refuse_blocking_file(path)?;
    let mut f = File::open(path).with_context(|| format!("opening {}", path.display()))?;
    let len = f.metadata()?.len();
    if h.image_size > len {
        return Ok(Check::Mismatch);
    }
    let mut hasher = D::new();
    hasher.update(&h.salt);
    let (mut left, mut buf) = (h.image_size, vec![0u8; CHUNK]);
    while left > 0 {
        let n = left.min(CHUNK as u64) as usize;
        f.read_exact(&mut buf[..n])?;
        hasher.update(&buf[..n]);
        left -= n as u64;
    }
    Ok(if hasher.finalize().as_slice() == h.digest.as_slice() {
        Check::Ok
    } else {
        Check::Mismatch
    })
}

fn descriptor_json(d: &Descriptor) -> Value {
    match d {
        Descriptor::Property { key, value } => {
            json!({"type": "property", "key": key, "value": value})
        }
        Descriptor::Hash(h) => json!({
            "type": "hash", "partition": h.partition, "algorithm": h.algorithm, "image_size": h.image_size,
            "salt": hex(&h.salt), "digest": hex(&h.digest), "flags": h.flags,
        }),
        Descriptor::Hashtree(h) => json!({
            "type": "hashtree", "partition": h.partition, "algorithm": h.algorithm, "version": h.version,
            "image_size": h.image_size, "tree_offset": h.tree_offset, "tree_size": h.tree_size,
            "data_block_size": h.data_block_size, "hash_block_size": h.hash_block_size,
            "fec_num_roots": h.fec_num_roots, "fec_offset": h.fec_offset, "fec_size": h.fec_size,
            "salt": hex(&h.salt), "root_digest": hex(&h.root_digest), "flags": h.flags,
        }),
        Descriptor::KernelCmdline { flags, text } => {
            json!({"type": "kernel_cmdline", "flags": flags, "cmdline": text})
        }
        Descriptor::ChainPartition {
            partition,
            rollback_index_location,
            public_key_sha256,
        } => json!({
            "type": "chain_partition", "partition": partition,
            "rollback_index_location": rollback_index_location, "public_key_sha256": public_key_sha256,
        }),
        Descriptor::Unknown { tag, len } => json!({"type": "unknown", "tag": tag, "bytes": len}),
    }
}

impl SignatureStatus {
    /// Serialize to a JSON value for the `signature_verified` field.
    fn to_json(&self) -> Value {
        match self {
            SignatureStatus::Valid => json!("valid"),
            SignatureStatus::Invalid => json!("invalid"),
            SignatureStatus::Absent => json!("absent"),
            SignatureStatus::Unsupported(n) => json!({"unsupported": n}),
        }
    }
    /// Human-readable one-liner for text output.
    fn to_text(&self) -> String {
        match self {
            SignatureStatus::Valid => "ok".into(),
            SignatureStatus::Invalid => "FAILED".into(),
            SignatureStatus::Absent => "n/a (no signature)".into(),
            SignatureStatus::Unsupported(n) => format!("not checked (algorithm {n} not supported)"),
        }
    }
}

impl Vbmeta {
    /// Named security states derived from the vbmeta image flags.
    pub fn security_states(&self) -> Vec<SecurityState> {
        let mut s = Vec::new();
        if self.flags & FLAG_HASHTREE_DISABLED != 0 {
            s.push(SecurityState::HashtreeDisabled);
        }
        if self.flags & FLAG_VERIFICATION_DISABLED != 0 {
            s.push(SecurityState::VerificationDisabled);
        }
        if self.flags & FLAG_ALLOW_ROLLBACK != 0 {
            s.push(SecurityState::UnlockedDevice);
        }
        s
    }

    /// Security findings derived from the vbmeta image, suitable for the audit
    /// command's finding list. Returns high-severity findings for unlocked /
    /// verification-disabled states, and never infers "secure" from absence.
    pub fn findings(&self) -> Vec<crate::audit::Finding> {
        let mut out = Vec::new();
        for s in self.security_states() {
            out.push(crate::audit::Finding {
                severity: crate::audit::Severity::High,
                rule: "avb-security-state",
                detail: format!("{}: {}", s.as_str(), s.explanation()),
            });
        }
        if self.signature_verified == SignatureStatus::Absent {
            if self.footer.is_some() {
                // A partition footer with Algorithm NONE is how AVB normally ships a partition:
                // the signed top-level vbmeta carries its hash descriptor and the signature.
                out.push(crate::audit::Finding {
                    severity: crate::audit::Severity::Info,
                    rule: "avb-unsigned-footer",
                    detail: "partition footer carries no signature (algorithm NONE); normal when a signed top-level vbmeta covers this partition, which is not checked here".into(),
                });
            } else {
                // An unsigned top-level vbmeta (Algorithm NONE / 0) means verified boot proves nothing.
                out.push(crate::audit::Finding {
                    severity: crate::audit::Severity::High,
                    rule: "avb-unsigned-image",
                    detail: "no signature present; verified boot proves nothing".into(),
                });
            }
        }
        // Unsupported algorithm: cannot check the signature.
        if let SignatureStatus::Unsupported(n) = self.signature_verified {
            out.push(crate::audit::Finding {
                severity: crate::audit::Severity::Warn,
                rule: "avb-unsupported-algorithm",
                detail: format!("signature not checked (algorithm {} not supported)", n),
            });
        }
        out
    }

    /// Interpret the rollback index. Reports the raw value. Index 0 is what `avbtool` writes
    /// by default, so it is no evidence of an old image: it only means the image records no
    /// rollback protection value. Never infers security from absence.
    pub fn rollback_index_interpretation(&self) -> RollbackIndexInterpretation {
        let detail = if self.rollback_index == 0 {
            format!(
                "rollback index {} (location {}): the default; this image records no rollback protection value",
                self.rollback_index, self.rollback_index_location
            )
        } else {
            format!(
                "rollback index {} (location {}): within expected range",
                self.rollback_index, self.rollback_index_location
            )
        };
        RollbackIndexInterpretation {
            detail,
            severity: crate::audit::Severity::Info,
        }
    }

    pub fn to_json(&self, checks: &[(String, Check)]) -> Value {
        json!({
            "libavb": format!("{}.{}", self.libavb.0, self.libavb.1),
            "algorithm": algorithm_name(self.algorithm),
            "rollback_index": self.rollback_index,
            "rollback_index_location": self.rollback_index_location,
            "flags": self.flags,
            "flag_names": flag_names(self.flags),
            "security_states": self.security_states().iter().map(|s| json!({"name": s.as_str(), "explanation": s.explanation()})).collect::<Vec<_>>(),
            "rollback_index_interpretation": json!({"detail": self.rollback_index_interpretation().detail, "severity": self.rollback_index_interpretation().severity.name()}),
            "release": self.release,
            "findings": self.findings().iter().map(|f| json!({
                "severity": f.severity.name(),
                "rule": f.rule,
                "detail": f.detail,
            })).collect::<Vec<_>>(),
            "authentication_block": self.auth_size,
            "auxiliary_block": self.aux_size,
            "signature_bytes": self.signature_len,
            "public_key_bits": self.public_key_bits,
            "public_key_sha256": self.public_key_sha256,
            "public_key_metadata_bytes": self.public_key_metadata_len,
            "digest_ok": self.digest_ok,
            "signature_verified": self.signature_verified.to_json(),
            "footer": self.footer.as_ref().map(|f| json!({
                "version": format!("{}.{}", f.version.0, f.version.1),
                "original_image_size": f.original_image_size,
                "vbmeta_offset": f.vbmeta_offset, "vbmeta_size": f.vbmeta_size,
            })),
            "descriptors": self.descriptors.iter().map(descriptor_json).collect::<Vec<_>>(),
            "partition_checks": checks.iter().map(|(n, c)| json!({"partition": n, "result": check_label(c)})).collect::<Vec<_>>(),
        })
    }

    pub fn to_text(&self, checks: &[(String, Check)]) -> String {
        let mut o = vec![format!(
            "vbmeta: libavb {}.{}, algorithm {}, rollback index {} (location {}), flags {:#x} [{}]",
            self.libavb.0,
            self.libavb.1,
            algorithm_name(self.algorithm),
            self.rollback_index,
            self.rollback_index_location,
            self.flags,
            flag_names(self.flags)
        )];
        // Security states: named interpretations of the flag bits, reported
        // alongside the raw hex so absence is never mistaken for safety.
        let states = self.security_states();
        if states.is_empty() {
            o.push("security: no unlocked/verification-disabled states detected".into());
        } else {
            for s in &states {
                o.push(format!("  security: {} — {}", s.as_str(), s.explanation()));
            }
        }
        // Rollback index interpretation
        o.push(self.rollback_index_interpretation().to_text());
        o.push(format!("release string: {:?}", self.release));
        let findings = self.findings();
        if !findings.is_empty() {
            o.push("security findings:".into());
            for f in &findings {
                o.push(format!(
                    "  [{}] {}: {}",
                    f.severity.name(),
                    f.rule,
                    f.detail
                ));
            }
        }
        o.push(format!(
            "authentication block {} bytes, auxiliary block {} bytes; digest check: {}; signature: {}",
            self.auth_size,
            self.aux_size,
            match self.digest_ok {
                Some(true) => "ok",
                Some(false) => "MISMATCH",
                None => "n/a (no signature)",
            },
            self.signature_verified.to_text()
        ));
        if let (Some(bits), Some(sha)) = (self.public_key_bits, &self.public_key_sha256) {
            o.push(format!("public key: {bits} bits, sha256 {sha}"));
        }
        if let Some(f) = &self.footer {
            o.push(format!(
                "footer {}.{}: original image {} bytes, vbmeta at {} ({} bytes)",
                f.version.0, f.version.1, f.original_image_size, f.vbmeta_offset, f.vbmeta_size
            ));
        }
        o.push(format!("{} descriptors:", self.descriptors.len()));
        for d in &self.descriptors {
            o.push(match d {
                Descriptor::Property { key, value } => format!("  prop {key} = {value}"),
                Descriptor::Hash(h) => format!(
                    "  hash {}: {} over {} bytes, salt {}, digest {}",
                    h.partition, h.algorithm, h.image_size, hex(&h.salt), hex(&h.digest)
                ),
                Descriptor::Hashtree(h) => format!(
                    "  hashtree {}: {} v{}, data {} bytes, tree {}+{}, blocks {}/{}, fec roots {}, salt {}, root {}",
                    h.partition, h.algorithm, h.version, h.image_size, h.tree_offset, h.tree_size,
                    h.data_block_size, h.hash_block_size, h.fec_num_roots, hex(&h.salt), hex(&h.root_digest)
                ),
                Descriptor::KernelCmdline { flags, text } => format!("  cmdline (flags {flags:#x}): {text}"),
                Descriptor::ChainPartition { partition, rollback_index_location, public_key_sha256 } => {
                    format!("  chain {partition}: rollback location {rollback_index_location}, key sha256 {public_key_sha256}")
                }
                Descriptor::Unknown { tag, len } => format!("  unknown descriptor tag {tag} ({len} bytes)"),
            });
        }
        for (n, c) in checks {
            o.push(format!("check {n}: {}", check_label(c)));
        }
        o.join("\n")
    }

    pub fn any_failure(&self, checks: &[(String, Check)]) -> bool {
        self.digest_ok == Some(false)
            || self.signature_verified == SignatureStatus::Invalid
            || self.signature_verified == SignatureStatus::Absent
            || checks.iter().any(|(_, c)| *c == Check::Mismatch)
    }

    /// Cross-check the top-level vbmeta against chained vbmeta partitions.
    ///
    /// When the top-level vbmeta has ChainPartition descriptors, each chained
    /// partition carries its own vbmeta with its own flags and rollback index.
    /// This method reads those chained vbmeta files from the given directory and
    /// returns findings if a chained vbmeta has verification disabled or an
    /// unlocked device flag, or if its rollback index is lower than the
    /// top-level index.
    pub fn cross_check_chained(&self, dir: &Path) -> Vec<crate::audit::Finding> {
        let mut out = Vec::new();
        let top_ri = self.rollback_index;
        for d in &self.descriptors {
            let Descriptor::ChainPartition { partition, .. } = d else {
                continue;
            };
            let path = dir.join(format!("{partition}.img"));
            if !path.is_file() {
                continue;
            }
            let chained = match read_input(&path, None) {
                Ok(m) => m,
                Err(_) => continue,
            };
            // Check the chained vbmeta's own security state.
            for s in chained.security_states() {
                out.push(crate::audit::Finding {
                    severity: crate::audit::Severity::High,
                    rule: "avb-chained-security-state",
                    detail: format!(
                        "chained vbmeta {}: {} - {}",
                        partition,
                        s.as_str(),
                        s.explanation()
                    ),
                });
            }
            // Check for unsigned / unsupported algorithm in chained vbmeta.
            for f in chained.findings() {
                // A chained partition's own vbmeta must be signed with the chain descriptor's
                // key, so an unsigned footer here is a real problem, unlike on a bare partition.
                if matches!(
                    f.rule,
                    "avb-unsigned-image" | "avb-unsigned-footer" | "avb-unsupported-algorithm"
                ) {
                    out.push(crate::audit::Finding {
                        severity: if f.rule == "avb-unsigned-footer" {
                            crate::audit::Severity::High
                        } else {
                            f.severity
                        },
                        rule: "avb-chained-security-state",
                        detail: format!("chained vbmeta {}: {}", partition, f.detail),
                    });
                }
            }
            // Compare rollback indices.
            if chained.rollback_index < top_ri {
                out.push(crate::audit::Finding {
                    severity: crate::audit::Severity::High,
                    rule: "avb-rollback-index",
                    detail: format!(
                        "chained vbmeta {} rollback index {} is lower than top-level index {}",
                        partition, chained.rollback_index, top_ri
                    ),
                });
            }
        }
        out
    }
}

fn check_label(c: &Check) -> String {
    match c {
        Check::Ok => "ok".into(),
        Check::Mismatch => "MISMATCH".into(),
        Check::Missing => "image not found".into(),
        Check::Unsupported(why) => format!("not checked ({why})"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn desc(tag: u64, body: &[u8]) -> Vec<u8> {
        let mut b = body.to_vec();
        b.resize(b.len().div_ceil(8) * 8, 0);
        let mut v = tag.to_be_bytes().to_vec();
        v.extend((b.len() as u64).to_be_bytes());
        v.extend(b);
        v
    }

    fn prop(k: &str, v: &str) -> Vec<u8> {
        let mut b = (k.len() as u64).to_be_bytes().to_vec();
        b.extend((v.len() as u64).to_be_bytes());
        b.extend(k.as_bytes());
        b.push(0);
        b.extend(v.as_bytes());
        b.push(0);
        desc(TAG_PROPERTY, &b)
    }

    fn alg32(name: &str) -> Vec<u8> {
        let mut a = name.as_bytes().to_vec();
        a.resize(32, 0);
        a
    }

    fn hash_desc(name: &str, size: u64, salt: &[u8], digest: &[u8]) -> Vec<u8> {
        let mut b = size.to_be_bytes().to_vec();
        b.extend(alg32("sha256"));
        for n in [name.len(), salt.len(), digest.len(), 0] {
            b.extend((n as u32).to_be_bytes());
        }
        b.extend([0u8; 60]);
        b.extend(name.as_bytes());
        b.extend(salt);
        b.extend(digest);
        desc(TAG_HASH, &b)
    }

    fn tree_desc(name: &str) -> Vec<u8> {
        let mut b = 1u32.to_be_bytes().to_vec();
        for n in [4096u64 * 10, 4096 * 10, 4096] {
            b.extend(n.to_be_bytes());
        }
        for n in [4096u32, 4096, 2] {
            b.extend(n.to_be_bytes());
        }
        for n in [45056u64, 8192] {
            b.extend(n.to_be_bytes());
        }
        b.extend(alg32("sha256"));
        for n in [name.len(), 4, 32, 1] {
            b.extend((n as u32).to_be_bytes());
        }
        b.extend([0u8; 60]);
        b.extend(name.as_bytes());
        b.extend([9u8; 4]);
        b.extend([7u8; 32]);
        desc(TAG_HASHTREE, &b)
    }

    fn cmdline(flags: u32, text: &str) -> Vec<u8> {
        let mut b = flags.to_be_bytes().to_vec();
        b.extend((text.len() as u32).to_be_bytes());
        b.extend(text.as_bytes());
        desc(TAG_KERNEL_CMDLINE, &b)
    }

    fn chain(name: &str, loc: u32, key: &[u8]) -> Vec<u8> {
        let mut b = loc.to_be_bytes().to_vec();
        b.extend((name.len() as u32).to_be_bytes());
        b.extend((key.len() as u32).to_be_bytes());
        b.extend([0u8; 64]);
        b.extend(name.as_bytes());
        b.extend(key);
        desc(TAG_CHAIN_PARTITION, &b)
    }

    /// A vbmeta block: algorithm 0 (none) or 1 (SHA256_RSA2048 with a zero signature).
    fn vbmeta(algorithm: u32, flags: u32, descs: &[Vec<u8>], key: &[u8]) -> Vec<u8> {
        let mut aux: Vec<u8> = descs.concat();
        let desc_len = aux.len();
        aux.extend(key);
        aux.resize(aux.len().div_ceil(64) * 64, 0);
        let (hash_len, sig_len): (usize, u64) = if algorithm == 0 { (0, 0) } else { (32, 256) };
        let auth_len = (hash_len + sig_len as usize).div_ceil(64) * 64;
        let mut h = vec![0u8; HEADER_LEN];
        h[..4].copy_from_slice(b"AVB0");
        h[4..8].copy_from_slice(&1u32.to_be_bytes());
        h[8..12].copy_from_slice(&0u32.to_be_bytes());
        h[12..20].copy_from_slice(&(auth_len as u64).to_be_bytes());
        h[20..28].copy_from_slice(&(aux.len() as u64).to_be_bytes());
        h[28..32].copy_from_slice(&algorithm.to_be_bytes());
        h[40..48].copy_from_slice(&(hash_len as u64).to_be_bytes());
        h[48..56].copy_from_slice(&(hash_len as u64).to_be_bytes());
        h[56..64].copy_from_slice(&sig_len.to_be_bytes());
        h[64..72].copy_from_slice(&(desc_len as u64).to_be_bytes());
        h[72..80].copy_from_slice(&(key.len() as u64).to_be_bytes());
        h[80..88].copy_from_slice(&((desc_len + key.len()) as u64).to_be_bytes());
        h[96..104].copy_from_slice(&0u64.to_be_bytes());
        h[104..112].copy_from_slice(&(desc_len as u64).to_be_bytes());
        h[112..120].copy_from_slice(&1234u64.to_be_bytes());
        h[120..124].copy_from_slice(&flags.to_be_bytes());
        h[124..128].copy_from_slice(&3u32.to_be_bytes());
        h[128..128 + 9].copy_from_slice(b"test 1.0\0");
        let mut auth = vec![0u8; auth_len];
        if algorithm != 0 {
            let mut signed = h.clone();
            signed.extend(&aux);
            auth[..32].copy_from_slice(&Sha256::digest(&signed));
        }
        [h, auth, aux].concat()
    }

    /// Create an AVB-format public key blob from an RSA private key, as `avbtool` writes it
    /// (`AvbRSAPublicKeyHeader`): `key_num_bits` and `n0inv` as big-endian u32, then the modulus
    /// and `rr` = 2^(2 * bits) mod n, each `bits / 8` bytes big-endian. 520 bytes for RSA-2048.
    fn key_blob_from_key(key: &RsaPrivateKey) -> Vec<u8> {
        let bits = key.n().bits() as u32;
        let key_bytes = (bits / 8) as usize;
        let pad = |v: Vec<u8>| {
            let mut out = vec![0u8; key_bytes - v.len()];
            out.extend(v);
            out
        };
        // n0inv = -(n^-1) mod 2^32, by Newton's iteration on the low word.
        let n0 = key.n().to_bytes_le()[..4]
            .iter()
            .rev()
            .fold(0u32, |a, b| (a << 8) | u32::from(*b));
        let mut inv = n0;
        for _ in 0..5 {
            inv = inv.wrapping_mul(2u32.wrapping_sub(n0.wrapping_mul(inv)));
        }
        let rr = (rsa::BigUint::from(1u8) << (2 * bits as usize)) % key.n();
        let mut k = bits.to_be_bytes().to_vec();
        k.extend(inv.wrapping_neg().to_be_bytes());
        k.extend(pad(key.n().to_bytes_be()));
        k.extend(pad(rr.to_bytes_be()));
        assert_eq!(k.len(), 8 + 2 * key_bytes);
        k
    }

    /// Create an AVB-format public key blob with a fake key of the given bit size.
    /// Only the header is real; the modulus and `rr` are filler. Used for tests that
    /// don't exercise RSA verification.
    fn key_blob(bits: u32) -> Vec<u8> {
        let key_bytes = (bits as usize) / 8;
        let mut k = bits.to_be_bytes().to_vec();
        k.extend([0u8; 4]); // n0inv
        k.resize(8 + 2 * key_bytes, 5u8);
        k
    }

    /// Build a properly signed vbmeta block using a real RSA private key.
    /// The key blob, authentication hash, and signature are all computed from scratch.
    fn vbmeta_signed(
        algorithm: u32,
        flags: u32,
        descs: &[Vec<u8>],
        priv_key: &RsaPrivateKey,
    ) -> Vec<u8> {
        let key_blob = key_blob_from_key(priv_key);
        let key_bits = algorithm_key_bits(algorithm).unwrap();
        let sig_len = key_bits / 8;
        let hash_len = match algorithm {
            1..=3 => 32,
            4..=6 => 64,
            _ => 0,
        };

        // Build the auxiliary block: descriptors + public key, padded to 64 bytes.
        let mut aux: Vec<u8> = descs.concat();
        let desc_len = aux.len();
        aux.extend(&key_blob);
        aux.resize(aux.len().div_ceil(64) * 64, 0);

        let auth_len = (hash_len + sig_len).div_ceil(64) * 64;

        // Build the header.
        let mut h = vec![0u8; HEADER_LEN];
        h[..4].copy_from_slice(b"AVB0");
        h[4..8].copy_from_slice(&1u32.to_be_bytes()); // libavb major
        h[8..12].copy_from_slice(&0u32.to_be_bytes()); // libavb minor
        h[12..20].copy_from_slice(&(auth_len as u64).to_be_bytes());
        h[20..28].copy_from_slice(&(aux.len() as u64).to_be_bytes());
        h[28..32].copy_from_slice(&algorithm.to_be_bytes());
        h[40..48].copy_from_slice(&(hash_len as u64).to_be_bytes()); // hash offset in auth
        h[48..56].copy_from_slice(&(hash_len as u64).to_be_bytes()); // hash size
        h[56..64].copy_from_slice(&(sig_len as u64).to_be_bytes()); // signature size
        h[64..72].copy_from_slice(&(desc_len as u64).to_be_bytes());
        h[72..80].copy_from_slice(&(key_blob.len() as u64).to_be_bytes());
        h[80..88].copy_from_slice(&((desc_len + key_blob.len()) as u64).to_be_bytes());
        h[96..104].copy_from_slice(&0u64.to_be_bytes());
        h[104..112].copy_from_slice(&(desc_len as u64).to_be_bytes());
        h[112..120].copy_from_slice(&1234u64.to_be_bytes());
        h[120..124].copy_from_slice(&flags.to_be_bytes());
        h[124..128].copy_from_slice(&3u32.to_be_bytes());
        h[128..128 + 9].copy_from_slice(b"test 1.0\0");

        // Compute the data that is signed: header + auxiliary block.
        let mut signed_data = h.clone();
        signed_data.extend(&aux);
        let digest = auth_hash(algorithm, &signed_data).unwrap();

        // Sign with PKCS#1 v1.5 using the appropriate DigestInfo prefix.
        let (prefix, _) = match algorithm {
            1..=3 => (pkcs1v15_sha256_prefix(), 32),
            4..=6 => (pkcs1v15_sha512_prefix(), 64),
            _ => unreachable!(),
        };
        let scheme = Pkcs1v15Sign {
            hash_len: Some(hash_len),
            prefix: prefix.into_boxed_slice(),
        };
        let signature = priv_key.sign(scheme, &digest).unwrap();

        let mut auth = vec![0u8; auth_len];
        auth[..hash_len].copy_from_slice(&digest);
        auth[hash_len..hash_len + sig_len].copy_from_slice(&signature);

        [h, auth, aux].concat()
    }

    #[test]
    fn parses_every_descriptor_kind() {
        let digest = [3u8; 32];
        let d = vec![
            prop("a.b", "value one"),
            hash_desc("boot", 8192, &[1, 2], &digest),
            tree_desc("system"),
            cmdline(2, "root=/dev/dm-0"),
            chain("vbmeta_system", 2, &[8u8; 40]),
            desc(99, &[1, 2, 3]),
        ];
        let m = parse(&vbmeta(1, 0, &d, &key_blob(2048)), None).unwrap();
        assert_eq!(m.libavb, (1, 0));
        assert_eq!(
            (m.rollback_index, m.rollback_index_location, m.flags),
            (1234, 3, 0)
        );
        assert_eq!(m.release, "test 1.0");
        assert_eq!(m.public_key_bits, Some(2048));
        assert_eq!(
            m.public_key_sha256.as_deref(),
            Some(hex(&Sha256::digest(key_blob(2048))).as_str())
        );
        assert_eq!(m.digest_ok, Some(true));
        assert_eq!(m.descriptors.len(), 6);
        assert_eq!(
            m.descriptors[0],
            Descriptor::Property {
                key: "a.b".into(),
                value: "value one".into()
            }
        );
        let Descriptor::Hash(h) = &m.descriptors[1] else {
            panic!()
        };
        assert_eq!(
            (h.partition.as_str(), h.algorithm.as_str(), h.image_size),
            ("boot", "sha256", 8192)
        );
        assert_eq!(
            (h.salt.as_slice(), h.digest.as_slice()),
            (&[1u8, 2][..], &digest[..])
        );
        let Descriptor::Hashtree(t) = &m.descriptors[2] else {
            panic!()
        };
        assert_eq!(
            (t.partition.as_str(), t.version, t.image_size, t.tree_size),
            ("system", 1, 40960, 4096)
        );
        assert_eq!(
            (
                t.data_block_size,
                t.fec_num_roots,
                t.fec_offset,
                t.fec_size,
                t.flags
            ),
            (4096, 2, 45056, 8192, 1)
        );
        assert_eq!(
            (t.salt.as_slice(), t.root_digest.as_slice()),
            (&[9u8; 4][..], &[7u8; 32][..])
        );
        assert_eq!(
            m.descriptors[3],
            Descriptor::KernelCmdline {
                flags: 2,
                text: "root=/dev/dm-0".into()
            }
        );
        let Descriptor::ChainPartition {
            partition,
            rollback_index_location,
            public_key_sha256,
        } = &m.descriptors[4]
        else {
            panic!()
        };
        assert_eq!(
            (partition.as_str(), *rollback_index_location),
            ("vbmeta_system", 2)
        );
        assert_eq!(public_key_sha256, &hex(&Sha256::digest([8u8; 40])));
        assert_eq!(m.descriptors[5], Descriptor::Unknown { tag: 99, len: 8 });
    }

    #[test]
    fn an_unsigned_image_has_no_digest_and_flags_are_named() {
        let m = parse(&vbmeta(0, 2, &[], &[]), None).unwrap();
        assert_eq!(
            (m.digest_ok, m.public_key_bits, m.public_key_sha256.clone()),
            (None, None, None)
        );
        assert!(m.to_text(&[]).contains("VERIFICATION_DISABLED"));
        assert!(m.to_text(&[]).contains("n/a (no signature)"));
        assert_eq!(flag_names(1), "HASHTREE_DISABLED");
        assert_eq!(flag_names(2), "VERIFICATION_DISABLED");
        assert_eq!(flag_names(3), "HASHTREE_DISABLED, VERIFICATION_DISABLED");
        assert_eq!(flag_names(4), "ALLOW_ROLLBACK");
        assert_eq!(flag_names(0), "none");
        assert_eq!(flag_names(8), "unknown bits");
    }

    #[test]
    fn a_changed_byte_breaks_the_digest() {
        let mut v = vbmeta(1, 0, &[prop("k", "v")], &key_blob(2048));
        assert_eq!(parse(&v, None).unwrap().digest_ok, Some(true));
        let last = v.len() - 1;
        v[last] ^= 1; // padding byte of the auxiliary block
        assert_eq!(parse(&v, None).unwrap().digest_ok, Some(false));
        let mut w = vbmeta(1, 0, &[prop("k", "v")], &key_blob(2048));
        w[112] ^= 1; // rollback index in the header
        assert_eq!(parse(&w, None).unwrap().digest_ok, Some(false));
        assert!(parse(&w, None).unwrap().any_failure(&[]));
    }

    #[test]
    fn sha512_algorithms_use_a_64_byte_digest() {
        assert_eq!(auth_hash(4, b"x").unwrap().len(), 64);
        assert_eq!(auth_hash(1, b"x").unwrap().len(), 32);
        assert!(auth_hash(0, b"x").is_none() && auth_hash(7, b"x").is_none());
        assert_eq!(algorithm_name(5), "SHA512_RSA4096");
        assert_eq!(algorithm_name(9), "unknown(9)");
    }

    #[test]
    fn hostile_headers_are_refused_with_a_reason() {
        let good = vbmeta(1, 0, &[prop("k", "v")], &key_blob(2048));
        let err = |v: Vec<u8>| format!("{:#}", parse(&v, None).unwrap_err());
        assert!(err(vec![0; 10]).contains("too short"));
        let mut bad_magic = good.clone();
        bad_magic[0] = b'X';
        assert!(err(bad_magic).contains("bad magic"));
        let mut huge = good.clone();
        huge[12..20].copy_from_slice(&u64::MAX.to_be_bytes());
        assert!(err(huge).contains("overflows"));
        let mut big = good.clone();
        big[20..28].copy_from_slice(&(1u64 << 40).to_be_bytes());
        assert!(err(big).contains("limit"));
        assert!(err(good[..good.len() - 64].to_vec()).contains("only"));
        for (at, what) in [
            (32usize, "authentication hash"),
            (48, "signature"),
            (64, "public key"),
            (80, "public key metadata"),
            (96, "descriptor area"),
        ] {
            let mut v = good.clone();
            v[at..at + 8].copy_from_slice(&(1u64 << 62).to_be_bytes());
            assert!(err(v).contains(what), "{what}");
        }
    }

    #[test]
    fn malformed_descriptors_are_refused() {
        let err =
            |d: Vec<Vec<u8>>| format!("{:#}", parse(&vbmeta(0, 0, &d, &[]), None).unwrap_err());
        // length not a multiple of 8
        let mut odd = prop("k", "v");
        odd[8..16].copy_from_slice(&5u64.to_be_bytes());
        assert!(err(vec![odd]).contains("multiple of 8"));
        // descriptor longer than the area
        let mut long = prop("k", "v");
        long[8..16].copy_from_slice(&4096u64.to_be_bytes());
        assert!(err(vec![long]).contains("runs past"));
        // name length beyond the descriptor
        let mut bad = hash_desc("boot", 1, &[], &[0; 32]);
        bad[16 + 8 + 32..16 + 8 + 32 + 4].copy_from_slice(&u32::MAX.to_be_bytes());
        assert!(err(vec![bad]).contains("runs past the end of its descriptor"));
        // property without its NUL terminators
        let mut nul = prop("key", "val");
        let at = 16 + 16 + 3;
        nul[at] = b'X';
        assert!(err(vec![nul]).contains("key is not NUL-terminated"));
        let mut nul2 = prop("key", "val");
        nul2[16 + 16 + 3 + 1 + 3] = b'X';
        assert!(err(vec![nul2]).contains("value is not NUL-terminated"));
        // a descriptor header cut short
        assert!(
            format!(
                "{:#}",
                parse(&vbmeta(0, 0, &[vec![0u8; 8]], &[]), None).unwrap_err()
            )
            .contains("header runs past")
        );
    }

    fn write_tmp(tag: &str, bytes: &[u8]) -> (crate::testutil::Scratch, std::path::PathBuf) {
        let g = crate::testutil::Scratch::new(&format!("avb-{tag}"));
        let p = g.join("x.img");
        std::fs::write(&p, bytes).unwrap();
        (g, p)
    }

    #[test]
    fn reads_a_padded_vbmeta_image_and_a_partition_with_a_footer() {
        let v = vbmeta(0, 0, &[prop("a", "b")], &[]);
        let mut padded = v.clone();
        padded.resize(8192, 0);
        let (_g, p) = write_tmp("pad", &padded);
        let m = read_input(&p, None).unwrap();
        assert_eq!(m.descriptors.len(), 1);
        assert!(m.footer.is_none());

        // a 1 MiB partition: data, then vbmeta at 4096, footer in the last 64 bytes
        let mut part = vec![0xAAu8; 1 << 20];
        part[4096..4096 + v.len()].copy_from_slice(&v);
        let mut footer = b"AVBf".to_vec();
        footer.extend(1u32.to_be_bytes());
        footer.extend(0u32.to_be_bytes());
        footer.extend(4096u64.to_be_bytes());
        footer.extend(4096u64.to_be_bytes());
        footer.extend((v.len() as u64).to_be_bytes());
        footer.resize(64, 0);
        let n = part.len();
        part[n - 64..].copy_from_slice(&footer);
        let (_g, p) = write_tmp("footer", &part);
        let m = read_input(&p, None).unwrap();
        let f = m.footer.unwrap();
        assert_eq!(
            (f.original_image_size, f.vbmeta_offset, f.vbmeta_size),
            (4096, 4096, v.len() as u64)
        );
        assert_eq!(m.descriptors.len(), 1);

        // footer pointing outside the image, and an image with neither
        let mut bad = part.clone();
        bad[n - 64 + 20..n - 64 + 28].copy_from_slice(&(1u64 << 50).to_be_bytes());
        assert!(
            format!(
                "{:#}",
                read_input(&write_tmp("badfoot", &bad).1, None).unwrap_err()
            )
            .contains("outside the image")
        );
        let e = format!(
            "{:#}",
            read_input(&write_tmp("none", &vec![1u8; 4096]).1, None).unwrap_err()
        );
        assert!(e.contains("not an AVB image"), "{e}");
        assert!(read_input(&write_tmp("tiny", b"AVB").1, None).is_err());
        assert!(read_input(Path::new("/definitely/not/here"), None).is_err());
    }

    #[test]
    fn partition_hashes_are_checked_against_the_descriptors() {
        let data = vec![0x5Au8; 10_000];
        let salt = [1u8, 2, 3, 4];
        let mut h = Sha256::new();
        h.update(salt);
        h.update(&data[..8192]);
        let digest = h.finalize();
        let wrong = [0u8; 32];
        let d = vec![
            hash_desc("good", 8192, &salt, &digest),
            hash_desc("bad", 8192, &salt, &wrong),
            hash_desc("missing", 8192, &salt, &digest),
            hash_desc("short", 20_000, &salt, &digest),
            hash_desc("../escape", 8192, &salt, &digest),
            tree_desc("system"),
        ];
        let m = parse(&vbmeta(0, 0, &d, &[]), None).unwrap();
        let (_g, tmp) = write_tmp("verify", b"");
        let outer = tmp.parent().unwrap().to_path_buf();
        let dir = outer.join("inner");
        std::fs::create_dir_all(&dir).unwrap();
        for n in ["good", "bad", "short"] {
            std::fs::write(dir.join(format!("{n}.img")), &data).unwrap();
        }
        // a real file one level up: a traversal in the partition name would find it
        std::fs::write(outer.join("escape.img"), &data).unwrap();
        let r = verify_images(&m, &dir).unwrap();
        let get = |n: &str| {
            r.iter()
                .find(|(p, _)| p == n)
                .map(|(_, c)| c.clone())
                .unwrap()
        };
        assert_eq!(get("good"), Check::Ok);
        assert_eq!(get("bad"), Check::Mismatch);
        assert_eq!(
            get("short"),
            Check::Mismatch,
            "an image shorter than the descriptor's size"
        );
        assert_eq!(get("missing"), Check::Missing);
        assert_eq!(
            get("../escape"),
            Check::Missing,
            "partition names cannot leave the directory"
        );
        assert_eq!(r.len(), 5, "hashtrees are not hashed");
        assert!(m.any_failure(&r));
        assert!(
            m.to_text(&r).contains("check good: ok")
                && m.to_text(&r).contains("check bad: MISMATCH")
        );
    }

    #[test]
    fn json_and_text_carry_the_main_fields() {
        let m = parse(
            &vbmeta(
                1,
                1,
                &[
                    prop("k", "v"),
                    hash_desc("boot", 1, &[], &[0; 32]),
                    tree_desc("s"),
                    cmdline(0, "c"),
                    chain("p", 1, &[1]),
                ],
                &key_blob(4096),
            ),
            None,
        )
        .unwrap();
        let j = m.to_json(&[("boot".into(), Check::Ok)]);
        assert_eq!(j["algorithm"], "SHA256_RSA2048");
        assert_eq!(j["flag_names"], "HASHTREE_DISABLED");
        assert_eq!(j["public_key_bits"], 4096);
        assert_eq!(j["digest_ok"], true);
        assert_eq!(j["signature_verified"], "invalid");
        assert_eq!(j["descriptors"].as_array().unwrap().len(), 5);
        assert_eq!(j["partition_checks"][0]["result"], "ok");
        let t = m.to_text(&[]);
        for want in [
            "prop k = v",
            "hash boot",
            "hashtree s",
            "cmdline (flags 0x0): c",
            "chain p",
            "public key: 4096 bits",
            "5 descriptors",
        ] {
            assert!(t.contains(want), "{want} in {t}");
        }
    }

    #[test]
    fn flipping_any_header_or_descriptor_byte_never_panics() {
        let v = vbmeta(
            1,
            0,
            &[
                prop("k", "v"),
                hash_desc("boot", 8192, &[1], &[3; 32]),
                tree_desc("s"),
                cmdline(0, "c"),
                chain("p", 1, &[1; 9]),
            ],
            &key_blob(2048),
        );
        let aux_at = HEADER_LEN + be64(&v, 12) as usize;
        let spots = (0..HEADER_LEN).chain(aux_at..(aux_at + 400).min(v.len()));
        let (mut ok, mut err) = (0, 0);
        for at in spots {
            for val in [0x00u8, 0xFF, 0x80, 0x01] {
                let mut w = v.clone();
                w[at] = val;
                match parse(&w, None) {
                    Ok(_) => ok += 1,
                    Err(_) => err += 1,
                }
            }
        }
        assert!(ok > 100 && err > 100, "ok={ok} err={err}");
    }

    #[test]
    fn rsa_signature_verifies_for_a_signed_block() {
        let mut rng = OsRng;
        let priv_key = RsaPrivateKey::new(&mut rng, 2048).unwrap();
        let v = vbmeta_signed(1, 0, &[prop("k", "v")], &priv_key);
        let m = parse(&v, None).unwrap();
        assert_eq!(m.algorithm, 1);
        assert_eq!(m.signature_verified, SignatureStatus::Valid);
        assert_eq!(m.digest_ok, Some(true));
        assert_eq!(m.public_key_bits, Some(2048));
        assert!(m.to_text(&[]).contains("signature: ok"));
        assert_eq!(m.to_json(&[])["signature_verified"], "valid");
    }

    #[test]
    fn a_flipped_signature_byte_breaks_rsa_verification() {
        let mut rng = OsRng;
        let priv_key = RsaPrivateKey::new(&mut rng, 2048).unwrap();
        let mut v = vbmeta_signed(1, 0, &[prop("k", "v")], &priv_key);
        // The digest is first 32 bytes of auth, then the 256-byte signature.
        let auth_start = HEADER_LEN + 64;
        let sig_start = auth_start + 32;
        v[sig_start] ^= 0x01;
        let m = parse(&v, None).unwrap();
        assert_eq!(m.digest_ok, Some(true));
        assert_eq!(m.signature_verified, SignatureStatus::Invalid);
        assert!(m.to_text(&[]).contains("signature: FAILED"));
    }

    #[test]
    fn a_flipped_header_byte_breaks_digest_and_signature() {
        let mut rng = OsRng;
        let priv_key = RsaPrivateKey::new(&mut rng, 2048).unwrap();
        let mut v = vbmeta_signed(1, 0, &[prop("k", "v")], &priv_key);
        // Flip a byte in the rollback_index field (offset 112) — structural fields
        // like auth_size/aux_size are untouched, so the block still parses.
        v[112] ^= 0x01;
        let m = parse(&v, None).unwrap();
        assert_eq!(m.digest_ok, Some(false));
        assert_eq!(m.signature_verified, SignatureStatus::Invalid);
        assert!(m.to_text(&[]).contains("digest check: MISMATCH"));
        assert!(m.to_text(&[]).contains("signature: FAILED"));
    }

    #[test]
    fn sha512_rsa4096_signature_verifies() {
        let mut rng = OsRng;
        let priv_key = RsaPrivateKey::new(&mut rng, 4096).unwrap();
        let v = vbmeta_signed(5, 0, &[prop("k", "v")], &priv_key);
        let m = parse(&v, None).unwrap();
        assert_eq!(m.algorithm, 5);
        assert_eq!(m.signature_verified, SignatureStatus::Valid);
        assert_eq!(m.digest_ok, Some(true));
        assert_eq!(m.public_key_bits, Some(4096));
        assert!(m.to_text(&[]).contains("signature: ok"));
    }

    #[test]
    fn an_unsupported_algorithm_is_not_a_failure() {
        // AVB algorithm 5 is actually SHA512_RSA4096, but use an unknown id (99)
        // to exercise the Unsupported path.
        let v = vbmeta(99, 0, &[prop("k", "v")], &[]);
        let m = parse(&v, None).unwrap();
        assert_eq!(m.algorithm, 99);
        assert_eq!(m.signature_verified, SignatureStatus::Unsupported(99));
        assert!(!m.to_text(&[]).contains("signature: FAILED"));
        assert!(
            m.to_text(&[])
                .contains("signature: not checked (algorithm 99 not supported)")
        );
        assert_eq!(
            m.to_json(&[])["signature_verified"],
            json!({"unsupported": 99})
        );
        assert!(!m.any_failure(&[]));
    }

    #[test]
    fn an_unsigned_block_has_no_signature_check() {
        let v = vbmeta(0, 0, &[prop("k", "v")], &[]);
        let m = parse(&v, None).unwrap();
        assert_eq!(m.algorithm, 0);
        assert_eq!(m.signature_verified, SignatureStatus::Absent);
        assert!(m.to_text(&[]).contains("signature: n/a (no signature)"));
        assert_eq!(m.to_json(&[])["signature_verified"], "absent");
    }

    #[test]
    fn verification_disabled_produces_a_high_severity_finding() {
        let m = parse(&vbmeta(0, 2, &[prop("k", "v")], &[]), None).unwrap();
        let findings = m.findings();
        assert_eq!(findings.len(), 2);
        assert_eq!(findings[0].severity, crate::audit::Severity::High);
        assert_eq!(findings[0].rule, "avb-security-state");
        assert!(findings[0].detail.contains("VERIFICATION_DISABLED"));
        // text output
        assert!(m.to_text(&[]).contains("VERIFICATION_DISABLED"));
        // json output
        let j = m.to_json(&[]);
        assert!(
            j["security_states"]
                .as_array()
                .unwrap()
                .iter()
                .any(|s| s["name"] == "VERIFICATION_DISABLED")
        );
    }

    #[test]
    fn allows_rollback_flag_produces_unlocked_device_finding() {
        let m = parse(&vbmeta(0, 4, &[prop("k", "v")], &[]), None).unwrap();
        let findings = m.findings();
        assert_eq!(findings.len(), 2);
        assert_eq!(findings[0].severity, crate::audit::Severity::High);
        assert_eq!(findings[0].rule, "avb-security-state");
        assert!(findings[0].detail.contains("UNLOCKED_DEVICE"));
        let t = m.to_text(&[]);
        assert!(t.contains("UNLOCKED_DEVICE"));
        assert!(t.contains("device is unlocked"));
        let j = m.to_json(&[]);
        assert!(j["flag_names"] == "ALLOW_ROLLBACK");
        assert!(
            j["security_states"]
                .as_array()
                .unwrap()
                .iter()
                .any(|s| s["name"] == "UNLOCKED_DEVICE")
        );
    }

    #[test]
    fn a_vbmeta_with_no_flags_has_no_security_states() {
        let m = parse(&vbmeta(0, 0, &[prop("k", "v")], &[]), None).unwrap();
        let findings = m.findings();
        assert_eq!(findings.len(), 1); // unsigned image
        let j = m.to_json(&[]);
        assert!(j["flag_names"] == "none");
        assert!(j["security_states"].as_array().unwrap().is_empty());
    }

    #[test]
    fn rollback_index_interpretation_reports_zero_index() {
        // The test helper sets rollback_index to 1234 by default; overwrite to 0.
        let mut v = vbmeta(0, 0, &[prop("k", "v")], &[]);
        v[112..120].copy_from_slice(&0u64.to_be_bytes());
        let m = parse(&v, None).unwrap();
        assert_eq!(m.rollback_index, 0);
        let ri = m.rollback_index_interpretation();
        // Index 0 is the default, not evidence of rollback (#118).
        assert_eq!(ri.severity, crate::audit::Severity::Info);
        assert!(ri.detail.contains("index 0") && ri.detail.contains("default"));
        assert!(!ri.detail.contains("older"), "{}", ri.detail);
        assert!(m.to_text(&[]).contains("rollback index 0"));
        let text = m.to_text(&[]);
        let line = text
            .lines()
            .find(|l| l.starts_with("rollback index 0 (location"))
            .expect("the rollback line");
        assert!(
            line.ends_with("[info]") && !line.contains("[high]"),
            "{line}"
        );
    }

    #[test]
    fn rollback_index_interpretation_reports_nonzero_index() {
        let m = parse(&vbmeta(1, 0, &[prop("k", "v")], &[]), None).unwrap();
        assert_eq!(m.rollback_index, 1234);
        let ri = m.rollback_index_interpretation();
        assert_eq!(ri.severity, crate::audit::Severity::Info);
        assert!(!ri.detail.contains("index 0"));
    }

    #[test]
    fn findings_are_included_in_json_output() {
        let m = parse(&vbmeta(0, 2, &[prop("k", "v")], &[]), None).unwrap();
        let j = m.to_json(&[]);
        let findings = j["findings"].as_array().unwrap();
        assert_eq!(findings.len(), 2);
        let f = &findings[0];
        assert_eq!(f["rule"], "avb-security-state");
        assert_eq!(f["severity"], "high");
    }

    #[test]
    fn findings_are_included_in_text_output() {
        let m = parse(&vbmeta(0, 2, &[prop("k", "v")], &[]), None).unwrap();
        let t = m.to_text(&[]);
        assert!(t.contains("VERIFICATION_DISABLED"));
        assert!(t.contains("security findings:"));
    }
    #[test]
    fn cross_check_chained_detects_downgrade_in_rollback_index() {
        use crate::testutil::Scratch;
        let chain_desc = chain("vendor", 5, &[0; 32]);
        let v = vbmeta(0, 0, &[prop("k", "v"), chain_desc], &[]);
        let m = parse(&v, None).unwrap();
        assert_eq!(m.descriptors.len(), 2);

        let mut chained = vbmeta(0, 0, &[prop("a", "b")], &[]);
        chained[112..120].copy_from_slice(&0u64.to_be_bytes());

        let dir = Scratch::new("chained_test");
        std::fs::write(dir.as_path().join("vendor.img"), &chained).unwrap();

        assert_eq!(m.rollback_index, 1234);
        let findings = m.cross_check_chained(dir.as_path());
        assert_eq!(findings.len(), 2); // rollback-index + unsigned
        assert_eq!(findings[1].rule, "avb-rollback-index");
        assert!(findings[1].detail.contains("vendor"));
        assert!(findings[1].detail.contains("lower than top-level"));
    }

    #[test]
    fn cross_check_chained_no_findings_when_indices_match_or_exceed() {
        use crate::testutil::Scratch;
        let chain_desc = chain("vendor", 5, &[0; 32]);
        let v = vbmeta(0, 0, &[prop("k", "v"), chain_desc], &[]);
        let m = parse(&v, None).unwrap();

        let mut chained = vbmeta(0, 0, &[prop("a", "b")], &[]);
        chained[112..120].copy_from_slice(&1234u64.to_be_bytes());

        let dir = Scratch::new("chained_good");
        std::fs::write(dir.as_path().join("vendor.img"), &chained).unwrap();

        let findings = m.cross_check_chained(dir.as_path());
        assert_eq!(findings.len(), 1); // unsigned image
    }
    #[test]
    fn an_unsigned_image_with_clean_flags_still_produces_a_finding() {
        let m = parse(&vbmeta(0, 0, &[prop("k", "v")], &[]), None).unwrap();
        let findings = m.findings();
        // Unsigned (Algorithm NONE) -> high severity finding
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule, "avb-unsigned-image");
        assert_eq!(findings[0].severity, crate::audit::Severity::High);
    }

    /// A 1 MiB partition image: filler, the vbmeta block at 4096, an AVB footer in the last 64.
    fn partition_with_footer(v: &[u8]) -> Vec<u8> {
        let mut part = vec![0xAAu8; 1 << 20];
        part[4096..4096 + v.len()].copy_from_slice(v);
        let mut footer = b"AVBf".to_vec();
        footer.extend(1u32.to_be_bytes());
        footer.extend(0u32.to_be_bytes());
        footer.extend(4096u64.to_be_bytes());
        footer.extend(4096u64.to_be_bytes());
        footer.extend((v.len() as u64).to_be_bytes());
        footer.resize(64, 0);
        let n = part.len();
        part[n - 64..].copy_from_slice(&footer);
        part
    }

    /// Issue #118: every per-partition footer (algorithm NONE) was reported `[high]`
    /// "no signature present; verified boot proves nothing", although a signed top-level
    /// vbmeta normally carries the signature. Only a bare unsigned vbmeta says that.
    #[test]
    fn an_unsigned_partition_footer_is_informational_but_an_unsigned_vbmeta_is_high() {
        let v = vbmeta(0, 0, &[prop("k", "v")], &[]);
        let (_g, p) = write_tmp("footer-info", &partition_with_footer(&v));
        let m = read_input(&p, None).unwrap();
        assert!(m.footer.is_some());
        let findings = m.findings();
        assert_eq!(
            findings.len(),
            1,
            "{:?}",
            findings.iter().map(|f| f.rule).collect::<Vec<_>>()
        );
        assert_eq!(findings[0].rule, "avb-unsigned-footer");
        assert_eq!(findings[0].severity, crate::audit::Severity::Info);
        assert!(!m.to_text(&[]).contains("[high]"), "{}", m.to_text(&[]));

        let (_g, bare) = write_tmp("bare-unsigned", &v);
        let top = read_input(&bare, None).unwrap().findings();
        assert_eq!(top[0].rule, "avb-unsigned-image");
        assert_eq!(top[0].severity, crate::audit::Severity::High);
    }

    /// The footer relief must not reach a chained partition: its vbmeta has to be signed with
    /// the chain descriptor's key, so an unsigned one is still a high finding there.
    #[test]
    fn an_unsigned_footer_on_a_chained_partition_is_still_high() {
        let top = parse(
            &vbmeta(0, 2, &[chain("vendor", 1, &key_blob(2048))], &[]),
            None,
        )
        .unwrap();
        let dir = crate::testutil::Scratch::new("chained_footer");
        let inner = vbmeta(0, 0, &[prop("a", "b")], &[]);
        std::fs::write(
            dir.as_path().join("vendor.img"),
            partition_with_footer(&inner),
        )
        .unwrap();
        let findings = top.cross_check_chained(dir.as_path());
        assert!(
            findings
                .iter()
                .any(|f| f.severity == crate::audit::Severity::High
                    && f.detail.contains("chained vbmeta vendor")
                    && f.detail.contains("no signature")),
            "{:?}",
            findings
                .iter()
                .map(|f| (&f.rule, &f.detail))
                .collect::<Vec<_>>()
        );
    }

    #[test]
    fn a_signed_image_with_clean_flags_produces_no_findings() {
        let mut rng = OsRng;
        let priv_key = RsaPrivateKey::new(&mut rng, 2048).unwrap();
        let v = vbmeta_signed(1, 0, &[prop("k", "v")], &priv_key);
        let m = parse(&v, None).unwrap();
        let findings = m.findings();
        // A correctly signed image with clean flags = no findings
        assert!(
            findings.is_empty(),
            "expected no findings for signed image, got {:?}",
            findings
        );
    }

    #[test]
    fn an_unsupported_algorithm_reports_not_checked() {
        let v = vbmeta(99, 0, &[prop("k", "v")], &[]);
        let m = parse(&v, None).unwrap();
        let findings = m.findings();
        // Unsupported algorithm -> warn, not checked
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule, "avb-unsupported-algorithm");
        assert_eq!(findings[0].severity, crate::audit::Severity::Warn);
        assert!(findings[0].detail.contains("not checked"));
    }
}
