//! Android Verified Boot (AVB) `vbmeta` inspection: the header, the public key, every descriptor,
//! the authentication digest, and (with a directory of images) the hash of each hashed partition.
//!
//! Layout from AOSP libavb (`avb_vbmeta_image.h`, `avb_descriptor.h`, `avb_footer.h`, Apache-2.0)
//! and checked against AOSP's `avbtool info_image`. The RSA signature itself is not verified: the
//! digest in the authentication block is, and so are partition hashes. All integers are big-endian.
use crate::detect::refuse_blocking_file;
use anyhow::{Context, Result, bail, ensure};
use serde_json::{Value, json};
use sha2::{Digest, Sha256, Sha512};
use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::path::Path;

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

/// Which digest the authentication block uses for an algorithm type.
fn auth_hash(algorithm: u32, data: &[u8]) -> Option<Vec<u8>> {
    match algorithm {
        1..=3 => Some(Sha256::digest(data).to_vec()),
        4..=6 => Some(Sha512::digest(data).to_vec()),
        _ => None,
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
    if flags & !(FLAG_HASHTREE_DISABLED | FLAG_VERIFICATION_DISABLED) != 0 {
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

pub fn parse(data: &[u8]) -> Result<Vbmeta> {
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
pub fn read_input(path: &Path) -> Result<Vbmeta> {
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
        return parse(&data);
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
    let mut meta = parse(&data).context("reading the vbmeta block the footer points to")?;
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

impl Vbmeta {
    pub fn to_json(&self, checks: &[(String, Check)]) -> Value {
        json!({
            "libavb": format!("{}.{}", self.libavb.0, self.libavb.1),
            "algorithm": algorithm_name(self.algorithm),
            "rollback_index": self.rollback_index,
            "rollback_index_location": self.rollback_index_location,
            "flags": self.flags,
            "flag_names": flag_names(self.flags),
            "release": self.release,
            "authentication_block": self.auth_size,
            "auxiliary_block": self.aux_size,
            "signature_bytes": self.signature_len,
            "public_key_bits": self.public_key_bits,
            "public_key_sha256": self.public_key_sha256,
            "public_key_metadata_bytes": self.public_key_metadata_len,
            "digest_ok": self.digest_ok,
            "signature_verified": false,
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
        o.push(format!("release string: {:?}", self.release));
        o.push(format!(
            "authentication block {} bytes, auxiliary block {} bytes; digest check: {}; signature: not verified",
            self.auth_size,
            self.aux_size,
            match self.digest_ok {
                Some(true) => "ok",
                Some(false) => "MISMATCH",
                None => "n/a (no signature)",
            }
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
        self.digest_ok == Some(false) || checks.iter().any(|(_, c)| *c == Check::Mismatch)
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

    fn key_blob(bits: u32) -> Vec<u8> {
        let mut k = bits.to_be_bytes().to_vec();
        k.extend([5u8; 60]);
        k
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
        let m = parse(&vbmeta(1, 0, &d, &key_blob(2048))).unwrap();
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
        let m = parse(&vbmeta(0, 2, &[], &[])).unwrap();
        assert_eq!(
            (m.digest_ok, m.public_key_bits, m.public_key_sha256.clone()),
            (None, None, None)
        );
        assert!(m.to_text(&[]).contains("VERIFICATION_DISABLED"));
        assert!(m.to_text(&[]).contains("n/a (no signature)"));
        assert_eq!(flag_names(1), "HASHTREE_DISABLED");
        assert_eq!(flag_names(3), "HASHTREE_DISABLED, VERIFICATION_DISABLED");
        assert_eq!(flag_names(0), "none");
        assert_eq!(flag_names(8), "unknown bits");
    }

    #[test]
    fn a_changed_byte_breaks_the_digest() {
        let mut v = vbmeta(1, 0, &[prop("k", "v")], &key_blob(2048));
        assert_eq!(parse(&v).unwrap().digest_ok, Some(true));
        let last = v.len() - 1;
        v[last] ^= 1; // padding byte of the auxiliary block
        assert_eq!(parse(&v).unwrap().digest_ok, Some(false));
        let mut w = vbmeta(1, 0, &[prop("k", "v")], &key_blob(2048));
        w[112] ^= 1; // rollback index in the header
        assert_eq!(parse(&w).unwrap().digest_ok, Some(false));
        assert!(parse(&w).unwrap().any_failure(&[]));
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
        let err = |v: Vec<u8>| format!("{:#}", parse(&v).unwrap_err());
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
        let err = |d: Vec<Vec<u8>>| format!("{:#}", parse(&vbmeta(0, 0, &d, &[])).unwrap_err());
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
                parse(&vbmeta(0, 0, &[vec![0u8; 8]], &[])).unwrap_err()
            )
            .contains("header runs past")
        );
    }

    fn write_tmp(tag: &str, bytes: &[u8]) -> std::path::PathBuf {
        let d = std::env::temp_dir().join(format!("ad-avb-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        let p = d.join("x.img");
        std::fs::write(&p, bytes).unwrap();
        p
    }

    #[test]
    fn reads_a_padded_vbmeta_image_and_a_partition_with_a_footer() {
        let v = vbmeta(0, 0, &[prop("a", "b")], &[]);
        let mut padded = v.clone();
        padded.resize(8192, 0);
        let m = read_input(&write_tmp("pad", &padded)).unwrap();
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
        let m = read_input(&write_tmp("footer", &part)).unwrap();
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
            format!("{:#}", read_input(&write_tmp("badfoot", &bad)).unwrap_err())
                .contains("outside the image")
        );
        let e = format!(
            "{:#}",
            read_input(&write_tmp("none", &vec![1u8; 4096])).unwrap_err()
        );
        assert!(e.contains("not an AVB image"), "{e}");
        assert!(read_input(&write_tmp("tiny", b"AVB")).is_err());
        assert!(read_input(Path::new("/definitely/not/here")).is_err());
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
        let m = parse(&vbmeta(0, 0, &d, &[])).unwrap();
        let outer = write_tmp("verify", b"").parent().unwrap().to_path_buf();
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
        let m = parse(&vbmeta(
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
        ))
        .unwrap();
        let j = m.to_json(&[("boot".into(), Check::Ok)]);
        assert_eq!(j["algorithm"], "SHA256_RSA2048");
        assert_eq!(j["flag_names"], "HASHTREE_DISABLED");
        assert_eq!(j["public_key_bits"], 4096);
        assert_eq!(j["digest_ok"], true);
        assert_eq!(j["signature_verified"], false);
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
                match parse(&w) {
                    Ok(_) => ok += 1,
                    Err(_) => err += 1,
                }
            }
        }
        assert!(ok > 100 && err > 100, "ok={ok} err={err}");
    }
}
