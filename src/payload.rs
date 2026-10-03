//! A/B OTA payloads (`payload.bin`, "CrAU" version 2), full OTAs only.
//!
//! The format is the AOSP `update_engine` payload (`update_metadata.proto`, Apache-2.0); this is
//! written from that description and checked against ssut/payload-dumper-go (Apache-2.0).
use crate::extract::{ExtractOptions, create_part};
use anyhow::{Context, Result, anyhow, bail, ensure};
use indicatif::{MultiProgress, ProgressBar, ProgressStyle};
use prost::Message;
use sha2::{Digest, Sha256};
use std::fs::File;
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

/// The protobuf messages, hand-written from `update_metadata.proto` (only the fields used here).
/// Unknown fields are skipped when decoding.
pub mod pb {
    #[derive(Clone, PartialEq, prost::Message)]
    pub struct Extent {
        #[prost(uint64, optional, tag = "1")]
        pub start_block: Option<u64>,
        #[prost(uint64, optional, tag = "2")]
        pub num_blocks: Option<u64>,
    }

    #[derive(Clone, PartialEq, prost::Message)]
    pub struct PartitionInfo {
        #[prost(uint64, optional, tag = "1")]
        pub size: Option<u64>,
        #[prost(bytes = "vec", optional, tag = "2")]
        pub hash: Option<Vec<u8>>,
    }

    #[derive(Clone, PartialEq, prost::Message)]
    pub struct InstallOperation {
        /// `InstallOperation.Type` as its integer value (kept raw so unknown types survive).
        #[prost(int32, required, tag = "1")]
        pub r#type: i32,
        #[prost(uint64, optional, tag = "2")]
        pub data_offset: Option<u64>,
        #[prost(uint64, optional, tag = "3")]
        pub data_length: Option<u64>,
        #[prost(message, repeated, tag = "4")]
        pub src_extents: Vec<Extent>,
        #[prost(message, repeated, tag = "6")]
        pub dst_extents: Vec<Extent>,
        #[prost(bytes = "vec", optional, tag = "8")]
        pub data_sha256_hash: Option<Vec<u8>>,
    }

    #[derive(Clone, PartialEq, prost::Message)]
    pub struct PartitionUpdate {
        #[prost(string, required, tag = "1")]
        pub partition_name: String,
        #[prost(message, optional, tag = "6")]
        pub old_partition_info: Option<PartitionInfo>,
        #[prost(message, optional, tag = "7")]
        pub new_partition_info: Option<PartitionInfo>,
        #[prost(message, repeated, tag = "8")]
        pub operations: Vec<InstallOperation>,
        #[prost(message, optional, tag = "10")]
        pub hash_tree_data_extent: Option<Extent>,
        #[prost(message, optional, tag = "11")]
        pub hash_tree_extent: Option<Extent>,
        #[prost(message, optional, tag = "14")]
        pub fec_data_extent: Option<Extent>,
        #[prost(message, optional, tag = "15")]
        pub fec_extent: Option<Extent>,
    }

    #[derive(Clone, PartialEq, prost::Message)]
    pub struct DeltaArchiveManifest {
        #[prost(uint32, optional, tag = "3")]
        pub block_size: Option<u32>,
        #[prost(uint32, optional, tag = "12")]
        pub minor_version: Option<u32>,
        #[prost(message, repeated, tag = "13")]
        pub partitions: Vec<PartitionUpdate>,
    }
}

const MAGIC: &[u8; 4] = b"CrAU";
const HEADER_LEN: u64 = 24;
const PAYLOAD_NAME: &str = "payload.bin";
/// A manifest is tens of KiB to a few MiB; this stops a hostile header from asking for gigabytes.
const MAX_MANIFEST_BYTES: u64 = 64 << 20;
/// Real payloads list a few dozen partitions.
const MAX_PARTITIONS: usize = 1024;
/// One operation's compressed data (update_engine writes 2 MiB chunks; this leaves a wide margin).
const MAX_BLOB_BYTES: u64 = 512 << 20;
/// Largest partition accepted. Real ones are at most about 10 GB; the cap also bounds the time
/// spent hashing zeros for a tiny payload that declares a huge partition (about 40 s at 64 GiB).
const MAX_PARTITION_BYTES: u64 = 64 << 30;
const COPY_BUF: usize = 1 << 20;

// InstallOperation.Type values (update_metadata.proto; 14 is ZSTD in current AOSP).
const OP_REPLACE: i32 = 0;
const OP_REPLACE_BZ: i32 = 1;
const OP_ZERO: i32 = 6;
const OP_DISCARD: i32 = 7;
const OP_REPLACE_XZ: i32 = 8;
const OP_ZSTD: i32 = 14;

fn op_name(t: i32) -> String {
    match t {
        0 => "REPLACE".into(),
        1 => "REPLACE_BZ".into(),
        2 => "MOVE".into(),
        3 => "BSDIFF".into(),
        4 => "SOURCE_COPY".into(),
        5 => "SOURCE_BSDIFF".into(),
        6 => "ZERO".into(),
        7 => "DISCARD".into(),
        8 => "REPLACE_XZ".into(),
        9 => "PUFFDIFF".into(),
        10 => "BROTLI_BSDIFF".into(),
        11 => "ZUCCHINI".into(),
        12 => "LZ4DIFF_BSDIFF".into(),
        13 => "LZ4DIFF_PUFFDIFF".into(),
        14 => "ZSTD".into(),
        other => format!("type {other}"),
    }
}

/// Where the payload bytes live: `len` bytes starting at `base` in the file at `path`
/// (`base` is 0 for a plain `payload.bin`, the data offset of a stored zip entry otherwise).
#[derive(Debug, Clone)]
pub struct Located {
    pub path: PathBuf,
    pub base: u64,
    pub len: u64,
}

/// Find a payload in `input`: a directory holding `payload.bin`, a zip with a stored
/// `payload.bin`, or a file that starts with the payload magic. `None` means "not an A/B OTA".
pub fn locate(input: &Path) -> Result<Option<Located>> {
    if input.is_dir() {
        let path = input.join(PAYLOAD_NAME);
        return match std::fs::metadata(&path) {
            Ok(m) if m.is_file() => Ok(Some(Located {
                path,
                base: 0,
                len: m.len(),
            })),
            _ => Ok(None),
        };
    }
    let mut file = File::open(input).with_context(|| format!("opening {}", input.display()))?;
    let mut magic = [0u8; 4];
    let got = file.read(&mut magic)?;
    if got == 4 && &magic == MAGIC {
        return Ok(Some(Located {
            path: input.to_path_buf(),
            base: 0,
            len: file.metadata()?.len(),
        }));
    }
    if got == 4 && &magic[..2] == b"PK" {
        file.seek(SeekFrom::Start(0))?;
        let Ok(mut zip) = zip::ZipArchive::new(file) else {
            return Ok(None);
        };
        let Ok(entry) = zip.by_name(PAYLOAD_NAME) else {
            return Ok(None);
        };
        ensure!(
            entry.compression() == zip::CompressionMethod::Stored,
            "{PAYLOAD_NAME} is compressed inside the zip; unzip it first (OTA zips normally store it uncompressed)"
        );
        let base = entry
            .data_start()
            .context("payload.bin has no data offset in the zip")?;
        return Ok(Some(Located {
            path: input.to_path_buf(),
            base,
            len: entry.size(),
        }));
    }
    Ok(None)
}

/// A parsed payload header and manifest.
pub struct Payload {
    pub manifest: pb::DeltaArchiveManifest,
    /// Offset of the data blobs, relative to the start of the payload.
    pub data_base: u64,
}

fn be64(b: &[u8]) -> u64 {
    u64::from_be_bytes(b[..8].try_into().expect("8 bytes"))
}

/// Read the header and manifest from the start of a payload of `len` bytes.
pub fn read_payload<R: Read>(r: &mut R, len: u64) -> Result<Payload> {
    ensure!(
        len >= HEADER_LEN,
        "payload is only {len} bytes, too short for a header"
    );
    let mut h = [0u8; HEADER_LEN as usize];
    r.read_exact(&mut h).context("reading the payload header")?;
    ensure!(&h[..4] == MAGIC, "not an A/B payload: bad magic");
    let version = be64(&h[4..12]);
    ensure!(
        version == 2,
        "unsupported payload version {version} (only version 2 is supported)"
    );
    let manifest_size = be64(&h[12..20]);
    let sig_size = u32::from_be_bytes(h[20..24].try_into().expect("4 bytes")) as u64;
    ensure!(
        manifest_size <= MAX_MANIFEST_BYTES && HEADER_LEN + manifest_size + sig_size <= len,
        "payload header claims a {manifest_size}-byte manifest and a {sig_size}-byte signature, which do not fit in {len} bytes"
    );
    let mut raw = vec![0u8; manifest_size as usize];
    r.read_exact(&mut raw).context("reading the manifest")?;
    let manifest = pb::DeltaArchiveManifest::decode(&raw[..]).context("decoding the manifest")?;
    Ok(Payload {
        manifest,
        data_base: HEADER_LEN + manifest_size + sig_size,
    })
}

fn open_payload(l: &Located) -> Result<Payload> {
    let mut f = File::open(&l.path).with_context(|| format!("opening {}", l.path.display()))?;
    f.seek(SeekFrom::Start(l.base))?;
    read_payload(&mut f, l.len)
}

fn block_size(m: &pb::DeltaArchiveManifest) -> Result<u64> {
    let bs = m.block_size.unwrap_or(4096) as u64;
    ensure!(
        (512..=(1 << 20)).contains(&bs) && bs.is_multiple_of(512),
        "unsupported block size {bs}"
    );
    Ok(bs)
}

fn is_data_op(t: i32) -> bool {
    matches!(t, OP_REPLACE | OP_REPLACE_BZ | OP_REPLACE_XZ | OP_ZSTD)
}

fn has_verity(p: &pb::PartitionUpdate) -> bool {
    [
        &p.hash_tree_data_extent,
        &p.hash_tree_extent,
        &p.fec_data_extent,
        &p.fec_extent,
    ]
    .iter()
    .any(|e| e.as_ref().is_some_and(|e| e.num_blocks.unwrap_or(0) > 0))
}

/// Byte extents `(offset, length)` of an operation's destination, validated.
fn byte_extents(op: &pb::InstallOperation, bs: u64) -> Result<Vec<(u64, u64)>> {
    ensure!(
        !op.dst_extents.is_empty(),
        "operation has no destination extents"
    );
    let mut out = Vec::with_capacity(op.dst_extents.len());
    for e in &op.dst_extents {
        let (start, num) = (e.start_block.unwrap_or(0), e.num_blocks.unwrap_or(0));
        ensure!(start != u64::MAX, "sparse-hole extents are not supported");
        let end = start.checked_add(num).context("extent overflows")?;
        // `end` is at least `start` and `num`, so if `end * bs` fits, so do `start * bs` and `num * bs`
        ensure!(end.checked_mul(bs).is_some(), "extent end overflows");
        if num > 0 {
            out.push((start * bs, num * bs));
        }
    }
    Ok(out)
}

/// One data operation, validated: where its blob is and where its output goes.
struct DataOp<'a> {
    op: &'a pb::InstallOperation,
    /// Destination byte extents `(offset, length)`.
    extents: Vec<(u64, u64)>,
    /// Offset of the blob in the payload file (relative to the payload start) and its length.
    start: u64,
    len: u64,
}

/// Everything about one partition that is checked before any file is created.
struct Plan<'a> {
    name: &'a str,
    update: &'a pb::PartitionUpdate,
    size: u64,
    data_ops: Vec<DataOp<'a>>,
    blob_bytes: u64,
}

fn plan_partition<'a>(
    p: &'a Payload,
    update: &'a pb::PartitionUpdate,
    file_len: u64,
    bs: u64,
) -> Result<Plan<'a>> {
    let name = update.partition_name.as_str();
    let mut ranges: Vec<(u64, u64)> = Vec::new();
    let mut data_ops = Vec::new();
    let mut blob_bytes = 0u64;
    for (i, op) in update.operations.iter().enumerate() {
        let ctx = || format!("partition {name}, operation {i} ({})", op_name(op.r#type));
        let extents = byte_extents(op, bs).with_context(ctx)?;
        ranges.extend(extents.iter().copied());
        if is_data_op(op.r#type) {
            let (off, len) = (op.data_offset.unwrap_or(0), op.data_length.unwrap_or(0));
            ensure!(len > 0, "{}: no data", ctx());
            ensure!(
                len <= MAX_BLOB_BYTES,
                "{}: {len} bytes of data is over the {MAX_BLOB_BYTES}-byte limit",
                ctx()
            );
            let start = p
                .data_base
                .checked_add(off)
                .context("blob offset overflows")
                .with_context(ctx)?;
            let end = start
                .checked_add(len)
                .context("blob end overflows")
                .with_context(ctx)?;
            ensure!(
                end <= file_len,
                "{}: data ends at {end} but the payload is {file_len} bytes",
                ctx()
            );
            data_ops.push(DataOp {
                op,
                extents,
                start,
                len,
            });
            blob_bytes += len;
        } else {
            ensure!(
                op.r#type == OP_ZERO || op.r#type == OP_DISCARD,
                "{}: unsupported",
                ctx()
            );
        }
    }
    // destination extents must not overlap: operations run in parallel and in any order
    ranges.sort_unstable();
    if let Some(w) = ranges.windows(2).find(|w| w[0].0 + w[0].1 > w[1].0) {
        bail!(
            "partition {name}: overlapping destination extents at byte {}",
            w[1].0
        );
    }
    let furthest = ranges.last().map_or(0, |r| r.0 + r.1);
    let declared = update.new_partition_info.as_ref().and_then(|i| i.size);
    let size = declared.unwrap_or(furthest);
    ensure!(
        size <= MAX_PARTITION_BYTES,
        "partition {name}: {size} bytes is over the {MAX_PARTITION_BYTES}-byte limit"
    );
    ensure!(
        furthest <= size,
        "partition {name}: extents reach byte {furthest} but the partition is {size} bytes"
    );
    data_ops.sort_by_key(|o| o.start); // read the payload front to back
    Ok(Plan {
        name,
        update,
        size,
        data_ops,
        blob_bytes,
    })
}

/// Reject incremental payloads (anything that needs the previous build) with one clear error.
fn check_full(payload: &Payload, selected: &[&pb::PartitionUpdate]) -> Result<()> {
    let mut needs_source: Vec<String> = Vec::new();
    for part in selected {
        let mut kinds: Vec<String> = part
            .operations
            .iter()
            .map(|o| o.r#type)
            .filter(|t| !is_data_op(*t) && *t != OP_ZERO && *t != OP_DISCARD)
            .map(op_name)
            .collect();
        kinds.sort();
        kinds.dedup();
        if !kinds.is_empty() {
            needs_source.push(format!("{} ({})", part.partition_name, kinds.join(", ")));
        } else if part.old_partition_info.is_some() {
            needs_source.push(format!(
                "{} (built against an older partition)",
                part.partition_name
            ));
        }
    }
    if !needs_source.is_empty() {
        bail!(
            "this is an incremental OTA (minor version {}); it needs the previous build, which is not supported: {}",
            payload.manifest.minor_version.unwrap_or(0),
            needs_source.join("; ")
        );
    }
    Ok(())
}

fn is_safe_name(p: &str) -> bool {
    !p.is_empty()
        && p.chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
}

/// Validate names, apply `--only`, and return the selected partitions sorted by name.
fn select<'a>(
    m: &'a pb::DeltaArchiveManifest,
    only: &Option<Vec<String>>,
) -> Result<Vec<&'a pb::PartitionUpdate>> {
    ensure!(!m.partitions.is_empty(), "the payload lists no partitions");
    ensure!(
        m.partitions.len() <= MAX_PARTITIONS,
        "the payload lists {} partitions, over the limit of {MAX_PARTITIONS}",
        m.partitions.len()
    );
    let mut all: Vec<&pb::PartitionUpdate> = m.partitions.iter().collect();
    all.sort_by(|a, b| a.partition_name.cmp(&b.partition_name));
    if let Some(bad) = all.iter().find(|p| !is_safe_name(&p.partition_name)) {
        bail!("unsafe partition name {:?}", bad.partition_name);
    }
    if let Some(w) = all.windows(2).find(|w| {
        w[0].partition_name
            .eq_ignore_ascii_case(&w[1].partition_name)
    }) {
        if w[0].partition_name == w[1].partition_name {
            bail!(
                "partition {} is listed more than once and would overwrite itself",
                w[0].partition_name
            );
        }
        bail!(
            "{} and {} differ only by case and would overwrite each other",
            w[0].partition_name,
            w[1].partition_name
        );
    }
    if let Some(only) = only {
        let names: Vec<&str> = all.iter().map(|p| p.partition_name.as_str()).collect();
        if let Some(bad) = only.iter().find(|o| !names.contains(&o.as_str())) {
            bail!("unknown name {bad:?}; available: {}", names.join(", "));
        }
        all.retain(|p| only.contains(&p.partition_name));
    }
    Ok(all)
}

/// `Some(names)` when `input` is an A/B OTA, `None` otherwise (used by `report`).
pub fn partition_names(input: &Path) -> Result<Option<Vec<String>>> {
    let Some(loc) = locate(input)? else {
        return Ok(None);
    };
    let payload = open_payload(&loc)?;
    let mut names: Vec<String> = payload
        .manifest
        .partitions
        .iter()
        .map(|p| p.partition_name.clone())
        .collect();
    names.sort();
    Ok(Some(names))
}

/// What `extract` would write, with sizes in bytes; `None` when `input` is not an A/B OTA.
pub fn list(input: &Path, opts: &ExtractOptions) -> Result<Option<Vec<(String, u64)>>> {
    let Some(loc) = locate(input)? else {
        return Ok(None);
    };
    let payload = open_payload(&loc)?;
    let bs = block_size(&payload.manifest)?;
    let mut out = Vec::new();
    for part in select(&payload.manifest, &opts.only)? {
        let plan = plan_partition(&payload, part, loc.len, bs)?;
        out.push((format!("{}.img", plan.name), plan.size));
    }
    Ok(Some(out))
}

/// Writes a stream into a list of byte extents of an output file.
struct ExtentWriter<'a> {
    file: File,
    extents: &'a [(u64, u64)],
    idx: usize,
    within: u64,
}

impl Write for ExtentWriter<'_> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let Some(&(off, len)) = self.extents.get(self.idx) else {
            return Err(std::io::Error::other(
                "more data than the destination extents hold",
            ));
        };
        let n = buf.len().min((len - self.within) as usize);
        self.file.seek(SeekFrom::Start(off + self.within))?;
        self.file.write_all(&buf[..n])?;
        self.within += n as u64;
        if self.within == len {
            self.idx += 1;
            self.within = 0;
        }
        Ok(n)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// Copy exactly `expected` bytes from `r` to `w`; fewer or more is an error.
fn copy_exact<R: Read, W: Write>(mut r: R, w: &mut W, expected: u64) -> Result<()> {
    let mut buf = vec![0u8; COPY_BUF];
    let mut left = expected;
    while left > 0 {
        let n = r.read(&mut buf[..left.min(COPY_BUF as u64) as usize])?;
        ensure!(
            n > 0,
            "data ends {left} bytes before the destination extents are full"
        );
        w.write_all(&buf[..n])?;
        left -= n as u64;
    }
    ensure!(
        r.read(&mut [0u8; 1])? == 0,
        "data holds more than the {expected} bytes the destination extents hold"
    );
    Ok(())
}

fn run_data_op(
    payload: &mut File,
    op: &pb::InstallOperation,
    extents: &[(u64, u64)],
    start: u64,
    len: u64,
    out_path: &Path,
    base: u64,
) -> Result<()> {
    payload.seek(SeekFrom::Start(base + start))?;
    let mut blob = vec![0u8; len as usize];
    payload
        .read_exact(&mut blob)
        .context("reading the operation data")?;
    if let Some(want) = op.data_sha256_hash.as_deref().filter(|h| !h.is_empty()) {
        let got = Sha256::digest(&blob);
        ensure!(
            got.as_slice() == want,
            "operation data does not match its sha256"
        );
    }
    let expected: u64 = extents.iter().map(|e| e.1).sum();
    // each operation opens the file itself (cheap): no shared handle, no lock, no open-file limit
    let file = File::options()
        .write(true)
        .open(out_path)
        .with_context(|| format!("opening {}", out_path.display()))?;
    let mut w = ExtentWriter {
        file,
        extents,
        idx: 0,
        within: 0,
    };
    match op.r#type {
        OP_REPLACE => copy_exact(&blob[..], &mut w, expected),
        OP_REPLACE_BZ => copy_exact(bzip2::read::BzDecoder::new(&blob[..]), &mut w, expected),
        OP_REPLACE_XZ => copy_exact(
            lzma_rust2::XzReader::new(&blob[..], false),
            &mut w,
            expected,
        ),
        OP_ZSTD => {
            let dec = ruzstd::decoding::StreamingDecoder::new(&blob[..])
                .map_err(|e| anyhow!("zstd: {e}"))?;
            copy_exact(dec, &mut w, expected)
        }
        other => bail!("unexpected operation type {}", op_name(other)),
    }
}

fn hash_file(path: &Path, size: u64) -> Result<Vec<u8>> {
    let mut f = File::open(path)?;
    let mut hasher = Sha256::new();
    let mut buf = vec![0u8; COPY_BUF];
    let mut left = size;
    while left > 0 {
        let n = f.read(&mut buf[..left.min(COPY_BUF as u64) as usize])?;
        ensure!(n > 0, "image is shorter than {size} bytes");
        hasher.update(&buf[..n]);
        left -= n as u64;
    }
    Ok(hasher.finalize().to_vec())
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn part_path(out_dir: &Path, name: &str) -> PathBuf {
    out_dir.join(format!("{name}.img.part"))
}

/// Extract every (selected) partition of an A/B OTA into `out_dir`. Returns `None` when `input`
/// is not an A/B OTA. All-or-nothing: on any error every `.part` file is removed and no image is
/// created. Each result carries a note on how far the image was verified.
pub fn extract(
    input: &Path,
    out_dir: &Path,
    opts: &ExtractOptions,
) -> Result<Option<Vec<(PathBuf, String)>>> {
    let Some(loc) = locate(input)? else {
        return Ok(None);
    };
    let payload = open_payload(&loc)?;
    let bs = block_size(&payload.manifest)?;
    let selected = select(&payload.manifest, &opts.only)?;
    check_full(&payload, &selected)?;
    let plans = selected
        .iter()
        .map(|u| plan_partition(&payload, u, loc.len, bs))
        .collect::<Result<Vec<_>>>()?;
    if !opts.force {
        let existing: Vec<String> = plans
            .iter()
            .map(|p| format!("{}.img", p.name))
            .filter(|n| out_dir.join(n).symlink_metadata().is_ok())
            .collect();
        ensure!(
            existing.is_empty(),
            "{} already exist in {}; pass --force to overwrite",
            existing.join(", "),
            out_dir.display()
        );
    }
    std::fs::create_dir_all(out_dir)?;

    // every output file is created and sized up front, then closed again
    let result = (|| -> Result<Vec<(PathBuf, String)>> {
        for plan in &plans {
            create_part(&part_path(out_dir, plan.name))?.set_len(plan.size)?;
        }
        run_operations(&loc, &plans, out_dir)?;
        verify_and_publish(&plans, out_dir)
    })();
    if result.is_err() {
        for plan in &plans {
            let _ = std::fs::remove_file(part_path(out_dir, plan.name));
        }
    }
    result.map(Some)
}

fn run_operations(loc: &Located, plans: &[Plan], out_dir: &Path) -> Result<()> {
    // flat task list in payload order: (partition index, operation index within the plan)
    let mut tasks: Vec<(usize, usize, u64)> = Vec::new();
    for (pi, plan) in plans.iter().enumerate() {
        for (oi, op) in plan.data_ops.iter().enumerate() {
            tasks.push((pi, oi, op.start));
        }
    }
    tasks.sort_by_key(|t| t.2);

    let multi = MultiProgress::new(); // hidden automatically when stderr is not a terminal
    let style = ProgressStyle::with_template("{prefix:>12} [{bar:30}] {bytes}/{total_bytes}")
        .expect("valid progress template")
        .progress_chars("=> ");
    let bars: Vec<ProgressBar> = plans
        .iter()
        .map(|p| {
            let bar = multi.add(ProgressBar::new(p.blob_bytes).with_style(style.clone()));
            bar.set_prefix(p.name.to_string());
            bar
        })
        .collect();

    let next = AtomicUsize::new(0);
    let stop = AtomicBool::new(false);
    let first_error: Mutex<Option<anyhow::Error>> = Mutex::new(None);
    let workers = std::thread::available_parallelism()
        .map_or(4, |n| n.get())
        .min(tasks.len().max(1));
    std::thread::scope(|scope| {
        for _ in 0..workers {
            scope.spawn(|| {
                let fail = |e: anyhow::Error| {
                    stop.store(true, Ordering::SeqCst);
                    let mut slot = first_error.lock().expect("error slot");
                    if slot.is_none() {
                        *slot = Some(e);
                    }
                };
                let mut file = match File::open(&loc.path) {
                    Ok(f) => f,
                    Err(e) => {
                        return fail(anyhow!(e).context(format!("opening {}", loc.path.display())));
                    }
                };
                while !stop.load(Ordering::SeqCst) {
                    let i = next.fetch_add(1, Ordering::SeqCst);
                    let Some(&(pi, oi, _)) = tasks.get(i) else {
                        break;
                    };
                    let plan = &plans[pi];
                    let d = &plan.data_ops[oi];
                    let (start, len) = (d.start, d.len);
                    let out_path = part_path(out_dir, plan.name);
                    let ran =
                        run_data_op(&mut file, d.op, &d.extents, start, len, &out_path, loc.base);
                    match ran {
                        Ok(()) => bars[pi].inc(len),
                        Err(e) => {
                            return fail(e.context(format!(
                                "partition {}, operation at payload byte {}",
                                plan.name, start
                            )));
                        }
                    }
                }
            });
        }
    });
    for bar in &bars {
        bar.finish_and_clear();
    }
    match first_error.into_inner().expect("error slot") {
        Some(e) => Err(e),
        None => Ok(()),
    }
}

/// Check each image's SHA-256 against the manifest, then rename `.part` files into place.
fn verify_and_publish(plans: &[Plan], out_dir: &Path) -> Result<Vec<(PathBuf, String)>> {
    let notes: Vec<Result<String>> = std::thread::scope(|scope| {
        let handles: Vec<_> = plans
            .iter()
            .map(|plan| {
                scope.spawn(move || -> Result<String> {
                    let want = plan.update.new_partition_info.as_ref().and_then(|i| i.hash.as_deref()).filter(|h| !h.is_empty());
                    let Some(want) = want else { return Ok("no hash in the payload to check".to_string()) };
                    if has_verity(plan.update) {
                        return Ok("sha256 not checked: the payload leaves out the dm-verity/FEC data the device adds".to_string());
                    }
                    let got = hash_file(&part_path(out_dir, plan.name), plan.size)?;
                    ensure!(
                        got == want,
                        "partition {}: sha256 mismatch (manifest {}, image {})",
                        plan.name,
                        hex(want),
                        hex(&got)
                    );
                    Ok("sha256 verified".to_string())
                })
            })
            .collect();
        handles
            .into_iter()
            .map(|h| {
                h.join()
                    .unwrap_or_else(|_| Err(anyhow!("verification thread panicked")))
            })
            .collect()
    });
    let notes = notes.into_iter().collect::<Result<Vec<_>>>()?;
    let mut out = Vec::new();
    for (plan, note) in plans.iter().zip(notes) {
        let final_path = out_dir.join(format!("{}.img", plan.name));
        std::fs::rename(part_path(out_dir, plan.name), &final_path)?;
        out.push((final_path, note));
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    const BS: u64 = 512; // small blocks keep the fixtures tiny; 512 is the smallest accepted size

    #[derive(Clone, Copy, PartialEq, Debug)]
    enum Kind {
        Raw,
        Bz,
        Xz,
        Zstd,
        Zero,
        Discard,
    }

    #[derive(Clone)]
    struct OpSpec {
        kind: Kind,
        extents: Vec<(u64, u64)>, // (start_block, num_blocks)
        data: Vec<u8>,            // what the op writes (uncompressed); empty for zero/discard
        bad_op_hash: bool,
        raw_type: Option<i32>, // override the encoded type (incremental / unknown types)
    }

    #[derive(Clone, Copy, PartialEq)]
    enum Hash {
        Good,
        Bad,
        Absent,
    }

    #[derive(Clone)]
    struct PartSpec {
        name: String,
        size: Option<u64>,
        ops: Vec<OpSpec>,
        hash: Hash,
        verity: bool,
        old_info: bool,
    }

    /// Deterministic bytes: half repetitive (compressible), half pseudo-random.
    fn bytes(seed: u8, n: usize) -> Vec<u8> {
        let mut x = 0x9E37_79B9u32 ^ seed as u32;
        (0..n)
            .map(|i| {
                x ^= x << 13;
                x ^= x >> 17;
                x ^= x << 5;
                if i % 2 == 0 { seed } else { x as u8 }
            })
            .collect()
    }

    fn op(kind: Kind, extents: &[(u64, u64)], seed: u8) -> OpSpec {
        let blocks: u64 = extents.iter().map(|e| e.1).sum();
        let data = match kind {
            Kind::Zero | Kind::Discard => vec![],
            _ => bytes(seed, (blocks * BS) as usize),
        };
        OpSpec {
            kind,
            extents: extents.to_vec(),
            data,
            bad_op_hash: false,
            raw_type: None,
        }
    }

    fn part(name: &str, ops: Vec<OpSpec>) -> PartSpec {
        PartSpec {
            name: name.into(),
            size: None,
            ops,
            hash: Hash::Good,
            verity: false,
            old_info: false,
        }
    }

    fn compress(kind: Kind, data: &[u8]) -> Vec<u8> {
        match kind {
            Kind::Raw => data.to_vec(),
            Kind::Bz => {
                let mut e = bzip2::write::BzEncoder::new(Vec::new(), bzip2::Compression::default());
                e.write_all(data).unwrap();
                e.finish().unwrap()
            }
            Kind::Xz => {
                let mut w =
                    lzma_rust2::XzWriter::new(Vec::new(), lzma_rust2::XzOptions::with_preset(1))
                        .unwrap();
                w.write_all(data).unwrap();
                w.finish().unwrap()
            }
            Kind::Zstd => {
                ruzstd::encoding::compress_to_vec(data, ruzstd::encoding::CompressionLevel::Fastest)
            }
            Kind::Zero | Kind::Discard => vec![],
        }
    }

    fn type_code(k: Kind) -> i32 {
        match k {
            Kind::Raw => OP_REPLACE,
            Kind::Bz => OP_REPLACE_BZ,
            Kind::Xz => OP_REPLACE_XZ,
            Kind::Zstd => OP_ZSTD,
            Kind::Zero => OP_ZERO,
            Kind::Discard => OP_DISCARD,
        }
    }

    /// Build a payload and the images it must produce.
    fn build(parts: &[PartSpec]) -> (Vec<u8>, Vec<(String, Vec<u8>)>) {
        let mut blobs: Vec<u8> = Vec::new();
        let mut updates = Vec::new();
        let mut expected = Vec::new();
        for p in parts {
            let furthest = p
                .ops
                .iter()
                .flat_map(|o| o.extents.iter())
                .map(|e| (e.0 + e.1) * BS)
                .max()
                .unwrap_or(0);
            let size = p.size.unwrap_or(furthest);
            let mut image = vec![0u8; size as usize];
            let mut ops = Vec::new();
            for o in &p.ops {
                let mut at = 0usize;
                for &(start, num) in &o.extents {
                    let len = (num * BS) as usize;
                    let n = len.min(o.data.len().saturating_sub(at)); // data may be deliberately short
                    if n > 0 && (start * BS) as usize + n <= image.len() {
                        image[(start * BS) as usize..][..n].copy_from_slice(&o.data[at..at + n]);
                    }
                    at += len;
                }
                let blob = compress(o.kind, &o.data);
                let (data_offset, data_length, hash) = if blob.is_empty() {
                    (None, None, None)
                } else {
                    let off = blobs.len() as u64;
                    blobs.extend(&blob);
                    let mut h = Sha256::digest(&blob).to_vec();
                    if o.bad_op_hash {
                        h[0] ^= 0xff;
                    }
                    (Some(off), Some(blob.len() as u64), Some(h))
                };
                ops.push(pb::InstallOperation {
                    r#type: o.raw_type.unwrap_or(type_code(o.kind)),
                    data_offset,
                    data_length,
                    src_extents: vec![],
                    dst_extents: o
                        .extents
                        .iter()
                        .map(|&(s, n)| pb::Extent {
                            start_block: Some(s),
                            num_blocks: Some(n),
                        })
                        .collect(),
                    data_sha256_hash: hash,
                });
            }
            let digest = Sha256::digest(&image).to_vec();
            let hash = match p.hash {
                Hash::Good => Some(digest),
                Hash::Bad => Some(vec![0xAB; 32]),
                Hash::Absent => None,
            };
            let ext = pb::Extent {
                start_block: Some(1),
                num_blocks: Some(1),
            };
            updates.push(pb::PartitionUpdate {
                partition_name: p.name.clone(),
                old_partition_info: p.old_info.then_some(pb::PartitionInfo {
                    size: Some(size),
                    hash: None,
                }),
                new_partition_info: Some(pb::PartitionInfo {
                    size: p.size.or(Some(furthest)),
                    hash,
                }),
                operations: ops,
                hash_tree_data_extent: None,
                hash_tree_extent: p.verity.then(|| ext.clone()),
                fec_data_extent: None,
                fec_extent: None,
            });
            expected.push((p.name.clone(), image));
        }
        let manifest = pb::DeltaArchiveManifest {
            block_size: Some(BS as u32),
            minor_version: Some(0),
            partitions: updates,
        };
        let m = manifest.encode_to_vec();
        let mut out = Vec::new();
        out.extend(MAGIC);
        out.extend(2u64.to_be_bytes());
        out.extend((m.len() as u64).to_be_bytes());
        out.extend(5u32.to_be_bytes());
        out.extend(&m);
        out.extend([0xEE; 5]); // metadata signature
        out.extend(&blobs);
        (out, expected)
    }

    fn scratch(tag: &str) -> crate::testutil::Scratch {
        crate::testutil::Scratch::new(&format!("payload-{tag}"))
    }

    fn as_dir(tag: &str, payload: &[u8]) -> (crate::testutil::Scratch, PathBuf) {
        let g = scratch(tag);
        let d = g.join("ota");
        std::fs::create_dir_all(&d).unwrap();
        std::fs::write(d.join("payload.bin"), payload).unwrap();
        (g, d)
    }

    fn as_file(tag: &str, payload: &[u8]) -> (crate::testutil::Scratch, PathBuf) {
        let g = scratch(tag);
        let f = g.join("whatever.bin");
        std::fs::write(&f, payload).unwrap();
        (g, f)
    }

    fn as_zip(
        tag: &str,
        payload: &[u8],
        method: zip::CompressionMethod,
    ) -> (crate::testutil::Scratch, PathBuf) {
        let g = scratch(tag);
        let z = g.join("ota.zip");
        let mut w = zip::ZipWriter::new(File::create(&z).unwrap());
        let opts = zip::write::SimpleFileOptions::default()
            .compression_method(zip::CompressionMethod::Stored);
        w.start_file("META-INF/com/android/metadata", opts).unwrap();
        w.write_all(b"ota-type=AB\n").unwrap();
        w.start_file(
            "payload.bin",
            zip::write::SimpleFileOptions::default().compression_method(method),
        )
        .unwrap();
        w.write_all(payload).unwrap();
        w.start_file("payload_properties.txt", opts).unwrap();
        w.write_all(b"FILE_HASH=x\n").unwrap();
        w.finish().unwrap();
        (g, z)
    }

    /// Run an extraction on a thread with a watchdog, so a hang fails the test instead of the run.
    fn run(input: &Path, out: &Path, opts: &ExtractOptions) -> Result<Vec<(PathBuf, String)>> {
        let (input, out, opts) = (input.to_path_buf(), out.to_path_buf(), opts.clone());
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let r = extract(&input, &out, &opts)
                .map(|o| o.expect("recognised as an A/B OTA"))
                .map_err(|e| format!("{e:#}"));
            let _ = tx.send(r);
        });
        rx.recv_timeout(std::time::Duration::from_secs(120))
            .expect("extraction hung")
            .map_err(|e| anyhow!(e))
    }

    fn go(input: &Path, tag: &str) -> Result<(crate::testutil::Scratch, Vec<(PathBuf, String)>)> {
        let out = scratch(&format!("{tag}-out"));
        let r = run(input, &out, &ExtractOptions::default())?;
        Ok((out, r))
    }

    fn images_match(out: &Path, expected: &[(String, Vec<u8>)]) {
        for (name, image) in expected {
            let got = std::fs::read(out.join(format!("{name}.img")))
                .unwrap_or_else(|e| panic!("{name}.img: {e}"));
            assert!(
                got == *image,
                "{name}.img differs ({} vs {} bytes)",
                got.len(),
                image.len()
            );
        }
    }

    fn files_in(dir: &Path) -> Vec<String> {
        let mut v: Vec<String> = std::fs::read_dir(dir)
            .map(|d| {
                d.map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
                    .collect()
            })
            .unwrap_or_default();
        v.sort();
        v
    }

    fn mixed() -> Vec<PartSpec> {
        vec![
            part(
                "system",
                vec![
                    op(Kind::Xz, &[(0, 6)], 1),
                    op(Kind::Bz, &[(6, 3)], 2),
                    op(Kind::Raw, &[(9, 2)], 3),
                    op(Kind::Zstd, &[(11, 4)], 4),
                    op(Kind::Zero, &[(15, 3)], 0),
                    op(Kind::Discard, &[(18, 2)], 0),
                    op(Kind::Xz, &[(20, 1)], 5),
                ],
            ),
            part("boot", vec![op(Kind::Raw, &[(0, 4)], 9)]),
        ]
    }

    #[test]
    fn every_operation_type_rebuilds_the_image_and_is_verified() {
        let (payload, expected) = build(&mixed());
        for (tag, (_g, input)) in [
            ("dir", as_dir("t1d", &payload)),
            ("file", as_file("t1f", &payload)),
            (
                "zip",
                as_zip("t1z", &payload, zip::CompressionMethod::Stored),
            ),
        ] {
            let (out, res) = go(&input, tag).unwrap();
            images_match(&out, &expected);
            assert_eq!(res.len(), 2, "{tag}");
            assert!(
                res.iter().all(|(_, note)| note == "sha256 verified"),
                "{tag}: {res:?}"
            );
            assert_eq!(
                files_in(&out),
                ["boot.img", "system.img"],
                "{tag}: no .part files remain"
            );
            assert_eq!(
                res[0].0.file_name().unwrap(),
                "boot.img",
                "results come back sorted"
            );
        }
    }

    #[test]
    fn blob_order_in_the_payload_does_not_matter() {
        let mut parts = mixed();
        parts[0].ops.reverse(); // operations listed back to front, blobs laid out in that order
        let (payload, expected) = build(&parts);
        let (out, _) = go(&as_dir("t2", &payload).1, "t2").unwrap();
        images_match(&out, &expected);
    }

    #[test]
    fn an_operation_can_scatter_over_several_extents() {
        let parts = vec![part(
            "p",
            vec![
                op(Kind::Xz, &[(10, 2), (0, 3), (20, 1)], 1),
                op(Kind::Raw, &[(3, 7)], 2),
                op(Kind::Bz, &[(12, 8)], 3),
            ],
        )];
        let (payload, expected) = build(&parts);
        let (out, _) = go(&as_dir("t3", &payload).1, "t3").unwrap();
        images_match(&out, &expected);
    }

    #[test]
    fn a_partition_with_many_operations_is_decoded_in_parallel_correctly() {
        let ops: Vec<OpSpec> = (0..300u64)
            .map(|i| {
                op(
                    [Kind::Xz, Kind::Bz, Kind::Raw, Kind::Zstd][i as usize % 4],
                    &[(i * 2, 2)],
                    i as u8,
                )
            })
            .collect();
        let (payload, expected) = build(&[part("big", ops)]);
        let (out, res) = go(&as_dir("t4", &payload).1, "t4").unwrap();
        images_match(&out, &expected);
        assert_eq!(res[0].1, "sha256 verified");
    }

    #[test]
    fn declared_size_larger_than_the_extents_leaves_zero_padding() {
        let mut p = part("p", vec![op(Kind::Raw, &[(0, 2)], 1)]);
        p.size = Some(10 * BS);
        let (payload, expected) = build(&[p]);
        let (out, _) = go(&as_dir("t5", &payload).1, "t5").unwrap();
        images_match(&out, &expected);
        assert_eq!(std::fs::metadata(out.join("p.img")).unwrap().len(), 10 * BS);
    }

    #[test]
    fn only_and_list_select_partitions_and_report_sizes() {
        let (payload, expected) = build(&mixed());
        let (_g, input) = as_dir("t6", &payload);
        let list = list(&input, &ExtractOptions::default()).unwrap().unwrap();
        assert_eq!(
            list,
            vec![
                ("boot.img".to_string(), 4 * BS),
                ("system.img".to_string(), 21 * BS)
            ]
        );
        let only = |n: &[&str]| ExtractOptions {
            only: Some(n.iter().map(|s| s.to_string()).collect()),
            ..Default::default()
        };
        let out = scratch("t6-out");
        let res = run(&input, &out, &only(&["boot"])).unwrap();
        assert_eq!(res.len(), 1);
        assert_eq!(files_in(&out), ["boot.img"]);
        assert_eq!(std::fs::read(out.join("boot.img")).unwrap(), expected[1].1);
        let e = run(&input, &scratch("t6-out2"), &only(&["boot", "sysem"]))
            .unwrap_err()
            .to_string();
        assert!(
            e.contains("unknown name \"sysem\"") && e.contains("available: boot, system"),
            "{e}"
        );
        assert_eq!(
            super::list(&input, &only(&["system"]))
                .unwrap()
                .unwrap()
                .len(),
            1
        );
    }

    #[test]
    fn headers_that_are_wrong_are_rejected_with_a_reason() {
        let (payload, _) = build(&mixed());
        let patch = |at: usize, bytes: &[u8]| {
            let mut p = payload.clone();
            p[at..at + bytes.len()].copy_from_slice(bytes);
            p
        };
        let read = |p: &[u8]| {
            read_payload(&mut &p[..], p.len() as u64)
                .map(|_| ())
                .unwrap_err()
                .to_string()
        };
        assert!(read(&patch(0, b"CrAV")).contains("bad magic"));
        assert!(read(&patch(4, &1u64.to_be_bytes())).contains("version 1"));
        assert!(read(&payload[..10]).contains("too short"));
        assert!(read(&patch(12, &u64::MAX.to_be_bytes())).contains("do not fit"));
        assert!(read(&patch(12, &(MAX_MANIFEST_BYTES + 1).to_be_bytes())).contains("do not fit"));
        assert!(read(&patch(20, &u32::MAX.to_be_bytes())).contains("do not fit"));
        assert!(
            read(&payload[..40]).contains("manifest"),
            "truncated inside the manifest"
        );
        let mut garbage = payload.clone();
        garbage[24..40].copy_from_slice(&[0xFF; 16]);
        assert!(read(&garbage).contains("decoding the manifest"));
    }

    #[test]
    fn every_truncation_of_a_payload_is_an_error_or_a_clean_failure() {
        let (payload, _) = build(&[part(
            "p",
            vec![op(Kind::Xz, &[(0, 2)], 1), op(Kind::Raw, &[(2, 2)], 2)],
        )]);
        let dir = scratch("t8");
        for cut in (0..payload.len()).step_by(7).chain([payload.len() - 1]) {
            let f = dir.join("payload.bin");
            std::fs::write(&f, &payload[..cut]).unwrap();
            let out = dir.join(format!("out{cut}"));
            let r = run(&dir, &out, &ExtractOptions::default());
            assert!(r.is_err(), "cut at {cut} of {} must fail", payload.len());
            assert!(
                files_in(&out)
                    .iter()
                    .all(|n| !n.ends_with(".part") && !n.ends_with(".img")),
                "cut {cut} left files: {:?}",
                files_in(&out)
            );
        }
    }

    #[test]
    fn incremental_operations_are_refused_before_anything_is_written() {
        for (what, edit) in [
            ("SOURCE_COPY", Some(4)),
            ("SOURCE_BSDIFF", Some(5)),
            ("BROTLI_BSDIFF", Some(10)),
            ("PUFFDIFF", Some(9)),
            ("type 77", Some(77)),
            ("older partition", None),
        ] {
            let mut parts = mixed();
            match edit {
                Some(t) => parts[0].ops[2].raw_type = Some(t),
                None => parts[1].old_info = true,
            }
            let (payload, _) = build(&parts);
            let out = scratch(&format!("t9-{}", what.replace(' ', "")));
            let e = run(
                &as_dir(&format!("t9{}", what.replace(' ', "")), &payload).1,
                &out,
                &ExtractOptions::default(),
            )
            .unwrap_err()
            .to_string();
            assert!(
                e.contains("incremental OTA") && e.contains(what),
                "{what}: {e}"
            );
            assert!(
                files_in(&out).is_empty(),
                "{what}: nothing may be created, found {:?}",
                files_in(&out)
            );
        }
    }

    #[test]
    fn incremental_partitions_are_fine_when_not_selected() {
        let mut parts = mixed();
        parts[0].ops[2].raw_type = Some(OP_REPLACE + 4); // SOURCE_COPY in system only
        let (payload, expected) = build(&parts);
        let out = scratch("t9b-out");
        let only = ExtractOptions {
            only: Some(vec!["boot".into()]),
            ..Default::default()
        };
        run(&as_dir("t9b", &payload).1, &out, &only).unwrap();
        assert_eq!(std::fs::read(out.join("boot.img")).unwrap(), expected[1].1);
    }

    #[test]
    fn a_corrupt_operation_hash_fails_everything_and_leaves_nothing() {
        let mut parts = mixed();
        parts[0].ops[1].bad_op_hash = true;
        let (payload, _) = build(&parts);
        let out = scratch("t10-out");
        let e = run(&as_dir("t10", &payload).1, &out, &ExtractOptions::default())
            .unwrap_err()
            .to_string();
        assert!(
            e.contains("does not match its sha256") && e.contains("partition system"),
            "{e}"
        );
        assert!(
            files_in(&out).is_empty(),
            "all-or-nothing: {:?}",
            files_in(&out)
        );
    }

    #[test]
    fn a_wrong_partition_hash_is_an_error_naming_both_hashes() {
        let mut parts = mixed();
        parts[1].hash = Hash::Bad;
        let (payload, _) = build(&parts);
        let out = scratch("t11-out");
        let e = run(&as_dir("t11", &payload).1, &out, &ExtractOptions::default())
            .unwrap_err()
            .to_string();
        assert!(
            e.contains("partition boot: sha256 mismatch") && e.contains(&"ab".repeat(32)),
            "{e}"
        );
        assert!(
            files_in(&out).is_empty(),
            "the good partition is not published either: {:?}",
            files_in(&out)
        );
    }

    #[test]
    fn missing_hashes_and_verity_data_are_reported_honestly() {
        let mut parts = mixed();
        parts[0].hash = Hash::Absent;
        parts[1].verity = true;
        parts[1].hash = Hash::Bad; // would fail if it were checked
        let (payload, expected) = build(&parts);
        let (out, res) = go(&as_dir("t12", &payload).1, "t12").unwrap();
        images_match(&out, &expected);
        assert_eq!(
            res[0].1,
            "sha256 not checked: the payload leaves out the dm-verity/FEC data the device adds"
        );
        assert_eq!(res[1].1, "no hash in the payload to check");
    }

    #[test]
    fn data_that_does_not_fill_its_extents_exactly_is_an_error() {
        for kind in [Kind::Raw, Kind::Bz, Kind::Xz, Kind::Zstd] {
            for (data_blocks, extent_blocks, what) in [(2u64, 3u64, "ends"), (3, 2, "more than")] {
                let mut o = op(kind, &[(0, extent_blocks)], 1);
                o.data = bytes(1, (data_blocks * BS) as usize);
                let mut p = part("p", vec![o]);
                p.hash = Hash::Absent;
                let (payload, _) = build(&[p]);
                let out = scratch(&format!("t13-{kind:?}-{data_blocks}"));
                let e = run(
                    &as_dir(&format!("t13{kind:?}{data_blocks}"), &payload).1,
                    &out,
                    &ExtractOptions::default(),
                )
                .unwrap_err()
                .to_string();
                assert!(
                    e.contains(what),
                    "{kind:?} {data_blocks}/{extent_blocks}: {e}"
                );
                assert!(files_in(&out).is_empty());
            }
        }
    }

    #[test]
    fn corrupt_compressed_data_is_an_error_not_a_panic() {
        for kind in [Kind::Bz, Kind::Xz, Kind::Zstd] {
            let mut spec = part("p", vec![op(kind, &[(0, 4)], 3)]);
            spec.hash = Hash::Absent;
            let (mut payload, _) = build(&[spec]);
            let at = payload.len() - 12;
            payload[at..].fill(0xFF); // damage the end of the only blob
            // drop the per-operation hash so the decoder, not the hash check, has to notice
            let payload = with_manifest(payload, |m| {
                m.partitions[0].operations[0].data_sha256_hash = None
            });
            let out = scratch(&format!("t14-{kind:?}-out"));
            let e = run(
                &as_dir(&format!("t14{kind:?}"), &payload).1,
                &out,
                &ExtractOptions::default(),
            );
            assert!(e.is_err(), "{kind:?}: corrupt data must fail");
            assert!(files_in(&out).is_empty(), "{kind:?}: {:?}", files_in(&out));
        }
    }

    fn with_manifest(
        mut payload: Vec<u8>,
        edit: impl Fn(&mut pb::DeltaArchiveManifest),
    ) -> Vec<u8> {
        let msize = be64(&payload[12..20]) as usize;
        let mut manifest = pb::DeltaArchiveManifest::decode(&payload[24..24 + msize]).unwrap();
        edit(&mut manifest);
        let m = manifest.encode_to_vec();
        let tail = payload.split_off(24 + msize + 5);
        let mut out = Vec::new();
        out.extend(MAGIC);
        out.extend(2u64.to_be_bytes());
        out.extend((m.len() as u64).to_be_bytes());
        out.extend(5u32.to_be_bytes());
        out.extend(&m);
        out.extend([0xEE; 5]);
        out.extend(tail);
        out
    }

    fn rejects(tag: &str, payload: Vec<u8>, want: &str) {
        let out = scratch(&format!("{tag}-out"));
        let e = run(&as_dir(tag, &payload).1, &out, &ExtractOptions::default())
            .unwrap_err()
            .to_string();
        assert!(e.contains(want), "{tag}: expected {want:?} in {e}");
        assert!(files_in(&out).is_empty(), "{tag}: {:?}", files_in(&out));
    }

    #[test]
    fn hostile_manifests_are_rejected_before_any_file_is_made() {
        let (base, _) = build(&mixed());
        rejects(
            "h1",
            with_manifest(base.clone(), |m| {
                m.partitions[0].operations[0].dst_extents[0].start_block = Some(u64::MAX / 2)
            }),
            "overflows",
        );
        rejects(
            "h2",
            with_manifest(base.clone(), |m| {
                m.partitions[0].operations[0].dst_extents[0].start_block = Some(u64::MAX)
            }),
            "sparse-hole",
        );
        rejects(
            "h3",
            with_manifest(base.clone(), |m| {
                m.partitions[0].operations[0].data_offset = Some(1 << 50)
            }),
            "data ends",
        );
        rejects(
            "h4",
            with_manifest(base.clone(), |m| {
                m.partitions[0].operations[0].data_length = Some(MAX_BLOB_BYTES + 1)
            }),
            "limit",
        );
        rejects(
            "h5",
            with_manifest(base.clone(), |m| {
                m.partitions[0].operations[0].data_length = Some(0)
            }),
            "no data",
        );
        rejects(
            "h6",
            with_manifest(base.clone(), |m| {
                m.partitions[0].operations[0].dst_extents.clear()
            }),
            "no destination extents",
        );
        rejects(
            "h7",
            with_manifest(base.clone(), |m| {
                m.partitions[0].new_partition_info.as_mut().unwrap().size =
                    Some(MAX_PARTITION_BYTES + 1)
            }),
            "limit",
        );
        rejects(
            "h8",
            with_manifest(base.clone(), |m| {
                m.partitions[0].new_partition_info.as_mut().unwrap().size = Some(BS)
            }),
            "extents reach",
        );
        rejects(
            "h9",
            with_manifest(base.clone(), |m| {
                m.partitions[0].operations[1].dst_extents[0].start_block = Some(1)
            }),
            "overlapping",
        );
        rejects(
            "h10",
            with_manifest(base.clone(), |m| m.block_size = Some(100)),
            "block size",
        );
        rejects(
            "h11",
            with_manifest(base.clone(), |m| m.block_size = Some(2 << 20)),
            "block size",
        );
        rejects(
            "h12",
            with_manifest(base.clone(), |m| m.partitions.clear()),
            "no partitions",
        );
        rejects(
            "h13",
            with_manifest(base.clone(), |m| {
                m.partitions[0].partition_name = "../evil".into()
            }),
            "unsafe partition name",
        );
        rejects(
            "h14",
            with_manifest(base.clone(), |m| {
                m.partitions[1].partition_name = "SYSTEM".into()
            }),
            "differ only by case",
        );
        rejects(
            "h15",
            with_manifest(base.clone(), |m| {
                m.partitions[0].operations[0].dst_extents[0].num_blocks = Some(u64::MAX / 100)
            }),
            "overflows",
        );
    }

    #[test]
    fn a_partition_listed_twice_is_refused_so_two_writers_never_share_a_file() {
        let (base, _) = build(&mixed());
        rejects(
            "d1",
            with_manifest(base.clone(), |m| {
                m.partitions[1].partition_name = m.partitions[0].partition_name.clone()
            }),
            "listed more than once",
        );
        // three entries, two of them equal and not adjacent in the manifest order
        rejects(
            "d2",
            with_manifest(base, |m| {
                let mut extra = m.partitions[0].clone();
                extra.partition_name = "zzz".into();
                m.partitions.push(extra);
                m.partitions[1].partition_name = "zzz".into();
            }),
            "listed more than once",
        );
    }

    #[test]
    fn the_failed_run_removes_part_files_even_when_workers_stop_midway() {
        let mut parts = mixed();
        parts[0].ops[4].raw_type = None;
        let mut bad = op(Kind::Xz, &[(30, 2)], 7);
        bad.bad_op_hash = true;
        parts[0].ops.push(bad);
        parts[0]
            .ops
            .extend((0..40u64).map(|i| op(Kind::Xz, &[(40 + i, 1)], i as u8)));
        let (payload, _) = build(&parts);
        let out = scratch("t16-out");
        assert!(run(&as_dir("t16", &payload).1, &out, &ExtractOptions::default()).is_err());
        assert!(files_in(&out).is_empty(), "{:?}", files_in(&out));
    }

    #[test]
    fn existing_output_is_refused_without_force_and_replaced_with_it() {
        let (payload, expected) = build(&mixed());
        let (_g, input) = as_dir("t17", &payload);
        let out = scratch("t17-out");
        std::fs::write(out.join("boot.img"), b"precious").unwrap();
        let e = run(&input, &out, &ExtractOptions::default())
            .unwrap_err()
            .to_string();
        assert!(
            e.contains("boot.img") && !e.contains("system.img") && e.contains("--force"),
            "{e}"
        );
        assert_eq!(files_in(&out), ["boot.img"], "a refused run writes nothing");
        assert_eq!(std::fs::read(out.join("boot.img")).unwrap(), b"precious");
        run(
            &input,
            &out,
            &ExtractOptions {
                force: true,
                ..Default::default()
            },
        )
        .unwrap();
        images_match(&out, &expected);
    }

    #[cfg(unix)]
    #[test]
    fn planted_symlinks_are_never_written_through() {
        use std::os::unix::fs::symlink;
        let (payload, expected) = build(&mixed());
        let (_g, input) = as_dir("t18", &payload);
        let out = scratch("t18-out");
        let gv = scratch("t18-victim");
        let victim = gv.join("v");
        symlink(&victim, out.join("boot.img.part")).unwrap();
        let gv2 = scratch("t18-victim2");
        symlink(gv2.join("w"), out.join("system.img")).unwrap(); // dangling
        let e = run(&input, &out, &ExtractOptions::default())
            .unwrap_err()
            .to_string();
        assert!(e.contains("system.img") && e.contains("--force"), "{e}");
        assert!(!victim.exists());
        std::fs::remove_file(out.join("system.img")).unwrap();
        run(&input, &out, &ExtractOptions::default()).unwrap();
        assert!(!victim.exists(), "the .part symlink must not be followed");
        images_match(&out, &expected);
    }

    #[test]
    fn a_deflated_payload_in_a_zip_gets_a_clear_message() {
        let (payload, _) = build(&mixed());
        let (_g, z) = as_zip("t19", &payload, zip::CompressionMethod::Deflated);
        let e = format!("{:#}", locate(&z).unwrap_err());
        assert!(
            e.contains("compressed inside the zip") && e.contains("unzip"),
            "{e}"
        );
    }

    #[test]
    fn inputs_that_are_not_ab_otas_are_left_alone() {
        let d = scratch("t20");
        assert!(
            locate(&d).unwrap().is_none(),
            "directory without payload.bin"
        );
        std::fs::write(d.join("x.txt"), b"hello").unwrap();
        assert!(locate(&d.join("x.txt")).unwrap().is_none());
        std::fs::write(d.join("tiny"), b"CrA").unwrap();
        assert!(locate(&d.join("tiny")).unwrap().is_none());
        std::fs::write(d.join("empty"), b"").unwrap();
        assert!(locate(&d.join("empty")).unwrap().is_none());
        let z = d.join("plain.zip");
        let mut w = zip::ZipWriter::new(File::create(&z).unwrap());
        w.start_file("a.txt", zip::write::SimpleFileOptions::default())
            .unwrap();
        w.write_all(b"x").unwrap();
        w.finish().unwrap();
        assert!(locate(&z).unwrap().is_none(), "a zip without payload.bin");
        std::fs::write(d.join("PKbad.zip"), b"PK\x03\x04garbage").unwrap();
        assert!(
            locate(&d.join("PKbad.zip")).unwrap().is_none(),
            "a damaged zip is not a payload"
        );
        assert!(locate(&d.join("missing")).is_err());
    }

    #[test]
    fn locate_finds_the_payload_inside_a_stored_zip_entry() {
        let (payload, _) = build(&mixed());
        let (_g, z) = as_zip("t21", &payload, zip::CompressionMethod::Stored);
        let loc = locate(&z).unwrap().unwrap();
        assert_eq!(loc.len, payload.len() as u64);
        let raw = std::fs::read(&z).unwrap();
        assert_eq!(&raw[loc.base as usize..loc.base as usize + 4], b"CrAU");
        assert_eq!(&raw[loc.base as usize..][..payload.len()], &payload[..]);
        assert_eq!(partition_names(&z).unwrap().unwrap(), ["boot", "system"]);
        assert!(partition_names(&scratch("t21b")).unwrap().is_none());
    }

    #[test]
    fn operation_type_numbers_are_the_literal_values_from_the_proto() {
        // not derived from the constants, so a wrong constant cannot hide behind the test builder
        assert_eq!(
            [
                OP_REPLACE,
                OP_REPLACE_BZ,
                OP_ZERO,
                OP_DISCARD,
                OP_REPLACE_XZ,
                OP_ZSTD
            ],
            [0, 1, 6, 7, 8, 14]
        );
        for (n, data_op) in [
            (0, true),
            (1, true),
            (8, true),
            (14, true),
            (6, false),
            (7, false),
            (4, false),
            (5, false),
            (2, false),
            (3, false),
            (9, false),
            (10, false),
            (11, false),
            (12, false),
            (13, false),
            (15, false),
            (-1, false),
        ] {
            assert_eq!(is_data_op(n), data_op, "type {n}");
        }
    }

    #[test]
    fn a_zero_length_verity_extent_does_not_count_as_verity_data() {
        let (payload, expected) = build(&mixed());
        let payload = with_manifest(payload, |m| {
            m.partitions[0].hash_tree_extent = Some(pb::Extent {
                start_block: Some(3),
                num_blocks: Some(0),
            });
            m.partitions[0].fec_extent = Some(pb::Extent {
                start_block: None,
                num_blocks: None,
            });
        });
        let (out, res) = go(&as_dir("t24", &payload).1, "t24").unwrap();
        images_match(&out, &expected);
        assert!(res.iter().all(|(_, n)| n == "sha256 verified"), "{res:?}");
        let with_data = with_manifest(build(&mixed()).0, |m| {
            m.partitions[1].fec_data_extent = Some(pb::Extent {
                start_block: Some(0),
                num_blocks: Some(1),
            })
        });
        let (_, res) = go(&as_dir("t24b", &with_data).1, "t24b").unwrap();
        assert!(
            res[0].1.starts_with("sha256 not checked"),
            "boot has fec data: {res:?}"
        );
        let with_fec = with_manifest(build(&mixed()).0, |m| {
            m.partitions[1].fec_extent = Some(pb::Extent {
                start_block: Some(0),
                num_blocks: Some(1),
            })
        });
        assert!(
            go(&as_dir("t24c", &with_fec).1, "t24c").unwrap().1[0]
                .1
                .starts_with("sha256 not checked")
        );
        let with_tree_data = with_manifest(build(&mixed()).0, |m| {
            m.partitions[1].hash_tree_data_extent = Some(pb::Extent {
                start_block: Some(0),
                num_blocks: Some(1),
            })
        });
        assert!(
            go(&as_dir("t24d", &with_tree_data).1, "t24d").unwrap().1[0]
                .1
                .starts_with("sha256 not checked")
        );
    }

    #[test]
    fn zero_block_extents_inside_an_operation_are_skipped() {
        let mut o = op(Kind::Xz, &[(0, 2), (9, 0), (6, 1), (0, 0)], 4);
        o.data = bytes(4, (3 * BS) as usize);
        let mut p = part("p", vec![o, op(Kind::Zero, &[(3, 0)], 0)]);
        p.size = Some(8 * BS);
        let (payload, expected) = build(&[p]);
        let (out, res) = go(&as_dir("t27", &payload).1, "t27").unwrap();
        images_match(&out, &expected);
        assert_eq!(res[0].1, "sha256 verified");
    }

    #[test]
    fn the_extent_writer_places_bytes_correctly_whatever_the_write_sizes() {
        let dir = scratch("t25");
        let path = dir.join("img");
        let extents = [(30u64, 4u64), (0, 6), (10, 1)];
        let data: Vec<u8> = (1..=11).collect();
        for pieces in [
            vec![11usize],
            vec![1; 11],
            vec![3, 3, 3, 2],
            vec![4, 6, 1],
            vec![5, 5, 1],
            vec![2, 8, 1],
            vec![10, 1],
        ] {
            File::create(&path).unwrap().set_len(40).unwrap();
            let mut w = ExtentWriter {
                file: File::options().write(true).open(&path).unwrap(),
                extents: &extents,
                idx: 0,
                within: 0,
            };
            let mut at = 0;
            for n in pieces.iter().copied() {
                w.write_all(&data[at..at + n]).unwrap();
                at += n;
            }
            let got = std::fs::read(&path).unwrap();
            let mut want = vec![0u8; 40];
            want[30..34].copy_from_slice(&data[0..4]);
            want[0..6].copy_from_slice(&data[4..10]);
            want[10] = data[10];
            assert_eq!(got, want, "writes of {pieces:?}");
            let e = w.write(&[1]).unwrap_err().to_string();
            assert!(e.contains("more data than"), "{e}");
        }
    }

    #[test]
    fn a_partition_count_over_the_limit_is_refused_before_anything_is_made() {
        let (base, _) = build(&mixed());
        let many = with_manifest(base.clone(), |m| {
            let one = m.partitions[1].clone();
            m.partitions = (0..=MAX_PARTITIONS)
                .map(|i| pb::PartitionUpdate {
                    partition_name: format!("p{i}"),
                    ..one.clone()
                })
                .collect();
        });
        rejects("c1", many, "over the limit of 1024");
        // exactly at the limit is fine, and does not need 1024 open files at once
        let at_limit = with_manifest(base, |m| {
            let mut one = m.partitions[1].clone();
            one.operations.truncate(1);
            m.partitions = (0..MAX_PARTITIONS)
                .map(|i| pb::PartitionUpdate {
                    partition_name: format!("p{i}"),
                    ..one.clone()
                })
                .collect();
        });
        let out = scratch("c2-out");
        let only = ExtractOptions {
            only: Some(vec!["p0".into(), "p1023".into()]),
            ..Default::default()
        };
        assert_eq!(
            run(&as_dir("c2", &at_limit).1, &out, &only).unwrap().len(),
            2
        );
    }

    #[test]
    fn the_limits_are_the_documented_values() {
        assert_eq!(MAX_PARTITION_BYTES, 64 << 30);
        assert_eq!(MAX_MANIFEST_BYTES, 64 << 20);
        assert_eq!(MAX_PARTITIONS, 1024);
        let (payload, _) = build(&mixed());
        let big = with_manifest(payload, |m| {
            m.partitions[1].new_partition_info.as_mut().unwrap().size =
                Some(MAX_PARTITION_BYTES + 1)
        });
        rejects("c3", big, "limit");
    }

    #[test]
    fn hashing_a_file_shorter_than_expected_is_an_error() {
        let dir = scratch("t26");
        std::fs::write(dir.join("short"), [7u8; 10]).unwrap();
        assert!(
            hash_file(&dir.join("short"), 20)
                .unwrap_err()
                .to_string()
                .contains("shorter")
        );
        assert_eq!(
            hash_file(&dir.join("short"), 10).unwrap(),
            Sha256::digest([7u8; 10]).to_vec()
        );
        assert_eq!(
            hash_file(&dir.join("short"), 4).unwrap(),
            Sha256::digest([7u8; 4]).to_vec(),
            "only the first `size` bytes"
        );
        assert_eq!(
            hash_file(&dir.join("short"), 0).unwrap(),
            Sha256::digest([]).to_vec()
        );
    }

    #[test]
    fn extent_overflow_edges_are_rejected_on_their_own() {
        let (base, _) = build(&mixed());
        // start and num each fit when multiplied by the block size, their sum does not
        let half = u64::MAX / BS;
        rejects(
            "o1",
            with_manifest(base.clone(), |m| {
                m.partitions[0].operations[0].dst_extents[0] = pb::Extent {
                    start_block: Some(half),
                    num_blocks: Some(half),
                };
            }),
            "extent end overflows",
        );
        // start + num itself overflows
        rejects(
            "o2",
            with_manifest(base.clone(), |m| {
                m.partitions[0].operations[0].dst_extents[0] = pb::Extent {
                    start_block: Some(u64::MAX - 1),
                    num_blocks: Some(5),
                };
            }),
            "extent overflows",
        );
        // a huge but representable extent is a size error, not an overflow
        rejects(
            "o3",
            with_manifest(base, |m| {
                m.partitions[0].operations[0].dst_extents[0] = pb::Extent {
                    start_block: Some(1 << 40),
                    num_blocks: Some(1),
                };
            }),
            "extents reach",
        );
    }

    #[test]
    fn the_operation_type_table_matches_the_proto() {
        for (n, name) in [
            (0, "REPLACE"),
            (1, "REPLACE_BZ"),
            (2, "MOVE"),
            (3, "BSDIFF"),
            (4, "SOURCE_COPY"),
            (5, "SOURCE_BSDIFF"),
            (6, "ZERO"),
            (7, "DISCARD"),
            (8, "REPLACE_XZ"),
            (9, "PUFFDIFF"),
            (10, "BROTLI_BSDIFF"),
            (11, "ZUCCHINI"),
            (12, "LZ4DIFF_BSDIFF"),
            (13, "LZ4DIFF_PUFFDIFF"),
            (14, "ZSTD"),
        ] {
            assert_eq!(op_name(n), name);
        }
        assert_eq!(op_name(99), "type 99");
        assert_eq!(hex(&[0x00, 0xab, 0x0f]), "00ab0f");
    }

    #[test]
    fn the_command_prints_a_note_per_image() {
        let (payload, _) = build(&mixed());
        let (_g, input) = as_dir("t23", &payload);
        let out = scratch("t23-out");
        let done =
            crate::extract::extract_all_noted(&input, &out, &ExtractOptions::default()).unwrap();
        assert_eq!(done.len(), 2);
        assert!(done.iter().all(|(_, n)| n == "sha256 verified"));
        assert_eq!(
            crate::extract::list_images(&input, &ExtractOptions::default())
                .unwrap()
                .len(),
            2
        );
        assert_eq!(
            crate::extract::partition_names(&input).unwrap(),
            ["boot", "system"]
        );
    }
}
