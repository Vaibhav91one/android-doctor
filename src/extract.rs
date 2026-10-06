//! Extract partition images from a block OTA (a zip or an already unpacked directory).
use crate::{detect, pac, payload, sdat, transfer_list};
use anyhow::{Context, Result, anyhow, bail};
use indicatif::{MultiProgress, ProgressBar, ProgressStyle};
use std::fs::File;
use std::io::IsTerminal;
use std::io::{BufReader, BufWriter, Read, Seek, Write};
use std::path::{Path, PathBuf};
use std::sync::mpsc::{Receiver, SyncSender, sync_channel};

const LIST_SUFFIX: &str = ".transfer.list";
/// Transfer lists are a few KiB; the cap stops a hostile zip from exhausting memory.
const MAX_LIST_BYTES: u64 = 16 << 20;

/// A top-level file from the OTA that no handler recognised.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Skipped {
    pub name: String,
    pub reason: String,
}

impl std::fmt::Display for Skipped {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "{} ({})", self.name, self.reason)
    }
}

/// Result of an extraction run: written image paths (with verification notes) and the
/// top-level inputs that were skipped or unrecognised.
#[derive(Debug, Default, Clone)]
pub struct ExtractResult {
    pub done: Vec<(PathBuf, String)>,
    /// Recognised OTA scaffolding we looked at and deliberately did not extract.
    pub ignored: Vec<Skipped>,
    /// Top-level inputs with no handler and no scaffolding match: the security-relevant case.
    pub unhandled: Vec<Skipped>,
}

/// Where the OTA files come from.
enum Source {
    Zip(zip::ZipArchive<File>),
    Dir(PathBuf),
}

impl Source {
    fn open(input: &Path) -> Result<Self> {
        if input.is_dir() {
            return Ok(Self::Dir(input.to_path_buf()));
        }
        let file = File::open(input).with_context(|| format!("opening {}", input.display()))?;
        Ok(Self::Zip(
            zip::ZipArchive::new(file).context("not a valid zip file")?,
        ))
    }

    /// Names of the files at the top level of the OTA.
    fn names(&self) -> Result<Vec<String>> {
        Ok(match self {
            Self::Zip(zip) => zip
                .file_names()
                .filter(|n| !n.contains('/'))
                .map(String::from)
                .collect(),
            Self::Dir(dir) => std::fs::read_dir(dir)?
                .filter(|e| e.as_ref().map_or(true, |e| e.path().is_file()))
                .map(|e| e.map(|e| e.file_name().to_string_lossy().into_owned()))
                .collect::<std::io::Result<_>>()?,
        })
    }

    /// Size in bytes of a top-level file, for the progress bar.
    fn file_size(&mut self, name: &str) -> Result<u64> {
        Ok(match self {
            Self::Zip(zip) => zip.by_name(name)?.size(),
            Self::Dir(dir) => std::fs::metadata(dir.join(name))?.len(),
        })
    }

    fn open_file(&mut self, name: &str) -> Result<Box<dyn Read + '_>> {
        let reader: Box<dyn Read + '_> = match self {
            Self::Zip(zip) => Box::new(
                zip.by_name(name)
                    .with_context(|| format!("{name} not found in zip"))?,
            ),
            Self::Dir(dir) => {
                Box::new(File::open(dir.join(name)).with_context(|| format!("opening {name}"))?)
            }
        };
        Ok(reader)
    }
}

/// Read and parse `<part>.transfer.list`.
fn read_list(src: &mut Source, part: &str) -> Result<transfer_list::TransferList> {
    let mut text = String::new();
    src.open_file(&format!("{part}{LIST_SUFFIX}"))?
        .take(MAX_LIST_BYTES + 1)
        .read_to_string(&mut text)?;
    if text.len() as u64 > MAX_LIST_BYTES {
        bail!("{part}{LIST_SUFFIX} is larger than {MAX_LIST_BYTES} bytes");
    }
    transfer_list::parse(&text).with_context(|| format!("{part}{LIST_SUFFIX}"))
}

/// The data file(s) of a partition in reading order, and whether they are brotli-compressed.
/// Preference: whole `.new.dat.br`, whole `.new.dat`, then numbered pieces (`.new.dat.br.N`,
/// `.new.dat.N`), which are joined in numeric order and must be consecutive from 0 or 1.
fn data_files(names: &[String], part: &str) -> Result<(Vec<String>, bool)> {
    for (name, compressed) in [
        (format!("{part}.new.dat.br"), true),
        (format!("{part}.new.dat"), false),
    ] {
        if names.contains(&name) {
            return Ok((vec![name], compressed));
        }
    }
    for (prefix, compressed) in [
        (format!("{part}.new.dat.br."), true),
        (format!("{part}.new.dat."), false),
    ] {
        let mut pieces: Vec<(u64, &String)> = names
            .iter()
            .filter_map(|n| {
                let digits = n.strip_prefix(&prefix)?;
                if digits.is_empty() || !digits.bytes().all(|b| b.is_ascii_digit()) {
                    return None;
                }
                Some((digits.parse().ok()?, n))
            })
            .collect();
        if pieces.is_empty() {
            continue;
        }
        pieces.sort_unstable();
        let first = pieces[0].0;
        if first > 1
            || pieces
                .iter()
                .enumerate()
                .any(|(i, p)| p.0 != first + i as u64)
        {
            let found: Vec<String> = pieces.iter().map(|p| p.0.to_string()).collect();
            bail!(
                "{part}: pieces {prefix}N are not consecutive from 0 or 1 (found {})",
                found.join(", ")
            );
        }
        return Ok((
            pieces.into_iter().map(|p| p.1.clone()).collect(),
            compressed,
        ));
    }
    bail!(
        "{part}: neither {part}.new.dat.br nor {part}.new.dat (nor numbered pieces of either) found"
    );
}

type Chunk = std::io::Result<Vec<u8>>;

/// Read the pieces one after the other (own handle on the OTA) and send them as chunks. An error
/// is sent as the last message; a closed channel means the consumer is done, so just stop.
fn pump_pieces(input: &Path, pieces: &[String], tx: SyncSender<Chunk>) {
    let sent = (|| -> Result<()> {
        let mut src = Source::open(input)?;
        for name in pieces {
            let mut reader = src.open_file(name)?;
            loop {
                let mut chunk = vec![0u8; 1 << 20];
                let n = reader
                    .read(&mut chunk)
                    .with_context(|| format!("reading {name}"))?;
                if n == 0 {
                    break;
                }
                chunk.truncate(n);
                if tx.send(Ok(chunk)).is_err() {
                    return Ok(());
                }
            }
        }
        Ok(())
    })();
    if let Err(e) = sent {
        let _ = tx.send(Err(std::io::Error::other(format!("{e:#}"))));
    }
}

/// `Read` over the chunks sent by `pump_pieces`.
struct ChunkReader {
    rx: Receiver<Chunk>,
    chunk: Vec<u8>,
    pos: usize,
}

impl ChunkReader {
    fn new(rx: Receiver<Chunk>) -> Self {
        Self {
            rx,
            chunk: Vec::new(),
            pos: 0,
        }
    }
}

impl Read for ChunkReader {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        while self.pos >= self.chunk.len() {
            match self.rx.recv() {
                Ok(chunk) => {
                    self.chunk = chunk?;
                    self.pos = 0;
                }
                Err(_) => return Ok(0), // sender finished: end of data
            }
        }
        let n = buf.len().min(self.chunk.len() - self.pos);
        buf[..n].copy_from_slice(&self.chunk[self.pos..self.pos + n]);
        self.pos += n;
        Ok(n)
    }
}

/// Build `<part>.img` in `out_dir`. The image is written under a temporary name and renamed
/// when complete, so a failed extraction never leaves a plausible-looking partial image.
fn extract_partition(
    input: &Path,
    src: &mut Source,
    names: &[String],
    part: &str,
    out_dir: &Path,
    bar: &ProgressBar,
) -> Result<PathBuf> {
    let list = read_list(src, part)?;
    let (data_names, compressed) = data_files(names, part)?;
    let mut total = 0;
    for name in &data_names {
        total += src.file_size(name)?;
    }
    bar.set_length(total);

    let final_path = out_dir.join(format!("{part}.img"));
    let tmp_path = out_dir.join(format!("{part}.img.part"));
    let built = std::thread::scope(|scope| -> Result<()> {
        let reader: Box<dyn Read + '_> = if let [only] = data_names.as_slice() {
            src.open_file(only)?
        } else {
            // Several pieces are read one after the other by a helper thread (each piece needs
            // its own handle on a zip) and handed over through a small bounded channel.
            let (tx, rx) = sync_channel(4);
            let pieces = &data_names;
            scope.spawn(move || pump_pieces(input, pieces, tx));
            Box::new(ChunkReader::new(rx))
        };
        let data = BufReader::new(bar.wrap_read(reader));
        let mut out = BufWriter::new(create_part(&tmp_path)?);
        if compressed {
            sdat::apply(&list, sdat::brotli_reader(data), &mut out)?;
        } else {
            sdat::apply(&list, data, &mut out)?;
        }
        out.flush()?;
        Ok(())
    });
    if let Err(e) = built {
        let _ = std::fs::remove_file(&tmp_path);
        return Err(e.context(format!("extracting {part}")));
    }
    std::fs::rename(&tmp_path, &final_path)?;
    Ok(final_path)
}

/// Partition names (from `<part>.transfer.list`) among the top-level file names, sorted.
fn partitions_in(names: &[String]) -> Vec<&str> {
    let mut parts: Vec<&str> = names
        .iter()
        .filter_map(|n| n.strip_suffix(LIST_SUFFIX))
        .collect();
    parts.sort_unstable();
    parts
}

/// Partition names found in an OTA zip or directory (empty for a non-block OTA).
pub fn partition_names(input: &Path) -> Result<Vec<String>> {
    if let Some(names) = payload::partition_names(input)? {
        return Ok(names);
    }
    if let Some(kind) = crate::oem::detect(input) {
        return crate::oem::partition_names(kind, input);
    }
    let names = Source::open(input)?.names()?;
    Ok(partitions_in(&names)
        .into_iter()
        .map(String::from)
        .collect())
}

/// What `extract` should do beyond the defaults.
#[derive(Debug, Default, Clone)]
pub struct ExtractOptions {
    /// Replace existing output files instead of refusing.
    pub force: bool,
    /// Directory holding the base partition images for an incremental OTA (`--base <dir>`).
    /// When `None`, incremental operations (SOURCE_COPY, SOURCE_BSDIFF) are refused.
    pub base: Option<PathBuf>,
    /// Extract only these partitions / raw images (by name without `.img`); `None` = all.
    pub only: Option<Vec<String>>,
    /// Print what would be extracted, with sizes, and write nothing.
    pub list: bool,
    /// Also extract the file tree of every ext2/3/4 image into `<out>/files/<image>/`.
    pub files: bool,
    /// Do not fail when some inputs are skipped; print a summary and exit 0.
    pub allow_partial: bool,
    /// Treat unrecognised top-level files as an error instead of a warning.
    pub strict: bool,
    /// Suppress progress bars and per-image summary lines; errors still show.
    pub quiet: bool,
    /// Print debug traces to stderr.
    pub verbose: bool,
    /// Never emit ANSI colour escapes.
    pub no_color: bool,
}

/// Create a fresh `.part` file. A stale one (or a planted symlink) is removed first and the new
/// file is created exclusively, so a write never follows a link to somewhere else.
pub(crate) fn create_part(path: &Path) -> Result<File> {
    let _ = std::fs::remove_file(path);
    File::create_new(path).with_context(|| format!("creating {}", path.display()))
}

/// Top-level `*.img` files (boot, recovery, dtbo, vbmeta, ...), sorted.
fn raw_images_in(names: &[String]) -> Vec<&str> {
    let mut raw: Vec<&str> = names
        .iter()
        .map(String::as_str)
        .filter(|n| n.ends_with(".img") || is_archive_name(n))
        .collect();
    raw.sort_unstable();
    raw
}

/// A file name that an update is likely to ship its partition images in: a tar, one wrapped
/// in a compression we can undo, or a Samsung `.tar.md5`.
fn is_archive_name(name: &str) -> bool {
    name.ends_with(".tar")
        || name.ends_with(".tar.gz")
        || name.ends_with(".tgz")
        || name.ends_with(".tar.xz")
        || name.ends_with(".txz")
        || name.ends_with(".tar.bz2")
        || name.ends_with(".tbz2")
        || name.ends_with(".tar.zst")
        || name.ends_with(".tar.lz4")
        || name.ends_with(".tar.md5")
        || name.ends_with(".ozip")
}

/// True when `name` is a tar, a tar wrapped in a compression we can undo, or a Samsung
/// `.tar.md5` (whose body starts with the tar). A compressed file only counts when what it
/// decompresses to is a tar: a gzip `dt.img` is an image, not an archive (#114).
fn is_tar_family(src: &mut Source, name: &str, head: &[u8]) -> bool {
    use crate::archive::{Kind, compressed_holds_tar, kind_of};
    let tar = match kind_of(head) {
        Some(Kind::Tar) => true,
        Some(Kind::Compressed(c)) => src
            .open_file(name)
            .is_ok_and(|r| compressed_holds_tar(c, r)),
        _ => false,
    };
    tar || head.windows(4).any(|w| w == b"ustar")
}

/// Copy a file out of the OTA unchanged (`.part` + rename, like partition images).
fn copy_raw(src: &mut Source, name: &str, out_dir: &Path) -> Result<PathBuf> {
    let final_path = out_dir.join(name);
    let tmp_path = out_dir.join(format!("{name}.part"));
    let copied = (|| -> Result<()> {
        let mut out = create_part(&tmp_path)?;
        std::io::copy(&mut src.open_file(name)?, &mut out)?;
        Ok(())
    })();
    if let Err(e) = copied {
        let _ = std::fs::remove_file(&tmp_path);
        return Err(e.context(format!("copying {name}")));
    }
    std::fs::rename(&tmp_path, &final_path)?;
    Ok(final_path)
}

fn is_safe_name(p: &str) -> bool {
    !p.is_empty()
        && p.chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
}

/// The directory name an archive is unpacked into: SUPER.tar.md5 and SUPER.tar.gz both
/// become SUPER. For .ozip, the stem strips the .ozip suffix.
fn archive_stem(name: &str) -> &str {
    let base = name.strip_suffix(".md5").unwrap_or(name);
    if let Some(stem) = [".tgz", ".txz", ".tbz2"]
        .iter()
        .find_map(|short| base.strip_suffix(short))
    {
        return stem;
    }
    let base = [".gz", ".xz", ".bz2", ".zst", ".lz4"]
        .iter()
        .find_map(|compression| base.strip_suffix(compression))
        .unwrap_or(base);
    let base = base.strip_suffix(".tar").unwrap_or(base);
    base.strip_suffix(".ozip").unwrap_or(base)
}

/// Unpack the contents of a zip file into dir using the shared sink (safe paths,
/// staging, collision handling). Directories in the zip are created; regular files are
/// written through the sink; symlinks, devices and fifos are refused.
fn extract_zip(input: &mut (impl Read + Seek), dir: &Path) -> Result<()> {
    let mut zip = zip::ZipArchive::new(input).context("not a valid zip file")?;
    let collisions = crate::treeout::host_collisions(dir);
    let mut sink = crate::treeout::Sink::with_collisions(dir, collisions);
    for i in 0..zip.len() {
        let mut entry = zip.by_index(i).with_context(|| format!("zip entry {i}"))?;
        let name = entry
            .enclosed_name()
            .ok_or_else(|| anyhow!("zip entry {i} has a non-UTF-8 or unsafe path"))?
            .to_string_lossy()
            .to_string();
        let cleaned =
            crate::treeout::clean_path(&name).with_context(|| format!("zip entry {name:?}"))?;
        if entry.is_dir() {
            sink.add_dir(&cleaned)?;
        } else if entry.is_file() {
            sink.write_file(&cleaned, entry.unix_mode().unwrap_or(0o644), &mut entry)?;
        } else {
            bail!("zip entry {cleaned:?} is not a regular file or directory");
        }
    }
    Ok(())
}

/// Validate the OTA's names and apply --only: returns (partitions, raw images), both sorted.
fn select<'a>(
    names: &'a [String],
    only: &Option<Vec<String>>,
) -> Result<(Vec<&'a str>, Vec<&'a str>)> {
    let mut parts = partitions_in(names);
    // A JioSTB-style update directory holds nothing but a tar of its partition images.
    let has_archive = names.iter().any(|n| is_archive_name(n));
    if parts.is_empty() && !has_archive {
        bail!(
            "no *{LIST_SUFFIX} files found, no payload.bin and no tar archive: not a block OTA, an A/B OTA or an archive"
        );
    }
    if let Some(bad) = parts.iter().find(|p| !is_safe_name(p)) {
        bail!("unsafe partition name {bad:?}");
    }
    let mut raw = raw_images_in(names);
    for name in &raw {
        let stem = name.strip_suffix(".img").unwrap_or(name);
        if is_archive_name(name) {
            // An archive is unpacked into a directory named after its stem, so that stem
            // must be a safe single component.
            if !is_safe_name(archive_stem(name)) {
                bail!("unsafe archive name {name:?}");
            }
        } else if !is_safe_name(stem) {
            bail!("unsafe file name {name:?}");
        }
        let stem = name
            .strip_suffix(".img")
            .or_else(|| name.strip_suffix(".ozip"))
            .unwrap_or(name);
        if parts.contains(&stem) {
            bail!("{name} conflicts with the {stem} partition rebuilt from {stem}{LIST_SUFFIX}");
        }
    }
    if let Some(only) = only {
        let stem = |n: &str| {
            n.strip_suffix(".img")
                .or_else(|| n.strip_suffix(".ozip"))
                .map(str::to_string)
        };
        let available: Vec<&str> = parts
            .iter()
            .copied()
            .chain(raw.iter().map(|n| {
                n.strip_suffix(".img")
                    .or_else(|| n.strip_suffix(".ozip"))
                    .unwrap_or(n)
            }))
            .collect();
        if let Some(bad) = only.iter().find(|o| !available.contains(&o.as_str())) {
            bail!("unknown name {bad:?}; available: {}", available.join(", "));
        }
        parts.retain(|p| only.iter().any(|o| o == p));
        raw.retain(|n| only.iter().any(|o| Some(o) == stem(n).as_ref()));
    }
    Ok((parts, raw))
}

/// What `extract` would write, with sizes in bytes (partition images first, then raw images);
/// reads only the transfer lists, writes nothing.
pub fn list_images(input: &Path, opts: &ExtractOptions) -> Result<Vec<(String, u64)>> {
    if let Some(images) = payload::list(input, opts)? {
        return Ok(images);
    }
    if pac::is_pac(input) {
        return pac::list(input, opts);
    }
    if let Some(kind) = crate::oem::detect(input) {
        return crate::oem::list(kind, input, opts);
    }
    let mut src = Source::open(input)?;
    let names = src.names()?;
    let (parts, raw) = select(&names, &opts.only)?;
    let mut images = Vec::new();
    for part in parts {
        let size = sdat::image_size(&read_list(&mut src, part)?)?;
        images.push((format!("{part}.img"), size));
    }
    for name in raw {
        images.push((name.to_string(), src.file_size(name)?));
    }
    Ok(images)
}

/// Extract every partition found in the OTA into `out_dir`, one thread per partition, and
/// return the image paths sorted by partition name, followed by the other top-level `*.img`
/// files (boot, recovery, ...) copied as they are. Every partition is attempted; the first
/// error (in partition order) is returned.
#[allow(dead_code)]
pub fn extract_all(input: &Path, out_dir: &Path, opts: &ExtractOptions) -> Result<Vec<PathBuf>> {
    extract_all_tracked(input, out_dir, opts).map(|r| r.done.into_iter().map(|(p, _)| p).collect())
}

/// Files a block OTA legitimately ships that are neither partitions nor partition data. These are
/// looked at, understood, and deliberately not extracted: reporting them as failures would make
/// the tool fail on every real update.
const KNOWN_OTA_FILES: &[&str] = &["cert.pem", "payload_properties.txt"];

/// Suffixes of OTA scaffolding. These arrive named after the partition they belong to
/// (`system.patch.dat`, `vendor.inf`), so they must be matched as suffixes, not names.
const KNOWN_OTA_SUFFIXES: &[&str] = &[
    // the zero-length delta half of a partition; present in every block OTA
    ".patch.dat",
    ".patch.dat.br",
    ".inf",
    ".properties",
    ".signature",
    ".signature1",
    ".signature2",
    ".rsa",
    ".dsa",
];

/// Directories that ship inside an OTA and hold signing metadata rather than partitions.
const KNOWN_OTA_DIRS: &[&str] = &["META-INF"];

/// Helper scripts some vendors include alongside the images (e.g. `sdat2img.py`).
const KNOWN_OTA_SCRIPTS: &[&str] = &["sdat2img.py", "sdat2img.sh", "extractor.sh"];

/// True when `name` is recognised OTA scaffolding: something we looked at on purpose and
/// deliberately did not extract, as opposed to a file we simply have no handler for.
pub(crate) fn is_known_scaffolding(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    if KNOWN_OTA_FILES.iter().any(|f| lower == *f) {
        return true;
    }
    // The delta half of a partition, named after the partition: `system.patch.dat`.
    if lower.ends_with(".patch.dat") || lower.ends_with(".patch.dat.br") {
        return true;
    }
    if KNOWN_OTA_SUFFIXES.iter().any(|e| lower.ends_with(e)) {
        return true;
    }
    if KNOWN_OTA_SCRIPTS.iter().any(|f| lower == *f) {
        return true;
    }
    let first = lower.split('/').next().unwrap_or(&lower);
    if KNOWN_OTA_DIRS.contains(&first) {
        return true;
    }
    false
}

/// Like `extract_all` but also returns which top-level inputs were skipped or unrecognised.
pub(crate) fn extract_all_tracked(
    input: &Path,
    out_dir: &Path,
    opts: &ExtractOptions,
) -> Result<ExtractResult> {
    if let Some(kind) = crate::oem::detect(input) {
        let paths = crate::oem::extract(kind, input, out_dir, opts)?;
        return Ok(ExtractResult {
            done: paths.into_iter().map(|p| (p, String::new())).collect(),
            ignored: Vec::new(),
            unhandled: Vec::new(),
        });
    }
    let names = Source::open(input)?.names()?;
    let (parts, raw) = select(&names, &opts.only)?;
    // Determine which top-level inputs were skipped (not a partition, raw image, or
    // partition data file like *.transfer.list / *.new.dat*).
    let recognised: std::collections::HashSet<&str> =
        parts.iter().chain(raw.iter()).copied().collect();
    let skipped: Vec<Skipped> = names
        .iter()
        .map(String::as_str)
        .filter(|n| !recognised.contains(n) && !n.ends_with(LIST_SUFFIX) && !n.contains(".new.dat"))
        .map(|n| Skipped {
            name: n.to_string(),
            reason: if is_known_scaffolding(n) {
                "known OTA file".to_string()
            } else {
                "no handler".to_string()
            },
        })
        .collect();
    let (ignored, mut unhandled): (Vec<Skipped>, Vec<Skipped>) = skipped
        .into_iter()
        .partition(|s| s.reason == "known OTA file");
    // Names that differ only by case would overwrite each other on case-insensitive filesystems.
    let out_names: Vec<String> = parts
        .iter()
        .map(|p| format!("{p}.img"))
        .chain(raw.iter().map(|n| n.to_string()))
        .collect();
    let mut seen = std::collections::HashMap::new();
    for name in &out_names {
        if let Some(prev) = seen.insert(name.to_lowercase(), name) {
            bail!("{prev} and {name} differ only by case and would overwrite each other");
        }
    }
    if !opts.force {
        let existing: Vec<&str> = out_names
            .iter()
            .map(String::as_str)
            .filter(|n| out_dir.join(n).symlink_metadata().is_ok())
            .collect();
        if !existing.is_empty() {
            bail!(
                "{} already exist in {}; pass --force to overwrite",
                existing.join(", "),
                out_dir.display()
            );
        }
    }
    std::fs::create_dir_all(out_dir)?;

    // Hidden automatically when stderr is not a terminal, or when --quiet is passed.
    let multi = if opts.quiet {
        MultiProgress::with_draw_target(indicatif::ProgressDrawTarget::hidden())
    } else {
        MultiProgress::new()
    };
    let style = ProgressStyle::with_template("{prefix:>10} [{bar:30}] {bytes}/{total_bytes}")
        .expect("valid progress template")
        .progress_chars("=> ");
    let results: Vec<Result<PathBuf>> = std::thread::scope(|scope| {
        let handles: Vec<_> = parts
            .iter()
            .map(|&part| {
                let bar = multi.add(ProgressBar::new(0).with_style(style.clone()));
                bar.set_prefix(part.to_string());
                let names = &names;
                scope.spawn(move || {
                    // each thread needs its own handle: a zip reader is not shareable
                    let mut src = Source::open(input)?;
                    let result = extract_partition(input, &mut src, names, part, out_dir, &bar);
                    bar.finish_and_clear();
                    result
                })
            })
            .collect();
        handles
            .into_iter()
            .map(|h| {
                h.join()
                    .unwrap_or_else(|_| Err(anyhow!("extraction thread panicked")))
            })
            .collect()
    });
    let mut paths = results.into_iter().collect::<Result<Vec<_>>>()?;
    let mut src = Source::open(input)?;
    for name in raw {
        // Only the head is read here, so a corrupt image still fails inside copy_raw with its
        // own error context.
        let head = {
            let mut r = src.open_file(name)?;
            let mut v = vec![0u8; detect::SNIFF_LEN];
            let n = r.read(&mut v)?;
            v.truncate(n);
            v
        };
        // One image that will not unpack must not cost the images after it (#116, #118): keep
        // its bytes by copying it raw, report it as unhandled, and go on. The run still fails
        // on it unless --allow-partial, so nothing is skipped silently.
        let mut produced: Vec<PathBuf> = Vec::new();
        let unpacked = (|| -> Result<()> {
            if is_tar_family(&mut src, name, &head) {
                // A JioSTB-style update keeps its partition images in a tar (optionally
                // .tar.md5 or wrapped in gzip/xz); unpack it instead of copying the blob.
                // Stage under the original name: the .md5 suffix is how the archive knows it
                // must verify the trailing hash, so renaming it would skip that check.
                let incoming = out_dir.join(format!(".incoming-{}", std::process::id()));
                let _ = std::fs::remove_dir_all(&incoming);
                std::fs::create_dir_all(&incoming)?;
                let staged = incoming.join(name);
                copy_raw(&mut src, name, out_dir)?;
                let _ = std::fs::rename(out_dir.join(name), &staged);
                let target = out_dir.join(archive_stem(name));
                // Route through the extraction engine (#26): it sniffs, dispatches to the
                // registered handler, and re-queues whatever that handler produced so nested
                // containers resolve without any handler knowing about the others.
                let unpacked = crate::engine::unpack_into(
                    &crate::engine::handlers(),
                    &staged,
                    &target,
                    &crate::engine::Limits::default(),
                );
                let _ = std::fs::remove_dir_all(&incoming);
                unpacked?;
                produced.push(target);
            } else if head.starts_with(&[0x3A, 0xFF, 0x26, 0xED]) {
                // A sparse partition image (system/vendor/product/... as flashed) expands to the
                // real filesystem image, under the same name, before anything reads it.
                let final_path = out_dir.join(name);
                let tmp_path = out_dir.join(format!("{name}.part"));
                let expanded = (|| -> Result<()> {
                    let reader = src.open_file(name)?;
                    let mut out = create_part(&tmp_path)?;
                    crate::sparse::unsparse(vec![reader], &mut out)?;
                    Ok(())
                })();
                if let Err(e) = expanded {
                    let _ = std::fs::remove_file(&tmp_path);
                    return Err(e.context(format!("unsparsing {name}")));
                }
                std::fs::rename(&tmp_path, &final_path)?;
                produced.push(final_path);
            } else if head.len() >= 4100 && head[4096..4100] == *b"gDla" {
                // super.img holds dynamic partitions: split it into <partition>.img files.
                let bytes = {
                    let mut r = src.open_file(name)?;
                    let mut v = Vec::new();
                    r.read_to_end(&mut v)?;
                    v
                };
                let parsed = crate::lp::parse_metadata(&bytes)?;
                let only = opts.only.as_deref();
                for (part, body) in crate::lp::split_partitions(&bytes, &parsed, only)? {
                    let part_path = out_dir.join(format!("{part}.img"));
                    let tmp_path = out_dir.join(format!("{part}.img.part"));
                    std::fs::write(&tmp_path, &body)?;
                    std::fs::rename(&tmp_path, &part_path)?;
                    produced.push(part_path);
                }
            } else if name.ends_with(".ozip") {
                // An Oppo/Realme .ozip is an AES-128-ECB encrypted zip. Decrypt it to a staging
                // zip file, then unpack that zip into <stem>/.
                let stem = name.strip_suffix(".ozip").unwrap_or(name);
                let target = out_dir.join(stem);
                let ok = (|| -> Result<()> {
                    let staged = out_dir.join(format!(".incoming-{}", std::process::id()));
                    let _ = std::fs::remove_dir_all(&staged);
                    std::fs::create_dir_all(&staged)?;
                    let staged_zip = staged.join(format!("{stem}.zip"));
                    crate::ozip::decrypt(&mut src.open_file(name)?, &staged_zip)
                        .with_context(|| format!("decrypting {}", name))?;
                    let mut zip = File::open(&staged_zip)
                        .with_context(|| format!("opening decrypted {}", name))?;
                    let archive = crate::treeout::prepare_staging(&target)?;
                    extract_zip(&mut zip, &archive)?;
                    crate::treeout::publish(&archive, &target)?;
                    let _ = std::fs::remove_dir_all(&staged);
                    std::fs::remove_file(&staged_zip).ok();
                    Ok(())
                })();
                if let Err(e) = ok {
                    let _ = std::fs::remove_dir_all(&target);
                    let staged = out_dir.join(format!(".incoming-{}", std::process::id()));
                    let _ = std::fs::remove_dir_all(&staged);
                    return Err(e);
                }
                produced.push(target);
            } else {
                produced.push(copy_raw(&mut src, name, out_dir)?);
            }
            Ok(())
        })();
        match unpacked {
            Ok(()) => paths.extend(produced),
            // A failed integrity check is tampering or corruption, not an unknown format: stop.
            Err(e) if e.chain().any(|c| c.is::<crate::archive::IntegrityError>()) => {
                for p in &produced {
                    let _ = std::fs::remove_file(p);
                }
                return Err(e);
            }
            Err(e) => {
                for p in &produced {
                    let _ = std::fs::remove_file(p);
                }
                let copied = copy_raw(&mut src, name, out_dir)
                    .with_context(|| format!("copying {name} raw after it failed to unpack"))?;
                paths.push(copied);
                unhandled.push(Skipped {
                    name: name.to_string(),
                    reason: format!("could not be unpacked, copied raw: {e:#}"),
                });
            }
        }
    }
    if opts.strict && !unhandled.is_empty() {
        let names: Vec<String> = unhandled.iter().map(|s| s.name.clone()).collect();
        bail!(
            "strict mode: cannot classify {} file(s): {}",
            unhandled.len(),
            names.join(", ")
        );
    }
    Ok(ExtractResult {
        done: paths.into_iter().map(|p| (p, String::new())).collect(),
        ignored,
        unhandled,
    })
}

/// `extract` command: extract all partitions and print one line per image.
pub fn run(input: &Path, out_dir: &Path, opts: &ExtractOptions) -> Result<()> {
    if opts.list {
        for (name, size) in list_images(input, opts)? {
            println!("{name}  {}", crate::term::human_size(size));
        }
        return Ok(());
    }
    let start = std::time::Instant::now();
    let style = crate::term::Style::detect(opts.no_color);
    if opts.verbose {
        let fmt = if payload::locate(input, opts.base.as_deref()).is_ok_and(|l| l.is_some()) {
            "A/B OTA payload"
        } else if pac::is_pac(input) {
            "PAC"
        } else if let Some(kind) = crate::oem::detect(input) {
            kind.id()
        } else {
            "block OTA"
        };
        let tag = if style.color() {
            "[2mtrace[0m"
        } else {
            "trace"
        };
        eprintln!("{tag} {}: detected format: {}", input.display(), fmt);
    }
    let result = extract_all_noted(input, out_dir, opts)?;
    if opts.verbose {
        eprintln!(
            "trace {}: extracted {} partition(s) in {}",
            input.display(),
            result.done.len(),
            human_elapsed(start.elapsed()),
        );
    }
    let done = &result.done;
    if !opts.quiet {
        for (path, note) in done {
            let line = describe(path)?;
            println!(
                "{}",
                if note.is_empty() {
                    line
                } else {
                    format!("{line}  {note}")
                }
            );
        }
    }
    if opts.files {
        let images: Vec<&Path> = done.iter().map(|(p, _)| p.as_path()).collect();
        extract_trees(&images, &out_dir.join("files"), opts)?;
    }
    // End-of-run summary (issue #80): account for every top-level input in one of three
    // buckets. Only genuinely unrecognised input is a failure.
    let say = |msg: &str| {
        if opts.quiet {
            eprintln!("{msg}")
        } else {
            println!("{msg}")
        }
    };
    let ignored_note = if result.ignored.is_empty() {
        String::new()
    } else {
        format!("; ignored {} known OTA file(s)", result.ignored.len())
    };
    say(&format!("wrote {} partition(s){ignored_note}", done.len()));
    if !result.unhandled.is_empty() {
        for s in &result.unhandled {
            say(&format!("unhandled: {s}"));
        }
        if !opts.allow_partial {
            return Err(anyhow!(
                "{} input(s) were not fully extracted ({}); pass --allow-partial to accept this",
                result.unhandled.len(),
                result
                    .unhandled
                    .iter()
                    .map(ToString::to_string)
                    .collect::<Vec<_>>()
                    .join(", ")
            ));
        }
    }
    Ok(())
}

/// Human-readable elapsed time for verbose traces (e.g. "1.23s").
fn human_elapsed(d: std::time::Duration) -> String {
    if d.as_millis() < 1000 {
        format!("{}ms", d.as_millis())
    } else {
        format!("{:.2}s", d.as_secs_f64())
    }
}

/// `--files`: write the file tree and manifest of every ext2/3/4 image under `<dir>/<image name>/`.
pub(crate) fn extract_trees(images: &[&Path], dir: &Path, opts: &ExtractOptions) -> Result<()> {
    let show_bar = std::io::stdout().is_terminal() && !opts.quiet;
    let bar = if show_bar {
        let b = ProgressBar::new(images.len() as u64);
        b.set_style(
            ProgressStyle::with_template("{prefix:>10} [{bar:30}] {pos}/{len}")
                .expect("valid progress template")
                .progress_chars("=> "),
        );
        b.set_prefix("files");
        Some(b)
    } else {
        None
    };
    let mut nothing = Vec::new();
    for (i, image) in images.iter().enumerate() {
        let kind = detect::filesystem_of_file(image);
        let name = image
            .file_stem()
            .and_then(|s| s.to_str())
            .unwrap_or("image");
        let target = dir.join(name);
        if opts.force && target.symlink_metadata().is_ok_and(|m| m.is_dir()) {
            std::fs::remove_dir_all(&target)?;
        }
        if let Some(_fs) = kind {
            let entries = crate::tree::Tree::open(image)?
                .extract(&target, None)
                .with_context(|| format!("extracting the files of {}", image.display()))?;
            let count = |k| entries.iter().filter(|e| e.kind == k).count();
            if !opts.quiet {
                if let Some(ref bar) = bar {
                    bar.println(format!(
                        "files: {name}  {} entries ({} files, {} symlinks) -> {}",
                        entries.len(),
                        count(crate::tree::Kind::File),
                        count(crate::tree::Kind::Symlink),
                        target.display()
                    ));
                } else {
                    println!(
                        "files: {name}  {} entries ({} files, {} symlinks) -> {}",
                        entries.len(),
                        count(crate::tree::Kind::File),
                        count(crate::tree::Kind::Symlink),
                        target.display()
                    );
                }
            }
        } else {
            nothing.push(name.to_string());
        }
        if let Some(ref bar) = bar {
            bar.set_position((i + 1) as u64);
        }
    }
    if let Some(bar) = &bar {
        bar.finish_and_clear();
    }
    if !nothing.is_empty() && !opts.quiet {
        eprintln!("no extractable file tree in: {}", nothing.join(", "));
    }
    Ok(())
}

/// `extract_all` plus a short note per image on how far it was verified (A/B payloads check each
/// image's SHA-256; block OTAs carry no hashes, so their notes are empty).
pub fn extract_all_noted(
    input: &Path,
    out_dir: &Path,
    opts: &ExtractOptions,
) -> Result<ExtractResult> {
    if let Some(done) = payload::extract(input, out_dir, opts)? {
        return Ok(ExtractResult {
            done,
            ignored: Vec::new(),
            unhandled: Vec::new(),
        });
    }
    if pac::is_pac(input) {
        let paths = pac::extract(input, out_dir, opts)?;
        return Ok(ExtractResult {
            done: paths.into_iter().map(|p| (p, String::new())).collect(),
            ignored: Vec::new(),
            unhandled: Vec::new(),
        });
    }
    let result = extract_all_tracked(input, out_dir, opts)?;
    Ok(ExtractResult {
        done: result.done,
        ignored: result.ignored,
        unhandled: result.unhandled,
    })
}

/// One result line: path, size, and the filesystem when the image holds one we recognise.
pub(crate) fn describe(path: &Path) -> Result<String> {
    let size = std::fs::metadata(path)?.len();
    let mut line = format!("{}  {}", path.display(), crate::term::human_size(size));
    if let Some(fs) = detect::filesystem_of_file(path) {
        line.push_str(&format!("  {fs}"));
        if size % sdat::BLOCK_SIZE as u64 != 0 {
            line.push_str(&format!(
                "  (size is not a multiple of {})",
                sdat::BLOCK_SIZE
            ));
        }
    }
    Ok(line)
}

#[cfg(test)]
mod tests {
    use super::*;

    const BLOCK: usize = sdat::BLOCK_SIZE;

    fn blk(b: u8) -> Vec<u8> {
        vec![b; BLOCK]
    }

    fn brotli(data: &[u8]) -> Vec<u8> {
        let mut packed = Vec::new();
        brotli::CompressorWriter::new(&mut packed, 4096, 5, 22)
            .write_all(data)
            .unwrap();
        packed
    }

    fn fresh_dir(tag: &str) -> crate::testutil::Scratch {
        crate::testutil::Scratch::new(&format!("x-{tag}"))
    }

    /// A `.tar.md5` whose tar has been altered must be refused: the recorded hash covers the
    /// tar bytes, so a flip anywhere in the body fails the check and nothing is written.
    #[test]
    fn a_tar_md5_whose_body_was_edited_is_refused() {
        let s = fresh_dir("tarmd5-bad");
        let mut tar_bytes = tar::Builder::new(Vec::new());
        let body: &[u8] = b"BOOT";
        let mut h = tar::Header::new_gnu();
        h.set_size(body.len() as u64);
        h.set_mode(0o644);
        h.set_cksum();
        tar_bytes.append_data(&mut h, "boot.img", body).unwrap();
        let tar_bytes = tar_bytes.into_inner().unwrap();
        use md5::Digest;
        let digest: String = md5::Md5::digest(&tar_bytes)
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        let mut blob = tar_bytes.clone();
        blob.extend_from_slice(format!("{digest}  - -\n").as_bytes());
        blob[600] ^= 0xff; // edit the tar, leaving the recorded hash alone
        let mut files = sample_files();
        files.push(("SUPER.tar.md5", blob));
        write_dir(&s, &files);
        let out = fresh_dir("tarmd5-bad-out");
        let e = format!(
            "{:#}",
            extract_all(&s, &out, &ExtractOptions::default()).unwrap_err()
        );
        assert!(e.contains("MD5 mismatch"), "{e}");
        assert!(
            !out.join("SUPER").exists(),
            "nothing is unpacked when the hash does not match"
        );
        // A failed integrity check is not an unparsable image: --allow-partial must not turn it
        // into a skip (#116).
        let _ = std::fs::remove_dir_all(&out);
        let opts = ExtractOptions {
            allow_partial: true,
            ..ExtractOptions::default()
        };
        let e = format!("{:#}", run(&s, &out, &opts).unwrap_err());
        assert!(e.contains("MD5 mismatch"), "{e}");
    }

    /// An OTA directory holding a JioSTB-style `SUPER.tar.md5` unpacks into its partition
    /// images instead of being copied as one blob.
    #[test]
    fn a_tar_md5_update_is_unpacked_rather_than_copied() {
        let s = fresh_dir("tarmd5");
        let mut tar_bytes = tar::Builder::new(Vec::new());
        for (name, body) in [("boot.img", b"BOOT".as_slice()), ("system.img", b"SYS")] {
            let mut h = tar::Header::new_gnu();
            h.set_size(body.len() as u64);
            h.set_mode(0o644);
            h.set_cksum();
            tar_bytes.append_data(&mut h, name, body).unwrap();
        }
        let tar_bytes = tar_bytes.into_inner().unwrap();
        let mut blob = tar_bytes.clone();
        use md5::Digest;
        let digest: String = md5::Md5::digest(&tar_bytes)
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        blob.extend_from_slice(format!("{digest}  - -\n").as_bytes());
        let mut files = sample_files();
        files.push(("SUPER.tar.md5", blob));
        write_dir(&s, &files);
        let out = fresh_dir("tarmd5-out");
        extract_all(&s, &out, &ExtractOptions::default()).unwrap();
        assert_eq!(
            std::fs::read(out.join("SUPER/files/boot.img")).unwrap(),
            b"BOOT"
        );
        assert_eq!(
            std::fs::read(out.join("SUPER/files/system.img")).unwrap(),
            b"SYS"
        );
        assert!(
            !out.join("SUPER.tar.md5").exists(),
            "the blob is not left behind"
        );
    }

    /// Partition `a` is brotli-compressed (blocks 1,2), `b` is raw (block 9).
    fn sample_files() -> Vec<(&'static str, Vec<u8>)> {
        vec![
            ("a.transfer.list", b"4\n2\n0\n0\nnew 2,0,2\n".to_vec()),
            ("a.new.dat.br", brotli(&[blk(1), blk(2)].concat())),
            ("b.transfer.list", b"4\n1\n0\n0\nnew 2,0,1\n".to_vec()),
            ("b.new.dat", blk(9)),
        ]
    }

    fn write_dir(dir: &Path, files: &[(&str, Vec<u8>)]) {
        for (name, body) in files {
            std::fs::write(dir.join(name), body).unwrap();
        }
    }

    fn check_sample_output(out: &Path) {
        assert_eq!(
            std::fs::read(out.join("a.img")).unwrap(),
            [blk(1), blk(2)].concat()
        );
        assert_eq!(std::fs::read(out.join("b.img")).unwrap(), blk(9));
    }

    #[test]
    fn extracts_every_partition_from_a_directory() {
        let (ota, out) = (fresh_dir("dir-in"), fresh_dir("dir-out"));
        write_dir(&ota, &sample_files());
        run(&ota, &out, &ExtractOptions::default()).unwrap();
        check_sample_output(&out);
    }

    #[test]
    fn extracts_every_partition_from_a_zip() {
        let (work, out) = (fresh_dir("zip-in"), fresh_dir("zip-out"));
        let zip_path = work.join("ota.zip");
        let mut w = zip::ZipWriter::new(File::create(&zip_path).unwrap());
        for (name, body) in sample_files() {
            w.start_file(name, zip::write::SimpleFileOptions::default())
                .unwrap();
            w.write_all(&body).unwrap();
        }
        w.finish().unwrap();
        run(&zip_path, &out, &ExtractOptions::default()).unwrap();
        check_sample_output(&out);
    }

    #[test]
    fn nested_zip_entries_are_ignored() {
        let (work, out) = (fresh_dir("nest-in"), fresh_dir("nest-out"));
        let zip_path = work.join("ota.zip");
        let mut w = zip::ZipWriter::new(File::create(&zip_path).unwrap());
        let nested = ("nested/z.transfer.list", b"junk".to_vec());
        for (name, body) in sample_files().into_iter().chain([nested]) {
            w.start_file(name, zip::write::SimpleFileOptions::default())
                .unwrap();
            w.write_all(&body).unwrap();
        }
        w.finish().unwrap();
        run(&zip_path, &out, &ExtractOptions::default()).unwrap();
        check_sample_output(&out);
        assert!(!out.join("z.img").exists());
    }

    #[test]
    fn many_partitions_extract_in_parallel_and_come_back_sorted() {
        let (ota, out, work) = (
            fresh_dir("many-in"),
            fresh_dir("many-out"),
            fresh_dir("many-zip"),
        );
        let mut files = Vec::new();
        for (i, name) in ["zeta", "alpha", "mid", "beta", "omega", "delta"]
            .iter()
            .enumerate()
        {
            files.push((
                format!("{name}.transfer.list"),
                b"4\n2\n0\n0\nnew 2,0,2\n".to_vec(),
            ));
            files.push((
                format!("{name}.new.dat.br"),
                brotli(&[blk(i as u8 + 1), blk(i as u8 + 50)].concat()),
            ));
        }
        let zip_path = work.join("ota.zip");
        let mut w = zip::ZipWriter::new(File::create(&zip_path).unwrap());
        for (name, body) in &files {
            std::fs::write(ota.join(name), body).unwrap();
            w.start_file(name.as_str(), zip::write::SimpleFileOptions::default())
                .unwrap();
            w.write_all(body).unwrap();
        }
        w.finish().unwrap();
        for input in [ota.as_path(), zip_path.as_path()] {
            let _ = std::fs::remove_dir_all(&out);
            let paths = extract_all(input, &out, &ExtractOptions::default()).unwrap();
            let names: Vec<_> = paths
                .iter()
                .map(|p| p.file_name().unwrap().to_string_lossy().into_owned())
                .collect();
            assert_eq!(
                names,
                [
                    "alpha.img",
                    "beta.img",
                    "delta.img",
                    "mid.img",
                    "omega.img",
                    "zeta.img"
                ]
            );
            for (i, name) in ["zeta", "alpha", "mid", "beta", "omega", "delta"]
                .iter()
                .enumerate()
            {
                let expect = [blk(i as u8 + 1), blk(i as u8 + 50)].concat();
                assert_eq!(
                    std::fs::read(out.join(format!("{name}.img"))).unwrap(),
                    expect,
                    "{name}"
                );
            }
        }
    }

    #[test]
    fn one_bad_partition_fails_the_run_but_good_ones_still_finish() {
        let (ota, out) = (fresh_dir("mixed-in"), fresh_dir("mixed-out"));
        write_dir(&ota, &sample_files());
        write_dir(
            &ota,
            &[
                ("c.transfer.list", b"4\n1\n0\n0\nnew 2,0,1\n".to_vec()),
                ("c.new.dat.br", vec![0xff; BLOCK]),
            ],
        );
        let e = extract_all(&ota, &out, &ExtractOptions::default()).unwrap_err();
        assert!(format!("{e:#}").contains("extracting c"), "{e:#}");
        assert!(out.join("a.img").exists() && out.join("b.img").exists());
        assert!(!out.join("c.img").exists() && !out.join("c.img.part").exists());
    }

    #[test]
    fn partition_names_lists_sorted_partitions_without_reading_data() {
        let ota = fresh_dir("names");
        write_dir(
            &ota,
            &[
                ("b.transfer.list", vec![]),
                ("a.transfer.list", vec![]),
                ("readme.txt", vec![]),
            ],
        );
        assert_eq!(partition_names(&ota).unwrap(), ["a", "b"]);
        let empty = fresh_dir("names-empty");
        assert!(partition_names(&empty).unwrap().is_empty());
    }

    fn zip_of(files: &[(&str, Vec<u8>)], path: &Path) {
        let mut w = zip::ZipWriter::new(File::create(path).unwrap());
        let stored = zip::write::SimpleFileOptions::default()
            .compression_method(zip::CompressionMethod::Stored);
        for (name, body) in files {
            w.start_file(*name, stored).unwrap();
            w.write_all(body).unwrap();
        }
        w.finish().unwrap();
    }

    #[test]
    fn raw_images_are_copied_unchanged_after_the_partitions() {
        let (ota, out, work) = (
            fresh_dir("raw-in"),
            fresh_dir("raw-out"),
            fresh_dir("raw-zip"),
        );
        let mut files = sample_files();
        // deliberately not in alphabetical order
        files.push(("vbmeta.img", vec![0x22; 64]));
        files.push(("dtbo.img", vec![0x33; 7]));
        files.push(("boot.img", vec![0x11; 5000]));
        files.push(("readme.txt", b"not an image".to_vec()));
        write_dir(&ota, &files);
        std::fs::create_dir(ota.join("dirnamed.img")).unwrap();
        let zip_path = work.join("ota.zip");
        zip_of(&files, &zip_path);
        for input in [ota.as_path(), zip_path.as_path()] {
            let _ = std::fs::remove_dir_all(&out);
            let paths = extract_all(input, &out, &ExtractOptions::default()).unwrap();
            let names: Vec<_> = paths
                .iter()
                .map(|p| p.file_name().unwrap().to_string_lossy().into_owned())
                .collect();
            assert_eq!(
                names,
                ["a.img", "b.img", "boot.img", "dtbo.img", "vbmeta.img"]
            );
            assert_eq!(
                std::fs::read(out.join("boot.img")).unwrap(),
                vec![0x11; 5000]
            );
            assert_eq!(
                std::fs::read(out.join("vbmeta.img")).unwrap(),
                vec![0x22; 64]
            );
            assert!(!out.join("readme.txt").exists() && !out.join("dirnamed.img").exists());
        }
    }

    /// Issue #114: a gzip-wrapped `dt.img` holds an Amlogic `AML_` container, not a tar. The
    /// compression magic alone made `extract` treat it as a `.tar.gz`, hand the container to the
    /// tar reader ("numeric field was not a number ... cksum for AML_"), and stop, so every
    /// image sorted after it was never written. It is an image: copy it unchanged and go on. A
    /// real gzip-compressed tar in the same update must still be unpacked.
    #[test]
    fn a_gzip_image_that_is_not_a_tar_is_copied_unchanged_and_the_run_continues() {
        use flate2::{Compression, write::GzEncoder};
        let gzip = |body: &[u8]| {
            let mut e = GzEncoder::new(Vec::new(), Compression::default());
            e.write_all(body).unwrap();
            e.finish().unwrap()
        };
        let mut aml = b"AML_".to_vec();
        aml.extend((0..2000u32).map(|i| (i.wrapping_mul(2654435761) >> 13) as u8));
        let dt = gzip(&aml);
        assert_eq!(&dt[..2], [0x1F, 0x8B]);

        let mut tar_bytes = tar::Builder::new(Vec::new());
        let mut h = tar::Header::new_gnu();
        h.set_size(4);
        h.set_mode(0o644);
        h.set_cksum();
        tar_bytes
            .append_data(&mut h, "inner.img", &b"DATA"[..])
            .unwrap();
        let tgz = gzip(&tar_bytes.into_inner().unwrap());

        let (ota, out, work) = (
            fresh_dir("gzimg-in"),
            fresh_dir("gzimg-out"),
            fresh_dir("gzimg-zip"),
        );
        let mut files = sample_files();
        files.push(("boot.img", vec![0x11; 300]));
        files.push(("dt.img", dt.clone()));
        files.push(("logo.img", vec![0x44; 90]));
        files.push(("recovery.img", vec![0x55; 90]));
        files.push(("PAYLOAD.tar", tgz));
        write_dir(&ota, &files);
        let zip_path = work.join("ota.zip");
        zip_of(&files, &zip_path);
        for input in [ota.as_path(), zip_path.as_path()] {
            let _ = std::fs::remove_dir_all(&out);
            extract_all(input, &out, &ExtractOptions::default())
                .unwrap_or_else(|e| panic!("one gzip image stopped the run: {e:#}"));
            assert_eq!(std::fs::read(out.join("dt.img")).unwrap(), dt, "{input:?}");
            assert_eq!(std::fs::read(out.join("logo.img")).unwrap(), vec![0x44; 90]);
            assert_eq!(
                std::fs::read(out.join("recovery.img")).unwrap(),
                vec![0x55; 90]
            );
            assert_eq!(
                std::fs::read(out.join("PAYLOAD/files/inner.img")).unwrap(),
                b"DATA",
                "a gzip-compressed tar is still unpacked"
            );
        }
    }

    /// Issue #118: an update with a super image stopped at it ("LP geometry struct_size 52 is too
    /// small", exit 1), so the `vbmeta.img` listed after it was never written.
    #[test]
    fn a_super_image_is_split_into_its_partitions_and_the_images_after_it_are_written() {
        let system = vec![0xA5u8; 1536];
        let (ota, out, work) = (
            fresh_dir("super-in"),
            fresh_dir("super-out"),
            fresh_dir("super-zip"),
        );
        let mut files = sample_files();
        files.push((
            "super.img",
            crate::lp::tests::lp_image(&[("system_a", &system)]),
        ));
        files.push(("vbmeta.img", vec![0x22; 64]));
        write_dir(&ota, &files);
        let zip_path = work.join("ota.zip");
        zip_of(&files, &zip_path);
        for input in [ota.as_path(), zip_path.as_path()] {
            let _ = std::fs::remove_dir_all(&out);
            extract_all(input, &out, &ExtractOptions::default())
                .unwrap_or_else(|e| panic!("a super image stopped the run: {e:#}"));
            assert_eq!(
                std::fs::read(out.join("system_a.img")).unwrap(),
                system,
                "{input:?}"
            );
            assert_eq!(
                std::fs::read(out.join("vbmeta.img")).unwrap(),
                vec![0x22; 64]
            );
        }
    }

    /// Issue #117: `archive_stem` promised that `SUPER.tar.gz` becomes `SUPER` but only stripped
    /// `.md5`, `.tar` and `.ozip`, so every compressed tar name kept its dots and was refused as
    /// an unsafe archive name.
    #[test]
    fn a_compressed_tar_name_loses_its_suffixes_to_become_the_directory_name() {
        for name in [
            "SUPER.tar",
            "SUPER.tar.md5",
            "SUPER.tar.gz",
            "SUPER.tgz",
            "SUPER.tar.xz",
            "SUPER.txz",
            "SUPER.tar.bz2",
            "SUPER.tbz2",
            "SUPER.tar.zst",
            "SUPER.tar.lz4",
            "SUPER.ozip",
        ] {
            assert_eq!(archive_stem(name), "SUPER", "{name}");
            assert!(is_safe_name(archive_stem(name)), "{name}");
        }
        // Not an archive suffix: left alone, so it is still refused rather than half-stripped.
        assert_eq!(archive_stem("SUPER.img"), "SUPER.img");
    }

    #[test]
    fn a_tar_gz_in_an_update_is_unpacked_into_a_directory_of_its_stem() {
        use flate2::{Compression, write::GzEncoder};
        let mut tar_bytes = tar::Builder::new(Vec::new());
        let mut h = tar::Header::new_gnu();
        h.set_size(4);
        h.set_mode(0o644);
        h.set_cksum();
        tar_bytes
            .append_data(&mut h, "inner.img", &b"DATA"[..])
            .unwrap();
        let mut e = GzEncoder::new(Vec::new(), Compression::default());
        e.write_all(&tar_bytes.into_inner().unwrap()).unwrap();
        let tgz = e.finish().unwrap();

        let (ota, out) = (fresh_dir("tgz-in"), fresh_dir("tgz-out"));
        let mut files = sample_files();
        files.push(("PAYLOAD.tar.gz", tgz));
        write_dir(&ota, &files);
        extract_all(&ota, &out, &ExtractOptions::default()).unwrap();
        assert_eq!(
            std::fs::read(out.join("PAYLOAD/files/inner.img")).unwrap(),
            b"DATA"
        );
    }

    /// Issue #127: the coverage guarantee. An OTA holding one of every standard Android
    /// partition image must extract with no error - the known containers resolved, the rest
    /// copied raw - and `identify` must name each type. This is the regression net behind
    /// "works on any Android firmware".
    #[test]
    fn every_standard_partition_image_is_identified_and_extracted() {
        // A 4096-byte block carrying an ext4 superblock magic, wrapped in a one-chunk sparse
        // image the way system/vendor are flashed.
        let mut ext4_block = vec![0u8; 4096];
        ext4_block[1024 + 0x38..1024 + 0x3A].copy_from_slice(&0xEF53u16.to_le_bytes());
        ext4_block[1024 + 0x60..1024 + 0x64].copy_from_slice(&0x40u32.to_le_bytes()); // INCOMPAT_EXTENTS
        let sparse_system = {
            let mut s = Vec::new();
            s.extend(0xED26_FF3Au32.to_le_bytes()); // magic
            s.extend(1u16.to_le_bytes()); // major
            s.extend(0u16.to_le_bytes()); // minor
            s.extend(28u16.to_le_bytes()); // file hdr size
            s.extend(12u16.to_le_bytes()); // chunk hdr size
            s.extend(4096u32.to_le_bytes()); // blk_sz
            s.extend(1u32.to_le_bytes()); // total_blks
            s.extend(1u32.to_le_bytes()); // total_chunks
            s.extend(0u32.to_le_bytes()); // checksum (unused)
            s.extend(0xCAC1u16.to_le_bytes()); // RAW
            s.extend(0u16.to_le_bytes());
            s.extend(1u32.to_le_bytes()); // one block
            s.extend((12 + ext4_block.len() as u32).to_le_bytes());
            s.extend(&ext4_block);
            s
        };
        let pad = |magic: &[u8]| {
            let mut v = magic.to_vec();
            v.resize(256, 0);
            v
        };
        let erofs = {
            let mut v = vec![0u8; 1128];
            v[1024..1028].copy_from_slice(&0xE0F5_E1E2u32.to_le_bytes());
            v
        };
        let ext4 = {
            let mut v = vec![0u8; 1128];
            v[1024 + 0x38..1024 + 0x3A].copy_from_slice(&0xEF53u16.to_le_bytes());
            v[1024 + 0x60..1024 + 0x64].copy_from_slice(&0x40u32.to_le_bytes());
            v
        };
        let super_img = crate::lp::tests::lp_image(&[("my_super_part", &[0x11u8; 512])]);

        // name, bytes, expected identify id, whether extract transforms it (not a raw copy)
        let fixtures: Vec<(&str, Vec<u8>, &str, bool)> = vec![
            ("boot.img", pad(b"ANDROID!"), "boot-image", false),
            ("recovery.img", pad(b"ANDROID!"), "boot-image", false),
            ("init_boot.img", pad(b"ANDROID!"), "boot-image", false),
            ("vendor_boot.img", pad(b"VNDRBOOT"), "vendor-boot", false),
            ("dtbo.img", pad(&[0xD7, 0xB7, 0xAB, 0x1E]), "dtbo", false),
            ("dt.img", pad(&[0xD0, 0x0D, 0xFE, 0xED]), "fdt", false), // FDT device tree
            ("dt_aml.img", pad(b"@AML"), "aml-container", false),
            ("vbmeta.img", pad(b"AVB0"), "avb-vbmeta", false),
            ("vbmeta_system.img", pad(b"AVB0"), "avb-vbmeta", false),
            ("product.img", ext4.clone(), "ext4", false),
            ("odm.img", ext4.clone(), "ext4", false),
            ("system_ext.img", ext4, "ext4", false),
            ("vendor.img", erofs, "erofs", false),
            ("system.img", sparse_system, "android-sparse", true), // sparse -> expanded
            ("super.img", super_img, "lp-super", true),            // split into partitions
        ];

        let (ota, out, work) = (
            fresh_dir("cov-in"),
            fresh_dir("cov-out"),
            fresh_dir("cov-zip"),
        );
        // A valid block OTA needs transfer-list partitions; the raw images sit alongside them.
        let mut files = sample_files();
        files.extend(fixtures.iter().map(|(n, b, _, _)| (*n, b.clone())));
        write_dir(&ota, &files);

        // identify names every partition image type, plus payload.bin on its own.
        for (name, _, id, _) in &fixtures {
            let got = crate::detect::identify_path(&ota.join(name)).unwrap();
            assert_eq!(&got.id, id, "identify of {name}");
        }
        std::fs::write(ota.join("payload.bin.sample"), pad(b"CrAU")).unwrap();
        assert_eq!(
            crate::detect::identify_path(&ota.join("payload.bin.sample"))
                .unwrap()
                .id,
            "payload-bin"
        );
        let _ = std::fs::remove_file(ota.join("payload.bin.sample"));

        let zip_path = work.join("ota.zip");
        zip_of(&files, &zip_path);
        for input in [ota.as_path(), zip_path.as_path()] {
            let _ = std::fs::remove_dir_all(&out);
            extract_all(input, &out, &ExtractOptions::default())
                .unwrap_or_else(|e| panic!("extract aborted on {input:?}: {e:#}"));
            for (name, bytes, _, transformed) in &fixtures {
                if *transformed {
                    continue;
                }
                assert_eq!(
                    &std::fs::read(out.join(name)).unwrap_or_else(|_| panic!("{name} missing")),
                    bytes,
                    "{name} from {input:?}"
                );
            }
            // system.img was sparse: it comes out as the expanded 4096-byte image.
            assert_eq!(
                std::fs::read(out.join("system.img")).unwrap().len(),
                4096,
                "sparse system.img expands, from {input:?}"
            );
            assert_eq!(std::fs::read(out.join("system.img")).unwrap(), ext4_block);
            // super.img was split, not copied.
            assert!(
                !out.join("super.img").exists(),
                "super is split, from {input:?}"
            );
            assert_eq!(
                std::fs::read(out.join("my_super_part.img")).unwrap(),
                vec![0x11u8; 512]
            );
        }
    }

    /// Issue #116 / #118: one image that fails to unpack must not stop the images after it. A
    /// super image with a broken geometry checksum is copied raw, reported as unhandled, and
    /// the image sorted after it is still written. Without --allow-partial the run fails (never
    /// silently); with it, the run succeeds.
    #[test]
    fn an_image_that_fails_to_unpack_is_copied_raw_and_the_run_continues() {
        let mut bad_super = crate::lp::tests::lp_image(&[("system_a", &[1u8; 512])]);
        bad_super[4096 + 40] ^= 1; // breaks the geometry checksum
        let (ota, out) = (fresh_dir("badsuper-in"), fresh_dir("badsuper-out"));
        let mut files = sample_files();
        files.push(("super.img", bad_super.clone()));
        files.push(("vbmeta.img", vec![0x22; 64]));
        write_dir(&ota, &files);

        let r = extract_all_tracked(&ota, &out, &ExtractOptions::default()).unwrap();
        assert_eq!(
            std::fs::read(out.join("super.img")).unwrap(),
            bad_super,
            "kept raw"
        );
        assert_eq!(
            std::fs::read(out.join("vbmeta.img")).unwrap(),
            vec![0x22; 64]
        );
        assert!(
            !out.join("system_a.img").exists(),
            "no half-split output left behind"
        );
        assert_eq!(r.unhandled.len(), 1);
        assert_eq!(r.unhandled[0].name, "super.img");
        assert!(
            r.unhandled[0].reason.contains("checksum"),
            "{}",
            r.unhandled[0].reason
        );

        let _ = std::fs::remove_dir_all(&out);
        let err = run(&ota, &out, &ExtractOptions::default()).unwrap_err();
        assert!(format!("{err:#}").contains("--allow-partial"), "{err:#}");
        assert!(
            out.join("vbmeta.img").exists(),
            "written even though the run fails"
        );

        let _ = std::fs::remove_dir_all(&out);
        let opts = ExtractOptions {
            allow_partial: true,
            ..ExtractOptions::default()
        };
        run(&ota, &out, &opts).unwrap();
        assert!(out.join("super.img").exists() && out.join("vbmeta.img").exists());
    }

    #[test]
    fn raw_image_colliding_with_a_partition_is_an_error_before_writing() {
        let (ota, out) = (fresh_dir("clash-in"), fresh_dir("clash-out"));
        let mut files = sample_files();
        files.push(("a.img", vec![1; 10]));
        write_dir(&ota, &files);
        let e = extract_all(&ota, &out, &ExtractOptions::default()).unwrap_err();
        assert!(
            e.to_string().contains("conflicts with the a partition"),
            "{e}"
        );
        assert!(!out.join("a.img").exists());
    }

    #[test]
    fn output_names_differing_only_by_case_are_rejected() {
        let (work, out) = (fresh_dir("case-zip"), fresh_dir("case-out"));
        let zip_path = work.join("ota.zip");
        let mut files = sample_files();
        files.push(("Boot.img", vec![0x11; 8]));
        files.push(("boot.img", vec![0x22; 8]));
        zip_of(&files, &zip_path);
        let e = extract_all(&zip_path, &out, &ExtractOptions::default()).unwrap_err();
        assert!(e.to_string().contains("differ only by case"), "{e}");
        // partitions: A and a rebuild to A.img and a.img
        let mut files = sample_files();
        files.push(("A.transfer.list", b"4\n1\n0\n0\nnew 2,0,1\n".to_vec()));
        files.push(("A.new.dat", blk(3)));
        zip_of(&files, &zip_path);
        let e = extract_all(&zip_path, &out, &ExtractOptions::default()).unwrap_err();
        assert!(e.to_string().contains("differ only by case"), "{e}");
        assert!(
            !out.join("a.img").exists(),
            "nothing is written when names clash"
        );
    }

    #[test]
    fn existing_output_is_refused_without_force_and_replaced_with_it() {
        let (ota, out) = (fresh_dir("force-in"), fresh_dir("force-out"));
        let mut files = sample_files();
        files.push(("boot.img", vec![0x11; 16]));
        write_dir(&ota, &files);
        extract_all(&ota, &out, &ExtractOptions::default()).unwrap();
        std::fs::write(out.join("a.img"), b"precious").unwrap();
        std::fs::write(out.join("boot.img"), b"also precious").unwrap();
        std::fs::remove_file(out.join("b.img")).unwrap();
        let e = extract_all(&ota, &out, &ExtractOptions::default()).unwrap_err();
        let msg = e.to_string();
        assert!(
            msg.contains("a.img") && msg.contains("boot.img") && msg.contains("--force"),
            "{msg}"
        );
        assert!(
            !msg.contains("b.img"),
            "only existing files are listed: {msg}"
        );
        assert_eq!(std::fs::read(out.join("a.img")).unwrap(), b"precious");
        assert_eq!(
            std::fs::read(out.join("boot.img")).unwrap(),
            b"also precious"
        );
        assert!(!out.join("a.img.part").exists() && !out.join("boot.img.part").exists());
        let force = ExtractOptions {
            force: true,
            ..Default::default()
        };
        extract_all(&ota, &out, &force).unwrap();
        check_sample_output(&out);
        assert_eq!(std::fs::read(out.join("boot.img")).unwrap(), vec![0x11; 16]);
    }

    #[cfg(unix)]
    #[test]
    fn symlinks_in_the_output_dir_are_never_written_through() {
        use std::os::unix::fs::symlink;
        let (ota, out, victims) = (
            fresh_dir("sym-in"),
            fresh_dir("sym-out"),
            fresh_dir("sym-victim"),
        );
        let mut files = sample_files();
        files.push(("boot.img", vec![0x11; 16]));
        write_dir(&ota, &files);
        // planted .part links, for a partition and for a raw image
        symlink(victims.join("v1"), out.join("a.img.part")).unwrap();
        symlink(victims.join("v2"), out.join("boot.img.part")).unwrap();
        extract_all(&ota, &out, &ExtractOptions::default()).unwrap();
        assert!(!victims.join("v1").exists() && !victims.join("v2").exists());
        check_sample_output(&out);
        assert_eq!(std::fs::read(out.join("boot.img")).unwrap(), vec![0x11; 16]);
        assert!(!out.join("a.img.part").exists() && !out.join("boot.img.part").exists());
    }

    #[cfg(unix)]
    #[test]
    fn a_symlink_named_like_an_output_counts_as_existing() {
        use std::os::unix::fs::symlink;
        let (ota, out, victims) = (
            fresh_dir("sym2-in"),
            fresh_dir("sym2-out"),
            fresh_dir("sym2-victim"),
        );
        write_dir(&ota, &sample_files());
        symlink(victims.join("nowhere"), out.join("a.img")).unwrap(); // dangling
        let e = extract_all(&ota, &out, &ExtractOptions::default()).unwrap_err();
        assert!(
            e.to_string().contains("a.img") && e.to_string().contains("--force"),
            "{e}"
        );
        assert!(
            out.join("a.img")
                .symlink_metadata()
                .unwrap()
                .file_type()
                .is_symlink()
        );
        assert!(!victims.join("nowhere").exists() && !out.join("b.img").exists());
    }

    fn only(names: &[&str]) -> ExtractOptions {
        ExtractOptions {
            only: Some(names.iter().map(|n| n.to_string()).collect()),
            ..Default::default()
        }
    }

    fn written(dir: &Path) -> Vec<String> {
        let mut v: Vec<String> = std::fs::read_dir(dir)
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        v.sort();
        v
    }

    #[test]
    fn only_selects_partitions_and_raw_images_by_name() {
        let (ota, out) = (fresh_dir("only-in"), fresh_dir("only-out"));
        let mut files = sample_files();
        files.push(("boot.img", vec![0x11; 16]));
        files.push(("vbmeta.img", vec![0x22; 16]));
        write_dir(&ota, &files);
        extract_all(&ota, &out, &only(&["b"])).unwrap();
        assert_eq!(written(&out), ["b.img"]);
        assert_eq!(std::fs::read(out.join("b.img")).unwrap(), blk(9));
        let out2 = fresh_dir("only-out2");
        let paths = extract_all(&ota, &out2, &only(&["boot", "a"])).unwrap();
        assert_eq!(written(&out2), ["a.img", "boot.img"]);
        assert_eq!(paths.len(), 2);
        assert_eq!(
            std::fs::read(out2.join("a.img")).unwrap(),
            [blk(1), blk(2)].concat()
        );
        assert_eq!(
            std::fs::read(out2.join("boot.img")).unwrap(),
            vec![0x11; 16]
        );
    }

    #[test]
    fn only_with_an_unknown_name_lists_the_valid_ones_and_writes_nothing() {
        let (ota, out) = (fresh_dir("onlybad-in"), fresh_dir("onlybad-out"));
        let mut files = sample_files();
        files.push(("boot.img", vec![0x11; 16]));
        write_dir(&ota, &files);
        let e = extract_all(&ota, &out, &only(&["a", "sysem"])).unwrap_err();
        let msg = e.to_string();
        assert!(
            msg.contains("unknown name \"sysem\"") && msg.contains("available: a, b, boot"),
            "{msg}"
        );
        assert!(written(&out).is_empty());
        assert!(extract_all(&ota, &out, &only(&[""])).is_err());
    }

    #[test]
    fn repeated_names_in_only_extract_each_image_once() {
        let (ota, out) = (fresh_dir("dup-in"), fresh_dir("dup-out"));
        write_dir(&ota, &sample_files());
        let paths = extract_all(&ota, &out, &only(&["a", "a", "a"])).unwrap();
        assert_eq!(paths.len(), 1);
        assert_eq!(written(&out), ["a.img"]);
        let listed = list_images(&ota, &only(&["b", "b"])).unwrap();
        assert_eq!(listed.len(), 1);
    }

    #[test]
    fn only_matches_names_exactly_not_ignoring_case() {
        let (ota, out) = (fresh_dir("exact-in"), fresh_dir("exact-out"));
        let mut files = sample_files();
        files.push(("Boot.img", vec![0x11; 16]));
        write_dir(&ota, &files);
        // "A" is not "a", and the Boot.img/boot-like clash only matters when both are selected
        assert!(extract_all(&ota, &out, &only(&["A"])).is_err());
        let paths = extract_all(&ota, &out, &only(&["a"])).unwrap();
        assert_eq!(paths.len(), 1);
        assert_eq!(written(&out), ["a.img"]);
    }

    #[test]
    fn a_trailing_comma_in_only_is_rejected_not_ignored() {
        let (ota, out) = (fresh_dir("comma-in"), fresh_dir("comma-out"));
        write_dir(&ota, &sample_files());
        let e = extract_all(&ota, &out, &only(&["a", ""])).unwrap_err();
        assert!(e.to_string().contains("unknown name \"\""), "{e}");
        assert!(written(&out).is_empty());
    }

    #[test]
    fn only_ignores_existing_files_that_are_not_selected() {
        let (ota, out) = (fresh_dir("onlyex-in"), fresh_dir("onlyex-out"));
        write_dir(&ota, &sample_files());
        std::fs::write(out.join("a.img"), b"keep me").unwrap();
        extract_all(&ota, &out, &only(&["b"])).unwrap();
        assert_eq!(std::fs::read(out.join("a.img")).unwrap(), b"keep me");
        assert!(extract_all(&ota, &out, &only(&["a"])).is_err());
    }

    #[test]
    fn list_reports_sizes_without_writing_anything() {
        let (ota, work, out) = (
            fresh_dir("list-in"),
            fresh_dir("list-zip"),
            fresh_dir("list-out"),
        );
        let mut files = sample_files();
        files.push(("boot.img", vec![0x11; 1234]));
        write_dir(&ota, &files);
        let zip_path = work.join("ota.zip");
        zip_of(&files, &zip_path);
        let expect = vec![
            ("a.img".to_string(), 2 * BLOCK as u64),
            ("b.img".to_string(), BLOCK as u64),
            ("boot.img".to_string(), 1234),
        ];
        for input in [ota.as_path(), zip_path.as_path()] {
            assert_eq!(
                list_images(input, &ExtractOptions::default()).unwrap(),
                expect
            );
        }
        let list = ExtractOptions {
            list: true,
            ..Default::default()
        };
        run(&ota, &out, &list).unwrap();
        assert!(written(&out).is_empty());
        let gone = out.join("never-created");
        run(&ota, &gone, &list).unwrap();
        assert!(
            !gone.exists(),
            "--list must not create the output directory"
        );
        let sel = ExtractOptions {
            only: Some(vec!["b".into()]),
            ..Default::default()
        };
        assert_eq!(
            list_images(&ota, &sel).unwrap(),
            vec![("b.img".to_string(), BLOCK as u64)]
        );
    }

    #[test]
    fn listed_size_matches_the_extracted_image_when_the_header_count_is_smaller() {
        let (ota, out) = (fresh_dir("listreal-in"), fresh_dir("listreal-out"));
        // header says 1 block was written, but an erase reaches block 5, as in real OTAs
        write_dir(
            &ota,
            &[
                (
                    "c.transfer.list",
                    b"4\n1\n0\n0\nnew 2,0,1\nerase 2,1,5\n".to_vec(),
                ),
                ("c.new.dat", blk(7)),
            ],
        );
        let listed = list_images(&ota, &ExtractOptions::default()).unwrap();
        assert_eq!(listed, vec![("c.img".to_string(), 5 * BLOCK as u64)]);
        extract_all(&ota, &out, &ExtractOptions::default()).unwrap();
        assert_eq!(
            std::fs::metadata(out.join("c.img")).unwrap().len(),
            listed[0].1
        );
    }

    #[test]
    fn list_does_not_care_about_existing_output() {
        let (ota, out) = (fresh_dir("listex-in"), fresh_dir("listex-out"));
        write_dir(&ota, &sample_files());
        std::fs::write(out.join("a.img"), b"x").unwrap();
        let list = ExtractOptions {
            list: true,
            ..Default::default()
        };
        run(&ota, &out, &list).unwrap();
        assert_eq!(std::fs::read(out.join("a.img")).unwrap(), b"x");
    }

    #[test]
    fn result_lines_show_the_filesystem_only_when_recognised() {
        let dir = fresh_dir("describe");
        let mut ext4 = vec![0u8; 8192];
        ext4[1024 + 0x38..1024 + 0x3A].copy_from_slice(&0xEF53u16.to_le_bytes());
        ext4[1024 + 0x60..1024 + 0x64].copy_from_slice(&0x40u32.to_le_bytes());
        std::fs::write(dir.join("system.img"), &ext4).unwrap();
        std::fs::write(dir.join("boot.img"), vec![7u8; 5000]).unwrap();
        let line = describe(&dir.join("system.img")).unwrap();
        assert!(line.ends_with("system.img  8 KiB  ext4"), "{line}");
        let line = describe(&dir.join("boot.img")).unwrap();
        assert!(line.ends_with("boot.img  4.9 KiB"), "{line}");
        // a recognised filesystem whose size is not block aligned gets a warning
        ext4.truncate(5000);
        ext4.resize(5001, 0);
        std::fs::write(dir.join("odd.img"), &ext4).unwrap();
        let line = describe(&dir.join("odd.img")).unwrap();
        assert!(
            line.contains("ext4  (size is not a multiple of 4096)"),
            "{line}"
        );
    }

    /// Cut `data` into pieces of the given sizes; the rest becomes the last piece.
    fn cut(data: &[u8], sizes: &[usize]) -> Vec<Vec<u8>> {
        let mut pieces = Vec::new();
        let mut at = 0;
        for &n in sizes {
            pieces.push(data[at..at + n].to_vec());
            at += n;
        }
        pieces.push(data[at..].to_vec());
        pieces
    }

    fn piece_files(prefix: &str, first: usize, pieces: Vec<Vec<u8>>) -> Vec<(String, Vec<u8>)> {
        let mut files = vec![(
            "a.transfer.list".to_string(),
            b"4\n3\n0\n0\nnew 2,0,3\n".to_vec(),
        )];
        for (i, body) in pieces.into_iter().enumerate() {
            files.push((format!("{prefix}.{}", first + i), body));
        }
        files
    }

    fn extract_files(
        tag: &str,
        files: &[(String, Vec<u8>)],
    ) -> (crate::testutil::Scratch, Result<Vec<PathBuf>>) {
        let (ota, out) = (
            fresh_dir(&format!("{tag}-in")),
            fresh_dir(&format!("{tag}-out")),
        );
        let borrowed: Vec<(&str, Vec<u8>)> =
            files.iter().map(|(n, b)| (n.as_str(), b.clone())).collect();
        write_dir(&ota, &borrowed);
        let res = extract_all(&ota, &out, &ExtractOptions::default());
        (out, res)
    }

    fn three_blocks() -> Vec<u8> {
        [blk(1), blk(2), blk(3)].concat()
    }

    #[test]
    fn split_raw_pieces_are_joined_in_order_whatever_their_sizes() {
        for first in [0, 1] {
            let files = piece_files("a.new.dat", first, cut(&three_blocks(), &[1000, 5000]));
            let (out, res) = extract_files(&format!("sraw{first}"), &files);
            res.unwrap();
            assert_eq!(
                std::fs::read(out.join("a.img")).unwrap(),
                three_blocks(),
                "first piece is .{first}"
            );
        }
    }

    #[test]
    fn split_brotli_pieces_are_joined_before_decompressing() {
        let packed = brotli(&three_blocks());
        let files = piece_files("a.new.dat.br", 1, cut(&packed, &[7, packed.len() / 2]));
        let (out, res) = extract_files("sbr", &files);
        res.unwrap();
        assert_eq!(std::fs::read(out.join("a.img")).unwrap(), three_blocks());
    }

    #[test]
    fn split_pieces_work_from_a_zip_too() {
        let (work, out) = (fresh_dir("szip-in"), fresh_dir("szip-out"));
        let files = piece_files("a.new.dat", 1, cut(&three_blocks(), &[4096, 4096]));
        let borrowed: Vec<(&str, Vec<u8>)> =
            files.iter().map(|(n, b)| (n.as_str(), b.clone())).collect();
        let zip_path = work.join("ota.zip");
        zip_of(&borrowed, &zip_path);
        extract_all(&zip_path, &out, &ExtractOptions::default()).unwrap();
        assert_eq!(std::fs::read(out.join("a.img")).unwrap(), three_blocks());
    }

    #[test]
    fn pieces_missing_from_the_sequence_are_an_error() {
        let mut files = piece_files("a.new.dat", 1, cut(&three_blocks(), &[4096, 4096]));
        files.retain(|(n, _)| n != "a.new.dat.2");
        let (out, res) = extract_files("smiss", &files);
        let msg = format!("{:#}", res.unwrap_err());
        assert!(
            msg.contains("not consecutive") && msg.contains("found 1, 3"),
            "{msg}"
        );
        let files = piece_files("a.new.dat", 2, cut(&three_blocks(), &[4096, 4096]));
        let (_, res) = extract_files("sfirst", &files);
        assert!(format!("{:#}", res.unwrap_err()).contains("not consecutive"));
        assert!(!out.join("a.img").exists());
    }

    #[test]
    fn a_whole_data_file_wins_over_pieces() {
        let mut files = piece_files("a.new.dat", 1, vec![vec![0x77; 4096]]);
        files[0].1 = b"4\n1\n0\n0\nnew 2,0,1\n".to_vec();
        files.push(("a.new.dat".to_string(), blk(9)));
        let (out, res) = extract_files("swhole", &files);
        res.unwrap();
        assert_eq!(std::fs::read(out.join("a.img")).unwrap(), blk(9));
    }

    #[test]
    fn surplus_data_in_pieces_is_an_error_and_does_not_hang() {
        let mut files = piece_files("a.new.dat", 1, cut(&three_blocks(), &[100]));
        files[0].1 = b"4\n2\n0\n0\nnew 2,0,2\n".to_vec();
        let (out, res) = extract_files("ssurplus", &files);
        assert!(format!("{:#}", res.unwrap_err()).contains("more blocks"));
        assert!(!out.join("a.img").exists() && !out.join("a.img.part").exists());
    }

    #[test]
    fn a_consumer_that_stops_early_never_leaves_the_piece_reader_blocked() {
        // 9 MiB of pieces but the transfer list needs 1 block: apply() fails after the first
        // chunk while the reader thread still has far more than the channel can hold. If the
        // receiver were kept alive that thread would block forever and the scope would hang.
        let mut files = piece_files("a.new.dat", 1, vec![vec![0xAB; 3 << 20]; 3]);
        files[0].1 = b"4\n1\n0\n0\nnew 2,0,1\n".to_vec();
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let (out, res) = extract_files("sstop", &files);
            let _ = tx.send((out, res.map(|_| ()).map_err(|e| format!("{e:#}"))));
        });
        let (out, res) = rx
            .recv_timeout(std::time::Duration::from_secs(60))
            .expect("extraction hung: the piece reader is blocked on a full channel");
        assert!(res.unwrap_err().contains("more blocks"));
        assert!(!out.join("a.img").exists() && !out.join("a.img.part").exists());
    }

    #[test]
    fn a_piece_read_error_after_the_consumer_finished_is_not_reported_as_success_or_truncation() {
        // the corrupt piece is the LAST one and the list needs only the first: the run fails with
        // the surplus-data error, never produces an image from a truncated stream
        let files = piece_files("a.new.dat", 1, cut(&three_blocks(), &[4096, 4096]));
        let mut files = files;
        files[0].1 = b"4\n1\n0\n0\nnew 2,0,1\n".to_vec();
        let (out, res) = extract_files("slate", &files);
        assert!(format!("{:#}", res.unwrap_err()).contains("more blocks"));
        assert!(!out.join("a.img").exists());
    }

    #[test]
    fn short_data_in_pieces_is_an_error() {
        let files = piece_files("a.new.dat", 1, cut(&three_blocks()[..8000], &[3000]));
        let (out, res) = extract_files("sshort", &files);
        assert!(format!("{:#}", res.unwrap_err()).contains("ended before"));
        assert!(!out.join("a.img").exists());
    }

    #[test]
    fn a_corrupt_piece_in_a_zip_fails_the_partition_cleanly() {
        let (work, out) = (fresh_dir("scrc-in"), fresh_dir("scrc-out"));
        let mut pieces = cut(&three_blocks(), &[4096, 4096]);
        pieces[1] = vec![0x5a; 4096];
        let files = piece_files("a.new.dat", 1, pieces);
        let borrowed: Vec<(&str, Vec<u8>)> =
            files.iter().map(|(n, b)| (n.as_str(), b.clone())).collect();
        let zip_path = work.join("ota.zip");
        zip_of(&borrowed, &zip_path);
        let mut bytes = std::fs::read(&zip_path).unwrap();
        let at = bytes.windows(64).position(|w| w == [0x5a; 64]).unwrap();
        bytes[at] ^= 0xff;
        std::fs::write(&zip_path, bytes).unwrap();
        let e = extract_all(&zip_path, &out, &ExtractOptions::default()).unwrap_err();
        let msg = format!("{e:#}");
        assert!(msg.contains("extracting a"), "{msg}");
        assert!(
            msg.contains("reading a.new.dat.2"),
            "the real cause must reach the user: {msg}"
        );
        assert!(!out.join("a.img").exists() && !out.join("a.img.part").exists());
    }

    #[test]
    fn data_files_orders_pieces_numerically_and_reports_compression() {
        let names: Vec<String> = [
            "a.transfer.list",
            "a.new.dat.10",
            "a.new.dat.2",
            "a.new.dat.1",
            "a.new.dat.3",
            "a.new.dat.4",
            "a.new.dat.5",
            "a.new.dat.6",
            "a.new.dat.7",
            "a.new.dat.8",
            "a.new.dat.9",
            "a.new.dat.notanumber",
            "a.new.dat.",
            "b.new.dat.1",
        ]
        .iter()
        .map(|s| s.to_string())
        .collect();
        let (files, compressed) = data_files(&names, "a").unwrap();
        let expect: Vec<String> = (1..=10).map(|n| format!("a.new.dat.{n}")).collect();
        assert_eq!(
            files, expect,
            "numeric order, junk suffixes and other partitions ignored"
        );
        assert!(!compressed);
        let br: Vec<String> = ["a.new.dat.br.1", "a.new.dat.br.0"]
            .iter()
            .map(|s| s.to_string())
            .collect();
        assert_eq!(
            data_files(&br, "a").unwrap(),
            (
                vec!["a.new.dat.br.0".to_string(), "a.new.dat.br.1".to_string()],
                true
            )
        );
        assert!(data_files(&["a.new.dat.x".to_string()], "a").is_err());
    }

    #[test]
    fn a_refused_run_writes_nothing_new() {
        let (ota, out) = (fresh_dir("refuse-in"), fresh_dir("refuse-out"));
        let mut files = sample_files();
        files.push(("boot.img", vec![0x11; 16]));
        write_dir(&ota, &files);
        std::fs::write(out.join("boot.img"), b"mine").unwrap();
        assert!(extract_all(&ota, &out, &ExtractOptions::default()).is_err());
        assert!(!out.join("a.img").exists() && !out.join("b.img").exists());
        assert_eq!(std::fs::read(out.join("boot.img")).unwrap(), b"mine");
    }

    #[test]
    fn unsafe_raw_image_names_are_rejected() {
        let (ota, out) = (fresh_dir("rawname-in"), fresh_dir("rawname-out"));
        let mut files = sample_files();
        files.push(("we ird.img", vec![1; 10]));
        write_dir(&ota, &files);
        let e = extract_all(&ota, &out, &ExtractOptions::default()).unwrap_err();
        assert!(e.to_string().contains("unsafe file name"), "{e}");
    }

    #[test]
    fn failed_raw_copy_leaves_nothing_behind() {
        let (work, out) = (fresh_dir("rawbad-zip"), fresh_dir("rawbad-out"));
        let mut files = sample_files();
        files.push(("boot.img", vec![0x5a; 64]));
        let zip_path = work.join("ota.zip");
        zip_of(&files, &zip_path);
        // flip one byte of the stored boot.img data so its CRC no longer matches
        let mut bytes = std::fs::read(&zip_path).unwrap();
        let at = bytes.windows(64).position(|w| w == [0x5a; 64]).unwrap();
        bytes[at] ^= 0xff;
        std::fs::write(&zip_path, bytes).unwrap();
        let e = extract_all(&zip_path, &out, &ExtractOptions::default()).unwrap_err();
        assert!(format!("{e:#}").contains("copying boot.img"), "{e:#}");
        assert!(out.join("a.img").exists());
        assert!(!out.join("boot.img").exists() && !out.join("boot.img.part").exists());
    }

    #[test]
    fn input_without_transfer_lists_is_an_error() {
        let (ota, out) = (fresh_dir("none-in"), fresh_dir("none-out"));
        write_dir(&ota, &[("readme.txt", b"hi".to_vec())]);
        let e = run(&ota, &out, &ExtractOptions::default()).unwrap_err();
        assert!(e.to_string().contains("not a block OTA"), "{e}");
    }

    #[test]
    fn missing_data_file_is_an_error() {
        let (ota, out) = (fresh_dir("nodata-in"), fresh_dir("nodata-out"));
        write_dir(
            &ota,
            &[("a.transfer.list", b"4\n1\n0\n0\nnew 2,0,1\n".to_vec())],
        );
        let e = run(&ota, &out, &ExtractOptions::default()).unwrap_err();
        assert!(
            e.to_string().contains("neither a.new.dat.br nor a.new.dat"),
            "{e}"
        );
    }

    #[test]
    fn failed_extraction_leaves_no_image_behind() {
        let (ota, out) = (fresh_dir("bad-in"), fresh_dir("bad-out"));
        write_dir(
            &ota,
            &[
                ("a.transfer.list", b"4\n1\n0\n0\nnew 2,0,1\n".to_vec()),
                ("a.new.dat.br", vec![0xff; BLOCK]),
            ],
        );
        assert!(run(&ota, &out, &ExtractOptions::default()).is_err());
        assert!(!out.join("a.img").exists());
        assert!(!out.join("a.img.part").exists());
    }

    #[test]
    fn unsafe_partition_names_are_rejected() {
        let (ota, out) = (fresh_dir("name-in"), fresh_dir("name-out"));
        write_dir(&ota, &[("we ird.transfer.list", b"4\n0\n0\n0\n".to_vec())]);
        let e = run(&ota, &out, &ExtractOptions::default()).unwrap_err();
        assert!(e.to_string().contains("unsafe partition name"), "{e}");
    }

    #[test]
    fn known_ota_scaffolding_is_ignored_not_unhandled() {
        // Everything a normal block OTA ships that is not a partition image. Treating any of
        // these as a failure would make the tool fail on every real update.
        for name in [
            "system.patch.dat",
            "vendor.patch.dat",
            "system.patch.dat.br",
            "sdat2img.py",
            "META-INF/CERT.RSA",
            "payload_properties.txt",
            "system.inf",
        ] {
            assert!(
                is_known_scaffolding(name),
                "{name} should be recognised as scaffolding"
            );
        }
    }

    #[test]
    fn a_partition_or_unknown_file_is_not_scaffolding() {
        for name in [
            "mystery.bin",
            "boot.img",
            "system.transfer.list",
            "random.txt",
        ] {
            assert!(
                !is_known_scaffolding(name),
                "{name} must not be treated as scaffolding"
            );
        }
    }

    #[test]
    fn an_unknown_top_level_file_fails_the_run_and_scaffolding_does_not() {
        let src = fresh_dir("unknown-in");
        let mut files = sample_files();
        files.push(("mystery.bin", b"???".to_vec()));
        files.push(("system.patch.dat", Vec::new()));
        write_dir(&src, &files);
        let out = fresh_dir("unknown-out");
        let e = format!(
            "{:#}",
            run(&src, &out, &ExtractOptions::default()).unwrap_err()
        );
        assert!(
            e.contains("mystery.bin"),
            "the unknown file must be named: {e}"
        );
        assert!(
            !e.contains("patch.dat"),
            "scaffolding must never be an error: {e}"
        );
    }

    #[test]
    fn allow_partial_succeeds_but_still_reports_the_unhandled_file() {
        let src = fresh_dir("partial-in");
        let mut files = sample_files();
        files.push(("mystery.bin", b"???".to_vec()));
        write_dir(&src, &files);
        let out = fresh_dir("partial-out");
        let opts = ExtractOptions {
            allow_partial: true,
            ..ExtractOptions::default()
        };
        let result = extract_all_noted(&src, &out, &opts).unwrap();
        assert_eq!(
            result.unhandled.len(),
            1,
            "the unknown file is still reported"
        );
        assert_eq!(result.unhandled[0].name, "mystery.bin");
        check_sample_output(&out);
    }

    #[test]
    fn skipped_files_are_reported_and_fail_without_allow_partial() {
        let (ota, out) = (fresh_dir("skip-in"), fresh_dir("skip-out"));
        let mut files = sample_files();
        files.push(("readme.txt", b"documentation".to_vec()));
        write_dir(&ota, &files);
        // Without --allow-partial, the run fails
        let e = run(&ota, &out, &ExtractOptions::default()).unwrap_err();
        assert!(
            e.to_string().contains("no handler") && e.to_string().contains("readme.txt"),
            "{e}"
        );
        // The files that were extracted are still present
        check_sample_output(&out);
    }

    #[test]
    fn allow_partial_silences_the_skip_error() {
        let (ota, out) = (fresh_dir("allow-in"), fresh_dir("allow-out"));
        let mut files = sample_files();
        files.push(("readme.txt", b"documentation".to_vec()));
        write_dir(&ota, &files);
        let opts = ExtractOptions {
            allow_partial: true,
            ..Default::default()
        };
        run(&ota, &out, &opts).unwrap();
        check_sample_output(&out);
    }

    #[test]
    fn extract_all_tracked_reports_skipped_files() {
        let (ota, out) = (fresh_dir("tracked-in"), fresh_dir("tracked-out"));
        let mut files = sample_files();
        files.push(("readme.txt", b"documentation".to_vec()));
        write_dir(&ota, &files);
        let result = extract_all_tracked(&ota, &out, &ExtractOptions::default()).unwrap();
        assert_eq!(result.unhandled.len(), 1);
        assert_eq!(result.unhandled[0].name, "readme.txt");
        assert_eq!(result.unhandled[0].reason, "no handler");
        assert_eq!(result.done.len(), 2);
    }

    #[test]
    fn extract_all_tracked_reports_no_skips_when_all_files_are_recognised() {
        let (ota, out) = (fresh_dir("noskip-in"), fresh_dir("noskip-out"));
        write_dir(&ota, &sample_files());
        let result = extract_all_tracked(&ota, &out, &ExtractOptions::default()).unwrap();
        assert!(result.unhandled.is_empty() && result.ignored.is_empty());
        assert_eq!(result.done.len(), 2);
    }

    #[test]
    fn quiet_mode_suppresses_per_image_lines() {
        let (ota, out) = (fresh_dir("quiet-in"), fresh_dir("quiet-out"));
        let mut files = sample_files();
        files.push(("readme.txt", b"documentation".to_vec()));
        write_dir(&ota, &files);
        let opts = ExtractOptions {
            allow_partial: true,
            quiet: true,
            ..Default::default()
        };
        // Should succeed without printing anything to stdout
        run(&ota, &out, &opts).unwrap();
        check_sample_output(&out);
    }

    #[test]
    fn strict_mode_fails_on_unrecognised_files() {
        let (ota, out) = (fresh_dir("strict-in"), fresh_dir("strict-out"));
        let mut files = sample_files();
        files.push(("readme.txt", b"documentation".to_vec()));
        write_dir(&ota, &files);
        let opts = ExtractOptions {
            strict: true,
            ..Default::default()
        };
        let e = extract_all_tracked(&ota, &out, &opts).unwrap_err();
        assert!(
            e.to_string().contains("strict mode") && e.to_string().contains("readme.txt"),
            "{e}"
        );
    }

    #[test]
    fn strict_mode_passes_when_no_unrecognised_files() {
        let (ota, out) = (fresh_dir("strict-ok-in"), fresh_dir("strict-ok-out"));
        write_dir(&ota, &sample_files());
        let opts = ExtractOptions {
            strict: true,
            ..Default::default()
        };
        extract_all_tracked(&ota, &out, &opts).unwrap();
        check_sample_output(&out);
    }
}
