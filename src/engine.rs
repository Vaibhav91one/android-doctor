//! The extraction engine: a queue of format handlers.
//!
//! A handler sniffs the head bytes of an input, and if it matches, unpacks it into a staging
//! directory. Each artifact produced is re-sniffed and queued again, so nested containers
//! (tar of zip of tar) resolve without any handler knowing about the others.

use crate::archive;
use anyhow::{Context, Result, ensure};
use std::path::{Path, PathBuf};

/// One container format the engine can unpack.
pub trait Handler {
    /// Stable id, used in messages and in the one-line registration.
    fn id(&self) -> &'static str;
    /// True when this handler recognises the input from its first bytes.
    fn matches(&self, head: &[u8]) -> bool;
    /// Unpack into `stage`, returning the artifacts found inside.
    fn unpack(&self, input: &Path, stage: &Path) -> Result<Vec<PathBuf>>;
}

/// Guards against a container that expands without bound.
#[derive(Debug, Clone)]
pub struct Limits {
    pub max_depth: usize,
    pub max_total_bytes: u64,
    pub max_files: usize,
}

impl Default for Limits {
    fn default() -> Self {
        Limits {
            max_depth: 8,
            max_total_bytes: 8 << 30,
            max_files: 100_000,
        }
    }
}

/// A file waiting to be unpacked, with its queue depth.
struct Queued {
    path: PathBuf,
    depth: usize,
}

/// Unpack `input` until only unrecognised files remain, returning what was produced.
///
/// Every artifact is re-sniffed and queued again, so nested containers resolve without any
/// handler knowing about the others. The limits are a zip-bomb guard.
pub fn run(
    handlers: &[Box<dyn Handler>],
    input: &Path,
    stage: &Path,
    limits: &Limits,
) -> Result<Vec<PathBuf>> {
    let mut queue = vec![Queued {
        path: input.to_path_buf(),
        depth: 0,
    }];
    let mut done = Vec::new();
    let mut total_bytes: u64 = 0;
    while let Some(item) = queue.pop() {
        ensure!(
            item.depth <= limits.max_depth,
            "container nesting deeper than {} levels",
            limits.max_depth
        );
        let head = read_head(&item.path, 512)?;
        let Some(handler) = handlers.iter().find(|h| h.matches(&head)) else {
            done.push(item.path);
            continue;
        };
        total_bytes += std::fs::metadata(&item.path)?.len();
        ensure!(
            total_bytes <= limits.max_total_bytes,
            "unpacked output exceeds the limit"
        );
        let before = stage.read_dir().map(|d| d.count()).unwrap_or(0);
        let produced = handler.unpack(&item.path, stage)?;
        ensure!(
            produced.len() <= limits.max_files,
            "handler {} produced more than {} files",
            handler.id(),
            limits.max_files
        );
        let after = stage.read_dir().map(|d| d.count()).unwrap_or(0);
        ensure!(
            after - before <= limits.max_files,
            "output file count exceeded the limit"
        );
        for p in produced {
            queue.push(Queued {
                path: p,
                depth: item.depth + 1,
            });
        }
    }
    Ok(done)
}

fn read_head(path: &Path, n: usize) -> Result<Vec<u8>> {
    use std::io::Read;
    let mut f = std::fs::File::open(path).with_context(|| format!("opening {}", path.display()))?;
    let mut v = vec![0u8; n];
    let got = f.read(&mut v)?;
    v.truncate(got);
    Ok(v)
}

/// The tar handler: unpacks plain tar, compressed tar, and Samsung `.tar.md5`.
/// Behaviour matches `archive::extract` exactly.
struct TarHandler;

impl Handler for TarHandler {
    fn id(&self) -> &'static str {
        "tar"
    }

    fn matches(&self, head: &[u8]) -> bool {
        archive::kind_of(head).is_some() || head.windows(4).any(|w| w == b"ustar")
    }

    fn unpack(&self, input: &Path, stage: &Path) -> Result<Vec<PathBuf>> {
        // Unpack directly into the staging root: the caller already decides what the output
        // directory is called, so adding a level here would change behaviour.
        std::fs::create_dir_all(stage)?;
        archive::extract(input, stage)?;
        walk_files(stage)
    }
}

/// Unpack `input` into `out_dir`, publishing only when the whole tree succeeded.
///
/// The staging directory is removed on every path, so a failure leaves nothing behind.
pub fn unpack_into(
    handlers: &[Box<dyn Handler>],
    input: &Path,
    out_dir: &Path,
    limits: &Limits,
) -> Result<()> {
    let staging = crate::treeout::prepare_staging(out_dir)?;
    match run(handlers, input, &staging, limits) {
        Ok(artifacts) => {
            let _ = artifacts;
            crate::treeout::publish(&staging, out_dir)?;
            Ok(())
        }
        Err(e) => {
            let _ = std::fs::remove_dir_all(&staging);
            Err(e)
        }
    }
}

/// All handlers registered with the engine, in priority order.
/// To add a new format handler, append one line:
///     handlers.push(Box::new(YourHandler));
pub fn handlers() -> Vec<Box<dyn Handler>> {
    vec![Box::new(TarHandler)]
}

/// Recursively collect every regular file under `dir`.
fn walk_files(dir: &Path) -> Result<Vec<PathBuf>> {
    let mut out = Vec::new();
    for entry in std::fs::read_dir(dir)? {
        let entry = entry?;
        let path = entry.path();
        let meta = entry.metadata()?;
        if meta.is_file() {
            out.push(path);
        } else if meta.is_dir() {
            out.extend(walk_files(&path)?);
        }
    }
    Ok(out)
}
