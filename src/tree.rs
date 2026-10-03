//! What every file-system reader (ext2/3/4, erofs) shares: the entry record, the manifest, and the
//! all-or-nothing extraction of a tree into a directory.
use crate::treeout::{Collisions, Sink, host_collisions, prepare_staging, publish, short};
use anyhow::{Context, Result};
use serde_json::{Value, json};
use std::collections::{BTreeMap, HashMap};
use std::fs::File;
use std::path::Path;

pub(crate) const MAX_ENTRIES: usize = 2_000_000;
pub(crate) const MAX_DEPTH: usize = 1024;
pub(crate) const MAX_PATH: usize = 4096;
pub(crate) const MAX_SYMLINK: u64 = 4096;
/// Largest directory a reader will list (a directory is read whole).
pub(crate) const MAX_DIR_BYTES: u64 = 256 << 20;

/// Largest logical size of one file (holes are hashed as zeros, so this bounds the time).
pub(crate) const MAX_FILE_BYTES: u64 = 16 << 30;
/// Largest total of logical file sizes in one extraction, or four times the image if larger.
pub(crate) const MIN_TOTAL_BYTES: u64 = 32 << 30;
pub(crate) const COPY_CHUNK: usize = 1 << 20;

#[derive(Debug, PartialEq, Clone, Copy)]
pub enum Kind {
    File,
    Dir,
    Symlink,
    CharDevice,
    BlockDevice,
    Fifo,
    Socket,
}

impl Kind {
    pub(crate) fn from_mode(mode: u16) -> Option<Kind> {
        Some(match mode & 0o170000 {
            0o100000 => Kind::File,
            0o040000 => Kind::Dir,
            0o120000 => Kind::Symlink,
            0o020000 => Kind::CharDevice,
            0o060000 => Kind::BlockDevice,
            0o010000 => Kind::Fifo,
            0o140000 => Kind::Socket,
            _ => return None,
        })
    }

    pub fn name(self) -> &'static str {
        match self {
            Kind::File => "file",
            Kind::Dir => "dir",
            Kind::Symlink => "symlink",
            Kind::CharDevice => "char",
            Kind::BlockDevice => "block",
            Kind::Fifo => "fifo",
            Kind::Socket => "socket",
        }
    }
}

/// One entry of the tree.
#[derive(Debug, Clone)]
pub struct Entry {
    pub path: String,
    pub kind: Kind,
    pub mode: u32,
    pub uid: u32,
    pub gid: u32,
    pub size: u64,
    pub mtime: i64,
    pub ino: u64,
    pub nlink: u32,
    pub link: Option<String>,
    pub rdev: Option<(u32, u32)>,
    pub xattrs: Vec<(String, String)>,
    pub sha256: Option<String>,
    /// Set when the file had to be extracted under another name (case collision).
    pub extracted_as: Option<String>,
}

/// A file system that can be walked and whose regular files can be copied out.
pub(crate) trait TreeSource {
    /// What the reader keeps per entry to read its data later (an inode).
    type Node;

    fn image_len(&self) -> u64;

    /// Every entry below the root, sorted by path. No file data is read.
    fn entries(&self) -> Result<Vec<(Entry, Self::Node)>>;

    /// Write a regular file's contents to `out` (holes stay holes) and return their SHA-256.
    /// `budget` is the number of logical bytes still allowed in this extraction.
    fn copy_data(&self, node: &Self::Node, out: &mut File, budget: &mut u64) -> Result<String>;

    /// The entries of the directory at `path` (not recursive), or the entry itself for a file.
    fn list_dir(&self, path: &str) -> Result<Vec<Entry>>;

    /// Write a regular file's contents to `out` (holes as zeros). Symlinks are not followed.
    fn cat_path(&self, path: &str, out: &mut dyn std::io::Write) -> Result<()>;
}

/// Refuse to print something that is not a regular file, saying what it is.
pub(crate) fn check_cat(entry: &Entry) -> Result<()> {
    match entry.kind {
        Kind::File => Ok(()),
        Kind::Symlink => anyhow::bail!(
            "/{} is a symlink to {}; give the real path",
            entry.path,
            entry.link.as_deref().unwrap_or("?")
        ),
        k => anyhow::bail!("/{} is a {}, not a regular file", entry.path, k.name()),
    }
}

/// An opened image of any file system we can read.
pub(crate) enum Tree {
    Ext(crate::ext4fs::Fs),
    Erofs(Box<crate::erofsfs::Fs>),
}

impl Tree {
    pub(crate) fn open(path: &Path) -> Result<Tree> {
        let fs = crate::detect::filesystem_of_file(path);
        match fs {
            Some(crate::detect::Filesystem::F2fs) => {
                anyhow::bail!(
                    "f2fs is not supported: the Linux kernel f2fs driver is GPL-licensed and no permissive Rust reader exists"
                );
            }
            Some(crate::detect::Filesystem::Erofs) => {
                Ok(Tree::Erofs(Box::new(crate::erofsfs::Fs::open(path)?)))
            }
            _ => Ok(Tree::Ext(crate::ext4fs::Fs::open(path)?)),
        }
    }

    pub(crate) fn extract(&self, out: &Path, collisions: Option<Collisions>) -> Result<Vec<Entry>> {
        match self {
            Tree::Ext(f) => f.extract(out, collisions),
            Tree::Erofs(f) => f.extract(out, collisions),
        }
    }

    pub(crate) fn entries(&self) -> Result<Vec<Entry>> {
        Ok(match self {
            Tree::Ext(f) => TreeSource::entries(f)?
                .into_iter()
                .map(|(e, _)| e)
                .collect(),
            Tree::Erofs(f) => TreeSource::entries(f.as_ref())?
                .into_iter()
                .map(|(e, _)| e)
                .collect(),
        })
    }

    pub(crate) fn list_dir(&self, path: &str) -> Result<Vec<Entry>> {
        match self {
            Tree::Ext(f) => TreeSource::list_dir(f, path),
            Tree::Erofs(f) => TreeSource::list_dir(f.as_ref(), path),
        }
    }

    pub(crate) fn cat_path(&self, path: &str, out: &mut dyn std::io::Write) -> Result<()> {
        match self {
            Tree::Ext(f) => TreeSource::cat_path(f, path, out),
            Tree::Erofs(f) => TreeSource::cat_path(f.as_ref(), path, out),
        }
    }
}

/// Extract the tree under `out_dir/files` with `manifest.json` beside it, all or nothing.
pub(crate) fn extract<T: TreeSource>(
    src: &T,
    out_dir: &Path,
    collisions: Option<Collisions>,
) -> Result<Vec<Entry>> {
    let staging = prepare_staging(out_dir)?;
    match extract_into(src, &staging, collisions) {
        Ok(entries) => {
            std::fs::write(
                staging.join("manifest.json"),
                serde_json::to_string_pretty(&manifest(&entries))?,
            )?;
            publish(&staging, out_dir)?;
            Ok(entries)
        }
        Err(e) => {
            let _ = std::fs::remove_dir_all(&staging);
            Err(e)
        }
    }
}

fn extract_into<T: TreeSource>(
    src: &T,
    staging: &Path,
    collisions: Option<Collisions>,
) -> Result<Vec<Entry>> {
    let files = staging.join("files");
    std::fs::create_dir(&files)?;
    let policy = collisions.unwrap_or_else(|| host_collisions(&files));
    let mut sink = Sink::with_collisions(&files, policy);
    let mut budget = MIN_TOTAL_BYTES.max(src.image_len().saturating_mul(4));
    let mut first_path: HashMap<u64, (String, String)> = HashMap::new(); // inode -> (path, sha)
    let mut done = Vec::new();
    for (mut entry, node) in src.entries()? {
        let path = entry.path.clone();
        let here = || format!("extracting {}", short(&path));
        match entry.kind {
            Kind::Dir => sink.make_parents(&format!("{path}/x")).with_context(here)?,
            Kind::Symlink => sink.note_symlink(&path).with_context(here)?,
            Kind::File => match first_path.get(&entry.ino) {
                Some((first, sha)) => {
                    sink.hard_link(first, &path).with_context(here)?;
                    entry.sha256 = Some(sha.clone());
                }
                None => {
                    let mut sha = None;
                    // owner read/write is added on disk so the tree stays usable; the manifest has the real mode
                    sink.write_with(&path, entry.mode | 0o600, |f| {
                        sha = Some(src.copy_data(&node, f, &mut budget)?);
                        Ok(())
                    })
                    .with_context(here)?;
                    let sha = sha.expect("the closure ran");
                    if entry.nlink > 1 {
                        first_path.insert(entry.ino, (path.clone(), sha.clone()));
                    }
                    entry.sha256 = Some(sha);
                }
            },
            _ => {}
        }
        let actual = sink.actual_path(&path);
        if actual != path && matches!(entry.kind, Kind::File | Kind::Dir) {
            entry.extracted_as = Some(actual);
        }
        done.push(entry);
    }
    Ok(done)
}

pub fn manifest(entries: &[Entry]) -> Value {
    let by: BTreeMap<&str, usize> = entries.iter().fold(BTreeMap::new(), |mut m, e| {
        *m.entry(e.kind.name()).or_default() += 1;
        m
    });
    json!({
        "entries": entries.iter().map(entry_json).collect::<Vec<_>>(),
        "summary": {"entries": entries.len(), "by_type": by},
    })
}

pub fn entry_json(e: &Entry) -> Value {
    let mut v = json!({
        "path": e.path, "type": e.kind.name(), "mode": e.mode, "uid": e.uid, "gid": e.gid,
        "size": e.size, "mtime": e.mtime, "inode": e.ino, "nlink": e.nlink,
        "link": e.link, "sha256": e.sha256,
        "xattrs": e.xattrs.iter().map(|(k, v)| (k.clone(), Value::String(v.clone()))).collect::<serde_json::Map<_, _>>(),
    });
    if let Some((major, minor)) = e.rdev {
        v["rdev"] = json!([major, minor]);
    }
    if let Some(a) = &e.extracted_as {
        v["extracted_as"] = json!(a);
    }
    v
}
