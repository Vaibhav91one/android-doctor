//! Read-only access to EROFS images (the compressed read-only file system most recent Android
//! releases use for system, vendor and product), and extraction of their files.
//!
//! The format work is done by the `am-fs-erofs` crate (MIT, clean-room): it reads every layout
//! `mkfs.erofs` 1.9 emits (plain, inline, chunked, LZ4/LZMA/DEFLATE/ZSTD compressed, big
//! pclusters, fragments, deduplication, xattrs, ACLs) and refuses features it cannot read. It was
//! checked against `fsck.erofs --extract` and against corrupted images before being adopted. What
//! this module adds is the same treatment of hostile images the ext reader gets: limits on depth,
//! entries, directory and symlink size and file size, reads in bounded chunks, holes kept as
//! holes, and loop detection.
use crate::detect::refuse_blocking_file;
use crate::ext4fs::{name_string, xattr_text};
use crate::tree::{
    COPY_CHUNK, Entry, Kind, MAX_DEPTH, MAX_DIR_BYTES, MAX_ENTRIES, MAX_FILE_BYTES, MAX_PATH,
    MAX_SYMLINK, TreeSource, check_cat,
};
use crate::treeout::{Collisions, short};
use anyhow::{Context, Result, anyhow, bail, ensure};
use fs_erofs::{FileType, Filesystem, Inode};
use sha2::{Digest, Sha256};
use std::collections::HashSet;
use std::fs::File;
use std::io::{Seek, SeekFrom, Write};
use std::path::Path;
use std::sync::Arc;

pub struct Fs {
    fs: Filesystem,
    len: u64,
}

/// Bounds on what one walk will accept (tests use tiny ones).
#[derive(Clone, Copy)]
struct Limits {
    depth: usize,
    path: usize,
    entries: usize,
}

const LIMITS: Limits = Limits {
    depth: MAX_DEPTH,
    path: MAX_PATH,
    entries: MAX_ENTRIES,
};

fn e<T>(r: std::result::Result<T, fs_erofs::Error>) -> Result<T> {
    r.map_err(|err| anyhow!("{err}"))
}

fn kind_of(inode: &Inode) -> Result<Kind> {
    Ok(match inode.file_type() {
        FileType::Dir => Kind::Dir,
        FileType::RegularFile => Kind::File,
        FileType::Symlink => Kind::Symlink,
        FileType::ChrDev => Kind::CharDevice,
        FileType::BlkDev => Kind::BlockDevice,
        FileType::Fifo => Kind::Fifo,
        FileType::Sock => Kind::Socket,
        FileType::Unknown => bail!("unknown file type in mode {:#o}", inode.mode),
    })
}

impl Fs {
    pub fn open(path: &Path) -> Result<Fs> {
        refuse_blocking_file(path)?;
        ensure!(
            !path.is_dir(),
            "{} is a directory, not an image",
            path.display()
        );
        let len = std::fs::metadata(path)
            .with_context(|| format!("opening {}", path.display()))?
            .len();
        let dev = fs_core::FileDevice::open(path)
            .map_err(|err| anyhow!("opening {}: {err}", path.display()))?;
        let fs = e(Filesystem::open(Arc::new(dev))).context("not a readable erofs image")?;
        Ok(Fs { fs, len })
    }

    fn read_dir(&self, dir: &Inode, max_entries: usize) -> Result<Vec<(String, u64)>> {
        ensure!(
            dir.size <= MAX_DIR_BYTES,
            "a directory of {} bytes is over the {MAX_DIR_BYTES}-byte limit",
            dir.size
        );
        let mut out = Vec::new();
        for d in e(self.fs.read_dir(dir))? {
            if d.name == b"." || d.name == b".." {
                continue;
            }
            ensure!(
                out.len() < max_entries,
                "a directory has more than {max_entries} entries"
            );
            out.push((name_string(&d.name), d.nid));
        }
        Ok(out)
    }

    fn entry_of(&self, path: String, inode: &Inode, kind: Kind) -> Result<Entry> {
        let link = if kind == Kind::Symlink {
            ensure!(
                inode.size <= MAX_SYMLINK,
                "a symlink target of {} bytes is not valid",
                inode.size
            );
            Some(name_string(&e(self.fs.read_symlink_target(inode))?))
        } else {
            None
        };
        let xattrs = e(self.fs.xattrs(inode))?;
        let mut xattrs: Vec<(String, String)> = xattrs
            .into_iter()
            .map(|(k, v)| (name_string(&k), xattr_text(&v)))
            .collect();
        xattrs.sort();
        Ok(Entry {
            path,
            kind,
            mode: inode.mode as u32 & 0o7777,
            uid: inode.uid,
            gid: inode.gid,
            size: if kind == Kind::File { inode.size } else { 0 },
            mtime: inode.mtime as i64,
            ino: inode.nid,
            nlink: inode.nlink,
            link,
            rdev: if matches!(kind, Kind::CharDevice | Kind::BlockDevice) {
                inode.rdev()
            } else {
                None
            },
            xattrs,
            sha256: None,
            extracted_as: None,
        })
    }

    /// Resolve `path` to its entry without following symlinks ("" or "/" is the root).
    fn lookup(&self, path: &str) -> Result<(Entry, Inode)> {
        let mut inode = e(self.fs.root_inode())?;
        let mut at = String::new();
        for part in path.split('/').filter(|p| !p.is_empty() && *p != ".") {
            ensure!(part != "..", "paths containing .. are not accepted");
            let here = if at.is_empty() {
                "/".to_string()
            } else {
                format!("/{at}")
            };
            ensure!(
                inode.is_dir(),
                "{} is not a directory (symlinks are not followed)",
                short(&here)
            );
            inode = self
                .fs
                .lookup(&inode, part.as_bytes())
                .map_err(|err| anyhow!("{} in {}: {err}", short(part), short(&here)))?;
            at = if at.is_empty() {
                part.to_string()
            } else {
                format!("{at}/{part}")
            };
        }
        let kind = kind_of(&inode)?;
        Ok((self.entry_of(at, &inode, kind)?, inode))
    }

    fn walk(&self) -> Result<Vec<(Entry, Inode)>> {
        self.walk_with(LIMITS)
    }

    fn walk_with(&self, limits: Limits) -> Result<Vec<(Entry, Inode)>> {
        let root = e(self.fs.root_inode()).context("reading the root directory")?;
        ensure!(root.is_dir(), "the root inode is not a directory");
        let mut out: Vec<(Entry, Inode)> = Vec::new();
        let mut seen_dirs: HashSet<u64> = HashSet::from([root.nid]);
        let mut stack = vec![(root, String::new(), 0usize)];
        while let Some((dir, prefix, depth)) = stack.pop() {
            ensure!(
                depth < limits.depth,
                "directories are nested more than {} deep",
                limits.depth
            );
            let mut children = self
                .read_dir(&dir, limits.entries)
                .with_context(|| format!("reading directory {}", short(&format!("/{prefix}"))))?;
            children.sort();
            for (name, nid) in children {
                let path = if prefix.is_empty() {
                    name
                } else {
                    format!("{prefix}/{name}")
                };
                ensure!(
                    path.len() <= limits.path,
                    "a path is longer than {} bytes",
                    limits.path
                );
                ensure!(
                    out.len() < limits.entries,
                    "the image has more than {} entries",
                    limits.entries
                );
                let inode = e(self.fs.read_inode(nid))
                    .with_context(|| format!("entry {}", short(&path)))?;
                let kind = kind_of(&inode).with_context(|| format!("entry {}", short(&path)))?;
                if kind == Kind::Dir {
                    ensure!(
                        seen_dirs.insert(nid),
                        "directory inode {nid} is reachable twice ({}): a loop",
                        short(&path)
                    );
                    stack.push((inode.clone(), path.clone(), depth + 1));
                }
                let entry = self
                    .entry_of(path.clone(), &inode, kind)
                    .with_context(|| format!("entry {}", short(&path)))?;
                out.push((entry, inode));
            }
        }
        out.sort_by(|a, b| a.0.path.cmp(&b.0.path));
        Ok(out)
    }

    /// Stream a regular file in bounded chunks. `write(offset, bytes)` is called for every chunk,
    /// in order, including all-zero ones; the caller decides whether to keep holes sparse.
    fn read_chunks(
        &self,
        inode: &Inode,
        mut write: impl FnMut(u64, &[u8]) -> Result<()>,
    ) -> Result<()> {
        ensure!(kind_of(inode)? == Kind::File, "not a regular file");
        ensure!(
            inode.size <= MAX_FILE_BYTES,
            "a file of {} bytes is over the {MAX_FILE_BYTES}-byte limit",
            inode.size
        );
        let mut buf = vec![0u8; COPY_CHUNK];
        let mut at = 0u64;
        while at < inode.size {
            let n = (inode.size - at).min(COPY_CHUNK as u64) as usize;
            e(self.fs.read_file(inode, at, &mut buf[..n]))
                .with_context(|| format!("reading file data at byte {at}"))?;
            write(at, &buf[..n])?;
            at += n as u64;
        }
        Ok(())
    }

    /// Extract the tree under `out_dir/files` with `manifest.json` beside it, all or nothing.
    pub fn extract(&self, out_dir: &Path, collisions: Option<Collisions>) -> Result<Vec<Entry>> {
        crate::tree::extract(self, out_dir, collisions)
    }
}

/// Write `bytes` at `at`, unless they are all zero: that stretch is left as a hole in the output
/// file (the caller sets the final length). Returns whether anything was written.
pub(crate) fn write_unless_zero<W: Write + Seek>(
    out: &mut W,
    at: u64,
    bytes: &[u8],
) -> Result<bool> {
    if bytes.iter().all(|b| *b == 0) {
        return Ok(false);
    }
    out.seek(SeekFrom::Start(at))?;
    out.write_all(bytes)?;
    Ok(true)
}

impl TreeSource for Fs {
    type Node = Inode;

    fn image_len(&self) -> u64 {
        self.len
    }

    fn entries(&self) -> Result<Vec<(Entry, Inode)>> {
        self.walk()
    }

    fn copy_data(&self, node: &Inode, out: &mut File, budget: &mut u64) -> Result<String> {
        ensure!(
            node.size <= *budget,
            "the files add up to more than the {}-byte limit",
            *budget
        );
        *budget -= node.size;
        let mut hasher = Sha256::new();
        self.read_chunks(node, |at, bytes| {
            hasher.update(bytes);
            write_unless_zero(out, at, bytes)?;
            Ok(())
        })?;
        out.set_len(node.size)?;
        Ok(hasher
            .finalize()
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect())
    }

    fn list_dir(&self, path: &str) -> Result<Vec<Entry>> {
        let (entry, inode) = self.lookup(path)?;
        if entry.kind != Kind::Dir {
            return Ok(vec![entry]);
        }
        let mut children = self.read_dir(&inode, MAX_ENTRIES)?;
        children.sort();
        children
            .into_iter()
            .map(|(name, nid)| {
                let child = e(self.fs.read_inode(nid))?;
                let kind = kind_of(&child).with_context(|| short(&name))?;
                let p = if entry.path.is_empty() {
                    name
                } else {
                    format!("{}/{name}", entry.path)
                };
                self.entry_of(p, &child, kind)
            })
            .collect()
    }

    fn cat_path(&self, path: &str, out: &mut dyn Write) -> Result<()> {
        let (entry, inode) = self.lookup(path)?;
        check_cat(&entry)?;
        self.read_chunks(&inode, |_, bytes| Ok(out.write_all(bytes)?))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tree::manifest;
    use fs_erofs::mkfs::{
        BuildOptions, CompressedAlgo, CompressedFileSpec, CompressedIndexFormat, Node, NodeMeta,
        XattrSpec, build_image, build_image_with,
    };
    use std::collections::BTreeMap;

    const REG: u16 = 0o100000;
    const DIR: u16 = 0o040000;
    const LNK: u16 = 0o120000;

    fn file(mode: u16, data: &[u8]) -> Node {
        Node::File {
            mode: REG | mode,
            data: data.to_vec(),
            meta: NodeMeta::default(),
            xattrs: vec![],
        }
    }

    fn dir(mode: u16, entries: Vec<(&str, Node)>) -> Node {
        Node::Dir {
            mode: DIR | mode,
            entries: entries
                .into_iter()
                .map(|(n, v)| (n.to_string(), v))
                .collect::<BTreeMap<_, _>>(),
            meta: NodeMeta::default(),
            xattrs: vec![],
        }
    }

    fn link(target: &str) -> Node {
        Node::Symlink {
            mode: LNK | 0o777,
            target: target.to_string(),
            meta: NodeMeta::default(),
            xattrs: vec![],
        }
    }

    fn compressible(n: usize) -> Vec<u8> {
        (0..n).map(|i| b"the quick brown fox "[i % 20]).collect()
    }

    fn compressed(algo: CompressedAlgo, index: CompressedIndexFormat, data: &[u8]) -> Node {
        Node::CompressedFile(CompressedFileSpec {
            mode: REG | 0o644,
            data: data.to_vec(),
            algo,
            lclusterbits: 0,
            meta: NodeMeta::default(),
            xattrs: vec![],
            index_format: index,
            ztailpacking: false,
            target_pcluster_blocks: CompressedFileSpec::default_target_pcluster_blocks(),
        })
    }

    fn tree() -> Node {
        dir(
            0o755,
            vec![
                ("a", file(0o644, b"hello\n")),
                ("empty", file(0o444, b"")),
                (
                    "d",
                    dir(
                        0o750,
                        vec![
                            ("b", file(0o600, &vec![7u8; 9000])),
                            ("c", file(0o644, &compressible(20_000))),
                        ],
                    ),
                ),
                ("s", link("a")),
                ("l", link(&"x".repeat(100))),
                (
                    "x",
                    Node::File {
                        mode: REG | 0o644,
                        data: b"labelled".to_vec(),
                        meta: NodeMeta {
                            uid: 1000,
                            gid: 2000,
                            mtime: 1_700_000_000,
                            mtime_nsec: 0,
                        },
                        xattrs: vec![XattrSpec::new(
                            6,
                            "selinux",
                            b"u:object_r:system_file:s0\0".to_vec(),
                        )],
                    },
                ),
            ],
        )
    }

    fn image() -> Vec<u8> {
        build_image(tree(), 12).unwrap()
    }

    /// Write the image to a temporary file and open it the way the commands do.
    fn from_bytes(image: Vec<u8>) -> Result<Fs> {
        use std::sync::atomic::{AtomicUsize, Ordering};
        static N: AtomicUsize = AtomicUsize::new(0);
        let d = scratch(&format!("img{}", N.fetch_add(1, Ordering::Relaxed)));
        let p = d.join("x.img");
        std::fs::write(&p, image).unwrap();
        Fs::open(&p)
    }

    fn scratch(tag: &str) -> crate::testutil::Scratch {
        crate::testutil::Scratch::new(&format!("erofs-{tag}"))
    }

    fn cat_bytes(fs: &Fs, path: &str) -> Vec<u8> {
        let mut out = Vec::new();
        fs.cat_path(path, &mut out).unwrap();
        out
    }

    #[test]
    fn lists_the_whole_tree_with_metadata() {
        let fs = from_bytes(image()).unwrap();
        let list = fs.walk().unwrap();
        let paths: Vec<_> = list.iter().map(|(e, _)| e.path.as_str()).collect();
        assert_eq!(paths, ["a", "d", "d/b", "d/c", "empty", "l", "s", "x"]);
        let by = |p: &str| &list.iter().find(|(e, _)| e.path == p).unwrap().0;
        assert_eq!(by("s").link.as_deref(), Some("a"));
        assert_eq!(by("l").link.as_deref(), Some("x".repeat(100).as_str()));
        assert_eq!((by("d").kind, by("d").mode), (Kind::Dir, 0o750));
        assert_eq!((by("d/b").size, by("d/b").mode), (9000, 0o600));
        assert_eq!(by("empty").size, 0);
        assert_eq!(
            (by("d").size, by("s").size, by("l").size),
            (0, 0, 0),
            "only files carry a size"
        );
        assert_eq!(
            (by("x").uid, by("x").gid, by("x").mtime),
            (1000, 2000, 1_700_000_000)
        );
        assert_eq!(
            by("x").xattrs,
            [(
                "security.selinux".to_string(),
                "u:object_r:system_file:s0".to_string()
            )]
        );
    }

    #[test]
    fn extracts_exact_bytes_and_a_manifest() {
        let fs = from_bytes(image()).unwrap();
        let dir = scratch("tree");
        let out = dir.join("o");
        let entries = fs.extract(&out, Some(Collisions::Allow)).unwrap();
        let files = out.join("files");
        assert_eq!(std::fs::read(files.join("a")).unwrap(), b"hello\n");
        assert_eq!(std::fs::read(files.join("d/b")).unwrap(), vec![7u8; 9000]);
        assert_eq!(
            std::fs::read(files.join("d/c")).unwrap(),
            compressible(20_000)
        );
        assert_eq!(std::fs::read(files.join("empty")).unwrap(), b"");
        assert!(
            files.join("s").symlink_metadata().is_err(),
            "symlinks are never created"
        );
        let sha = |b: &[u8]| -> String {
            Sha256::digest(b)
                .iter()
                .map(|x| format!("{x:02x}"))
                .collect()
        };
        let by = |p: &str| entries.iter().find(|e| e.path == p).unwrap();
        assert_eq!(by("a").sha256.as_deref(), Some(sha(b"hello\n").as_str()));
        assert_eq!(
            by("d/c").sha256.as_deref(),
            Some(sha(&compressible(20_000)).as_str())
        );
        let m: serde_json::Value =
            serde_json::from_slice(&std::fs::read(out.join("manifest.json")).unwrap()).unwrap();
        assert_eq!(m["summary"]["entries"], 8);
        assert_eq!(manifest(&entries)["summary"]["by_type"]["symlink"], 2);
    }

    #[test]
    fn every_compression_and_index_format_reads_back() {
        let data = compressible(70_000);
        for algo in [
            CompressedAlgo::Lz4,
            CompressedAlgo::Lzma,
            CompressedAlgo::Deflate,
        ] {
            for index in [
                CompressedIndexFormat::Legacy,
                CompressedIndexFormat::Compacted2B,
            ] {
                let root = dir(0o755, vec![("f", compressed(algo, index, &data))]);
                let fs = from_bytes(build_image_with(root, 12, BuildOptions::default()).unwrap())
                    .unwrap();
                assert_eq!(cat_bytes(&fs, "f"), data, "{algo:?} {index:?}");
            }
        }
    }

    #[test]
    fn path_lookup_and_listing_do_not_follow_symlinks() {
        let fs = from_bytes(image()).unwrap();
        for p in ["a", "/a", "a/", "./a", "//a", "d/b", "/d//b/"] {
            assert!(fs.lookup(p).is_ok(), "{p}");
        }
        assert_eq!(fs.lookup("/").unwrap().0.kind, Kind::Dir);
        assert_eq!(fs.lookup("s").unwrap().0.kind, Kind::Symlink);
        let err = |p: &str| format!("{:#}", fs.lookup(p).unwrap_err());
        assert!(err("nope").contains("nope"), "{}", err("nope"));
        assert!(err("a/x").contains("not a directory"));
        assert!(err("s/x").contains("symlinks are not followed"));
        assert!(err("d/../a").contains("not accepted"));
        let names = |p: &str| {
            fs.list_dir(p)
                .unwrap()
                .into_iter()
                .map(|e| e.path)
                .collect::<Vec<_>>()
        };
        assert_eq!(names("/"), ["a", "d", "empty", "l", "s", "x"]);
        assert_eq!(names("d"), ["d/b", "d/c"]);
        assert_eq!(names("a"), ["a"]);
    }

    #[test]
    fn cat_refuses_what_is_not_a_file() {
        let fs = from_bytes(image()).unwrap();
        assert_eq!(cat_bytes(&fs, "d/b"), vec![7u8; 9000]);
        let e = |p: &str| format!("{:#}", fs.cat_path(p, &mut Vec::new()).unwrap_err());
        assert!(e("d").contains("not a regular file"), "{}", e("d"));
        assert!(e("s").contains("symlink to a"), "{}", e("s"));
    }

    #[test]
    fn all_zero_chunks_are_not_written() {
        let mut out = std::io::Cursor::new(Vec::new());
        assert!(!write_unless_zero(&mut out, 0, &[0u8; 4096]).unwrap());
        assert!(!write_unless_zero(&mut out, 4096, &[]).unwrap());
        assert!(out.get_ref().is_empty(), "nothing was written for zeros");
        assert!(write_unless_zero(&mut out, 8192, &[0, 0, 1, 0]).unwrap());
        assert_eq!(out.get_ref().len(), 8196);
        assert_eq!(&out.get_ref()[8192..], [0, 0, 1, 0]);
        assert!(
            out.get_ref()[..8192].iter().all(|b| *b == 0),
            "the gap before it reads as zeros"
        );
    }

    #[test]
    fn a_file_with_zero_stretches_extracts_to_the_exact_bytes() {
        let mut data = vec![0u8; 3 << 20];
        data[10] = 1;
        let n = data.len();
        data[n - 1] = 2;
        let fs = from_bytes(build_image(dir(0o755, vec![("z", file(0o644, &data))]), 12).unwrap())
            .unwrap();
        let dirp = scratch("holes");
        let entries = fs
            .extract(&dirp.join("o"), Some(Collisions::Allow))
            .unwrap();
        assert_eq!(std::fs::read(dirp.join("o/files/z")).unwrap(), data);
        let sha: String = Sha256::digest(&data)
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        assert_eq!(entries[0].sha256.as_deref(), Some(sha.as_str()));
        assert_eq!(cat_bytes(&fs, "z"), data);
    }

    #[test]
    fn walk_limits_are_enforced() {
        let fs = from_bytes(image()).unwrap();
        let big = Limits {
            depth: 8,
            path: 64,
            entries: 100,
        };
        assert_eq!(fs.walk_with(big).unwrap().len(), 8);
        let err = |l: Limits| format!("{:#}", fs.walk_with(l).unwrap_err());
        assert!(err(Limits { depth: 1, ..big }).contains("nested more than 1 deep"));
        assert!(err(Limits { path: 2, ..big }).contains("longer than 2 bytes"));
        // the root lists 6 names, so 7 passes the per-directory cap and only the total can trip
        assert!(err(Limits { entries: 7, ..big }).contains("the image has more than 7 entries"));
        assert!(err(Limits { entries: 5, ..big }).contains("directory has more than 5"));
        // a single directory over the per-directory cap is refused while listing
        let root = fs.fs.root_inode().unwrap();
        assert!(
            format!("{:#}", fs.read_dir(&root, 3).unwrap_err())
                .contains("directory has more than 3")
        );
        assert_eq!(fs.read_dir(&root, 100).unwrap().len(), 6);
    }

    #[test]
    fn reading_data_of_something_that_is_not_a_file_is_refused() {
        let fs = from_bytes(image()).unwrap();
        let (_, dir) = fs.lookup("d").unwrap();
        let e = format!("{:#}", fs.read_chunks(&dir, |_, _| Ok(())).unwrap_err());
        assert!(e.contains("not a regular file"), "{e}");
    }

    #[test]
    fn a_trailing_stretch_of_zeros_keeps_the_file_length() {
        let mut data = vec![0u8; 2 * (1 << 20) + 100];
        data[..4].copy_from_slice(b"head");
        let fs = from_bytes(build_image(dir(0o755, vec![("z", file(0o644, &data))]), 12).unwrap())
            .unwrap();
        let dirp = scratch("trailzero");
        let entries = fs
            .extract(&dirp.join("o"), Some(Collisions::Allow))
            .unwrap();
        let got = std::fs::read(dirp.join("o/files/z")).unwrap();
        assert_eq!(got.len(), data.len(), "the zero tail must not be cut off");
        assert_eq!(got, data);
        let sha: String = Sha256::digest(&data)
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        assert_eq!(entries[0].sha256.as_deref(), Some(sha.as_str()));
    }

    #[test]
    fn size_limits_are_enforced() {
        let fs = from_bytes(image()).unwrap();
        let (_, inode) = fs.lookup("d/b").unwrap();
        let g = scratch("limit");
        let mut f = std::fs::File::create(g.join("x")).unwrap();
        let mut budget = 10_000;
        fs.copy_data(&inode, &mut f, &mut budget).unwrap();
        assert_eq!(budget, 1000);
        let e = format!(
            "{:#}",
            fs.copy_data(&inode, &mut f, &mut budget).unwrap_err()
        );
        assert!(e.contains("add up to more than"), "{e}");
        let mut big = inode.clone();
        big.size = MAX_FILE_BYTES + 1;
        let e = format!("{:#}", fs.read_chunks(&big, |_, _| Ok(())).unwrap_err());
        assert!(e.contains("-byte limit"), "{e}");
        let mut bigdir = e_root(&fs);
        bigdir.size = MAX_DIR_BYTES + 1;
        assert!(
            format!("{:#}", fs.read_dir(&bigdir, MAX_ENTRIES).unwrap_err())
                .contains("directory of")
        );
        let mut longlink = fs.lookup("s").unwrap().1;
        longlink.size = MAX_SYMLINK + 1;
        let e = format!(
            "{:#}",
            fs.entry_of("s".into(), &longlink, Kind::Symlink)
                .unwrap_err()
        );
        assert!(e.contains("is not valid"), "{e}");
    }

    fn e_root(fs: &Fs) -> Inode {
        fs.fs.root_inode().unwrap()
    }

    #[test]
    fn refuses_bad_images_clearly() {
        let good = image();
        let mut bad = good.clone();
        bad[1024] ^= 0xFF; // magic
        let e = format!("{:#}", from_bytes(bad).err().unwrap());
        assert!(e.contains("not a readable erofs image"), "{e}");
        assert!(from_bytes(Vec::new()).is_err());
        assert!(from_bytes(good[..1100].to_vec()).is_err());
        assert!(Fs::open(Path::new("/definitely/not/here")).is_err());
        let d = scratch("open");
        assert!(format!("{:#}", Fs::open(&d).err().unwrap()).contains("directory"));
    }

    #[test]
    fn a_directory_loop_is_refused() {
        // make the root's entry "d" point back at the root: find the 12-byte dirent of "d" (its
        // nid, a name offset, file type 2) and try each candidate until the walk reports the loop
        let good = image();
        let fs = from_bytes(good.clone()).unwrap();
        let root = fs.fs.root_inode().unwrap();
        let d_nid = fs
            .fs
            .read_dir(&root)
            .unwrap()
            .into_iter()
            .find(|d| d.name == b"d")
            .unwrap()
            .nid;
        let mut loops = 0;
        for at in 0..good.len() - 12 {
            if u64::from_le_bytes(good[at..at + 8].try_into().unwrap()) != d_nid
                || good[at + 10] != 2
            {
                continue;
            }
            let mut img = good.clone();
            img[at..at + 8].copy_from_slice(&root.nid.to_le_bytes());
            if let Ok(f) = from_bytes(img)
                && let Err(e) = f.walk()
                && format!("{e:#}").contains("loop")
            {
                loops += 1;
            }
        }
        assert_eq!(
            loops, 1,
            "exactly one placement is the real directory entry"
        );
    }

    #[test]
    fn corrupting_metadata_bytes_never_panics() {
        let good = image();
        let (mut ok, mut err) = (0, 0);
        for at in (0..good.len().min(8192)).step_by(1) {
            for v in [0x00u8, 0xFF] {
                if good[at] == v {
                    continue;
                }
                let mut img = good.clone();
                img[at] = v;
                let r = from_bytes(img).and_then(|f| {
                    for (e, i) in f.walk()? {
                        if e.kind == Kind::File {
                            f.read_chunks(&i, |_, _| Ok(()))?;
                        }
                    }
                    Ok(())
                });
                match r {
                    Ok(()) => ok += 1,
                    Err(_) => err += 1,
                }
            }
        }
        assert!(ok > 100 && err > 100, "ok={ok} err={err}");
    }
}
