//! Shared by every command that extracts a file tree: safe output paths, a staging directory
//! that is renamed into place only when everything succeeded, and the rules that stop an archive
//! or filesystem image from writing outside the output directory.
//!
//! Symlinks, devices, fifos and sockets are never created; callers record them in a manifest.
use anyhow::{Context, Result, bail, ensure};
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::fs::File;
use std::io::Read;
use std::path::{Component, Path, PathBuf};

/// A path from an archive, made safe: no leading `./`, no absolute paths, no `..`.
pub fn clean_path(raw: &str) -> Result<String> {
    ensure!(
        !raw.is_empty() && !raw.contains('\0'),
        "empty or NUL-containing path"
    );
    let mut parts = Vec::new();
    for comp in Path::new(raw).components() {
        match comp {
            Component::Normal(p) => parts.push(p.to_string_lossy().into_owned()),
            Component::CurDir => {}
            Component::RootDir | Component::Prefix(_) => bail!("absolute path {raw:?}"),
            Component::ParentDir => bail!("path {raw:?} climbs out of the archive"),
        }
    }
    Ok(parts.join("/"))
}

/// A long path, shortened for an error message.
pub(crate) fn short(p: &str) -> String {
    let n = p.chars().count();
    if n <= 120 {
        return p.to_string();
    }
    let head: String = p.chars().take(60).collect();
    let tail: String = p.chars().skip(n - 40).collect();
    format!("{head}...{tail}")
}

/// Where extracted files go, and the state needed to do it safely.
/// What to do when two source paths differ only by letter case.
#[derive(Debug, Clone, Copy, PartialEq)]
pub(crate) enum Collisions {
    /// Refuse: the source is not expected to have such names (archives).
    Reject,
    /// Keep the first name and extract each later one as `name~case2`, `name~case3`, ... (a
    /// case-insensitive host cannot hold both).
    Rename,
    /// Keep every name as it is (a case-sensitive host).
    Allow,
}

/// Decide the policy for `dir` by asking the file system there whether `Aa` and `aA` are the
/// same name. Any doubt means `Rename`.
pub(crate) fn host_collisions(dir: &Path) -> Collisions {
    let upper = dir.join(".adprobe-Aa");
    let lower = dir.join(".adprobe-aA");
    let _ = std::fs::remove_file(&upper);
    let result = match File::create(&upper) {
        Ok(_) => {
            if lower.symlink_metadata().is_ok() {
                Collisions::Rename
            } else {
                Collisions::Allow
            }
        }
        Err(_) => Collisions::Rename,
    };
    let _ = std::fs::remove_file(&upper);
    result
}

pub(crate) struct Sink {
    root: PathBuf,
    collisions: Collisions,
    /// source path -> the path actually used under `root` (differs only after a rename)
    actual: HashMap<String, String>,
    /// path -> is_dir, for every path created
    created: BTreeMap<String, bool>,
    /// paths the archive makes symlinks: recorded, never created
    symlinks: BTreeSet<String>,
    lowered: BTreeSet<String>,
}

impl Sink {
    pub(crate) fn new(root: &Path) -> Self {
        Sink {
            root: root.to_path_buf(),
            created: BTreeMap::new(),
            symlinks: BTreeSet::new(),
            lowered: BTreeSet::new(),
            collisions: Collisions::Reject,
            actual: HashMap::new(),
        }
    }

    pub(crate) fn with_collisions(root: &Path, collisions: Collisions) -> Self {
        Sink {
            collisions,
            ..Sink::new(root)
        }
    }

    /// The path (relative to the root) a source path was extracted as.
    pub(crate) fn actual_path(&self, path: &str) -> String {
        self.actual
            .get(path)
            .cloned()
            .unwrap_or_else(|| path.to_string())
    }

    /// Record that `path` is a symlink in the source: it is never created, and nothing may be
    /// written below it or under the same name.
    pub(crate) fn note_symlink(&mut self, path: &str) -> Result<()> {
        self.make_parents(path)?;
        ensure!(
            !self.created.contains_key(path),
            "{path} is listed as both a file or directory and a symlink"
        );
        self.symlinks.insert(path.to_string());
        Ok(())
    }

    /// Create `to` as a hard link of the already written `from`, falling back to a copy.
    pub(crate) fn hard_link(&mut self, from: &str, to: &str) -> Result<()> {
        self.make_parents(to)?;
        let again = !self.claim(to, false)?;
        let t = self.target(to);
        if again {
            std::fs::remove_file(&t).ok();
        }
        let source = self.target(from);
        if std::fs::hard_link(&source, &t).is_err() {
            std::fs::copy(&source, &t).with_context(|| format!("linking {}", short(to)))?;
        }
        Ok(())
    }

    pub(crate) fn target(&self, path: &str) -> PathBuf {
        self.root.join(self.actual_path(path))
    }

    /// Make every parent directory of `path`, refusing to pass through anything that is a file.
    pub(crate) fn make_parents(&mut self, path: &str) -> Result<()> {
        let mut at = String::new();
        let parts: Vec<&str> = path.split('/').collect();
        for part in &parts[..parts.len() - 1] {
            if !at.is_empty() {
                at.push('/');
            }
            at.push_str(part);
            ensure!(
                !self.symlinks.contains(&at),
                "{path} goes through the symlink {at}, which is recorded but never created"
            );
            match self.created.get(&at) {
                Some(true) => {}
                Some(false) => bail!("{at} is a file but {path} needs it to be a directory"),
                None => self.add_dir(&at.clone())?,
            }
        }
        Ok(())
    }

    pub(crate) fn claim(&mut self, path: &str, is_dir: bool) -> Result<bool> {
        ensure!(
            !self.symlinks.contains(path),
            "{path} is listed as both a symlink and something else"
        );
        match self.created.get(path) {
            Some(&was_dir) if was_dir == is_dir => return Ok(false), // listed again
            Some(_) => bail!("{path} is listed as both a file and a directory"),
            None => {}
        }
        let (parent, name) = match path.rsplit_once('/') {
            Some((p, n)) => (self.actual_path(p), n),
            None => (String::new(), path),
        };
        let join = |n: &str| {
            if parent.is_empty() {
                n.to_string()
            } else {
                format!("{parent}/{n}")
            }
        };
        let mut chosen = join(name);
        match self.collisions {
            Collisions::Reject => ensure!(
                self.lowered.insert(chosen.to_lowercase()),
                "{path} differs only by case from another path and would overwrite it"
            ),
            Collisions::Allow => {}
            Collisions::Rename => {
                let mut n = 2;
                while !self.lowered.insert(chosen.to_lowercase()) {
                    chosen = join(&format!("{name}~case{n}"));
                    n += 1;
                }
            }
        }
        if chosen != path {
            self.actual.insert(path.to_string(), chosen);
        }
        self.created.insert(path.to_string(), is_dir);
        Ok(true)
    }

    pub(crate) fn add_dir(&mut self, path: &str) -> Result<()> {
        if self.claim(path, true)? {
            let t = self.target(path);
            std::fs::create_dir(&t)
                .with_context(|| format!("creating {}", short(&t.display().to_string())))?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                std::fs::set_permissions(&t, std::fs::Permissions::from_mode(0o755))?;
            }
        }
        Ok(())
    }

    pub(crate) fn write_file(&mut self, path: &str, mode: u32, data: &mut dyn Read) -> Result<()> {
        self.write_with(path, mode, |f| {
            std::io::copy(data, f)?;
            Ok(())
        })
    }

    /// Create the file and let `fill` write it (it may seek and `set_len`, so holes stay holes).
    pub(crate) fn write_with(
        &mut self,
        path: &str,
        mode: u32,
        fill: impl FnOnce(&mut File) -> Result<()>,
    ) -> Result<()> {
        self.make_parents(path)?;
        let again = !self.claim(path, false)?;
        let t = self.target(path);
        if again {
            std::fs::remove_file(&t).ok();
        }
        let mut f = File::options()
            .write(true)
            .create_new(true)
            .open(&t)
            .with_context(|| format!("creating {}", short(&t.display().to_string())))?;
        fill(&mut f)?;
        self.set_mode(&t, mode)
    }

    /// Create `to` as a copy of the already written `from` (a hardlink: same content, own mode).
    pub(crate) fn copy_file(&mut self, from: &str, to: &str, mode: u32) -> Result<()> {
        self.make_parents(to)?;
        let again = !self.claim(to, false)?;
        let t = self.target(to);
        if again {
            std::fs::remove_file(&t).ok();
        }
        std::fs::copy(self.target(from), &t).with_context(|| format!("linking {}", short(to)))?;
        self.set_mode(&t, mode)
    }

    /// Create an empty file (a hardlink name whose group never carried any data).
    pub(crate) fn empty_file(&mut self, path: &str, mode: u32) -> Result<()> {
        self.make_parents(path)?;
        self.claim(path, false)?;
        let t = self.target(path);
        File::options()
            .write(true)
            .create_new(true)
            .open(&t)
            .with_context(|| format!("creating {}", short(&t.display().to_string())))?;
        self.set_mode(&t, mode)
    }

    /// Permission bits only: setuid, setgid and sticky are dropped (the manifest keeps them).
    pub(crate) fn set_mode(&self, path: &Path, mode: u32) -> Result<()> {
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode & 0o777))?;
        }
        let _ = (path, mode);
        Ok(())
    }
}

pub(crate) fn staging_path(out: &Path) -> PathBuf {
    let mut s = out.as_os_str().to_owned();
    s.push(".part");
    PathBuf::from(s)
}

/// The output directory must not exist (or be empty); work happens in `<out>.part`.
pub(crate) fn prepare_staging(out: &Path) -> Result<PathBuf> {
    if let Ok(meta) = out.symlink_metadata() {
        ensure!(
            meta.is_dir(),
            "{} exists and is not a directory",
            out.display()
        );
        ensure!(
            std::fs::read_dir(out)?.next().is_none(),
            "{} already exists and is not empty",
            out.display()
        );
    }
    let staging = staging_path(out);
    if let Ok(meta) = staging.symlink_metadata() {
        if meta.is_dir() {
            std::fs::remove_dir_all(&staging)?;
        } else {
            std::fs::remove_file(&staging)?;
        }
    }
    if let Some(parent) = out.parent().filter(|p| !p.as_os_str().is_empty()) {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::create_dir(&staging).with_context(|| format!("creating {}", staging.display()))?;
    Ok(staging)
}

pub(crate) fn publish(staging: &Path, out: &Path) -> Result<()> {
    if out.symlink_metadata().is_ok() {
        std::fs::remove_dir(out)?; // only an empty directory gets here
    }
    std::fs::rename(staging, out).with_context(|| format!("publishing {}", out.display()))
}
