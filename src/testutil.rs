//! Helpers shared by the test suites.
use std::path::PathBuf;

/// A temporary directory that is deleted when the value is dropped, so a
/// failed or panicking test cannot leak it (earlier helpers returned a bare
/// `PathBuf` and every test run left its directories behind).
pub struct Scratch(PathBuf);

impl Scratch {
    pub fn new(tag: &str) -> Self {
        let dir = std::env::temp_dir().join(format!("ad-test-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        Self(dir)
    }
}

impl std::ops::Deref for Scratch {
    type Target = PathBuf;
    fn deref(&self) -> &PathBuf {
        &self.0
    }
}

impl AsRef<std::path::Path> for Scratch {
    fn as_ref(&self) -> &std::path::Path {
        &self.0
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_directory_is_removed_on_drop() {
        let p;
        {
            let s = Scratch::new("selfcheck");
            p = s.join("x");
            std::fs::write(&p, b"x").unwrap();
            assert!(p.exists());
        }
        assert!(!p.exists(), "the file goes with the directory");
        assert!(
            !p.parent().unwrap().exists(),
            "the directory itself is gone"
        );
    }
}
