//! The agent skill: what android-doctor is, what each finding means, how to drive it.
//!
//! Written into an agent config directory so a coding agent can interpret output without
//! having to read the source.

use anyhow::{Context, Result};
use std::path::PathBuf;

/// Agents we know how to install a skill for, with their config directory.
#[derive(Debug, Clone, Copy)]
pub enum Agent {
    ClaudeCode,
    Cursor,
    Codex,
    Opencode,
}

impl Agent {
    pub fn all() -> [Agent; 4] {
        [
            Agent::ClaudeCode,
            Agent::Cursor,
            Agent::Codex,
            Agent::Opencode,
        ]
    }

    pub fn name(self) -> &'static str {
        match self {
            Agent::ClaudeCode => "claude-code",
            Agent::Cursor => "cursor",
            Agent::Codex => "codex",
            Agent::Opencode => "opencode",
        }
    }

    /// Where this agent looks for a local skill, relative to $HOME.
    pub fn skill_dir(self) -> PathBuf {
        let home = std::env::var_os("HOME")
            .map(PathBuf::from)
            .unwrap_or_default();
        match self {
            Agent::ClaudeCode => home.join(".claude/skills"),
            Agent::Cursor => home.join(".cursor/skills"),
            Agent::Codex => home.join(".codex/skills"),
            Agent::Opencode => home.join(".config/opencode/skills"),
        }
    }

    /// Skill directory name. Keep it stable so re-install overwrites rather than duplicating.
    pub fn skill_name(self) -> &'static str {
        "android-doctor"
    }
}

/// Frontmatter that agents parse to register the skill.
const FRONTMATTER: &str = "---
id: android-doctor
name: android-doctor
description: Static analysis for Android OTA firmware images.
version: 0.1.0
---
";

/// The skill body, written after the frontmatter.
const SKILL_BODY: &str = include_str!("skill_body.md");

/// Write the skill file for `agent` into its config directory and return the file path.
///
/// Idempotent: re-running produces the same file.  Creates the skills directory if it
/// does not exist.  If a file already exists at the destination that is not the skill
/// file (i.e. a different agent's file), this function does not touch it.
/// Write the skill into `dir`, under the agent's own subdirectory.
pub fn install_in(agent: Agent, dir: &std::path::Path) -> Result<PathBuf> {
    std::fs::create_dir_all(dir).with_context(|| format!("creating {}", dir.display()))?;
    let dest = dir.join(format!("{}.md", agent.skill_name()));
    std::fs::write(&dest, skill_content())
        .with_context(|| format!("writing {}", dest.display()))?;
    Ok(dest)
}

/// The skill body on its own, for `--print`.
pub fn content() -> String {
    SKILL_BODY.to_string()
}

/// The full skill file: frontmatter, then the body.
fn skill_content() -> String {
    format!("{}{}", FRONTMATTER, SKILL_BODY)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::Scratch;

    /// Install into a scratch dir. The `Scratch` is returned too: it deletes its directory on
    /// drop, so letting it die here would remove the file before the test could look at it.
    fn install_in_scratch(agent: Agent) -> (Scratch, PathBuf) {
        let scratch = Scratch::new(&format!("skill-{}", agent.name()));
        let path = install_in(agent, scratch.as_ref()).unwrap();
        (scratch, path)
    }

    #[test]
    fn install_creates_the_file_and_dir() {
        let (_s, path) = install_in_scratch(Agent::ClaudeCode);
        assert!(
            path.is_file(),
            "skill file should exist at {}",
            path.display()
        );
        assert!(path.parent().unwrap().is_dir());
    }

    #[test]
    fn install_writes_frontmatter() {
        let (_s, path) = install_in_scratch(Agent::Cursor);
        let content = std::fs::read_to_string(&path).unwrap();
        assert!(content.starts_with("---\n"), "frontmatter starts with ---");
        assert!(content.contains("id: android-doctor"), "frontmatter has id");
        assert!(
            content.contains("name: android-doctor"),
            "frontmatter has name"
        );
    }

    #[test]
    fn install_is_idempotent() {
        let (_s, path) = install_in_scratch(Agent::Codex);
        let first = std::fs::read_to_string(&path).unwrap();
        let path2 = install_in(Agent::Codex, path.parent().unwrap()).unwrap();
        assert_eq!(path, path2);
        let second = std::fs::read_to_string(&path2).unwrap();
        assert_eq!(first, second);
    }

    #[test]
    fn install_all_agents_writes_valid_files() {
        for agent in Agent::all() {
            let (_s, path) = install_in_scratch(agent);
            let content = std::fs::read_to_string(&path).unwrap();
            assert!(
                content.contains("id: android-doctor"),
                "{} skill file is valid",
                agent.name()
            );
        }
    }
}
