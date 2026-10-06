# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

## [Unreleased]

### Added

- Corpus/precision gate (#109): `tests/corpus.rs` generates deterministic ext4 and erofs fixtures from text source trees, asserts exact `audit` and `doctor scan` findings against committed snapshots, and checks two builds are byte-identical; a required `corpus` CI job and `docs/precision.md`.
- Tag-triggered publishing: the release workflow checks that the tag, `Cargo.toml` and `npm/package.json` agree, then publishes GitHub release binaries, the crate to crates.io (`CARGO_REGISTRY_TOKEN`) and the launcher to npm with provenance (`NPM_TOKEN`); each registry step is skipped with a notice when its secret is unset.
- `npx android-doctor` downloads and caches the matching release binary on first run (falls back to a binary on `PATH`).
- Illustrated logo (layered partition stack under a magnifier) and a standalone `docs/assets/mark.svg`.
- Crate metadata and package excludes so `cargo publish` passes.
- `doctor install --agent cursor` also writes `.cursor/rules/android-doctor.mdc`, and `--agent codex` / `--agent opencode` add a managed block to `AGENTS.md`; `--agent claude` is accepted for `claude-code`.
- README rewrite, `AGENTS.md`, logo assets and an npm launcher (`npx android-doctor`).

## [0.1.0]

First tagged release.

### Added

- Extraction: A/B `payload.bin` (full OTAs, verified against payload-dumper-go) (#52), block OTAs with brotli streaming and parallel per-partition progress (#8, #9, #10, #14, #15), `--only`, `--list` and `--force` (#44-#46), tar and Samsung `.tar.md5` (#72, #73), Spreadtrum PAC (#70), Oppo/Realme `.ozip` (#94), `super.img` dynamic partitions (#71), and incremental OTAs over a base build with `--base` (#102).
- Inspection: `identify` by magic bytes (#50), `info` and `report` staleness verdict (#11, #16), `unpack` for boot and vendor_boot (#53), `ramdisk` (#54), `unsparse` (#51), `dt` (#95), Qualcomm/MediaTek flash manifests (#93), Amlogic `@AML` containers (#101), `hash-tree` regeneration of dm-verity trees (#104).
- File systems: `files`, `ls`, `cat` and `extract --files` for ext2/3/4 (#55, #62) and erofs (#63), with SELinux labels; f2fs detected with a clear not-supported error (#69).
- AVB: `vbmeta` inspection and authentication digest (#61), RSA signature verification (#86), boot-chain state interpretation (#89).
- Security: `audit` for ADB properties, setuid files, `su` binaries and init services (#65), APK package names and signing certificates (#92), hardcoded credentials (#91).
- `doctor scan`: deterministic health scan with security and quality rules (#90, #97).
- Agent integration: skill installer for claude-code, cursor, codex and opencode, and an MCP server exposing identify, doctor and audit (#103).
- `--json` output across commands, consistent terminal rendering and `--verbose` (#87).
- Tagged release workflow with prebuilt binaries and `cargo install` instructions (#96).
- Hostile-input sweep over every subcommand (#99); about 450 tests.
- Format support matrix and third-party notices (#49).
