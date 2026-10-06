# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

## [Unreleased]

### Added

- `vbmeta <partition> --vbmeta <top-level>` judges a partition footer against the signed top-level vbmeta: `avb-footer-covered` (info) only when the top-level signature verifies and its hash descriptor matches the partition's bytes (or, for a chain descriptor, the partition is signed with the chained key); otherwise `avb-footer-not-covered` (high). Hashtree descriptors are named but not recomputed. The partition name comes from its own descriptor, else the file name without `.img` and an `_a`/`_b` slot (#123).
- f2fs read support (#128): a clean-room, read-only reader written from the public on-disk format, so `ls`, `cat`, `files`, `audit` and `extract --files` work on f2fs images (userdata, and system/vendor/product on devices that use it) the way they do on ext4 and erofs, with SELinux labels, file capabilities, modes, owners, hard links and symlinks. It reads the newest valid checkpoint (CRC checked), the NAT and its journal, inline data and inline directories, direct, indirect and double-indirect block maps, dentry blocks and extended attributes, with the same hostile-input limits as the other readers. Refused with a clear error: compressed files, encrypted files and directories, zoned, multi-device and device-alias volumes, large NAT bitmaps and unknown feature bits. `tests/f2fs.rs` builds real volumes with `mkfs.f2fs` and `sload.f2fs` and a required `f2fs` CI job runs it. This replaces the "f2fs is not supported" error (#69, #36).
- OEM full-firmware containers (clean-room, validated against spec-built synthetic fixtures only, not real firmware): `extract` unwraps Huawei `UPDATE.APP` (#130), LG `.kdz`/`.dz` (#131) and Sony `.sin` (#132, header auth blocks skipped and reported as unverified) into partition images, expanding sparse payloads. `identify` names `huawei-update-app`, `lg-kdz`, `lg-dz`, `sony-sin`, and also `coolpad-cpb` and `nokia-nb0`, which `extract` refuses as "recognized but unsupported" (#133, #134 stay open).
- `extract` auto-expands a sparse partition image (`system.img`/`vendor.img`/... as flashed) to the real filesystem image, instead of copying the sparse blob; `identify` now names device-tree blobs (`fdt`). A coverage test asserts that every standard Android partition image (boot/recovery/vendor_boot/init_boot, dtbo, FDT, `@AML`, super, vbmeta, ext4/erofs filesystems, sparse) is identified and extracted with no abort, from both a directory and a zip (#127).
- Composite GitHub Action (`action.yml`, logic in `scripts/android-doctor-action.sh`): installs the pinned release binary (Linux x86_64, macOS arm64/x86_64; `version` defaults to the action's own `@vX.Y.Z` ref, never `latest`; `binary` skips the download), runs `doctor scan` or `audit` with `--sarif` and `--json`, writes a step summary, uploads SARIF (skipped with a notice on forks or without `security-events: write`), gates on `fail-on` (or only on new findings with `baseline`, exit 3) and outputs `score`, `status` and `sarif`. `.github/workflows/action-selftest.yml` runs it against the generated corpus fixtures using a binary built from the checkout. The pinned ref resolves once the release containing `action.yml` is tagged (#106).
- `ci install [--dir DIR] [--print] [--force] [--path FIRMWARE_DIR] [--fail-on LEVEL]` writes `.github/workflows/android-doctor.yml`, which runs the action on pull requests and `workflow_dispatch`, pinned to this binary's version. It refuses to overwrite without `--force` (exit 1) and never writes through a symlink (#108).
- `--score` on `audit` and `doctor scan` prints a deterministic 0-100 health score (severity-weighted per rule, capped, never negative; 100 only when nothing was found and every rule ran). On a terminal both commands print a grouped, worst-first digest with a `Next steps:` line; piped output is unchanged. `audit --json` gains `score` (#111).
- `--baseline <FILE>` on `audit` and `doctor scan`: report only findings whose fingerprint is not in a previous `--json` report, count what was suppressed, and exit `3` when something new above `info` appeared. Coverage gaps are never suppressed; a missing, unreadable or foreign baseline is an error. `audit --json` gains a top-level `findings` array (#110).
- `--sarif <FILE>` on `audit` and `doctor scan` writes SARIF 2.1.0 (one rule per rule id with the remedy as help, levels from severity, locations inside the image, `partialFingerprints`, the health score under `runs[0].properties.score`) (#105).
- A shared findings layer for `audit` and `doctor scan`: one severity scale (`error > high > medium > warn > info`) and a stable fingerprint per finding. `doctor scan --json` rows gain an additive `fingerprint` (and `image` inside an image) field.
- Corpus/precision gate (#109): `tests/corpus.rs` generates deterministic ext4 and erofs fixtures from text source trees, asserts exact `audit` and `doctor scan` findings against committed snapshots, and checks two builds are byte-identical; a required `corpus` CI job and `docs/precision.md`.
- `fix [--agent claude|codex|cursor] [--print] [--yolo] <dir>`: runs the doctor scan and renders one prompt for a coding agent (findings worst first, firmware text fenced as untrusted, a clause forbidding suppressing findings, and the `doctor scan <dir> --json` re-run command). Launches the agent only if its binary is on PATH, with its approval prompts kept unless `--yolo`; never launches inside an agent (`CLAUDECODE`, `CODEX_THREAD_ID`, `CODEX_SANDBOX`, `CURSOR_SANDBOX`, `ANDROID_DOCTOR_AGENT=1`). A clean scan prints "nothing to fix" and exits 0 (#107).
- Tag-triggered publishing: the release workflow checks that the tag, `Cargo.toml` and `npm/package.json` agree, then publishes GitHub release binaries, the crate to crates.io (`CARGO_REGISTRY_TOKEN`) and the launcher to npm with provenance (`NPM_TOKEN`); each registry step is skipped with a notice when its secret is unset.
- `npx android-doctor` downloads and caches the matching release binary on first run (falls back to a binary on `PATH`).
- Illustrated logo (layered partition stack under a magnifier) and a standalone `docs/assets/mark.svg`.
- Crate metadata and package excludes so `cargo publish` passes.
- `doctor install --agent cursor` also writes `.cursor/rules/android-doctor.mdc`, and `--agent codex` / `--agent opencode` add a managed block to `AGENTS.md`; `--agent claude` is accepted for `claude-code`.
- README rewrite, `AGENTS.md`, logo assets and an npm launcher (`npx android-doctor`).

### Fixed

- `extract` no longer stops at one image it cannot unpack (a corrupt super image, a sparse image that will not expand, a broken tar or ozip): the image is copied raw, listed as unhandled with the reason, and the images after it are still written. The run still fails on it unless `--allow-partial`, so nothing is skipped silently. A failed integrity check (a `.tar.md5` whose MD5 does not match) stays fatal even with `--allow-partial` (#116, #123).
- f2fs images are recognised by the real superblock magic, `0xF2F52010` at byte 1024. Detection used `0xF2F52011` at `0x170`, which is neither the superblock magic nor an offset inside the superblock, so no real f2fs image was ever identified as f2fs.
- `extract` no longer aborts on a gzip-wrapped image that is not a tar (a gzip `dt.img` holding an Amlogic `AML_` container failed with "numeric field was not a number ... cksum for AML_" and left every later image unwritten). A compressed file now counts as a tar only if its decompressed first block is a tar header; otherwise it is copied unchanged. `dt` and `amlogic` read through a gzip wrapper (#114, #118).
- `extract` unpacks `*.tar.gz`, `*.tgz`, `*.tar.xz`, `*.txz`, `*.tar.bz2`, `*.tbz2`, `*.tar.zst` and `*.tar.lz4` entries instead of rejecting the name as unsafe (#117).
- Super (LP) images are read: the geometry is 52 bytes (not 64) and its checksum covers `struct_size` bytes, the primary metadata is at 12288, the header's table descriptors are at 80/92/104/116, and extent and block-device entries are 24 and 64 bytes. Every real super image used to fail with "LP geometry struct_size 52 is too small", exit 1, and skip the images after it (#118).
- `vbmeta` verifies RSA signatures: the AVB public key blob has an 8-byte header (`key_num_bits`, `n0inv`) before the modulus, and the verifier read the modulus from byte 4, so every real signature reported FAILED (#118).
- `vbmeta` no longer reports `[high]` for an unsigned per-partition footer (now `avb-unsigned-footer`, `[info]`, since a signed top-level vbmeta normally carries the signature) or for rollback index 0 (the default). An unsigned top-level vbmeta, and an unsigned footer on a chained partition, stay `[high]` (#118).

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
