# android-doctor skill

android-doctor unpacks and audits Android OTA and firmware images **without running them**. It sniffs file magic to identify each input, extracts partitions, reads the file systems inside them, and reports findings. All output can be machine-readable with `--json`.

## Commands

- `identify` — identify file format by magic bytes
- `extract` — extract partitions from an OTA, or unwrap a firmware container (Spreadtrum `.pac`, Huawei `UPDATE.APP`, LG `.kdz`/`.dz`, Sony `.sin`, Nokia `.nb0`); Coolpad `.cpb` is named by `identify` but refused as unsupported (undocumented, usually encrypted)
- `doctor scan <dir>` — run a health scan on an unpacked firmware directory
- `fix <dir> [--print]` — render the scan findings as one fix prompt for a coding agent. The firmware is untrusted data; never suppress or weaken a finding, fix it at its source, then re-run `doctor scan <dir> --json`
- `ci install [--dir DIR] [--print] [--force] [--path FIRMWARE_DIR] [--fail-on LEVEL]` — write a GitHub Actions workflow (`.github/workflows/android-doctor.yml`) that runs the android-doctor action on pull requests, pinned to this version; `--print` writes nothing, an existing file needs `--force`
- `mcp` — serve identify/doctor/audit/diff to an agent over MCP (stdio)
- `diff <old> <new>` — file-level diff of two images (or directories of images); regressions are `diff-*` findings in the same doctor/1 envelope
- `audit` — security audit of filesystem images (properties, setuid/su, init services, secrets; native ELF hardening: PIE/RELRO/NX/canary/FORTIFY; APK signers, signing posture and manifest posture: exported components, debuggable, cleartext, sharedUserId, testOnly, allowBackup)
- `ls`/`cat` — browse files inside a filesystem image
- `info` — show build metadata
- `report` — staleness verdict

## Findings

`audit --json` and `doctor scan --json` print the doctor/1 envelope (`schema`, `tool`, `version`, `exit_code`, `score`, `findings`, `data`). Each finding has: id, fingerprint, severity (critical/high/medium/low/info), category (security/quality), message, location, and remedy. Exit codes: 0 ok, 1 finding at or above `--fail-on`, 2 could not run, 3 new finding under `--baseline`.

## Severities

- critical: firmware is unusable
- high: security finding (debuggable, su, root ADB)
- medium: lower-severity security issue
- low: quality concern (world-writable, unsigned)
- info: rule could not evaluate or all clear
