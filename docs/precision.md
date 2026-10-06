# Corpus and precision gate

`tests/corpus.rs` stops a rule change from silently losing or adding a finding. It builds small
firmware images from known source trees, runs the built `android-doctor` on them, and compares
the findings with committed snapshots. Any difference fails the test.

This is a precision gate on synthetic fixtures. It measures nothing about real firmware.

## What it asserts

For every case under `tests/corpus/trees/`:

1. **Findings match.** `audit --json` and `doctor scan --json` are run on the generated
   directory. The rows `(id, severity, subject)` of each, sorted, must equal
   `tests/corpus/expected/<case>.json`. For `audit` the id is the finding `rule` and the subject
   is the image name. Only those three keys are compared, so extra JSON fields never break the
   gate. A lost row means the tool stopped saying something. An added row means it started.
2. **Clean is quiet.** The `clean` case must give an empty `audit`, and a `doctor scan` with
   nothing above `info` (the images carry no SELinux labels and there is no `vbmeta.img`, so the
   "cannot evaluate" infos stay, on purpose).
3. **Builds are deterministic.** Every image is built twice and the sha256 sums must match.

## How fixtures are generated

Nothing binary is committed. Each case is a directory of plain text:

- `NAME.ext4/` becomes `NAME.img` via `mke2fs -d`; `NAME.erofs/` becomes `NAME.img` via
  `mkfs.erofs`. The directory's own contents are the filesystem root.
- Any other file or directory (`notes.txt`, `system.transfer.list`, a deliberately corrupt
  `system.img`) is copied to the output directory as it is.
- `modes.txt` (optional): lines of `<octal mode> <path relative to the case>`. Git does not
  keep modes, so setuid, world-writable and executable bits are applied by the runner.
  Everything else is 0644 / 0755.

Pinned for determinism: sorted copy, all mtimes set to the epoch, `mke2fs` with a fixed UUID,
label, `hash_seed`, `root_owner=0:0`, a pinned `mke2fs.conf`, `E2FSPROGS_FAKE_TIME=0` and
`SOURCE_DATE_EPOCH=0`; `mkfs.erofs` with a fixed UUID, `-T0 --mkfs-time` and `--all-root`.
File owners in ext4 images are the uid of whoever runs the test, so images are identical on one
machine, not necessarily across machines. Findings do not depend on it.

## Cases

| Case | Fires |
| --- | --- |
| `clean` | nothing from `audit`; `doctor`: info only |
| `debug-props` | `debuggable-build`, `insecure-adb`, `adb-unauthenticated`, `adb-root`, `test-keys`, `debug-build-type`, `adb-by-default` |
| `perms` (erofs) | `su-binary`, `writable-setuid`, `setuid-files`, `world-writable`, `mode_anomalies` |
| `init-services` | `adbd-service`, `shell-service`, `su-service`, `init_service_hygiene` |
| `secret-key` / `secret-cloud` / `secret-debug` | `hardcoded_credentials` / `cloud_credentials` / `debug_endpoints` |
| `leftovers` | `debug_leftovers`, `duplicate_properties`, `unhandled_input` |
| `ota-blocks` | the "cannot evaluate" infos for every quality rule (OTA with no images) |
| `corrupt-image` | the same infos, from an unreadable image |

Every `doctor` case also shows `partition_coverage`, `selinux_label_gaps` and `avb_signature`
where they apply. Not covered: `file-capabilities` (needs `security.capability` xattrs, which an
unprivileged `mke2fs -d` cannot set) and `avb_signature` with a real `vbmeta.img`.

## Adding a case

1. Make `tests/corpus/trees/<case>/` with `NAME.ext4/...` or `NAME.erofs/...` (and `modes.txt`
   if you need modes).
2. `UPDATE_CORPUS=1 cargo test --test corpus` writes `tests/corpus/expected/<case>.json`.
3. Read the snapshot. Check it says what the case is meant to say, then commit it with the tree.

## Updating snapshots

After an intended rule change run `UPDATE_CORPUS=1 cargo test --test corpus` and review
`git diff tests/corpus/expected`. Every changed line is a finding that was lost or gained; the PR
should say why.

## Reading a failure

```
corpus drift (...):
perms:
  - LOST   audit: su-binary  high  system
  + ADDED  doctor: mode_anomalies  warn  system/bin/ping
```

`LOST` is a finding in the snapshot that the tool no longer reports (a regression, or a
deliberate removal). `ADDED` is a new finding (a new rule, or a false positive). If a `clean`
failure appears, the new rule fires on healthy firmware: fix the rule, not the snapshot.

## Running it

Needs `mke2fs` (e2fsprogs) and `mkfs.erofs` (erofs-utils). Set `MKE2FS` / `MKFS_EROFS` to point
at them if they are off `PATH`. Without them the tests print `CORPUS GATE SKIPPED` and pass,
unless `CORPUS_REQUIRED=1` is set, where a missing tool fails. The `corpus` job in
`.github/workflows/ci.yml` sets it, installs both tools and checks the log to confirm the three
tests ran (the plain `check` job skips them).

```sh
cargo test --test corpus -- --nocapture
```
