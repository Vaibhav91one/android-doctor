<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="docs/assets/logo-dark.svg">
    <img src="docs/assets/logo-light.svg" alt="android-doctor" width="360">
  </picture>
</p>

<p align="center">
  <a href="https://github.com/Vaibhav91one/android-doctor/actions/workflows/ci.yml"><img src="https://github.com/Vaibhav91one/android-doctor/actions/workflows/ci.yml/badge.svg" alt="CI"></a>
  <img src="https://img.shields.io/badge/Rust-2024-000000?style=flat&color=000000&labelColor=000000" alt="Rust 2024">
  <img src="https://img.shields.io/badge/license-MIT-000000?style=flat&color=000000&labelColor=000000" alt="license MIT">
  <img src="https://img.shields.io/badge/telemetry-none-000000?style=flat&color=000000&labelColor=000000" alt="telemetry none">
</p>

Extracts and audits Android OTA and firmware images, without running them.

Firmware is a pile of containers inside containers: an OTA zip holds a
`payload.bin`, which holds partitions, which hold ext4 or erofs trees, which
hold init scripts and properties. `android-doctor` opens every layer, with no
root, no mount and no device, and answers one question: **is this build
shipping a debuggable, rooted or unsigned configuration?** Output is plain
text for people and `--json` for agents.

```sh
npx android-doctor extract ota.zip -o out/
android-doctor audit out/system.img
android-doctor doctor scan out/
```

## Contents

- [Get started](#get-started)
- [What it catches](#what-it-catches)
- [Agent integration](#agent-integration)
- [CLI reference](#cli-reference)
- [Format support](#format-support)
- [What it will not tell you](#what-it-will-not-tell-you)
- [Exit codes](#exit-codes)
- [Privacy and telemetry](#privacy-and-telemetry)
- [Build](#build)
- [Third-party code and references](#third-party-code-and-references)
- [License](#license)

## Get started

### 1. Install

Prebuilt release binaries for macOS (aarch64 and x86_64) and Linux (x86_64) are
attached to each [GitHub release](https://github.com/Vaibhav91one/android-doctor/releases).
Download the `android-doctor-<target>.tar.gz` for your platform, extract it, and
place the binary on your `PATH`:

```sh
tar xzf android-doctor-aarch64-apple-darwin.tar.gz
sudo mv android-doctor /usr/local/bin/
```

Or from source with Cargo:

```sh
cargo install --git https://github.com/Vaibhav91one/android-doctor android-doctor
```

`npx android-doctor ...` also works: the npm package in [`npm/`](npm/) is a
small launcher that runs the native binary on your `PATH` and passes on its
exit code.

### 2. Identify and extract

`identify` says what a file is by its magic bytes, never by its name:

```sh
android-doctor identify system.img
```

```
system.img: ext4 filesystem
```

`extract` reads an OTA zip, a directory or a bare `payload.bin` and writes the
partition images. See [What `extract` does](#what-extract-does).

### 3. Audit an image

`audit` reads the file system inside the image (ext2/3/4 or erofs) and reports
ADB properties, setuid files, `su` binaries and init services. This image was
built from a tree with a debuggable `build.prop` and a setuid `su`:

```sh
android-doctor audit system.img
```

```
ADB: ro.secure=0 ro.adb.secure=0 ro.debuggable=1 usb=not set: adbd can run as root

== system (5 entries)
[high] debuggable-build: ro.debuggable=1 in system/build.prop: adbd runs as root
[high] insecure-adb: ro.secure=0 in system/build.prop: adbd keeps root
[high] adb-unauthenticated: ro.adb.secure=0 in system/build.prop: ADB connections need no authorization
[high] su-binary: /system/xbin/su looks like a su binary
[info] setuid-files: 1 setuid/setgid files
properties:
  ro.debuggable=1  (system/build.prop)
  ro.secure=0  (system/build.prop)
  ro.adb.secure=0  (system/build.prop)
  ro.build.version.security_patch=2021-01-05  (system/build.prop)
setuid/setgid files:
  4755 501:0 /system/xbin/su
```

### 4. Health-scan a directory

`doctor scan` runs the deterministic rule set over an unpacked firmware
directory: security rules plus quality rules (missing partitions, duplicate
properties, SELinux label gaps, mode anomalies, service hygiene, debug
leftovers). Add `--json` for one object per finding with `id`, `category`,
`severity`, `subject`, `message` and `remedy`:

```sh
android-doctor doctor scan fw/
```

```
warn quality partition_coverage: system.img: expected partition image system is missing
    └ ensure system.img is present; the device may not boot without it
warn quality partition_coverage: vendor.img: expected partition image vendor is missing
    └ ensure vendor.img is present; the device may not boot without it
info security avb_signature: vbmeta.img: no vbmeta.img found; AVB signature not checked
    └ point doctor at a directory containing vbmeta.img
```

A rule that cannot evaluate says so (`info ... cannot evaluate`) instead of
staying silent.

## What it catches

| Area | Examples |
| --- | --- |
| ADB and debug posture | `ro.debuggable=1`, `ro.secure=0`, `ro.adb.secure=0`, adbd services running as root or shell |
| Privilege | `su` binaries, setuid/setgid files, file capabilities, world-writable files |
| Boot chain | AVB flags, rollback index, chained vbmeta, unsigned images, RSA signature and partition hash checks |
| Secrets and apps | Hardcoded credentials in file contents, APK package names and signing certificates |
| Quality | Missing partitions, duplicate properties, SELinux label gaps, mode anomalies, init service hygiene, debug leftovers |
| Staleness | Security patch level age from OTA metadata: `ok`, `stale` (over 90 days), `very stale` (over 365) |

## Agent integration

Two ways to hand the tool to an AI coding agent.

**MCP server.** `android-doctor mcp` speaks the Model Context Protocol over
stdio and exposes three tools, `identify`, `doctor` and `audit`, each taking a
`path`. Findings arrive as structured data instead of scraped stdout. Register
it in your agent's MCP config:

```json
{ "mcpServers": { "android-doctor": { "command": "android-doctor", "args": ["mcp"] } } }
```

**Skill installer.** `doctor install` writes a short skill describing the
commands, findings and severities:

```sh
android-doctor doctor install                    # list where each agent would go
android-doctor doctor install --agent claude     # claude-code | cursor | codex | opencode
android-doctor doctor install --print-only       # print the skill
```

Besides the per-user skill file, `--agent cursor` writes
`.cursor/rules/android-doctor.mdc` and `--agent codex` / `--agent opencode`
add a managed block to `AGENTS.md`, both in the current directory. Re-running
replaces the block and never touches the rest of the file.

See [AGENTS.md](AGENTS.md) for the contributor and agent-usage contract.

## CLI reference

Every subcommand takes `--help`. `--no-color` (or `NO_COLOR`) disables colour.

| Command | What it does |
| --- | --- |
| `extract <ota.zip\|dir\|payload.bin> [-o out] [--only a,b] [--list] [--force]` | OTA to partition images (add `--files` for file trees, `--base` for incremental OTAs) |
| `unpack <boot.img\|vendor_boot.img> [-o dir] [--json]` | Header, and with `-o` the kernel, ramdisk and dtb sections |
| `ramdisk <boot.img\|ramdisk> [-o dir] [--json] [--list]` | Ramdisk contents and ADB properties |
| `audit <image\|dir>... [--json]` | ADB properties, setuid files, `su` binaries, init services, findings |
| `vbmeta <vbmeta.img> [--images dir] [--json] [--key key.pem]` | AVB header, key, signature, descriptors, partition hashes |
| `ls <image> [path]` / `cat <image> <path>` | Browse and read files inside an ext2/3/4 or erofs image |
| `files <image> [-o dir] [--json]` | List or extract an image's files with SELinux labels |
| `unsparse <file>... -o out.img` | Android sparse images to a raw image |
| `identify <path>... [--json]` | What is this file, by magic bytes |
| `info <ota> [--json]` / `report <ota> [--json]` | Build metadata / staleness verdict |
| `dt <file> [--json]` | Device tree, dtbo table or container header |
| `amlogic <file>` | Describe an Amlogic image container |
| `partitions <dir> [--json] [--sector-size N]` | Qualcomm `rawprogram*.xml` / MediaTek `scatter.txt` flash manifest |
| `hash-tree <image>` | Regenerate the dm-verity hash tree for a rebuilt partition |
| `doctor scan <dir> [--json]` | Deterministic health scan |
| `doctor install [--agent <name>] [--print-only]` | Install the agent skill |
| `mcp [--verbose]` | MCP server on stdio |

### What `extract` does

`extract` recognises the kind of OTA by looking inside it.

**Full A/B OTAs** (a zip with a stored `payload.bin`, a directory holding `payload.bin`, or a bare `payload.bin`):

- Decodes the `REPLACE`, `REPLACE_BZ`, `REPLACE_XZ` and `ZSTD` operations (and `ZERO`/`DISCARD`) in parallel across all CPU cores, straight from the zip (no unzip step), with a progress bar per partition.
- Checks the SHA-256 of every operation's data and of every finished image against the manifest, and says so on the result line (`sha256 verified`).
- All-or-nothing: if anything fails, no image is published and every `.part` file is removed.
- Incremental OTAs (operations that need the previous build) are refused up front with a message naming the operation types.
- Limits that stop a hostile file from burning time or disk: manifest 64 MiB, 1024 partitions, 64 GiB per partition.
- Not done: partitions that declare dm-verity/FEC extents get their data extracted, but the whole-image hash is reported as "not checked", because the device adds those bytes at install time. A `payload.bin` stored compressed inside the zip must be unzipped first.

Full **block OTAs** (`<part>.new.dat.br` or `.new.dat` plus `<part>.transfer.list`, as a zip or an unpacked directory):

- Reads a zip in place (no unzip step), decompresses brotli on the fly and rebuilds each partition image, one thread per partition with a progress bar.
- Joins numbered pieces (`<part>.new.dat.N`, `<part>.new.dat.br.N`) when an OTA ships them.
- Copies the top-level `*.img` files (boot, recovery, dtbo, vbmeta, ...) unchanged.
- Prints the filesystem (`ext2`/`ext3`/`ext4`/`erofs`) on the result line of each image that holds one (raw images such as `boot.img` get no tag); `--list` shows what would be written, with sizes, and writes nothing; `--only system,boot` selects images.
- Refuses to overwrite existing files unless `--force`; writes `<name>.part` and renames when complete, so a failed run never leaves a half-written image; never writes through symlinks.

`report` rates the security patch level by age: up to 90 days is `ok`, up to 365 is `stale`, older is `very stale`. The Android version line is informational.

## Format support

Status: **verified** = checked against an independent reference tool on real firmware; **synthetic** = implemented and tested with generated fixtures only; **planned** = not implemented yet; **no** = not supported.

| Format | Status | Notes |
|---|---|---|
| A/B `payload.bin`, full OTA (`REPLACE`, `REPLACE_BZ`, `REPLACE_XZ`) | verified | A real 18-partition OTA: every image equals `payload-dumper-go`'s and the hash decoded from the manifest by `protoc`; about 2.5x faster than `payload-dumper-go` on that file |
| A/B `payload.bin`: `ZERO`, `DISCARD`, `ZSTD` operations | synthetic | The real sample has none; checked against an independent payload builder and against `payload-dumper-go` on those payloads |
| Block OTA, brotli (`*.new.dat.br`) | verified | Two real OTAs, sha256 equal to `brotli -d` + sdat2img |
| Block OTA, raw (`*.new.dat`) and numbered pieces | verified | Real partitions split into pieces rebuild to the reference hashes |
| Raw images inside an OTA (boot, recovery, ...) | verified | Byte-identical to the zip entries |
| Filesystem detection: ext2/3/4 | verified | Four real images, cross-checked with an independent superblock parse |
| Filesystem detection: erofs | verified | Real `mkfs.erofs` images (plain and lz4hc) |
| Android sparse images (`unsparse`), single and split files | verified | Real partitions converted by `img2simg` (block sizes 1024 to 65536) and split by `simg2simg`: sha256 equal to the original and to `simg2img` |
| File identification (`identify`) | verified | 27 real files, from OTA zips to boot images to xz/zstd/lz4 output |
| `super.img` (dynamic partitions): detect (`identify`), parse LP metadata and split into partition images (`extract`) | verified | Synthetic super image with geometry/header/table checksums and a linear extent: geometry magic detected, checksums validated, and extents split byte-for-byte; `extract` writes one `<partition>.img` per linear/zero extent |
| Files out of ext2/3/4 images (`files`, `ls`, `cat`, `extract --files`) | verified | Four real partition images (3,553 entries) equal `7z`'s path list and file hashes, and SELinux labels and file capabilities of every inode equal an independent scanner; images built by `mke2fs -d` from a known tree in six variants (ext2, ext3, ext4, 128-byte inodes with 1 KiB blocks, 64bit, no extents) equal the source tree in content, mode, hardlinks, sparse files and xattrs. Written from the on-disk format: no root, no mount, bounded memory (23 MB peak on 540 hostile images). `extract <ota> --files` writes every ext2/3/4 image's tree and manifest under `<out>/files/<image>/`; `ls` and `cat` read straight from an image without extracting it (checked against `7z`'s listing and bytes, and against the extracted tree). Case-colliding names are renamed `name~case2` on case-insensitive hosts. Not supported: `inline_data`, encrypted files, `meta_bg`, xattr values stored in their own inode |
| AVB `vbmeta` (`vbmeta`): header, public key, hash/hashtree/property/cmdline/chain descriptors, footer, authentication digest, partition hashes | verified | Every field equals AOSP `avbtool info_image` on four real images (a signed RSA-4096 vbmeta with 22 descriptors, a boot and a dtbo image read through their footers, and an unsigned vbmeta with verification disabled); the boot and dtbo hashes equal the descriptors and a flipped byte is caught. The RSA signature itself is not verified, nor are hashtrees |
| Security audit (`audit`): ADB and build properties, setuid/setgid files, file capabilities, world-writable files, `su` binaries, init services (adbd, root or shell-domain services), findings with a severity | verified | On the four real stock images every list equals an independent re-derivation from `7z`'s listing and file contents (properties, setuid, world-writable, `su`, all 117 init services); images built from a known tree with `su`, setuid files, debuggable properties and an `adbd` service give the expected 12 rule findings, identical for ext4 and erofs. Reports every file that sets a property (init load order is not simulated) and reads at most 50,000 text files per image. Not included: APK package names and signing certificates, SELinux policy analysis |
| Files out of erofs images (same `files`, `ls`, `cat`, `extract --files`) | verified | Images built by `mkfs.erofs` 1.9 in ten layouts (plain, lz4, lz4hc, lzma, deflate, two algorithms at once, big pclusters with ztailpacking, fragments with dedupe, chunk-based, an xattr prefix dictionary): every entry equals `fsck.erofs --extract` in content, size and links, hard links stay shared, and `ls`/`cat` agree. Reading is done by the `am-fs-erofs` crate (MIT, clean-room); this tool adds limits on depth, entries, directory and file size, bounded reads and hole-preserving output, and was run against 600 corrupted images (no panic, hang or kill, 48 MB peak). Not verified: ZSTD-compressed images (the Homebrew `mkfs.erofs` has no zstd, so none could be built) and a real device image; images using 48-bit addressing or the metabox are refused by name |
| Boot / recovery / vendor_boot images: header and sections (`unpack`) | verified | Real STB boot and recovery (header v1) and a real A/B boot (v2): every section and header field equals AOSP's `unpack_bootimg.py`. Boot v0, v3, v4 and vendor_boot v3, v4 on images built by AOSP's `mkbootimg.py`: identical |
| Ramdisk (`ramdisk`): gzip, bzip2, xz, zstd, lz4 (frame and legacy), plain cpio | verified | A real 37 MB gzip ramdisk (486 entries): every file sha256, directory, symlink target, mode and size equals `bsdtar`'s; archives built by `bsdtar` and compressed with the standard tools in all six formats; a `vendor_boot` with gzip, lz4 and xz fragments built by `mkbootimg.py` |
| ADB/debug properties from a ramdisk (`ro.secure`, `ro.adb.secure`, `ro.debuggable`, ...) | verified | Found through the `default.prop -> prop.default` symlink on the real ramdisk, equal to the values read from the extracted file |
| Encrypted boot sections (Amlogic `@AML` containers and ciphertext) | detected only | `unpack` labels them (`aml-container`, `unknown-high-entropy`) and `ramdisk` explains why it cannot read them; there is no way to decrypt without the vendor's keys. The real STB recovery image is one of these |
| tar, `.tar.md5`, gzip, bzip2, xz, lz4 wrappers | verified | Synthetic tars built with `tar::Builder` and wrapped with `flate2`: plain, gzip and Samsung `.tar.md5` all round-trip `boot.img`/`system.img` byte-for-byte, and an `extract` run over an update directory unpacks `SUPER.tar.md5` into its partition images instead of copying the blob. A `.tar.md5` whose trailing MD5 does not match the tar is refused before anything is written; an entry named `../evil`, an absolute path or a NUL is rejected, and device and fifo entries are refused rather than created. Extraction stages into `<out>.part` and is published only on success |
| AVB / vbmeta inspection | verified | RSA signature verification over the header + auxiliary block, matching `avbtool verify_image` |
| Oppo/Realme `.ozip` (AES-128-ECB encrypted zip) | synthetic | Decrypts to the inner zip using a per-model key table (adapted from B. Kerler's `oppo_ozip_decrypt`, MIT); tested with generated fixtures, not yet verified on real firmware |
| Qualcomm `rawprogram*.xml` and MediaTek `scatter.txt` flash manifests | synthetic | Parsed and checked against the image files present (`partitions` command); tested with generated fixtures |
| Device tree / dtbo tables (`dt`) | synthetic | Parses and displays the device tree blob and dtbo table headers; tested on AOSP `mkdtboimg` output |
| Other vendor containers (Amlogic, ...) | planned | Without real samples these will be marked unverified |
| Spreadtrum/MediaTek `.pac` containers | synthetic | Parser and extractor (adapted from SR Labs PacHandler, Apache-2.0); tested with generated fixtures, not yet verified on real firmware |
| Incremental OTAs (`*.patch.dat`, delta payloads) | no | Fails with a clear error |
| dm-verity hash tree and FEC regeneration for A/B partitions | planned | Needed to check the whole-image hash of partitions that declare those extents |
| f2fs | detected | Detected by magic, but not readable: the Linux kernel f2fs driver is GPL-licensed and no permissive Rust reader exists; commands that read a filesystem (`files`, `ls`, `cat`, `audit`, `extract --files`) fail with "f2fs is not supported" |
| `.ofp` and other key-protected containers | no | |

Roadmap and issue list: see the milestones on GitHub.

## What it will not tell you

- It never runs firmware. It reads bytes, so runtime behaviour (what a service
  actually does once booted) is out of scope.
- No APK or SELinux policy analysis beyond package names, signing certificates
  and label gaps.
- The whole-image hash of a partition with dm-verity/FEC extents is reported as
  "not checked"; the device adds those bytes at install time.
- f2fs is detected but not readable. Key-protected containers (`.ofp`, encrypted
  Amlogic sections) are not decrypted.
- Unsupported or unreadable input is reported as such, never as clean.

## Exit codes

| | |
| --- | --- |
| `0` | ran to completion |
| `1` | `doctor scan` found an `error`-severity finding, or a failure: bad flag, unreadable or hostile input |

`audit` reports its findings in the output; it exits `0` unless it fails to read the input.

## Privacy and telemetry

None. No network calls, no analytics. Everything runs locally on the files you
point it at.

## Build

```sh
cargo build --release
cargo test
```

## Third-party code and references

See [THIRD_PARTY.md](THIRD_PARTY.md). Code is adapted only from permissively licensed projects and credited there.

Not affiliated with or endorsed by Google. Android is a trademark of Google LLC.

## License

MIT
