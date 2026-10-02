# android-doctor

Command-line tool to extract and audit Android firmware packages.

```
android-doctor extract <ota.zip|dir> [-o out] [--only a,b] [--list] [--force]
android-doctor info    <ota.zip|dir> [--json]   # build metadata (META-INF/com/android/metadata)
android-doctor report  <ota.zip|dir> [--json]   # staleness verdict from the security patch level
```

## What `extract` does today

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
| Block OTA, brotli (`*.new.dat.br`) | verified | Two real OTAs, sha256 equal to `brotli -d` + sdat2img |
| Block OTA, raw (`*.new.dat`) and numbered pieces | verified | Real partitions split into pieces rebuild to the reference hashes |
| Raw images inside an OTA (boot, recovery, ...) | verified | Byte-identical to the zip entries |
| Filesystem detection: ext2/3/4 | verified | Four real images, cross-checked with an independent superblock parse |
| Filesystem detection: erofs | verified | Real `mkfs.erofs` images (plain and lz4hc) |
| Android sparse images | planned | |
| A/B `payload.bin` (full OTA) | planned | |
| `super.img` (dynamic partitions) | planned | |
| Reading files out of ext4 / erofs images | planned | Today use `7z x system.img` |
| Boot / recovery / vendor_boot images | planned | |
| tar, `.tar.md5`, gzip, bzip2, xz, lz4 wrappers | planned | |
| AVB / vbmeta inspection | planned | |
| Vendor containers (`.ozip`, `.pac`, Qualcomm `rawprogram`, Amlogic, ...) | planned | Without real samples these will be marked unverified |
| Incremental OTAs (`*.patch.dat`, delta payloads) | no | Fails with a clear error |
| f2fs | no | No permissive reader exists |
| `.ofp` and other key-protected containers | no | |

Roadmap and issue list: see the milestones on GitHub.

## Build

```
cargo build --release
```

## Third-party code and references

See [THIRD_PARTY.md](THIRD_PARTY.md). Code is adapted only from permissively licensed projects and credited there.

Not affiliated with or endorsed by Google. Android is a trademark of Google LLC.

## License

MIT
