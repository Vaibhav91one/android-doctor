# android-doctor

Command-line tool to extract and audit Android firmware packages.

```
android-doctor extract  <ota.zip|dir|payload.bin> [-o out] [--only a,b] [--list] [--force]
android-doctor unpack   <boot.img|vendor_boot.img> [-o dir] [--json] [--force]   # header, and with -o the sections
android-doctor ramdisk  <boot.img|vendor_boot.img|ramdisk> [-o dir] [--json] [--list]   # ramdisk contents and ADB properties
android-doctor vbmeta   <vbmeta.img|image-with-footer> [--images dir] [--json]   # AVB header, key, descriptors, partition hashes
android-doctor files    <image.img> [-o dir] [--json]   # list or extract an ext2/3/4 image (no root), with SELinux labels
android-doctor unsparse <file>... -o out.img [--force]   # Android sparse image(s) to a raw image
android-doctor identify <path>... [--json]               # what is this file, by magic bytes
android-doctor info     <ota.zip|dir> [--json]           # build metadata (META-INF/com/android/metadata)
android-doctor report   <ota.zip|dir> [--json]           # staleness verdict from the security patch level
```

## What `extract` does today

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
| `super.img` (dynamic partitions) | planned | |
| Files out of ext2/3/4 images (`files`) | verified | Four real partition images (3,553 entries) equal `7z`'s path list and file hashes, and SELinux labels and file capabilities of every inode equal an independent scanner; images built by `mke2fs -d` from a known tree in six variants (ext2, ext3, ext4, 128-byte inodes with 1 KiB blocks, 64bit, no extents) equal the source tree in content, mode, hardlinks, sparse files and xattrs. Written from the on-disk format: no root, no mount, bounded memory (23 MB peak on 540 hostile images). Case-colliding names are renamed `name~case2` on case-insensitive hosts. Not supported: `inline_data`, encrypted files, `meta_bg`, xattr values stored in their own inode |
| AVB `vbmeta` (`vbmeta`): header, public key, hash/hashtree/property/cmdline/chain descriptors, footer, authentication digest, partition hashes | verified | Every field equals AOSP `avbtool info_image` on four real images (a signed RSA-4096 vbmeta with 22 descriptors, a boot and a dtbo image read through their footers, and an unsigned vbmeta with verification disabled); the boot and dtbo hashes equal the descriptors and a flipped byte is caught. The RSA signature itself is not verified, nor are hashtrees |
| Files out of erofs images | planned | Today use `fsck.erofs --extract` |
| Boot / recovery / vendor_boot images: header and sections (`unpack`) | verified | Real STB boot and recovery (header v1) and a real A/B boot (v2): every section and header field equals AOSP's `unpack_bootimg.py`. Boot v0, v3, v4 and vendor_boot v3, v4 on images built by AOSP's `mkbootimg.py`: identical |
| Ramdisk (`ramdisk`): gzip, bzip2, xz, zstd, lz4 (frame and legacy), plain cpio | verified | A real 37 MB gzip ramdisk (486 entries): every file sha256, directory, symlink target, mode and size equals `bsdtar`'s; archives built by `bsdtar` and compressed with the standard tools in all six formats; a `vendor_boot` with gzip, lz4 and xz fragments built by `mkbootimg.py` |
| ADB/debug properties from a ramdisk (`ro.secure`, `ro.adb.secure`, `ro.debuggable`, ...) | verified | Found through the `default.prop -> prop.default` symlink on the real ramdisk, equal to the values read from the extracted file |
| Encrypted boot sections (Amlogic `@AML` containers and ciphertext) | detected only | `unpack` labels them (`aml-container`, `unknown-high-entropy`) and `ramdisk` explains why it cannot read them; there is no way to decrypt without the vendor's keys. The real STB recovery image is one of these |
| tar, `.tar.md5`, gzip, bzip2, xz, lz4 wrappers | planned | |
| AVB / vbmeta inspection | planned | |
| Vendor containers (`.ozip`, `.pac`, Qualcomm `rawprogram`, Amlogic, ...) | planned | Without real samples these will be marked unverified |
| Incremental OTAs (`*.patch.dat`, delta payloads) | no | Fails with a clear error |
| dm-verity hash tree and FEC regeneration for A/B partitions | planned | Needed to check the whole-image hash of partitions that declare those extents |
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
