# android-doctor

Command-line tool to extract and audit Android OTA firmware packages.

```
android-doctor extract <ota.zip|dir> [-o out]   # write <partition>.img for every partition
android-doctor info    <ota.zip|dir> [--json]   # build metadata (META-INF/com/android/metadata)
android-doctor report  <ota.zip|dir> [--json]   # staleness verdict from the security patch level
```

`extract` reads a zip in place (no unzip step), decompresses `*.new.dat.br` on the fly and rebuilds each partition image from its `*.transfer.list`, one thread per partition with a progress bar. Images are written to `<name>.img.part` and renamed when complete, so a failed run never leaves a half-written image behind. Output is byte-identical to `brotli -d` followed by [sdat2img](https://github.com/xpirt/sdat2img).

`report` rates the security patch level by age: up to 90 days is `ok`, up to 365 is `stale`, older is `very stale`. The Android version line is informational.

## Build

```
cargo build --release
```

## Limits

- Full block OTAs only (`system.new.dat.br` + `system.transfer.list`). Incremental OTAs and `payload.bin` (A/B) packages are rejected with an error.
- The latest-known Android version used in the `report` text is a constant that needs a bump per Android release.
- Not yet implemented: listing files inside an image, `boot.img` unpacking, signature and `vbmeta` checks.

Not affiliated with or endorsed by Google. Android is a trademark of Google LLC.

## License

MIT
