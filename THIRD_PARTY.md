# Third-party code, references and licenses

## Policy

- Code is adapted only from projects under permissive licenses (Apache-2.0, MIT, BSD). Anything adapted is cited in a comment at the place it is used and listed in this file.
- Projects without a license, or under GPL/LGPL, are never copied from. They are not used as a source of code.
- Test fixtures are generated inside the tests. Real firmware is never committed.

## Code copied or adapted

None so far. Every source file in this repository was written for this project.

## References (behaviour and formats; no code taken)

| Project | License | How it is used |
|---|---|---|
| [sdat2img](https://github.com/xpirt/sdat2img) | MIT | Reference for how a block-OTA transfer list becomes an image; its output (via `brotli -d`) is the independent check that `extract` is byte-identical |
| [SR Labs extractor](https://github.com/srlabs/extractor) | Apache-2.0 | Inspiration for the planned queue of format handlers; formats it covers guide the roadmap |
| Android Open Source Project | Apache-2.0 | On-disk formats: the sparse image format and the update payload (`update_metadata.proto`, whose messages are hand-written in `src/payload.rs`) are implemented from the AOSP definitions; LP metadata, boot images and AVB will follow |
| [payload-dumper-go](https://github.com/ssut/payload-dumper-go) | Apache-2.0 | Read for how operations map onto extents; used as the independent check for A/B payload extraction (its output must equal ours). No code copied |
| `simg2img`/`img2simg`, `erofs-utils` (`mkfs.erofs`, `fsck.erofs`), 7-Zip, `brotli` | various | Used only as external checks while developing; not linked or bundled |

## Rust dependencies (direct)

| Crate | License |
|---|---|
| anyhow | MIT OR Apache-2.0 |
| brotli | BSD-3-Clause AND MIT |
| bzip2 | MIT OR Apache-2.0 |
| crc32fast | MIT OR Apache-2.0 |
| lzma-rust2 | Apache-2.0 |
| clap | MIT OR Apache-2.0 |
| indicatif | MIT |
| prost | Apache-2.0 |
| ruzstd | MIT |
| sha2 | MIT OR Apache-2.0 |
| serde_json | MIT OR Apache-2.0 |
| zip | MIT |

All transitive dependencies are permissively licensed. One is dual-licensed with an LGPL option (`MIT OR Apache-2.0 OR LGPL-2.1-or-later`); this project uses it under MIT/Apache-2.0. Run `cargo metadata` for the full list.
