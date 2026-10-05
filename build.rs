use std::path::PathBuf;

/// Compile the vendored libbrotli decoder into a static archive and link it.
///
/// brotli is essentially the whole critical path for rebuilding a partition in a block OTA:
/// the pure-Rust `brotli` crate measured 250 MB/s against libbrotli's 391 MB/s on real
/// firmware. Vendoring the C decoder is the only way to close that 1.56x gap, and only the
/// decoder subset is built - we never compress.
///
/// Vendored: libbrotli 1.1.0, MIT (see vendor/libbrotli-1.1.0/LICENSE).
fn main() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("vendor/libbrotli-1.1.0");
    if !root.is_dir() {
        panic!("vendored libbrotli missing at {}", root.display());
    }

    let mut build = cc::Build::new();
    build
        .include(root.join("c/include"))
        .include(root.join("c/common"))
        .include(root.join("c/dec"))
        .file(root.join("c/common/dictionary.c"))
        .file(root.join("c/common/constants.c"))
        .file(root.join("c/common/transform.c"))
        .file(root.join("c/common/platform.c"))
        .file(root.join("c/common/shared_dictionary.c"))
        .file(root.join("c/common/context.c"))
        .file(root.join("c/dec/state.c"))
        .file(root.join("c/dec/decode.c"))
        .file(root.join("c/dec/huffman.c"))
        .file(root.join("c/dec/bit_reader.c"))
        .warnings(false);
    // Only decode is vendored, so the encoder entry points are unused.
    build.define("BROTLI_BUILD_PORTABLE", None);
    build.compile("brotli_dec");

    println!("cargo:rerun-if-changed=vendor/libbrotli-1.1.0");
    println!("cargo:rerun-if-changed=build.rs");
}
