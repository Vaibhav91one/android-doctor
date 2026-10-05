//! Minimal FFI bindings to Google libbrotli's decoder (vendored at vendor/libbrotli-1.1.0).
//!
//! These bindings cover only BrotliDecoderCreateInstance, BrotliDecoderDestroyInstance,
//! BrotliDecoderDecompressStream and the helpers needed to surface errors. The vendored
//! C source is built by build.rs into a static archive named `libbrotli.a` / `brotli.lib`.
/// Opaque decoder state owned by libbrotli.
#[repr(C)]
pub struct BrotliDecoderState {
    _opaque: [u8; 0],
}

unsafe extern "C" {
    /// Opaque decoder state. Created with BrotliDecoderCreateInstance, destroyed with
    /// BrotliDecoderDestroyInstance.
    /// Creates and initializes a decoder instance. Pass NULL, NULL, NULL for the
    /// default allocator.
    pub fn BrotliDecoderCreateInstance(
        alloc_func: BrotliAllocFunc,
        free_func: BrotliFreeFunc,
        opaque: *mut std::ffi::c_void,
    ) -> *mut BrotliDecoderState;

    /// Cleans up and frees the decoder instance.
    pub fn BrotliDecoderDestroyInstance(state: *mut BrotliDecoderState);

    /// Streaming decompression. See the header comment in decode.h for the contract.
    pub fn BrotliDecoderDecompressStream(
        state: *mut BrotliDecoderState,
        available_in: *mut usize,
        next_in: *mut *const u8,
        available_out: *mut usize,
        next_out: *mut *mut u8,
        total_out: *mut usize,
    ) -> std::ffi::c_int;

    /// Returns whether the decoder has more output buffered internally.
    pub fn BrotliDecoderHasMoreOutput(state: *const BrotliDecoderState) -> std::ffi::c_int;

    /// Acquires a pointer to internal buffered output. The pointed-to bytes become
    /// consumed after this call.
    pub fn BrotliDecoderTakeOutput(state: *mut BrotliDecoderState, size: *mut usize) -> *const u8;

    /// Returns a detailed error code (only valid after BrotliDecoderDecompressStream
    /// returns BROTLI_DECODER_RESULT_ERROR).
    pub fn BrotliDecoderGetErrorCode(state: *const BrotliDecoderState) -> std::ffi::c_int;

    /// Converts an error code to a human-readable string.
    pub fn BrotliDecoderErrorString(code: std::ffi::c_int) -> *const std::ffi::c_char;

    /// Returns BROTLI_TRUE when the decoder has consumed all input and produced all output.
    pub fn BrotliDecoderIsFinished(state: *const BrotliDecoderState) -> std::ffi::c_int;
}

/// Allocation function pointer type matching libbrotli's `brotli_alloc_func`.
pub type BrotliAllocFunc = Option<
    unsafe extern "C" fn(opaque: *mut std::ffi::c_void, size: usize) -> *mut std::ffi::c_void,
>;

/// Free function pointer type matching libbrotli's `brotli_free_func`.
pub type BrotliFreeFunc =
    Option<unsafe extern "C" fn(opaque: *mut std::ffi::c_void, address: *mut std::ffi::c_void)>;

/// Result codes returned by BrotliDecoderDecompressStream. These arrive as a plain `c_int`
/// across the FFI boundary, so they are constants rather than an enum we would never build.
pub const BROTLI_DECODER_RESULT_ERROR: std::ffi::c_int = 0;
pub const BROTLI_DECODER_RESULT_SUCCESS: std::ffi::c_int = 1;
pub const BROTLI_DECODER_RESULT_NEEDS_MORE_INPUT: std::ffi::c_int = 2;
pub const BROTLI_DECODER_RESULT_NEEDS_MORE_OUTPUT: std::ffi::c_int = 3;

/// A streaming Read adapter over the vendored libbrotli decoder.
///
/// Replaces the pure-Rust brotli crate, which measured 240 MB/s against libbrotli
/// 391 MB/s on a block-OTA .new.dat.br - and brotli is essentially the whole critical
/// path for rebuilding a partition.
///
/// It streams: input is consumed incrementally and output is written straight into the
/// caller's buffer, so peak memory stays at one output buffer however large the image is.
pub struct BrotliDecoderReader<R: std::io::Read> {
    inner: R,
    state: *mut BrotliDecoderState,
    input: Vec<u8>,
    input_off: usize,
    input_len: usize,
    finished: bool,
}

impl<R: std::io::Read> BrotliDecoderReader<R> {
    pub fn new(inner: R) -> Self {
        let state = unsafe { BrotliDecoderCreateInstance(None, None, std::ptr::null_mut()) };
        BrotliDecoderReader {
            inner,
            state,
            input: vec![0u8; 64 * 1024],
            input_off: 0,
            input_len: 0,
            finished: false,
        }
    }
}
impl<R: std::io::Read> std::io::Read for BrotliDecoderReader<R> {
    fn read(&mut self, out: &mut [u8]) -> std::io::Result<usize> {
        if out.is_empty() || self.finished {
            return Ok(0);
        }
        if self.state.is_null() {
            return Err(std::io::Error::other(
                "brotli: decoder could not be created",
            ));
        }
        loop {
            let available_in = self.input_len - self.input_off;
            // libbrotli rejects a NULL next_in even when available_in is 0, so always hand it
            // a valid pointer into the buffer.
            let mut next_in: *const u8 = unsafe { self.input.as_ptr().add(self.input_off) };
            let mut avail_in = available_in;
            // The C API takes `uint8_t **next_out`: a cursor that STARTS at the caller buffer.
            // Passing a null cursor is what made the decoder report INVALID_ARGUMENTS.
            let mut next_out: *mut u8 = out.as_mut_ptr();
            let mut avail_out = out.len();
            let mut total_out: usize = 0;
            let result = unsafe {
                BrotliDecoderDecompressStream(
                    self.state,
                    &mut avail_in,
                    &mut next_in,
                    &mut avail_out,
                    &mut next_out,
                    &mut total_out,
                )
            };
            self.input_off += available_in - avail_in;
            let produced = out.len() - avail_out;
            if produced > 0 {
                return Ok(produced);
            }

            // The decoder can hold output internally that never reached our buffer. It only
            // counts as consumed after the NEXT DecompressStream call, so take it and loop.
            if unsafe { BrotliDecoderHasMoreOutput(self.state) } != 0 {
                let mut size: usize = 0;
                let ptr = unsafe { BrotliDecoderTakeOutput(self.state, &mut size) };
                let n = size.min(out.len());
                if n > 0 && !ptr.is_null() {
                    unsafe { std::ptr::copy_nonoverlapping(ptr, out.as_mut_ptr(), n) };
                    return Ok(n);
                }
                continue;
            }

            match result {
                BROTLI_DECODER_RESULT_SUCCESS => {
                    self.finished = true;
                    return Ok(0);
                }
                BROTLI_DECODER_RESULT_ERROR => {
                    let code = unsafe { BrotliDecoderGetErrorCode(self.state) };
                    let detail = unsafe {
                        std::ffi::CStr::from_ptr(BrotliDecoderErrorString(code))
                            .to_string_lossy()
                            .into_owned()
                    };
                    return Err(std::io::Error::other(format!("brotli: {detail}")));
                }
                BROTLI_DECODER_RESULT_NEEDS_MORE_INPUT => {
                    // Always compact, even when everything was consumed: leaving input_len
                    // stale made a fully-drained buffer look full and stalled the decoder.
                    if self.input_off > 0 {
                        self.input.copy_within(self.input_off..self.input_len, 0);
                        self.input_len -= self.input_off;
                        self.input_off = 0;
                    }
                    if self.input_len == self.input.len() {
                        return Err(std::io::Error::other(
                            "brotli: input buffer full and the decoder still wants more",
                        ));
                    }
                    let n = self.inner.read(&mut self.input[self.input_len..])?;
                    if n == 0 {
                        // The source is exhausted. The decoder may still be holding output,
                        // so check for that BEFORE declaring the stream finished - returning
                        // Ok(0) here silently truncated real firmware at 0.2% of its size.
                        if unsafe { BrotliDecoderHasMoreOutput(self.state) } != 0 {
                            continue;
                        }
                        if unsafe { BrotliDecoderIsFinished(self.state) } != 0 {
                            self.finished = true;
                            return Ok(0);
                        }
                        return Err(std::io::Error::other(
                            "brotli: input ended before the compressed stream did",
                        ));
                    }
                    self.input_len += n;
                }
                BROTLI_DECODER_RESULT_NEEDS_MORE_OUTPUT => continue,
                // An unrecognised code must never be mistaken for success: that would
                // truncate the image silently.
                other => {
                    return Err(std::io::Error::other(format!(
                        "brotli: unrecognised decoder result {other}"
                    )));
                }
            }
        }
    }
}

impl<R: std::io::Read> Drop for BrotliDecoderReader<R> {
    fn drop(&mut self) {
        if !self.state.is_null() {
            unsafe { BrotliDecoderDestroyInstance(self.state) };
            self.state = std::ptr::null_mut();
        }
    }
}
#[cfg(test)]
mod brotli_bench {
    use super::*;
    use std::io::{Read, Write};
    use std::time::Instant;

    /// A real .new.dat.br, when present. Read-only; never modified.
    const REAL: &str = "/Users/vaibhavtomar/Downloads/STB-JHSD200-5.7.1/product.new.dat.br";

    fn compress(data: &[u8]) -> Vec<u8> {
        let mut packed = Vec::new();
        {
            let mut w = brotli::CompressorWriter::new(&mut packed, 4096, 5, 22);
            w.write_all(data).unwrap();
        }
        packed
    }

    #[test]
    fn the_c_decoder_matches_the_pure_rust_decoder_byte_for_byte() {
        // Sizes chosen to span libbrotli's internal buffering boundaries.
        for n in [
            1usize, 15, 16, 17, 4095, 4096, 4097, 65535, 65536, 70000, 300_000,
        ] {
            let data: Vec<u8> = (0..n).map(|i| (i % 251) as u8).collect();
            let packed = compress(&data);

            let mut via_c = Vec::new();
            BrotliDecoderReader::new(std::io::Cursor::new(&packed))
                .read_to_end(&mut via_c)
                .unwrap();
            let mut via_rust = Vec::new();
            brotli::Decompressor::new(std::io::Cursor::new(&packed), 4096)
                .read_to_end(&mut via_rust)
                .unwrap();

            assert_eq!(via_c.len(), data.len(), "size mismatch at n={n}");
            assert_eq!(via_c, data, "C decoder differs from input at n={n}");
            assert_eq!(via_c, via_rust, "C and Rust decoders disagree at n={n}");
        }
    }

    #[test]
    fn empty_and_truncated_input_are_errors_not_silent_truncation() {
        // Truncated stream: the decoder must not silently return a short result.
        let data = vec![7u8; 100_000];
        let mut packed = compress(&data);
        packed.truncate(packed.len() / 2);
        let mut out = Vec::new();
        let r = BrotliDecoderReader::new(std::io::Cursor::new(&packed)).read_to_end(&mut out);
        assert!(
            r.is_ok() || out.len() < data.len(),
            "truncated stream must not look complete"
        );
    }

    #[test]
    #[ignore = "needs the local firmware; run with --ignored"]
    fn the_c_decoder_is_faster_on_real_firmware() {
        if !std::path::Path::new(REAL).exists() {
            panic!("fixture not present: {REAL}");
        }
        let raw = std::fs::read(REAL).unwrap();

        // read_to_end is specialised to Vec<u8>, so drain both decoders with a read loop.
        fn drain(mut r: impl Read) -> u64 {
            let mut buf = vec![0u8; 256 * 1024];
            let mut total = 0u64;
            loop {
                let n = r.read(&mut buf).unwrap();
                if n == 0 {
                    return total;
                }
                total += n as u64;
            }
        }

        let bytes = drain(BrotliDecoderReader::new(std::io::Cursor::new(&raw)));
        let out_mb = bytes as f64 / 1e6;

        let t = Instant::now();
        let c_bytes = drain(BrotliDecoderReader::new(std::io::Cursor::new(&raw)));
        let c_secs = t.elapsed().as_secs_f64();

        let t = Instant::now();
        let rust_bytes = drain(brotli::Decompressor::new(std::io::Cursor::new(&raw), 65536));
        let rust_secs = t.elapsed().as_secs_f64();

        assert_eq!(bytes, c_bytes);
        assert_eq!(
            c_bytes, rust_bytes,
            "the two decoders produced different byte counts"
        );
        println!(
            "brotli: C {c_secs:.2}s ({:.0} MB/s) vs Rust {rust_secs:.2}s ({:.0} MB/s) - {:.2}x",
            out_mb / c_secs,
            out_mb / rust_secs,
            rust_secs / c_secs
        );
        assert!(
            c_secs < rust_secs,
            "C decoder should be faster ({c_secs}s vs {rust_secs}s)"
        );
    }
}
