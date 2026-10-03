//! Android sparse images: RAW, FILL, DONT_CARE and CRC32 chunks, as defined by AOSP libsparse
//! (`sparse_format.h`, Apache-2.0). Written from that format description.
use crate::extract;
use anyhow::{Context, Result, bail, ensure};
use std::fs::File;
use std::io::{BufReader, BufWriter, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

const MAGIC: u32 = 0xED26_FF3A;
const CHUNK_RAW: u16 = 0xCAC1;
const CHUNK_FILL: u16 = 0xCAC2;
const CHUNK_DONT_CARE: u16 = 0xCAC3;
const CHUNK_CRC32: u16 = 0xCAC4;
const FILE_HDR_LEN: usize = 28;
const CHUNK_HDR_LEN: usize = 12;
/// Refuse images claiming more than this, so a hostile header cannot ask for a petabyte file.
pub const MAX_IMAGE_BYTES: u64 = 1 << 40;
const COPY_BUF: usize = 1 << 20;

#[derive(Debug, PartialEq, Clone, Copy)]
pub struct Header {
    pub blk_sz: u32,
    pub total_blks: u32,
    pub total_chunks: u32,
    chunk_hdr_sz: usize,
}

impl Header {
    pub fn image_bytes(&self) -> u64 {
        self.total_blks as u64 * self.blk_sz as u64
    }
}

fn le16(b: &[u8], at: usize) -> u16 {
    u16::from_le_bytes([b[at], b[at + 1]])
}

fn le32(b: &[u8], at: usize) -> u32 {
    u32::from_le_bytes([b[at], b[at + 1], b[at + 2], b[at + 3]])
}

fn skip<R: Read>(r: &mut R, n: u64) -> Result<()> {
    let copied = std::io::copy(&mut r.by_ref().take(n), &mut std::io::sink())?;
    ensure!(copied == n, "input ends inside a header");
    Ok(())
}

pub fn read_header<R: Read>(r: &mut R) -> Result<Header> {
    let mut b = [0u8; FILE_HDR_LEN];
    r.read_exact(&mut b)
        .context("not a sparse image: too short")?;
    ensure!(le32(&b, 0) == MAGIC, "not a sparse image: bad magic");
    ensure!(
        le16(&b, 4) == 1,
        "unsupported sparse major version {}",
        le16(&b, 4)
    );
    let (file_hdr_sz, chunk_hdr_sz) = (le16(&b, 8) as usize, le16(&b, 10) as usize);
    ensure!(
        file_hdr_sz >= FILE_HDR_LEN,
        "sparse file header size {file_hdr_sz} is too small"
    );
    ensure!(
        chunk_hdr_sz >= CHUNK_HDR_LEN,
        "sparse chunk header size {chunk_hdr_sz} is too small"
    );
    let h = Header {
        blk_sz: le32(&b, 12),
        total_blks: le32(&b, 16),
        total_chunks: le32(&b, 20),
        chunk_hdr_sz,
    };
    ensure!(
        h.blk_sz != 0 && h.blk_sz.is_multiple_of(4),
        "invalid sparse block size {}",
        h.blk_sz
    );
    ensure!(
        h.image_bytes() <= MAX_IMAGE_BYTES,
        "sparse image of {} bytes is larger than the {MAX_IMAGE_BYTES}-byte limit",
        h.image_bytes()
    );
    skip(r, (file_hdr_sz - FILE_HDR_LEN) as u64)?;
    Ok(h)
}

/// CRC-32 state of `n` zero bytes, built by repeated doubling so that a huge DONT_CARE gap costs
/// a few dozen steps instead of hashing every byte.
fn zeros_crc(n: u64) -> crc32fast::Hasher {
    let mut result = crc32fast::Hasher::new();
    let mut power = crc32fast::Hasher::new(); // zeros of length 2^k, starting with one byte
    power.update(&[0]);
    let mut bits = n;
    while bits > 0 {
        if bits & 1 == 1 {
            result.combine(&power);
        }
        let again = power.clone();
        power.combine(&again);
        bits >>= 1;
    }
    result
}

/// Write `len` bytes of the repeating 4-byte `pattern`, feeding the checksum.
fn write_fill<W: Write>(
    out: &mut W,
    pattern: [u8; 4],
    len: u64,
    crc: Option<&mut crc32fast::Hasher>,
) -> Result<()> {
    let mut crc = crc;
    let block: Vec<u8> = pattern.iter().copied().cycle().take(COPY_BUF).collect();
    let mut left = len;
    while left > 0 {
        let n = left.min(COPY_BUF as u64) as usize;
        out.write_all(&block[..n])?;
        if let Some(crc) = crc.as_deref_mut() {
            crc.update(&block[..n]);
        }
        left -= n as u64;
    }
    Ok(())
}

/// Apply one sparse file to `out`. Gaps (DONT_CARE) are skipped, not zeroed, so several files
/// that each cover a different part of one image can be applied one after the other.
fn apply_one<R: Read, W: Write + Seek>(
    input: &mut R,
    h: &Header,
    out: &mut W,
    mut crc: Option<&mut crc32fast::Hasher>,
) -> Result<()> {
    let blk = h.blk_sz as u64;
    let mut at: u64 = 0; // current position in blocks
    let mut buf = vec![0u8; COPY_BUF];
    for index in 0..h.total_chunks {
        let mut hdr = vec![0u8; h.chunk_hdr_sz];
        input
            .read_exact(&mut hdr)
            .with_context(|| format!("input ends before chunk {index} of {}", h.total_chunks))?;
        let (kind, chunk_sz, total_sz) =
            (le16(&hdr, 0), le32(&hdr, 4) as u64, le32(&hdr, 8) as u64);
        let payload = total_sz
            .checked_sub(h.chunk_hdr_sz as u64)
            .with_context(|| {
                format!("chunk {index}: total size {total_sz} is smaller than its header")
            })?;
        let covers = |at: u64| at + chunk_sz <= h.total_blks as u64;
        match kind {
            CHUNK_RAW => {
                ensure!(
                    payload == chunk_sz * blk,
                    "chunk {index}: RAW payload is {payload} bytes, expected {}",
                    chunk_sz * blk
                );
                ensure!(covers(at), "chunk {index} runs past the end of the image");
                out.seek(SeekFrom::Start(at * blk))?;
                let mut left = payload;
                while left > 0 {
                    let n = left.min(COPY_BUF as u64) as usize;
                    input
                        .read_exact(&mut buf[..n])
                        .with_context(|| format!("input ends inside RAW chunk {index}"))?;
                    out.write_all(&buf[..n])?;
                    if let Some(crc) = crc.as_deref_mut() {
                        crc.update(&buf[..n]);
                    }
                    left -= n as u64;
                }
                at += chunk_sz;
            }
            CHUNK_FILL => {
                ensure!(
                    payload == 4,
                    "chunk {index}: FILL payload is {payload} bytes, expected 4"
                );
                ensure!(covers(at), "chunk {index} runs past the end of the image");
                let mut pattern = [0u8; 4];
                input
                    .read_exact(&mut pattern)
                    .with_context(|| format!("input ends inside FILL chunk {index}"))?;
                out.seek(SeekFrom::Start(at * blk))?;
                write_fill(out, pattern, chunk_sz * blk, crc.as_deref_mut())?;
                at += chunk_sz;
            }
            CHUNK_DONT_CARE => {
                ensure!(
                    payload == 0,
                    "chunk {index}: DONT_CARE has {payload} payload bytes"
                );
                ensure!(covers(at), "chunk {index} runs past the end of the image");
                if let Some(crc) = crc.as_deref_mut() {
                    crc.combine(&zeros_crc(chunk_sz * blk));
                }
                at += chunk_sz;
            }
            CHUNK_CRC32 => {
                ensure!(
                    payload == 4,
                    "chunk {index}: CRC32 payload is {payload} bytes, expected 4"
                );
                let mut want = [0u8; 4];
                input
                    .read_exact(&mut want)
                    .with_context(|| format!("input ends inside CRC32 chunk {index}"))?;
                if let Some(crc) = crc.as_deref() {
                    let got = crc.clone().finalize();
                    ensure!(
                        got == u32::from_le_bytes(want),
                        "chunk {index}: checksum mismatch (image has {got:#010x}, file says {:#010x})",
                        u32::from_le_bytes(want)
                    );
                }
            }
            other => bail!("chunk {index}: unknown chunk type {other:#06x}"),
        }
    }
    ensure!(
        at == h.total_blks as u64,
        "chunks cover {at} blocks but the header says {}",
        h.total_blks
    );
    Ok(())
}

/// Rebuild the raw image from one sparse file, or from several that describe the same image
/// (same block size and total size) and are applied in the order given. `out` must start empty.
/// Trailing bytes after the last chunk are ignored, as libsparse does. A CRC32 chunk is checked
/// when there is a single input.
pub fn unsparse<R: Read, W: Write + Seek>(mut inputs: Vec<R>, out: &mut W) -> Result<Header> {
    ensure!(!inputs.is_empty(), "no sparse input given");
    let mut headers = Vec::new();
    // headers are read one input at a time below; keep only the first here to size the output
    let first = read_header(&mut inputs[0]).context("first input")?;
    headers.push(first);
    let size = first.image_bytes();
    if size > 0 {
        out.seek(SeekFrom::Start(size - 1))?;
        out.write_all(&[0])?;
    }
    // checksums are only verified for a single input, so only then is any hashing done
    let mut crc = (inputs.len() == 1).then(crc32fast::Hasher::new);
    let count = inputs.len();
    for (n, input) in inputs.iter_mut().enumerate() {
        let h = if n == 0 {
            first
        } else {
            let h = read_header(input).with_context(|| format!("input {}", n + 1))?;
            ensure!(
                h.blk_sz == first.blk_sz && h.total_blks == first.total_blks,
                "input {} describes a different image ({} blocks of {} bytes, the first has {} of {})",
                n + 1,
                h.total_blks,
                h.blk_sz,
                first.total_blks,
                first.blk_sz
            );
            h
        };
        apply_one(input, &h, out, crc.as_mut()).with_context(|| {
            if count > 1 {
                format!("input {}", n + 1)
            } else {
                "sparse image".to_string()
            }
        })?;
    }
    Ok(first)
}

/// `unsparse` command: rebuild `output` from one or more sparse files. Nothing is created until
/// every input has been opened; the image is written to `<output>.part` and renamed when complete.
pub fn run(inputs: &[PathBuf], output: &Path, force: bool) -> Result<()> {
    if !force && output.symlink_metadata().is_ok() {
        bail!(
            "{} already exists; pass --force to overwrite",
            output.display()
        );
    }
    let files = inputs
        .iter()
        .map(|p| {
            File::open(p)
                .map(BufReader::new)
                .with_context(|| format!("opening {}", p.display()))
        })
        .collect::<Result<Vec<_>>>()?;
    if let Some(dir) = output.parent().filter(|d| !d.as_os_str().is_empty()) {
        std::fs::create_dir_all(dir)?;
    }
    let mut part = output.as_os_str().to_owned();
    part.push(".part");
    let part = PathBuf::from(part);
    let built = (|| -> Result<()> {
        let mut out = BufWriter::new(extract::create_part(&part)?);
        unsparse(files, &mut out)?;
        out.flush()?;
        Ok(())
    })();
    if let Err(e) = built {
        let _ = std::fs::remove_file(&part);
        return Err(e);
    }
    std::fs::rename(&part, output)?;
    println!("{}", extract::describe(output)?);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    /// One chunk of a sparse image, for building test inputs.
    enum C {
        Raw(Vec<u8>),
        Fill(u32, u32), // pattern, blocks
        Skip(u32),      // DONT_CARE blocks
        Crc(u32),
    }

    const BLK: u32 = 8;

    fn le(v: u32) -> [u8; 4] {
        v.to_le_bytes()
    }

    fn chunk_bytes(c: &C, blk: u32) -> Vec<u8> {
        let (kind, blocks, payload): (u16, u32, Vec<u8>) = match c {
            C::Raw(d) => (CHUNK_RAW, d.len() as u32 / blk, d.clone()),
            C::Fill(p, n) => (CHUNK_FILL, *n, le(*p).to_vec()),
            C::Skip(n) => (CHUNK_DONT_CARE, *n, vec![]),
            C::Crc(v) => (CHUNK_CRC32, 0, le(*v).to_vec()),
        };
        let mut b = Vec::new();
        b.extend(kind.to_le_bytes());
        b.extend(0u16.to_le_bytes());
        b.extend(le(blocks));
        b.extend(le(12 + payload.len() as u32));
        b.extend(payload);
        b
    }

    fn image_with(blk: u32, total_blks: u32, chunks: &[C]) -> Vec<u8> {
        let mut b = Vec::new();
        b.extend(le(MAGIC));
        b.extend(1u16.to_le_bytes());
        b.extend(0u16.to_le_bytes());
        b.extend(28u16.to_le_bytes());
        b.extend(12u16.to_le_bytes());
        b.extend(le(blk));
        b.extend(le(total_blks));
        b.extend(le(chunks.len() as u32));
        b.extend(le(0));
        for c in chunks {
            b.extend(chunk_bytes(c, blk));
        }
        b
    }

    fn image(total_blks: u32, chunks: &[C]) -> Vec<u8> {
        image_with(BLK, total_blks, chunks)
    }

    fn run(inputs: Vec<Vec<u8>>) -> Result<Vec<u8>> {
        let mut out = Cursor::new(Vec::new());
        unsparse(inputs.into_iter().map(Cursor::new).collect(), &mut out)?;
        Ok(out.into_inner())
    }

    fn one(img: Vec<u8>) -> Result<Vec<u8>> {
        run(vec![img])
    }

    fn err(img: Vec<u8>) -> String {
        format!("{:#}", one(img).unwrap_err())
    }

    fn blocks(b: u8, n: usize) -> Vec<u8> {
        vec![b; BLK as usize * n]
    }

    #[test]
    fn every_chunk_type_lands_at_its_offset() {
        let img = image(
            7,
            &[
                C::Raw(blocks(1, 2)),
                C::Fill(0x0403_0201, 2),
                C::Skip(1),
                C::Raw(blocks(9, 1)),
                C::Skip(1),
            ],
        );
        let out = one(img).unwrap();
        let mut want = blocks(1, 2);
        want.extend([1, 2, 3, 4, 1, 2, 3, 4].repeat(2)); // fill pattern is little-endian bytes 01 02 03 04
        want.extend(blocks(0, 1));
        want.extend(blocks(9, 1));
        want.extend(blocks(0, 1));
        assert_eq!(out, want);
    }

    #[test]
    fn output_is_full_size_even_when_it_ends_with_a_gap() {
        assert_eq!(
            one(image(5, &[C::Raw(blocks(3, 1)), C::Skip(4)]))
                .unwrap()
                .len(),
            5 * BLK as usize
        );
        assert_eq!(one(image(0, &[])).unwrap().len(), 0);
    }

    #[test]
    fn fill_larger_than_the_copy_buffer_repeats_correctly() {
        let n = (COPY_BUF as u32 / BLK) * 2 + 3; // spans several buffers, not aligned to them
        let out = one(image(n, &[C::Fill(0xDEAD_BEEF, n)])).unwrap();
        assert_eq!(out.len(), n as usize * BLK as usize);
        assert!(out.chunks(4).all(|c| c == [0xEF, 0xBE, 0xAD, 0xDE]));
    }

    #[test]
    fn raw_larger_than_the_copy_buffer_is_copied_whole() {
        let n = (COPY_BUF as u32 / BLK) + 5;
        let data: Vec<u8> = (0..n as usize * BLK as usize)
            .map(|i| (i % 251) as u8)
            .collect();
        assert_eq!(one(image(n, &[C::Raw(data.clone())])).unwrap(), data);
    }

    #[test]
    fn a_correct_crc_chunk_passes_and_a_wrong_one_fails() {
        let data = [blocks(1, 1), blocks(2, 1), blocks(0, 1)].concat(); // incl. a DONT_CARE gap = zeros
        let crc = crc32fast::hash(&data);
        let ok = image(
            3,
            &[
                C::Raw(blocks(1, 1)),
                C::Raw(blocks(2, 1)),
                C::Skip(1),
                C::Crc(crc),
            ],
        );
        assert_eq!(one(ok).unwrap(), data);
        let bad = image(
            3,
            &[
                C::Raw(blocks(1, 1)),
                C::Raw(blocks(2, 1)),
                C::Skip(1),
                C::Crc(crc ^ 1),
            ],
        );
        assert!(err(bad).contains("checksum mismatch"));
        // a CRC chunk only covers what came before it
        let mid = image(
            2,
            &[
                C::Raw(blocks(1, 1)),
                C::Crc(crc32fast::hash(&blocks(1, 1))),
                C::Raw(blocks(2, 1)),
            ],
        );
        assert!(one(mid).is_ok());
    }

    #[test]
    fn zeros_crc_equals_hashing_the_zeros_one_by_one() {
        for n in [
            0u64,
            1,
            2,
            3,
            4,
            7,
            8,
            255,
            256,
            4095,
            4096,
            4097,
            65_536,
            1_000_003,
            COPY_BUF as u64,
            COPY_BUF as u64 + 13,
            5 * COPY_BUF as u64 + 3,
        ] {
            let want = crc32fast::hash(&vec![0u8; n as usize]);
            assert_eq!(zeros_crc(n).finalize(), want, "{n} zero bytes");
        }
    }

    #[test]
    fn zeros_crc_composes_with_data_on_both_sides() {
        let (before, after) = (b"before".as_slice(), b"after!".as_slice());
        let mut all = before.to_vec();
        all.extend(vec![0u8; 12345]);
        all.extend(after);
        let mut h = crc32fast::Hasher::new();
        h.update(before);
        h.combine(&zeros_crc(12345));
        h.update(after);
        assert_eq!(h.finalize(), crc32fast::hash(&all));
    }

    /// A writer that only counts, so a test can "write" a terabyte without allocating it.
    struct Sink {
        pos: u64,
        end: u64,
        written: u64,
    }

    impl Write for Sink {
        fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
            self.pos += b.len() as u64;
            self.written += b.len() as u64;
            self.end = self.end.max(self.pos);
            Ok(b.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    impl Seek for Sink {
        fn seek(&mut self, to: SeekFrom) -> std::io::Result<u64> {
            if let SeekFrom::Start(p) = to {
                self.pos = p;
            }
            Ok(self.pos)
        }
    }

    #[test]
    fn a_huge_dont_care_gap_is_instant_and_writes_nothing() {
        // 40 bytes claiming 1 TiB of DONT_CARE: it once burned CPU hashing a terabyte of zeros
        let blocks = 1u32 << 28; // 2^28 blocks of 4096 bytes = 1 TiB
        let img = image_with(4096, blocks, &[C::Skip(blocks)]);
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let mut sink = Sink {
                pos: 0,
                end: 0,
                written: 0,
            };
            let res = unsparse(vec![Cursor::new(img)], &mut sink).map(|h| h.image_bytes());
            let _ = tx.send((res.map_err(|e| format!("{e:#}")), sink.written));
        });
        let (res, written) = rx
            .recv_timeout(std::time::Duration::from_secs(20))
            .expect("a DONT_CARE gap must not cost time proportional to its size");
        assert_eq!(res.unwrap(), 1 << 40);
        assert_eq!(
            written, 1,
            "only the last byte is written to extend the file"
        );
    }

    #[test]
    fn a_checksum_after_a_huge_gap_is_still_verified() {
        let blocks = 1u32 << 20; // 4 GiB of zeros
        let expect = {
            let mut h = crc32fast::Hasher::new();
            h.update(&blocks_of(1, 1));
            h.combine(&zeros_crc(blocks as u64 * 4096));
            h.finalize()
        };
        let good = image_with(
            4096,
            blocks + 1,
            &[C::Raw(blocks_of(1, 1)), C::Skip(blocks), C::Crc(expect)],
        );
        let bad = image_with(
            4096,
            blocks + 1,
            &[C::Raw(blocks_of(1, 1)), C::Skip(blocks), C::Crc(expect ^ 1)],
        );
        let run_sink = |img: Vec<u8>| {
            let mut sink = Sink {
                pos: 0,
                end: 0,
                written: 0,
            };
            unsparse(vec![Cursor::new(img)], &mut sink).map(|_| ())
        };
        assert!(run_sink(good).is_ok());
        assert!(format!("{:#}", run_sink(bad).unwrap_err()).contains("checksum mismatch"));
    }

    fn blocks_of(b: u8, n: usize) -> Vec<u8> {
        vec![b; 4096 * n]
    }

    #[test]
    fn the_real_format_bytes_are_what_we_read_and_write() {
        // literal bytes from sparse_format.h: magic 0xed26ff3a, RAW 0xcac1, FILL 0xcac2,
        // DONT_CARE 0xcac3, CRC32 0xcac4, all little-endian; this is what img2simg produces
        let mut img = vec![0x3a, 0xff, 0x26, 0xed, 1, 0, 0, 0, 28, 0, 12, 0];
        img.extend([8, 0, 0, 0]); // block size 8
        img.extend([4, 0, 0, 0]); // 4 blocks
        img.extend([4, 0, 0, 0]); // 4 chunks
        img.extend([0, 0, 0, 0]); // image checksum
        img.extend([0xc1, 0xca, 0, 0, 1, 0, 0, 0, 20, 0, 0, 0]);
        img.extend([1, 2, 3, 4, 5, 6, 7, 8]);
        img.extend([0xc2, 0xca, 0, 0, 1, 0, 0, 0, 16, 0, 0, 0]);
        img.extend([0xAA, 0xBB, 0xCC, 0xDD]);
        img.extend([0xc3, 0xca, 0, 0, 1, 0, 0, 0, 12, 0, 0, 0]);
        img.extend([0xc3, 0xca, 0, 0, 1, 0, 0, 0, 12, 0, 0, 0]);
        let out = one(img.clone()).unwrap();
        assert_eq!(
            out,
            [
                1, 2, 3, 4, 5, 6, 7, 8, // RAW block
                0xAA, 0xBB, 0xCC, 0xDD, 0xAA, 0xBB, 0xCC, 0xDD, // FILL block
                0, 0, 0, 0, 0, 0, 0, 0, // DONT_CARE
                0, 0, 0, 0, 0, 0, 0, 0, // DONT_CARE
            ]
        );

        // and a CRC32 chunk, whose checksum is the IEEE crc32 of the image so far
        let crc = crc32fast::hash(&out);
        img[20..24].copy_from_slice(&le(5));
        img.extend([0xc4, 0xca, 0, 0, 0, 0, 0, 0, 16, 0, 0, 0]);
        img.extend(crc.to_le_bytes());
        assert_eq!(one(img).unwrap(), out);
        assert_eq!(
            crc32fast::hash(b"123456789"),
            0xCBF4_3926,
            "IEEE CRC-32 check value"
        );
    }

    #[test]
    fn crc_covers_fill_chunks_too() {
        let mut data = Vec::new();
        data.extend([1u8, 2, 3, 4].repeat(2));
        data.extend(blocks(5, 1));
        let ok = image(
            2,
            &[
                C::Fill(0x0403_0201, 1),
                C::Raw(blocks(5, 1)),
                C::Crc(crc32fast::hash(&data)),
            ],
        );
        assert_eq!(one(ok).unwrap(), data);
        let bad = image(
            2,
            &[
                C::Fill(0x0403_0201, 1),
                C::Raw(blocks(5, 1)),
                C::Crc(crc32fast::hash(&blocks(5, 1))),
            ],
        );
        assert!(err(bad).contains("checksum mismatch"));
    }

    #[test]
    fn header_errors_are_reported() {
        let good = image(1, &[C::Raw(blocks(1, 1))]);
        assert!(one(good.clone()).is_ok());
        let patch = |at: usize, bytes: &[u8]| {
            let mut b = good.clone();
            b[at..at + bytes.len()].copy_from_slice(bytes);
            b
        };
        assert!(err(patch(0, b"XXXX")).contains("bad magic"));
        assert!(err(patch(4, &2u16.to_le_bytes())).contains("major version 2"));
        assert!(err(patch(8, &27u16.to_le_bytes())).contains("file header size 27"));
        assert!(err(patch(10, &11u16.to_le_bytes())).contains("chunk header size 11"));
        assert!(err(patch(12, &le(0))).contains("invalid sparse block size 0"));
        assert!(err(patch(12, &le(6))).contains("invalid sparse block size 6"));
        assert!(err(good[..10].to_vec()).contains("too short"));
        assert!(err(vec![]).contains("too short"));
    }

    #[test]
    fn chunk_errors_are_reported() {
        let raw = |total_sz: u32, chunk_sz: u32| {
            let mut c = chunk_bytes(&C::Raw(blocks(1, 1)), BLK);
            c[4..8].copy_from_slice(&le(chunk_sz));
            c[8..12].copy_from_slice(&le(total_sz));
            c
        };
        let with = |chunk: Vec<u8>, total: u32| {
            let mut b = image(total, &[]);
            b[20..24].copy_from_slice(&le(1));
            b.extend(chunk);
            b
        };
        assert!(err(with(raw(12 + BLK + 1, 1), 1)).contains("RAW payload is 9 bytes, expected 8"));
        assert!(err(with(raw(5, 1), 1)).contains("smaller than its header"));
        assert!(err(with(raw(12 + BLK, 2), 1)).contains("RAW payload is 8 bytes, expected 16"));
        let mut fill = chunk_bytes(&C::Fill(1, 1), BLK);
        fill[8..12].copy_from_slice(&le(20));
        assert!(err(with(fill, 1)).contains("FILL payload is 8 bytes, expected 4"));
        let mut dc = chunk_bytes(&C::Skip(1), BLK);
        dc[8..12].copy_from_slice(&le(16));
        assert!(err(with(dc, 1)).contains("DONT_CARE has 4 payload bytes"));
        let mut crc = chunk_bytes(&C::Crc(0), BLK);
        crc[8..12].copy_from_slice(&le(12));
        assert!(err(with(crc, 1)).contains("CRC32 payload is 0 bytes, expected 4"));
        let mut unknown = chunk_bytes(&C::Skip(1), BLK);
        unknown[0..2].copy_from_slice(&0xCAFEu16.to_le_bytes());
        assert!(err(with(unknown, 1)).contains("unknown chunk type 0xcafe"));
    }

    #[test]
    fn block_accounting_must_match_the_header() {
        assert!(
            err(image(3, &[C::Raw(blocks(1, 2))])).contains("cover 2 blocks but the header says 3")
        );
        assert!(err(image(1, &[C::Raw(blocks(1, 2))])).contains("past the end"));
        assert!(err(image(2, &[C::Raw(blocks(1, 1)), C::Skip(2)])).contains("past the end"));
        assert!(err(image(2, &[C::Fill(1, 3)])).contains("past the end"));
    }

    #[test]
    fn truncated_input_is_an_error_everywhere() {
        let img = image(4, &[C::Raw(blocks(1, 2)), C::Fill(7, 1), C::Skip(1)]);
        for cut in 0..img.len() {
            assert!(
                one(img[..cut].to_vec()).is_err(),
                "cut at {cut} of {}",
                img.len()
            );
        }
        assert!(one(img).is_ok());
        let mut missing_chunks = image(1, &[C::Raw(blocks(1, 1))]);
        missing_chunks[20..24].copy_from_slice(&le(2)); // header promises 2 chunks, 1 present
        assert!(err(missing_chunks).contains("input ends before chunk 1 of 2"));
    }

    #[test]
    fn longer_headers_are_skipped_and_trailing_bytes_ignored() {
        let mut img = Vec::new();
        let base = image(1, &[C::Raw(blocks(5, 1))]);
        img.extend(&base[..8]);
        img.extend(32u16.to_le_bytes()); // file header 4 bytes longer
        img.extend(16u16.to_le_bytes()); // chunk header 4 bytes longer
        img.extend(&base[12..28]);
        img.extend([0xEE; 4]);
        let chunk = chunk_bytes(&C::Raw(blocks(5, 1)), BLK);
        img.extend(&chunk[..8]);
        img.extend(le(16 + BLK));
        img.extend([0xDD; 4]);
        img.extend(&chunk[12..]);
        img.extend(b"trailing signature bytes");
        assert_eq!(one(img).unwrap(), blocks(5, 1));
    }

    #[test]
    fn several_files_for_one_image_merge_without_erasing_each_other() {
        let a = image(4, &[C::Raw(blocks(1, 2)), C::Skip(2)]);
        let b = image(
            4,
            &[C::Skip(2), C::Raw(blocks(2, 1)), C::Fill(0x0A0A_0A0A, 1)],
        );
        let want = [blocks(1, 2), blocks(2, 1), blocks(0x0A, 1)].concat();
        assert_eq!(run(vec![a.clone(), b.clone()]).unwrap(), want);
        assert_eq!(
            run(vec![b, a]).unwrap(),
            want,
            "order does not matter when the parts do not overlap"
        );
    }

    #[test]
    fn files_describing_different_images_are_rejected() {
        let a = image(4, &[C::Skip(4)]);
        let other_size = image(5, &[C::Skip(5)]);
        let other_block = image_with(16, 4, &[C::Skip(4)]);
        for bad in [other_size, other_block] {
            let e = format!("{:#}", run(vec![a.clone(), bad]).unwrap_err());
            assert!(e.contains("input 2 describes a different image"), "{e}");
        }
        let e = format!(
            "{:#}",
            run(vec![a.clone(), image(4, &[C::Skip(3)])]).unwrap_err()
        );
        assert!(e.contains("input 2") && e.contains("cover 3 blocks"), "{e}");
    }

    #[test]
    fn crc_is_not_checked_when_merging_several_files() {
        let a = image(2, &[C::Raw(blocks(1, 1)), C::Skip(1), C::Crc(0xDEAD_BEEF)]);
        let b = image(2, &[C::Skip(1), C::Raw(blocks(2, 1))]);
        assert!(run(vec![a, b]).is_ok());
    }

    #[test]
    fn absurd_sizes_are_refused_before_any_output() {
        let mut huge = image(1, &[C::Raw(blocks(1, 1))]);
        huge[12..16].copy_from_slice(&le(1 << 20));
        huge[16..20].copy_from_slice(&le(u32::MAX));
        assert!(err(huge).contains("larger than the"));
        let mut max = image(1, &[C::Raw(blocks(1, 1))]);
        max[12..16].copy_from_slice(&le(u32::MAX - 3)); // multiple of 4, product < u64::MAX
        max[16..20].copy_from_slice(&le(u32::MAX));
        assert!(err(max).contains("larger than the"));
        assert!(run(vec![]).is_err());
    }

    fn scratch(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "android-doctor-sparse-{}-{tag}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn the_command_writes_the_image_and_refuses_to_overwrite_without_force() {
        let dir = scratch("cmd");
        let (a, b) = (dir.join("a.simg"), dir.join("b.simg"));
        std::fs::write(&a, image(3, &[C::Raw(blocks(1, 1)), C::Skip(2)])).unwrap();
        std::fs::write(&b, image(3, &[C::Skip(1), C::Raw(blocks(2, 2))])).unwrap();
        let out = dir.join("sub/raw.img");
        run_cmd(&[a.clone(), b.clone()], &out, false).unwrap();
        assert_eq!(
            std::fs::read(&out).unwrap(),
            [blocks(1, 1), blocks(2, 2)].concat()
        );
        assert!(!dir.join("sub/raw.img.part").exists());
        std::fs::write(&out, b"keep").unwrap();
        let e = run_cmd(std::slice::from_ref(&a), &out, false).unwrap_err();
        assert!(e.to_string().contains("--force"), "{e}");
        assert_eq!(std::fs::read(&out).unwrap(), b"keep");
        run_cmd(&[a, b], &out, true).unwrap();
        assert_eq!(std::fs::read(&out).unwrap().len(), 3 * BLK as usize);
    }

    fn run_cmd(inputs: &[PathBuf], output: &Path, force: bool) -> Result<()> {
        super::run(inputs, output, force)
    }

    #[test]
    fn a_failed_command_leaves_nothing_behind() {
        let dir = scratch("cmdfail");
        let bad = dir.join("bad.simg");
        let mut img = image(2, &[C::Raw(blocks(1, 1)), C::Raw(blocks(2, 1))]);
        img.truncate(img.len() - 3);
        std::fs::write(&bad, img).unwrap();
        let out = dir.join("raw.img");
        assert!(run_cmd(&[bad], &out, false).is_err());
        assert!(!out.exists() && !dir.join("raw.img.part").exists());
        let e = run_cmd(&[dir.join("missing.simg")], &out, false).unwrap_err();
        assert!(e.to_string().contains("opening"), "{e}");
        assert!(
            !out.exists(),
            "nothing is created when an input cannot be opened"
        );
        let deep = dir.join("nested/deeper/raw.img");
        assert!(run_cmd(&[dir.join("missing.simg")], &deep, false).is_err());
        assert!(
            !dir.join("nested").exists(),
            "no directories are created when an input cannot be opened"
        );
    }
}
