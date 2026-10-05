//! The bsdiff patch format used by Android incremental updates.
//!
//! A BSDIFF4 patch is:
//!
//! ```
//! header : "BSDIFF40" (8 bytes), then three int64 little-endian: ctrl_len, diff_len, new_size
//! ctrl   : ctrl_len bytes of bzip2 stream holding i64 triples (x, y, z)
//! diff   : diff_len bytes of bzip2 stream
//! extra  : bzip2 stream holding bytes copied verbatim from the target
//! ```
//!
//! Applying it (the original bsdiff algorithm):
//!
//! ```
//! oldpos = 0; newpos = 0
//! while newpos < new_size:
//!     read (x, y, z) from ctrl
//!     read x bytes from diff, ADD the corresponding bytes from old at oldpos
//!     read y bytes from extra verbatim
//!     oldpos += x; newpos += x + y
//! ```
//!
//! `x` and `z` are SIGNED: a negative `z` seeks backwards into the source. Getting that wrong
//! yields a plausible-looking but wrong image, so the bounds are checked on every step.
//!
//! Format from the original bsdiff (BSD licensed); the Android variant is unchanged.
use anyhow::{Context, Result, ensure};
use std::io::Read;

/// Refuse absurd headers rather than allocating from a file-supplied size.
const MAX_PATCH: usize = 1 << 31;

fn i64le(b: &[u8], at: usize) -> Result<i64> {
    ensure!(at + 8 <= b.len(), "bsdiff: truncated");
    let mut v = [0u8; 8];
    v.copy_from_slice(&b[at..at + 8]);
    Ok(i64::from_le_bytes(v))
}

/// Decompress a bzip2 block, refusing an implausible declared size.
fn inflate(block: &[u8], expected_hint: Option<usize>, what: &str) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    bzip2::read::BzDecoder::new(block)
        .read_to_end(&mut out)
        .with_context(|| format!("bsdiff: {what} block is not valid bzip2"))?;
    if let Some(hint) = expected_hint {
        ensure!(
            out.len() <= hint,
            "bsdiff: {what} block is larger than declared"
        );
    }
    Ok(out)
}

/// Apply a BSDIFF4 patch to `old`, returning the new contents.
pub fn apply(patch: &[u8], old: &[u8]) -> Result<Vec<u8>> {
    ensure!(patch.len() >= 32, "bsdiff: patch is truncated");
    ensure!(&patch[..8] == b"BSDIFF40", "bsdiff: bad magic");
    let ctrl_len = i64le(patch, 8)?;
    let diff_len = i64le(patch, 16)?;
    let new_size = i64le(patch, 24)?;

    ensure!(
        ctrl_len >= 0 && diff_len >= 0,
        "bsdiff: negative block length"
    );
    ensure!(new_size >= 0, "bsdiff: negative output size");
    ensure!(
        new_size as usize <= MAX_PATCH,
        "bsdiff: implausible output size {new_size}"
    );
    let ctrl_len = ctrl_len as usize;
    let diff_len = diff_len as usize;
    ensure!(
        32usize
            .checked_add(ctrl_len)
            .and_then(|v| v.checked_add(diff_len))
            .is_some_and(|v| v <= patch.len()),
        "bsdiff: block lengths run past the end of the patch"
    );

    let ctrl = inflate(&patch[32..32 + ctrl_len], None, "ctrl")?;
    ensure!(
        ctrl.len() % 24 == 0,
        "bsdiff: ctrl block is not a whole number of triples"
    );
    let diff = inflate(
        &patch[32 + ctrl_len..32 + ctrl_len + diff_len],
        None,
        "diff",
    )?;
    // The extra block runs to the end of the patch; bzip2 stops at its own stream end.
    let extra = inflate(
        &patch[32 + ctrl_len + diff_len..],
        Some(new_size as usize),
        "extra",
    )?;

    let new_size = new_size as usize;
    let mut new = Vec::with_capacity(new_size.min(1 << 26));
    // THREE separate cursors: ctrl, diff and extra advance independently. Sharing one index
    // between them reads past the end of the diff block on the very first triple.
    let mut ctrl_pos = 0usize;
    let mut diff_pos = 0usize;
    let mut extra_pos = 0usize;
    let mut old_pos: i64 = 0;

    while new.len() < new_size {
        ensure!(
            ctrl_pos + 24 <= ctrl.len(),
            "bsdiff: ran out of control triples with {} bytes left",
            new_size - new.len()
        );
        let x = i64le(&ctrl, ctrl_pos)?;
        let y = i64le(&ctrl, ctrl_pos + 8)?;
        let z = i64le(&ctrl, ctrl_pos + 16)?;
        ctrl_pos += 24;

        // x and y are counts and cannot be negative. z IS a signed seek and is routinely
        // negative - rejecting it would reject most real patches.
        ensure!(
            x >= 0 && y >= 0,
            "bsdiff: negative count in control triple ({x},{y},{z})"
        );
        let x = x as usize;
        let y = y as usize;

        // Adding diff to the corresponding source range.
        let src_end = old_pos
            .checked_add(x as i64)
            .context("bsdiff: source offset overflow")?;
        ensure!(
            src_end >= 0 && src_end as usize <= old.len(),
            "bsdiff: patch reads past the source"
        );
        ensure!(
            new.len() + x <= new_size,
            "bsdiff: control triple overruns the output size"
        );
        for i in 0..x {
            let d = *diff
                .get(diff_pos + i)
                .context("bsdiff: ran out of diff data")?;
            let s = old[old_pos as usize + i];
            new.push(d.wrapping_add(s));
        }
        diff_pos += x;

        // Bytes copied verbatim from the extra block.
        ensure!(
            new.len() + y <= new_size,
            "bsdiff: extra run overruns the output size"
        );
        ensure!(
            extra_pos + y <= extra.len(),
            "bsdiff: ran out of extra data"
        );
        new.extend_from_slice(&extra[extra_pos..extra_pos + y]);
        extra_pos += y;

        old_pos += x as i64 + z;
    }

    ensure!(
        new.len() == new_size,
        "bsdiff: produced {} bytes, header said {new_size}",
        new.len()
    );
    Ok(new)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn bz(data: &[u8]) -> Vec<u8> {
        let mut e = bzip2::write::BzEncoder::new(Vec::new(), bzip2::Compression::default());
        e.write_all(data).unwrap();
        e.finish().unwrap()
    }

    /// Build a BSDIFF4 patch turning `old` into `new` for these simple cases.
    fn patch(new: &[u8], ctrl: &[(i64, i64, i64)], diff: &[u8], extra: &[u8]) -> Vec<u8> {
        let ctrl_raw: Vec<u8> = ctrl
            .iter()
            .flat_map(|(x, y, z)| {
                [x.to_le_bytes(), y.to_le_bytes(), z.to_le_bytes()]
                    .into_iter()
                    .flatten()
                    .collect::<Vec<u8>>()
            })
            .collect();
        let c = bz(&ctrl_raw);
        let d = bz(diff);
        let e = bz(extra);
        let mut out = Vec::new();
        out.extend_from_slice(b"BSDIFF40");
        out.extend_from_slice(&(c.len() as i64).to_le_bytes());
        out.extend_from_slice(&(d.len() as i64).to_le_bytes());
        out.extend_from_slice(&(new.len() as i64).to_le_bytes());
        out.extend_from_slice(&c);
        out.extend_from_slice(&d);
        out.extend_from_slice(&e);
        out
    }

    #[test]
    fn an_extra_only_patch_reproduces_the_output() {
        // x = 0 (no diff bytes), y = len (all from extra).
        let want = b"hello world".to_vec();
        let p = patch(&want, &[(0, 11, 0)], &[], &want);
        assert_eq!(apply(&p, b"").unwrap(), want);
    }

    #[test]
    fn a_diff_patch_adds_source_bytes() {
        // old = "ABC", diff = 3 zero bytes => each output byte equals the source byte.
        let old = b"ABC";
        let diff = vec![0u8, 0, 0];
        let p = patch(b"ABC", &[(3, 0, 0)], &diff, &[]);
        assert_eq!(apply(&p, old).unwrap(), b"ABC");
    }

    #[test]
    fn diff_and_extra_interleave_in_one_control_triple() {
        let old = b"XY";
        // 2 bytes from diff (unchanged) then 2 bytes from extra ("zz").
        let diff = vec![0u8, 0];
        let p = patch(b"XYzz", &[(2, 2, 0)], &diff, b"zz");
        assert_eq!(apply(&p, old).unwrap(), b"XYzz");
    }

    #[test]
    fn a_negative_seek_in_z_is_honoured() {
        // Second triple reads BACK one byte from the source: old = "abcd".
        let old = b"abcd";
        let p = patch(b"abcda", &[(4, 0, -4), (1, 0, 0)], &[0, 0, 0, 0, 0], b"");
        assert_eq!(apply(&p, old).unwrap(), b"abcda");
    }

    #[test]
    fn a_bad_magic_is_refused() {
        let mut p = patch(b"x", &[(0, 1, 0)], &[], b"x");
        p[0] = b'X';
        assert!(apply(&p, b"").is_err());
    }

    #[test]
    fn a_truncated_patch_is_an_error_not_a_panic() {
        let p = patch(b"hello", &[(0, 5, 0)], &[], b"hello");
        for n in [0usize, 8, 16, 31] {
            assert!(apply(&p[..n], b"").is_err(), "cut at {n} must be refused");
        }
    }

    #[test]
    fn a_patch_reading_past_the_source_is_refused() {
        // Claims 10 diff bytes from a 2-byte source.
        let p = patch(&[0u8; 10], &[(10, 0, 0)], &[0u8; 10], &[]);
        assert!(apply(&p, b"ab").is_err());
    }

    #[test]
    fn a_patch_that_overruns_the_declared_size_is_refused() {
        // ctrl claims 5 extra bytes but new_size is 2.
        let p = patch(b"ab", &[(0, 5, 0)], &[], b"hello");
        assert!(apply(&p, b"").is_err());
    }

    #[test]
    fn corrupt_bzip2_blocks_are_an_error() {
        let mut p = patch(b"hello", &[(0, 5, 0)], &[], b"hello");
        // Scribble over the first ctrl block.
        for b in p[32..40].iter_mut() {
            *b = 0xFF;
        }
        assert!(apply(&p, b"").is_err());
    }

    #[test]
    fn an_implausible_output_size_is_refused_without_allocating() {
        let mut p = patch(b"x", &[(0, 1, 0)], &[], b"x");
        p[24..32].copy_from_slice(&i64::MAX.to_le_bytes());
        assert!(apply(&p, b"").is_err());
    }
}
