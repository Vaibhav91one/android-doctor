//! Build a raw partition image from block-OTA data (`*.new.dat`) following a transfer list.
use crate::transfer_list::{Command, TransferList};
use anyhow::{Context, Result, bail};
use std::io::{Read, Seek, SeekFrom, Write};

pub const BLOCK_SIZE: usize = 4096;

fn command_ranges(cmd: &Command) -> &[(u64, u64)] {
    let (Command::New(r) | Command::Zero(r) | Command::Erase(r)) = cmd;
    r
}

/// Decompress a `.new.dat.br` stream on the fly, so no temporary `.new.dat` file is needed.
pub fn brotli_reader<R: Read>(input: R) -> impl Read {
    brotli::Decompressor::new(input, 64 * 1024)
}

/// Size in bytes of the image a transfer list describes. Header line 2 only counts the blocks
/// written; the image spans the furthest range of any command (an `erase` usually reaches the
/// end of the partition).
pub fn image_size(list: &TransferList) -> Result<u64> {
    let end = list
        .commands
        .iter()
        .flat_map(command_ranges)
        .map(|&(_, end)| end)
        .max()
        .unwrap_or(0);
    end.checked_mul(BLOCK_SIZE as u64)
        .context("image size overflows")
}

/// Build the image described by `list` into `out`, reading the contents of `new` ranges from
/// `data` in order. `zero` and `erase` ranges stay zero, so `out` must start empty.
pub fn apply<R: Read, W: Write + Seek>(
    list: &TransferList,
    mut data: R,
    out: &mut W,
) -> Result<()> {
    let size = image_size(list)?;
    if size > 0 {
        out.seek(SeekFrom::Start(size - 1))?;
        out.write_all(&[0])?;
    }
    let mut block = [0u8; BLOCK_SIZE];
    for cmd in &list.commands {
        if let Command::New(ranges) = cmd {
            for &(start, end) in ranges {
                out.seek(SeekFrom::Start(start * BLOCK_SIZE as u64))?;
                for _ in start..end {
                    data.read_exact(&mut block)
                        .context("data ended before all new blocks were written")?;
                    out.write_all(&block)?;
                }
            }
        }
    }
    if data.read(&mut [0u8; 1])? != 0 {
        bail!("data has more blocks than the transfer list describes");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transfer_list;
    use std::io::Cursor;

    fn blk(b: u8) -> Vec<u8> {
        vec![b; BLOCK_SIZE]
    }

    fn run(list: &str, data: Vec<u8>) -> Result<Vec<u8>> {
        let list = transfer_list::parse(list)?;
        let mut out = Cursor::new(Vec::new());
        apply(&list, Cursor::new(data), &mut out)?;
        Ok(out.into_inner())
    }

    fn assert_blocks(img: &[u8], expect: &[u8]) {
        assert_eq!(img.len(), expect.len() * BLOCK_SIZE);
        for (i, &b) in expect.iter().enumerate() {
            assert_eq!(
                img[i * BLOCK_SIZE..(i + 1) * BLOCK_SIZE],
                blk(b)[..],
                "block {i}"
            );
        }
    }

    #[test]
    fn writes_new_blocks_in_order_at_their_offsets() {
        let data = [blk(1), blk(2), blk(3)].concat();
        let img = run("4\n6\n0\n0\nnew 4,0,1,4,6\n", data).unwrap();
        assert_blocks(&img, &[1, 0, 0, 0, 2, 3]);
    }

    #[test]
    fn zero_and_erase_stay_zero_and_count_toward_size() {
        let img = run("4\n3\n0\n0\nnew 2,0,1\nzero 2,1,2\nerase 2,2,3\n", blk(7)).unwrap();
        assert_blocks(&img, &[7, 0, 0]);
    }

    #[test]
    fn short_data_is_an_error() {
        let e = run("4\n2\n0\n0\nnew 2,0,2\n", blk(1)).unwrap_err();
        assert!(e.to_string().contains("ended before"), "{e}");
    }

    #[test]
    fn extra_data_is_an_error() {
        let e = run("4\n2\n0\n0\nnew 2,0,1\n", [blk(1), blk(2)].concat()).unwrap_err();
        assert!(e.to_string().contains("more blocks"), "{e}");
    }

    #[test]
    fn image_spans_the_furthest_range_of_any_command() {
        // header count (1) is smaller than where the ranges end, as in real lists
        let img = run("4\n1\n0\n0\nnew 2,4,5\nerase 2,5,6\n", blk(7)).unwrap();
        assert_blocks(&img, &[0, 0, 0, 0, 7, 0]);
        let img = run("4\n1\n0\n0\nnew 2,0,1\nerase 2,3,6\n", blk(7)).unwrap();
        assert_blocks(&img, &[7, 0, 0, 0, 0, 0]);
        let img = run("4\n1\n0\n0\nnew 2,0,1\nzero 2,1,4\n", blk(7)).unwrap();
        assert_blocks(&img, &[7, 0, 0, 0]);
    }

    #[test]
    fn image_size_is_the_furthest_range_end_in_bytes() {
        let size = |t: &str| image_size(&transfer_list::parse(t).unwrap()).unwrap();
        assert_eq!(
            size("4\n1\n0\n0\nnew 2,4,5\nerase 2,5,6\n"),
            6 * BLOCK_SIZE as u64
        );
        assert_eq!(
            size("4\n9\n0\n0\nnew 2,0,1\nzero 2,1,3\n"),
            3 * BLOCK_SIZE as u64
        );
        assert_eq!(size("4\n0\n0\n0\n"), 0);
        let huge = transfer_list::parse("4\n1\n0\n0\nerase 2,0,18446744073709551615\n").unwrap();
        assert!(image_size(&huge).is_err());
    }

    #[test]
    fn absurd_range_end_is_an_error() {
        let e = run("4\n1\n0\n0\nerase 2,0,18446744073709551615\n", vec![]).unwrap_err();
        assert!(e.to_string().contains("overflows"), "{e}");
    }

    #[test]
    fn brotli_stream_round_trips_into_an_image() {
        let mut packed = Vec::new();
        {
            let mut w = brotli::CompressorWriter::new(&mut packed, 4096, 5, 22);
            w.write_all(&[blk(1), blk(2)].concat()).unwrap();
        }
        let list = transfer_list::parse("4\n3\n0\n0\nnew 2,0,1\nnew 2,2,3\n").unwrap();
        let mut out = Cursor::new(Vec::new());
        apply(&list, brotli_reader(Cursor::new(packed)), &mut out).unwrap();
        assert_blocks(&out.into_inner(), &[1, 0, 2]);
    }

    #[test]
    fn corrupt_brotli_input_is_an_error() {
        let list = transfer_list::parse("4\n1\n0\n0\nnew 2,0,1\n").unwrap();
        let mut out = Cursor::new(Vec::new());
        let bad = Cursor::new(vec![0xffu8; BLOCK_SIZE]);
        assert!(apply(&list, brotli_reader(bad), &mut out).is_err());
    }
}
