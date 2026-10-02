//! Extract partition images from a block OTA (a zip or an already unpacked directory).
use crate::{sdat, transfer_list};
use anyhow::{Context, Result, bail};
use std::fs::File;
use std::io::{BufReader, BufWriter, Read, Write};
use std::path::{Path, PathBuf};

const LIST_SUFFIX: &str = ".transfer.list";
/// Transfer lists are a few KiB; the cap stops a hostile zip from exhausting memory.
const MAX_LIST_BYTES: u64 = 16 << 20;

/// Where the OTA files come from.
enum Source {
    Zip(zip::ZipArchive<File>),
    Dir(PathBuf),
}

impl Source {
    fn open(input: &Path) -> Result<Self> {
        if input.is_dir() {
            return Ok(Self::Dir(input.to_path_buf()));
        }
        let file = File::open(input).with_context(|| format!("opening {}", input.display()))?;
        Ok(Self::Zip(
            zip::ZipArchive::new(file).context("not a valid zip file")?,
        ))
    }

    /// Names of the files at the top level of the OTA.
    fn names(&self) -> Result<Vec<String>> {
        Ok(match self {
            Self::Zip(zip) => zip
                .file_names()
                .filter(|n| !n.contains('/'))
                .map(String::from)
                .collect(),
            Self::Dir(dir) => std::fs::read_dir(dir)?
                .map(|e| e.map(|e| e.file_name().to_string_lossy().into_owned()))
                .collect::<std::io::Result<_>>()?,
        })
    }

    fn open_file(&mut self, name: &str) -> Result<Box<dyn Read + '_>> {
        let reader: Box<dyn Read + '_> = match self {
            Self::Zip(zip) => Box::new(
                zip.by_name(name)
                    .with_context(|| format!("{name} not found in zip"))?,
            ),
            Self::Dir(dir) => {
                Box::new(File::open(dir.join(name)).with_context(|| format!("opening {name}"))?)
            }
        };
        Ok(reader)
    }
}

/// Build `<part>.img` in `out_dir`. The image is written under a temporary name and renamed
/// when complete, so a failed extraction never leaves a plausible-looking partial image.
fn extract_partition(
    src: &mut Source,
    names: &[String],
    part: &str,
    out_dir: &Path,
) -> Result<PathBuf> {
    let mut list_text = String::new();
    src.open_file(&format!("{part}{LIST_SUFFIX}"))?
        .take(MAX_LIST_BYTES + 1)
        .read_to_string(&mut list_text)?;
    if list_text.len() as u64 > MAX_LIST_BYTES {
        bail!("{part}{LIST_SUFFIX} is larger than {MAX_LIST_BYTES} bytes");
    }
    let list = transfer_list::parse(&list_text).with_context(|| format!("{part}{LIST_SUFFIX}"))?;

    let br = format!("{part}.new.dat.br");
    let raw = format!("{part}.new.dat");
    let (data_name, compressed) = if names.contains(&br) {
        (br, true)
    } else if names.contains(&raw) {
        (raw, false)
    } else {
        bail!("{part}: neither {br} nor {raw} found");
    };
    let data = BufReader::new(src.open_file(&data_name)?);

    let final_path = out_dir.join(format!("{part}.img"));
    let tmp_path = out_dir.join(format!("{part}.img.part"));
    let built = (|| -> Result<()> {
        let mut out = BufWriter::new(File::create(&tmp_path)?);
        if compressed {
            sdat::apply(&list, sdat::brotli_reader(data), &mut out)?;
        } else {
            sdat::apply(&list, data, &mut out)?;
        }
        out.flush()?;
        Ok(())
    })();
    if let Err(e) = built {
        let _ = std::fs::remove_file(&tmp_path);
        return Err(e.context(format!("extracting {part}")));
    }
    std::fs::rename(&tmp_path, &final_path)?;
    Ok(final_path)
}

/// Extract every partition found in the OTA into `out_dir`, printing one line per image.
pub fn run(input: &Path, out_dir: &Path) -> Result<()> {
    let mut src = Source::open(input)?;
    let names = src.names()?;
    let mut parts: Vec<&str> = names
        .iter()
        .filter_map(|n| n.strip_suffix(LIST_SUFFIX))
        .collect();
    parts.sort_unstable();
    if parts.is_empty() {
        bail!(
            "no *{LIST_SUFFIX} files found: not a block OTA (payload.bin OTAs are not supported)"
        );
    }
    let safe = |p: &str| {
        !p.is_empty()
            && p.chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
    };
    if let Some(bad) = parts.iter().find(|p| !safe(p)) {
        bail!("unsafe partition name {bad:?}");
    }
    std::fs::create_dir_all(out_dir)?;
    for part in parts {
        let path = extract_partition(&mut src, &names, part, out_dir)?;
        println!(
            "{}  {} bytes",
            path.display(),
            std::fs::metadata(&path)?.len()
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const BLOCK: usize = sdat::BLOCK_SIZE;

    fn blk(b: u8) -> Vec<u8> {
        vec![b; BLOCK]
    }

    fn brotli(data: &[u8]) -> Vec<u8> {
        let mut packed = Vec::new();
        brotli::CompressorWriter::new(&mut packed, 4096, 5, 22)
            .write_all(data)
            .unwrap();
        packed
    }

    fn fresh_dir(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("android-doctor-{}-{tag}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    /// Partition `a` is brotli-compressed (blocks 1,2), `b` is raw (block 9).
    fn sample_files() -> Vec<(&'static str, Vec<u8>)> {
        vec![
            ("a.transfer.list", b"4\n2\n0\n0\nnew 2,0,2\n".to_vec()),
            ("a.new.dat.br", brotli(&[blk(1), blk(2)].concat())),
            ("b.transfer.list", b"4\n1\n0\n0\nnew 2,0,1\n".to_vec()),
            ("b.new.dat", blk(9)),
        ]
    }

    fn write_dir(dir: &Path, files: &[(&str, Vec<u8>)]) {
        for (name, body) in files {
            std::fs::write(dir.join(name), body).unwrap();
        }
    }

    fn check_sample_output(out: &Path) {
        assert_eq!(
            std::fs::read(out.join("a.img")).unwrap(),
            [blk(1), blk(2)].concat()
        );
        assert_eq!(std::fs::read(out.join("b.img")).unwrap(), blk(9));
    }

    #[test]
    fn extracts_every_partition_from_a_directory() {
        let (ota, out) = (fresh_dir("dir-in"), fresh_dir("dir-out"));
        write_dir(&ota, &sample_files());
        run(&ota, &out).unwrap();
        check_sample_output(&out);
    }

    #[test]
    fn extracts_every_partition_from_a_zip() {
        let (work, out) = (fresh_dir("zip-in"), fresh_dir("zip-out"));
        let zip_path = work.join("ota.zip");
        let mut w = zip::ZipWriter::new(File::create(&zip_path).unwrap());
        for (name, body) in sample_files() {
            w.start_file(name, zip::write::SimpleFileOptions::default())
                .unwrap();
            w.write_all(&body).unwrap();
        }
        w.finish().unwrap();
        run(&zip_path, &out).unwrap();
        check_sample_output(&out);
    }

    #[test]
    fn nested_zip_entries_are_ignored() {
        let (work, out) = (fresh_dir("nest-in"), fresh_dir("nest-out"));
        let zip_path = work.join("ota.zip");
        let mut w = zip::ZipWriter::new(File::create(&zip_path).unwrap());
        let nested = ("nested/z.transfer.list", b"junk".to_vec());
        for (name, body) in sample_files().into_iter().chain([nested]) {
            w.start_file(name, zip::write::SimpleFileOptions::default())
                .unwrap();
            w.write_all(&body).unwrap();
        }
        w.finish().unwrap();
        run(&zip_path, &out).unwrap();
        check_sample_output(&out);
        assert!(!out.join("z.img").exists());
    }

    #[test]
    fn input_without_transfer_lists_is_an_error() {
        let (ota, out) = (fresh_dir("none-in"), fresh_dir("none-out"));
        write_dir(&ota, &[("readme.txt", b"hi".to_vec())]);
        let e = run(&ota, &out).unwrap_err();
        assert!(e.to_string().contains("not a block OTA"), "{e}");
    }

    #[test]
    fn missing_data_file_is_an_error() {
        let (ota, out) = (fresh_dir("nodata-in"), fresh_dir("nodata-out"));
        write_dir(
            &ota,
            &[("a.transfer.list", b"4\n1\n0\n0\nnew 2,0,1\n".to_vec())],
        );
        let e = run(&ota, &out).unwrap_err();
        assert!(
            e.to_string().contains("neither a.new.dat.br nor a.new.dat"),
            "{e}"
        );
    }

    #[test]
    fn failed_extraction_leaves_no_image_behind() {
        let (ota, out) = (fresh_dir("bad-in"), fresh_dir("bad-out"));
        write_dir(
            &ota,
            &[
                ("a.transfer.list", b"4\n1\n0\n0\nnew 2,0,1\n".to_vec()),
                ("a.new.dat.br", vec![0xff; BLOCK]),
            ],
        );
        assert!(run(&ota, &out).is_err());
        assert!(!out.join("a.img").exists());
        assert!(!out.join("a.img.part").exists());
    }

    #[test]
    fn unsafe_partition_names_are_rejected() {
        let (ota, out) = (fresh_dir("name-in"), fresh_dir("name-out"));
        write_dir(&ota, &[("we ird.transfer.list", b"4\n0\n0\n0\n".to_vec())]);
        let e = run(&ota, &out).unwrap_err();
        assert!(e.to_string().contains("unsafe partition name"), "{e}");
    }
}
