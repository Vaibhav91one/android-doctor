//! Extract partition images from a block OTA (a zip or an already unpacked directory).
use crate::{sdat, transfer_list};
use anyhow::{Context, Result, anyhow, bail};
use indicatif::{MultiProgress, ProgressBar, ProgressStyle};
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
                .filter(|e| e.as_ref().map_or(true, |e| e.path().is_file()))
                .map(|e| e.map(|e| e.file_name().to_string_lossy().into_owned()))
                .collect::<std::io::Result<_>>()?,
        })
    }

    /// Size in bytes of a top-level file, for the progress bar.
    fn file_size(&mut self, name: &str) -> Result<u64> {
        Ok(match self {
            Self::Zip(zip) => zip.by_name(name)?.size(),
            Self::Dir(dir) => std::fs::metadata(dir.join(name))?.len(),
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
    bar: &ProgressBar,
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
    bar.set_length(src.file_size(&data_name)?);
    let data = BufReader::new(bar.wrap_read(src.open_file(&data_name)?));

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

/// Partition names (from `<part>.transfer.list`) among the top-level file names, sorted.
fn partitions_in(names: &[String]) -> Vec<&str> {
    let mut parts: Vec<&str> = names
        .iter()
        .filter_map(|n| n.strip_suffix(LIST_SUFFIX))
        .collect();
    parts.sort_unstable();
    parts
}

/// Partition names found in an OTA zip or directory (empty for a non-block OTA).
pub fn partition_names(input: &Path) -> Result<Vec<String>> {
    let names = Source::open(input)?.names()?;
    Ok(partitions_in(&names)
        .into_iter()
        .map(String::from)
        .collect())
}

/// Top-level `*.img` files (boot, recovery, dtbo, vbmeta, ...), sorted.
fn raw_images_in(names: &[String]) -> Vec<&str> {
    let mut raw: Vec<&str> = names
        .iter()
        .map(String::as_str)
        .filter(|n| n.ends_with(".img"))
        .collect();
    raw.sort_unstable();
    raw
}

/// Copy a file out of the OTA unchanged (`.part` + rename, like partition images).
fn copy_raw(src: &mut Source, name: &str, out_dir: &Path) -> Result<PathBuf> {
    let final_path = out_dir.join(name);
    let tmp_path = out_dir.join(format!("{name}.part"));
    let copied = (|| -> Result<()> {
        let mut out = File::create(&tmp_path)?;
        std::io::copy(&mut src.open_file(name)?, &mut out)?;
        Ok(())
    })();
    if let Err(e) = copied {
        let _ = std::fs::remove_file(&tmp_path);
        return Err(e.context(format!("copying {name}")));
    }
    std::fs::rename(&tmp_path, &final_path)?;
    Ok(final_path)
}

/// Extract every partition found in the OTA into `out_dir`, one thread per partition, and
/// return the image paths sorted by partition name, followed by the other top-level `*.img`
/// files (boot, recovery, ...) copied as they are. Every partition is attempted; the first
/// error (in partition order) is returned.
pub fn extract_all(input: &Path, out_dir: &Path) -> Result<Vec<PathBuf>> {
    let names = Source::open(input)?.names()?;
    let parts = partitions_in(&names);
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
    let raw = raw_images_in(&names);
    for name in &raw {
        let stem = name.strip_suffix(".img").unwrap_or(name);
        if !safe(stem) {
            bail!("unsafe file name {name:?}");
        }
        if parts.contains(&stem) {
            bail!("{name} conflicts with the {stem} partition rebuilt from {stem}{LIST_SUFFIX}");
        }
    }
    // Names that differ only by case would overwrite each other on case-insensitive filesystems.
    let mut seen = std::collections::HashMap::new();
    let out_names = parts
        .iter()
        .map(|p| format!("{p}.img"))
        .chain(raw.iter().map(|n| n.to_string()));
    for name in out_names {
        if let Some(prev) = seen.insert(name.to_lowercase(), name.clone()) {
            bail!("{prev} and {name} differ only by case and would overwrite each other");
        }
    }
    std::fs::create_dir_all(out_dir)?;

    // Hidden automatically when stderr is not a terminal.
    let multi = MultiProgress::new();
    let style = ProgressStyle::with_template("{prefix:>10} [{bar:30}] {bytes}/{total_bytes}")
        .expect("valid progress template")
        .progress_chars("=> ");
    let results: Vec<Result<PathBuf>> = std::thread::scope(|scope| {
        let handles: Vec<_> = parts
            .iter()
            .map(|&part| {
                let bar = multi.add(ProgressBar::new(0).with_style(style.clone()));
                bar.set_prefix(part.to_string());
                let names = &names;
                scope.spawn(move || {
                    // each thread needs its own handle: a zip reader is not shareable
                    let mut src = Source::open(input)?;
                    let result = extract_partition(&mut src, names, part, out_dir, &bar);
                    bar.finish_and_clear();
                    result
                })
            })
            .collect();
        handles
            .into_iter()
            .map(|h| {
                h.join()
                    .unwrap_or_else(|_| Err(anyhow!("extraction thread panicked")))
            })
            .collect()
    });
    let mut paths = results.into_iter().collect::<Result<Vec<_>>>()?;
    let mut src = Source::open(input)?;
    for name in raw {
        paths.push(copy_raw(&mut src, name, out_dir)?);
    }
    Ok(paths)
}

/// `extract` command: extract all partitions and print one line per image.
pub fn run(input: &Path, out_dir: &Path) -> Result<()> {
    for path in extract_all(input, out_dir)? {
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
    fn many_partitions_extract_in_parallel_and_come_back_sorted() {
        let (ota, out, work) = (
            fresh_dir("many-in"),
            fresh_dir("many-out"),
            fresh_dir("many-zip"),
        );
        let mut files = Vec::new();
        for (i, name) in ["zeta", "alpha", "mid", "beta", "omega", "delta"]
            .iter()
            .enumerate()
        {
            files.push((
                format!("{name}.transfer.list"),
                b"4\n2\n0\n0\nnew 2,0,2\n".to_vec(),
            ));
            files.push((
                format!("{name}.new.dat.br"),
                brotli(&[blk(i as u8 + 1), blk(i as u8 + 50)].concat()),
            ));
        }
        let zip_path = work.join("ota.zip");
        let mut w = zip::ZipWriter::new(File::create(&zip_path).unwrap());
        for (name, body) in &files {
            std::fs::write(ota.join(name), body).unwrap();
            w.start_file(name.as_str(), zip::write::SimpleFileOptions::default())
                .unwrap();
            w.write_all(body).unwrap();
        }
        w.finish().unwrap();
        for input in [&ota, &zip_path] {
            let _ = std::fs::remove_dir_all(&out);
            let paths = extract_all(input, &out).unwrap();
            let names: Vec<_> = paths
                .iter()
                .map(|p| p.file_name().unwrap().to_string_lossy().into_owned())
                .collect();
            assert_eq!(
                names,
                [
                    "alpha.img",
                    "beta.img",
                    "delta.img",
                    "mid.img",
                    "omega.img",
                    "zeta.img"
                ]
            );
            for (i, name) in ["zeta", "alpha", "mid", "beta", "omega", "delta"]
                .iter()
                .enumerate()
            {
                let expect = [blk(i as u8 + 1), blk(i as u8 + 50)].concat();
                assert_eq!(
                    std::fs::read(out.join(format!("{name}.img"))).unwrap(),
                    expect,
                    "{name}"
                );
            }
        }
    }

    #[test]
    fn one_bad_partition_fails_the_run_but_good_ones_still_finish() {
        let (ota, out) = (fresh_dir("mixed-in"), fresh_dir("mixed-out"));
        write_dir(&ota, &sample_files());
        write_dir(
            &ota,
            &[
                ("c.transfer.list", b"4\n1\n0\n0\nnew 2,0,1\n".to_vec()),
                ("c.new.dat.br", vec![0xff; BLOCK]),
            ],
        );
        let e = extract_all(&ota, &out).unwrap_err();
        assert!(format!("{e:#}").contains("extracting c"), "{e:#}");
        assert!(out.join("a.img").exists() && out.join("b.img").exists());
        assert!(!out.join("c.img").exists() && !out.join("c.img.part").exists());
    }

    #[test]
    fn partition_names_lists_sorted_partitions_without_reading_data() {
        let ota = fresh_dir("names");
        write_dir(
            &ota,
            &[
                ("b.transfer.list", vec![]),
                ("a.transfer.list", vec![]),
                ("readme.txt", vec![]),
            ],
        );
        assert_eq!(partition_names(&ota).unwrap(), ["a", "b"]);
        let empty = fresh_dir("names-empty");
        assert!(partition_names(&empty).unwrap().is_empty());
    }

    fn zip_of(files: &[(&str, Vec<u8>)], path: &Path) {
        let mut w = zip::ZipWriter::new(File::create(path).unwrap());
        let stored = zip::write::SimpleFileOptions::default()
            .compression_method(zip::CompressionMethod::Stored);
        for (name, body) in files {
            w.start_file(*name, stored).unwrap();
            w.write_all(body).unwrap();
        }
        w.finish().unwrap();
    }

    #[test]
    fn raw_images_are_copied_unchanged_after_the_partitions() {
        let (ota, out, work) = (
            fresh_dir("raw-in"),
            fresh_dir("raw-out"),
            fresh_dir("raw-zip"),
        );
        let mut files = sample_files();
        // deliberately not in alphabetical order
        files.push(("vbmeta.img", vec![0x22; 64]));
        files.push(("dtbo.img", vec![0x33; 7]));
        files.push(("boot.img", vec![0x11; 5000]));
        files.push(("readme.txt", b"not an image".to_vec()));
        write_dir(&ota, &files);
        std::fs::create_dir(ota.join("dirnamed.img")).unwrap();
        let zip_path = work.join("ota.zip");
        zip_of(&files, &zip_path);
        for input in [&ota, &zip_path] {
            let _ = std::fs::remove_dir_all(&out);
            let paths = extract_all(input, &out).unwrap();
            let names: Vec<_> = paths
                .iter()
                .map(|p| p.file_name().unwrap().to_string_lossy().into_owned())
                .collect();
            assert_eq!(
                names,
                ["a.img", "b.img", "boot.img", "dtbo.img", "vbmeta.img"]
            );
            assert_eq!(
                std::fs::read(out.join("boot.img")).unwrap(),
                vec![0x11; 5000]
            );
            assert_eq!(
                std::fs::read(out.join("vbmeta.img")).unwrap(),
                vec![0x22; 64]
            );
            assert!(!out.join("readme.txt").exists() && !out.join("dirnamed.img").exists());
        }
    }

    #[test]
    fn raw_image_colliding_with_a_partition_is_an_error_before_writing() {
        let (ota, out) = (fresh_dir("clash-in"), fresh_dir("clash-out"));
        let mut files = sample_files();
        files.push(("a.img", vec![1; 10]));
        write_dir(&ota, &files);
        let e = extract_all(&ota, &out).unwrap_err();
        assert!(
            e.to_string().contains("conflicts with the a partition"),
            "{e}"
        );
        assert!(!out.join("a.img").exists());
    }

    #[test]
    fn output_names_differing_only_by_case_are_rejected() {
        let (work, out) = (fresh_dir("case-zip"), fresh_dir("case-out"));
        let zip_path = work.join("ota.zip");
        let mut files = sample_files();
        files.push(("Boot.img", vec![0x11; 8]));
        files.push(("boot.img", vec![0x22; 8]));
        zip_of(&files, &zip_path);
        let e = extract_all(&zip_path, &out).unwrap_err();
        assert!(e.to_string().contains("differ only by case"), "{e}");
        // partitions: A and a rebuild to A.img and a.img
        let mut files = sample_files();
        files.push(("A.transfer.list", b"4\n1\n0\n0\nnew 2,0,1\n".to_vec()));
        files.push(("A.new.dat", blk(3)));
        zip_of(&files, &zip_path);
        let e = extract_all(&zip_path, &out).unwrap_err();
        assert!(e.to_string().contains("differ only by case"), "{e}");
        assert!(
            !out.join("a.img").exists(),
            "nothing is written when names clash"
        );
    }

    #[test]
    fn unsafe_raw_image_names_are_rejected() {
        let (ota, out) = (fresh_dir("rawname-in"), fresh_dir("rawname-out"));
        let mut files = sample_files();
        files.push(("we ird.img", vec![1; 10]));
        write_dir(&ota, &files);
        let e = extract_all(&ota, &out).unwrap_err();
        assert!(e.to_string().contains("unsafe file name"), "{e}");
    }

    #[test]
    fn failed_raw_copy_leaves_nothing_behind() {
        let (work, out) = (fresh_dir("rawbad-zip"), fresh_dir("rawbad-out"));
        let mut files = sample_files();
        files.push(("boot.img", vec![0x5a; 64]));
        let zip_path = work.join("ota.zip");
        zip_of(&files, &zip_path);
        // flip one byte of the stored boot.img data so its CRC no longer matches
        let mut bytes = std::fs::read(&zip_path).unwrap();
        let at = bytes.windows(64).position(|w| w == [0x5a; 64]).unwrap();
        bytes[at] ^= 0xff;
        std::fs::write(&zip_path, bytes).unwrap();
        let e = extract_all(&zip_path, &out).unwrap_err();
        assert!(format!("{e:#}").contains("copying boot.img"), "{e:#}");
        assert!(out.join("a.img").exists());
        assert!(!out.join("boot.img").exists() && !out.join("boot.img.part").exists());
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
