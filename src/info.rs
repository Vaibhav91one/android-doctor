//! Read build metadata from an OTA (`META-INF/com/android/metadata`).
use anyhow::{Context, Result, bail};
use std::collections::BTreeMap;
use std::fs::File;
use std::io::{Read, Seek};
use std::path::Path;

const METADATA_PATH: &str = "META-INF/com/android/metadata";
/// Real metadata files are well under 1 KiB; the cap stops a hostile zip from exhausting memory.
const MAX_METADATA_BYTES: u64 = 1 << 20;

pub type Metadata = BTreeMap<String, String>;

/// Parse `key=value` lines; lines without `=` are ignored.
pub fn parse(text: &str) -> Metadata {
    text.lines()
        .filter_map(|line| line.split_once('='))
        .map(|(k, v)| (k.trim().to_string(), v.trim().to_string()))
        .collect()
}

fn from_zip<R: Read + Seek>(input: R) -> Result<Metadata> {
    let mut zip = zip::ZipArchive::new(input).context("not a valid zip file")?;
    let mut text = String::new();
    let entry = zip
        .by_name(METADATA_PATH)
        .with_context(|| format!("{METADATA_PATH} not found in zip"))?;
    entry
        .take(MAX_METADATA_BYTES + 1)
        .read_to_string(&mut text)?;
    if text.len() as u64 > MAX_METADATA_BYTES {
        bail!("{METADATA_PATH} is larger than {MAX_METADATA_BYTES} bytes");
    }
    Ok(parse(&text))
}

/// Read the metadata from an OTA zip or from an already extracted OTA directory.
pub fn read(input: &Path) -> Result<Metadata> {
    let meta = if input.is_dir() {
        let path = input.join(METADATA_PATH);
        let mut text = String::new();
        File::open(&path)
            .with_context(|| format!("reading {}", path.display()))?
            .take(MAX_METADATA_BYTES + 1)
            .read_to_string(&mut text)?;
        if text.len() as u64 > MAX_METADATA_BYTES {
            bail!("{METADATA_PATH} is larger than {MAX_METADATA_BYTES} bytes");
        }
        parse(&text)
    } else {
        let file = File::open(input).with_context(|| format!("opening {}", input.display()))?;
        from_zip(file)?
    };
    if meta.is_empty() {
        bail!("{METADATA_PATH} has no key=value entries");
    }
    Ok(meta)
}

/// Aligned `key  value` lines, or pretty JSON when `json` is set.
pub fn render(meta: &Metadata, json: bool) -> Result<String> {
    if json {
        return Ok(serde_json::to_string_pretty(meta)?);
    }
    let width = meta.keys().map(String::len).max().unwrap_or(0);
    Ok(meta
        .iter()
        .map(|(k, v)| format!("{k:<width$}  {v}"))
        .collect::<Vec<_>>()
        .join("\n"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Cursor, Write};

    const SAMPLE: &str = "post-build=Acme/dev/dev:9/1.0/1:user/release-keys\n\
        post-sdk-level=28\n  ota-type = BLOCK  \nnoise line\nnote=a=b\n";

    fn zip_with(name: &str, body: &str) -> Cursor<Vec<u8>> {
        let mut w = zip::ZipWriter::new(Cursor::new(Vec::new()));
        w.start_file(name, zip::write::SimpleFileOptions::default())
            .unwrap();
        w.write_all(body.as_bytes()).unwrap();
        w.finish().unwrap()
    }

    #[test]
    fn parse_trims_skips_noise_and_splits_on_first_equals() {
        let m = parse(SAMPLE);
        assert_eq!(m.len(), 4);
        assert_eq!(m["ota-type"], "BLOCK");
        assert_eq!(m["post-sdk-level"], "28");
        assert_eq!(m["note"], "a=b");
    }

    #[test]
    fn table_is_aligned_and_sorted() {
        let m = parse("b=2\nlonger-key=1\n");
        assert_eq!(render(&m, false).unwrap(), "b           2\nlonger-key  1");
    }

    #[test]
    fn json_round_trips() {
        let m = parse(SAMPLE);
        let back: Metadata = serde_json::from_str(&render(&m, true).unwrap()).unwrap();
        assert_eq!(back, m);
    }

    #[test]
    fn reads_metadata_from_a_zip() {
        let m = from_zip(zip_with(METADATA_PATH, SAMPLE)).unwrap();
        assert_eq!(m["post-sdk-level"], "28");
    }

    #[test]
    fn oversized_metadata_is_rejected_in_zip_and_dir() {
        let big = "k=v\n".repeat(MAX_METADATA_BYTES as usize / 4 + 1);
        let e = from_zip(zip_with(METADATA_PATH, &big)).unwrap_err();
        assert!(e.to_string().contains("larger than"), "{e}");
        let dir = crate::testutil::Scratch::new("info-big");
        std::fs::create_dir_all(dir.join("META-INF/com/android")).unwrap();
        std::fs::write(dir.join(METADATA_PATH), &big).unwrap();
        let e = read(&dir).unwrap_err();
        assert!(e.to_string().contains("larger than"), "{e}");
    }

    #[test]
    fn zip_without_metadata_is_an_error() {
        let e = from_zip(zip_with("other.txt", SAMPLE)).unwrap_err();
        assert!(e.to_string().contains("not found in zip"), "{e}");
    }

    #[test]
    fn reads_metadata_from_a_directory_and_rejects_empty_or_missing() {
        let dir = crate::testutil::Scratch::new("info-dir");
        let meta_dir = dir.join("META-INF/com/android");
        std::fs::create_dir_all(&meta_dir).unwrap();
        std::fs::write(meta_dir.join("metadata"), SAMPLE).unwrap();
        assert_eq!(read(&dir).unwrap()["ota-type"], "BLOCK");
        std::fs::write(meta_dir.join("metadata"), "no pairs here\n").unwrap();
        assert!(read(&dir).unwrap_err().to_string().contains("no key=value"));
        std::fs::remove_dir_all(&meta_dir).unwrap();
        assert!(read(&dir).is_err(), "a dir without metadata still fails");
    }
}
