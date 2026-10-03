use clap::{Parser, Subcommand};
use std::io::Write;
use std::path::PathBuf;

mod audit;
mod avb;
mod bootimg;
mod detect;
mod erofsfs;
mod ext4fs;
mod extract;
mod info;
mod lp;
mod otameta;
mod pac;
mod payload;
mod ramdisk;
mod report;
mod sdat;
mod sparse;
#[cfg(test)]
mod testutil;
mod transfer_list;
mod tree;
mod treeout;

#[derive(Parser)]
#[command(version, about = "Extract and audit Android OTA/ROM images")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Extract partition images from an OTA zip or directory
    Extract {
        input: PathBuf,
        #[arg(short, long, default_value = "out")]
        output: PathBuf,
        /// Replace existing output files instead of refusing
        #[arg(long)]
        force: bool,
        /// Extract only these partitions or images, comma-separated (e.g. system,boot)
        #[arg(long, value_delimiter = ',')]
        only: Vec<String>,
        /// List what would be extracted, with sizes, and write nothing
        #[arg(long)]
        list: bool,
        /// Also extract the files of every ext2/3/4 image into <out>/files/<image>/ (with manifests)
        #[arg(long)]
        files: bool,
    },
    /// Print build info from an OTA without extracting
    Info {
        input: PathBuf,
        /// Print all metadata as JSON
        #[arg(long)]
        json: bool,
        /// Also summarise the updater-script and read the signing certificate
        #[arg(long)]
        details: bool,
    },
    /// Show a boot or vendor_boot image's header, and with -o write its kernel, ramdisk, dtb, ...
    Unpack {
        input: PathBuf,
        /// Write the sections (kernel, ramdisk, second, dtb, ...) into this directory
        #[arg(short, long)]
        output: Option<PathBuf>,
        /// Print the header as JSON
        #[arg(long)]
        json: bool,
        /// Replace existing files instead of refusing
        #[arg(long)]
        force: bool,
    },
    /// List a directory (or show one file) inside an ext2/3/4 image, without extracting it
    Ls {
        image: PathBuf,
        /// Path inside the image (default: the root)
        #[arg(default_value = "/")]
        path: String,
        /// Print JSON instead of text
        #[arg(long)]
        json: bool,
    },
    /// Print one regular file from an ext2/3/4 image to standard output
    Cat { image: PathBuf, path: String },
    /// Security posture of firmware images: ADB properties, setuid files, su binaries, init services
    Audit {
        /// Image files (ext2/3/4 or erofs), or a directory of them (such as an `extract` output)
        #[arg(required = true)]
        images: Vec<PathBuf>,
        /// Print JSON instead of text
        #[arg(long)]
        json: bool,
    },
    /// Show an AVB vbmeta image (or a partition with an AVB footer): header, key, descriptors, hashes
    Vbmeta {
        image: PathBuf,
        /// Also hash each hashed partition found as <DIR>/<partition>.img and compare
        #[arg(long)]
        images: Option<PathBuf>,
        /// Print JSON instead of text
        #[arg(long)]
        json: bool,
    },
    /// List a boot image's ramdisk (or a ramdisk file), report its ADB properties, and with -o extract it
    Ramdisk {
        input: PathBuf,
        /// Extract the files into this new directory (symlinks and devices are recorded, not created)
        #[arg(short, long)]
        output: Option<PathBuf>,
        /// Print the result as JSON
        #[arg(long)]
        json: bool,
        /// Also list every entry
        #[arg(long)]
        list: bool,
    },
    /// List or extract the files of an ext2/3/4 image (with SELinux labels), no root needed
    Files {
        image: PathBuf,
        /// Extract into this new directory (files/ plus manifest.json); without it, list only
        #[arg(short, long)]
        output: Option<PathBuf>,
        /// Print JSON instead of text
        #[arg(long)]
        json: bool,
    },
    /// Turn Android sparse image(s) into a raw image
    Unsparse {
        /// Sparse file(s); several files that describe the same image are applied in the order given
        #[arg(required = true)]
        inputs: Vec<PathBuf>,
        #[arg(short, long)]
        output: PathBuf,
        /// Replace an existing output file instead of refusing
        #[arg(long)]
        force: bool,
    },
    /// Say what each file is, by its magic bytes (never by name)
    Identify {
        #[arg(required = true)]
        paths: Vec<PathBuf>,
        /// Print the result as JSON
        #[arg(long)]
        json: bool,
    },
    /// Staleness verdict from the OTA's build metadata
    Report {
        input: PathBuf,
        /// Print the report as JSON
        #[arg(long)]
        json: bool,
    },
}

fn identify(paths: &[PathBuf], json: bool) -> anyhow::Result<()> {
    let mut failed = 0;
    let mut rows = Vec::new();
    for path in paths {
        match detect::identify_path(path) {
            Ok(i) => rows.push(serde_json::json!({
                "path": path.display().to_string(),
                "id": i.id,
                "description": i.description,
            })),
            Err(e) => {
                failed += 1;
                rows.push(serde_json::json!({
                    "path": path.display().to_string(),
                    "error": format!("{e:#}"),
                }));
            }
        }
    }
    let text = if json {
        serde_json::to_string_pretty(&rows)?
    } else {
        rows.iter()
            .map(|r| match r["error"].as_str() {
                Some(e) => format!("{}: error: {e}", r["path"].as_str().unwrap_or("")),
                None => format!(
                    "{}: {}",
                    r["path"].as_str().unwrap_or(""),
                    r["description"].as_str().unwrap_or("")
                ),
            })
            .collect::<Vec<_>>()
            .join("\n")
    };
    print_out(&text)?;
    if failed > 0 {
        anyhow::bail!("{failed} of {} paths could not be read", paths.len());
    }
    Ok(())
}

fn ramdisk_command(
    input: &std::path::Path,
    output: Option<&std::path::Path>,
    json: bool,
    list: bool,
) -> anyhow::Result<()> {
    let found = ramdisk::read_input(input, output)?;
    let mut failed = 0;
    let text = if json {
        let rows: Vec<_> = found
            .iter()
            .map(|f| match &f.report {
                Ok(r) => serde_json::json!({"ramdisk": f.name, "result": r.to_json()}),
                Err(e) => {
                    failed += 1;
                    serde_json::json!({"ramdisk": f.name, "error": format!("{e:#}")})
                }
            })
            .collect();
        serde_json::to_string_pretty(&rows)?
    } else {
        found
            .iter()
            .map(|f| match &f.report {
                Ok(r) => format!("{}:\n{}", f.name, r.to_text(list)),
                Err(e) => {
                    failed += 1;
                    format!("{}: error: {e:#}", f.name)
                }
            })
            .collect::<Vec<_>>()
            .join("\n\n")
    };
    print_out(&text)?;
    anyhow::ensure!(
        failed == 0,
        "{failed} of {} ramdisks could not be read",
        found.len()
    );
    Ok(())
}

fn print_out(text: &str) -> anyhow::Result<()> {
    match writeln!(std::io::stdout(), "{text}") {
        Err(e) if e.kind() == std::io::ErrorKind::BrokenPipe => Ok(()), // e.g. `| head`
        other => Ok(other?),
    }
}

fn main() -> anyhow::Result<()> {
    match Cli::parse().command {
        Command::Extract {
            input,
            output,
            force,
            only,
            list,
            files,
        } => {
            let opts = extract::ExtractOptions {
                force,
                only: (!only.is_empty()).then_some(only),
                list,
                files,
            };
            extract::run(&input, &output, &opts)
        }
        Command::Info {
            input,
            json,
            details,
        } => info_command(&input, json, details),
        Command::Unpack {
            input,
            output,
            json,
            force,
        } => {
            let image = bootimg::read(&input)?;
            if let Some(dir) = &output {
                bootimg::write_sections(&input, &image, dir, force)?;
            }
            let text = if json {
                serde_json::to_string_pretty(&bootimg::to_json(&image))?
            } else {
                bootimg::to_text(&image)
            };
            print_out(&text)
        }
        Command::Ramdisk {
            input,
            output,
            json,
            list,
        } => ramdisk_command(&input, output.as_deref(), json, list),
        Command::Ls { image, path, json } => ls_command(&image, &path, json),
        Command::Cat { image, path } => cat_command(&image, &path),
        Command::Audit { images, json } => audit_command(&images, json),
        Command::Vbmeta {
            image,
            images,
            json,
        } => vbmeta_command(&image, images.as_deref(), json),
        Command::Files {
            image,
            output,
            json,
        } => files_command(&image, output.as_deref(), json),
        Command::Unsparse {
            inputs,
            output,
            force,
        } => sparse::run(&inputs, &output, force),
        Command::Identify { paths, json } => identify(&paths, json),
        Command::Report { input, json } => {
            let meta = info::read(&input)?;
            let parts = extract::partition_names(&input)?;
            let report = report::analyze(&meta, parts, report::today_days())?;
            print_out(&report::render(&report, json)?)
        }
    }
}

fn files_command(
    image: &std::path::Path,
    output: Option<&std::path::Path>,
    json: bool,
) -> anyhow::Result<()> {
    let fs = tree::Tree::open(image)?;
    let entries = match output {
        Some(out) => fs.extract(out, None)?,
        None => fs.entries()?,
    };
    let text = if json {
        serde_json::to_string_pretty(&tree::manifest(&entries))?
    } else {
        entries
            .iter()
            .map(entry_line)
            .collect::<Vec<_>>()
            .join("\n")
    };
    print_out(&text)
}

fn vbmeta_command(
    image: &std::path::Path,
    images: Option<&std::path::Path>,
    json: bool,
) -> anyhow::Result<()> {
    let meta = avb::read_input(image)?;
    let checks = match images {
        Some(dir) => avb::verify_images(&meta, dir)?,
        None => Vec::new(),
    };
    let text = if json {
        serde_json::to_string_pretty(&meta.to_json(&checks))?
    } else {
        meta.to_text(&checks)
    };
    print_out(&text)?;
    anyhow::ensure!(
        !meta.any_failure(&checks),
        "the digest or a partition hash does not match"
    );
    Ok(())
}

fn entry_line(e: &tree::Entry) -> String {
    let label = e
        .xattrs
        .iter()
        .find(|(k, _)| k == "security.selinux")
        .map_or("", |(_, v)| v.as_str());
    let link = e
        .link
        .as_deref()
        .map(|l| format!(" -> {l}"))
        .unwrap_or_default();
    let name = if e.path.is_empty() {
        "/"
    } else {
        e.path.as_str()
    };
    format!(
        "{:7} {:04o} {:>5} {:>5} {:>11} {}{} {}",
        e.kind.name(),
        e.mode,
        e.uid,
        e.gid,
        e.size,
        name,
        link,
        label
    )
}

fn ls_command(image: &std::path::Path, path: &str, json: bool) -> anyhow::Result<()> {
    let entries = tree::Tree::open(image)?.list_dir(path)?;
    let text = if json {
        serde_json::to_string_pretty(&entries.iter().map(tree::entry_json).collect::<Vec<_>>())?
    } else {
        entries
            .iter()
            .map(entry_line)
            .collect::<Vec<_>>()
            .join("\n")
    };
    print_out(&text)
}

fn cat_command(image: &std::path::Path, path: &str) -> anyhow::Result<()> {
    let fs = tree::Tree::open(image)?;
    let mut out = std::io::stdout().lock();
    match fs.cat_path(path, &mut out) {
        Err(e)
            if e.downcast_ref::<std::io::Error>()
                .is_some_and(|e| e.kind() == std::io::ErrorKind::BrokenPipe) =>
        {
            Ok(())
        }
        r => r,
    }
}

fn audit_command(images: &[PathBuf], json: bool) -> anyhow::Result<()> {
    let audits = audit::image_list(images)?
        .iter()
        .map(|p| audit::audit_image(p))
        .collect::<anyhow::Result<Vec<_>>>()?;
    let text = if json {
        serde_json::to_string_pretty(&audit::to_json(&audits))?
    } else {
        audit::to_text(&audits)
    };
    print_out(&text)
}

fn info_command(input: &std::path::Path, json: bool, details: bool) -> anyhow::Result<()> {
    let meta = info::read(input)?;
    if !details {
        return print_out(&info::render(&meta, json)?);
    }
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs() as i64);
    let d = otameta::read_details(input)?;
    if json {
        let mut v = d.to_json(now);
        v["metadata"] = serde_json::to_value(&meta)?;
        return print_out(&serde_json::to_string_pretty(&v)?);
    }
    print_out(&format!(
        "{}\n\n{}",
        info::render(&meta, false)?,
        d.to_text(now)
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::CommandFactory;

    #[test]
    fn cli_definition_is_valid() {
        Cli::command().debug_assert();
    }
}
