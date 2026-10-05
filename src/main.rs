use clap::{Parser, Subcommand};
use std::io::Write;
use std::path::PathBuf;

mod apk;
mod archive;
mod audit;
mod avb;
mod bootimg;
mod content;
mod detect;
mod doctor;
mod erofsfs;
mod ext4fs;
mod extract;
mod info;
mod lp;
mod manifest;
mod otameta;
mod pac;
mod payload;
mod ramdisk;
mod report;
mod sdat;
mod sparse;
mod term;
#[cfg(test)]
mod testutil;
mod transfer_list;
mod tree;
mod treeout;

#[derive(Parser)]
#[command(version, about = "Extract and audit Android OTA/ROM images")]
struct Cli {
    /// Never emit colour, even on a terminal (also honours the NO_COLOR environment variable)
    #[arg(long, global = true)]
    no_color: bool,

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
        /// Do not fail when some inputs are skipped; report and exit 0
        #[arg(long)]
        allow_partial: bool,
        /// Fail on any file that cannot be classified at all
        #[arg(long)]
        strict: bool,
        /// Suppress progress bars and summary output
        #[arg(short = 'q', long)]
        quiet: bool,
        /// Print debug traces to stderr
        #[arg(short, long)]
        verbose: bool,
        /// Never emit colour
        #[arg(long)]
        no_color: bool,
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
    /// Show a flash manifest (Qualcomm rawprogram*.xml or MediaTek scatter.txt) and check it
    /// against the image files actually present
    Partitions {
        /// Directory holding rawprogram*.xml or scatter.txt, plus the images it references
        input: PathBuf,
        /// Bytes per sector (Qualcomm uses 4096; MediaTek varies by device)
        #[arg(long, default_value = "4096")]
        sector_size: u64,
        /// Print JSON instead of text
        #[arg(long)]
        json: bool,
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
    /// Show an AVB vbmeta image (or a partition with an AVB footer): header, key, signature, descriptors, hashes
    Vbmeta {
        image: PathBuf,
        /// Also hash each hashed partition found as <DIR>/<partition>.img and compare
        #[arg(long)]
        images: Option<PathBuf>,
        /// Print JSON instead of text
        #[arg(long)]
        json: bool,
        /// Verify the RSA signature against this PEM-encoded public key (overrides the key embedded in the image)
        #[arg(short, long)]
        key: Option<PathBuf>,
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
    /// Run a deterministic health scan on an unpacked firmware directory
    Doctor {
        /// Directory to scan
        input: PathBuf,
        /// Print findings as JSON
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

fn render_findings(findings: &[doctor::Finding]) -> String {
    let mut lines = Vec::new();
    for f in findings {
        lines.push(format!(
            "{} {} {}: {}: {}",
            f.severity, f.category, f.id, f.subject, f.message
        ));
        if let Some(r) = &f.remedy {
            lines.push(format!("    └ {}", r));
        }
    }
    lines.join(
        "
",
    )
}

fn print_out(text: &str) -> anyhow::Result<()> {
    match writeln!(std::io::stdout(), "{text}") {
        Err(e) if e.kind() == std::io::ErrorKind::BrokenPipe => Ok(()), // e.g. `| head`
        other => Ok(other?),
    }
}

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    let no_color = cli.no_color;
    let result = match cli.command {
        Command::Extract {
            input,
            output,
            force,
            only,
            list,
            files,
            allow_partial,
            strict,
            quiet,
            verbose,
            no_color,
        } => {
            let opts = extract::ExtractOptions {
                force,
                only: (!only.is_empty()).then_some(only),
                list,
                files,
                allow_partial,
                strict,
                quiet,
                verbose,
                no_color,
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
        Command::Audit { images, json } => audit_command(&images, json, no_color),
        Command::Vbmeta {
            image,
            images,
            json,
            key,
        } => vbmeta_command(&image, images.as_deref(), json, key.as_deref()),
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
        Command::Partitions {
            input,
            sector_size,
            json,
        } => partitions_command(&input, sector_size, json),
        Command::Report { input, json } => {
            let meta = info::read(&input)?;
            let parts = extract::partition_names(&input)?;
            let report = report::analyze(&meta, parts, report::today_days())?;
            print_out(&report::render(&report, json)?)
        }
        Command::Doctor { input, json } => {
            let findings = doctor::scan(&input)?;
            let text = if json {
                let rows: Vec<serde_json::Value> = findings
                    .iter()
                    .map(|f| {
                        serde_json::json!({
                            "id": f.id,
                            "category": f.category,
                            "severity": f.severity,
                            "subject": f.subject,
                            "message": f.message,
                            "remedy": f.remedy,
                        })
                    })
                    .collect();
                serde_json::to_string_pretty(&rows)?
            } else {
                render_findings(&findings)
            };
            print_out(&text)?;
            if findings.iter().any(|f| f.severity == "error") {
                anyhow::bail!("one or more findings have severity error");
            }
            Ok(())
        }
    };
    // Unified error rendering (issue #77): a one-line headline, then the indented cause
    // chain. Printed once, here, and the process exits non-zero - returning the error as
    // well would make the runtime print it a second time.
    match result {
        Ok(()) => Ok(()),
        Err(e) => {
            eprintln!(
                "{}",
                term::Renderer::new(term::Style::detect(no_color)).error(&e)
            );
            std::process::exit(1);
        }
    }
}

/// `partitions`: show a flash manifest and cross-check it against the images present.
fn partitions_command(input: &std::path::Path, sector_size: u64, json: bool) -> anyhow::Result<()> {
    let m = manifest::read(input, sector_size)?;
    let text = if json {
        serde_json::to_string_pretty(&manifest_json(&m))?
    } else {
        manifest::to_text(&m)
    };
    print_out(&text)?;
    // A manifest that references a missing image is not a usable firmware set.
    if !m.missing_images.is_empty() {
        anyhow::bail!(
            "{} manifest image(s) are missing from {}",
            m.missing_images.len(),
            input.display()
        );
    }
    Ok(())
}

/// One manifest as JSON.
fn manifest_json(m: &manifest::Manifest) -> serde_json::Value {
    serde_json::json!({
        "format": m.kind.name(),
        "sector_size": m.sector_size,
        "partitions": m.partitions.iter().map(|p| serde_json::json!({
            "label": p.label,
            "filename": p.filename,
            "start_sector": p.start_sector,
            "num_sectors": p.num_sectors,
            "size_bytes": p.num_sectors * m.sector_size,
            "sparse": p.sparse,
        })).collect::<Vec<_>>(),
        "missing_images": m.missing_images,
        "unreferenced_images": m.unreferenced_images,
    })
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
    key: Option<&std::path::Path>,
) -> anyhow::Result<()> {
    let external_key = if let Some(k) = key {
        Some(avb::read_key(k)?)
    } else {
        None
    };
    let meta = avb::read_input(image, external_key.as_ref())?;
    let checks = match images {
        Some(dir) => avb::verify_images(&meta, dir)?,
        None => Vec::new(),
    };
    let chained_findings: Vec<_> = images
        .map(|d| meta.cross_check_chained(d))
        .unwrap_or_default();
    let text = if json {
        let mut v = meta.to_json(&checks);
        v["findings"] = serde_json::json!(
            meta.findings()
                .into_iter()
                .chain(chained_findings.into_iter())
                .map(|f| serde_json::json!({
                    "severity": f.severity.name(),
                    "rule": f.rule,
                    "detail": f.detail,
                }))
                .collect::<Vec<_>>()
        );
        serde_json::to_string_pretty(&v)?
    } else {
        let mut t = meta.to_text(&checks);
        for f in &chained_findings {
            t.push_str(&format!(
                "\n  [{}] {}: {}\n",
                f.severity.name(),
                f.rule,
                f.detail
            ));
        }
        t
    };
    print_out(&text)?;
    anyhow::ensure!(
        !meta.any_failure(&checks),
        "the digest, signature, or a partition hash does not match"
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

fn audit_command(images: &[PathBuf], json: bool, no_color: bool) -> anyhow::Result<()> {
    let audits = audit::image_list(images)?
        .iter()
        .map(|p| audit::audit_image(p))
        .collect::<anyhow::Result<Vec<_>>>()?;
    let text = if json {
        serde_json::to_string_pretty(&audit::to_json(&audits))?
    } else {
        audit::to_text(&audits, no_color)
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
