use clap::{Parser, Subcommand};
use std::io::Write;
use std::path::PathBuf;

mod bootimg;
mod detect;
mod extract;
mod info;
mod payload;
mod ramdisk;
mod report;
mod sdat;
mod sparse;
mod transfer_list;

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
    },
    /// Print build info from an OTA without extracting
    Info {
        input: PathBuf,
        /// Print all metadata as JSON
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
        } => {
            let opts = extract::ExtractOptions {
                force,
                only: (!only.is_empty()).then_some(only),
                list,
            };
            extract::run(&input, &output, &opts)
        }
        Command::Info { input, json } => print_out(&info::render(&info::read(&input)?, json)?),
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

#[cfg(test)]
mod tests {
    use super::*;
    use clap::CommandFactory;

    #[test]
    fn cli_definition_is_valid() {
        Cli::command().debug_assert();
    }
}
