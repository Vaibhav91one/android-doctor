use clap::{Parser, Subcommand};
use std::io::Write;
use std::path::PathBuf;

mod extract;
mod info;
mod report;
mod sdat;
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
    },
    /// Print build info from an OTA without extracting
    Info {
        input: PathBuf,
        /// Print all metadata as JSON
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
        } => extract::run(&input, &output, &extract::ExtractOptions { force }),
        Command::Info { input, json } => print_out(&info::render(&info::read(&input)?, json)?),
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
