use clap::{Parser, Subcommand};
use std::io::Write;
use std::path::PathBuf;

mod info;
#[allow(dead_code)] // wired up by the extract command (issue #4)
mod sdat;
#[allow(dead_code)] // wired up by the extract command (issue #4)
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
    },
    /// Print build info from an OTA without extracting
    Info {
        input: PathBuf,
        /// Print all metadata as JSON
        #[arg(long)]
        json: bool,
    },
}

fn main() -> anyhow::Result<()> {
    match Cli::parse().command {
        Command::Extract { .. } => anyhow::bail!("not implemented yet"),
        Command::Info { input, json } => {
            let text = info::render(&info::read(&input)?, json)?;
            match writeln!(std::io::stdout(), "{text}") {
                Err(e) if e.kind() == std::io::ErrorKind::BrokenPipe => Ok(()), // e.g. `| head`
                other => Ok(other?),
            }
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
