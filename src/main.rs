use clap::{Parser, Subcommand};
use std::path::PathBuf;

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
    Info { input: PathBuf },
}

fn main() -> anyhow::Result<()> {
    match Cli::parse().command {
        Command::Extract { .. } | Command::Info { .. } => anyhow::bail!("not implemented yet"),
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
