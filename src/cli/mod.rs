//! Command line argument definitions and entry point dispatch.

pub mod commands;
#[cfg(test)]
pub mod tests;

use std::path::PathBuf;
use clap::{Parser, Subcommand};

pub use commands::{cmd_run, cmd_status, cmd_top, cmd_validate};

/// Command line interface for `wpmulti`.
#[derive(Parser, Debug, Clone, PartialEq, Eq)]
#[clap(
    name = "wpmulti",
    version = env!("CARGO_PKG_VERSION"),
    about = "High-concurrency multi-tunnel WireGuard proxy daemon for gotatun"
)]
pub struct Cli {
    #[clap(subcommand)]
    pub command: Commands,
}

/// Available subcommands for `wpmulti`.
#[derive(Subcommand, Debug, Clone, PartialEq, Eq)]
pub enum Commands {
    /// Start the multi-tunnel proxy daemon
    Run {
        /// Path to main configuration file (e.g. wpmulti.toml)
        #[clap(short, long)]
        config: Option<PathBuf>,

        /// Path to directory containing WireGuard .conf files
        #[clap(short, long)]
        dir: Option<PathBuf>,

        /// Launch integrated interactive TUI monitor alongside daemon
        #[clap(long)]
        tui: bool,
    },
    /// Launch the standalone interactive TUI monitor
    Top {
        /// Admin API URL to connect to (e.g. http://127.0.0.1:9090)
        #[clap(long, default_value = "http://127.0.0.1:9090")]
        admin_url: String,
    },
    /// Validate configuration and tunnel files without starting listeners
    Validate {
        /// Path to main configuration file (e.g. wpmulti.toml)
        #[clap(short, long)]
        config: Option<PathBuf>,

        /// Path to directory containing WireGuard .conf files
        #[clap(short, long)]
        dir: Option<PathBuf>,
    },
    /// Query daemon status from Admin API and print to stdout
    Status {
        /// Admin API URL to connect to (e.g. http://127.0.0.1:9090)
        #[clap(long, default_value = "http://127.0.0.1:9090")]
        admin_url: String,
    },
}

/// Parse arguments and execute the selected subcommand.
pub async fn run_cli() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();
    match cli.command {
        Commands::Run { config, dir, tui } => cmd_run(config, dir, tui).await,
        Commands::Top { admin_url } => cmd_top(admin_url).await,
        Commands::Validate { config, dir } => {
            cmd_validate(config, dir)?;
            Ok(())
        }
        Commands::Status { admin_url } => {
            cmd_status(admin_url).await?;
            Ok(())
        }
    }
}
