//! Command line argument definitions and entry point dispatch.

pub mod commands;
#[cfg(test)]
pub mod tests;

use clap::{Parser, Subcommand};
use std::path::PathBuf;

pub use commands::{
    ProbeResult, cmd_probe, cmd_run, cmd_status, cmd_toggle_tunnels, cmd_top, cmd_validate,
    run_probe_single,
};

/// Command line interface for `wpmulti`.
#[derive(Parser, Debug, Clone, PartialEq, Eq)]
#[clap(
    name = "wpmulti",
    version = env!("CARGO_PKG_VERSION"),
    about = "High-concurrency multi-tunnel WireGuard proxy daemon for gotatun",
    long_about = "wpmulti runs hundreds or thousands of WireGuard configs simultaneously in userspace \
                  (using gotatun + smoltcp, no kernel TUN interfaces required) and exposes them as \
                  SOCKS5 (TCP + UDP ASSOCIATE) and HTTP/HTTPS CONNECT proxies.",
    after_help = "EXAMPLES:\n  \
                  wpmulti validate -d ./confs\n  \
                  wpmulti run -d ./confs --tui\n  \
                  wpmulti run -c wpmulti.toml\n  \
                  wpmulti top --admin-url http://127.0.0.1:9090\n  \
                  wpmulti status --admin-url http://127.0.0.1:9090\n\n\
                  PROXY USAGE:\n  \
                  Per-tunnel default ports : SOCKS5 10000+N, HTTP 20000+N\n  \
                  Shared port routing      : username = <tunnel_id> | auto | random | round-robin | least-conn\n  \
                  Example curl             : curl -x socks5h://wgcf-001@127.0.0.1:1080 https://ifconfig.co"
)]
pub struct Cli {
    #[clap(subcommand)]
    pub command: Commands,
}

/// Available subcommands for `wpmulti`.
#[derive(Subcommand, Debug, Clone, PartialEq, Eq)]
pub enum Commands {
    /// Start the multi-tunnel proxy daemon
    #[clap(after_help = "EXAMPLES:\n  \
                         wpmulti run -d ./confs\n  \
                         wpmulti run -d ./confs --tui\n  \
                         wpmulti run -c wpmulti.toml")]
    Run {
        /// Path to main configuration file (e.g. wpmulti.toml)
        #[clap(short, long)]
        config: Option<PathBuf>,

        /// Path to directory containing WireGuard .conf files (overrides global.config_dir)
        #[clap(short, long)]
        dir: Option<PathBuf>,

        /// Launch integrated interactive TUI monitor alongside daemon
        #[clap(long)]
        tui: bool,
    },
    /// Launch the standalone interactive TUI monitor
    #[clap(after_help = "EXAMPLE:\n  wpmulti top --admin-url http://127.0.0.1:9090")]
    Top {
        /// Admin API URL to connect to (e.g. http://127.0.0.1:9090)
        #[clap(long, default_value = "http://127.0.0.1:9090")]
        admin_url: String,

        /// Bearer authentication token for protected Admin API
        #[clap(long)]
        auth_token: Option<String>,
    },
    /// Validate configuration and tunnel files without starting listeners
    #[clap(after_help = "EXAMPLES:\n  \
                         wpmulti validate -d ./confs\n  \
                         wpmulti validate -c wpmulti.toml")]
    Validate {
        /// Path to main configuration file (e.g. wpmulti.toml)
        #[clap(short, long)]
        config: Option<PathBuf>,

        /// Path to directory containing WireGuard .conf files
        #[clap(short, long)]
        dir: Option<PathBuf>,
    },
    /// Query daemon status from Admin API and print to stdout
    #[clap(after_help = "EXAMPLE:\n  wpmulti status --admin-url http://127.0.0.1:9090")]
    Status {
        /// Admin API URL to connect to (e.g. http://127.0.0.1:9090)
        #[clap(long, default_value = "http://127.0.0.1:9090")]
        admin_url: String,

        /// Bearer authentication token for protected Admin API
        #[clap(long)]
        auth_token: Option<String>,
    },
    /// Probe WireGuard tunnel configs for connectivity, RTT latency, and exit IP
    #[clap(after_help = "EXAMPLES:\n  \
                         wpmulti probe -c ./wgcf-profile.conf\n  \
                         wpmulti probe -d ./confs\n  \
                         wpmulti probe -d ./confs --json")]
    Probe {
        /// Path to single WireGuard .conf file
        #[clap(short, long)]
        config: Option<PathBuf>,

        /// Path to directory containing WireGuard .conf files
        #[clap(short, long)]
        dir: Option<PathBuf>,

        /// Output results as JSON
        #[clap(long)]
        json: bool,

        /// Probe timeout (e.g. 5s, 10s)
        #[clap(long, default_value = "5s")]
        timeout: String,
    },
    /// Disable one or more tunnels (`A`, `1`, `1-200`, `all`) via Admin API
    #[clap(after_help = "EXAMPLES:\n  \
                         wpmulti disable wgcf-001\n  \
                         wpmulti disable 1\n  \
                         wpmulti disable 1-200\n  \
                         wpmulti disable all")]
    Disable {
        /// Target tunnel(s): name, 1-based index, range (1-200), comma list, or 'all'
        target: String,

        /// Admin API URL to connect to (e.g. http://127.0.0.1:9090)
        #[clap(long, default_value = "http://127.0.0.1:9090")]
        admin_url: String,

        /// Bearer authentication token for protected Admin API
        #[clap(long)]
        auth_token: Option<String>,
    },
    /// Enable one or more disabled tunnels (`A`, `1`, `1-200`, `all`) via Admin API
    #[clap(after_help = "EXAMPLES:\n  \
                         wpmulti enable wgcf-001\n  \
                         wpmulti enable 1\n  \
                         wpmulti enable 1-200\n  \
                         wpmulti enable all")]
    Enable {
        /// Target tunnel(s): name, 1-based index, range (1-200), comma list, or 'all'
        target: String,

        /// Admin API URL to connect to (e.g. http://127.0.0.1:9090)
        #[clap(long, default_value = "http://127.0.0.1:9090")]
        admin_url: String,

        /// Bearer authentication token for protected Admin API
        #[clap(long)]
        auth_token: Option<String>,
    },
}

/// Parse arguments and execute the selected subcommand.
pub async fn run_cli() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();
    if let Commands::Run { config, dir, tui } = cli.command {
        return cmd_run(config, dir, tui).await;
    }

    if !matches!(cli.command, Commands::Top { .. }) {
        let _ = tracing_subscriber::fmt()
            .with_max_level(tracing::Level::INFO)
            .try_init();
    }
    let env_token = std::env::var("WPMULTI_ADMIN_TOKEN")
        .ok()
        .filter(|s| !s.is_empty());
    match cli.command {
        Commands::Run { .. } => unreachable!(),
        Commands::Top {
            admin_url,
            auth_token,
        } => cmd_top(admin_url, auth_token.or(env_token)).await,
        Commands::Validate { config, dir } => {
            cmd_validate(config, dir)?;
            Ok(())
        }
        Commands::Status {
            admin_url,
            auth_token,
        } => {
            cmd_status(admin_url, auth_token.or(env_token)).await?;
            Ok(())
        }
        Commands::Probe {
            config,
            dir,
            json,
            timeout,
        } => {
            cmd_probe(config, dir, json, timeout).await?;
            Ok(())
        }
        Commands::Disable {
            target,
            admin_url,
            auth_token,
        } => cmd_toggle_tunnels(target, true, admin_url, auth_token.or(env_token)).await,
        Commands::Enable {
            target,
            admin_url,
            auth_token,
        } => cmd_toggle_tunnels(target, false, admin_url, auth_token.or(env_token)).await,
    }
}
