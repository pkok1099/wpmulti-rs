//! Command line argument definitions and entry point dispatch.

pub mod commands;
#[cfg(test)]
pub mod tests;

use clap::{Parser, Subcommand};
use std::path::{Path, PathBuf};

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
                  wpmulti run -d ./confs\n  \
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
                         wpmulti run -c wpmulti.toml")]
    Run {
        /// Path to main configuration file (e.g. wpmulti.toml)
        #[clap(short, long)]
        config: Option<PathBuf>,

        /// Path to directory containing WireGuard .conf files (overrides global.config_dir)
        #[clap(short, long)]
        dir: Option<PathBuf>,
    },
    /// Monitor a running daemon's tunnels, connections and logs (reads the
    /// daemon through its Admin API; a loopback Admin API needs no token)
    #[clap(after_help = "EXAMPLE:\n  wpmulti top --admin-url http://127.0.0.1:9090")]
    Top {
        /// Admin API URL to connect to (e.g. http://127.0.0.1:9090)
        #[clap(long, default_value = "http://127.0.0.1:9090")]
        admin_url: String,

        /// Path to a file holding the bearer authentication token for
        /// a protected Admin API (first line, trimmed). The token is
        /// never passed on the command line: `--auth-token` was removed
        /// (audit run-3 #13) because argv stays visible in
        /// `/proc/<pid>/cmdline` to other local users. When omitted,
        /// the `WPMULTI_ADMIN_TOKEN` environment variable is used.
        #[clap(long)]
        auth_token_file: Option<PathBuf>,
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

        /// Path to a file holding the bearer authentication token for
        /// a protected Admin API (first line, trimmed). The token is
        /// never passed on the command line: `--auth-token` was removed
        /// (audit run-3 #13) because argv stays visible in
        /// `/proc/<pid>/cmdline` to other local users. When omitted,
        /// the `WPMULTI_ADMIN_TOKEN` environment variable is used.
        #[clap(long)]
        auth_token_file: Option<PathBuf>,
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

        /// Output results as JSON (exits 1 if all probes fail, like table mode; stdout stays a pure JSON array)
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

        /// Path to a file holding the bearer authentication token for
        /// a protected Admin API (first line, trimmed). The token is
        /// never passed on the command line: `--auth-token` was removed
        /// (audit run-3 #13) because argv stays visible in
        /// `/proc/<pid>/cmdline` to other local users. When omitted,
        /// the `WPMULTI_ADMIN_TOKEN` environment variable is used.
        #[clap(long)]
        auth_token_file: Option<PathBuf>,
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

        /// Path to a file holding the bearer authentication token for
        /// a protected Admin API (first line, trimmed). The token is
        /// never passed on the command line: `--auth-token` was removed
        /// (audit run-3 #13) because argv stays visible in
        /// `/proc/<pid>/cmdline` to other local users. When omitted,
        /// the `WPMULTI_ADMIN_TOKEN` environment variable is used.
        #[clap(long)]
        auth_token_file: Option<PathBuf>,
    },
}

/// Compute whether ANSI color escape codes should be enabled for CLI diagnostics.
///
/// ANSI escapes are disabled whenever structured JSON output is requested or `stderr`
/// is not an interactive terminal so log lines never inject control sequences into pipes
/// or combined streams.
pub(crate) const fn cli_log_ansi_enabled(json_mode: bool, stderr_is_terminal: bool) -> bool {
    !json_mode && stderr_is_terminal
}

/// Construct a `tracing` subscriber writing diagnostic logs to `writer`.
pub(crate) fn build_cli_tracing_subscriber<W>(
    max_level: tracing::Level,
    ansi: bool,
    writer: W,
) -> impl tracing::Subscriber + Send + Sync
where
    W: for<'a> tracing_subscriber::fmt::MakeWriter<'a> + Send + Sync + 'static,
{
    tracing_subscriber::fmt()
        .with_max_level(max_level)
        .with_ansi(ansi)
        .with_writer(writer)
        .finish()
}

/// Read an Admin token from a file: the first line, trimmed. An empty
/// or whitespace-only file means "no token", like an unset
/// `WPMULTI_ADMIN_TOKEN`. The token value is never logged.
pub(crate) fn read_auth_token_file(path: &Path) -> Result<Option<String>, String> {
    let content = std::fs::read_to_string(path)
        .map_err(|e| format!("Failed to read admin token file '{}': {e}", path.display()))?;
    Ok(content
        .lines()
        .next()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .map(str::to_string))
}

/// Resolve the Admin token for `top`/`status`/`disable`/`enable`:
/// `--auth-token-file` wins over the `WPMULTI_ADMIN_TOKEN`
/// environment variable; with neither, there is no token.
pub(crate) fn resolve_admin_token(
    auth_token_file: Option<PathBuf>,
    env_token: Option<String>,
) -> Result<Option<String>, String> {
    auth_token_file.map_or_else(
        || Ok(env_token.filter(|token| !token.is_empty())),
        |path| read_auth_token_file(&path),
    )
}

/// Parse arguments and execute the selected subcommand.
pub async fn run_cli() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();
    if let Commands::Run { config, dir } = cli.command {
        return cmd_run(config, dir).await;
    }

    if !matches!(cli.command, Commands::Top { .. }) {
        use std::io::IsTerminal;
        use tracing_subscriber::util::SubscriberInitExt;
        let json_mode = matches!(cli.command, Commands::Probe { json: true, .. });
        let level = if matches!(cli.command, Commands::Probe { .. }) {
            tracing::Level::WARN
        } else {
            tracing::Level::INFO
        };
        let ansi = cli_log_ansi_enabled(json_mode, std::io::stderr().is_terminal());
        let _ = build_cli_tracing_subscriber(level, ansi, std::io::stderr).try_init();
    }
    let env_token = std::env::var("WPMULTI_ADMIN_TOKEN")
        .ok()
        .filter(|s| !s.is_empty());
    match cli.command {
        Commands::Run { .. } => unreachable!(),
        Commands::Top {
            admin_url,
            auth_token_file,
        } => cmd_top(admin_url, resolve_admin_token(auth_token_file, env_token)?).await,
        Commands::Validate { config, dir } => {
            cmd_validate(config, dir)?;
            Ok(())
        }
        Commands::Status {
            admin_url,
            auth_token_file,
        } => {
            cmd_status(admin_url, resolve_admin_token(auth_token_file, env_token)?).await?;
            Ok(())
        }
        Commands::Probe {
            config,
            dir,
            json,
            timeout,
        } => {
            let results = cmd_probe(config, dir, json, timeout).await?;
            // Same rule for table and JSON output: scripts must not read a
            // successful exit code from `--json` when every tunnel failed.
            if !results.is_empty() && results.iter().all(|r| !r.healthy) {
                return Err("All probed tunnels failed".into());
            }
            Ok(())
        }
        Commands::Disable {
            target,
            admin_url,
            auth_token_file,
        } => {
            cmd_toggle_tunnels(
                target,
                true,
                admin_url,
                resolve_admin_token(auth_token_file, env_token)?,
            )
            .await
        }
        Commands::Enable {
            target,
            admin_url,
            auth_token_file,
        } => {
            cmd_toggle_tunnels(
                target,
                false,
                admin_url,
                resolve_admin_token(auth_token_file, env_token)?,
            )
            .await
        }
    }
}
