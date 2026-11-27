//! Command handlers for the `wpmulti` CLI.

use std::collections::HashSet;
use std::fs;
use std::io::Write;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};

use crate::api::AdminServer;
use crate::config::{
    IpMode, MainConfig, TunnelConfig, load_tunnel_config_from_file, load_tunnel_configs_from_dir,
    load_tunnel_configs_from_dir_partial, parse_duration_str,
};
use crate::core::TunnelManager;
use crate::netstack::{DEFAULT_CHANNEL_CAPACITY, VirtualNetworkStack, VirtualTunBridge};
use crate::proxy::router::is_forbidden_destination_ip;
use crate::tui::{TuiApp, TuiDataSource, run_terminal_tui};

fn init_logging(log_level: crate::config::LogLevel, log_buffer: &crate::tui::TuiLogBuffer) {
    use std::io::IsTerminal;
    use tracing_subscriber::fmt::writer::MakeWriterExt;
    use tracing_subscriber::util::SubscriberInitExt;
    let max_level = match log_level {
        crate::config::LogLevel::Trace => tracing::Level::TRACE,
        crate::config::LogLevel::Debug => tracing::Level::DEBUG,
        crate::config::LogLevel::Info => tracing::Level::INFO,
        crate::config::LogLevel::Warn => tracing::Level::WARN,
        crate::config::LogLevel::Error => tracing::Level::ERROR,
    };
    let ansi = super::cli_log_ansi_enabled(false, std::io::stderr().is_terminal());
    let _ = super::build_cli_tracing_subscriber(
        max_level,
        ansi,
        log_buffer.clone().and(std::io::stderr),
    )
    .try_init();
}

const DEFAULT_DAEMON_DRAIN_TIMEOUT: Duration = Duration::from_secs(5);

struct ShutdownSignalGuard {
    absorber: Option<tokio::task::JoinHandle<()>>,
}

impl Drop for ShutdownSignalGuard {
    fn drop(&mut self) {
        if let Some(handle) = self.absorber.take() {
            handle.abort();
        }
    }
}

/// Wait for `SIGINT` (Ctrl+C) or `SIGTERM` (Unix), keeping signal handlers registered during
/// teardown so a second signal cannot panic, deadlock, or trigger abrupt OS termination.
async fn wait_for_shutdown_signal() -> std::io::Result<ShutdownSignalGuard> {
    #[cfg(unix)]
    let mut sigterm = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;

    #[cfg(unix)]
    {
        tokio::select! {
            res = tokio::signal::ctrl_c() => {
                res?;
                tracing::info!("SIGINT received. Starting graceful shutdown...");
            }
            _ = sigterm.recv() => {
                tracing::info!("SIGTERM received. Starting graceful shutdown...");
            }
        }
        let absorber = tokio::spawn(async move {
            loop {
                tokio::select! {
                    _ = tokio::signal::ctrl_c() => {
                        tracing::debug!("Ignoring duplicate SIGINT during graceful drain");
                    }
                    _ = sigterm.recv() => {
                        tracing::debug!("Ignoring duplicate SIGTERM during graceful drain");
                    }
                }
            }
        });
        Ok(ShutdownSignalGuard {
            absorber: Some(absorber),
        })
    }

    #[cfg(not(unix))]
    {
        tokio::signal::ctrl_c().await?;
        tracing::info!("SIGINT received. Starting graceful shutdown...");
        let absorber = tokio::spawn(async {
            while tokio::signal::ctrl_c().await.is_ok() {
                tracing::debug!("Ignoring duplicate SIGINT during graceful drain");
            }
        });
        Ok(ShutdownSignalGuard {
            absorber: Some(absorber),
        })
    }
}

/// Deterministic 4-phase graceful shutdown coordinator across listeners, Admin API, workers, and tunnels.
pub async fn graceful_shutdown(
    manager: &TunnelManager,
    admin_server: Option<&AdminServer>,
    drain_timeout: Duration,
) {
    // 1. Immediately stop accepting new connections on Admin API and all proxy listeners
    if let Some(srv) = admin_server {
        srv.begin_shutdown(drain_timeout);
    }
    manager.listeners().begin_shutdown(drain_timeout);

    // 2. Stop background workers (ActiveProber & idle reaper) before draining/closing tunnels
    manager.prober().stop().await;
    manager.lifecycle().stop_background_tasks().await;

    // 3. Drain active proxy & admin connections concurrently with bounded timeout
    if let Some(srv) = admin_server {
        tokio::join!(
            manager.listeners().drain(drain_timeout),
            srv.drain(drain_timeout),
        );
    } else {
        manager.listeners().drain(drain_timeout).await;
    }

    // 4. Close all tunnels, wake parked stack wakers, and await reactor tasks
    manager.lifecycle().close_all_tunnels().await;
}

/// A `wpmulti.toml` found in the working directory is only trusted when
/// it is owned by the process UID or by root (audit run-1,
/// `config/cwd-wpmulti-toml-discovery-precedence`): without the check a
/// planted file in a shared, extracted, or cloned directory would be
/// loaded as the operator's config and redirect tunnel loading. A
/// root-owned file is trusted because the operator's own install (e.g.
/// `/etc` copies, `sudo` runs) is root-owned; any other owner is not.
#[cfg(unix)]
pub(crate) const fn config_file_owner_trusted(file_uid: u32, process_uid: u32) -> bool {
    file_uid == process_uid || file_uid == 0
}

/// Real UID of this process, read from `/proc/self/status` (Linux and
/// Android; `unsafe_code = "forbid"` rules out `libc::getuid()`).
/// `None` when the UID cannot be determined.
#[cfg(unix)]
fn process_uid() -> Option<u32> {
    let status = fs::read_to_string("/proc/self/status").ok()?;
    for line in status.lines() {
        if let Some(rest) = line.strip_prefix("Uid:") {
            return rest.split_whitespace().next()?.parse().ok();
        }
    }
    None
}

/// A config file found by discovery. `path` is the pathname (used for
/// error messages and for resolving relative `config_dir` entries);
/// `content` carries the file's content when it was read from the same
/// opened file descriptor the owner check ran on (CWD discovery, audit
/// run-3 #2): check and read are bound to one inode, so a symlink
/// swapped after the open cannot redirect the read. `content` is `None`
/// for paths found outside CWD discovery (explicit `-c`, XDG user
/// config), which the caller reads by pathname as before — an explicit
/// operator choice needs no TOCTOU binding.
pub(crate) struct DiscoveredConfig {
    pub path: PathBuf,
    pub content: Option<String>,
}

impl DiscoveredConfig {
    /// An explicitly passed (`-c`) config path: no fd-bound content,
    /// the caller reads it by pathname.
    const fn from_explicit(path: PathBuf) -> Self {
        Self {
            path,
            content: None,
        }
    }
}

/// Open `path`, fstat the fd for the owner check, and read the config
/// from that fd (audit run-3 #2). The open follows symlinks on purpose:
/// a symlink to an operator-owned file is a legitimate config, and the
/// owner check applies to the file actually opened, whichever it is.
/// What the fd binding rules out is the check-then-read swap: the check
/// (`fstat` on the fd) and the read both operate on the opened inode,
/// never on the pathname again, so a symlink swapped after this open
/// cannot redirect either step. `O_NOFOLLOW` was deliberately not used:
/// it would reject symlinks to operator-owned files outright, which is
/// a behaviour change beyond the finding, while the fd binding already
/// provides the security property — the owner decision is always made
/// about the exact inode that is read.
#[cfg(unix)]
fn read_local_config_bound(path: &Path) -> Option<String> {
    use std::io::Read;
    use std::os::unix::fs::MetadataExt;

    let mut file = match fs::File::open(path) {
        Ok(file) => file,
        Err(e) => {
            tracing::warn!(
                "Ignoring wpmulti.toml in working directory '{}': cannot open it: {e}",
                path.display()
            );
            return None;
        }
    };
    // `File::metadata` is `fstat` on the opened fd: bound to the inode
    // above, not to the pathname.
    let file_uid = match file.metadata() {
        Ok(meta) => meta.uid(),
        Err(e) => {
            tracing::warn!(
                "Ignoring wpmulti.toml in working directory '{}': cannot stat it: {e}",
                path.display()
            );
            return None;
        }
    };
    match process_uid() {
        Some(uid) if config_file_owner_trusted(file_uid, uid) => {}
        Some(uid) => {
            tracing::warn!(
                "Ignoring wpmulti.toml in working directory '{}': owned by uid {} (process uid {}); pass -c <file> to use it explicitly",
                path.display(),
                file_uid,
                uid
            );
            return None;
        }
        None => {
            tracing::warn!(
                "Ignoring wpmulti.toml in working directory '{}': cannot determine process uid; pass -c <file> to use it explicitly",
                path.display()
            );
            return None;
        }
    }
    let mut content = String::new();
    if let Err(e) = file.read_to_string(&mut content) {
        tracing::warn!(
            "Ignoring wpmulti.toml in working directory '{}': cannot read it: {e}",
            path.display()
        );
        return None;
    }
    Some(content)
}

/// Find a `wpmulti.toml` in `dir` for `run` when it was started without
/// `-c` or `-d`. `run` without arguments used to ignore a `wpmulti.toml`
/// sitting in the working directory and start with the compiled-in
/// defaults instead (whose `config_dir` points at `/etc/wpmulti/conf.d`),
/// so a user standing in a folder that already had a config got "No
/// WireGuard tunnel configurations found" for a config that was right
/// there.
///
/// Only a file owned by the process UID (or root) is trusted here: a
/// `wpmulti.toml` planted in a shared, extracted, or cloned directory
/// by another local user must not silently override the per-user
/// config. An untrusted file is ignored with a warning; pass `-c
/// <file>` to use such a file explicitly.
pub(crate) fn discover_local_config_in(dir: &Path) -> Option<DiscoveredConfig> {
    let path = dir.join("wpmulti.toml");
    if !path.exists() {
        return None;
    }
    #[cfg(unix)]
    let content = Some(read_local_config_bound(&path)?);
    #[cfg(not(unix))]
    let content: Option<String> = None;
    Some(DiscoveredConfig { path, content })
}

/// Resolve the config file to use when no explicit `-c` was given, in
/// priority order:
/// 1. `wpmulti.toml` in the working directory (the historical behaviour),
///    but only when it is owned by the process UID or root — an
///    untrusted local file is ignored (see
///    [`discover_local_config_in`]).
/// 2. The per-user `wpmulti.toml` under the XDG config directory
///    (`$XDG_CONFIG_HOME/wpmulti/wpmulti.toml`, or
///    `~/.config/wpmulti/wpmulti.toml` when `XDG_CONFIG_HOME` is unset) —
///    the universal location, present on Termux, Ubuntu, Debian and other
///    Unix systems.
///
/// Returns `None` when neither exists and the caller falls back to the
/// compiled-in defaults.
pub(crate) fn discover_default_config() -> Option<DiscoveredConfig> {
    discover_default_config_in(
        Path::new("."),
        std::env::var_os("XDG_CONFIG_HOME").as_deref(),
        std::env::var_os("HOME").as_deref(),
    )
}

/// Testable core of [`discover_default_config`]: `cwd` is the working
/// directory, `xdg_config_home` / `home` the environment values (or
/// `None` when unset).
pub(crate) fn discover_default_config_in(
    cwd: &Path,
    xdg_config_home: Option<&std::ffi::OsStr>,
    home: Option<&std::ffi::OsStr>,
) -> Option<DiscoveredConfig> {
    if let Some(local) = discover_local_config_in(cwd) {
        return Some(local);
    }
    user_config_file(xdg_config_home, home)
        .filter(|path| path.exists())
        .map(|path| DiscoveredConfig {
            path,
            content: None,
        })
}

/// Absolute path of the per-user config file:
/// `$XDG_CONFIG_HOME/wpmulti/wpmulti.toml` when `XDG_CONFIG_HOME` names
/// an absolute directory, otherwise `$HOME/.config/wpmulti/wpmulti.toml`.
/// `None` when neither location can be determined (no `HOME` and no
/// usable `XDG_CONFIG_HOME`).
fn user_config_file(
    xdg_config_home: Option<&std::ffi::OsStr>,
    home: Option<&std::ffi::OsStr>,
) -> Option<PathBuf> {
    if let Some(xdg) = xdg_config_home {
        let base = PathBuf::from(xdg);
        if !xdg.is_empty() && base.is_absolute() {
            return Some(base.join("wpmulti").join("wpmulti.toml"));
        }
    }
    let home = PathBuf::from(home?);
    Some(home.join(".config").join("wpmulti").join("wpmulti.toml"))
}

/// Report one quarantined `.conf` file on stderr. `tracing` is not
/// usable here yet: `run`/`probe` print before logging is initialized,
/// and `eprintln!` is banned by the repo lint config — the locked
/// `stderr` write below is the same pattern `cmd_validate` uses for
/// stdout.
fn warn_skipped_tunnel_config(failure: &crate::config::TunnelLoadFailure) {
    let mut err_out = std::io::stderr().lock();
    let _ = writeln!(
        err_out,
        "warning: skipping broken tunnel config '{}': {}",
        failure.path.display(),
        failure.error
    );
}

/// Load tunnels for `run`, degraded (audit run-1,
/// `config/load-dir-single-bad-conf-fails-all`): one broken `.conf`
/// must not block the whole daemon. Returns the valid set, warns about
/// each quarantined file, and only refuses to start when nothing valid
/// remains. `validate` keeps the strict loader.
fn load_tunnels_for_run(config_dir: &Path) -> Result<Vec<TunnelConfig>, String> {
    if !config_dir.exists() {
        return Ok(Vec::new());
    }
    let partial = load_tunnel_configs_from_dir_partial(config_dir)
        .map_err(|e| format!("Failed to load tunnels: {e}"))?;
    for failure in &partial.failures {
        warn_skipped_tunnel_config(failure);
    }
    if partial.configs.is_empty() && !partial.failures.is_empty() {
        return Err(format!(
            "Failed to load tunnels: {}",
            partial
                .failures
                .iter()
                .map(|f| f.error.as_str())
                .collect::<Vec<_>>()
                .join("\n")
        ));
    }
    Ok(partial.configs)
}

/// Execute the `wpmulti run` command: starts the multi-tunnel daemon.
/// Monitoring a running daemon is done with `wpmulti top`, which reads
/// it through the Admin API; `run` itself stays a plain daemon.
pub async fn cmd_run(
    config_path: Option<PathBuf>,
    dir_path: Option<PathBuf>,
) -> Result<(), Box<dyn std::error::Error>> {
    // No explicit `-c`: a `wpmulti.toml` in the working directory wins,
    // then the per-user config under the XDG config directory
    // (`~/.config/wpmulti/wpmulti.toml` by default), then the compiled-in
    // defaults. This applies with `-d` too: `-d` only overrides where the
    // tunnel `.conf` files live, it must not silently discard the user's
    // config.
    let config_path = config_path
        .map(DiscoveredConfig::from_explicit)
        .or_else(discover_default_config);
    let saved_config_path = config_path.as_ref().map(|found| found.path.clone());
    let mut config = if let Some(found) = config_path {
        // A CWD-discovered config carries content read from the opened
        // fd (audit run-3 #2): use it, never re-resolve the pathname.
        // Anything else (explicit `-c`, XDG user config) is read by
        // pathname as before.
        let content = match found.content {
            Some(content) => content,
            None => tokio::fs::read_to_string(&found.path).await.map_err(|e| {
                format!(
                    "Failed to read config file '{}': {}",
                    found.path.display(),
                    e
                )
            })?,
        };
        let mut cfg = MainConfig::from_toml_str(&content).map_err(|e| {
            format!(
                "Failed to parse config file '{}': {}",
                found.path.display(),
                e
            )
        })?;
        cfg.resolve_config_dir_against(&found.path);
        cfg
    } else {
        MainConfig::default()
    };

    if let Some(dir) = dir_path {
        config.global.config_dir = dir;
    }

    let tunnels = load_tunnels_for_run(&config.global.config_dir)?;

    if tunnels.is_empty() {
        return Err(format!(
            "No WireGuard tunnel configurations found in '{}' (directory missing or empty). Create .conf files there first, pass -d <dir> with your tunnel configs, or run from a directory containing wpmulti.toml (or pass -c <file>); refusing to start a daemon with 0 tunnels.",
            config.global.config_dir.display()
        )
        .into());
    }

    // A config that names a tunnel ID no .conf file provides (a typo in
    // `pool`, `disabled_tunnels`, `eager_tunnels`, or an override key)
    // would otherwise start fine and only fail later as `no healthy
    // tunnels available in pool` — refuse to start instead.
    let known_ids: HashSet<String> = tunnels.iter().map(|t| t.id.clone()).collect();
    config
        .validate_tunnel_references(&known_ids)
        .map_err(|e| format!("Invalid tunnel reference: {e}"))?;

    let total_tunnels = tunnels.len();
    let manager = Arc::new(
        TunnelManager::new(config.clone(), tunnels)
            .map_err(|e| format!("Failed to initialize TunnelManager: {e}"))?,
    );

    let tui_log_buffer = manager.log_buffer().clone();
    if let Some(ref cfg_path) = saved_config_path {
        manager.set_config_path(cfg_path.clone());
    }
    init_logging(config.global.log_level, &tui_log_buffer);

    let admin_server = if config.admin.enabled {
        let srv = AdminServer::new(
            config.admin.bind,
            Arc::clone(&manager),
            config.admin.auth_token.clone(),
        );
        let bound = srv.start().await?;
        tracing::info!("Admin HTTP API listening on http://{}", bound);
        Some(srv)
    } else {
        None
    };

    if let Err(e) = manager.start().await {
        graceful_shutdown(&manager, admin_server.as_ref(), Duration::from_secs(1)).await;
        return Err(format!("Failed to start TunnelManager: {e}").into());
    }
    tracing::info!(
        "wpmulti daemon started successfully with {} tunnels",
        total_tunnels
    );
    if saved_config_path.is_none() {
        tracing::info!(
            "Running without a config file: dedicated per-tunnel ports active (pass -c <file>, or place wpmulti.toml at ~/.config/wpmulti/wpmulti.toml, for shared listeners & Admin API)."
        );
    }
    log_active_listeners(&manager.listeners().list_listeners());

    // The daemon runs until it receives SIGINT/SIGTERM; monitoring a
    // running daemon is `wpmulti top`'s job, not `run`'s.
    tracing::info!("Daemon running. Send SIGINT or SIGTERM to terminate.");
    let _signal_guard = wait_for_shutdown_signal().await?;
    graceful_shutdown(
        &manager,
        admin_server.as_ref(),
        DEFAULT_DAEMON_DRAIN_TIMEOUT,
    )
    .await;

    tracing::info!("wpmulti stopped cleanly.");
    Ok(())
}

fn log_active_listeners(listeners: &[crate::core::ActiveListenerInfo]) {
    if listeners.is_empty() {
        tracing::info!("No proxy listeners active.");
        return;
    }
    let mut dedicated_socks = Vec::new();
    let mut dedicated_http = Vec::new();
    for info in listeners {
        if info.is_shared {
            let kind = match info.listener_type {
                crate::config::ListenerType::Socks5 => "socks5",
                crate::config::ListenerType::Http => "http",
            };
            tracing::info!(
                "Shared {} listener '{}' listening on {}",
                kind,
                info.name,
                info.address
            );
        } else {
            let tid = info.tunnel_id.as_deref().unwrap_or("unknown");
            match info.listener_type {
                crate::config::ListenerType::Socks5 => {
                    dedicated_socks.push((tid.to_string(), info.address));
                }
                crate::config::ListenerType::Http => {
                    dedicated_http.push((tid.to_string(), info.address));
                }
            }
        }
    }
    for (label, entries) in [("socks5", dedicated_socks), ("http", dedicated_http)] {
        if let (Some((_, first)), Some((_, last))) = (entries.first(), entries.last()) {
            if entries.len() == 1 {
                if let Some((tid, addr)) = entries.first() {
                    tracing::info!("Dedicated {label} listener: {tid} -> {addr}");
                }
            } else if entries.len() <= 20 {
                let mapping: Vec<String> = entries
                    .iter()
                    .map(|(tid, addr)| format!("{tid}={addr}"))
                    .collect();
                tracing::info!(
                    "Dedicated {label} listeners ({}): {}",
                    entries.len(),
                    mapping.join(", ")
                );
            } else {
                tracing::info!(
                    "Dedicated {label} listeners: {} ({first} .. {last})",
                    entries.len()
                );
            }
        }
    }
}

/// Execute the `wpmulti validate` command: validates config and tunnel files without binding ports.
pub fn cmd_validate(
    config_path: Option<PathBuf>,
    dir_path: Option<PathBuf>,
) -> Result<usize, Box<dyn std::error::Error>> {
    // Same discovery as `run`: an explicit `-c` wins, then
    // `./wpmulti.toml`, then `~/.config/wpmulti/wpmulti.toml`.
    let config_path = config_path
        .map(DiscoveredConfig::from_explicit)
        .or_else(discover_default_config);
    let mut config = if let Some(found) = config_path {
        // A CWD-discovered config carries content read from the opened
        // fd (audit run-3 #2): use it, never re-resolve the pathname.
        // Anything else (explicit `-c`, XDG user config) is read by
        // pathname as before.
        let content = match found.content {
            Some(content) => content,
            None => fs::read_to_string(&found.path).map_err(|e| {
                format!(
                    "Failed to read config file '{}': {}",
                    found.path.display(),
                    e
                )
            })?,
        };
        let mut cfg = MainConfig::from_toml_str(&content).map_err(|e| {
            format!(
                "Failed to parse config file '{}': {}",
                found.path.display(),
                e
            )
        })?;
        cfg.resolve_config_dir_against(&found.path);
        cfg
    } else {
        MainConfig::default()
    };

    if let Some(dir) = dir_path {
        config.global.config_dir = dir;
    }

    if !config.global.config_dir.exists() {
        return Err(format!(
            "Tunnel directory '{}' does not exist",
            config.global.config_dir.display()
        )
        .into());
    }
    let tunnels = load_tunnel_configs_from_dir(&config.global.config_dir)?;

    // Same check as `run`: a config referencing a tunnel ID that no
    // loaded `.conf` provides is a typo until proven otherwise.
    let known_ids: HashSet<String> = tunnels.iter().map(|t| t.id.clone()).collect();
    config
        .validate_tunnel_references(&known_ids)
        .map_err(|e| format!("Invalid tunnel reference: {e}"))?;

    let count = tunnels.len();
    let mut out = std::io::stdout().lock();
    let _ = writeln!(out, "Configuration valid.");
    let _ = writeln!(
        out,
        "Found {} valid WireGuard tunnel configuration(s) in '{}'.",
        count,
        config.global.config_dir.display()
    );
    Ok(count)
}

/// Execute the `wpmulti status` command: fetches daemon status from Admin API and prints to stdout.
pub async fn cmd_status(
    admin_url: String,
    auth_token: Option<String>,
) -> Result<serde_json::Value, Box<dyn std::error::Error>> {
    let body =
        crate::tui::app::admin_http_request(&admin_url, "GET", "/status", auth_token.as_deref())
            .await
            .map_err(std::io::Error::other)?;

    let val: serde_json::Value =
        serde_json::from_slice(&body).map_err(|e| format!("Failed to parse JSON response: {e}"))?;

    let _ = writeln!(
        std::io::stdout().lock(),
        "{}",
        serde_json::to_string_pretty(&val)?
    );
    Ok(val)
}

/// Execute the `wpmulti top` command: launches the standalone interactive TUI monitor.
pub async fn cmd_top(
    admin_url: String,
    auth_token: Option<String>,
) -> Result<(), Box<dyn std::error::Error>> {
    let source = TuiDataSource {
        admin_url,
        auth_token,
    };
    let app = TuiApp::new(source, crate::config::TuiSortField::Id);
    run_terminal_tui(app, 500).await?;
    Ok(())
}

/// Human-readable error for a failed Admin API call: an HTTP status
/// response is reported as what the API returned — the API was reached,
/// the request itself failed (e.g. unknown tunnel name) — while
/// transport errors keep their own wording, which already names the
/// Admin API.
pub(crate) fn admin_api_call_error(e: String) -> String {
    if e.starts_with("HTTP ") {
        format!("Admin API returned {e}")
    } else if e.starts_with("Failed to connect") || e.starts_with("Timed out") {
        e
    } else {
        format!("Failed to reach Admin API: {e}")
    }
}

/// Enable or disable tunnels (`A`, `1`, `1-200`, `all`) via Admin API.
pub async fn cmd_toggle_tunnels(
    target: String,
    disabled: bool,
    admin_url: String,
    auth_token: Option<String>,
) -> Result<(), Box<dyn std::error::Error>> {
    let path = if disabled {
        "/tunnels/batch/disable"
    } else {
        "/tunnels/batch/enable"
    };
    let body = serde_json::to_vec(&serde_json::json!({ "target": target }))?;
    let resp = crate::tui::app::admin_http_request_with_body(
        &admin_url,
        "POST",
        path,
        auth_token.as_deref(),
        Some(&body),
    )
    .await
    .map_err(admin_api_call_error)?;
    let val: serde_json::Value = serde_json::from_slice(&resp)?;
    let count = val
        .get("count")
        .and_then(serde_json::Value::as_u64)
        .unwrap_or(0);
    let action = if disabled { "Disabled" } else { "Enabled" };
    let _ = writeln!(
        std::io::stdout().lock(),
        "{action} {count} tunnel(s) matching '{target}'."
    );
    Ok(())
}

/// Diagnostic result of probing a single WireGuard configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProbeResult {
    /// Tunnel ID.
    pub id: String,
    /// Path or name of configuration file.
    pub config_file: String,
    /// Peer endpoint address.
    pub endpoint: String,
    /// Whether handshake and connectivity probe succeeded.
    pub healthy: bool,
    /// Round-trip time in milliseconds, if handshake succeeded.
    pub rtt_ms: Option<f64>,
    /// In-tunnel exit IP address, if measured. The probe verifies
    /// egress with an in-tunnel DNS query, which proves the data
    /// plane carries traffic but does not reveal the egress address,
    /// so this is currently always `None`: an unmeasured address
    /// (e.g. the locally configured interface address) is never
    /// reported as the exit IP.
    pub exit_ip: Option<String>,
    /// Error message, if probe failed.
    pub error: Option<String>,
}

fn probe_error_result(
    id: &str,
    config_file: String,
    endpoint: String,
    error: String,
) -> ProbeResult {
    ProbeResult {
        id: id.to_string(),
        config_file,
        endpoint,
        healthy: false,
        rtt_ms: None,
        exit_ip: None,
        error: Some(error),
    }
}

async fn build_probe_peers(config: &TunnelConfig, timeout: Duration) -> Vec<gotatun::device::Peer> {
    let mut peers = Vec::with_capacity(config.peers.len());
    for p_cfg in &config.peers {
        let mut peer = gotatun::device::Peer::new(p_cfg.public_key);
        if let Ok(addr) = p_cfg.endpoint.parse::<SocketAddr>() {
            peer.endpoint = Some(addr);
        } else if let Ok(Ok(mut addrs)) =
            tokio::time::timeout(timeout, tokio::net::lookup_host(&p_cfg.endpoint)).await
        {
            // Same rule as `LifecycleController::build_peers`: never
            // handshake an endpoint the host resolver points at a
            // forbidden address (audit run-1,
            // `lifecycle:build-peers-unchecked-dns-endpoint`). Take
            // the first allowed answer; leave the endpoint unset when
            // every answer is forbidden.
            peer.endpoint = addrs.find(|addr| !is_forbidden_destination_ip(addr.ip()));
        } else {
            // Endpoint unresolvable; leave peer.endpoint as None.
        }
        peer.allowed_ips = p_cfg.allowed_ips.clone();
        peer.preshared_key = p_cfg.preshared_key;
        peer.keepalive = p_cfg.persistent_keepalive;
        peers.push(peer);
    }
    peers
}

/// Run probe for a single tunnel config.
pub async fn run_probe_single(
    config: &TunnelConfig,
    config_file: String,
    timeout: Duration,
) -> ProbeResult {
    let endpoint = config
        .peers
        .first()
        .map_or_else(|| "none".to_string(), |p| p.endpoint.clone());

    let Some(peer_pubkey) = config.peers.first().map(|p| p.public_key) else {
        return probe_error_result(
            &config.id,
            config_file,
            endpoint,
            "no peers configured in tunnel file".to_string(),
        );
    };

    let (bridge, bridge_tx, bridge_rx) =
        VirtualTunBridge::new(config.interface.mtu, DEFAULT_CHANNEL_CAPACITY);
    let peers = build_probe_peers(config, timeout).await;

    let mut builder = gotatun::device::DeviceBuilder::new()
        .with_default_udp()
        .with_ip_pair(bridge_tx, bridge_rx)
        .with_private_key(config.interface.private_key.clone())
        .with_peers(peers)
        .suspended(false);

    if let Some(port) = config.interface.listen_port {
        builder = builder.with_listen_port(port);
    }

    let device = match builder.build().await {
        Ok(d) => d,
        Err(e) => {
            return probe_error_result(
                &config.id,
                config_file,
                endpoint,
                format!("failed to build WireGuard device: {e}"),
            );
        }
    };

    let netstack = match VirtualNetworkStack::new_with_mode(
        &config.interface,
        bridge,
        IpMode::DualStack,
        false,
    ) {
        Ok(ns) => ns,
        Err(e) => {
            let () = device.suspend().await;
            return probe_error_result(
                &config.id,
                config_file,
                endpoint,
                format!("failed to build network stack: {e}"),
            );
        }
    };

    let t0 = Instant::now();
    let handshake_res = tokio::time::timeout(timeout, device.force_handshake(&peer_pubkey)).await;

    // A handshake alone proves only that the peer answers: the tunnel
    // is healthy only when the data plane also carries traffic, so a
    // successful handshake is followed by an uncached in-tunnel DNS
    // egress probe through the netstack that was built for this probe
    // (audit run-1,
    // `cli/probe/handshake-only-healthy-unmeasured-exit-ip`). The
    // egress probe gets the time left from the probe timeout, so one
    // probe costs at most `timeout` in total.
    let (healthy, rtt_ms, error) = match handshake_res {
        Ok(Ok(())) => {
            let remaining = timeout.checked_sub(t0.elapsed()).unwrap_or(Duration::ZERO);
            match netstack.probe_egress(remaining).await {
                Ok(()) => {
                    let elapsed = t0.elapsed().as_secs_f64() * 1000.0;
                    (true, Some(elapsed), None)
                }
                Err(e) => (
                    false,
                    None,
                    Some(format!("handshake ok but egress probe failed: {e}")),
                ),
            }
        }
        Ok(Err(e)) => (false, None, Some(format!("handshake failed: {e}"))),
        Err(_) => (
            false,
            None,
            Some(format!("handshake timed out after {timeout:?}")),
        ),
    };

    // No in-tunnel egress address is ever measured by this probe, so
    // none is reported: the configured interface address is the local
    // tunnel address, not the observed exit IP.
    let exit_ip = None;

    let () = device.suspend().await;
    netstack.close().await;

    ProbeResult {
        id: config.id.clone(),
        config_file,
        endpoint,
        healthy,
        rtt_ms,
        exit_ip,
        error,
    }
}

/// Execute the `wpmulti probe` command: probes one or more WireGuard configuration files.
pub async fn cmd_probe(
    config_path: Option<PathBuf>,
    dir_path: Option<PathBuf>,
    json_output: bool,
    timeout_str: String,
) -> Result<Vec<ProbeResult>, Box<dyn std::error::Error>> {
    const MAX_CONCURRENT_PROBES: usize = 32;

    let timeout = parse_duration_str(&timeout_str)
        .map_err(|e| format!("Invalid probe timeout '{timeout_str}': {e}"))?;

    let configs_with_path: Vec<(TunnelConfig, String)> = match (config_path, dir_path) {
        (Some(file), None) => {
            if file
                .extension()
                .is_some_and(|e| e.eq_ignore_ascii_case("toml"))
            {
                return Err(format!(
                    "File '{}' looks like a wpmulti.toml config; pass a single WireGuard .conf file to -c/--config or use -d/--dir <conf.d>",
                    file.display()
                )
                .into());
            }
            let t = load_tunnel_config_from_file(&file)
                .map_err(|e| format!("Failed to load config '{}': {}", file.display(), e))?;
            vec![(t, file.display().to_string())]
        }
        (None, Some(dir)) => {
            // Degraded probe (audit run-1,
            // `config/load-dir-single-bad-conf-fails-all`): probe the
            // healthy tunnels and report the broken files instead of
            // refusing the whole directory.
            let partial = load_tunnel_configs_from_dir_partial(&dir)
                .map_err(|e| format!("Failed to load configs from '{}': {}", dir.display(), e))?;
            for failure in &partial.failures {
                warn_skipped_tunnel_config(failure);
            }
            if partial.configs.is_empty() && !partial.failures.is_empty() {
                return Err(format!(
                    "Failed to load configs from '{}': all {} tunnel config(s) failed to load",
                    dir.display(),
                    partial.failures.len()
                )
                .into());
            }
            partial
                .configs
                .into_iter()
                .map(|t| {
                    let filename = format!("{}/{}.conf", dir.display(), t.id);
                    (t, filename)
                })
                .collect()
        }
        (Some(_), Some(_)) => {
            return Err("Cannot specify both -c/--config and -d/--dir simultaneously".into());
        }
        (None, None) => {
            return Err("Must specify either -c/--config <FILE> or -d/--dir <DIR>".into());
        }
    };

    if configs_with_path.is_empty() {
        let mut out = std::io::stdout().lock();
        if json_output {
            write_probe_json(&mut out, &[])?;
        } else {
            let _ = writeln!(out, "No tunnel configurations found to probe.");
        }
        return Ok(Vec::new());
    }

    let sem = Arc::new(tokio::sync::Semaphore::new(MAX_CONCURRENT_PROBES));
    let mut set = tokio::task::JoinSet::new();
    let total = configs_with_path.len();

    for (idx, (cfg, file)) in configs_with_path.into_iter().enumerate() {
        let sem_clone = Arc::clone(&sem);
        set.spawn(async move {
            let _permit = sem_clone.acquire_owned().await.ok();
            let res = run_probe_single(&cfg, file, timeout).await;
            (idx, res)
        });
    }

    let mut indexed_results = Vec::with_capacity(total);
    while let Some(joined) = set.join_next().await {
        if let Ok(item) = joined {
            indexed_results.push(item);
        }
    }
    indexed_results.sort_by_key(|(idx, _)| *idx);
    let results: Vec<ProbeResult> = indexed_results.into_iter().map(|(_, r)| r).collect();

    if json_output {
        write_probe_json(&mut std::io::stdout().lock(), &results)?;
    } else {
        print_probe_table(&results);
    }
    write_udp_blocked_hint(&mut std::io::stderr().lock(), &results);

    Ok(results)
}

/// Write serialized probe results as a single pretty-printed JSON payload.
pub(crate) fn write_probe_json<W: Write>(
    out: &mut W,
    results: &[ProbeResult],
) -> Result<(), Box<dyn std::error::Error>> {
    writeln!(out, "{}", serde_json::to_string_pretty(results)?)?;
    Ok(())
}

/// Warn on stderr when a probe failure looks like UDP being blocked in this
/// environment (sandbox/container without permission to send UDP). WireGuard
/// handshakes need UDP, so such a failure says nothing about the tunnel
/// configs themselves — without this hint the user cannot tell a broken
/// setup apart from a blocked environment. Prints nothing otherwise, and
/// never touches stdout, so `--json` output stays parseable.
pub(crate) fn write_udp_blocked_hint<W: Write>(out: &mut W, results: &[ProbeResult]) {
    let blocked = results.iter().any(|r| {
        r.error.as_deref().is_some_and(|err| {
            let lower = err.to_lowercase();
            lower.contains("operation not permitted") || lower.contains("permission denied")
        })
    });
    if blocked {
        let _ = writeln!(
            out,
            "Hint: a tunnel failed with \"Operation not permitted\" — UDP appears to be blocked in this environment, and WireGuard handshakes need UDP. The tunnel configs themselves may be fine. Quick check: python3 -c \"import socket; socket.socket(socket.AF_INET, socket.SOCK_DGRAM).sendto(b'x', ('8.8.8.8', 53))\""
        );
    }
}

fn print_probe_table(results: &[ProbeResult]) {
    print_probe_table_to(&mut std::io::stdout().lock(), results);
}

pub(crate) fn print_probe_table_to<W: Write>(out: &mut W, results: &[ProbeResult]) {
    let _ = writeln!(
        out,
        "┌──────────┬──────────────────────┬─────────────┬────────────────┬────────────────────────┬──────────────────────────────┐"
    );
    let _ = writeln!(
        out,
        "│ STATUS   │ CONFIG               │ RTT         │ EXIT IP        │ ENDPOINT               │ ERROR                        │"
    );
    let _ = writeln!(
        out,
        "├──────────┼──────────────────────┼─────────────┼────────────────┼────────────────────────┼──────────────────────────────┤"
    );

    let mut passed = 0;
    let mut failed = 0;

    for r in results {
        let status = if r.healthy {
            passed += 1;
            "OK"
        } else {
            failed += 1;
            "FAILED"
        };

        let rtt = r
            .rtt_ms
            .map_or_else(|| "-".to_string(), |ms| format!("{ms:.1} ms"));

        let exit_ip = r.exit_ip.as_deref().unwrap_or("-");
        let err_msg = r.error.as_deref().unwrap_or("-");

        let clean_id: String = r.id.chars().filter(|c| !c.is_control()).collect();
        let clean_exit: String = exit_ip.chars().filter(|c| !c.is_control()).collect();
        let clean_ep: String = r.endpoint.chars().filter(|c| !c.is_control()).collect();
        let clean_err: String = err_msg.chars().filter(|c| !c.is_control()).collect();

        let _ = writeln!(
            out,
            "│ {:<8} │ {:<20} │ {:<11} │ {:<14} │ {:<22} │ {:<28} │",
            status,
            truncate_str(&clean_id, 20),
            truncate_str(&rtt, 11),
            truncate_str(&clean_exit, 14),
            truncate_str(&clean_ep, 22),
            truncate_str(&clean_err, 28),
        );
    }

    let _ = writeln!(
        out,
        "└──────────┴──────────────────────┴─────────────┴────────────────┴────────────────────────┴──────────────────────────────┘"
    );
    let _ = writeln!(
        out,
        "Probe completed: {} passed, {} failed (total {}).",
        passed,
        failed,
        results.len()
    );
    if failed > 0 {
        let _ = writeln!(out, "Failed probe errors (full text):");
        for r in results.iter().filter(|r| !r.healthy) {
            if let Some(err) = r.error.as_deref() {
                let clean: String = err.chars().filter(|c| !c.is_control()).collect();
                let _ = writeln!(out, "  {}: {}", r.id, clean);
            }
        }
    }
}

fn truncate_str(s: &str, max_len: usize) -> String {
    if s.chars().count() > max_len {
        let prefix: String = s.chars().take(max_len.saturating_sub(1)).collect();
        format!("{prefix}…")
    } else {
        s.to_string()
    }
}
