//! Command handlers for the `wpmulti` CLI.

use std::fs;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};

use crate::api::AdminServer;
use crate::config::{
    load_tunnel_config_from_file, load_tunnel_configs_from_dir, parse_duration_str, IpMode,
    MainConfig, TunnelConfig,
};
use crate::core::TunnelManager;
use crate::netstack::{VirtualNetworkStack, VirtualTunBridge, DEFAULT_CHANNEL_CAPACITY};
use crate::tui::{run_terminal_tui, TuiApp, TuiDataSource};

/// Execute the `wpmulti run` command: starts multi-tunnel daemon and optional TUI.
pub async fn cmd_run(
    config_path: Option<PathBuf>,
    dir_path: Option<PathBuf>,
    tui_mode: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    let saved_config_path = config_path.clone();
    let mut config = if let Some(path) = config_path {
        let content = fs::read_to_string(&path)
            .map_err(|e| format!("Failed to read config file '{}': {}", path.display(), e))?;
        MainConfig::from_toml_str(&content)
            .map_err(|e| format!("Failed to parse config file '{}': {}", path.display(), e))?
    } else {
        MainConfig::default()
    };

    if let Some(dir) = dir_path {
        config.global.config_dir = dir;
    }

    let max_level = match config.global.log_level {
        crate::config::LogLevel::Trace => tracing::Level::TRACE,
        crate::config::LogLevel::Debug => tracing::Level::DEBUG,
        crate::config::LogLevel::Info => tracing::Level::INFO,
        crate::config::LogLevel::Warn => tracing::Level::WARN,
        crate::config::LogLevel::Error => tracing::Level::ERROR,
    };
    let tunnels = if config.global.config_dir.exists() {
        load_tunnel_configs_from_dir(&config.global.config_dir)
            .map_err(|e| format!("Failed to load tunnels: {}", e))?
    } else {
        Vec::new()
    };

    let total_tunnels = tunnels.len();
    let manager = Arc::new(
        TunnelManager::new(config.clone(), tunnels)
            .map_err(|e| format!("Failed to initialize TunnelManager: {}", e))?,
    );

    let tui_log_buffer = manager.log_buffer().clone();
    if tui_mode {
        let _ = tracing_subscriber::fmt()
            .with_max_level(max_level)
            .with_ansi(false)
            .with_writer(tui_log_buffer.clone())
            .try_init();
    } else {
        use tracing_subscriber::fmt::writer::MakeWriterExt;
        let _ = tracing_subscriber::fmt()
            .with_max_level(max_level)
            .with_writer(tui_log_buffer.clone().and(std::io::stdout))
            .try_init();
    }
    let tui_log_buffer = Some(tui_log_buffer);

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

    manager
        .start()
        .await
        .map_err(|e| format!("Failed to start TunnelManager: {}", e))?;
    tracing::info!(
        "wpmulti daemon started successfully with {} tunnels",
        total_tunnels
    );

    if tui_mode {
        let mut app = TuiApp::new(
            TuiDataSource::InProcess(Arc::clone(&manager)),
            config.tui.default_sort,
        );
        if let Some(buf) = tui_log_buffer {
            app = app.with_log_buffer(buf);
        }
        if let Some(path) = saved_config_path {
            app = app.with_config_path(path);
        }
        let _ = run_terminal_tui(app, config.tui.refresh_rate_ms).await;

        tracing::info!("TUI exited. Stopping daemon...");
        let _ = manager.stop().await;
        if let Some(srv) = admin_server {
            srv.stop().await;
        }
    } else {
        tracing::info!("Daemon running. Press Ctrl+C to terminate.");
        tokio::signal::ctrl_c().await?;
        tracing::info!("Shutdown signal received. Stopping daemon...");
        let _ = manager.stop().await;
        if let Some(srv) = admin_server {
            srv.stop().await;
        }
    }

    tracing::info!("wpmulti stopped cleanly.");
    Ok(())
}

/// Execute the `wpmulti validate` command: validates config and tunnel files without binding ports.
pub fn cmd_validate(
    config_path: Option<PathBuf>,
    dir_path: Option<PathBuf>,
) -> Result<usize, Box<dyn std::error::Error>> {
    let mut config = if let Some(path) = config_path {
        let content = fs::read_to_string(&path)
            .map_err(|e| format!("Failed to read config file '{}': {}", path.display(), e))?;
        MainConfig::from_toml_str(&content)
            .map_err(|e| format!("Failed to parse config file '{}': {}", path.display(), e))?
    } else {
        MainConfig::default()
    };

    if let Some(dir) = dir_path {
        config.global.config_dir = dir;
    }

    let tunnels = if config.global.config_dir.exists() {
        load_tunnel_configs_from_dir(&config.global.config_dir)?
    } else {
        Vec::new()
    };

    let count = tunnels.len();
    println!("Configuration valid.");
    println!(
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
    let body = crate::tui::app::admin_http_request(
        &admin_url,
        "GET",
        "/status",
        auth_token.as_deref(),
    )
    .await
    .map_err(std::io::Error::other)?;

    let val: serde_json::Value = serde_json::from_slice(&body)
        .map_err(|e| format!("Failed to parse JSON response: {}", e))?;

    println!("{}", serde_json::to_string_pretty(&val)?);
    Ok(val)
}

/// Execute the `wpmulti top` command: launches the standalone interactive TUI monitor.
pub async fn cmd_top(
    admin_url: String,
    auth_token: Option<String>,
) -> Result<(), Box<dyn std::error::Error>> {
    let source = TuiDataSource::Remote {
        admin_url,
        auth_token,
    };
    let app = TuiApp::new(source, crate::config::TuiSortField::Id);
    run_terminal_tui(app, 500).await?;
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
    /// In-tunnel exit IP address, if available.
    pub exit_ip: Option<String>,
    /// Error message, if probe failed.
    pub error: Option<String>,
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
        .map(|p| p.endpoint.clone())
        .unwrap_or_else(|| "none".to_string());

    let peer_pubkey = match config.peers.first().map(|p| p.public_key) {
        Some(pk) => pk,
        None => {
            return ProbeResult {
                id: config.id.clone(),
                config_file,
                endpoint,
                healthy: false,
                rtt_ms: None,
                exit_ip: None,
                error: Some("no peers configured in tunnel file".to_string()),
            };
        }
    };

    let (bridge, bridge_tx, bridge_rx) =
        VirtualTunBridge::new(config.interface.mtu, DEFAULT_CHANNEL_CAPACITY);

    let mut peers = Vec::with_capacity(config.peers.len());
    for p_cfg in &config.peers {
        let mut peer = gotatun::device::Peer::new(p_cfg.public_key);
        if let Ok(addr) = p_cfg.endpoint.parse::<SocketAddr>() {
            peer.endpoint = Some(addr);
        } else if let Ok(mut addrs) = tokio::net::lookup_host(&p_cfg.endpoint).await {
            peer.endpoint = addrs.next();
        }
        peer.allowed_ips = p_cfg.allowed_ips.clone();
        peer.preshared_key = p_cfg.preshared_key;
        peer.keepalive = p_cfg.persistent_keepalive;
        peers.push(peer);
    }

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
            return ProbeResult {
                id: config.id.clone(),
                config_file,
                endpoint,
                healthy: false,
                rtt_ms: None,
                exit_ip: None,
                error: Some(format!("failed to build WireGuard device: {e}")),
            };
        }
    };

    let netstack = match VirtualNetworkStack::new_with_mode(
        &config.interface,
        bridge,
        IpMode::DualStack,
        false,
    )
    .await
    {
        Ok(ns) => ns,
        Err(e) => {
            let _ = device.suspend().await;
            return ProbeResult {
                id: config.id.clone(),
                config_file,
                endpoint,
                healthy: false,
                rtt_ms: None,
                exit_ip: None,
                error: Some(format!("failed to build network stack: {e}")),
            };
        }
    };

    let t0 = Instant::now();
    let handshake_res = tokio::time::timeout(timeout, device.force_handshake(&peer_pubkey)).await;

    let (healthy, rtt_ms, error) = match handshake_res {
        Ok(Ok(())) => {
            let elapsed = t0.elapsed().as_secs_f64() * 1000.0;
            (true, Some(elapsed), None)
        }
        Ok(Err(e)) => (false, None, Some(format!("handshake failed: {e}"))),
        Err(_) => (false, None, Some(format!("handshake timed out after {:?}", timeout))),
    };

    let exit_ip = if healthy {
        config.interface.addresses.first().map(|net| net.ip().to_string())
    } else {
        None
    };

    let _ = device.suspend().await;
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
    let timeout = parse_duration_str(&timeout_str)
        .map_err(|e| format!("Invalid probe timeout '{}': {}", timeout_str, e))?;

    let configs_with_path: Vec<(TunnelConfig, String)> = match (config_path, dir_path) {
        (Some(file), None) => {
            let t = load_tunnel_config_from_file(&file)
                .map_err(|e| format!("Failed to load config '{}': {}", file.display(), e))?;
            vec![(t, file.display().to_string())]
        }
        (None, Some(dir)) => {
            let tunnels = load_tunnel_configs_from_dir(&dir)
                .map_err(|e| format!("Failed to load configs from '{}': {}", dir.display(), e))?;
            tunnels
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
        println!("No tunnel configurations found to probe.");
        return Ok(Vec::new());
    }

    const MAX_CONCURRENT_PROBES: usize = 32;
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
        println!("{}", serde_json::to_string_pretty(&results)?);
    } else {
        print_probe_table(&results);
    }

    Ok(results)
}

fn print_probe_table(results: &[ProbeResult]) {
    println!("┌──────────┬──────────────────────┬─────────────┬────────────────┬────────────────────────┐");
    println!("│ STATUS   │ CONFIG               │ RTT         │ EXIT IP        │ ENDPOINT               │");
    println!("├──────────┼──────────────────────┼─────────────┼────────────────┼────────────────────────┤");

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

        let rtt = match r.rtt_ms {
            Some(ms) => format!("{:.1} ms", ms),
            None => "-".to_string(),
        };

        let exit_ip = r.exit_ip.as_deref().unwrap_or("-");

        println!(
            "│ {:<8} │ {:<20} │ {:<11} │ {:<14} │ {:<22} │",
            status,
            truncate_str(&r.id, 20),
            truncate_str(&rtt, 11),
            truncate_str(exit_ip, 14),
            truncate_str(&r.endpoint, 22),
        );
    }

    println!("└──────────┴──────────────────────┴─────────────┴────────────────┴────────────────────────┘");
    println!(
        "Probe completed: {} passed, {} failed (total {}).",
        passed,
        failed,
        results.len()
    );
}

fn truncate_str(s: &str, max_len: usize) -> String {
    if s.len() > max_len {
        format!("{}…", &s[..max_len.saturating_sub(1)])
    } else {
        s.to_string()
    }
}
