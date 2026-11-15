//! Command handlers for the `wpmulti` CLI.

use std::fs;
use std::path::PathBuf;
use std::sync::Arc;

use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::api::AdminServer;
use crate::config::{load_tunnel_configs_from_dir, MainConfig};
use crate::core::TunnelManager;
use crate::tui::{run_terminal_tui, TuiApp, TuiDataSource};

/// Execute the `wpmulti run` command: starts multi-tunnel daemon and optional TUI.
pub async fn cmd_run(
    config_path: Option<PathBuf>,
    dir_path: Option<PathBuf>,
    tui_mode: bool,
) -> Result<(), Box<dyn std::error::Error>> {
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
        load_tunnel_configs_from_dir(&config.global.config_dir)
            .map_err(|e| format!("Failed to load tunnels: {}", e))?
    } else {
        tracing::warn!(
            "Config directory '{}' not found; starting with 0 tunnels",
            config.global.config_dir.display()
        );
        Vec::new()
    };

    let total_tunnels = tunnels.len();
    let manager = Arc::new(
        TunnelManager::new(config.clone(), tunnels)
            .map_err(|e| format!("Failed to initialize TunnelManager: {}", e))?,
    );

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
        let app = TuiApp::new(
            TuiDataSource::InProcess(Arc::clone(&manager)),
            config.tui.default_sort,
        );
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
pub async fn cmd_status(admin_url: String) -> Result<serde_json::Value, Box<dyn std::error::Error>> {
    let url = admin_url.trim_end_matches('/');
    let host_port = url
        .strip_prefix("http://")
        .or_else(|| url.strip_prefix("https://"))
        .unwrap_or(url);

    let mut stream = tokio::net::TcpStream::connect(host_port)
        .await
        .map_err(|e| format!("Failed to connect to Admin API at '{}': {}", url, e))?;

    let req = format!(
        "GET /status HTTP/1.1\r\nHost: {}\r\nConnection: close\r\n\r\n",
        host_port
    );
    stream.write_all(req.as_bytes()).await?;

    let mut buf = Vec::new();
    stream.read_to_end(&mut buf).await?;

    let body_offset = buf
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .map(|p| p + 4)
        .unwrap_or(0);

    let val: serde_json::Value = serde_json::from_slice(&buf[body_offset..])
        .map_err(|e| format!("Failed to parse JSON response: {}", e))?;

    println!("{}", serde_json::to_string_pretty(&val)?);
    Ok(val)
}

/// Execute the `wpmulti top` command: launches the standalone interactive TUI monitor.
pub async fn cmd_top(admin_url: String) -> Result<(), Box<dyn std::error::Error>> {
    let source = TuiDataSource::Remote {
        admin_url,
        auth_token: None,
    };
    let app = TuiApp::new(source, crate::config::TuiSortField::Id);
    run_terminal_tui(app, 500).await?;
    Ok(())
}
