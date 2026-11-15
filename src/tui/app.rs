//! Application state and business logic for the interactive TUI monitor.

use std::collections::VecDeque;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::config::toml_config::{DnsStrategy, LogLevel};
use crate::config::{parse_duration_str, IpMode, LifecycleMode, MainConfig, TuiSortField};
use crate::core::{
    ActiveListenerInfo, ReloadReport, TunnelManager, TunnelState, TunnelSummary,
};
use crate::tui::logs::TuiLogBuffer;

/// Active tab in the nyx-style multi-tab TUI.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TuiTab {
    Tunnels,
    Logs,
    Listeners,
    Config,
    Probe,
}

impl TuiTab {
    /// All tabs in display order.
    pub const ALL: [TuiTab; 5] = [
        TuiTab::Tunnels,
        TuiTab::Logs,
        TuiTab::Listeners,
        TuiTab::Config,
        TuiTab::Probe,
    ];

    /// Short human-readable label for the tab bar.
    pub fn label(self) -> &'static str {
        match self {
            TuiTab::Tunnels => "1:Tunnels",
            TuiTab::Logs => "2:Logs",
            TuiTab::Listeners => "3:Listeners",
            TuiTab::Config => "4:Config",
            TuiTab::Probe => "5:Probe",
        }
    }

    /// Cycle to the next tab.
    pub fn next(self) -> Self {
        match self {
            TuiTab::Tunnels => TuiTab::Logs,
            TuiTab::Logs => TuiTab::Listeners,
            TuiTab::Listeners => TuiTab::Config,
            TuiTab::Config => TuiTab::Probe,
            TuiTab::Probe => TuiTab::Tunnels,
        }
    }

    /// Cycle to the previous tab.
    pub fn prev(self) -> Self {
        match self {
            TuiTab::Tunnels => TuiTab::Probe,
            TuiTab::Logs => TuiTab::Tunnels,
            TuiTab::Listeners => TuiTab::Logs,
            TuiTab::Config => TuiTab::Listeners,
            TuiTab::Probe => TuiTab::Config,
        }
    }
}

/// Result of a live handshake/connectivity probe triggered from the TUI Probe tab.
#[derive(Debug, Clone)]
pub struct TuiProbeResult {
    pub id: String,
    pub endpoint: String,
    pub ok: bool,
    pub rtt_ms: Option<u64>,
    pub message: String,
}

/// Number of editable runtime configuration rows in the Config tab.
pub const CONFIG_ROW_COUNT: usize = 8;

/// Data source powering the TUI dashboard: either an in-process manager or a remote Admin API.
#[derive(Clone)]
pub enum TuiDataSource {
    InProcess(Arc<TunnelManager>),
    Remote {
        admin_url: String,
        auth_token: Option<String>,
    },
}

/// Validate that a string contains no HTTP control characters (`\r`, `\n`, `\0`) or whitespace.
fn validate_http_token_or_segment(val: &str, field: &str) -> Result<(), String> {
    if val.bytes().any(|b| b <= 0x20 || b == 0x7f) {
        return Err(format!("Invalid {} (contains control characters or whitespace)", field));
    }
    Ok(())
}

/// Parse an Admin API URL (`http://host[:port]`) into `host:port`.
fn parse_admin_http_url(admin_url: &str) -> Result<String, String> {
    let url = admin_url.trim().trim_end_matches('/');
    if url.starts_with("https://") {
        return Err("HTTPS is not supported for Admin API; use http://".to_string());
    }
    let authority = url.strip_prefix("http://").unwrap_or(url);
    if authority.is_empty() || authority.contains('/') || authority.bytes().any(|b| b <= 0x20 || b == 0x7f) {
        return Err(format!("Invalid Admin API URL '{}'", admin_url));
    }
    let has_port = if let Some(rest) = authority.strip_prefix('[') {
        rest.contains("]:")
    } else {
        authority.contains(':')
    };
    if has_port {
        Ok(authority.to_string())
    } else {
        Ok(format!("{}:80", authority))
    }
}

/// Execute an HTTP/1.1 request against the Admin API, validating HTTP status and returning body bytes.
pub(crate) async fn admin_http_request(
    admin_url: &str,
    method: &str,
    path: &str,
    auth_token: Option<&str>,
) -> Result<Vec<u8>, String> {
    admin_http_request_with_body(admin_url, method, path, auth_token, None).await
}

pub(crate) async fn admin_http_request_with_body(
    admin_url: &str,
    method: &str,
    path: &str,
    auth_token: Option<&str>,
    body_bytes: Option<&[u8]>,
) -> Result<Vec<u8>, String> {
    let host_port = parse_admin_http_url(admin_url)?;
    validate_http_token_or_segment(path, "request path")?;
    if let Some(tok) = auth_token
        && tok.bytes().any(|b| b == b'\r' || b == b'\n' || b == 0)
    {
        return Err("Invalid auth_token (contains CR/LF/NUL)".to_string());
    }

    let io_timeout = Duration::from_secs(10);
    let mut stream = tokio::time::timeout(io_timeout, tokio::net::TcpStream::connect(&host_port))
        .await
        .map_err(|_| format!("Timed out connecting to Admin API at '{}'", admin_url))?
        .map_err(|e| format!("Failed to connect to Admin API at '{}': {}", admin_url, e))?;

    let mut req = format!(
        "{} {} HTTP/1.1\r\nHost: {}\r\n",
        method, path, host_port
    );
    if let Some(payload) = body_bytes {
        req.push_str(&format!(
            "Content-Type: application/json\r\nContent-Length: {}\r\n",
            payload.len()
        ));
    } else if method == "POST" {
        req.push_str("Content-Length: 0\r\n");
    }
    if let Some(token) = auth_token {
        req.push_str(&format!("Authorization: Bearer {}\r\n", token));
    }
    req.push_str("Connection: close\r\n\r\n");

    let mut wire = req.into_bytes();
    if let Some(payload) = body_bytes {
        wire.extend_from_slice(payload);
    }

    tokio::time::timeout(io_timeout, stream.write_all(&wire))
        .await
        .map_err(|_| "Timed out writing Admin API request".to_string())?
        .map_err(|e| format!("Write failed: {}", e))?;

    let mut resp_buf = Vec::new();
    tokio::time::timeout(io_timeout, stream.read_to_end(&mut resp_buf))
        .await
        .map_err(|_| "Timed out reading Admin API response".to_string())?
        .map_err(|e| format!("Read failed: {}", e))?;

    let header_end = resp_buf
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .ok_or_else(|| "Malformed HTTP response from Admin API".to_string())?;

    let header_str = std::str::from_utf8(&resp_buf[..header_end])
        .map_err(|_| "Non-UTF8 HTTP response headers from Admin API".to_string())?;
    let status_line = header_str.lines().next().unwrap_or("");
    let status_code: u16 = status_line
        .split_whitespace()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .ok_or_else(|| format!("Invalid HTTP status line: '{}'", status_line))?;

    let body = &resp_buf[header_end + 4..];
    if !(200..300).contains(&status_code) {
        if let Ok(json_err) = serde_json::from_slice::<serde_json::Value>(body)
            && let Some(msg) = json_err.get("error").and_then(|v| v.as_str())
        {
            return Err(format!("HTTP {}: {}", status_code, msg));
        }
        return Err(format!("HTTP error {}", status_code));
    }

    Ok(body.to_vec())
}

impl TuiDataSource {
    /// Retrieve list of all tunnels from the data source.
    pub async fn fetch_tunnels(&self) -> Result<Vec<TunnelSummary>, String> {
        match self {
            TuiDataSource::InProcess(mgr) => Ok(mgr.get_tunnel_stats()),
            TuiDataSource::Remote {
                admin_url,
                auth_token,
            } => {
                let body = admin_http_request(admin_url, "GET", "/tunnels", auth_token.as_deref()).await?;
                let tunnels: Vec<TunnelSummary> = serde_json::from_slice(&body)
                    .map_err(|e| format!("Failed to deserialize tunnels response: {}", e))?;
                Ok(tunnels)
            }
        }
    }

    /// Activate a dormant or suspended tunnel.
    pub async fn activate_tunnel(&self, id: &str) -> Result<(), String> {
        match self {
            TuiDataSource::InProcess(mgr) => mgr
                .activate_tunnel(id)
                .await
                .map(|_| ())
                .map_err(|e| e.to_string()),
            TuiDataSource::Remote {
                admin_url,
                auth_token,
            } => {
                validate_http_token_or_segment(id, "tunnel id")?;
                let path = format!("/tunnels/{}/activate", id);
                let _ = admin_http_request(admin_url, "POST", &path, auth_token.as_deref()).await?;
                Ok(())
            }
        }
    }

    /// Suspend an active tunnel.
    pub async fn suspend_tunnel(&self, id: &str) -> Result<(), String> {
        match self {
            TuiDataSource::InProcess(mgr) => mgr
                .suspend_tunnel(id)
                .await
                .map_err(|e| e.to_string()),
            TuiDataSource::Remote {
                admin_url,
                auth_token,
            } => {
                validate_http_token_or_segment(id, "tunnel id")?;
                let path = format!("/tunnels/{}/suspend", id);
                let _ = admin_http_request(admin_url, "POST", &path, auth_token.as_deref()).await?;
                Ok(())
            }
        }
    }

    /// Trigger configuration reload.
    /// Enable or disable one or more tunnels (`A`, `1`, `1-200`, `all`).
    pub async fn set_tunnels_disabled(&self, target: &str, disabled: bool) -> Result<usize, String> {
        match self {
            TuiDataSource::InProcess(mgr) => mgr
                .set_tunnels_disabled(target, disabled)
                .await
                .map(|v| v.len())
                .map_err(|e| format!("{:?}", e)),
            TuiDataSource::Remote {
                admin_url,
                auth_token,
            } => {
                let path = if disabled {
                    "/tunnels/batch/disable"
                } else {
                    "/tunnels/batch/enable"
                };
                let body = serde_json::to_vec(&serde_json::json!({ "target": target }))
                    .map_err(|e| e.to_string())?;
                let resp = admin_http_request_with_body(
                    admin_url,
                    "POST",
                    path,
                    auth_token.as_deref(),
                    Some(&body),
                )
                .await?;
                let val: serde_json::Value =
                    serde_json::from_slice(&resp).map_err(|e| e.to_string())?;
                Ok(val["count"].as_u64().unwrap_or(0) as usize)
            }
        }
    }

    pub async fn reload(&self) -> Result<ReloadReport, String> {
        match self {
            TuiDataSource::InProcess(mgr) => mgr
                .reload()
                .await
                .map_err(|e| e.to_string()),
            TuiDataSource::Remote {
                admin_url,
                auth_token,
            } => {
                let body = admin_http_request(admin_url, "POST", "/reload", auth_token.as_deref()).await?;

                #[derive(serde::Deserialize)]
                struct ReloadResp {
                    report: Option<ReloadReport>,
                }
                let parsed: ReloadResp = serde_json::from_slice(&body)
                    .map_err(|e| format!("Failed to parse reload response: {}", e))?;
                Ok(parsed.report.unwrap_or_default())
            }
        }
    }

    /// Fetch daemon log lines (in-process buffer or `GET /logs`).
    pub async fn fetch_logs(&self) -> Result<Vec<String>, String> {
        match self {
            TuiDataSource::InProcess(mgr) => Ok(mgr.log_buffer().snapshot()),
            TuiDataSource::Remote {
                admin_url,
                auth_token,
            } => {
                let body =
                    admin_http_request(admin_url, "GET", "/logs", auth_token.as_deref()).await?;
                serde_json::from_slice::<Vec<String>>(&body)
                    .map_err(|e| format!("Invalid /logs JSON: {}", e))
            }
        }
    }

    /// Retrieve active listeners from the data source.
    pub async fn fetch_listeners(&self) -> Result<Vec<ActiveListenerInfo>, String> {
        match self {
            TuiDataSource::InProcess(mgr) => Ok(mgr.listeners().list_listeners()),
            TuiDataSource::Remote {
                admin_url,
                auth_token,
            } => {
                let body =
                    admin_http_request(admin_url, "GET", "/listeners", auth_token.as_deref()).await?;
                serde_json::from_slice(&body)
                    .map_err(|e| format!("Failed to deserialize listeners response: {}", e))
            }
        }
    }

    /// Retrieve current configuration snapshot from the data source.
    pub async fn fetch_config(&self) -> Result<MainConfig, String> {
        match self {
            TuiDataSource::InProcess(mgr) => Ok(mgr.config_snapshot()),
            TuiDataSource::Remote {
                admin_url,
                auth_token,
            } => {
                let body =
                    admin_http_request(admin_url, "GET", "/config", auth_token.as_deref()).await?;
                serde_json::from_slice(&body)
                    .map_err(|e| format!("Failed to deserialize config response: {}", e))
            }
        }
    }

    /// Apply updated runtime configuration to the data source.
    pub async fn apply_config(&self, cfg: &MainConfig) -> Result<(), String> {
        match self {
            TuiDataSource::InProcess(mgr) => mgr
                .update_runtime_config(cfg.clone())
                .map_err(|e| e.to_string()),
            TuiDataSource::Remote {
                admin_url,
                auth_token,
            } => {
                let json_bytes =
                    serde_json::to_vec(cfg).map_err(|e| format!("Serialize error: {}", e))?;
                let _ = admin_http_request_with_body(
                    admin_url,
                    "POST",
                    "/config",
                    auth_token.as_deref(),
                    Some(&json_bytes),
                )
                .await?;
                Ok(())
            }
        }
    }

    /// Probe a single tunnel by activating it (and performing a handshake check when in-process).
    pub async fn probe_tunnel(&self, id: &str, endpoint: &str) -> TuiProbeResult {
        let start = Instant::now();
        match self {
            TuiDataSource::InProcess(mgr) => match mgr.activate_tunnel(id).await {
                Ok(active) => {
                    let probe_timeout = mgr.config_snapshot().health_check.probe_timeout;
                    let peer_pubkey = mgr
                        .registry()
                        .get(id)
                        .and_then(|entry| entry.config.read().peers.first().map(|p| p.public_key));
                    match peer_pubkey {
                        Some(pubkey) => {
                            match tokio::time::timeout(
                                probe_timeout,
                                active.device.force_handshake(&pubkey),
                            )
                            .await
                            {
                                Ok(Ok(())) => TuiProbeResult {
                                    id: id.to_string(),
                                    endpoint: endpoint.to_string(),
                                    ok: true,
                                    rtt_ms: Some(start.elapsed().as_millis() as u64),
                                    message: "Handshake OK".to_string(),
                                },
                                Ok(Err(e)) => TuiProbeResult {
                                    id: id.to_string(),
                                    endpoint: endpoint.to_string(),
                                    ok: false,
                                    rtt_ms: None,
                                    message: e.to_string(),
                                },
                                Err(_) => TuiProbeResult {
                                    id: id.to_string(),
                                    endpoint: endpoint.to_string(),
                                    ok: false,
                                    rtt_ms: None,
                                    message: "Handshake timed out".to_string(),
                                },
                            }
                        }
                        None => TuiProbeResult {
                            id: id.to_string(),
                            endpoint: endpoint.to_string(),
                            ok: false,
                            rtt_ms: None,
                            message: "No peer public key configured".to_string(),
                        },
                    }
                }
                Err(e) => TuiProbeResult {
                    id: id.to_string(),
                    endpoint: endpoint.to_string(),
                    ok: false,
                    rtt_ms: None,
                    message: e.to_string(),
                },
            },
            TuiDataSource::Remote { .. } => match self.activate_tunnel(id).await {
                Ok(()) => TuiProbeResult {
                    id: id.to_string(),
                    endpoint: endpoint.to_string(),
                    ok: true,
                    rtt_ms: Some(start.elapsed().as_millis() as u64),
                    message: "Activated OK".to_string(),
                },
                Err(e) => TuiProbeResult {
                    id: id.to_string(),
                    endpoint: endpoint.to_string(),
                    ok: false,
                    rtt_ms: None,
                    message: e,
                },
            },
        }
    }
}

/// Central state model for the TUI monitor dashboard.
pub struct TuiApp {
    pub data_source: TuiDataSource,
    pub active_tab: TuiTab,
    pub tunnels: Vec<TunnelSummary>,
    pub filtered_indices: Vec<usize>,
    pub selected_index: usize,
    pub scroll_offset: usize,
    pub search_query: String,
    pub is_searching: bool,
    pub sort_field: TuiSortField,
    pub sort_ascending: bool,
    pub status_message: Option<(String, Instant)>,
    pub running: bool,
    // Bandwidth sparkline state (bytes/sec samples)
    pub rx_rates: VecDeque<u64>,
    pub tx_rates: VecDeque<u64>,
    pub current_rx_bps: u64,
    pub current_tx_bps: u64,
    pub prev_total_rx: Option<u64>,
    pub prev_total_tx: Option<u64>,
    pub last_sample_at: Option<Instant>,
    // Live Logs tab state
    pub log_buffer: Option<TuiLogBuffer>,
    pub remote_logs: Vec<String>,
    pub log_scroll: usize,
    pub log_level_filter: Option<String>,
    // Listeners tab state
    pub listeners: Vec<ActiveListenerInfo>,
    pub listener_scroll: usize,
    // Config tab state
    pub config_snapshot: Option<MainConfig>,
    pub config_path: Option<PathBuf>,
    pub config_selected: usize,
    pub config_editing: Option<String>,
    // Probe tab state
    pub probe_results: Vec<TuiProbeResult>,
    pub probe_scroll: usize,
    // Animation tick counter (incremented every 100ms UI frame)
    pub anim_tick: u64,
    // Inline batch enable/disable prompt buffer (`-1-200`, `+1-200`, `A`, `all`)
    pub batch_prompt: Option<String>,
}

impl TuiApp {
    /// Construct a new [`TuiApp`] with the given data source and initial sort field.
    pub fn new(data_source: TuiDataSource, sort_field: TuiSortField) -> Self {
        Self {
            data_source,
            active_tab: TuiTab::Tunnels,
            tunnels: Vec::new(),
            filtered_indices: Vec::new(),
            selected_index: 0,
            scroll_offset: 0,
            search_query: String::new(),
            is_searching: false,
            sort_field,
            sort_ascending: true,
            status_message: None,
            running: true,
            rx_rates: VecDeque::with_capacity(64),
            tx_rates: VecDeque::with_capacity(64),
            current_rx_bps: 0,
            current_tx_bps: 0,
            prev_total_rx: None,
            prev_total_tx: None,
            last_sample_at: None,
            log_buffer: None,
            remote_logs: Vec::new(),
            log_scroll: 0,
            log_level_filter: None,
            listeners: Vec::new(),
            listener_scroll: 0,
            config_snapshot: None,
            config_path: None,
            config_selected: 0,
            config_editing: None,
            probe_results: Vec::new(),
            probe_scroll: 0,
            anim_tick: 0,
            batch_prompt: None,
        }
    }

    /// Attach an in-memory log buffer for the Live Logs tab.
    pub fn with_log_buffer(mut self, buffer: TuiLogBuffer) -> Self {
        self.log_buffer = Some(buffer);
        self
    }

    /// Attach the path to `wpmulti.toml` so the Config tab can save changes back to disk.
    pub fn with_config_path(mut self, path: PathBuf) -> Self {
        self.config_path = Some(path);
        self
    }

    /// Switch active tab and cancel any active inline edit/search mode.
    pub fn set_tab(&mut self, tab: TuiTab) {
        self.active_tab = tab;
        self.is_searching = false;
        self.config_editing = None;
    }

    /// Cycle to the next TUI tab.
    pub fn next_tab(&mut self) {
        self.set_tab(self.active_tab.next());
    }

    /// Cycle to the previous TUI tab.
    pub fn prev_tab(&mut self) {
        self.set_tab(self.active_tab.prev());
    }

    /// Cycle the log level filter (`None` -> `ERROR` -> `WARN` -> `INFO` -> `DEBUG`).
    pub fn cycle_log_filter(&mut self) {
        self.log_level_filter = match self.log_level_filter.as_deref() {
            None => Some("ERROR".to_string()),
            Some("ERROR") => Some("WARN".to_string()),
            Some("WARN") => Some("INFO".to_string()),
            Some("INFO") => Some("DEBUG".to_string()),
            _ => None,
        };
        self.log_scroll = 0;
    }

    /// Return filtered log lines from `log_buffer` or `remote_logs` (oldest to newest).
    pub fn filtered_logs(&self) -> Vec<String> {
        let all = match &self.log_buffer {
            Some(buf) => buf.snapshot(),
            None => self.remote_logs.clone(),
        };
        match &self.log_level_filter {
            None => all,
            Some(lvl) => all.into_iter().filter(|l| l.contains(lvl)).collect(),
        }
    }

    /// Total number of configuration rows displayed in the Config tab.
    pub const CONFIG_ROW_COUNT: usize = 15;

    /// Return `(label, current_value, is_cycle_toggle)` for a Config tab row.
    pub fn config_row_display(cfg: &MainConfig, idx: usize) -> (&'static str, String, bool) {
        match idx {
            0 => ("global.log_level", format!("{:?}", cfg.global.log_level).to_lowercase(), true),
            1 => ("global.ip_mode", format!("{:?}", cfg.global.ip_mode).to_lowercase(), true),
            2 => ("global.dns_strategy", format!("{:?}", cfg.global.dns_strategy).to_lowercase(), true),
            3 => ("global.dns_preference", format!("{:?}", cfg.global.dns_preference).to_lowercase(), true),
            4 => ("global.dns_fallback", cfg.global.dns_fallback.to_string(), false),
            5 => ("global.max_active_tunnels", cfg.global.max_active_tunnels.to_string(), false),
            6 => ("lifecycle.mode", format!("{:?}", cfg.lifecycle.mode).to_lowercase(), true),
            7 => ("lifecycle.idle_timeout", format!("{}s", cfg.lifecycle.idle_timeout.as_secs()), false),
            8 => ("lifecycle.handshake_timeout", format!("{}s", cfg.lifecycle.handshake_timeout.as_secs()), false),
            9 => ("health_check.probe_interval", format!("{}s", cfg.health_check.probe_interval.as_secs()), false),
            10 => ("health_check.probe_timeout", format!("{}s", cfg.health_check.probe_timeout.as_secs()), false),
            11 => ("health_check.threshold", cfg.health_check.threshold.to_string(), false),
            12 => ("health_check.cooldown", format!("{}s", cfg.health_check.cooldown.as_secs()), false),
            13 => ("per_tunnel.enabled", cfg.per_tunnel.enabled.to_string(), true),
            _ => ("tui.refresh_rate_ms", cfg.tui.refresh_rate_ms.to_string(), false),
        }
    }

    /// Either cycle a toggle/enum config field immediately or start inline text editing.
    pub async fn activate_config_row(&mut self) -> Result<(), String> {
        let Some(mut cfg) = self.config_snapshot.clone() else {
            self.config_snapshot = self.data_source.fetch_config().await.ok();
            return Ok(());
        };
        let idx = self.config_selected;
        match idx {
            0 => {
                cfg.global.log_level = match cfg.global.log_level {
                    LogLevel::Trace => LogLevel::Debug,
                    LogLevel::Debug => LogLevel::Info,
                    LogLevel::Info => LogLevel::Warn,
                    LogLevel::Warn => LogLevel::Error,
                    LogLevel::Error => LogLevel::Trace,
                };
            }
            1 => {
                cfg.global.ip_mode = match cfg.global.ip_mode {
                    IpMode::DualStack => IpMode::Ipv4Only,
                    IpMode::Ipv4Only => IpMode::Ipv6Only,
                    IpMode::Ipv6Only => IpMode::DualStack,
                };
            }
            2 => {
                cfg.global.dns_strategy = match cfg.global.dns_strategy {
                    DnsStrategy::TunnelOnly => DnsStrategy::TunnelFirst,
                    DnsStrategy::TunnelFirst => DnsStrategy::Host,
                    DnsStrategy::Host => DnsStrategy::TunnelOnly,
                };
            }
            3 => {
                cfg.global.dns_preference = match cfg.global.dns_preference {
                    crate::config::toml_config::DnsPreference::Ipv4First => {
                        crate::config::toml_config::DnsPreference::Ipv6First
                    }
                    crate::config::toml_config::DnsPreference::Ipv6First => {
                        crate::config::toml_config::DnsPreference::Ipv4First
                    }
                };
            }
            6 => {
                cfg.lifecycle.mode = match cfg.lifecycle.mode {
                    LifecycleMode::Lazy => LifecycleMode::Eager,
                    LifecycleMode::Eager => LifecycleMode::Lazy,
                };
            }
            13 => {
                cfg.per_tunnel.enabled = !cfg.per_tunnel.enabled;
            }
            _ => {
                let (_, val, _) = Self::config_row_display(&cfg, idx);
                self.config_editing = Some(val);
                return Ok(());
            }
        }
        self.data_source.apply_config(&cfg).await?;
        self.config_snapshot = Some(cfg);
        self.set_status("Updated runtime configuration");
        Ok(())
    }

    /// Commit inline edited text for the selected Config tab field.
    pub async fn commit_config_edit(&mut self) -> Result<(), String> {
        let Some(raw) = self.config_editing.take() else {
            return Ok(());
        };
        let Some(mut cfg) = self.config_snapshot.clone() else {
            return Err("Config snapshot not loaded".to_string());
        };
        let trimmed = raw.trim();
        match self.config_selected {
            4 => {
                let addr: std::net::SocketAddr = trimmed
                    .parse()
                    .map_err(|_| format!("Invalid socket address '{}'", trimmed))?;
                cfg.global.dns_fallback = addr;
            }
            5 => {
                let n: usize = trimmed
                    .parse()
                    .map_err(|_| format!("Invalid integer '{}'", trimmed))?;
                cfg.global.max_active_tunnels = n;
            }
            7 => {
                cfg.lifecycle.idle_timeout = parse_duration_str(trimmed)?;
            }
            8 => {
                cfg.lifecycle.handshake_timeout = parse_duration_str(trimmed)?;
            }
            9 => {
                cfg.health_check.probe_interval = parse_duration_str(trimmed)?;
            }
            10 => {
                cfg.health_check.probe_timeout = parse_duration_str(trimmed)?;
            }
            11 => {
                let n: usize = trimmed
                    .parse()
                    .map_err(|_| format!("Invalid integer '{}'", trimmed))?;
                cfg.health_check.threshold = n;
            }
            12 => {
                cfg.health_check.cooldown = parse_duration_str(trimmed)?;
            }
            14 => {
                let ms: u64 = trimmed
                    .parse()
                    .map_err(|_| format!("Invalid integer '{}'", trimmed))?;
                cfg.tui.refresh_rate_ms = ms;
            }
            _ => {}
        }
        self.data_source.apply_config(&cfg).await?;
        self.config_snapshot = Some(cfg);
        self.set_status("Applied runtime config change");
        Ok(())
    }

    /// Persist `config_snapshot` to `config_path` (if set) and trigger `reload()`.
    pub async fn save_config_and_reload(&mut self) -> Result<(), String> {
        if let (Some(cfg), Some(path)) = (&self.config_snapshot, &self.config_path) {
            let serialized = toml::to_string_pretty(cfg)
                .map_err(|e| format!("Failed to serialize TOML: {}", e))?;
            std::fs::write(path, serialized)
                .map_err(|e| format!("Failed to write '{}': {}", path.display(), e))?;
        }
        let rep = self.data_source.reload().await?;
        self.set_status(format!(
            "Saved & reloaded: +{} -{} ~{} ({} total)",
            rep.added, rep.removed, rep.updated, rep.total
        ));
        Ok(())
    }

    /// Probe the currently selected tunnel (or first tunnel) and record the result.
    pub async fn probe_selected_tunnel(&mut self) {
        let target = self
            .selected_tunnel()
            .or_else(|| self.tunnels.first())
            .map(|t| (t.id.clone(), t.endpoint.clone().unwrap_or_else(|| "-".into())));
        let Some((id, endpoint)) = target else {
            self.set_status("No tunnels available to probe");
            return;
        };
        let res = self.data_source.probe_tunnel(&id, &endpoint).await;
        self.set_status(format!("Probe {}: {}", res.id, res.message));
        if let Some(pos) = self.probe_results.iter().position(|r| r.id == res.id) {
            self.probe_results[pos] = res;
        } else {
            self.probe_results.push(res);
        }
    }

    /// Probe up to 16 tunnels sequentially/concurrently and update `probe_results`.
    pub async fn probe_all_tunnels(&mut self) {
        let targets: Vec<(String, String)> = self
            .tunnels
            .iter()
            .take(16)
            .map(|t| (t.id.clone(), t.endpoint.clone().unwrap_or_else(|| "-".into())))
            .collect();
        if targets.is_empty() {
            self.set_status("No tunnels available to probe");
            return;
        }
        let mut results = Vec::with_capacity(targets.len());
        for (id, endpoint) in targets {
            results.push(self.data_source.probe_tunnel(&id, &endpoint).await);
        }
        let ok_count = results.iter().filter(|r| r.ok).count();
        let total = results.len();
        self.probe_results = results;
        self.probe_scroll = 0;
        self.set_status(format!("Probed {} tunnels: {} OK", total, ok_count));
    }

    /// Update tunnel dataset and refresh filtered/sorted view.
    /// Return the top `limit` busiest tunnels sorted by total `rx_bytes + tx_bytes`.
    pub fn top_tunnels(&self, limit: usize) -> Vec<(&str, u64)> {
        let mut items: Vec<(&str, u64)> = self
            .tunnels
            .iter()
            .map(|t| (t.id.as_str(), t.rx_bytes.saturating_add(t.tx_bytes)))
            .collect();
        items.sort_by_key(|b| std::cmp::Reverse(b.1));
        items.truncate(limit);
        items
    }

    pub fn set_tunnels(&mut self, tunnels: Vec<TunnelSummary>) {
        let prev_selected_id = self.selected_tunnel().map(|t| t.id.clone());
        self.tunnels = tunnels;
        self.apply_filter_and_sort();

        // Restore selection by ID if possible
        if let Some(id) = prev_selected_id
            && let Some(pos) = self
                .filtered_indices
                .iter()
                .position(|&idx| self.tunnels[idx].id == id)
            {
                self.selected_index = pos;
            }
    }

    /// Re-filter and sort active indices based on search query and sort criteria.
    pub fn apply_filter_and_sort(&mut self) {
        let q = self.search_query.trim().to_lowercase();
        let mut indices: Vec<usize> = self
            .tunnels
            .iter()
            .enumerate()
            .filter(|(_, t)| {
                if q.is_empty() {
                    true
                } else {
                    t.id.to_lowercase().contains(&q)
                        || t.endpoint
                            .as_deref()
                            .unwrap_or("")
                            .to_lowercase()
                            .contains(&q)
                }
            })
            .map(|(i, _)| i)
            .collect();

        // Sort indices
        let tunnels = &self.tunnels;
        let field = self.sort_field;
        let ascending = self.sort_ascending;

        indices.sort_by(|&a, &b| {
            let ta = &tunnels[a];
            let tb = &tunnels[b];
            let ord = match field {
                TuiSortField::Id => ta.id.cmp(&tb.id),
                TuiSortField::Status => {
                    let rank = |s: &TunnelState| match s {
                        TunnelState::Active => 0,
                        TunnelState::Activating => 1,
                        TunnelState::Suspended => 2,
                        TunnelState::Dormant => 3,
                    };
                    rank(&ta.state).cmp(&rank(&tb.state))
                }
                TuiSortField::Conns => ta.active_conns.cmp(&tb.active_conns),
                TuiSortField::Rx => ta.rx_bytes.cmp(&tb.rx_bytes),
                TuiSortField::Tx => ta.tx_bytes.cmp(&tb.tx_bytes),
            };

            if ascending {
                ord
            } else {
                ord.reverse()
            }
        });

        self.filtered_indices = indices;
        if self.filtered_indices.is_empty() {
            self.selected_index = 0;
            self.scroll_offset = 0;
        } else if self.selected_index >= self.filtered_indices.len() {
            self.selected_index = self.filtered_indices.len() - 1;
        }
    }

    /// Move selection down by 1.
    pub fn select_next(&mut self) {
        if !self.filtered_indices.is_empty() && self.selected_index + 1 < self.filtered_indices.len() {
            self.selected_index += 1;
        }
    }

    /// Move selection up by 1.
    pub fn select_prev(&mut self) {
        if self.selected_index > 0 {
            self.selected_index -= 1;
        }
    }

    /// Page down by specified row count.
    pub fn page_down(&mut self, page_size: usize) {
        if !self.filtered_indices.is_empty() {
            self.selected_index = (self.selected_index + page_size).min(self.filtered_indices.len() - 1);
        }
    }

    /// Page up by specified row count.
    pub fn page_up(&mut self, page_size: usize) {
        self.selected_index = self.selected_index.saturating_sub(page_size);
    }

    /// Jump directly to top of tunnel list.
    pub fn scroll_to_top(&mut self) {
        self.selected_index = 0;
    }

    /// Jump directly to bottom of tunnel list.
    pub fn scroll_to_bottom(&mut self) {
        if !self.filtered_indices.is_empty() {
            self.selected_index = self.filtered_indices.len() - 1;
        }
    }

    /// Cycle sort field through Id -> Status -> Conns -> Rx -> Tx -> Id.
    pub fn cycle_sort(&mut self) {
        self.sort_field = match self.sort_field {
            TuiSortField::Id => TuiSortField::Status,
            TuiSortField::Status => TuiSortField::Conns,
            TuiSortField::Conns => TuiSortField::Rx,
            TuiSortField::Rx => TuiSortField::Tx,
            TuiSortField::Tx => TuiSortField::Id,
        };
        self.apply_filter_and_sort();
    }

    /// Invert current sorting direction.
    pub fn toggle_sort_direction(&mut self) {
        self.sort_ascending = !self.sort_ascending;
        self.apply_filter_and_sort();
    }

    /// Currently selected tunnel summary snapshot.
    pub fn selected_tunnel(&self) -> Option<&TunnelSummary> {
        self.filtered_indices
            .get(self.selected_index)
            .and_then(|&idx| self.tunnels.get(idx))
    }

    /// Set ephemeral status banner message.
    pub fn set_status(&mut self, msg: impl Into<String>) {
        self.status_message = Some((msg.into(), Instant::now()));
    }

    /// Clear status message if it has been displayed longer than `max_age`.
    pub fn clear_status_if_expired(&mut self, max_age: Duration) {
        if let Some((_, ts)) = &self.status_message
            && ts.elapsed() > max_age {
                self.status_message = None;
            }
    }

    /// Fetch latest tunnel states (and active tab data + bandwidth samples) from data source.
    pub async fn refresh(&mut self) -> Result<(), String> {
        let list = self.data_source.fetch_tunnels().await?;
        let total_rx: u64 = list.iter().map(|t| t.rx_bytes).sum();
        let total_tx: u64 = list.iter().map(|t| t.tx_bytes).sum();
        let now = Instant::now();
        if let (Some(prev_rx), Some(prev_tx), Some(prev_at)) =
            (self.prev_total_rx, self.prev_total_tx, self.last_sample_at)
        {
            let elapsed = now.duration_since(prev_at).as_secs_f64().max(0.05);
            let rx_bps = (total_rx.saturating_sub(prev_rx) as f64 / elapsed) as u64;
            let tx_bps = (total_tx.saturating_sub(prev_tx) as f64 / elapsed) as u64;
            self.current_rx_bps = rx_bps;
            self.current_tx_bps = tx_bps;
            if self.rx_rates.len() >= 40 {
                self.rx_rates.pop_front();
            }
            if self.tx_rates.len() >= 40 {
                self.tx_rates.pop_front();
            }
            self.rx_rates.push_back(rx_bps);
            self.tx_rates.push_back(tx_bps);
        }
        self.prev_total_rx = Some(total_rx);
        self.prev_total_tx = Some(total_tx);
        self.last_sample_at = Some(now);
        self.set_tunnels(list);

        if self.active_tab == TuiTab::Logs
            && self.log_buffer.is_none()
            && let Ok(logs) = self.data_source.fetch_logs().await
        {
            self.remote_logs = logs;
        }
        if self.active_tab == TuiTab::Listeners
            && let Ok(listeners) = self.data_source.fetch_listeners().await
        {
            self.listeners = listeners;
        }
        if self.active_tab == TuiTab::Config
            && self.config_snapshot.is_none()
            && let Ok(cfg) = self.data_source.fetch_config().await
        {
            self.config_snapshot = Some(cfg);
        }
        Ok(())
    }

    /// Activate currently selected tunnel.
    pub async fn activate_selected(&mut self) -> Result<(), String> {
        if let Some(t) = self.selected_tunnel() {
            let id = t.id.clone();
            self.data_source.activate_tunnel(&id).await?;
            self.set_status(format!("Activated tunnel '{}'", id));
            self.refresh().await?;
            Ok(())
        } else {
            Err("No tunnel selected".to_string())
        }
    }

    /// Suspend currently selected tunnel.
    pub async fn suspend_selected(&mut self) -> Result<(), String> {
        if let Some(t) = self.selected_tunnel() {
            let id = t.id.clone();
            self.data_source.suspend_tunnel(&id).await?;
            self.set_status(format!("Suspended tunnel '{}'", id));
            self.refresh().await?;
            Ok(())
        } else {
            Err("No tunnel selected".to_string())
        }
    }

    /// Trigger hot-reload of configurations.
    /// Toggle enable/disable on the currently selected tunnel.
    pub async fn toggle_selected_disabled(&mut self) -> Result<(), String> {
        let Some(t) = self.selected_tunnel().cloned() else {
            return Ok(());
        };
        let next_disabled = !t.disabled;
        self.data_source
            .set_tunnels_disabled(&t.id, next_disabled)
            .await?;
        let action = if next_disabled { "Disabled" } else { "Enabled" };
        self.set_status(format!("{} '{}'", action, t.id));
        let _ = self.refresh().await;
        Ok(())
    }

    /// Commit inline batch enable/disable prompt (`+target` enables, `-target` or plain `target` disables).
    pub async fn commit_batch_toggle(&mut self) -> Result<(), String> {
        let Some(raw) = self.batch_prompt.take() else {
            return Ok(());
        };
        let trimmed = raw.trim();
        if trimmed.is_empty() {
            return Ok(());
        }
        let (disabled, target) = if let Some(rest) = trimmed.strip_prefix('+') {
            (false, rest.trim())
        } else if let Some(rest) = trimmed.strip_prefix('-') {
            (true, rest.trim())
        } else {
            (true, trimmed)
        };
        let count = self
            .data_source
            .set_tunnels_disabled(target, disabled)
            .await?;
        let action = if disabled { "Disabled" } else { "Enabled" };
        self.set_status(format!("{} {} tunnel(s) ({})", action, count, target));
        let _ = self.refresh().await;
        Ok(())
    }

    pub async fn trigger_reload(&mut self) -> Result<ReloadReport, String> {
        let rep = self.data_source.reload().await?;
        self.set_status(format!(
            "Reloaded: {} added, {} removed, {} updated, {} total",
            rep.added, rep.removed, rep.updated, rep.total
        ));
        self.refresh().await?;
        Ok(rep)
    }

    /// Adjust viewport scroll offset so selected row is guaranteed visible.
    pub fn update_scroll(&mut self, viewport_height: usize) {
        if viewport_height == 0 || self.filtered_indices.is_empty() {
            self.scroll_offset = 0;
            return;
        }

        if self.selected_index < self.scroll_offset {
            self.scroll_offset = self.selected_index;
        } else if self.selected_index >= self.scroll_offset + viewport_height {
            self.scroll_offset = self.selected_index + 1 - viewport_height;
        }
    }
}
