//! Application state and business logic for the interactive TUI monitor.

use std::collections::VecDeque;
use std::path::PathBuf;
use std::time::{Duration, Instant};

use tokio::io::{AsyncReadExt, AsyncWriteExt};

use serde::Deserialize;

use crate::config::{MainConfig, TuiSortField};
use crate::core::{ActiveListenerInfo, ReloadReport, TunnelState, TunnelSummary};
use crate::tui::config_editor::{
    ConfigApplyScope, ConfigDiffSummary, ConfigField, ConfigSaveReport, diff_config_scopes,
    format_save_status,
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

/// Overlay on top of the active tab. The overlays are mutually
/// exclusive and own the keyboard while open, so a single enum — not
/// one bool per overlay — keeps the state unambiguous.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum TuiOverlay {
    /// No overlay: the active tab owns the screen and the keyboard.
    #[default]
    None,
    /// Help overlay, toggled by `?` on any tab.
    Help,
    /// Tunnel detail overlay, opened by `Enter` on the Tunnels tab.
    TunnelDetail,
}

impl TuiTab {
    /// All tabs in display order.
    pub const ALL: [Self; 5] = [
        Self::Tunnels,
        Self::Logs,
        Self::Listeners,
        Self::Config,
        Self::Probe,
    ];

    /// Short human-readable label for the tab bar.
    pub const fn label(self) -> &'static str {
        match self {
            Self::Tunnels => "1:Tunnels",
            Self::Logs => "2:Logs",
            Self::Listeners => "3:Listeners",
            Self::Config => "4:Config",
            Self::Probe => "5:Probe",
        }
    }

    /// Cycle to the next tab.
    pub const fn next(self) -> Self {
        match self {
            Self::Tunnels => Self::Logs,
            Self::Logs => Self::Listeners,
            Self::Listeners => Self::Config,
            Self::Config => Self::Probe,
            Self::Probe => Self::Tunnels,
        }
    }

    /// Cycle to the previous tab.
    pub const fn prev(self) -> Self {
        match self {
            Self::Tunnels => Self::Probe,
            Self::Logs => Self::Tunnels,
            Self::Listeners => Self::Logs,
            Self::Config => Self::Listeners,
            Self::Probe => Self::Config,
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

/// Response body of `POST /tunnels/{id}/probe` on the Admin API.
#[derive(Debug, Deserialize)]
struct AdminProbeResponse {
    ok: bool,
    rtt_ms: Option<u64>,
    message: String,
}

/// Number of editable runtime configuration rows in the Config tab.
pub const CONFIG_ROW_COUNT: usize = ConfigField::ALL.len();

/// Data source powering the TUI dashboard: the Admin API of a running
/// daemon. `top` is the only TUI now and always talks to the daemon over
/// HTTP, never in-process — so this is a plain struct, not an enum.
#[derive(Clone)]
pub struct TuiDataSource {
    pub admin_url: String,
    pub auth_token: Option<String>,
}

impl std::fmt::Debug for TuiDataSource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TuiDataSource")
            .field("admin_url", &self.admin_url)
            .field(
                "auth_token",
                &self.auth_token.as_ref().map(|_| "[REDACTED]"),
            )
            .finish()
    }
}

/// Validate that a URL path segment contains no HTTP control characters, whitespace, or delimiters.
fn validate_http_token_or_segment(val: &str, field: &str) -> Result<(), String> {
    if val.is_empty()
        || val == "."
        || val == ".."
        || val
            .bytes()
            .any(|b| b <= 0x20 || b == 0x7f || matches!(b, b'/' | b'\\' | b'?' | b'#'))
    {
        return Err(format!(
            "Invalid {field} (contains control characters, whitespace, or path delimiters)"
        ));
    }
    Ok(())
}

/// Validate an HTTP request target path (must begin with `/`, contain no whitespace/controls/traversal).
fn validate_http_request_path(path: &str) -> Result<(), String> {
    if !path.starts_with('/')
        || path.contains("..")
        || path
            .bytes()
            .any(|b| b <= 0x20 || b == 0x7f || matches!(b, b'\\' | b'?' | b'#'))
    {
        return Err("Invalid request path".to_string());
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
    if authority.is_empty()
        || authority.contains('/')
        || authority.bytes().any(|b| b <= 0x20 || b == 0x7f)
    {
        return Err(format!("Invalid Admin API URL '{admin_url}'"));
    }
    let has_port = authority
        .strip_prefix('[')
        .map_or_else(|| authority.contains(':'), |rest| rest.contains("]:"));
    if has_port {
        Ok(authority.to_string())
    } else {
        Ok(format!("{authority}:80"))
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
    const MAX_ADMIN_RESP_BYTES: u64 = 8 * 1024 * 1024;
    let host_port = parse_admin_http_url(admin_url)?;
    validate_http_request_path(path)?;
    if let Some(tok) = auth_token
        && tok.bytes().any(|b| b == b'\r' || b == b'\n' || b == 0)
    {
        return Err("Invalid auth_token (contains CR/LF/NUL)".to_string());
    }

    let io_timeout = Duration::from_secs(10);
    let mut stream = tokio::time::timeout(io_timeout, tokio::net::TcpStream::connect(&host_port))
        .await
        .map_err(|_| format!("Timed out connecting to Admin API at '{admin_url}'"))?
        .map_err(|e| format!("Failed to connect to Admin API at '{admin_url}': {e}"))?;

    let mut req = format!("{method} {path} HTTP/1.0\r\nHost: {host_port}\r\n");
    if let Some(payload) = body_bytes {
        let _ = std::fmt::Write::write_fmt(
            &mut req,
            format_args!(
                "Content-Type: application/json\r\nContent-Length: {}\r\n",
                payload.len()
            ),
        );
    } else if method == "POST" {
        req.push_str("Content-Length: 0\r\n");
    } else {
        // No body and not POST: no Content-Length header.
    }
    if let Some(token) = auth_token {
        let _ =
            std::fmt::Write::write_fmt(&mut req, format_args!("Authorization: Bearer {token}\r\n"));
    }
    req.push_str("Connection: close\r\n\r\n");

    let mut wire = req.into_bytes();
    if let Some(payload) = body_bytes {
        wire.extend_from_slice(payload);
    }

    tokio::time::timeout(io_timeout, stream.write_all(&wire))
        .await
        .map_err(|_| "Timed out writing Admin API request".to_string())?
        .map_err(|e| format!("Write failed: {e}"))?;

    let mut resp_buf = Vec::new();
    tokio::time::timeout(
        io_timeout,
        AsyncReadExt::take(stream, MAX_ADMIN_RESP_BYTES + 1).read_to_end(&mut resp_buf),
    )
    .await
    .map_err(|_| "Timed out reading Admin API response".to_string())?
    .map_err(|e| format!("Read failed: {e}"))?;
    if resp_buf.len() as u64 > MAX_ADMIN_RESP_BYTES {
        return Err("Admin API response exceeded 8 MiB size limit".to_string());
    }

    let header_end = resp_buf
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .ok_or_else(|| "Malformed HTTP response from Admin API".to_string())?;

    let header_bytes = resp_buf
        .get(..header_end)
        .ok_or_else(|| "Malformed HTTP response from Admin API".to_string())?;
    let header_str = std::str::from_utf8(header_bytes)
        .map_err(|_| "Non-UTF8 HTTP response headers from Admin API".to_string())?;
    let status_line = header_str.lines().next().unwrap_or("");
    let status_code: u16 = status_line
        .split_whitespace()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .ok_or_else(|| format!("Invalid HTTP status line: '{status_line}'"))?;

    let body = resp_buf.get(header_end + 4..).unwrap_or_default();
    if !(200..300).contains(&status_code) {
        if let Ok(json_err) = serde_json::from_slice::<serde_json::Value>(body)
            && let Some(msg) = json_err.get("error").and_then(|v| v.as_str())
        {
            return Err(format!("HTTP {status_code}: {msg}"));
        }
        return Err(format!("HTTP error {status_code}"));
    }

    Ok(body.to_vec())
}

impl TuiDataSource {
    /// Retrieve list of all tunnels from the data source.
    pub async fn fetch_tunnels(&self) -> Result<Vec<TunnelSummary>, String> {
        let body = admin_http_request(
            &self.admin_url,
            "GET",
            "/tunnels",
            self.auth_token.as_deref(),
        )
        .await?;
        let tunnels: Vec<TunnelSummary> = serde_json::from_slice(&body)
            .map_err(|e| format!("Failed to deserialize tunnels response: {e}"))?;
        Ok(tunnels)
    }

    /// Activate a dormant or suspended tunnel.
    pub async fn activate_tunnel(&self, id: &str) -> Result<(), String> {
        validate_http_token_or_segment(id, "tunnel id")?;
        let path = format!("/tunnels/{id}/activate");
        let _ =
            admin_http_request(&self.admin_url, "POST", &path, self.auth_token.as_deref()).await?;
        Ok(())
    }

    /// Suspend an active tunnel.
    pub async fn suspend_tunnel(&self, id: &str) -> Result<(), String> {
        validate_http_token_or_segment(id, "tunnel id")?;
        let path = format!("/tunnels/{id}/suspend");
        let _ =
            admin_http_request(&self.admin_url, "POST", &path, self.auth_token.as_deref()).await?;
        Ok(())
    }

    /// Trigger configuration reload.
    /// Enable or disable one or more tunnels (`A`, `1`, `1-200`, `all`).
    pub async fn set_tunnels_disabled(
        &self,
        target: &str,
        disabled: bool,
    ) -> Result<usize, String> {
        let path = if disabled {
            "/tunnels/batch/disable"
        } else {
            "/tunnels/batch/enable"
        };
        let body = serde_json::to_vec(&serde_json::json!({ "target": target }))
            .map_err(|e| e.to_string())?;
        let resp = admin_http_request_with_body(
            &self.admin_url,
            "POST",
            path,
            self.auth_token.as_deref(),
            Some(&body),
        )
        .await?;
        let val: serde_json::Value = serde_json::from_slice(&resp).map_err(|e| e.to_string())?;
        Ok(val
            .get("count")
            .and_then(serde_json::Value::as_u64)
            .unwrap_or(0) as usize)
    }

    pub async fn reload(&self) -> Result<ReloadReport, String> {
        #[derive(serde::Deserialize)]
        struct ReloadResp {
            report: Option<ReloadReport>,
        }
        let body = admin_http_request(
            &self.admin_url,
            "POST",
            "/reload",
            self.auth_token.as_deref(),
        )
        .await?;
        let parsed: ReloadResp = serde_json::from_slice(&body)
            .map_err(|e| format!("Failed to parse reload response: {e}"))?;
        Ok(parsed.report.unwrap_or_default())
    }

    /// Fetch daemon log lines (`GET /logs`).
    pub async fn fetch_logs(&self) -> Result<Vec<String>, String> {
        let body =
            admin_http_request(&self.admin_url, "GET", "/logs", self.auth_token.as_deref()).await?;
        serde_json::from_slice::<Vec<String>>(&body).map_err(|e| format!("Invalid /logs JSON: {e}"))
    }

    /// Retrieve active listeners from the data source.
    pub async fn fetch_listeners(&self) -> Result<Vec<ActiveListenerInfo>, String> {
        let body = admin_http_request(
            &self.admin_url,
            "GET",
            "/listeners",
            self.auth_token.as_deref(),
        )
        .await?;
        serde_json::from_slice(&body)
            .map_err(|e| format!("Failed to deserialize listeners response: {e}"))
    }

    /// Retrieve current configuration snapshot from the data source.
    pub async fn fetch_config(&self) -> Result<MainConfig, String> {
        let body = admin_http_request(
            &self.admin_url,
            "GET",
            "/config",
            self.auth_token.as_deref(),
        )
        .await?;
        serde_json::from_slice(&body)
            .map_err(|e| format!("Failed to deserialize config response: {e}"))
    }

    /// Apply updated runtime configuration to the data source.
    pub async fn apply_config(&self, cfg: &MainConfig) -> Result<(), String> {
        let json_bytes = serde_json::to_vec(cfg).map_err(|e| format!("Serialize error: {e}"))?;
        let _ = admin_http_request_with_body(
            &self.admin_url,
            "POST",
            "/config",
            self.auth_token.as_deref(),
            Some(&json_bytes),
        )
        .await?;
        Ok(())
    }

    /// Update the Admin API bearer token after an explicit token rotation.
    pub fn set_remote_auth_token(&mut self, next: Option<String>) {
        self.auth_token = next;
    }

    /// Probe a single tunnel with a real WireGuard handshake check
    /// through the Admin API. Activation alone is not a probe result:
    /// a tunnel that activates but never completes a handshake must
    /// report FAIL, not "Activated OK".
    pub async fn probe_tunnel(&self, id: &str, endpoint: &str) -> TuiProbeResult {
        let outcome = async {
            validate_http_token_or_segment(id, "tunnel id")?;
            let path = format!("/tunnels/{id}/probe");
            let body =
                admin_http_request(&self.admin_url, "POST", &path, self.auth_token.as_deref())
                    .await?;
            let parsed: AdminProbeResponse = serde_json::from_slice(&body)
                .map_err(|e| format!("Failed to deserialize probe response: {e}"))?;
            Ok::<AdminProbeResponse, String>(parsed)
        }
        .await;
        match outcome {
            Ok(parsed) => TuiProbeResult {
                id: id.to_string(),
                endpoint: endpoint.to_string(),
                ok: parsed.ok,
                rtt_ms: parsed.rtt_ms,
                message: parsed.message,
            },
            Err(e) => TuiProbeResult {
                id: id.to_string(),
                endpoint: endpoint.to_string(),
                ok: false,
                rtt_ms: None,
                message: e,
            },
        }
    }
}

/// Central state model for the TUI monitor dashboard.
#[derive(Debug)]
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
    /// Last data-source fetch failure, if any. A monitor must keep
    /// retrying, but a dead data source must never look like an empty
    /// daemon: while this is set the footer shows the error on every
    /// tab until a fetch succeeds again.
    pub data_source_error: Option<String>,
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
    /// Last remote log line visible when `c` cleared the Logs tab.
    /// The daemon keeps its own history and `GET /logs` re-fetches all
    /// of it on every refresh, so without this the cleared lines came
    /// straight back. `refresh()` drops everything up to and including
    /// this line, so cleared lines stay gone and only lines logged
    /// after the clear reappear. If the marker has rotated out of the
    /// daemon's ring buffer, everything fetched is newer than it, so
    /// nothing is dropped.
    pub remote_logs_clear_marker: Option<String>,
    pub log_scroll: usize,
    pub log_level_filter: Option<String>,
    // Listeners tab state
    pub listeners: Vec<ActiveListenerInfo>,
    pub listener_scroll: usize,
    // Config tab state
    pub config_snapshot: Option<MainConfig>,
    pub config_startup_baseline: Option<MainConfig>,
    pub config_saved_baseline: Option<MainConfig>,
    pub config_path: Option<PathBuf>,
    pub config_selected: usize,
    pub config_editing: Option<String>,
    pub config_refresh_rate_ms: u64,
    // Probe tab state
    pub probe_results: Vec<TuiProbeResult>,
    pub probe_scroll: usize,
    // Animation tick counter (incremented every 100ms UI frame)
    pub anim_tick: u64,
    // Inline batch enable/disable prompt buffer (`-1-200`, `+1-200`, `A`, `all`)
    pub batch_prompt: Option<String>,
    /// Overlay on top of the active tab (`?` help, `Enter` tunnel detail).
    pub overlay: TuiOverlay,
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
            data_source_error: None,
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
            remote_logs_clear_marker: None,
            log_scroll: 0,
            log_level_filter: None,
            listeners: Vec::new(),
            listener_scroll: 0,
            config_snapshot: None,
            config_startup_baseline: None,
            config_saved_baseline: None,
            config_path: None,
            config_selected: 0,
            config_editing: None,
            config_refresh_rate_ms: 500,
            probe_results: Vec::new(),
            probe_scroll: 0,
            anim_tick: 0,
            batch_prompt: None,
            overlay: TuiOverlay::None,
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

    /// Switch active tab and cancel any active inline edit/search/batch mode.
    pub fn set_tab(&mut self, tab: TuiTab) {
        self.active_tab = tab;
        self.is_searching = false;
        self.config_editing = None;
        self.batch_prompt = None;
    }

    /// Cycle to the next TUI tab.
    pub fn next_tab(&mut self) {
        self.set_tab(self.active_tab.next());
    }

    /// Cycle to the previous TUI tab.
    pub fn prev_tab(&mut self) {
        self.set_tab(self.active_tab.prev());
    }

    /// Clear the visible log buffer. In-process this clears the shared
    /// buffer, so cleared lines stay gone. In remote mode the daemon
    /// keeps its own history and the next refresh re-fetches all of it,
    /// so the last visible line is remembered as a marker (see
    /// `remote_logs_clear_marker`) for `refresh()` to drop.
    pub fn clear_logs(&mut self) {
        if let Some(buf) = &self.log_buffer {
            buf.clear();
        } else {
            // Only move the marker when lines are actually visible:
            // clearing an already-empty view must keep the previous
            // marker, or the next refresh would resurrect the lines
            // the first clear dropped.
            if let Some(last) = self.remote_logs.last() {
                self.remote_logs_clear_marker = Some(last.clone());
            }
            self.remote_logs.clear();
        }
    }

    /// Drop lines up to and including the clear marker from a freshly
    /// fetched remote log list. Log lines carry timestamps, so the
    /// marker is unique in practice; the LAST occurrence is dropped
    /// through, so a duplicate of the marker logged after the clear
    /// is the only line this can over-drop. A missing marker means it
    /// rotated out of the daemon's ring buffer, in which case
    /// everything fetched is newer than the clear — keep it all.
    pub(crate) fn drop_cleared_logs(&self, mut logs: Vec<String>) -> Vec<String> {
        if let Some(marker) = &self.remote_logs_clear_marker
            && let Some(pos) = logs.iter().rposition(|l| l == marker)
        {
            logs.drain(..=pos);
        }
        logs
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
        let all = self
            .log_buffer
            .as_ref()
            .map_or_else(|| self.remote_logs.clone(), TuiLogBuffer::snapshot);
        match &self.log_level_filter {
            None => all,
            Some(lvl) => all.into_iter().filter(|l| l.contains(lvl)).collect(),
        }
    }

    /// Total number of configuration rows displayed in the Config tab.
    pub const CONFIG_ROW_COUNT: usize = ConfigField::ALL.len();

    /// Return `(label, current_value, is_cycle_toggle)` for a Config tab row.
    pub fn config_row_display(cfg: &MainConfig, idx: usize) -> (&'static str, String, bool) {
        let Some(field) = ConfigField::from_index(idx) else {
            return ("unknown", String::new(), false);
        };
        (field.key(), field.display_value(cfg), field.is_cycle())
    }

    /// Synchronize live TUI presentation settings (`tui.refresh_rate_ms`, `tui.default_sort`).
    pub fn sync_tui_settings(&mut self, cfg: &MainConfig) {
        self.config_refresh_rate_ms = cfg.tui.refresh_rate_ms;
        if self.sort_field != cfg.tui.default_sort {
            self.sort_field = cfg.tui.default_sort;
            self.apply_filter_and_sort();
        }
    }

    /// Current effective dashboard polling interval, reacting live to `tui.refresh_rate_ms`.
    pub fn effective_refresh_interval(&self, default_ms: u64) -> Duration {
        let ms = self
            .config_snapshot
            .as_ref()
            .map_or(default_ms, |c| c.tui.refresh_rate_ms)
            .max(50);
        Duration::from_millis(ms)
    }

    /// Compute changed `[LIVE]` and `[RESTART]` fields relative to the last saved baseline.
    pub fn config_diff_vs_saved(&self) -> ConfigDiffSummary {
        let Some(cfg) = &self.config_snapshot else {
            return ConfigDiffSummary::default();
        };
        let baseline = self.config_saved_baseline.as_ref().unwrap_or(cfg);
        diff_config_scopes(baseline, cfg)
    }

    /// List `[RESTART]` fields that currently differ from the daemon's startup configuration.
    pub fn config_pending_restart(&self) -> Vec<&'static str> {
        let Some(cfg) = &self.config_snapshot else {
            return Vec::new();
        };
        let startup = self.config_startup_baseline.as_ref().unwrap_or(cfg);
        diff_config_scopes(startup, cfg).restart_changed
    }

    async fn commit_mutated_config(
        &mut self,
        field: ConfigField,
        cfg: MainConfig,
    ) -> Result<(), String> {
        // The Admin API validates the config server-side; `top` never
        // validates locally.
        match field.scope() {
            ConfigApplyScope::Live => {
                // Apply the live change now — but only that change. The
                // table may also hold staged `[RESTART]` edits (their
                // values live in `cfg` too), and posting the whole
                // snapshot would apply them early: remotely that also
                // writes them to the daemon's file, so quitting with
                // `q` would have "saved" a change the UI calls unsaved.
                // Revert every restart-scoped field to the last saved
                // baseline for the apply; the staged values stay visible
                // in the table until `w`.
                let mut to_apply = cfg.clone();
                if let Some(base) = self
                    .config_saved_baseline
                    .clone()
                    .or_else(|| self.config_startup_baseline.clone())
                    .or_else(|| self.config_snapshot.clone())
                {
                    for f in ConfigField::ALL {
                        if f.scope() == ConfigApplyScope::Restart {
                            f.copy_value(&base, &mut to_apply);
                        }
                    }
                }
                self.data_source.apply_config(&to_apply).await?;
            }
            // `[RESTART]` edits are staged only: the daemon (and its
            // file) keep the old value until `w` saves and applies the
            // whole snapshot. Nothing here touches the daemon, so
            // quitting with `q` genuinely discards them.
            ConfigApplyScope::Restart => {}
        }
        let val = field.display_value(&cfg);
        self.sync_tui_settings(&cfg);
        self.config_snapshot = Some(cfg);
        let msg = match field.scope() {
            ConfigApplyScope::Live => format!(
                "Applied [LIVE] {} = {val} (press 'w' to save to disk)",
                field.key()
            ),
            ConfigApplyScope::Restart => format!(
                "Staged [RESTART] {} = {val} (press 'w' to save; daemon restart required)",
                field.key()
            ),
        };
        self.set_status(msg);
        Ok(())
    }

    /// Either cycle a toggle/enum config field immediately or start inline text editing.
    pub async fn activate_config_row(&mut self) -> Result<(), String> {
        let Some(mut cfg) = self.config_snapshot.clone() else {
            if let Ok(fetched) = self.data_source.fetch_config().await {
                self.set_loaded_config_baselines(&fetched);
                self.config_snapshot = Some(fetched);
            }
            return Ok(());
        };
        let Some(field) = ConfigField::from_index(self.config_selected) else {
            return Ok(());
        };
        if field.cycle(&mut cfg) {
            return self.commit_mutated_config(field, cfg).await;
        }
        self.config_editing = Some(field.initial_edit_buffer(&cfg));
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
        let Some(field) = ConfigField::from_index(self.config_selected) else {
            return Err("Invalid config field index".to_string());
        };
        field.apply_text(&mut cfg, &raw)?;
        self.commit_mutated_config(field, cfg).await
    }

    fn set_loaded_config_baselines(&mut self, cfg: &MainConfig) {
        if self.config_startup_baseline.is_none() {
            self.config_startup_baseline = Some(cfg.clone());
        }
        if self.config_saved_baseline.is_none() {
            self.config_saved_baseline = Some(cfg.clone());
        }
        self.sync_tui_settings(cfg);
    }

    /// Validate, persist `config_snapshot` to `config_path`, apply runtime settings,
    /// reload `.conf` tunnels, and return a structured [`ConfigSaveReport`].
    pub async fn save_config_and_reload_with_report(&mut self) -> Result<ConfigSaveReport, String> {
        let Some(cfg) = self.config_snapshot.clone() else {
            return Err("Config snapshot not loaded".to_string());
        };
        if self.config_path.is_some() {
            cfg.validate()
                .map_err(|e| format!("Config validation failed: {e}"))?;
        }

        let saved_to_disk = if let Some(path) = &self.config_path {
            let fresh = toml::to_string_pretty(&cfg)
                .map_err(|e| format!("Failed to serialize TOML: {e}"))?;
            // Preserve the user's comments in the existing file where
            // possible; fall back to the plain dump if the file cannot
            // be merged safely.
            let existing = tokio::fs::read_to_string(path).await.ok();
            let serialized = existing
                .as_deref()
                .and_then(|text| crate::config::merge_config_preserving_comments(text, &fresh))
                .unwrap_or(fresh);
            crate::core::write_config_atomically(path, &serialized)
                .await
                .map_err(|e| format!("Failed to write '{}': {e}", path.display()))?;
            true
        } else {
            false
        };

        self.data_source.apply_config(&cfg).await?;
        // A rotated `admin.auth_token` is a `[RESTART]` edit, so it is
        // only staged at commit time and the TUI must not start using it
        // before this save applies it — the daemon doesn't know the new
        // token yet. Switch the remote bearer here, once the save has
        // landed, so the refresh right after a rotation stays
        // authenticated.
        if let Some(tok) = &cfg.admin.auth_token
            && !crate::config::is_redacted_secret_placeholder(tok)
        {
            self.data_source.set_remote_auth_token(Some(tok.clone()));
        }
        self.sync_tui_settings(&cfg);
        let reload_report = self.data_source.reload().await?;

        let live_applied = self
            .config_saved_baseline
            .as_ref()
            .map_or_else(Vec::new, |saved| {
                diff_config_scopes(saved, &cfg).live_changed
            });
        let restart_pending = self
            .config_startup_baseline
            .as_ref()
            .map_or_else(Vec::new, |start| {
                diff_config_scopes(start, &cfg).restart_changed
            });
        self.config_saved_baseline = Some(cfg);

        let report = ConfigSaveReport {
            saved_to_disk,
            live_applied,
            restart_pending,
            reload_report,
        };
        self.set_status(format_save_status(&report));
        Ok(report)
    }

    /// Persist `config_snapshot` to `config_path` (if set), apply runtime settings, and reload.
    pub async fn save_config_and_reload(&mut self) -> Result<(), String> {
        let _report = self.save_config_and_reload_with_report().await?;
        Ok(())
    }

    /// Probe the currently selected tunnel (or first tunnel) and record the result.
    pub async fn probe_selected_tunnel(&mut self) {
        let target = self
            .selected_tunnel()
            .or_else(|| self.tunnels.first())
            .map(|t| {
                (
                    t.id.clone(),
                    t.endpoint.clone().unwrap_or_else(|| "-".into()),
                )
            });
        let Some((id, endpoint)) = target else {
            self.set_status("No tunnels available to probe");
            return;
        };
        let res = self.data_source.probe_tunnel(&id, &endpoint).await;
        self.set_status(format!("Probe {}: {}", res.id, res.message));
        if let Some(slot) = self.probe_results.iter_mut().find(|r| r.id == res.id) {
            *slot = res;
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
            .map(|t| {
                (
                    t.id.clone(),
                    t.endpoint.clone().unwrap_or_else(|| "-".into()),
                )
            })
            .collect();
        if targets.is_empty() {
            self.set_status("No tunnels available to probe");
            return;
        }
        let mut set = tokio::task::JoinSet::new();
        for (idx, (id, endpoint)) in targets.into_iter().enumerate() {
            let ds = self.data_source.clone();
            set.spawn(async move { (idx, ds.probe_tunnel(&id, &endpoint).await) });
        }
        let mut indexed = Vec::new();
        while let Some(res) = set.join_next().await {
            if let Ok(item) = res {
                indexed.push(item);
            }
        }
        indexed.sort_by_key(|(idx, _)| *idx);
        let results: Vec<TuiProbeResult> = indexed.into_iter().map(|(_, r)| r).collect();
        let ok_count = results.iter().filter(|r| r.ok).count();
        let total = results.len();
        self.probe_results = results;
        self.probe_scroll = 0;
        self.set_status(format!("Probed {total} tunnels: {ok_count} OK"));
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
                .position(|&idx| self.tunnels.get(idx).is_some_and(|t| t.id == id))
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
            let (Some(ta), Some(tb)) = (tunnels.get(a), tunnels.get(b)) else {
                return std::cmp::Ordering::Equal;
            };
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

            if ascending { ord } else { ord.reverse() }
        });

        self.filtered_indices = indices;
        if self.filtered_indices.is_empty() {
            self.selected_index = 0;
            self.scroll_offset = 0;
        } else if self.selected_index >= self.filtered_indices.len() {
            self.selected_index = self.filtered_indices.len() - 1;
        } else {
            // Selection already within bounds.
        }
    }

    /// Move selection down by 1.
    pub const fn select_next(&mut self) {
        if !self.filtered_indices.is_empty()
            && self.selected_index + 1 < self.filtered_indices.len()
        {
            self.selected_index += 1;
        }
    }

    /// Move selection up by 1.
    pub const fn select_prev(&mut self) {
        if self.selected_index > 0 {
            self.selected_index -= 1;
        }
    }

    /// Page down by specified row count.
    pub fn page_down(&mut self, page_size: usize) {
        if !self.filtered_indices.is_empty() {
            self.selected_index =
                (self.selected_index + page_size).min(self.filtered_indices.len() - 1);
        }
    }

    /// Page up by specified row count.
    pub const fn page_up(&mut self, page_size: usize) {
        self.selected_index = self.selected_index.saturating_sub(page_size);
    }

    /// Jump directly to top of tunnel list.
    pub const fn scroll_to_top(&mut self) {
        self.selected_index = 0;
    }

    /// Jump directly to bottom of tunnel list.
    pub const fn scroll_to_bottom(&mut self) {
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
        self.sort_ascending.toggle();
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
            && ts.elapsed() > max_age
        {
            self.status_message = None;
        }
    }

    /// Fetch latest tunnel states (and active tab data + bandwidth samples) from data source.
    /// Refresh tunnel list (and tab-specific data) from the data source.
    /// A fetch failure is recorded in `data_source_error` and reported
    /// as `Ok`: the monitor keeps retrying on its 500 ms tick and the
    /// footer shows the error instead of an empty dashboard that looks
    /// like a healthy daemon with no tunnels.
    pub async fn refresh(&mut self) -> Result<(), String> {
        let list = match self.data_source.fetch_tunnels().await {
            Ok(list) => {
                self.data_source_error = None;
                list
            }
            Err(e) => {
                self.data_source_error = Some(e);
                return Ok(());
            }
        };
        let total_rx: u64 = list
            .iter()
            .fold(0u64, |acc, t| acc.saturating_add(t.rx_bytes));
        let total_tx: u64 = list
            .iter()
            .fold(0u64, |acc, t| acc.saturating_add(t.tx_bytes));
        let now = Instant::now();
        if let (Some(prev_rx), Some(prev_tx), Some(prev_at)) =
            (self.prev_total_rx, self.prev_total_tx, self.last_sample_at)
        {
            let elapsed_ms = now.duration_since(prev_at).as_millis().max(50);
            let rx_bps =
                u64::try_from(u128::from(total_rx.saturating_sub(prev_rx)) * 1000 / elapsed_ms)
                    .unwrap_or(u64::MAX);
            let tx_bps =
                u64::try_from(u128::from(total_tx.saturating_sub(prev_tx)) * 1000 / elapsed_ms)
                    .unwrap_or(u64::MAX);
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
            self.remote_logs = self.drop_cleared_logs(logs);
        }
        if self.active_tab == TuiTab::Listeners
            && let Ok(listeners) = self.data_source.fetch_listeners().await
        {
            self.listeners = listeners;
            self.listener_scroll = self
                .listener_scroll
                .min(self.listeners.len().saturating_sub(1));
        }
        if self.active_tab == TuiTab::Config
            && self.config_snapshot.is_none()
            && let Ok(cfg) = self.data_source.fetch_config().await
        {
            self.set_loaded_config_baselines(&cfg);
            self.config_snapshot = Some(cfg);
        }
        Ok(())
    }

    /// Activate currently selected tunnel.
    pub async fn activate_selected(&mut self) -> Result<(), String> {
        if let Some(t) = self.selected_tunnel() {
            let id = t.id.clone();
            self.data_source.activate_tunnel(&id).await?;
            self.set_status(format!("Activated tunnel '{id}'"));
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
            self.set_status(format!("Suspended tunnel '{id}'"));
            self.refresh().await?;
            Ok(())
        } else {
            Err("No tunnel selected".to_string())
        }
    }

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
        let (disabled, target) = trimmed.strip_prefix('+').map_or_else(
            || {
                trimmed
                    .strip_prefix('-')
                    .map_or((true, trimmed), |rest| (true, rest.trim()))
            },
            |rest| (false, rest.trim()),
        );
        let count = self
            .data_source
            .set_tunnels_disabled(target, disabled)
            .await?;
        let action = if disabled { "Disabled" } else { "Enabled" };
        self.set_status(format!("{action} {count} tunnel(s) ({target})"));
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
    pub const fn update_scroll(&mut self, viewport_height: usize) {
        if viewport_height == 0 || self.filtered_indices.is_empty() {
            self.scroll_offset = 0;
            return;
        }

        if self.selected_index < self.scroll_offset {
            self.scroll_offset = self.selected_index;
        } else if self.selected_index >= self.scroll_offset + viewport_height {
            self.scroll_offset = self.selected_index + 1 - viewport_height;
        } else {
            // Selected row already visible.
        }
    }
}
