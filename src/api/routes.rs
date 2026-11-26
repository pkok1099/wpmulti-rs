//! HTTP routing and request dispatch for the Admin REST API.

use std::collections::HashMap;
use std::sync::Arc;

use serde::Serialize;
use serde_json::json;

use crate::api::metrics::generate_prometheus_metrics;
use crate::core::{CoreError, TunnelManager, TunnelState};

/// Inbound HTTP request model.
#[derive(Debug, Clone)]
pub struct HttpRequest {
    pub method: String,
    pub path: String,
    pub query: Option<String>,
    pub headers: HashMap<String, String>,
    pub body: Vec<u8>,
}

/// Outbound HTTP response model.
#[derive(Debug, Clone)]
pub struct HttpResponse {
    pub status: u16,
    pub reason: &'static str,
    pub content_type: &'static str,
    pub body: Vec<u8>,
}

impl HttpResponse {
    /// Construct a 200 OK JSON response.
    pub fn ok_json(val: &impl Serialize) -> Self {
        let body = serde_json::to_vec(val).unwrap_or_else(|_| b"{}".to_vec());
        Self {
            status: 200,
            reason: "OK",
            content_type: "application/json",
            body,
        }
    }

    /// Construct a 200 OK text response (e.g. for Prometheus metrics).
    pub const fn ok_text(text: String, content_type: &'static str) -> Self {
        Self {
            status: 200,
            reason: "OK",
            content_type,
            body: text.into_bytes(),
        }
    }

    /// Construct a 400 Bad Request response.
    pub fn bad_request(msg: &str) -> Self {
        let body = serde_json::to_vec(&json!({ "error": msg })).unwrap_or_default();
        Self {
            status: 400,
            reason: "Bad Request",
            content_type: "application/json",
            body,
        }
    }

    /// Construct a 413 Payload Too Large response.
    pub fn payload_too_large(msg: &str) -> Self {
        let body = serde_json::to_vec(&json!({ "error": msg })).unwrap_or_default();
        Self {
            status: 413,
            reason: "Payload Too Large",
            content_type: "application/json",
            body,
        }
    }

    /// Construct a 401 Unauthorized response.
    pub fn unauthorized() -> Self {
        let body = serde_json::to_vec(&json!({ "error": "unauthorized" })).unwrap_or_default();
        Self {
            status: 401,
            reason: "Unauthorized",
            content_type: "application/json",
            body,
        }
    }

    /// Construct a 404 Not Found response.
    pub fn not_found(msg: &str) -> Self {
        let body = serde_json::to_vec(&json!({ "error": msg })).unwrap_or_default();
        Self {
            status: 404,
            reason: "Not Found",
            content_type: "application/json",
            body,
        }
    }

    /// Construct a 405 Method Not Allowed response.
    pub fn method_not_allowed(msg: &str) -> Self {
        let body = serde_json::to_vec(&json!({ "error": msg })).unwrap_or_default();
        Self {
            status: 405,
            reason: "Method Not Allowed",
            content_type: "application/json",
            body,
        }
    }

    /// Construct a 403 Forbidden response.
    pub fn forbidden(msg: &str) -> Self {
        let body = serde_json::to_vec(&json!({ "error": msg })).unwrap_or_default();
        Self {
            status: 403,
            reason: "Forbidden",
            content_type: "application/json",
            body,
        }
    }

    /// Construct a 500 Internal Server Error response.
    pub fn internal_error(msg: &str) -> Self {
        let body = serde_json::to_vec(&json!({ "error": msg })).unwrap_or_default();
        Self {
            status: 500,
            reason: "Internal Server Error",
            content_type: "application/json",
            body,
        }
    }

    /// Serialize into standard HTTP/1.1 wire protocol format.
    pub fn to_bytes(&self) -> Vec<u8> {
        let header = format!(
            "HTTP/1.1 {} {}\r\nContent-Type: {}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            self.status,
            self.reason,
            self.content_type,
            self.body.len()
        );
        let mut bytes = Vec::with_capacity(header.len() + self.body.len());
        bytes.extend_from_slice(header.as_bytes());
        bytes.extend_from_slice(&self.body);
        bytes
    }
}

/// Parse raw HTTP/1.1 request bytes.
pub fn parse_http_request(bytes: &[u8]) -> Result<HttpRequest, String> {
    let header_end = bytes
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .ok_or_else(|| "Incomplete HTTP headers".to_string())?;

    let header_bytes = bytes
        .get(..header_end)
        .ok_or_else(|| "Incomplete HTTP headers".to_string())?;
    let header_str =
        std::str::from_utf8(header_bytes).map_err(|e| format!("Invalid UTF-8 in headers: {e}"))?;
    let mut lines = header_str.split("\r\n");

    let req_line = lines
        .next()
        .ok_or_else(|| "Missing request line".to_string())?;
    if req_line.contains(['\r', '\n', '\0', '\t']) {
        return Err("Invalid control character in request line".to_string());
    }
    let mut req_parts = req_line.split(' ');
    let (Some(method_raw), Some(uri), Some(version), None) = (
        req_parts.next(),
        req_parts.next(),
        req_parts.next(),
        req_parts.next(),
    ) else {
        return Err("Malformed HTTP request line".to_string());
    };
    if method_raw.is_empty() || uri.is_empty() || (version != "HTTP/1.1" && version != "HTTP/1.0") {
        return Err("Invalid HTTP method, URI, or version".to_string());
    }
    let method = method_raw.to_uppercase();

    let (path, query) = match uri.split_once('?') {
        Some((p, q)) => (percent_decode(p), Some(q.to_string())),
        None => (percent_decode(uri), None),
    };

    let mut headers = HashMap::new();
    for line in lines {
        if line.is_empty() {
            continue;
        }
        if line.contains(['\r', '\n', '\0']) {
            return Err("Invalid control character in header".to_string());
        }
        let Some((k, v)) = line.split_once(':') else {
            return Err("Malformed HTTP header line".to_string());
        };
        if k.is_empty() || k.chars().any(char::is_whitespace) {
            return Err("Invalid HTTP header name".to_string());
        }
        let key = k.to_ascii_lowercase();
        if key == "transfer-encoding" {
            return Err("Transfer-Encoding is not supported".to_string());
        }
        if matches!(key.as_str(), "content-length" | "authorization" | "host")
            && headers.contains_key(&key)
        {
            return Err(format!("Duplicate '{key}' header"));
        }
        headers.insert(key, v.trim().to_string());
    }

    let body_start = header_end + 4;
    let body = bytes.get(body_start..).unwrap_or_default().to_vec();

    Ok(HttpRequest {
        method,
        path,
        query,
        headers,
        body,
    })
}

fn percent_decode(input: &str) -> String {
    let bytes = input.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes.get(i) == Some(&b'%')
            && let (Some(&hi), Some(&lo)) = (bytes.get(i + 1), bytes.get(i + 2))
            && let (Some(h), Some(l)) = (char::from(hi).to_digit(16), char::from(lo).to_digit(16))
        {
            out.push((h * 16 + l) as u8);
            i += 3;
            continue;
        }
        if let Some(&b) = bytes.get(i) {
            out.push(b);
        }
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// Parse query string pairs into key-value map.
fn parse_query_params(query: Option<&str>) -> HashMap<String, String> {
    let mut map = HashMap::new();
    if let Some(q) = query {
        for part in q.split('&') {
            if let Some((k, v)) = part.split_once('=') {
                map.insert(
                    percent_decode(k.trim()).to_lowercase(),
                    percent_decode(v.trim()),
                );
            }
        }
    }
    map
}

fn is_authorized(req: &HttpRequest, auth_token: Option<&str>) -> bool {
    let Some(expected_token) = auth_token else {
        return true;
    };
    if expected_token.is_empty() {
        return false;
    }
    let Some(h) = req.headers.get("authorization") else {
        return false;
    };
    let Some((scheme, token)) = h.split_once(' ') else {
        return false;
    };
    if !scheme.eq_ignore_ascii_case("bearer")
        || token.is_empty()
        || token
            .bytes()
            .any(|b| b.is_ascii_whitespace() || b.is_ascii_control())
    {
        return false;
    }
    crate::proxy::router::constant_time_eq_str(token, expected_token)
}

fn handle_status_request(manager: &Arc<TunnelManager>, uptime_secs: u64) -> HttpResponse {
    let stats = manager.get_tunnel_stats();
    let total_tunnels = stats.len();
    let active_tunnels = stats
        .iter()
        .filter(|s| s.state == TunnelState::Active)
        .count();
    let suspended_tunnels = stats
        .iter()
        .filter(|s| s.state == TunnelState::Suspended)
        .count();
    let dormant_tunnels = stats
        .iter()
        .filter(|s| s.state == TunnelState::Dormant)
        .count();
    let disabled_tunnels = stats.iter().filter(|s| s.disabled).count();
    let healthy_tunnels = stats
        .iter()
        .filter(|s| s.health == crate::core::HealthStatus::Healthy)
        .count();
    let untested_tunnels = stats
        .iter()
        .filter(|s| s.health == crate::core::HealthStatus::Untested)
        .count();
    let unhealthy_tunnels = stats
        .iter()
        .filter(|s| s.health == crate::core::HealthStatus::Unhealthy)
        .count();
    let half_open_tunnels = stats
        .iter()
        .filter(|s| s.health == crate::core::HealthStatus::HalfOpen)
        .count();
    let dead_tunnels = stats
        .iter()
        .filter(|s| s.health == crate::core::HealthStatus::Dead)
        .count();
    let total_connections: u64 = stats.iter().map(|s| s.total_conns).sum();
    let active_connections: usize = stats.iter().map(|s| s.active_conns).sum();
    let rx_bytes: u64 = stats.iter().map(|s| s.rx_bytes).sum();
    let tx_bytes: u64 = stats.iter().map(|s| s.tx_bytes).sum();
    let listeners = manager.listeners().list_listeners();

    HttpResponse::ok_json(&json!({
        "status": "ok",
        "version": env!("CARGO_PKG_VERSION"),
        "uptime_secs": uptime_secs,
        "total_tunnels": total_tunnels,
        "active_tunnels": active_tunnels,
        "suspended_tunnels": suspended_tunnels,
        "dormant_tunnels": dormant_tunnels,
        "disabled_tunnels": disabled_tunnels,
        "healthy_tunnels": healthy_tunnels,
        "untested_tunnels": untested_tunnels,
        "half_open_tunnels": half_open_tunnels,
        "unhealthy_tunnels": unhealthy_tunnels,
        "dead_tunnels": dead_tunnels,
        "total_connections": total_connections,
        "active_connections": active_connections,
        "rx_bytes": rx_bytes,
        "tx_bytes": tx_bytes,
        "listeners": listeners
    }))
}

fn handle_list_tunnels_request(req: &HttpRequest, manager: &Arc<TunnelManager>) -> HttpResponse {
    let params = parse_query_params(req.query.as_deref());
    let query_filter = params.get("q").map(|s| s.to_lowercase());
    let state_filter = params.get("state").map(|s| s.to_lowercase());
    // A filter value that matches no state used to answer `[]` with HTTP
    // 200, so a typo (or a copy of the capitalised `"Active"` from the
    // JSON) looked like "no tunnels in that state". Reject it loudly.
    if let Some(st) = &state_filter
        && !matches!(
            st.as_str(),
            "dormant" | "activating" | "active" | "suspended"
        )
    {
        return HttpResponse::bad_request(&format!(
            "Invalid state filter '{st}': expected one of dormant, activating, active, suspended"
        ));
    }
    let mut tunnels = manager.get_tunnel_stats();

    if let Some(q) = query_filter {
        tunnels.retain(|t| {
            t.id.to_lowercase().contains(&q)
                || t.endpoint
                    .as_deref()
                    .unwrap_or("")
                    .to_lowercase()
                    .contains(&q)
        });
    }
    if let Some(st) = state_filter {
        tunnels.retain(|t| t.state.to_string().to_lowercase() == st);
    }

    HttpResponse::ok_json(&tunnels)
}

fn tunnel_action_response<T>(
    res: Result<T, CoreError>,
    id: &str,
    status_label: &str,
    err_prefix: &str,
    manager: &Arc<TunnelManager>,
) -> HttpResponse {
    match res {
        Ok(_) => {
            let summary = manager.registry().get(id).map(|e| e.summary());
            HttpResponse::ok_json(&json!({
                "status": status_label,
                "tunnel": summary
            }))
        }
        Err(CoreError::TunnelNotFound(_)) => {
            HttpResponse::not_found(&format!("Tunnel '{id}' not found"))
        }
        Err(e) => HttpResponse::internal_error(&format!("{err_prefix}: {e}")),
    }
}

async fn handle_batch_toggle(
    path: &str,
    body: &[u8],
    manager: &Arc<TunnelManager>,
) -> HttpResponse {
    #[derive(serde::Deserialize)]
    struct BatchReq {
        target: String,
    }
    let disabled = path.ends_with("/disable");
    let payload = match serde_json::from_slice::<BatchReq>(body) {
        Ok(p) => p,
        Err(e) => return HttpResponse::bad_request(&format!("Invalid JSON body: {e}")),
    };
    match manager
        .set_tunnels_disabled(&payload.target, disabled)
        .await
    {
        Ok(updated) => HttpResponse::ok_json(&json!({
            "status": if disabled { "disabled" } else { "enabled" },
            "count": updated.len(),
            "tunnels": updated
        })),
        Err(CoreError::TunnelNotFound(msg)) => {
            HttpResponse::not_found(&format!("Tunnel target not found: {msg}"))
        }
        Err(e) => HttpResponse::bad_request(&format!("Invalid target: {e}")),
    }
}

async fn handle_tunnel_subroute(
    method: &str,
    sub: &str,
    manager: &Arc<TunnelManager>,
) -> HttpResponse {
    if let Some((id, action)) = sub.split_once('/') {
        return match (method, action) {
            ("POST", "activate") => tunnel_action_response(
                manager.activate_tunnel(id).await,
                id,
                "activated",
                "Activation error",
                manager,
            ),
            ("POST", "probe") => {
                if manager.registry().get(id).is_none() {
                    HttpResponse::not_found(&format!("Tunnel '{id}' not found"))
                } else {
                    // A probe reports the handshake outcome, never the
                    // activation outcome: `ok` is false when the
                    // handshake fails or times out, even though the
                    // tunnel activated fine.
                    let outcome = manager.probe_tunnel(id).await;
                    HttpResponse::ok_json(&json!({
                        "id": id,
                        "ok": outcome.ok,
                        "rtt_ms": outcome.rtt_ms,
                        "message": outcome.message,
                    }))
                }
            }
            ("POST", "suspend" | "deactivate") => {
                let res = manager.suspend_tunnel(id).await;
                // A suspend that changes nothing must not claim
                // "suspended": a dormant tunnel stays dormant, and a
                // busy active tunnel stays active. Report the
                // resulting state instead.
                let label = match manager.registry().get(id).map(|e| e.summary().state) {
                    Some(TunnelState::Suspended) | None => "suspended".to_string(),
                    Some(TunnelState::Dormant) => "already dormant".to_string(),
                    Some(TunnelState::Activating) => "already activating".to_string(),
                    Some(TunnelState::Active) => "already active".to_string(),
                };
                tunnel_action_response(res, id, &label, "Suspend error", manager)
            }
            ("POST", "disable") => {
                if manager.registry().get(id).is_none() {
                    HttpResponse::not_found(&format!("Tunnel '{id}' not found"))
                } else {
                    let res = manager.set_tunnels_disabled(id, true).await;
                    // A disable that leaves live sessions running must not
                    // claim plain "disabled": the tunnel stays Active
                    // until drained. Report the pending state instead
                    // (the tunnel summary also carries disable_pending).
                    let label = match manager.registry().get(id) {
                        Some(e) if e.is_disable_pending() => format!(
                            "disabled (pending: {} active connection(s) still running; will suspend when drained)",
                            e.summary().active_conns
                        ),
                        _ => "disabled".to_string(),
                    };
                    tunnel_action_response(res, id, &label, "Disable error", manager)
                }
            }
            ("POST", "enable") => {
                if manager.registry().get(id).is_none() {
                    HttpResponse::not_found(&format!("Tunnel '{id}' not found"))
                } else {
                    tunnel_action_response(
                        manager.set_tunnels_disabled(id, false).await,
                        id,
                        "enabled",
                        "Enable error",
                        manager,
                    )
                }
            }
            _ => HttpResponse::not_found("Action not found"),
        };
    }

    match method {
        "GET" => manager.registry().get(sub).map_or_else(
            || HttpResponse::not_found(&format!("Tunnel '{sub}' not found")),
            |entry| HttpResponse::ok_json(&entry.summary()),
        ),
        _ => HttpResponse::method_not_allowed("Method not allowed"),
    }
}

fn is_allowed_unauthenticated_host(host_header: &str) -> bool {
    let trimmed = host_header.trim();
    let host_only = trimmed.strip_prefix('[').map_or_else(
        || trimmed.split_once(':').map_or(trimmed, |(h, _)| h),
        |rest| rest.split_once(']').map_or(trimmed, |(h, _)| h),
    );
    host_only.eq_ignore_ascii_case("localhost") || host_only.parse::<std::net::IpAddr>().is_ok()
}

fn has_json_content_type(req: &HttpRequest) -> bool {
    req.headers.get("content-type").is_some_and(|ct| {
        ct.split(';')
            .next()
            .is_some_and(|mime| mime.trim().eq_ignore_ascii_case("application/json"))
    })
}

/// Core routing function for incoming Admin REST API requests.
pub async fn handle_admin_request(
    req: &HttpRequest,
    manager: &Arc<TunnelManager>,
    auth_token: Option<&str>,
    uptime_secs: u64,
) -> HttpResponse {
    if auth_token.is_none()
        && let Some(host) = req.headers.get("host")
        && !is_allowed_unauthenticated_host(host)
    {
        return HttpResponse::forbidden("Invalid Host header for unauthenticated Admin API");
    }

    if !is_authorized(req, auth_token) {
        return HttpResponse::unauthorized();
    }

    let method = req.method.as_str();
    let path = req.path.as_str();

    match (method, path) {
        ("GET", "/health") => HttpResponse::ok_json(&json!({
            "status": "ok",
            "version": env!("CARGO_PKG_VERSION"),
            "uptime_secs": uptime_secs
        })),
        ("GET", "/status") => handle_status_request(manager, uptime_secs),
        ("GET", "/tunnels") => handle_list_tunnels_request(req, manager),
        ("GET", "/logs") => HttpResponse::ok_json(&manager.log_buffer().snapshot()),
        ("GET", "/listeners") => HttpResponse::ok_json(&manager.listeners().list_listeners()),
        ("GET", "/config") => {
            HttpResponse::ok_json(&redact_config_secrets(manager.config_snapshot()))
        }
        ("POST", "/config") => {
            if !has_json_content_type(req) {
                return HttpResponse::bad_request("Content-Type must be application/json");
            }
            handle_post_config(&req.body, manager).await
        }
        ("POST", "/reload") => {
            // A cross-origin simple request (HTML form, no-cors fetch)
            // cannot carry `application/json`: the browser either sends
            // a simple content type or fires a CORS preflight this
            // server does not answer. Requiring JSON here is what keeps
            // a website visited by the operator from firing a reload
            // through the loopback no-token bypass, exactly like
            // `POST /config` and the batch toggle already do. The
            // first-party client sends this header on every POST
            // (see `admin_http_request_with_body`).
            if !has_json_content_type(req) {
                return HttpResponse::bad_request("Content-Type must be application/json");
            }
            match manager.reload().await {
                Ok(report) => HttpResponse::ok_json(&json!({
                    "status": "reloaded",
                    "report": {
                        "added": report.added,
                        "removed": report.removed,
                        "updated": report.updated,
                        "total": report.total
                    },
                    "reloaded": report.total
                })),
                Err(e) => {
                    tracing::error!("Admin API /reload failed: {}", e);
                    let msg = if e.to_string().contains("does not exist") {
                        "Reload failed: config directory does not exist"
                    } else {
                        "Reload failed"
                    };
                    HttpResponse::internal_error(msg)
                }
            }
        }
        ("GET", "/metrics") => HttpResponse::ok_text(
            generate_prometheus_metrics(manager),
            "text/plain; version=0.0.4; charset=utf-8",
        ),
        ("POST", "/tunnels/batch/disable" | "/tunnels/batch/enable") => {
            if !has_json_content_type(req) {
                return HttpResponse::bad_request("Content-Type must be application/json");
            }
            handle_batch_toggle(path, &req.body, manager).await
        }
        _ => {
            if let Some(subpath) = path.strip_prefix("/tunnels/") {
                // Same cross-origin guard as `POST /reload` above: a
                // state-changing tunnel action must not be reachable as
                // a cross-origin simple request. Read-only `GET` on a
                // single tunnel is unaffected.
                if method == "POST" && !has_json_content_type(req) {
                    return HttpResponse::bad_request("Content-Type must be application/json");
                }
                handle_tunnel_subroute(method, subpath, manager).await
            } else {
                HttpResponse::not_found("Not found")
            }
        }
    }
}

async fn handle_post_config(body: &[u8], manager: &Arc<TunnelManager>) -> HttpResponse {
    // `POST /config` is a *partial* update: only the fields present in the
    // body change. A body used to be deserialized straight into `MainConfig`,
    // so every omitted section silently fell back to its serde default —
    // a one-setting change wiped `shared_listeners` and disabled the Admin
    // API while answering `{"status":"updated"}`. Deep-merge the incoming
    // JSON object over the running config instead; arrays (e.g.
    // `shared_listeners`) still replace wholesale when present.
    let incoming = match serde_json::from_slice::<serde_json::Value>(body) {
        Ok(v) => v,
        Err(e) => return HttpResponse::bad_request(&format!("Invalid JSON config: {e}")),
    };
    let Some(patch) = incoming.as_object() else {
        return HttpResponse::bad_request("Invalid JSON config: expected a JSON object");
    };
    // Serialize the whole snapshot+merge+write+apply cycle against
    // concurrent POST /config, batch disables, and reloads (audit run-1,
    // `src/api/routes.rs:post-config-concurrent-stale-snapshot-resurrection`):
    // without the guard two requests can merge from the same stale base
    // and the last applier — not the last writer — decides the live
    // config, silently losing an update or resurrecting a revoked token
    // that the stale snapshot round-tripped as `[REDACTED]`.
    let _apply_guard = manager.lock_config_apply().await;
    let existing = manager.config_snapshot();
    let mut merged = match serde_json::to_value(&existing) {
        Ok(v) => v,
        Err(e) => {
            tracing::error!("Admin API POST /config failed to serialize current config: {e}");
            return HttpResponse::internal_error("Failed to save configuration");
        }
    };
    // The `shared_listeners` field serializes under its TOML name
    // `shared_listener` (singular) and accepts `shared_listeners` only
    // as a serde alias. The merge below is keyed on the serialized
    // names, so a patch using the alias would leave both keys in the
    // merged object and serde would reject it as a duplicate field.
    // Normalize the alias to the canonical key first.
    let mut patch = patch.clone();
    if let Some(listeners) = patch.remove("shared_listeners") {
        if patch.contains_key("shared_listener") {
            return HttpResponse::bad_request(
                "Invalid JSON config: use only one of `shared_listener` or `shared_listeners`",
            );
        }
        patch.insert("shared_listener".to_string(), listeners);
    }
    merge_config_json(&mut merged, &patch);
    let mut new_cfg = match serde_json::from_value::<crate::config::MainConfig>(merged) {
        Ok(cfg) => cfg,
        Err(e) => return HttpResponse::bad_request(&format!("Invalid JSON config: {e}")),
    };
    // `config_dir` is deliberately not preserved from remote updates:
    // letting the Admin API redirect the directory the daemon loads
    // .conf files from would let a remote caller point it at
    // attacker-controlled configs. Reject the change loudly instead
    // of silently discarding it while answering "updated".
    if new_cfg.global.config_dir != existing.global.config_dir {
        return HttpResponse::bad_request(
            "config_dir cannot be changed through the Admin API: edit wpmulti.toml directly and restart the daemon",
        );
    }
    preserve_config_secrets(&mut new_cfg, &existing);
    if let Err(e) = new_cfg.validate() {
        return HttpResponse::bad_request(&format!("Invalid config: {e}"));
    }
    // Tell the caller which of the settings it just changed only take
    // effect after a daemon restart, instead of letting `"updated"`
    // imply everything is live now. Live vs Restart follows the same
    // scope table the TUI Config tab shows (`[LIVE]` / `[RESTART]`).
    let restart_pending =
        crate::tui::config_editor::diff_config_scopes(&existing, &new_cfg).restart_changed;
    match manager.save_and_apply_runtime_config_locked(new_cfg).await {
        Ok(()) => HttpResponse::ok_json(&json!({
            "status": "updated",
            "restart_pending": restart_pending,
        })),
        Err(CoreError::Config(e)) => HttpResponse::bad_request(&format!("Invalid config: {e}")),
        Err(e) => {
            tracing::error!("Admin API POST /config failed: {}", e);
            HttpResponse::internal_error("Failed to save configuration")
        }
    }
}

/// Recursively merge `patch` into `base`: object keys merge key-by-key,
/// anything else (arrays, scalars, `null`) replaces the base value.
/// `patch` is borrowed so the caller keeps the parsed body.
fn merge_config_json(
    base: &mut serde_json::Value,
    patch: &serde_json::Map<String, serde_json::Value>,
) {
    let Some(base_obj) = base.as_object_mut() else {
        return;
    };
    for (key, value) in patch {
        match (base_obj.get_mut(key), value) {
            (Some(existing), serde_json::Value::Object(patch_obj)) if existing.is_object() => {
                merge_config_json(existing, patch_obj);
            }
            _ => {
                base_obj.insert(key.clone(), value.clone());
            }
        }
    }
}

/// Placeholder marking a secret that is set but hidden from API responses.
const REDACTED_PLACEHOLDER: &str = "[REDACTED]";

fn redact_config_secrets(mut cfg: crate::config::MainConfig) -> crate::config::MainConfig {
    // Replace a set secret with a placeholder instead of removing it,
    // so a client (e.g. `top`) can tell "a secret is set" from "no
    // secret is set": the TUI shows `[KEEP]` / `[REDACTED]` for a set
    // secret and an empty editor when none is set. Posting the
    // placeholder back preserves the original secret (see
    // `should_preserve_secret`).
    if cfg.admin.auth_token.is_some() {
        cfg.admin.auth_token = Some(REDACTED_PLACEHOLDER.to_string());
    }
    for l in &mut cfg.shared_listeners {
        if l.global_password.is_some() {
            l.global_password = Some(REDACTED_PLACEHOLDER.to_string());
        }
    }
    for o in cfg.per_tunnel.overrides.values_mut() {
        if o.password.is_some() {
            o.password = Some(REDACTED_PLACEHOLDER.to_string());
        }
    }
    cfg
}

fn should_preserve_secret(incoming: Option<&str>) -> bool {
    incoming.is_none_or(crate::config::is_redacted_secret_placeholder)
}

fn find_matching_listener<'a>(
    listener: &crate::config::SharedListenerSettings,
    existing: &'a [crate::config::SharedListenerSettings],
) -> Option<&'a crate::config::SharedListenerSettings> {
    existing
        .iter()
        .find(|p| p.name == listener.name && p.bind == listener.bind)
        .or_else(|| existing.iter().find(|p| p.name == listener.name))
        .or_else(|| {
            let mut by_bind = existing.iter().filter(|p| p.bind == listener.bind);
            match (by_bind.next(), by_bind.next()) {
                (Some(only), None) => Some(only),
                _ => None,
            }
        })
}

fn preserve_config_secrets(
    new_cfg: &mut crate::config::MainConfig,
    existing: &crate::config::MainConfig,
) {
    // Prevent remote config updates from redirecting config_dir to an arbitrary path
    new_cfg
        .global
        .config_dir
        .clone_from(&existing.global.config_dir);
    if should_preserve_secret(new_cfg.admin.auth_token.as_deref()) {
        new_cfg
            .admin
            .auth_token
            .clone_from(&existing.admin.auth_token);
    }
    for l in &mut new_cfg.shared_listeners {
        if should_preserve_secret(l.global_password.as_deref()) {
            l.global_password = find_matching_listener(l, &existing.shared_listeners)
                .and_then(|prev| prev.global_password.clone());
        }
    }
    for (k, o) in &mut new_cfg.per_tunnel.overrides {
        if should_preserve_secret(o.password.as_deref()) {
            o.password = existing
                .per_tunnel
                .overrides
                .get(k)
                .and_then(|prev| prev.password.clone());
        }
    }
}
