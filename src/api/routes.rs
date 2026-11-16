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
    let healthy_tunnels = stats
        .iter()
        .filter(|s| s.health == crate::core::HealthStatus::Healthy)
        .count();
    let unhealthy_tunnels = stats
        .iter()
        .filter(|s| s.health == crate::core::HealthStatus::Unhealthy)
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
        "healthy_tunnels": healthy_tunnels,
        "unhealthy_tunnels": unhealthy_tunnels,
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
            ("POST", "suspend" | "deactivate") => tunnel_action_response(
                manager.suspend_tunnel(id).await,
                id,
                "suspended",
                "Suspend error",
                manager,
            ),
            ("POST", "disable") => {
                if manager.registry().get(id).is_none() {
                    HttpResponse::not_found(&format!("Tunnel '{id}' not found"))
                } else {
                    tunnel_action_response(
                        manager.set_tunnels_disabled(id, true).await,
                        id,
                        "disabled",
                        "Disable error",
                        manager,
                    )
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
        ("POST", "/reload") => match manager.reload().await {
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
                tracing::error!("Admin API /reload failed: {:?}", e);
                let msg = if e.to_string().contains("does not exist") {
                    "Reload failed: config directory does not exist"
                } else {
                    "Reload failed"
                };
                HttpResponse::internal_error(msg)
            }
        },
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
                handle_tunnel_subroute(method, subpath, manager).await
            } else {
                HttpResponse::not_found("Not found")
            }
        }
    }
}

async fn handle_post_config(body: &[u8], manager: &Arc<TunnelManager>) -> HttpResponse {
    let mut new_cfg = match serde_json::from_slice::<crate::config::MainConfig>(body) {
        Ok(cfg) => cfg,
        Err(e) => return HttpResponse::bad_request(&format!("Invalid JSON config: {e}")),
    };
    preserve_config_secrets(&mut new_cfg, &manager.config_snapshot());
    if let Err(e) = new_cfg.validate() {
        return HttpResponse::bad_request(&format!("Invalid config: {e}"));
    }
    match manager.save_and_apply_runtime_config(new_cfg).await {
        Ok(()) => HttpResponse::ok_json(&json!({ "status": "updated" })),
        Err(CoreError::Config(e)) => HttpResponse::bad_request(&format!("Invalid config: {e}")),
        Err(e) => {
            tracing::error!("Admin API POST /config failed: {:?}", e);
            HttpResponse::internal_error("Failed to save configuration")
        }
    }
}

fn redact_config_secrets(mut cfg: crate::config::MainConfig) -> crate::config::MainConfig {
    cfg.admin.auth_token = None;
    for l in &mut cfg.shared_listeners {
        l.global_password = None;
    }
    for o in cfg.per_tunnel.overrides.values_mut() {
        o.password = None;
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
