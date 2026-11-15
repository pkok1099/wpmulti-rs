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
    pub fn ok_text(text: String, content_type: &'static str) -> Self {
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
    let mut header_end = 0;
    while header_end + 3 < bytes.len() {
        if &bytes[header_end..header_end + 4] == b"\r\n\r\n" {
            break;
        }
        header_end += 1;
    }

    if header_end + 3 >= bytes.len() {
        return Err("Incomplete HTTP headers".to_string());
    }

    let header_str = std::str::from_utf8(&bytes[..header_end])
        .map_err(|e| format!("Invalid UTF-8 in headers: {}", e))?;
    let mut lines = header_str.split("\r\n");

    let req_line = lines.next().ok_or_else(|| "Missing request line".to_string())?;
    let mut req_parts = req_line.split_whitespace();
    let method = req_parts
        .next()
        .ok_or_else(|| "Missing HTTP method".to_string())?
        .to_uppercase();
    let uri = req_parts
        .next()
        .ok_or_else(|| "Missing HTTP URI".to_string())?;

    let (path, query) = match uri.split_once('?') {
        Some((p, q)) => (p.to_string(), Some(q.to_string())),
        None => (uri.to_string(), None),
    };

    let mut headers = HashMap::new();
    for line in lines {
        if line.is_empty() {
            continue;
        }
        if let Some((k, v)) = line.split_once(':') {
            headers.insert(k.trim().to_lowercase(), v.trim().to_string());
        }
    }

    let body_start = header_end + 4;
    let body = bytes[body_start..].to_vec();

    Ok(HttpRequest {
        method,
        path,
        query,
        headers,
        body,
    })
}

/// Parse query string pairs into key-value map.
fn parse_query_params(query: Option<&str>) -> HashMap<String, String> {
    let mut map = HashMap::new();
    if let Some(q) = query {
        for part in q.split('&') {
            if let Some((k, v)) = part.split_once('=') {
                map.insert(k.trim().to_lowercase(), v.trim().to_string());
            }
        }
    }
    map
}

/// Core routing function for incoming Admin REST API requests.
pub async fn handle_admin_request(
    req: &HttpRequest,
    manager: &Arc<TunnelManager>,
    auth_token: Option<&str>,
    uptime_secs: u64,
) -> HttpResponse {
    // 1. Verify authentication token if configured
    if let Some(expected_token) = auth_token {
        let auth_hdr = req.headers.get("authorization");
        let authorized = match auth_hdr {
            Some(h) => {
                if let Some(token) = h.strip_prefix("Bearer ") {
                    token.trim() == expected_token
                } else {
                    false
                }
            }
            None => false,
        };

        if !authorized {
            return HttpResponse::unauthorized();
        }
    }

    let method = req.method.as_str();
    let path = req.path.as_str();

    // 2. Dispatch routes
    match (method, path) {
        // GET /health
        ("GET", "/health") => {
            HttpResponse::ok_json(&json!({
                "status": "ok",
                "version": env!("CARGO_PKG_VERSION"),
                "uptime_secs": uptime_secs
            }))
        }

        // GET /status
        ("GET", "/status") => {
            let stats = manager.get_tunnel_stats();
            let total_tunnels = stats.len();
            let active_tunnels = stats.iter().filter(|s| s.state == TunnelState::Active).count();
            let suspended_tunnels = stats.iter().filter(|s| s.state == TunnelState::Suspended).count();
            let dormant_tunnels = stats.iter().filter(|s| s.state == TunnelState::Dormant).count();
            let healthy_tunnels = stats.iter().filter(|s| s.health == crate::core::HealthStatus::Healthy).count();
            let unhealthy_tunnels = stats.iter().filter(|s| s.health == crate::core::HealthStatus::Unhealthy).count();
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

        // GET /tunnels
        ("GET", "/tunnels") => {
            let params = parse_query_params(req.query.as_deref());
            let query_filter = params.get("q").map(|s| s.to_lowercase());
            let state_filter = params.get("state").map(|s| s.to_lowercase());

            let mut tunnels = manager.get_tunnel_stats();

            if let Some(q) = query_filter {
                tunnels.retain(|t| {
                    t.id.to_lowercase().contains(&q)
                        || t.endpoint.as_deref().unwrap_or("").to_lowercase().contains(&q)
                });
            }

            if let Some(st) = state_filter {
                tunnels.retain(|t| t.state.to_string().to_lowercase() == st);
            }

            HttpResponse::ok_json(&tunnels)
        }

        // POST /reload
        ("POST", "/reload") => {
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
                Err(e) => HttpResponse::internal_error(&format!("Reload failed: {}", e)),
            }
        }

        // GET /metrics
        ("GET", "/metrics") => {
            let metrics_text = generate_prometheus_metrics(manager);
            HttpResponse::ok_text(
                metrics_text,
                "text/plain; version=0.0.4; charset=utf-8",
            )
        }

        // Parameterized routes /tunnels/:id and /tunnels/:id/action
        _ if path.starts_with("/tunnels/") => {
            let sub = &path["/tunnels/".len()..];
            if let Some((id, action)) = sub.split_once('/') {
                match (method, action) {
                    ("POST", "activate") => {
                        match manager.activate_tunnel(id).await {
                            Ok(_) => {
                                let summary = manager.registry().get(id).map(|e| e.summary());
                                HttpResponse::ok_json(&json!({
                                    "status": "activated",
                                    "tunnel": summary
                                }))
                            }
                            Err(CoreError::TunnelNotFound(_)) => {
                                HttpResponse::not_found(&format!("Tunnel '{}' not found", id))
                            }
                            Err(e) => {
                                HttpResponse::internal_error(&format!("Activation error: {}", e))
                            }
                        }
                    }
                    ("POST", "suspend") | ("POST", "deactivate") => {
                        match manager.suspend_tunnel(id).await {
                            Ok(_) => {
                                let summary = manager.registry().get(id).map(|e| e.summary());
                                HttpResponse::ok_json(&json!({
                                    "status": "suspended",
                                    "tunnel": summary
                                }))
                            }
                            Err(CoreError::TunnelNotFound(_)) => {
                                HttpResponse::not_found(&format!("Tunnel '{}' not found", id))
                            }
                            Err(e) => {
                                HttpResponse::internal_error(&format!("Suspend error: {}", e))
                            }
                        }
                    }
                    _ => HttpResponse::not_found("Action not found"),
                }
            } else {
                let id = sub;
                match method {
                    "GET" => {
                        if let Some(entry) = manager.registry().get(id) {
                            HttpResponse::ok_json(&entry.summary())
                        } else {
                            HttpResponse::not_found(&format!("Tunnel '{}' not found", id))
                        }
                    }
                    _ => HttpResponse::bad_request("Method not allowed"),
                }
            }
        }

        _ => HttpResponse::not_found("Not found"),
    }
}
