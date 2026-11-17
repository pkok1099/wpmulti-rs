//! Unit tests for Milestone 5: HTTP Admin REST API & Prometheus metrics.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use x25519_dalek::{PublicKey, StaticSecret};

use crate::api::routes::{HttpRequest, handle_admin_request};
use crate::api::server::AdminServer;
use crate::config::{MainConfig, TunnelConfig, WgInterfaceConfig, WgPeerConfig};
use crate::core::TunnelManager;

fn make_test_tunnel_config(id: &str, endpoint: &str) -> TunnelConfig {
    let iface = WgInterfaceConfig {
        private_key: StaticSecret::from([42u8; 32]),
        addresses: vec!["172.16.0.2/32".parse().unwrap()],
        dns: vec!["1.1.1.1".parse().unwrap()],
        listen_port: None,
        mtu: 1420,
    };

    let peer = WgPeerConfig {
        public_key: PublicKey::from([99u8; 32]),
        endpoint: endpoint.to_string(),
        allowed_ips: vec!["0.0.0.0/0".parse().unwrap()],
        preshared_key: None,
        persistent_keepalive: Some(25),
    };

    TunnelConfig {
        id: id.to_string(),
        interface: iface,
        peers: vec![peer],
    }
}

fn create_test_manager() -> Arc<TunnelManager> {
    let mut config = MainConfig::default();
    config.per_tunnel.enabled = false;
    let tunnels = vec![
        make_test_tunnel_config("wgcf-001", "198.51.100.1:51820"),
        make_test_tunnel_config("wgcf-002", "198.51.100.2:51820"),
        make_test_tunnel_config("vpn-backup", "198.51.100.3:51820"),
    ];
    let mgr = TunnelManager::new(config, tunnels).expect("manager created");
    Arc::new(mgr)
}

#[tokio::test]
async fn test_health_endpoint() {
    let manager = create_test_manager();
    let req = HttpRequest {
        method: "GET".to_string(),
        path: "/health".to_string(),
        query: None,
        headers: HashMap::new(),
        body: Vec::new(),
    };

    let resp = handle_admin_request(&req, &manager, None, 42).await;
    assert_eq!(resp.status, 200);
    assert_eq!(resp.content_type, "application/json");

    let json_val: serde_json::Value = serde_json::from_slice(&resp.body).unwrap();
    assert_eq!(json_val["status"], "ok");
    assert_eq!(json_val["version"], env!("CARGO_PKG_VERSION"));
    assert_eq!(json_val["uptime_secs"], 42);
}

#[tokio::test]
async fn test_status_endpoint() {
    let manager = create_test_manager();
    let req = HttpRequest {
        method: "GET".to_string(),
        path: "/status".to_string(),
        query: None,
        headers: HashMap::new(),
        body: Vec::new(),
    };

    let resp = handle_admin_request(&req, &manager, None, 10).await;
    assert_eq!(resp.status, 200);

    let json_val: serde_json::Value = serde_json::from_slice(&resp.body).unwrap();
    assert_eq!(json_val["status"], "ok");
    assert_eq!(json_val["total_tunnels"], 3);
    assert_eq!(json_val["active_tunnels"], 0);
    assert_eq!(json_val["dormant_tunnels"], 3);
    assert_eq!(json_val["disabled_tunnels"], 0);
    assert_eq!(json_val["healthy_tunnels"], 0);
    assert_eq!(json_val["unknown_tunnels"], 3);
    assert_eq!(json_val["unhealthy_tunnels"], 0);
    assert_eq!(json_val["total_connections"], 0);
    assert!(json_val["listeners"].is_array());
}

#[tokio::test]
async fn test_status_endpoint_counts_disabled_tunnels() {
    // A dormant tunnel that is disabled stays "Dormant" in the state
    // counts, so the summary needs its own disabled count — otherwise
    // `disable` looks like it had no effect on `wpmulti status`.
    let manager = create_test_manager();
    manager
        .set_tunnels_disabled("wgcf-001", true)
        .await
        .expect("disable succeeds");
    let req = HttpRequest {
        method: "GET".to_string(),
        path: "/status".to_string(),
        query: None,
        headers: HashMap::new(),
        body: Vec::new(),
    };

    let resp = handle_admin_request(&req, &manager, None, 10).await;
    assert_eq!(resp.status, 200);

    let json_val: serde_json::Value = serde_json::from_slice(&resp.body).unwrap();
    assert_eq!(json_val["total_tunnels"], 3);
    assert_eq!(json_val["dormant_tunnels"], 3);
    assert_eq!(json_val["disabled_tunnels"], 1);

    manager
        .set_tunnels_disabled("wgcf-001", false)
        .await
        .expect("enable succeeds");
    let resp = handle_admin_request(&req, &manager, None, 10).await;
    let json_val: serde_json::Value = serde_json::from_slice(&resp.body).unwrap();
    assert_eq!(json_val["disabled_tunnels"], 0);
}

#[tokio::test]
async fn test_list_tunnels_unfiltered() {
    let manager = create_test_manager();
    let req = HttpRequest {
        method: "GET".to_string(),
        path: "/tunnels".to_string(),
        query: None,
        headers: HashMap::new(),
        body: Vec::new(),
    };

    let resp = handle_admin_request(&req, &manager, None, 10).await;
    assert_eq!(resp.status, 200);

    let json_val: serde_json::Value = serde_json::from_slice(&resp.body).unwrap();
    let arr = json_val.as_array().expect("array of tunnels");
    assert_eq!(arr.len(), 3);
}

#[tokio::test]
async fn test_list_tunnels_query_filter() {
    let manager = create_test_manager();
    let req = HttpRequest {
        method: "GET".to_string(),
        path: "/tunnels".to_string(),
        query: Some("q=wgcf".to_string()),
        headers: HashMap::new(),
        body: Vec::new(),
    };

    let resp = handle_admin_request(&req, &manager, None, 10).await;
    assert_eq!(resp.status, 200);

    let json_val: serde_json::Value = serde_json::from_slice(&resp.body).unwrap();
    let arr = json_val.as_array().expect("array of tunnels");
    assert_eq!(arr.len(), 2);
    assert!(
        arr.iter()
            .all(|t| t["id"].as_str().unwrap().contains("wgcf"))
    );
}

#[tokio::test]
async fn test_list_tunnels_state_filter() {
    let manager = create_test_manager();
    let req = HttpRequest {
        method: "GET".to_string(),
        path: "/tunnels".to_string(),
        query: Some("state=dormant".to_string()),
        headers: HashMap::new(),
        body: Vec::new(),
    };

    let resp = handle_admin_request(&req, &manager, None, 10).await;
    assert_eq!(resp.status, 200);

    let json_val: serde_json::Value = serde_json::from_slice(&resp.body).unwrap();
    let arr = json_val.as_array().expect("array of tunnels");
    assert_eq!(arr.len(), 3);

    // Filter by active when none are active
    let req_active = HttpRequest {
        method: "GET".to_string(),
        path: "/tunnels".to_string(),
        query: Some("state=active".to_string()),
        headers: HashMap::new(),
        body: Vec::new(),
    };
    let resp_active = handle_admin_request(&req_active, &manager, None, 10).await;
    let json_active: serde_json::Value = serde_json::from_slice(&resp_active.body).unwrap();
    assert_eq!(json_active.as_array().unwrap().len(), 0);

    // Matching is case-insensitive: the JSON spells the state "Dormant"
    // (capitalised), so a user copying that value must get the same
    // result as the lowercase spelling in the docs.
    let req_capital = HttpRequest {
        method: "GET".to_string(),
        path: "/tunnels".to_string(),
        query: Some("state=Dormant".to_string()),
        headers: HashMap::new(),
        body: Vec::new(),
    };
    let resp_capital = handle_admin_request(&req_capital, &manager, None, 10).await;
    assert_eq!(resp_capital.status, 200);
    let json_capital: serde_json::Value = serde_json::from_slice(&resp_capital.body).unwrap();
    assert_eq!(json_capital.as_array().unwrap().len(), 3);

    // A value that matches no state is rejected loudly instead of
    // silently answering an empty list.
    let req_bogus = HttpRequest {
        method: "GET".to_string(),
        path: "/tunnels".to_string(),
        query: Some("state=bogus".to_string()),
        headers: HashMap::new(),
        body: Vec::new(),
    };
    let resp_bogus = handle_admin_request(&req_bogus, &manager, None, 10).await;
    assert_eq!(resp_bogus.status, 400);
    let body_bogus = String::from_utf8_lossy(&resp_bogus.body);
    assert!(
        body_bogus.contains("bogus") && body_bogus.contains("dormant"),
        "expected the 400 to name the bad value and the valid ones, got: {body_bogus}"
    );
}

#[tokio::test]
async fn test_get_tunnel_by_id_found_and_not_found() {
    let manager = create_test_manager();

    // 1. Found
    let req_found = HttpRequest {
        method: "GET".to_string(),
        path: "/tunnels/wgcf-001".to_string(),
        query: None,
        headers: HashMap::new(),
        body: Vec::new(),
    };
    let resp_found = handle_admin_request(&req_found, &manager, None, 10).await;
    assert_eq!(resp_found.status, 200);
    let val_found: serde_json::Value = serde_json::from_slice(&resp_found.body).unwrap();
    assert_eq!(val_found["id"], "wgcf-001");
    assert_eq!(val_found["endpoint"], "198.51.100.1:51820");

    // 2. Not found
    let req_missing = HttpRequest {
        method: "GET".to_string(),
        path: "/tunnels/nonexistent".to_string(),
        query: None,
        headers: HashMap::new(),
        body: Vec::new(),
    };
    let resp_missing = handle_admin_request(&req_missing, &manager, None, 10).await;
    assert_eq!(resp_missing.status, 404);
}

#[tokio::test]
async fn test_activate_and_suspend_endpoints() {
    let manager = create_test_manager();

    // Activate tunnel
    let req_act = HttpRequest {
        method: "POST".to_string(),
        path: "/tunnels/wgcf-001/activate".to_string(),
        query: None,
        headers: HashMap::new(),
        body: Vec::new(),
    };
    let resp_act = handle_admin_request(&req_act, &manager, None, 10).await;
    assert_eq!(resp_act.status, 200);
    let val_act: serde_json::Value = serde_json::from_slice(&resp_act.body).unwrap();
    assert_eq!(val_act["status"], "activated");
    assert_eq!(val_act["tunnel"]["id"], "wgcf-001");
    assert_eq!(val_act["tunnel"]["state"], "Active");

    // Suspend tunnel
    let req_susp = HttpRequest {
        method: "POST".to_string(),
        path: "/tunnels/wgcf-001/suspend".to_string(),
        query: None,
        headers: HashMap::new(),
        body: Vec::new(),
    };
    let resp_susp = handle_admin_request(&req_susp, &manager, None, 10).await;
    assert_eq!(resp_susp.status, 200);
    let val_susp: serde_json::Value = serde_json::from_slice(&resp_susp.body).unwrap();
    assert_eq!(val_susp["status"], "suspended");
    assert_eq!(val_susp["tunnel"]["state"], "Suspended");

    // Deactivate alias
    let req_deact = HttpRequest {
        method: "POST".to_string(),
        path: "/tunnels/wgcf-001/deactivate".to_string(),
        query: None,
        headers: HashMap::new(),
        body: Vec::new(),
    };
    let resp_deact = handle_admin_request(&req_deact, &manager, None, 10).await;
    assert_eq!(resp_deact.status, 200);
}

#[tokio::test]
async fn test_probe_endpoint_reports_handshake_outcome_and_404_for_unknown() {
    // The test tunnels point at TEST-NET endpoints no handshake can
    // ever complete against, so the probe must report the handshake
    // failure — never a success from merely activating the tunnel.
    // A short probe timeout bounds the wait on machines where UDP
    // works and the handshake would otherwise hang until timeout.
    let mut config = MainConfig::default();
    config.per_tunnel.enabled = false;
    config.health_check.probe_timeout = Duration::from_secs(1);
    let tunnels = vec![
        make_test_tunnel_config("wgcf-001", "198.51.100.1:51820"),
        make_test_tunnel_config("wgcf-002", "198.51.100.2:51820"),
    ];
    let manager = Arc::new(TunnelManager::new(config, tunnels).expect("manager created"));

    let req = HttpRequest {
        method: "POST".to_string(),
        path: "/tunnels/wgcf-001/probe".to_string(),
        query: None,
        headers: HashMap::new(),
        body: Vec::new(),
    };
    let resp = handle_admin_request(&req, &manager, None, 10).await;
    assert_eq!(resp.status, 200);
    let val: serde_json::Value = serde_json::from_slice(&resp.body).unwrap();
    assert_eq!(val["id"], "wgcf-001");
    assert_eq!(val["ok"], false);
    assert!(val["rtt_ms"].is_null());
    assert!(!val["message"].as_str().unwrap_or_default().is_empty());

    let req_unknown = HttpRequest {
        method: "POST".to_string(),
        path: "/tunnels/wgcf-999/probe".to_string(),
        query: None,
        headers: HashMap::new(),
        body: Vec::new(),
    };
    let resp_unknown = handle_admin_request(&req_unknown, &manager, None, 10).await;
    assert_eq!(resp_unknown.status, 404);
}

#[tokio::test]
async fn test_suspend_dormant_tunnel_reports_already_dormant() {
    // Suspending a tunnel that was never activated changes nothing, so
    // the response must say so instead of claiming "suspended".
    let manager = create_test_manager();
    let req = HttpRequest {
        method: "POST".to_string(),
        path: "/tunnels/wgcf-001/suspend".to_string(),
        query: None,
        headers: HashMap::new(),
        body: Vec::new(),
    };

    let resp = handle_admin_request(&req, &manager, None, 10).await;
    assert_eq!(resp.status, 200);
    let val: serde_json::Value = serde_json::from_slice(&resp.body).unwrap();
    assert_eq!(val["status"], "already dormant");
    assert_eq!(val["tunnel"]["state"], "Dormant");

    // Suspending an active tunnel still reports "suspended", and
    // suspending it again keeps "suspended" — the resulting state
    // really is Suspended in both cases.
    let req_act = HttpRequest {
        method: "POST".to_string(),
        path: "/tunnels/wgcf-001/activate".to_string(),
        query: None,
        headers: HashMap::new(),
        body: Vec::new(),
    };
    let resp_act = handle_admin_request(&req_act, &manager, None, 10).await;
    assert_eq!(resp_act.status, 200);
    let resp = handle_admin_request(&req, &manager, None, 10).await;
    let val: serde_json::Value = serde_json::from_slice(&resp.body).unwrap();
    assert_eq!(val["status"], "suspended");
    assert_eq!(val["tunnel"]["state"], "Suspended");
    let resp = handle_admin_request(&req, &manager, None, 10).await;
    let val: serde_json::Value = serde_json::from_slice(&resp.body).unwrap();
    assert_eq!(val["status"], "suspended");
    assert_eq!(val["tunnel"]["state"], "Suspended");
}

#[tokio::test]
async fn test_reload_endpoint() {
    let manager = create_test_manager();
    let req = HttpRequest {
        method: "POST".to_string(),
        path: "/reload".to_string(),
        query: None,
        headers: HashMap::new(),
        body: Vec::new(),
    };

    // Reload with non-existent config_dir returns 500 error cleanly
    let resp = handle_admin_request(&req, &manager, None, 10).await;
    assert_eq!(resp.status, 500);
    let val: serde_json::Value = serde_json::from_slice(&resp.body).unwrap();
    assert!(val["error"].as_str().unwrap().contains("does not exist"));
}

#[tokio::test]
async fn test_metrics_prometheus_exposition() {
    let manager = create_test_manager();
    let entry = manager.registry().get("wgcf-001").unwrap();
    entry.stats.add_rx(1048576);
    entry.stats.add_tx(524288);
    entry.stats.inc_conns();

    let req = HttpRequest {
        method: "GET".to_string(),
        path: "/metrics".to_string(),
        query: None,
        headers: HashMap::new(),
        body: Vec::new(),
    };
    let resp = handle_admin_request(&req, &manager, None, 10).await;
    assert_eq!(resp.status, 200);
    assert!(resp.content_type.contains("text/plain"));

    let body_str = String::from_utf8(resp.body).unwrap();
    assert!(body_str.contains("wpmulti_tunnels_total 3"));
    assert!(body_str.contains("wpmulti_tunnels_healthy 0"));
    assert!(body_str.contains("wpmulti_tunnels_unknown 3"));
    assert!(body_str.contains("wpmulti_tunnels_unhealthy 0"));
    assert!(body_str.contains("wpmulti_connections_active_total 1"));
    assert!(body_str.contains("wpmulti_tunnel_rx_bytes{tunnel_id=\"wgcf-001\"} 1048576"));
    assert!(body_str.contains("wpmulti_tunnel_tx_bytes{tunnel_id=\"wgcf-001\"} 524288"));
    assert!(body_str.contains("wpmulti_tunnel_active_conns{tunnel_id=\"wgcf-001\"} 1"));
    assert!(body_str.contains("wpmulti_tunnel_health{tunnel_id=\"wgcf-001\"} 0"));
    assert!(body_str.contains("wpmulti_tunnel_consecutive_failures{tunnel_id=\"wgcf-001\"} 0"));
}

#[tokio::test]
async fn test_auth_token_unauthorized_and_authorized() {
    let manager = create_test_manager();
    let secret_token = "secret123";

    // 1. Missing Authorization header
    let req_unauth = HttpRequest {
        method: "GET".to_string(),
        path: "/health".to_string(),
        query: None,
        headers: HashMap::new(),
        body: Vec::new(),
    };
    let resp_unauth = handle_admin_request(&req_unauth, &manager, Some(secret_token), 10).await;
    assert_eq!(resp_unauth.status, 401);

    // 2. Wrong Bearer token
    let mut bad_headers = HashMap::new();
    bad_headers.insert(
        "authorization".to_string(),
        "Bearer wrong_token".to_string(),
    );
    let req_bad = HttpRequest {
        method: "GET".to_string(),
        path: "/health".to_string(),
        query: None,
        headers: bad_headers,
        body: Vec::new(),
    };
    let resp_bad = handle_admin_request(&req_bad, &manager, Some(secret_token), 10).await;
    assert_eq!(resp_bad.status, 401);

    // 3. Valid Bearer token
    let mut good_headers = HashMap::new();
    good_headers.insert("authorization".to_string(), "Bearer secret123".to_string());
    let req_good = HttpRequest {
        method: "GET".to_string(),
        path: "/health".to_string(),
        query: None,
        headers: good_headers,
        body: Vec::new(),
    };
    let resp_good = handle_admin_request(&req_good, &manager, Some(secret_token), 10).await;
    assert_eq!(resp_good.status, 200);
}

#[tokio::test]
async fn test_admin_server_e2e_tcp() {
    let manager = create_test_manager();
    let server = AdminServer::new(
        "127.0.0.1:0".parse().unwrap(),
        manager,
        Some("test_token".to_string()),
    );
    let bound_addr = server.start().await.expect("server started");

    // Connect via raw TCP stream and issue GET /health with Bearer token
    let mut client = TcpStream::connect(bound_addr).await.expect("connect");
    let req = format!(
        "GET /health HTTP/1.1\r\nHost: {}\r\nAuthorization: Bearer test_token\r\nConnection: close\r\n\r\n",
        bound_addr
    );
    client.write_all(req.as_bytes()).await.unwrap();

    let mut resp_buf = Vec::new();
    client.read_to_end(&mut resp_buf).await.unwrap();
    let resp_str = String::from_utf8_lossy(&resp_buf);
    assert!(resp_str.starts_with("HTTP/1.1 200 OK"));
    assert!(resp_str.contains("\"status\":\"ok\""));

    server.stop().await;
}

#[tokio::test]
async fn test_admin_server_content_length_limit() {
    let manager = create_test_manager();
    let server = AdminServer::new("127.0.0.1:0".parse().unwrap(), manager, None);
    let bound_addr = server.start().await.expect("server started");

    let mut client = TcpStream::connect(bound_addr).await.expect("connect");
    let req = format!(
        "POST /api/v1/reload HTTP/1.1\r\nHost: {}\r\nContent-Length: 1048576\r\nConnection: close\r\n\r\n",
        bound_addr
    );
    client.write_all(req.as_bytes()).await.unwrap();

    let mut resp_buf = Vec::new();
    client.read_to_end(&mut resp_buf).await.unwrap();
    let resp_str = String::from_utf8_lossy(&resp_buf);
    assert!(resp_str.starts_with("HTTP/1.1 413 Payload Too Large"));

    server.stop().await;
}

#[tokio::test]
async fn test_listeners_and_config_endpoints() {
    let manager = create_test_manager();

    let req_listeners = HttpRequest {
        method: "GET".to_string(),
        path: "/listeners".to_string(),
        query: None,
        headers: HashMap::new(),
        body: Vec::new(),
    };
    let resp_listeners = handle_admin_request(&req_listeners, &manager, None, 10).await;
    assert_eq!(resp_listeners.status, 200);
    let listeners_json: serde_json::Value = serde_json::from_slice(&resp_listeners.body).unwrap();
    assert!(listeners_json.is_array());

    let req_get_cfg = HttpRequest {
        method: "GET".to_string(),
        path: "/config".to_string(),
        query: None,
        headers: HashMap::new(),
        body: Vec::new(),
    };
    let resp_get_cfg = handle_admin_request(&req_get_cfg, &manager, None, 10).await;
    assert_eq!(resp_get_cfg.status, 200);
    let mut cfg: crate::config::toml_config::MainConfig =
        serde_json::from_slice(&resp_get_cfg.body).unwrap();
    cfg.global.max_active_tunnels = 42;

    let req_post_cfg = HttpRequest {
        method: "POST".to_string(),
        path: "/config".to_string(),
        query: None,
        headers: HashMap::from([("content-type".to_string(), "application/json".to_string())]),
        body: serde_json::to_vec(&cfg).unwrap(),
    };
    let resp_post_cfg = handle_admin_request(&req_post_cfg, &manager, None, 10).await;
    assert_eq!(resp_post_cfg.status, 200);
    assert_eq!(manager.config_snapshot().global.max_active_tunnels, 42);
}

#[tokio::test]
async fn test_batch_and_single_tunnel_disable_enable() {
    let manager = create_test_manager();

    // Alphabetical order: 1 = vpn-backup, 2 = wgcf-001, 3 = wgcf-002
    assert_eq!(
        manager.resolve_tunnel_targets("1").unwrap(),
        vec!["vpn-backup"]
    );
    assert_eq!(
        manager.resolve_tunnel_targets("1-2").unwrap(),
        vec!["vpn-backup", "wgcf-001"]
    );
    assert_eq!(
        manager.resolve_tunnel_targets("wgcf-002").unwrap(),
        vec!["wgcf-002"]
    );
    assert_eq!(
        manager.resolve_tunnel_targets("all").unwrap(),
        vec!["vpn-backup", "wgcf-001", "wgcf-002"]
    );

    let req_batch_disable = HttpRequest {
        method: "POST".to_string(),
        path: "/tunnels/batch/disable".to_string(),
        query: None,
        headers: HashMap::from([("content-type".to_string(), "application/json".to_string())]),
        body: br#"{"target":"1-2"}"#.to_vec(),
    };
    let resp = handle_admin_request(&req_batch_disable, &manager, None, 10).await;
    assert_eq!(resp.status, 200);
    assert!(manager.registry().get("vpn-backup").unwrap().is_disabled());
    assert!(manager.registry().get("wgcf-001").unwrap().is_disabled());
    assert!(!manager.registry().get("wgcf-002").unwrap().is_disabled());
    assert_eq!(
        manager.config_snapshot().disabled_tunnels,
        vec!["vpn-backup".to_string(), "wgcf-001".to_string()]
    );

    let req_single_disable = HttpRequest {
        method: "POST".to_string(),
        path: "/tunnels/wgcf-002/disable".to_string(),
        query: None,
        headers: HashMap::new(),
        body: Vec::new(),
    };
    let resp2 = handle_admin_request(&req_single_disable, &manager, None, 10).await;
    assert_eq!(resp2.status, 200);
    assert!(manager.registry().get("wgcf-002").unwrap().is_disabled());

    let req_batch_enable = HttpRequest {
        method: "POST".to_string(),
        path: "/tunnels/batch/enable".to_string(),
        query: None,
        headers: HashMap::from([("content-type".to_string(), "application/json".to_string())]),
        body: br#"{"target":"all"}"#.to_vec(),
    };
    let resp3 = handle_admin_request(&req_batch_enable, &manager, None, 10).await;
    assert_eq!(resp3.status, 200);
    assert!(!manager.registry().get("vpn-backup").unwrap().is_disabled());
    assert!(!manager.registry().get("wgcf-001").unwrap().is_disabled());
    assert!(!manager.registry().get("wgcf-002").unwrap().is_disabled());
    assert!(manager.config_snapshot().disabled_tunnels.is_empty());
}

#[tokio::test]
async fn test_config_endpoint_redacts_and_preserves_secrets_and_auth_rejects_empty_token() {
    let mut cfg = MainConfig::default();
    cfg.per_tunnel.enabled = false;
    cfg.admin.auth_token = Some("super-secret-token".to_string());
    if let Some(l) = cfg.shared_listeners.first_mut() {
        l.global_password = Some("proxy-pass".to_string());
    }

    let manager = Arc::new(TunnelManager::new(cfg, Vec::new()).unwrap());

    // Empty expected token must fail closed.
    let empty_auth_req = HttpRequest {
        method: "GET".to_string(),
        path: "/status".to_string(),
        query: None,
        headers: HashMap::from([("authorization".to_string(), "Bearer ".to_string())]),
        body: Vec::new(),
    };
    let resp_empty = handle_admin_request(&empty_auth_req, &manager, Some(""), 10).await;
    assert_eq!(resp_empty.status, 401);

    // Case-insensitive bearer scheme must be accepted.
    let lowercase_bearer_req = HttpRequest {
        method: "GET".to_string(),
        path: "/config".to_string(),
        query: None,
        headers: HashMap::from([(
            "authorization".to_string(),
            "bearer super-secret-token".to_string(),
        )]),
        body: Vec::new(),
    };
    let resp_get = handle_admin_request(
        &lowercase_bearer_req,
        &manager,
        Some("super-secret-token"),
        10,
    )
    .await;
    assert_eq!(resp_get.status, 200);

    let returned_cfg: MainConfig = serde_json::from_slice(&resp_get.body).unwrap();
    assert!(returned_cfg.admin.auth_token.is_none());
    if let Some(l) = returned_cfg.shared_listeners.first() {
        assert!(l.global_password.is_none());
    }

    // Posting the redacted config back must preserve existing secrets.
    let post_req = HttpRequest {
        method: "POST".to_string(),
        path: "/config".to_string(),
        query: None,
        headers: HashMap::from([
            (
                "authorization".to_string(),
                "Bearer super-secret-token".to_string(),
            ),
            ("content-type".to_string(), "application/json".to_string()),
        ]),
        body: resp_get.body,
    };
    let resp_post = handle_admin_request(&post_req, &manager, Some("super-secret-token"), 10).await;
    assert_eq!(resp_post.status, 200);
    assert_eq!(
        manager.config_snapshot().admin.auth_token.as_deref(),
        Some("super-secret-token")
    );
}

#[tokio::test]
async fn test_post_config_rejects_config_dir_change() {
    // A remote config update that changes config_dir used to be
    // silently discarded while the API answered {"status":"updated"}.
    // The change must now be rejected loudly; an unchanged config_dir
    // still posts fine.
    let manager = create_test_manager();

    let get_req = HttpRequest {
        method: "GET".to_string(),
        path: "/config".to_string(),
        query: None,
        headers: HashMap::new(),
        body: Vec::new(),
    };
    let resp_get = handle_admin_request(&get_req, &manager, None, 10).await;
    assert_eq!(resp_get.status, 200);
    let mut cfg: MainConfig = serde_json::from_slice(&resp_get.body).unwrap();
    let original_dir = cfg.global.config_dir.clone();

    cfg.global.config_dir = std::path::PathBuf::from("./confs9");
    let changed_req = HttpRequest {
        method: "POST".to_string(),
        path: "/config".to_string(),
        query: None,
        headers: HashMap::from([("content-type".to_string(), "application/json".to_string())]),
        body: serde_json::to_vec(&cfg).unwrap(),
    };
    let resp_changed = handle_admin_request(&changed_req, &manager, None, 10).await;
    assert_eq!(resp_changed.status, 400);
    let val: serde_json::Value = serde_json::from_slice(&resp_changed.body).unwrap();
    assert!(
        val["error"]
            .as_str()
            .unwrap_or_default()
            .contains("config_dir"),
        "expected a config_dir error, got: {val}"
    );
    assert_eq!(manager.config_snapshot().global.config_dir, original_dir);

    cfg.global.config_dir = original_dir;
    let unchanged_req = HttpRequest {
        method: "POST".to_string(),
        path: "/config".to_string(),
        query: None,
        headers: HashMap::from([("content-type".to_string(), "application/json".to_string())]),
        body: serde_json::to_vec(&cfg).unwrap(),
    };
    let resp_unchanged = handle_admin_request(&unchanged_req, &manager, None, 10).await;
    assert_eq!(resp_unchanged.status, 200);
}

fn post_config_request(body: Vec<u8>) -> HttpRequest {
    HttpRequest {
        method: "POST".to_string(),
        path: "/config".to_string(),
        query: None,
        headers: HashMap::from([("content-type".to_string(), "application/json".to_string())]),
        body,
    }
}

fn create_test_manager_with_listeners() -> Arc<TunnelManager> {
    use crate::config::{
        AuthMode, ListenerType, PoolStrategy, SharedListenerSettings, TunnelPoolSelection,
    };

    let mut config = MainConfig::default();
    config.per_tunnel.enabled = false;
    config.admin.enabled = true;
    config.shared_listeners = vec![
        SharedListenerSettings {
            name: "shared-socks".to_string(),
            listener_type: ListenerType::Socks5,
            bind: "127.0.0.1:1080".parse().unwrap(),
            auth_mode: AuthMode::None,
            global_password: None,
            default_strategy: PoolStrategy::RoundRobin,
            allow_anonymous: true,
            pool: TunnelPoolSelection::All,
            ip_mode: None,
        },
        SharedListenerSettings {
            name: "shared-http".to_string(),
            listener_type: ListenerType::Http,
            bind: "127.0.0.1:8080".parse().unwrap(),
            auth_mode: AuthMode::None,
            global_password: None,
            default_strategy: PoolStrategy::RoundRobin,
            allow_anonymous: true,
            pool: TunnelPoolSelection::All,
            ip_mode: None,
        },
    ];
    let tunnels = vec![make_test_tunnel_config("wgcf-001", "198.51.100.1:51820")];
    Arc::new(TunnelManager::new(config, tunnels).expect("manager created"))
}

#[tokio::test]
async fn test_post_config_partial_body_keeps_omitted_sections() {
    // A partial body used to be deserialized straight into MainConfig, so
    // every omitted section silently fell back to its serde default: one
    // `{"global":{"log_level":"debug"}}` wiped `shared_listeners` and
    // disabled the Admin API while answering `{"status":"updated"}`.
    // Partial bodies must now merge over the running config.
    use crate::config::LogLevel;

    let manager = create_test_manager_with_listeners();

    let resp = handle_admin_request(
        &post_config_request(br#"{"global":{"log_level":"debug"}}"#.to_vec()),
        &manager,
        None,
        10,
    )
    .await;
    assert_eq!(resp.status, 200);
    let val: serde_json::Value = serde_json::from_slice(&resp.body).unwrap();
    assert_eq!(val["status"], "updated");
    // `log_level` is a [RESTART] setting: the response must say so instead
    // of implying everything is live now.
    let pending = val["restart_pending"].as_array().expect("restart_pending");
    assert!(
        pending.iter().any(|v| v == "global.log_level"),
        "expected global.log_level in restart_pending, got: {val}"
    );

    let snap = manager.config_snapshot();
    assert_eq!(snap.global.log_level, LogLevel::Debug);
    assert_eq!(
        snap.shared_listeners.len(),
        2,
        "partial POST wiped listeners"
    );
    assert!(snap.admin.enabled, "partial POST disabled the Admin API");

    // A partial body that changes only a [LIVE] setting reports nothing pending.
    let resp_live = handle_admin_request(
        &post_config_request(br#"{"health_check":{"threshold":9}}"#.to_vec()),
        &manager,
        None,
        10,
    )
    .await;
    assert_eq!(resp_live.status, 200);
    let val_live: serde_json::Value = serde_json::from_slice(&resp_live.body).unwrap();
    assert_eq!(val_live["restart_pending"].as_array().unwrap().len(), 0);
    let snap_live = manager.config_snapshot();
    assert_eq!(snap_live.health_check.threshold, 9);
    assert_eq!(snap_live.shared_listeners.len(), 2);
    assert_eq!(snap_live.global.log_level, LogLevel::Debug);
}

#[tokio::test]
async fn test_post_config_listener_array_replaces_and_alias_works() {
    let manager = create_test_manager_with_listeners();

    // An array that IS present replaces wholesale (documented): posting a
    // single listener leaves exactly that one. The field serializes
    // under its TOML name `shared_listener` (singular).
    let resp_arr = handle_admin_request(
        &post_config_request(
            br#"{"shared_listener":[{"name":"only","type":"socks5","bind":"127.0.0.1:1080","auth_mode":"none","default_strategy":"round-robin","allow_anonymous":true,"pool":"all"}]}"#
                .to_vec(),
        ),
        &manager,
        None,
        10,
    )
    .await;
    assert_eq!(resp_arr.status, 200);
    assert_eq!(manager.config_snapshot().shared_listeners.len(), 1);
    // `restart_pending` must name the field the way `GET /config`
    // serializes it (`shared_listener`, singular) — a client looking the
    // key up in the GET response must find it.
    let val_arr: serde_json::Value = serde_json::from_slice(&resp_arr.body).unwrap();
    let pending_arr = val_arr["restart_pending"]
        .as_array()
        .expect("restart_pending");
    assert!(
        pending_arr.iter().any(|v| v == "shared_listener"),
        "expected shared_listener in restart_pending, got: {val_arr}"
    );

    // The plural spelling is a serde alias and must keep working after
    // the merge: it may not collide with the serialized singular key.
    let resp_alias = handle_admin_request(
        &post_config_request(
            br#"{"shared_listeners":[{"name":"a","type":"socks5","bind":"127.0.0.1:1080","auth_mode":"none","default_strategy":"round-robin","allow_anonymous":true,"pool":"all"},{"name":"b","type":"http","bind":"127.0.0.1:8080","auth_mode":"none","default_strategy":"round-robin","allow_anonymous":true,"pool":"all"}]}"#
                .to_vec(),
        ),
        &manager,
        None,
        10,
    )
    .await;
    assert_eq!(resp_alias.status, 200);
    assert_eq!(manager.config_snapshot().shared_listeners.len(), 2);

    // A non-object body is rejected loudly, not merged into nonsense.
    let resp_bad = handle_admin_request(
        &post_config_request(br#"[1, 2, 3]"#.to_vec()),
        &manager,
        None,
        10,
    )
    .await;
    assert_eq!(resp_bad.status, 400);
}

#[tokio::test]
async fn test_post_config_rejects_unknown_tunnel_id() {
    // The test manager loads exactly one tunnel, wgcf-001. A listener
    // pool (or disabled list) naming any other id is a typo: reject it
    // with 400 instead of storing the ghost id and failing later as
    // `no healthy tunnels available in pool`.
    let manager = create_test_manager_with_listeners();

    let resp = handle_admin_request(
        &post_config_request(
            br#"{"shared_listener":[{"name":"only","type":"socks5","bind":"127.0.0.1:1080","auth_mode":"none","default_strategy":"round-robin","allow_anonymous":true,"pool":["wgcf-999"]}]}"#.to_vec(),
        ),
        &manager,
        None,
        10,
    )
    .await;
    assert_eq!(resp.status, 400);
    let body = String::from_utf8_lossy(&resp.body);
    assert!(body.contains("wgcf-999"), "got: {body}");
    // The stored config is untouched: still 2 listeners, no ghost id.
    assert_eq!(manager.config_snapshot().shared_listeners.len(), 2);
    assert!(
        manager.config_snapshot().disabled_tunnels.is_empty(),
        "ghost id must not be persisted"
    );

    // The same field with a real id is accepted.
    let resp_ok = handle_admin_request(
        &post_config_request(br#"{"disabled_tunnels":["wgcf-001"]}"#.to_vec()),
        &manager,
        None,
        10,
    )
    .await;
    assert_eq!(resp_ok.status, 200);
    assert_eq!(
        manager.config_snapshot().disabled_tunnels,
        vec!["wgcf-001".to_string()]
    );
}

#[tokio::test]
async fn test_admin_rejects_dns_rebinding_host_and_non_json_post() {
    let manager = create_test_manager();

    let rebind_req = HttpRequest {
        method: "GET".to_string(),
        path: "/status".to_string(),
        query: None,
        headers: HashMap::from([("host".to_string(), "attacker.example:9090".to_string())]),
        body: Vec::new(),
    };
    let resp = handle_admin_request(&rebind_req, &manager, None, 10).await;
    assert_eq!(resp.status, 403);

    let csrf_post = HttpRequest {
        method: "POST".to_string(),
        path: "/tunnels/batch/disable".to_string(),
        query: None,
        headers: HashMap::from([("content-type".to_string(), "text/plain".to_string())]),
        body: br#"{"target":"all"}"#.to_vec(),
    };
    let resp2 = handle_admin_request(&csrf_post, &manager, None, 10).await;
    assert_eq!(resp2.status, 400);
}

#[test]
fn test_admin_parse_http_request_rejects_bare_lf_and_duplicate_auth() {
    let bare_lf = b"GET /health HTTP/1.1\r\nHost: 127.0.0.1\nX-Test: 1\r\n\r\n";
    assert!(crate::api::routes::parse_http_request(bare_lf).is_err());

    let dup_auth =
        b"GET /health HTTP/1.1\r\nAuthorization: Bearer a\r\nAuthorization: Bearer b\r\n\r\n";
    assert!(crate::api::routes::parse_http_request(dup_auth).is_err());
}

#[tokio::test]
async fn test_admin_auth_rejects_partial_malformed_and_verifies_constant_time() {
    use crate::proxy::router::constant_time_eq_str;

    assert!(constant_time_eq_str("secret-token-123", "secret-token-123"));
    assert!(!constant_time_eq_str(
        "secret-token-123",
        "secret-token-124"
    ));
    assert!(!constant_time_eq_str("secret-token-123", "secret-token"));
    assert!(!constant_time_eq_str("", "secret-token-123"));

    let manager = create_test_manager();
    let expected = Some("super-secret-token");

    for bad_header in [
        None,
        Some(""),
        Some("Bearer"),
        Some("Bearer "),
        Some("Bearer  super-secret-token"),
        Some("Bearer super-secret-token "),
        Some("Bearer\tsuper-secret-token"),
        Some("Bearer super-secret-token\n"),
        Some("Basic c3VwZXItc2VjcmV0LXRva2Vu"),
        Some("Bearer super-secret-toke"),
        Some("Bearer super-secret-token-extra"),
        Some("Bearer super-secret-tokex"),
    ] {
        let mut headers = HashMap::new();
        if let Some(val) = bad_header {
            headers.insert("authorization".to_string(), val.to_string());
        }
        let req = HttpRequest {
            method: "GET".to_string(),
            path: "/status".to_string(),
            query: None,
            headers,
            body: Vec::new(),
        };
        let resp = handle_admin_request(&req, &manager, expected, 10).await;
        assert_eq!(
            resp.status, 401,
            "bad auth header {bad_header:?} must return 401"
        );
    }
}

#[tokio::test]
async fn test_metrics_requires_auth_and_sanitizes_control_labels() {
    let manager = create_test_manager();
    let token = Some("metrics-secret");

    let unauth_req = HttpRequest {
        method: "GET".to_string(),
        path: "/metrics".to_string(),
        query: None,
        headers: HashMap::new(),
        body: Vec::new(),
    };
    let unauth_resp = handle_admin_request(&unauth_req, &manager, token, 10).await;
    assert_eq!(unauth_resp.status, 401);

    let auth_req = HttpRequest {
        method: "GET".to_string(),
        path: "/metrics".to_string(),
        query: None,
        headers: HashMap::from([(
            "authorization".to_string(),
            "Bearer metrics-secret".to_string(),
        )]),
        body: Vec::new(),
    };
    let auth_resp = handle_admin_request(&auth_req, &manager, token, 10).await;
    assert_eq!(auth_resp.status, 200);
    let body = String::from_utf8(auth_resp.body).unwrap();
    assert!(body.contains("wpmulti_tunnels_total 3"));
    assert!(!body.contains("metrics-secret"));
}

#[tokio::test]
async fn test_admin_server_rejects_oversized_headers() {
    let manager = create_test_manager();
    let server = AdminServer::new("127.0.0.1:0".parse().unwrap(), manager, None);
    let bound = server.start().await.unwrap();

    let mut stream = TcpStream::connect(bound).await.unwrap();
    let big_val = "A".repeat(70_000);
    let req = format!("GET /health HTTP/1.1\r\nHost: 127.0.0.1\r\nX-Big: {big_val}\r\n\r\n");
    let _ = stream.write_all(req.as_bytes()).await;

    let mut resp = Vec::new();
    let _ = stream.read_to_end(&mut resp).await;
    let resp_str = String::from_utf8_lossy(&resp);
    assert!(
        resp_str.starts_with("HTTP/1.1 400 Bad Request"),
        "oversized header must return 400 Bad Request, got: {resp_str}"
    );

    server.stop().await;
}

async fn tcp_http_exchange(
    addr: std::net::SocketAddr,
    method: &str,
    path: &str,
    token: Option<&str>,
    body: Option<&[u8]>,
) -> (u16, String) {
    let mut client = TcpStream::connect(addr).await.expect("tcp connect");
    let mut raw = format!("{method} {path} HTTP/1.1\r\nHost: {addr}\r\n");
    if let Some(tok) = token {
        raw.push_str(&format!("Authorization: Bearer {tok}\r\n"));
    }
    if let Some(payload) = body {
        raw.push_str(&format!(
            "Content-Type: application/json\r\nContent-Length: {}\r\n",
            payload.len()
        ));
    }
    raw.push_str("Connection: close\r\n\r\n");
    client.write_all(raw.as_bytes()).await.expect("write head");
    if let Some(payload) = body {
        client.write_all(payload).await.expect("write body");
    }
    let mut buf = Vec::new();
    client.read_to_end(&mut buf).await.expect("read response");
    let text = String::from_utf8(buf).expect("utf8 response");
    let (head, resp_body) = text.split_once("\r\n\r\n").unwrap_or((&text, ""));
    let status = head
        .lines()
        .next()
        .and_then(|l| l.split_whitespace().nth(1))
        .and_then(|c| c.parse::<u16>().ok())
        .unwrap_or(0);
    (status, resp_body.to_string())
}

fn build_secret_test_config(conf_dir: &std::path::Path) -> MainConfig {
    use crate::config::{
        AuthMode, ListenerType, PoolStrategy, SharedListenerSettings, TunnelPoolSelection,
        TunnelPortOverride,
    };

    let mut cfg = MainConfig::default();
    cfg.global.config_dir = conf_dir.to_path_buf();
    cfg.per_tunnel.enabled = false;
    cfg.admin.enabled = true;
    cfg.admin.bind = "0.0.0.0:9090".parse().expect("bind");
    cfg.admin.auth_token = Some("adm-secret-01".to_string());
    cfg.shared_listeners = vec![
        SharedListenerSettings {
            name: "s5-a".to_string(),
            listener_type: ListenerType::Socks5,
            bind: "127.0.0.1:10801".parse().expect("bind1"),
            auth_mode: AuthMode::Global,
            global_password: Some("s5a-pass".to_string()),
            default_strategy: PoolStrategy::RoundRobin,
            allow_anonymous: false,
            pool: TunnelPoolSelection::All,
            ip_mode: None,
        },
        SharedListenerSettings {
            name: "http-b".to_string(),
            listener_type: ListenerType::Http,
            bind: "127.0.0.1:18082".parse().expect("bind2"),
            auth_mode: AuthMode::PerTunnel,
            global_password: Some("httpb-pass".to_string()),
            default_strategy: PoolStrategy::Random,
            allow_anonymous: true,
            pool: TunnelPoolSelection::All,
            ip_mode: None,
        },
    ];
    cfg.per_tunnel.overrides.insert(
        "wg-1".to_string(),
        TunnelPortOverride {
            socks5_port: Some(11001),
            http_port: None,
            password: Some("ov1-pass".to_string()),
        },
    );
    cfg.per_tunnel.overrides.insert(
        "wg-2".to_string(),
        TunnelPortOverride {
            socks5_port: Some(11002),
            http_port: None,
            password: Some("ov2-pass".to_string()),
        },
    );
    cfg
}

#[tokio::test]
async fn test_post_config_preserves_placeholder_secrets_reorders_and_persists_toml() {
    let temp = tempfile::TempDir::new().expect("temp");
    let toml_path = temp.path().join("wpmulti.toml");
    let cfg = build_secret_test_config(temp.path());
    std::fs::write(&toml_path, toml::to_string_pretty(&cfg).expect("toml")).expect("write");

    let manager = Arc::new(
        TunnelManager::new(
            cfg,
            vec![
                make_test_tunnel_config("wg-1", "198.51.100.1:51820"),
                make_test_tunnel_config("wg-2", "198.51.100.2:51820"),
            ],
        )
        .expect("mgr"),
    );
    manager.set_config_path(toml_path.clone());
    let server = AdminServer::new(
        "127.0.0.1:0".parse().expect("addr"),
        Arc::clone(&manager),
        Some("adm-secret-01".to_string()),
    );
    let addr = server.start().await.expect("start admin");

    let (status, get_body) =
        tcp_http_exchange(addr, "GET", "/config", Some("adm-secret-01"), None).await;
    assert_eq!(status, 200);
    for secret in [
        "adm-secret-01",
        "s5a-pass",
        "httpb-pass",
        "ov1-pass",
        "ov2-pass",
    ] {
        assert!(!get_body.contains(secret));
    }

    let mut payload: MainConfig = serde_json::from_str(&get_body).expect("json");
    payload.global.max_active_tunnels = 88;
    payload.admin.auth_token = Some("[REDACTED]".to_string());
    payload.shared_listeners.reverse();
    payload.shared_listeners[0].global_password = Some("[SET]".to_string());
    payload.shared_listeners[1].bind = "127.0.0.1:10809".parse().expect("rebind");
    payload.shared_listeners[1].global_password = Some("[KEEP]".to_string());
    payload
        .per_tunnel
        .overrides
        .get_mut("wg-1")
        .expect("wg1")
        .password = Some("[REDACTED]".to_string());
    payload
        .per_tunnel
        .overrides
        .get_mut("wg-2")
        .expect("wg2")
        .password = Some("***REDACTED***".to_string());

    let body = serde_json::to_vec(&payload).expect("encode");
    let (post_status, _) =
        tcp_http_exchange(addr, "POST", "/config", Some("adm-secret-01"), Some(&body)).await;
    assert_eq!(post_status, 200);

    for snapshot in [
        manager.config_snapshot(),
        MainConfig::from_file(&toml_path).expect("reload disk toml"),
    ] {
        assert_eq!(snapshot.global.max_active_tunnels, 88);
        assert_eq!(snapshot.admin.auth_token.as_deref(), Some("adm-secret-01"));
        assert_eq!(snapshot.shared_listeners[0].name, "http-b");
        assert_eq!(
            snapshot.shared_listeners[0].global_password.as_deref(),
            Some("httpb-pass")
        );
        assert_eq!(snapshot.shared_listeners[1].name, "s5-a");
        assert_eq!(snapshot.shared_listeners[1].bind.port(), 10809);
        assert_eq!(
            snapshot.shared_listeners[1].global_password.as_deref(),
            Some("s5a-pass")
        );
        assert_eq!(
            snapshot.per_tunnel.overrides["wg-1"].password.as_deref(),
            Some("ov1-pass")
        );
        assert_eq!(
            snapshot.per_tunnel.overrides["wg-2"].password.as_deref(),
            Some("ov2-pass")
        );
    }

    assert_eq!(
        tcp_http_exchange(addr, "GET", "/status", Some("adm-secret-01"), None)
            .await
            .0,
        200
    );
    assert_eq!(
        tcp_http_exchange(addr, "GET", "/status", Some("[REDACTED]"), None)
            .await
            .0,
        401
    );
    server.stop().await;
}

#[tokio::test]
async fn test_post_config_validates_post_merge_and_rotates_new_secrets() {
    let temp = tempfile::TempDir::new().expect("temp");
    let toml_path = temp.path().join("wpmulti.toml");

    // Non-loopback bind without prior secret must fail validation after placeholder merges to None
    let no_secret_mgr = Arc::new(TunnelManager::new(MainConfig::default(), Vec::new()).expect("m"));
    let mut bad_payload = MainConfig::default();
    bad_payload.admin.enabled = true;
    bad_payload.admin.bind = "0.0.0.0:9091".parse().expect("bind");
    bad_payload.admin.auth_token = Some("[REDACTED]".to_string());
    let req_bad = HttpRequest {
        method: "POST".to_string(),
        path: "/config".to_string(),
        query: None,
        headers: HashMap::from([("content-type".to_string(), "application/json".to_string())]),
        body: serde_json::to_vec(&bad_payload).expect("json"),
    };
    let resp_bad = handle_admin_request(&req_bad, &no_secret_mgr, None, 10).await;
    assert_eq!(resp_bad.status, 400);

    // Explicitly sending new secrets updates both runtime and disk .toml
    let cfg = build_secret_test_config(temp.path());
    std::fs::write(&toml_path, toml::to_string_pretty(&cfg).expect("toml")).expect("write");
    // The fixture config has per-tunnel overrides for wg-1/wg-2, so the
    // manager must actually load those tunnels: the reference check
    // rejects configs naming IDs no loaded .conf provides.
    let manager = Arc::new(
        TunnelManager::new(
            cfg,
            vec![
                make_test_tunnel_config("wg-1", "198.51.100.1:51820"),
                make_test_tunnel_config("wg-2", "198.51.100.2:51820"),
            ],
        )
        .expect("mgr"),
    );
    manager.set_config_path(toml_path.clone());
    let server = AdminServer::new(
        "127.0.0.1:0".parse().expect("addr"),
        Arc::clone(&manager),
        Some("adm-secret-01".to_string()),
    );
    let addr = server.start().await.expect("start admin");

    let mut rotated = manager.config_snapshot();
    rotated.admin.auth_token = Some("new-adm-tok-99".to_string());
    rotated.shared_listeners[0].global_password = Some("new-s5a-pass".to_string());
    rotated
        .per_tunnel
        .overrides
        .get_mut("wg-1")
        .expect("wg1")
        .password = Some("new-ov1-pass".to_string());

    let (post_status, _) = tcp_http_exchange(
        addr,
        "POST",
        "/config",
        Some("adm-secret-01"),
        Some(&serde_json::to_vec(&rotated).expect("json")),
    )
    .await;
    assert_eq!(post_status, 200);

    for snap in [
        manager.config_snapshot(),
        MainConfig::from_file(&toml_path).expect("reload disk"),
    ] {
        assert_eq!(snap.admin.auth_token.as_deref(), Some("new-adm-tok-99"));
        assert_eq!(
            snap.shared_listeners[0].global_password.as_deref(),
            Some("new-s5a-pass")
        );
        assert_eq!(
            snap.per_tunnel.overrides["wg-1"].password.as_deref(),
            Some("new-ov1-pass")
        );
    }
    assert_eq!(
        tcp_http_exchange(addr, "GET", "/status", Some("adm-secret-01"), None)
            .await
            .0,
        401
    );
    assert_eq!(
        tcp_http_exchange(addr, "GET", "/status", Some("new-adm-tok-99"), None)
            .await
            .0,
        200
    );
    server.stop().await;
}
