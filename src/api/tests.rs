//! Unit tests for Milestone 5: HTTP Admin REST API & Prometheus metrics.

use std::collections::HashMap;
use std::sync::Arc;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use x25519_dalek::{PublicKey, StaticSecret};

use crate::api::routes::{handle_admin_request, HttpRequest};
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
    assert_eq!(json_val["version"], "0.1.0");
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
    assert_eq!(json_val["total_connections"], 0);
    assert!(json_val["listeners"].is_array());
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
    assert!(arr.iter().all(|t| t["id"].as_str().unwrap().contains("wgcf")));
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
    assert!(body_str.contains("wpmulti_connections_active_total 1"));
    assert!(body_str.contains("wpmulti_tunnel_rx_bytes{tunnel_id=\"wgcf-001\"} 1048576"));
    assert!(body_str.contains("wpmulti_tunnel_tx_bytes{tunnel_id=\"wgcf-001\"} 524288"));
    assert!(body_str.contains("wpmulti_tunnel_active_conns{tunnel_id=\"wgcf-001\"} 1"));
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
    bad_headers.insert("authorization".to_string(), "Bearer wrong_token".to_string());
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
