#![allow(
    unreachable_pub,
    unused_qualifications,
    trivial_casts,
    clippy::pedantic,
    clippy::nursery,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::large_futures,
    clippy::type_complexity,
    clippy::wildcard_enum_match_arm,
    clippy::too_many_arguments,
    reason = "test builds: fixtures and helpers need looser lints"
)]
#![warn(clippy::too_many_lines, clippy::cognitive_complexity)]

use std::collections::HashMap;
use std::fs;
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::Duration;

use tempfile::tempdir;
use x25519_dalek::{PublicKey, StaticSecret};

use wpmulti::api::handle_admin_request;
use wpmulti::api::routes::HttpRequest;
use wpmulti::cli::cmd_probe;
use wpmulti::config::{
    HealthCheckSettings, LifecycleMode, MainConfig, PoolStrategy, TunnelConfig, WgInterfaceConfig,
    WgPeerConfig,
};
use wpmulti::core::{
    ActiveProber, HealthStatus, LifecycleController, MultiTenantRouter, TunnelEntry,
    TunnelHealthTracker, TunnelManager, TunnelRegistry, TunnelState,
};

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

// =============================================================================
// Test 1: Passive Circuit Breaker Tripping, Cooldown, and Half-Open Trial
// =============================================================================

fn assert_tracker_state(
    tracker: &TunnelHealthTracker,
    expected_status: HealthStatus,
    expected_failures: usize,
    expected_routable: bool,
) {
    assert_eq!(tracker.current_status(), expected_status);
    assert_eq!(tracker.consecutive_failures(), expected_failures);
    assert_eq!(tracker.is_routable(), expected_routable);
}

#[test]
fn test_circuit_breaker_passive_lifecycle() {
    let tracker = TunnelHealthTracker::new();
    let threshold = 3;
    let cooldown = Duration::from_millis(50);

    // Initial state: Untested (never proven) but routable
    assert_tracker_state(&tracker, HealthStatus::Untested, 0, true);
    assert_eq!(tracker.cooldown_remaining_secs(), 0);

    // Failure 1 & 2: below threshold -> remains Unknown
    tracker.record_failure(threshold, cooldown);
    assert_tracker_state(&tracker, HealthStatus::Untested, 1, true);

    tracker.record_failure(threshold, cooldown);
    assert_tracker_state(&tracker, HealthStatus::Untested, 2, true);

    // Failure 3: reaches threshold -> trips to Unhealthy
    tracker.record_failure(threshold, cooldown);
    assert_tracker_state(&tracker, HealthStatus::Unhealthy, 3, false);

    // While cooling down: remains not routable
    assert!(!tracker.is_routable());

    // Wait for cooldown expiration
    std::thread::sleep(Duration::from_millis(60));

    // After cooldown: is_routable() advances state to HalfOpen and allows single trial
    assert!(tracker.is_routable());
    assert_eq!(tracker.current_status(), HealthStatus::HalfOpen);

    // Successful trial resets circuit breaker to Healthy
    tracker.record_success();
    assert_tracker_state(&tracker, HealthStatus::Healthy, 0, true);
    assert_eq!(tracker.cooldown_remaining_secs(), 0);
}

#[test]
fn test_circuit_breaker_half_open_failure_re_enters_cooldown() {
    let tracker = TunnelHealthTracker::new();
    let threshold = 2;
    let cooldown = Duration::from_millis(50);

    tracker.record_failure(threshold, cooldown);
    tracker.record_failure(threshold, cooldown);
    assert_eq!(tracker.current_status(), HealthStatus::Unhealthy);

    std::thread::sleep(Duration::from_millis(60));
    assert!(tracker.is_routable());
    assert_eq!(tracker.current_status(), HealthStatus::HalfOpen);

    // Trial fails: immediately re-enters Unhealthy
    tracker.record_failure(threshold, cooldown);
    assert_eq!(tracker.current_status(), HealthStatus::Unhealthy);
    assert!(!tracker.is_routable());
}

// =============================================================================
// Test 2: Dormant Lazy Tunnel Invariant (0% Idle CPU & 0 Socket Allocations)
// =============================================================================

#[test]
fn test_dormant_lazy_tunnel_preserves_zero_background_resources() {
    let registry = Arc::new(TunnelRegistry::new());
    let cfg = make_test_tunnel_config("lazy-zero-cpu", "192.0.2.1:51820");
    let entry = registry
        .register(TunnelEntry::new("lazy-zero-cpu", cfg, LifecycleMode::Lazy))
        .expect("register lazy tunnel");

    // Invariant 1: Tunnel state is Dormant
    assert_eq!(*entry.state.read(), TunnelState::Dormant);
    assert_eq!(entry.lifecycle_mode, LifecycleMode::Lazy);

    // Invariant 2: No active device handle or smoltcp network stack
    assert!(entry.active.read().is_none());

    // Invariant 3: Health status is routable with 0 failures
    assert!(entry.health.is_routable());
    assert_eq!(entry.health.consecutive_failures(), 0);

    // Invariant 4: No background tasks or active timers - cooldown is purely timestamp arithmetic
    entry.health.mark_unhealthy(Duration::from_millis(30));
    assert_eq!(entry.health.current_status(), HealthStatus::Unhealthy);
    assert!(!entry.health.is_routable());

    std::thread::sleep(Duration::from_millis(40));
    // Lazily queried:
    assert!(entry.health.is_routable());
    assert_eq!(entry.health.current_status(), HealthStatus::HalfOpen);

    // Still Dormant with zero sockets
    assert_eq!(*entry.state.read(), TunnelState::Dormant);
    assert!(entry.active.read().is_none());
}

// =============================================================================
// Test 3: MultiTenantRouter Auto-Failover Across 4 Strategies
// =============================================================================

#[test]
fn test_multitenant_router_failover_round_robin() {
    let registry = Arc::new(TunnelRegistry::new());
    let _e1 = registry
        .register(TunnelEntry::new(
            "t1",
            make_test_tunnel_config("t1", "1.1.1.1:51820"),
            LifecycleMode::Lazy,
        ))
        .unwrap();
    let e2 = registry
        .register(TunnelEntry::new(
            "t2",
            make_test_tunnel_config("t2", "1.1.1.2:51820"),
            LifecycleMode::Lazy,
        ))
        .unwrap();
    let _e3 = registry
        .register(TunnelEntry::new(
            "t3",
            make_test_tunnel_config("t3", "1.1.1.3:51820"),
            LifecycleMode::Lazy,
        ))
        .unwrap();

    let lifecycle = LifecycleController::new(
        Arc::clone(&registry),
        Duration::from_secs(60),
        Duration::from_secs(1),
    );
    let router = MultiTenantRouter::new(
        lifecycle,
        Arc::clone(&registry),
        PoolStrategy::RoundRobin,
        true,
    );
    let candidates = vec!["t1".to_string(), "t2".to_string(), "t3".to_string()];
    router.set_allowed_tunnels(Some(candidates.clone()));

    // When all 3 are healthy: all 3 participate in candidate pool
    let h1 = router.filter_healthy_candidates(&candidates);
    assert_eq!(h1.len(), 3);

    // Mark t2 Unhealthy
    e2.health.mark_unhealthy(Duration::from_secs(60));
    let h2 = router.filter_healthy_candidates(&candidates);
    assert_eq!(h2.len(), 2);
    assert_eq!(h2, vec![&"t1".to_string(), &"t3".to_string()]);

    // Restore t2
    e2.health.record_success();
    let h3 = router.filter_healthy_candidates(&candidates);
    assert_eq!(h3.len(), 3);
}

#[test]
fn test_multitenant_router_failover_least_conn() {
    let registry = Arc::new(TunnelRegistry::new());
    let e1 = registry
        .register(TunnelEntry::new(
            "t1",
            make_test_tunnel_config("t1", "1.1.1.1:51820"),
            LifecycleMode::Lazy,
        ))
        .unwrap();
    let e2 = registry
        .register(TunnelEntry::new(
            "t2",
            make_test_tunnel_config("t2", "1.1.1.2:51820"),
            LifecycleMode::Lazy,
        ))
        .unwrap();

    // t1 has 0 active connections; t2 has 5 active connections
    e1.stats.active_conns.store(0, Ordering::Relaxed);
    e2.stats.active_conns.store(5, Ordering::Relaxed);

    let lifecycle = LifecycleController::new(
        Arc::clone(&registry),
        Duration::from_secs(60),
        Duration::from_secs(1),
    );
    let router = MultiTenantRouter::new(
        lifecycle,
        Arc::clone(&registry),
        PoolStrategy::LeastConn,
        true,
    );
    let candidates = vec!["t1".to_string(), "t2".to_string()];
    router.set_allowed_tunnels(Some(candidates.clone()));

    // Initially, both healthy: t1 (0 conns) preferred over t2 (5 conns)
    let h = router.filter_healthy_candidates(&candidates);
    assert_eq!(h.len(), 2);

    // If t1 becomes Unhealthy: only t2 is available despite having 5 connections
    e1.health.mark_unhealthy(Duration::from_secs(60));
    let h2 = router.filter_healthy_candidates(&candidates);
    assert_eq!(h2.len(), 1);
    assert_eq!(h2[0], &"t2".to_string());
}

#[test]
fn test_multitenant_router_true_priority_fallback() {
    let registry = Arc::new(TunnelRegistry::new());
    let e1 = registry
        .register(TunnelEntry::new(
            "primary",
            make_test_tunnel_config("primary", "1.1.1.1:51820"),
            LifecycleMode::Lazy,
        ))
        .unwrap();
    let e2 = registry
        .register(TunnelEntry::new(
            "backup1",
            make_test_tunnel_config("backup1", "1.1.1.2:51820"),
            LifecycleMode::Lazy,
        ))
        .unwrap();
    let e3 = registry
        .register(TunnelEntry::new(
            "backup2",
            make_test_tunnel_config("backup2", "1.1.1.3:51820"),
            LifecycleMode::Lazy,
        ))
        .unwrap();

    let lifecycle = LifecycleController::new(
        Arc::clone(&registry),
        Duration::from_secs(60),
        Duration::from_secs(1),
    );
    let router = MultiTenantRouter::new(
        lifecycle,
        Arc::clone(&registry),
        PoolStrategy::Fallback,
        true,
    );
    let pool = vec![
        "primary".to_string(),
        "backup1".to_string(),
        "backup2".to_string(),
    ];
    router.set_allowed_tunnels(Some(pool.clone()));

    // 1. All healthy: primary candidate is always selected
    let healthy_all = router.filter_healthy_candidates(&pool);
    assert_eq!(healthy_all.len(), 3);

    // 2. Trip primary: failover seamlessly selects backup1
    e1.health.mark_unhealthy(Duration::from_secs(60));
    let healthy_after_e1 = router.filter_healthy_candidates(&pool);
    assert_eq!(healthy_after_e1.len(), 2);
    assert_eq!(healthy_after_e1[0], &"backup1".to_string());

    // 3. Trip backup1: failover selects backup2
    e2.health.mark_unhealthy(Duration::from_secs(60));
    let healthy_after_e2 = router.filter_healthy_candidates(&pool);
    assert_eq!(healthy_after_e2.len(), 1);
    assert_eq!(healthy_after_e2[0], &"backup2".to_string());

    // 4. Primary recovers: automatically resumes traffic on primary!
    e1.health.record_success();
    let healthy_restored = router.filter_healthy_candidates(&pool);
    assert_eq!(healthy_restored.len(), 2);
    assert_eq!(healthy_restored[0], &"primary".to_string());

    // 5. All unhealthy: filter returns empty
    e1.health.mark_unhealthy(Duration::from_secs(60));
    e3.health.mark_unhealthy(Duration::from_secs(60));
    let empty = router.filter_healthy_candidates(&pool);
    assert!(empty.is_empty());
}

// =============================================================================
// Test 4: Active Periodic Prober
// =============================================================================

#[tokio::test]
async fn test_active_prober_lifecycle() {
    let registry = Arc::new(TunnelRegistry::new());
    let e1 = registry
        .register(TunnelEntry::new(
            "lazy-1",
            make_test_tunnel_config("lazy-1", "1.1.1.1:51820"),
            LifecycleMode::Lazy,
        ))
        .unwrap();
    let _e2 = registry
        .register(TunnelEntry::new(
            "eager-1",
            make_test_tunnel_config("eager-1", "1.1.1.2:51820"),
            LifecycleMode::Eager,
        ))
        .unwrap();

    let prober = ActiveProber::new();
    let settings = HealthCheckSettings {
        threshold: 3,
        cooldown: Duration::from_secs(30),
        probe_interval: Duration::from_millis(50),
        probe_timeout: Duration::from_millis(20),
        probe_concurrency: 16,
        probe_attempts: 1,
    };

    // Lazy tunnel is never probed by ActiveProber
    assert_eq!(e1.lifecycle_mode, LifecycleMode::Lazy);
    prober.start(Arc::clone(&registry), settings);

    // Let the prober tick
    tokio::time::sleep(Duration::from_millis(120)).await;

    // Stop prober cleanly
    prober.stop().await;
}

// =============================================================================
// Test 5: CLI Subcommand `wpmulti probe`
// =============================================================================

#[tokio::test]
async fn test_cli_probe_single_and_dir() {
    let dir = tempdir().expect("tempdir");

    let conf1 = dir.path().join("probe-tunnel-1.conf");
    let conf2 = dir.path().join("probe-tunnel-2.conf");

    fs::write(
        &conf1,
        r#"
[Interface]
PrivateKey = 0OaUaQd4uJq5m8eN8uJq5m8eN8uJq5m8eN8uJq5m8eM=
Address = 10.0.0.1/32

[Peer]
PublicKey = bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo=
Endpoint = 192.0.2.1:51820
AllowedIPs = 0.0.0.0/0
"#,
    )
    .unwrap();

    fs::write(
        &conf2,
        r#"
[Interface]
PrivateKey = 0OaUaQd4uJq5m8eN8uJq5m8eN8uJq5m8eN8uJq5m8eM=
Address = 10.0.0.2/32

[Peer]
PublicKey = bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo=
Endpoint = 192.0.2.2:51820
AllowedIPs = 0.0.0.0/0
"#,
    )
    .unwrap();

    // 1. Probe single config with short timeout
    let res_single = cmd_probe(Some(conf1.clone()), None, true, "100ms".into())
        .await
        .expect("probe single");
    assert_eq!(res_single.len(), 1);
    assert_eq!(res_single[0].id, "probe-tunnel-1");
    assert_eq!(res_single[0].endpoint, "192.0.2.1:51820");

    // 2. Probe directory of configs
    let res_dir = cmd_probe(None, Some(dir.path().to_path_buf()), true, "100ms".into())
        .await
        .expect("probe directory");
    assert_eq!(res_dir.len(), 2);
    assert_eq!(res_dir[0].id, "probe-tunnel-1");
    assert_eq!(res_dir[1].id, "probe-tunnel-2");

    // 3. Validation: specifying neither -c nor -d returns error
    let err_none = cmd_probe(None, None, true, "5s".into()).await;
    assert!(err_none.is_err());

    // 4. Validation: specifying both -c and -d returns error
    let err_both = cmd_probe(
        Some(conf1),
        Some(dir.path().to_path_buf()),
        true,
        "5s".into(),
    )
    .await;
    assert!(err_both.is_err());
}

// =============================================================================
// Test 6: Admin REST API & Prometheus Metrics Health Visibility
// =============================================================================

#[tokio::test]
async fn test_admin_api_health_visibility() {
    let mut config = MainConfig::default();
    config.per_tunnel.enabled = false;

    let tunnels = vec![
        make_test_tunnel_config("tun-ok-1", "198.51.100.1:51820"),
        make_test_tunnel_config("tun-ok-2", "198.51.100.2:51820"),
        make_test_tunnel_config("tun-fail", "198.51.100.3:51820"),
    ];
    let manager = Arc::new(TunnelManager::new(config, tunnels).expect("manager created"));

    // Mark tun-fail as Unhealthy
    let fail_entry = manager.registry().get("tun-fail").unwrap();
    fail_entry.health.mark_unhealthy(Duration::from_secs(60));

    // 1. Test GET /status payload
    let req_status = HttpRequest {
        method: "GET".to_string(),
        path: "/status".to_string(),
        query: None,
        headers: HashMap::new(),
        body: Vec::new(),
    };
    let resp = handle_admin_request(&req_status, &manager, None, 10).await;
    assert_eq!(resp.status, 200);

    let val: serde_json::Value = serde_json::from_slice(&resp.body).unwrap();
    assert_eq!(val["total_tunnels"], 3);
    assert_eq!(val["healthy_tunnels"], 0);
    assert_eq!(val["untested_tunnels"], 2);
    assert_eq!(val["unhealthy_tunnels"], 1);

    // 2. Test GET /tunnels includes health fields in TunnelSummary
    let req_tunnels = HttpRequest {
        method: "GET".to_string(),
        path: "/tunnels".to_string(),
        query: None,
        headers: HashMap::new(),
        body: Vec::new(),
    };
    let resp_tunnels = handle_admin_request(&req_tunnels, &manager, None, 10).await;
    assert_eq!(resp_tunnels.status, 200);
    let tunnels_json: Vec<serde_json::Value> = serde_json::from_slice(&resp_tunnels.body).unwrap();
    let tun_fail_json = tunnels_json.iter().find(|t| t["id"] == "tun-fail").unwrap();
    assert_eq!(tun_fail_json["health"], "unhealthy");
    assert!(tun_fail_json["cooldown_remaining_secs"].as_u64().unwrap() > 0);

    // 3. Test GET /metrics Prometheus exposition
    let req_metrics = HttpRequest {
        method: "GET".to_string(),
        path: "/metrics".to_string(),
        query: None,
        headers: HashMap::new(),
        body: Vec::new(),
    };
    let resp_metrics = handle_admin_request(&req_metrics, &manager, None, 10).await;
    assert_eq!(resp_metrics.status, 200);
    let metrics_text = String::from_utf8(resp_metrics.body).unwrap();

    assert!(metrics_text.contains("wpmulti_tunnels_healthy 0"));
    assert!(metrics_text.contains("wpmulti_tunnels_untested 2"));
    assert!(metrics_text.contains("wpmulti_tunnels_unhealthy 1"));
    assert!(metrics_text.contains("wpmulti_tunnel_health{tunnel_id=\"tun-ok-1\"} 0"));
    assert!(metrics_text.contains("wpmulti_tunnel_health{tunnel_id=\"tun-fail\"} 0"));
    assert!(metrics_text.contains("wpmulti_tunnel_consecutive_failures{tunnel_id=\"tun-fail\"}"));
    assert!(
        metrics_text.contains("wpmulti_tunnel_cooldown_remaining_seconds{tunnel_id=\"tun-fail\"}")
    );
}
