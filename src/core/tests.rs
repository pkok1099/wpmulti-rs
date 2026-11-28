//! Unit tests for Milestone 4: Multi-Tunnel Manager & Scalable Lifecycle.

use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use x25519_dalek::{PublicKey, StaticSecret};

use crate::config::{
    AuthMode, LifecycleMode, ListenerType, MainConfig, PerTunnelSettings, PoolStrategy,
    SharedListenerSettings, TunnelConfig, TunnelPoolSelection, TunnelPortOverride,
    WgInterfaceConfig, WgPeerConfig,
};
use crate::core::TunnelManager;
use crate::core::health::{HealthStatus, TunnelHealthTracker};
use crate::core::lifecycle::{LifecycleController, TunnelConnGuard};
use crate::core::listener::{ListenerSupervisor, MAX_CONNS_PER_SOURCE_IP, PerIpConnTracker};
use crate::core::registry::{TunnelEntry, TunnelRegistry, TunnelState, TunnelStats};
use crate::core::router::{
    DedicatedTunnelRouter, MAX_LIVE_TUNNEL_CONNS, MultiTenantRouter, preferred_entries,
};
use crate::core::selection::{
    WarmList, dormant_surcharge_ms, score_entry, slow_start_weight, tunnel_score,
};
use crate::core::warm_up_complement_ids;
use crate::proxy::{PoolKeyword, ProxyAuthError, TunnelRouter, TunnelSelector};

fn make_test_tunnel_config(id: &str) -> TunnelConfig {
    let iface = WgInterfaceConfig {
        private_key: StaticSecret::from([42u8; 32]),
        addresses: vec![
            "172.16.0.2/32".parse().unwrap(),
            "2606:4700:110:8751:5a4:5d1e:287e:46c4/128".parse().unwrap(),
        ],
        dns: vec!["1.1.1.1".parse().unwrap()],
        listen_port: None,
        mtu: 1420,
    };

    let peer = WgPeerConfig {
        public_key: PublicKey::from([99u8; 32]),
        endpoint: "127.0.0.1:51820".to_string(),
        allowed_ips: vec!["0.0.0.0/0".parse().unwrap(), "::/0".parse().unwrap()],
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
// 1. Multi-Tunnel Registry: 245+ Cloned Identical Configs Storage & Zero Collision
// =============================================================================

#[test]
fn test_registry_245_cloned_wgcf_no_collision() {
    let registry = TunnelRegistry::new();
    let total_clones = 250;

    // Simulate 250 identical wgcf configs from Cloudflare WARP with same keys and IPs,
    // each assigned a unique filename / tunnel_id.
    for i in 1..=total_clones {
        let id = format!("wgcf-{:03}", i);
        let config = make_test_tunnel_config(&id);
        let entry = TunnelEntry::new(id.clone(), config, LifecycleMode::Lazy);
        let registered = registry.register(entry);
        assert!(registered.is_ok(), "failed to register clone {}", id);
    }

    // Verify registry size and integrity
    assert_eq!(registry.count(), total_clones);
    assert_eq!(registry.active_count(), 0);

    // Verify lookup by ID
    let sample = registry.get("wgcf-100").expect("tunnel 100 must exist");
    assert_eq!(sample.id, "wgcf-100");
    assert_eq!(*sample.state.read(), TunnelState::Dormant);
    assert_eq!(sample.lifecycle_mode, LifecycleMode::Lazy);
    assert_eq!(sample.stats.active_conns.load(Ordering::Relaxed), 0);
    assert!(sample.active.read().is_none());

    // Verify lookup by sequential index
    let sample_idx = registry.get_by_index(99).expect("index 99 must exist");
    assert_eq!(sample_idx.id, "wgcf-100");

    // Verify duplicate registration rejection
    let dup_cfg = make_test_tunnel_config("wgcf-100");
    let dup_entry = TunnelEntry::new("wgcf-100", dup_cfg, LifecycleMode::Lazy);
    assert!(registry.register(dup_entry).is_err());

    // Verify summary stats generation for all 250 tunnels
    let summaries = registry.get_stats();
    assert_eq!(summaries.len(), total_clones);
    assert!(summaries.iter().all(|s| s.state == TunnelState::Dormant));
}

// =============================================================================
// 2. Lazy / On-Demand Lifecycle: Dormant -> Activate -> ConnGuard -> Suspend
// =============================================================================

#[tokio::test]
async fn test_lazy_activation_lifecycle_and_guard() {
    let registry = Arc::new(TunnelRegistry::new());
    let cfg = make_test_tunnel_config("wgcf-lazy-01");
    let entry = TunnelEntry::new("wgcf-lazy-01", cfg, LifecycleMode::Lazy);
    registry.register(entry).unwrap();

    let idle_timeout = Duration::from_millis(50);
    let check_interval = Duration::from_millis(10);
    let lifecycle = LifecycleController::new(Arc::clone(&registry), idle_timeout, check_interval);

    // Initial state is Dormant
    let initial_entry = registry.get("wgcf-lazy-01").unwrap();
    assert_eq!(*initial_entry.state.read(), TunnelState::Dormant);
    assert_eq!(registry.active_count(), 0);

    // Step 1: On-demand connection triggers get_or_activate
    let (active_tunnel, guard1) = lifecycle
        .get_or_activate("wgcf-lazy-01")
        .await
        .expect("activation should succeed");

    assert_eq!(active_tunnel.id, "wgcf-lazy-01");
    assert_eq!(*initial_entry.state.read(), TunnelState::Active);
    assert_eq!(registry.active_count(), 1);
    assert_eq!(initial_entry.stats.active_conns.load(Ordering::SeqCst), 1);
    assert_eq!(initial_entry.stats.total_conns.load(Ordering::Relaxed), 1);

    // Step 2: Second concurrent connection increments active conns
    let guard2 = TunnelConnGuard::new("wgcf-lazy-01", Arc::clone(&initial_entry.stats));
    assert_eq!(initial_entry.stats.active_conns.load(Ordering::SeqCst), 2);
    assert_eq!(initial_entry.stats.total_conns.load(Ordering::Relaxed), 2);

    // Step 3: Dropping guard2 decrements active conns to 1
    drop(guard2);
    assert_eq!(initial_entry.stats.active_conns.load(Ordering::SeqCst), 1);
    assert_eq!(*initial_entry.state.read(), TunnelState::Active);

    // Step 4: Dropping guard1 drops active conns to 0 and records last_active_at
    drop(guard1);
    assert_eq!(initial_entry.stats.active_conns.load(Ordering::SeqCst), 0);
    let last_active = initial_entry.stats.last_active_at.load(Ordering::Relaxed);
    assert!(last_active > 0);

    // Step 5: Suspend tunnel explicitly via lifecycle controller
    lifecycle.suspend_tunnel("wgcf-lazy-01").await.unwrap();
    assert_eq!(*initial_entry.state.read(), TunnelState::Suspended);
    assert_eq!(registry.active_count(), 0);

    // Step 6: Subsequent connection re-resumes the existing tunnel handle
    let (resumed_tunnel, guard3) = lifecycle
        .get_or_activate("wgcf-lazy-01")
        .await
        .expect("resume should succeed");

    assert_eq!(resumed_tunnel.id, "wgcf-lazy-01");
    assert_eq!(*initial_entry.state.read(), TunnelState::Active);
    assert_eq!(registry.active_count(), 1);
    assert_eq!(initial_entry.stats.active_conns.load(Ordering::SeqCst), 1);

    drop(guard3);
}

// =============================================================================
// 3. Eager Tunnel Activation: Always Active & Immunity from Idle Teardown
// =============================================================================

#[tokio::test]
async fn test_eager_tunnel_activation() {
    let mut config = MainConfig::default();
    config.lifecycle.mode = LifecycleMode::Lazy;
    config.lifecycle.eager_tunnels = vec!["wgcf-eager-01".to_string()];
    config.per_tunnel.enabled = false;
    config.shared_listeners.clear();

    let tunnels = vec![
        make_test_tunnel_config("wgcf-lazy-01"),
        make_test_tunnel_config("wgcf-eager-01"),
    ];

    let manager = TunnelManager::new(config, tunnels).unwrap();
    assert_eq!(manager.tunnel_count(), 2);
    assert_eq!(manager.active_tunnel_count(), 0);

    // Start manager
    manager.start().await.unwrap();

    // Verify eager tunnel was automatically booted — and the
    // warm-up complement tops the pool up to 8 tunnels, so with
    // only two registered the lazy tunnel is booted too (its
    // lifecycle mode stays Lazy: warmed at startup, not
    // reclassified).
    assert_eq!(manager.active_tunnel_count(), 2);
    let eager_entry = manager.registry().get("wgcf-eager-01").unwrap();
    assert_eq!(*eager_entry.state.read(), TunnelState::Active);
    assert_eq!(eager_entry.lifecycle_mode, LifecycleMode::Eager);

    // Verify lazy tunnel was warmed by the complement
    let lazy_entry = manager.registry().get("wgcf-lazy-01").unwrap();
    assert_eq!(*lazy_entry.state.read(), TunnelState::Active);
    assert_eq!(lazy_entry.lifecycle_mode, LifecycleMode::Lazy);

    // Stop manager cleanly
    manager.stop().await.unwrap();
    assert_eq!(manager.active_tunnel_count(), 0);
}

#[tokio::test]
async fn test_boot_warm_up_complement_tops_up_to_eight_tunnels() {
    let mut config = MainConfig::default();
    config.lifecycle.mode = LifecycleMode::Lazy;
    config.lifecycle.eager_tunnels = vec!["wgcf-eager-01".to_string()];
    config.per_tunnel.enabled = false;
    config.shared_listeners.clear();
    // Dead endpoints: keep the probe pass short; the boot assertions
    // do not depend on probe outcomes.
    config.health_check.probe_timeout = Duration::from_millis(100);

    let mut tunnels = vec![make_test_tunnel_config("wgcf-eager-01")];
    for i in 1..=10 {
        tunnels.push(make_test_tunnel_config(&format!("wgcf-lazy-{i:02}")));
    }

    let manager = TunnelManager::new(config, tunnels).unwrap();
    assert_eq!(manager.tunnel_count(), 11);
    manager.start().await.unwrap();

    // One eager + seven lowest-id lazy tunnels = 8 warm tunnels.
    assert_eq!(manager.active_tunnel_count(), 8);
    for i in 1..=7 {
        let id = format!("wgcf-lazy-{i:02}");
        assert_eq!(
            *manager.registry().get(&id).unwrap().state.read(),
            TunnelState::Active,
            "{id} must be warmed by the complement"
        );
    }
    // The remaining lazy tunnels stay dormant.
    for i in 8..=10 {
        let id = format!("wgcf-lazy-{i:02}");
        assert_eq!(
            *manager.registry().get(&id).unwrap().state.read(),
            TunnelState::Dormant,
            "{id} must stay dormant past the 8-tunnel warm-up target"
        );
    }

    manager.stop().await.unwrap();
    assert_eq!(manager.active_tunnel_count(), 0);
}

// =============================================================================
// 4. Multi-Tenant Shared Port Router: ById, ByKeyword, DefaultPool, & Auth
// =============================================================================

#[tokio::test]
async fn test_shared_port_router_auth_and_strategies() {
    let registry = Arc::new(TunnelRegistry::new());
    for i in 1..=3 {
        let id = format!("wgcf-tenant-{:02}", i);
        let cfg = make_test_tunnel_config(&id);
        registry
            .register(TunnelEntry::new(id, cfg, LifecycleMode::Lazy))
            .unwrap();
    }

    let idle_timeout = Duration::from_secs(60);
    let check_interval = Duration::from_secs(1);
    let lifecycle = LifecycleController::new(Arc::clone(&registry), idle_timeout, check_interval);

    let router = MultiTenantRouter::new(
        Arc::clone(&lifecycle),
        Arc::clone(&registry),
        PoolStrategy::RoundRobin,
        false, // anonymous access disallowed
    )
    .with_auth(AuthMode::Global, Some("secret123".to_string()));

    // Test 1: Unauthenticated request fails when anonymous is disallowed
    let auth_res = router.authenticate(None);
    assert_eq!(auth_res, Err(ProxyAuthError::AuthRequired));

    // Test 2: Invalid password fails
    let bad_pass = router.authenticate(Some(("wgcf-tenant-01", "wrong")));
    assert_eq!(bad_pass, Err(ProxyAuthError::InvalidCredentials));

    // Test 3: Valid credentials with tunnel ID username
    let ok_auth = router
        .authenticate(Some(("wgcf-tenant-01", "secret123")))
        .expect("auth should succeed");
    assert_eq!(ok_auth, TunnelSelector::ById("wgcf-tenant-01".to_string()));

    // Test 4: Select tunnel ById activates target
    let target = router
        .select_tunnel(&ok_auth, None)
        .await
        .expect("select tunnel should succeed");
    assert!(registry.get("wgcf-tenant-01").unwrap().is_active());

    // Test 5: Round-Robin Keyword cycling
    let sel_rr = TunnelSelector::ByKeyword(PoolKeyword::RoundRobin);
    for _ in 0..3 {
        let _ = router.select_tunnel(&sel_rr, None).await.unwrap();
    }
    // Verify all 3 tunnels in pool were activated across the round-robin cycle
    assert_eq!(registry.active_count(), 3);

    // Test 6: Least-Connection Strategy selection
    // Artificially increase connections on tenant-01 and tenant-02
    let t1 = registry.get("wgcf-tenant-01").unwrap();
    let t2 = registry.get("wgcf-tenant-02").unwrap();
    let t3 = registry.get("wgcf-tenant-03").unwrap();
    t1.stats.active_conns.store(10, Ordering::Relaxed);
    t2.stats.active_conns.store(5, Ordering::Relaxed);
    t3.stats.active_conns.store(0, Ordering::Relaxed);

    let sel_least = TunnelSelector::ByKeyword(PoolKeyword::LeastConn);
    let least_target = router.select_tunnel(&sel_least, None).await.unwrap();
    // Guard created on t3 increments it to 1
    assert_eq!(t3.stats.active_conns.load(Ordering::Relaxed), 1);

    drop(target);
    drop(least_target);
}

// =============================================================================
// 4b. Pre-resolve selection gate (run-3 #7)
// =============================================================================

fn make_test_router() -> (Arc<TunnelRegistry>, Arc<MultiTenantRouter>) {
    let registry = Arc::new(TunnelRegistry::new());
    let lifecycle = LifecycleController::new(
        Arc::clone(&registry),
        Duration::from_secs(60),
        Duration::from_secs(1),
    );
    let router = MultiTenantRouter::new(
        Arc::clone(&lifecycle),
        Arc::clone(&registry),
        PoolStrategy::RoundRobin,
        true, // anonymous access allowed
    );
    (registry, router)
}

/// Race trace (GPT round 12): the candidate-selection source names
/// the draw — explicit id, warm-list member vs random pool for P2C,
/// and the keyword strategies.
#[test]
fn test_selection_source_names_the_draw() {
    let (_registry, router) = make_test_router();

    assert_eq!(
        router.selection_source(&TunnelSelector::ById("wgcf-a".to_string()), "wgcf-a"),
        "by_id"
    );
    assert_eq!(
        router.selection_source(&TunnelSelector::ByTag("wgcf".to_string()), "wgcf-a"),
        "by_tag"
    );
    assert_eq!(
        router.selection_source(&TunnelSelector::ByKeyword(PoolKeyword::Random), "wgcf-a"),
        "random"
    );
    assert_eq!(
        router.selection_source(
            &TunnelSelector::ByKeyword(PoolKeyword::RoundRobin),
            "wgcf-a"
        ),
        "round_robin"
    );
    assert_eq!(
        router.selection_source(&TunnelSelector::ByKeyword(PoolKeyword::LeastConn), "wgcf-a"),
        "least_conn"
    );
    // The default pool is P2C here (the RoundRobin strategy routes
    // through it): a warm-list member reads warm_list, anything else
    // random_pool.
    assert_eq!(
        router.selection_source(&TunnelSelector::DefaultPool, "wgcf-a"),
        "random_pool"
    );
    router.note_warm_success("wgcf-a");
    assert_eq!(
        router.selection_source(&TunnelSelector::DefaultPool, "wgcf-a"),
        "warm_list"
    );
    assert_eq!(
        router.selection_source(&TunnelSelector::ByKeyword(PoolKeyword::Auto), "wgcf-a"),
        "warm_list"
    );
}

/// Race trace (GPT round 12): warm-list membership tracks success
/// and blackhole removal.
#[test]
fn test_warm_list_contains() {
    let warm = WarmList::new();
    assert!(!warm.contains("wgcf-a"));
    warm.note_success("wgcf-a");
    assert!(warm.contains("wgcf-a"));
    warm.note_failure("wgcf-a");
    assert!(!warm.contains("wgcf-a"));
}

/// Regression (audit run-3 #7,
/// `proxy.dns-pre-resolve-cross-tunnel-no-selector-binding`): the DNS
/// pre-resolve used to ask the router for any live tunnel with no
/// selector binding, so a domain query egressed via an unselected
/// tunnel — even for a client whose credentials the selected tunnel
/// rejects. `live_resolve_target` is deleted; the pre-resolve now runs
/// through `select_tunnel` first, so a rejected selection means no
/// DNS query anywhere. This test pins the gate the pre-resolve depends
/// on at the real router (two tunnels, only B live and warm, client
/// asking for A with wrong A credentials); the stub-level test in
/// `proxy::tests` proves the zero-query consequence.
#[tokio::test]
async fn test_preresolve_gate_rejects_wrong_credentials_before_dns() {
    use crate::proxy::router::{RouterConnectError, TargetAddr, connect_via_router};

    let registry = Arc::new(TunnelRegistry::new());
    for id in ["wgcf-a", "wgcf-b"] {
        registry
            .register(TunnelEntry::new(
                id,
                make_test_tunnel_config(id),
                LifecycleMode::Lazy,
            ))
            .unwrap();
    }
    let lifecycle = LifecycleController::new(
        Arc::clone(&registry),
        Duration::from_secs(60),
        Duration::from_secs(1),
    );
    let mut passwords = std::collections::HashMap::new();
    passwords.insert("wgcf-a".to_string(), "pw-a".to_string());
    passwords.insert("wgcf-b".to_string(), "pw-b".to_string());
    let router = MultiTenantRouter::new(
        Arc::clone(&lifecycle),
        Arc::clone(&registry),
        PoolStrategy::RoundRobin,
        false,
    )
    .with_auth(AuthMode::PerTunnel, None)
    .with_per_tunnel_passwords(passwords);

    // Only B is live and warm — the tunnel the old unbound pre-resolve
    // would have picked for any selector. Activate B and mark it Live.
    let _b_target = router
        .select_tunnel(
            &TunnelSelector::ById("wgcf-b".to_string()),
            Some(("wgcf-b", "pw-b")),
        )
        .await
        .expect("activating B must succeed");
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let b_entry = registry.get("wgcf-b").unwrap();
    b_entry.stats.record_handshake(now);
    b_entry.health.record_success();
    router.note_warm_success("wgcf-b");

    // Client asks for A with wrong A credentials: selection must fail
    // before any DNS is attempted, and A must never activate.
    let router_dyn: Arc<dyn TunnelRouter> = router;
    let err = connect_via_router(
        &router_dyn,
        &TunnelSelector::ById("wgcf-a".to_string()),
        &TargetAddr::Domain("victim.example.test".to_string(), 443),
        Some(("wgcf-a", "WRONG")),
        None,
    )
    .await
    .err()
    .expect("wrong credentials must fail the connect");
    let RouterConnectError::SelectTunnel(e) = err else {
        panic!("wrong credentials must fail at selection, got {err:?}");
    };
    assert_eq!(e.kind(), std::io::ErrorKind::PermissionDenied);
    assert!(
        !registry.get("wgcf-a").unwrap().is_active(),
        "rejected selection must not activate tunnel A"
    );
}

#[tokio::test]
async fn test_record_tunnel_blackhole_penalizes_tunnel() {
    let (registry, router) = make_test_router();
    let id = "wgcf-blackhole-01".to_string();
    registry
        .register(TunnelEntry::new(
            id.clone(),
            make_test_tunnel_config(&id),
            LifecycleMode::Lazy,
        ))
        .unwrap();
    let entry = registry.get(&id).unwrap();
    // A healthy tunnel with a known RTT baseline: the state a
    // blackhole report must change.
    entry.stats.record_rtt_sample(50);
    entry.health.record_success();
    router.note_warm_success(&id);

    router.record_tunnel_blackhole(&id);
    assert_eq!(
        entry.health.consecutive_failures(),
        1,
        "one blackhole is one breaker failure"
    );
    assert_eq!(
        entry.health.current_status(),
        HealthStatus::Healthy,
        "one blackhole must not eject a healthy tunnel"
    );
    // The EWMA penalty: the 10s failure sample joins the 50ms
    // baseline at alpha 0.2 — (10000 + 4*50) / 5 = 2040ms.
    assert_eq!(
        entry.stats.rtt_ewma_ms.load(Ordering::Relaxed),
        2040,
        "a blackhole must penalize the tunnel's EWMA score"
    );

    // Two more blackholes trip the breaker at the default threshold.
    router.record_tunnel_blackhole(&id);
    router.record_tunnel_blackhole(&id);
    assert_eq!(entry.health.consecutive_failures(), 3);
    assert_eq!(
        entry.health.current_status(),
        HealthStatus::Unhealthy,
        "three consecutive blackholes must eject the tunnel"
    );
}

// =============================================================================
// 5. Dedicated Per-Tunnel Listener Supervisor & Loopback Binding
// =============================================================================

#[tokio::test]
async fn test_dedicated_and_shared_listeners() {
    let registry = Arc::new(TunnelRegistry::new());
    let cfg1 = make_test_tunnel_config("wgcf-listen-01");
    let cfg2 = make_test_tunnel_config("wgcf-listen-02");
    registry
        .register(TunnelEntry::new(
            "wgcf-listen-01",
            cfg1,
            LifecycleMode::Lazy,
        ))
        .unwrap();
    registry
        .register(TunnelEntry::new(
            "wgcf-listen-02",
            cfg2,
            LifecycleMode::Lazy,
        ))
        .unwrap();

    let idle_timeout = Duration::from_secs(60);
    let check_interval = Duration::from_secs(1);
    let lifecycle = LifecycleController::new(Arc::clone(&registry), idle_timeout, check_interval);

    let supervisor = ListenerSupervisor::new();

    // Use loopback with ephemeral ports
    // Pick an available ephemeral port for tunnel 1
    let temp_listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port1 = temp_listener.local_addr().unwrap().port();
    drop(temp_listener);

    let mut overrides = std::collections::HashMap::new();
    overrides.insert(
        "wgcf-listen-01".to_string(),
        TunnelPortOverride {
            socks5_port: Some(port1),
            http_port: None,
            password: None,
        },
    );

    // PerTunnel dedicated configuration:
    let per_tunnel = PerTunnelSettings {
        enabled: true,
        base_socks5_port: Some(port1),
        base_http_port: None,
        overrides,
    };

    let started = supervisor
        .start_dedicated_listeners(
            &per_tunnel,
            None,
            "127.0.0.1".parse().unwrap(),
            &registry,
            &lifecycle,
        )
        .await
        .expect("dedicated listener should start");

    assert!(!started.is_empty());
    let active_info = &started[0];
    assert_eq!(active_info.listener_type, ListenerType::Socks5);
    assert_eq!(active_info.address.port(), port1);

    // Verify TCP connection succeeds to dedicated port
    let stream_res =
        tokio::net::TcpStream::connect(SocketAddr::new("127.0.0.1".parse().unwrap(), port1)).await;
    assert!(stream_res.is_ok(), "must connect to dedicated listener");

    // Clean shutdown
    supervisor.stop().await;
}

// =============================================================================
// 6. TunnelManager Reload: Add, Remove, and Update Detection
// =============================================================================

#[tokio::test]
async fn test_manager_reload_add_remove_update() {
    let mut config = MainConfig::default();
    config.per_tunnel.enabled = false;
    config.shared_listeners.clear();

    let initial_tunnels = vec![
        make_test_tunnel_config("wgcf-reload-01"),
        make_test_tunnel_config("wgcf-reload-02"),
    ];

    let manager = TunnelManager::new(config, initial_tunnels).unwrap();
    assert_eq!(manager.tunnel_count(), 2);

    // Prepare updated set:
    // - wgcf-reload-01 is removed
    // - wgcf-reload-02 has new private key (updated)
    // - wgcf-reload-03 is added (new)
    let mut updated_02 = make_test_tunnel_config("wgcf-reload-02");
    updated_02.interface.private_key = StaticSecret::from([77u8; 32]);
    let new_03 = make_test_tunnel_config("wgcf-reload-03");

    let report = manager
        .reload_with_tunnels(vec![updated_02, new_03])
        .await
        .expect("reload should succeed");

    assert_eq!(report.added, 1, "expected 1 added");
    assert_eq!(report.removed, 1, "expected 1 removed");
    assert_eq!(report.updated, 1, "expected 1 updated");
    assert_eq!(report.total, 2, "expected 2 total");

    assert!(manager.registry().get("wgcf-reload-01").is_none());
    assert!(manager.registry().get("wgcf-reload-02").is_some());
    assert!(manager.registry().get("wgcf-reload-03").is_some());
}

#[tokio::test]
async fn test_concurrent_reloads_apply_exactly_one_set() {
    // Serialization (audit run-1,
    // `core/reload-with-tunnels-unserialized-concurrent-reload`): two
    // reloads racing must leave exactly one caller's set, never the
    // union of both. Repeated with fresh managers: the interleave is
    // timing-dependent, but the invariant must hold on every run.
    for _ in 0..5 {
        let mut config = MainConfig::default();
        config.per_tunnel.enabled = false;
        config.shared_listeners.clear();
        let manager = TunnelManager::new(config, vec![make_test_tunnel_config("wgcf-a")]).unwrap();

        let (r1, r2) = tokio::join!(
            manager.reload_with_tunnels(vec![make_test_tunnel_config("wgcf-a")]),
            manager.reload_with_tunnels(vec![make_test_tunnel_config("wgcf-b")]),
        );
        r1.expect("reload A should succeed");
        r2.expect("reload B should succeed");
        let ids = manager.registry().all_ids();
        assert!(
            ids == vec!["wgcf-a".to_string()] || ids == vec!["wgcf-b".to_string()],
            "concurrent reloads must leave exactly one caller's set, got: {ids:?}"
        );
    }
}

#[tokio::test]
async fn test_concurrent_reloads_adding_same_tunnel_do_not_duplicate() {
    // Two reloads adding the same new tunnel must not fail with
    // DuplicateTunnel mid-apply (audit run-1,
    // `core/reload-with-tunnels-unserialized-concurrent-reload`).
    let mut config = MainConfig::default();
    config.per_tunnel.enabled = false;
    config.shared_listeners.clear();
    let manager = TunnelManager::new(config, Vec::new()).unwrap();

    let (r1, r2) = tokio::join!(
        manager.reload_with_tunnels(vec![make_test_tunnel_config("wgcf-x")]),
        manager.reload_with_tunnels(vec![make_test_tunnel_config("wgcf-x")]),
    );
    r1.expect("first reload adding X should succeed");
    r2.expect("second reload adding X should succeed");
    assert_eq!(manager.tunnel_count(), 1);
    assert!(manager.registry().get("wgcf-x").is_some());
}

#[tokio::test]
async fn test_set_tunnels_disabled_and_post_config_do_not_lose_updates() {
    // Serialization (audit run-1,
    // `src/core/mod.rs:set_tunnels_disabled:lost-update-vs-post-config`,
    // `src/api/routes.rs:post-config-concurrent-stale-snapshot-resurrection`):
    // a disable racing a config apply must not be silently lost, and
    // the registry, the live config, and the on-disk file must agree
    // afterwards — whichever writer wins, all three follow it.
    let temp_dir = tempfile::tempdir().expect("tempdir");
    let toml_path = temp_dir.path().join("wpmulti.toml");
    std::fs::write(&toml_path, "[global]\n").expect("write toml");
    let mut config = MainConfig::default();
    config.per_tunnel.enabled = false;
    config.shared_listeners.clear();
    let manager = TunnelManager::new(config, vec![make_test_tunnel_config("wgcf-001")]).unwrap();
    manager.set_config_path(toml_path.clone());

    let mut new_cfg = manager.config_snapshot();
    new_cfg.global.max_active_tunnels = 7;
    let (disable_res, apply_res) = tokio::join!(
        manager.set_tunnels_disabled("wgcf-001", true),
        manager.save_and_apply_runtime_config(new_cfg),
    );
    disable_res.expect("disable should succeed");
    apply_res.expect("config apply should succeed");

    let entry_disabled = manager
        .registry()
        .get("wgcf-001")
        .expect("tunnel present")
        .is_disabled();
    let cfg_disabled = manager
        .config_snapshot()
        .disabled_tunnels
        .contains(&"wgcf-001".to_string());
    let on_disk = MainConfig::from_file(&toml_path).expect("read persisted toml");
    let disk_disabled = on_disk.disabled_tunnels.contains(&"wgcf-001".to_string());
    assert_eq!(
        entry_disabled, cfg_disabled,
        "registry flag and live config disagree after concurrent disable/apply"
    );
    assert_eq!(
        entry_disabled, disk_disabled,
        "live config and on-disk config disagree after concurrent disable/apply"
    );
}

#[tokio::test]
async fn test_set_tunnels_disabled_reports_persist_failure() {
    // Fail closed (audit run-1,
    // `src/core/mod.rs:set_tunnels_disabled:persist-failure-swallowed`):
    // a disable whose write to disk fails must return Err, not Ok with
    // a success the next restart silently undoes.
    let temp_dir = tempfile::tempdir().expect("tempdir");
    let mut config = MainConfig::default();
    config.per_tunnel.enabled = false;
    config.shared_listeners.clear();
    let manager = TunnelManager::new(config, vec![make_test_tunnel_config("wgcf-001")]).unwrap();
    manager.set_config_path(temp_dir.path().join("missing-dir").join("wpmulti.toml"));

    let res = manager.set_tunnels_disabled("wgcf-001", true).await;
    assert!(
        res.is_err(),
        "persist failure must be reported, got: {res:?}"
    );
}

#[test]
fn test_resolve_tunnel_targets_literal_id_wins_over_syntax() {
    // Audit run-1,
    // `src/core/mod.rs:resolve_tunnel_token:literal-id-shadowed`: a
    // tunnel literally named `2`, `1-2`, `all`, or `a,b` is selected
    // by identity, never reinterpreted as an index, a range, `all`,
    // or split at the comma.
    let ids = ["1", "2", "10", "1-2", "all", "a,b", "wgcf-001"];
    let tunnels: Vec<TunnelConfig> = ids.iter().map(|id| make_test_tunnel_config(id)).collect();
    let manager = TunnelManager::new(MainConfig::default(), tunnels).unwrap();
    assert_eq!(
        manager.resolve_tunnel_targets("2").unwrap(),
        vec!["2".to_string()]
    );
    assert_eq!(
        manager.resolve_tunnel_targets("1-2").unwrap(),
        vec!["1-2".to_string()]
    );
    assert_eq!(
        manager.resolve_tunnel_targets("all").unwrap(),
        vec!["all".to_string()]
    );
    assert_eq!(
        manager.resolve_tunnel_targets("a,b").unwrap(),
        vec!["a,b".to_string()]
    );
}

#[test]
fn test_resolve_tunnel_targets_syntax_and_out_of_range_errors() {
    // Selector syntax still works when no literal collides, and an
    // out-of-range index or range errors like `select_id_index`
    // (audit run-1, `src/core/mod.rs:select_id_range:silent-truncation`).
    let ids = ["wgcf-001", "wgcf-002", "wgcf-003"];
    let tunnels: Vec<TunnelConfig> = ids.iter().map(|id| make_test_tunnel_config(id)).collect();
    let manager = TunnelManager::new(MainConfig::default(), tunnels).unwrap();
    assert_eq!(
        manager.resolve_tunnel_targets("1").unwrap(),
        vec!["wgcf-001".to_string()]
    );
    assert_eq!(
        manager.resolve_tunnel_targets("1-2").unwrap(),
        vec!["wgcf-001".to_string(), "wgcf-002".to_string()]
    );
    assert_eq!(manager.resolve_tunnel_targets("all").unwrap().len(), 3);
    assert_eq!(manager.resolve_tunnel_targets("*").unwrap().len(), 3);
    assert!(
        manager.resolve_tunnel_targets("5").is_err(),
        "index past the registry must error"
    );
    assert!(
        manager.resolve_tunnel_targets("2-9").is_err(),
        "range with end past the registry must error, not clamp"
    );
    assert!(
        manager.resolve_tunnel_targets("9-10").is_err(),
        "range starting past the registry must error, not return empty"
    );
    assert!(
        manager.resolve_tunnel_targets("3-2").is_err(),
        "reversed range must error"
    );
    assert!(
        manager.resolve_tunnel_targets("nope").is_err(),
        "unknown literal must error"
    );
}

#[tokio::test]
async fn test_apply_runtime_config_reconciles_dedicated_listeners_on_enabled_flip() {
    // A `per_tunnel.enabled` flip must start/stop the dedicated
    // listeners, not just change what `GET /config` reports (audit
    // run-1, `core/apply-runtime-config:per-tunnel-enabled-no-listener-reconcile`).
    // Stopping must also clear the assigned port.
    let temp_listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind ephemeral");
    let port = temp_listener.local_addr().expect("local addr").port();
    drop(temp_listener);

    let mut config = MainConfig::default();
    config.shared_listeners.clear();
    config.per_tunnel.enabled = true;
    config.per_tunnel.base_socks5_port = Some(port);
    config.per_tunnel.base_http_port = None;
    let manager = TunnelManager::new(config, vec![make_test_tunnel_config("wgcf-flip")]).unwrap();
    manager.start().await.expect("start manager");
    assert!(
        manager
            .listeners()
            .list_listeners()
            .iter()
            .any(|l| !l.is_shared && l.tunnel_id.as_deref() == Some("wgcf-flip")),
        "dedicated listener must exist while enabled"
    );
    assert_eq!(
        *manager
            .registry()
            .get("wgcf-flip")
            .expect("tunnel present")
            .assigned_port
            .read(),
        Some(port)
    );

    let mut new_cfg = manager.config_snapshot();
    new_cfg.per_tunnel.enabled = false;
    manager
        .apply_runtime_config(new_cfg)
        .await
        .expect("apply disabled");
    assert!(
        manager
            .listeners()
            .list_listeners()
            .iter()
            .all(|l| l.is_shared),
        "no dedicated listener may survive the flip to disabled"
    );
    assert_eq!(
        *manager
            .registry()
            .get("wgcf-flip")
            .expect("tunnel present")
            .assigned_port
            .read(),
        None,
        "stopping a dedicated listener must clear its assigned port"
    );

    let mut new_cfg = manager.config_snapshot();
    new_cfg.per_tunnel.enabled = true;
    manager
        .apply_runtime_config(new_cfg)
        .await
        .expect("apply enabled");
    assert!(
        manager
            .listeners()
            .list_listeners()
            .iter()
            .any(|l| !l.is_shared && l.tunnel_id.as_deref() == Some("wgcf-flip")),
        "dedicated listener must come back on the flip to enabled"
    );

    manager.stop().await.expect("stop manager");
}

#[tokio::test]
async fn test_apply_runtime_config_restarts_shared_listener_on_bind_change() {
    // A rotated bind address (same restart path as a rotated proxy
    // password: both are captured at listener start) must move the
    // live socket — the old port stops accepting and the new one
    // starts (audit run-1,
    // `core/listener:stale-proxy-credentials-after-config-rotation`).
    let temp_listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind ephemeral");
    let port_old = temp_listener.local_addr().expect("local addr").port();
    drop(temp_listener);
    let temp_listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind ephemeral");
    let port_new = temp_listener.local_addr().expect("local addr").port();
    drop(temp_listener);
    assert_ne!(port_old, port_new);

    let mut config = MainConfig::default();
    config.per_tunnel.enabled = false;
    config.shared_listeners = vec![SharedListenerSettings {
        name: "s5".to_string(),
        listener_type: ListenerType::Socks5,
        bind: SocketAddr::new("127.0.0.1".parse().expect("loopback"), port_old),
        auth_mode: AuthMode::None,
        global_password: None,
        default_strategy: PoolStrategy::RoundRobin,
        allow_anonymous: true,
        pool: TunnelPoolSelection::All,
        ip_mode: None,
    }];
    let manager = TunnelManager::new(config, vec![make_test_tunnel_config("wgcf-bind")]).unwrap();
    manager.start().await.expect("start manager");
    assert!(
        tokio::net::TcpStream::connect(SocketAddr::new(
            "127.0.0.1".parse().expect("loopback"),
            port_old
        ))
        .await
        .is_ok(),
        "old shared listener must accept before rotation"
    );

    let mut new_cfg = manager.config_snapshot();
    new_cfg.shared_listeners[0].bind =
        SocketAddr::new("127.0.0.1".parse().expect("loopback"), port_new);
    manager
        .apply_runtime_config(new_cfg)
        .await
        .expect("apply bind change");
    assert!(
        manager
            .listeners()
            .list_listeners()
            .iter()
            .any(|l| l.is_shared && l.address.port() == port_new),
        "new shared listener must be listed after rotation"
    );
    assert!(
        tokio::net::TcpStream::connect(SocketAddr::new(
            "127.0.0.1".parse().expect("loopback"),
            port_new
        ))
        .await
        .is_ok(),
        "new shared listener must accept after rotation"
    );
    assert!(
        tokio::net::TcpStream::connect(SocketAddr::new(
            "127.0.0.1".parse().expect("loopback"),
            port_old
        ))
        .await
        .is_err(),
        "old shared listener must stop accepting after rotation"
    );

    manager.stop().await.expect("stop manager");
}

// =============================================================================
// 7. Metered Stream and Traffic Statistics Verification
// =============================================================================

#[tokio::test]
async fn test_metered_traffic_counters() {
    let registry = Arc::new(TunnelRegistry::new());
    let cfg = make_test_tunnel_config("wgcf-metered-01");
    let entry = registry
        .register(TunnelEntry::new(
            "wgcf-metered-01",
            cfg,
            LifecycleMode::Lazy,
        ))
        .unwrap();

    let (mut client_stream, server_stream) = tokio::io::duplex(4096);
    let metered = crate::core::registry::MeteredStream {
        inner: Box::new(server_stream),
        stats: Arc::clone(&entry.stats),
    };

    let mut metered = Box::pin(metered);

    // Write from client to metered stream -> increments rx
    client_stream.write_all(b"hello world").await.unwrap();
    client_stream.flush().await.unwrap();

    let mut buf = [0u8; 11];
    metered.read_exact(&mut buf).await.unwrap();
    assert_eq!(&buf, b"hello world");
    assert_eq!(entry.stats.rx_bytes.load(Ordering::Relaxed), 11);

    // Write from metered stream to client -> increments tx
    metered.write_all(b"reply data").await.unwrap();
    metered.flush().await.unwrap();
    assert_eq!(entry.stats.tx_bytes.load(Ordering::Relaxed), 10);
}

// =============================================================================
// 8. Regression: Idle Teardown Race Aborts When Active Conns Non-zero
// =============================================================================

#[tokio::test]
async fn test_idle_teardown_race_aborts_when_active_conns_nonzero() {
    let registry = Arc::new(TunnelRegistry::new());
    let cfg = make_test_tunnel_config("wgcf-race-01");
    let entry = registry
        .register(TunnelEntry::new("wgcf-race-01", cfg, LifecycleMode::Lazy))
        .unwrap();

    let lifecycle = LifecycleController::new(
        Arc::clone(&registry),
        Duration::from_millis(50),
        Duration::from_millis(10),
    );

    // Activate tunnel and hold guard (active_conns == 1)
    let (_active, guard) = lifecycle
        .get_or_activate("wgcf-race-01")
        .await
        .expect("activation should succeed");

    assert_eq!(*entry.state.read(), TunnelState::Active);
    assert_eq!(entry.stats.active_conns.load(Ordering::SeqCst), 1);

    // Attempt to suspend while active_conns > 0
    let suspend_res = lifecycle.suspend_tunnel("wgcf-race-01").await;
    assert!(suspend_res.is_ok());

    // Suspension MUST be aborted; tunnel MUST remain Active
    assert_eq!(
        *entry.state.read(),
        TunnelState::Active,
        "tunnel with active connections must not be suspended"
    );

    // Drop connection guard -> active_conns becomes 0
    drop(guard);
    assert_eq!(entry.stats.active_conns.load(Ordering::SeqCst), 0);

    // Now suspension should succeed
    lifecycle
        .suspend_tunnel("wgcf-race-01")
        .await
        .expect("suspension should succeed when idle");
    assert_eq!(*entry.state.read(), TunnelState::Suspended);
}

// =============================================================================
// 9. Regression: Manual Activation Does Not Prematurely Suspend
// =============================================================================

#[tokio::test]
async fn test_manual_activation_does_not_prematurely_suspend() {
    let registry = Arc::new(TunnelRegistry::new());
    let cfg = make_test_tunnel_config("wgcf-manual-01");
    let entry = registry
        .register(TunnelEntry::new("wgcf-manual-01", cfg, LifecycleMode::Lazy))
        .unwrap();

    // 300-second idle timeout
    let idle_timeout = Duration::from_secs(300);
    let check_interval = Duration::from_millis(10);
    let lifecycle = LifecycleController::new(Arc::clone(&registry), idle_timeout, check_interval);

    // Manually activate lazy tunnel without a connection guard
    let _active = lifecycle
        .activate_tunnel("wgcf-manual-01")
        .await
        .expect("manual activation should succeed");

    assert_eq!(*entry.state.read(), TunnelState::Active);
    let last_active = entry.stats.last_active_at.load(Ordering::Relaxed);
    assert!(
        last_active > 0,
        "last_active_at must be stamped on manual activation"
    );

    // Run idle check immediately; it must not suspend because idle_timeout (300s) has not elapsed
    lifecycle.check_idle_tunnels().await;
    assert_eq!(
        *entry.state.read(),
        TunnelState::Active,
        "tunnel must not be prematurely suspended immediately after activation"
    );
}

// =============================================================================
// 9b. Idle Teardown Closes Long-Suspended Tunnels (fix7: peak RAM)
// =============================================================================

/// Build a lazy tunnel, activate it, then suspend it; returns the entry
/// with `active` still held so the test can assert the close drops it.
async fn suspended_tunnel_fixture(
    registry: &Arc<TunnelRegistry>,
    lifecycle: &LifecycleController,
    id: &str,
) -> Arc<TunnelEntry> {
    let cfg = make_test_tunnel_config(id);
    let entry = registry
        .register(TunnelEntry::new(id, cfg, LifecycleMode::Lazy))
        .unwrap();
    let (_active, guard) = lifecycle
        .get_or_activate(id)
        .await
        .expect("activation should succeed");
    drop(guard);
    lifecycle
        .suspend_tunnel(id)
        .await
        .expect("suspension should succeed");
    assert_eq!(*entry.state.read(), TunnelState::Suspended);
    assert!(
        entry.active.read().is_some(),
        "suspended tunnel must still hold its stack"
    );
    entry
}

fn unix_now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

#[tokio::test]
async fn test_idle_teardown_closes_long_suspended_tunnel() {
    let registry = Arc::new(TunnelRegistry::new());
    // 300s idle timeout -> close threshold max(2 * 300, 300) = 600s.
    let idle_timeout = Duration::from_secs(300);
    let check_interval = Duration::from_millis(10);
    let lifecycle = LifecycleController::new(Arc::clone(&registry), idle_timeout, check_interval);

    let entry = suspended_tunnel_fixture(&registry, &lifecycle, "wgcf-close-01").await;

    // Fake 601s of idleness, past the 600s close threshold.
    let now = unix_now_secs();
    entry
        .stats
        .last_active_at
        .store(now.saturating_sub(601), Ordering::Relaxed);

    lifecycle.check_idle_tunnels().await;
    assert_eq!(
        *entry.state.read(),
        TunnelState::Dormant,
        "suspended tunnel idle past the close threshold must be closed"
    );
    assert!(
        entry.active.read().is_none(),
        "closed tunnel must drop its stack"
    );
}

#[tokio::test]
async fn test_idle_teardown_keeps_recently_suspended_tunnel() {
    let registry = Arc::new(TunnelRegistry::new());
    let idle_timeout = Duration::from_secs(300);
    let check_interval = Duration::from_millis(10);
    let lifecycle = LifecycleController::new(Arc::clone(&registry), idle_timeout, check_interval);

    let entry = suspended_tunnel_fixture(&registry, &lifecycle, "wgcf-close-02").await;

    // 60s idle: inside the P2C warm window (120s) and far below the
    // 600s close threshold — the stack must be kept for a cheap resume.
    let now = unix_now_secs();
    entry
        .stats
        .last_active_at
        .store(now.saturating_sub(60), Ordering::Relaxed);

    lifecycle.check_idle_tunnels().await;
    assert_eq!(
        *entry.state.read(),
        TunnelState::Suspended,
        "recently suspended tunnel must be kept, not closed"
    );
    assert!(
        entry.active.read().is_some(),
        "kept tunnel must still hold its stack"
    );
}

#[tokio::test]
async fn test_idle_teardown_close_threshold_is_twice_idle_timeout() {
    let registry = Arc::new(TunnelRegistry::new());
    // 400s idle timeout -> close threshold max(2 * 400, 300) = 800s.
    let idle_timeout = Duration::from_secs(400);
    let check_interval = Duration::from_millis(10);
    let lifecycle = LifecycleController::new(Arc::clone(&registry), idle_timeout, check_interval);

    let entry = suspended_tunnel_fixture(&registry, &lifecycle, "wgcf-close-03").await;

    // 500s idle: past the suspend timeout but below the 800s close
    // threshold — still suspended.
    let now = unix_now_secs();
    entry
        .stats
        .last_active_at
        .store(now.saturating_sub(500), Ordering::Relaxed);
    lifecycle.check_idle_tunnels().await;
    assert_eq!(*entry.state.read(), TunnelState::Suspended);

    // 801s idle: past the threshold — closed.
    entry
        .stats
        .last_active_at
        .store(now.saturating_sub(801), Ordering::Relaxed);
    lifecycle.check_idle_tunnels().await;
    assert_eq!(
        *entry.state.read(),
        TunnelState::Dormant,
        "suspended tunnel idle past 2x idle_timeout must be closed"
    );
    assert!(entry.active.read().is_none());
}

// =============================================================================
// 10. Regression: Multi-Tenant Pool Isolation Rejects Unallowed ById
// =============================================================================

#[tokio::test]
async fn test_pool_isolation_rejects_unallowed_by_id() {
    let registry = Arc::new(TunnelRegistry::new());
    let cfg_a = make_test_tunnel_config("wgcf-pool-allowed");
    let cfg_b = make_test_tunnel_config("wgcf-pool-forbidden");
    registry
        .register(TunnelEntry::new(
            "wgcf-pool-allowed",
            cfg_a,
            LifecycleMode::Lazy,
        ))
        .unwrap();
    registry
        .register(TunnelEntry::new(
            "wgcf-pool-forbidden",
            cfg_b,
            LifecycleMode::Lazy,
        ))
        .unwrap();

    let lifecycle = LifecycleController::new(
        Arc::clone(&registry),
        Duration::from_secs(60),
        Duration::from_secs(1),
    );

    let router = MultiTenantRouter::new(
        Arc::clone(&lifecycle),
        Arc::clone(&registry),
        PoolStrategy::RoundRobin,
        true,
    );

    // Restrict pool to only allow wgcf-pool-allowed
    router.set_allowed_tunnels(Some(vec!["wgcf-pool-allowed".to_string()]));

    // Attempt to select wgcf-pool-forbidden ById: must be rejected with NotFound
    let selector_forbidden = TunnelSelector::ById("wgcf-pool-forbidden".to_string());
    let res = router.select_tunnel(&selector_forbidden, None).await;
    let Err(err) = res else {
        panic!("selecting unallowed tunnel ById must fail");
    };
    assert_eq!(err.kind(), std::io::ErrorKind::NotFound);
    assert!(
        err.to_string().contains("not allowed in this pool"),
        "error must indicate tunnel not allowed in pool: {}",
        err
    );

    // Selecting allowed tunnel ById must succeed
    let selector_allowed = TunnelSelector::ById("wgcf-pool-allowed".to_string());
    let res_allowed = router.select_tunnel(&selector_allowed, None).await;
    assert!(
        res_allowed.is_ok(),
        "selecting allowed tunnel ById must succeed"
    );
}

#[tokio::test]
async fn test_selector_error_escapes_newlines_for_log_safety() {
    // Audit run-1,
    // `proxy.log-injection.unescaped-selector-error-to-stderr-tracing`:
    // a selector carrying `\n`/`\r` must not smuggle a forged log line
    // into the error Display string the proxy handler logs.
    use crate::core::router::escape_log_value;
    assert_eq!(escape_log_value("a\nb\rc"), "a\\nb\\rc");
    assert_eq!(escape_log_value("plain-id"), "plain-id");
    assert_eq!(escape_log_value("a\x07b"), "a\\u{7}b");

    let registry = Arc::new(TunnelRegistry::new());
    registry
        .register(TunnelEntry::new(
            "wgcf-001",
            make_test_tunnel_config("wgcf-001"),
            LifecycleMode::Lazy,
        ))
        .unwrap();
    let lifecycle = LifecycleController::new(
        Arc::clone(&registry),
        Duration::from_secs(60),
        Duration::from_secs(1),
    );
    let router = MultiTenantRouter::new(
        Arc::clone(&lifecycle),
        Arc::clone(&registry),
        PoolStrategy::RoundRobin,
        true,
    );
    let selector = TunnelSelector::ById("nope\nFAKE-WARN forged line".to_string());
    let Err(err) = router.select_tunnel(&selector, None).await else {
        panic!("unknown tunnel id must fail");
    };
    let text = err.to_string();
    assert!(
        !text.contains('\n') && !text.contains('\r'),
        "error must contain no raw newline: {text:?}"
    );
    assert!(
        text.contains("nope\\nFAKE-WARN forged line"),
        "newline must be escaped, got: {text:?}"
    );
    let tag_selector = TunnelSelector::ByTag("x\rOVERWRITE".to_string());
    let Err(tag_err) = router.select_tunnel(&tag_selector, None).await else {
        panic!("unknown tag must fail");
    };
    assert!(
        !tag_err.to_string().contains('\r'),
        "tag error must contain no raw CR: {:?}",
        tag_err.to_string()
    );
}

// =============================================================================
// 11. Regression: Reload Applies New Tunnel Config
// =============================================================================

#[tokio::test]
async fn test_reload_applies_new_tunnel_config() {
    let mut config = MainConfig::default();
    config.per_tunnel.enabled = false;
    config.shared_listeners.clear();

    let initial = make_test_tunnel_config("wgcf-reload-hot");
    let manager = TunnelManager::new(config, vec![initial]).unwrap();

    // Activate initial tunnel
    manager.activate_tunnel("wgcf-reload-hot").await.unwrap();
    let initial_entry = manager.registry().get("wgcf-reload-hot").unwrap();
    assert_eq!(*initial_entry.state.read(), TunnelState::Active);
    assert_eq!(
        initial_entry.config.read().interface.private_key.to_bytes(),
        [42u8; 32]
    );

    // Prepare updated configuration with a new private key and updated peer endpoint
    let mut updated = make_test_tunnel_config("wgcf-reload-hot");
    let new_key = [88u8; 32];
    updated.interface.private_key = StaticSecret::from(new_key);
    updated.peers[0].endpoint = "127.0.0.1:51829".to_string();

    let report = manager
        .reload_with_tunnels(vec![updated])
        .await
        .expect("reload should succeed");
    assert_eq!(report.updated, 1);

    // Verify registry entry has the new configuration
    let reloaded_entry = manager
        .registry()
        .get("wgcf-reload-hot")
        .expect("entry must exist in registry");
    assert_eq!(
        reloaded_entry
            .config
            .read()
            .interface
            .private_key
            .to_bytes(),
        new_key,
        "reloaded entry must store new private key"
    );
    assert_eq!(
        reloaded_entry.config.read().peers[0].endpoint,
        "127.0.0.1:51829",
        "reloaded entry must store new peer endpoint"
    );

    // Re-activate tunnel and verify it boots with the updated configuration
    let active = manager
        .activate_tunnel("wgcf-reload-hot")
        .await
        .expect("re-activation should succeed");
    assert_eq!(active.id, "wgcf-reload-hot");
    assert_eq!(*reloaded_entry.state.read(), TunnelState::Active);
}

// =============================================================================
// 12. Regression: Assigned Port Reflected in Tunnel Summary
// =============================================================================

#[tokio::test]
async fn test_assigned_port_reflected_in_summary() {
    let registry = Arc::new(TunnelRegistry::new());
    let cfg = make_test_tunnel_config("wgcf-port-reflect-01");
    let entry = registry
        .register(TunnelEntry::new(
            "wgcf-port-reflect-01",
            cfg,
            LifecycleMode::Lazy,
        ))
        .unwrap();

    // Initially assigned_port is None
    assert_eq!(entry.summary().assigned_port, None);

    let lifecycle = LifecycleController::new(
        Arc::clone(&registry),
        Duration::from_secs(60),
        Duration::from_secs(1),
    );
    let supervisor = ListenerSupervisor::new();

    // Bind ephemeral port for test
    let temp = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = temp.local_addr().unwrap().port();
    drop(temp);

    let per_tunnel = PerTunnelSettings {
        enabled: true,
        base_socks5_port: Some(port),
        ..Default::default()
    };

    supervisor
        .start_dedicated_listeners(
            &per_tunnel,
            None,
            "127.0.0.1".parse().unwrap(),
            &registry,
            &lifecycle,
        )
        .await
        .expect("dedicated listener start must succeed");

    // Verify assigned_port is updated on entry and reflected in summary
    assert_eq!(entry.summary().assigned_port, Some(port));

    // Verify registry.get_stats() also reflects the assigned port
    let summaries = registry.get_stats();
    let target_summary = summaries
        .iter()
        .find(|s| s.id == "wgcf-port-reflect-01")
        .expect("summary must exist");
    assert_eq!(target_summary.assigned_port, Some(port));

    supervisor.stop().await;
}

#[test]
fn test_active_conns_underflow_protection() {
    let stats = TunnelStats::default();
    assert_eq!(stats.active_conns.load(Ordering::SeqCst), 0);

    // Decrementing when already 0 must NOT underflow to usize::MAX
    stats.dec_conns();
    assert_eq!(stats.active_conns.load(Ordering::SeqCst), 0);
    stats.dec_conns();
    assert_eq!(stats.active_conns.load(Ordering::SeqCst), 0);

    // Normal increment and decrement
    stats.inc_conns();
    assert_eq!(stats.active_conns.load(Ordering::SeqCst), 1);
    stats.dec_conns();
    assert_eq!(stats.active_conns.load(Ordering::SeqCst), 0);
}

#[test]
fn test_registry_indexing_and_least_conn() {
    let registry = TunnelRegistry::new();
    let e1 = TunnelEntry::new("t1", make_test_tunnel_config("t1"), LifecycleMode::Lazy);
    let e2 = TunnelEntry::new("t2", make_test_tunnel_config("t2"), LifecycleMode::Lazy);
    e1.stats.active_conns.store(5, Ordering::Relaxed);
    e2.stats.active_conns.store(2, Ordering::Relaxed);
    registry.register(e1).unwrap();
    registry.register(e2).unwrap();

    assert_eq!(registry.id_by_index(0), Some("t1".to_string()));
    assert_eq!(registry.id_by_index(1), Some("t2".to_string()));
    assert_eq!(registry.id_by_index(2), None);

    assert_eq!(registry.least_conn_id(), Some("t2".to_string()));
}

#[tokio::test]
async fn test_reload_detects_peer_endpoint_change() {
    let mut initial_cfg = make_test_tunnel_config("tun-reload-diff");
    let manager = TunnelManager::new(MainConfig::default(), vec![initial_cfg.clone()]).unwrap();

    // Modify peer endpoint IP without changing peer count or keys
    initial_cfg.peers[0].endpoint = "203.0.113.50:51820".to_string();
    let report = manager
        .reload_with_tunnels(vec![initial_cfg.clone()])
        .await
        .unwrap();
    assert_eq!(report.updated, 1);
    assert_eq!(report.added, 0);
    assert_eq!(report.removed, 0);

    let current = manager.registry().get("tun-reload-diff").unwrap();
    assert_eq!(
        current.config.read().peers[0].endpoint,
        "203.0.113.50:51820"
    );
}

#[tokio::test]
async fn test_guarded_udp_socket_preserves_active_conns() {
    use crate::proxy::ProxyTunnelTarget;

    let registry = Arc::new(TunnelRegistry::new());
    let cfg = make_test_tunnel_config("tun-udp-guard");
    let entry = registry
        .register(TunnelEntry::new("tun-udp-guard", cfg, LifecycleMode::Lazy))
        .unwrap();

    let lifecycle = LifecycleController::new(
        Arc::clone(&registry),
        Duration::from_secs(60),
        Duration::from_secs(1),
    );
    let (target, guard) = lifecycle.get_or_activate("tun-udp-guard").await.unwrap();
    assert_eq!(entry.stats.active_conns.load(Ordering::SeqCst), 1);

    // Create a GuardedTunnelTarget and bind UDP socket
    let guarded_target = crate::core::lifecycle::GuardedTunnelTarget::new(target, guard);

    let socket = guarded_target.udp_bind(0).await.unwrap();
    assert_eq!(entry.stats.active_conns.load(Ordering::SeqCst), 1);

    drop(guarded_target);
    // Connection guard is still held by socket!
    assert_eq!(entry.stats.active_conns.load(Ordering::SeqCst), 1);

    drop(socket);
    // Dropping socket releases the guard!
    assert_eq!(entry.stats.active_conns.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn test_udp_bind_does_not_mark_tunnel_healthy() {
    use crate::proxy::ProxyTunnelTarget;

    let registry = Arc::new(TunnelRegistry::new());
    let cfg = make_test_tunnel_config("tun-udp-bind-health");
    registry
        .register(TunnelEntry::new(
            "tun-udp-bind-health",
            cfg,
            LifecycleMode::Lazy,
        ))
        .unwrap();

    let lifecycle = LifecycleController::new(
        Arc::clone(&registry),
        Duration::from_secs(60),
        Duration::from_secs(1),
    );
    let (target, guard) = lifecycle
        .get_or_activate("tun-udp-bind-health")
        .await
        .unwrap();

    let tracker = Arc::new(TunnelHealthTracker::new());
    let guarded_target = crate::core::lifecycle::GuardedTunnelTarget::new_with_health(
        target,
        guard,
        Arc::clone(&tracker),
        3,
        Duration::from_secs(30),
    );

    // Binding a virtual UDP socket must not promote an unproven
    // tunnel to Healthy: no packet has crossed the handshake.
    let socket = guarded_target.udp_bind(0).await.unwrap();
    drop(socket);
    assert_eq!(tracker.current_status(), HealthStatus::Untested);
    assert_eq!(tracker.consecutive_failures(), 0);

    // Nor must it rescue an Unhealthy tunnel or reset its failures.
    tracker.record_failure(3, Duration::from_secs(30));
    tracker.record_failure(3, Duration::from_secs(30));
    tracker.record_failure(3, Duration::from_secs(30));
    assert_eq!(tracker.current_status(), HealthStatus::Unhealthy);
    assert_eq!(tracker.consecutive_failures(), 3);
    let socket = guarded_target.udp_bind(0).await.unwrap();
    drop(socket);
    assert_eq!(tracker.current_status(), HealthStatus::Unhealthy);
    assert_eq!(tracker.consecutive_failures(), 3);
}

#[tokio::test]
async fn test_boot_failure_reverts_state_to_dormant() {
    let registry = Arc::new(TunnelRegistry::new());
    let mut cfg = make_test_tunnel_config("tun-boot-fail");
    // Empty addresses will fail inside VirtualNetworkStack::new_with_mode after gotatun device is built
    cfg.interface.addresses.clear();
    let entry = registry
        .register(TunnelEntry::new("tun-boot-fail", cfg, LifecycleMode::Lazy))
        .unwrap();

    let lifecycle = LifecycleController::new(
        Arc::clone(&registry),
        Duration::from_secs(60),
        Duration::from_secs(1),
    );
    let res = lifecycle.get_or_activate("tun-boot-fail").await;
    assert!(res.is_err());
    assert_eq!(*entry.state.read(), TunnelState::Dormant);
}

#[tokio::test]
async fn test_router_failover_strategies() {
    let registry = Arc::new(TunnelRegistry::new());
    let e1 = registry
        .register(TunnelEntry::new(
            "t1",
            make_test_tunnel_config("t1"),
            LifecycleMode::Lazy,
        ))
        .unwrap();
    let e2 = registry
        .register(TunnelEntry::new(
            "t2",
            make_test_tunnel_config("t2"),
            LifecycleMode::Lazy,
        ))
        .unwrap();
    let e3 = registry
        .register(TunnelEntry::new(
            "t3",
            make_test_tunnel_config("t3"),
            LifecycleMode::Lazy,
        ))
        .unwrap();

    let lifecycle = LifecycleController::new(
        Arc::clone(&registry),
        Duration::from_secs(60),
        Duration::from_secs(1),
    );

    // 1. Fallback Strategy
    let router_fallback = MultiTenantRouter::new(
        Arc::clone(&lifecycle),
        Arc::clone(&registry),
        PoolStrategy::Fallback,
        true,
    );
    router_fallback.set_allowed_tunnels(Some(vec!["t1".into(), "t2".into(), "t3".into()]));

    // All healthy: primary t1 selected
    let s = router_fallback.authenticate(None).unwrap();
    match s {
        TunnelSelector::DefaultPool => {
            let candidates = router_fallback.get_candidates();
            assert_eq!(candidates, vec!["t1", "t2", "t3"]);
        }
        _ => panic!("expected DefaultPool"),
    }

    // Mark t1 Unhealthy: falls back to t2
    e1.health.mark_unhealthy(Duration::from_secs(60));
    assert!(!e1.health.is_routable());

    // 2. Round-Robin skips Unhealthy t1
    let router_rr = MultiTenantRouter::new(
        Arc::clone(&lifecycle),
        Arc::clone(&registry),
        PoolStrategy::RoundRobin,
        true,
    );
    router_rr.set_allowed_tunnels(Some(vec!["t1".into(), "t2".into(), "t3".into()]));

    for _ in 0..10 {
        let chosen = router_rr.authenticate(None).unwrap();
        assert_eq!(chosen, TunnelSelector::DefaultPool);
        // Direct keyword selection to inspect chosen tunnel
        let selected = router_rr.get_candidates();
        let healthy = router_rr.filter_healthy_candidates(&selected);
        assert_eq!(healthy.len(), 2);
        assert!(!healthy.contains(&&"t1".to_string()));
    }

    // 3. Least-Conn selects healthy even with higher connections.
    // A tunnel at the per-tunnel cap is left out of the candidate
    // list so load spills to the next tier instead of piling onto
    // it; it stays selectable only when every tunnel is capped.
    e2.stats.active_conns.store(100, Ordering::Relaxed);
    e3.stats.active_conns.store(5, Ordering::Relaxed);
    let router_lc = MultiTenantRouter::new(
        Arc::clone(&lifecycle),
        Arc::clone(&registry),
        PoolStrategy::LeastConn,
        true,
    );
    router_lc.set_allowed_tunnels(Some(vec!["t1".into(), "t2".into(), "t3".into()]));

    // e1 has 0 conns, but is unhealthy; e2 (100 conns) is over the
    // per-tunnel cap, so only e3 (5 conns) is offered as a candidate.
    let candidates = vec!["t1".to_string(), "t2".to_string(), "t3".to_string()];
    let filtered = router_lc.filter_healthy_candidates(&candidates);
    assert_eq!(filtered, vec![&candidates[2]]);

    // When every tunnel is capped the cap never blocks selection: the
    // best tier is offered whole instead of failing.
    e3.stats.active_conns.store(100, Ordering::Relaxed);
    let filtered_capped = router_lc.filter_healthy_candidates(&candidates);
    assert_eq!(filtered_capped.len(), 2);

    // 4. Fallback recovery: restore e1, verify it becomes primary again
    e1.health.record_success();
    assert!(e1.health.is_routable());
    // §3 left e2/e3 at the cap; reset so recovery is measured on
    // health alone.
    e2.stats.active_conns.store(0, Ordering::Relaxed);
    e3.stats.active_conns.store(0, Ordering::Relaxed);
    let filtered_after = router_fallback.filter_healthy_candidates(&candidates);
    assert_eq!(filtered_after.len(), 3);
}

#[test]
fn test_router_all_unhealthy_fails() {
    let registry = Arc::new(TunnelRegistry::new());
    let e1 = registry
        .register(TunnelEntry::new(
            "t1",
            make_test_tunnel_config("t1"),
            LifecycleMode::Lazy,
        ))
        .unwrap();
    let e2 = registry
        .register(TunnelEntry::new(
            "t2",
            make_test_tunnel_config("t2"),
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
    router.set_allowed_tunnels(Some(vec!["t1".into(), "t2".into()]));

    e1.health.mark_unhealthy(Duration::from_secs(60));
    e2.health.mark_unhealthy(Duration::from_secs(60));

    let candidates = vec!["t1".to_string(), "t2".to_string()];
    let healthy = router.filter_healthy_candidates(&candidates);
    assert!(healthy.is_empty());
}

#[test]
fn test_pool_prefers_handshaked_tunnels() {
    let registry = Arc::new(TunnelRegistry::new());
    let e1 = registry
        .register(TunnelEntry::new(
            "t1",
            make_test_tunnel_config("t1"),
            LifecycleMode::Lazy,
        ))
        .unwrap();
    let _e2 = registry
        .register(TunnelEntry::new(
            "t2",
            make_test_tunnel_config("t2"),
            LifecycleMode::Lazy,
        ))
        .unwrap();
    let e3 = registry
        .register(TunnelEntry::new(
            "t3",
            make_test_tunnel_config("t3"),
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

    // No tunnel has handshaked yet: fall back to all routable tunnels so
    // a fresh daemon can still bring tunnels up through real traffic.
    let healthy = router.filter_healthy_candidates(&candidates);
    assert_eq!(healthy.len(), 3);

    // t1 and t3 have handshaked; t2 never has. The unproven tunnel must
    // not be selected while proven tunnels exist, or a real connection
    // could burn its whole failover budget on a handshake that never
    // completes (reproduced live: github.com failed in exactly 3.5s).
    e1.stats.record_handshake(1_700_000_000);
    e3.stats.record_handshake(1_700_000_000);
    let healthy = router.filter_healthy_candidates(&candidates);
    assert_eq!(healthy.len(), 2);
    assert!(healthy.contains(&&"t1".to_string()));
    assert!(healthy.contains(&&"t3".to_string()));
    assert!(!healthy.contains(&&"t2".to_string()));

    // When every proven tunnel goes unhealthy, the unproven tunnel is the
    // only routable one left and must be returned (fallback).
    e1.health.mark_unhealthy(Duration::from_secs(60));
    e3.health.mark_unhealthy(Duration::from_secs(60));
    let healthy = router.filter_healthy_candidates(&candidates);
    assert_eq!(healthy, vec![&"t2".to_string()]);
}

#[test]
fn test_pool_prefers_live_tunnel_over_dormant_proven() {
    let registry = Arc::new(TunnelRegistry::new());
    let e1 = registry
        .register(TunnelEntry::new(
            "t1",
            make_test_tunnel_config("t1"),
            LifecycleMode::Lazy,
        ))
        .unwrap();
    let e2 = registry
        .register(TunnelEntry::new(
            "t2",
            make_test_tunnel_config("t2"),
            LifecycleMode::Lazy,
        ))
        .unwrap();
    let e3 = registry
        .register(TunnelEntry::new(
            "t3",
            make_test_tunnel_config("t3"),
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
    let now_secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();

    // t1 and t3 handshaked long ago and are dormant (the old "proven"
    // tier); t2 is active, Healthy, and handshaked just now (live).
    // Only the live tunnel must be returned: the dormant ones would
    // pay a fresh activation + handshake inside the caller's failover
    // budget while a live session sits unused.
    e1.stats.record_handshake(1_700_000_000);
    e3.stats.record_handshake(1_700_000_000);
    e2.stats.record_handshake(now_secs);
    e2.health.record_success();
    *e2.state.write() = TunnelState::Active;

    let healthy = router.filter_healthy_candidates(&candidates);
    assert_eq!(healthy, vec![&"t2".to_string()]);

    // When the live tunnel goes dormant again, it is still proven, so
    // selection falls back to the proven tier — all three tunnels —
    // instead of failing.
    *e2.state.write() = TunnelState::Dormant;
    let healthy = router.filter_healthy_candidates(&candidates);
    assert_eq!(healthy.len(), 3);
    assert!(healthy.contains(&&"t1".to_string()));
    assert!(healthy.contains(&&"t2".to_string()));
    assert!(healthy.contains(&&"t3".to_string()));
}

#[test]
fn test_pool_live_tier_needs_fresh_handshake() {
    let registry = Arc::new(TunnelRegistry::new());
    let e1 = registry
        .register(TunnelEntry::new(
            "t1",
            make_test_tunnel_config("t1"),
            LifecycleMode::Lazy,
        ))
        .unwrap();
    let _e2 = registry
        .register(TunnelEntry::new(
            "t2",
            make_test_tunnel_config("t2"),
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

    let candidates = vec!["t1".to_string(), "t2".to_string()];

    // t1 is active and Healthy but its handshake is stale (long ago),
    // so it is proven, not live: the session may have gone stale since
    // the last success. With no live tunnel, the proven tier is
    // returned; the unproven tunnel is still excluded.
    e1.stats.record_handshake(1_700_000_000);
    e1.health.record_success();
    *e1.state.write() = TunnelState::Active;

    let healthy = router.filter_healthy_candidates(&candidates);
    assert_eq!(healthy, vec![&"t1".to_string()]);
}

#[test]
fn test_pool_spills_to_proven_when_live_tier_capped() {
    let registry = Arc::new(TunnelRegistry::new());
    let e1 = registry
        .register(TunnelEntry::new(
            "t1",
            make_test_tunnel_config("t1"),
            LifecycleMode::Lazy,
        ))
        .unwrap();
    let e2 = registry
        .register(TunnelEntry::new(
            "t2",
            make_test_tunnel_config("t2"),
            LifecycleMode::Lazy,
        ))
        .unwrap();
    let e3 = registry
        .register(TunnelEntry::new(
            "t3",
            make_test_tunnel_config("t3"),
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
    let now_secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();

    // t1 and t2 are live but both carry MAX_LIVE_TUNNEL_CONNS
    // connections; t3 is proven (handshaked long ago, dormant). All
    // traffic piling onto the two live tunnels is what produced the
    // ~1% post-grant empty replies live, so selection must spill to
    // the proven tier — which also grows the live set, since a proven
    // tunnel that carries traffic becomes live.
    for e in [&e1, &e2] {
        e.stats.record_handshake(now_secs);
        e.health.record_success();
        *e.state.write() = TunnelState::Active;
        e.stats
            .active_conns
            .store(MAX_LIVE_TUNNEL_CONNS, Ordering::Relaxed);
    }
    e3.stats.record_handshake(1_700_000_000);

    let healthy = router.filter_healthy_candidates(&candidates);
    assert_eq!(healthy, vec![&"t3".to_string()]);

    let entries = registry.all_entries();
    let preferred = preferred_entries(&entries);
    let ids: Vec<&str> = preferred.iter().map(|e| e.id.as_str()).collect();
    assert_eq!(ids, vec!["t3"]);
}

#[test]
fn test_pool_prefers_under_cap_live_tunnel() {
    let registry = Arc::new(TunnelRegistry::new());
    let e1 = registry
        .register(TunnelEntry::new(
            "t1",
            make_test_tunnel_config("t1"),
            LifecycleMode::Lazy,
        ))
        .unwrap();
    let e2 = registry
        .register(TunnelEntry::new(
            "t2",
            make_test_tunnel_config("t2"),
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

    let candidates = vec!["t1".to_string(), "t2".to_string()];
    let now_secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();

    // t1 is live but at the cap; t2 is live with room. Only t2 may
    // be returned — returning t1 as well would let round-robin keep
    // piling connections onto the capped tunnel.
    for e in [&e1, &e2] {
        e.stats.record_handshake(now_secs);
        e.health.record_success();
        *e.state.write() = TunnelState::Active;
    }
    e1.stats
        .active_conns
        .store(MAX_LIVE_TUNNEL_CONNS, Ordering::Relaxed);
    e2.stats.active_conns.store(2, Ordering::Relaxed);

    let healthy = router.filter_healthy_candidates(&candidates);
    assert_eq!(healthy, vec![&"t2".to_string()]);

    let entries = registry.all_entries();
    let preferred = preferred_entries(&entries);
    let ids: Vec<&str> = preferred.iter().map(|e| e.id.as_str()).collect();
    assert_eq!(ids, vec!["t2"]);
}

#[test]
fn test_pool_cap_never_blocks_selection() {
    let registry = Arc::new(TunnelRegistry::new());
    let e1 = registry
        .register(TunnelEntry::new(
            "t1",
            make_test_tunnel_config("t1"),
            LifecycleMode::Lazy,
        ))
        .unwrap();
    let e2 = registry
        .register(TunnelEntry::new(
            "t2",
            make_test_tunnel_config("t2"),
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

    let candidates = vec!["t1".to_string(), "t2".to_string()];
    let now_secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();

    // Every live tunnel is at the cap and there is no lower tier to
    // spill to: the cap is a preference, never a hard limit, so the
    // best tier is returned whole instead of failing selection.
    for e in [&e1, &e2] {
        e.stats.record_handshake(now_secs);
        e.health.record_success();
        *e.state.write() = TunnelState::Active;
        e.stats
            .active_conns
            .store(MAX_LIVE_TUNNEL_CONNS, Ordering::Relaxed);
    }

    let healthy = router.filter_healthy_candidates(&candidates);
    assert_eq!(healthy.len(), 2);
    assert!(healthy.contains(&&"t1".to_string()));
    assert!(healthy.contains(&&"t2".to_string()));

    let entries = registry.all_entries();
    let preferred = preferred_entries(&entries);
    assert_eq!(preferred.len(), 2);
}

#[test]
fn test_per_tunnel_auth_override_and_global_fallback() {
    let registry = Arc::new(TunnelRegistry::new());
    registry
        .register(TunnelEntry::new(
            "tun-vip",
            make_test_tunnel_config("tun-vip"),
            LifecycleMode::Lazy,
        ))
        .unwrap();
    registry
        .register(TunnelEntry::new(
            "tun-std",
            make_test_tunnel_config("tun-std"),
            LifecycleMode::Lazy,
        ))
        .unwrap();

    let lifecycle = LifecycleController::new(
        Arc::clone(&registry),
        Duration::from_secs(60),
        Duration::from_secs(1),
    );
    let mut passwords = std::collections::HashMap::new();
    passwords.insert("tun-vip".to_string(), "vip-secret".to_string());

    let router = MultiTenantRouter::new(
        lifecycle,
        Arc::clone(&registry),
        PoolStrategy::RoundRobin,
        false,
    )
    .with_auth(AuthMode::PerTunnel, Some("global-secret".to_string()))
    .with_per_tunnel_passwords(passwords);

    // 1. Tunnel with override password requires its own password and rejects global password
    assert_eq!(
        router
            .authenticate(Some(("tun-vip", "vip-secret")))
            .unwrap(),
        TunnelSelector::ById("tun-vip".to_string())
    );
    assert!(
        router
            .authenticate(Some(("tun-vip", "global-secret")))
            .is_err()
    );

    // 2. Tunnel without override password falls back to global_password
    assert_eq!(
        router
            .authenticate(Some(("tun-std", "global-secret")))
            .unwrap(),
        TunnelSelector::ById("tun-std".to_string())
    );
    assert!(
        router
            .authenticate(Some(("tun-std", "vip-secret")))
            .is_err()
    );

    // 3. Pool keyword falls back to global_password
    assert_eq!(
        router
            .authenticate(Some(("auto", "global-secret")))
            .unwrap(),
        TunnelSelector::ByKeyword(PoolKeyword::Auto)
    );
    assert!(router.authenticate(Some(("auto", "vip-secret"))).is_err());

    // 4. When global_password is None in PerTunnel mode, un-overridden tunnels are rejected (fail-closed)
    let mut passwords2 = std::collections::HashMap::new();
    passwords2.insert("tun-vip".to_string(), "vip-secret".to_string());
    let router_strict = MultiTenantRouter::new(
        LifecycleController::new(
            Arc::clone(&registry),
            Duration::from_secs(60),
            Duration::from_secs(1),
        ),
        Arc::clone(&registry),
        PoolStrategy::RoundRobin,
        false,
    )
    .with_auth(AuthMode::PerTunnel, None)
    .with_per_tunnel_passwords(passwords2);

    assert_eq!(
        router_strict
            .authenticate(Some(("tun-vip", "vip-secret")))
            .unwrap(),
        TunnelSelector::ById("tun-vip".to_string())
    );
    assert!(
        router_strict
            .authenticate(Some(("tun-std", "any-pass")))
            .is_err()
    );
    assert!(
        router_strict
            .authenticate(Some(("auto", "any-pass")))
            .is_err()
    );
}

/// Regression (audit run-1, `proxy.auth.per-tunnel-password-bypass-via-tag-selector`):
/// in PerTunnel mode a tag selector must not open a password-protected
/// tunnel with the global password. `authenticate` still accepts the
/// global password provisionally (it cannot know which tunnel the tag
/// resolves to); `select_tunnel` is the authoritative check and must
/// reject it before activating the tunnel.
#[tokio::test]
async fn test_per_tunnel_tag_selector_rejects_global_password() {
    let registry = Arc::new(TunnelRegistry::new());
    registry
        .register(TunnelEntry::new(
            "wgcf-premium-01",
            make_test_tunnel_config("wgcf-premium-01"),
            LifecycleMode::Lazy,
        ))
        .unwrap();
    registry
        .register(TunnelEntry::new(
            "wgcf-open-01",
            make_test_tunnel_config("wgcf-open-01"),
            LifecycleMode::Lazy,
        ))
        .unwrap();

    let lifecycle = LifecycleController::new(
        Arc::clone(&registry),
        Duration::from_secs(60),
        Duration::from_secs(1),
    );
    let mut passwords = std::collections::HashMap::new();
    passwords.insert("wgcf-premium-01".to_string(), "premium-secret".to_string());

    let router = MultiTenantRouter::new(
        lifecycle,
        Arc::clone(&registry),
        PoolStrategy::RoundRobin,
        false,
    )
    .with_auth(AuthMode::PerTunnel, Some("global-secret".to_string()))
    .with_per_tunnel_passwords(passwords);

    // Auth-time acceptance is provisional: the tag resolves to the
    // premium tunnel, whose own password is required.
    let selector = router
        .authenticate(Some(("tag:wgcf-premium-01", "global-secret")))
        .expect("tag auth with the global password is provisionally accepted");
    assert_eq!(
        selector,
        TunnelSelector::ByTag("wgcf-premium-01".to_string())
    );

    // Selection with the global password must fail before activation.
    let Err(err) = router
        .select_tunnel(&selector, Some(("tag:wgcf-premium-01", "global-secret")))
        .await
    else {
        panic!("global password must not open the premium tunnel");
    };
    assert_eq!(err.kind(), std::io::ErrorKind::PermissionDenied);
    assert!(
        err.to_string()
            .contains("invalid proxy credentials for the selected tunnel"),
        "unexpected error: {err}"
    );
    assert!(
        !registry.get("wgcf-premium-01").unwrap().is_active(),
        "rejected selection must not activate the tunnel"
    );

    // The tunnel's own password opens it.
    let target = router
        .select_tunnel(&selector, Some(("tag:wgcf-premium-01", "premium-secret")))
        .await
        .expect("tunnel password must open the premium tunnel");
    assert_eq!(target.tunnel_id(), Some("wgcf-premium-01"));
    assert!(
        registry.get("wgcf-premium-01").unwrap().is_active(),
        "accepted selection must activate the tunnel"
    );
    drop(target);

    // Control: ById with the global password is rejected the same way.
    let by_id = TunnelSelector::ById("wgcf-premium-01".to_string());
    let Err(err) = router
        .select_tunnel(&by_id, Some(("wgcf-premium-01", "global-secret")))
        .await
    else {
        panic!("global password must not open the premium tunnel by id either");
    };
    assert_eq!(err.kind(), std::io::ErrorKind::PermissionDenied);

    // Control: the unprotected tunnel still accepts the global password.
    let open_selector = TunnelSelector::ByTag("wgcf-open-01".to_string());
    let open_target = router
        .select_tunnel(&open_selector, Some(("tag:wgcf-open-01", "global-secret")))
        .await
        .expect("global password must open the unprotected tunnel");
    assert_eq!(open_target.tunnel_id(), Some("wgcf-open-01"));
    drop(open_target);
}

/// Same bypass, keyword selector: with only the protected tunnel in the
/// pool, `auto` + the global password must fail and the tunnel's own
/// password must succeed.
#[tokio::test]
async fn test_per_tunnel_keyword_selector_rejects_global_password() {
    let registry = Arc::new(TunnelRegistry::new());
    registry
        .register(TunnelEntry::new(
            "wgcf-premium-01",
            make_test_tunnel_config("wgcf-premium-01"),
            LifecycleMode::Lazy,
        ))
        .unwrap();

    let lifecycle = LifecycleController::new(
        Arc::clone(&registry),
        Duration::from_secs(60),
        Duration::from_secs(1),
    );
    let mut passwords = std::collections::HashMap::new();
    passwords.insert("wgcf-premium-01".to_string(), "premium-secret".to_string());

    let router = MultiTenantRouter::new(
        lifecycle,
        Arc::clone(&registry),
        PoolStrategy::RoundRobin,
        false,
    )
    .with_auth(AuthMode::PerTunnel, Some("global-secret".to_string()))
    .with_per_tunnel_passwords(passwords);

    let selector = TunnelSelector::ByKeyword(PoolKeyword::Auto);
    let Err(err) = router
        .select_tunnel(&selector, Some(("auto", "global-secret")))
        .await
    else {
        panic!("global password must not open the premium tunnel via keyword");
    };
    assert_eq!(err.kind(), std::io::ErrorKind::PermissionDenied);

    let target = router
        .select_tunnel(&selector, Some(("auto", "premium-secret")))
        .await
        .expect("tunnel password must open the premium tunnel via keyword");
    assert_eq!(target.tunnel_id(), Some("wgcf-premium-01"));
    drop(target);
}

/// Regression (audit run-1,
/// `proxy.auth.anonymous-bypass-per-tunnel-password-via-default-pool`):
/// in PerTunnel mode with `allow_anonymous = true`, a client presenting
/// no credentials must not reach a tunnel with its own override
/// password through the default pool — only that tunnel's own password
/// opens it. A tunnel protected only by the global password keeps the
/// documented anonymous behaviour.
#[tokio::test]
async fn test_per_tunnel_default_pool_rejects_anonymous_for_override_tunnel() {
    let registry = Arc::new(TunnelRegistry::new());
    registry
        .register(TunnelEntry::new(
            "wgcf-premium-01",
            make_test_tunnel_config("wgcf-premium-01"),
            LifecycleMode::Lazy,
        ))
        .unwrap();

    let lifecycle = LifecycleController::new(
        Arc::clone(&registry),
        Duration::from_secs(60),
        Duration::from_secs(1),
    );
    let mut passwords = std::collections::HashMap::new();
    passwords.insert("wgcf-premium-01".to_string(), "premium-secret".to_string());

    let router = MultiTenantRouter::new(
        lifecycle,
        Arc::clone(&registry),
        PoolStrategy::RoundRobin,
        true,
    )
    .with_auth(AuthMode::PerTunnel, Some("global-secret".to_string()))
    .with_per_tunnel_passwords(passwords);

    let selector = TunnelSelector::DefaultPool;
    let Err(err) = router.select_tunnel(&selector, None).await else {
        panic!("anonymous client must not reach the override-protected tunnel via DefaultPool");
    };
    assert_eq!(err.kind(), std::io::ErrorKind::PermissionDenied);

    // Control: the same anonymous DefaultPool request reaches a tunnel
    // protected only by the global password — the documented
    // "a configured password does not block anonymous requests" rule.
    let open_registry = Arc::new(TunnelRegistry::new());
    open_registry
        .register(TunnelEntry::new(
            "wgcf-open-01",
            make_test_tunnel_config("wgcf-open-01"),
            LifecycleMode::Lazy,
        ))
        .unwrap();
    let open_router = MultiTenantRouter::new(
        LifecycleController::new(
            Arc::clone(&open_registry),
            Duration::from_secs(60),
            Duration::from_secs(1),
        ),
        Arc::clone(&open_registry),
        PoolStrategy::RoundRobin,
        true,
    )
    .with_auth(AuthMode::PerTunnel, Some("global-secret".to_string()));
    let target = open_router
        .select_tunnel(&selector, None)
        .await
        .expect("anonymous client still reaches a global-password-only tunnel");
    assert_eq!(target.tunnel_id(), Some("wgcf-open-01"));
    drop(target);
}

#[test]
fn test_health_tracker_half_open_single_trial_and_failure_rearms_cooldown() {
    use crate::core::health::{HealthStatus, TunnelHealthTracker};
    let tracker = TunnelHealthTracker::new();
    tracker.record_failure(2, Duration::from_millis(20));
    assert_eq!(tracker.current_status(), HealthStatus::Untested);
    assert!(tracker.is_routable());

    tracker.record_failure(2, Duration::from_millis(20));
    assert_eq!(tracker.current_status(), HealthStatus::Unhealthy);
    assert!(!tracker.is_routable());

    std::thread::sleep(Duration::from_millis(30));

    // First caller gets the single HalfOpen trial slot; concurrent second caller is blocked.
    assert!(tracker.is_routable());
    assert!(!tracker.is_routable());
    assert_eq!(tracker.current_status(), HealthStatus::HalfOpen);

    // Failed trial immediately returns tracker to Unhealthy with a fresh cooldown.
    tracker.record_failure(5, Duration::from_secs(30));
    assert_eq!(tracker.current_status(), HealthStatus::Unhealthy);
    assert!(!tracker.is_routable());

    // Success restores Healthy.
    tracker.record_success();
    assert_eq!(tracker.current_status(), HealthStatus::Healthy);
    assert!(tracker.is_routable());
}

#[tokio::test]
async fn test_disabled_active_tunnel_is_suspended_and_eager_disabled_starts_cleanly() {
    let mut config = MainConfig::default();
    config.per_tunnel.enabled = false;
    config.shared_listeners.clear();
    config.lifecycle.mode = LifecycleMode::Eager;
    config.disabled_tunnels = vec!["eager-disabled".to_string()];

    let t1 = make_test_tunnel_config("eager-disabled");
    let t2 = make_test_tunnel_config("lazy-active");
    let manager = TunnelManager::new(config, vec![t1, t2]).unwrap();

    // start() must skip disabled eager tunnels instead of failing.
    manager.start().await.unwrap();
    assert_eq!(
        *manager
            .registry()
            .get("eager-disabled")
            .unwrap()
            .state
            .read(),
        TunnelState::Dormant
    );

    // Activate lazy-active, then disable it: it must transition to Suspended (not stay Active).
    manager.activate_tunnel("lazy-active").await.unwrap();
    assert_eq!(
        *manager.registry().get("lazy-active").unwrap().state.read(),
        TunnelState::Active
    );
    manager
        .set_tunnels_disabled("lazy-active", true)
        .await
        .unwrap();
    assert!(manager.registry().get("lazy-active").unwrap().is_disabled());
    assert_eq!(
        *manager.registry().get("lazy-active").unwrap().state.read(),
        TunnelState::Suspended
    );

    manager.stop().await.unwrap();
}

async fn disable_busy_tunnel_pending_flow(mode: LifecycleMode) {
    // Shared by the Lazy and Eager legs below: disabling a busy tunnel
    // must report pending (not success), refuse new connections, keep
    // the live session running, and suspend once drained.
    let mut config = MainConfig::default();
    config.per_tunnel.enabled = false;
    config.shared_listeners.clear();
    config.lifecycle.mode = mode;

    let manager = TunnelManager::new(config, vec![make_test_tunnel_config("busy-one")]).unwrap();
    manager.start().await.unwrap();
    manager.activate_tunnel("busy-one").await.unwrap();
    let entry = manager.registry().get("busy-one").unwrap();
    assert_eq!(*entry.state.read(), TunnelState::Active);
    // Simulate one live session held by a proxy connection.
    entry.stats.active_conns.store(1, Ordering::SeqCst);

    manager
        .set_tunnels_disabled("busy-one", true)
        .await
        .unwrap();
    let entry = manager.registry().get("busy-one").unwrap();
    assert!(entry.is_disabled());
    assert!(
        entry.is_disable_pending(),
        "busy tunnel must stay disable-pending, not report plain success"
    );
    assert_eq!(*entry.state.read(), TunnelState::Active);

    // New connections are refused while disabled...
    assert!(manager.activate_tunnel("busy-one").await.is_err());

    // ...but the live session keeps running until it drains.
    entry.stats.active_conns.store(0, Ordering::SeqCst);
    manager.lifecycle.check_idle_tunnels().await;
    let entry = manager.registry().get("busy-one").unwrap();
    assert_eq!(*entry.state.read(), TunnelState::Suspended);
    assert!(!entry.is_disable_pending());

    manager.stop().await.unwrap();
}

#[tokio::test]
async fn test_disable_busy_lazy_tunnel_stays_pending_until_drained() {
    disable_busy_tunnel_pending_flow(LifecycleMode::Lazy).await;
}

#[tokio::test]
async fn test_disable_busy_eager_tunnel_stays_pending_until_drained() {
    // The Eager leg: without the fix, check_idle_tunnels skipped Eager
    // tunnels entirely, so a disabled eager tunnel stayed Active forever.
    disable_busy_tunnel_pending_flow(LifecycleMode::Eager).await;
}

#[tokio::test]
async fn test_reenable_clears_disable_pending() {
    let mut config = MainConfig::default();
    config.per_tunnel.enabled = false;
    config.shared_listeners.clear();

    let manager = TunnelManager::new(config, vec![make_test_tunnel_config("pending-one")]).unwrap();
    manager.start().await.unwrap();
    manager.activate_tunnel("pending-one").await.unwrap();
    let entry = manager.registry().get("pending-one").unwrap();
    entry.stats.active_conns.store(1, Ordering::SeqCst);

    manager
        .set_tunnels_disabled("pending-one", true)
        .await
        .unwrap();
    assert!(
        manager
            .registry()
            .get("pending-one")
            .unwrap()
            .is_disable_pending()
    );

    manager
        .set_tunnels_disabled("pending-one", false)
        .await
        .unwrap();
    let entry = manager.registry().get("pending-one").unwrap();
    assert!(!entry.is_disabled());
    assert!(!entry.is_disable_pending());

    manager.stop().await.unwrap();
}

#[tokio::test]
async fn test_half_open_trial_slot_released_when_guarded_target_dropped_unused() {
    let registry = Arc::new(TunnelRegistry::new());
    let entry = registry
        .register(TunnelEntry::new(
            "tun-halfopen",
            make_test_tunnel_config("tun-halfopen"),
            LifecycleMode::Lazy,
        ))
        .unwrap();

    // Force Unhealthy with expired cooldown so is_routable() transitions to HalfOpen
    entry.health.mark_unhealthy(Duration::from_millis(1));
    tokio::time::sleep(Duration::from_millis(10)).await;
    assert!(entry.health.is_routable());
    assert_eq!(
        entry.health.current_status(),
        crate::core::HealthStatus::HalfOpen
    );
    assert!(
        !entry.health.can_route(),
        "trial_in_flight should block concurrent routing"
    );

    // Build an ActiveTunnel and wrap in GuardedTunnelTarget, then drop without calling tcp_connect/udp_bind
    let lifecycle = LifecycleController::new(
        Arc::clone(&registry),
        Duration::from_secs(60),
        Duration::from_secs(1),
    );
    let (active, guard) = lifecycle.get_or_activate("tun-halfopen").await.unwrap();
    let guarded = crate::core::GuardedTunnelTarget::new_with_health(
        active,
        guard,
        Arc::clone(&entry.health),
        3,
        Duration::from_secs(30),
    );
    drop(guarded);

    assert!(
        entry.health.can_route(),
        "HalfOpen trial slot must be released when GuardedTunnelTarget is dropped unused"
    );
    lifecycle.stop().await;
}

#[tokio::test]
async fn test_half_open_trial_resolves_as_inconclusive_when_attempt_aborted() {
    use crate::proxy::ProxyTunnelTarget;

    let registry = Arc::new(TunnelRegistry::new());
    let entry = registry
        .register(TunnelEntry::new(
            "tun-halfopen-abort",
            make_test_tunnel_config("tun-halfopen-abort"),
            LifecycleMode::Lazy,
        ))
        .unwrap();

    // Force Unhealthy with expired cooldown so is_routable() transitions to HalfOpen
    entry.health.mark_unhealthy(Duration::from_millis(1));
    tokio::time::sleep(Duration::from_millis(10)).await;
    assert!(entry.health.is_routable());
    assert_eq!(
        entry.health.current_status(),
        crate::core::HealthStatus::HalfOpen
    );

    let lifecycle = LifecycleController::new(
        Arc::clone(&registry),
        Duration::from_secs(60),
        Duration::from_secs(1),
    );
    let (active, guard) = lifecycle
        .get_or_activate("tun-halfopen-abort")
        .await
        .unwrap();
    let guarded = crate::core::GuardedTunnelTarget::new_with_health(
        active,
        guard,
        Arc::clone(&entry.health),
        3,
        Duration::from_secs(30),
    );

    // An attempt cut off mid-flight (pool budget / candidate timeout)
    // ended without a verdict about the tunnel — the destination may
    // simply be slow — so it must not count as a failure (audit run-1,
    // medium): the HalfOpen trial slot is released, status and failure
    // count untouched, and the next request may trial the tunnel again.
    guarded.note_attempt_aborted();
    assert_eq!(
        entry.health.current_status(),
        crate::core::HealthStatus::HalfOpen
    );
    assert_eq!(entry.health.consecutive_failures(), 0);
    assert_eq!(entry.health.cooldown_remaining_secs(), 0);
    assert!(
        entry.health.can_route(),
        "aborted trial must release the slot for immediate retry, not re-arm the cooldown"
    );

    // Idempotent per target instance: a second abort note (budget abort
    // after an inner per-candidate timeout) must not count twice.
    guarded.note_attempt_aborted();
    assert_eq!(entry.health.consecutive_failures(), 0);

    drop(guarded);
    lifecycle.stop().await;
}

#[tokio::test]
async fn test_half_open_trial_slot_released_on_password_verify_failure() {
    // A wrong per-tunnel password on a HalfOpen tunnel selected by tag
    // claims the trial slot during selection and then fails verification
    // before any `GuardedTunnelTarget` exists — the slot must be
    // released here, or the tunnel stays unroutable until a probe or
    // restart (audit run-1,
    // `lifecycle.halfopen-trial-slot-leak-on-password-verify`).
    let registry = Arc::new(TunnelRegistry::new());
    let entry = registry
        .register(TunnelEntry::new(
            "tun-halfopen",
            make_test_tunnel_config("tun-halfopen"),
            LifecycleMode::Lazy,
        ))
        .unwrap();

    // Force Unhealthy with expired cooldown; `current_status()` observes
    // the lazy HalfOpen transition without claiming the trial slot —
    // selection below must be the claim.
    entry.health.mark_unhealthy(Duration::from_millis(1));
    tokio::time::sleep(Duration::from_millis(10)).await;
    assert_eq!(
        entry.health.current_status(),
        crate::core::HealthStatus::HalfOpen
    );
    assert!(
        entry.health.can_route(),
        "HalfOpen tunnel with no trial in flight must be routable"
    );

    let lifecycle = LifecycleController::new(
        Arc::clone(&registry),
        Duration::from_secs(60),
        Duration::from_secs(1),
    );
    let mut passwords = std::collections::HashMap::new();
    passwords.insert("tun-halfopen".to_string(), "tun-pass".to_string());
    let router = MultiTenantRouter::new(
        Arc::clone(&lifecycle),
        Arc::clone(&registry),
        PoolStrategy::RoundRobin,
        false,
    )
    .with_auth(AuthMode::PerTunnel, Some("global-pass".to_string()))
    .with_per_tunnel_passwords(passwords);

    let err = match router
        .select_tunnel(
            &TunnelSelector::ByTag("halfopen".to_string()),
            Some(("user", "wrong-pass")),
        )
        .await
    {
        Ok(_) => panic!("wrong per-tunnel password must be rejected"),
        Err(e) => e,
    };
    assert_eq!(err.kind(), std::io::ErrorKind::PermissionDenied);
    assert_eq!(
        entry.health.current_status(),
        crate::core::HealthStatus::HalfOpen
    );
    assert!(
        entry.health.can_route(),
        "HalfOpen trial slot must be released when password verification fails"
    );
    lifecycle.stop().await;
}

#[test]
fn test_destination_caused_error_classification() {
    use crate::core::lifecycle::is_destination_caused_error;
    use std::io::ErrorKind;

    // Destination-caused, regardless of handshake history: a refused
    // connection proves the tunnel carried the SYN; an unroutable
    // address family or a nonexistent domain is a property of the request.
    assert!(is_destination_caused_error(
        ErrorKind::ConnectionRefused,
        false
    ));
    assert!(is_destination_caused_error(
        ErrorKind::AddrNotAvailable,
        false
    ));
    assert!(is_destination_caused_error(ErrorKind::NotFound, false));
    assert!(is_destination_caused_error(ErrorKind::InvalidInput, false));
    // Timeout: only destination-caused when the peer has handshaked
    // recently (a blackholing destination); a timeout against a peer
    // whose last handshake is stale — or that never handshaked — points
    // at the peer itself.
    assert!(is_destination_caused_error(ErrorKind::TimedOut, true));
    assert!(!is_destination_caused_error(ErrorKind::TimedOut, false));
    // Tunnel-side / unexpected: still a failure.
    assert!(!is_destination_caused_error(ErrorKind::BrokenPipe, true));
    assert!(!is_destination_caused_error(
        ErrorKind::ConnectionReset,
        true
    ));
    assert!(!is_destination_caused_error(
        ErrorKind::NetworkUnreachable,
        true
    ));
    assert!(!is_destination_caused_error(ErrorKind::Other, true));
}

#[test]
fn test_handshake_freshness_window() {
    use crate::core::lifecycle::{HANDSHAKE_FRESHNESS_WINDOW_SECS, handshake_is_fresh};

    let now = 1_700_000_000;
    // Never handshaked: never fresh.
    assert!(!handshake_is_fresh(0, now));
    // Just now: fresh.
    assert!(handshake_is_fresh(now, now));
    // One second inside the window: still fresh.
    assert!(handshake_is_fresh(
        now - HANDSHAKE_FRESHNESS_WINDOW_SECS + 1,
        now
    ));
    // Exactly at the window edge: stale.
    assert!(!handshake_is_fresh(
        now - HANDSHAKE_FRESHNESS_WINDOW_SECS,
        now
    ));
    // Ten minutes ago: stale.
    assert!(!handshake_is_fresh(now - 600, now));
}

#[tokio::test]
async fn test_dns_timeout_with_stale_handshake_counts_as_failure() {
    use crate::proxy::ProxyTunnelTarget;

    let registry = Arc::new(TunnelRegistry::new());
    registry
        .register(TunnelEntry::new(
            "tun-dns-timeout-stale",
            make_test_tunnel_config("tun-dns-timeout-stale"),
            LifecycleMode::Lazy,
        ))
        .unwrap();

    let lifecycle = LifecycleController::new(
        Arc::clone(&registry),
        Duration::from_secs(60),
        Duration::from_secs(1),
    );
    let (target, guard) = lifecycle
        .get_or_activate("tun-dns-timeout-stale")
        .await
        .unwrap();
    let tracker = Arc::new(TunnelHealthTracker::new());
    let guarded = crate::core::lifecycle::GuardedTunnelTarget::new_with_health(
        target,
        guard,
        Arc::clone(&tracker),
        3,
        Duration::from_secs(30),
    );

    // The peer handshaked ten minutes ago and has been silent since: a
    // DNS timeout now points at the dead peer, not at a blackholing
    // destination — it must count as a tunnel-side failure (the old
    // "ever handshaked" rule excused it, so the tunnel kept being
    // selected and burned the pool failover budget).
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    // `target` moved into `guarded` above; reach the shared stats
    // through the guarded target's tunnel handle.
    guarded.tunnel().stats.record_handshake(now - 600);

    let err = guarded
        .resolve_all_in_tunnel("nonexistent.invalid")
        .await
        .expect_err("in-tunnel DNS must time out without a peer");
    assert_eq!(err.kind(), std::io::ErrorKind::TimedOut);
    assert_eq!(tracker.consecutive_failures(), 1);
    assert_eq!(tracker.current_status(), HealthStatus::Untested);

    drop(guarded);
    lifecycle.stop().await;
}

#[tokio::test]
async fn test_dns_timeout_with_fresh_handshake_is_inconclusive() {
    use crate::proxy::ProxyTunnelTarget;

    let registry = Arc::new(TunnelRegistry::new());
    registry
        .register(TunnelEntry::new(
            "tun-dns-timeout-fresh",
            make_test_tunnel_config("tun-dns-timeout-fresh"),
            LifecycleMode::Lazy,
        ))
        .unwrap();

    let lifecycle = LifecycleController::new(
        Arc::clone(&registry),
        Duration::from_secs(60),
        Duration::from_secs(1),
    );
    let (target, guard) = lifecycle
        .get_or_activate("tun-dns-timeout-fresh")
        .await
        .unwrap();
    let tracker = Arc::new(TunnelHealthTracker::new());
    let guarded = crate::core::lifecycle::GuardedTunnelTarget::new_with_health(
        target,
        guard,
        Arc::clone(&tracker),
        3,
        Duration::from_secs(30),
    );

    // Control leg: the peer handshaked just now, so a DNS timeout is
    // still plausibly the destination's fault — it must not count
    // against the tunnel.
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    guarded.tunnel().stats.record_handshake(now);

    let err = guarded
        .resolve_all_in_tunnel("nonexistent.invalid")
        .await
        .expect_err("in-tunnel DNS must time out without a peer");
    assert_eq!(err.kind(), std::io::ErrorKind::TimedOut);
    assert_eq!(tracker.consecutive_failures(), 0);
    assert_eq!(tracker.current_status(), HealthStatus::Untested);

    drop(guarded);
    lifecycle.stop().await;
}

#[tokio::test]
async fn test_destination_caused_tcp_errors_do_not_trip_breaker() {
    use crate::proxy::ProxyTunnelTarget;

    let registry = Arc::new(TunnelRegistry::new());
    // A v6-only tunnel: any IPv4 destination is unroutable before any
    // handshake — the failure is the request's, not the tunnel's.
    let mut cfg = make_test_tunnel_config("tun-v6-only");
    cfg.interface.addresses = vec!["2606:4700:110:8751:5a4:5d1e:287e:46c4/128".parse().unwrap()];
    registry
        .register(TunnelEntry::new("tun-v6-only", cfg, LifecycleMode::Lazy))
        .unwrap();

    let lifecycle = LifecycleController::new(
        Arc::clone(&registry),
        Duration::from_secs(60),
        Duration::from_secs(1),
    );
    let (target, guard) = lifecycle.get_or_activate("tun-v6-only").await.unwrap();
    let tracker = Arc::new(TunnelHealthTracker::new());
    let guarded = crate::core::lifecycle::GuardedTunnelTarget::new_with_health(
        target,
        guard,
        Arc::clone(&tracker),
        3,
        Duration::from_secs(30),
    );

    // Three unroutable attempts must not trip the breaker (old behavior:
    // Unhealthy after the third, with the pool refusing every client).
    for _ in 0..3 {
        let err = match guarded.tcp_connect("203.0.113.1:80".parse().unwrap()).await {
            Ok(_) => panic!("v6-only tunnel must refuse IPv4"),
            Err(e) => e,
        };
        assert_eq!(err.kind(), std::io::ErrorKind::AddrNotAvailable);
    }
    assert_eq!(tracker.current_status(), HealthStatus::Untested);
    assert_eq!(tracker.consecutive_failures(), 0);

    // Nor must they drag down a healthy tunnel.
    tracker.record_success();
    assert_eq!(tracker.current_status(), HealthStatus::Healthy);
    let err = match guarded.tcp_connect("203.0.113.1:80".parse().unwrap()).await {
        Ok(_) => panic!("v6-only tunnel must refuse IPv4"),
        Err(e) => e,
    };
    assert_eq!(err.kind(), std::io::ErrorKind::AddrNotAvailable);
    assert_eq!(tracker.current_status(), HealthStatus::Healthy);
    assert_eq!(tracker.consecutive_failures(), 0);

    drop(guarded);
    lifecycle.stop().await;
}

#[tokio::test]
async fn test_dns_timeout_without_handshake_still_counts_as_failure() {
    use crate::proxy::ProxyTunnelTarget;

    let registry = Arc::new(TunnelRegistry::new());
    registry
        .register(TunnelEntry::new(
            "tun-dns-timeout",
            make_test_tunnel_config("tun-dns-timeout"),
            LifecycleMode::Lazy,
        ))
        .unwrap();

    let lifecycle = LifecycleController::new(
        Arc::clone(&registry),
        Duration::from_secs(60),
        Duration::from_secs(1),
    );
    let (target, guard) = lifecycle.get_or_activate("tun-dns-timeout").await.unwrap();
    let tracker = Arc::new(TunnelHealthTracker::new());
    let guarded = crate::core::lifecycle::GuardedTunnelTarget::new_with_health(
        target,
        guard,
        Arc::clone(&tracker),
        3,
        Duration::from_secs(30),
    );

    // Control leg: a DNS timeout against a peer that never handshaked is
    // a tunnel-side failure, not a destination verdict — it must still
    // count (the `.invalid` TLD never resolves, so no host fallback can
    // rescue the attempt).
    let err = guarded
        .resolve_all_in_tunnel("nonexistent.invalid")
        .await
        .expect_err("in-tunnel DNS must time out without a peer");
    assert_eq!(err.kind(), std::io::ErrorKind::TimedOut);
    assert_eq!(tracker.consecutive_failures(), 1);
    assert_eq!(tracker.current_status(), HealthStatus::Untested);

    drop(guarded);
    lifecycle.stop().await;
}

#[tokio::test]
async fn test_disable_persists_without_destroying_comments() {
    // The batch disable path used to rewrite wpmulti.toml from the
    // parsed model (plain dump), silently destroying every comment —
    // the same bug the POST /config path had before the merge helper.
    // Disabling a tunnel must only change the disabled_tunnels value.
    let temp = tempfile::TempDir::new().unwrap();
    let cfg_path = temp.path().join("wpmulti.toml");
    let cfg = MainConfig::default();
    let commented = format!(
        "# My production config - DO NOT EDIT BY HAND\n# Contact: ops team\n{}",
        toml::to_string_pretty(&cfg).expect("serialize config")
    );
    std::fs::write(&cfg_path, &commented).unwrap();

    let manager = TunnelManager::new(cfg, vec![make_test_tunnel_config("wgcf-001")]).unwrap();
    manager.set_config_path(cfg_path.clone());
    manager
        .set_tunnels_disabled("wgcf-001", true)
        .await
        .unwrap();

    let saved = std::fs::read_to_string(&cfg_path).unwrap();
    assert!(
        saved.contains("# My production config - DO NOT EDIT BY HAND"),
        "header comment lost:\n{saved}"
    );
    assert!(
        saved.contains("# Contact: ops team"),
        "contact comment lost:\n{saved}"
    );
    assert!(
        saved.contains("disabled_tunnels = [\"wgcf-001\"]"),
        "disable did not persist:\n{saved}"
    );
    let reparsed: MainConfig = toml::from_str(&saved).expect("saved file must parse");
    assert_eq!(reparsed.disabled_tunnels, vec!["wgcf-001".to_string()]);
    manager.stop().await.unwrap();
}

#[cfg(unix)]
struct RestoreDirPerms(std::path::PathBuf, u32);

#[cfg(unix)]
impl Drop for RestoreDirPerms {
    fn drop(&mut self) {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&self.0, std::fs::Permissions::from_mode(self.1));
    }
}

#[cfg(unix)]
#[test]
fn test_in_place_fallback_shrinks_tightens_perms_and_reports_errors() {
    use std::os::unix::fs::PermissionsExt;

    let temp = tempfile::TempDir::new().unwrap();
    let cfg_path = temp.path().join("wpmulti.toml");
    std::fs::write(&cfg_path, "initial_longer_value = true\n").unwrap();
    std::fs::set_permissions(&cfg_path, std::fs::Permissions::from_mode(0o644)).unwrap();

    crate::core::try_in_place_fallback_blocking(&cfg_path, "ok = 1\n").unwrap();
    assert_eq!(std::fs::read_to_string(&cfg_path).unwrap(), "ok = 1\n");
    let mode = std::fs::metadata(&cfg_path).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode, 0o640, "world permission bits must be stripped");

    let link_path = temp.path().join("link.toml");
    std::os::unix::fs::symlink(&cfg_path, &link_path).unwrap();
    let sym_err =
        crate::core::try_in_place_fallback_blocking(&link_path, "pwned = true\n").unwrap_err();
    assert_eq!(sym_err.kind(), std::io::ErrorKind::InvalidInput);
    assert_eq!(std::fs::read_to_string(&cfg_path).unwrap(), "ok = 1\n");

    let missing_err =
        crate::core::try_in_place_fallback_blocking(&temp.path().join("missing.toml"), "x = 1\n")
            .unwrap_err();
    assert_eq!(missing_err.kind(), std::io::ErrorKind::NotFound);
}

#[cfg(unix)]
#[tokio::test]
async fn test_write_config_atomically_fallback_when_parent_dir_read_only() {
    use std::os::unix::fs::PermissionsExt;

    let temp = tempfile::TempDir::new().unwrap();
    let cfg_dir = temp.path().join("etc_wpmulti");
    std::fs::create_dir_all(&cfg_dir).unwrap();
    let cfg_path = cfg_dir.join("wpmulti.toml");

    crate::core::write_config_atomically(&cfg_path, "initial_longer_value = true\n")
        .await
        .unwrap();
    assert_eq!(
        std::fs::read_to_string(&cfg_path).unwrap(),
        "initial_longer_value = true\n"
    );

    let link_path = cfg_dir.join("link.toml");
    std::os::unix::fs::symlink(&cfg_path, &link_path).unwrap();

    let _restore = RestoreDirPerms(cfg_dir.clone(), 0o755);
    std::fs::set_permissions(&cfg_path, std::fs::Permissions::from_mode(0o600)).unwrap();
    std::fs::set_permissions(&cfg_dir, std::fs::Permissions::from_mode(0o555)).unwrap();

    // Skip DAC-dependent fallback assertion if process runs with UID 0 / CAP_DAC_OVERRIDE.
    let probe_path = cfg_dir.join(".dac_probe");
    if let Ok(_f) = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&probe_path)
    {
        drop(_restore);
        let _ = std::fs::set_permissions(&cfg_dir, std::fs::Permissions::from_mode(0o755));
        let _ = std::fs::remove_file(&probe_path);
        return;
    }

    // Parent dir is read-only (0o555) so atomic temp+rename is blocked,
    // regular writable target falls back in-place (including shrinking),
    // and symlink target surfaces real InvalidInput without masking.
    crate::core::write_config_atomically(&cfg_path, "updated = true\n")
        .await
        .unwrap();
    assert_eq!(
        std::fs::read_to_string(&cfg_path).unwrap(),
        "updated = true\n"
    );

    let err = crate::core::write_config_atomically(&link_path, "pwned = true\n")
        .await
        .unwrap_err();
    assert_eq!(err.kind(), std::io::ErrorKind::InvalidInput);
    assert_eq!(
        std::fs::read_to_string(&cfg_path).unwrap(),
        "updated = true\n"
    );
}

/// Send a SOCKS5 CONNECT for an unresolvable domain through `addr` and
/// assert the error reply. The in-tunnel DNS query times out (no live
/// peer answers), which books a tunnel-side failure — unlike the old
/// IPv6-connect generator, whose AddrNotAvailable (family mismatch) no
/// longer counts as a failure since audit run-1 finding 2. Each call
/// costs ~3s (the in-tunnel DNS deadline).
async fn send_socks5_unresolvable_domain_connect(addr: SocketAddr) {
    let mut stream = tokio::net::TcpStream::connect(addr).await.unwrap();
    stream.write_all(&[0x05, 0x01, 0x00]).await.unwrap();
    let mut method_resp = [0u8; 2];
    stream.read_exact(&mut method_resp).await.unwrap();
    assert_eq!(method_resp, [0x05, 0x00]);

    // CONNECT nonexistent.invalid:80 (ATYP=0x03 domain)
    let domain = b"nonexistent.invalid";
    let mut req = vec![0x05, 0x01, 0x00, 0x03, domain.len() as u8];
    req.extend_from_slice(domain);
    req.extend_from_slice(&80u16.to_be_bytes());
    stream.write_all(&req).await.unwrap();

    // Verify SOCKS5 error reply and drain EOF so handler finishes recording failure.
    let mut reply = [0u8; 10];
    stream.read_exact(&mut reply).await.unwrap();
    assert_eq!(reply[0], 0x05);
    assert_ne!(reply[1], 0x00);
    let mut eof = [0u8; 16];
    let _ = stream.read(&mut eof).await;
}

#[tokio::test]
async fn test_shared_listener_health_override_and_dynamic_lifecycle_tracking() {
    use crate::config::{SharedListenerSettings, TunnelPoolSelection};
    use crate::core::health::HealthStatus;

    let registry = Arc::new(TunnelRegistry::new());
    let mut t_cfg = make_test_tunnel_config("v4-only-health");
    t_cfg.interface.addresses = vec!["172.16.0.2/32".parse().unwrap()];
    let entry = registry
        .register(TunnelEntry::new(
            "v4-only-health",
            t_cfg,
            LifecycleMode::Lazy,
        ))
        .unwrap();

    // Lifecycle defaults to threshold = 3.
    let lifecycle = LifecycleController::new(
        Arc::clone(&registry),
        Duration::from_secs(60),
        Duration::from_secs(1),
    );
    let supervisor = ListenerSupervisor::new();

    let s1 = SharedListenerSettings {
        name: "health-override".to_string(),
        listener_type: ListenerType::Socks5,
        bind: "127.0.0.1:0".parse().unwrap(),
        auth_mode: AuthMode::None,
        global_password: None,
        default_strategy: PoolStrategy::RoundRobin,
        allow_anonymous: true,
        pool: TunnelPoolSelection::All,
        ip_mode: None,
    };
    let info1 = supervisor
        .start_shared_listener_with_health(&s1, &registry, &lifecycle, 1, Duration::from_secs(60))
        .await
        .unwrap();

    // One unresolvable-domain connect failure trips threshold=1 immediately.
    send_socks5_unresolvable_domain_connect(info1.address).await;
    assert_eq!(entry.health.current_status(), HealthStatus::Unhealthy);

    // Dynamic listener without override tracks lifecycle.set_health_check(...) dynamically.
    entry.health.reset();
    lifecycle.set_health_check(2, Duration::from_secs(45));
    let info2 = supervisor
        .start_shared_listener(&s1, &registry, &lifecycle)
        .await
        .unwrap();

    send_socks5_unresolvable_domain_connect(info2.address).await;
    assert_eq!(entry.health.current_status(), HealthStatus::Untested);
    send_socks5_unresolvable_domain_connect(info2.address).await;
    assert_eq!(entry.health.current_status(), HealthStatus::Unhealthy);

    supervisor.stop().await;
    lifecycle.stop().await;
}

#[tokio::test]
async fn test_router_registry_keyword_least_conn_and_all_unhealthy() {
    let registry = Arc::new(TunnelRegistry::new());
    let e1 = registry
        .register(TunnelEntry::new(
            "reg-a",
            make_test_tunnel_config("reg-a"),
            LifecycleMode::Lazy,
        ))
        .unwrap();
    let e2 = registry
        .register(TunnelEntry::new(
            "reg-b",
            make_test_tunnel_config("reg-b"),
            LifecycleMode::Lazy,
        ))
        .unwrap();
    let e3_disabled = registry
        .register(TunnelEntry::new(
            "reg-c-disabled",
            make_test_tunnel_config("reg-c-disabled"),
            LifecycleMode::Lazy,
        ))
        .unwrap();
    e1.stats.active_conns.store(5, Ordering::Relaxed);
    e2.stats.active_conns.store(1, Ordering::Relaxed);
    e3_disabled.stats.active_conns.store(0, Ordering::Relaxed);
    e3_disabled.set_disabled(true);

    let lifecycle = LifecycleController::new(
        Arc::clone(&registry),
        Duration::from_secs(60),
        Duration::from_secs(1),
    );
    let router = MultiTenantRouter::new(
        Arc::clone(&lifecycle),
        Arc::clone(&registry),
        PoolStrategy::RoundRobin,
        true,
    );

    let _t = router
        .select_tunnel(&TunnelSelector::ByKeyword(PoolKeyword::LeastConn), None)
        .await
        .unwrap();
    assert_eq!(e2.stats.active_conns.load(Ordering::Relaxed), 2);
    assert_eq!(e1.stats.active_conns.load(Ordering::Relaxed), 5);
    assert_eq!(e3_disabled.stats.active_conns.load(Ordering::Relaxed), 0);

    // Random and RoundRobin skip disabled tunnel.
    drop(_t);
    e2.health.mark_unhealthy(Duration::from_secs(60));
    let _t_rand = router
        .select_tunnel(&TunnelSelector::ByKeyword(PoolKeyword::Random), None)
        .await
        .unwrap();
    assert_eq!(e1.stats.active_conns.load(Ordering::Relaxed), 6);
    assert_eq!(e3_disabled.stats.active_conns.load(Ordering::Relaxed), 0);
    drop(_t_rand);

    e1.health.mark_unhealthy(Duration::from_secs(60));
    for kw in [
        PoolKeyword::LeastConn,
        PoolKeyword::RoundRobin,
        PoolKeyword::Random,
    ] {
        assert!(
            router
                .select_tunnel(&TunnelSelector::ByKeyword(kw), None)
                .await
                .is_err()
        );
    }

    lifecycle.stop().await;
}

#[tokio::test]
async fn test_dedicated_listeners_shift_and_skip_on_port_conflict() {
    use crate::config::PerTunnelSettings;
    use crate::config::toml_config::TunnelPortOverride;

    let occupied = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let busy_port = occupied.local_addr().unwrap().port();

    let registry = Arc::new(TunnelRegistry::new());
    for id in ["t-skip", "t-ok"] {
        registry
            .register(TunnelEntry::new(
                id,
                make_test_tunnel_config(id),
                LifecycleMode::Lazy,
            ))
            .unwrap();
    }
    let lifecycle = LifecycleController::new(
        Arc::clone(&registry),
        Duration::from_secs(60),
        Duration::from_secs(1),
    );
    let supervisor = ListenerSupervisor::new();

    // Explicit override on busy_port skips "t-skip" and shifts/starts "t-ok" without aborting.
    let mut overrides = std::collections::HashMap::new();
    overrides.insert(
        "t-skip".to_string(),
        TunnelPortOverride {
            socks5_port: Some(busy_port),
            http_port: None,
            password: None,
        },
    );
    let settings = PerTunnelSettings {
        enabled: true,
        base_socks5_port: Some(busy_port),
        base_http_port: None,
        overrides,
    };
    let started = supervisor
        .start_dedicated_listeners(
            &settings,
            None,
            "127.0.0.1".parse().unwrap(),
            &registry,
            &lifecycle,
        )
        .await
        .unwrap();

    assert_eq!(started.len(), 1);
    assert_eq!(started[0].tunnel_id.as_deref(), Some("t-ok"));
    assert_ne!(started[0].address.port(), busy_port);

    supervisor.stop().await;
    lifecycle.stop().await;
    drop(occupied);
}

#[tokio::test]
async fn test_dedicated_listener_requires_configured_global_password() {
    // Audit run-1 (high): a dedicated port must enforce the configured
    // global password when its tunnel has no own override password.
    let registry = Arc::new(TunnelRegistry::new());
    registry
        .register(TunnelEntry::new(
            "wgcf-auth-01",
            make_test_tunnel_config("wgcf-auth-01"),
            LifecycleMode::Lazy,
        ))
        .unwrap();
    let lifecycle = LifecycleController::new(
        Arc::clone(&registry),
        Duration::from_secs(60),
        Duration::from_secs(1),
    );
    let supervisor = ListenerSupervisor::new();

    let temp_listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = temp_listener.local_addr().unwrap().port();
    drop(temp_listener);

    let per_tunnel = PerTunnelSettings {
        enabled: true,
        base_socks5_port: Some(port),
        base_http_port: None,
        overrides: std::collections::HashMap::new(),
    };
    let started = supervisor
        .start_dedicated_listeners(
            &per_tunnel,
            Some("s3cret"),
            "127.0.0.1".parse().unwrap(),
            &registry,
            &lifecycle,
        )
        .await
        .expect("dedicated listener should start");
    assert_eq!(started.len(), 1);
    let addr = started[0].address;

    // No-auth greeting is refused: no acceptable method.
    let mut stream = tokio::net::TcpStream::connect(addr).await.unwrap();
    stream.write_all(&[5, 1, 0]).await.unwrap();
    let mut reply = [0u8; 2];
    stream.read_exact(&mut reply).await.unwrap();
    assert_eq!(reply, [5, 255]);

    // USERPASS with the tunnel id + global password succeeds.
    let mut stream = tokio::net::TcpStream::connect(addr).await.unwrap();
    stream.write_all(&[5, 1, 2]).await.unwrap();
    stream.read_exact(&mut reply).await.unwrap();
    assert_eq!(reply, [5, 2]);
    let mut auth_req = vec![1, 12];
    auth_req.extend_from_slice(b"wgcf-auth-01");
    auth_req.push(6);
    auth_req.extend_from_slice(b"s3cret");
    stream.write_all(&auth_req).await.unwrap();
    stream.read_exact(&mut reply).await.unwrap();
    assert_eq!(reply, [1, 0]);

    // Wrong password is rejected.
    let mut stream = tokio::net::TcpStream::connect(addr).await.unwrap();
    stream.write_all(&[5, 1, 2]).await.unwrap();
    stream.read_exact(&mut reply).await.unwrap();
    assert_eq!(reply, [5, 2]);
    let mut auth_req = vec![1, 12];
    auth_req.extend_from_slice(b"wgcf-auth-01");
    auth_req.push(6);
    auth_req.extend_from_slice(b"wrong1");
    stream.write_all(&auth_req).await.unwrap();
    stream.read_exact(&mut reply).await.unwrap();
    assert_eq!(reply, [1, 1]);

    supervisor.stop().await;
    lifecycle.stop().await;
}

#[tokio::test]
async fn test_dedicated_listener_fails_closed_when_tunnel_has_no_password() {
    // Audit run-1 (high): when a password is configured anywhere but a
    // tunnel has neither an override nor a global fallback, its dedicated
    // listener must not start unauthenticated.
    let registry = Arc::new(TunnelRegistry::new());
    for id in ["wgcf-locked-01", "wgcf-open-01"] {
        registry
            .register(TunnelEntry::new(
                id,
                make_test_tunnel_config(id),
                LifecycleMode::Lazy,
            ))
            .unwrap();
    }
    let lifecycle = LifecycleController::new(
        Arc::clone(&registry),
        Duration::from_secs(60),
        Duration::from_secs(1),
    );
    let supervisor = ListenerSupervisor::new();

    let temp_listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = temp_listener.local_addr().unwrap().port();
    drop(temp_listener);

    let mut overrides = std::collections::HashMap::new();
    overrides.insert(
        "wgcf-locked-01".to_string(),
        TunnelPortOverride {
            socks5_port: None,
            http_port: None,
            password: Some("l0cked".to_string()),
        },
    );
    let per_tunnel = PerTunnelSettings {
        enabled: true,
        base_socks5_port: Some(port),
        base_http_port: None,
        overrides,
    };
    let err = supervisor
        .start_dedicated_listeners(
            &per_tunnel,
            None,
            "127.0.0.1".parse().unwrap(),
            &registry,
            &lifecycle,
        )
        .await
        .expect_err("dedicated listener must fail closed for wgcf-open-01");
    assert!(
        err.to_string().contains("wgcf-open-01"),
        "error must name the unprotected tunnel: {err}"
    );

    supervisor.stop().await;
    lifecycle.stop().await;
}

#[tokio::test]
async fn test_start_without_listeners_skips_proxy_listeners() {
    let config = MainConfig::default();
    let manager = TunnelManager::new(config, vec![make_test_tunnel_config("wgcf-001")]).unwrap();
    manager
        .start_without_listeners()
        .await
        .expect("start without listeners should succeed");
    assert!(
        !manager.listeners().is_started(),
        "no proxy listener may start in VPN mode"
    );
    assert_eq!(manager.tunnel_count(), 1);
    manager.stop().await.expect("stop should succeed");
    assert!(!manager.listeners().is_started());
}

// =============================================================================
// VPN mode: protected UDP factory + TUN-endpoint boot
// =============================================================================

#[tokio::test]
async fn test_protected_udp_factory_protects_bound_socket() {
    use std::sync::Mutex as StdMutex;

    use gotatun::udp::{UdpTransportFactory, UdpTransportFactoryParams};

    use crate::core::protector::{ProtectedUdpFactory, SocketProtector};

    #[derive(Debug)]
    struct RecordingProtector {
        fds: Arc<StdMutex<Vec<i32>>>,
        accept: bool,
    }

    impl SocketProtector for RecordingProtector {
        fn protect(&self, fd: i32) -> bool {
            if let Ok(mut fds) = self.fds.lock() {
                fds.push(fd);
            }
            self.accept
        }
    }

    let params = UdpTransportFactoryParams {
        addr: Some("127.0.0.1".parse().unwrap()),
        port: 0,
        #[cfg(target_os = "linux")]
        fwmark: None,
    };

    // Accepting protector: bind succeeds and the socket fd is reported once.
    let recorded_fds: Arc<StdMutex<Vec<i32>>> = Arc::new(StdMutex::new(Vec::new()));
    let protector: Arc<dyn SocketProtector> = Arc::new(RecordingProtector {
        fds: Arc::clone(&recorded_fds),
        accept: true,
    });
    let mut factory = ProtectedUdpFactory::new(Arc::clone(&protector));
    let (_send, _recv) = factory.bind(&params).await.expect("bind must succeed");
    {
        let fds = recorded_fds.lock().expect("fds lock");
        assert_eq!(fds.len(), 1, "protect must be called exactly once per bind");
        assert!(fds[0] >= 0, "protected fd must be valid");
    };

    // Rejecting protector: bind fails, the socket is never handed out.
    let rejecting: Arc<dyn SocketProtector> = Arc::new(RecordingProtector {
        fds: Arc::new(StdMutex::new(Vec::new())),
        accept: false,
    });
    let mut factory = ProtectedUdpFactory::new(rejecting);
    assert!(
        factory.bind(&params).await.is_err(),
        "a rejected protect must fail the bind"
    );

    // No protector: bind succeeds unprotected.
    let mut factory = ProtectedUdpFactory::unprotected();
    assert!(
        factory.bind(&params).await.is_ok(),
        "unprotected factory must bind"
    );
}

#[tokio::test]
async fn test_protected_udp_factory_panicking_protector_fails_bind() {
    // Audit run-1, `uniffi:socket-protector-kotlin-exception-panics`:
    // a protector that panics (how a Kotlin exception surfaces
    // through the UniFFI callback) must fail the bind like a `false`
    // return, not unwind past the caller's cleanup.
    use gotatun::udp::{UdpTransportFactory, UdpTransportFactoryParams};

    use crate::core::protector::{ProtectedUdpFactory, SocketProtector};

    #[derive(Debug)]
    struct PanickingProtector;
    impl SocketProtector for PanickingProtector {
        fn protect(&self, _fd: i32) -> bool {
            panic!("simulated Kotlin exception in protect()");
        }
    }

    let params = UdpTransportFactoryParams {
        addr: Some("127.0.0.1".parse().unwrap()),
        port: 0,
        #[cfg(target_os = "linux")]
        fwmark: None,
    };
    let panicking: Arc<dyn SocketProtector> = Arc::new(PanickingProtector);
    let mut factory = ProtectedUdpFactory::new(panicking);
    let err = match factory.bind(&params).await {
        Ok(_) => panic!("a panicking protect must fail the bind"),
        Err(err) => err,
    };
    assert!(
        err.to_string().contains("panicked"),
        "error must name the panic, got: {err}"
    );
}

#[tokio::test]
async fn test_vpn_mode_boot_has_no_netstack_and_uses_tun_endpoint() {
    use std::os::fd::OwnedFd;
    use std::os::unix::net::UnixStream;

    use crate::core::protector::SocketProtector;
    use crate::core::{EgressProbeOutcome, WgDevice};
    use crate::netstack::TunEndpoint;

    #[derive(Debug)]
    struct AcceptingProtector;
    impl SocketProtector for AcceptingProtector {
        fn protect(&self, _fd: i32) -> bool {
            true
        }
    }

    let registry = Arc::new(TunnelRegistry::new());
    registry
        .register(TunnelEntry::new(
            "wgcf-vpn-01",
            make_test_tunnel_config("wgcf-vpn-01"),
            LifecycleMode::Lazy,
        ))
        .unwrap();
    let lifecycle = LifecycleController::new(
        Arc::clone(&registry),
        Duration::from_secs(60),
        Duration::from_secs(1),
    );

    // A socketpair stands in for the Android TUN fd.
    let (tun_side, _peer_side) = UnixStream::pair().expect("socketpair for TUN test");
    let endpoint =
        TunEndpoint::from_owned_fd(OwnedFd::from(tun_side), 1420).expect("endpoint from fd");
    endpoint.start_dispatcher().expect("dispatcher starts");
    lifecycle.set_vpn_mode(true);
    lifecycle.set_tun_endpoint(Some(Arc::clone(&endpoint)));
    // VPN-mode boot fails closed without a protector (audit run-1,
    // `uniffi:vpn-mode-unprotected-udp-fallback`).
    lifecycle.set_socket_protector(Arc::new(AcceptingProtector));
    assert!(lifecycle.vpn_mode());

    let active = lifecycle
        .activate_tunnel("wgcf-vpn-01")
        .await
        .expect("VPN-mode activation must succeed");
    assert!(
        active.netstack.is_none(),
        "VPN mode builds no smoltcp stack"
    );
    assert!(
        matches!(active.device, WgDevice::Vpn(_)),
        "VPN mode must boot the TUN device variant"
    );
    // No netstack means no data-plane check is available: egress is
    // unverified, never a vacuous success (audit run-1,
    // `core/probe_egress:vpn-mode-noop-success`).
    assert_eq!(
        active
            .probe_egress(Duration::from_secs(1))
            .await
            .expect("probe_egress must not fail"),
        EgressProbeOutcome::Unverified
    );

    // Suspend drops the route; resume re-adds it on the same device.
    lifecycle
        .suspend_tunnel("wgcf-vpn-01")
        .await
        .expect("suspend must succeed");
    assert_eq!(
        *registry
            .get("wgcf-vpn-01")
            .expect("tunnel must exist")
            .state
            .read(),
        TunnelState::Suspended
    );
    let resumed = lifecycle
        .activate_tunnel("wgcf-vpn-01")
        .await
        .expect("resume must succeed");
    assert!(
        Arc::ptr_eq(&active, &resumed),
        "resume keeps the same device"
    );
    assert!(resumed.netstack.is_none());

    lifecycle
        .close_tunnel("wgcf-vpn-01")
        .await
        .expect("close must succeed");
    endpoint.shutdown().await;
}

#[tokio::test]
async fn test_migrate_proxy_tunnels_to_vpn_reboots_active_tunnel() {
    // Audit run-1,
    // `uniffi:attach-order-pre-attach-proxy-boot-never-migrates-to-tun`:
    // a tunnel booted in proxy mode before `attach_tun` must be
    // closed and re-booted on the TUN endpoint, not left proxy-booted
    // forever.
    use std::os::fd::OwnedFd;
    use std::os::unix::net::UnixStream;

    use crate::core::WgDevice;
    use crate::core::protector::SocketProtector;
    use crate::netstack::TunEndpoint;

    #[derive(Debug)]
    struct AcceptingProtector;
    impl SocketProtector for AcceptingProtector {
        fn protect(&self, _fd: i32) -> bool {
            true
        }
    }

    let registry = Arc::new(TunnelRegistry::new());
    registry
        .register(TunnelEntry::new(
            "wgcf-mig-01",
            make_test_tunnel_config("wgcf-mig-01"),
            LifecycleMode::Lazy,
        ))
        .unwrap();
    let lifecycle = LifecycleController::new(
        Arc::clone(&registry),
        Duration::from_secs(60),
        Duration::from_secs(1),
    );

    let active = lifecycle
        .activate_tunnel("wgcf-mig-01")
        .await
        .expect("proxy activation must succeed");
    assert!(
        matches!(active.device, WgDevice::Proxy(_)),
        "tunnel must start proxy-booted"
    );
    assert!(active.netstack.is_some(), "proxy mode builds a netstack");

    let (tun_side, _peer_side) = UnixStream::pair().expect("socketpair for TUN test");
    let endpoint =
        TunEndpoint::from_owned_fd(OwnedFd::from(tun_side), 1420).expect("endpoint from fd");
    endpoint.start_dispatcher().expect("dispatcher starts");
    lifecycle.set_socket_protector(Arc::new(AcceptingProtector));
    lifecycle.set_vpn_mode(true);
    lifecycle.set_tun_endpoint(Some(Arc::clone(&endpoint)));

    let migrated = lifecycle
        .migrate_proxy_tunnels_to_vpn()
        .await
        .expect("migration must succeed");
    assert_eq!(migrated, vec!["wgcf-mig-01".to_string()]);
    let active = registry
        .get("wgcf-mig-01")
        .expect("tunnel must exist")
        .active
        .read()
        .clone()
        .expect("tunnel must still be active after migration");
    assert!(
        matches!(active.device, WgDevice::Vpn(_)),
        "tunnel must be VPN-booted after migration"
    );
    assert!(active.netstack.is_none(), "VPN mode builds no netstack");

    lifecycle
        .close_tunnel("wgcf-mig-01")
        .await
        .expect("close must succeed");
    endpoint.shutdown().await;
}

#[tokio::test]
async fn test_vpn_mode_boot_without_protector_fails_closed() {
    // Audit run-1, `uniffi:vpn-mode-unprotected-udp-fallback`:
    // booting a VPN-mode tunnel with no socket protector installed
    // must fail activation instead of binding unprotected sockets.
    use std::os::fd::OwnedFd;
    use std::os::unix::net::UnixStream;

    use crate::netstack::TunEndpoint;

    let registry = Arc::new(TunnelRegistry::new());
    registry
        .register(TunnelEntry::new(
            "wgcf-vpn-02",
            make_test_tunnel_config("wgcf-vpn-02"),
            LifecycleMode::Lazy,
        ))
        .unwrap();
    let lifecycle = LifecycleController::new(
        Arc::clone(&registry),
        Duration::from_secs(60),
        Duration::from_secs(1),
    );
    let (tun_side, _peer_side) = UnixStream::pair().expect("socketpair for TUN test");
    let endpoint =
        TunEndpoint::from_owned_fd(OwnedFd::from(tun_side), 1420).expect("endpoint from fd");
    endpoint.start_dispatcher().expect("dispatcher starts");
    lifecycle.set_vpn_mode(true);
    lifecycle.set_tun_endpoint(Some(Arc::clone(&endpoint)));

    let err = lifecycle
        .activate_tunnel("wgcf-vpn-02")
        .await
        .expect_err("VPN-mode activation without a protector must fail");
    assert!(
        err.to_string().contains("protector"),
        "error must name the missing protector, got: {err}"
    );
    assert_eq!(
        *registry
            .get("wgcf-vpn-02")
            .expect("tunnel must exist")
            .state
            .read(),
        TunnelState::Dormant,
        "a failed boot must leave the tunnel dormant"
    );
    endpoint.shutdown().await;
}

// =============================================================================
// Stratified P2C + Peak EWMA selection, warm list, inflight guard,
// boot warm-up complement (racing + selection fixes, Fase 1)
// =============================================================================

#[test]
fn test_dormant_surcharge_zones() {
    assert_eq!(dormant_surcharge_ms(0, 0), 0);
    assert_eq!(dormant_surcharge_ms(90, 0), 0);
    assert_eq!(dormant_surcharge_ms(91, 0), 5);
    assert_eq!(dormant_surcharge_ms(105, 0), 75);
    assert_eq!(dormant_surcharge_ms(120, 0), 150);
    assert_eq!(dormant_surcharge_ms(121, 0), 800);
    assert_eq!(dormant_surcharge_ms(121, 200), 1000);
    assert_eq!(dormant_surcharge_ms(10_000, 37), 837);
}

#[test]
fn test_slow_start_weight_clamped_to_unit() {
    assert!((slow_start_weight(0) - 0.1).abs() < f64::EPSILON);
    assert!((slow_start_weight(30) - 0.5).abs() < f64::EPSILON);
    assert!((slow_start_weight(60) - 1.0).abs() < f64::EPSILON);
    // Without the clamp an old tunnel would weigh > 1 and score
    // below its unweighted latency, dominating purely by age.
    assert!((slow_start_weight(3600) - 1.0).abs() < f64::EPSILON);
}

#[test]
fn test_tunnel_score_combines_latency_surcharge_load_weight() {
    // Warm, fast, idle: score is the raw EWMA.
    assert!((tunnel_score(50, 10, 0, 1.0, 0) - 50.0).abs() < f64::EPSILON);
    // Dormant: +800 surcharge.
    assert!((tunnel_score(50, 1000, 0, 1.0, 0) - 850.0).abs() < f64::EPSILON);
    // Three sessions in flight quadruple the score.
    assert!((tunnel_score(50, 10, 3, 1.0, 0) - 200.0).abs() < f64::EPSILON);
    // Slow-start at 10% weight multiplies the score by ten.
    assert!((tunnel_score(50, 10, 0, 0.1, 0) - 500.0).abs() < f64::EPSILON);
    // No sample yet falls back to the default RTT.
    assert!((tunnel_score(0, 10, 0, 1.0, 0) - 100.0).abs() < f64::EPSILON);
}

#[test]
fn test_peak_ewma_alpha_and_failure_tau() {
    let stats = TunnelStats::new();
    stats.record_rtt_sample(100);
    assert_eq!(stats.rtt_ewma_ms.load(Ordering::Relaxed), 100);
    stats.record_rtt_sample(200);
    // alpha 0.2: 0.2*200 + 0.8*100 = 120.
    assert_eq!(stats.rtt_ewma_ms.load(Ordering::Relaxed), 120);
    stats.record_rtt_failure();
    // Failure counts as a tau (10 s) sample: 0.2*10000 + 0.8*120 = 2096.
    assert_eq!(stats.rtt_ewma_ms.load(Ordering::Relaxed), 2096);
    stats.record_rtt_sample(0);
    // Samples clamp to 1 ms: (1 + 4*2096) / 5 = 1677.
    assert_eq!(stats.rtt_ewma_ms.load(Ordering::Relaxed), 1677);
    stats.record_rtt_sample(99_999);
    // Samples clamp to tau: (10000 + 4*1677) / 5 = 3341.
    assert_eq!(stats.rtt_ewma_ms.load(Ordering::Relaxed), 3341);
}

#[test]
fn test_warm_list_bounded_most_recent_first_and_o1_pick() {
    let warm = WarmList::new();
    assert!(warm.is_empty());
    for i in 0..20 {
        warm.note_success(&format!("wgcf-{i:03}"));
    }
    assert_eq!(warm.len(), 12);
    let snapshot = warm.snapshot();
    assert_eq!(snapshot[0], "wgcf-019");
    assert_eq!(snapshot[11], "wgcf-008");
    // Re-noting an existing member moves it to the front without growing.
    warm.note_success("wgcf-010");
    assert_eq!(warm.len(), 12);
    assert_eq!(warm.snapshot()[0], "wgcf-010");
    // Picks stay inside the membership.
    for _ in 0..50 {
        let picked = warm.pick().expect("non-empty warm list must pick");
        assert!(warm.snapshot().contains(&picked));
    }
}

#[test]
fn test_warm_list_note_failure_drops_member() {
    let warm = WarmList::new();
    warm.note_success("wgcf-001");
    warm.note_success("wgcf-002");
    warm.note_success("wgcf-003");
    warm.note_failure("wgcf-002");
    let snapshot = warm.snapshot();
    assert_eq!(snapshot.len(), 2);
    assert_eq!(snapshot[0], "wgcf-003");
    assert_eq!(snapshot[1], "wgcf-001");
    // Dropping a non-member is a no-op.
    warm.note_failure("wgcf-999");
    assert_eq!(warm.len(), 2);
}

#[test]
fn test_inflight_guard_releases_exactly_once_and_never_underflows() {
    let stats = Arc::new(TunnelStats::new());
    assert_eq!(stats.active_conns.load(Ordering::SeqCst), 0);
    let guard_a = TunnelConnGuard::new("tun-guard", Arc::clone(&stats));
    let guard_b = TunnelConnGuard::new("tun-guard", Arc::clone(&stats));
    assert_eq!(stats.active_conns.load(Ordering::SeqCst), 2);
    drop(guard_a);
    assert_eq!(stats.active_conns.load(Ordering::SeqCst), 1);
    drop(guard_b);
    assert_eq!(stats.active_conns.load(Ordering::SeqCst), 0);
    // A stray decrement at zero stays at zero: the counter cannot
    // underflow even if a release path runs twice.
    stats.dec_conns();
    assert_eq!(stats.active_conns.load(Ordering::SeqCst), 0);
}

#[test]
fn test_score_entry_slow_start_ramp_from_activation() {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("system time before epoch")
        .as_secs();
    let fresh = TunnelEntry::new(
        "fresh",
        make_test_tunnel_config("fresh"),
        LifecycleMode::Lazy,
    );
    let old = TunnelEntry::new("old", make_test_tunnel_config("old"), LifecycleMode::Lazy);
    for entry in [&fresh, &old] {
        entry.stats.record_handshake(now);
        entry.stats.record_rtt_sample(50);
    }
    // Same latency and freshness; only the admission instant differs.
    fresh.stats.record_activated(now);
    old.stats.record_activated(now - 3600);
    let fresh_score = score_entry(&fresh, now, 0);
    let old_score = score_entry(&old, now, 0);
    // Freshly admitted: 10% weight, score 10x the old tunnel's.
    assert!((fresh_score - 500.0).abs() < f64::EPSILON);
    assert!((old_score - 50.0).abs() < f64::EPSILON);
    assert!(fresh_score > old_score);
}

#[test]
fn test_warm_up_complement_ids_tops_up_to_eight_sorted() {
    let eager: Vec<String> = vec!["wgcf-001".into(), "wgcf-003".into()];
    let all: Vec<String> = (1..=10).map(|i| format!("wgcf-{i:03}")).collect();
    assert_eq!(
        warm_up_complement_ids(&eager, &all),
        vec![
            "wgcf-002", "wgcf-004", "wgcf-005", "wgcf-006", "wgcf-007", "wgcf-008",
        ]
    );
    // Eight or more eager tunnels need no complement.
    let eager8: Vec<String> = (1..=8).map(|i| format!("wgcf-{i:03}")).collect();
    assert!(warm_up_complement_ids(&eager8, &all).is_empty());
    // No eager tunnels: the eight lowest ids.
    assert_eq!(
        warm_up_complement_ids(&[], &all),
        (1..=8).map(|i| format!("wgcf-{i:03}")).collect::<Vec<_>>()
    );
}

#[tokio::test]
async fn test_p2c_prefers_warm_low_ewma_over_dormant() {
    let registry = Arc::new(TunnelRegistry::new());
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("system time before epoch")
        .as_secs();
    // t1: warm (fresh handshake, fast EWMA, admitted long ago).
    let e1 = registry
        .register(TunnelEntry::new(
            "t1",
            make_test_tunnel_config("t1"),
            LifecycleMode::Lazy,
        ))
        .unwrap();
    e1.stats.record_handshake(now);
    e1.stats.record_rtt_sample(50);
    e1.stats.record_activated(now - 3600);
    // t2: dormant (stale handshake) with the same EWMA.
    let e2 = registry
        .register(TunnelEntry::new(
            "t2",
            make_test_tunnel_config("t2"),
            LifecycleMode::Lazy,
        ))
        .unwrap();
    e2.stats.record_handshake(now - 1000);
    e2.stats.record_rtt_sample(50);
    e2.stats.record_activated(now - 3600);
    // t3: unproven, never handshaked.
    let _e3 = registry
        .register(TunnelEntry::new(
            "t3",
            make_test_tunnel_config("t3"),
            LifecycleMode::Lazy,
        ))
        .unwrap();
    _e3.stats.record_activated(now - 3600);

    let lifecycle = LifecycleController::new(
        Arc::clone(&registry),
        Duration::from_secs(60),
        Duration::from_secs(1),
    );
    let router = MultiTenantRouter::new(
        Arc::clone(&lifecycle),
        Arc::clone(&registry),
        PoolStrategy::RoundRobin,
        true,
    );
    router.note_warm_success("t1");

    // The warm list always yields t1 as candidate A; candidate B
    // draws t2/t3 at random, both scoring far worse (800 ms dormant
    // surcharge), so t1 wins every draw.
    for _ in 0..30 {
        assert_eq!(router.select_p2c(None).unwrap(), "t1");
    }

    // Eject t1: it must never be selected again, and the pick falls
    // to the remaining tunnels.
    e1.health.mark_unhealthy(Duration::from_secs(60));
    assert!(!e1.health.is_routable());
    for _ in 0..30 {
        let picked = router.select_p2c(None).unwrap();
        assert!(
            picked == "t2" || picked == "t3",
            "ejected t1 must never be picked, got {picked}"
        );
    }

    lifecycle.stop().await;
}

#[tokio::test]
async fn test_p2c_auto_keyword_selects_warm_tunnel() {
    let registry = Arc::new(TunnelRegistry::new());
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("system time before epoch")
        .as_secs();
    let e1 = registry
        .register(TunnelEntry::new(
            "t1",
            make_test_tunnel_config("t1"),
            LifecycleMode::Lazy,
        ))
        .unwrap();
    e1.stats.record_handshake(now);
    e1.stats.record_rtt_sample(50);
    e1.stats.record_activated(now - 3600);
    let e2 = registry
        .register(TunnelEntry::new(
            "t2",
            make_test_tunnel_config("t2"),
            LifecycleMode::Lazy,
        ))
        .unwrap();
    e2.stats.record_handshake(now - 1000);
    e2.stats.record_rtt_sample(50);
    e2.stats.record_activated(now - 3600);

    let lifecycle = LifecycleController::new(
        Arc::clone(&registry),
        Duration::from_secs(60),
        Duration::from_secs(1),
    );
    let router = MultiTenantRouter::new(
        Arc::clone(&lifecycle),
        Arc::clone(&registry),
        PoolStrategy::RoundRobin,
        true,
    );
    router.note_warm_success("t1");

    // The `auto` keyword routes through P2C, so the warm tunnel is
    // selected and activated; the dormant one stays dormant.
    let target = router
        .select_tunnel(&TunnelSelector::ByKeyword(PoolKeyword::Auto), None)
        .await
        .expect("auto selection must succeed");
    assert_eq!(target.tunnel_id(), Some("t1"));
    assert!(registry.get("t1").unwrap().is_active());
    assert!(!registry.get("t2").unwrap().is_active());
    drop(target);

    lifecycle.stop().await;
}

// =============================================================================
// P2C loser HalfOpen trial-slot release (run-3 #3)
// =============================================================================

async fn p2c_halfopen_setup(
    t1_fresh: bool,
    t2_fresh: bool,
) -> (
    Arc<TunnelRegistry>,
    Arc<MultiTenantRouter>,
    Arc<LifecycleController>,
) {
    let registry = Arc::new(TunnelRegistry::new());
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("system time before epoch")
        .as_secs();
    for (id, fresh) in [("t1", t1_fresh), ("t2", t2_fresh)] {
        let entry = registry
            .register(TunnelEntry::new(
                id,
                make_test_tunnel_config(id),
                LifecycleMode::Lazy,
            ))
            .unwrap();
        if fresh {
            entry.stats.record_handshake(now);
        } else {
            entry.stats.record_handshake(now - 1000);
        }
        entry.stats.record_rtt_sample(50);
        entry.stats.record_activated(now - 3600);
        // Force HalfOpen without claiming the trial slot.
        entry.health.mark_unhealthy(Duration::from_millis(1));
        tokio::time::sleep(Duration::from_millis(10)).await;
        assert_eq!(
            entry.health.current_status(),
            HealthStatus::HalfOpen,
            "{id} must be HalfOpen before selection"
        );
        assert!(
            entry.health.can_route(),
            "{id} must be routable before selection (no slot claimed yet)"
        );
    }
    let lifecycle = LifecycleController::new(
        Arc::clone(&registry),
        Duration::from_secs(60),
        Duration::from_secs(1),
    );
    let router = MultiTenantRouter::new(
        Arc::clone(&lifecycle),
        Arc::clone(&registry),
        PoolStrategy::RoundRobin,
        true,
    );
    router.note_warm_success("t1");
    (registry, router, lifecycle)
}

/// Loser drawn from the random draw: warm-list t1 is fresh (wins),
/// random-draw t2 is dormant (loses). After select_p2c the loser
/// must still be routable — its trial slot must have been released.
#[tokio::test]
async fn test_p2c_loser_from_random_draw_releases_halfopen_slot() {
    let (registry, router, lifecycle) = p2c_halfopen_setup(true, false).await;
    let picked = router
        .select_p2c(Some(&["t2".to_string()]))
        .expect("selection must succeed with two HalfOpen tunnels");
    assert_eq!(picked, "t1", "fresh warm-list tunnel must win");
    let t1 = registry.get("t1").unwrap();
    let t2 = registry.get("t2").unwrap();
    assert!(
        !t1.health.can_route(),
        "winner t1 legitimately holds its trial slot for the caller"
    );
    assert!(
        t2.health.can_route(),
        "loser t2 (random draw) must be routable again: its HalfOpen trial slot must be released by select_p2c"
    );
    lifecycle.stop().await;
}

/// Loser drawn from the warm list: warm-list t1 is dormant (loses),
/// random-draw t2 is fresh (wins). After select_p2c the warm-list
/// loser must still be routable.
#[tokio::test]
async fn test_p2c_loser_from_warm_list_releases_halfopen_slot() {
    let (registry, router, lifecycle) = p2c_halfopen_setup(false, true).await;
    let picked = router
        .select_p2c(Some(&["t2".to_string()]))
        .expect("selection must succeed with two HalfOpen tunnels");
    assert_eq!(picked, "t2", "fresh random-draw tunnel must win");
    let t1 = registry.get("t1").unwrap();
    let t2 = registry.get("t2").unwrap();
    assert!(
        !t2.health.can_route(),
        "winner t2 legitimately holds its trial slot for the caller"
    );
    assert!(
        t1.health.can_route(),
        "loser t1 (warm list) must be routable again: its HalfOpen trial slot must be released by select_p2c"
    );
    lifecycle.stop().await;
}

/// Regression (audit run-3 #8): both halves of a dedicated router's
/// credential pair must be checked — a wrong username and a wrong
/// password are both plain rejections, with no short-circuit between
/// the two comparisons.
#[test]
fn test_dedicated_router_authenticate_checks_both_halves() {
    let registry = Arc::new(TunnelRegistry::new());
    let lifecycle = LifecycleController::new(
        Arc::clone(&registry),
        Duration::from_secs(60),
        Duration::from_secs(1),
    );
    let router = DedicatedTunnelRouter::new(
        "wgcf-dedicated-01",
        lifecycle,
        Some(("admin".to_string(), "secret123".to_string())),
    );
    assert_eq!(
        router.authenticate(Some(("admin", "secret123"))),
        Ok(TunnelSelector::ById("wgcf-dedicated-01".to_string()))
    );
    assert_eq!(
        router.authenticate(Some(("wrong-user", "secret123"))),
        Err(ProxyAuthError::InvalidCredentials)
    );
    assert_eq!(
        router.authenticate(Some(("admin", "wrong-pass"))),
        Err(ProxyAuthError::InvalidCredentials)
    );
    assert_eq!(
        router.authenticate(Some(("wrong-user", "wrong-pass"))),
        Err(ProxyAuthError::InvalidCredentials)
    );
    assert_eq!(router.authenticate(None), Err(ProxyAuthError::AuthRequired));
}

// =============================================================================
// Per-source-IP fairness (audit run-3, #5)
// =============================================================================

/// Open a TCP connection to `port` from the given loopback source IP
/// (`127.0.0.1` vs `127.0.0.2` are distinct peers on Linux loopback),
/// so the test can act as two different source IPs.
async fn connect_from(source: std::net::IpAddr, port: u16) -> tokio::net::TcpStream {
    let socket = tokio::net::TcpSocket::new_v4().expect("loopback tcp socket");
    socket
        .bind(std::net::SocketAddr::new(source, 0))
        .expect("bind loopback source address");
    socket
        .connect(std::net::SocketAddr::new(
            "127.0.0.1".parse().unwrap(),
            port,
        ))
        .await
        .expect("connect to test listener")
}

/// Send a SOCKS5 no-auth greeting and expect the `[0x05, 0x00]`
/// method-selection reply: proof the server accepted the connection
/// and is holding it as a live session.
async fn socks5_greet_no_auth(stream: &mut tokio::net::TcpStream) {
    stream
        .write_all(&[0x05, 0x01, 0x00])
        .await
        .expect("write socks5 greeting");
    let mut reply = [0u8; 2];
    stream
        .read_exact(&mut reply)
        .await
        .expect("read socks5 method reply");
    assert_eq!(reply, [0x05, 0x00], "server must select no-auth");
}

#[test]
fn test_per_ip_tracker_caps_one_ip_and_releases_on_drop() {
    // Pinning test for the per-IP slot accounting (not the regression
    // test itself): the cap binds per IP, a released slot is reusable,
    // and another IP is unaffected while the first is at its cap.
    let tracker = Arc::new(PerIpConnTracker::default());
    let greedy: std::net::IpAddr = "127.0.0.1".parse().unwrap();
    let other: std::net::IpAddr = "127.0.0.2".parse().unwrap();

    let mut slots = Vec::with_capacity(MAX_CONNS_PER_SOURCE_IP);
    for _ in 0..MAX_CONNS_PER_SOURCE_IP {
        let slot = tracker.try_acquire(greedy);
        assert!(slot.is_some(), "slot below the per-IP cap must succeed");
        slots.push(slot.unwrap());
    }
    assert!(
        tracker.try_acquire(greedy).is_none(),
        "one slot past the per-IP cap must be refused"
    );
    assert!(
        tracker.try_acquire(other).is_some(),
        "another IP must still get a slot while the first is at its cap"
    );

    // Releasing one slot frees it immediately: no permanent lockout.
    slots.pop();
    assert!(
        tracker.try_acquire(greedy).is_some(),
        "a released slot must be reusable by the same IP"
    );
}

#[tokio::test]
async fn test_per_source_ip_fairness_greedy_ip_cannot_starve_other_ip() {
    // Regression test for audit run-3, #5: without per-IP fairness a
    // single source IP could hold the whole 4096-permit global budget
    // and starve every other IP. With the fix, the greedy IP is capped
    // at MAX_CONNS_PER_SOURCE_IP, its next connection is closed
    // promptly, and another IP is still served.
    //
    // On the old code this test fails at the 257th-connection
    // assertion: the over-cap connection stays open (the server waits
    // for its SOCKS5 greeting) until the 5 s read timeout fires.
    let registry = Arc::new(TunnelRegistry::new());
    let lifecycle = LifecycleController::new(
        Arc::clone(&registry),
        Duration::from_secs(60),
        Duration::from_secs(1),
    );
    let supervisor = ListenerSupervisor::new();
    let settings = SharedListenerSettings {
        name: "fairness-test".to_string(),
        listener_type: ListenerType::Socks5,
        bind: std::net::SocketAddr::new("127.0.0.1".parse().unwrap(), 0),
        auth_mode: AuthMode::None,
        global_password: None,
        default_strategy: PoolStrategy::default(),
        allow_anonymous: true,
        pool: TunnelPoolSelection::default(),
        ip_mode: None,
    };
    let info = supervisor
        .start_shared_listener(&settings, &registry, &lifecycle)
        .await
        .expect("shared test listener should start");
    let port = info.address.port();

    let greedy: std::net::IpAddr = "127.0.0.1".parse().unwrap();
    let other: std::net::IpAddr = "127.0.0.2".parse().unwrap();

    // Fill the greedy IP's whole per-IP share with live sessions; each
    // greeting reply proves the server accepted and holds that session.
    let mut greedy_sessions = Vec::with_capacity(MAX_CONNS_PER_SOURCE_IP);
    for _ in 0..MAX_CONNS_PER_SOURCE_IP {
        let mut stream = connect_from(greedy, port).await;
        socks5_greet_no_auth(&mut stream).await;
        greedy_sessions.push(stream);
    }

    // One more connection from the greedy IP must be closed promptly
    // instead of being held as a session.
    let mut over_cap = connect_from(greedy, port).await;
    let mut byte = [0u8; 1];
    let closed = tokio::time::timeout(Duration::from_secs(5), over_cap.read(&mut byte)).await;
    assert!(
        matches!(closed, Ok(Ok(0))),
        "over-cap connection from the greedy IP must be closed promptly, got {closed:?}"
    );
    drop(over_cap);

    // Another IP is still served while the greedy IP is at its cap.
    let mut other_stream = connect_from(other, port).await;
    socks5_greet_no_auth(&mut other_stream).await;
    drop(other_stream);

    // Releasing one greedy session frees its slot: no permanent lockout.
    greedy_sessions.pop();
    let mut recovered = connect_from(greedy, port).await;
    socks5_greet_no_auth(&mut recovered).await;

    drop(recovered);
    drop(greedy_sessions);
    supervisor.stop().await;
}
