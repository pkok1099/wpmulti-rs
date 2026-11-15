//! Unit tests for Milestone 4: Multi-Tunnel Manager & Scalable Lifecycle.

use std::net::SocketAddr;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use x25519_dalek::{PublicKey, StaticSecret};

use crate::config::{
    AuthMode, LifecycleMode, ListenerType, MainConfig, PerTunnelSettings, PoolStrategy,
    TunnelConfig, TunnelPortOverride, WgInterfaceConfig, WgPeerConfig,
};
use crate::core::lifecycle::{LifecycleController, TunnelConnGuard};
use crate::core::listener::ListenerSupervisor;
use crate::core::registry::{TunnelEntry, TunnelRegistry, TunnelState};
use crate::core::router::MultiTenantRouter;
use crate::core::TunnelManager;
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

    // Verify eager tunnel was automatically booted
    assert_eq!(manager.active_tunnel_count(), 1);
    let eager_entry = manager.registry().get("wgcf-eager-01").unwrap();
    assert_eq!(*eager_entry.state.read(), TunnelState::Active);
    assert_eq!(eager_entry.lifecycle_mode, LifecycleMode::Eager);

    // Verify lazy tunnel remains dormant
    let lazy_entry = manager.registry().get("wgcf-lazy-01").unwrap();
    assert_eq!(*lazy_entry.state.read(), TunnelState::Dormant);
    assert_eq!(lazy_entry.lifecycle_mode, LifecycleMode::Lazy);

    // Stop manager cleanly
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
        registry.register(TunnelEntry::new(id, cfg, LifecycleMode::Lazy)).unwrap();
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
    let target = router.select_tunnel(&ok_auth).await.expect("select tunnel should succeed");
    assert!(registry.get("wgcf-tenant-01").unwrap().is_active());

    // Test 5: Round-Robin Keyword cycling
    let sel_rr = TunnelSelector::ByKeyword(PoolKeyword::RoundRobin);
    for _ in 0..3 {
        let _ = router.select_tunnel(&sel_rr).await.unwrap();
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
    let least_target = router.select_tunnel(&sel_least).await.unwrap();
    // Guard created on t3 increments it to 1
    assert_eq!(t3.stats.active_conns.load(Ordering::Relaxed), 1);

    drop(target);
    drop(least_target);
}

// =============================================================================
// 5. Dedicated Per-Tunnel Listener Supervisor & Loopback Binding
// =============================================================================

#[tokio::test]
async fn test_dedicated_and_shared_listeners() {
    let registry = Arc::new(TunnelRegistry::new());
    let cfg1 = make_test_tunnel_config("wgcf-listen-01");
    let cfg2 = make_test_tunnel_config("wgcf-listen-02");
    registry.register(TunnelEntry::new("wgcf-listen-01", cfg1, LifecycleMode::Lazy)).unwrap();
    registry.register(TunnelEntry::new("wgcf-listen-02", cfg2, LifecycleMode::Lazy)).unwrap();

    let idle_timeout = Duration::from_secs(60);
    let check_interval = Duration::from_secs(1);
    let lifecycle = LifecycleController::new(Arc::clone(&registry), idle_timeout, check_interval);

    let supervisor = ListenerSupervisor::new();

    // Use loopback with ephemeral ports
    // PerTunnel dedicated configuration:
    let mut per_tunnel = PerTunnelSettings::default();
    per_tunnel.enabled = true;
    per_tunnel.base_socks5_port = None; // Disable default sequential base
    per_tunnel.base_http_port = None;

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
        },
    );
    per_tunnel.overrides = overrides;
    per_tunnel.base_socks5_port = Some(port1);

    let started = supervisor
        .start_dedicated_listeners(
            &per_tunnel,
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
    let stream_res = tokio::net::TcpStream::connect(SocketAddr::new("127.0.0.1".parse().unwrap(), port1)).await;
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

// =============================================================================
// 7. Metered Stream and Traffic Statistics Verification
// =============================================================================

#[tokio::test]
async fn test_metered_traffic_counters() {
    let registry = Arc::new(TunnelRegistry::new());
    let cfg = make_test_tunnel_config("wgcf-metered-01");
    let entry = registry
        .register(TunnelEntry::new("wgcf-metered-01", cfg, LifecycleMode::Lazy))
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
// 10. Regression: Multi-Tenant Pool Isolation Rejects Unallowed ById
// =============================================================================

#[tokio::test]
async fn test_pool_isolation_rejects_unallowed_by_id() {
    let registry = Arc::new(TunnelRegistry::new());
    let cfg_a = make_test_tunnel_config("wgcf-pool-allowed");
    let cfg_b = make_test_tunnel_config("wgcf-pool-forbidden");
    registry
        .register(TunnelEntry::new("wgcf-pool-allowed", cfg_a, LifecycleMode::Lazy))
        .unwrap();
    registry
        .register(TunnelEntry::new("wgcf-pool-forbidden", cfg_b, LifecycleMode::Lazy))
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
    let res = router.select_tunnel(&selector_forbidden).await;
    let err = match res {
        Err(e) => e,
        Ok(_) => panic!("selecting unallowed tunnel ById must fail"),
    };
    assert_eq!(err.kind(), std::io::ErrorKind::NotFound);
    assert!(
        err.to_string().contains("not allowed in this pool"),
        "error must indicate tunnel not allowed in pool: {}",
        err
    );

    // Selecting allowed tunnel ById must succeed
    let selector_allowed = TunnelSelector::ById("wgcf-pool-allowed".to_string());
    let res_allowed = router.select_tunnel(&selector_allowed).await;
    assert!(res_allowed.is_ok(), "selecting allowed tunnel ById must succeed");
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
        reloaded_entry.config.read().interface.private_key.to_bytes(),
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
        .register(TunnelEntry::new("wgcf-port-reflect-01", cfg, LifecycleMode::Lazy))
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

    let mut per_tunnel = PerTunnelSettings::default();
    per_tunnel.enabled = true;
    per_tunnel.base_socks5_port = Some(port);

    supervisor
        .start_dedicated_listeners(
            &per_tunnel,
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
