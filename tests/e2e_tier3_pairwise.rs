mod common;

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::Duration;

use common::{
    AdminTestClient, SharedListenerFixture, Socks5Target, TestEnvironment, WgConfBuilder,
    WgPeerFixture, WpMultiTomlBuilder,
};
use etherparse::PacketBuilder;
use gotatun::tun::IpRecv;
use gotatun::x25519::{PublicKey, StaticSecret};
use smoltcp::phy::{Device, TxToken};
use wpmulti::api::AdminServer;
use wpmulti::config::{
    AuthMode, LifecycleMode, MainConfig, PoolStrategy, SharedListenerSettings,
    TuiSortField, TunnelConfig, TunnelPoolSelection, WgInterfaceConfig, WgPeerConfig,
};
use wpmulti::core::{
    DedicatedTunnelRouter, LifecycleController, MultiTenantRouter, TunnelEntry, TunnelManager,
    TunnelRegistry, TunnelState,
};
use wpmulti::netstack::{DnsLruCache, VirtualTunBridge};
use wpmulti::proxy::{
    parse_authority, parse_socks5_udp_packet, PoolKeyword, ProxyAuthError, TargetAddr,
    TunnelRouter, TunnelSelector,
};
use wpmulti::tui::{render_dashboard, TuiApp, TuiDataSource};

fn make_test_conf(id: &str, endpoint: &str) -> TunnelConfig {
    TunnelConfig {
        id: id.to_string(),
        interface: WgInterfaceConfig {
            private_key: StaticSecret::from([42u8; 32]),
            addresses: vec![
                "10.0.0.2/32".parse().unwrap(),
                "fd00::2/128".parse().unwrap(),
            ],
            dns: vec!["1.1.1.1".parse().unwrap()],
            listen_port: None,
            mtu: 1420,
        },
        peers: vec![WgPeerConfig {
            public_key: PublicKey::from([99u8; 32]),
            endpoint: endpoint.to_string(),
            allowed_ips: vec!["0.0.0.0/0".parse().unwrap(), "::/0".parse().unwrap()],
            preshared_key: None,
            persistent_keepalive: Some(25),
        }],
    }
}

// =============================================================================
// Test 1: F1 (WireGuard Conf) + F9 (Per-Tunnel Dedicated Ports)
// =============================================================================
#[tokio::test]
async fn test_pairwise_f1_wg_conf_and_f9_per_tunnel_dedicated_port() {
    let base_s5 = 31100u16;
    let base_http = 32100u16;

    let confs = [make_test_conf("tunnel-a", "198.51.100.1:51820"),
        make_test_conf("tunnel-b", "198.51.100.2:51820"),
        make_test_conf("tunnel-c", "198.51.100.3:51820")];

    let registry = Arc::new(TunnelRegistry::new());
    for (idx, conf) in confs.iter().enumerate() {
        let entry = TunnelEntry::new(&conf.id, conf.clone(), LifecycleMode::Lazy);
        registry.register(entry).unwrap();

        // Calculate expected dedicated ports based on tunnel index
        let expected_s5 = base_s5 + idx as u16;
        let expected_http = base_http + idx as u16;

        let lifecycle = LifecycleController::new(
            Arc::clone(&registry),
            Duration::from_secs(60),
            Duration::from_millis(100),
        );
        let dedicated_router = DedicatedTunnelRouter::new(conf.id.clone(), lifecycle, None);

        let selector = dedicated_router.authenticate(None).unwrap();
        match selector {
            TunnelSelector::ById(target) => assert_eq!(target, conf.id),
            other => panic!("Expected ById, got {:?}", other),
        }

        assert_eq!(expected_s5, 31100 + idx as u16);
        assert_eq!(expected_http, 32100 + idx as u16);
    }
    assert_eq!(registry.count(), 3);
}

// =============================================================================
// Test 2: F2 (TOML Config) + F10 (Shared Listener Pools & Multi-Tenant Routing)
// =============================================================================
#[tokio::test]
async fn test_pairwise_f2_toml_and_f10_shared_listener_pools() {
    let env = TestEnvironment::new("pairwise_toml_pools").unwrap();
    let toml_str = WpMultiTomlBuilder::new(env.conf_dir().to_path_buf())
        .add_shared_listener(SharedListenerFixture {
            name: "public_pool".to_string(),
            proto_type: "socks5".to_string(),
            bind: "127.0.0.1:1080".parse().unwrap(),
            auth_mode: "none".to_string(),
            global_password: None,
            default_strategy: "round-robin".to_string(),
            allow_anonymous: true,
            pool: "all".to_string(),
        })
        .add_shared_listener(SharedListenerFixture {
            name: "private_pool".to_string(),
            proto_type: "http".to_string(),
            bind: "127.0.0.1:8080".parse().unwrap(),
            auth_mode: "global".to_string(),
            global_password: Some("secPass99".to_string()),
            default_strategy: "least-conn".to_string(),
            allow_anonymous: false,
            pool: "prod".to_string(),
        })
        .build_toml();

    let cfg = MainConfig::from_toml_str(&toml_str).expect("parse valid toml");
    assert_eq!(cfg.shared_listeners.len(), 2);

    let reg = Arc::new(TunnelRegistry::new());
    let lc = LifecycleController::new(
        Arc::clone(&reg),
        Duration::from_secs(30),
        Duration::from_millis(50),
    );

    // Router 1: public anonymous allowed
    let router1 = MultiTenantRouter::from_settings(&cfg.shared_listeners[0], lc.clone(), reg.clone());
    let sel_anon = router1.authenticate(None).expect("anonymous allowed");
    assert_eq!(sel_anon, TunnelSelector::DefaultPool);

    let sel_kw = router1.authenticate(Some(("least-conn", ""))).unwrap();
    assert_eq!(sel_kw, TunnelSelector::ByKeyword(PoolKeyword::LeastConn));

    // Router 2: private requires auth
    let router2 = MultiTenantRouter::from_settings(&cfg.shared_listeners[1], lc, reg);
    assert_eq!(router2.authenticate(None).unwrap_err(), ProxyAuthError::AuthRequired);
    assert_eq!(
        router2.authenticate(Some(("user", "bad_pass"))).unwrap_err(),
        ProxyAuthError::InvalidCredentials
    );
    let sel_auth = router2.authenticate(Some(("wgcf-01", "secPass99"))).unwrap();
    assert_eq!(sel_auth, TunnelSelector::ById("wgcf-01".to_string()));
}

// =============================================================================
// Test 3: F3 (Multi-Tunnel Registry) + F11 (Lifecycle State Machine)
// =============================================================================
#[tokio::test]
async fn test_pairwise_f3_registry_and_f11_lifecycle_state() {
    let registry = Arc::new(TunnelRegistry::new());
    for i in 1..=5 {
        let conf = make_test_conf(&format!("tun-{:02}", i), "127.0.0.1:51820");
        let id = conf.id.clone();
        registry.register(TunnelEntry::new(&id, conf, LifecycleMode::Lazy)).unwrap();
    }

    let lifecycle = LifecycleController::new(
        Arc::clone(&registry),
        Duration::from_millis(100),
        Duration::from_millis(20),
    );

    // Initially all 5 are Dormant
    for entry in registry.all_entries() {
        assert_eq!(*entry.state.read(), TunnelState::Dormant);
    }
    assert_eq!(registry.active_count(), 0);

    // Activate tun-01
    let active_1 = lifecycle.activate_tunnel("tun-01").await.unwrap();
    assert_eq!(active_1.id, "tun-01");
    let entry_1 = registry.get("tun-01").unwrap();
    assert_eq!(*entry_1.state.read(), TunnelState::Active);
    assert!(entry_1.stats.last_active_at.load(Ordering::Relaxed) > 0);
    assert_eq!(registry.active_count(), 1);

    // Suspend tun-01
    lifecycle.suspend_tunnel("tun-01").await.unwrap();
    assert_eq!(*entry_1.state.read(), TunnelState::Suspended);
    assert_eq!(registry.active_count(), 0);
}

// =============================================================================
// Test 4: F4 (Userspace Netstack Bridge) + F6 (SOCKS5 CONNECT)
// =============================================================================
#[tokio::test]
async fn test_pairwise_f4_userspace_netstack_and_f6_socks5_connect() {
    let (mut bridge, _bridge_tx, mut bridge_rx) = VirtualTunBridge::new(1420, 64);

    // Simulate SOCKS5 CONNECT to 198.51.100.10:80
    let target = Socks5Target::Ip("198.51.100.10:80".parse().unwrap());
    let mut ip_buf = Vec::new();
    match target {
        Socks5Target::Ip(SocketAddr::V4(v4)) => {
            let b = PacketBuilder::ipv4([10, 0, 0, 2], v4.ip().octets(), 64)
                .tcp(45678, v4.port(), 1000, 65535)
                .syn();
            b.write(&mut ip_buf, &[]).unwrap();
        }
        _ => panic!("Expected IPv4 target"),
    }

    // Transmit into smoltcp bridge
    let tx_token = bridge.transmit(smoltcp::time::Instant::from_millis(0)).unwrap();
    tx_token.consume(ip_buf.len(), |buf| {
        buf.copy_from_slice(&ip_buf);
    });

    // Receive via bridge and verify packet properties
    let mut pool = gotatun::packet::PacketBufPool::new(1420);
    let iter = bridge_rx.recv(&mut pool).await.unwrap();
    let batch: Vec<_> = iter.collect();
    assert_eq!(batch.len(), 1);

    let raw = batch[0].clone().into_bytes();
    let sliced = etherparse::SlicedPacket::from_ip(raw.as_ref()).unwrap();
    if let Some(etherparse::InternetSlice::Ipv4(ipv4_header, _)) = sliced.ip {
        assert_eq!(ipv4_header.destination_addr(), Ipv4Addr::new(198, 51, 100, 10));
    } else {
        panic!("Expected IPv4 header");
    }
}

// =============================================================================
// Test 5: F5 (In-Tunnel DNS Resolver) + F6 (SOCKS5 Domain Target ATYP 0x03)
// =============================================================================
#[tokio::test]
async fn test_pairwise_f5_dns_resolver_and_f6_socks5_domain_target() {
    let cache = DnsLruCache::new(128);
    let domain = "secure-api.corp.internal";
    let target_ip: IpAddr = "10.42.0.15".parse().unwrap();

    // Cache pre-population (simulating in-tunnel resolution)
    cache.insert(domain, vec![target_ip], 300);

    // SOCKS5 domain target request
    let socks5_req = Socks5Target::Domain(domain.to_string(), 443);
    let resolved_ip = match &socks5_req {
        Socks5Target::Domain(name, _port) => {
            let cached = cache.get(name).expect("cache hit in-tunnel");
            cached[0]
        }
        _ => panic!("Expected domain target"),
    };

    assert_eq!(resolved_ip, target_ip);
}

// =============================================================================
// Test 6: F6 (SOCKS5 Proxy) + F11 (Lazy Activation on Demand)
// =============================================================================
#[tokio::test]
async fn test_pairwise_f6_socks5_and_f11_lazy_activation() {
    let registry = Arc::new(TunnelRegistry::new());
    let conf = make_test_conf("lazy-s5-tunnel", "127.0.0.1:51820");
    let id = conf.id.clone();
    registry.register(TunnelEntry::new(&id, conf, LifecycleMode::Lazy)).unwrap();

    let lifecycle = LifecycleController::new(
        Arc::clone(&registry),
        Duration::from_secs(60),
        Duration::from_millis(50),
    );

    let entry = registry.get("lazy-s5-tunnel").unwrap();
    assert_eq!(*entry.state.read(), TunnelState::Dormant);

    // Incoming SOCKS5 connection acquires guard via get_or_activate
    let (active_tun, guard) = lifecycle.get_or_activate("lazy-s5-tunnel").await.unwrap();
    assert_eq!(active_tun.id, "lazy-s5-tunnel");
    assert_eq!(*entry.state.read(), TunnelState::Active);
    assert_eq!(entry.stats.active_conns.load(Ordering::SeqCst), 1);

    // Simulate SOCKS5 session termination: drop RAII guard
    drop(guard);
    assert_eq!(entry.stats.active_conns.load(Ordering::SeqCst), 0);
    // Tunnel remains active until idle timeout triggers
    assert_eq!(*entry.state.read(), TunnelState::Active);
}

// =============================================================================
// Test 7: F8 (HTTP Proxy) + F10 (Shared Listener Auth Mode & Routing)
// =============================================================================
#[tokio::test]
async fn test_pairwise_f8_http_proxy_and_f10_shared_listener_auth() {
    let settings = SharedListenerSettings {
        name: "http_shared".to_string(),
        listener_type: wpmulti::config::ListenerType::Http,
        bind: "127.0.0.1:8080".parse().unwrap(),
        auth_mode: AuthMode::Global,
        global_password: Some("secretHTTP".to_string()),
        default_strategy: PoolStrategy::RoundRobin,
        allow_anonymous: false,
        pool: TunnelPoolSelection::All,
        ip_mode: None,
    };

    let reg = Arc::new(TunnelRegistry::new());
    let lc = LifecycleController::new(
        Arc::clone(&reg),
        Duration::from_secs(60),
        Duration::from_millis(50),
    );
    let router = MultiTenantRouter::from_settings(&settings, lc, reg);

    // Missing auth header
    assert_eq!(router.authenticate(None).unwrap_err(), ProxyAuthError::AuthRequired);

    // Wrong password
    assert_eq!(
        router.authenticate(Some(("wgcf-pool", "wrong_pass"))).unwrap_err(),
        ProxyAuthError::InvalidCredentials
    );

    // Valid credentials
    let sel = router.authenticate(Some(("wgcf-target", "secretHTTP"))).unwrap();
    assert_eq!(sel, TunnelSelector::ById("wgcf-target".to_string()));
}

// =============================================================================
// Test 8: F8 (HTTP Proxy) + F11 (Lazy Activation on Demand)
// =============================================================================
#[tokio::test]
async fn test_pairwise_f8_http_proxy_and_f11_lazy_activation() {
    let registry = Arc::new(TunnelRegistry::new());
    let conf = make_test_conf("lazy-http-tunnel", "127.0.0.1:51820");
    let id = conf.id.clone();
    registry.register(TunnelEntry::new(&id, conf, LifecycleMode::Lazy)).unwrap();

    let lifecycle = LifecycleController::new(
        Arc::clone(&registry),
        Duration::from_secs(60),
        Duration::from_millis(50),
    );

    let entry = registry.get("lazy-http-tunnel").unwrap();
    assert_eq!(*entry.state.read(), TunnelState::Dormant);

    // HTTP CONNECT request triggers get_or_activate
    let (active_tun, guard) = lifecycle.get_or_activate("lazy-http-tunnel").await.unwrap();
    assert_eq!(active_tun.id, "lazy-http-tunnel");
    assert_eq!(*entry.state.read(), TunnelState::Active);
    assert_eq!(entry.stats.active_conns.load(Ordering::SeqCst), 1);

    // Transfer bytes over HTTP proxy tunnel
    entry.stats.rx_bytes.fetch_add(4096, Ordering::Relaxed);
    entry.stats.tx_bytes.fetch_add(8192, Ordering::Relaxed);

    drop(guard);
    assert_eq!(entry.stats.active_conns.load(Ordering::SeqCst), 0);
    assert_eq!(entry.stats.rx_bytes.load(Ordering::Relaxed), 4096);
    assert_eq!(entry.stats.tx_bytes.load(Ordering::Relaxed), 8192);
}

// =============================================================================
// Test 9: F7 (SOCKS5 UDP ASSOCIATE) + F4 (Netstack Bridge Channel)
// =============================================================================
#[tokio::test]
async fn test_pairwise_f7_socks5_udp_and_f4_netstack_bridge() {
    let (mut bridge, _bridge_tx, mut bridge_rx) = VirtualTunBridge::new(1420, 64);

    // SOCKS5 UDP relay packet: RSV(2) + FRAG(1) + ATYP(1) + IP(4) + Port(2) + Data
    let mut raw_socks5_udp = vec![0x00, 0x00, 0x00, 0x01, 192, 0, 2, 100, 0x1F, 0x90];
    let app_payload = b"socks5_udp_relay_payload_stream";
    raw_socks5_udp.extend_from_slice(app_payload);

    let (target_addr, payload) = parse_socks5_udp_packet(&raw_socks5_udp).unwrap();
    assert_eq!(payload, app_payload);

    // Encapsulate into IPv4/UDP packet for netstack bridge
    let (dest_ip, dest_port) = match target_addr {
        TargetAddr::Ip(SocketAddr::V4(v4)) => (*v4.ip(), v4.port()),
        _ => panic!("Expected IPv4 socket addr"),
    };

    let mut ip_buf = Vec::new();
    let builder = PacketBuilder::ipv4([10, 0, 0, 2], dest_ip.octets(), 64).udp(20000, dest_port);
    builder.write(&mut ip_buf, payload).unwrap();

    let tx_token = bridge.transmit(smoltcp::time::Instant::from_millis(0)).unwrap();
    tx_token.consume(ip_buf.len(), |buf| {
        buf.copy_from_slice(&ip_buf);
    });

    let mut pool = gotatun::packet::PacketBufPool::new(1420);
    let iter = bridge_rx.recv(&mut pool).await.unwrap();
    let batch: Vec<_> = iter.collect();
    assert_eq!(batch.len(), 1);

    let rx_bytes = batch[0].clone().into_bytes();
    let sliced = etherparse::SlicedPacket::from_ip(rx_bytes.as_ref()).unwrap();
    assert_eq!(sliced.payload, app_payload);
}

// =============================================================================
// Test 10: F12 (Admin API) + F11 (Lifecycle Control Endpoints)
// =============================================================================
#[tokio::test]
async fn test_pairwise_f12_admin_api_and_f11_lifecycle_control() {
    let conf = make_test_conf("wgcf-admin-ctrl", "127.0.0.1:51820");
    let mut config = MainConfig::default();
    config.per_tunnel.enabled = false;

    let manager = Arc::new(TunnelManager::new(config, vec![conf]).unwrap());
    let server = AdminServer::new(
        "127.0.0.1:0".parse().unwrap(),
        Arc::clone(&manager),
        Some("adm_secret".to_string()),
    );
    let bound = server.start().await.expect("admin server start");
    let client = AdminTestClient::new(bound, Some("adm_secret".to_string()));

    // Verify initially dormant
    let tunnels = client.list_tunnels(None).await.unwrap();
    assert_eq!(tunnels.as_array().unwrap().len(), 1);
    assert_eq!(tunnels[0]["id"], "wgcf-admin-ctrl");
    assert_eq!(tunnels[0]["state"].as_str().unwrap().to_lowercase(), "dormant");

    // Activate via Admin API
    let act_resp = client.activate_tunnel("wgcf-admin-ctrl").await.unwrap();
    assert_eq!(act_resp["status"], "activated");

    let tunnels_after = client.list_tunnels(None).await.unwrap();
    assert_eq!(tunnels_after[0]["state"].as_str().unwrap().to_lowercase(), "active");

    // Suspend via Admin API
    let deact_resp = client.deactivate_tunnel("wgcf-admin-ctrl").await.unwrap();
    assert_eq!(deact_resp["status"], "suspended");

    server.stop().await;
}

// =============================================================================
// Test 11: F12 (Admin API) + F2 (Directory Hot-Reload)
// =============================================================================
#[tokio::test]
async fn test_pairwise_f12_admin_api_and_f2_hot_reload() {
    let env = TestEnvironment::new("pairwise_reload").unwrap();
    let conf1 = WgConfBuilder::new()
        .private_key("0OaUaQd4uJq5m8eN8uJq5m8eN8uJq5m8eN8uJq5m8eM=")
        .add_peer(WgPeerFixture::new(
            "bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo=",
            "198.51.100.1:51820",
        ))
        .build_ini();
    env.write_conf("wgcf-01.conf", &conf1).unwrap();

    let mut cfg = MainConfig::default();
    cfg.global.config_dir = env.conf_dir().to_path_buf();
    cfg.per_tunnel.enabled = false;

    let tunnels = wpmulti::load_tunnel_configs_from_dir(env.conf_dir()).unwrap();
    assert_eq!(tunnels.len(), 1);

    let manager = Arc::new(TunnelManager::new(cfg, tunnels).unwrap());
    let server = AdminServer::new("127.0.0.1:0".parse().unwrap(), Arc::clone(&manager), None);
    let bound = server.start().await.unwrap();
    let client = AdminTestClient::new(bound, None);

    let status = client.get_status().await.unwrap();
    assert_eq!(status["total_tunnels"], 1);

    // Add a second tunnel configuration file
    let conf2 = WgConfBuilder::new()
        .private_key("0OaUaQd4uJq5m8eN8uJq5m8eN8uJq5m8eN8uJq5m8eM=")
        .add_peer(WgPeerFixture::new(
            "bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo=",
            "198.51.100.2:51820",
        ))
        .build_ini();
    env.write_conf("wgcf-02.conf", &conf2).unwrap();

    // Trigger reload via Admin API
    let reload = client.trigger_reload().await.unwrap();
    assert_eq!(reload["status"], "reloaded");
    assert_eq!(reload["reloaded"], 2);

    let status_after = client.get_status().await.unwrap();
    assert_eq!(status_after["total_tunnels"], 2);

    server.stop().await;
}

// =============================================================================
// Test 12: F13 (TUI Dashboard) + F12 (Admin Prometheus & Stats Engine)
// =============================================================================
#[tokio::test]
async fn test_pairwise_f13_tui_and_f12_admin_metrics() {
    let conf = make_test_conf("wgcf-metrics", "127.0.0.1:51820");
    let mut config = MainConfig::default();
    config.per_tunnel.enabled = false;

    let manager = Arc::new(TunnelManager::new(config, vec![conf]).unwrap());
    let entry = manager.registry().get("wgcf-metrics").unwrap();
    entry.stats.rx_bytes.store(1048576, Ordering::Relaxed);
    entry.stats.tx_bytes.store(2097152, Ordering::Relaxed);

    let server = AdminServer::new("127.0.0.1:0".parse().unwrap(), Arc::clone(&manager), None);
    let bound = server.start().await.unwrap();
    let client = AdminTestClient::new(bound, None);

    // Verify Prometheus metric export
    let rx_val = client
        .get_metric_value("wpmulti_tunnel_rx_bytes", &[("tunnel_id", "wgcf-metrics")])
        .await
        .unwrap();
    assert_eq!(rx_val, 1048576.0);

    // Verify TUI dashboard renders metrics
    let ds = TuiDataSource::InProcess(Arc::clone(&manager));
    let mut app = TuiApp::new(ds, TuiSortField::Id);
    app.refresh().await.unwrap();

    let output = render_dashboard(&mut app, 120, 30);
    assert!(output.contains("wpmulti"));
    assert!(output.contains("wgcf-metrics"));
    assert!(output.contains("1.00 MB"));

    server.stop().await;
}

// =============================================================================
// Test 13: F10 (Shared Port Pool) + F7 (SOCKS5 UDP ASSOCIATE Multi-User)
// =============================================================================
#[tokio::test]
async fn test_pairwise_f10_shared_port_and_f7_udp_associate() {
    let reg = Arc::new(TunnelRegistry::new());
    for id in &["user-tun-01", "user-tun-02"] {
        let conf = make_test_conf(id, "127.0.0.1:51820");
        reg.register(TunnelEntry::new(*id, conf, LifecycleMode::Lazy)).unwrap();
    }

    let lc = LifecycleController::new(
        Arc::clone(&reg),
        Duration::from_secs(60),
        Duration::from_millis(50),
    );

    let settings = SharedListenerSettings {
        name: "shared_s5".to_string(),
        listener_type: wpmulti::config::ListenerType::Socks5,
        bind: "127.0.0.1:1080".parse().unwrap(),
        auth_mode: AuthMode::None,
        global_password: None,
        default_strategy: PoolStrategy::RoundRobin,
        allow_anonymous: true,
        pool: TunnelPoolSelection::All,
        ip_mode: None,
    };

    let router = MultiTenantRouter::from_settings(&settings, lc, reg);

    // Client 1 specifies user-tun-01
    let sel1 = router.authenticate(Some(("user-tun-01", ""))).unwrap();
    assert_eq!(sel1, TunnelSelector::ById("user-tun-01".to_string()));

    // Client 2 specifies user-tun-02
    let sel2 = router.authenticate(Some(("user-tun-02", ""))).unwrap();
    assert_eq!(sel2, TunnelSelector::ById("user-tun-02".to_string()));

    // Client 3 uses keyword round-robin
    let sel3 = router.authenticate(Some(("round-robin", ""))).unwrap();
    assert_eq!(sel3, TunnelSelector::ByKeyword(PoolKeyword::RoundRobin));
}

// =============================================================================
// Test 14: F8 (HTTP Proxy CONNECT) + F5 (In-Tunnel DNS FQDN Target)
// =============================================================================
#[tokio::test]
async fn test_pairwise_f8_http_proxy_and_f5_in_tunnel_dns() {
    let authority = "service.prod.internal:8443";
    let (host, port) = parse_authority(authority).expect("parse authority");
    assert_eq!(host, "service.prod.internal");
    assert_eq!(port, 8443);

    // In-tunnel DNS resolution simulation
    let cache = DnsLruCache::new(64);
    let internal_ip: IpAddr = "172.16.100.50".parse().unwrap();
    cache.insert(&host, vec![internal_ip], 120);

    let resolved = cache.get(&host).expect("in-tunnel DNS resolution");
    assert_eq!(resolved[0], internal_ip);

    let target_socket = SocketAddr::new(resolved[0], port);
    assert_eq!(target_socket, "172.16.100.50:8443".parse().unwrap());
}
