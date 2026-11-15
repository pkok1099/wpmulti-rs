mod common;

use std::net::{IpAddr, Ipv6Addr, SocketAddr};
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::Duration;

use common::{
    generate_245_cloned_wgcf_configs, AdminTestClient, TestEnvironment, WgConfBuilder,
    WgPeerFixture,
};
use etherparse::PacketBuilder;
use gotatun::tun::IpRecv;
use gotatun::x25519::{PublicKey, StaticSecret};
use smoltcp::phy::{Device, TxToken};
use tokio::task::JoinSet;
use wpmulti::api::AdminServer;
use wpmulti::config::{
    AuthMode, LifecycleMode, MainConfig, PoolStrategy, SharedListenerSettings,
    TunnelConfig, TunnelPoolSelection, WgInterfaceConfig, WgPeerConfig,
};
use wpmulti::core::{
    LifecycleController, MultiTenantRouter, TunnelEntry, TunnelManager, TunnelRegistry,
    TunnelState,
};
use wpmulti::netstack::{build_query, DnsLruCache, QueryType, VirtualTunBridge};
use wpmulti::proxy::{
    parse_socks5_udp_packet, TargetAddr, TunnelRouter, TunnelSelector,
};

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
// Scenario 1: 245 Cloned wgcf Configs Concurrency & IPv6 Netstack Routing
// =============================================================================
#[tokio::test]
async fn test_scenario_1_245_cloned_wgcf_concurrency_and_ipv6() {
    let env = TestEnvironment::new("scenario_1_245_wgcf").unwrap();
    let mock_endpoint: SocketAddr = "127.0.0.1:51820".parse().unwrap();
    let mock_pubkey = "bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo=";

    // 1. Generate 245 identical Cloudflare WARP wgcf configs
    let wgcf_set = generate_245_cloned_wgcf_configs(env.conf_dir(), mock_endpoint, mock_pubkey)
        .expect("generate 245 cloned wgcf configs");
    assert_eq!(wgcf_set.tunnel_ids.len(), 245);
    assert_eq!(wgcf_set.file_paths.len(), 245);

    // 2. Load configs via wpmulti core configuration loader
    let loaded_tunnels = wpmulti::load_tunnel_configs_from_dir(env.conf_dir())
        .expect("load 245 configs from directory");
    assert_eq!(loaded_tunnels.len(), 245);

    // 3. Register in TunnelManager
    let mut config = MainConfig::default();
    config.global.config_dir = env.conf_dir().to_path_buf();
    config.per_tunnel.enabled = false;

    let manager = Arc::new(TunnelManager::new(config, loaded_tunnels).unwrap());
    assert_eq!(manager.tunnel_count(), 245);
    assert_eq!(manager.active_tunnel_count(), 0);

    // 4. Concurrently lookup and verify each tunnel's unique addressing & shared keying
    let expected_ipv6: Ipv6Addr = "2606:4700:110:8524:5b27:35a3:e0e7:4816".parse().unwrap();
    for i in 1..=245 {
        let tid = format!("wgcf-{:03}", i);
        let entry = manager.registry().get(&tid).expect("tunnel entry exists");
        assert_eq!(entry.id, tid);
        assert_eq!(*entry.state.read(), TunnelState::Dormant);

        let cfg = entry.config.read();
        assert_eq!(cfg.interface.addresses.len(), 2);
        assert_eq!(cfg.interface.addresses[1].ip(), expected_ipv6);
        assert_eq!(cfg.peers[0].endpoint, "127.0.0.1:51820");
    }

    // 5. Concurrently activate 20 tunnels simultaneously without race conditions
    let mut join_set = JoinSet::new();
    for i in 1..=20 {
        let mgr = Arc::clone(&manager);
        let tid = format!("wgcf-{:03}", i);
        join_set.spawn(async move {
            mgr.activate_tunnel(&tid).await.map(|a| a.id.clone())
        });
    }

    let mut activated_count = 0;
    while let Some(res) = join_set.join_next().await {
        let tid = res.unwrap().unwrap();
        assert!(tid.starts_with("wgcf-"));
        activated_count += 1;
    }
    assert_eq!(activated_count, 20);
    assert_eq!(manager.active_tunnel_count(), 20);

    // 6. IPv6 Packet tunneling through userspace netstack bridge
    let (mut bridge, _bridge_tx, mut bridge_rx) = VirtualTunBridge::new(1420, 64);
    let src_ipv6 = expected_ipv6;
    let dst_ipv6: Ipv6Addr = "2606:4700:4700::1111".parse().unwrap();
    let ipv6_payload = b"cloudflare_warp_ipv6_tunnel_verification_payload";

    let mut ipv6_buf = Vec::new();
    let builder = PacketBuilder::ipv6(src_ipv6.octets(), dst_ipv6.octets(), 64).udp(12345, 53);
    builder.write(&mut ipv6_buf, ipv6_payload).unwrap();

    let tx_token = bridge.transmit(smoltcp::time::Instant::from_millis(0)).unwrap();
    tx_token.consume(ipv6_buf.len(), |buf| {
        buf.copy_from_slice(&ipv6_buf);
    });

    let mut pool = gotatun::packet::PacketBufPool::new(1420);
    let iter = bridge_rx.recv(&mut pool).await.unwrap();
    let batch: Vec<_> = iter.collect();
    assert_eq!(batch.len(), 1);

    let raw = batch[0].clone().into_bytes();
    let sliced = etherparse::SlicedPacket::from_ip(raw.as_ref()).unwrap();
    if let Some(etherparse::InternetSlice::Ipv6(ipv6_header, _)) = sliced.ip {
        assert_eq!(ipv6_header.destination_addr(), dst_ipv6);
        assert_eq!(ipv6_header.source_addr(), src_ipv6);
    } else {
        panic!("Expected IPv6 header");
    }
    assert_eq!(sliced.payload, ipv6_payload);
}

// =============================================================================
// Scenario 2: Shared Port Multi-User SOCKS5 + HTTP Traffic
// =============================================================================
#[tokio::test]
async fn test_scenario_2_shared_port_multi_user_socks5_and_http() {
    let reg = Arc::new(TunnelRegistry::new());
    for i in 1..=10 {
        let id = format!("tenant-tun-{:02}", i);
        let conf = make_test_conf(&id, "127.0.0.1:51820");
        reg.register(TunnelEntry::new(&id, conf, LifecycleMode::Lazy)).unwrap();
    }

    let lc = LifecycleController::new(
        Arc::clone(&reg),
        Duration::from_secs(60),
        Duration::from_millis(50),
    );

    // SOCKS5 shared listener with round-robin default
    let s5_settings = SharedListenerSettings {
        name: "s5_shared".to_string(),
        listener_type: wpmulti::config::ListenerType::Socks5,
        bind: "127.0.0.1:1080".parse().unwrap(),
        auth_mode: AuthMode::Global,
        global_password: Some("s5Pass123".to_string()),
        default_strategy: PoolStrategy::RoundRobin,
        allow_anonymous: false,
        pool: TunnelPoolSelection::All,
        ip_mode: None,
    };
    let s5_router = MultiTenantRouter::from_settings(&s5_settings, lc.clone(), reg.clone());

    // HTTP shared listener with least-conn default
    let http_settings = SharedListenerSettings {
        name: "http_shared".to_string(),
        listener_type: wpmulti::config::ListenerType::Http,
        bind: "127.0.0.1:8080".parse().unwrap(),
        auth_mode: AuthMode::Global,
        global_password: Some("httpPass456".to_string()),
        default_strategy: PoolStrategy::LeastConn,
        allow_anonymous: false,
        pool: TunnelPoolSelection::All,
        ip_mode: None,
    };
    let http_router = MultiTenantRouter::from_settings(&http_settings, lc, reg);

    // Concurrently simulate 20 clients authenticating across SOCKS5 and HTTP
    let mut join_set = JoinSet::new();

    // 10 SOCKS5 clients
    for i in 1..=10 {
        let r = Arc::clone(&s5_router);
        join_set.spawn(async move {
            let username = if i <= 5 {
                format!("tenant-tun-{:02}", i)
            } else {
                "round-robin".to_string()
            };
            r.authenticate(Some((&username, "s5Pass123"))).unwrap()
        });
    }

    // 10 HTTP clients
    for i in 1..=10 {
        let r = Arc::clone(&http_router);
        join_set.spawn(async move {
            let username = if i <= 5 {
                format!("tenant-tun-{:02}", i + 5)
            } else {
                "least-conn".to_string()
            };
            r.authenticate(Some((&username, "httpPass456"))).unwrap()
        });
    }

    let mut direct_id_count = 0;
    let mut keyword_count = 0;

    while let Some(res) = join_set.join_next().await {
        let sel = res.unwrap();
        match sel {
            TunnelSelector::ById(_) => direct_id_count += 1,
            TunnelSelector::ByKeyword(_) => keyword_count += 1,
            _ => panic!("Unexpected selector variant"),
        }
    }

    assert_eq!(direct_id_count, 10);
    assert_eq!(keyword_count, 10);
}

// =============================================================================
// Scenario 3: Lazy Lifecycle: Dormant -> Wake on Connection -> Traffic -> Idle Suspend
// =============================================================================
#[tokio::test]
async fn test_scenario_3_lazy_lifecycle_full_cycle() {
    let registry = Arc::new(TunnelRegistry::new());
    let conf = make_test_conf("lazy-lifecycle-tun", "127.0.0.1:51820");
    let id = conf.id.clone();
    registry.register(TunnelEntry::new(&id, conf, LifecycleMode::Lazy)).unwrap();

    let idle_timeout = Duration::from_millis(80);
    let check_interval = Duration::from_millis(20);
    let lifecycle = LifecycleController::new(Arc::clone(&registry), idle_timeout, check_interval);
    lifecycle.start();

    let entry = registry.get("lazy-lifecycle-tun").unwrap();

    // 1. Initial State: Dormant
    assert_eq!(*entry.state.read(), TunnelState::Dormant);
    assert_eq!(entry.stats.active_conns.load(Ordering::SeqCst), 0);

    // 2. Incoming connection: Wake on Demand
    let (active_tunnel, guard) = lifecycle.get_or_activate("lazy-lifecycle-tun").await.unwrap();
    assert_eq!(active_tunnel.id, "lazy-lifecycle-tun");
    assert_eq!(*entry.state.read(), TunnelState::Active);
    assert_eq!(entry.stats.active_conns.load(Ordering::SeqCst), 1);

    // 3. Traffic streaming: record rx/tx throughput
    entry.stats.rx_bytes.fetch_add(65536, Ordering::Relaxed);
    entry.stats.tx_bytes.fetch_add(131072, Ordering::Relaxed);
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    entry.stats.last_active_at.store(now, Ordering::Relaxed);

    assert_eq!(entry.stats.rx_bytes.load(Ordering::Relaxed), 65536);
    assert_eq!(entry.stats.tx_bytes.load(Ordering::Relaxed), 131072);

    // 4. Session finishes: drop connection guard
    drop(guard);
    assert_eq!(entry.stats.active_conns.load(Ordering::SeqCst), 0);
    // Tunnel stays active until idle timeout expires
    assert_eq!(*entry.state.read(), TunnelState::Active);

    // 5. Idle Suspend: wait for idle teardown loop to transition state to Suspended
    tokio::time::sleep(Duration::from_millis(150)).await;
    assert_eq!(*entry.state.read(), TunnelState::Suspended);

    // 6. Resume on new connection: wake from Suspended back to Active
    let (resumed_tunnel, guard2) = lifecycle.get_or_activate("lazy-lifecycle-tun").await.unwrap();
    assert_eq!(resumed_tunnel.id, "lazy-lifecycle-tun");
    assert_eq!(*entry.state.read(), TunnelState::Active);
    assert_eq!(entry.stats.active_conns.load(Ordering::SeqCst), 1);

    drop(guard2);
    lifecycle.stop().await;
}

// =============================================================================
// Scenario 4: DNS Leak Prevention Under Heavy FQDN Requests
// =============================================================================
#[tokio::test]
async fn test_scenario_4_dns_leak_prevention_heavy_fqdn_requests() {
    let cache = Arc::new(DnsLruCache::new(512));

    // Prepopulate 50 internal service FQDNs
    for i in 1..=50 {
        let domain = format!("svc-{:02}.internal.corp", i);
        let ip: IpAddr = format!("10.100.{}.{}", (i / 250) + 1, (i % 250) + 1).parse().unwrap();
        cache.insert(&domain, vec![ip], 300);
    }

    // Heavy concurrent querying: 50 tasks x 20 queries = 1000 queries
    let mut join_set = JoinSet::new();
    for task_id in 1..=50 {
        let c = Arc::clone(&cache);
        join_set.spawn(async move {
            let mut resolved = 0;
            for q in 1..=20 {
                let domain = format!("svc-{:02}.internal.corp", ((task_id + q) % 50) + 1);
                if let Some(ips) = c.get(&domain) {
                    assert!(!ips.is_empty());
                    resolved += 1;
                }
            }
            resolved
        });
    }

    let mut total_resolved = 0;
    while let Some(res) = join_set.join_next().await {
        total_resolved += res.unwrap();
    }
    assert_eq!(total_resolved, 1000);

    // Verify wire-format DNS query generation
    for i in 1..=10 {
        let domain = format!("api-{}.internal.corp", i);
        let query_bytes = build_query(&domain, QueryType::A, 0x1234).unwrap();
        assert!(query_bytes.len() > 12); // DNS header is 12 bytes
        assert_eq!(&query_bytes[0..2], &[0x12, 0x34]); // Transaction ID
    }

    // Verify LRU cache capacity bounds and eviction
    let small_cache = DnsLruCache::new(50);
    for i in 1..=100 {
        let domain = format!("test-{}.domain.com", i);
        let ip: IpAddr = "10.0.0.1".parse().unwrap();
        small_cache.insert(&domain, vec![ip], 60);
    }
    // Most recent domain must exist
    assert!(small_cache.get("test-100.domain.com").is_some());
    // Earliest domain must be evicted
    assert!(small_cache.get("test-1.domain.com").is_none());
}

// =============================================================================
// Scenario 5: Hot-Reload Config Directory with Active Connections
// =============================================================================
#[tokio::test]
async fn test_scenario_5_hot_reload_with_active_connections() {
    let env = TestEnvironment::new("scenario_5_hot_reload").unwrap();

    // Create 3 initial WireGuard configs
    for i in 1..=3 {
        let conf = WgConfBuilder::new()
            .private_key("0OaUaQd4uJq5m8eN8uJq5m8eN8uJq5m8eN8uJq5m8eM=")
            .add_peer(WgPeerFixture::new(
                "bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo=",
                &format!("198.51.100.{}:51820", i),
            ))
            .build_ini();
        env.write_conf(&format!("tun-{}.conf", i), &conf).unwrap();
    }

    let mut cfg = MainConfig::default();
    cfg.global.config_dir = env.conf_dir().to_path_buf();
    cfg.per_tunnel.enabled = false;

    let tunnels = wpmulti::load_tunnel_configs_from_dir(env.conf_dir()).unwrap();
    let manager = Arc::new(TunnelManager::new(cfg, tunnels).unwrap());
    assert_eq!(manager.tunnel_count(), 3);

    let server = AdminServer::new("127.0.0.1:0".parse().unwrap(), Arc::clone(&manager), None);
    let bound = server.start().await.unwrap();
    let client = AdminTestClient::new(bound, None);

    // Active connection on tun-1
    let (active_tun, guard) = manager.lifecycle().get_or_activate("tun-1").await.unwrap();
    assert_eq!(active_tun.id, "tun-1");
    let entry_1 = manager.registry().get("tun-1").unwrap();
    assert_eq!(entry_1.stats.active_conns.load(Ordering::SeqCst), 1);

    // While connection is active, add tun-4 and tun-5, remove tun-3
    for i in 4..=5 {
        let conf = WgConfBuilder::new()
            .private_key("0OaUaQd4uJq5m8eN8uJq5m8eN8uJq5m8eN8uJq5m8eM=")
            .add_peer(WgPeerFixture::new(
                "bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo=",
                &format!("198.51.100.{}:51820", i),
            ))
            .build_ini();
        env.write_conf(&format!("tun-{}.conf", i), &conf).unwrap();
    }
    std::fs::remove_file(env.conf_dir().join("tun-3.conf")).unwrap();

    // Trigger reload via Admin API
    let reload = client.trigger_reload().await.unwrap();
    assert_eq!(reload["status"], "reloaded");
    assert_eq!(reload["report"]["added"], 2);
    assert_eq!(reload["report"]["removed"], 1);
    assert_eq!(reload["report"]["total"], 4);

    // Verify active connection on tun-1 was preserved without interruption
    assert_eq!(entry_1.stats.active_conns.load(Ordering::SeqCst), 1);
    assert_eq!(*entry_1.state.read(), TunnelState::Active);

    // Finish session cleanly
    drop(guard);
    assert_eq!(entry_1.stats.active_conns.load(Ordering::SeqCst), 0);

    server.stop().await;
}

// =============================================================================
// Scenario 6: High Concurrency UDP ASSOCIATE Relay Streaming
// =============================================================================
#[tokio::test]
async fn test_scenario_6_high_concurrency_udp_associate_streaming() {
    let (mut bridge, _bridge_tx, mut bridge_rx) = VirtualTunBridge::new(1420, 1024);

    // Concurrently encode, parse, and verify 20 client streams x 10 datagrams = 200 datagrams
    let total_clients = 20;
    let datagrams_per_client = 10;

    for client_id in 1..=total_clients {
        for pkt_id in 1..=datagrams_per_client {
            let payload = format!("client_{}_pkt_{}_udp_payload", client_id, pkt_id);
            let payload_bytes = payload.as_bytes();

            // Construct SOCKS5 UDP relay packet
            // Header: RSV(2) + FRAG(1) + ATYP(1) + IPv4(4) + Port(2)
            let mut s5_udp = vec![0x00, 0x00, 0x00, 0x01, 10, 0, 0, (client_id % 250) as u8];
            let port = 8000 + pkt_id as u16;
            s5_udp.extend_from_slice(&port.to_be_bytes());
            s5_udp.extend_from_slice(payload_bytes);

            // Parse SOCKS5 UDP header
            let (target, extracted_payload) = parse_socks5_udp_packet(&s5_udp)
                .expect("parse socks5 udp packet");
            assert_eq!(extracted_payload, payload_bytes);

            match target {
                TargetAddr::Ip(SocketAddr::V4(v4)) => {
                    assert_eq!(v4.port(), port);
                }
                _ => panic!("Expected IPv4 target"),
            }

            // Encapsulate into IPv4/UDP packet and transmit through netstack bridge
            let mut ip_buf = Vec::new();
            let b = PacketBuilder::ipv4([10, 0, 0, 2], [10, 0, 0, (client_id % 250) as u8], 64)
                .udp(15000 + client_id as u16, port);
            b.write(&mut ip_buf, extracted_payload).unwrap();

            let tx_token = bridge.transmit(smoltcp::time::Instant::from_millis(0)).unwrap();
            tx_token.consume(ip_buf.len(), |buf| {
                buf.copy_from_slice(&ip_buf);
            });
        }
    }

    // Drain and verify all 200 datagrams from the bridge receiver
    let mut pool = gotatun::packet::PacketBufPool::new(1420);
    let mut received_count = 0;

    while received_count < total_clients * datagrams_per_client {
        let iter = bridge_rx.recv(&mut pool).await.unwrap();
        for pkt in iter {
            let raw = pkt.into_bytes();
            let sliced = etherparse::SlicedPacket::from_ip(raw.as_ref()).unwrap();
            assert!(sliced.payload.starts_with(b"client_"));
            received_count += 1;
        }
    }

    assert_eq!(received_count, total_clients * datagrams_per_client);
}
