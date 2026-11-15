mod common;

use std::net::{IpAddr, Ipv6Addr, SocketAddr};
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::Duration;

use common::{
    generate_245_cloned_wgcf_configs, TestEnvironment,
};
use etherparse::PacketBuilder;
use gotatun::tun::IpRecv;
use gotatun::x25519::{PublicKey, StaticSecret};
use smoltcp::phy::{Device, TxToken};
use tokio::task::JoinSet;
use wpmulti::config::{
    AuthMode, LifecycleMode, MainConfig, PoolStrategy, SharedListenerSettings,
    TunnelConfig, TunnelPoolSelection, WgInterfaceConfig, WgPeerConfig,
};
use wpmulti::core::{
    LifecycleController, MultiTenantRouter, TunnelEntry, TunnelManager, TunnelRegistry,
    TunnelState,
};
use wpmulti::netstack::{
    DnsLruCache, InTunnelDnsResolver, VirtualNetworkStack, VirtualTunBridge,
};
use wpmulti::proxy::{ProxyAuthError, TunnelRouter, TunnelSelector};

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
// Adversarial Test 1: Full 245 Cloned wgcf Concurrent Activation & Teardown
// Stress-tests all 245 tunnels running concurrently in userspace
// =============================================================================
#[tokio::test]
async fn test_adv_245_all_concurrent_activation_and_teardown() {
    let env = TestEnvironment::new("adv_245_all_activation").unwrap();
    let mock_endpoint: SocketAddr = "127.0.0.1:51820".parse().unwrap();
    let mock_pubkey = "bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo=";

    // 1. Generate 245 identical Cloudflare WARP configs
    let wgcf_set = generate_245_cloned_wgcf_configs(env.conf_dir(), mock_endpoint, mock_pubkey)
        .expect("generate 245 cloned configs");
    assert_eq!(wgcf_set.tunnel_ids.len(), 245);

    // 2. Load configs via wpmulti core configuration loader
    let loaded_tunnels = wpmulti::load_tunnel_configs_from_dir(env.conf_dir())
        .expect("load 245 configs");
    assert_eq!(loaded_tunnels.len(), 245);

    let mut config = MainConfig::default();
    config.global.config_dir = env.conf_dir().to_path_buf();
    config.per_tunnel.enabled = false;

    let manager = Arc::new(TunnelManager::new(config, loaded_tunnels).unwrap());
    assert_eq!(manager.tunnel_count(), 245);
    assert_eq!(manager.active_tunnel_count(), 0);

    // 3. Concurrently activate ALL 245 tunnels simultaneously
    let mut activate_set = JoinSet::new();
    for i in 1..=245 {
        let mgr = Arc::clone(&manager);
        let tid = format!("wgcf-{:03}", i);
        activate_set.spawn(async move {
            mgr.activate_tunnel(&tid).await.map(|a| a.id.clone())
        });
    }

    let mut activated_count = 0;
    while let Some(res) = activate_set.join_next().await {
        match res.unwrap() {
            Ok(tid) => {
                assert!(tid.starts_with("wgcf-"));
                activated_count += 1;
            }
            Err(e) => panic!("Tunnel activation failed: {:?}", e),
        }
    }
    assert_eq!(activated_count, 245);
    assert_eq!(manager.active_tunnel_count(), 245);

    // Verify all 245 entries are in Active state
    for i in 1..=245 {
        let tid = format!("wgcf-{:03}", i);
        let entry = manager.registry().get(&tid).unwrap();
        assert_eq!(*entry.state.read(), TunnelState::Active);
    }

    // 4. Concurrently suspend ALL 245 tunnels
    let mut suspend_set = JoinSet::new();
    for i in 1..=245 {
        let mgr = Arc::clone(&manager);
        let tid = format!("wgcf-{:03}", i);
        suspend_set.spawn(async move {
            mgr.suspend_tunnel(&tid).await
        });
    }

    let mut suspended_count = 0;
    while let Some(res) = suspend_set.join_next().await {
        res.unwrap().expect("Tunnel suspend failed");
        suspended_count += 1;
    }
    assert_eq!(suspended_count, 245);
    assert_eq!(manager.active_tunnel_count(), 0);

    // Verify all 245 entries are in Suspended state
    for i in 1..=245 {
        let tid = format!("wgcf-{:03}", i);
        let entry = manager.registry().get(&tid).unwrap();
        assert_eq!(*entry.state.read(), TunnelState::Suspended);
    }
}

// =============================================================================
// Adversarial Test 2: High Concurrency Multi-Tenant Authentication & Strategy Hammer
// =============================================================================
#[tokio::test]
async fn test_adv_socks5_http_high_concurrency_stress() {
    let reg = Arc::new(TunnelRegistry::new());
    for i in 1..=10 {
        let id = format!("tenant-{:02}", i);
        let conf = make_test_conf(&id, "127.0.0.1:51820");
        reg.register(TunnelEntry::new(&id, conf, LifecycleMode::Lazy)).unwrap();
    }

    let lc = LifecycleController::new(
        Arc::clone(&reg),
        Duration::from_secs(60),
        Duration::from_millis(50),
    );

    let s5_settings = SharedListenerSettings {
        name: "s5_shared".to_string(),
        listener_type: wpmulti::config::ListenerType::Socks5,
        bind: "127.0.0.1:1080".parse().unwrap(),
        auth_mode: AuthMode::Global,
        global_password: Some("secret123".to_string()),
        default_strategy: PoolStrategy::RoundRobin,
        allow_anonymous: false,
        pool: TunnelPoolSelection::All,
    };
    let router = MultiTenantRouter::from_settings(&s5_settings, lc, reg);

    // Concurrently execute 100 authentication requests
    let mut join_set: JoinSet<Result<(usize, &'static str, TunnelSelector), ProxyAuthError>> = JoinSet::new();
    for req_id in 0..100 {
        let r = Arc::clone(&router);
        join_set.spawn(async move {
            match req_id % 5 {
                0 => {
                    // Valid direct ID
                    let user = format!("tenant-{:02}", (req_id % 10) + 1);
                    let sel = r.authenticate(Some((&user, "secret123")))?;
                    Ok((req_id, "direct", sel))
                }
                1 => {
                    // Round robin keyword
                    let sel = r.authenticate(Some(("round-robin", "secret123")))?;
                    Ok((req_id, "round-robin", sel))
                }
                2 => {
                    // Least conn keyword
                    let sel = r.authenticate(Some(("least-conn", "secret123")))?;
                    Ok((req_id, "least-conn", sel))
                }
                3 => {
                    // Invalid password (must fail)
                    match r.authenticate(Some(("tenant-01", "wrong_pass"))) {
                        Err(ProxyAuthError::InvalidCredentials) => {
                            Ok((req_id, "auth_rejected", TunnelSelector::DefaultPool))
                        }
                        other => panic!("Expected InvalidCredentials, got {:?}", other),
                    }
                }
                _ => {
                    // Unknown tunnel ID: authenticate succeeds with ById, but select_tunnel must fail with NotFound
                    let sel = r.authenticate(Some(("unknown-tenant-99", "secret123")))?;
                    let res = r.select_tunnel(&sel).await;
                    match res {
                        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                            Ok((req_id, "route_rejected", sel))
                        }
                        Err(e) => panic!("Expected NotFound from select_tunnel, got err {:?}", e),
                        Ok(_) => panic!("Expected NotFound from select_tunnel, got Ok"),
                    }
                }
            }
        });
    }

    let mut direct_count = 0;
    let mut rr_count = 0;
    let mut lc_count = 0;
    let mut auth_rejected_count = 0;
    let mut route_rejected_count = 0;

    while let Some(res) = join_set.join_next().await {
        let (_, cat, _) = res.unwrap().expect("request handler failed");
        match cat {
            "direct" => direct_count += 1,
            "round-robin" => rr_count += 1,
            "least-conn" => lc_count += 1,
            "auth_rejected" => auth_rejected_count += 1,
            "route_rejected" => route_rejected_count += 1,
            _ => unreachable!(),
        }
    }

    assert_eq!(direct_count, 20);
    assert_eq!(rr_count, 20);
    assert_eq!(lc_count, 20);
    assert_eq!(auth_rejected_count, 20);
    assert_eq!(route_rejected_count, 20);
}

// =============================================================================
// Adversarial Test 3: Lazy Lifecycle Thundering Herd & Idle Race
// =============================================================================
#[tokio::test]
async fn test_adv_lazy_lifecycle_thundering_herd_and_idle_race() {
    let registry = Arc::new(TunnelRegistry::new());
    let conf = make_test_conf("herd-tun", "127.0.0.1:51820");
    registry.register(TunnelEntry::new("herd-tun", conf, LifecycleMode::Lazy)).unwrap();

    let idle_timeout = Duration::from_millis(100);
    let check_interval = Duration::from_millis(25);
    let lifecycle = LifecycleController::new(Arc::clone(&registry), idle_timeout, check_interval);
    lifecycle.start();

    let entry = registry.get("herd-tun").unwrap();
    assert_eq!(*entry.state.read(), TunnelState::Dormant);

    // Thundering herd: 50 concurrent tasks all calling get_or_activate on the same dormant tunnel
    let mut join_set = JoinSet::new();
    for _ in 0..50 {
        let lc = Arc::clone(&lifecycle);
        join_set.spawn(async move {
            lc.get_or_activate("herd-tun").await
        });
    }

    let mut guards = Vec::new();
    while let Some(res) = join_set.join_next().await {
        let (tunnel, guard) = res.unwrap().expect("activation must succeed");
        assert_eq!(tunnel.id, "herd-tun");
        guards.push(guard);
    }

    assert_eq!(guards.len(), 50);
    assert_eq!(*entry.state.read(), TunnelState::Active);
    assert_eq!(entry.stats.active_conns.load(Ordering::SeqCst), 50);

    // Drop 49 guards; 1 guard remains active
    guards.truncate(1);
    assert_eq!(entry.stats.active_conns.load(Ordering::SeqCst), 1);

    // Sleep past idle timeout - tunnel MUST NOT suspend because active_conns > 0
    tokio::time::sleep(Duration::from_millis(150)).await;
    assert_eq!(*entry.state.read(), TunnelState::Active);

    // Drop the last guard
    guards.clear();
    assert_eq!(entry.stats.active_conns.load(Ordering::SeqCst), 0);

    // Sleep past idle timeout - now it MUST suspend
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert_eq!(*entry.state.read(), TunnelState::Suspended);

    // Re-activate from suspended state
    let (resumed, guard_resumed) = lifecycle.get_or_activate("herd-tun").await.unwrap();
    assert_eq!(resumed.id, "herd-tun");
    assert_eq!(*entry.state.read(), TunnelState::Active);
    assert_eq!(entry.stats.active_conns.load(Ordering::SeqCst), 1);

    drop(guard_resumed);
    lifecycle.stop().await;
}

// =============================================================================
// Adversarial Test 4: In-Tunnel DNS Leak Prevention Under Heavy Churn
// =============================================================================
#[tokio::test]
async fn test_adv_dns_leak_prevention_and_cache_churn() {
    let cache = Arc::new(DnsLruCache::new(256));

    // Hammer cache with 2,500 distinct domain insertions across 10 concurrent tasks
    let mut join_set = JoinSet::new();
    for task_id in 0..10 {
        let c = Arc::clone(&cache);
        join_set.spawn(async move {
            for i in 0..250 {
                let domain = format!("host-{}-{}.churn.test", task_id, i);
                let ip: IpAddr = format!("10.200.{}.{}", task_id + 1, (i % 250) + 1).parse().unwrap();
                c.insert(&domain, vec![ip], 60);
            }
        });
    }

    while let Some(res) = join_set.join_next().await {
        res.unwrap();
    }

    // Capacity must be strictly bounded at 256
    assert!(cache.len() <= 256, "Cache size {} exceeded capacity 256", cache.len());

    // Verify InTunnelDnsResolver strictly fails without leaking when DNS server is unreachable
    let unreachable_dns: [IpAddr; 1] = ["192.0.2.1".parse().unwrap()]; // RFC 5737 TEST-NET-1 (unroutable)
    let resolver = InTunnelDnsResolver::new(&unreachable_dns);

    let (bridge, _tx, _rx) = VirtualTunBridge::new(1420, 64);
    let iface_cfg = WgInterfaceConfig {
        private_key: StaticSecret::from([1u8; 32]),
        addresses: vec!["10.0.0.2/32".parse().unwrap()],
        dns: vec!["192.0.2.1".parse().unwrap()],
        listen_port: None,
        mtu: 1420,
    };
    let stack = VirtualNetworkStack::new(&iface_cfg, bridge).await.unwrap();

    // Query non-existent domain to unroutable DNS
    let start = std::time::Instant::now();
    let res = resolver.resolve(&stack, "leak-check.internal.corp").await;
    let elapsed = start.elapsed();

    // It MUST fail cleanly and NOT resolve via host system DNS
    assert!(res.is_err(), "Expected DNS resolution failure, got {:?}", res);
    // Verified query failed cleanly through timeout
    assert!(elapsed >= Duration::from_millis(50));
}

// =============================================================================
// Adversarial Test 5: IPv6 Userspace Routing & Smoltcp Netstack Boundary
// =============================================================================
#[tokio::test]
async fn test_adv_ipv6_userspace_routing_and_boundaries() {
    let (mut bridge, _bridge_tx, mut bridge_rx) = VirtualTunBridge::new(1420, 64);

    let src_ipv6: Ipv6Addr = "2606:4700:110:8524:5b27:35a3:e0e7:4816".parse().unwrap();
    let dst_ipv6: Ipv6Addr = "2606:4700:4700::1111".parse().unwrap();

    // 1. Minimum IPv6 payload (UDP zero payload)
    let mut min_buf = Vec::new();
    PacketBuilder::ipv6(src_ipv6.octets(), dst_ipv6.octets(), 64)
        .udp(10001, 53)
        .write(&mut min_buf, &[])
        .unwrap();

    let tx = bridge.transmit(smoltcp::time::Instant::from_millis(0)).unwrap();
    tx.consume(min_buf.len(), |b| b.copy_from_slice(&min_buf));

    // 2. Exact MTU IPv6 packet (MTU 1420: 40-byte IPv6 header + 8-byte UDP header + 1372 payload)
    let max_payload = vec![0xAA; 1372];
    let mut max_buf = Vec::new();
    PacketBuilder::ipv6(src_ipv6.octets(), dst_ipv6.octets(), 64)
        .udp(10002, 53)
        .write(&mut max_buf, &max_payload)
        .unwrap();
    assert_eq!(max_buf.len(), 1420);

    let tx2 = bridge.transmit(smoltcp::time::Instant::from_millis(0)).unwrap();
    tx2.consume(max_buf.len(), |b| b.copy_from_slice(&max_buf));

    // 3. Receive and verify both packets through bridge_rx
    let mut pool = gotatun::packet::PacketBufPool::new(1420);
    let iter = bridge_rx.recv(&mut pool).await.unwrap();
    let pkts: Vec<_> = iter.collect();
    assert_eq!(pkts.len(), 2);

    // Verify min packet
    let p0 = pkts[0].clone().into_bytes();
    let s0 = etherparse::SlicedPacket::from_ip(p0.as_ref()).unwrap();
    assert_eq!(s0.payload.len(), 0);

    // Verify max MTU packet
    let p1 = pkts[1].clone().into_bytes();
    let s1 = etherparse::SlicedPacket::from_ip(p1.as_ref()).unwrap();
    assert_eq!(s1.payload.len(), 1372);
    assert_eq!(s1.payload, &max_payload[..]);

    // 4. Boundary: Jumbo packet exceeding MTU (1500 bytes on 1420 bridge)
    let jumbo_payload = vec![0xBB; 1460];
    let mut jumbo_buf = Vec::new();
    PacketBuilder::ipv6(src_ipv6.octets(), dst_ipv6.octets(), 64)
        .udp(10003, 53)
        .write(&mut jumbo_buf, &jumbo_payload)
        .unwrap();
    assert!(jumbo_buf.len() > 1420);

    let tx3 = bridge.transmit(smoltcp::time::Instant::from_millis(0)).unwrap();
    // Consuming jumbo size must be handled safely
    tx3.consume(jumbo_buf.len(), |b| {
        // bridge MTU limits buffer slice to bridge MTU
        let copy_len = b.len().min(jumbo_buf.len());
        b[..copy_len].copy_from_slice(&jumbo_buf[..copy_len]);
    });
}

// =============================================================================
// Adversarial Test 6: Raw Malformed SOCKS5 Packets against handle_socks5
// =============================================================================
#[tokio::test]
async fn test_adv_raw_malformed_socks5_packets() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use wpmulti::proxy::handle_socks5;

    let reg = Arc::new(TunnelRegistry::new());
    let conf = make_test_conf("s5-malform-tun", "127.0.0.1:51820");
    reg.register(TunnelEntry::new("s5-malform-tun", conf, LifecycleMode::Lazy)).unwrap();
    let lc = LifecycleController::new(Arc::clone(&reg), Duration::from_secs(60), Duration::from_millis(50));

    let settings = SharedListenerSettings {
        name: "s5_malform".to_string(),
        listener_type: wpmulti::config::ListenerType::Socks5,
        bind: "127.0.0.1:1080".parse().unwrap(),
        auth_mode: AuthMode::Global,
        global_password: Some("correctpass".to_string()),
        default_strategy: PoolStrategy::RoundRobin,
        allow_anonymous: false,
        pool: TunnelPoolSelection::All,
    };
    let router = MultiTenantRouter::from_settings(&settings, lc, reg);

    // Subtest A: Wrong SOCKS version (0x04)
    {
        let (client, server) = tokio::io::duplex(1024);
        let r = Arc::clone(&router);
        let srv_task = tokio::spawn(async move { handle_socks5(server, r).await });

        let mut cl = client;
        cl.write_all(&[0x04, 0x01, 0x00]).await.unwrap();
        let res = srv_task.await.unwrap();
        assert!(res.is_err(), "Expected error for SOCKS4 version, got {:?}", res);
    }

    // Subtest B: Nmethods = 0
    {
        let (client, server) = tokio::io::duplex(1024);
        let r = Arc::clone(&router);
        let srv_task = tokio::spawn(async move { handle_socks5(server, r).await });

        let mut cl = client;
        cl.write_all(&[0x05, 0x00]).await.unwrap();
        let res = srv_task.await.unwrap();
        assert!(res.is_err(), "Expected error for nmethods=0, got {:?}", res);
    }

    // Subtest C: Unsupported method offered (0x01 GSSAPI only) -> reply must be [0x05, 0xFF]
    {
        let (client, server) = tokio::io::duplex(1024);
        let r = Arc::clone(&router);
        let srv_task = tokio::spawn(async move { handle_socks5(server, r).await });

        let mut cl = client;
        cl.write_all(&[0x05, 0x01, 0x01]).await.unwrap();
        let mut reply = [0u8; 2];
        cl.read_exact(&mut reply).await.unwrap();
        assert_eq!(reply, [0x05, 0xFF]);
        let res = srv_task.await.unwrap();
        assert!(res.is_err());
    }

    // Subtest D: User/Pass authentication with bad password -> reply must be [0x01, 0x01]
    {
        let (client, server) = tokio::io::duplex(1024);
        let r = Arc::clone(&router);
        let srv_task = tokio::spawn(async move { handle_socks5(server, r).await });

        let mut cl = client;
        // Greeting: SOCKS5, 1 method: 0x02 (User/Pass)
        cl.write_all(&[0x05, 0x01, 0x02]).await.unwrap();
        let mut reply = [0u8; 2];
        cl.read_exact(&mut reply).await.unwrap();
        assert_eq!(reply, [0x05, 0x02]);

        // Subnegotiation: ver=1, ulen=7 ("s5-malform-tun"), plen=8 ("wrongpwd")
        let mut subneg = vec![0x01, 14];
        subneg.extend_from_slice(b"s5-malform-tun");
        subneg.push(8);
        subneg.extend_from_slice(b"wrongpwd");
        cl.write_all(&subneg).await.unwrap();

        let mut auth_reply = [0u8; 2];
        cl.read_exact(&mut auth_reply).await.unwrap();
        assert_eq!(auth_reply, [0x01, 0x01]); // 0x01 = Auth Failure
        let res = srv_task.await.unwrap();
        assert!(res.is_err());
    }
}

// =============================================================================
// Adversarial Test 7: Raw Malformed HTTP Requests against handle_http
// =============================================================================
#[tokio::test]
async fn test_adv_raw_malformed_http_requests() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use wpmulti::proxy::handle_http;

    let reg = Arc::new(TunnelRegistry::new());
    let conf = make_test_conf("http-malform-tun", "127.0.0.1:51820");
    reg.register(TunnelEntry::new("http-malform-tun", conf, LifecycleMode::Lazy)).unwrap();
    let lc = LifecycleController::new(Arc::clone(&reg), Duration::from_secs(60), Duration::from_millis(50));

    let settings = SharedListenerSettings {
        name: "http_malform".to_string(),
        listener_type: wpmulti::config::ListenerType::Http,
        bind: "127.0.0.1:8080".parse().unwrap(),
        auth_mode: AuthMode::Global,
        global_password: Some("httppass".to_string()),
        default_strategy: PoolStrategy::RoundRobin,
        allow_anonymous: false,
        pool: TunnelPoolSelection::All,
    };
    let router = MultiTenantRouter::from_settings(&settings, lc, reg);

    // Subtest A: Missing auth credentials -> must reply 407 Proxy Authentication Required
    {
        let (client, server) = tokio::io::duplex(2048);
        let r = Arc::clone(&router);
        let srv_task = tokio::spawn(async move { handle_http(server, r).await });

        let mut cl = client;
        cl.write_all(b"CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n").await.unwrap();

        let mut resp_buf = vec![0u8; 256];
        let n = cl.read(&mut resp_buf).await.unwrap();
        let resp_str = String::from_utf8_lossy(&resp_buf[..n]);
        assert!(resp_str.contains("407 Proxy Authentication Required"));
        assert!(resp_str.contains("Proxy-Authenticate: Basic"));
        let _ = srv_task.await.unwrap();
    }

    // Subtest B: Bad Base64 in Proxy-Authorization -> must reply 407
    {
        let (client, server) = tokio::io::duplex(2048);
        let r = Arc::clone(&router);
        let srv_task = tokio::spawn(async move { handle_http(server, r).await });

        let mut cl = client;
        cl.write_all(b"CONNECT example.com:443 HTTP/1.1\r\nProxy-Authorization: Basic ???bad_base64???\r\n\r\n").await.unwrap();

        let mut resp_buf = vec![0u8; 256];
        let n = cl.read(&mut resp_buf).await.unwrap();
        let resp_str = String::from_utf8_lossy(&resp_buf[..n]);
        assert!(resp_str.contains("407 Proxy Authentication Required"));
        let _ = srv_task.await.unwrap();
    }

    // Subtest C: Invalid Authority (no port) with valid auth -> must reply 400 Bad Request
    {
        let (client, server) = tokio::io::duplex(2048);
        let r = Arc::clone(&router);
        let srv_task = tokio::spawn(async move { handle_http(server, r).await });

        // Base64 of "http-malform-tun:httppass"
        let auth_val = base64::Engine::encode(&base64::engine::general_purpose::STANDARD, b"http-malform-tun:httppass");
        let req = format!("CONNECT invalid_authority_no_port HTTP/1.1\r\nProxy-Authorization: Basic {}\r\n\r\n", auth_val);

        let mut cl = client;
        cl.write_all(req.as_bytes()).await.unwrap();

        let mut resp_buf = vec![0u8; 256];
        let n = cl.read(&mut resp_buf).await.unwrap();
        let resp_str = String::from_utf8_lossy(&resp_buf[..n]);
        assert!(resp_str.contains("400 Bad Request"));
        let res = srv_task.await.unwrap();
        assert!(res.is_err());
    }

    // Subtest D: Non-CONNECT origin-form request (e.g. GET /index.html) -> must reply 400 Bad Request
    {
        let (client, server) = tokio::io::duplex(2048);
        let r = Arc::clone(&router);
        let srv_task = tokio::spawn(async move { handle_http(server, r).await });

        let auth_val = base64::Engine::encode(&base64::engine::general_purpose::STANDARD, b"http-malform-tun:httppass");
        let req = format!("GET /index.html HTTP/1.1\r\nHost: example.com\r\nProxy-Authorization: Basic {}\r\n\r\n", auth_val);

        let mut cl = client;
        cl.write_all(req.as_bytes()).await.unwrap();

        let mut resp_buf = vec![0u8; 256];
        let n = cl.read(&mut resp_buf).await.unwrap();
        let resp_str = String::from_utf8_lossy(&resp_buf[..n]);
        assert!(resp_str.contains("400 Bad Request"));
        let res = srv_task.await.unwrap();
        assert!(res.is_err());
    }
}

