mod common;

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::Duration;

use common::{
    allocate_ephemeral_port, AdminTestClient, HttpProxyTestClient,
    SharedListenerFixture, Socks5Target, Socks5TestClient, TestEnvironment, WgConfBuilder,
    WgPeerFixture, WpMultiTomlBuilder,
};
use etherparse::PacketBuilder;
use gotatun::tun::{IpRecv, IpSend};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, UdpSocket};

use wpmulti::config::{
    load_tunnel_config_from_file, load_tunnel_config_from_str, parse_wg_conf,
    AuthMode, DnsStrategy, LifecycleMode, LogLevel, MainConfig, PoolStrategy, TuiSortField,
};
use wpmulti::core::{
    DedicatedTunnelRouter, LifecycleController, ListenerSupervisor, MultiTenantRouter,
    TunnelConnGuard, TunnelEntry, TunnelManager, TunnelRegistry, TunnelState,
};
use wpmulti::netstack::{
    build_query, parse_response, DnsLruCache, QueryType, VirtualTunBridge,
};
use wpmulti::proxy::{
    build_socks5_udp_packet, extract_basic_auth, handle_http, handle_socks5_with_addrs,
    parse_authority, parse_socks5_udp_packet, DirectTunnelTarget, PoolKeyword, SingleTunnelRouter,
    TargetAddr, TunnelRouter, TunnelSelector, METHOD_NO_AUTH, METHOD_USER_PASS,
};
use wpmulti::tui::{format_bytes, render_dashboard, TuiApp, TuiDataSource};

fn make_valid_wg_conf() -> String {
    WgConfBuilder::new()
        .add_peer(WgPeerFixture::new(
            "bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo=",
            "127.0.0.1:51820",
        ))
        .build_ini()
}

// =============================================================================
// Feature 1: WireGuard Conf Parser (F1)
// =============================================================================

#[test]
fn test_f1_wg_conf_ipv4_standard() {
    let conf_content = "\
[Interface]
PrivateKey = 0OaUaQd4uJq5m8eN8uJq5m8eN8uJq5m8eN8uJq5m8eM=
Address = 10.0.0.2/32
DNS = 1.1.1.1
MTU = 1420

[Peer]
PublicKey = bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo=
Endpoint = 198.51.100.1:51820
AllowedIPs = 0.0.0.0/0
";
    let (iface, peers) = parse_wg_conf(conf_content).expect("Failed to parse standard IPv4 WG conf");
    assert_eq!(iface.addresses.len(), 1);
    assert_eq!(
        iface.addresses[0],
        "10.0.0.2/32".parse().unwrap()
    );
    assert_eq!(iface.dns.len(), 1);
    assert_eq!(iface.dns[0], "1.1.1.1".parse::<IpAddr>().unwrap());
    assert_eq!(iface.mtu, 1420);
    assert_eq!(peers.len(), 1);
    assert_eq!(peers[0].endpoint, "198.51.100.1:51820");
    assert_eq!(peers[0].allowed_ips.len(), 1);
}

#[test]
fn test_f1_wg_conf_dual_stack() {
    let conf = WgConfBuilder::new()
        .private_key("0OaUaQd4uJq5m8eN8uJq5m8eN8uJq5m8eN8uJq5m8eM=")
        .addresses(&["172.16.0.2/32", "2606:4700:110:8524:5b27:35a3:e0e7:4816/128"])
        .dns(&["1.1.1.1", "2606:4700:4700::1111"])
        .add_peer(
            WgPeerFixture::new(
                "bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo=",
                "162.159.192.1:2408",
            )
            .allowed_ips(&["0.0.0.0/0", "::/0"]),
        )
        .build_ini();

    let (iface, _peers) = parse_wg_conf(&conf).expect("Failed to parse dual stack WG conf");
    assert_eq!(iface.addresses.len(), 2);
    assert!(iface.addresses[0].is_ipv4());
    assert!(iface.addresses[1].is_ipv6());
    assert_eq!(iface.dns.len(), 2);
    assert!(iface.dns[0].is_ipv4());
    assert!(iface.dns[1].is_ipv6());
}

#[test]
fn test_f1_wg_conf_custom_mtu_and_listen_port() {
    let conf = WgConfBuilder::new()
        .private_key("0OaUaQd4uJq5m8eN8uJq5m8eN8uJq5m8eN8uJq5m8eM=")
        .listen_port(51820)
        .mtu(1280)
        .add_peer(WgPeerFixture::new(
            "bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo=",
            "127.0.0.1:51820",
        ))
        .build_ini();

    let (iface, _peers) = parse_wg_conf(&conf).expect("Failed to parse custom MTU and ListenPort");
    assert_eq!(iface.listen_port, Some(51820));
    assert_eq!(iface.mtu, 1280);
}

#[test]
fn test_f1_wg_conf_multi_peer_with_psk_and_keepalive() {
    let conf = WgConfBuilder::new()
        .private_key("0OaUaQd4uJq5m8eN8uJq5m8eN8uJq5m8eN8uJq5m8eM=")
        .add_peer(
            WgPeerFixture::new(
                "bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo=",
                "198.51.100.1:51820",
            )
            .preshared_key("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=")
            .persistent_keepalive(15),
        )
        .add_peer(
            WgPeerFixture::new(
                "bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo=",
                "198.51.100.2:51820",
            )
            .persistent_keepalive(30),
        )
        .build_ini();

    let (_iface, peers) = parse_wg_conf(&conf).expect("Failed to parse multi-peer WG conf");
    assert_eq!(peers.len(), 2);
    assert!(peers[0].preshared_key.is_some());
    assert_eq!(peers[0].persistent_keepalive, Some(15));
    assert!(peers[1].preshared_key.is_none());
    assert_eq!(peers[1].persistent_keepalive, Some(30));
}

#[test]
fn test_f1_wg_conf_wg_quick_directives_tolerance() {
    let conf = "\
# wg-quick managed interface
[Interface]
PrivateKey = 0OaUaQd4uJq5m8eN8uJq5m8eN8uJq5m8eN8uJq5m8eM=
Address = 10.0.0.2/32
DNS = 1.1.1.1
Table = off
PostUp = iptables -A FORWARD -i %i -j ACCEPT
PreDown = echo 'disconnecting...'
SaveConfig = true ; ignore this comment

[Peer]
PublicKey = bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo=
Endpoint = 198.51.100.1:51820 # endpoint comment
AllowedIPs = 0.0.0.0/0
";
    let (iface, peers) = parse_wg_conf(conf).expect("wg-quick directives must be tolerated");
    assert_eq!(iface.addresses.len(), 1);
    assert_eq!(peers.len(), 1);
}

// =============================================================================
// Feature 2: Main TOML Config Parser (F2)
// =============================================================================

#[test]
fn test_f2_toml_config_minimal_defaults() {
    let toml_str = r#"
[global]
config_dir = "/etc/wpmulti/conf.d"
"#;
    let cfg: MainConfig = toml::from_str(toml_str).expect("Failed to parse minimal TOML");
    assert_eq!(cfg.global.bind_address, "127.0.0.1".parse::<IpAddr>().unwrap());
    assert_eq!(cfg.global.log_level, LogLevel::Info);
    assert_eq!(cfg.global.dns_strategy, DnsStrategy::TunnelOnly);
    assert_eq!(cfg.lifecycle.mode, LifecycleMode::Lazy);
    assert_eq!(cfg.lifecycle.idle_timeout, Duration::from_secs(300));
}

#[test]
fn test_f2_toml_config_full_schema() {
    let env = TestEnvironment::new("f2_full").unwrap();
    let toml_str = WpMultiTomlBuilder::new(env.conf_dir().to_path_buf())
        .bind_address("0.0.0.0")
        .log_level("debug")
        .lifecycle_mode("lazy")
        .idle_timeout("1m")
        .base_ports(Some(10080), Some(18080))
        .add_shared_listener(SharedListenerFixture {
            name: "public_s5".to_string(),
            proto_type: "socks5".to_string(),
            bind: "127.0.0.1:1080".parse().unwrap(),
            auth_mode: "none".to_string(),
            global_password: None,
            default_strategy: "round-robin".to_string(),
            allow_anonymous: true,
            pool: "all".to_string(),
        })
        .admin(true, Some("127.0.0.1:9090".parse().unwrap()), Some("adm_token"))
        .build_toml();

    let cfg: MainConfig = toml::from_str(&toml_str).expect("Failed to parse full TOML");
    assert_eq!(cfg.global.bind_address, "0.0.0.0".parse::<IpAddr>().unwrap());
    assert_eq!(cfg.global.log_level, LogLevel::Debug);
    assert_eq!(cfg.per_tunnel.base_socks5_port, Some(10080));
    assert_eq!(cfg.per_tunnel.base_http_port, Some(18080));
    assert_eq!(cfg.shared_listeners.len(), 1);
    assert!(cfg.admin.enabled);
    assert_eq!(cfg.admin.auth_token, Some("adm_token".to_string()));
}

#[test]
fn test_f2_toml_config_per_tunnel_port_overrides() {
    let env = TestEnvironment::new("f2_override").unwrap();
    let toml_str = WpMultiTomlBuilder::new(env.conf_dir().to_path_buf())
        .base_ports(Some(10000), Some(20000))
        .add_override("tunnel-alpha", Some(10500), Some(20500))
        .add_override("tunnel-beta", Some(10501), None)
        .build_toml();

    let cfg: MainConfig = toml::from_str(&toml_str).expect("Failed to parse port overrides");
    assert_eq!(cfg.per_tunnel.overrides.len(), 2);
    let alpha = cfg.per_tunnel.overrides.get("tunnel-alpha").unwrap();
    assert_eq!(alpha.socks5_port, Some(10500));
    assert_eq!(alpha.http_port, Some(20500));
    let beta = cfg.per_tunnel.overrides.get("tunnel-beta").unwrap();
    assert_eq!(beta.socks5_port, Some(10501));
    assert_eq!(beta.http_port, None);
}

#[test]
fn test_f2_toml_config_multiple_shared_listeners() {
    let env = TestEnvironment::new("f2_shared").unwrap();
    let toml_str = WpMultiTomlBuilder::new(env.conf_dir().to_path_buf())
        .add_shared_listener(SharedListenerFixture {
            name: "s5_shared".to_string(),
            proto_type: "socks5".to_string(),
            bind: "127.0.0.1:1080".parse().unwrap(),
            auth_mode: "per_tunnel".to_string(),
            global_password: None,
            default_strategy: "round-robin".to_string(),
            allow_anonymous: false,
            pool: "all".to_string(),
        })
        .add_shared_listener(SharedListenerFixture {
            name: "http_shared".to_string(),
            proto_type: "http".to_string(),
            bind: "127.0.0.1:8080".parse().unwrap(),
            auth_mode: "global".to_string(),
            global_password: Some("secret123".to_string()),
            default_strategy: "random".to_string(),
            allow_anonymous: false,
            pool: "wgcf".to_string(),
        })
        .build_toml();

    let cfg: MainConfig = toml::from_str(&toml_str).expect("Failed to parse shared listeners");
    assert_eq!(cfg.shared_listeners.len(), 2);
    assert_eq!(cfg.shared_listeners[0].auth_mode, AuthMode::PerTunnel);
    assert_eq!(cfg.shared_listeners[0].default_strategy, PoolStrategy::RoundRobin);
    assert_eq!(cfg.shared_listeners[1].auth_mode, AuthMode::Global);
    assert_eq!(cfg.shared_listeners[1].default_strategy, PoolStrategy::Random);
}

#[test]
fn test_f2_toml_config_lifecycle_and_eager_tunnels() {
    let toml_str = r#"
[global]
config_dir = "/etc/wpmulti/conf.d"

[lifecycle]
mode = "lazy"
idle_timeout = "45s"
handshake_timeout = "8s"
eager_tunnels = ["wgcf-001", "wgcf-002"]
"#;
    let cfg: MainConfig = toml::from_str(toml_str).expect("Failed to parse lifecycle TOML");
    assert_eq!(cfg.lifecycle.mode, LifecycleMode::Lazy);
    assert_eq!(cfg.lifecycle.idle_timeout, Duration::from_secs(45));
    assert_eq!(cfg.lifecycle.handshake_timeout, Duration::from_secs(8));
    assert_eq!(cfg.lifecycle.eager_tunnels, vec!["wgcf-001", "wgcf-002"]);
}

// =============================================================================
// Feature 3: Unique Tunnel ID Addressing (F3)
// =============================================================================

#[test]
fn test_f3_unique_id_derivation_from_file_path() {
    let env = TestEnvironment::new("f3_deriv").unwrap();
    let conf = make_valid_wg_conf();
    let p1 = env.write_conf("wgcf-warp-east.conf", &conf).unwrap();
    let p2 = env.write_conf("us-west-01.conf", &conf).unwrap();

    let t1 = load_tunnel_config_from_file(&p1).unwrap();
    let t2 = load_tunnel_config_from_file(&p2).unwrap();

    assert_eq!(t1.id, "wgcf-warp-east");
    assert_eq!(t2.id, "us-west-01");
}

#[test]
fn test_f3_unique_id_multiple_clones_registered() {
    let registry = TunnelRegistry::new();
    for i in 1..=10 {
        let id = format!("wgcf-{:03}", i);
        let conf = load_tunnel_config_from_str(&id, &make_valid_wg_conf()).unwrap();
        let entry = TunnelEntry::new(id.clone(), conf, LifecycleMode::Lazy);
        registry.register(entry).expect("Registration must succeed");
    }

    assert_eq!(registry.count(), 10);
    assert_eq!(registry.active_count(), 0);
    for i in 1..=10 {
        let id = format!("wgcf-{:03}", i);
        assert!(registry.get(&id).is_some());
    }
}

#[test]
fn test_f3_unique_id_lookup_by_exact_id() {
    let registry = TunnelRegistry::new();
    let conf_a = load_tunnel_config_from_str(
        "node-a",
        &WgConfBuilder::new()
            .mtu(1280)
            .add_peer(WgPeerFixture::new("bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo=", "127.0.0.1:51820"))
            .build_ini(),
    )
    .unwrap();
    let conf_b = load_tunnel_config_from_str(
        "node-b",
        &WgConfBuilder::new()
            .mtu(1420)
            .add_peer(WgPeerFixture::new("bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo=", "127.0.0.1:51820"))
            .build_ini(),
    )
    .unwrap();

    registry.register(TunnelEntry::new("node-a", conf_a, LifecycleMode::Lazy)).unwrap();
    registry.register(TunnelEntry::new("node-b", conf_b, LifecycleMode::Eager)).unwrap();

    let entry_a = registry.get("node-a").unwrap();
    let entry_b = registry.get("node-b").unwrap();

    assert_eq!(entry_a.config.read().interface.mtu, 1280);
    assert_eq!(entry_b.config.read().interface.mtu, 1420);
    assert_eq!(entry_b.lifecycle_mode, LifecycleMode::Eager);
}

#[test]
fn test_f3_unique_id_directory_batch_load() {
    let env = TestEnvironment::new("f3_batch").unwrap();
    for i in 1..=5 {
        let filename = format!("client_{}.conf", i);
        env.write_conf(&filename, &make_valid_wg_conf()).unwrap();
    }

    let tunnels = wpmulti::load_tunnel_configs_from_dir(env.conf_dir()).unwrap();
    assert_eq!(tunnels.len(), 5);
    let mut ids: Vec<_> = tunnels.iter().map(|t| t.id.as_str()).collect();
    ids.sort();
    assert_eq!(ids, vec!["client_1", "client_2", "client_3", "client_4", "client_5"]);
}

#[test]
fn test_f3_unique_id_summary_snapshots() {
    let registry = TunnelRegistry::new();
    let conf = load_tunnel_config_from_str("alpha", &make_valid_wg_conf()).unwrap();
    let entry = TunnelEntry::new("alpha", conf, LifecycleMode::Lazy);
    entry.set_assigned_port(10080);
    registry.register(entry).unwrap();

    let stats = registry.get_stats();
    assert_eq!(stats.len(), 1);
    assert_eq!(stats[0].id, "alpha");
    assert_eq!(stats[0].state, TunnelState::Dormant);
    assert_eq!(stats[0].assigned_port, Some(10080));
}

// =============================================================================
// Feature 4: smoltcp Userspace Layer 3 Bridge (F4)
// =============================================================================

#[test]
fn test_f4_bridge_capabilities_and_medium() {
    let (bridge, _ip_send, _ip_recv) = VirtualTunBridge::new(1420, 64);
    use smoltcp::phy::Device;
    let caps = bridge.capabilities();
    assert_eq!(caps.medium, smoltcp::phy::Medium::Ip);
    assert_eq!(caps.max_transmission_unit, 1420);
}

#[tokio::test]
async fn test_f4_bridge_rx_pipeline_delivers_packet() {
    let (mut bridge, mut ip_send, _ip_recv) = VirtualTunBridge::new(1420, 64);
    let raw_payload = b"test_f4_rx_packet";

    let mut ipv4_buf = Vec::new();
    let b = PacketBuilder::ipv4([10, 0, 0, 1], [10, 0, 0, 2], 64).udp(1234, 5678);
    ipv4_buf.reserve(b.size(raw_payload.len()));
    b.write(&mut ipv4_buf, raw_payload).unwrap();

    // gotatun IpSend sends packet into bridge
    let pkt = gotatun::packet::Packet::copy_from(ipv4_buf.as_slice()).try_into_ip().unwrap();
    ip_send.send(pkt).await.unwrap();

    // Bridge rx_token receives packet into smoltcp
    use smoltcp::phy::{Device, RxToken};
    let token_res = bridge.receive(smoltcp::time::Instant::from_millis(0));
    assert!(token_res.is_some());
    let (rx_token, _tx_token) = token_res.unwrap();

    rx_token.consume(|buffer| {
        let sliced = etherparse::SlicedPacket::from_ip(buffer).unwrap();
        assert_eq!(sliced.payload, raw_payload);
    });
}

#[tokio::test]
async fn test_f4_bridge_tx_pipeline_transmits_packet() {
    let (mut bridge, _ip_send, mut ip_recv) = VirtualTunBridge::new(1420, 64);
    let raw_payload = b"test_f4_tx_packet";

    let mut ipv4_buf = Vec::new();
    let b = PacketBuilder::ipv4([10, 0, 0, 2], [10, 0, 0, 1], 64).udp(5678, 1234);
    ipv4_buf.reserve(b.size(raw_payload.len()));
    b.write(&mut ipv4_buf, raw_payload).unwrap();

    // smoltcp transmit into bridge
    use smoltcp::phy::{Device, TxToken};
    let tx_token = bridge.transmit(smoltcp::time::Instant::from_millis(0)).unwrap();
    tx_token.consume(ipv4_buf.len(), |buf| {
        buf.copy_from_slice(&ipv4_buf);
    });

    // gotatun IpRecv drains packet
    let mut pool = gotatun::packet::PacketBufPool::new(1420);
    let iter = ip_recv.recv(&mut pool).await.unwrap();
    let batch: Vec<_> = iter.collect();
    assert_eq!(batch.len(), 1);
    assert_eq!(batch[0].clone().into_bytes().as_ref(), &ipv4_buf[..]);
}

#[tokio::test]
async fn test_f4_bridge_dual_stack_ipv4_and_ipv6() {
    let (mut bridge, mut ip_send, _ip_recv) = VirtualTunBridge::new(1420, 64);

    // IPv6 packet
    let v6_payload = b"ipv6_bridge_test";
    let mut v6_buf = Vec::new();
    let b6 = PacketBuilder::ipv6(
        "fd00::1".parse::<Ipv6Addr>().unwrap().octets(),
        "fd00::2".parse::<Ipv6Addr>().unwrap().octets(),
        64,
    )
    .udp(9999, 8888);
    v6_buf.reserve(b6.size(v6_payload.len()));
    b6.write(&mut v6_buf, v6_payload).unwrap();

    let pkt = gotatun::packet::Packet::copy_from(v6_buf.as_slice()).try_into_ip().unwrap();
    ip_send.send(pkt).await.unwrap();

    use smoltcp::phy::{Device, RxToken};
    let (rx_token, _) = bridge.receive(smoltcp::time::Instant::from_millis(0)).unwrap();
    rx_token.consume(|buffer| {
        let sliced = etherparse::SlicedPacket::from_ip(buffer).unwrap();
        assert_eq!(sliced.payload, v6_payload);
    });
}

#[tokio::test]
async fn test_f4_bridge_notify_wakes_event_loop() {
    let (_bridge, mut ip_send, _ip_recv) = VirtualTunBridge::new(1420, 64);
    let payload = b"wake_event_loop";
    let mut buf = Vec::new();
    let b = PacketBuilder::ipv4([10, 0, 0, 1], [10, 0, 0, 2], 64).udp(1, 2);
    buf.reserve(b.size(payload.len()));
    b.write(&mut buf, payload).unwrap();

    let pkt = gotatun::packet::Packet::copy_from(buf.as_slice()).try_into_ip().unwrap();
    let send_res = ip_send.send(pkt).await;
    assert!(send_res.is_ok());
}

// =============================================================================
// Feature 5: In-Tunnel Remote DNS (1.1.1.1 fallback) (F5)
// =============================================================================

#[test]
fn test_f5_dns_query_encoding_a_record() {
    let query_bytes = build_query("example.com", QueryType::A, 0x1234).unwrap();
    assert!(query_bytes.len() >= 12);
    assert_eq!(&query_bytes[0..2], &0x1234u16.to_be_bytes());
    // Flags: QR=0, RD=1
    assert_eq!(&query_bytes[2..4], &0x0100u16.to_be_bytes());
    // QDCOUNT: 1
    assert_eq!(&query_bytes[4..6], &1u16.to_be_bytes());
}

#[test]
fn test_f5_dns_query_encoding_aaaa_record() {
    let query_bytes = build_query("ipv6.example.org", QueryType::AAAA, 0xABCD).unwrap();
    assert_eq!(&query_bytes[0..2], &0xABCDu16.to_be_bytes());
    // Verify QTYPE AAAA (28) in tail
    assert_eq!(&query_bytes[query_bytes.len() - 4..query_bytes.len() - 2], &28u16.to_be_bytes());
}

#[test]
fn test_f5_dns_lru_cache_hit() {
    let cache = DnsLruCache::new(10);
    let ip = "93.184.216.34".parse::<IpAddr>().unwrap();
    cache.insert("example.com", vec![ip], 300);

    let hit = cache.get("example.com");
    assert!(hit.is_some());
    assert_eq!(hit.unwrap(), vec![ip]);

    // Case-insensitivity check
    let hit_upper = cache.get("EXAMPLE.COM.");
    assert!(hit_upper.is_some());
    assert_eq!(hit_upper.unwrap(), vec![ip]);
}

#[test]
fn test_f5_dns_fallback_resolver_default() {
    let conf = WgConfBuilder::new()
        .dns(&[])
        .add_peer(WgPeerFixture::new(
            "bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo=",
            "127.0.0.1:51820",
        ))
        .build_ini();
    let (iface, _peers) = parse_wg_conf(&conf).unwrap();
    assert!(iface.dns.is_empty());

    let main_cfg = MainConfig::default();
    assert_eq!(main_cfg.global.dns_fallback, "1.1.1.1:53".parse().unwrap());
}

#[test]
fn test_f5_dns_response_decoding_success() {
    let mut resp = Vec::new();
    resp.extend_from_slice(&0x4321u16.to_be_bytes()); // TxID
    resp.extend_from_slice(&0x8180u16.to_be_bytes()); // Flags: Response, NoError
    resp.extend_from_slice(&1u16.to_be_bytes());      // QDCOUNT = 1
    resp.extend_from_slice(&1u16.to_be_bytes());      // ANCOUNT = 1
    resp.extend_from_slice(&0u16.to_be_bytes());      // NSCOUNT = 0
    resp.extend_from_slice(&0u16.to_be_bytes());      // ARCOUNT = 0
    resp.extend_from_slice(b"\x03foo\x03com\x00");
    resp.extend_from_slice(&1u16.to_be_bytes());   // QTYPE = A
    resp.extend_from_slice(&1u16.to_be_bytes());   // QCLASS = IN
    resp.extend_from_slice(&[0xC0, 0x0C]);         // Pointer to QNAME
    resp.extend_from_slice(&1u16.to_be_bytes());   // TYPE = A
    resp.extend_from_slice(&1u16.to_be_bytes());   // CLASS = IN
    resp.extend_from_slice(&300u32.to_be_bytes()); // TTL = 300
    resp.extend_from_slice(&4u16.to_be_bytes());   // RDLENGTH = 4
    resp.extend_from_slice(&[93, 184, 216, 34]);   // 93.184.216.34

    let (ips, ttl) = parse_response(&resp, 0x4321).expect("Failed to parse DNS response");
    assert_eq!(ips, vec!["93.184.216.34".parse::<IpAddr>().unwrap()]);
    assert_eq!(ttl, 300);
}

// =============================================================================
// Feature 6: SOCKS5 TCP CONNECT (F6)
// =============================================================================

async fn spawn_real_socks5_server(
    expected_pass: Option<&str>,
) -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let router: Arc<dyn TunnelRouter> = Arc::new(SingleTunnelRouter::new(
        "e2e-socks5",
        Arc::new(DirectTunnelTarget),
        expected_pass.map(|s| ("admin".to_string(), s.to_string())),
    ));
    tokio::spawn(async move {
        if let Ok((stream, peer_addr)) = listener.accept().await {
            let local_ip = stream.local_addr().ok().map(|a| a.ip());
            let _ = handle_socks5_with_addrs(stream, router, local_ip, Some(peer_addr.ip())).await;
        }
    });
    addr
}

async fn spawn_real_http_server(
    expected_pass: Option<&str>,
) -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let router: Arc<dyn TunnelRouter> = Arc::new(SingleTunnelRouter::new(
        "e2e-http",
        Arc::new(DirectTunnelTarget),
        expected_pass.map(|s| ("admin".to_string(), s.to_string())),
    ));
    tokio::spawn(async move {
        if let Ok((stream, _)) = listener.accept().await {
            let _ = handle_http(stream, router).await;
        }
    });
    addr
}

#[tokio::test]
async fn test_f6_socks5_greeting_no_auth() {
    let addr = spawn_real_socks5_server(None).await;

    let mut client = Socks5TestClient::connect(addr).await.unwrap();
    let method = client.greeting(&[METHOD_NO_AUTH]).await.unwrap();
    assert_eq!(method, METHOD_NO_AUTH);
}

#[tokio::test]
async fn test_f6_socks5_greeting_user_pass_negotiation() {
    let addr = spawn_real_socks5_server(Some("pass123")).await;

    let mut client = Socks5TestClient::connect(addr).await.unwrap();
    let method = client.greeting(&[METHOD_NO_AUTH, METHOD_USER_PASS]).await.unwrap();
    assert_eq!(method, METHOD_USER_PASS);
}

#[tokio::test]
async fn test_f6_socks5_rfc1929_authentication_success() {
    let addr = spawn_real_socks5_server(Some("pass123")).await;

    let mut client = Socks5TestClient::connect(addr).await.unwrap();
    let method = client.greeting(&[METHOD_USER_PASS]).await.unwrap();
    assert_eq!(method, METHOD_USER_PASS);
    client.authenticate("admin", "pass123").await.expect("Auth should succeed");
}

#[tokio::test]
async fn test_f6_socks5_connect_ipv4_success() {
    let echo_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let echo_addr = echo_listener.local_addr().unwrap();
    tokio::spawn(async move {
        let (_s, _) = echo_listener.accept().await.unwrap();
    });

    let addr = spawn_real_socks5_server(None).await;
    let mut client = Socks5TestClient::connect(addr).await.unwrap();
    client.greeting(&[METHOD_NO_AUTH]).await.unwrap();
    let ip = match echo_addr.ip() {
        IpAddr::V4(v4) => v4,
        _ => unreachable!(),
    };
    let _stream = client.cmd_connect_ipv4(ip, echo_addr.port()).await.unwrap();
}

#[tokio::test]
async fn test_f6_socks5_connect_streaming_echo() {
    let echo_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let echo_addr = echo_listener.local_addr().unwrap();
    tokio::spawn(async move {
        let (mut s, _) = echo_listener.accept().await.unwrap();
        let mut buf = [0u8; 11];
        s.read_exact(&mut buf).await.unwrap();
        s.write_all(&buf).await.unwrap();
    });

    let addr = spawn_real_socks5_server(None).await;
    let mut client = Socks5TestClient::connect(addr).await.unwrap();
    client.greeting(&[METHOD_NO_AUTH]).await.unwrap();
    let ip = match echo_addr.ip() {
        IpAddr::V4(v4) => v4,
        _ => unreachable!(),
    };
    let mut stream = client.cmd_connect_ipv4(ip, echo_addr.port()).await.unwrap();

    stream.write_all(b"socks5_echo").await.unwrap();
    let mut resp = [0u8; 11];
    stream.read_exact(&mut resp).await.unwrap();
    assert_eq!(&resp, b"socks5_echo");
}

// =============================================================================
// Feature 7: SOCKS5 UDP ASSOCIATE (F7)
// =============================================================================

#[tokio::test]
async fn test_f7_socks5_udp_associate_handshake() {
    let server_addr = spawn_real_socks5_server(None).await;

    let mut client = Socks5TestClient::connect(server_addr).await.unwrap();
    client.greeting(&[METHOD_NO_AUTH]).await.unwrap();
    let session = client.cmd_udp_associate(None).await.unwrap();
    assert_eq!(session.relay_addr().ip(), IpAddr::V4(Ipv4Addr::LOCALHOST));
    assert_ne!(session.relay_addr().port(), 0);
}

#[test]
fn test_f7_socks5_udp_packet_encapsulate_ipv4() {
    let target = TargetAddr::Ip("93.184.216.34:80".parse().unwrap());
    let payload = b"hello_udp_v4";
    let encoded = build_socks5_udp_packet(&target, payload);

    let (parsed_target, parsed_payload) = parse_socks5_udp_packet(&encoded).unwrap();
    assert_eq!(parsed_target, target);
    assert_eq!(parsed_payload, payload);
}

#[test]
fn test_f7_socks5_udp_packet_encapsulate_ipv6() {
    let target = TargetAddr::Ip("[2606:4700:4700::1111]:53".parse().unwrap());
    let payload = b"dns_query_ipv6";
    let encoded = build_socks5_udp_packet(&target, payload);

    let (parsed_target, parsed_payload) = parse_socks5_udp_packet(&encoded).unwrap();
    assert_eq!(parsed_target, target);
    assert_eq!(parsed_payload, payload);
}

#[test]
fn test_f7_socks5_udp_packet_encapsulate_domain() {
    let target = TargetAddr::Domain("dns.google".to_string(), 53);
    let payload = b"dns_over_udp_domain";
    let encoded = build_socks5_udp_packet(&target, payload);

    let (parsed_target, parsed_payload) = parse_socks5_udp_packet(&encoded).unwrap();
    assert_eq!(parsed_target, target);
    assert_eq!(parsed_payload, payload);
}

#[tokio::test]
async fn test_f7_socks5_udp_associate_echo_roundtrip() {
    let echo_udp = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let echo_addr = echo_udp.local_addr().unwrap();
    tokio::spawn(async move {
        let mut buf = [0u8; 1024];
        let (n, client_addr) = echo_udp.recv_from(&mut buf).await.unwrap();
        echo_udp.send_to(&buf[..n], client_addr).await.unwrap();
    });

    let server_addr = spawn_real_socks5_server(None).await;

    let mut client = Socks5TestClient::connect(server_addr).await.unwrap();
    client.greeting(&[METHOD_NO_AUTH]).await.unwrap();
    let session = client.cmd_udp_associate(None).await.unwrap();

    let target = Socks5Target::Ip(echo_addr);
    let echo = session
        .query_echo(&target, b"udp_ping_payload", Duration::from_secs(2))
        .await
        .unwrap();
    assert_eq!(echo, b"udp_ping_payload");
}

// =============================================================================
// Feature 8: HTTP/HTTPS CONNECT Proxy (F8)
// =============================================================================

#[test]
fn test_f8_http_connect_authority_parsing() {
    let (host, port) = parse_authority("example.com:443").unwrap();
    assert_eq!(host, "example.com");
    assert_eq!(port, 443);

    let (ip_host, ip_port) = parse_authority("192.0.2.1:8080").unwrap();
    assert_eq!(ip_host, "192.0.2.1");
    assert_eq!(ip_port, 8080);

    let (v6_host, v6_port) = parse_authority("[2001:db8::1]:8443").unwrap();
    assert_eq!(v6_host, "2001:db8::1");
    assert_eq!(v6_port, 8443);
}

#[tokio::test]
async fn test_f8_http_connect_handshake_200_ok() {
    let target_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let target_addr = target_listener.local_addr().unwrap();
    tokio::spawn(async move {
        let (_s, _) = target_listener.accept().await.unwrap();
    });

    let addr = spawn_real_http_server(None).await;
    let _stream = HttpProxyTestClient::connect_tunnel(addr, &target_addr.to_string(), None)
        .await
        .unwrap();
}

#[test]
fn test_f8_http_basic_auth_header_generation_and_parse() {
    let header_val = HttpProxyTestClient::basic_auth_header("alice", "secret123");
    let mut headers = std::collections::HashMap::new();
    headers.insert("proxy-authorization".to_string(), header_val);
    let (user, pass) = extract_basic_auth(&headers).unwrap();
    assert_eq!(user, "alice");
    assert_eq!(pass, "secret123");
}

#[tokio::test]
async fn test_f8_http_forward_proxy_request_parsing() {
    let origin_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let origin_addr = origin_listener.local_addr().unwrap();
    tokio::spawn(async move {
        let (mut s, _) = origin_listener.accept().await.unwrap();
        let mut buf = [0u8; 256];
        let _ = s.read(&mut buf).await.unwrap();
        let resp_body = "forward_ok";
        let resp = format!(
            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
            resp_body.len(),
            resp_body
        );
        s.write_all(resp.as_bytes()).await.unwrap();
    });

    let addr = spawn_real_http_server(None).await;
    let url = format!("http://{}/get", origin_addr);
    let resp = HttpProxyTestClient::forward_request(addr, "GET", &url, None)
        .await
        .unwrap();
    assert!(resp.is_success());
    assert_eq!(String::from_utf8_lossy(&resp.body), "forward_ok");
}

#[tokio::test]
async fn test_f8_http_connect_tunnel_data_streaming() {
    let target_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let target_addr = target_listener.local_addr().unwrap();
    tokio::spawn(async move {
        let (mut s, _) = target_listener.accept().await.unwrap();
        let mut echo_buf = [0u8; 12];
        s.read_exact(&mut echo_buf).await.unwrap();
        s.write_all(&echo_buf).await.unwrap();
    });

    let addr = spawn_real_http_server(None).await;
    let mut stream = HttpProxyTestClient::connect_tunnel(addr, &target_addr.to_string(), None)
        .await
        .unwrap();

    stream.write_all(b"stream_bytes").await.unwrap();
    let mut echo = [0u8; 12];
    stream.read_exact(&mut echo).await.unwrap();
    assert_eq!(&echo, b"stream_bytes");
}

// =============================================================================
// Feature 9: Per-Config Port Auto-Bind (F9)
// =============================================================================

#[test]
fn test_f9_port_auto_bind_sequential_socks5() {
    let mut config = MainConfig::default();
    config.per_tunnel.enabled = true;
    config.per_tunnel.base_socks5_port = Some(10000);
    config.per_tunnel.base_http_port = None;

    let tunnels = vec![
        load_tunnel_config_from_str("tun-0", &make_valid_wg_conf()).unwrap(),
        load_tunnel_config_from_str("tun-1", &make_valid_wg_conf()).unwrap(),
        load_tunnel_config_from_str("tun-2", &make_valid_wg_conf()).unwrap(),
    ];

    let registry = Arc::new(TunnelRegistry::new());
    for t in tunnels {
        registry.register(TunnelEntry::new(t.id.clone(), t, LifecycleMode::Lazy)).unwrap();
    }

    let entries = registry.all_entries();
    for (i, entry) in entries.iter().enumerate() {
        let port = config.per_tunnel.base_socks5_port.unwrap() + i as u16;
        entry.set_assigned_port(port);
    }

    assert_eq!(*registry.get("tun-0").unwrap().assigned_port.read(), Some(10000));
    assert_eq!(*registry.get("tun-1").unwrap().assigned_port.read(), Some(10001));
    assert_eq!(*registry.get("tun-2").unwrap().assigned_port.read(), Some(10002));
}

#[test]
fn test_f9_port_auto_bind_sequential_http() {
    let mut config = MainConfig::default();
    config.per_tunnel.enabled = true;
    config.per_tunnel.base_socks5_port = None;
    config.per_tunnel.base_http_port = Some(20000);

    let tunnels = vec![
        load_tunnel_config_from_str("http-0", &make_valid_wg_conf()).unwrap(),
        load_tunnel_config_from_str("http-1", &make_valid_wg_conf()).unwrap(),
    ];

    let registry = Arc::new(TunnelRegistry::new());
    for t in tunnels {
        registry.register(TunnelEntry::new(t.id.clone(), t, LifecycleMode::Lazy)).unwrap();
    }

    for (i, entry) in registry.all_entries().iter().enumerate() {
        let port = config.per_tunnel.base_http_port.unwrap() + i as u16;
        entry.set_assigned_port(port);
    }

    assert_eq!(*registry.get("http-0").unwrap().assigned_port.read(), Some(20000));
    assert_eq!(*registry.get("http-1").unwrap().assigned_port.read(), Some(20001));
}

#[test]
fn test_f9_port_override_takes_precedence() {
    let mut config = MainConfig::default();
    config.per_tunnel.enabled = true;
    config.per_tunnel.base_socks5_port = Some(10000);
    config.per_tunnel.overrides.insert(
        "special_tun".to_string(),
        wpmulti::config::TunnelPortOverride {
            socks5_port: Some(19999),
            http_port: None,
        },
    );

    let entry = TunnelEntry::new(
        "special_tun",
        load_tunnel_config_from_str("special_tun", &make_valid_wg_conf()).unwrap(),
        LifecycleMode::Lazy,
    );

    let assigned = config
        .per_tunnel
        .overrides
        .get("special_tun")
        .and_then(|o| o.socks5_port)
        .unwrap_or(10000);
    entry.set_assigned_port(assigned);

    assert_eq!(*entry.assigned_port.read(), Some(19999));
}

#[tokio::test]
async fn test_f9_listener_supervisor_starts_dedicated_listeners() {
    let port = allocate_ephemeral_port();
    let mut config = MainConfig::default();
    config.per_tunnel.enabled = true;
    config.per_tunnel.base_socks5_port = Some(port);
    config.per_tunnel.base_http_port = None;
    config.shared_listeners.clear();

    let tunnel = load_tunnel_config_from_str("ded-01", &make_valid_wg_conf()).unwrap();
    let registry = Arc::new(TunnelRegistry::new());
    registry.register(TunnelEntry::new("ded-01", tunnel, LifecycleMode::Lazy)).unwrap();

    let lifecycle = LifecycleController::new(Arc::clone(&registry), Duration::from_secs(60), Duration::from_secs(1));
    let supervisor = ListenerSupervisor::new();

    let started = supervisor
        .start_all(&config, &registry, &lifecycle)
        .await
        .expect("Failed to start dedicated listeners");

    assert_eq!(started.len(), 1);
    assert_eq!(started[0].tunnel_id, Some("ded-01".to_string()));
    assert_eq!(started[0].address.port(), port);

    supervisor.stop().await;
}

#[tokio::test]
async fn test_f9_dedicated_router_targets_assigned_tunnel() {
    let registry = Arc::new(TunnelRegistry::new());
    let t = load_tunnel_config_from_str("fixed_tun", &make_valid_wg_conf()).unwrap();
    registry.register(TunnelEntry::new("fixed_tun", t, LifecycleMode::Lazy)).unwrap();

    let lifecycle = LifecycleController::new(Arc::clone(&registry), Duration::from_secs(60), Duration::from_secs(1));
    let router = DedicatedTunnelRouter::new("fixed_tun".to_string(), lifecycle, None);

    let _selected = router
        .select_tunnel(&TunnelSelector::DefaultPool)
        .await
        .expect("Dedicated router should select fixed tunnel");
    assert!(registry.get("fixed_tun").unwrap().is_active());
}

// =============================================================================
// Feature 10: Shared Port Multi-Tenant Routing (F10)
// =============================================================================

#[tokio::test]
async fn test_f10_shared_port_route_by_tunnel_id() {
    let registry = Arc::new(TunnelRegistry::new());
    for id in ["wgcf-001", "wgcf-002", "wgcf-003"] {
        let t = load_tunnel_config_from_str(id, &make_valid_wg_conf()).unwrap();
        registry.register(TunnelEntry::new(id, t, LifecycleMode::Lazy)).unwrap();
    }
    let lifecycle = LifecycleController::new(Arc::clone(&registry), Duration::from_secs(60), Duration::from_secs(1));

    let router = MultiTenantRouter::new(
        lifecycle,
        Arc::clone(&registry),
        PoolStrategy::RoundRobin,
        false,
    );

    let _sel = router
        .select_tunnel(&TunnelSelector::ById("wgcf-002".to_string()))
        .await
        .unwrap();
    assert!(registry.get("wgcf-002").unwrap().is_active());
}

#[tokio::test]
async fn test_f10_shared_port_route_by_round_robin_keyword() {
    let registry = Arc::new(TunnelRegistry::new());
    for id in ["tun-a", "tun-b"] {
        let t = load_tunnel_config_from_str(id, &make_valid_wg_conf()).unwrap();
        registry.register(TunnelEntry::new(id, t, LifecycleMode::Lazy)).unwrap();
    }
    let lifecycle = LifecycleController::new(Arc::clone(&registry), Duration::from_secs(60), Duration::from_secs(1));

    let router = MultiTenantRouter::new(
        lifecycle,
        Arc::clone(&registry),
        PoolStrategy::RoundRobin,
        true,
    );

    let _sel1 = router.select_tunnel(&TunnelSelector::ByKeyword(PoolKeyword::RoundRobin)).await.unwrap();
    let _sel2 = router.select_tunnel(&TunnelSelector::ByKeyword(PoolKeyword::RoundRobin)).await.unwrap();
    assert_eq!(registry.active_count(), 2);
}

#[tokio::test]
async fn test_f10_shared_port_route_by_random_keyword() {
    let registry = Arc::new(TunnelRegistry::new());
    for id in ["rand-1", "rand-2", "rand-3"] {
        let t = load_tunnel_config_from_str(id, &make_valid_wg_conf()).unwrap();
        registry.register(TunnelEntry::new(id, t, LifecycleMode::Lazy)).unwrap();
    }
    let lifecycle = LifecycleController::new(Arc::clone(&registry), Duration::from_secs(60), Duration::from_secs(1));

    let router = MultiTenantRouter::new(
        lifecycle,
        Arc::clone(&registry),
        PoolStrategy::Random,
        true,
    );

    let _sel = router.select_tunnel(&TunnelSelector::ByKeyword(PoolKeyword::Random)).await.unwrap();
    assert!(registry.active_count() >= 1);
}

#[tokio::test]
async fn test_f10_shared_port_anonymous_default_pool() {
    let registry = Arc::new(TunnelRegistry::new());
    let t = load_tunnel_config_from_str("anon-tun", &make_valid_wg_conf()).unwrap();
    registry.register(TunnelEntry::new("anon-tun", t, LifecycleMode::Lazy)).unwrap();
    let lifecycle = LifecycleController::new(Arc::clone(&registry), Duration::from_secs(60), Duration::from_secs(1));

    let router = MultiTenantRouter::new(
        lifecycle,
        Arc::clone(&registry),
        PoolStrategy::RoundRobin,
        true,
    );

    let _sel = router.select_tunnel(&TunnelSelector::DefaultPool).await.unwrap();
    assert!(registry.get("anon-tun").unwrap().is_active());
}

#[tokio::test]
async fn test_f10_shared_port_global_password_validation() {
    let registry = Arc::new(TunnelRegistry::new());
    let t = load_tunnel_config_from_str("tun-glob", &make_valid_wg_conf()).unwrap();
    registry.register(TunnelEntry::new("tun-glob", t, LifecycleMode::Lazy)).unwrap();
    let lifecycle = LifecycleController::new(Arc::clone(&registry), Duration::from_secs(60), Duration::from_secs(1));

    let router = MultiTenantRouter::new(
        lifecycle,
        Arc::clone(&registry),
        PoolStrategy::RoundRobin,
        false,
    ).with_auth(AuthMode::Global, Some("supersecret".to_string()));

    let authed = router.authenticate(Some(("tun-glob", "supersecret"))).unwrap();
    assert_eq!(authed, TunnelSelector::ById("tun-glob".to_string()));

    let failed = router.authenticate(Some(("tun-glob", "wrongpass")));
    assert!(failed.is_err());
}

// =============================================================================
// Feature 11: Lazy Lifecycle (Suspend/Resume/Idle) (F11)
// =============================================================================

#[test]
fn test_f11_lazy_initial_state_is_dormant() {
    let t = load_tunnel_config_from_str("lazy-01", &make_valid_wg_conf()).unwrap();
    let entry = TunnelEntry::new("lazy-01", t, LifecycleMode::Lazy);
    assert_eq!(*entry.state.read(), TunnelState::Dormant);
    assert_eq!(entry.stats.active_conns.load(Ordering::SeqCst), 0);
    assert!(entry.active.read().is_none());
}

#[tokio::test]
async fn test_f11_lazy_wake_on_demand_activates() {
    let registry = Arc::new(TunnelRegistry::new());
    let t = load_tunnel_config_from_str("lazy-wake", &make_valid_wg_conf()).unwrap();
    registry.register(TunnelEntry::new("lazy-wake", t, LifecycleMode::Lazy)).unwrap();

    let lifecycle = LifecycleController::new(Arc::clone(&registry), Duration::from_secs(10), Duration::from_millis(50));
    assert_eq!(registry.active_count(), 0);

    let (active, _guard) = lifecycle.get_or_activate("lazy-wake").await.unwrap();
    assert_eq!(active.id, "lazy-wake");
    assert_eq!(registry.active_count(), 1);
    assert_eq!(*registry.get("lazy-wake").unwrap().state.read(), TunnelState::Active);
}

#[test]
fn test_f11_lazy_connection_guard_tracking() {
    let stats = Arc::new(wpmulti::core::TunnelStats::default());
    assert_eq!(stats.active_conns.load(Ordering::SeqCst), 0);
    assert_eq!(stats.total_conns.load(Ordering::SeqCst), 0);

    let guard1 = TunnelConnGuard::new("tun-guard", Arc::clone(&stats));
    assert_eq!(stats.active_conns.load(Ordering::SeqCst), 1);
    assert_eq!(stats.total_conns.load(Ordering::SeqCst), 1);

    let guard2 = TunnelConnGuard::new("tun-guard", Arc::clone(&stats));
    assert_eq!(stats.active_conns.load(Ordering::SeqCst), 2);

    drop(guard1);
    assert_eq!(stats.active_conns.load(Ordering::SeqCst), 1);

    drop(guard2);
    assert_eq!(stats.active_conns.load(Ordering::SeqCst), 0);
    assert!(stats.last_active_at.load(Ordering::SeqCst) > 0);
}

#[tokio::test]
async fn test_f11_lazy_manual_suspend_transition() {
    let registry = Arc::new(TunnelRegistry::new());
    let t = load_tunnel_config_from_str("lazy-susp", &make_valid_wg_conf()).unwrap();
    registry.register(TunnelEntry::new("lazy-susp", t, LifecycleMode::Lazy)).unwrap();

    let lifecycle = LifecycleController::new(Arc::clone(&registry), Duration::from_secs(10), Duration::from_millis(50));
    let (_active, guard) = lifecycle.get_or_activate("lazy-susp").await.unwrap();
    assert_eq!(registry.active_count(), 1);

    drop(guard);
    lifecycle.suspend_tunnel("lazy-susp").await.unwrap();
    assert_eq!(registry.active_count(), 0);
    assert_eq!(*registry.get("lazy-susp").unwrap().state.read(), TunnelState::Suspended);
}

#[tokio::test]
async fn test_f11_eager_tunnel_starts_active() {
    let mut config = MainConfig::default();
    config.lifecycle.mode = LifecycleMode::Lazy;
    config.lifecycle.eager_tunnels = vec!["eager-boot".to_string()];
    config.per_tunnel.enabled = false;
    config.shared_listeners.clear();

    let tunnels = vec![
        load_tunnel_config_from_str("lazy-stay", &make_valid_wg_conf()).unwrap(),
        load_tunnel_config_from_str("eager-boot", &make_valid_wg_conf()).unwrap(),
    ];

    let manager = TunnelManager::new(config, tunnels).unwrap();
    manager.start().await.unwrap();

    assert_eq!(manager.active_tunnel_count(), 1);
    let eager_entry = manager.registry().get("eager-boot").unwrap();
    assert_eq!(*eager_entry.state.read(), TunnelState::Active);

    let lazy_entry = manager.registry().get("lazy-stay").unwrap();
    assert_eq!(*lazy_entry.state.read(), TunnelState::Dormant);

    manager.stop().await.unwrap();
}

// =============================================================================
// Feature 12: HTTP Admin API & Metrics (F12)
// =============================================================================

#[tokio::test]
async fn test_f12_admin_get_health_status() {
    let port = allocate_ephemeral_port();
    let mut config = MainConfig::default();
    config.per_tunnel.enabled = false;
    config.shared_listeners.clear();
    config.admin.enabled = true;
    config.admin.bind = format!("127.0.0.1:{}", port).parse().unwrap();

    let manager = Arc::new(TunnelManager::new(config.clone(), Vec::new()).unwrap());
    let server = wpmulti::api::AdminServer::new(config.admin.bind, Arc::clone(&manager), None);
    let bound = server.start().await.unwrap();

    let client = AdminTestClient::new(bound, None);
    let health = client.get_health().await.unwrap();
    assert_eq!(health["status"], "ok");

    server.stop().await;
}

#[tokio::test]
async fn test_f12_admin_get_status_overview() {
    let port = allocate_ephemeral_port();
    let mut config = MainConfig::default();
    config.per_tunnel.enabled = false;
    config.shared_listeners.clear();
    config.admin.enabled = true;
    config.admin.bind = format!("127.0.0.1:{}", port).parse().unwrap();

    let tunnels = vec![
        load_tunnel_config_from_str("t-1", &make_valid_wg_conf()).unwrap(),
        load_tunnel_config_from_str("t-2", &make_valid_wg_conf()).unwrap(),
    ];
    let manager = Arc::new(TunnelManager::new(config.clone(), tunnels).unwrap());
    let server = wpmulti::api::AdminServer::new(config.admin.bind, Arc::clone(&manager), None);
    let bound = server.start().await.unwrap();

    let client = AdminTestClient::new(bound, None);
    let status = client.get_status().await.unwrap();
    assert_eq!(status["total_tunnels"], 2);
    assert_eq!(status["active_tunnels"], 0);

    server.stop().await;
}

#[tokio::test]
async fn test_f12_admin_get_tunnels_list() {
    let port = allocate_ephemeral_port();
    let mut config = MainConfig::default();
    config.per_tunnel.enabled = false;
    config.shared_listeners.clear();
    config.admin.enabled = true;
    config.admin.bind = format!("127.0.0.1:{}", port).parse().unwrap();

    let tunnels = vec![load_tunnel_config_from_str("listed-tun", &make_valid_wg_conf()).unwrap()];
    let manager = Arc::new(TunnelManager::new(config.clone(), tunnels).unwrap());
    let server = wpmulti::api::AdminServer::new(config.admin.bind, Arc::clone(&manager), None);
    let bound = server.start().await.unwrap();

    let client = AdminTestClient::new(bound, None);
    let list = client.list_tunnels(None).await.unwrap();
    let arr = list.as_array().unwrap();
    assert_eq!(arr.len(), 1);
    assert_eq!(arr[0]["id"], "listed-tun");
    assert_eq!(arr[0]["state"].as_str().unwrap().to_lowercase(), "dormant");

    server.stop().await;
}

#[tokio::test]
async fn test_f12_admin_activate_and_suspend_endpoints() {
    let port = allocate_ephemeral_port();
    let mut config = MainConfig::default();
    config.per_tunnel.enabled = false;
    config.shared_listeners.clear();
    config.admin.enabled = true;
    config.admin.bind = format!("127.0.0.1:{}", port).parse().unwrap();

    let tunnels = vec![load_tunnel_config_from_str("ctrl-tun", &make_valid_wg_conf()).unwrap()];
    let manager = Arc::new(TunnelManager::new(config.clone(), tunnels).unwrap());
    let server = wpmulti::api::AdminServer::new(config.admin.bind, Arc::clone(&manager), None);
    let bound = server.start().await.unwrap();

    let client = AdminTestClient::new(bound, None);

    // Activate
    let act = client.activate_tunnel("ctrl-tun").await.unwrap();
    assert_eq!(act["status"], "activated");
    assert_eq!(manager.active_tunnel_count(), 1);

    // Deactivate / suspend
    let susp = client.deactivate_tunnel("ctrl-tun").await.unwrap();
    assert_eq!(susp["status"], "suspended");
    assert_eq!(manager.active_tunnel_count(), 0);

    server.stop().await;
}

#[tokio::test]
async fn test_f12_admin_prometheus_metrics_exposition() {
    let port = allocate_ephemeral_port();
    let mut config = MainConfig::default();
    config.per_tunnel.enabled = false;
    config.shared_listeners.clear();
    config.admin.enabled = true;
    config.admin.bind = format!("127.0.0.1:{}", port).parse().unwrap();

    let t = load_tunnel_config_from_str("metric-tun", &make_valid_wg_conf()).unwrap();
    let manager = Arc::new(TunnelManager::new(config.clone(), vec![t]).unwrap());
    let entry = manager.registry().get("metric-tun").unwrap();
    entry.stats.rx_bytes.store(2048, Ordering::SeqCst);
    entry.stats.tx_bytes.store(1024, Ordering::SeqCst);

    let server = wpmulti::api::AdminServer::new(config.admin.bind, Arc::clone(&manager), None);
    let bound = server.start().await.unwrap();

    let client = AdminTestClient::new(bound, None);
    let rx_val = client
        .get_metric_value("wpmulti_tunnel_rx_bytes", &[("tunnel_id", "metric-tun")])
        .await
        .unwrap();
    assert_eq!(rx_val, 2048.0);

    let tx_val = client
        .get_metric_value("wpmulti_tunnel_tx_bytes", &[("tunnel_id", "metric-tun")])
        .await
        .unwrap();
    assert_eq!(tx_val, 1024.0);

    server.stop().await;
}

// =============================================================================
// Feature 13: Ratatui TUI Monitor (F13)
// =============================================================================

#[test]
fn test_f13_tui_app_state_initialization() {
    let dummy_source = TuiDataSource::Remote {
        admin_url: "http://127.0.0.1:9090".to_string(),
        auth_token: None,
    };
    let app = TuiApp::new(dummy_source, TuiSortField::Id);
    assert_eq!(app.selected_index, 0);
    assert_eq!(app.sort_field, TuiSortField::Id);
    assert!(!app.is_searching);
    assert!(app.search_query.is_empty());
}

#[test]
fn test_f13_tui_app_navigation_key_events() {
    let dummy_source = TuiDataSource::Remote {
        admin_url: "http://127.0.0.1:9090".to_string(),
        auth_token: None,
    };
    let mut app = TuiApp::new(dummy_source, TuiSortField::Id);

    let list = vec![
        wpmulti::core::TunnelSummary {
            id: "wgcf-001".to_string(),
            state: TunnelState::Dormant,
            mode: LifecycleMode::Lazy,
            active_conns: 0,
            total_conns: 0,
            rx_bytes: 0,
            tx_bytes: 0,
            last_handshake: None,
            last_active_at: None,
            assigned_port: Some(10000),
            endpoint: Some("127.0.0.1:51820".to_string()),
            health: wpmulti::core::HealthStatus::Healthy,
            consecutive_failures: 0,
            cooldown_remaining_secs: 0,
        },
        wpmulti::core::TunnelSummary {
            id: "wgcf-002".to_string(),
            state: TunnelState::Active,
            mode: LifecycleMode::Lazy,
            active_conns: 1,
            total_conns: 1,
            rx_bytes: 100,
            tx_bytes: 200,
            last_handshake: None,
            last_active_at: None,
            assigned_port: Some(10001),
            endpoint: Some("127.0.0.1:51820".to_string()),
            health: wpmulti::core::HealthStatus::Healthy,
            consecutive_failures: 0,
            cooldown_remaining_secs: 0,
        },
    ];
    app.set_tunnels(list);

    assert_eq!(app.selected_index, 0);
    app.select_next();
    assert_eq!(app.selected_index, 1);
    app.select_prev();
    assert_eq!(app.selected_index, 0);
}

#[test]
fn test_f13_tui_app_search_filtering() {
    let dummy_source = TuiDataSource::Remote {
        admin_url: "http://127.0.0.1:9090".to_string(),
        auth_token: None,
    };
    let mut app = TuiApp::new(dummy_source, TuiSortField::Id);

    let list = vec![
        wpmulti::core::TunnelSummary {
            id: "prod-us-east".to_string(),
            state: TunnelState::Active,
            mode: LifecycleMode::Lazy,
            active_conns: 0,
            total_conns: 0,
            rx_bytes: 0,
            tx_bytes: 0,
            last_handshake: None,
            last_active_at: None,
            assigned_port: None,
            endpoint: None,
            health: wpmulti::core::HealthStatus::Healthy,
            consecutive_failures: 0,
            cooldown_remaining_secs: 0,
        },
        wpmulti::core::TunnelSummary {
            id: "staging-eu-west".to_string(),
            state: TunnelState::Dormant,
            mode: LifecycleMode::Lazy,
            active_conns: 0,
            total_conns: 0,
            rx_bytes: 0,
            tx_bytes: 0,
            last_handshake: None,
            last_active_at: None,
            assigned_port: None,
            endpoint: None,
            health: wpmulti::core::HealthStatus::Healthy,
            consecutive_failures: 0,
            cooldown_remaining_secs: 0,
        },
    ];
    app.set_tunnels(list);
    assert_eq!(app.filtered_indices.len(), 2);

    app.search_query = "eu-west".to_string();
    app.apply_filter_and_sort();
    assert_eq!(app.filtered_indices.len(), 1);
    assert_eq!(app.tunnels[app.filtered_indices[0]].id, "staging-eu-west");
}

#[test]
fn test_f13_tui_app_column_sorting() {
    let dummy_source = TuiDataSource::Remote {
        admin_url: "http://127.0.0.1:9090".to_string(),
        auth_token: None,
    };
    let mut app = TuiApp::new(dummy_source, TuiSortField::Id);

    let list = vec![
        wpmulti::core::TunnelSummary {
            id: "tun-z".to_string(),
            state: TunnelState::Active,
            mode: LifecycleMode::Lazy,
            active_conns: 5,
            total_conns: 5,
            rx_bytes: 10,
            tx_bytes: 10,
            last_handshake: None,
            last_active_at: None,
            assigned_port: None,
            endpoint: None,
            health: wpmulti::core::HealthStatus::Healthy,
            consecutive_failures: 0,
            cooldown_remaining_secs: 0,
        },
        wpmulti::core::TunnelSummary {
            id: "tun-a".to_string(),
            state: TunnelState::Dormant,
            mode: LifecycleMode::Lazy,
            active_conns: 1,
            total_conns: 1,
            rx_bytes: 50,
            tx_bytes: 50,
            last_handshake: None,
            last_active_at: None,
            assigned_port: None,
            endpoint: None,
            health: wpmulti::core::HealthStatus::Healthy,
            consecutive_failures: 0,
            cooldown_remaining_secs: 0,
        },
    ];
    app.set_tunnels(list);

    // Sort by Conns
    app.sort_field = TuiSortField::Conns;
    app.apply_filter_and_sort();
    assert_eq!(app.sort_field, TuiSortField::Conns);
    assert_eq!(app.tunnels[app.filtered_indices[0]].id, "tun-a"); // ascending: 1 < 5

    // Toggle sort order (descending)
    app.sort_ascending = false;
    app.apply_filter_and_sort();
    assert_eq!(app.tunnels[app.filtered_indices[0]].id, "tun-z"); // descending: 5 > 1
}

#[test]
fn test_f13_tui_render_dashboard_output() {
    let dummy_source = TuiDataSource::Remote {
        admin_url: "http://127.0.0.1:9090".to_string(),
        auth_token: None,
    };
    let mut app = TuiApp::new(dummy_source, TuiSortField::Id);
    let list = vec![wpmulti::core::TunnelSummary {
        id: "render-01".to_string(),
        state: TunnelState::Active,
        mode: LifecycleMode::Lazy,
        active_conns: 2,
        total_conns: 4,
        rx_bytes: 1048576,
        tx_bytes: 524288,
        last_handshake: None,
        last_active_at: None,
        assigned_port: Some(10080),
        endpoint: Some("127.0.0.1:51820".to_string()),
        health: wpmulti::core::HealthStatus::Healthy,
        consecutive_failures: 0,
        cooldown_remaining_secs: 0,
    }];
    app.set_tunnels(list);

    let rendered = render_dashboard(&mut app, 80, 24);
    assert!(rendered.contains("wpmulti"));
    assert!(rendered.contains("render-01"));
    assert!(rendered.contains("Active"));
    assert_eq!(format_bytes(1048576), "1.00 MB");
}
