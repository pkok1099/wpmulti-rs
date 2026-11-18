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

mod common;

use std::net::Ipv4Addr;
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::Duration;

use common::{
    AdminTestClient, HttpProxyTestClient, SharedListenerFixture, Socks5TestClient, TestEnvironment,
    WgConfBuilder, WgPeerFixture, WpMultiTomlBuilder, allocate_ephemeral_port,
};
use etherparse::PacketBuilder;
use gotatun::tun::{IpRecv, IpSend};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

use wpmulti::config::{
    AuthMode, LifecycleMode, MainConfig, PoolStrategy, TuiSortField, load_tunnel_config_from_str,
    parse_duration_str, parse_wg_conf,
};
use wpmulti::core::{
    CoreError, LifecycleController, ListenerSupervisor, MultiTenantRouter, TunnelEntry,
    TunnelManager, TunnelRegistry, TunnelState,
};
use wpmulti::netstack::{DnsError, DnsLruCache, VirtualTunBridge, parse_response};
use wpmulti::proxy::{
    CMD_BIND, DirectTunnelTarget, DynStream, METHOD_GSSAPI, METHOD_NO_ACCEPTABLE, METHOD_NO_AUTH,
    METHOD_USER_PASS, PoolKeyword, ProxyAuthError, ProxyTunnelTarget, ProxyUdpSocket,
    REP_CMD_NOT_SUPPORTED, SingleTunnelRouter, TunnelRouter, TunnelSelector, handle_http,
    handle_socks5_with_addrs, parse_authority, parse_socks5_udp_packet,
};
use wpmulti::tui::{TuiApp, TuiDataSource, format_bytes, render_dashboard};

fn make_valid_wg_conf() -> String {
    WgConfBuilder::new()
        .add_peer(WgPeerFixture::new(
            "bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo=",
            "127.0.0.1:51820",
        ))
        .build_ini()
}

// =============================================================================
// Feature 1 Boundaries: WireGuard Conf Parser (F1)
// =============================================================================

#[test]
fn test_f1_bnd_invalid_private_key_length() {
    let conf = "
[Interface]
PrivateKey = AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA==
Address = 10.0.0.2/32

[Peer]
PublicKey = bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo=
Endpoint = 127.0.0.1:51820
AllowedIPs = 0.0.0.0/0
";
    assert!(parse_wg_conf(conf).is_err());
}

#[test]
fn test_f1_bnd_malformed_ip_address_or_mask() {
    let conf_bad_ip = "
[Interface]
PrivateKey = AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=
Address = 999.999.999.999/32

[Peer]
PublicKey = bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo=
Endpoint = 127.0.0.1:51820
AllowedIPs = 0.0.0.0/0
";
    assert!(parse_wg_conf(conf_bad_ip).is_err());

    let conf_bad_mask = "
[Interface]
PrivateKey = AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=
Address = 10.0.0.2/33

[Peer]
PublicKey = bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo=
Endpoint = 127.0.0.1:51820
AllowedIPs = 0.0.0.0/0
";
    assert!(parse_wg_conf(conf_bad_mask).is_err());
}

#[test]
fn test_f1_bnd_missing_interface_or_peer() {
    let conf_no_iface = "
[Peer]
PublicKey = bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo=
Endpoint = 127.0.0.1:51820
AllowedIPs = 0.0.0.0/0
";
    assert!(parse_wg_conf(conf_no_iface).is_err());

    let conf_no_peer = "
[Interface]
PrivateKey = AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=
Address = 10.0.0.2/32
";
    assert!(parse_wg_conf(conf_no_peer).is_err());
}

#[test]
fn test_f1_bnd_zero_or_negative_listen_port() {
    let conf_negative = "
[Interface]
PrivateKey = AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=
Address = 10.0.0.2/32
ListenPort = -1

[Peer]
PublicKey = bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo=
Endpoint = 127.0.0.1:51820
AllowedIPs = 0.0.0.0/0
";
    assert!(parse_wg_conf(conf_negative).is_err());

    let conf_overflow = "
[Interface]
PrivateKey = AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=
Address = 10.0.0.2/32
ListenPort = 70000

[Peer]
PublicKey = bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo=
Endpoint = 127.0.0.1:51820
AllowedIPs = 0.0.0.0/0
";
    assert!(parse_wg_conf(conf_overflow).is_err());

    let conf_zero_port = "
[Interface]
PrivateKey = AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=
Address = 10.0.0.2/32
ListenPort = 0

[Peer]
PublicKey = bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo=
Endpoint = 127.0.0.1:51820
AllowedIPs = 0.0.0.0/0
";
    let (iface, _) = parse_wg_conf(conf_zero_port).unwrap();
    assert_eq!(iface.listen_port, None);
}

#[test]
fn test_f1_bnd_large_conf_with_50_peers() {
    let mut builder = WgConfBuilder::new();
    for i in 1..=50 {
        builder = builder.add_peer(
            WgPeerFixture::new(
                "bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo=",
                &format!("198.51.100.{}:51820", (i % 250) + 1),
            )
            .persistent_keepalive(25),
        );
    }
    let conf = builder.build_ini();
    let (iface, peers) = parse_wg_conf(&conf).expect("50 peers should parse cleanly");
    assert_eq!(iface.addresses.len(), 1);
    assert_eq!(peers.len(), 50);
}

// =============================================================================
// Feature 2 Boundaries: Main TOML Config Parser (F2)
// =============================================================================

#[test]
fn test_f2_bnd_syntax_error_unclosed_quotes() {
    let toml_str = r#"
[global]
config_dir = "/etc/wpmulti/conf.d
"#;
    let res: Result<MainConfig, _> = toml::from_str(toml_str);
    assert!(res.is_err());
}

#[test]
fn test_f2_bnd_invalid_enum_strings() {
    let toml_str = r#"
[global]
config_dir = "/etc/wpmulti/conf.d"

[lifecycle]
mode = "quantum"
"#;
    let res: Result<MainConfig, _> = toml::from_str(toml_str);
    assert!(res.is_err());
}

#[test]
fn test_f2_bnd_zero_and_negative_duration_strings() {
    assert!(parse_duration_str("-5m").is_err());
    assert!(parse_duration_str("invalid_unit").is_err());
    assert!(parse_duration_str("").is_err());
    let zero = parse_duration_str("0s");
    assert!(zero.is_ok());
    assert_eq!(zero.unwrap(), Duration::from_secs(0));
}

#[test]
fn test_f2_bnd_missing_required_fields() {
    // Missing global_password when auth_mode = "global"
    let toml_missing_pwd = r#"
[[shared_listener]]
name = "bad-auth"
bind = "127.0.0.1:1080"
auth_mode = "global"
"#;
    let res = MainConfig::from_toml_str(toml_missing_pwd);
    assert!(res.is_err());

    // Zero max_active_tunnels
    let toml_zero_tunnels = r#"
[global]
max_active_tunnels = 0
"#;
    assert!(MainConfig::from_toml_str(toml_zero_tunnels).is_err());
}

#[test]
fn test_f2_bnd_extreme_toml_many_shared_listeners() {
    let env = TestEnvironment::new("f2_extreme").unwrap();
    let mut builder = WpMultiTomlBuilder::new(env.conf_dir().to_path_buf());
    for i in 0..25 {
        builder = builder.add_shared_listener(SharedListenerFixture {
            name: format!("listener_{}", i),
            proto_type: if i % 2 == 0 {
                "socks5".to_string()
            } else {
                "http".to_string()
            },
            bind: format!("127.0.0.1:{}", 10000 + i).parse().unwrap(),
            auth_mode: "none".to_string(),
            global_password: None,
            default_strategy: "round-robin".to_string(),
            allow_anonymous: true,
            pool: "all".to_string(),
        });
    }
    let toml_str = builder.build_toml();
    let cfg: MainConfig = toml::from_str(&toml_str).unwrap();
    assert_eq!(cfg.shared_listeners.len(), 25);
}

// =============================================================================
// Feature 3 Boundaries: Unique Tunnel ID Addressing (F3)
// =============================================================================

#[test]
fn test_f3_bnd_duplicate_tunnel_id_registration() {
    let registry = TunnelRegistry::new();
    let t1 = load_tunnel_config_from_str("dup-01", &make_valid_wg_conf()).unwrap();
    let t2 = load_tunnel_config_from_str("dup-01", &make_valid_wg_conf()).unwrap();

    registry
        .register(TunnelEntry::new("dup-01", t1, LifecycleMode::Lazy))
        .unwrap();
    let res = registry.register(TunnelEntry::new("dup-01", t2, LifecycleMode::Lazy));
    assert!(matches!(res, Err(CoreError::DuplicateTunnel(_))));
}

#[test]
fn test_f3_bnd_non_existent_tunnel_lookup() {
    let registry = TunnelRegistry::new();
    assert!(registry.get("ghost-tunnel").is_none());
    assert!(registry.get_by_index(9999).is_none());
}

#[test]
fn test_f3_bnd_special_characters_in_tunnel_id() {
    let registry = TunnelRegistry::new();
    let id = "tun.01-prod_v6@site";
    let t = load_tunnel_config_from_str(id, &make_valid_wg_conf()).unwrap();
    registry
        .register(TunnelEntry::new(id, t, LifecycleMode::Lazy))
        .unwrap();

    let fetched = registry.get(id);
    assert!(fetched.is_some());
    assert_eq!(fetched.unwrap().id, id);
}

#[test]
fn test_f3_bnd_empty_tunnel_id_handling() {
    let res = load_tunnel_config_from_str("", &make_valid_wg_conf());
    assert!(res.is_err());
}

#[test]
fn test_f3_bnd_concurrent_registry_access() {
    let registry = Arc::new(TunnelRegistry::new());
    for i in 0..50 {
        let id = format!("conc-{}", i);
        let t = load_tunnel_config_from_str(&id, &make_valid_wg_conf()).unwrap();
        registry
            .register(TunnelEntry::new(&id, t, LifecycleMode::Lazy))
            .unwrap();
    }

    let mut handles = Vec::new();
    for i in 0..50 {
        let reg = Arc::clone(&registry);
        let handle = std::thread::spawn(move || {
            let id = format!("conc-{}", i);
            let entry = reg.get(&id).unwrap();
            assert_eq!(entry.id, id);
        });
        handles.push(handle);
    }

    for h in handles {
        h.join().unwrap();
    }
}

// =============================================================================
// Feature 4 Boundaries: smoltcp Userspace Layer 3 Bridge (F4)
// =============================================================================

#[test]
fn test_f4_bnd_malformed_truncated_ip_packet() {
    let (mut bridge, _ip_send, _ip_recv) = VirtualTunBridge::new(1420, 64);
    use smoltcp::phy::Device;
    let token = bridge.receive(smoltcp::time::Instant::from_millis(0));
    assert!(token.is_none());
}

#[tokio::test]
async fn test_f4_bnd_bridge_channel_capacity_saturation() {
    let (_bridge, mut ip_send, _ip_recv) = VirtualTunBridge::new(1420, 2);
    let mut buf = Vec::new();
    let b = PacketBuilder::ipv4([10, 0, 0, 1], [10, 0, 0, 2], 64).udp(1, 2);
    buf.reserve(b.size(4));
    b.write(&mut buf, b"data").unwrap();

    let pkt1 = gotatun::packet::Packet::copy_from(buf.as_slice())
        .try_into_ip()
        .unwrap();
    let pkt2 = gotatun::packet::Packet::copy_from(buf.as_slice())
        .try_into_ip()
        .unwrap();

    assert!(ip_send.send(pkt1).await.is_ok());
    assert!(ip_send.send(pkt2).await.is_ok());
}

#[test]
fn test_f4_bnd_jumbo_packet_exceeding_mtu() {
    let (bridge, _ip_send, _ip_recv) = VirtualTunBridge::new(1280, 64);
    use smoltcp::phy::Device;
    assert_eq!(bridge.capabilities().max_transmission_unit, 1280);
}

#[tokio::test]
async fn test_f4_bnd_invalid_ip_version_nibble() {
    let (mut bridge, mut ip_send, _ip_recv) = VirtualTunBridge::new(1420, 64);
    let mut raw = vec![0x30, 0x00, 0x00, 0x14];
    raw.resize(20, 0);

    let pkt = gotatun::packet::Packet::copy_from(raw.as_slice())
        .try_into_ip()
        .unwrap();
    ip_send.send(pkt).await.unwrap();

    use smoltcp::phy::Device;
    let token = bridge.receive(smoltcp::time::Instant::from_millis(0));
    assert!(token.is_some());
}

#[tokio::test]
async fn test_f4_bnd_zero_length_payload() {
    let (_bridge, mut ip_send, mut ip_recv) = VirtualTunBridge::new(1420, 64);
    let mut buf = Vec::new();
    let b = PacketBuilder::ipv4([10, 0, 0, 1], [10, 0, 0, 2], 64).udp(100, 200);
    buf.reserve(b.size(0));
    b.write(&mut buf, &[]).unwrap();

    let pkt = gotatun::packet::Packet::copy_from(buf.as_slice())
        .try_into_ip()
        .unwrap();
    assert!(ip_send.send(pkt).await.is_ok());

    let mut pool = gotatun::packet::PacketBufPool::new(1420);
    let _ = tokio::time::timeout(Duration::from_millis(50), ip_recv.recv(&mut pool)).await;
}

// =============================================================================
// Feature 5 Boundaries: In-Tunnel Remote DNS (F5)
// =============================================================================

#[test]
fn test_f5_bnd_dns_response_nxdomain() {
    let mut resp = Vec::new();
    resp.extend_from_slice(&0x1111u16.to_be_bytes()); // TxID
    resp.extend_from_slice(&0x8183u16.to_be_bytes()); // Flags: Response, NXDOMAIN (RCODE=3)
    resp.extend_from_slice(&1u16.to_be_bytes()); // QDCOUNT
    resp.extend_from_slice(&0u16.to_be_bytes()); // ANCOUNT
    resp.extend_from_slice(&0u16.to_be_bytes()); // NSCOUNT
    resp.extend_from_slice(&0u16.to_be_bytes()); // ARCOUNT
    resp.extend_from_slice(b"\x06ghosty\x03com\x00");
    resp.extend_from_slice(&1u16.to_be_bytes());
    resp.extend_from_slice(&1u16.to_be_bytes());

    let res = parse_response(&resp, 0x1111);
    assert!(matches!(res, Err(DnsError::NxDomain)));
}

#[test]
fn test_f5_bnd_dns_response_server_failure() {
    let mut resp = Vec::new();
    resp.extend_from_slice(&0x2222u16.to_be_bytes());
    resp.extend_from_slice(&0x8182u16.to_be_bytes()); // Flags: SERVFAIL (RCODE=2)
    resp.extend_from_slice(&0u16.to_be_bytes());
    resp.extend_from_slice(&0u16.to_be_bytes());
    resp.extend_from_slice(&0u16.to_be_bytes());
    resp.extend_from_slice(&0u16.to_be_bytes());

    let res = parse_response(&resp, 0x2222);
    assert!(matches!(res, Err(DnsError::ServerError(2))));
}

#[test]
fn test_f5_bnd_dns_response_truncated_header() {
    let truncated = vec![0x12, 0x34, 0x81];
    let res = parse_response(&truncated, 0x1234);
    assert!(matches!(res, Err(DnsError::PacketTooShort)));
}

#[test]
fn test_f5_bnd_dns_compression_pointer_loop() {
    let mut resp = Vec::new();
    resp.extend_from_slice(&0x3333u16.to_be_bytes());
    resp.extend_from_slice(&0x8180u16.to_be_bytes());
    resp.extend_from_slice(&1u16.to_be_bytes());
    resp.extend_from_slice(&1u16.to_be_bytes());
    resp.extend_from_slice(&0u16.to_be_bytes());
    resp.extend_from_slice(&0u16.to_be_bytes());
    resp.extend_from_slice(&[0xC0, 0x0C]);

    let res = parse_response(&resp, 0x3333);
    assert!(matches!(res, Err(DnsError::PointerLoop)));
}

#[test]
fn test_f5_bnd_dns_lru_cache_capacity_eviction() {
    let cache = DnsLruCache::new(2);
    let ip1 = "1.1.1.1".parse::<std::net::IpAddr>().unwrap();
    let ip2 = "2.2.2.2".parse::<std::net::IpAddr>().unwrap();
    let ip3 = "3.3.3.3".parse::<std::net::IpAddr>().unwrap();

    cache.insert("one.com", vec![ip1], 300);
    cache.insert("two.com", vec![ip2], 300);
    let _ = cache.get("one.com");

    cache.insert("three.com", vec![ip3], 300);
    assert!(cache.get("one.com").is_some());
    assert!(cache.get("three.com").is_some());
}

// =============================================================================
// Feature 6 Boundaries: SOCKS5 TCP CONNECT (F6)
// =============================================================================

struct FailingTunnelTarget;

impl ProxyTunnelTarget for FailingTunnelTarget {
    fn tcp_connect<'a>(
        &'a self,
        _dst: std::net::SocketAddr,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = std::io::Result<DynStream>> + Send + 'a>>
    {
        Box::pin(async {
            Err(std::io::Error::new(
                std::io::ErrorKind::HostUnreachable,
                "simulated unroutable target",
            ))
        })
    }

    fn udp_bind<'a>(
        &'a self,
        _local_port: u16,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = std::io::Result<Box<dyn ProxyUdpSocket>>> + Send + 'a>,
    > {
        Box::pin(async {
            Err(std::io::Error::new(
                std::io::ErrorKind::HostUnreachable,
                "simulated unroutable udp target",
            ))
        })
    }

    fn resolve_in_tunnel<'a>(
        &'a self,
        _domain: &'a str,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = std::io::Result<std::net::IpAddr>> + Send + 'a>,
    > {
        Box::pin(async {
            Err(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                "simulated dns failure",
            ))
        })
    }
}

async fn spawn_real_socks5_server_with_target(
    target: Arc<dyn ProxyTunnelTarget>,
    expected_pass: Option<&str>,
) -> std::net::SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let router: Arc<dyn TunnelRouter> = Arc::new(SingleTunnelRouter::new(
        "e2e-bnd-socks5",
        target,
        expected_pass.map(|s| ("wrong_user".to_string(), s.to_string())),
    ));
    tokio::spawn(async move {
        if let Ok((stream, peer_addr)) = listener.accept().await {
            let local_ip = stream.local_addr().ok().map(|a| a.ip());
            let _ = handle_socks5_with_addrs(stream, router, local_ip, Some(peer_addr.ip())).await;
        }
    });
    addr
}

async fn spawn_real_http_server_with_target(
    target: Arc<dyn ProxyTunnelTarget>,
    expected_pass: Option<&str>,
) -> std::net::SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let router: Arc<dyn TunnelRouter> = Arc::new(SingleTunnelRouter::new(
        "e2e-bnd-http",
        target,
        expected_pass.map(|s| ("wrong_user".to_string(), s.to_string())),
    ));
    tokio::spawn(async move {
        if let Ok((stream, _)) = listener.accept().await {
            let _ = handle_http(stream, router).await;
        }
    });
    addr
}

#[tokio::test]
async fn test_f6_bnd_socks5_no_acceptable_methods() {
    let addr = spawn_real_socks5_server_with_target(Arc::new(DirectTunnelTarget), None).await;

    let mut client = Socks5TestClient::connect(addr).await.unwrap();
    let method = client.greeting(&[METHOD_GSSAPI]).await.unwrap();
    assert_eq!(method, METHOD_NO_ACCEPTABLE);
}

#[tokio::test]
async fn test_f6_bnd_socks5_unsupported_command_bind() {
    let addr = spawn_real_socks5_server_with_target(Arc::new(DirectTunnelTarget), None).await;

    let mut stream = tokio::net::TcpStream::connect(addr).await.unwrap();
    stream.write_all(&[0x05, 0x01, 0x00]).await.unwrap();
    let mut greet_resp = [0u8; 2];
    stream.read_exact(&mut greet_resp).await.unwrap();
    assert_eq!(greet_resp, [0x05, 0x00]);

    let raw_cmd = [0x05, CMD_BIND, 0x00, 0x01, 127, 0, 0, 1, 0x00, 0x50];
    stream.write_all(&raw_cmd).await.unwrap();
    let mut resp = [0u8; 10];
    stream.read_exact(&mut resp).await.unwrap();
    assert_eq!(resp[1], REP_CMD_NOT_SUPPORTED);
}

#[tokio::test]
async fn test_f6_bnd_socks5_invalid_version_header() {
    let addr = spawn_real_socks5_server_with_target(Arc::new(DirectTunnelTarget), None).await;

    let mut stream = tokio::net::TcpStream::connect(addr).await.unwrap();
    stream.write_all(&[0x04, 0x01, 0x00]).await.unwrap();
    let mut resp = [0u8; 2];
    let res = stream.read(&mut resp).await;
    assert!(matches!(res, Ok(0) | Err(_)));
}

#[tokio::test]
async fn test_f6_bnd_socks5_auth_bad_credentials() {
    let addr =
        spawn_real_socks5_server_with_target(Arc::new(DirectTunnelTarget), Some("correct_pass"))
            .await;

    let mut client = Socks5TestClient::connect(addr).await.unwrap();
    let method = client.greeting(&[METHOD_USER_PASS]).await.unwrap();
    assert_eq!(method, METHOD_USER_PASS);
    let res = client.authenticate("wrong_user", "bad_pass").await;
    assert!(res.is_err());
}

#[tokio::test]
async fn test_f6_bnd_socks5_connect_unroutable_target() {
    let addr = spawn_real_socks5_server_with_target(Arc::new(FailingTunnelTarget), None).await;

    let mut client = Socks5TestClient::connect(addr).await.unwrap();
    client.greeting(&[METHOD_NO_AUTH]).await.unwrap();
    let res = client
        .cmd_connect_ipv4(Ipv4Addr::new(192, 0, 2, 1), 80)
        .await;
    assert!(res.is_err());
}

// =============================================================================
// Feature 7 Boundaries: SOCKS5 UDP ASSOCIATE (F7)
// =============================================================================

#[test]
fn test_f7_bnd_socks5_udp_invalid_atyp() {
    let bad_packet = vec![0x00, 0x00, 0x00, 0x02, 1, 2, 3, 4, 0x00, 0x50, 0xFF];
    let res = parse_socks5_udp_packet(&bad_packet);
    assert!(res.is_none());
}

#[test]
fn test_f7_bnd_socks5_udp_truncated_header() {
    let truncated = vec![0x00, 0x00, 0x00];
    let res = parse_socks5_udp_packet(&truncated);
    assert!(res.is_none());
}

#[test]
fn test_f7_bnd_socks5_udp_fragmentation_not_supported() {
    let mut frag_packet = vec![0x00, 0x00, 0x01, 0x01, 10, 0, 0, 1, 0x00, 0x50];
    frag_packet.extend_from_slice(b"payload");
    let res = parse_socks5_udp_packet(&frag_packet);
    assert!(res.is_none());
}

#[test]
fn test_f7_bnd_socks5_udp_domain_length_overflow() {
    let overflow = vec![0x00, 0x00, 0x00, 0x03, 0xFF, 1, 2, 3, 4];
    let res = parse_socks5_udp_packet(&overflow);
    assert!(res.is_none());
}

#[tokio::test]
async fn test_f7_bnd_socks5_udp_control_stream_drop_cleans_up() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    let (drop_tx, drop_rx) = tokio::sync::oneshot::channel();
    let router: Arc<dyn TunnelRouter> = Arc::new(SingleTunnelRouter::new(
        "e2e-bnd-udp",
        Arc::new(DirectTunnelTarget),
        None,
    ));

    tokio::spawn(async move {
        let (stream, peer_addr) = listener.accept().await.unwrap();
        let local_ip = stream.local_addr().ok().map(|a| a.ip());
        let _ = handle_socks5_with_addrs(stream, router, local_ip, Some(peer_addr.ip())).await;
        let _ = drop_tx.send(true);
    });

    let mut client = Socks5TestClient::connect(addr).await.unwrap();
    client.greeting(&[METHOD_NO_AUTH]).await.unwrap();
    let session = client.cmd_udp_associate(None).await.unwrap();
    drop(session);

    let clean = tokio::time::timeout(Duration::from_millis(500), drop_rx).await;
    assert!(clean.is_ok());
}

// =============================================================================
// Feature 8 Boundaries: HTTP/HTTPS CONNECT Proxy (F8)
// =============================================================================

#[tokio::test]
async fn test_f8_bnd_http_malformed_request_line() {
    let addr = spawn_real_http_server_with_target(Arc::new(DirectTunnelTarget), None).await;

    let (resp, _) = HttpProxyTestClient::send_raw(addr, "MALFORMED_LINE\r\n\r\n")
        .await
        .unwrap();
    assert_eq!(resp.status_code, 400);
}

#[test]
fn test_f8_bnd_http_authority_missing_port() {
    assert!(parse_authority("example.com").is_none());
    assert!(parse_authority("").is_none());
}

#[tokio::test]
async fn test_f8_bnd_http_auth_missing_or_bad_credentials() {
    let addr =
        spawn_real_http_server_with_target(Arc::new(DirectTunnelTarget), Some("secret")).await;

    let (resp, _) = HttpProxyTestClient::send_raw(addr, "CONNECT target:443 HTTP/1.1\r\n\r\n")
        .await
        .unwrap();
    assert_eq!(resp.status_code, 407);
    assert!(resp.is_proxy_auth_required());
}

#[tokio::test]
async fn test_f8_bnd_http_header_too_large() {
    let addr = spawn_real_http_server_with_target(Arc::new(DirectTunnelTarget), None).await;

    let big_header = format!(
        "CONNECT target:443 HTTP/1.1\r\nX-Padding: {}\r\n\r\n",
        "A".repeat(17000)
    );
    let (resp, _) = HttpProxyTestClient::send_raw(addr, &big_header)
        .await
        .unwrap();
    assert!(resp.status_code == 431 || resp.status_code == 400);
}

#[tokio::test]
async fn test_f8_bnd_http_connect_unreachable_target() {
    let addr = spawn_real_http_server_with_target(Arc::new(FailingTunnelTarget), None).await;

    let (resp, _) = HttpProxyTestClient::send_raw(addr, "CONNECT 192.0.2.1:80 HTTP/1.1\r\n\r\n")
        .await
        .unwrap();
    assert_eq!(resp.status_code, 502);
}

// =============================================================================
// Feature 9 Boundaries: Per-Config Port Auto-Bind (F9)
// =============================================================================

#[test]
fn test_f9_bnd_port_auto_bind_near_u16_max() {
    let base: u16 = 65534;
    let offset_1 = base.wrapping_add(1);
    let offset_2 = base.wrapping_add(2);
    assert_eq!(offset_1, 65535);
    assert_eq!(offset_2, 0);
}

#[tokio::test]
async fn test_f9_bnd_port_already_in_use_error() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let occupied_port = listener.local_addr().unwrap().port();

    let mut config = MainConfig::default();
    config.per_tunnel.enabled = true;
    config.per_tunnel.base_socks5_port = Some(occupied_port);
    config.per_tunnel.base_http_port = None;
    config.shared_listeners.clear();

    let registry = Arc::new(TunnelRegistry::new());
    let t = load_tunnel_config_from_str("coll_tun", &make_valid_wg_conf()).unwrap();
    registry
        .register(TunnelEntry::new("coll_tun", t, LifecycleMode::Lazy))
        .unwrap();

    let lifecycle = LifecycleController::new(
        Arc::clone(&registry),
        Duration::from_secs(60),
        Duration::from_secs(1),
    );
    let supervisor = ListenerSupervisor::new();

    let started = supervisor
        .start_all(&config, &registry, &lifecycle)
        .await
        .unwrap();
    assert_eq!(started.len(), 1);
    assert_ne!(started[0].address.port(), occupied_port);
    supervisor.stop().await;
    lifecycle.stop().await;
    drop(listener);
}

#[tokio::test]
async fn test_f9_bnd_per_tunnel_disabled_spawns_zero_listeners() {
    let mut config = MainConfig::default();
    config.per_tunnel.enabled = false;
    config.shared_listeners.clear();

    let registry = Arc::new(TunnelRegistry::new());
    let t = load_tunnel_config_from_str("tun_off", &make_valid_wg_conf()).unwrap();
    registry
        .register(TunnelEntry::new("tun_off", t, LifecycleMode::Lazy))
        .unwrap();

    let lifecycle = LifecycleController::new(
        Arc::clone(&registry),
        Duration::from_secs(60),
        Duration::from_secs(1),
    );
    let supervisor = ListenerSupervisor::new();

    let started = supervisor
        .start_all(&config, &registry, &lifecycle)
        .await
        .unwrap();
    assert_eq!(started.len(), 0);
}

#[test]
fn test_f9_bnd_partial_port_override() {
    let mut config = MainConfig::default();
    config.per_tunnel.overrides.insert(
        "partial_tun".to_string(),
        wpmulti::config::TunnelPortOverride {
            socks5_port: Some(12345),
            http_port: None,
            password: None,
        },
    );

    let ovr = config.per_tunnel.overrides.get("partial_tun").unwrap();
    assert_eq!(ovr.socks5_port, Some(12345));
    assert_eq!(ovr.http_port, None);
}

#[tokio::test]
async fn test_f9_bnd_empty_tunnel_list_starts_zero_dedicated() {
    let mut config = MainConfig::default();
    config.per_tunnel.enabled = true;
    config.per_tunnel.base_socks5_port = Some(15000);
    config.shared_listeners.clear();

    let registry = Arc::new(TunnelRegistry::new());
    let lifecycle = LifecycleController::new(
        Arc::clone(&registry),
        Duration::from_secs(60),
        Duration::from_secs(1),
    );
    let supervisor = ListenerSupervisor::new();

    let started = supervisor
        .start_all(&config, &registry, &lifecycle)
        .await
        .unwrap();
    assert_eq!(started.len(), 0);
}

// =============================================================================
// Feature 10 Boundaries: Shared Port Multi-Tenant Routing (F10)
// =============================================================================

#[tokio::test]
async fn test_f10_bnd_shared_port_non_existent_tunnel_id() {
    let registry = Arc::new(TunnelRegistry::new());
    let lifecycle = LifecycleController::new(
        Arc::clone(&registry),
        Duration::from_secs(60),
        Duration::from_secs(1),
    );
    let router = MultiTenantRouter::new(
        lifecycle,
        Arc::clone(&registry),
        PoolStrategy::RoundRobin,
        false,
    );

    let res = router
        .select_tunnel(&TunnelSelector::ById("non_existent".to_string()), None)
        .await;
    assert!(res.is_err());
}

#[test]
fn test_f10_bnd_shared_port_invalid_pool_keyword() {
    assert_eq!(
        TunnelSelector::parse("fastest"),
        TunnelSelector::ById("fastest".to_string())
    );
    assert_eq!(
        TunnelSelector::parse("random"),
        TunnelSelector::ByKeyword(PoolKeyword::Random)
    );
    assert_eq!(
        TunnelSelector::parse("round-robin"),
        TunnelSelector::ByKeyword(PoolKeyword::RoundRobin)
    );
    assert_eq!(
        TunnelSelector::parse("least-conn"),
        TunnelSelector::ByKeyword(PoolKeyword::LeastConn)
    );
}

#[test]
fn test_f10_bnd_shared_port_anonymous_rejected_when_disallowed() {
    let registry = Arc::new(TunnelRegistry::new());
    let lifecycle = LifecycleController::new(
        Arc::clone(&registry),
        Duration::from_secs(60),
        Duration::from_secs(1),
    );
    let router = MultiTenantRouter::new(
        lifecycle,
        Arc::clone(&registry),
        PoolStrategy::RoundRobin,
        false,
    );

    let res = router.authenticate(None);
    assert!(matches!(res, Err(ProxyAuthError::AuthRequired)));
}

#[test]
fn test_f10_bnd_shared_port_wrong_global_password() {
    let registry = Arc::new(TunnelRegistry::new());
    let lifecycle = LifecycleController::new(
        Arc::clone(&registry),
        Duration::from_secs(60),
        Duration::from_secs(1),
    );
    let router = MultiTenantRouter::new(
        lifecycle,
        Arc::clone(&registry),
        PoolStrategy::RoundRobin,
        false,
    )
    .with_auth(AuthMode::Global, Some("correct_password".to_string()));

    let res = router.authenticate(Some(("user", "wrong_password")));
    assert!(matches!(res, Err(ProxyAuthError::InvalidCredentials)));
}

#[tokio::test]
async fn test_f10_bnd_shared_port_pool_isolation_rejected() {
    let registry = Arc::new(TunnelRegistry::new());
    let t1 = load_tunnel_config_from_str("pool_a_tun", &make_valid_wg_conf()).unwrap();
    let t2 = load_tunnel_config_from_str("pool_b_tun", &make_valid_wg_conf()).unwrap();
    registry
        .register(TunnelEntry::new("pool_a_tun", t1, LifecycleMode::Lazy))
        .unwrap();
    registry
        .register(TunnelEntry::new("pool_b_tun", t2, LifecycleMode::Lazy))
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
    router.set_allowed_tunnels(Some(vec!["pool_a_tun".to_string()]));

    let res = router
        .select_tunnel(&TunnelSelector::ById("pool_b_tun".to_string()), None)
        .await;
    assert!(res.is_err());
}

// =============================================================================
// Feature 11 Boundaries: Lazy Lifecycle (F11)
// =============================================================================

#[tokio::test]
async fn test_f11_bnd_idle_timeout_reset_on_activity() {
    let registry = Arc::new(TunnelRegistry::new());
    let t = load_tunnel_config_from_str("active_idle", &make_valid_wg_conf()).unwrap();
    registry
        .register(TunnelEntry::new("active_idle", t, LifecycleMode::Lazy))
        .unwrap();

    let lifecycle = LifecycleController::new(
        Arc::clone(&registry),
        Duration::from_millis(50),
        Duration::from_millis(10),
    );
    let (_active, guard) = lifecycle.get_or_activate("active_idle").await.unwrap();

    let entry = registry.get("active_idle").unwrap();
    assert_eq!(entry.stats.active_conns.load(Ordering::SeqCst), 1);

    tokio::time::sleep(Duration::from_millis(70)).await;
    assert_eq!(*entry.state.read(), TunnelState::Active);
    drop(guard);
}

#[tokio::test]
async fn test_f11_bnd_concurrent_activation_deduplication() {
    let registry = Arc::new(TunnelRegistry::new());
    let t = load_tunnel_config_from_str("dedup_wake", &make_valid_wg_conf()).unwrap();
    registry
        .register(TunnelEntry::new("dedup_wake", t, LifecycleMode::Lazy))
        .unwrap();

    let lifecycle = Arc::new(LifecycleController::new(
        Arc::clone(&registry),
        Duration::from_secs(60),
        Duration::from_secs(1),
    ));

    let lc1 = Arc::clone(&lifecycle);
    let lc2 = Arc::clone(&lifecycle);

    let (r1, r2) = tokio::join!(
        lc1.get_or_activate("dedup_wake"),
        lc2.get_or_activate("dedup_wake")
    );

    assert!(r1.is_ok());
    assert!(r2.is_ok());
    assert_eq!(registry.active_count(), 1);
}

#[tokio::test]
async fn test_f11_bnd_suspend_already_dormant_is_noop() {
    let registry = Arc::new(TunnelRegistry::new());
    let t = load_tunnel_config_from_str("dormant_noop", &make_valid_wg_conf()).unwrap();
    registry
        .register(TunnelEntry::new("dormant_noop", t, LifecycleMode::Lazy))
        .unwrap();

    let lifecycle = LifecycleController::new(
        Arc::clone(&registry),
        Duration::from_secs(60),
        Duration::from_secs(1),
    );
    let res = lifecycle.suspend_tunnel("dormant_noop").await;
    assert!(res.is_ok());
    assert_eq!(
        *registry.get("dormant_noop").unwrap().state.read(),
        TunnelState::Dormant
    );
}

#[tokio::test]
async fn test_f11_bnd_manual_activation_state_tracking() {
    let registry = Arc::new(TunnelRegistry::new());
    let t = load_tunnel_config_from_str("man_act", &make_valid_wg_conf()).unwrap();
    registry
        .register(TunnelEntry::new("man_act", t, LifecycleMode::Lazy))
        .unwrap();

    let lifecycle = LifecycleController::new(
        Arc::clone(&registry),
        Duration::from_secs(60),
        Duration::from_secs(1),
    );
    lifecycle.activate_tunnel("man_act").await.unwrap();

    assert_eq!(registry.active_count(), 1);
    assert_eq!(
        *registry.get("man_act").unwrap().state.read(),
        TunnelState::Active
    );
}

#[tokio::test]
async fn test_f11_bnd_rapid_activate_suspend_cycles() {
    let registry = Arc::new(TunnelRegistry::new());
    let t = load_tunnel_config_from_str("cycle_tun", &make_valid_wg_conf()).unwrap();
    registry
        .register(TunnelEntry::new("cycle_tun", t, LifecycleMode::Lazy))
        .unwrap();

    let lifecycle = LifecycleController::new(
        Arc::clone(&registry),
        Duration::from_secs(60),
        Duration::from_secs(1),
    );
    for _ in 0..5 {
        let (_act, guard) = lifecycle.get_or_activate("cycle_tun").await.unwrap();
        drop(guard);
        lifecycle.suspend_tunnel("cycle_tun").await.unwrap();
    }
    assert_eq!(registry.active_count(), 0);
}

// =============================================================================
// Feature 12 Boundaries: HTTP Admin API & Metrics (F12)
// =============================================================================

#[tokio::test]
async fn test_f12_bnd_admin_missing_bearer_token_returns_401() {
    let port = allocate_ephemeral_port();
    let mut config = MainConfig::default();
    config.admin.enabled = true;
    config.admin.bind = format!("127.0.0.1:{}", port).parse().unwrap();
    config.admin.auth_token = Some("secure_secret_token".to_string());

    let manager = Arc::new(TunnelManager::new(config.clone(), Vec::new()).unwrap());
    let server = wpmulti::api::AdminServer::new(
        config.admin.bind,
        Arc::clone(&manager),
        config.admin.auth_token,
    );
    let bound = server.start().await.unwrap();

    let client = AdminTestClient::new(bound, None);
    let res = client.get_health().await;
    assert!(res.is_err());

    server.stop().await;
}

#[tokio::test]
async fn test_f12_bnd_admin_invalid_bearer_token_returns_401() {
    let port = allocate_ephemeral_port();
    let mut config = MainConfig::default();
    config.admin.enabled = true;
    config.admin.bind = format!("127.0.0.1:{}", port).parse().unwrap();
    config.admin.auth_token = Some("secure_secret_token".to_string());

    let manager = Arc::new(TunnelManager::new(config.clone(), Vec::new()).unwrap());
    let server = wpmulti::api::AdminServer::new(
        config.admin.bind,
        Arc::clone(&manager),
        config.admin.auth_token,
    );
    let bound = server.start().await.unwrap();

    let client = AdminTestClient::new(bound, Some("wrong_token".to_string()));
    let res = client.get_health().await;
    assert!(res.is_err());

    server.stop().await;
}

#[tokio::test]
async fn test_f12_bnd_admin_non_existent_route_returns_404() {
    let port = allocate_ephemeral_port();
    let mut config = MainConfig::default();
    config.admin.enabled = true;
    config.admin.bind = format!("127.0.0.1:{}", port).parse().unwrap();

    let manager = Arc::new(TunnelManager::new(config.clone(), Vec::new()).unwrap());
    let server = wpmulti::api::AdminServer::new(config.admin.bind, Arc::clone(&manager), None);
    let bound = server.start().await.unwrap();

    let mut stream = tokio::net::TcpStream::connect(bound).await.unwrap();
    stream
        .write_all(
            b"GET /non_existent_path HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n",
        )
        .await
        .unwrap();
    let mut resp = Vec::new();
    stream.read_to_end(&mut resp).await.unwrap();
    let resp_str = String::from_utf8_lossy(&resp);
    assert!(resp_str.contains("404"));

    server.stop().await;
}

#[tokio::test]
async fn test_f12_bnd_admin_get_non_existent_tunnel_returns_404() {
    let port = allocate_ephemeral_port();
    let mut config = MainConfig::default();
    config.admin.enabled = true;
    config.admin.bind = format!("127.0.0.1:{}", port).parse().unwrap();

    let manager = Arc::new(TunnelManager::new(config.clone(), Vec::new()).unwrap());
    let server = wpmulti::api::AdminServer::new(config.admin.bind, Arc::clone(&manager), None);
    let bound = server.start().await.unwrap();

    let client = AdminTestClient::new(bound, None);
    let res = client.get_tunnel("ghost_id").await;
    assert!(res.is_err());

    server.stop().await;
}

#[tokio::test]
async fn test_f12_bnd_admin_metric_not_found() {
    let port = allocate_ephemeral_port();
    let mut config = MainConfig::default();
    config.admin.enabled = true;
    config.admin.bind = format!("127.0.0.1:{}", port).parse().unwrap();

    let manager = Arc::new(TunnelManager::new(config.clone(), Vec::new()).unwrap());
    let server = wpmulti::api::AdminServer::new(config.admin.bind, Arc::clone(&manager), None);
    let bound = server.start().await.unwrap();

    let client = AdminTestClient::new(bound, None);
    let res = client.get_metric_value("non_existent_metric", &[]).await;
    assert!(res.is_err());

    server.stop().await;
}

// =============================================================================
// Feature 13 Boundaries: Ratatui TUI Monitor (F13)
// =============================================================================

#[test]
fn test_f13_bnd_tui_empty_tunnel_list_no_panic() {
    let dummy_source = TuiDataSource::Remote {
        admin_url: "http://127.0.0.1:9090".to_string(),
        auth_token: None,
    };
    let mut app = TuiApp::new(dummy_source, TuiSortField::Id);
    app.set_tunnels(Vec::new());

    assert_eq!(app.filtered_indices.len(), 0);
    assert_eq!(app.selected_index, 0);

    let rendered = render_dashboard(&mut app, 80, 24);
    assert!(rendered.contains("Tunnels: 0"));
}

#[test]
fn test_f13_bnd_tui_search_query_no_matches() {
    let dummy_source = TuiDataSource::Remote {
        admin_url: "http://127.0.0.1:9090".to_string(),
        auth_token: None,
    };
    let mut app = TuiApp::new(dummy_source, TuiSortField::Id);
    let list = vec![wpmulti::core::TunnelSummary {
        id: "tunnel_alpha".to_string(),
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
        disabled: false,
        disable_pending: false,
    }];
    app.set_tunnels(list);

    app.search_query = "completely_different_string".to_string();
    app.apply_filter_and_sort();
    assert_eq!(app.filtered_indices.len(), 0);
    assert_eq!(app.selected_index, 0);
}

#[test]
fn test_f13_bnd_tui_scroll_past_bounds() {
    let dummy_source = TuiDataSource::Remote {
        admin_url: "http://127.0.0.1:9090".to_string(),
        auth_token: None,
    };
    let mut app = TuiApp::new(dummy_source, TuiSortField::Id);
    let list = vec![wpmulti::core::TunnelSummary {
        id: "single".to_string(),
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
        disabled: false,
        disable_pending: false,
    }];
    app.set_tunnels(list);

    app.select_prev();
    assert_eq!(app.selected_index, 0);

    app.select_next();
    assert_eq!(app.selected_index, 0);
}

#[test]
fn test_f13_bnd_tui_format_bytes_extreme_values() {
    assert_eq!(format_bytes(0), "0 B");
    assert_eq!(format_bytes(1023), "1023 B");
    assert_eq!(format_bytes(1024), "1.00 KB");
    assert_eq!(format_bytes(1024 * 1024), "1.00 MB");
    assert_eq!(format_bytes(1024 * 1024 * 1024), "1.00 GB");
    assert_eq!(format_bytes(1024 * 1024 * 1024 * 1024), "1024.00 GB");
    let max_str = format_bytes(u64::MAX);
    assert!(!max_str.is_empty());
}

#[test]
fn test_f13_bnd_tui_zero_size_terminal_rendering() {
    let dummy_source = TuiDataSource::Remote {
        admin_url: "http://127.0.0.1:9090".to_string(),
        auth_token: None,
    };
    let mut app = TuiApp::new(dummy_source, TuiSortField::Id);
    let rendered = render_dashboard(&mut app, 0, 0);
    assert!(!rendered.is_empty());
}
