//! Milestone 2 comprehensive unit test suite for virtual networking stack.

use etherparse::PacketBuilder;
use gotatun::tun::IpSend;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use x25519_dalek::StaticSecret;

use crate::config::WgInterfaceConfig;
use crate::netstack::bridge::{
    BridgeIpRecv, DEFAULT_CHANNEL_CAPACITY, DEFAULT_MTU, VirtualTunBridge,
};
use crate::netstack::dns::{
    DnsError, DnsLruCache, QueryType, build_query, build_response, parse_response,
};
use crate::netstack::stack::{StackDnsConfig, VirtualNetworkStack};

fn make_test_config(v4: &str, v6: Option<&str>) -> WgInterfaceConfig {
    let mut addrs = vec![v4.parse().unwrap()];
    if let Some(v6_str) = v6 {
        addrs.push(v6_str.parse().unwrap());
    }
    WgInterfaceConfig {
        private_key: StaticSecret::from([1u8; 32]),
        addresses: addrs,
        dns: vec!["1.1.1.1".parse().unwrap()],
        listen_port: None,
        mtu: DEFAULT_MTU,
    }
}

// =========================================================================
// 1. DNS Packet Encoding & Decoding Tests
// =========================================================================

#[test]
fn test_dns_query_encoding_a() {
    let query = build_query("example.com", QueryType::A, 0x1234).unwrap();
    // ID: 0x12, 0x34
    assert_eq!(&query[0..2], &[0x12, 0x34]);
    // Flags: 0x01, 0x00 (RD = 1)
    assert_eq!(&query[2..4], &[0x01, 0x00]);
    // QDCOUNT: 1
    assert_eq!(&query[4..6], &[0x00, 0x01]);
    // QNAME: \x07example\x03com\x00
    let expected_qname = b"\x07example\x03com\x00";
    assert_eq!(&query[12..12 + expected_qname.len()], expected_qname);
    // QTYPE = 1 (A), QCLASS = 1 (IN)
    let rest = &query[12 + expected_qname.len()..];
    assert_eq!(rest, &[0x00, 0x01, 0x00, 0x01]);
}

#[test]
fn test_dns_query_encoding_aaaa() {
    let query = build_query("ipv6.google.com", QueryType::AAAA, 0xabcd).unwrap();
    assert_eq!(&query[0..2], &[0xab, 0xcd]);
    // Last 4 bytes: QTYPE=28 (0x00, 0x1c), QCLASS=1 (0x00, 0x01)
    let len = query.len();
    assert_eq!(&query[len - 4..], &[0x00, 0x1c, 0x00, 0x01]);
}

#[test]
fn test_dns_query_invalid_domain() {
    assert!(matches!(
        build_query("foo..bar", QueryType::A, 1),
        Err(DnsError::InvalidDomain(_))
    ));
    let long_label = "a".repeat(64);
    assert!(matches!(
        build_query(&format!("{long_label}.com"), QueryType::A, 1),
        Err(DnsError::InvalidDomain(_))
    ));
}

#[test]
fn test_dns_response_decoding_ipv4() {
    // Synthesize valid RFC 1035 response for "example.com" -> 93.184.216.34, TTL 300
    let mut resp = Vec::new();
    resp.extend_from_slice(&[0x12, 0x34]); // ID
    resp.extend_from_slice(&[0x81, 0x80]); // QR=1, RD=1, RA=1, RCODE=0
    resp.extend_from_slice(&[0x00, 0x01]); // QDCOUNT=1
    resp.extend_from_slice(&[0x00, 0x01]); // ANCOUNT=1
    resp.extend_from_slice(&[0x00, 0x00]); // NSCOUNT=0
    resp.extend_from_slice(&[0x00, 0x00]); // ARCOUNT=0
    // Question: \x07example\x03com\x00, Type 1, Class 1
    resp.extend_from_slice(b"\x07example\x03com\x00\x00\x01\x00\x01");
    // Answer: Compression pointer to question name (0xC0, 0x0C)
    resp.extend_from_slice(&[0xC0, 0x0C]);
    resp.extend_from_slice(&[0x00, 0x01]); // Type A
    resp.extend_from_slice(&[0x00, 0x01]); // Class IN
    resp.extend_from_slice(&[0x00, 0x00, 0x01, 0x2C]); // TTL = 300
    resp.extend_from_slice(&[0x00, 0x04]); // RDLENGTH = 4
    resp.extend_from_slice(&[93, 184, 216, 34]); // 93.184.216.34

    let (ips, ttl) = parse_response(&resp, 0x1234).unwrap();
    assert_eq!(ips, vec![IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34))]);
    assert_eq!(ttl, 300);
}

#[test]
fn test_dns_response_decoding_ipv6() {
    let mut resp = Vec::new();
    resp.extend_from_slice(&[0x56, 0x78]); // ID
    resp.extend_from_slice(&[0x81, 0x80]); // QR=1, RCODE=0
    resp.extend_from_slice(&[0x00, 0x01]); // QDCOUNT=1
    resp.extend_from_slice(&[0x00, 0x01]); // ANCOUNT=1
    resp.extend_from_slice(&[0x00, 0x00]);
    resp.extend_from_slice(&[0x00, 0x00]);
    resp.extend_from_slice(b"\x04test\x00\x00\x1c\x00\x01"); // QNAME "test", AAAA, IN
    resp.extend_from_slice(&[0xC0, 0x0C]); // Pointer to "test"
    resp.extend_from_slice(&[0x00, 0x1c]); // Type AAAA
    resp.extend_from_slice(&[0x00, 0x01]); // Class IN
    resp.extend_from_slice(&[0x00, 0x00, 0x0e, 0x10]); // TTL = 3600
    resp.extend_from_slice(&[0x00, 0x10]); // RDLENGTH = 16
    let v6: Ipv6Addr = "2606:2800:220:1:248:1893:25c8:1946".parse().unwrap();
    resp.extend_from_slice(&v6.octets());

    let (ips, ttl) = parse_response(&resp, 0x5678).unwrap();
    assert_eq!(ips, vec![IpAddr::V6(v6)]);
    assert_eq!(ttl, 3600);
}

#[test]
fn test_dns_response_nxdomain() {
    let mut resp = Vec::new();
    resp.extend_from_slice(&[0x12, 0x34]);
    resp.extend_from_slice(&[0x81, 0x83]); // QR=1, RCODE=3 (NXDOMAIN)
    resp.extend_from_slice(&[0x00, 0x01]);
    resp.extend_from_slice(&[0x00, 0x00]);
    resp.extend_from_slice(&[0x00, 0x00]);
    resp.extend_from_slice(&[0x00, 0x00]);
    resp.extend_from_slice(b"\x07example\x03com\x00\x00\x01\x00\x01");

    assert!(matches!(
        parse_response(&resp, 0x1234),
        Err(DnsError::NxDomain)
    ));
}

#[test]
fn test_dns_response_server_error() {
    let mut resp = Vec::new();
    resp.extend_from_slice(&[0x12, 0x34]);
    resp.extend_from_slice(&[0x81, 0x82]); // QR=1, RCODE=2 (Server Failure)
    resp.extend_from_slice(&[0x00, 0x01]);
    resp.extend_from_slice(&[0x00, 0x00]);
    resp.extend_from_slice(&[0x00, 0x00]);
    resp.extend_from_slice(&[0x00, 0x00]);
    resp.extend_from_slice(b"\x07example\x03com\x00\x00\x01\x00\x01");

    assert!(matches!(
        parse_response(&resp, 0x1234),
        Err(DnsError::ServerError(2))
    ));
}

#[test]
fn test_dns_corrupt_packet_handling() {
    let truncated = vec![0x12, 0x34, 0x81];
    assert!(matches!(
        parse_response(&truncated, 0x1234),
        Err(DnsError::PacketTooShort)
    ));

    let query = build_query("example.com", QueryType::A, 0x1111).unwrap();
    assert!(matches!(
        parse_response(&query, 0x2222),
        Err(DnsError::IdMismatch)
    ));

    assert!(matches!(
        parse_response(&query, 0x1111),
        Err(DnsError::NotAResponse)
    ));
}

#[test]
fn test_dns_compression_pointer_loop() {
    let mut loop_pkt = Vec::new();
    loop_pkt.extend_from_slice(&[
        0x12, 0x34, 0x81, 0x80, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    ]);
    loop_pkt.extend_from_slice(&[0xC0, 0x0C]); // Pointer points to itself
    assert!(matches!(
        parse_response(&loop_pkt, 0x1234),
        Err(DnsError::PointerLoop)
    ));
}

#[test]
fn test_dns_compression_pointer_out_of_bounds() {
    let mut oob_pkt = Vec::new();
    oob_pkt.extend_from_slice(&[
        0x12, 0x34, 0x81, 0x80, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    ]);
    oob_pkt.extend_from_slice(&[0xC0, 0xFF]); // Pointer points beyond buffer length
    assert!(matches!(
        parse_response(&oob_pkt, 0x1234),
        Err(DnsError::PacketTooShort)
    ));
}

// =========================================================================
// 2. TTL-Aware LRU Cache Tests
// =========================================================================

#[test]
fn test_dns_cache_hit_and_expiration() {
    let cache = DnsLruCache::new(4);
    let ip: IpAddr = "1.2.3.4".parse().unwrap();

    cache.insert("example.com", vec![ip], 60);
    assert_eq!(cache.get("example.com"), Some(vec![ip]));
    assert_eq!(cache.get("EXAMPLE.COM."), Some(vec![ip])); // Case insensitive & trailing dot
    assert_eq!(cache.get("unknown.com"), None);
}

#[test]
fn test_dns_cache_lru_eviction() {
    let cache = DnsLruCache::new(2);
    let ip1: IpAddr = "1.1.1.1".parse().unwrap();
    let ip2: IpAddr = "2.2.2.2".parse().unwrap();
    let ip3: IpAddr = "3.3.3.3".parse().unwrap();

    cache.insert("a.com", vec![ip1], 60);
    cache.insert("b.com", vec![ip2], 60);
    assert_eq!(cache.len(), 2);

    // Access a.com so b.com is least recently accessed
    assert!(cache.get("a.com").is_some());

    // Insert c.com -> must evict b.com
    cache.insert("c.com", vec![ip3], 60);
    assert_eq!(cache.len(), 2);

    assert!(cache.get("a.com").is_some());
    assert!(cache.get("c.com").is_some());
    assert!(cache.get("b.com").is_none());
}

#[test]
fn test_dns_cache_ttl_clamping() {
    let cache = DnsLruCache::new(10);
    let ip: IpAddr = "1.1.1.1".parse().unwrap();

    // Inserting with TTL = 0 should be clamped to min_ttl (60 seconds)
    cache.insert("min.com", vec![ip], 0);
    assert_eq!(cache.get("min.com"), Some(vec![ip]));

    cache.clear();
    assert_eq!(cache.len(), 0);
    assert!(cache.is_empty());
}

#[test]
fn test_dns_cache_concurrent_access_no_deadlock() {
    use std::sync::Arc;
    let cache = Arc::new(DnsLruCache::new(50));
    let mut handles = Vec::new();
    for i in 0..10 {
        let c = Arc::clone(&cache);
        handles.push(std::thread::spawn(move || {
            let ip: IpAddr = format!("10.0.0.{}", i).parse().unwrap();
            for j in 0..100 {
                let domain = format!("test-{}.com", j % 20);
                c.insert(&domain, vec![ip], 60);
                let _ = c.get(&domain);
            }
        }));
    }
    for h in handles {
        h.join().unwrap();
    }
}

// =========================================================================
// 3. VirtualTunBridge Capabilities & Data Flow Tests
// =========================================================================

#[test]
fn test_bridge_capabilities() {
    let (bridge, _ip_send, _ip_recv) = VirtualTunBridge::new(1400, 128);
    use smoltcp::phy::{Device, Medium};
    let caps = bridge.capabilities();
    assert_eq!(caps.medium, Medium::Ip);
    assert_eq!(caps.max_transmission_unit, 1400);
    assert_eq!(bridge.mtu(), 1400);
}

#[tokio::test]
async fn test_bridge_rx_zero_copy() {
    let (mut bridge, mut ip_send, _ip_recv) =
        VirtualTunBridge::new(DEFAULT_MTU, DEFAULT_CHANNEL_CAPACITY);
    let pool = gotatun::packet::PacketBufPool::<4096>::new(16);

    // Build valid 28-byte IPv4 packet
    let builder = PacketBuilder::ipv4([10, 0, 0, 1], [10, 0, 0, 2], 64).udp(1234, 5678);
    let mut raw = Vec::new();
    builder.write(&mut raw, b"PAYLOAD").unwrap();

    let mut pkt = pool.get();
    pkt.truncate(raw.len());
    pkt.copy_from_slice(&raw);
    let ip_pkt = pkt.try_into_ip().unwrap();

    ip_send.send(ip_pkt).await.unwrap();

    use smoltcp::phy::{Device, RxToken};
    let now = smoltcp::time::Instant::now();
    let (rx_token, _tx_token) = bridge.receive(now).expect("must receive packet");

    rx_token.consume(|buf| {
        assert_eq!(buf, &raw[..]);
    });
}

#[tokio::test]
async fn test_bridge_tx_pipeline() {
    let (mut bridge, _ip_send, mut ip_recv) = VirtualTunBridge::new(DEFAULT_MTU, 16);
    let mut pool = gotatun::packet::PacketBufPool::<4096>::new(16);

    let builder = PacketBuilder::ipv4([10, 2, 0, 2], [1, 1, 1, 1], 64).udp(4567, 53);
    let mut raw = Vec::new();
    builder.write(&mut raw, b"DNSQUERY").unwrap();

    use smoltcp::phy::{Device, TxToken};
    let now = smoltcp::time::Instant::now();
    let tx_token = bridge.transmit(now).expect("must get tx token");
    tx_token.consume(raw.len(), |buf| {
        buf.copy_from_slice(&raw);
    });

    use gotatun::tun::IpRecv;
    let mut packets = ip_recv.recv(&mut pool).await.unwrap();
    let pkt = packets.next().expect("packet must be received");

    use zerocopy::IntoBytes;
    assert_eq!((*pkt).as_bytes(), &raw[..]);
}

#[test]
fn test_bridge_tx_backpressure() {
    let (mut bridge, _ip_send, _ip_recv) = VirtualTunBridge::new(DEFAULT_MTU, 2);
    use smoltcp::phy::{Device, TxToken};
    let now = smoltcp::time::Instant::now();

    // Consume 2 tokens to fill channel
    let tx1 = bridge.transmit(now).expect("slot 1 available");
    tx1.consume(20, |_| {});
    let tx2 = bridge.transmit(now).expect("slot 2 available");
    tx2.consume(20, |_| {});

    // Third token should return None because channel is full
    assert!(bridge.transmit(now).is_none());
}

#[tokio::test]
async fn test_bridge_notify_liveness() {
    let (_bridge, mut ip_send, _ip_recv) = VirtualTunBridge::new(DEFAULT_MTU, 16);
    let notify = ip_send.notify_clone();
    let pool = gotatun::packet::PacketBufPool::<4096>::new(16);

    let builder = PacketBuilder::ipv4([10, 0, 0, 1], [10, 0, 0, 2], 64).udp(1111, 2222);
    let mut raw = Vec::new();
    builder.write(&mut raw, b"NOTIFY").unwrap();

    let mut pkt = pool.get();
    pkt.truncate(raw.len());
    pkt.copy_from_slice(&raw);
    let ip_pkt = pkt.try_into_ip().unwrap();

    let notified = notify.notified();
    tokio::pin!(notified);

    ip_send.send(ip_pkt).await.unwrap();
    tokio::time::timeout(Duration::from_millis(50), notified)
        .await
        .expect("notify must trigger");
}

#[tokio::test]
async fn test_bridge_malformed_ip_rejection() {
    let (mut bridge, _ip_send, mut ip_recv) = VirtualTunBridge::new(DEFAULT_MTU, 16);
    let mut pool = gotatun::packet::PacketBufPool::<4096>::new(16);

    // A packet shorter than 20 bytes is not a valid IP packet: it must be
    // dropped by `recv` instead of delivered.
    use smoltcp::phy::{Device, TxToken};
    let now = smoltcp::time::Instant::now();
    let tx_token = bridge.transmit(now).expect("must get tx token");
    tx_token.consume(3, |buf| {
        buf.copy_from_slice(&[0x45, 0x00, 0x00]);
    });

    // A valid packet sent after it must still arrive.
    let builder = PacketBuilder::ipv4([10, 2, 0, 2], [1, 1, 1, 1], 64).udp(4567, 53);
    let mut raw = Vec::new();
    builder.write(&mut raw, b"DNSQUERY").unwrap();
    let tx_token = bridge.transmit(now).expect("must get tx token");
    tx_token.consume(raw.len(), |buf| {
        buf.copy_from_slice(&raw);
    });

    use gotatun::tun::IpRecv;
    let mut packets = ip_recv.recv(&mut pool).await.unwrap();
    let pkt = packets.next().expect("valid packet must be received");
    use zerocopy::IntoBytes;
    assert_eq!((*pkt).as_bytes(), &raw[..]);
    assert!(packets.next().is_none());
}

#[tokio::test]
async fn test_bridge_tx_oversize_mtu() {
    // MTU above the 4096-byte pool buffer: the TX token must grow its buffer
    // and the full packet must still arrive intact.
    let (mut bridge, _ip_send, mut ip_recv) = VirtualTunBridge::new(9000, 16);
    let mut pool = gotatun::packet::PacketBufPool::<4096>::new(16);

    let builder = PacketBuilder::ipv4([10, 2, 0, 2], [1, 1, 1, 1], 64).udp(4567, 53);
    let mut raw = Vec::new();
    builder.write(&mut raw, &[0xab; 4960]).unwrap();
    assert!(raw.len() > 4096, "test packet must exceed the pool buffer");

    use smoltcp::phy::{Device, TxToken};
    let now = smoltcp::time::Instant::now();
    let tx_token = bridge.transmit(now).expect("must get tx token");
    tx_token.consume(raw.len(), |buf| {
        buf.copy_from_slice(&raw);
    });

    use gotatun::tun::IpRecv;
    let mut packets = ip_recv.recv(&mut pool).await.unwrap();
    let pkt = packets.next().expect("oversize packet must be received");
    use zerocopy::IntoBytes;
    assert_eq!((*pkt).as_bytes(), &raw[..]);
}

// =========================================================================
// 4. VirtualNetworkStack Addressing, Routing & Ephemeral Ports
// =========================================================================

#[tokio::test]
async fn test_stack_dual_stack_addressing() {
    let config = make_test_config("10.2.0.2/32", Some("fd00::2/128"));
    let (bridge, _ip_send, _ip_recv) = VirtualTunBridge::new(DEFAULT_MTU, 64);

    let stack = VirtualNetworkStack::new(&config, bridge).unwrap();

    assert_eq!(stack.local_v4(), Some(Ipv4Addr::new(10, 2, 0, 2)));
    assert_eq!(
        stack.local_v6(),
        Some("fd00::2".parse::<Ipv6Addr>().unwrap())
    );

    stack.close().await;
}

#[tokio::test]
async fn test_stack_ephemeral_port_cycling() {
    let config = make_test_config("10.2.0.2/32", None);
    let (bridge, _ip_send, _ip_recv) = VirtualTunBridge::new(DEFAULT_MTU, 64);
    let stack = VirtualNetworkStack::new(&config, bridge).unwrap();

    let mut prev = stack.alloc_ephemeral_port();
    assert!(prev >= 49152);

    for _ in 0..100 {
        let next = stack.alloc_ephemeral_port();
        assert!(next >= 49152);
        assert_ne!(next, prev);
        prev = next;
    }

    stack.close().await;
}

#[tokio::test]
async fn test_stack_clean_shutdown() {
    let config = make_test_config("172.16.0.2/32", None);
    let (bridge, _ip_send, _ip_recv) = VirtualTunBridge::new(DEFAULT_MTU, 64);
    let stack = VirtualNetworkStack::new(&config, bridge).unwrap();

    // Close and ensure background task terminates without hanging
    tokio::time::timeout(Duration::from_millis(500), stack.close())
        .await
        .expect("close must terminate promptly");
}

// =========================================================================
// 5. VirtualUdpSocket Send & Recv Loopback Tests
// =========================================================================

#[tokio::test]
async fn test_udp_socket_bind_and_port() {
    let config = make_test_config("10.2.0.2/32", None);
    let (bridge, _ip_send, _ip_recv) = VirtualTunBridge::new(DEFAULT_MTU, 64);
    let stack = VirtualNetworkStack::new(&config, bridge).unwrap();

    // Ephemeral port binding (0)
    let sock_ephemeral = stack.udp_bind(0).unwrap();
    assert!(sock_ephemeral.local_port() >= 49152);

    // Explicit port binding
    let sock_explicit = stack.udp_bind(5353).unwrap();
    assert_eq!(sock_explicit.local_port(), 5353);

    stack.close().await;
}

#[tokio::test]
async fn test_udp_socket_send_and_recv_loopback() {
    let config = make_test_config("10.2.0.2/32", None);
    let (bridge, mut ip_send, mut ip_recv) = VirtualTunBridge::new(DEFAULT_MTU, 64);
    let stack = VirtualNetworkStack::new(&config, bridge).unwrap();

    let udp = stack.udp_bind(12345).unwrap();
    let target = SocketAddr::from(([1, 1, 1, 1], 53));

    // 1. Send datagram from virtual socket
    udp.send_to(b"PING_DATAGRAM", target).await.unwrap();

    // 2. Receive outbound IP packet from gotatun BridgeIpRecv
    let mut pool = gotatun::packet::PacketBufPool::<4096>::new(16);
    use gotatun::tun::IpRecv;
    let mut packets = tokio::time::timeout(Duration::from_millis(500), ip_recv.recv(&mut pool))
        .await
        .expect("must recv packet from bridge")
        .expect("must succeed");

    let pkt = packets.next().expect("packet present");
    use zerocopy::IntoBytes;
    let raw_out = (*pkt).as_bytes();

    // Verify it is an IPv4 UDP packet
    let parsed = etherparse::SlicedPacket::from_ip(raw_out).unwrap();
    let Some(etherparse::TransportSlice::Udp(udp_slice)) = parsed.transport else {
        panic!("expected udp");
    };
    assert_eq!(udp_slice.payload(), b"PING_DATAGRAM");

    // 3. Inject a reply UDP packet back via BridgeIpSend
    let builder = PacketBuilder::ipv4([1, 1, 1, 1], [10, 2, 0, 2], 64).udp(53, 12345);
    let mut reply_raw = Vec::new();
    builder.write(&mut reply_raw, b"PONG_DATAGRAM").unwrap();

    let mut reply_pkt = pool.get();
    reply_pkt.truncate(reply_raw.len());
    reply_pkt.copy_from_slice(&reply_raw);
    let ip_reply = reply_pkt.try_into_ip().unwrap();

    use gotatun::tun::IpSend;
    ip_send.send(ip_reply).await.unwrap();

    // 4. VirtualUdpSocket receives the datagram
    let mut recv_buf = [0u8; 128];
    let (len, peer) =
        tokio::time::timeout(Duration::from_millis(500), udp.recv_from(&mut recv_buf))
            .await
            .expect("must recv on udp socket")
            .expect("recv succeeds");

    assert_eq!(&recv_buf[..len], b"PONG_DATAGRAM");
    assert_eq!(peer, target);

    stack.close().await;
}

// =========================================================================
// 6. In-Tunnel DNS Resolution Tests
// =========================================================================

#[tokio::test]
async fn test_in_tunnel_dns_ip_literal_fast_path() {
    let config = make_test_config("10.2.0.2/32", Some("fd00::2/128"));
    let (bridge, _ip_send, _ip_recv) = VirtualTunBridge::new(DEFAULT_MTU, 64);
    let stack = VirtualNetworkStack::new(&config, bridge).unwrap();

    // IPv4 literal fast-path
    let ip4 = stack.resolve_in_tunnel("93.184.216.34").await.unwrap();
    assert_eq!(ip4, IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34)));

    // IPv6 literal fast-path
    let ip6 = stack
        .resolve_in_tunnel("2606:4700:4700::1111")
        .await
        .unwrap();
    assert_eq!(ip6, "2606:4700:4700::1111".parse::<IpAddr>().unwrap());

    stack.close().await;
}

#[tokio::test]
async fn test_in_tunnel_dns_resolution_and_cache() {
    let config = make_test_config("10.2.0.2/32", None);
    let (bridge, mut ip_send, mut ip_recv) = VirtualTunBridge::new(DEFAULT_MTU, 64);
    let stack = VirtualNetworkStack::new(&config, bridge).unwrap();

    let mut pool = gotatun::packet::PacketBufPool::<4096>::new(16);

    // Spawn mock DNS responder task on the tunnel bridge
    let responder_task = tokio::spawn(async move {
        use gotatun::tun::{IpRecv, IpSend};
        use zerocopy::IntoBytes;

        let mut packets = ip_recv.recv(&mut pool).await.unwrap();
        let pkt = packets.next().unwrap();
        let raw = (*pkt).as_bytes();

        let parsed = etherparse::SlicedPacket::from_ip(raw).unwrap();
        let udp_hdr = match &parsed.transport {
            Some(etherparse::TransportSlice::Udp(u)) => u,
            _ => panic!("expected udp"),
        };
        let dns_query = udp_hdr.payload();
        let tx_id = u16::from_be_bytes([dns_query[0], dns_query[1]]);

        // Build mock DNS response pointing to 93.184.216.34
        let mut dns_resp = Vec::new();
        dns_resp.extend_from_slice(&tx_id.to_be_bytes());
        dns_resp.extend_from_slice(&[0x81, 0x80]); // Response
        dns_resp.extend_from_slice(&[0x00, 0x01]); // QDCOUNT=1
        dns_resp.extend_from_slice(&[0x00, 0x01]); // ANCOUNT=1
        dns_resp.extend_from_slice(&[0x00, 0x00]);
        dns_resp.extend_from_slice(&[0x00, 0x00]);
        // Echo question
        dns_resp.extend_from_slice(&dns_query[12..]);
        // Answer: compression pointer to name
        dns_resp.extend_from_slice(&[0xC0, 0x0C]);
        dns_resp.extend_from_slice(&[0x00, 0x01]); // Type A
        dns_resp.extend_from_slice(&[0x00, 0x01]); // Class IN
        dns_resp.extend_from_slice(&[0x00, 0x00, 0x00, 0x3C]); // TTL=60s
        dns_resp.extend_from_slice(&[0x00, 0x04]); // Len=4
        dns_resp.extend_from_slice(&[93, 184, 216, 34]);

        let (src_ip, dst_ip) = match parsed.net.unwrap() {
            etherparse::NetSlice::Ipv4(v4) => (v4.header().source(), v4.header().destination()),
            _ => panic!("expected ipv4"),
        };
        let udp_ports = (udp_hdr.source_port(), udp_hdr.destination_port());

        let builder = PacketBuilder::ipv4(dst_ip, src_ip, 64).udp(udp_ports.1, udp_ports.0);
        let mut reply_raw = Vec::new();
        builder.write(&mut reply_raw, &dns_resp).unwrap();

        let mut reply_pkt = pool.get();
        reply_pkt.truncate(reply_raw.len());
        reply_pkt.copy_from_slice(&reply_raw);
        let ip_reply = reply_pkt.try_into_ip().unwrap();

        ip_send.send(ip_reply).await.unwrap();
    });

    // First resolution: queries tunnel mock DNS
    let resolved = stack.resolve_in_tunnel("example.com").await.unwrap();
    assert_eq!(resolved, IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34)));

    responder_task.await.unwrap();

    // Second resolution: served directly from LRU cache without network packet!
    let cached = stack.resolve_in_tunnel("example.com").await.unwrap();
    assert_eq!(cached, IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34)));

    stack.close().await;
}

#[tokio::test]
async fn test_shared_dns_cache_across_stacks() {
    use std::sync::Arc;

    use crate::config::toml_config::DnsStrategy;

    // One daemon-wide cache shared by both stacks.
    let shared = Arc::new(DnsLruCache::new(2048));
    let dns_a = StackDnsConfig::with_shared_cache(
        SocketAddr::new(IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)), 53),
        DnsStrategy::TunnelOnly,
        Arc::clone(&shared),
    );
    let dns_b = StackDnsConfig::with_shared_cache(
        SocketAddr::new(IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)), 53),
        DnsStrategy::TunnelOnly,
        Arc::clone(&shared),
    );

    let config = make_test_config("10.2.0.2/32", None);
    let (bridge_a, mut ip_send_a, mut ip_recv_a) = VirtualTunBridge::new(DEFAULT_MTU, 64);
    let stack_a = VirtualNetworkStack::new_with_options(
        &config,
        bridge_a,
        crate::config::IpMode::DualStack,
        false,
        &dns_a,
        Duration::from_secs(15),
    )
    .unwrap();

    // Stack B has no mock DNS responder on its bridge: if the cache were
    // per-stack, resolving via B would have to query the (absent) upstream
    // and time out. A shared cache serves it from A's earlier lookup.
    let (bridge_b, _ip_send_b, _ip_recv_b) = VirtualTunBridge::new(DEFAULT_MTU, 64);
    let stack_b = VirtualNetworkStack::new_with_options(
        &config,
        bridge_b,
        crate::config::IpMode::DualStack,
        false,
        &dns_b,
        Duration::from_secs(15),
    )
    .unwrap();

    let mut pool = gotatun::packet::PacketBufPool::<4096>::new(16);

    // Spawn mock DNS responder task on stack A's bridge only.
    let responder_task = tokio::spawn(async move {
        use gotatun::tun::{IpRecv, IpSend};
        use zerocopy::IntoBytes;

        let mut packets = ip_recv_a.recv(&mut pool).await.unwrap();
        let pkt = packets.next().unwrap();
        let raw = (*pkt).as_bytes();

        let parsed = etherparse::SlicedPacket::from_ip(raw).unwrap();
        let udp_hdr = match &parsed.transport {
            Some(etherparse::TransportSlice::Udp(u)) => u,
            _ => panic!("expected udp"),
        };
        let dns_query = udp_hdr.payload();
        let tx_id = u16::from_be_bytes([dns_query[0], dns_query[1]]);

        // Build mock DNS response pointing to 93.184.216.34
        let mut dns_resp = Vec::new();
        dns_resp.extend_from_slice(&tx_id.to_be_bytes());
        dns_resp.extend_from_slice(&[0x81, 0x80]); // Response
        dns_resp.extend_from_slice(&[0x00, 0x01]); // QDCOUNT=1
        dns_resp.extend_from_slice(&[0x00, 0x01]); // ANCOUNT=1
        dns_resp.extend_from_slice(&[0x00, 0x00]);
        dns_resp.extend_from_slice(&[0x00, 0x00]);
        // Echo question
        dns_resp.extend_from_slice(&dns_query[12..]);
        // Answer: compression pointer to name
        dns_resp.extend_from_slice(&[0xC0, 0x0C]);
        dns_resp.extend_from_slice(&[0x00, 0x01]); // Type A
        dns_resp.extend_from_slice(&[0x00, 0x01]); // Class IN
        dns_resp.extend_from_slice(&[0x00, 0x00, 0x00, 0x3C]); // TTL=60s
        dns_resp.extend_from_slice(&[0x00, 0x04]); // Len=4
        dns_resp.extend_from_slice(&[93, 184, 216, 34]);

        let (src_ip, dst_ip) = match parsed.net.unwrap() {
            etherparse::NetSlice::Ipv4(v4) => (v4.header().source(), v4.header().destination()),
            _ => panic!("expected ipv4"),
        };
        let udp_ports = (udp_hdr.source_port(), udp_hdr.destination_port());

        let builder = PacketBuilder::ipv4(dst_ip, src_ip, 64).udp(udp_ports.1, udp_ports.0);
        let mut reply_raw = Vec::new();
        builder.write(&mut reply_raw, &dns_resp).unwrap();

        let mut reply_pkt = pool.get();
        reply_pkt.truncate(reply_raw.len());
        reply_pkt.copy_from_slice(&reply_raw);
        let ip_reply = reply_pkt.try_into_ip().unwrap();

        ip_send_a.send(ip_reply).await.unwrap();
    });

    // First resolution via A: queries the mock DNS, populates the shared cache.
    let resolved_a = stack_a.resolve_in_tunnel("example.com").await.unwrap();
    assert_eq!(resolved_a, IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34)));

    responder_task.await.unwrap();

    // Resolution via B: must be served from the shared cache without any
    // network packet. Bounded so a regression (per-stack cache) fails fast
    // instead of waiting out the 3s in-tunnel DNS deadline.
    let resolved_b = tokio::time::timeout(
        Duration::from_secs(2),
        stack_b.resolve_in_tunnel("example.com"),
    )
    .await
    .expect("stack B resolution timed out: shared DNS cache not used")
    .unwrap();
    assert_eq!(resolved_b, IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34)));

    stack_a.close().await;
    stack_b.close().await;
}

#[tokio::test]
async fn test_shared_dns_cache_scoped_by_upstream_servers() {
    use std::sync::Arc;

    use crate::config::toml_config::DnsStrategy;

    // Same daemon-wide cache, but the stacks resolve through different
    // configured DNS servers: an answer learned via A must not be
    // served to B (audit run-1, `dns-shared-cache-cross-tunnel-poisoning`).
    let shared = Arc::new(DnsLruCache::new(2048));
    let dns_a = StackDnsConfig::with_shared_cache(
        SocketAddr::new(IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)), 53),
        DnsStrategy::TunnelOnly,
        Arc::clone(&shared),
    );
    let dns_b = StackDnsConfig::with_shared_cache(
        SocketAddr::new(IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)), 53),
        DnsStrategy::TunnelOnly,
        Arc::clone(&shared),
    );

    let config_a = make_test_config("10.2.0.2/32", None);
    let mut config_b = make_test_config("10.3.0.2/32", None);
    config_b.dns = vec!["8.8.8.8".parse().unwrap()];
    let (bridge_a, mut ip_send_a, mut ip_recv_a) = VirtualTunBridge::new(DEFAULT_MTU, 64);
    let stack_a = VirtualNetworkStack::new_with_options(
        &config_a,
        bridge_a,
        crate::config::IpMode::DualStack,
        false,
        &dns_a,
        Duration::from_secs(15),
    )
    .unwrap();

    // Stack B has no mock DNS responder on its bridge: if the cache
    // were keyed by domain only, resolving via B would return A's
    // answer from the shared cache. Scoped keys force B to query its
    // own (absent) upstream and fail.
    let (bridge_b, _ip_send_b, _ip_recv_b) = VirtualTunBridge::new(DEFAULT_MTU, 64);
    let stack_b = VirtualNetworkStack::new_with_options(
        &config_b,
        bridge_b,
        crate::config::IpMode::DualStack,
        false,
        &dns_b,
        Duration::from_secs(15),
    )
    .unwrap();

    let mut pool = gotatun::packet::PacketBufPool::<4096>::new(16);

    // Spawn mock DNS responder task on stack A's bridge only.
    let responder_task = tokio::spawn(async move {
        use gotatun::tun::{IpRecv, IpSend};
        use zerocopy::IntoBytes;

        let mut packets = ip_recv_a.recv(&mut pool).await.unwrap();
        let pkt = packets.next().unwrap();
        let raw = (*pkt).as_bytes();

        let parsed = etherparse::SlicedPacket::from_ip(raw).unwrap();
        let udp_hdr = match &parsed.transport {
            Some(etherparse::TransportSlice::Udp(u)) => u,
            _ => panic!("expected udp"),
        };
        let dns_query = udp_hdr.payload();
        let tx_id = u16::from_be_bytes([dns_query[0], dns_query[1]]);

        // Build mock DNS response pointing to 93.184.216.34
        let mut dns_resp = Vec::new();
        dns_resp.extend_from_slice(&tx_id.to_be_bytes());
        dns_resp.extend_from_slice(&[0x81, 0x80]); // Response
        dns_resp.extend_from_slice(&[0x00, 0x01]); // QDCOUNT=1
        dns_resp.extend_from_slice(&[0x00, 0x01]); // ANCOUNT=1
        dns_resp.extend_from_slice(&[0x00, 0x00]);
        dns_resp.extend_from_slice(&[0x00, 0x00]);
        // Echo question
        dns_resp.extend_from_slice(&dns_query[12..]);
        // Answer: compression pointer to name
        dns_resp.extend_from_slice(&[0xC0, 0x0C]);
        dns_resp.extend_from_slice(&[0x00, 0x01]); // Type A
        dns_resp.extend_from_slice(&[0x00, 0x01]); // Class IN
        dns_resp.extend_from_slice(&[0x00, 0x00, 0x00, 0x3C]); // TTL=60s
        dns_resp.extend_from_slice(&[0x00, 0x04]); // Len=4
        dns_resp.extend_from_slice(&[93, 184, 216, 34]);

        let (src_ip, dst_ip) = match parsed.net.unwrap() {
            etherparse::NetSlice::Ipv4(v4) => (v4.header().source(), v4.header().destination()),
            _ => panic!("expected ipv4"),
        };
        let udp_ports = (udp_hdr.source_port(), udp_hdr.destination_port());

        let builder = PacketBuilder::ipv4(dst_ip, src_ip, 64).udp(udp_ports.1, udp_ports.0);
        let mut reply_raw = Vec::new();
        builder.write(&mut reply_raw, &dns_resp).unwrap();

        let mut reply_pkt = pool.get();
        reply_pkt.truncate(reply_raw.len());
        reply_pkt.copy_from_slice(&reply_raw);
        let ip_reply = reply_pkt.try_into_ip().unwrap();

        ip_send_a.send(ip_reply).await.unwrap();
    });

    // First resolution via A: queries the mock DNS, populates the shared cache.
    let resolved_a = stack_a.resolve_in_tunnel("example.com").await.unwrap();
    assert_eq!(resolved_a, IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34)));

    responder_task.await.unwrap();

    // Resolution via B: must NOT be served from the shared cache, so it
    // fails against its own (absent) upstream instead of returning A's
    // answer. Bounded so the failure is observed fast.
    let resolved_b = tokio::time::timeout(
        Duration::from_secs(5),
        stack_b.resolve_in_tunnel("example.com"),
    )
    .await
    .expect("stack B resolution must finish within the timeout");
    assert!(
        resolved_b.is_err(),
        "stack B must not reuse stack A's cached answer for a different upstream"
    );

    stack_a.close().await;
    stack_b.close().await;
}

#[tokio::test]
async fn test_dns_singleflight_coalesces_concurrent_lookups() {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    let config = make_test_config("10.2.0.2/32", None);
    let (bridge, mut ip_send, mut ip_recv) = VirtualTunBridge::new(DEFAULT_MTU, 64);
    let stack = Arc::new(VirtualNetworkStack::new(&config, bridge).unwrap());

    let query_count = Arc::new(AtomicUsize::new(0));
    let counter = Arc::clone(&query_count);

    // Mock DNS responder: counts every query and answers 93.184.216.34.
    // Stops after 300ms with no further query.
    let responder_task = tokio::spawn(async move {
        use gotatun::tun::{IpRecv, IpSend};
        use zerocopy::IntoBytes;

        let mut pool = gotatun::packet::PacketBufPool::<4096>::new(16);
        loop {
            let recv =
                tokio::time::timeout(Duration::from_millis(300), ip_recv.recv(&mut pool)).await;
            let Ok(Ok(mut packets)) = recv else {
                break;
            };
            // Collect owned query bytes first; the packet iterator borrows
            // the pool, so replies (which need `pool.get()`) go after it.
            let mut queries = Vec::new();
            for pkt in packets.by_ref() {
                counter.fetch_add(1, Ordering::Relaxed);
                queries.push((*pkt).as_bytes().to_vec());
            }
            drop(packets);

            for raw in queries {
                let parsed = etherparse::SlicedPacket::from_ip(&raw).unwrap();
                let udp_hdr = match &parsed.transport {
                    Some(etherparse::TransportSlice::Udp(u)) => u,
                    _ => panic!("expected udp"),
                };
                let dns_query = udp_hdr.payload();
                let tx_id = u16::from_be_bytes([dns_query[0], dns_query[1]]);

                let mut dns_resp = Vec::new();
                dns_resp.extend_from_slice(&tx_id.to_be_bytes());
                dns_resp.extend_from_slice(&[0x81, 0x80]);
                dns_resp.extend_from_slice(&[0x00, 0x01]);
                dns_resp.extend_from_slice(&[0x00, 0x01]);
                dns_resp.extend_from_slice(&[0x00, 0x00]);
                dns_resp.extend_from_slice(&[0x00, 0x00]);
                dns_resp.extend_from_slice(&dns_query[12..]);
                dns_resp.extend_from_slice(&[0xC0, 0x0C]);
                dns_resp.extend_from_slice(&[0x00, 0x01]);
                dns_resp.extend_from_slice(&[0x00, 0x01]);
                dns_resp.extend_from_slice(&[0x00, 0x00, 0x00, 0x3C]);
                dns_resp.extend_from_slice(&[0x00, 0x04]);
                dns_resp.extend_from_slice(&[93, 184, 216, 34]);

                let (src_ip, dst_ip) = match parsed.net.unwrap() {
                    etherparse::NetSlice::Ipv4(v4) => {
                        (v4.header().source(), v4.header().destination())
                    }
                    _ => panic!("expected ipv4"),
                };
                let udp_ports = (udp_hdr.source_port(), udp_hdr.destination_port());

                let builder = PacketBuilder::ipv4(dst_ip, src_ip, 64).udp(udp_ports.1, udp_ports.0);
                let mut reply_raw = Vec::new();
                builder.write(&mut reply_raw, &dns_resp).unwrap();

                let mut reply_pkt = pool.get();
                reply_pkt.truncate(reply_raw.len());
                reply_pkt.copy_from_slice(&reply_raw);
                let ip_reply = reply_pkt.try_into_ip().unwrap();

                ip_send.send(ip_reply).await.unwrap();
            }
        }
    });

    // 8 concurrent resolutions, released at once via a barrier so they overlap.
    const N: usize = 8;
    let barrier = Arc::new(tokio::sync::Barrier::new(N));
    let mut handles = Vec::new();
    for _ in 0..N {
        let stack = Arc::clone(&stack);
        let barrier = Arc::clone(&barrier);
        handles.push(tokio::spawn(async move {
            barrier.wait().await;
            stack.resolve_in_tunnel("example.com").await
        }));
    }
    for handle in handles {
        let ip = handle.await.unwrap().unwrap();
        assert_eq!(ip, IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34)));
    }

    responder_task.await.unwrap();
    assert_eq!(
        query_count.load(Ordering::Relaxed),
        1,
        "singleflight must coalesce concurrent lookups into one upstream query"
    );

    stack.close().await;
}

// =========================================================================
// 7. VirtualTcpStream Handshake and Streaming Tests
// =========================================================================

#[tokio::test]
async fn test_tcp_stream_connect_unaddressable() {
    let config = make_test_config("10.2.0.2/32", None); // IPv4 only
    let (bridge, _ip_send, _ip_recv) = VirtualTunBridge::new(DEFAULT_MTU, 64);
    let stack = VirtualNetworkStack::new(&config, bridge).unwrap();

    // Attempting to connect to IPv6 when only IPv4 configured must fail
    let dst = SocketAddr::from(([0x26, 0x06, 0, 0, 0, 0, 0, 1], 80));
    let res = stack.tcp_connect(dst).await;
    assert!(res.is_err());
    assert_eq!(
        res.unwrap_err().kind(),
        std::io::ErrorKind::AddrNotAvailable
    );

    stack.close().await;
}

struct CapturedIpv4Tcp {
    src_ip: [u8; 4],
    dst_ip: [u8; 4],
    src_port: u16,
    dst_port: u16,
    seq: u32,
    syn: bool,
    ack: bool,
    payload: Vec<u8>,
}

struct TcpReplySpec<'a> {
    src_ip: [u8; 4],
    dst_ip: [u8; 4],
    src_port: u16,
    dst_port: u16,
    seq: u32,
    ack: u32,
    syn: bool,
    fin: bool,
    payload: &'a [u8],
}

async fn recv_ipv4_tcp(
    ip_recv: &mut BridgeIpRecv,
    pool: &mut gotatun::packet::PacketBufPool<4096>,
) -> CapturedIpv4Tcp {
    use gotatun::tun::IpRecv;
    use zerocopy::IntoBytes;

    let mut packets = ip_recv.recv(pool).await.unwrap();
    let pkt = packets.next().unwrap();
    let raw = (*pkt).as_bytes().to_vec();
    drop(packets);

    let parsed = etherparse::SlicedPacket::from_ip(&raw).unwrap();
    let (src_ip, dst_ip) = match parsed.net.unwrap() {
        etherparse::NetSlice::Ipv4(ip) => (ip.header().source(), ip.header().destination()),
        _ => panic!("expected ipv4 tcp"),
    };
    let etherparse::TransportSlice::Tcp(tcp_hdr) = parsed.transport.unwrap() else {
        panic!("expected ipv4 tcp");
    };

    CapturedIpv4Tcp {
        src_ip,
        dst_ip,
        src_port: tcp_hdr.source_port(),
        dst_port: tcp_hdr.destination_port(),
        seq: tcp_hdr.sequence_number(),
        syn: tcp_hdr.syn(),
        ack: tcp_hdr.ack(),
        payload: tcp_hdr.payload().to_vec(),
    }
}

async fn send_ipv4_tcp_ack(
    ip_send: &mut crate::netstack::bridge::BridgeIpSend,
    pool: &mut gotatun::packet::PacketBufPool<4096>,
    spec: TcpReplySpec<'_>,
) {
    let mut builder = PacketBuilder::ipv4(spec.src_ip, spec.dst_ip, 64)
        .tcp(spec.src_port, spec.dst_port, spec.seq, 65535)
        .ack(spec.ack);
    if spec.syn {
        builder = builder.syn();
    }
    if spec.fin {
        builder = builder.fin();
    }

    let mut raw = Vec::new();
    builder.write(&mut raw, spec.payload).unwrap();

    let mut reply_pkt = pool.get();
    reply_pkt.truncate(raw.len());
    reply_pkt.copy_from_slice(&raw);
    let ip_reply = reply_pkt.try_into_ip().unwrap();
    ip_send.send(ip_reply).await.unwrap();
}

#[tokio::test]
async fn test_tcp_stream_handshake_and_exchange() {
    let config = make_test_config("10.2.0.2/32", None);
    let (bridge, mut ip_send, mut ip_recv) = VirtualTunBridge::new(DEFAULT_MTU, 64);
    let stack = VirtualNetworkStack::new(&config, bridge).unwrap();

    let dst = SocketAddr::from(([93, 184, 216, 34], 80));
    let mut pool = gotatun::packet::PacketBufPool::<4096>::new(16);

    // Spawn mock peer task to drive TCP state machine over tunnel bridge
    let peer_task = tokio::spawn(async move {
        // 1. Receive SYN packet
        let syn_pkt = recv_ipv4_tcp(&mut ip_recv, &mut pool).await;
        assert!(syn_pkt.syn);
        let server_isn = 50000u32;

        // 2. Reply with SYN-ACK
        send_ipv4_tcp_ack(
            &mut ip_send,
            &mut pool,
            TcpReplySpec {
                src_ip: syn_pkt.dst_ip,
                dst_ip: syn_pkt.src_ip,
                src_port: syn_pkt.dst_port,
                dst_port: syn_pkt.src_port,
                seq: server_isn,
                ack: syn_pkt.seq + 1,
                syn: true,
                fin: false,
                payload: &[],
            },
        )
        .await;

        // 3. Receive ACK (completes handshake)
        let ack_pkt = recv_ipv4_tcp(&mut ip_recv, &mut pool).await;
        assert!(ack_pkt.ack);

        // 4. Receive client data (b"PING_DATA")
        let data_pkt = recv_ipv4_tcp(&mut ip_recv, &mut pool).await;
        let payload_len = data_pkt.payload.len() as u32;
        assert_eq!(data_pkt.payload, b"PING_DATA");

        // 5. Send server data (b"PONG_DATA") + ACK
        send_ipv4_tcp_ack(
            &mut ip_send,
            &mut pool,
            TcpReplySpec {
                src_ip: data_pkt.dst_ip,
                dst_ip: data_pkt.src_ip,
                src_port: data_pkt.dst_port,
                dst_port: data_pkt.src_port,
                seq: server_isn + 1,
                ack: data_pkt.seq + payload_len,
                syn: false,
                fin: false,
                payload: b"PONG_DATA",
            },
        )
        .await;

        // 6. Send FIN to signal EOF
        send_ipv4_tcp_ack(
            &mut ip_send,
            &mut pool,
            TcpReplySpec {
                src_ip: data_pkt.dst_ip,
                dst_ip: data_pkt.src_ip,
                src_port: data_pkt.dst_port,
                dst_port: data_pkt.src_port,
                seq: server_isn + 1 + 9, // + len("PONG_DATA")
                ack: data_pkt.seq + payload_len,
                syn: false,
                fin: true,
                payload: &[],
            },
        )
        .await;
    });

    // Client: initiate TCP connect
    let mut stream = stack
        .tcp_connect(dst)
        .await
        .expect("tcp_connect must succeed");
    assert_eq!(stream.peer_addr(), dst);

    // Write data
    stream
        .write_all(b"PING_DATA")
        .await
        .expect("write_all succeeds");
    stream.flush().await.expect("flush succeeds");

    // Read data
    let mut buf = [0u8; 9];
    stream
        .read_exact(&mut buf)
        .await
        .expect("read_exact succeeds");
    assert_eq!(&buf, b"PONG_DATA");

    // Read EOF after FIN
    let mut eof_buf = [0u8; 16];
    let n = stream
        .read(&mut eof_buf)
        .await
        .expect("read at EOF succeeds");
    assert_eq!(n, 0);

    peer_task.await.unwrap();
    stack.close().await;
}

// =========================================================================
// 8. IpMode Isolation Tests (ipv4_only & ipv6_only)
// =========================================================================

#[tokio::test]
async fn test_stack_ipv4_only_isolation() {
    let config = make_test_config("10.2.0.2/32", Some("fd00::2/128"));
    let (bridge, _ip_send, _ip_recv) = VirtualTunBridge::new(DEFAULT_MTU, 64);

    let stack =
        VirtualNetworkStack::new_with_mode(&config, bridge, crate::config::IpMode::Ipv4Only, false)
            .unwrap();

    assert_eq!(stack.local_v4(), Some(Ipv4Addr::new(10, 2, 0, 2)));
    assert_eq!(stack.local_v6(), None);

    // IPv6 TCP connect must be blocked immediately
    let v6_dst: SocketAddr = "[2606:4700:4700::1111]:443".parse().unwrap();
    let tcp_err = stack.tcp_connect(v6_dst).await.unwrap_err();
    assert_eq!(tcp_err.kind(), std::io::ErrorKind::AddrNotAvailable);

    // IPv6 UDP send_to must be blocked immediately
    let udp = stack.udp_bind(0).unwrap();
    let udp_err = udp.send_to(b"hello", v6_dst).await.unwrap_err();
    assert_eq!(udp_err.kind(), std::io::ErrorKind::AddrNotAvailable);

    // IPv6 literal resolution must be blocked, IPv4 literal allowed
    let dns_v6_err = stack
        .resolve_in_tunnel("2606:4700:4700::1111")
        .await
        .unwrap_err();
    assert_eq!(dns_v6_err.kind(), std::io::ErrorKind::AddrNotAvailable);
    let dns_v4 = stack.resolve_in_tunnel("1.1.1.1").await.unwrap();
    assert_eq!(dns_v4, IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)));

    stack.close().await;
}

#[tokio::test]
async fn test_stack_ipv6_only_isolation() {
    let config = make_test_config("10.2.0.2/32", Some("fd00::2/128"));
    let (bridge, _ip_send, _ip_recv) = VirtualTunBridge::new(DEFAULT_MTU, 64);

    let stack =
        VirtualNetworkStack::new_with_mode(&config, bridge, crate::config::IpMode::Ipv6Only, false)
            .unwrap();

    assert_eq!(stack.local_v4(), None);
    assert_eq!(
        stack.local_v6(),
        Some("fd00::2".parse::<Ipv6Addr>().unwrap())
    );

    // IPv4 TCP connect must be blocked immediately
    let v4_dst: SocketAddr = "1.1.1.1:443".parse().unwrap();
    let tcp_err = stack.tcp_connect(v4_dst).await.unwrap_err();
    assert_eq!(tcp_err.kind(), std::io::ErrorKind::AddrNotAvailable);

    // IPv4 UDP send_to must be blocked immediately
    let udp = stack.udp_bind(0).unwrap();
    let udp_err = udp.send_to(b"hello", v4_dst).await.unwrap_err();
    assert_eq!(udp_err.kind(), std::io::ErrorKind::AddrNotAvailable);

    // IPv4 literal resolution must be blocked, IPv6 literal allowed
    let dns_v4_err = stack.resolve_in_tunnel("1.1.1.1").await.unwrap_err();
    assert_eq!(dns_v4_err.kind(), std::io::ErrorKind::AddrNotAvailable);
    let dns_v6 = stack
        .resolve_in_tunnel("2606:4700:4700::1111")
        .await
        .unwrap();
    assert_eq!(
        dns_v6,
        IpAddr::V6("2606:4700:4700::1111".parse::<Ipv6Addr>().unwrap())
    );

    stack.close().await;
}

#[tokio::test]
async fn test_stack_close_wakes_parked_udp_and_connect() {
    let config = make_test_config("10.2.0.3/32", None);
    let (bridge, _ip_send, _ip_recv) = VirtualTunBridge::new(DEFAULT_MTU, 64);
    let stack = std::sync::Arc::new(VirtualNetworkStack::new(&config, bridge).unwrap());

    let udp = stack.udp_bind(0).unwrap();
    let recv_task = tokio::spawn(async move {
        let mut buf = [0u8; 64];
        udp.recv_from(&mut buf).await
    });

    let stack_for_connect = std::sync::Arc::clone(&stack);
    let connect_task = tokio::spawn(async move {
        stack_for_connect
            .tcp_connect("1.1.1.1:80".parse().unwrap())
            .await
    });

    // Yield briefly so both tasks park on wakers, then close stack
    tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    stack.close().await;

    let recv_res = tokio::time::timeout(std::time::Duration::from_millis(200), recv_task)
        .await
        .expect("parked udp recv_from must wake immediately on close")
        .unwrap();
    assert!(recv_res.is_err());

    let conn_res = tokio::time::timeout(std::time::Duration::from_millis(200), connect_task)
        .await
        .expect("parked tcp_connect must wake immediately on close")
        .unwrap();
    assert!(conn_res.is_err());
}

#[tokio::test]
async fn test_dual_stack_clamps_effective_ip_mode_to_interface_addresses() {
    let v4_only_cfg = make_test_config("10.2.0.4/32", None);
    let (bridge1, _s1, _r1) = VirtualTunBridge::new(DEFAULT_MTU, 64);
    let stack_v4 = VirtualNetworkStack::new_with_mode(
        &v4_only_cfg,
        bridge1,
        crate::config::IpMode::DualStack,
        true,
    )
    .unwrap();
    assert_eq!(
        stack_v4.effective_ip_mode(),
        crate::config::IpMode::Ipv4Only
    );
    stack_v4.close().await;

    let v6_only_cfg = WgInterfaceConfig {
        private_key: StaticSecret::from([42u8; 32]),
        addresses: vec!["fd00::4/128".parse().unwrap()],
        dns: vec!["2606:4700:4700::1111".parse().unwrap()],
        listen_port: None,
        mtu: 1420,
    };
    let (bridge2, _s2, _r2) = VirtualTunBridge::new(DEFAULT_MTU, 64);
    let stack_v6 = VirtualNetworkStack::new_with_mode(
        &v6_only_cfg,
        bridge2,
        crate::config::IpMode::DualStack,
        false,
    )
    .unwrap();
    assert_eq!(
        stack_v6.effective_ip_mode(),
        crate::config::IpMode::Ipv6Only
    );
    stack_v6.close().await;
}

#[test]
fn test_dns_build_query_rejects_control_chars_and_whitespace() {
    assert!(matches!(
        build_query("evil domain.com", QueryType::A, 1),
        Err(DnsError::InvalidDomain(_))
    ));
    assert!(matches!(
        build_query("evil\ndomain.com", QueryType::A, 1),
        Err(DnsError::InvalidDomain(_))
    ));
}

#[tokio::test]
async fn test_bridge_recv_skips_malformed_packet_and_recovers() {
    let (mut bridge, _ip_send, mut ip_recv) = VirtualTunBridge::new(DEFAULT_MTU, 16);
    let mut pool = gotatun::packet::PacketBufPool::<4096>::new(16);

    use smoltcp::phy::{Device, TxToken};
    let now = smoltcp::time::Instant::now();

    // Inject malformed 3-byte packet first
    let tx_bad = bridge.transmit(now).unwrap();
    tx_bad.consume(3, |buf| buf.copy_from_slice(&[0x45, 0x00, 0x00]));

    // Inject valid IPv4 UDP packet second
    let builder = PacketBuilder::ipv4([10, 2, 0, 2], [1, 1, 1, 1], 64).udp(4567, 53);
    let mut raw_good = Vec::new();
    builder.write(&mut raw_good, b"OK").unwrap();
    let tx_good = bridge.transmit(now).unwrap();
    tx_good.consume(raw_good.len(), |buf| buf.copy_from_slice(&raw_good));

    use gotatun::tun::IpRecv;
    let mut packets = ip_recv.recv(&mut pool).await.unwrap();
    let pkt = packets
        .next()
        .expect("valid packet after malformed skipped");
    use zerocopy::IntoBytes;
    assert_eq!((*pkt).as_bytes(), &raw_good[..]);
}

#[tokio::test]
async fn test_shutdown_wakers_bounded_and_cleaned_on_socket_drop() {
    let config = make_test_config("10.2.0.5/32", None);
    let (bridge, _ip_send, _ip_recv) = VirtualTunBridge::new(DEFAULT_MTU, 64);
    let stack = VirtualNetworkStack::new(&config, bridge).unwrap();

    for _ in 0..10 {
        let udp = stack.udp_bind(0).unwrap();
        let mut recv_buf = [0u8; 32];
        let fut = udp.recv_from(&mut recv_buf);
        let _ = tokio::time::timeout(Duration::from_millis(5), fut).await;
        drop(udp);
        assert!(
            stack.inner().lock().shutdown_wakers.is_empty(),
            "shutdown_wakers must be cleaned when socket drops"
        );
    }

    stack.close().await;
}

async fn drain_one_ip_packet(
    ip_recv: &mut BridgeIpRecv,
    pool: &mut gotatun::packet::PacketBufPool<4096>,
) {
    use gotatun::tun::IpRecv;
    let _ = ip_recv.recv(pool).await.unwrap();
}

#[tokio::test]
async fn test_stack_live_ip_mode_widening_and_narrowing() {
    let config = make_test_config("10.2.0.2/32", Some("fd00:1::2/128"));
    let (bridge, mut ip_send, mut ip_recv) = VirtualTunBridge::new(DEFAULT_MTU, 64);
    let stack =
        VirtualNetworkStack::new_with_mode(&config, bridge, crate::config::IpMode::Ipv6Only, false)
            .unwrap();

    assert_eq!(stack.local_v4(), None);
    assert_eq!(stack.local_v6(), Some("fd00:1::2".parse().unwrap()));
    assert_eq!(stack.effective_ip_mode(), crate::config::IpMode::Ipv6Only);

    let v4_tcp_dst = SocketAddr::from(([93, 184, 216, 34], 80));
    let v4_udp_dst = SocketAddr::from(([1, 1, 1, 1], 53));
    assert_eq!(
        stack.tcp_connect(v4_tcp_dst).await.unwrap_err().kind(),
        std::io::ErrorKind::AddrNotAvailable
    );
    let udp_sock = stack.udp_bind(0).unwrap();
    assert_eq!(
        udp_sock
            .send_to(b"blocked", v4_udp_dst)
            .await
            .unwrap_err()
            .kind(),
        std::io::ErrorKind::AddrNotAvailable
    );

    // Widen live to DualStack: IPv4 address, default route, DNS mode, and open UDP sockets update.
    stack.set_ip_mode(crate::config::IpMode::DualStack);
    assert_eq!(stack.local_v4(), Some(Ipv4Addr::new(10, 2, 0, 2)));
    assert_eq!(stack.effective_ip_mode(), crate::config::IpMode::DualStack);
    {
        let inner = stack.inner().lock();
        assert!(inner.iface.routes().get_default_ipv4_route().is_some());
        assert!(inner.iface.routes().get_default_ipv6_route().is_some())
    };
    assert_eq!(udp_sock.send_to(b"ok", v4_udp_dst).await.unwrap(), 2);

    let mut pool = gotatun::packet::PacketBufPool::<4096>::new(16);
    let peer_task = tokio::spawn(async move {
        drain_one_ip_packet(&mut ip_recv, &mut pool).await;
        let syn_pkt = recv_ipv4_tcp(&mut ip_recv, &mut pool).await;
        assert!(syn_pkt.syn);
        send_ipv4_tcp_ack(
            &mut ip_send,
            &mut pool,
            TcpReplySpec {
                src_ip: syn_pkt.dst_ip,
                dst_ip: syn_pkt.src_ip,
                src_port: syn_pkt.dst_port,
                dst_port: syn_pkt.src_port,
                seq: 7000,
                ack: syn_pkt.seq + 1,
                syn: true,
                fin: false,
                payload: &[],
            },
        )
        .await;
    });

    let stream = tokio::time::timeout(Duration::from_secs(2), stack.tcp_connect(v4_tcp_dst))
        .await
        .expect("v4 connect after live DualStack widening should complete")
        .expect("v4 connect should succeed after widening");
    assert_eq!(
        stream.local_addr().ip(),
        IpAddr::V4(Ipv4Addr::new(10, 2, 0, 2))
    );
    drop(stream);
    peer_task.await.unwrap();

    // Narrow back live to Ipv6Only: IPv4 address/route removed and IPv4 traffic blocked again.
    stack.set_ip_mode(crate::config::IpMode::Ipv6Only);
    assert_eq!(stack.local_v4(), None);
    assert_eq!(stack.effective_ip_mode(), crate::config::IpMode::Ipv6Only);
    assert!(
        stack
            .inner()
            .lock()
            .iface
            .routes()
            .get_default_ipv4_route()
            .is_none()
    );
    assert_eq!(
        stack.tcp_connect(v4_tcp_dst).await.unwrap_err().kind(),
        std::io::ErrorKind::AddrNotAvailable
    );
    assert_eq!(
        udp_sock
            .send_to(b"blocked2", v4_udp_dst)
            .await
            .unwrap_err()
            .kind(),
        std::io::ErrorKind::AddrNotAvailable
    );

    stack.close().await;
}

#[tokio::test]
async fn test_stack_live_ip_mode_clamps_single_stack_on_widening() {
    let v6_only_cfg = WgInterfaceConfig {
        private_key: StaticSecret::from([42u8; 32]),
        addresses: vec!["fd00::4/128".parse().unwrap()],
        dns: vec!["2606:4700:4700::1111".parse().unwrap()],
        listen_port: None,
        mtu: 1420,
    };
    let (bridge, _send, _recv) = VirtualTunBridge::new(DEFAULT_MTU, 64);
    let stack = VirtualNetworkStack::new_with_mode(
        &v6_only_cfg,
        bridge,
        crate::config::IpMode::Ipv6Only,
        false,
    )
    .unwrap();

    stack.set_ip_mode(crate::config::IpMode::DualStack);
    assert_eq!(stack.effective_ip_mode(), crate::config::IpMode::Ipv6Only);
    assert_eq!(stack.local_v4(), None);
    assert_eq!(
        stack.local_v6(),
        Some("fd00::4".parse::<Ipv6Addr>().unwrap())
    );

    stack.close().await;
}

// =========================================================================
// 13. TUN adapter: dispatcher routing, suspend/resume/detach
// =========================================================================

/// Build a minimal IPv4 packet for TUN tests. Layout matches the
/// parser in `tun.rs`: version/IHL, protocol, addresses, ports.
fn tun_test_ipv4_packet(
    src: [u8; 4],
    dst: [u8; 4],
    proto: u8,
    src_port: u16,
    dst_port: u16,
) -> Vec<u8> {
    let mut packet = vec![0u8; 24];
    packet[0] = 0x45;
    packet[2] = 0;
    packet[3] = 24;
    packet[8] = 64;
    packet[9] = proto;
    packet[12..16].copy_from_slice(&src);
    packet[16..20].copy_from_slice(&dst);
    packet[20..22].copy_from_slice(&src_port.to_be_bytes());
    packet[22..24].copy_from_slice(&dst_port.to_be_bytes());
    packet
}

/// A socketpair stands in for the Android TUN fd: the endpoint only
/// reads/writes raw bytes, so any byte-stream fd works for the test.
fn tun_test_endpoint() -> (
    std::sync::Arc<crate::netstack::TunEndpoint>,
    std::os::unix::net::UnixStream,
) {
    use std::os::fd::OwnedFd;
    use std::os::unix::net::UnixStream;

    let (tun_side, peer_side) = UnixStream::pair().expect("socketpair for TUN test");
    let endpoint = crate::netstack::TunEndpoint::from_owned_fd(OwnedFd::from(tun_side), 1500)
        .expect("endpoint from socketpair fd");
    (endpoint, peer_side)
}

#[tokio::test]
async fn test_tun_dispatcher_routes_packet_to_attached_tunnel() {
    use gotatun::packet::PacketBufPool;
    use gotatun::tun::{IpRecv, IpSend};
    use std::io::{Read, Write};
    use std::time::Duration;
    use zerocopy::IntoBytes;

    let (endpoint, mut peer) = tun_test_endpoint();
    endpoint.start_dispatcher().expect("dispatcher starts");
    let (mut ip_send, mut ip_recv) =
        endpoint.attach_tunnel("wgcf-001", vec!["0.0.0.0/0".parse().unwrap()], vec![]);

    // Outbound: write a DNS packet into the "TUN" fd, expect it on
    // the tunnel's receiver with the same destination.
    let packet = tun_test_ipv4_packet([10, 0, 0, 2], [8, 8, 8, 8], 17, 12345, 53);
    peer.write_all(&packet).expect("write packet to TUN fd");
    let mut pool = PacketBufPool::new(8);
    let received = tokio::time::timeout(Duration::from_secs(2), ip_recv.recv(&mut pool))
        .await
        .expect("packet must arrive within timeout")
        .expect("recv must succeed");
    let mut packets: Vec<_> = received.collect();
    assert_eq!(packets.len(), 1);
    let routed = packets.pop().expect("one packet");
    assert_eq!(
        routed.destination(),
        Some("8.8.8.8".parse().unwrap()),
        "routed packet keeps its destination"
    );
    assert!(
        crate::netstack::parse_flow_key((*routed).as_bytes())
            .expect("routed packet parses")
            .is_dns(),
        "the routed packet is the DNS query"
    );

    // Inbound: send the same packet back through TunIpSend and read
    // the raw bytes off the "TUN" fd.
    peer.set_read_timeout(Some(Duration::from_secs(2)))
        .expect("set read timeout");
    ip_send.send(routed).await.expect("send to TUN fd");
    let mut buf = vec![0u8; 64];
    let n = peer.read(&mut buf).expect("read packet from TUN fd");
    assert_eq!(&buf[..n], &packet[..], "round-tripped packet is unchanged");

    // The VPN data plane counts its own bytes: TX is the packet read
    // from TUN into the tunnel, RX is the packet written back.
    let counts = endpoint.byte_counts();
    let (rx, tx) = counts
        .get("wgcf-001")
        .copied()
        .expect("byte counts exist for the attached tunnel");
    assert_eq!(tx, packet.len() as u64, "TX counts the outbound packet");
    assert_eq!(rx, packet.len() as u64, "RX counts the returned packet");

    endpoint.shutdown().await;
}

#[tokio::test]
async fn test_tun_dispatcher_counters() {
    use gotatun::packet::PacketBufPool;
    use gotatun::tun::IpRecv;
    use std::io::Write;
    use std::time::Duration;

    let (endpoint, mut peer) = tun_test_endpoint();
    endpoint.start_dispatcher().expect("dispatcher starts");
    let (_ip_send, mut ip_recv) =
        endpoint.attach_tunnel("wgcf-001", vec!["10.0.0.0/8".parse().unwrap()], vec![]);
    let mut pool = PacketBufPool::new(8);

    // One routed packet, then one with no route. Written separately:
    // the socketpair is a stream, so back-to-back writes can coalesce
    // into a single dispatcher read.
    let routed = tun_test_ipv4_packet([10, 0, 0, 2], [10, 1, 2, 3], 6, 40000, 443);
    peer.write_all(&routed).expect("write routed packet");
    let received = tokio::time::timeout(Duration::from_secs(2), ip_recv.recv(&mut pool))
        .await
        .expect("routed packet must arrive")
        .expect("recv must succeed");
    assert_eq!(received.count(), 1);
    let unrouted = tun_test_ipv4_packet([10, 0, 0, 2], [8, 8, 8, 8], 17, 1001, 53);
    peer.write_all(&unrouted).expect("write unrouted packet");

    // The dispatcher is async: wait until both reads are counted.
    let deadline = std::time::Instant::now() + Duration::from_secs(2);
    let stats = loop {
        let stats = endpoint.stats_snapshot();
        if stats.packets_read >= 2 {
            break stats;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "dispatcher must count both packets, got {}",
            stats.packets_read
        );
        tokio::time::sleep(Duration::from_millis(10)).await;
    };
    assert_eq!(stats.packets_queued, 1, "one packet reaches a tunnel");
    assert_eq!(stats.packets_no_route, 1, "one packet has no route");
    assert_eq!(stats.read_errors, 0);
    assert!(stats.dispatcher_running, "dispatcher still running");
    assert!(stats.last_read_error.is_none());

    endpoint.shutdown().await;
    assert!(
        !endpoint.stats_snapshot().dispatcher_running,
        "dispatcher reports stopped after shutdown"
    );
}

#[tokio::test]
async fn test_tun_dispatcher_suspend_resume_detach() {
    use gotatun::packet::PacketBufPool;
    use gotatun::tun::IpRecv;
    use std::io::Write;
    use std::time::Duration;

    let (endpoint, mut peer) = tun_test_endpoint();
    endpoint.start_dispatcher().expect("dispatcher starts");
    let (_ip_send, mut ip_recv) =
        endpoint.attach_tunnel("wgcf-001", vec!["10.0.0.0/8".parse().unwrap()], vec![]);
    let mut pool = PacketBufPool::new(8);

    // No route for 8.8.8.8: the packet is dropped, nothing arrives.
    let unrouted = tun_test_ipv4_packet([10, 0, 0, 2], [8, 8, 8, 8], 17, 1001, 53);
    peer.write_all(&unrouted).expect("write unrouted packet");
    assert!(
        tokio::time::timeout(Duration::from_millis(200), ip_recv.recv(&mut pool))
            .await
            .is_err(),
        "unrouted packet must not arrive"
    );

    // A routed packet arrives.
    let routed = tun_test_ipv4_packet([10, 0, 0, 2], [10, 1, 2, 3], 6, 40000, 443);
    peer.write_all(&routed).expect("write routed packet");
    let got = tokio::time::timeout(Duration::from_secs(2), ip_recv.recv(&mut pool))
        .await
        .expect("routed packet must arrive")
        .expect("recv must succeed");
    assert_eq!(got.count(), 1);

    // Suspend: a NEW flow is dropped (no route), while the old flow
    // stays pinned and would keep buffering into the kept channel.
    endpoint.suspend_tunnel("wgcf-001");
    let new_flow = tun_test_ipv4_packet([10, 0, 0, 2], [10, 1, 2, 3], 6, 40001, 443);
    peer.write_all(&new_flow)
        .expect("write packet while suspended");
    assert!(
        tokio::time::timeout(Duration::from_millis(200), ip_recv.recv(&mut pool))
            .await
            .is_err(),
        "new flow while suspended must not arrive"
    );

    // Resume: the new flow routes again on the same receiver.
    endpoint.resume_tunnel("wgcf-001", vec!["10.0.0.0/8".parse().unwrap()], vec![]);
    peer.write_all(&new_flow)
        .expect("write packet after resume");
    let got = tokio::time::timeout(Duration::from_secs(2), ip_recv.recv(&mut pool))
        .await
        .expect("packet after resume must arrive")
        .expect("recv must succeed");
    assert_eq!(got.count(), 1);

    // Detach: routing stops and the receiver fails with EOF.
    endpoint.detach_tunnel("wgcf-001");
    let after_detach = tun_test_ipv4_packet([10, 0, 0, 2], [10, 1, 2, 3], 6, 40002, 443);
    peer.write_all(&after_detach)
        .expect("write packet after detach");
    let err = match tokio::time::timeout(Duration::from_secs(2), ip_recv.recv(&mut pool))
        .await
        .expect("detached recv must resolve")
    {
        Ok(_) => panic!("detached receiver must fail"),
        Err(err) => err,
    };
    assert_eq!(err.kind(), std::io::ErrorKind::UnexpectedEof);

    endpoint.shutdown().await;
}

// =========================================================================
// 14. TUN adapter: multi-tunnel routing and source NAT
// =========================================================================

/// Receive one packet from a tunnel receiver, or fail the test.
async fn tun_recv_one(
    recv: &mut crate::netstack::TunIpRecv,
    pool: &mut gotatun::packet::PacketBufPool,
) -> gotatun::packet::Packet<gotatun::packet::Ip> {
    use gotatun::tun::IpRecv;
    let received = tokio::time::timeout(Duration::from_secs(2), recv.recv(pool))
        .await
        .expect("packet must arrive within timeout")
        .expect("recv must succeed");
    let mut packets: Vec<_> = received.collect();
    assert_eq!(packets.len(), 1, "exactly one packet per write");
    packets.pop().expect("one packet")
}

/// Recompute an IPv4 header checksum (field zeroed) for test checks.
fn test_ipv4_header_checksum(header: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    let (pairs, _) = header.as_chunks::<2>();
    for pair in pairs {
        sum += u32::from(u16::from_be_bytes(*pair));
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

/// True when the IPv4 header checksum stored in `packet` is valid.
fn test_ipv4_checksum_valid(packet: &[u8]) -> bool {
    let ihl = (packet[0] & 0x0f) as usize * 4;
    if packet.len() < ihl || ihl < 20 {
        return false;
    }
    let stored = u16::from_be_bytes([packet[10], packet[11]]);
    let mut header = packet[..ihl].to_vec();
    header[10] = 0;
    header[11] = 0;
    test_ipv4_header_checksum(&header) == stored
}

/// Checker that marks a set of tunnel ids unusable (test double for
/// the manager's health/state check).
struct TestUsableChecker {
    unusable: std::sync::Mutex<std::collections::HashSet<String>>,
}

impl TestUsableChecker {
    fn new(unusable: &[&str]) -> Self {
        Self {
            unusable: std::sync::Mutex::new(unusable.iter().map(|id| (*id).to_string()).collect()),
        }
    }

    fn mark_unusable(&self, id: &str) {
        self.unusable
            .lock()
            .expect("checker lock")
            .insert(id.to_string());
    }
}

impl crate::netstack::TunnelUsable for TestUsableChecker {
    fn is_usable(&self, id: &str) -> bool {
        !self.unusable.lock().expect("checker lock").contains(id)
    }
}

#[tokio::test]
async fn test_tun_multi_tunnel_round_robin() {
    use gotatun::packet::PacketBufPool;
    use gotatun::tun::IpRecv;
    use std::io::Write;
    use zerocopy::IntoBytes;

    let (endpoint, mut peer) = tun_test_endpoint();
    endpoint.start_dispatcher().expect("dispatcher starts");
    endpoint.set_strategy(crate::netstack::VpnRouteStrategy::RoundRobin);
    let (_send_a, mut recv_a) =
        endpoint.attach_tunnel("tunnel-a", vec!["0.0.0.0/0".parse().unwrap()], vec![]);
    let (_send_b, mut recv_b) =
        endpoint.attach_tunnel("tunnel-b", vec!["0.0.0.0/0".parse().unwrap()], vec![]);
    let mut pool = PacketBufPool::new(8);

    // Four distinct flows, one packet each, received before the next
    // write (the socketpair is a stream and coalesces back-to-back
    // writes). Round Robin must alternate tunnels per new flow.
    for (index, sport) in [40000u16, 40001, 40002, 40003].iter().enumerate() {
        let packet = tun_test_ipv4_packet([10, 0, 0, 2], [1, 2, 3, 4], 6, *sport, 443);
        peer.write_all(&packet).expect("write packet to TUN fd");
        if index % 2 == 0 {
            let got = tun_recv_one(&mut recv_a, &mut pool).await;
            assert_eq!(
                crate::netstack::parse_flow_key((*got).as_bytes())
                    .expect("packet parses")
                    .src_port,
                *sport,
                "even flow {index} goes to tunnel-a"
            );
            assert!(
                tokio::time::timeout(Duration::from_millis(100), recv_b.recv(&mut pool))
                    .await
                    .is_err(),
                "tunnel-b must not see flow {index}"
            );
        } else {
            let got = tun_recv_one(&mut recv_b, &mut pool).await;
            assert_eq!(
                crate::netstack::parse_flow_key((*got).as_bytes())
                    .expect("packet parses")
                    .src_port,
                *sport,
                "odd flow {index} goes to tunnel-b"
            );
            assert!(
                tokio::time::timeout(Duration::from_millis(100), recv_a.recv(&mut pool))
                    .await
                    .is_err(),
                "tunnel-a must not see flow {index}"
            );
        }
    }

    endpoint.shutdown().await;
}

#[tokio::test]
async fn test_tun_multi_tunnel_fallback_and_failover() {
    use gotatun::packet::PacketBufPool;
    use std::io::Write;
    use std::sync::Arc;

    let (endpoint, mut peer) = tun_test_endpoint();
    endpoint.start_dispatcher().expect("dispatcher starts");
    endpoint.set_strategy(crate::netstack::VpnRouteStrategy::Fallback);
    let checker = Arc::new(TestUsableChecker::new(&[]));
    endpoint.set_usable_checker(Some(
        Arc::clone(&checker) as Arc<dyn crate::netstack::TunnelUsable>
    ));
    let (_send_a, mut recv_a) =
        endpoint.attach_tunnel("tunnel-a", vec!["0.0.0.0/0".parse().unwrap()], vec![]);
    let (_send_b, mut recv_b) =
        endpoint.attach_tunnel("tunnel-b", vec!["0.0.0.0/0".parse().unwrap()], vec![]);
    let mut pool = PacketBufPool::new(8);

    // Fallback: every new flow goes to the first usable tunnel.
    let first = tun_test_ipv4_packet([10, 0, 0, 2], [1, 2, 3, 4], 6, 40000, 443);
    peer.write_all(&first).expect("write first flow");
    tun_recv_one(&mut recv_a, &mut pool).await;
    let second = tun_test_ipv4_packet([10, 0, 0, 2], [1, 2, 3, 4], 6, 40001, 443);
    peer.write_all(&second).expect("write second flow");
    tun_recv_one(&mut recv_a, &mut pool).await;

    // Failover: tunnel-a becomes unusable, so the pinned first flow
    // re-routes to tunnel-b on its next packet, and new flows follow.
    checker.mark_unusable("tunnel-a");
    peer.write_all(&first).expect("write first flow again");
    tun_recv_one(&mut recv_b, &mut pool).await;
    peer.write_all(&second).expect("write second flow again");
    tun_recv_one(&mut recv_b, &mut pool).await;

    endpoint.shutdown().await;
}

#[tokio::test]
async fn test_tun_source_nat_rewrites_and_restores() {
    use gotatun::packet::PacketBufPool;
    use std::io::{Read, Write};
    use zerocopy::IntoBytes;

    let (endpoint, mut peer) = tun_test_endpoint();
    endpoint.start_dispatcher().expect("dispatcher starts");
    let (mut ip_send, mut ip_recv) = endpoint.attach_tunnel(
        "wgcf-001",
        vec!["0.0.0.0/0".parse().unwrap()],
        vec!["172.16.0.2/32".parse().unwrap()],
    );
    let mut pool = PacketBufPool::new(8);

    // Outbound: the kernel stamps the TUN address 10.8.0.2, but the
    // peer only accepts 172.16.0.2, so the dispatcher rewrites it.
    let packet = tun_test_ipv4_packet([10, 8, 0, 2], [1, 2, 3, 4], 6, 40000, 443);
    peer.write_all(&packet).expect("write packet to TUN fd");
    let routed = tun_recv_one(&mut ip_recv, &mut pool).await;
    let routed_bytes = (*routed).as_bytes().to_vec();
    assert_eq!(
        &routed_bytes[12..16],
        &[172, 16, 0, 2],
        "source is rewritten to the tunnel's Interface address"
    );
    assert_eq!(
        &routed_bytes[16..20],
        &[1, 2, 3, 4],
        "destination is unchanged"
    );
    assert!(
        test_ipv4_checksum_valid(&routed_bytes),
        "rewritten packet carries a valid IPv4 header checksum"
    );

    // Inbound: the reply comes back addressed to 172.16.0.2; the
    // return path restores the original source as the destination.
    let mut reply = routed_bytes.clone();
    reply[12..16].copy_from_slice(&[1, 2, 3, 4]);
    reply[16..20].copy_from_slice(&[172, 16, 0, 2]);
    reply[20..22].copy_from_slice(&443u16.to_be_bytes());
    reply[22..24].copy_from_slice(&40000u16.to_be_bytes());
    let mut reply_raw = pool.get();
    reply_raw.buf_mut().resize(reply.len(), 0);
    reply_raw.buf_mut().copy_from_slice(&reply);
    let reply_packet = reply_raw.try_into_ip().expect("reply parses");
    peer.set_read_timeout(Some(Duration::from_secs(2)))
        .expect("set read timeout");
    ip_send
        .send(reply_packet)
        .await
        .expect("send reply to TUN fd");
    let mut buf = vec![0u8; 64];
    let n = peer.read(&mut buf).expect("read reply from TUN fd");
    let written = &buf[..n];
    assert_eq!(
        &written[16..20],
        &[10, 8, 0, 2],
        "destination is restored to the original TUN address"
    );
    assert_eq!(
        &written[12..16],
        &[1, 2, 3, 4],
        "source is unchanged on the return path"
    );
    assert!(
        test_ipv4_checksum_valid(written),
        "restored packet carries a valid IPv4 header checksum"
    );

    endpoint.shutdown().await;
}

#[tokio::test]
async fn test_tun_multi_tunnel_weighted() {
    use gotatun::packet::PacketBufPool;
    use gotatun::tun::IpRecv;
    use std::io::Write;
    use zerocopy::IntoBytes;

    let (endpoint, mut peer) = tun_test_endpoint();
    endpoint.start_dispatcher().expect("dispatcher starts");
    endpoint.set_strategy(crate::netstack::VpnRouteStrategy::Weighted);
    endpoint.set_weight("tunnel-a", 3);
    endpoint.set_weight("tunnel-b", 1);
    let (_send_a, mut recv_a) =
        endpoint.attach_tunnel("tunnel-a", vec!["0.0.0.0/0".parse().unwrap()], vec![]);
    let (_send_b, mut recv_b) =
        endpoint.attach_tunnel("tunnel-b", vec!["0.0.0.0/0".parse().unwrap()], vec![]);
    let mut pool = PacketBufPool::new(8);

    // Weights 3:1 over 8 new flows must split 6:2. One packet per
    // write, received before the next write (stream coalescing).
    let mut counts = [0usize; 2];
    for sport in 40000u16..40008 {
        let packet = tun_test_ipv4_packet([10, 0, 0, 2], [1, 2, 3, 4], 6, sport, 443);
        peer.write_all(&packet).expect("write packet to TUN fd");
        let got_a = tokio::time::timeout(Duration::from_millis(100), recv_a.recv(&mut pool)).await;
        let got_b = tokio::time::timeout(Duration::from_millis(100), recv_b.recv(&mut pool)).await;
        match (got_a, got_b) {
            (Ok(_), Err(_)) => counts[0] += 1,
            (Err(_), Ok(_)) => counts[1] += 1,
            _ => panic!("flow {sport} must arrive on exactly one tunnel"),
        }
    }
    assert_eq!(counts, [6, 2], "weights 3:1 split 8 flows 6:2");

    // Weight 0: tunnel-b is never picked for new flows.
    endpoint.set_weight("tunnel-b", 0);
    for sport in 40100u16..40104 {
        let packet = tun_test_ipv4_packet([10, 0, 0, 2], [1, 2, 3, 4], 6, sport, 443);
        peer.write_all(&packet).expect("write packet to TUN fd");
        let got = tun_recv_one(&mut recv_a, &mut pool).await;
        assert_eq!(
            crate::netstack::parse_flow_key((*got).as_bytes())
                .expect("packet parses")
                .src_port,
            sport,
            "weight-0 tunnel gets no new flows"
        );
    }

    endpoint.shutdown().await;
}

/// Build a minimal IPv4/UDP packet carrying `payload` (no checksum).
fn tun_test_udp_packet(
    src: [u8; 4],
    dst: [u8; 4],
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> Vec<u8> {
    let total = 20 + 8 + payload.len();
    let mut packet = vec![0u8; total];
    packet[0] = 0x45;
    packet[2] = (total >> 8) as u8;
    packet[3] = total as u8;
    packet[8] = 64;
    packet[9] = 17;
    packet[12..16].copy_from_slice(&src);
    packet[16..20].copy_from_slice(&dst);
    packet[20..22].copy_from_slice(&src_port.to_be_bytes());
    packet[22..24].copy_from_slice(&dst_port.to_be_bytes());
    packet[24..26].copy_from_slice(&((8 + payload.len()) as u16).to_be_bytes());
    packet[28..].copy_from_slice(payload);
    packet
}

/// Build a minimal DNS response: one A answer for `domain` -> `ip`.
fn tun_test_dns_response(id: u16, domain: &str, ip: [u8; 4], ttl: u32) -> Vec<u8> {
    let mut resp = Vec::new();
    resp.extend_from_slice(&id.to_be_bytes());
    resp.extend_from_slice(&0x8180u16.to_be_bytes()); // QR=1, RD=1, RA=1, RCODE=0
    resp.extend_from_slice(&1u16.to_be_bytes()); // QDCOUNT
    resp.extend_from_slice(&1u16.to_be_bytes()); // ANCOUNT
    resp.extend_from_slice(&0u16.to_be_bytes());
    resp.extend_from_slice(&0u16.to_be_bytes());
    for label in domain.split('.') {
        resp.push(label.len() as u8);
        resp.extend_from_slice(label.as_bytes());
    }
    resp.push(0);
    resp.extend_from_slice(&1u16.to_be_bytes()); // QTYPE A
    resp.extend_from_slice(&1u16.to_be_bytes()); // QCLASS IN
    resp.extend_from_slice(&0xC00Cu16.to_be_bytes()); // NAME: pointer to offset 12
    resp.extend_from_slice(&1u16.to_be_bytes()); // TYPE A
    resp.extend_from_slice(&1u16.to_be_bytes()); // CLASS IN
    resp.extend_from_slice(&ttl.to_be_bytes());
    resp.extend_from_slice(&4u16.to_be_bytes());
    resp.extend_from_slice(&ip);
    resp
}

#[tokio::test]
async fn test_tun_domain_routing() {
    use gotatun::packet::PacketBufPool;
    use gotatun::tun::{IpRecv, IpSend};
    use std::io::{Read, Write};

    let (endpoint, mut peer) = tun_test_endpoint();
    endpoint.start_dispatcher().expect("dispatcher starts");
    endpoint.set_domain_rule("example.com", "tunnel-b");
    let (mut send_a, mut recv_a) =
        endpoint.attach_tunnel("tunnel-a", vec!["0.0.0.0/0".parse().unwrap()], vec![]);
    let (mut send_b, mut recv_b) =
        endpoint.attach_tunnel("tunnel-b", vec!["0.0.0.0/0".parse().unwrap()], vec![]);
    let mut pool = PacketBufPool::new(8);

    // 1. DNS query for video.example.com goes out through a tunnel.
    let query = crate::netstack::dns::build_query(
        "video.example.com",
        crate::netstack::QueryType::A,
        0x1234,
    )
    .expect("query builds");
    let query_packet = tun_test_udp_packet([10, 0, 0, 2], [1, 1, 1, 1], 12345, 53, &query);
    peer.write_all(&query_packet)
        .expect("write query to TUN fd");
    let got_a = tokio::time::timeout(Duration::from_millis(200), recv_a.recv(&mut pool)).await;
    let got_b = tokio::time::timeout(Duration::from_millis(200), recv_b.recv(&mut pool)).await;
    let (query_sender, query_receiver) = match (got_a, got_b) {
        (Ok(_), Err(_)) => ("tunnel-a", "a"),
        (Err(_), Ok(_)) => ("tunnel-b", "b"),
        _ => panic!("DNS query must arrive on exactly one tunnel"),
    };
    assert_eq!(
        query_receiver, "a",
        "first flow takes tunnel-a under round robin"
    );

    // 2. The answer comes back through the same tunnel and is written
    // into TUN; snooping learns 93.184.216.34 -> video.example.com.
    let answer = tun_test_dns_response(0x1234, "video.example.com", [93, 184, 216, 34], 300);
    let answer_packet = tun_test_udp_packet([1, 1, 1, 1], [10, 0, 0, 2], 53, 12345, &answer);
    let mut raw = pool.get();
    raw.buf_mut().resize(answer_packet.len(), 0);
    raw.buf_mut().copy_from_slice(&answer_packet);
    let packet = raw.try_into_ip().expect("answer parses");
    if query_sender == "tunnel-a" {
        send_a.send(packet).await.expect("answer back to TUN");
    } else {
        send_b.send(packet).await.expect("answer back to TUN");
    }
    peer.set_read_timeout(Some(Duration::from_secs(2)))
        .expect("set read timeout");
    let mut buf = vec![0u8; 512];
    let n = peer.read(&mut buf).expect("read answer from TUN fd");
    assert_eq!(&buf[..n], &answer_packet[..], "answer round-trips into TUN");

    // 3. A new TCP flow to the learned IP must take tunnel-b (the
    // domain rule), not the round-robin pick.
    let flow = tun_test_ipv4_packet([10, 0, 0, 2], [93, 184, 216, 34], 6, 50000, 443);
    peer.write_all(&flow).expect("write flow to TUN fd");
    let got_b = tokio::time::timeout(Duration::from_millis(200), recv_b.recv(&mut pool)).await;
    let got_a = tokio::time::timeout(Duration::from_millis(200), recv_a.recv(&mut pool)).await;
    assert!(got_b.is_ok(), "ruled flow must arrive on tunnel-b");
    assert!(got_a.is_err(), "ruled flow must not arrive on tunnel-a");

    endpoint.shutdown().await;
}

#[tokio::test]
async fn test_tun_dns_snoop_rejects_unbound_answers() {
    use gotatun::packet::PacketBufPool;
    use gotatun::tun::{IpRecv, IpSend};
    use std::io::{Read, Write};

    let (endpoint, mut peer) = tun_test_endpoint();
    endpoint.start_dispatcher().expect("dispatcher starts");
    endpoint.set_domain_rule("example.com", "tunnel-b");
    let (mut send_a, mut recv_a) =
        endpoint.attach_tunnel("tunnel-a", vec!["0.0.0.0/0".parse().unwrap()], vec![]);
    let (_send_b, mut recv_b) =
        endpoint.attach_tunnel("tunnel-b", vec!["0.0.0.0/0".parse().unwrap()], vec![]);
    let mut pool = PacketBufPool::new(8);

    // DNS query for video.example.com to 1.1.1.1.
    let query = crate::netstack::dns::build_query(
        "video.example.com",
        crate::netstack::QueryType::A,
        0x1234,
    )
    .expect("query builds");
    let query_packet = tun_test_udp_packet([10, 0, 0, 2], [1, 1, 1, 1], 12345, 53, &query);
    peer.write_all(&query_packet)
        .expect("write query to TUN fd");
    // The query flow takes tunnel-a (round robin, first pick).
    let got_a = tokio::time::timeout(Duration::from_millis(200), recv_a.recv(&mut pool)).await;
    assert!(got_a.is_ok(), "DNS query must arrive on tunnel-a");
    drop(got_a);

    // Spoof attempt 1: an answer for the same TXID from a server that
    // was never asked (8.8.8.8 instead of 1.1.1.1). It still
    // round-trips into TUN (snooping observes only) but must not be
    // learned.
    let spoof = tun_test_dns_response(0x1234, "video.example.com", [93, 184, 216, 34], 300);
    let spoof_packet = tun_test_udp_packet([8, 8, 8, 8], [10, 0, 0, 2], 53, 12345, &spoof);
    let mut raw = pool.get();
    raw.buf_mut().resize(spoof_packet.len(), 0);
    raw.buf_mut().copy_from_slice(&spoof_packet);
    send_a
        .send(raw.try_into_ip().expect("spoof parses"))
        .await
        .expect("spoof back to TUN");
    peer.set_read_timeout(Some(Duration::from_secs(2)))
        .expect("set read timeout");
    let mut buf = vec![0u8; 512];
    let n = peer.read(&mut buf).expect("read spoof from TUN fd");
    assert_eq!(&buf[..n], &spoof_packet[..], "spoof round-trips into TUN");

    // Spoof attempt 2: an answer from the right server but for a
    // different name (same TXID). Also must not be learned.
    let wrong_q = tun_test_dns_response(0x1234, "other.example.com", [93, 184, 216, 34], 300);
    let wrong_q_packet = tun_test_udp_packet([1, 1, 1, 1], [10, 0, 0, 2], 53, 12345, &wrong_q);
    let mut raw = pool.get();
    raw.buf_mut().resize(wrong_q_packet.len(), 0);
    raw.buf_mut().copy_from_slice(&wrong_q_packet);
    send_a
        .send(raw.try_into_ip().expect("wrong-question parses"))
        .await
        .expect("wrong-question back to TUN");
    let n = peer
        .read(&mut buf)
        .expect("read wrong-question from TUN fd");
    assert_eq!(
        &buf[..n],
        &wrong_q_packet[..],
        "wrong-question round-trips into TUN"
    );

    // Flows to 93.184.216.34 must follow round robin, not the rule:
    // the first takes tunnel-b (second round-robin pick), the second
    // must take tunnel-a. Had either spoof been learned, the rule
    // would pin both flows to tunnel-b.
    let flow1 = tun_test_ipv4_packet([10, 0, 0, 2], [93, 184, 216, 34], 6, 50000, 443);
    peer.write_all(&flow1).expect("write flow 1 to TUN fd");
    let got_b = tokio::time::timeout(Duration::from_millis(200), recv_b.recv(&mut pool)).await;
    assert!(got_b.is_ok(), "flow 1 must arrive on tunnel-b");
    drop(got_b);
    let flow2 = tun_test_ipv4_packet([10, 0, 0, 2], [93, 184, 216, 34], 6, 50001, 443);
    peer.write_all(&flow2).expect("write flow 2 to TUN fd");
    let got_a = tokio::time::timeout(Duration::from_millis(200), recv_a.recv(&mut pool)).await;
    let got_b = tokio::time::timeout(Duration::from_millis(200), recv_b.recv(&mut pool)).await;
    assert!(got_a.is_ok(), "flow 2 must arrive on tunnel-a");
    assert!(
        got_b.is_err(),
        "flow 2 must not be pinned to tunnel-b by an unbound answer"
    );

    endpoint.shutdown().await;
}

#[tokio::test]
async fn test_tun_dns_snoop_rejects_forbidden_learned_ip() {
    use gotatun::packet::PacketBufPool;
    use gotatun::tun::{IpRecv, IpSend};
    use std::io::{Read, Write};

    let (endpoint, mut peer) = tun_test_endpoint();
    endpoint.start_dispatcher().expect("dispatcher starts");
    endpoint.set_domain_rule("example.com", "tunnel-b");
    let (mut send_a, mut recv_a) =
        endpoint.attach_tunnel("tunnel-a", vec!["0.0.0.0/0".parse().unwrap()], vec![]);
    let (_send_b, mut recv_b) =
        endpoint.attach_tunnel("tunnel-b", vec!["0.0.0.0/0".parse().unwrap()], vec![]);
    let mut pool = PacketBufPool::new(8);

    // DNS query for video.example.com to 1.1.1.1.
    let query = crate::netstack::dns::build_query(
        "video.example.com",
        crate::netstack::QueryType::A,
        0x1234,
    )
    .expect("query builds");
    let query_packet = tun_test_udp_packet([10, 0, 0, 2], [1, 1, 1, 1], 12345, 53, &query);
    peer.write_all(&query_packet)
        .expect("write query to TUN fd");
    let got_a = tokio::time::timeout(Duration::from_millis(200), recv_a.recv(&mut pool)).await;
    assert!(got_a.is_ok(), "DNS query must arrive on tunnel-a");
    drop(got_a);

    // Bound answer (right server, right question) but pointing at a
    // private IP: must not be learned as a routing pin.
    let answer = tun_test_dns_response(0x1234, "video.example.com", [10, 0, 0, 99], 300);
    let answer_packet = tun_test_udp_packet([1, 1, 1, 1], [10, 0, 0, 2], 53, 12345, &answer);
    let mut raw = pool.get();
    raw.buf_mut().resize(answer_packet.len(), 0);
    raw.buf_mut().copy_from_slice(&answer_packet);
    send_a
        .send(raw.try_into_ip().expect("answer parses"))
        .await
        .expect("answer back to TUN");
    peer.set_read_timeout(Some(Duration::from_secs(2)))
        .expect("set read timeout");
    let mut buf = vec![0u8; 512];
    let n = peer.read(&mut buf).expect("read answer from TUN fd");
    assert_eq!(&buf[..n], &answer_packet[..], "answer round-trips into TUN");

    // Flows to 10.0.0.99 follow round robin (tunnel-b then
    // tunnel-a); a learned pin would send both to tunnel-b.
    let flow1 = tun_test_ipv4_packet([10, 0, 0, 2], [10, 0, 0, 99], 6, 50000, 443);
    peer.write_all(&flow1).expect("write flow 1 to TUN fd");
    let got_b = tokio::time::timeout(Duration::from_millis(200), recv_b.recv(&mut pool)).await;
    assert!(got_b.is_ok(), "flow 1 must arrive on tunnel-b");
    drop(got_b);
    let flow2 = tun_test_ipv4_packet([10, 0, 0, 2], [10, 0, 0, 99], 6, 50001, 443);
    peer.write_all(&flow2).expect("write flow 2 to TUN fd");
    let got_a = tokio::time::timeout(Duration::from_millis(200), recv_a.recv(&mut pool)).await;
    let got_b = tokio::time::timeout(Duration::from_millis(200), recv_b.recv(&mut pool)).await;
    assert!(got_a.is_ok(), "flow 2 must arrive on tunnel-a");
    assert!(
        got_b.is_err(),
        "flow 2 must not be pinned to tunnel-b by a forbidden learned IP"
    );

    endpoint.shutdown().await;
}

#[test]
fn test_dns_response_synthesis() {
    let query = build_query("example.com", QueryType::A, 0x1234).unwrap();
    let resp = build_response(
        &query,
        &[(IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34)), 300)],
    )
    .unwrap();
    // Question echoed verbatim after the 12-byte header.
    assert_eq!(&resp[12..query.len()], &query[12..]);
    let (ips, ttl) = parse_response(&resp, 0x1234).unwrap();
    assert_eq!(ips, vec![IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34))]);
    assert_eq!(ttl, 300);

    // AAAA answer round-trips the same way.
    let query6 = build_query("ipv6.example.com", QueryType::AAAA, 0xabcd).unwrap();
    let v6: Ipv6Addr = "2606:2800:220:1:248:1893:25c8:1946".parse().unwrap();
    let resp6 = build_response(&query6, &[(IpAddr::V6(v6), 3600)]).unwrap();
    let (ips6, ttl6) = parse_response(&resp6, 0xabcd).unwrap();
    assert_eq!(ips6, vec![IpAddr::V6(v6)]);
    assert_eq!(ttl6, 3600);
}

#[tokio::test]
async fn test_doh_exchange_http() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::{TcpListener, TcpStream};

    let query = build_query("example.com", QueryType::A, 0x4321).unwrap();
    let response_msg = build_response(
        &query,
        &[(IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34)), 300)],
    )
    .unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let expected_body = response_msg.clone();
    let server = tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.unwrap();
        let mut head = Vec::new();
        let mut byte = [0u8; 1];
        while !head.ends_with(b"\r\n\r\n") {
            let n = socket.read(&mut byte).await.unwrap();
            assert_eq!(n, 1, "mock server reads the request");
            head.push(byte[0]);
        }
        let head_text = String::from_utf8_lossy(&head).into_owned();
        assert!(
            head_text.starts_with("POST /dns-query HTTP/1.1\r\n"),
            "DoH request line: {head_text}"
        );
        assert!(
            head_text.contains("Content-Type: application/dns-message\r\n"),
            "DoH content type: {head_text}"
        );
        let len: usize = head_text
            .lines()
            .filter_map(|line| {
                let (name, value) = line.split_once(':')?;
                if name.trim().eq_ignore_ascii_case("Content-Length") {
                    value.trim().parse().ok()
                } else {
                    None
                }
            })
            .next()
            .unwrap();
        let mut body = vec![0u8; len];
        socket.read_exact(&mut body).await.unwrap();
        let response = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/dns-message\r\nContent-Length: {}\r\nConnection: keep-alive\r\n\r\n",
            expected_body.len()
        );
        socket.write_all(response.as_bytes()).await.unwrap();
        socket.write_all(&expected_body).await.unwrap();
        socket.flush().await.unwrap();
    });
    let mut stream = TcpStream::connect(addr).await.unwrap();
    let message = crate::netstack::doh::exchange_http(&mut stream, &query)
        .await
        .expect("DoH exchange succeeds");
    assert_eq!(message, response_msg, "exchange returns the DNS message");
    server.abort();
}

#[tokio::test]
async fn test_doh_tls_failure_is_distinguished_from_transient() {
    use std::future::Future;
    use std::pin::Pin;

    use crate::netstack::doh::{DohClient, DohError, DohTcpConnector};
    use crate::proxy::router::DynStream;

    /// Connector handing the client a stream whose peer is already
    /// gone, so the TLS handshake fails immediately.
    struct DeadStreamConnector;

    impl DohTcpConnector for DeadStreamConnector {
        fn connect(
            &self,
            _dst: std::net::SocketAddr,
        ) -> Pin<Box<dyn Future<Output = std::io::Result<DynStream>> + Send>> {
            Box::pin(async move {
                let (client_side, server_side) = tokio::io::duplex(1024);
                drop(server_side);
                Ok(Box::new(client_side) as DynStream)
            })
        }
    }

    let client = DohClient::new(std::sync::Arc::new(DeadStreamConnector)).unwrap();
    let detailed = client.resolve_detailed("example.com", QueryType::A).await;
    assert!(
        matches!(detailed, Err(DohError::Tls(_))),
        "TLS handshake failure must surface as DohError::Tls, got {detailed:?}"
    );
    // The collapsing `resolve` keeps its old contract (None on any
    // failure); only the detailed path carries the TLS signal.
    assert!(
        client.resolve("example.com", QueryType::A).await.is_none(),
        "plain resolve still collapses failures to None"
    );
}

/// Stub DoH resolver for dispatcher tests: answers example.com A
/// with a canned IP, nothing else.
struct StubDohResolver;

/// Stub DoH resolver that always fails at TLS: the dispatcher must
/// fail closed and never forward the query as plain DNS.
struct TlsFailingResolver;

/// Stub DoH resolver that blocks inside `resolve` until released,
/// counting how many resolutions started: proves the answer-task
/// concurrency bound (no more than `MAX_CONCURRENT_DNS_ANSWERS`
/// tasks start while all permits are held).
struct CountingBlockingResolver {
    count: std::sync::Arc<std::sync::atomic::AtomicUsize>,
    release: std::sync::Arc<tokio::sync::Notify>,
}

impl crate::netstack::tun::DnsResolver for CountingBlockingResolver {
    fn resolve(
        &self,
        _domain: String,
        _qtype: QueryType,
    ) -> crate::netstack::tun::DnsResolveFuture<'_> {
        let count = std::sync::Arc::clone(&self.count);
        let release = std::sync::Arc::clone(&self.release);
        Box::pin(async move {
            count.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            release.notified().await;
            crate::netstack::tun::DnsResolveOutcome::Answered(
                vec![IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34))],
                300,
            )
        })
    }
}

/// Stub DoH resolver that blocks inside `resolve` until released:
/// proves `shutdown` aborts an in-flight answer task instead of
/// letting it write a stale response into TUN afterwards.
struct BlockingResolver {
    entered: std::sync::Arc<std::sync::atomic::AtomicBool>,
    release: std::sync::Arc<tokio::sync::Notify>,
}

impl crate::netstack::tun::DnsResolver for BlockingResolver {
    fn resolve(
        &self,
        _domain: String,
        _qtype: QueryType,
    ) -> crate::netstack::tun::DnsResolveFuture<'_> {
        let entered = std::sync::Arc::clone(&self.entered);
        let release = std::sync::Arc::clone(&self.release);
        Box::pin(async move {
            entered.store(true, std::sync::atomic::Ordering::SeqCst);
            release.notified().await;
            crate::netstack::tun::DnsResolveOutcome::Answered(
                vec![IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34))],
                300,
            )
        })
    }
}

impl crate::netstack::tun::DnsResolver for TlsFailingResolver {
    fn resolve(
        &self,
        _domain: String,
        _qtype: QueryType,
    ) -> crate::netstack::tun::DnsResolveFuture<'_> {
        Box::pin(async move { crate::netstack::tun::DnsResolveOutcome::TlsFailed })
    }
}

impl crate::netstack::tun::DnsResolver for StubDohResolver {
    fn resolve(
        &self,
        domain: String,
        qtype: QueryType,
    ) -> crate::netstack::tun::DnsResolveFuture<'_> {
        Box::pin(async move {
            if domain == "example.com" && qtype == QueryType::A {
                crate::netstack::tun::DnsResolveOutcome::Answered(
                    vec![IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34))],
                    300,
                )
            } else {
                crate::netstack::tun::DnsResolveOutcome::Unavailable
            }
        })
    }
}

#[tokio::test]
async fn test_tun_doh_answers_query() {
    use gotatun::packet::PacketBufPool;
    use gotatun::tun::IpRecv;
    use std::io::{Read, Write};

    let (endpoint, mut peer) = tun_test_endpoint();
    endpoint.start_dispatcher().expect("dispatcher starts");
    endpoint.set_dns_resolver(Some(std::sync::Arc::new(StubDohResolver)));
    let (_send_a, mut recv_a) =
        endpoint.attach_tunnel("tunnel-a", vec!["0.0.0.0/0".parse().unwrap()], vec![]);
    let (_send_b, mut recv_b) =
        endpoint.attach_tunnel("tunnel-b", vec!["0.0.0.0/0".parse().unwrap()], vec![]);

    let query = build_query("example.com", QueryType::A, 0x2222).unwrap();
    let query_packet = tun_test_udp_packet([10, 0, 0, 2], [1, 1, 1, 1], 12345, 53, &query);
    peer.write_all(&query_packet)
        .expect("write query to TUN fd");
    // The blocking read below would starve the current-thread
    // runtime, so let the dispatcher and the answer task run first.
    tokio::time::sleep(Duration::from_millis(300)).await;
    peer.set_read_timeout(Some(Duration::from_secs(2)))
        .expect("set read timeout");
    let mut buf = vec![0u8; 512];
    let n = peer.read(&mut buf).expect("read answer from TUN fd");
    let answer_packet = &buf[..n];
    // Response comes back from the DNS server to the phone, same ports.
    let key = crate::netstack::parse_flow_key(answer_packet).expect("answer parses");
    assert_eq!(key.src, IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)));
    assert_eq!(key.dst, IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)));
    assert_eq!(key.src_port, 53);
    assert_eq!(key.dst_port, 12345);
    let (ips, ttl) = parse_response(&answer_packet[28..], 0x2222).unwrap();
    assert_eq!(ips, vec![IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34))]);
    assert_eq!(ttl, 300);
    // The query never entered a tunnel.
    let mut pool = PacketBufPool::new(8);
    assert!(
        tokio::time::timeout(Duration::from_millis(200), recv_a.recv(&mut pool))
            .await
            .is_err(),
        "answered query must not reach tunnel-a"
    );
    assert!(
        tokio::time::timeout(Duration::from_millis(200), recv_b.recv(&mut pool))
            .await
            .is_err(),
        "answered query must not reach tunnel-b"
    );

    endpoint.shutdown().await;
}

#[tokio::test]
async fn test_tun_doh_tls_failure_fails_closed() {
    use gotatun::packet::PacketBufPool;
    use gotatun::tun::IpRecv;
    use std::io::{Read, Write};

    let (endpoint, mut peer) = tun_test_endpoint();
    endpoint.start_dispatcher().expect("dispatcher starts");
    endpoint.set_dns_resolver(Some(std::sync::Arc::new(TlsFailingResolver)));
    let (_send_a, mut recv_a) =
        endpoint.attach_tunnel("tunnel-a", vec!["0.0.0.0/0".parse().unwrap()], vec![]);
    let (_send_b, mut recv_b) =
        endpoint.attach_tunnel("tunnel-b", vec!["0.0.0.0/0".parse().unwrap()], vec![]);

    let query = build_query("example.com", QueryType::A, 0x2223).unwrap();
    let query_packet = tun_test_udp_packet([10, 0, 0, 2], [1, 1, 1, 1], 12345, 53, &query);
    peer.write_all(&query_packet)
        .expect("write query to TUN fd");
    // Let the dispatcher and the answer task run first.
    tokio::time::sleep(Duration::from_millis(300)).await;

    // The query must NOT be forwarded to any tunnel (no plaintext
    // downgrade on a TLS failure).
    let mut pool = PacketBufPool::new(8);
    assert!(
        tokio::time::timeout(Duration::from_millis(200), recv_a.recv(&mut pool))
            .await
            .is_err(),
        "TLS-failed query must not reach tunnel-a"
    );
    assert!(
        tokio::time::timeout(Duration::from_millis(200), recv_b.recv(&mut pool))
            .await
            .is_err(),
        "TLS-failed query must not reach tunnel-b"
    );
    // And no synthesized answer is written back into TUN either.
    peer.set_read_timeout(Some(Duration::from_millis(200)))
        .expect("set read timeout");
    let mut buf = vec![0u8; 512];
    let read = peer.read(&mut buf);
    assert!(
        read.is_err(),
        "TLS-failed query must not produce a TUN answer, got {read:?}"
    );

    endpoint.shutdown().await;
}

#[tokio::test]
async fn test_tun_doh_answer_task_aborted_on_shutdown() {
    use std::io::{Read, Write};

    let entered = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let release = std::sync::Arc::new(tokio::sync::Notify::new());
    let resolver = BlockingResolver {
        entered: std::sync::Arc::clone(&entered),
        release: std::sync::Arc::clone(&release),
    };
    let (endpoint, mut peer) = tun_test_endpoint();
    endpoint.start_dispatcher().expect("dispatcher starts");
    endpoint.set_dns_resolver(Some(std::sync::Arc::new(resolver)));
    let (_send_a, _recv_a) =
        endpoint.attach_tunnel("tunnel-a", vec!["0.0.0.0/0".parse().unwrap()], vec![]);

    let query = build_query("example.com", QueryType::A, 0x2224).unwrap();
    let query_packet = tun_test_udp_packet([10, 0, 0, 2], [1, 1, 1, 1], 12345, 53, &query);
    peer.write_all(&query_packet)
        .expect("write query to TUN fd");

    // Wait until the answer task has entered the (blocked) resolve.
    let started = tokio::time::timeout(Duration::from_secs(2), async {
        while !entered.load(std::sync::atomic::Ordering::SeqCst) {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await;
    assert!(started.is_ok(), "answer task must start resolving");

    // Shutdown must return promptly even though the resolve is still
    // blocked: the answer task is aborted, not awaited.
    tokio::time::timeout(Duration::from_secs(2), endpoint.shutdown())
        .await
        .expect("shutdown must not hang on a blocked DNS answer task");

    // Release the resolver: a detached task would now answer into TUN.
    release.notify_waiters();
    tokio::time::sleep(Duration::from_millis(300)).await;
    peer.set_read_timeout(Some(Duration::from_millis(200)))
        .expect("set read timeout");
    let mut buf = vec![0u8; 512];
    let read = peer.read(&mut buf);
    assert!(
        read.is_err(),
        "aborted answer task must not write a stale response into TUN after shutdown, got {read:?}"
    );
}

#[tokio::test]
async fn test_tun_doh_answer_concurrency_bounded() {
    use gotatun::packet::PacketBufPool;
    use gotatun::tun::IpRecv;
    use std::io::Write;

    // 32 is `MAX_CONCURRENT_DNS_ANSWERS` in tun.rs; keep in sync.
    const ANSWER_LIMIT: usize = 32;
    let count = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let release = std::sync::Arc::new(tokio::sync::Notify::new());
    let resolver = CountingBlockingResolver {
        count: std::sync::Arc::clone(&count),
        release: std::sync::Arc::clone(&release),
    };
    let (endpoint, mut peer) = tun_test_endpoint();
    endpoint.start_dispatcher().expect("dispatcher starts");
    endpoint.set_dns_resolver(Some(std::sync::Arc::new(resolver)));
    let (_send_a, mut recv_a) =
        endpoint.attach_tunnel("tunnel-a", vec!["0.0.0.0/0".parse().unwrap()], vec![]);
    let mut pool = PacketBufPool::new(8);

    // Fill every answer slot with a blocked resolution. Each write
    // waits until its answer task has started: the test TUN fd is a
    // stream socket, so a burst of writes can coalesce into one read
    // and lose packets.
    for i in 0..ANSWER_LIMIT as u16 {
        let query = build_query("example.com", QueryType::A, 0x3000 + i).unwrap();
        let query_packet = tun_test_udp_packet([10, 0, 0, 2], [1, 1, 1, 1], 12345 + i, 53, &query);
        peer.write_all(&query_packet)
            .expect("write query to TUN fd");
        let started = tokio::time::timeout(Duration::from_secs(2), async {
            while count.load(std::sync::atomic::Ordering::SeqCst) < usize::from(i) + 1 {
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await;
        assert!(started.is_ok(), "answer task {i} must start");
    }

    // One more query: no permit is left, so it must fall through to
    // normal routing instead of spawning a 33rd task.
    let query = build_query("example.com", QueryType::A, 0x4000).unwrap();
    let query_packet = tun_test_udp_packet([10, 0, 0, 2], [1, 1, 1, 1], 12400, 53, &query);
    peer.write_all(&query_packet)
        .expect("write overflow query to TUN fd");
    assert!(
        tokio::time::timeout(Duration::from_millis(500), recv_a.recv(&mut pool))
            .await
            .is_ok(),
        "query past the answer limit must route through the tunnel instead of spawning"
    );
    assert_eq!(
        count.load(std::sync::atomic::Ordering::SeqCst),
        ANSWER_LIMIT,
        "no 33rd answer task may start while all permits are held"
    );

    endpoint.shutdown().await;
}

#[tokio::test]
async fn test_tun_doh_forwards_other_types_and_failures() {
    use gotatun::packet::PacketBufPool;
    use gotatun::tun::IpRecv;
    use std::io::Write;

    let (endpoint, mut peer) = tun_test_endpoint();
    endpoint.start_dispatcher().expect("dispatcher starts");
    endpoint.set_dns_resolver(Some(std::sync::Arc::new(StubDohResolver)));
    let (_send_a, mut recv_a) =
        endpoint.attach_tunnel("tunnel-a", vec!["0.0.0.0/0".parse().unwrap()], vec![]);
    let (_send_b, mut recv_b) =
        endpoint.attach_tunnel("tunnel-b", vec!["0.0.0.0/0".parse().unwrap()], vec![]);
    let mut pool = PacketBufPool::new(8);

    // MX query: not A/AAAA, so it forwards through the tunnel.
    let mut mx = build_query("example.com", QueryType::A, 0x3333).unwrap();
    let qtype_at = mx.len() - 4;
    mx[qtype_at..qtype_at + 2].copy_from_slice(&15u16.to_be_bytes());
    let mx_packet = tun_test_udp_packet([10, 0, 0, 2], [1, 1, 1, 1], 12346, 53, &mx);
    peer.write_all(&mx_packet)
        .expect("write MX query to TUN fd");
    assert!(
        tokio::time::timeout(Duration::from_millis(500), recv_a.recv(&mut pool))
            .await
            .is_ok(),
        "MX query must forward to a tunnel"
    );

    // A query the resolver cannot answer: forwarded, not dropped.
    let other = build_query("other.com", QueryType::A, 0x4444).unwrap();
    let other_packet = tun_test_udp_packet([10, 0, 0, 2], [1, 1, 1, 1], 12347, 53, &other);
    peer.write_all(&other_packet)
        .expect("write other query to TUN fd");
    let got_a = tokio::time::timeout(Duration::from_millis(500), recv_a.recv(&mut pool)).await;
    let got_b = tokio::time::timeout(Duration::from_millis(500), recv_b.recv(&mut pool)).await;
    assert!(
        got_a.is_ok() || got_b.is_ok(),
        "unanswered query must forward to a tunnel"
    );

    endpoint.shutdown().await;
}

#[tokio::test]
async fn test_tun_drops_local_destinations() {
    use gotatun::packet::PacketBufPool;
    use gotatun::tun::IpRecv;
    use std::io::Write;

    let (endpoint, mut peer) = tun_test_endpoint();
    endpoint.start_dispatcher().expect("dispatcher starts");
    // AllowedIPs 0.0.0.0/0 would match every IPv4 destination, so
    // without the local-destination drop these packets would queue.
    let (_send_a, mut recv_a) =
        endpoint.attach_tunnel("tunnel-a", vec!["0.0.0.0/0".parse().unwrap()], vec![]);
    let mut pool = PacketBufPool::new(8);

    // mDNS multicast, link-local, broadcast, unspecified.
    // The TUN side is a byte-stream socketpair, so consecutive writes
    // can coalesce into one read (and the tail would be ignored):
    // pause between writes so the dispatcher reads one packet each.
    for dst in [
        [224, 0, 0, 251],
        [169, 254, 1, 1],
        [255, 255, 255, 255],
        [0, 0, 0, 0],
    ] {
        let packet = tun_test_udp_packet([10, 0, 0, 2], dst, 12345, 5353, &[]);
        peer.write_all(&packet)
            .expect("write local packet to TUN fd");
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    // Wait until all four are counted (or time out and fail below).
    let deadline = tokio::time::Instant::now() + Duration::from_secs(2);
    while endpoint.stats_snapshot().packets_dropped_local < 4
        && tokio::time::Instant::now() < deadline
    {
        tokio::time::sleep(Duration::from_millis(50)).await;
    }

    let snapshot = endpoint.stats_snapshot();
    assert_eq!(snapshot.packets_dropped_local, 4);
    assert_eq!(snapshot.packets_no_route, 0);
    assert_eq!(snapshot.packets_queued, 0);
    assert!(
        tokio::time::timeout(Duration::from_millis(200), recv_a.recv(&mut pool))
            .await
            .is_err(),
        "local packets must not reach a tunnel"
    );

    endpoint.shutdown().await;
}
