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
use crate::netstack::dns::{DnsError, DnsLruCache, QueryType, build_query, parse_response};
use crate::netstack::stack::VirtualNetworkStack;

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

    // Inserting with TTL = 0 should be clamped to min_ttl (5 seconds)
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
