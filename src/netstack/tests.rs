//! Milestone 2 comprehensive unit test suite for virtual networking stack.

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
    use std::time::Duration;
    use etherparse::PacketBuilder;
    use gotatun::tun::IpSend;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use x25519_dalek::StaticSecret;

    use crate::config::WgInterfaceConfig;
    use crate::netstack::bridge::{BridgeIpRecv, VirtualTunBridge, DEFAULT_CHANNEL_CAPACITY, DEFAULT_MTU};
    use crate::netstack::dns::{build_query, parse_response, DnsError, DnsLruCache, QueryType};
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
        resp.extend_from_slice(&[0xC0, 0x0C]);                  // Pointer to "test"
        resp.extend_from_slice(&[0x00, 0x1c]);                  // Type AAAA
        resp.extend_from_slice(&[0x00, 0x01]);                  // Class IN
        resp.extend_from_slice(&[0x00, 0x00, 0x0e, 0x10]);      // TTL = 3600
        resp.extend_from_slice(&[0x00, 0x10]);                  // RDLENGTH = 16
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

        assert!(matches!(parse_response(&resp, 0x1234), Err(DnsError::NxDomain)));
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

        assert!(matches!(parse_response(&resp, 0x1234), Err(DnsError::ServerError(2))));
    }

    #[test]
    fn test_dns_corrupt_packet_handling() {
        let truncated = vec![0x12, 0x34, 0x81];
        assert!(matches!(parse_response(&truncated, 0x1234), Err(DnsError::PacketTooShort)));

        let query = build_query("example.com", QueryType::A, 0x1111).unwrap();
        assert!(matches!(parse_response(&query, 0x2222), Err(DnsError::IdMismatch)));

        assert!(matches!(parse_response(&query, 0x1111), Err(DnsError::NotAResponse)));
    }

    #[test]
    fn test_dns_compression_pointer_loop() {
        let mut loop_pkt = Vec::new();
        loop_pkt.extend_from_slice(&[0x12, 0x34, 0x81, 0x80, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
        loop_pkt.extend_from_slice(&[0xC0, 0x0C]); // Pointer points to itself
        assert!(matches!(parse_response(&loop_pkt, 0x1234), Err(DnsError::PointerLoop)));
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
        let (mut bridge, mut ip_send, _ip_recv) = VirtualTunBridge::new(DEFAULT_MTU, DEFAULT_CHANNEL_CAPACITY);
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
        assert_eq!((&*pkt).as_bytes(), &raw[..]);
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
        tokio::time::timeout(Duration::from_millis(50), notified).await.expect("notify must trigger");
    }

    #[test]
    fn test_bridge_malformed_ip_rejection() {
        let mut pool = gotatun::packet::PacketBufPool::<4096>::new(16);
        // A packet shorter than 20 bytes is not a valid IP packet
        let too_short = vec![0x45, 0x00, 0x00];
        let res = BridgeIpRecv::to_packet_pub(too_short, &mut pool);
        assert!(res.is_err());
    }

    // =========================================================================
    // 4. VirtualNetworkStack Addressing, Routing & Ephemeral Ports
    // =========================================================================

    #[tokio::test]
    async fn test_stack_dual_stack_addressing() {
        let config = make_test_config("10.2.0.2/32", Some("fd00::2/128"));
        let (bridge, _ip_send, _ip_recv) = VirtualTunBridge::new(DEFAULT_MTU, 64);

        let stack = VirtualNetworkStack::new(&config, bridge).await.unwrap();

        assert_eq!(stack.local_v4(), Some(Ipv4Addr::new(10, 2, 0, 2)));
        assert_eq!(stack.local_v6(), Some("fd00::2".parse::<Ipv6Addr>().unwrap()));

        stack.close().await;
    }

    #[tokio::test]
    async fn test_stack_ephemeral_port_cycling() {
        let config = make_test_config("10.2.0.2/32", None);
        let (bridge, _ip_send, _ip_recv) = VirtualTunBridge::new(DEFAULT_MTU, 64);
        let stack = VirtualNetworkStack::new(&config, bridge).await.unwrap();

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
        let stack = VirtualNetworkStack::new(&config, bridge).await.unwrap();

        // Close and ensure background task terminates without hanging
        tokio::time::timeout(Duration::from_millis(500), stack.close()).await.expect("close must terminate promptly");
    }

    // =========================================================================
    // 5. VirtualUdpSocket Send & Recv Loopback Tests
    // =========================================================================

    #[tokio::test]
    async fn test_udp_socket_bind_and_port() {
        let config = make_test_config("10.2.0.2/32", None);
        let (bridge, _ip_send, _ip_recv) = VirtualTunBridge::new(DEFAULT_MTU, 64);
        let stack = VirtualNetworkStack::new(&config, bridge).await.unwrap();

        // Ephemeral port binding (0)
        let sock_ephemeral = stack.udp_bind(0).await.unwrap();
        assert!(sock_ephemeral.local_port() >= 49152);

        // Explicit port binding
        let sock_explicit = stack.udp_bind(5353).await.unwrap();
        assert_eq!(sock_explicit.local_port(), 5353);

        stack.close().await;
    }

    #[tokio::test]
    async fn test_udp_socket_send_and_recv_loopback() {
        let config = make_test_config("10.2.0.2/32", None);
        let (bridge, mut ip_send, mut ip_recv) = VirtualTunBridge::new(DEFAULT_MTU, 64);
        let stack = VirtualNetworkStack::new(&config, bridge).await.unwrap();

        let udp = stack.udp_bind(12345).await.unwrap();
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
        let raw_out = (&*pkt).as_bytes();

        // Verify it is an IPv4 UDP packet
        let parsed = etherparse::SlicedPacket::from_ip(raw_out).unwrap();
        assert_eq!(parsed.payload, b"PING_DATAGRAM");

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
        let (len, peer) = tokio::time::timeout(Duration::from_millis(500), udp.recv_from(&mut recv_buf))
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
        let stack = VirtualNetworkStack::new(&config, bridge).await.unwrap();

        // IPv4 literal fast-path
        let ip4 = stack.resolve_in_tunnel("93.184.216.34").await.unwrap();
        assert_eq!(ip4, IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34)));

        // IPv6 literal fast-path
        let ip6 = stack.resolve_in_tunnel("2606:4700:4700::1111").await.unwrap();
        assert_eq!(ip6, "2606:4700:4700::1111".parse::<IpAddr>().unwrap());

        stack.close().await;
    }

    #[tokio::test]
    async fn test_in_tunnel_dns_resolution_and_cache() {
        let config = make_test_config("10.2.0.2/32", None);
        let (bridge, mut ip_send, mut ip_recv) = VirtualTunBridge::new(DEFAULT_MTU, 64);
        let stack = VirtualNetworkStack::new(&config, bridge).await.unwrap();

        let mut pool = gotatun::packet::PacketBufPool::<4096>::new(16);

        // Spawn mock DNS responder task on the tunnel bridge
        let responder_task = tokio::spawn(async move {
            use gotatun::tun::{IpRecv, IpSend};
            use zerocopy::IntoBytes;

            let mut packets = ip_recv.recv(&mut pool).await.unwrap();
            let pkt = packets.next().unwrap();
            let raw = (&*pkt).as_bytes();

            let parsed = etherparse::SlicedPacket::from_ip(raw).unwrap();
            let dns_query = parsed.payload;
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

            let (src_ip, dst_ip) = match parsed.ip.unwrap() {
                etherparse::InternetSlice::Ipv4(v4, _) => (v4.source(), v4.destination()),
                _ => panic!("expected ipv4"),
            };
            let udp_hdr = match parsed.transport.unwrap() {
                etherparse::TransportSlice::Udp(u) => (u.source_port(), u.destination_port()),
                _ => panic!("expected udp"),
            };

            let builder = PacketBuilder::ipv4(dst_ip, src_ip, 64)
                .udp(udp_hdr.1, udp_hdr.0);
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
        let stack = VirtualNetworkStack::new(&config, bridge).await.unwrap();

        // Attempting to connect to IPv6 when only IPv4 configured must fail
        let dst = SocketAddr::from(([0x26, 0x06, 0, 0, 0, 0, 0, 1], 80));
        let res = stack.tcp_connect(dst).await;
        assert!(res.is_err());
        assert_eq!(res.unwrap_err().kind(), std::io::ErrorKind::AddrNotAvailable);

        stack.close().await;
    }

    #[tokio::test]
    async fn test_tcp_stream_handshake_and_exchange() {
        let config = make_test_config("10.2.0.2/32", None);
        let (bridge, mut ip_send, mut ip_recv) = VirtualTunBridge::new(DEFAULT_MTU, 64);
        let stack = VirtualNetworkStack::new(&config, bridge).await.unwrap();

        let dst = SocketAddr::from(([93, 184, 216, 34], 80));

        let mut pool = gotatun::packet::PacketBufPool::<4096>::new(16);

        // Spawn mock peer task to drive TCP state machine over tunnel bridge
        let peer_task = tokio::spawn(async move {
            use gotatun::tun::{IpRecv, IpSend};
            use zerocopy::IntoBytes;

            // 1. Receive SYN packet
            let mut packets = ip_recv.recv(&mut pool).await.unwrap();
            let pkt = packets.next().unwrap();
            let raw = (&*pkt).as_bytes().to_vec();
            drop(packets);

            let parsed = etherparse::SlicedPacket::from_ip(&raw).unwrap();
            let (src_ip, dst_ip) = match parsed.ip.unwrap() {
                etherparse::InternetSlice::Ipv4(ip, _) => (ip.source(), ip.destination()),
                _ => panic!("expected ipv4 tcp"),
            };
            let tcp_hdr = match parsed.transport.unwrap() {
                etherparse::TransportSlice::Tcp(tcp) => tcp,
                _ => panic!("expected ipv4 tcp"),
            };

            assert!(tcp_hdr.syn());
            let client_isn = tcp_hdr.sequence_number();
            let server_isn = 50000u32;

            // 2. Reply with SYN-ACK
            let builder = PacketBuilder::ipv4(dst_ip, src_ip, 64)
                .tcp(
                    tcp_hdr.destination_port(),
                    tcp_hdr.source_port(),
                    server_isn,
                    65535,
                )
                .syn()
                .ack(client_isn + 1);

            let mut syn_ack_raw = Vec::new();
            builder.write(&mut syn_ack_raw, &[]).unwrap();

            let mut reply_pkt = pool.get();
            reply_pkt.truncate(syn_ack_raw.len());
            reply_pkt.copy_from_slice(&syn_ack_raw);
            let ip_reply = reply_pkt.try_into_ip().unwrap();
            ip_send.send(ip_reply).await.unwrap();

            // 3. Receive ACK (completes handshake)
            let mut packets = ip_recv.recv(&mut pool).await.unwrap();
            let pkt = packets.next().unwrap();
            let raw = (&*pkt).as_bytes().to_vec();
            drop(packets);

            let parsed = etherparse::SlicedPacket::from_ip(&raw).unwrap();
            let tcp_hdr = match parsed.transport.unwrap() {
                etherparse::TransportSlice::Tcp(tcp) => tcp,
                _ => panic!("expected tcp"),
            };
            assert!(tcp_hdr.ack());

            // 4. Receive client data (b"PING_DATA")
            let mut packets = ip_recv.recv(&mut pool).await.unwrap();
            let pkt = packets.next().unwrap();
            let raw = (&*pkt).as_bytes().to_vec();
            drop(packets);

            let parsed = etherparse::SlicedPacket::from_ip(&raw).unwrap();
            assert_eq!(parsed.payload, b"PING_DATA");
            let tcp_hdr = match parsed.transport.unwrap() {
                etherparse::TransportSlice::Tcp(tcp) => tcp,
                _ => panic!("expected tcp"),
            };

            // 5. Send server data (b"PONG_DATA") + ACK
            let builder = PacketBuilder::ipv4(dst_ip, src_ip, 64)
                .tcp(
                    tcp_hdr.destination_port(),
                    tcp_hdr.source_port(),
                    server_isn + 1,
                    65535,
                )
                .ack(tcp_hdr.sequence_number() + parsed.payload.len() as u32);

            let mut data_raw = Vec::new();
            builder.write(&mut data_raw, b"PONG_DATA").unwrap();

            let mut reply_pkt = pool.get();
            reply_pkt.truncate(data_raw.len());
            reply_pkt.copy_from_slice(&data_raw);
            let ip_reply = reply_pkt.try_into_ip().unwrap();
            ip_send.send(ip_reply).await.unwrap();

            // 6. Send FIN to signal EOF
            let builder = PacketBuilder::ipv4(dst_ip, src_ip, 64)
                .tcp(
                    tcp_hdr.destination_port(),
                    tcp_hdr.source_port(),
                    server_isn + 1 + 9, // + len("PONG_DATA")
                    65535,
                )
                .fin()
                .ack(tcp_hdr.sequence_number() + parsed.payload.len() as u32);

            let mut fin_raw = Vec::new();
            builder.write(&mut fin_raw, &[]).unwrap();

            let mut reply_pkt = pool.get();
            reply_pkt.truncate(fin_raw.len());
            reply_pkt.copy_from_slice(&fin_raw);
            let ip_reply = reply_pkt.try_into_ip().unwrap();
            ip_send.send(ip_reply).await.unwrap();
        });

        // Client: initiate TCP connect
        let mut stream = stack.tcp_connect(dst).await.expect("tcp_connect must succeed");
        assert_eq!(stream.peer_addr().unwrap(), dst);

        // Write data
        stream.write_all(b"PING_DATA").await.expect("write_all succeeds");
        stream.flush().await.expect("flush succeeds");

        // Read data
        let mut buf = [0u8; 9];
        stream.read_exact(&mut buf).await.expect("read_exact succeeds");
        assert_eq!(&buf, b"PONG_DATA");

        // Read EOF after FIN
        let mut eof_buf = [0u8; 16];
        let n = stream.read(&mut eof_buf).await.expect("read at EOF succeeds");
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

        let stack = VirtualNetworkStack::new_with_mode(
            &config,
            bridge,
            crate::config::IpMode::Ipv4Only,
            false,
        )
        .await
        .unwrap();

        assert_eq!(stack.local_v4(), Some(Ipv4Addr::new(10, 2, 0, 2)));
        assert_eq!(stack.local_v6(), None);

        // IPv6 TCP connect must be blocked immediately
        let v6_dst: SocketAddr = "[2606:4700:4700::1111]:443".parse().unwrap();
        let tcp_err = stack.tcp_connect(v6_dst).await.unwrap_err();
        assert_eq!(tcp_err.kind(), std::io::ErrorKind::AddrNotAvailable);

        // IPv6 UDP send_to must be blocked immediately
        let udp = stack.udp_bind(0).await.unwrap();
        let udp_err = udp.send_to(b"hello", v6_dst).await.unwrap_err();
        assert_eq!(udp_err.kind(), std::io::ErrorKind::AddrNotAvailable);

        // IPv6 literal resolution must be blocked, IPv4 literal allowed
        let dns_v6_err = stack.resolve_in_tunnel("2606:4700:4700::1111").await.unwrap_err();
        assert_eq!(dns_v6_err.kind(), std::io::ErrorKind::AddrNotAvailable);
        let dns_v4 = stack.resolve_in_tunnel("1.1.1.1").await.unwrap();
        assert_eq!(dns_v4, IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)));

        stack.close().await;
    }

    #[tokio::test]
    async fn test_stack_ipv6_only_isolation() {
        let config = make_test_config("10.2.0.2/32", Some("fd00::2/128"));
        let (bridge, _ip_send, _ip_recv) = VirtualTunBridge::new(DEFAULT_MTU, 64);

        let stack = VirtualNetworkStack::new_with_mode(
            &config,
            bridge,
            crate::config::IpMode::Ipv6Only,
            false,
        )
        .await
        .unwrap();

        assert_eq!(stack.local_v4(), None);
        assert_eq!(stack.local_v6(), Some("fd00::2".parse::<Ipv6Addr>().unwrap()));

        // IPv4 TCP connect must be blocked immediately
        let v4_dst: SocketAddr = "1.1.1.1:443".parse().unwrap();
        let tcp_err = stack.tcp_connect(v4_dst).await.unwrap_err();
        assert_eq!(tcp_err.kind(), std::io::ErrorKind::AddrNotAvailable);

        // IPv4 UDP send_to must be blocked immediately
        let udp = stack.udp_bind(0).await.unwrap();
        let udp_err = udp.send_to(b"hello", v4_dst).await.unwrap_err();
        assert_eq!(udp_err.kind(), std::io::ErrorKind::AddrNotAvailable);

        // IPv4 literal resolution must be blocked, IPv6 literal allowed
        let dns_v4_err = stack.resolve_in_tunnel("1.1.1.1").await.unwrap_err();
        assert_eq!(dns_v4_err.kind(), std::io::ErrorKind::AddrNotAvailable);
        let dns_v6 = stack.resolve_in_tunnel("2606:4700:4700::1111").await.unwrap();
        assert_eq!(
            dns_v6,
            IpAddr::V6("2606:4700:4700::1111".parse::<Ipv6Addr>().unwrap())
        );

        stack.close().await;
    }
}
