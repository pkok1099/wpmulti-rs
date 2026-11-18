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

use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::Duration;

use common::{
    AdminTestClient, HttpProxyTestClient, MockWireGuardPeer, SharedListenerFixture, Socks5Target,
    Socks5TestClient, TestEnvironment, WgConfBuilder, WgPeerFixture, WpMultiTomlBuilder,
    allocate_ephemeral_port, allocate_ephemeral_port_range, generate_245_cloned_wgcf_configs,
};
use etherparse::PacketBuilder;
use gotatun::{
    noise::{Tunn, TunnResult, index_table::IndexTable, rate_limiter::RateLimiter},
    packet::{Packet, WgKind},
    x25519,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, UdpSocket};
use zerocopy::IntoBytes;

// -----------------------------------------------------------------------------
// Test 1: Mock WireGuard Peer — Noise IK Handshake & L3 IP Engine
// -----------------------------------------------------------------------------

async fn perform_mock_handshake(
    client_tunn: &mut Tunn,
    client_socket: &UdpSocket,
    peer_endpoint: SocketAddr,
) {
    let init = client_tunn
        .format_handshake_initiation(false)
        .expect("Failed to format handshake initiation");
    let init_bytes = (*init).as_bytes();
    client_socket
        .send_to(init_bytes, peer_endpoint)
        .await
        .expect("Failed to send handshake init");

    let mut resp_buf = vec![0u8; 1500];
    let (n, _) = client_socket
        .recv_from(&mut resp_buf)
        .await
        .expect("Failed to receive handshake resp");
    let resp_packet = Packet::copy_from(&resp_buf[..n])
        .try_into_wg()
        .expect("Failed to parse WG packet");

    if let TunnResult::WriteToNetwork(pkt) = client_tunn.handle_incoming_packet(resp_packet) {
        let keepalive_bytes = match pkt {
            WgKind::Data(d) => d.into_bytes().as_ref().to_vec(),
            _ => panic!("Expected Data/Keepalive packet from client"),
        };
        client_socket
            .send_to(&keepalive_bytes, peer_endpoint)
            .await
            .expect("Failed to send keepalive");
    }
}

async fn exchange_tunnel_packet(
    client_tunn: &mut Tunn,
    client_socket: &UdpSocket,
    peer_endpoint: SocketAddr,
    ip_packet: &[u8],
) -> Vec<u8> {
    let encap = client_tunn
        .encapsulate_with_session(Packet::copy_from(ip_packet))
        .expect("Failed to encapsulate IP packet");
    let encap_bytes = encap.into_bytes();
    client_socket
        .send_to(encap_bytes.as_ref(), peer_endpoint)
        .await
        .expect("Failed to send encap packet");

    let mut resp_buf = vec![0u8; 1500];
    let (n, _) = client_socket
        .recv_from(&mut resp_buf)
        .await
        .expect("Failed to receive echo response");
    let resp_wg = Packet::copy_from(&resp_buf[..n])
        .try_into_wg()
        .expect("Failed to parse WG response");

    match client_tunn.handle_incoming_packet(resp_wg) {
        TunnResult::WriteToTunnel(decrypted_ip) => decrypted_ip.as_ref().to_vec(),
        other => panic!("Expected WriteToTunnel, got {:?}", other),
    }
}

fn build_example_dns_query(tx_id: u16) -> Vec<u8> {
    let mut dns_query = Vec::new();
    dns_query.extend_from_slice(&tx_id.to_be_bytes());
    dns_query.extend_from_slice(&0x0100u16.to_be_bytes());
    dns_query.extend_from_slice(&1u16.to_be_bytes());
    dns_query.extend_from_slice(&0u16.to_be_bytes());
    dns_query.extend_from_slice(&0u16.to_be_bytes());
    dns_query.extend_from_slice(&0u16.to_be_bytes());
    dns_query.extend_from_slice(b"\x07example\x03com\x00");
    dns_query.extend_from_slice(&1u16.to_be_bytes());
    dns_query.extend_from_slice(&1u16.to_be_bytes());
    dns_query
}

async fn verify_mock_udp_and_dns(
    client_tunn: &mut Tunn,
    client_socket: &UdpSocket,
    peer_endpoint: SocketAddr,
    mock: &MockWireGuardPeer,
) {
    let client_ipv4 = Ipv4Addr::new(10, 0, 0, 2);
    let server_ipv4 = Ipv4Addr::new(10, 0, 0, 1);

    // In-Tunnel UDP Echo
    let echo_payload = b"test_wireguard_udp_echo_payload";
    let mut udp_pkt_buf = Vec::new();
    let b = PacketBuilder::ipv4(client_ipv4.octets(), server_ipv4.octets(), 64).udp(12345, 9999);
    udp_pkt_buf.reserve(b.size(echo_payload.len()));
    b.write(&mut udp_pkt_buf, echo_payload)
        .expect("Failed to build UDP packet");

    let decrypted_udp =
        exchange_tunnel_packet(client_tunn, client_socket, peer_endpoint, &udp_pkt_buf).await;
    let sliced = etherparse::SlicedPacket::from_ip(&decrypted_udp)
        .expect("Failed to slice decrypted IP packet");
    let Some(etherparse::TransportSlice::Udp(udp)) = sliced.transport else {
        panic!("Expected UDP transport");
    };
    assert_eq!(udp.payload(), echo_payload);
    assert!(mock.stats().udp_echo_packets.load(Ordering::SeqCst) >= 1);
    assert!(mock.stats().ipv4_packets.load(Ordering::SeqCst) >= 1);

    // In-Tunnel RFC 1035 UDP DNS Query on Port 53
    let dns_query = build_example_dns_query(0x1234);
    let mut dns_ip_buf = Vec::new();
    let b_dns = PacketBuilder::ipv4(client_ipv4.octets(), server_ipv4.octets(), 64).udp(54321, 53);
    dns_ip_buf.reserve(b_dns.size(dns_query.len()));
    b_dns
        .write(&mut dns_ip_buf, &dns_query)
        .expect("Failed to build DNS packet");

    let decrypted_dns =
        exchange_tunnel_packet(client_tunn, client_socket, peer_endpoint, &dns_ip_buf).await;
    let sliced_dns = etherparse::SlicedPacket::from_ip(&decrypted_dns)
        .expect("Failed to slice decrypted DNS packet");
    let Some(etherparse::TransportSlice::Udp(udp_dns)) = sliced_dns.transport else {
        panic!("Expected UDP transport");
    };
    let dns_payload = udp_dns.payload();
    assert!(dns_payload.len() >= 12);
    assert_eq!(&dns_payload[0..2], &0x1234u16.to_be_bytes());
    assert_eq!(u16::from_be_bytes([dns_payload[2], dns_payload[3]]), 0x8180);
    assert_eq!(u16::from_be_bytes([dns_payload[6], dns_payload[7]]), 1);
    assert_eq!(mock.stats().dns_queries_answered.load(Ordering::SeqCst), 1);
}

async fn verify_mock_tcp_echo(
    client_tunn: &mut Tunn,
    client_socket: &UdpSocket,
    peer_endpoint: SocketAddr,
    mock: &MockWireGuardPeer,
) {
    let client_ipv4 = Ipv4Addr::new(10, 0, 0, 2);
    let server_ipv4 = Ipv4Addr::new(10, 0, 0, 1);

    let mut syn_buf = Vec::new();
    let b_syn = PacketBuilder::ipv4(client_ipv4.octets(), server_ipv4.octets(), 64)
        .tcp(23456, 8080, 100, 65535)
        .syn();
    syn_buf.reserve(b_syn.size(0));
    b_syn.write(&mut syn_buf, &[]).expect("Failed to build SYN");

    let synack_ip =
        exchange_tunnel_packet(client_tunn, client_socket, peer_endpoint, &syn_buf).await;
    let sliced =
        etherparse::SlicedPacket::from_ip(&synack_ip).expect("Failed to slice decrypted SYN/ACK");
    let server_isn = if let Some(etherparse::TransportSlice::Tcp(tcp)) = sliced.transport {
        assert!(tcp.syn() && tcp.ack());
        assert_eq!(tcp.acknowledgment_number(), 101);
        tcp.sequence_number()
    } else {
        panic!("Expected TCP slice in SYN/ACK");
    };
    assert_eq!(mock.stats().tcp_syn_received.load(Ordering::SeqCst), 1);

    let tcp_payload = b"hello_in_tunnel_tcp_echo";
    let mut data_buf = Vec::new();
    let b_data = PacketBuilder::ipv4(client_ipv4.octets(), server_ipv4.octets(), 64)
        .tcp(23456, 8080, 101, 65535)
        .psh()
        .ack(server_isn.wrapping_add(1));
    data_buf.reserve(b_data.size(tcp_payload.len()));
    b_data
        .write(&mut data_buf, tcp_payload)
        .expect("Failed to build TCP Data");

    let tcp_echo_ip =
        exchange_tunnel_packet(client_tunn, client_socket, peer_endpoint, &data_buf).await;
    let sliced_echo = etherparse::SlicedPacket::from_ip(&tcp_echo_ip)
        .expect("Failed to slice decrypted TCP Echo");
    let Some(etherparse::TransportSlice::Tcp(tcp)) = sliced_echo.transport else {
        panic!("Expected TCP transport");
    };
    assert_eq!(tcp.payload(), tcp_payload);
    assert_eq!(
        mock.stats().tcp_bytes_echoed.load(Ordering::SeqCst),
        tcp_payload.len() as u64
    );
}

#[tokio::test]
async fn test_mock_peer_handshake_and_l3_echo() {
    let mock = MockWireGuardPeer::start_ephemeral()
        .await
        .expect("Failed to start ephemeral mock peer");
    let peer_endpoint = mock.endpoint();
    let peer_pubkey = mock.public_key();

    let client_secret = x25519::StaticSecret::from(rand::random::<[u8; 32]>());
    let mut client_tunn = Tunn::new(
        client_secret,
        x25519::PublicKey::from(peer_pubkey),
        None,
        None,
        IndexTable::from_os_rng(),
        Arc::new(RateLimiter::new(&x25519::PublicKey::from(peer_pubkey), 100)),
    );
    let client_socket = UdpSocket::bind("127.0.0.1:0")
        .await
        .expect("Failed to bind client UDP socket");

    perform_mock_handshake(&mut client_tunn, &client_socket, peer_endpoint).await;
    assert_eq!(mock.stats().handshakes_received.load(Ordering::SeqCst), 1);
    assert_eq!(mock.stats().handshakes_completed.load(Ordering::SeqCst), 1);

    verify_mock_udp_and_dns(&mut client_tunn, &client_socket, peer_endpoint, &mock).await;
    verify_mock_tcp_echo(&mut client_tunn, &client_socket, peer_endpoint, &mock).await;

    // In-Tunnel IPv6 UDP Echo
    let client_ipv6: Ipv6Addr = "fd00::2".parse().unwrap();
    let server_ipv6: Ipv6Addr = "2606:4700:4700::1111".parse().unwrap();
    let echo_v6_payload = b"ipv6_test_payload";
    let mut udp_v6_buf = Vec::new();
    let b_v6 = PacketBuilder::ipv6(client_ipv6.octets(), server_ipv6.octets(), 64).udp(12346, 9998);
    udp_v6_buf.reserve(b_v6.size(echo_v6_payload.len()));
    b_v6.write(&mut udp_v6_buf, echo_v6_payload)
        .expect("Failed to build IPv6 UDP packet");

    let decrypted_v6 =
        exchange_tunnel_packet(&mut client_tunn, &client_socket, peer_endpoint, &udp_v6_buf).await;
    let sliced_v6 = etherparse::SlicedPacket::from_ip(&decrypted_v6)
        .expect("Failed to slice decrypted IPv6 packet");
    let Some(etherparse::TransportSlice::Udp(udp_v6)) = sliced_v6.transport else {
        panic!("Expected UDP transport");
    };
    assert_eq!(udp_v6.payload(), echo_v6_payload);
    assert_eq!(mock.stats().ipv6_packets.load(Ordering::SeqCst), 1);

    // Fault-Injection Control (drop_data)
    mock.controls().drop_data.store(true, Ordering::SeqCst);
    let encap_v6 = client_tunn
        .encapsulate_with_session(Packet::copy_from(udp_v6_buf.as_slice()))
        .expect("Failed to encapsulate IPv6 UDP packet");
    let encap_v6_bytes = encap_v6.into_bytes();
    client_socket
        .send_to(encap_v6_bytes.as_ref(), peer_endpoint)
        .await
        .expect("Failed to send encap data");

    let mut resp_buf = vec![0u8; 1500];
    let timeout_res = tokio::time::timeout(
        Duration::from_millis(80),
        client_socket.recv_from(&mut resp_buf),
    )
    .await;
    assert!(
        timeout_res.is_err(),
        "Expected packet to be dropped by controls"
    );
    mock.controls().drop_data.store(false, Ordering::SeqCst);

    mock.stop().await;
}

// -----------------------------------------------------------------------------
// Test 2: SOCKS5 Test Client — Greeting, RFC 1929 Auth, CONNECT & UDP ASSOCIATE
// -----------------------------------------------------------------------------

#[tokio::test]
async fn test_socks5_client_driver() {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("Failed to bind mock socks5 listener");
    let server_addr = listener.local_addr().unwrap();

    // Spawn lightweight in-process mock SOCKS5 server for test driver validation
    tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();

        // 1. Greeting negotiation
        let mut greeting_header = [0u8; 2];
        stream.read_exact(&mut greeting_header).await.unwrap();
        assert_eq!(greeting_header[0], 0x05); // SOCKS5
        let nmethods = greeting_header[1] as usize;
        let mut methods = vec![0u8; nmethods];
        stream.read_exact(&mut methods).await.unwrap();
        // Respond with Method 0x02 (User/Pass)
        stream.write_all(&[0x05, 0x02]).await.unwrap();

        // 2. RFC 1929 Auth
        let mut auth_ver = [0u8; 2];
        stream.read_exact(&mut auth_ver).await.unwrap();
        assert_eq!(auth_ver[0], 0x01); // RFC 1929
        let ulen = auth_ver[1] as usize;
        let mut uname = vec![0u8; ulen];
        stream.read_exact(&mut uname).await.unwrap();
        let mut plen_buf = [0u8; 1];
        stream.read_exact(&mut plen_buf).await.unwrap();
        let plen = plen_buf[0] as usize;
        let mut pass = vec![0u8; plen];
        stream.read_exact(&mut pass).await.unwrap();

        if uname == b"wgcf-001" && pass == b"secret123" {
            stream.write_all(&[0x01, 0x00]).await.unwrap(); // Success
        } else {
            stream.write_all(&[0x01, 0x01]).await.unwrap(); // Failure
            return;
        }

        // 3. Command: CMD_CONNECT (0x01)
        let mut cmd_buf = [0u8; 4];
        stream.read_exact(&mut cmd_buf).await.unwrap();
        assert_eq!(cmd_buf[0], 0x05);
        assert_eq!(cmd_buf[1], 0x01); // CONNECT
        assert_eq!(cmd_buf[3], 0x01); // ATYP IPv4
        let mut ip_port = [0u8; 6];
        stream.read_exact(&mut ip_port).await.unwrap();

        // Respond Success with bound 127.0.0.1:9999
        stream
            .write_all(&[0x05, 0x00, 0x00, 0x01, 127, 0, 0, 1, 0x27, 0x0F])
            .await
            .unwrap();

        // 4. Data streaming loopback
        let mut payload = [0u8; 12];
        stream.read_exact(&mut payload).await.unwrap();
        stream.write_all(&payload).await.unwrap();
    });

    // Run Socks5TestClient against mock server
    let mut client = Socks5TestClient::connect(server_addr)
        .await
        .expect("Failed to connect");
    let chosen_method = client
        .greeting(&[0x00, 0x02])
        .await
        .expect("Greeting failed");
    assert_eq!(chosen_method, 0x02);

    client
        .authenticate("wgcf-001", "secret123")
        .await
        .expect("Authentication failed");

    let mut stream = client
        .cmd_connect_ipv4(Ipv4Addr::new(93, 184, 216, 34), 80)
        .await
        .expect("CONNECT failed");

    stream.write_all(b"socks5_echo!").await.unwrap();
    let mut echo_buf = [0u8; 12];
    stream.read_exact(&mut echo_buf).await.unwrap();
    assert_eq!(&echo_buf, b"socks5_echo!");
}

#[tokio::test]
async fn test_socks5_udp_associate_driver() {
    let udp_relay = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let relay_addr = udp_relay.local_addr().unwrap();

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let server_addr = listener.local_addr().unwrap();

    // Spawn mock SOCKS5 server handling UDP ASSOCIATE
    tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();

        // Greeting
        let mut g = [0u8; 3];
        stream.read_exact(&mut g).await.unwrap();
        stream.write_all(&[0x05, 0x00]).await.unwrap(); // No auth

        // Command: UDP ASSOCIATE (0x03)
        let mut cmd = [0u8; 10];
        stream.read_exact(&mut cmd).await.unwrap();
        assert_eq!(cmd[1], 0x03);

        // Reply with relay address
        let mut resp = vec![0x05, 0x00, 0x00, 0x01];
        if let SocketAddr::V4(v4) = relay_addr {
            resp.extend_from_slice(&v4.ip().octets());
            resp.extend_from_slice(&v4.port().to_be_bytes());
        }
        stream.write_all(&resp).await.unwrap();

        // Keep connection open until client finishes
        let mut dummy = [0u8; 1];
        let _ = stream.read(&mut dummy).await;
    });

    // Spawn mock UDP relay echo
    tokio::spawn(async move {
        let mut buf = [0u8; 1024];
        let (n, client_addr) = udp_relay.recv_from(&mut buf).await.unwrap();
        // Echo packet straight back to client
        udp_relay.send_to(&buf[..n], client_addr).await.unwrap();
    });

    let mut client = Socks5TestClient::connect(server_addr)
        .await
        .expect("Failed to connect");
    let method = client.greeting(&[0x00]).await.unwrap();
    assert_eq!(method, 0x00);

    let session = client
        .cmd_udp_associate(None)
        .await
        .expect("UDP associate failed");
    assert_eq!(session.relay_addr(), relay_addr);

    let target = Socks5Target::Ip(SocketAddr::V4(std::net::SocketAddrV4::new(
        Ipv4Addr::new(8, 8, 8, 8),
        53,
    )));
    let echo_res = session
        .query_echo(&target, b"dns_over_udp_assoc", Duration::from_secs(2))
        .await
        .expect("UDP echo failed");
    assert_eq!(echo_res, b"dns_over_udp_assoc");
}

// -----------------------------------------------------------------------------
// Test 3: HTTP Proxy Test Client — CONNECT, Basic Auth & 407 Challenge
// -----------------------------------------------------------------------------

// Helper for mock HTTP proxy to read request line and headers
async fn read_mock_http_request<R: tokio::io::AsyncRead + Unpin>(
    reader: &mut R,
) -> (String, std::collections::HashMap<String, String>) {
    let mut header_bytes = Vec::new();
    let mut byte_buf = [0u8; 1];
    while header_bytes.len() < 16384 {
        reader.read_exact(&mut byte_buf).await.unwrap();
        header_bytes.push(byte_buf[0]);
        if header_bytes.ends_with(b"\r\n\r\n") {
            break;
        }
    }
    let header_str = String::from_utf8_lossy(&header_bytes);
    let mut lines = header_str.split("\r\n");
    let req_line = lines.next().unwrap_or("").to_string();
    let mut headers = std::collections::HashMap::new();
    for line in lines {
        if line.is_empty() {
            break;
        }
        if let Some((k, v)) = line.split_once(':') {
            headers.insert(k.trim().to_ascii_lowercase(), v.trim().to_string());
        }
    }
    (req_line, headers)
}

#[tokio::test]
async fn test_http_proxy_client_driver() {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("Failed to bind mock http proxy listener");
    let server_addr = listener.local_addr().unwrap();

    tokio::spawn(async move {
        // First connection: unauthenticated -> respond 407
        let (mut stream, _) = listener.accept().await.unwrap();
        let (_req_line, headers) = read_mock_http_request(&mut stream).await;

        if !headers.contains_key("proxy-authorization") {
            let resp = "HTTP/1.1 407 Proxy Authentication Required\r\n\
                        Proxy-Authenticate: Basic realm=\"wpmulti-realm\"\r\n\
                        Content-Length: 0\r\n\r\n";
            stream.write_all(resp.as_bytes()).await.unwrap();
        }

        // Second connection: authenticated -> respond 200 Connection Established
        let (mut stream2, _) = listener.accept().await.unwrap();
        let (_req_line2, headers2) = read_mock_http_request(&mut stream2).await;
        let auth = headers2.get("proxy-authorization").unwrap();
        let expected_auth = HttpProxyTestClient::basic_auth_header("tunnel_user", "tunnel_pass");
        assert_eq!(auth, &expected_auth);

        let ok_resp = "HTTP/1.1 200 Connection Established\r\n\r\n";
        stream2.write_all(ok_resp.as_bytes()).await.unwrap();

        // Echo tunneled data
        let mut buf = [0u8; 15];
        stream2.read_exact(&mut buf).await.unwrap();
        stream2.write_all(&buf).await.unwrap();
    });

    let mut stream = HttpProxyTestClient::connect_tunnel_with_challenge(
        server_addr,
        "api.example.com:443",
        "tunnel_user",
        "tunnel_pass",
    )
    .await
    .expect("CONNECT with challenge failed");

    stream.write_all(b"http_tunnel_msg").await.unwrap();
    let mut echo = [0u8; 15];
    stream.read_exact(&mut echo).await.unwrap();
    assert_eq!(&echo, b"http_tunnel_msg");
}

#[tokio::test]
async fn test_http_proxy_forward_and_raw() {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("Failed to bind mock forward proxy listener");
    let server_addr = listener.local_addr().unwrap();

    tokio::spawn(async move {
        // Forward proxy request
        let (mut stream, _) = listener.accept().await.unwrap();
        let (req_line, headers) = read_mock_http_request(&mut stream).await;
        assert!(req_line.starts_with("GET http://example.com/data HTTP/1.1"));
        assert!(headers.contains_key("proxy-authorization"));

        let resp_body = "forward_proxy_ok";
        let resp = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: {}\r\n\r\n{}",
            resp_body.len(),
            resp_body
        );
        stream.write_all(resp.as_bytes()).await.unwrap();

        // Raw request test
        let (mut stream2, _) = listener.accept().await.unwrap();
        let (_raw_line, _) = read_mock_http_request(&mut stream2).await;
        let err_resp = "HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n";
        stream2.write_all(err_resp.as_bytes()).await.unwrap();
    });

    let resp = HttpProxyTestClient::forward_request(
        server_addr,
        "GET",
        "http://example.com/data",
        Some(("user", "pass")),
    )
    .await
    .expect("Forward request failed");
    assert!(resp.is_success());
    assert_eq!(String::from_utf8_lossy(&resp.body), "forward_proxy_ok");

    let (raw_resp, _) = HttpProxyTestClient::send_raw(server_addr, "INVALID / HTTP/1.1\r\n\r\n")
        .await
        .expect("send_raw failed");
    assert_eq!(raw_resp.status_code, 400);
}

// -----------------------------------------------------------------------------
// Test 4: Admin API Test Client — Status, Health, Metrics & REST Actions
// -----------------------------------------------------------------------------

#[tokio::test]
async fn test_admin_client_driver() {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("Failed to bind mock admin listener");
    let admin_addr = listener.local_addr().unwrap();

    tokio::spawn(async move {
        loop {
            let (mut stream, _) = match listener.accept().await {
                Ok(conn) => conn,
                Err(_) => break,
            };

            let mut header_bytes = Vec::new();
            let mut byte_buf = [0u8; 1];
            while header_bytes.len() < 4096 {
                if stream.read_exact(&mut byte_buf).await.is_err() {
                    break;
                }
                header_bytes.push(byte_buf[0]);
                if header_bytes.ends_with(b"\r\n\r\n") {
                    break;
                }
            }

            let req_str = String::from_utf8_lossy(&header_bytes);
            let first_line = req_str.lines().next().unwrap_or("");

            if first_line.starts_with("GET /health") {
                let body = r#"{"status":"ok"}"#;
                let resp = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
                    body.len(),
                    body
                );
                let _ = stream.write_all(resp.as_bytes()).await;
            } else if first_line.starts_with("GET /status") {
                let body = r#"{"version":"0.1.0","total_tunnels":245,"active_tunnels":1}"#;
                let resp = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
                    body.len(),
                    body
                );
                let _ = stream.write_all(resp.as_bytes()).await;
            } else if first_line.starts_with("GET /metrics") {
                let body = "# HELP wpmulti_tunnel_rx_bytes Total received bytes\n\
                            # TYPE wpmulti_tunnel_rx_bytes counter\n\
                            wpmulti_tunnel_rx_bytes{tunnel_id=\"wgcf-001\"} 1048576\n\
                            wpmulti_tunnel_tx_bytes{tunnel_id=\"wgcf-001\"} 524288\n";
                let resp = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: {}\r\n\r\n{}",
                    body.len(),
                    body
                );
                let _ = stream.write_all(resp.as_bytes()).await;
            } else if first_line.starts_with("POST /reload") {
                let body = r#"{"reloaded":245}"#;
                let resp = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
                    body.len(),
                    body
                );
                let _ = stream.write_all(resp.as_bytes()).await;
            } else {
                // Unknown path: no response, the connection just closes.
            }
        }
    });

    let client = AdminTestClient::new(admin_addr, Some("secret_token".to_string()));

    let health = client.get_health().await.expect("Health check failed");
    assert_eq!(health["status"], "ok");

    let status = client.get_status().await.expect("Status check failed");
    assert_eq!(status["total_tunnels"], 245);
    assert_eq!(status["active_tunnels"], 1);

    let reload = client.trigger_reload().await.expect("Reload failed");
    assert_eq!(reload["reloaded"], 245);

    let rx_val = client
        .get_metric_value("wpmulti_tunnel_rx_bytes", &[("tunnel_id", "wgcf-001")])
        .await
        .expect("Metric parse failed");
    assert_eq!(rx_val, 1048576.0);
}

// -----------------------------------------------------------------------------
// Test 5: Fixtures — WgConf, TOML, Ephemeral Ports & 245 Cloned wgcf Configs
// -----------------------------------------------------------------------------

#[tokio::test]
async fn test_fixtures_builders_and_245_cloned_wgcf() {
    let env = TestEnvironment::new("infra_smoke").expect("Failed to create TestEnvironment");

    // 1. Verify WgConfBuilder
    let wg_conf_str = WgConfBuilder::new()
        .private_key("0OaUaQd4uJq5m8eN8uJq5m8eN8uJq5m8eN8uJq5m8eM=")
        .addresses(&["10.0.0.2/32", "fd00::2/128"])
        .dns(&["1.1.1.1", "2606:4700:4700::1111"])
        .mtu(1360)
        .add_peer(
            WgPeerFixture::new(
                "bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo=",
                "198.51.100.1:51820",
            )
            .allowed_ips(&["0.0.0.0/0", "::/0"])
            .persistent_keepalive(25),
        )
        .build_ini();

    let conf_path = env
        .write_conf("test_peer.conf", &wg_conf_str)
        .expect("Failed to write conf");
    let parsed_conf =
        wpmulti::load_tunnel_config_from_file(&conf_path).expect("Failed to parse WG conf");
    assert_eq!(parsed_conf.id, "test_peer");
    assert_eq!(parsed_conf.interface.mtu, 1360);
    assert_eq!(parsed_conf.interface.addresses.len(), 2);
    assert_eq!(parsed_conf.interface.dns.len(), 2);
    assert_eq!(parsed_conf.peers.len(), 1);

    // 2. Verify WpMultiTomlBuilder
    let s5_port = allocate_ephemeral_port();
    let http_port = allocate_ephemeral_port();
    assert_ne!(s5_port, 0);
    assert_ne!(http_port, 0);

    let toml_str = WpMultiTomlBuilder::new(env.conf_dir().to_path_buf())
        .lifecycle_mode("lazy")
        .idle_timeout("30s")
        .base_ports(Some(s5_port), Some(http_port))
        .add_shared_listener(SharedListenerFixture {
            name: "shared_s5".to_string(),
            proto_type: "socks5".to_string(),
            bind: "127.0.0.1:1080".parse().unwrap(),
            auth_mode: "none".to_string(),
            global_password: None,
            default_strategy: "round-robin".to_string(),
            allow_anonymous: true,
            pool: "all".to_string(),
        })
        .admin(true, Some("127.0.0.1:9090".parse().unwrap()), None)
        .build_toml();

    assert!(toml_str.contains("config_dir ="));
    assert!(toml_str.contains("mode = \"lazy\""));
    assert!(toml_str.contains("[[shared_listener]]"));

    // 3. Verify Ephemeral Port Range Allocator
    let base_range = allocate_ephemeral_port_range(5);
    assert!(base_range >= 30000);

    // 4. Verify 245 Cloned wgcf Configs Generation in dedicated directory
    let cloned_env =
        TestEnvironment::new("wgcf_245").expect("Failed to create cloned TestEnvironment");
    let mock_endpoint = "127.0.0.1:51820".parse().unwrap();
    let mock_pubkey = "bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo=";

    let wgcf_set =
        generate_245_cloned_wgcf_configs(cloned_env.conf_dir(), mock_endpoint, mock_pubkey)
            .expect("Failed to generate 245 cloned wgcf configs");

    assert_eq!(wgcf_set.tunnel_ids.len(), 245);
    assert_eq!(wgcf_set.file_paths.len(), 245);
    assert_eq!(wgcf_set.tunnel_ids[0], "wgcf-001");
    assert_eq!(wgcf_set.tunnel_ids[244], "wgcf-245");

    // Load configs from directory via wpmulti core configuration engine
    let loaded_tunnels = wpmulti::load_tunnel_configs_from_dir(cloned_env.conf_dir())
        .expect("Failed to load 245 configs from directory");
    assert_eq!(loaded_tunnels.len(), 245);
    // Verify each tunnel has unique ID despite sharing identical private/public keys and IPs
    for (i, t) in loaded_tunnels.iter().enumerate() {
        assert_eq!(t.id, format!("wgcf-{:03}", i + 1));
        assert_eq!(t.interface.addresses.len(), 2); // IPv4 and IPv6
        assert_eq!(t.peers[0].endpoint, "127.0.0.1:51820");
    }
}

#[tokio::test]
async fn test_full_e2e_pipeline_socks5_and_http_via_mock_wg_peer() {
    use base64::Engine as _;

    // 1. Start in-process MockWireGuardPeer (Noise IK + MockIpEngine DNS/TCP/UDP)
    let mock = MockWireGuardPeer::start_ephemeral()
        .await
        .expect("Failed to start MockWireGuardPeer");
    let peer_pubkey_b64 = base64::engine::general_purpose::STANDARD.encode(mock.public_key());

    // 2. Build TunnelConfig pointing to MockWireGuardPeer
    let client_secret = x25519::StaticSecret::from(rand::random::<[u8; 32]>());
    let client_priv_b64 =
        base64::engine::general_purpose::STANDARD.encode(client_secret.to_bytes());

    let conf_ini = WgConfBuilder::new()
        .private_key(&client_priv_b64)
        .addresses(&["10.7.0.2/32"])
        .dns(&["1.1.1.1"])
        .mtu(1280)
        .add_peer(WgPeerFixture::new(
            &peer_pubkey_b64,
            &mock.endpoint().to_string(),
        ))
        .build_ini();
    let tunnel_cfg =
        wpmulti::load_tunnel_config_from_str("wg-e2e-full", &conf_ini).expect("parse wg conf");

    // 3. Configure TunnelManager with dedicated SOCKS5 and HTTP listeners
    let s5_port = allocate_ephemeral_port();
    let http_port = allocate_ephemeral_port();

    let mut main_cfg = wpmulti::MainConfig::default();
    main_cfg.per_tunnel.enabled = true;
    main_cfg.per_tunnel.base_socks5_port = Some(s5_port);
    main_cfg.per_tunnel.base_http_port = Some(http_port);

    let manager =
        wpmulti::TunnelManager::new(main_cfg, vec![tunnel_cfg]).expect("TunnelManager::new failed");
    manager.start().await.expect("TunnelManager::start failed");

    // 4. SOCKS5 CONNECT with in-tunnel domain DNS resolution -> MockWireGuardPeer TCP echo
    let s5_addr: SocketAddr = format!("127.0.0.1:{}", s5_port).parse().unwrap();
    let mut s5_client = Socks5TestClient::connect(s5_addr)
        .await
        .expect("SOCKS5 connect to listener");
    let method = s5_client.greeting(&[0x00]).await.expect("SOCKS5 greeting");
    assert_eq!(method, 0x00);

    let mut s5_stream = s5_client
        .cmd_connect_domain("e2e-echo.test", 8080)
        .await
        .expect("SOCKS5 CONNECT domain through WireGuard tunnel");

    let s5_payload = b"hello_full_e2e_socks5_wg";
    s5_stream.write_all(s5_payload).await.expect("SOCKS5 write");
    let mut s5_echo = vec![0u8; s5_payload.len()];
    s5_stream
        .read_exact(&mut s5_echo)
        .await
        .expect("SOCKS5 read");
    assert_eq!(&s5_echo, s5_payload);
    drop(s5_stream);

    // 5. HTTP CONNECT -> MockWireGuardPeer TCP echo
    let http_addr: SocketAddr = format!("127.0.0.1:{}", http_port).parse().unwrap();
    let mut http_stream =
        HttpProxyTestClient::connect_tunnel(http_addr, "93.184.216.34:8080", None)
            .await
            .expect("HTTP CONNECT through WireGuard tunnel");

    let http_payload = b"hello_full_e2e_http_wg";
    http_stream
        .write_all(http_payload)
        .await
        .expect("HTTP write");
    let mut http_echo = vec![0u8; http_payload.len()];
    http_stream
        .read_exact(&mut http_echo)
        .await
        .expect("HTTP read");
    assert_eq!(&http_echo, http_payload);
    drop(http_stream);

    // Verify MockWireGuardPeer actually processed handshake + encrypted transport packets
    assert!(
        mock.stats()
            .handshakes_completed
            .load(std::sync::atomic::Ordering::Relaxed)
            >= 1
    );
    assert!(
        mock.stats()
            .data_packets_received
            .load(std::sync::atomic::Ordering::Relaxed)
            >= 2
    );
    assert!(
        mock.stats()
            .tcp_syn_received
            .load(std::sync::atomic::Ordering::Relaxed)
            >= 2
    );

    manager.stop().await.expect("TunnelManager::stop");
    drop(mock);
}
