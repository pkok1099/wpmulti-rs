//! Comprehensive unit tests for SOCKS5 and HTTP proxy engines.

use std::collections::HashMap;
use std::future::Future;
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use parking_lot::RwLock;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};

use crate::config::{AuthMode, PoolStrategy};
use crate::proxy::http::{
    extract_basic_auth, handle_http, parse_authority, read_http_request_headers_buffered,
};
use crate::proxy::router::{
    DirectTunnelTarget, DynStream, PoolKeyword, PoolRouter, ProxyTunnelTarget, ProxyUdpSocket,
    SingleTunnelRouter, TargetAddr, TunnelRouter, TunnelSelector,
};
use crate::proxy::socks5::{
    ATYP_DOMAIN, ATYP_IPV4, ATYP_IPV6, CMD_CONNECT, CMD_UDP_ASSOCIATE, METHOD_NO_ACCEPTABLE,
    METHOD_NO_AUTH, METHOD_USER_PASS, REP_CONN_REFUSED, REP_HOST_UNREACHABLE, REP_SUCCESS,
    RFC1929_VERSION, SOCKS5_VERSION, build_socks5_udp_packet, handle_socks5,
    parse_socks5_udp_packet, send_socks5_reply,
};

/// Mock tunnel target with configurable DNS resolution table and connection interception.
struct MockTunnelTarget {
    id: String,
    dns_table: RwLock<HashMap<String, IpAddr>>,
    tcp_conns: AtomicUsize,
}

impl MockTunnelTarget {
    fn new(id: &str) -> Self {
        Self {
            id: id.to_string(),
            dns_table: RwLock::new(HashMap::new()),
            tcp_conns: AtomicUsize::new(0),
        }
    }

    fn id(&self) -> &str {
        &self.id
    }

    fn with_dns(self, domain: &str, ip: IpAddr) -> Self {
        self.dns_table.write().insert(domain.to_string(), ip);
        self
    }
}

impl ProxyTunnelTarget for MockTunnelTarget {
    fn tcp_connect<'a>(
        &'a self,
        dst: SocketAddr,
    ) -> Pin<Box<dyn Future<Output = io::Result<DynStream>> + Send + 'a>> {
        self.tcp_conns.fetch_add(1, Ordering::SeqCst);
        Box::pin(async move {
            let stream = TcpStream::connect(dst).await?;
            Ok(Box::new(stream) as DynStream)
        })
    }

    fn udp_bind<'a>(
        &'a self,
        local_port: u16,
    ) -> Pin<Box<dyn Future<Output = io::Result<Box<dyn ProxyUdpSocket>>> + Send + 'a>> {
        Box::pin(async move {
            let bind_addr = SocketAddr::from(([127, 0, 0, 1], local_port));
            let socket = UdpSocket::bind(bind_addr).await?;
            Ok(Box::new(socket) as Box<dyn ProxyUdpSocket>)
        })
    }

    fn resolve_in_tunnel<'a>(
        &'a self,
        domain: &'a str,
    ) -> Pin<Box<dyn Future<Output = io::Result<IpAddr>> + Send + 'a>> {
        Box::pin(async move {
            if let Ok(ip) = domain.parse::<IpAddr>() {
                return Ok(ip);
            }
            let table = self.dns_table.read();
            if let Some(ip) = table.get(domain) {
                Ok(*ip)
            } else {
                Err(io::Error::new(
                    io::ErrorKind::NotFound,
                    format!("mock dns could not resolve '{}'", domain),
                ))
            }
        })
    }
}

// -----------------------------------------------------------------------------
// Test Helpers: Mock TCP/UDP/HTTP Servers
// -----------------------------------------------------------------------------

async fn spawn_echo_tcp_server() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        while let Ok((mut stream, _)) = listener.accept().await {
            tokio::spawn(async move {
                let mut buf = [0u8; 1024];
                while let Ok(n) = stream.read(&mut buf).await {
                    if n == 0 {
                        break;
                    }
                    if stream.write_all(&buf[..n]).await.is_err() {
                        break;
                    }
                }
            });
        }
    });
    addr
}

async fn spawn_echo_tcp_server_ipv6() -> Option<SocketAddr> {
    let listener = TcpListener::bind("[::1]:0").await.ok()?;
    let addr = listener.local_addr().ok()?;
    tokio::spawn(async move {
        while let Ok((mut stream, _)) = listener.accept().await {
            tokio::spawn(async move {
                let mut buf = [0u8; 1024];
                while let Ok(n) = stream.read(&mut buf).await {
                    if n == 0 {
                        break;
                    }
                    if stream.write_all(&buf[..n]).await.is_err() {
                        break;
                    }
                }
            });
        }
    });
    Some(addr)
}

async fn spawn_echo_udp_server() -> SocketAddr {
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let addr = socket.local_addr().unwrap();
    tokio::spawn(async move {
        let mut buf = [0u8; 2048];
        while let Ok((n, client_addr)) = socket.recv_from(&mut buf).await {
            let _ = socket.send_to(&buf[..n], client_addr).await;
        }
    });
    addr
}

async fn spawn_mock_http_server(response_body: &'static str) -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        while let Ok((mut stream, _)) = listener.accept().await {
            let body = response_body.as_bytes();
            tokio::spawn(async move {
                let mut header_buf = Vec::new();
                let mut b = [0u8; 1];
                while header_buf.len() < 8192 {
                    if stream.read_exact(&mut b).await.is_err() {
                        break;
                    }
                    header_buf.push(b[0]);
                    if header_buf.ends_with(b"\r\n\r\n") {
                        break;
                    }
                }
                let resp = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                    body.len()
                );
                let _ = stream.write_all(resp.as_bytes()).await;
                let _ = stream.write_all(body).await;
                let _ = stream.flush().await;
            });
        }
    });
    addr
}

// -----------------------------------------------------------------------------
// SOCKS5 Tests: Greeting & Authentication
// -----------------------------------------------------------------------------

#[tokio::test]
async fn test_socks5_greeting_no_auth() {
    let target = Arc::new(DirectTunnelTarget);
    let router: Arc<dyn TunnelRouter> =
        Arc::new(SingleTunnelRouter::new("test-tunnel", target, None));

    let (client, server) = tokio::io::duplex(1024);
    tokio::spawn(async move {
        let _ = handle_socks5(server, router).await;
    });

    let mut client = client;
    // Offer [0x00] (No Auth)
    client
        .write_all(&[SOCKS5_VERSION, 1, METHOD_NO_AUTH])
        .await
        .unwrap();

    let mut resp = [0u8; 2];
    client.read_exact(&mut resp).await.unwrap();
    assert_eq!(resp, [SOCKS5_VERSION, METHOD_NO_AUTH]);
}

#[tokio::test]
async fn test_socks5_greeting_user_pass_negotiation() {
    let target = Arc::new(DirectTunnelTarget);
    let router: Arc<dyn TunnelRouter> = Arc::new(SingleTunnelRouter::new(
        "auth-tunnel",
        target,
        Some(("admin".to_string(), "secret123".to_string())),
    ));

    let (client, server) = tokio::io::duplex(1024);
    tokio::spawn(async move {
        let _ = handle_socks5(server, router).await;
    });

    let mut client = client;
    // Client offers [0x00, 0x02]; since server requires auth, it must choose 0x02
    client
        .write_all(&[SOCKS5_VERSION, 2, METHOD_NO_AUTH, METHOD_USER_PASS])
        .await
        .unwrap();

    let mut resp = [0u8; 2];
    client.read_exact(&mut resp).await.unwrap();
    assert_eq!(resp, [SOCKS5_VERSION, METHOD_USER_PASS]);
}

#[tokio::test]
async fn test_socks5_greeting_no_acceptable_method() {
    let target = Arc::new(DirectTunnelTarget);
    let router: Arc<dyn TunnelRouter> = Arc::new(SingleTunnelRouter::new(
        "auth-tunnel",
        target,
        Some(("admin".to_string(), "secret123".to_string())),
    ));

    let (client, server) = tokio::io::duplex(1024);
    tokio::spawn(async move {
        let _ = handle_socks5(server, router).await;
    });

    let mut client = client;
    // Client only offers [0x00]; server requires auth -> must return 0xFF
    client
        .write_all(&[SOCKS5_VERSION, 1, METHOD_NO_AUTH])
        .await
        .unwrap();

    let mut resp = [0u8; 2];
    client.read_exact(&mut resp).await.unwrap();
    assert_eq!(resp, [SOCKS5_VERSION, METHOD_NO_ACCEPTABLE]);
}

#[tokio::test]
async fn test_socks5_rfc1929_auth_success_and_failure() {
    let target = Arc::new(DirectTunnelTarget);
    let router: Arc<dyn TunnelRouter> = Arc::new(SingleTunnelRouter::new(
        "test-tunn",
        target,
        Some(("alice".to_string(), "pass123".to_string())),
    ));

    // Case 1: Wrong password -> Auth failure (0x01)
    {
        let (mut client, server) = tokio::io::duplex(1024);
        let r = Arc::clone(&router);
        tokio::spawn(async move {
            let _ = handle_socks5(server, r).await;
        });

        // Greeting
        client
            .write_all(&[SOCKS5_VERSION, 1, METHOD_USER_PASS])
            .await
            .unwrap();
        let mut g_resp = [0u8; 2];
        client.read_exact(&mut g_resp).await.unwrap();
        assert_eq!(g_resp, [SOCKS5_VERSION, METHOD_USER_PASS]);

        // RFC 1929 Subnegotiation with wrong password
        let mut auth_req = vec![RFC1929_VERSION, 5];
        auth_req.extend_from_slice(b"alice");
        auth_req.push(5);
        auth_req.extend_from_slice(b"wrong");
        client.write_all(&auth_req).await.unwrap();

        let mut a_resp = [0u8; 2];
        client.read_exact(&mut a_resp).await.unwrap();
        assert_eq!(a_resp[0], RFC1929_VERSION);
        assert_ne!(a_resp[1], 0x00); // Non-zero failure
    }

    // Case 2: Correct password -> Auth success (0x00)
    {
        let (mut client, server) = tokio::io::duplex(1024);
        let r = Arc::clone(&router);
        tokio::spawn(async move {
            let _ = handle_socks5(server, r).await;
        });

        // Greeting
        client
            .write_all(&[SOCKS5_VERSION, 1, METHOD_USER_PASS])
            .await
            .unwrap();
        let mut g_resp = [0u8; 2];
        client.read_exact(&mut g_resp).await.unwrap();
        assert_eq!(g_resp, [SOCKS5_VERSION, METHOD_USER_PASS]);

        // RFC 1929 Subnegotiation with correct password
        let mut auth_req = vec![RFC1929_VERSION, 5];
        auth_req.extend_from_slice(b"alice");
        auth_req.push(7);
        auth_req.extend_from_slice(b"pass123");
        client.write_all(&auth_req).await.unwrap();

        let mut a_resp = [0u8; 2];
        client.read_exact(&mut a_resp).await.unwrap();
        assert_eq!(a_resp, [RFC1929_VERSION, 0x00]); // Status 0x00: Success
    }
}

// -----------------------------------------------------------------------------
// SOCKS5 Tests: CONNECT Command (IPv4, IPv6, Domain)
// -----------------------------------------------------------------------------

#[tokio::test]
async fn test_socks5_connect_ipv4() {
    let echo_addr = spawn_echo_tcp_server().await;
    let SocketAddr::V4(echo_v4) = echo_addr else {
        unreachable!();
    };

    let target = Arc::new(DirectTunnelTarget);
    let router: Arc<dyn TunnelRouter> =
        Arc::new(SingleTunnelRouter::new("test-tunnel", target, None));

    let (mut client, server) = tokio::io::duplex(2048);
    tokio::spawn(async move {
        let _ = handle_socks5(server, router).await;
    });

    // 1. Greeting
    client
        .write_all(&[SOCKS5_VERSION, 1, METHOD_NO_AUTH])
        .await
        .unwrap();
    let mut g_resp = [0u8; 2];
    client.read_exact(&mut g_resp).await.unwrap();
    assert_eq!(g_resp[1], METHOD_NO_AUTH);

    // 2. CONNECT IPv4
    let mut cmd = vec![SOCKS5_VERSION, CMD_CONNECT, 0x00, ATYP_IPV4];
    cmd.extend_from_slice(&echo_v4.ip().octets());
    cmd.extend_from_slice(&echo_v4.port().to_be_bytes());
    client.write_all(&cmd).await.unwrap();

    let mut reply_hdr = [0u8; 4];
    client.read_exact(&mut reply_hdr).await.unwrap();
    assert_eq!(reply_hdr[0], SOCKS5_VERSION);
    assert_eq!(reply_hdr[1], REP_SUCCESS);
    assert_eq!(reply_hdr[3], ATYP_IPV4);
    let mut bnd_buf = [0u8; 6];
    client.read_exact(&mut bnd_buf).await.unwrap();

    // 3. Bidirectional data echo through tunnel
    let msg = b"socks5_echo_test_message!";
    client.write_all(msg).await.unwrap();
    let mut echo_buf = vec![0u8; msg.len()];
    client.read_exact(&mut echo_buf).await.unwrap();
    assert_eq!(&echo_buf, msg);
}

#[tokio::test]
async fn test_socks5_connect_ipv6() {
    let maybe_echo_addr = spawn_echo_tcp_server_ipv6().await;
    let Some(echo_addr) = maybe_echo_addr else {
        return; // IPv6 disabled on host; skip
    };
    let SocketAddr::V6(echo_v6) = echo_addr else {
        unreachable!();
    };

    let target = Arc::new(DirectTunnelTarget);
    let router: Arc<dyn TunnelRouter> =
        Arc::new(SingleTunnelRouter::new("test-tunnel-v6", target, None));

    let (mut client, server) = tokio::io::duplex(2048);
    tokio::spawn(async move {
        let _ = handle_socks5(server, router).await;
    });

    client
        .write_all(&[SOCKS5_VERSION, 1, METHOD_NO_AUTH])
        .await
        .unwrap();
    let mut g_resp = [0u8; 2];
    client.read_exact(&mut g_resp).await.unwrap();

    let mut cmd = vec![SOCKS5_VERSION, CMD_CONNECT, 0x00, ATYP_IPV6];
    cmd.extend_from_slice(&echo_v6.ip().octets());
    cmd.extend_from_slice(&echo_v6.port().to_be_bytes());
    client.write_all(&cmd).await.unwrap();

    let mut reply_hdr = [0u8; 4];
    client.read_exact(&mut reply_hdr).await.unwrap();
    assert_eq!(reply_hdr[1], REP_SUCCESS);
    let mut dummy_bnd = [0u8; 6];
    client.read_exact(&mut dummy_bnd).await.unwrap();

    client.write_all(b"ipv6_socks5_echo").await.unwrap();
    let mut buf = [0u8; 16];
    client.read_exact(&mut buf).await.unwrap();
    assert_eq!(&buf, b"ipv6_socks5_echo");
}

#[tokio::test]
async fn test_socks5_connect_domain_with_tunnel_resolution() {
    let echo_addr = spawn_echo_tcp_server().await;
    let echo_ip = echo_addr.ip();
    let echo_port = echo_addr.port();

    let mock_target =
        Arc::new(MockTunnelTarget::new("tunnel-01").with_dns("echo.tunnel.local", echo_ip));
    assert_eq!(mock_target.id(), "tunnel-01");
    let router: Arc<dyn TunnelRouter> =
        Arc::new(SingleTunnelRouter::new("tunnel-01", mock_target, None));

    let (mut client, server) = tokio::io::duplex(2048);
    tokio::spawn(async move {
        let _ = handle_socks5(server, router).await;
    });

    // 1. Greeting
    client
        .write_all(&[SOCKS5_VERSION, 1, METHOD_NO_AUTH])
        .await
        .unwrap();
    let mut g_resp = [0u8; 2];
    client.read_exact(&mut g_resp).await.unwrap();
    assert_eq!(g_resp[1], METHOD_NO_AUTH);

    // 2. CONNECT Domain: "echo.tunnel.local:port"
    let domain = "echo.tunnel.local";
    let mut cmd = vec![SOCKS5_VERSION, CMD_CONNECT, 0x00, ATYP_DOMAIN];
    cmd.push(domain.len() as u8);
    cmd.extend_from_slice(domain.as_bytes());
    cmd.extend_from_slice(&echo_port.to_be_bytes());
    client.write_all(&cmd).await.unwrap();

    let mut reply_hdr = [0u8; 4];
    client.read_exact(&mut reply_hdr).await.unwrap();
    assert_eq!(reply_hdr[1], REP_SUCCESS);
    let mut dummy_bnd = [0u8; 6];
    client.read_exact(&mut dummy_bnd).await.unwrap();

    // 3. Echo verification
    client.write_all(b"domain_tunnel_ok").await.unwrap();
    let mut buf = [0u8; 16];
    client.read_exact(&mut buf).await.unwrap();
    assert_eq!(&buf, b"domain_tunnel_ok");
}

#[tokio::test]
async fn test_socks5_connect_unreachable_target_returns_error() {
    let target = Arc::new(DirectTunnelTarget);
    let router: Arc<dyn TunnelRouter> =
        Arc::new(SingleTunnelRouter::new("test-tunnel", target, None));

    let (mut client, server) = tokio::io::duplex(1024);
    tokio::spawn(async move {
        let _ = handle_socks5(server, router).await;
    });

    client
        .write_all(&[SOCKS5_VERSION, 1, METHOD_NO_AUTH])
        .await
        .unwrap();
    let mut g_resp = [0u8; 2];
    client.read_exact(&mut g_resp).await.unwrap();

    // CONNECT to 127.0.0.1 on a closed port (e.g. 1)
    let mut cmd = vec![SOCKS5_VERSION, CMD_CONNECT, 0x00, ATYP_IPV4];
    cmd.extend_from_slice(&[127, 0, 0, 1]);
    cmd.extend_from_slice(&1u16.to_be_bytes());
    client.write_all(&cmd).await.unwrap();

    let mut reply_hdr = [0u8; 4];
    client.read_exact(&mut reply_hdr).await.unwrap();
    assert_eq!(reply_hdr[0], SOCKS5_VERSION);
    assert!(
        reply_hdr[1] == REP_CONN_REFUSED || reply_hdr[1] == REP_HOST_UNREACHABLE,
        "Expected connection refused or host unreachable, got 0x{:02X}",
        reply_hdr[1]
    );
}

#[tokio::test]
async fn test_send_socks5_reply_helper() {
    let (mut client, mut server) = tokio::io::duplex(128);
    let test_addr: SocketAddr = "192.168.1.10:8080".parse().unwrap();
    send_socks5_reply(&mut server, REP_SUCCESS, test_addr)
        .await
        .unwrap();

    let mut buf = [0u8; 10];
    client.read_exact(&mut buf).await.unwrap();
    assert_eq!(buf[0], SOCKS5_VERSION);
    assert_eq!(buf[1], REP_SUCCESS);
    assert_eq!(buf[2], 0x00);
    assert_eq!(buf[3], ATYP_IPV4);
    assert_eq!(&buf[4..8], &[192, 168, 1, 10]);
    assert_eq!(&buf[8..10], &8080u16.to_be_bytes());
}

// -----------------------------------------------------------------------------
// SOCKS5 Tests: UDP Header Encode/Decode & UDP ASSOCIATE Relay
// -----------------------------------------------------------------------------

#[test]
fn test_socks5_udp_header_encode_decode() {
    // 1. IPv4 Target
    let v4_target = TargetAddr::Ip(SocketAddr::V4(SocketAddrV4::new(
        Ipv4Addr::new(1, 1, 1, 1),
        53,
    )));
    let payload = b"dns_query_data";
    let packet = build_socks5_udp_packet(&v4_target, payload);

    let (parsed_target, parsed_payload) =
        parse_socks5_udp_packet(&packet).expect("failed to parse v4");
    assert_eq!(parsed_target, v4_target);
    assert_eq!(parsed_payload, payload);

    // 2. IPv6 Target
    let v6_target = TargetAddr::Ip(SocketAddr::V6(SocketAddrV6::new(
        Ipv6Addr::new(0x2606, 0x4700, 0x4700, 0, 0, 0, 0, 0x1111),
        53,
        0,
        0,
    )));
    let packet_v6 = build_socks5_udp_packet(&v6_target, payload);
    let (parsed_v6, parsed_payload_v6) =
        parse_socks5_udp_packet(&packet_v6).expect("failed to parse v6");
    assert_eq!(parsed_v6, v6_target);
    assert_eq!(parsed_payload_v6, payload);

    // 3. Domain Target
    let domain_target = TargetAddr::Domain("dns.google.com".to_string(), 853);
    let packet_dom = build_socks5_udp_packet(&domain_target, payload);
    let (parsed_dom, parsed_payload_dom) =
        parse_socks5_udp_packet(&packet_dom).expect("failed to parse domain");
    assert_eq!(parsed_dom, domain_target);
    assert_eq!(parsed_payload_dom, payload);

    // 4. Fragmented packet (FRAG != 0) should be dropped
    let mut frag_pkt = packet.clone();
    frag_pkt[2] = 0x01; // FRAG = 1
    assert!(parse_socks5_udp_packet(&frag_pkt).is_none());

    // 5. Truncated packet
    assert!(parse_socks5_udp_packet(&packet[..3]).is_none());
}

#[tokio::test]
async fn test_socks5_udp_associate_relay() {
    let echo_udp_addr = spawn_echo_udp_server().await;

    let target = Arc::new(DirectTunnelTarget);
    let router: Arc<dyn TunnelRouter> =
        Arc::new(SingleTunnelRouter::new("udp-tunnel", target, None));

    // Bind real TCP listener for SOCKS5 server to exercise real UDP relay sockets
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let s5_addr = listener.local_addr().unwrap();

    let r = Arc::clone(&router);
    tokio::spawn(async move {
        if let Ok((stream, _)) = listener.accept().await {
            let _ = handle_socks5(stream, r).await;
        }
    });

    // Client connects via TCP control connection
    let mut tcp_client = TcpStream::connect(s5_addr).await.unwrap();

    // 1. Greeting
    tcp_client
        .write_all(&[SOCKS5_VERSION, 1, METHOD_NO_AUTH])
        .await
        .unwrap();
    let mut g_resp = [0u8; 2];
    tcp_client.read_exact(&mut g_resp).await.unwrap();
    assert_eq!(g_resp[1], METHOD_NO_AUTH);

    // 2. CMD_UDP_ASSOCIATE
    let cmd = [
        SOCKS5_VERSION,
        CMD_UDP_ASSOCIATE,
        0x00,
        ATYP_IPV4,
        0,
        0,
        0,
        0,
        0,
        0,
    ];
    tcp_client.write_all(&cmd).await.unwrap();

    let mut reply_hdr = [0u8; 4];
    tcp_client.read_exact(&mut reply_hdr).await.unwrap();
    assert_eq!(reply_hdr[1], REP_SUCCESS);

    let relay_addr = match reply_hdr[3] {
        ATYP_IPV4 => {
            let mut buf = [0u8; 6];
            tcp_client.read_exact(&mut buf).await.unwrap();
            let ip = Ipv4Addr::new(buf[0], buf[1], buf[2], buf[3]);
            let port = u16::from_be_bytes([buf[4], buf[5]]);
            let ip = if ip.is_unspecified() {
                s5_addr.ip()
            } else {
                IpAddr::V4(ip)
            };
            SocketAddr::new(ip, port)
        }
        _ => panic!("Expected IPv4 relay address"),
    };

    // 3. Client binds UDP socket and sends datagram to relay address targeting echo server
    let client_udp = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let target_dest = TargetAddr::Ip(echo_udp_addr);
    let payload = b"hello_socks5_udp_relay!";
    let encap_pkt = build_socks5_udp_packet(&target_dest, payload);

    client_udp.send_to(&encap_pkt, relay_addr).await.unwrap();

    // 4. Client receives echoed datagram from relay socket
    let mut resp_buf = vec![0u8; 2048];
    let (n, from_relay) =
        tokio::time::timeout(Duration::from_secs(2), client_udp.recv_from(&mut resp_buf))
            .await
            .expect("Timeout waiting for relayed UDP")
            .unwrap();

    assert_eq!(from_relay, relay_addr);
    let (from_target, echoed_payload) =
        parse_socks5_udp_packet(&resp_buf[..n]).expect("Failed to parse echoed packet");
    assert_eq!(from_target, target_dest);
    assert_eq!(echoed_payload, payload);
}

// -----------------------------------------------------------------------------
// HTTP Proxy Tests: CONNECT & Forward Proxy
// -----------------------------------------------------------------------------

#[test]
fn test_parse_authority() {
    assert_eq!(
        parse_authority("example.com:443"),
        Some(("example.com".to_string(), 443))
    );
    assert_eq!(
        parse_authority("1.2.3.4:8080"),
        Some(("1.2.3.4".to_string(), 8080))
    );
    assert_eq!(
        parse_authority("[::1]:9000"),
        Some(("::1".to_string(), 9000))
    );
    assert_eq!(parse_authority("invalid"), None);
    assert_eq!(parse_authority("example.com:notaport"), None);
}

#[test]
fn test_extract_basic_auth() {
    let mut headers = HashMap::new();
    headers.insert(
        "proxy-authorization".to_string(),
        format_basic_auth("user1", "pass1"),
    );
    assert_eq!(
        extract_basic_auth(&headers),
        Some(("user1".to_string(), "pass1".to_string()))
    );

    let mut empty_headers = HashMap::new();
    assert_eq!(extract_basic_auth(&empty_headers), None);

    empty_headers.insert(
        "proxy-authorization".to_string(),
        "Bearer token123".to_string(),
    );
    assert_eq!(extract_basic_auth(&empty_headers), None);
}

#[tokio::test]
async fn test_read_http_request_headers_unit() {
    let raw = b"GET http://example.com/index.html HTTP/1.1\r\nHost: example.com\r\nUser-Agent: test\r\n\r\nbody";
    let (mut client, mut server) = tokio::io::duplex(256);
    tokio::spawn(async move {
        server.write_all(raw).await.unwrap();
    });

    let (method, uri, version, headers, leftover) = read_http_request_headers_buffered(&mut client)
        .await
        .unwrap();
    assert_eq!(method, "GET");
    assert_eq!(uri, "http://example.com/index.html");
    assert_eq!(version, "HTTP/1.1");
    assert_eq!(headers.get("host").unwrap(), "example.com");
    assert_eq!(headers.get("user-agent").unwrap(), "test");
    assert_eq!(&leftover, b"body");
}

#[tokio::test]
async fn test_http_connect_no_auth() {
    let echo_addr = spawn_echo_tcp_server().await;
    let target = Arc::new(DirectTunnelTarget);
    let router: Arc<dyn TunnelRouter> =
        Arc::new(SingleTunnelRouter::new("http-tunnel", target, None));

    let (mut client, server) = tokio::io::duplex(2048);
    tokio::spawn(async move {
        let _ = handle_http(server, router).await;
    });

    let connect_req = format!(
        "CONNECT {} HTTP/1.1\r\nHost: {}\r\n\r\n",
        echo_addr, echo_addr
    );
    client.write_all(connect_req.as_bytes()).await.unwrap();

    // Read 200 Connection Established response
    let (status, reason, _, _) = read_http_headers_helper(&mut client).await.unwrap();
    assert_eq!(status, 200);
    assert!(reason.contains("Connection Established"));

    // Tunnel data transfer
    client.write_all(b"http_tunneled_bytes").await.unwrap();
    let mut buf = [0u8; 19];
    client.read_exact(&mut buf).await.unwrap();
    assert_eq!(&buf, b"http_tunneled_bytes");
}

#[tokio::test]
async fn test_http_basic_auth_challenge_and_success() {
    let echo_addr = spawn_echo_tcp_server().await;
    let target = Arc::new(DirectTunnelTarget);
    let router: Arc<dyn TunnelRouter> = Arc::new(SingleTunnelRouter::new(
        "auth-http",
        target,
        Some(("proxyuser".to_string(), "proxypass123".to_string())),
    ));

    // Case 1: Unauthenticated -> 407 Proxy Authentication Required
    {
        let (mut client, server) = tokio::io::duplex(1024);
        let r = Arc::clone(&router);
        tokio::spawn(async move {
            let _ = handle_http(server, r).await;
        });

        let req = format!(
            "CONNECT {} HTTP/1.1\r\nHost: {}\r\n\r\n",
            echo_addr, echo_addr
        );
        client.write_all(req.as_bytes()).await.unwrap();

        let (status, _, headers, _) = read_http_headers_helper(&mut client).await.unwrap();
        assert_eq!(status, 407);
        assert!(headers.contains_key("proxy-authenticate"));
    }

    // Case 2: Wrong credentials -> 407
    {
        let (mut client, server) = tokio::io::duplex(1024);
        let r = Arc::clone(&router);
        tokio::spawn(async move {
            let _ = handle_http(server, r).await;
        });

        let auth_hdr = format_basic_auth("proxyuser", "wrongpassword");
        let req = format!(
            "CONNECT {} HTTP/1.1\r\nHost: {}\r\nProxy-Authorization: {}\r\n\r\n",
            echo_addr, echo_addr, auth_hdr
        );
        client.write_all(req.as_bytes()).await.unwrap();

        let (status, _, _, _) = read_http_headers_helper(&mut client).await.unwrap();
        assert_eq!(status, 407);
    }

    // Case 3: Valid credentials -> 200 OK
    {
        let (mut client, server) = tokio::io::duplex(2048);
        let r = Arc::clone(&router);
        tokio::spawn(async move {
            let _ = handle_http(server, r).await;
        });

        let auth_hdr = format_basic_auth("proxyuser", "proxypass123");
        let req = format!(
            "CONNECT {} HTTP/1.1\r\nHost: {}\r\nProxy-Authorization: {}\r\n\r\n",
            echo_addr, echo_addr, auth_hdr
        );
        client.write_all(req.as_bytes()).await.unwrap();

        let (status, _, _, _) = read_http_headers_helper(&mut client).await.unwrap();
        assert_eq!(status, 200);

        client
            .write_all(b"authenticated_http_tunnel")
            .await
            .unwrap();
        let mut buf = [0u8; 25];
        client.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"authenticated_http_tunnel");
    }
}

#[tokio::test]
async fn test_http_forward_proxy() {
    let mock_server_addr = spawn_mock_http_server("forward_proxy_payload_ok").await;
    let target = Arc::new(DirectTunnelTarget);
    let router: Arc<dyn TunnelRouter> =
        Arc::new(SingleTunnelRouter::new("fwd-tunnel", target, None));

    let (mut client, server) = tokio::io::duplex(4096);
    tokio::spawn(async move {
        let _ = handle_http(server, router).await;
    });

    let req = format!(
        "GET http://{}/test/api HTTP/1.1\r\nHost: {}\r\nUser-Agent: test\r\n\r\n",
        mock_server_addr, mock_server_addr
    );
    client.write_all(req.as_bytes()).await.unwrap();

    let (status, _, _, body) = read_http_headers_helper(&mut client).await.unwrap();
    assert_eq!(status, 200);
    assert_eq!(String::from_utf8_lossy(&body), "forward_proxy_payload_ok");
}

#[tokio::test]
async fn test_http_forward_proxy_ipv6_bracket() {
    let mock_server_addr = spawn_mock_http_server("ipv6_bracket_ok").await;
    // mock_server_addr is IPv4 127.0.0.1:port. Now test IPv6 mock server if IPv6 available
    if let Some(v6_addr) = spawn_echo_tcp_server_ipv6().await {
        let Some((host, port)) = parse_authority(&format!("[::1]:{}", v6_addr.port())) else {
            panic!("failed to parse [::1]:port");
        };
        assert_eq!(host, "::1");
        assert_eq!(port, v6_addr.port());
    }

    let target = Arc::new(DirectTunnelTarget);
    let router: Arc<dyn TunnelRouter> =
        Arc::new(SingleTunnelRouter::new("fwd-tunnel-v6", target, None));
    let (mut client, server) = tokio::io::duplex(4096);
    tokio::spawn(async move {
        let _ = handle_http(server, router).await;
    });

    let req = format!(
        "GET http://{}/test/api HTTP/1.1\r\nHost: {}\r\nConnection: keep-alive\r\n\r\n",
        mock_server_addr, mock_server_addr
    );
    client.write_all(req.as_bytes()).await.unwrap();

    let (status, _, _, body) = read_http_headers_helper(&mut client).await.unwrap();
    assert_eq!(status, 200);
    assert_eq!(String::from_utf8_lossy(&body), "ipv6_bracket_ok");
}

#[tokio::test]
async fn test_http_bad_request_handling() {
    let target = Arc::new(DirectTunnelTarget);
    let router: Arc<dyn TunnelRouter> = Arc::new(SingleTunnelRouter::new("test", target, None));

    let (mut client, server) = tokio::io::duplex(1024);
    tokio::spawn(async move {
        let _ = handle_http(server, router).await;
    });

    client
        .write_all(b"MALFORMED_REQUEST_LINE\r\n\r\n")
        .await
        .unwrap();
    let (status, _, _, _) = read_http_headers_helper(&mut client).await.unwrap();
    assert_eq!(status, 400);
}

// -----------------------------------------------------------------------------
// Router Tests: Username Selectors & Multi-Tunnel Pool
// -----------------------------------------------------------------------------

#[test]
fn test_tunnel_selector_parsing() {
    assert_eq!(TunnelSelector::parse(""), TunnelSelector::DefaultPool);
    assert_eq!(
        TunnelSelector::parse("default"),
        TunnelSelector::DefaultPool
    );
    assert_eq!(
        TunnelSelector::parse("auto"),
        TunnelSelector::ByKeyword(PoolKeyword::Auto)
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
        TunnelSelector::parse("roundrobin"),
        TunnelSelector::ByKeyword(PoolKeyword::RoundRobin)
    );
    assert_eq!(
        TunnelSelector::parse("least-conn"),
        TunnelSelector::ByKeyword(PoolKeyword::LeastConn)
    );
    assert_eq!(
        TunnelSelector::parse("tag:streaming"),
        TunnelSelector::ByTag("streaming".to_string())
    );
    assert_eq!(
        TunnelSelector::parse("wgcf-042"),
        TunnelSelector::ById("wgcf-042".to_string())
    );
}

#[tokio::test]
async fn test_pool_router_routing_and_round_robin() {
    let t1 = Arc::new(MockTunnelTarget::new("wgcf-001"));
    let t2 = Arc::new(MockTunnelTarget::new("wgcf-002"));

    let pool = Arc::new(
        PoolRouter::new(PoolStrategy::RoundRobin, true)
            .with_auth(AuthMode::Global, Some("globalpass".to_string())),
    );
    pool.add_tunnel("wgcf-001", Arc::clone(&t1) as Arc<dyn ProxyTunnelTarget>);
    pool.add_tunnel("wgcf-002", Arc::clone(&t2) as Arc<dyn ProxyTunnelTarget>);

    // 1. Authenticate with username specifying explicit tunnel ID
    let sel1 = pool.authenticate(Some(("wgcf-001", "globalpass"))).unwrap();
    assert_eq!(sel1, TunnelSelector::ById("wgcf-001".to_string()));
    let target1 = pool.select_tunnel(&sel1).await.unwrap();
    assert!(Arc::ptr_eq(
        &target1,
        &(Arc::clone(&t1) as Arc<dyn ProxyTunnelTarget>)
    ));

    // 2. Authenticate with "auto" keyword
    let sel_auto = pool.authenticate(Some(("auto", "globalpass"))).unwrap();
    assert_eq!(sel_auto, TunnelSelector::ByKeyword(PoolKeyword::Auto));

    // 3. Test round-robin cycling
    let t_first = pool
        .select_tunnel(&TunnelSelector::DefaultPool)
        .await
        .unwrap();
    let t_second = pool
        .select_tunnel(&TunnelSelector::DefaultPool)
        .await
        .unwrap();
    let t_third = pool
        .select_tunnel(&TunnelSelector::DefaultPool)
        .await
        .unwrap();

    assert!(Arc::ptr_eq(
        &t_first,
        &(Arc::clone(&t1) as Arc<dyn ProxyTunnelTarget>)
    ));
    assert!(Arc::ptr_eq(
        &t_second,
        &(Arc::clone(&t2) as Arc<dyn ProxyTunnelTarget>)
    ));
    assert!(Arc::ptr_eq(
        &t_third,
        &(Arc::clone(&t1) as Arc<dyn ProxyTunnelTarget>)
    ));
}

// -----------------------------------------------------------------------------
// Test Helpers
// -----------------------------------------------------------------------------

fn format_basic_auth(user: &str, pass: &str) -> String {
    use base64::Engine;
    let creds = format!("{}:{}", user, pass);
    let b64 = base64::prelude::BASE64_STANDARD.encode(creds.as_bytes());
    format!("Basic {}", b64)
}

async fn read_http_headers_helper<R: AsyncReadExt + Unpin>(
    reader: &mut R,
) -> io::Result<(u16, String, HashMap<String, String>, Vec<u8>)> {
    let mut header_bytes = Vec::new();
    let mut b = [0u8; 1];
    while header_bytes.len() < 16384 {
        reader.read_exact(&mut b).await?;
        header_bytes.push(b[0]);
        if header_bytes.ends_with(b"\r\n\r\n") {
            break;
        }
    }
    let header_str = String::from_utf8_lossy(&header_bytes);
    let mut lines = header_str.split("\r\n");
    let status_line = lines
        .next()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "empty status line"))?;
    let parts: Vec<&str> = status_line.split_whitespace().collect();
    let status_code: u16 = parts.get(1).and_then(|s| s.parse().ok()).unwrap_or(0);
    let reason = parts.get(2..).map(|p| p.join(" ")).unwrap_or_default();

    let mut headers = HashMap::new();
    for line in lines {
        if line.is_empty() {
            break;
        }
        if let Some((k, v)) = line.split_once(':') {
            headers.insert(k.trim().to_ascii_lowercase(), v.trim().to_string());
        }
    }

    let mut body = Vec::new();
    if let Some(len_str) = headers.get("content-length")
        && let Ok(len) = len_str.parse::<usize>()
        && len > 0
    {
        body.resize(len, 0);
        reader.read_exact(&mut body).await?;
    }

    Ok((status_code, reason, headers, body))
}

#[tokio::test]
async fn test_http_forward_rejects_mismatched_and_duplicate_host() {
    let target: Arc<dyn ProxyTunnelTarget> = Arc::new(DirectTunnelTarget);
    let router: Arc<dyn TunnelRouter> = Arc::new(SingleTunnelRouter::new("test", target, None));

    // Mismatched Host header
    let (mut client, server) = tokio::io::duplex(2048);
    let r1 = Arc::clone(&router);
    tokio::spawn(async move {
        let _ = handle_http(server, r1).await;
    });
    client
        .write_all(b"GET http://127.0.0.1:8080/test HTTP/1.1\r\nHost: evil.example\r\n\r\n")
        .await
        .unwrap();
    let (status, _, _, _) = read_http_headers_helper(&mut client).await.unwrap();
    assert_eq!(status, 400);

    // Duplicate Host header
    let (mut client2, server2) = tokio::io::duplex(2048);
    tokio::spawn(async move {
        let _ = handle_http(server2, router).await;
    });
    client2
        .write_all(b"GET http://127.0.0.1:8080/test HTTP/1.1\r\nHost: 127.0.0.1:8080\r\nHost: evil.example\r\n\r\n")
        .await
        .unwrap();
    let (status2, _, _, _) = read_http_headers_helper(&mut client2).await.unwrap();
    assert_eq!(status2, 400);
}

#[tokio::test]
async fn test_http_connect_blocks_link_local_ssrf() {
    let target: Arc<dyn ProxyTunnelTarget> = Arc::new(DirectTunnelTarget);
    let router: Arc<dyn TunnelRouter> = Arc::new(SingleTunnelRouter::new("test", target, None));

    let (mut client, server) = tokio::io::duplex(2048);
    tokio::spawn(async move {
        let _ = handle_http(server, router).await;
    });
    client
        .write_all(b"CONNECT 169.254.169.254:80 HTTP/1.1\r\nHost: 169.254.169.254:80\r\n\r\n")
        .await
        .unwrap();
    let (status, _, _, _) = read_http_headers_helper(&mut client).await.unwrap();
    assert_eq!(status, 403);
}

#[test]
fn test_socks5_udp_rejects_empty_domain_and_zero_port() {
    // Empty domain (ATYP=0x03, len=0)
    let empty_dom = [0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x50, b'h', b'i'];
    assert!(parse_socks5_udp_packet(&empty_dom).is_none());

    // Port 0
    let zero_port = [0x00, 0x00, 0x00, 0x01, 1, 1, 1, 1, 0x00, 0x00, b'h', b'i'];
    assert!(parse_socks5_udp_packet(&zero_port).is_none());
}
