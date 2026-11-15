//! SOCKS5 Proxy Protocol Engine (RFC 1928 & RFC 1929).
//!
//! Implements RFC 1928 greeting handshake, RFC 1929 username/password authentication,
//! TCP stream tunneling via `CMD_CONNECT`, and UDP datagram relaying via `CMD_UDP_ASSOCIATE`.

use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};
use std::sync::Arc;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::proxy::router::{
    DynStream, ProxyTunnelTarget, ProxyUdpSocket, TargetAddr, TunnelRouter, TunnelSelector,
};

// SOCKS Protocol Versions
pub const SOCKS5_VERSION: u8 = 0x05;
pub const RFC1929_VERSION: u8 = 0x01;

// Authentication Methods (RFC 1928 Section 3)
pub const METHOD_NO_AUTH: u8 = 0x00;
pub const METHOD_GSSAPI: u8 = 0x01;
pub const METHOD_USER_PASS: u8 = 0x02;
pub const METHOD_NO_ACCEPTABLE: u8 = 0xFF;

// Command Codes (RFC 1928 Section 4)
pub const CMD_CONNECT: u8 = 0x01;
pub const CMD_BIND: u8 = 0x02;
pub const CMD_UDP_ASSOCIATE: u8 = 0x03;

// Address Types (RFC 1928 Section 5)
pub const ATYP_IPV4: u8 = 0x01;
pub const ATYP_DOMAIN: u8 = 0x03;
pub const ATYP_IPV6: u8 = 0x04;

// Reply Codes (RFC 1928 Section 6)
pub const REP_SUCCESS: u8 = 0x00;
pub const REP_GENERAL_FAILURE: u8 = 0x01;
pub const REP_CONN_NOT_ALLOWED: u8 = 0x02;
pub const REP_NETWORK_UNREACHABLE: u8 = 0x03;
pub const REP_HOST_UNREACHABLE: u8 = 0x04;
pub const REP_CONN_REFUSED: u8 = 0x05;
pub const REP_TTL_EXPIRED: u8 = 0x06;
pub const REP_CMD_NOT_SUPPORTED: u8 = 0x07;
pub const REP_ADDR_NOT_SUPPORTED: u8 = 0x08;

/// Encodes a [`TargetAddr`] into SOCKS5 address format `[ATYP, ADDR, PORT]`.
pub fn encode_target_addr(target: &TargetAddr, buf: &mut Vec<u8>) {
    match target {
        TargetAddr::Ip(SocketAddr::V4(v4)) => {
            buf.push(ATYP_IPV4);
            buf.extend_from_slice(&v4.ip().octets());
            buf.extend_from_slice(&v4.port().to_be_bytes());
        }
        TargetAddr::Ip(SocketAddr::V6(v6)) => {
            buf.push(ATYP_IPV6);
            buf.extend_from_slice(&v6.ip().octets());
            buf.extend_from_slice(&v6.port().to_be_bytes());
        }
        TargetAddr::Domain(domain, port) => {
            buf.push(ATYP_DOMAIN);
            let bytes = domain.as_bytes();
            let len = bytes.len().min(255) as u8;
            buf.push(len);
            buf.extend_from_slice(&bytes[..len as usize]);
            buf.extend_from_slice(&port.to_be_bytes());
        }
    }
}

/// Encodes a [`TargetAddr`] into a pre-allocated slice in SOCKS5 format, returning the number of bytes written.
pub fn encode_target_addr_slice(target: &TargetAddr, buf: &mut [u8]) -> usize {
    match target {
        TargetAddr::Ip(SocketAddr::V4(v4)) => {
            buf[0] = ATYP_IPV4;
            buf[1..5].copy_from_slice(&v4.ip().octets());
            buf[5..7].copy_from_slice(&v4.port().to_be_bytes());
            7
        }
        TargetAddr::Ip(SocketAddr::V6(v6)) => {
            buf[0] = ATYP_IPV6;
            buf[1..17].copy_from_slice(&v6.ip().octets());
            buf[17..19].copy_from_slice(&v6.port().to_be_bytes());
            19
        }
        TargetAddr::Domain(domain, port) => {
            buf[0] = ATYP_DOMAIN;
            let bytes = domain.as_bytes();
            let len = bytes.len().min(255);
            buf[1] = len as u8;
            buf[2..2 + len].copy_from_slice(&bytes[..len]);
            buf[2 + len..4 + len].copy_from_slice(&port.to_be_bytes());
            4 + len
        }
    }
}

/// Writes RFC 1928 SOCKS5 UDP header `[RSV 2B, FRAG 1B, ATYP, ADDR, PORT]` into a pre-allocated slice.
pub fn write_socks5_udp_header(target: &TargetAddr, out: &mut [u8]) -> usize {
    out[0] = 0x00;
    out[1] = 0x00;
    out[2] = 0x00;
    let addr_len = encode_target_addr_slice(target, &mut out[3..]);
    3 + addr_len
}

/// Sends a formatted SOCKS5 reply `[VER, REP, RSV, ATYP, BND.ADDR, BND.PORT]`.
pub async fn send_socks5_reply<W: AsyncWrite + Unpin>(
    writer: &mut W,
    rep: u8,
    bnd_addr: SocketAddr,
) -> io::Result<()> {
    let mut reply = [0u8; 32];
    reply[0] = SOCKS5_VERSION;
    reply[1] = rep;
    reply[2] = 0x00;
    let len = encode_target_addr_slice(&TargetAddr::Ip(bnd_addr), &mut reply[3..]);
    writer.write_all(&reply[..3 + len]).await?;
    writer.flush().await
}

/// Parses an RFC 1928 UDP datagram: `[RSV 2B, FRAG 1B, ATYP 1B, DST.ADDR, DST.PORT, Payload]`.
pub fn parse_socks5_udp_packet(buf: &[u8]) -> Option<(TargetAddr, &[u8])> {
    if buf.len() < 4 {
        return None;
    }
    // buf[0..2] is RSV (0x00, 0x00)
    // buf[2] is FRAG (fragment index); we drop non-zero fragments as standalone is standard
    if buf[2] != 0 {
        return None;
    }

    let atyp = buf[3];
    let mut offset = 4;
    let target = match atyp {
        ATYP_IPV4 => {
            if buf.len() < offset + 4 + 2 {
                return None;
            }
            let ip = Ipv4Addr::new(buf[offset], buf[offset + 1], buf[offset + 2], buf[offset + 3]);
            let port = u16::from_be_bytes([buf[offset + 4], buf[offset + 5]]);
            offset += 6;
            TargetAddr::Ip(SocketAddr::V4(SocketAddrV4::new(ip, port)))
        }
        ATYP_DOMAIN => {
            if buf.len() < offset + 1 {
                return None;
            }
            let len = buf[offset] as usize;
            offset += 1;
            if buf.len() < offset + len + 2 {
                return None;
            }
            let domain = String::from_utf8(buf[offset..offset + len].to_vec()).ok()?;
            offset += len;
            let port = u16::from_be_bytes([buf[offset], buf[offset + 1]]);
            offset += 2;
            TargetAddr::Domain(domain, port)
        }
        ATYP_IPV6 => {
            if buf.len() < offset + 16 + 2 {
                return None;
            }
            let mut octets = [0u8; 16];
            octets.copy_from_slice(&buf[offset..offset + 16]);
            let ip = Ipv6Addr::from(octets);
            offset += 16;
            let port = u16::from_be_bytes([buf[offset], buf[offset + 1]]);
            offset += 2;
            TargetAddr::Ip(SocketAddr::V6(SocketAddrV6::new(ip, port, 0, 0)))
        }
        _ => return None,
    };

    Some((target, &buf[offset..]))
}

/// Encapsulates a payload into an RFC 1928 UDP relay datagram.
pub fn build_socks5_udp_packet(target: &TargetAddr, payload: &[u8]) -> Vec<u8> {
    let mut pkt = Vec::with_capacity(10 + payload.len());
    pkt.push(0x00); // RSV
    pkt.push(0x00); // RSV
    pkt.push(0x00); // FRAG: 0
    encode_target_addr(target, &mut pkt);
    pkt.extend_from_slice(payload);
    pkt
}

/// Core SOCKS5 connection handler.
///
/// Accepts an incoming client stream, executes the greeting and authentication handshake,
/// processes commands (`CONNECT` or `UDP ASSOCIATE`), and routes traffic to the virtual tunnel.
pub async fn handle_socks5<S>(stream: S, router: Arc<dyn TunnelRouter>) -> io::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    handle_socks5_with_addrs(stream, router, None, None).await
}

/// Core SOCKS5 connection handler with explicit local and peer IP addresses from the TCP control socket.
///
/// When `local_ip` and `peer_ip` are provided, `UDP ASSOCIATE` binds the relay socket to `local_ip`
/// (returning a non-unspecified `BND.ADDR`) and restricts the first UDP datagram to `peer_ip`.
pub async fn handle_socks5_with_addrs<S>(
    mut stream: S,
    router: Arc<dyn TunnelRouter>,
    local_ip: Option<IpAddr>,
    peer_ip: Option<IpAddr>,
) -> io::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    // -------------------------------------------------------------------------
    // Phase 1: Greeting & Method Selection (RFC 1928 Section 3)
    // -------------------------------------------------------------------------
    let mut header = [0u8; 2];
    stream.read_exact(&mut header).await?;
    if header[0] != SOCKS5_VERSION {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("unsupported SOCKS version: 0x{:02X}", header[0]),
        ));
    }

    let nmethods = header[1] as usize;
    if nmethods == 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "no authentication methods offered by client",
        ));
    }

    let mut methods = vec![0u8; nmethods];
    stream.read_exact(&mut methods).await?;

    let allow_anonymous = router.authenticate(None).is_ok();

    let chosen_method = if allow_anonymous {
        if methods.contains(&METHOD_NO_AUTH) {
            METHOD_NO_AUTH
        } else if methods.contains(&METHOD_USER_PASS) {
            METHOD_USER_PASS
        } else {
            METHOD_NO_ACCEPTABLE
        }
    } else {
        if methods.contains(&METHOD_USER_PASS) {
            METHOD_USER_PASS
        } else {
            METHOD_NO_ACCEPTABLE
        }
    };

    stream.write_all(&[SOCKS5_VERSION, chosen_method]).await?;
    stream.flush().await?;

    if chosen_method == METHOD_NO_ACCEPTABLE {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "no acceptable authentication method agreed upon",
        ));
    }

    // -------------------------------------------------------------------------
    // Phase 2: RFC 1929 Subnegotiation (if User/Pass chosen)
    // -------------------------------------------------------------------------
    let selector = if chosen_method == METHOD_USER_PASS {
        let mut auth_ver = [0u8; 2];
        stream.read_exact(&mut auth_ver).await?;
        if auth_ver[0] != RFC1929_VERSION {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("unsupported RFC 1929 auth version: 0x{:02X}", auth_ver[0]),
            ));
        }

        let ulen = auth_ver[1] as usize;
        let mut uname_buf = vec![0u8; ulen];
        stream.read_exact(&mut uname_buf).await?;

        let mut plen_buf = [0u8; 1];
        stream.read_exact(&mut plen_buf).await?;
        let plen = plen_buf[0] as usize;
        let mut pass_buf = vec![0u8; plen];
        stream.read_exact(&mut pass_buf).await?;

        let username = String::from_utf8_lossy(&uname_buf);
        let password = String::from_utf8_lossy(&pass_buf);

        match router.authenticate(Some((&username, &password))) {
            Ok(sel) => {
                stream.write_all(&[RFC1929_VERSION, 0x00]).await?;
                stream.flush().await?;
                sel
            }
            Err(err) => {
                tracing::debug!("SOCKS5 RFC 1929 authentication rejected: {:?}", err);
                stream.write_all(&[RFC1929_VERSION, 0x01]).await?;
                stream.flush().await?;
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "authentication rejected",
                ));
            }
        }
    } else {
        router.authenticate(None).map_err(|e| {
            io::Error::new(
                io::ErrorKind::PermissionDenied,
                format!("anonymous access not permitted: {:?}", e),
            )
        })?
    };

    // -------------------------------------------------------------------------
    // Phase 3: Command Request (RFC 1928 Section 4)
    // -------------------------------------------------------------------------
    let mut cmd_hdr = [0u8; 4];
    stream.read_exact(&mut cmd_hdr).await?;
    if cmd_hdr[0] != SOCKS5_VERSION {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid version in SOCKS5 command request",
        ));
    }

    let cmd = cmd_hdr[1];
    let atyp = cmd_hdr[3];

    let target = match atyp {
        ATYP_IPV4 => {
            let mut buf = [0u8; 6];
            stream.read_exact(&mut buf).await?;
            let ip = Ipv4Addr::new(buf[0], buf[1], buf[2], buf[3]);
            let port = u16::from_be_bytes([buf[4], buf[5]]);
            TargetAddr::Ip(SocketAddr::V4(SocketAddrV4::new(ip, port)))
        }
        ATYP_DOMAIN => {
            let mut len_buf = [0u8; 1];
            stream.read_exact(&mut len_buf).await?;
            let len = len_buf[0] as usize;
            let mut dom_buf = vec![0u8; len];
            stream.read_exact(&mut dom_buf).await?;
            let domain = String::from_utf8(dom_buf).map_err(|_| {
                io::Error::new(io::ErrorKind::InvalidData, "invalid domain string")
            })?;
            let mut port_buf = [0u8; 2];
            stream.read_exact(&mut port_buf).await?;
            let port = u16::from_be_bytes(port_buf);
            TargetAddr::Domain(domain, port)
        }
        ATYP_IPV6 => {
            let mut buf = [0u8; 18];
            stream.read_exact(&mut buf).await?;
            let mut octets = [0u8; 16];
            octets.copy_from_slice(&buf[0..16]);
            let ip = Ipv6Addr::from(octets);
            let port = u16::from_be_bytes([buf[16], buf[17]]);
            TargetAddr::Ip(SocketAddr::V6(SocketAddrV6::new(ip, port, 0, 0)))
        }
        other => {
            let dummy_addr = SocketAddr::from(([0, 0, 0, 0], 0));
            let _ = send_socks5_reply(&mut stream, REP_ADDR_NOT_SUPPORTED, dummy_addr).await;
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("unsupported address type 0x{:02X}", other),
            ));
        }
    };

    // -------------------------------------------------------------------------
    // Phase 4: Command Execution (CONNECT or UDP ASSOCIATE)
    // -------------------------------------------------------------------------
    match cmd {
        CMD_CONNECT => {
            handle_connect(stream, router, &selector, target).await
        }
        CMD_UDP_ASSOCIATE => {
            handle_udp_associate(stream, router, &selector, local_ip, peer_ip).await
        }
        other => {
            let dummy_addr = SocketAddr::from(([0, 0, 0, 0], 0));
            let _ = send_socks5_reply(&mut stream, REP_CMD_NOT_SUPPORTED, dummy_addr).await;
            Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("unsupported SOCKS5 command 0x{:02X}", other),
            ))
        }
    }
}

/// Executes SOCKS5 `CMD_CONNECT` TCP stream tunneling.
async fn handle_connect<S: AsyncRead + AsyncWrite + Unpin>(
    mut stream: S,
    router: Arc<dyn TunnelRouter>,
    selector: &TunnelSelector,
    target: TargetAddr,
) -> io::Result<()> {
    let dummy_addr = SocketAddr::from(([0, 0, 0, 0], 0));

    // Resolve tunnel
    let target_tunnel = match router.select_tunnel(selector).await {
        Ok(t) => t,
        Err(e) => {
            tracing::warn!("Failed to select tunnel for {:?}: {:?}", selector, e);
            let _ = send_socks5_reply(&mut stream, REP_HOST_UNREACHABLE, dummy_addr).await;
            return Err(e);
        }
    };

    // Resolve target IP destination
    let dst_addr = match target {
        TargetAddr::Ip(addr) => addr,
        TargetAddr::Domain(ref domain, port) => {
            match target_tunnel.resolve_in_tunnel(domain).await {
                Ok(ip) => SocketAddr::new(ip, port),
                Err(e) => {
                    tracing::warn!("Failed to resolve target domain '{}': {:?}", domain, e);
                    let _ = send_socks5_reply(&mut stream, REP_HOST_UNREACHABLE, dummy_addr).await;
                    return Err(e);
                }
            }
        }
    };

    // Connect to target via tunnel connector
    let mut tunnel_stream: DynStream = match target_tunnel.tcp_connect(dst_addr).await {
        Ok(s) => s,
        Err(e) => {
            let rep = match e.kind() {
                io::ErrorKind::ConnectionRefused => REP_CONN_REFUSED,
                io::ErrorKind::TimedOut => REP_TTL_EXPIRED,
                io::ErrorKind::AddrNotAvailable => REP_HOST_UNREACHABLE,
                _ => REP_GENERAL_FAILURE,
            };
            let _ = send_socks5_reply(&mut stream, rep, dummy_addr).await;
            return Err(e);
        }
    };

    // Send SOCKS5 success reply
    send_socks5_reply(&mut stream, REP_SUCCESS, dummy_addr).await?;

    // Bidirectional streaming
    tokio::io::copy_bidirectional(&mut stream, &mut tunnel_stream).await?;

    Ok(())
}

/// Executes SOCKS5 `CMD_UDP_ASSOCIATE` UDP relay session.
async fn handle_udp_associate<S: AsyncRead + AsyncWrite + Unpin>(
    mut stream: S,
    router: Arc<dyn TunnelRouter>,
    selector: &TunnelSelector,
    local_ip: Option<IpAddr>,
    peer_ip: Option<IpAddr>,
) -> io::Result<()> {
    let dummy_addr = SocketAddr::from(([0, 0, 0, 0], 0));

    // Resolve tunnel
    let target_tunnel = match router.select_tunnel(selector).await {
        Ok(t) => t,
        Err(e) => {
            tracing::warn!("Failed to select tunnel for {:?}: {:?}", selector, e);
            let _ = send_socks5_reply(&mut stream, REP_HOST_UNREACHABLE, dummy_addr).await;
            return Err(e);
        }
    };

    // Bind local Tokio UDP relay socket on the control socket's local IP (fallback to loopback)
    let bind_ip = match local_ip {
        Some(ip) if !ip.is_unspecified() => ip,
        _ => IpAddr::V4(Ipv4Addr::LOCALHOST),
    };
    let bind_addr = SocketAddr::new(bind_ip, 0);
    let relay_socket = match tokio::net::UdpSocket::bind(bind_addr).await {
        Ok(s) => s,
        Err(e) => {
            tracing::error!("Failed to bind Tokio UDP relay socket on {}: {:?}", bind_addr, e);
            let _ = send_socks5_reply(&mut stream, REP_GENERAL_FAILURE, dummy_addr).await;
            return Err(e);
        }
    };
    let mut relay_addr = relay_socket.local_addr()?;
    if relay_addr.ip().is_unspecified() {
        let fallback_ip = if relay_addr.is_ipv6() {
            IpAddr::V6(Ipv6Addr::LOCALHOST)
        } else {
            IpAddr::V4(Ipv4Addr::LOCALHOST)
        };
        relay_addr.set_ip(fallback_ip);
    }

    // Bind virtual UDP socket inside the tunnel
    let virtual_udp = match target_tunnel.udp_bind(0).await {
        Ok(s) => s,
        Err(e) => {
            tracing::error!("Failed to bind virtual UDP socket in tunnel: {:?}", e);
            let _ = send_socks5_reply(&mut stream, REP_GENERAL_FAILURE, dummy_addr).await;
            return Err(e);
        }
    };

    // Respond with bound relay address
    send_socks5_reply(&mut stream, REP_SUCCESS, relay_addr).await?;

    // Run UDP relay session driven by the TCP control connection lifecycle
    run_udp_relay_loop(&mut stream, relay_socket, virtual_udp, target_tunnel, peer_ip).await
}

/// Normalizes IPv4-mapped IPv6 addresses to IPv4 for consistent peer IP comparison.
fn normalize_ip(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
            Some(v4) => IpAddr::V4(v4),
            None => IpAddr::V6(v6),
        },
        v4 => v4,
    }
}

/// Loops relaying UDP datagrams between client and tunnel until client TCP closes.
async fn run_udp_relay_loop<S: AsyncRead + Unpin>(
    control_stream: &mut S,
    relay_socket: tokio::net::UdpSocket,
    virtual_udp: Box<dyn ProxyUdpSocket>,
    target_tunnel: Arc<dyn ProxyTunnelTarget>,
    expected_client_ip: Option<IpAddr>,
) -> io::Result<()> {
    let relay_socket = Arc::new(relay_socket);
    let mut tcp_byte = [0u8; 1];
    let mut client_udp_addr: Option<SocketAddr> = None;
    let normalized_expected_ip = expected_client_ip.map(normalize_ip);

    let mut relay_buf = vec![0u8; 65536];
    let mut virtual_buf = vec![0u8; 65536];
    let mut out_pkt_buf = vec![0u8; 65536 + 32];

    loop {
        tokio::select! {
            // 1. Monitor TCP control connection for EOF / termination
            tcp_res = control_stream.read(&mut tcp_byte) => {
                match tcp_res {
                    Ok(0) | Err(_) => {
                        tracing::debug!("SOCKS5 UDP ASSOCIATE control connection closed by client");
                        break;
                    }
                    Ok(_) => {
                        // Unexpected data on control stream; continue
                    }
                }
            }

            // 2. Incoming datagram from client on Tokio UDP relay socket
            relay_res = relay_socket.recv_from(&mut relay_buf) => {
                match relay_res {
                    Ok((n, from_addr)) => {
                        if let Some(expected_addr) = client_udp_addr {
                            if expected_addr != from_addr {
                                tracing::warn!(
                                    "Ignoring UDP packet from unexpected source {}; expected locked source {}",
                                    from_addr,
                                    expected_addr
                                );
                                continue;
                            }
                        } else {
                            if let Some(expected_ip) = normalized_expected_ip
                                && normalize_ip(from_addr.ip()) != expected_ip
                            {
                                tracing::warn!(
                                    "Rejecting UDP associate packet from {} (does not match control TCP peer IP {})",
                                    from_addr,
                                    expected_ip
                                );
                                continue;
                            }
                            client_udp_addr = Some(from_addr);
                        }
                        if let Some((target_addr, payload)) = parse_socks5_udp_packet(&relay_buf[..n]) {
                            let resolved = match target_addr {
                                TargetAddr::Ip(addr) => Some(addr),
                                TargetAddr::Domain(ref dom, port) => {
                                    match target_tunnel.resolve_in_tunnel(dom).await {
                                        Ok(ip) => Some(SocketAddr::new(ip, port)),
                                        Err(e) => {
                                            tracing::warn!("Failed to resolve UDP target domain '{}': {:?}", dom, e);
                                            None
                                        }
                                    }
                                }
                            };
                            if let Some(target_sock) = resolved {
                                let _ = virtual_udp.send_to(payload, target_sock).await;
                            }
                        }
                    }
                    Err(e) => {
                        tracing::debug!("Tokio UDP relay socket recv error: {:?}", e);
                        break;
                    }
                }
            }

            // 3. Incoming datagram from tunnel on Virtual UDP socket
            virtual_res = virtual_udp.recv_from(&mut virtual_buf) => {
                match virtual_res {
                    Ok((n, peer_addr)) => {
                        if let Some(c_addr) = client_udp_addr {
                            let hdr_len = write_socks5_udp_header(&TargetAddr::Ip(peer_addr), &mut out_pkt_buf);
                            out_pkt_buf[hdr_len..hdr_len + n].copy_from_slice(&virtual_buf[..n]);
                            let _ = relay_socket.send_to(&out_pkt_buf[..hdr_len + n], c_addr).await;
                        }
                    }
                    Err(e) => {
                        tracing::debug!("Virtual UDP socket recv error: {:?}", e);
                        break;
                    }
                }
            }
        }
    }

    Ok(())
}
