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
    bound_candidate_addrs, connect_validated_addrs, is_forbidden_destination_ip,
    is_valid_target_domain, parse_domain_ip_literal, resolve_and_validate_domain,
    send_udp_to_validated_addrs,
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
            let len = bytes.len().min(255);
            buf.push(len as u8);
            if let Some(slice) = bytes.get(..len) {
                buf.extend_from_slice(slice);
            }
            buf.extend_from_slice(&port.to_be_bytes());
        }
    }
}

fn copy_into_at(dst: &mut [u8], offset: usize, src: &[u8]) -> bool {
    dst.get_mut(offset..offset + src.len()).is_some_and(|slot| {
        slot.copy_from_slice(src);
        true
    })
}

/// Encodes a [`TargetAddr`] into a pre-allocated slice in SOCKS5 format, returning the number of bytes written.
pub fn encode_target_addr_slice(target: &TargetAddr, buf: &mut [u8]) -> usize {
    match target {
        TargetAddr::Ip(SocketAddr::V4(v4)) => {
            if let Some(slot) = buf.get_mut(0) {
                *slot = ATYP_IPV4;
            }
            copy_into_at(buf, 1, &v4.ip().octets());
            copy_into_at(buf, 5, &v4.port().to_be_bytes());
            7
        }
        TargetAddr::Ip(SocketAddr::V6(v6)) => {
            if let Some(slot) = buf.get_mut(0) {
                *slot = ATYP_IPV6;
            }
            copy_into_at(buf, 1, &v6.ip().octets());
            copy_into_at(buf, 17, &v6.port().to_be_bytes());
            19
        }
        TargetAddr::Domain(domain, port) => {
            let bytes = domain.as_bytes();
            let len = bytes.len().min(255);
            if let Some(slot) = buf.get_mut(0) {
                *slot = ATYP_DOMAIN;
            }
            if let Some(slot) = buf.get_mut(1) {
                *slot = len as u8;
            }
            if let Some(src) = bytes.get(..len) {
                copy_into_at(buf, 2, src);
            }
            copy_into_at(buf, 2 + len, &port.to_be_bytes());
            4 + len
        }
    }
}

/// Writes RFC 1928 SOCKS5 UDP header `[RSV 2B, FRAG 1B, ATYP, ADDR, PORT]` into a pre-allocated slice.
pub fn write_socks5_udp_header(target: &TargetAddr, out: &mut [u8]) -> usize {
    copy_into_at(out, 0, &[0x00, 0x00, 0x00]);
    let addr_len = out
        .get_mut(3..)
        .map_or(0, |rest| encode_target_addr_slice(target, rest));
    3 + addr_len
}

/// Sends a formatted SOCKS5 reply `[VER, REP, RSV, ATYP, BND.ADDR, BND.PORT]`.
pub async fn send_socks5_reply<W: AsyncWrite + Unpin>(
    writer: &mut W,
    rep: u8,
    bnd_addr: SocketAddr,
) -> io::Result<()> {
    let mut reply = [0u8; 32];
    let len = {
        let [ver, code, rsv, rest @ ..] = &mut reply;
        *ver = SOCKS5_VERSION;
        *code = rep;
        *rsv = 0x00;
        encode_target_addr_slice(&TargetAddr::Ip(bnd_addr), rest)
    };
    if let Some(frame) = reply.get(..3 + len) {
        writer.write_all(frame).await?;
    }
    writer.flush().await
}

/// Parses an RFC 1928 UDP datagram: `[RSV 2B, FRAG 1B, ATYP 1B, DST.ADDR, DST.PORT, Payload]`.
pub fn parse_socks5_udp_packet(buf: &[u8]) -> Option<(TargetAddr, &[u8])> {
    let &[_, _, frag, atyp, ref rest @ ..] = buf else {
        return None;
    };
    // frag is FRAG (fragment index); we drop non-zero fragments as standalone is standard
    if frag != 0 {
        return None;
    }

    let (target, payload) = match atyp {
        ATYP_IPV4 => {
            let (addr_bytes, payload) = rest.split_at_checked(4)?;
            let ip_octets: [u8; 4] = addr_bytes.try_into().ok()?;
            let (port_bytes, payload) = payload.split_at_checked(2)?;
            let port_octets: [u8; 2] = port_bytes.try_into().ok()?;
            let port = u16::from_be_bytes(port_octets);
            if port == 0 {
                return None;
            }
            let addr = SocketAddrV4::new(Ipv4Addr::from(ip_octets), port);
            (TargetAddr::Ip(SocketAddr::V4(addr)), payload)
        }
        ATYP_DOMAIN => {
            let (&len_byte, after_len) = rest.split_first()?;
            let len = len_byte as usize;
            if len == 0 {
                return None;
            }
            let (domain_bytes, after_domain) = after_len.split_at_checked(len)?;
            let domain = String::from_utf8(domain_bytes.to_vec()).ok()?;
            let (port_bytes, payload) = after_domain.split_at_checked(2)?;
            let port_octets: [u8; 2] = port_bytes.try_into().ok()?;
            let port = u16::from_be_bytes(port_octets);
            if port == 0 {
                return None;
            }
            if let Some(ip) = parse_domain_ip_literal(&domain) {
                (TargetAddr::Ip(SocketAddr::new(ip, port)), payload)
            } else if is_valid_target_domain(&domain) {
                (TargetAddr::Domain(domain, port), payload)
            } else {
                return None;
            }
        }
        ATYP_IPV6 => {
            let (addr_bytes, after_addr) = rest.split_at_checked(16)?;
            let ip_octets: [u8; 16] = addr_bytes.try_into().ok()?;
            let (port_bytes, payload) = after_addr.split_at_checked(2)?;
            let port_octets: [u8; 2] = port_bytes.try_into().ok()?;
            let port = u16::from_be_bytes(port_octets);
            if port == 0 {
                return None;
            }
            let addr = SocketAddrV6::new(Ipv6Addr::from(ip_octets), port, 0, 0);
            (TargetAddr::Ip(SocketAddr::V6(addr)), payload)
        }
        _ => return None,
    };

    Some((target, payload))
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

async fn read_rfc1929_credentials<S: AsyncRead + AsyncWrite + Unpin>(
    stream: &mut S,
) -> io::Result<(String, String)> {
    let mut auth_ver = [0u8; 2];
    stream.read_exact(&mut auth_ver).await?;
    if auth_ver[0] != RFC1929_VERSION {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("unsupported RFC 1929 auth version: 0x{:02X}", auth_ver[0]),
        ));
    }

    if auth_ver[1] == 0 {
        stream.write_all(&[RFC1929_VERSION, 0x01]).await?;
        stream.flush().await?;
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "empty RFC 1929 username",
        ));
    }
    let mut uname_buf = vec![0u8; auth_ver[1] as usize];
    stream.read_exact(&mut uname_buf).await?;

    let mut plen_buf = [0u8; 1];
    stream.read_exact(&mut plen_buf).await?;
    if plen_buf[0] == 0 {
        stream.write_all(&[RFC1929_VERSION, 0x01]).await?;
        stream.flush().await?;
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "empty RFC 1929 password",
        ));
    }
    let mut pass_buf = vec![0u8; plen_buf[0] as usize];
    stream.read_exact(&mut pass_buf).await?;

    let (Ok(username), Ok(password)) = (
        std::str::from_utf8(&uname_buf),
        std::str::from_utf8(&pass_buf),
    ) else {
        stream.write_all(&[RFC1929_VERSION, 0x01]).await?;
        stream.flush().await?;
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "non-UTF-8 RFC 1929 credentials",
        ));
    };

    Ok((username.to_string(), password.to_string()))
}

async fn negotiate_socks5_auth<S: AsyncRead + AsyncWrite + Unpin>(
    stream: &mut S,
    router: &Arc<dyn TunnelRouter>,
) -> io::Result<TunnelSelector> {
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
    let chosen_method = if allow_anonymous && methods.contains(&METHOD_NO_AUTH) {
        METHOD_NO_AUTH
    } else if methods.contains(&METHOD_USER_PASS) {
        METHOD_USER_PASS
    } else {
        METHOD_NO_ACCEPTABLE
    };

    stream.write_all(&[SOCKS5_VERSION, chosen_method]).await?;
    stream.flush().await?;

    if chosen_method == METHOD_NO_ACCEPTABLE {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "no acceptable authentication method agreed upon",
        ));
    }

    if chosen_method != METHOD_USER_PASS {
        return router.authenticate(None).map_err(|e| {
            io::Error::new(
                io::ErrorKind::PermissionDenied,
                format!("anonymous access not permitted: {e:?}"),
            )
        });
    }

    let (username, password) = read_rfc1929_credentials(stream).await?;

    match router.authenticate(Some((&username, &password))) {
        Ok(sel) => {
            stream.write_all(&[RFC1929_VERSION, 0x00]).await?;
            stream.flush().await?;
            Ok(sel)
        }
        Err(err) => {
            tracing::debug!("SOCKS5 RFC 1929 authentication rejected: {:?}", err);
            stream.write_all(&[RFC1929_VERSION, 0x01]).await?;
            stream.flush().await?;
            Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "authentication rejected",
            ))
        }
    }
}

async fn read_socks5_command<S: AsyncRead + AsyncWrite + Unpin>(
    stream: &mut S,
) -> io::Result<(u8, TargetAddr)> {
    let mut cmd_hdr = [0u8; 4];
    stream.read_exact(&mut cmd_hdr).await?;
    if cmd_hdr[0] != SOCKS5_VERSION || cmd_hdr[2] != 0x00 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid version or reserved byte in SOCKS5 command request",
        ));
    }

    let cmd = cmd_hdr[1];
    let target = match cmd_hdr[3] {
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
            if len_buf[0] == 0 {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "empty domain string",
                ));
            }
            let mut dom_buf = vec![0u8; len_buf[0] as usize];
            stream.read_exact(&mut dom_buf).await?;
            let domain = String::from_utf8(dom_buf)
                .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "invalid domain string"))?;
            let mut port_buf = [0u8; 2];
            stream.read_exact(&mut port_buf).await?;
            let port = u16::from_be_bytes(port_buf);
            if let Some(ip) = parse_domain_ip_literal(&domain) {
                TargetAddr::Ip(SocketAddr::new(ip, port))
            } else if is_valid_target_domain(&domain) {
                TargetAddr::Domain(domain, port)
            } else {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "invalid domain name in SOCKS5 request",
                ));
            }
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
            let _ = send_socks5_reply(stream, REP_ADDR_NOT_SUPPORTED, dummy_addr).await;
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("unsupported address type 0x{other:02X}"),
            ));
        }
    };

    Ok((cmd, target))
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
    let handshake_timeout = std::time::Duration::from_secs(30);
    let selector = tokio::time::timeout(
        handshake_timeout,
        negotiate_socks5_auth(&mut stream, &router),
    )
    .await
    .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "SOCKS5 auth timed out"))??;
    let (cmd, target) = tokio::time::timeout(handshake_timeout, read_socks5_command(&mut stream))
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "SOCKS5 command timed out"))??;

    match cmd {
        CMD_CONNECT => {
            let port = match &target {
                TargetAddr::Ip(addr) => addr.port(),
                TargetAddr::Domain(_, p) => *p,
            };
            if port == 0 {
                let dummy_addr = SocketAddr::from(([0, 0, 0, 0], 0));
                let _ = send_socks5_reply(&mut stream, REP_GENERAL_FAILURE, dummy_addr).await;
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "CONNECT target port cannot be 0",
                ));
            }
            handle_connect(stream, router, &selector, target).await
        }
        CMD_UDP_ASSOCIATE => {
            let initial_client = match target {
                TargetAddr::Ip(addr) if !addr.ip().is_unspecified() && addr.port() != 0 => {
                    Some(addr)
                }
                TargetAddr::Ip(_) | TargetAddr::Domain(_, _) => None,
            };
            handle_udp_associate(stream, router, &selector, local_ip, peer_ip, initial_client).await
        }
        other => {
            let dummy_addr = SocketAddr::from(([0, 0, 0, 0], 0));
            let _ = send_socks5_reply(&mut stream, REP_CMD_NOT_SUPPORTED, dummy_addr).await;
            Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("unsupported SOCKS5 command 0x{other:02X}"),
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

    if let TargetAddr::Ip(addr) = &target
        && is_forbidden_destination_ip(addr.ip())
    {
        let _ = send_socks5_reply(&mut stream, REP_CONN_NOT_ALLOWED, dummy_addr).await;
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!("blocked forbidden destination IP: {}", addr.ip()),
        ));
    }

    // Resolve tunnel
    let target_tunnel = match router.select_tunnel(selector).await {
        Ok(t) => t,
        Err(e) => {
            tracing::warn!("Failed to select tunnel for {:?}: {:?}", selector, e);
            let _ = send_socks5_reply(&mut stream, REP_HOST_UNREACHABLE, dummy_addr).await;
            return Err(e);
        }
    };

    // Connect to target via tunnel connector directly from validated SocketAddr(s) (zero TOCTOU)
    let connect_res = match target {
        TargetAddr::Ip(dst_addr) => target_tunnel.tcp_connect(dst_addr).await,
        TargetAddr::Domain(ref domain, port) => {
            let ips = match resolve_and_validate_domain(target_tunnel.as_ref(), domain).await {
                Ok(ips) => ips,
                Err(e) => {
                    let rep = if e.kind() == io::ErrorKind::PermissionDenied {
                        REP_CONN_NOT_ALLOWED
                    } else {
                        REP_HOST_UNREACHABLE
                    };
                    tracing::warn!("Failed to resolve target domain '{}': {:?}", domain, e);
                    let _ = send_socks5_reply(&mut stream, rep, dummy_addr).await;
                    return Err(e);
                }
            };
            connect_validated_addrs(target_tunnel.as_ref(), &ips, port).await
        }
    };

    let mut tunnel_stream: DynStream = match connect_res {
        Ok(s) => s,
        Err(e) => {
            // `std::io::ErrorKind` is `#[non_exhaustive]` with ~40 variants; map all others to general failure.
            #[allow(clippy::wildcard_enum_match_arm)]
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
    initial_client: Option<SocketAddr>,
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
            tracing::error!(
                "Failed to bind Tokio UDP relay socket on {}: {:?}",
                bind_addr,
                e
            );
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
    run_udp_relay_loop(
        &mut stream,
        relay_socket,
        virtual_udp,
        target_tunnel,
        peer_ip,
        initial_client,
    )
    .await
}

/// Normalizes IPv4-mapped IPv6 addresses to IPv4 for consistent peer IP comparison.
const fn normalize_ip(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
            Some(v4) => IpAddr::V4(v4),
            None => IpAddr::V6(v6),
        },
        IpAddr::V4(v4) => IpAddr::V4(v4),
    }
}

const MAX_UDP_DNS_TASKS: usize = 16;

struct UdpRelayCtx<'a> {
    client_udp_addr: &'a mut Option<SocketAddr>,
    normalized_expected_ip: Option<IpAddr>,
    virtual_udp: &'a dyn ProxyUdpSocket,
    target_tunnel: &'a Arc<dyn ProxyTunnelTarget>,
    dns_tasks: &'a mut tokio::task::JoinSet<()>,
    dns_tx: &'a tokio::sync::mpsc::Sender<(Vec<SocketAddr>, Vec<u8>)>,
}

async fn forward_client_udp_datagram(
    packet: &[u8],
    from_addr: SocketAddr,
    ctx: &mut UdpRelayCtx<'_>,
) {
    if let Some(expected_addr) = *ctx.client_udp_addr {
        if expected_addr != from_addr {
            tracing::warn!(
                "Ignoring UDP packet from unexpected source {}; expected locked source {}",
                from_addr,
                expected_addr
            );
            return;
        }
    } else if let Some(expected_ip) = ctx.normalized_expected_ip
        && normalize_ip(from_addr.ip()) != expected_ip
    {
        tracing::warn!(
            "Rejecting UDP associate packet from {} (does not match control TCP peer IP {})",
            from_addr,
            expected_ip
        );
        return;
    }

    let Some((target_addr, payload)) = parse_socks5_udp_packet(packet) else {
        return;
    };
    if ctx.client_udp_addr.is_none() {
        *ctx.client_udp_addr = Some(from_addr);
    }
    match target_addr {
        TargetAddr::Ip(addr) => {
            if !is_forbidden_destination_ip(addr.ip()) {
                let _ = ctx.virtual_udp.send_to(payload, addr).await;
            }
        }
        TargetAddr::Domain(dom, port) => {
            if ctx.dns_tasks.len() >= MAX_UDP_DNS_TASKS {
                tracing::debug!(
                    "Dropping UDP datagram for '{}': DNS resolution queue full",
                    dom
                );
                return;
            }
            let tunnel = Arc::clone(ctx.target_tunnel);
            let tx = ctx.dns_tx.clone();
            let payload_owned = payload.to_vec();
            ctx.dns_tasks.spawn(async move {
                match tokio::time::timeout(
                    std::time::Duration::from_secs(5),
                    resolve_and_validate_domain(tunnel.as_ref(), &dom),
                )
                .await
                {
                    Ok(Ok(ips)) => {
                        let addrs = bound_candidate_addrs(&ips, port);
                        let _ = tx.send((addrs, payload_owned)).await;
                    }
                    Ok(Err(e)) => {
                        tracing::warn!("Failed to resolve UDP target domain '{}': {:?}", dom, e);
                    }
                    Err(_) => {
                        tracing::warn!("Timed out resolving UDP target domain '{}'", dom);
                    }
                }
            });
        }
    }
}

async fn forward_virtual_to_relay(
    payload: &[u8],
    peer_addr: SocketAddr,
    client_udp_addr: Option<SocketAddr>,
    out_pkt_buf: &mut [u8],
    relay_socket: &tokio::net::UdpSocket,
) {
    let Some(c_addr) = client_udp_addr else {
        return;
    };
    let hdr_len = write_socks5_udp_header(&TargetAddr::Ip(peer_addr), out_pkt_buf);
    if let Some(dst) = out_pkt_buf.get_mut(hdr_len..hdr_len + payload.len()) {
        dst.copy_from_slice(payload);
        if let Some(frame) = out_pkt_buf.get(..hdr_len + payload.len()) {
            let _ = relay_socket.send_to(frame, c_addr).await;
        }
    }
}

async fn dispatch_resolved_udp_datagram(
    virtual_udp: &dyn ProxyUdpSocket,
    payload: &[u8],
    addrs: &[SocketAddr],
) {
    if let Err(e) = send_udp_to_validated_addrs(virtual_udp, payload, addrs).await {
        tracing::debug!("UDP relay send to validated candidates failed: {:?}", e);
    }
}

/// Loops relaying UDP datagrams between client and tunnel until client TCP closes.
async fn run_udp_relay_loop<S: AsyncRead + Unpin>(
    control_stream: &mut S,
    relay_socket: tokio::net::UdpSocket,
    virtual_udp: Box<dyn ProxyUdpSocket>,
    target_tunnel: Arc<dyn ProxyTunnelTarget>,
    expected_client_ip: Option<IpAddr>,
    initial_client: Option<SocketAddr>,
) -> io::Result<()> {
    let relay_socket = Arc::new(relay_socket);
    let mut tcp_byte = [0u8; 1];
    let mut client_udp_addr: Option<SocketAddr> = initial_client.filter(|addr| {
        expected_client_ip.is_none_or(|exp| normalize_ip(addr.ip()) == normalize_ip(exp))
    });
    let normalized_expected_ip = expected_client_ip.map(normalize_ip);

    let mut relay_buf = vec![0u8; 65536];
    let mut virtual_buf = vec![0u8; 65536];
    let mut out_pkt_buf = vec![0u8; 65536 + 32];
    let idle_timeout = std::time::Duration::from_mins(5);
    let mut dns_tasks = tokio::task::JoinSet::new();
    let (dns_tx, mut dns_rx) = tokio::sync::mpsc::channel::<(Vec<SocketAddr>, Vec<u8>)>(64);

    loop {
        while let Some(res) = dns_tasks.try_join_next() {
            let _ = res;
        }
        tokio::select! {
            () = tokio::time::sleep(idle_timeout) => {
                tracing::debug!("SOCKS5 UDP ASSOCIATE relay timed out after {:?} of inactivity", idle_timeout);
                break;
            }
            tcp_res = control_stream.read(&mut tcp_byte) => {
                if !matches!(tcp_res, Ok(1..)) {
                    tracing::debug!("SOCKS5 UDP ASSOCIATE control connection closed by client");
                    break;
                }
            }

            Some((target_socks, payload)) = dns_rx.recv() => {
                dispatch_resolved_udp_datagram(virtual_udp.as_ref(), &payload, &target_socks).await;
            }

            relay_res = relay_socket.recv_from(&mut relay_buf) => {
                let Ok((n, from_addr)) = relay_res else {
                    tracing::debug!("Tokio UDP relay socket recv error: {:?}", relay_res.err());
                    break;
                };
                if let Some(pkt) = relay_buf.get(..n) {
                    let mut ctx = UdpRelayCtx {
                        client_udp_addr: &mut client_udp_addr,
                        normalized_expected_ip,
                        virtual_udp: virtual_udp.as_ref(),
                        target_tunnel: &target_tunnel,
                        dns_tasks: &mut dns_tasks,
                        dns_tx: &dns_tx,
                    };
                    forward_client_udp_datagram(pkt, from_addr, &mut ctx).await;
                }
            }

            virtual_res = virtual_udp.recv_from(&mut virtual_buf) => {
                let Ok((n, peer_addr)) = virtual_res else {
                    tracing::debug!("Virtual UDP socket recv error: {:?}", virtual_res.err());
                    break;
                };
                if let Some(payload) = virtual_buf.get(..n) {
                    forward_virtual_to_relay(
                        payload,
                        peer_addr,
                        client_udp_addr,
                        &mut out_pkt_buf,
                        &relay_socket,
                    ).await;
                }
            }
        }
    }

    Ok(())
}
