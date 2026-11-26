//! Proxy engines for `wpmulti`: SOCKS5 (RFC 1928, RFC 1929) and HTTP CONNECT (RFC 9110, RFC 7617).

pub mod http;
pub mod router;
pub mod socks5;
#[cfg(test)]
pub mod tests;

use std::io;
use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

pub use http::{
    extract_basic_auth, handle_http, parse_authority, read_http_request_headers,
    read_http_request_headers_buffered,
};
pub use router::{
    AsyncReadWrite, DirectTunnelTarget, DynStream, PoolKeyword, PoolRouter, ProxyAuthError,
    ProxyTunnelTarget, ProxyUdpSocket, SingleTunnelRouter, TargetAddr, TunnelRouter,
    TunnelSelector,
};
pub use socks5::{
    ATYP_DOMAIN, ATYP_IPV4, ATYP_IPV6, CMD_BIND, CMD_CONNECT, CMD_UDP_ASSOCIATE, METHOD_GSSAPI,
    METHOD_NO_ACCEPTABLE, METHOD_NO_AUTH, METHOD_USER_PASS, REP_ADDR_NOT_SUPPORTED,
    REP_CMD_NOT_SUPPORTED, REP_CONN_NOT_ALLOWED, REP_CONN_REFUSED, REP_GENERAL_FAILURE,
    REP_HOST_UNREACHABLE, REP_NETWORK_UNREACHABLE, REP_SUCCESS, REP_TTL_EXPIRED, RFC1929_VERSION,
    SOCKS5_VERSION, build_socks5_udp_packet, encode_target_addr, encode_target_addr_slice,
    handle_socks5, handle_socks5_with_addrs, parse_socks5_udp_packet, send_socks5_reply,
    write_socks5_udp_header,
};

const MAX_PROXY_CONCURRENT_CONNS: usize = 4096;

/// Idle timeout for an established CONNECT session (audit run-1,
/// `wpmulti/proxy:established-connect-no-idle-timeout`): 5 minutes
/// matches the lifecycle tunnel idle timeout and the UDP ASSOCIATE
/// relay's idle timeout. Without it an idle-but-open session holds a
/// listener permit and its tunnel's `active_conns` forever, so the
/// tunnel can never go idle either.
pub(crate) const CONNECT_IDLE_TIMEOUT: Duration = Duration::from_mins(5);

/// Relay bytes in both directions between `a` and `b` until either side
/// closes, and end the session when no byte flows in either direction
/// for `idle_timeout` (audit run-1,
/// `wpmulti/proxy:established-connect-no-idle-timeout`). Behaves like
/// [`tokio::io::copy_bidirectional`] except for the idle bound: each
/// direction's EOF half-closes the other side, traffic in either
/// direction resets the idle deadline for the session, and I/O errors
/// are returned. The idle bound applies to reads; writes follow
/// `copy_bidirectional` (a stalled write blocks like a stalled read
/// would there).
pub(crate) async fn copy_bidirectional_with_idle_timeout<A, B>(
    a: &mut A,
    b: &mut B,
    idle_timeout: Duration,
) -> io::Result<()>
where
    A: AsyncRead + AsyncWrite + Unpin,
    B: AsyncRead + AsyncWrite + Unpin,
{
    let (mut a_read, mut a_write) = tokio::io::split(a);
    let (mut b_read, mut b_write) = tokio::io::split(b);
    // Heap buffers: two 8 KiB stack buffers would push this future
    // (and every caller awaiting it) past the large-future threshold.
    let mut buf_a = Box::new([0u8; 8192]);
    let mut buf_b = Box::new([0u8; 8192]);
    let mut a_done = false;
    let mut b_done = false;
    loop {
        if a_done && b_done {
            return Ok(());
        }
        tokio::select! {
            res = tokio::time::timeout(idle_timeout, a_read.read(&mut buf_a[..])), if !a_done => {
                match res {
                    Ok(Ok(0)) => {
                        a_done = true;
                        let _ = b_write.shutdown().await;
                    }
                    Ok(Ok(n)) => {
                        let Some(chunk) = buf_a.get(..n) else {
                            return Err(io::Error::new(
                                io::ErrorKind::InvalidData,
                                "relay read overran its buffer",
                            ));
                        };
                        b_write.write_all(chunk).await?;
                    }
                    Ok(Err(e)) => return Err(e),
                    Err(_) => {
                        tracing::debug!("CONNECT session closed after {:?} idle", idle_timeout);
                        return Ok(());
                    }
                }
            }
            res = tokio::time::timeout(idle_timeout, b_read.read(&mut buf_b[..])), if !b_done => {
                match res {
                    Ok(Ok(0)) => {
                        b_done = true;
                        let _ = a_write.shutdown().await;
                    }
                    Ok(Ok(n)) => {
                        let Some(chunk) = buf_b.get(..n) else {
                            return Err(io::Error::new(
                                io::ErrorKind::InvalidData,
                                "relay read overran its buffer",
                            ));
                        };
                        a_write.write_all(chunk).await?;
                    }
                    Ok(Err(e)) => return Err(e),
                    Err(_) => {
                        tracing::debug!("CONNECT session closed after {:?} idle", idle_timeout);
                        return Ok(());
                    }
                }
            }
        }
    }
}

/// Runs an asynchronous SOCKS5 server listening on the provided [`tokio::net::TcpListener`].
pub async fn run_socks5_listener(
    listener: tokio::net::TcpListener,
    router: Arc<dyn TunnelRouter>,
) -> io::Result<()> {
    let sem = Arc::new(tokio::sync::Semaphore::new(MAX_PROXY_CONCURRENT_CONNS));
    loop {
        let (stream, peer_addr) = match listener.accept().await {
            Ok(conn) => conn,
            Err(e) => {
                tracing::warn!("SOCKS5 listener accept error: {}", e);
                tokio::time::sleep(Duration::from_millis(50)).await;
                continue;
            }
        };
        let Ok(permit) = Arc::clone(&sem).acquire_owned().await else {
            break;
        };
        let local_ip = stream.local_addr().ok().map(|a| a.ip());
        let peer_ip = Some(peer_addr.ip());
        let router_clone = Arc::clone(&router);
        tokio::spawn(async move {
            let _permit = permit;
            if let Err(e) = handle_socks5_with_addrs(stream, router_clone, local_ip, peer_ip).await
            {
                tracing::debug!("SOCKS5 client {} disconnected: {:?}", peer_addr, e);
            }
        });
    }
    Ok(())
}

/// Runs an asynchronous HTTP/HTTPS CONNECT proxy server listening on the provided [`tokio::net::TcpListener`].
pub async fn run_http_listener(
    listener: tokio::net::TcpListener,
    router: Arc<dyn TunnelRouter>,
) -> io::Result<()> {
    let sem = Arc::new(tokio::sync::Semaphore::new(MAX_PROXY_CONCURRENT_CONNS));
    loop {
        let (stream, peer_addr) = match listener.accept().await {
            Ok(conn) => conn,
            Err(e) => {
                tracing::warn!("HTTP listener accept error: {}", e);
                tokio::time::sleep(Duration::from_millis(50)).await;
                continue;
            }
        };
        let Ok(permit) = Arc::clone(&sem).acquire_owned().await else {
            break;
        };
        let router_clone = Arc::clone(&router);
        tokio::spawn(async move {
            let _permit = permit;
            if let Err(e) = handle_http(stream, router_clone).await {
                tracing::debug!("HTTP proxy client {} disconnected: {:?}", peer_addr, e);
            }
        });
    }
    Ok(())
}
