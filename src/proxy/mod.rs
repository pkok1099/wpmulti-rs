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
/// are returned.
///
/// The two directions run as concurrent tasks: a stalled write in one
/// direction must never starve reads in the other. A single `select!`
/// loop that `await`s each `write_all` inline deadlocks on a sustained
/// bidirectional bulk transfer once every socket buffer is full — the
/// loop waits for the peer to read while the peer waits for this side
/// to read, and neither side ever runs again (found by the offline
/// throughput test, which stalled at 91% of an 8x8 MiB load).
/// Idleness is therefore tracked session-wide: every forwarded chunk
/// bumps a shared activity counter, and the session closes only when
/// that counter is still for `idle_timeout`.
pub(crate) async fn copy_bidirectional_with_idle_timeout<A, B>(
    a: &mut A,
    b: &mut B,
    idle_timeout: Duration,
) -> io::Result<()>
where
    A: AsyncRead + AsyncWrite + Unpin,
    B: AsyncRead + AsyncWrite + Unpin,
{
    let (a_read, a_write) = tokio::io::split(a);
    let (b_read, b_write) = tokio::io::split(b);
    let (activity_tx, mut activity_rx) = tokio::sync::watch::channel(0u64);
    let mut a_to_b = Box::pin(copy_direction(a_read, b_write, activity_tx.clone()));
    let mut b_to_a = Box::pin(copy_direction(b_read, a_write, activity_tx));
    let mut a_done = false;
    let mut b_done = false;
    loop {
        if a_done && b_done {
            return Ok(());
        }
        tokio::select! {
            res = &mut a_to_b, if !a_done => {
                match res {
                    Ok(()) => a_done = true,
                    Err(e) => return Err(e),
                }
            }
            res = &mut b_to_a, if !b_done => {
                match res {
                    Ok(()) => b_done = true,
                    Err(e) => return Err(e),
                }
            }
            res = tokio::time::timeout(idle_timeout, activity_rx.changed()), if !(a_done && b_done) => {
                // Ok(_): activity in either direction, or all senders
                // dropped: loop again with a fresh deadline.
                if res.is_err() {
                    tracing::debug!("CONNECT session closed after {:?} idle", idle_timeout);
                    return Ok(());
                }
            }
        }
    }
}

/// Copy one direction until EOF (half-closing the far write side) or an
/// I/O error, bumping `activity` after every forwarded chunk so the
/// session-wide idle watchdog sees it.
async fn copy_direction<R, W>(
    mut read: R,
    mut write: W,
    activity: tokio::sync::watch::Sender<u64>,
) -> io::Result<()>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    // Heap buffer: an 8 KiB stack buffer would push this future (and
    // every caller awaiting it) past the large-future threshold.
    let mut buf = Box::new([0u8; 8192]);
    loop {
        let n = read.read(&mut buf[..]).await?;
        if n == 0 {
            let _ = write.shutdown().await;
            return Ok(());
        }
        let Some(chunk) = buf.get(..n) else {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "relay read overran its buffer",
            ));
        };
        write.write_all(chunk).await?;
        activity.send_modify(|count| *count += 1);
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
