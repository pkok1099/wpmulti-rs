//! Proxy engines for `wpmulti`: SOCKS5 (RFC 1928, RFC 1929) and HTTP CONNECT (RFC 9110, RFC 7617).

pub mod http;
pub mod router;
pub mod socks5;
#[cfg(test)]
pub mod tests;

use std::io;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::Duration;

use parking_lot::Mutex;
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

/// Log the end of an established CONNECT session at WARN when it
/// failed outright or ended without a usable response, so the next
/// measurement run can classify every "empty reply" failure from the
/// daemon log alone.
///
/// The failure this catches is silent by construction: once the
/// SOCKS5 success reply (or HTTP 200) is sent, the outbound TCP is
/// already established, so a target that then closes the connection
/// with no data makes the tunnel stream return EOF — the copy ends
/// cleanly with `Ok`, the protocol handler returns `Ok`, and the
/// listener logs nothing at all. A 2000-request measurement showed
/// 21 such failures (~1%, ~0.25s each) with zero log lines. The
/// signature is a session where the client sent bytes
/// (`client_bytes > 0`) but the target sent none back
/// (`tunnel_bytes == 0`); a client that connects and leaves without
/// sending anything has both counts at zero and is not a failure.
/// Copy errors warn too, except timeouts — the listener already warns
/// on those, so logging them here would double-report one session.
/// One WARN per failed session, never per chunk: at the measured ~1%
/// failure rate this is rare and actionable, not noise.
pub(crate) fn log_connect_session_end(
    protocol: &str,
    selector: &TunnelSelector,
    target: &TargetAddr,
    tunnel_id: Option<&str>,
    result: &io::Result<(u64, u64)>,
) {
    match result {
        Ok((client_bytes, tunnel_bytes)) => {
            if *client_bytes > 0 && *tunnel_bytes == 0 {
                tracing::warn!(
                    protocol = protocol,
                    selector = ?selector,
                    target = %target,
                    tunnel_id = ?tunnel_id,
                    client_bytes = client_bytes,
                    "CONNECT session ended with no response bytes from target"
                );
            }
        }
        Err(e) => {
            if e.kind() != io::ErrorKind::TimedOut {
                tracing::warn!(
                    protocol = protocol,
                    selector = ?selector,
                    target = %target,
                    tunnel_id = ?tunnel_id,
                    "CONNECT session failed after grant: {e}"
                );
            }
        }
    }
}

/// Maximum client-sent prefix buffered for a transparent
/// zero-response retry: 64 KiB covers the observed failure (a 75-byte
/// HTTP GET) and any small request head, while bounding the
/// per-session memory the proxy holds for a retry that may never
/// happen. A client that sends more than this before the target
/// answers cannot be replayed in full, so its session is never
/// retried — the buffered prefix would be an incomplete request.
pub(crate) const ZERO_RESPONSE_RETRY_PREFIX_CAP: usize = 64 * 1024;

/// What a CONNECT session needs to re-dial through a different tunnel
/// after the first one closed the session with no response bytes.
///
/// The retry trades a small double-submit risk for eliminating the
/// observed 0.2-0.75% empty-reply failures: a zero-response EOF makes
/// it unlikely the target processed the request (no response was ever
/// delivered), but not impossible — the target may have processed it
/// and the response was lost. The retry is therefore limited to the
/// zero-response EOF case only (never a timeout or a budget failure),
/// to one attempt, and to sessions whose whole client-sent prefix
/// fits in [`ZERO_RESPONSE_RETRY_PREFIX_CAP`].
pub(crate) struct ZeroResponseRetry<'a> {
    router: &'a Arc<dyn TunnelRouter>,
    selector: &'a TunnelSelector,
    target: &'a TargetAddr,
    credentials: Option<(&'a str, &'a str)>,
    /// Protocol name for the retry log line (`"SOCKS5"` / `"HTTP"`).
    protocol: &'static str,
    /// Bytes already sent to the first tunnel before the copy started
    /// (HTTP CONNECT pipelined leftovers). Seeded into the replay
    /// prefix so a retry replays the whole client-sent prefix.
    seed_prefix: Vec<u8>,
}

impl<'a> ZeroResponseRetry<'a> {
    pub(crate) fn new(
        router: &'a Arc<dyn TunnelRouter>,
        selector: &'a TunnelSelector,
        target: &'a TargetAddr,
        credentials: Option<(&'a str, &'a str)>,
        protocol: &'static str,
        seed_prefix: Vec<u8>,
    ) -> Self {
        Self {
            router,
            selector,
            target,
            credentials,
            protocol,
            seed_prefix,
        }
    }
}

/// Client-sent prefix buffered for a transparent zero-response retry:
/// the first [`ZERO_RESPONSE_RETRY_PREFIX_CAP`] bytes the client sent
/// in this session. Appended only by the client-to-tunnel direction
/// (a single writer), read by the epoch loop when the tunnel EOFs and
/// by the replay after a re-dial — hence interior mutability instead
/// of a borrow the direction future would hold across the loop.
struct RetryPrefix {
    buf: Mutex<Vec<u8>>,
    complete: AtomicBool,
}

impl RetryPrefix {
    const fn new(seed: Vec<u8>) -> Self {
        let complete = seed.len() <= ZERO_RESPONSE_RETRY_PREFIX_CAP;
        Self {
            buf: Mutex::new(seed),
            complete: AtomicBool::new(complete),
        }
    }

    /// Append a chunk just read from the client. Once the buffered
    /// bytes would pass the cap, stop appending and mark the prefix
    /// incomplete — a prefix that overflows the cap can never be
    /// replayed in full, so the session must not be retried.
    fn push(&self, chunk: &[u8]) {
        if !self.complete.load(Ordering::Relaxed) {
            return;
        }
        let mut buf = self.buf.lock();
        if buf.len() + chunk.len() > ZERO_RESPONSE_RETRY_PREFIX_CAP {
            self.complete.store(false, Ordering::Relaxed);
            return;
        }
        buf.extend_from_slice(chunk);
    }

    /// The buffered prefix if it holds every byte the client sent so
    /// far, else `None` — the session cannot be replayed completely.
    fn snapshot_if_complete(&self) -> Option<Vec<u8>> {
        self.complete
            .load(Ordering::Relaxed)
            .then(|| self.buf.lock().clone())
    }
}

/// Outcome of one copy epoch: either the session ended (both sides
/// done, idle, or an error) or the tunnel side reached EOF with zero
/// response bytes while a retry is still available.
enum EpochOutcome {
    Done(io::Result<(u64, u64)>),
    ZeroResponse,
}

/// Shared state across the epochs of one retrying CONNECT session.
/// The byte counters and the activity channel live here (not in the
/// per-epoch direction futures) so the totals span the re-dial: a
/// session that is retried and then succeeds reports the bytes of
/// the whole session, and the idle deadline is session-wide.
struct RetryCopy {
    activity_tx: tokio::sync::watch::Sender<u64>,
    activity_rx: tokio::sync::watch::Receiver<u64>,
    client_bytes: Arc<AtomicU64>,
    tunnel_bytes: Arc<AtomicU64>,
    prefix: Arc<RetryPrefix>,
    retried: bool,
    idle_timeout: Duration,
}

impl RetryCopy {
    fn counts(&self) -> (u64, u64) {
        (
            self.client_bytes.load(Ordering::Relaxed),
            self.tunnel_bytes.load(Ordering::Relaxed),
        )
    }

    /// Run one epoch: relay both directions on the current tunnel
    /// stream until one side ends. The tunnel side does not
    /// half-close the client on EOF — the client must not see EOF
    /// while a retry may still deliver its response — and the epoch
    /// ends as soon as the tunnel side ends (there is no tunnel left
    /// to read from), instead of waiting for the client to close.
    async fn run_epoch<A, B>(&mut self, a: &mut A, b: &mut B) -> EpochOutcome
    where
        A: AsyncRead + AsyncWrite + Unpin,
        B: AsyncRead + AsyncWrite + Unpin,
    {
        let activity_tx = self.activity_tx.clone();
        let client_bytes = Arc::clone(&self.client_bytes);
        let tunnel_bytes = Arc::clone(&self.tunnel_bytes);
        let prefix = Arc::clone(&self.prefix);
        let retried = self.retried;
        let idle_timeout = self.idle_timeout;
        let (a_read, a_write) = tokio::io::split(a);
        let (b_read, b_write) = tokio::io::split(b);
        // Capture the prefix only in the first epoch: after a retry
        // the replayed bytes are already buffered, and new client
        // bytes flow live through the fresh tunnel.
        let capture = if retried {
            None
        } else {
            Some(Arc::clone(&prefix))
        };
        let mut a_to_b = Box::pin(copy_direction_retry(
            a_read,
            b_write,
            activity_tx.clone(),
            Arc::clone(&client_bytes),
            capture,
            true,
        ));
        let mut b_to_a = Box::pin(copy_direction_retry(
            b_read,
            a_write,
            activity_tx,
            Arc::clone(&tunnel_bytes),
            None,
            false,
        ));
        let mut a_done = false;
        loop {
            tokio::select! {
                res = &mut a_to_b, if !a_done => {
                    match res {
                        Ok(()) => a_done = true,
                        Err(e) => return EpochOutcome::Done(Err(e)),
                    }
                }
                res = &mut b_to_a => {
                    match res {
                        Ok(()) => {
                            let client = client_bytes.load(Ordering::Relaxed);
                            let tunnel = tunnel_bytes.load(Ordering::Relaxed);
                            if tunnel == 0
                                && client > 0
                                && !a_done
                                && !retried
                                && prefix.complete.load(Ordering::Relaxed)
                            {
                                return EpochOutcome::ZeroResponse;
                            }
                            return EpochOutcome::Done(Ok((client, tunnel)));
                        }
                        Err(e) => return EpochOutcome::Done(Err(e)),
                    }
                }
                res = tokio::time::timeout(idle_timeout, self.activity_rx.changed()) => {
                    if res.is_err() {
                        tracing::debug!("CONNECT session closed after {:?} idle", idle_timeout);
                        return EpochOutcome::Done(Ok((
                            client_bytes.load(Ordering::Relaxed),
                            tunnel_bytes.load(Ordering::Relaxed),
                        )));
                    }
                }
            }
        }
    }

    /// Attempt the one zero-response retry: re-dial through a
    /// different tunnel and replay the buffered client prefix.
    /// Returns the fresh tunnel stream on success (and updates
    /// `tunnel_id` + `retried`); returns `None` when the retry is
    /// impossible (redial or replay failed) — the caller then ends
    /// the session and the existing WARN fires.
    async fn attempt_retry(
        &mut self,
        ctx: ZeroResponseRetry<'_>,
        tunnel_id: &mut Option<String>,
    ) -> Option<DynStream> {
        let Some(prefix) = self.prefix.snapshot_if_complete() else {
            tracing::debug!(
                protocol = ctx.protocol,
                selector = ?ctx.selector,
                target = %ctx.target,
                failed_tunnel = ?tunnel_id.as_deref(),
                "zero-response retry skipped: client sent more than the replay cap"
            );
            return None;
        };
        let (mut stream, new_id) = match router::connect_via_router(
            ctx.router,
            ctx.selector,
            ctx.target,
            ctx.credentials,
            tunnel_id.as_deref(),
        )
        .await
        {
            Ok(pair) => pair,
            Err(e) => {
                let inner = match e {
                    router::RouterConnectError::SelectTunnel(e)
                    | router::RouterConnectError::ForbiddenDestination(e)
                    | router::RouterConnectError::DnsResolution(e)
                    | router::RouterConnectError::TcpConnect(e) => e,
                };
                tracing::debug!(
                    protocol = ctx.protocol,
                    selector = ?ctx.selector,
                    target = %ctx.target,
                    failed_tunnel = ?tunnel_id.as_deref(),
                    "zero-response retry re-dial failed: {inner}"
                );
                return None;
            }
        };
        let replayed = prefix.len();
        let replay = async {
            stream.write_all(&prefix).await?;
            stream.flush().await
        };
        if let Err(e) = replay.await {
            tracing::debug!(
                protocol = ctx.protocol,
                selector = ?ctx.selector,
                target = %ctx.target,
                failed_tunnel = ?tunnel_id.as_deref(),
                "zero-response retry replay failed: {e}"
            );
            return None;
        }
        tracing::info!(
            protocol = ctx.protocol,
            selector = ?ctx.selector,
            target = %ctx.target,
            from_tunnel = ?tunnel_id.as_deref(),
            to_tunnel = ?new_id.as_deref(),
            replayed_bytes = replayed,
            "CONNECT session retried after zero-response EOF"
        );
        *tunnel_id = new_id;
        self.retried = true;
        Some(stream)
    }
}

/// Relay bytes in both directions between `a` and `b` until either side
/// closes, and end the session when no byte flows in either direction
/// for `idle_timeout` (audit run-1,
/// `wpmulti/proxy:established-connect-no-idle-timeout`). When the
/// tunnel side reaches EOF with zero response bytes while the client
/// is still connected, re-dial the same target through a different
/// tunnel and replay the buffered client prefix instead of handing
/// the client an empty reply.
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
///
/// The retry fires at most once per session, only when the whole
/// client-sent prefix fits in [`ZERO_RESPONSE_RETRY_PREFIX_CAP`] (so
/// it can be replayed in full), and only for pool selectors — a
/// `ById` selector names one tunnel, so there is no different tunnel
/// to re-dial through. Timeouts and budget failures are never
/// retried: they are a different failure (the target never answered
/// in time), not an empty reply.
///
/// Returns `(a_to_b_bytes, b_to_a_bytes)`: the byte counts each
/// direction forwarded. Callers need them to tell a session that died
/// with no response from the target apart from one the client closed
/// without sending anything — see [`log_connect_session_end`]. On a
/// retried session the counts span the whole session (the replayed
/// prefix is counted once, when the client first sent it).
/// `tunnel_id` is updated to the tunnel that ultimately served the
/// session, so the caller's [`log_connect_session_end`] names the
/// right tunnel when the session still fails after the retry.
pub(crate) async fn copy_bidirectional_with_zero_response_retry<A>(
    a: &mut A,
    mut b: DynStream,
    idle_timeout: Duration,
    retry: Option<ZeroResponseRetry<'_>>,
    tunnel_id: &mut Option<String>,
) -> io::Result<(u64, u64)>
where
    A: AsyncRead + AsyncWrite + Unpin,
{
    let (activity_tx, activity_rx) = tokio::sync::watch::channel(0u64);
    let seed = retry
        .as_ref()
        .map_or(Vec::new(), |ctx| ctx.seed_prefix.clone());
    let mut state = RetryCopy {
        activity_tx,
        activity_rx,
        client_bytes: Arc::new(AtomicU64::new(0)),
        tunnel_bytes: Arc::new(AtomicU64::new(0)),
        prefix: Arc::new(RetryPrefix::new(seed)),
        retried: retry.is_none(),
        idle_timeout,
    };
    let mut retry = retry;
    loop {
        match state.run_epoch(&mut *a, &mut b).await {
            EpochOutcome::Done(result) => return result,
            EpochOutcome::ZeroResponse => {
                let Some(ctx) = retry.take() else {
                    // run_epoch only reports a zero response while a
                    // retry is available; unreachable in practice.
                    return Ok(state.counts());
                };
                let Some(new_stream) = state.attempt_retry(ctx, tunnel_id).await else {
                    return Ok(state.counts());
                };
                b = new_stream;
            }
        }
    }
}

/// Copy one direction until EOF or an I/O error, bumping `activity`
/// after every forwarded chunk so the session-wide idle watchdog sees
/// it, and adding the chunk to the shared `forwarded` counter so the
/// caller can read the byte totals even when the session ends on the
/// idle timeout. It also captures the forwarded bytes into `prefix`
/// (so they can be replayed on a fresh tunnel) and half-closes the
/// far write side on EOF only when `shutdown_on_eof` is set. The
/// tunnel-to-client direction runs with it unset: the client must
/// not see EOF while a retry may still deliver its response. The
/// prefix is captured when a chunk is read — before it is written —
/// so a chunk dropped mid-write by a tunnel EOF is still replayed
/// in full.
async fn copy_direction_retry<R, W>(
    mut read: R,
    mut write: W,
    activity: tokio::sync::watch::Sender<u64>,
    forwarded: Arc<AtomicU64>,
    prefix: Option<Arc<RetryPrefix>>,
    shutdown_on_eof: bool,
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
            if shutdown_on_eof {
                let _ = write.shutdown().await;
            }
            return Ok(());
        }
        let Some(chunk) = buf.get(..n) else {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "relay read overran its buffer",
            ));
        };
        if let Some(prefix) = &prefix {
            prefix.push(chunk);
        }
        write.write_all(chunk).await?;
        forwarded.fetch_add(n as u64, Ordering::Relaxed);
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
