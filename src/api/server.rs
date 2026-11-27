//! Embedded asynchronous HTTP Admin REST API server.

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use parking_lot::Mutex;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::sync::watch;
use tokio::task::JoinHandle;

use crate::api::routes::{HttpResponse, handle_admin_request_with_peer, parse_http_request};
use crate::core::TunnelManager;

/// Embedded HTTP Admin REST API server.
#[derive(Debug)]
pub struct AdminServer {
    bind_addr: SocketAddr,
    manager: Arc<TunnelManager>,
    auth_token: Option<String>,
    start_time: Instant,
    shutdown_tx: watch::Sender<bool>,
    drain_timeout_ms: Arc<AtomicU64>,
    task_handle: Mutex<Option<JoinHandle<()>>>,
}

impl AdminServer {
    /// Construct a new [`AdminServer`].
    pub fn new(
        bind_addr: SocketAddr,
        manager: Arc<TunnelManager>,
        auth_token: Option<String>,
    ) -> Self {
        let (shutdown_tx, _) = watch::channel(false);
        Self {
            bind_addr,
            manager,
            auth_token,
            start_time: Instant::now(),
            shutdown_tx,
            drain_timeout_ms: Arc::new(AtomicU64::new(500)),
            task_handle: Mutex::new(None),
        }
    }

    /// Bound or configured listen address.
    pub const fn bind_addr(&self) -> SocketAddr {
        self.bind_addr
    }

    /// Start listening and accepting incoming administrative HTTP connections.
    /// Returns the bound [`SocketAddr`] (useful when configured with port `0`).
    pub async fn start(&self) -> Result<SocketAddr, std::io::Error> {
        if self.task_handle.lock().is_some() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::AlreadyExists,
                "AdminServer is already running",
            ));
        }
        let _ = self.shutdown_tx.send(false);
        let listener = TcpListener::bind(self.bind_addr).await.map_err(|e| {
            std::io::Error::new(
                e.kind(),
                format!("failed to bind Admin API on {}: {e}", self.bind_addr),
            )
        })?;
        let local_addr = listener.local_addr()?;

        let manager = Arc::clone(&self.manager);
        let auth_token = self.auth_token.clone();
        let start_time = self.start_time;
        let drain_timeout_ms = Arc::clone(&self.drain_timeout_ms);
        let mut shutdown_rx = self.shutdown_tx.subscribe();

        let task = tokio::spawn(async move {
            let conn_sem = Arc::new(tokio::sync::Semaphore::new(MAX_ADMIN_CONNS_GENERAL));
            let reserve_sem = Arc::new(tokio::sync::Semaphore::new(ADMIN_RESERVED_CONNS));
            // Live per-IP connection counts: one peer may hold at most
            // `MAX_ADMIN_CONNS_PER_IP` slots, so a single Slowloris peer
            // cannot take all 64 slots (audit run-1,
            // `admin-http-parse:slowloris-connection-slot-exhaustion`).
            // The accept loop is a single task, but the counts are also
            // decremented by the spawned client tasks, hence the shared
            // map (lock is never held across an `.await`).
            let per_ip_counts: Arc<Mutex<HashMap<IpAddr, usize>>> =
                Arc::new(Mutex::new(HashMap::new()));
            let mut client_tasks = tokio::task::JoinSet::new();

            loop {
                while let Some(res) = client_tasks.try_join_next() {
                    if let Err(e) = res {
                        tracing::warn!("Admin client task failed: {e}");
                    }
                }

                tokio::select! {
                    biased;
                    _ = shutdown_rx.changed() => {
                        if *shutdown_rx.borrow() {
                            break;
                        }
                    }
                    res = listener.accept() => {
                        match res {
                            Ok((stream, peer_addr)) => {
                                let Some((permit, per_ip_guard)) =
                                    try_admit_admin_connection(
                                        &conn_sem,
                                        &reserve_sem,
                                        &per_ip_counts,
                                        peer_addr.ip(),
                                    )
                                else {
                                    drop(stream);
                                    continue;
                                };
                                let m = Arc::clone(&manager);
                                let tok = auth_token.clone();
                                client_tasks.spawn(async move {
                                    let _permit = permit;
                                    let _per_ip_guard = per_ip_guard;
                                    handle_client_connection(
                                        stream,
                                        peer_addr,
                                        m,
                                        tok.as_deref(),
                                        start_time,
                                    )
                                    .await;
                                });
                            }
                            Err(e) => {
                                let is_transient = matches!(
                                    e.raw_os_error(),
                                    Some(libc::EMFILE | libc::ENFILE | libc::ECONNABORTED | libc::EINTR)
                                ) || e.kind() == std::io::ErrorKind::ConnectionAborted
                                    || e.kind() == std::io::ErrorKind::Interrupted;

                                if is_transient {
                                    tracing::warn!("Transient Admin HTTP accept error: {}; backing off", e);
                                    tokio::time::sleep(Duration::from_millis(50)).await;
                                } else {
                                    tracing::debug!("Admin HTTP accept error: {:?}", e);
                                    break;
                                }
                            }
                        }
                    }
                }
            }

            drop(listener);
            let drain_dur = Duration::from_millis(drain_timeout_ms.load(Ordering::Relaxed));
            drain_admin_client_tasks(&mut client_tasks, drain_dur).await;
        });

        *self.task_handle.lock() = Some(task);
        Ok(local_addr)
    }

    /// Signal the Admin API server to immediately stop accepting new connections.
    pub fn begin_shutdown(&self, drain_timeout: Duration) {
        let ms = drain_timeout.as_millis().min(u128::from(u64::MAX)) as u64;
        self.drain_timeout_ms.store(ms, Ordering::Relaxed);
        let _ = self.shutdown_tx.send(true);
    }

    /// Wait up to `drain_timeout` for in-flight Admin API requests to complete,
    /// then abort any remaining handlers.
    pub async fn drain(&self, drain_timeout: Duration) {
        let handle = self.task_handle.lock().take();
        if let Some(mut h) = handle
            && tokio::time::timeout(drain_timeout + Duration::from_millis(250), &mut h)
                .await
                .is_err()
        {
            h.abort();
            let _ = h.await;
        }
    }

    /// Gracefully stop the administrative HTTP server.
    pub async fn stop(&self) {
        let drain_timeout = Duration::from_millis(500);
        self.begin_shutdown(drain_timeout);
        self.drain(drain_timeout).await;
    }
}

/// Maximum time allowed to read a single HTTP request from an Admin API client.
const ADMIN_READ_TIMEOUT: Duration = Duration::from_secs(10);
/// Maximum time allowed to write an HTTP response to an Admin API client.
const ADMIN_WRITE_TIMEOUT: Duration = Duration::from_secs(10);
/// Maximum time allowed for one 1 KiB read chunk while reading an Admin
/// request: a peer must make progress at least this often, so a Slowloris
/// peer trickling one byte at a time cannot hold a slot for the whole
/// `ADMIN_READ_TIMEOUT` (audit run-1,
/// `admin-http-parse:slowloris-connection-slot-exhaustion`). The outer
/// 10 s timeout remains as the absolute bound for the whole request.
const ADMIN_READ_CHUNK_TIMEOUT: Duration = Duration::from_secs(2);
/// Maximum concurrent Admin connections from one peer IP: fairness so a
/// single peer cannot take all `MAX_ADMIN_CONNS` (64) slots. 8 leaves
/// room for the local operator and TUI polling from one address while
/// still requiring at least 8 distinct IPs to exhaust the server.
const MAX_ADMIN_CONNS_PER_IP: usize = 8;
/// Global Admin slot budget (64): 56 general slots open to any peer,
/// plus 8 reserved slots that only a peer IP's *first* live connection
/// may take. The reserve keeps a legitimate request from a fresh IP
/// servable while slow peers hold the general pool (audit run-3,
/// `admin-slot-exhaustion`: 8 IPs x 8 trickling connections used to
/// take all 64). A first connection tries the general pool first and
/// falls back to the reserve only when it is full, so the reserve
/// stays free until it is actually needed.
const MAX_ADMIN_CONNS: usize = 64;
const ADMIN_RESERVED_CONNS: usize = 8;
const MAX_ADMIN_CONNS_GENERAL: usize = MAX_ADMIN_CONNS - ADMIN_RESERVED_CONNS;

/// RAII decrement of a peer IP's live Admin-connection count; dropped
/// when its client task ends (including on abort during shutdown).
struct PerIpConnGuard {
    counts: Arc<Mutex<HashMap<IpAddr, usize>>>,
    ip: IpAddr,
}

impl Drop for PerIpConnGuard {
    fn drop(&mut self) {
        let mut counts = self.counts.lock();
        if let Some(count) = counts.get_mut(&self.ip) {
            *count = count.saturating_sub(1);
            if *count == 0 {
                counts.remove(&self.ip);
            }
        }
    }
}

/// Admit one Admin connection from `peer_ip` under the per-IP cap,
/// returning the RAII guard that releases the slot when the client task
/// ends, plus whether this is the peer's first live connection (its
/// count was 0 before this admission — the caller may let such a
/// connection fall back to the reserved global pool). `None` when the
/// peer already holds `MAX_ADMIN_CONNS_PER_IP` slots (audit run-1,
/// `admin-http-parse:slowloris-connection-slot-exhaustion`).
fn try_admit_admin_ip(
    counts: &Arc<Mutex<HashMap<IpAddr, usize>>>,
    peer_ip: IpAddr,
) -> Option<(PerIpConnGuard, bool)> {
    let mut locked = counts.lock();
    let slot = locked.entry(peer_ip).or_insert(0);
    if *slot >= MAX_ADMIN_CONNS_PER_IP {
        return None;
    }
    let is_first_conn = *slot == 0;
    *slot += 1;
    // Release the lock before building the guard: the count is already
    // bumped, and the guard only carries the shared map for its Drop.
    drop(locked);
    Some((
        PerIpConnGuard {
            counts: Arc::clone(counts),
            ip: peer_ip,
        },
        is_first_conn,
    ))
}

/// Admit one Admin connection from `peer_ip`: per-IP cap first, then a
/// global slot — the general pool, or the reserved pool when this is
/// the peer's first live connection and the general pool is full.
/// Returns the global permit and the per-IP guard, both held by the
/// spawned client task; `None` (after logging which limit hit) when
/// either limit is hit and the connection must be dropped.
fn try_admit_admin_connection(
    conn_sem: &Arc<tokio::sync::Semaphore>,
    reserve_sem: &Arc<tokio::sync::Semaphore>,
    per_ip_counts: &Arc<Mutex<HashMap<IpAddr, usize>>>,
    peer_ip: IpAddr,
) -> Option<(tokio::sync::OwnedSemaphorePermit, PerIpConnGuard)> {
    let Some((per_ip_guard, is_first_conn)) = try_admit_admin_ip(per_ip_counts, peer_ip) else {
        tracing::warn!(
            "Admin server per-IP connection limit ({MAX_ADMIN_CONNS_PER_IP}) reached for {peer_ip}; dropping connection"
        );
        return None;
    };
    let permit = if is_first_conn {
        Arc::clone(conn_sem)
            .try_acquire_owned()
            .ok()
            .or_else(|| Arc::clone(reserve_sem).try_acquire_owned().ok())
    } else {
        Arc::clone(conn_sem).try_acquire_owned().ok()
    };
    permit.map_or_else(
        || {
            tracing::warn!(
                "Admin server connection limit ({MAX_ADMIN_CONNS}) reached; dropping connection"
            );
            None
        },
        |permit| Some((permit, per_ip_guard)),
    )
}

/// Wait up to `drain_dur` for in-flight Admin client tasks to finish,
/// then abort any that remain.
async fn drain_admin_client_tasks(
    client_tasks: &mut tokio::task::JoinSet<()>,
    drain_dur: Duration,
) {
    if !client_tasks.is_empty() && !drain_dur.is_zero() {
        let deadline = tokio::time::Instant::now() + drain_dur;
        while !client_tasks.is_empty() {
            let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
            if remaining.is_zero() {
                break;
            }
            match tokio::time::timeout(remaining, client_tasks.join_next()).await {
                Ok(Some(_)) => {}
                Ok(None) | Err(_) => break,
            }
        }
    }

    client_tasks.abort_all();
    while client_tasks.join_next().await.is_some() {}
}

/// Handle a single incoming HTTP connection.
fn parse_request_content_length(header_bytes: &[u8]) -> Result<usize, HttpResponse> {
    let Ok(header_str) = std::str::from_utf8(header_bytes) else {
        return Err(HttpResponse::bad_request("Invalid UTF-8 in headers"));
    };
    let mut parsed_len: Option<usize> = None;
    for (idx, line) in header_str.split("\r\n").enumerate() {
        if line.contains(['\r', '\n', '\0']) {
            return Err(HttpResponse::bad_request(
                "Invalid control character in headers",
            ));
        }
        if idx == 0 || line.is_empty() {
            continue;
        }
        let Some((k, v)) = line.split_once(':') else {
            return Err(HttpResponse::bad_request("Malformed HTTP header line"));
        };
        if k.is_empty() || k.chars().any(char::is_whitespace) {
            return Err(HttpResponse::bad_request("Invalid HTTP header name"));
        }
        if k.eq_ignore_ascii_case("transfer-encoding") {
            return Err(HttpResponse::bad_request("Transfer-Encoding not supported"));
        }
        if k.eq_ignore_ascii_case("content-length") {
            let val_trim = v.trim();
            if val_trim.is_empty() || !val_trim.bytes().all(|b| b.is_ascii_digit()) {
                return Err(HttpResponse::bad_request("Invalid Content-Length"));
            }
            let Ok(len) = val_trim.parse::<usize>() else {
                return Err(HttpResponse::payload_too_large("Content-Length overflow"));
            };
            if parsed_len.is_some() {
                return Err(HttpResponse::bad_request("Duplicate Content-Length"));
            }
            parsed_len = Some(len);
        }
    }
    Ok(parsed_len.unwrap_or(0))
}

/// Read one chunk with a progress deadline: the peer must deliver each
/// chunk within `ADMIN_READ_CHUNK_TIMEOUT`, so a Slowloris peer cannot
/// hold a connection slot by trickling bytes (audit run-1,
/// `admin-http-parse:slowloris-connection-slot-exhaustion`).
async fn read_admin_chunk<S: AsyncReadExt + Unpin>(
    stream: &mut S,
    buf: &mut [u8],
) -> Result<usize, ()> {
    match tokio::time::timeout(ADMIN_READ_CHUNK_TIMEOUT, stream.read(buf)).await {
        Ok(Ok(n)) => Ok(n),
        Ok(Err(_)) | Err(_) => Err(()),
    }
}

async fn read_admin_request_bytes<S: AsyncReadExt + AsyncWriteExt + Unpin>(
    stream: &mut S,
) -> Result<Vec<u8>, ()> {
    const MAX_ADMIN_HEADER_BYTES: usize = 65536;

    let mut buf = Vec::with_capacity(4096);
    let mut temp = [0u8; 1024];

    loop {
        let prev_len = buf.len();
        let n = match read_admin_chunk(stream, &mut temp).await {
            Ok(0) => break,
            Ok(n) => n,
            Err(()) => return Err(()),
        };
        if let Some(chunk) = temp.get(..n) {
            buf.extend_from_slice(chunk);
        }

        if let Some(pos) = find_header_end(&buf, prev_len) {
            return read_admin_request_body(stream, buf, pos).await;
        }

        if buf.len() > MAX_ADMIN_HEADER_BYTES {
            send_admin_error(
                stream,
                HttpResponse::bad_request("Request header too large"),
            )
            .await;
            return Err(());
        }
    }
    Ok(buf)
}

/// Locate the end of the HTTP header (`\r\n\r\n`) in `buf`, if fully received.
fn find_header_end(buf: &[u8], prev_len: usize) -> Option<usize> {
    let search_start = prev_len.saturating_sub(3);
    buf.get(search_start..)
        .and_then(|tail| tail.windows(4).position(|w| w == b"\r\n\r\n"))
        .map(|rel_pos| search_start + rel_pos)
}

/// Write an error response to the admin client (best effort).
async fn send_admin_error<S: AsyncWriteExt + Unpin>(stream: &mut S, resp: HttpResponse) {
    let _ = stream.write_all(&resp.to_bytes()).await;
}

/// Validate the header and read the remaining body bytes for a request whose
/// header ends at `pos`; `buf` already holds the bytes read so far.
async fn read_admin_request_body<S: AsyncReadExt + AsyncWriteExt + Unpin>(
    stream: &mut S,
    mut buf: Vec<u8>,
    pos: usize,
) -> Result<Vec<u8>, ()> {
    const MAX_ADMIN_HEADER_BYTES: usize = 65536;
    const MAX_ADMIN_BODY_BYTES: usize = 65536;
    const MAX_ADMIN_TOTAL_BYTES: usize = MAX_ADMIN_HEADER_BYTES + MAX_ADMIN_BODY_BYTES;

    let mut temp = [0u8; 1024];

    if pos + 4 > MAX_ADMIN_HEADER_BYTES {
        send_admin_error(
            stream,
            HttpResponse::bad_request("Request header too large"),
        )
        .await;
        return Err(());
    }
    let header_bytes = buf.get(..pos).unwrap_or_default();
    let content_len = match parse_request_content_length(header_bytes) {
        Ok(len) => len,
        Err(resp) => {
            send_admin_error(stream, resp).await;
            return Err(());
        }
    };

    if content_len > MAX_ADMIN_BODY_BYTES {
        send_admin_error(
            stream,
            HttpResponse::payload_too_large("Request body too large (max 64 KiB)"),
        )
        .await;
        return Err(());
    }

    let required_total = pos + 4 + content_len;
    if required_total > MAX_ADMIN_TOTAL_BYTES {
        send_admin_error(stream, HttpResponse::payload_too_large("Request too large")).await;
        return Err(());
    }

    while buf.len() < required_total {
        let n = match read_admin_chunk(stream, &mut temp).await {
            Ok(0) => {
                send_admin_error(stream, HttpResponse::bad_request("Truncated request body")).await;
                return Err(());
            }
            Ok(n) => n,
            Err(()) => return Err(()),
        };
        if let Some(chunk) = temp.get(..n) {
            buf.extend_from_slice(chunk);
        }
        if buf.len() > MAX_ADMIN_TOTAL_BYTES {
            send_admin_error(stream, HttpResponse::payload_too_large("Request too large")).await;
            return Err(());
        }
    }
    buf.truncate(required_total);
    Ok(buf)
}

async fn handle_client_connection<S: AsyncReadExt + AsyncWriteExt + Unpin>(
    mut stream: S,
    peer_addr: SocketAddr,
    manager: Arc<TunnelManager>,
    auth_token: Option<&str>,
    start_time: Instant,
) {
    // Read headers until \r\n\r\n with overall read timeout (Slowloris protection)
    let buf = match tokio::time::timeout(ADMIN_READ_TIMEOUT, read_admin_request_bytes(&mut stream))
        .await
    {
        Ok(Ok(buf)) => buf,
        Ok(Err(())) => return,
        Err(_) => {
            let resp = HttpResponse::bad_request("Request read timed out");
            let _ = stream.write_all(&resp.to_bytes()).await;
            let _ = stream.flush().await;
            return;
        }
    };

    if buf.is_empty() {
        return;
    }

    let uptime_secs = start_time.elapsed().as_secs();

    let dynamic_token = manager.config_snapshot().admin.auth_token;

    let response = match parse_http_request(&buf) {
        Ok(req) => {
            // A configured admin token gates every peer, loopback
            // included: loopback is not an identity, any local UID can
            // connect to it (audit run-3, `loopback-no-token-any-local-
            // user-admin`). When no token is configured at all the
            // request stays unauthenticated, as before. First-party
            // clients (`wpmulti top`, `status`, `disable`/`enable`)
            // send the token from `WPMULTI_ADMIN_TOKEN` /
            // `--auth-token` when one is configured.
            let effective_auth_token = dynamic_token.as_deref().or(auth_token);
            handle_admin_request_with_peer(
                &req,
                &manager,
                effective_auth_token,
                uptime_secs,
                Some(peer_addr.ip()),
            )
            .await
        }
        Err(e) => HttpResponse::bad_request(&e),
    };

    let resp_bytes = response.to_bytes();
    let _ = tokio::time::timeout(ADMIN_WRITE_TIMEOUT, async {
        stream.write_all(&resp_bytes).await?;
        stream.flush().await
    })
    .await;
}
