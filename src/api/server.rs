//! Embedded asynchronous HTTP Admin REST API server.

use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use parking_lot::Mutex;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::sync::watch;
use tokio::task::JoinHandle;

use crate::api::routes::{HttpResponse, handle_admin_request, parse_http_request};
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
            const MAX_ADMIN_CONNS: usize = 64;
            let conn_sem = Arc::new(tokio::sync::Semaphore::new(MAX_ADMIN_CONNS));
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
                            Ok((stream, _peer_addr)) => {
                                let Ok(permit) = Arc::clone(&conn_sem).try_acquire_owned() else {
                                    tracing::warn!("Admin server connection limit ({}) reached; dropping connection", MAX_ADMIN_CONNS);
                                    drop(stream);
                                    continue;
                                };
                                let m = Arc::clone(&manager);
                                let tok = auth_token.clone();
                                client_tasks.spawn(async move {
                                    let _permit = permit;
                                    handle_client_connection(stream, m, tok.as_deref(), start_time).await;
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

async fn read_admin_request_bytes<S: AsyncReadExt + AsyncWriteExt + Unpin>(
    stream: &mut S,
) -> Result<Vec<u8>, ()> {
    const MAX_ADMIN_HEADER_BYTES: usize = 65536;

    let mut buf = Vec::with_capacity(4096);
    let mut temp = [0u8; 1024];

    loop {
        let prev_len = buf.len();
        let n = match stream.read(&mut temp).await {
            Ok(0) => break,
            Ok(n) => n,
            Err(_) => return Err(()),
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
        let n = match stream.read(&mut temp).await {
            Ok(0) => {
                send_admin_error(stream, HttpResponse::bad_request("Truncated request body")).await;
                return Err(());
            }
            Ok(n) => n,
            Err(_) => return Err(()),
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
    let effective_auth_token = dynamic_token.as_deref().or(auth_token);

    let response = match parse_http_request(&buf) {
        Ok(req) => handle_admin_request(&req, &manager, effective_auth_token, uptime_secs).await,
        Err(e) => HttpResponse::bad_request(&e),
    };

    let resp_bytes = response.to_bytes();
    let _ = tokio::time::timeout(ADMIN_WRITE_TIMEOUT, async {
        stream.write_all(&resp_bytes).await?;
        stream.flush().await
    })
    .await;
}
