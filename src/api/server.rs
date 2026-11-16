//! Embedded asynchronous HTTP Admin REST API server.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Instant;

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
        let listener = TcpListener::bind(self.bind_addr).await?;
        let local_addr = listener.local_addr()?;

        let manager = Arc::clone(&self.manager);
        let auth_token = self.auth_token.clone();
        let start_time = self.start_time;
        let mut shutdown_rx = self.shutdown_tx.subscribe();

        let task = tokio::spawn(async move {
            const MAX_ADMIN_CONNS: usize = 64;
            let conn_sem = Arc::new(tokio::sync::Semaphore::new(MAX_ADMIN_CONNS));
            let mut client_tasks = tokio::task::JoinSet::new();

            loop {
                while let Some(res) = client_tasks.try_join_next() {
                    let _ = res;
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
                                    tracing::warn!("Transient Admin HTTP accept error: {:?}; backing off", e);
                                    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
                                } else {
                                    tracing::debug!("Admin HTTP accept error: {:?}", e);
                                    break;
                                }
                            }
                        }
                    }
                }
            }

            client_tasks.abort_all();
            while client_tasks.join_next().await.is_some() {}
        });

        *self.task_handle.lock() = Some(task);
        Ok(local_addr)
    }

    /// Gracefully stop the administrative HTTP server.
    pub async fn stop(&self) {
        let _ = self.shutdown_tx.send(true);
        let handle = self.task_handle.lock().take();
        if let Some(mut h) = handle
            && tokio::time::timeout(std::time::Duration::from_secs(2), &mut h)
                .await
                .is_err()
        {
            h.abort();
            let _ = h.await;
        }
    }
}

/// Maximum time allowed to read a single HTTP request from an Admin API client.
const ADMIN_READ_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);
/// Maximum time allowed to write an HTTP response to an Admin API client.
const ADMIN_WRITE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);

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
    const MAX_ADMIN_BODY_BYTES: usize = 65536;
    const MAX_ADMIN_TOTAL_BYTES: usize = MAX_ADMIN_HEADER_BYTES + MAX_ADMIN_BODY_BYTES;

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

        let search_start = prev_len.saturating_sub(3);
        if let Some(rel_pos) = buf
            .get(search_start..)
            .and_then(|tail| tail.windows(4).position(|w| w == b"\r\n\r\n"))
        {
            let pos = search_start + rel_pos;
            if pos + 4 > MAX_ADMIN_HEADER_BYTES {
                let resp = HttpResponse::bad_request("Request header too large");
                let _ = stream.write_all(&resp.to_bytes()).await;
                return Err(());
            }
            let header_bytes = buf.get(..pos).unwrap_or_default();
            let content_len = match parse_request_content_length(header_bytes) {
                Ok(len) => len,
                Err(resp) => {
                    let _ = stream.write_all(&resp.to_bytes()).await;
                    return Err(());
                }
            };

            if content_len > MAX_ADMIN_BODY_BYTES {
                let resp = HttpResponse::payload_too_large("Request body too large (max 64 KiB)");
                let _ = stream.write_all(&resp.to_bytes()).await;
                return Err(());
            }

            let required_total = pos + 4 + content_len;
            if required_total > MAX_ADMIN_TOTAL_BYTES {
                let resp = HttpResponse::payload_too_large("Request too large");
                let _ = stream.write_all(&resp.to_bytes()).await;
                return Err(());
            }

            while buf.len() < required_total {
                let n = match stream.read(&mut temp).await {
                    Ok(0) => {
                        let resp = HttpResponse::bad_request("Truncated request body");
                        let _ = stream.write_all(&resp.to_bytes()).await;
                        return Err(());
                    }
                    Ok(n) => n,
                    Err(_) => return Err(()),
                };
                if let Some(chunk) = temp.get(..n) {
                    buf.extend_from_slice(chunk);
                }
                if buf.len() > MAX_ADMIN_TOTAL_BYTES {
                    let resp = HttpResponse::payload_too_large("Request too large");
                    let _ = stream.write_all(&resp.to_bytes()).await;
                    return Err(());
                }
            }
            buf.truncate(required_total);
            break;
        }

        if buf.len() > MAX_ADMIN_HEADER_BYTES {
            let resp = HttpResponse::bad_request("Request header too large");
            let _ = stream.write_all(&resp.to_bytes()).await;
            return Err(());
        }
    }
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

    let response = match parse_http_request(&buf) {
        Ok(req) => handle_admin_request(&req, &manager, auth_token, uptime_secs).await,
        Err(e) => HttpResponse::bad_request(&e),
    };

    let resp_bytes = response.to_bytes();
    let _ = tokio::time::timeout(ADMIN_WRITE_TIMEOUT, async {
        stream.write_all(&resp_bytes).await?;
        stream.flush().await
    })
    .await;
}
