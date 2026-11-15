//! Embedded asynchronous HTTP Admin REST API server.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Instant;

use parking_lot::Mutex;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::sync::watch;
use tokio::task::JoinHandle;

use crate::api::routes::{handle_admin_request, parse_http_request, HttpResponse};
use crate::core::TunnelManager;

/// Embedded HTTP Admin REST API server.
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
    pub fn bind_addr(&self) -> SocketAddr {
        self.bind_addr
    }

    /// Start listening and accepting incoming administrative HTTP connections.
    /// Returns the bound [`SocketAddr`] (useful when configured with port `0`).
    pub async fn start(&self) -> Result<SocketAddr, std::io::Error> {
        let listener = TcpListener::bind(self.bind_addr).await?;
        let local_addr = listener.local_addr()?;

        let manager = Arc::clone(&self.manager);
        let auth_token = self.auth_token.clone();
        let start_time = self.start_time;
        let mut shutdown_rx = self.shutdown_tx.subscribe();

        let task = tokio::spawn(async move {
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
                                let m = Arc::clone(&manager);
                                let tok = auth_token.clone();
                                client_tasks.spawn(async move {
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
        if let Some(h) = handle {
            h.abort();
            let _ = h.await;
        }
    }
}

/// Maximum time allowed to read a single HTTP request from an Admin API client.
const ADMIN_READ_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);

/// Handle a single incoming HTTP connection.
async fn handle_client_connection<S: AsyncReadExt + AsyncWriteExt + Unpin>(
    mut stream: S,
    manager: Arc<TunnelManager>,
    auth_token: Option<&str>,
    start_time: Instant,
) {
    let mut buf = Vec::with_capacity(4096);
    let mut temp = [0u8; 1024];

    // Read headers until \r\n\r\n with overall read timeout (Slowloris protection)
    let read_res = tokio::time::timeout(ADMIN_READ_TIMEOUT, async {
        loop {
            let n = match stream.read(&mut temp).await {
                Ok(0) => break,
                Ok(n) => n,
                Err(_) => return Err(()),
            };
            buf.extend_from_slice(&temp[..n]);

            if let Some(pos) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
                // Check Content-Length to read remainder of body if any
                let header_str = String::from_utf8_lossy(&buf[..pos]);
                let mut content_len = 0;
                for line in header_str.lines() {
                    if let Some((k, v)) = line.split_once(':')
                        && k.trim().eq_ignore_ascii_case("content-length") {
                        content_len = v.trim().parse::<usize>().unwrap_or(0);
                    }
                }

                if content_len > 65536 {
                    let resp = HttpResponse::payload_too_large("Request body too large (max 64 KiB)");
                    let _ = stream.write_all(&resp.to_bytes()).await;
                    return Err(());
                }

                let required_total = pos + 4 + content_len;
                if required_total > 131072 {
                    let resp = HttpResponse::payload_too_large("Request too large");
                    let _ = stream.write_all(&resp.to_bytes()).await;
                    return Err(());
                }

                while buf.len() < required_total {
                    let n = match stream.read(&mut temp).await {
                        Ok(0) => break,
                        Ok(n) => n,
                        Err(_) => return Err(()),
                    };
                    buf.extend_from_slice(&temp[..n]);
                    if buf.len() > required_total {
                        break;
                    }
                }
                break;
            }

            if buf.len() > 65536 {
                let resp = HttpResponse::bad_request("Request header too large");
                let _ = stream.write_all(&resp.to_bytes()).await;
                return Err(());
            }
        }
        Ok(())
    })
    .await;

    match read_res {
        Ok(Ok(())) => {}
        Ok(Err(())) => return,
        Err(_) => {
            let resp = HttpResponse::bad_request("Request read timed out");
            let _ = stream.write_all(&resp.to_bytes()).await;
            let _ = stream.flush().await;
            return;
        }
    }

    if buf.is_empty() {
        return;
    }

    let uptime_secs = start_time.elapsed().as_secs();

    let response = match parse_http_request(&buf) {
        Ok(req) => handle_admin_request(&req, &manager, auth_token, uptime_secs).await,
        Err(e) => HttpResponse::bad_request(&e),
    };

    let resp_bytes = response.to_bytes();
    let _ = stream.write_all(&resp_bytes).await;
    let _ = stream.flush().await;
}
