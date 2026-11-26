//! DNS-over-HTTPS (RFC 8484) client resolving through a WireGuard tunnel.
//!
//! The phone's DNS is plain UDP inside the tunnel by default. With DoH
//! enabled, the TUN dispatcher intercepts A/AAAA queries and answers
//! them from this client instead: one TLS connection to
//! `cloudflare-dns.com:443` (reached through a tunnel via the injected
//! TCP connector), HTTP/1.1 POST of the DNS wire message, answers
//! cached per (domain, type) with the response TTL. The TLS connection
//! is kept alive and reused across queries; a transient failure returns
//! `None` and the dispatcher forwards the query as plain DNS, so DoH is
//! best-effort — except for TLS failures, which are reported distinctly
//! ([`DohClient::resolve_detailed`]) so the dispatcher fails closed
//! instead of silently downgrading to plaintext.

use std::future::Future;
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::pin::Pin;
use std::sync::Arc;

use rustls::ClientConfig;
use rustls::pki_types::ServerName;
use thiserror::Error;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, BufReader};
use tokio::sync::Mutex as AsyncMutex;
use tokio_rustls::TlsConnector;
use tokio_rustls::client::TlsStream;

use crate::netstack::dns::{DnsLruCache, QueryType, build_query, parse_response};
use crate::netstack::tun::{DnsResolveFuture, DnsResolveOutcome, DnsResolver};
use crate::proxy::router::DynStream;

/// DoH server: Cloudflare, reached at its anycast IP with SNI for the
/// hostname (the certificate is for the hostname, not the IP).
const DOH_HOST: &str = "cloudflare-dns.com";
const DOH_ADDR: SocketAddr = SocketAddr::new(IpAddr::V4(std::net::Ipv4Addr::new(1, 1, 1, 1)), 443);
const DOH_PATH: &str = "/dns-query";
/// Whole-exchange budget (TCP + TLS + HTTP), per attempt.
const DOH_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);
/// Largest DNS message and HTTP body the client accepts.
const MAX_DNS_MESSAGE: usize = 65_535;
const MAX_HTTP_HEADERS: usize = 8 * 1024;

#[derive(Error, Debug)]
pub enum DohError {
    #[error("TLS setup failed: {0}")]
    Tls(String),
    #[error("I/O error: {0}")]
    Io(#[from] io::Error),
    #[error("HTTP error: {0}")]
    Http(String),
    #[error("DNS error: {0}")]
    Dns(String),
    #[error("timed out")]
    Timeout,
}

/// Opens a TCP stream through a WireGuard tunnel. Implemented by the
/// UniFFI engine from the `TunnelManager` (first usable tunnel).
pub trait DohTcpConnector: Send + Sync {
    fn connect(
        &self,
        dst: SocketAddr,
    ) -> Pin<Box<dyn Future<Output = io::Result<DynStream>> + Send>>;
}

/// DNS-over-HTTPS resolver: TLS + HTTP/1.1 to Cloudflare, with answer
/// cache and a reused connection.
pub struct DohClient {
    connector: Arc<dyn DohTcpConnector>,
    tls: TlsConnector,
    server_name: ServerName<'static>,
    server_addr: SocketAddr,
    cache: DnsLruCache,
    conn: AsyncMutex<Option<TlsStream<DynStream>>>,
}

impl DohClient {
    /// Build a client over `connector`. No network happens here; the
    /// first query opens the TLS connection.
    ///
    /// # Errors
    ///
    /// Returns [`DohError::Tls`] when the TLS config cannot be built.
    pub fn new(connector: Arc<dyn DohTcpConnector>) -> Result<Self, DohError> {
        let mut roots = rustls::RootCertStore::empty();
        roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        let provider = rustls::crypto::aws_lc_rs::default_provider();
        let config = ClientConfig::builder_with_provider(Arc::new(provider))
            .with_protocol_versions(&[&rustls::version::TLS13, &rustls::version::TLS12])
            .map_err(|e| DohError::Tls(e.to_string()))?
            .with_root_certificates(roots)
            .with_no_client_auth();
        Ok(Self {
            connector,
            tls: TlsConnector::from(Arc::new(config)),
            server_name: ServerName::try_from(DOH_HOST)
                .map_err(|e| DohError::Tls(e.to_string()))?
                .to_owned(),
            server_addr: DOH_ADDR,
            cache: DnsLruCache::new(512),
            conn: AsyncMutex::new(None),
        })
    }

    /// Resolve `domain` (`A` or `AAAA`) over DoH. Returns the
    /// addresses and the minimum TTL, or `None` on any failure (the
    /// caller falls back to plain DNS). A TLS failure is collapsed to
    /// `None` here too; callers that must fail closed on TLS errors
    /// use [`Self::resolve_detailed`] instead.
    pub async fn resolve(&self, domain: &str, qtype: QueryType) -> Option<(Vec<IpAddr>, u32)> {
        self.resolve_detailed(domain, qtype).await.ok().flatten()
    }

    /// Resolve `domain` (`A` or `AAAA`) over DoH, distinguishing a
    /// TLS failure from every other failure. Returns `Ok(None)` on a
    /// transient failure (timeout, I/O, HTTP, DNS parse: the caller
    /// may fall back to plain DNS) and `Err(DohError::Tls(..))` when
    /// the TLS handshake itself failed, so the caller can fail closed
    /// instead of downgrading to plaintext (audit run-1,
    /// `doh-fallback-to-plain-dns-on-tls-failure`).
    pub async fn resolve_detailed(
        &self,
        domain: &str,
        qtype: QueryType,
    ) -> Result<Option<(Vec<IpAddr>, u32)>, DohError> {
        let key = format!("{domain}|{}", qtype as u16);
        if let Some(ips) = self.cache.get(&key) {
            return Ok(Some((ips, 300)));
        }
        let Ok(query) = build_query(domain, qtype, next_query_id()) else {
            return Ok(None);
        };
        let response = tokio::time::timeout(DOH_TIMEOUT, self.exchange(&query)).await;
        let message = match response {
            Ok(Ok(message)) => message,
            Ok(Err(e)) => return Err(e),
            Err(_) => return Ok(None),
        };
        let Some(id) = query
            .get(..2)
            .and_then(|bytes| bytes.try_into().ok())
            .map(u16::from_be_bytes)
        else {
            return Ok(None);
        };
        let Ok((ips, ttl)) = parse_response(&message, id) else {
            return Ok(None);
        };
        if ips.is_empty() {
            return Ok(None);
        }
        self.cache.insert(&key, ips.clone(), ttl);
        Ok(Some((ips, ttl)))
    }

    /// One DoH exchange over the reused TLS connection, reconnecting
    /// once when the stored connection is dead. The connection slot
    /// is only locked to take and store the stream, never across
    /// network I/O, so concurrent queries do not queue behind one
    /// another (each may open its own connection; the last one wins
    /// the slot).
    async fn exchange(&self, query: &[u8]) -> Result<Vec<u8>, DohError> {
        let mut stream = self.conn.lock().await.take();
        for _ in 0..2 {
            let current = match stream.take() {
                Some(stream) => stream,
                None => self.connect_tls().await?,
            };
            let mut reader = BufReader::new(current);
            match exchange_http(&mut reader, query).await {
                Ok(message) => {
                    *self.conn.lock().await = Some(reader.into_inner());
                    return Ok(message);
                }
                Err(e) => {
                    stream = None;
                    if matches!(e, DohError::Io(_)) {
                        continue;
                    }
                    return Err(e);
                }
            }
        }
        Err(DohError::Io(io::Error::new(
            io::ErrorKind::ConnectionAborted,
            "DoH connection failed twice",
        )))
    }

    /// Open a fresh TLS connection to the DoH server through a tunnel.
    async fn connect_tls(&self) -> Result<TlsStream<DynStream>, DohError> {
        let tcp = tokio::time::timeout(DOH_TIMEOUT, self.connector.connect(self.server_addr))
            .await
            .map_err(|_| DohError::Timeout)??;
        let tls =
            tokio::time::timeout(DOH_TIMEOUT, self.tls.connect(self.server_name.clone(), tcp))
                .await
                .map_err(|_| DohError::Timeout)?
                .map_err(|e| DohError::Tls(e.to_string()))?;
        Ok(tls)
    }
}

impl std::fmt::Debug for DohClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DohClient")
            .field("server_name", &self.server_name)
            .field("server_addr", &self.server_addr)
            .finish_non_exhaustive()
    }
}

impl DnsResolver for DohClient {
    fn resolve(&self, domain: String, qtype: QueryType) -> DnsResolveFuture<'_> {
        Box::pin(async move {
            match self.resolve_detailed(&domain, qtype).await {
                Ok(Some((ips, ttl))) => DnsResolveOutcome::Answered(ips, ttl),
                Err(DohError::Tls(_)) => DnsResolveOutcome::TlsFailed,
                Ok(None)
                | Err(DohError::Io(_) | DohError::Http(_) | DohError::Dns(_) | DohError::Timeout) => {
                    DnsResolveOutcome::Unavailable
                }
            }
        })
    }
}

/// Transaction ids for DoH queries: process-wide counter, no secrecy
/// needed (the TLS channel already authenticates the peer).
fn next_query_id() -> u16 {
    use std::sync::atomic::{AtomicU16, Ordering};
    static NEXT_ID: AtomicU16 = AtomicU16::new(1);
    NEXT_ID.fetch_add(1, Ordering::Relaxed)
}

/// One DoH exchange over an already-open stream: POST the DNS query
/// as `application/dns-message`, read the HTTP/1.1 response, return
/// its body (the DNS response message). Used over the TLS connection
/// in production and over plain TCP in tests.
pub(crate) async fn exchange_http<S>(stream: &mut S, query: &[u8]) -> Result<Vec<u8>, DohError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let mut request = Vec::with_capacity(256 + query.len());
    request.extend_from_slice(
        format!(
            "POST {DOH_PATH} HTTP/1.1\r\nHost: {DOH_HOST}\r\nContent-Type: application/dns-message\r\nAccept: application/dns-message\r\nContent-Length: {}\r\nConnection: keep-alive\r\n\r\n",
            query.len()
        )
        .as_bytes(),
    );
    request.extend_from_slice(query);
    stream.write_all(&request).await?;
    stream.flush().await?;

    let mut head = Vec::with_capacity(1024);
    let mut byte = [0u8; 1];
    while !head.ends_with(b"\r\n\r\n") {
        if head.len() >= MAX_HTTP_HEADERS {
            return Err(DohError::Http("response headers too large".to_string()));
        }
        let n = stream.read(&mut byte).await?;
        if n == 0 {
            return Err(DohError::Http(
                "connection closed during headers".to_string(),
            ));
        }
        head.push(byte[0]);
    }
    let head_text = String::from_utf8_lossy(&head);
    let mut lines = head_text.lines();
    let status = lines.next().unwrap_or("");
    let code: u16 = status
        .split_whitespace()
        .nth(1)
        .and_then(|code| code.parse().ok())
        .ok_or_else(|| DohError::Http(format!("bad status line: {status}")))?;
    if code != 200 {
        return Err(DohError::Http(format!("DoH server returned {code}")));
    }
    let mut content_length: Option<usize> = None;
    let mut chunked = false;
    for line in lines {
        let Some((name, value)) = line.split_once(':') else {
            continue;
        };
        match name.trim().to_ascii_lowercase().as_str() {
            "content-length" => content_length = value.trim().parse().ok(),
            "transfer-encoding" if value.trim().eq_ignore_ascii_case("chunked") => chunked = true,
            _ => {}
        }
    }
    if chunked {
        read_chunked_body(stream).await
    } else {
        let len = content_length
            .ok_or_else(|| DohError::Http("no content-length or chunked body".to_string()))?;
        if len > MAX_DNS_MESSAGE {
            return Err(DohError::Http("response body too large".to_string()));
        }
        let mut body = vec![0u8; len];
        stream.read_exact(&mut body).await?;
        Ok(body)
    }
}

/// Read an HTTP/1.1 chunked body.
async fn read_chunked_body<S>(stream: &mut S) -> Result<Vec<u8>, DohError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let mut body = Vec::new();
    loop {
        let size_line = read_line(stream).await?;
        let size_str = size_line.split(';').next().unwrap_or("").trim();
        let size = usize::from_str_radix(size_str, 16)
            .map_err(|_| DohError::Http(format!("bad chunk size: {size_line}")))?;
        if size == 0 {
            // Trailing headers up to the empty line.
            loop {
                let line = read_line(stream).await?;
                if line.is_empty() {
                    break;
                }
            }
            break;
        }
        if body.len() + size > MAX_DNS_MESSAGE {
            return Err(DohError::Http("response body too large".to_string()));
        }
        let start = body.len();
        body.resize(start + size, 0);
        let Some(chunk) = body.get_mut(start..) else {
            return Err(DohError::Http("chunk out of range".to_string()));
        };
        stream.read_exact(chunk).await?;
        // Trailing CRLF after the chunk.
        let mut crlf = [0u8; 2];
        stream.read_exact(&mut crlf).await?;
    }
    Ok(body)
}

/// Read one CRLF-terminated line (without the CRLF).
async fn read_line<S>(stream: &mut S) -> Result<String, DohError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let mut line = Vec::new();
    let mut byte = [0u8; 1];
    while !line.ends_with(b"\r\n") {
        if line.len() >= MAX_HTTP_HEADERS {
            return Err(DohError::Http("header line too long".to_string()));
        }
        let n = stream.read(&mut byte).await?;
        if n == 0 {
            return Err(DohError::Http("connection closed during body".to_string()));
        }
        line.push(byte[0]);
    }
    line.truncate(line.len().saturating_sub(2));
    Ok(String::from_utf8_lossy(&line).into_owned())
}
