//! Comprehensive unit tests for SOCKS5 and HTTP proxy engines.

use std::collections::HashMap;
use std::future::Future;
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use parking_lot::RwLock;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};

use crate::config::{AuthMode, PoolStrategy};
use crate::proxy::http::{
    ResponseBodyFraming, copy_limited_idle, extract_basic_auth, handle_http, handle_http_with_peer,
    parse_authority, parse_response_head, read_http_request_headers_buffered,
};
use crate::proxy::router::{
    DirectTunnelTarget, DynStream, FailedAuthLimiter, MAX_FAILED_AUTH_ATTEMPTS, PoolKeyword,
    PoolRouter, ProxyAuthError, ProxyTunnelTarget, ProxyUdpSocket, SelectTunnelFut,
    SingleTunnelRouter, TargetAddr, TunnelRouter, TunnelSelector,
};
use crate::proxy::socks5::ExpectedUdpReplies;
use crate::proxy::socks5::{
    ATYP_DOMAIN, ATYP_IPV4, ATYP_IPV6, CMD_CONNECT, CMD_UDP_ASSOCIATE, METHOD_NO_ACCEPTABLE,
    METHOD_NO_AUTH, METHOD_USER_PASS, REP_CONN_NOT_ALLOWED, REP_GENERAL_FAILURE,
    REP_HOST_UNREACHABLE, REP_NETWORK_UNREACHABLE, REP_SUCCESS, RFC1929_VERSION, SOCKS5_VERSION,
    UdpPayloadPool, build_socks5_udp_packet, handle_socks5, handle_socks5_with_addrs,
    parse_socks5_udp_packet, send_socks5_reply,
};

/// TEST-NET-1 address named as the proxy-visible destination in tests
/// that need a live echo server. The destination guard forbids loopback
/// (and RFC1918) targets, so the client names this address and the mock
/// tunnel target redirects the actual dial/send to the loopback echo
/// listener — the proxy path under test still sees a public destination.
/// Never a real egress: the mock only ever dials the local echo server.
const TEST_ECHO_IP: IpAddr = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1));

/// Proxy-visible destination for `echo_addr`: same port, TEST-NET-1 IP.
fn test_echo_target(echo_addr: SocketAddr) -> SocketAddr {
    SocketAddr::new(TEST_ECHO_IP, echo_addr.port())
}

/// Mock tunnel target with configurable DNS resolution table and connection interception.
struct MockTunnelTarget {
    id: String,
    dns_table: RwLock<HashMap<String, IpAddr>>,
    tcp_conns: AtomicUsize,
    fail_tcp_with: Option<io::ErrorKind>,
    hang_tcp: bool,
    /// Delay a successful TCP dial by this long (stands in for a
    /// slow dormant tunnel whose handshake eats the budget).
    tcp_delay: Duration,
    aborted: Arc<AtomicBool>,
    /// When set, TCP dials go to this address instead of the requested
    /// destination (see [`TEST_ECHO_IP`]).
    dial_redirect: Option<SocketAddr>,
    /// When set, UDP sends go to this address instead of the requested
    /// destination (see [`TEST_ECHO_IP`]).
    udp_redirect: Option<SocketAddr>,
    /// Whether this mock reports a live session (`is_live`), standing
    /// in for a tunnel that just moved real traffic.
    live: bool,
}

impl MockTunnelTarget {
    fn new(id: &str) -> Self {
        Self {
            id: id.to_string(),
            dns_table: RwLock::new(HashMap::new()),
            tcp_conns: AtomicUsize::new(0),
            fail_tcp_with: None,
            hang_tcp: false,
            tcp_delay: Duration::ZERO,
            aborted: Arc::new(AtomicBool::new(false)),
            dial_redirect: None,
            udp_redirect: None,
            live: false,
        }
    }

    /// Report a live session from `is_live`.
    fn with_live(self) -> Self {
        Self { live: true, ..self }
    }

    /// Redirect actual TCP dials to `addr` while the proxy still sees
    /// the requested (public) destination.
    fn with_dial_redirect(self, addr: SocketAddr) -> Self {
        Self {
            dial_redirect: Some(addr),
            ..self
        }
    }

    /// Redirect actual UDP sends to `addr` while the proxy still sees
    /// the requested (public) destination.
    fn with_udp_redirect(self, addr: SocketAddr) -> Self {
        Self {
            udp_redirect: Some(addr),
            ..self
        }
    }

    fn id(&self) -> &str {
        &self.id
    }

    fn with_dns(self, domain: &str, ip: IpAddr) -> Self {
        self.dns_table.write().insert(domain.to_string(), ip);
        self
    }

    fn with_tcp_failure(self, kind: io::ErrorKind) -> Self {
        Self {
            fail_tcp_with: Some(kind),
            ..self
        }
    }

    fn with_hanging_tcp(self) -> Self {
        Self {
            hang_tcp: true,
            ..self
        }
    }

    /// Delay a successful TCP dial by `delay`.
    fn with_tcp_delay(self, delay: Duration) -> Self {
        Self {
            tcp_delay: delay,
            ..self
        }
    }
}

/// Test-only UDP socket that sends every datagram to a fixed echo
/// address instead of the requested destination (see [`TEST_ECHO_IP`]).
/// A reply is reported as coming from the destination the send was
/// addressed to, modeling a real tunnel socket where a reply's sender
/// is the contacted destination (the relay's expected-source check
/// relies on that invariant).
struct RedirectUdpSocket {
    inner: UdpSocket,
    redirect: SocketAddr,
    last_target: Mutex<Option<SocketAddr>>,
}

impl ProxyUdpSocket for RedirectUdpSocket {
    fn send_to<'a>(
        &'a self,
        buf: &'a [u8],
        target: SocketAddr,
    ) -> Pin<Box<dyn Future<Output = io::Result<usize>> + Send + 'a>> {
        let redirect = self.redirect;
        *self.last_target.lock().unwrap() = Some(target);
        Box::pin(async move { self.inner.send_to(buf, redirect).await })
    }

    fn recv_from<'a>(
        &'a self,
        buf: &'a mut [u8],
    ) -> Pin<Box<dyn Future<Output = io::Result<(usize, SocketAddr)>> + Send + 'a>> {
        let redirect = self.redirect;
        Box::pin(async move {
            let (n, from) = self.inner.recv_from(buf).await?;
            // The echo server really sent this, but the proxy asked for
            // `last_target`: report that as the sender, as a real
            // tunnel socket would.
            let peer = if from == redirect {
                self.last_target.lock().unwrap().unwrap_or(from)
            } else {
                from
            };
            Ok((n, peer))
        })
    }

    fn local_port(&self) -> u16 {
        self.inner.local_addr().map_or(0, |a| a.port())
    }
}

impl ProxyTunnelTarget for MockTunnelTarget {
    fn tcp_connect<'a>(
        &'a self,
        dst: SocketAddr,
    ) -> Pin<Box<dyn Future<Output = io::Result<DynStream>> + Send + 'a>> {
        self.tcp_conns.fetch_add(1, Ordering::SeqCst);
        if self.hang_tcp {
            // Never completes: the caller must time the attempt out.
            return Box::pin(async move { std::future::pending::<io::Result<DynStream>>().await });
        }
        if let Some(kind) = self.fail_tcp_with {
            return Box::pin(async move { Err(io::Error::new(kind, "mock tcp connect failed")) });
        }
        if !self.tcp_delay.is_zero() {
            let delay = self.tcp_delay;
            let redirect = self.dial_redirect;
            return Box::pin(async move {
                tokio::time::sleep(delay).await;
                let stream = TcpStream::connect(redirect.unwrap_or(dst)).await?;
                Ok(Box::new(stream) as DynStream)
            });
        }
        Box::pin(async move {
            let stream = TcpStream::connect(self.dial_redirect.unwrap_or(dst)).await?;
            Ok(Box::new(stream) as DynStream)
        })
    }

    fn udp_bind<'a>(
        &'a self,
        local_port: u16,
    ) -> Pin<Box<dyn Future<Output = io::Result<Box<dyn ProxyUdpSocket>>> + Send + 'a>> {
        let udp_redirect = self.udp_redirect;
        Box::pin(async move {
            let bind_addr = SocketAddr::from(([127, 0, 0, 1], local_port));
            let socket = UdpSocket::bind(bind_addr).await?;
            if let Some(redirect) = udp_redirect {
                return Ok(Box::new(RedirectUdpSocket {
                    inner: socket,
                    redirect,
                    last_target: Mutex::new(None),
                }) as Box<dyn ProxyUdpSocket>);
            }
            Ok(Box::new(socket) as Box<dyn ProxyUdpSocket>)
        })
    }

    fn resolve_in_tunnel<'a>(
        &'a self,
        domain: &'a str,
    ) -> Pin<Box<dyn Future<Output = io::Result<IpAddr>> + Send + 'a>> {
        Box::pin(async move {
            if let Ok(ip) = domain.parse::<IpAddr>() {
                return Ok(ip);
            }
            let table = self.dns_table.read();
            if let Some(ip) = table.get(domain) {
                Ok(*ip)
            } else {
                Err(io::Error::new(
                    io::ErrorKind::NotFound,
                    format!("mock dns could not resolve '{}'", domain),
                ))
            }
        })
    }

    fn note_attempt_aborted(&self) {
        self.aborted.store(true, Ordering::SeqCst);
    }

    fn tunnel_id(&self) -> Option<&str> {
        // Real targets report their tunnel id so the router can
        // deduplicate pool failover attempts (and so the
        // terminal-failure log can name the tunnel tried); the mock
        // must do the same, otherwise a single-tunnel pool re-tries
        // the same mock three times and the log shows no tunnel.
        Some(&self.id)
    }

    fn is_live(&self) -> bool {
        self.live
    }
}

// -----------------------------------------------------------------------------
// Test Helpers: Mock TCP/UDP/HTTP Servers
// -----------------------------------------------------------------------------

async fn spawn_echo_tcp_server() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        while let Ok((mut stream, _)) = listener.accept().await {
            tokio::spawn(async move {
                let mut buf = [0u8; 1024];
                while let Ok(n) = stream.read(&mut buf).await {
                    if n == 0 {
                        break;
                    }
                    if stream.write_all(&buf[..n]).await.is_err() {
                        break;
                    }
                }
            });
        }
    });
    addr
}

/// Accept connections, read `expect_bytes` bytes from each, then close
/// without replying — the zero-response EOF the retry is built for.
/// Reading first (instead of closing immediately) lets the client's
/// write succeed, so the proxy sees a clean EOF after a real request
/// rather than a broken pipe.
async fn spawn_blackhole_tcp_server(expect_bytes: usize) -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        while let Ok((mut stream, _)) = listener.accept().await {
            tokio::spawn(async move {
                let mut buf = [0u8; 8192];
                let mut read = 0usize;
                while read < expect_bytes {
                    let want = (expect_bytes - read).min(buf.len());
                    match stream.read(&mut buf[..want]).await {
                        Ok(0) => break,
                        Ok(n) => read += n,
                        Err(_) => break,
                    }
                }
            });
        }
    });
    addr
}

/// Accept connections, read the request, write back exactly one byte,
/// then close — a session that received a response (so no retry) but
/// still ended early.
async fn spawn_one_byte_tcp_server() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        while let Ok((mut stream, _)) = listener.accept().await {
            tokio::spawn(async move {
                let mut buf = [0u8; 1024];
                if stream.read(&mut buf).await.is_ok() {
                    let _ = stream.write_all(b"X").await;
                }
            });
        }
    });
    addr
}

/// Accept connections and close immediately without reading — the
/// peer sends RST (Linux resets a socket closed with unread data in
/// its receive buffer), so the proxy sees a tunnel-side reset with
/// zero response bytes instead of the clean EOF the blackhole gives.
async fn spawn_reset_tcp_server() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        while let Ok((stream, _)) = listener.accept().await {
            drop(stream);
        }
    });
    addr
}

/// Accept connections, read the request, write back exactly one
/// byte, then close with the rest of the request unread — the proxy
/// sees one response byte followed by a reset, so it must NOT retry.
async fn spawn_reset_after_response_tcp_server() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        while let Ok((mut stream, _)) = listener.accept().await {
            tokio::spawn(async move {
                let mut buf = [0u8; 1];
                if stream.read_exact(&mut buf).await.is_ok() {
                    let _ = stream.write_all(b"X").await;
                }
            });
        }
    });
    addr
}

/// Accept connections, read the whole GET head, wait `delay`, then
/// echo it back — a slow primary that answers late (fix12: the
/// secondary wins the race, but the primary was only slow, not
/// dead, so it must take no breaker penalty).
async fn spawn_delayed_echo_tcp_server(delay: Duration) -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        while let Ok((mut stream, _)) = listener.accept().await {
            tokio::spawn(async move {
                let mut buf = [0u8; 8192];
                let mut read = 0usize;
                while read < buf.len() {
                    match stream.read(&mut buf[read..]).await {
                        Ok(0) => break,
                        Ok(n) => {
                            read += n;
                            if read >= 4 && buf[..read].ends_with(b"\r\n\r\n") {
                                break;
                            }
                        }
                        Err(_) => break,
                    }
                }
                tokio::time::sleep(delay).await;
                let _ = stream.write_all(&buf[..read]).await;
            });
        }
    });
    addr
}

/// Like `spawn_delayed_echo_tcp_server`, but the connection stays
/// open after the delayed echo instead of closing: a primary that
/// answers late without ending the epoch, so a secondary dial in
/// flight reaches its pre-send check (and is suppressed as
/// primary-won) instead of being aborted by the epoch end.
async fn spawn_delayed_echo_keep_open_tcp_server(delay: Duration) -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        while let Ok((mut stream, _)) = listener.accept().await {
            tokio::spawn(async move {
                let mut buf = [0u8; 8192];
                let mut read = 0usize;
                while read < buf.len() {
                    match stream.read(&mut buf[read..]).await {
                        Ok(0) => return,
                        Ok(n) => {
                            read += n;
                            if read >= 4 && buf[..read].ends_with(b"\r\n\r\n") {
                                break;
                            }
                        }
                        Err(_) => return,
                    }
                }
                tokio::time::sleep(delay).await;
                let _ = stream.write_all(&buf[..read]).await;
                // Stay open: the epoch must outlive the dial for the
                // pre-send check to run. (The session ends on the
                // test's idle timeout instead.)
                tokio::time::sleep(Duration::from_secs(30)).await;
            });
        }
    });
    addr
}

/// Accept connections, read the request, wait `delay`, then close
/// without replying — a primary whose connection dies after a delay
/// (fix12: EOF before any response byte is a transport failure,
/// not a blackhole).
async fn spawn_delayed_close_tcp_server(delay: Duration) -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        while let Ok((mut stream, _)) = listener.accept().await {
            tokio::spawn(async move {
                let mut buf = [0u8; 1024];
                let _ = stream.read(&mut buf).await;
                tokio::time::sleep(delay).await;
                // Dropping the stream closes the connection: the
                // observer sees EOF.
            });
        }
    });
    addr
}

/// A `PoolRouter` wrapper that records every attribution call
/// (blackhole / transport failure / RTT sample) per tunnel id, so
/// fix12 tests can prove what penalty the losing primary earned.
/// The pool router itself uses the trait's no-op defaults, so
/// penalties are invisible through it.
struct RecordingRouter {
    inner: Arc<PoolRouter>,
    blackholes: Mutex<Vec<String>>,
    transport_failures: Mutex<Vec<String>>,
    rtt_samples: Mutex<Vec<(String, u64)>>,
}

impl RecordingRouter {
    fn new(inner: Arc<PoolRouter>) -> Self {
        Self {
            inner,
            blackholes: Mutex::new(Vec::new()),
            transport_failures: Mutex::new(Vec::new()),
            rtt_samples: Mutex::new(Vec::new()),
        }
    }

    fn blackhole_count(&self, tunnel_id: &str) -> usize {
        self.blackholes
            .lock()
            .unwrap()
            .iter()
            .filter(|id| id.as_str() == tunnel_id)
            .count()
    }

    fn transport_failure_count(&self, tunnel_id: &str) -> usize {
        self.transport_failures
            .lock()
            .unwrap()
            .iter()
            .filter(|id| id.as_str() == tunnel_id)
            .count()
    }

    fn rtt_samples_for(&self, tunnel_id: &str) -> Vec<u64> {
        self.rtt_samples
            .lock()
            .unwrap()
            .iter()
            .filter(|(id, _)| id.as_str() == tunnel_id)
            .map(|(_, ms)| *ms)
            .collect()
    }
}

impl TunnelRouter for RecordingRouter {
    fn authenticate(
        &self,
        credentials: Option<(&str, &str)>,
    ) -> Result<TunnelSelector, ProxyAuthError> {
        self.inner.authenticate(credentials)
    }

    fn select_tunnel<'a>(
        &'a self,
        selector: &'a TunnelSelector,
        credentials: Option<(&'a str, &'a str)>,
    ) -> SelectTunnelFut<'a> {
        self.inner.select_tunnel(selector, credentials)
    }

    fn record_tunnel_blackhole(&self, tunnel_id: &str) {
        self.blackholes.lock().unwrap().push(tunnel_id.to_string());
    }

    fn record_tunnel_transport_failure(&self, tunnel_id: &str) {
        self.transport_failures
            .lock()
            .unwrap()
            .push(tunnel_id.to_string());
    }

    fn record_tunnel_rtt(&self, tunnel_id: &str, sample_ms: u64) {
        self.rtt_samples
            .lock()
            .unwrap()
            .push((tunnel_id.to_string(), sample_ms));
    }
}

/// Test-only tunnel target that records every DNS query and TCP dial
/// (requested destination) instead of performing them, so tests can
/// prove which tunnel a query or dial went through (run-3 #7
/// pre-resolve, #6 forbidden destinations). DNS answers come from a
/// fixed table; TCP dials go to a redirect address (a loopback echo
/// server) while the proxy still sees the requested destination.
struct RecordingStubTarget {
    id: String,
    live: bool,
    dns_table: RwLock<HashMap<String, IpAddr>>,
    queries: Mutex<Vec<String>>,
    dials: Mutex<Vec<SocketAddr>>,
    fail_tcp: bool,
    dial_redirect: Option<SocketAddr>,
}

impl RecordingStubTarget {
    fn new(id: &str) -> Self {
        Self {
            id: id.to_string(),
            live: false,
            dns_table: RwLock::new(HashMap::new()),
            queries: Mutex::new(Vec::new()),
            dials: Mutex::new(Vec::new()),
            fail_tcp: false,
            dial_redirect: None,
        }
    }

    fn with_live(self) -> Self {
        Self { live: true, ..self }
    }

    /// Fail TCP dials fast (after recording them) instead of dialing.
    fn with_failing_tcp(self) -> Self {
        Self {
            fail_tcp: true,
            ..self
        }
    }

    fn with_dns(self, domain: &str, ip: IpAddr) -> Self {
        self.dns_table.write().insert(domain.to_string(), ip);
        self
    }

    /// Redirect actual TCP dials to `addr` while the proxy still sees
    /// the requested (public) destination (see [`TEST_ECHO_IP`]).
    fn with_dial_redirect(self, addr: SocketAddr) -> Self {
        Self {
            dial_redirect: Some(addr),
            ..self
        }
    }

    fn queries(&self) -> Vec<String> {
        self.queries.lock().unwrap().clone()
    }

    fn dials(&self) -> Vec<SocketAddr> {
        self.dials.lock().unwrap().clone()
    }
}

impl ProxyTunnelTarget for RecordingStubTarget {
    fn tcp_connect<'a>(
        &'a self,
        dst: SocketAddr,
    ) -> Pin<Box<dyn Future<Output = io::Result<DynStream>> + Send + 'a>> {
        self.dials.lock().unwrap().push(dst);
        if self.fail_tcp {
            return Box::pin(async move {
                Err(io::Error::new(
                    io::ErrorKind::ConnectionRefused,
                    "stub tcp connect refused",
                ))
            });
        }
        let redirect = self.dial_redirect;
        Box::pin(async move {
            let stream = TcpStream::connect(redirect.unwrap_or(dst)).await?;
            Ok(Box::new(stream) as DynStream)
        })
    }

    fn udp_bind<'a>(
        &'a self,
        _local_port: u16,
    ) -> Pin<Box<dyn Future<Output = io::Result<Box<dyn ProxyUdpSocket>>> + Send + 'a>> {
        Box::pin(async move { Err(io::Error::other("stub udp unused")) })
    }

    fn resolve_in_tunnel<'a>(
        &'a self,
        domain: &'a str,
    ) -> Pin<Box<dyn Future<Output = io::Result<IpAddr>> + Send + 'a>> {
        self.queries.lock().unwrap().push(domain.to_string());
        let found = self.dns_table.read().get(domain).copied();
        match found {
            Some(ip) => Box::pin(async move { Ok(ip) }),
            None => Box::pin(async move {
                Err(io::Error::new(
                    io::ErrorKind::NotFound,
                    format!("stub dns could not resolve '{domain}'"),
                ))
            }),
        }
    }

    fn tunnel_id(&self) -> Option<&str> {
        Some(&self.id)
    }

    fn is_live(&self) -> bool {
        self.live
    }
}

/// Stub `TunnelRouter` for the #7 pre-resolve tests: `select_tunnel`
/// enforces tunnel-A credentials and only ever returns target A —
/// the real router's password gate without a live WireGuard stack.
/// Target B is held only by the test, as the tunnel the old unbound
/// pre-resolve would have picked.
struct AuthEnforcingStubRouter {
    target_a: Arc<dyn ProxyTunnelTarget>,
}

impl TunnelRouter for AuthEnforcingStubRouter {
    fn authenticate(
        &self,
        credentials: Option<(&str, &str)>,
    ) -> Result<TunnelSelector, ProxyAuthError> {
        match credentials {
            Some(("wgcf-a", "pw-a")) => Ok(TunnelSelector::ById("wgcf-a".to_string())),
            Some(_) => Err(ProxyAuthError::InvalidCredentials),
            None => Err(ProxyAuthError::AuthRequired),
        }
    }

    fn select_tunnel<'a>(
        &'a self,
        _selector: &'a TunnelSelector,
        credentials: Option<(&'a str, &'a str)>,
    ) -> SelectTunnelFut<'a> {
        let target = Arc::clone(&self.target_a);
        Box::pin(async move {
            match credentials {
                Some(("wgcf-a", "pw-a")) => Ok(target),
                _ => Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "invalid proxy credentials for the selected tunnel",
                )),
            }
        })
    }
}

async fn spawn_echo_tcp_server_ipv6() -> Option<SocketAddr> {
    let listener = TcpListener::bind("[::1]:0").await.ok()?;
    let addr = listener.local_addr().ok()?;
    tokio::spawn(async move {
        while let Ok((mut stream, _)) = listener.accept().await {
            tokio::spawn(async move {
                let mut buf = [0u8; 1024];
                while let Ok(n) = stream.read(&mut buf).await {
                    if n == 0 {
                        break;
                    }
                    if stream.write_all(&buf[..n]).await.is_err() {
                        break;
                    }
                }
            });
        }
    });
    Some(addr)
}

async fn spawn_echo_udp_server() -> SocketAddr {
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let addr = socket.local_addr().unwrap();
    tokio::spawn(async move {
        let mut buf = [0u8; 2048];
        while let Ok((n, client_addr)) = socket.recv_from(&mut buf).await {
            let _ = socket.send_to(&buf[..n], client_addr).await;
        }
    });
    addr
}

async fn spawn_mock_http_server(response_body: &'static str) -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        while let Ok((mut stream, _)) = listener.accept().await {
            let body = response_body.as_bytes();
            tokio::spawn(async move {
                let mut header_buf = Vec::new();
                let mut b = [0u8; 1];
                while header_buf.len() < 8192 {
                    if stream.read_exact(&mut b).await.is_err() {
                        break;
                    }
                    header_buf.push(b[0]);
                    if header_buf.ends_with(b"\r\n\r\n") {
                        break;
                    }
                }
                let resp = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                    body.len()
                );
                let _ = stream.write_all(resp.as_bytes()).await;
                let _ = stream.write_all(body).await;
                let _ = stream.flush().await;
            });
        }
    });
    addr
}

// -----------------------------------------------------------------------------
// SOCKS5 Tests: Greeting & Authentication
// -----------------------------------------------------------------------------

#[tokio::test]
async fn test_socks5_greeting_no_auth() {
    let target = Arc::new(DirectTunnelTarget);
    let router: Arc<dyn TunnelRouter> =
        Arc::new(SingleTunnelRouter::new("test-tunnel", target, None));

    let (client, server) = tokio::io::duplex(1024);
    tokio::spawn(async move {
        let _ = handle_socks5(server, router).await;
    });

    let mut client = client;
    // Offer [0x00] (No Auth)
    client
        .write_all(&[SOCKS5_VERSION, 1, METHOD_NO_AUTH])
        .await
        .unwrap();

    let mut resp = [0u8; 2];
    client.read_exact(&mut resp).await.unwrap();
    assert_eq!(resp, [SOCKS5_VERSION, METHOD_NO_AUTH]);
}

#[tokio::test]
async fn test_socks5_greeting_user_pass_negotiation() {
    let target = Arc::new(DirectTunnelTarget);
    let router: Arc<dyn TunnelRouter> = Arc::new(SingleTunnelRouter::new(
        "auth-tunnel",
        target,
        Some(("admin".to_string(), "secret123".to_string())),
    ));

    let (client, server) = tokio::io::duplex(1024);
    tokio::spawn(async move {
        let _ = handle_socks5(server, router).await;
    });

    let mut client = client;
    // Client offers [0x00, 0x02]; since server requires auth, it must choose 0x02
    client
        .write_all(&[SOCKS5_VERSION, 2, METHOD_NO_AUTH, METHOD_USER_PASS])
        .await
        .unwrap();

    let mut resp = [0u8; 2];
    client.read_exact(&mut resp).await.unwrap();
    assert_eq!(resp, [SOCKS5_VERSION, METHOD_USER_PASS]);
}

#[tokio::test]
async fn test_socks5_greeting_no_acceptable_method() {
    let target = Arc::new(DirectTunnelTarget);
    let router: Arc<dyn TunnelRouter> = Arc::new(SingleTunnelRouter::new(
        "auth-tunnel",
        target,
        Some(("admin".to_string(), "secret123".to_string())),
    ));

    let (client, server) = tokio::io::duplex(1024);
    tokio::spawn(async move {
        let _ = handle_socks5(server, router).await;
    });

    let mut client = client;
    // Client only offers [0x00]; server requires auth -> must return 0xFF
    client
        .write_all(&[SOCKS5_VERSION, 1, METHOD_NO_AUTH])
        .await
        .unwrap();

    let mut resp = [0u8; 2];
    client.read_exact(&mut resp).await.unwrap();
    assert_eq!(resp, [SOCKS5_VERSION, METHOD_NO_ACCEPTABLE]);
}

#[tokio::test]
async fn test_socks5_rfc1929_auth_success_and_failure() {
    let target = Arc::new(DirectTunnelTarget);
    let router: Arc<dyn TunnelRouter> = Arc::new(SingleTunnelRouter::new(
        "test-tunn",
        target,
        Some(("alice".to_string(), "pass123".to_string())),
    ));

    // Case 1: Wrong password -> Auth failure (0x01)
    {
        let (mut client, server) = tokio::io::duplex(1024);
        let r = Arc::clone(&router);
        tokio::spawn(async move {
            let _ = handle_socks5(server, r).await;
        });

        // Greeting
        client
            .write_all(&[SOCKS5_VERSION, 1, METHOD_USER_PASS])
            .await
            .unwrap();
        let mut g_resp = [0u8; 2];
        client.read_exact(&mut g_resp).await.unwrap();
        assert_eq!(g_resp, [SOCKS5_VERSION, METHOD_USER_PASS]);

        // RFC 1929 Subnegotiation with wrong password
        let mut auth_req = vec![RFC1929_VERSION, 5];
        auth_req.extend_from_slice(b"alice");
        auth_req.push(5);
        auth_req.extend_from_slice(b"wrong");
        client.write_all(&auth_req).await.unwrap();

        let mut a_resp = [0u8; 2];
        client.read_exact(&mut a_resp).await.unwrap();
        assert_eq!(a_resp[0], RFC1929_VERSION);
        assert_ne!(a_resp[1], 0x00) // Non-zero failure
    };

    // Case 2: Correct password -> Auth success (0x00)
    {
        let (mut client, server) = tokio::io::duplex(1024);
        let r = Arc::clone(&router);
        tokio::spawn(async move {
            let _ = handle_socks5(server, r).await;
        });

        // Greeting
        client
            .write_all(&[SOCKS5_VERSION, 1, METHOD_USER_PASS])
            .await
            .unwrap();
        let mut g_resp = [0u8; 2];
        client.read_exact(&mut g_resp).await.unwrap();
        assert_eq!(g_resp, [SOCKS5_VERSION, METHOD_USER_PASS]);

        // RFC 1929 Subnegotiation with correct password
        let mut auth_req = vec![RFC1929_VERSION, 5];
        auth_req.extend_from_slice(b"alice");
        auth_req.push(7);
        auth_req.extend_from_slice(b"pass123");
        client.write_all(&auth_req).await.unwrap();

        let mut a_resp = [0u8; 2];
        client.read_exact(&mut a_resp).await.unwrap();
        assert_eq!(a_resp, [RFC1929_VERSION, 0x00]); // Status 0x00: Success
    }
}

// -----------------------------------------------------------------------------
// SOCKS5 Tests: CONNECT Command (IPv4, IPv6, Domain)
// -----------------------------------------------------------------------------

#[tokio::test]
async fn test_socks5_connect_ipv4() {
    let echo_addr = spawn_echo_tcp_server().await;
    let target_addr = test_echo_target(echo_addr);
    let SocketAddr::V4(target_v4) = target_addr else {
        unreachable!();
    };

    // The destination guard forbids loopback targets, so the client
    // names the TEST-NET-1 stand-in and the mock dials the loopback
    // echo server (see `TEST_ECHO_IP`).
    let target = Arc::new(MockTunnelTarget::new("test-tunnel").with_dial_redirect(echo_addr));
    let router: Arc<dyn TunnelRouter> =
        Arc::new(SingleTunnelRouter::new("test-tunnel", target, None));

    let (mut client, server) = tokio::io::duplex(2048);
    tokio::spawn(async move {
        let _ = handle_socks5(server, router).await;
    });

    // 1. Greeting
    client
        .write_all(&[SOCKS5_VERSION, 1, METHOD_NO_AUTH])
        .await
        .unwrap();
    let mut g_resp = [0u8; 2];
    client.read_exact(&mut g_resp).await.unwrap();
    assert_eq!(g_resp[1], METHOD_NO_AUTH);

    // 2. CONNECT IPv4
    let mut cmd = vec![SOCKS5_VERSION, CMD_CONNECT, 0x00, ATYP_IPV4];
    cmd.extend_from_slice(&target_v4.ip().octets());
    cmd.extend_from_slice(&target_v4.port().to_be_bytes());
    client.write_all(&cmd).await.unwrap();

    let mut reply_hdr = [0u8; 4];
    client.read_exact(&mut reply_hdr).await.unwrap();
    assert_eq!(reply_hdr[0], SOCKS5_VERSION);
    assert_eq!(reply_hdr[1], REP_SUCCESS);
    assert_eq!(reply_hdr[3], ATYP_IPV4);
    let mut bnd_buf = [0u8; 6];
    client.read_exact(&mut bnd_buf).await.unwrap();

    // 3. Bidirectional data echo through tunnel
    let msg = b"socks5_echo_test_message!";
    client.write_all(msg).await.unwrap();
    let mut echo_buf = vec![0u8; msg.len()];
    client.read_exact(&mut echo_buf).await.unwrap();
    assert_eq!(&echo_buf, msg);
}

#[tokio::test]
async fn test_socks5_connect_ipv6() {
    struct MockIpv6EchoTarget {
        expected_dst: SocketAddr,
    }

    impl ProxyTunnelTarget for MockIpv6EchoTarget {
        fn tcp_connect<'a>(
            &'a self,
            dst: SocketAddr,
        ) -> Pin<Box<dyn Future<Output = io::Result<DynStream>> + Send + 'a>> {
            let expected = self.expected_dst;
            Box::pin(async move {
                assert_eq!(dst, expected);
                let (client_side, mut server_side) = tokio::io::duplex(2048);
                tokio::spawn(async move {
                    let mut buf = [0u8; 64];
                    if let Ok(n) = server_side.read(&mut buf).await
                        && n > 0
                    {
                        let _ = server_side.write_all(&buf[..n]).await;
                    }
                });
                Ok(Box::new(client_side) as DynStream)
            })
        }

        fn udp_bind<'a>(
            &'a self,
            _local_port: u16,
        ) -> Pin<Box<dyn Future<Output = io::Result<Box<dyn ProxyUdpSocket>>> + Send + 'a>>
        {
            Box::pin(async { Err(io::Error::other("unused")) })
        }

        fn resolve_in_tunnel<'a>(
            &'a self,
            _domain: &'a str,
        ) -> Pin<Box<dyn Future<Output = io::Result<IpAddr>> + Send + 'a>> {
            Box::pin(async { Err(io::Error::other("unused")) })
        }
    }

    let echo_v6: std::net::SocketAddrV6 = "[2606:4700:4700::1111]:443".parse().unwrap();
    let target = Arc::new(MockIpv6EchoTarget {
        expected_dst: SocketAddr::V6(echo_v6),
    });
    let router: Arc<dyn TunnelRouter> =
        Arc::new(SingleTunnelRouter::new("test-tunnel-v6", target, None));

    let (mut client, server) = tokio::io::duplex(2048);
    tokio::spawn(async move {
        let _ = handle_socks5(server, router).await;
    });

    client
        .write_all(&[SOCKS5_VERSION, 1, METHOD_NO_AUTH])
        .await
        .unwrap();
    let mut g_resp = [0u8; 2];
    client.read_exact(&mut g_resp).await.unwrap();

    let mut cmd = vec![SOCKS5_VERSION, CMD_CONNECT, 0x00, ATYP_IPV6];
    cmd.extend_from_slice(&echo_v6.ip().octets());
    cmd.extend_from_slice(&echo_v6.port().to_be_bytes());
    client.write_all(&cmd).await.unwrap();

    let mut reply_hdr = [0u8; 4];
    client.read_exact(&mut reply_hdr).await.unwrap();
    assert_eq!(reply_hdr[1], REP_SUCCESS);
    let mut dummy_bnd = [0u8; 6];
    client.read_exact(&mut dummy_bnd).await.unwrap();

    client.write_all(b"ipv6_socks5_echo").await.unwrap();
    let mut buf = [0u8; 16];
    client.read_exact(&mut buf).await.unwrap();
    assert_eq!(&buf, b"ipv6_socks5_echo");
}

#[tokio::test]
async fn test_socks5_connect_domain_with_tunnel_resolution() {
    let echo_addr = spawn_echo_tcp_server().await;
    let echo_port = echo_addr.port();

    let mock_target = Arc::new(
        MockTunnelTarget::new("tunnel-01")
            .with_dns("echo.tunnel.local", TEST_ECHO_IP)
            .with_dial_redirect(echo_addr),
    );
    assert_eq!(mock_target.id(), "tunnel-01");
    let router: Arc<dyn TunnelRouter> =
        Arc::new(SingleTunnelRouter::new("tunnel-01", mock_target, None));

    let (mut client, server) = tokio::io::duplex(2048);
    tokio::spawn(async move {
        let _ = handle_socks5(server, router).await;
    });

    // 1. Greeting
    client
        .write_all(&[SOCKS5_VERSION, 1, METHOD_NO_AUTH])
        .await
        .unwrap();
    let mut g_resp = [0u8; 2];
    client.read_exact(&mut g_resp).await.unwrap();
    assert_eq!(g_resp[1], METHOD_NO_AUTH);

    // 2. CONNECT Domain: "echo.tunnel.local:port"
    let domain = "echo.tunnel.local";
    let mut cmd = vec![SOCKS5_VERSION, CMD_CONNECT, 0x00, ATYP_DOMAIN];
    cmd.push(domain.len() as u8);
    cmd.extend_from_slice(domain.as_bytes());
    cmd.extend_from_slice(&echo_port.to_be_bytes());
    client.write_all(&cmd).await.unwrap();

    let mut reply_hdr = [0u8; 4];
    client.read_exact(&mut reply_hdr).await.unwrap();
    assert_eq!(reply_hdr[1], REP_SUCCESS);
    let mut dummy_bnd = [0u8; 6];
    client.read_exact(&mut dummy_bnd).await.unwrap();

    // 3. Echo verification
    client.write_all(b"domain_tunnel_ok").await.unwrap();
    let mut buf = [0u8; 16];
    client.read_exact(&mut buf).await.unwrap();
    assert_eq!(&buf, b"domain_tunnel_ok");
}

#[tokio::test]
async fn test_socks5_connect_unreachable_target_returns_error() {
    let target = Arc::new(DirectTunnelTarget);
    let router: Arc<dyn TunnelRouter> =
        Arc::new(SingleTunnelRouter::new("test-tunnel", target, None));

    let (mut client, server) = tokio::io::duplex(1024);
    tokio::spawn(async move {
        let _ = handle_socks5(server, router).await;
    });

    client
        .write_all(&[SOCKS5_VERSION, 1, METHOD_NO_AUTH])
        .await
        .unwrap();
    let mut g_resp = [0u8; 2];
    client.read_exact(&mut g_resp).await.unwrap();

    // CONNECT to 127.0.0.1 on a closed port (e.g. 1). The destination
    // guard rejects loopback targets before dialing, so this now
    // reports connection-not-allowed instead of refused/unreachable
    // (audit run-1, `proxy.destination.ipv4-loopback-rfc1918-not-forbidden`).
    let mut cmd = vec![SOCKS5_VERSION, CMD_CONNECT, 0x00, ATYP_IPV4];
    cmd.extend_from_slice(&[127, 0, 0, 1]);
    cmd.extend_from_slice(&1u16.to_be_bytes());
    client.write_all(&cmd).await.unwrap();

    let mut reply_hdr = [0u8; 4];
    client.read_exact(&mut reply_hdr).await.unwrap();
    assert_eq!(reply_hdr[0], SOCKS5_VERSION);
    assert_eq!(
        reply_hdr[1], REP_CONN_NOT_ALLOWED,
        "Expected connection not allowed for a loopback target, got 0x{:02X}",
        reply_hdr[1]
    );
}

#[tokio::test]
async fn test_socks5_connect_unknown_tunnel_reports_general_failure() {
    // A username naming a tunnel that does not exist fails selection, and
    // the reply must be general failure (0x01) — not host unreachable
    // (0x04) — so a client can tell a bad tunnel name apart from a tunnel
    // whose handshake failed.
    let t1 = Arc::new(MockTunnelTarget::new("wgcf-001"));
    let pool = Arc::new(
        PoolRouter::new(PoolStrategy::RoundRobin, true).with_auth(AuthMode::PerTunnel, None),
    );
    pool.add_tunnel("wgcf-001", Arc::clone(&t1) as Arc<dyn ProxyTunnelTarget>);
    let router: Arc<dyn TunnelRouter> = pool;

    let (mut client, server) = tokio::io::duplex(2048);
    tokio::spawn(async move {
        let _ = handle_socks5(server, router).await;
    });

    // Greeting offering only username/password auth.
    client
        .write_all(&[SOCKS5_VERSION, 1, METHOD_USER_PASS])
        .await
        .unwrap();
    let mut g_resp = [0u8; 2];
    client.read_exact(&mut g_resp).await.unwrap();
    assert_eq!(g_resp, [SOCKS5_VERSION, METHOD_USER_PASS]);

    // Authenticate as a tunnel that does not exist (no password set, so
    // auth itself succeeds and selection fails at CONNECT).
    let mut auth_req = vec![RFC1929_VERSION, 11];
    auth_req.extend_from_slice(b"nonexistent");
    auth_req.push(0);
    client.write_all(&auth_req).await.unwrap();
    let mut a_resp = [0u8; 2];
    client.read_exact(&mut a_resp).await.unwrap();
    assert_eq!(a_resp, [RFC1929_VERSION, 0x00]);

    // CONNECT to any target; selection must fail before connecting.
    // The target is a public TEST-NET-2 address: a loopback target
    // would be rejected by the destination guard before selection
    // runs, hiding the general-failure reply under test.
    let mut cmd = vec![SOCKS5_VERSION, CMD_CONNECT, 0x00, ATYP_IPV4];
    cmd.extend_from_slice(&[198, 51, 100, 1]);
    cmd.extend_from_slice(&80u16.to_be_bytes());
    client.write_all(&cmd).await.unwrap();

    let mut reply_hdr = [0u8; 4];
    client.read_exact(&mut reply_hdr).await.unwrap();
    assert_eq!(reply_hdr[0], SOCKS5_VERSION);
    assert_eq!(
        reply_hdr[1], REP_GENERAL_FAILURE,
        "unknown tunnel must report general failure, got 0x{:02X}",
        reply_hdr[1]
    );
}

#[tokio::test]
async fn test_socks5_connect_timeout_reports_host_unreachable() {
    // A tunnel whose TCP connect times out — the WireGuard handshake
    // never completes — must report host unreachable (0x04), not TTL
    // expired (0x06): the peer is unreachable, and TTL expiry never
    // applies to this userspace stack. The reply code must be stable
    // for the same failure (a DNS failure inside the tunnel already
    // reports 0x04).
    let t1 = Arc::new(MockTunnelTarget::new("wgcf-001").with_tcp_failure(io::ErrorKind::TimedOut));
    let pool = Arc::new(
        PoolRouter::new(PoolStrategy::RoundRobin, true).with_auth(AuthMode::PerTunnel, None),
    );
    pool.add_tunnel("wgcf-001", Arc::clone(&t1) as Arc<dyn ProxyTunnelTarget>);
    let router: Arc<dyn TunnelRouter> = pool;

    let (mut client, server) = tokio::io::duplex(2048);
    tokio::spawn(async move {
        let _ = handle_socks5(server, router).await;
    });

    // Greeting offering only username/password auth.
    client
        .write_all(&[SOCKS5_VERSION, 1, METHOD_USER_PASS])
        .await
        .unwrap();
    let mut g_resp = [0u8; 2];
    client.read_exact(&mut g_resp).await.unwrap();
    assert_eq!(g_resp, [SOCKS5_VERSION, METHOD_USER_PASS]);

    // Authenticate as the existing tunnel (no password set, so auth
    // itself succeeds and the failure happens at CONNECT).
    let mut auth_req = vec![RFC1929_VERSION, 8];
    auth_req.extend_from_slice(b"wgcf-001");
    auth_req.push(0);
    client.write_all(&auth_req).await.unwrap();
    let mut a_resp = [0u8; 2];
    client.read_exact(&mut a_resp).await.unwrap();
    assert_eq!(a_resp, [RFC1929_VERSION, 0x00]);

    // CONNECT to an IP literal, so no DNS is involved and the failure
    // comes from the TCP connect itself.
    let mut cmd = vec![SOCKS5_VERSION, CMD_CONNECT, 0x00, ATYP_IPV4];
    cmd.extend_from_slice(&[93, 184, 216, 34]);
    cmd.extend_from_slice(&80u16.to_be_bytes());
    client.write_all(&cmd).await.unwrap();

    let mut reply_hdr = [0u8; 4];
    client.read_exact(&mut reply_hdr).await.unwrap();
    assert_eq!(reply_hdr[0], SOCKS5_VERSION);
    assert_eq!(
        reply_hdr[1], REP_HOST_UNREACHABLE,
        "timed-out connect must report host unreachable, got 0x{:02X}",
        reply_hdr[1]
    );
}

#[tokio::test]
async fn test_socks5_connect_empty_pool_reports_network_unreachable() {
    // A valid selector whose pool is empty — no tunnel is healthy right
    // now — must report network unreachable (0x03), not general failure
    // (0x01): 0x01 means "you mistyped the name", 0x03 means "all
    // tunnels are down". The client can tell the two apart without the
    // daemon log.
    let pool = Arc::new(
        PoolRouter::new(PoolStrategy::RoundRobin, true).with_auth(AuthMode::PerTunnel, None),
    );
    let router: Arc<dyn TunnelRouter> = pool;

    let (mut client, server) = tokio::io::duplex(2048);
    tokio::spawn(async move {
        let _ = handle_socks5(server, router).await;
    });

    // Greeting offering only username/password auth.
    client
        .write_all(&[SOCKS5_VERSION, 1, METHOD_USER_PASS])
        .await
        .unwrap();
    let mut g_resp = [0u8; 2];
    client.read_exact(&mut g_resp).await.unwrap();
    assert_eq!(g_resp, [SOCKS5_VERSION, METHOD_USER_PASS]);

    // Authenticate as the `round-robin` keyword (no password set, so
    // auth itself succeeds and selection fails at CONNECT).
    let mut auth_req = vec![RFC1929_VERSION, 11];
    auth_req.extend_from_slice(b"round-robin");
    auth_req.push(0);
    client.write_all(&auth_req).await.unwrap();
    let mut a_resp = [0u8; 2];
    client.read_exact(&mut a_resp).await.unwrap();
    assert_eq!(a_resp, [RFC1929_VERSION, 0x00]);

    // CONNECT to an IP literal; selection must fail before connecting.
    let mut cmd = vec![SOCKS5_VERSION, CMD_CONNECT, 0x00, ATYP_IPV4];
    cmd.extend_from_slice(&[93, 184, 216, 34]);
    cmd.extend_from_slice(&80u16.to_be_bytes());
    client.write_all(&cmd).await.unwrap();

    let mut reply_hdr = [0u8; 4];
    client.read_exact(&mut reply_hdr).await.unwrap();
    assert_eq!(reply_hdr[0], SOCKS5_VERSION);
    assert_eq!(
        reply_hdr[1], REP_NETWORK_UNREACHABLE,
        "empty pool must report network unreachable, got 0x{:02X}",
        reply_hdr[1]
    );
}

#[tokio::test]
async fn test_http_connect_unknown_tunnel_returns_404() {
    // Same distinction as the SOCKS5 test above, over HTTP CONNECT: a
    // tunnel name that does not exist answers 404, while a tunnel that
    // exists but cannot connect stays 502.
    let t1 = Arc::new(MockTunnelTarget::new("wgcf-001"));
    let pool = Arc::new(
        PoolRouter::new(PoolStrategy::RoundRobin, true).with_auth(AuthMode::PerTunnel, None),
    );
    pool.add_tunnel("wgcf-001", Arc::clone(&t1) as Arc<dyn ProxyTunnelTarget>);
    let router: Arc<dyn TunnelRouter> = pool;

    let (mut client, server) = tokio::io::duplex(4096);
    let server_task = tokio::spawn(async move { handle_http(server, router).await });

    // "nonexistent:" in base64; no password is set, so auth succeeds and
    // selection fails at CONNECT.
    let req = "CONNECT 192.0.2.1:80 HTTP/1.1\r\nHost: 192.0.2.1:80\r\nProxy-Authorization: Basic bm9uZXhpc3RlbnQ6\r\n\r\n";
    client.write_all(req.as_bytes()).await.unwrap();

    let mut resp = Vec::new();
    client.read_to_end(&mut resp).await.unwrap();
    let resp_str = String::from_utf8_lossy(&resp);
    assert!(
        resp_str.starts_with("HTTP/1.1 404 Not Found"),
        "expected 404 Not Found for unknown tunnel, got: {resp_str:?}"
    );
    let _ = server_task.await;
}

#[tokio::test]
async fn test_http_connect_empty_pool_returns_503() {
    // Same distinction as the SOCKS5 test above, over HTTP CONNECT: a
    // valid selector whose pool is empty answers 503 (no healthy tunnel
    // right now), while a bad name answers 404 and a dead tunnel 502.
    let pool = Arc::new(
        PoolRouter::new(PoolStrategy::RoundRobin, true).with_auth(AuthMode::PerTunnel, None),
    );
    let router: Arc<dyn TunnelRouter> = pool;

    let (mut client, server) = tokio::io::duplex(4096);
    let server_task = tokio::spawn(async move { handle_http(server, router).await });

    // "round-robin:" in base64; no password is set, so auth succeeds and
    // selection fails at CONNECT.
    let req = "CONNECT 192.0.2.1:80 HTTP/1.1\r\nHost: 192.0.2.1:80\r\nProxy-Authorization: Basic cm91bmQtcm9iaW46\r\n\r\n";
    client.write_all(req.as_bytes()).await.unwrap();

    let mut resp = Vec::new();
    client.read_to_end(&mut resp).await.unwrap();
    let resp_str = String::from_utf8_lossy(&resp);
    assert!(
        resp_str.starts_with("HTTP/1.1 503 Service Unavailable"),
        "expected 503 Service Unavailable for empty pool, got: {resp_str:?}"
    );
    let _ = server_task.await;
}

/// In-memory `tracing` writer for log-capture tests: events written
/// here can be asserted on as plain text (shared by the HTTP and
/// `connect_via_router` log tests below).
#[derive(Clone)]
struct VecMakeWriter(Arc<Mutex<Vec<u8>>>);

struct VecWriter(Arc<Mutex<Vec<u8>>>);

impl io::Write for VecWriter {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for VecMakeWriter {
    type Writer = VecWriter;

    fn make_writer(&'a self) -> Self::Writer {
        VecWriter(Arc::clone(&self.0))
    }
}

#[tokio::test]
async fn test_http_connect_empty_pool_logs_selection_failure() {
    // Docs §4 promises the `no healthy tunnels available in pool`
    // line for the pool-empty case; the HTTP path used to answer 503
    // without leaving any daemon-side trace of it. This test router
    // holds zero tunnels, so its selection error reads "no tunnels
    // registered in pool" instead of the production router's
    // "no healthy tunnels available in pool" — what matters here is
    // that the HTTP path logs the selection failure at all, with the
    // same WARN format as the SOCKS5 path.
    let captured = Arc::new(Mutex::new(Vec::new()));
    let subscriber = tracing_subscriber::fmt()
        .with_max_level(tracing::Level::WARN)
        .with_writer(VecMakeWriter(Arc::clone(&captured)))
        .finish();
    let _guard = tracing::subscriber::set_default(subscriber);

    let pool = Arc::new(
        PoolRouter::new(PoolStrategy::RoundRobin, true).with_auth(AuthMode::PerTunnel, None),
    );
    let router: Arc<dyn TunnelRouter> = pool;

    let (mut client, server) = tokio::io::duplex(4096);
    let server_task = tokio::spawn(async move { handle_http(server, router).await });

    let req = "CONNECT 192.0.2.1:80 HTTP/1.1\r\nHost: 192.0.2.1:80\r\nProxy-Authorization: Basic cm91bmQtcm9iaW46\r\n\r\n";
    client.write_all(req.as_bytes()).await.unwrap();

    let mut resp = Vec::new();
    client.read_to_end(&mut resp).await.unwrap();
    let resp_str = String::from_utf8_lossy(&resp);
    assert!(
        resp_str.starts_with("HTTP/1.1 503 Service Unavailable"),
        "expected 503 Service Unavailable for empty pool, got: {resp_str:?}"
    );
    let _ = server_task.await;

    let rendered = String::from_utf8(captured.lock().unwrap().clone()).unwrap();
    assert!(
        rendered.contains("Failed to select tunnel for ByKeyword(RoundRobin):"),
        "expected the selection-failure WARN in the daemon log, got: {rendered:?}"
    );
    assert!(
        rendered.contains("no tunnels registered in pool"),
        "expected the selection error in the daemon log, got: {rendered:?}"
    );
}

#[tokio::test]
async fn test_forbidden_destination_logs_info_on_socks5_and_http() {
    // A forbidden destination is a policy rejection, not a proxy
    // failure — but it is a failed connection from the client's view,
    // and before this fix neither path left any daemon-side trace of
    // it (the listener only warns on timeouts). Both paths must now
    // emit one INFO line naming the target.
    let captured = Arc::new(Mutex::new(Vec::new()));
    let subscriber = tracing_subscriber::fmt()
        .with_max_level(tracing::Level::INFO)
        .with_writer(VecMakeWriter(Arc::clone(&captured)))
        .finish();
    let _guard = tracing::subscriber::set_default(subscriber);

    let mock = Arc::new(
        MockTunnelTarget::new("forbidden-1")
            .with_dns("forbidden.example.com", "127.0.0.1".parse().unwrap()),
    );
    let router: Arc<dyn TunnelRouter> =
        Arc::new(SingleTunnelRouter::new("forbidden-1", mock, None));

    // SOCKS5 CONNECT to a domain that resolves to loopback.
    run_socks5_connect_expect_rep(
        Arc::clone(&router),
        ATYP_DOMAIN,
        b"forbidden.example.com",
        80,
        Some(REP_CONN_NOT_ALLOWED),
    )
    .await;

    // HTTP CONNECT to the same domain.
    let (mut client, server) = tokio::io::duplex(4096);
    let r_connect = Arc::clone(&router);
    let server_task = tokio::spawn(async move { handle_http(server, r_connect).await });
    client
        .write_all(
            b"CONNECT forbidden.example.com:443 HTTP/1.1\r\nHost: forbidden.example.com:443\r\n\r\n",
        )
        .await
        .unwrap();
    let (status, _, _, _) = read_http_headers_helper(&mut client).await.unwrap();
    assert_eq!(status, 403);
    let _ = server_task.await;

    let rendered = String::from_utf8(captured.lock().unwrap().clone()).unwrap();
    assert!(
        rendered.contains("SOCKS5 CONNECT rejected: forbidden destination:"),
        "expected the SOCKS5 forbidden-destination INFO in the daemon log, got: {rendered:?}"
    );
    assert!(
        rendered.contains("HTTP CONNECT rejected: forbidden destination:"),
        "expected the HTTP forbidden-destination INFO in the daemon log, got: {rendered:?}"
    );
    assert!(
        rendered.contains("forbidden.example.com:80")
            && rendered.contains("forbidden.example.com:443"),
        "expected both targets in the daemon log, got: {rendered:?}"
    );
}

#[tokio::test]
async fn test_send_socks5_reply_helper() {
    let (mut client, mut server) = tokio::io::duplex(128);
    let test_addr: SocketAddr = "192.168.1.10:8080".parse().unwrap();
    send_socks5_reply(&mut server, REP_SUCCESS, test_addr)
        .await
        .unwrap();

    let mut buf = [0u8; 10];
    client.read_exact(&mut buf).await.unwrap();
    assert_eq!(buf[0], SOCKS5_VERSION);
    assert_eq!(buf[1], REP_SUCCESS);
    assert_eq!(buf[2], 0x00);
    assert_eq!(buf[3], ATYP_IPV4);
    assert_eq!(&buf[4..8], &[192, 168, 1, 10]);
    assert_eq!(&buf[8..10], &8080u16.to_be_bytes());
}

// -----------------------------------------------------------------------------
// SOCKS5 Tests: UDP Header Encode/Decode & UDP ASSOCIATE Relay
// -----------------------------------------------------------------------------

#[test]
fn test_socks5_udp_header_encode_decode() {
    // 1. IPv4 Target
    let v4_target = TargetAddr::Ip(SocketAddr::V4(SocketAddrV4::new(
        Ipv4Addr::new(1, 1, 1, 1),
        53,
    )));
    let payload = b"dns_query_data";
    let packet = build_socks5_udp_packet(&v4_target, payload);

    let (parsed_target, parsed_payload) =
        parse_socks5_udp_packet(&packet).expect("failed to parse v4");
    assert_eq!(parsed_target, v4_target);
    assert_eq!(parsed_payload, payload);

    // 2. IPv6 Target
    let v6_target = TargetAddr::Ip(SocketAddr::V6(SocketAddrV6::new(
        Ipv6Addr::new(0x2606, 0x4700, 0x4700, 0, 0, 0, 0, 0x1111),
        53,
        0,
        0,
    )));
    let packet_v6 = build_socks5_udp_packet(&v6_target, payload);
    let (parsed_v6, parsed_payload_v6) =
        parse_socks5_udp_packet(&packet_v6).expect("failed to parse v6");
    assert_eq!(parsed_v6, v6_target);
    assert_eq!(parsed_payload_v6, payload);

    // 3. Domain Target
    let domain_target = TargetAddr::Domain("dns.google.com".to_string(), 853);
    let packet_dom = build_socks5_udp_packet(&domain_target, payload);
    let (parsed_dom, parsed_payload_dom) =
        parse_socks5_udp_packet(&packet_dom).expect("failed to parse domain");
    assert_eq!(parsed_dom, domain_target);
    assert_eq!(parsed_payload_dom, payload);

    // 4. Fragmented packet (FRAG != 0) should be dropped
    let mut frag_pkt = packet.clone();
    frag_pkt[2] = 0x01; // FRAG = 1
    assert!(parse_socks5_udp_packet(&frag_pkt).is_none());

    // 5. Truncated packet
    assert!(parse_socks5_udp_packet(&packet[..3]).is_none());
}

#[test]
fn test_udp_payload_pool_reuses_buffer() {
    let mut pool = UdpPayloadPool::default();
    let first = pool.take(b"hello");
    assert_eq!(&first[..], b"hello");
    let first_ptr = first.as_ptr();
    pool.release(first);

    // A same-size payload reuses the exact same allocation: no fresh heap
    // allocation for the second datagram.
    let second = pool.take(b"world");
    assert_eq!(second.as_ptr(), first_ptr);
    assert_eq!(&second[..], b"world");
}

#[test]
fn test_udp_payload_pool_grows_for_larger_payload() {
    let mut pool = UdpPayloadPool::default();
    let small = pool.take(b"hi");
    pool.release(small);

    // A larger payload after a small one grows the pooled buffer instead of
    // truncating.
    let large = pool.take(b"hello_socks5_udp_relay!");
    assert_eq!(&large[..], b"hello_socks5_udp_relay!");
}

#[tokio::test]
async fn test_socks5_udp_associate_relay() {
    let echo_udp_addr = spawn_echo_udp_server().await;

    // The destination guard forbids loopback targets, so packets name
    // the TEST-NET-1 stand-in and the mock UDP socket redirects the
    // send to the loopback echo server (see `TEST_ECHO_IP`).
    let target = Arc::new(MockTunnelTarget::new("udp-tunnel").with_udp_redirect(echo_udp_addr));
    let router: Arc<dyn TunnelRouter> =
        Arc::new(SingleTunnelRouter::new("udp-tunnel", target, None));

    // Bind real TCP listener for SOCKS5 server to exercise real UDP relay sockets
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let s5_addr = listener.local_addr().unwrap();

    let r = Arc::clone(&router);
    tokio::spawn(async move {
        if let Ok((stream, _)) = listener.accept().await {
            let _ = handle_socks5(stream, r).await;
        }
    });

    // Client connects via TCP control connection
    let mut tcp_client = TcpStream::connect(s5_addr).await.unwrap();

    // 1. Greeting
    tcp_client
        .write_all(&[SOCKS5_VERSION, 1, METHOD_NO_AUTH])
        .await
        .unwrap();
    let mut g_resp = [0u8; 2];
    tcp_client.read_exact(&mut g_resp).await.unwrap();
    assert_eq!(g_resp[1], METHOD_NO_AUTH);

    // 2. CMD_UDP_ASSOCIATE
    let cmd = [
        SOCKS5_VERSION,
        CMD_UDP_ASSOCIATE,
        0x00,
        ATYP_IPV4,
        0,
        0,
        0,
        0,
        0,
        0,
    ];
    tcp_client.write_all(&cmd).await.unwrap();

    let mut reply_hdr = [0u8; 4];
    tcp_client.read_exact(&mut reply_hdr).await.unwrap();
    assert_eq!(reply_hdr[1], REP_SUCCESS);

    let relay_addr = match reply_hdr[3] {
        ATYP_IPV4 => {
            let mut buf = [0u8; 6];
            tcp_client.read_exact(&mut buf).await.unwrap();
            let ip = Ipv4Addr::new(buf[0], buf[1], buf[2], buf[3]);
            let port = u16::from_be_bytes([buf[4], buf[5]]);
            let ip = if ip.is_unspecified() {
                s5_addr.ip()
            } else {
                IpAddr::V4(ip)
            };
            SocketAddr::new(ip, port)
        }
        _ => panic!("Expected IPv4 relay address"),
    };

    // 3. Client binds UDP socket and sends datagram to relay address targeting echo server
    let client_udp = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let packet_dest = TargetAddr::Ip(test_echo_target(echo_udp_addr));
    let payload = b"hello_socks5_udp_relay!";
    let encap_pkt = build_socks5_udp_packet(&packet_dest, payload);

    client_udp.send_to(&encap_pkt, relay_addr).await.unwrap();

    // 4. Client receives echoed datagram from relay socket
    let mut resp_buf = vec![0u8; 2048];
    let (n, from_relay) =
        tokio::time::timeout(Duration::from_secs(2), client_udp.recv_from(&mut resp_buf))
            .await
            .expect("Timeout waiting for relayed UDP")
            .unwrap();

    assert_eq!(from_relay, relay_addr);
    let (from_target, echoed_payload) =
        parse_socks5_udp_packet(&resp_buf[..n]).expect("Failed to parse echoed packet");
    // The relay stamps the expected (requested) destination, not an
    // arbitrary tunnel sender.
    assert_eq!(from_target, packet_dest);
    assert_eq!(echoed_payload, payload);
}

#[tokio::test]
async fn test_socks5_udp_associate_relay_domain() {
    let echo_udp_addr = spawn_echo_udp_server().await;
    let echo_port = echo_udp_addr.port();

    // Mock tunnel resolves the domain to the TEST-NET-1 stand-in (the
    // destination guard forbids loopback), and redirects UDP sends to
    // the loopback echo server (see `TEST_ECHO_IP`).
    let target = Arc::new(
        MockTunnelTarget::new("udp-tunnel")
            .with_dns("echo.tunnel.local", TEST_ECHO_IP)
            .with_udp_redirect(echo_udp_addr),
    );
    let router: Arc<dyn TunnelRouter> =
        Arc::new(SingleTunnelRouter::new("udp-tunnel", target, None));

    // Bind real TCP listener for SOCKS5 server to exercise real UDP relay sockets
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let s5_addr = listener.local_addr().unwrap();

    let r = Arc::clone(&router);
    tokio::spawn(async move {
        if let Ok((stream, _)) = listener.accept().await {
            let _ = handle_socks5(stream, r).await;
        }
    });

    // Client connects via TCP control connection
    let mut tcp_client = TcpStream::connect(s5_addr).await.unwrap();

    // 1. Greeting
    tcp_client
        .write_all(&[SOCKS5_VERSION, 1, METHOD_NO_AUTH])
        .await
        .unwrap();
    let mut g_resp = [0u8; 2];
    tcp_client.read_exact(&mut g_resp).await.unwrap();
    assert_eq!(g_resp[1], METHOD_NO_AUTH);

    // 2. CMD_UDP_ASSOCIATE
    let cmd = [
        SOCKS5_VERSION,
        CMD_UDP_ASSOCIATE,
        0x00,
        ATYP_IPV4,
        0,
        0,
        0,
        0,
        0,
        0,
    ];
    tcp_client.write_all(&cmd).await.unwrap();

    let mut reply_hdr = [0u8; 4];
    tcp_client.read_exact(&mut reply_hdr).await.unwrap();
    assert_eq!(reply_hdr[1], REP_SUCCESS);

    let relay_addr = match reply_hdr[3] {
        ATYP_IPV4 => {
            let mut buf = [0u8; 6];
            tcp_client.read_exact(&mut buf).await.unwrap();
            let ip = Ipv4Addr::new(buf[0], buf[1], buf[2], buf[3]);
            let port = u16::from_be_bytes([buf[4], buf[5]]);
            let ip = if ip.is_unspecified() {
                s5_addr.ip()
            } else {
                IpAddr::V4(ip)
            };
            SocketAddr::new(ip, port)
        }
        _ => panic!("Expected IPv4 relay address"),
    };

    // 3. Client binds UDP socket and sends two datagrams targeting the echo
    // server by domain name; both must come back echoed, proving the pooled
    // payload survives DNS resolution and dispatch.
    let client_udp = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let target_dest = TargetAddr::Domain("echo.tunnel.local".to_string(), echo_port);
    let payloads = [
        b"first_domain_datagram!".as_slice(),
        b"second_domain_datagram".as_slice(),
    ];
    for payload in payloads {
        let encap_pkt = build_socks5_udp_packet(&target_dest, payload);
        client_udp.send_to(&encap_pkt, relay_addr).await.unwrap();

        let mut resp_buf = vec![0u8; 2048];
        let (n, from_relay) =
            tokio::time::timeout(Duration::from_secs(2), client_udp.recv_from(&mut resp_buf))
                .await
                .expect("Timeout waiting for relayed UDP")
                .unwrap();

        assert_eq!(from_relay, relay_addr);
        let (from_target, echoed_payload) =
            parse_socks5_udp_packet(&resp_buf[..n]).expect("Failed to parse echoed packet");
        // The domain resolved to the TEST-NET-1 stand-in, so the relay
        // stamps that requested destination.
        assert_eq!(from_target, TargetAddr::Ip(test_echo_target(echo_udp_addr)));
        assert_eq!(echoed_payload, payload);
    }
}

// -----------------------------------------------------------------------------
// HTTP Proxy Tests: CONNECT & Forward Proxy
// -----------------------------------------------------------------------------

#[test]
fn test_parse_authority() {
    assert_eq!(
        parse_authority("example.com:443"),
        Some(("example.com".to_string(), 443))
    );
    assert_eq!(
        parse_authority("1.2.3.4:8080"),
        Some(("1.2.3.4".to_string(), 8080))
    );
    assert_eq!(
        parse_authority("[::1]:9000"),
        Some(("::1".to_string(), 9000))
    );
    assert_eq!(parse_authority("invalid"), None);
    assert_eq!(parse_authority("example.com:notaport"), None);
}

#[test]
fn test_extract_basic_auth() {
    let mut headers = HashMap::new();
    headers.insert(
        "proxy-authorization".to_string(),
        format_basic_auth("user1", "pass1"),
    );
    assert_eq!(
        extract_basic_auth(&headers),
        Some(("user1".to_string(), "pass1".to_string()))
    );

    let mut empty_headers = HashMap::new();
    assert_eq!(extract_basic_auth(&empty_headers), None);

    empty_headers.insert(
        "proxy-authorization".to_string(),
        "Bearer token123".to_string(),
    );
    assert_eq!(extract_basic_auth(&empty_headers), None);
}

#[tokio::test]
async fn test_read_http_request_headers_unit() {
    let raw = b"GET http://example.com/index.html HTTP/1.1\r\nHost: example.com\r\nUser-Agent: test\r\n\r\nbody";
    let (mut client, mut server) = tokio::io::duplex(256);
    tokio::spawn(async move {
        server.write_all(raw).await.unwrap();
    });

    let (method, uri, version, headers, leftover) = read_http_request_headers_buffered(&mut client)
        .await
        .unwrap();
    assert_eq!(method, "GET");
    assert_eq!(uri, "http://example.com/index.html");
    assert_eq!(version, "HTTP/1.1");
    assert_eq!(headers.get("host").unwrap(), "example.com");
    assert_eq!(headers.get("user-agent").unwrap(), "test");
    assert_eq!(&leftover, b"body");
}

#[tokio::test]
async fn test_http_connect_no_auth() {
    let echo_addr = spawn_echo_tcp_server().await;
    let target_addr = test_echo_target(echo_addr);
    let target = Arc::new(MockTunnelTarget::new("http-tunnel").with_dial_redirect(echo_addr));
    let router: Arc<dyn TunnelRouter> =
        Arc::new(SingleTunnelRouter::new("http-tunnel", target, None));

    let (mut client, server) = tokio::io::duplex(2048);
    tokio::spawn(async move {
        let _ = handle_http(server, router).await;
    });

    let connect_req = format!("CONNECT {target_addr} HTTP/1.1\r\nHost: {target_addr}\r\n\r\n",);
    client.write_all(connect_req.as_bytes()).await.unwrap();

    // Read 200 Connection Established response
    let (status, reason, _, _) = read_http_headers_helper(&mut client).await.unwrap();
    assert_eq!(status, 200);
    assert!(reason.contains("Connection Established"));

    // Tunnel data transfer
    client.write_all(b"http_tunneled_bytes").await.unwrap();
    let mut buf = [0u8; 19];
    client.read_exact(&mut buf).await.unwrap();
    assert_eq!(&buf, b"http_tunneled_bytes");
}

#[tokio::test]
async fn test_http_basic_auth_challenge_and_success() {
    let echo_addr = spawn_echo_tcp_server().await;
    let target_addr = test_echo_target(echo_addr);
    let target = Arc::new(MockTunnelTarget::new("auth-http").with_dial_redirect(echo_addr));
    let router: Arc<dyn TunnelRouter> = Arc::new(SingleTunnelRouter::new(
        "auth-http",
        target,
        Some(("proxyuser".to_string(), "proxypass123".to_string())),
    ));

    // Case 1: Unauthenticated -> 407 Proxy Authentication Required
    {
        let (mut client, server) = tokio::io::duplex(1024);
        let r = Arc::clone(&router);
        tokio::spawn(async move {
            let _ = handle_http(server, r).await;
        });

        let req = format!("CONNECT {target_addr} HTTP/1.1\r\nHost: {target_addr}\r\n\r\n",);
        client.write_all(req.as_bytes()).await.unwrap();

        let (status, _, headers, _) = read_http_headers_helper(&mut client).await.unwrap();
        assert_eq!(status, 407);
        assert!(headers.contains_key("proxy-authenticate"))
    };

    // Case 2: Wrong credentials -> 407
    {
        let (mut client, server) = tokio::io::duplex(1024);
        let r = Arc::clone(&router);
        tokio::spawn(async move {
            let _ = handle_http(server, r).await;
        });

        let auth_hdr = format_basic_auth("proxyuser", "wrongpassword");
        let req = format!(
            "CONNECT {target_addr} HTTP/1.1\r\nHost: {target_addr}\r\nProxy-Authorization: {auth_hdr}\r\n\r\n",
        );
        client.write_all(req.as_bytes()).await.unwrap();

        let (status, _, _, _) = read_http_headers_helper(&mut client).await.unwrap();
        assert_eq!(status, 407)
    };

    // Case 3: Valid credentials -> 200 OK
    {
        let (mut client, server) = tokio::io::duplex(2048);
        let r = Arc::clone(&router);
        tokio::spawn(async move {
            let _ = handle_http(server, r).await;
        });

        let auth_hdr = format_basic_auth("proxyuser", "proxypass123");
        let req = format!(
            "CONNECT {target_addr} HTTP/1.1\r\nHost: {target_addr}\r\nProxy-Authorization: {auth_hdr}\r\n\r\n",
        );
        client.write_all(req.as_bytes()).await.unwrap();

        let (status, _, _, _) = read_http_headers_helper(&mut client).await.unwrap();
        assert_eq!(status, 200);

        client
            .write_all(b"authenticated_http_tunnel")
            .await
            .unwrap();
        let mut buf = [0u8; 25];
        client.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"authenticated_http_tunnel");
    }
}

#[tokio::test]
async fn test_http_forward_proxy() {
    let mock_server_addr = spawn_mock_http_server("forward_proxy_payload_ok").await;
    let target_addr = test_echo_target(mock_server_addr);
    let target = Arc::new(MockTunnelTarget::new("fwd-tunnel").with_dial_redirect(mock_server_addr));
    let router: Arc<dyn TunnelRouter> =
        Arc::new(SingleTunnelRouter::new("fwd-tunnel", target, None));

    let (mut client, server) = tokio::io::duplex(4096);
    tokio::spawn(async move {
        let _ = handle_http(server, router).await;
    });

    let req = format!(
        "GET http://{target_addr}/test/api HTTP/1.1\r\nHost: {target_addr}\r\nUser-Agent: test\r\n\r\n",
    );
    client.write_all(req.as_bytes()).await.unwrap();

    let (status, _, _, body) = read_http_headers_helper(&mut client).await.unwrap();
    assert_eq!(status, 200);
    assert_eq!(String::from_utf8_lossy(&body), "forward_proxy_payload_ok");
}

#[tokio::test]
async fn test_http_forward_proxy_ipv6_bracket() {
    let mock_server_addr = spawn_mock_http_server("ipv6_bracket_ok").await;
    // mock_server_addr is IPv4 127.0.0.1:port. Now test IPv6 mock server if IPv6 available
    if let Some(v6_addr) = spawn_echo_tcp_server_ipv6().await {
        let Some((host, port)) = parse_authority(&format!("[::1]:{}", v6_addr.port())) else {
            panic!("failed to parse [::1]:port");
        };
        assert_eq!(host, "::1");
        assert_eq!(port, v6_addr.port());
    }

    let target_addr = test_echo_target(mock_server_addr);
    let target =
        Arc::new(MockTunnelTarget::new("fwd-tunnel-v6").with_dial_redirect(mock_server_addr));
    let router: Arc<dyn TunnelRouter> =
        Arc::new(SingleTunnelRouter::new("fwd-tunnel-v6", target, None));
    let (mut client, server) = tokio::io::duplex(4096);
    tokio::spawn(async move {
        let _ = handle_http(server, router).await;
    });

    let req = format!(
        "GET http://{target_addr}/test/api HTTP/1.1\r\nHost: {target_addr}\r\nConnection: keep-alive\r\n\r\n",
    );
    client.write_all(req.as_bytes()).await.unwrap();

    let (status, _, _, body) = read_http_headers_helper(&mut client).await.unwrap();
    assert_eq!(status, 200);
    assert_eq!(String::from_utf8_lossy(&body), "ipv6_bracket_ok");
}

#[tokio::test]
async fn test_http_bad_request_handling() {
    let target = Arc::new(DirectTunnelTarget);
    let router: Arc<dyn TunnelRouter> = Arc::new(SingleTunnelRouter::new("test", target, None));

    let (mut client, server) = tokio::io::duplex(1024);
    tokio::spawn(async move {
        let _ = handle_http(server, router).await;
    });

    client
        .write_all(b"MALFORMED_REQUEST_LINE\r\n\r\n")
        .await
        .unwrap();
    let (status, _, _, _) = read_http_headers_helper(&mut client).await.unwrap();
    assert_eq!(status, 400);
}

// -----------------------------------------------------------------------------
// Router Tests: Username Selectors & Multi-Tunnel Pool
// -----------------------------------------------------------------------------

#[test]
fn test_tunnel_selector_parsing() {
    assert_eq!(TunnelSelector::parse(""), TunnelSelector::DefaultPool);
    assert_eq!(
        TunnelSelector::parse("default"),
        TunnelSelector::DefaultPool
    );
    assert_eq!(
        TunnelSelector::parse("auto"),
        TunnelSelector::ByKeyword(PoolKeyword::Auto)
    );
    assert_eq!(
        TunnelSelector::parse("random"),
        TunnelSelector::ByKeyword(PoolKeyword::Random)
    );
    assert_eq!(
        TunnelSelector::parse("round-robin"),
        TunnelSelector::ByKeyword(PoolKeyword::RoundRobin)
    );
    assert_eq!(
        TunnelSelector::parse("roundrobin"),
        TunnelSelector::ByKeyword(PoolKeyword::RoundRobin)
    );
    assert_eq!(
        TunnelSelector::parse("least-conn"),
        TunnelSelector::ByKeyword(PoolKeyword::LeastConn)
    );
    assert_eq!(
        TunnelSelector::parse("tag:streaming"),
        TunnelSelector::ByTag("streaming".to_string())
    );
    assert_eq!(
        TunnelSelector::parse("wgcf-042"),
        TunnelSelector::ById("wgcf-042".to_string())
    );
}

#[tokio::test]
async fn test_pool_router_routing_and_round_robin() {
    let t1 = Arc::new(MockTunnelTarget::new("wgcf-001"));
    let t2 = Arc::new(MockTunnelTarget::new("wgcf-002"));

    let pool = Arc::new(
        PoolRouter::new(PoolStrategy::RoundRobin, true)
            .with_auth(AuthMode::Global, Some("globalpass".to_string())),
    );
    pool.add_tunnel("wgcf-001", Arc::clone(&t1) as Arc<dyn ProxyTunnelTarget>);
    pool.add_tunnel("wgcf-002", Arc::clone(&t2) as Arc<dyn ProxyTunnelTarget>);

    // 1. Authenticate with username specifying explicit tunnel ID
    let sel1 = pool.authenticate(Some(("wgcf-001", "globalpass"))).unwrap();
    assert_eq!(sel1, TunnelSelector::ById("wgcf-001".to_string()));
    let target1 = pool.select_tunnel(&sel1, None).await.unwrap();
    assert!(Arc::ptr_eq(
        &target1,
        &(Arc::clone(&t1) as Arc<dyn ProxyTunnelTarget>)
    ));

    // 2. Authenticate with "auto" keyword
    let sel_auto = pool.authenticate(Some(("auto", "globalpass"))).unwrap();
    assert_eq!(sel_auto, TunnelSelector::ByKeyword(PoolKeyword::Auto));

    // 3. Test round-robin cycling
    let t_first = pool
        .select_tunnel(&TunnelSelector::DefaultPool, None)
        .await
        .unwrap();
    let t_second = pool
        .select_tunnel(&TunnelSelector::DefaultPool, None)
        .await
        .unwrap();
    let t_third = pool
        .select_tunnel(&TunnelSelector::DefaultPool, None)
        .await
        .unwrap();

    assert!(Arc::ptr_eq(
        &t_first,
        &(Arc::clone(&t1) as Arc<dyn ProxyTunnelTarget>)
    ));
    assert!(Arc::ptr_eq(
        &t_second,
        &(Arc::clone(&t2) as Arc<dyn ProxyTunnelTarget>)
    ));
    assert!(Arc::ptr_eq(
        &t_third,
        &(Arc::clone(&t1) as Arc<dyn ProxyTunnelTarget>)
    ));
}

#[tokio::test]
async fn test_pool_prefers_live_tunnel_over_dormant() {
    let dormant = Arc::new(MockTunnelTarget::new("wgcf-001"));
    let live = Arc::new(MockTunnelTarget::new("wgcf-002").with_live());

    let pool = Arc::new(PoolRouter::new(PoolStrategy::RoundRobin, true));
    pool.add_tunnel(
        "wgcf-001",
        Arc::clone(&dormant) as Arc<dyn ProxyTunnelTarget>,
    );
    pool.add_tunnel("wgcf-002", Arc::clone(&live) as Arc<dyn ProxyTunnelTarget>);

    // Every DefaultPool pick lands on the live tunnel, even though the
    // dormant one is first in the pool.
    for _ in 0..6 {
        let picked = pool
            .select_tunnel(&TunnelSelector::DefaultPool, None)
            .await
            .unwrap();
        assert!(Arc::ptr_eq(
            &picked,
            &(Arc::clone(&live) as Arc<dyn ProxyTunnelTarget>)
        ));
    }
    // Same for the ByKeyword auto path.
    for _ in 0..6 {
        let picked = pool
            .select_tunnel(&TunnelSelector::ByKeyword(PoolKeyword::Auto), None)
            .await
            .unwrap();
        assert!(Arc::ptr_eq(
            &picked,
            &(Arc::clone(&live) as Arc<dyn ProxyTunnelTarget>)
        ));
    }
}

#[tokio::test]
async fn test_pool_falls_back_to_dormant_when_nothing_live() {
    let t1 = Arc::new(MockTunnelTarget::new("wgcf-001"));
    let t2 = Arc::new(MockTunnelTarget::new("wgcf-002"));

    let pool = Arc::new(PoolRouter::new(PoolStrategy::RoundRobin, true));
    pool.add_tunnel("wgcf-001", Arc::clone(&t1) as Arc<dyn ProxyTunnelTarget>);
    pool.add_tunnel("wgcf-002", Arc::clone(&t2) as Arc<dyn ProxyTunnelTarget>);

    // No live tunnel: round-robin over the full pool, unchanged.
    let first = pool
        .select_tunnel(&TunnelSelector::DefaultPool, None)
        .await
        .unwrap();
    let second = pool
        .select_tunnel(&TunnelSelector::DefaultPool, None)
        .await
        .unwrap();
    assert!(Arc::ptr_eq(
        &first,
        &(Arc::clone(&t1) as Arc<dyn ProxyTunnelTarget>)
    ));
    assert!(Arc::ptr_eq(
        &second,
        &(Arc::clone(&t2) as Arc<dyn ProxyTunnelTarget>)
    ));
}

#[tokio::test]
async fn test_pool_single_tunnel_and_empty_pool_unchanged() {
    // Single live tunnel: picked.
    let live = Arc::new(MockTunnelTarget::new("only").with_live());
    let pool = Arc::new(PoolRouter::new(PoolStrategy::RoundRobin, true));
    pool.add_tunnel("only", Arc::clone(&live) as Arc<dyn ProxyTunnelTarget>);
    let picked = pool
        .select_tunnel(&TunnelSelector::DefaultPool, None)
        .await
        .unwrap();
    assert!(Arc::ptr_eq(
        &picked,
        &(Arc::clone(&live) as Arc<dyn ProxyTunnelTarget>)
    ));

    // Single dormant tunnel: still picked (fallback), never an error.
    let dormant = Arc::new(MockTunnelTarget::new("only"));
    let pool2 = Arc::new(PoolRouter::new(PoolStrategy::RoundRobin, true));
    pool2.add_tunnel("only", Arc::clone(&dormant) as Arc<dyn ProxyTunnelTarget>);
    let picked2 = pool2
        .select_tunnel(&TunnelSelector::DefaultPool, None)
        .await
        .unwrap();
    assert!(Arc::ptr_eq(
        &picked2,
        &(Arc::clone(&dormant) as Arc<dyn ProxyTunnelTarget>)
    ));

    // Empty pool: unchanged error.
    let empty = PoolRouter::new(PoolStrategy::RoundRobin, true);
    assert!(matches!(
        empty.select_tunnel(&TunnelSelector::DefaultPool, None).await,
        Err(err) if err.kind() == io::ErrorKind::NotConnected
    ));
}

// -----------------------------------------------------------------------------
// Test Helpers
// -----------------------------------------------------------------------------

fn format_basic_auth(user: &str, pass: &str) -> String {
    use base64::Engine;
    let creds = format!("{}:{}", user, pass);
    let b64 = base64::prelude::BASE64_STANDARD.encode(creds.as_bytes());
    format!("Basic {}", b64)
}

async fn read_http_headers_helper<R: AsyncReadExt + Unpin>(
    reader: &mut R,
) -> io::Result<(u16, String, HashMap<String, String>, Vec<u8>)> {
    let mut header_bytes = Vec::new();
    let mut b = [0u8; 1];
    while header_bytes.len() < 16384 {
        reader.read_exact(&mut b).await?;
        header_bytes.push(b[0]);
        if header_bytes.ends_with(b"\r\n\r\n") {
            break;
        }
    }
    let header_str = String::from_utf8_lossy(&header_bytes);
    let mut lines = header_str.split("\r\n");
    let status_line = lines
        .next()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "empty status line"))?;
    let parts: Vec<&str> = status_line.split_whitespace().collect();
    let status_code: u16 = parts.get(1).and_then(|s| s.parse().ok()).unwrap_or(0);
    let reason = parts.get(2..).map(|p| p.join(" ")).unwrap_or_default();

    let mut headers = HashMap::new();
    for line in lines {
        if line.is_empty() {
            break;
        }
        if let Some((k, v)) = line.split_once(':') {
            headers.insert(k.trim().to_ascii_lowercase(), v.trim().to_string());
        }
    }

    let mut body = Vec::new();
    if let Some(len_str) = headers.get("content-length")
        && let Ok(len) = len_str.parse::<usize>()
        && len > 0
    {
        body.resize(len, 0);
        reader.read_exact(&mut body).await?;
    }

    Ok((status_code, reason, headers, body))
}

#[tokio::test]
async fn test_http_forward_rejects_mismatched_and_duplicate_host() {
    let target: Arc<dyn ProxyTunnelTarget> = Arc::new(DirectTunnelTarget);
    let router: Arc<dyn TunnelRouter> = Arc::new(SingleTunnelRouter::new("test", target, None));

    // Mismatched Host header
    let (mut client, server) = tokio::io::duplex(2048);
    let r1 = Arc::clone(&router);
    tokio::spawn(async move {
        let _ = handle_http(server, r1).await;
    });
    client
        .write_all(b"GET http://127.0.0.1:8080/test HTTP/1.1\r\nHost: evil.example\r\n\r\n")
        .await
        .unwrap();
    let (status, _, _, _) = read_http_headers_helper(&mut client).await.unwrap();
    assert_eq!(status, 400);

    // Duplicate Host header
    let (mut client2, server2) = tokio::io::duplex(2048);
    tokio::spawn(async move {
        let _ = handle_http(server2, router).await;
    });
    client2
        .write_all(b"GET http://127.0.0.1:8080/test HTTP/1.1\r\nHost: 127.0.0.1:8080\r\nHost: evil.example\r\n\r\n")
        .await
        .unwrap();
    let (status2, _, _, _) = read_http_headers_helper(&mut client2).await.unwrap();
    assert_eq!(status2, 400);
}

#[tokio::test]
async fn test_http_connect_blocks_link_local_ssrf() {
    let target: Arc<dyn ProxyTunnelTarget> = Arc::new(DirectTunnelTarget);
    let router: Arc<dyn TunnelRouter> = Arc::new(SingleTunnelRouter::new("test", target, None));

    let (mut client, server) = tokio::io::duplex(2048);
    tokio::spawn(async move {
        let _ = handle_http(server, router).await;
    });
    client
        .write_all(b"CONNECT 169.254.169.254:80 HTTP/1.1\r\nHost: 169.254.169.254:80\r\n\r\n")
        .await
        .unwrap();
    let (status, _, _, _) = read_http_headers_helper(&mut client).await.unwrap();
    assert_eq!(status, 403);
}

#[test]
fn test_socks5_udp_rejects_empty_domain_and_zero_port() {
    // Empty domain (ATYP=0x03, len=0)
    let empty_dom = [0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x50, b'h', b'i'];
    assert!(parse_socks5_udp_packet(&empty_dom).is_none());

    // Port 0
    let zero_port = [0x00, 0x00, 0x00, 0x01, 1, 1, 1, 1, 0x00, 0x00, b'h', b'i'];
    assert!(parse_socks5_udp_packet(&zero_port).is_none());
}

#[tokio::test]
async fn test_http_connect_blocks_ipv4_mapped_ipv6_ssrf() {
    let target: Arc<dyn ProxyTunnelTarget> = Arc::new(DirectTunnelTarget);
    let router: Arc<dyn TunnelRouter> = Arc::new(SingleTunnelRouter::new("test", target, None));

    let (mut client, server) = tokio::io::duplex(2048);
    tokio::spawn(async move {
        let _ = handle_http(server, router).await;
    });
    client
        .write_all(
            b"CONNECT [::ffff:169.254.169.254]:80 HTTP/1.1\r\nHost: [::ffff:169.254.169.254]:80\r\n\r\n",
        )
        .await
        .unwrap();
    let (status, _, _, _) = read_http_headers_helper(&mut client).await.unwrap();
    assert_eq!(status, 403);
}

#[test]
fn test_is_forbidden_destination_ip_parity_and_ipv6_ranges() {
    use crate::proxy::router::is_forbidden_destination_ip;

    let forbidden = [
        "0.0.0.0",
        "127.0.0.1",
        "127.0.0.2",
        "10.0.0.1",
        "172.16.0.1",
        "172.31.255.255",
        "192.168.1.1",
        "169.254.169.254",
        "224.0.0.1",
        "255.255.255.255",
        "::",
        "::1",
        "fe80::1",
        "fc00::1",
        "fd12:3456:789a::1",
        "ff02::1",
        "::ffff:127.0.0.1",
        "::ffff:10.0.0.1",
        "::ffff:192.168.0.1",
        "::ffff:169.254.169.254",
        "::ffff:0.0.0.0",
        "::ffff:255.255.255.255",
        "64:ff9b::127.0.0.1",
        "64:ff9b::10.0.0.1",
        "64:ff9b::169.254.169.254",
        "64:ff9b::0.0.0.0",
        // Run-3 #6: CGNAT, benchmarking, reserved, 0.0.0.0/8 remainder,
        // deprecated site-local, and embedded-IPv4 forms.
        "100.64.0.1",
        "100.127.255.255",
        "198.18.0.1",
        "198.19.255.255",
        "240.0.0.1",
        "248.1.2.3",
        "0.1.2.3",
        "0.255.255.255",
        "fec0::1",
        "feff::1",
        "2002:6440:1::1",
        "2002:7f00:1::1",
        "2001:0000:0102:0304:0000:0000:9bbf:fffe",
        "2001:0000:0102:0304:0000:0000:f5ff:fffe",
        "::ffff:100.64.0.1",
        "64:ff9b::100.64.0.1",
    ];
    for s in forbidden {
        let ip: IpAddr = s.parse().unwrap();
        assert!(is_forbidden_destination_ip(ip), "{s} must be forbidden");
    }

    let allowed = [
        "1.1.1.1",
        "2606:4700:4700::1111",
        "64:ff9b::1.1.1.1",
        "::ffff:1.1.1.1",
        // Just outside the run-3 #6 ranges: still public destinations.
        "100.63.255.255",
        "100.128.0.1",
        "198.20.0.1",
        "8.8.8.8",
        "2002:808:808::1",
    ];
    for s in allowed {
        let ip: IpAddr = s.parse().unwrap();
        assert!(!is_forbidden_destination_ip(ip), "{s} must be allowed");
    }
}

async fn run_socks5_connect_expect_rep(
    router: Arc<dyn TunnelRouter>,
    atyp: u8,
    addr_bytes: &[u8],
    port: u16,
    expected_rep: Option<u8>,
) {
    let (mut client, server) = tokio::io::duplex(2048);
    tokio::spawn(async move {
        let _ = handle_socks5(server, router).await;
    });

    client
        .write_all(&[SOCKS5_VERSION, 1, METHOD_NO_AUTH])
        .await
        .unwrap();
    let mut g_resp = [0u8; 2];
    client.read_exact(&mut g_resp).await.unwrap();
    assert_eq!(g_resp, [SOCKS5_VERSION, METHOD_NO_AUTH]);

    let mut cmd = vec![SOCKS5_VERSION, CMD_CONNECT, 0x00, atyp];
    if atyp == ATYP_DOMAIN {
        cmd.push(addr_bytes.len() as u8);
    }
    cmd.extend_from_slice(addr_bytes);
    cmd.extend_from_slice(&port.to_be_bytes());
    client.write_all(&cmd).await.unwrap();

    let mut reply_hdr = [0u8; 4];
    let res = client.read_exact(&mut reply_hdr).await;
    match expected_rep {
        Some(rep) => {
            res.expect("expected SOCKS5 reply");
            assert_eq!(reply_hdr[1], rep);
        }
        None => {
            assert!(res.is_err(), "expected connection to close without reply");
        }
    }
}

#[tokio::test]
async fn test_socks5_ssrf_blocks_ipv6_mapped_and_domain_literals() {
    let mock_target = Arc::new(
        MockTunnelTarget::new("ssrf-tun")
            .with_dns("meta.internal", "169.254.169.254".parse().unwrap()),
    );
    let router: Arc<dyn TunnelRouter> =
        Arc::new(SingleTunnelRouter::new("ssrf-tun", mock_target, None));

    // ATYP_IPV6 forbidden targets
    for v6_str in [
        "::ffff:169.254.169.254",
        "fd00::1",
        "fe80::1",
        "::1",
        "64:ff9b::169.254.169.254",
    ] {
        let v6: std::net::Ipv6Addr = v6_str.parse().unwrap();
        run_socks5_connect_expect_rep(
            Arc::clone(&router),
            ATYP_IPV6,
            &v6.octets(),
            80,
            Some(crate::proxy::socks5::REP_CONN_NOT_ALLOWED),
        )
        .await;
    }

    // ATYP_DOMAIN containing IP literals
    for dom in ["::ffff:169.254.169.254", "[::1]", "169.254.169.254"] {
        run_socks5_connect_expect_rep(
            Arc::clone(&router),
            ATYP_DOMAIN,
            dom.as_bytes(),
            80,
            Some(crate::proxy::socks5::REP_CONN_NOT_ALLOWED),
        )
        .await;
    }

    // ATYP_DOMAIN resolving to forbidden IP via DNS
    run_socks5_connect_expect_rep(
        Arc::clone(&router),
        ATYP_DOMAIN,
        b"meta.internal",
        80,
        Some(crate::proxy::socks5::REP_CONN_NOT_ALLOWED),
    )
    .await;

    // ATYP_DOMAIN with whitespace, control chars, or oversized label (>63)
    run_socks5_connect_expect_rep(Arc::clone(&router), ATYP_DOMAIN, b"evil .com", 80, None).await;
    run_socks5_connect_expect_rep(Arc::clone(&router), ATYP_DOMAIN, b"evil\n.com", 80, None).await;
    let long_label = format!("{}.com", "a".repeat(64));
    run_socks5_connect_expect_rep(
        Arc::clone(&router),
        ATYP_DOMAIN,
        long_label.as_bytes(),
        80,
        None,
    )
    .await;
}

#[test]
fn test_socks5_udp_parse_validates_domain_and_normalizes_ip_literals() {
    // Whitespace in domain -> rejected
    let mut pkt_ws = vec![0x00, 0x00, 0x00, ATYP_DOMAIN, 9];
    pkt_ws.extend_from_slice(b"evil .com");
    pkt_ws.extend_from_slice(&53u16.to_be_bytes());
    pkt_ws.extend_from_slice(b"hi");
    assert!(parse_socks5_udp_packet(&pkt_ws).is_none());

    // Oversized label (>63) -> rejected
    let bad_label = format!("{}.com", "a".repeat(64));
    let mut pkt_lbl = vec![0x00, 0x00, 0x00, ATYP_DOMAIN, bad_label.len() as u8];
    pkt_lbl.extend_from_slice(bad_label.as_bytes());
    pkt_lbl.extend_from_slice(&53u16.to_be_bytes());
    pkt_lbl.extend_from_slice(b"hi");
    assert!(parse_socks5_udp_packet(&pkt_lbl).is_none());

    // IP literal in ATYP_DOMAIN -> normalized to TargetAddr::Ip so SSRF filter catches it
    let lit = b"[::ffff:169.254.169.254]";
    let mut pkt_lit = vec![0x00, 0x00, 0x00, ATYP_DOMAIN, lit.len() as u8];
    pkt_lit.extend_from_slice(lit);
    pkt_lit.extend_from_slice(&80u16.to_be_bytes());
    pkt_lit.extend_from_slice(b"hi");
    let (target, payload) = parse_socks5_udp_packet(&pkt_lit).expect("ip literal parsed");
    assert_eq!(payload, b"hi");
    match target {
        TargetAddr::Ip(addr) => {
            assert!(crate::proxy::router::is_forbidden_destination_ip(addr.ip()));
        }
        TargetAddr::Domain(_, _) => panic!("expected TargetAddr::Ip for IP literal"),
    }
}

#[tokio::test]
async fn test_multi_ip_dns_fail_closed_in_socks5_and_http() {
    struct MultiIpMockTarget {
        ips: Vec<IpAddr>,
    }

    impl ProxyTunnelTarget for MultiIpMockTarget {
        fn tcp_connect<'a>(
            &'a self,
            _dst: SocketAddr,
        ) -> Pin<Box<dyn Future<Output = io::Result<DynStream>> + Send + 'a>> {
            Box::pin(async {
                panic!("tcp_connect must NOT be called when DNS includes forbidden IP")
            })
        }

        fn udp_bind<'a>(
            &'a self,
            _local_port: u16,
        ) -> Pin<Box<dyn Future<Output = io::Result<Box<dyn ProxyUdpSocket>>> + Send + 'a>>
        {
            Box::pin(async { Err(io::Error::other("unused")) })
        }

        fn resolve_in_tunnel<'a>(
            &'a self,
            _domain: &'a str,
        ) -> Pin<Box<dyn Future<Output = io::Result<IpAddr>> + Send + 'a>> {
            let first = self.ips[0];
            Box::pin(async move { Ok(first) })
        }

        fn resolve_all_in_tunnel<'a>(
            &'a self,
            _domain: &'a str,
        ) -> Pin<Box<dyn Future<Output = io::Result<Vec<IpAddr>>> + Send + 'a>> {
            let ips = self.ips.clone();
            Box::pin(async move { Ok(ips) })
        }
    }

    let mixed_target: Arc<dyn ProxyTunnelTarget> = Arc::new(MultiIpMockTarget {
        ips: vec![
            "1.1.1.1".parse().unwrap(),
            "::ffff:169.254.169.254".parse().unwrap(),
        ],
    });
    let router: Arc<dyn TunnelRouter> =
        Arc::new(SingleTunnelRouter::new("mixed-dns", mixed_target, None));

    // 1. SOCKS5 CONNECT must reject fail-closed with REP_CONN_NOT_ALLOWED
    run_socks5_connect_expect_rep(
        Arc::clone(&router),
        ATYP_DOMAIN,
        b"mixed.example.com.",
        80,
        Some(crate::proxy::socks5::REP_CONN_NOT_ALLOWED),
    )
    .await;

    // 2. HTTP CONNECT must reject fail-closed with 403 Forbidden
    let (mut client, server) = tokio::io::duplex(2048);
    let r_connect = Arc::clone(&router);
    tokio::spawn(async move {
        let _ = handle_http(server, r_connect).await;
    });
    client
        .write_all(
            b"CONNECT mixed.example.com.:443 HTTP/1.1\r\nHost: mixed.example.com.:443\r\n\r\n",
        )
        .await
        .unwrap();
    let (status, _, _, _) = read_http_headers_helper(&mut client).await.unwrap();
    assert_eq!(status, 403);

    // 3. HTTP forward proxy must reject fail-closed with 403 Forbidden
    let (mut client2, server2) = tokio::io::duplex(2048);
    tokio::spawn(async move {
        let _ = handle_http(server2, router).await;
    });
    client2
        .write_all(b"GET http://mixed.example.com./ HTTP/1.1\r\nHost: mixed.example.com.\r\n\r\n")
        .await
        .unwrap();
    let (status2, _, _, _) = read_http_headers_helper(&mut client2).await.unwrap();
    assert_eq!(status2, 403);
}

#[test]
fn test_fqdn_trailing_dot_parity_between_router_and_dns() {
    use crate::netstack::dns::{QueryType, build_query};
    use crate::proxy::router::is_valid_target_domain;

    assert!(is_valid_target_domain("example.com."));
    assert!(build_query("example.com.", QueryType::A, 1).is_ok());

    assert!(!is_valid_target_domain("example.com.."));
    assert!(build_query("example.com..", QueryType::A, 1).is_err());

    assert!(!is_valid_target_domain(" example.com "));
    assert!(build_query(" example.com ", QueryType::A, 1).is_err());
}

struct FallbackMockTarget {
    dns_calls: AtomicUsize,
    dialed_addrs: parking_lot::Mutex<Vec<SocketAddr>>,
    ips: Vec<IpAddr>,
    /// When set, dials of any IP other than `ips[0]` go here instead
    /// (see [`TEST_ECHO_IP`]).
    dial_redirect: Option<SocketAddr>,
}

impl FallbackMockTarget {
    fn new(ips: Vec<IpAddr>) -> Self {
        Self {
            dns_calls: AtomicUsize::new(0),
            dialed_addrs: parking_lot::Mutex::new(Vec::new()),
            ips,
            dial_redirect: None,
        }
    }

    fn with_dial_redirect(self, addr: SocketAddr) -> Self {
        Self {
            dial_redirect: Some(addr),
            ..self
        }
    }
}

impl ProxyTunnelTarget for FallbackMockTarget {
    fn tcp_connect<'a>(
        &'a self,
        dst: SocketAddr,
    ) -> Pin<Box<dyn Future<Output = io::Result<DynStream>> + Send + 'a>> {
        self.dialed_addrs.lock().push(dst);
        let first_ip = self.ips[0];
        let dial_redirect = self.dial_redirect;
        Box::pin(async move {
            if dst.ip() == first_ip {
                return Err(io::Error::new(
                    io::ErrorKind::ConnectionRefused,
                    "first IP unreachable",
                ));
            }
            let stream = TcpStream::connect(dial_redirect.unwrap_or(dst)).await?;
            Ok(Box::new(stream) as DynStream)
        })
    }

    fn udp_bind<'a>(
        &'a self,
        _local_port: u16,
    ) -> Pin<Box<dyn Future<Output = io::Result<Box<dyn ProxyUdpSocket>>> + Send + 'a>> {
        Box::pin(async { Err(io::Error::other("unused")) })
    }

    fn resolve_in_tunnel<'a>(
        &'a self,
        _domain: &'a str,
    ) -> Pin<Box<dyn Future<Output = io::Result<IpAddr>> + Send + 'a>> {
        Box::pin(async {
            panic!(
                "resolve_in_tunnel must not be called; zero-TOCTOU uses resolve_all_in_tunnel once"
            )
        })
    }

    fn resolve_all_in_tunnel<'a>(
        &'a self,
        _domain: &'a str,
    ) -> crate::proxy::router::ResolveAllFut<'a> {
        self.dns_calls.fetch_add(1, Ordering::SeqCst);
        let ips = self.ips.clone();
        Box::pin(async move { Ok(ips) })
    }
}

async fn assert_socks5_fallback_connect(router: Arc<dyn TunnelRouter>, domain: &[u8], port: u16) {
    let (mut client, server) = tokio::io::duplex(2048);
    tokio::spawn(async move {
        let _ = handle_socks5(server, router).await;
    });
    client
        .write_all(&[SOCKS5_VERSION, 1, METHOD_NO_AUTH])
        .await
        .unwrap();
    let mut g_resp = [0u8; 2];
    client.read_exact(&mut g_resp).await.unwrap();

    let mut cmd = vec![
        SOCKS5_VERSION,
        CMD_CONNECT,
        0x00,
        ATYP_DOMAIN,
        domain.len() as u8,
    ];
    cmd.extend_from_slice(domain);
    cmd.extend_from_slice(&port.to_be_bytes());
    client.write_all(&cmd).await.unwrap();

    let mut reply_hdr = [0u8; 4];
    client.read_exact(&mut reply_hdr).await.unwrap();
    assert_eq!(reply_hdr[1], REP_SUCCESS);
    let mut bnd = [0u8; 6];
    client.read_exact(&mut bnd).await.unwrap();
    client.write_all(b"ping").await.unwrap();
    let mut pong = [0u8; 4];
    client.read_exact(&mut pong).await.unwrap();
    assert_eq!(&pong, b"ping");
}

async fn assert_http_connect_fallback(router: Arc<dyn TunnelRouter>, port: u16) {
    let (mut h_client, h_server) = tokio::io::duplex(2048);
    tokio::spawn(async move {
        let _ = handle_http(h_server, router).await;
    });
    let connect_req = format!(
        "CONNECT multi-ip.example.com:{port} HTTP/1.1\r\nHost: multi-ip.example.com:{port}\r\n\r\n"
    );
    h_client.write_all(connect_req.as_bytes()).await.unwrap();
    let (status, _, _, _) = read_http_headers_helper(&mut h_client).await.unwrap();
    assert_eq!(status, 200);
    h_client.write_all(b"http").await.unwrap();
    let mut hpong = [0u8; 4];
    h_client.read_exact(&mut hpong).await.unwrap();
    assert_eq!(&hpong, b"http");
}

#[tokio::test]
async fn test_zero_toctou_single_dns_and_multi_ip_fallback_socks5_and_http() {
    let echo_addr = spawn_echo_tcp_server().await;
    let first_ip: IpAddr = "198.51.100.10".parse().unwrap();
    // The second candidate is the TEST-NET-1 stand-in (loopback
    // candidates are rejected by the destination guard); the mock dials
    // the loopback echo server for it (see `TEST_ECHO_IP`).
    let second_ip = TEST_ECHO_IP;

    let mock =
        Arc::new(FallbackMockTarget::new(vec![first_ip, second_ip]).with_dial_redirect(echo_addr));
    let router: Arc<dyn TunnelRouter> = Arc::new(SingleTunnelRouter::new(
        "fallback-tun",
        Arc::clone(&mock) as Arc<dyn ProxyTunnelTarget>,
        None,
    ));

    // 1. SOCKS5 CONNECT: single DNS lookup, fails first_ip, falls back to second_ip
    assert_socks5_fallback_connect(
        Arc::clone(&router),
        b"multi-ip.example.com",
        echo_addr.port(),
    )
    .await;
    assert_eq!(mock.dns_calls.load(Ordering::SeqCst), 1);
    assert_eq!(
        *mock.dialed_addrs.lock(),
        vec![
            SocketAddr::new(first_ip, echo_addr.port()),
            SocketAddr::new(second_ip, echo_addr.port()),
        ]
    );

    // 2. HTTP CONNECT: single DNS lookup, fails first_ip, falls back to second_ip
    mock.dialed_addrs.lock().clear();
    assert_http_connect_fallback(Arc::clone(&router), echo_addr.port()).await;
    assert_eq!(mock.dns_calls.load(Ordering::SeqCst), 2);
    assert_eq!(
        *mock.dialed_addrs.lock(),
        vec![
            SocketAddr::new(first_ip, echo_addr.port()),
            SocketAddr::new(second_ip, echo_addr.port()),
        ]
    );

    // 3. HTTP forward proxy: single DNS lookup, fails first_ip, falls back to second_ip
    let http_srv = spawn_mock_http_server("multi_ip_http_ok").await;
    let first_http_ip: IpAddr = "198.51.100.11".parse().unwrap();
    let mock_fwd = Arc::new(
        FallbackMockTarget::new(vec![first_http_ip, TEST_ECHO_IP]).with_dial_redirect(http_srv),
    );
    let r_fwd: Arc<dyn TunnelRouter> = Arc::new(SingleTunnelRouter::new(
        "fallback-fwd",
        Arc::clone(&mock_fwd) as Arc<dyn ProxyTunnelTarget>,
        None,
    ));
    let (mut f_client, f_server) = tokio::io::duplex(4096);
    tokio::spawn(async move {
        let _ = handle_http(f_server, r_fwd).await;
    });
    let fwd_req = format!(
        "GET http://multi-ip.example.com:{p}/test HTTP/1.1\r\nHost: multi-ip.example.com:{p}\r\n\r\n",
        p = http_srv.port()
    );
    f_client.write_all(fwd_req.as_bytes()).await.unwrap();
    let (f_status, _, _, f_body) = read_http_headers_helper(&mut f_client).await.unwrap();
    assert_eq!(f_status, 200);
    assert_eq!(String::from_utf8_lossy(&f_body), "multi_ip_http_ok");
    assert_eq!(mock_fwd.dns_calls.load(Ordering::SeqCst), 1);
    assert_eq!(
        *mock_fwd.dialed_addrs.lock(),
        vec![
            SocketAddr::new(first_http_ip, http_srv.port()),
            SocketAddr::new(TEST_ECHO_IP, http_srv.port()),
        ]
    );
}

struct BlackholeCapMockTarget {
    blackhole_ips: std::collections::HashSet<IpAddr>,
    refused_ips: std::collections::HashSet<IpAddr>,
    dialed_addrs: parking_lot::Mutex<Vec<SocketAddr>>,
    /// When set, dials of any non-blackhole, non-refused IP go here
    /// instead (see [`TEST_ECHO_IP`]).
    dial_redirect: Option<SocketAddr>,
}

impl BlackholeCapMockTarget {
    fn new(blackhole_ips: Vec<IpAddr>, refused_ips: Vec<IpAddr>) -> Self {
        Self {
            blackhole_ips: blackhole_ips.into_iter().collect(),
            refused_ips: refused_ips.into_iter().collect(),
            dialed_addrs: parking_lot::Mutex::new(Vec::new()),
            dial_redirect: None,
        }
    }

    fn with_dial_redirect(self, addr: SocketAddr) -> Self {
        Self {
            dial_redirect: Some(addr),
            ..self
        }
    }
}

impl ProxyTunnelTarget for BlackholeCapMockTarget {
    fn tcp_connect<'a>(
        &'a self,
        dst: SocketAddr,
    ) -> Pin<Box<dyn Future<Output = io::Result<DynStream>> + Send + 'a>> {
        self.dialed_addrs.lock().push(dst);
        let is_blackhole = self.blackhole_ips.contains(&dst.ip());
        let is_refused = self.refused_ips.contains(&dst.ip());
        let dial_redirect = self.dial_redirect;
        Box::pin(async move {
            if is_blackhole {
                std::future::pending::<io::Result<DynStream>>().await
            } else if is_refused {
                Err(io::Error::new(
                    io::ErrorKind::ConnectionRefused,
                    "mock refused",
                ))
            } else {
                let stream = TcpStream::connect(dial_redirect.unwrap_or(dst)).await?;
                Ok(Box::new(stream) as DynStream)
            }
        })
    }

    fn udp_bind<'a>(
        &'a self,
        _local_port: u16,
    ) -> Pin<Box<dyn Future<Output = io::Result<Box<dyn ProxyUdpSocket>>> + Send + 'a>> {
        Box::pin(async { Err(io::Error::other("unused")) })
    }

    fn resolve_in_tunnel<'a>(
        &'a self,
        _domain: &'a str,
    ) -> Pin<Box<dyn Future<Output = io::Result<IpAddr>> + Send + 'a>> {
        Box::pin(async { Err(io::Error::other("unused")) })
    }
}

struct MockUdpFallbackSocket {
    blackhole_addrs: std::collections::HashSet<SocketAddr>,
    failing_addrs: std::collections::HashSet<SocketAddr>,
    sent_addrs: parking_lot::Mutex<Vec<SocketAddr>>,
}

impl MockUdpFallbackSocket {
    fn new(blackhole_addrs: Vec<SocketAddr>, failing_addrs: Vec<SocketAddr>) -> Self {
        Self {
            blackhole_addrs: blackhole_addrs.into_iter().collect(),
            failing_addrs: failing_addrs.into_iter().collect(),
            sent_addrs: parking_lot::Mutex::new(Vec::new()),
        }
    }
}

impl ProxyUdpSocket for MockUdpFallbackSocket {
    fn send_to<'a>(
        &'a self,
        buf: &'a [u8],
        target: SocketAddr,
    ) -> Pin<Box<dyn Future<Output = io::Result<usize>> + Send + 'a>> {
        self.sent_addrs.lock().push(target);
        let is_blackhole = self.blackhole_addrs.contains(&target);
        let is_failing = self.failing_addrs.contains(&target);
        let len = buf.len();
        Box::pin(async move {
            if is_blackhole {
                std::future::pending::<io::Result<usize>>().await
            } else if is_failing {
                Err(io::Error::new(
                    io::ErrorKind::ConnectionRefused,
                    "mock udp send refused",
                ))
            } else {
                Ok(len)
            }
        })
    }

    fn recv_from<'a>(&'a self, _buf: &'a mut [u8]) -> crate::proxy::router::RecvFromFut<'a> {
        Box::pin(async { std::future::pending().await })
    }

    fn local_port(&self) -> u16 {
        0
    }
}

#[test]
fn test_bound_candidate_addrs_filters_before_capping_and_preserves_order() {
    use crate::proxy::router::{
        MAX_CANDIDATE_IPS, MIN_ATTEMPT_TIMEOUT, bound_candidate_addrs,
        bound_candidate_socket_addrs, next_attempt_timeout,
    };

    let forbidden: IpAddr = "169.254.169.254".parse().unwrap();
    let v6_preferred: IpAddr = "2001:db8::1".parse().unwrap();
    let mut ips = vec![forbidden, v6_preferred];
    for octet in 1..=12u8 {
        ips.push(IpAddr::V4(Ipv4Addr::new(198, 51, 100, octet)));
    }

    let bounded = bound_candidate_addrs(&ips, 443);
    assert_eq!(bounded.len(), MAX_CANDIDATE_IPS);
    assert_eq!(bounded[0], SocketAddr::new(v6_preferred, 443));
    assert_eq!(
        bounded[MAX_CANDIDATE_IPS - 1],
        SocketAddr::new(IpAddr::V4(Ipv4Addr::new(198, 51, 100, 7)), 443)
    );

    let sock_inputs: Vec<SocketAddr> = ips.iter().map(|&ip| SocketAddr::new(ip, 53)).collect();
    let sock_bounded = bound_candidate_socket_addrs(&sock_inputs);
    assert_eq!(sock_bounded.len(), MAX_CANDIDATE_IPS);
    assert_eq!(sock_bounded[0], SocketAddr::new(v6_preferred, 53));

    let now = tokio::time::Instant::now();
    let fair = next_attempt_timeout(now + Duration::from_secs(2), 4).unwrap();
    assert!(fair > MIN_ATTEMPT_TIMEOUT && fair <= Duration::from_secs(2));
    let floored = next_attempt_timeout(now + Duration::from_millis(600), 8).unwrap();
    assert!(floored >= Duration::from_millis(200) && floored <= MIN_ATTEMPT_TIMEOUT);
    let clamped = next_attempt_timeout(now + Duration::from_millis(80), 4).unwrap();
    assert!(clamped <= Duration::from_millis(80));
    assert!(next_attempt_timeout(now - Duration::from_millis(1), 1).is_none());
}

#[tokio::test]
async fn test_connect_validated_addrs_caps_attempts_at_max_candidate_ips() {
    use crate::proxy::router::{MAX_CANDIDATE_IPS, connect_validated_addrs_with_timeout};

    let ips: Vec<IpAddr> = (1..=14u8)
        .map(|octet| IpAddr::V4(Ipv4Addr::new(198, 51, 100, octet)))
        .collect();
    let mock = BlackholeCapMockTarget::new(Vec::new(), ips.clone());

    let err = connect_validated_addrs_with_timeout(&mock, &ips, 80, Duration::from_secs(2))
        .await
        .err()
        .expect("all refused IPs must error");
    assert_eq!(err.kind(), io::ErrorKind::ConnectionRefused);

    let dialed = mock.dialed_addrs.lock();
    assert_eq!(dialed.len(), MAX_CANDIDATE_IPS);
    assert_eq!(dialed[0], SocketAddr::new(ips[0], 80));
    assert_eq!(
        dialed[MAX_CANDIDATE_IPS - 1],
        SocketAddr::new(ips[MAX_CANDIDATE_IPS - 1], 80)
    );
}

#[tokio::test]
async fn test_connect_validated_addrs_all_blackhole_bounded_by_total_timeout() {
    use crate::proxy::router::{MAX_CANDIDATE_IPS, connect_validated_addrs_with_timeout};

    let ips: Vec<IpAddr> = (1..=10u8)
        .map(|octet| IpAddr::V4(Ipv4Addr::new(198, 51, 100, octet)))
        .collect();
    let mock = BlackholeCapMockTarget::new(ips.clone(), Vec::new());
    let total_budget = Duration::from_millis(650);

    let start = tokio::time::Instant::now();
    let err = connect_validated_addrs_with_timeout(&mock, &ips, 80, total_budget)
        .await
        .err()
        .expect("all blackhole IPs must time out");
    let elapsed = start.elapsed();

    assert_eq!(err.kind(), io::ErrorKind::TimedOut);
    assert!(
        elapsed < Duration::from_millis(1200),
        "elapsed {elapsed:?} exceeded bounded total budget {total_budget:?}"
    );
    assert!(mock.dialed_addrs.lock().len() <= MAX_CANDIDATE_IPS);
}

#[tokio::test]
async fn test_connect_validated_addrs_timeout_notes_attempt_aborted() {
    use crate::proxy::router::connect_validated_addrs_with_timeout;

    // A per-candidate timeout drops the connect future mid-flight
    // without a verdict. The target must be told, so a `HalfOpen`
    // trial resolves as a failure instead of lingering undecided.
    let mock = MockTunnelTarget::new("hang-1").with_hanging_tcp();
    let aborted = Arc::clone(&mock.aborted);
    let ips: Vec<IpAddr> = vec!["198.51.100.1".parse().unwrap()];

    let err = connect_validated_addrs_with_timeout(&mock, &ips, 80, Duration::from_millis(300))
        .await
        .err()
        .expect("hanging candidate must time out");
    assert_eq!(err.kind(), io::ErrorKind::TimedOut);
    assert!(
        aborted.load(Ordering::SeqCst),
        "per-candidate timeout must note the aborted attempt on the target"
    );
}

#[tokio::test]
async fn test_connect_via_router_budget_abort_notes_attempt_aborted() {
    use crate::proxy::router::{RouterConnectError, connect_via_router};

    // The per-attempt deadline (1.25 s) cuts a hanging attempt off
    // mid-flight — the pool no longer burns the whole 3.5 s budget
    // on one dead tunnel. The target must still be told, so a
    // `HalfOpen` trial resolves as a failure and the next request
    // can fail fast instead of burning the budget again.
    let target = Arc::new(MockTunnelTarget::new("hang-1").with_hanging_tcp());
    let aborted = Arc::clone(&target.aborted);
    let router: Arc<dyn TunnelRouter> = Arc::new(SingleTunnelRouter::new("hang-1", target, None));
    let dst: SocketAddr = "203.0.113.1:80".parse().unwrap();

    let start = tokio::time::Instant::now();
    let err = connect_via_router(
        &router,
        &TunnelSelector::DefaultPool,
        &TargetAddr::Ip(dst),
        None,
        None,
    )
    .await
    .err()
    .expect("hanging pool attempt must fail on the deadline");
    let elapsed = start.elapsed();

    let RouterConnectError::TcpConnect(e) = err else {
        panic!("deadline abort must surface as a TcpConnect error");
    };
    assert_eq!(e.kind(), io::ErrorKind::TimedOut);
    assert!(
        e.to_string().contains("timed out after"),
        "unexpected deadline error: {e}"
    );
    assert!(
        elapsed >= Duration::from_millis(1000),
        "deadline abort must wait out the per-attempt deadline, took {elapsed:?}"
    );
    assert!(
        elapsed < Duration::from_secs(3),
        "deadline abort must not burn the full failover budget, took {elapsed:?}"
    );
    assert!(
        aborted.load(Ordering::SeqCst),
        "pool deadline abort must note the aborted attempt on the target"
    );
}

/// Probe trace (P=64): a successful pool dial returns its trace — the
/// winning leg, its stage durations, and the attempt count — so the
/// analysis can classify each CONNECT as M1 (slow TCP stage, fast DNS)
/// or M2 (slow DNS stage) without joining client records.
#[tokio::test]
async fn test_connect_trace_records_winning_leg_and_stages() {
    use crate::proxy::router::{LegOutcomeKind, RaceLeg, connect_via_router};

    let echo_addr = spawn_echo_tcp_server().await;
    let target = TargetAddr::Ip(test_echo_target(echo_addr));
    let pool = Arc::new(PoolRouter::new(PoolStrategy::RoundRobin, true));
    pool.add_tunnel(
        "alive-1",
        Arc::new(MockTunnelTarget::new("alive-1").with_dial_redirect(echo_addr)),
    );
    pool.add_tunnel(
        "alive-2",
        Arc::new(MockTunnelTarget::new("alive-2").with_dial_redirect(echo_addr)),
    );
    let router: Arc<dyn TunnelRouter> = pool;

    let (_stream, winner_id, trace) =
        connect_via_router(&router, &TunnelSelector::DefaultPool, &target, None, None)
            .await
            .expect("dial must succeed");
    assert_eq!(winner_id.as_deref(), Some("alive-1"));
    assert_eq!(trace.winner_leg, Some(RaceLeg::First));
    assert_eq!(trace.attempts, 1);
    assert_eq!(trace.first_leg.tunnel_id.as_deref(), Some("alive-1"));
    assert_eq!(trace.first_leg.outcome, LegOutcomeKind::Won);
    assert!(
        trace.first_leg.tcp_ms.is_some(),
        "winning leg must carry its TCP stage duration"
    );
    assert_eq!(trace.first_leg.dns_ms, None, "IP target has no DNS stage");
    assert!(trace.second_leg.is_none(), "fast first leg is never hedged");
    assert!(trace.total_ms < 5000, "trace total took {}", trace.total_ms);
}

/// Regression (audit run-3 #7,
/// `proxy.dns-pre-resolve-cross-tunnel-no-selector-binding`): the
/// pre-resolve used to ask the router for any live tunnel with no
/// selector binding, so a domain query egressed via the unselected
/// tunnel B — even for a client whose credentials tunnel A rejects.
/// The pre-resolve now runs through `select_tunnel` first and only via
/// the selected tunnel when it is live; a failed selection means no
/// DNS query anywhere.
#[tokio::test]
async fn test_preresolve_uses_selected_tunnel_only() {
    use crate::proxy::router::{RouterConnectError, connect_via_router};

    let echo_addr = spawn_echo_tcp_server().await;
    let target_a = Arc::new(
        RecordingStubTarget::new("wgcf-a")
            .with_live()
            .with_dns("victim.example.test", "192.0.2.99".parse().unwrap())
            .with_dns("victim2.example.test", "192.0.2.99".parse().unwrap())
            .with_dial_redirect(echo_addr),
    );
    let target_b = Arc::new(
        RecordingStubTarget::new("wgcf-b")
            .with_live()
            .with_dns("victim.example.test", "192.0.2.99".parse().unwrap())
            .with_dns("victim2.example.test", "192.0.2.99".parse().unwrap()),
    );
    let router: Arc<dyn TunnelRouter> = Arc::new(AuthEnforcingStubRouter {
        target_a: Arc::<RecordingStubTarget>::clone(&target_a),
    });

    // Case 2 first (wrong credentials, fresh targets): selection must
    // fail before any DNS is attempted, on either tunnel.
    let err = connect_via_router(
        &router,
        &TunnelSelector::ById("wgcf-a".to_string()),
        &TargetAddr::Domain("victim2.example.test".to_string(), 443),
        Some(("wgcf-a", "WRONG")),
        None,
    )
    .await
    .err()
    .expect("wrong credentials must fail the connect");
    let RouterConnectError::SelectTunnel(e) = err else {
        panic!("wrong credentials must fail at selection, got {err:?}");
    };
    assert_eq!(e.kind(), io::ErrorKind::PermissionDenied);
    assert!(
        target_a.queries().is_empty() && target_b.queries().is_empty(),
        "a rejected client must cause zero DNS queries anywhere: A={:?} B={:?}",
        target_a.queries(),
        target_b.queries()
    );
    assert!(
        target_a.dials().is_empty() && target_b.dials().is_empty(),
        "a rejected client must cause zero dials anywhere: A={:?} B={:?}",
        target_a.dials(),
        target_b.dials()
    );

    // Case 1 — client authenticated only for tunnel A, ById(A): the
    // query must go via A (pre-resolve + per-leg resolve), never via
    // B, and the dial must go via A.
    let (stream, winner, _) = connect_via_router(
        &router,
        &TunnelSelector::ById("wgcf-a".to_string()),
        &TargetAddr::Domain("victim.example.test".to_string(), 443),
        Some(("wgcf-a", "pw-a")),
        None,
    )
    .await
    .expect("authenticated connect must succeed");
    drop(stream);
    assert_eq!(winner.as_deref(), Some("wgcf-a"));
    assert_eq!(
        target_a.queries(),
        vec![
            "victim.example.test".to_string(),
            "victim.example.test".to_string()
        ],
        "pre-resolve and per-leg resolve must both go via the selected tunnel A"
    );
    assert!(
        target_b.queries().is_empty(),
        "the unselected tunnel B must see no DNS query, got {:?}",
        target_b.queries()
    );
    assert_eq!(
        target_a.dials(),
        vec!["192.0.2.99:443".parse::<SocketAddr>().unwrap()],
        "the dial must go via the selected tunnel A"
    );
    assert!(
        target_b.dials().is_empty(),
        "the unselected tunnel B must see no dial, got {:?}",
        target_b.dials()
    );
}

/// Regression (audit run-3 #6,
/// `proxy.destination.cgnat-reserved-ranges-not-forbidden`): SOCKS5 and
/// HTTP CONNECT to CGNAT, benchmarking, reserved, and 0.0.0.0/8-remainder
/// destinations must be rejected with the forbidden-destination reply
/// and never dialled through the tunnel.
#[tokio::test]
async fn test_socks5_and_http_reject_cgnat_and_reserved_ranges() {
    let stub = Arc::new(RecordingStubTarget::new("cgnat-stub").with_failing_tcp());
    let router: Arc<dyn TunnelRouter> = Arc::new(SingleTunnelRouter::new(
        "cgnat-stub",
        Arc::<RecordingStubTarget>::clone(&stub),
        None,
    ));

    for ip_str in ["100.64.0.1", "198.18.0.1", "240.0.0.1", "0.1.2.3"] {
        let ip: Ipv4Addr = ip_str.parse().unwrap();
        run_socks5_connect_expect_rep(
            Arc::clone(&router),
            ATYP_IPV4,
            &ip.octets(),
            80,
            Some(crate::proxy::socks5::REP_CONN_NOT_ALLOWED),
        )
        .await;
    }

    for ip_str in ["100.64.0.1", "198.18.0.1", "240.0.0.1"] {
        let (mut client, server) = tokio::io::duplex(2048);
        let r_connect = Arc::clone(&router);
        tokio::spawn(async move {
            let _ = handle_http(server, r_connect).await;
        });
        let req = format!("CONNECT {ip_str}:80 HTTP/1.1\r\nHost: {ip_str}:80\r\n\r\n");
        client.write_all(req.as_bytes()).await.unwrap();
        let (status, _, _, _) = read_http_headers_helper(&mut client).await.unwrap();
        assert_eq!(
            status, 403,
            "HTTP CONNECT to {ip_str} must be rejected with 403"
        );
    }

    assert!(
        stub.dials().is_empty(),
        "no dial may be attempted to a forbidden range, got {:?}",
        stub.dials()
    );
}

/// Regression (audit run-3 #8, `proxy/router.rs:constant-time-eq-str-max-length-timing-leaks-secret-length`):
/// the comparator must stay correct while its running time no longer
/// depends on either input's length (fixed iteration count).
#[test]
fn test_constant_time_eq_str_correctness() {
    use crate::proxy::router::constant_time_eq_str;

    assert!(constant_time_eq_str("secret-token-123", "secret-token-123"));
    assert!(!constant_time_eq_str(
        "secret-token-123",
        "secret-token-124"
    ));
    assert!(!constant_time_eq_str("secret-token-123", "secret-token"));
    assert!(!constant_time_eq_str("secret-token", "secret-token-123"));
    assert!(!constant_time_eq_str("", "secret-token-123"));
    assert!(!constant_time_eq_str("secret-token-123", ""));
    assert!(constant_time_eq_str("", ""));
    // The fixed-iteration cap: inputs longer than the cap never compare
    // equal, even when identical — fail closed, never open.
    let at_cap = "a".repeat(256);
    assert!(constant_time_eq_str(&at_cap, &at_cap));
    let over_cap = "a".repeat(257);
    assert!(!constant_time_eq_str(&over_cap, &over_cap));
    assert!(!constant_time_eq_str(&over_cap, &at_cap));
    // A long guess sharing the secret's prefix must not match.
    let long_guess = format!("secret-token-123{}", "x".repeat(300));
    assert!(!constant_time_eq_str(&long_guess, "secret-token-123"));
}

/// Regression (audit run-3 #8): both halves of a credential pair must
/// be checked — a wrong username and a wrong password are both plain
/// rejections, with no short-circuit between the two comparisons.
#[test]
fn test_single_tunnel_router_authenticate_checks_both_halves() {
    let target = Arc::new(DirectTunnelTarget);
    let router = SingleTunnelRouter::new(
        "auth-tunnel",
        target,
        Some(("admin".to_string(), "secret123".to_string())),
    );
    assert_eq!(
        router.authenticate(Some(("admin", "secret123"))),
        Ok(TunnelSelector::ById("auth-tunnel".to_string()))
    );
    assert_eq!(
        router.authenticate(Some(("wrong-user", "secret123"))),
        Err(ProxyAuthError::InvalidCredentials)
    );
    assert_eq!(
        router.authenticate(Some(("admin", "wrong-pass"))),
        Err(ProxyAuthError::InvalidCredentials)
    );
    assert_eq!(
        router.authenticate(Some(("wrong-user", "wrong-pass"))),
        Err(ProxyAuthError::InvalidCredentials)
    );
    assert_eq!(router.authenticate(None), Err(ProxyAuthError::AuthRequired));
}

#[tokio::test]
async fn test_race_hedges_dormant_slow_leg_with_second_tunnel() {
    use crate::proxy::router::connect_via_router;

    let echo_addr = spawn_echo_tcp_server().await;
    let target = TargetAddr::Ip(test_echo_target(echo_addr));

    // First leg: dormant (not live) and slow — its dial would take
    // 2 s, past the 1.25 s per-attempt deadline.
    let slow = Arc::new(
        MockTunnelTarget::new("wgcf-001")
            .with_dial_redirect(echo_addr)
            .with_tcp_delay(Duration::from_millis(2000)),
    );
    let slow_aborted = Arc::clone(&slow.aborted);
    let fast = Arc::new(MockTunnelTarget::new("wgcf-002").with_dial_redirect(echo_addr));

    let pool = Arc::new(PoolRouter::new(PoolStrategy::RoundRobin, true));
    pool.add_tunnel("wgcf-001", Arc::clone(&slow) as Arc<dyn ProxyTunnelTarget>);
    pool.add_tunnel("wgcf-002", Arc::clone(&fast) as Arc<dyn ProxyTunnelTarget>);
    let router: Arc<dyn TunnelRouter> = pool;

    let start = tokio::time::Instant::now();
    let (stream, id, _) =
        connect_via_router(&router, &TunnelSelector::DefaultPool, &target, None, None)
            .await
            .expect("hedged dial must succeed");
    let elapsed = start.elapsed();
    drop(stream);

    // The second tunnel wins the race: the request succeeds in ~250 ms
    // instead of waiting out the slow leg's 2 s dial.
    assert_eq!(id.as_deref(), Some("wgcf-002"));
    assert!(
        elapsed < Duration::from_millis(1500),
        "hedged dial must finish well before the slow leg would, took {elapsed:?}"
    );
    // Both legs actually started; the loser was cancelled and its
    // attempt resolved, not left dangling.
    assert_eq!(slow.tcp_conns.load(Ordering::SeqCst), 1);
    assert_eq!(fast.tcp_conns.load(Ordering::SeqCst), 1);
    assert!(
        slow_aborted.load(Ordering::SeqCst),
        "losing leg must be noted aborted"
    );
}

#[tokio::test]
async fn test_race_does_not_hedge_live_first_leg() {
    use crate::proxy::router::connect_via_router;

    let echo_addr = spawn_echo_tcp_server().await;
    let target = TargetAddr::Ip(test_echo_target(echo_addr));

    // First leg is live but slow (600 ms): it finishes inside the
    // 1.25 s per-attempt deadline, so no hedge may start — hedging a
    // live tunnel would only double-spend a healthy tunnel for a
    // slow target.
    let live_slow = Arc::new(
        MockTunnelTarget::new("wgcf-001")
            .with_live()
            .with_dial_redirect(echo_addr)
            .with_tcp_delay(Duration::from_millis(600)),
    );
    let fast = Arc::new(MockTunnelTarget::new("wgcf-002").with_dial_redirect(echo_addr));

    let pool = Arc::new(PoolRouter::new(PoolStrategy::RoundRobin, true));
    pool.add_tunnel(
        "wgcf-001",
        Arc::clone(&live_slow) as Arc<dyn ProxyTunnelTarget>,
    );
    pool.add_tunnel("wgcf-002", Arc::clone(&fast) as Arc<dyn ProxyTunnelTarget>);
    let router: Arc<dyn TunnelRouter> = pool;

    let start = tokio::time::Instant::now();
    let (stream, id, _) =
        connect_via_router(&router, &TunnelSelector::DefaultPool, &target, None, None)
            .await
            .expect("live slow dial must succeed");
    let elapsed = start.elapsed();
    drop(stream);

    assert_eq!(id.as_deref(), Some("wgcf-001"));
    assert!(
        elapsed >= Duration::from_millis(500),
        "live slow leg must run to completion, took {elapsed:?}"
    );
    assert!(
        elapsed < Duration::from_millis(1250),
        "live slow leg must finish inside its per-attempt deadline, took {elapsed:?}"
    );
    assert_eq!(
        fast.tcp_conns.load(Ordering::SeqCst),
        0,
        "second tunnel must never be dialed when the first leg is live"
    );
}

#[tokio::test]
async fn test_race_both_legs_timeout_within_budget() {
    use crate::proxy::router::{RouterConnectError, connect_via_router};

    // Two hanging tunnels: the first leg times out at 1.25 s, the
    // hedged second leg at ~1.5 s, and the round ends — the request
    // fails inside the 3.5 s budget instead of burning it all on one
    // tunnel.
    let t1 = Arc::new(MockTunnelTarget::new("wgcf-001").with_hanging_tcp());
    let t2 = Arc::new(MockTunnelTarget::new("wgcf-002").with_hanging_tcp());
    let pool = Arc::new(PoolRouter::new(PoolStrategy::RoundRobin, true));
    pool.add_tunnel("wgcf-001", Arc::clone(&t1) as Arc<dyn ProxyTunnelTarget>);
    pool.add_tunnel("wgcf-002", Arc::clone(&t2) as Arc<dyn ProxyTunnelTarget>);
    let router: Arc<dyn TunnelRouter> = pool;
    let dst: SocketAddr = "203.0.113.1:80".parse().unwrap();

    let start = tokio::time::Instant::now();
    let err = connect_via_router(
        &router,
        &TunnelSelector::DefaultPool,
        &TargetAddr::Ip(dst),
        None,
        None,
    )
    .await
    .err()
    .expect("two hanging legs must fail");
    let elapsed = start.elapsed();

    let RouterConnectError::TcpConnect(e) = err else {
        panic!("two hanging legs must surface as a TcpConnect error, got {err:?}");
    };
    assert_eq!(e.kind(), io::ErrorKind::TimedOut);
    assert!(
        elapsed >= Duration::from_secs(1),
        "both legs must run out their per-attempt deadlines, took {elapsed:?}"
    );
    assert!(
        elapsed < Duration::from_secs(3),
        "two hanging legs must fail inside the failover budget, took {elapsed:?}"
    );
}

#[test]
fn test_should_warn_terminal_failure_gating() {
    use crate::proxy::router::{RouterConnectError, should_warn_terminal_failure};

    let refused = || io::Error::new(io::ErrorKind::ConnectionRefused, "refused");
    let timed_out = || io::Error::new(io::ErrorKind::TimedOut, "timed out");
    let not_connected =
        || io::Error::new(io::ErrorKind::NotConnected, "no healthy tunnels available");

    // Fast TCP/DNS failures: no other layer warns about them.
    assert!(should_warn_terminal_failure(
        &RouterConnectError::TcpConnect(refused())
    ));
    assert!(should_warn_terminal_failure(
        &RouterConnectError::DnsResolution(refused())
    ));
    // Timed-out errors: the listener already warns on `TimedOut`.
    assert!(!should_warn_terminal_failure(
        &RouterConnectError::TcpConnect(timed_out())
    ));
    assert!(!should_warn_terminal_failure(
        &RouterConnectError::DnsResolution(timed_out())
    ));
    // Selection failures: the protocol handlers already warn.
    assert!(!should_warn_terminal_failure(
        &RouterConnectError::SelectTunnel(not_connected())
    ));
    // Forbidden destinations: deterministic policy rejections.
    assert!(!should_warn_terminal_failure(
        &RouterConnectError::ForbiddenDestination(refused())
    ));
}

#[tokio::test]
async fn test_connect_via_router_fast_tcp_failure_warns_with_tunnel_and_target() {
    use crate::proxy::router::{RouterConnectError, connect_via_router};

    // A fast TCP refusal must be classifiable from the log alone:
    // one WARN naming the tunnel tried, the target, and the error.
    // (The 0.25s/0.35s failures in the 2000-request measurement had
    // no WARN at all, so they could not be classified.)
    let captured = Arc::new(Mutex::new(Vec::new()));
    let subscriber = tracing_subscriber::fmt()
        .with_max_level(tracing::Level::WARN)
        .with_writer(VecMakeWriter(Arc::clone(&captured)))
        .finish();
    let _guard = tracing::subscriber::set_default(subscriber);

    let target = Arc::new(
        MockTunnelTarget::new("refused-1").with_tcp_failure(io::ErrorKind::ConnectionRefused),
    );
    let router: Arc<dyn TunnelRouter> =
        Arc::new(SingleTunnelRouter::new("refused-1", target, None));
    let dst: SocketAddr = "203.0.113.1:80".parse().unwrap();

    let start = tokio::time::Instant::now();
    let err = connect_via_router(
        &router,
        &TunnelSelector::DefaultPool,
        &TargetAddr::Ip(dst),
        None,
        None,
    )
    .await
    .err()
    .expect("refused pool attempt must fail fast");
    let elapsed = start.elapsed();

    let RouterConnectError::TcpConnect(e) = err else {
        panic!("fast TCP refusal must surface as a TcpConnect error");
    };
    assert_eq!(e.kind(), io::ErrorKind::ConnectionRefused);
    assert!(
        elapsed < Duration::from_secs(1),
        "fast refusal must not burn the failover budget, took {elapsed:?}"
    );

    let rendered = String::from_utf8(captured.lock().unwrap().clone()).unwrap();
    assert!(
        rendered.contains("proxy connection failed"),
        "expected the terminal-failure WARN in the daemon log, got: {rendered:?}"
    );
    assert!(
        rendered.contains("refused-1"),
        "expected the tried tunnel id in the WARN, got: {rendered:?}"
    );
    assert!(
        rendered.contains("203.0.113.1:80"),
        "expected the target in the WARN, got: {rendered:?}"
    );
    assert!(
        rendered.contains("tcp_connect"),
        "expected the error kind in the WARN, got: {rendered:?}"
    );
}

#[test]
fn test_log_connect_session_end_warns_on_empty_reply() {
    use crate::proxy::{ConnectSessionOutcome, CopyEndKind, log_connect_session_end};

    fn outcome(
        result: io::Result<(u64, u64)>,
        kind: CopyEndKind,
        ms: u64,
    ) -> ConnectSessionOutcome {
        ConnectSessionOutcome {
            result,
            kind,
            duration: Duration::from_millis(ms),
            // Fabricated outcome, no replay session to join.
            request_id: 0,
        }
    }

    // The measured "empty reply" failure: the client sent a request
    // and the target sent nothing back, yet the copy returned `Ok` —
    // the session must leave one WARN naming the tunnel and target.
    // Plain output: with ANSI colors the `duration_ms=15000` field
    // is split by escape codes and never matches as one string.
    let captured = Arc::new(Mutex::new(Vec::new()));
    let subscriber = tracing_subscriber::fmt()
        .with_max_level(tracing::Level::WARN)
        .with_ansi(false)
        .with_writer(VecMakeWriter(Arc::clone(&captured)))
        .finish();
    let _guard = tracing::subscriber::set_default(subscriber);

    let target = TargetAddr::Ip("203.0.113.1:80".parse().unwrap());
    log_connect_session_end(
        "SOCKS5",
        &TunnelSelector::DefaultPool,
        &target,
        Some("live-1"),
        &outcome(Ok((128, 0)), CopyEndKind::ClientAborted, 15_000),
    );
    let rendered = String::from_utf8(captured.lock().unwrap().clone()).unwrap();
    assert!(
        rendered.contains("no response bytes"),
        "expected the empty-reply WARN in the daemon log, got: {rendered:?}"
    );
    assert!(
        rendered.contains("live-1"),
        "expected the serving tunnel id in the WARN, got: {rendered:?}"
    );
    assert!(
        rendered.contains("203.0.113.1:80"),
        "expected the target in the WARN, got: {rendered:?}"
    );
    assert!(
        rendered.contains("ClientAborted"),
        "expected the session ending in the WARN, got: {rendered:?}"
    );
    assert!(
        rendered.contains("duration_ms=15000"),
        "expected the session duration in the WARN, got: {rendered:?}"
    );

    // A session that exchanged bytes both ways is healthy: no WARN.
    captured.lock().unwrap().clear();
    log_connect_session_end(
        "SOCKS5",
        &TunnelSelector::DefaultPool,
        &target,
        Some("live-1"),
        &outcome(Ok((128, 512)), CopyEndKind::TunnelClosed, 1_200),
    );
    assert!(
        captured.lock().unwrap().is_empty(),
        "healthy session must not warn"
    );

    // A client that connects and leaves without sending anything is
    // routine, not a failure: no WARN.
    log_connect_session_end(
        "SOCKS5",
        &TunnelSelector::DefaultPool,
        &target,
        Some("live-1"),
        &outcome(Ok((0, 0)), CopyEndKind::IdleTimeout, 300_000),
    );
    assert!(
        captured.lock().unwrap().is_empty(),
        "client that sent nothing must not warn"
    );
}

#[test]
fn test_log_connect_session_end_warns_on_errors_except_timeouts() {
    use crate::proxy::{ConnectSessionOutcome, CopyEndKind, log_connect_session_end};

    fn outcome(
        result: io::Result<(u64, u64)>,
        kind: CopyEndKind,
        ms: u64,
    ) -> ConnectSessionOutcome {
        ConnectSessionOutcome {
            result,
            kind,
            duration: Duration::from_millis(ms),
            // Fabricated outcome, no replay session to join.
            request_id: 0,
        }
    }

    // A copy error after the grant is a failed session: one WARN with
    // the error. Timeouts are excluded — the listener already warns
    // on those, so logging them here would double-report one session.
    let captured = Arc::new(Mutex::new(Vec::new()));
    let subscriber = tracing_subscriber::fmt()
        .with_max_level(tracing::Level::WARN)
        .with_writer(VecMakeWriter(Arc::clone(&captured)))
        .finish();
    let _guard = tracing::subscriber::set_default(subscriber);

    let target = TargetAddr::Ip("203.0.113.1:80".parse().unwrap());
    let reset = io::Error::new(io::ErrorKind::ConnectionReset, "connection reset by peer");
    log_connect_session_end(
        "SOCKS5",
        &TunnelSelector::DefaultPool,
        &target,
        Some("live-1"),
        &outcome(Err(reset), CopyEndKind::Failed, 2_500),
    );
    let rendered = String::from_utf8(captured.lock().unwrap().clone()).unwrap();
    assert!(
        rendered.contains("failed after grant"),
        "expected the post-grant failure WARN, got: {rendered:?}"
    );
    captured.lock().unwrap().clear();
    let timed_out = io::Error::new(io::ErrorKind::TimedOut, "timed out");
    log_connect_session_end(
        "SOCKS5",
        &TunnelSelector::DefaultPool,
        &target,
        Some("live-1"),
        &outcome(Err(timed_out), CopyEndKind::IdleTimeout, 300_000),
    );
    assert!(
        captured.lock().unwrap().is_empty(),
        "timeout must not warn here (listener already warns)"
    );
}

#[tokio::test]
async fn test_connect_validated_addrs_falls_back_after_blackhole_within_budget() {
    use crate::proxy::router::connect_validated_addrs_with_timeout;

    let echo_addr = spawn_echo_tcp_server().await;
    let blackhole_ip: IpAddr = "198.51.100.1".parse().unwrap();
    // The second candidate is the TEST-NET-1 stand-in (loopback
    // candidates are filtered by the destination guard); the mock
    // dials the loopback echo server for it (see `TEST_ECHO_IP`).
    let valid_target = test_echo_target(echo_addr);
    let mock =
        BlackholeCapMockTarget::new(vec![blackhole_ip], Vec::new()).with_dial_redirect(echo_addr);

    let start = tokio::time::Instant::now();
    let mut stream = connect_validated_addrs_with_timeout(
        &mock,
        &[blackhole_ip, valid_target.ip()],
        echo_addr.port(),
        Duration::from_millis(900),
    )
    .await
    .expect("should fall back from blackhole IP to valid echo IP within budget");
    let elapsed = start.elapsed();

    assert!(elapsed < Duration::from_millis(900));
    stream.write_all(b"pong").await.unwrap();
    let mut buf = [0u8; 4];
    stream.read_exact(&mut buf).await.unwrap();
    assert_eq!(&buf, b"pong");
    assert_eq!(
        *mock.dialed_addrs.lock(),
        vec![
            SocketAddr::new(blackhole_ip, echo_addr.port()),
            valid_target,
        ]
    );
}

#[tokio::test]
async fn test_send_udp_to_validated_addrs_caps_and_falls_back_from_blackhole() {
    use crate::proxy::router::{MAX_CANDIDATE_IPS, send_udp_to_validated_addrs_with_timeout};

    let failing_addrs: Vec<SocketAddr> = (1..=12u8)
        .map(|octet| SocketAddr::new(IpAddr::V4(Ipv4Addr::new(198, 51, 100, octet)), 5353))
        .collect();
    let mock_cap = MockUdpFallbackSocket::new(Vec::new(), failing_addrs.clone());
    let cap_err = send_udp_to_validated_addrs_with_timeout(
        &mock_cap,
        b"pkt",
        &failing_addrs,
        Duration::from_secs(2),
    )
    .await
    .expect_err("all refused UDP targets should error");
    assert_eq!(cap_err.kind(), io::ErrorKind::ConnectionRefused);
    assert_eq!(mock_cap.sent_addrs.lock().len(), MAX_CANDIDATE_IPS);

    let blackhole_sock = SocketAddr::new("198.51.100.50".parse().unwrap(), 5353);
    let valid_sock = SocketAddr::new("203.0.113.50".parse().unwrap(), 5353);
    let mock_fb = MockUdpFallbackSocket::new(vec![blackhole_sock], Vec::new());

    let start = tokio::time::Instant::now();
    send_udp_to_validated_addrs_with_timeout(
        &mock_fb,
        b"pkt",
        &[blackhole_sock, valid_sock],
        Duration::from_millis(900),
    )
    .await
    .expect("UDP send should fall back to valid target after blackhole timeout");
    assert!(start.elapsed() < Duration::from_millis(900));
    assert_eq!(*mock_fb.sent_addrs.lock(), vec![blackhole_sock, valid_sock]);

    let all_blackhole_socks: Vec<SocketAddr> = (1..=10u8)
        .map(|octet| SocketAddr::new(IpAddr::V4(Ipv4Addr::new(198, 51, 100, octet)), 5353))
        .collect();
    let mock_bh = MockUdpFallbackSocket::new(all_blackhole_socks.clone(), Vec::new());
    let total_budget = Duration::from_millis(650);
    let bh_start = tokio::time::Instant::now();
    let bh_err = send_udp_to_validated_addrs_with_timeout(
        &mock_bh,
        b"pkt",
        &all_blackhole_socks,
        total_budget,
    )
    .await
    .expect_err("all blackhole UDP targets should time out");
    assert_eq!(bh_err.kind(), io::ErrorKind::TimedOut);
    assert!(bh_start.elapsed() < Duration::from_millis(1200));
    assert!(mock_bh.sent_addrs.lock().len() <= MAX_CANDIDATE_IPS);
}

async fn perform_socks5_greeting_and_auth(
    router: Arc<PoolRouter>,
    methods: &[u8],
    creds: Option<(&str, &str)>,
    dst: SocketAddr,
) -> (u8, Option<u8>) {
    let (client_raw, server) = tokio::io::duplex(4096);
    let server_task = tokio::spawn(async move {
        let _ = handle_socks5(server, router).await;
    });
    let mut client = client_raw;

    let mut greeting = Vec::with_capacity(2 + methods.len());
    greeting.push(SOCKS5_VERSION);
    greeting.push(u8::try_from(methods.len()).unwrap());
    greeting.extend_from_slice(methods);
    client.write_all(&greeting).await.unwrap();

    let mut g_resp = [0u8; 2];
    client.read_exact(&mut g_resp).await.unwrap();
    assert_eq!(g_resp[0], SOCKS5_VERSION);
    let chosen_method = g_resp[1];

    let auth_status = if chosen_method == METHOD_USER_PASS {
        if let Some((user, pass)) = creds {
            let mut pkt = vec![RFC1929_VERSION, u8::try_from(user.len()).unwrap()];
            pkt.extend_from_slice(user.as_bytes());
            pkt.push(u8::try_from(pass.len()).unwrap());
            pkt.extend_from_slice(pass.as_bytes());
            client.write_all(&pkt).await.unwrap();

            let mut a_resp = [0u8; 2];
            client.read_exact(&mut a_resp).await.unwrap();
            assert_eq!(a_resp[0], RFC1929_VERSION);
            if a_resp[1] != 0x00 {
                drop(client);
                let _ = server_task.await;
                return (chosen_method, Some(a_resp[1]));
            }
            Some(a_resp[1])
        } else {
            drop(client);
            let _ = server_task.await;
            return (chosen_method, None);
        }
    } else {
        None
    };

    let SocketAddr::V4(v4) = dst else {
        panic!("expected ipv4 echo listener");
    };
    let mut req = vec![SOCKS5_VERSION, 0x01, 0x00, 0x01];
    req.extend_from_slice(&v4.ip().octets());
    req.extend_from_slice(&v4.port().to_be_bytes());
    client.write_all(&req).await.unwrap();

    let mut rep = [0u8; 10];
    client.read_exact(&mut rep).await.unwrap();
    assert_eq!(rep[1], REP_SUCCESS);

    drop(client);
    let _ = server_task.await;
    (chosen_method, auth_status)
}

#[tokio::test]
async fn test_socks5_prefers_user_pass_over_no_auth_when_anonymous_allowed() {
    let echo = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let echo_addr = echo.local_addr().unwrap();
    tokio::spawn(async move {
        while let Ok((mut s, _)) = echo.accept().await {
            tokio::spawn(async move {
                let mut buf = [0u8; 16];
                let _ = s.read(&mut buf).await;
            });
        }
    });

    // 1. AuthMode::None + allow_anonymous=true: client offering [0x00, 0x02] gets 0x02 and routes to tenant.
    let target_addr = test_echo_target(echo_addr);
    let t1 = Arc::new(MockTunnelTarget::new("wgcf-001").with_dial_redirect(echo_addr));
    let t2 = Arc::new(MockTunnelTarget::new("wgcf-002").with_dial_redirect(echo_addr));
    let pool_none = Arc::new(PoolRouter::new(PoolStrategy::RoundRobin, true));
    pool_none.add_tunnel("wgcf-001", Arc::clone(&t1) as Arc<dyn ProxyTunnelTarget>);
    pool_none.add_tunnel("wgcf-002", Arc::clone(&t2) as Arc<dyn ProxyTunnelTarget>);

    let (chosen, status) = perform_socks5_greeting_and_auth(
        Arc::clone(&pool_none),
        &[METHOD_NO_AUTH, METHOD_USER_PASS],
        Some(("wgcf-002", "any")),
        target_addr,
    )
    .await;
    assert_eq!(chosen, METHOD_USER_PASS);
    assert_eq!(status, Some(0x00));
    assert_eq!(t2.tcp_conns.load(Ordering::SeqCst), 1);
    assert_eq!(t1.tcp_conns.load(Ordering::SeqCst), 0);

    // 2. Client offering only [0x00] still falls back to anonymous NO_AUTH (0x00).
    let (anon_chosen, anon_status) =
        perform_socks5_greeting_and_auth(pool_none, &[METHOD_NO_AUTH], None, target_addr).await;
    assert_eq!(anon_chosen, METHOD_NO_AUTH);
    assert_eq!(anon_status, None);
    assert_eq!(t1.tcp_conns.load(Ordering::SeqCst), 1);

    // 3. AuthMode::Global + allow_anonymous=true: offering [0x00, 0x02] picks 0x02 and validates password.
    let g1 = Arc::new(MockTunnelTarget::new("wgcf-001").with_dial_redirect(echo_addr));
    let g2 = Arc::new(MockTunnelTarget::new("wgcf-002").with_dial_redirect(echo_addr));
    let pool_global = Arc::new(
        PoolRouter::new(PoolStrategy::RoundRobin, true)
            .with_auth(AuthMode::Global, Some("secret".to_string())),
    );
    pool_global.add_tunnel("wgcf-001", Arc::clone(&g1) as Arc<dyn ProxyTunnelTarget>);
    pool_global.add_tunnel("wgcf-002", Arc::clone(&g2) as Arc<dyn ProxyTunnelTarget>);

    let (bad_chosen, bad_status) = perform_socks5_greeting_and_auth(
        Arc::clone(&pool_global),
        &[METHOD_NO_AUTH, METHOD_USER_PASS],
        Some(("wgcf-002", "wrong")),
        target_addr,
    )
    .await;
    assert_eq!(bad_chosen, METHOD_USER_PASS);
    assert_eq!(bad_status, Some(0x01));
    assert_eq!(g2.tcp_conns.load(Ordering::SeqCst), 0);

    let (ok_chosen, ok_status) = perform_socks5_greeting_and_auth(
        pool_global,
        &[METHOD_NO_AUTH, METHOD_USER_PASS],
        Some(("wgcf-002", "secret")),
        target_addr,
    )
    .await;
    assert_eq!(ok_chosen, METHOD_USER_PASS);
    assert_eq!(ok_status, Some(0x00));
    assert_eq!(g2.tcp_conns.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn test_http_forward_empty_upstream_returns_502() {
    let upstream_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let upstream_addr = upstream_listener.local_addr().unwrap();
    tokio::spawn(async move {
        if let Ok((sock, _)) = upstream_listener.accept().await {
            drop(sock);
        }
    });

    let target_addr = test_echo_target(upstream_addr);
    let router: Arc<dyn TunnelRouter> = Arc::new(SingleTunnelRouter::new(
        "direct",
        Arc::new(MockTunnelTarget::new("direct").with_dial_redirect(upstream_addr))
            as Arc<dyn ProxyTunnelTarget>,
        None,
    ));
    let (mut client, server) = tokio::io::duplex(4096);
    let server_task = tokio::spawn(async move { handle_http(server, router).await });

    let req = format!("GET http://{target_addr}/ HTTP/1.1\r\nHost: {target_addr}\r\n\r\n",);
    client.write_all(req.as_bytes()).await.unwrap();

    let mut resp = Vec::new();
    client.read_to_end(&mut resp).await.unwrap();
    let resp_str = String::from_utf8_lossy(&resp);
    assert!(
        resp_str.starts_with("HTTP/1.1 502 Bad Gateway"),
        "expected 502 Bad Gateway on empty upstream response, got: {resp_str:?}"
    );
    let _ = server_task.await;
}

#[tokio::test]
async fn test_pool_round_robin_failover_on_dead_tunnel() {
    struct DeadTunnelTarget;

    impl ProxyTunnelTarget for DeadTunnelTarget {
        fn tcp_connect<'a>(
            &'a self,
            _dst: SocketAddr,
        ) -> Pin<Box<dyn Future<Output = io::Result<DynStream>> + Send + 'a>> {
            Box::pin(async {
                Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "simulated dead tunnel",
                ))
            })
        }

        fn udp_bind(&self, _local_port: u16) -> crate::proxy::router::UdpBindFut<'_> {
            Box::pin(async { Err(io::Error::new(io::ErrorKind::TimedOut, "dead")) })
        }

        fn resolve_in_tunnel<'a>(
            &'a self,
            _domain: &'a str,
        ) -> Pin<Box<dyn Future<Output = io::Result<IpAddr>> + Send + 'a>> {
            Box::pin(async {
                Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "simulated dead DNS",
                ))
            })
        }

        fn tunnel_id(&self) -> Option<&str> {
            Some("wgcf-dead")
        }
    }

    let echo_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let echo_addr = echo_listener.local_addr().unwrap();
    tokio::spawn(async move {
        if let Ok((mut sock, _)) = echo_listener.accept().await {
            let mut buf = [0u8; 32];
            if let Ok(n) = sock.read(&mut buf).await {
                let _ = sock.write_all(&buf[..n]).await;
            }
        }
    });

    let pool = Arc::new(PoolRouter::new(PoolStrategy::RoundRobin, true));
    pool.add_tunnel("wgcf-dead", Arc::new(DeadTunnelTarget));
    let ok_target = Arc::new(MockTunnelTarget::new("wgcf-ok").with_dial_redirect(echo_addr));
    pool.add_tunnel(
        "wgcf-ok",
        Arc::clone(&ok_target) as Arc<dyn ProxyTunnelTarget>,
    );

    let (mut client, server) = tokio::io::duplex(4096);
    let router: Arc<dyn TunnelRouter> = pool;
    let server_task = tokio::spawn(async move { handle_socks5(server, router).await });

    client.write_all(&[0x05, 0x01, 0x00]).await.unwrap();
    let mut method_resp = [0u8; 2];
    client.read_exact(&mut method_resp).await.unwrap();
    assert_eq!(method_resp, [0x05, 0x00]);

    // The client names the TEST-NET-1 stand-in (loopback targets are
    // rejected by the destination guard); the mock dials the loopback
    // echo server (see `TEST_ECHO_IP`).
    let target_addr = test_echo_target(echo_addr);
    let ip_octets = match target_addr.ip() {
        IpAddr::V4(v4) => v4.octets(),
        IpAddr::V6(_) => unreachable!(),
    };
    let mut req = vec![0x05, 0x01, 0x00, 0x01];
    req.extend_from_slice(&ip_octets);
    req.extend_from_slice(&target_addr.port().to_be_bytes());
    client.write_all(&req).await.unwrap();

    let mut rep = [0u8; 10];
    client.read_exact(&mut rep).await.unwrap();
    assert_eq!(rep[1], 0x00, "expected failover to wgcf-ok to succeed");

    client.write_all(b"ping").await.unwrap();
    let mut echo = [0u8; 4];
    client.read_exact(&mut echo).await.unwrap();
    assert_eq!(&echo, b"ping");
    assert_eq!(ok_target.tcp_conns.load(Ordering::SeqCst), 1);

    drop(client);
    let _ = server_task.await;
}

#[tokio::test]
async fn test_socks5_selector_username_with_empty_password_allowed_when_anonymous() {
    let echo_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let echo_addr = echo_listener.local_addr().unwrap();
    let accept_task = tokio::spawn(async move {
        while let Ok((sock, _)) = echo_listener.accept().await {
            drop(sock);
        }
    });

    for mode in [AuthMode::None, AuthMode::PerTunnel] {
        let t1 = Arc::new(MockTunnelTarget::new("wgcf-001").with_dial_redirect(echo_addr));
        let pool = Arc::new(PoolRouter::new(PoolStrategy::RoundRobin, true).with_auth(mode, None));
        pool.add_tunnel("wgcf-001", Arc::clone(&t1) as Arc<dyn ProxyTunnelTarget>);

        let (chosen, status) = perform_socks5_greeting_and_auth(
            pool,
            &[METHOD_NO_AUTH, METHOD_USER_PASS],
            Some(("round-robin", "")),
            test_echo_target(echo_addr),
        )
        .await;
        assert_eq!(chosen, METHOD_USER_PASS);
        assert_eq!(
            status,
            Some(0x00),
            "expected round-robin@ with empty password to succeed for {mode:?}"
        );
        assert_eq!(t1.tcp_conns.load(Ordering::SeqCst), 1);
    }

    accept_task.abort();
}

/// Upstream that replies to one proxied request with the given raw bytes.
/// When `close_after` is set it closes the connection after replying;
/// otherwise it holds the connection open forever, so a proxy that
/// copies to EOF would hang instead of finishing the response.
async fn spawn_raw_upstream_server(response: Vec<u8>, close_after: bool) -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        if let Ok((mut stream, _)) = listener.accept().await {
            let mut header_buf = Vec::new();
            let mut b = [0u8; 1];
            while header_buf.len() < 8192 {
                if stream.read_exact(&mut b).await.is_err() {
                    return;
                }
                header_buf.push(b[0]);
                if header_buf.ends_with(b"\r\n\r\n") {
                    break;
                }
            }
            let _ = stream.write_all(&response).await;
            let _ = stream.flush().await;
            if close_after {
                drop(stream);
            } else {
                std::future::pending::<()>().await;
            }
        }
    });
    addr
}

fn http_forward_router(upstream_addr: SocketAddr) -> Arc<dyn TunnelRouter> {
    Arc::new(SingleTunnelRouter::new(
        "fwd",
        Arc::new(MockTunnelTarget::new("fwd").with_dial_redirect(upstream_addr))
            as Arc<dyn ProxyTunnelTarget>,
        None,
    ))
}

async fn http_forward_get(
    upstream_addr: SocketAddr,
) -> (
    tokio::io::DuplexStream,
    tokio::task::JoinHandle<io::Result<()>>,
) {
    let router = http_forward_router(upstream_addr);
    let (mut client, server) = tokio::io::duplex(65536);
    let task = tokio::spawn(async move { handle_http(server, router).await });
    let target_addr = test_echo_target(upstream_addr);
    let req = format!("GET http://{target_addr}/ HTTP/1.1\r\nHost: {target_addr}\r\n\r\n");
    client.write_all(req.as_bytes()).await.unwrap();
    (client, task)
}

#[tokio::test]
async fn test_http_forward_enforces_content_length_and_closes() {
    // Upstream declares 5 body bytes but sends more, then holds the
    // connection open: the client must receive exactly the 5 declared
    // bytes and then EOF — never the trailing bytes (audit run-1,
    // `src/proxy/http.rs:forward_upstream_response-verbatim-no-framing-validation`).
    let upstream = spawn_raw_upstream_server(
        b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 5\r\n\r\nHELLOEXTRA-PIPELINED-BYTES"
            .to_vec(),
        false,
    )
    .await;
    let (mut client, task) = http_forward_get(upstream).await;
    let mut resp = Vec::new();
    tokio::time::timeout(Duration::from_secs(5), client.read_to_end(&mut resp))
        .await
        .expect("proxy must finish the first response without waiting for upstream close")
        .unwrap();
    assert_eq!(
        resp,
        b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 5\r\n\r\nHELLO"
    );
    let _ = task.await;
}

#[tokio::test]
async fn test_http_forward_chunked_stops_at_terminal_chunk() {
    // Chunked upstream followed by trailing bytes: only the framed
    // chunks reach the client, then the connection closes.
    let upstream = spawn_raw_upstream_server(
        b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nHELLO\r\n0\r\n\r\nTRAILING"
            .to_vec(),
        false,
    )
    .await;
    let (mut client, task) = http_forward_get(upstream).await;
    let mut resp = Vec::new();
    tokio::time::timeout(Duration::from_secs(5), client.read_to_end(&mut resp))
        .await
        .expect("proxy must finish the chunked response")
        .unwrap();
    assert_eq!(
        resp,
        b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nHELLO\r\n0\r\n\r\n"
    );
    let _ = task.await;
}

#[tokio::test]
async fn test_http_forward_close_delimited_body_until_close() {
    // No framing at all: the body runs until the upstream closes.
    let upstream = spawn_raw_upstream_server(
        b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\nBODY-NO-LENGTH".to_vec(),
        true,
    )
    .await;
    let (mut client, task) = http_forward_get(upstream).await;
    let mut resp = Vec::new();
    tokio::time::timeout(Duration::from_secs(5), client.read_to_end(&mut resp))
        .await
        .expect("proxy must finish the close-delimited response")
        .unwrap();
    assert_eq!(
        resp,
        b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\nBODY-NO-LENGTH"
    );
    let _ = task.await;
}

#[tokio::test]
async fn test_http_forward_invalid_response_framing_returns_502() {
    let upstream = spawn_raw_upstream_server(b"GARBAGE\r\n\r\n".to_vec(), true).await;
    let (mut client, task) = http_forward_get(upstream).await;
    let mut resp = Vec::new();
    tokio::time::timeout(Duration::from_secs(5), client.read_to_end(&mut resp))
        .await
        .expect("proxy must answer a malformed upstream response")
        .unwrap();
    assert!(
        String::from_utf8_lossy(&resp).starts_with("HTTP/1.1 502 Bad Gateway"),
        "malformed upstream framing must return 502, got: {}",
        String::from_utf8_lossy(&resp)
    );
    let _ = task.await;
}

#[test]
fn test_parse_response_head_framing() {
    let (status, framing) =
        parse_response_head(b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\n").unwrap();
    assert_eq!(status, 200);
    assert!(matches!(framing, ResponseBodyFraming::ContentLength(5)));

    let (status, framing) =
        parse_response_head(b"HTTP/1.0 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n").unwrap();
    assert_eq!(status, 200);
    assert!(matches!(framing, ResponseBodyFraming::Chunked));

    let (status, framing) =
        parse_response_head(b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\n").unwrap();
    assert_eq!(status, 200);
    assert!(matches!(framing, ResponseBodyFraming::UntilClose));

    let (_, framing) =
        parse_response_head(b"HTTP/1.1 204 No Content\r\nContent-Length: 9\r\n\r\n").unwrap();
    assert!(matches!(framing, ResponseBodyFraming::ContentLength(0)));

    assert!(parse_response_head(b"GARBAGE\r\n\r\n").is_err());
    assert!(
        parse_response_head(b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\nContent-Length: 6\r\n\r\n")
            .is_err()
    );
    assert!(
        parse_response_head(
            b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\nTransfer-Encoding: chunked\r\n\r\n"
        )
        .is_err()
    );
    assert!(parse_response_head(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: gzip\r\n\r\n").is_err());
}

#[tokio::test]
async fn test_copy_limited_idle_enforces_size_and_idle() {
    // Size bound: the copy stops at exactly the limit even when the
    // reader offers more, so a never-ending stream cannot hold the
    // session past the bound.
    let (mut w, mut r) = tokio::io::duplex(64);
    w.write_all(b"0123456789").await.unwrap();
    drop(w);
    let mut out = Vec::new();
    let n = copy_limited_idle(&mut r, &mut out, 5, Duration::from_secs(5))
        .await
        .unwrap();
    assert_eq!((n, out), (5, b"01234".to_vec()));

    // Idle timeout: a stalled reader fails after the deadline.
    let (_w, mut r) = tokio::io::duplex(64);
    let mut out = Vec::new();
    let err = copy_limited_idle(&mut r, &mut out, 1024, Duration::from_millis(50))
        .await
        .expect_err("idle copy must time out");
    assert_eq!(err.kind(), io::ErrorKind::TimedOut);

    // Happy path: all bytes copied until EOF.
    let (mut w, mut r) = tokio::io::duplex(64);
    w.write_all(b"abc").await.unwrap();
    drop(w);
    let mut out = Vec::new();
    let n = copy_limited_idle(&mut r, &mut out, 1024, Duration::from_secs(5))
        .await
        .unwrap();
    assert_eq!((n, out), (3, b"abc".to_vec()));
}

#[test]
fn test_expected_udp_replies_rejects_unexpected_source() {
    // Only replies to destinations this session asked for are
    // expected; anything else (e.g. a spoofed source) is dropped
    // (audit run-1, `socks5-udp-relay-unvalidated-tunnel-reply-source`).
    let mut expected = ExpectedUdpReplies::default();
    let server: SocketAddr = "192.0.2.1:1234".parse().unwrap();
    let stranger: SocketAddr = "192.0.2.99:1234".parse().unwrap();
    assert!(!expected.is_expected(server, b"hello"));
    expected.note_sent(server, b"hello");
    assert!(expected.is_expected(server, b"reply"));
    assert!(!expected.is_expected(stranger, b"reply"));

    // DNS: a reply from the queried server must carry an outstanding
    // TXID, which is then consumed; a wrong TXID or a replay is dropped.
    let dns_server: SocketAddr = "8.8.8.8:53".parse().unwrap();
    let mut query = [0u8; 12];
    query[..2].copy_from_slice(&0x1234u16.to_be_bytes());
    expected.note_sent(dns_server, &query);
    let mut answer = [0u8; 12];
    answer[..2].copy_from_slice(&0x1234u16.to_be_bytes());
    assert!(expected.is_expected(dns_server, &answer));
    assert!(!expected.is_expected(dns_server, &answer));
    let mut wrong_txid = [0u8; 12];
    wrong_txid[..2].copy_from_slice(&0x5678u16.to_be_bytes());
    expected.note_sent(dns_server, &query);
    assert!(!expected.is_expected(dns_server, &wrong_txid));
}

#[test]
fn test_udp_first_datagram_grace_sleep() {
    use crate::proxy::socks5::udp_first_datagram_grace_sleep;
    // Pinned sessions never take the grace branch.
    let deadline = tokio::time::Instant::now() + Duration::from_secs(30);
    assert_eq!(
        udp_first_datagram_grace_sleep(true, deadline),
        Duration::from_secs(3600)
    );
    // Unpinned: the remaining time until the deadline.
    let remaining = udp_first_datagram_grace_sleep(false, deadline);
    assert!(remaining > Duration::ZERO && remaining <= Duration::from_secs(30));
    // Unpinned past the deadline: fire immediately.
    let past = tokio::time::Instant::now() - Duration::from_secs(1);
    assert_eq!(udp_first_datagram_grace_sleep(false, past), Duration::ZERO);
}

// -----------------------------------------------------------------------------
// Zero-Response Retry Tests
// -----------------------------------------------------------------------------

#[tokio::test]
async fn test_retry_copy_idle_timeout() {
    use crate::proxy::{CopyEndKind, copy_bidirectional_with_zero_response_retry};
    let (mut c1, mut s1) = tokio::io::duplex(1024);
    let (mut c2, s2) = tokio::io::duplex(1024);
    let s2: DynStream = Box::new(s2);
    let relay = tokio::spawn(async move {
        let mut tunnel_id = None;
        copy_bidirectional_with_zero_response_retry(
            &mut s1,
            s2,
            Duration::from_millis(100),
            None,
            &mut tunnel_id,
        )
        .await
    });
    // Traffic flows both ways through the relay.
    c1.write_all(b"ping").await.unwrap();
    let mut buf = [0u8; 4];
    c2.read_exact(&mut buf).await.unwrap();
    assert_eq!(&buf, b"ping");
    c2.write_all(b"pong").await.unwrap();
    c1.read_exact(&mut buf).await.unwrap();
    assert_eq!(&buf, b"pong");
    // Then an idle session ends on its own instead of hanging forever
    // (audit run-1, `wpmulti/proxy:established-connect-no-idle-timeout`).
    let outcome = tokio::time::timeout(Duration::from_secs(2), relay)
        .await
        .expect("idle relay must finish")
        .expect("relay task panicked");
    assert_eq!(outcome.kind, CopyEndKind::IdleTimeout);
    let (client_bytes, tunnel_bytes) = outcome.result.expect("idle relay must end cleanly");
    assert_eq!((client_bytes, tunnel_bytes), (4, 4));
}

#[tokio::test]
async fn test_blackhole_session_ends_promptly_when_client_gives_up() {
    use crate::proxy::{
        CLIENT_ABORT_SILENCE_THRESHOLD, CopyEndKind, copy_bidirectional_with_zero_response_retry,
    };

    // A tunnel that reads the request and then stays silent forever
    // (never a byte back, never an EOF): the fix8 blackhole shape.
    // `usize::MAX` keeps the server reading past the request instead
    // of closing after it.
    let blackhole_addr = spawn_blackhole_tcp_server(usize::MAX).await;
    let tunnel: DynStream = Box::new(TcpStream::connect(blackhole_addr).await.unwrap());

    let (mut client, mut server) = tokio::io::duplex(2048);
    // The idle timeout is far above the silence threshold, so only
    // the prompt end can finish this session in time.
    let idle_timeout = Duration::from_secs(30);
    let mut tunnel_id = None;
    let (outcome, ()) = tokio::time::timeout(Duration::from_secs(10), async {
        tokio::join!(
            copy_bidirectional_with_zero_response_retry(
                &mut server,
                tunnel,
                idle_timeout,
                None,
                &mut tunnel_id,
            ),
            async move {
                client.write_all(b"hello").await.unwrap();
                // Wait past the silence threshold, then give up:
                // the client half-closes when it drops here, as
                // curl does at its 15s timeout.
                tokio::time::sleep(CLIENT_ABORT_SILENCE_THRESHOLD + Duration::from_millis(500))
                    .await;
            },
        )
    })
    .await
    .expect("blackhole session must end promptly, not at the idle timeout");
    assert_eq!(outcome.kind, CopyEndKind::ClientAborted);
    let (client_bytes, tunnel_bytes) = outcome.result.expect("session must end cleanly");
    assert_eq!((client_bytes, tunnel_bytes), (5, 0));
    assert!(
        outcome.duration >= CLIENT_ABORT_SILENCE_THRESHOLD,
        "session must have run past the silence threshold, got {:?}",
        outcome.duration
    );
}

#[tokio::test]
async fn test_blackhole_session_ends_promptly_with_real_tcp_client() {
    use crate::proxy::{
        CLIENT_ABORT_SILENCE_THRESHOLD, CopyEndKind, copy_bidirectional_with_zero_response_retry,
    };

    // Same blackhole shape as the duplex test, but the client side is
    // a real loopback TCP pair: production curl closes a real socket,
    // and the copy must observe that close the same way it observes
    // a dropped duplex half. (fix10 repro: the duplex test passes
    // while production sessions linger to the idle timeout.)
    let blackhole_addr = spawn_blackhole_tcp_server(usize::MAX).await;
    let tunnel: DynStream = Box::new(TcpStream::connect(blackhole_addr).await.unwrap());

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let client_addr = listener.local_addr().unwrap();
    let connect = tokio::spawn(async move { TcpStream::connect(client_addr).await.unwrap() });
    let (mut server, _) = listener.accept().await.unwrap();
    let mut client = connect.await.unwrap();

    // The idle timeout is far above the silence threshold, so only
    // the prompt end can finish this session in time.
    let idle_timeout = Duration::from_secs(30);
    let mut tunnel_id = None;
    let (outcome, ()) = tokio::time::timeout(Duration::from_secs(10), async {
        tokio::join!(
            copy_bidirectional_with_zero_response_retry(
                &mut server,
                tunnel,
                idle_timeout,
                None,
                &mut tunnel_id,
            ),
            async move {
                client.write_all(b"hello").await.unwrap();
                // Wait past the silence threshold, then give up:
                // drop the client socket the way curl does at its
                // 15s timeout.
                tokio::time::sleep(CLIENT_ABORT_SILENCE_THRESHOLD + Duration::from_millis(500))
                    .await;
                drop(client);
            },
        )
    })
    .await
    .expect("blackhole session must end promptly, not at the idle timeout");
    assert_eq!(outcome.kind, CopyEndKind::ClientAborted);
    let (client_bytes, tunnel_bytes) = outcome.result.expect("session must end cleanly");
    assert_eq!((client_bytes, tunnel_bytes), (5, 0));
    assert!(
        outcome.duration >= CLIENT_ABORT_SILENCE_THRESHOLD,
        "session must have run past the silence threshold, got {:?}",
        outcome.duration
    );
}

#[tokio::test]
async fn test_blackhole_session_ends_promptly_via_socks_handler() {
    use crate::proxy::CLIENT_ABORT_SILENCE_THRESHOLD;
    use crate::proxy::replay::REPLAY_TEST_LOCK;

    // fix11: this test sends an eligible GET through the full
    // handler and waits past the 2.5 s silence timer, so it fires
    // a silence replay (which finds no second tunnel and is
    // suppressed as NoTunnel). It asserts no metrics, but it holds
    // the replay lock so its counter increments cannot land inside
    // another test's delta window.
    let _replay_guard = REPLAY_TEST_LOCK.lock().await;

    // Full production path: real TCP client -> SOCKS5 handshake ->
    // mock tunnel dials a real blackhole TCP server -> copy with
    // retry enabled (as production does). The client closes after
    // 3s of silence; the handler task must finish promptly, not at
    // the idle timeout. (fix10: isolates the handler path + retry
    // from the copy loop, which already passes with a real TCP
    // client.)
    let blackhole_addr = spawn_blackhole_tcp_server(usize::MAX).await;
    let t1 = Arc::new(MockTunnelTarget::new("bh-1").with_dial_redirect(blackhole_addr));
    let pool = Arc::new(
        PoolRouter::new(PoolStrategy::RoundRobin, true).with_auth(AuthMode::PerTunnel, None),
    );
    pool.add_tunnel("bh-1", Arc::clone(&t1) as Arc<dyn ProxyTunnelTarget>);
    let router: Arc<dyn TunnelRouter> = pool;

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let proxy_addr = listener.local_addr().unwrap();
    let handler = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        handle_socks5(stream, router).await
    });

    // Raw SOCKS5 client (what curl does at the socket level).
    let mut client = TcpStream::connect(proxy_addr).await.unwrap();
    client
        .write_all(&[SOCKS5_VERSION, 1, METHOD_USER_PASS])
        .await
        .unwrap();
    let mut g_resp = [0u8; 2];
    client.read_exact(&mut g_resp).await.unwrap();
    assert_eq!(g_resp, [SOCKS5_VERSION, METHOD_USER_PASS]);

    let mut auth_req = vec![RFC1929_VERSION, 4];
    auth_req.extend_from_slice(b"bh-1");
    auth_req.push(0);
    client.write_all(&auth_req).await.unwrap();
    let mut a_resp = [0u8; 2];
    client.read_exact(&mut a_resp).await.unwrap();
    assert_eq!(a_resp, [RFC1929_VERSION, 0x00]);

    // CONNECT 192.0.2.1:80 (TEST-NET-1, passes the destination guard).
    let mut cmd = vec![SOCKS5_VERSION, CMD_CONNECT, 0x00, ATYP_IPV4];
    cmd.extend_from_slice(&[192, 0, 2, 1]);
    cmd.extend_from_slice(&80u16.to_be_bytes());
    client.write_all(&cmd).await.unwrap();
    let mut reply = [0u8; 10];
    client.read_exact(&mut reply).await.unwrap();
    assert_eq!(reply[0], SOCKS5_VERSION);
    assert_eq!(
        reply[1], REP_SUCCESS,
        "grant must succeed, got 0x{:02X}",
        reply[1]
    );

    // Send the request, wait past the silence threshold, then give
    // up the way curl does at its 15s timeout.
    client
        .write_all(b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")
        .await
        .unwrap();
    tokio::time::sleep(CLIENT_ABORT_SILENCE_THRESHOLD + Duration::from_millis(500)).await;
    drop(client);

    // The handler must finish promptly (client gave up), not at the
    // 300s idle timeout. 10s bound keeps the test fast while leaving
    // ample margin over the 3s silence.
    let joined = tokio::time::timeout(Duration::from_secs(10), handler)
        .await
        .expect("handler must end promptly after the client gives up");
    let result = joined.expect("handler task must not panic");
    assert!(result.is_ok(), "handler must end cleanly, got {result:?}");
}

#[tokio::test]
async fn test_zero_response_retry_retries_through_different_tunnel() {
    use crate::proxy::replay::{REPLAY_TEST_LOCK, replay_metrics, reset_replay_state_for_tests};
    use crate::proxy::router::connect_via_router;
    use crate::proxy::{
        CopyEndKind, ZeroResponseRetry, copy_bidirectional_with_zero_response_retry,
    };

    // fix11: the replayed request must be a positively identified
    // safe HTTP GET (the old opaque "retry me" is no longer
    // replayed once bytes were sent). The silence replay must not
    // also fire: fix5 wins the shared token, and the epoch ends
    // long before the 2.5 s timer.
    let _replay_guard = REPLAY_TEST_LOCK.lock().await;
    reset_replay_state_for_tests();

    let msg = b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n";
    let blackhole_addr = spawn_blackhole_tcp_server(msg.len()).await;
    let echo_addr = spawn_echo_tcp_server().await;
    let target = TargetAddr::Ip(test_echo_target(echo_addr));

    let pool = Arc::new(PoolRouter::new(PoolStrategy::RoundRobin, true));
    pool.add_tunnel(
        "dead-1",
        Arc::new(MockTunnelTarget::new("dead-1").with_dial_redirect(blackhole_addr)),
    );
    pool.add_tunnel(
        "alive-1",
        Arc::new(MockTunnelTarget::new("alive-1").with_dial_redirect(echo_addr)),
    );
    let router: Arc<dyn TunnelRouter> = pool;
    let selector = TunnelSelector::DefaultPool;

    // First dial lands on the blackhole (RoundRobin starts at index 0).
    let (first_stream, first_id, _) = connect_via_router(&router, &selector, &target, None, None)
        .await
        .expect("first dial must succeed");
    assert_eq!(first_id.as_deref(), Some("dead-1"));

    let (mut client, mut server) = tokio::io::duplex(2048);
    let retry = ZeroResponseRetry::new(&router, &selector, &target, None, "SOCKS5", Vec::new());
    let (relay_out, echo_buf) = tokio::time::timeout(Duration::from_secs(5), async {
        tokio::join!(
            async move {
                let mut tunnel_id = first_id;
                let result = copy_bidirectional_with_zero_response_retry(
                    &mut server,
                    first_stream,
                    Duration::from_millis(500),
                    Some(retry),
                    &mut tunnel_id,
                )
                .await;
                (result, tunnel_id)
            },
            async {
                client.write_all(msg).await.unwrap();
                // The request went to the blackhole first (no reply),
                // was retried through the echo tunnel, and comes back.
                let mut echo_buf = vec![0u8; msg.len()];
                client.read_exact(&mut echo_buf).await.unwrap();
                echo_buf
            },
        )
    })
    .await
    .expect("test must finish within 5s");
    assert_eq!(&echo_buf, msg);

    let (result, tunnel_id) = relay_out;
    let (client_bytes, tunnel_bytes) = result.result.expect("relay must end cleanly");
    assert_eq!(result.kind, CopyEndKind::IdleTimeout);
    assert_eq!(tunnel_id.as_deref(), Some("alive-1"));
    // The replayed prefix is counted once, when the client first sent it.
    assert_eq!(
        (client_bytes, tunnel_bytes),
        (msg.len() as u64, msg.len() as u64)
    );
    // The shared post-send token went to fix5, not to the silence
    // replay: one replay per chain, and the timer never fired.
    let metrics = replay_metrics();
    assert_eq!(metrics.claimed_fix5.load(Ordering::Relaxed), 1);
    assert_eq!(metrics.claimed_silence.load(Ordering::Relaxed), 0);
    assert_eq!(metrics.silence_trigger.load(Ordering::Relaxed), 0);
}

#[tokio::test]
async fn test_zero_response_retry_skips_when_prefix_overflows_cap() {
    use crate::proxy::router::connect_via_router;
    use crate::proxy::{
        CopyEndKind, ZERO_RESPONSE_RETRY_PREFIX_CAP, ZeroResponseRetry,
        copy_bidirectional_with_zero_response_retry,
    };

    let payload_len = ZERO_RESPONSE_RETRY_PREFIX_CAP + 1024;
    let blackhole_addr = spawn_blackhole_tcp_server(payload_len).await;
    let echo_addr = spawn_echo_tcp_server().await;
    let target = TargetAddr::Ip(test_echo_target(echo_addr));

    let pool = Arc::new(PoolRouter::new(PoolStrategy::RoundRobin, true));
    pool.add_tunnel(
        "dead-1",
        Arc::new(MockTunnelTarget::new("dead-1").with_dial_redirect(blackhole_addr)),
    );
    pool.add_tunnel(
        "alive-1",
        Arc::new(MockTunnelTarget::new("alive-1").with_dial_redirect(echo_addr)),
    );
    let router: Arc<dyn TunnelRouter> = pool;
    let selector = TunnelSelector::DefaultPool;

    let (first_stream, first_id, _) = connect_via_router(&router, &selector, &target, None, None)
        .await
        .expect("first dial must succeed");
    assert_eq!(first_id.as_deref(), Some("dead-1"));

    let (mut client, mut server) = tokio::io::duplex(8192);
    let retry = ZeroResponseRetry::new(&router, &selector, &target, None, "SOCKS5", Vec::new());
    let payload = vec![0xABu8; payload_len];
    let (relay_out, ()) = tokio::time::timeout(Duration::from_secs(10), async {
        tokio::join!(
            async move {
                let mut tunnel_id = first_id;
                let result = copy_bidirectional_with_zero_response_retry(
                    &mut server,
                    first_stream,
                    Duration::from_millis(500),
                    Some(retry),
                    &mut tunnel_id,
                )
                .await;
                (result, tunnel_id)
            },
            async {
                // The write blocks until the relay drains it; the
                // blackhole consumes it all, then closes with no reply.
                client.write_all(&payload).await.unwrap();
                // No echo may arrive: the session must end with no
                // response bytes, not a retried echo.
                let mut one = [0u8; 1];
                let n = client.read(&mut one).await.unwrap();
                assert_eq!(
                    n, 0,
                    "no response bytes must arrive when the retry is skipped"
                );
            },
        )
    })
    .await
    .expect("test must finish within 10s");
    let (result, tunnel_id) = relay_out;
    let (client_bytes, tunnel_bytes) = result.result.expect("relay must end cleanly");
    assert_eq!(result.kind, CopyEndKind::TunnelClosed);
    assert_eq!(tunnel_id.as_deref(), Some("dead-1"));
    assert_eq!(client_bytes, payload_len as u64);
    assert_eq!(tunnel_bytes, 0);
}

#[tokio::test]
async fn test_zero_response_retry_no_retry_when_response_received() {
    use crate::proxy::router::connect_via_router;
    use crate::proxy::{
        CopyEndKind, ZeroResponseRetry, copy_bidirectional_with_zero_response_retry,
    };

    let msg = b"hello";
    let one_byte_addr = spawn_one_byte_tcp_server().await;
    let echo_addr = spawn_echo_tcp_server().await;
    let target = TargetAddr::Ip(test_echo_target(echo_addr));

    let pool = Arc::new(PoolRouter::new(PoolStrategy::RoundRobin, true));
    pool.add_tunnel(
        "one-byte-1",
        Arc::new(MockTunnelTarget::new("one-byte-1").with_dial_redirect(one_byte_addr)),
    );
    pool.add_tunnel(
        "alive-1",
        Arc::new(MockTunnelTarget::new("alive-1").with_dial_redirect(echo_addr)),
    );
    let router: Arc<dyn TunnelRouter> = pool;
    let selector = TunnelSelector::DefaultPool;

    let (first_stream, first_id, _) = connect_via_router(&router, &selector, &target, None, None)
        .await
        .expect("first dial must succeed");
    assert_eq!(first_id.as_deref(), Some("one-byte-1"));

    let (mut client, mut server) = tokio::io::duplex(2048);
    let retry = ZeroResponseRetry::new(&router, &selector, &target, None, "SOCKS5", Vec::new());
    let (relay_out, first_byte) = tokio::time::timeout(Duration::from_secs(5), async {
        tokio::join!(
            async move {
                let mut tunnel_id = first_id;
                let result = copy_bidirectional_with_zero_response_retry(
                    &mut server,
                    first_stream,
                    Duration::from_millis(500),
                    Some(retry),
                    &mut tunnel_id,
                )
                .await;
                (result, tunnel_id)
            },
            async {
                client.write_all(msg).await.unwrap();
                // Exactly one response byte, then EOF — the session
                // must NOT be retried (a response was received).
                let mut buf = [0u8; 1];
                client.read_exact(&mut buf).await.unwrap();
                buf[0]
            },
        )
    })
    .await
    .expect("test must finish within 5s");
    assert_eq!(first_byte, b'X');
    let (result, tunnel_id) = relay_out;
    let (client_bytes, tunnel_bytes) = result.result.expect("relay must end cleanly");
    assert_eq!(result.kind, CopyEndKind::TunnelClosed);
    assert_eq!(tunnel_id.as_deref(), Some("one-byte-1"));
    assert_eq!((client_bytes, tunnel_bytes), (msg.len() as u64, 1));
}

#[tokio::test]
async fn test_zero_response_retry_retries_after_reset() {
    use crate::proxy::replay::{REPLAY_TEST_LOCK, replay_metrics, reset_replay_state_for_tests};
    use crate::proxy::router::connect_via_router;
    use crate::proxy::{
        CopyEndKind, ZeroResponseRetry, copy_bidirectional_with_zero_response_retry,
    };

    // fix11: the replayed request must be a positively identified
    // safe HTTP GET (the old opaque "retry me" is no longer
    // replayed once bytes were sent). fix5 wins the shared token;
    // the silence timer never fires.
    let _replay_guard = REPLAY_TEST_LOCK.lock().await;
    reset_replay_state_for_tests();

    let msg = b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n";
    let reset_addr = spawn_reset_tcp_server().await;
    let echo_addr = spawn_echo_tcp_server().await;
    let target = TargetAddr::Ip(test_echo_target(echo_addr));

    let pool = Arc::new(PoolRouter::new(PoolStrategy::RoundRobin, true));
    pool.add_tunnel(
        "reset-1",
        Arc::new(MockTunnelTarget::new("reset-1").with_dial_redirect(reset_addr)),
    );
    pool.add_tunnel(
        "alive-1",
        Arc::new(MockTunnelTarget::new("alive-1").with_dial_redirect(echo_addr)),
    );
    let router: Arc<dyn TunnelRouter> = pool;
    let selector = TunnelSelector::DefaultPool;

    // First dial lands on the reset server (RoundRobin starts at index 0).
    let (first_stream, first_id, _) = connect_via_router(&router, &selector, &target, None, None)
        .await
        .expect("first dial must succeed");
    assert_eq!(first_id.as_deref(), Some("reset-1"));

    let (mut client, mut server) = tokio::io::duplex(2048);
    let retry = ZeroResponseRetry::new(&router, &selector, &target, None, "SOCKS5", Vec::new());
    let (relay_out, echo_buf) = tokio::time::timeout(Duration::from_secs(5), async {
        tokio::join!(
            async move {
                let mut tunnel_id = first_id;
                let result = copy_bidirectional_with_zero_response_retry(
                    &mut server,
                    first_stream,
                    Duration::from_millis(500),
                    Some(retry),
                    &mut tunnel_id,
                )
                .await;
                (result, tunnel_id)
            },
            async {
                client.write_all(msg).await.unwrap();
                // The request hit a reset with zero response bytes,
                // was retried through the echo tunnel, and comes back.
                let mut echo_buf = vec![0u8; msg.len()];
                client.read_exact(&mut echo_buf).await.unwrap();
                echo_buf
            },
        )
    })
    .await
    .expect("test must finish within 5s");
    assert_eq!(&echo_buf, msg);

    let (result, tunnel_id) = relay_out;
    let (client_bytes, tunnel_bytes) = result.result.expect("relay must end cleanly");
    assert_eq!(result.kind, CopyEndKind::IdleTimeout);
    assert_eq!(tunnel_id.as_deref(), Some("alive-1"));
    assert_eq!(
        (client_bytes, tunnel_bytes),
        (msg.len() as u64, msg.len() as u64)
    );
    // The shared post-send token went to fix5, not to the silence
    // replay: one replay per chain, and the timer never fired.
    let metrics = replay_metrics();
    assert_eq!(metrics.claimed_fix5.load(Ordering::Relaxed), 1);
    assert_eq!(metrics.claimed_silence.load(Ordering::Relaxed), 0);
    assert_eq!(metrics.silence_trigger.load(Ordering::Relaxed), 0);
}

#[tokio::test]
async fn test_zero_response_retry_retries_after_reset_large_prefix() {
    use crate::proxy::replay::{REPLAY_TEST_LOCK, replay_metrics, reset_replay_state_for_tests};
    use crate::proxy::router::connect_via_router;
    use crate::proxy::{
        CopyEndKind, ZeroResponseRetry, copy_bidirectional_with_zero_response_retry,
    };

    // fix11 rework: this used to assert that a 32 KiB opaque payload
    // is retried after a reset. The tightened fix5 only replays a
    // request when no app byte was written upstream, or when it is
    // a positively identified safe HTTP GET — so an opaque payload
    // whose bytes were all written to the tunnel must NOT be
    // retried. The blackhole reads the whole payload (every byte is
    // written upstream, deterministically) and then closes with zero
    // response bytes, so the session must end as TunnelClosed with
    // no echo and a suppressed{ineligible} count.
    let _replay_guard = REPLAY_TEST_LOCK.lock().await;
    reset_replay_state_for_tests();

    // 32 KiB fits the 64 KiB replay cap, so the cap is not what
    // blocks the retry here — the opaque content is.
    let payload_len = 32 * 1024;
    let payload: Vec<u8> = (0..payload_len).map(|i| (i % 251) as u8).collect();
    let blackhole_addr = spawn_blackhole_tcp_server(payload_len).await;
    let echo_addr = spawn_echo_tcp_server().await;
    let target = TargetAddr::Ip(test_echo_target(echo_addr));

    let pool = Arc::new(PoolRouter::new(PoolStrategy::RoundRobin, true));
    pool.add_tunnel(
        "dead-1",
        Arc::new(MockTunnelTarget::new("dead-1").with_dial_redirect(blackhole_addr)),
    );
    pool.add_tunnel(
        "alive-1",
        Arc::new(MockTunnelTarget::new("alive-1").with_dial_redirect(echo_addr)),
    );
    let router: Arc<dyn TunnelRouter> = pool;
    let selector = TunnelSelector::DefaultPool;

    let (first_stream, first_id, _) = connect_via_router(&router, &selector, &target, None, None)
        .await
        .expect("first dial must succeed");
    assert_eq!(first_id.as_deref(), Some("dead-1"));

    let (mut client, mut server) = tokio::io::duplex(2048);
    let retry = ZeroResponseRetry::new(&router, &selector, &target, None, "SOCKS5", Vec::new());
    let (relay_out, ()) = tokio::time::timeout(Duration::from_secs(10), async {
        tokio::join!(
            async move {
                let mut tunnel_id = first_id;
                let result = copy_bidirectional_with_zero_response_retry(
                    &mut server,
                    first_stream,
                    Duration::from_millis(500),
                    Some(retry),
                    &mut tunnel_id,
                )
                .await;
                (result, tunnel_id)
            },
            async {
                // The blackhole consumes the whole payload, then
                // closes with no reply. No echo may arrive: the
                // session must end with no response bytes, not a
                // retried echo.
                client.write_all(&payload).await.unwrap();
                let mut one = [0u8; 1];
                let n = client.read(&mut one).await.unwrap();
                assert_eq!(
                    n, 0,
                    "no response bytes must arrive when the retry is blocked"
                );
            },
        )
    })
    .await
    .expect("test must finish within 10s");

    let (result, tunnel_id) = relay_out;
    let (client_bytes, tunnel_bytes) = result.result.expect("relay must end cleanly");
    assert_eq!(result.kind, CopyEndKind::TunnelClosed);
    assert_eq!(tunnel_id.as_deref(), Some("dead-1"));
    assert_eq!(client_bytes, payload_len as u64);
    assert_eq!(tunnel_bytes, 0);
    // The retry was blocked as ineligible, not spent: no token was
    // claimed by either replay path.
    let metrics = replay_metrics();
    assert_eq!(metrics.suppressed_ineligible.load(Ordering::Relaxed), 1);
    assert_eq!(metrics.claimed_fix5.load(Ordering::Relaxed), 0);
    assert_eq!(metrics.claimed_silence.load(Ordering::Relaxed), 0);
}

#[tokio::test]
async fn test_zero_response_retry_no_retry_after_reset_with_response() {
    use crate::proxy::router::connect_via_router;
    use crate::proxy::{
        CopyEndKind, ZeroResponseRetry, copy_bidirectional_with_zero_response_retry,
    };

    let msg = b"hello";
    let reset_addr = spawn_reset_after_response_tcp_server().await;
    let echo_addr = spawn_echo_tcp_server().await;
    let target = TargetAddr::Ip(test_echo_target(echo_addr));

    let pool = Arc::new(PoolRouter::new(PoolStrategy::RoundRobin, true));
    pool.add_tunnel(
        "reset-1",
        Arc::new(MockTunnelTarget::new("reset-1").with_dial_redirect(reset_addr)),
    );
    pool.add_tunnel(
        "alive-1",
        Arc::new(MockTunnelTarget::new("alive-1").with_dial_redirect(echo_addr)),
    );
    let router: Arc<dyn TunnelRouter> = pool;
    let selector = TunnelSelector::DefaultPool;

    let (first_stream, first_id, _) = connect_via_router(&router, &selector, &target, None, None)
        .await
        .expect("first dial must succeed");
    assert_eq!(first_id.as_deref(), Some("reset-1"));

    let (mut client, mut server) = tokio::io::duplex(2048);
    let retry = ZeroResponseRetry::new(&router, &selector, &target, None, "SOCKS5", Vec::new());
    let (relay_out, first_byte) = tokio::time::timeout(Duration::from_secs(5), async {
        tokio::join!(
            async move {
                let mut tunnel_id = first_id;
                let result = copy_bidirectional_with_zero_response_retry(
                    &mut server,
                    first_stream,
                    Duration::from_millis(500),
                    Some(retry),
                    &mut tunnel_id,
                )
                .await;
                (result, tunnel_id)
            },
            async {
                client.write_all(msg).await.unwrap();
                // Exactly one response byte, then a reset — the
                // session must NOT be retried (a response was received).
                let mut buf = [0u8; 1];
                client.read_exact(&mut buf).await.unwrap();
                buf[0]
            },
        )
    })
    .await
    .expect("test must finish within 5s");
    assert_eq!(first_byte, b'X');
    let (result, tunnel_id) = relay_out;
    assert_eq!(tunnel_id.as_deref(), Some("reset-1"));
    let err = result
        .result
        .expect_err("relay must end with the reset error, not a retry");
    assert_eq!(result.kind, CopyEndKind::Failed);
    assert_eq!(err.kind(), io::ErrorKind::ConnectionReset);
}

#[tokio::test]
async fn test_connect_via_router_excludes_tunnel() {
    use crate::proxy::router::{RouterConnectError, connect_via_router};
    let echo_addr = spawn_echo_tcp_server().await;
    let target = TargetAddr::Ip(test_echo_target(echo_addr));
    let target_obj = Arc::new(MockTunnelTarget::new("only-1").with_dial_redirect(echo_addr));
    let router: Arc<dyn TunnelRouter> =
        Arc::new(SingleTunnelRouter::new("only-1", target_obj, None));
    let selector = TunnelSelector::DefaultPool;

    // Excluding an unrelated tunnel changes nothing.
    let (_, id, _) = connect_via_router(&router, &selector, &target, None, Some("other"))
        .await
        .expect("dial must succeed when the exclusion does not match");
    assert_eq!(id.as_deref(), Some("only-1"));

    // Excluding the only tunnel fails fast instead of dialing it.
    let err = connect_via_router(&router, &selector, &target, None, Some("only-1"))
        .await
        .err()
        .expect("dial must fail when the only tunnel is excluded");
    let RouterConnectError::SelectTunnel(e) = err else {
        panic!("expected a SelectTunnel error, got {err:?}");
    };
    assert_eq!(e.kind(), io::ErrorKind::NotConnected);
}

#[tokio::test]
async fn test_socks5_connect_zero_response_retry() {
    use crate::proxy::replay::{REPLAY_TEST_LOCK, replay_metrics, reset_replay_state_for_tests};

    // fix11: the replayed request must be a positively identified
    // safe HTTP GET (the old opaque "socks5_retry_test!" is no
    // longer replayed once bytes were sent). fix5 wins the shared
    // token; the silence timer never fires.
    let _replay_guard = REPLAY_TEST_LOCK.lock().await;
    reset_replay_state_for_tests();

    let msg = b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n";
    let blackhole_addr = spawn_blackhole_tcp_server(msg.len()).await;
    let echo_addr = spawn_echo_tcp_server().await;
    let target_addr = test_echo_target(echo_addr);
    let SocketAddr::V4(target_v4) = target_addr else {
        unreachable!();
    };

    let pool = Arc::new(PoolRouter::new(PoolStrategy::RoundRobin, true));
    pool.add_tunnel(
        "dead-1",
        Arc::new(MockTunnelTarget::new("dead-1").with_dial_redirect(blackhole_addr)),
    );
    pool.add_tunnel(
        "alive-1",
        Arc::new(MockTunnelTarget::new("alive-1").with_dial_redirect(echo_addr)),
    );
    let router: Arc<dyn TunnelRouter> = pool;

    let (mut client, server) = tokio::io::duplex(2048);
    tokio::spawn(async move {
        let _ = handle_socks5(server, router).await;
    });

    // 1. Greeting
    client
        .write_all(&[SOCKS5_VERSION, 1, METHOD_NO_AUTH])
        .await
        .unwrap();
    let mut g_resp = [0u8; 2];
    client.read_exact(&mut g_resp).await.unwrap();
    assert_eq!(g_resp[1], METHOD_NO_AUTH);

    // 2. CONNECT IPv4
    let mut cmd = vec![SOCKS5_VERSION, CMD_CONNECT, 0x00, ATYP_IPV4];
    cmd.extend_from_slice(&target_v4.ip().octets());
    cmd.extend_from_slice(&target_v4.port().to_be_bytes());
    client.write_all(&cmd).await.unwrap();
    let mut reply_hdr = [0u8; 4];
    client.read_exact(&mut reply_hdr).await.unwrap();
    assert_eq!(reply_hdr[1], REP_SUCCESS);
    let mut bnd_buf = [0u8; 6];
    client.read_exact(&mut bnd_buf).await.unwrap();

    // 3. The request is retried through the echo tunnel and comes back.
    client.write_all(msg).await.unwrap();
    let mut echo_buf = vec![0u8; msg.len()];
    tokio::time::timeout(Duration::from_secs(5), client.read_exact(&mut echo_buf))
        .await
        .expect("echo must arrive after the retry")
        .expect("echo read must succeed");
    assert_eq!(&echo_buf, msg);
    // The shared post-send token went to fix5: the echo can only
    // arrive after the retry claimed it, and the silence timer
    // never fired (the blackhole closed in milliseconds).
    let metrics = replay_metrics();
    assert_eq!(metrics.claimed_fix5.load(Ordering::Relaxed), 1);
    assert_eq!(metrics.claimed_silence.load(Ordering::Relaxed), 0);
    assert_eq!(metrics.silence_trigger.load(Ordering::Relaxed), 0);
}

#[tokio::test]
async fn test_safe_http_silence_replay_rescues_blackhole() {
    use crate::proxy::replay::{
        REPLAY_TEST_LOCK, replay_budget_concurrent_for_tests, replay_metrics,
        reset_replay_state_for_tests,
    };
    use crate::proxy::router::connect_via_router;
    use crate::proxy::{
        CopyEndKind, ZeroResponseRetry, copy_bidirectional_with_zero_response_retry,
    };

    // fix11: a plaintext GET to a blackhole primary is rescued by
    // the silence replay — at 2.5 s a second tunnel is dialled, the
    // buffered GET is sent on it, and the echo comes back through
    // the secondary. fix12: the primary is NOT penalised at the
    // win — it is observed until its 15 s deadline, and only a
    // deadline miss earns the blackhole penalty.
    let _replay_guard = REPLAY_TEST_LOCK.lock().await;
    reset_replay_state_for_tests();

    let msg = b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n";
    // The primary reads the GET and then stays silent forever.
    let blackhole_addr = spawn_blackhole_tcp_server(usize::MAX).await;
    let echo_addr = spawn_echo_tcp_server().await;
    let target = TargetAddr::Ip(test_echo_target(echo_addr));

    let pool = Arc::new(PoolRouter::new(PoolStrategy::RoundRobin, true));
    pool.add_tunnel(
        "dead-1",
        Arc::new(MockTunnelTarget::new("dead-1").with_dial_redirect(blackhole_addr)),
    );
    pool.add_tunnel(
        "alive-1",
        Arc::new(MockTunnelTarget::new("alive-1").with_dial_redirect(echo_addr)),
    );
    let router: Arc<dyn TunnelRouter> = pool;
    let selector = TunnelSelector::DefaultPool;

    let (first_stream, first_id, _) = connect_via_router(&router, &selector, &target, None, None)
        .await
        .expect("first dial must succeed");
    assert_eq!(first_id.as_deref(), Some("dead-1"));

    let (mut client, mut server) = tokio::io::duplex(2048);
    let retry = ZeroResponseRetry::new(&router, &selector, &target, None, "SOCKS5", Vec::new());
    // The idle timeout must exceed the 2.5 s silence timer, or the
    // session ends idle before the replay can fire.
    let (relay_out, echo_buf) = tokio::time::timeout(Duration::from_secs(10), async {
        tokio::join!(
            async move {
                let mut tunnel_id = first_id;
                let result = copy_bidirectional_with_zero_response_retry(
                    &mut server,
                    first_stream,
                    Duration::from_secs(3),
                    Some(retry),
                    &mut tunnel_id,
                )
                .await;
                (result, tunnel_id)
            },
            async {
                client.write_all(msg).await.unwrap();
                // The GET went to the blackhole first (no reply for
                // 2.5 s), was replayed through the echo tunnel, and
                // comes back.
                let mut echo_buf = vec![0u8; msg.len()];
                client.read_exact(&mut echo_buf).await.unwrap();
                echo_buf
            },
        )
    })
    .await
    .expect("test must finish within 10s");
    assert_eq!(&echo_buf, msg);

    let (result, tunnel_id) = relay_out;
    let (client_bytes, tunnel_bytes) = result.result.expect("relay must end cleanly");
    // After the rescue the session idles out, as in the fix5 retry
    // tests: the mock echo server does not produce a prompt tunnel
    // EOF once the client drops. The rescue is proven by the echo
    // arriving through the secondary, the tunnel switch, and the
    // counters below — not by the end kind.
    assert_eq!(result.kind, CopyEndKind::IdleTimeout);
    assert_eq!(tunnel_id.as_deref(), Some("alive-1"));
    assert_eq!(
        (client_bytes, tunnel_bytes),
        (msg.len() as u64, msg.len() as u64)
    );
    // The silence replay claimed the shared token (fix5 did not),
    // fired once, sent the GET on the secondary, and the secondary
    // won the race. fix12: the blackhole primary is NOT penalised
    // here — it is under observation until its 15 s deadline, so
    // at this point no verdict exists yet and the replay slot is
    // still held by the observer.
    let metrics = replay_metrics();
    assert_eq!(metrics.eligible.load(Ordering::Relaxed), 1);
    assert_eq!(metrics.silence_trigger.load(Ordering::Relaxed), 1);
    assert_eq!(metrics.dial_started.load(Ordering::Relaxed), 1);
    assert_eq!(metrics.dial_failed.load(Ordering::Relaxed), 0);
    assert_eq!(metrics.request_sent.load(Ordering::Relaxed), 1);
    assert_eq!(metrics.winner_secondary.load(Ordering::Relaxed), 1);
    assert_eq!(metrics.secondary_wins.load(Ordering::Relaxed), 1);
    assert_eq!(metrics.unobserved_loser.load(Ordering::Relaxed), 0);
    assert_eq!(metrics.late_response.load(Ordering::Relaxed), 0);
    assert_eq!(metrics.deadline_miss.load(Ordering::Relaxed), 0);
    assert_eq!(metrics.claimed_silence.load(Ordering::Relaxed), 1);
    assert_eq!(metrics.claimed_fix5.load(Ordering::Relaxed), 0);
    assert_eq!(replay_budget_concurrent_for_tests(), 1);
}

#[tokio::test]
async fn test_safe_http_silence_replay_ignores_opaque_tls() {
    use crate::proxy::replay::{REPLAY_TEST_LOCK, replay_metrics, reset_replay_state_for_tests};
    use crate::proxy::router::connect_via_router;
    use crate::proxy::{
        CopyEndKind, ZeroResponseRetry, copy_bidirectional_with_zero_response_retry,
    };

    // fix11: opaque TLS-like bytes are never replayed. The client
    // sends a TLS ClientHello prefix to a silent blackhole, waits
    // past the 2.5 s silence timer, and gives up — the session must
    // end as ClientAborted on the primary tunnel, with no replay
    // dialled and no counter moved.
    let _replay_guard = REPLAY_TEST_LOCK.lock().await;
    reset_replay_state_for_tests();

    // First bytes of a TLS 1.2 ClientHello: handshake, TLS 1.0
    // record version, then a length. Not a GET, not text.
    let msg: &[u8] = &[
        0x16, 0x03, 0x01, 0x00, 0x2e, 0x01, 0x00, 0x00, 0x2a, 0x03, 0x03, 0x5a, 0x6b, 0x7c, 0x8d,
        0x9e, 0xaf, 0x00,
    ];
    let blackhole_addr = spawn_blackhole_tcp_server(usize::MAX).await;
    let echo_addr = spawn_echo_tcp_server().await;
    let target = TargetAddr::Ip(test_echo_target(echo_addr));

    let pool = Arc::new(PoolRouter::new(PoolStrategy::RoundRobin, true));
    pool.add_tunnel(
        "dead-1",
        Arc::new(MockTunnelTarget::new("dead-1").with_dial_redirect(blackhole_addr)),
    );
    pool.add_tunnel(
        "alive-1",
        Arc::new(MockTunnelTarget::new("alive-1").with_dial_redirect(echo_addr)),
    );
    let router: Arc<dyn TunnelRouter> = pool;
    let selector = TunnelSelector::DefaultPool;

    let (first_stream, first_id, _) = connect_via_router(&router, &selector, &target, None, None)
        .await
        .expect("first dial must succeed");
    assert_eq!(first_id.as_deref(), Some("dead-1"));

    let (mut client, mut server) = tokio::io::duplex(2048);
    let retry = ZeroResponseRetry::new(&router, &selector, &target, None, "SOCKS5", Vec::new());
    let (relay_out, ()) = tokio::time::timeout(Duration::from_secs(10), async {
        tokio::join!(
            async move {
                let mut tunnel_id = first_id;
                let result = copy_bidirectional_with_zero_response_retry(
                    &mut server,
                    first_stream,
                    Duration::from_secs(5),
                    Some(retry),
                    &mut tunnel_id,
                )
                .await;
                (result, tunnel_id)
            },
            async {
                client.write_all(msg).await.unwrap();
                // Wait past the silence timer, then give up the way
                // curl does at its timeout: drop the client half.
                tokio::time::sleep(Duration::from_millis(3000)).await;
                drop(client);
            },
        )
    })
    .await
    .expect("test must finish within 10s");

    let (result, tunnel_id) = relay_out;
    let (client_bytes, tunnel_bytes) = result.result.expect("relay must end cleanly");
    assert_eq!(result.kind, CopyEndKind::ClientAborted);
    assert_eq!(tunnel_id.as_deref(), Some("dead-1"));
    assert_eq!(client_bytes, msg.len() as u64);
    assert_eq!(tunnel_bytes, 0);
    // No replay of any kind: the request never parsed as a safe
    // GET, so the timer never armed and the token was never claimed.
    let metrics = replay_metrics();
    assert_eq!(metrics.eligible.load(Ordering::Relaxed), 0);
    assert_eq!(metrics.silence_trigger.load(Ordering::Relaxed), 0);
    assert_eq!(metrics.dial_started.load(Ordering::Relaxed), 0);
    assert_eq!(metrics.request_sent.load(Ordering::Relaxed), 0);
    assert_eq!(metrics.secondary_wins.load(Ordering::Relaxed), 0);
    assert_eq!(metrics.claimed_silence.load(Ordering::Relaxed), 0);
    assert_eq!(metrics.claimed_fix5.load(Ordering::Relaxed), 0);
}

#[tokio::test]
async fn test_zero_response_retry_blocks_opaque_after_bytes_written() {
    use crate::proxy::replay::{REPLAY_TEST_LOCK, replay_metrics, reset_replay_state_for_tests};
    use crate::proxy::router::connect_via_router;
    use crate::proxy::{
        CopyEndKind, ZeroResponseRetry, copy_bidirectional_with_zero_response_retry,
    };

    // fix11: the tightened fix5. A small opaque request whose bytes
    // were all written to the tunnel must NOT be replayed when the
    // tunnel closes with zero response bytes — only a positively
    // identified safe GET (or zero bytes written) may be. The
    // blackhole reads the whole message first, so every byte was
    // written upstream, deterministically.
    let _replay_guard = REPLAY_TEST_LOCK.lock().await;
    reset_replay_state_for_tests();

    let msg = b"opaque request, not a GET";
    let blackhole_addr = spawn_blackhole_tcp_server(msg.len()).await;
    let echo_addr = spawn_echo_tcp_server().await;
    let target = TargetAddr::Ip(test_echo_target(echo_addr));

    let pool = Arc::new(PoolRouter::new(PoolStrategy::RoundRobin, true));
    pool.add_tunnel(
        "dead-1",
        Arc::new(MockTunnelTarget::new("dead-1").with_dial_redirect(blackhole_addr)),
    );
    pool.add_tunnel(
        "alive-1",
        Arc::new(MockTunnelTarget::new("alive-1").with_dial_redirect(echo_addr)),
    );
    let router: Arc<dyn TunnelRouter> = pool;
    let selector = TunnelSelector::DefaultPool;

    let (first_stream, first_id, _) = connect_via_router(&router, &selector, &target, None, None)
        .await
        .expect("first dial must succeed");
    assert_eq!(first_id.as_deref(), Some("dead-1"));

    let (mut client, mut server) = tokio::io::duplex(2048);
    let retry = ZeroResponseRetry::new(&router, &selector, &target, None, "SOCKS5", Vec::new());
    let (relay_out, ()) = tokio::time::timeout(Duration::from_secs(10), async {
        tokio::join!(
            async move {
                let mut tunnel_id = first_id;
                let result = copy_bidirectional_with_zero_response_retry(
                    &mut server,
                    first_stream,
                    Duration::from_millis(500),
                    Some(retry),
                    &mut tunnel_id,
                )
                .await;
                (result, tunnel_id)
            },
            async {
                client.write_all(msg).await.unwrap();
                // No echo may arrive: the session must end with no
                // response bytes, not a retried echo.
                let mut one = [0u8; 1];
                let n = client.read(&mut one).await.unwrap();
                assert_eq!(
                    n, 0,
                    "no response bytes must arrive when the retry is blocked"
                );
            },
        )
    })
    .await
    .expect("test must finish within 10s");

    let (result, tunnel_id) = relay_out;
    let (client_bytes, tunnel_bytes) = result.result.expect("relay must end cleanly");
    assert_eq!(result.kind, CopyEndKind::TunnelClosed);
    assert_eq!(tunnel_id.as_deref(), Some("dead-1"));
    assert_eq!(client_bytes, msg.len() as u64);
    assert_eq!(tunnel_bytes, 0);
    // The retry was blocked as ineligible, not spent.
    let metrics = replay_metrics();
    assert_eq!(metrics.suppressed_ineligible.load(Ordering::Relaxed), 1);
    assert_eq!(metrics.claimed_fix5.load(Ordering::Relaxed), 0);
    assert_eq!(metrics.claimed_silence.load(Ordering::Relaxed), 0);
}

#[tokio::test]
async fn test_hedge_loser_classify_late_response_eof_rst_and_silence() {
    use crate::proxy::replay::{HedgeLoserOutcome, classify_hedge_loser};
    use std::time::Instant;

    // Late response: one byte after 200 ms, well before the deadline.
    let (observed, mut peer) = tokio::io::duplex(64);
    let mut observed: DynStream = Box::new(observed);
    tokio::spawn(async move {
        tokio::time::sleep(Duration::from_millis(200)).await;
        let _ = peer.write_all(b"X").await;
    });
    let start = Instant::now();
    let outcome = classify_hedge_loser(&mut observed, start + Duration::from_secs(5)).await;
    match outcome {
        HedgeLoserOutcome::LateResponse { first_byte_at } => {
            let ms = first_byte_at.duration_since(start).as_millis();
            assert!(
                ms >= 150,
                "late byte must arrive after the 200 ms delay, got {ms} ms"
            );
            assert!(
                ms < 2000,
                "late byte must not wait out the deadline, got {ms} ms"
            );
        }
        _ => panic!("a byte before the deadline must classify as LateResponse"),
    }

    // EOF: the peer drops at once.
    let (observed, peer) = tokio::io::duplex(64);
    let mut observed: DynStream = Box::new(observed);
    drop(peer);
    let outcome =
        classify_hedge_loser(&mut observed, Instant::now() + Duration::from_secs(5)).await;
    assert!(
        matches!(outcome, HedgeLoserOutcome::TransportFailure),
        "an immediate EOF must classify as TransportFailure"
    );

    // RST: a real TCP pair; the peer reads one byte of the request
    // and then closes with the rest unread, so Linux resets the
    // socket instead of sending FIN.
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let server_addr = listener.local_addr().unwrap();
    let accept = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut buf = [0u8; 1];
        let _ = stream.read_exact(&mut buf).await;
        drop(stream);
    });
    let mut observed: DynStream = Box::new(TcpStream::connect(server_addr).await.unwrap());
    observed
        .write_all(b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")
        .await
        .unwrap();
    let outcome =
        classify_hedge_loser(&mut observed, Instant::now() + Duration::from_secs(5)).await;
    assert!(
        matches!(outcome, HedgeLoserOutcome::TransportFailure),
        "a reset before any response byte must classify as TransportFailure"
    );
    accept.await.unwrap();

    // Silence: the peer stays open but never answers, and the short
    // deadline passes.
    let (observed, _peer) = tokio::io::duplex(64);
    let mut observed: DynStream = Box::new(observed);
    let start = Instant::now();
    let outcome = classify_hedge_loser(&mut observed, start + Duration::from_millis(200)).await;
    assert!(
        matches!(outcome, HedgeLoserOutcome::DeadlineMiss),
        "silence until the deadline must classify as DeadlineMiss"
    );
    assert!(
        start.elapsed().as_millis() >= 150,
        "the classifier must wait out the deadline, not return at once"
    );
}

#[tokio::test]
async fn test_hedge_loser_apply_outcome_charges_only_deadline_miss() {
    use crate::proxy::replay::{
        HedgeLoserCtx, HedgeLoserOutcome, REPLAY_TEST_LOCK, apply_hedge_loser_outcome,
        replay_metrics, reset_replay_state_for_tests,
    };
    use std::time::Instant;

    // One outcome of each kind through the same context: only the
    // deadline miss may charge the blackhole penalty.
    let _replay_guard = REPLAY_TEST_LOCK.lock().await;
    reset_replay_state_for_tests();

    let pool = Arc::new(PoolRouter::new(PoolStrategy::RoundRobin, true));
    let recording = Arc::new(RecordingRouter::new(pool));
    let router_inner: Arc<RecordingRouter> = Arc::clone(&recording);
    let router: Arc<dyn TunnelRouter> = router_inner;
    let forwarded_at = Instant::now();
    let ctx = HedgeLoserCtx {
        router,
        primary_tunnel_id: "slow-1".to_string(),
        request_id: 7,
        primary_request_forwarded_at: forwarded_at,
        secondary_request_forwarded_at: Some(forwarded_at),
        secondary_first_response_at: forwarded_at,
    };

    apply_hedge_loser_outcome(
        &ctx,
        &HedgeLoserOutcome::LateResponse {
            first_byte_at: forwarded_at + Duration::from_millis(3200),
        },
    );
    apply_hedge_loser_outcome(&ctx, &HedgeLoserOutcome::TransportFailure);
    apply_hedge_loser_outcome(&ctx, &HedgeLoserOutcome::DeadlineMiss);

    let metrics = replay_metrics();
    assert_eq!(metrics.late_response.load(Ordering::Relaxed), 1);
    assert_eq!(metrics.transport_failure.load(Ordering::Relaxed), 1);
    assert_eq!(metrics.deadline_miss.load(Ordering::Relaxed), 1);
    assert_eq!(metrics.true_rescues.load(Ordering::Relaxed), 1);
    assert_eq!(metrics.both_legs_responded.load(Ordering::Relaxed), 1);
    assert_eq!(
        metrics
            .primary_response_latency_ms_sum
            .load(Ordering::Relaxed),
        3200
    );
    assert_eq!(
        metrics
            .blackhole_ejections_deadline_miss
            .load(Ordering::Relaxed),
        1
    );
    assert_eq!(recording.blackhole_count("slow-1"), 1);
    assert_eq!(recording.transport_failure_count("slow-1"), 1);
    assert_eq!(recording.rtt_samples_for("slow-1"), vec![3200]);
}

#[tokio::test]
async fn test_hedge_loser_late_response_no_penalty() {
    use crate::proxy::replay::{
        REPLAY_TEST_LOCK, replay_budget_concurrent_for_tests, replay_metrics,
        reset_replay_state_for_tests,
    };
    use crate::proxy::router::connect_via_router;
    use crate::proxy::{
        CopyEndKind, ZeroResponseRetry, copy_bidirectional_with_zero_response_retry,
    };

    // fix12: the primary answers 3 s after the request — after the
    // secondary won the race at 2.5 s, but before the 15 s deadline.
    // It must take NO breaker penalty, and its observed latency must
    // feed the EWMA instead. The replay slot stays held while the
    // loser is observed and is released once the verdict lands.
    let _replay_guard = REPLAY_TEST_LOCK.lock().await;
    reset_replay_state_for_tests();

    let msg = b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n";
    let slow_addr = spawn_delayed_echo_tcp_server(Duration::from_secs(3)).await;
    let echo_addr = spawn_echo_tcp_server().await;
    let target = TargetAddr::Ip(test_echo_target(echo_addr));

    let pool = Arc::new(PoolRouter::new(PoolStrategy::RoundRobin, true));
    pool.add_tunnel(
        "slow-1",
        Arc::new(MockTunnelTarget::new("slow-1").with_dial_redirect(slow_addr)),
    );
    pool.add_tunnel(
        "alive-1",
        Arc::new(MockTunnelTarget::new("alive-1").with_dial_redirect(echo_addr)),
    );
    let recording = Arc::new(RecordingRouter::new(pool));
    let router_inner: Arc<RecordingRouter> = Arc::clone(&recording);
    let router: Arc<dyn TunnelRouter> = router_inner;
    let selector = TunnelSelector::DefaultPool;

    let (first_stream, first_id, _) = connect_via_router(&router, &selector, &target, None, None)
        .await
        .expect("first dial must succeed");
    assert_eq!(first_id.as_deref(), Some("slow-1"));

    let (mut client, mut server) = tokio::io::duplex(2048);
    let retry = ZeroResponseRetry::new(&router, &selector, &target, None, "SOCKS5", Vec::new());
    let (relay_out, echo_buf) = tokio::time::timeout(Duration::from_secs(15), async {
        tokio::join!(
            async move {
                let mut tunnel_id = first_id;
                let result = copy_bidirectional_with_zero_response_retry(
                    &mut server,
                    first_stream,
                    Duration::from_secs(3),
                    Some(retry),
                    &mut tunnel_id,
                )
                .await;
                (result, tunnel_id)
            },
            async {
                client.write_all(msg).await.unwrap();
                let mut echo_buf = vec![0u8; msg.len()];
                client.read_exact(&mut echo_buf).await.unwrap();
                echo_buf
            },
        )
    })
    .await
    .expect("test must finish within 15s");
    assert_eq!(&echo_buf, msg);

    let (result, tunnel_id) = relay_out;
    let (client_bytes, tunnel_bytes) = result.result.expect("relay must end cleanly");
    assert_eq!(result.kind, CopyEndKind::IdleTimeout);
    assert_eq!(tunnel_id.as_deref(), Some("alive-1"));
    assert_eq!(
        (client_bytes, tunnel_bytes),
        (msg.len() as u64, msg.len() as u64)
    );

    // The secondary won, the slow primary answered at ~3 s, and the
    // observer resolved before the session ended.
    let metrics = replay_metrics();
    assert_eq!(metrics.secondary_wins.load(Ordering::Relaxed), 1);
    assert_eq!(metrics.late_response.load(Ordering::Relaxed), 1);
    assert_eq!(metrics.transport_failure.load(Ordering::Relaxed), 0);
    assert_eq!(metrics.deadline_miss.load(Ordering::Relaxed), 0);
    assert_eq!(metrics.true_rescues.load(Ordering::Relaxed), 0);
    assert_eq!(metrics.both_legs_responded.load(Ordering::Relaxed), 1);
    assert_eq!(recording.blackhole_count("slow-1"), 0);
    assert_eq!(recording.transport_failure_count("slow-1"), 0);
    let samples = recording.rtt_samples_for("slow-1");
    assert_eq!(samples.len(), 1);
    assert!(
        samples[0] >= 2500,
        "observed latency must cover the 3 s delay, got {} ms",
        samples[0]
    );
    assert!(
        samples[0] < 6000,
        "observed latency must not wait out the deadline, got {} ms",
        samples[0]
    );
    assert_eq!(replay_budget_concurrent_for_tests(), 0);
}

#[tokio::test]
async fn test_hedge_loser_transport_failure_no_blackhole() {
    use crate::proxy::replay::{
        REPLAY_TEST_LOCK, replay_budget_concurrent_for_tests, replay_metrics,
        reset_replay_state_for_tests,
    };
    use crate::proxy::router::connect_via_router;
    use crate::proxy::{
        CopyEndKind, ZeroResponseRetry, copy_bidirectional_with_zero_response_retry,
    };

    // fix12: the primary's connection dies 2.8 s after the request —
    // after the secondary won the race at 2.5 s, before answering.
    // That is a transport failure, not a blackhole: no blackhole
    // penalty, and the slot is released once the verdict lands.
    let _replay_guard = REPLAY_TEST_LOCK.lock().await;
    reset_replay_state_for_tests();

    let msg = b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n";
    let dying_addr = spawn_delayed_close_tcp_server(Duration::from_millis(2800)).await;
    let echo_addr = spawn_echo_tcp_server().await;
    let target = TargetAddr::Ip(test_echo_target(echo_addr));

    let pool = Arc::new(PoolRouter::new(PoolStrategy::RoundRobin, true));
    pool.add_tunnel(
        "dying-1",
        Arc::new(MockTunnelTarget::new("dying-1").with_dial_redirect(dying_addr)),
    );
    pool.add_tunnel(
        "alive-1",
        Arc::new(MockTunnelTarget::new("alive-1").with_dial_redirect(echo_addr)),
    );
    let recording = Arc::new(RecordingRouter::new(pool));
    let router_inner: Arc<RecordingRouter> = Arc::clone(&recording);
    let router: Arc<dyn TunnelRouter> = router_inner;
    let selector = TunnelSelector::DefaultPool;

    let (first_stream, first_id, _) = connect_via_router(&router, &selector, &target, None, None)
        .await
        .expect("first dial must succeed");
    assert_eq!(first_id.as_deref(), Some("dying-1"));

    let (mut client, mut server) = tokio::io::duplex(2048);
    let retry = ZeroResponseRetry::new(&router, &selector, &target, None, "SOCKS5", Vec::new());
    let (relay_out, echo_buf) = tokio::time::timeout(Duration::from_secs(15), async {
        tokio::join!(
            async move {
                let mut tunnel_id = first_id;
                let result = copy_bidirectional_with_zero_response_retry(
                    &mut server,
                    first_stream,
                    Duration::from_secs(3),
                    Some(retry),
                    &mut tunnel_id,
                )
                .await;
                (result, tunnel_id)
            },
            async {
                client.write_all(msg).await.unwrap();
                let mut echo_buf = vec![0u8; msg.len()];
                client.read_exact(&mut echo_buf).await.unwrap();
                echo_buf
            },
        )
    })
    .await
    .expect("test must finish within 15s");
    assert_eq!(&echo_buf, msg);

    let (result, tunnel_id) = relay_out;
    let (client_bytes, tunnel_bytes) = result.result.expect("relay must end cleanly");
    assert_eq!(result.kind, CopyEndKind::IdleTimeout);
    assert_eq!(tunnel_id.as_deref(), Some("alive-1"));
    assert_eq!(
        (client_bytes, tunnel_bytes),
        (msg.len() as u64, msg.len() as u64)
    );

    // The secondary won, the dying primary closed at ~2.8 s, and
    // the observer resolved before the session ended.
    let metrics = replay_metrics();
    assert_eq!(metrics.secondary_wins.load(Ordering::Relaxed), 1);
    assert_eq!(metrics.late_response.load(Ordering::Relaxed), 0);
    assert_eq!(metrics.transport_failure.load(Ordering::Relaxed), 1);
    assert_eq!(metrics.deadline_miss.load(Ordering::Relaxed), 0);
    assert_eq!(metrics.true_rescues.load(Ordering::Relaxed), 0);
    assert_eq!(metrics.both_legs_responded.load(Ordering::Relaxed), 0);
    assert_eq!(recording.blackhole_count("dying-1"), 0);
    assert_eq!(recording.transport_failure_count("dying-1"), 1);
    assert!(recording.rtt_samples_for("dying-1").is_empty());
    assert_eq!(replay_budget_concurrent_for_tests(), 0);
}

#[test]
fn test_parse_safe_http_get_header_eligible() {
    use crate::proxy::replay::{SafeGetParse, parse_safe_http_get_header};

    // Eligible: HTTP/1.1 and HTTP/1.0, with and without an explicit
    // zero Content-Length. Only the header is returned, not a
    // pipelined second request.
    let get11 = b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n";
    assert!(matches!(
        parse_safe_http_get_header(get11),
        SafeGetParse::Eligible(_)
    ));
    assert!(matches!(
        parse_safe_http_get_header(b"GET /path?x=1 HTTP/1.0\r\nHost: a\r\n\r\n"),
        SafeGetParse::Eligible(_)
    ));
    assert!(matches!(
        parse_safe_http_get_header(
            b"GET / HTTP/1.1\r\nHost: example.com\r\nContent-Length: 0\r\n\r\n"
        ),
        SafeGetParse::Eligible(_)
    ));
    if let SafeGetParse::Eligible(header) = parse_safe_http_get_header(
        b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\nGET /second HTTP/1.1\r\nHost: x\r\n\r\n",
    ) {
        assert_eq!(&*header, get11);
    } else {
        panic!("pipelined GET must parse as eligible with only the first header");
    }
}

#[test]
fn test_parse_safe_http_get_header_ineligible() {
    use crate::proxy::replay::{SafeGetParse, parse_safe_http_get_header};

    fn ineligible(bytes: &[u8]) -> bool {
        matches!(parse_safe_http_get_header(bytes), SafeGetParse::Ineligible)
    }

    // Ineligible: every other method, a body, an upgrade, and
    // ambiguous length headers.
    assert!(ineligible(b"POST / HTTP/1.1\r\nHost: a\r\n\r\n"));
    assert!(ineligible(b"HEAD / HTTP/1.1\r\nHost: a\r\n\r\n"));
    assert!(ineligible(b"OPTIONS * HTTP/1.1\r\nHost: a\r\n\r\n"));
    assert!(ineligible(
        b"CONNECT example.com:443 HTTP/1.1\r\nHost: a\r\n\r\n"
    ));
    assert!(ineligible(
        b"GET / HTTP/1.1\r\nHost: a\r\nTransfer-Encoding: chunked\r\n\r\n"
    ));
    assert!(ineligible(
        b"GET / HTTP/1.1\r\nHost: a\r\nContent-Length: 5\r\n\r\n"
    ));
    assert!(ineligible(
        b"GET / HTTP/1.1\r\nHost: a\r\nContent-Length: 0\r\nContent-Length: 0\r\n\r\n"
    ));
    assert!(ineligible(
        b"GET / HTTP/1.1\r\nHost: a\r\nExpect: 100-continue\r\n\r\n"
    ));
    assert!(ineligible(
        b"GET / HTTP/1.1\r\nHost: a\r\nUpgrade: websocket\r\n\r\n"
    ));
    assert!(ineligible(
        b"GET / HTTP/1.1\r\nHost: a\r\nConnection: upgrade\r\n\r\n"
    ));
    assert!(ineligible(b"GET * HTTP/1.1\r\nHost: a\r\n\r\n"));
    // A header past the 16 KiB cap is ineligible even with a
    // terminator at the end.
    let mut big = b"GET / HTTP/1.1\r\nHost: a\r\nX-Pad: ".to_vec();
    big.extend(std::iter::repeat_n(b'a', 17 * 1024));
    big.extend_from_slice(b"\r\n\r\n");
    assert!(ineligible(&big));
    // A binary blob past the 16 KiB cap, with no terminator, is
    // ineligible (it cannot become a GET).
    let blob = vec![0x16u8; 17 * 1024];
    assert!(ineligible(&blob));
}

#[test]
fn test_parse_safe_http_get_header_incomplete() {
    use crate::proxy::replay::{SafeGetParse, parse_safe_http_get_header};

    // Incomplete: no terminator yet, header still under the cap.
    assert!(matches!(
        parse_safe_http_get_header(b"GET / HTTP/1.1\r\nHost: example.com\r\n"),
        SafeGetParse::Incomplete
    ));
    assert!(matches!(
        parse_safe_http_get_header(b"GET / HTTP/1.1\r\n"),
        SafeGetParse::Incomplete
    ));
    assert!(matches!(
        parse_safe_http_get_header(b""),
        SafeGetParse::Incomplete
    ));
    // A short binary blob (or TLS prefix) with no terminator yet is
    // incomplete too: the parser cannot rule it out until a
    // terminator arrives or the cap is passed.
    assert!(matches!(
        parse_safe_http_get_header(&[0x16, 0x03, 0x01, 0x00, 0x2e, 0x01]),
        SafeGetParse::Incomplete
    ));
    assert!(matches!(
        parse_safe_http_get_header(&[0x00, 0x01, 0x02, 0xff, 0xfe]),
        SafeGetParse::Incomplete
    ));
}

/// Fields every replay decision record must carry (fix13):
/// the correlation id, the decision, the primary tunnel, the
/// target, and the decision offsets.
const REPLAY_DECISION_FIELDS: &[&str] = &[
    "request_id=",
    "decision",
    "started",
    "dead-1",
    "primary_tunnel_id=",
    "target=",
    "decision_timestamp=",
    "request_forwarded_ms=",
    "silence_trigger_ms=",
    "primary_response_bytes=",
    "active_replays=",
    "max_concurrent_replays=",
    "bucket_tokens=",
    "bucket_capacity=",
    "token_available=",
    "slot_available=",
    "admission_result=",
];

/// Pull the `request_id=<digits>` value out of one rendered log
/// line, so a test can prove two records carry the same session id.
fn request_id_in_line(line: &str) -> Option<u64> {
    let rest = line.split("request_id=").nth(1)?;
    rest.chars()
        .take_while(|c| c.is_ascii_digit())
        .collect::<String>()
        .parse()
        .ok()
}

/// Assert one rendered log line carries every listed field
/// substring (fix13 decision/suppression records).
fn assert_line_has_fields(line: &str, fields: &[&str]) {
    for field in fields {
        assert!(
            line.contains(field),
            "log line must carry {field}, got: {line:?}"
        );
    }
}

#[tokio::test]
async fn test_replay_decision_record_at_trigger_has_required_fields() {
    use crate::proxy::replay::{REPLAY_TEST_LOCK, replay_metrics, reset_replay_state_for_tests};
    use crate::proxy::router::connect_via_router;
    use crate::proxy::{
        CopyEndKind, ZeroResponseRetry, copy_bidirectional_with_zero_response_retry,
    };

    // fix13: a request that reaches the 2.5 s decision point emits
    // one structured record carrying the session's correlation id,
    // the primary tunnel, the target, and the decision offsets —
    // and the same id appears on the race-resolution line and on
    // the session outcome, so the whole decision chain joins.
    let _replay_guard = REPLAY_TEST_LOCK.lock().await;
    reset_replay_state_for_tests();

    let captured = Arc::new(Mutex::new(Vec::new()));
    let subscriber = tracing_subscriber::fmt()
        .with_max_level(tracing::Level::INFO)
        .with_ansi(false)
        .with_writer(VecMakeWriter(Arc::clone(&captured)))
        .finish();
    let _guard = tracing::subscriber::set_default(subscriber);

    let msg = b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n";
    let blackhole_addr = spawn_blackhole_tcp_server(usize::MAX).await;
    let echo_addr = spawn_echo_tcp_server().await;
    let target = TargetAddr::Ip(test_echo_target(echo_addr));

    let pool = Arc::new(PoolRouter::new(PoolStrategy::RoundRobin, true));
    pool.add_tunnel(
        "dead-1",
        Arc::new(MockTunnelTarget::new("dead-1").with_dial_redirect(blackhole_addr)),
    );
    pool.add_tunnel(
        "alive-1",
        Arc::new(MockTunnelTarget::new("alive-1").with_dial_redirect(echo_addr)),
    );
    let router: Arc<dyn TunnelRouter> = pool;
    let selector = TunnelSelector::DefaultPool;

    let (first_stream, first_id, _) = connect_via_router(&router, &selector, &target, None, None)
        .await
        .expect("first dial must succeed");
    assert_eq!(first_id.as_deref(), Some("dead-1"));

    let (mut client, mut server) = tokio::io::duplex(2048);
    let retry = ZeroResponseRetry::new(&router, &selector, &target, None, "SOCKS5", Vec::new());
    let (relay_out, echo_buf) = tokio::time::timeout(Duration::from_secs(10), async {
        tokio::join!(
            async move {
                let mut tunnel_id = first_id;
                let result = copy_bidirectional_with_zero_response_retry(
                    &mut server,
                    first_stream,
                    Duration::from_secs(3),
                    Some(retry),
                    &mut tunnel_id,
                )
                .await;
                (result, tunnel_id)
            },
            async {
                client.write_all(msg).await.unwrap();
                let mut echo_buf = vec![0u8; msg.len()];
                client.read_exact(&mut echo_buf).await.unwrap();
                echo_buf
            },
        )
    })
    .await
    .expect("test must finish within 10s");
    assert_eq!(&echo_buf, msg);

    let (result, tunnel_id) = relay_out;
    assert_eq!(result.kind, CopyEndKind::IdleTimeout);
    assert_eq!(tunnel_id.as_deref(), Some("alive-1"));
    assert_ne!(
        result.request_id, 0,
        "a replay session must mint a correlation id"
    );

    let rendered = String::from_utf8(captured.lock().unwrap().clone()).unwrap();
    let decision_line = rendered
        .lines()
        .find(|line| line.contains("safe HTTP silence replay decision"))
        .unwrap_or_else(|| {
            panic!("expected one decision record at the trigger, got: {rendered:?}")
        });
    // Required fields: the correlation id, the decision, the
    // primary tunnel, the target, and the decision offsets.
    assert_line_has_fields(decision_line, REPLAY_DECISION_FIELDS);
    // The same id joins the decision to the race resolution and to
    // the session outcome.
    let id = request_id_in_line(decision_line).expect("decision record must carry a numeric id");
    assert_eq!(result.request_id, id);
    let won_line = rendered
        .lines()
        .find(|line| line.contains("secondary won the race"))
        .unwrap_or_else(|| panic!("expected the secondary-win line, got: {rendered:?}"));
    assert!(
        won_line.contains(&format!("request_id={id}")),
        "race resolution must carry the same id, got: {won_line:?}"
    );
    // Behaviour unchanged: the replay still fired exactly once.
    let metrics = replay_metrics();
    assert_eq!(metrics.silence_trigger.load(Ordering::Relaxed), 1);
    assert_eq!(metrics.request_sent.load(Ordering::Relaxed), 1);
    assert_eq!(metrics.secondary_wins.load(Ordering::Relaxed), 1);
}

/// Drain all 10 bucket tokens through the admission API: each
/// admitted guard is dropped at the end of the statement, so the
/// bucket — not the concurrency cap — is what runs out.
fn drain_replay_bucket_tokens() {
    use crate::proxy::replay::{ReplayAdmission, replay_budget_try_start};
    for _ in 0..10 {
        assert!(matches!(
            replay_budget_try_start(),
            ReplayAdmission::Admitted { .. }
        ));
    }
}

#[tokio::test]
async fn test_replay_suppression_budget_records_reason() {
    use crate::proxy::replay::{REPLAY_TEST_LOCK, replay_metrics, reset_replay_state_for_tests};
    use crate::proxy::router::connect_via_router;
    use crate::proxy::{
        CopyEndKind, ZeroResponseRetry, copy_bidirectional_with_zero_response_retry,
    };

    // fix13: when the 2.5 s trigger fires but the global bucket is
    // empty, the suppression record names the reason
    // (`token_empty`: the bucket ran out while slots were free)
    // under the session's id — the exact record the fix12
    // measurement was missing. fix14 (GPT round 7): the record
    // also carries the budget state the decision was based on.
    let _replay_guard = REPLAY_TEST_LOCK.lock().await;
    reset_replay_state_for_tests();
    drain_replay_bucket_tokens();

    let captured = Arc::new(Mutex::new(Vec::new()));
    let subscriber = tracing_subscriber::fmt()
        .with_max_level(tracing::Level::DEBUG)
        .with_ansi(false)
        .with_writer(VecMakeWriter(Arc::clone(&captured)))
        .finish();
    let _guard = tracing::subscriber::set_default(subscriber);

    let msg = b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n";
    let blackhole_addr = spawn_blackhole_tcp_server(usize::MAX).await;
    let echo_addr = spawn_echo_tcp_server().await;
    let target = TargetAddr::Ip(test_echo_target(echo_addr));

    let pool = Arc::new(PoolRouter::new(PoolStrategy::RoundRobin, true));
    pool.add_tunnel(
        "dead-1",
        Arc::new(MockTunnelTarget::new("dead-1").with_dial_redirect(blackhole_addr)),
    );
    pool.add_tunnel(
        "alive-1",
        Arc::new(MockTunnelTarget::new("alive-1").with_dial_redirect(echo_addr)),
    );
    let router: Arc<dyn TunnelRouter> = pool;
    let selector = TunnelSelector::DefaultPool;

    let (first_stream, first_id, _) = connect_via_router(&router, &selector, &target, None, None)
        .await
        .expect("first dial must succeed");
    assert_eq!(first_id.as_deref(), Some("dead-1"));

    let (mut client, mut server) = tokio::io::duplex(2048);
    let retry = ZeroResponseRetry::new(&router, &selector, &target, None, "SOCKS5", Vec::new());
    let (relay_out, ()) = tokio::time::timeout(Duration::from_secs(10), async {
        tokio::join!(
            async move {
                let mut tunnel_id = first_id;
                let result = copy_bidirectional_with_zero_response_retry(
                    &mut server,
                    first_stream,
                    Duration::from_secs(5),
                    Some(retry),
                    &mut tunnel_id,
                )
                .await;
                (result, tunnel_id)
            },
            async {
                client.write_all(msg).await.unwrap();
                // Wait past the silence timer, then give up the way
                // curl does at its timeout: drop the client half.
                tokio::time::sleep(Duration::from_millis(3000)).await;
                drop(client);
            },
        )
    })
    .await
    .expect("test must finish within 10s");

    let (result, tunnel_id) = relay_out;
    assert_eq!(result.kind, CopyEndKind::ClientAborted);
    assert_eq!(tunnel_id.as_deref(), Some("dead-1"));
    assert_ne!(result.request_id, 0);

    let metrics = replay_metrics();
    assert_eq!(metrics.silence_trigger.load(Ordering::Relaxed), 0);
    assert_eq!(metrics.dial_started.load(Ordering::Relaxed), 0);
    assert_eq!(metrics.suppressed_token_empty.load(Ordering::Relaxed), 1);
    assert_eq!(
        metrics.suppressed_concurrency_full.load(Ordering::Relaxed),
        0
    );
    assert_eq!(metrics.suppressed_both_exhausted.load(Ordering::Relaxed), 0);

    let rendered = String::from_utf8(captured.lock().unwrap().clone()).unwrap();
    let suppressed_line = rendered
        .lines()
        .find(|line| line.contains("safe HTTP silence replay suppressed"))
        .unwrap_or_else(|| panic!("expected one suppression record, got: {rendered:?}"));
    assert_line_has_fields(
        suppressed_line,
        &[
            "request_id=",
            "token_empty",
            "dead-1",
            "decision_timestamp=",
            "request_forwarded_ms=",
            "silence_trigger_ms=",
            "active_replays=",
            "bucket_tokens=",
            "token_available=",
            "slot_available=",
            "admission_result=",
        ],
    );
}

#[tokio::test]
async fn test_replay_budget_suppression_splits_token_and_slot() {
    use crate::proxy::replay::{
        REPLAY_TEST_LOCK, ReplayAdmission, ReplaySlotGuard, SuppressReason,
        replay_budget_concurrent_for_tests, replay_budget_try_start, reset_replay_state_for_tests,
    };

    // GPT round 7: the old `budget_exhausted` hid which of the two
    // constraints bound the replay — an empty token bucket or a
    // full concurrency cap. The admission classifies both at the
    // decision point and names the binding one (or both).
    let _replay_guard = REPLAY_TEST_LOCK.lock().await;
    reset_replay_state_for_tests();

    // Admit one replay and keep its concurrency slot held; the
    // token is spent at reservation. The caller drives the budget
    // into a known state first, so an admission must succeed here.
    let admit_holding_slot = || match replay_budget_try_start() {
        ReplayAdmission::Admitted {
            slot,
            token: _token,
            ..
        } => slot,
        ReplayAdmission::Suppressed { reason, .. } => {
            panic!("expected admission, got suppression {reason:?}")
        }
    };

    // Concurrency full, tokens available: hold all 4 slots (6 of
    // the 10 tokens still left) and the next admission names the
    // full cap, not the bucket.
    let mut held: Vec<ReplaySlotGuard> = Vec::new();
    for _ in 0..4 {
        held.push(admit_holding_slot());
    }
    assert_eq!(replay_budget_concurrent_for_tests(), 4);
    match replay_budget_try_start() {
        ReplayAdmission::Suppressed { reason, snapshot } => {
            assert_eq!(reason, SuppressReason::ConcurrencyFull);
            assert_eq!(snapshot.tokens, 6);
            assert_eq!(snapshot.concurrent, 4);
            assert!(snapshot.token_available());
            assert!(!snapshot.slot_available());
        }
        ReplayAdmission::Admitted { .. } => panic!("expected suppression, got admission"),
    }
    drop(held);
    assert_eq!(replay_budget_concurrent_for_tests(), 0);

    // Token empty, slots free: spend the remaining 6 tokens one at
    // a time (releasing each slot right away) and the next
    // admission names the empty bucket, not the cap.
    for _ in 0..6 {
        drop(admit_holding_slot());
    }
    assert_eq!(replay_budget_concurrent_for_tests(), 0);
    match replay_budget_try_start() {
        ReplayAdmission::Suppressed { reason, snapshot } => {
            assert_eq!(reason, SuppressReason::TokenEmpty);
            assert_eq!(snapshot.tokens, 0);
            assert_eq!(snapshot.concurrent, 0);
            assert!(!snapshot.token_available());
            assert!(snapshot.slot_available());
        }
        ReplayAdmission::Admitted { .. } => panic!("expected suppression, got admission"),
    }

    // Both exhausted: spend the tokens while all 4 slots are held.
    // Admit in waves — 4, then 2 at a time after releasing 2 — so
    // the last admissions leave the bucket empty with the cap
    // still full.
    reset_replay_state_for_tests();
    let mut held: Vec<ReplaySlotGuard> = Vec::new();
    for _ in 0..4 {
        held.push(admit_holding_slot());
    }
    for _ in 0..3 {
        held.truncate(2);
        for _ in 0..2 {
            held.push(admit_holding_slot());
        }
    }
    assert_eq!(replay_budget_concurrent_for_tests(), 4);
    match replay_budget_try_start() {
        ReplayAdmission::Suppressed { reason, snapshot } => {
            assert_eq!(reason, SuppressReason::BothExhausted);
            assert_eq!(snapshot.tokens, 0);
            assert_eq!(snapshot.concurrent, 4);
            assert!(!snapshot.token_available());
            assert!(!snapshot.slot_available());
        }
        ReplayAdmission::Admitted { .. } => panic!("expected suppression, got admission"),
    }
    drop(held);
}

#[tokio::test]
async fn test_replay_dial_not_sent_records_no_tunnel_reason() {
    use crate::proxy::replay::{REPLAY_TEST_LOCK, replay_metrics, reset_replay_state_for_tests};
    use crate::proxy::router::connect_via_router;
    use crate::proxy::{
        CopyEndKind, ZeroResponseRetry, copy_bidirectional_with_zero_response_retry,
    };

    // fix13: a replay whose dial ends without sending the request
    // records why — here the pool holds only the primary tunnel, so
    // there is no alternate to dial through.
    let _replay_guard = REPLAY_TEST_LOCK.lock().await;
    reset_replay_state_for_tests();

    let captured = Arc::new(Mutex::new(Vec::new()));
    let subscriber = tracing_subscriber::fmt()
        .with_max_level(tracing::Level::DEBUG)
        .with_ansi(false)
        .with_writer(VecMakeWriter(Arc::clone(&captured)))
        .finish();
    let _guard = tracing::subscriber::set_default(subscriber);

    let msg = b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n";
    let blackhole_addr = spawn_blackhole_tcp_server(usize::MAX).await;
    let echo_addr = spawn_echo_tcp_server().await;
    let target = TargetAddr::Ip(test_echo_target(echo_addr));

    let pool = Arc::new(PoolRouter::new(PoolStrategy::RoundRobin, true));
    pool.add_tunnel(
        "dead-1",
        Arc::new(MockTunnelTarget::new("dead-1").with_dial_redirect(blackhole_addr)),
    );
    let router: Arc<dyn TunnelRouter> = pool;
    let selector = TunnelSelector::DefaultPool;

    let (first_stream, first_id, _) = connect_via_router(&router, &selector, &target, None, None)
        .await
        .expect("first dial must succeed");
    assert_eq!(first_id.as_deref(), Some("dead-1"));

    let (mut client, mut server) = tokio::io::duplex(2048);
    let retry = ZeroResponseRetry::new(&router, &selector, &target, None, "SOCKS5", Vec::new());
    let (relay_out, ()) = tokio::time::timeout(Duration::from_secs(10), async {
        tokio::join!(
            async move {
                let mut tunnel_id = first_id;
                let result = copy_bidirectional_with_zero_response_retry(
                    &mut server,
                    first_stream,
                    Duration::from_secs(5),
                    Some(retry),
                    &mut tunnel_id,
                )
                .await;
                (result, tunnel_id)
            },
            async {
                client.write_all(msg).await.unwrap();
                tokio::time::sleep(Duration::from_millis(3000)).await;
                drop(client);
            },
        )
    })
    .await
    .expect("test must finish within 10s");

    let (result, tunnel_id) = relay_out;
    assert_eq!(result.kind, CopyEndKind::ClientAborted);
    assert_eq!(tunnel_id.as_deref(), Some("dead-1"));

    let metrics = replay_metrics();
    assert_eq!(metrics.silence_trigger.load(Ordering::Relaxed), 1);
    assert_eq!(metrics.dial_started.load(Ordering::Relaxed), 1);
    assert_eq!(metrics.request_sent.load(Ordering::Relaxed), 0);
    assert_eq!(metrics.dial_failed.load(Ordering::Relaxed), 0);
    assert_eq!(metrics.suppressed_no_tunnel.load(Ordering::Relaxed), 1);

    let rendered = String::from_utf8(captured.lock().unwrap().clone()).unwrap();
    let suppressed_line = rendered
        .lines()
        .find(|line| line.contains("safe HTTP silence replay suppressed"))
        .unwrap_or_else(|| panic!("expected one suppression record, got: {rendered:?}"));
    assert_line_has_fields(suppressed_line, &["request_id=", "no_tunnel", "dead-1"]);
    // The decision record fired first (the dial started), under the
    // same id as the suppression that followed it.
    let decision_line = rendered
        .lines()
        .find(|line| line.contains("safe HTTP silence replay decision"))
        .unwrap_or_else(|| panic!("expected the decision record, got: {rendered:?}"));
    let decision_id = request_id_in_line(decision_line).expect("decision record must carry an id");
    let suppressed_id =
        request_id_in_line(suppressed_line).expect("suppression record must carry an id");
    assert_eq!(decision_id, suppressed_id);
    assert_eq!(result.request_id, decision_id);
}

/// Assert the fix15 terminal-outcome counters, in
/// `request_sent, dial_failed, primary_won, client_closed, other`
/// order. Each started dial ends in exactly one outcome, so callers
/// assert the total against `dial_started` separately.
fn assert_dial_outcome_counts(
    sent: u64,
    failed: u64,
    primary_won: u64,
    client_closed: u64,
    other: u64,
) {
    use crate::proxy::replay::replay_metrics;
    let metrics = replay_metrics();
    assert_eq!(
        metrics.dial_outcome_request_sent.load(Ordering::Relaxed),
        sent
    );
    assert_eq!(
        metrics.dial_outcome_dial_failed.load(Ordering::Relaxed),
        failed
    );
    assert_eq!(
        metrics
            .dial_outcome_cancelled_primary_won
            .load(Ordering::Relaxed),
        primary_won
    );
    assert_eq!(
        metrics
            .dial_outcome_cancelled_client_closed
            .load(Ordering::Relaxed),
        client_closed
    );
    assert_eq!(
        metrics.dial_outcome_cancelled_other.load(Ordering::Relaxed),
        other
    );
}

/// Fields every fix15 dial-outcome record must carry: the session
/// id, the terminal outcome, and the per-stage dial timestamps as
/// millisecond offsets from the session start.
const DIAL_OUTCOME_FIELDS: &[&str] = &[
    "request_id=",
    "outcome=",
    "secondary_dial_started_ms=",
    "dns_started_ms=",
    "dns_completed_ms=",
    "tunnel_ready_ms=",
    "tcp_connect_started_ms=",
    "tcp_connected_ms=",
    "primary_closed_ms=",
];

#[tokio::test]
async fn test_replay_dial_primary_wins_before_send_records_terminal_outcome() {
    use crate::proxy::replay::{REPLAY_TEST_LOCK, replay_metrics, reset_replay_state_for_tests};
    use crate::proxy::router::connect_via_router;
    use crate::proxy::{
        CopyEndKind, ZeroResponseRetry, copy_bidirectional_with_zero_response_retry,
    };

    // fix15: a secondary dial that ends because the primary answered
    // first — the primary echoes at ~2.8 s, the secondary dial takes
    // ~1 s from the 2.5 s trigger, so the pre-send check finds
    // response bytes — records exactly one terminal outcome
    // (`cancelled_primary_won_before_send`), and the outcome record
    // carries the same request id as the trigger decision.
    let _replay_guard = REPLAY_TEST_LOCK.lock().await;
    reset_replay_state_for_tests();

    let captured = Arc::new(Mutex::new(Vec::new()));
    let subscriber = tracing_subscriber::fmt()
        .with_max_level(tracing::Level::DEBUG)
        .with_ansi(false)
        .with_writer(VecMakeWriter(Arc::clone(&captured)))
        .finish();
    let _guard = tracing::subscriber::set_default(subscriber);

    let msg = b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n";
    let slow_addr = spawn_delayed_echo_keep_open_tcp_server(Duration::from_millis(2800)).await;
    let echo_addr = spawn_echo_tcp_server().await;
    let target = TargetAddr::Ip(test_echo_target(echo_addr));

    let pool = Arc::new(PoolRouter::new(PoolStrategy::RoundRobin, true));
    pool.add_tunnel(
        "slow-1",
        Arc::new(MockTunnelTarget::new("slow-1").with_dial_redirect(slow_addr)),
    );
    pool.add_tunnel(
        "alive-1",
        Arc::new(
            MockTunnelTarget::new("alive-1")
                .with_dial_redirect(echo_addr)
                .with_tcp_delay(Duration::from_millis(1000)),
        ),
    );
    let router: Arc<dyn TunnelRouter> = pool;
    let selector = TunnelSelector::DefaultPool;

    let (first_stream, first_id, _) = connect_via_router(&router, &selector, &target, None, None)
        .await
        .expect("first dial must succeed");
    assert_eq!(first_id.as_deref(), Some("slow-1"));

    let (mut client, mut server) = tokio::io::duplex(2048);
    let retry = ZeroResponseRetry::new(&router, &selector, &target, None, "SOCKS5", Vec::new());
    let (relay_out, echo_buf) = tokio::time::timeout(Duration::from_secs(10), async {
        tokio::join!(
            async move {
                let mut tunnel_id = first_id;
                let result = copy_bidirectional_with_zero_response_retry(
                    &mut server,
                    first_stream,
                    Duration::from_secs(3),
                    Some(retry),
                    &mut tunnel_id,
                )
                .await;
                (result, tunnel_id)
            },
            async {
                client.write_all(msg).await.unwrap();
                let mut echo_buf = vec![0u8; msg.len()];
                client.read_exact(&mut echo_buf).await.unwrap();
                echo_buf
            },
        )
    })
    .await
    .expect("test must finish within 10s");
    assert_eq!(&echo_buf, msg);

    let (result, tunnel_id) = relay_out;
    assert_eq!(result.kind, CopyEndKind::IdleTimeout);
    assert_eq!(tunnel_id.as_deref(), Some("slow-1"));

    // Exactly one terminal outcome, and the outcome family sums to
    // the started dials: no started dial ends without an outcome.
    let metrics = replay_metrics();
    assert_eq!(metrics.silence_trigger.load(Ordering::Relaxed), 1);
    assert_eq!(metrics.dial_started.load(Ordering::Relaxed), 1);
    assert_eq!(metrics.request_sent.load(Ordering::Relaxed), 0);
    assert_dial_outcome_counts(0, 0, 1, 0, 0);

    let rendered = String::from_utf8(captured.lock().unwrap().clone()).unwrap();
    let outcome_line = rendered
        .lines()
        .find(|line| line.contains("safe HTTP silence replay dial outcome"))
        .unwrap_or_else(|| panic!("expected one dial-outcome record, got: {rendered:?}"));
    assert_line_has_fields(outcome_line, DIAL_OUTCOME_FIELDS);
    assert!(
        outcome_line.contains("cancelled_primary_won_before_send"),
        "outcome must name the primary winning first, got: {outcome_line:?}"
    );
    let outcome_id =
        request_id_in_line(outcome_line).expect("outcome record must carry a numeric id");
    assert_eq!(result.request_id, outcome_id);
    let decision_line = rendered
        .lines()
        .find(|line| line.contains("safe HTTP silence replay decision"))
        .unwrap_or_else(|| panic!("expected the decision record, got: {rendered:?}"));
    assert_eq!(
        request_id_in_line(decision_line).expect("decision record must carry an id"),
        outcome_id
    );
}

#[tokio::test]
async fn test_replay_dial_records_stage_timestamps() {
    use crate::proxy::replay::{
        REPLAY_TEST_LOCK, ReplayDialCtx, ReplayDialOutcome, SilenceReplay, dial_secondary_leg,
        next_replay_request_id, reset_replay_state_for_tests,
    };

    // fix15: a secondary dial through a domain target records every
    // stage it passes through — tunnel selection, DNS, TCP connect
    // — on the shared timings, and ends with the `request_sent`
    // terminal outcome.
    let _replay_guard = REPLAY_TEST_LOCK.lock().await;
    reset_replay_state_for_tests();

    let captured = Arc::new(Mutex::new(Vec::new()));
    let subscriber = tracing_subscriber::fmt()
        .with_max_level(tracing::Level::INFO)
        .with_ansi(false)
        .with_writer(VecMakeWriter(Arc::clone(&captured)))
        .finish();
    let _guard = tracing::subscriber::set_default(subscriber);

    let echo_addr = spawn_echo_tcp_server().await;
    let pool = Arc::new(PoolRouter::new(PoolStrategy::RoundRobin, true));
    pool.add_tunnel(
        "stage-1",
        Arc::new(
            MockTunnelTarget::new("stage-1")
                .with_dns("example.test", TEST_ECHO_IP)
                .with_dial_redirect(echo_addr),
        ),
    );
    let router: Arc<dyn TunnelRouter> = pool;

    let header: Arc<[u8]> = Arc::from(b"GET / HTTP/1.1\r\nHost: example.test\r\n\r\n".as_slice());
    let replay = SilenceReplay::new();
    let shared = Arc::clone(&replay.shared);
    let ctx = Arc::new(ReplayDialCtx {
        router: Arc::clone(&router),
        selector: TunnelSelector::DefaultPool,
        target: TargetAddr::Domain("example.test".to_string(), echo_addr.port()),
        credentials: None,
        protocol: "SOCKS5",
        request_id: next_replay_request_id(),
        session_started_at: std::time::Instant::now(),
    });
    let outcome = dial_secondary_leg(
        ctx,
        None,
        header,
        Arc::new(AtomicU64::new(0)),
        Arc::new(AtomicU64::new(0)),
        Arc::clone(&shared),
    )
    .await;
    assert!(
        matches!(outcome, ReplayDialOutcome::Ready(_)),
        "domain dial through the mock must send the GET, got a terminal failure instead"
    );

    let timings = shared.timings.lock();
    assert!(
        timings.dial_started_at.is_some(),
        "dial start must be stamped"
    );
    assert!(
        timings.dns_started_at.is_some(),
        "DNS start must be stamped"
    );
    assert!(
        timings.dns_completed_at.is_some(),
        "DNS completion must be stamped"
    );
    assert!(
        timings.tunnel_ready_at.is_some(),
        "tunnel selection must be stamped"
    );
    assert!(
        timings.tcp_connect_started_at.is_some(),
        "TCP connect start must be stamped"
    );
    assert!(
        timings.dial_connected_at.is_some(),
        "TCP connect must be stamped"
    );
    assert!(
        timings.primary_closed_at.is_none(),
        "no primary closed during this dial"
    );
    drop(timings);

    assert_dial_outcome_counts(1, 0, 0, 0, 0);

    let rendered = String::from_utf8(captured.lock().unwrap().clone()).unwrap();
    let outcome_line = rendered
        .lines()
        .find(|line| line.contains("safe HTTP silence replay dial outcome"))
        .unwrap_or_else(|| panic!("expected one dial-outcome record, got: {rendered:?}"));
    assert_line_has_fields(outcome_line, DIAL_OUTCOME_FIELDS);
    assert!(
        outcome_line.contains("request_sent"),
        "outcome must be request_sent, got: {outcome_line:?}"
    );
}

#[tokio::test]
async fn test_replay_dial_aborted_records_cancelled_other() {
    use crate::proxy::replay::{
        REPLAY_TEST_LOCK, ReplayDialCtx, SilenceReplay, dial_secondary_leg, next_replay_request_id,
        reset_replay_state_for_tests,
    };

    // fix15: a dial task aborted mid-flight (its epoch ended before
    // the dial returned) still ends with exactly one terminal
    // outcome — the guard's drop records `cancelled_other` when the
    // primary never answered and the client never went away.
    let _replay_guard = REPLAY_TEST_LOCK.lock().await;
    reset_replay_state_for_tests();

    let captured = Arc::new(Mutex::new(Vec::new()));
    let subscriber = tracing_subscriber::fmt()
        .with_max_level(tracing::Level::INFO)
        .with_ansi(false)
        .with_writer(VecMakeWriter(Arc::clone(&captured)))
        .finish();
    let _guard = tracing::subscriber::set_default(subscriber);

    let echo_addr = spawn_echo_tcp_server().await;
    let pool = Arc::new(PoolRouter::new(PoolStrategy::RoundRobin, true));
    pool.add_tunnel(
        "hang-1",
        Arc::new(MockTunnelTarget::new("hang-1").with_hanging_tcp()),
    );
    let router: Arc<dyn TunnelRouter> = pool;

    let header: Arc<[u8]> = Arc::from(b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n".as_slice());
    let replay = SilenceReplay::new();
    let shared = Arc::clone(&replay.shared);
    let ctx = Arc::new(ReplayDialCtx {
        router: Arc::clone(&router),
        selector: TunnelSelector::DefaultPool,
        target: TargetAddr::Ip(test_echo_target(echo_addr)),
        credentials: None,
        protocol: "SOCKS5",
        request_id: next_replay_request_id(),
        session_started_at: std::time::Instant::now(),
    });
    let handle = tokio::spawn(dial_secondary_leg(
        ctx,
        None,
        header,
        Arc::new(AtomicU64::new(0)),
        Arc::new(AtomicU64::new(0)),
        Arc::clone(&shared),
    ));
    tokio::time::sleep(Duration::from_millis(100)).await;
    handle.abort();
    let joined = handle.await;
    assert!(
        joined.is_err(),
        "the aborted dial task must not return normally"
    );

    assert_dial_outcome_counts(0, 0, 0, 0, 1);

    let rendered = String::from_utf8(captured.lock().unwrap().clone()).unwrap();
    let outcome_lines: Vec<&str> = rendered
        .lines()
        .filter(|line| line.contains("safe HTTP silence replay dial outcome"))
        .collect();
    assert_eq!(
        outcome_lines.len(),
        1,
        "an aborted dial must record exactly one outcome, got: {rendered:?}"
    );
    assert_line_has_fields(outcome_lines[0], DIAL_OUTCOME_FIELDS);
    assert!(
        outcome_lines[0].contains("cancelled_other"),
        "outcome must be cancelled_other, got: {:?}",
        outcome_lines[0]
    );
}

// -----------------------------------------------------------------------------
// Shared listener connection cap (audit run-3 #9)
// -----------------------------------------------------------------------------

/// Open a SOCKS5 session (no-auth greeting + CONNECT to `target`) and
/// return the held client stream; the session stays open against the
/// echo server, so it keeps holding its listener permit.
async fn open_socks5_session(listener_addr: SocketAddr, target: SocketAddr) -> TcpStream {
    let mut client = TcpStream::connect(listener_addr).await.unwrap();
    client
        .write_all(&[SOCKS5_VERSION, 1, METHOD_NO_AUTH])
        .await
        .unwrap();
    let mut resp = [0u8; 2];
    client.read_exact(&mut resp).await.unwrap();
    assert_eq!(resp, [SOCKS5_VERSION, METHOD_NO_AUTH]);
    let SocketAddr::V4(target_v4) = target else {
        unreachable!();
    };
    let mut req = vec![SOCKS5_VERSION, 0x01, 0x00, ATYP_IPV4];
    req.extend_from_slice(&target_v4.ip().octets());
    req.extend_from_slice(&target_v4.port().to_be_bytes());
    client.write_all(&req).await.unwrap();
    let mut reply = [0u8; 10];
    client.read_exact(&mut reply).await.unwrap();
    assert_eq!(reply[0], SOCKS5_VERSION);
    assert_eq!(reply[1], REP_SUCCESS);
    client
}

/// Open an HTTP CONNECT session to `target` and return the held
/// client stream; the session stays open against the echo server.
async fn open_http_session(listener_addr: SocketAddr, target: SocketAddr) -> TcpStream {
    let mut client = TcpStream::connect(listener_addr).await.unwrap();
    let req = format!("CONNECT {target} HTTP/1.1\r\nHost: {target}\r\n\r\n",);
    client.write_all(req.as_bytes()).await.unwrap();
    let (status, _, _, _) = read_http_headers_helper(&mut client).await.unwrap();
    assert_eq!(status, 200);
    client
}

#[tokio::test]
async fn test_shared_proxy_conn_cap_across_listeners() {
    // Audit run-3 #9: each public listener helper used to make its
    // own private 4096 semaphore, so 2x SOCKS5 + 1x HTTP served
    // 12275 aggregate ~= 3x4096 on Colab. With one shared budget,
    // sessions opened across all three listeners must draw from the
    // same pool: 9 held sessions consume exactly 9 permits. The
    // delta (not the absolute count) is asserted, so the test is
    // robust to other tests in the process holding permits.
    let echo_addr = spawn_echo_tcp_server().await;
    let target_addr = test_echo_target(echo_addr);
    let target = Arc::new(MockTunnelTarget::new("cap-tunnel").with_dial_redirect(echo_addr));
    let router: Arc<dyn TunnelRouter> =
        Arc::new(SingleTunnelRouter::new("cap-tunnel", target, None));

    let listener_a = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr_a = listener_a.local_addr().unwrap();
    let listener_b = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr_b = listener_b.local_addr().unwrap();
    let listener_c = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr_c = listener_c.local_addr().unwrap();
    let r = Arc::clone(&router);
    tokio::spawn(async move {
        let _ = super::run_socks5_listener(listener_a, r).await;
    });
    let r = Arc::clone(&router);
    tokio::spawn(async move {
        let _ = super::run_socks5_listener(listener_b, r).await;
    });
    let r = Arc::clone(&router);
    tokio::spawn(async move {
        let _ = super::run_http_listener(listener_c, r).await;
    });

    let baseline = super::SHARED_PROXY_CONN_SEM.available_permits();
    let mut held = Vec::new();
    for addr in [addr_a, addr_b] {
        for _ in 0..3 {
            held.push(open_socks5_session(addr, target_addr).await);
        }
    }
    for _ in 0..3 {
        held.push(open_http_session(addr_c, target_addr).await);
    }
    assert_eq!(
        baseline - super::SHARED_PROXY_CONN_SEM.available_permits(),
        9,
        "9 sessions across 3 listeners must consume 9 permits from one shared budget"
    );
    drop(held);
}

#[tokio::test]
async fn test_replay_budget_exhaustion_emits_no_warn() {
    use crate::proxy::replay::{REPLAY_TEST_LOCK, replay_metrics, reset_replay_state_for_tests};
    use crate::proxy::router::connect_via_router;
    use crate::proxy::{
        CopyEndKind, ZeroResponseRetry, copy_bidirectional_with_zero_response_retry,
    };

    // fix13: a normal budget exhaustion is not an operational
    // warning — the suppression is recorded at DEBUG, and nothing
    // at WARN or above is emitted while the trigger fires and the
    // session ends.
    let _replay_guard = REPLAY_TEST_LOCK.lock().await;
    reset_replay_state_for_tests();
    drain_replay_bucket_tokens();

    let captured = Arc::new(Mutex::new(Vec::new()));
    let subscriber = tracing_subscriber::fmt()
        .with_max_level(tracing::Level::WARN)
        .with_ansi(false)
        .with_writer(VecMakeWriter(Arc::clone(&captured)))
        .finish();
    let _guard = tracing::subscriber::set_default(subscriber);

    let msg = b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n";
    let blackhole_addr = spawn_blackhole_tcp_server(usize::MAX).await;
    let echo_addr = spawn_echo_tcp_server().await;
    let target = TargetAddr::Ip(test_echo_target(echo_addr));

    let pool = Arc::new(PoolRouter::new(PoolStrategy::RoundRobin, true));
    pool.add_tunnel(
        "dead-1",
        Arc::new(MockTunnelTarget::new("dead-1").with_dial_redirect(blackhole_addr)),
    );
    pool.add_tunnel(
        "alive-1",
        Arc::new(MockTunnelTarget::new("alive-1").with_dial_redirect(echo_addr)),
    );
    let router: Arc<dyn TunnelRouter> = pool;
    let selector = TunnelSelector::DefaultPool;

    let (first_stream, first_id, _) = connect_via_router(&router, &selector, &target, None, None)
        .await
        .expect("first dial must succeed");
    assert_eq!(first_id.as_deref(), Some("dead-1"));

    let (mut client, mut server) = tokio::io::duplex(2048);
    let retry = ZeroResponseRetry::new(&router, &selector, &target, None, "SOCKS5", Vec::new());
    let (relay_out, ()) = tokio::time::timeout(Duration::from_secs(10), async {
        tokio::join!(
            async move {
                let mut tunnel_id = first_id;
                let result = copy_bidirectional_with_zero_response_retry(
                    &mut server,
                    first_stream,
                    Duration::from_secs(5),
                    Some(retry),
                    &mut tunnel_id,
                )
                .await;
                (result, tunnel_id)
            },
            async {
                client.write_all(msg).await.unwrap();
                tokio::time::sleep(Duration::from_millis(3000)).await;
                drop(client);
            },
        )
    })
    .await
    .expect("test must finish within 10s");

    let (result, tunnel_id) = relay_out;
    assert_eq!(result.kind, CopyEndKind::ClientAborted);
    assert_eq!(tunnel_id.as_deref(), Some("dead-1"));

    let metrics = replay_metrics();
    assert_eq!(metrics.suppressed_token_empty.load(Ordering::Relaxed), 1);

    let rendered = String::from_utf8(captured.lock().unwrap().clone()).unwrap();
    assert!(
        rendered.is_empty(),
        "budget exhaustion must emit no WARN, got: {rendered:?}"
    );
}

// -----------------------------------------------------------------------------
// Failed-auth rate limiting (audit run-3 #1)
// -----------------------------------------------------------------------------

#[test]
fn test_failed_auth_limiter_blocks_after_threshold() {
    let limiter =
        FailedAuthLimiter::with_limits(3, Duration::from_secs(60), Duration::from_secs(60));
    let ip: IpAddr = "127.0.0.2".parse().unwrap();
    assert!(!limiter.is_blocked(ip));
    limiter.note_failure(ip);
    assert!(!limiter.is_blocked(ip));
    limiter.note_failure(ip);
    assert!(!limiter.is_blocked(ip));
    limiter.note_failure(ip);
    assert!(limiter.is_blocked(ip));
}

#[test]
fn test_failed_auth_limiter_success_resets_failures() {
    let limiter =
        FailedAuthLimiter::with_limits(3, Duration::from_secs(60), Duration::from_secs(60));
    let ip: IpAddr = "127.0.0.2".parse().unwrap();
    limiter.note_failure(ip);
    limiter.note_failure(ip);
    limiter.note_success(ip);
    limiter.note_failure(ip);
    limiter.note_failure(ip);
    assert!(!limiter.is_blocked(ip));
}

#[test]
fn test_failed_auth_limiter_block_expires_and_resets() {
    let limiter =
        FailedAuthLimiter::with_limits(2, Duration::from_secs(60), Duration::from_millis(100));
    let ip: IpAddr = "127.0.0.2".parse().unwrap();
    limiter.note_failure(ip);
    limiter.note_failure(ip);
    assert!(limiter.is_blocked(ip));
    std::thread::sleep(Duration::from_millis(150));
    assert!(!limiter.is_blocked(ip));
    // Clean slate after the block: one more failure does not re-block.
    limiter.note_failure(ip);
    assert!(!limiter.is_blocked(ip));
}

#[test]
fn test_failed_auth_limiter_window_expiry_resets_failures() {
    let limiter =
        FailedAuthLimiter::with_limits(3, Duration::from_millis(100), Duration::from_secs(60));
    let ip: IpAddr = "127.0.0.2".parse().unwrap();
    limiter.note_failure(ip);
    limiter.note_failure(ip);
    std::thread::sleep(Duration::from_millis(150));
    limiter.note_failure(ip);
    assert!(!limiter.is_blocked(ip));
    limiter.note_failure(ip);
    limiter.note_failure(ip);
    assert!(limiter.is_blocked(ip));
}

#[test]
fn test_failed_auth_limiter_is_per_ip() {
    let limiter =
        FailedAuthLimiter::with_limits(2, Duration::from_secs(60), Duration::from_secs(60));
    let blocked: IpAddr = "127.0.0.2".parse().unwrap();
    let other: IpAddr = "127.0.0.3".parse().unwrap();
    limiter.note_failure(blocked);
    limiter.note_failure(blocked);
    assert!(limiter.is_blocked(blocked));
    assert!(!limiter.is_blocked(other));
}

/// One SOCKS5 RFC 1929 auth attempt from `peer_ip` over a duplex
/// stream; returns the RFC 1929 status byte (`0x00` success).
async fn socks5_auth_attempt(
    router: &Arc<dyn TunnelRouter>,
    peer_ip: IpAddr,
    user: &str,
    pass: &str,
) -> u8 {
    let (mut client, server) = tokio::io::duplex(1024);
    let r = Arc::clone(router);
    tokio::spawn(async move {
        let _ = handle_socks5_with_addrs(server, r, None, Some(peer_ip)).await;
    });
    client
        .write_all(&[SOCKS5_VERSION, 1, METHOD_USER_PASS])
        .await
        .unwrap();
    let mut g_resp = [0u8; 2];
    client.read_exact(&mut g_resp).await.unwrap();
    assert_eq!(g_resp, [SOCKS5_VERSION, METHOD_USER_PASS]);
    let mut auth_req = vec![RFC1929_VERSION, user.len() as u8];
    auth_req.extend_from_slice(user.as_bytes());
    auth_req.push(pass.len() as u8);
    auth_req.extend_from_slice(pass.as_bytes());
    client.write_all(&auth_req).await.unwrap();
    let mut a_resp = [0u8; 2];
    client.read_exact(&mut a_resp).await.unwrap();
    assert_eq!(a_resp[0], RFC1929_VERSION);
    a_resp[1]
}

#[tokio::test]
async fn test_socks5_auth_rate_limited_after_repeated_failures() {
    // Audit run-3 #1: 1000 wrong SOCKS5 credentials were answered
    // immediately at 283.6/s. After the threshold, even the correct
    // credential must be rejected while the source is blocked, and
    // another source must be unaffected.
    let ip: IpAddr = "127.0.0.2".parse().unwrap();
    let other_ip: IpAddr = "127.0.0.3".parse().unwrap();
    let target = Arc::new(DirectTunnelTarget);
    let router: Arc<dyn TunnelRouter> = Arc::new(SingleTunnelRouter::new(
        "auth-tunnel",
        target,
        Some(("alice".to_string(), "pass123".to_string())),
    ));
    for _ in 0..MAX_FAILED_AUTH_ATTEMPTS {
        assert_eq!(
            socks5_auth_attempt(&router, ip, "alice", "wrong").await,
            0x01,
            "wrong password must be rejected"
        );
    }
    assert_eq!(
        socks5_auth_attempt(&router, ip, "alice", "pass123").await,
        0x01,
        "correct password from a blocked source must still be rejected"
    );
    assert_eq!(
        socks5_auth_attempt(&router, other_ip, "alice", "pass123").await,
        0x00,
        "correct password from another source must succeed"
    );
}

/// One HTTP proxy CONNECT attempt from `peer_ip` over a duplex
/// stream; returns the HTTP status code of the first response.
async fn http_auth_attempt(
    router: &Arc<dyn TunnelRouter>,
    peer_ip: IpAddr,
    target_addr: SocketAddr,
    user: &str,
    pass: &str,
) -> u16 {
    let (mut client, server) = tokio::io::duplex(2048);
    let r = Arc::clone(router);
    tokio::spawn(async move {
        let _ = handle_http_with_peer(server, r, Some(peer_ip)).await;
    });
    let auth_hdr = format_basic_auth(user, pass);
    let req = format!(
        "CONNECT {target_addr} HTTP/1.1\r\nHost: {target_addr}\r\nProxy-Authorization: {auth_hdr}\r\n\r\n",
    );
    client.write_all(req.as_bytes()).await.unwrap();
    let (status, _, _, _) = read_http_headers_helper(&mut client).await.unwrap();
    status
}

#[tokio::test]
async fn test_http_auth_rate_limited_after_repeated_failures() {
    // Audit run-3 #1: 1000 wrong HTTP proxy credentials were answered
    // immediately at 345.8/s. After the threshold the source gets
    // 429, and another source still authenticates (200 via the echo
    // server behind the mock tunnel target).
    let echo_addr = spawn_echo_tcp_server().await;
    let target_addr = test_echo_target(echo_addr);
    let target = Arc::new(MockTunnelTarget::new("http-tunnel").with_dial_redirect(echo_addr));
    let router: Arc<dyn TunnelRouter> = Arc::new(SingleTunnelRouter::new(
        "http-tunnel",
        target,
        Some(("proxyuser".to_string(), "proxypass123".to_string())),
    ));
    let ip: IpAddr = "127.0.0.4".parse().unwrap();
    let other_ip: IpAddr = "127.0.0.5".parse().unwrap();
    for _ in 0..MAX_FAILED_AUTH_ATTEMPTS {
        assert_eq!(
            http_auth_attempt(&router, ip, target_addr, "proxyuser", "wrongpassword").await,
            407,
            "wrong password must be rejected with 407"
        );
    }
    assert_eq!(
        http_auth_attempt(&router, ip, target_addr, "proxyuser", "proxypass123").await,
        429,
        "correct password from a blocked source must be rate-limited"
    );
    assert_eq!(
        http_auth_attempt(&router, other_ip, target_addr, "proxyuser", "proxypass123").await,
        200,
        "correct password from another source must succeed"
    );
}
