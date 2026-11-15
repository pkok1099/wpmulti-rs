//! Proxy connector and routing abstractions.
//!
//! Defines traits and concrete types bridging proxy client requests (SOCKS5 and HTTP CONNECT)
//! to userspace network stacks ([`VirtualNetworkStack`]), direct connections, or multi-tunnel pools.

use std::collections::HashMap;
use std::future::Future;
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use parking_lot::RwLock;
use tokio::io::{AsyncRead, AsyncWrite};

use crate::config::{AuthMode, PoolStrategy};
use crate::netstack::{VirtualNetworkStack, VirtualUdpSocket};

/// Target destination requested by a proxy client.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TargetAddr {
    /// Direct IP socket address (IPv4 or IPv6).
    Ip(SocketAddr),
    /// Fully qualified domain name and destination port.
    Domain(String, u16),
}

impl std::fmt::Display for TargetAddr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Ip(addr) => write!(f, "{addr}"),
            Self::Domain(domain, port) => write!(f, "{domain}:{port}"),
        }
    }
}

/// Helper trait combining [`AsyncRead`], [`AsyncWrite`], [`Send`], and [`Unpin`].
pub trait AsyncReadWrite: AsyncRead + AsyncWrite + Send + Unpin {}
impl<T: AsyncRead + AsyncWrite + Send + Unpin> AsyncReadWrite for T {}

/// Dynamically dispatched asynchronous bidirectional byte stream.
pub type DynStream = Box<dyn AsyncReadWrite>;

/// Future returned by [`ProxyUdpSocket::recv_from`].
pub type RecvFromFut<'a> =
    Pin<Box<dyn Future<Output = io::Result<(usize, SocketAddr)>> + Send + 'a>>;

/// Future returned by [`ProxyTunnelTarget::udp_bind`].
pub type UdpBindFut<'a> =
    Pin<Box<dyn Future<Output = io::Result<Box<dyn ProxyUdpSocket>>> + Send + 'a>>;

/// Future returned by [`TunnelRouter::select_tunnel`].
pub type SelectTunnelFut<'a> =
    Pin<Box<dyn Future<Output = io::Result<Arc<dyn ProxyTunnelTarget>>> + Send + 'a>>;

/// Trait abstracting a virtual or physical UDP socket used by proxy relays.
pub trait ProxyUdpSocket: Send + Sync {
    /// Send a UDP datagram to the specified destination.
    fn send_to<'a>(
        &'a self,
        buf: &'a [u8],
        target: SocketAddr,
    ) -> Pin<Box<dyn Future<Output = io::Result<usize>> + Send + 'a>>;

    /// Receive a UDP datagram into the provided buffer.
    fn recv_from<'a>(&'a self, buf: &'a mut [u8]) -> RecvFromFut<'a>;

    /// Returns the bound local port of this UDP socket.
    fn local_port(&self) -> u16;
}

impl ProxyUdpSocket for VirtualUdpSocket {
    fn send_to<'a>(
        &'a self,
        buf: &'a [u8],
        target: SocketAddr,
    ) -> Pin<Box<dyn Future<Output = io::Result<usize>> + Send + 'a>> {
        Box::pin(async move { self.send_to(buf, target).await })
    }

    fn recv_from<'a>(
        &'a self,
        buf: &'a mut [u8],
    ) -> Pin<Box<dyn Future<Output = io::Result<(usize, SocketAddr)>> + Send + 'a>> {
        Box::pin(async move { self.recv_from(buf).await })
    }

    fn local_port(&self) -> u16 {
        self.local_port()
    }
}

impl ProxyUdpSocket for tokio::net::UdpSocket {
    fn send_to<'a>(
        &'a self,
        buf: &'a [u8],
        target: SocketAddr,
    ) -> Pin<Box<dyn Future<Output = io::Result<usize>> + Send + 'a>> {
        Box::pin(async move { Self::send_to(self, buf, target).await })
    }

    fn recv_from<'a>(
        &'a self,
        buf: &'a mut [u8],
    ) -> Pin<Box<dyn Future<Output = io::Result<(usize, SocketAddr)>> + Send + 'a>> {
        Box::pin(async move { Self::recv_from(self, buf).await })
    }

    fn local_port(&self) -> u16 {
        self.local_addr().map_or(0, |a| a.port())
    }
}

/// Abstract tunnel connector capable of establishing TCP streams, binding UDP sockets,
/// and resolving domain names through a WireGuard tunnel.
pub trait ProxyTunnelTarget: Send + Sync {
    /// Connect a TCP stream to the destination IP and port.
    fn tcp_connect<'a>(
        &'a self,
        dst: SocketAddr,
    ) -> Pin<Box<dyn Future<Output = io::Result<DynStream>> + Send + 'a>>;

    /// Bind a UDP socket in the tunnel.
    fn udp_bind(&self, local_port: u16) -> UdpBindFut<'_>;

    /// Resolve a domain name inside the tunnel.
    fn resolve_in_tunnel<'a>(
        &'a self,
        domain: &'a str,
    ) -> Pin<Box<dyn Future<Output = io::Result<IpAddr>> + Send + 'a>>;
}

impl ProxyTunnelTarget for VirtualNetworkStack {
    fn tcp_connect<'a>(
        &'a self,
        dst: SocketAddr,
    ) -> Pin<Box<dyn Future<Output = io::Result<DynStream>> + Send + 'a>> {
        Box::pin(async move {
            let stream: DynStream = Box::new(self.tcp_connect(dst).await?);
            Ok(stream)
        })
    }

    fn udp_bind<'a>(
        &'a self,
        local_port: u16,
    ) -> Pin<Box<dyn Future<Output = io::Result<Box<dyn ProxyUdpSocket>>> + Send + 'a>> {
        Box::pin(async move {
            let sock: Box<dyn ProxyUdpSocket> = Box::new(self.udp_bind(local_port).await?);
            Ok(sock)
        })
    }

    fn resolve_in_tunnel<'a>(
        &'a self,
        domain: &'a str,
    ) -> Pin<Box<dyn Future<Output = io::Result<IpAddr>> + Send + 'a>> {
        Box::pin(async move { self.resolve_in_tunnel(domain).await })
    }
}

impl<T: ProxyTunnelTarget + ?Sized> ProxyTunnelTarget for Arc<T> {
    fn tcp_connect<'a>(
        &'a self,
        dst: SocketAddr,
    ) -> Pin<Box<dyn Future<Output = io::Result<DynStream>> + Send + 'a>> {
        (**self).tcp_connect(dst)
    }

    fn udp_bind<'a>(
        &'a self,
        local_port: u16,
    ) -> Pin<Box<dyn Future<Output = io::Result<Box<dyn ProxyUdpSocket>>> + Send + 'a>> {
        (**self).udp_bind(local_port)
    }

    fn resolve_in_tunnel<'a>(
        &'a self,
        domain: &'a str,
    ) -> Pin<Box<dyn Future<Output = io::Result<IpAddr>> + Send + 'a>> {
        (**self).resolve_in_tunnel(domain)
    }
}

/// Direct host connector bypassing WireGuard tunnels (useful for loopback testing).
#[derive(Debug)]
pub struct DirectTunnelTarget;

impl ProxyTunnelTarget for DirectTunnelTarget {
    fn tcp_connect<'a>(
        &'a self,
        dst: SocketAddr,
    ) -> Pin<Box<dyn Future<Output = io::Result<DynStream>> + Send + 'a>> {
        Box::pin(async move {
            let stream: DynStream = Box::new(tokio::net::TcpStream::connect(dst).await?);
            Ok(stream)
        })
    }

    fn udp_bind<'a>(
        &'a self,
        local_port: u16,
    ) -> Pin<Box<dyn Future<Output = io::Result<Box<dyn ProxyUdpSocket>>> + Send + 'a>> {
        Box::pin(async move {
            let bind_addr = SocketAddr::from(([0, 0, 0, 0], local_port));
            let socket: Box<dyn ProxyUdpSocket> =
                Box::new(tokio::net::UdpSocket::bind(bind_addr).await?);
            Ok(socket)
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
            let host_port = format!("{domain}:0");
            let mut addrs = tokio::net::lookup_host(&host_port).await?;
            addrs
                .next()
                .map(|s| s.ip())
                .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "no addresses found"))
        })
    }
}

/// Pool strategy keyword parsed from username.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PoolKeyword {
    Auto,
    Random,
    RoundRobin,
    LeastConn,
}

/// Tunnel selector extracted from client authentication username or connection mode.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TunnelSelector {
    /// Explicit tunnel ID (e.g., "wgcf-001").
    ById(String),
    /// Tunnel pool strategy keyword ("auto", "random", "round-robin", "least-conn").
    ByKeyword(PoolKeyword),
    /// Group tag selector ("tag:premium").
    ByTag(String),
    /// Default pool strategy selection when unauthenticated or omitted.
    DefaultPool,
}

impl TunnelSelector {
    /// Parse username string into a `TunnelSelector`.
    pub fn parse(username: &str) -> Self {
        let u = username.trim();
        if u.is_empty() || u.eq_ignore_ascii_case("default") {
            return Self::DefaultPool;
        }
        if u.eq_ignore_ascii_case("auto") {
            return Self::ByKeyword(PoolKeyword::Auto);
        }
        if u.eq_ignore_ascii_case("random") {
            return Self::ByKeyword(PoolKeyword::Random);
        }
        if u.eq_ignore_ascii_case("round-robin") || u.eq_ignore_ascii_case("roundrobin") {
            return Self::ByKeyword(PoolKeyword::RoundRobin);
        }
        if u.eq_ignore_ascii_case("least-conn") || u.eq_ignore_ascii_case("leastconn") {
            return Self::ByKeyword(PoolKeyword::LeastConn);
        }
        if let Some(tag) = u.strip_prefix("tag:") {
            return Self::ByTag(tag.to_string());
        }
        Self::ById(u.to_string())
    }
}

/// Errors during proxy authentication or tunnel resolution.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ProxyAuthError {
    #[error("Proxy authentication required")]
    AuthRequired,
    #[error("Invalid proxy credentials")]
    InvalidCredentials,
    #[error("Tunnel with ID '{0}' not found")]
    TunnelNotFound(String),
    #[error("No available tunnel in pool")]
    NoAvailableTunnel,
}

/// Core router interface responsible for verifying proxy credentials and selecting
/// a target tunnel connector.
pub trait TunnelRouter: Send + Sync {
    /// Validate client credentials (if provided or required) and return a [`TunnelSelector`].
    fn authenticate(
        &self,
        credentials: Option<(&str, &str)>,
    ) -> Result<TunnelSelector, ProxyAuthError>;

    /// Resolve a [`TunnelSelector`] to an active [`ProxyTunnelTarget`].
    fn select_tunnel<'a>(&'a self, selector: &'a TunnelSelector) -> SelectTunnelFut<'a>;
}

impl<T: TunnelRouter + ?Sized> TunnelRouter for Arc<T> {
    fn authenticate(
        &self,
        credentials: Option<(&str, &str)>,
    ) -> Result<TunnelSelector, ProxyAuthError> {
        (**self).authenticate(credentials)
    }

    fn select_tunnel<'a>(
        &'a self,
        selector: &'a TunnelSelector,
    ) -> Pin<Box<dyn Future<Output = io::Result<Arc<dyn ProxyTunnelTarget>>> + Send + 'a>> {
        (**self).select_tunnel(selector)
    }
}

/// Router for dedicated per-tunnel ports forwarding all connections to a single tunnel target.
pub struct SingleTunnelRouter {
    target: Arc<dyn ProxyTunnelTarget>,
    tunnel_id: String,
    auth: Option<(String, String)>,
}

impl std::fmt::Debug for SingleTunnelRouter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SingleTunnelRouter")
            .field("tunnel_id", &self.tunnel_id)
            .field("has_auth", &self.auth.is_some())
            .finish_non_exhaustive()
    }
}

impl SingleTunnelRouter {
    /// Create a new router for a single tunnel with optional username/password authentication.
    pub fn new(
        tunnel_id: impl Into<String>,
        target: Arc<dyn ProxyTunnelTarget>,
        auth: Option<(String, String)>,
    ) -> Self {
        Self {
            target,
            tunnel_id: tunnel_id.into(),
            auth,
        }
    }
}

/// Constant-time byte comparison to prevent timing side-channel attacks on proxy credentials.
pub fn constant_time_eq_str(a: &str, b: &str) -> bool {
    let a = a.as_bytes();
    let b = b.as_bytes();
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (&x, &y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

impl TunnelRouter for SingleTunnelRouter {
    fn authenticate(
        &self,
        credentials: Option<(&str, &str)>,
    ) -> Result<TunnelSelector, ProxyAuthError> {
        if let Some((expected_user, expected_pass)) = &self.auth {
            match credentials {
                Some((u, p))
                    if constant_time_eq_str(u, expected_user)
                        && constant_time_eq_str(p, expected_pass) =>
                {
                    Ok(TunnelSelector::ById(self.tunnel_id.clone()))
                }
                Some(_) => Err(ProxyAuthError::InvalidCredentials),
                None => Err(ProxyAuthError::AuthRequired),
            }
        } else {
            Ok(TunnelSelector::ById(self.tunnel_id.clone()))
        }
    }

    fn select_tunnel<'a>(
        &'a self,
        _selector: &'a TunnelSelector,
    ) -> Pin<Box<dyn Future<Output = io::Result<Arc<dyn ProxyTunnelTarget>>> + Send + 'a>> {
        let target = Arc::clone(&self.target);
        Box::pin(async move { Ok(target) })
    }
}

struct PoolInner {
    tunnels: HashMap<String, Arc<dyn ProxyTunnelTarget>>,
    keys: Vec<String>,
}

/// Router for shared ports managing multiple tunnels with pool strategies and credentials.
pub struct PoolRouter {
    inner: RwLock<PoolInner>,
    strategy: PoolStrategy,
    auth_mode: AuthMode,
    global_password: Option<String>,
    per_tunnel_passwords: RwLock<HashMap<String, String>>,
    allow_anonymous: bool,
    rr_counter: AtomicUsize,
}

impl std::fmt::Debug for PoolRouter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PoolRouter")
            .field("strategy", &self.strategy)
            .field("auth_mode", &self.auth_mode)
            .field("allow_anonymous", &self.allow_anonymous)
            .finish_non_exhaustive()
    }
}

impl PoolRouter {
    /// Create a new pool router with the given strategy and anonymous access flag.
    pub fn new(strategy: PoolStrategy, allow_anonymous: bool) -> Self {
        Self {
            inner: RwLock::new(PoolInner {
                tunnels: HashMap::new(),
                keys: Vec::new(),
            }),
            strategy,
            auth_mode: AuthMode::None,
            global_password: None,
            per_tunnel_passwords: RwLock::new(HashMap::new()),
            allow_anonymous,
            rr_counter: AtomicUsize::new(0),
        }
    }

    /// Set authentication mode and optional global password.
    pub fn with_auth(mut self, auth_mode: AuthMode, global_password: Option<String>) -> Self {
        self.auth_mode = auth_mode;
        self.global_password = global_password;
        self
    }

    /// Configure per-tunnel override passwords used when `AuthMode::PerTunnel` is active.
    pub fn with_per_tunnel_passwords(self, passwords: HashMap<String, String>) -> Self {
        *self.per_tunnel_passwords.write() = passwords;
        self
    }

    /// Register or update a per-tunnel password override.
    pub fn set_tunnel_password(&self, id: impl Into<String>, password: impl Into<String>) {
        self.per_tunnel_passwords
            .write()
            .insert(id.into(), password.into());
    }

    /// Register a tunnel target in this pool.
    pub fn add_tunnel(self: &Arc<Self>, id: impl Into<String>, target: Arc<dyn ProxyTunnelTarget>) {
        let id_str = id.into();
        let mut inner = self.inner.write();
        if !inner.tunnels.contains_key(&id_str) {
            inner.keys.push(id_str.clone());
        }
        inner.tunnels.insert(id_str, target);
    }

    fn pick_pool_tunnel(&self) -> io::Result<Arc<dyn ProxyTunnelTarget>> {
        let inner = self.inner.read();
        if inner.keys.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::NotConnected,
                "no tunnels registered in pool",
            ));
        }

        let selected_id = match self.strategy {
            PoolStrategy::RoundRobin | PoolStrategy::LeastConn => {
                let idx = self.rr_counter.fetch_add(1, Ordering::Relaxed) % inner.keys.len();
                inner.keys.get(idx)
            }
            PoolStrategy::Fallback => inner.keys.first(),
            PoolStrategy::Random => {
                let idx = (rand::random::<u32>() as usize) % inner.keys.len();
                inner.keys.get(idx)
            }
        }
        .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "selected tunnel not found"))?;

        inner
            .tunnels
            .get(selected_id)
            .cloned()
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "selected tunnel not found"))
    }
}

impl TunnelRouter for PoolRouter {
    fn authenticate(
        &self,
        credentials: Option<(&str, &str)>,
    ) -> Result<TunnelSelector, ProxyAuthError> {
        match self.auth_mode {
            AuthMode::None => {
                if let Some((user, _pass)) = credentials {
                    Ok(TunnelSelector::parse(user))
                } else {
                    Ok(TunnelSelector::DefaultPool)
                }
            }
            AuthMode::Global => match credentials {
                None => {
                    if self.allow_anonymous {
                        Ok(TunnelSelector::DefaultPool)
                    } else {
                        Err(ProxyAuthError::AuthRequired)
                    }
                }
                Some((user, pass)) => match &self.global_password {
                    Some(expected_pass) if constant_time_eq_str(pass, expected_pass) => {
                        Ok(TunnelSelector::parse(user))
                    }
                    _ => Err(ProxyAuthError::InvalidCredentials),
                },
            },
            AuthMode::PerTunnel => match credentials {
                None => {
                    if self.allow_anonymous {
                        Ok(TunnelSelector::DefaultPool)
                    } else {
                        Err(ProxyAuthError::AuthRequired)
                    }
                }
                Some((user, pass)) => {
                    let selector = TunnelSelector::parse(user);
                    if let TunnelSelector::ById(ref id) = selector
                        && let Some(tunnel_pass) = self.per_tunnel_passwords.read().get(id)
                    {
                        return if constant_time_eq_str(pass, tunnel_pass) {
                            Ok(selector)
                        } else {
                            Err(ProxyAuthError::InvalidCredentials)
                        };
                    }
                    match &self.global_password {
                        Some(expected_pass) if constant_time_eq_str(pass, expected_pass) => {
                            Ok(selector)
                        }
                        _ => Err(ProxyAuthError::InvalidCredentials),
                    }
                }
            },
        }
    }

    fn select_tunnel<'a>(
        &'a self,
        selector: &'a TunnelSelector,
    ) -> Pin<Box<dyn Future<Output = io::Result<Arc<dyn ProxyTunnelTarget>>> + Send + 'a>> {
        Box::pin(async move {
            match selector {
                TunnelSelector::ById(id) => {
                    let inner = self.inner.read();
                    inner.tunnels.get(id).cloned().ok_or_else(|| {
                        io::Error::new(
                            io::ErrorKind::NotFound,
                            format!("tunnel '{id}' not found in pool"),
                        )
                    })
                }
                TunnelSelector::ByKeyword(keyword) => {
                    let inner = self.inner.read();
                    if inner.keys.is_empty() {
                        return Err(io::Error::new(
                            io::ErrorKind::NotConnected,
                            "no tunnels registered in pool",
                        ));
                    }
                    let idx = match keyword {
                        PoolKeyword::Random => (rand::random::<u32>() as usize) % inner.keys.len(),
                        PoolKeyword::Auto | PoolKeyword::RoundRobin | PoolKeyword::LeastConn => {
                            self.rr_counter.fetch_add(1, Ordering::Relaxed) % inner.keys.len()
                        }
                    };
                    let target = inner
                        .keys
                        .get(idx)
                        .and_then(|id| inner.tunnels.get(id))
                        .cloned();
                    drop(inner);
                    target
                        .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "tunnel not found"))
                }
                TunnelSelector::ByTag(tag) => {
                    // Match prefix or substring in registered tunnel IDs
                    let matched = {
                        let inner = self.inner.read();
                        inner
                            .tunnels
                            .iter()
                            .find(|(id, _)| id.contains(tag))
                            .map(|(_, target)| Arc::clone(target))
                    };
                    matched.ok_or_else(|| {
                        io::Error::new(
                            io::ErrorKind::NotFound,
                            format!("no tunnel found matching tag '{tag}'"),
                        )
                    })
                }
                TunnelSelector::DefaultPool => self.pick_pool_tunnel(),
            }
        })
    }
}
