//! Multi-tenant routing and proxy connector bridging.
//!
//! Bridges [`crate::proxy::TunnelRouter`] requests from SOCKS5 and HTTP proxy listeners
//! to [`crate::core::TunnelManager`] and [`crate::core::LifecycleController`].
//! Supports ById, ByKeyword (`auto`, `random`, `round-robin`, `least-conn`), tag selection,
//! and unauthenticated pool defaults.

use std::future::Future;
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::pin::Pin;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use parking_lot::RwLock;

use crate::config::{AuthMode, IpMode, PoolStrategy, SharedListenerSettings, TunnelPoolSelection};
use crate::core::lifecycle::{GuardedTunnelTarget, LifecycleController};
use crate::core::registry::TunnelRegistry;
use crate::proxy::{
    DynStream, PoolKeyword, ProxyAuthError, ProxyTunnelTarget, ProxyUdpSocket, TunnelRouter,
    TunnelSelector,
};

/// Multi-tenant proxy router for shared listener ports.
pub struct MultiTenantRouter {
    lifecycle: Arc<LifecycleController>,
    registry: Arc<TunnelRegistry>,
    allowed_tunnels: RwLock<Option<Arc<[String]>>>,
    default_strategy: PoolStrategy,
    auth_mode: AuthMode,
    global_password: Option<String>,
    per_tunnel_passwords: RwLock<std::collections::HashMap<String, String>>,
    allow_anonymous: bool,
    ip_mode: IpMode,
    rr_counter: AtomicUsize,
    failure_threshold: usize,
    cooldown_duration: Duration,
}

impl MultiTenantRouter {
    /// Create a new multi-tenant router from shared listener configuration.
    pub fn from_settings(
        settings: &SharedListenerSettings,
        lifecycle: Arc<LifecycleController>,
        registry: Arc<TunnelRegistry>,
    ) -> Arc<Self> {
        Self::from_settings_with_health(
            settings,
            lifecycle,
            registry,
            3,
            Duration::from_secs(30),
        )
    }

    /// Create a new multi-tenant router from shared listener configuration with health parameters.
    pub fn from_settings_with_health(
        settings: &SharedListenerSettings,
        lifecycle: Arc<LifecycleController>,
        registry: Arc<TunnelRegistry>,
        failure_threshold: usize,
        cooldown_duration: Duration,
    ) -> Arc<Self> {
        let allowed: Option<Arc<[String]>> = match &settings.pool {
            TunnelPoolSelection::All => None,
            TunnelPoolSelection::Selected(list) => Some(list.as_slice().into()),
        };
        let ip_mode = IpMode::effective_with_global(settings.ip_mode, lifecycle.ip_mode())
            .unwrap_or(lifecycle.ip_mode());

        Arc::new(Self {
            lifecycle,
            registry,
            allowed_tunnels: RwLock::new(allowed),
            default_strategy: settings.default_strategy,
            auth_mode: settings.auth_mode,
            global_password: settings.global_password.clone(),
            per_tunnel_passwords: RwLock::new(std::collections::HashMap::new()),
            allow_anonymous: settings.allow_anonymous,
            ip_mode,
            rr_counter: AtomicUsize::new(0),
            failure_threshold,
            cooldown_duration,
        })
    }

    /// Construct a multi-tenant router with custom parameters.
    pub fn new(
        lifecycle: Arc<LifecycleController>,
        registry: Arc<TunnelRegistry>,
        default_strategy: PoolStrategy,
        allow_anonymous: bool,
    ) -> Arc<Self> {
        let ip_mode = lifecycle.ip_mode();
        Arc::new(Self {
            lifecycle,
            registry,
            allowed_tunnels: RwLock::new(None),
            default_strategy,
            auth_mode: AuthMode::None,
            global_password: None,
            per_tunnel_passwords: RwLock::new(std::collections::HashMap::new()),
            allow_anonymous,
            ip_mode,
            rr_counter: AtomicUsize::new(0),
            failure_threshold: 3,
            cooldown_duration: Duration::from_secs(30),
        })
    }

    /// Configure health check parameters.
    pub fn with_health_settings(
        self: Arc<Self>,
        failure_threshold: usize,
        cooldown_duration: Duration,
    ) -> Arc<Self> {
        let mut router = Arc::try_unwrap(self).unwrap_or_else(|a| (*a).clone_shallow());
        router.failure_threshold = failure_threshold;
        router.cooldown_duration = cooldown_duration;
        Arc::new(router)
    }

    /// Configure authentication mode and global password.
    pub fn with_auth(
        self: Arc<Self>,
        auth_mode: AuthMode,
        global_password: Option<String>,
    ) -> Arc<Self> {
        let mut router = Arc::try_unwrap(self).unwrap_or_else(|a| (*a).clone_shallow());
        router.auth_mode = auth_mode;
        router.global_password = global_password;
        Arc::new(router)
    }

    /// Configure per-tunnel override passwords used when `AuthMode::PerTunnel` is active.
    pub fn with_per_tunnel_passwords(
        self: Arc<Self>,
        passwords: std::collections::HashMap<String, String>,
    ) -> Arc<Self> {
        *self.per_tunnel_passwords.write() = passwords;
        self
    }

    /// Update per-tunnel override passwords under lock.
    pub fn set_per_tunnel_passwords(&self, passwords: std::collections::HashMap<String, String>) {
        *self.per_tunnel_passwords.write() = passwords;
    }

    /// Update the allowed tunnel pool IDs under lock.
    pub fn set_allowed_tunnels(&self, list: Option<Vec<String>>) {
        let mut allowed = self.allowed_tunnels.write();
        *allowed = list.map(|l| l.into_boxed_slice().into());
    }

    fn clone_shallow(&self) -> Self {
        Self {
            lifecycle: Arc::clone(&self.lifecycle),
            registry: Arc::clone(&self.registry),
            allowed_tunnels: RwLock::new(self.allowed_tunnels.read().clone()),
            default_strategy: self.default_strategy,
            auth_mode: self.auth_mode,
            global_password: self.global_password.clone(),
            per_tunnel_passwords: RwLock::new(self.per_tunnel_passwords.read().clone()),
            allow_anonymous: self.allow_anonymous,
            ip_mode: self.ip_mode,
            rr_counter: AtomicUsize::new(self.rr_counter.load(Ordering::Relaxed)),
            failure_threshold: self.failure_threshold,
            cooldown_duration: self.cooldown_duration,
        }
    }

    /// Collect candidate tunnel IDs allowed for this pool.
    pub fn get_candidates(&self) -> Vec<String> {
        let allowed = self.allowed_tunnels.read().clone();
        if let Some(list) = allowed {
            list.to_vec()
        } else {
            self.registry.all_ids()
        }
    }

    /// Filter candidates to only those whose health status is routable.
    pub fn filter_healthy_candidates<'a>(&self, candidates: &'a [String]) -> Vec<&'a String> {
        candidates
            .iter()
            .filter(|id| {
                if let Some(entry) = self.registry.get(id) {
                    entry.health.is_routable()
                } else {
                    false
                }
            })
            .collect()
    }

    /// Select a tunnel ID from slice based on keyword without cloning candidate lists.
    fn select_by_keyword_slice(&self, keyword: PoolKeyword, candidates: &[String]) -> io::Result<String> {
        let healthy = self.filter_healthy_candidates(candidates);
        if healthy.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::NotConnected,
                "no healthy tunnels available in pool",
            ));
        }

        match keyword {
            PoolKeyword::Random => {
                let idx = (rand::random::<u32>() as usize) % healthy.len();
                Ok((*healthy[idx]).clone())
            }
            PoolKeyword::RoundRobin | PoolKeyword::Auto => {
                let idx = self.rr_counter.fetch_add(1, Ordering::Relaxed) % healthy.len();
                Ok((*healthy[idx]).clone())
            }
            PoolKeyword::LeastConn => self.select_least_conn_refs(&healthy),
        }
    }

    /// Select a tunnel ID directly from the registry without candidate vector allocation.
    fn select_by_keyword_registry(&self, keyword: PoolKeyword) -> io::Result<String> {
        let candidates = self.registry.all_ids();
        self.select_by_keyword_slice(keyword, &candidates)
    }

    /// Select a candidate tunnel with lowest active connections among healthy candidates.
    fn select_least_conn_refs(&self, healthy: &[&String]) -> io::Result<String> {
        let mut best_id = None;
        let mut min_conns = usize::MAX;

        for &id in healthy {
            if let Some(entry) = self.registry.get(id) {
                let conns = entry.stats.active_conns.load(Ordering::Relaxed);
                if conns < min_conns {
                    min_conns = conns;
                    best_id = Some(id.clone());
                }
            }
        }

        best_id.ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::NotConnected,
                "no candidate tunnels found in registry",
            )
        })
    }

    /// Select a candidate tunnel with lowest active connections from a slice.
    fn select_least_conn_slice(&self, candidates: &[String]) -> io::Result<String> {
        let healthy = self.filter_healthy_candidates(candidates);
        if healthy.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::NotConnected,
                "no healthy tunnels available in pool",
            ));
        }
        self.select_least_conn_refs(&healthy)
    }

    /// Select a tunnel ID using default pool strategy from slice.
    fn select_default_pool_slice(&self, candidates: &[String]) -> io::Result<String> {
        if candidates.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::NotConnected,
                "no available tunnels in default pool",
            ));
        }

        match self.default_strategy {
            PoolStrategy::Fallback => {
                // True priority fallback: select first routable candidate in sequence
                for id in candidates {
                    if let Some(entry) = self.registry.get(id)
                        && entry.health.is_routable()
                    {
                        return Ok(id.clone());
                    }
                }
                Err(io::Error::new(
                    io::ErrorKind::NotConnected,
                    "all tunnels in fallback pool are unhealthy",
                ))
            }
            PoolStrategy::RoundRobin => {
                let healthy = self.filter_healthy_candidates(candidates);
                if healthy.is_empty() {
                    return Err(io::Error::new(
                        io::ErrorKind::NotConnected,
                        "no healthy tunnels available in pool",
                    ));
                }
                let idx = self.rr_counter.fetch_add(1, Ordering::Relaxed) % healthy.len();
                Ok((*healthy[idx]).clone())
            }
            PoolStrategy::Random => {
                let healthy = self.filter_healthy_candidates(candidates);
                if healthy.is_empty() {
                    return Err(io::Error::new(
                        io::ErrorKind::NotConnected,
                        "no healthy tunnels available in pool",
                    ));
                }
                let idx = (rand::random::<u32>() as usize) % healthy.len();
                Ok((*healthy[idx]).clone())
            }
            PoolStrategy::LeastConn => self.select_least_conn_slice(candidates),
        }
    }

    /// Select a tunnel ID using default pool strategy from registry directly.
    fn select_default_pool_registry(&self) -> io::Result<String> {
        let candidates = self.registry.all_ids();
        self.select_default_pool_slice(&candidates)
    }
}

impl TunnelRouter for MultiTenantRouter {
    fn authenticate(
        &self,
        credentials: Option<(&str, &str)>,
    ) -> Result<TunnelSelector, ProxyAuthError> {
        match self.auth_mode {
            AuthMode::None => {
                if let Some((user, _pass)) = credentials {
                    Ok(TunnelSelector::parse(user))
                } else if self.allow_anonymous {
                    Ok(TunnelSelector::DefaultPool)
                } else {
                    Err(ProxyAuthError::AuthRequired)
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
                    Some(expected_pass)
                        if crate::proxy::router::constant_time_eq_str(pass, expected_pass) =>
                    {
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
                        return if crate::proxy::router::constant_time_eq_str(pass, tunnel_pass) {
                            Ok(selector)
                        } else {
                            Err(ProxyAuthError::InvalidCredentials)
                        };
                    }
                    match &self.global_password {
                        Some(expected_pass)
                            if crate::proxy::router::constant_time_eq_str(pass, expected_pass) =>
                        {
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
            let allowed_guard = self.allowed_tunnels.read().clone();

            let target_id = match selector {
                TunnelSelector::ById(id) => {
                    // Check if tunnel ID is recognized and allowed
                    if let Some(ref allowed) = allowed_guard
                        && !allowed.is_empty() && !allowed.iter().any(|s| s == id) {
                            return Err(io::Error::new(
                                io::ErrorKind::NotFound,
                                format!("tunnel '{}' not allowed in this pool", id),
                            ));
                        }
                    if self.registry.get(id).is_none() {
                        return Err(io::Error::new(
                            io::ErrorKind::NotFound,
                            format!("tunnel '{}' not found in registry", id),
                        ));
                    }
                    id.clone()
                }
                TunnelSelector::ByKeyword(keyword) => {
                    if let Some(ref allowed) = allowed_guard {
                        self.select_by_keyword_slice(*keyword, allowed)?
                    } else {
                        self.select_by_keyword_registry(*keyword)?
                    }
                }
                TunnelSelector::ByTag(tag) => {
                    if let Some(ref allowed) = allowed_guard {
                        let matched = allowed.iter().find(|id| id.contains(tag)).cloned();
                        matched.ok_or_else(|| {
                            io::Error::new(
                                io::ErrorKind::NotFound,
                                format!("no tunnel found matching tag '{}'", tag),
                            )
                        })?
                    } else {
                        let all = self.registry.all_ids();
                        let matched = all.into_iter().find(|id| id.contains(tag));
                        matched.ok_or_else(|| {
                            io::Error::new(
                                io::ErrorKind::NotFound,
                                format!("no tunnel found matching tag '{}'", tag),
                            )
                        })?
                    }
                }
                TunnelSelector::DefaultPool => {
                    if let Some(ref allowed) = allowed_guard {
                        self.select_default_pool_slice(allowed)?
                    } else {
                        self.select_default_pool_registry()?
                    }
                }
            };

            // Dynamically activate or resume on demand with RAII connection guard
            let (active_tunnel, guard) = self
                .lifecycle
                .get_or_activate(&target_id)
                .await
                .map_err(|e| io::Error::other(format!("tunnel activation failed: {:?}", e)))?;

            let entry = self.registry.get(&target_id);
            let health = entry.as_ref().map(|e| Arc::clone(&e.health));

            let guarded = if let Some(h) = health {
                GuardedTunnelTarget::new_with_health(
                    active_tunnel,
                    guard,
                    h,
                    self.failure_threshold,
                    self.cooldown_duration,
                )
            } else {
                GuardedTunnelTarget::new(active_tunnel, guard)
            };

            if self.ip_mode == IpMode::DualStack {
                Ok(Arc::new(guarded) as Arc<dyn ProxyTunnelTarget>)
            } else {
                Ok(Arc::new(IpFilteredTunnelTarget::new(
                    Arc::new(guarded),
                    self.ip_mode,
                )) as Arc<dyn ProxyTunnelTarget>)
            }
        })
    }
}

/// Dedicated router for per-tunnel ports forwarding all connections directly to a single tunnel.
pub struct DedicatedTunnelRouter {
    tunnel_id: String,
    lifecycle: Arc<LifecycleController>,
    auth: Option<(String, String)>,
}

impl DedicatedTunnelRouter {
    /// Construct a new dedicated router for a single tunnel.
    pub fn new(
        tunnel_id: impl Into<String>,
        lifecycle: Arc<LifecycleController>,
        auth: Option<(String, String)>,
    ) -> Self {
        Self {
            tunnel_id: tunnel_id.into(),
            lifecycle,
            auth,
        }
    }
}

impl TunnelRouter for DedicatedTunnelRouter {
    fn authenticate(
        &self,
        credentials: Option<(&str, &str)>,
    ) -> Result<TunnelSelector, ProxyAuthError> {
        if let Some((expected_user, expected_pass)) = &self.auth {
            match credentials {
                Some((u, p))
                    if crate::proxy::router::constant_time_eq_str(u, expected_user)
                        && crate::proxy::router::constant_time_eq_str(p, expected_pass) =>
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
        Box::pin(async move {
            let (active, guard) = self
                .lifecycle
                .get_or_activate(&self.tunnel_id)
                .await
                .map_err(|e| io::Error::other(format!("tunnel activation failed: {:?}", e)))?;

            let entry = self.lifecycle.registry().get(&self.tunnel_id);
            let health = entry.as_ref().map(|e| Arc::clone(&e.health));

            let guarded = if let Some(h) = health {
                GuardedTunnelTarget::new_with_health(
                    active,
                    guard,
                    h,
                    3,
                    Duration::from_secs(30),
                )
            } else {
                GuardedTunnelTarget::new(active, guard)
            };

            let ip_mode = self.lifecycle.ip_mode();
            if ip_mode == IpMode::DualStack {
                Ok(Arc::new(guarded) as Arc<dyn ProxyTunnelTarget>)
            } else {
                Ok(Arc::new(IpFilteredTunnelTarget::new(
                    Arc::new(guarded),
                    ip_mode,
                )) as Arc<dyn ProxyTunnelTarget>)
            }
        })
    }
}

/// Tunnel target wrapper enforcing a listener- or global-level [`IpMode`] on TCP, UDP, and DNS.
pub struct IpFilteredTunnelTarget {
    inner: Arc<GuardedTunnelTarget>,
    ip_mode: IpMode,
}

impl IpFilteredTunnelTarget {
    /// Wrap a [`GuardedTunnelTarget`] with an [`IpMode`] filter.
    pub fn new(inner: Arc<GuardedTunnelTarget>, ip_mode: IpMode) -> Self {
        Self { inner, ip_mode }
    }
}

impl ProxyTunnelTarget for IpFilteredTunnelTarget {
    fn tcp_connect<'a>(
        &'a self,
        dst: SocketAddr,
    ) -> Pin<Box<dyn Future<Output = io::Result<DynStream>> + Send + 'a>> {
        if let Err(e) = self.ip_mode.check_ip(dst.ip(), "TCP destination") {
            return Box::pin(async move { Err(e) });
        }
        self.inner.tcp_connect(dst)
    }

    fn udp_bind<'a>(
        &'a self,
        local_port: u16,
    ) -> Pin<Box<dyn Future<Output = io::Result<Box<dyn ProxyUdpSocket>>> + Send + 'a>> {
        let inner = Arc::clone(&self.inner);
        let ip_mode = self.ip_mode;
        Box::pin(async move {
            let sock = inner.udp_bind(local_port).await?;
            Ok(Box::new(IpFilteredUdpSocket {
                inner: sock,
                ip_mode,
            }) as Box<dyn ProxyUdpSocket>)
        })
    }

    fn resolve_in_tunnel<'a>(
        &'a self,
        domain: &'a str,
    ) -> Pin<Box<dyn Future<Output = io::Result<IpAddr>> + Send + 'a>> {
        self.inner
            .tunnel()
            .resolve_in_tunnel_with_mode(domain, self.ip_mode)
    }
}

/// UDP socket wrapper enforcing an [`IpMode`] filter on outbound datagrams.
struct IpFilteredUdpSocket {
    inner: Box<dyn ProxyUdpSocket>,
    ip_mode: IpMode,
}

impl ProxyUdpSocket for IpFilteredUdpSocket {
    fn send_to<'a>(
        &'a self,
        buf: &'a [u8],
        target: SocketAddr,
    ) -> Pin<Box<dyn Future<Output = io::Result<usize>> + Send + 'a>> {
        if let Err(e) = self.ip_mode.check_ip(target.ip(), "UDP destination") {
            return Box::pin(async move { Err(e) });
        }
        self.inner.send_to(buf, target)
    }

    fn recv_from<'a>(
        &'a self,
        buf: &'a mut [u8],
    ) -> Pin<Box<dyn Future<Output = io::Result<(usize, SocketAddr)>> + Send + 'a>> {
        let ip_mode = self.ip_mode;
        Box::pin(async move {
            loop {
                let (len, peer) = self.inner.recv_from(buf).await?;
                if ip_mode.allows_ip(peer.ip()) {
                    return Ok((len, peer));
                }
            }
        })
    }

    fn local_port(&self) -> u16 {
        self.inner.local_port()
    }
}
