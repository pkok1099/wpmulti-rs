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
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use parking_lot::RwLock;

use crate::config::{AuthMode, IpMode, PoolStrategy, SharedListenerSettings, TunnelPoolSelection};
use crate::core::lifecycle::{GuardedTunnelTarget, LifecycleController};
use crate::core::registry::{TunnelEntry, TunnelRegistry};
use crate::proxy::router::AuthChecker;
use crate::proxy::{
    DynStream, PoolKeyword, ProxyAuthError, ProxyTunnelTarget, ProxyUdpSocket, TunnelRouter,
    TunnelSelector,
};

/// Multi-tenant proxy router for shared listener ports.
#[derive(Debug)]
pub struct MultiTenantRouter {
    lifecycle: Arc<LifecycleController>,
    registry: Arc<TunnelRegistry>,
    allowed_tunnels: RwLock<Option<Arc<[String]>>>,
    default_strategy: PoolStrategy,
    auth_mode: AuthMode,
    global_password: Option<String>,
    per_tunnel_passwords: RwLock<std::collections::HashMap<String, String>>,
    allow_anonymous: bool,
    listener_ip_mode: Option<IpMode>,
    rr_counter: AtomicUsize,
    health_override: Option<(usize, Duration)>,
}

impl MultiTenantRouter {
    /// Create a new multi-tenant router from shared listener configuration.
    ///
    /// Tracks `lifecycle.health_check()` and `lifecycle.ip_mode()` dynamically for live updates.
    pub fn from_settings(
        settings: &SharedListenerSettings,
        lifecycle: Arc<LifecycleController>,
        registry: Arc<TunnelRegistry>,
    ) -> Arc<Self> {
        let allowed: Option<Arc<[String]>> = match &settings.pool {
            TunnelPoolSelection::All => None,
            TunnelPoolSelection::Selected(list) => Some(list.as_slice().into()),
        };

        Arc::new(Self {
            lifecycle,
            registry,
            allowed_tunnels: RwLock::new(allowed),
            default_strategy: settings.default_strategy,
            auth_mode: settings.auth_mode,
            global_password: settings.global_password.clone(),
            per_tunnel_passwords: RwLock::new(std::collections::HashMap::new()),
            allow_anonymous: settings.allow_anonymous,
            listener_ip_mode: settings.ip_mode,
            rr_counter: AtomicUsize::new(0),
            health_override: None,
        })
    }

    /// Create a new multi-tenant router from shared listener configuration with explicit health parameters.
    pub fn from_settings_with_health(
        settings: &SharedListenerSettings,
        lifecycle: Arc<LifecycleController>,
        registry: Arc<TunnelRegistry>,
        failure_threshold: usize,
        cooldown_duration: Duration,
    ) -> Arc<Self> {
        Self::from_settings(settings, lifecycle, registry)
            .with_health_settings(failure_threshold, cooldown_duration)
    }

    /// Construct a multi-tenant router with custom parameters.
    pub fn new(
        lifecycle: Arc<LifecycleController>,
        registry: Arc<TunnelRegistry>,
        default_strategy: PoolStrategy,
        allow_anonymous: bool,
    ) -> Arc<Self> {
        Arc::new(Self {
            lifecycle,
            registry,
            allowed_tunnels: RwLock::new(None),
            default_strategy,
            auth_mode: AuthMode::None,
            global_password: None,
            per_tunnel_passwords: RwLock::new(std::collections::HashMap::new()),
            allow_anonymous,
            listener_ip_mode: None,
            rr_counter: AtomicUsize::new(0),
            health_override: None,
        })
    }

    /// Configure explicit static health check parameters overriding [`LifecycleController`].
    pub fn with_health_settings(
        self: Arc<Self>,
        failure_threshold: usize,
        cooldown_duration: Duration,
    ) -> Arc<Self> {
        let mut router = Arc::try_unwrap(self).unwrap_or_else(|a| (*a).clone_shallow());
        router.health_override = Some((failure_threshold, cooldown_duration));
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

    fn effective_ip_mode(&self) -> io::Result<IpMode> {
        IpMode::effective_with_global(self.listener_ip_mode, self.lifecycle.ip_mode())
            .map_err(|msg| io::Error::new(io::ErrorKind::PermissionDenied, msg))
    }

    fn effective_health(&self) -> (usize, Duration) {
        self.health_override
            .unwrap_or_else(|| self.lifecycle.health_check())
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
            listener_ip_mode: self.listener_ip_mode,
            rr_counter: AtomicUsize::new(self.rr_counter.load(Ordering::Relaxed)),
            health_override: self.health_override,
        }
    }

    /// Collect candidate tunnel IDs allowed for this pool.
    pub fn get_candidates(&self) -> Vec<String> {
        let allowed = self.allowed_tunnels.read().clone();
        allowed.map_or_else(|| self.registry.all_ids(), |list| list.to_vec())
    }

    /// Filter candidates to only those whose health status is routable.
    pub fn filter_healthy_candidates<'a>(&self, candidates: &'a [String]) -> Vec<&'a String> {
        candidates
            .iter()
            .filter(|id| {
                self.registry
                    .get(id)
                    .is_some_and(|entry| !entry.is_disabled() && entry.health.can_route())
            })
            .collect()
    }

    fn try_claim_candidate(&self, id: &str) -> bool {
        self.registry
            .get(id)
            .is_some_and(|entry| !entry.is_disabled() && entry.health.is_routable())
    }

    fn claim_from_healthy(&self, healthy: &[&String], start_idx: usize) -> io::Result<String> {
        if healthy.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::NotConnected,
                "no healthy tunnels available in pool",
            ));
        }
        for offset in 0..healthy.len() {
            let idx = (start_idx + offset) % healthy.len();
            if let Some(&id) = healthy.get(idx)
                && self.try_claim_candidate(id)
            {
                return Ok(id.clone());
            }
        }
        Err(io::Error::new(
            io::ErrorKind::NotConnected,
            "no healthy tunnels available in pool",
        ))
    }

    /// Select a tunnel ID from slice based on keyword without cloning candidate lists.
    fn select_by_keyword_slice(
        &self,
        keyword: PoolKeyword,
        candidates: &[String],
    ) -> io::Result<String> {
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
                self.claim_from_healthy(&healthy, idx)
            }
            PoolKeyword::RoundRobin | PoolKeyword::Auto => {
                let idx = self.rr_counter.fetch_add(1, Ordering::Relaxed) % healthy.len();
                self.claim_from_healthy(&healthy, idx)
            }
            PoolKeyword::LeastConn => self.select_least_conn_refs(&healthy),
        }
    }

    fn select_least_conn_registry(&self, entries: &[Arc<TunnelEntry>]) -> Option<String> {
        let mut candidates: Vec<(usize, &str)> = entries
            .iter()
            .filter(|e| !e.is_disabled() && e.health.can_route())
            .map(|e| (e.stats.active_conns.load(Ordering::Relaxed), e.id.as_str()))
            .collect();
        candidates.sort_by_key(|(conns, _)| *conns);
        candidates
            .into_iter()
            .find_map(|(_, id)| self.try_claim_candidate(id).then(|| id.to_string()))
    }

    fn select_rr_or_random_registry(
        &self,
        entries: &[Arc<TunnelEntry>],
        is_random: bool,
    ) -> Option<String> {
        let healthy: Vec<_> = entries
            .iter()
            .filter(|e| !e.is_disabled() && e.health.can_route())
            .collect();
        if healthy.is_empty() {
            return None;
        }
        let start_idx = if is_random {
            (rand::random::<u32>() as usize) % healthy.len()
        } else {
            self.rr_counter.fetch_add(1, Ordering::Relaxed) % healthy.len()
        };
        for offset in 0..healthy.len() {
            let idx = (start_idx + offset) % healthy.len();
            if let Some(entry) = healthy.get(idx)
                && !entry.is_disabled()
                && entry.health.is_routable()
            {
                return Some(entry.id.clone());
            }
        }
        None
    }

    /// Select a tunnel ID directly from the registry without candidate vector or HashMap lookups.
    fn select_by_keyword_registry(&self, keyword: PoolKeyword) -> io::Result<String> {
        let entries = self.registry.all_entries();
        if entries.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::NotConnected,
                "no healthy tunnels available in pool",
            ));
        }

        let selected = match keyword {
            PoolKeyword::LeastConn => self.select_least_conn_registry(&entries),
            PoolKeyword::Random => self.select_rr_or_random_registry(&entries, true),
            PoolKeyword::RoundRobin | PoolKeyword::Auto => {
                self.select_rr_or_random_registry(&entries, false)
            }
        };

        selected.ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::NotConnected,
                "no healthy tunnels available in pool",
            )
        })
    }

    /// Select a candidate tunnel with lowest active connections among healthy candidates.
    fn select_least_conn_refs(&self, healthy: &[&String]) -> io::Result<String> {
        let mut ranked: Vec<(usize, &String)> = healthy
            .iter()
            .filter_map(|&id| {
                self.registry
                    .get(id)
                    .map(|entry| (entry.stats.active_conns.load(Ordering::Relaxed), id))
            })
            .collect();
        ranked.sort_by_key(|(conns, _)| *conns);

        for (_, id) in ranked {
            if self.try_claim_candidate(id) {
                return Ok(id.clone());
            }
        }

        Err(io::Error::new(
            io::ErrorKind::NotConnected,
            "no healthy tunnels available in pool",
        ))
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
                    if self.try_claim_candidate(id) {
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
                let idx = if healthy.is_empty() {
                    0
                } else {
                    self.rr_counter.fetch_add(1, Ordering::Relaxed) % healthy.len()
                };
                self.claim_from_healthy(&healthy, idx)
            }
            PoolStrategy::Random => {
                let healthy = self.filter_healthy_candidates(candidates);
                let idx = if healthy.is_empty() {
                    0
                } else {
                    (rand::random::<u32>() as usize) % healthy.len()
                };
                self.claim_from_healthy(&healthy, idx)
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

fn resolve_selector(
    router: &MultiTenantRouter,
    selector: &TunnelSelector,
    allowed_guard: Option<&[String]>,
) -> io::Result<String> {
    match selector {
        TunnelSelector::ById(id) => {
            if let Some(allowed) = allowed_guard
                && !allowed.iter().any(|s| s == id)
            {
                return Err(io::Error::new(
                    io::ErrorKind::NotFound,
                    format!("tunnel '{id}' not allowed in this pool"),
                ));
            }
            if router.registry.get(id).is_none() {
                return Err(io::Error::new(
                    io::ErrorKind::NotFound,
                    format!("tunnel '{id}' not found in registry"),
                ));
            }
            Ok(id.clone())
        }
        TunnelSelector::ByKeyword(keyword) => allowed_guard.map_or_else(
            || router.select_by_keyword_registry(*keyword),
            |allowed| router.select_by_keyword_slice(*keyword, allowed),
        ),
        TunnelSelector::ByTag(tag) => {
            let matched = allowed_guard.map_or_else(
                || {
                    router
                        .registry
                        .all_entries()
                        .into_iter()
                        .find(|e| e.id.contains(tag) && !e.is_disabled() && e.health.is_routable())
                        .map(|e| e.id.clone())
                },
                |allowed| {
                    allowed
                        .iter()
                        .find(|id| id.contains(tag) && router.try_claim_candidate(id))
                        .cloned()
                },
            );
            matched.ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::NotFound,
                    format!("no healthy tunnel found matching tag '{tag}'"),
                )
            })
        }
        TunnelSelector::DefaultPool => allowed_guard.map_or_else(
            || router.select_default_pool_registry(),
            |allowed| router.select_default_pool_slice(allowed),
        ),
    }
}

impl TunnelRouter for MultiTenantRouter {
    fn authenticate(
        &self,
        credentials: Option<(&str, &str)>,
    ) -> Result<TunnelSelector, ProxyAuthError> {
        AuthChecker {
            auth_mode: self.auth_mode,
            global_password: &self.global_password,
            per_tunnel_passwords: &self.per_tunnel_passwords,
            allow_anonymous: self.allow_anonymous,
            // Without credentials under `AuthMode::None`, anonymous access
            // must be enabled; otherwise auth is required.
            none_without_credentials_ok: false,
        }
        .authenticate(credentials)
    }

    fn select_tunnel<'a>(
        &'a self,
        selector: &'a TunnelSelector,
    ) -> Pin<Box<dyn Future<Output = io::Result<Arc<dyn ProxyTunnelTarget>>> + Send + 'a>> {
        Box::pin(async move {
            let allowed_guard = self.allowed_tunnels.read().clone();

            let max_attempts = match selector {
                TunnelSelector::ByKeyword(_) | TunnelSelector::DefaultPool => 3,
                TunnelSelector::ById(_) | TunnelSelector::ByTag(_) => 1,
            };

            let mut last_err = None;
            let mut chosen = None;
            let mut failed_ids: Vec<String> = Vec::new();

            for attempt in 0..max_attempts {
                let candidate_override: Option<Vec<String>> = if failed_ids.is_empty() {
                    None
                } else {
                    let base: Vec<String> = allowed_guard
                        .as_deref()
                        .map_or_else(|| self.registry.all_ids(), ToOwned::to_owned);
                    let remaining: Vec<String> = base
                        .into_iter()
                        .filter(|id| !failed_ids.contains(id))
                        .collect();
                    if remaining.is_empty() {
                        break;
                    }
                    Some(remaining)
                };
                let effective_allowed = candidate_override.as_deref().or(allowed_guard.as_deref());
                let target_id = resolve_selector(self, selector, effective_allowed)?;

                match self.lifecycle.get_or_activate(&target_id).await {
                    Ok((active_tunnel, guard)) => {
                        chosen = Some((target_id, active_tunnel, guard));
                        break;
                    }
                    Err(e) => {
                        if !matches!(selector, TunnelSelector::ById(_))
                            && let Some(entry) = self.registry.get(&target_id)
                        {
                            entry.health.release_trial_slot();
                        }
                        tracing::warn!(
                            "Tunnel '{}' activation failed (attempt {}/{}): {:?}",
                            target_id,
                            attempt + 1,
                            max_attempts,
                            e
                        );
                        failed_ids.push(target_id);
                        last_err =
                            Some(io::Error::other(format!("tunnel activation failed: {e:?}")));
                        if attempt + 1 < max_attempts {
                            let backoff_ms = 100u64 << attempt; // 100ms, 200ms
                            tokio::time::sleep(Duration::from_millis(backoff_ms)).await;
                        }
                    }
                }
            }

            let Some((target_id, active_tunnel, guard)) = chosen else {
                return Err(last_err.unwrap_or_else(|| {
                    io::Error::other("tunnel activation failed after retries")
                }));
            };

            let entry = self.registry.get(&target_id);
            let health = entry.as_ref().map(|e| Arc::clone(&e.health));

            let guarded = if let Some(h) = health {
                let (threshold, cooldown) = self.effective_health();
                GuardedTunnelTarget::new_with_health(active_tunnel, guard, h, threshold, cooldown)
            } else {
                GuardedTunnelTarget::new(active_tunnel, guard)
            };

            let ip_mode = self.effective_ip_mode()?;
            let target: Arc<dyn ProxyTunnelTarget> = if ip_mode == IpMode::DualStack {
                Arc::new(guarded)
            } else {
                Arc::new(IpFilteredTunnelTarget::new(Arc::new(guarded), ip_mode))
            };
            Ok(target)
        })
    }
}

/// Dedicated router for per-tunnel ports forwarding all connections directly to a single tunnel.
#[derive(Debug)]
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
                .map_err(|e| io::Error::other(format!("tunnel activation failed: {e:?}")))?;

            let entry = self.lifecycle.registry().get(&self.tunnel_id);
            let health = entry.as_ref().map(|e| Arc::clone(&e.health));

            let guarded = if let Some(h) = health {
                let (threshold, cooldown) = self.lifecycle.health_check();
                GuardedTunnelTarget::new_with_health(active, guard, h, threshold, cooldown)
            } else {
                GuardedTunnelTarget::new(active, guard)
            };

            let ip_mode = self.lifecycle.ip_mode();
            let target: Arc<dyn ProxyTunnelTarget> = if ip_mode == IpMode::DualStack {
                Arc::new(guarded)
            } else {
                Arc::new(IpFilteredTunnelTarget::new(Arc::new(guarded), ip_mode))
            };
            Ok(target)
        })
    }
}

/// Tunnel target wrapper enforcing a listener- or global-level [`IpMode`] on TCP, UDP, and DNS.
#[derive(Debug)]
pub struct IpFilteredTunnelTarget {
    inner: Arc<GuardedTunnelTarget>,
    ip_mode: IpMode,
}

impl IpFilteredTunnelTarget {
    /// Wrap a [`GuardedTunnelTarget`] with an [`IpMode`] filter.
    pub const fn new(inner: Arc<GuardedTunnelTarget>, ip_mode: IpMode) -> Self {
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
            let filtered: Box<dyn ProxyUdpSocket> = Box::new(IpFilteredUdpSocket {
                inner: sock,
                ip_mode,
            });
            Ok(filtered)
        })
    }

    fn resolve_in_tunnel<'a>(
        &'a self,
        domain: &'a str,
    ) -> Pin<Box<dyn Future<Output = io::Result<IpAddr>> + Send + 'a>> {
        self.inner.resolve_in_tunnel_with_mode(domain, self.ip_mode)
    }

    fn resolve_all_in_tunnel<'a>(
        &'a self,
        domain: &'a str,
    ) -> crate::proxy::router::ResolveAllFut<'a> {
        self.inner
            .resolve_all_in_tunnel_with_mode(domain, self.ip_mode)
    }

    fn connect_timeout(&self) -> Duration {
        self.inner.connect_timeout()
    }

    fn tunnel_id(&self) -> Option<&str> {
        self.inner.tunnel_id()
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
