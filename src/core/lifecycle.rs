//! Lazy and on-demand tunnel lifecycle management.
//!
//! Provides [`LifecycleController`] managing on-demand boot, native `Device::suspend()` and `Device::resume()`,
//! RAII active connection tracking via [`TunnelConnGuard`], and debounced background idle teardown.

use std::future::Future;
use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::Duration;

use parking_lot::Mutex;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::sync::watch;
use tokio::task::JoinHandle;

use crate::config::LifecycleMode;
use crate::core::CoreError;
use crate::core::health::TunnelHealthTracker;
use crate::core::registry::{ActiveTunnel, TunnelEntry, TunnelRegistry, TunnelState, TunnelStats};
use crate::netstack::{DEFAULT_CHANNEL_CAPACITY, VirtualNetworkStack, VirtualTunBridge};
use crate::proxy::{DynStream, ProxyTunnelTarget, ProxyUdpSocket};

/// RAII Guard tracking an active connection routed through a specific tunnel.
///
/// Increments the tunnel's `active_conns` count on creation and decrements it on drop.
/// When the active count reaches zero, records `last_active_at` for idle teardown debouncing.
#[derive(Debug)]
pub struct TunnelConnGuard {
    tunnel_id: String,
    stats: Arc<TunnelStats>,
}

impl TunnelConnGuard {
    /// Create and arm a new connection guard for the given tunnel statistics.
    pub fn new(tunnel_id: impl Into<String>, stats: Arc<TunnelStats>) -> Self {
        let id = tunnel_id.into();
        stats.inc_conns();
        Self {
            tunnel_id: id,
            stats,
        }
    }

    /// ID of the guarded tunnel.
    pub fn tunnel_id(&self) -> &str {
        &self.tunnel_id
    }
}

impl Drop for TunnelConnGuard {
    fn drop(&mut self) {
        self.stats.dec_conns();
    }
}

/// A [`ProxyTunnelTarget`] wrapper that holds an RAII [`TunnelConnGuard`].
#[derive(Debug)]
pub struct GuardedTunnelTarget {
    tunnel: Arc<ActiveTunnel>,
    guard: Arc<TunnelConnGuard>,
    health: Option<Arc<TunnelHealthTracker>>,
    threshold: usize,
    cooldown: Duration,
    trial_resolved: Arc<std::sync::atomic::AtomicBool>,
}

impl Drop for GuardedTunnelTarget {
    fn drop(&mut self) {
        if !self.trial_resolved.load(Ordering::Relaxed)
            && let Some(h) = &self.health
        {
            h.release_trial_slot();
        }
    }
}

impl GuardedTunnelTarget {
    /// Wrap an active tunnel and connection guard into a guarded target.
    pub fn new(tunnel: Arc<ActiveTunnel>, guard: TunnelConnGuard) -> Self {
        Self {
            tunnel,
            guard: Arc::new(guard),
            health: None,
            threshold: 3,
            cooldown: Duration::from_secs(30),
            trial_resolved: Arc::new(std::sync::atomic::AtomicBool::new(false)),
        }
    }

    /// Wrap an active tunnel, connection guard, and health tracker into a guarded target.
    pub fn new_with_health(
        tunnel: Arc<ActiveTunnel>,
        guard: TunnelConnGuard,
        health: Arc<TunnelHealthTracker>,
        threshold: usize,
        cooldown: Duration,
    ) -> Self {
        Self {
            tunnel,
            guard: Arc::new(guard),
            health: Some(health),
            threshold,
            cooldown,
            trial_resolved: Arc::new(std::sync::atomic::AtomicBool::new(false)),
        }
    }

    /// Attach health tracker, failure threshold, and cooldown duration.
    pub fn with_health(
        mut self,
        health: Arc<TunnelHealthTracker>,
        threshold: usize,
        cooldown: Duration,
    ) -> Self {
        self.health = Some(health);
        self.threshold = threshold;
        self.cooldown = cooldown;
        self
    }

    /// Access the underlying active tunnel handle.
    pub const fn tunnel(&self) -> &Arc<ActiveTunnel> {
        &self.tunnel
    }

    /// Resolve a domain through the tunnel with an explicit [`IpMode`] while updating
    /// handshake stats and circuit-breaker health.
    pub fn resolve_in_tunnel_with_mode<'a>(
        &'a self,
        domain: &'a str,
        ip_mode: crate::config::IpMode,
    ) -> Pin<Box<dyn Future<Output = io::Result<std::net::IpAddr>> + Send + 'a>> {
        let fut = self.resolve_all_in_tunnel_with_mode(domain, ip_mode);
        Box::pin(async move {
            let addrs = fut.await?;
            addrs.into_iter().next().ok_or_else(|| {
                io::Error::new(io::ErrorKind::NotFound, "no IP addresses found for domain")
            })
        })
    }

    /// Resolve a domain through the tunnel with an explicit [`IpMode`], returning all
    /// candidate IP addresses while updating handshake stats and circuit-breaker health.
    pub fn resolve_all_in_tunnel_with_mode<'a>(
        &'a self,
        domain: &'a str,
        ip_mode: crate::config::IpMode,
    ) -> crate::proxy::router::ResolveAllFut<'a> {
        let tunnel = Arc::clone(&self.tunnel);
        let health = self.health.clone();
        let threshold = self.threshold;
        let cooldown = self.cooldown;
        let trial_resolved = Arc::clone(&self.trial_resolved);
        Box::pin(async move {
            match tunnel
                .resolve_all_in_tunnel_with_mode(domain, ip_mode)
                .await
            {
                Ok(ips) => {
                    tunnel.stats.record_handshake(now_unix_secs());
                    // Deliberately NOT marking the trial resolved here:
                    // a successful DNS resolve proves nothing about the
                    // tunnel carrying traffic yet. The verdict comes
                    // from the TCP connect (or UDP bind) that follows;
                    // marking it here would let a later aborted connect
                    // leak the claimed `HalfOpen` trial slot forever.
                    Ok(ips)
                }
                Err(e) => {
                    trial_resolved.store(true, Ordering::Relaxed);
                    if let Some(h) = &health {
                        let handshaked = tunnel.stats.last_handshake.load(Ordering::Relaxed) > 0;
                        if is_destination_caused_error(e.kind(), handshaked) {
                            h.record_inconclusive();
                        } else {
                            h.record_failure(threshold, cooldown);
                        }
                    }
                    let err = if e.kind() == io::ErrorKind::TimedOut
                        && tunnel.stats.last_handshake.load(Ordering::Relaxed) == 0
                    {
                        io::Error::new(
                            io::ErrorKind::TimedOut,
                            "WireGuard handshake not yet established (peer unreachable or timed out)",
                        )
                    } else {
                        e
                    };
                    Err(err)
                }
            }
        })
    }
}

fn now_unix_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

/// Whether a failed attempt says nothing about the tunnel's health: the
/// failure is attributable to the client-chosen destination, not to the
/// WireGuard peer. Such attempts must not trip the circuit breaker
/// (audit run-1, medium). A refused connection proves the tunnel carried
/// the SYN and got an answer back; an unroutable address family or a
/// nonexistent domain is a property of the request; a timeout against a
/// peer that has handshaked before points at a blackholing destination,
/// while a timeout against a peer that never handshaked points at the
/// peer itself — so it stays a failure.
pub(crate) const fn is_destination_caused_error(
    kind: io::ErrorKind,
    tunnel_handshaked: bool,
) -> bool {
    // `std::io::ErrorKind` is `#[non_exhaustive]` with ~40 variants; the
    // destination-caused ones are listed explicitly and all others stay
    // tunnel-side failures.
    #[allow(clippy::wildcard_enum_match_arm)]
    match kind {
        io::ErrorKind::ConnectionRefused
        | io::ErrorKind::AddrNotAvailable
        | io::ErrorKind::InvalidInput
        | io::ErrorKind::NotFound => true,
        io::ErrorKind::TimedOut => tunnel_handshaked,
        _ => false,
    }
}

impl ProxyTunnelTarget for GuardedTunnelTarget {
    fn tcp_connect<'a>(
        &'a self,
        dst: SocketAddr,
    ) -> Pin<Box<dyn Future<Output = io::Result<DynStream>> + Send + 'a>> {
        let tunnel = Arc::clone(&self.tunnel);
        let guard = Arc::clone(&self.guard);
        let health = self.health.clone();
        let threshold = self.threshold;
        let cooldown = self.cooldown;
        let trial_resolved = Arc::clone(&self.trial_resolved);
        Box::pin(async move {
            match tunnel.tcp_connect(dst).await {
                Ok(stream) => {
                    tunnel.stats.record_handshake(now_unix_secs());
                    trial_resolved.store(true, Ordering::Relaxed);
                    if let Some(h) = &health {
                        h.record_success();
                    }
                    let guarded: DynStream = Box::new(GuardedStream {
                        inner: stream,
                        _guard: guard,
                    });
                    Ok(guarded)
                }
                Err(e) => {
                    trial_resolved.store(true, Ordering::Relaxed);
                    if let Some(h) = &health {
                        let handshaked = tunnel.stats.last_handshake.load(Ordering::Relaxed) > 0;
                        if is_destination_caused_error(e.kind(), handshaked) {
                            h.record_inconclusive();
                        } else {
                            h.record_failure(threshold, cooldown);
                        }
                    }
                    let err = if e.kind() == io::ErrorKind::TimedOut
                        && tunnel.stats.last_handshake.load(Ordering::Relaxed) == 0
                    {
                        io::Error::new(
                            io::ErrorKind::TimedOut,
                            "WireGuard handshake not yet established (peer unreachable or timed out)",
                        )
                    } else {
                        e
                    };
                    Err(err)
                }
            }
        })
    }

    fn udp_bind<'a>(
        &'a self,
        local_port: u16,
    ) -> Pin<Box<dyn Future<Output = io::Result<Box<dyn ProxyUdpSocket>>> + Send + 'a>> {
        let tunnel = Arc::clone(&self.tunnel);
        let guard = Arc::clone(&self.guard);
        let health = self.health.clone();
        let threshold = self.threshold;
        let cooldown = self.cooldown;
        let trial_resolved = Arc::clone(&self.trial_resolved);
        Box::pin(async move {
            match tunnel.udp_bind(local_port).await {
                Ok(socket) => {
                    trial_resolved.store(true, Ordering::Relaxed);
                    if let Some(h) = &health {
                        // Binding a virtual UDP socket only allocates
                        // a local port in the netstack — no packet has
                        // crossed the WireGuard handshake — so granting
                        // a UDP relay proves nothing about the tunnel.
                        // It must not promote the tunnel to Healthy or
                        // reset its failure count.
                        h.record_inconclusive();
                    }
                    let guarded: Box<dyn ProxyUdpSocket> = Box::new(GuardedUdpSocket {
                        inner: socket,
                        _guard: guard,
                    });
                    Ok(guarded)
                }
                Err(e) => {
                    trial_resolved.store(true, Ordering::Relaxed);
                    if let Some(h) = &health {
                        h.record_failure(threshold, cooldown);
                    }
                    let err = if e.kind() == io::ErrorKind::TimedOut
                        && tunnel.stats.last_handshake.load(Ordering::Relaxed) == 0
                    {
                        io::Error::new(
                            io::ErrorKind::TimedOut,
                            "WireGuard handshake not yet established (peer unreachable or timed out)",
                        )
                    } else {
                        e
                    };
                    Err(err)
                }
            }
        })
    }

    fn resolve_in_tunnel<'a>(
        &'a self,
        domain: &'a str,
    ) -> Pin<Box<dyn Future<Output = io::Result<std::net::IpAddr>> + Send + 'a>> {
        let mode = self.tunnel.netstack.effective_ip_mode();
        self.resolve_in_tunnel_with_mode(domain, mode)
    }

    fn resolve_all_in_tunnel<'a>(
        &'a self,
        domain: &'a str,
    ) -> crate::proxy::router::ResolveAllFut<'a> {
        let mode = self.tunnel.netstack.effective_ip_mode();
        self.resolve_all_in_tunnel_with_mode(domain, mode)
    }

    fn tunnel_id(&self) -> Option<&str> {
        Some(self.guard.tunnel_id())
    }

    fn connect_timeout(&self) -> Duration {
        self.tunnel.netstack.connect_timeout()
    }

    fn note_attempt_aborted(&self) {
        // Idempotent per target instance: the swap claims the verdict
        // exactly once, so a budget abort after an inner per-candidate
        // timeout cannot count the same attempt twice.
        if self.trial_resolved.swap(true, Ordering::SeqCst) {
            return;
        }
        if let Some(h) = &self.health {
            // A budget-aborted attempt ended without a verdict about the
            // tunnel — the destination may simply be slow — so it must not
            // count as a failure (audit run-1, medium). Release the
            // HalfOpen trial slot without touching status or failure
            // count; the next request may trial the tunnel again.
            h.record_inconclusive();
        }
    }
}

/// A wrapper around a [`ProxyUdpSocket`] that keeps a [`TunnelConnGuard`] alive until dropped.
pub struct GuardedUdpSocket {
    inner: Box<dyn ProxyUdpSocket>,
    _guard: Arc<TunnelConnGuard>,
}

impl std::fmt::Debug for GuardedUdpSocket {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GuardedUdpSocket").finish_non_exhaustive()
    }
}

impl ProxyUdpSocket for GuardedUdpSocket {
    fn send_to<'a>(
        &'a self,
        buf: &'a [u8],
        target: SocketAddr,
    ) -> Pin<Box<dyn Future<Output = io::Result<usize>> + Send + 'a>> {
        self.inner.send_to(buf, target)
    }

    fn recv_from<'a>(
        &'a self,
        buf: &'a mut [u8],
    ) -> Pin<Box<dyn Future<Output = io::Result<(usize, SocketAddr)>> + Send + 'a>> {
        self.inner.recv_from(buf)
    }

    fn local_port(&self) -> u16 {
        self.inner.local_port()
    }
}

/// A wrapper around a [`DynStream`] that keeps a [`TunnelConnGuard`] alive until dropped.
pub struct GuardedStream {
    inner: DynStream,
    _guard: Arc<TunnelConnGuard>,
}

impl std::fmt::Debug for GuardedStream {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GuardedStream").finish_non_exhaustive()
    }
}

impl AsyncRead for GuardedStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl AsyncWrite for GuardedStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(cx, buf)
    }

    fn poll_flush(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

/// RAII guard ensuring `TunnelState::Activating` reverts to `Dormant` if activation is cancelled.
struct ActivatingGuard<'a> {
    entry: &'a TunnelEntry,
    revert_state: TunnelState,
    defused: bool,
}

impl<'a> ActivatingGuard<'a> {
    fn new(entry: &'a TunnelEntry) -> Self {
        Self::with_revert_state(entry, TunnelState::Dormant)
    }

    fn with_revert_state(entry: &'a TunnelEntry, revert_state: TunnelState) -> Self {
        *entry.state.write() = TunnelState::Activating;
        Self {
            entry,
            revert_state,
            defused: false,
        }
    }

    fn defuse(mut self) {
        self.defused = true;
    }
}

impl Drop for ActivatingGuard<'_> {
    fn drop(&mut self) {
        if !self.defused {
            *self.entry.state.write() = self.revert_state;
        }
    }
}

/// Controller orchestrating lazy on-demand activation, native suspend/resume, and idle teardown.
#[derive(Debug)]
pub struct LifecycleController {
    registry: Arc<TunnelRegistry>,
    idle_timeout_ms: std::sync::atomic::AtomicU64,
    check_interval: Duration,
    handshake_timeout_ms: std::sync::atomic::AtomicU64,
    health_threshold: std::sync::atomic::AtomicUsize,
    health_cooldown_ms: std::sync::atomic::AtomicU64,
    max_active_tunnels: std::sync::atomic::AtomicUsize,
    dns_fallback: Mutex<SocketAddr>,
    dns_strategy: std::sync::atomic::AtomicU8,
    shutdown_tx: watch::Sender<bool>,
    teardown_handle: Mutex<Option<JoinHandle<()>>>,
    prefer_ipv6: std::sync::atomic::AtomicBool,
    ip_mode: std::sync::atomic::AtomicU8,
    eviction_lock: tokio::sync::Mutex<()>,
}

impl LifecycleController {
    /// Construct a new lifecycle controller.
    pub fn new(
        registry: Arc<TunnelRegistry>,
        idle_timeout: Duration,
        check_interval: Duration,
    ) -> Arc<Self> {
        let (shutdown_tx, _) = watch::channel(false);
        let idle_ms = idle_timeout.as_millis().min(u128::from(u64::MAX)) as u64;
        Arc::new(Self {
            registry,
            idle_timeout_ms: std::sync::atomic::AtomicU64::new(idle_ms),
            check_interval,
            handshake_timeout_ms: std::sync::atomic::AtomicU64::new(10_000),
            health_threshold: std::sync::atomic::AtomicUsize::new(3),
            health_cooldown_ms: std::sync::atomic::AtomicU64::new(30_000),
            max_active_tunnels: std::sync::atomic::AtomicUsize::new(usize::MAX),
            dns_fallback: Mutex::new(SocketAddr::new(
                std::net::IpAddr::V4(std::net::Ipv4Addr::new(1, 1, 1, 1)),
                53,
            )),
            dns_strategy: std::sync::atomic::AtomicU8::new(0),
            shutdown_tx,
            teardown_handle: Mutex::new(None),
            prefer_ipv6: std::sync::atomic::AtomicBool::new(false),
            ip_mode: std::sync::atomic::AtomicU8::new(0),
            eviction_lock: tokio::sync::Mutex::new(()),
        })
    }

    /// Configure the idle timeout before inactive lazy tunnels are suspended.
    pub fn set_idle_timeout(&self, timeout: Duration) {
        let ms = timeout.as_millis().min(u128::from(u64::MAX)) as u64;
        self.idle_timeout_ms.store(ms, Ordering::Relaxed);
    }

    /// Return the configured idle timeout.
    pub fn idle_timeout(&self) -> Duration {
        Duration::from_millis(self.idle_timeout_ms.load(Ordering::Relaxed))
    }

    /// Configure the circuit-breaker failure threshold and cooldown duration.
    pub fn set_health_check(&self, threshold: usize, cooldown: Duration) {
        self.health_threshold
            .store(threshold.max(1), Ordering::Relaxed);
        let ms = cooldown.as_millis().min(u128::from(u64::MAX)) as u64;
        self.health_cooldown_ms.store(ms, Ordering::Relaxed);
    }

    /// Return the configured circuit-breaker `(threshold, cooldown)`.
    pub fn health_check(&self) -> (usize, Duration) {
        (
            self.health_threshold.load(Ordering::Relaxed),
            Duration::from_millis(self.health_cooldown_ms.load(Ordering::Relaxed)),
        )
    }

    /// Configure the maximum number of concurrently active tunnels (`usize::MAX` = unlimited).
    pub fn set_max_active_tunnels(&self, max: usize) {
        self.max_active_tunnels.store(max.max(1), Ordering::Relaxed);
    }

    /// Configure the fallback DNS server address used when `.conf` has no `DNS` entries.
    pub fn set_dns_fallback(&self, addr: SocketAddr) {
        *self.dns_fallback.lock() = addr;
    }

    /// Configure the DNS resolution strategy (`TunnelOnly`, `TunnelFirst`, `Host`).
    pub fn set_dns_strategy(&self, strategy: crate::config::toml_config::DnsStrategy) {
        let val = match strategy {
            crate::config::toml_config::DnsStrategy::TunnelOnly => 0,
            crate::config::toml_config::DnsStrategy::TunnelFirst => 1,
            crate::config::toml_config::DnsStrategy::Host => 2,
        };
        self.dns_strategy.store(val, Ordering::Relaxed);
    }

    /// Return the configured DNS resolution strategy.
    pub fn dns_strategy(&self) -> crate::config::toml_config::DnsStrategy {
        match self.dns_strategy.load(Ordering::Relaxed) {
            1 => crate::config::toml_config::DnsStrategy::TunnelFirst,
            2 => crate::config::toml_config::DnsStrategy::Host,
            _ => crate::config::toml_config::DnsStrategy::TunnelOnly,
        }
    }

    /// Configure the handshake / endpoint resolution timeout for tunnel activation.
    pub fn set_handshake_timeout(&self, timeout: Duration) {
        let ms = timeout.as_millis().min(u128::from(u64::MAX)) as u64;
        self.handshake_timeout_ms
            .store(ms.max(1), Ordering::Relaxed);
    }

    /// Return the configured handshake / endpoint resolution timeout.
    pub fn handshake_timeout(&self) -> Duration {
        Duration::from_millis(self.handshake_timeout_ms.load(Ordering::Relaxed))
    }

    /// Configure whether dual-stack domain resolution prefers IPv6 (`AAAA`) over IPv4 (`A`).
    pub fn set_prefer_ipv6(&self, prefer: bool) {
        self.prefer_ipv6.store(prefer, Ordering::Relaxed);
    }

    /// Configure the global IP stack mode for newly booted tunnels.
    pub fn set_ip_mode(&self, mode: crate::config::IpMode) {
        self.ip_mode.store(mode.to_u8(), Ordering::Relaxed);
    }

    /// Return the configured global IP stack mode.
    pub fn ip_mode(&self) -> crate::config::IpMode {
        crate::config::IpMode::from_u8(self.ip_mode.load(Ordering::Relaxed))
    }

    /// Access the underlying [`TunnelRegistry`].
    pub const fn registry(&self) -> &Arc<TunnelRegistry> {
        &self.registry
    }

    /// Start the background debounced idle teardown task.
    pub fn start(self: &Arc<Self>) {
        let mut handle_lock = self.teardown_handle.lock();
        if handle_lock.is_some() {
            return;
        }
        let _ = self.shutdown_tx.send(false);

        let controller = Arc::clone(self);
        let mut shutdown_rx = self.shutdown_tx.subscribe();
        let interval = self.check_interval;

        let handle = tokio::spawn(async move {
            let mut ticker = tokio::time::interval(interval);
            ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

            loop {
                tokio::select! {
                    biased;
                    _ = shutdown_rx.changed() => {
                        if *shutdown_rx.borrow() {
                            break;
                        }
                    }
                    _ = ticker.tick() => {
                        controller.check_idle_tunnels().await;
                    }
                }
            }
        });

        *handle_lock = Some(handle);
    }

    /// Stop the background idle teardown task without closing tunnels yet.
    pub async fn stop_background_tasks(&self) {
        let _ = self.shutdown_tx.send(true);
        let handle = self.teardown_handle.lock().take();
        if let Some(h) = handle {
            let _ = h.await;
        }
    }

    /// Cleanly close all active and suspended tunnels in the registry and await reactor teardown.
    pub async fn close_all_tunnels(&self) {
        for entry in self.registry.all_entries() {
            let _ = self.close_tunnel(&entry.id).await;
        }
    }

    /// Stop the background idle teardown task and cleanly close all tunnels.
    pub async fn stop(&self) {
        self.stop_background_tasks().await;
        self.close_all_tunnels().await;
    }

    /// Cleanly close a tunnel: terminates its smoltcp reactor task and suspends its WireGuard device.
    pub async fn close_tunnel(&self, id: &str) -> Result<(), CoreError> {
        let entry = self
            .registry
            .get(id)
            .ok_or_else(|| CoreError::TunnelNotFound(id.to_string()))?;

        let _lock = entry.activation_lock.lock().await;

        let maybe_active = entry.active.write().take();
        if let Some(active) = maybe_active {
            tracing::debug!("Closing and shutting down netstack for tunnel '{}'", id);
            let () = active.device.suspend().await;
            active.netstack.close().await;
        }
        *entry.state.write() = TunnelState::Dormant;
        Ok(())
    }

    /// Ensure active+activating tunnel count is below `max_active_tunnels`, evicting oldest idle lazy tunnels if needed,
    /// and atomically reserve an `Activating` slot under `eviction_lock`.
    async fn enforce_max_active_tunnels(&self, target: &TunnelEntry) -> Result<(), CoreError> {
        let _evict_guard = self.eviction_lock.lock().await;
        let max_active = self.max_active_tunnels.load(Ordering::Relaxed);
        let active_or_activating_count = || {
            self.registry
                .all_entries()
                .into_iter()
                .filter(|e| {
                    e.id != target.id
                        && matches!(
                            *e.state.read(),
                            TunnelState::Active | TunnelState::Activating
                        )
                })
                .count()
        };

        if max_active != usize::MAX && active_or_activating_count() >= max_active {
            let mut candidates: Vec<(u64, String)> = self
                .registry
                .all_entries()
                .into_iter()
                .filter(|e| {
                    e.id != target.id
                        && e.lifecycle_mode == LifecycleMode::Lazy
                        && *e.state.read() == TunnelState::Active
                        && e.stats.active_conns.load(Ordering::SeqCst) == 0
                })
                .map(|e| (e.stats.last_active_at.load(Ordering::Relaxed), e.id.clone()))
                .collect();

            candidates.sort_by_key(|(last_active, _)| *last_active);

            for (_, evict_id) in candidates {
                if active_or_activating_count() < max_active {
                    break;
                }
                self.try_suspend_for_eviction(&evict_id).await;
            }

            if active_or_activating_count() >= max_active {
                return Err(CoreError::ActivationFailed(
                    target.id.clone(),
                    format!("max_active_tunnels ({max_active}) limit reached"),
                ));
            }
        }

        // Reserve slot while holding eviction_lock to eliminate TOCTOU race
        *target.state.write() = TunnelState::Activating;
        Ok(())
    }

    /// Non-blocking suspend helper used by `enforce_max_active_tunnels` to avoid lock-order inversion.
    async fn try_suspend_for_eviction(&self, id: &str) {
        let Some(entry) = self.registry.get(id) else {
            return;
        };
        let Ok(_lock) = entry.activation_lock.try_lock() else {
            return;
        };
        if entry.stats.active_conns.load(Ordering::SeqCst) > 0 {
            return;
        }
        if *entry.state.read() != TunnelState::Active {
            return;
        }
        let maybe_active = entry.active.read().clone();
        if let Some(active) = maybe_active {
            tracing::debug!("Evicting idle lazy tunnel '{}'", id);
            *entry.state.write() = TunnelState::Suspended;
            active.device.suspend().await;
            active.netstack.notify().notify_one();
        }
    }

    /// Get an active tunnel handle or dynamically boot/resume it on demand.
    ///
    /// Returns both the [`ActiveTunnel`] and a fresh [`TunnelConnGuard`].
    pub async fn get_or_activate(
        &self,
        id: &str,
    ) -> Result<(Arc<ActiveTunnel>, TunnelConnGuard), CoreError> {
        let entry = self
            .registry
            .get(id)
            .ok_or_else(|| CoreError::TunnelNotFound(id.to_string()))?;

        if entry.is_disabled() {
            return Err(CoreError::ActivationFailed(
                id.to_string(),
                "tunnel is disabled".into(),
            ));
        }

        let _lock = entry.activation_lock.lock().await;

        if entry.is_disabled() {
            return Err(CoreError::ActivationFailed(
                id.to_string(),
                "tunnel is disabled".into(),
            ));
        }

        // Check if already active or suspended
        let current_state = *entry.state.read();
        if current_state != TunnelState::Active {
            self.enforce_max_active_tunnels(&entry).await?;
        }

        match current_state {
            TunnelState::Active => {
                let active = entry.active.read().clone().ok_or_else(|| {
                    CoreError::ActivationFailed(id.to_string(), "active handle missing".into())
                })?;
                let guard = TunnelConnGuard::new(id, Arc::clone(&entry.stats));
                Ok((active, guard))
            }
            TunnelState::Suspended => {
                // Resume existing device with cancellation guard
                let activating_guard =
                    ActivatingGuard::with_revert_state(&entry, TunnelState::Suspended);
                let Some(active) = entry.active.read().clone() else {
                    *entry.state.write() = TunnelState::Dormant;
                    activating_guard.defuse();
                    return Err(CoreError::ActivationFailed(
                        id.to_string(),
                        "suspended handle missing".into(),
                    ));
                };

                tracing::debug!("Resuming suspended tunnel '{}'", id);
                if let Err(e) = active.device.resume().await {
                    let (threshold, cooldown) = self.health_check();
                    entry.health.record_failure(threshold, cooldown);
                    return Err(CoreError::ActivationFailed(
                        id.to_string(),
                        format!("device resume error: {e:?}"),
                    ));
                }

                *entry.state.write() = TunnelState::Active;
                activating_guard.defuse();
                let guard = TunnelConnGuard::new(id, Arc::clone(&entry.stats));
                Ok((active, guard))
            }
            TunnelState::Dormant | TunnelState::Activating => {
                let activating_guard = ActivatingGuard::new(&entry);
                let dns_fallback = *self.dns_fallback.lock();
                match Self::boot_tunnel(
                    &entry,
                    self.ip_mode(),
                    self.prefer_ipv6.load(Ordering::Relaxed),
                    self.handshake_timeout(),
                    dns_fallback,
                    self.dns_strategy(),
                )
                .await
                {
                    Ok(active) => {
                        *entry.active.write() = Some(Arc::clone(&active));
                        *entry.state.write() = TunnelState::Active;
                        activating_guard.defuse();

                        let guard = TunnelConnGuard::new(id, Arc::clone(&entry.stats));
                        Ok((active, guard))
                    }
                    Err(e) => {
                        drop(activating_guard);
                        let (threshold, cooldown) = self.health_check();
                        entry.health.record_failure(threshold, cooldown);
                        Err(e)
                    }
                }
            }
        }
    }

    /// Explicitly activate a tunnel without returning a connection guard (e.g. for Eager tunnels).
    pub async fn activate_tunnel(&self, id: &str) -> Result<Arc<ActiveTunnel>, CoreError> {
        let entry = self
            .registry
            .get(id)
            .ok_or_else(|| CoreError::TunnelNotFound(id.to_string()))?;

        if entry.is_disabled() {
            return Err(CoreError::ActivationFailed(
                id.to_string(),
                "tunnel is disabled".into(),
            ));
        }

        let _lock = entry.activation_lock.lock().await;

        if entry.is_disabled() {
            return Err(CoreError::ActivationFailed(
                id.to_string(),
                "tunnel is disabled".into(),
            ));
        }

        let current_state = *entry.state.read();
        if current_state != TunnelState::Active {
            self.enforce_max_active_tunnels(&entry).await?;
        }

        match current_state {
            TunnelState::Active => {
                let now = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs();
                entry.stats.last_active_at.store(now, Ordering::Relaxed);
                entry.active.read().clone().ok_or_else(|| {
                    CoreError::ActivationFailed(id.to_string(), "active handle missing".into())
                })
            }
            TunnelState::Suspended => {
                let activating_guard =
                    ActivatingGuard::with_revert_state(&entry, TunnelState::Suspended);
                let Some(active) = entry.active.read().clone() else {
                    *entry.state.write() = TunnelState::Dormant;
                    activating_guard.defuse();
                    return Err(CoreError::ActivationFailed(
                        id.to_string(),
                        "suspended handle missing".into(),
                    ));
                };

                tracing::debug!("Resuming suspended tunnel '{}'", id);
                if let Err(e) = active.device.resume().await {
                    let (threshold, cooldown) = self.health_check();
                    entry.health.record_failure(threshold, cooldown);
                    return Err(CoreError::ActivationFailed(
                        id.to_string(),
                        format!("device resume error: {e:?}"),
                    ));
                }

                let now = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs();
                entry.stats.last_active_at.store(now, Ordering::Relaxed);

                *entry.state.write() = TunnelState::Active;
                activating_guard.defuse();
                Ok(active)
            }
            TunnelState::Dormant | TunnelState::Activating => {
                let activating_guard = ActivatingGuard::new(&entry);
                let dns_fallback = *self.dns_fallback.lock();
                match Self::boot_tunnel(
                    &entry,
                    self.ip_mode(),
                    self.prefer_ipv6.load(Ordering::Relaxed),
                    self.handshake_timeout(),
                    dns_fallback,
                    self.dns_strategy(),
                )
                .await
                {
                    Ok(active) => {
                        *entry.active.write() = Some(Arc::clone(&active));
                        *entry.state.write() = TunnelState::Active;
                        activating_guard.defuse();
                        Ok(active)
                    }
                    Err(e) => {
                        drop(activating_guard);
                        let (threshold, cooldown) = self.health_check();
                        entry.health.record_failure(threshold, cooldown);
                        Err(e)
                    }
                }
            }
        }
    }

    /// Suspend an active tunnel using native [`gotatun::device::Device::suspend`].
    pub async fn suspend_tunnel(&self, id: &str) -> Result<(), CoreError> {
        let entry = self
            .registry
            .get(id)
            .ok_or_else(|| CoreError::TunnelNotFound(id.to_string()))?;

        let _lock = entry.activation_lock.lock().await;

        if entry.stats.active_conns.load(Ordering::SeqCst) > 0 {
            tracing::debug!(
                "Aborting suspension for tunnel '{}': active connections exist",
                id
            );
            return Ok(());
        }

        if *entry.state.read() != TunnelState::Active {
            return Ok(());
        }

        let maybe_active = entry.active.read().clone();
        if let Some(active) = maybe_active {
            tracing::debug!("Suspending active tunnel '{}'", id);
            *entry.state.write() = TunnelState::Suspended;
            active.device.suspend().await;
            active.netstack.notify().notify_one();
        }

        Ok(())
    }

    /// Build a new [`ActiveTunnel`] from a dormant [`TunnelEntry`].
    async fn boot_tunnel(
        entry: &TunnelEntry,
        ip_mode: crate::config::IpMode,
        prefer_ipv6: bool,
        handshake_timeout: Duration,
        dns_fallback: SocketAddr,
        dns_strategy: crate::config::toml_config::DnsStrategy,
    ) -> Result<Arc<ActiveTunnel>, CoreError> {
        let (config_interface, config_peers) = {
            let cfg = entry.config.read();
            (cfg.interface.clone(), cfg.peers.clone())
        };
        let mtu = config_interface.mtu;
        let (bridge, bridge_tx, bridge_rx) = VirtualTunBridge::new(mtu, DEFAULT_CHANNEL_CAPACITY);

        // Prepare peers
        let mut peers = Vec::with_capacity(config_peers.len());
        for p_cfg in &config_peers {
            let mut peer = gotatun::device::Peer::new(p_cfg.public_key);
            if let Ok(addr) = p_cfg.endpoint.parse::<SocketAddr>() {
                peer.endpoint = Some(addr);
            } else {
                match tokio::time::timeout(
                    handshake_timeout,
                    tokio::net::lookup_host(&p_cfg.endpoint),
                )
                .await
                {
                    Ok(Ok(mut addrs)) => {
                        let Some(addr) = addrs.next() else {
                            return Err(CoreError::ActivationFailed(
                                entry.id.clone(),
                                format!(
                                    "endpoint DNS lookup returned no addresses for '{}'",
                                    p_cfg.endpoint
                                ),
                            ));
                        };
                        peer.endpoint = Some(addr);
                    }
                    Ok(Err(e)) => {
                        return Err(CoreError::ActivationFailed(
                            entry.id.clone(),
                            format!("endpoint DNS lookup failed for '{}': {e}", p_cfg.endpoint),
                        ));
                    }
                    Err(_) => {
                        return Err(CoreError::ActivationFailed(
                            entry.id.clone(),
                            format!("endpoint DNS lookup timed out for '{}'", p_cfg.endpoint),
                        ));
                    }
                }
            }
            peer.allowed_ips = p_cfg.allowed_ips.clone();
            peer.preshared_key = p_cfg.preshared_key;
            peer.keepalive = p_cfg.persistent_keepalive;
            peers.push(peer);
        }

        // Build gotatun Device
        let mut builder = gotatun::device::DeviceBuilder::new()
            .with_default_udp()
            .with_ip_pair(bridge_tx, bridge_rx)
            .with_private_key(config_interface.private_key.clone())
            .with_peers(peers)
            .suspended(false);

        if let Some(port) = config_interface.listen_port {
            builder = builder.with_listen_port(port);
        }

        let device = builder.build().await.map_err(|e| {
            CoreError::ActivationFailed(
                entry.id.clone(),
                format!("failed to build gotatun device: {e:?}"),
            )
        })?;

        // Build smoltcp VirtualNetworkStack
        let netstack = match VirtualNetworkStack::new_with_options(
            &config_interface,
            bridge,
            ip_mode,
            prefer_ipv6,
            (dns_fallback, dns_strategy),
            handshake_timeout,
        ) {
            Ok(ns) => ns,
            Err(e) => {
                let () = device.suspend().await;
                return Err(CoreError::ActivationFailed(
                    entry.id.clone(),
                    format!("failed to build netstack: {e:?}"),
                ));
            }
        };

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        entry.stats.last_active_at.store(now, Ordering::Relaxed);

        let active = Arc::new(ActiveTunnel::new(
            entry.id.clone(),
            device,
            Arc::new(netstack),
            Arc::clone(&entry.stats),
        ));

        Ok(active)
    }

    /// Periodically inspects all tunnels and suspends idle lazy tunnels.
    pub async fn check_idle_tunnels(&self) {
        let entries = self.registry.all_entries();
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        for entry in entries {
            let disable_pending = entry.is_disable_pending();
            // Eager tunnels never idle-suspend — except when a disable is
            // waiting for their live sessions to drain (audit run-1,
            // medium): a disabled eager tunnel must be re-attempted once
            // idle, or it stays Active forever.
            if entry.lifecycle_mode == LifecycleMode::Eager && !disable_pending {
                continue;
            }

            if *entry.state.read() != TunnelState::Active {
                continue;
            }

            let active_conns = entry.stats.active_conns.load(Ordering::SeqCst);
            if active_conns == 0 {
                if disable_pending {
                    // A disabled tunnel with drained connections suspends
                    // immediately, regardless of mode or idle timeout.
                    let _ = self.suspend_tunnel(&entry.id).await;
                    if *entry.state.read() != TunnelState::Active {
                        entry.set_disable_pending(false);
                    }
                    continue;
                }
                let last_active = entry.stats.last_active_at.load(Ordering::Relaxed);
                let idle_secs = if last_active > 0 {
                    now.saturating_sub(last_active)
                } else {
                    entry.stats.last_active_at.store(now, Ordering::Relaxed);
                    0
                };

                let idle_timeout_secs = self.idle_timeout().as_secs();
                if idle_secs >= idle_timeout_secs {
                    tracing::info!(
                        "Tunnel '{}' idle for {}s (threshold: {}s); suspending to save resources",
                        entry.id,
                        idle_secs,
                        idle_timeout_secs
                    );
                    let _ = self.suspend_tunnel(&entry.id).await;
                }
            }
        }
    }
}
