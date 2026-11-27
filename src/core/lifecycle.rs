//! Lazy and on-demand tunnel lifecycle management.
//!
//! Provides [`LifecycleController`] managing on-demand boot, native `Device::suspend()` and `Device::resume()`,
//! RAII active connection tracking via [`TunnelConnGuard`], and debounced background idle teardown.

use std::collections::HashMap;
use std::future::Future;
use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::atomic::Ordering;
use std::sync::{Arc, LazyLock};
use std::time::{Duration, Instant};

use gotatun::device::{Device, DeviceBuilder, Peer};
use gotatun::tun::{IpRecv, IpSend};
use gotatun::udp::UdpTransportFactory;
use parking_lot::{Mutex, RwLock};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::sync::watch;
use tokio::task::JoinHandle;
use x25519_dalek::StaticSecret;

use crate::config::{LifecycleMode, WgInterfaceConfig, WgPeerConfig};
use crate::core::CoreError;
use crate::core::health::{HealthStatus, TunnelHealthTracker};
use crate::core::protector::{ProtectedUdpFactory, SocketProtector};
use crate::core::registry::{
    ActiveTunnel, TunnelEntry, TunnelRegistry, TunnelState, TunnelStats, WgDevice,
};
use crate::core::selection::WarmList;
use crate::netstack::tun::TunEndpoint;
use crate::netstack::{
    DEFAULT_CHANNEL_CAPACITY, DnsLruCache, StackDnsConfig, VirtualNetworkStack, VirtualTunBridge,
};
use crate::proxy::router::is_forbidden_destination_ip;
use crate::proxy::{DynStream, ProxyTunnelTarget, ProxyUdpSocket};

/// RAII Guard tracking an active connection routed through a specific tunnel.
///
/// Increments the tunnel's `active_conns` count on creation and decrements it on drop.
/// When the active count reaches zero, records `last_active_at` for idle teardown debouncing.
///
/// This is the pool's inflight guard: it is acquired at selection time
/// ([`LifecycleController::get_or_activate`] creates one per selected
/// tunnel, including each leg of a race) and released exactly once by
/// `Drop` — there is no manual release path alongside it, so a
/// cancelled Tokio task cannot leak a count and the counter cannot
/// underflow ([`TunnelStats::dec_conns`] refuses to decrement past
/// zero). A racing loser's guard is released when its target handle
/// is dropped at the end of the race round.
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
    /// Pool warm list to seed on a proven dial, if this target was
    /// built by a pool router. `None` for dedicated routers and
    /// test-built targets, which have no pool to seed.
    warm_list: Option<Arc<WarmList>>,
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
            warm_list: None,
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
            warm_list: None,
        }
    }

    /// Attach the pool warm list this target reports proven dials to.
    /// Called by the pool router after construction; a target without
    /// a warm list simply does not seed one.
    pub(crate) fn set_warm_list(&mut self, warm_list: Arc<WarmList>) {
        self.warm_list = Some(warm_list);
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
                        let handshaked_recently = handshake_is_fresh(
                            tunnel.stats.last_handshake.load(Ordering::Relaxed),
                            now_unix_secs(),
                        );
                        if is_destination_caused_error(e.kind(), handshaked_recently) {
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

/// A WireGuard handshake counts as fresh for failure attribution when it
/// completed within this window. The prober re-handshakes every healthy
/// tunnel each `probe_interval` (30s by default), so a live tunnel's last
/// handshake is at most one interval plus one slow probe pass old. A
/// timeout against a tunnel whose last handshake is older than this
/// points at the dead peer, not at a blackholing destination, so it must
/// count as a tunnel-side failure (and trip the breaker) instead of being
/// excused as destination-caused — otherwise a tunnel that died after
/// proving itself once keeps being selected forever, burning the pool
/// failover budget on DNS timeouts until the prober happens to re-mark
/// it.
pub(crate) const HANDSHAKE_FRESHNESS_WINDOW_SECS: u64 = 90;

/// Whether the tunnel's last successful handshake is fresh enough that a
/// timeout is more plausibly the destination's fault than the peer's.
/// A tunnel that never handshaked (`last_handshake_secs == 0`) is never
/// fresh.
pub(crate) const fn handshake_is_fresh(last_handshake_secs: u64, now_secs: u64) -> bool {
    last_handshake_secs > 0
        && now_secs.saturating_sub(last_handshake_secs) < HANDSHAKE_FRESHNESS_WINDOW_SECS
}

/// Whether a failed attempt says nothing about the tunnel's health: the
/// failure is attributable to the client-chosen destination, not to the
/// WireGuard peer. Such attempts must not trip the circuit breaker
/// (audit run-1, medium). A refused connection proves the tunnel carried
/// the SYN and got an answer back; an unroutable address family or a
/// nonexistent domain is a property of the request; a timeout against a
/// peer that has handshaked recently points at a blackholing destination,
/// while a timeout against a peer whose last handshake is stale — or
/// that never handshaked — points at the peer itself, so it stays a
/// failure.
pub(crate) const fn is_destination_caused_error(
    kind: io::ErrorKind,
    handshaked_recently: bool,
) -> bool {
    // `std::io::ErrorKind` is `#[non_exhaustive]` with ~40 variants; the
    // destination-caused ones are listed explicitly and all others stay
    // tunnel-side failures.
    #[allow(
        clippy::wildcard_enum_match_arm,
        reason = "io::ErrorKind is non_exhaustive with ~40 variants; unlisted kinds stay tunnel-side failures"
    )]
    match kind {
        io::ErrorKind::ConnectionRefused
        | io::ErrorKind::AddrNotAvailable
        | io::ErrorKind::InvalidInput
        | io::ErrorKind::NotFound => true,
        io::ErrorKind::TimedOut => handshaked_recently,
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
        let warm_list = self.warm_list.clone();
        Box::pin(async move {
            // Time the dial: the verdict feeds the Peak-EWMA latency
            // score, so a tunnel that dials slowly (or not at all) is
            // deprioritised by the next selection instead of being
            // retried blindly. A cached DNS answer is not timed here —
            // only the dial that actually crosses the tunnel counts.
            let started = Instant::now();
            match tunnel.tcp_connect(dst).await {
                Ok(stream) => {
                    tunnel.stats.record_handshake(now_unix_secs());
                    let sample_ms =
                        u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX);
                    tunnel.stats.record_rtt_sample(sample_ms);
                    trial_resolved.store(true, Ordering::Relaxed);
                    if let Some(h) = &health {
                        h.record_success();
                    }
                    if let Some(warm) = &warm_list {
                        warm.note_success(guard.tunnel_id());
                    }
                    let guarded: DynStream = Box::new(GuardedStream {
                        inner: stream,
                        _guard: guard,
                    });
                    Ok(guarded)
                }
                Err(e) => {
                    trial_resolved.store(true, Ordering::Relaxed);
                    let handshaked_recently = handshake_is_fresh(
                        tunnel.stats.last_handshake.load(Ordering::Relaxed),
                        now_unix_secs(),
                    );
                    // A tunnel-side failure counts as a maximally slow
                    // latency sample, so the score jumps at once. A
                    // destination-caused failure (refused, unroutable,
                    // or a timeout against a freshly handshaked peer)
                    // says nothing about the tunnel and must not
                    // poison its score — one slow target would
                    // otherwise demote every tunnel in turn.
                    if !is_destination_caused_error(e.kind(), handshaked_recently) {
                        tunnel.stats.record_rtt_failure();
                    }
                    if let Some(h) = &health {
                        if is_destination_caused_error(e.kind(), handshaked_recently) {
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
        let mode = self.tunnel.effective_ip_mode();
        self.resolve_in_tunnel_with_mode(domain, mode)
    }

    fn resolve_all_in_tunnel<'a>(
        &'a self,
        domain: &'a str,
    ) -> crate::proxy::router::ResolveAllFut<'a> {
        let mode = self.tunnel.effective_ip_mode();
        self.resolve_all_in_tunnel_with_mode(domain, mode)
    }

    fn tunnel_id(&self) -> Option<&str> {
        Some(self.guard.tunnel_id())
    }

    fn connect_timeout(&self) -> Duration {
        self.tunnel.connect_timeout()
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

    fn is_live(&self) -> bool {
        // A live session means this tunnel moved real traffic recently.
        // A fresh handshake alone is not enough: an in-tunnel DNS
        // resolve records one even when the answer came from the shared
        // cache without any packet crossing the tunnel. Healthy alone
        // is not enough either: it persists until failures trip the
        // breaker, while the session may have gone stale since the last
        // success. Both together — Healthy plus a fresh handshake —
        // mean the tunnel proved itself by moving traffic within the
        // freshness window. Without a tracker there is no health
        // signal, so a fresh handshake is the best available evidence.
        let fresh = handshake_is_fresh(
            self.tunnel.stats.last_handshake.load(Ordering::Relaxed),
            now_unix_secs(),
        );
        if !fresh {
            return false;
        }
        self.health
            .as_ref()
            .is_none_or(|h| h.current_status() == HealthStatus::Healthy)
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

/// Floor for the suspended-tunnel close threshold (seconds). A suspended
/// tunnel is only closed after `max(2 * idle_timeout, this)` seconds of
/// idleness, so a short operator-configured idle timeout cannot close a
/// tunnel whose WireGuard session is still resumable (session lifetime
/// is ~180s; the P2C warm window is 120s).
const MIN_CLOSE_AFTER_SECS: u64 = 300;

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
    /// Daemon-wide DNS cache shared by every tunnel's resolver, so
    /// round-robin across many tunnels does not re-resolve the same domain
    /// on every connection (each tunnel's own cache would go cold between
    /// its turns).
    shared_dns_cache: Arc<DnsLruCache>,
    /// VPN mode: when true, `boot_tunnel` builds devices on the shared
    /// TUN endpoint with a protected UDP factory instead of the smoltcp
    /// bridge + netstack. Off by default; the daemon proxy path is
    /// untouched while off.
    vpn_mode: std::sync::atomic::AtomicBool,
    /// Installed socket protector (`VpnService.protect`), if any.
    socket_protector: RwLock<Option<Arc<dyn SocketProtector>>>,
    /// Shared TUN endpoint for VPN mode, if one was attached.
    tun_endpoint: RwLock<Option<Arc<TunEndpoint>>>,
}

/// Union of all peers' `AllowedIPs` for one tunnel entry.
fn allowed_ips_of(entry: &TunnelEntry) -> Vec<ipnetwork::IpNetwork> {
    entry
        .config
        .read()
        .peers
        .iter()
        .flat_map(|peer| peer.allowed_ips.iter().copied())
        .collect()
}

/// The tunnel's `Interface` addresses, used by the VPN data plane for
/// per-tunnel source NAT.
fn interface_addrs_of(entry: &TunnelEntry) -> Vec<ipnetwork::IpNetwork> {
    entry.config.read().interface.addresses.clone()
}

/// How long a resolved WireGuard endpoint address is reused before a
/// fresh DNS lookup is required. Operators usually point every tunnel
/// at one endpoint hostname, so a single cached answer serves all of
/// them while it is fresh.
const ENDPOINT_DNS_CACHE_TTL: Duration = Duration::from_secs(300);

/// How long a stale endpoint address may keep being served after a
/// lookup timeout. A timeout means the resolver cannot currently
/// confirm the edge, so the stale address may point at a dead edge:
/// it must not be served for the remainder of the 300 s TTL. Capping
/// it to this window bounds the damage while still bridging a
/// transient DNS outage; after it, the next activation re-resolves
/// (and may land on a different, live edge).
const ENDPOINT_DNS_STALE_SERVE_WINDOW: Duration = Duration::from_secs(30);

/// One cached WireGuard endpoint DNS answer.
#[derive(Debug)]
struct EndpointDnsCacheEntry {
    addr: SocketAddr,
    expires_at: Instant,
}

/// Small TTL cache for WireGuard endpoint DNS answers, shared by every
/// tunnel activation.
///
/// This is separate from the target-domain cache in
/// [`crate::netstack::DnsLruCache`]: that one resolves the *destination*
/// of a proxied connection, while this one resolves the *endpoint* a
/// tunnel itself dials (e.g. `engage.cloudflareclient.com:2408`).
/// Without it, every dormant-tunnel activation pays a fresh OS-resolver
/// round trip for the same hostname, and a slow lookup stalls the
/// activation until the handshake timeout.
///
/// The map is keyed by the endpoint string as written in config and is
/// bounded by the number of distinct configured endpoints; it is not
/// an LRU because the key space is tiny and config-bound.
#[derive(Debug)]
struct EndpointDnsCache {
    entries: RwLock<HashMap<String, EndpointDnsCacheEntry>>,
}

impl EndpointDnsCache {
    fn new() -> Self {
        Self {
            entries: RwLock::new(HashMap::new()),
        }
    }

    /// The cached address, but only while it is still fresh.
    fn get(&self, endpoint: &str) -> Option<SocketAddr> {
        let entries = self.entries.read();
        entries
            .get(endpoint)
            .filter(|entry| Instant::now() < entry.expires_at)
            .map(|entry| entry.addr)
    }

    /// The cached address regardless of freshness, served only when a
    /// fresh lookup times out — with its remaining lifetime capped to
    /// `window`: a lookup timeout means the resolver cannot currently
    /// confirm the edge, so the stale address may point at a dead edge
    /// and must not be served for the remainder of the TTL. The cap is
    /// applied atomically with the read, so a fresh entry inserted
    /// concurrently is never shortened by mistake.
    fn serve_stale_capped(&self, endpoint: &str, window: Duration) -> Option<SocketAddr> {
        let mut entries = self.entries.write();
        let entry = entries.get_mut(endpoint)?;
        let capped = Instant::now() + window;
        if entry.expires_at > capped {
            entry.expires_at = capped;
        }
        let addr = entry.addr;
        drop(entries);
        Some(addr)
    }

    /// Drop the cached address for an endpoint, forcing the next
    /// activation to re-resolve it. Used when a tunnel that never
    /// handshaked fails its probe: the cached edge IP may be dead,
    /// and serving it for the rest of the TTL would keep every
    /// activation dialing the same dead edge.
    fn invalidate(&self, endpoint: &str) {
        self.entries.write().remove(endpoint);
    }

    fn insert(&self, endpoint: &str, addr: SocketAddr) {
        let mut entries = self.entries.write();
        entries.insert(
            endpoint.to_string(),
            EndpointDnsCacheEntry {
                addr,
                expires_at: Instant::now() + ENDPOINT_DNS_CACHE_TTL,
            },
        );
    }

    /// Test-only: store an entry that is already expired, so tests can
    /// force a fresh lookup without waiting out the TTL.
    #[cfg(test)]
    fn insert_expired(&self, endpoint: &str, addr: SocketAddr) {
        let mut entries = self.entries.write();
        entries.insert(
            endpoint.to_string(),
            EndpointDnsCacheEntry {
                addr,
                expires_at: Instant::now()
                    .checked_sub(Duration::from_secs(1))
                    .unwrap_or_else(Instant::now),
            },
        );
    }
}

/// Daemon-wide endpoint DNS cache shared by every tunnel activation.
static ENDPOINT_DNS_CACHE: LazyLock<EndpointDnsCache> = LazyLock::new(EndpointDnsCache::new);

/// Drop the cached endpoint address for `endpoint`, forcing the next
/// activation to re-resolve it. The cache key is the endpoint string
/// as written in config, so callers pass exactly that string. A
/// missing key is a no-op (literal-IP endpoints never enter the
/// cache). Called when a tunnel that never handshaked fails its
/// probe: the cached edge IP may be dead.
pub(crate) fn invalidate_endpoint_dns_cache(endpoint: &str) {
    ENDPOINT_DNS_CACHE.invalidate(endpoint);
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
            shared_dns_cache: Arc::new(DnsLruCache::new(2048)),
            vpn_mode: std::sync::atomic::AtomicBool::new(false),
            socket_protector: RwLock::new(None),
            tun_endpoint: RwLock::new(None),
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

    /// Enable or disable VPN mode. When enabled, newly booted tunnels
    /// use the shared TUN endpoint and a protected UDP factory.
    /// `set_vpn_mode` itself does not migrate tunnels that are
    /// already active; [`Engine::attach_tun`] migrates those via
    /// [`Self::migrate_proxy_tunnels_to_vpn`] after installing the
    /// endpoint.
    pub fn set_vpn_mode(&self, enabled: bool) {
        self.vpn_mode.store(enabled, Ordering::Relaxed);
    }

    /// Return whether VPN mode is active.
    pub fn vpn_mode(&self) -> bool {
        self.vpn_mode.load(Ordering::Relaxed)
    }

    /// Install the socket protector used for WireGuard UDP sockets
    /// booted in VPN mode.
    pub fn set_socket_protector(&self, protector: Arc<dyn SocketProtector>) {
        *self.socket_protector.write() = Some(protector);
    }

    /// Return the installed socket protector, if any.
    pub fn socket_protector(&self) -> Option<Arc<dyn SocketProtector>> {
        self.socket_protector.read().clone()
    }

    /// Attach (or clear with `None`) the shared TUN endpoint used by
    /// VPN-mode tunnels.
    pub fn set_tun_endpoint(&self, endpoint: Option<Arc<TunEndpoint>>) {
        *self.tun_endpoint.write() = endpoint;
    }

    /// Return the attached TUN endpoint, if any.
    pub fn tun_endpoint(&self) -> Option<Arc<TunEndpoint>> {
        self.tun_endpoint.read().clone()
    }

    /// Drop one tunnel's route from the TUN endpoint (suspend path);
    /// no-op when no endpoint is attached.
    fn detach_vpn_route(&self, id: &str) {
        if let Some(endpoint) = self.tun_endpoint() {
            endpoint.suspend_tunnel(id);
        }
    }

    /// Re-add one tunnel's route to the TUN endpoint (resume path);
    /// no-op when VPN mode is off or no endpoint is attached.
    fn attach_vpn_route(&self, entry: &TunnelEntry) {
        if !self.vpn_mode() {
            return;
        }
        let Some(endpoint) = self.tun_endpoint() else {
            return;
        };
        endpoint.resume_tunnel(&entry.id, allowed_ips_of(entry), interface_addrs_of(entry));
    }

    /// IDs of tunnels currently booted in proxy mode (Active or
    /// Suspended with a `WgDevice::Proxy` device). These are the
    /// tunnels `attach_tun` must migrate to VPN mode.
    pub fn proxy_booted_tunnel_ids(&self) -> Vec<String> {
        self.registry
            .all_entries()
            .into_iter()
            .filter(|entry| {
                matches!(
                    *entry.state.read(),
                    TunnelState::Active | TunnelState::Suspended
                ) && entry
                    .active
                    .read()
                    .as_ref()
                    .is_some_and(|active| matches!(active.device, WgDevice::Proxy(_)))
            })
            .map(|entry| entry.id.clone())
            .collect()
    }

    /// Re-boot every proxy-booted tunnel in VPN mode, returning the
    /// migrated IDs. Called by `attach_tun` after the TUN endpoint is
    /// installed and VPN mode is on: a proxy-booted device can only
    /// change mode by being closed and re-booted, because
    /// `activate_tunnel` returns the existing handle for an Active
    /// tunnel and the suspend/resume path re-adds the route only for
    /// tunnels that already have a TUN channel. A migration failure
    /// closes the tunnels already migrated, so no VPN-mode device is
    /// left on an endpoint the caller is about to tear down; the
    /// failed tunnel itself is left Dormant. Live proxy sessions on
    /// a migrated tunnel are dropped by the close.
    pub async fn migrate_proxy_tunnels_to_vpn(&self) -> Result<Vec<String>, CoreError> {
        let ids = self.proxy_booted_tunnel_ids();
        let mut migrated: Vec<String> = Vec::with_capacity(ids.len());
        for id in ids {
            if let Err(e) = self.close_tunnel(&id).await {
                self.unwind_migrated(&migrated).await;
                return Err(e);
            }
            match self.activate_tunnel(&id).await {
                Ok(_) => migrated.push(id),
                Err(e) => {
                    self.unwind_migrated(&migrated).await;
                    return Err(e);
                }
            }
        }
        Ok(migrated)
    }

    /// Best-effort close of tunnels already migrated by
    /// [`Self::migrate_proxy_tunnels_to_vpn`], used when a later
    /// migration fails.
    async fn unwind_migrated(&self, migrated: &[String]) {
        for id in migrated {
            let _ = self.close_tunnel(id).await;
        }
    }

    /// Detach one tunnel from the TUN endpoint entirely (close path);
    /// no-op when no endpoint is attached.
    fn detach_vpn_tunnel(&self, id: &str) {
        if let Some(endpoint) = self.tun_endpoint() {
            endpoint.detach_tunnel(id);
        }
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
        if let Some(handle) = self.stop_background_tasks_sync() {
            let _ = handle.await;
        }
    }

    /// Synchronously signal the idle-teardown task to stop and detach
    /// it without waiting. The caller may abort the returned handle
    /// when waiting is impossible (e.g. `Drop` paths); the signal
    /// alone stops the loop at its next tick (audit run-1,
    /// `uniffi:engine-destroy-without-stop-detached-vpn`).
    pub fn stop_background_tasks_sync(&self) -> Option<JoinHandle<()>> {
        let _ = self.shutdown_tx.send(true);
        self.teardown_handle.lock().take()
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
            active.close_netstack().await;
        }
        self.detach_vpn_tunnel(id);
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
            active.notify_netstack();
            self.detach_vpn_route(id);
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
                self.attach_vpn_route(&entry);
                entry.stats.record_activated(now_unix_secs());
                let guard = TunnelConnGuard::new(id, Arc::clone(&entry.stats));
                Ok((active, guard))
            }
            TunnelState::Dormant | TunnelState::Activating => {
                let activating_guard = ActivatingGuard::new(&entry);
                let dns = StackDnsConfig::with_shared_cache(
                    *self.dns_fallback.lock(),
                    self.dns_strategy(),
                    Arc::clone(&self.shared_dns_cache),
                );
                match self
                    .boot_tunnel(
                        &entry,
                        self.ip_mode(),
                        self.prefer_ipv6.load(Ordering::Relaxed),
                        self.handshake_timeout(),
                        &dns,
                    )
                    .await
                {
                    Ok(active) => {
                        *entry.active.write() = Some(Arc::clone(&active));
                        *entry.state.write() = TunnelState::Active;
                        activating_guard.defuse();
                        entry.stats.record_activated(now_unix_secs());

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
                self.attach_vpn_route(&entry);
                entry.stats.record_activated(now_unix_secs());
                Ok(active)
            }
            TunnelState::Dormant | TunnelState::Activating => {
                let activating_guard = ActivatingGuard::new(&entry);
                let dns = StackDnsConfig::with_shared_cache(
                    *self.dns_fallback.lock(),
                    self.dns_strategy(),
                    Arc::clone(&self.shared_dns_cache),
                );
                match self
                    .boot_tunnel(
                        &entry,
                        self.ip_mode(),
                        self.prefer_ipv6.load(Ordering::Relaxed),
                        self.handshake_timeout(),
                        &dns,
                    )
                    .await
                {
                    Ok(active) => {
                        *entry.active.write() = Some(Arc::clone(&active));
                        *entry.state.write() = TunnelState::Active;
                        activating_guard.defuse();
                        entry.stats.record_activated(now_unix_secs());
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
            active.notify_netstack();
            self.detach_vpn_route(id);
        }

        Ok(())
    }

    /// Build a new [`ActiveTunnel`] from a dormant [`TunnelEntry`].
    ///
    /// In proxy mode (default) the device is built on a
    /// [`VirtualTunBridge`] + [`VirtualNetworkStack`]. In VPN mode the
    /// device is built on the shared [`TunEndpoint`] pair with a
    /// [`ProtectedUdpFactory`], and no smoltcp stack is created.
    async fn boot_tunnel(
        &self,
        entry: &TunnelEntry,
        ip_mode: crate::config::IpMode,
        prefer_ipv6: bool,
        handshake_timeout: Duration,
        dns: &StackDnsConfig,
    ) -> Result<Arc<ActiveTunnel>, CoreError> {
        let (config_interface, config_peers) = {
            let cfg = entry.config.read();
            (cfg.interface.clone(), cfg.peers.clone())
        };
        let peers = Self::build_peers(&config_peers, handshake_timeout, &entry.id).await?;
        if self.vpn_mode() {
            return self.boot_tunnel_vpn(entry, &config_interface, peers).await;
        }

        let mtu = config_interface.mtu;
        let (bridge, bridge_tx, bridge_rx) = VirtualTunBridge::new(mtu, DEFAULT_CHANNEL_CAPACITY);
        let builder = DeviceBuilder::new()
            .with_default_udp()
            .with_ip_pair(bridge_tx, bridge_rx);
        let device = Self::finish_device_build(
            builder,
            config_interface.private_key.clone(),
            peers,
            config_interface.listen_port,
            &entry.id,
        )
        .await
        .map(WgDevice::Proxy)?;

        // Build smoltcp VirtualNetworkStack (shares the daemon-wide DNS cache)
        let netstack = match VirtualNetworkStack::new_with_options(
            &config_interface,
            bridge,
            ip_mode,
            prefer_ipv6,
            dns,
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

        Ok(Self::new_active_tunnel(
            entry,
            device,
            Some(Arc::new(netstack)),
        ))
    }

    /// Build a new [`ActiveTunnel`] in VPN mode: device on the shared
    /// TUN endpoint with a protected UDP factory, no smoltcp stack.
    /// The tunnel is registered with the endpoint's router before the
    /// device is built; a failed build unregisters it again.
    async fn boot_tunnel_vpn(
        &self,
        entry: &TunnelEntry,
        interface: &WgInterfaceConfig,
        peers: Vec<Peer>,
    ) -> Result<Arc<ActiveTunnel>, CoreError> {
        let endpoint = self.tun_endpoint().ok_or_else(|| {
            CoreError::ActivationFailed(
                entry.id.clone(),
                "vpn mode active but no TUN endpoint attached (call attach_tun first)".into(),
            )
        })?;
        // Fail closed before registering any route: without a
        // protector the tunnel's own handshake packets would be
        // routed into the TUN interface and wedge the tunnel (audit
        // run-1, `uniffi:vpn-mode-unprotected-udp-fallback`). There
        // is no unprotected fallback here; install a protector with
        // `set_socket_protector` first.
        let Some(factory) = self.socket_protector().map(ProtectedUdpFactory::new) else {
            return Err(CoreError::ActivationFailed(
                entry.id.clone(),
                "vpn mode requires a socket protector (call set_socket_protector before attach_tun); refusing to boot with unprotected sockets".into(),
            ));
        };
        let (ip_send, ip_recv) =
            endpoint.attach_tunnel(&entry.id, allowed_ips_of(entry), interface_addrs_of(entry));
        let builder = DeviceBuilder::new()
            .with_udp(factory)
            .with_ip_pair(ip_send, ip_recv);
        let device = match Self::finish_device_build(
            builder,
            interface.private_key.clone(),
            peers,
            interface.listen_port,
            &entry.id,
        )
        .await
        {
            Ok(device) => WgDevice::Vpn(device),
            Err(e) => {
                endpoint.detach_tunnel(&entry.id);
                return Err(e);
            }
        };
        Ok(Self::new_active_tunnel(entry, device, None))
    }

    /// Record activation time and wrap a fresh device in an [`ActiveTunnel`].
    fn new_active_tunnel(
        entry: &TunnelEntry,
        device: WgDevice,
        netstack: Option<Arc<VirtualNetworkStack>>,
    ) -> Arc<ActiveTunnel> {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        entry.stats.last_active_at.store(now, Ordering::Relaxed);
        Arc::new(ActiveTunnel::new(
            entry.id.clone(),
            device,
            netstack,
            Arc::clone(&entry.stats),
        ))
    }

    /// Resolve a non-literal WireGuard endpoint hostname through DNS,
    /// reusing the shared endpoint cache while its answer is fresh.
    ///
    /// A lookup timeout is transient (slow or unreachable DNS), so the
    /// last-known-good cached address is served instead and a warning
    /// is logged: a wrong endpoint only fails the handshake. The stale
    /// address is served for at most
    /// [`ENDPOINT_DNS_STALE_SERVE_WINDOW`] more — a dead edge must not
    /// be pinned for the rest of the TTL. A hard
    /// resolution error, an empty answer, or an answer of only
    /// forbidden addresses keeps the existing strict failure: those
    /// mean the name is gone or hijacked, and masking them would hide
    /// a config problem.
    ///
    /// The cache lock is never held across the `.await`: the fresh
    /// check, the lookup, and the store are three separate critical
    /// sections.
    ///
    /// # Errors
    /// Returns [`CoreError::ActivationFailed`] when the endpoint
    /// cannot be resolved and no cached address exists.
    async fn resolve_endpoint_cached(
        cache: &EndpointDnsCache,
        endpoint: &str,
        handshake_timeout: Duration,
        tunnel_id: &str,
    ) -> Result<SocketAddr, CoreError> {
        if let Some(addr) = cache.get(endpoint) {
            return Ok(addr);
        }
        match tokio::time::timeout(handshake_timeout, tokio::net::lookup_host(endpoint)).await {
            Ok(Ok(addrs)) => {
                let addrs: Vec<SocketAddr> = addrs.collect();
                if addrs.is_empty() {
                    return Err(CoreError::ActivationFailed(
                        tunnel_id.to_string(),
                        format!("endpoint DNS lookup returned no addresses for '{endpoint}'"),
                    ));
                }
                // The host resolver's answer is third-party data, not
                // operator config: never handshake an endpoint that
                // resolves to a forbidden address (loopback/private/
                // link-local/...). Take the first allowed answer; when
                // every answer is forbidden, fail the tunnel instead
                // of silently using a dangerous one (audit run-1,
                // `lifecycle:build-peers-unchecked-dns-endpoint`).
                let Some(addr) = addrs
                    .iter()
                    .copied()
                    .find(|addr| !is_forbidden_destination_ip(addr.ip()))
                else {
                    return Err(CoreError::ActivationFailed(
                        tunnel_id.to_string(),
                        format!(
                            "endpoint DNS lookup for '{endpoint}' resolved only to forbidden addresses"
                        ),
                    ));
                };
                cache.insert(endpoint, addr);
                Ok(addr)
            }
            Ok(Err(e)) => Err(CoreError::ActivationFailed(
                tunnel_id.to_string(),
                format!("endpoint DNS lookup failed for '{endpoint}': {e}"),
            )),
            Err(_) => {
                let Some(addr) =
                    cache.serve_stale_capped(endpoint, ENDPOINT_DNS_STALE_SERVE_WINDOW)
                else {
                    return Err(CoreError::ActivationFailed(
                        tunnel_id.to_string(),
                        format!("endpoint DNS lookup timed out for '{endpoint}'"),
                    ));
                };
                tracing::warn!(
                    "Endpoint DNS lookup timed out for '{endpoint}'; using stale cached address {addr} (served at most {}s more)",
                    ENDPOINT_DNS_STALE_SERVE_WINDOW.as_secs()
                );
                Ok(addr)
            }
        }
    }

    /// Build gotatun peers from the tunnel config, resolving
    /// non-literal endpoints through DNS under `handshake_timeout`.
    /// Endpoint answers are shared through the daemon-wide
    /// [`EndpointDnsCache`], so activating many tunnels that point at
    /// one hostname does not re-query DNS for each of them.
    async fn build_peers(
        config_peers: &[WgPeerConfig],
        handshake_timeout: Duration,
        tunnel_id: &str,
    ) -> Result<Vec<Peer>, CoreError> {
        let mut peers = Vec::with_capacity(config_peers.len());
        for p_cfg in config_peers {
            let mut peer = Peer::new(p_cfg.public_key);
            if let Ok(addr) = p_cfg.endpoint.parse::<SocketAddr>() {
                peer.endpoint = Some(addr);
            } else {
                let addr = Self::resolve_endpoint_cached(
                    &ENDPOINT_DNS_CACHE,
                    &p_cfg.endpoint,
                    handshake_timeout,
                    tunnel_id,
                )
                .await?;
                peer.endpoint = Some(addr);
            }
            peer.allowed_ips = p_cfg.allowed_ips.clone();
            peer.preshared_key = p_cfg.preshared_key;
            peer.keepalive = p_cfg.persistent_keepalive;
            peers.push(peer);
        }
        Ok(peers)
    }

    /// Finish a gotatun device build: keys, peers, listen port, then
    /// `build()`. Shared by the proxy and VPN boot paths so the two
    /// builders cannot drift apart.
    async fn finish_device_build<Udp, Tx, Rx>(
        builder: DeviceBuilder<Udp, Tx, Rx>,
        private_key: StaticSecret,
        peers: Vec<Peer>,
        listen_port: Option<u16>,
        tunnel_id: &str,
    ) -> Result<Device<(Udp, Tx, Rx)>, CoreError>
    where
        Udp: UdpTransportFactory,
        Tx: IpSend,
        Rx: IpRecv,
    {
        let mut builder = builder
            .with_private_key(private_key)
            .with_peers(peers)
            .suspended(false);
        if let Some(port) = listen_port {
            builder = builder.with_listen_port(port);
        }
        builder.build().await.map_err(|e| {
            CoreError::ActivationFailed(
                tunnel_id.to_string(),
                format!("failed to build gotatun device: {e:?}"),
            )
        })
    }

    /// Seconds since the tunnel last carried traffic. A tunnel that never
    /// recorded activity is stamped with `now` and treated as fresh, so
    /// the caller never tears down a just-booted tunnel for a zero stamp.
    fn idle_seconds(entry: &TunnelEntry, now: u64) -> u64 {
        let last_active = entry.stats.last_active_at.load(Ordering::Relaxed);
        if last_active > 0 {
            now.saturating_sub(last_active)
        } else {
            entry.stats.last_active_at.store(now, Ordering::Relaxed);
            0
        }
    }

    /// Idle seconds after which a suspended tunnel is closed to free its
    /// stack: twice the suspend timeout, floored at `MIN_CLOSE_AFTER_SECS`.
    /// Any tunnel reaching this threshold is past both the WireGuard
    /// session lifetime and the P2C warm window, so closing it only costs
    /// a fresh handshake on next use.
    fn close_after_secs(&self) -> u64 {
        self.idle_timeout()
            .as_secs()
            .saturating_mul(2)
            .max(MIN_CLOSE_AFTER_SECS)
    }

    /// Close a suspended tunnel that has sat unused past the close
    /// threshold, freeing its smoltcp stack and gotatun device buffers.
    /// Suspended tunnels are skipped by the suspend branch of
    /// `check_idle_tunnels`, so without this their stacks would stay
    /// allocated for the daemon's whole lifetime. Disabled tunnels are
    /// left to the disable flow.
    async fn close_if_long_idle(&self, entry: &TunnelEntry, now: u64) {
        if entry.is_disable_pending() {
            return;
        }
        if entry.stats.active_conns.load(Ordering::SeqCst) > 0 {
            return;
        }
        let idle_secs = Self::idle_seconds(entry, now);
        let close_after = self.close_after_secs();
        if idle_secs >= close_after {
            tracing::info!(
                "Tunnel '{}' suspended idle for {}s (threshold: {}s); closing to free its stack",
                entry.id,
                idle_secs,
                close_after
            );
            if let Err(e) = self.close_tunnel(&entry.id).await {
                tracing::warn!("Failed to close tunnel '{}': {e}", entry.id);
            }
        }
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

            // A suspended tunnel keeps its stack allocated, so after a
            // longer idle stretch it is closed instead of kept.
            if *entry.state.read() == TunnelState::Suspended {
                self.close_if_long_idle(&entry, now).await;
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
                    if let Err(e) = self.suspend_tunnel(&entry.id).await {
                        tracing::warn!("Failed to suspend tunnel '{}': {e}", entry.id);
                    }
                    if *entry.state.read() != TunnelState::Active {
                        entry.set_disable_pending(false);
                    }
                    continue;
                }
                let idle_secs = Self::idle_seconds(&entry, now);

                let idle_timeout_secs = self.idle_timeout().as_secs();
                if idle_secs >= idle_timeout_secs {
                    tracing::info!(
                        "Tunnel '{}' idle for {}s (threshold: {}s); suspending to save resources",
                        entry.id,
                        idle_secs,
                        idle_timeout_secs
                    );
                    if let Err(e) = self.suspend_tunnel(&entry.id).await {
                        tracing::warn!("Failed to suspend tunnel '{}': {e}", entry.id);
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use x25519_dalek::PublicKey;

    fn test_peer(endpoint: &str) -> WgPeerConfig {
        WgPeerConfig {
            public_key: PublicKey::from([99u8; 32]),
            endpoint: endpoint.to_string(),
            allowed_ips: vec!["0.0.0.0/0".parse().unwrap()],
            preshared_key: None,
            persistent_keepalive: None,
        }
    }

    #[tokio::test]
    async fn test_build_peers_rejects_endpoint_resolving_to_forbidden_ip() {
        // `localhost` resolves to ::1 and 127.0.0.1, both forbidden:
        // the tunnel must fail instead of handshaking loopback (audit
        // run-1, `lifecycle:build-peers-unchecked-dns-endpoint`).
        let err = LifecycleController::build_peers(
            &[test_peer("localhost:51820")],
            Duration::from_secs(5),
            "tunnel-test",
        )
        .await
        .expect_err("localhost endpoint must be rejected");
        assert!(
            err.to_string().contains("forbidden"),
            "error must name the forbidden-address rejection, got: {err}"
        );
    }

    #[tokio::test]
    async fn test_build_peers_keeps_literal_endpoint() {
        // An operator-authored IP literal is not a DNS answer and is
        // left untouched by the forbidden-address check.
        let peers = LifecycleController::build_peers(
            &[test_peer("127.0.0.1:51820")],
            Duration::from_secs(5),
            "tunnel-test",
        )
        .await
        .expect("literal endpoint must build");
        assert_eq!(peers[0].endpoint, Some("127.0.0.1:51820".parse().unwrap()));
    }

    #[tokio::test]
    async fn test_endpoint_dns_cache_fresh_hit_skips_lookup() {
        // A fresh cached entry is returned without touching DNS: the
        // hostname below is bogus (`.invalid` never resolves), so any
        // lookup attempt would fail the test.
        let cache = EndpointDnsCache::new();
        let endpoint = "endpoint-cache-fresh-hit.invalid:51820";
        let cached: SocketAddr = "192.0.2.1:51820".parse().unwrap();
        cache.insert(endpoint, cached);
        let resolved = LifecycleController::resolve_endpoint_cached(
            &cache,
            endpoint,
            Duration::from_secs(5),
            "tunnel-test",
        )
        .await
        .expect("fresh cache entry must be returned without a lookup");
        assert_eq!(resolved, cached);
    }

    #[tokio::test]
    async fn test_endpoint_dns_cache_expired_entry_forces_fresh_lookup() {
        // An expired entry must not satisfy the request: the helper
        // attempts a fresh lookup, and the lookup's hard resolution
        // error surfaces instead of the stale address. The endpoint
        // is the empty name on purpose: some environments (including
        // this sandbox) synthesize DNS answers for any syntactically
        // valid name, so only an empty name fails deterministically
        // at the resolver with "Name or service not known".
        let cache = EndpointDnsCache::new();
        let endpoint = "";
        let stale: SocketAddr = "192.0.2.2:51820".parse().unwrap();
        cache.insert_expired(endpoint, stale);
        let err = LifecycleController::resolve_endpoint_cached(
            &cache,
            endpoint,
            Duration::from_secs(5),
            "tunnel-test",
        )
        .await
        .expect_err("expired entry must force a fresh lookup, which must fail here");
        assert!(
            err.to_string().contains("endpoint DNS lookup failed"),
            "error must come from the fresh lookup, got: {err}"
        );
    }

    #[tokio::test]
    async fn test_endpoint_dns_cache_timeout_serves_stale_entry() {
        // A lookup that times out (1us is far below any real DNS round
        // trip) serves the last-known-good address instead of failing
        // the activation.
        let cache = EndpointDnsCache::new();
        let endpoint = "endpoint-cache-timeout-serves-stale.invalid:51820";
        let stale: SocketAddr = "192.0.2.3:51820".parse().unwrap();
        cache.insert_expired(endpoint, stale);
        let resolved = LifecycleController::resolve_endpoint_cached(
            &cache,
            endpoint,
            Duration::from_micros(1),
            "tunnel-test",
        )
        .await
        .expect("timed-out lookup must serve the stale entry");
        assert_eq!(resolved, stale);
    }

    #[test]
    fn test_endpoint_dns_cache_invalidate_removes_entry() {
        let cache = EndpointDnsCache::new();
        let endpoint = "endpoint-cache-invalidate.invalid:51820";
        let cached: SocketAddr = "192.0.2.1:51820".parse().unwrap();
        cache.insert(endpoint, cached);
        assert_eq!(cache.get(endpoint), Some(cached));
        cache.invalidate(endpoint);
        assert_eq!(cache.get(endpoint), None);
        // Invalidating a missing key is a no-op, not a panic.
        cache.invalidate(endpoint);
        cache.invalidate("never-inserted.invalid:51820");
    }

    #[tokio::test]
    async fn test_endpoint_dns_cache_stale_serve_caps_remaining_ttl() {
        // A stale address served after a lookup timeout must not live
        // for the rest of the 300 s TTL: serving it caps its remaining
        // life to the short stale-serve window, after which the next
        // activation re-resolves.
        let cache = EndpointDnsCache::new();
        let endpoint = "endpoint-cache-stale-cap.invalid:51820";
        let stale: SocketAddr = "192.0.2.3:51820".parse().unwrap();
        cache.insert(endpoint, stale);
        assert_eq!(cache.get(endpoint), Some(stale));
        let served = cache.serve_stale_capped(endpoint, Duration::from_millis(50));
        assert_eq!(served, Some(stale));
        tokio::time::sleep(Duration::from_millis(80)).await;
        assert_eq!(
            cache.get(endpoint),
            None,
            "stale entry must expire once the capped window passes"
        );
    }
}
