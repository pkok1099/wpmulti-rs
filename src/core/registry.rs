//! Multi-tunnel registry and memory-efficient tunnel storage.
//!
//! Manages thousands of WireGuard tunnel configurations indexed by unique tunnel IDs.
//! Dormant tunnels consume minimal memory (~500 bytes per tunnel) with zero active sockets,
//! while active tunnels hold running [`gotatun::device::Device`] and [`VirtualNetworkStack`] handles.

use std::collections::HashMap;
use std::future::Future;
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};

use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncRead, AsyncWrite};

use crate::config::{LifecycleMode, TunnelConfig};
use crate::core::CoreError;
use crate::core::health::{HealthStatus, TunnelHealthTracker};
use crate::netstack::{BridgeIpRecv, BridgeIpSend, VirtualNetworkStack};
use crate::proxy::{DynStream, ProxyTunnelTarget, ProxyUdpSocket};

/// Concrete type alias for a WireGuard device integrated with virtual smoltcp bridges.
pub type WgDevice = gotatun::device::Device<(
    gotatun::udp::socket::UdpSocketFactory,
    BridgeIpSend,
    BridgeIpRecv,
)>;

/// Operational state of a WireGuard tunnel in the registry.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum TunnelState {
    /// Config loaded in memory; no running device, sockets, or background tasks.
    #[default]
    Dormant,
    /// Currently transitioning from dormant to active.
    Activating,
    /// Fully active: WireGuard device running, smoltcp stack polling, routing traffic.
    Active,
    /// Temporarily suspended by idle teardown: sockets closed and timers stopped.
    Suspended,
}

impl std::fmt::Display for TunnelState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Dormant => write!(f, "dormant"),
            Self::Activating => write!(f, "activating"),
            Self::Active => write!(f, "active"),
            Self::Suspended => write!(f, "suspended"),
        }
    }
}

/// Dynamic statistical counters for a single tunnel.
#[derive(Debug, Default)]
pub struct TunnelStats {
    /// Total received payload bytes.
    pub rx_bytes: AtomicU64,
    /// Total transmitted payload bytes.
    pub tx_bytes: AtomicU64,
    /// Currently active proxy connections routed through this tunnel.
    pub active_conns: AtomicUsize,
    /// Cumulative count of all proxy connections served.
    pub total_conns: AtomicU64,
    /// Unix timestamp (seconds) of the latest handshake.
    pub last_handshake: AtomicU64,
    /// Unix timestamp (seconds) when active connections last transitioned to zero.
    pub last_active_at: AtomicU64,
}

impl TunnelStats {
    /// Create new empty statistics initialized to zero.
    pub fn new() -> Self {
        Self::default()
    }

    /// Record newly received bytes.
    pub fn add_rx(&self, bytes: u64) {
        self.rx_bytes.fetch_add(bytes, Ordering::Relaxed);
    }

    /// Record newly transmitted bytes.
    pub fn add_tx(&self, bytes: u64) {
        self.tx_bytes.fetch_add(bytes, Ordering::Relaxed);
    }

    /// Update the last handshake timestamp.
    pub fn record_handshake(&self, ts_secs: u64) {
        self.last_handshake.store(ts_secs, Ordering::Relaxed);
    }

    /// Record an active connection increment.
    pub fn inc_conns(&self) {
        self.active_conns.fetch_add(1, Ordering::SeqCst);
        self.total_conns.fetch_add(1, Ordering::Relaxed);
    }

    /// Record an active connection decrement. If active conns hit 0, records `last_active_at`.
    /// Guarded against underflow if called when active_conns is already 0.
    pub fn dec_conns(&self) {
        let mut current = self.active_conns.load(Ordering::SeqCst);
        loop {
            if current == 0 {
                return;
            }
            match self.active_conns.compare_exchange_weak(
                current,
                current - 1,
                Ordering::SeqCst,
                Ordering::SeqCst,
            ) {
                Ok(prev) => {
                    if prev == 1 {
                        let now = std::time::SystemTime::now()
                            .duration_since(std::time::UNIX_EPOCH)
                            .unwrap_or_default()
                            .as_secs();
                        self.last_active_at.store(now, Ordering::Relaxed);
                    }
                    return;
                }
                Err(actual) => current = actual,
            }
        }
    }
}

/// Handle to an active WireGuard tunnel.
pub struct ActiveTunnel {
    /// Unique identifier for this tunnel.
    pub id: String,
    /// Running WireGuard device.
    pub device: WgDevice,
    /// Userspace smoltcp network stack.
    pub netstack: Arc<VirtualNetworkStack>,
    /// Shared statistics handle.
    pub stats: Arc<TunnelStats>,
}

impl std::fmt::Debug for ActiveTunnel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ActiveTunnel")
            .field("id", &self.id)
            .field("netstack", &self.netstack)
            .field("stats", &self.stats)
            .finish_non_exhaustive()
    }
}

impl ActiveTunnel {
    /// Create a new active tunnel handle.
    pub fn new(
        id: impl Into<String>,
        device: WgDevice,
        netstack: Arc<VirtualNetworkStack>,
        stats: Arc<TunnelStats>,
    ) -> Self {
        Self {
            id: id.into(),
            device,
            netstack,
            stats,
        }
    }

    /// Resolve a domain name inside the tunnel under an explicit [`IpMode`].
    pub fn resolve_in_tunnel_with_mode<'a>(
        &'a self,
        domain: &'a str,
        mode: crate::config::IpMode,
    ) -> Pin<Box<dyn Future<Output = io::Result<IpAddr>> + Send + 'a>> {
        Box::pin(self.netstack.resolve_in_tunnel_with_mode(domain, mode))
    }

    /// Resolve a domain name inside the tunnel under an explicit [`IpMode`],
    /// returning all candidate IP addresses.
    pub fn resolve_all_in_tunnel_with_mode<'a>(
        &'a self,
        domain: &'a str,
        mode: crate::config::IpMode,
    ) -> crate::proxy::router::ResolveAllFut<'a> {
        Box::pin(self.netstack.resolve_all_in_tunnel_with_mode(domain, mode))
    }
}

impl ProxyTunnelTarget for ActiveTunnel {
    fn tcp_connect<'a>(
        &'a self,
        dst: SocketAddr,
    ) -> Pin<Box<dyn Future<Output = io::Result<DynStream>> + Send + 'a>> {
        let netstack = Arc::clone(&self.netstack);
        let stats = Arc::clone(&self.stats);
        Box::pin(async move {
            let stream = netstack.tcp_connect(dst).await?;
            let metered: DynStream = Box::new(MeteredStream {
                inner: Box::new(stream),
                stats,
            });
            Ok(metered)
        })
    }

    fn udp_bind<'a>(
        &'a self,
        local_port: u16,
    ) -> Pin<Box<dyn Future<Output = io::Result<Box<dyn ProxyUdpSocket>>> + Send + 'a>> {
        let netstack = Arc::clone(&self.netstack);
        let stats = Arc::clone(&self.stats);
        Box::pin(async move {
            let sock = netstack.udp_bind(local_port).await?;
            let metered: Box<dyn ProxyUdpSocket> =
                Box::new(MeteredUdpSocket { inner: sock, stats });
            Ok(metered)
        })
    }

    fn resolve_in_tunnel<'a>(
        &'a self,
        domain: &'a str,
    ) -> Pin<Box<dyn Future<Output = io::Result<IpAddr>> + Send + 'a>> {
        self.netstack.resolve_in_tunnel(domain)
    }

    fn resolve_all_in_tunnel<'a>(
        &'a self,
        domain: &'a str,
    ) -> crate::proxy::router::ResolveAllFut<'a> {
        Box::pin(self.netstack.resolve_all_in_tunnel(domain))
    }
}

/// A wrapper around a [`DynStream`] that updates tunnel RX and TX statistics.
pub struct MeteredStream {
    pub inner: DynStream,
    pub stats: Arc<TunnelStats>,
}

impl std::fmt::Debug for MeteredStream {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MeteredStream")
            .field("stats", &self.stats)
            .finish_non_exhaustive()
    }
}

impl MeteredStream {
    /// Create a new metered stream.
    pub fn new(inner: DynStream, stats: Arc<TunnelStats>) -> Self {
        Self { inner, stats }
    }
}

impl AsyncRead for MeteredStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        let before = buf.filled().len();
        let res = Pin::new(&mut self.inner).poll_read(cx, buf);
        if res.is_ready() {
            let n = buf.filled().len().saturating_sub(before);
            if n > 0 {
                self.stats.add_rx(n as u64);
            }
        }
        res
    }
}

impl AsyncWrite for MeteredStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<io::Result<usize>> {
        let res = Pin::new(&mut self.inner).poll_write(cx, buf);
        if let std::task::Poll::Ready(Ok(n)) = res
            && n > 0
        {
            self.stats.add_tx(n as u64);
        }
        res
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

/// A wrapper around [`ProxyUdpSocket`] tracking traffic metrics.
pub struct MeteredUdpSocket {
    inner: Box<dyn ProxyUdpSocket>,
    stats: Arc<TunnelStats>,
}

impl std::fmt::Debug for MeteredUdpSocket {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MeteredUdpSocket")
            .field("stats", &self.stats)
            .finish_non_exhaustive()
    }
}

impl ProxyUdpSocket for MeteredUdpSocket {
    fn send_to<'a>(
        &'a self,
        buf: &'a [u8],
        target: SocketAddr,
    ) -> Pin<Box<dyn Future<Output = io::Result<usize>> + Send + 'a>> {
        let stats = Arc::clone(&self.stats);
        Box::pin(async move {
            let n = self.inner.send_to(buf, target).await?;
            stats.add_tx(n as u64);
            Ok(n)
        })
    }

    fn recv_from<'a>(
        &'a self,
        buf: &'a mut [u8],
    ) -> Pin<Box<dyn Future<Output = io::Result<(usize, SocketAddr)>> + Send + 'a>> {
        let stats = Arc::clone(&self.stats);
        Box::pin(async move {
            let (n, addr) = self.inner.recv_from(buf).await?;
            stats.add_rx(n as u64);
            Ok((n, addr))
        })
    }

    fn local_port(&self) -> u16 {
        self.inner.local_port()
    }
}

/// An entry in the [`TunnelRegistry`], holding both dormant config and dynamic state.
#[derive(Debug)]
pub struct TunnelEntry {
    /// Unique tunnel ID (e.g., "wgcf-001").
    pub id: String,
    /// WireGuard tunnel configuration (keys, peers, interface).
    pub config: RwLock<TunnelConfig>,
    /// Lifecycle policy (Lazy or AlwaysOn).
    pub lifecycle_mode: LifecycleMode,
    /// Current operational state.
    pub state: RwLock<TunnelState>,
    /// Live statistical counters.
    pub stats: Arc<TunnelStats>,
    /// Live health status and circuit breaker tracker.
    pub health: Arc<TunnelHealthTracker>,
    /// Reference to the active device handle, if currently booted.
    pub active: RwLock<Option<Arc<ActiveTunnel>>>,
    /// Dedicated local port assigned to this tunnel, if any.
    pub assigned_port: RwLock<Option<u16>>,
    /// Mutual exclusion lock ensuring serialized activation/boot per tunnel.
    pub activation_lock: Arc<tokio::sync::Mutex<()>>,
    /// Whether this tunnel is administratively disabled (`true` = off).
    pub disabled: std::sync::atomic::AtomicBool,
}

impl TunnelEntry {
    /// Construct a new dormant tunnel entry.
    pub fn new(id: impl Into<String>, config: TunnelConfig, lifecycle_mode: LifecycleMode) -> Self {
        let id_str = id.into();
        Self {
            id: id_str,
            config: RwLock::new(config),
            lifecycle_mode,
            state: RwLock::new(TunnelState::Dormant),
            stats: Arc::new(TunnelStats::new()),
            health: Arc::new(TunnelHealthTracker::new()),
            active: RwLock::new(None),
            assigned_port: RwLock::new(None),
            activation_lock: Arc::new(tokio::sync::Mutex::new(())),
            disabled: std::sync::atomic::AtomicBool::new(false),
        }
    }

    /// Set assigned dedicated port.
    pub fn with_assigned_port(self, port: u16) -> Self {
        *self.assigned_port.write() = Some(port);
        self
    }

    /// Update the assigned port.
    pub fn set_assigned_port(&self, port: u16) {
        *self.assigned_port.write() = Some(port);
    }

    /// Check if the tunnel is currently in the active state.
    pub fn is_active(&self) -> bool {
        *self.state.read() == TunnelState::Active
    }

    /// Check if the tunnel is administratively disabled.
    pub fn is_disabled(&self) -> bool {
        self.disabled.load(Ordering::Relaxed)
    }

    /// Set whether the tunnel is administratively disabled.
    pub fn set_disabled(&self, disabled: bool) {
        self.disabled.store(disabled, Ordering::Relaxed);
    }

    /// Generate a summary snapshot for status APIs and TUI dashboards.
    pub fn summary(&self) -> TunnelSummary {
        let state = *self.state.read();
        let endpoint = self.config.read().peers.first().map(|p| p.endpoint.clone());
        let last_handshake = self.stats.last_handshake.load(Ordering::Relaxed);
        let last_active = self.stats.last_active_at.load(Ordering::Relaxed);

        TunnelSummary {
            id: self.id.clone(),
            state,
            mode: self.lifecycle_mode,
            active_conns: self.stats.active_conns.load(Ordering::Relaxed),
            total_conns: self.stats.total_conns.load(Ordering::Relaxed),
            rx_bytes: self.stats.rx_bytes.load(Ordering::Relaxed),
            tx_bytes: self.stats.tx_bytes.load(Ordering::Relaxed),
            last_handshake: if last_handshake > 0 {
                Some(last_handshake)
            } else {
                None
            },
            last_active_at: if last_active > 0 {
                Some(last_active)
            } else {
                None
            },
            assigned_port: *self.assigned_port.read(),
            endpoint,
            health: self.health.current_status(),
            consecutive_failures: self.health.consecutive_failures(),
            cooldown_remaining_secs: self.health.cooldown_remaining_secs(),
            disabled: self.is_disabled(),
        }
    }
}

/// Serializable snapshot of tunnel health and metrics.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct TunnelSummary {
    /// Unique tunnel ID.
    pub id: String,
    /// Current operational state.
    pub state: TunnelState,
    /// Configured lifecycle mode.
    pub mode: LifecycleMode,
    /// Number of concurrent active proxy connections.
    pub active_conns: usize,
    /// Total cumulative connections served.
    pub total_conns: u64,
    /// Total bytes received through this tunnel.
    pub rx_bytes: u64,
    /// Total bytes transmitted through this tunnel.
    pub tx_bytes: u64,
    /// Timestamp of the last handshake (seconds since UNIX epoch), if any.
    pub last_handshake: Option<u64>,
    /// Timestamp when active connections last dropped to 0, if any.
    pub last_active_at: Option<u64>,
    /// Dedicated local port assigned, if any.
    pub assigned_port: Option<u16>,
    /// Primary WireGuard peer endpoint address.
    pub endpoint: Option<String>,
    /// Health status of the tunnel.
    #[serde(default)]
    pub health: HealthStatus,
    /// Consecutive connection or probe failures.
    #[serde(default)]
    pub consecutive_failures: usize,
    /// Remaining circuit breaker cooldown in seconds.
    #[serde(default)]
    pub cooldown_remaining_secs: u64,
    /// Whether the tunnel is administratively disabled.
    #[serde(default)]
    pub disabled: bool,
}

#[derive(Debug)]
struct RegistryInner {
    entries: HashMap<String, Arc<TunnelEntry>>,
    keys: Vec<String>,
}

/// Thread-safe registry holding thousands of tunnel configurations.
#[derive(Debug)]
pub struct TunnelRegistry {
    inner: RwLock<RegistryInner>,
}

impl Default for TunnelRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl TunnelRegistry {
    /// Create a new empty registry.
    pub fn new() -> Self {
        Self {
            inner: RwLock::new(RegistryInner {
                entries: HashMap::new(),
                keys: Vec::new(),
            }),
        }
    }

    /// Register a new tunnel entry. Fails if a tunnel with the same ID already exists.
    pub fn register(&self, entry: TunnelEntry) -> Result<Arc<TunnelEntry>, CoreError> {
        let id = entry.id.clone();
        let arc_entry = Arc::new(entry);
        {
            let mut inner = self.inner.write();
            if inner.entries.contains_key(&id) {
                return Err(CoreError::DuplicateTunnel(id));
            }
            inner.keys.push(id.clone());
            inner.entries.insert(id, Arc::clone(&arc_entry));
        }
        Ok(arc_entry)
    }

    /// Replace an existing tunnel entry or register a new one.
    pub fn replace(&self, entry: TunnelEntry) -> Arc<TunnelEntry> {
        let mut inner = self.inner.write();
        let id = entry.id.clone();
        let arc_entry = Arc::new(entry);
        if !inner.entries.contains_key(&id) {
            inner.keys.push(id.clone());
        }
        inner.entries.insert(id, Arc::clone(&arc_entry));
        arc_entry
    }

    /// Look up a tunnel entry by its unique ID.
    pub fn get(&self, id: &str) -> Option<Arc<TunnelEntry>> {
        let inner = self.inner.read();
        inner.entries.get(id).cloned()
    }

    /// Look up a tunnel entry by its registered sequential index.
    pub fn get_by_index(&self, index: usize) -> Option<Arc<TunnelEntry>> {
        let inner = self.inner.read();
        inner
            .keys
            .get(index)
            .and_then(|id| inner.entries.get(id))
            .cloned()
    }

    /// Look up a tunnel ID by its registered sequential index without cloning all IDs.
    pub fn id_by_index(&self, index: usize) -> Option<String> {
        let inner = self.inner.read();
        inner.keys.get(index).cloned()
    }

    /// Find the tunnel ID with the least active connections in a single scan.
    pub fn least_conn_id(&self) -> Option<String> {
        let mut min_conns = usize::MAX;
        let mut chosen = None;
        {
            let inner = self.inner.read();
            for (id, entry) in &inner.entries {
                let conns = entry.stats.active_conns.load(Ordering::Relaxed);
                if conns < min_conns {
                    min_conns = conns;
                    chosen = Some(id.clone());
                }
            }
        }
        chosen
    }

    /// Return all registered tunnel IDs in insertion order.
    pub fn all_ids(&self) -> Vec<String> {
        let inner = self.inner.read();
        inner.keys.clone()
    }

    /// Return registered tunnel IDs whose health status is routable.
    pub fn healthy_ids(&self) -> Vec<String> {
        let inner = self.inner.read();
        inner
            .keys
            .iter()
            .filter(|k| {
                inner
                    .entries
                    .get(*k)
                    .is_some_and(|entry| entry.health.can_route())
            })
            .cloned()
            .collect()
    }

    /// Return all registered tunnel entries.
    pub fn all_entries(&self) -> Vec<Arc<TunnelEntry>> {
        let inner = self.inner.read();
        inner
            .keys
            .iter()
            .filter_map(|k| inner.entries.get(k).cloned())
            .collect()
    }

    /// Total count of tunnels registered in memory.
    pub fn count(&self) -> usize {
        let inner = self.inner.read();
        inner.keys.len()
    }

    /// Total count of tunnels currently in the [`TunnelState::Active`] state.
    pub fn active_count(&self) -> usize {
        let inner = self.inner.read();
        inner
            .entries
            .values()
            .filter(|entry| entry.is_active())
            .count()
    }

    /// Remove a tunnel from the registry by its ID.
    pub fn remove(&self, id: &str) -> Option<Arc<TunnelEntry>> {
        let mut inner = self.inner.write();
        let entry = inner.entries.remove(id);
        if entry.is_some() {
            inner.keys.retain(|k| k != id);
        }
        entry
    }

    /// Generate summary statistics snapshots for all tunnels.
    pub fn get_stats(&self) -> Vec<TunnelSummary> {
        let inner = self.inner.read();
        inner
            .keys
            .iter()
            .filter_map(|k| inner.entries.get(k))
            .map(|entry| entry.summary())
            .collect()
    }

    /// Clear all entries from the registry.
    pub fn clear(&self) {
        let mut inner = self.inner.write();
        inner.entries.clear();
        inner.keys.clear();
    }
}
