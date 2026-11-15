//! Lazy and on-demand tunnel lifecycle management.
//!
//! Provides [`LifecycleController`] managing on-demand boot, native `Device::suspend()` and `Device::resume()`,
//! RAII active connection tracking via [`TunnelConnGuard`], and debounced background idle teardown.

use std::future::Future;
use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::Duration;

use parking_lot::Mutex;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::sync::watch;
use tokio::task::JoinHandle;

use crate::config::LifecycleMode;
use crate::core::registry::{ActiveTunnel, TunnelEntry, TunnelRegistry, TunnelState, TunnelStats};
use crate::core::CoreError;
use crate::netstack::{VirtualNetworkStack, VirtualTunBridge, DEFAULT_CHANNEL_CAPACITY};
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
pub struct GuardedTunnelTarget {
    tunnel: Arc<ActiveTunnel>,
    guard: Arc<TunnelConnGuard>,
}

impl GuardedTunnelTarget {
    /// Wrap an active tunnel and connection guard into a guarded target.
    pub fn new(tunnel: Arc<ActiveTunnel>, guard: TunnelConnGuard) -> Self {
        Self {
            tunnel,
            guard: Arc::new(guard),
        }
    }

    /// Access the underlying active tunnel handle.
    pub fn tunnel(&self) -> &Arc<ActiveTunnel> {
        &self.tunnel
    }
}

impl ProxyTunnelTarget for GuardedTunnelTarget {
    fn tcp_connect<'a>(
        &'a self,
        dst: SocketAddr,
    ) -> Pin<Box<dyn Future<Output = io::Result<DynStream>> + Send + 'a>> {
        let tunnel = Arc::clone(&self.tunnel);
        let guard = Arc::clone(&self.guard);
        Box::pin(async move {
            let stream = tunnel.tcp_connect(dst).await?;
            let guarded = GuardedStream {
                inner: stream,
                _guard: guard,
            };
            Ok(Box::new(guarded) as DynStream)
        })
    }

    fn udp_bind<'a>(
        &'a self,
        local_port: u16,
    ) -> Pin<Box<dyn Future<Output = io::Result<Box<dyn ProxyUdpSocket>>> + Send + 'a>> {
        self.tunnel.udp_bind(local_port)
    }

    fn resolve_in_tunnel<'a>(
        &'a self,
        domain: &'a str,
    ) -> Pin<Box<dyn Future<Output = io::Result<std::net::IpAddr>> + Send + 'a>> {
        self.tunnel.resolve_in_tunnel(domain)
    }
}

/// A wrapper around a [`DynStream`] that keeps a [`TunnelConnGuard`] alive until dropped.
pub struct GuardedStream {
    inner: DynStream,
    _guard: Arc<TunnelConnGuard>,
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

/// Controller orchestrating lazy on-demand activation, native suspend/resume, and idle teardown.
pub struct LifecycleController {
    registry: Arc<TunnelRegistry>,
    idle_timeout: Duration,
    check_interval: Duration,
    shutdown_tx: watch::Sender<bool>,
    teardown_handle: Mutex<Option<JoinHandle<()>>>,
    prefer_ipv6: std::sync::atomic::AtomicBool,
    ip_mode: std::sync::atomic::AtomicU8,
}

impl LifecycleController {
    /// Construct a new lifecycle controller.
    pub fn new(
        registry: Arc<TunnelRegistry>,
        idle_timeout: Duration,
        check_interval: Duration,
    ) -> Arc<Self> {
        let (shutdown_tx, _) = watch::channel(false);
        Arc::new(Self {
            registry,
            idle_timeout,
            check_interval,
            shutdown_tx,
            teardown_handle: Mutex::new(None),
            prefer_ipv6: std::sync::atomic::AtomicBool::new(false),
            ip_mode: std::sync::atomic::AtomicU8::new(0),
        })
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

    /// Start the background debounced idle teardown task.
    pub fn start(self: &Arc<Self>) {
        let mut handle_lock = self.teardown_handle.lock();
        if handle_lock.is_some() {
            return;
        }

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

    /// Stop the background idle teardown task.
    pub async fn stop(&self) {
        let _ = self.shutdown_tx.send(true);
        let handle = self.teardown_handle.lock().take();
        if let Some(h) = handle {
            let _ = h.await;
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

        let _lock = entry.activation_lock.lock().await;

        // Check if already active or suspended
        let current_state = *entry.state.read();
        match current_state {
            TunnelState::Active => {
                let active = entry
                    .active
                    .read()
                    .clone()
                    .ok_or_else(|| CoreError::ActivationFailed(id.to_string(), "active handle missing".into()))?;
                let guard = TunnelConnGuard::new(id, Arc::clone(&entry.stats));
                Ok((active, guard))
            }
            TunnelState::Suspended => {
                // Resume existing device
                let active = entry
                    .active
                    .read()
                    .clone()
                    .ok_or_else(|| CoreError::ActivationFailed(id.to_string(), "suspended handle missing".into()))?;

                tracing::debug!("Resuming suspended tunnel '{}'", id);
                active
                    .device
                    .resume()
                    .await
                    .map_err(|e| CoreError::ActivationFailed(id.to_string(), format!("device resume error: {:?}", e)))?;

                *entry.state.write() = TunnelState::Active;
                let guard = TunnelConnGuard::new(id, Arc::clone(&entry.stats));
                Ok((active, guard))
            }
            TunnelState::Dormant | TunnelState::Activating => {
                *entry.state.write() = TunnelState::Activating;
                let active = Self::boot_tunnel(
            &entry,
            self.ip_mode(),
            self.prefer_ipv6.load(Ordering::Relaxed),
        )
        .await?;
                *entry.active.write() = Some(Arc::clone(&active));
                *entry.state.write() = TunnelState::Active;

                let guard = TunnelConnGuard::new(id, Arc::clone(&entry.stats));
                Ok((active, guard))
            }
        }
    }

    /// Explicitly activate a tunnel without returning a connection guard (e.g. for Eager tunnels).
    pub async fn activate_tunnel(&self, id: &str) -> Result<Arc<ActiveTunnel>, CoreError> {
        let entry = self
            .registry
            .get(id)
            .ok_or_else(|| CoreError::TunnelNotFound(id.to_string()))?;

        let _lock = entry.activation_lock.lock().await;

        let current_state = *entry.state.read();
        match current_state {
            TunnelState::Active => {
                let now = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs();
                entry.stats.last_active_at.store(now, Ordering::Relaxed);
                entry
                    .active
                    .read()
                    .clone()
                    .ok_or_else(|| CoreError::ActivationFailed(id.to_string(), "active handle missing".into()))
            }
            TunnelState::Suspended => {
                let active = entry
                    .active
                    .read()
                    .clone()
                    .ok_or_else(|| CoreError::ActivationFailed(id.to_string(), "suspended handle missing".into()))?;

                tracing::debug!("Resuming suspended tunnel '{}'", id);
                active
                    .device
                    .resume()
                    .await
                    .map_err(|e| CoreError::ActivationFailed(id.to_string(), format!("device resume error: {:?}", e)))?;

                let now = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs();
                entry.stats.last_active_at.store(now, Ordering::Relaxed);

                *entry.state.write() = TunnelState::Active;
                Ok(active)
            }
            TunnelState::Dormant | TunnelState::Activating => {
                *entry.state.write() = TunnelState::Activating;
                let active = Self::boot_tunnel(
            &entry,
            self.ip_mode(),
            self.prefer_ipv6.load(Ordering::Relaxed),
        )
        .await?;
                *entry.active.write() = Some(Arc::clone(&active));
                *entry.state.write() = TunnelState::Active;
                Ok(active)
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
            tracing::debug!("Aborting suspension for tunnel '{}': active connections exist", id);
            return Ok(());
        }

        if *entry.state.read() != TunnelState::Active {
            return Ok(());
        }

        let maybe_active = entry.active.read().clone();
        if let Some(active) = maybe_active {
            tracing::debug!("Suspending active tunnel '{}'", id);
            active.device.suspend().await;
            *entry.state.write() = TunnelState::Suspended;
        }

        Ok(())
    }

    /// Build a new [`ActiveTunnel`] from a dormant [`TunnelEntry`].
    async fn boot_tunnel(
        entry: &TunnelEntry,
        ip_mode: crate::config::IpMode,
        prefer_ipv6: bool,
    ) -> Result<Arc<ActiveTunnel>, CoreError> {
        let (config_interface, config_peers) = {
            let cfg = entry.config.read();
            (cfg.interface.clone(), cfg.peers.clone())
        };
        let mtu = config_interface.mtu;
        let (bridge, bridge_tx, bridge_rx) =
            VirtualTunBridge::new(mtu, DEFAULT_CHANNEL_CAPACITY);

        // Prepare peers
        let mut peers = Vec::with_capacity(config_peers.len());
        for p_cfg in &config_peers {
            let mut peer = gotatun::device::Peer::new(p_cfg.public_key);
            if let Ok(addr) = p_cfg.endpoint.parse::<SocketAddr>() {
                peer.endpoint = Some(addr);
            } else if let Ok(mut addrs) = tokio::net::lookup_host(&p_cfg.endpoint).await {
                peer.endpoint = addrs.next();
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
            CoreError::ActivationFailed(entry.id.clone(), format!("failed to build gotatun device: {:?}", e))
        })?;

        // Build smoltcp VirtualNetworkStack
        let netstack = VirtualNetworkStack::new_with_mode(&config_interface, bridge, ip_mode, prefer_ipv6)
            .await
            .map_err(|e| {
                CoreError::ActivationFailed(entry.id.clone(), format!("failed to build netstack: {:?}", e))
            })?;

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
            if entry.lifecycle_mode == LifecycleMode::Eager {
                continue;
            }

            if *entry.state.read() != TunnelState::Active {
                continue;
            }

            let active_conns = entry.stats.active_conns.load(Ordering::SeqCst);
            if active_conns == 0 {
                let last_active = entry.stats.last_active_at.load(Ordering::Relaxed);
                let idle_secs = if last_active > 0 {
                    now.saturating_sub(last_active)
                } else {
                    entry.stats.last_active_at.store(now, Ordering::Relaxed);
                    0
                };

                if idle_secs >= self.idle_timeout.as_secs() {
                    tracing::info!(
                        "Tunnel '{}' idle for {}s (threshold: {}s); suspending to save resources",
                        entry.id,
                        idle_secs,
                        self.idle_timeout.as_secs()
                    );
                    let _ = self.suspend_tunnel(&entry.id).await;
                }
            }
        }
    }
}
