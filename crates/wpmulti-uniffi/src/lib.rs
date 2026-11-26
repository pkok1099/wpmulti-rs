//! UniFFI bindings for the wpmulti Rust engine (Android VPN).
//!
//! Thin adapter only: all tunnel lifecycle, routing, and health logic
//! lives in the `wpmulti` crate. This crate converts between UniFFI
//! types and core types at the boundary and never stores tunnel
//! configuration text or private keys after construction.

use std::collections::HashMap;
use std::future::Future;
use std::io;
use std::net::SocketAddr;
use std::os::fd::{FromRawFd, OwnedFd};
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Weak};
use std::time::Duration;

use wpmulti::netstack::{DohClient, DohTcpConnector};
use wpmulti::proxy::router::{DynStream, ProxyTunnelTarget};
use wpmulti::{
    CoreError, DnsPreference as CoreDnsPreference, DnsStrategy as CoreDnsStrategy,
    HealthStatus as CoreHealthStatus, IpMode as CoreIpMode, LifecycleMode as CoreLifecycleMode,
    MainConfig, SocketProtector as CoreSocketProtector, TunEndpoint, TunnelManager,
    TunnelState as CoreTunnelState, TunnelSummary, TunnelUsable as CoreTunnelUsable,
    VpnRouteStrategy as CoreVpnRouteStrategy,
};

uniffi::setup_scaffolding!();

/// Maximum tunnels the phone engine is allowed to keep active at once.
const MAX_ACTIVE_TUNNELS_PHONE: usize = 8;

/// A WireGuard tunnel configuration, as text, with its tunnel ID.
///
/// The ID cannot be derived from the `.conf` text (WireGuard configs
/// carry no ID field), so Kotlin passes the file stem as `id`.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct TunnelConfInput {
    /// Tunnel ID, e.g. `wgcf-001`. Must pass `validate_tunnel_id`.
    pub id: String,
    /// Full `.conf` text. Private keys are parsed and then dropped;
    /// this crate never stores the text.
    pub content: String,
}

/// Engine errors, mapped from [`CoreError`] and config errors.
#[derive(Debug, thiserror::Error, uniffi::Error)]
pub enum EngineError {
    /// The engine has not been started yet.
    #[error("engine not started")]
    NotStarted,
    /// The engine is already started.
    #[error("engine already started")]
    AlreadyStarted,
    /// No tunnel with this ID exists.
    #[error("tunnel not found: {0}")]
    TunnelNotFound(String),
    /// The TOML or `.conf` text failed to parse or validate.
    #[error("invalid config: {0}")]
    InvalidConfig(String),
    /// A tunnel operation failed (activation, suspend, reload, ...).
    #[error("operation failed: {0}")]
    OperationFailed(String),
    /// Requested feature is not implemented yet (e.g. TUN attach, Phase 2).
    #[error("not supported: {0}")]
    NotSupported(String),
}

impl From<CoreError> for EngineError {
    fn from(err: CoreError) -> Self {
        match err {
            CoreError::TunnelNotFound(id) => Self::TunnelNotFound(id),
            CoreError::Config(err) => Self::InvalidConfig(err.to_string()),
            CoreError::ActivationFailed(id, msg) => {
                Self::OperationFailed(format!("failed to activate tunnel '{id}': {msg}"))
            }
            CoreError::SuspendFailed(id, msg) => {
                Self::OperationFailed(format!("failed to suspend tunnel '{id}': {msg}"))
            }
            CoreError::Io(err) => Self::OperationFailed(err.to_string()),
            CoreError::ListenerError(msg) | CoreError::Other(msg) => Self::OperationFailed(msg),
            CoreError::DuplicateTunnel(id) => {
                Self::InvalidConfig(format!("duplicate tunnel '{id}'"))
            }
        }
    }
}

impl From<wpmulti::ConfigError> for EngineError {
    fn from(err: wpmulti::ConfigError) -> Self {
        Self::InvalidConfig(err.to_string())
    }
}

/// Tunnel state, mirroring [`CoreTunnelState`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum TunnelState {
    Dormant,
    Activating,
    Active,
    Suspended,
}

impl From<CoreTunnelState> for TunnelState {
    fn from(state: CoreTunnelState) -> Self {
        match state {
            CoreTunnelState::Dormant => Self::Dormant,
            CoreTunnelState::Activating => Self::Activating,
            CoreTunnelState::Active => Self::Active,
            CoreTunnelState::Suspended => Self::Suspended,
        }
    }
}

/// Tunnel health, mirroring [`CoreHealthStatus`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum HealthStatus {
    Untested,
    Healthy,
    Unhealthy,
    HalfOpen,
    Dead,
}

impl From<CoreHealthStatus> for HealthStatus {
    fn from(health: CoreHealthStatus) -> Self {
        match health {
            CoreHealthStatus::Untested => Self::Untested,
            CoreHealthStatus::Healthy => Self::Healthy,
            CoreHealthStatus::Unhealthy => Self::Unhealthy,
            CoreHealthStatus::HalfOpen => Self::HalfOpen,
            CoreHealthStatus::Dead => Self::Dead,
        }
    }
}

/// DNS strategy, mirroring [`CoreDnsStrategy`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum DnsStrategy {
    TunnelOnly,
    TunnelFirst,
    Host,
}

impl From<CoreDnsStrategy> for DnsStrategy {
    fn from(strategy: CoreDnsStrategy) -> Self {
        match strategy {
            CoreDnsStrategy::TunnelOnly => Self::TunnelOnly,
            CoreDnsStrategy::TunnelFirst => Self::TunnelFirst,
            CoreDnsStrategy::Host => Self::Host,
        }
    }
}

impl From<DnsStrategy> for CoreDnsStrategy {
    fn from(strategy: DnsStrategy) -> Self {
        match strategy {
            DnsStrategy::TunnelOnly => Self::TunnelOnly,
            DnsStrategy::TunnelFirst => Self::TunnelFirst,
            DnsStrategy::Host => Self::Host,
        }
    }
}

/// DNS preference, mirroring [`CoreDnsPreference`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum DnsPreference {
    Ipv4First,
    Ipv6First,
}

impl From<CoreDnsPreference> for DnsPreference {
    fn from(preference: CoreDnsPreference) -> Self {
        match preference {
            CoreDnsPreference::Ipv4First => Self::Ipv4First,
            CoreDnsPreference::Ipv6First => Self::Ipv6First,
        }
    }
}

impl From<DnsPreference> for CoreDnsPreference {
    fn from(preference: DnsPreference) -> Self {
        match preference {
            DnsPreference::Ipv4First => Self::Ipv4First,
            DnsPreference::Ipv6First => Self::Ipv6First,
        }
    }
}

/// IP family mode, mirroring [`CoreIpMode`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum IpMode {
    DualStack,
    Ipv4Only,
    Ipv6Only,
}

impl From<CoreIpMode> for IpMode {
    fn from(mode: CoreIpMode) -> Self {
        match mode {
            CoreIpMode::DualStack => Self::DualStack,
            CoreIpMode::Ipv4Only => Self::Ipv4Only,
            CoreIpMode::Ipv6Only => Self::Ipv6Only,
        }
    }
}

impl From<IpMode> for CoreIpMode {
    fn from(mode: IpMode) -> Self {
        match mode {
            IpMode::DualStack => Self::DualStack,
            IpMode::Ipv4Only => Self::Ipv4Only,
            IpMode::Ipv6Only => Self::Ipv6Only,
        }
    }
}

/// Lifecycle mode, mirroring [`CoreLifecycleMode`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum LifecycleMode {
    Lazy,
    Eager,
}

impl From<CoreLifecycleMode> for LifecycleMode {
    fn from(mode: CoreLifecycleMode) -> Self {
        match mode {
            CoreLifecycleMode::Lazy => Self::Lazy,
            CoreLifecycleMode::Eager => Self::Eager,
        }
    }
}

impl From<LifecycleMode> for CoreLifecycleMode {
    fn from(mode: LifecycleMode) -> Self {
        match mode {
            LifecycleMode::Lazy => Self::Lazy,
            LifecycleMode::Eager => Self::Eager,
        }
    }
}

/// Snapshot of one tunnel, mirroring [`TunnelSummary`] without any keys.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct TunnelInfo {
    pub id: String,
    pub state: TunnelState,
    pub mode: LifecycleMode,
    pub health: HealthStatus,
    pub active_conns: u64,
    pub total_conns: u64,
    pub rx_bytes: u64,
    pub tx_bytes: u64,
    pub last_handshake: Option<u64>,
    pub endpoint: Option<String>,
    pub assigned_port: Option<u16>,
    pub consecutive_failures: u64,
    pub cooldown_remaining_secs: u64,
    pub disabled: bool,
    pub disable_pending: bool,
}

impl From<TunnelSummary> for TunnelInfo {
    fn from(summary: TunnelSummary) -> Self {
        Self {
            id: summary.id,
            state: TunnelState::from(summary.state),
            mode: LifecycleMode::from(summary.mode),
            health: HealthStatus::from(summary.health),
            active_conns: u64_from_usize(summary.active_conns),
            total_conns: summary.total_conns,
            rx_bytes: summary.rx_bytes,
            tx_bytes: summary.tx_bytes,
            last_handshake: summary.last_handshake,
            endpoint: summary.endpoint,
            assigned_port: summary.assigned_port,
            consecutive_failures: u64_from_usize(summary.consecutive_failures),
            cooldown_remaining_secs: summary.cooldown_remaining_secs,
            disabled: summary.disabled,
            disable_pending: summary.disable_pending,
        }
    }
}

/// Outcome of a handshake probe.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct ProbeOutcome {
    pub ok: bool,
    pub rtt_ms: Option<u64>,
    pub message: String,
}

/// Report of a tunnel reload.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct ReloadReport {
    pub added: u64,
    pub removed: u64,
    pub updated: u64,
    pub total: u64,
}

/// Overall engine status.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct EngineStatus {
    pub started: bool,
    pub tunnel_count: u64,
    pub active_tunnel_count: u64,
}

/// TUN data-plane counters, for phone-side diagnosis. Zeroes when no
/// TUN endpoint is attached.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct TunStats {
    pub packets_read: u64,
    pub read_errors: u64,
    pub packets_unparsable: u64,
    pub packets_no_route: u64,
    pub packets_dropped_local: u64,
    pub packets_queued: u64,
    pub packets_dropped_channel: u64,
    pub packets_malformed: u64,
    pub packets_written: u64,
    pub write_errors: u64,
    pub dispatcher_running: bool,
    pub last_read_error: Option<String>,
}

/// The subset of engine settings Kotlin is allowed to read and change.
/// Durations are seconds; counts are plain numbers. No paths, no
/// listeners, no admin settings, and no keys are exposed here.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct EngineConfig {
    pub dns_strategy: DnsStrategy,
    pub dns_preference: DnsPreference,
    pub ip_mode: IpMode,
    pub max_active_tunnels: u64,
    pub lifecycle_mode: LifecycleMode,
    pub idle_timeout_secs: u64,
    pub handshake_timeout_secs: u64,
    pub probe_timeout_secs: u64,
    pub disabled_tunnel_ids: Vec<String>,
}

impl From<MainConfig> for EngineConfig {
    fn from(config: MainConfig) -> Self {
        Self {
            dns_strategy: DnsStrategy::from(config.global.dns_strategy),
            dns_preference: DnsPreference::from(config.global.dns_preference),
            ip_mode: IpMode::from(config.global.ip_mode),
            max_active_tunnels: u64_from_usize(config.global.max_active_tunnels),
            lifecycle_mode: LifecycleMode::from(config.lifecycle.mode),
            idle_timeout_secs: config.lifecycle.idle_timeout.as_secs(),
            handshake_timeout_secs: config.lifecycle.handshake_timeout.as_secs(),
            probe_timeout_secs: config.health_check.probe_timeout.as_secs(),
            disabled_tunnel_ids: config.disabled_tunnels,
        }
    }
}

fn u64_from_usize(value: usize) -> u64 {
    u64::try_from(value).unwrap_or(u64::MAX)
}

/// Phone defaults applied to every config the engine is built with:
/// at most 8 active tunnels, no proxy listeners, no per-tunnel
/// listeners, and no admin server. The daemon defaults (1000 tunnels,
/// listeners on, admin on) are not safe on a phone.
fn apply_phone_defaults(config: &mut MainConfig) {
    config.global.max_active_tunnels = config
        .global
        .max_active_tunnels
        .clamp(1, MAX_ACTIVE_TUNNELS_PHONE);
    config.shared_listeners.clear();
    config.per_tunnel.enabled = false;
    config.admin.enabled = false;
    config.health_check.probe_concurrency = config.health_check.probe_concurrency.clamp(2, 4);
}

fn parse_tunnel_confs(
    tunnel_confs: &[TunnelConfInput],
) -> Result<Vec<wpmulti::TunnelConfig>, EngineError> {
    let mut tunnels = Vec::with_capacity(tunnel_confs.len());
    for input in tunnel_confs {
        let tunnel = wpmulti::load_tunnel_config_from_str(input.id.clone(), &input.content)?;
        tunnels.push(tunnel);
    }
    Ok(tunnels)
}

/// Kotlin-side socket protector, called back from Rust whenever a
/// WireGuard UDP socket is bound in VPN mode. Implemented in Kotlin
/// with `VpnService.protect(fd)`; returning `false` fails the bind.
#[uniffi::export(callback_interface)]
pub trait SocketProtector: Send + Sync {
    /// Protect `fd` from the VPN's own routing. Returns `true` on success.
    fn protect(&self, fd: i32) -> bool;
}

/// Bridges the UniFFI callback trait to the core [`CoreSocketProtector`] trait.
struct KotlinSocketProtector {
    inner: Box<dyn SocketProtector>,
}

impl std::fmt::Debug for KotlinSocketProtector {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("KotlinSocketProtector")
            .finish_non_exhaustive()
    }
}

impl CoreSocketProtector for KotlinSocketProtector {
    fn protect(&self, fd: i32) -> bool {
        self.inner.protect(fd)
    }
}

/// Take ownership of a raw fd handed over by Android's `VpnService`.
///
/// The fd must be open and exclusively owned by the caller at this
/// point: `VpnService.Builder.establish()` transfers ownership of the
/// TUN fd to the caller, and the engine closes it on `stop()`. The
/// `unsafe` is unavoidable — std has no safe API that turns a raw fd
/// into an `OwnedFd` — and is confined to this one function.
#[allow(
    unsafe_code,
    reason = "no safe std API converts a raw fd into an OwnedFd; fd is open and uniquely owned per the VpnService contract"
)]
fn take_tun_fd(fd: i32) -> OwnedFd {
    unsafe { OwnedFd::from_raw_fd(fd) }
}

/// Multi-tunnel strategy for the VPN data plane: how new flows pick
/// a tunnel when several routes match one destination.
#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum VpnStrategy {
    /// New flows rotate across usable tunnels in registration order.
    RoundRobin,
    /// Always the first usable tunnel; later tunnels are fallback.
    Fallback,
    /// New flows rotate across usable tunnels in proportion to their
    /// per-tunnel weights (see `set_tunnel_weight`).
    Weighted,
}

impl From<VpnStrategy> for CoreVpnRouteStrategy {
    fn from(strategy: VpnStrategy) -> Self {
        match strategy {
            VpnStrategy::RoundRobin => Self::RoundRobin,
            VpnStrategy::Fallback => Self::Fallback,
            VpnStrategy::Weighted => Self::Weighted,
        }
    }
}

/// Lets the TUN endpoint ask the [`TunnelManager`] whether a tunnel
/// may receive new flows (active, not disabled, health routable).
/// Holds the manager weakly: the endpoint outlives the engine when
/// `stop()` is skipped, and a strong reference here would close the
/// manager → lifecycle → endpoint → checker cycle that kept the whole
/// engine alive after destroy (audit run-1,
/// `uniffi:engine-destroy-without-stop-detached-vpn`). A dropped
/// manager simply answers "not usable".
struct ManagerUsableChecker {
    manager: Weak<TunnelManager>,
}

impl CoreTunnelUsable for ManagerUsableChecker {
    fn is_usable(&self, id: &str) -> bool {
        self.manager
            .upgrade()
            .is_some_and(|manager| manager.is_tunnel_usable(id))
    }
}

/// The Android VPN engine: a thin UniFFI wrapper around [`TunnelManager`].
#[derive(Debug, uniffi::Object)]
pub struct Engine {
    manager: Arc<TunnelManager>,
    started: AtomicBool,
    tun_endpoint: tokio::sync::Mutex<Option<Arc<TunEndpoint>>>,
    vpn_strategy: std::sync::Mutex<CoreVpnRouteStrategy>,
    vpn_weights: std::sync::Mutex<HashMap<String, u32>>,
    domain_rules: std::sync::Mutex<Vec<(String, String)>>,
    doh_enabled: AtomicBool,
    doh_client: std::sync::Mutex<Option<Arc<DohClient>>>,
}

/// Opens TCP through the first usable tunnel, for the DoH client.
/// Holds the manager weakly for the same reason as
/// [`ManagerUsableChecker`]: a strong reference here would close
/// the manager → lifecycle → endpoint → DoH client → connector cycle
/// and keep the engine alive after destroy. A dropped manager fails
/// the connect with `NotFound`, like having no usable tunnel.
struct ManagerTcpConnector {
    manager: Weak<TunnelManager>,
}

impl DohTcpConnector for ManagerTcpConnector {
    fn connect(
        &self,
        dst: SocketAddr,
    ) -> Pin<Box<dyn Future<Output = io::Result<DynStream>> + Send>> {
        let Some(manager) = self.manager.upgrade() else {
            return Box::pin(async {
                Err(io::Error::new(
                    io::ErrorKind::NotFound,
                    "engine destroyed: no usable tunnel for DoH",
                ))
            });
        };
        Box::pin(async move {
            // Try every usable tunnel in order: the first one may be
            // down (stale handshake, dead peer) while another works.
            // Only the last error is reported, when none succeeded.
            let ids: Vec<String> = manager
                .get_tunnel_stats()
                .into_iter()
                .filter(|summary| manager.is_tunnel_usable(&summary.id))
                .map(|summary| summary.id)
                .collect();
            let mut last_error = None;
            for id in ids {
                match manager.activate_tunnel(&id).await {
                    Ok(tunnel) => match tunnel.tcp_connect(dst).await {
                        Ok(stream) => return Ok(stream),
                        Err(e) => last_error = Some(e),
                    },
                    Err(e) => {
                        last_error = Some(io::Error::other(format!(
                            "DoH tunnel activation failed: {e}"
                        )));
                    }
                }
            }
            match last_error {
                Some(e) => Err(e),
                None => Err(io::Error::new(
                    io::ErrorKind::NotFound,
                    "no usable tunnel for DoH",
                )),
            }
        })
    }
}

#[uniffi::export]
impl Engine {
    /// Build an engine from TOML text and WireGuard `.conf` texts.
    ///
    /// # Errors
    ///
    /// Returns [`EngineError::InvalidConfig`] when the TOML or any
    /// `.conf` text fails to parse or validate.
    #[allow(
        clippy::needless_pass_by_value,
        reason = "UniFFI exports require owned String/Vec; &str/&[...] cannot cross the FFI boundary"
    )]
    #[uniffi::constructor]
    pub fn new(toml: String, tunnel_confs: Vec<TunnelConfInput>) -> Result<Arc<Self>, EngineError> {
        let mut config = MainConfig::from_toml_str(&toml)?;
        apply_phone_defaults(&mut config);
        let tunnels = parse_tunnel_confs(&tunnel_confs)?;
        let manager = TunnelManager::new(config, tunnels)?;
        Ok(Arc::new(Self {
            manager: Arc::new(manager),
            started: AtomicBool::new(false),
            tun_endpoint: tokio::sync::Mutex::new(None),
            vpn_strategy: std::sync::Mutex::new(CoreVpnRouteStrategy::default()),
            vpn_weights: std::sync::Mutex::new(HashMap::new()),
            domain_rules: std::sync::Mutex::new(Vec::new()),
            doh_enabled: AtomicBool::new(false),
            doh_client: std::sync::Mutex::new(None),
        }))
    }

    /// Install the Kotlin socket protector (`VpnService.protect`).
    /// WireGuard UDP sockets booted in VPN mode are protected through
    /// it. A tunnel cannot boot in VPN mode until a protector is
    /// installed: activation fails closed rather than binding sockets
    /// unprotected (audit run-1,
    /// `uniffi:vpn-mode-unprotected-udp-fallback`).
    ///
    /// The parameter is `Box<dyn SocketProtector>`: UniFFI callback
    /// interfaces lift as `Box`, not `Arc`.
    pub fn set_socket_protector(&self, protector: Box<dyn SocketProtector>) {
        let bridge: Arc<dyn CoreSocketProtector> =
            Arc::new(KotlinSocketProtector { inner: protector });
        self.manager.set_socket_protector(bridge);
    }

    /// Pick the multi-tunnel strategy for new VPN flows. Applies to
    /// the attached TUN endpoint immediately when one exists, and is
    /// remembered for the next attach otherwise. Already-pinned flows
    /// keep their tunnel.
    pub fn set_vpn_strategy(&self, strategy: VpnStrategy) {
        let core_strategy = CoreVpnRouteStrategy::from(strategy);
        if let Ok(mut stored) = self.vpn_strategy.lock() {
            *stored = core_strategy;
        }
        if let Ok(guard) = self.tun_endpoint.try_lock()
            && let Some(endpoint) = guard.as_ref()
        {
            endpoint.set_strategy(core_strategy);
        }
    }

    /// Set one tunnel's weight for the `Weighted` strategy (default 1;
    /// 0 means the tunnel is never picked for new flows). Applies to
    /// the attached TUN endpoint immediately when one exists, and is
    /// remembered for the next attach otherwise.
    pub fn set_tunnel_weight(&self, id: String, weight: u32) {
        if let Ok(guard) = self.tun_endpoint.try_lock()
            && let Some(endpoint) = guard.as_ref()
        {
            endpoint.set_weight(&id, weight);
        }
        if let Ok(mut stored) = self.vpn_weights.lock() {
            // Move `id` in (no clone): the endpoint above only borrowed it.
            stored.insert(id, weight);
        }
    }

    /// Route `suffix` (and its subdomains) to `tunnel_id` for flows
    /// whose destination was learned from a DNS answer. May be called
    /// before `attach_tun`; pending rules are applied to the endpoint
    /// at attach time.
    pub fn set_domain_rule(&self, suffix: String, tunnel_id: String) {
        if let Ok(guard) = self.tun_endpoint.try_lock()
            && let Some(endpoint) = guard.as_ref()
        {
            endpoint.set_domain_rule(&suffix, &tunnel_id);
        }
        if let Ok(mut stored) = self.domain_rules.lock() {
            stored.retain(|(existing, _)| *existing != suffix);
            // Move both strings in (no clones): the endpoint above only borrowed them.
            stored.push((suffix, tunnel_id));
        }
    }

    /// Drop every domain rule.
    pub fn clear_domain_rules(&self) {
        if let Ok(mut stored) = self.domain_rules.lock() {
            stored.clear();
        }
        if let Ok(guard) = self.tun_endpoint.try_lock()
            && let Some(endpoint) = guard.as_ref()
        {
            endpoint.clear_domain_rules();
        }
    }

    /// Turn DNS-over-HTTPS on or off. When on, A/AAAA queries from
    /// the phone are answered over TLS (Cloudflare) through the first
    /// usable tunnel instead of plain UDP; anything DoH transiently
    /// cannot answer falls back to plain DNS. A TLS failure fails
    /// closed: the query is dropped, never downgraded to plaintext.
    /// May be called before `attach_tun`; the client is installed on
    /// the endpoint at attach time.
    pub fn set_doh_enabled(&self, enabled: bool) {
        self.doh_enabled.store(enabled, Ordering::SeqCst);
        if enabled {
            match DohClient::new(Arc::new(ManagerTcpConnector {
                manager: Arc::downgrade(&self.manager),
            })) {
                Ok(client) => {
                    let client = Arc::new(client);
                    if let Ok(mut slot) = self.doh_client.lock() {
                        *slot = Some(Arc::clone(&client));
                    }
                    if let Ok(guard) = self.tun_endpoint.try_lock()
                        && let Some(endpoint) = guard.as_ref()
                    {
                        endpoint.set_dns_resolver(Some(client));
                    }
                }
                Err(e) => tracing::warn!("DoH client failed to start: {e}"),
            }
        } else {
            if let Ok(mut slot) = self.doh_client.lock() {
                *slot = None;
            }
            if let Ok(guard) = self.tun_endpoint.try_lock()
                && let Some(endpoint) = guard.as_ref()
            {
                endpoint.set_dns_resolver(None);
            }
        }
    }

    /// Current engine status.
    #[must_use]
    pub fn status(&self) -> EngineStatus {
        EngineStatus {
            started: self.started.load(Ordering::SeqCst),
            tunnel_count: u64_from_usize(self.manager.tunnel_count()),
            active_tunnel_count: u64_from_usize(self.manager.active_tunnel_count()),
        }
    }

    /// Snapshot of every registered tunnel.
    ///
    /// In VPN mode the TUN data plane counts its own bytes (the proxy
    /// path's `MeteredStream` never sees these packets), so the
    /// endpoint's per-tunnel byte counts are added on top of the
    /// registry's counters here.
    #[must_use]
    pub fn list_tunnels(&self) -> Vec<TunnelInfo> {
        let tun_bytes = self
            .manager
            .tun_endpoint()
            .map(|endpoint| endpoint.byte_counts());
        self.manager
            .get_tunnel_stats()
            .into_iter()
            .map(|summary| {
                let mut info = TunnelInfo::from(summary);
                if let Some(counts) = tun_bytes.as_ref().and_then(|bytes| bytes.get(&info.id)) {
                    info.rx_bytes += counts.0;
                    info.tx_bytes += counts.1;
                }
                info
            })
            .collect()
    }

    /// TUN data-plane counters. All zeroes when no TUN endpoint is
    /// attached (VPN mode off).
    #[must_use]
    pub fn tun_stats(&self) -> TunStats {
        let snapshot = self
            .manager
            .tun_endpoint()
            .map(|endpoint| endpoint.stats_snapshot());
        match snapshot {
            Some(s) => TunStats {
                packets_read: s.packets_read,
                read_errors: s.read_errors,
                packets_unparsable: s.packets_unparsable,
                packets_no_route: s.packets_no_route,
                packets_dropped_local: s.packets_dropped_local,
                packets_queued: s.packets_queued,
                packets_dropped_channel: s.packets_dropped_channel,
                packets_malformed: s.packets_malformed,
                packets_written: s.packets_written,
                write_errors: s.write_errors,
                dispatcher_running: s.dispatcher_running,
                last_read_error: s.last_read_error,
            },
            None => TunStats {
                packets_read: 0,
                read_errors: 0,
                packets_unparsable: 0,
                packets_no_route: 0,
                packets_dropped_local: 0,
                packets_queued: 0,
                packets_dropped_channel: 0,
                packets_malformed: 0,
                packets_written: 0,
                write_errors: 0,
                dispatcher_running: false,
                last_read_error: None,
            },
        }
    }

    /// Current engine settings (the safe subset).
    #[must_use]
    pub fn get_config(&self) -> EngineConfig {
        EngineConfig::from(self.manager.config_snapshot())
    }
}

/// True when `value` is shaped like a `1-200` numeric range selector.
fn is_numeric_range(value: &str) -> bool {
    value.split_once('-').is_some_and(|(a, b)| {
        a.trim().parse::<usize>().is_ok() && b.trim().parse::<usize>().is_ok()
    })
}

#[uniffi::export(async_runtime = "tokio")]
impl Engine {
    /// Start the engine without any proxy listeners.
    ///
    /// # Errors
    ///
    /// Returns [`EngineError::AlreadyStarted`] when already started, or
    /// [`EngineError::OperationFailed`] when the core fails to start.
    pub async fn start(&self) -> Result<(), EngineError> {
        match self
            .started
            .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
        {
            Ok(_) => {}
            Err(_) => return Err(EngineError::AlreadyStarted),
        }
        if let Err(err) = self.manager.start_without_listeners().await {
            self.started.store(false, Ordering::SeqCst);
            return Err(EngineError::from(err));
        }
        Ok(())
    }

    /// Attach a TUN file descriptor to the engine and switch it to VPN mode.
    ///
    /// Takes ownership of `fd`: the engine closes it on [`Engine::stop`].
    /// Ideally called before `start()` / tunnel activation, but tunnels
    /// already booted in proxy mode are migrated, not stranded: after
    /// the endpoint is installed they are closed and re-booted in VPN
    /// mode (audit run-1,
    /// `uniffi:attach-order-pre-attach-proxy-boot-never-migrates-to-tun`).
    /// Migration needs a socket protector installed first
    /// ([`Engine::set_socket_protector`]): without one every
    /// migration boot fails closed, so `attach_tun` refuses the attach
    /// up front instead of leaving a half-migrated engine. A migration
    /// failure rolls the attach back (endpoint shut down, VPN mode
    /// left) and reports the error. Attaching twice without an
    /// intervening `stop()` is an error.
    ///
    /// # Errors
    ///
    /// Returns [`EngineError::InvalidConfig`] for a negative fd, a
    /// zero MTU, or an attach that would need to migrate active
    /// tunnels with no protector installed;
    /// [`EngineError::OperationFailed`] when a TUN fd is already
    /// attached, the fd cannot be used, or a migration fails.
    pub async fn attach_tun(&self, fd: i32, mtu: u16) -> Result<(), EngineError> {
        if fd < 0 {
            return Err(EngineError::InvalidConfig(format!(
                "tun fd must be >= 0, got {fd}"
            )));
        }
        if mtu == 0 {
            return Err(EngineError::InvalidConfig(
                "tun mtu must be > 0".to_string(),
            ));
        }
        let endpoint = {
            let mut guard = self.tun_endpoint.lock().await;
            if guard.is_some() {
                return Err(EngineError::OperationFailed(
                    "tun already attached; stop the engine first".to_string(),
                ));
            }
            let owned = take_tun_fd(fd);
            let endpoint = TunEndpoint::from_owned_fd(owned, mtu)
                .map_err(|e| EngineError::OperationFailed(e.to_string()))?;
            if let Ok(strategy) = self.vpn_strategy.lock() {
                endpoint.set_strategy(*strategy);
            }
            if let Ok(weights) = self.vpn_weights.lock() {
                for (id, weight) in weights.iter() {
                    endpoint.set_weight(id, *weight);
                }
            }
            if let Ok(rules) = self.domain_rules.lock() {
                for (suffix, tunnel_id) in rules.iter() {
                    endpoint.set_domain_rule(suffix, tunnel_id);
                }
            }
            if self.doh_enabled.load(Ordering::SeqCst)
                && let Ok(slot) = self.doh_client.lock()
                && let Some(client) = slot.as_ref()
            {
                let owned = Arc::clone(client);
                endpoint.set_dns_resolver(Some(owned));
            }
            endpoint.set_usable_checker(Some(Arc::new(ManagerUsableChecker {
                manager: Arc::downgrade(&self.manager),
            })));
            endpoint
                .start_dispatcher()
                .map_err(|e| EngineError::OperationFailed(e.to_string()))?;
            *guard = Some(Arc::clone(&endpoint));
            endpoint
        };
        self.manager.set_vpn_mode(true);
        self.manager.set_tun_endpoint(Some(Arc::clone(&endpoint)));
        // Fail fast when migration is needed but no protector is
        // installed: every migration boot would fail closed, and a
        // half-migrated engine is worse than a refused attach.
        if !self.manager.proxy_booted_tunnel_ids().is_empty()
            && !self.manager.has_socket_protector()
        {
            self.rollback_attach(&endpoint).await;
            return Err(EngineError::InvalidConfig(
                "tunnels are already active: call set_socket_protector before attach_tun so they can migrate to VPN mode".to_string(),
            ));
        }
        if let Err(e) = self.manager.migrate_proxy_tunnels_to_vpn().await {
            self.rollback_attach(&endpoint).await;
            return Err(EngineError::from(e));
        }
        Ok(())
    }

    /// Stop the engine. Idempotent: stopping an engine that was never
    /// started is a no-op success. Also shuts the TUN endpoint down
    /// (closing the fd) and leaves VPN mode.
    ///
    /// # Errors
    ///
    /// Returns [`EngineError::OperationFailed`] when the core fails to stop.
    pub async fn stop(&self) -> Result<(), EngineError> {
        self.manager.stop().await?;
        if let Some(endpoint) = self.tun_endpoint.lock().await.take() {
            endpoint.shutdown().await;
        }
        self.manager.clear_vpn();
        self.started.store(false, Ordering::SeqCst);
        Ok(())
    }

    /// Activate one tunnel by ID.
    ///
    /// # Errors
    ///
    /// Returns [`EngineError::TunnelNotFound`] or
    /// [`EngineError::OperationFailed`] on failure.
    pub async fn activate_tunnel(&self, id: String) -> Result<(), EngineError> {
        self.manager.activate_tunnel(&id).await?;
        Ok(())
    }

    /// Suspend one tunnel by ID.
    ///
    /// # Errors
    ///
    /// Returns [`EngineError::TunnelNotFound`] or
    /// [`EngineError::OperationFailed`] on failure.
    pub async fn suspend_tunnel(&self, id: String) -> Result<(), EngineError> {
        self.manager.suspend_tunnel(&id).await?;
        Ok(())
    }

    /// Probe one tunnel with a forced WireGuard handshake plus an
    /// in-tunnel egress check. Never fails: the outcome is the probe
    /// result. A handshake alone never reports `ok: true`: the data
    /// plane must be verified (or, in VPN mode, the outcome reports
    /// the egress as unverified instead of reviving the tunnel).
    pub async fn probe_tunnel(&self, id: String) -> ProbeOutcome {
        let outcome = self.manager.probe_tunnel(&id).await;
        ProbeOutcome {
            ok: outcome.ok,
            rtt_ms: outcome.rtt_ms,
            message: outcome.message,
        }
    }

    /// Enable or disable one tunnel by ID. The `id` must be one exact
    /// registered tunnel ID: batch selector syntax (commas, `all`/`*`,
    /// `1-200` ranges, numeric indexes) is rejected, as is an unknown
    /// ID (audit run-1, `uniffi:set-tunnel-disabled-batch-selector`).
    /// The Admin batch route keeps its own batch semantics; this
    /// single-tunnel wrapper must never disable a whole fleet.
    ///
    /// # Errors
    ///
    /// Returns [`EngineError::InvalidConfig`] for batch selector
    /// syntax, [`EngineError::TunnelNotFound`] for an unknown ID, or
    /// [`EngineError::OperationFailed`] on failure.
    pub async fn set_tunnel_disabled(&self, id: String, disabled: bool) -> Result<(), EngineError> {
        if id.contains(',')
            || id.eq_ignore_ascii_case("all")
            || id == "*"
            || id.parse::<usize>().is_ok()
            || is_numeric_range(&id)
        {
            return Err(EngineError::InvalidConfig(format!(
                "set_tunnel_disabled takes one exact tunnel ID, not a batch selector: '{id}'"
            )));
        }
        if self.manager.registry().get(&id).is_none() {
            return Err(EngineError::TunnelNotFound(id));
        }
        self.manager.set_tunnels_disabled(&id, disabled).await?;
        Ok(())
    }

    /// Reload the tunnel set from new `.conf` texts.
    ///
    /// # Errors
    ///
    /// Returns [`EngineError::InvalidConfig`] when a `.conf` text fails
    /// to parse, or [`EngineError::OperationFailed`] on reload failure.
    pub async fn reload(
        &self,
        tunnel_confs: Vec<TunnelConfInput>,
    ) -> Result<ReloadReport, EngineError> {
        let tunnels = parse_tunnel_confs(&tunnel_confs)?;
        let report = self.manager.reload_with_tunnels(tunnels).await?;
        Ok(ReloadReport {
            added: u64_from_usize(report.added),
            removed: u64_from_usize(report.removed),
            updated: u64_from_usize(report.updated),
            total: u64_from_usize(report.total),
        })
    }

    /// Apply new engine settings (the safe subset) in memory.
    ///
    /// # Errors
    ///
    /// Returns [`EngineError::InvalidConfig`] when the settings fail
    /// validation, or [`EngineError::OperationFailed`] on apply failure.
    pub async fn apply_config(&self, config: EngineConfig) -> Result<(), EngineError> {
        let mut snapshot = self.manager.config_snapshot();
        snapshot.global.dns_strategy = CoreDnsStrategy::from(config.dns_strategy);
        snapshot.global.dns_preference = CoreDnsPreference::from(config.dns_preference);
        snapshot.global.ip_mode = CoreIpMode::from(config.ip_mode);
        snapshot.global.max_active_tunnels =
            usize::try_from(config.max_active_tunnels).unwrap_or(MAX_ACTIVE_TUNNELS_PHONE);
        snapshot.lifecycle.mode = CoreLifecycleMode::from(config.lifecycle_mode);
        snapshot.lifecycle.idle_timeout = Duration::from_secs(config.idle_timeout_secs);
        snapshot.lifecycle.handshake_timeout = Duration::from_secs(config.handshake_timeout_secs);
        snapshot.health_check.probe_timeout = Duration::from_secs(config.probe_timeout_secs);
        snapshot.disabled_tunnels = config.disabled_tunnel_ids;
        apply_phone_defaults(&mut snapshot);
        self.manager.apply_runtime_config(snapshot).await?;
        Ok(())
    }
}

// Non-exported helpers: this block is deliberately outside the
// `#[uniffi::export]` impls, so its methods are never offered to
// Kotlin and may use non-FFI types such as `Arc<TunEndpoint>`.
impl Engine {
    /// Undo a half-installed [`Engine::attach_tun`]: shut the endpoint
    /// down, leave VPN mode, and clear the attached slot so a later
    /// attach can retry.
    async fn rollback_attach(&self, endpoint: &Arc<TunEndpoint>) {
        endpoint.shutdown().await;
        self.manager.clear_vpn();
        let _ = self.tun_endpoint.lock().await.take();
    }
}

impl Drop for Engine {
    /// Last-resort teardown when the engine is destroyed without
    /// `stop()` (audit run-1,
    /// `uniffi:engine-destroy-without-stop-detached-vpn`): stop the
    /// background prober and idle checker, shut the TUN endpoint
    /// down, and leave VPN mode — all synchronously, because `Drop`
    /// cannot await. Tunnels themselves are closed when the
    /// manager's `Arc` finally drops, which is possible because the
    /// endpoint's usable checker and the DoH connector hold only
    /// `Weak` references to the manager, breaking the cycle that used
    /// to keep the whole engine alive after destroy. Listeners are
    /// untouched: this engine never starts them. Steps that cannot
    /// run synchronously (tunnel close, listener drain) are
    /// best-effort only; callers must still call `stop()` for a
    /// clean shutdown.
    fn drop(&mut self) {
        self.started.store(false, Ordering::SeqCst);
        if let Ok(mut slot) = self.tun_endpoint.try_lock()
            && let Some(endpoint) = slot.take()
        {
            let _ = endpoint.shutdown_sync();
        }
        if let Ok(mut slot) = self.doh_client.lock() {
            *slot = None;
        }
        self.manager.stop_background_tasks_sync();
        self.manager.clear_vpn();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// With no tunnels at all the DoH connector reports NotFound
    /// instead of picking a (nonexistent) first tunnel.
    #[tokio::test]
    async fn manager_connector_no_tunnel_returns_not_found() {
        let manager = Arc::new(
            TunnelManager::new(MainConfig::default(), Vec::new()).expect("manager with no tunnels"),
        );
        let connector = ManagerTcpConnector {
            manager: Arc::downgrade(&manager),
        };
        let result = connector
            .connect(SocketAddr::from(([1, 1, 1, 1], 443)))
            .await;
        // `expect_err` cannot be used here: `DynStream` is not `Debug`.
        let Err(error) = result else {
            panic!("connect must fail with no tunnels");
        };
        assert_eq!(error.kind(), io::ErrorKind::NotFound);
    }

    /// Destroying the engine without `stop()` must still release the
    /// manager, the registry, and the TUN endpoint: the `Drop` impl
    /// aborts the background tasks and shuts the endpoint down, and
    /// the `Weak` checker/connector break the cycle that used to keep
    /// the manager alive (audit run-1,
    /// `uniffi:engine-destroy-without-stop-detached-vpn`).
    #[tokio::test]
    async fn engine_drop_without_stop_releases_resources() {
        use std::os::unix::io::AsRawFd;
        use std::os::unix::net::UnixStream;

        let engine = Engine::new(String::new(), vec![]).expect("engine should build");
        engine.start().await.expect("start should succeed");
        let (tun_side, _other_side) = UnixStream::pair().expect("socketpair");
        let fd = tun_side.as_raw_fd();
        std::mem::forget(tun_side);
        engine
            .attach_tun(fd, 1500)
            .await
            .expect("attach must succeed");
        let weak_manager = Arc::downgrade(&engine.manager);
        let weak_registry = Arc::downgrade(engine.manager.registry());
        let weak_endpoint = Arc::downgrade(
            &engine
                .manager
                .tun_endpoint()
                .expect("endpoint must be attached"),
        );
        drop(engine);
        // Aborted tasks release their `Arc`s on the runtime's next
        // ticks, so poll briefly instead of asserting immediately.
        for _ in 0..200 {
            if weak_manager.upgrade().is_none()
                && weak_registry.upgrade().is_none()
                && weak_endpoint.upgrade().is_none()
            {
                return;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        panic!(
            "engine resources still alive 1s after drop without stop(): manager={}, registry={}, endpoint={}",
            weak_manager.upgrade().is_some(),
            weak_registry.upgrade().is_some(),
            weak_endpoint.upgrade().is_some(),
        );
    }
}
