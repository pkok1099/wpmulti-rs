//! Multi-tunnel manager, registry, and lifecycle coordinator.
//!
//! Provides [`TunnelManager`], the central coordinator managing thousands of WireGuard
//! configurations in userspace, lazy on-demand lifecycle transitions, multi-tenant proxy routing,
//! and listener supervision.

pub mod health;
pub mod lifecycle;
pub mod listener;
pub mod protector;
pub mod registry;
pub mod router;
pub mod selection;
#[cfg(test)]
pub mod tests;

use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::{Duration, Instant};

use parking_lot::RwLock;
use serde::{Deserialize, Serialize};

use crate::config::{
    HealthCheckSettings, LifecycleMode, MainConfig, TunnelConfig,
    load_tunnel_configs_from_dir_partial,
};
pub use health::{ActiveProber, HealthStatus, TunnelHealthTracker};
pub use lifecycle::{GuardedStream, GuardedTunnelTarget, LifecycleController, TunnelConnGuard};
pub use listener::{ActiveListenerInfo, ListenerSupervisor};
pub use protector::{ProtectedUdpFactory, SocketProtector};
pub use registry::{
    ActiveTunnel, EgressProbeOutcome, MeteredStream, MeteredUdpSocket, TunnelEntry, TunnelRegistry,
    TunnelState, TunnelStats, TunnelSummary, WgDevice,
};
pub use router::{DedicatedTunnelRouter, IpFilteredTunnelTarget, MultiTenantRouter};

/// Core error types originating in multi-tunnel management.
#[derive(Debug, thiserror::Error)]
pub enum CoreError {
    #[error("Tunnel with ID '{0}' not found")]
    TunnelNotFound(String),
    #[error("Tunnel with ID '{0}' already exists")]
    DuplicateTunnel(String),
    #[error("Failed to activate tunnel '{0}': {1}")]
    ActivationFailed(String, String),
    #[error("Failed to suspend tunnel '{0}': {1}")]
    SuspendFailed(String, String),
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("Configuration error: {0}")]
    Config(#[from] crate::config::ConfigError),
    #[error("Listener supervisor error: {0}")]
    ListenerError(String),
    #[error("Core error: {0}")]
    Other(String),
}

/// Summary report returned upon configuration reload.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReloadReport {
    /// Number of new tunnels registered.
    pub added: usize,
    /// Number of tunnels removed and suspended.
    pub removed: usize,
    /// Number of existing tunnels whose configurations were updated.
    pub updated: usize,
    /// Total count of tunnels active in the registry following reload.
    pub total: usize,
}

/// Outcome of a handshake probe of one tunnel (see
/// [`TunnelManager::probe_tunnel`]). `rtt_ms` is set only when the
/// handshake completes; `message` always explains the outcome.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TunnelProbeOutcome {
    pub ok: bool,
    pub rtt_ms: Option<u64>,
    pub message: String,
}

/// Central multi-tunnel coordinator managing lifecycle, routing, and listeners.
#[derive(Debug)]
pub struct TunnelManager {
    config: RwLock<MainConfig>,
    config_path: RwLock<Option<std::path::PathBuf>>,
    config_write_lock: tokio::sync::Mutex<()>,
    /// Serializes whole config read-modify-write-apply cycles against
    /// each other: `POST /config` (snapshot+merge+write+apply),
    /// `set_tunnels_disabled`, `reload_with_tunnels`, and
    /// `apply_runtime_config` (audit run-1, `core/reload-*`,
    /// `src/api/routes.rs:post-config-*`,
    /// `src/core/mod.rs:set_tunnels_disabled:lost-update-vs-post-config`).
    /// Held across the full cycle, never just the file write: the
    /// `config_write_lock` below only guards the TOML write itself and
    /// is always taken *inside* this lock, never the reverse.
    /// A `tokio::sync::Mutex` is used deliberately — the cycles await
    /// lifecycle/listener work while holding it.
    config_apply_lock: tokio::sync::Mutex<()>,
    registry: Arc<TunnelRegistry>,
    lifecycle: Arc<LifecycleController>,
    listeners: Arc<ListenerSupervisor>,
    prober: Arc<ActiveProber>,
    log_buffer: crate::tui::TuiLogBuffer,
}

/// Apply a disable/enable to the in-memory `disabled_tunnels` list.
/// Sync helper so the config write guard never enters an async future:
/// a `parking_lot` guard held across `.await` would make the future
/// `!Send`.
fn apply_disabled_flags(config: &RwLock<MainConfig>, targets: &[String], disabled: bool) {
    let mut cfg = config.write();
    if disabled {
        for id in targets {
            if !cfg.disabled_tunnels.contains(id) {
                cfg.disabled_tunnels.push(id.clone());
            }
        }
    } else {
        cfg.disabled_tunnels.retain(|id| !targets.contains(id));
    }
    cfg.disabled_tunnels.sort();
}

/// Append `id` to `selected` unless it is already present.
fn add_unique(selected: &mut Vec<String>, id: &str) {
    if !selected.iter().any(|existing| existing.as_str() == id) {
        selected.push(id.to_string());
    }
}

/// Append every sorted ID to `selected` (deduped).
fn add_all_ids(sorted_ids: &[String], selected: &mut Vec<String>) {
    for id in sorted_ids {
        add_unique(selected, id);
    }
}

/// Resolve a `1`-based inclusive range token (`a-b`) against sorted IDs.
fn select_id_range(
    tok: &str,
    a: usize,
    b: usize,
    sorted_ids: &[String],
    selected: &mut Vec<String>,
) -> Result<(), CoreError> {
    if a == 0 || b == 0 || a > b {
        return Err(CoreError::ActivationFailed(
            tok.to_string(),
            "invalid 1-based range".into(),
        ));
    }
    let start = a - 1;
    // Out-of-range bounds fail like `select_id_index` instead of
    // silently clamping to an empty (or partial) selection (audit
    // run-1, `src/core/mod.rs:select_id_range:silent-truncation`):
    // a range naming no tunnel must error, never succeed with nothing.
    if start >= sorted_ids.len() || b > sorted_ids.len() {
        return Err(CoreError::TunnelNotFound(format!(
            "tunnel range {tok} out of range (1..={})",
            sorted_ids.len()
        )));
    }
    let end = b;
    if let Some(slice) = sorted_ids.get(start..end) {
        for id in slice {
            add_unique(selected, id);
        }
    }
    Ok(())
}

/// Resolve a `1`-based index token against sorted IDs.
fn select_id_index(
    idx: usize,
    sorted_ids: &[String],
    selected: &mut Vec<String>,
) -> Result<(), CoreError> {
    let Some(id) = idx.checked_sub(1).and_then(|i| sorted_ids.get(i)) else {
        return Err(CoreError::TunnelNotFound(format!(
            "tunnel index {} out of range (1..={})",
            idx,
            sorted_ids.len()
        )));
    };
    add_unique(selected, id);
    Ok(())
}

/// Target size of the boot warm pool: eager tunnels plus complement
/// (see [`warm_up_complement_ids`]) should leave at least this many
/// tunnels with live sessions before listeners start accepting
/// traffic, so the first requests do not pay activation + handshake
/// inside the failover budget.
pub(crate) const WARM_UP_TARGET_TUNNELS: usize = 8;

/// Complement for the boot warm pool: the lowest tunnel ids needed to
/// reach [`WARM_UP_TARGET_TUNNELS`] warm tunnels, skipping ids that
/// are already eager. Pure, so the top-up rule is unit-testable.
/// Disabled tunnels are not filtered here — booting one fails fast
/// and only warns — so the complement stays a plain id computation.
pub(crate) fn warm_up_complement_ids(eager_ids: &[String], all_ids: &[String]) -> Vec<String> {
    if eager_ids.len() >= WARM_UP_TARGET_TUNNELS {
        return Vec::new();
    }
    let mut sorted: Vec<&String> = all_ids.iter().collect();
    sorted.sort();
    sorted
        .into_iter()
        .filter(|id| !eager_ids.iter().any(|eager| eager == *id))
        .take(WARM_UP_TARGET_TUNNELS - eager_ids.len())
        .cloned()
        .collect()
}

impl TunnelManager {
    /// Construct a new [`TunnelManager`] from [`MainConfig`] and an initial set of [`TunnelConfig`]s.
    pub fn new(config: MainConfig, tunnels: Vec<TunnelConfig>) -> Result<Self, CoreError> {
        let registry = Arc::new(TunnelRegistry::new());

        let default_mode = config.lifecycle.mode;
        for t_cfg in tunnels {
            let mode = if config.lifecycle.eager_tunnels.contains(&t_cfg.id) {
                LifecycleMode::Eager
            } else {
                default_mode
            };
            let entry = TunnelEntry::new(t_cfg.id.clone(), t_cfg, mode);
            if config.disabled_tunnels.iter().any(|d| d == &entry.id) {
                entry.set_disabled(true);
            }
            registry.register(entry)?;
        }

        let idle_timeout = config.lifecycle.idle_timeout;
        let check_interval = Duration::from_secs(1);
        let lifecycle =
            LifecycleController::new(Arc::clone(&registry), idle_timeout, check_interval);
        lifecycle.set_prefer_ipv6(
            config.global.dns_preference == crate::config::toml_config::DnsPreference::Ipv6First,
        );
        lifecycle.set_ip_mode(config.global.ip_mode);
        lifecycle.set_handshake_timeout(config.lifecycle.handshake_timeout);
        lifecycle.set_max_active_tunnels(config.global.max_active_tunnels);
        lifecycle.set_dns_fallback(config.global.dns_fallback);
        lifecycle.set_dns_strategy(config.global.dns_strategy);
        lifecycle.set_health_check(config.health_check.threshold, config.health_check.cooldown);

        let listeners = Arc::new(ListenerSupervisor::new());
        let prober = Arc::new(ActiveProber::new());

        Ok(Self {
            config: RwLock::new(config),
            config_path: RwLock::new(None),
            config_write_lock: tokio::sync::Mutex::new(()),
            config_apply_lock: tokio::sync::Mutex::new(()),
            registry,
            lifecycle,
            listeners,
            prober,
            log_buffer: crate::tui::TuiLogBuffer::new(500),
        })
    }

    /// Access the underlying [`TunnelRegistry`].
    pub const fn registry(&self) -> &Arc<TunnelRegistry> {
        &self.registry
    }

    /// Access the underlying [`LifecycleController`].
    pub const fn lifecycle(&self) -> &Arc<LifecycleController> {
        &self.lifecycle
    }

    /// Enable or disable VPN mode on the lifecycle: newly booted
    /// tunnels use the shared TUN endpoint instead of the smoltcp
    /// bridge. Tunnels already active are migrated by
    /// [`Engine::attach_tun`], not by this setter.
    pub fn set_vpn_mode(&self, enabled: bool) {
        self.lifecycle.set_vpn_mode(enabled);
    }

    /// Install the socket protector used for WireGuard UDP sockets
    /// booted in VPN mode.
    pub fn set_socket_protector(&self, protector: Arc<dyn SocketProtector>) {
        self.lifecycle.set_socket_protector(protector);
    }

    /// True when a socket protector is installed for VPN-mode boots.
    pub fn has_socket_protector(&self) -> bool {
        self.lifecycle.socket_protector().is_some()
    }

    /// IDs of tunnels currently booted in proxy mode (see
    /// [`LifecycleController::proxy_booted_tunnel_ids`]).
    pub fn proxy_booted_tunnel_ids(&self) -> Vec<String> {
        self.lifecycle.proxy_booted_tunnel_ids()
    }

    /// Re-boot every proxy-booted tunnel in VPN mode (see
    /// [`LifecycleController::migrate_proxy_tunnels_to_vpn`]).
    pub async fn migrate_proxy_tunnels_to_vpn(&self) -> Result<Vec<String>, CoreError> {
        self.lifecycle.migrate_proxy_tunnels_to_vpn().await
    }

    /// Attach (or clear with `None`) the shared TUN endpoint used by
    /// VPN-mode tunnels.
    pub fn set_tun_endpoint(&self, endpoint: Option<Arc<crate::netstack::TunEndpoint>>) {
        self.lifecycle.set_tun_endpoint(endpoint);
    }

    /// Return the attached TUN endpoint, if any.
    pub fn tun_endpoint(&self) -> Option<Arc<crate::netstack::TunEndpoint>> {
        self.lifecycle.tun_endpoint()
    }

    /// True when a tunnel may receive new VPN flows: registered,
    /// active, not disabled, and its health tracker still routes to
    /// it (untested and healthy count as usable; a tripped breaker
    /// or dead tunnel does not).
    pub fn is_tunnel_usable(&self, id: &str) -> bool {
        let Some(entry) = self.registry.get(id) else {
            return false;
        };
        !entry.is_disabled()
            && matches!(*entry.state.read(), TunnelState::Active)
            && entry.health.is_routable()
    }

    /// Leave VPN mode: disable it and drop the TUN endpoint reference.
    /// Call after the engine stopped and its tunnels closed.
    pub fn clear_vpn(&self) {
        self.lifecycle.set_vpn_mode(false);
        self.lifecycle.set_tun_endpoint(None);
    }

    /// Access the underlying [`ListenerSupervisor`].
    pub const fn listeners(&self) -> &Arc<ListenerSupervisor> {
        &self.listeners
    }

    /// Access the underlying [`ActiveProber`].
    pub const fn prober(&self) -> &Arc<ActiveProber> {
        &self.prober
    }

    /// Access the daemon's bounded [`crate::tui::TuiLogBuffer`].
    pub const fn log_buffer(&self) -> &crate::tui::TuiLogBuffer {
        &self.log_buffer
    }

    /// Associate a configuration file path so `disabled_tunnels` updates persist to disk.
    pub fn set_config_path(&self, path: std::path::PathBuf) {
        *self.config_path.write() = Some(path);
    }

    /// Return the configured `wpmulti.toml` path on disk, if any.
    pub fn config_path(&self) -> Option<std::path::PathBuf> {
        self.config_path.read().clone()
    }

    /// Resolve a flexible tunnel target expression (`A`, `1`, `1-200`, `all`, or comma-separated)
    /// against alphabetically sorted tunnel IDs. A literal registered
    /// ID always wins over selector syntax (audit run-1,
    /// `src/core/mod.rs:resolve_tunnel_token:literal-id-shadowed`):
    /// the whole spec is tried as one literal ID first, so an ID
    /// containing a comma (`a,b.conf`) is not split, and each token
    /// is tried literally before `all` / range / index parsing.
    pub fn resolve_tunnel_targets(&self, spec: &str) -> Result<Vec<String>, CoreError> {
        let trimmed = spec.trim();
        if !trimmed.is_empty() && self.registry.get(trimmed).is_some() {
            return Ok(vec![trimmed.to_string()]);
        }
        let mut sorted_ids = self.registry.all_ids();
        sorted_ids.sort();
        let mut selected = Vec::new();

        for raw_token in spec.split(',') {
            let tok = raw_token.trim();
            if tok.is_empty() {
                continue;
            }
            self.resolve_tunnel_token(tok, &sorted_ids, &mut selected)?;
        }

        if selected.is_empty() {
            return Err(CoreError::TunnelNotFound(spec.to_string()));
        }
        Ok(selected)
    }

    /// Resolve one comma-separated token (`all`, `1-200`, `1`, or a tunnel ID).
    /// A literal registered ID wins over selector syntax: a tunnel
    /// literally named `2`, `1-2`, or `all` is selected by identity,
    /// never reinterpreted as an index, a range, or "every tunnel".
    fn resolve_tunnel_token(
        &self,
        tok: &str,
        sorted_ids: &[String],
        selected: &mut Vec<String>,
    ) -> Result<(), CoreError> {
        if self.registry.get(tok).is_some() {
            add_unique(selected, tok);
            return Ok(());
        }
        if tok.eq_ignore_ascii_case("all") || tok == "*" {
            add_all_ids(sorted_ids, selected);
            return Ok(());
        }
        if let Some((a_str, b_str)) = tok.split_once('-')
            && let (Ok(a), Ok(b)) = (a_str.trim().parse::<usize>(), b_str.trim().parse::<usize>())
        {
            return select_id_range(tok, a, b, sorted_ids, selected);
        }
        if let Ok(idx) = tok.parse::<usize>() {
            return select_id_index(idx, sorted_ids, selected);
        }
        Err(CoreError::TunnelNotFound(tok.to_string()))
    }

    /// Enable or disable one or more tunnels (`A`, `1`, `1-200`, `all`) in runtime and persist
    /// `disabled_tunnels` to `wpmulti.toml` if a config path is configured.
    /// Suspend a newly disabled tunnel, marking it disable-pending when
    /// live sessions keep it Active so the idle checker can suspend it
    /// once drained (audit run-1, medium). A suspend that actually
    /// happens clears any pending flag.
    async fn suspend_disabled_tunnel(&self, entry: &Arc<TunnelEntry>) {
        if let Err(e) = self.lifecycle.suspend_tunnel(&entry.id).await {
            tracing::warn!("Failed to suspend disabled tunnel '{}': {}", entry.id, e);
        }
        let still_busy = *entry.state.read() == TunnelState::Active
            && entry.stats.active_conns.load(Ordering::SeqCst) > 0;
        entry.set_disable_pending(still_busy);
    }

    pub async fn set_tunnels_disabled(
        &self,
        spec: &str,
        disabled: bool,
    ) -> Result<Vec<String>, CoreError> {
        // Serialize against POST /config and reload: the registry flags,
        // the in-memory `disabled_tunnels`, and the on-disk file must all
        // move together, or a concurrent config apply silently drops the
        // disable (audit run-1,
        // `src/core/mod.rs:set_tunnels_disabled:lost-update-vs-post-config`).
        let _apply_guard = self.config_apply_lock.lock().await;
        let targets = self.resolve_tunnel_targets(spec)?;
        for id in &targets {
            if let Some(entry) = self.registry.get(id) {
                entry.set_disabled(disabled);
                if disabled {
                    self.suspend_disabled_tunnel(&entry).await;
                } else {
                    entry.set_disable_pending(false);
                    if entry.lifecycle_mode == LifecycleMode::Eager
                        && let Err(e) = self.lifecycle.activate_tunnel(id).await
                    {
                        tracing::warn!("Failed to activate re-enabled tunnel '{}': {}", id, e);
                    }
                }
            }
        }

        apply_disabled_flags(&self.config, &targets, disabled);

        let maybe_path = self.config_path.read().clone();
        if let Some(path) = maybe_path {
            let _write_guard = self.config_write_lock.lock().await;
            let latest_snapshot = self.config.read().clone();
            if let Ok(fresh) = toml::to_string_pretty(&latest_snapshot) {
                // Preserve the user's comments in the existing file
                // where possible; fall back to the plain dump if the
                // file cannot be merged safely.
                let existing = tokio::fs::read_to_string(&path).await.ok();
                let serialized = existing
                    .as_deref()
                    .and_then(|text| crate::config::merge_config_preserving_comments(text, &fresh))
                    .unwrap_or(fresh);
                // Fail closed (audit run-1,
                // `src/core/mod.rs:set_tunnels_disabled:persist-failure-swallowed`):
                // a caller told the disable succeeded must be able to
                // trust it survives a restart. Swallowing the error
                // here used to answer 200 while `wpmulti.toml` still
                // held the old list.
                write_config_atomically(&path, &serialized)
                    .await
                    .map_err(|e| {
                        CoreError::Other(format!(
                            "Failed to persist disabled_tunnels to '{}': {e}",
                            path.display()
                        ))
                    })?;
            }
        }

        Ok(targets)
    }

    /// Return a cloned snapshot of the current [`MainConfig`].
    pub fn config_snapshot(&self) -> MainConfig {
        self.config.read().clone()
    }

    /// Validate and apply updated runtime settings synchronously across manager, lifecycle,
    /// active prober, and currently active virtual network stacks.
    ///
    /// Callers must hold the config-apply lock (see
    /// [`TunnelManager::lock_config_apply`]): this swaps the live config
    /// wholesale, so it must never interleave with a reload or another
    /// config apply. [`TunnelManager::apply_runtime_config`] is the
    /// locking entry point.
    pub fn update_runtime_config(&self, new_cfg: MainConfig) -> Result<(), CoreError> {
        new_cfg.validate()?;
        let prefer_ipv6 =
            new_cfg.global.dns_preference == crate::config::toml_config::DnsPreference::Ipv6First;
        self.lifecycle.set_prefer_ipv6(prefer_ipv6);
        self.lifecycle.set_ip_mode(new_cfg.global.ip_mode);
        self.lifecycle
            .set_idle_timeout(new_cfg.lifecycle.idle_timeout);
        self.lifecycle
            .set_handshake_timeout(new_cfg.lifecycle.handshake_timeout);
        self.lifecycle.set_health_check(
            new_cfg.health_check.threshold,
            new_cfg.health_check.cooldown,
        );
        self.lifecycle
            .set_max_active_tunnels(new_cfg.global.max_active_tunnels);
        self.lifecycle.set_dns_fallback(new_cfg.global.dns_fallback);
        self.lifecycle.set_dns_strategy(new_cfg.global.dns_strategy);
        self.prober.update_settings(new_cfg.health_check.clone());

        for entry in self.registry.all_entries() {
            let disabled = new_cfg.disabled_tunnels.iter().any(|d| d == &entry.id);
            entry.set_disabled(disabled);
            if !disabled {
                entry.set_disable_pending(false);
            }
            let maybe_active = entry.active.read().clone();
            if let Some(active) = maybe_active
                && let Some(netstack) = active.netstack.as_ref()
            {
                netstack.set_prefer_ipv6(prefer_ipv6);
                netstack.set_dns_strategy(new_cfg.global.dns_strategy);
                netstack.set_dns_fallback(new_cfg.global.dns_fallback);
                netstack.set_connect_timeout(new_cfg.lifecycle.handshake_timeout);
                netstack.set_ip_mode(new_cfg.global.ip_mode);
            }
        }

        *self.config.write() = new_cfg;
        Ok(())
    }

    /// Acquire the config-apply mutex for a whole read-modify-write-apply
    /// cycle. `POST /config` holds the returned guard across
    /// snapshot+merge+write+apply so two concurrent admin sessions
    /// cannot lose each other's update or resurrect a revoked token
    /// (audit run-1,
    /// `src/api/routes.rs:post-config-concurrent-stale-snapshot-resurrection`).
    /// The `*_locked` methods below run with the guard already held and
    /// must not be called while holding any other config lock; the
    /// `config_write_lock` is always taken inside this lock.
    pub async fn lock_config_apply(&self) -> tokio::sync::MutexGuard<'_, ()> {
        self.config_apply_lock.lock().await
    }

    /// Validate and apply updated runtime settings asynchronously, suspending newly disabled
    /// tunnels, re-activating newly re-enabled eager tunnels, and
    /// reconciling the live listener set with the new config.
    pub async fn apply_runtime_config(&self, new_cfg: MainConfig) -> Result<(), CoreError> {
        let _apply_guard = self.config_apply_lock.lock().await;
        self.apply_runtime_config_locked(new_cfg).await
    }

    /// [`TunnelManager::apply_runtime_config`] with the config-apply lock
    /// already held (called by `save_and_apply_runtime_config_locked`
    /// and by the locking wrapper above).
    async fn apply_runtime_config_locked(&self, new_cfg: MainConfig) -> Result<(), CoreError> {
        // Reject configs that reference tunnel IDs the registry never
        // loaded (a typo in `pool`, `disabled_tunnels`, `eager_tunnels`,
        // or an override key) before anything is applied or saved. This
        // is the runtime counterpart of the CLI `validate`/`run` check;
        // both `POST /config` and the in-process TUI save path flow
        // through here.
        let known_ids: std::collections::HashSet<String> =
            self.registry.all_ids().into_iter().collect();
        new_cfg.validate_tunnel_references(&known_ids)?;
        let prev_disabled: Vec<(String, bool)> = self
            .registry
            .all_entries()
            .into_iter()
            .map(|e| (e.id.clone(), e.is_disabled()))
            .collect();
        let old_cfg = self.config.read().clone();
        self.update_runtime_config(new_cfg)?;

        for (id, was_disabled) in prev_disabled {
            let Some(entry) = self.registry.get(&id) else {
                continue;
            };
            let is_disabled = entry.is_disabled();
            if is_disabled && *entry.state.read() == TunnelState::Active {
                self.suspend_disabled_tunnel(&entry).await;
            } else if was_disabled
                && !is_disabled
                && entry.lifecycle_mode == LifecycleMode::Eager
                && self.listeners.is_started()
                && let Err(e) = self.lifecycle.activate_tunnel(&id).await
            {
                tracing::warn!("Failed to activate re-enabled eager tunnel '{}': {}", id, e);
            } else {
                // No state transition required for this entry.
            }
        }
        self.reconcile_listeners_after_apply(&old_cfg).await;
        Ok(())
    }

    /// Reconcile the live listener set with the config just applied.
    /// Listener identity (bind addresses, proxy credentials, dedicated
    /// ports) is captured at listener start, so a config change that
    /// moves it must restart the affected listeners — otherwise the old
    /// password stays accepted and the new one rejected while `GET
    /// /config` reports the new values (audit run-1, `core/listener:stale-proxy-credentials-after-config-rotation`,
    /// `core/apply-runtime-config:per-tunnel-enabled-no-listener-reconcile`).
    /// A restart failure is logged, not returned: the config is already
    /// applied and persisted by the caller, so failing here would report
    /// a failure while the new config is live.
    async fn reconcile_listeners_after_apply(&self, old_cfg: &MainConfig) {
        if !self.listeners.is_started() {
            return;
        }
        let new_cfg = self.config.read().clone();
        // Any shared-listener change (bind, global password, auth mode,
        // pool) or a global bind change moves a live socket or a live
        // router credential: restart every listener.
        let shared_identity_changed = old_cfg.global.bind_address != new_cfg.global.bind_address
            || old_cfg.shared_listeners != new_cfg.shared_listeners;
        // Dedicated listeners are gated on `per_tunnel.enabled` and
        // capture their credential and ports at start; a flip or a
        // credential/port change restarts only the dedicated set.
        let dedicated_changed = old_cfg.per_tunnel != new_cfg.per_tunnel;
        if shared_identity_changed {
            self.listeners.stop().await;
            if let Err(e) = self
                .listeners
                .start_all(&new_cfg, &self.registry, &self.lifecycle)
                .await
            {
                tracing::warn!("Failed to restart listeners after config apply: {e}");
            }
            return;
        }
        if dedicated_changed {
            self.listeners.stop_all_dedicated(&self.registry).await;
            if new_cfg.per_tunnel.enabled
                && let Err(e) = self
                    .listeners
                    .start_dedicated_listeners(
                        &new_cfg.per_tunnel,
                        new_cfg.dedicated_fallback_password().as_deref(),
                        new_cfg.global.bind_address,
                        &self.registry,
                        &self.lifecycle,
                    )
                    .await
            {
                tracing::warn!("Failed to start dedicated listeners after config apply: {e}");
            }
        }
    }

    /// Validate, atomically write `new_cfg` to `config_path` (when configured),
    /// and apply updated runtime settings cleanly.
    pub async fn save_and_apply_runtime_config(
        &self,
        new_cfg: MainConfig,
    ) -> Result<(), CoreError> {
        let _apply_guard = self.config_apply_lock.lock().await;
        self.save_and_apply_runtime_config_locked(new_cfg).await
    }

    /// [`TunnelManager::save_and_apply_runtime_config`] with the
    /// config-apply lock already held: the file write and the runtime
    /// apply are one atomic step under that lock, so the disk and the
    /// live config can never diverge across concurrent writers (audit
    /// run-1,
    /// `src/api/routes.rs:post-config-concurrent-stale-snapshot-resurrection`).
    pub(crate) async fn save_and_apply_runtime_config_locked(
        &self,
        new_cfg: MainConfig,
    ) -> Result<(), CoreError> {
        new_cfg.validate()?;
        // Check references BEFORE writing the file: `apply_runtime_config`
        // below checks again, but by then the bad config would already be
        // persisted to disk.
        let known_ids: std::collections::HashSet<String> =
            self.registry.all_ids().into_iter().collect();
        new_cfg.validate_tunnel_references(&known_ids)?;
        let maybe_path = self.config_path.read().clone();
        if let Some(path) = maybe_path {
            let _write_guard = self.config_write_lock.lock().await;
            let fresh = toml::to_string_pretty(&new_cfg)
                .map_err(|e| CoreError::Other(format!("Failed to serialize TOML: {e}")))?;
            // Preserve the user's comments in the existing file where
            // possible; fall back to the plain dump if the file cannot
            // be merged safely.
            let existing = tokio::fs::read_to_string(&path).await.ok();
            let serialized = existing
                .as_deref()
                .and_then(|text| crate::config::merge_config_preserving_comments(text, &fresh))
                .unwrap_or(fresh);
            write_config_atomically(&path, &serialized)
                .await
                .map_err(|e| {
                    CoreError::Other(format!("Failed to write config '{}': {e}", path.display()))
                })?;
        }
        self.apply_runtime_config_locked(new_cfg).await
    }

    /// Start the tunnel manager: launches lifecycle idle teardown, boots eager tunnels,
    /// starts active prober, and starts all configured listeners.
    pub async fn start(&self) -> Result<(), CoreError> {
        self.start_inner(true).await
    }

    /// Start the tunnel manager without any proxy listeners.
    ///
    /// Same steps as [`TunnelManager::start`] except step 5 (starting the
    /// SOCKS5/HTTP listeners) is skipped. This is the entry point for the
    /// Android VPN engine, where traffic arrives from a TUN interface
    /// instead of local proxy listeners.
    pub async fn start_without_listeners(&self) -> Result<(), CoreError> {
        self.start_inner(false).await
    }

    /// Boot + probe the warm-up complement (step 2b of
    /// [`Self::start_inner`]): staggered, failures only warn, never
    /// fail startup.
    async fn warm_up_complement(&self, ids: Vec<String>, health_check: &HealthCheckSettings) {
        if ids.is_empty() {
            return;
        }
        tracing::info!(
            "Warming up {} additional tunnel(s) to reach 8 warm tunnels",
            ids.len()
        );
        let mut set = tokio::task::JoinSet::new();
        for id in ids {
            let lifecycle = Arc::clone(&self.lifecycle);
            let registry = Arc::clone(&self.registry);
            let health_check = health_check.clone();
            set.spawn(async move {
                if let Err(e) = lifecycle.activate_tunnel(&id).await {
                    tracing::warn!("Failed to boot warm-up tunnel '{id}': {e}");
                    return;
                }
                ActiveProber::probe_single_by_id(&registry, &id, &health_check).await;
            });
            // Stagger spawns: ~300 ms plus up to 200 ms jitter
            // between handshakes, a few per second at most.
            let stagger_ms = 300 + rand::random::<u64>() % 201;
            tokio::time::sleep(Duration::from_millis(stagger_ms)).await;
        }
        while set.join_next().await.is_some() {}
    }

    async fn start_inner(&self, with_listeners: bool) -> Result<(), CoreError> {
        // 1. Start lifecycle teardown background task
        self.lifecycle.start();

        // 2. Eagerly activate Eager tunnels in parallel (bounded concurrency)
        let eager_ids: Vec<String> = self
            .registry
            .all_entries()
            .into_iter()
            .filter(|e| e.lifecycle_mode == LifecycleMode::Eager && !e.is_disabled())
            .map(|e| e.id.clone())
            .collect();
        // Captured before the boot loop below moves `eager_ids`.
        let has_eager_tunnels = !eager_ids.is_empty();
        let eager_tunnel_count = eager_ids.len();
        // Computed before the boot loop moves `eager_ids` too: the
        // top-up ids depend only on the eager list and the registry.
        let complement_ids = warm_up_complement_ids(&eager_ids, &self.registry.all_ids());

        if !eager_ids.is_empty() {
            const MAX_CONCURRENT_BOOTS: usize = 64;
            let sem = Arc::new(tokio::sync::Semaphore::new(MAX_CONCURRENT_BOOTS));
            let mut set = tokio::task::JoinSet::new();

            for id in eager_ids {
                let lifecycle = Arc::clone(&self.lifecycle);
                let sem = Arc::clone(&sem);
                set.spawn(async move {
                    let _permit = sem
                        .acquire_owned()
                        .await
                        .map_err(|_| CoreError::Other("Boot semaphore closed".to_string()))?;
                    tracing::info!("Eagerly booting Eager tunnel '{}'", id);
                    lifecycle.activate_tunnel(&id).await?;
                    Ok::<(), CoreError>(())
                });
            }

            while let Some(res) = set.join_next().await {
                match res {
                    Ok(Ok(())) => {}
                    Ok(Err(e)) => {
                        set.abort_all();
                        while set.join_next().await.is_some() {}
                        let _ = self.stop().await;
                        return Err(e);
                    }
                    Err(e) => {
                        set.abort_all();
                        while set.join_next().await.is_some() {}
                        let _ = self.stop().await;
                        return Err(CoreError::Other(format!(
                            "Parallel tunnel boot task failed: {e}"
                        )));
                    }
                }
            }
        }

        // 2b. Top the warm pool up to 8 tunnels: when fewer eager
        // tunnels are configured, the first requests still land on
        // dormant tunnels and pay activation + handshake inside the
        // failover budget. Complement with the lowest tunnel ids not
        // already eager. Boots and probes run staggered (a few
        // handshakes per second, jittered) so the burst cannot push
        // the Cloudflare edge into cookie under-load mode — and a
        // complement failure only warns: warm-up must never fail
        // startup (unlike the eager boot above).
        let cfg = self.config.read().clone();
        self.warm_up_complement(complement_ids, &cfg.health_check)
            .await;

        // 3. Warm up eager tunnels: one probe pass (handshake + egress
        // check) before any listener accepts traffic, so the first
        // request finds live sessions instead of paying activation +
        // handshake inside its failover budget. A probe failure only
        // records a health failure — it never fails startup (unlike
        // the eager boot above, where one activation error aborts the
        // whole start). Skipped when no eager tunnel is configured, so
        // a pure-lazy daemon starts exactly as before. The prober loop
        // started below re-probes on its first tick; that duplicate
        // pass is harmless (health recording is idempotent). Bounded by
        // one probe timeout per tunnel (`probe_timeout`, default 5s).
        if has_eager_tunnels {
            tracing::info!(
                "Warming up {eager_tunnel_count} eager tunnel(s) before listeners start"
            );
            ActiveProber::probe_eager_tunnels(&self.registry, &cfg.health_check).await;
        }

        // 4. Start active prober for eager tunnels
        self.prober
            .start(Arc::clone(&self.registry), cfg.health_check.clone());

        // 5. Start listeners (skipped for the Android VPN engine, which
        // receives traffic from a TUN interface instead).
        if with_listeners
            && let Err(e) = self
                .listeners
                .start_all(&cfg, &self.registry, &self.lifecycle)
                .await
        {
            let _ = self.stop().await;
            return Err(e);
        }

        Ok(())
    }

    /// Stop the tunnel manager: stops accepting new connections, stops background workers,
    /// drains active connections up to `drain_timeout`, and cleanly closes all tunnels.
    pub async fn stop_with_drain_timeout(&self, drain_timeout: Duration) -> Result<(), CoreError> {
        // 1. Stop accepting new proxy connections immediately
        self.listeners.begin_shutdown(drain_timeout);

        // 2. Stop background workers before draining/closing tunnels so they cannot re-activate
        self.prober.stop().await;
        self.lifecycle.stop_background_tasks().await;

        // 3. Drain active proxy sessions within bounded timeout, then abort lingering ones
        self.listeners.drain(drain_timeout).await;

        // 4. Cleanly close all tunnels and wake netstack reactors/wakers
        self.lifecycle.close_all_tunnels().await;

        Ok(())
    }

    /// Stop the tunnel manager with the default bounded drain timeout (500ms).
    pub async fn stop(&self) -> Result<(), CoreError> {
        self.stop_with_drain_timeout(Duration::from_millis(500))
            .await
    }

    /// Synchronously stop the background workers (active prober,
    /// idle-teardown task) without waiting for them: signal each loop
    /// to exit and abort its task. Used by `Drop` paths (the UniFFI
    /// engine destroyed without `stop()`), where awaiting is
    /// impossible (audit run-1,
    /// `uniffi:engine-destroy-without-stop-detached-vpn`).
    /// Listeners are untouched: the engine path never starts them.
    pub fn stop_background_tasks_sync(&self) {
        if let Some(handle) = self.prober.stop_sync() {
            handle.abort();
        }
        if let Some(handle) = self.lifecycle.stop_background_tasks_sync() {
            handle.abort();
        }
    }

    /// Returns the total number of tunnels registered in memory.
    pub fn tunnel_count(&self) -> usize {
        self.registry.count()
    }

    /// Returns the number of currently active tunnels.
    pub fn active_tunnel_count(&self) -> usize {
        self.registry.active_count()
    }

    /// Retrieve summary snapshots for all tunnels.
    pub fn get_tunnel_stats(&self) -> Vec<TunnelSummary> {
        self.registry.get_stats()
    }

    /// Manually activate a tunnel by its ID.
    pub async fn activate_tunnel(&self, id: &str) -> Result<Arc<ActiveTunnel>, CoreError> {
        self.lifecycle.activate_tunnel(id).await
    }

    /// Probe one tunnel: activate it, then force a WireGuard handshake
    /// with its first peer and verify the data plane with an egress
    /// probe before reporting success. A handshake alone proves only
    /// that the peer answers; it never revives a Dead tunnel (audit
    /// run-1, `core/probe_tunnel:handshake-only-revives-dead`). The
    /// Admin API exposes this so `wpmulti top` can probe a remote
    /// daemon honestly instead of reporting activation as a probe result.
    pub async fn probe_tunnel(&self, id: &str) -> TunnelProbeOutcome {
        let start = Instant::now();
        let active = match self.activate_tunnel(id).await {
            Ok(active) => active,
            Err(e) => {
                return TunnelProbeOutcome {
                    ok: false,
                    rtt_ms: None,
                    message: e.to_string(),
                };
            }
        };
        let probe_timeout = self.config_snapshot().health_check.probe_timeout;
        let Some(pubkey) = self
            .registry()
            .get(id)
            .and_then(|entry| entry.config.read().peers.first().map(|p| p.public_key))
        else {
            return TunnelProbeOutcome {
                ok: false,
                rtt_ms: None,
                message: "No peer public key configured".to_string(),
            };
        };
        match tokio::time::timeout(probe_timeout, active.device.force_handshake(&pubkey)).await {
            Ok(Ok(())) => {
                // The handshake only proves the peer answers. Egress
                // is verified separately; only a verified data plane
                // records success, so a Dead tunnel is revived only by
                // proof the tunnel carries traffic. A probe is
                // diagnostic: an unverified or failed egress records
                // no failure either.
                match active.probe_egress(probe_timeout).await {
                    Ok(EgressProbeOutcome::Verified) => {
                        if let Some(entry) = self.registry().get(id) {
                            entry.health.record_success();
                        }
                        TunnelProbeOutcome {
                            ok: true,
                            rtt_ms: Some(start.elapsed().as_millis() as u64),
                            message: "Handshake OK, egress verified".to_string(),
                        }
                    }
                    Ok(EgressProbeOutcome::Unverified) => TunnelProbeOutcome {
                        ok: false,
                        rtt_ms: Some(start.elapsed().as_millis() as u64),
                        message: "Handshake OK, but data-plane egress not verified \
                            (VPN mode: no in-tunnel probe available)"
                            .to_string(),
                    },
                    Err(e) => TunnelProbeOutcome {
                        ok: false,
                        rtt_ms: Some(start.elapsed().as_millis() as u64),
                        message: format!("Handshake OK, but egress probe failed: {e}"),
                    },
                }
            }
            Ok(Err(e)) => TunnelProbeOutcome {
                ok: false,
                rtt_ms: None,
                message: e.to_string(),
            },
            Err(_) => TunnelProbeOutcome {
                ok: false,
                rtt_ms: None,
                message: "Handshake timed out".to_string(),
            },
        }
    }

    /// Manually suspend a tunnel by its ID.
    pub async fn suspend_tunnel(&self, id: &str) -> Result<(), CoreError> {
        self.lifecycle.suspend_tunnel(id).await
    }

    /// Reload tunnel configurations from the configured `config_dir`.
    pub async fn reload(&self) -> Result<ReloadReport, CoreError> {
        let dir = self.config.read().global.config_dir.clone();
        if !dir.exists() {
            return Err(CoreError::Other(format!(
                "tunnels directory '{}' does not exist",
                dir.display()
            )));
        }

        // Degraded reload (audit run-1,
        // `config/load-dir-single-bad-conf-fails-all`): one broken `.conf`
        // must not fail the whole reload. Apply the valid set and
        // quarantine the broken files — but a tunnel whose file failed to
        // load keeps its current config instead of being removed, so a
        // corrupt file cannot delete a live tunnel from the registry.
        let partial = load_tunnel_configs_from_dir_partial(&dir)?;
        let mut new_tunnels = partial.configs;
        for failure in &partial.failures {
            tracing::warn!(
                "Reload skipping broken tunnel config '{}': {}",
                failure.path.display(),
                failure.error
            );
            if let Some(id) = &failure.id
                && !new_tunnels.iter().any(|t| &t.id == id)
                && let Some(entry) = self.registry.get(id)
            {
                new_tunnels.push(entry.config.read().clone());
            }
        }
        self.reload_with_tunnels(new_tunnels).await
    }

    /// Reload the registry with an updated set of tunnel configurations.
    pub async fn reload_with_tunnels(
        &self,
        new_tunnels: Vec<TunnelConfig>,
    ) -> Result<ReloadReport, CoreError> {
        // Serialize against config applies and other reloads (audit
        // run-1, `core/reload-with-tunnels-unserialized-concurrent-reload`,
        // `core/reload-stale-snapshot-disabled-tunnel-activated`): the
        // snapshot below stays live for the whole reload, so a concurrent
        // apply cannot clear a disabled flag mid-reload only for this
        // reload to resurrect it, and two concurrent reloads apply their
        // sets one after the other instead of interleaving into a union.
        let _apply_guard = self.config_apply_lock.lock().await;
        let mut report = ReloadReport::default();
        let cfg_snapshot = self.config.read().clone();
        let default_mode = cfg_snapshot.lifecycle.mode;
        let eager_tunnels = &cfg_snapshot.lifecycle.eager_tunnels;

        let incoming_ids: std::collections::HashSet<String> =
            new_tunnels.iter().map(|t| t.id.clone()).collect();

        // Detect and remove deleted tunnels first so freed dedicated ports are available to additions
        let existing_ids = self.registry.all_ids();
        for id in existing_ids {
            if !incoming_ids.contains(&id) {
                if self.listeners.is_started() {
                    self.listeners.stop_dedicated_for_tunnel(&id).await;
                }
                let _ = self.lifecycle.close_tunnel(&id).await;
                self.registry.remove(&id);
                report.removed += 1;
            }
        }

        for t_cfg in new_tunnels {
            if let Some(existing) = self.registry.get(&t_cfg.id) {
                if self
                    .reload_existing_tunnel(&existing, t_cfg, &cfg_snapshot)
                    .await
                {
                    report.updated += 1;
                }
            } else {
                // New tunnel added: respect eager_tunnels and disabled_tunnels lists
                let mode = if eager_tunnels.contains(&t_cfg.id) {
                    LifecycleMode::Eager
                } else {
                    default_mode
                };
                let new_id = t_cfg.id.clone();
                let new_entry = TunnelEntry::new(new_id.clone(), t_cfg, mode);
                if cfg_snapshot.disabled_tunnels.iter().any(|d| d == &new_id) {
                    new_entry.set_disabled(true);
                }
                let entry = self.registry.register(new_entry)?;

                if cfg_snapshot.per_tunnel.enabled
                    && self.listeners.is_started()
                    && let Err(e) = self
                        .listeners
                        .start_dedicated_for_tunnel(
                            &entry,
                            &cfg_snapshot.per_tunnel,
                            cfg_snapshot.dedicated_fallback_password().as_deref(),
                            cfg_snapshot.global.bind_address,
                            &self.lifecycle,
                        )
                        .await
                {
                    tracing::warn!(
                        "Failed to start dedicated listener for reloaded tunnel '{}': {}",
                        new_id,
                        e
                    );
                }

                if mode == LifecycleMode::Eager
                    && self.listeners.is_started()
                    && let Err(e) = self.lifecycle.activate_tunnel(&new_id).await
                {
                    tracing::warn!(
                        "Failed to activate eager tunnel '{}' during reload: {}",
                        new_id,
                        e
                    );
                }

                report.added += 1;
            }
        }

        report.total = self.tunnel_count();
        Ok(report)
    }

    async fn reload_existing_tunnel(
        &self,
        existing: &Arc<TunnelEntry>,
        t_cfg: TunnelConfig,
        cfg_snapshot: &MainConfig,
    ) -> bool {
        let config_changed = {
            let cur = existing.config.read();
            *cur != t_cfg
        };
        if !config_changed {
            return false;
        }

        let should_reactivate = {
            let _act_lock = existing.activation_lock.lock().await;
            let active_conns = existing.stats.active_conns.load(Ordering::SeqCst);
            let maybe_active = existing.active.write().take();
            if active_conns == 0 {
                if let Some(active) = maybe_active {
                    active.device.suspend().await;
                    active.close_netstack().await;
                }
            } else {
                // Existing connections retain their Arc<ActiveTunnel> until completion;
                // detaching it from `existing.active` ensures new connections boot with the new config.
                drop(maybe_active);
            }
            *existing.state.write() = TunnelState::Dormant;
            *existing.config.write() = t_cfg.clone();

            let disabled = existing.is_disabled()
                || cfg_snapshot.disabled_tunnels.iter().any(|d| d == &t_cfg.id);
            existing.set_disabled(disabled);
            existing.health.reset();

            existing.lifecycle_mode == LifecycleMode::Eager && !disabled
        };
        if should_reactivate {
            let _ = self.lifecycle.activate_tunnel(&existing.id).await;
        }
        true
    }
}

fn write_and_sync_file(file: &mut std::fs::File, data: &str) -> std::io::Result<()> {
    use std::io::Write;
    file.write_all(data.as_bytes())?;
    file.sync_all()
}

fn is_parent_dir_write_blocked(err: &std::io::Error) -> bool {
    if err.kind() == std::io::ErrorKind::PermissionDenied {
        return true;
    }
    #[cfg(unix)]
    if matches!(
        err.raw_os_error(),
        Some(libc::EACCES | libc::EPERM | libc::EROFS | libc::EBUSY | libc::EXDEV)
    ) {
        return true;
    }
    false
}

fn try_atomic_replace_blocking(path: &std::path::Path, data: &str) -> std::io::Result<()> {
    let parent = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or_else(|| std::path::Path::new("."));
    let suffix: u64 = rand::random();
    let tmp_name = format!(
        ".{}.{suffix:016x}.tmp",
        path.file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("wpmulti.toml")
    );
    let tmp_path = parent.join(tmp_name);

    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600)
    };
    let mut file = opts.open(&tmp_path)?;
    if let Err(e) = write_and_sync_file(&mut file, data) {
        let _ = std::fs::remove_file(&tmp_path);
        return Err(e);
    }
    drop(file);
    if let Err(e) = std::fs::rename(&tmp_path, path) {
        let _ = std::fs::remove_file(&tmp_path);
        return Err(e);
    }
    Ok(())
}

fn write_in_place_and_sync(file: &mut std::fs::File, data: &str) -> std::io::Result<()> {
    use std::io::{Seek, SeekFrom, Write};
    let target_len = u64::try_from(data.len()).map_err(std::io::Error::other)?;
    file.seek(SeekFrom::Start(0))?;
    file.write_all(data.as_bytes())?;
    file.set_len(target_len)?;
    file.sync_all()
}

fn try_in_place_fallback_blocking(path: &std::path::Path, data: &str) -> std::io::Result<()> {
    let meta = std::fs::symlink_metadata(path)?;
    if !meta.file_type().is_file() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "refusing in-place config write to non-regular file or symlink",
        ));
    }

    let mut opts = std::fs::OpenOptions::new();
    opts.write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.custom_flags(libc::O_NOFOLLOW)
    };
    let mut file = opts.open(path)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = meta.permissions().mode();
        if mode & 0o007 != 0 {
            let _ = file.set_permissions(std::fs::Permissions::from_mode(mode & 0o770));
        }
    }
    write_in_place_and_sync(&mut file, data)
}

/// Atomically serialize and write config contents to `path`.
///
/// Uses a sibling temp file + `fsync` + `rename`, falling back to a direct `O_NOFOLLOW` in-place
/// write when only the target file (not its parent directory) is writable.
pub async fn write_config_atomically(
    path: &std::path::Path,
    contents: &str,
) -> std::io::Result<()> {
    let path_owned = path.to_path_buf();
    let data = contents.to_owned();
    tokio::task::spawn_blocking(
        move || match try_atomic_replace_blocking(&path_owned, &data) {
            Ok(()) => Ok(()),
            Err(e) if is_parent_dir_write_blocked(&e) => {
                try_in_place_fallback_blocking(&path_owned, &data)
            }
            Err(e) => Err(e),
        },
    )
    .await
    .map_err(std::io::Error::other)?
}
