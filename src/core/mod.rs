//! Multi-tunnel manager, registry, and lifecycle coordinator.
//!
//! Provides [`TunnelManager`], the central coordinator managing thousands of WireGuard
//! configurations in userspace, lazy on-demand lifecycle transitions, multi-tenant proxy routing,
//! and listener supervision.

pub mod health;
pub mod lifecycle;
pub mod listener;
pub mod registry;
pub mod router;
#[cfg(test)]
pub mod tests;

use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::{Duration, Instant};

use parking_lot::RwLock;
use serde::{Deserialize, Serialize};

use crate::config::{LifecycleMode, MainConfig, TunnelConfig, load_tunnel_configs_from_dir};
pub use health::{ActiveProber, HealthStatus, TunnelHealthTracker};
pub use lifecycle::{GuardedStream, GuardedTunnelTarget, LifecycleController, TunnelConnGuard};
pub use listener::{ActiveListenerInfo, ListenerSupervisor};
pub use registry::{
    ActiveTunnel, MeteredStream, MeteredUdpSocket, TunnelEntry, TunnelRegistry, TunnelState,
    TunnelStats, TunnelSummary, WgDevice,
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
    registry: Arc<TunnelRegistry>,
    lifecycle: Arc<LifecycleController>,
    listeners: Arc<ListenerSupervisor>,
    prober: Arc<ActiveProber>,
    log_buffer: crate::tui::TuiLogBuffer,
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
    let end = b.min(sorted_ids.len());
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
    /// against alphabetically sorted tunnel IDs.
    pub fn resolve_tunnel_targets(&self, spec: &str) -> Result<Vec<String>, CoreError> {
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
    fn resolve_tunnel_token(
        &self,
        tok: &str,
        sorted_ids: &[String],
        selected: &mut Vec<String>,
    ) -> Result<(), CoreError> {
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
        if self.registry.get(tok).is_none() {
            return Err(CoreError::TunnelNotFound(tok.to_string()));
        }
        add_unique(selected, tok);
        Ok(())
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

        let cfg_snapshot = {
            let mut cfg = self.config.write();
            if disabled {
                for id in &targets {
                    if !cfg.disabled_tunnels.contains(id) {
                        cfg.disabled_tunnels.push(id.clone());
                    }
                }
            } else {
                cfg.disabled_tunnels.retain(|id| !targets.contains(id));
            }
            cfg.disabled_tunnels.sort();
            cfg.clone()
        };

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
                if let Err(e) = write_config_atomically(&path, &serialized).await {
                    tracing::warn!(
                        "Failed to persist disabled_tunnels to '{}': {}",
                        path.display(),
                        e
                    );
                }
            }
        }
        let _ = cfg_snapshot;

        Ok(targets)
    }

    /// Return a cloned snapshot of the current [`MainConfig`].
    pub fn config_snapshot(&self) -> MainConfig {
        self.config.read().clone()
    }

    /// Validate and apply updated runtime settings synchronously across manager, lifecycle,
    /// active prober, and currently active virtual network stacks.
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
            if let Some(active) = maybe_active {
                active.netstack.set_prefer_ipv6(prefer_ipv6);
                active
                    .netstack
                    .set_dns_strategy(new_cfg.global.dns_strategy);
                active
                    .netstack
                    .set_dns_fallback(new_cfg.global.dns_fallback);
                active
                    .netstack
                    .set_connect_timeout(new_cfg.lifecycle.handshake_timeout);
                active.netstack.set_ip_mode(new_cfg.global.ip_mode);
            }
        }

        *self.config.write() = new_cfg;
        Ok(())
    }

    /// Validate and apply updated runtime settings asynchronously, suspending newly disabled
    /// tunnels and re-activating newly re-enabled eager tunnels.
    pub async fn apply_runtime_config(&self, new_cfg: MainConfig) -> Result<(), CoreError> {
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
            }
        }
        Ok(())
    }

    /// Validate, atomically write `new_cfg` to `config_path` (when configured),
    /// and apply updated runtime settings cleanly.
    pub async fn save_and_apply_runtime_config(
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
        self.apply_runtime_config(new_cfg).await
    }

    /// Start the tunnel manager: launches lifecycle idle teardown, boots eager tunnels,
    /// starts active prober, and starts all configured listeners.
    pub async fn start(&self) -> Result<(), CoreError> {
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

        // 3. Start active prober for eager tunnels
        let cfg = self.config.read().clone();
        self.prober
            .start(Arc::clone(&self.registry), cfg.health_check.clone());

        // 4. Start listeners
        if let Err(e) = self
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
    /// with its first peer and report whether it completes within the
    /// configured probe timeout. Activation alone proves nothing about
    /// the tunnel, so the outcome is the handshake result, never the
    /// activation result. The Admin API exposes this so `wpmulti top`
    /// can probe a remote daemon honestly instead of reporting
    /// activation as a probe result.
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
            Ok(Ok(())) => TunnelProbeOutcome {
                ok: true,
                rtt_ms: Some(start.elapsed().as_millis() as u64),
                message: "Handshake OK".to_string(),
            },
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

        let new_tunnels = load_tunnel_configs_from_dir(&dir)?;
        self.reload_with_tunnels(new_tunnels).await
    }

    /// Reload the registry with an updated set of tunnel configurations.
    pub async fn reload_with_tunnels(
        &self,
        new_tunnels: Vec<TunnelConfig>,
    ) -> Result<ReloadReport, CoreError> {
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
                    active.netstack.close().await;
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
        opts.mode(0o600);
    }
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
        opts.custom_flags(libc::O_NOFOLLOW);
    }
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
