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
use std::time::Duration;

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

/// Central multi-tunnel coordinator managing lifecycle, routing, and listeners.
#[derive(Debug)]
pub struct TunnelManager {
    config: RwLock<MainConfig>,
    config_path: RwLock<Option<std::path::PathBuf>>,
    registry: Arc<TunnelRegistry>,
    lifecycle: Arc<LifecycleController>,
    listeners: Arc<ListenerSupervisor>,
    prober: Arc<ActiveProber>,
    log_buffer: crate::tui::TuiLogBuffer,
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
            if tok.eq_ignore_ascii_case("all") || tok == "*" {
                for id in &sorted_ids {
                    if !selected.contains(id) {
                        selected.push(id.clone());
                    }
                }
                continue;
            }
            if let Some((a_str, b_str)) = tok.split_once('-')
                && let (Ok(a), Ok(b)) =
                    (a_str.trim().parse::<usize>(), b_str.trim().parse::<usize>())
            {
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
                        if !selected.contains(id) {
                            selected.push(id.clone());
                        }
                    }
                }
                continue;
            }
            if let Ok(idx) = tok.parse::<usize>() {
                let Some(id) = idx.checked_sub(1).and_then(|i| sorted_ids.get(i)) else {
                    return Err(CoreError::TunnelNotFound(format!(
                        "tunnel index {} out of range (1..={})",
                        idx,
                        sorted_ids.len()
                    )));
                };
                if !selected.contains(id) {
                    selected.push(id.clone());
                }
                continue;
            }
            if self.registry.get(tok).is_none() {
                return Err(CoreError::TunnelNotFound(tok.to_string()));
            }
            let id = tok.to_string();
            if !selected.contains(&id) {
                selected.push(id);
            }
        }

        if selected.is_empty() {
            return Err(CoreError::TunnelNotFound(spec.to_string()));
        }
        Ok(selected)
    }

    /// Enable or disable one or more tunnels (`A`, `1`, `1-200`, `all`) in runtime and persist
    /// `disabled_tunnels` to `wpmulti.toml` if a config path is configured.
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
                    if let Err(e) = self.lifecycle.suspend_tunnel(id).await {
                        tracing::warn!("Failed to suspend disabled tunnel '{}': {}", id, e);
                    }
                } else if entry.lifecycle_mode == LifecycleMode::Eager
                    && let Err(e) = self.lifecycle.activate_tunnel(id).await
                {
                    tracing::warn!("Failed to activate re-enabled tunnel '{}': {}", id, e);
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
        if let Some(path) = maybe_path
            && let Ok(toml_str) = toml::to_string_pretty(&cfg_snapshot)
            && let Err(e) = tokio::fs::write(&path, toml_str).await
        {
            tracing::warn!(
                "Failed to persist disabled_tunnels to '{}': {}",
                path.display(),
                e
            );
        }

        Ok(targets)
    }

    /// Return a cloned snapshot of the current [`MainConfig`].
    pub fn config_snapshot(&self) -> MainConfig {
        self.config.read().clone()
    }

    /// Validate and apply updated runtime settings to the manager and lifecycle controller.
    pub fn update_runtime_config(&self, new_cfg: MainConfig) -> Result<(), CoreError> {
        new_cfg.validate()?;
        self.lifecycle.set_prefer_ipv6(
            new_cfg.global.dns_preference == crate::config::toml_config::DnsPreference::Ipv6First,
        );
        self.lifecycle.set_ip_mode(new_cfg.global.ip_mode);
        self.lifecycle
            .set_idle_timeout(new_cfg.lifecycle.idle_timeout);
        self.lifecycle
            .set_handshake_timeout(new_cfg.lifecycle.handshake_timeout);
        self.lifecycle
            .set_health_check(new_cfg.health_check.threshold, new_cfg.health_check.cooldown);
        self.lifecycle
            .set_max_active_tunnels(new_cfg.global.max_active_tunnels);
        self.lifecycle.set_dns_fallback(new_cfg.global.dns_fallback);
        self.lifecycle.set_dns_strategy(new_cfg.global.dns_strategy);
        *self.config.write() = new_cfg;
        Ok(())
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
                    Ok(Err(e)) => return Err(e),
                    Err(e) => {
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
        self.listeners
            .start_all(&cfg, &self.registry, &self.lifecycle)
            .await?;

        Ok(())
    }

    /// Stop the tunnel manager: terminates listeners, stops active prober, stops idle teardown,
    /// and cleanly closes all running and suspended tunnels.
    pub async fn stop(&self) -> Result<(), CoreError> {
        // 1. Stop all proxy listeners
        self.listeners.stop().await;

        // 2. Stop active prober
        self.prober.stop().await;

        // 3. Stop lifecycle controller and cleanly shut down all tunnels
        self.lifecycle.stop().await;

        Ok(())
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

        let _act_lock = existing.activation_lock.lock().await;
        if existing.stats.active_conns.load(Ordering::SeqCst) == 0 {
            let maybe_active = existing.active.write().take();
            if let Some(active) = maybe_active {
                active.device.suspend().await;
                active.netstack.close().await;
            }
            *existing.state.write() = TunnelState::Dormant;

            let saved_port = *existing.assigned_port.read();
            let was_disabled = existing.is_disabled()
                || cfg_snapshot.disabled_tunnels.iter().any(|d| d == &t_cfg.id);
            *existing.config.write() = t_cfg.clone();

            let new_entry = TunnelEntry::new(t_cfg.id.clone(), t_cfg, existing.lifecycle_mode);
            if was_disabled {
                new_entry.set_disabled(true);
            }
            if let Some(p) = saved_port {
                new_entry.set_assigned_port(p);
            }
            self.registry.replace(new_entry);
        } else {
            *existing.config.write() = t_cfg;
        }
        true
    }
}
