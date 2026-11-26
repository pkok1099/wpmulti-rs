//! Listener supervisor managing dedicated per-tunnel and shared multi-tenant proxy listeners.
//!
//! Handles automatic port assignment, socket binding, protocol dispatch (SOCKS5 and HTTP),
//! and coordinated graceful shutdown.

use std::io;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::Duration;

use parking_lot::Mutex;
use serde::{Deserialize, Serialize};
use tokio::net::TcpListener;
use tokio::sync::watch;
use tokio::task::JoinHandle;

use crate::config::{ListenerType, MainConfig, PerTunnelSettings, SharedListenerSettings};
use crate::core::CoreError;
use crate::core::lifecycle::LifecycleController;
use crate::core::registry::TunnelRegistry;
use crate::core::router::{DedicatedTunnelRouter, MultiTenantRouter};
use crate::proxy::{TunnelRouter, handle_http, handle_socks5_with_addrs};

/// Diagnostic metadata for an active TCP listener.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActiveListenerInfo {
    /// Human-readable descriptive name.
    pub name: String,
    /// Bound socket address.
    pub address: SocketAddr,
    /// Supported proxy protocol.
    pub listener_type: ListenerType,
    /// Whether this is a multi-tenant shared listener.
    pub is_shared: bool,
    /// Associated tunnel ID if this is a dedicated per-tunnel listener.
    pub tunnel_id: Option<String>,
}

#[derive(Debug)]
struct ListenerHandle {
    info: ActiveListenerInfo,
    task: JoinHandle<()>,
}

/// Supervisor managing all proxy TCP listeners.
#[derive(Debug)]
pub struct ListenerSupervisor {
    shutdown_tx: watch::Sender<bool>,
    handles: Mutex<Vec<ListenerHandle>>,
    started: AtomicBool,
    drain_timeout_ms: Arc<AtomicU64>,
    /// Daemon-wide connection semaphore shared by every listener loop
    /// (audit run-1, `listener-per-listener-conn-cap-no-global-cap`):
    /// the per-listener semaphore alone lets the aggregate grow with
    /// the listener count, so each accepted connection also holds one
    /// permit here for its whole lifetime.
    global_conn_sem: Arc<tokio::sync::Semaphore>,
}

impl Default for ListenerSupervisor {
    fn default() -> Self {
        Self::new()
    }
}

/// Settings shared by both dedicated-protocol start passes: the
/// per-tunnel section plus the global-password fallback derived from the
/// shared listeners (see `MainConfig::dedicated_fallback_password`).
#[derive(Clone, Copy)]
struct DedicatedStartup<'a> {
    per_tunnel: &'a PerTunnelSettings,
    fallback_password: Option<&'a str>,
    bind_address: IpAddr,
}

impl ListenerSupervisor {
    /// Construct a new listener supervisor.
    pub fn new() -> Self {
        let (shutdown_tx, _) = watch::channel(false);
        Self {
            shutdown_tx,
            handles: Mutex::new(Vec::new()),
            started: AtomicBool::new(false),
            drain_timeout_ms: Arc::new(AtomicU64::new(500)),
            global_conn_sem: Arc::new(tokio::sync::Semaphore::new(MAX_GLOBAL_LISTENER_CONNS)),
        }
    }

    /// Return whether `start_all` has been invoked on this supervisor.
    pub fn is_started(&self) -> bool {
        self.started.load(Ordering::Relaxed)
    }

    /// Start all listeners configured in [`MainConfig`].
    pub async fn start_all(
        &self,
        config: &MainConfig,
        registry: &Arc<TunnelRegistry>,
        lifecycle: &Arc<LifecycleController>,
    ) -> Result<Vec<ActiveListenerInfo>, CoreError> {
        let _ = self.shutdown_tx.send(false);
        let mut started = Vec::new();

        // 1. Start dedicated per-tunnel listeners if enabled
        if config.per_tunnel.enabled {
            let dedicated = self
                .start_dedicated_listeners(
                    &config.per_tunnel,
                    config.dedicated_fallback_password().as_deref(),
                    config.global.bind_address,
                    registry,
                    lifecycle,
                )
                .await?;
            started.extend(dedicated);
        }

        // 2. Start configured shared listeners
        let per_tunnel_passwords: std::collections::HashMap<String, String> = config
            .per_tunnel
            .overrides
            .iter()
            .filter_map(|(id, ovr)| ovr.password.as_ref().map(|p| (id.clone(), p.clone())))
            .collect();

        for shared_cfg in &config.shared_listeners {
            let info = match self
                .start_shared_listener_inner(
                    shared_cfg,
                    registry,
                    lifecycle,
                    None,
                    per_tunnel_passwords.clone(),
                )
                .await
            {
                Ok(info) => info,
                Err(e) => {
                    self.rollback_started_listeners(&started, Some(registry));
                    return Err(e);
                }
            };
            started.push(info);
        }

        self.started.store(true, Ordering::Relaxed);
        Ok(started)
    }

    fn pick_free_dedicated_port(
        used_ports: &mut std::collections::HashSet<u16>,
        next_port: &mut u16,
    ) -> Option<u16> {
        for _ in 0..=u16::MAX {
            if *next_port == 0 {
                *next_port = 1;
            }
            if used_ports.insert(*next_port) {
                let chosen = *next_port;
                *next_port = next_port.wrapping_add(1);
                return Some(chosen);
            }
            *next_port = next_port.wrapping_add(1);
        }
        None
    }

    fn rollback_dedicated_batch(
        &self,
        started: &[ActiveListenerInfo],
        entries: &[Arc<crate::core::registry::TunnelEntry>],
    ) {
        self.rollback_started_listeners(started, None);
        for s in started {
            if let Some(tid) = &s.tunnel_id
                && let Some(e) = entries.iter().find(|e| &e.id == tid)
            {
                *e.assigned_port.write() = None;
            }
        }
    }

    async fn bind_dedicated_listener(
        bind_address: IpAddr,
        proto_label: &str,
        tunnel_id: &str,
        override_port: Option<u16>,
        used_ports: &mut std::collections::HashSet<u16>,
        next_port: &mut u16,
    ) -> Result<Option<TcpListener>, CoreError> {
        if let Some(port) = override_port {
            let bind_addr = SocketAddr::new(bind_address, port);
            return match TcpListener::bind(bind_addr).await {
                Ok(l) => Ok(Some(l)),
                Err(e) if e.kind() == io::ErrorKind::AddrInUse => {
                    tracing::warn!(
                        "Skipping dedicated {proto_label} listener for tunnel '{tunnel_id}' on {bind_addr}: {e} (port already in use)"
                    );
                    Ok(None)
                }
                Err(e) => Err(CoreError::ListenerError(format!(
                    "failed to bind dedicated {proto_label} listener for tunnel '{tunnel_id}' on {bind_addr}: {e}"
                ))),
            };
        }

        while let Some(port) = Self::pick_free_dedicated_port(used_ports, next_port) {
            let bind_addr = SocketAddr::new(bind_address, port);
            match TcpListener::bind(bind_addr).await {
                Ok(l) => return Ok(Some(l)),
                Err(e) if e.kind() == io::ErrorKind::AddrInUse => {
                    tracing::warn!(
                        "Port {port} already in use while binding dedicated {proto_label} listener for tunnel '{tunnel_id}', shifting to next free port"
                    );
                }
                Err(e) => {
                    return Err(CoreError::ListenerError(format!(
                        "failed to bind dedicated {proto_label} listener for tunnel '{tunnel_id}' on {bind_addr}: {e}"
                    )));
                }
            }
        }

        Err(CoreError::ListenerError(format!(
            "no free {proto_label} port available for tunnel '{tunnel_id}'"
        )))
    }

    /// Derive the credential a dedicated listener must enforce for
    /// `tunnel_id`: the tunnel's own override password when one exists,
    /// else the single configured global password (fallback). Fails closed:
    /// when a password is configured anywhere (a global fallback or any
    /// override) but this tunnel has neither, the listener must not start
    /// unauthenticated (audit run-1, high).
    fn dedicated_auth_for_tunnel(
        per_tunnel: &PerTunnelSettings,
        fallback_password: Option<&str>,
        tunnel_id: &str,
    ) -> Result<Option<(String, String)>, CoreError> {
        let auth = per_tunnel
            .overrides
            .get(tunnel_id)
            .and_then(|o| o.password.as_ref())
            .map(|p| (tunnel_id.to_string(), p.clone()))
            .or_else(|| fallback_password.map(|p| (tunnel_id.to_string(), p.to_string())));
        if auth.is_none() {
            let any_password = fallback_password.is_some()
                || per_tunnel
                    .overrides
                    .values()
                    .any(|o| o.password.as_ref().is_some_and(|p| !p.is_empty()));
            if any_password {
                return Err(CoreError::ListenerError(format!(
                    "dedicated listener for tunnel '{tunnel_id}' would accept unauthenticated clients while a proxy password is configured; set a per_tunnel.overrides.{tunnel_id}.password or disable dedicated listeners"
                )));
            }
        }
        Ok(auth)
    }

    fn register_dedicated_listener(
        &self,
        (listener, actual_addr): (TcpListener, SocketAddr),
        entry: &Arc<crate::core::registry::TunnelEntry>,
        auth: Option<(String, String)>,
        listener_type: ListenerType,
        lifecycle: &Arc<LifecycleController>,
    ) -> ActiveListenerInfo {
        let proto_label = match listener_type {
            ListenerType::Socks5 => "socks5",
            ListenerType::Http => "http",
        };
        if listener_type == ListenerType::Socks5 || entry.assigned_port.read().is_none() {
            entry.set_assigned_port(actual_addr.port());
        }

        let router = Arc::new(DedicatedTunnelRouter::new(
            entry.id.clone(),
            Arc::clone(lifecycle),
            auth,
        ));

        let info = ActiveListenerInfo {
            name: format!("dedicated-{proto_label}-{}", entry.id),
            address: actual_addr,
            listener_type,
            is_shared: false,
            tunnel_id: Some(entry.id.clone()),
        };

        let shutdown_rx = self.shutdown_tx.subscribe();
        let task = tokio::spawn(run_listener_loop(
            listener,
            router,
            listener_type,
            shutdown_rx,
            Arc::clone(&self.drain_timeout_ms),
            Arc::clone(&self.global_conn_sem),
        ));

        self.handles.lock().push(ListenerHandle {
            info: info.clone(),
            task,
        });
        info
    }

    async fn start_dedicated_protocol_listeners(
        &self,
        entries: &[Arc<crate::core::registry::TunnelEntry>],
        startup: DedicatedStartup<'_>,
        listener_type: ListenerType,
        lifecycle: &Arc<LifecycleController>,
    ) -> Result<Vec<ActiveListenerInfo>, CoreError> {
        let base_port = match listener_type {
            ListenerType::Socks5 => startup.per_tunnel.base_socks5_port,
            ListenerType::Http => startup.per_tunnel.base_http_port,
        };
        let Some(base_port) = base_port else {
            return Ok(Vec::new());
        };
        let proto_label = match listener_type {
            ListenerType::Socks5 => "socks5",
            ListenerType::Http => "http",
        };
        let mut started = Vec::with_capacity(entries.len());
        let mut used_ports: std::collections::HashSet<u16> = {
            let handles = self.handles.lock();
            handles.iter().map(|h| h.info.address.port()).collect()
        };
        for e in entries {
            if let Some(p) =
                startup
                    .per_tunnel
                    .overrides
                    .get(&e.id)
                    .and_then(|o| match listener_type {
                        ListenerType::Socks5 => o.socks5_port,
                        ListenerType::Http => o.http_port,
                    })
            {
                used_ports.insert(p);
            }
        }
        let mut next_port = if base_port == 0 { 1 } else { base_port };

        for entry in entries {
            let override_port =
                startup
                    .per_tunnel
                    .overrides
                    .get(&entry.id)
                    .and_then(|o| match listener_type {
                        ListenerType::Socks5 => o.socks5_port,
                        ListenerType::Http => o.http_port,
                    });
            // Derive (and enforce) the credential before binding: a tunnel
            // with no credential must not get an unauthenticated dedicated
            // listener while a password is configured anywhere.
            let auth = match Self::dedicated_auth_for_tunnel(
                startup.per_tunnel,
                startup.fallback_password,
                &entry.id,
            ) {
                Ok(auth) => auth,
                Err(e) => {
                    self.rollback_dedicated_batch(&started, entries);
                    return Err(e);
                }
            };
            let listener = match Self::bind_dedicated_listener(
                startup.bind_address,
                proto_label,
                &entry.id,
                override_port,
                &mut used_ports,
                &mut next_port,
            )
            .await
            {
                Ok(Some(l)) => l,
                Ok(None) => continue,
                Err(e) => {
                    self.rollback_dedicated_batch(&started, entries);
                    return Err(e);
                }
            };
            let actual_addr = match listener.local_addr() {
                Ok(addr) => addr,
                Err(e) => {
                    self.rollback_dedicated_batch(&started, entries);
                    return Err(CoreError::ListenerError(format!(
                        "failed to query local_addr for {proto_label} tunnel '{}': {e}",
                        entry.id
                    )));
                }
            };

            let info = self.register_dedicated_listener(
                (listener, actual_addr),
                entry,
                auth,
                listener_type,
                lifecycle,
            );
            started.push(info);
        }

        Ok(started)
    }

    fn rollback_started_listeners(
        &self,
        started: &[ActiveListenerInfo],
        registry: Option<&Arc<TunnelRegistry>>,
    ) {
        let rollback_keys: std::collections::HashSet<(&str, SocketAddr)> = started
            .iter()
            .map(|i| (i.name.as_str(), i.address))
            .collect();
        let mut removed = Vec::new();
        {
            let mut handles = self.handles.lock();
            let mut idx = 0;
            while idx < handles.len() {
                if handles.get(idx).is_some_and(|h| {
                    rollback_keys.contains(&(h.info.name.as_str(), h.info.address))
                }) {
                    removed.push(handles.swap_remove(idx));
                } else {
                    idx += 1;
                }
            }
            if handles.is_empty() {
                self.started.store(false, Ordering::Relaxed);
            }
            drop(handles);
        };
        if let Some(reg) = registry {
            for info in started {
                if let Some(ref tid) = info.tunnel_id
                    && let Some(entry) = reg.get(tid)
                {
                    *entry.assigned_port.write() = None;
                }
            }
        }
        for h in removed {
            h.task.abort();
        }
    }

    /// Start dedicated per-tunnel listeners for all registered tunnels.
    pub async fn start_dedicated_listeners(
        &self,
        per_tunnel: &PerTunnelSettings,
        fallback_password: Option<&str>,
        bind_address: IpAddr,
        registry: &Arc<TunnelRegistry>,
        lifecycle: &Arc<LifecycleController>,
    ) -> Result<Vec<ActiveListenerInfo>, CoreError> {
        let entries = registry.all_entries();
        let startup = DedicatedStartup {
            per_tunnel,
            fallback_password,
            bind_address,
        };
        let mut started = self
            .start_dedicated_protocol_listeners(&entries, startup, ListenerType::Socks5, lifecycle)
            .await?;
        let http_started = match self
            .start_dedicated_protocol_listeners(&entries, startup, ListenerType::Http, lifecycle)
            .await
        {
            Ok(h) => h,
            Err(e) => {
                self.rollback_started_listeners(&started, Some(registry));
                return Err(e);
            }
        };
        started.extend(http_started);

        Ok(started)
    }

    /// Start a single shared listener from [`SharedListenerSettings`], tracking
    /// [`LifecycleController::health_check`] dynamically.
    pub async fn start_shared_listener(
        &self,
        settings: &SharedListenerSettings,
        registry: &Arc<TunnelRegistry>,
        lifecycle: &Arc<LifecycleController>,
    ) -> Result<ActiveListenerInfo, CoreError> {
        self.start_shared_listener_inner(
            settings,
            registry,
            lifecycle,
            None,
            std::collections::HashMap::new(),
        )
        .await
    }

    /// Start a single shared listener with explicit static health check parameters.
    pub async fn start_shared_listener_with_health(
        &self,
        settings: &SharedListenerSettings,
        registry: &Arc<TunnelRegistry>,
        lifecycle: &Arc<LifecycleController>,
        failure_threshold: usize,
        cooldown_duration: Duration,
    ) -> Result<ActiveListenerInfo, CoreError> {
        self.start_shared_listener_with_options(
            settings,
            registry,
            lifecycle,
            (failure_threshold, cooldown_duration),
            std::collections::HashMap::new(),
        )
        .await
    }

    /// Start a single shared listener with explicit health check parameters and per-tunnel password overrides.
    pub async fn start_shared_listener_with_options(
        &self,
        settings: &SharedListenerSettings,
        registry: &Arc<TunnelRegistry>,
        lifecycle: &Arc<LifecycleController>,
        health: (usize, Duration),
        per_tunnel_passwords: std::collections::HashMap<String, String>,
    ) -> Result<ActiveListenerInfo, CoreError> {
        self.start_shared_listener_inner(
            settings,
            registry,
            lifecycle,
            Some(health),
            per_tunnel_passwords,
        )
        .await
    }

    async fn start_shared_listener_inner(
        &self,
        settings: &SharedListenerSettings,
        registry: &Arc<TunnelRegistry>,
        lifecycle: &Arc<LifecycleController>,
        health_override: Option<(usize, Duration)>,
        per_tunnel_passwords: std::collections::HashMap<String, String>,
    ) -> Result<ActiveListenerInfo, CoreError> {
        let bind_addr = settings.bind;
        let listener = TcpListener::bind(bind_addr).await.map_err(|e| {
            CoreError::ListenerError(format!(
                "failed to bind shared listener on {bind_addr}: {e:?}"
            ))
        })?;

        let router = match health_override {
            Some((threshold, cooldown)) => MultiTenantRouter::from_settings_with_health(
                settings,
                Arc::clone(lifecycle),
                Arc::clone(registry),
                threshold,
                cooldown,
            ),
            None => MultiTenantRouter::from_settings(
                settings,
                Arc::clone(lifecycle),
                Arc::clone(registry),
            ),
        }
        .with_per_tunnel_passwords(per_tunnel_passwords);

        let actual_addr = listener.local_addr().unwrap_or(bind_addr);

        let info = ActiveListenerInfo {
            name: settings.name.clone(),
            address: actual_addr,
            listener_type: settings.listener_type,
            is_shared: true,
            tunnel_id: None,
        };

        let shutdown_rx = self.shutdown_tx.subscribe();
        let task = tokio::spawn(run_listener_loop(
            listener,
            router,
            settings.listener_type,
            shutdown_rx,
            Arc::clone(&self.drain_timeout_ms),
            Arc::clone(&self.global_conn_sem),
        ));

        self.handles.lock().push(ListenerHandle {
            info: info.clone(),
            task,
        });

        Ok(info)
    }

    /// List all currently running listeners.
    pub fn list_listeners(&self) -> Vec<ActiveListenerInfo> {
        let handles = self.handles.lock();
        handles.iter().map(|h| h.info.clone()).collect()
    }

    /// Stop and remove all dedicated (non-shared) listeners, clearing
    /// each tunnel's assigned port (audit run-1,
    /// `core/apply-runtime-config:per-tunnel-enabled-no-listener-reconcile`).
    /// Used when `per_tunnel.enabled` is flipped off — or when the
    /// dedicated listener identity (credentials, ports) changes — at
    /// runtime. Shared listeners are untouched.
    pub async fn stop_all_dedicated(&self, registry: &Arc<TunnelRegistry>) {
        let removed: Vec<ListenerHandle> = {
            let mut guard = self.handles.lock();
            let mut kept = Vec::with_capacity(guard.len());
            let mut to_stop = Vec::new();
            for h in guard.drain(..) {
                if h.info.is_shared {
                    kept.push(h);
                } else {
                    to_stop.push(h);
                }
            }
            *guard = kept;
            to_stop
        };

        for handle in &removed {
            if let Some(tid) = &handle.info.tunnel_id
                && let Some(entry) = registry.get(tid)
            {
                *entry.assigned_port.write() = None;
            }
        }
        for handle in removed {
            handle.task.abort();
            let _ = handle.task.await;
        }
    }

    /// Stop and remove dedicated listeners belonging to `tunnel_id` (used during hot-reload).
    pub async fn stop_dedicated_for_tunnel(&self, tunnel_id: &str) {
        let removed: Vec<ListenerHandle> = {
            let mut guard = self.handles.lock();
            let mut kept = Vec::with_capacity(guard.len());
            let mut to_stop = Vec::new();
            for h in guard.drain(..) {
                if !h.info.is_shared && h.info.tunnel_id.as_deref() == Some(tunnel_id) {
                    to_stop.push(h);
                } else {
                    kept.push(h);
                }
            }
            *guard = kept;
            to_stop
        };

        for handle in removed {
            handle.task.abort();
            let _ = handle.task.await;
        }
    }

    async fn spawn_dedicated_listener(
        &self,
        entry: &Arc<crate::core::registry::TunnelEntry>,
        bind_addr: SocketAddr,
        listener_type: ListenerType,
        auth: Option<(String, String)>,
        lifecycle: &Arc<LifecycleController>,
    ) -> Result<ActiveListenerInfo, CoreError> {
        let kind = match listener_type {
            ListenerType::Socks5 => "SOCKS5",
            ListenerType::Http => "HTTP",
        };
        let listener = TcpListener::bind(bind_addr).await.map_err(|e| {
            CoreError::ListenerError(format!(
                "failed to bind dedicated {} listener for tunnel '{}' on {}: {:?}",
                kind, entry.id, bind_addr, e
            ))
        })?;
        let actual_addr = listener.local_addr().unwrap_or(bind_addr);
        if entry.assigned_port.read().is_none() {
            entry.set_assigned_port(actual_addr.port());
        }

        let router = Arc::new(DedicatedTunnelRouter::new(
            entry.id.clone(),
            Arc::clone(lifecycle),
            auth,
        ));
        let info = ActiveListenerInfo {
            name: format!("dedicated-{}-{}", kind.to_ascii_lowercase(), entry.id),
            address: actual_addr,
            listener_type,
            is_shared: false,
            tunnel_id: Some(entry.id.clone()),
        };
        let task = tokio::spawn(run_listener_loop(
            listener,
            router,
            listener_type,
            self.shutdown_tx.subscribe(),
            Arc::clone(&self.drain_timeout_ms),
            Arc::clone(&self.global_conn_sem),
        ));
        self.handles.lock().push(ListenerHandle {
            info: info.clone(),
            task,
        });
        Ok(info)
    }

    /// Start dedicated SOCKS5/HTTP listeners for a single newly added tunnel (used during hot-reload).
    pub async fn start_dedicated_for_tunnel(
        &self,
        entry: &Arc<crate::core::registry::TunnelEntry>,
        per_tunnel: &PerTunnelSettings,
        fallback_password: Option<&str>,
        bind_address: IpAddr,
        lifecycle: &Arc<LifecycleController>,
    ) -> Result<Vec<ActiveListenerInfo>, CoreError> {
        let mut started = Vec::new();
        let mut used_ports: std::collections::HashSet<u16> = {
            let handles = self.handles.lock();
            handles.iter().map(|h| h.info.address.port()).collect()
        };

        let ovr = per_tunnel.overrides.get(&entry.id);
        // Fail fast before binding anything: a tunnel with no credential
        // must not get an unauthenticated dedicated listener while a
        // password is configured anywhere (audit run-1, high).
        let auth = Self::dedicated_auth_for_tunnel(per_tunnel, fallback_password, &entry.id)?;

        let specs = [
            (
                per_tunnel.base_socks5_port,
                ovr.and_then(|o| o.socks5_port),
                ListenerType::Socks5,
            ),
            (
                per_tunnel.base_http_port,
                ovr.and_then(|o| o.http_port),
                ListenerType::Http,
            ),
        ];

        for (base_opt, override_port, listener_type) in specs {
            let Some(mut next_port) = base_opt else {
                continue;
            };
            let port = if let Some(p) = override_port {
                used_ports.insert(p);
                p
            } else {
                let Some(p) = Self::pick_free_dedicated_port(&mut used_ports, &mut next_port)
                else {
                    self.rollback_started_listeners(&started, None);
                    *entry.assigned_port.write() = None;
                    return Err(CoreError::ListenerError(format!(
                        "no free port available for tunnel '{}'",
                        entry.id
                    )));
                };
                p
            };
            let info = match self
                .spawn_dedicated_listener(
                    entry,
                    SocketAddr::new(bind_address, port),
                    listener_type,
                    auth.clone(),
                    lifecycle,
                )
                .await
            {
                Ok(info) => info,
                Err(e) => {
                    self.rollback_started_listeners(&started, None);
                    *entry.assigned_port.write() = None;
                    return Err(e);
                }
            };
            started.push(info);
        }

        Ok(started)
    }

    /// Signal all listeners to stop accepting new connections immediately while allowing
    /// existing connections up to `drain_timeout` to finish.
    pub fn begin_shutdown(&self, drain_timeout: Duration) {
        self.started.store(false, Ordering::Relaxed);
        let ms = drain_timeout.as_millis().min(u128::from(u64::MAX)) as u64;
        self.drain_timeout_ms.store(ms, Ordering::Relaxed);
        let _ = self.shutdown_tx.send(true);
    }

    /// Wait concurrently up to `drain_timeout` for all listener tasks and their active connections
    /// to finish, then abort any remaining tasks.
    pub async fn drain(&self, drain_timeout: Duration) {
        let handles = {
            let mut guard = self.handles.lock();
            std::mem::take(&mut *guard)
        };
        if handles.is_empty() {
            return;
        }
        let abort_handles: Vec<_> = handles.iter().map(|h| h.task.abort_handle()).collect();
        let mut join_set = tokio::task::JoinSet::new();
        for handle in handles {
            join_set.spawn(async move {
                let _ = handle.task.await;
            });
        }
        if tokio::time::timeout(drain_timeout + Duration::from_millis(250), async {
            while join_set.join_next().await.is_some() {}
        })
        .await
        .is_err()
        {
            for ah in abort_handles {
                ah.abort();
            }
            while join_set.join_next().await.is_some() {}
        }
    }

    /// Gracefully stop and join all running listeners with the default drain timeout.
    pub async fn stop(&self) {
        let drain_timeout = Duration::from_millis(500);
        self.begin_shutdown(drain_timeout);
        self.drain(drain_timeout).await;
    }

    /// Gracefully stop and join all running listeners with an explicit drain timeout.
    pub async fn stop_with_drain_timeout(&self, drain_timeout: Duration) {
        self.begin_shutdown(drain_timeout);
        self.drain(drain_timeout).await;
    }
}

/// Maximum concurrent client connections accepted per proxy listener.
const MAX_LISTENER_CONNS: usize = 4096;

/// Maximum concurrent client connections daemon-wide, across all proxy
/// listeners (audit run-1, `listener-per-listener-conn-cap-no-global-cap`).
/// Equal to the per-listener cap, so the daemon as a whole never holds
/// more live proxy connections than one listener could on its own. The
/// per-listener cap stays as a sub-limit; a single busy listener may
/// still consume the whole global budget, but the daemon-wide total
/// (file descriptors, tasks, tunnel resources) is now bounded no matter
/// how many dedicated listeners exist.
const MAX_GLOBAL_LISTENER_CONNS: usize = MAX_LISTENER_CONNS;

async fn acquire_one_permit(
    conn_sem: &Arc<tokio::sync::Semaphore>,
    shutdown_rx: &mut watch::Receiver<bool>,
) -> Option<tokio::sync::OwnedSemaphorePermit> {
    tokio::select! {
        biased;
        _ = shutdown_rx.changed() => {
            if *shutdown_rx.borrow() {
                return None;
            }
            Arc::clone(conn_sem).acquire_owned().await.ok()
        }
        res = Arc::clone(conn_sem).acquire_owned() => res.ok(),
    }
}

/// Acquire the daemon-wide permit first, then the per-listener permit;
/// both are held for the life of the accepted connection. The fixed
/// order (global, then local) avoids any circular wait between loops.
async fn acquire_listener_permits(
    global_sem: &Arc<tokio::sync::Semaphore>,
    conn_sem: &Arc<tokio::sync::Semaphore>,
    shutdown_rx: &mut watch::Receiver<bool>,
) -> Option<(
    tokio::sync::OwnedSemaphorePermit,
    tokio::sync::OwnedSemaphorePermit,
)> {
    let global = acquire_one_permit(global_sem, shutdown_rx).await?;
    let local = acquire_one_permit(conn_sem, shutdown_rx).await?;
    Some((global, local))
}

async fn drain_client_tasks(client_tasks: &mut tokio::task::JoinSet<()>, drain_dur: Duration) {
    if !client_tasks.is_empty() && !drain_dur.is_zero() {
        let deadline = tokio::time::Instant::now() + drain_dur;
        while !client_tasks.is_empty() {
            let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
            if remaining.is_zero() {
                break;
            }
            match tokio::time::timeout(remaining, client_tasks.join_next()).await {
                Ok(Some(_)) => {}
                Ok(None) | Err(_) => break,
            }
        }
    }

    client_tasks.abort_all();
    while client_tasks.join_next().await.is_some() {}
}

/// Core asynchronous accept loop for a TCP proxy listener.
async fn run_listener_loop(
    listener: TcpListener,
    router: Arc<dyn TunnelRouter>,
    listener_type: ListenerType,
    mut shutdown_rx: watch::Receiver<bool>,
    drain_timeout_ms: Arc<AtomicU64>,
    global_sem: Arc<tokio::sync::Semaphore>,
) {
    let mut client_tasks = tokio::task::JoinSet::new();
    let conn_sem = Arc::new(tokio::sync::Semaphore::new(MAX_LISTENER_CONNS));

    loop {
        while let Some(res) = client_tasks.try_join_next() {
            let _ = res;
        }

        let Some((global_permit, permit)) =
            acquire_listener_permits(&global_sem, &conn_sem, &mut shutdown_rx).await
        else {
            break;
        };

        tokio::select! {
            biased;
            _ = shutdown_rx.changed() => {
                if *shutdown_rx.borrow() {
                    break;
                }
            }
            res = listener.accept() => {
                match res {
                    Ok((stream, peer_addr)) => {
                        let r = Arc::clone(&router);
                        let local_ip = stream.local_addr().ok().map(|a| a.ip());
                        let peer_ip = Some(peer_addr.ip());
                        client_tasks.spawn(async move {
                            let _permit = permit;
                            let _global_permit = global_permit;
                            let result = match listener_type {
                                ListenerType::Socks5 => {
                                    handle_socks5_with_addrs(stream, r, local_ip, peer_ip).await
                                }
                                ListenerType::Http => handle_http(stream, r).await,
                            };
                            if let Err(e) = result {
                                // A handshake timeout means the client
                                // stalled mid-handshake and the server
                                // closed the connection without a
                                // reply — worth a warning so it is
                                // diagnosable. Anything else (a client
                                // disconnecting mid-request, a rejected
                                // auth) is routine noise.
                                if e.kind() == io::ErrorKind::TimedOut {
                                    tracing::warn!(
                                        "Proxy connection from {peer_addr} failed: {e}"
                                    );
                                } else {
                                    tracing::debug!(
                                        "Proxy connection from {peer_addr} ended: {e}"
                                    );
                                }
                            }
                        });
                    }
                    Err(e) => {
                        let is_transient = matches!(
                            e.raw_os_error(),
                            Some(libc::EMFILE | libc::ENFILE | libc::ECONNABORTED | libc::EINTR)
                        ) || e.kind() == io::ErrorKind::ConnectionAborted
                            || e.kind() == io::ErrorKind::Interrupted;

                        if is_transient {
                            tracing::warn!("Transient TCP accept error: {}; backing off", e);
                            tokio::time::sleep(Duration::from_millis(50)).await;
                        } else {
                            tracing::debug!("TCP listener accept stopped: {:?}", e);
                            break;
                        }
                    }
                }
            }
        }
    }

    // Stop accepting new connections immediately before draining active sessions.
    drop(listener);

    let drain_dur = Duration::from_millis(drain_timeout_ms.load(Ordering::Relaxed));
    drain_client_tasks(&mut client_tasks, drain_dur).await;
}
