//! Listener supervisor managing dedicated per-tunnel and shared multi-tenant proxy listeners.
//!
//! Handles automatic port assignment, socket binding, protocol dispatch (SOCKS5 and HTTP),
//! and coordinated graceful shutdown.

use std::io;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
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
    started: std::sync::atomic::AtomicBool,
}

impl Default for ListenerSupervisor {
    fn default() -> Self {
        Self::new()
    }
}

impl ListenerSupervisor {
    /// Construct a new listener supervisor.
    pub fn new() -> Self {
        let (shutdown_tx, _) = watch::channel(false);
        Self {
            shutdown_tx,
            handles: Mutex::new(Vec::new()),
            started: std::sync::atomic::AtomicBool::new(false),
        }
    }

    /// Return whether `start_all` has been invoked on this supervisor.
    pub fn is_started(&self) -> bool {
        self.started.load(std::sync::atomic::Ordering::Relaxed)
    }

    /// Start all listeners configured in [`MainConfig`].
    pub async fn start_all(
        &self,
        config: &MainConfig,
        registry: &Arc<TunnelRegistry>,
        lifecycle: &Arc<LifecycleController>,
    ) -> Result<Vec<ActiveListenerInfo>, CoreError> {
        let mut started = Vec::new();

        // 1. Start dedicated per-tunnel listeners if enabled
        if config.per_tunnel.enabled {
            let dedicated = self
                .start_dedicated_listeners(
                    &config.per_tunnel,
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
                .start_shared_listener_with_options(
                    shared_cfg,
                    registry,
                    lifecycle,
                    (config.health_check.threshold, config.health_check.cooldown),
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

        self.started
            .store(true, std::sync::atomic::Ordering::Relaxed);
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

    async fn start_dedicated_protocol_listeners(
        &self,
        entries: &[Arc<crate::core::registry::TunnelEntry>],
        per_tunnel: &PerTunnelSettings,
        bind_address: IpAddr,
        listener_type: ListenerType,
        lifecycle: &Arc<LifecycleController>,
    ) -> Result<Vec<ActiveListenerInfo>, CoreError> {
        let base_port = match listener_type {
            ListenerType::Socks5 => per_tunnel.base_socks5_port,
            ListenerType::Http => per_tunnel.base_http_port,
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
            if let Some(p) = per_tunnel
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
                per_tunnel
                    .overrides
                    .get(&entry.id)
                    .and_then(|o| match listener_type {
                        ListenerType::Socks5 => o.socks5_port,
                        ListenerType::Http => o.http_port,
                    });
            let port = if let Some(p) = override_port {
                p
            } else {
                let Some(p) = Self::pick_free_dedicated_port(&mut used_ports, &mut next_port)
                else {
                    self.rollback_dedicated_batch(&started, entries);
                    return Err(CoreError::ListenerError(format!(
                        "no free {proto_label} port available for tunnel '{}'",
                        entry.id
                    )));
                };
                p
            };

            let bind_addr = SocketAddr::new(bind_address, port);
            let listener = match TcpListener::bind(bind_addr).await {
                Ok(l) => l,
                Err(e) => {
                    self.rollback_dedicated_batch(&started, entries);
                    return Err(CoreError::ListenerError(format!(
                        "failed to bind dedicated {proto_label} listener for tunnel '{}' on {bind_addr}: {e:?}",
                        entry.id
                    )));
                }
            };
            let actual_addr = listener.local_addr().unwrap_or(bind_addr);

            if listener_type == ListenerType::Socks5 || entry.assigned_port.read().is_none() {
                entry.set_assigned_port(actual_addr.port());
            }

            let auth = per_tunnel
                .overrides
                .get(&entry.id)
                .and_then(|o| o.password.as_ref())
                .map(|p| (entry.id.clone(), p.clone()));

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
            ));

            self.handles.lock().push(ListenerHandle {
                info: info.clone(),
                task,
            });
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
                self.started
                    .store(false, std::sync::atomic::Ordering::Relaxed);
            }
            drop(handles);
        }
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
        bind_address: IpAddr,
        registry: &Arc<TunnelRegistry>,
        lifecycle: &Arc<LifecycleController>,
    ) -> Result<Vec<ActiveListenerInfo>, CoreError> {
        let entries = registry.all_entries();
        let mut started = self
            .start_dedicated_protocol_listeners(
                &entries,
                per_tunnel,
                bind_address,
                ListenerType::Socks5,
                lifecycle,
            )
            .await?;
        let http_started = match self
            .start_dedicated_protocol_listeners(
                &entries,
                per_tunnel,
                bind_address,
                ListenerType::Http,
                lifecycle,
            )
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

    /// Start a single shared listener from [`SharedListenerSettings`].
    pub async fn start_shared_listener(
        &self,
        settings: &SharedListenerSettings,
        registry: &Arc<TunnelRegistry>,
        lifecycle: &Arc<LifecycleController>,
    ) -> Result<ActiveListenerInfo, CoreError> {
        self.start_shared_listener_with_health(
            settings,
            registry,
            lifecycle,
            3,
            Duration::from_secs(30),
        )
        .await
    }

    /// Start a single shared listener with specified health check parameters.
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

    /// Start a single shared listener with health check parameters and per-tunnel password overrides.
    pub async fn start_shared_listener_with_options(
        &self,
        settings: &SharedListenerSettings,
        registry: &Arc<TunnelRegistry>,
        lifecycle: &Arc<LifecycleController>,
        (failure_threshold, cooldown_duration): (usize, Duration),
        per_tunnel_passwords: std::collections::HashMap<String, String>,
    ) -> Result<ActiveListenerInfo, CoreError> {
        let bind_addr = settings.bind;
        let listener = TcpListener::bind(bind_addr).await.map_err(|e| {
            CoreError::ListenerError(format!(
                "failed to bind shared listener on {bind_addr}: {e:?}"
            ))
        })?;

        let router = MultiTenantRouter::from_settings_with_health(
            settings,
            Arc::clone(lifecycle),
            Arc::clone(registry),
            failure_threshold,
            cooldown_duration,
        )
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
        bind_address: IpAddr,
        lifecycle: &Arc<LifecycleController>,
    ) -> Result<Vec<ActiveListenerInfo>, CoreError> {
        let mut started = Vec::new();
        let mut used_ports: std::collections::HashSet<u16> = {
            let handles = self.handles.lock();
            handles.iter().map(|h| h.info.address.port()).collect()
        };

        let ovr = per_tunnel.overrides.get(&entry.id);
        let auth = ovr
            .and_then(|o| o.password.as_ref())
            .map(|p| (entry.id.clone(), p.clone()));

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

    /// Gracefully stop and join all running listeners.
    pub async fn stop(&self) {
        self.started
            .store(false, std::sync::atomic::Ordering::Relaxed);
        let _ = self.shutdown_tx.send(true);
        let handles = {
            let mut guard = self.handles.lock();
            std::mem::take(&mut *guard)
        };

        for mut handle in handles {
            if tokio::time::timeout(Duration::from_millis(500), &mut handle.task)
                .await
                .is_err()
            {
                handle.task.abort();
                let _ = handle.task.await;
            }
        }
    }
}

/// Maximum concurrent client connections accepted per proxy listener.
const MAX_LISTENER_CONNS: usize = 4096;

async fn acquire_listener_permit(
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

/// Core asynchronous accept loop for a TCP proxy listener.
async fn run_listener_loop(
    listener: TcpListener,
    router: Arc<dyn TunnelRouter>,
    listener_type: ListenerType,
    mut shutdown_rx: watch::Receiver<bool>,
) {
    let mut client_tasks = tokio::task::JoinSet::new();
    let conn_sem = Arc::new(tokio::sync::Semaphore::new(MAX_LISTENER_CONNS));

    loop {
        while let Some(res) = client_tasks.try_join_next() {
            let _ = res;
        }

        let Some(permit) = acquire_listener_permit(&conn_sem, &mut shutdown_rx).await else {
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
                            match listener_type {
                                ListenerType::Socks5 => {
                                    let _ = handle_socks5_with_addrs(stream, r, local_ip, peer_ip).await;
                                }
                                ListenerType::Http => {
                                    let _ = handle_http(stream, r).await;
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
                            tracing::warn!("Transient TCP accept error: {:?}; backing off", e);
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

    client_tasks.abort_all();
    while client_tasks.join_next().await.is_some() {}
}
