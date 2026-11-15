//! Listener supervisor managing dedicated per-tunnel and shared multi-tenant proxy listeners.
//!
//! Handles automatic port assignment, socket binding, protocol dispatch (SOCKS5 and HTTP),
//! and coordinated graceful shutdown.

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;

use parking_lot::Mutex;
use serde::{Deserialize, Serialize};
use tokio::net::TcpListener;
use tokio::sync::watch;
use tokio::task::JoinHandle;

use crate::config::{ListenerType, MainConfig, PerTunnelSettings, SharedListenerSettings};
use crate::core::lifecycle::LifecycleController;
use crate::core::registry::TunnelRegistry;
use crate::core::router::{DedicatedTunnelRouter, MultiTenantRouter};
use crate::core::CoreError;
use crate::proxy::{handle_http, handle_socks5, TunnelRouter};

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

struct ListenerHandle {
    info: ActiveListenerInfo,
    task: JoinHandle<()>,
}

/// Supervisor managing all proxy TCP listeners.
pub struct ListenerSupervisor {
    shutdown_tx: watch::Sender<bool>,
    handles: Mutex<Vec<ListenerHandle>>,
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
        }
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
        for shared_cfg in &config.shared_listeners {
            let info = self
                .start_shared_listener(shared_cfg, registry, lifecycle)
                .await?;
            started.push(info);
        }

        Ok(started)
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
        let mut started = Vec::new();

        // Dedicated SOCKS5 listeners
        if let Some(base_socks5) = per_tunnel.base_socks5_port {
            for (idx, entry) in entries.iter().enumerate() {
                let port = per_tunnel
                    .overrides
                    .get(&entry.id)
                    .and_then(|o| o.socks5_port)
                    .unwrap_or_else(|| base_socks5.wrapping_add(idx as u16));

                let bind_addr = SocketAddr::new(bind_address, port);
                let listener = TcpListener::bind(bind_addr).await.map_err(|e| {
                    CoreError::ListenerError(format!(
                        "failed to bind dedicated SOCKS5 listener for tunnel '{}' on {}: {:?}",
                        entry.id, bind_addr, e
                    ))
                })?;

                entry.set_assigned_port(port);

                let router = Arc::new(DedicatedTunnelRouter::new(
                    entry.id.clone(),
                    Arc::clone(lifecycle),
                    None,
                ));

                let info = ActiveListenerInfo {
                    name: format!("dedicated-socks5-{}", entry.id),
                    address: bind_addr,
                    listener_type: ListenerType::Socks5,
                    is_shared: false,
                    tunnel_id: Some(entry.id.clone()),
                };

                let shutdown_rx = self.shutdown_tx.subscribe();
                let task = tokio::spawn(run_listener_loop(
                    listener,
                    router,
                    ListenerType::Socks5,
                    shutdown_rx,
                ));

                self.handles.lock().push(ListenerHandle {
                    info: info.clone(),
                    task,
                });
                started.push(info);
            }
        }

        // Dedicated HTTP listeners
        if let Some(base_http) = per_tunnel.base_http_port {
            for (idx, entry) in entries.iter().enumerate() {
                let port = per_tunnel
                    .overrides
                    .get(&entry.id)
                    .and_then(|o| o.http_port)
                    .unwrap_or_else(|| base_http.wrapping_add(idx as u16));

                let bind_addr = SocketAddr::new(bind_address, port);
                let listener = TcpListener::bind(bind_addr).await.map_err(|e| {
                    CoreError::ListenerError(format!(
                        "failed to bind dedicated HTTP listener for tunnel '{}' on {}: {:?}",
                        entry.id, bind_addr, e
                    ))
                })?;

                if entry.assigned_port.read().is_none() {
                    entry.set_assigned_port(port);
                }

                let router = Arc::new(DedicatedTunnelRouter::new(
                    entry.id.clone(),
                    Arc::clone(lifecycle),
                    None,
                ));

                let info = ActiveListenerInfo {
                    name: format!("dedicated-http-{}", entry.id),
                    address: bind_addr,
                    listener_type: ListenerType::Http,
                    is_shared: false,
                    tunnel_id: Some(entry.id.clone()),
                };

                let shutdown_rx = self.shutdown_tx.subscribe();
                let task = tokio::spawn(run_listener_loop(
                    listener,
                    router,
                    ListenerType::Http,
                    shutdown_rx,
                ));

                self.handles.lock().push(ListenerHandle {
                    info: info.clone(),
                    task,
                });
                started.push(info);
            }
        }

        Ok(started)
    }

    /// Start a single shared listener from [`SharedListenerSettings`].
    pub async fn start_shared_listener(
        &self,
        settings: &SharedListenerSettings,
        registry: &Arc<TunnelRegistry>,
        lifecycle: &Arc<LifecycleController>,
    ) -> Result<ActiveListenerInfo, CoreError> {
        let bind_addr = settings.bind;
        let listener = TcpListener::bind(bind_addr).await.map_err(|e| {
            CoreError::ListenerError(format!(
                "failed to bind shared listener on {}: {:?}",
                bind_addr, e
            ))
        })?;

        let router = MultiTenantRouter::from_settings(
            settings,
            Arc::clone(lifecycle),
            Arc::clone(registry),
        );

        let info = ActiveListenerInfo {
            name: settings.name.clone(),
            address: bind_addr,
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

    /// Gracefully stop and join all running listeners.
    pub async fn stop(&self) {
        let _ = self.shutdown_tx.send(true);
        let mut handles = {
            let mut guard = self.handles.lock();
            std::mem::take(&mut *guard)
        };

        for handle in handles.drain(..) {
            handle.task.abort();
            let _ = handle.task.await;
        }
    }
}

/// Core asynchronous accept loop for a TCP proxy listener.
async fn run_listener_loop(
    listener: TcpListener,
    router: Arc<dyn TunnelRouter>,
    listener_type: ListenerType,
    mut shutdown_rx: watch::Receiver<bool>,
) {
    loop {
        tokio::select! {
            biased;
            _ = shutdown_rx.changed() => {
                if *shutdown_rx.borrow() {
                    break;
                }
            }
            res = listener.accept() => {
                match res {
                    Ok((stream, _peer_addr)) => {
                        let r = Arc::clone(&router);
                        tokio::spawn(async move {
                            match listener_type {
                                ListenerType::Socks5 => {
                                    let _ = handle_socks5(stream, r).await;
                                }
                                ListenerType::Http => {
                                    let _ = handle_http(stream, r).await;
                                }
                            }
                        });
                    }
                    Err(e) => {
                        tracing::debug!("TCP listener accept stopped: {:?}", e);
                        break;
                    }
                }
            }
        }
    }
}
