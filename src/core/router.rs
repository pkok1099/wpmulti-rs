//! Multi-tenant routing and proxy connector bridging.
//!
//! Bridges [`crate::proxy::TunnelRouter`] requests from SOCKS5 and HTTP proxy listeners
//! to [`crate::core::TunnelManager`] and [`crate::core::LifecycleController`].
//! Supports ById, ByKeyword (`auto`, `random`, `round-robin`, `least-conn`), tag selection,
//! and unauthenticated pool defaults.

use std::future::Future;
use std::io;
use std::pin::Pin;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use parking_lot::RwLock;

use crate::config::{AuthMode, PoolStrategy, SharedListenerSettings, TunnelPoolSelection};
use crate::core::lifecycle::{GuardedTunnelTarget, LifecycleController};
use crate::core::registry::TunnelRegistry;
use crate::proxy::{
    PoolKeyword, ProxyAuthError, ProxyTunnelTarget, TunnelRouter, TunnelSelector,
};

/// Multi-tenant proxy router for shared listener ports.
pub struct MultiTenantRouter {
    lifecycle: Arc<LifecycleController>,
    registry: Arc<TunnelRegistry>,
    allowed_tunnels: RwLock<Option<Vec<String>>>,
    default_strategy: PoolStrategy,
    auth_mode: AuthMode,
    global_password: Option<String>,
    allow_anonymous: bool,
    rr_counter: AtomicUsize,
}

impl MultiTenantRouter {
    /// Create a new multi-tenant router from shared listener configuration.
    pub fn from_settings(
        settings: &SharedListenerSettings,
        lifecycle: Arc<LifecycleController>,
        registry: Arc<TunnelRegistry>,
    ) -> Arc<Self> {
        let allowed = match &settings.pool {
            TunnelPoolSelection::All => None,
            TunnelPoolSelection::Selected(list) => Some(list.clone()),
        };

        Arc::new(Self {
            lifecycle,
            registry,
            allowed_tunnels: RwLock::new(allowed),
            default_strategy: settings.default_strategy,
            auth_mode: settings.auth_mode,
            global_password: settings.global_password.clone(),
            allow_anonymous: settings.allow_anonymous,
            rr_counter: AtomicUsize::new(0),
        })
    }

    /// Construct a multi-tenant router with custom parameters.
    pub fn new(
        lifecycle: Arc<LifecycleController>,
        registry: Arc<TunnelRegistry>,
        default_strategy: PoolStrategy,
        allow_anonymous: bool,
    ) -> Arc<Self> {
        Arc::new(Self {
            lifecycle,
            registry,
            allowed_tunnels: RwLock::new(None),
            default_strategy,
            auth_mode: AuthMode::None,
            global_password: None,
            allow_anonymous,
            rr_counter: AtomicUsize::new(0),
        })
    }

    /// Configure authentication mode and global password.
    pub fn with_auth(
        self: Arc<Self>,
        auth_mode: AuthMode,
        global_password: Option<String>,
    ) -> Arc<Self> {
        let mut router = Arc::try_unwrap(self).unwrap_or_else(|a| (*a).clone_shallow());
        router.auth_mode = auth_mode;
        router.global_password = global_password;
        Arc::new(router)
    }

    /// Update the allowed tunnel pool IDs under lock.
    pub fn set_allowed_tunnels(&self, list: Option<Vec<String>>) {
        let mut allowed = self.allowed_tunnels.write();
        *allowed = list;
    }

    fn clone_shallow(&self) -> Self {
        Self {
            lifecycle: Arc::clone(&self.lifecycle),
            registry: Arc::clone(&self.registry),
            allowed_tunnels: RwLock::new(self.allowed_tunnels.read().clone()),
            default_strategy: self.default_strategy,
            auth_mode: self.auth_mode,
            global_password: self.global_password.clone(),
            allow_anonymous: self.allow_anonymous,
            rr_counter: AtomicUsize::new(self.rr_counter.load(Ordering::Relaxed)),
        }
    }

    /// Collect candidate tunnel IDs allowed for this pool.
    fn get_candidates(&self) -> Vec<String> {
        let allowed = self.allowed_tunnels.read().clone();
        if let Some(list) = allowed {
            list
        } else {
            self.registry.all_ids()
        }
    }

    /// Select a tunnel ID based on a pool keyword strategy.
    fn select_by_keyword(&self, keyword: PoolKeyword, candidates: &[String]) -> io::Result<String> {
        if candidates.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::NotConnected,
                "no available tunnels in pool",
            ));
        }

        match keyword {
            PoolKeyword::Random => {
                let idx = (rand::random::<u32>() as usize) % candidates.len();
                Ok(candidates[idx].clone())
            }
            PoolKeyword::RoundRobin | PoolKeyword::Auto => {
                let idx = self.rr_counter.fetch_add(1, Ordering::Relaxed) % candidates.len();
                Ok(candidates[idx].clone())
            }
            PoolKeyword::LeastConn => {
                self.select_least_conn(candidates)
            }
        }
    }

    /// Select a candidate tunnel with the lowest number of active connections.
    fn select_least_conn(&self, candidates: &[String]) -> io::Result<String> {
        let mut best_id = None;
        let mut min_conns = usize::MAX;

        for id in candidates {
            if let Some(entry) = self.registry.get(id) {
                let conns = entry.stats.active_conns.load(Ordering::Relaxed);
                if conns < min_conns {
                    min_conns = conns;
                    best_id = Some(id.clone());
                }
            }
        }

        best_id.ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::NotConnected,
                "no candidate tunnels found in registry",
            )
        })
    }

    /// Select a tunnel ID using the default pool strategy.
    fn select_default_pool(&self, candidates: &[String]) -> io::Result<String> {
        if candidates.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::NotConnected,
                "no available tunnels in default pool",
            ));
        }

        match self.default_strategy {
            PoolStrategy::RoundRobin | PoolStrategy::Fallback => {
                let idx = self.rr_counter.fetch_add(1, Ordering::Relaxed) % candidates.len();
                Ok(candidates[idx].clone())
            }
            PoolStrategy::Random => {
                let idx = (rand::random::<u32>() as usize) % candidates.len();
                Ok(candidates[idx].clone())
            }
            PoolStrategy::LeastConn => self.select_least_conn(candidates),
        }
    }
}

impl TunnelRouter for MultiTenantRouter {
    fn authenticate(
        &self,
        credentials: Option<(&str, &str)>,
    ) -> Result<TunnelSelector, ProxyAuthError> {
        match self.auth_mode {
            AuthMode::None => {
                if let Some((user, _pass)) = credentials {
                    Ok(TunnelSelector::parse(user))
                } else if self.allow_anonymous {
                    Ok(TunnelSelector::DefaultPool)
                } else {
                    Err(ProxyAuthError::AuthRequired)
                }
            }
            AuthMode::Global | AuthMode::PerTunnel => {
                match credentials {
                    None => {
                        if self.allow_anonymous {
                            Ok(TunnelSelector::DefaultPool)
                        } else {
                            Err(ProxyAuthError::AuthRequired)
                        }
                    }
                    Some((user, pass)) => {
                        if let Some(expected_pass) = &self.global_password {
                            if pass != expected_pass {
                                return Err(ProxyAuthError::InvalidCredentials);
                            }
                        }
                        Ok(TunnelSelector::parse(user))
                    }
                }
            }
        }
    }

    fn select_tunnel<'a>(
        &'a self,
        selector: &'a TunnelSelector,
    ) -> Pin<Box<dyn Future<Output = io::Result<Arc<dyn ProxyTunnelTarget>>> + Send + 'a>> {
        Box::pin(async move {
            let candidates = self.get_candidates();

            let target_id = match selector {
                TunnelSelector::ById(id) => {
                    // Check if tunnel ID is recognized and allowed
                    if !candidates.is_empty() && !candidates.contains(id) {
                        return Err(io::Error::new(
                            io::ErrorKind::NotFound,
                            format!("tunnel '{}' not allowed in this pool", id),
                        ));
                    }
                    if self.registry.get(id).is_none() {
                        return Err(io::Error::new(
                            io::ErrorKind::NotFound,
                            format!("tunnel '{}' not found in registry", id),
                        ));
                    }
                    id.clone()
                }
                TunnelSelector::ByKeyword(keyword) => {
                    self.select_by_keyword(*keyword, &candidates)?
                }
                TunnelSelector::ByTag(tag) => {
                    // Match prefix or substring among candidates
                    let matched = candidates
                        .iter()
                        .find(|id| id.contains(tag))
                        .cloned();

                    matched.ok_or_else(|| {
                        io::Error::new(
                            io::ErrorKind::NotFound,
                            format!("no tunnel found matching tag '{}'", tag),
                        )
                    })?
                }
                TunnelSelector::DefaultPool => {
                    self.select_default_pool(&candidates)?
                }
            };

            // Dynamically activate or resume on demand with RAII connection guard
            let (active_tunnel, guard) = self
                .lifecycle
                .get_or_activate(&target_id)
                .await
                .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("tunnel activation failed: {:?}", e)))?;

            let guarded = GuardedTunnelTarget::new(active_tunnel, guard);
            Ok(Arc::new(guarded) as Arc<dyn ProxyTunnelTarget>)
        })
    }
}

/// Dedicated router for per-tunnel ports forwarding all connections directly to a single tunnel.
pub struct DedicatedTunnelRouter {
    tunnel_id: String,
    lifecycle: Arc<LifecycleController>,
    auth: Option<(String, String)>,
}

impl DedicatedTunnelRouter {
    /// Construct a new dedicated router for a single tunnel.
    pub fn new(
        tunnel_id: impl Into<String>,
        lifecycle: Arc<LifecycleController>,
        auth: Option<(String, String)>,
    ) -> Self {
        Self {
            tunnel_id: tunnel_id.into(),
            lifecycle,
            auth,
        }
    }
}

impl TunnelRouter for DedicatedTunnelRouter {
    fn authenticate(
        &self,
        credentials: Option<(&str, &str)>,
    ) -> Result<TunnelSelector, ProxyAuthError> {
        if let Some((expected_user, expected_pass)) = &self.auth {
            match credentials {
                Some((u, p)) if u == expected_user && p == expected_pass => {
                    Ok(TunnelSelector::ById(self.tunnel_id.clone()))
                }
                Some(_) => Err(ProxyAuthError::InvalidCredentials),
                None => Err(ProxyAuthError::AuthRequired),
            }
        } else {
            Ok(TunnelSelector::ById(self.tunnel_id.clone()))
        }
    }

    fn select_tunnel<'a>(
        &'a self,
        _selector: &'a TunnelSelector,
    ) -> Pin<Box<dyn Future<Output = io::Result<Arc<dyn ProxyTunnelTarget>>> + Send + 'a>> {
        Box::pin(async move {
            let (active, guard) = self
                .lifecycle
                .get_or_activate(&self.tunnel_id)
                .await
                .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("tunnel activation failed: {:?}", e)))?;

            let guarded = GuardedTunnelTarget::new(active, guard);
            Ok(Arc::new(guarded) as Arc<dyn ProxyTunnelTarget>)
        })
    }
}
