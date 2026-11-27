//! Multi-tenant routing and proxy connector bridging.
//!
//! Bridges [`crate::proxy::TunnelRouter`] requests from SOCKS5 and HTTP proxy listeners
//! to [`crate::core::TunnelManager`] and [`crate::core::LifecycleController`].
//! Supports ById, ByKeyword (`auto`, `random`, `round-robin`, `least-conn`), tag selection,
//! and unauthenticated pool defaults.

use std::fmt::Write as _;
use std::future::Future;
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use parking_lot::RwLock;

use crate::config::{AuthMode, IpMode, PoolStrategy, SharedListenerSettings, TunnelPoolSelection};
use crate::core::health::HealthStatus;
use crate::core::lifecycle::{GuardedTunnelTarget, LifecycleController, handshake_is_fresh};
use crate::core::registry::{TunnelEntry, TunnelRegistry};
use crate::core::selection::{WarmList, dormant_jitter_ms, score_entry};
use crate::proxy::router::{AuthChecker, constant_time_eq_str};
use crate::proxy::{
    DynStream, PoolKeyword, ProxyAuthError, ProxyTunnelTarget, ProxyUdpSocket, TunnelRouter,
    TunnelSelector,
};

/// Random draws spent looking for one routable second candidate
/// before the stratified pick falls back to a tiered scan. Twelve
/// draws miss a 50%-healthy pool with probability 0.5^12; a sparser
/// pool falls back to the scan, which is the correct behaviour when
/// almost nothing is routable.
const P2C_DRAWS: usize = 12;

/// Multi-tenant proxy router for shared listener ports.
#[derive(Debug)]
pub struct MultiTenantRouter {
    lifecycle: Arc<LifecycleController>,
    registry: Arc<TunnelRegistry>,
    allowed_tunnels: RwLock<Option<Arc<[String]>>>,
    default_strategy: PoolStrategy,
    auth_mode: AuthMode,
    global_password: Option<String>,
    per_tunnel_passwords: RwLock<std::collections::HashMap<String, String>>,
    allow_anonymous: bool,
    listener_ip_mode: Option<IpMode>,
    rr_counter: AtomicUsize,
    health_override: Option<(usize, Duration)>,
    /// Bounded warm list (see [`WarmList`]): the fast path samples
    /// one candidate from here instead of scanning the pool.
    warm_list: Arc<WarmList>,
}

impl MultiTenantRouter {
    /// Create a new multi-tenant router from shared listener configuration.
    ///
    /// Tracks `lifecycle.health_check()` and `lifecycle.ip_mode()` dynamically for live updates.
    pub fn from_settings(
        settings: &SharedListenerSettings,
        lifecycle: Arc<LifecycleController>,
        registry: Arc<TunnelRegistry>,
    ) -> Arc<Self> {
        let allowed: Option<Arc<[String]>> = match &settings.pool {
            TunnelPoolSelection::All => None,
            TunnelPoolSelection::Selected(list) => Some(list.as_slice().into()),
        };

        Arc::new(Self {
            lifecycle,
            registry,
            allowed_tunnels: RwLock::new(allowed),
            default_strategy: settings.default_strategy,
            auth_mode: settings.auth_mode,
            global_password: settings.global_password.clone(),
            per_tunnel_passwords: RwLock::new(std::collections::HashMap::new()),
            allow_anonymous: settings.allow_anonymous,
            listener_ip_mode: settings.ip_mode,
            rr_counter: AtomicUsize::new(0),
            health_override: None,
            warm_list: Arc::new(WarmList::new()),
        })
    }

    /// Create a new multi-tenant router from shared listener configuration with explicit health parameters.
    pub fn from_settings_with_health(
        settings: &SharedListenerSettings,
        lifecycle: Arc<LifecycleController>,
        registry: Arc<TunnelRegistry>,
        failure_threshold: usize,
        cooldown_duration: Duration,
    ) -> Arc<Self> {
        Self::from_settings(settings, lifecycle, registry)
            .with_health_settings(failure_threshold, cooldown_duration)
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
            per_tunnel_passwords: RwLock::new(std::collections::HashMap::new()),
            allow_anonymous,
            listener_ip_mode: None,
            rr_counter: AtomicUsize::new(0),
            health_override: None,
            warm_list: Arc::new(WarmList::new()),
        })
    }

    /// Configure explicit static health check parameters overriding [`LifecycleController`].
    pub fn with_health_settings(
        self: Arc<Self>,
        failure_threshold: usize,
        cooldown_duration: Duration,
    ) -> Arc<Self> {
        let mut router = Arc::try_unwrap(self).unwrap_or_else(|a| (*a).clone_shallow());
        router.health_override = Some((failure_threshold, cooldown_duration));
        Arc::new(router)
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

    /// Configure per-tunnel override passwords used when `AuthMode::PerTunnel` is active.
    pub fn with_per_tunnel_passwords(
        self: Arc<Self>,
        passwords: std::collections::HashMap<String, String>,
    ) -> Arc<Self> {
        *self.per_tunnel_passwords.write() = passwords;
        self
    }

    /// Update per-tunnel override passwords under lock.
    pub fn set_per_tunnel_passwords(&self, passwords: std::collections::HashMap<String, String>) {
        *self.per_tunnel_passwords.write() = passwords;
    }

    /// Update the allowed tunnel pool IDs under lock.
    pub fn set_allowed_tunnels(&self, list: Option<Vec<String>>) {
        let mut allowed = self.allowed_tunnels.write();
        *allowed = list.map(|l| l.into_boxed_slice().into());
    }

    /// Verify `credentials` against the password of the tunnel the
    /// selector resolved to. Only enforced in [`AuthMode::PerTunnel`]:
    /// the tunnel's own override password when one is set, else the
    /// global password when one is set, else the anonymous rule — the
    /// same rule `AuthChecker::authenticate` applies to a `ById`
    /// selector, so a tag/keyword/default-pool selector cannot smuggle
    /// the global password into a password-protected tunnel (audit
    /// run-1, `proxy.auth.per-tunnel-password-bypass-via-tag-selector`).
    /// One exception to the anonymous rule: a tunnel with its own
    /// override password never admits a client presenting no
    /// credentials at all, even when `allow_anonymous` is set (audit
    /// run-1, `proxy.auth.anonymous-bypass-per-tunnel-password-via-default-pool`).
    /// Only that tunnel's own password is accepted for it; the
    /// documented anonymous passthrough survives only for tunnels
    /// protected by the global password alone.
    fn verify_chosen_tunnel_password(
        &self,
        tunnel_id: &str,
        credentials: Option<(&str, &str)>,
    ) -> Result<(), ProxyAuthError> {
        if self.auth_mode != AuthMode::PerTunnel {
            return Ok(());
        }
        let per_tunnel = self.per_tunnel_passwords.read().get(tunnel_id).cloned();
        let expected = per_tunnel.clone().or_else(|| self.global_password.clone());
        match (expected, credentials) {
            (Some(expected), Some((_, pass))) if constant_time_eq_str(pass, &expected) => Ok(()),
            (Some(_), Some(_)) => Err(ProxyAuthError::InvalidCredentials),
            (None, Some(_)) => {
                if self.allow_anonymous {
                    Ok(())
                } else {
                    // A password was presented but none is configured
                    // for this tunnel and anonymous access is off, so
                    // there is nothing it could have matched.
                    Err(ProxyAuthError::InvalidCredentials)
                }
            }
            // No credentials for a tunnel with its own override
            // password: the anonymous rule must not open it — the
            // override password is the only key to that tunnel.
            (Some(_), None) if per_tunnel.is_some() => Err(ProxyAuthError::AuthRequired),
            (_, None) => {
                if self.allow_anonymous {
                    Ok(())
                } else {
                    Err(ProxyAuthError::AuthRequired)
                }
            }
        }
    }

    fn effective_ip_mode(&self) -> io::Result<IpMode> {
        IpMode::effective_with_global(self.listener_ip_mode, self.lifecycle.ip_mode())
            .map_err(|msg| io::Error::new(io::ErrorKind::PermissionDenied, msg))
    }

    fn effective_health(&self) -> (usize, Duration) {
        self.health_override
            .unwrap_or_else(|| self.lifecycle.health_check())
    }

    fn clone_shallow(&self) -> Self {
        Self {
            lifecycle: Arc::clone(&self.lifecycle),
            registry: Arc::clone(&self.registry),
            allowed_tunnels: RwLock::new(self.allowed_tunnels.read().clone()),
            default_strategy: self.default_strategy,
            auth_mode: self.auth_mode,
            global_password: self.global_password.clone(),
            per_tunnel_passwords: RwLock::new(self.per_tunnel_passwords.read().clone()),
            allow_anonymous: self.allow_anonymous,
            listener_ip_mode: self.listener_ip_mode,
            rr_counter: AtomicUsize::new(self.rr_counter.load(Ordering::Relaxed)),
            health_override: self.health_override,
            warm_list: Arc::clone(&self.warm_list),
        }
    }

    /// Collect candidate tunnel IDs allowed for this pool.
    pub fn get_candidates(&self) -> Vec<String> {
        let allowed = self.allowed_tunnels.read().clone();
        allowed.map_or_else(|| self.registry.all_ids(), |list| list.to_vec())
    }

    /// Filter candidates to only those whose health status is routable,
    /// preferring live tunnels first: a tunnel that just proved itself
    /// by moving real traffic has a live WireGuard session, so the next
    /// packet flows without paying a fresh activation + handshake inside
    /// the caller's failover budget. Only fall back to proven tunnels
    /// (handshaked at some point) and then to unproven ones when no live
    /// tunnel is routable, so a fresh daemon whose tunnels have not
    /// handshaked yet can still bring them up through real traffic.
    /// Within the best tier, tunnels at the per-tunnel connection cap
    /// ([`MAX_LIVE_TUNNEL_CONNS`]) are skipped in favor of the next
    /// tier, so load spreads instead of piling onto a few live tunnels.
    pub fn filter_healthy_candidates<'a>(&self, candidates: &'a [String]) -> Vec<&'a String> {
        let now_secs = now_unix_secs();
        let mut live: Vec<&'a String> = Vec::new();
        let mut proven: Vec<&'a String> = Vec::new();
        let mut unproven: Vec<&'a String> = Vec::new();
        for id in candidates {
            if let Some(entry) = self.registry.get(id)
                && !entry.is_disabled()
                && entry.health.can_route()
            {
                match selection_tier(&entry, now_secs) {
                    SelectionTier::Live => live.push(id),
                    SelectionTier::Proven => proven.push(id),
                    SelectionTier::Unproven => unproven.push(id),
                }
            }
        }
        pick_tier(live, proven, unproven, |id| {
            self.registry.get(id).map_or(usize::MAX, |entry| {
                entry.stats.active_conns.load(Ordering::Relaxed)
            })
        })
    }

    fn try_claim_candidate(&self, id: &str) -> bool {
        self.registry
            .get(id)
            .is_some_and(|entry| !entry.is_disabled() && entry.health.is_routable())
    }

    /// Release a `HalfOpen` trial slot claimed during selection (e.g.
    /// the P2C loser): a no-op unless the tunnel is `HalfOpen` with a
    /// slot in flight.
    fn release_trial(&self, id: &str) {
        if let Some(entry) = self.registry.get(id) {
            entry.health.release_trial_slot();
        }
    }

    fn claim_from_healthy(&self, healthy: &[&String], start_idx: usize) -> io::Result<String> {
        if healthy.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::NotConnected,
                "no healthy tunnels available in pool",
            ));
        }
        for offset in 0..healthy.len() {
            let idx = (start_idx + offset) % healthy.len();
            if let Some(&id) = healthy.get(idx)
                && self.try_claim_candidate(id)
            {
                return Ok(id.clone());
            }
        }
        Err(io::Error::new(
            io::ErrorKind::NotConnected,
            "no healthy tunnels available in pool",
        ))
    }

    /// Select a tunnel ID from slice based on keyword without cloning candidate lists.
    ///
    /// `Auto` is the adaptive selector (stratified P2C over the
    /// Peak-EWMA score); the explicit keywords keep their historic
    /// meanings. The P2C path returns before the tiered scan, so the
    /// fast path never filters the whole candidate list.
    fn select_by_keyword_slice(
        &self,
        keyword: PoolKeyword,
        candidates: &[String],
    ) -> io::Result<String> {
        if keyword == PoolKeyword::Auto {
            return self.select_p2c(Some(candidates));
        }
        let healthy = self.filter_healthy_candidates(candidates);
        if healthy.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::NotConnected,
                "no healthy tunnels available in pool",
            ));
        }

        match keyword {
            PoolKeyword::Random => {
                let idx = (rand::random::<u32>() as usize) % healthy.len();
                self.claim_from_healthy(&healthy, idx)
            }
            PoolKeyword::RoundRobin => {
                let idx = self.rr_counter.fetch_add(1, Ordering::Relaxed) % healthy.len();
                self.claim_from_healthy(&healthy, idx)
            }
            PoolKeyword::LeastConn => self.select_least_conn_refs(&healthy),
            // Handled by the early return above; kept for exhaustiveness.
            PoolKeyword::Auto => self.select_p2c(Some(candidates)),
        }
    }

    fn select_least_conn_registry(&self, entries: &[Arc<TunnelEntry>]) -> Option<String> {
        let pool = preferred_entries(entries);
        if pool.is_empty() {
            return None;
        }
        let mut candidates: Vec<(usize, &str)> = pool
            .iter()
            .map(|e| (e.stats.active_conns.load(Ordering::Relaxed), e.id.as_str()))
            .collect();
        candidates.sort_by_key(|(conns, _)| *conns);
        candidates
            .into_iter()
            .find_map(|(_, id)| self.try_claim_candidate(id).then(|| id.to_string()))
    }

    fn select_rr_or_random_registry(
        &self,
        entries: &[Arc<TunnelEntry>],
        is_random: bool,
    ) -> Option<String> {
        let pool = preferred_entries(entries);
        if pool.is_empty() {
            return None;
        }
        let start_idx = if is_random {
            (rand::random::<u32>() as usize) % pool.len()
        } else {
            self.rr_counter.fetch_add(1, Ordering::Relaxed) % pool.len()
        };
        for offset in 0..pool.len() {
            let idx = (start_idx + offset) % pool.len();
            if let Some(entry) = pool.get(idx)
                && !entry.is_disabled()
                && entry.health.is_routable()
            {
                return Some(entry.id.clone());
            }
        }
        None
    }

    /// Select a tunnel ID directly from the registry without candidate vector or HashMap lookups.
    fn select_by_keyword_registry(&self, keyword: PoolKeyword) -> io::Result<String> {
        if keyword == PoolKeyword::Auto {
            return self.select_p2c(None);
        }
        let entries = self.registry.all_entries();
        if entries.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::NotConnected,
                "no healthy tunnels available in pool",
            ));
        }

        let selected = match keyword {
            PoolKeyword::LeastConn => self.select_least_conn_registry(&entries),
            PoolKeyword::Random => self.select_rr_or_random_registry(&entries, true),
            PoolKeyword::RoundRobin | PoolKeyword::Auto => {
                self.select_rr_or_random_registry(&entries, false)
            }
        };

        selected.ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::NotConnected,
                "no healthy tunnels available in pool",
            )
        })
    }

    /// Select a candidate tunnel with lowest active connections among healthy candidates.
    fn select_least_conn_refs(&self, healthy: &[&String]) -> io::Result<String> {
        let mut ranked: Vec<(usize, &String)> = healthy
            .iter()
            .filter_map(|&id| {
                self.registry
                    .get(id)
                    .map(|entry| (entry.stats.active_conns.load(Ordering::Relaxed), id))
            })
            .collect();
        ranked.sort_by_key(|(conns, _)| *conns);

        for (_, id) in ranked {
            if self.try_claim_candidate(id) {
                return Ok(id.clone());
            }
        }

        Err(io::Error::new(
            io::ErrorKind::NotConnected,
            "no healthy tunnels available in pool",
        ))
    }

    /// Record that `id` proved itself by moving real traffic, seeding
    /// the warm list. Tests use it to seed the list deterministically.
    #[cfg(test)]
    pub(crate) fn note_warm_success(&self, id: &str) {
        self.warm_list.note_success(id);
    }

    /// Stratified Power-of-Two-Choices selection over the Peak-EWMA
    /// score ([`score_entry`]).
    ///
    /// Candidate A is drawn O(1) from the warm list; candidate B is
    /// drawn uniformly from the whole pool (or `allowed`, when a pool
    /// restriction applies), retried until a routable tunnel distinct
    /// from A turns up. The lower score wins. Ejected, disabled, and
    /// unhealthy tunnels never enter either draw
    /// ([`Self::try_claim_candidate`]).
    ///
    /// When both draws come up empty the pool is so unhealthy that
    /// scoring order hardly matters, so selection falls back to the
    /// tiered scan — the only full-pool scan on this path, and only
    /// in that degraded case. It preserves the old "no healthy
    /// tunnels" error instead of inventing a new one.
    pub(crate) fn select_p2c(&self, allowed: Option<&[String]>) -> io::Result<String> {
        let now_secs = now_unix_secs();
        let best: Option<(f64, String)> = if let Some(id) = self.warm_list.pick()
            && self.try_claim_candidate(&id)
        {
            Some((self.score_of(&id, now_secs), id))
        } else {
            None
        };
        let mut second: Option<(f64, String)> = None;
        for _ in 0..P2C_DRAWS {
            let Some(id) = self.draw_random_id(allowed) else {
                break;
            };
            if best.as_ref().is_some_and(|(_, best_id)| best_id == &id) {
                continue;
            }
            if !self.try_claim_candidate(&id) {
                continue;
            }
            second = Some((self.score_of(&id, now_secs), id));
            break;
        }
        match (best, second) {
            (Some((a_score, a)), Some((b_score, b))) => {
                // The loser claimed a `HalfOpen` trial slot in
                // `try_claim_candidate` but will never be used: release
                // it here, or it stays unroutable — and skipped by the
                // prober — with no timeout (audit run-3 #3). The winner
                // keeps its slot for the caller, as before.
                if b_score < a_score {
                    self.release_trial(&a);
                    Ok(b)
                } else {
                    self.release_trial(&b);
                    Ok(a)
                }
            }
            (Some((_, a)), None) | (None, Some((_, a))) => Ok(a),
            (None, None) => self.fallback_scan_select(allowed),
        }
    }

    /// Degraded-pool fallback for [`Self::select_p2c`]: tiered scan
    /// over the allowed candidates, claiming the first routable one.
    fn fallback_scan_select(&self, allowed: Option<&[String]>) -> io::Result<String> {
        let candidates: Vec<String> =
            allowed.map_or_else(|| self.registry.all_ids(), ToOwned::to_owned);
        let healthy = self.filter_healthy_candidates(&candidates);
        self.claim_from_healthy(&healthy, 0)
    }

    /// Peak-EWMA selection score for one tunnel, or `f64::MAX` when
    /// the entry vanished between the routability check and scoring
    /// (so it sorts last instead of failing selection).
    fn score_of(&self, id: &str, now_secs: u64) -> f64 {
        self.registry.get(id).map_or(f64::MAX, |entry| {
            score_entry(&entry, now_secs, dormant_jitter_ms())
        })
    }

    /// Draw one tunnel ID uniformly at random: from `allowed` when a
    /// pool restriction applies, else by registry index (O(1), no
    /// ID-list allocation). Returns `None` for an empty pool.
    fn draw_random_id(&self, allowed: Option<&[String]>) -> Option<String> {
        if let Some(list) = allowed {
            if list.is_empty() {
                return None;
            }
            let idx = rand::random::<u32>() as usize % list.len();
            return list.get(idx).cloned();
        }
        let count = self.registry.count();
        if count == 0 {
            return None;
        }
        self.registry
            .id_by_index(rand::random::<u32>() as usize % count)
    }

    /// Select a tunnel ID using default pool strategy from slice.
    ///
    /// `Fallback` keeps its priority meaning (first routable
    /// candidate in sequence). Every other configured default
    /// strategy routes through the adaptive P2C selector: the
    /// unnamed default pool is where the measured budget failures
    /// happen, so it gets the latency-aware selector, while the
    /// explicit `round-robin` / `random` / `least-conn` keywords
    /// still offer the historic strategies on demand.
    fn select_default_pool_slice(&self, candidates: &[String]) -> io::Result<String> {
        if candidates.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::NotConnected,
                "no available tunnels in default pool",
            ));
        }

        match self.default_strategy {
            PoolStrategy::Fallback => {
                // True priority fallback: select first routable candidate in sequence
                for id in candidates {
                    if self.try_claim_candidate(id) {
                        return Ok(id.clone());
                    }
                }
                Err(io::Error::new(
                    io::ErrorKind::NotConnected,
                    "all tunnels in fallback pool are unhealthy",
                ))
            }
            PoolStrategy::RoundRobin | PoolStrategy::Random | PoolStrategy::LeastConn => {
                self.select_p2c(Some(candidates))
            }
        }
    }

    /// Select a tunnel ID using default pool strategy from registry directly.
    fn select_default_pool_registry(&self) -> io::Result<String> {
        if self.default_strategy == PoolStrategy::Fallback {
            let candidates = self.registry.all_ids();
            self.select_default_pool_slice(&candidates)
        } else {
            self.select_p2c(None)
        }
    }
}

/// Preference tier of a routable tunnel for pool selection, best first.
///
/// A tunnel that just proved itself by moving real traffic has a live
/// WireGuard session, so the next packet flows without paying a fresh
/// activation + handshake inside the caller's failover budget. Tunnels
/// below the live tier need a re-boot and possibly a fresh handshake —
/// and a first handshake on a fresh device frequently goes unanswered
/// within the budget — so they are only picked when no live tunnel
/// exists.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SelectionTier {
    /// Currently active, Healthy, and handshaked within the freshness
    /// window: a live session.
    Live,
    /// Completed a handshake at some point (possibly dormant or
    /// stale): proven before, but needs a re-boot and possibly a
    /// fresh handshake.
    Proven,
    /// Never completed a handshake: unproven, may be unreachable.
    Unproven,
}

/// Classify a routable tunnel into a pool-selection preference tier.
///
/// The live tier needs all three signals at once. A fresh handshake
/// alone is not enough: an in-tunnel DNS resolve records one even
/// when the answer came from the shared cache without any packet
/// crossing the tunnel. Healthy alone is not enough either: it
/// persists until failures trip the breaker, while the session may
/// have gone stale since the last success. Active alone proves even
/// less: a freshly booted device has no session yet.
pub(crate) fn selection_tier(entry: &TunnelEntry, now_secs: u64) -> SelectionTier {
    let fresh_handshake =
        handshake_is_fresh(entry.stats.last_handshake.load(Ordering::Relaxed), now_secs);
    if entry.is_active()
        && fresh_handshake
        && entry.health.current_status() == HealthStatus::Healthy
    {
        SelectionTier::Live
    } else if entry.has_handshaked() {
        SelectionTier::Proven
    } else {
        SelectionTier::Unproven
    }
}

/// Current Unix time in seconds, for handshake-freshness checks.
fn now_unix_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

/// Maximum concurrent connections a single tunnel carries before pool
/// selection spills over to the next preference tier.
///
/// Measured live (2000 requests, concurrency 32): with all traffic
/// concentrated on 2 live tunnels (~16 connections each), ~1% of
/// requests died right after the SOCKS grant with an empty reply; with
/// the same load spread over ~32 active tunnels (~1-2 each), the same
/// failure mode was 0.15%. The cap bounds per-tunnel load at half the
/// observed failure point and lets the live set grow — spilled
/// requests activate proven tunnels, which then join the live tier —
/// until the cap no longer binds. It is a preference, never a hard
/// limit: when every tunnel is at the cap, selection falls back to
/// the best tier instead of failing.
pub(crate) const MAX_LIVE_TUNNEL_CONNS: usize = 8;

/// Pick the tier to draw pool selection from: the best tier (live,
/// proven, unproven, in that order) that still has a tunnel under
/// [`MAX_LIVE_TUNNEL_CONNS`]; the best non-empty tier when every tier
/// is fully capped, so the cap never blocks selection outright.
/// `conns_of` reads a tunnel's current active-connection count.
fn pick_tier<T: Clone>(
    live: Vec<T>,
    proven: Vec<T>,
    unproven: Vec<T>,
    conns_of: impl Fn(&T) -> usize,
) -> Vec<T> {
    let fallback = if !live.is_empty() {
        live.clone()
    } else if !proven.is_empty() {
        proven.clone()
    } else {
        unproven.clone()
    };
    for tier in [live, proven, unproven] {
        if tier.is_empty() {
            continue;
        }
        let under_cap: Vec<T> = tier
            .into_iter()
            .filter(|entry| conns_of(entry) < MAX_LIVE_TUNNEL_CONNS)
            .collect();
        if !under_cap.is_empty() {
            return under_cap;
        }
    }
    fallback
}

/// Routable entries in preference order: live tunnels first, then
/// proven, then unproven. Returns an empty vec when nothing is
/// routable. Callers pick within the first non-empty tier, so a
/// fresh pool (no live or proven tunnel yet) still routes through
/// real traffic — which is how tunnels prove themselves and become
/// live in the first place.
///
/// `pub(crate)` so the tier selection can be unit-tested directly.
pub(crate) fn preferred_entries(entries: &[Arc<TunnelEntry>]) -> Vec<&Arc<TunnelEntry>> {
    let now_secs = now_unix_secs();
    let mut live = Vec::new();
    let mut proven = Vec::new();
    let mut unproven = Vec::new();
    for entry in entries {
        if entry.is_disabled() || !entry.health.can_route() {
            continue;
        }
        match selection_tier(entry, now_secs) {
            SelectionTier::Live => live.push(entry),
            SelectionTier::Proven => proven.push(entry),
            SelectionTier::Unproven => unproven.push(entry),
        }
    }
    pick_tier(live, proven, unproven, |entry| {
        entry.stats.active_conns.load(Ordering::Relaxed)
    })
}

/// Escape newline and control characters in a client-supplied value
/// before it is interpolated into an error message (audit run-1,
/// `proxy.log-injection.unescaped-selector-error-to-stderr-tracing`):
/// the tracing formatter passes interior `\n`/`\r` through verbatim,
/// so a raw selector could forge log lines in stderr and the TUI log
/// buffer. ESC bytes need no handling here: tracing-subscriber escapes
/// them by default (`ansi_sanitization`).
pub(crate) fn escape_log_value(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for c in value.chars() {
        match c {
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            c if c.is_control() => {
                let _ = write!(out, "\\u{{{:x}}}", c as u32);
            }
            c => out.push(c),
        }
    }
    out
}

fn resolve_selector(
    router: &MultiTenantRouter,
    selector: &TunnelSelector,
    allowed_guard: Option<&[String]>,
) -> io::Result<String> {
    match selector {
        TunnelSelector::ById(id) => {
            if let Some(allowed) = allowed_guard
                && !allowed.iter().any(|s| s == id)
            {
                return Err(io::Error::new(
                    io::ErrorKind::NotFound,
                    format!("tunnel '{}' not allowed in this pool", escape_log_value(id)),
                ));
            }
            if router.registry.get(id).is_none() {
                return Err(io::Error::new(
                    io::ErrorKind::NotFound,
                    format!("tunnel '{}' not found in registry", escape_log_value(id)),
                ));
            }
            Ok(id.clone())
        }
        TunnelSelector::ByKeyword(keyword) => allowed_guard.map_or_else(
            || router.select_by_keyword_registry(*keyword),
            |allowed| router.select_by_keyword_slice(*keyword, allowed),
        ),
        TunnelSelector::ByTag(tag) => {
            let matched = allowed_guard.map_or_else(
                || {
                    router
                        .registry
                        .all_entries()
                        .into_iter()
                        .find(|e| e.id.contains(tag) && !e.is_disabled() && e.health.is_routable())
                        .map(|e| e.id.clone())
                },
                |allowed| {
                    allowed
                        .iter()
                        .find(|id| id.contains(tag) && router.try_claim_candidate(id))
                        .cloned()
                },
            );
            matched.ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::NotFound,
                    format!(
                        "no healthy tunnel found matching tag '{}'",
                        escape_log_value(tag)
                    ),
                )
            })
        }
        TunnelSelector::DefaultPool => allowed_guard.map_or_else(
            || router.select_default_pool_registry(),
            |allowed| router.select_default_pool_slice(allowed),
        ),
    }
}

impl TunnelRouter for MultiTenantRouter {
    fn authenticate(
        &self,
        credentials: Option<(&str, &str)>,
    ) -> Result<TunnelSelector, ProxyAuthError> {
        AuthChecker {
            auth_mode: self.auth_mode,
            global_password: &self.global_password,
            per_tunnel_passwords: &self.per_tunnel_passwords,
            allow_anonymous: self.allow_anonymous,
            // Without credentials under `AuthMode::None`, anonymous access
            // must be enabled; otherwise auth is required.
            none_without_credentials_ok: false,
        }
        .authenticate(credentials)
    }

    fn select_tunnel<'a>(
        &'a self,
        selector: &'a TunnelSelector,
        credentials: Option<(&'a str, &'a str)>,
    ) -> Pin<Box<dyn Future<Output = io::Result<Arc<dyn ProxyTunnelTarget>>> + Send + 'a>> {
        Box::pin(async move {
            let allowed_guard = self.allowed_tunnels.read().clone();

            let max_attempts = match selector {
                TunnelSelector::ByKeyword(_) | TunnelSelector::DefaultPool => 3,
                TunnelSelector::ById(_) | TunnelSelector::ByTag(_) => 1,
            };

            let mut last_err = None;
            let mut chosen = None;
            let mut failed_ids: Vec<String> = Vec::new();

            for attempt in 0..max_attempts {
                let candidate_override: Option<Vec<String>> = if failed_ids.is_empty() {
                    None
                } else {
                    let base: Vec<String> = allowed_guard
                        .as_deref()
                        .map_or_else(|| self.registry.all_ids(), ToOwned::to_owned);
                    let remaining: Vec<String> = base
                        .into_iter()
                        .filter(|id| !failed_ids.contains(id))
                        .collect();
                    if remaining.is_empty() {
                        break;
                    }
                    Some(remaining)
                };
                let effective_allowed = candidate_override.as_deref().or(allowed_guard.as_deref());
                let target_id = resolve_selector(self, selector, effective_allowed)?;

                // Enforce the resolved tunnel's password before activating
                // it: in PerTunnel mode a tag/keyword/default-pool selector
                // must not open a password-protected tunnel with the global
                // password (audit run-1,
                // `proxy.auth.per-tunnel-password-bypass-via-tag-selector`).
                // `authenticate` accepted the credentials only
                // provisionally; this is the authoritative check, and a
                // failure here is terminal — failing over to another tunnel
                // with the same credentials would route the client to a
                // tunnel it did not select. The error names no tunnel id,
                // so a keyword selector cannot leak which tunnel was picked.
                if self
                    .verify_chosen_tunnel_password(&target_id, credentials)
                    .is_err()
                {
                    // The trial slot was claimed during selection
                    // (`resolve_selector`); this path returns before any
                    // `GuardedTunnelTarget` exists, so release the slot
                    // here or the HalfOpen tunnel stays unroutable until
                    // a probe or restart (audit run-1,
                    // `lifecycle.halfopen-trial-slot-leak-on-password-verify`).
                    // `ById` never claims a slot, so it releases none —
                    // same guard as the activation-failure branch below.
                    if !matches!(selector, TunnelSelector::ById(_))
                        && let Some(entry) = self.registry.get(&target_id)
                    {
                        entry.health.release_trial_slot();
                    }
                    return Err(io::Error::new(
                        io::ErrorKind::PermissionDenied,
                        "invalid proxy credentials for the selected tunnel",
                    ));
                }

                match self.lifecycle.get_or_activate(&target_id).await {
                    Ok((active_tunnel, guard)) => {
                        chosen = Some((target_id, active_tunnel, guard));
                        break;
                    }
                    Err(e) => {
                        if !matches!(selector, TunnelSelector::ById(_))
                            && let Some(entry) = self.registry.get(&target_id)
                        {
                            entry.health.release_trial_slot();
                        }
                        tracing::warn!(
                            "Tunnel '{}' activation failed (attempt {}/{}): {:?}",
                            target_id,
                            attempt + 1,
                            max_attempts,
                            e
                        );
                        failed_ids.push(target_id);
                        last_err =
                            Some(io::Error::other(format!("tunnel activation failed: {e:?}")));
                        if attempt + 1 < max_attempts {
                            let backoff_ms = 100u64 << attempt; // 100ms, 200ms
                            tokio::time::sleep(Duration::from_millis(backoff_ms)).await;
                        }
                    }
                }
            }

            let Some((target_id, active_tunnel, guard)) = chosen else {
                return Err(last_err.unwrap_or_else(|| {
                    io::Error::other("tunnel activation failed after retries")
                }));
            };

            let entry = self.registry.get(&target_id);
            let health = entry.as_ref().map(|e| Arc::clone(&e.health));

            let mut guarded = if let Some(h) = health {
                let (threshold, cooldown) = self.effective_health();
                GuardedTunnelTarget::new_with_health(active_tunnel, guard, h, threshold, cooldown)
            } else {
                GuardedTunnelTarget::new(active_tunnel, guard)
            };
            guarded.set_warm_list(Arc::clone(&self.warm_list));
            // A tunnel that is live right now joins the warm list at
            // once, so the next selection can draw it O(1) instead of
            // waiting for a dial to prove it again.
            if guarded.is_live() {
                self.warm_list.note_success(&target_id);
            }

            let ip_mode = self.effective_ip_mode()?;
            let target: Arc<dyn ProxyTunnelTarget> = if ip_mode == IpMode::DualStack {
                Arc::new(guarded)
            } else {
                Arc::new(IpFilteredTunnelTarget::new(Arc::new(guarded), ip_mode))
            };
            Ok(target)
        })
    }

    fn record_tunnel_blackhole(&self, tunnel_id: &str) {
        // A request went out on this tunnel and nothing came back:
        // charge the failure to the tunnel, not the target. The
        // breaker (threshold 3 by default) ejects a tunnel that
        // blackholes repeatedly, the EWMA penalty makes the
        // selector prefer slower-scoring tunnels immediately, and
        // the warm list drops it so the fast path stops sampling
        // it. A single misattribution (a tarpit target that
        // answers nothing) is bounded: the breaker needs 3
        // consecutive failures, a success resets it, and warm-list
        // removal is reversible on the next success.
        let Some(entry) = self.registry.get(tunnel_id) else {
            return;
        };
        let (threshold, cooldown) = self.effective_health();
        entry.health.record_failure(threshold, cooldown);
        entry.stats.record_rtt_failure();
        self.warm_list.note_failure(tunnel_id);
    }

    fn record_tunnel_rtt(&self, tunnel_id: &str, sample_ms: u64) {
        // A real first-byte latency sample: feed it to the
        // Peak-EWMA as-is (clamped to 1 ms–tau inside). The
        // hedge-loser observer calls this for a primary that
        // answered late — slow, not dead — so the selector learns
        // the tunnel is slow instead of treating it as dead.
        let Some(entry) = self.registry.get(tunnel_id) else {
            return;
        };
        entry.stats.record_rtt_sample(sample_ms);
    }

    fn record_tunnel_transport_failure(&self, tunnel_id: &str) {
        // The tunnel's connection died (EOF / reset) before
        // answering: the same failure charge the dial path applies
        // to a tunnel-side failure (breaker + maximally slow EWMA
        // sample), but without the warm-list removal — a dead
        // connection is not evidence the tunnel is silently
        // blackholing, so the fast path keeps sampling it.
        let Some(entry) = self.registry.get(tunnel_id) else {
            return;
        };
        let (threshold, cooldown) = self.effective_health();
        entry.health.record_failure(threshold, cooldown);
        entry.stats.record_rtt_failure();
    }
}

/// Dedicated router for per-tunnel ports forwarding all connections directly to a single tunnel.
#[derive(Debug)]
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
                Some((u, p))
                    if constant_time_eq_str(u, expected_user)
                        && constant_time_eq_str(p, expected_pass) =>
                {
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
        _credentials: Option<(&'a str, &'a str)>,
    ) -> Pin<Box<dyn Future<Output = io::Result<Arc<dyn ProxyTunnelTarget>>> + Send + 'a>> {
        // A dedicated router serves one tunnel whose credentials were
        // already verified by `authenticate`; there is nothing further
        // to check at selection time.
        Box::pin(async move {
            let (active, guard) = self
                .lifecycle
                .get_or_activate(&self.tunnel_id)
                .await
                .map_err(|e| io::Error::other(format!("tunnel activation failed: {e:?}")))?;

            let entry = self.lifecycle.registry().get(&self.tunnel_id);
            let health = entry.as_ref().map(|e| Arc::clone(&e.health));

            let guarded = if let Some(h) = health {
                let (threshold, cooldown) = self.lifecycle.health_check();
                GuardedTunnelTarget::new_with_health(active, guard, h, threshold, cooldown)
            } else {
                GuardedTunnelTarget::new(active, guard)
            };

            let ip_mode = self.lifecycle.ip_mode();
            let target: Arc<dyn ProxyTunnelTarget> = if ip_mode == IpMode::DualStack {
                Arc::new(guarded)
            } else {
                Arc::new(IpFilteredTunnelTarget::new(Arc::new(guarded), ip_mode))
            };
            Ok(target)
        })
    }
}

/// Tunnel target wrapper enforcing a listener- or global-level [`IpMode`] on TCP, UDP, and DNS.
#[derive(Debug)]
pub struct IpFilteredTunnelTarget {
    inner: Arc<GuardedTunnelTarget>,
    ip_mode: IpMode,
}

impl IpFilteredTunnelTarget {
    /// Wrap a [`GuardedTunnelTarget`] with an [`IpMode`] filter.
    pub const fn new(inner: Arc<GuardedTunnelTarget>, ip_mode: IpMode) -> Self {
        Self { inner, ip_mode }
    }
}

impl ProxyTunnelTarget for IpFilteredTunnelTarget {
    fn tcp_connect<'a>(
        &'a self,
        dst: SocketAddr,
    ) -> Pin<Box<dyn Future<Output = io::Result<DynStream>> + Send + 'a>> {
        if let Err(e) = self.ip_mode.check_ip(dst.ip(), "TCP destination") {
            return Box::pin(async move { Err(e) });
        }
        self.inner.tcp_connect(dst)
    }

    fn udp_bind<'a>(
        &'a self,
        local_port: u16,
    ) -> Pin<Box<dyn Future<Output = io::Result<Box<dyn ProxyUdpSocket>>> + Send + 'a>> {
        let inner = Arc::clone(&self.inner);
        let ip_mode = self.ip_mode;
        Box::pin(async move {
            let sock = inner.udp_bind(local_port).await?;
            let filtered: Box<dyn ProxyUdpSocket> = Box::new(IpFilteredUdpSocket {
                inner: sock,
                ip_mode,
            });
            Ok(filtered)
        })
    }

    fn resolve_in_tunnel<'a>(
        &'a self,
        domain: &'a str,
    ) -> Pin<Box<dyn Future<Output = io::Result<IpAddr>> + Send + 'a>> {
        self.inner.resolve_in_tunnel_with_mode(domain, self.ip_mode)
    }

    fn resolve_all_in_tunnel<'a>(
        &'a self,
        domain: &'a str,
    ) -> crate::proxy::router::ResolveAllFut<'a> {
        self.inner
            .resolve_all_in_tunnel_with_mode(domain, self.ip_mode)
    }

    fn connect_timeout(&self) -> Duration {
        self.inner.connect_timeout()
    }

    fn tunnel_id(&self) -> Option<&str> {
        self.inner.tunnel_id()
    }

    fn note_attempt_aborted(&self) {
        self.inner.note_attempt_aborted();
    }

    fn is_live(&self) -> bool {
        self.inner.is_live()
    }
}

/// UDP socket wrapper enforcing an [`IpMode`] filter on outbound datagrams.
struct IpFilteredUdpSocket {
    inner: Box<dyn ProxyUdpSocket>,
    ip_mode: IpMode,
}

impl ProxyUdpSocket for IpFilteredUdpSocket {
    fn send_to<'a>(
        &'a self,
        buf: &'a [u8],
        target: SocketAddr,
    ) -> Pin<Box<dyn Future<Output = io::Result<usize>> + Send + 'a>> {
        if let Err(e) = self.ip_mode.check_ip(target.ip(), "UDP destination") {
            return Box::pin(async move { Err(e) });
        }
        self.inner.send_to(buf, target)
    }

    fn recv_from<'a>(
        &'a self,
        buf: &'a mut [u8],
    ) -> Pin<Box<dyn Future<Output = io::Result<(usize, SocketAddr)>> + Send + 'a>> {
        let ip_mode = self.ip_mode;
        Box::pin(async move {
            loop {
                let (len, peer) = self.inner.recv_from(buf).await?;
                if ip_mode.allows_ip(peer.ip()) {
                    return Ok((len, peer));
                }
            }
        })
    }

    fn local_port(&self) -> u16 {
        self.inner.local_port()
    }
}
