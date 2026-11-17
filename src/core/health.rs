//! Hybrid health check and circuit breaker engine.
//!
//! Provides [`HealthStatus`], [`TunnelHealthTracker`], and [`ActiveProber`] for tracking
//! tunnel health, tripping passive circuit breakers for dormant/lazy tunnels with 0% idle CPU,
//! and actively probing eager tunnels.

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use parking_lot::{Mutex, RwLock};
use serde::{Deserialize, Serialize};
use tokio::sync::watch;
use tokio::task::JoinHandle;

use crate::config::{HealthCheckSettings, LifecycleMode};
use crate::core::registry::TunnelRegistry;

/// Health status of a WireGuard tunnel.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum HealthStatus {
    /// No successful handshake or probe has been observed yet (fresh or reset tunnel).
    /// The tunnel still participates in routing (unproven, not broken), but it is
    /// reported distinctly from proven-healthy tunnels so callers can tell the
    /// difference between "works" and "never tried".
    #[default]
    Unknown,
    /// Normal operating state. Tunnel participates in routing.
    Healthy,
    /// Circuit breaker tripped after threshold consecutive failures. In cooldown.
    Unhealthy,
    /// Cooldown timer has elapsed; single trial connection or probe permitted.
    HalfOpen,
}

impl std::fmt::Display for HealthStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Unknown => write!(f, "unknown"),
            Self::Healthy => write!(f, "healthy"),
            Self::Unhealthy => write!(f, "unhealthy"),
            Self::HalfOpen => write!(f, "half_open"),
        }
    }
}

#[derive(Debug, Clone, Copy)]
struct HealthState {
    status: HealthStatus,
    cooldown_until: Option<Instant>,
    trial_in_flight: bool,
}

/// Thread-safe tracker maintaining circuit breaker health status and failure counts.
///
/// Designed to guarantee 0% idle CPU and 0 socket allocations for dormant lazy tunnels
/// by evaluating cooldown expiration lazily upon query.
#[derive(Debug)]
pub struct TunnelHealthTracker {
    state: RwLock<HealthState>,
    consecutive_failures: AtomicUsize,
    last_failure_at: AtomicU64,
}

impl Default for TunnelHealthTracker {
    fn default() -> Self {
        Self::new()
    }
}

impl TunnelHealthTracker {
    /// Construct a new tracker initialized to Unknown (never proven).
    pub const fn new() -> Self {
        Self {
            state: RwLock::new(HealthState {
                status: HealthStatus::Unknown,
                cooldown_until: None,
                trial_in_flight: false,
            }),
            consecutive_failures: AtomicUsize::new(0),
            last_failure_at: AtomicU64::new(0),
        }
    }

    /// Pure read-only check whether the tunnel is eligible to route traffic (does not claim a trial slot).
    pub fn can_route(&self) -> bool {
        let state = self.state.read();
        match state.status {
            HealthStatus::Unknown | HealthStatus::Healthy => true,
            HealthStatus::HalfOpen => !state.trial_in_flight,
            HealthStatus::Unhealthy => state
                .cooldown_until
                .is_none_or(|until| Instant::now() >= until),
        }
    }

    /// Release an unclaimed `HalfOpen` trial slot (e.g. when a selected tunnel was not actually used).
    pub fn release_trial_slot(&self) {
        let mut state = self.state.write();
        if state.status == HealthStatus::HalfOpen {
            state.trial_in_flight = false;
        }
    }

    /// Check whether the tunnel is eligible to route traffic.
    ///
    /// If in `Unhealthy` state and cooldown timer has elapsed, lazily transitions
    /// the state to `HalfOpen` and returns `true` (allowing 1 trial attempt).
    pub fn is_routable(&self) -> bool {
        {
            let state = self.state.read();
            match state.status {
                HealthStatus::Unknown | HealthStatus::Healthy => return true,
                HealthStatus::HalfOpen if state.trial_in_flight => return false,
                HealthStatus::HalfOpen | HealthStatus::Unhealthy => {}
            }
        }

        let mut state = self.state.write();
        match state.status {
            HealthStatus::Unknown | HealthStatus::Healthy => true,
            HealthStatus::HalfOpen => {
                if state.trial_in_flight {
                    false
                } else {
                    state.trial_in_flight = true;
                    true
                }
            }
            HealthStatus::Unhealthy => {
                if let Some(until) = state.cooldown_until {
                    if Instant::now() >= until {
                        state.status = HealthStatus::HalfOpen;
                        state.trial_in_flight = true;
                        true
                    } else {
                        false
                    }
                } else {
                    state.status = HealthStatus::Healthy;
                    state.trial_in_flight = false;
                    true
                }
            }
        }
    }

    /// Query current health status, lazily advancing from Unhealthy to HalfOpen if cooldown elapsed.
    pub fn current_status(&self) -> HealthStatus {
        {
            let state = self.state.read();
            if state.status != HealthStatus::Unhealthy {
                return state.status;
            }
        }
        let mut state = self.state.write();
        if state.status == HealthStatus::Unhealthy
            && let Some(until) = state.cooldown_until
            && Instant::now() >= until
        {
            state.status = HealthStatus::HalfOpen;
            state.trial_in_flight = false;
        }
        state.status
    }

    /// Record a successful connection, handshake, or probe attempt.
    /// Resets consecutive failures to 0 and restores Healthy status.
    pub fn record_success(&self) {
        let mut state = self.state.write();
        self.consecutive_failures.store(0, Ordering::Relaxed);
        state.cooldown_until = None;
        state.status = HealthStatus::Healthy;
        state.trial_in_flight = false;
    }

    /// Record an inconclusive attempt: the operation completed without
    /// proving the tunnel works (or not). Binding a virtual UDP socket,
    /// for example, only allocates a local port — no packet has crossed
    /// the WireGuard handshake — so it must neither promote the tunnel
    /// to Healthy nor reset its failure count. A HalfOpen trial slot is
    /// released so a later trial can decide; anything else is untouched.
    pub fn record_inconclusive(&self) {
        let mut state = self.state.write();
        if state.status == HealthStatus::HalfOpen {
            state.trial_in_flight = false;
        }
    }

    /// Record a failed connection, handshake, or probe attempt.
    ///
    /// Increments consecutive failure count. If it meets or exceeds `threshold`,
    /// transitions status to `Unhealthy` and arms cooldown timer.
    pub fn record_failure(&self, threshold: usize, cooldown: Duration) {
        let now_secs = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        self.last_failure_at.store(now_secs, Ordering::Relaxed);

        let mut state = self.state.write();
        let failures = self.consecutive_failures.fetch_add(1, Ordering::SeqCst) + 1;
        match state.status {
            HealthStatus::Unknown | HealthStatus::Healthy => {
                if failures >= threshold {
                    state.cooldown_until = Some(Instant::now() + cooldown);
                    state.status = HealthStatus::Unhealthy;
                    state.trial_in_flight = false;
                }
            }
            HealthStatus::HalfOpen => {
                state.cooldown_until = Some(Instant::now() + cooldown);
                state.status = HealthStatus::Unhealthy;
                state.trial_in_flight = false;
            }
            HealthStatus::Unhealthy => {
                // Keep existing cooldown_until so repeated probe/request failures
                // cannot permanently trap the tunnel in Unhealthy.
                state.trial_in_flight = false;
            }
        }
    }

    /// Directly mark the tunnel as Unhealthy with a given cooldown duration.
    pub fn mark_unhealthy(&self, cooldown: Duration) {
        let mut state = self.state.write();
        state.cooldown_until = Some(Instant::now() + cooldown);
        state.status = HealthStatus::Unhealthy;
        state.trial_in_flight = false;
    }

    /// Return the count of consecutive failures.
    pub fn consecutive_failures(&self) -> usize {
        self.consecutive_failures.load(Ordering::Relaxed)
    }

    /// Return the remaining cooldown in seconds, or 0 if not currently cooling down.
    pub fn cooldown_remaining_secs(&self) -> u64 {
        let until = self.state.read().cooldown_until;
        until.map_or(0, |u| {
            let now = Instant::now();
            if u > now {
                u.duration_since(now).as_secs()
            } else {
                0
            }
        })
    }

    /// Reset the tracker to its initial state: Unknown with no failure history.
    /// Forgets any proven-healthy past; the tunnel must succeed again to be Healthy.
    pub fn reset(&self) {
        let mut state = self.state.write();
        self.consecutive_failures.store(0, Ordering::Relaxed);
        state.cooldown_until = None;
        state.status = HealthStatus::Unknown;
        state.trial_in_flight = false;
    }
}

#[derive(Debug)]
struct ProberTask {
    shutdown_tx: watch::Sender<bool>,
    settings_tx: watch::Sender<HealthCheckSettings>,
    handle: JoinHandle<()>,
}

/// Background supervisor periodically checking eager tunnels via `force_handshake`.
///
/// Strictly ignores lazy tunnels to ensure zero background overhead while dormant.
#[derive(Debug)]
pub struct ActiveProber {
    task: Mutex<Option<ProberTask>>,
    live_settings: Arc<RwLock<HealthCheckSettings>>,
}

impl Default for ActiveProber {
    fn default() -> Self {
        Self::new()
    }
}

impl ActiveProber {
    /// Create a new dormant active prober.
    pub fn new() -> Self {
        Self {
            task: Mutex::new(None),
            live_settings: Arc::new(RwLock::new(HealthCheckSettings::default())),
        }
    }

    fn make_interval(probe_interval: Duration) -> tokio::time::Interval {
        let mut interval = tokio::time::interval(probe_interval.max(Duration::from_millis(1)));
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        interval
    }

    /// Update active prober settings dynamically (applies to next wait cycle & probes).
    pub fn update_settings(&self, settings: HealthCheckSettings) {
        *self.live_settings.write() = settings.clone();
        if let Some(t) = self.task.lock().as_ref() {
            let _ = t.settings_tx.send(settings);
        }
    }

    /// Return a snapshot of the prober's active health-check settings.
    pub fn settings_snapshot(&self) -> HealthCheckSettings {
        self.live_settings.read().clone()
    }

    /// Start the active prober background task.
    pub fn start(&self, registry: Arc<TunnelRegistry>, settings: HealthCheckSettings) {
        let mut guard = self.task.lock();
        if guard.is_some() {
            return;
        }
        let initial_interval = settings.probe_interval;
        *self.live_settings.write() = settings.clone();
        let (tx, shutdown_rx) = watch::channel(false);
        let (settings_tx, settings_rx) = watch::channel(settings);
        let live_settings = Arc::clone(&self.live_settings);

        let handle = tokio::spawn(Self::run_prober_loop(
            registry,
            initial_interval,
            live_settings,
            shutdown_rx,
            settings_rx,
        ));

        *guard = Some(ProberTask {
            shutdown_tx: tx,
            settings_tx,
            handle,
        });
    }

    async fn run_prober_loop(
        registry: Arc<TunnelRegistry>,
        initial_interval: Duration,
        live_settings: Arc<RwLock<HealthCheckSettings>>,
        mut shutdown_rx: watch::Receiver<bool>,
        mut settings_rx: watch::Receiver<HealthCheckSettings>,
    ) {
        let mut interval = Self::make_interval(initial_interval);
        // Skip the immediate initial tick to allow startup initialization
        interval.tick().await;

        loop {
            tokio::select! {
                biased;
                _ = shutdown_rx.changed() => {
                    if *shutdown_rx.borrow() {
                        break;
                    }
                }
                res = settings_rx.changed() => {
                    if res.is_ok() {
                        let next_interval = settings_rx.borrow_and_update().probe_interval;
                        interval = Self::make_interval(next_interval);
                        interval.tick().await;
                    }
                }
                _ = interval.tick() => {
                    let snapshot = live_settings.read().clone();
                    Self::probe_eager_tunnels_with_shutdown(&registry, &snapshot, &mut shutdown_rx)
                        .await;
                    if *shutdown_rx.borrow() {
                        break;
                    }
                }
            }
        }
    }

    /// Run a single probe pass over all Eager tunnels with bounded concurrency.
    pub async fn probe_eager_tunnels(
        registry: &Arc<TunnelRegistry>,
        settings: &HealthCheckSettings,
    ) {
        let (_tx, mut rx) = watch::channel(false);
        Self::probe_eager_tunnels_with_shutdown(registry, settings, &mut rx).await;
    }

    async fn probe_eager_tunnels_with_shutdown(
        registry: &Arc<TunnelRegistry>,
        settings: &HealthCheckSettings,
        shutdown_rx: &mut watch::Receiver<bool>,
    ) {
        const MAX_CONCURRENT_PROBES: usize = 12;
        let sem = Arc::new(tokio::sync::Semaphore::new(MAX_CONCURRENT_PROBES));
        let mut set = tokio::task::JoinSet::new();

        for entry in registry.all_entries() {
            // STRICTLY SKIP LAZY, DISABLED, OR NON-ACTIVE TUNNELS
            if entry.lifecycle_mode != LifecycleMode::Eager
                || entry.is_disabled()
                || *entry.state.read() != crate::core::registry::TunnelState::Active
                || (entry.health.current_status() == HealthStatus::HalfOpen
                    && !entry.health.can_route())
            {
                continue;
            }

            let maybe_active = entry.active.read().clone();
            if let Some(active) = maybe_active {
                let peer_pubkey = {
                    let cfg = entry.config.read();
                    match cfg.peers.first() {
                        Some(p) => p.public_key,
                        None => continue,
                    }
                };

                let entry_ref = Arc::clone(&entry);
                let threshold = settings.threshold;
                let cooldown = settings.cooldown;
                let timeout = settings.probe_timeout;
                let active_clone = Arc::clone(&active);
                let sem_clone = Arc::clone(&sem);

                set.spawn(async move {
                    let Ok(_permit) = sem_clone.acquire_owned().await else {
                        return;
                    };
                    Self::probe_single_tunnel(
                        &entry_ref,
                        &active_clone,
                        peer_pubkey,
                        timeout,
                        threshold,
                        cooldown,
                    )
                    .await;
                });
            }
        }

        loop {
            tokio::select! {
                biased;
                _ = shutdown_rx.changed() => {
                    if *shutdown_rx.borrow() {
                        set.abort_all();
                        while set.join_next().await.is_some() {}
                        break;
                    }
                }
                res = set.join_next() => {
                    if res.is_none() {
                        break;
                    }
                }
            }
        }
    }

    async fn probe_single_tunnel(
        entry_ref: &Arc<crate::core::registry::TunnelEntry>,
        active_clone: &Arc<crate::core::registry::ActiveTunnel>,
        peer_pubkey: x25519_dalek::PublicKey,
        timeout: Duration,
        threshold: usize,
        cooldown: Duration,
    ) {
        const MAX_PROBE_ATTEMPTS: usize = 3;
        if entry_ref.is_disabled()
            || *entry_ref.state.read() != crate::core::registry::TunnelState::Active
        {
            return;
        }
        let mut succeeded = false;
        for attempt in 0..MAX_PROBE_ATTEMPTS {
            let probe_res =
                tokio::time::timeout(timeout, active_clone.device.force_handshake(&peer_pubkey))
                    .await;
            match probe_res {
                Ok(Ok(())) => {
                    let now = SystemTime::now()
                        .duration_since(UNIX_EPOCH)
                        .unwrap_or_default()
                        .as_secs();
                    entry_ref.stats.record_handshake(now);
                    match active_clone.netstack.probe_egress(timeout).await {
                        Ok(()) => {
                            entry_ref.health.record_success();
                            succeeded = true;
                            break;
                        }
                        Err(e) => {
                            tracing::debug!(
                                "Active probe egress check failed (attempt {}/{}): {}",
                                attempt + 1,
                                MAX_PROBE_ATTEMPTS,
                                e
                            );
                        }
                    }
                }
                Ok(Err(e)) => {
                    tracing::debug!(
                        "Active probe handshake failed (attempt {}/{}): {}",
                        attempt + 1,
                        MAX_PROBE_ATTEMPTS,
                        e
                    );
                }
                Err(_) => {
                    tracing::debug!(
                        "Active probe handshake timed out (attempt {}/{})",
                        attempt + 1,
                        MAX_PROBE_ATTEMPTS
                    );
                }
            }
            if attempt + 1 < MAX_PROBE_ATTEMPTS {
                let backoff_ms = 200u64 << attempt; // 200ms, 400ms
                tokio::time::sleep(Duration::from_millis(backoff_ms)).await;
            }
        }
        if !succeeded
            && !entry_ref.is_disabled()
            && *entry_ref.state.read() == crate::core::registry::TunnelState::Active
        {
            entry_ref.health.record_failure(threshold, cooldown);
        }
    }

    /// Stop the prober background task and wait for its clean shutdown.
    pub async fn stop(&self) {
        let task = self.task.lock().take();
        if let Some(t) = task {
            let _ = t.shutdown_tx.send(true);
            let _ = t.handle.await;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn assert_tracker_state(
        tracker: &TunnelHealthTracker,
        status: HealthStatus,
        failures: usize,
        routable: bool,
    ) {
        assert_eq!(tracker.current_status(), status);
        assert_eq!(tracker.consecutive_failures(), failures);
        assert_eq!(tracker.is_routable(), routable);
    }

    #[test]
    fn test_health_tracker_state_transitions() {
        let tracker = TunnelHealthTracker::new();
        assert_tracker_state(&tracker, HealthStatus::Unknown, 0, true);
        assert_eq!(tracker.cooldown_remaining_secs(), 0);

        let threshold = 3;
        let cooldown = Duration::from_millis(50);

        tracker.record_failure(threshold, cooldown);
        assert_tracker_state(&tracker, HealthStatus::Unknown, 1, true);

        tracker.record_success();
        assert_tracker_state(&tracker, HealthStatus::Healthy, 0, true);

        tracker.record_failure(threshold, cooldown);
        tracker.record_failure(threshold, cooldown);
        assert_tracker_state(&tracker, HealthStatus::Healthy, 2, true);

        tracker.record_failure(threshold, cooldown);
        assert_tracker_state(&tracker, HealthStatus::Unhealthy, 3, false);

        std::thread::sleep(Duration::from_millis(60));
        assert_eq!(tracker.cooldown_remaining_secs(), 0);
        assert!(tracker.is_routable());
        assert_eq!(tracker.current_status(), HealthStatus::HalfOpen);

        tracker.record_success();
        assert_tracker_state(&tracker, HealthStatus::Healthy, 0, true);
    }

    #[test]
    fn test_health_tracker_half_open_failure_returns_to_unhealthy() {
        let tracker = TunnelHealthTracker::new();
        let threshold = 1;
        let cooldown = Duration::from_millis(50);

        tracker.record_failure(threshold, cooldown);
        assert_eq!(tracker.current_status(), HealthStatus::Unhealthy);

        std::thread::sleep(Duration::from_millis(60));
        assert!(tracker.is_routable());
        assert_eq!(tracker.current_status(), HealthStatus::HalfOpen);

        // Failed trial immediately returns to Unhealthy
        tracker.record_failure(threshold, cooldown);
        assert_eq!(tracker.current_status(), HealthStatus::Unhealthy);
        assert!(!tracker.is_routable());
    }

    #[test]
    fn test_record_inconclusive_keeps_status_and_failures() {
        let tracker = TunnelHealthTracker::new();
        let threshold = 3;
        let cooldown = Duration::from_millis(50);

        // A fresh tunnel stays Unknown: an inconclusive attempt proves
        // nothing, so it must not promote to Healthy.
        tracker.record_inconclusive();
        assert_tracker_state(&tracker, HealthStatus::Unknown, 0, true);

        // Drive it to Unhealthy, then claim the HalfOpen trial slot.
        tracker.record_failure(threshold, cooldown);
        tracker.record_failure(threshold, cooldown);
        tracker.record_failure(threshold, cooldown);
        assert_eq!(tracker.current_status(), HealthStatus::Unhealthy);
        assert_eq!(tracker.consecutive_failures(), 3);
        std::thread::sleep(Duration::from_millis(60));
        assert!(tracker.is_routable());
        assert_eq!(tracker.current_status(), HealthStatus::HalfOpen);

        // An inconclusive trial must not reset the failure count or
        // promote the tunnel — but it releases the trial slot, so a
        // later trial can still decide.
        tracker.record_inconclusive();
        assert_eq!(tracker.current_status(), HealthStatus::HalfOpen);
        assert_eq!(tracker.consecutive_failures(), 3);
        assert!(tracker.is_routable());
        assert_eq!(tracker.current_status(), HealthStatus::HalfOpen);

        // And a failed trial after that still returns to Unhealthy.
        tracker.record_failure(threshold, cooldown);
        assert_eq!(tracker.current_status(), HealthStatus::Unhealthy);
        assert_eq!(tracker.consecutive_failures(), 4);
    }

    #[test]
    fn test_health_tracker_reset() {
        let tracker = TunnelHealthTracker::new();
        tracker.record_failure(1, Duration::from_secs(60));
        assert_eq!(tracker.current_status(), HealthStatus::Unhealthy);
        assert!(!tracker.is_routable());

        tracker.reset();
        assert_eq!(tracker.current_status(), HealthStatus::Unknown);
        assert!(tracker.is_routable());
        assert_eq!(tracker.consecutive_failures(), 0);
    }

    #[test]
    fn test_health_tracker_unknown_until_first_success() {
        let tracker = TunnelHealthTracker::new();

        // A fresh tunnel is Unknown, not Healthy: never proven, but still routable.
        assert_tracker_state(&tracker, HealthStatus::Unknown, 0, true);

        // Failures below threshold keep it Unknown (still unproven, not broken).
        tracker.record_failure(3, Duration::from_secs(30));
        assert_tracker_state(&tracker, HealthStatus::Unknown, 1, true);

        // Only a success promotes it to Healthy.
        tracker.record_success();
        assert_tracker_state(&tracker, HealthStatus::Healthy, 0, true);

        // And reset() forgets the proven past, returning to Unknown.
        tracker.reset();
        assert_tracker_state(&tracker, HealthStatus::Unknown, 0, true);
    }

    #[test]
    fn test_record_failure_while_unhealthy_does_not_extend_cooldown() {
        let tracker = TunnelHealthTracker::new();
        tracker.record_failure(1, Duration::from_millis(80));
        assert_eq!(tracker.current_status(), HealthStatus::Unhealthy);

        std::thread::sleep(Duration::from_millis(50));
        // Repeated failure while already Unhealthy must NOT reset cooldown_until
        tracker.record_failure(1, Duration::from_millis(80));

        std::thread::sleep(Duration::from_millis(45));
        assert!(
            tracker.is_routable(),
            "cooldown should have expired without being extended"
        );
        assert_eq!(tracker.current_status(), HealthStatus::HalfOpen);
    }
}
