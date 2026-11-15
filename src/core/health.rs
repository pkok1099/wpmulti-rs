//! Hybrid health check and circuit breaker engine.
//!
//! Provides [`HealthStatus`], [`TunnelHealthTracker`], and [`ActiveProber`] for tracking
//! tunnel health, tripping passive circuit breakers for dormant/lazy tunnels with 0% idle CPU,
//! and actively probing eager tunnels.

use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::Arc;
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
    /// Normal operating state. Tunnel participates in routing.
    #[default]
    Healthy,
    /// Circuit breaker tripped after threshold consecutive failures. In cooldown.
    Unhealthy,
    /// Cooldown timer has elapsed; single trial connection or probe permitted.
    HalfOpen,
}

impl std::fmt::Display for HealthStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            HealthStatus::Healthy => write!(f, "healthy"),
            HealthStatus::Unhealthy => write!(f, "unhealthy"),
            HealthStatus::HalfOpen => write!(f, "half_open"),
        }
    }
}

/// Thread-safe tracker maintaining circuit breaker health status and failure counts.
///
/// Designed to guarantee 0% idle CPU and 0 socket allocations for dormant lazy tunnels
/// by evaluating cooldown expiration lazily upon query.
#[derive(Debug)]
pub struct TunnelHealthTracker {
    status: RwLock<HealthStatus>,
    consecutive_failures: AtomicUsize,
    last_failure_at: AtomicU64,
    cooldown_until: RwLock<Option<Instant>>,
}

impl Default for TunnelHealthTracker {
    fn default() -> Self {
        Self::new()
    }
}

impl TunnelHealthTracker {
    /// Construct a new tracker initialized to Healthy.
    pub fn new() -> Self {
        Self {
            status: RwLock::new(HealthStatus::Healthy),
            consecutive_failures: AtomicUsize::new(0),
            last_failure_at: AtomicU64::new(0),
            cooldown_until: RwLock::new(None),
        }
    }

    /// Check whether the tunnel is eligible to route traffic.
    ///
    /// If in `Unhealthy` state and cooldown timer has elapsed, lazily transitions
    /// the state to `HalfOpen` and returns `true` (allowing 1 trial attempt).
    pub fn is_routable(&self) -> bool {
        let mut status = self.status.write();
        match *status {
            HealthStatus::Healthy => true,
            HealthStatus::HalfOpen => true,
            HealthStatus::Unhealthy => {
                let cooldown = self.cooldown_until.read();
                if let Some(until) = *cooldown {
                    if Instant::now() >= until {
                        drop(cooldown);
                        *status = HealthStatus::HalfOpen;
                        true
                    } else {
                        false
                    }
                } else {
                    *status = HealthStatus::Healthy;
                    true
                }
            }
        }
    }

    /// Query current health status, lazily advancing from Unhealthy to HalfOpen if cooldown elapsed.
    pub fn current_status(&self) -> HealthStatus {
        let mut status = self.status.write();
        if *status == HealthStatus::Unhealthy
            && let Some(until) = *self.cooldown_until.read()
            && Instant::now() >= until
        {
            *status = HealthStatus::HalfOpen;
        }
        *status
    }

    /// Record a successful connection, handshake, or probe attempt.
    /// Resets consecutive failures to 0 and restores Healthy status.
    pub fn record_success(&self) {
        self.consecutive_failures.store(0, Ordering::Relaxed);
        *self.cooldown_until.write() = None;
        *self.status.write() = HealthStatus::Healthy;
    }

    /// Record a failed connection, handshake, or probe attempt.
    ///
    /// Increments consecutive failure count. If it meets or exceeds `threshold`,
    /// transitions status to `Unhealthy` and arms cooldown timer.
    pub fn record_failure(&self, threshold: usize, cooldown: Duration) {
        let failures = self.consecutive_failures.fetch_add(1, Ordering::SeqCst) + 1;
        let now_secs = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        self.last_failure_at.store(now_secs, Ordering::Relaxed);

        if failures >= threshold {
            *self.cooldown_until.write() = Some(Instant::now() + cooldown);
            *self.status.write() = HealthStatus::Unhealthy;
        }
    }

    /// Directly mark the tunnel as Unhealthy with a given cooldown duration.
    pub fn mark_unhealthy(&self, cooldown: Duration) {
        *self.cooldown_until.write() = Some(Instant::now() + cooldown);
        *self.status.write() = HealthStatus::Unhealthy;
    }

    /// Return the count of consecutive failures.
    pub fn consecutive_failures(&self) -> usize {
        self.consecutive_failures.load(Ordering::Relaxed)
    }

    /// Return the remaining cooldown in seconds, or 0 if not currently cooling down.
    pub fn cooldown_remaining_secs(&self) -> u64 {
        if let Some(until) = *self.cooldown_until.read() {
            let now = Instant::now();
            if until > now {
                until.duration_since(now).as_secs()
            } else {
                0
            }
        } else {
            0
        }
    }

    /// Reset tracker back to initial Healthy state.
    pub fn reset(&self) {
        self.consecutive_failures.store(0, Ordering::Relaxed);
        *self.cooldown_until.write() = None;
        *self.status.write() = HealthStatus::Healthy;
    }
}

/// Background supervisor periodically checking eager tunnels via `force_handshake`.
///
/// Strictly ignores lazy tunnels to ensure zero background overhead while dormant.
pub struct ActiveProber {
    shutdown_tx: Mutex<Option<watch::Sender<bool>>>,
    task_handle: Mutex<Option<JoinHandle<()>>>,
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
            shutdown_tx: Mutex::new(None),
            task_handle: Mutex::new(None),
        }
    }

    /// Start the active prober background task.
    pub fn start(
        &self,
        registry: Arc<TunnelRegistry>,
        settings: HealthCheckSettings,
    ) {
        let mut tx_guard = self.shutdown_tx.lock();
        if tx_guard.is_some() {
            return;
        }

        let (tx, mut rx) = watch::channel(false);
        *tx_guard = Some(tx);

        let handle = tokio::spawn(async move {
            let mut interval = tokio::time::interval(settings.probe_interval);
            // Skip the immediate initial tick to allow startup initialization
            interval.tick().await;

            loop {
                tokio::select! {
                    _ = interval.tick() => {
                        Self::probe_eager_tunnels(&registry, &settings).await;
                    }
                    _ = rx.changed() => {
                        if *rx.borrow() {
                            break;
                        }
                    }
                }
            }
        });

        *self.task_handle.lock() = Some(handle);
    }

    /// Run a single probe pass over all Eager tunnels with bounded concurrency.
    pub async fn probe_eager_tunnels(
        registry: &Arc<TunnelRegistry>,
        settings: &HealthCheckSettings,
    ) {
        const MAX_CONCURRENT_PROBES: usize = 12;
        let sem = Arc::new(tokio::sync::Semaphore::new(MAX_CONCURRENT_PROBES));
        let mut set = tokio::task::JoinSet::new();

        for entry in registry.all_entries() {
            // STRICTLY SKIP LAZY TUNNELS to guarantee 0% idle CPU and 0 sockets
            if entry.lifecycle_mode != LifecycleMode::Eager {
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

                let health = Arc::clone(&entry.health);
                let stats = Arc::clone(&entry.stats);
                let threshold = settings.threshold;
                let cooldown = settings.cooldown;
                let timeout = settings.probe_timeout;
                let active_clone = Arc::clone(&active);
                let sem_clone = Arc::clone(&sem);

                set.spawn(async move {
                    let Ok(_permit) = sem_clone.acquire_owned().await else {
                        return;
                    };
                    let mut succeeded = false;
                    const MAX_PROBE_ATTEMPTS: usize = 3;
                    for attempt in 0..MAX_PROBE_ATTEMPTS {
                        let probe_res = tokio::time::timeout(
                            timeout,
                            active_clone.device.force_handshake(&peer_pubkey),
                        )
                        .await;
                        match probe_res {
                            Ok(Ok(())) => {
                                health.record_success();
                                let now = std::time::SystemTime::now()
                                    .duration_since(std::time::UNIX_EPOCH)
                                    .unwrap_or_default()
                                    .as_secs();
                                stats.record_handshake(now);
                                succeeded = true;
                                break;
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
                    if !succeeded {
                        health.record_failure(threshold, cooldown);
                    }
                });
            }
        }

        while set.join_next().await.is_some() {}
    }

    /// Stop the prober background task and wait for its clean shutdown.
    pub async fn stop(&self) {
        if let Some(tx) = self.shutdown_tx.lock().take() {
            let _ = tx.send(true);
        }
        let handle = self.task_handle.lock().take();
        if let Some(handle) = handle {
            let _ = handle.await;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_health_tracker_state_transitions() {
        let tracker = TunnelHealthTracker::new();
        assert_eq!(tracker.current_status(), HealthStatus::Healthy);
        assert!(tracker.is_routable());
        assert_eq!(tracker.consecutive_failures(), 0);
        assert_eq!(tracker.cooldown_remaining_secs(), 0);

        let threshold = 3;
        let cooldown = Duration::from_millis(50);

        // First failure: below threshold
        tracker.record_failure(threshold, cooldown);
        assert_eq!(tracker.consecutive_failures(), 1);
        assert_eq!(tracker.current_status(), HealthStatus::Healthy);
        assert!(tracker.is_routable());

        // Success resets failures
        tracker.record_success();
        assert_eq!(tracker.consecutive_failures(), 0);
        assert_eq!(tracker.current_status(), HealthStatus::Healthy);

        // Trigger failures up to threshold
        tracker.record_failure(threshold, cooldown);
        tracker.record_failure(threshold, cooldown);
        assert_eq!(tracker.consecutive_failures(), 2);
        assert_eq!(tracker.current_status(), HealthStatus::Healthy);
        assert!(tracker.is_routable());

        // Tripping failure
        tracker.record_failure(threshold, cooldown);
        assert_eq!(tracker.consecutive_failures(), 3);
        assert_eq!(tracker.current_status(), HealthStatus::Unhealthy);
        assert!(!tracker.is_routable());

        // Wait for cooldown expiration
        std::thread::sleep(Duration::from_millis(60));
        assert_eq!(tracker.cooldown_remaining_secs(), 0);

        // When cooldown expires, is_routable() transitions to HalfOpen and allows trial
        assert!(tracker.is_routable());
        assert_eq!(tracker.current_status(), HealthStatus::HalfOpen);

        // Successful trial restores Healthy
        tracker.record_success();
        assert_eq!(tracker.current_status(), HealthStatus::Healthy);
        assert_eq!(tracker.consecutive_failures(), 0);
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
    fn test_health_tracker_reset() {
        let tracker = TunnelHealthTracker::new();
        tracker.record_failure(1, Duration::from_secs(60));
        assert_eq!(tracker.current_status(), HealthStatus::Unhealthy);
        assert!(!tracker.is_routable());

        tracker.reset();
        assert_eq!(tracker.current_status(), HealthStatus::Healthy);
        assert!(tracker.is_routable());
        assert_eq!(tracker.consecutive_failures(), 0);
    }
}
