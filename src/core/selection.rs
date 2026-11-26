//! Adaptive tunnel selection: stratified Power-of-Two-Choices over a
//! Peak-EWMA latency score with a dormant surcharge and slow-start weight.
//!
//! The fast path never scans the whole pool. It draws one candidate from
//! the bounded warm list ([`WarmList`], the 8–12 tunnels that most
//! recently proved themselves by moving real traffic) and one candidate
//! at random from the whole pool, then serves the lower score:
//!
//! ```text
//! score = (peak_ewma_rtt_ms + dormant_surcharge_ms(t_idle)) × (inflight + 1) / weight
//! ```
//!
//! * `peak_ewma_rtt_ms` — EWMA (alpha 0.2) of TCP-connect latency
//!   samples recorded by [`crate::core::lifecycle::GuardedTunnelTarget`];
//!   a failure counts as a sample of `tau` (10 s), so a failing tunnel's
//!   score jumps instead of decaying quietly. Samples are clamped to
//!   1 ms–10 s. Tunnels with no sample yet use [`DEFAULT_RTT_MS`].
//! * `dormant_surcharge_ms` — 0 while the last handshake is at most
//!   90 s old, ramping linearly to 150 ms at 120 s, then 800 ms plus
//!   up to 200 ms of jitter. `t_idle` is measured from the last
//!   handshake, never from connection activity: a tunnel can sit idle
//!   with connections while its WireGuard session ages out (rekey at
//!   120 s, reject at 180 s).
//! * `weight` — Envoy-style slow start: a freshly (re)admitted tunnel
//!   ramps from 10% to full weight over [`SLOW_START_WINDOW_SECS`].
//!   The time factor is clamped to [0, 1] before it is used, so an
//!   old tunnel never scores below its unweighted value.
//!
//! Ejected tunnels never enter either draw: callers validate candidates
//! with `health.can_route()` before scoring them.

use std::collections::VecDeque;

use parking_lot::RwLock;

use crate::core::registry::TunnelEntry;

/// Maximum warm-list size: the last 12 tunnels to prove themselves.
pub(crate) const WARM_LIST_CAP: usize = 12;

/// Slow-start ramp window: a (re)admitted tunnel reaches full weight
/// after this many seconds of pool membership.
pub(crate) const SLOW_START_WINDOW_SECS: u64 = 60;

/// Minimum slow-start weight: a fresh tunnel still gets 10% so it can
/// prove itself instead of starving (Envoy `MinWeightPercent`).
pub(crate) const SLOW_START_MIN_WEIGHT: f64 = 0.1;

/// Default RTT assumed for a tunnel with no latency sample yet.
pub(crate) const DEFAULT_RTT_MS: u64 = 100;

/// Idle time (from the last handshake) below which no surcharge applies.
pub(crate) const WARM_IDLE_SECS: u64 = 90;

/// Idle time above which the full dormant surcharge applies.
pub(crate) const DORMANT_IDLE_SECS: u64 = 120;

/// Surcharge at the end of the warm→dormant ramp.
pub(crate) const RAMP_SURCHARGE_MS: u64 = 150;

/// Flat surcharge for a dormant tunnel, before jitter.
pub(crate) const DORMANT_SURCHARGE_MS: u64 = 800;

/// Maximum jitter added to the dormant surcharge, to decorrelate
/// selectors that would otherwise agree on the same "least dormant"
/// tunnel at the same instant.
pub(crate) const DORMANT_JITTER_MAX_MS: u64 = 200;

/// Dormant surcharge for a tunnel idle `t_idle_secs` since its last
/// handshake: 0 while warm, a linear ramp across the transition zone,
/// then the flat dormant penalty plus the caller's jitter (0–200 ms).
/// Pure, so the zone boundaries are unit-testable without randomness.
pub(crate) const fn dormant_surcharge_ms(t_idle_secs: u64, jitter_ms: u64) -> u64 {
    if t_idle_secs <= WARM_IDLE_SECS {
        0
    } else if t_idle_secs <= DORMANT_IDLE_SECS {
        (t_idle_secs - WARM_IDLE_SECS) * (RAMP_SURCHARGE_MS / (DORMANT_IDLE_SECS - WARM_IDLE_SECS))
    } else {
        DORMANT_SURCHARGE_MS + jitter_ms
    }
}

/// Slow-start weight for a tunnel admitted `elapsed_secs` ago: the
/// Envoy time factor `max(elapsed, 1s) / window`, clamped to [0, 1]
/// and floored at [`SLOW_START_MIN_WEIGHT`]. The clamp matters: an
/// unclamped factor above 1 would shrink the score below the
/// tunnel's unweighted latency and let an old tunnel dominate
/// purely by age.
pub(crate) fn slow_start_weight(elapsed_secs: u64) -> f64 {
    let factor = (elapsed_secs as f64 / SLOW_START_WINDOW_SECS as f64).clamp(0.0, 1.0);
    factor.max(SLOW_START_MIN_WEIGHT)
}

/// Peak-EWMA selection score for one tunnel, from plain inputs.
/// `ewma_ms == 0` means "no sample yet" and falls back to
/// [`DEFAULT_RTT_MS`]; `weight` is defensively floored at the slow-start
/// minimum so a caller can never divide by zero or a negative weight.
pub(crate) fn tunnel_score(
    ewma_ms: u64,
    t_idle_secs: u64,
    inflight: usize,
    weight: f64,
    jitter_ms: u64,
) -> f64 {
    let rtt = if ewma_ms == 0 {
        DEFAULT_RTT_MS
    } else {
        ewma_ms
    };
    let base = rtt.saturating_add(dormant_surcharge_ms(t_idle_secs, jitter_ms));
    let load = inflight.saturating_add(1) as f64;
    base as f64 * load / weight.max(SLOW_START_MIN_WEIGHT)
}

/// Selection score for a registry entry, reading its live counters.
/// `now_secs` is Unix time in seconds; `jitter_ms` is the caller's
/// 0–200 ms decorrelation jitter for dormant tunnels.
pub(crate) fn score_entry(entry: &TunnelEntry, now_secs: u64, jitter_ms: u64) -> f64 {
    use std::sync::atomic::Ordering;
    let stats = &entry.stats;
    let last_handshake = stats.last_handshake.load(Ordering::Relaxed);
    let t_idle = now_secs.saturating_sub(last_handshake);
    let activated = stats.activated_at.load(Ordering::Relaxed);
    let elapsed = now_secs.saturating_sub(activated);
    let ewma = stats.rtt_ewma_ms.load(Ordering::Relaxed);
    let inflight = stats.active_conns.load(Ordering::Relaxed);
    let weight = if activated == 0 {
        SLOW_START_MIN_WEIGHT
    } else {
        slow_start_weight(elapsed)
    };
    tunnel_score(ewma, t_idle, inflight, weight, jitter_ms)
}

/// Fresh jitter for one dormant-surcharge evaluation (0–200 ms).
pub(crate) fn dormant_jitter_ms() -> u64 {
    rand::random::<u64>() % (DORMANT_JITTER_MAX_MS + 1)
}

/// Bounded index of the tunnels that most recently proved themselves
/// by moving real traffic: the warm aperture the fast path samples
/// from. Membership is most-recent-first, deduplicated, capped at
/// [`WARM_LIST_CAP`]; a random pick is O(1) and never scans the pool.
#[derive(Debug, Default)]
pub(crate) struct WarmList {
    inner: RwLock<VecDeque<String>>,
}

impl WarmList {
    /// Create an empty warm list.
    pub(crate) fn new() -> Self {
        Self::default()
    }

    /// Record a success for `id`: move it to the front, dropping the
    /// oldest entries past the cap. Cheap (at most 12 entries), and
    /// called only on proven success, not on every selection.
    pub(crate) fn note_success(&self, id: &str) {
        let mut inner = self.inner.write();
        inner.retain(|existing| existing != id);
        inner.push_front(id.to_string());
        while inner.len() > WARM_LIST_CAP {
            inner.pop_back();
        }
        drop(inner);
    }

    /// Pick a random member in O(1), or `None` when empty. Callers
    /// validate the pick (routable, not ejected) before using it.
    pub(crate) fn pick(&self) -> Option<String> {
        let inner = self.inner.read();
        if inner.is_empty() {
            return None;
        }
        let idx = rand::random::<u32>() as usize % inner.len();
        inner.get(idx).cloned()
    }

    /// Current membership, most-recent-first.
    #[cfg(test)]
    pub(crate) fn snapshot(&self) -> Vec<String> {
        self.inner.read().iter().cloned().collect()
    }

    /// Number of members, for tests and diagnostics.
    #[cfg(test)]
    pub(crate) fn len(&self) -> usize {
        self.inner.read().len()
    }

    /// Whether the list holds no tunnel.
    #[cfg(test)]
    pub(crate) fn is_empty(&self) -> bool {
        self.inner.read().is_empty()
    }
}
