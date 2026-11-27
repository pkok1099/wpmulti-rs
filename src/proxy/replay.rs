//! Post-send replay machinery shared by the fix5 transparent retry
//! and `safe_http_silence_replay` (fix11).
//!
//! Both mechanisms re-send client bytes that already went upstream,
//! so they share one allowance per session: a single atomic token
//! (`Available -> Claimed`) that exactly one of them can win. A
//! replay that wins the token may re-dial through a different tunnel
//! — but only through [`connect_direct`], never through the fix6
//! racing router, or one replay would spend the request chain's
//! whole dial budget on speculative legs. The silence replay is
//! additionally gated by a global token bucket (load control) and by
//! a strict positive parse of the request as a bodyless plaintext
//! HTTP GET: opaque TLS and unknown streams are never replayed after
//! bytes were sent, because the origin may already have processed
//! them.
//!
//! A replayed GET is safe by the HTTP contract (idempotent), but a
//! badly implemented server may not treat it that way — the caveat
//! is real, and it is why the parse is strict and the replay is
//! one-shot. There is no config surface for this: the mechanism is
//! always on for CONNECT sessions with a retry context.

use std::fmt::Write as _;
use std::io;
use std::sync::Arc;
use std::sync::atomic::{AtomicU8, AtomicU64, AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use parking_lot::Mutex;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::sync::oneshot;

use super::router::{
    DynStream, RouterConnectError, TargetAddr, TunnelRouter, TunnelSelector, connect_direct,
};

/// Silence after the complete GET header was written to the primary
/// tunnel before one alternate-tunnel attempt is started. Fixed, not
/// per-target p95: a p95 trigger would duplicate ~5% of healthy
/// requests while the failure it rescues is 0.02-0.05%.
pub(crate) const SILENCE_REPLAY_DELAY: Duration = Duration::from_millis(2500);

/// How long a losing primary is observed after the secondary wins:
/// until the client's own 15 s deadline, measured from when the
/// request was forwarded to the primary. The observer only watches
/// for the primary's first response byte, its close, or its silence
/// until this deadline — it never forwards anything from the primary
/// to the client.
pub(crate) const HEDGE_LOSER_OBSERVE_DEADLINE: Duration = Duration::from_secs(15);

/// Largest request header a silence replay will consider: a GET head
/// past this is not a small idempotent request, and the replay bytes
/// must be known exactly without re-reading the client stream.
pub(crate) const SAFE_GET_MAX_HEADER_BYTES: usize = 16 * 1024;

/// Global replay token bucket capacity (shared across all tunnels,
/// not per tunnel): at most this many silence replays may start
/// before the bucket refills.
const REPLAY_BUCKET_CAPACITY: u32 = 10;

/// Primary requests per bucket refill token: the bucket refills
/// slowly enough that replays add at most ~1% extra upstream load.
const REPLAY_BUCKET_REFILL_REQUESTS: u32 = 100;

/// Most post-send replays live at once: a second load control on top
/// of the bucket, so a burst of blackholes cannot fan out.
const MAX_CONCURRENT_REPLAYS: u32 = 4;

/// Which mechanism claimed the session's one post-send replay.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ReplaySource {
    /// The fix5 zero-response retry (EOF / reset / failed write).
    Fix5,
    /// The fix11 delayed silence replay of a safe HTTP GET.
    SilenceReplay,
}

impl ReplaySource {
    const fn code(self) -> u8 {
        match self {
            Self::Fix5 => 1,
            Self::SilenceReplay => 2,
        }
    }

    pub(crate) const fn label(self) -> &'static str {
        match self {
            Self::Fix5 => "fix5",
            Self::SilenceReplay => "silence",
        }
    }
}

/// Why a replay was suppressed (the `reason` label of
/// `safe_http_replay_suppressed_total`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum SuppressReason {
    /// The request is not a positively identified safe HTTP GET (and
    /// bytes were already sent): opaque TLS / unknown streams are
    /// never replayed.
    Ineligible,
    /// The shared post-send token was already claimed by the other
    /// mechanism.
    TokenClaimed,
    /// The global replay bucket (or the concurrency limit) is empty.
    BudgetExhausted,
    /// The primary answered before the secondary was ready.
    ResponseStarted,
    /// No tunnel other than the primary exists to re-dial through.
    NoTunnel,
    /// The client went away before the replay could start.
    ClientGone,
    /// The client sent bytes past the GET header: they already went
    /// to the primary, and a secondary win would lose them.
    ClientSentMore,
}

impl SuppressReason {
    pub(crate) const fn label(self) -> &'static str {
        match self {
            Self::Ineligible => "ineligible",
            Self::TokenClaimed => "token_claimed",
            Self::BudgetExhausted => "budget_exhausted",
            Self::ResponseStarted => "response_started",
            Self::NoTunnel => "no_tunnel",
            Self::ClientGone => "client_gone",
            Self::ClientSentMore => "client_sent_more",
        }
    }
}

/// Why a tunnel was ejected by the blackhole penalty, the `reason`
/// label of `tunnel_blackhole_ejections_total`. The label set is
/// closed (an enum, never free text) so the metric stays bounded.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum BlackholeEjectionReason {
    /// The hedge-loser observer watched the primary miss its
    /// deadline after losing the race.
    DeadlineMiss,
    /// The fix5 zero-response retry rescued the session and charged
    /// the failed tunnel.
    ZeroResponseRetry,
    /// A session ended with bytes sent and zero response bytes.
    SessionEnd,
}

impl BlackholeEjectionReason {
    pub(crate) const fn label(self) -> &'static str {
        match self {
            Self::DeadlineMiss => "deadline_miss",
            Self::ZeroResponseRetry => "zero_response_retry",
            Self::SessionEnd => "session_end",
        }
    }
}

/// The one post-send replay a CONNECT session is allowed. fix5 and
/// the silence replay call the same `claim`: the timer and the EOF
/// handler race, so the transition must be a single
/// compare-exchange, never a check-then-set. fix6 does not consume
/// this token — its loser never received request bytes, so it cannot
/// duplicate an operation.
pub(crate) struct PostSendReplayToken {
    claimed_by: AtomicU8,
}

impl PostSendReplayToken {
    pub(crate) const fn new() -> Self {
        Self {
            claimed_by: AtomicU8::new(0),
        }
    }

    /// Atomically claim the session's one post-send replay for
    /// `source`. Returns false when it was already claimed.
    pub(crate) fn claim(&self, source: ReplaySource) -> bool {
        self.claimed_by
            .compare_exchange(0, source.code(), Ordering::AcqRel, Ordering::Relaxed)
            .is_ok()
    }
}

/// Global load control for silence replays: a token bucket (capacity
/// [`REPLAY_BUCKET_CAPACITY`], one token per
/// [`REPLAY_BUCKET_REFILL_REQUESTS`] primary requests) plus a cap on
/// simultaneously live replays. The per-request token is the
/// correctness control; this bucket is only a load control, and only
/// the silence replay draws from it — fix5 keeps its own (one per
/// session) limit. Held only for brief synchronous updates, never
/// across an await.
struct ReplayBudget {
    tokens: u32,
    requests_since_refill: u32,
    concurrent: u32,
}

static REPLAY_BUDGET: Mutex<ReplayBudget> = Mutex::new(ReplayBudget {
    tokens: REPLAY_BUCKET_CAPACITY,
    requests_since_refill: 0,
    concurrent: 0,
});

/// Process-wide monotonic id minted once per CONNECT session, so
/// every replay decision record of one session — trigger, dial
/// outcome, race resolution, observer verdict, session end — can be
/// joined by grepping a single number. Starts at 1 so 0 means "no
/// session id" (the forward path, which never replays). Never a
/// Prometheus label: only a structured log field.
static NEXT_REQUEST_ID: AtomicU64 = AtomicU64::new(1);

/// Mint the next per-session correlation id.
pub(crate) fn next_replay_request_id() -> u64 {
    NEXT_REQUEST_ID.fetch_add(1, Ordering::Relaxed)
}

/// Count one primary CONNECT request towards the bucket refill: one
/// token per [`REPLAY_BUCKET_REFILL_REQUESTS`] requests.
pub(crate) fn replay_budget_note_primary_request() {
    let mut budget = REPLAY_BUDGET.lock();
    budget.requests_since_refill += 1;
    if budget.requests_since_refill >= REPLAY_BUCKET_REFILL_REQUESTS {
        budget.requests_since_refill = 0;
        if budget.tokens < REPLAY_BUCKET_CAPACITY {
            budget.tokens += 1;
        }
    }
}

/// Reserve a global replay slot (one bucket token + one concurrency
/// slot). Returns false when the bucket or the concurrency limit is
/// empty; the caller must not claim the per-request token then.
pub(crate) fn replay_budget_try_start() -> bool {
    let mut budget = REPLAY_BUDGET.lock();
    if budget.tokens > 0 && budget.concurrent < MAX_CONCURRENT_REPLAYS {
        budget.tokens -= 1;
        budget.concurrent += 1;
        true
    } else {
        false
    }
}

/// Release a concurrency slot reserved by
/// [`replay_budget_try_start`]. The bucket token is spent, not
/// refunded. Idempotent only when paired with one reservation per
/// session — callers guard it with their own `budget_held` flag.
pub(crate) fn replay_budget_finish() {
    let mut budget = REPLAY_BUDGET.lock();
    budget.concurrent = budget.concurrent.saturating_sub(1);
}

/// Counters for the post-send replay mechanisms, exposed on
/// Prometheus `/metrics` following the existing `wpmulti_*`
/// convention. A hedge starting, losing, or being suppressed is
/// expected behaviour, so it is counted here — never logged at WARN.
pub(crate) struct ReplayMetrics {
    pub(crate) eligible: AtomicU64,
    pub(crate) suppressed_ineligible: AtomicU64,
    pub(crate) suppressed_token_claimed: AtomicU64,
    pub(crate) suppressed_budget: AtomicU64,
    pub(crate) suppressed_response_started: AtomicU64,
    pub(crate) suppressed_no_tunnel: AtomicU64,
    pub(crate) suppressed_client_gone: AtomicU64,
    pub(crate) suppressed_client_sent_more: AtomicU64,
    pub(crate) silence_trigger: AtomicU64,
    pub(crate) dial_started: AtomicU64,
    pub(crate) dial_failed: AtomicU64,
    pub(crate) request_sent: AtomicU64,
    pub(crate) winner_primary: AtomicU64,
    pub(crate) winner_secondary: AtomicU64,
    /// Secondary legs that produced the first response byte: a win,
    /// not yet proven a rescue — the primary may only have been
    /// slow (fix12 renames the fix11 `rescued` counter, which
    /// claimed a rescue the observation never proved).
    pub(crate) secondary_wins: AtomicU64,
    pub(crate) both_legs_responded: AtomicU64,
    pub(crate) claimed_fix5: AtomicU64,
    pub(crate) claimed_silence: AtomicU64,
    /// Hedge-loser observation outcomes (fix12): what the losing
    /// primary did after the secondary won the race.
    pub(crate) late_response: AtomicU64,
    pub(crate) transport_failure: AtomicU64,
    pub(crate) deadline_miss: AtomicU64,
    /// Secondary wins where the primary missed its deadline: the
    /// only ones that are proven rescues.
    pub(crate) true_rescues: AtomicU64,
    /// Secondary wins whose loser could not be observed at all
    /// (no observer could start): no penalty is ever charged.
    pub(crate) unobserved_loser: AtomicU64,
    /// Sum of observed late-response latencies, in milliseconds:
    /// the mean late latency is this divided by `late_response`.
    pub(crate) primary_response_latency_ms_sum: AtomicU64,
    /// Blackhole ejections, by the path that charged them.
    pub(crate) blackhole_ejections_deadline_miss: AtomicU64,
    pub(crate) blackhole_ejections_zero_response_retry: AtomicU64,
    pub(crate) blackhole_ejections_session_end: AtomicU64,
}

impl ReplayMetrics {
    const fn new() -> Self {
        Self {
            eligible: AtomicU64::new(0),
            suppressed_ineligible: AtomicU64::new(0),
            suppressed_token_claimed: AtomicU64::new(0),
            suppressed_budget: AtomicU64::new(0),
            suppressed_response_started: AtomicU64::new(0),
            suppressed_no_tunnel: AtomicU64::new(0),
            suppressed_client_gone: AtomicU64::new(0),
            suppressed_client_sent_more: AtomicU64::new(0),
            silence_trigger: AtomicU64::new(0),
            dial_started: AtomicU64::new(0),
            dial_failed: AtomicU64::new(0),
            request_sent: AtomicU64::new(0),
            winner_primary: AtomicU64::new(0),
            winner_secondary: AtomicU64::new(0),
            secondary_wins: AtomicU64::new(0),
            both_legs_responded: AtomicU64::new(0),
            claimed_fix5: AtomicU64::new(0),
            claimed_silence: AtomicU64::new(0),
            late_response: AtomicU64::new(0),
            transport_failure: AtomicU64::new(0),
            deadline_miss: AtomicU64::new(0),
            true_rescues: AtomicU64::new(0),
            unobserved_loser: AtomicU64::new(0),
            primary_response_latency_ms_sum: AtomicU64::new(0),
            blackhole_ejections_deadline_miss: AtomicU64::new(0),
            blackhole_ejections_zero_response_retry: AtomicU64::new(0),
            blackhole_ejections_session_end: AtomicU64::new(0),
        }
    }

    pub(crate) fn inc_eligible(&self) {
        self.eligible.fetch_add(1, Ordering::Relaxed);
    }

    pub(crate) fn inc_suppressed(&self, reason: SuppressReason) {
        let counter = match reason {
            SuppressReason::Ineligible => &self.suppressed_ineligible,
            SuppressReason::TokenClaimed => &self.suppressed_token_claimed,
            SuppressReason::BudgetExhausted => &self.suppressed_budget,
            SuppressReason::ResponseStarted => &self.suppressed_response_started,
            SuppressReason::NoTunnel => &self.suppressed_no_tunnel,
            SuppressReason::ClientGone => &self.suppressed_client_gone,
            SuppressReason::ClientSentMore => &self.suppressed_client_sent_more,
        };
        counter.fetch_add(1, Ordering::Relaxed);
    }

    pub(crate) fn inc_silence_trigger(&self) {
        self.silence_trigger.fetch_add(1, Ordering::Relaxed);
    }

    pub(crate) fn inc_dial_started(&self) {
        self.dial_started.fetch_add(1, Ordering::Relaxed);
    }

    pub(crate) fn inc_dial_failed(&self) {
        self.dial_failed.fetch_add(1, Ordering::Relaxed);
    }

    pub(crate) fn inc_request_sent(&self) {
        self.request_sent.fetch_add(1, Ordering::Relaxed);
    }

    pub(crate) fn inc_winner_primary(&self) {
        self.winner_primary.fetch_add(1, Ordering::Relaxed);
    }

    pub(crate) fn inc_winner_secondary(&self) {
        self.winner_secondary.fetch_add(1, Ordering::Relaxed);
    }

    pub(crate) fn inc_secondary_win(&self) {
        self.secondary_wins.fetch_add(1, Ordering::Relaxed);
    }

    pub(crate) fn inc_both_legs_responded(&self) {
        self.both_legs_responded.fetch_add(1, Ordering::Relaxed);
    }

    pub(crate) fn inc_late_response(&self) {
        self.late_response.fetch_add(1, Ordering::Relaxed);
    }

    pub(crate) fn inc_transport_failure(&self) {
        self.transport_failure.fetch_add(1, Ordering::Relaxed);
    }

    pub(crate) fn inc_deadline_miss(&self) {
        self.deadline_miss.fetch_add(1, Ordering::Relaxed);
    }

    pub(crate) fn inc_true_rescue(&self) {
        self.true_rescues.fetch_add(1, Ordering::Relaxed);
    }

    pub(crate) fn inc_unobserved_loser(&self) {
        self.unobserved_loser.fetch_add(1, Ordering::Relaxed);
    }

    pub(crate) fn add_primary_response_latency_ms(&self, ms: u64) {
        self.primary_response_latency_ms_sum
            .fetch_add(ms, Ordering::Relaxed);
    }

    pub(crate) fn inc_blackhole_ejection(&self, reason: BlackholeEjectionReason) {
        let counter = match reason {
            BlackholeEjectionReason::DeadlineMiss => &self.blackhole_ejections_deadline_miss,
            BlackholeEjectionReason::ZeroResponseRetry => {
                &self.blackhole_ejections_zero_response_retry
            }
            BlackholeEjectionReason::SessionEnd => &self.blackhole_ejections_session_end,
        };
        counter.fetch_add(1, Ordering::Relaxed);
    }

    pub(crate) fn inc_claimed(&self, source: ReplaySource) {
        let counter = match source {
            ReplaySource::Fix5 => &self.claimed_fix5,
            ReplaySource::SilenceReplay => &self.claimed_silence,
        };
        counter.fetch_add(1, Ordering::Relaxed);
    }

    /// Append the replay counters to a Prometheus exposition string,
    /// in the same HELP/TYPE/counter shape as the tunnel metrics.
    pub(crate) fn render(&self, out: &mut String) {
        self.render_eligibility(out);
        self.render_race(out);
        self.render_claimed(out);
        self.render_hedge(out);
    }

    /// Eligibility and suppression counters.
    fn render_eligibility(&self, out: &mut String) {
        write_counter(
            out,
            "safe_http_replay_eligible_total",
            "CONNECT sessions whose first request parsed as an eligible safe HTTP GET",
            self.eligible.load(Ordering::Relaxed),
        );
        write_counter_labeled(
            out,
            "safe_http_replay_suppressed_total",
            "Replays suppressed, by reason",
            "reason",
            SuppressReason::Ineligible.label(),
            self.suppressed_ineligible.load(Ordering::Relaxed),
        );
        write_counter_labeled(
            out,
            "safe_http_replay_suppressed_total",
            "Replays suppressed, by reason",
            "reason",
            SuppressReason::TokenClaimed.label(),
            self.suppressed_token_claimed.load(Ordering::Relaxed),
        );
        write_counter_labeled(
            out,
            "safe_http_replay_suppressed_total",
            "Replays suppressed, by reason",
            "reason",
            SuppressReason::BudgetExhausted.label(),
            self.suppressed_budget.load(Ordering::Relaxed),
        );
        write_counter_labeled(
            out,
            "safe_http_replay_suppressed_total",
            "Replays suppressed, by reason",
            "reason",
            SuppressReason::ResponseStarted.label(),
            self.suppressed_response_started.load(Ordering::Relaxed),
        );
        write_counter_labeled(
            out,
            "safe_http_replay_suppressed_total",
            "Replays suppressed, by reason",
            "reason",
            SuppressReason::NoTunnel.label(),
            self.suppressed_no_tunnel.load(Ordering::Relaxed),
        );
        write_counter_labeled(
            out,
            "safe_http_replay_suppressed_total",
            "Replays suppressed, by reason",
            "reason",
            SuppressReason::ClientGone.label(),
            self.suppressed_client_gone.load(Ordering::Relaxed),
        );
        write_counter_labeled(
            out,
            "safe_http_replay_suppressed_total",
            "Replays suppressed, by reason",
            "reason",
            SuppressReason::ClientSentMore.label(),
            self.suppressed_client_sent_more.load(Ordering::Relaxed),
        );
    }

    /// Race outcome counters: trigger, dial, winner, rescue.
    fn render_race(&self, out: &mut String) {
        write_counter(
            out,
            "safe_http_silence_trigger_total",
            "Silence timers that fired on an eligible GET",
            self.silence_trigger.load(Ordering::Relaxed),
        );
        write_counter(
            out,
            "safe_http_replay_dial_started_total",
            "Secondary dials started for a silence replay",
            self.dial_started.load(Ordering::Relaxed),
        );
        write_counter(
            out,
            "safe_http_replay_dial_failed_total",
            "Secondary dials (or GET sends) that failed",
            self.dial_failed.load(Ordering::Relaxed),
        );
        write_counter(
            out,
            "safe_http_replay_request_sent_total",
            "GET headers sent on a secondary leg",
            self.request_sent.load(Ordering::Relaxed),
        );
        write_counter_labeled(
            out,
            "safe_http_replay_winner_total",
            "First-response-byte race winner, by leg",
            "leg",
            "primary",
            self.winner_primary.load(Ordering::Relaxed),
        );
        write_counter_labeled(
            out,
            "safe_http_replay_winner_total",
            "First-response-byte race winner, by leg",
            "leg",
            "secondary",
            self.winner_secondary.load(Ordering::Relaxed),
        );
        write_counter(
            out,
            "hedge_secondary_wins_total",
            "Secondary legs that produced the first response byte: a race win, not yet proven a rescue",
            self.secondary_wins.load(Ordering::Relaxed),
        );
        write_counter(
            out,
            "safe_http_replay_both_legs_responded_total",
            "Races where both legs produced a response byte",
            self.both_legs_responded.load(Ordering::Relaxed),
        );
    }

    /// Hedge-loser observation outcomes (fix12): what the losing
    /// primary did after the secondary won, and the proven-rescue
    /// rate behind them. `true_rescue_rate =
    /// hedge_primary_deadline_miss_total /
    /// safe_http_replay_request_sent_total`;
    /// `latency-only_win_rate = hedge_primary_late_response_total /
    /// safe_http_replay_request_sent_total`. The latency sum divided
    /// by `hedge_primary_late_response_total` is the mean late
    /// latency of the primaries that answered.
    fn render_hedge(&self, out: &mut String) {
        write_counter(
            out,
            "hedge_primary_late_response_total",
            "Losing primaries that answered before their deadline: slow, not dead, no penalty",
            self.late_response.load(Ordering::Relaxed),
        );
        write_counter(
            out,
            "hedge_primary_transport_failure_total",
            "Losing primaries that closed or reset before answering",
            self.transport_failure.load(Ordering::Relaxed),
        );
        write_counter(
            out,
            "hedge_primary_deadline_miss_total",
            "Losing primaries that stayed silent until their deadline: proven blackholes",
            self.deadline_miss.load(Ordering::Relaxed),
        );
        write_counter(
            out,
            "hedge_true_rescues_total",
            "Secondary wins where the primary missed its deadline: the only proven rescues",
            self.true_rescues.load(Ordering::Relaxed),
        );
        write_counter(
            out,
            "hedge_unobserved_loser_total",
            "Secondary wins whose loser could not be observed at all: no penalty charged",
            self.unobserved_loser.load(Ordering::Relaxed),
        );
        write_counter(
            out,
            "hedge_primary_response_latency_ms_total",
            "Sum of observed late-response latencies in milliseconds (mean = this / hedge_primary_late_response_total)",
            self.primary_response_latency_ms_sum.load(Ordering::Relaxed),
        );
        write_counter_labeled(
            out,
            "tunnel_blackhole_ejections_total",
            "Tunnels ejected by the blackhole penalty, by the path that charged them",
            "reason",
            BlackholeEjectionReason::DeadlineMiss.label(),
            self.blackhole_ejections_deadline_miss
                .load(Ordering::Relaxed),
        );
        write_counter_labeled(
            out,
            "tunnel_blackhole_ejections_total",
            "Tunnels ejected by the blackhole penalty, by the path that charged them",
            "reason",
            BlackholeEjectionReason::ZeroResponseRetry.label(),
            self.blackhole_ejections_zero_response_retry
                .load(Ordering::Relaxed),
        );
        write_counter_labeled(
            out,
            "tunnel_blackhole_ejections_total",
            "Tunnels ejected by the blackhole penalty, by the path that charged them",
            "reason",
            BlackholeEjectionReason::SessionEnd.label(),
            self.blackhole_ejections_session_end.load(Ordering::Relaxed),
        );
    }

    /// Shared post-send token claims, by mechanism.
    fn render_claimed(&self, out: &mut String) {
        write_counter_labeled(
            out,
            "post_send_replay_claimed_total",
            "Shared post-send replay tokens claimed, by mechanism",
            "source",
            ReplaySource::Fix5.label(),
            self.claimed_fix5.load(Ordering::Relaxed),
        );
        write_counter_labeled(
            out,
            "post_send_replay_claimed_total",
            "Shared post-send replay tokens claimed, by mechanism",
            "source",
            ReplaySource::SilenceReplay.label(),
            self.claimed_silence.load(Ordering::Relaxed),
        );
    }
}

static REPLAY_METRICS: ReplayMetrics = ReplayMetrics::new();

/// The process-wide replay counters (tests read them, the admin
/// `/metrics` endpoint renders them).
pub(crate) fn replay_metrics() -> &'static ReplayMetrics {
    &REPLAY_METRICS
}

/// Append the replay counters to a Prometheus exposition string.
pub(crate) fn write_replay_metrics(out: &mut String) {
    REPLAY_METRICS.render(out);
}

fn write_counter(out: &mut String, name: &str, help: &str, value: u64) {
    let _ = writeln!(out, "# HELP {name} {help}");
    let _ = writeln!(out, "# TYPE {name} counter");
    let _ = writeln!(out, "{name} {value}");
}

fn write_counter_labeled(
    out: &mut String,
    name: &str,
    help: &str,
    label_name: &str,
    label_value: &str,
    value: u64,
) {
    let _ = writeln!(out, "# HELP {name} {help}");
    let _ = writeln!(out, "# TYPE {name} counter");
    let _ = writeln!(out, "{name}{{{label_name}=\"{label_value}\"}} {value}");
}

/// Serialiser for the tests that touch the replay counters: the
/// counters are process-global and nextest runs the tests in one
/// binary in parallel threads, so a test that asserts on a counter
/// delta must hold this for its whole duration, and every other
/// test that can move the same counters must hold it too (even
/// when it asserts nothing). A `tokio::sync::Mutex` is used
/// deliberately so it may be held across awaits.
#[cfg(test)]
pub(crate) static REPLAY_TEST_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

/// Reset the replay counters and the global budget. Tests only:
/// call it while holding [`REPLAY_TEST_LOCK`], before the test
/// body, so no other test's increments land in this test's delta.
#[cfg(test)]
pub(crate) fn reset_replay_state_for_tests() {
    REPLAY_METRICS.eligible.store(0, Ordering::Relaxed);
    REPLAY_METRICS
        .suppressed_ineligible
        .store(0, Ordering::Relaxed);
    REPLAY_METRICS
        .suppressed_token_claimed
        .store(0, Ordering::Relaxed);
    REPLAY_METRICS.suppressed_budget.store(0, Ordering::Relaxed);
    REPLAY_METRICS
        .suppressed_response_started
        .store(0, Ordering::Relaxed);
    REPLAY_METRICS
        .suppressed_no_tunnel
        .store(0, Ordering::Relaxed);
    REPLAY_METRICS
        .suppressed_client_gone
        .store(0, Ordering::Relaxed);
    REPLAY_METRICS
        .suppressed_client_sent_more
        .store(0, Ordering::Relaxed);
    REPLAY_METRICS.silence_trigger.store(0, Ordering::Relaxed);
    REPLAY_METRICS.dial_started.store(0, Ordering::Relaxed);
    REPLAY_METRICS.dial_failed.store(0, Ordering::Relaxed);
    REPLAY_METRICS.request_sent.store(0, Ordering::Relaxed);
    REPLAY_METRICS.winner_primary.store(0, Ordering::Relaxed);
    REPLAY_METRICS.winner_secondary.store(0, Ordering::Relaxed);
    REPLAY_METRICS.secondary_wins.store(0, Ordering::Relaxed);
    REPLAY_METRICS
        .both_legs_responded
        .store(0, Ordering::Relaxed);
    REPLAY_METRICS.late_response.store(0, Ordering::Relaxed);
    REPLAY_METRICS.transport_failure.store(0, Ordering::Relaxed);
    REPLAY_METRICS.deadline_miss.store(0, Ordering::Relaxed);
    REPLAY_METRICS.true_rescues.store(0, Ordering::Relaxed);
    REPLAY_METRICS.unobserved_loser.store(0, Ordering::Relaxed);
    REPLAY_METRICS
        .primary_response_latency_ms_sum
        .store(0, Ordering::Relaxed);
    REPLAY_METRICS
        .blackhole_ejections_deadline_miss
        .store(0, Ordering::Relaxed);
    REPLAY_METRICS
        .blackhole_ejections_zero_response_retry
        .store(0, Ordering::Relaxed);
    REPLAY_METRICS
        .blackhole_ejections_session_end
        .store(0, Ordering::Relaxed);
    REPLAY_METRICS.claimed_fix5.store(0, Ordering::Relaxed);
    REPLAY_METRICS.claimed_silence.store(0, Ordering::Relaxed);
    let mut budget = REPLAY_BUDGET.lock();
    budget.tokens = REPLAY_BUCKET_CAPACITY;
    budget.requests_since_refill = 0;
    budget.concurrent = 0;
}

/// How many replay concurrency slots are held right now. Tests
/// only: proves the slot stays held while a hedge loser is being
/// observed, and is released when the observation ends.
#[cfg(test)]
pub(crate) fn replay_budget_concurrent_for_tests() -> u32 {
    REPLAY_BUDGET.lock().concurrent
}

/// The result of positively parsing the buffered client prefix as a
/// safe HTTP GET request head. Never infer HTTP from the port alone:
/// only a request that parses under these rules may be replayed.
pub(crate) enum SafeGetParse {
    /// A complete eligible GET: the header bytes (up to and
    /// including the `\r\n\r\n` terminator) to replay verbatim.
    Eligible(Arc<[u8]>),
    /// The buffered bytes are not, and cannot become, an eligible
    /// GET: wrong method, a body, an upgrade, a header over the cap,
    /// or malformed framing.
    Ineligible,
    /// The buffered bytes may still become an eligible GET once more
    /// bytes arrive (no terminator yet, header still under the cap).
    Incomplete,
}

const fn is_token_char(b: u8) -> bool {
    b.is_ascii_alphanumeric()
        || matches!(
            b,
            b'!' | b'#'
                | b'$'
                | b'%'
                | b'&'
                | b'\''
                | b'*'
                | b'+'
                | b'-'
                | b'.'
                | b'^'
                | b'_'
                | b'`'
                | b'|'
                | b'~'
        )
}

/// Positively parse `bytes` (the buffered client prefix, first
/// request first) as a bodyless plaintext HTTP GET. All of these
/// must hold: HTTP/1.0 or HTTP/1.1, method exactly `GET`, a complete
/// `\r\n\r\n` terminator, header at most
/// [`SAFE_GET_MAX_HEADER_BYTES`], no `Transfer-Encoding`, no
/// `Content-Length` other than exactly `0` (and at most one of it),
/// no `Expect`, no `Upgrade`, no `Connection: upgrade`, no body and
/// no streaming upload. Anything else — TLS ClientHello, POST, a
/// binary blob, a header that only looks like one — is
/// [`SafeGetParse::Ineligible`], never replayed. Only the header
/// bytes are returned; a pipelined second request is not part of the
/// replay.
pub(crate) fn parse_safe_http_get_header(bytes: &[u8]) -> SafeGetParse {
    // Only the first SAFE_GET_MAX_HEADER_BYTES can hold an eligible
    // header: a terminator past the cap makes the request ineligible
    // without scanning the whole (up to 64 KiB) prefix.
    let search_len = SAFE_GET_MAX_HEADER_BYTES.min(bytes.len());
    let Some(head) = bytes.get(..search_len) else {
        return SafeGetParse::Incomplete;
    };
    let Some(term) = head.windows(4).position(|w| w == b"\r\n\r\n") else {
        return if bytes.len() > SAFE_GET_MAX_HEADER_BYTES {
            SafeGetParse::Ineligible
        } else {
            SafeGetParse::Incomplete
        };
    };
    let header_end = term + 4;
    let Some(header) = bytes.get(..header_end) else {
        return SafeGetParse::Incomplete;
    };
    // The header must be text, with no control bytes other than the
    // line endings (and tab inside a header value): a binary blob is
    // not a GET, however it starts.
    if header
        .iter()
        .any(|&b| (b < 0x20 && !matches!(b, b'\t' | b'\r' | b'\n')) || b == 0x7f)
    {
        return SafeGetParse::Ineligible;
    }
    let Ok(text) = std::str::from_utf8(header) else {
        return SafeGetParse::Ineligible;
    };
    let Some((request_line, rest)) = text.split_once("\r\n") else {
        return SafeGetParse::Ineligible;
    };
    // Request line: exactly `GET <target> HTTP/1.0|HTTP/1.1`.
    let mut parts = request_line.split(' ');
    let (Some(method), Some(target), Some(version)) = (parts.next(), parts.next(), parts.next())
    else {
        return SafeGetParse::Ineligible;
    };
    if parts.next().is_some() {
        return SafeGetParse::Ineligible;
    }
    if method != "GET"
        || target.is_empty()
        || target == "*"
        || target.bytes().any(|b| b < 0x21 || b == 0x7f)
        || (version != "HTTP/1.0" && version != "HTTP/1.1")
    {
        return SafeGetParse::Ineligible;
    }
    // Header lines: each `Name: value`, no bare CR/LF, no empty line
    // except the terminating blank line.
    let mut content_length: Option<u64> = None;
    let mut saw_blank = false;
    for line in rest.split("\r\n") {
        if line.is_empty() {
            saw_blank = true;
            continue;
        }
        if saw_blank || line.contains(['\r', '\n']) {
            return SafeGetParse::Ineligible;
        }
        let Some((name, value)) = line.split_once(':') else {
            return SafeGetParse::Ineligible;
        };
        if name.is_empty() || !name.bytes().all(is_token_char) {
            return SafeGetParse::Ineligible;
        }
        match name.to_ascii_lowercase().as_str() {
            "transfer-encoding" | "expect" | "upgrade" => return SafeGetParse::Ineligible,
            "content-length" => {
                if content_length.is_some() {
                    return SafeGetParse::Ineligible;
                }
                let Ok(len) = value.trim().parse::<u64>() else {
                    return SafeGetParse::Ineligible;
                };
                if len != 0 {
                    return SafeGetParse::Ineligible;
                }
                content_length = Some(len);
            }
            "connection"
                if value
                    .split(',')
                    .any(|token| token.trim().eq_ignore_ascii_case("upgrade")) =>
            {
                return SafeGetParse::Ineligible;
            }
            _ => {}
        }
    }
    SafeGetParse::Eligible(Arc::from(header))
}

/// Owned dial context for a post-send replay: everything a re-dial
/// needs, cloned from the handler's ZeroResponseRetry at session
/// start so the silence replay can dial from a spawned task, where
/// the handler's borrows do not live. The session builder (in the
/// parent module) fills this in.
pub(crate) struct ReplayDialCtx {
    pub(crate) router: Arc<dyn TunnelRouter>,
    pub(crate) selector: TunnelSelector,
    pub(crate) target: TargetAddr,
    pub(crate) credentials: Option<(String, String)>,
    pub(crate) protocol: &'static str,
}

/// The replay phase, for the epoch loop's timer guard: the timer
/// only fires while `Armed`, and the phase only moves forward.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum SilencePhase {
    /// No eligible GET seen yet (or the request is ineligible).
    Idle,
    /// An eligible GET header was written to the primary; the 2.5 s
    /// timer is running.
    Armed,
    /// The secondary dial task is running.
    Dialing,
    /// Both legs are alive and the first response byte wins.
    Racing,
    /// The replay resolved (won, lost, suppressed, or failed): the
    /// shared token is spent and the timer never re-fires.
    Done,
}

/// Per-session state of the one delayed silence replay.
pub(crate) struct SilenceReplay {
    /// Whether the buffered prefix has been examined for a safe GET
    /// header: once decided (eligible or not) it is not re-examined.
    pub(crate) checked: bool,
    /// The complete eligible GET header, once positively parsed.
    pub(crate) header: Option<Arc<[u8]>>,
    /// When the complete GET header was written to the primary
    /// tunnel: the 2.5 s silence timer runs from here.
    pub(crate) header_written_at: Option<Instant>,
    /// When the 2.5 s silence timer fired: the decision point the
    /// fix13 diagnostic record is anchored to. Set once, in
    /// `start_silence_replay`, the only path out of `Armed`.
    pub(crate) trigger_fired_at: Option<Instant>,
    /// The replay phase.
    pub(crate) phase: SilencePhase,
    /// Whether this session holds a slot in the global replay
    /// budget (released exactly once, when the replay resolves or
    /// the session ends).
    pub(crate) budget_held: bool,
    /// Shared race state, also visible to the tunnel-to-client
    /// reader (header-length guard, winner, timings).
    pub(crate) shared: Arc<RaceShared>,
}

impl SilenceReplay {
    pub(crate) fn new() -> Self {
        Self {
            checked: false,
            header: None,
            header_written_at: None,
            trigger_fired_at: None,
            phase: SilencePhase::Idle,
            budget_held: false,
            shared: Arc::new(RaceShared::new()),
        }
    }

    /// How long until the silence timer fires (zero once due).
    pub(crate) fn delay_until_firing(&self) -> Duration {
        self.header_written_at.map_or(Duration::ZERO, |written| {
            SILENCE_REPLAY_DELAY.saturating_sub(written.elapsed())
        })
    }
}

/// Race winner codes, stored in [`RaceShared::winner`].
pub(crate) const RACE_UNDECIDED: u8 = 0;
pub(crate) const RACE_PRIMARY: u8 = 1;
pub(crate) const RACE_SECONDARY: u8 = 2;
pub(crate) const RACE_SECONDARY_FAILED: u8 = 3;

/// Replay timings, for the resolution log lines: when the secondary
/// dial started and connected, when each leg produced its first
/// response byte, and which tunnel the secondary is on. (The primary
/// header-written time lives on the session state, not here.)
#[derive(Default)]
pub(crate) struct ReplayTimings {
    pub(crate) dial_started_at: Option<Instant>,
    pub(crate) dial_connected_at: Option<Instant>,
    /// When the GET header was written to the secondary leg: the
    /// second of the four hedge timestamps (the other three are the
    /// primary header-written time, the secondary first byte, and
    /// the primary first byte the observer records).
    pub(crate) secondary_request_sent_at: Option<Instant>,
    pub(crate) primary_first_byte_at: Option<Instant>,
    pub(crate) secondary_first_byte_at: Option<Instant>,
    pub(crate) secondary_tunnel_id: Option<String>,
}

/// State shared between the epoch loop and the tunnel-to-client race
/// reader: the GET header length (the reader's "client sent nothing
/// past the header" guard), the race winner, and the timings. The
/// mutex is held only for brief synchronous reads/writes, never
/// across an await.
pub(crate) struct RaceShared {
    pub(crate) header_len: AtomicUsize,
    pub(crate) winner: AtomicU8,
    pub(crate) timings: Mutex<ReplayTimings>,
}

impl RaceShared {
    const fn new() -> Self {
        Self {
            header_len: AtomicUsize::new(0),
            winner: AtomicU8::new(RACE_UNDECIDED),
            timings: Mutex::new(ReplayTimings {
                dial_started_at: None,
                dial_connected_at: None,
                secondary_request_sent_at: None,
                primary_first_byte_at: None,
                secondary_first_byte_at: None,
                secondary_tunnel_id: None,
            }),
        }
    }
}

/// One dialed secondary leg: the stream, which tunnel it is on, and
/// when the dial started and connected (for the replay latency
/// metrics). Handed to the race reader once the GET header is sent.
pub(crate) struct SecondaryLeg {
    pub(crate) stream: DynStream,
    pub(crate) tunnel_id: Option<String>,
    pub(crate) dial_started_at: Instant,
    pub(crate) dial_connected_at: Instant,
}

/// What the secondary dial task found.
pub(crate) enum ReplayDialOutcome {
    /// Dialed, GET sent: hand the leg to the race reader.
    Ready(SecondaryLeg),
    /// The replay is moot: the primary answered, or the client sent
    /// past the GET header, while the dial was in flight.
    Suppressed(SuppressReason),
    /// No tunnel other than the primary exists to re-dial through.
    NoTunnel,
    /// The dial (or the GET send) failed: leave the primary alive.
    Failed(RouterConnectError),
}

/// Dial one different tunnel and send the buffered GET header on it:
/// the secondary leg of a silence replay. Runs as a spawned task so
/// the epoch loop keeps reading the primary while the dial is in
/// flight. The primary is re-checked right before the send — if it
/// answered while the dial was in flight, the replay is moot and the
/// dialed stream is dropped without sending.
pub(crate) async fn dial_secondary_leg(
    ctx: Arc<ReplayDialCtx>,
    exclude_tunnel: Option<String>,
    header: Arc<[u8]>,
    tunnel_bytes: Arc<AtomicU64>,
    client_bytes: Arc<AtomicU64>,
    shared: Arc<RaceShared>,
) -> ReplayDialOutcome {
    let started = Instant::now();
    let credentials = ctx
        .credentials
        .as_ref()
        .map(|(user, pass)| (user.as_str(), pass.as_str()));
    let dialed = connect_direct(
        &ctx.router,
        &ctx.selector,
        &ctx.target,
        credentials,
        exclude_tunnel.as_deref(),
    )
    .await;
    let (mut stream, tunnel_id) = match dialed {
        Ok(pair) => pair,
        Err(RouterConnectError::SelectTunnel(e)) if e.kind() == io::ErrorKind::NotConnected => {
            return ReplayDialOutcome::NoTunnel;
        }
        Err(e) => return ReplayDialOutcome::Failed(e),
    };
    let connected = Instant::now();
    // The primary answered while the dial was in flight: the replay
    // is moot — do not send the request to a second origin.
    if tunnel_bytes.load(Ordering::Relaxed) > 0 {
        return ReplayDialOutcome::Suppressed(SuppressReason::ResponseStarted);
    }
    // The client sent more than the GET header while the dial was in
    // flight: those bytes already went to the primary, and a
    // secondary win would lose them — do not send.
    let header_len = shared.header_len.load(Ordering::Relaxed);
    if client_bytes.load(Ordering::Relaxed) > header_len as u64 {
        return ReplayDialOutcome::Suppressed(SuppressReason::ClientSentMore);
    }
    let send = async {
        stream.write_all(&header).await?;
        stream.flush().await
    };
    match send.await {
        Ok(()) => {
            // The GET is on the secondary: record when, for the
            // hedge timestamps (the observer logs all four).
            shared.timings.lock().secondary_request_sent_at = Some(Instant::now());
            ReplayDialOutcome::Ready(SecondaryLeg {
                stream,
                tunnel_id,
                dial_started_at: started,
                dial_connected_at: connected,
            })
        }
        Err(e) => ReplayDialOutcome::Failed(RouterConnectError::TcpConnect(e)),
    }
}

/// What the tunnel-to-client race reader stopped on.
pub(crate) enum RaceReaderDone {
    /// The primary tunnel closed (EOF): the epoch ends as before.
    PrimaryClosed,
    /// The primary tunnel reset: the fix5 trigger (gated by the
    /// shared replay token and the tightened eligibility rule).
    /// Carries the original read error, so the epoch can end as
    /// `Failed` with it when no retry fires.
    PrimaryReset(io::Error),
    /// The copy failed with an I/O error on the primary leg (or a
    /// failed write to the client).
    PrimaryFailed(io::Error),
    /// The secondary leg produced the first response byte: the
    /// session continues on the secondary stream.
    SecondaryWon(SecondaryWin),
}

/// A secondary win: the leg that won, and when its first response
/// byte arrived (for the rescue latency metrics).
pub(crate) struct SecondaryWin {
    pub(crate) leg: SecondaryLeg,
    pub(crate) first_byte_at: Instant,
}

/// Inputs to the tunnel-to-client race reader, bundled so the
/// constructor stays under the argument limit.
pub(crate) struct RaceReaderArgs<'a, A, B> {
    pub(crate) client_write: tokio::io::WriteHalf<&'a mut A>,
    pub(crate) primary_read: tokio::io::ReadHalf<&'a mut B>,
    pub(crate) secondary_rx: oneshot::Receiver<SecondaryLeg>,
    pub(crate) activity: tokio::sync::watch::Sender<u64>,
    pub(crate) tunnel_bytes: Arc<AtomicU64>,
    pub(crate) client_bytes: Arc<AtomicU64>,
    pub(crate) shared: Arc<RaceShared>,
}

/// The tunnel-to-client direction, which can also race a secondary
/// upstream leg once a silence replay is in flight. It owns the
/// client write half and the primary read half (the same halves the
/// plain direction owned), plus a oneshot receiver through which the
/// epoch loop hands it the dialed secondary leg. One future reads
/// both legs, so no lock sits on the hot path: the first response
/// byte wins, the loser is closed at once, and the session never
/// sees two responses interleaved.
///
/// The primary is preferred on ties (`biased` select): a primary
/// byte that arrived while the secondary was being dialled means the
/// primary was never a blackhole, so it must win and must not be
/// charged one.
pub(crate) struct UpstreamRaceReader<'a, A, B> {
    client_write: tokio::io::WriteHalf<&'a mut A>,
    primary_read: tokio::io::ReadHalf<&'a mut B>,
    secondary_rx: Option<oneshot::Receiver<SecondaryLeg>>,
    secondary: Option<SecondaryLeg>,
    activity: tokio::sync::watch::Sender<u64>,
    tunnel_bytes: Arc<AtomicU64>,
    client_bytes: Arc<AtomicU64>,
    shared: Arc<RaceShared>,
    primary_responded: bool,
    secondary_responded: bool,
}

impl<'a, A, B> UpstreamRaceReader<'a, A, B>
where
    A: AsyncRead + AsyncWrite + Unpin,
    B: AsyncRead + AsyncWrite + Unpin,
{
    pub(crate) fn new(args: RaceReaderArgs<'a, A, B>) -> Self {
        Self {
            client_write: args.client_write,
            primary_read: args.primary_read,
            secondary_rx: Some(args.secondary_rx),
            secondary: None,
            activity: args.activity,
            tunnel_bytes: args.tunnel_bytes,
            client_bytes: args.client_bytes,
            shared: args.shared,
            primary_responded: false,
            secondary_responded: false,
        }
    }

    /// Run until the primary closes, fails, or the secondary wins
    /// the first-response-byte race. Returning on a secondary win
    /// ends the epoch, so the session switches to the secondary leg
    /// (the client-to-tunnel direction must follow it, and it owns
    /// the primary write half the epoch is about to drop).
    pub(crate) async fn run(mut self) -> RaceReaderDone {
        enum Read {
            Primary(io::Result<usize>),
            Secondary(io::Result<usize>),
            Arrived(Result<SecondaryLeg, oneshot::error::RecvError>),
        }
        // Heap buffers: an 8 KiB stack buffer would push this future
        // (and every caller awaiting it) past the large-future
        // threshold.
        let mut buf_p = Box::new([0u8; 8192]);
        let mut buf_s = Box::new([0u8; 8192]);
        loop {
            let read = tokio::select! {
                biased;
                res = self.primary_read.read(&mut buf_p[..]) => Read::Primary(res),
                res = async {
                    match self.secondary.as_mut() {
                        Some(leg) => leg.stream.read(&mut buf_s[..]).await,
                        None => std::future::pending().await,
                    }
                } => Read::Secondary(res),
                res = async {
                    match self.secondary_rx.as_mut() {
                        Some(rx) => rx.await,
                        None => std::future::pending().await,
                    }
                } => Read::Arrived(res),
            };
            let done = match read {
                Read::Primary(Ok(n)) => {
                    let Some(chunk) = buf_p.get(..n) else {
                        return RaceReaderDone::PrimaryFailed(io::Error::new(
                            io::ErrorKind::InvalidData,
                            "relay read overran its buffer",
                        ));
                    };
                    self.on_primary(chunk).await
                }
                Read::Primary(Err(e)) => Some(Self::on_primary_err(e)),
                Read::Secondary(Ok(n)) => {
                    let Some(chunk) = buf_s.get(..n) else {
                        return RaceReaderDone::PrimaryFailed(io::Error::new(
                            io::ErrorKind::InvalidData,
                            "relay read overran its buffer",
                        ));
                    };
                    self.on_secondary(chunk).await
                }
                Read::Secondary(Err(e)) => self.on_secondary_err(&e),
                Read::Arrived(res) => {
                    self.on_secondary_arrived(res);
                    None
                }
            };
            if let Some(done) = done {
                return done;
            }
        }
    }

    /// Forward one primary chunk to the client. The first response
    /// byte decides the race when a secondary leg is racing: the
    /// primary answered first, so the secondary (which may already
    /// hold the request) is closed at once and the session continues
    /// on the primary.
    async fn on_primary(&mut self, chunk: &[u8]) -> Option<RaceReaderDone> {
        if chunk.is_empty() {
            return Some(RaceReaderDone::PrimaryClosed);
        }
        if let Err(e) = self.client_write.write_all(chunk).await {
            return Some(RaceReaderDone::PrimaryFailed(e));
        }
        self.tunnel_bytes
            .fetch_add(chunk.len() as u64, Ordering::Relaxed);
        self.activity.send_modify(|count| *count += 1);
        if !self.primary_responded {
            self.primary_responded = true;
            self.shared.timings.lock().primary_first_byte_at = Some(Instant::now());
            if self.secondary_responded {
                REPLAY_METRICS.inc_both_legs_responded();
            }
            if self.secondary.is_some() {
                self.note_primary_win();
            }
        }
        None
    }

    fn on_primary_err(e: io::Error) -> RaceReaderDone {
        if e.kind() == io::ErrorKind::ConnectionReset {
            RaceReaderDone::PrimaryReset(e)
        } else {
            RaceReaderDone::PrimaryFailed(e)
        }
    }

    /// Forward one secondary chunk to the client. Only the first
    /// response byte is ever forwarded: it wins the race and the
    /// reader returns, so the epoch switches the session to the
    /// secondary leg. A secondary byte is only forwarded when the
    /// client sent nothing past the GET header — otherwise those
    /// bytes already went to the primary and a secondary win would
    /// lose them, so the secondary is dropped and the primary wins.
    async fn on_secondary(&mut self, chunk: &[u8]) -> Option<RaceReaderDone> {
        if chunk.is_empty() {
            // The secondary closed without answering: it failed, the
            // primary continues, and the replay is over.
            self.secondary = None;
            self.shared
                .winner
                .store(RACE_SECONDARY_FAILED, Ordering::Relaxed);
            return None;
        }
        if !self.secondary_may_win() {
            self.note_primary_win();
            return None;
        }
        if let Err(e) = self.client_write.write_all(chunk).await {
            return Some(RaceReaderDone::PrimaryFailed(e));
        }
        self.tunnel_bytes
            .fetch_add(chunk.len() as u64, Ordering::Relaxed);
        self.activity.send_modify(|count| *count += 1);
        if !self.secondary_responded {
            self.secondary_responded = true;
            if self.primary_responded {
                REPLAY_METRICS.inc_both_legs_responded();
            }
        }
        let first_byte_at = Instant::now();
        self.shared.timings.lock().secondary_first_byte_at = Some(first_byte_at);
        let leg = self.secondary.take()?;
        self.shared.winner.store(RACE_SECONDARY, Ordering::Relaxed);
        Some(RaceReaderDone::SecondaryWon(SecondaryWin {
            leg,
            first_byte_at,
        }))
    }

    /// The secondary leg failed to read: drop it, the primary
    /// continues, and the replay is over.
    fn on_secondary_err(&mut self, e: &io::Error) -> Option<RaceReaderDone> {
        tracing::debug!("silence replay secondary leg failed: {e}");
        self.secondary = None;
        self.shared
            .winner
            .store(RACE_SECONDARY_FAILED, Ordering::Relaxed);
        None
    }

    /// Record when the secondary dial started and connected, and
    /// which tunnel it is on, for the resolution log lines.
    fn record_dial_timings(&self, leg: &SecondaryLeg) {
        let mut timings = self.shared.timings.lock();
        timings.dial_started_at = Some(leg.dial_started_at);
        timings.dial_connected_at = Some(leg.dial_connected_at);
        timings.secondary_tunnel_id.clone_from(&leg.tunnel_id);
    }

    /// The dial task handed over a secondary leg (GET already sent).
    /// If the primary already answered, the race is over before it
    /// started: drop the leg at once. Otherwise record the dial
    /// timings and start racing it.
    fn on_secondary_arrived(&mut self, res: Result<SecondaryLeg, oneshot::error::RecvError>) {
        let Ok(leg) = res else {
            // The epoch ended (or the dial was never started): no
            // secondary will arrive.
            self.secondary_rx = None;
            return;
        };
        self.secondary_rx = None;
        self.record_dial_timings(&leg);
        if self.primary_responded {
            // The primary answered while the dial was in flight (or
            // just before the leg arrived): it wins, and the leg is
            // closed without ever racing.
            self.note_primary_win();
            return;
        }
        self.secondary = Some(leg);
    }

    /// Whether the secondary may win the race: the client must have
    /// sent nothing past the GET header (those bytes already went to
    /// the primary), and a header must have been detected at all.
    fn secondary_may_win(&self) -> bool {
        let header_len = self.shared.header_len.load(Ordering::Relaxed);
        header_len > 0 && self.client_bytes.load(Ordering::Relaxed) <= header_len as u64
    }

    /// The primary wins the race (or the secondary is ineligible to
    /// win): close the secondary at once and record the winner so
    /// the epoch loop releases the replay budget.
    fn note_primary_win(&mut self) {
        self.shared.winner.store(RACE_PRIMARY, Ordering::Relaxed);
        self.secondary = None;
    }
}

/// What the hedge-loser observation found about the primary that
/// lost the first-response-byte race. Only `DeadlineMiss` charges
/// the blackhole penalty: a late answer proves the tunnel was slow,
/// and a close/reset proves its connection died — neither proves it
/// was silently blackholing.
pub(crate) enum HedgeLoserOutcome {
    /// The primary answered before the deadline: slow, not dead.
    /// Carries when its first response byte arrived, so the
    /// observed latency can feed the EWMA.
    LateResponse { first_byte_at: Instant },
    /// The primary closed (EOF) or reset before answering.
    TransportFailure,
    /// The primary stayed silent until the deadline: a proven
    /// blackhole.
    DeadlineMiss,
}

/// Everything the hedge-loser observer needs, bundled so the spawn
/// call stays under the argument limit. The primary stream itself
/// travels separately (it is moved into the spawned task).
pub(crate) struct HedgeLoserCtx {
    pub(crate) router: Arc<dyn TunnelRouter>,
    pub(crate) primary_tunnel_id: String,
    /// The session the loser belongs to, so the observer verdict
    /// joins the same request's trigger and race records.
    pub(crate) request_id: u64,
    /// When the request was forwarded to the primary: the anchor
    /// for the deadline and for all four hedge timestamps.
    pub(crate) primary_request_forwarded_at: Instant,
    pub(crate) secondary_request_forwarded_at: Option<Instant>,
    pub(crate) secondary_first_response_at: Instant,
}

/// Observe the losing primary until it answers, dies, or the
/// deadline passes. Only a 1-byte read: the response bytes are
/// never forwarded or parsed, they only prove the tunnel was alive.
/// Awaiting one byte in Tokio is cheap — no polling loop — and the
/// read is bounded by the deadline, so the observation always ends.
pub(crate) async fn classify_hedge_loser(
    primary: &mut DynStream,
    deadline: Instant,
) -> HedgeLoserOutcome {
    let mut probe = [0u8; 1];
    match tokio::time::timeout_at(deadline.into(), primary.read(&mut probe)).await {
        Ok(Ok(n)) if n > 0 => HedgeLoserOutcome::LateResponse {
            first_byte_at: Instant::now(),
        },
        Ok(Ok(_) | Err(_)) => HedgeLoserOutcome::TransportFailure,
        Err(_) => HedgeLoserOutcome::DeadlineMiss,
    }
}

/// Apply one observation: the penalty (or none) the losing primary
/// earned, the hedge counters, and one structured log line carrying
/// all four hedge timestamps as millisecond offsets from when the
/// request was forwarded to the primary (bounded numbers, never
/// unbounded labels).
pub(crate) fn apply_hedge_loser_outcome(ctx: &HedgeLoserCtx, outcome: &HedgeLoserOutcome) {
    let metrics = replay_metrics();
    let primary_first_ms = match outcome {
        HedgeLoserOutcome::LateResponse { first_byte_at } => {
            // Slow, not dead: no breaker charge. The observed
            // first-byte latency feeds the Peak-EWMA, so the
            // selector learns the tunnel is slow instead of
            // treating it as dead.
            let latency = first_byte_at.saturating_duration_since(ctx.primary_request_forwarded_at);
            let latency_ms = u64::try_from(latency.as_millis()).unwrap_or(u64::MAX);
            ctx.router
                .record_tunnel_rtt(&ctx.primary_tunnel_id, latency_ms);
            metrics.inc_late_response();
            metrics.add_primary_response_latency_ms(latency_ms);
            metrics.inc_both_legs_responded();
            latency.as_millis()
        }
        HedgeLoserOutcome::TransportFailure => {
            // The connection died loudly: charge the transport
            // failure (breaker + RTT failure), not the blackhole
            // penalty — a dead connection is not a silent tunnel,
            // and it stays on the warm list.
            ctx.router
                .record_tunnel_transport_failure(&ctx.primary_tunnel_id);
            metrics.inc_transport_failure();
            0
        }
        HedgeLoserOutcome::DeadlineMiss => {
            // Silent until the deadline: the blackhole penalty, as
            // a proven blackhole — breaker, EWMA, warm-list removal.
            ctx.router.record_tunnel_blackhole(&ctx.primary_tunnel_id);
            metrics.inc_deadline_miss();
            metrics.inc_true_rescue();
            metrics.inc_blackhole_ejection(BlackholeEjectionReason::DeadlineMiss);
            0
        }
    };
    let outcome_label = match outcome {
        HedgeLoserOutcome::LateResponse { .. } => "late_response",
        HedgeLoserOutcome::TransportFailure => "transport_failure",
        HedgeLoserOutcome::DeadlineMiss => "deadline_miss",
    };
    tracing::info!(
        request_id = ctx.request_id,
        outcome = outcome_label,
        primary_tunnel = ctx.primary_tunnel_id.as_str(),
        primary_first_byte_ms = primary_first_ms,
        secondary_request_sent_ms = super::latency_ms(
            Some(ctx.primary_request_forwarded_at),
            ctx.secondary_request_forwarded_at
        ),
        secondary_first_response_ms = super::latency_ms(
            Some(ctx.primary_request_forwarded_at),
            Some(ctx.secondary_first_response_at)
        ),
        "hedge loser observed"
    );
}

/// Run one hedge-loser observation to its verdict, then release the
/// replay concurrency slot the win transferred to this task.
/// Exactly once: the slot is released here and nowhere else once
/// the session handed it over, and the observation always ends
/// (answer, close, or deadline), so the slot cannot leak.
async fn observe_hedge_loser(ctx: HedgeLoserCtx, primary: DynStream, deadline: Instant) {
    let mut primary = primary;
    let outcome = classify_hedge_loser(&mut primary, deadline).await;
    // The verdict is in: close the loser now, whatever it did.
    drop(primary);
    apply_hedge_loser_outcome(&ctx, &outcome);
    replay_budget_finish();
}

/// Spawn the hedge-loser observer for a primary that lost the race.
/// The task owns the primary stream, the router, and the replay
/// budget slot until the observation ends.
pub(crate) fn spawn_hedge_loser_observer(
    ctx: HedgeLoserCtx,
    primary: DynStream,
    deadline: Instant,
) {
    tokio::spawn(async move {
        observe_hedge_loser(ctx, primary, deadline).await;
    });
}
