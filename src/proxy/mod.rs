//! Proxy engines for `wpmulti`: SOCKS5 (RFC 1928, RFC 1929) and HTTP CONNECT (RFC 9110, RFC 7617).

pub mod http;
pub mod replay;
pub mod router;
pub mod socks5;
#[cfg(test)]
pub mod tests;

use std::io;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::{Duration, Instant};

use parking_lot::Mutex;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use replay::{
    PostSendReplayToken, RACE_PRIMARY, RACE_SECONDARY_FAILED, RaceReaderArgs, RaceReaderDone,
    ReplayDialCtx, ReplayDialOutcome, ReplaySource, SafeGetParse, SecondaryLeg, SilencePhase,
    SilenceReplay, SuppressReason, UpstreamRaceReader, dial_secondary_leg,
    parse_safe_http_get_header, replay_budget_finish, replay_budget_note_primary_request,
    replay_budget_try_start, replay_metrics,
};

pub use http::{
    extract_basic_auth, handle_http, parse_authority, read_http_request_headers,
    read_http_request_headers_buffered,
};
pub use router::{
    AsyncReadWrite, DirectTunnelTarget, DynStream, PoolKeyword, PoolRouter, ProxyAuthError,
    ProxyTunnelTarget, ProxyUdpSocket, SingleTunnelRouter, TargetAddr, TunnelRouter,
    TunnelSelector,
};
pub use socks5::{
    ATYP_DOMAIN, ATYP_IPV4, ATYP_IPV6, CMD_BIND, CMD_CONNECT, CMD_UDP_ASSOCIATE, METHOD_GSSAPI,
    METHOD_NO_ACCEPTABLE, METHOD_NO_AUTH, METHOD_USER_PASS, REP_ADDR_NOT_SUPPORTED,
    REP_CMD_NOT_SUPPORTED, REP_CONN_NOT_ALLOWED, REP_CONN_REFUSED, REP_GENERAL_FAILURE,
    REP_HOST_UNREACHABLE, REP_NETWORK_UNREACHABLE, REP_SUCCESS, REP_TTL_EXPIRED, RFC1929_VERSION,
    SOCKS5_VERSION, build_socks5_udp_packet, encode_target_addr, encode_target_addr_slice,
    handle_socks5, handle_socks5_with_addrs, parse_socks5_udp_packet, send_socks5_reply,
    write_socks5_udp_header,
};

const MAX_PROXY_CONCURRENT_CONNS: usize = 4096;

/// Idle timeout for an established CONNECT session (audit run-1,
/// `wpmulti/proxy:established-connect-no-idle-timeout`): 5 minutes
/// matches the lifecycle tunnel idle timeout and the UDP ASSOCIATE
/// relay's idle timeout. Without it an idle-but-open session holds a
/// listener permit and its tunnel's `active_conns` forever, so the
/// tunnel can never go idle either.
pub(crate) const CONNECT_IDLE_TIMEOUT: Duration = Duration::from_mins(5);

/// Silence after the client has sent its request after which a
/// client half-close is read as the client giving up on a silent
/// tunnel, not as a normal finish: the session is ended promptly as
/// [`CopyEndKind::ClientAborted`] instead of lingering until
/// [`CONNECT_IDLE_TIMEOUT`]. Well below the curl client's 15s
/// timeout (so the daemon's record lands first) and well above
/// normal first-byte latencies, so a fast half-close still ends the
/// old way.
pub(crate) const CLIENT_ABORT_SILENCE_THRESHOLD: Duration = Duration::from_millis(2500);

/// How a CONNECT copy session ended, for the session-end WARN and
/// for tunnel attribution: a session that ends with the client
/// having sent bytes and the tunnel none is a blackhole whatever the
/// mechanism, and the mechanism decides what the selector learns.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum CopyEndKind {
    /// The tunnel side ended the session (EOF / reset / error)
    /// after the session ran its course.
    TunnelClosed,
    /// No byte flowed in either direction for [`CONNECT_IDLE_TIMEOUT`].
    IdleTimeout,
    /// The client half-closed after sending its request and waiting
    /// longer than [`CLIENT_ABORT_SILENCE_THRESHOLD`] for a response
    /// that never came — the client gave up on a silent tunnel.
    ClientAborted,
    /// The copy failed with an I/O error.
    Failed,
    /// The HTTP forward path completed its (non-copy) session
    /// without an error — used for the fabricated forward outcome.
    Completed,
}

/// What a CONNECT copy session returned, plus how it ended and how
/// long it ran. Handlers log it with [`log_connect_session_end`] and
/// attribute blackhole sessions (client bytes sent, zero response)
/// to the serving tunnel.
pub(crate) struct ConnectSessionOutcome {
    pub(crate) result: io::Result<(u64, u64)>,
    pub(crate) kind: CopyEndKind,
    pub(crate) duration: Duration,
}

/// Log the end of an established CONNECT session at WARN when it
/// failed outright or ended without a usable response, so the next
/// measurement run can classify every "empty reply" failure from the
/// daemon log alone. Each WARN names how the session ended (`end`)
/// and how long it ran (`duration_ms`), so a session that only ends
/// when the client gives up on a silent tunnel is still
/// attributable to its tunnel and its ending.
///
/// The failure this catches is silent by construction: once the
/// SOCKS5 success reply (or HTTP 200) is sent, the outbound TCP is
/// already established, so a target that then closes the connection
/// with no data makes the tunnel stream return EOF — the copy ends
/// cleanly with `Ok`, the protocol handler returns `Ok`, and the
/// listener logs nothing at all. A 2000-request measurement showed
/// 21 such failures (~1%, ~0.25s each) with zero log lines. The
/// signature is a session where the client sent bytes
/// (`client_bytes > 0`) but the target sent none back
/// (`tunnel_bytes == 0`); a client that connects and leaves without
/// sending anything has both counts at zero and is not a failure.
/// Copy errors warn too, except timeouts — the listener already warns
/// on those, so logging them here would double-report one session.
/// (The CONNECT copy itself cannot produce `TimedOut`: neither
/// stream carries a read/write timeout — the only `TimedOut` in the
/// stack is the dial phase — so the exclusion guards only the
/// forward path, where the listener owns the timeout WARN.)
/// One WARN per failed session, never per chunk: at the measured ~1%
/// failure rate this is rare and actionable, not noise.
pub(crate) fn log_connect_session_end(
    protocol: &str,
    selector: &TunnelSelector,
    target: &TargetAddr,
    tunnel_id: Option<&str>,
    outcome: &ConnectSessionOutcome,
) {
    match &outcome.result {
        Ok((client_bytes, tunnel_bytes)) => {
            if *client_bytes > 0 && *tunnel_bytes == 0 {
                tracing::warn!(
                    protocol = protocol,
                    selector = ?selector,
                    target = %target,
                    tunnel_id = ?tunnel_id,
                    client_bytes = client_bytes,
                    end = ?outcome.kind,
                    duration_ms = outcome.duration.as_millis(),
                    "CONNECT session ended with no response bytes from target"
                );
            }
        }
        Err(e) => {
            if e.kind() != io::ErrorKind::TimedOut {
                tracing::warn!(
                    protocol = protocol,
                    selector = ?selector,
                    target = %target,
                    tunnel_id = ?tunnel_id,
                    end = ?outcome.kind,
                    duration_ms = outcome.duration.as_millis(),
                    "CONNECT session failed after grant: {e}"
                );
            }
        }
    }
}

/// Maximum client-sent prefix buffered for a transparent
/// zero-response retry: 64 KiB covers the observed failure (a 75-byte
/// HTTP GET) and any small request head, while bounding the
/// per-session memory the proxy holds for a retry that may never
/// happen. A client that sends more than this before the target
/// answers cannot be replayed in full, so its session is never
/// retried — the buffered prefix would be an incomplete request.
pub(crate) const ZERO_RESPONSE_RETRY_PREFIX_CAP: usize = 64 * 1024;

/// What a CONNECT session needs to re-dial through a different tunnel
/// after the first one closed the session with no response bytes.
///
/// The retry trades a small double-submit risk for eliminating the
/// observed 0.2-0.75% empty-reply failures: a zero-response EOF makes
/// it unlikely the target processed the request (no response was ever
/// delivered), but not impossible — the target may have processed it
/// and the response was lost. The same shape covers a tunnel-side
/// reset (`ConnectionReset` on the tunnel read) and a failed tunnel
/// write (`BrokenPipe` on the tunnel write): both end the session
/// with zero response bytes on the initial flight, before any
/// response byte arrived. Since fix11 the retry is only allowed when
/// no app byte was written upstream, or when the buffered prefix is
/// a positively identified safe HTTP GET (`parse_safe_http_get_header`
/// in `replay.rs`): opaque TLS and unclassified traffic are never
/// replayed after bytes were sent, because the origin may already
/// have processed them and the EOF does not prove otherwise. The
/// retry is therefore limited to the zero-response cases only (never
/// a timeout or a budget failure), to one attempt, and to sessions
/// whose whole client-sent prefix fits in
/// [`ZERO_RESPONSE_RETRY_PREFIX_CAP`].
pub(crate) struct ZeroResponseRetry<'a> {
    router: &'a Arc<dyn TunnelRouter>,
    selector: &'a TunnelSelector,
    target: &'a TargetAddr,
    credentials: Option<(&'a str, &'a str)>,
    /// Protocol name for the retry log line (`"SOCKS5"` / `"HTTP"`).
    protocol: &'static str,
    /// Bytes already sent to the first tunnel before the copy started
    /// (HTTP CONNECT pipelined leftovers). Seeded into the replay
    /// prefix so a retry replays the whole client-sent prefix.
    seed_prefix: Vec<u8>,
}

impl<'a> ZeroResponseRetry<'a> {
    pub(crate) fn new(
        router: &'a Arc<dyn TunnelRouter>,
        selector: &'a TunnelSelector,
        target: &'a TargetAddr,
        credentials: Option<(&'a str, &'a str)>,
        protocol: &'static str,
        seed_prefix: Vec<u8>,
    ) -> Self {
        Self {
            router,
            selector,
            target,
            credentials,
            protocol,
            seed_prefix,
        }
    }
}

/// Client-sent prefix buffered for a transparent zero-response retry:
/// the first [`ZERO_RESPONSE_RETRY_PREFIX_CAP`] bytes the client sent
/// in this session. Appended only by the client-to-tunnel direction
/// (a single writer), read by the epoch loop when the tunnel EOFs and
/// by the replay after a re-dial — hence interior mutability instead
/// of a borrow the direction future would hold across the loop.
struct RetryPrefix {
    buf: Mutex<Vec<u8>>,
    complete: AtomicBool,
}

impl RetryPrefix {
    const fn new(seed: Vec<u8>) -> Self {
        let complete = seed.len() <= ZERO_RESPONSE_RETRY_PREFIX_CAP;
        Self {
            buf: Mutex::new(seed),
            complete: AtomicBool::new(complete),
        }
    }

    /// Append a chunk just read from the client. Once the buffered
    /// bytes would pass the cap, stop appending and mark the prefix
    /// incomplete — a prefix that overflows the cap can never be
    /// replayed in full, so the session must not be retried.
    fn push(&self, chunk: &[u8]) {
        if !self.complete.load(Ordering::Relaxed) {
            return;
        }
        let mut buf = self.buf.lock();
        if buf.len() + chunk.len() > ZERO_RESPONSE_RETRY_PREFIX_CAP {
            self.complete.store(false, Ordering::Relaxed);
            return;
        }
        buf.extend_from_slice(chunk);
    }

    /// The buffered prefix if it holds every byte the client sent so
    /// far, else `None` — the session cannot be replayed completely.
    fn snapshot_if_complete(&self) -> Option<Vec<u8>> {
        self.complete
            .load(Ordering::Relaxed)
            .then(|| self.buf.lock().clone())
    }

    /// The buffered prefix parsed as a safe GET header, without
    /// cloning the whole prefix: the parse only reads the first
    /// 16 KiB, so it stays cheap while the prefix grows. The lock is
    /// held only for the short synchronous scan, never across an
    /// await.
    fn safe_get_parse(&self) -> SafeGetParse {
        let buf = self.buf.lock();
        parse_safe_http_get_header(&buf)
    }
}

/// Outcome of one copy epoch: either the session ended (both sides
/// done, idle, or an error) or the tunnel side ended the session with
/// zero response bytes while a retry is still available — a clean EOF,
/// a tunnel-side reset, or a failed tunnel write, all with no response
/// byte delivered (see [`RetryCopy::run_epoch`]).
enum EpochOutcome {
    Done((CopyEndKind, io::Result<(u64, u64)>)),
    ZeroResponse,
    /// The secondary leg of a silence replay produced the first
    /// response byte: the session continues on the secondary stream
    /// (the outer loop updates the tunnel id and records the
    /// blackhole on the primary).
    SilenceReplayWon {
        leg: SecondaryLeg,
        first_byte_at: Instant,
    },
}

/// Shared state across the epochs of one retrying CONNECT session.
/// The byte counters and the activity channel live here (not in the
/// per-epoch direction futures) so the totals span the re-dial: a
/// session that is retried and then succeeds reports the bytes of
/// the whole session, and the idle deadline is session-wide.
struct RetryCopy {
    activity_tx: tokio::sync::watch::Sender<u64>,
    activity_rx: tokio::sync::watch::Receiver<u64>,
    client_bytes: Arc<AtomicU64>,
    tunnel_bytes: Arc<AtomicU64>,
    prefix: Arc<RetryPrefix>,
    retried: bool,
    idle_timeout: Duration,
    /// When the session started, for the prompt-end check in
    /// [`RetryCopy::run_epoch`] and the session-end WARN.
    started_at: Instant,
    /// Why the current epoch is being retried, for the retry log
    /// line (`"zero-response EOF"`, or the reset / write-failure
    /// reason that triggered it).
    retry_reason: &'static str,
    /// The session's one post-send replay, shared by fix5 and the
    /// silence replay: exactly one of them can claim it.
    replay_token: PostSendReplayToken,
    /// Owned dial context for a post-send replay (None when the
    /// session has no retry context: then no replay is possible).
    dial_ctx: Option<Arc<ReplayDialCtx>>,
    /// Bytes already written to the first tunnel before the copy
    /// started (the seed prefix): they count as app bytes written
    /// upstream for the tightened fix5 rule.
    seed_len: usize,
    /// Per-session state of the one delayed silence replay.
    silence: SilenceReplay,
}

/// Milliseconds from `from` to `to` (0 when either is missing, or
/// when the order is reversed): the replay latency metrics.
fn latency_ms(from: Option<Instant>, to: Option<Instant>) -> u128 {
    match (from, to) {
        (Some(from), Some(to)) => to.saturating_duration_since(from).as_millis(),
        _ => 0,
    }
}

impl RetryCopy {
    fn counts(&self) -> (u64, u64) {
        (
            self.client_bytes.load(Ordering::Relaxed),
            self.tunnel_bytes.load(Ordering::Relaxed),
        )
    }

    /// Build the session outcome for `kind`/`result`: the session
    /// ran from `started_at` until now.
    fn outcome(&self, kind: CopyEndKind, result: io::Result<(u64, u64)>) -> ConnectSessionOutcome {
        ConnectSessionOutcome {
            result,
            kind,
            duration: self.started_at.elapsed(),
        }
    }

    /// Whether the client has given up on a silent tunnel: it sent
    /// bytes, received none, and the session has run longer than
    /// [`CLIENT_ABORT_SILENCE_THRESHOLD`].
    fn client_aborted_after_silence(&self) -> bool {
        self.client_bytes.load(Ordering::Relaxed) > 0
            && self.tunnel_bytes.load(Ordering::Relaxed) == 0
            && self.started_at.elapsed() > CLIENT_ABORT_SILENCE_THRESHOLD
    }

    /// Claim the session's one post-send replay for `source`, and
    /// record it. On success the fix5 trigger sites are gated off
    /// too (`retried`), so the other mechanism cannot also fire.
    fn claim_post_send_replay(&mut self, source: ReplaySource) -> bool {
        if !self.replay_token.claim(source) {
            return false;
        }
        self.retried = true;
        replay_metrics().inc_claimed(source);
        true
    }

    /// Release the global replay budget slot this session holds, if
    /// any. Idempotent: the slot is released exactly once.
    fn finish_replay_budget(&mut self) {
        if self.silence.budget_held {
            self.silence.budget_held = false;
            replay_budget_finish();
        }
    }

    /// App bytes actually written upstream so far: the seed prefix
    /// (written by the handler before the copy) plus the bytes the
    /// client-to-tunnel direction forwarded. A chunk whose write
    /// failed is not counted — it never reached a target.
    fn bytes_written_upstream(&self) -> u64 {
        self.seed_len as u64 + self.client_bytes.load(Ordering::Relaxed)
    }

    /// Whether a zero-response retry may re-send the buffered
    /// prefix: always when no app byte was written upstream (nothing
    /// could have been processed), and otherwise only when the
    /// prefix is a positively identified safe HTTP GET. Opaque TLS
    /// and unknown streams are never replayed after bytes were sent.
    fn post_send_retry_allowed(&self, prefix: &[u8]) -> bool {
        if self.bytes_written_upstream() == 0 {
            return true;
        }
        matches!(
            parse_safe_http_get_header(prefix),
            SafeGetParse::Eligible(_)
        )
    }

    /// The buffered prefix may now hold a complete eligible GET
    /// header: examine it once (and only while a replay is
    /// possible). When an eligible GET is found, record the header
    /// and arm the 2.5 s timer from when the header was written to
    /// the primary.
    fn note_activity_for_silence(&mut self) {
        // Only arm from Idle: once the timer is armed, or once a
        // replay was claimed (fix5) or suppressed, later activity
        // (for example the echo arriving in the retry epoch) must
        // not re-arm it.
        if self.silence.checked
            || self.silence.phase != SilencePhase::Idle
            || self.dial_ctx.is_none()
        {
            return;
        }
        match self.prefix.safe_get_parse() {
            SafeGetParse::Eligible(header) => {
                self.silence.checked = true;
                self.silence.header = Some(Arc::clone(&header));
                self.silence
                    .shared
                    .header_len
                    .store(header.len(), Ordering::Relaxed);
                self.silence.header_written_at = Some(Instant::now());
                self.silence.phase = SilencePhase::Armed;
                replay_metrics().inc_eligible();
            }
            SafeGetParse::Ineligible => {
                self.silence.checked = true;
            }
            SafeGetParse::Incomplete => {}
        }
    }

    /// The replay is suppressed: record the reason, close the phase,
    /// and never re-arm the timer for this session.
    fn suppress_silence_replay(&mut self, reason: SuppressReason) {
        replay_metrics().inc_suppressed(reason);
        tracing::debug!(
            reason = reason.label(),
            "safe HTTP silence replay suppressed"
        );
        self.silence.phase = SilencePhase::Done;
    }

    /// Pick up a race resolution the reader recorded: the primary won
    /// (or the secondary failed). Close the phase, release the
    /// budget, and record the winner — the reader only sets the
    /// flag, so this is the one place the resolution is logged and
    /// counted. A secondary win never reaches here: the reader
    /// returns instead, and the outer loop logs the rescue.
    fn check_replay_resolution(&mut self, primary_tunnel: Option<&str>) {
        if self.silence.phase != SilencePhase::Racing {
            return;
        }
        let winner = self.silence.shared.winner.load(Ordering::Relaxed);
        if winner == RACE_PRIMARY {
            self.silence.phase = SilencePhase::Done;
            self.finish_replay_budget();
            replay_metrics().inc_winner_primary();
            let timings = self.silence.shared.timings.lock();
            tracing::info!(
                protocol = self.dial_ctx.as_ref().map_or("?", |ctx| ctx.protocol),
                selector = ?self.dial_ctx.as_ref().map(|ctx| &ctx.selector),
                target = ?self.dial_ctx.as_ref().map(|ctx| &ctx.target),
                primary_tunnel = ?primary_tunnel,
                secondary_tunnel = ?timings.secondary_tunnel_id.as_deref(),
                primary_first_byte_ms = latency_ms(
                    self.silence.header_written_at,
                    timings.primary_first_byte_at
                ),
                secondary_dial_ms = latency_ms(
                    timings.dial_started_at,
                    timings.dial_connected_at
                ),
                "safe HTTP silence replay: primary won the race; secondary closed"
            );
        } else if winner == RACE_SECONDARY_FAILED {
            self.silence.phase = SilencePhase::Done;
            self.finish_replay_budget();
            tracing::info!(
                protocol = self.dial_ctx.as_ref().map_or("?", |ctx| ctx.protocol),
                primary_tunnel = ?primary_tunnel,
                "safe HTTP silence replay: secondary leg failed; primary continues"
            );
        } else {
            // No resolution yet: the race is still running.
        }
    }

    /// The 2.5 s timer fired on an eligible GET: start the replay if
    /// every condition still holds, and return whether the dial
    /// should be spawned (the spawn itself happens outside the
    /// select loop, so it cannot borrow the dial set the loop is
    /// polling). The global budget is reserved before the shared
    /// token is claimed, so a budget failure leaves the token free
    /// for a fix5 retry later in the session.
    fn start_silence_replay(&mut self, client_done: bool) -> bool {
        let Some(header) = self.silence.header.clone() else {
            return false;
        };
        if self.tunnel_bytes.load(Ordering::Relaxed) > 0 {
            self.suppress_silence_replay(SuppressReason::ResponseStarted);
            return false;
        }
        if client_done {
            self.suppress_silence_replay(SuppressReason::ClientGone);
            return false;
        }
        if self.client_bytes.load(Ordering::Relaxed) > header.len() as u64 {
            self.suppress_silence_replay(SuppressReason::ClientSentMore);
            return false;
        }
        if !replay_budget_try_start() {
            self.suppress_silence_replay(SuppressReason::BudgetExhausted);
            return false;
        }
        self.silence.budget_held = true;
        if !self.claim_post_send_replay(ReplaySource::SilenceReplay) {
            self.finish_replay_budget();
            self.suppress_silence_replay(SuppressReason::TokenClaimed);
            return false;
        }
        self.silence.phase = SilencePhase::Dialing;
        replay_metrics().inc_silence_trigger();
        replay_metrics().inc_dial_started();
        true
    }

    /// Spawn the secondary dial task into the epoch's dial set. The
    /// task dials one different tunnel and sends the GET header on
    /// it; the epoch loop keeps reading the primary while it runs.
    /// Called outside the select loop (after the timer arm fired),
    /// so it can borrow the dial set the loop polls.
    fn spawn_silence_dial(
        &self,
        primary_tunnel: Option<&str>,
        dial_set: &mut tokio::task::JoinSet<ReplayDialOutcome>,
    ) {
        let Some(ctx) = self.dial_ctx.clone() else {
            return;
        };
        let Some(header) = self.silence.header.clone() else {
            return;
        };
        let shared = Arc::clone(&self.silence.shared);
        let tunnel_bytes = Arc::clone(&self.tunnel_bytes);
        let client_bytes = Arc::clone(&self.client_bytes);
        let exclude = primary_tunnel.map(str::to_string);
        dial_set.spawn(dial_secondary_leg(
            ctx,
            exclude,
            header,
            tunnel_bytes,
            client_bytes,
            shared,
        ));
    }

    /// Handle what the secondary dial task found: hand a ready leg
    /// to the race reader, or close the replay (and release the
    /// budget) when it was moot, impossible, or failed.
    fn on_dial_outcome(
        &mut self,
        outcome: ReplayDialOutcome,
        secondary_tx: &mut Option<tokio::sync::oneshot::Sender<SecondaryLeg>>,
    ) {
        match outcome {
            ReplayDialOutcome::Ready(leg) => {
                self.silence.phase = SilencePhase::Racing;
                replay_metrics().inc_request_sent();
                let sent = secondary_tx.take().is_some_and(|tx| tx.send(leg).is_ok());
                if !sent {
                    // The reader is gone (the epoch ended): the leg
                    // is dropped with the failed send.
                    self.silence.phase = SilencePhase::Done;
                    self.finish_replay_budget();
                }
            }
            ReplayDialOutcome::Suppressed(reason) => {
                self.suppress_silence_replay(reason);
                self.finish_replay_budget();
            }
            ReplayDialOutcome::NoTunnel => {
                self.suppress_silence_replay(SuppressReason::NoTunnel);
                self.finish_replay_budget();
            }
            ReplayDialOutcome::Failed(e) => {
                self.on_replay_dial_failed(&e);
            }
        }
    }

    /// The secondary dial (or the GET send) failed: leave the
    /// primary alive, close the replay, and count it.
    fn on_replay_dial_failed(&mut self, e: &router::RouterConnectError) {
        replay_metrics().inc_dial_failed();
        tracing::debug!("safe HTTP silence replay dial failed: {e:?}");
        self.silence.phase = SilencePhase::Done;
        self.finish_replay_budget();
    }

    /// Decide how the epoch ends when the tunnel side closes
    /// cleanly: a zero-response retry while one is still available,
    /// or the session end.
    ///
    /// A clean tunnel EOF with zero response bytes ends the session
    /// on a fresh tunnel instead of handing the client an empty
    /// reply: the tunnel can die before the client's first bytes
    /// are even read, so requiring `client > 0` here would end the
    /// session while the client is about to send — and its next
    /// write would fail. The retry replays the buffered prefix
    /// (possibly empty) and the session continues live on the new
    /// tunnel; if the client never sends anything, the fresh epoch
    /// ends on the idle timeout exactly as before.
    fn on_tunnel_closed(&self, client: u64, tunnel: u64, a_done: bool) -> EpochOutcome {
        if tunnel == 0 && !a_done && !self.retried && self.prefix.complete.load(Ordering::Relaxed) {
            return EpochOutcome::ZeroResponse;
        }
        EpochOutcome::Done((CopyEndKind::TunnelClosed, Ok((client, tunnel))))
    }

    /// Handle the client-to-tunnel direction finishing. Returns
    /// `Some(outcome)` when the epoch ends, or `None` when the
    /// client half closed and the epoch continues (the caller sets
    /// `a_done`).
    fn on_client_done(&mut self, res: io::Result<()>) -> Option<EpochOutcome> {
        match res {
            Ok(()) => {
                // A client half-close after a long silent wait is
                // the client giving up on a blackhole tunnel: end
                // now instead of lingering until the idle timeout.
                if self.client_aborted_after_silence() {
                    return Some(EpochOutcome::Done((
                        CopyEndKind::ClientAborted,
                        Ok(self.counts()),
                    )));
                }
                None
            }
            // A failed write to the tunnel with zero response bytes
            // is the same retryable shape as a clean EOF: the
            // request never got an answer, and the whole
            // client-sent prefix is buffered for replay. Only
            // `BrokenPipe` counts here — it is the write side
            // failing because the tunnel reset the connection. A
            // client-read failure (`ConnectionReset` on this
            // direction) means the client itself went away, so
            // there is nobody to retry for. No client-sent check is
            // needed: the chunk whose write failed was pushed to the
            // prefix before the write was attempted.
            Err(e)
                if e.kind() == io::ErrorKind::BrokenPipe
                    && self.tunnel_bytes.load(Ordering::Relaxed) == 0
                    && !self.retried
                    && self.prefix.complete.load(Ordering::Relaxed) =>
            {
                self.retry_reason = "tunnel write failed with zero response bytes";
                Some(EpochOutcome::ZeroResponse)
            }
            Err(e) => Some(EpochOutcome::Done((CopyEndKind::Failed, Err(e)))),
        }
    }

    /// Handle the tunnel-to-client direction (the race reader)
    /// finishing. Always ends the epoch. The reader may have
    /// resolved the race just before returning (primary won, then
    /// the tunnel closed): record it before the epoch ends.
    fn on_upstream_done(
        &mut self,
        res: RaceReaderDone,
        a_done: bool,
        tunnel_id: Option<&str>,
    ) -> EpochOutcome {
        self.check_replay_resolution(tunnel_id);
        match res {
            RaceReaderDone::PrimaryClosed => self.on_tunnel_closed(
                self.client_bytes.load(Ordering::Relaxed),
                self.tunnel_bytes.load(Ordering::Relaxed),
                a_done,
            ),
            // A tunnel-side reset with zero response bytes is the
            // same retryable shape as a clean EOF: the target never
            // answered, and the whole client-sent prefix is buffered
            // for replay. Only `ConnectionReset` counts here — it is
            // the read side failing because the tunnel reset the
            // connection. A client-write failure (`BrokenPipe` on
            // this direction) means the client itself went away, so
            // there is nobody to retry for. No client-sent check is
            // needed: the reset can arrive before the client's first
            // bytes are read, and the retry replays the (possibly
            // empty) prefix the same way the clean-EOF arm does.
            RaceReaderDone::PrimaryReset(_e)
                if self.tunnel_bytes.load(Ordering::Relaxed) == 0
                    && !a_done
                    && !self.retried
                    && self.prefix.complete.load(Ordering::Relaxed) =>
            {
                self.retry_reason = "connection reset with zero response bytes";
                EpochOutcome::ZeroResponse
            }
            RaceReaderDone::PrimaryReset(e) | RaceReaderDone::PrimaryFailed(e) => {
                EpochOutcome::Done((CopyEndKind::Failed, Err(e)))
            }
            RaceReaderDone::SecondaryWon(win) => EpochOutcome::SilenceReplayWon {
                leg: win.leg,
                first_byte_at: win.first_byte_at,
            },
        }
    }

    /// Run one epoch: relay both directions on the current tunnel
    /// stream until one side ends. The tunnel side does not
    /// half-close the client on EOF — the client must not see EOF
    /// while a retry may still deliver its response — and the epoch
    /// ends as soon as the tunnel side ends (there is no tunnel left
    /// to read from), instead of waiting for the client to close.
    async fn run_epoch<A, B>(
        &mut self,
        a: &mut A,
        b: &mut B,
        tunnel_id: Option<&str>,
    ) -> EpochOutcome
    where
        A: AsyncRead + AsyncWrite + Unpin,
        B: AsyncRead + AsyncWrite + Unpin,
    {
        let activity_tx = self.activity_tx.clone();
        let client_bytes = Arc::clone(&self.client_bytes);
        let tunnel_bytes = Arc::clone(&self.tunnel_bytes);
        let prefix = Arc::clone(&self.prefix);
        let retried = self.retried;
        let idle_timeout = self.idle_timeout;
        let (a_read, a_write) = tokio::io::split(a);
        let (b_read, b_write) = tokio::io::split(b);
        // Capture the prefix only in the first epoch: after a retry
        // the replayed bytes are already buffered, and new client
        // bytes flow live through the fresh tunnel.
        let capture = if retried {
            None
        } else {
            Some(Arc::clone(&prefix))
        };
        let mut a_to_b = Box::pin(copy_direction_retry(
            a_read,
            b_write,
            activity_tx.clone(),
            Arc::clone(&client_bytes),
            capture,
            true,
        ));
        // The tunnel-to-client direction is the race reader: it
        // forwards the primary's responses, and races a secondary
        // leg once the silence replay hands it one.
        let (secondary_tx, secondary_rx) = tokio::sync::oneshot::channel();
        let mut secondary_tx = Some(secondary_tx);
        let mut upstream = Box::pin(
            UpstreamRaceReader::new(RaceReaderArgs {
                client_write: a_write,
                primary_read: b_read,
                secondary_rx,
                activity: activity_tx,
                tunnel_bytes: Arc::clone(&tunnel_bytes),
                client_bytes: Arc::clone(&client_bytes),
                shared: Arc::clone(&self.silence.shared),
            })
            .run(),
        );
        // The secondary dial runs as a spawned task, so the epoch
        // loop keeps reading the primary while the dial is in
        // flight. Dropping the set aborts a dial still in flight
        // when the epoch ends.
        let mut dial_set: tokio::task::JoinSet<ReplayDialOutcome> = tokio::task::JoinSet::new();
        let mut a_done = false;
        loop {
            // The race reader resolves the replay on its own (primary
            // win / secondary failure): pick up the resolution —
            // release the budget, close the phase — before the next
            // select, so a resolved replay never holds its slot past
            // the next wakeup.
            self.check_replay_resolution(tunnel_id);
            let armed = self.silence.phase == SilencePhase::Armed;
            let delay = self.silence.delay_until_firing();
            let mut spawn_dial = false;
            tokio::select! {
                res = &mut a_to_b, if !a_done => {
                    if let Some(outcome) = self.on_client_done(res) {
                        return outcome;
                    }
                    a_done = true;
                }
                res = &mut upstream => {
                    return self.on_upstream_done(res, a_done, tunnel_id);
                }
                res = tokio::time::timeout(idle_timeout, self.activity_rx.changed()) => {
                    if res.is_err() {
                        tracing::debug!("CONNECT session closed after {:?} idle", idle_timeout);
                        return EpochOutcome::Done((
                            CopyEndKind::IdleTimeout,
                            Ok((
                                client_bytes.load(Ordering::Relaxed),
                                tunnel_bytes.load(Ordering::Relaxed),
                            )),
                        ));
                    }
                    // A chunk flowed: the buffered prefix may now
                    // hold a complete eligible GET header.
                    self.note_activity_for_silence();
                }
                () = tokio::time::sleep(delay), if armed => {
                    // The 2.5 s timer fired on an eligible GET. The
                    // arm only decides to start the replay; the
                    // spawn happens after the select, so it can
                    // borrow the dial set the loop polls.
                    spawn_dial = self.start_silence_replay(a_done);
                }
                res = dial_set.join_next(), if !dial_set.is_empty() => {
                    match res {
                        Some(Ok(outcome)) => {
                            self.on_dial_outcome(outcome, &mut secondary_tx);
                        }
                        Some(Err(e)) => {
                            // The dial task panicked: treat it as a
                            // failed dial and leave the primary alive.
                            tracing::debug!("silence replay dial task failed: {e}");
                            self.on_replay_dial_failed(
                                &router::RouterConnectError::TcpConnect(io::Error::other(
                                    "dial task failed",
                                )),
                            );
                        }
                        None => {}
                    }
                }
            }
            if spawn_dial {
                self.spawn_silence_dial(tunnel_id, &mut dial_set);
            }
        }
    }

    /// Attempt the one zero-response retry: re-dial through a
    /// different tunnel and replay the buffered client prefix.
    /// Returns the fresh tunnel stream on success (and updates
    /// `tunnel_id` + `retried`); returns `None` when the retry is
    /// impossible (redial or replay failed) — the caller then ends
    /// the session and the existing WARN fires. On success the
    /// failed tunnel is recorded as a blackhole before `tunnel_id`
    /// is updated, so the rescued session still costs the dead
    /// tunnel its health.
    async fn attempt_retry(
        &mut self,
        ctx: ZeroResponseRetry<'_>,
        tunnel_id: &mut Option<String>,
    ) -> Option<DynStream> {
        let Some(prefix) = self.prefix.snapshot_if_complete() else {
            tracing::debug!(
                protocol = ctx.protocol,
                selector = ?ctx.selector,
                target = %ctx.target,
                failed_tunnel = ?tunnel_id.as_deref(),
                "zero-response retry skipped: client sent more than the replay cap"
            );
            return None;
        };
        // Tightened fix5 (fix11): a request is only replayed when no
        // app byte was written upstream, or when it is a positively
        // identified safe HTTP GET. Opaque TLS and unknown streams
        // are never replayed after bytes were sent — the origin may
        // already have processed them, and the EOF does not prove
        // otherwise.
        if !self.post_send_retry_allowed(&prefix) {
            tracing::debug!(
                protocol = ctx.protocol,
                selector = ?ctx.selector,
                target = %ctx.target,
                failed_tunnel = ?tunnel_id.as_deref(),
                "zero-response retry skipped: request is not a replayable safe GET"
            );
            replay_metrics().inc_suppressed(SuppressReason::Ineligible);
            return None;
        }
        // The silence replay shares this token: if it already
        // claimed the session's one post-send replay, fix5 cannot
        // also re-dial.
        if !self.claim_post_send_replay(ReplaySource::Fix5) {
            tracing::debug!(
                protocol = ctx.protocol,
                selector = ?ctx.selector,
                target = %ctx.target,
                failed_tunnel = ?tunnel_id.as_deref(),
                "zero-response retry skipped: post-send replay already claimed"
            );
            replay_metrics().inc_suppressed(SuppressReason::TokenClaimed);
            return None;
        }
        // The re-dial is a single direct dial, not the racing
        // router: a replay must not start its own fix6 race.
        let (mut stream, new_id) = match router::connect_direct(
            ctx.router,
            ctx.selector,
            ctx.target,
            ctx.credentials,
            tunnel_id.as_deref(),
        )
        .await
        {
            Ok(pair) => pair,
            Err(e) => {
                let inner = match e {
                    router::RouterConnectError::SelectTunnel(e)
                    | router::RouterConnectError::ForbiddenDestination(e)
                    | router::RouterConnectError::DnsResolution(e)
                    | router::RouterConnectError::TcpConnect(e) => e,
                };
                tracing::debug!(
                    protocol = ctx.protocol,
                    selector = ?ctx.selector,
                    target = %ctx.target,
                    failed_tunnel = ?tunnel_id.as_deref(),
                    "zero-response retry re-dial failed: {inner}"
                );
                return None;
            }
        };
        let replayed = prefix.len();
        let replay = async {
            stream.write_all(&prefix).await?;
            stream.flush().await
        };
        if let Err(e) = replay.await {
            tracing::debug!(
                protocol = ctx.protocol,
                selector = ?ctx.selector,
                target = %ctx.target,
                failed_tunnel = ?tunnel_id.as_deref(),
                "zero-response retry replay failed: {e}"
            );
            return None;
        }
        // The replayed prefix counts once, when the client first sent
        // it — but a failed tunnel write never bumped the counter for
        // the bytes it dropped, so top it up by the uncounted portion
        // here. Bytes the first tunnel accepted already counted and
        // are not added twice.
        let counted = self.client_bytes.load(Ordering::Relaxed);
        if let Some(uncounted) = replayed.checked_sub(counted as usize) {
            self.client_bytes
                .fetch_add(uncounted as u64, Ordering::Relaxed);
        }
        tracing::info!(
            protocol = ctx.protocol,
            selector = ?ctx.selector,
            target = %ctx.target,
            from_tunnel = ?tunnel_id.as_deref(),
            to_tunnel = ?new_id.as_deref(),
            replayed_bytes = replayed,
            reason = self.retry_reason,
            "CONNECT session retried"
        );
        // The rescue worked, so the failed tunnel will not be
        // reported by the session end: record its blackhole now,
        // while `tunnel_id` still names it. (A retry that fails
        // leaves `tunnel_id` on the failed tunnel, so the handler
        // records it once at the session end instead — never both.)
        if let Some(failed) = tunnel_id.as_deref() {
            ctx.router.record_tunnel_blackhole(failed);
        }
        *tunnel_id = new_id;
        Some(stream)
    }
}

/// Relay bytes in both directions between `a` and `b` until either side
/// closes, and end the session when no byte flows in either direction
/// for `idle_timeout` (audit run-1,
/// `wpmulti/proxy:established-connect-no-idle-timeout`). When the
/// tunnel side ends the session with zero response bytes while the
/// client is still connected — a clean EOF, a tunnel-side reset, or a
/// failed tunnel write — re-dial the same target through a different
/// tunnel and replay the buffered client prefix instead of handing
/// the client an empty reply.
///
/// The two directions run as concurrent tasks: a stalled write in one
/// direction must never starve reads in the other. A single `select!`
/// loop that `await`s each `write_all` inline deadlocks on a sustained
/// bidirectional bulk transfer once every socket buffer is full — the
/// loop waits for the peer to read while the peer waits for this side
/// to read, and neither side ever runs again (found by the offline
/// throughput test, which stalled at 91% of an 8x8 MiB load).
/// Idleness is therefore tracked session-wide: every forwarded chunk
/// bumps a shared activity counter, and the session closes only when
/// that counter is still for `idle_timeout`.
///
/// The retry fires at most once per session, only when the whole
/// client-sent prefix fits in [`ZERO_RESPONSE_RETRY_PREFIX_CAP`] (so
/// it can be replayed in full), and only for pool selectors — a
/// `ById` selector names one tunnel, so there is no different tunnel
/// to re-dial through. Timeouts and budget failures are never
/// retried: they are a different failure (the target never answered
/// in time), not an empty reply. A reset or a failed tunnel write
/// after a response byte arrived is never retried either: the session
/// already delivered something, so replaying the request could
/// double-submit it.
///
/// Returns a [`ConnectSessionOutcome`]: the byte counts each
/// direction forwarded, how the session ended, and how long it ran.
/// Callers need the counts to tell a session that died with no
/// response from the target apart from one the client closed
/// without sending anything — see [`log_connect_session_end`]. On a
/// retried session the counts span the whole session (the replayed
/// prefix is counted once, when the client first sent it).
/// `tunnel_id` is updated to the tunnel that ultimately served the
/// session, so the caller's [`log_connect_session_end`] names the
/// right tunnel when the session still fails after the retry.
pub(crate) async fn copy_bidirectional_with_zero_response_retry<A>(
    a: &mut A,
    mut b: DynStream,
    idle_timeout: Duration,
    retry: Option<ZeroResponseRetry<'_>>,
    tunnel_id: &mut Option<String>,
) -> ConnectSessionOutcome
where
    A: AsyncRead + AsyncWrite + Unpin,
{
    let (activity_tx, activity_rx) = tokio::sync::watch::channel(0u64);
    let seed = retry
        .as_ref()
        .map_or(Vec::new(), |ctx| ctx.seed_prefix.clone());
    let seed_len = seed.len();
    // The silence replay draws from the global bucket: one primary
    // request per refill token.
    replay_budget_note_primary_request();
    // Owned dial context for a post-send replay, cloned from the
    // handler's borrowed context: the silence replay dials from a
    // spawned task, where those borrows do not live.
    let dial_ctx = retry.as_ref().map(|ctx| {
        Arc::new(ReplayDialCtx {
            router: Arc::clone(ctx.router),
            selector: ctx.selector.clone(),
            target: ctx.target.clone(),
            credentials: ctx
                .credentials
                .map(|(user, pass)| (user.to_string(), pass.to_string())),
            protocol: ctx.protocol,
        })
    });
    let mut state = RetryCopy {
        activity_tx,
        activity_rx,
        client_bytes: Arc::new(AtomicU64::new(0)),
        tunnel_bytes: Arc::new(AtomicU64::new(0)),
        prefix: Arc::new(RetryPrefix::new(seed)),
        retried: retry.is_none(),
        idle_timeout,
        started_at: Instant::now(),
        retry_reason: "zero-response EOF",
        replay_token: PostSendReplayToken::new(),
        dial_ctx,
        seed_len,
        silence: SilenceReplay::new(),
    };
    let mut retry = retry;
    loop {
        let outcome = state.run_epoch(&mut *a, &mut b, tunnel_id.as_deref()).await;
        // Backstop: free the replay slot when the epoch ends. The
        // prompt path is the race resolution mid-epoch, through the
        // reader; this only covers a session that ends while a
        // replay is still in flight.
        state.finish_replay_budget();
        match outcome {
            EpochOutcome::Done((kind, result)) => return state.outcome(kind, result),
            EpochOutcome::ZeroResponse => {
                let Some(ctx) = retry.take() else {
                    // run_epoch only reports a zero response while a
                    // retry is available; unreachable in practice.
                    return state.outcome(CopyEndKind::TunnelClosed, Ok(state.counts()));
                };
                let Some(new_stream) = state.attempt_retry(ctx, tunnel_id).await else {
                    return state.outcome(CopyEndKind::TunnelClosed, Ok(state.counts()));
                };
                b = new_stream;
            }
            EpochOutcome::SilenceReplayWon { leg, first_byte_at } => {
                // The secondary answered first: the primary was
                // slow/unhealthy, so it takes the blackhole penalty
                // (breaker, EWMA, warm-list removal), exactly as a
                // blackhole session does. A primary win after the
                // secondary dial started is not evidence the
                // secondary is bad, so the secondary is never
                // penalised for losing the race.
                if let Some(primary) = tunnel_id.as_deref()
                    && let Some(ctx) = state.dial_ctx.as_ref()
                {
                    ctx.router.record_tunnel_blackhole(primary);
                }
                let header_written_at = state.silence.header_written_at;
                let (secondary_dial_ms, secondary_first_byte_ms, primary_first_byte_ms) = {
                    let timings = state.silence.shared.timings.lock();
                    (
                        latency_ms(timings.dial_started_at, timings.dial_connected_at),
                        latency_ms(timings.dial_connected_at, Some(first_byte_at)),
                        latency_ms(header_written_at, timings.primary_first_byte_at),
                    )
                };
                tracing::info!(
                    protocol = state.dial_ctx.as_ref().map_or("?", |ctx| ctx.protocol),
                    selector = ?state.dial_ctx.as_ref().map(|ctx| &ctx.selector),
                    target = ?state.dial_ctx.as_ref().map(|ctx| &ctx.target),
                    from_tunnel = ?tunnel_id.as_deref(),
                    to_tunnel = ?leg.tunnel_id.as_deref(),
                    primary_first_byte_ms = primary_first_byte_ms,
                    secondary_dial_ms = secondary_dial_ms,
                    secondary_first_byte_ms = secondary_first_byte_ms,
                    total_ms = latency_ms(header_written_at, Some(first_byte_at)),
                    "CONNECT session rescued by safe HTTP silence replay"
                );
                replay_metrics().inc_winner_secondary();
                replay_metrics().inc_rescued();
                *tunnel_id = leg.tunnel_id;
                state.silence.phase = SilencePhase::Done;
                b = leg.stream;
            }
        }
    }
}

/// Copy one direction until EOF or an I/O error, bumping `activity`
/// after every forwarded chunk so the session-wide idle watchdog sees
/// it, and adding the chunk to the shared `forwarded` counter so the
/// caller can read the byte totals even when the session ends on the
/// idle timeout. It also captures the forwarded bytes into `prefix`
/// (so they can be replayed on a fresh tunnel) and half-closes the
/// far write side on EOF only when `shutdown_on_eof` is set. The
/// tunnel-to-client direction runs with it unset: the client must
/// not see EOF while a retry may still deliver its response. The
/// prefix is captured when a chunk is read — before it is written —
/// so a chunk dropped mid-write by a tunnel EOF is still replayed
/// in full.
async fn copy_direction_retry<R, W>(
    mut read: R,
    mut write: W,
    activity: tokio::sync::watch::Sender<u64>,
    forwarded: Arc<AtomicU64>,
    prefix: Option<Arc<RetryPrefix>>,
    shutdown_on_eof: bool,
) -> io::Result<()>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    // Heap buffer: an 8 KiB stack buffer would push this future (and
    // every caller awaiting it) past the large-future threshold.
    let mut buf = Box::new([0u8; 8192]);
    loop {
        let n = read.read(&mut buf[..]).await?;
        if n == 0 {
            if shutdown_on_eof {
                let _ = write.shutdown().await;
            }
            return Ok(());
        }
        let Some(chunk) = buf.get(..n) else {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "relay read overran its buffer",
            ));
        };
        if let Some(prefix) = &prefix {
            prefix.push(chunk);
        }
        write.write_all(chunk).await?;
        forwarded.fetch_add(n as u64, Ordering::Relaxed);
        activity.send_modify(|count| *count += 1);
    }
}

/// Runs an asynchronous SOCKS5 server listening on the provided [`tokio::net::TcpListener`].
pub async fn run_socks5_listener(
    listener: tokio::net::TcpListener,
    router: Arc<dyn TunnelRouter>,
) -> io::Result<()> {
    let sem = Arc::new(tokio::sync::Semaphore::new(MAX_PROXY_CONCURRENT_CONNS));
    loop {
        let (stream, peer_addr) = match listener.accept().await {
            Ok(conn) => conn,
            Err(e) => {
                tracing::warn!("SOCKS5 listener accept error: {}", e);
                tokio::time::sleep(Duration::from_millis(50)).await;
                continue;
            }
        };
        let Ok(permit) = Arc::clone(&sem).acquire_owned().await else {
            break;
        };
        let local_ip = stream.local_addr().ok().map(|a| a.ip());
        let peer_ip = Some(peer_addr.ip());
        let router_clone = Arc::clone(&router);
        tokio::spawn(async move {
            let _permit = permit;
            if let Err(e) = handle_socks5_with_addrs(stream, router_clone, local_ip, peer_ip).await
            {
                tracing::debug!("SOCKS5 client {} disconnected: {:?}", peer_addr, e);
            }
        });
    }
    Ok(())
}

/// Runs an asynchronous HTTP/HTTPS CONNECT proxy server listening on the provided [`tokio::net::TcpListener`].
pub async fn run_http_listener(
    listener: tokio::net::TcpListener,
    router: Arc<dyn TunnelRouter>,
) -> io::Result<()> {
    let sem = Arc::new(tokio::sync::Semaphore::new(MAX_PROXY_CONCURRENT_CONNS));
    loop {
        let (stream, peer_addr) = match listener.accept().await {
            Ok(conn) => conn,
            Err(e) => {
                tracing::warn!("HTTP listener accept error: {}", e);
                tokio::time::sleep(Duration::from_millis(50)).await;
                continue;
            }
        };
        let Ok(permit) = Arc::clone(&sem).acquire_owned().await else {
            break;
        };
        let router_clone = Arc::clone(&router);
        tokio::spawn(async move {
            let _permit = permit;
            if let Err(e) = handle_http(stream, router_clone).await {
                tracing::debug!("HTTP proxy client {} disconnected: {:?}", peer_addr, e);
            }
        });
    }
    Ok(())
}
