//! Proxy connector and routing abstractions.
//!
//! Defines traits and concrete types bridging proxy client requests (SOCKS5 and HTTP CONNECT)
//! to userspace network stacks ([`VirtualNetworkStack`]), direct connections, or multi-tunnel pools.

use std::collections::HashMap;
use std::future::Future;
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use parking_lot::RwLock;
use smallvec::SmallVec;
use tokio::io::{AsyncRead, AsyncWrite};

use crate::config::{AuthMode, PoolStrategy};
use crate::netstack::{DEFAULT_CONNECT_TIMEOUT, VirtualNetworkStack, VirtualUdpSocket};

/// Maximum number of candidate IP addresses attempted per resolved domain.
pub(crate) const MAX_CANDIDATE_IPS: usize = 8;

/// Maximum number of tunnel attempts for pool selectors (`round-robin`, `random`, `least-conn`, `auto`, `tag`).
pub(crate) const MAX_POOL_FAILOVER_ATTEMPTS: usize = 3;

/// Maximum total elapsed time spent failing over across pool tunnels for a single connect request.
pub(crate) const MAX_POOL_FAILOVER_BUDGET: Duration = Duration::from_millis(3500);

/// Per-attempt deadline for one pool dial inside the failover budget.
///
/// A live tunnel's handshake + TCP connect normally finishes in well
/// under a second (median ~90 ms in the 2000-request measurement), so
/// 1.25 s leaves ample headroom while guaranteeing the outer failover
/// loop still has budget for two more attempts. A dormant tunnel whose
/// handshake is lost waits 5 s for the WireGuard rekey timer — far
/// past this deadline — so capping the attempt is what lets the race
/// (below) rescue the request instead of burning the whole budget.
pub(crate) const FIRST_ATTEMPT_TIMEOUT: Duration = Duration::from_millis(1250);

/// Stagger before hedging a dormant first leg (RFC 8305 Connection
/// Attempt Delay, 250 ms). A live first leg is never hedged: only a
/// dormant or unknown leg gets a second tunnel racing it.
pub(crate) const RACE_STAGGER: Duration = Duration::from_millis(250);

/// Minimum timeout budget allocated to each candidate dial/send attempt while budget remains.
pub(crate) const MIN_ATTEMPT_TIMEOUT: Duration = Duration::from_millis(250);

/// Default overall timeout budget for validated multi-address UDP datagram sends.
pub(crate) const DEFAULT_UDP_SEND_TIMEOUT: Duration = Duration::from_secs(5);

/// Returns `true` if `v4` is a forbidden IPv4 destination: unspecified
/// (`0.0.0.0/8` — the whole /8, not just `0.0.0.0` itself), loopback,
/// private (RFC1918), link-local, multicast, broadcast, shared/CGNAT
/// (`100.64.0.0/10`), benchmarking (`198.18.0.0/15`), and reserved
/// (`240.0.0.0/4`) (audit run-3 #6).
///
/// The CGNAT/benchmarking/reserved ranges use manual octet checks: the
/// `std` helpers (`is_shared`, `is_benchmarking`, `is_reserved`) are
/// still unstable on this toolchain, and each range is a couple of
/// integer comparisons.
pub(crate) const fn is_forbidden_ipv4(v4: Ipv4Addr) -> bool {
    let o = v4.octets();
    o[0] == 0
        || v4.is_loopback()
        || v4.is_private()
        || v4.is_link_local()
        || v4.is_multicast()
        || v4.is_broadcast()
        || (o[0] == 100 && o[1] >= 64 && o[1] <= 127)
        || (o[0] == 198 && o[1] >= 18 && o[1] <= 19)
        || o[0] >= 240
}

/// Returns `true` if `ip` is an unsafe/forbidden proxy destination:
/// - IPv4: unspecified (`0.0.0.0/8`), loopback (`127.0.0.0/8`), private/RFC1918 (`10/8`,
///   `172.16/12`, `192.168/16`), link-local (`169.254.0.0/16`), multicast (`224.0.0.0/4`),
///   broadcast (`255.255.255.255`), shared/CGNAT (`100.64.0.0/10`), benchmarking
///   (`198.18.0.0/15`), reserved (`240.0.0.0/4`). Loopback and RFC1918 destinations would reach services
///   on the tunnel peer's loopback/LAN, not the public internet, so a proxy client must
///   not be able to name them (audit run-1,
///   `proxy.destination.ipv4-loopback-rfc1918-not-forbidden`); the CGNAT/benchmarking/
///   reserved ranges are likewise peer-side infrastructure, not public destinations
///   (audit run-3 #6).
/// - IPv6: loopback (`::1`), unspecified (`::`), link-local (`fe80::/10`), Unique Local (`fc00::/7`),
///   multicast (`ff00::/8`), deprecated site-local (`fec0::/10`), IPv4-mapped IPv6 (`::ffff:0:0/96`),
///   NAT64 well-known prefix (`64:ff9b::/96`), 6to4 (`2002::/16`), and Teredo (`2001::/32`)
///   when embedding a forbidden IPv4 address.
pub(crate) const fn is_forbidden_destination_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => is_forbidden_ipv4(v4),
        IpAddr::V6(v6) => {
            if let Some(v4) = v6.to_ipv4_mapped() {
                return is_forbidden_ipv4(v4);
            }
            let segs = v6.segments();
            // NAT64 well-known prefix 64:ff9b::/96
            if segs[0] == 0x0064
                && segs[1] == 0xff9b
                && segs[2] == 0
                && segs[3] == 0
                && segs[4] == 0
                && segs[5] == 0
            {
                let o = v6.octets();
                let embedded_v4 = Ipv4Addr::new(o[12], o[13], o[14], o[15]);
                return is_forbidden_ipv4(embedded_v4);
            }
            // 6to4 2002::/16: the embedded IPv4 address is segments 1-2.
            if segs[0] == 0x2002 {
                let embedded_v4 = Ipv4Addr::new(
                    (segs[1] >> 8) as u8,
                    segs[1] as u8,
                    (segs[2] >> 8) as u8,
                    segs[2] as u8,
                );
                return is_forbidden_ipv4(embedded_v4);
            }
            // Teredo 2001::/32: the embedded client IPv4 address is the
            // last 32 bits, XORed with 0xffffffff (RFC 4380).
            if segs[0] == 0x2001 && segs[1] == 0 {
                let xored = ((segs[6] as u32) << 16) | (segs[7] as u32);
                let client = !xored;
                let embedded_v4 = Ipv4Addr::new(
                    (client >> 24) as u8,
                    (client >> 16) as u8,
                    (client >> 8) as u8,
                    client as u8,
                );
                return is_forbidden_ipv4(embedded_v4);
            }
            v6.is_loopback()
                || v6.is_unspecified()
                || v6.is_multicast()
                || (segs[0] & 0xffc0) == 0xfe80
                || (segs[0] & 0xfe00) == 0xfc00
                || (segs[0] & 0xffc0) == 0xfec0
        }
    }
}

/// Parse an IP literal that may appear inside a domain/host field (e.g. `127.0.0.1`, `::1`, `[::1]`).
pub(crate) fn parse_domain_ip_literal(host: &str) -> Option<IpAddr> {
    if let Ok(ip) = host.parse::<IpAddr>() {
        return Some(ip);
    }
    if let Some(inner) = host.strip_prefix('[').and_then(|s| s.strip_suffix(']'))
        && let Ok(v6) = inner.parse::<Ipv6Addr>()
    {
        return Some(IpAddr::V6(v6));
    }
    None
}

/// Validate a target domain name against DNS length limits and unsafe ASCII control/whitespace characters.
pub(crate) fn is_valid_target_domain(domain: &str) -> bool {
    if domain.is_empty()
        || domain
            .bytes()
            .any(|b| b.is_ascii_control() || b.is_ascii_whitespace())
    {
        return false;
    }
    let clean = domain.strip_suffix('.').unwrap_or(domain);
    if clean.is_empty() || clean.len() > 253 {
        return false;
    }
    clean
        .split('.')
        .all(|label| !label.is_empty() && label.len() <= 63)
}

/// Target destination requested by a proxy client.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TargetAddr {
    /// Direct IP socket address (IPv4 or IPv6).
    Ip(SocketAddr),
    /// Fully qualified domain name and destination port.
    Domain(String, u16),
}

impl std::fmt::Display for TargetAddr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Ip(addr) => write!(f, "{addr}"),
            Self::Domain(domain, port) => write!(f, "{domain}:{port}"),
        }
    }
}

/// Helper trait combining [`AsyncRead`], [`AsyncWrite`], [`Send`], and [`Unpin`].
pub trait AsyncReadWrite: AsyncRead + AsyncWrite + Send + Unpin {}
impl<T: AsyncRead + AsyncWrite + Send + Unpin> AsyncReadWrite for T {}

/// Dynamically dispatched asynchronous bidirectional byte stream.
pub type DynStream = Box<dyn AsyncReadWrite>;

/// Future returned by [`ProxyUdpSocket::recv_from`].
pub type RecvFromFut<'a> =
    Pin<Box<dyn Future<Output = io::Result<(usize, SocketAddr)>> + Send + 'a>>;

/// Future returned by [`ProxyTunnelTarget::udp_bind`].
pub type UdpBindFut<'a> =
    Pin<Box<dyn Future<Output = io::Result<Box<dyn ProxyUdpSocket>>> + Send + 'a>>;

/// Future returned by [`TunnelRouter::select_tunnel`].
pub type SelectTunnelFut<'a> =
    Pin<Box<dyn Future<Output = io::Result<Arc<dyn ProxyTunnelTarget>>> + Send + 'a>>;

/// Future returned by [`ProxyTunnelTarget::resolve_all_in_tunnel`].
pub type ResolveAllFut<'a> = Pin<Box<dyn Future<Output = io::Result<Vec<IpAddr>>> + Send + 'a>>;

/// Trait abstracting a virtual or physical UDP socket used by proxy relays.
pub trait ProxyUdpSocket: Send + Sync {
    /// Send a UDP datagram to the specified destination.
    fn send_to<'a>(
        &'a self,
        buf: &'a [u8],
        target: SocketAddr,
    ) -> Pin<Box<dyn Future<Output = io::Result<usize>> + Send + 'a>>;

    /// Receive a UDP datagram into the provided buffer.
    fn recv_from<'a>(&'a self, buf: &'a mut [u8]) -> RecvFromFut<'a>;

    /// Returns the bound local port of this UDP socket.
    fn local_port(&self) -> u16;
}

impl ProxyUdpSocket for VirtualUdpSocket {
    fn send_to<'a>(
        &'a self,
        buf: &'a [u8],
        target: SocketAddr,
    ) -> Pin<Box<dyn Future<Output = io::Result<usize>> + Send + 'a>> {
        Box::pin(async move { self.send_to(buf, target).await })
    }

    fn recv_from<'a>(
        &'a self,
        buf: &'a mut [u8],
    ) -> Pin<Box<dyn Future<Output = io::Result<(usize, SocketAddr)>> + Send + 'a>> {
        Box::pin(async move { self.recv_from(buf).await })
    }

    fn local_port(&self) -> u16 {
        self.local_port()
    }
}

impl ProxyUdpSocket for tokio::net::UdpSocket {
    fn send_to<'a>(
        &'a self,
        buf: &'a [u8],
        target: SocketAddr,
    ) -> Pin<Box<dyn Future<Output = io::Result<usize>> + Send + 'a>> {
        Box::pin(async move { Self::send_to(self, buf, target).await })
    }

    fn recv_from<'a>(
        &'a self,
        buf: &'a mut [u8],
    ) -> Pin<Box<dyn Future<Output = io::Result<(usize, SocketAddr)>> + Send + 'a>> {
        Box::pin(async move { Self::recv_from(self, buf).await })
    }

    fn local_port(&self) -> u16 {
        self.local_addr().map_or(0, |a| a.port())
    }
}

/// Abstract tunnel connector capable of establishing TCP streams, binding UDP sockets,
/// and resolving domain names through a WireGuard tunnel.
pub trait ProxyTunnelTarget: Send + Sync {
    /// Connect a TCP stream to the destination IP and port.
    fn tcp_connect<'a>(
        &'a self,
        dst: SocketAddr,
    ) -> Pin<Box<dyn Future<Output = io::Result<DynStream>> + Send + 'a>>;

    /// Bind a UDP socket in the tunnel.
    fn udp_bind(&self, local_port: u16) -> UdpBindFut<'_>;

    /// Resolve a domain name inside the tunnel.
    fn resolve_in_tunnel<'a>(
        &'a self,
        domain: &'a str,
    ) -> Pin<Box<dyn Future<Output = io::Result<IpAddr>> + Send + 'a>>;

    /// Resolve a domain name inside the tunnel, returning all candidate IP addresses.
    fn resolve_all_in_tunnel<'a>(&'a self, domain: &'a str) -> ResolveAllFut<'a> {
        Box::pin(async move { Ok(vec![self.resolve_in_tunnel(domain).await?]) })
    }

    /// Maximum total timeout budget for connecting across candidate addresses.
    fn connect_timeout(&self) -> Duration {
        DEFAULT_CONNECT_TIMEOUT
    }

    /// Optional identifier of the underlying tunnel for deduplicating pool failover attempts.
    fn tunnel_id(&self) -> Option<&str> {
        None
    }

    /// Record that an in-flight attempt through this target was aborted
    /// before it could deliver a verdict — for example, cut off by the
    /// pool failover budget or by a per-candidate connect timeout.
    /// An aborted attempt counts as a failed attempt for
    /// circuit-breaker purposes, so a `HalfOpen` trial resolves as a
    /// failure (back to `Unhealthy` with a fresh cooldown) instead of
    /// lingering undecided forever while every later request burns the
    /// full budget again. The default implementation does nothing;
    /// targets without health tracking keep it.
    fn note_attempt_aborted(&self) {}

    /// Whether this target is backed by a tunnel with a live session
    /// right now — recently proven by real traffic, so selecting it
    /// avoids paying a fresh activation + handshake inside the
    /// caller's failover budget. Pool selection prefers live targets
    /// and falls back to any registered target when none is live. The
    /// default is `false`: targets without liveness knowledge are
    /// eligible but never preferred.
    fn is_live(&self) -> bool {
        false
    }
}

/// Filter out forbidden destination IPs and cap candidates at [`MAX_CANDIDATE_IPS`],
/// preserving the caller's address-family priority ordering.
fn collect_bounded_candidates<I>(iter: I) -> Vec<SocketAddr>
where
    I: IntoIterator<Item = SocketAddr>,
{
    iter.into_iter()
        .filter(|addr| !is_forbidden_destination_ip(addr.ip()))
        .take(MAX_CANDIDATE_IPS)
        .collect()
}

/// Build bounded TCP socket candidates from validated IP addresses while preserving order.
pub(crate) fn bound_candidate_addrs(ips: &[IpAddr], port: u16) -> Vec<SocketAddr> {
    collect_bounded_candidates(ips.iter().copied().map(|ip| SocketAddr::new(ip, port)))
}

/// Filter and bound UDP target socket addresses to [`MAX_CANDIDATE_IPS`] while preserving order.
pub(crate) fn bound_candidate_socket_addrs(addrs: &[SocketAddr]) -> Vec<SocketAddr> {
    collect_bounded_candidates(addrs.iter().copied())
}

/// Compute the timeout budget for the next candidate attempt given the overall deadline.
///
/// Returns `None` once the total deadline has elapsed.
pub(crate) fn next_attempt_timeout(
    deadline: tokio::time::Instant,
    remaining_attempts: usize,
) -> Option<Duration> {
    let remaining_budget = deadline.saturating_duration_since(tokio::time::Instant::now());
    if remaining_budget.is_zero() || remaining_attempts == 0 {
        return None;
    }
    let divisor = u32::try_from(remaining_attempts).unwrap_or(u32::MAX);
    let fair_share = remaining_budget / divisor;
    Some(fair_share.max(MIN_ATTEMPT_TIMEOUT).min(remaining_budget))
}

fn empty_candidates_error(was_empty: bool, action: &str) -> io::Error {
    if was_empty {
        io::Error::new(
            io::ErrorKind::NotFound,
            format!("no candidate IP addresses to {action}"),
        )
    } else {
        io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!("all candidate IP addresses for {action} are forbidden"),
        )
    }
}

/// Resolve `domain` via `tunnel` and fail-closed reject if ANY returned IP is forbidden.
pub(crate) async fn resolve_and_validate_domain(
    tunnel: &dyn ProxyTunnelTarget,
    domain: &str,
) -> io::Result<Vec<IpAddr>> {
    let ips = tunnel.resolve_all_in_tunnel(domain).await?;
    if ips.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            format!("no IP addresses resolved for '{domain}'"),
        ));
    }
    if ips.iter().copied().any(is_forbidden_destination_ip) {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!("blocked forbidden destination IP in DNS response for '{domain}'"),
        ));
    }
    Ok(ips)
}

/// Categorized error from [`connect_via_router`] so protocol handlers can emit accurate status codes.
#[derive(Debug)]
pub(crate) enum RouterConnectError {
    SelectTunnel(io::Error),
    ForbiddenDestination(io::Error),
    DnsResolution(io::Error),
    TcpConnect(io::Error),
}

/// Whether a terminal [`RouterConnectError`] deserves the WARN in
/// [`log_terminal_connect_failure`]: only failures no other layer
/// warns about. The listener warns on `TimedOut` errors (that is where
/// the "pool failover budget exceeded" line comes from) and the
/// protocol handlers warn on tunnel-selection failures, so those are
/// excluded here — otherwise one failed connection would emit two WARN
/// lines. A forbidden destination is a deterministic policy rejection,
/// not a proxy failure, so it stays at the listener's debug line.
///
/// `pub(crate)` so the gating can be unit-tested directly.
pub(crate) fn should_warn_terminal_failure(error: &RouterConnectError) -> bool {
    match error {
        RouterConnectError::TcpConnect(e) | RouterConnectError::DnsResolution(e) => {
            e.kind() != io::ErrorKind::TimedOut
        }
        RouterConnectError::SelectTunnel(_) | RouterConnectError::ForbiddenDestination(_) => false,
    }
}

/// Log a terminal proxy-connection failure with enough context to
/// classify it in the next measurement run: which pool/tunnel
/// selector, which target, which tunnels were tried, how many attempts
/// ran, and the error itself. Without this line, a fast TCP refusal
/// or reset (or a DNS failure after all attempts) surfaced only as a
/// debug "connection ended" line with no target or tunnel context —
/// which is why the 0.25s/0.35s failures in the 2000-request
/// measurement could not be classified. One line per failed
/// connection, never per attempt: at the measured 0.15% failure rate
/// this is rare and actionable (WARN), not noise.
fn log_terminal_connect_failure(
    selector: &TunnelSelector,
    target: &TargetAddr,
    tried_ids: &[String],
    attempts: usize,
    error: &RouterConnectError,
) {
    if !should_warn_terminal_failure(error) {
        return;
    }
    let (kind, inner) = match error {
        RouterConnectError::TcpConnect(e) => ("tcp_connect", e),
        RouterConnectError::DnsResolution(e) => ("dns_resolution", e),
        RouterConnectError::SelectTunnel(_) | RouterConnectError::ForbiddenDestination(_) => {
            return;
        }
    };
    tracing::warn!(
        selector = ?selector,
        target = %target,
        tried_tunnels = ?tried_ids,
        attempts = attempts,
        error_kind = kind,
        "proxy connection failed: {inner}"
    );
}

/// Select a tunnel (with failover across healthy pool tunnels on transient DNS/connect failures)
/// and establish a validated TCP stream to `target`.
///
/// Returns the stream plus the id of the tunnel that served the
/// connection (the last id in the attempt list), so protocol handlers
/// can name the tunnel in post-grant session logging — a stream alone
/// carries no tunnel identity.
///
/// `exclude_tunnel` names a tunnel that must never be selected on
/// this call: a zero-response retry re-dials after that tunnel closed
/// the session with no data, so reusing it would replay the request
/// into the same dead session. An excluded tunnel is skipped before
/// dialing (it is not counted as an attempt); the skip is bounded by
/// the attempt budget, so a single-tunnel pool fails fast with
/// `NotConnected` instead of selecting forever. `None` is the
/// ordinary first dial.
///
/// `credentials` are forwarded to [`TunnelRouter::select_tunnel`] so a
/// router can verify them against the tunnel it finally selects.
pub(crate) async fn connect_via_router(
    router: &Arc<dyn TunnelRouter>,
    selector: &TunnelSelector,
    target: &TargetAddr,
    credentials: Option<(&str, &str)>,
    exclude_tunnel: Option<&str>,
) -> Result<(DynStream, Option<String>), RouterConnectError> {
    // Select the tunnel — and verify the caller's credentials against
    // it — BEFORE any DNS leaves the daemon. The old pre-resolve asked
    // the router for a live target with no selector binding, so the
    // query egressed via whatever warm-list tunnel happened to be
    // live, even for a client whose credentials the selected tunnel
    // rejects (audit run-3 #7). A selection failure is terminal here,
    // so a rejected client causes zero DNS queries anywhere.
    //
    // The pre-resolve still only runs on a live tunnel: the
    // singleflight query must never go through a cold tunnel. The
    // measured failure was one cold-tunnel query timing out (1 s DNS
    // deadline vs a handshake that takes longer) and fanning out to
    // 31 waiters in 38 ms — every one of them logging a WARN on
    // attempt 1/3. A pre-resolve on the selected live tunnel populates
    // the shared cache, so the race legs hit the LRU fast-path instead
    // of creating a cell on a cold tunnel; when the domain is already
    // cached this is just the LRU lookup. A pre-resolve failure is
    // best-effort and falls through to the per-leg resolve below, so
    // a selected tunnel that is not live behaves exactly as before.
    // The failover deadline is created after this, so the pre-resolve
    // never eats the race budget.
    //
    // The pre-selected target is dropped at the end of this block —
    // its trial slot, if one was claimed, is released by the guard's
    // `Drop` — and the failover loop below selects the dial tunnel
    // itself.
    if let TargetAddr::Domain(domain, _) = target {
        let selected = match router.select_tunnel(selector, credentials).await {
            Ok(target) => target,
            Err(e) => return Err(RouterConnectError::SelectTunnel(e)),
        };
        let excluded = selected.tunnel_id() == exclude_tunnel;
        if selected.is_live()
            && !excluded
            && let Err(e) = resolve_and_validate_domain(selected.as_ref(), domain).await
        {
            tracing::debug!(
                "live pre-resolve of '{domain}' failed ({}); falling back to per-leg resolve",
                e
            );
        }
    }

    let max_attempts = if matches!(selector, TunnelSelector::ById(_)) {
        1
    } else {
        MAX_POOL_FAILOVER_ATTEMPTS
    };

    let mut last_err: Option<RouterConnectError> = None;
    let mut tried_ids: SmallVec<[String; MAX_POOL_FAILOVER_ATTEMPTS]> = SmallVec::new();
    let mut attempts_run = 0;
    let mut excluded_skips = 0;
    let failover_deadline = tokio::time::Instant::now() + MAX_POOL_FAILOVER_BUDGET;
    for attempt in 0..max_attempts {
        if !within_failover_budget(attempt, failover_deadline) {
            break;
        }
        attempts_run += 1;
        let target_tunnel = match router.select_tunnel(selector, credentials).await {
            Ok(t) => t,
            Err(e) => {
                // A credential failure is terminal and must not be masked
                // by an earlier attempt's error: the client presented
                // credentials the selected tunnel rejects.
                if e.kind() == io::ErrorKind::PermissionDenied {
                    return Err(RouterConnectError::SelectTunnel(e));
                }
                let err = last_err.unwrap_or(RouterConnectError::SelectTunnel(e));
                log_terminal_connect_failure(selector, target, &tried_ids, attempts_run, &err);
                return Err(err);
            }
        };

        if let Some(id) = target_tunnel.tunnel_id() {
            if Some(id) == exclude_tunnel {
                // The pool returned the tunnel this call must not
                // reuse. Select again instead of dialing it; the skip
                // is bounded so a pool with no other tunnel fails
                // fast instead of selecting forever.
                excluded_skips += 1;
                if excluded_skips >= max_attempts {
                    return Err(RouterConnectError::SelectTunnel(io::Error::new(
                        io::ErrorKind::NotConnected,
                        format!("no healthy tunnels available excluding '{id}'"),
                    )));
                }
                continue;
            }
            if tried_ids.iter().any(|prev| prev == id) {
                break;
            }
            tried_ids.push(id.to_string());
        }

        let attempt_res = if max_attempts > 1 {
            let remaining =
                failover_deadline.saturating_duration_since(tokio::time::Instant::now());
            if remaining.is_zero() {
                break;
            }
            let race = LegRace {
                router,
                selector,
                target,
                credentials,
                exclude_tunnel,
                deadline: failover_deadline,
                attempt,
                max_attempts,
            };
            race.race(target_tunnel, &mut tried_ids).await
        } else {
            connect_target(&target_tunnel, target, attempt, max_attempts, true)
                .await
                .map(|stream| (stream, tried_ids.last().cloned()))
        };

        match attempt_res {
            Ok((stream, winner)) => return Ok((stream, winner)),
            Err(err @ RouterConnectError::ForbiddenDestination(_)) => return Err(err),
            Err(err) => {
                last_err = Some(err);
            }
        }
    }

    let err = last_err.unwrap_or_else(|| {
        RouterConnectError::SelectTunnel(io::Error::new(
            io::ErrorKind::NotConnected,
            "no healthy tunnels available in pool",
        ))
    });
    log_terminal_connect_failure(selector, target, &tried_ids, attempts_run, &err);
    Err(err)
}

/// Which leg of a pool race an outcome belongs to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RaceLeg {
    First,
    Second,
}

/// Outcome of one race leg: which leg it was, and its dial result.
type LegOutcome = (RaceLeg, Result<DynStream, RouterConnectError>);

/// Tries to select a second tunnel distinct from the first leg.
const MAX_RACE_SELECT_TRIES: usize = 3;

/// Everything one pool race needs, bundled so the race helpers stay
/// under the argument limit.
struct LegRace<'a> {
    router: &'a Arc<dyn TunnelRouter>,
    selector: &'a TunnelSelector,
    target: &'a TargetAddr,
    credentials: Option<(&'a str, &'a str)>,
    exclude_tunnel: Option<&'a str>,
    deadline: tokio::time::Instant,
    attempt: usize,
    max_attempts: usize,
}

impl LegRace<'_> {
    /// Deadline for one race leg: the remaining failover budget,
    /// capped at [`FIRST_ATTEMPT_TIMEOUT`].
    fn first_leg_timeout(&self) -> Duration {
        self.deadline
            .saturating_duration_since(tokio::time::Instant::now())
            .min(FIRST_ATTEMPT_TIMEOUT)
    }

    /// Spawn one race leg: the dial bounded by the per-attempt
    /// deadline. A deadline cut resolves the attempt as aborted, so a
    /// HalfOpen trial cannot linger undecided (the same guarantee the
    /// old whole-budget timeout gave, now per leg).
    fn spawn_leg(
        &self,
        set: &mut tokio::task::JoinSet<LegOutcome>,
        tunnel: Arc<dyn ProxyTunnelTarget>,
        leg: RaceLeg,
    ) {
        let target = self.target.clone();
        let attempt = self.attempt;
        let max_attempts = self.max_attempts;
        let timeout = self.first_leg_timeout();
        set.spawn(async move {
            let result = tokio::time::timeout(
                timeout,
                connect_target(&tunnel, &target, attempt, max_attempts, true),
            )
            .await
            .unwrap_or_else(|_| {
                tunnel.note_attempt_aborted();
                Err(RouterConnectError::TcpConnect(io::Error::new(
                    io::ErrorKind::TimedOut,
                    format!("connect attempt timed out after {timeout:?}"),
                )))
            });
            (leg, result)
        });
    }

    /// Select a tunnel distinct from the first leg (and from the
    /// excluded tunnel) for the hedge. Retried a few times because
    /// the router may return the first leg again; `None` means no
    /// second leg is available and the first leg runs alone.
    async fn select_distinct(&self, tried_ids: &[String]) -> Option<Arc<dyn ProxyTunnelTarget>> {
        for _ in 0..MAX_RACE_SELECT_TRIES {
            let Ok(target) = self
                .router
                .select_tunnel(self.selector, self.credentials)
                .await
            else {
                continue;
            };
            let distinct = target.tunnel_id().is_none_or(|id| {
                Some(id) != self.exclude_tunnel && !tried_ids.iter().any(|prev| prev == id)
            });
            if distinct {
                return Some(target);
            }
        }
        None
    }

    /// Start the hedge leg on a distinct tunnel, if one is available,
    /// recording it so the race can cancel and resolve it on a win.
    async fn spawn_hedge(
        &self,
        set: &mut tokio::task::JoinSet<LegOutcome>,
        tried_ids: &[String],
        second: &mut Option<Arc<dyn ProxyTunnelTarget>>,
    ) {
        let Some(distinct) = self.select_distinct(tried_ids).await else {
            return;
        };
        self.spawn_leg(set, Arc::clone(&distinct), RaceLeg::Second);
        *second = Some(distinct);
    }

    /// Race the first leg against a hedged second leg and return the
    /// winner's stream and tunnel id.
    ///
    /// The first leg runs with a per-attempt deadline. If it has not
    /// finished after [`RACE_STAGGER`] and its tunnel is not live, a
    /// second leg starts on a different tunnel; the first success
    /// wins and the loser is cancelled at once (its dial future is
    /// dropped, the netstack socket guard removes the socket, and its
    /// trial is resolved as inconclusive). A live first leg is never
    /// hedged — hedging it would only double-spend a healthy tunnel
    /// for a slow target. A leg that fails fast hedges immediately
    /// instead of waiting out the stagger.
    async fn race(
        &self,
        first: Arc<dyn ProxyTunnelTarget>,
        tried_ids: &mut SmallVec<[String; MAX_POOL_FAILOVER_ATTEMPTS]>,
    ) -> Result<(DynStream, Option<String>), RouterConnectError> {
        let first_is_live = first.is_live();
        let first_id = first.tunnel_id().map(str::to_string);
        let mut set: tokio::task::JoinSet<LegOutcome> = tokio::task::JoinSet::new();
        self.spawn_leg(&mut set, Arc::clone(&first), RaceLeg::First);
        let mut second: Option<Arc<dyn ProxyTunnelTarget>> = None;
        let mut first_done = false;
        let mut second_done = false;
        let mut hedge_spawned = false;
        let mut last_err: Option<RouterConnectError> = None;
        let hedge_deadline = tokio::time::sleep(RACE_STAGGER);
        tokio::pin!(hedge_deadline);
        loop {
            if set.is_empty() {
                break;
            }
            tokio::select! {
                biased;
                res = set.join_next() => {
                    let Some(joined) = res else { break };
                    let Ok((leg, outcome)) = joined else {
                        last_err = Some(RouterConnectError::TcpConnect(io::Error::other(
                            "race leg task ended unexpectedly",
                        )));
                        continue;
                    };
                    match leg {
                        RaceLeg::First => first_done = true,
                        RaceLeg::Second => second_done = true,
                    }
                    match outcome {
                        Ok(stream) => {
                            abort_loser(
                                &mut set,
                                leg,
                                &first,
                                second.as_ref(),
                                first_done,
                                second_done,
                            );
                            match leg {
                                RaceLeg::First => return Ok((stream, first_id)),
                                RaceLeg::Second => {
                                    let winner_id = second
                                        .as_ref()
                                        .and_then(|t| t.tunnel_id().map(str::to_string));
                                    if let Some(id) = &winner_id {
                                        tried_ids.push(id.clone());
                                    }
                                    return Ok((stream, winner_id));
                                }
                            }
                        }
                        Err(err @ RouterConnectError::ForbiddenDestination(_)) => {
                            abort_loser(
                                &mut set,
                                leg,
                                &first,
                                second.as_ref(),
                                first_done,
                                second_done,
                            );
                            return Err(err);
                        }
                        Err(err) => {
                            last_err = Some(err);
                            if leg == RaceLeg::First && !hedge_spawned && !first_is_live {
                                hedge_spawned = true;
                                self.spawn_hedge(&mut set, tried_ids, &mut second).await;
                            }
                        }
                    }
                }
                () = &mut hedge_deadline, if !hedge_spawned && !first_is_live => {
                    hedge_spawned = true;
                    self.spawn_hedge(&mut set, tried_ids, &mut second).await;
                }
            }
        }
        Err(last_err.unwrap_or_else(|| {
            RouterConnectError::SelectTunnel(io::Error::new(
                io::ErrorKind::NotConnected,
                "no healthy tunnels available in pool",
            ))
        }))
    }
}

/// Cancel the still-running leg after the race is decided and resolve
/// its trial as inconclusive: it was cut off mid-flight, so it
/// delivered no verdict about its tunnel. A leg that already finished
/// resolved its own trial and is left alone. The aborted task's dial
/// future is dropped, and the netstack socket guard removes its
/// socket, so no socket or session leaks.
fn abort_loser(
    set: &mut tokio::task::JoinSet<LegOutcome>,
    winner: RaceLeg,
    first: &Arc<dyn ProxyTunnelTarget>,
    second: Option<&Arc<dyn ProxyTunnelTarget>>,
    first_done: bool,
    second_done: bool,
) {
    set.abort_all();
    match winner {
        RaceLeg::First => {
            if !second_done && let Some(loser) = second {
                loser.note_attempt_aborted();
            }
        }
        RaceLeg::Second => {
            if !first_done {
                first.note_attempt_aborted();
            }
        }
    }
}

/// True while the pool-failover budget still allows another attempt.
fn within_failover_budget(attempt: usize, deadline: tokio::time::Instant) -> bool {
    if attempt == 0 {
        return true;
    }
    deadline.saturating_duration_since(tokio::time::Instant::now()) >= MIN_ATTEMPT_TIMEOUT
}

/// Attempt one connection through `target_tunnel` for `target`.
async fn connect_target(
    target_tunnel: &Arc<dyn ProxyTunnelTarget>,
    target: &TargetAddr,
    attempt: usize,
    max_attempts: usize,
    warn_dns: bool,
) -> Result<DynStream, RouterConnectError> {
    match target {
        TargetAddr::Ip(dst_addr) => target_tunnel
            .tcp_connect(*dst_addr)
            .await
            .map_err(RouterConnectError::TcpConnect),
        TargetAddr::Domain(domain, port) => {
            match resolve_and_validate_domain(target_tunnel.as_ref(), domain).await {
                Ok(ips) => connect_validated_addrs(target_tunnel.as_ref(), &ips, *port)
                    .await
                    .map_err(RouterConnectError::TcpConnect),
                Err(e) if e.kind() == io::ErrorKind::PermissionDenied => {
                    Err(RouterConnectError::ForbiddenDestination(e))
                }
                Err(e) => {
                    // A replay dial is best-effort: its failures are
                    // replay metrics, not WARNs, so the caller
                    // suppresses the DNS warning for it.
                    if warn_dns {
                        tracing::warn!(
                            "Failed to resolve target domain '{}' (attempt {}/{}): {:?}",
                            domain,
                            attempt + 1,
                            max_attempts,
                            e
                        );
                    }
                    Err(RouterConnectError::DnsResolution(e))
                }
            }
        }
    }
}

/// Dial `target` through exactly one tunnel selected by `selector`,
/// excluding `exclude_tunnel`, without the fix6 dial race and without
/// the pool failover loop: a post-send replay (fix5 retry or the
/// `safe_http_silence_replay`) must not start its own race, or one
/// replay would spend the whole request chain's dial budget on
/// speculative legs. The single dial is capped at
/// [`FIRST_ATTEMPT_TIMEOUT`], the same per-leg cap the race uses, so
/// a slow dormant tunnel fails the replay fast and the primary leg
/// keeps serving. Returns `NotConnected` when no tunnel other than
/// the excluded one exists (a `ById` selector, or a one-tunnel pool),
/// so the caller can tell "no different tunnel" apart from a dial
/// failure.
pub(crate) async fn connect_direct(
    router: &Arc<dyn TunnelRouter>,
    selector: &TunnelSelector,
    target: &TargetAddr,
    credentials: Option<(&str, &str)>,
    exclude_tunnel: Option<&str>,
) -> Result<(DynStream, Option<String>), RouterConnectError> {
    for attempt in 1..=MAX_RACE_SELECT_TRIES {
        let target_tunnel = router
            .select_tunnel(selector, credentials)
            .await
            .map_err(RouterConnectError::SelectTunnel)?;
        let id = target_tunnel.tunnel_id().map(str::to_string);
        if id.as_deref() == exclude_tunnel {
            continue;
        }
        let dial = connect_target(
            &target_tunnel,
            target,
            attempt,
            MAX_RACE_SELECT_TRIES,
            false,
        );
        return match tokio::time::timeout(FIRST_ATTEMPT_TIMEOUT, dial).await {
            Ok(Ok(stream)) => Ok((stream, id)),
            Ok(Err(e)) => Err(e),
            Err(_) => Err(RouterConnectError::TcpConnect(io::Error::new(
                io::ErrorKind::TimedOut,
                "replay dial timed out",
            ))),
        };
    }
    Err(RouterConnectError::SelectTunnel(io::Error::new(
        io::ErrorKind::NotConnected,
        "no tunnel other than the excluded one",
    )))
}

/// Dial TCP sequentially over validated candidate `IpAddr`s on `port` without re-resolving DNS,
/// using the tunnel's configured connection timeout as the total deadline budget.
pub(crate) async fn connect_validated_addrs(
    tunnel: &dyn ProxyTunnelTarget,
    ips: &[IpAddr],
    port: u16,
) -> io::Result<DynStream> {
    connect_validated_addrs_with_timeout(tunnel, ips, port, tunnel.connect_timeout()).await
}

/// Dial TCP sequentially over at most [`MAX_CANDIDATE_IPS`] validated candidates bounded by
/// `total_timeout` and proportional per-attempt timeout sharing.
pub(crate) async fn connect_validated_addrs_with_timeout(
    tunnel: &dyn ProxyTunnelTarget,
    ips: &[IpAddr],
    port: u16,
    total_timeout: Duration,
) -> io::Result<DynStream> {
    let candidates = bound_candidate_addrs(ips, port);
    if candidates.is_empty() {
        return Err(empty_candidates_error(ips.is_empty(), "connect"));
    }

    let deadline = tokio::time::Instant::now() + total_timeout;
    let total_candidates = candidates.len();
    let mut last_err = None;

    for (idx, dst_addr) in candidates.into_iter().enumerate() {
        let Some(attempt_timeout) = next_attempt_timeout(deadline, total_candidates - idx) else {
            return Err(last_err.unwrap_or_else(|| {
                io::Error::new(
                    io::ErrorKind::TimedOut,
                    "connection attempt deadline exceeded",
                )
            }));
        };

        match tokio::time::timeout(attempt_timeout, tunnel.tcp_connect(dst_addr)).await {
            Ok(Ok(stream)) => return Ok(stream),
            Ok(Err(e)) => last_err = Some(e),
            Err(_) => {
                // The per-candidate timeout dropped the connect future
                // mid-flight without a verdict; resolve it as a
                // failure (see `note_attempt_aborted`) so a `HalfOpen`
                // trial cannot linger undecided.
                tunnel.note_attempt_aborted();
                last_err = Some(io::Error::new(
                    io::ErrorKind::TimedOut,
                    format!("connect attempt to {dst_addr} timed out after {attempt_timeout:?}"),
                ));
            }
        }
    }

    Err(last_err.unwrap_or_else(|| {
        io::Error::new(
            io::ErrorKind::TimedOut,
            "all candidate connection attempts failed",
        )
    }))
}

/// Send a UDP datagram sequentially over validated candidate `SocketAddr`s within the default
/// total timeout budget.
pub(crate) async fn send_udp_to_validated_addrs(
    virtual_udp: &dyn ProxyUdpSocket,
    payload: &[u8],
    addrs: &[SocketAddr],
) -> io::Result<()> {
    send_udp_to_validated_addrs_with_timeout(virtual_udp, payload, addrs, DEFAULT_UDP_SEND_TIMEOUT)
        .await
}

/// Send a UDP datagram sequentially over at most [`MAX_CANDIDATE_IPS`] validated candidates
/// bounded by `total_timeout` and proportional per-attempt timeout sharing.
pub(crate) async fn send_udp_to_validated_addrs_with_timeout(
    virtual_udp: &dyn ProxyUdpSocket,
    payload: &[u8],
    addrs: &[SocketAddr],
    total_timeout: Duration,
) -> io::Result<()> {
    let candidates = bound_candidate_socket_addrs(addrs);
    if candidates.is_empty() {
        return Err(empty_candidates_error(addrs.is_empty(), "send UDP"));
    }

    let deadline = tokio::time::Instant::now() + total_timeout;
    let total_candidates = candidates.len();
    let mut last_err = None;

    for (idx, target_sock) in candidates.into_iter().enumerate() {
        let Some(attempt_timeout) = next_attempt_timeout(deadline, total_candidates - idx) else {
            return Err(last_err.unwrap_or_else(|| {
                io::Error::new(
                    io::ErrorKind::TimedOut,
                    "UDP send attempt deadline exceeded",
                )
            }));
        };

        match tokio::time::timeout(attempt_timeout, virtual_udp.send_to(payload, target_sock)).await
        {
            Ok(Ok(_)) => return Ok(()),
            Ok(Err(e)) => last_err = Some(e),
            Err(_) => {
                last_err = Some(io::Error::new(
                    io::ErrorKind::TimedOut,
                    format!("UDP send to {target_sock} timed out after {attempt_timeout:?}"),
                ));
            }
        }
    }

    Err(last_err.unwrap_or_else(|| {
        io::Error::new(
            io::ErrorKind::TimedOut,
            "all candidate UDP send attempts failed",
        )
    }))
}

impl ProxyTunnelTarget for VirtualNetworkStack {
    fn tcp_connect<'a>(
        &'a self,
        dst: SocketAddr,
    ) -> Pin<Box<dyn Future<Output = io::Result<DynStream>> + Send + 'a>> {
        Box::pin(async move {
            let stream: DynStream = Box::new(self.tcp_connect(dst).await?);
            Ok(stream)
        })
    }

    fn udp_bind<'a>(
        &'a self,
        local_port: u16,
    ) -> Pin<Box<dyn Future<Output = io::Result<Box<dyn ProxyUdpSocket>>> + Send + 'a>> {
        let res = self.udp_bind(local_port).map(|sock| {
            let boxed: Box<dyn ProxyUdpSocket> = Box::new(sock);
            boxed
        });
        Box::pin(std::future::ready(res))
    }

    fn resolve_in_tunnel<'a>(
        &'a self,
        domain: &'a str,
    ) -> Pin<Box<dyn Future<Output = io::Result<IpAddr>> + Send + 'a>> {
        Box::pin(async move { self.resolve_in_tunnel(domain).await })
    }

    fn resolve_all_in_tunnel<'a>(&'a self, domain: &'a str) -> ResolveAllFut<'a> {
        Box::pin(async move { self.resolve_all_in_tunnel(domain).await })
    }

    fn connect_timeout(&self) -> Duration {
        self.connect_timeout()
    }
}

impl<T: ProxyTunnelTarget + ?Sized> ProxyTunnelTarget for Arc<T> {
    fn tcp_connect<'a>(
        &'a self,
        dst: SocketAddr,
    ) -> Pin<Box<dyn Future<Output = io::Result<DynStream>> + Send + 'a>> {
        (**self).tcp_connect(dst)
    }

    fn udp_bind<'a>(
        &'a self,
        local_port: u16,
    ) -> Pin<Box<dyn Future<Output = io::Result<Box<dyn ProxyUdpSocket>>> + Send + 'a>> {
        (**self).udp_bind(local_port)
    }

    fn resolve_in_tunnel<'a>(
        &'a self,
        domain: &'a str,
    ) -> Pin<Box<dyn Future<Output = io::Result<IpAddr>> + Send + 'a>> {
        (**self).resolve_in_tunnel(domain)
    }

    fn resolve_all_in_tunnel<'a>(&'a self, domain: &'a str) -> ResolveAllFut<'a> {
        (**self).resolve_all_in_tunnel(domain)
    }

    fn connect_timeout(&self) -> Duration {
        (**self).connect_timeout()
    }

    fn tunnel_id(&self) -> Option<&str> {
        (**self).tunnel_id()
    }

    fn note_attempt_aborted(&self) {
        (**self).note_attempt_aborted();
    }

    fn is_live(&self) -> bool {
        (**self).is_live()
    }
}

/// Direct host connector bypassing WireGuard tunnels (useful for loopback testing).
#[derive(Debug)]
pub struct DirectTunnelTarget;

impl ProxyTunnelTarget for DirectTunnelTarget {
    fn tcp_connect<'a>(
        &'a self,
        dst: SocketAddr,
    ) -> Pin<Box<dyn Future<Output = io::Result<DynStream>> + Send + 'a>> {
        Box::pin(async move {
            let stream: DynStream = Box::new(tokio::net::TcpStream::connect(dst).await?);
            Ok(stream)
        })
    }

    fn udp_bind<'a>(
        &'a self,
        local_port: u16,
    ) -> Pin<Box<dyn Future<Output = io::Result<Box<dyn ProxyUdpSocket>>> + Send + 'a>> {
        Box::pin(async move {
            let bind_addr = SocketAddr::from(([0, 0, 0, 0], local_port));
            let socket: Box<dyn ProxyUdpSocket> =
                Box::new(tokio::net::UdpSocket::bind(bind_addr).await?);
            Ok(socket)
        })
    }

    fn resolve_in_tunnel<'a>(
        &'a self,
        domain: &'a str,
    ) -> Pin<Box<dyn Future<Output = io::Result<IpAddr>> + Send + 'a>> {
        Box::pin(async move {
            if let Ok(ip) = domain.parse::<IpAddr>() {
                return Ok(ip);
            }
            let host_port = format!("{domain}:0");
            let mut addrs = tokio::net::lookup_host(&host_port).await?;
            addrs
                .next()
                .map(|s| s.ip())
                .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "no addresses found"))
        })
    }

    fn resolve_all_in_tunnel<'a>(&'a self, domain: &'a str) -> ResolveAllFut<'a> {
        Box::pin(async move {
            if let Ok(ip) = domain.parse::<IpAddr>() {
                return Ok(vec![ip]);
            }
            let host_port = format!("{domain}:0");
            let ips: Vec<IpAddr> = tokio::net::lookup_host(&host_port)
                .await?
                .map(|s| s.ip())
                .collect();
            if ips.is_empty() {
                Err(io::Error::new(
                    io::ErrorKind::NotFound,
                    "no addresses found",
                ))
            } else {
                Ok(ips)
            }
        })
    }
}

/// Pool strategy keyword parsed from username.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PoolKeyword {
    Auto,
    Random,
    RoundRobin,
    LeastConn,
}

/// Tunnel selector extracted from client authentication username or connection mode.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TunnelSelector {
    /// Explicit tunnel ID (e.g., "wgcf-001").
    ById(String),
    /// Tunnel pool strategy keyword ("auto", "random", "round-robin", "least-conn").
    ByKeyword(PoolKeyword),
    /// Group tag selector ("tag:premium").
    ByTag(String),
    /// Default pool strategy selection when unauthenticated or omitted.
    DefaultPool,
}

impl TunnelSelector {
    /// Parse username string into a `TunnelSelector`.
    pub fn parse(username: &str) -> Self {
        let u = username.trim();
        if u.is_empty() || u.eq_ignore_ascii_case("default") {
            return Self::DefaultPool;
        }
        if u.eq_ignore_ascii_case("auto") {
            return Self::ByKeyword(PoolKeyword::Auto);
        }
        if u.eq_ignore_ascii_case("random") {
            return Self::ByKeyword(PoolKeyword::Random);
        }
        if u.eq_ignore_ascii_case("round-robin") || u.eq_ignore_ascii_case("roundrobin") {
            return Self::ByKeyword(PoolKeyword::RoundRobin);
        }
        if u.eq_ignore_ascii_case("least-conn") || u.eq_ignore_ascii_case("leastconn") {
            return Self::ByKeyword(PoolKeyword::LeastConn);
        }
        if let Some(tag) = u.strip_prefix("tag:")
            && !tag.is_empty()
        {
            return Self::ByTag(tag.to_string());
        }
        Self::ById(u.to_string())
    }
}

/// Errors during proxy authentication or tunnel resolution.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ProxyAuthError {
    #[error("Proxy authentication required")]
    AuthRequired,
    #[error("Invalid proxy credentials")]
    InvalidCredentials,
    #[error("Tunnel with ID '{0}' not found")]
    TunnelNotFound(String),
    #[error("No available tunnel in pool")]
    NoAvailableTunnel,
}

/// Core router interface responsible for verifying proxy credentials and selecting
/// a target tunnel connector.
pub trait TunnelRouter: Send + Sync {
    /// Validate client credentials (if provided or required) and return a [`TunnelSelector`].
    fn authenticate(
        &self,
        credentials: Option<(&str, &str)>,
    ) -> Result<TunnelSelector, ProxyAuthError>;

    /// Resolve a [`TunnelSelector`] to an active [`ProxyTunnelTarget`].
    ///
    /// `credentials` are the credentials the client presented at auth
    /// time (the same pair passed to `authenticate`). A router that
    /// enforces per-tunnel passwords verifies them here against the
    /// password of the tunnel the selector finally resolves to, so a
    /// selector that does not name a tunnel (tag, keyword, default pool)
    /// cannot smuggle the global password into a password-protected
    /// tunnel (audit run-1,
    /// `proxy.auth.per-tunnel-password-bypass-via-tag-selector`).
    /// Routers without per-tunnel passwords ignore the argument.
    fn select_tunnel<'a>(
        &'a self,
        selector: &'a TunnelSelector,
        credentials: Option<(&'a str, &'a str)>,
    ) -> SelectTunnelFut<'a>;

    /// Record a blackhole session on `tunnel_id`: the client sent
    /// its request through this tunnel and received zero response
    /// bytes while the tunnel stayed silent. The router charges
    /// the failure to the tunnel's health so the selector avoids a
    /// tunnel that is currently blackholing. Callers must only
    /// report a tunnel whose request was actually sent and whose
    /// silence was observed — never a client abort before the
    /// first byte. The default is a no-op (pool routers do not
    /// track per-tunnel health).
    fn record_tunnel_blackhole(&self, _tunnel_id: &str) {}

    /// Record one first-byte latency sample (milliseconds) for
    /// `tunnel_id` into the Peak-EWMA. For the hedge-loser
    /// observer: a primary that answered late proved itself slow,
    /// not dead, so its observed latency — not a maximal failure
    /// sample — feeds the score. The default is a no-op.
    fn record_tunnel_rtt(&self, _tunnel_id: &str, _sample_ms: u64) {}

    /// Record a transport failure on `tunnel_id`: the tunnel's
    /// connection died (EOF / reset) before answering. The router
    /// charges the failure to the tunnel's health, but — unlike a
    /// blackhole — does not drop it from the warm list: a dead
    /// connection is not evidence the tunnel is silently
    /// blackholing. The default is a no-op.
    fn record_tunnel_transport_failure(&self, _tunnel_id: &str) {}
}

impl<T: TunnelRouter + ?Sized> TunnelRouter for Arc<T> {
    fn authenticate(
        &self,
        credentials: Option<(&str, &str)>,
    ) -> Result<TunnelSelector, ProxyAuthError> {
        (**self).authenticate(credentials)
    }

    fn select_tunnel<'a>(
        &'a self,
        selector: &'a TunnelSelector,
        credentials: Option<(&'a str, &'a str)>,
    ) -> Pin<Box<dyn Future<Output = io::Result<Arc<dyn ProxyTunnelTarget>>> + Send + 'a>> {
        (**self).select_tunnel(selector, credentials)
    }

    fn record_tunnel_blackhole(&self, tunnel_id: &str) {
        (**self).record_tunnel_blackhole(tunnel_id);
    }

    fn record_tunnel_rtt(&self, tunnel_id: &str, sample_ms: u64) {
        (**self).record_tunnel_rtt(tunnel_id, sample_ms);
    }

    fn record_tunnel_transport_failure(&self, tunnel_id: &str) {
        (**self).record_tunnel_transport_failure(tunnel_id);
    }
}

/// Router for dedicated per-tunnel ports forwarding all connections to a single tunnel target.
pub struct SingleTunnelRouter {
    target: Arc<dyn ProxyTunnelTarget>,
    tunnel_id: String,
    auth: Option<(String, String)>,
}

impl std::fmt::Debug for SingleTunnelRouter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SingleTunnelRouter")
            .field("tunnel_id", &self.tunnel_id)
            .field("has_auth", &self.auth.is_some())
            .finish_non_exhaustive()
    }
}

impl SingleTunnelRouter {
    /// Create a new router for a single tunnel with optional username/password authentication.
    pub fn new(
        tunnel_id: impl Into<String>,
        target: Arc<dyn ProxyTunnelTarget>,
        auth: Option<(String, String)>,
    ) -> Self {
        Self {
            target,
            tunnel_id: tunnel_id.into(),
            auth,
        }
    }
}

/// Maximum input length compared by [`constant_time_eq_str`]: the
/// comparison always iterates exactly this many bytes, so its running
/// time cannot reveal either input's length (audit run-3 #8). Inputs
/// longer than this fail closed — they can never compare equal — which
/// is safe for the short secrets this guards (admin tokens, proxy
/// passwords): it can only reject absurdly long credentials, never
/// accept a wrong one.
const MAX_COMPARED_SECRET_LEN: usize = 256;

/// Constant-time string comparison independent of both inputs' lengths.
///
/// It always iterates exactly [`MAX_COMPARED_SECRET_LEN`] bytes,
/// treating missing bytes as 0, so no length knee is observable (audit
/// run-3 #8: the old loop ran `max(len)` iterations, costing ~+0.8
/// ns/byte past the secret length, with the knee exactly at the secret
/// length). Length (in)equality is folded into the accumulator, never
/// branched on early. Inputs longer than the cap compare unequal.
pub fn constant_time_eq_str(a: &str, b: &str) -> bool {
    let a = a.as_bytes();
    let b = b.as_bytes();
    let mut diff = usize::from(a.len() != b.len());
    diff |= usize::from(a.len() > MAX_COMPARED_SECRET_LEN);
    diff |= usize::from(b.len() > MAX_COMPARED_SECRET_LEN);
    for i in 0..MAX_COMPARED_SECRET_LEN {
        let x = a.get(i).copied().unwrap_or(0);
        let y = b.get(i).copied().unwrap_or(0);
        diff |= usize::from(x ^ y);
    }
    diff == 0
}

/// Compare both halves of a credential pair, always running both.
///
/// Combining them with `&&` would skip the password check when the
/// username mismatches, leaking which half failed through timing (audit
/// run-3 #8: ~+13 ns for right-user/wrong-pass vs wrong-user). The `&`
/// below only combines already-computed results.
pub fn credentials_match(presented: (&str, &str), expected: (&str, &str)) -> bool {
    let user_matches = constant_time_eq_str(presented.0, expected.0);
    let pass_matches = constant_time_eq_str(presented.1, expected.1);
    user_matches & pass_matches
}

/// Shared credential check for routers that resolve a [`TunnelSelector`]
/// from optional SOCKS5/HTTP credentials.
///
/// [`MultiTenantRouter`](crate::core::router::MultiTenantRouter) and
/// [`PoolRouter`] authenticate the same way; the only difference is how
/// `AuthMode::None` without credentials behaves: a pool router always falls
/// back to the default pool, while a multi-tenant router requires anonymous
/// access to be enabled (see `none_without_credentials_ok`).
#[derive(Debug)]
pub struct AuthChecker<'a> {
    /// Auth mode selecting which credentials are accepted.
    pub auth_mode: AuthMode,
    /// Optional global password accepted for any selector.
    pub global_password: &'a Option<String>,
    /// Per-tunnel password overrides, keyed by tunnel id.
    pub per_tunnel_passwords: &'a RwLock<HashMap<String, String>>,
    /// Whether requests without credentials may use the default pool.
    pub allow_anonymous: bool,
    /// When true, `AuthMode::None` without credentials always selects the
    /// default pool instead of requiring anonymous access.
    pub none_without_credentials_ok: bool,
}

impl AuthChecker<'_> {
    /// Resolve `credentials` to a tunnel selector under this checker's config.
    pub fn authenticate(
        &self,
        credentials: Option<(&str, &str)>,
    ) -> Result<TunnelSelector, ProxyAuthError> {
        match self.auth_mode {
            AuthMode::None => match credentials {
                Some((user, _pass)) => Ok(TunnelSelector::parse(user)),
                None if self.none_without_credentials_ok => Ok(TunnelSelector::DefaultPool),
                None => self.anonymous_or_required(),
            },
            AuthMode::Global => match credentials {
                None => self.anonymous_or_required(),
                Some((user, pass)) => self.check_global_password(user, pass),
            },
            AuthMode::PerTunnel => match credentials {
                None => self.anonymous_or_required(),
                Some((user, pass)) => {
                    let selector = TunnelSelector::parse(user);
                    self.per_tunnel_password(&selector).map_or_else(
                        || self.check_global_password(user, pass),
                        |tunnel_pass| {
                            if constant_time_eq_str(pass, &tunnel_pass) {
                                Ok(selector)
                            } else {
                                Err(ProxyAuthError::InvalidCredentials)
                            }
                        },
                    )
                }
            },
        }
    }

    /// `DefaultPool` when anonymous access is allowed, else auth is required.
    const fn anonymous_or_required(&self) -> Result<TunnelSelector, ProxyAuthError> {
        if self.allow_anonymous {
            Ok(TunnelSelector::DefaultPool)
        } else {
            Err(ProxyAuthError::AuthRequired)
        }
    }

    /// Check `pass` against the global password, falling back to anonymous access.
    fn check_global_password(
        &self,
        user: &str,
        pass: &str,
    ) -> Result<TunnelSelector, ProxyAuthError> {
        match self.global_password {
            Some(expected_pass) if constant_time_eq_str(pass, expected_pass) => {
                Ok(TunnelSelector::parse(user))
            }
            None if self.allow_anonymous => Ok(TunnelSelector::parse(user)),
            _ => Err(ProxyAuthError::InvalidCredentials),
        }
    }

    /// The configured per-tunnel password for a `ById` selector, if any.
    fn per_tunnel_password(&self, selector: &TunnelSelector) -> Option<String> {
        let TunnelSelector::ById(id) = selector else {
            return None;
        };
        self.per_tunnel_passwords.read().get(id).cloned()
    }
}

impl TunnelRouter for SingleTunnelRouter {
    fn authenticate(
        &self,
        credentials: Option<(&str, &str)>,
    ) -> Result<TunnelSelector, ProxyAuthError> {
        if let Some((expected_user, expected_pass)) = &self.auth {
            match credentials {
                Some((u, p))
                    if credentials_match(
                        (u, p),
                        (expected_user.as_str(), expected_pass.as_str()),
                    ) =>
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
        let target = Arc::clone(&self.target);
        Box::pin(async move { Ok(target) })
    }
}

struct PoolInner {
    tunnels: HashMap<String, Arc<dyn ProxyTunnelTarget>>,
    keys: Vec<String>,
}

/// Router for shared ports managing multiple tunnels with pool strategies and credentials.
pub struct PoolRouter {
    inner: RwLock<PoolInner>,
    strategy: PoolStrategy,
    auth_mode: AuthMode,
    global_password: Option<String>,
    per_tunnel_passwords: RwLock<HashMap<String, String>>,
    allow_anonymous: bool,
    rr_counter: AtomicUsize,
}

impl std::fmt::Debug for PoolRouter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PoolRouter")
            .field("strategy", &self.strategy)
            .field("auth_mode", &self.auth_mode)
            .field("allow_anonymous", &self.allow_anonymous)
            .finish_non_exhaustive()
    }
}

/// Tunnel IDs in preference order for pool selection: targets backed
/// by a live session first, so a request does not pay a fresh
/// activation + handshake while live tunnels sit unused. Falls back to
/// the full key list when no target is live, so a fresh pool can still
/// bring tunnels up through real traffic — which is how targets become
/// live in the first place.
fn preferred_pool_ids(inner: &PoolInner) -> Vec<&String> {
    let live: Vec<&String> = inner
        .keys
        .iter()
        .filter(|id| {
            inner
                .tunnels
                .get(*id)
                .is_some_and(ProxyTunnelTarget::is_live)
        })
        .collect();
    if live.is_empty() {
        inner.keys.iter().collect()
    } else {
        live
    }
}

impl PoolRouter {
    /// Create a new pool router with the given strategy and anonymous access flag.
    pub fn new(strategy: PoolStrategy, allow_anonymous: bool) -> Self {
        Self {
            inner: RwLock::new(PoolInner {
                tunnels: HashMap::new(),
                keys: Vec::new(),
            }),
            strategy,
            auth_mode: AuthMode::None,
            global_password: None,
            per_tunnel_passwords: RwLock::new(HashMap::new()),
            allow_anonymous,
            rr_counter: AtomicUsize::new(0),
        }
    }

    /// Set authentication mode and optional global password.
    pub fn with_auth(mut self, auth_mode: AuthMode, global_password: Option<String>) -> Self {
        self.auth_mode = auth_mode;
        self.global_password = global_password;
        self
    }

    /// Configure per-tunnel override passwords used when `AuthMode::PerTunnel` is active.
    pub fn with_per_tunnel_passwords(self, passwords: HashMap<String, String>) -> Self {
        *self.per_tunnel_passwords.write() = passwords;
        self
    }

    /// Register or update a per-tunnel password override.
    pub fn set_tunnel_password(&self, id: impl Into<String>, password: impl Into<String>) {
        self.per_tunnel_passwords
            .write()
            .insert(id.into(), password.into());
    }

    /// Register a tunnel target in this pool.
    pub fn add_tunnel(self: &Arc<Self>, id: impl Into<String>, target: Arc<dyn ProxyTunnelTarget>) {
        let id_str = id.into();
        let mut inner = self.inner.write();
        if !inner.tunnels.contains_key(&id_str) {
            inner.keys.push(id_str.clone());
        }
        inner.tunnels.insert(id_str, target);
    }

    fn pick_pool_tunnel(&self) -> io::Result<Arc<dyn ProxyTunnelTarget>> {
        let inner = self.inner.read();
        if inner.keys.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::NotConnected,
                "no tunnels registered in pool",
            ));
        }

        let candidates = preferred_pool_ids(&inner);
        let selected_id = match self.strategy {
            PoolStrategy::RoundRobin | PoolStrategy::LeastConn => {
                let idx = self.rr_counter.fetch_add(1, Ordering::Relaxed) % candidates.len();
                candidates.get(idx).copied()
            }
            PoolStrategy::Fallback => candidates.first().copied(),
            PoolStrategy::Random => {
                let idx = (rand::random::<u32>() as usize) % candidates.len();
                candidates.get(idx).copied()
            }
        }
        .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "selected tunnel not found"))?;

        inner
            .tunnels
            .get(selected_id)
            .cloned()
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "selected tunnel not found"))
    }
}

impl TunnelRouter for PoolRouter {
    fn authenticate(
        &self,
        credentials: Option<(&str, &str)>,
    ) -> Result<TunnelSelector, ProxyAuthError> {
        AuthChecker {
            auth_mode: self.auth_mode,
            global_password: &self.global_password,
            per_tunnel_passwords: &self.per_tunnel_passwords,
            allow_anonymous: self.allow_anonymous,
            // A pool router always falls back to the default pool when no
            // credentials are given under `AuthMode::None`.
            none_without_credentials_ok: true,
        }
        .authenticate(credentials)
    }

    fn select_tunnel<'a>(
        &'a self,
        selector: &'a TunnelSelector,
        _credentials: Option<(&'a str, &'a str)>,
    ) -> Pin<Box<dyn Future<Output = io::Result<Arc<dyn ProxyTunnelTarget>>> + Send + 'a>> {
        // Test-only router: its targets carry no per-tunnel passwords,
        // so selection cannot enforce any. `authenticate` is the only
        // credential gate here, as before.
        Box::pin(async move {
            match selector {
                TunnelSelector::ById(id) => {
                    let inner = self.inner.read();
                    inner.tunnels.get(id).cloned().ok_or_else(|| {
                        io::Error::new(
                            io::ErrorKind::NotFound,
                            format!("tunnel '{id}' not found in pool"),
                        )
                    })
                }
                TunnelSelector::ByKeyword(keyword) => {
                    let inner = self.inner.read();
                    if inner.keys.is_empty() {
                        return Err(io::Error::new(
                            io::ErrorKind::NotConnected,
                            "no tunnels registered in pool",
                        ));
                    }
                    let candidates = preferred_pool_ids(&inner);
                    let idx = match keyword {
                        PoolKeyword::Random => (rand::random::<u32>() as usize) % candidates.len(),
                        PoolKeyword::Auto | PoolKeyword::RoundRobin | PoolKeyword::LeastConn => {
                            self.rr_counter.fetch_add(1, Ordering::Relaxed) % candidates.len()
                        }
                    };
                    let target = candidates
                        .get(idx)
                        .and_then(|id| inner.tunnels.get(id.as_str()))
                        .cloned();
                    drop(inner);
                    target
                        .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "tunnel not found"))
                }
                TunnelSelector::ByTag(tag) => {
                    // Match prefix or substring in registered tunnel IDs
                    let matched = {
                        let inner = self.inner.read();
                        inner
                            .tunnels
                            .iter()
                            .find(|(id, _)| id.contains(tag))
                            .map(|(_, target)| Arc::clone(target))
                    };
                    matched.ok_or_else(|| {
                        io::Error::new(
                            io::ErrorKind::NotFound,
                            format!("no tunnel found matching tag '{tag}'"),
                        )
                    })
                }
                TunnelSelector::DefaultPool => self.pick_pool_tunnel(),
            }
        })
    }
}
