//! Android TUN adapter: one shared TUN fd, a central dispatcher, and
//! per-tunnel channels into gotatun.
//!
//! Design decisions (Phase 1, VPN data plane):
//!
//! * One fd, one reader. Android hands the engine a single TUN fd, so a
//!   single dispatcher task owns the read half and fans packets out to
//!   one bounded channel per tunnel (`tunnel_id -> sender`). A single
//!   `mpsc` channel cannot do this: it has exactly one consumer, while
//!   every active tunnel needs its own consumer. The map of senders is
//!   the fan-out.
//! * Reads use [`tokio::fs::File`], not [`tokio::io::unix::AsyncFd`].
//!   `AsyncFd` needs a raw `read(2)` on the fd inside `try_io`, which
//!   has no safe std API (`BorrowedFd` offers no `Read`). `tokio::fs::File`
//!   is built from the `OwnedFd` with only safe conversions
//!   (`File::from(OwnedFd)`), and its blocking-pool reads are exactly
//!   what a packet-oriented TUN fd needs: each `read` returns one whole
//!   IP packet and blocks until one arrives. Writes go through the same
//!   file behind a `tokio::sync::Mutex`, shared by every tunnel's
//!   [`TunIpSend`].
//! * Routing is flow-first, then strategy. An outbound packet is keyed
//!   by its 5-tuple; a flow-table hit pins it to the tunnel that carried
//!   the first packet of the flow (60 s idle expiry), so the two
//!   directions of one connection never split across tunnels — unless
//!   that tunnel stopped being usable, in which case the flow is
//!   re-routed. On a miss, the destination is matched against every
//!   active tunnel's `AllowedIPs` with longest-prefix wins; ties (e.g.
//!   several `0.0.0.0/0` tunnels) are broken by the endpoint strategy
//!   (`RoundRobin` rotates new flows, `Fallback` takes the first
//!   usable tunnel in registration order), skipping tunnels the
//!   usable-checker rejects. Only live tunnels are registered.
//! * Source NAT per tunnel. The phone's kernel stamps outbound packets
//!   with the TUN interface address, but a peer only accepts packets
//!   from the `Interface` address of its own tunnel. When a flow is
//!   routed to a tunnel whose address differs, the dispatcher rewrites
//!   the source (fixing IPv4/TCP/UDP checksums) and the return
//!   packet's destination is rewritten back before it re-enters TUN.
//! * DNS is routed, not answered — unless DoH is on. A UDP packet to
//!   port 53 is an ordinary UDP flow: it follows the flow table /
//!   AllowedIPs like any other packet and is answered by the peer's
//!   resolver. With a [`DnsResolver`] installed (DoH), A/AAAA queries
//!   are instead answered locally from the resolver and never enter a
//!   tunnel; anything the resolver transiently cannot answer is
//!   forwarded as plain DNS, so a transient DoH failure never
//!   black-holes a lookup — but a TLS failure fails closed and the
//!   query is dropped rather than downgraded to plaintext. The
//!   dispatcher also snoops queries and answers (`DnsSnoop`) to learn
//!   which IPs belong to which domain, so domain rules can pin later
//!   flows to a chosen tunnel.
//! * IPv6 extension headers are not parsed: ports are read at the fixed
//!   offset 40. Packets with extension headers still route correctly by
//!   destination address; only their flow key may carry wrong ports.
//! * Suspend keeps the channel, drops the route. A suspended tunnel's
//!   packets stop arriving (no route), but its channel stays alive so a
//!   resume re-attaches the same receiver the device already holds.
//!   Close drops both route and channel.

use std::collections::HashMap;
use std::future::Future;
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::os::fd::OwnedFd;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::{Duration, Instant};

use gotatun::packet::{Ip, Packet, PacketBufPool};
use gotatun::tun::{IpRecv, IpSend, MtuWatcher};
use ipnetwork::IpNetwork;
use parking_lot::Mutex;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::{Semaphore, mpsc};
use tokio::task::{JoinHandle, JoinSet};
use zerocopy::IntoBytes;

use crate::netstack::DEFAULT_CHANNEL_CAPACITY;
use crate::netstack::dns::QueryType;

/// Idle time after which a flow-table entry is dropped and the next
/// packet of that flow is re-routed by `AllowedIPs`.
pub const FLOW_IDLE_TIMEOUT: Duration = Duration::from_secs(60);

/// Hard cap on pinned flows (audit run-1, `tun-flow-table-unbounded-growth`):
/// matches `MAX_SNOOP_LEARNED`, so the flow table cannot grow with a
/// flood of distinct fresh 5-tuples. When full, expired entries are
/// dropped first, then the oldest, following the `DnsSnoop` pattern.
const MAX_FLOW_ENTRIES: usize = 4096;

/// Live counters for the TUN data plane, for phone-side diagnosis.
///
/// Every drop point has its own counter so a dead data plane can be
/// located from the numbers alone: `read == 0` means no packet ever
/// arrived from Android, `read > 0` with `queued == 0` means routing
/// dropped them, `queued > 0` with `written == 0` means the tunnel
/// device never answered.
#[derive(Debug, Default)]
pub struct TunCounters {
    /// Packets read from the TUN fd.
    pub packets_read: AtomicU64,
    /// Reads that failed (the dispatcher stops after the first one).
    pub read_errors: AtomicU64,
    /// Packets whose IP header could not be parsed.
    pub packets_unparsable: AtomicU64,
    /// Packets with a valid header but no route to any tunnel.
    pub packets_no_route: AtomicU64,
    /// Packets dropped because the destination is local-only
    /// (multicast, link-local, loopback, broadcast, unspecified):
    /// normal TUN noise, not a routing failure.
    pub packets_dropped_local: AtomicU64,
    /// Packets handed to a tunnel channel.
    pub packets_queued: AtomicU64,
    /// Packets dropped because the tunnel channel was full or closed.
    pub packets_dropped_channel: AtomicU64,
    /// Packets that failed `try_into_ip` after routing.
    pub packets_malformed: AtomicU64,
    /// Decrypted packets written back into the TUN fd.
    pub packets_written: AtomicU64,
    /// Failed TUN writes.
    pub write_errors: AtomicU64,
}

/// Per-tunnel byte counters for the VPN data plane.
///
/// The proxy path counts bytes in `MeteredStream`/`MeteredUdpSocket`,
/// but TUN packets bypass those wrappers, so without these the
/// Dashboard RX/TX stays 0 in VPN mode even while traffic flows.
#[derive(Debug, Default)]
pub struct TunByteCounts {
    /// Bytes received from the tunnel (written back into the TUN fd).
    pub rx_bytes: AtomicU64,
    /// Bytes sent into the tunnel (read from the TUN fd).
    pub tx_bytes: AtomicU64,
}

/// Point-in-time snapshot of [`TunCounters`], plus dispatcher state.
#[derive(Debug, Clone, Default)]
pub struct TunStatsSnapshot {
    pub packets_read: u64,
    pub read_errors: u64,
    pub packets_unparsable: u64,
    pub packets_no_route: u64,
    pub packets_dropped_local: u64,
    pub packets_queued: u64,
    pub packets_dropped_channel: u64,
    pub packets_malformed: u64,
    pub packets_written: u64,
    pub write_errors: u64,
    pub dispatcher_running: bool,
    pub last_read_error: Option<String>,
}

impl TunCounters {
    pub fn snapshot(
        &self,
        dispatcher_running: bool,
        last_read_error: Option<String>,
    ) -> TunStatsSnapshot {
        let load = |c: &AtomicU64| c.load(Ordering::Relaxed);
        TunStatsSnapshot {
            packets_read: load(&self.packets_read),
            read_errors: load(&self.read_errors),
            packets_unparsable: load(&self.packets_unparsable),
            packets_no_route: load(&self.packets_no_route),
            packets_dropped_local: load(&self.packets_dropped_local),
            packets_queued: load(&self.packets_queued),
            packets_dropped_channel: load(&self.packets_dropped_channel),
            packets_malformed: load(&self.packets_malformed),
            packets_written: load(&self.packets_written),
            write_errors: load(&self.write_errors),
            dispatcher_running,
            last_read_error,
        }
    }
}

/// Largest single IP packet the dispatcher reads from the TUN fd.
/// A TUN read returns one whole packet; 64 KiB covers any MTU.
const MAX_TUN_PACKET_LEN: usize = 65_535;

/// Packet buffers retained by the dispatcher's own [`PacketBufPool`].
const DISPATCHER_PACKET_POOL_CAPACITY: usize = 64;

/// IANA protocol number for TCP.
const PROTO_TCP: u8 = 6;

/// IANA protocol number for UDP.
const PROTO_UDP: u8 = 17;

/// Destination port of a DNS query.
const DNS_PORT: u16 = 53;

/// Most DNS answer tasks (DoH resolutions) running at once. One
/// intercepted query spawns one task that can live up to the 10 s DoH
/// budget, so without a bound a burst of local queries spawns
/// unbounded tasks (audit run-1, `tun-doh-answer-unbounded-spawn`).
/// Past the bound the dispatcher routes the query through the tunnel
/// as plain DNS instead of spawning, so no lookup is black-holed.
const MAX_CONCURRENT_DNS_ANSWERS: usize = 32;

/// 5-tuple identifying one traffic flow: source/destination addresses,
/// source/destination transport ports, and the IP protocol number.
/// Non-TCP/UDP packets (ICMP, ...) carry ports `0`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct FlowKey {
    pub src: IpAddr,
    pub dst: IpAddr,
    pub src_port: u16,
    pub dst_port: u16,
    pub proto: u8,
}

impl FlowKey {
    /// True when this flow is a DNS query (UDP to port 53).
    ///
    /// DNS is routed like any other UDP flow in Phase 1; this is only
    /// a classifier for tests and logging, never a local answer path.
    pub const fn is_dns(&self) -> bool {
        self.proto == PROTO_UDP && self.dst_port == DNS_PORT
    }
}

/// Parse the 5-tuple flow key of one raw IP packet.
///
/// Returns `None` for truncated packets and unknown IP versions.
/// IPv6 extension headers are not walked (see module docs).
pub fn parse_flow_key(packet: &[u8]) -> Option<FlowKey> {
    let version = packet.first().map(|first| first >> 4)?;
    match version {
        4 => parse_ipv4_flow_key(packet),
        6 => parse_ipv6_flow_key(packet),
        _ => None,
    }
}

/// True when the destination must never enter a tunnel: multicast,
/// link-local, loopback, broadcast or unspecified. These are normal
/// TUN noise (mDNS, DHCP, neighbour discovery) and would otherwise
/// be counted as "no route" even though dropping them is correct.
const fn is_local_destination(dst: IpAddr) -> bool {
    match dst {
        IpAddr::V4(ip) => {
            ip.is_multicast()
                || ip.is_link_local()
                || ip.is_loopback()
                || ip.is_broadcast()
                || ip.is_unspecified()
        }
        IpAddr::V6(ip) => {
            ip.is_multicast()
                || ip.is_unicast_link_local()
                || ip.is_loopback()
                || ip.is_unspecified()
        }
    }
}

fn parse_ipv4_flow_key(packet: &[u8]) -> Option<FlowKey> {
    if packet.len() < 20 {
        return None;
    }
    let first = *packet.first()?;
    let ihl = (first & 0x0f) as usize * 4;
    if ihl < 20 || packet.len() < ihl {
        return None;
    }
    let proto = *packet.get(9)?;
    let src = IpAddr::V4(read_ipv4(packet, 12)?);
    let dst = IpAddr::V4(read_ipv4(packet, 16)?);
    let (src_port, dst_port) = transport_ports(packet, ihl, proto);
    Some(FlowKey {
        src,
        dst,
        src_port,
        dst_port,
        proto,
    })
}

fn parse_ipv6_flow_key(packet: &[u8]) -> Option<FlowKey> {
    if packet.len() < 40 {
        return None;
    }
    let proto = *packet.get(6)?;
    let src = IpAddr::V6(read_ipv6(packet, 8)?);
    let dst = IpAddr::V6(read_ipv6(packet, 24)?);
    let (src_port, dst_port) = transport_ports(packet, 40, proto);
    Some(FlowKey {
        src,
        dst,
        src_port,
        dst_port,
        proto,
    })
}

fn transport_ports(packet: &[u8], header_len: usize, proto: u8) -> (u16, u16) {
    if proto != PROTO_TCP && proto != PROTO_UDP {
        return (0, 0);
    }
    let src = read_u16_be(packet, header_len).unwrap_or(0);
    let dst = read_u16_be(packet, header_len + 2).unwrap_or(0);
    (src, dst)
}

fn read_u16_be(bytes: &[u8], at: usize) -> Option<u16> {
    let hi = *bytes.get(at)?;
    let lo = *bytes.get(at + 1)?;
    Some(u16::from_be_bytes([hi, lo]))
}

fn read_ipv4(bytes: &[u8], at: usize) -> Option<Ipv4Addr> {
    let octets: &[u8; 4] = bytes.get(at..at + 4)?.try_into().ok()?;
    Some(Ipv4Addr::from(*octets))
}

fn read_ipv6(bytes: &[u8], at: usize) -> Option<Ipv6Addr> {
    let octets: &[u8; 16] = bytes.get(at..at + 16)?.try_into().ok()?;
    Some(Ipv6Addr::from(*octets))
}

/// Where one flow is pinned, including source-NAT state.
///
/// `orig_src` is the address the phone's kernel put on the packet
/// (the TUN interface address); `nat_src` is the address the chosen
/// tunnel's peer expects (that tunnel's `Interface` address). The two
/// differ when the flow was routed to a tunnel other than the one
/// that owns the TUN address, and the return packet's destination is
/// rewritten back to `orig_src` on the way into the TUN fd.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FlowRoute {
    pub tunnel_id: String,
    pub orig_src: IpAddr,
    pub nat_src: IpAddr,
}

impl FlowRoute {
    /// True when a return packet addressed to `dst` needs its
    /// destination rewritten back to the original source: the flow
    /// was source-NATed and this packet is aimed at the NAT address.
    pub fn needs_reverse_nat(&self, dst: IpAddr) -> bool {
        self.nat_src != self.orig_src && dst == self.nat_src
    }
}

/// Flow table: 5-tuple -> [`FlowRoute`], with idle expiry.
///
/// Shared between the dispatcher task (outbound routing) and every
/// tunnel's [`TunIpSend`] (inbound reverse-NAT lookup), so it lives
/// behind a lock on the endpoint. A lookup refreshes `last_seen`, so
/// only flows idle longer than the timeout are re-routed.
///
/// A source-NATed flow is also indexed by its NAT-adjusted forward
/// key (`src` replaced by `nat_src`) in `reverse`, so the return
/// path can find the flow from a packet that only ever carried the
/// NAT address.
#[derive(Debug)]
pub struct FlowTable {
    entries: HashMap<FlowKey, FlowEntry>,
    reverse: HashMap<FlowKey, FlowKey>,
    idle_timeout: Duration,
}

#[derive(Debug, Clone)]
struct FlowEntry {
    route: FlowRoute,
    last_seen: Instant,
}

impl Default for FlowTable {
    fn default() -> Self {
        Self::new(FLOW_IDLE_TIMEOUT)
    }
}

impl FlowTable {
    /// Create an empty flow table with the given idle timeout.
    pub fn new(idle_timeout: Duration) -> Self {
        Self {
            entries: HashMap::new(),
            reverse: HashMap::new(),
            idle_timeout,
        }
    }

    /// Look a flow up, refreshing its idle timer. An expired entry is
    /// dropped and reported as a miss; the drop goes through
    /// [`FlowTable::remove`] so a NATed flow's reverse-NAT index entry
    /// is dropped with it instead of leaking.
    pub fn lookup(&mut self, key: &FlowKey) -> Option<FlowRoute> {
        let now = Instant::now();
        if let Some(entry) = self.entries.get(key)
            && now.duration_since(entry.last_seen) > self.idle_timeout
        {
            self.remove(key);
            return None;
        }
        let entry = self.entries.get_mut(key)?;
        entry.last_seen = now;
        Some(entry.route.clone())
    }

    /// Look a return packet's flow up by its NAT-adjusted forward key
    /// (the key the outbound packet carried after source NAT), then
    /// by the original key. `None` when the flow was never NATed or
    /// has expired.
    pub fn lookup_reverse(&mut self, nat_key: &FlowKey) -> Option<FlowRoute> {
        let original = self.reverse.get(nat_key).copied()?;
        self.lookup(&original)
    }

    /// Pin a flow to a route (overwrites any previous pin). When the
    /// table is at `MAX_FLOW_ENTRIES` and the key is new, expired
    /// entries are dropped first, then the oldest flow is evicted, so
    /// the table never grows past the cap.
    pub fn insert(&mut self, key: FlowKey, route: FlowRoute) {
        if !self.entries.contains_key(&key) && self.entries.len() >= MAX_FLOW_ENTRIES {
            self.prune_expired();
            if self.entries.len() >= MAX_FLOW_ENTRIES {
                self.evict_oldest();
            }
        }
        if route.nat_src != route.orig_src {
            let nat_key = FlowKey {
                src: route.nat_src,
                ..key
            };
            self.reverse.insert(nat_key, key);
        }
        self.entries.insert(
            key,
            FlowEntry {
                route,
                last_seen: Instant::now(),
            },
        );
    }

    /// Evict the least-recently-seen flow (and its reverse-NAT index,
    /// via [`FlowTable::remove`]) to make room for a new pin.
    fn evict_oldest(&mut self) {
        if let Some((&oldest, _)) = self.entries.iter().min_by_key(|(_, entry)| entry.last_seen) {
            self.remove(&oldest);
        }
    }

    /// Drop a flow pin (e.g. its tunnel was detached mid-flight).
    pub fn remove(&mut self, key: &FlowKey) {
        if let Some(entry) = self.entries.get(key)
            && entry.route.nat_src != entry.route.orig_src
        {
            let nat_key = FlowKey {
                src: entry.route.nat_src,
                ..*key
            };
            self.reverse.remove(&nat_key);
        }
        self.entries.remove(key);
    }

    /// Drop every entry idle longer than the timeout, plus reverse
    /// entries whose flow is gone.
    pub fn prune_expired(&mut self) {
        let now = Instant::now();
        let timeout = self.idle_timeout;
        self.entries
            .retain(|_, entry| now.duration_since(entry.last_seen) <= timeout);
        self.reverse.retain(|_, key| self.entries.contains_key(key));
    }

    /// Number of pinned flows.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// True when no flow is pinned.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

/// Strategy for picking a tunnel when several routes match one
/// destination (e.g. two `0.0.0.0/0` tunnels).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum VpnRouteStrategy {
    /// New flows rotate across usable tunnels in registration order.
    #[default]
    RoundRobin,
    /// Always the first usable tunnel in registration order; later
    /// tunnels only carry traffic when earlier ones are unusable.
    Fallback,
    /// New flows rotate across usable tunnels in proportion to their
    /// per-tunnel weights (weight 0 = never picked for new flows).
    Weighted,
}

/// Decides whether a tunnel may receive new flows.
///
/// Implemented by the caller (the UniFFI engine asks the
/// `TunnelManager`); the endpoint itself knows nothing about health,
/// state, or disabled flags. When no checker is installed every
/// tunnel counts as usable.
pub trait TunnelUsable: Send + Sync {
    fn is_usable(&self, id: &str) -> bool;
}

/// One tunnel's routable networks, in registration order.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TunRoute {
    /// Tunnel id, as registered in the [`crate::core::TunnelRegistry`].
    pub id: String,
    /// Union of the tunnel peers' `AllowedIPs`.
    pub allowed_ips: Vec<IpNetwork>,
    /// The tunnel's `Interface` addresses (source addresses its peer
    /// accepts). Used for per-tunnel source NAT.
    pub interface_addrs: Vec<IpNetwork>,
}

/// Longest-prefix match of `dst` against every route's `AllowedIPs`.
/// Ties keep the first route in registration order.
pub fn longest_prefix_route(dst: IpAddr, routes: &[TunRoute]) -> Option<String> {
    let mut best: Option<(u8, &str)> = None;
    for route in routes {
        for network in &route.allowed_ips {
            if !network.contains(dst) {
                continue;
            }
            let replace = match best {
                Some((best_prefix, _)) => network.prefix() > best_prefix,
                None => true,
            };
            if replace {
                best = Some((network.prefix(), route.id.as_str()));
            }
        }
    }
    best.map(|(_, id)| id.to_string())
}

/// Routing tables shared between the dispatcher task and the
/// lifecycle: routes (registration order = tie-break order) and the
/// per-tunnel packet channels.
#[derive(Default)]
struct TunTables {
    routes: Vec<TunRoute>,
    channels: HashMap<String, mpsc::Sender<Packet<Ip>>>,
}

impl std::fmt::Debug for TunTables {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TunTables")
            .field("routes", &self.routes.len())
            .field("channels", &self.channels.len())
            .finish_non_exhaustive()
    }
}

/// DNS snooping for domain routing: watches plain-UDP DNS (port 53)
/// crossing the data plane and learns which IPs answer for which
/// domain, so a later flow to a learned IP can be pinned to the
/// tunnel a domain rule names. This observes only — it never answers
/// a query itself and never changes the DNS packet on the wire.
///
/// A query is keyed by (client address, client port, DNS id); its
/// answer is matched on the reversed 5-tuple. An answer is only
/// learned when it comes back from the server that was asked and its
/// question section matches the asked name and type — an unbound
/// answer from any other server, or for another name, never becomes
/// a routing decision. Learned entries expire with the answer's TTL
/// (clamped to 1–60 minutes) and record the tunnel they arrived via.
///
/// Both maps are hard-capped: once full, expired entries are dropped
/// first, then the oldest, so a flood of queries or a giant answer
/// cannot grow the snooper without bound.
const MAX_SNOOP_PENDING: usize = 1024;
const MAX_SNOOP_LEARNED: usize = 4096;
const MAX_SNOOP_IPS_PER_ANSWER: usize = 32;
#[derive(Debug, Clone)]
struct PendingQuery {
    domain: String,
    qtype: QueryType,
    /// The DNS server the query was sent to; an answer must come back
    /// from this server to be trusted.
    server: IpAddr,
    sent: Instant,
}

/// One IP learned from a DNS answer, with the tunnel it arrived via.
#[derive(Debug, Clone)]
struct LearnedAddr {
    domain: String,
    expires: Instant,
    via_tunnel: String,
}

#[derive(Default)]
struct DnsSnoop {
    pending: HashMap<(IpAddr, u16, u16), PendingQuery>,
    learned: HashMap<IpAddr, LearnedAddr>,
    rules: Vec<(String, String)>,
}

impl DnsSnoop {
    /// Record an outbound DNS query (UDP to port 53).
    fn note_query(&mut self, key: &FlowKey, payload: &[u8]) {
        let Some(query) = parse_dns_query(payload) else {
            return;
        };
        if self.pending.len() >= MAX_SNOOP_PENDING {
            let now = Instant::now();
            self.pending
                .retain(|_, entry| now.duration_since(entry.sent) < Duration::from_secs(30));
            // Still full: evict the oldest pending query so the map
            // never grows past the cap.
            if self.pending.len() >= MAX_SNOOP_PENDING
                && let Some((&oldest, _)) = self.pending.iter().min_by_key(|(_, entry)| entry.sent)
            {
                self.pending.remove(&oldest);
            }
        }
        self.pending.insert(
            (key.src, key.src_port, query.id),
            PendingQuery {
                domain: query.domain,
                qtype: query.qtype,
                server: key.dst,
                sent: Instant::now(),
            },
        );
    }

    /// Record an inbound DNS answer (UDP from port 53) and learn its
    /// addresses for the domain the matching query asked about.
    /// `tunnel_id` is the tunnel the answer arrived via, recorded on
    /// each learned entry for routing attribution.
    fn note_response(&mut self, key: &FlowKey, payload: &[u8], tunnel_id: &str) {
        if key.proto != PROTO_UDP || key.src_port != DNS_PORT {
            return;
        }
        let Some(id) = read_u16_be(payload, 0) else {
            return;
        };
        let Some(pending) = self.pending.remove(&(key.dst, key.dst_port, id)) else {
            return;
        };
        // Bind the answer to the query it claims to answer: it must
        // come from the server that was asked, and its question
        // section must match the asked name and type. An answer from
        // any other server, or for another name/type, is not learned
        // (audit run-1, `tun-dns-snoop-unbound-answer-routing-pin`).
        if key.src != pending.server {
            return;
        }
        if !crate::netstack::dns::response_matches_question(payload, &pending.domain, pending.qtype)
        {
            return;
        }
        let Ok((ips, ttl)) = crate::netstack::dns::parse_response(payload, id) else {
            return;
        };
        let expires = Instant::now() + Duration::from_secs(u64::from(ttl.clamp(60, 3600)));
        if self.learned.len() >= MAX_SNOOP_LEARNED {
            let now = Instant::now();
            self.learned.retain(|_, entry| entry.expires > now);
        }
        // Never learn a destination the proxy itself must refuse: a
        // poisoned answer pointing at loopback/private space must not
        // become a routing pin. At most `MAX_SNOOP_IPS_PER_ANSWER`
        // addresses are learned from one response, and the map never
        // grows past its cap: when full, the earliest-expiring entry
        // is evicted first.
        for ip in ips
            .into_iter()
            .filter(|ip| !crate::proxy::router::is_forbidden_destination_ip(*ip))
            .take(MAX_SNOOP_IPS_PER_ANSWER)
        {
            if self.learned.len() >= MAX_SNOOP_LEARNED
                && let Some((&oldest, _)) =
                    self.learned.iter().min_by_key(|(_, entry)| entry.expires)
            {
                self.learned.remove(&oldest);
            }
            self.learned.insert(
                ip,
                LearnedAddr {
                    domain: pending.domain.clone(),
                    expires,
                    via_tunnel: tunnel_id.to_string(),
                },
            );
        }
    }

    /// The tunnel a domain rule names for `dst`, when the address was
    /// learned from a DNS answer whose domain the rule covers.
    /// Suffix match: `example.com` also covers `video.example.com`.
    fn rule_tunnel_for(&mut self, dst: IpAddr) -> Option<String> {
        let entry = self.learned.get(&dst)?.clone();
        if entry.expires <= Instant::now() {
            self.learned.remove(&dst);
            return None;
        }
        let rule = self.rules.iter().find(|(suffix, _)| {
            entry.domain == *suffix || entry.domain.ends_with(&format!(".{suffix}"))
        })?;
        // Attribution is observable: the answer that taught this
        // mapping arrived via `entry.via_tunnel`, which may differ
        // from the rule's tunnel — the pin is the operator's rule,
        // the attribution records where the evidence came from.
        tracing::debug!(
            "DnsSnoop: pinning {dst} (learned for {} via tunnel {}) to rule tunnel {}",
            entry.domain,
            entry.via_tunnel,
            rule.1
        );
        Some(rule.1.clone())
    }

    /// Route `suffix` (and its subdomains) to `tunnel_id`. Replaces
    /// any earlier rule for the same suffix.
    fn set_domain_rule(&mut self, suffix: &str, tunnel_id: &str) {
        let suffix = suffix.trim().trim_end_matches('.').to_lowercase();
        if suffix.is_empty() || tunnel_id.is_empty() {
            return;
        }
        self.rules.retain(|(existing, _)| *existing != suffix);
        self.rules.push((suffix, tunnel_id.to_string()));
    }

    fn clear_domain_rules(&mut self) {
        self.rules.clear();
    }
}

/// The UDP payload of one raw IP packet (past the IP and UDP headers).
fn udp_payload(packet: &[u8]) -> Option<&[u8]> {
    let version = packet.first().map(|first| first >> 4)?;
    let header_len = match version {
        4 => (packet.first()? & 0x0f) as usize * 4,
        6 => 40,
        _ => return None,
    };
    if header_len < 20 || packet.len() < header_len + 8 {
        return None;
    }
    packet.get(header_len + 8..)
}

/// One parsed DNS query: transaction id, questioned name, question type.
/// Only A/AAAA questions parse: anything else is not answered locally.
struct DnsQuery {
    id: u16,
    domain: String,
    qtype: QueryType,
}

/// Outcome of one [`DnsResolver::resolve`] call.
#[derive(Debug)]
pub enum DnsResolveOutcome {
    /// The resolver answered: addresses and minimum TTL.
    Answered(Vec<IpAddr>, u32),
    /// Transient failure (timeout, I/O, HTTP, DNS parse): the caller
    /// may fall back to plain DNS through the tunnel.
    Unavailable,
    /// TLS failure (handshake/verification): fail closed — the caller
    /// must NOT forward the query as plain DNS, or a TLS failure
    /// would silently downgrade the lookup to plaintext (audit run-1,
    /// `doh-fallback-to-plain-dns-on-tls-failure`).
    TlsFailed,
}

/// Future returned by [`DnsResolver::resolve`].
pub type DnsResolveFuture<'a> = Pin<Box<dyn Future<Output = DnsResolveOutcome> + Send + 'a>>;

/// Answers DNS queries without the tunnel (DoH). Implemented by
/// [`DohClient`](crate::netstack::doh::DohClient).
///
/// Returning [`DnsResolveOutcome::Unavailable`] means "fall back to
/// plain DNS through the tunnel";
/// [`DnsResolveOutcome::TlsFailed`] means "fail closed, do not
/// downgrade".
pub trait DnsResolver: Send + Sync {
    fn resolve(&self, domain: String, qtype: QueryType) -> DnsResolveFuture<'_>;
}

/// Parse a DNS query's transaction id, questioned name, and question
/// type. Returns `None` for non-queries, non-A/AAAA questions,
/// malformed questions, and non-UTF-8 names.
fn parse_dns_query(payload: &[u8]) -> Option<DnsQuery> {
    if payload.len() < 12 {
        return None;
    }
    let id = read_u16_be(payload, 0)?;
    let flags = read_u16_be(payload, 2)?;
    if flags & 0x8000 != 0 {
        return None;
    }
    let qdcount = read_u16_be(payload, 4)?;
    if qdcount == 0 {
        return None;
    }
    let mut labels: Vec<&str> = Vec::new();
    let mut offset = 12;
    loop {
        let len = *payload.get(offset)? as usize;
        if len == 0 {
            break;
        }
        if len > 63 || offset + 1 + len > payload.len() || labels.len() >= 127 {
            return None;
        }
        let label = std::str::from_utf8(payload.get(offset + 1..offset + 1 + len)?).ok()?;
        labels.push(label);
        offset += 1 + len;
    }
    if labels.is_empty() {
        return None;
    }
    let qtype = match read_u16_be(payload, offset + 1)? {
        1 => QueryType::A,
        28 => QueryType::AAAA,
        _ => return None,
    };
    Some(DnsQuery {
        id,
        domain: labels.join(".").to_lowercase(),
        qtype,
    })
}

/// The Android TUN endpoint: one shared fd, one dispatcher task, and
/// the per-tunnel fan-out tables.
///
/// The read half lives in the dispatcher task; the write half is shared
/// by every tunnel's [`TunIpSend`] behind a `tokio::sync::Mutex`.
/// Create with [`TunEndpoint::from_owned_fd`], start the reader with
/// [`TunEndpoint::start_dispatcher`], attach tunnels with
/// [`TunEndpoint::attach_tunnel`], and stop everything with
/// [`TunEndpoint::shutdown`].
pub struct TunEndpoint {
    mtu: u16,
    writer: Arc<tokio::sync::Mutex<tokio::fs::File>>,
    reader: Mutex<Option<tokio::fs::File>>,
    tables: Mutex<TunTables>,
    dispatcher: Mutex<Option<JoinHandle<()>>>,
    /// In-flight DNS answer tasks spawned by [`Self::try_answer_dns`].
    /// Owned here (not detached) so [`Self::shutdown`] can abort them.
    dns_answer_tasks: Mutex<JoinSet<()>>,
    /// Bounds concurrent DNS answer tasks (see
    /// [`MAX_CONCURRENT_DNS_ANSWERS`]). A task holds its permit until
    /// it finishes, so a burst of queries cannot spawn unbounded work.
    dns_answer_sem: Arc<Semaphore>,
    /// Set by [`Self::shutdown`]: no new answer task may spawn, and a
    /// task that already resolved must not write or forward afterwards.
    shut_down: AtomicBool,
    counters: Arc<TunCounters>,
    last_read_error: Mutex<Option<String>>,
    bytes: Mutex<HashMap<String, Arc<TunByteCounts>>>,
    strategy: Mutex<VpnRouteStrategy>,
    rr_counter: AtomicU64,
    usable: Mutex<Option<Arc<dyn TunnelUsable>>>,
    flows: Arc<Mutex<FlowTable>>,
    weights: Mutex<HashMap<String, u32>>,
    dns_snoop: Arc<Mutex<DnsSnoop>>,
    dns_resolver: Mutex<Option<Arc<dyn DnsResolver>>>,
}

impl std::fmt::Debug for TunEndpoint {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let tables = self.tables.lock();
        f.debug_struct("TunEndpoint")
            .field("mtu", &self.mtu)
            .field("routes", &tables.routes.len())
            .field("channels", &tables.channels.len())
            .field("dispatcher_running", &self.dispatcher.lock().is_some())
            .finish_non_exhaustive()
    }
}

impl TunEndpoint {
    /// Take ownership of a raw TUN fd (from Android `VpnService`) and
    /// build the endpoint around it. The fd is `dup`ed once: the copy
    /// feeds the dispatcher reader, the original feeds the shared
    /// writer. Both halves close when the endpoint and its senders drop.
    ///
    /// # Errors
    ///
    /// Returns the OS error when the fd cannot be duplicated.
    pub fn from_owned_fd(fd: OwnedFd, mtu: u16) -> io::Result<Arc<Self>> {
        let std_file = std::fs::File::from(fd);
        let read_file = std_file.try_clone()?;
        let reader = tokio::fs::File::from_std(read_file);
        let writer = tokio::fs::File::from_std(std_file);
        Ok(Arc::new(Self {
            mtu,
            writer: Arc::new(tokio::sync::Mutex::new(writer)),
            reader: Mutex::new(Some(reader)),
            tables: Mutex::new(TunTables::default()),
            dispatcher: Mutex::new(None),
            dns_answer_tasks: Mutex::new(JoinSet::new()),
            dns_answer_sem: Arc::new(Semaphore::new(MAX_CONCURRENT_DNS_ANSWERS)),
            shut_down: AtomicBool::new(false),
            counters: Arc::new(TunCounters::default()),
            last_read_error: Mutex::new(None),
            bytes: Mutex::new(HashMap::new()),
            strategy: Mutex::new(VpnRouteStrategy::default()),
            rr_counter: AtomicU64::new(0),
            usable: Mutex::new(None),
            flows: Arc::new(Mutex::new(FlowTable::default())),
            weights: Mutex::new(HashMap::new()),
            dns_snoop: Arc::new(Mutex::new(DnsSnoop::default())),
            dns_resolver: Mutex::new(None),
        }))
    }

    /// Configured TUN MTU, as passed by Android.
    pub const fn mtu(&self) -> u16 {
        self.mtu
    }

    /// Pick the multi-tunnel strategy for new flows. Applies to flows
    /// routed after the call; already-pinned flows keep their tunnel.
    pub fn set_strategy(&self, strategy: VpnRouteStrategy) {
        *self.strategy.lock() = strategy;
    }

    /// Set one tunnel's weight for the `Weighted` strategy (default
    /// 1; 0 means the tunnel is never picked for new flows). Applies
    /// to flows routed after the call.
    pub fn set_weight(&self, id: &str, weight: u32) {
        self.weights.lock().insert(id.to_string(), weight);
    }

    /// One tunnel's weight for the `Weighted` strategy (1 when unset).
    fn weight_of(&self, id: &str) -> u32 {
        self.weights.lock().get(id).copied().unwrap_or(1)
    }

    /// Route `suffix` (and its subdomains) to `tunnel_id` for flows
    /// whose destination was learned from a DNS answer. Applies to
    /// flows routed after the call.
    pub fn set_domain_rule(&self, suffix: &str, tunnel_id: &str) {
        self.dns_snoop.lock().set_domain_rule(suffix, tunnel_id);
    }

    /// Drop every domain rule.
    pub fn clear_domain_rules(&self) {
        self.dns_snoop.lock().clear_domain_rules();
    }

    /// Install the resolver that answers DNS queries locally (DoH).
    /// `None` clears it and every query forwards through the tunnel.
    pub fn set_dns_resolver(&self, resolver: Option<Arc<dyn DnsResolver>>) {
        *self.dns_resolver.lock() = resolver;
    }

    /// Take a DNS query for local answering when a resolver is
    /// installed and the question is A/AAAA. Returns true when the
    /// query was taken (a task answers it, or forwards it on
    /// failure); false when the dispatcher should route it normally.
    /// The answer task is registered on the endpoint (not detached)
    /// so [`Self::shutdown`] can abort it, and holds one
    /// [`MAX_CONCURRENT_DNS_ANSWERS`] permit: when no permit is
    /// available the query is routed normally instead of spawning,
    /// so a burst never black-holes a lookup.
    fn try_answer_dns(self: &Arc<Self>, bytes: &[u8]) -> bool {
        if self.shut_down.load(Ordering::Acquire) {
            return false;
        }
        let Some(resolver) = self.dns_resolver.lock().clone() else {
            return false;
        };
        let Some(key) = parse_flow_key(bytes) else {
            return false;
        };
        if !key.is_dns() {
            return false;
        }
        let Some(payload) = udp_payload(bytes) else {
            return false;
        };
        let Some(query) = parse_dns_query(payload) else {
            return false;
        };
        let Ok(permit) = Arc::clone(&self.dns_answer_sem).try_acquire_owned() else {
            return false;
        };
        let endpoint = Arc::clone(self);
        let query_bytes = bytes.to_vec();
        self.dns_answer_tasks.lock().spawn(async move {
            let _permit = permit;
            endpoint
                .answer_dns_query(query_bytes, query, resolver)
                .await;
        });
        true
    }

    /// Answer one intercepted DNS query: resolve via the installed
    /// resolver, write the synthesized response into TUN, or forward
    /// the original query through the tunnel when resolution fails.
    /// A TLS failure fails closed: the query is dropped, never
    /// forwarded as plain DNS (see [`DnsResolveOutcome::TlsFailed`]).
    async fn answer_dns_query(
        self: &Arc<Self>,
        query_bytes: Vec<u8>,
        query: DnsQuery,
        resolver: Arc<dyn DnsResolver>,
    ) {
        let outcome = resolver.resolve(query.domain.clone(), query.qtype).await;
        // Liveness check: the endpoint may have shut down while the
        // resolution was in flight — never write a stale response
        // into TUN (or forward the query) after stop.
        if self.shut_down.load(Ordering::Acquire) {
            return;
        }
        match outcome {
            DnsResolveOutcome::Answered(ips, ttl) => {
                let Some(payload) = udp_payload(&query_bytes) else {
                    return;
                };
                let answers: Vec<(IpAddr, u32)> = ips.iter().map(|ip| (*ip, ttl)).collect();
                let Ok(message) = crate::netstack::dns::build_response(payload, &answers) else {
                    return;
                };
                let Some(packet) = build_dns_response_packet(&query_bytes, &message) else {
                    return;
                };
                let mut writer = self.writer.lock().await;
                if writer.write_all(&packet).await.is_ok() {
                    let _ = writer.flush().await;
                    self.counters
                        .packets_written
                        .fetch_add(1, Ordering::Relaxed);
                }
                drop(writer);
            }
            DnsResolveOutcome::TlsFailed => {
                // DoH TLS failed: fail closed. Forwarding the query as
                // plain DNS would silently downgrade a lookup the user
                // asked to protect with DoH.
                tracing::warn!(
                    "DoH TLS failure for {}; dropping query instead of falling back to plain DNS",
                    query.domain
                );
            }
            DnsResolveOutcome::Unavailable => {
                let pool = PacketBufPool::new(8);
                self.dispatch_packet(&query_bytes, &pool);
            }
        }
    }

    /// Install the checker that decides whether a tunnel may receive
    /// new flows (health / state / disabled). `None` clears it and
    /// every tunnel counts as usable again.
    pub fn set_usable_checker(&self, checker: Option<Arc<dyn TunnelUsable>>) {
        *self.usable.lock() = checker;
    }

    /// True when the tunnel may receive new flows: usable when no
    /// checker is installed, otherwise the checker's answer.
    fn is_usable(&self, id: &str) -> bool {
        self.usable
            .lock()
            .as_ref()
            .is_none_or(|checker| checker.is_usable(id))
    }

    /// Per-tunnel byte counts `(rx_bytes, tx_bytes)` for the VPN data
    /// plane. Entries survive detach so a tunnel's totals stay visible.
    pub fn byte_counts(&self) -> HashMap<String, (u64, u64)> {
        self.bytes
            .lock()
            .iter()
            .map(|(id, counts)| {
                (
                    id.clone(),
                    (
                        counts.rx_bytes.load(Ordering::Relaxed),
                        counts.tx_bytes.load(Ordering::Relaxed),
                    ),
                )
            })
            .collect()
    }

    /// Point-in-time snapshot of the data-plane counters.
    pub fn stats_snapshot(&self) -> TunStatsSnapshot {
        let last_error = self.last_read_error.lock().clone();
        let running = self
            .dispatcher
            .lock()
            .as_ref()
            .is_some_and(|handle| !handle.is_finished());
        self.counters.snapshot(running, last_error)
    }

    /// Spawn the dispatcher task that reads the TUN fd and fans packets
    /// out to attached tunnels. Must be called from inside a tokio
    /// runtime. Calling it twice is an error.
    ///
    /// # Errors
    ///
    /// Returns `AlreadyExists` when the dispatcher is already running.
    pub fn start_dispatcher(self: &Arc<Self>) -> io::Result<()> {
        if self.dispatcher.lock().is_some() {
            return Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                "TunEndpoint dispatcher already started",
            ));
        }
        let Some(reader) = self.reader.lock().take() else {
            return Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                "TunEndpoint dispatcher already started",
            ));
        };
        let endpoint = Arc::clone(self);
        let handle = tokio::spawn(async move { run_dispatcher(endpoint, reader).await });
        *self.dispatcher.lock() = Some(handle);
        Ok(())
    }

    /// Attach a tunnel: register its route and create its packet
    /// channel, returning the gotatun pair for the tunnel's device.
    /// Re-attaching an id replaces its previous route and channel.
    /// `interface_addrs` are the tunnel's `Interface` addresses, used
    /// for per-tunnel source NAT when the flow's source address
    /// belongs to another tunnel.
    pub fn attach_tunnel(
        &self,
        id: &str,
        allowed_ips: Vec<IpNetwork>,
        interface_addrs: Vec<IpNetwork>,
    ) -> (TunIpSend, TunIpRecv) {
        let (sender, receiver) = mpsc::channel(DEFAULT_CHANNEL_CAPACITY);
        let mut tables = self.tables.lock();
        tables.routes.retain(|route| route.id != id);
        tables.routes.push(TunRoute {
            id: id.to_string(),
            allowed_ips,
            interface_addrs,
        });
        tables.channels.insert(id.to_string(), sender);
        drop(tables);
        let bytes = {
            let mut map = self.bytes.lock();
            Arc::clone(
                map.entry(id.to_string())
                    .or_insert_with(|| Arc::new(TunByteCounts::default())),
            )
        };
        (
            TunIpSend {
                writer: Arc::clone(&self.writer),
                counters: Arc::clone(&self.counters),
                bytes,
                flows: Arc::clone(&self.flows),
                dns_snoop: Arc::clone(&self.dns_snoop),
                tunnel_id: id.to_string(),
            },
            TunIpRecv {
                receiver,
                mtu: MtuWatcher::new(self.mtu),
            },
        )
    }

    /// Suspend a tunnel: drop its route, keep its channel. Packets for
    /// it stop arriving until [`TunEndpoint::resume_tunnel`] re-adds
    /// the route; the device keeps the same receiver throughout.
    pub fn suspend_tunnel(&self, id: &str) {
        self.tables.lock().routes.retain(|route| route.id != id);
    }

    /// Resume a tunnel: re-add its route (no-op when the tunnel was
    /// detached, i.e. its channel is gone).
    pub fn resume_tunnel(
        &self,
        id: &str,
        allowed_ips: Vec<IpNetwork>,
        interface_addrs: Vec<IpNetwork>,
    ) {
        let mut tables = self.tables.lock();
        if !tables.channels.contains_key(id) {
            return;
        }
        tables.routes.retain(|route| route.id != id);
        tables.routes.push(TunRoute {
            id: id.to_string(),
            allowed_ips,
            interface_addrs,
        });
    }

    /// Detach a tunnel for good: drop its route and its channel.
    /// Dropping the sender makes the tunnel's [`TunIpRecv`] fail with
    /// `UnexpectedEof`, which is the device's shutdown signal.
    pub fn detach_tunnel(&self, id: &str) {
        let mut tables = self.tables.lock();
        tables.routes.retain(|route| route.id != id);
        tables.channels.remove(id);
    }

    /// Stop the dispatcher and drop every route and channel. The TUN
    /// fd closes once the last [`TunIpSend`] is dropped by its device.
    /// Also aborts in-flight DNS answer tasks and waits for them, so
    /// no detached task can write a stale response into TUN after
    /// stop (audit run-1, `tun-dns-answer-detached-after-shutdown`).
    pub async fn shutdown(&self) {
        // Take the answer set out first so it can be drained below;
        // the dispatcher is the only spawner, and it is aborted by
        // `shutdown_sync`, so no task can be added to the taken set.
        let mut answer_tasks = std::mem::take(&mut *self.dns_answer_tasks.lock());
        if let Some(handle) = self.shutdown_sync() {
            let _ = handle.await;
        }
        answer_tasks.abort_all();
        while answer_tasks.join_next().await.is_some() {}
    }

    /// Synchronous core of [`Self::shutdown`]: flag shutdown, abort
    /// the dispatcher, abort in-flight DNS answer tasks, and drop
    /// every route, channel, and resolver — without waiting for any
    /// task to finish. Used by `Drop` paths (e.g. the UniFFI engine
    /// destroyed without `stop()`), where awaiting is impossible; the
    /// aborted tasks are cancelled and release their `Arc<Self>`
    /// when they actually stop. Returns the aborted dispatcher
    /// handle so the async [`Self::shutdown`] can still await it.
    pub fn shutdown_sync(&self) -> Option<JoinHandle<()>> {
        // Set first: the dispatcher is the only spawner, and it is
        // aborted below, so no answer task can start after this.
        self.shut_down.store(true, Ordering::Release);
        let handle = self.dispatcher.lock().take();
        if let Some(handle) = &handle {
            handle.abort();
        }
        self.dns_answer_tasks.lock().abort_all();
        *self.dns_resolver.lock() = None;
        let mut tables = self.tables.lock();
        tables.routes.clear();
        tables.channels.clear();
        handle
    }

    /// Route one raw packet read from the TUN fd to its tunnel.
    /// Unparsable packets and packets with no route are dropped.
    /// When the chosen tunnel's peer expects a different source
    /// address than the packet carries, the source is rewritten
    /// (with checksums fixed) before the packet enters the tunnel.
    fn dispatch_packet(&self, bytes: &[u8], pool: &PacketBufPool) {
        let Some(key) = parse_flow_key(bytes) else {
            self.counters
                .packets_unparsable
                .fetch_add(1, Ordering::Relaxed);
            tracing::debug!(
                "TunEndpoint: dropping unparsable packet ({} bytes)",
                bytes.len()
            );
            return;
        };
        // Local-only destinations never enter a tunnel and are not a
        // routing failure: drop them before snooping and routing.
        if is_local_destination(key.dst) {
            self.counters
                .packets_dropped_local
                .fetch_add(1, Ordering::Relaxed);
            tracing::debug!("TunEndpoint: dropping local packet to {}", key.dst);
            return;
        }
        if key.is_dns()
            && let Some(payload) = udp_payload(bytes)
        {
            self.dns_snoop.lock().note_query(&key, payload);
        }
        let Some((route, sender)) = self.resolve_route(&key) else {
            self.counters
                .packets_no_route
                .fetch_add(1, Ordering::Relaxed);
            tracing::debug!("TunEndpoint: no route for {} -> {}", key.src, key.dst);
            return;
        };
        let mut raw = pool.get();
        raw.buf_mut().resize(bytes.len(), 0);
        raw.buf_mut().copy_from_slice(bytes);
        if route.nat_src != route.orig_src {
            rewrite_source(raw.buf_mut(), route.nat_src);
        }
        match raw.try_into_ip() {
            Ok(packet) => {
                if sender.try_send(packet).is_err() {
                    self.counters
                        .packets_dropped_channel
                        .fetch_add(1, Ordering::Relaxed);
                    tracing::debug!("TunEndpoint: dropping packet, tunnel channel full or closed");
                } else {
                    self.counters.packets_queued.fetch_add(1, Ordering::Relaxed);
                    if let Some(counts) = self.bytes.lock().get(&route.tunnel_id) {
                        counts
                            .tx_bytes
                            .fetch_add(bytes.len() as u64, Ordering::Relaxed);
                    }
                }
            }
            Err(e) => {
                self.counters
                    .packets_malformed
                    .fetch_add(1, Ordering::Relaxed);
                tracing::debug!("TunEndpoint: dropping malformed packet: {e}");
            }
        }
    }

    /// Pick the tunnel for a packet's flow: pinned flow first (when
    /// its tunnel is still usable), otherwise the strategy pick among
    /// the longest-prefix routes for the destination. Pins the flow
    /// and returns its route with the tunnel's packet channel.
    fn resolve_route(&self, key: &FlowKey) -> Option<(FlowRoute, mpsc::Sender<Packet<Ip>>)> {
        // Pinned flow first. A pin to a detached or unusable tunnel
        // is dropped so the flow re-routes below.
        let pinned = {
            let mut flows = self.flows.lock();
            match flows.lookup(key) {
                Some(route) if self.is_usable(&route.tunnel_id) => Some(route),
                Some(_) => {
                    flows.remove(key);
                    None
                }
                None => None,
            }
        };
        if let Some(route) = pinned {
            let sender = self.tables.lock().channels.get(&route.tunnel_id).cloned();
            if let Some(sender) = sender {
                return Some((route, sender));
            }
            self.flows.lock().remove(key);
        }
        // Candidates are copied out of the tables lock so no lock
        // guard is held across the strategy and flow-table locks.
        let candidates: Vec<(String, Vec<IpNetwork>)> = {
            let tables = self.tables.lock();
            let best_prefix = tables
                .routes
                .iter()
                .flat_map(|route| route.allowed_ips.iter())
                .filter(|network| network.contains(key.dst))
                .map(IpNetwork::prefix)
                .max()?;
            tables
                .routes
                .iter()
                .filter(|route| {
                    route
                        .allowed_ips
                        .iter()
                        .any(|network| network.prefix() == best_prefix && network.contains(key.dst))
                })
                .filter(|route| self.is_usable(&route.id))
                .map(|route| (route.id.clone(), route.interface_addrs.clone()))
                .collect()
        };
        if candidates.is_empty() {
            return None;
        }
        // A domain rule wins over the strategy when the destination
        // was learned from a DNS answer the rule covers and the named
        // tunnel is among the candidates (i.e. still usable).
        let index = if let Some(rule_id) = self.dns_snoop.lock().rule_tunnel_for(key.dst)
            && let Some(position) = candidates.iter().position(|(id, _)| *id == rule_id)
        {
            position
        } else {
            self.pick_by_strategy(&candidates)
        };
        let (chosen_id, chosen_addrs) = candidates.get(index)?;
        let sender = self
            .tables
            .lock()
            .channels
            .get(chosen_id.as_str())
            .cloned()?;
        let nat_src = nat_addr_for(chosen_addrs, key.src);
        let route = FlowRoute {
            tunnel_id: chosen_id.clone(),
            orig_src: key.src,
            nat_src,
        };
        {
            let mut flows = self.flows.lock();
            flows.insert(*key, route.clone());
            if flows.len() > 1024 {
                flows.prune_expired();
            }
        }
        Some((route, sender))
    }
}

impl TunEndpoint {
    /// Index of the candidate a new flow takes under the endpoint
    /// strategy: rotation for Round Robin, first usable for Fallback,
    /// weight-proportional rotation for Weighted.
    fn pick_by_strategy(&self, candidates: &[(String, Vec<IpNetwork>)]) -> usize {
        let strategy = *self.strategy.lock();
        match strategy {
            VpnRouteStrategy::RoundRobin => {
                self.rr_counter.fetch_add(1, Ordering::Relaxed) as usize % candidates.len()
            }
            VpnRouteStrategy::Fallback => 0,
            VpnRouteStrategy::Weighted => {
                // Weighted rotation: the counter walks a virtual
                // ring where each tunnel occupies `weight` slots. A
                // total weight of 0 (every tunnel weight 0) degrades
                // to plain round robin instead of dropping traffic.
                let total: u64 = candidates
                    .iter()
                    .map(|(id, _)| u64::from(self.weight_of(id)))
                    .sum();
                if total == 0 {
                    self.rr_counter.fetch_add(1, Ordering::Relaxed) as usize % candidates.len()
                } else {
                    let slot = self.rr_counter.fetch_add(1, Ordering::Relaxed) % total;
                    let mut seen: u64 = 0;
                    let mut picked = 0;
                    for (index, (id, _)) in candidates.iter().enumerate() {
                        seen += u64::from(self.weight_of(id));
                        if slot < seen {
                            picked = index;
                            break;
                        }
                    }
                    picked
                }
            }
        }
    }
}

/// Build the IP packet carrying a synthesized DNS response: the
/// query packet with addresses and ports swapped and its UDP payload
/// replaced by `dns_response`. Lengths and checksums are fixed.
/// Returns `None` for non-UDP packets and oversize responses.
fn build_dns_response_packet(query_packet: &[u8], dns_response: &[u8]) -> Option<Vec<u8>> {
    let key = parse_flow_key(query_packet)?;
    if key.proto != PROTO_UDP {
        return None;
    }
    let version = query_packet.first().map(|first| first >> 4)?;
    let header_len = match version {
        4 => (query_packet.first()? & 0x0f) as usize * 4,
        6 => 40,
        _ => return None,
    };
    if header_len < 20 || query_packet.len() < header_len + 8 {
        return None;
    }
    let total = header_len + 8 + dns_response.len();
    if total > u16::MAX as usize {
        return None;
    }
    let mut packet = Vec::with_capacity(total);
    packet.extend_from_slice(query_packet.get(..header_len + 8)?);
    packet.extend_from_slice(dns_response);
    match (version, key.src, key.dst) {
        (4, IpAddr::V4(src), IpAddr::V4(dst)) => {
            packet.get_mut(12..16)?.copy_from_slice(&dst.octets());
            packet.get_mut(16..20)?.copy_from_slice(&src.octets());
        }
        (6, IpAddr::V6(src), IpAddr::V6(dst)) => {
            packet.get_mut(8..24)?.copy_from_slice(&dst.octets());
            packet.get_mut(24..40)?.copy_from_slice(&src.octets());
        }
        _ => return None,
    }
    packet
        .get_mut(header_len..header_len + 2)?
        .copy_from_slice(&key.dst_port.to_be_bytes());
    packet
        .get_mut(header_len + 2..header_len + 4)?
        .copy_from_slice(&key.src_port.to_be_bytes());
    match version {
        4 => {
            packet
                .get_mut(2..4)?
                .copy_from_slice(&(total as u16).to_be_bytes());
        }
        6 => {
            packet
                .get_mut(4..6)?
                .copy_from_slice(&((total - 40) as u16).to_be_bytes());
        }
        _ => return None,
    }
    packet
        .get_mut(header_len + 4..header_len + 6)?
        .copy_from_slice(&((8 + dns_response.len()) as u16).to_be_bytes());
    packet
        .get_mut(header_len + 6..header_len + 8)?
        .copy_from_slice(&[0, 0]);
    fix_checksums(&mut packet);
    Some(packet)
}

/// Pick the source address a packet must carry into a tunnel: the
/// tunnel's `Interface` address of the packet's address family, or
/// the packet's own source when the tunnel has none (or already
/// matches). A `None` here would mean "no NAT", expressed as the
/// original source so callers compare directly.
fn nat_addr_for(interface_addrs: &[IpNetwork], src: IpAddr) -> IpAddr {
    interface_addrs
        .iter()
        .map(IpNetwork::ip)
        .find(|addr| std::mem::discriminant(addr) == std::mem::discriminant(&src))
        .unwrap_or(src)
}

/// Rewrite a packet's source address and fix the checksums that cover
/// it (IPv4 header, TCP, UDP). ICMP needs no fix: its checksum does
/// not cover the IP header.
fn rewrite_source(packet: &mut [u8], new_src: IpAddr) {
    match new_src {
        IpAddr::V4(addr) => {
            if let Some(field) = packet.get_mut(12..16) {
                field.copy_from_slice(&addr.octets());
            }
        }
        IpAddr::V6(addr) => {
            if let Some(field) = packet.get_mut(8..24) {
                field.copy_from_slice(&addr.octets());
            }
        }
    }
    fix_checksums(packet);
}

/// Rewrite a packet's destination address and fix the checksums that
/// cover it. Used on the return path to undo source NAT.
fn rewrite_destination(packet: &mut [u8], new_dst: IpAddr) {
    match new_dst {
        IpAddr::V4(addr) => {
            if let Some(field) = packet.get_mut(16..20) {
                field.copy_from_slice(&addr.octets());
            }
        }
        IpAddr::V6(addr) => {
            if let Some(field) = packet.get_mut(24..40) {
                field.copy_from_slice(&addr.octets());
            }
        }
    }
    fix_checksums(packet);
}

/// Recompute the checksums of one IP packet after an address rewrite:
/// the IPv4 header checksum, and the TCP checksum (or the UDP
/// checksum when present, or mandatory for IPv6).
fn fix_checksums(packet: &mut [u8]) {
    let Some(key) = parse_flow_key(packet) else {
        return;
    };
    let version = packet.first().map_or(0, |first| first >> 4);
    match version {
        4 => {
            let Some(header_len) = packet
                .first()
                .map(|first| (first & 0x0f) as usize * 4)
                .filter(|len| *len >= 20 && packet.len() >= *len)
            else {
                return;
            };
            if let Some(header) = packet.get_mut(..header_len) {
                if let Some(field) = header.get_mut(10..12) {
                    field.copy_from_slice(&[0, 0]);
                }
                let sum = internet_checksum(header);
                if let Some(field) = header.get_mut(10..12) {
                    field.copy_from_slice(&sum.to_be_bytes());
                }
            }
            fix_transport_checksum(packet, header_len, key.proto, key.src, key.dst, false);
        }
        6 => fix_transport_checksum(packet, 40, key.proto, key.src, key.dst, true),
        _ => {}
    }
}

/// Recompute the TCP/UDP checksum over the pseudo-header. For IPv4
/// UDP a stored zero means "no checksum" and is left alone; for IPv6
/// the checksum is mandatory, so a computed zero is sent as `0xFFFF`.
fn fix_transport_checksum(
    packet: &mut [u8],
    header_len: usize,
    proto: u8,
    src: IpAddr,
    dst: IpAddr,
    ipv6: bool,
) {
    if proto != PROTO_TCP && proto != PROTO_UDP {
        return;
    }
    // The checksum field sits at offset 16 in TCP, 6 in UDP.
    let field_at = if proto == PROTO_TCP { 16 } else { 6 };
    if proto == PROTO_UDP && !ipv6 {
        let Some(stored_bytes) = packet.get(header_len + 6..header_len + 8) else {
            return;
        };
        let Ok(stored_arr): Result<&[u8; 2], _> = stored_bytes.try_into() else {
            return;
        };
        if u16::from_be_bytes(*stored_arr) == 0 {
            return;
        }
    }
    // Zero the field first: the checksum is computed with it cleared.
    if let Some(field) = packet.get_mut(header_len + field_at..header_len + field_at + 2) {
        field.copy_from_slice(&[0, 0]);
    }
    let Some(segment) = packet.get(header_len..) else {
        return;
    };
    if segment.len() < 4 {
        return;
    }
    let sum = transport_checksum(segment, proto, src, dst);
    let stored = if sum == 0 && ipv6 { 0xffff } else { sum };
    if let Some(field) = packet.get_mut(header_len + field_at..header_len + field_at + 2) {
        field.copy_from_slice(&stored.to_be_bytes());
    }
}

/// Add the 16-bit words of `data` to a running checksum sum,
/// padding a trailing odd byte with zero.
fn add_checksum_words(sum: &mut u32, data: &[u8]) {
    let (pairs, remainder) = data.as_chunks::<2>();
    for pair in pairs {
        *sum += u32::from(u16::from_be_bytes(*pair));
    }
    if let [last] = remainder {
        *sum += u32::from(*last) << 8;
    }
}

/// Fold a 32-bit sum to 16 bits and complement it.
const fn fold_checksum(sum: u32) -> u16 {
    let mut sum = sum;
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

/// Internet checksum over `data`, padding a trailing odd byte with zero.
fn internet_checksum(data: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    add_checksum_words(&mut sum, data);
    fold_checksum(sum)
}

/// TCP/UDP checksum: pseudo-header (src, dst, zero, proto, length)
/// plus the transport segment.
fn transport_checksum(segment: &[u8], proto: u8, src: IpAddr, dst: IpAddr) -> u16 {
    let mut sum: u32 = 0;
    match (src, dst) {
        (IpAddr::V4(src), IpAddr::V4(dst)) => {
            add_checksum_words(&mut sum, &src.octets());
            add_checksum_words(&mut sum, &dst.octets());
        }
        (IpAddr::V6(src), IpAddr::V6(dst)) => {
            add_checksum_words(&mut sum, &src.octets());
            add_checksum_words(&mut sum, &dst.octets());
        }
        _ => return 0,
    }
    sum += u32::from(proto);
    sum += segment.len() as u32;
    add_checksum_words(&mut sum, segment);
    fold_checksum(sum)
}

/// Dispatcher loop: read one packet at a time from the TUN fd and hand
/// it to [`TunEndpoint::dispatch_packet`]. Ends on EOF or a fatal read
/// error (both mean the fd is gone).
///
/// Android hands out a non-blocking TUN fd, so a read with no packet
/// waiting fails with `WouldBlock` (`EAGAIN`) instead of blocking.
/// That is normal idle, not a fatal error: wait briefly and try again.
/// Treating it as fatal kills the dispatcher after the first idle
/// moment, which is exactly what happened on the phone (3 packets
/// read, then `Try again (os error 11)` and no more traffic).
async fn run_dispatcher(endpoint: Arc<TunEndpoint>, mut reader: tokio::fs::File) {
    let mut buf = vec![0u8; MAX_TUN_PACKET_LEN];
    let pool = PacketBufPool::new(DISPATCHER_PACKET_POOL_CAPACITY);
    loop {
        match reader.read(&mut buf).await {
            Ok(0) => {
                tracing::debug!("TunEndpoint dispatcher: TUN fd closed (EOF)");
                break;
            }
            Ok(n) => {
                endpoint
                    .counters
                    .packets_read
                    .fetch_add(1, Ordering::Relaxed);
                let Some(chunk) = buf.get(..n) else {
                    continue;
                };
                if !endpoint.try_answer_dns(chunk) {
                    endpoint.dispatch_packet(chunk, &pool);
                }
            }
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
            Err(e) => {
                endpoint
                    .counters
                    .read_errors
                    .fetch_add(1, Ordering::Relaxed);
                *endpoint.last_read_error.lock() = Some(e.to_string());
                tracing::warn!("TunEndpoint dispatcher: TUN read failed: {e}");
                break;
            }
        }
    }
}

/// Decrypted-packet sink for one tunnel: writes raw IP packets from
/// gotatun back into the shared TUN fd. Cloneable: every tunnel holds
/// its own handle over the same writer.
#[derive(Clone)]
pub struct TunIpSend {
    writer: Arc<tokio::sync::Mutex<tokio::fs::File>>,
    counters: Arc<TunCounters>,
    bytes: Arc<TunByteCounts>,
    flows: Arc<Mutex<FlowTable>>,
    dns_snoop: Arc<Mutex<DnsSnoop>>,
    /// Id of the tunnel this sender belongs to, recorded on learned
    /// DNS answers for routing attribution.
    tunnel_id: String,
}

impl std::fmt::Debug for TunIpSend {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TunIpSend").finish_non_exhaustive()
    }
}

impl IpSend for TunIpSend {
    async fn send(&mut self, packet: Packet<Ip>) -> io::Result<()> {
        let bytes = (*packet).as_bytes();
        // Learn DNS answers crossing back into TUN before any
        // reverse-NAT rewrite (ports are untouched by the rewrite).
        if let Some(key) = parse_flow_key(bytes)
            && let Some(payload) = udp_payload(bytes)
        {
            self.dns_snoop
                .lock()
                .note_response(&key, payload, &self.tunnel_id);
        }
        // Undo source NAT: a return packet addressed to the tunnel's
        // Interface address belongs to the flow whose original source
        // was the TUN address; restore it before the kernel sees it.
        let mut owned;
        let bytes = if let Some(key) = parse_flow_key(bytes) {
            let reverse = FlowKey {
                src: key.dst,
                dst: key.src,
                src_port: key.dst_port,
                dst_port: key.src_port,
                proto: key.proto,
            };
            let route = self.flows.lock().lookup_reverse(&reverse);
            match route {
                Some(route) if route.needs_reverse_nat(key.dst) => {
                    owned = bytes.to_vec();
                    rewrite_destination(&mut owned, route.orig_src);
                    &owned
                }
                _ => bytes,
            }
        } else {
            bytes
        };
        let mut writer = self.writer.lock().await;
        let result = async {
            writer.write_all(bytes).await?;
            writer.flush().await
        }
        .await;
        drop(writer);
        match result {
            Ok(()) => {
                self.counters
                    .packets_written
                    .fetch_add(1, Ordering::Relaxed);
                self.bytes
                    .rx_bytes
                    .fetch_add(bytes.len() as u64, Ordering::Relaxed);
                Ok(())
            }
            Err(e) => {
                self.counters.write_errors.fetch_add(1, Ordering::Relaxed);
                Err(e)
            }
        }
    }
}

/// Packet source for one tunnel: yields the packets the dispatcher
/// routed to this tunnel. Closes with `UnexpectedEof` when the tunnel
/// is detached from the endpoint.
pub struct TunIpRecv {
    receiver: mpsc::Receiver<Packet<Ip>>,
    mtu: MtuWatcher,
}

impl std::fmt::Debug for TunIpRecv {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TunIpRecv").finish_non_exhaustive()
    }
}

impl IpRecv for TunIpRecv {
    async fn recv<'a>(
        &'a mut self,
        _pool: &mut PacketBufPool,
    ) -> io::Result<impl Iterator<Item = Packet<Ip>> + Send + 'a> {
        let packet = self.receiver.recv().await.ok_or_else(|| {
            io::Error::new(io::ErrorKind::UnexpectedEof, "TunEndpoint channel closed")
        })?;
        Ok(std::iter::once(packet))
    }

    fn mtu(&self) -> MtuWatcher {
        self.mtu.clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn snoop_query_key(src_port: u16) -> FlowKey {
        FlowKey {
            src: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
            dst: IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)),
            src_port,
            dst_port: DNS_PORT,
            proto: PROTO_UDP,
        }
    }

    fn snoop_answer_key(src_port: u16) -> FlowKey {
        FlowKey {
            src: IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)),
            dst: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
            src_port: DNS_PORT,
            dst_port: src_port,
            proto: PROTO_UDP,
        }
    }

    #[test]
    fn test_dns_snoop_pending_is_hard_capped() {
        let mut snoop = DnsSnoop::default();
        // 1100 distinct queries, all fresh: the map must stop at the
        // cap instead of growing with the flood.
        for port in 1..=1100u16 {
            let query =
                crate::netstack::dns::build_query("example.com", QueryType::A, 0x1234).unwrap();
            snoop.note_query(&snoop_query_key(port), &query);
        }
        assert!(
            snoop.pending.len() <= MAX_SNOOP_PENDING,
            "pending must be capped at {MAX_SNOOP_PENDING}, got {}",
            snoop.pending.len()
        );
        assert_eq!(
            snoop.pending.len(),
            MAX_SNOOP_PENDING,
            "fresh queries keep the map exactly at the cap"
        );
    }

    #[test]
    fn test_flow_table_is_hard_capped() {
        let mut table = FlowTable::default();
        // 5000 distinct fresh flows, past the cap: the table must stop
        // at the cap instead of growing with the flood, and the newest
        // flow must still be pinned (oldest evicted first).
        for n in 0..5000u32 {
            let key = FlowKey {
                src: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
                dst: IpAddr::V4(Ipv4Addr::new(93, 184, (n >> 8) as u8, (n & 0xff) as u8)),
                src_port: 10000 + (n % 50000) as u16,
                dst_port: 443,
                proto: PROTO_TCP,
            };
            table.insert(
                key,
                FlowRoute {
                    tunnel_id: "tunnel-a".to_string(),
                    orig_src: key.src,
                    nat_src: key.src,
                },
            );
        }
        assert!(
            table.len() <= MAX_FLOW_ENTRIES,
            "flow table must be capped at {MAX_FLOW_ENTRIES}, got {}",
            table.len()
        );
        assert_eq!(
            table.len(),
            MAX_FLOW_ENTRIES,
            "fresh flows keep the table exactly at the cap"
        );
        // The newest flow (n = 4999) is 93.184.19.135:14999.
        let newest = FlowKey {
            src: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
            dst: IpAddr::V4(Ipv4Addr::new(93, 184, 19, 135)),
            src_port: 14999,
            dst_port: 443,
            proto: PROTO_TCP,
        };
        assert!(
            table.lookup(&newest).is_some(),
            "newest flow must survive eviction of the oldest"
        );
    }

    #[test]
    fn test_flow_table_reverse_index_does_not_leak_on_expiry_lookup() {
        let mut table = FlowTable::new(Duration::from_millis(5));
        let orig_src = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
        let nat_src = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 100));
        let mut prev_reverse_len = 0usize;
        for cycle in 0..3u32 {
            // 64 distinct NATed flows per cycle (well under the 1024
            // live-entry threshold where resolve_route prunes).
            let keys: Vec<FlowKey> = (0..64u32)
                .map(|n| FlowKey {
                    src: orig_src,
                    dst: IpAddr::V4(Ipv4Addr::new(
                        93,
                        184,
                        ((cycle * 64 + n) >> 8) as u8,
                        ((cycle * 64 + n) & 0xff) as u8,
                    )),
                    src_port: 10000 + (cycle * 64 + n) as u16,
                    dst_port: 443,
                    proto: PROTO_TCP,
                })
                .collect();
            for key in &keys {
                table.insert(
                    *key,
                    FlowRoute {
                        tunnel_id: "tunnel-a".to_string(),
                        orig_src,
                        nat_src,
                    },
                );
            }
            assert_eq!(
                table.len(),
                64,
                "cycle {cycle}: forward table holds one cycle"
            );
            assert_eq!(
                table.reverse.len(),
                64,
                "cycle {cycle}: reverse index holds one entry per NATed flow"
            );
            std::thread::sleep(Duration::from_millis(15));
            // One late return packet per expired flow, no re-insert.
            for key in &keys {
                let nat_key = FlowKey {
                    src: nat_src,
                    ..*key
                };
                assert!(
                    table.lookup_reverse(&nat_key).is_none(),
                    "cycle {cycle}: expired flow must miss on reverse lookup"
                );
            }
            assert_eq!(
                table.len(),
                0,
                "cycle {cycle}: forward table must be empty after all expiry lookups"
            );
            assert_eq!(
                table.reverse.len(),
                prev_reverse_len,
                "cycle {cycle}: reverse index must not grow across cycles (was {}, now {})",
                prev_reverse_len,
                table.reverse.len()
            );
            prev_reverse_len = table.reverse.len();
        }
    }

    #[test]
    fn test_dns_snoop_learned_is_hard_capped() {
        let mut snoop = DnsSnoop::default();
        // 140 answers x 32 distinct public IPs each = 4480 learned
        // addresses, past the 4096 cap.
        for round in 0..140u16 {
            let src_port = 20000 + round;
            let query =
                crate::netstack::dns::build_query("example.com", QueryType::A, 0x1234).unwrap();
            snoop.note_query(&snoop_query_key(src_port), &query);
            let answers: Vec<(IpAddr, u32)> = (0..32)
                .map(|n| {
                    let index = u32::from(round) * 32 + n;
                    (
                        IpAddr::V4(Ipv4Addr::new(
                            93,
                            184,
                            (index >> 8) as u8,
                            (index & 0xff) as u8,
                        )),
                        300,
                    )
                })
                .collect();
            let response =
                crate::netstack::dns::build_response(&query, &answers).expect("response builds");
            snoop.note_response(&snoop_answer_key(src_port), &response, "tunnel-a");
        }
        assert!(
            snoop.learned.len() <= MAX_SNOOP_LEARNED,
            "learned must be capped at {MAX_SNOOP_LEARNED}, got {}",
            snoop.learned.len()
        );
        assert_eq!(
            snoop.learned.len(),
            MAX_SNOOP_LEARNED,
            "fresh answers keep the map exactly at the cap"
        );
    }
}
