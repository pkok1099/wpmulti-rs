//! In-tunnel remote DNS resolver with minimal RFC 1035 encoder/decoder and LRU cache.
//!
//! Queries are strictly routed inside the WireGuard tunnel over virtual UDP to
//! eliminate host DNS leaks.

use parking_lot::RwLock;
use std::collections::HashMap;
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};
use thiserror::Error;
use tokio::sync::{Mutex as AsyncMutex, OnceCell};

use crate::netstack::stack::VirtualNetworkStack;

#[derive(Error, Debug)]
pub enum DnsError {
    #[error("packet too short")]
    PacketTooShort,
    #[error("DNS transaction ID mismatch")]
    IdMismatch,
    #[error("message is not a DNS response")]
    NotAResponse,
    #[error("domain not found (NXDOMAIN)")]
    NxDomain,
    #[error("DNS server returned error code {0}")]
    ServerError(u16),
    #[error("no A or AAAA address records found in response")]
    NoAddressesFound,
    #[error("corrupt label format")]
    CorruptLabel,
    #[error("circular compression pointer loop detected")]
    PointerLoop,
    #[error("invalid domain name: {0}")]
    InvalidDomain(&'static str),
}

// Standard RFC 1035 / RFC 3596 DNS record type acronyms (`A`, `AAAA`).
#[allow(
    clippy::upper_case_acronyms,
    reason = "standard RFC 1035 / RFC 3596 DNS record type acronyms (A, AAAA)"
)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QueryType {
    A = 1,
    AAAA = 28,
}

/// Builds an RFC 1035 compliant DNS query packet for standard recursive resolution.
pub fn build_query(domain: &str, qtype: QueryType, id: u16) -> Result<Vec<u8>, DnsError> {
    let mut packet = Vec::with_capacity(64);
    // Header (12 bytes)
    packet.extend_from_slice(&id.to_be_bytes());
    packet.extend_from_slice(&0x0100u16.to_be_bytes()); // QR=0, RD=1
    packet.extend_from_slice(&1u16.to_be_bytes()); // QDCOUNT = 1
    packet.extend_from_slice(&0u16.to_be_bytes()); // ANCOUNT = 0
    packet.extend_from_slice(&0u16.to_be_bytes()); // NSCOUNT = 0
    packet.extend_from_slice(&0u16.to_be_bytes()); // ARCOUNT = 0

    // Question: QNAME
    if domain.bytes().any(|b| b <= 0x20 || b == 0x7f) {
        return Err(DnsError::InvalidDomain(
            "domain contains whitespace or control characters",
        ));
    }
    let clean = domain.strip_suffix('.').unwrap_or(domain);
    if clean.is_empty() {
        return Err(DnsError::InvalidDomain("empty domain"));
    }
    let mut qname_len = 1usize; // trailing 0 byte
    for label in clean.split('.') {
        if label.is_empty() {
            return Err(DnsError::InvalidDomain("empty label in domain"));
        }
        if label.len() > 63 {
            return Err(DnsError::InvalidDomain("label exceeds 63 bytes"));
        }
        qname_len += 1 + label.len();
        if qname_len > 255 {
            return Err(DnsError::InvalidDomain("domain name exceeds 255 bytes"));
        }
        packet.push(label.len() as u8);
        packet.extend_from_slice(label.as_bytes());
    }
    packet.push(0);

    // QTYPE and QCLASS (1 = IN)
    packet.extend_from_slice(&(qtype as u16).to_be_bytes());
    packet.extend_from_slice(&1u16.to_be_bytes());

    Ok(packet)
}

fn read_u16_be(buf: &[u8], offset: usize) -> Result<u16, DnsError> {
    let slice = buf
        .get(offset..offset + 2)
        .ok_or(DnsError::PacketTooShort)?;
    let arr: [u8; 2] = slice.try_into().map_err(|_| DnsError::PacketTooShort)?;
    Ok(u16::from_be_bytes(arr))
}

fn read_u32_be(buf: &[u8], offset: usize) -> Result<u32, DnsError> {
    let slice = buf
        .get(offset..offset + 4)
        .ok_or(DnsError::PacketTooShort)?;
    let arr: [u8; 4] = slice.try_into().map_err(|_| DnsError::PacketTooShort)?;
    Ok(u32::from_be_bytes(arr))
}

/// Parses an RFC 1035 DNS response packet, extracting IP addresses and minimum TTL.
pub fn parse_response(buf: &[u8], expected_id: u16) -> Result<(Vec<IpAddr>, u32), DnsError> {
    if buf.len() < 12 {
        return Err(DnsError::PacketTooShort);
    }

    let id = read_u16_be(buf, 0)?;
    if id != expected_id {
        return Err(DnsError::IdMismatch);
    }

    let flags = read_u16_be(buf, 2)?;
    let qr = (flags >> 15) & 1;
    if qr == 0 {
        return Err(DnsError::NotAResponse);
    }

    let rcode = flags & 0x000F;
    if rcode == 3 {
        return Err(DnsError::NxDomain);
    }
    if rcode != 0 {
        return Err(DnsError::ServerError(rcode));
    }
    // rcode 0: no error, continue parsing.

    let qdcount = read_u16_be(buf, 4)? as usize;
    let ancount = read_u16_be(buf, 6)? as usize;

    let mut offset = 12;

    // Skip question section
    for _ in 0..qdcount {
        offset = skip_name(buf, offset)?;
        if offset + 4 > buf.len() {
            return Err(DnsError::PacketTooShort);
        }
        offset += 4; // QTYPE + QCLASS
    }

    let mut ips = Vec::new();
    let mut min_ttl = u32::MAX;

    // Parse answers
    for _ in 0..ancount {
        if offset >= buf.len() {
            break;
        }
        offset = skip_name(buf, offset)?;
        if offset + 10 > buf.len() {
            return Err(DnsError::PacketTooShort);
        }

        let atype = read_u16_be(buf, offset)?;
        let aclass = read_u16_be(buf, offset + 2)?;
        let ttl = read_u32_be(buf, offset + 4)?;
        let rdlength = read_u16_be(buf, offset + 8)? as usize;
        offset += 10;

        let rdata = buf
            .get(offset..offset + rdlength)
            .ok_or(DnsError::PacketTooShort)?;
        offset += rdlength;

        if aclass != 1 {
            continue;
        }
        if atype == 1
            && let Ok(octets) = <[u8; 4]>::try_from(rdata)
        {
            // A Record (IPv4)
            ips.push(IpAddr::V4(Ipv4Addr::from(octets)));
            min_ttl = min_ttl.min(ttl);
        } else if atype == 28
            && let Ok(octets) = <[u8; 16]>::try_from(rdata)
        {
            // AAAA Record (IPv6)
            ips.push(IpAddr::V6(Ipv6Addr::from(octets)));
            min_ttl = min_ttl.min(ttl);
        } else {
            // Other record types are ignored.
        }
    }

    if ips.is_empty() {
        return Err(DnsError::NoAddressesFound);
    }

    if min_ttl == u32::MAX {
        min_ttl = 300;
    }

    Ok((ips, min_ttl))
}

/// Builds a DNS response message answering `query` with `answers`.
///
/// The question section is echoed verbatim, each answer name is a
/// compression pointer to it, and the RD bit is copied from the query
/// with RA set. The caller guarantees the answers match the query's
/// QTYPE.
pub fn build_response(query: &[u8], answers: &[(IpAddr, u32)]) -> Result<Vec<u8>, DnsError> {
    if query.len() < 12 {
        return Err(DnsError::PacketTooShort);
    }
    let qdcount = read_u16_be(query, 4)?;
    if qdcount == 0 {
        return Err(DnsError::InvalidDomain("query has no question"));
    }
    let question_end = skip_name(query, 12)?;
    let question_end = question_end
        .checked_add(4)
        .filter(|end| *end <= query.len())
        .ok_or(DnsError::PacketTooShort)?;
    let mut resp = Vec::with_capacity(question_end + answers.len() * 28);
    resp.extend_from_slice(query.get(..2).ok_or(DnsError::PacketTooShort)?);
    let query_flags = read_u16_be(query, 2)?;
    let flags = 0x8180 | (query_flags & 0x0100);
    resp.extend_from_slice(&flags.to_be_bytes());
    resp.extend_from_slice(&qdcount.to_be_bytes());
    resp.extend_from_slice(&(answers.len() as u16).to_be_bytes());
    resp.extend_from_slice(&0u16.to_be_bytes());
    resp.extend_from_slice(&0u16.to_be_bytes());
    resp.extend_from_slice(
        query
            .get(12..question_end)
            .ok_or(DnsError::PacketTooShort)?,
    );
    for (ip, ttl) in answers {
        resp.extend_from_slice(&[0xC0, 0x0C]);
        let (record_type, rdata): (u16, Vec<u8>) = match ip {
            IpAddr::V4(addr) => (1, addr.octets().to_vec()),
            IpAddr::V6(addr) => (28, addr.octets().to_vec()),
        };
        resp.extend_from_slice(&record_type.to_be_bytes());
        resp.extend_from_slice(&1u16.to_be_bytes());
        resp.extend_from_slice(&ttl.to_be_bytes());
        resp.extend_from_slice(&(rdata.len() as u16).to_be_bytes());
        resp.extend_from_slice(&rdata);
    }
    Ok(resp)
}

/// Skips a DNS domain name in wire format, handling RFC 1035 compression pointers safely.
fn skip_name(buf: &[u8], offset: usize) -> Result<usize, DnsError> {
    let mut end_offset = None;
    let mut curr = offset;
    let mut hops = 0;

    while let Some(&len) = buf.get(curr) {
        if len == 0 {
            if end_offset.is_none() {
                end_offset = Some(curr + 1);
            }
            break;
        } else if (len & 0xC0) == 0xC0 {
            let Some(&next_byte) = buf.get(curr + 1) else {
                return Err(DnsError::PacketTooShort);
            };
            if end_offset.is_none() {
                end_offset = Some(curr + 2);
            }
            let ptr = (((len & 0x3F) as usize) << 8) | (next_byte as usize);
            if ptr >= buf.len() {
                return Err(DnsError::PacketTooShort);
            }
            curr = ptr;
            hops += 1;
            if hops > 16 {
                return Err(DnsError::PointerLoop);
            }
        } else if (len & 0xC0) == 0 {
            curr += 1 + (len as usize);
            if curr > buf.len() {
                return Err(DnsError::PacketTooShort);
            }
        } else {
            return Err(DnsError::CorruptLabel);
        }
    }

    end_offset.ok_or(DnsError::PacketTooShort)
}

#[derive(Debug)]
struct DnsCacheEntry {
    ips: Vec<IpAddr>,
    expires_at: Instant,
    last_accessed: AtomicU64,
}

/// Cloneable DNS result shared by concurrent lookups of the same domain
/// (singleflight). `io::Error` is not `Clone`, so both arms are `Arc`d.
type SharedDnsResult = Result<Arc<Vec<IpAddr>>, Arc<io::Error>>;

/// Thread-safe TTL-aware LRU cache for resolved DNS domain names.
#[derive(Debug)]
pub struct DnsLruCache {
    entries: RwLock<HashMap<String, DnsCacheEntry>>,
    capacity: usize,
    access_counter: AtomicU64,
    min_ttl: Duration,
    max_ttl: Duration,
    /// In-flight singleflight cells keyed by cache key. Concurrent lookups
    /// for the same key share one upstream query instead of each doing
    /// its own slow in-tunnel query. The key carries the resolver's
    /// upstream scope (see [`InTunnelDnsResolver::cache_key`]), so the
    /// cell only coalesces lookups that would hit the same servers.
    inflight: AsyncMutex<HashMap<String, Arc<OnceCell<SharedDnsResult>>>>,
}

impl DnsLruCache {
    pub fn new(capacity: usize) -> Self {
        Self {
            entries: RwLock::new(HashMap::with_capacity(capacity)),
            capacity,
            access_counter: AtomicU64::new(0),
            // Clamped min TTL (60s): a resolved entry survives at least a minute,
            // so a burst of fresh lookups for the same domain does not re-query
            // the upstream on every request. Records with a longer TTL keep it.
            min_ttl: Duration::from_secs(60),
            max_ttl: Duration::from_hours(24), // Clamped max TTL (24h)
            inflight: AsyncMutex::new(HashMap::new()),
        }
    }

    /// Get or create the singleflight cell for a cache key.
    async fn inflight_cell(&self, key: &str) -> Arc<OnceCell<SharedDnsResult>> {
        {
            let mut inflight = self.inflight.lock().await;
            Arc::clone(
                inflight
                    .entry(key.to_string())
                    .or_insert_with(|| Arc::new(OnceCell::new())),
            )
        }
    }

    /// Remove the singleflight cell for a key, but only if it is still the
    /// same cell (a newer lookup for the same key may have replaced it).
    async fn remove_inflight(&self, key: &str, cell: &Arc<OnceCell<SharedDnsResult>>) {
        let mut inflight = self.inflight.lock().await;
        if let Some(existing) = inflight.get(key)
            && Arc::ptr_eq(existing, cell)
        {
            inflight.remove(key);
        }
    }

    pub fn get(&self, domain: &str) -> Option<Vec<IpAddr>> {
        let key = domain.trim().trim_end_matches('.').to_ascii_lowercase();
        let now = Instant::now();

        let (cached, has_expired) = {
            let entries = self.entries.read();
            match entries.get(&key) {
                Some(entry) if now < entry.expires_at => {
                    let access_time = self.access_counter.fetch_add(1, Ordering::Relaxed) + 1;
                    entry.last_accessed.store(access_time, Ordering::Relaxed);
                    (Some(entry.ips.clone()), false)
                }
                Some(_) => (None, true),
                None => (None, false),
            }
        };
        if let Some(ips) = cached {
            return Some(ips);
        }

        if has_expired {
            let mut entries = self.entries.write();
            if let Some(entry) = entries.get(&key)
                && now >= entry.expires_at
            {
                entries.remove(&key);
            }
        }
        None
    }

    pub fn insert(&self, domain: &str, ips: Vec<IpAddr>, ttl_secs: u32) {
        if self.capacity == 0 || ips.is_empty() {
            return;
        }
        let key = domain.trim().trim_end_matches('.').to_ascii_lowercase();
        let ttl = Duration::from_secs(u64::from(ttl_secs)).clamp(self.min_ttl, self.max_ttl);
        let expires_at = Instant::now() + ttl;

        let access_time = self.access_counter.fetch_add(1, Ordering::Relaxed) + 1;

        let mut entries = self.entries.write();

        if entries.len() >= self.capacity && !entries.contains_key(&key) {
            let now = Instant::now();
            entries.retain(|_, v| now < v.expires_at);

            if entries.len() >= self.capacity
                && let Some(lru_key) = entries
                    .iter()
                    .min_by_key(|(_, v)| v.last_accessed.load(Ordering::Relaxed))
                    .map(|(k, _)| k.clone())
            {
                entries.remove(&lru_key);
            }
        }

        entries.insert(
            key,
            DnsCacheEntry {
                ips,
                expires_at,
                last_accessed: AtomicU64::new(access_time),
            },
        );
    }

    pub fn clear(&self) {
        self.entries.write().clear();
    }

    pub fn len(&self) -> usize {
        self.entries.read().len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

/// Build the fallback DNS server list when a tunnel `.conf` omits `DNS`.
fn build_fallback_servers(fallback: SocketAddr) -> Vec<SocketAddr> {
    let mut servers = vec![fallback];
    let default_v4 = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)), 53);
    if fallback != default_v4 {
        servers.push(default_v4);
    }
    servers.push(SocketAddr::new(IpAddr::V4(Ipv4Addr::new(1, 0, 0, 1)), 53));
    servers
}

/// In-tunnel DNS resolver guaranteeing zero host DNS leaks.
///
/// The cache is reference-counted so one daemon-wide cache can be shared by
/// every tunnel's resolver — but entries are keyed by the resolver's
/// upstream DNS servers (see [`Self::cache_key`]), so a shared cache
/// never serves one tunnel's DNS answer to a resolver with different
/// upstreams; host-fallback answers live under a separate `host|`
/// namespace. With per-tunnel caches, round-robin across many tunnels
/// re-resolves the same domain on nearly every connection (each
/// tunnel's cache goes cold between its turns), while a scoped shared
/// cache stays warm as long as any tunnel with the same upstreams
/// resolved the domain recently.
#[derive(Debug)]
pub struct InTunnelDnsResolver {
    has_configured_dns: bool,
    dns_servers: RwLock<Vec<SocketAddr>>,
    cache: Arc<DnsLruCache>,
    timeout: Duration,
    max_retries: usize,
    prefer_ipv6: std::sync::atomic::AtomicBool,
    ip_mode: std::sync::atomic::AtomicU8,
    dns_strategy: std::sync::atomic::AtomicU8,
}

impl InTunnelDnsResolver {
    /// Construct resolver from configured tunnel DNS addresses, with `1.1.1.1:53` fallback.
    pub fn new(configured_dns: &[IpAddr]) -> Self {
        Self::with_fallback(
            configured_dns,
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)), 53),
        )
    }

    /// Construct resolver from configured tunnel DNS addresses and an explicit fallback server.
    pub fn with_fallback(configured_dns: &[IpAddr], fallback: SocketAddr) -> Self {
        Self::with_fallback_and_cache(configured_dns, fallback, Arc::new(DnsLruCache::new(2048)))
    }

    /// Construct resolver sharing a daemon-wide DNS cache with other tunnels.
    pub fn with_fallback_and_cache(
        configured_dns: &[IpAddr],
        fallback: SocketAddr,
        cache: Arc<DnsLruCache>,
    ) -> Self {
        let has_configured_dns = !configured_dns.is_empty();
        let servers = if has_configured_dns {
            configured_dns
                .iter()
                .map(|&ip| SocketAddr::new(ip, 53))
                .collect()
        } else {
            build_fallback_servers(fallback)
        };

        Self {
            has_configured_dns,
            dns_servers: RwLock::new(servers),
            cache,
            timeout: Duration::from_secs(2),
            max_retries: 2,
            prefer_ipv6: std::sync::atomic::AtomicBool::new(false),
            ip_mode: std::sync::atomic::AtomicU8::new(0),
            dns_strategy: std::sync::atomic::AtomicU8::new(0),
        }
    }

    /// Update the fallback DNS servers dynamically when the tunnel has no explicit `.conf` `DNS`.
    pub fn set_dns_fallback(&self, fallback: SocketAddr) {
        if !self.has_configured_dns {
            *self.dns_servers.write() = build_fallback_servers(fallback);
        }
    }

    /// Return the active upstream DNS server list.
    pub fn dns_servers(&self) -> Vec<SocketAddr> {
        self.dns_servers.read().clone()
    }

    /// Configure the DNS resolution strategy (`TunnelOnly`, `TunnelFirst`, `Host`).
    pub fn set_dns_strategy(&self, strategy: crate::config::toml_config::DnsStrategy) {
        let val = match strategy {
            crate::config::toml_config::DnsStrategy::TunnelOnly => 0,
            crate::config::toml_config::DnsStrategy::TunnelFirst => 1,
            crate::config::toml_config::DnsStrategy::Host => 2,
        };
        self.dns_strategy.store(val, Ordering::Relaxed);
    }

    /// Return the configured DNS resolution strategy.
    pub fn dns_strategy(&self) -> crate::config::toml_config::DnsStrategy {
        match self.dns_strategy.load(Ordering::Relaxed) {
            1 => crate::config::toml_config::DnsStrategy::TunnelFirst,
            2 => crate::config::toml_config::DnsStrategy::Host,
            _ => crate::config::toml_config::DnsStrategy::TunnelOnly,
        }
    }

    /// Configure whether dual-stack domain resolution prefers IPv6 (`AAAA`) over IPv4 (`A`).
    pub fn set_prefer_ipv6(&self, prefer: bool) {
        self.prefer_ipv6.store(prefer, Ordering::Relaxed);
    }

    /// Return whether dual-stack domain resolution prefers IPv6 (`AAAA`).
    pub fn prefer_ipv6(&self) -> bool {
        self.prefer_ipv6.load(Ordering::Relaxed)
    }

    /// Configure strict IP family isolation mode (`DualStack`, `Ipv4Only`, `Ipv6Only`).
    pub fn set_ip_mode(&self, mode: crate::config::IpMode) {
        self.ip_mode.store(mode.to_u8(), Ordering::Relaxed);
    }

    /// Return the configured strict IP family isolation mode.
    pub fn ip_mode(&self) -> crate::config::IpMode {
        crate::config::IpMode::from_u8(self.ip_mode.load(Ordering::Relaxed))
    }

    /// Resolve domain to a single IP address using the resolver's configured `IpMode`.
    pub async fn resolve(
        &self,
        stack: &VirtualNetworkStack,
        domain: &str,
    ) -> Result<IpAddr, io::Error> {
        self.resolve_with_mode(stack, domain, self.ip_mode()).await
    }

    /// Resolve domain to a single IP address enforced by an explicit `IpMode`.
    pub async fn resolve_with_mode(
        &self,
        stack: &VirtualNetworkStack,
        domain: &str,
        mode: crate::config::IpMode,
    ) -> Result<IpAddr, io::Error> {
        let addrs = self.resolve_all_with_mode(stack, domain, mode).await?;
        addrs.into_iter().next().ok_or_else(|| {
            io::Error::new(io::ErrorKind::NotFound, "no IP addresses found for domain")
        })
    }

    /// Resolve domain to all resolved IPv4/IPv6 addresses.
    pub async fn resolve_all(
        &self,
        stack: &VirtualNetworkStack,
        domain: &str,
    ) -> Result<Vec<IpAddr>, io::Error> {
        self.resolve_all_with_mode(stack, domain, self.ip_mode())
            .await
    }

    /// Cache key for a lookup, scoped so one tunnel's DNS answer can
    /// never poison another tunnel's resolution (audit run-1,
    /// `dns-shared-cache-cross-tunnel-poisoning`): the key carries the
    /// resolver's upstream DNS server list, so only resolvers with
    /// identical upstreams share entries (and the singleflight cell,
    /// which is keyed the same way). Host-strategy lookups use the
    /// separate `host|` namespace instead, so a host-resolver answer
    /// is never served as a tunnel answer.
    fn cache_key(&self, mode: crate::config::IpMode, prefer_v6: bool, domain: &str) -> String {
        if self.dns_strategy() == crate::config::toml_config::DnsStrategy::Host {
            return Self::host_cache_key(mode, prefer_v6, domain);
        }
        let mut servers = self.dns_servers();
        servers.sort();
        let scope = servers
            .iter()
            .map(SocketAddr::to_string)
            .collect::<Vec<_>>()
            .join(",");
        format!("{scope}|{}", Self::mode_cache_key(mode, prefer_v6, domain))
    }

    /// Cache key for a host-resolver answer: its own namespace, never
    /// shared with tunnel answers.
    fn host_cache_key(mode: crate::config::IpMode, prefer_v6: bool, domain: &str) -> String {
        format!("host|{}", Self::mode_cache_key(mode, prefer_v6, domain))
    }

    /// Mode/domain part of a cache key.
    fn mode_cache_key(mode: crate::config::IpMode, prefer_v6: bool, domain: &str) -> String {
        match mode {
            crate::config::IpMode::DualStack => {
                if prefer_v6 {
                    format!("ds6:{domain}")
                } else {
                    format!("ds4:{domain}")
                }
            }
            crate::config::IpMode::Ipv4Only => format!("v4:{domain}"),
            crate::config::IpMode::Ipv6Only => format!("v6:{domain}"),
        }
    }

    /// Resolve domain to all resolved addresses permitted by `mode`.
    pub async fn resolve_all_with_mode(
        &self,
        stack: &VirtualNetworkStack,
        domain: &str,
        mode: crate::config::IpMode,
    ) -> Result<Vec<IpAddr>, io::Error> {
        let trimmed = domain.trim().trim_end_matches('.');
        // Fast-path: check if domain is already a valid IP literal
        if let Ok(ip) = trimmed.parse::<IpAddr>() {
            mode.check_ip(ip, "IP address")?;
            return Ok(vec![ip]);
        }

        let prefer_v6 = self.prefer_ipv6.load(Ordering::Relaxed);
        let cache_key = self.cache_key(mode, prefer_v6, trimmed);

        // Check LRU cache
        if let Some(cached) = self.cache.get(&cache_key) {
            return Ok(cached);
        }

        // Singleflight: concurrent lookups for the same domain share one
        // upstream query instead of each doing its own slow in-tunnel query
        // (a stampede when the cache entry expires under load).
        let cell = self.cache.inflight_cell(&cache_key).await;
        let shared = cell
            .get_or_init(|| async {
                match self
                    .resolve_uncached(stack, trimmed, mode, prefer_v6, &cache_key)
                    .await
                {
                    Ok(ips) => Ok(Arc::new(ips)),
                    Err(err) => Err(Arc::new(err)),
                }
            })
            .await
            .clone();
        self.cache.remove_inflight(&cache_key, &cell).await;

        match shared {
            Ok(ips) => Ok((*ips).clone()),
            // Rebuild the error with the same kind and message; the
            // original's source chain is not shareable across tasks.
            Err(err) => Err(io::Error::new(err.kind(), err.to_string())),
        }
    }

    /// Perform the actual upstream lookup (host or in-tunnel) and populate
    /// the cache on success. Called once per cache key via singleflight.
    async fn resolve_uncached(
        &self,
        stack: &VirtualNetworkStack,
        trimmed: &str,
        mode: crate::config::IpMode,
        prefer_v6: bool,
        cache_key: &str,
    ) -> Result<Vec<IpAddr>, io::Error> {
        let strategy = self.dns_strategy();
        if strategy == crate::config::toml_config::DnsStrategy::Host {
            let ips = self.resolve_via_host(trimmed, mode, prefer_v6).await?;
            self.cache.insert(cache_key, ips.clone(), 60);
            return Ok(ips);
        }

        let servers = self.effective_servers(mode);

        // Query tunnel DNS servers strictly inside the WireGuard tunnel
        let mut last_err = io::Error::new(io::ErrorKind::TimedOut, "DNS resolution timed out");
        // Total DNS deadline (1s): a single slow lookup must fail fast so the
        // router can try another tunnel within the 3.5s failover budget.
        // A 3s deadline consumed nearly the whole budget on one tunnel.
        let dns_deadline = tokio::time::Instant::now() + Duration::from_secs(1);

        'servers: for &server in &servers {
            for retry in 0..self.max_retries {
                let Some(remaining) =
                    dns_deadline.checked_duration_since(tokio::time::Instant::now())
                else {
                    break 'servers;
                };
                if remaining.is_zero() {
                    break 'servers;
                }
                match tokio::time::timeout(
                    remaining,
                    self.query_server(stack, trimmed, server, mode, dns_deadline),
                )
                .await
                {
                    Ok(Ok((ips, ttl))) => {
                        self.cache.insert(cache_key, ips.clone(), ttl);
                        return Ok(ips);
                    }
                    Ok(Err(e)) => {
                        tracing::debug!(
                            "DNS query to {} attempt {} failed: {}",
                            server,
                            retry + 1,
                            e
                        );
                        let is_definitive = e.kind() == io::ErrorKind::NotFound;
                        last_err = e;
                        if is_definitive {
                            break;
                        }
                        if retry + 1 < self.max_retries {
                            tokio::time::sleep(Duration::from_millis(50 * (retry as u64 + 1)))
                                .await;
                        }
                    }
                    Err(_) => {
                        last_err = io::Error::new(io::ErrorKind::TimedOut, "DNS query timed out");
                        break 'servers;
                    }
                }
            }
        }

        let is_transport_err = matches!(
            last_err.kind(),
            io::ErrorKind::TimedOut
                | io::ErrorKind::ConnectionRefused
                | io::ErrorKind::ConnectionReset
                | io::ErrorKind::NetworkUnreachable
                | io::ErrorKind::HostUnreachable
        );
        if strategy == crate::config::toml_config::DnsStrategy::TunnelFirst && is_transport_err {
            // Host-fallback answers live under the separate `host|`
            // namespace: a host answer must never be served as a
            // tunnel answer, and a tunnel lookup must never be
            // satisfied from the host cache.
            let host_key = Self::host_cache_key(mode, prefer_v6, trimmed);
            if let Some(ips) = self.cache.get(&host_key) {
                return Ok(ips);
            }
            if let Ok(ips) = self.resolve_via_host(trimmed, mode, prefer_v6).await {
                self.cache.insert(&host_key, ips.clone(), 60);
                return Ok(ips);
            }
        }

        Err(last_err)
    }

    fn effective_servers(&self, mode: crate::config::IpMode) -> Vec<SocketAddr> {
        let mut servers: Vec<SocketAddr> = self
            .dns_servers
            .read()
            .iter()
            .copied()
            .filter(|s| mode.allows_ip(s.ip()))
            .collect();

        if servers.is_empty() {
            match mode {
                crate::config::IpMode::Ipv4Only => {
                    servers.push(SocketAddr::new(IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)), 53));
                    servers.push(SocketAddr::new(IpAddr::V4(Ipv4Addr::new(1, 0, 0, 1)), 53));
                }
                crate::config::IpMode::Ipv6Only => {
                    servers.push(SocketAddr::new(
                        IpAddr::V6(Ipv6Addr::new(0x2606, 0x4700, 0x4700, 0, 0, 0, 0, 0x1111)),
                        53,
                    ));
                    servers.push(SocketAddr::new(
                        IpAddr::V6(Ipv6Addr::new(0x2606, 0x4700, 0x4700, 0, 0, 0, 0, 0x1001)),
                        53,
                    ));
                }
                crate::config::IpMode::DualStack => {}
            }
        }
        servers
    }

    /// Perform an uncached in-tunnel DNS query to verify actual data-plane egress.
    pub async fn probe_egress(
        &self,
        stack: &VirtualNetworkStack,
        timeout: Duration,
    ) -> Result<(), io::Error> {
        let mode = self.ip_mode();
        let servers = self.effective_servers(mode);
        let Some(&server) = servers.first() else {
            return Err(io::Error::new(
                io::ErrorKind::NotFound,
                "no in-tunnel DNS server available for egress probe",
            ));
        };
        let qtype = match mode {
            crate::config::IpMode::Ipv4Only => QueryType::A,
            crate::config::IpMode::Ipv6Only => QueryType::AAAA,
            crate::config::IpMode::DualStack => {
                if server.is_ipv6() || self.prefer_ipv6.load(Ordering::Relaxed) {
                    QueryType::AAAA
                } else {
                    QueryType::A
                }
            }
        };
        tokio::time::timeout(
            timeout,
            self.query_record(
                stack,
                "one.one.one.one",
                server,
                qtype,
                tokio::time::Instant::now() + timeout,
            ),
        )
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "egress DNS probe timed out"))??;
        Ok(())
    }

    /// Resolve a domain via the host OS resolver, filtering by `IpMode` and sorting by `prefer_ipv6`.
    async fn resolve_via_host(
        &self,
        domain: &str,
        mode: crate::config::IpMode,
        prefer_v6: bool,
    ) -> Result<Vec<IpAddr>, io::Error> {
        let mut ips: Vec<IpAddr> =
            tokio::time::timeout(self.timeout, tokio::net::lookup_host((domain, 0u16)))
                .await
                .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "host DNS lookup timed out"))??
                .map(|s| s.ip())
                .filter(|ip| mode.allows_ip(*ip))
                .collect();

        if ips.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::NotFound,
                "no permitted IP addresses returned by host DNS",
            ));
        }

        ips.sort_by_key(|ip| match (prefer_v6, ip) {
            (true, IpAddr::V6(_)) | (false, IpAddr::V4(_)) => 0u8,
            _ => 1u8,
        });
        Ok(ips)
    }

    /// Query a single upstream DNS server according to `IpMode` and `prefer_ipv6`.
    /// `deadline` is the caller's overall budget; a TCP fallback after a
    /// truncated UDP answer fails against it (see [`Self::query_record`]).
    async fn query_server(
        &self,
        stack: &VirtualNetworkStack,
        domain: &str,
        server: SocketAddr,
        mode: crate::config::IpMode,
        deadline: tokio::time::Instant,
    ) -> Result<(Vec<IpAddr>, u32), io::Error> {
        let qtypes: &[QueryType] = match mode {
            crate::config::IpMode::Ipv4Only => &[QueryType::A],
            crate::config::IpMode::Ipv6Only => &[QueryType::AAAA],
            crate::config::IpMode::DualStack => {
                if self.prefer_ipv6.load(Ordering::Relaxed) {
                    &[QueryType::AAAA, QueryType::A]
                } else {
                    &[QueryType::A, QueryType::AAAA]
                }
            }
        };

        let mut collected_ips = Vec::new();
        let mut min_ttl = u32::MAX;
        let mut last_err = io::Error::new(io::ErrorKind::NotFound, "no DNS records found");
        for &qtype in qtypes {
            match self
                .query_record(stack, domain, server, qtype, deadline)
                .await
            {
                Ok((mut ips, ttl)) => {
                    ips.retain(|ip| mode.allows_ip(*ip));
                    if !ips.is_empty() {
                        min_ttl = min_ttl.min(ttl);
                        collected_ips.extend(ips);
                    }
                }
                Err(e) => last_err = e,
            }
        }
        if !collected_ips.is_empty() {
            return Ok((collected_ips, min_ttl));
        }
        Err(last_err)
    }

    async fn query_record(
        &self,
        stack: &VirtualNetworkStack,
        domain: &str,
        server: SocketAddr,
        qtype: QueryType,
        deadline: tokio::time::Instant,
    ) -> Result<(Vec<IpAddr>, u32), io::Error> {
        let socket = stack.udp_bind_with_size(0, 4096, 4096, 2)?;
        let tx_id = rand::random::<u16>();

        let query = build_query(domain, qtype, tx_id)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e.to_string()))?;

        // UDP phase. A truncated (TC) response ends the phase with
        // `None` instead of an answer: the server already proved
        // reachable over UDP, so the TCP retry below runs under its
        // own budget and its failure must not look like a tunnel
        // transport failure (audit run-1,
        // `dns-tcp-fallback-failure-triggers-host-dns-leak`).
        let answered = tokio::time::timeout(
            self.timeout,
            Self::query_record_udp(&socket, server, &query, domain, qtype, tx_id),
        )
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "DNS query timed out"))??;
        let Some(answer) = answered else {
            // TCP fallback after a truncated UDP answer: any failure
            // here (refused/reset/timed-out TCP/53) is a failure of
            // the already-proven DNS server, not of the tunnel
            // transport, so report it with `Other` — a kind
            // `resolve_uncached` never treats as a host-fallback
            // trigger — instead of the raw transport kind. The
            // fallback runs against the caller's shared `deadline`
            // (not a fresh budget), so even a hung TCP/53 surfaces
            // here as `Other` instead of expiring as `TimedOut` in
            // the caller's timeout and leaking the domain to host DNS.
            return tokio::time::timeout_at(
                deadline,
                self.query_record_tcp(stack, server, &query, domain, qtype),
            )
            .await
            .map_err(|_| {
                io::Error::other("DNS TCP fallback timed out after truncated UDP response")
            })?
            .map_err(|e| {
                io::Error::other(format!(
                    "DNS TCP fallback failed after truncated UDP response: {e}"
                ))
            });
        };
        Ok(answer)
    }

    /// One UDP DNS exchange: send `query` to `server` and wait for the
    /// matching response. Returns `Ok(None)` when the response has the
    /// TC (Truncated) bit set and the caller must retry over TCP.
    async fn query_record_udp(
        socket: &crate::netstack::VirtualUdpSocket,
        server: SocketAddr,
        query: &[u8],
        domain: &str,
        qtype: QueryType,
        tx_id: u16,
    ) -> Result<Option<(Vec<IpAddr>, u32)>, io::Error> {
        socket.send_to(query, server).await?;

        let mut buf = [0u8; 1500];
        loop {
            let (len, from) = socket.recv_from(&mut buf).await?;
            if from != server {
                continue;
            }
            let resp_slice = buf
                .get(..len)
                .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "short DNS buffer"))?;
            if let (Ok(id), Ok(flags)) = (read_u16_be(resp_slice, 0), read_u16_be(resp_slice, 2)) {
                if id != tx_id || (flags & 0x8000) == 0 {
                    continue;
                }
                if !response_matches_question(resp_slice, domain, qtype) {
                    continue;
                }
                // TC (Truncated) bit set -> fall back to DNS-over-TCP
                if flags & 0x0200 != 0 {
                    return Ok(None);
                }
            } else {
                continue;
            }
            let (ips, ttl) =
                parse_response(resp_slice, tx_id).map_err(|e| io::Error::other(e.to_string()))?;
            return Ok(Some((ips, ttl)));
        }
    }

    async fn query_record_tcp(
        &self,
        stack: &VirtualNetworkStack,
        server: SocketAddr,
        query: &[u8],
        domain: &str,
        qtype: QueryType,
    ) -> Result<(Vec<IpAddr>, u32), io::Error> {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let tx_id = read_u16_be(query, 0)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e.to_string()))?;
        let mut stream = stack.tcp_connect(server).await?;
        let len_prefix = u16::try_from(query.len()).map_err(|_| {
            io::Error::new(io::ErrorKind::InvalidInput, "DNS query too large for TCP")
        })?;
        stream.write_all(&len_prefix.to_be_bytes()).await?;
        stream.write_all(query).await?;
        stream.flush().await?;

        let mut resp_len_buf = [0u8; 2];
        stream.read_exact(&mut resp_len_buf).await?;
        let resp_len = u16::from_be_bytes(resp_len_buf) as usize;
        if resp_len < 12 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "DNS TCP response too short",
            ));
        }
        let mut resp = vec![0u8; resp_len];
        stream.read_exact(&mut resp).await?;
        if !response_matches_question(&resp, domain, qtype) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "DNS TCP response question mismatch",
            ));
        }
        parse_response(&resp, tx_id).map_err(|e| io::Error::other(e.to_string()))
    }
}

/// Whether a DNS response's question section matches the expected
/// domain, question type, and IN class.
pub(crate) fn response_matches_question(
    buf: &[u8],
    expected_domain: &str,
    expected_qtype: QueryType,
) -> bool {
    let Ok(qdcount) = read_u16_be(buf, 4) else {
        return false;
    };
    if qdcount == 0 {
        return false;
    }
    let expected_clean = expected_domain.trim().trim_end_matches('.');
    let Some((decoded_name, next_offset)) = decode_name(buf, 12, 0) else {
        return false;
    };
    let Ok(qtype) = read_u16_be(buf, next_offset) else {
        return false;
    };
    let Ok(qclass) = read_u16_be(buf, next_offset + 2) else {
        return false;
    };
    decoded_name.eq_ignore_ascii_case(expected_clean)
        && qtype == expected_qtype as u16
        && qclass == 1
}

fn decode_name(buf: &[u8], mut offset: usize, depth: usize) -> Option<(String, usize)> {
    if depth > 16 {
        return None;
    }
    let mut labels = Vec::new();
    let mut jumped_next = None;
    loop {
        let len = *buf.get(offset)?;
        if len == 0 {
            if jumped_next.is_none() {
                jumped_next = Some(offset + 1);
            }
            break;
        }
        if (len & 0xC0) == 0xC0 {
            let b2 = *buf.get(offset + 1)?;
            let ptr = ((usize::from(len & 0x3F)) << 8) | usize::from(b2);
            if jumped_next.is_none() {
                jumped_next = Some(offset + 2);
            }
            let (rest, _) = decode_name(buf, ptr, depth + 1)?;
            if !rest.is_empty() {
                labels.push(rest);
            }
            break;
        }
        if len > 63 {
            return None;
        }
        offset += 1;
        let label_bytes = buf.get(offset..offset + usize::from(len))?;
        let label = std::str::from_utf8(label_bytes).ok()?;
        labels.push(label.to_string());
        offset += usize::from(len);
    }
    Some((labels.join("."), jumped_next?))
}
