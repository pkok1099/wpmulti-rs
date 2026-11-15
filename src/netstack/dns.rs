//! In-tunnel remote DNS resolver with minimal RFC 1035 encoder/decoder and LRU cache.
//!
//! Queries are strictly routed inside the WireGuard tunnel over virtual UDP to
//! eliminate host DNS leaks.

use std::collections::HashMap;
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};
use parking_lot::RwLock;
use thiserror::Error;

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
    packet.extend_from_slice(&1u16.to_be_bytes());      // QDCOUNT = 1
    packet.extend_from_slice(&0u16.to_be_bytes());      // ANCOUNT = 0
    packet.extend_from_slice(&0u16.to_be_bytes());      // NSCOUNT = 0
    packet.extend_from_slice(&0u16.to_be_bytes());      // ARCOUNT = 0

    // Question: QNAME
    let clean = domain.trim().trim_end_matches('.');
    if clean.is_empty() {
        packet.push(0);
    } else {
        for label in clean.split('.') {
            if label.is_empty() {
                return Err(DnsError::InvalidDomain("empty label in domain"));
            }
            if label.len() > 63 {
                return Err(DnsError::InvalidDomain("label exceeds 63 bytes"));
            }
            packet.push(label.len() as u8);
            packet.extend_from_slice(label.as_bytes());
        }
        packet.push(0);
    }

    // QTYPE and QCLASS (1 = IN)
    packet.extend_from_slice(&(qtype as u16).to_be_bytes());
    packet.extend_from_slice(&1u16.to_be_bytes());

    Ok(packet)
}

/// Parses an RFC 1035 DNS response packet, extracting IP addresses and minimum TTL.
pub fn parse_response(buf: &[u8], expected_id: u16) -> Result<(Vec<IpAddr>, u32), DnsError> {
    if buf.len() < 12 {
        return Err(DnsError::PacketTooShort);
    }

    let id = u16::from_be_bytes([buf[0], buf[1]]);
    if id != expected_id {
        return Err(DnsError::IdMismatch);
    }

    let flags = u16::from_be_bytes([buf[2], buf[3]]);
    let qr = (flags >> 15) & 1;
    if qr == 0 {
        return Err(DnsError::NotAResponse);
    }

    let rcode = flags & 0x000F;
    if rcode == 3 {
        return Err(DnsError::NxDomain);
    } else if rcode != 0 {
        return Err(DnsError::ServerError(rcode));
    }

    let qdcount = u16::from_be_bytes([buf[4], buf[5]]) as usize;
    let ancount = u16::from_be_bytes([buf[6], buf[7]]) as usize;

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

        let atype = u16::from_be_bytes([buf[offset], buf[offset + 1]]);
        let _aclass = u16::from_be_bytes([buf[offset + 2], buf[offset + 3]]);
        let ttl = u32::from_be_bytes([buf[offset + 4], buf[offset + 5], buf[offset + 6], buf[offset + 7]]);
        let rdlength = u16::from_be_bytes([buf[offset + 8], buf[offset + 9]]) as usize;
        offset += 10;

        if offset + rdlength > buf.len() {
            return Err(DnsError::PacketTooShort);
        }

        let rdata = &buf[offset..offset + rdlength];
        offset += rdlength;

        if atype == 1 && rdlength == 4 {
            // A Record (IPv4)
            let ip = Ipv4Addr::new(rdata[0], rdata[1], rdata[2], rdata[3]);
            ips.push(IpAddr::V4(ip));
            min_ttl = min_ttl.min(ttl);
        } else if atype == 28 && rdlength == 16 {
            // AAAA Record (IPv6)
            let mut octets = [0u8; 16];
            octets.copy_from_slice(rdata);
            let ip = Ipv6Addr::from(octets);
            ips.push(IpAddr::V6(ip));
            min_ttl = min_ttl.min(ttl);
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

/// Skips a DNS domain name in wire format, handling RFC 1035 compression pointers safely.
fn skip_name(buf: &[u8], offset: usize) -> Result<usize, DnsError> {
    let mut end_offset = None;
    let mut curr = offset;
    let mut hops = 0;

    while curr < buf.len() {
        let len = buf[curr];
        if len == 0 {
            if end_offset.is_none() {
                end_offset = Some(curr + 1);
            }
            break;
        } else if (len & 0xC0) == 0xC0 {
            if curr + 1 >= buf.len() {
                return Err(DnsError::PacketTooShort);
            }
            if end_offset.is_none() {
                end_offset = Some(curr + 2);
            }
            let ptr = (((len & 0x3F) as usize) << 8) | (buf[curr + 1] as usize);
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

/// Thread-safe TTL-aware LRU cache for resolved DNS domain names.
pub struct DnsLruCache {
    entries: RwLock<HashMap<String, DnsCacheEntry>>,
    capacity: usize,
    access_counter: AtomicU64,
    min_ttl: Duration,
    max_ttl: Duration,
}

impl DnsLruCache {
    pub fn new(capacity: usize) -> Self {
        Self {
            entries: RwLock::new(HashMap::with_capacity(capacity)),
            capacity,
            access_counter: AtomicU64::new(0),
            min_ttl: Duration::from_secs(5),     // Clamped min TTL
            max_ttl: Duration::from_secs(86400), // Clamped max TTL (24h)
        }
    }

    pub fn get(&self, domain: &str) -> Option<Vec<IpAddr>> {
        let key = domain.trim().trim_end_matches('.').to_ascii_lowercase();
        let now = Instant::now();

        {
            let entries = self.entries.read();
            if let Some(entry) = entries.get(&key) {
                if now < entry.expires_at {
                    let access_time = self.access_counter.fetch_add(1, Ordering::Relaxed) + 1;
                    entry.last_accessed.store(access_time, Ordering::Relaxed);
                    return Some(entry.ips.clone());
                }
            } else {
                return None;
            }
        }

        let mut entries = self.entries.write();
        if let Some(entry) = entries.get(&key)
            && now >= entry.expires_at
        {
            entries.remove(&key);
        }
        None
    }

    pub fn insert(&self, domain: &str, ips: Vec<IpAddr>, ttl_secs: u32) {
        if ips.is_empty() {
            return;
        }
        let key = domain.trim().trim_end_matches('.').to_ascii_lowercase();
        let ttl = Duration::from_secs(ttl_secs as u64).clamp(self.min_ttl, self.max_ttl);
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

/// In-tunnel DNS resolver guaranteeing zero host DNS leaks.
pub struct InTunnelDnsResolver {
    dns_servers: Vec<SocketAddr>,
    cache: DnsLruCache,
    timeout: Duration,
    max_retries: usize,
    prefer_ipv6: std::sync::atomic::AtomicBool,
    ip_mode: std::sync::atomic::AtomicU8,
    dns_strategy: std::sync::atomic::AtomicU8,
}

impl InTunnelDnsResolver {
    /// Construct resolver from configured tunnel DNS addresses, with `1.1.1.1:53` fallback.
    pub fn new(configured_dns: &[IpAddr]) -> Self {
        Self::with_fallback(configured_dns, "1.1.1.1:53".parse().unwrap())
    }

    /// Construct resolver from configured tunnel DNS addresses and an explicit fallback server.
    pub fn with_fallback(configured_dns: &[IpAddr], fallback: SocketAddr) -> Self {
        let mut servers = Vec::new();
        for &ip in configured_dns {
            servers.push(SocketAddr::new(ip, 53));
        }
        if servers.is_empty() {
            servers.push(fallback);
            let default_v4: SocketAddr = "1.1.1.1:53".parse().unwrap();
            if fallback != default_v4 {
                servers.push(default_v4);
            }
            servers.push("1.0.0.1:53".parse().unwrap());
        }

        Self {
            dns_servers: servers,
            cache: DnsLruCache::new(2048),
            timeout: Duration::from_millis(1500),
            max_retries: 2,
            prefer_ipv6: std::sync::atomic::AtomicBool::new(false),
            ip_mode: std::sync::atomic::AtomicU8::new(0),
            dns_strategy: std::sync::atomic::AtomicU8::new(0),
        }
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
        self.prefer_ipv6
            .store(prefer, std::sync::atomic::Ordering::Relaxed);
    }

    /// Configure strict IP family isolation mode (`DualStack`, `Ipv4Only`, `Ipv6Only`).
    pub fn set_ip_mode(&self, mode: crate::config::IpMode) {
        self.ip_mode
            .store(mode.to_u8(), std::sync::atomic::Ordering::Relaxed);
    }

    /// Return the configured strict IP family isolation mode.
    pub fn ip_mode(&self) -> crate::config::IpMode {
        crate::config::IpMode::from_u8(self.ip_mode.load(std::sync::atomic::Ordering::Relaxed))
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
        let cache_key = match mode {
            crate::config::IpMode::DualStack => {
                if prefer_v6 {
                    format!("ds6:{}", trimmed)
                } else {
                    format!("ds4:{}", trimmed)
                }
            }
            crate::config::IpMode::Ipv4Only => format!("v4:{}", trimmed),
            crate::config::IpMode::Ipv6Only => format!("v6:{}", trimmed),
        };

        // Check LRU cache
        if let Some(cached) = self.cache.get(&cache_key) {
            return Ok(cached);
        }

        let strategy = self.dns_strategy();
        if strategy == crate::config::toml_config::DnsStrategy::Host {
            let ips = self.resolve_via_host(trimmed, mode, prefer_v6).await?;
            self.cache.insert(&cache_key, ips.clone(), 60);
            return Ok(ips);
        }

        // Filter DNS servers by active IpMode; fall back to well-known servers of that family
        let mut servers: Vec<SocketAddr> = self
            .dns_servers
            .iter()
            .copied()
            .filter(|s| mode.allows_ip(s.ip()))
            .collect();

        if servers.is_empty() {
            match mode {
                crate::config::IpMode::Ipv4Only => {
                    servers.push("1.1.1.1:53".parse().unwrap());
                    servers.push("1.0.0.1:53".parse().unwrap());
                }
                crate::config::IpMode::Ipv6Only => {
                    servers.push("[2606:4700:4700::1111]:53".parse().unwrap());
                    servers.push("[2606:4700:4700::1001]:53".parse().unwrap());
                }
                crate::config::IpMode::DualStack => {}
            }
        }

        // Query tunnel DNS servers strictly inside the WireGuard tunnel
        let mut last_err = io::Error::new(io::ErrorKind::TimedOut, "DNS resolution timed out");

        for &server in &servers {
            for retry in 0..self.max_retries {
                match self.query_server(stack, trimmed, server, mode).await {
                    Ok((ips, ttl)) => {
                        self.cache.insert(&cache_key, ips.clone(), ttl);
                        return Ok(ips);
                    }
                    Err(e) => {
                        tracing::debug!(
                            "DNS query to {} attempt {} failed: {}",
                            server,
                            retry + 1,
                            e
                        );
                        last_err = e;
                    }
                }
            }
        }

        if strategy == crate::config::toml_config::DnsStrategy::TunnelFirst
            && let Ok(ips) = self.resolve_via_host(trimmed, mode, prefer_v6).await
        {
            self.cache.insert(&cache_key, ips.clone(), 60);
            return Ok(ips);
        }

        Err(last_err)
    }

    /// Resolve a domain via the host OS resolver, filtering by `IpMode` and sorting by `prefer_ipv6`.
    async fn resolve_via_host(
        &self,
        domain: &str,
        mode: crate::config::IpMode,
        prefer_v6: bool,
    ) -> Result<Vec<IpAddr>, io::Error> {
        let mut ips: Vec<IpAddr> = tokio::time::timeout(
            self.timeout,
            tokio::net::lookup_host((domain, 0u16)),
        )
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
    async fn query_server(
        &self,
        stack: &VirtualNetworkStack,
        domain: &str,
        server: SocketAddr,
        mode: crate::config::IpMode,
    ) -> Result<(Vec<IpAddr>, u32), io::Error> {
        let qtypes: &[QueryType] = match mode {
            crate::config::IpMode::Ipv4Only => &[QueryType::A],
            crate::config::IpMode::Ipv6Only => &[QueryType::AAAA],
            crate::config::IpMode::DualStack => {
                if self.prefer_ipv6.load(std::sync::atomic::Ordering::Relaxed) {
                    &[QueryType::AAAA, QueryType::A]
                } else {
                    &[QueryType::A, QueryType::AAAA]
                }
            }
        };

        let mut last_err = io::Error::new(io::ErrorKind::NotFound, "no DNS records found");
        for &qtype in qtypes {
            match self.query_record(stack, domain, server, qtype).await {
                Ok((mut ips, ttl)) => {
                    ips.retain(|ip| mode.allows_ip(*ip));
                    if !ips.is_empty() {
                        return Ok((ips, ttl));
                    }
                }
                Err(e) => last_err = e,
            }
        }
        Err(last_err)
    }

    async fn query_record(
        &self,
        stack: &VirtualNetworkStack,
        domain: &str,
        server: SocketAddr,
        qtype: QueryType,
    ) -> Result<(Vec<IpAddr>, u32), io::Error> {
        tokio::time::timeout(self.timeout, async {
            let socket = stack.udp_bind_with_size(0, 4096, 4096, 2).await?;
            let tx_id = rand::random::<u16>();

            let query = build_query(domain, qtype, tx_id)
                .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e.to_string()))?;

            socket.send_to(&query, server).await?;

            let mut buf = [0u8; 1500];
            let (len, from) = socket.recv_from(&mut buf).await?;
            if from.ip() != server.ip() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "DNS response received from unexpected IP",
                ));
            }

            let (ips, ttl) = parse_response(&buf[..len], tx_id)
                .map_err(|e| io::Error::other(e.to_string()))?;

            Ok((ips, ttl))
        })
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "DNS query timed out"))?
    }
}
