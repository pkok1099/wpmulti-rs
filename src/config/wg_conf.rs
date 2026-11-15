//! WireGuard Configuration (`.conf`) Parser
//!
//! Implements a robust line-oriented parser for WireGuard INI-style configuration files,
//! supporting dual-stack IPv4/IPv6 addresses, multiple peers, wg-quick directives tolerance,
//! inline and full-line comments (`#` and `;`), and case-insensitive headers and directives.

use base64::prelude::*;
use ipnetwork::IpNetwork;
use std::net::IpAddr;
use std::path::Path;
use x25519_dalek::{PublicKey, StaticSecret};

/// Complete parsed WireGuard configuration.
#[derive(Clone)]
pub struct WgConfig {
    pub interface: WgInterfaceConfig,
    pub peers: Vec<WgPeerConfig>,
}

impl std::fmt::Debug for WgConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WgConfig")
            .field("interface", &self.interface)
            .field("peers", &self.peers)
            .finish()
    }
}

impl std::str::FromStr for WgConfig {
    type Err = WgConfError;

    fn from_str(content: &str) -> Result<Self, Self::Err> {
        let (interface, peers) = parse_wg_conf(content)?;
        Ok(Self { interface, peers })
    }
}

impl WgConfig {
    /// Parse configuration from a filesystem path.
    pub fn from_file<P: AsRef<Path>>(path: P) -> Result<Self, WgConfError> {
        let content = std::fs::read_to_string(path)?;
        content.parse()
    }
}

/// Interface configuration parsed from the `[Interface]` section.
#[derive(Clone)]
pub struct WgInterfaceConfig {
    /// 32-byte Curve25519 private secret key.
    pub private_key: StaticSecret,
    /// Dual-stack client virtual network IP addresses (CIDR).
    pub addresses: Vec<IpNetwork>,
    /// In-tunnel DNS resolver IP addresses.
    pub dns: Vec<IpAddr>,
    /// Optional local UDP listening port.
    pub listen_port: Option<u16>,
    /// Packet Maximum Transmission Unit (defaults to 1420).
    pub mtu: u16,
}

impl std::fmt::Debug for WgInterfaceConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WgInterfaceConfig")
            .field("private_key", &"[REDACTED]")
            .field("addresses", &self.addresses)
            .field("dns", &self.dns)
            .field("listen_port", &self.listen_port)
            .field("mtu", &self.mtu)
            .finish()
    }
}

impl PartialEq for WgInterfaceConfig {
    fn eq(&self, other: &Self) -> bool {
        self.private_key.to_bytes() == other.private_key.to_bytes()
            && self.addresses == other.addresses
            && self.dns == other.dns
            && self.listen_port == other.listen_port
            && self.mtu == other.mtu
    }
}

impl Eq for WgInterfaceConfig {}

/// Peer configuration parsed from a `[Peer]` section.
#[derive(Clone, PartialEq, Eq)]
pub struct WgPeerConfig {
    /// 32-byte Curve25519 remote peer public key.
    pub public_key: PublicKey,
    /// Remote peer endpoint (`host:port`).
    pub endpoint: String,
    /// Allowed IP ranges routed through this peer.
    pub allowed_ips: Vec<IpNetwork>,
    /// Optional 32-byte symmetric pre-shared key.
    pub preshared_key: Option<[u8; 32]>,
    /// Optional NAT keepalive interval in seconds.
    pub persistent_keepalive: Option<u16>,
}

impl std::fmt::Debug for WgPeerConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WgPeerConfig")
            .field("public_key", &self.public_key)
            .field("endpoint", &self.endpoint)
            .field("allowed_ips", &self.allowed_ips)
            .field(
                "preshared_key",
                &self.preshared_key.as_ref().map(|_| "[REDACTED]"),
            )
            .field("persistent_keepalive", &self.persistent_keepalive)
            .finish()
    }
}

/// Errors occurring while parsing WireGuard configuration files.
#[derive(Debug, thiserror::Error)]
pub enum WgConfError {
    #[error("I/O error reading WireGuard configuration: {0}")]
    Io(#[from] std::io::Error),

    #[error("line {line_number}: directive before section header: '{line}'")]
    MissingSectionHeader { line_number: usize, line: String },

    #[error("line {line_number}: malformed line (missing '=' delimiter): '{line}'")]
    MalformedLine { line_number: usize, line: String },

    #[error("line {line_number}: unknown section header '[{section}]'")]
    UnknownSection { line_number: usize, section: String },

    #[error("line {line_number}: duplicate [Interface] section header")]
    DuplicateInterface { line_number: usize },

    #[error("missing required [Interface] section")]
    MissingInterface,

    #[error("[Interface] section is missing required 'PrivateKey'")]
    MissingPrivateKey,

    #[error("line {line_number}: invalid base64 encoding in '{field}': {source}")]
    InvalidBase64Key {
        line_number: usize,
        field: &'static str,
        #[source]
        source: base64::DecodeError,
    },

    #[error(
        "line {line_number}: invalid key length for '{field}': expected {expected} bytes, got {actual}"
    )]
    InvalidKeyLength {
        line_number: usize,
        field: &'static str,
        expected: usize,
        actual: usize,
    },

    #[error("line {line_number}: invalid CIDR network '{value}' in '{field}': {reason}")]
    InvalidCidr {
        line_number: usize,
        field: &'static str,
        value: String,
        reason: String,
    },

    #[error("line {line_number}: invalid DNS address '{value}'")]
    InvalidDnsAddress { line_number: usize, value: String },

    #[error("line {line_number}: invalid port number '{value}' in '{field}'")]
    InvalidPort {
        line_number: usize,
        field: &'static str,
        value: String,
    },

    #[error("line {line_number}: invalid MTU value '{value}'")]
    InvalidMtu { line_number: usize, value: String },

    #[error("line {line_number}: invalid PersistentKeepalive '{value}'")]
    InvalidKeepalive { line_number: usize, value: String },

    #[error("line {line_number}: invalid endpoint '{value}': {reason}")]
    InvalidEndpoint {
        line_number: usize,
        value: String,
        reason: &'static str,
    },

    #[error("peer section at line {line_number} is missing required 'PublicKey'")]
    MissingPeerPublicKey { line_number: usize },

    #[error("peer section at line {line_number} is missing required 'Endpoint'")]
    MissingPeerEndpoint { line_number: usize },

    #[error("no peers configured in WireGuard configuration")]
    NoPeers,
}

#[derive(Default)]
struct InterfaceBuilder {
    private_key: Option<StaticSecret>,
    addresses: Vec<IpNetwork>,
    dns: Vec<IpAddr>,
    listen_port: Option<u16>,
    mtu: Option<u16>,
}

#[derive(Default)]
struct PeerBuilder {
    line_number: usize,
    public_key: Option<PublicKey>,
    endpoint: Option<String>,
    allowed_ips: Vec<IpNetwork>,
    preshared_key: Option<[u8; 32]>,
    persistent_keepalive: Option<u16>,
}

enum CurrentSection {
    None,
    Interface,
    Peer(usize),
}

/// Strip comments (`#` and `;`) and trim whitespace.
/// Full-line comments start with `#` or `;` (after trimming leading whitespace).
/// Inline comments start with `#` or `;` preceded by whitespace.
pub fn strip_comment(line: &str) -> &str {
    let trimmed_start = line.trim_start();
    if trimmed_start.starts_with('#') || trimmed_start.starts_with(';') {
        return "";
    }
    let mut prev_is_ws = false;
    let mut cut_idx = None;
    for (i, c) in line.char_indices() {
        if prev_is_ws && (c == '#' || c == ';') {
            cut_idx = Some(i);
            break;
        }
        prev_is_ws = c.is_whitespace();
    }
    cut_idx
        .and_then(|idx| line.get(..idx))
        .map_or_else(|| line.trim(), str::trim)
}

/// Decode a 32-byte Curve25519 key from Base64 (padded or unpadded).
fn decode_32byte_key(
    val: &str,
    line_number: usize,
    field: &'static str,
) -> Result<[u8; 32], WgConfError> {
    let trimmed = val.trim();
    let bytes = match BASE64_STANDARD.decode(trimmed) {
        Ok(b) => b,
        Err(_) if trimmed.len() == 43 => base64::engine::general_purpose::STANDARD_NO_PAD
            .decode(trimmed)
            .map_err(|e| WgConfError::InvalidBase64Key {
                line_number,
                field,
                source: e,
            })?,
        Err(e) => {
            return Err(WgConfError::InvalidBase64Key {
                line_number,
                field,
                source: e,
            });
        }
    };

    if bytes.len() != 32 {
        return Err(WgConfError::InvalidKeyLength {
            line_number,
            field,
            expected: 32,
            actual: bytes.len(),
        });
    }

    let mut key = [0u8; 32];
    key.copy_from_slice(&bytes);
    Ok(key)
}

/// Parse an IP network CIDR string, auto-appending /32 or /128 if mask is omitted.
fn parse_cidr(s: &str, line_number: usize, field: &'static str) -> Result<IpNetwork, WgConfError> {
    let s = s.trim();
    if s.is_empty() {
        return Err(WgConfError::InvalidCidr {
            line_number,
            field,
            value: s.to_string(),
            reason: "empty address token".to_string(),
        });
    }

    if s.contains('/') {
        s.parse::<IpNetwork>()
            .map_err(|e| WgConfError::InvalidCidr {
                line_number,
                field,
                value: s.to_string(),
                reason: e.to_string(),
            })
    } else {
        let ip: IpAddr =
            s.parse()
                .map_err(|e: std::net::AddrParseError| WgConfError::InvalidCidr {
                    line_number,
                    field,
                    value: s.to_string(),
                    reason: e.to_string(),
                })?;
        match ip {
            IpAddr::V4(v4) => ipnetwork::Ipv4Network::new(v4, 32)
                .map(IpNetwork::V4)
                .map_err(|e| WgConfError::InvalidCidr {
                    line_number,
                    field,
                    value: s.to_string(),
                    reason: e.to_string(),
                }),
            IpAddr::V6(v6) => ipnetwork::Ipv6Network::new(v6, 128)
                .map(IpNetwork::V6)
                .map_err(|e| WgConfError::InvalidCidr {
                    line_number,
                    field,
                    value: s.to_string(),
                    reason: e.to_string(),
                }),
        }
    }
}

/// Validate endpoint format: `<host>:<port>`.
fn validate_endpoint(endpoint: &str, line_number: usize) -> Result<(), WgConfError> {
    let (_host, port_str) = if endpoint.starts_with('[') {
        let closing = endpoint
            .find(']')
            .ok_or_else(|| WgConfError::InvalidEndpoint {
                line_number,
                value: endpoint.to_string(),
                reason: "unclosed bracket in IPv6 endpoint",
            })?;
        let host = &endpoint[1..closing];
        let rest = &endpoint[closing + 1..];
        if !rest.starts_with(':') {
            return Err(WgConfError::InvalidEndpoint {
                line_number,
                value: endpoint.to_string(),
                reason: "missing ':' and port after bracket in IPv6 endpoint",
            });
        }
        let port_str = &rest[1..];
        if host.parse::<std::net::Ipv6Addr>().is_err() {
            return Err(WgConfError::InvalidEndpoint {
                line_number,
                value: endpoint.to_string(),
                reason: "invalid IPv6 address inside brackets",
            });
        }
        (host, port_str)
    } else {
        let mut parts = endpoint.rsplitn(2, ':');
        let port_str = parts.next().ok_or_else(|| WgConfError::InvalidEndpoint {
            line_number,
            value: endpoint.to_string(),
            reason: "missing port in endpoint",
        })?;
        let host = parts.next().ok_or_else(|| WgConfError::InvalidEndpoint {
            line_number,
            value: endpoint.to_string(),
            reason: "missing host in endpoint",
        })?;
        if host.is_empty() {
            return Err(WgConfError::InvalidEndpoint {
                line_number,
                value: endpoint.to_string(),
                reason: "host portion is empty",
            });
        }
        if host.parse::<std::net::Ipv4Addr>().is_err()
            && !host
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-')
        {
            return Err(WgConfError::InvalidEndpoint {
                line_number,
                value: endpoint.to_string(),
                reason: "hostname contains invalid characters",
            });
        }
        (host, port_str)
    };

    let port: u16 = port_str.parse().map_err(|_| WgConfError::InvalidEndpoint {
        line_number,
        value: endpoint.to_string(),
        reason: "port number must be between 1 and 65535",
    })?;
    if port == 0 {
        return Err(WgConfError::InvalidEndpoint {
            line_number,
            value: endpoint.to_string(),
            reason: "port number cannot be 0",
        });
    }
    Ok(())
}

fn apply_interface_kv(
    iface: &mut InterfaceBuilder,
    key: &str,
    val: &str,
    line_number: usize,
) -> Result<(), WgConfError> {
    match key.to_ascii_lowercase().as_str() {
        "privatekey" => {
            let key_bytes = decode_32byte_key(val, line_number, "PrivateKey")?;
            iface.private_key = Some(StaticSecret::from(key_bytes));
        }
        "address" => {
            for token in val.split(',').map(str::trim).filter(|t| !t.is_empty()) {
                iface
                    .addresses
                    .push(parse_cidr(token, line_number, "Address")?);
            }
        }
        "dns" => {
            for token in val.split(',').map(str::trim).filter(|t| !t.is_empty()) {
                if let Ok(ip) = token.parse::<IpAddr>() {
                    iface.dns.push(ip);
                } else {
                    tracing::debug!(line_number, "Ignoring non-IP DNS search domain: {token}");
                }
            }
        }
        "listenport" if !val.is_empty() => {
            let port: u16 = val.parse().map_err(|_| WgConfError::InvalidPort {
                line_number,
                field: "ListenPort",
                value: val.to_string(),
            })?;
            iface.listen_port = if port == 0 { None } else { Some(port) };
        }
        "mtu" => {
            let mtu: u16 = val.parse().map_err(|_| WgConfError::InvalidMtu {
                line_number,
                value: val.to_string(),
            })?;
            if mtu == 0 {
                return Err(WgConfError::InvalidMtu {
                    line_number,
                    value: val.to_string(),
                });
            }
            iface.mtu = Some(mtu);
        }
        "listenport" | "table" | "postup" | "preup" | "postdown" | "predown" | "saveconfig"
        | "fwmark" => {
            tracing::trace!(line_number, "Ignored wg-quick directive {key} = {val}");
        }
        unknown => {
            tracing::debug!(
                line_number,
                "Ignored unrecognized interface key '{unknown}'"
            );
        }
    }
    Ok(())
}

fn apply_peer_kv(
    peer: &mut PeerBuilder,
    key: &str,
    val: &str,
    line_number: usize,
) -> Result<(), WgConfError> {
    match key.to_ascii_lowercase().as_str() {
        "publickey" => {
            let key_bytes = decode_32byte_key(val, line_number, "PublicKey")?;
            peer.public_key = Some(PublicKey::from(key_bytes));
        }
        "endpoint" => {
            validate_endpoint(val, line_number)?;
            peer.endpoint = Some(val.to_string());
        }
        "allowedips" => {
            for token in val.split(',').map(str::trim).filter(|t| !t.is_empty()) {
                peer.allowed_ips
                    .push(parse_cidr(token, line_number, "AllowedIPs")?);
            }
        }
        "presharedkey" => {
            let key_bytes = decode_32byte_key(val, line_number, "PresharedKey")?;
            peer.preshared_key = Some(key_bytes);
        }
        "persistentkeepalive" => {
            let keepalive: u16 = val.parse().map_err(|_| WgConfError::InvalidKeepalive {
                line_number,
                value: val.to_string(),
            })?;
            peer.persistent_keepalive = Some(keepalive);
        }
        unknown => {
            tracing::debug!(line_number, "Ignored unrecognized peer key '{unknown}'");
        }
    }
    Ok(())
}

/// Parse a WireGuard configuration file from a string slice.
/// Returns the parsed `WgInterfaceConfig` and list of `WgPeerConfig`.
pub fn parse_wg_conf(content: &str) -> Result<(WgInterfaceConfig, Vec<WgPeerConfig>), WgConfError> {
    let mut iface_builder: Option<InterfaceBuilder> = None;
    let mut peer_builders: Vec<PeerBuilder> = Vec::new();
    let mut current_section = CurrentSection::None;

    for (idx, raw_line) in content.lines().enumerate() {
        let line_number = idx + 1;
        let line = strip_comment(raw_line);
        if line.is_empty() {
            continue;
        }

        if line.starts_with('[') && line.ends_with(']') {
            let header = line[1..line.len() - 1].trim();
            if header.eq_ignore_ascii_case("interface") {
                if iface_builder.is_some() {
                    return Err(WgConfError::DuplicateInterface { line_number });
                }
                iface_builder = Some(InterfaceBuilder::default());
                current_section = CurrentSection::Interface;
            } else if header.eq_ignore_ascii_case("peer") {
                peer_builders.push(PeerBuilder {
                    line_number,
                    ..Default::default()
                });
                current_section = CurrentSection::Peer(peer_builders.len() - 1);
            } else {
                return Err(WgConfError::UnknownSection {
                    line_number,
                    section: header.to_string(),
                });
            }
            continue;
        }

        let Some((k, v)) = line.split_once('=') else {
            return Err(WgConfError::MalformedLine {
                line_number,
                line: line.to_string(),
            });
        };
        let (key, val) = (k.trim(), v.trim());

        match current_section {
            CurrentSection::None => {
                return Err(WgConfError::MissingSectionHeader {
                    line_number,
                    line: line.to_string(),
                });
            }
            CurrentSection::Interface => {
                let Some(iface) = iface_builder.as_mut() else {
                    return Err(WgConfError::MissingInterface);
                };
                apply_interface_kv(iface, key, val, line_number)?;
            }
            CurrentSection::Peer(idx) => {
                let Some(peer) = peer_builders.get_mut(idx) else {
                    return Err(WgConfError::MissingInterface);
                };
                apply_peer_kv(peer, key, val, line_number)?;
            }
        }
    }

    let iface = iface_builder.ok_or(WgConfError::MissingInterface)?;
    let private_key = iface.private_key.ok_or(WgConfError::MissingPrivateKey)?;
    let interface_config = WgInterfaceConfig {
        private_key,
        addresses: iface.addresses,
        dns: iface.dns,
        listen_port: iface.listen_port,
        mtu: iface.mtu.unwrap_or(1420),
    };

    if peer_builders.is_empty() {
        return Err(WgConfError::NoPeers);
    }
    let mut peers = Vec::with_capacity(peer_builders.len());
    for pb in peer_builders {
        let public_key = pb.public_key.ok_or(WgConfError::MissingPeerPublicKey {
            line_number: pb.line_number,
        })?;
        let endpoint = pb.endpoint.ok_or(WgConfError::MissingPeerEndpoint {
            line_number: pb.line_number,
        })?;
        peers.push(WgPeerConfig {
            public_key,
            endpoint,
            allowed_ips: pb.allowed_ips,
            preshared_key: pb.preshared_key,
            persistent_keepalive: pb.persistent_keepalive,
        });
    }

    Ok((interface_config, peers))
}

/// Parse a WireGuard configuration file from a filesystem path.
pub fn parse_wg_conf_file<P: AsRef<Path>>(
    path: P,
) -> Result<(WgInterfaceConfig, Vec<WgPeerConfig>), WgConfError> {
    let content = std::fs::read_to_string(path.as_ref())?;
    parse_wg_conf(&content)
}
