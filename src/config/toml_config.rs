//! Main Configuration Schema (`wpmulti.toml`)
//!
//! Provides Serde data structures, sensible defaults, duration parsers,
//! and validation logic for `wpmulti`.

use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::{Path, PathBuf};
use std::time::Duration;
use thiserror::Error;

/// Configuration errors encountered during deserialization or validation.
#[derive(Debug, Error)]
pub enum ConfigError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Failed to parse TOML configuration: {0}")]
    TomlParse(#[from] toml::de::Error),

    #[error("WireGuard config error: {0}")]
    WgConf(String),

    #[error("Invalid tunnel ID: {0}")]
    InvalidTunnelId(String),

    #[error("Duplicate tunnel ID '{id}': found in '{file1}' and '{file2}'")]
    DuplicateTunnelId {
        id: String,
        file1: PathBuf,
        file2: PathBuf,
    },

    #[error("Directory not found: {0}")]
    DirectoryNotFound(PathBuf),

    #[error("Configuration validation error: {0}")]
    Validation(String),
}

/// Helper to parse human-readable durations like "5m", "10s", "500ms", "1h", "300".
pub fn parse_duration_str(s: &str) -> Result<Duration, String> {
    let s = s.trim();
    if s.is_empty() {
        return Err("Duration string cannot be empty".to_string());
    }

    if let Ok(secs) = s.parse::<u64>() {
        return Ok(Duration::from_secs(secs));
    }

    if let Some(rest) = s.strip_suffix("ms") {
        let v: u64 = rest
            .trim()
            .parse()
            .map_err(|e| format!("Invalid ms duration: {e}"))?;
        return Ok(Duration::from_millis(v));
    }
    if let Some(rest) = s.strip_suffix('s') {
        let v: u64 = rest
            .trim()
            .parse()
            .map_err(|e| format!("Invalid s duration: {e}"))?;
        return Ok(Duration::from_secs(v));
    }
    if let Some(rest) = s.strip_suffix('m') {
        let v: u64 = rest
            .trim()
            .parse()
            .map_err(|e| format!("Invalid m duration: {e}"))?;
        let secs = v
            .checked_mul(60)
            .ok_or_else(|| format!("Duration overflow: '{s}'"))?;
        return Ok(Duration::from_secs(secs));
    }
    if let Some(rest) = s.strip_suffix('h') {
        let v: u64 = rest
            .trim()
            .parse()
            .map_err(|e| format!("Invalid h duration: {e}"))?;
        let secs = v
            .checked_mul(3600)
            .ok_or_else(|| format!("Duration overflow: '{s}'"))?;
        return Ok(Duration::from_secs(secs));
    }
    if let Some(rest) = s.strip_suffix('d') {
        let v: u64 = rest
            .trim()
            .parse()
            .map_err(|e| format!("Invalid d duration: {e}"))?;
        let secs = v
            .checked_mul(86400)
            .ok_or_else(|| format!("Duration overflow: '{s}'"))?;
        return Ok(Duration::from_secs(secs));
    }

    Err(format!(
        "Unsupported duration format: '{s}' (supported: ms, s, m, h, d)"
    ))
}

/// Serde module for Duration strings or integer seconds.
pub mod duration_str_serde {
    use super::{Deserialize, Deserializer, Duration, Serializer, parse_duration_str};

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Duration, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(untagged)]
        enum DurationHelper {
            Str(String),
            Secs(u64),
        }

        match DurationHelper::deserialize(deserializer)? {
            DurationHelper::Str(s) => parse_duration_str(&s).map_err(serde::de::Error::custom),
            DurationHelper::Secs(secs) => Ok(Duration::from_secs(secs)),
        }
    }

    pub fn serialize<S>(duration: &Duration, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let secs = duration.as_secs();
        if duration.subsec_millis() > 0 {
            serializer.serialize_str(&format!("{}ms", duration.as_millis()))
        } else if secs.is_multiple_of(3600) && secs > 0 {
            serializer.serialize_str(&format!("{}h", secs / 3600))
        } else if secs.is_multiple_of(60) && secs > 0 {
            serializer.serialize_str(&format!("{}m", secs / 60))
        } else {
            serializer.serialize_str(&format!("{secs}s"))
        }
    }
}

/// Logging level configuration.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum LogLevel {
    Trace,
    Debug,
    #[default]
    Info,
    Warn,
    Error,
}

/// In-tunnel DNS resolution strategy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum DnsStrategy {
    #[default]
    TunnelOnly,
    TunnelFirst,
    Host,
}

/// IP address family preference when resolving dual-stack domains.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum DnsPreference {
    #[default]
    Ipv4First,
    Ipv6First,
}

/// Strict IP family isolation mode for tunnel traffic and DNS.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum IpMode {
    #[default]
    DualStack,
    Ipv4Only,
    Ipv6Only,
}

impl IpMode {
    /// Returns true if the given IP address is permitted under this mode.
    pub const fn allows_ip(self, ip: IpAddr) -> bool {
        match self {
            Self::DualStack => true,
            Self::Ipv4Only => ip.is_ipv4(),
            Self::Ipv6Only => ip.is_ipv6(),
        }
    }

    /// Validate that `ip` is permitted under this mode, returning `AddrNotAvailable` otherwise.
    pub fn check_ip(self, ip: IpAddr, context: &str) -> std::io::Result<()> {
        if self.allows_ip(ip) {
            Ok(())
        } else {
            Err(std::io::Error::new(
                std::io::ErrorKind::AddrNotAvailable,
                format!("{context} {ip} blocked by ip_mode {self:?}"),
            ))
        }
    }

    /// Encode this mode into a compact `u8` representation for atomic storage.
    pub const fn to_u8(self) -> u8 {
        match self {
            Self::DualStack => 0,
            Self::Ipv4Only => 1,
            Self::Ipv6Only => 2,
        }
    }

    /// Decode a `u8` representation back into [`IpMode`].
    pub const fn from_u8(code: u8) -> Self {
        match code {
            1 => Self::Ipv4Only,
            2 => Self::Ipv6Only,
            _ => Self::DualStack,
        }
    }

    /// Combine a listener-level override with the global `IpMode`.
    /// Rejects contradictory strict modes (e.g. global `ipv4_only` + listener `ipv6_only`).
    pub fn effective_with_global(
        listener_override: Option<Self>,
        global: Self,
    ) -> Result<Self, String> {
        match (global, listener_override) {
            (g, None) => Ok(g),
            (Self::DualStack, Some(l)) => Ok(l),
            (Self::Ipv4Only, Some(Self::Ipv4Only)) => Ok(Self::Ipv4Only),
            (Self::Ipv6Only, Some(Self::Ipv6Only)) => Ok(Self::Ipv6Only),
            (Self::Ipv4Only, Some(Self::DualStack)) => Err(
                "listener ip_mode 'dual_stack' cannot loosen global ip_mode 'ipv4_only'"
                    .to_string(),
            ),
            (Self::Ipv6Only, Some(Self::DualStack)) => Err(
                "listener ip_mode 'dual_stack' cannot loosen global ip_mode 'ipv6_only'"
                    .to_string(),
            ),
            (Self::Ipv4Only, Some(Self::Ipv6Only)) => Err(
                "listener ip_mode 'ipv6_only' conflicts with global ip_mode 'ipv4_only'"
                    .to_string(),
            ),
            (Self::Ipv6Only, Some(Self::Ipv4Only)) => Err(
                "listener ip_mode 'ipv4_only' conflicts with global ip_mode 'ipv6_only'"
                    .to_string(),
            ),
        }
    }
}

/// Tunnel lifecycle mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum LifecycleMode {
    #[default]
    Lazy,
    Eager,
}

/// Shared listener proxy type.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum ListenerType {
    #[default]
    Socks5,
    Http,
}

/// Authentication mode for shared port listeners.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum AuthMode {
    #[default]
    None,
    Global,
    PerTunnel,
}

/// Routing strategy for multi-tunnel pools.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "kebab-case")]
pub enum PoolStrategy {
    #[default]
    RoundRobin,
    Random,
    LeastConn,
    Fallback,
}

/// TUI dashboard sort criteria.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum TuiSortField {
    #[default]
    Id,
    Status,
    Conns,
    Rx,
    Tx,
}

/// Selection of tunnels participating in a shared listener pool.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub enum TunnelPoolSelection {
    #[default]
    All,
    Selected(Vec<String>),
}

impl<'de> Deserialize<'de> for TunnelPoolSelection {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(untagged)]
        enum PoolHelper {
            Str(String),
            List(Vec<String>),
        }

        match PoolHelper::deserialize(deserializer)? {
            PoolHelper::Str(s) => {
                if s.eq_ignore_ascii_case("all") {
                    Ok(Self::All)
                } else {
                    Ok(Self::Selected(vec![s]))
                }
            }
            PoolHelper::List(list) => Ok(Self::Selected(list)),
        }
    }
}

impl Serialize for TunnelPoolSelection {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match self {
            Self::All => serializer.serialize_str("all"),
            Self::Selected(list) => list.serialize(serializer),
        }
    }
}

/// Global settings section `[global]`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GlobalSettings {
    #[serde(default = "default_config_dir")]
    pub config_dir: PathBuf,

    #[serde(default = "default_bind_address")]
    pub bind_address: IpAddr,

    #[serde(default)]
    pub log_level: LogLevel,

    #[serde(default = "default_dns_fallback")]
    pub dns_fallback: SocketAddr,

    #[serde(default)]
    pub dns_strategy: DnsStrategy,

    #[serde(default)]
    pub dns_preference: DnsPreference,

    #[serde(default)]
    pub ip_mode: IpMode,

    #[serde(default = "default_max_active_tunnels")]
    pub max_active_tunnels: usize,
}

fn default_config_dir() -> PathBuf {
    PathBuf::from("/etc/wpmulti/conf.d")
}

const fn default_bind_address() -> IpAddr {
    IpAddr::V4(Ipv4Addr::LOCALHOST)
}

const fn default_dns_fallback() -> SocketAddr {
    SocketAddr::new(IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)), 53)
}

const fn default_max_active_tunnels() -> usize {
    1000
}

impl Default for GlobalSettings {
    fn default() -> Self {
        Self {
            config_dir: default_config_dir(),
            bind_address: default_bind_address(),
            log_level: LogLevel::default(),
            dns_fallback: default_dns_fallback(),
            dns_strategy: DnsStrategy::default(),
            dns_preference: DnsPreference::default(),
            ip_mode: IpMode::default(),
            max_active_tunnels: default_max_active_tunnels(),
        }
    }
}

/// Lifecycle section `[lifecycle]`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LifecycleSettings {
    #[serde(default)]
    pub mode: LifecycleMode,

    #[serde(default = "default_idle_timeout", with = "duration_str_serde")]
    pub idle_timeout: Duration,

    #[serde(default = "default_handshake_timeout", with = "duration_str_serde")]
    pub handshake_timeout: Duration,

    #[serde(default)]
    pub eager_tunnels: Vec<String>,
}

const fn default_idle_timeout() -> Duration {
    Duration::from_mins(5)
}

const fn default_handshake_timeout() -> Duration {
    Duration::from_secs(10)
}

impl Default for LifecycleSettings {
    fn default() -> Self {
        Self {
            mode: LifecycleMode::default(),
            idle_timeout: default_idle_timeout(),
            handshake_timeout: default_handshake_timeout(),
            eager_tunnels: Vec::new(),
        }
    }
}

/// Explicit port and credential overrides for specific tunnel IDs.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct TunnelPortOverride {
    #[serde(default)]
    pub socks5_port: Option<u16>,

    #[serde(default)]
    pub http_port: Option<u16>,

    #[serde(default)]
    pub password: Option<String>,
}

impl std::fmt::Debug for TunnelPortOverride {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TunnelPortOverride")
            .field("socks5_port", &self.socks5_port)
            .field("http_port", &self.http_port)
            .field("password", &self.password.as_ref().map(|_| "[REDACTED]"))
            .finish()
    }
}

/// Per-tunnel dedicated port configuration `[per_tunnel]`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PerTunnelSettings {
    #[serde(default = "default_true")]
    pub enabled: bool,

    #[serde(default = "default_base_socks5_port")]
    pub base_socks5_port: Option<u16>,

    #[serde(default = "default_base_http_port")]
    pub base_http_port: Option<u16>,

    #[serde(default)]
    pub overrides: HashMap<String, TunnelPortOverride>,
}

const fn default_true() -> bool {
    true
}

// `#[serde(default = "...")]` requires returning the exact `Option<u16>` field type.
#[allow(clippy::unnecessary_wraps)]
const fn default_base_socks5_port() -> Option<u16> {
    Some(10000)
}

// `#[serde(default = "...")]` requires returning the exact `Option<u16>` field type.
#[allow(clippy::unnecessary_wraps)]
const fn default_base_http_port() -> Option<u16> {
    Some(20000)
}

impl Default for PerTunnelSettings {
    fn default() -> Self {
        Self {
            enabled: true,
            base_socks5_port: default_base_socks5_port(),
            base_http_port: default_base_http_port(),
            overrides: HashMap::new(),
        }
    }
}

/// Shared listener section `[[shared_listener]]`.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SharedListenerSettings {
    pub name: String,

    #[serde(rename = "type", default)]
    pub listener_type: ListenerType,

    pub bind: SocketAddr,

    #[serde(default)]
    pub auth_mode: AuthMode,

    #[serde(default)]
    pub global_password: Option<String>,

    #[serde(default)]
    pub default_strategy: PoolStrategy,

    #[serde(default = "default_false")]
    pub allow_anonymous: bool,

    #[serde(default)]
    pub pool: TunnelPoolSelection,

    #[serde(default)]
    pub ip_mode: Option<IpMode>,
}

impl std::fmt::Debug for SharedListenerSettings {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SharedListenerSettings")
            .field("name", &self.name)
            .field("listener_type", &self.listener_type)
            .field("bind", &self.bind)
            .field("auth_mode", &self.auth_mode)
            .field(
                "global_password",
                &self.global_password.as_ref().map(|_| "[REDACTED]"),
            )
            .field("default_strategy", &self.default_strategy)
            .field("allow_anonymous", &self.allow_anonymous)
            .field("pool", &self.pool)
            .field("ip_mode", &self.ip_mode)
            .finish()
    }
}

const fn default_false() -> bool {
    false
}

/// Admin HTTP REST API section `[admin]`.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AdminSettings {
    #[serde(default = "default_false")]
    pub enabled: bool,

    #[serde(default = "default_admin_bind")]
    pub bind: SocketAddr,

    #[serde(default)]
    pub auth_token: Option<String>,
}

impl std::fmt::Debug for AdminSettings {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AdminSettings")
            .field("enabled", &self.enabled)
            .field("bind", &self.bind)
            .field(
                "auth_token",
                &self.auth_token.as_ref().map(|_| "[REDACTED]"),
            )
            .finish()
    }
}

const fn default_admin_bind() -> SocketAddr {
    SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 9090)
}

impl Default for AdminSettings {
    fn default() -> Self {
        Self {
            enabled: false,
            bind: default_admin_bind(),
            auth_token: None,
        }
    }
}

/// TUI Monitor dashboard section `[tui]`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TuiSettings {
    #[serde(default = "default_refresh_rate_ms")]
    pub refresh_rate_ms: u64,

    #[serde(default)]
    pub default_sort: TuiSortField,
}

const fn default_refresh_rate_ms() -> u64 {
    500
}

impl Default for TuiSettings {
    fn default() -> Self {
        Self {
            refresh_rate_ms: default_refresh_rate_ms(),
            default_sort: TuiSortField::default(),
        }
    }
}

/// Health check configuration `[health_check]`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HealthCheckSettings {
    #[serde(default = "default_failure_threshold")]
    pub threshold: usize,

    #[serde(default = "default_cooldown", with = "duration_str_serde")]
    pub cooldown: Duration,

    #[serde(default = "default_probe_interval", with = "duration_str_serde")]
    pub probe_interval: Duration,

    #[serde(default = "default_probe_timeout", with = "duration_str_serde")]
    pub probe_timeout: Duration,
}

const fn default_failure_threshold() -> usize {
    3
}

const fn default_cooldown() -> Duration {
    Duration::from_secs(30)
}

const fn default_probe_interval() -> Duration {
    Duration::from_secs(30)
}

const fn default_probe_timeout() -> Duration {
    Duration::from_secs(5)
}

impl Default for HealthCheckSettings {
    fn default() -> Self {
        Self {
            threshold: default_failure_threshold(),
            cooldown: default_cooldown(),
            probe_interval: default_probe_interval(),
            probe_timeout: default_probe_timeout(),
        }
    }
}

/// Main application configuration structure.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct MainConfig {
    #[serde(default)]
    pub global: GlobalSettings,

    #[serde(default)]
    pub lifecycle: LifecycleSettings,

    #[serde(default)]
    pub per_tunnel: PerTunnelSettings,

    #[serde(default, rename = "shared_listener", alias = "shared_listeners")]
    pub shared_listeners: Vec<SharedListenerSettings>,

    #[serde(default)]
    pub admin: AdminSettings,

    #[serde(default)]
    pub tui: TuiSettings,

    #[serde(default)]
    pub health_check: HealthCheckSettings,

    /// Persisted list of disabled tunnel IDs (excluded from routing and probing).
    #[serde(default)]
    pub disabled_tunnels: Vec<String>,
}

impl MainConfig {
    /// Parse and validate configuration from a TOML string.
    pub fn from_toml_str(s: &str) -> Result<Self, ConfigError> {
        let config: Self = toml::from_str(s)?;
        config.validate()?;
        Ok(config)
    }

    /// Load and validate configuration from a file path.
    pub fn from_file<P: AsRef<Path>>(path: P) -> Result<Self, ConfigError> {
        let content = std::fs::read_to_string(path)?;
        Self::from_toml_str(&content)
    }

    fn validate_shared_listeners(&self) -> Result<(), ConfigError> {
        let mut listener_names = HashSet::new();
        let mut bound_addrs: Vec<SocketAddr> = Vec::new();

        self.validate_admin_bind(&mut bound_addrs)?;

        for listener in &self.shared_listeners {
            if listener.name.trim().is_empty() {
                return Err(ConfigError::Validation(
                    "shared_listener name cannot be empty".into(),
                ));
            }
            if !listener_names.insert(&listener.name) {
                return Err(ConfigError::Validation(format!(
                    "Duplicate shared_listener name: '{}'",
                    listener.name
                )));
            }
            if listener.bind.port() == 0 {
                return Err(ConfigError::Validation(format!(
                    "shared_listener '{}' cannot bind to port 0",
                    listener.name
                )));
            }
            if Self::bind_conflicts(&bound_addrs, listener.bind) {
                return Err(ConfigError::Validation(format!(
                    "Port conflict: shared_listener '{}' bind address '{}' is already in use",
                    listener.name, listener.bind
                )));
            }
            bound_addrs.push(listener.bind);
            if let Err(msg) = IpMode::effective_with_global(listener.ip_mode, self.global.ip_mode) {
                return Err(ConfigError::Validation(format!(
                    "shared_listener '{}': {}",
                    listener.name, msg
                )));
            }
            self.validate_listener_auth(listener)?;
        }
        Ok(())
    }

    /// Validate the admin bind address (when enabled) and reserve it for conflict checks.
    fn validate_admin_bind(&self, bound_addrs: &mut Vec<SocketAddr>) -> Result<(), ConfigError> {
        if !self.admin.enabled {
            return Ok(());
        }
        if self.admin.bind.port() == 0 {
            return Err(ConfigError::Validation(
                "admin.bind cannot use port 0 when admin is enabled".into(),
            ));
        }
        if self.admin.auth_token.as_deref() == Some("") {
            return Err(ConfigError::Validation(
                "admin.auth_token cannot be an empty string".into(),
            ));
        }
        if !self.admin.bind.ip().is_loopback()
            && self.admin.auth_token.as_deref().is_none_or(str::is_empty)
        {
            return Err(ConfigError::Validation(
                "admin.auth_token is required when admin.bind is not a loopback address".into(),
            ));
        }
        bound_addrs.push(self.admin.bind);
        Ok(())
    }

    /// Validate the auth settings of one shared listener.
    fn validate_listener_auth(&self, listener: &SharedListenerSettings) -> Result<(), ConfigError> {
        if listener.auth_mode == AuthMode::Global {
            match &listener.global_password {
                Some(pwd) if !pwd.is_empty() => {}
                _ => {
                    return Err(ConfigError::Validation(format!(
                        "shared_listener '{}' specifies auth_mode = 'global' but global_password is missing or empty",
                        listener.name
                    )));
                }
            }
        }
        if listener.auth_mode == AuthMode::PerTunnel {
            self.validate_per_tunnel_auth(listener)?;
        }
        Ok(())
    }

    /// Validate `per_tunnel` auth: a password must exist somewhere unless anonymous is allowed.
    fn validate_per_tunnel_auth(
        &self,
        listener: &SharedListenerSettings,
    ) -> Result<(), ConfigError> {
        if let Some(pwd) = &listener.global_password
            && pwd.is_empty()
        {
            return Err(ConfigError::Validation(format!(
                "shared_listener '{}' specifies empty global_password",
                listener.name
            )));
        }
        let has_global = listener
            .global_password
            .as_ref()
            .is_some_and(|p| !p.is_empty());
        let has_override = self
            .per_tunnel
            .overrides
            .values()
            .any(|o| o.password.as_ref().is_some_and(|p| !p.is_empty()));
        if !has_global && !has_override && !listener.allow_anonymous {
            return Err(ConfigError::Validation(format!(
                "shared_listener '{}' specifies auth_mode = 'per_tunnel' but neither global_password nor any per_tunnel.overrides.<id>.password is configured",
                listener.name
            )));
        }
        Ok(())
    }

    fn validate_per_tunnel(&self) -> Result<(), ConfigError> {
        for (id, override_cfg) in &self.per_tunnel.overrides {
            if let Some(pwd) = &override_cfg.password
                && pwd.is_empty()
            {
                return Err(ConfigError::Validation(format!(
                    "Override password for tunnel '{id}' cannot be empty"
                )));
            }
        }

        if !self.per_tunnel.enabled {
            return Ok(());
        }

        if let Some(s5) = self.per_tunnel.base_socks5_port
            && s5 == 0
        {
            return Err(ConfigError::Validation(
                "per_tunnel.base_socks5_port cannot be 0".into(),
            ));
        }
        if let Some(http) = self.per_tunnel.base_http_port
            && http == 0
        {
            return Err(ConfigError::Validation(
                "per_tunnel.base_http_port cannot be 0".into(),
            ));
        }
        if let (Some(s5), Some(http)) = (
            self.per_tunnel.base_socks5_port,
            self.per_tunnel.base_http_port,
        ) && s5 == http
        {
            return Err(ConfigError::Validation(
                "per_tunnel.base_socks5_port and base_http_port cannot be identical".into(),
            ));
        }
        let mut override_ports = HashSet::new();
        for (id, override_port) in &self.per_tunnel.overrides {
            if let Some(p) = override_port.socks5_port {
                if p == 0 {
                    return Err(ConfigError::Validation(format!(
                        "Override socks5_port for tunnel '{id}' cannot be 0"
                    )));
                }
                if !override_ports.insert(p) {
                    return Err(ConfigError::Validation(format!(
                        "Override port {p} for tunnel '{id}' conflicts with another override port"
                    )));
                }
            }
            if let Some(p) = override_port.http_port {
                if p == 0 {
                    return Err(ConfigError::Validation(format!(
                        "Override http_port for tunnel '{id}' cannot be 0"
                    )));
                }
                if !override_ports.insert(p) {
                    return Err(ConfigError::Validation(format!(
                        "Override port {p} for tunnel '{id}' conflicts with another override port"
                    )));
                }
            }
        }
        Ok(())
    }

    fn ips_overlap(a: IpAddr, b: IpAddr) -> bool {
        a == b || (a.is_ipv4() == b.is_ipv4() && (a.is_unspecified() || b.is_unspecified()))
    }

    /// True when `bind` would clash with an already-reserved address (same port and
    /// same, wildcard, or overlapping IP).
    fn bind_conflicts(bound_addrs: &[SocketAddr], bind: SocketAddr) -> bool {
        bound_addrs.iter().any(|existing| {
            existing.port() == bind.port()
                && (existing.ip() == bind.ip()
                    || existing.ip().is_unspecified()
                    || bind.ip().is_unspecified())
        })
    }

    fn validate_port_conflicts(&self) -> Result<(), ConfigError> {
        for (i, a) in self.shared_listeners.iter().enumerate() {
            let port_a = a.bind.port();
            if port_a == 0 {
                continue;
            }
            for b in self.shared_listeners.iter().skip(i + 1) {
                if b.bind.port() == port_a && Self::ips_overlap(a.bind.ip(), b.bind.ip()) {
                    return Err(ConfigError::Validation(format!(
                        "shared_listener '{}' ({}) conflicts with shared_listener '{}' ({})",
                        a.name, a.bind, b.name, b.bind
                    )));
                }
            }
            if self.admin.enabled
                && self.admin.bind.port() == port_a
                && Self::ips_overlap(a.bind.ip(), self.admin.bind.ip())
            {
                return Err(ConfigError::Validation(format!(
                    "shared_listener '{}' ({}) conflicts with admin.bind ({})",
                    a.name, a.bind, self.admin.bind
                )));
            }
        }

        if !self.per_tunnel.enabled {
            return Ok(());
        }

        let ded_ip = self.global.bind_address;
        for (label, port_opt) in [
            (
                "per_tunnel.base_socks5_port",
                self.per_tunnel.base_socks5_port,
            ),
            ("per_tunnel.base_http_port", self.per_tunnel.base_http_port),
        ] {
            let Some(port) = port_opt else {
                continue;
            };
            self.check_dedicated_port_against_listeners(label, ded_ip, port)?;
        }

        for (id, ovr) in &self.per_tunnel.overrides {
            for (kind, port_opt) in [
                ("socks5_port", ovr.socks5_port),
                ("http_port", ovr.http_port),
            ] {
                let Some(port) = port_opt else {
                    continue;
                };
                let label = format!("per_tunnel.overrides.{id}.{kind}");
                self.check_dedicated_port_against_listeners(&label, ded_ip, port)?;
            }
        }
        Ok(())
    }

    fn check_dedicated_port_against_listeners(
        &self,
        label: &str,
        ded_ip: IpAddr,
        port: u16,
    ) -> Result<(), ConfigError> {
        for shared in &self.shared_listeners {
            if shared.bind.port() == port && Self::ips_overlap(ded_ip, shared.bind.ip()) {
                return Err(ConfigError::Validation(format!(
                    "{label} ({ded_ip}:{port}) conflicts with shared_listener '{}' ({})",
                    shared.name, shared.bind
                )));
            }
        }
        if self.admin.enabled
            && self.admin.bind.port() == port
            && Self::ips_overlap(ded_ip, self.admin.bind.ip())
        {
            return Err(ConfigError::Validation(format!(
                "{label} ({ded_ip}:{port}) conflicts with admin.bind ({})",
                self.admin.bind
            )));
        }
        Ok(())
    }

    /// Perform comprehensive validation of configuration invariants.
    pub fn validate(&self) -> Result<(), ConfigError> {
        if self.global.max_active_tunnels == 0 {
            return Err(ConfigError::Validation(
                "global.max_active_tunnels must be greater than 0".into(),
            ));
        }
        if self.lifecycle.handshake_timeout.is_zero() {
            return Err(ConfigError::Validation(
                "lifecycle.handshake_timeout must be greater than 0".into(),
            ));
        }

        self.validate_shared_listeners()?;
        self.validate_per_tunnel()?;
        self.validate_port_conflicts()?;

        if self.tui.refresh_rate_ms < 50 {
            return Err(ConfigError::Validation(
                "tui.refresh_rate_ms must be at least 50 ms".into(),
            ));
        }
        if self.health_check.threshold == 0 {
            return Err(ConfigError::Validation(
                "health_check.threshold must be greater than 0".into(),
            ));
        }
        if self.health_check.cooldown.is_zero() {
            return Err(ConfigError::Validation(
                "health_check.cooldown must be greater than 0".into(),
            ));
        }
        if self.health_check.probe_interval.is_zero() {
            return Err(ConfigError::Validation(
                "health_check.probe_interval must be greater than 0".into(),
            ));
        }
        if self.health_check.probe_timeout.is_zero() {
            return Err(ConfigError::Validation(
                "health_check.probe_timeout must be greater than 0".into(),
            ));
        }

        Ok(())
    }
}

/// Returns `true` when `val` is empty or matches a redaction sentinel placeholder
/// (`[REDACTED]`, `[SET]`, `[KEEP]`, etc.) that must not overwrite stored secrets.
pub fn is_redacted_secret_placeholder(val: &str) -> bool {
    let trimmed = val.trim();
    trimmed.is_empty()
        || trimmed.eq_ignore_ascii_case("[REDACTED]")
        || trimmed.eq_ignore_ascii_case("[SET]")
        || trimmed.eq_ignore_ascii_case("[KEEP]")
        || trimmed.eq_ignore_ascii_case("***REDACTED***")
        || trimmed.eq_ignore_ascii_case("<redacted>")
        || trimmed == "***"
}
