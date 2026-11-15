//! Main Configuration Schema (`wpmulti.toml`)
//!
//! Provides Serde data structures, sensible defaults, duration parsers,
//! and validation logic for `wpmulti`.

use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::{Path, PathBuf};
use std::time::Duration;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
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
        let v: u64 = rest.trim().parse().map_err(|e| format!("Invalid ms duration: {e}"))?;
        return Ok(Duration::from_millis(v));
    }
    if let Some(rest) = s.strip_suffix('s') {
        let v: u64 = rest.trim().parse().map_err(|e| format!("Invalid s duration: {e}"))?;
        return Ok(Duration::from_secs(v));
    }
    if let Some(rest) = s.strip_suffix('m') {
        let v: u64 = rest.trim().parse().map_err(|e| format!("Invalid m duration: {e}"))?;
        return Ok(Duration::from_secs(v * 60));
    }
    if let Some(rest) = s.strip_suffix('h') {
        let v: u64 = rest.trim().parse().map_err(|e| format!("Invalid h duration: {e}"))?;
        return Ok(Duration::from_secs(v * 3600));
    }
    if let Some(rest) = s.strip_suffix('d') {
        let v: u64 = rest.trim().parse().map_err(|e| format!("Invalid d duration: {e}"))?;
        return Ok(Duration::from_secs(v * 86400));
    }

    Err(format!("Unsupported duration format: '{s}' (supported: ms, s, m, h, d)"))
}

/// Serde module for Duration strings or integer seconds.
pub mod duration_str_serde {
    use super::*;

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
        } else if secs % 3600 == 0 && secs > 0 {
            serializer.serialize_str(&format!("{}h", secs / 3600))
        } else if secs % 60 == 0 && secs > 0 {
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
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TunnelPoolSelection {
    All,
    Selected(Vec<String>),
}

impl Default for TunnelPoolSelection {
    fn default() -> Self {
        TunnelPoolSelection::All
    }
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
                    Ok(TunnelPoolSelection::All)
                } else {
                    Ok(TunnelPoolSelection::Selected(vec![s]))
                }
            }
            PoolHelper::List(list) => Ok(TunnelPoolSelection::Selected(list)),
        }
    }
}

impl Serialize for TunnelPoolSelection {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match self {
            TunnelPoolSelection::All => serializer.serialize_str("all"),
            TunnelPoolSelection::Selected(list) => list.serialize(serializer),
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

    #[serde(default = "default_max_active_tunnels")]
    pub max_active_tunnels: usize,
}

fn default_config_dir() -> PathBuf {
    PathBuf::from("/etc/wpmulti/conf.d")
}

fn default_bind_address() -> IpAddr {
    IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1))
}

fn default_dns_fallback() -> SocketAddr {
    "1.1.1.1:53".parse().expect("valid socket addr")
}

fn default_max_active_tunnels() -> usize {
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

fn default_idle_timeout() -> Duration {
    Duration::from_secs(300)
}

fn default_handshake_timeout() -> Duration {
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

/// Explicit port overrides for specific tunnel IDs.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct TunnelPortOverride {
    #[serde(default)]
    pub socks5_port: Option<u16>,

    #[serde(default)]
    pub http_port: Option<u16>,
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

fn default_true() -> bool {
    true
}

fn default_base_socks5_port() -> Option<u16> {
    Some(10000)
}

fn default_base_http_port() -> Option<u16> {
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
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
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
}

fn default_false() -> bool {
    false
}

/// Admin HTTP REST API section `[admin]`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AdminSettings {
    #[serde(default = "default_false")]
    pub enabled: bool,

    #[serde(default = "default_admin_bind")]
    pub bind: SocketAddr,

    #[serde(default)]
    pub auth_token: Option<String>,
}

fn default_admin_bind() -> SocketAddr {
    "127.0.0.1:9090".parse().expect("valid socket addr")
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

fn default_refresh_rate_ms() -> u64 {
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

        let mut listener_names = HashSet::new();
        let mut bind_ports = HashSet::new();

        if self.admin.enabled {
            bind_ports.insert(self.admin.bind);
        }

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
            if !bind_ports.insert(listener.bind) {
                return Err(ConfigError::Validation(format!(
                    "Port conflict: shared_listener '{}' bind address '{}' is already in use",
                    listener.name, listener.bind
                )));
            }
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
        }

        if self.per_tunnel.enabled {
            if let Some(s5) = self.per_tunnel.base_socks5_port {
                if s5 == 0 {
                    return Err(ConfigError::Validation(
                        "per_tunnel.base_socks5_port cannot be 0".into(),
                    ));
                }
            }
            if let Some(http) = self.per_tunnel.base_http_port {
                if http == 0 {
                    return Err(ConfigError::Validation(
                        "per_tunnel.base_http_port cannot be 0".into(),
                    ));
                }
            }
            if let (Some(s5), Some(http)) = (self.per_tunnel.base_socks5_port, self.per_tunnel.base_http_port) {
                if s5 == http {
                    return Err(ConfigError::Validation(
                        "per_tunnel.base_socks5_port and base_http_port cannot be identical".into(),
                    ));
                }
            }
            for (id, override_port) in &self.per_tunnel.overrides {
                if let Some(p) = override_port.socks5_port {
                    if p == 0 {
                        return Err(ConfigError::Validation(format!(
                            "Override socks5_port for tunnel '{id}' cannot be 0"
                        )));
                    }
                }
                if let Some(p) = override_port.http_port {
                    if p == 0 {
                        return Err(ConfigError::Validation(format!(
                            "Override http_port for tunnel '{id}' cannot be 0"
                        )));
                    }
                }
            }
        }

        if self.tui.refresh_rate_ms < 50 {
            return Err(ConfigError::Validation(
                "tui.refresh_rate_ms must be at least 50 ms".into(),
            ));
        }

        Ok(())
    }
}
