//! Metadata, scope classification (`[LIVE]` vs `[RESTART]`), display formatting,
//! parsing, secret redaction/preservation, and diffing for all [`MainConfig`] fields.

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;
use std::time::Duration;

use crate::config::toml_config::{DnsPreference, DnsStrategy};
use crate::config::{
    IpMode, LifecycleMode, LogLevel, MainConfig, SharedListenerSettings, TuiSortField,
    TunnelPortOverride, is_redacted_secret_placeholder, parse_duration_str,
};
use crate::core::ReloadReport;

const REDACTED_PLACEHOLDER: &str = "[REDACTED]";
const KEEP_TOKEN_PLACEHOLDER: &str = "[KEEP]";

/// Indicates whether a configuration setting takes effect immediately at runtime or after restart.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConfigApplyScope {
    /// Propagated to running components without restarting the daemon.
    Live,
    /// Saved to `wpmulti.toml`, requires daemon/listener restart to take effect.
    Restart,
}

impl ConfigApplyScope {
    /// Short badge label rendered in the Config tab and status messages.
    pub const fn tag(self) -> &'static str {
        match self {
            Self::Live => "[LIVE]",
            Self::Restart => "[RESTART]",
        }
    }
}

/// Summary of `[LIVE]` and `[RESTART]` configuration differences between two snapshots.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ConfigDiffSummary {
    pub live_changed: Vec<&'static str>,
    pub restart_changed: Vec<&'static str>,
}

/// Outcome returned after validating, saving, and applying TUI configuration changes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConfigSaveReport {
    pub saved_to_disk: bool,
    pub live_applied: Vec<&'static str>,
    pub restart_pending: Vec<&'static str>,
    pub reload_report: ReloadReport,
}

/// Exhaustive enumeration of every configuration field across [`MainConfig`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConfigField {
    GlobalConfigDir,
    GlobalBindAddress,
    GlobalLogLevel,
    GlobalDnsFallback,
    GlobalDnsStrategy,
    GlobalDnsPreference,
    GlobalIpMode,
    GlobalMaxActiveTunnels,
    LifecycleMode,
    LifecycleIdleTimeout,
    LifecycleHandshakeTimeout,
    LifecycleEagerTunnels,
    PerTunnelEnabled,
    PerTunnelBaseSocks5Port,
    PerTunnelBaseHttpPort,
    PerTunnelOverrides,
    SharedListeners,
    AdminEnabled,
    AdminBind,
    AdminAuthToken,
    TuiRefreshRateMs,
    TuiDefaultSort,
    HealthCheckThreshold,
    HealthCheckCooldown,
    HealthCheckProbeInterval,
    HealthCheckProbeTimeout,
    DisabledTunnels,
}

impl ConfigField {
    /// Ordered list of all configuration rows rendered in the TUI Config tab.
    pub const ALL: [Self; 27] = [
        Self::GlobalConfigDir,
        Self::GlobalBindAddress,
        Self::GlobalLogLevel,
        Self::GlobalDnsFallback,
        Self::GlobalDnsStrategy,
        Self::GlobalDnsPreference,
        Self::GlobalIpMode,
        Self::GlobalMaxActiveTunnels,
        Self::LifecycleMode,
        Self::LifecycleIdleTimeout,
        Self::LifecycleHandshakeTimeout,
        Self::LifecycleEagerTunnels,
        Self::PerTunnelEnabled,
        Self::PerTunnelBaseSocks5Port,
        Self::PerTunnelBaseHttpPort,
        Self::PerTunnelOverrides,
        Self::SharedListeners,
        Self::AdminEnabled,
        Self::AdminBind,
        Self::AdminAuthToken,
        Self::TuiRefreshRateMs,
        Self::TuiDefaultSort,
        Self::HealthCheckThreshold,
        Self::HealthCheckCooldown,
        Self::HealthCheckProbeInterval,
        Self::HealthCheckProbeTimeout,
        Self::DisabledTunnels,
    ];

    /// Resolve a row index into its [`ConfigField`].
    pub fn from_index(idx: usize) -> Option<Self> {
        Self::ALL.get(idx).copied()
    }

    /// Canonical dotted setting path matching `wpmulti.toml`.
    pub const fn key(self) -> &'static str {
        match self {
            Self::GlobalConfigDir => "global.config_dir",
            Self::GlobalBindAddress => "global.bind_address",
            Self::GlobalLogLevel => "global.log_level",
            Self::GlobalDnsFallback => "global.dns_fallback",
            Self::GlobalDnsStrategy => "global.dns_strategy",
            Self::GlobalDnsPreference => "global.dns_preference",
            Self::GlobalIpMode => "global.ip_mode",
            Self::GlobalMaxActiveTunnels => "global.max_active_tunnels",
            Self::LifecycleMode => "lifecycle.mode",
            Self::LifecycleIdleTimeout => "lifecycle.idle_timeout",
            Self::LifecycleHandshakeTimeout => "lifecycle.handshake_timeout",
            Self::LifecycleEagerTunnels => "lifecycle.eager_tunnels",
            Self::PerTunnelEnabled => "per_tunnel.enabled",
            Self::PerTunnelBaseSocks5Port => "per_tunnel.base_socks5_port",
            Self::PerTunnelBaseHttpPort => "per_tunnel.base_http_port",
            Self::PerTunnelOverrides => "per_tunnel.overrides",
            Self::SharedListeners => "shared_listeners",
            Self::AdminEnabled => "admin.enabled",
            Self::AdminBind => "admin.bind",
            Self::AdminAuthToken => "admin.auth_token",
            Self::TuiRefreshRateMs => "tui.refresh_rate_ms",
            Self::TuiDefaultSort => "tui.default_sort",
            Self::HealthCheckThreshold => "health_check.threshold",
            Self::HealthCheckCooldown => "health_check.cooldown",
            Self::HealthCheckProbeInterval => "health_check.probe_interval",
            Self::HealthCheckProbeTimeout => "health_check.probe_timeout",
            Self::DisabledTunnels => "disabled_tunnels",
        }
    }

    /// Runtime application scope (`Live` vs `Restart`).
    pub const fn scope(self) -> ConfigApplyScope {
        match self {
            Self::GlobalDnsFallback
            | Self::GlobalDnsStrategy
            | Self::GlobalDnsPreference
            | Self::GlobalIpMode
            | Self::GlobalMaxActiveTunnels
            | Self::LifecycleIdleTimeout
            | Self::LifecycleHandshakeTimeout
            | Self::TuiRefreshRateMs
            | Self::TuiDefaultSort
            | Self::HealthCheckThreshold
            | Self::HealthCheckCooldown
            | Self::HealthCheckProbeInterval
            | Self::HealthCheckProbeTimeout
            | Self::DisabledTunnels => ConfigApplyScope::Live,
            Self::GlobalConfigDir
            | Self::GlobalBindAddress
            | Self::GlobalLogLevel
            | Self::LifecycleMode
            | Self::LifecycleEagerTunnels
            | Self::PerTunnelEnabled
            | Self::PerTunnelBaseSocks5Port
            | Self::PerTunnelBaseHttpPort
            | Self::PerTunnelOverrides
            | Self::SharedListeners
            | Self::AdminEnabled
            | Self::AdminBind
            | Self::AdminAuthToken => ConfigApplyScope::Restart,
        }
    }

    /// Returns `true` if `Enter`/`Space` cycles enum/boolean values directly without text entry.
    pub const fn is_cycle(self) -> bool {
        matches!(
            self,
            Self::GlobalLogLevel
                | Self::GlobalDnsStrategy
                | Self::GlobalDnsPreference
                | Self::GlobalIpMode
                | Self::LifecycleMode
                | Self::PerTunnelEnabled
                | Self::AdminEnabled
                | Self::TuiDefaultSort
        )
    }

    /// Returns `true` when this field differs between two [`MainConfig`] snapshots.
    pub fn differs(self, a: &MainConfig, b: &MainConfig) -> bool {
        match self {
            Self::GlobalConfigDir => a.global.config_dir != b.global.config_dir,
            Self::GlobalBindAddress => a.global.bind_address != b.global.bind_address,
            Self::GlobalLogLevel => a.global.log_level != b.global.log_level,
            Self::GlobalDnsFallback => a.global.dns_fallback != b.global.dns_fallback,
            Self::GlobalDnsStrategy => a.global.dns_strategy != b.global.dns_strategy,
            Self::GlobalDnsPreference => a.global.dns_preference != b.global.dns_preference,
            Self::GlobalIpMode => a.global.ip_mode != b.global.ip_mode,
            Self::GlobalMaxActiveTunnels => {
                a.global.max_active_tunnels != b.global.max_active_tunnels
            }
            Self::LifecycleMode => a.lifecycle.mode != b.lifecycle.mode,
            Self::LifecycleIdleTimeout => a.lifecycle.idle_timeout != b.lifecycle.idle_timeout,
            Self::LifecycleHandshakeTimeout => {
                a.lifecycle.handshake_timeout != b.lifecycle.handshake_timeout
            }
            Self::LifecycleEagerTunnels => a.lifecycle.eager_tunnels != b.lifecycle.eager_tunnels,
            Self::PerTunnelEnabled => a.per_tunnel.enabled != b.per_tunnel.enabled,
            Self::PerTunnelBaseSocks5Port => {
                a.per_tunnel.base_socks5_port != b.per_tunnel.base_socks5_port
            }
            Self::PerTunnelBaseHttpPort => {
                a.per_tunnel.base_http_port != b.per_tunnel.base_http_port
            }
            Self::PerTunnelOverrides => a.per_tunnel.overrides != b.per_tunnel.overrides,
            Self::SharedListeners => a.shared_listeners != b.shared_listeners,
            Self::AdminEnabled => a.admin.enabled != b.admin.enabled,
            Self::AdminBind => a.admin.bind != b.admin.bind,
            Self::AdminAuthToken => a.admin.auth_token != b.admin.auth_token,
            Self::TuiRefreshRateMs => a.tui.refresh_rate_ms != b.tui.refresh_rate_ms,
            Self::TuiDefaultSort => a.tui.default_sort != b.tui.default_sort,
            Self::HealthCheckThreshold => a.health_check.threshold != b.health_check.threshold,
            Self::HealthCheckCooldown => a.health_check.cooldown != b.health_check.cooldown,
            Self::HealthCheckProbeInterval => {
                a.health_check.probe_interval != b.health_check.probe_interval
            }
            Self::HealthCheckProbeTimeout => {
                a.health_check.probe_timeout != b.health_check.probe_timeout
            }
            Self::DisabledTunnels => a.disabled_tunnels != b.disabled_tunnels,
        }
    }

    /// Safe human-readable string displayed in the Config table (secrets redacted).
    pub fn display_value(self, cfg: &MainConfig) -> String {
        match self {
            Self::GlobalConfigDir => cfg.global.config_dir.display().to_string(),
            Self::GlobalBindAddress => cfg.global.bind_address.to_string(),
            Self::GlobalLogLevel => format_log_level(cfg.global.log_level).to_string(),
            Self::GlobalDnsFallback => cfg.global.dns_fallback.to_string(),
            Self::GlobalDnsStrategy => format_dns_strategy(cfg.global.dns_strategy).to_string(),
            Self::GlobalDnsPreference => {
                format_dns_preference(cfg.global.dns_preference).to_string()
            }
            Self::GlobalIpMode => format_ip_mode(cfg.global.ip_mode).to_string(),
            Self::GlobalMaxActiveTunnels => cfg.global.max_active_tunnels.to_string(),
            Self::LifecycleMode => format_lifecycle_mode(cfg.lifecycle.mode).to_string(),
            Self::LifecycleIdleTimeout => format_duration_compact(cfg.lifecycle.idle_timeout),
            Self::LifecycleHandshakeTimeout => {
                format_duration_compact(cfg.lifecycle.handshake_timeout)
            }
            Self::LifecycleEagerTunnels => format_string_list(&cfg.lifecycle.eager_tunnels),
            Self::PerTunnelEnabled => cfg.per_tunnel.enabled.to_string(),
            Self::PerTunnelBaseSocks5Port => format_optional_port(cfg.per_tunnel.base_socks5_port),
            Self::PerTunnelBaseHttpPort => format_optional_port(cfg.per_tunnel.base_http_port),
            Self::PerTunnelOverrides => format_overrides_summary(&cfg.per_tunnel.overrides),
            Self::SharedListeners => format_listeners_summary(&cfg.shared_listeners),
            Self::AdminEnabled => cfg.admin.enabled.to_string(),
            Self::AdminBind => cfg.admin.bind.to_string(),
            Self::AdminAuthToken => {
                if cfg.admin.auth_token.is_some() {
                    "[SET]".to_string()
                } else {
                    "<none>".to_string()
                }
            }
            Self::TuiRefreshRateMs => cfg.tui.refresh_rate_ms.to_string(),
            Self::TuiDefaultSort => format_sort_field(cfg.tui.default_sort).to_string(),
            Self::HealthCheckThreshold => cfg.health_check.threshold.to_string(),
            Self::HealthCheckCooldown => format_duration_compact(cfg.health_check.cooldown),
            Self::HealthCheckProbeInterval => {
                format_duration_compact(cfg.health_check.probe_interval)
            }
            Self::HealthCheckProbeTimeout => {
                format_duration_compact(cfg.health_check.probe_timeout)
            }
            Self::DisabledTunnels => format_string_list(&cfg.disabled_tunnels),
        }
    }

    /// Initial buffer pre-filled when opening inline text editing for this field.
    pub fn initial_edit_buffer(self, cfg: &MainConfig) -> String {
        match self {
            Self::PerTunnelOverrides => redacted_overrides_json(&cfg.per_tunnel.overrides),
            Self::SharedListeners => redacted_listeners_json(&cfg.shared_listeners),
            Self::AdminAuthToken => {
                if cfg.admin.auth_token.is_some() {
                    KEEP_TOKEN_PLACEHOLDER.to_string()
                } else {
                    String::new()
                }
            }
            Self::LifecycleEagerTunnels => cfg.lifecycle.eager_tunnels.join(","),
            Self::DisabledTunnels => cfg.disabled_tunnels.join(","),
            Self::GlobalConfigDir
            | Self::GlobalBindAddress
            | Self::GlobalLogLevel
            | Self::GlobalDnsFallback
            | Self::GlobalDnsStrategy
            | Self::GlobalDnsPreference
            | Self::GlobalIpMode
            | Self::GlobalMaxActiveTunnels
            | Self::LifecycleMode
            | Self::LifecycleIdleTimeout
            | Self::LifecycleHandshakeTimeout
            | Self::PerTunnelEnabled
            | Self::PerTunnelBaseSocks5Port
            | Self::PerTunnelBaseHttpPort
            | Self::AdminEnabled
            | Self::AdminBind
            | Self::TuiRefreshRateMs
            | Self::TuiDefaultSort
            | Self::HealthCheckThreshold
            | Self::HealthCheckCooldown
            | Self::HealthCheckProbeInterval
            | Self::HealthCheckProbeTimeout => self.display_value(cfg),
        }
    }

    /// Cycle enum or boolean fields in-place; returns `false` if text input is required.
    pub const fn cycle(self, cfg: &mut MainConfig) -> bool {
        match self {
            Self::GlobalLogLevel => {
                cfg.global.log_level = match cfg.global.log_level {
                    LogLevel::Trace => LogLevel::Debug,
                    LogLevel::Debug => LogLevel::Info,
                    LogLevel::Info => LogLevel::Warn,
                    LogLevel::Warn => LogLevel::Error,
                    LogLevel::Error => LogLevel::Trace,
                };
            }
            Self::GlobalIpMode => {
                cfg.global.ip_mode = match cfg.global.ip_mode {
                    IpMode::DualStack => IpMode::Ipv4Only,
                    IpMode::Ipv4Only => IpMode::Ipv6Only,
                    IpMode::Ipv6Only => IpMode::DualStack,
                };
            }
            Self::GlobalDnsStrategy => {
                cfg.global.dns_strategy = match cfg.global.dns_strategy {
                    DnsStrategy::TunnelOnly => DnsStrategy::TunnelFirst,
                    DnsStrategy::TunnelFirst => DnsStrategy::Host,
                    DnsStrategy::Host => DnsStrategy::TunnelOnly,
                };
            }
            Self::GlobalDnsPreference => {
                cfg.global.dns_preference = match cfg.global.dns_preference {
                    DnsPreference::Ipv4First => DnsPreference::Ipv6First,
                    DnsPreference::Ipv6First => DnsPreference::Ipv4First,
                };
            }
            Self::LifecycleMode => {
                cfg.lifecycle.mode = match cfg.lifecycle.mode {
                    LifecycleMode::Lazy => LifecycleMode::Eager,
                    LifecycleMode::Eager => LifecycleMode::Lazy,
                };
            }
            Self::PerTunnelEnabled => cfg.per_tunnel.enabled = !cfg.per_tunnel.enabled,
            Self::AdminEnabled => cfg.admin.enabled = !cfg.admin.enabled,
            Self::TuiDefaultSort => {
                cfg.tui.default_sort = match cfg.tui.default_sort {
                    TuiSortField::Id => TuiSortField::Status,
                    TuiSortField::Status => TuiSortField::Conns,
                    TuiSortField::Conns => TuiSortField::Rx,
                    TuiSortField::Rx => TuiSortField::Tx,
                    TuiSortField::Tx => TuiSortField::Id,
                };
            }
            Self::GlobalConfigDir
            | Self::GlobalBindAddress
            | Self::GlobalDnsFallback
            | Self::GlobalMaxActiveTunnels
            | Self::LifecycleIdleTimeout
            | Self::LifecycleHandshakeTimeout
            | Self::LifecycleEagerTunnels
            | Self::PerTunnelBaseSocks5Port
            | Self::PerTunnelBaseHttpPort
            | Self::PerTunnelOverrides
            | Self::SharedListeners
            | Self::AdminBind
            | Self::AdminAuthToken
            | Self::TuiRefreshRateMs
            | Self::HealthCheckThreshold
            | Self::HealthCheckCooldown
            | Self::HealthCheckProbeInterval
            | Self::HealthCheckProbeTimeout
            | Self::DisabledTunnels => return false,
        }
        true
    }

    /// Parse and assign a text value into `cfg`, preserving redacted secrets when untouched.
    pub fn apply_text(self, cfg: &mut MainConfig, raw: &str) -> Result<(), String> {
        self.apply_text_with_mode(cfg, raw, false)
    }

    /// Parse and assign a text value into `cfg`; in `is_remote` mode retains redacted sentinels
    /// cleanly so `POST /config` merges stored server secrets without overwriting them.
    pub fn apply_text_with_mode(
        self,
        cfg: &mut MainConfig,
        raw: &str,
        is_remote: bool,
    ) -> Result<(), String> {
        let trimmed = raw.trim();
        match self {
            Self::GlobalConfigDir => apply_config_dir(cfg, trimmed),
            Self::GlobalBindAddress => {
                cfg.global.bind_address = parse_ip_addr(trimmed)?;
                Ok(())
            }
            Self::GlobalDnsFallback => {
                cfg.global.dns_fallback = parse_socket_addr(trimmed)?;
                Ok(())
            }
            Self::GlobalMaxActiveTunnels => {
                cfg.global.max_active_tunnels = parse_usize(trimmed)?;
                Ok(())
            }
            Self::LifecycleIdleTimeout => {
                cfg.lifecycle.idle_timeout = parse_duration_str(trimmed)?;
                Ok(())
            }
            Self::LifecycleHandshakeTimeout => {
                cfg.lifecycle.handshake_timeout = parse_duration_str(trimmed)?;
                Ok(())
            }
            Self::LifecycleEagerTunnels => {
                cfg.lifecycle.eager_tunnels = parse_string_list(trimmed)?;
                Ok(())
            }
            Self::PerTunnelBaseSocks5Port => {
                cfg.per_tunnel.base_socks5_port = parse_optional_port(trimmed)?;
                Ok(())
            }
            Self::PerTunnelBaseHttpPort => {
                cfg.per_tunnel.base_http_port = parse_optional_port(trimmed)?;
                Ok(())
            }
            Self::PerTunnelOverrides => apply_overrides_json(cfg, trimmed, is_remote),
            Self::SharedListeners => apply_listeners_json(cfg, trimmed, is_remote),
            Self::AdminBind => {
                cfg.admin.bind = parse_socket_addr(trimmed)?;
                Ok(())
            }
            Self::AdminAuthToken => {
                apply_auth_token(cfg, trimmed);
                Ok(())
            }
            Self::TuiRefreshRateMs => {
                cfg.tui.refresh_rate_ms = trimmed
                    .parse()
                    .map_err(|_| format!("Invalid integer '{trimmed}'"))?;
                Ok(())
            }
            Self::HealthCheckThreshold => {
                cfg.health_check.threshold = parse_usize(trimmed)?;
                Ok(())
            }
            Self::HealthCheckCooldown => {
                cfg.health_check.cooldown = parse_duration_str(trimmed)?;
                Ok(())
            }
            Self::HealthCheckProbeInterval => {
                cfg.health_check.probe_interval = parse_duration_str(trimmed)?;
                Ok(())
            }
            Self::HealthCheckProbeTimeout => {
                cfg.health_check.probe_timeout = parse_duration_str(trimmed)?;
                Ok(())
            }
            Self::DisabledTunnels => {
                let mut list = parse_string_list(trimmed)?;
                list.sort();
                list.dedup();
                cfg.disabled_tunnels = list;
                Ok(())
            }
            Self::GlobalLogLevel
            | Self::GlobalDnsStrategy
            | Self::GlobalDnsPreference
            | Self::GlobalIpMode
            | Self::LifecycleMode
            | Self::PerTunnelEnabled
            | Self::AdminEnabled
            | Self::TuiDefaultSort => {
                Err(format!("Field '{}' uses Enter/Space cycling", self.key()))
            }
        }
    }
}

/// Compute which `[LIVE]` and `[RESTART]` fields changed between `baseline` and `current`.
pub fn diff_config_scopes(baseline: &MainConfig, current: &MainConfig) -> ConfigDiffSummary {
    let mut summary = ConfigDiffSummary::default();
    for field in ConfigField::ALL {
        if field.differs(baseline, current) {
            match field.scope() {
                ConfigApplyScope::Live => summary.live_changed.push(field.key()),
                ConfigApplyScope::Restart => summary.restart_changed.push(field.key()),
            }
        }
    }
    summary
}

/// Format a human-readable banner summarising save, `[LIVE]` hot-reload, and `[RESTART]` status.
pub fn format_save_status(report: &ConfigSaveReport) -> String {
    let prefix = if report.saved_to_disk {
        "Saved wpmulti.toml"
    } else {
        "Applied config (no .toml path)"
    };
    let live_part = if report.live_applied.is_empty() {
        "0 [LIVE] applied".to_string()
    } else if report.live_applied.len() <= 3 {
        format!(
            "{} [LIVE] applied ({})",
            report.live_applied.len(),
            report.live_applied.join(", ")
        )
    } else {
        format!("{} [LIVE] applied", report.live_applied.len())
    };
    let rep = &report.reload_report;
    let tunnel_part = if rep.added + rep.removed + rep.updated > 0 {
        format!(
            "; .conf +{} -{} ~{} ({} total)",
            rep.added, rep.removed, rep.updated, rep.total
        )
    } else {
        String::new()
    };
    let restart_part = if report.restart_pending.is_empty() {
        "; no restart needed".to_string()
    } else if report.restart_pending.len() <= 3 {
        format!(
            " | WARNING: {} [RESTART] change(s) require restart ({})",
            report.restart_pending.len(),
            report.restart_pending.join(", ")
        )
    } else {
        format!(
            " | WARNING: {} [RESTART] change(s) require daemon restart",
            report.restart_pending.len()
        )
    };
    format!("{prefix}: {live_part}{tunnel_part}{restart_part}")
}

/// Format a [`Duration`] concisely so it round-trips losslessly through [`parse_duration_str`].
pub fn format_duration_compact(d: Duration) -> String {
    let secs = d.as_secs();
    if d.subsec_nanos() > 0 {
        format!("{}ms", d.as_millis())
    } else if secs > 0 && secs.is_multiple_of(86400) {
        format!("{}d", secs / 86400)
    } else if secs > 0 && secs.is_multiple_of(3600) {
        format!("{}h", secs / 3600)
    } else if secs > 0 && secs.is_multiple_of(60) {
        format!("{}m", secs / 60)
    } else {
        format!("{secs}s")
    }
}

const fn format_log_level(level: LogLevel) -> &'static str {
    match level {
        LogLevel::Trace => "trace",
        LogLevel::Debug => "debug",
        LogLevel::Info => "info",
        LogLevel::Warn => "warn",
        LogLevel::Error => "error",
    }
}

const fn format_dns_strategy(strategy: DnsStrategy) -> &'static str {
    match strategy {
        DnsStrategy::TunnelOnly => "tunnel_only",
        DnsStrategy::TunnelFirst => "tunnel_first",
        DnsStrategy::Host => "host",
    }
}

const fn format_dns_preference(pref: DnsPreference) -> &'static str {
    match pref {
        DnsPreference::Ipv4First => "ipv4_first",
        DnsPreference::Ipv6First => "ipv6_first",
    }
}

const fn format_ip_mode(mode: IpMode) -> &'static str {
    match mode {
        IpMode::DualStack => "dual_stack",
        IpMode::Ipv4Only => "ipv4_only",
        IpMode::Ipv6Only => "ipv6_only",
    }
}

const fn format_lifecycle_mode(mode: LifecycleMode) -> &'static str {
    match mode {
        LifecycleMode::Lazy => "lazy",
        LifecycleMode::Eager => "eager",
    }
}

const fn format_sort_field(sort: TuiSortField) -> &'static str {
    match sort {
        TuiSortField::Id => "id",
        TuiSortField::Status => "status",
        TuiSortField::Conns => "conns",
        TuiSortField::Rx => "rx",
        TuiSortField::Tx => "tx",
    }
}

fn format_optional_port(port: Option<u16>) -> String {
    port.map_or_else(|| "none".to_string(), |p| p.to_string())
}

fn format_string_list(items: &[String]) -> String {
    if items.is_empty() {
        "none".to_string()
    } else {
        items.join(", ")
    }
}

fn format_overrides_summary(overrides: &HashMap<String, TunnelPortOverride>) -> String {
    if overrides.is_empty() {
        return "0 override(s)".to_string();
    }
    let mut keys: Vec<&String> = overrides.keys().collect();
    keys.sort();
    let preview: Vec<&str> = keys.iter().take(2).map(|k| k.as_str()).collect();
    let suffix = if keys.len() > 2 { ", ..." } else { "" };
    format!(
        "{} override(s): {}{}",
        keys.len(),
        preview.join(", "),
        suffix
    )
}

fn format_listeners_summary(listeners: &[SharedListenerSettings]) -> String {
    if listeners.is_empty() {
        return "0 listener(s)".to_string();
    }
    let preview: Vec<String> = listeners
        .iter()
        .take(2)
        .map(|l| format!("{}({})", l.name, l.bind))
        .collect();
    let suffix = if listeners.len() > 2 { ", ..." } else { "" };
    format!(
        "{} listener(s): {}{}",
        listeners.len(),
        preview.join(", "),
        suffix
    )
}

fn redacted_overrides_json(overrides: &HashMap<String, TunnelPortOverride>) -> String {
    let redacted: HashMap<&String, TunnelPortOverride> = overrides
        .iter()
        .map(|(k, v)| {
            let mut cloned = v.clone();
            if cloned.password.is_some() {
                cloned.password = Some(REDACTED_PLACEHOLDER.to_string());
            }
            (k, cloned)
        })
        .collect();
    serde_json::to_string(&redacted).unwrap_or_else(|_| "{}".to_string())
}

fn redacted_listeners_json(listeners: &[SharedListenerSettings]) -> String {
    let redacted: Vec<SharedListenerSettings> = listeners
        .iter()
        .map(|l| {
            let mut cloned = l.clone();
            if cloned.global_password.is_some() {
                cloned.global_password = Some(REDACTED_PLACEHOLDER.to_string());
            }
            cloned
        })
        .collect();
    serde_json::to_string(&redacted).unwrap_or_else(|_| "[]".to_string())
}

fn apply_config_dir(cfg: &mut MainConfig, trimmed: &str) -> Result<(), String> {
    if trimmed.is_empty() {
        return Err("global.config_dir cannot be empty".to_string());
    }
    cfg.global.config_dir = PathBuf::from(trimmed);
    Ok(())
}

fn parse_ip_addr(trimmed: &str) -> Result<IpAddr, String> {
    trimmed
        .parse()
        .map_err(|_| format!("Invalid IP address '{trimmed}'"))
}

fn parse_socket_addr(trimmed: &str) -> Result<SocketAddr, String> {
    trimmed
        .parse()
        .map_err(|_| format!("Invalid socket address '{trimmed}'"))
}

fn parse_usize(trimmed: &str) -> Result<usize, String> {
    trimmed
        .parse()
        .map_err(|_| format!("Invalid integer '{trimmed}'"))
}

fn parse_optional_port(trimmed: &str) -> Result<Option<u16>, String> {
    if trimmed.is_empty()
        || trimmed.eq_ignore_ascii_case("none")
        || trimmed.eq_ignore_ascii_case("<none>")
    {
        return Ok(None);
    }
    let port: u16 = trimmed
        .parse()
        .map_err(|_| format!("Invalid port '{trimmed}'"))?;
    Ok(Some(port))
}

fn parse_string_list(trimmed: &str) -> Result<Vec<String>, String> {
    if trimmed.is_empty()
        || trimmed.eq_ignore_ascii_case("none")
        || trimmed.eq_ignore_ascii_case("<none>")
    {
        return Ok(Vec::new());
    }
    if trimmed.starts_with('[') {
        let items: Vec<String> =
            serde_json::from_str(trimmed).map_err(|e| format!("Invalid JSON string list: {e}"))?;
        let cleaned: Vec<String> = items
            .into_iter()
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect();
        return Ok(cleaned);
    }
    let mut out = Vec::new();
    for part in trimmed.split(',') {
        let token = part.trim();
        if token.is_empty() {
            return Err(format!("Empty tunnel ID element in list '{trimmed}'"));
        }
        if !out.iter().any(|existing| existing == token) {
            out.push(token.to_string());
        }
    }
    Ok(out)
}

fn apply_auth_token(cfg: &mut MainConfig, trimmed: &str) {
    if trimmed == KEEP_TOKEN_PLACEHOLDER
        || (!trimmed.is_empty() && is_redacted_secret_placeholder(trimmed))
    {
        return;
    }
    if trimmed.is_empty()
        || trimmed.eq_ignore_ascii_case("none")
        || trimmed.eq_ignore_ascii_case("<none>")
    {
        cfg.admin.auth_token = None;
    } else {
        cfg.admin.auth_token = Some(trimmed.to_string());
    }
}

fn find_listener_for_secret<'a>(
    listener: &SharedListenerSettings,
    existing: &'a [SharedListenerSettings],
) -> Option<&'a SharedListenerSettings> {
    existing
        .iter()
        .find(|old| old.name == listener.name && old.bind == listener.bind)
        .or_else(|| existing.iter().find(|old| old.name == listener.name))
        .or_else(|| {
            let mut by_bind = existing.iter().filter(|old| old.bind == listener.bind);
            match (by_bind.next(), by_bind.next()) {
                (Some(only), None) => Some(only),
                _ => None,
            }
        })
}

fn apply_overrides_json(
    cfg: &mut MainConfig,
    trimmed: &str,
    is_remote: bool,
) -> Result<(), String> {
    let mut parsed: HashMap<String, TunnelPortOverride> = serde_json::from_str(trimmed)
        .map_err(|e| format!("Invalid JSON for per_tunnel.overrides: {e}"))?;
    for (id, entry) in &mut parsed {
        if entry
            .password
            .as_deref()
            .is_some_and(|p| !p.is_empty() && is_redacted_secret_placeholder(p))
        {
            let prev = cfg
                .per_tunnel
                .overrides
                .get(id)
                .and_then(|old| old.password.clone());
            if prev.is_some() {
                entry.password = prev;
            } else if is_remote {
                entry.password = Some(REDACTED_PLACEHOLDER.to_string());
            } else {
                return Err(format!(
                    "Provide an explicit password for override '{id}' instead of {REDACTED_PLACEHOLDER}"
                ));
            }
        }
    }
    cfg.per_tunnel.overrides = parsed;
    Ok(())
}

fn apply_listeners_json(
    cfg: &mut MainConfig,
    trimmed: &str,
    is_remote: bool,
) -> Result<(), String> {
    let mut parsed: Vec<SharedListenerSettings> = serde_json::from_str(trimmed)
        .map_err(|e| format!("Invalid JSON for shared_listeners: {e}"))?;
    for listener in &mut parsed {
        if listener
            .global_password
            .as_deref()
            .is_some_and(|p| !p.is_empty() && is_redacted_secret_placeholder(p))
        {
            let prev = find_listener_for_secret(listener, &cfg.shared_listeners)
                .and_then(|old| old.global_password.clone());
            if prev.is_some() {
                listener.global_password = prev;
            } else if is_remote {
                listener.global_password = Some(REDACTED_PLACEHOLDER.to_string());
            } else {
                return Err(format!(
                    "Provide an explicit global_password for listener '{}' instead of {REDACTED_PLACEHOLDER}",
                    listener.name
                ));
            }
        }
    }
    cfg.shared_listeners = parsed;
    Ok(())
}
