//! Multi-Tunnel Configuration Module
//!
//! Provides WireGuard `.conf` parsing, TOML orchestration schema parsing,
//! unique tunnel ID addressing, and batch loading from directories.

#[cfg(test)]
mod tests;
pub mod toml_config;
pub mod toml_preserve;
pub mod wg_conf;

pub use toml_config::{
    AdminSettings, AuthMode, ConfigError, DnsPreference, DnsStrategy, GlobalSettings,
    HealthCheckSettings, IpMode, LifecycleMode, LifecycleSettings, ListenerType, LogLevel,
    MainConfig, PerTunnelSettings, PoolStrategy, SharedListenerSettings, TuiSettings, TuiSortField,
    TunnelPoolSelection, TunnelPortOverride, is_redacted_secret_placeholder, parse_duration_str,
};
pub use toml_preserve::merge_config_preserving_comments;
pub use wg_conf::{
    WgConfError, WgConfig, WgInterfaceConfig, WgPeerConfig, parse_wg_conf, parse_wg_conf_file,
    strip_comment,
};

use std::collections::HashMap;
use std::ffi::OsStr;
use std::path::{Path, PathBuf};

/// Self-contained WireGuard tunnel configuration indexed by unique ID.
#[derive(Debug, Clone)]
pub struct TunnelConfig {
    /// Unique primary key identifier for the tunnel (e.g. derived from filename stem).
    pub id: String,
    /// WireGuard interface settings.
    pub interface: WgInterfaceConfig,
    /// Remote WireGuard peers.
    pub peers: Vec<WgPeerConfig>,
}

impl PartialEq for TunnelConfig {
    fn eq(&self, other: &Self) -> bool {
        self.id == other.id && self.interface == other.interface && self.peers == other.peers
    }
}

impl Eq for TunnelConfig {}

/// Load a single tunnel configuration from a `.conf` file.
///
/// Derives the unique tunnel ID from the file stem (e.g. `wgcf-001.conf` -> `wgcf-001`).
pub fn load_tunnel_config_from_file<P: AsRef<Path>>(path: P) -> Result<TunnelConfig, ConfigError> {
    let path = path.as_ref();
    let id = path
        .file_stem()
        .and_then(OsStr::to_str)
        .ok_or_else(|| {
            ConfigError::InvalidTunnelId(format!(
                "Path '{}' has no valid filename stem",
                path.display()
            ))
        })?
        .to_string();

    let meta = std::fs::symlink_metadata(path)?;
    if meta.len() > MAX_WG_CONF_BYTES {
        return Err(ConfigError::WgConf(format!(
            "File '{}' exceeds maximum size of {} bytes",
            path.display(),
            MAX_WG_CONF_BYTES
        )));
    }
    let content = std::fs::read_to_string(path)?;
    load_tunnel_config_from_str(id, &content)
}

const MAX_WG_CONF_BYTES: u64 = 1024 * 1024;

fn validate_tunnel_id(id: &str) -> Result<(), ConfigError> {
    if id.trim().is_empty() || id == "." || id == ".." {
        return Err(ConfigError::InvalidTunnelId(
            "Tunnel ID cannot be empty or '.' / '..'".into(),
        ));
    }
    if id.chars().any(|c| {
        c.is_control() || c.is_whitespace() || matches!(c, '?' | '#' | '/' | '%' | '"' | '\\')
    }) {
        return Err(ConfigError::InvalidTunnelId(format!(
            "Tunnel ID '{id}' contains disallowed characters"
        )));
    }
    Ok(())
}

/// Load a tunnel configuration from a string with an explicitly specified tunnel ID.
pub fn load_tunnel_config_from_str(
    id: impl Into<String>,
    content: &str,
) -> Result<TunnelConfig, ConfigError> {
    let id = id.into();
    validate_tunnel_id(&id)?;
    let (interface, peers) =
        parse_wg_conf(content).map_err(|e| ConfigError::WgConf(e.to_string()))?;

    Ok(TunnelConfig {
        id,
        interface,
        peers,
    })
}

/// Load all WireGuard `.conf` files from a directory, assigning unique tunnel IDs
/// based on filename stems, detecting duplicate stems, and sorting by ID.
pub fn load_tunnel_configs_from_dir<P: AsRef<Path>>(
    dir: P,
) -> Result<Vec<TunnelConfig>, ConfigError> {
    let dir = dir.as_ref();
    if !dir.is_dir() {
        return Err(ConfigError::DirectoryNotFound(dir.to_path_buf()));
    }

    let mut entries: Vec<PathBuf> = Vec::new();
    for entry in std::fs::read_dir(dir)? {
        let entry = entry?;
        if !entry.file_type()?.is_file() {
            continue;
        }
        let path = entry.path();
        if let Some(ext) = path.extension().and_then(OsStr::to_str)
            && ext.eq_ignore_ascii_case("conf")
        {
            entries.push(path);
        }
    }

    // Sort paths alphabetically to ensure deterministic ordering
    entries.sort();

    // Every broken file is reported, not just the first one: a user with
    // several bad `.conf` files should fix them all in one pass instead of
    // re-running `validate` after each single fix. Per-file failures are
    // collected and returned together; only files that parse cleanly are
    // loaded (a failed file never reserves its tunnel id).
    let mut seen_ids: HashMap<String, PathBuf> = HashMap::new();
    let mut configs = Vec::with_capacity(entries.len());
    let mut failures: Vec<String> = Vec::new();

    for path in entries {
        let Some(stem) = path.file_stem().and_then(OsStr::to_str) else {
            failures.push(format!(
                "Path '{}' has no valid filename stem",
                path.display()
            ));
            continue;
        };
        let id = stem.to_string();
        if let Err(e) = validate_tunnel_id(&id) {
            failures.push(e.to_string());
            continue;
        }
        if let Some(first_path) = seen_ids.get(&id) {
            failures.push(
                ConfigError::DuplicateTunnelId {
                    id,
                    file1: first_path.clone(),
                    file2: path,
                }
                .to_string(),
            );
            continue;
        }

        let loaded = (|| -> Result<(WgInterfaceConfig, Vec<WgPeerConfig>), ConfigError> {
            let meta = std::fs::symlink_metadata(&path)?;
            if meta.len() > MAX_WG_CONF_BYTES {
                return Err(ConfigError::WgConf(format!(
                    "File '{}' exceeds maximum size of {} bytes",
                    path.display(),
                    MAX_WG_CONF_BYTES
                )));
            }
            let content = std::fs::read_to_string(&path)?;
            parse_wg_conf(&content)
                .map_err(|e| ConfigError::WgConf(format!("Failed parsing {}: {e}", path.display())))
        })();
        match loaded {
            Ok((interface, peers)) => {
                seen_ids.insert(id.clone(), path.clone());
                configs.push(TunnelConfig {
                    id,
                    interface,
                    peers,
                });
            }
            Err(e) => failures.push(e.to_string()),
        }
    }

    if failures.is_empty() {
        Ok(configs)
    } else {
        Err(ConfigError::MultipleTunnelErrors(failures.join("\n")))
    }
}
