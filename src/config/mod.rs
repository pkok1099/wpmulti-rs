//! Multi-Tunnel Configuration Module
//!
//! Provides WireGuard `.conf` parsing, TOML orchestration schema parsing,
//! unique tunnel ID addressing, and batch loading from directories.

pub mod wg_conf;
pub mod toml_config;
#[cfg(test)]
mod tests;

pub use wg_conf::{
    parse_wg_conf, parse_wg_conf_file, strip_comment, WgConfig, WgConfError,
    WgInterfaceConfig, WgPeerConfig,
};
pub use toml_config::{
    parse_duration_str, AdminSettings, AuthMode, ConfigError, DnsPreference, DnsStrategy,
    GlobalSettings, IpMode, LifecycleMode, LifecycleSettings, ListenerType, LogLevel,
    MainConfig, PerTunnelSettings, PoolStrategy, SharedListenerSettings,
    TuiSettings, TuiSortField, TunnelPoolSelection, TunnelPortOverride,
};

use std::collections::HashMap;
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
pub fn load_tunnel_config_from_file<P: AsRef<Path>>(
    path: P,
) -> Result<TunnelConfig, ConfigError> {
    let path = path.as_ref();
    let id = path
        .file_stem()
        .and_then(|s| s.to_str())
        .ok_or_else(|| ConfigError::InvalidTunnelId(format!("Path '{}' has no valid filename stem", path.display())))?
        .to_string();

    let content = std::fs::read_to_string(path)?;
    load_tunnel_config_from_str(id, &content)
}

/// Load a tunnel configuration from a string with an explicitly specified tunnel ID.
pub fn load_tunnel_config_from_str(
    id: impl Into<String>,
    content: &str,
) -> Result<TunnelConfig, ConfigError> {
    let id = id.into();
    if id.trim().is_empty() {
        return Err(ConfigError::InvalidTunnelId("Tunnel ID cannot be empty".into()));
    }
    let (interface, peers) = wg_conf::parse_wg_conf(content)
        .map_err(|e| ConfigError::WgConf(e.to_string()))?;

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
        let path = entry.path();
        if path.is_file() {
            if let Some(ext) = path.extension().and_then(|s| s.to_str()) {
                if ext.eq_ignore_ascii_case("conf") {
                    entries.push(path);
                }
            }
        }
    }

    // Sort paths alphabetically to ensure deterministic ordering
    entries.sort();

    let mut seen_ids: HashMap<String, PathBuf> = HashMap::new();
    let mut configs = Vec::with_capacity(entries.len());

    for path in entries {
        let id = path
            .file_stem()
            .and_then(|s| s.to_str())
            .ok_or_else(|| ConfigError::InvalidTunnelId(format!("Path '{}' has no valid filename stem", path.display())))?
            .to_string();

        if let Some(first_path) = seen_ids.get(&id) {
            return Err(ConfigError::DuplicateTunnelId {
                id,
                file1: first_path.clone(),
                file2: path,
            });
        }
        seen_ids.insert(id.clone(), path.clone());

        let content = std::fs::read_to_string(&path)?;
        let (interface, peers) = wg_conf::parse_wg_conf(&content)
            .map_err(|e| ConfigError::WgConf(format!("Failed parsing {}: {e}", path.display())))?;

        configs.push(TunnelConfig {
            id,
            interface,
            peers,
        });
    }

    Ok(configs)
}
