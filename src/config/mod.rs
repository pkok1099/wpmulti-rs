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

use wg_conf::open_no_follow;

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

    // Open without following symlinks and verify the opened inode with
    // post-open `fstat` (audit run-1,
    // `config/wg-conf-dir-loader-symlink-toctou`): a symlink swapped in
    // after enumeration must not redirect this read outside the config
    // directory, and the size bound must describe the file actually read.
    let mut file = open_no_follow(path)?;
    let meta = file.metadata()?;
    if !meta.file_type().is_file() {
        return Err(ConfigError::WgConf(format!(
            "File '{}' is not a regular file",
            path.display()
        )));
    }
    if meta.len() > MAX_WG_CONF_BYTES {
        return Err(ConfigError::WgConf(format!(
            "File '{}' exceeds maximum size of {} bytes",
            path.display(),
            MAX_WG_CONF_BYTES
        )));
    }
    let mut content = String::new();
    std::io::Read::read_to_string(&mut file, &mut content)?;
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

/// One `.conf` file that failed to load from a directory, quarantined
/// instead of failing the whole directory load (audit run-1,
/// `config/load-dir-single-bad-conf-fails-all`).
#[derive(Debug, Clone)]
pub struct TunnelLoadFailure {
    /// File that failed to load.
    pub path: PathBuf,
    /// Tunnel ID derived from the file stem, when one could be derived.
    pub id: Option<String>,
    /// Human-readable reason, in the same wording the strict loader
    /// used to report for this file.
    pub error: String,
}

/// Result of a partial directory load: every file that parsed cleanly,
/// plus one entry per file that failed (quarantined, never reserving
/// its tunnel id).
#[derive(Debug, Clone, Default)]
pub struct PartialTunnelLoad {
    pub configs: Vec<TunnelConfig>,
    pub failures: Vec<TunnelLoadFailure>,
}

/// Load all WireGuard `.conf` files from a directory, assigning unique tunnel IDs
/// based on filename stems, detecting duplicate stems, and sorting by ID.
///
/// Strict all-or-nothing variant used by `validate`: any failure aborts
/// the whole load, so a directory with broken files is reported in full
/// instead of silently starting degraded. `run`, `probe`, and `reload`
/// use [`load_tunnel_configs_from_dir_partial`] instead, which starts
/// degraded with the valid set and quarantines the broken files.
pub fn load_tunnel_configs_from_dir<P: AsRef<Path>>(
    dir: P,
) -> Result<Vec<TunnelConfig>, ConfigError> {
    let partial = load_tunnel_configs_from_dir_partial(dir)?;
    if partial.failures.is_empty() {
        Ok(partial.configs)
    } else {
        Err(ConfigError::MultipleTunnelErrors(
            partial
                .failures
                .iter()
                .map(|f| f.error.as_str())
                .collect::<Vec<_>>()
                .join("\n"),
        ))
    }
}

/// Collect the `.conf` entries of `dir` in deterministic (sorted)
/// order, quarantining unreadable entries instead of aborting the scan.
fn collect_conf_entries(dir: &Path) -> Result<(Vec<PathBuf>, Vec<TunnelLoadFailure>), ConfigError> {
    let mut entries: Vec<PathBuf> = Vec::new();
    let mut failures: Vec<TunnelLoadFailure> = Vec::new();
    for entry in std::fs::read_dir(dir)? {
        let entry = match entry {
            Ok(entry) => entry,
            Err(e) => {
                failures.push(TunnelLoadFailure {
                    path: dir.to_path_buf(),
                    id: None,
                    error: e.to_string(),
                });
                continue;
            }
        };
        let is_file = match entry.file_type() {
            Ok(file_type) => file_type.is_file(),
            Err(e) => {
                failures.push(TunnelLoadFailure {
                    path: entry.path(),
                    id: None,
                    error: e.to_string(),
                });
                continue;
            }
        };
        if !is_file {
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
    Ok((entries, failures))
}

/// Load all WireGuard `.conf` files from a directory, returning the valid
/// set plus one [`TunnelLoadFailure`] per broken file.
///
/// A failed file never reserves its tunnel id; the caller decides what
/// to do with the failures (log and quarantine them for
/// `run`/`probe`/`reload`, fail for `validate` via
/// [`load_tunnel_configs_from_dir`]).
pub fn load_tunnel_configs_from_dir_partial<P: AsRef<Path>>(
    dir: P,
) -> Result<PartialTunnelLoad, ConfigError> {
    let dir = dir.as_ref();
    if !dir.is_dir() {
        return Err(ConfigError::DirectoryNotFound(dir.to_path_buf()));
    }

    let (entries, mut failures) = collect_conf_entries(dir)?;

    // Every broken file is reported, not just the first one: a user with
    // several bad `.conf` files should fix them all in one pass instead of
    // re-running `validate` after each single fix. Per-file failures are
    // collected and returned together; only files that parse cleanly are
    // loaded (a failed file never reserves its tunnel id).
    let mut seen_ids: HashMap<String, PathBuf> = HashMap::new();
    let mut configs = Vec::with_capacity(entries.len());

    for path in entries {
        let Some(stem) = path.file_stem().and_then(OsStr::to_str) else {
            failures.push(TunnelLoadFailure {
                path: path.clone(),
                id: None,
                error: format!("Path '{}' has no valid filename stem", path.display()),
            });
            continue;
        };
        let id = stem.to_string();
        if let Err(e) = validate_tunnel_id(&id) {
            failures.push(TunnelLoadFailure {
                path: path.clone(),
                id: Some(id),
                error: e.to_string(),
            });
            continue;
        }
        if let Some(first_path) = seen_ids.get(&id) {
            failures.push(TunnelLoadFailure {
                path: path.clone(),
                id: Some(id.clone()),
                error: ConfigError::DuplicateTunnelId {
                    id,
                    file1: first_path.clone(),
                    file2: path,
                }
                .to_string(),
            });
            continue;
        }

        let loaded = (|| -> Result<(WgInterfaceConfig, Vec<WgPeerConfig>), ConfigError> {
            // Open without following symlinks and verify the opened inode
            // with post-open `fstat` (audit run-1,
            // `config/wg-conf-dir-loader-symlink-toctou`).
            let mut file = open_no_follow(&path)?;
            let meta = file.metadata()?;
            if !meta.file_type().is_file() {
                return Err(ConfigError::WgConf(format!(
                    "File '{}' is not a regular file",
                    path.display()
                )));
            }
            if meta.len() > MAX_WG_CONF_BYTES {
                return Err(ConfigError::WgConf(format!(
                    "File '{}' exceeds maximum size of {} bytes",
                    path.display(),
                    MAX_WG_CONF_BYTES
                )));
            }
            let mut content = String::new();
            std::io::Read::read_to_string(&mut file, &mut content)?;
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
            Err(e) => failures.push(TunnelLoadFailure {
                path: path.clone(),
                id: Some(id),
                error: e.to_string(),
            }),
        }
    }

    Ok(PartialTunnelLoad { configs, failures })
}
