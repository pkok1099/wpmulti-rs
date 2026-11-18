//! Interactive terminal dashboard monitor (htop-style) for WireGuard tunnels.
//!
//! Provides color-coded real-time tunnel visualization, search, sort, and lifecycle controls.

pub mod app;
pub mod config_editor;
pub mod logs;
#[cfg(test)]
pub mod tests;
pub mod ui;

pub use app::{TuiApp, TuiDataSource, TuiOverlay, TuiProbeResult, TuiTab};
pub use config_editor::{ConfigApplyScope, ConfigDiffSummary, ConfigField, ConfigSaveReport};
pub use logs::TuiLogBuffer;
pub use ui::{format_bytes, render_dashboard, run_terminal_tui};
