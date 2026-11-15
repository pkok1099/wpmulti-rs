//! Interactive terminal dashboard monitor (htop-style) for WireGuard tunnels.
//!
//! Provides color-coded real-time tunnel visualization, search, sort, and lifecycle controls.

pub mod app;
pub mod ui;
#[cfg(test)]
pub mod tests;

pub use app::{TuiApp, TuiDataSource};
pub use ui::{format_bytes, render_dashboard, run_terminal_tui};
