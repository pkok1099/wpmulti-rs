//! Prometheus and OpenMetrics text exposition generator.
//!
//! Exposes daemon-wide and per-tunnel statistical counters and gauges in Prometheus text format.

use std::fmt::Write;

use crate::core::TunnelManager;

/// Generate Prometheus / OpenMetrics exposition format text for the given [`TunnelManager`].
pub fn generate_prometheus_metrics(manager: &TunnelManager) -> String {
    let mut out = String::with_capacity(4096);

    let stats = manager.get_tunnel_stats();
    let total_tunnels = stats.len();
    let active_tunnels = stats.iter().filter(|s| s.state == crate::core::TunnelState::Active).count();
    let active_conns_total: usize = stats.iter().map(|s| s.active_conns).sum();

    // 1. Daemon-wide gauges
    let _ = writeln!(out, "# HELP wpmulti_tunnels_total Total number of registered tunnels");
    let _ = writeln!(out, "# TYPE wpmulti_tunnels_total gauge");
    let _ = writeln!(out, "wpmulti_tunnels_total {}", total_tunnels);

    let _ = writeln!(out, "# HELP wpmulti_tunnels_active Number of currently active tunnels");
    let _ = writeln!(out, "# TYPE wpmulti_tunnels_active gauge");
    let _ = writeln!(out, "wpmulti_tunnels_active {}", active_tunnels);

    let _ = writeln!(
        out,
        "# HELP wpmulti_connections_active_total Total currently active connections across all tunnels"
    );
    let _ = writeln!(out, "# TYPE wpmulti_connections_active_total gauge");
    let _ = writeln!(out, "wpmulti_connections_active_total {}", active_conns_total);

    // 2. Per-tunnel counters: RX bytes
    let _ = writeln!(out, "# HELP wpmulti_tunnel_rx_bytes Total received bytes per tunnel");
    let _ = writeln!(out, "# TYPE wpmulti_tunnel_rx_bytes counter");
    for s in &stats {
        let _ = writeln!(out, "wpmulti_tunnel_rx_bytes{{tunnel_id=\"{}\"}} {}", s.id, s.rx_bytes);
    }

    // 3. Per-tunnel counters: TX bytes
    let _ = writeln!(out, "# HELP wpmulti_tunnel_tx_bytes Total transmitted bytes per tunnel");
    let _ = writeln!(out, "# TYPE wpmulti_tunnel_tx_bytes counter");
    for s in &stats {
        let _ = writeln!(out, "wpmulti_tunnel_tx_bytes{{tunnel_id=\"{}\"}} {}", s.id, s.tx_bytes);
    }

    // 4. Per-tunnel gauges: Active connections
    let _ = writeln!(out, "# HELP wpmulti_tunnel_active_conns Active connections per tunnel");
    let _ = writeln!(out, "# TYPE wpmulti_tunnel_active_conns gauge");
    for s in &stats {
        let _ = writeln!(out, "wpmulti_tunnel_active_conns{{tunnel_id=\"{}\"}} {}", s.id, s.active_conns);
    }

    out
}
