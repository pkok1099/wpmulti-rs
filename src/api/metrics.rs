//! Prometheus and OpenMetrics text exposition generator.
//!
//! Exposes daemon-wide and per-tunnel statistical counters and gauges in Prometheus text format.

use std::fmt::Write;
use std::sync::atomic::Ordering;

use crate::core::TunnelManager;

/// Generate Prometheus / OpenMetrics exposition format text for the given [`TunnelManager`].
pub fn generate_prometheus_metrics(manager: &TunnelManager) -> String {
    let entries = manager.registry().all_entries();
    let total_tunnels = entries.len();
    let mut active_tunnels = 0;
    let mut active_conns_total = 0;

    for entry in &entries {
        if entry.is_active() {
            active_tunnels += 1;
        }
        active_conns_total += entry.stats.active_conns.load(Ordering::Relaxed);
    }

    let mut out = String::with_capacity(total_tunnels * 160 + 512);

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
    for entry in &entries {
        let rx = entry.stats.rx_bytes.load(Ordering::Relaxed);
        let _ = writeln!(out, "wpmulti_tunnel_rx_bytes{{tunnel_id=\"{}\"}} {}", entry.id, rx);
    }

    // 3. Per-tunnel counters: TX bytes
    let _ = writeln!(out, "# HELP wpmulti_tunnel_tx_bytes Total transmitted bytes per tunnel");
    let _ = writeln!(out, "# TYPE wpmulti_tunnel_tx_bytes counter");
    for entry in &entries {
        let tx = entry.stats.tx_bytes.load(Ordering::Relaxed);
        let _ = writeln!(out, "wpmulti_tunnel_tx_bytes{{tunnel_id=\"{}\"}} {}", entry.id, tx);
    }

    // 4. Per-tunnel gauges: Active connections
    let _ = writeln!(out, "# HELP wpmulti_tunnel_active_conns Active connections per tunnel");
    let _ = writeln!(out, "# TYPE wpmulti_tunnel_active_conns gauge");
    for entry in &entries {
        let conns = entry.stats.active_conns.load(Ordering::Relaxed);
        let _ = writeln!(out, "wpmulti_tunnel_active_conns{{tunnel_id=\"{}\"}} {}", entry.id, conns);
    }

    out
}
