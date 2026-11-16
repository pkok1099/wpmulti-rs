//! Prometheus and OpenMetrics text exposition generator.
//!
//! Exposes daemon-wide and per-tunnel statistical counters and gauges in Prometheus text format.

use std::fmt::Write;
use std::sync::atomic::Ordering;

use crate::core::{HealthStatus, TunnelManager};

fn write_scalar_gauge(out: &mut String, name: &str, help: &str, value: usize) {
    let _ = writeln!(out, "# HELP {name} {help}");
    let _ = writeln!(out, "# TYPE {name} gauge");
    let _ = writeln!(out, "{name} {value}");
}

fn escape_prometheus_label(val: &str) -> String {
    let mut out = String::with_capacity(val.len());
    for ch in val.chars() {
        match ch {
            '\\' => out.push_str("\\\\"),
            '"' => out.push_str("\\\""),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            c if c.is_ascii_control() => out.push(' '),
            other => out.push(other),
        }
    }
    out
}

fn write_tunnel_metric<T: std::fmt::Display>(
    out: &mut String,
    name: &str,
    metric_type: &str,
    help: &str,
    entries: &[std::sync::Arc<crate::core::registry::TunnelEntry>],
    val_fn: impl Fn(&crate::core::registry::TunnelEntry) -> T,
) {
    let _ = writeln!(out, "# HELP {name} {help}");
    let _ = writeln!(out, "# TYPE {name} {metric_type}");
    for entry in entries {
        let val = val_fn(entry);
        let escaped_id = escape_prometheus_label(&entry.id);
        let _ = writeln!(out, "{name}{{tunnel_id=\"{escaped_id}\"}} {val}");
    }
}

/// Generate Prometheus / OpenMetrics exposition format text for the given [`TunnelManager`].
pub fn generate_prometheus_metrics(manager: &TunnelManager) -> String {
    let entries = manager.registry().all_entries();
    let total_tunnels = entries.len();
    let mut active_tunnels = 0;
    let mut active_conns_total = 0;
    let mut healthy_tunnels = 0;
    let mut unhealthy_tunnels = 0;

    for entry in &entries {
        if entry.is_active() {
            active_tunnels += 1;
        }
        active_conns_total += entry.stats.active_conns.load(Ordering::Relaxed);
        match entry.health.current_status() {
            HealthStatus::Healthy => healthy_tunnels += 1,
            HealthStatus::Unhealthy => unhealthy_tunnels += 1,
            HealthStatus::HalfOpen => {}
        }
    }

    let mut out = String::with_capacity(total_tunnels * 240 + 512);

    write_scalar_gauge(
        &mut out,
        "wpmulti_tunnels_total",
        "Total number of registered tunnels",
        total_tunnels,
    );
    write_scalar_gauge(
        &mut out,
        "wpmulti_tunnels_active",
        "Number of currently active tunnels",
        active_tunnels,
    );
    write_scalar_gauge(
        &mut out,
        "wpmulti_tunnels_healthy",
        "Number of healthy tunnels",
        healthy_tunnels,
    );
    write_scalar_gauge(
        &mut out,
        "wpmulti_tunnels_unhealthy",
        "Number of unhealthy tunnels",
        unhealthy_tunnels,
    );
    write_scalar_gauge(
        &mut out,
        "wpmulti_connections_active_total",
        "Total currently active connections across all tunnels",
        active_conns_total,
    );

    write_tunnel_metric(
        &mut out,
        "wpmulti_tunnel_rx_bytes",
        "counter",
        "Total received bytes per tunnel",
        &entries,
        |e| e.stats.rx_bytes.load(Ordering::Relaxed),
    );
    write_tunnel_metric(
        &mut out,
        "wpmulti_tunnel_tx_bytes",
        "counter",
        "Total transmitted bytes per tunnel",
        &entries,
        |e| e.stats.tx_bytes.load(Ordering::Relaxed),
    );
    write_tunnel_metric(
        &mut out,
        "wpmulti_tunnel_active_conns",
        "gauge",
        "Active connections per tunnel",
        &entries,
        |e| e.stats.active_conns.load(Ordering::Relaxed),
    );
    write_tunnel_metric(
        &mut out,
        "wpmulti_tunnel_health",
        "gauge",
        "Health status of tunnel (1 = healthy, 0 = unhealthy)",
        &entries,
        |e| i32::from(e.health.current_status() == HealthStatus::Healthy),
    );
    write_tunnel_metric(
        &mut out,
        "wpmulti_tunnel_consecutive_failures",
        "gauge",
        "Consecutive failure count per tunnel",
        &entries,
        |e| e.health.consecutive_failures(),
    );
    write_tunnel_metric(
        &mut out,
        "wpmulti_tunnel_cooldown_remaining_seconds",
        "gauge",
        "Remaining cooldown seconds per tunnel",
        &entries,
        |e| e.health.cooldown_remaining_secs(),
    );

    out
}
