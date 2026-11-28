//! Prometheus and OpenMetrics text exposition generator.
//!
//! Exposes daemon-wide and per-tunnel statistical counters and gauges in Prometheus text format.

use std::fmt::Write;
use std::sync::Arc;
use std::sync::atomic::Ordering;

use crate::core::{HealthStatus, TunnelEntry, TunnelManager};
use crate::netstack::bridge::BridgeCounters;

/// Read one bridge counter for a tunnel entry: 0 when the tunnel has
/// no running netstack (dormant, or VPN mode).
fn tunnel_bridge_counter(entry: &TunnelEntry, load: impl Fn(&BridgeCounters) -> u64) -> u64 {
    entry
        .active
        .read()
        .as_ref()
        .and_then(|active| active.netstack.as_ref())
        .map_or(0, |stack| load(stack.bridge_counters()))
}

/// Count registered tunnels by health status: (healthy, untested, unhealthy, dead).
/// Half-open tunnels count in none of the four buckets.
fn count_health_statuses(entries: &[Arc<TunnelEntry>]) -> (usize, usize, usize, usize) {
    let mut healthy = 0;
    let mut untested = 0;
    let mut unhealthy = 0;
    let mut dead = 0;
    for entry in entries {
        match entry.health.current_status() {
            HealthStatus::Healthy => healthy += 1,
            HealthStatus::Untested => untested += 1,
            HealthStatus::Unhealthy => unhealthy += 1,
            HealthStatus::Dead => dead += 1,
            HealthStatus::HalfOpen => {}
        }
    }
    (healthy, untested, unhealthy, dead)
}

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
    entries: &[Arc<TunnelEntry>],
    val_fn: impl Fn(&TunnelEntry) -> T,
) {
    let _ = writeln!(out, "# HELP {name} {help}");
    let _ = writeln!(out, "# TYPE {name} {metric_type}");
    for entry in entries {
        let val = val_fn(entry);
        let escaped_id = escape_prometheus_label(&entry.id);
        let _ = writeln!(out, "{name}{{tunnel_id=\"{escaped_id}\"}} {val}");
    }
}

/// Write the four per-health-status tunnel count gauges.
fn write_health_count_gauges(
    out: &mut String,
    healthy: usize,
    untested: usize,
    unhealthy: usize,
    dead: usize,
) {
    write_scalar_gauge(
        out,
        "wpmulti_tunnels_healthy",
        "Number of healthy tunnels",
        healthy,
    );
    write_scalar_gauge(
        out,
        "wpmulti_tunnels_untested",
        "Number of tunnels that have never completed a successful handshake or probe",
        untested,
    );
    write_scalar_gauge(
        out,
        "wpmulti_tunnels_unhealthy",
        "Number of unhealthy tunnels",
        unhealthy,
    );
    write_scalar_gauge(
        out,
        "wpmulti_tunnels_dead",
        "Number of dead tunnels (circuit breaker tripped 3 times; no longer probed or routed to)",
        dead,
    );
}

/// Generate Prometheus / OpenMetrics exposition format text for the given [`TunnelManager`].
pub fn generate_prometheus_metrics(manager: &TunnelManager) -> String {
    let entries = manager.registry().all_entries();
    let total_tunnels = entries.len();
    let mut active_tunnels = 0;
    let mut active_conns_total = 0;
    let (healthy_tunnels, untested_tunnels, unhealthy_tunnels, dead_tunnels) =
        count_health_statuses(&entries);

    for entry in &entries {
        if entry.is_active() {
            active_tunnels += 1;
        }
        active_conns_total += entry.stats.active_conns.load(Ordering::Relaxed);
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
    write_health_count_gauges(
        &mut out,
        healthy_tunnels,
        untested_tunnels,
        unhealthy_tunnels,
        dead_tunnels,
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
    write_bridge_metrics(&mut out, &entries);
    // Safe HTTP silence replay (fix11): global counters rendered
    // from the proxy's replay state, next to the tunnel gauges.
    crate::proxy::replay::write_replay_metrics(&mut out);

    out
}

/// P=64 probe: per-stack bridge counters (see [`BridgeCounters`]).
fn write_bridge_metrics(out: &mut String, entries: &[Arc<TunnelEntry>]) {
    write_tunnel_metric(
        out,
        "wpmulti_tunnel_tcp_syn_retransmits",
        "counter",
        "Outgoing TCP SYNs repeating a recent (source port, sequence number): smoltcp RTO retransmits",
        entries,
        |e| tunnel_bridge_counter(e, |c| c.syn_retransmits.load(Ordering::Relaxed)),
    );
    write_tunnel_metric(
        out,
        "wpmulti_tunnel_tx_full_rx_stall_episodes",
        "counter",
        "Episodes where Device::receive returned None because the TX channel was full (TX-full RX stall)",
        entries,
        |e| tunnel_bridge_counter(e, |c| c.tx_full_rx_stall_episodes.load(Ordering::Relaxed)),
    );
    write_tunnel_metric(
        out,
        "wpmulti_tunnel_tx_full_drops",
        "counter",
        "Outbound packets dropped because the TX channel was full or closed",
        entries,
        |e| tunnel_bridge_counter(e, |c| c.tx_full_drops.load(Ordering::Relaxed)),
    );
    write_tunnel_metric(
        out,
        "wpmulti_tunnel_ipsend_wait_ms_total",
        "counter",
        "Total milliseconds BridgeIpSend::send spent awaiting RX channel capacity",
        entries,
        |e| tunnel_bridge_counter(e, |c| c.ipsend_wait_ms_total.load(Ordering::Relaxed)),
    );
    write_tunnel_metric(
        out,
        "wpmulti_tunnel_ipsend_waits_over_10ms",
        "counter",
        "Sends that waited over 10 ms for RX channel capacity",
        entries,
        |e| tunnel_bridge_counter(e, |c| c.ipsend_waits_over_10ms.load(Ordering::Relaxed)),
    );
    write_tunnel_metric(
        out,
        "wpmulti_tunnel_rx_depth_max",
        "gauge",
        "Deepest RX channel occupancy observed (packets waiting for smoltcp)",
        entries,
        |e| tunnel_bridge_counter(e, |c| c.rx_depth_max.load(Ordering::Relaxed) as u64),
    );
}
