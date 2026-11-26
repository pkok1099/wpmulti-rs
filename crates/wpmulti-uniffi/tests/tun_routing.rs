//! Tests for the TUN adapter's pure routing pieces: 5-tuple parsing,
//! flow-table pinning + expiry, `AllowedIPs` longest-prefix match,
//! and DNS classification.
//!
//! All packets below are hand-built synthetic bytes; no real tunnel
//! credentials are involved.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::time::Duration;

use wpmulti::{
    FLOW_IDLE_TIMEOUT, FlowKey, FlowRoute, FlowTable, TunRoute, longest_prefix_route,
    parse_flow_key,
};

/// Test-local equivalent of the planned `route_packet` helper (pinned-flow
/// lookup, else longest-prefix match + pin). The library exposes the pieces
/// (`FlowTable::lookup`/`insert`, `longest_prefix_route`); this composes
/// them the way the dispatcher does, without adding production API.
fn route_packet(key: &FlowKey, routes: &[TunRoute], flows: &mut FlowTable) -> Option<String> {
    if let Some(pinned) = flows.lookup(key) {
        return Some(pinned.tunnel_id);
    }
    let id = longest_prefix_route(key.dst, routes)?;
    flows.insert(
        *key,
        FlowRoute {
            tunnel_id: id.clone(),
            orig_src: key.src,
            nat_src: key.src,
        },
    );
    Some(id)
}

/// Build a minimal IPv4 header + payload. `proto` is the IP protocol
/// number; `src_port`/`dst_port` are written at the transport offset
/// for TCP/UDP, ignored otherwise.
fn ipv4_packet(src: [u8; 4], dst: [u8; 4], proto: u8, src_port: u16, dst_port: u16) -> Vec<u8> {
    let mut packet = vec![0u8; 24];
    packet[0] = 0x45;
    packet[2] = 0;
    packet[3] = 24;
    packet[8] = 64;
    packet[9] = proto;
    packet[12..16].copy_from_slice(&src);
    packet[16..20].copy_from_slice(&dst);
    packet[20..22].copy_from_slice(&src_port.to_be_bytes());
    packet[22..24].copy_from_slice(&dst_port.to_be_bytes());
    packet
}

/// Build a minimal IPv6 header + payload.
fn ipv6_packet(src: [u8; 16], dst: [u8; 16], proto: u8, src_port: u16, dst_port: u16) -> Vec<u8> {
    let mut packet = vec![0u8; 44];
    packet[0] = 0x60;
    packet[4] = 0;
    packet[5] = 4;
    packet[6] = proto;
    packet[7] = 64;
    packet[8..24].copy_from_slice(&src);
    packet[24..40].copy_from_slice(&dst);
    packet[40..42].copy_from_slice(&src_port.to_be_bytes());
    packet[42..44].copy_from_slice(&dst_port.to_be_bytes());
    packet
}

fn route(id: &str, networks: &[&str]) -> TunRoute {
    TunRoute {
        id: id.to_string(),
        // No `.expect()` here: clippy's `expect_used` is denied and this
        // helper is not itself a `#[test]` fn, so a parse failure must not
        // panic. The literals below are all valid; a bad one would surface
        // as a failed routing assertion instead of a parse error.
        allowed_ips: networks.iter().filter_map(|net| net.parse().ok()).collect(),
        interface_addrs: vec![],
    }
}

#[test]
fn parse_ipv4_udp_flow_key() {
    let packet = ipv4_packet([10, 0, 0, 2], [8, 8, 8, 8], 17, 12345, 53);
    let key = parse_flow_key(&packet).expect("valid IPv4 UDP packet");
    assert_eq!(key.src, IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)));
    assert_eq!(key.dst, IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)));
    assert_eq!(key.src_port, 12345);
    assert_eq!(key.dst_port, 53);
    assert_eq!(key.proto, 17);
    assert!(key.is_dns(), "UDP to port 53 must classify as DNS");
}

#[test]
fn parse_ipv4_tcp_and_icmp_flow_keys() {
    let tcp = ipv4_packet([10, 0, 0, 2], [1, 1, 1, 1], 6, 40000, 443);
    let key = parse_flow_key(&tcp).expect("valid IPv4 TCP packet");
    assert_eq!((key.src_port, key.dst_port, key.proto), (40000, 443, 6));
    assert!(!key.is_dns(), "TCP to 443 is not DNS");

    let icmp = ipv4_packet([10, 0, 0, 2], [1, 1, 1, 1], 1, 0, 0);
    let key = parse_flow_key(&icmp).expect("valid IPv4 ICMP packet");
    assert_eq!((key.src_port, key.dst_port, key.proto), (0, 0, 1));
    assert!(!key.is_dns());
}

#[test]
fn parse_ipv6_udp_flow_key_and_dns() {
    let src: [u8; 16] = Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 2).octets();
    let dst: [u8; 16] = Ipv6Addr::new(0x2606, 0x4700, 0x4700, 0, 0, 0, 0, 0x1111).octets();
    let packet = ipv6_packet(src, dst, 17, 54321, 53);
    let key = parse_flow_key(&packet).expect("valid IPv6 UDP packet");
    assert_eq!(key.src, IpAddr::V6(Ipv6Addr::from(src)));
    assert_eq!(key.dst, IpAddr::V6(Ipv6Addr::from(dst)));
    assert_eq!((key.src_port, key.dst_port, key.proto), (54321, 53, 17));
    assert!(key.is_dns());

    let not_dns = ipv6_packet(src, dst, 17, 54321, 443);
    let key = parse_flow_key(&not_dns).expect("valid IPv6 UDP packet");
    assert!(!key.is_dns(), "UDP to 443 is not DNS");
}

#[test]
fn parse_rejects_garbage() {
    assert!(parse_flow_key(&[]).is_none(), "empty input");
    assert!(parse_flow_key(&[0x45]).is_none(), "truncated header");
    assert!(
        parse_flow_key(&[
            0x70, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
        ])
        .is_none(),
        "unknown IP version 7"
    );
    assert!(
        parse_flow_key(&ipv4_packet([10, 0, 0, 2], [8, 8, 8, 8], 17, 1, 53)[..10]).is_none(),
        "truncated IPv4 header"
    );
}

#[test]
fn longest_prefix_wins_and_first_tiebreaks() {
    let routes = vec![
        route("wgcf-001", &["0.0.0.0/0"]),
        route("wgcf-002", &["10.0.0.0/8"]),
        route("wgcf-003", &["0.0.0.0/0"]),
    ];
    assert_eq!(
        longest_prefix_route("10.1.2.3".parse().unwrap(), &routes).as_deref(),
        Some("wgcf-002"),
        "the /8 must beat the /0 for 10.1.2.3"
    );
    assert_eq!(
        longest_prefix_route("8.8.8.8".parse().unwrap(), &routes).as_deref(),
        Some("wgcf-001"),
        "tied /0 routes keep the first in registration order"
    );
    assert_eq!(
        longest_prefix_route("2001:db8::1".parse().unwrap(), &routes),
        None,
        "no IPv6 route covers the address"
    );

    let v6_routes = vec![
        route("wgcf-v6", &["::/0"]),
        route("wgcf-v6-sub", &["2001:db8::/32"]),
    ];
    assert_eq!(
        longest_prefix_route("2001:db8::1".parse().unwrap(), &v6_routes).as_deref(),
        Some("wgcf-v6-sub")
    );
}

#[test]
fn flow_table_pins_and_expires() {
    let packet = ipv4_packet([10, 0, 0, 2], [10, 1, 2, 3], 6, 40000, 443);
    let key = parse_flow_key(&packet).expect("valid packet");
    let routes = vec![route("wgcf-001", &["0.0.0.0/0"])];

    let mut flows = FlowTable::new(Duration::from_millis(50));
    assert_eq!(
        route_packet(&key, &routes, &mut flows).as_deref(),
        Some("wgcf-001")
    );
    assert_eq!(flows.len(), 1);

    // Re-route with the /0 now pointing elsewhere: the flow pin wins.
    let moved = vec![route("wgcf-002", &["0.0.0.0/0"])];
    assert_eq!(
        route_packet(&key, &moved, &mut flows).as_deref(),
        Some("wgcf-001"),
        "pinned flow must keep its original tunnel"
    );

    // After the idle timeout the pin expires and the new route applies.
    std::thread::sleep(Duration::from_millis(60));
    assert_eq!(
        route_packet(&key, &moved, &mut flows).as_deref(),
        Some("wgcf-002")
    );

    // A lookup of an expired entry is a miss, and prune drops it.
    let mut stale = FlowTable::new(Duration::from_millis(1));
    stale.insert(
        key,
        FlowRoute {
            tunnel_id: "wgcf-001".to_string(),
            orig_src: key.src,
            nat_src: key.src,
        },
    );
    std::thread::sleep(Duration::from_millis(2));
    assert_eq!(stale.lookup(&key), None);
    stale.insert(
        key,
        FlowRoute {
            tunnel_id: "wgcf-001".to_string(),
            orig_src: key.src,
            nat_src: key.src,
        },
    );
    std::thread::sleep(Duration::from_millis(2));
    stale.prune_expired();
    assert!(stale.is_empty());
    assert_eq!(
        FLOW_IDLE_TIMEOUT,
        Duration::from_secs(60),
        "default flow idle timeout is 60s"
    );
}

#[test]
fn route_packet_returns_none_without_route() {
    let packet = ipv4_packet([10, 0, 0, 2], [8, 8, 8, 8], 17, 1234, 53);
    let key = parse_flow_key(&packet).expect("valid packet");
    let mut flows = FlowTable::default();
    assert_eq!(
        route_packet(&key, &[], &mut flows),
        None,
        "no route means the packet is dropped"
    );
    assert!(flows.is_empty(), "a dropped packet pins no flow");
}
