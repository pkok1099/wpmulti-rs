//! Loopback destination guard tests (RFC 1122: loopback never rides the tunnel).

use std::net::SocketAddr;

use x25519_dalek::StaticSecret;

use crate::config::WgInterfaceConfig;
use crate::netstack::bridge::{DEFAULT_MTU, VirtualTunBridge};
use crate::netstack::stack::VirtualNetworkStack;

fn make_test_config(v4: &str, v6: Option<&str>) -> WgInterfaceConfig {
    let mut addrs = vec![v4.parse().unwrap()];
    if let Some(v6_str) = v6 {
        addrs.push(v6_str.parse().unwrap());
    }
    WgInterfaceConfig {
        private_key: StaticSecret::from([1u8; 32]),
        addresses: addrs,
        dns: vec!["1.1.1.1".parse().unwrap()],
        listen_port: None,
        mtu: DEFAULT_MTU,
    }
}

#[tokio::test]
async fn test_stack_rejects_loopback_tcp_connect() {
    let config = make_test_config("10.7.0.2/32", Some("fd00:7::2/128"));
    let (bridge, _ip_send, _ip_recv) = VirtualTunBridge::new(DEFAULT_MTU, 64);
    let stack = VirtualNetworkStack::new_with_mode(
        &config,
        bridge,
        crate::config::IpMode::DualStack,
        false,
    )
    .unwrap();

    // IPv4 loopback, IPv6 loopback, and IPv4-mapped loopback all fail fast
    // with AddrNotAvailable instead of hanging until the connect timeout.
    for dst in [
        "127.0.0.1:80".parse::<SocketAddr>().unwrap(),
        "127.200.13.9:8080".parse().unwrap(),
        "[::1]:443".parse().unwrap(),
        "[::ffff:127.0.0.1]:80".parse().unwrap(),
    ] {
        let err = stack.tcp_connect(dst).await.unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::AddrNotAvailable, "{dst}");
        assert!(err.to_string().contains("loopback"), "{dst}: {err}");
    }

    stack.close().await;
}

#[tokio::test]
async fn test_stack_rejects_loopback_udp_send_to() {
    let config = make_test_config("10.8.0.2/32", Some("fd00:8::2/128"));
    let (bridge, _ip_send, _ip_recv) = VirtualTunBridge::new(DEFAULT_MTU, 64);
    let stack = VirtualNetworkStack::new_with_mode(
        &config,
        bridge,
        crate::config::IpMode::DualStack,
        false,
    )
    .unwrap();
    let udp_sock = stack.udp_bind(0).unwrap();

    for target in [
        "127.0.0.1:53".parse::<SocketAddr>().unwrap(),
        "[::1]:53".parse().unwrap(),
        "[::ffff:127.0.0.1]:53".parse().unwrap(),
    ] {
        let err = udp_sock.send_to(b"query", target).await.unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::AddrNotAvailable, "{target}");
    }

    // A non-loopback destination is unaffected and reaches the bridge channel.
    let public_dst: SocketAddr = "1.1.1.1:53".parse().unwrap();
    assert_eq!(udp_sock.send_to(b"query", public_dst).await.unwrap(), 5);

    stack.close().await;
}

#[test]
fn test_reject_loopback_dst_helper() {
    use crate::netstack::stack::reject_loopback_dst;

    for loopback in [
        "127.0.0.1:1".parse::<SocketAddr>().unwrap(),
        "127.255.255.254:65535".parse().unwrap(),
        "[::1]:1".parse().unwrap(),
        "[::ffff:127.0.0.2]:1".parse().unwrap(),
    ] {
        assert!(reject_loopback_dst(loopback).is_err(), "{loopback}");
    }
    for reachable in [
        "10.0.0.1:1".parse::<SocketAddr>().unwrap(),
        "192.168.1.1:1".parse().unwrap(),
        "1.1.1.1:1".parse().unwrap(),
        "[2606:4700:4700::1111]:1".parse().unwrap(),
        "[::ffff:1.1.1.1]:1".parse().unwrap(),
    ] {
        assert!(reject_loopback_dst(reachable).is_ok(), "{reachable}");
    }
}
