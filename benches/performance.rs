//! Milestone 1 Performance Benchmarks
//!
//! Measures performance improvements across the 4 key optimized subsystems:
//! 1. Virtual TUN bridge packet throughput and recycled buffer allocations
//! 2. HTTP request header chunked parsing vs 1-byte read loop
//! 3. MultiTenantRouter tunnel selection with zero-copy Arc<[String]> and O(1) indexed lookup
//! 4. In-tunnel DNS resolution encoding and DnsLruCache concurrent throughput

#![allow(
    unreachable_pub,
    unused_qualifications,
    trivial_casts,
    clippy::pedantic,
    clippy::nursery,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::large_futures,
    clippy::type_complexity,
    clippy::wildcard_enum_match_arm,
    clippy::too_many_arguments,
    clippy::print_stdout
)]
#![warn(clippy::too_many_lines, clippy::cognitive_complexity)]

use std::collections::HashMap;
use std::io::Cursor;
use std::sync::Arc;
use std::time::Instant;

use etherparse::PacketBuilder;
use gotatun::tun::{IpRecv, IpSend};
use smoltcp::phy::{Device, RxToken, TxToken};
use tokio::io::AsyncReadExt;
use x25519_dalek::{PublicKey, StaticSecret};
use zerocopy::IntoBytes;

use wpmulti::config::{LifecycleMode, PoolStrategy, TunnelConfig, WgInterfaceConfig, WgPeerConfig};
use wpmulti::core::lifecycle::LifecycleController;
use wpmulti::core::registry::{TunnelEntry, TunnelRegistry};
use wpmulti::core::router::MultiTenantRouter;
use wpmulti::netstack::bridge::{DEFAULT_MTU, VirtualTunBridge};
use wpmulti::netstack::dns::{DnsLruCache, QueryType, build_query};
use wpmulti::proxy::http::read_http_request_headers_buffered;
use wpmulti::proxy::{PoolKeyword, TunnelRouter, TunnelSelector};

fn make_bench_tunnel_config(id: &str) -> TunnelConfig {
    let iface = WgInterfaceConfig {
        private_key: StaticSecret::from([7u8; 32]),
        addresses: vec!["172.16.0.2/32".parse().unwrap()],
        dns: vec!["1.1.1.1".parse().unwrap()],
        listen_port: None,
        mtu: 1420,
    };
    let peer = WgPeerConfig {
        public_key: PublicKey::from([8u8; 32]),
        endpoint: "127.0.0.1:51820".to_string(),
        allowed_ips: vec!["0.0.0.0/0".parse().unwrap()],
        preshared_key: None,
        persistent_keepalive: None,
    };
    TunnelConfig {
        id: id.to_string(),
        interface: iface,
        peers: vec![peer],
    }
}

/// Baseline 1-byte read loop for HTTP header parsing comparison.
async fn baseline_read_http_headers<R: AsyncReadExt + Unpin>(
    reader: &mut R,
) -> std::io::Result<(String, String, String, HashMap<String, String>)> {
    let mut buf = Vec::with_capacity(512);
    let mut single = [0u8; 1];

    loop {
        let n = reader.read(&mut single).await?;
        if n == 0 {
            break;
        }
        buf.push(single[0]);
        if buf.ends_with(b"\r\n\r\n") {
            break;
        }
    }

    let text = String::from_utf8_lossy(&buf);
    let mut lines = text.split("\r\n");
    let req_line = lines.next().unwrap_or("");
    let mut parts = req_line.split_whitespace();
    let method = parts.next().unwrap_or("").to_string();
    let uri = parts.next().unwrap_or("").to_string();
    let version = parts.next().unwrap_or("").to_string();

    let mut headers = HashMap::new();
    for line in lines {
        if line.is_empty() {
            continue;
        }
        if let Some((k, v)) = line.split_once(':') {
            headers.insert(k.trim().to_ascii_lowercase(), v.trim().to_string());
        }
    }

    Ok((method, uri, version, headers))
}

#[tokio::main]
async fn main() {
    println!("===============================================================================");
    println!("                    WPMULTI MILESTONE 1 BENCHMARK SUITE                        ");
    println!("===============================================================================\n");

    // -------------------------------------------------------------------------
    // Benchmark 1: Virtual TUN Bridge Packet Throughput & Recycling
    // -------------------------------------------------------------------------
    println!(">>> Running Benchmark 1: Virtual TUN Bridge Packet Throughput & Recycling...");
    let packet_count = 50_000usize;

    // Build sample 28-byte IPv4 UDP packet
    let builder = PacketBuilder::ipv4([10, 0, 0, 1], [10, 0, 0, 2], 64).udp(1234, 5678);
    let mut raw_packet = Vec::new();
    builder
        .write(&mut raw_packet, b"BENCHMARK_PAYLOAD_DATA")
        .unwrap();
    let packet_size = raw_packet.len();

    let (mut bridge, mut bridge_tx, mut bridge_rx) = VirtualTunBridge::new(DEFAULT_MTU, 1024);
    let mut pool = gotatun::packet::PacketBufPool::<4096>::new(64);

    // smoltcp TX pipeline: transmit -> bridge_rx
    let start_tx = Instant::now();
    for _ in 0..packet_count {
        let now = smoltcp::time::Instant::now();
        let tx_token = bridge.transmit(now).expect("tx token available");
        tx_token.consume(packet_size, |buf| {
            buf.copy_from_slice(&raw_packet);
        });

        let mut packets = bridge_rx.recv(&mut pool).await.unwrap();
        let pkt = packets.next().expect("packet received");
        assert_eq!((*pkt).as_bytes().len(), packet_size);
    }
    let elapsed_bridge_tx = start_tx.elapsed();
    let bridge_tx_rate = packet_count as f64 / elapsed_bridge_tx.as_secs_f64();
    let bridge_tx_mb =
        (packet_count * packet_size) as f64 / (1024.0 * 1024.0) / elapsed_bridge_tx.as_secs_f64();

    // smoltcp RX pipeline: bridge_tx -> receive
    let start_rx = Instant::now();
    for _ in 0..packet_count {
        let mut pkt = pool.get();
        pkt.truncate(packet_size);
        pkt.copy_from_slice(&raw_packet);
        let ip_pkt = pkt.try_into_ip().unwrap();
        bridge_tx.send(ip_pkt).await.unwrap();

        let now = smoltcp::time::Instant::now();
        let (rx_token, _) = bridge.receive(now).expect("packet received");
        rx_token.consume(|buf| {
            assert_eq!(buf.len(), packet_size);
        });
    }
    let elapsed_bridge_rx = start_rx.elapsed();
    let bridge_rx_rate = packet_count as f64 / elapsed_bridge_rx.as_secs_f64();
    let bridge_rx_mb =
        (packet_count * packet_size) as f64 / (1024.0 * 1024.0) / elapsed_bridge_rx.as_secs_f64();

    println!(
        "  * smoltcp TX -> Bridge RX:   {:.2} packets/s ({:.2} MB/s) [Elapsed: {:.2?}]",
        bridge_tx_rate, bridge_tx_mb, elapsed_bridge_tx
    );
    println!(
        "  * Bridge TX -> smoltcp RX:   {:.2} packets/s ({:.2} MB/s) [Elapsed: {:.2?}]",
        bridge_rx_rate, bridge_rx_mb, elapsed_bridge_rx
    );

    // -------------------------------------------------------------------------
    // Benchmark 2: HTTP Header Parsing (Chunked Buffered vs 1-Byte Read)
    // -------------------------------------------------------------------------
    println!("\n>>> Running Benchmark 2: HTTP Request Header Parsing...");
    let http_req = b"GET http://example.com/api/v1/resource HTTP/1.1\r\n\
                     Host: example.com\r\n\
                     User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64)\r\n\
                     Accept: application/json, text/plain, */*\r\n\
                     Accept-Encoding: gzip, deflate, br\r\n\
                     Authorization: Basic dXNlcjpwYXNz\r\n\
                     Proxy-Connection: keep-alive\r\n\r\n";
    let iterations = 10_000usize;

    // Baseline 1-byte read
    let start_base = Instant::now();
    for _ in 0..iterations {
        let mut cursor = Cursor::new(http_req);
        let (method, uri, _, headers) = baseline_read_http_headers(&mut cursor).await.unwrap();
        assert_eq!(method, "GET");
        assert_eq!(uri, "http://example.com/api/v1/resource");
        assert_eq!(headers.get("host").map(|s| s.as_str()), Some("example.com"));
    }
    let elapsed_base = start_base.elapsed();
    let base_rate = iterations as f64 / elapsed_base.as_secs_f64();

    // Optimized chunked buffered read
    let start_opt = Instant::now();
    for _ in 0..iterations {
        let mut cursor = Cursor::new(http_req);
        let (method, uri, _, headers, _) = read_http_request_headers_buffered(&mut cursor)
            .await
            .unwrap();
        assert_eq!(method, "GET");
        assert_eq!(uri, "http://example.com/api/v1/resource");
        assert_eq!(headers.get("host").map(|s| s.as_str()), Some("example.com"));
    }
    let elapsed_opt = start_opt.elapsed();
    let opt_rate = iterations as f64 / elapsed_opt.as_secs_f64();
    let speedup = elapsed_base.as_secs_f64() / elapsed_opt.as_secs_f64();

    println!(
        "  * Baseline (1-byte read):    {:.2} req/s [Elapsed: {:.2?}]",
        base_rate, elapsed_base
    );
    println!(
        "  * Optimized (chunked read):  {:.2} req/s [Elapsed: {:.2?}]",
        opt_rate, elapsed_opt
    );
    println!("  * Speedup Factor:            {:.2}x faster", speedup);

    // -------------------------------------------------------------------------
    // Benchmark 3: MultiTenantRouter Tunnel Selection
    // -------------------------------------------------------------------------
    println!("\n>>> Running Benchmark 3: MultiTenantRouter Tunnel Selection (245 Tunnels)...");
    let router_selections = 100_000usize;
    let registry = Arc::new(TunnelRegistry::new());
    for i in 0..245 {
        let tid = format!("wgcf-{:03}", i);
        let cfg = make_bench_tunnel_config(&tid);
        let entry = TunnelEntry::new(&tid, cfg, LifecycleMode::Lazy);
        registry.register(entry).unwrap();
    }

    let lifecycle = LifecycleController::new(
        Arc::clone(&registry),
        std::time::Duration::from_secs(60),
        std::time::Duration::from_secs(1),
    );

    let router = MultiTenantRouter::new(
        Arc::clone(&lifecycle),
        Arc::clone(&registry),
        PoolStrategy::RoundRobin,
        true,
    );
    let selector = TunnelSelector::ByKeyword(PoolKeyword::RoundRobin);

    // Measure candidate lookup + round-robin selection
    let start_router = Instant::now();
    for _ in 0..router_selections {
        let _ = router.select_tunnel(&selector).await;
    }
    let elapsed_router = start_router.elapsed();
    let router_rate = router_selections as f64 / elapsed_router.as_secs_f64();
    let router_lat_ns = (elapsed_router.as_nanos() as f64) / (router_selections as f64);

    println!(
        "  * Router Throughput:         {:.2} selections/s",
        router_rate
    );
    println!(
        "  * Average Selection Latency: {:.2} ns/selection",
        router_lat_ns
    );

    // -------------------------------------------------------------------------
    // Benchmark 4: DNS Resolution Encoding & Concurrent LRU Cache
    // -------------------------------------------------------------------------
    println!("\n>>> Running Benchmark 4: DNS Query Encoding & Concurrent LRU Cache...");
    let dns_ops = 100_000usize;
    let cache = Arc::new(DnsLruCache::new(4096));

    // Pre-populate 100 domains
    for i in 0..100 {
        let domain = format!("host-{}.internal.example.org", i);
        cache.insert(&domain, vec!["93.184.216.34".parse().unwrap()], 300);
    }

    // Benchmark concurrent cache reads across 4 tokio tasks
    let start_dns = Instant::now();
    let mut tasks = Vec::new();
    for _ in 0..4 {
        let c = Arc::clone(&cache);
        let per_task = dns_ops / 4;
        tasks.push(tokio::spawn(async move {
            for i in 0..per_task {
                let domain = format!("host-{}.internal.example.org", i % 100);
                let hit = c.get(&domain);
                assert!(hit.is_some());
            }
        }));
    }
    for t in tasks {
        t.await.unwrap();
    }
    let elapsed_dns = start_dns.elapsed();
    let dns_rate = dns_ops as f64 / elapsed_dns.as_secs_f64();
    let dns_lat_ns = (elapsed_dns.as_nanos() as f64) / (dns_ops as f64);

    // DNS query wire encoding benchmark
    let start_enc = Instant::now();
    for i in 0..dns_ops {
        let domain = format!("test-{}.domain.example.com", i % 500);
        let _ = build_query(&domain, QueryType::A, (i % 65535) as u16);
    }
    let elapsed_enc = start_enc.elapsed();
    let enc_rate = dns_ops as f64 / elapsed_enc.as_secs_f64();

    println!(
        "  * DNS LRU Cache (4 threads): {:.2} lookups/s ({:.2} ns/lookup)",
        dns_rate, dns_lat_ns
    );
    println!("  * DNS Query Encoding:        {:.2} queries/s", enc_rate);

    // -------------------------------------------------------------------------
    // Summary Table
    // -------------------------------------------------------------------------
    println!("\n===============================================================================");
    println!("                          BENCHMARK SUMMARY RESULTS                            ");
    println!("===============================================================================");
    println!(
        "| Subsystem                      | Operations   | Elapsed     | Rate / Speedup       |"
    );
    println!(
        "|--------------------------------|--------------|-------------|----------------------|"
    );
    println!(
        "| 1. smoltcp TX -> Bridge RX     | {:>12} | {:>11.2?} | {:>14.2} pkts/s |",
        packet_count, elapsed_bridge_tx, bridge_tx_rate
    );
    println!(
        "| 1. Bridge TX -> smoltcp RX     | {:>12} | {:>11.2?} | {:>14.2} pkts/s |",
        packet_count, elapsed_bridge_rx, bridge_rx_rate
    );
    println!(
        "| 2. HTTP Header Baseline (1B)   | {:>12} | {:>11.2?} | {:>14.2} reqs/s |",
        iterations, elapsed_base, base_rate
    );
    println!(
        "| 2. HTTP Header Chunked (1KB)   | {:>12} | {:>11.2?} | {:>10.2} req/s ({:.1}x) |",
        iterations, elapsed_opt, opt_rate, speedup
    );
    println!(
        "| 3. MultiTenantRouter (245 tun) | {:>12} | {:>11.2?} | {:>14.2} ops/s  |",
        router_selections, elapsed_router, router_rate
    );
    println!(
        "| 4. DNS LRU Cache Concurrent    | {:>12} | {:>11.2?} | {:>14.2} hits/s |",
        dns_ops, elapsed_dns, dns_rate
    );
    println!(
        "| 4. DNS Wire Query Encoding     | {:>12} | {:>11.2?} | {:>14.2} pkts/s |",
        dns_ops, elapsed_enc, enc_rate
    );
    println!("===============================================================================\n");
}
