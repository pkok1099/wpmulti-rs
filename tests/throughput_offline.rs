//! Offline throughput test for the SOCKS5 proxy data plane.
//!
//! Everything is fake/local — no internet, no real WireGuard peer, no real
//! DNS server:
//!
//! * **Fake DNS**: [`FakeDnsTarget`] answers every domain instantly with the
//!   TEST-NET-1 stand-in (`192.0.2.1`, see [`TEST_ECHO_IP`]); the TCP dial
//!   then redirects to the loopback echo listener, exactly like
//!   [`EchoRedirectTarget`] does for TCP.
//! * **Fake requests**: synthetic payloads (deterministic byte pattern) are
//!   pumped through SOCKS5 CONNECT and echoed back by a loopback server.
//! * **Measurement**: wall time + process CPU time (`/proc/self/stat`,
//!   Linux) are reported, so a throughput optimisation can be judged by
//!   "same Mbps at less CPU" instead of by wall time alone.
//!
//! Run it with output visible:
//!
//! ```sh
//! cargo test --test throughput_offline -- --nocapture
//! ```
//!
//! Tune the load with env vars (defaults: 8 connections x 8 MiB, 64 KiB
//! chunks): `THROUGHPUT_CONNECTIONS`, `THROUGHPUT_BYTES_PER_CONN`,
//! `THROUGHPUT_CHUNK_BYTES`.
//!
//! The test asserts correctness only (every byte echoed back, fake DNS was
//! actually used). It asserts no throughput floor: CI runners vary too much
//! for a threshold to be meaningful — read the printed numbers instead.

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
    reason = "test builds: fixtures and helpers need looser lints"
)]
#![warn(clippy::too_many_lines, clippy::cognitive_complexity)]

mod common;

use std::future::Future;
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use common::{METHOD_NO_AUTH, Socks5TestClient, TEST_ECHO_IP};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use wpmulti::proxy::{
    DirectTunnelTarget, DynStream, ProxyTunnelTarget, ProxyUdpSocket, SingleTunnelRouter,
    TunnelRouter, handle_socks5_with_addrs,
};

/// Domain the load generator CONNECTs to. It does not exist anywhere; the
/// fake DNS below answers it instantly.
const FAKE_DOMAIN: &str = "echo.fake";

/// Overall wall-clock budget for the load phase. A hang must fail the test
/// instead of hanging CI forever.
const LOAD_TIMEOUT: Duration = Duration::from_secs(120);

fn env_usize(name: &str, default: usize) -> usize {
    std::env::var(name)
        .ok()
        .and_then(|v| v.parse().ok())
        .filter(|v| *v > 0)
        .unwrap_or(default)
}

/// Tunnel target with **fake DNS**: every domain resolves instantly to the
/// TEST-NET-1 stand-in (which passes the destination guard), and the TCP
/// dial redirects to the loopback echo listener regardless of the named
/// destination. No real resolver is ever consulted.
struct FakeDnsTarget {
    echo: SocketAddr,
    dns_queries: AtomicUsize,
    direct: DirectTunnelTarget,
}

impl FakeDnsTarget {
    fn new(echo: SocketAddr) -> Self {
        Self {
            echo,
            dns_queries: AtomicUsize::new(0),
            direct: DirectTunnelTarget,
        }
    }

    fn dns_queries(&self) -> usize {
        self.dns_queries.load(Ordering::Relaxed)
    }
}

impl ProxyTunnelTarget for FakeDnsTarget {
    fn tcp_connect<'a>(
        &'a self,
        _dst: SocketAddr,
    ) -> Pin<Box<dyn Future<Output = io::Result<DynStream>> + Send + 'a>> {
        let echo = self.echo;
        Box::pin(async move {
            let stream: DynStream = Box::new(TcpStream::connect(echo).await?);
            Ok(stream)
        })
    }

    fn udp_bind<'a>(
        &'a self,
        local_port: u16,
    ) -> Pin<Box<dyn Future<Output = io::Result<Box<dyn ProxyUdpSocket>>> + Send + 'a>> {
        self.direct.udp_bind(local_port)
    }

    fn resolve_in_tunnel<'a>(
        &'a self,
        _domain: &'a str,
    ) -> Pin<Box<dyn Future<Output = io::Result<IpAddr>> + Send + 'a>> {
        self.dns_queries.fetch_add(1, Ordering::Relaxed);
        Box::pin(async move { Ok(TEST_ECHO_IP) })
    }

    fn resolve_all_in_tunnel<'a>(
        &'a self,
        _domain: &'a str,
    ) -> Pin<Box<dyn Future<Output = io::Result<Vec<IpAddr>>> + Send + 'a>> {
        self.dns_queries.fetch_add(1, Ordering::Relaxed);
        Box::pin(async move { Ok(vec![TEST_ECHO_IP]) })
    }
}

/// Process CPU time (user + system) in seconds, from `/proc/self/stat`
/// fields 14+15. Linux-only; `None` elsewhere. `CLK_TCK` is 100 on Linux.
fn proc_cpu_seconds() -> Option<f64> {
    let stat = std::fs::read_to_string("/proc/self/stat").ok()?;
    let after_comm = stat.rsplit_once(')')?.1;
    let fields: Vec<&str> = after_comm.split_whitespace().collect();
    // After `(comm)`: fields[0] is stat field 3 (state), so utime (14)
    // is fields[11] and stime (15) is fields[12].
    let utime: f64 = fields.get(11)?.parse().ok()?;
    let stime: f64 = fields.get(12)?.parse().ok()?;
    Some((utime + stime) / 100.0)
}

/// Deterministic payload chunk: byte `i` is `(offset + i) mod 251`, so the
/// reader can verify content without storing the whole stream.
fn fill_chunk(buf: &mut [u8], offset: usize) {
    for (i, b) in buf.iter_mut().enumerate() {
        *b = ((offset + i) % 251) as u8;
    }
}

fn verify_chunk(buf: &[u8], offset: usize) {
    for (i, b) in buf.iter().enumerate() {
        assert_eq!(
            *b,
            ((offset + i) % 251) as u8,
            "echoed payload corrupted at offset {}",
            offset + i
        );
    }
}

async fn run_load(
    proxy_addr: SocketAddr,
    echo_port: u16,
    connections: usize,
    bytes_per_conn: usize,
    chunk: usize,
    received: Arc<AtomicUsize>,
) -> usize {
    let mut tasks = tokio::task::JoinSet::new();
    for _ in 0..connections {
        let received = Arc::clone(&received);
        tasks.spawn(async move {
            let mut client = Socks5TestClient::connect(proxy_addr).await.unwrap();
            client.greeting(&[METHOD_NO_AUTH]).await.unwrap();
            let stream = client
                .cmd_connect_domain(FAKE_DOMAIN, echo_port)
                .await
                .unwrap();
            let (mut rd, mut wr) = stream.into_split();

            let total = bytes_per_conn;
            let writer = tokio::spawn(async move {
                let mut buf = vec![0u8; chunk];
                let mut sent = 0usize;
                while sent < total {
                    let n = (total - sent).min(chunk);
                    fill_chunk(&mut buf[..n], sent);
                    wr.write_all(&buf[..n]).await.unwrap();
                    sent += n;
                }
                wr.shutdown().await.unwrap();
            });
            let reader = tokio::spawn(async move {
                let mut buf = vec![0u8; chunk];
                let mut received_bytes = 0usize;
                while received_bytes < total {
                    let n = (total - received_bytes).min(chunk);
                    rd.read_exact(&mut buf[..n]).await.unwrap();
                    verify_chunk(&buf[..n], received_bytes);
                    received_bytes += n;
                    received.fetch_add(n, Ordering::Relaxed);
                }
                received_bytes
            });
            let (w, r) = tokio::join!(writer, reader);
            w.unwrap();
            r.unwrap()
        });
    }
    let mut total = 0usize;
    while let Some(res) = tasks.join_next().await {
        total += res.unwrap();
    }
    total
}

/// Loopback echo server: reads everything and writes it back.
async fn spawn_echo_server() -> SocketAddr {
    let echo_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let echo_addr = echo_listener.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let Ok((stream, _)) = echo_listener.accept().await else {
                return;
            };
            tokio::spawn(async move {
                let (mut rd, mut wr) = stream.into_split();
                let _ = tokio::io::copy(&mut rd, &mut wr).await;
            });
        }
    });
    echo_addr
}

/// SOCKS5 proxy backed by the fake-DNS tunnel target.
async fn spawn_proxy_server(target: Arc<FakeDnsTarget>) -> SocketAddr {
    let router_target = Arc::clone(&target) as Arc<dyn ProxyTunnelTarget>;
    let router: Arc<dyn TunnelRouter> = Arc::new(SingleTunnelRouter::new(
        "throughput-offline",
        router_target,
        None,
    ));
    let proxy_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let proxy_addr = proxy_listener.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let Ok((stream, peer_addr)) = proxy_listener.accept().await else {
                return;
            };
            let router = Arc::clone(&router);
            tokio::spawn(async move {
                let local_ip = stream.local_addr().ok().map(|a| a.ip());
                let _ =
                    handle_socks5_with_addrs(stream, router, local_ip, Some(peer_addr.ip())).await;
            });
        }
    });
    proxy_addr
}

/// Prints received-bytes progress every 5 s until the load finishes.
fn start_progress_reporter(
    received: Arc<AtomicUsize>,
    expected_total: usize,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let start = Instant::now();
        loop {
            tokio::time::sleep(Duration::from_secs(5)).await;
            let got = received.load(Ordering::Relaxed);
            eprintln!(
                "[throughput-offline] progress: {got}/{expected_total} bytes ({:.1}%) after {:.1}s",
                got as f64 / expected_total as f64 * 100.0,
                start.elapsed().as_secs_f64()
            );
            if got >= expected_total {
                return;
            }
        }
    })
}

fn print_report(
    connections: usize,
    bytes_per_conn: usize,
    chunk: usize,
    cpus: usize,
    dns_queries: usize,
    total_bytes: usize,
    elapsed: Duration,
    cpu_before: Option<f64>,
    cpu_after: Option<f64>,
) {
    let secs = elapsed.as_secs_f64();
    let mbps = (total_bytes as f64 * 8.0) / (secs * 1_000_000.0);
    println!(
        "[throughput-offline] connections={connections} bytes_per_conn={bytes_per_conn} chunk={chunk} cpus={cpus}"
    );
    println!("[throughput-offline] fake DNS queries served: {dns_queries}");
    println!(
        "[throughput-offline] total={total_bytes} bytes elapsed={secs:.3}s throughput={mbps:.1} Mbps ({:.1} Mbps/conn)",
        mbps / connections as f64
    );
    match (cpu_before, cpu_after) {
        (Some(before), Some(after)) => {
            let cpu = after - before;
            println!(
                "[throughput-offline] process CPU={cpu:.2}s cpu/wall={:.0}% (all cores); {:.0}% of one core per core-count",
                cpu / secs * 100.0,
                cpu / secs / cpus as f64 * 100.0
            );
        }
        _ => println!("[throughput-offline] process CPU: unavailable (not Linux /proc)"),
    }
}

#[tokio::test]
async fn offline_socks5_connect_throughput() {
    let connections = env_usize("THROUGHPUT_CONNECTIONS", 8);
    let bytes_per_conn = env_usize("THROUGHPUT_BYTES_PER_CONN", 8 * 1024 * 1024);
    let chunk = env_usize("THROUGHPUT_CHUNK_BYTES", 64 * 1024);
    assert_eq!(
        bytes_per_conn % chunk,
        0,
        "bytes per conn must be a multiple of the chunk size"
    );

    let echo_addr = spawn_echo_server().await;
    let target = Arc::new(FakeDnsTarget::new(echo_addr));
    let proxy_addr = spawn_proxy_server(Arc::clone(&target)).await;

    let cpus = std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(1);
    let cpu_before = proc_cpu_seconds();
    let received = Arc::new(AtomicUsize::new(0));
    let expected_total = connections * bytes_per_conn;
    let reporter = start_progress_reporter(Arc::clone(&received), expected_total);
    let start = Instant::now();
    let total_bytes = tokio::time::timeout(
        LOAD_TIMEOUT,
        run_load(
            proxy_addr,
            echo_addr.port(),
            connections,
            bytes_per_conn,
            chunk,
            Arc::clone(&received),
        ),
    )
    .await
    .expect("throughput load timed out");
    reporter.abort();
    let elapsed = start.elapsed();
    let cpu_after = proc_cpu_seconds();

    assert_eq!(total_bytes, expected_total, "echoed byte count mismatch");
    assert!(
        target.dns_queries() >= connections,
        "fake DNS was not exercised: {} queries for {} connections",
        target.dns_queries(),
        connections
    );
    print_report(
        connections,
        bytes_per_conn,
        chunk,
        cpus,
        target.dns_queries(),
        total_bytes,
        elapsed,
        cpu_before,
        cpu_after,
    );
}
