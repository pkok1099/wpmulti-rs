# Architecture, Performance & Hardening

This document describes the internal architecture of `wpmulti`, its packet/data flow, CPU & memory optimizations, concurrency & lifecycle hardening, and how to run the benchmark and verification suites.

---

## 1. High-Level Architecture

`wpmulti` runs multiple WireGuard tunnels concurrently in pure userspace by bridging [`gotatun`](https://github.com/mullvad/gotatun) (`IpSend` / `IpRecv`) with a per-tunnel [`smoltcp`](https://github.com/smoltcp-rs/smoltcp) Layer-3 TCP/IP stack (`Medium::Ip`).

```text
Client (TCP / UDP)
   │
   ▼
ProxyListener (src/core/listener.rs)
   │  JoinSet task tracking + transient accept() backoff
   ▼
SOCKS5 / HTTP Proxy (src/proxy/{socks5,http}.rs)
   │  Username / port routing
   ▼
MultiTenantRouter (src/core/router.rs)
   │  O(1) Arc<[String]> candidate selection (auto, random, round-robin, least-conn, <id>)
   ▼
LifecycleController (src/core/lifecycle.rs)
   │  Lazy wake (Device::resume) / active connection guards / idle suspend
   ▼
NetstackHandle / smoltcp Reactor (src/netstack/stack.rs)
   │  Event-driven poll loop (sleep up to 500ms when idle)
   ▼
VirtualTunBridge (src/netstack/bridge.rs)
   │  Bounded 64-slot recycled buffer pool
   ▼
gotatun::Device (WireGuard UDP encryption & transport)
```

---

## 2. CPU & Memory Optimizations

### 2.1 Event-Driven `smoltcp` Reactor (`src/netstack/stack.rs`)
- **Problem**: Sub-millisecond poll delays previously caused idle tunnels to spin continuously at ~100% CPU.
- **Design**: When `smoltcp` reports no pending work, the reactor clamps its sleep duration up to `500ms` and wakes immediately on:
  - `Notify` signals from proxy stream/datagram operations
  - Incoming packets on `bridge_rx.recv()`
  - Tunnel shutdown signals
- **Result**: Idle tunnels consume **0.00% CPU**.

### 2.2 `VirtualTunBridge` Buffer Recycling (`src/netstack/bridge.rs`)
- **Problem**: Every outbound IP packet previously allocated a fresh `vec![0u8; len]` and performed extra copies across the `smoltcp` / `gotatun` boundary.
- **Design**: Uses a bounded recycled buffer pool (`buf_pool`, up to 64 slots) to reuse packet buffers on the outbound hot path.
- **Measured Throughput**: **2.13M – 2.26M packets/sec** (~101 – 107 MB/s) in `benches/performance.rs`, with **53.5 MB flat RSS** (0 KB delta) across a sustained 1,000,000-packet stress test.

### 2.3 In-Tunnel DNS & Lock-Free LRU (`src/netstack/dns.rs`, `src/netstack/stack.rs`)
- **Lock-Free LRU Timestamps**: Replaced inner per-entry mutexes with an `AtomicU64` timestamp counter updated via `fetch_add`, eliminating ABBA lock inversion between `entries.read()` and `last_accessed` and sustaining **>1,005,000 lookups/sec** under concurrent load.
- **16x DNS Socket Memory Reduction**: Added `udp_bind_with_size` using **4 KiB RX + 4 KiB TX (8 KiB total)** buffers for in-tunnel DNS queries instead of 128 KiB (64 KiB + 64 KiB), saving **120 KiB RAM per active DNS query socket**.
- **Compression Pointer Bounds Check**: Validates `0xC0` DNS name compression jumps (`ptr < buf.len()`) before dereferencing, returning `DnsError::PacketTooShort` on malformed packets.

### 2.4 HTTP & SOCKS5 Proxy Hot Paths (`src/proxy/http.rs`, `src/proxy/socks5.rs`)
- **Chunked HTTP Header Reader**: `read_http_request_headers_buffered` reads headers in **1024-byte chunks** (preserving leftover body bytes for downstream forwarding) instead of 1-byte async `read` syscalls, accelerating header parsing by **1.9x – 2.3x** (422,283 req/s in-memory).
- **Keep-Alive Hang Fix**: Strips hop-by-hop `Connection` headers on forwarded HTTP requests and injects `Connection: close\r\n\r\n` so bidirectional stream copy terminates cleanly.
- **IPv6 Authority Parsing**: Supports bracketed IPv6 literals both with and without explicit ports (e.g., `http://[2001:db8::1]/path`).
- **Zero-Alloc SOCKS5 UDP Relay**: Uses stack slice encoders and buffer reuse in the UDP datagram relay loop instead of per-datagram heap `Vec` allocations.

### 2.5 Zero-Copy Routing & Metrics (`src/core/router.rs`, `src/api/metrics.rs`)
- **Router Candidate Indexing**: `MultiTenantRouter` stores allowed tunnel lists as `Option<Arc<[String]>>` with O(1) indexed lookups, eliminating per-connection `Vec<String>` cloning (**>679,000 selections/sec**, 1.3 – 1.8 µs latency across 245–500 tunnels).
- **Direct Prometheus Streaming**: `/metrics` streams Prometheus lines directly from registry entries without intermediate summary cloning.

---

## 3. Lifecycle, Concurrency & Security Hardening

| Area | File | Hardening Detail |
| :--- | :--- | :--- |
| **Connection Guard (UDP)** | `src/core/lifecycle.rs` | `GuardedUdpSocket` holds `Arc<TunnelConnGuard>` for the lifetime of UDP sessions so active UDP traffic does not drop `active_conns` to 0 and trigger premature idle suspend. |
| **Boot Failure Cleanup** | `src/core/lifecycle.rs` | On tunnel boot failure, explicitly invokes `device.suspend().await` and reverts tunnel state from `Activating` back to `Dormant`. |
| **Reactor Teardown** | `src/core/lifecycle.rs` | `close_tunnel(&id)` cleanly shuts down reactor tasks and channels on suspension or stop, preventing leaked Tokio tasks. |
| **Atomic Counter Safety** | `src/core/registry.rs` | `dec_conns()` uses an atomic `compare_exchange_weak` loop to decrement only when `cur > 0`, preventing `usize::MAX` wrap-around underflow. |
| **Listener Resilience** | `src/core/listener.rs` | Client tasks are tracked via `tokio::task::JoinSet` (with active reaping and graceful shutdown abort); transient OS `accept()` errors (`EMFILE`, `ENFILE`, `ECONNABORTED`) log a warning and back off 50ms instead of crashing the listener. |
| **Socket Handle Safety** | `src/netstack/stream.rs` | Stream and datagram poll paths verify handle existence before `get_mut::<T>()` to prevent panics on closed or evicted handles. |
| **Admin Body DoS Limit** | `src/api/server.rs` | Enforces `MAX_ADMIN_BODY_SIZE` (**64 KiB** body limit, 128 KiB total buffer) and rejects oversized `Content-Length` headers with `413 Payload Too Large`. |
| **Hot-Reload Diffing** | `src/core/mod.rs` | `reload_with_tunnels` compares full `TunnelConfig` structs (`*cur != t_cfg`) so peer endpoint, DNS, and MTU changes are applied accurately. |
| **CLI Validation** | `src/cli/commands.rs` | Routes CLI config loading through `MainConfig::from_toml_str` so all schema and semantic checks run consistently. |

---

## 4. Verification & Benchmarks

> This section is for developers working from the repository — it runs
> `cargo` commands against the source tree. If you installed wpmulti as
> a prebuilt binary, there is no source tree to check; skip this section
> (the rest of this document still describes how the binary you run
> works).

Run the full verification and benchmark suite from the repository root:

```bash
# Type-check & lint (must pass with 0 warnings)
cargo check --all-targets
cargo clippy --all-targets -- -D warnings

# Run all unit, integration, adversarial, and E2E tests
cargo test --all-targets

# Run micro-benchmarks (benches/performance.rs)
cargo bench
```
