# wpmulti

High-concurrency multi-tunnel WireGuard proxy daemon in Rust, built on top of [`gotatun`](https://github.com/mullvad/gotatun) and [`smoltcp`](https://github.com/smoltcp-rs/smoltcp).

`wpmulti` runs hundreds or thousands of WireGuard `.conf` files simultaneously **entirely in userspace** (no root privileges or kernel `wg0`/TUN interfaces required) and exposes them as **SOCKS5** and **HTTP/HTTPS CONNECT** proxies.

## Features

- **Pure Userspace Networking**: Connects `gotatun::Device` (`IpSend`/`IpRecv`) directly to a Layer-3 `smoltcp` TCP/IP stack (`Medium::Ip`), supporting both IPv4 and IPv6.
- **Hybrid Proxy Exposure**:
  - **Per-Tunnel Dedicated Ports**: Each `.conf` gets its own local SOCKS5 and/or HTTP port (auto-assigned from base ports or explicitly overridden).
  - **Shared Port Multiplexing**: Single shared port(s) routing traffic by proxy username (`<tunnel_id>`, `auto`, `random`, `round-robin`, `least-conn`) or pool strategy.
- **SOCKS5 & HTTP/HTTPS Proxy**:
  - **SOCKS5** (RFC 1928 & RFC 1929): `CONNECT` (TCP) and `UDP ASSOCIATE`, with optional username/password authentication.
  - **HTTP Proxy** (RFC 9110 & RFC 7617): `CONNECT` tunneling (HTTPS) and forward HTTP requests, with optional `Proxy-Authorization: Basic`.
- **Scalable Lifecycle (Lazy / On-Demand)**:
  - **Lazy mode (default)**: Tunnels start `Dormant` (0 OS sockets, ~500B metadata) and wake via `Device::resume()` when a connection arrives, then automatically suspend (`Device::suspend()`) after `idle_timeout`.
  - **Eager mode**: Keep all or selected (`eager_tunnels`) tunnels always active and handshaked.
- **In-Tunnel Remote DNS (Anti-Leak)**:
  - Resolves domains through the WireGuard tunnel using the `.conf` `DNS` field (fallback `1.1.1.1:53`) with a TTL-aware LRU cache. Strategies: `tunnel_only` (default), `tunnel_first`, or `host`.
- **Observability, Hot-Reload & TUI**:
  - **HTTP Admin REST API** (`/health`, `/status`, `/tunnels`, `/reload`, `/metrics` in Prometheus format, plus per-tunnel activate/suspend).
  - **Interactive TUI (`wpmulti top`)**: `htop`-style terminal dashboard with live stats, search, sorting, and tunnel controls.

## Quick Start

### 1. Build
```bash
cargo build --release -p wpmulti
# Binary: ./target/release/wpmulti
```

### 2. Run Directly with a Folder of `.conf` Files
```bash
# Validate all WireGuard configs
wpmulti validate -d ./confs

# Start daemon + interactive TUI
wpmulti run -d ./confs --tui
```
By default (without a `wpmulti.toml`), `wpmulti` binds per-tunnel ports starting at **SOCKS5 `10000`** and **HTTP `20000`** in `lazy` mode.

### 3. Run with `wpmulti.toml`
```bash
wpmulti run -c wpmulti.toml
```
See [docs/configuration.md](docs/configuration.md) for the full `wpmulti.toml` schema and [docs/proxy-and-api.md](docs/proxy-and-api.md) for proxy usage, routing rules, TUI shortcuts, and Admin API endpoints.

## Proxy Usage Examples

```bash
# Dedicated per-tunnel port (e.g. tunnel #1 on default base ports)
curl -x socks5h://127.0.0.1:10000 https://ifconfig.co
curl -x http://127.0.0.1:20000 https://ifconfig.co

# Shared port: route to a specific tunnel ID (filename without .conf)
curl -x socks5h://wgcf-001@127.0.0.1:1080 https://ifconfig.co

# Shared port: automatic pool routing keywords
curl -x socks5h://round-robin@127.0.0.1:1080 https://ifconfig.co
curl -x socks5h://random@127.0.0.1:1080 https://ifconfig.co
curl -x http://least-conn@127.0.0.1:8080 https://ifconfig.co
curl -x http://auto@127.0.0.1:8080 https://ifconfig.co
```

## CLI Subcommands

| Command | Description |
| :--- | :--- |
| `wpmulti run [-c FILE] [-d DIR] [--tui]` | Start the multi-tunnel proxy daemon (optionally with integrated TUI). |
| `wpmulti validate [-c FILE] [-d DIR]` | Validate `wpmulti.toml` and all `.conf` files without binding ports. |
| `wpmulti top [--admin-url URL]` | Attach standalone `htop`-style TUI monitor to a running daemon's Admin API. |
| `wpmulti status [--admin-url URL]` | Print JSON status from a running daemon's Admin API. |

## Documentation

- [Configuration Reference (`wpmulti.toml` & `.conf`)](docs/configuration.md)
- [Proxy Modes, Routing, TUI & Admin API](docs/proxy-and-api.md)
- [Architecture, Performance & Hardening](docs/architecture-and-performance.md)
