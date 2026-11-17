# wpmulti

[![CI](https://github.com/pkok1099/wpmulti-rs/actions/workflows/ci.yml/badge.svg)](https://github.com/pkok1099/wpmulti-rs/actions/workflows/ci.yml)
[![License: MPL-2.0](https://img.shields.io/badge/License-MPL--2.0-blue.svg)](LICENSE)
[![Rust: 1.95+](https://img.shields.io/badge/Rust-1.95%2B-orange.svg)](https://www.rust-lang.org)

High-concurrency multi-tunnel WireGuard SOCKS5 & HTTP proxy daemon in Rust, built on top of [`gotatun`](https://github.com/mullvad/gotatun) and [`smoltcp`](https://github.com/smoltcp-rs/smoltcp).

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

### 1. Get the binary

Download a prebuilt binary from [GitHub Releases](https://github.com/pkok1099/wpmulti-rs/releases) — pick the tarball for your platform (`linux-amd64`, `linux-arm64`, `linux-x86`, or `termux-arm64`), or a `.deb` package for Debian/Ubuntu and Termux:

```bash
# Prebuilt binary (example: Linux amd64, v0.2.9 — use the latest release)
curl -LO https://github.com/pkok1099/wpmulti-rs/releases/download/v0.2.9/wpmulti-v0.2.9-linux-amd64.tar.gz
tar -xzf wpmulti-v0.2.9-linux-amd64.tar.gz
./wpmulti-v0.2.9-linux-amd64/wpmulti --help
```

Or build from source:

```bash
cargo build --release -p wpmulti
# Binary: ./target/release/wpmulti
```

### 2. Run Directly with a Folder of `.conf` Files
```bash
# Validate all WireGuard configs
wpmulti validate -d ./confs

# Start the daemon (foreground; Ctrl-C to stop)
wpmulti run -d ./confs
```
Add `--tui` for the interactive monitor — it needs a real terminal, so it
fails in scripts, CI, or any non-terminal session:

```bash
wpmulti run -d ./confs --tui
```
By default (without a `wpmulti.toml`), `wpmulti` binds per-tunnel ports starting at **SOCKS5 `10000`** and **HTTP `20000`** in `lazy` mode. If a port in that range is already in use (for example by another running daemon), the daemon shifts that tunnel to the next free port and logs a warning with the actual port — the startup line lists the ports it really bound, so check it instead of assuming `10000`/`20000`. A tunnel whose port is set explicitly under `[per_tunnel.overrides]` gets no listener at all when that port is busy (same warning, no shift).

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

# Shared port (requires -c wpmulti.toml): route to a specific tunnel ID (filename without .conf)
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
| `wpmulti run [-c FILE] [-d DIR] [--tui]` | Start the daemon (`-d` alone starts dedicated ports only; `-c wpmulti.toml` enables shared ports & Admin API; with neither flag, a `wpmulti.toml` in the current directory is used if one exists). |
| `wpmulti validate [-c FILE] [-d DIR]` | Validate `wpmulti.toml` and all `.conf` files without binding ports. |
| `wpmulti probe [-c WG_CONF \| -d DIR] [--json]` | Actively probe WireGuard tunnel handshake, RTT, and exit IP. |
| `wpmulti disable <TARGET>` / `enable <TARGET>` | Disable or re-enable tunnels by ID, 1-based index/range (`1`, `1-200`), comma list, or `all` via Admin API. |
| `wpmulti top [--admin-url URL]` | Attach standalone `htop`-style TUI monitor to a running daemon's Admin API. |
| `wpmulti status [--admin-url URL]` | Print JSON status from a running daemon's Admin API. |

## Documentation

- [Configuration Reference (`wpmulti.toml` & `.conf`)](docs/configuration.md)
- [Proxy Modes, Routing, TUI & Admin API](docs/proxy-and-api.md)
- [Architecture, Performance & Hardening](docs/architecture-and-performance.md)

## License & Acknowledgments

`wpmulti` is licensed under the [Mozilla Public License 2.0 (MPL-2.0)](LICENSE).

Built on [`gotatun`](https://github.com/mullvad/gotatun) (Mullvad VPN) and [`smoltcp`](https://github.com/smoltcp-rs/smoltcp). See [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md) for full dependency attributions and licenses.
