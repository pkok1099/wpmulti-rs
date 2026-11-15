# Proxy Modes, Routing, TUI & Admin API

## 1. Proxy Modes

`wpmulti` supports two proxy exposure modes that can run together (hybrid):

### A. Per-Tunnel Dedicated Ports
Each WireGuard config file gets its own dedicated SOCKS5 and/or HTTP port (configured via `[per_tunnel]`).
- No authentication is required; connecting to that port always routes through that specific tunnel.
- Example:
  ```bash
  curl -x socks5h://127.0.0.1:10000 https://ifconfig.co
  curl -x http://127.0.0.1:20000 https://ifconfig.co
  ```
  *(Use `socks5h://` so `curl` sends the domain name to `wpmulti` for in-tunnel DNS resolution instead of resolving locally.)*

### B. Shared Listener Ports (`[[shared_listener]]`)
One or more shared ports can multiplex across all tunnels (or a subset defined by `pool`).

#### Tunnel Selection via Username
Pass the target in the proxy username (for SOCKS5 RFC 1929 auth or HTTP `Proxy-Authorization: Basic`):
- `<tunnel_id>` (e.g. `wgcf-042`): Routes directly to that specific tunnel.
- `auto` / `round-robin`: Cycles sequentially across healthy/pool tunnels.
- `random`: Picks a random tunnel from the pool.
- `least-conn`: Picks the tunnel with the fewest active connections.
- **No username (anonymous)**: Allowed when `allow_anonymous = true` (or `auth_mode = "none"`), using the listener's `default_strategy`.

```bash
# Target a specific tunnel
curl -x socks5h://wgcf-042@127.0.0.1:1080 https://ifconfig.co
curl -x http://wgcf-042@127.0.0.1:8080 https://ifconfig.co

# Automatic rotation
curl -x socks5h://round-robin@127.0.0.1:1080 https://ifconfig.co
curl -x http://random@127.0.0.1:8080 https://ifconfig.co
```

---

## 2. Interactive TUI Monitor (`wpmulti top` / `--tui`)

Launch integrated with the daemon:
```bash
wpmulti run -c wpmulti.toml --tui
```
Or attach remotely to a running daemon (requires `[admin] enabled = true`):
```bash
wpmulti top --admin-url http://127.0.0.1:9090
```

### TUI Keyboard Controls
- `/` — Search / filter tunnels by ID or endpoint (`Enter` / `Esc` to finish)
- `Tab` — Cycle sort field (`ID` → `Status` → `Conns` → `RX` → `TX`)
- `a` / `A` — Activate selected tunnel
- `s` / `S` — Suspend selected tunnel
- `r` / `R` — Trigger hot-reload of tunnel configurations
- `j` / `k` or `↑` / `↓` — Move selection (`g` / `G` for top / bottom)
- `q` / `Q` — Quit TUI

---

## 3. Admin HTTP REST API & Prometheus Metrics

Enable in `wpmulti.toml`:
```toml
[admin]
enabled = true
bind = "127.0.0.1:9090"
# auth_token = "optional-secret"
```

### Endpoints

| Method | Path | Description |
| :--- | :--- | :--- |
| `GET` | `/health` | Healthcheck (`status`, `version`, `uptime_secs`). |
| `GET` | `/status` | Global summary (`total_tunnels`, `active_tunnels`, `suspended_tunnels`, `dormant_tunnels`, `rx_bytes`, `tx_bytes`, `listeners`). |
| `GET` | `/tunnels` | List all tunnels. Supports `?q=<filter>` and `?state=active\|suspended\|dormant`. |
| `GET` | `/tunnels/<id>` | Detailed summary for a single tunnel. |
| `POST` | `/tunnels/<id>/activate` | Manually wake/resume a tunnel. |
| `POST` | `/tunnels/<id>/suspend` | Manually suspend a tunnel (`deactivate` alias also supported). |
| `POST` | `/reload` | Hot-reload `.conf` files from `config_dir` without restarting active tunnels. |
| `GET` | `/metrics` | Prometheus text exposition metrics. |

If `auth_token` is set, include `Authorization: Bearer <token>` in requests:
```bash
curl -H "Authorization: Bearer my-token" http://127.0.0.1:9090/status
curl -X POST http://127.0.0.1:9090/reload
```
