# Configuration Reference

`wpmulti` uses two types of configuration:
1. **WireGuard `.conf` directory**: Standard WireGuard `[Interface]` and `[Peer]` files (e.g. `wgcf-001.conf`). Each file's stem (filename without `.conf`) becomes its unique `tunnel_id`, allowing identical/cloned configs (such as 245 copies of `wgcf-profile.conf`) to run concurrently without key or IP collisions.
2. **Main config file (`wpmulti.toml`)**: Optional TOML file controlling global settings, lifecycle, dedicated ports, shared listeners, Admin API, and TUI.

## Complete `wpmulti.toml` Example

```toml
[global]
config_dir = "/etc/wpmulti/conf.d"
bind_address = "127.0.0.1"
log_level = "info"                  # trace | debug | info | warn | error
dns_fallback = "1.1.1.1:53"
dns_strategy = "tunnel_only"        # tunnel_only | tunnel_first | host
ip_mode = "dual_stack"              # dual_stack | ipv4_only | ipv6_only
max_active_tunnels = 1000

[lifecycle]
mode = "lazy"                       # lazy | eager
idle_timeout = "5m"                 # supports ms, s, m, h, d or integer seconds
handshake_timeout = "10s"
eager_tunnels = ["wgcf-001"]        # tunnels kept always-on even when mode = "lazy"

[per_tunnel]
enabled = true
base_socks5_port = 10000            # set/omit as needed; each tunnel gets base + index
base_http_port = 20000

[per_tunnel.overrides.wgcf-001]
socks5_port = 15001
http_port = 25001

[[shared_listener]]
name = "shared-socks"
type = "socks5"                     # socks5 | http
bind = "127.0.0.1:1080"
auth_mode = "per_tunnel"            # none | global | per_tunnel
# global_password = "secret"        # optional password when auth_mode = "global" or "per_tunnel"
default_strategy = "round-robin"    # round-robin | random | least-conn | fallback
allow_anonymous = true              # allow requests with no username (uses default_strategy)
pool = "all"                        # "all" or ["wgcf-001", "wgcf-002"]
# ip_mode = "ipv6_only"             # optional per-listener override when global ip_mode = "dual_stack"

[[shared_listener]]
name = "shared-http"
type = "http"
bind = "127.0.0.1:8080"
auth_mode = "per_tunnel"
default_strategy = "round-robin"
allow_anonymous = true
pool = "all"

[admin]
enabled = false
bind = "127.0.0.1:9090"
# auth_token = "my-bearer-token"    # optional Bearer token for Admin API

[tui]
refresh_rate_ms = 500
default_sort = "id"                 # id | status | conns | rx | tx
```

## Section Details

### `[global]`
- `config_dir` (default `"/etc/wpmulti/conf.d"`): Directory scanned for `*.conf` files. Overridden by `-d / --dir`.
- `bind_address` (default `"127.0.0.1"`): IP address used by `[per_tunnel]` listeners.
- `dns_strategy` (default `"tunnel_only"`):
  - `tunnel_only`: All domain lookups go through the WireGuard tunnel (zero host DNS leak).
  - `tunnel_first`: Try in-tunnel DNS first, fall back to host DNS on failure.
  - `host`: Resolve domains using the host OS resolver.
- `max_active_tunnels` (default `1000`): Maximum concurrently active tunnels.

### `[lifecycle]`
- `mode`:
  - `lazy` (default): Tunnels start dormant, wake on first proxy connection, and suspend after `idle_timeout` with 0 active connections.
  - `eager`: All tunnels are activated immediately at startup.
- `idle_timeout` (default `"5m"`): Time after the last connection closes before a lazy tunnel is suspended.
- `eager_tunnels`: List of specific `tunnel_id`s to keep always active even in `lazy` mode.

### `[per_tunnel]`
- Assigns dedicated local ports sequentially (sorted by `tunnel_id`), skipping any port overridden under `[per_tunnel.overrides.<tunnel_id>]`.
- Tip: If a port range (such as `20000+`) conflicts with local services on your host, change `base_http_port` / `base_socks5_port` (e.g. `30000` / `11000`) or set `enabled = false` to use only `[[shared_listener]]`.
