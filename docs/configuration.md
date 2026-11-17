# Configuration Reference

`wpmulti` uses two types of configuration:
1. **WireGuard `.conf` directory**: Standard WireGuard `[Interface]` and `[Peer]` files (e.g. `wgcf-001.conf`). Each file's stem (filename without `.conf`) becomes its unique `tunnel_id`, allowing identical/cloned configs (such as 245 copies of `wgcf-profile.conf`) to run concurrently without key or IP collisions.
2. **Main config file (`wpmulti.toml`)**: Optional TOML file controlling global settings, lifecycle, dedicated ports, shared listeners, Admin API, and TUI.

## Complete `wpmulti.toml` Example

```toml
# Tunnel IDs that start disabled (excluded from routing and probing).
# `wpmulti disable <id>` / `wpmulti enable <id>` update this list.
disabled_tunnels = []

[global]
config_dir = "/etc/wpmulti/conf.d"
bind_address = "127.0.0.1"
log_level = "info"                  # trace | debug | info | warn | error
dns_fallback = "1.1.1.1:53"
dns_strategy = "tunnel_only"        # tunnel_only | tunnel_first | host
dns_preference = "ipv4_first"       # ipv4_first | ipv6_first
ip_mode = "dual_stack"              # dual_stack | ipv4_only | ipv6_only
max_active_tunnels = 1000

[lifecycle]
mode = "lazy"                       # lazy | eager
idle_timeout = "5m"                 # supports ms, s, m, h, d or integer seconds
handshake_timeout = "10s"
eager_tunnels = ["wgcf-001"]        # tunnels kept always-on even when mode = "lazy"

[health_check]
threshold = 3                       # consecutive failures before marking unhealthy (circuit breaker)
cooldown = "30s"                    # cooldown period before attempting half-open recovery
probe_interval = "30s"              # active probe interval for eager tunnels (force_handshake)
probe_timeout = "5s"                # active probe handshake timeout

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
allow_anonymous = true              # allow requests with no username (uses default_strategy); anonymous requests bypass global_password — set false to require it
pool = "all"                        # "all" or ["wgcf-001", "wgcf-002"]
# ip_mode = "ipv6_only"             # optional per-listener override when global ip_mode = "dual_stack"

[[shared_listener]]
name = "shared-http"
type = "http"
bind = "127.0.0.1:8080"
auth_mode = "per_tunnel"
default_strategy = "round-robin"
allow_anonymous = true              # allow requests with no username (uses default_strategy); anonymous requests bypass global_password — set false to require it
pool = "all"

[admin]
enabled = true
bind = "127.0.0.1:9090"
# auth_token = "my-bearer-token"    # optional Bearer token for Admin API

[tui]
refresh_rate_ms = 500
default_sort = "id"                 # id | status | conns | rx | tx
```

## Section Details

Unknown keys are rejected: a misspelled key (e.g. `log_leve` instead of
`log_level`) or an unknown top-level key fails `validate` and `run` with
an `unknown field` error naming the key, instead of being silently
ignored. The same applies to a `POST /config` body with an unknown key.

Tunnel IDs referenced *by value* are checked the same way: `validate`,
`run`, and `POST /config` reject a config whose `disabled_tunnels`,
`lifecycle.eager_tunnels`, `per_tunnel.overrides.<id>` key, or
`shared_listener` `pool` list names a tunnel ID that no loaded `.conf`
file provides — with an `unknown tunnel id '<id>' referenced by …`
error naming the id and where it was referenced. A typo such as
`pool = ["wgcf-010"]` would otherwise start fine and only fail later
as `no healthy tunnels available in pool`.

Saving a config preserves your comments: `wpmulti disable` / `enable`,
`POST /config`, and the TUI's `w` save overlay the new values onto the
existing `wpmulti.toml` instead of rewriting it from scratch, so header
warnings, per-section notes, and trailing `# comments` survive a save.
Keys the new config no longer contains are removed; comments inside a
replaced `[[shared_listener]]` array do not survive. One exception:
`config_dir` is stored in its resolved form (against the TOML file's
directory), so saving a config loaded with `-c /some/dir/wpmulti.toml`
rewrites that one value to the resolved path; a TOML in the working
directory keeps `./confs` verbatim.

### `[global]`
- `config_dir` (default `"/etc/wpmulti/conf.d"`): Directory scanned for `*.conf` files. Overridden by `-d / --dir`. A relative `config_dir` is resolved against the directory containing the `wpmulti.toml` file it was loaded from — so `validate -c /some/dir/wpmulti.toml` and `run -c /some/dir/wpmulti.toml` work from any working directory; an explicit `-d` path is resolved against the working directory as usual.
- `bind_address` (default `"127.0.0.1"`): IP address used by `[per_tunnel]` listeners.
- `dns_strategy` (default `"tunnel_only"`):
  - `tunnel_only`: All domain lookups go through the WireGuard tunnel (zero host DNS leak).
  - `tunnel_first`: Try in-tunnel DNS first, fall back to host DNS on failure.
  - `host`: Resolve domains using the host OS resolver.
- `dns_preference` (default `"ipv4_first"`): Address-family preference when both IPv4 and IPv6 are available (e.g. when resolving domains in-tunnel): `ipv4_first` prefers IPv4, `ipv6_first` prefers IPv6.
- `max_active_tunnels` (default `1000`): Maximum concurrently active tunnels.

### Top-level keys
- `disabled_tunnels` (default `[]`): Tunnel IDs that start disabled — excluded from routing and probing. `wpmulti disable <id>` adds an ID here (persisted to `wpmulti.toml`); `wpmulti enable <id>` removes it.

### `[lifecycle]`
- `mode`:
  - `lazy` (default): Tunnels start dormant, wake on first proxy connection, and suspend after `idle_timeout` with 0 active connections.
  - `eager`: All tunnels are activated immediately at startup.
- `idle_timeout` (default `"5m"`): Time after the last connection closes before a lazy tunnel is suspended.
- `eager_tunnels`: List of specific `tunnel_id`s to keep always active even in `lazy` mode.

### `[health_check]`
- `threshold` (default `3`): Consecutive failures before the circuit breaker marks a tunnel unhealthy.
- `cooldown` (default `"30s"`): Cooldown period before a half-open recovery trial is attempted.
- `probe_interval` (default `"30s"`): Active probe interval for eager tunnels (force_handshake).
- `probe_timeout` (default `"5s"`): Active probe handshake timeout.
- A tunnel starts as `unknown` (never proven) and becomes `healthy` only after its first successful handshake or probe; it is never reported as healthy before that.

### `[per_tunnel]`
- Assigns dedicated local ports sequentially (sorted by `tunnel_id`), skipping any port overridden under `[per_tunnel.overrides.<tunnel_id>]`.
- Tip: If a port range (such as `20000+`) conflicts with local services on your host, change `base_http_port` / `base_socks5_port` (e.g. `30000` / `11000`) or set `enabled = false` to use only `[[shared_listener]]`.
- If a port in the range is already in use when the daemon starts, that tunnel silently shifts to the next free port instead of failing: the daemon logs `Port <port> already in use while binding dedicated <socks5|http> listener for tunnel '<id>', shifting to next free port` (the `<id>` is the tunnel whose listener is shifting, not the tunnel that owns the busy port in the other daemon), and the startup line lists the ports actually bound. This only applies to the automatic range; a tunnel with an explicit port under `[per_tunnel.overrides.<tunnel_id>]` gets no listener at all when that port is busy (a warning is logged and the tunnel stays unreachable on its dedicated port).
