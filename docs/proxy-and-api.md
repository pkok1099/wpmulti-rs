# Proxy Modes, Routing, TUI & Admin API

## 1. Proxy Modes

`wpmulti` supports two proxy exposure modes that can run together (hybrid):

### A. Per-Tunnel Dedicated Ports
Each WireGuard config file gets its own dedicated SOCKS5 and/or HTTP port (configured via `[per_tunnel]`).
- Authentication: a dedicated port enforces the tunnel's own
  `[per_tunnel.overrides.<id>]` password when one is set, else the single
  `global_password` configured on the shared listeners when one is set;
  with no password configured anywhere, no authentication is required.
  The username must be the tunnel id. When a password is configured
  anywhere but a tunnel has neither an override password nor a global
  fallback (e.g. several shared listeners enforce distinct global
  passwords), the daemon refuses to start that tunnel's dedicated
  listener instead of leaving it open — see the error at startup.
  While dedicated listeners are enabled, a config whose shared
  listeners enforce distinct global passwords is rejected at load
  time instead (the fallback would be ambiguous): use the same
  `global_password` on all shared listeners, set a
  `per_tunnel.overrides.<id>.password` for each tunnel, or disable
  dedicated listeners (`[per_tunnel] enabled = false`, which also
  lifts the load-time check — distinct per-listener passwords are a
  legitimate config then).
  Connecting to that port always routes through that specific tunnel.
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

#### Passwords: what is actually checked

The username selects the tunnel; the password is only checked when one
is configured. With `allow_anonymous = true` and no password configured
anywhere (no `global_password` on the listener, no
`[per_tunnel.overrides.<id>] password`), **any password — including an
empty one — is accepted**, because there is nothing to check it against;
only the username matters for routing. (The *username* itself must still
be non-empty on SOCKS5: an empty username is rejected before any password
check — the server replies auth failure `[0x01, 0x01]`. Over HTTP, an
empty Basic username is ignored for *routing* — it selects the default
pool, like no username — but it does **not** skip the password check:
if a `Proxy-Authorization` header is sent at all, the password in it is
still verified. With no password configured that check passes (any
password, including empty, is accepted); with a password configured,
`Basic Og==` (empty user, empty password) is rejected with `407`,
while `Basic :<correct-password>` is accepted and routed to the
default pool.) This is by design, and the
listeners bind to `127.0.0.1` by default, so only local processes can
reach them. To require a password, set `global_password` on the shared
listener (or a per-tunnel password in `[per_tunnel.overrides.<id>]`);
a wrong password is then rejected — SOCKS5 replies auth failure
(`[0x01, 0x01]`), HTTP replies `407 Proxy Authentication Required`.

With `auth_mode = "per_tunnel"`, the password is checked against the
password of the tunnel the selector **finally resolves to**: the
tunnel's own override password when one is set, else the listener's
`global_password`, else the anonymous rule. A tag (`tag:prem`),
keyword (`auto`), or default-pool selector therefore cannot open a
password-protected tunnel with the global password — only that
tunnel's own password is accepted for it. One protocol wrinkle: the
auth-time check cannot know which tunnel a tag/keyword selector will
resolve to, so it accepts the global password provisionally and the
authoritative check runs at selection time, *after* the auth reply
was already sent. A wrong password for the resolved tunnel then
surfaces as a connect failure rather than an auth failure — SOCKS5
replies general failure (`0x01`), HTTP replies `404 Tunnel Not
Found` with `invalid proxy credentials for the selected tunnel` in
the body. A `ById` selector is checked at auth time as before, so it
still fails cleanly with `[0x01, 0x01]` / `407`.

**A configured password does not block anonymous requests.** The
password is only checked when credentials are actually presented — and
"presented" means a `Proxy-Authorization` header (HTTP) or an auth
method with credentials (SOCKS5) was sent at all. With
`allow_anonymous = true` (the default in the provided
`wpmulti.toml`), a request with no credentials at all goes
straight to the listener's default strategy — it is never asked for
the password, even when `global_password` is set. The one exception
is a tunnel with its own override password (in
`[per_tunnel.overrides.<id>]`): an anonymous request is never routed
to that tunnel — only that tunnel's own password opens it, whichever
selector picked it. But a request that
*does* present credentials — even empty ones, such as HTTP
`Basic Og==` — has its password verified, and is rejected with `407`
when it does not match the configured password. To actually require a
password, set **both** `global_password` on the listener **and**
`allow_anonymous = false`: anonymous requests are then rejected —
SOCKS5 replies no acceptable methods (`[5, 255]`), HTTP replies `407
Proxy Authentication Required`.

**Handshake timeout.** Each step of the SOCKS5 handshake must complete
within 30 s: the greeting *and* the authentication exchange share one
30 s budget (a stall while the client is still sending its greeting
closes the connection the same way, with a `SOCKS5 auth timed out`
warning), and the command request has its own 30 s budget. If a client
stalls mid-handshake, the server closes the connection without a reply
and logs a timeout warning (`SOCKS5 auth timed out` or
`SOCKS5 command timed out`). A single stalled attempt is transient:
retry the request. In testing this was intermittent — a handful of
stalled credentialed auth attempts across two daemons, then 140+ clean
attempts — and always self-resolving.

```bash
# Target a specific tunnel
curl -x socks5h://wgcf-042@127.0.0.1:1080 https://ifconfig.co
curl -x http://wgcf-042@127.0.0.1:8080 https://ifconfig.co

# Automatic rotation
curl -x socks5h://round-robin@127.0.0.1:1080 https://ifconfig.co
curl -x http://random@127.0.0.1:8080 https://ifconfig.co
```

---

## 2. Interactive TUI Monitor (`wpmulti top`)

Attach to a running daemon (requires `[admin] enabled = true`):
```bash
wpmulti top --admin-url http://127.0.0.1:9090
```
A loopback Admin API needs no token, so `wpmulti top` on the same machine just works.

### Tabs

The TUI has five tabs. Switch with `1`–`5`, `Tab` / `→` for the next tab, `←` for the previous tab (clicking a tab header with the mouse also works). `q` (or `Ctrl-C`) quits from any tab. The footer always shows the keys for the active tab. When `wpmulti top` cannot reach the Admin API (wrong `--admin-url`, daemon not running, wrong port), the dashboard stays open and keeps retrying, but the footer shows the connection error in red on every tab (for example `Failed to connect to Admin API at 'http://127.0.0.1:19999': Connection refused (os error 111)`) — an empty tunnel table under that warning means the daemon is unreachable, not that it has no tunnels.

- **1: Tunnels** — the tunnel table (ID, STATE, HEALTH, CONNS, RX, TX, PORT, ENDPOINT), plus RX/TX totals and Pool Health. Keys: `j`/`k` or `↑`/`↓` move the selection (`PgUp`/`PgDn` jump 10 rows, `Home`/`End` first/last), `/` searches by ID or endpoint (`Enter`/`Esc` to finish; the filter applies as you type, and opening `/` starts a fresh search — to clear an active filter, press `Esc` with no prompt open, or `/` then `Enter` with an empty query; the footer shows `Esc:Clear filter` while a filter is active), `s` cycles the sort field (ID → Status → Conns → RX → TX), `a` activates the selected tunnel, `d` suspends it, `x` toggles it disabled/enabled, `X` opens a batch prompt to disable/enable several tunnels at once (`-` disables, `+` enables; e.g. `-1-200`, `+1-50`, `all`), `r` triggers a hot reload of tunnel configurations.
- **2: Logs** — the daemon's recent log lines, color-coded by level (ERROR red, WARN yellow, INFO green, DEBUG cyan). Keys: `j`/`k` scroll, `f` cycles the level filter (ALL → ERROR → WARN → INFO → DEBUG), `c` clears the visible log buffer. The clear sticks in both modes: in remote `top` the lines cleared stay gone and only lines logged after the clear reappear on refresh.
- **3: Listeners** — every active listener: NAME, TYPE, ADDRESS, MODE (Shared or Dedicated), TUNNEL. Keys: `j`/`k` scroll.
- **4: Config** — the daemon's runtime configuration as an editable table (SCOPE, SETTING, VALUE, ACTION). Each row is tagged `Live` (applies immediately) or `Restart` (needs a daemon restart). Keys: `j`/`k` or `PgUp`/`PgDn`/`Home`/`End` move, `Enter` or `Space` edits/cycles the selected value, `w` saves and applies. While a text value is being edited, `Enter` confirms the new value and `Esc` cancels it; every other key, including `q`, types into the editor (the footer says so while editing). The title shows the config source (file path, or `remote/in-memory`), plus how many rows are unsaved and how many are restart-pending. A `[RESTART]` edit is only *staged* when you press `Enter`: it changes nothing on the daemon (or in its file) until you press `w`, and quitting with `q` discards it — a later `[LIVE]` edit never drags a staged restart value along with it. The `shared_listener` row shows a one-line summary per listener (name, type, `anon`/`auth`, pool strategy, bind address — in that order, so the informative tokens survive the cut in a narrow terminal); press `Enter` on it to see and edit the full per-listener JSON (passwords redacted), including `allow_anonymous`, `default_strategy`, `pool`, and `auth_mode`. A long value being edited shows its *tail* (the end, where the cursor is) instead of being cut off at the right edge — the editor is append-only, so what you type is always visible.
- **5: Probe** — handshake probe results (TUNNEL, ENDPOINT, STATUS, RTT, MESSAGE). Keys: `p` probes the selected tunnel, `P` probes all tunnels, `j`/`k` scroll. A probe is a real WireGuard handshake check that runs on the daemon through `POST /tunnels/<id>/probe`: a tunnel that activates but never completes a handshake reports `FAIL`, never `OK`.

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
| `GET` | `/health` | Healthcheck (`status`, `version`, `uptime_secs`). Like every other endpoint, it requires the `Authorization: Bearer` token when one is configured — it is not an open backdoor for probers or load balancers. |
| `GET` | `/status` | Global summary (`total_tunnels`, `active_tunnels`, `suspended_tunnels`, `dormant_tunnels`, `disabled_tunnels`, `healthy_tunnels`, `unknown_tunnels`, `half_open_tunnels`, `unhealthy_tunnels`, `rx_bytes`, `tx_bytes`, `listeners`). A tunnel counts as `healthy` only after its first successful handshake or probe; before that it is `unknown`. Granting a UDP relay (`UDP ASSOCIATE`) does not count: binding a virtual socket proves nothing about the handshake, so it neither promotes the tunnel nor resets its failure count. |
| `GET` | `/tunnels` | List all tunnels. Supports `?q=<filter>` and `?state=active\|suspended\|dormant` (also `activating`; matching is case-insensitive, so `?state=Active` works — a value that matches no state is rejected with HTTP 400 instead of silently returning an empty list). All timestamps in the API (`last_handshake`, `last_active_at`, …) are Unix epoch seconds; a value of `null` means it never happened. |
| `GET` | `/tunnels/<id>` | Detailed summary for a single tunnel. |
| `POST` | `/tunnels/<id>/activate` | Manually wake/resume a tunnel. |
| `POST` | `/tunnels/<id>/suspend` | Manually suspend a tunnel (`deactivate` alias also supported). Reports `already dormant` when the tunnel was never activated (nothing changes). |
| `POST` | `/tunnels/<id>/disable` | Disable a tunnel (suspends it and excludes it from routing until enabled). If live sessions are running, the tunnel stays Active until they drain — the answer reports `disabled (pending: N active connection(s)...)` and the tunnel summary carries `disable_pending: true`; new connections are refused immediately. |
| `POST` | `/tunnels/<id>/enable` | Re-enable a previously disabled tunnel. |
| `POST` | `/tunnels/<id>/probe` | Force a WireGuard handshake with the tunnel's first peer and report the outcome (`id`, `ok`, `rtt_ms`, `message`). `ok` is `false` when the handshake fails or times out, even if the tunnel activated fine; 404 for an unknown tunnel. |
| `GET` | `/config` | Current runtime configuration (secrets are redacted: `auth_token`, `global_password`, and per-tunnel passwords come back as `null`). |
| `POST` | `/config` | Apply a new runtime configuration (JSON body). **Partial update:** only the fields present in the body change; every omitted section keeps its current value (an array that *is* present, e.g. `shared_listener`, replaces that whole list). The answer is `{"status":"updated","restart_pending":[...]}` — `restart_pending` lists the changed settings that only take effect after a daemon restart (`[LIVE]` settings apply immediately, `[RESTART]` settings do not; the same tags the TUI Config tab shows). A request that changes `global.config_dir` is rejected with HTTP 400 — the Admin API must not redirect the directory the daemon loads `.conf` files from, so change `config_dir` by editing `wpmulti.toml` directly and restarting the daemon. A request that references a tunnel ID no loaded `.conf` provides (in `disabled_tunnels`, `eager_tunnels`, an override key, or a listener `pool`) is also rejected with HTTP 400, and nothing is saved. A successful save preserves the comments in `wpmulti.toml` (see `docs/configuration.md`). |
| `POST` | `/tunnels/batch/disable` | Disable tunnels by JSON `{"target": "<id\|1\|1-200\|all>"}`. |
| `POST` | `/tunnels/batch/enable` | Re-enable tunnels by JSON `{"target": "<id\|1\|1-200\|all>"}`. |
| `POST` | `/reload` | Hot-reload `.conf` files from `config_dir` without restarting active tunnels. |
| `GET` | `/metrics` | Prometheus text exposition metrics. |

If `auth_token` is set, include `Authorization: Bearer <token>` in requests:
```bash
curl -H "Authorization: Bearer my-token" http://127.0.0.1:9090/status
curl -X POST http://127.0.0.1:9090/reload
```

---

## 4. Troubleshooting

### Every request fails the same way — how do I tell the causes apart?

From the client side, most tunnel failures look identical: SOCKS5 clients
report `curl: (97) Can't complete SOCKS5 connection`, HTTP clients report
`curl: (56) CONNECT tunnel failed` with no status code at all
(`http_code=000`). The reply codes below distinguish the causes, but only
at the protocol level — plain `curl` does not show them. Use `curl -v`
to see the HTTP status line (`404`, `503`, or `502`), compare timing
(instant vs a few seconds), or check the daemon log, which always names
the cause.

| Symptom | Likely cause | How to confirm |
| :--- | :--- | :--- |
| Fails **instantly** (< 0.1 s), SOCKS5 `0x01` / HTTP `404` | The tunnel name is wrong | Daemon log: `tunnel '<name>' not found in registry`. |
| Fails **instantly** (< 0.1 s), SOCKS5 `0x01` / HTTP `404` | The tunnel is disabled | Daemon log: `tunnel activation failed: ActivationFailed("<id>", "tunnel is disabled")`. Enable it with `wpmulti enable <id>`. |
| Fails after a **few seconds**, SOCKS5 `0x04` / HTTP `502` | The tunnel is suspended — a request wakes it again (lazy activation), then fails exactly like a dead tunnel | Daemon log: `WireGuard handshake not yet established (peer unreachable or timed out)`, the same message as a dead tunnel. Confirm with `wpmulti status`: the tunnel is `Active` again after the request. Same timing as a dead tunnel (~3 s for a domain, full `handshake_timeout` for an IP literal). |
| Fails **instantly** (< 0.1 s), SOCKS5 `0x03` / HTTP `503` | The selector is valid (a keyword such as `round-robin`, or a tunnel id) but **no tunnel is healthy right now** — all are down, unhealthy, or in cooldown | Daemon log: `no healthy tunnels available in pool`. Check `wpmulti status`: `healthy_tunnels: 0` means wait for a cooldown to end, or `enable` a tunnel. One exception is not a health problem at all: a `pool` (or `disabled_tunnels` / `eager_tunnels` / override key) naming a tunnel ID that no loaded `.conf` provides — a typo like `pool = ["wgcf-010"]` — also produces instant 0x03/503, because no tunnel can ever be tried. `validate` and `run` reject such configs with an `unknown tunnel id` error, so if you see this on a running daemon, the config was written before that check existed: run `wpmulti validate -c wpmulti.toml` to find the ghost id. Exceptions — the request first *tries* a tunnel instead of failing instantly when one can be tried: if a tunnel is `half_open`, the request first tries that one trial — and if the trial fails it fails like a dead tunnel (0x04/502), including when the trial is cut off by the 3.5 s failover budget, which ends without a verdict — the trial slot is released and the tunnel may be tried again; the same applies to a tunnel that has **never been tried yet** (`unknown` in `wpmulti status`): it is attempted like a healthy one, so the first request takes a few seconds and fails 0x04/502 if the handshake never completes. 0x03/503 only appears when no tunnel can be tried at all. |
| Fails after a **few seconds**, SOCKS5 `0x04` / HTTP `502` | The tunnel exists but the WireGuard handshake never completes (peer unreachable, wrong endpoint, or UDP blocked). Note the timing depends on the request: a domain name fails after ~3 s (the in-tunnel DNS query has a 3 s deadline), while an IP literal waits for the full `handshake_timeout` (`10s` by default). | Daemon log: `WireGuard handshake not yet established (peer unreachable or timed out)`. Run `wpmulti probe` (below). |
| Daemon log: `pool failover budget exceeded` | A pool request (e.g. `round-robin`) tried several tunnels and ran out of its shared **3.5 s failover budget** before any attempt completed — every candidate tunnel was failing its handshake. This is not a setting you can tune; it is the total time the pool is willing to spend failing over between tunnels. The message names the last attempt's error (e.g. `last error: WireGuard handshake not yet established …`), so the cause is on that same line; earlier WARN lines show each attempt. When no attempt finished inside the budget at all, the message reads `(no attempt completed)` instead — there is no last error to name. An attempt cut off by the budget ends without a verdict about the tunnel: it does not count as a failure, and a `half_open` trial cut off this way releases its trial slot without touching the failure count or cooldown, so the next request may trial the tunnel again. Destination-caused failures likewise do not count toward the breaker — a refused connection, an unroutable address family, a nonexistent domain, or a timeout against a peer that has handshaked before says the destination is at fault, not the tunnel; only genuine peer-side failures (a handshake that never completes, a torn-down stack) trip it. | Daemon log: read the `last error` in the same line, or the per-attempt WARN lines above it. |
| `probe` says `Operation not permitted` | **UDP is blocked in this environment** (sandbox/container without permission to send UDP). WireGuard handshakes need UDP, so no tunnel can ever connect here — the configs themselves may be fine. | `probe` prints a hint on stderr. Quick check: `python3 -c "import socket; socket.socket(socket.AF_INET, socket.SOCK_DGRAM).sendto(b'x', ('8.8.8.8', 53))"` — if that fails with `PermissionError`, UDP is blocked. |
| `probe` times out for one tunnel only | That tunnel's endpoint is unreachable or its keys are wrong | `probe` prints the full per-tunnel error under `Failed probe errors (full text):`. |
| SOCKS5 client hangs with no auth reply, then the connection closes after ~30 s | The 30 s handshake timeout fired: the auth exchange did not complete in time, so the server closed the connection without a reply | Daemon log: `SOCKS5 auth timed out` (warn). Retry the request — in testing this was intermittent and self-resolving. |

A misspelled tunnel name is **rejected**, never silently routed to another
tunnel: `curl -x socks5h://typo@127.0.0.1:1080 https://example.com` fails
immediately instead of using round-robin. If you expected round-robin, use
no username (or a keyword such as `auto`) instead of a tunnel name.

### The log shows ERROR lines from gotatun when I stop the daemon — or when I run `probe` — is something broken?

No — if the last line is `wpmulti stopped cleanly.`, the shutdown
succeeded. While the daemon tears down its WireGuard devices, the
`gotatun` stack can log:

- `ERROR gotatun::device: Unexpected error on tun interface: Custom { kind: UnexpectedEof, error: "channel closed" }`
- `ERROR gotatun::task: task "handle_outgoing" errored: true`

These are the tunnel device's background tasks noticing their channel
closed during teardown — expected noise, not a failure of your tunnels
or configs. They appear whenever a tunnel device is torn down: at
shutdown, or when an active tunnel is suspended or disabled. A one-shot
`probe` does the same thing in miniature — it brings a tunnel device
up, probes it, and tears it down again — so the same two lines can
appear right before the probe table. They say nothing about why the
probe failed; the real reason is the error text under the table (or in
`--json` output). The timing is racy — the same shutdown often shows
none of them at all — so seeing them mid-operation (for example right
after a `disable`) does not mean anything is broken, as long as the
daemon keeps running and `wpmulti status` looks normal.

### `wpmulti probe` says everything failed — what next?

1. Read the full error text under `Failed probe errors (full text):` (or use
   `--json`); the table truncates it.
2. `Operation not permitted` means UDP is blocked where wpmulti runs — see
   the table above. No config change fixes that; run wpmulti where UDP
   sends are allowed.
3. A timeout with no handshake means the peer never answered: check the
   `Endpoint` in the `.conf` file and the peer's public key.
