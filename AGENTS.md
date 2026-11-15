# Agent & Contributor Rules (`wpmulti`)

Every AI agent and contributor working in this repository MUST follow these rules so all changes are consistent, safe, and maintainable.

## 1. Mandatory Verification Before Finishing
Always run after your final edit:
```bash
cargo fmt --check
cargo clippy --locked --all-targets -- -D warnings
cargo test --locked --all-targets
```
Never report checks as passing unless you ran them after your final edit and observed 0 errors, 0 warnings, and 0 test failures.

## 2. Strict Lint & Code-Size Policy (`clippy.toml` + `Cargo.toml`)
- **No panics in production code (`src/`)**:
  - `unwrap_used = "deny"`, `expect_used = "warn"`, `panic = "warn"`, `indexing_slicing = "warn"`.
  - Use `?`, `let ... else`, `.get(...)`, `.first()`, `.split_once(...)` instead of `.unwrap()` or `slice[i]`.
- **No unsafe or placeholders**:
  - `unsafe_code = "forbid"`, `dbg_macro = "deny"`, `todo = "deny"`, `unimplemented = "deny"`.
- **Async & Concurrency safety**:
  - `await_holding_lock = "deny"`, `large_futures = "warn"`. Never hold `parking_lot` / `std::sync` locks across `.await`.
- **Exhaustive enum matching**:
  - `wildcard_enum_match_arm = "deny"` and `unnested_or_patterns = "deny"`. Match enum variants explicitly so new variants fail to compile until handled.
- **Function & Type Complexity Limits (`clippy.toml`)**:
  - Max lines per function: `100`
  - Max cognitive complexity: `20`
  - Max function arguments: `6` (group related args into a struct or tuple)
  - Max `bool` parameters per function: `2` (use a small options struct or enum)
  - No `#[allow(clippy::...)]` in production code unless genuinely unavoidable (e.g. RFC acronym like `AAAA`) with a brief comment explaining why.

## 3. Code Organization & Module Boundaries
Keep each module focused and single-purpose:
- `src/config/` — `wpmulti.toml` and WireGuard `.conf` parsing, defaults, and validation.
- `src/core/` — `TunnelManager`, `TunnelRegistry`, `LifecycleController`, `TunnelHealthTracker`/`ActiveProber`, `MultiTenantRouter`, `ListenerManager`.
- `src/netstack/` — Userspace `smoltcp` TCP/UDP stack, `VirtualTunBridge`, and in-tunnel DNS resolver/cache.
- `src/proxy/` — Protocol handlers (SOCKS5 TCP/UDP ASSOCIATE, HTTP CONNECT/forward) and router traits.
- `src/api/` — Admin HTTP REST API routes, server, and Prometheus `/metrics`.
- `src/tui/` — Ratatui UI rendering (`ui.rs`), state (`app.rs`), and log ring buffer (`logs.rs`).
- `src/cli/` — `clap` CLI definitions (`mod.rs`) and command handlers (`commands.rs`).

## 4. Coding Style
- Format with `rustfmt.toml` (`edition = "2024"`, `max_width = 100`, field-init & `?` shorthands).
- Avoid duplicate logic: extract shared helpers instead of copy-pasting blocks.
- Keep docstrings accurate; comment *why* for non-obvious invariants, not *what*.
- Every new feature or bugfix must add or update tests in the corresponding `tests.rs` or `tests/` integration suite.
