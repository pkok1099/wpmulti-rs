# Third-Party Notices & Attributions

`wpmulti` is licensed under the **Mozilla Public License 2.0** ([LICENSE](LICENSE)) and builds upon the following open-source projects and Rust crates.

## Core Upstream Foundations

- **[gotatun](https://github.com/mullvad/gotatun)** (`gotatun`, `gotatun-crypto`, `gotatun-packet`) — Mullvad VPN's userspace WireGuard implementation in Rust (originally forked from Cloudflare's `boringtun`). Licensed under **MPL-2.0**.
- **[smoltcp](https://github.com/smoltcp-rs/smoltcp)** — Standalone, event-driven TCP/IP stack for embedded and userspace networking. Licensed under **0BSD**.

## Direct Crate Dependencies

| Crate | Version | License | Repository |
| :--- | :--- | :--- | :--- |
| `base64` | 0.22.1 | MIT OR Apache-2.0 | https://github.com/marshallpierce/rust-base64 |
| `clap` | 3.2.25 | MIT OR Apache-2.0 | https://github.com/clap-rs/clap |
| `gotatun` | 0.10.3 | MPL-2.0 | https://github.com/mullvad/gotatun |
| `gotatun-crypto` | 0.1.0 | MPL-2.0 | https://github.com/mullvad/gotatun |
| `gotatun-packet` | 0.1.0 | MPL-2.0 | https://github.com/mullvad/gotatun |
| `ipnetwork` | 0.21.1 | MIT OR Apache-2.0 | https://github.com/achanda/ipnetwork |
| `libc` | 0.2.191 | MIT OR Apache-2.0 | https://github.com/rust-lang/libc |
| `parking_lot` | 0.12.5 | MIT OR Apache-2.0 | https://github.com/Amanieu/parking_lot |
| `rand` | 0.9.5 | MIT OR Apache-2.0 | https://github.com/rust-random/rand |
| `serde` | 1.0.229 | MIT OR Apache-2.0 | https://github.com/serde-rs/serde |
| `serde_json` | 1.0.154 | MIT OR Apache-2.0 | https://github.com/serde-rs/json |
| `smoltcp` | 0.14.0 | 0BSD | https://github.com/smoltcp-rs/smoltcp.git |
| `thiserror` | 1.0.69 | MIT OR Apache-2.0 | https://github.com/dtolnay/thiserror |
| `tokio` | 1.54.1 | MIT | https://github.com/tokio-rs/tokio |
| `toml` | 0.8.23 | MIT OR Apache-2.0 | https://github.com/toml-rs/toml |
| `tracing` | 0.1.44 | MIT | https://github.com/tokio-rs/tracing |
| `tracing-subscriber` | 0.3.23 | MIT | https://github.com/tokio-rs/tracing |
| `x25519-dalek` | 2.0.1 | BSD-3-Clause | https://github.com/dalek-cryptography/curve25519-dalek/tree/main/x25519-dalek |
| `zerocopy` | 0.8.63 | BSD-2-Clause OR Apache-2.0 OR MIT | https://github.com/google/zerocopy |

> **Note for binary / mobile distributions**: When distributing compiled binaries or Android AAR/APK builds, generate a full transitive license bundle from `Cargo.lock` using `cargo about` or `cargo license`.
