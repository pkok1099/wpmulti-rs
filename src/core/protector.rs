//! Socket protection for VPN mode: keep WireGuard's own UDP sockets
//! outside the VPN's routing, so tunnel traffic does not loop back
//! into the TUN interface it is supposed to carry.
//!
//! On Android this is `VpnService.protect(fd)`, reached through a
//! UniFFI callback from Kotlin. The core only knows the
//! [`SocketProtector`] trait; the UniFFI crate bridges it to Kotlin.

use std::io;
use std::os::fd::{AsFd, AsRawFd};
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::sync::Arc;

use gotatun::udp::socket::{UdpSocket, UdpSocketFactory};
use gotatun::udp::{UdpTransportFactory, UdpTransportFactoryParams};

/// Protect one socket fd from the VPN's own routing.
///
/// Implemented in Kotlin by `VpnService.protect(fd)`. Returning
/// `false` means protection failed and the socket must not be used.
pub trait SocketProtector: Send + Sync + std::fmt::Debug {
    /// Protect `fd` (a UDP socket). Returns `true` on success.
    fn protect(&self, fd: i32) -> bool;
}

/// A gotatun UDP factory that protects every socket it binds.
///
/// Delegates the bind to [`UdpSocketFactory`], then calls the
/// protector on the socket's raw fd before returning it. `bind` hands
/// back two clones of one underlying socket, so one `protect` call
/// covers both halves. A failed `protect` fails the bind: a tunnel
/// must never come up with an unprotected socket, silently skipping
/// the call would route its own handshake packets into the TUN
/// interface and wedge the tunnel.
///
/// The call is synchronous on purpose. `bind` runs once per tunnel
/// boot, never on the data path, so blocking the worker briefly for
/// the protector's binder round-trip is acceptable. `block_in_place`
/// was not used: gotatun may invoke `bind` from contexts where it
/// panics (current-thread runtimes, `block_on` in tests), while a
/// direct call works everywhere.
#[derive(Debug, Default)]
pub struct ProtectedUdpFactory {
    inner: UdpSocketFactory,
    protector: Option<Arc<dyn SocketProtector>>,
}

impl ProtectedUdpFactory {
    /// Build a factory that protects sockets with `protector`.
    pub fn new(protector: Arc<dyn SocketProtector>) -> Self {
        Self {
            inner: UdpSocketFactory::default(),
            protector: Some(protector),
        }
    }

    /// Build a factory that binds sockets without protecting them.
    /// Test-only: unit tests of the factory itself use it directly.
    /// VPN-mode boots never use it — [`LifecycleController::boot_tunnel_vpn`]
    /// fails closed when no protector is installed instead of
    /// silently binding unprotected sockets.
    pub fn unprotected() -> Self {
        Self::default()
    }
}

impl UdpTransportFactory for ProtectedUdpFactory {
    type Send = UdpSocket;
    type Recv = UdpSocket;

    async fn bind(
        &mut self,
        params: &UdpTransportFactoryParams,
    ) -> io::Result<(Self::Send, Self::Recv)> {
        let (send, recv) = self.inner.bind(params).await?;
        if let Some(protector) = &self.protector {
            let fd = send.as_fd().as_raw_fd();
            // The protector is a Kotlin callback (`VpnService.protect`)
            // reached through UniFFI: a Kotlin exception surfaces here
            // as a Rust panic (the callback has no error return), and
            // an uncaught panic would unwind past the boot path's
            // cleanup (audit run-1,
            // `uniffi:socket-protector-kotlin-exception-panics`).
            // Catch it and fail the bind like a `false` return, so
            // `boot_tunnel_vpn` detaches the TUN route it already
            // registered. This only helps under `panic=unwind`
            // (the `release-android` profile); under `panic=abort`
            // the process still dies, as it must.
            let Ok(protected) = catch_unwind(AssertUnwindSafe(|| protector.protect(fd))) else {
                return Err(io::Error::other(format!(
                    "socket protect() panicked for fd {fd}"
                )));
            };
            if !protected {
                return Err(io::Error::other(format!(
                    "socket protect() rejected fd {fd}"
                )));
            }
        }
        Ok((send, recv))
    }
}
