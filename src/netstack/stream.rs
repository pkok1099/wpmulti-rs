//! Virtual TCP stream and UDP socket implementations over smoltcp.
//!
//! Provides [`VirtualTcpStream`] implementing [`tokio::io::AsyncRead`] and
//! [`tokio::io::AsyncWrite`], and [`VirtualUdpSocket`] for datagram transfer.

use parking_lot::Mutex;
use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use smoltcp::iface::SocketHandle;
use smoltcp::socket::tcp::{self, State};
use smoltcp::socket::udp;
use smoltcp::wire::{IpAddress, IpEndpoint};
use tokio::sync::Notify;

use crate::netstack::stack::StackInner;

impl std::fmt::Debug for VirtualTcpStream {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("VirtualTcpStream")
            .field("handle", &self.handle)
            .field("local_addr", &self.local_addr)
            .field("peer_addr", &self.peer_addr)
            .field("closed", &self.closed)
            .finish_non_exhaustive()
    }
}

impl std::fmt::Debug for VirtualUdpSocket {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("VirtualUdpSocket")
            .field("handle", &self.handle)
            .field("local_port", &self.local_port)
            .finish_non_exhaustive()
    }
}
pub const fn to_smoltcp_endpoint(addr: SocketAddr) -> IpEndpoint {
    match addr {
        SocketAddr::V4(v4) => IpEndpoint::new(IpAddress::Ipv4(*v4.ip()), v4.port()),
        SocketAddr::V6(v6) => IpEndpoint::new(IpAddress::Ipv6(*v6.ip()), v6.port()),
    }
}

/// Helper: convert smoltcp IpEndpoint to standard SocketAddr.
pub const fn to_std_socket_addr(ep: IpEndpoint) -> SocketAddr {
    match ep.addr {
        IpAddress::Ipv4(v4) => SocketAddr::V4(std::net::SocketAddrV4::new(v4, ep.port)),
        IpAddress::Ipv6(v6) => SocketAddr::V6(std::net::SocketAddrV6::new(v6, ep.port, 0, 0)),
    }
}

/// Asynchronous TCP stream operating inside the virtual smoltcp network stack.
pub struct VirtualTcpStream {
    pub(crate) handle: SocketHandle,
    pub(crate) inner: Arc<Mutex<StackInner>>,
    pub(crate) notify: Arc<Notify>,
    pub(crate) local_addr: SocketAddr,
    pub(crate) peer_addr: SocketAddr,
    pub(crate) closed: bool,
}

impl VirtualTcpStream {
    /// Create a new stream wrapper from an established socket handle.
    pub(crate) const fn new(
        handle: SocketHandle,
        inner: Arc<Mutex<StackInner>>,
        notify: Arc<Notify>,
        local_addr: SocketAddr,
        peer_addr: SocketAddr,
    ) -> Self {
        Self {
            handle,
            inner,
            notify,
            local_addr,
            peer_addr,
            closed: false,
        }
    }

    /// Returns the local address of this stream.
    pub const fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }

    /// Returns the remote peer address of this stream.
    pub const fn peer_addr(&self) -> SocketAddr {
        self.peer_addr
    }
}

impl AsyncRead for VirtualTcpStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if self.closed {
            return Poll::Ready(Ok(()));
        }

        let mut inner = self.inner.lock();
        if !inner.sockets.iter().any(|(h, _)| h == self.handle) {
            drop(inner);
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::NotConnected,
                "tcp socket handle not found in socket set",
            )));
        }
        let socket = inner.sockets.get_mut::<tcp::Socket<'_>>(self.handle);

        match socket.state() {
            State::Established | State::CloseWait | State::FinWait1 | State::FinWait2 => {
                if socket.can_recv() {
                    let unfilled = buf.initialize_unfilled();
                    match socket.recv_slice(unfilled) {
                        Ok(n) => {
                            buf.advance(n);
                            drop(inner);
                            self.notify.notify_one();
                            Poll::Ready(Ok(()))
                        }
                        Err(tcp::RecvError::Finished) => Poll::Ready(Ok(())),
                        Err(tcp::RecvError::InvalidState) => Poll::Ready(Err(io::Error::new(
                            io::ErrorKind::NotConnected,
                            "tcp socket invalid state for recv",
                        ))),
                    }
                } else if !socket.may_recv() {
                    // FIN received and all bytes drained
                    Poll::Ready(Ok(()))
                } else {
                    socket.register_recv_waker(cx.waker());
                    Poll::Pending
                }
            }
            State::Closing | State::TimeWait | State::LastAck | State::Closed => {
                if socket.can_recv() {
                    let unfilled = buf.initialize_unfilled();
                    if let Ok(n) = socket.recv_slice(unfilled) {
                        buf.advance(n);
                        drop(inner);
                        self.notify.notify_one();
                        return Poll::Ready(Ok(()));
                    }
                }
                Poll::Ready(Ok(()))
            }
            State::SynSent | State::SynReceived => {
                socket.register_recv_waker(cx.waker());
                Poll::Pending
            }
            State::Listen => Poll::Ready(Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "listening socket cannot be read",
            ))),
        }
    }
}

impl AsyncWrite for VirtualTcpStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        if self.closed {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "stream is closed",
            )));
        }

        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }

        let mut inner = self.inner.lock();
        if !inner.sockets.iter().any(|(h, _)| h == self.handle) {
            drop(inner);
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::NotConnected,
                "tcp socket handle not found in socket set",
            )));
        }
        let socket = inner.sockets.get_mut::<tcp::Socket<'_>>(self.handle);

        match socket.state() {
            State::Established | State::CloseWait => {
                if !socket.may_send() {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::BrokenPipe,
                        "connection closed for writing",
                    )));
                }

                if socket.can_send() {
                    match socket.send_slice(buf) {
                        Ok(n) => {
                            drop(inner);
                            self.notify.notify_one();
                            Poll::Ready(Ok(n))
                        }
                        Err(tcp::SendError::InvalidState) => Poll::Ready(Err(io::Error::new(
                            io::ErrorKind::NotConnected,
                            "tcp socket invalid state for send",
                        ))),
                    }
                } else {
                    socket.register_send_waker(cx.waker());
                    Poll::Pending
                }
            }
            State::SynSent | State::SynReceived => {
                socket.register_send_waker(cx.waker());
                Poll::Pending
            }
            State::FinWait1
            | State::FinWait2
            | State::Closing
            | State::TimeWait
            | State::LastAck
            | State::Closed => Poll::Ready(Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "connection reset by peer or closed",
            ))),
            State::Listen => Poll::Ready(Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "listening socket cannot be written",
            ))),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if self.closed {
            return Poll::Ready(Ok(()));
        }

        let mut inner = self.inner.lock();
        if !inner.sockets.iter().any(|(h, _)| h == self.handle) {
            drop(inner);
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::NotConnected,
                "tcp socket handle not found in socket set",
            )));
        }
        let socket = inner.sockets.get_mut::<tcp::Socket<'_>>(self.handle);

        let poll = match socket.state() {
            State::Established | State::CloseWait => {
                if socket.send_queue() == 0 {
                    Poll::Ready(Ok(()))
                } else {
                    socket.register_send_waker(cx.waker());
                    Poll::Pending
                }
            }
            State::SynSent | State::SynReceived => {
                socket.register_send_waker(cx.waker());
                Poll::Pending
            }
            State::Closed
            | State::Listen
            | State::FinWait1
            | State::FinWait2
            | State::Closing
            | State::LastAck
            | State::TimeWait => Poll::Ready(Ok(())),
        };
        drop(inner);
        poll
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if self.closed {
            return Poll::Ready(Ok(()));
        }

        let mut inner = self.inner.lock();
        if !inner.sockets.iter().any(|(h, _)| h == self.handle) {
            drop(inner);
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::NotConnected,
                "tcp socket handle not found in socket set",
            )));
        }
        let socket = inner.sockets.get_mut::<tcp::Socket<'_>>(self.handle);

        match socket.state() {
            State::Established | State::CloseWait => {
                socket.close();
                socket.register_send_waker(cx.waker());
                drop(inner);
                self.notify.notify_one();
                Poll::Pending
            }
            State::FinWait1 | State::FinWait2 | State::Closing | State::LastAck => {
                socket.register_send_waker(cx.waker());
                Poll::Pending
            }
            State::Closed
            | State::Listen
            | State::SynSent
            | State::SynReceived
            | State::TimeWait => {
                drop(inner);
                self.get_mut().closed = true;
                Poll::Ready(Ok(()))
            }
        }
    }
}

impl Drop for VirtualTcpStream {
    fn drop(&mut self) {
        let mut inner = self.inner.lock();
        let exists = inner.sockets.iter().any(|(h, _)| h == self.handle);
        if exists {
            let socket = inner.sockets.get_mut::<tcp::Socket<'_>>(self.handle);
            if socket.is_active() {
                socket.abort();
            }
            inner.sockets.remove(self.handle);
            drop(inner);
            self.notify.notify_one();
        }
    }
}

/// Asynchronous UDP socket operating inside the virtual smoltcp network stack.
pub struct VirtualUdpSocket {
    pub(crate) handle: SocketHandle,
    pub(crate) inner: Arc<Mutex<StackInner>>,
    pub(crate) notify: Arc<Notify>,
    pub(crate) local_port: u16,
    pub(crate) ip_mode: crate::config::IpMode,
}

impl VirtualUdpSocket {
    /// Create a new virtual UDP socket wrapper.
    pub(crate) const fn new(
        handle: SocketHandle,
        inner: Arc<Mutex<StackInner>>,
        notify: Arc<Notify>,
        local_port: u16,
        ip_mode: crate::config::IpMode,
    ) -> Self {
        Self {
            handle,
            inner,
            notify,
            local_port,
            ip_mode,
        }
    }

    /// Send a UDP datagram to the specified destination.
    pub async fn send_to(&self, buf: &[u8], target: SocketAddr) -> Result<usize, io::Error> {
        self.ip_mode.check_ip(target.ip(), "UDP destination")?;
        let endpoint = to_smoltcp_endpoint(target);
        std::future::poll_fn(|cx| {
            let mut inner = self.inner.lock();
            if !inner.sockets.iter().any(|(h, _)| h == self.handle) {
                return Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::NotConnected,
                    "udp socket handle not found in socket set",
                )));
            }
            let socket = inner.sockets.get_mut::<udp::Socket<'_>>(self.handle);

            if socket.can_send() {
                match socket.send_slice(buf, endpoint) {
                    Ok(()) => {
                        drop(inner);
                        self.notify.notify_one();
                        Poll::Ready(Ok(buf.len()))
                    }
                    Err(udp::SendError::BufferFull) => {
                        socket.register_send_waker(cx.waker());
                        Poll::Pending
                    }
                    Err(udp::SendError::Unaddressable) => Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::AddrNotAvailable,
                        "unaddressable destination endpoint",
                    ))),
                }
            } else {
                socket.register_send_waker(cx.waker());
                Poll::Pending
            }
        })
        .await
    }

    /// Receive a UDP datagram into the provided buffer.
    pub async fn recv_from(&self, buf: &mut [u8]) -> Result<(usize, SocketAddr), io::Error> {
        std::future::poll_fn(|cx| {
            let mut inner = self.inner.lock();
            if !inner.sockets.iter().any(|(h, _)| h == self.handle) {
                return Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::NotConnected,
                    "udp socket handle not found in socket set",
                )));
            }
            let socket = inner.sockets.get_mut::<udp::Socket<'_>>(self.handle);

            if socket.can_recv() {
                match socket.recv_slice(buf) {
                    Ok((len, meta)) => {
                        let peer_addr = to_std_socket_addr(meta.endpoint);
                        drop(inner);
                        self.notify.notify_one();
                        Poll::Ready(Ok((len, peer_addr)))
                    }
                    Err(udp::RecvError::Truncated) => Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "received datagram truncated, buffer too small",
                    ))),
                    Err(udp::RecvError::Exhausted) => {
                        socket.register_recv_waker(cx.waker());
                        Poll::Pending
                    }
                }
            } else {
                socket.register_recv_waker(cx.waker());
                Poll::Pending
            }
        })
        .await
    }

    /// Returns the local port bound by this UDP socket.
    pub const fn local_port(&self) -> u16 {
        self.local_port
    }
}

impl Drop for VirtualUdpSocket {
    fn drop(&mut self) {
        let mut inner = self.inner.lock();
        let exists = inner.sockets.iter().any(|(h, _)| h == self.handle);
        if exists {
            inner.sockets.remove(self.handle);
            drop(inner);
            self.notify.notify_one();
        }
    }
}
