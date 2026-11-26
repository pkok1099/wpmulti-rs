//! Test-only tunnel target for end-to-end proxy tests that need a live echo server.
//!
//! The destination guard forbids loopback (and RFC1918) proxy targets, so the
//! client names a public TEST-NET-1 stand-in address and this target dials the
//! loopback echo listener instead. The proxy path under test still sees a
//! public destination, and no real egress happens: the mock only ever dials
//! the local echo server.

use std::future::Future;
use std::io;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::pin::Pin;

use wpmulti::proxy::{DynStream, ProxyTunnelTarget, ProxyUdpSocket};

/// TEST-NET-1 address named as the proxy-visible destination in tests that
/// need a live echo server (see [`EchoRedirectTarget`]).
pub const TEST_ECHO_IP: IpAddr = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1));

/// Proxy-visible destination for `echo_addr`: same port, TEST-NET-1 IP.
pub fn test_echo_target(echo_addr: SocketAddr) -> SocketAddr {
    SocketAddr::new(TEST_ECHO_IP, echo_addr.port())
}

/// UDP socket that redirects the TEST-NET-1 stand-in to the loopback echo
/// listener on send, and reports replies as coming from the stand-in on
/// receive — so the relay's expected-destination check (which keys on the
/// destination the client actually named) passes for the echoed reply.
pub struct UdpEchoRedirectSocket {
    inner: tokio::net::UdpSocket,
    echo: SocketAddr,
}

impl UdpEchoRedirectSocket {
    pub fn new(inner: tokio::net::UdpSocket, echo: SocketAddr) -> Self {
        Self { inner, echo }
    }
}

impl ProxyUdpSocket for UdpEchoRedirectSocket {
    fn send_to<'a>(
        &'a self,
        buf: &'a [u8],
        target: SocketAddr,
    ) -> Pin<Box<dyn Future<Output = io::Result<usize>> + Send + 'a>> {
        Box::pin(async move {
            let dst = if target.ip() == TEST_ECHO_IP {
                SocketAddr::new(self.echo.ip(), target.port())
            } else {
                target
            };
            self.inner.send_to(buf, dst).await
        })
    }

    fn recv_from<'a>(
        &'a self,
        buf: &'a mut [u8],
    ) -> Pin<Box<dyn Future<Output = io::Result<(usize, SocketAddr)>> + Send + 'a>> {
        Box::pin(async move {
            let (n, peer) = self.inner.recv_from(buf).await?;
            let peer = if peer.ip() == self.echo.ip() {
                SocketAddr::new(TEST_ECHO_IP, peer.port())
            } else {
                peer
            };
            Ok((n, peer))
        })
    }

    fn local_port(&self) -> u16 {
        self.inner.local_addr().map_or(0, |a| a.port())
    }
}

/// Tunnel target that dials a fixed loopback echo listener regardless of
/// the destination the proxy client named (TCP) and redirects UDP
/// datagrams named at the TEST-NET-1 stand-in to the same listener.
pub struct EchoRedirectTarget {
    dial: SocketAddr,
}

impl EchoRedirectTarget {
    pub fn new(dial: SocketAddr) -> Self {
        Self { dial }
    }
}

impl ProxyTunnelTarget for EchoRedirectTarget {
    fn tcp_connect<'a>(
        &'a self,
        _dst: SocketAddr,
    ) -> Pin<Box<dyn Future<Output = io::Result<DynStream>> + Send + 'a>> {
        let dial = self.dial;
        Box::pin(async move {
            let stream: DynStream = Box::new(tokio::net::TcpStream::connect(dial).await?);
            Ok(stream)
        })
    }

    fn udp_bind<'a>(
        &'a self,
        local_port: u16,
    ) -> Pin<Box<dyn Future<Output = io::Result<Box<dyn ProxyUdpSocket>>> + Send + 'a>> {
        let echo = self.dial;
        Box::pin(async move {
            let bind_addr = SocketAddr::from(([0, 0, 0, 0], local_port));
            let socket = tokio::net::UdpSocket::bind(bind_addr).await?;
            let socket: Box<dyn ProxyUdpSocket> =
                Box::new(UdpEchoRedirectSocket::new(socket, echo));
            Ok(socket)
        })
    }

    fn resolve_in_tunnel<'a>(
        &'a self,
        domain: &'a str,
    ) -> Pin<Box<dyn Future<Output = io::Result<IpAddr>> + Send + 'a>> {
        Box::pin(async move {
            if let Ok(ip) = domain.parse::<IpAddr>() {
                return Ok(ip);
            }
            let host_port = format!("{domain}:0");
            let mut addrs = tokio::net::lookup_host(&host_port).await?;
            addrs
                .next()
                .map(|s| s.ip())
                .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "no addresses found"))
        })
    }
}
