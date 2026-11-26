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

/// Tunnel target that dials a fixed loopback echo listener regardless of
/// the destination the proxy client named.
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
        Box::pin(async move {
            let bind_addr = SocketAddr::from(([0, 0, 0, 0], local_port));
            let socket: Box<dyn ProxyUdpSocket> =
                Box::new(tokio::net::UdpSocket::bind(bind_addr).await?);
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
