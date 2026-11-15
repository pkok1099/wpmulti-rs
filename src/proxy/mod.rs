//! Proxy engines for `wpmulti`: SOCKS5 (RFC 1928, RFC 1929) and HTTP CONNECT (RFC 9110, RFC 7617).

pub mod http;
pub mod router;
pub mod socks5;
#[cfg(test)]
pub mod tests;

use std::io;
use std::sync::Arc;

pub use http::{
    extract_basic_auth, handle_http, parse_authority, read_http_request_headers,
    read_http_request_headers_buffered,
};
pub use router::{
    AsyncReadWrite, DirectTunnelTarget, DynStream, PoolKeyword, PoolRouter, ProxyAuthError,
    ProxyTunnelTarget, ProxyUdpSocket, SingleTunnelRouter, TargetAddr, TunnelRouter, TunnelSelector,
};
pub use socks5::{
    build_socks5_udp_packet, encode_target_addr, encode_target_addr_slice, handle_socks5,
    handle_socks5_with_addrs, parse_socks5_udp_packet, send_socks5_reply,
    write_socks5_udp_header, ATYP_DOMAIN, ATYP_IPV4, ATYP_IPV6, CMD_BIND, CMD_CONNECT,
    CMD_UDP_ASSOCIATE, METHOD_GSSAPI, METHOD_NO_ACCEPTABLE, METHOD_NO_AUTH, METHOD_USER_PASS,
    REP_ADDR_NOT_SUPPORTED, REP_CMD_NOT_SUPPORTED, REP_CONN_NOT_ALLOWED, REP_CONN_REFUSED,
    REP_GENERAL_FAILURE, REP_HOST_UNREACHABLE, REP_NETWORK_UNREACHABLE, REP_SUCCESS,
    REP_TTL_EXPIRED, RFC1929_VERSION, SOCKS5_VERSION,
};

/// Runs an asynchronous SOCKS5 server listening on the provided [`tokio::net::TcpListener`].
pub async fn run_socks5_listener(
    listener: tokio::net::TcpListener,
    router: Arc<dyn TunnelRouter>,
) -> io::Result<()> {
    loop {
        let (stream, peer_addr) = listener.accept().await?;
        let local_ip = stream.local_addr().ok().map(|a| a.ip());
        let peer_ip = Some(peer_addr.ip());
        let router_clone = Arc::clone(&router);
        tokio::spawn(async move {
            if let Err(e) = handle_socks5_with_addrs(stream, router_clone, local_ip, peer_ip).await {
                tracing::debug!("SOCKS5 client {} disconnected: {:?}", peer_addr, e);
            }
        });
    }
}

/// Runs an asynchronous HTTP/HTTPS CONNECT proxy server listening on the provided [`tokio::net::TcpListener`].
pub async fn run_http_listener(
    listener: tokio::net::TcpListener,
    router: Arc<dyn TunnelRouter>,
) -> io::Result<()> {
    loop {
        let (stream, peer_addr) = listener.accept().await?;
        let router_clone = Arc::clone(&router);
        tokio::spawn(async move {
            if let Err(e) = handle_http(stream, router_clone).await {
                tracing::debug!("HTTP proxy client {} disconnected: {:?}", peer_addr, e);
            }
        });
    }
}
