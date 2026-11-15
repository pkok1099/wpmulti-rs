//! smoltcp-based userspace network stack for wpmulti.

pub mod bridge;
pub mod dns;
pub mod stack;
pub mod stream;
#[cfg(test)]
pub mod tests;

pub use bridge::{
    BridgeIpRecv, BridgeIpSend, DEFAULT_CHANNEL_CAPACITY, DEFAULT_MTU, MAX_DRAIN_BATCH_SIZE,
    VirtualTunBridge,
};
pub use dns::{DnsError, DnsLruCache, InTunnelDnsResolver, QueryType, build_query, parse_response};
pub use stack::{
    DEFAULT_CONNECT_TIMEOUT, StackInner, TCP_RX_BUF_SIZE, TCP_TX_BUF_SIZE,
    UDP_PACKET_QUEUE_CAPACITY, UDP_PAYLOAD_BUF_SIZE, VirtualNetworkStack,
};
pub use stream::{VirtualTcpStream, VirtualUdpSocket, to_smoltcp_endpoint, to_std_socket_addr};
