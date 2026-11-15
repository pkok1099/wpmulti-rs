//! smoltcp-based userspace network stack for wpmulti.

pub mod bridge;
pub mod dns;
pub mod stack;
pub mod stream;
#[cfg(test)]
pub mod tests;

pub use bridge::{
    BridgeIpRecv, BridgeIpSend, VirtualTunBridge, DEFAULT_CHANNEL_CAPACITY, DEFAULT_MTU,
    MAX_DRAIN_BATCH_SIZE,
};
pub use dns::{build_query, parse_response, DnsError, DnsLruCache, InTunnelDnsResolver, QueryType};
pub use stack::{
    StackInner, VirtualNetworkStack, DEFAULT_CONNECT_TIMEOUT, TCP_RX_BUF_SIZE, TCP_TX_BUF_SIZE,
    UDP_PACKET_QUEUE_CAPACITY, UDP_PAYLOAD_BUF_SIZE,
};
pub use stream::{to_smoltcp_endpoint, to_std_socket_addr, VirtualTcpStream, VirtualUdpSocket};
