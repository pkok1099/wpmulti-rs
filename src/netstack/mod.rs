//! smoltcp-based userspace network stack for wpmulti.

pub mod bridge;
pub mod dns;
pub mod doh;
#[cfg(test)]
mod loopback_guard_tests;
pub mod stack;
pub mod stream;
#[cfg(test)]
pub mod tests;
pub mod tun;

pub use bridge::{
    BridgeCounters, BridgeCountersSnapshot, BridgeIpRecv, BridgeIpSend, DEFAULT_CHANNEL_CAPACITY,
    DEFAULT_MTU, MAX_DRAIN_BATCH_SIZE, VirtualTunBridge,
};
pub use dns::{
    DnsError, DnsLruCache, InTunnelDnsResolver, QueryType, build_query, build_response,
    parse_response,
};
pub use doh::{DohClient, DohError, DohTcpConnector};
pub use stack::{
    DEFAULT_CONNECT_TIMEOUT, StackDnsConfig, StackInner, TCP_RX_BUF_SIZE, TCP_TX_BUF_SIZE,
    UDP_PACKET_QUEUE_CAPACITY, UDP_PAYLOAD_BUF_SIZE, VirtualNetworkStack,
};
pub use stream::{VirtualTcpStream, VirtualUdpSocket, to_smoltcp_endpoint, to_std_socket_addr};
pub use tun::{
    DnsResolver, FLOW_IDLE_TIMEOUT, FlowKey, FlowRoute, FlowTable, TunByteCounts, TunCounters,
    TunEndpoint, TunIpRecv, TunIpSend, TunRoute, TunStatsSnapshot, TunnelUsable, VpnRouteStrategy,
    longest_prefix_route, parse_flow_key,
};
