//! `wpmulti` is a high-concurrency multi-tunnel WireGuard proxy daemon
//! built on top of `gotatun` and `smoltcp`.

pub mod api;
pub mod cli;
pub mod config;
pub mod core;
pub mod netstack;
pub mod proxy;
pub mod tui;

// Public re-exports for easy access by downstream modules and consumers
pub use api::{
    generate_prometheus_metrics, handle_admin_request, parse_http_request, AdminServer,
    HttpRequest, HttpResponse,
};
pub use cli::{cmd_run, cmd_status, cmd_top, cmd_validate, run_cli, Cli, Commands};
pub use tui::{format_bytes, render_dashboard, run_terminal_tui, TuiApp, TuiDataSource};
pub use core::{
    ActiveListenerInfo, ActiveTunnel, CoreError, DedicatedTunnelRouter, GuardedStream,
    GuardedTunnelTarget, LifecycleController, ListenerSupervisor, MeteredStream, MeteredUdpSocket,
    MultiTenantRouter, ReloadReport, TunnelConnGuard, TunnelEntry, TunnelManager,
    TunnelRegistry, TunnelState, TunnelStats, TunnelSummary, WgDevice,
};
pub use config::{
    load_tunnel_config_from_file, load_tunnel_config_from_str, load_tunnel_configs_from_dir,
    parse_duration_str, parse_wg_conf, parse_wg_conf_file, strip_comment, AdminSettings,
    AuthMode, ConfigError, DnsPreference, DnsStrategy, GlobalSettings, IpMode, LifecycleMode,
    LifecycleSettings, ListenerType, LogLevel, MainConfig, PerTunnelSettings, PoolStrategy,
    SharedListenerSettings, TuiSettings, TuiSortField, TunnelConfig, TunnelPoolSelection,
    TunnelPortOverride, WgConfig, WgConfError, WgInterfaceConfig, WgPeerConfig,
};
pub use netstack::{
    build_query, parse_response, to_smoltcp_endpoint, to_std_socket_addr, BridgeIpRecv,
    BridgeIpSend, DnsError, DnsLruCache, InTunnelDnsResolver, QueryType, StackInner,
    VirtualNetworkStack, VirtualTcpStream, VirtualTunBridge, VirtualUdpSocket,
    DEFAULT_CHANNEL_CAPACITY, DEFAULT_CONNECT_TIMEOUT, DEFAULT_MTU, MAX_DRAIN_BATCH_SIZE,
    TCP_RX_BUF_SIZE, TCP_TX_BUF_SIZE, UDP_PACKET_QUEUE_CAPACITY, UDP_PAYLOAD_BUF_SIZE,
};
pub use proxy::{
    build_socks5_udp_packet, encode_target_addr, extract_basic_auth, handle_http, handle_socks5,
    parse_authority, parse_socks5_udp_packet, read_http_request_headers, run_http_listener,
    run_socks5_listener, send_socks5_reply, AsyncReadWrite, DirectTunnelTarget, DynStream,
    PoolKeyword, PoolRouter, ProxyAuthError, ProxyTunnelTarget, ProxyUdpSocket, SingleTunnelRouter,
    TargetAddr, TunnelRouter, TunnelSelector, ATYP_DOMAIN, ATYP_IPV4, ATYP_IPV6, CMD_BIND,
    CMD_CONNECT, CMD_UDP_ASSOCIATE, METHOD_GSSAPI, METHOD_NO_ACCEPTABLE, METHOD_NO_AUTH,
    METHOD_USER_PASS, REP_ADDR_NOT_SUPPORTED, REP_CMD_NOT_SUPPORTED, REP_CONN_NOT_ALLOWED,
    REP_CONN_REFUSED, REP_GENERAL_FAILURE, REP_HOST_UNREACHABLE, REP_NETWORK_UNREACHABLE,
    REP_SUCCESS, REP_TTL_EXPIRED, RFC1929_VERSION, SOCKS5_VERSION,
};
