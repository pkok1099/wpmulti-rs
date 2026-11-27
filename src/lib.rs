//! `wpmulti` is a high-concurrency multi-tunnel WireGuard proxy daemon
//! built on top of `gotatun` and `smoltcp`.

#![cfg_attr(
    test,
    allow(
        trivial_casts,
        unused_qualifications,
        clippy::pedantic,
        clippy::nursery,
        clippy::wildcard_enum_match_arm,
        clippy::large_futures,
        clippy::type_complexity,
        clippy::too_many_arguments,
        reason = "test builds: fixtures and helpers need looser lints"
    )
)]
#![cfg_attr(test, warn(clippy::too_many_lines, clippy::cognitive_complexity))]

pub mod api;
pub mod cli;
pub mod config;
pub mod core;
pub mod netstack;
pub mod proxy;
pub mod tui;

// Public re-exports for easy access by downstream modules and consumers
pub use api::{
    AdminServer, HttpRequest, HttpResponse, generate_prometheus_metrics, handle_admin_request,
    parse_http_request,
};
pub use cli::{
    Cli, Commands, ProbeResult, cmd_probe, cmd_run, cmd_status, cmd_top, cmd_validate, run_cli,
    run_probe_single,
};
pub use config::{
    AdminSettings, AuthMode, ConfigError, DnsPreference, DnsStrategy, GlobalSettings,
    HealthCheckSettings, IpMode, LifecycleMode, LifecycleSettings, ListenerType, LogLevel,
    MainConfig, PartialTunnelLoad, PerTunnelSettings, PoolStrategy, SharedListenerSettings,
    TuiSettings, TuiSortField, TunnelConfig, TunnelLoadFailure, TunnelPoolSelection,
    TunnelPortOverride, WgConfError, WgConfig, WgInterfaceConfig, WgPeerConfig,
    load_tunnel_config_from_file, load_tunnel_config_from_str, load_tunnel_configs_from_dir,
    load_tunnel_configs_from_dir_partial, parse_duration_str, parse_wg_conf, parse_wg_conf_file,
    strip_comment,
};
pub use core::{
    ActiveListenerInfo, ActiveProber, ActiveTunnel, CoreError, DedicatedTunnelRouter,
    GuardedStream, GuardedTunnelTarget, HealthStatus, LifecycleController, ListenerSupervisor,
    MeteredStream, MeteredUdpSocket, MultiTenantRouter, ProtectedUdpFactory, ReloadReport,
    SocketProtector, TunnelConnGuard, TunnelEntry, TunnelHealthTracker, TunnelManager,
    TunnelRegistry, TunnelState, TunnelStats, TunnelSummary, WgDevice,
};
pub use netstack::{
    BridgeIpRecv, BridgeIpSend, DEFAULT_CHANNEL_CAPACITY, DEFAULT_CONNECT_TIMEOUT, DEFAULT_MTU,
    DnsError, DnsLruCache, FLOW_IDLE_TIMEOUT, FlowKey, FlowRoute, FlowTable, InTunnelDnsResolver,
    MAX_DRAIN_BATCH_SIZE, QueryType, StackInner, TCP_RX_BUF_SIZE, TCP_TX_BUF_SIZE, TunEndpoint,
    TunIpRecv, TunIpSend, TunRoute, TunnelUsable, UDP_PACKET_QUEUE_CAPACITY, UDP_PAYLOAD_BUF_SIZE,
    VirtualNetworkStack, VirtualTcpStream, VirtualTunBridge, VirtualUdpSocket, VpnRouteStrategy,
    build_query, longest_prefix_route, parse_flow_key, parse_response, to_smoltcp_endpoint,
    to_std_socket_addr,
};
pub use proxy::{
    ATYP_DOMAIN, ATYP_IPV4, ATYP_IPV6, AsyncReadWrite, CMD_BIND, CMD_CONNECT, CMD_UDP_ASSOCIATE,
    DirectTunnelTarget, DynStream, METHOD_GSSAPI, METHOD_NO_ACCEPTABLE, METHOD_NO_AUTH,
    METHOD_USER_PASS, PoolKeyword, PoolRouter, ProxyAuthError, ProxyTunnelTarget, ProxyUdpSocket,
    REP_ADDR_NOT_SUPPORTED, REP_CMD_NOT_SUPPORTED, REP_CONN_NOT_ALLOWED, REP_CONN_REFUSED,
    REP_GENERAL_FAILURE, REP_HOST_UNREACHABLE, REP_NETWORK_UNREACHABLE, REP_SUCCESS,
    REP_TTL_EXPIRED, RFC1929_VERSION, SOCKS5_VERSION, SingleTunnelRouter, TargetAddr, TunnelRouter,
    TunnelSelector, build_socks5_udp_packet, encode_target_addr, encode_target_addr_slice,
    extract_basic_auth, handle_http, handle_http_with_peer, handle_socks5,
    handle_socks5_with_addrs, parse_authority, parse_socks5_udp_packet, read_http_request_headers,
    read_http_request_headers_buffered, run_http_listener, run_socks5_listener, send_socks5_reply,
    write_socks5_udp_header,
};
pub use tui::{TuiApp, TuiDataSource, format_bytes, render_dashboard, run_terminal_tui};
