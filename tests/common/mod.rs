#![allow(dead_code)]
#![allow(unused_imports)]

pub mod admin_client;
pub mod fixtures;
pub mod http_client;
pub mod mock_peer;
pub mod socks5_client;

// Convenient re-exports for integration tests
pub use admin_client::AdminTestClient;
pub use fixtures::{
    SharedListenerFixture, TestEnvironment, WgConfBuilder, WgPeerFixture, WgcfFixtureSet,
    WpMultiTomlBuilder, allocate_ephemeral_port, allocate_ephemeral_port_range,
    generate_245_cloned_wgcf_configs,
};
pub use http_client::{HttpProxyTestClient, HttpResponse, read_http_headers};
pub use mock_peer::{MockIpEngine, MockPeerControls, MockPeerStats, MockWireGuardPeer};
pub use socks5_client::{
    ATYP_DOMAIN, ATYP_IPV4, ATYP_IPV6, CMD_CONNECT, CMD_UDP_ASSOCIATE, METHOD_NO_ACCEPTABLE,
    METHOD_NO_AUTH, METHOD_USER_PASS, REP_COMMAND_NOT_SUPPORTED, REP_CONN_REFUSED,
    REP_GENERAL_FAILURE, REP_SUCCESS, Socks5Target, Socks5TestClient, Socks5UdpSession,
};
