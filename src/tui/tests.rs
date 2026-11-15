//! Unit tests for Milestone 5: Interactive TUI Monitor (`wpmulti top`).

use std::sync::Arc;

use x25519_dalek::{PublicKey, StaticSecret};

use crate::config::{LifecycleMode, MainConfig, TuiSortField, TunnelConfig, WgInterfaceConfig, WgPeerConfig};
use crate::core::{TunnelManager, TunnelState, TunnelSummary};
use crate::tui::app::{TuiApp, TuiDataSource};
use crate::tui::ui::{format_bytes, render_dashboard};

fn make_test_tunnel_config(id: &str, endpoint: &str) -> TunnelConfig {
    TunnelConfig {
        id: id.to_string(),
        interface: WgInterfaceConfig {
            private_key: StaticSecret::from([42u8; 32]),
            addresses: vec!["172.16.0.2/32".parse().unwrap()],
            dns: vec!["1.1.1.1".parse().unwrap()],
            listen_port: None,
            mtu: 1420,
        },
        peers: vec![WgPeerConfig {
            public_key: PublicKey::from([99u8; 32]),
            endpoint: endpoint.to_string(),
            allowed_ips: vec!["0.0.0.0/0".parse().unwrap()],
            preshared_key: None,
            persistent_keepalive: Some(25),
        }],
    }
}

fn make_dummy_summary(id: &str, state: TunnelState, conns: usize, rx: u64, tx: u64) -> TunnelSummary {
    TunnelSummary {
        id: id.to_string(),
        state,
        mode: LifecycleMode::Lazy,
        active_conns: conns,
        total_conns: conns as u64,
        rx_bytes: rx,
        tx_bytes: tx,
        last_handshake: None,
        last_active_at: None,
        assigned_port: Some(10000),
        endpoint: Some("198.51.100.1:51820".to_string()),
    }
}

#[test]
fn test_tui_format_bytes() {
    assert_eq!(format_bytes(500), "500 B");
    assert_eq!(format_bytes(2048), "2.00 KB");
    assert_eq!(format_bytes(5 * 1024 * 1024), "5.00 MB");
    assert_eq!(format_bytes(10 * 1024 * 1024 * 1024), "10.00 GB");
}

#[test]
fn test_tui_app_initial_state_and_navigation() {
    let dummy_source = TuiDataSource::Remote {
        admin_url: "http://127.0.0.1:9090".to_string(),
        auth_token: None,
    };
    let mut app = TuiApp::new(dummy_source, TuiSortField::Id);

    let list = vec![
        make_dummy_summary("wgcf-001", TunnelState::Dormant, 0, 100, 200),
        make_dummy_summary("wgcf-002", TunnelState::Active, 2, 500, 600),
        make_dummy_summary("wgcf-003", TunnelState::Suspended, 0, 10, 20),
    ];
    app.set_tunnels(list);

    assert_eq!(app.filtered_indices.len(), 3);
    assert_eq!(app.selected_index, 0);

    // Navigate down
    app.select_next();
    assert_eq!(app.selected_index, 1);
    app.select_next();
    assert_eq!(app.selected_index, 2);
    // Boundary check
    app.select_next();
    assert_eq!(app.selected_index, 2);

    // Navigate up
    app.select_prev();
    assert_eq!(app.selected_index, 1);
    app.select_prev();
    assert_eq!(app.selected_index, 0);
    app.select_prev();
    assert_eq!(app.selected_index, 0);

    // Jump to bottom & top
    app.scroll_to_bottom();
    assert_eq!(app.selected_index, 2);
    app.scroll_to_top();
    assert_eq!(app.selected_index, 0);
}

#[test]
fn test_tui_search_filtering() {
    let dummy_source = TuiDataSource::Remote {
        admin_url: "http://127.0.0.1:9090".to_string(),
        auth_token: None,
    };
    let mut app = TuiApp::new(dummy_source, TuiSortField::Id);

    let list = vec![
        make_dummy_summary("alpha-01", TunnelState::Dormant, 0, 0, 0),
        make_dummy_summary("beta-02", TunnelState::Active, 0, 0, 0),
        make_dummy_summary("alpha-03", TunnelState::Suspended, 0, 0, 0),
    ];
    app.set_tunnels(list);
    assert_eq!(app.filtered_indices.len(), 3);

    // Search query matching 2 tunnels
    app.search_query = "alpha".to_string();
    app.apply_filter_and_sort();
    assert_eq!(app.filtered_indices.len(), 2);
    assert_eq!(app.tunnels[app.filtered_indices[0]].id, "alpha-01");
    assert_eq!(app.tunnels[app.filtered_indices[1]].id, "alpha-03");

    // Search query matching nothing
    app.search_query = "gamma".to_string();
    app.apply_filter_and_sort();
    assert_eq!(app.filtered_indices.len(), 0);
    assert_eq!(app.selected_index, 0);

    // Clear search
    app.search_query.clear();
    app.apply_filter_and_sort();
    assert_eq!(app.filtered_indices.len(), 3);
}

#[test]
fn test_tui_sorting() {
    let dummy_source = TuiDataSource::Remote {
        admin_url: "http://127.0.0.1:9090".to_string(),
        auth_token: None,
    };
    let mut app = TuiApp::new(dummy_source, TuiSortField::Conns);

    let list = vec![
        make_dummy_summary("t-low", TunnelState::Dormant, 1, 10, 20),
        make_dummy_summary("t-high", TunnelState::Active, 10, 50, 60),
        make_dummy_summary("t-mid", TunnelState::Suspended, 5, 30, 40),
    ];
    app.set_tunnels(list);

    // Ascending by Conns: 1, 5, 10
    assert_eq!(app.tunnels[app.filtered_indices[0]].id, "t-low");
    assert_eq!(app.tunnels[app.filtered_indices[1]].id, "t-mid");
    assert_eq!(app.tunnels[app.filtered_indices[2]].id, "t-high");

    // Invert to Descending: 10, 5, 1
    app.toggle_sort_direction();
    assert_eq!(app.tunnels[app.filtered_indices[0]].id, "t-high");
    assert_eq!(app.tunnels[app.filtered_indices[1]].id, "t-mid");
    assert_eq!(app.tunnels[app.filtered_indices[2]].id, "t-low");

    // Cycle sort field: Conns -> Rx
    app.cycle_sort();
    assert_eq!(app.sort_field, TuiSortField::Rx);
}

#[test]
fn test_tui_render_dashboard_ansi() {
    let dummy_source = TuiDataSource::Remote {
        admin_url: "http://127.0.0.1:9090".to_string(),
        auth_token: None,
    };
    let mut app = TuiApp::new(dummy_source, TuiSortField::Id);

    let list = vec![
        make_dummy_summary("wgcf-001", TunnelState::Active, 3, 1048576, 524288),
        make_dummy_summary("wgcf-002", TunnelState::Suspended, 0, 0, 0),
    ];
    app.set_tunnels(list);

    let output = render_dashboard(&mut app, 100, 30);
    assert!(output.contains("wpmulti v"));
    assert!(output.contains("Tunnels: Total: 2"));
    assert!(output.contains("Active:"));
    assert!(output.contains("wgcf-001"));
    assert!(output.contains("wgcf-002"));
    assert!(output.contains("Active Conns: 3"));
}

#[tokio::test]
async fn test_tui_in_process_activation_and_suspension() {
    let mut config = MainConfig::default();
    config.per_tunnel.enabled = false;
    let tunnels = vec![
        make_test_tunnel_config("t-alpha", "127.0.0.1:51820"),
    ];
    let mgr = Arc::new(TunnelManager::new(config, tunnels).unwrap());

    let mut app = TuiApp::new(TuiDataSource::InProcess(Arc::clone(&mgr)), TuiSortField::Id);
    app.refresh().await.expect("initial refresh");

    assert_eq!(app.tunnels.len(), 1);
    assert_eq!(app.tunnels[0].state, TunnelState::Dormant);

    // Activate selected
    app.activate_selected().await.expect("activate");
    assert_eq!(app.tunnels[0].state, TunnelState::Active);

    // Suspend selected
    app.suspend_selected().await.expect("suspend");
    assert_eq!(app.tunnels[0].state, TunnelState::Suspended);
}
