//! Unit tests for Milestone 5: Interactive TUI Monitor (`wpmulti top`).

use std::sync::Arc;

use x25519_dalek::{PublicKey, StaticSecret};

use crate::config::{LifecycleMode, MainConfig, TuiSortField, TunnelConfig, WgInterfaceConfig, WgPeerConfig};
use crate::core::{HealthStatus, TunnelManager, TunnelState, TunnelSummary};
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
        health: HealthStatus::Healthy,
        consecutive_failures: 0,
        cooldown_remaining_secs: 0,
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
    assert!(output.contains("Tunnels: 2"));
    assert!(output.contains("1 active"));
    assert!(output.contains("wgcf-001"));
    assert!(output.contains("wgcf-002"));
    assert!(output.contains("Conns: 3"));
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

#[test]
fn test_parse_key_sequence_arrows_and_nav() {
    use crate::tui::ui::{parse_key_sequence, parse_keys_from_bytes, parse_next_key, TuiKey};

    assert_eq!(parse_key_sequence(b"\x1b[A"), Some(TuiKey::Up));
    assert_eq!(parse_key_sequence(b"\x1b[B"), Some(TuiKey::Down));
    assert_eq!(parse_key_sequence(b"\x1bOA"), Some(TuiKey::Up));
    assert_eq!(parse_key_sequence(b"\x1bOB"), Some(TuiKey::Down));
    assert_eq!(parse_key_sequence(b"\x1b[5~"), Some(TuiKey::PageUp));
    assert_eq!(parse_key_sequence(b"\x1b[6~"), Some(TuiKey::PageDown));
    assert_eq!(parse_key_sequence(b"\x1b[H"), Some(TuiKey::Home));
    assert_eq!(parse_key_sequence(b"\x1b[F"), Some(TuiKey::End));
    assert_eq!(parse_key_sequence(b"\x1b[7~"), Some(TuiKey::Home));
    assert_eq!(parse_key_sequence(b"\x1b[8~"), Some(TuiKey::End));
    assert_eq!(parse_key_sequence(b"\x1b"), Some(TuiKey::Esc));
    assert_eq!(parse_key_sequence(b"j"), Some(TuiKey::Char('j')));
    assert_eq!(parse_key_sequence(b""), None);

    // Incomplete CSI prefix waits for more bytes
    assert_eq!(parse_next_key(b"\x1b["), (None, 0));

    // Coalesced reads & UTF-8 input
    assert_eq!(
        parse_keys_from_bytes(b"\x1b[A\x1b[Bjq"),
        vec![TuiKey::Up, TuiKey::Down, TuiKey::Char('j'), TuiKey::Char('q')]
    );
    assert_eq!(
        parse_keys_from_bytes("αβ".as_bytes()),
        vec![TuiKey::Char('α'), TuiKey::Char('β')]
    );
}

#[test]
fn test_render_dashboard_small_terminal_auto_resize() {
    use crate::tui::ui::render_dashboard;

    let mut app = TuiApp::new(
        TuiDataSource::Remote {
            admin_url: "http://127.0.0.1:9090".to_string(),
            auth_token: None,
        },
        TuiSortField::Id,
    );
    app.set_tunnels(vec![
        make_dummy_summary("wgcf-very-long-tunnel-name-001", TunnelState::Active, 2, 1024, 2048),
        make_dummy_summary("wgcf-002", TunnelState::Dormant, 0, 0, 0),
    ]);

    // Minimum clamped terminal (24x8): compact header, no trailing newline
    let min_render = render_dashboard(&mut app, 24, 8);
    assert!(min_render.contains("wpmulti v"));
    assert!(!min_render.ends_with('\n'));

    // Very small terminal (50x12) uses compact header and omits ENDPOINT/PORT/TX
    let compact = render_dashboard(&mut app, 50, 12);
    assert!(compact.contains("wpmulti v"));
    assert!(!compact.contains("ENDPOINT"));
    assert!(compact.contains("Tunnel 1 of 2"));
    assert!(!compact.ends_with('\n'));

    // Medium terminal (80x20) shows full box header and PORT, omits ENDPOINT
    let medium = render_dashboard(&mut app, 80, 20);
    assert!(medium.contains("PORT"));
    assert!(!medium.contains("ENDPOINT"));

    // Active search & status banner render cleanly
    app.is_searching = true;
    app.search_query = "wgcf".to_string();
    let with_search = render_dashboard(&mut app, 80, 20);
    assert!(with_search.contains("Search: wgcf"));

    app.is_searching = false;
    app.status_message = Some(("Reloaded".to_string(), std::time::Instant::now()));
    let with_status = render_dashboard(&mut app, 80, 20);
    assert!(with_status.contains(">>> Reloaded"));
}

#[test]
fn test_multi_tab_switching_logs_and_rendering() {
    use crate::config::toml_config::MainConfig;
    use crate::config::ListenerType;
    use crate::core::listener::ActiveListenerInfo;
    use crate::tui::logs::TuiLogBuffer;
    use crate::tui::ui::{parse_key_sequence, render_dashboard, TuiKey};
    use crate::tui::TuiTab;

    assert_eq!(parse_key_sequence(b"\x1b[C"), Some(TuiKey::Right));
    assert_eq!(parse_key_sequence(b"\x1b[D"), Some(TuiKey::Left));

    let log_buf = TuiLogBuffer::new(3);
    log_buf.push_line("2026-11-15T10:00:00Z INFO wpmulti::core: tunnel-1 active".to_string());
    log_buf.push_line("2026-11-15T10:00:01Z WARN wpmulti::health: slow probe".to_string());
    log_buf.push_line("2026-11-15T10:00:02Z ERROR wpmulti::net: timeout".to_string());
    log_buf.push_line("2026-11-15T10:00:03Z DEBUG wpmulti::dns: resolved".to_string());
    // Bounded ring buffer keeps only last 3 lines
    assert_eq!(log_buf.snapshot().len(), 3);

    let mut app = TuiApp::new(
        TuiDataSource::Remote {
            admin_url: "http://127.0.0.1:9090".to_string(),
            auth_token: None,
        },
        TuiSortField::Id,
    )
    .with_log_buffer(log_buf);
    app.listeners = vec![ActiveListenerInfo {
        name: "shared-socks5".to_string(),
        address: "127.0.0.1:1080".parse().unwrap(),
        listener_type: ListenerType::Socks5,
        is_shared: true,
        tunnel_id: None,
    }];
    app.config_snapshot = Some(MainConfig::default());

    assert_eq!(app.active_tab, TuiTab::Tunnels);
    app.next_tab();
    assert_eq!(app.active_tab, TuiTab::Logs);
    let logs_out = render_dashboard(&mut app, 90, 24);
    assert!(logs_out.contains("2:Logs"));
    assert!(logs_out.contains("slow probe"));

    app.cycle_log_filter(); // ALL -> ERROR
    assert_eq!(app.filtered_logs().len(), 1);
    app.cycle_log_filter(); // ERROR -> WARN
    assert_eq!(app.filtered_logs().len(), 1);

    app.next_tab();
    assert_eq!(app.active_tab, TuiTab::Listeners);
    let listeners_out = render_dashboard(&mut app, 90, 24);
    assert!(listeners_out.contains("127.0.0.1:1080"));

    app.next_tab();
    assert_eq!(app.active_tab, TuiTab::Config);
    let config_out = render_dashboard(&mut app, 90, 24);
    assert!(config_out.contains("global.dns_strategy"));

    app.next_tab();
    assert_eq!(app.active_tab, TuiTab::Probe);
    let probe_out = render_dashboard(&mut app, 90, 24);
    assert!(probe_out.contains("Probe"));

    app.prev_tab();
    assert_eq!(app.active_tab, TuiTab::Config);
}
