//! Unit tests for Milestone 5: Interactive TUI Monitor (`wpmulti top`).

use std::sync::Arc;

use x25519_dalek::{PublicKey, StaticSecret};

use crate::config::{
    LifecycleMode, MainConfig, TuiSortField, TunnelConfig, WgInterfaceConfig, WgPeerConfig,
};
use crate::core::{HealthStatus, TunnelManager, TunnelState, TunnelSummary};
use crate::tui::app::{TuiApp, TuiDataSource};
use crate::tui::ui::{
    common_prefix, format_bytes, render_dashboard, short_bar_label, visible_edit_tail,
};

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

fn make_dummy_summary(
    id: &str,
    state: TunnelState,
    conns: usize,
    rx: u64,
    tx: u64,
) -> TunnelSummary {
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
        disabled: false,
        disable_pending: false,
    }
}

/// Start a real Admin API server for `mgr` on a loopback ephemeral port
/// and return it together with a [`TuiDataSource`] pointing at it. This
/// is how `top` talks to a running daemon, so TUI tests that need a live
/// data source use this. Keep the returned server alive for the whole
/// test; dropping it stops the API.
async fn remote_data_source_for(
    mgr: &Arc<TunnelManager>,
    auth_token: Option<String>,
) -> (crate::api::AdminServer, TuiDataSource) {
    use crate::api::AdminServer;
    let server = AdminServer::new(
        "127.0.0.1:0".parse().expect("addr"),
        Arc::clone(mgr),
        auth_token.clone(),
    );
    let addr = server.start().await.expect("start admin");
    (
        server,
        TuiDataSource {
            admin_url: format!("http://{addr}"),
            auth_token,
        },
    )
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
    let dummy_source = TuiDataSource {
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

#[tokio::test]
async fn test_tui_refresh_records_unreachable_admin_api_error() {
    // `top` against a dead Admin API used to show an empty dashboard
    // with no error at all. A failed fetch must now be recorded so the
    // footer can show it, and the app must stay alive and keep
    // retrying instead of failing the refresh.
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let dead_port = listener.local_addr().unwrap().port();
    drop(listener);
    let source = TuiDataSource {
        admin_url: format!("http://127.0.0.1:{dead_port}"),
        auth_token: None,
    };
    let mut app = TuiApp::new(source, TuiSortField::Id);

    let result = app.refresh().await;
    assert!(
        result.is_ok(),
        "refresh must not fail on a dead API: {result:?}"
    );
    let err = app
        .data_source_error
        .as_deref()
        .expect("a fetch failure must be recorded");
    assert!(
        err.contains("Failed to connect to Admin API"),
        "expected a connection error, got: {err}"
    );
    assert!(
        err.contains(&dead_port.to_string()),
        "error must name the unreachable address, got: {err}"
    );
    assert!(app.tunnels.is_empty());
}

#[test]
fn test_tui_search_filtering() {
    let dummy_source = TuiDataSource {
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

#[tokio::test]
async fn test_tui_search_filter_can_be_cleared() {
    use crate::tui::ui::{TuiKey, handle_tui_key};

    let dummy_source = TuiDataSource {
        admin_url: "http://127.0.0.1:9090".to_string(),
        auth_token: None,
    };
    let mut app = TuiApp::new(dummy_source, TuiSortField::Id);
    let list = vec![
        make_dummy_summary("wgcf-001", TunnelState::Dormant, 0, 0, 0),
        make_dummy_summary("wgcf-002", TunnelState::Active, 0, 0, 0),
    ];
    app.set_tunnels(list);
    assert_eq!(app.filtered_indices.len(), 2);

    // `/` + "002" + Enter filters to one tunnel.
    handle_tui_key(&mut app, TuiKey::Char('/')).await;
    assert!(app.is_searching);
    for c in "002".chars() {
        handle_tui_key(&mut app, TuiKey::Char(c)).await;
    }
    handle_tui_key(&mut app, TuiKey::Enter).await;
    assert!(!app.is_searching);
    assert_eq!(app.filtered_indices.len(), 1);
    assert_eq!(app.tunnels[app.filtered_indices[0]].id, "wgcf-002");
    // The footer says how to clear the filter while one is active.
    assert!(render_dashboard(&mut app, 110, 24).contains("Esc:Clear filter"));

    // `Esc` with no prompt open clears the active filter.
    handle_tui_key(&mut app, TuiKey::Esc).await;
    assert!(app.search_query.is_empty());
    assert_eq!(app.filtered_indices.len(), 2);
    assert!(!render_dashboard(&mut app, 110, 24).contains("Esc:Clear filter"));

    // Opening `/` starts a fresh search: the old query is not carried
    // over, so `/` + `Enter` with nothing typed clears the filter too.
    handle_tui_key(&mut app, TuiKey::Char('/')).await;
    assert!(app.is_searching);
    assert!(app.search_query.is_empty());
    for c in "001".chars() {
        handle_tui_key(&mut app, TuiKey::Char(c)).await;
    }
    handle_tui_key(&mut app, TuiKey::Enter).await;
    assert_eq!(app.filtered_indices.len(), 1);
    handle_tui_key(&mut app, TuiKey::Char('/')).await;
    assert!(app.search_query.is_empty());
    assert_eq!(app.filtered_indices.len(), 2);
    handle_tui_key(&mut app, TuiKey::Enter).await;
    assert!(!app.is_searching);
    assert_eq!(app.filtered_indices.len(), 2);
}

#[tokio::test]
async fn test_tui_remote_logs_clear_sticks_across_refresh() {
    // In remote `top` mode, `c` used to clear only the local copy: the
    // next 500 ms refresh re-fetched the daemon's full history and the
    // same lines came straight back. The clear must remember the last
    // visible line as a marker and drop everything up to it on the
    // next fetch, so cleared lines stay gone and only lines logged
    // after the clear reappear.
    use crate::tui::TuiTab;
    use crate::tui::ui::{TuiKey, handle_tui_key};

    let dummy_source = TuiDataSource {
        admin_url: "http://127.0.0.1:9090".to_string(),
        auth_token: None,
    };
    let mut app = TuiApp::new(dummy_source, TuiSortField::Id);
    app.set_tab(TuiTab::Logs);
    app.remote_logs = vec![
        "2026-11-17T04:34:59Z INFO first".to_string(),
        "2026-11-17T04:35:00Z INFO second".to_string(),
        "2026-11-17T04:35:01Z INFO third".to_string(),
    ];

    handle_tui_key(&mut app, TuiKey::Char('c')).await;
    assert!(app.remote_logs.is_empty());
    assert_eq!(
        app.remote_logs_clear_marker.as_deref(),
        Some("2026-11-17T04:35:01Z INFO third")
    );

    // A refresh fetching the same history plus one new line drops
    // everything up to the marker and keeps only the new line.
    let fetched = vec![
        "2026-11-17T04:34:59Z INFO first".to_string(),
        "2026-11-17T04:35:00Z INFO second".to_string(),
        "2026-11-17T04:35:01Z INFO third".to_string(),
        "2026-11-17T04:35:02Z INFO fourth".to_string(),
    ];
    assert_eq!(
        app.drop_cleared_logs(fetched),
        vec!["2026-11-17T04:35:02Z INFO fourth".to_string()]
    );

    // A fetch where the marker rotated out of the daemon's ring buffer
    // keeps everything: it is all newer than the clear.
    let rotated = vec!["2026-11-17T04:35:03Z INFO fifth".to_string()];
    assert_eq!(app.drop_cleared_logs(rotated.clone()), rotated);

    // Clearing an already-empty view keeps the previous marker: wiping
    // it would let the next refresh resurrect the dropped lines.
    handle_tui_key(&mut app, TuiKey::Char('c')).await;
    assert_eq!(
        app.remote_logs_clear_marker.as_deref(),
        Some("2026-11-17T04:35:01Z INFO third")
    );
}

#[test]
fn test_tui_sorting() {
    let dummy_source = TuiDataSource {
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
    let dummy_source = TuiDataSource {
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

#[test]
fn test_tui_render_dashboard_shows_unknown_health() {
    let dummy_source = TuiDataSource {
        admin_url: "http://127.0.0.1:9090".to_string(),
        auth_token: None,
    };
    let mut app = TuiApp::new(dummy_source, TuiSortField::Id);

    let mut summary = make_dummy_summary("wgcf-new", TunnelState::Dormant, 0, 0, 0);
    summary.health = HealthStatus::Unknown;
    app.set_tunnels(vec![summary]);

    let output = render_dashboard(&mut app, 100, 30);
    assert!(output.contains("Unknown"), "dashboard was:\n{output}");
    assert!(
        !output.contains("Healthy"),
        "unproven tunnel shown as Healthy:\n{output}"
    );
}

#[tokio::test]
async fn test_tui_remote_activation_and_suspension() {
    let mut config = MainConfig::default();
    config.per_tunnel.enabled = false;
    let tunnels = vec![make_test_tunnel_config("t-alpha", "127.0.0.1:51820")];
    let mgr = Arc::new(TunnelManager::new(config, tunnels).unwrap());
    let (_server, source) = remote_data_source_for(&mgr, None).await;

    let mut app = TuiApp::new(source, TuiSortField::Id);
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
    use crate::tui::ui::{TuiKey, parse_key_sequence, parse_keys_from_bytes, parse_next_key};

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
        vec![
            TuiKey::Up,
            TuiKey::Down,
            TuiKey::Char('j'),
            TuiKey::Char('q')
        ]
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
        TuiDataSource {
            admin_url: "http://127.0.0.1:9090".to_string(),
            auth_token: None,
        },
        TuiSortField::Id,
    );
    app.set_tunnels(vec![
        make_dummy_summary(
            "wgcf-very-long-tunnel-name-001",
            TunnelState::Active,
            2,
            1024,
            2048,
        ),
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
    use crate::config::ListenerType;
    use crate::config::toml_config::MainConfig;
    use crate::core::listener::ActiveListenerInfo;
    use crate::tui::TuiTab;
    use crate::tui::logs::TuiLogBuffer;
    use crate::tui::ui::{TuiKey, parse_key_sequence, render_dashboard};

    assert_eq!(parse_key_sequence(b"\x1b[C"), Some(TuiKey::Right));
    assert_eq!(parse_key_sequence(b"\x1b[D"), Some(TuiKey::Left));

    let log_buf = TuiLogBuffer::new(3);
    log_buf.push_line("2026-11-15T10:00:00Z INFO wpmulti::core: tunnel-1 active");
    log_buf.push_line("2026-11-15T10:00:01Z WARN wpmulti::health: slow probe");
    log_buf.push_line("2026-11-15T10:00:02Z ERROR wpmulti::net: timeout");
    log_buf.push_line("2026-11-15T10:00:03Z DEBUG wpmulti::dns: resolved");
    // Bounded ring buffer keeps only last 3 lines
    assert_eq!(log_buf.snapshot().len(), 3);

    let mut app = TuiApp::new(
        TuiDataSource {
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

#[test]
fn test_tui_disabled_badge_renders() {
    let mut app = TuiApp::new(
        TuiDataSource {
            admin_url: "http://127.0.0.1:9090".to_string(),
            auth_token: None,
        },
        TuiSortField::Id,
    );
    let mut summary = make_dummy_summary("wgcf-001", TunnelState::Dormant, 0, 0, 0);
    summary.disabled = true;
    app.set_tunnels(vec![summary]);

    let out = render_dashboard(&mut app, 90, 24);
    assert!(out.contains("Disabled"));
    assert!(out.contains("x:Toggle"));
    assert!(out.contains("X:Batch"));
}

fn collect_main_config_json_keys() -> Vec<String> {
    let val = serde_json::to_value(MainConfig::default()).expect("serialize MainConfig");
    let obj = val
        .as_object()
        .expect("MainConfig must serialize as object");
    let mut keys = Vec::new();
    for (top_key, top_val) in obj {
        if let Some(sub) = top_val.as_object() {
            for sub_key in sub.keys() {
                keys.push(format!("{top_key}.{sub_key}"));
            }
        } else {
            keys.push(top_key.clone());
        }
    }
    keys.sort();
    keys
}

fn select_config_field(app: &mut TuiApp, target: crate::tui::ConfigField) {
    let idx = crate::tui::ConfigField::ALL
        .iter()
        .position(|&f| f == target)
        .expect("ConfigField present in ALL");
    app.config_selected = idx;
}

#[test]
fn test_tui_config_covers_100_percent_main_config_fields_and_renders_badges() {
    use crate::tui::{ConfigApplyScope, ConfigField, TuiTab};

    let expected = collect_main_config_json_keys();
    let mut actual: Vec<String> = ConfigField::ALL
        .iter()
        .map(|f| f.key().to_string())
        .collect();
    actual.sort();
    actual.dedup();
    assert_eq!(actual.len(), ConfigField::ALL.len());
    assert_eq!(actual, expected);

    let mut cfg = MainConfig::default();
    cfg.admin.auth_token = Some("super-secret-admin-token".to_string());
    let mut app = TuiApp::new(
        TuiDataSource {
            admin_url: "http://127.0.0.1:9090".to_string(),
            auth_token: None,
        },
        TuiSortField::Id,
    );
    app.config_snapshot = Some(cfg);
    app.active_tab = TuiTab::Config;

    let top_render = render_dashboard(&mut app, 110, 22);
    assert!(top_render.contains("[RESTART]"));
    assert!(top_render.contains("[LIVE]"));
    assert!(top_render.contains("global.config_dir"));
    assert!(!top_render.contains("super-secret-admin-token"));

    select_config_field(&mut app, ConfigField::DisabledTunnels);
    let bottom_render = render_dashboard(&mut app, 110, 22);
    assert!(bottom_render.contains("disabled_tunnels"));
    assert!(bottom_render.contains("[SET]"));
    assert!(!bottom_render.contains("super-secret-admin-token"));
    assert_eq!(
        ConfigField::GlobalLogLevel.scope(),
        ConfigApplyScope::Restart
    );
    assert_eq!(
        ConfigField::TuiRefreshRateMs.scope(),
        ConfigApplyScope::Live
    );
}

#[tokio::test]
async fn test_tui_config_all_editors_secret_preservation_and_validation() {
    use crate::config::{
        AuthMode, ListenerType, SharedListenerSettings, TunnelPoolSelection, TunnelPortOverride,
    };
    use crate::tui::{ConfigField, TuiTab};

    let temp = tempfile::TempDir::new().expect("temp dir");
    let toml_path = temp.path().join("wpmulti.toml");

    let mut cfg = MainConfig::default();
    cfg.global.config_dir = temp.path().to_path_buf();
    cfg.per_tunnel.enabled = false;
    cfg.admin.auth_token = Some("admin-keep-secret".to_string());
    cfg.per_tunnel.overrides.insert(
        "wg-01".to_string(),
        TunnelPortOverride {
            socks5_port: Some(11001),
            http_port: None,
            password: Some("ov-keep-secret".to_string()),
        },
    );
    cfg.shared_listeners.push(SharedListenerSettings {
        name: "socks-shared".to_string(),
        listener_type: ListenerType::Socks5,
        bind: "127.0.0.1:10800".parse().expect("bind"),
        auth_mode: AuthMode::Global,
        global_password: Some("listener-keep-secret".to_string()),
        default_strategy: crate::config::PoolStrategy::RoundRobin,
        allow_anonymous: false,
        pool: TunnelPoolSelection::All,
        ip_mode: None,
    });
    let initial_toml = toml::to_string_pretty(&cfg).expect("serialize");
    std::fs::write(&toml_path, &initial_toml).expect("write initial toml");

    let mgr = Arc::new(TunnelManager::new(cfg, Vec::new()).expect("mgr"));
    let (_server, source) =
        remote_data_source_for(&mgr, Some("admin-keep-secret".to_string())).await;
    let mut app = TuiApp::new(source, TuiSortField::Id).with_config_path(toml_path.clone());
    // Load the (redacted) config from the daemon before editing.
    app.set_tab(TuiTab::Config);
    app.refresh().await.expect("load config");

    // Editing auth_token starts with [KEEP], never raw secret
    select_config_field(&mut app, ConfigField::AdminAuthToken);
    app.activate_config_row().await.expect("open edit");
    assert_eq!(app.config_editing.as_deref(), Some("[KEEP]"));
    app.commit_config_edit().await.expect("keep token");
    assert_eq!(
        mgr.config_snapshot().admin.auth_token.as_deref(),
        Some("admin-keep-secret")
    );

    // Editing shared_listeners redacts password cleanly and restores original on save
    select_config_field(&mut app, ConfigField::SharedListeners);
    app.activate_config_row()
        .await
        .expect("open listeners edit");
    let buf = app.config_editing.take().expect("edit buf");
    assert!(!buf.contains("listener-keep-secret"));
    assert!(buf.contains("[REDACTED]"));
    let updated_buf = buf.replace("10800", "10801");
    app.config_editing = Some(updated_buf);
    app.commit_config_edit()
        .await
        .expect("commit listeners edit");
    assert_eq!(
        mgr.config_snapshot().shared_listeners[0]
            .global_password
            .as_deref(),
        Some("listener-keep-secret")
    );

    // Editing per_tunnel.overrides redacts password and preserves it
    select_config_field(&mut app, ConfigField::PerTunnelOverrides);
    app.activate_config_row()
        .await
        .expect("open overrides edit");
    let ov_buf = app.config_editing.take().expect("ov buf");
    assert!(!ov_buf.contains("ov-keep-secret"));
    assert!(ov_buf.contains("[REDACTED]"));
    app.config_editing = Some(ov_buf.replace("11001", "11002"));
    app.commit_config_edit()
        .await
        .expect("commit overrides edit");
    assert_eq!(
        mgr.config_snapshot().per_tunnel.overrides["wg-01"]
            .password
            .as_deref(),
        Some("ov-keep-secret")
    );

    // Invalid value rejected cleanly before modifying manager or disk .toml
    select_config_field(&mut app, ConfigField::TuiRefreshRateMs);
    app.config_editing = Some("10".to_string());
    let err = app
        .commit_config_edit()
        .await
        .expect_err("refresh_rate < 50 must fail");
    assert!(err.contains("refresh_rate_ms"));
    assert_eq!(
        std::fs::read_to_string(&toml_path).expect("read"),
        initial_toml
    );
}

async fn apply_live_test_edits(app: &mut TuiApp) {
    use crate::tui::ConfigField;

    let edits = [
        (ConfigField::GlobalDnsFallback, "9.9.9.9:53"),
        (ConfigField::GlobalMaxActiveTunnels, "42"),
        (ConfigField::LifecycleIdleTimeout, "2m"),
        (ConfigField::LifecycleHandshakeTimeout, "7s"),
        (ConfigField::TuiRefreshRateMs, "180"),
        (ConfigField::HealthCheckThreshold, "6"),
        (ConfigField::HealthCheckCooldown, "45s"),
        (ConfigField::HealthCheckProbeInterval, "12s"),
        (ConfigField::HealthCheckProbeTimeout, "3s"),
        (ConfigField::DisabledTunnels, "t-dormant"),
    ];
    for (field, val) in edits {
        select_config_field(app, field);
        app.config_editing = Some(val.to_string());
        app.commit_config_edit().await.expect("commit text edit");
    }
    for field in [
        ConfigField::GlobalDnsStrategy,   // TunnelOnly -> TunnelFirst
        ConfigField::GlobalDnsPreference, // Ipv4First -> Ipv6First
        ConfigField::GlobalIpMode,        // DualStack -> Ipv4Only
        ConfigField::TuiDefaultSort,      // Id -> Status
    ] {
        select_config_field(app, field);
        app.activate_config_row().await.expect("cycle field");
    }
}

fn assert_live_runtime_propagation(
    mgr: &TunnelManager,
    active: &crate::core::ActiveTunnel,
    app: &TuiApp,
) {
    use crate::config::IpMode;
    use crate::config::toml_config::DnsStrategy;
    use std::time::Duration;

    assert_eq!(
        active.netstack.dns_resolver().dns_strategy(),
        DnsStrategy::TunnelFirst
    );
    assert!(active.netstack.dns_resolver().prefer_ipv6());
    assert_eq!(
        active.netstack.dns_resolver().dns_servers()[0],
        "9.9.9.9:53".parse().expect("dns")
    );
    assert_eq!(active.netstack.effective_ip_mode(), IpMode::Ipv4Only);
    assert_eq!(active.netstack.connect_timeout(), Duration::from_secs(7));
    assert_eq!(mgr.lifecycle().health_check(), (6, Duration::from_secs(45)));
    assert_eq!(
        mgr.prober().settings_snapshot().probe_interval,
        Duration::from_secs(12)
    );
    assert_eq!(
        mgr.prober().settings_snapshot().probe_timeout,
        Duration::from_secs(3)
    );
    assert!(
        mgr.registry()
            .get("t-dormant")
            .expect("dormant")
            .is_disabled()
    );
    assert_eq!(
        app.effective_refresh_interval(500),
        Duration::from_millis(180)
    );
    assert_eq!(app.sort_field, TuiSortField::Status);
}

fn write_test_wg_conf(dir: &std::path::Path, id: &str, addrs: &str, endpoint: &str) {
    use base64::Engine;
    let priv_b64 = base64::engine::general_purpose::STANDARD.encode([42u8; 32]);
    let pub_b64 = base64::engine::general_purpose::STANDARD.encode([99u8; 32]);
    let content = format!(
        "[Interface]\nPrivateKey = {priv_b64}\nAddress = {addrs}\n\n[Peer]\nPublicKey = {pub_b64}\nEndpoint = {endpoint}\nAllowedIPs = 0.0.0.0/0\nPersistentKeepalive = 25\n"
    );
    std::fs::write(dir.join(format!("{id}.conf")), content).expect("write wg conf");
}

#[tokio::test]
async fn test_tui_config_live_hot_reload_and_restart_warning_e2e() {
    use crate::config::toml_config::{DnsPreference, DnsStrategy};
    use crate::config::{IpMode, MainConfig, load_tunnel_configs_from_dir};
    use crate::core::MultiTenantRouter;
    use crate::proxy::{TunnelRouter, TunnelSelector};
    use crate::tui::{ConfigField, TuiTab};

    let temp = tempfile::TempDir::new().expect("temp dir");
    let conf_dir = temp.path().join("conf.d");
    std::fs::create_dir_all(&conf_dir).expect("mkdir conf.d");
    write_test_wg_conf(
        &conf_dir,
        "t-live",
        "172.16.0.2/32, fd00::2/128",
        "127.0.0.1:51820",
    );
    write_test_wg_conf(&conf_dir, "t-dormant", "172.16.0.3/32", "127.0.0.1:51821");
    let tunnels = load_tunnel_configs_from_dir(&conf_dir).expect("load conf dir");
    let toml_path = temp.path().join("wpmulti.toml");

    let mut cfg = MainConfig::default();
    cfg.global.config_dir = conf_dir;
    cfg.per_tunnel.enabled = false;
    cfg.lifecycle.mode = LifecycleMode::Eager;
    std::fs::write(&toml_path, toml::to_string_pretty(&cfg).expect("toml"))
        .expect("write initial toml");

    let mgr = Arc::new(TunnelManager::new(cfg.clone(), tunnels).expect("mgr"));
    mgr.set_config_path(toml_path.clone());
    let active = mgr
        .activate_tunnel("t-live")
        .await
        .expect("activate t-live");
    mgr.prober()
        .start(Arc::clone(mgr.registry()), cfg.health_check.clone());

    let listener_cfg = crate::config::SharedListenerSettings {
        name: "shared".to_string(),
        listener_type: crate::config::ListenerType::Socks5,
        bind: "127.0.0.1:1080".parse().expect("bind"),
        auth_mode: crate::config::AuthMode::None,
        global_password: None,
        default_strategy: crate::config::PoolStrategy::RoundRobin,
        allow_anonymous: true,
        pool: crate::config::TunnelPoolSelection::All,
        ip_mode: None,
    };
    let router = MultiTenantRouter::from_settings(
        &listener_cfg,
        Arc::clone(mgr.lifecycle()),
        Arc::clone(mgr.registry()),
    );

    let (_server, source) = remote_data_source_for(&mgr, None).await;
    let mut app = TuiApp::new(source, TuiSortField::Id).with_config_path(toml_path.clone());
    app.set_tab(TuiTab::Config);
    // Load the config from the daemon before editing.
    app.refresh().await.expect("load config");
    apply_live_test_edits(&mut app).await;

    let report = app
        .save_config_and_reload_with_report()
        .await
        .expect("save and reload");
    assert!(report.saved_to_disk);
    assert!(report.restart_pending.is_empty());
    assert!(report.live_applied.contains(&"global.dns_strategy"));
    assert!(report.live_applied.contains(&"health_check.probe_interval"));
    assert!(report.live_applied.contains(&"tui.refresh_rate_ms"));
    let banner = app.status_message.as_ref().expect("status").0.clone();
    assert!(banner.contains("Saved wpmulti.toml") && banner.contains("[LIVE] applied"));
    assert!(banner.contains("no restart needed"));

    let persisted = MainConfig::from_file(&toml_path).expect("reload persisted toml");
    assert_eq!(persisted.global.dns_strategy, DnsStrategy::TunnelFirst);
    assert_eq!(persisted.global.dns_preference, DnsPreference::Ipv6First);
    assert_eq!(persisted.global.ip_mode, IpMode::Ipv4Only);
    assert_eq!(persisted.global.max_active_tunnels, 42);
    assert_eq!(persisted.tui.refresh_rate_ms, 180);
    assert_eq!(persisted.tui.default_sort, TuiSortField::Status);
    assert_eq!(persisted.disabled_tunnels, vec!["t-dormant".to_string()]);
    assert_live_runtime_propagation(&mgr, &active, &app);

    let target = router
        .select_tunnel(&TunnelSelector::ById("t-live".to_string()), None)
        .await
        .expect("select target");
    let v6_err = target
        .resolve_in_tunnel("2001:4860:4860::8888")
        .await
        .expect_err("ipv6 blocked by updated global.ip_mode");
    assert!(v6_err.to_string().contains("Ipv4Only"));

    select_config_field(&mut app, ConfigField::GlobalLogLevel);
    app.activate_config_row().await.expect("cycle log_level");
    let restart_report = app
        .save_config_and_reload_with_report()
        .await
        .expect("save restart change");
    assert!(restart_report.restart_pending.contains(&"global.log_level"));
    let warn_banner = app.status_message.as_ref().expect("warn status").0.clone();
    assert!(warn_banner.contains("WARNING") && warn_banner.contains("[RESTART]"));
    assert!(warn_banner.contains("global.log_level"));
    assert!(render_dashboard(&mut app, 110, 30).contains("restart pending"));

    let _ = mgr.stop().await;
}

#[test]
fn test_config_edit_tail_keeps_cursor_visible() {
    // While editing, the buffer is append-only and the cursor sits at
    // its end — but the VALUE cell used to show the head of a long value
    // and clip the tail, so the end of a listener JSON (where
    // `allow_anonymous` and `pool` live) could never be seen. The tail
    // window keeps the cursor visible instead.
    assert_eq!(visible_edit_tail("abc", 10), "abc_");
    assert_eq!(visible_edit_tail("abc", 4), "abc_");
    assert_eq!(visible_edit_tail("", 10), "_");
    assert_eq!(visible_edit_tail("0123456789ABCDEF", 10), "…89ABCDEF_");
    assert_eq!(
        visible_edit_tail(
            r#"[{"name":"shared-socks","type":"socks5","bind":"127.0.0.1:1080","auth_mode":"per_tunnel","default_strategy":"round-robin","allow_anonymous":true,"pool":"all"}]"#,
            53
        ),
        "…\"round-robin\",\"allow_anonymous\":true,\"pool\":\"all\"}]_"
    );
}

#[test]
fn test_shared_listeners_row_shows_anon_auth_and_strategy() {
    // The Config tab row for `shared_listeners` used to show only names
    // and ports ("2 listener(s): shared-socks(127.0.0.1:1080), ..."),
    // so a user could not see whether a listener allows anonymous
    // requests or which pool strategy it uses without opening the JSON
    // editor. The row must show both at a glance.
    use crate::config::{
        AuthMode, ListenerType, PoolStrategy, SharedListenerSettings, TunnelPoolSelection,
    };
    use crate::tui::ConfigField;

    let cfg = MainConfig {
        shared_listeners: vec![
            SharedListenerSettings {
                name: "shared-socks".to_string(),
                listener_type: ListenerType::Socks5,
                bind: "127.0.0.1:1080".parse().unwrap(),
                auth_mode: AuthMode::None,
                global_password: None,
                default_strategy: PoolStrategy::RoundRobin,
                allow_anonymous: true,
                pool: TunnelPoolSelection::All,
                ip_mode: None,
            },
            SharedListenerSettings {
                name: "shared-http".to_string(),
                listener_type: ListenerType::Http,
                bind: "127.0.0.1:8080".parse().unwrap(),
                auth_mode: AuthMode::Global,
                global_password: Some("secret".to_string()),
                default_strategy: PoolStrategy::LeastConn,
                allow_anonymous: false,
                pool: TunnelPoolSelection::All,
                ip_mode: None,
            },
        ],
        ..Default::default()
    };
    let shown = ConfigField::SharedListeners.display_value(&cfg);
    assert_eq!(
        shown,
        "2 listener(s): shared-socks socks5 anon round-robin 127.0.0.1:1080, \
         shared-http http auth least-conn 127.0.0.1:8080"
    );
    assert_eq!(
        ConfigField::SharedListeners.display_value(&MainConfig::default()),
        "0 listener(s)"
    );
}

#[test]
fn test_top_tunnels_bar_labels_stay_distinguishable() {
    // Bars are 7 cells wide, so a label longer than that is clipped by
    // the chart. A plain first-7-chars truncation rendered `wgcf-001`
    // and `wgcf-002` identically as `wgcf-00`, so the two bars could
    // not be told apart. Stripping the shared prefix first keeps the
    // distinguishing tail visible.
    assert_eq!(common_prefix(&["wgcf-001", "wgcf-002"]), "wgcf-00");
    assert_eq!(common_prefix(&["alpha", "beta"]), "");
    assert_eq!(common_prefix(&["only"]), "only");
    assert_eq!(common_prefix(&[]), "");
    assert_eq!(short_bar_label("wgcf-001", "wgcf-00"), "001");
    assert_eq!(short_bar_label("wgcf-002", "wgcf-00"), "002");
    assert_eq!(short_bar_label("wgcf-001", "wgcf-001"), "001");
    assert_eq!(short_bar_label("alpha-long-name", ""), "alpha-l");
    assert_eq!(short_bar_label("ab", ""), "ab");
}

#[tokio::test]
async fn test_tui_restart_edit_stays_staged_until_save() {
    // A `[RESTART]` edit used to be applied to the daemon (and, remotely,
    // written to its file) the moment Enter was pressed — so quitting
    // with `q` "saved" a change the UI itself called unsaved. A staged
    // restart change must touch nothing until `w`, and a later `[LIVE]`
    // apply must not drag the staged value along with it.
    use crate::config::{LogLevel, MainConfig, load_tunnel_configs_from_dir};
    use crate::tui::{ConfigField, TuiTab};

    let temp = tempfile::TempDir::new().expect("temp dir");
    let conf_dir = temp.path().join("conf.d");
    std::fs::create_dir_all(&conf_dir).expect("mkdir conf.d");
    write_test_wg_conf(&conf_dir, "t-stage", "172.16.0.2/32", "127.0.0.1:51820");
    let tunnels = load_tunnel_configs_from_dir(&conf_dir).expect("load conf dir");
    let toml_path = temp.path().join("wpmulti.toml");

    let mut cfg = MainConfig::default();
    cfg.global.config_dir = conf_dir;
    std::fs::write(&toml_path, toml::to_string_pretty(&cfg).expect("toml"))
        .expect("write initial toml");

    let mgr = Arc::new(TunnelManager::new(cfg.clone(), tunnels).expect("mgr"));
    mgr.set_config_path(toml_path.clone());

    let (_server, source) = remote_data_source_for(&mgr, None).await;
    let mut app = TuiApp::new(source, TuiSortField::Id).with_config_path(toml_path.clone());
    app.set_tab(TuiTab::Config);
    // Load the config from the daemon before editing.
    app.refresh().await.expect("load config");

    // Stage a [RESTART] change (info -> warn) without saving.
    select_config_field(&mut app, ConfigField::GlobalLogLevel);
    app.activate_config_row().await.expect("cycle log_level");
    assert_eq!(
        app.config_snapshot.as_ref().unwrap().global.log_level,
        LogLevel::Warn
    );
    assert_eq!(mgr.config_snapshot().global.log_level, LogLevel::Info);
    assert_eq!(
        MainConfig::from_file(&toml_path)
            .expect("toml")
            .global
            .log_level,
        LogLevel::Info,
        "staged restart change leaked onto disk"
    );

    // Apply a [LIVE] change: it lands immediately, but the staged
    // restart value must not leak through with it.
    select_config_field(&mut app, ConfigField::GlobalDnsFallback);
    app.config_editing = Some("9.9.9.9:53".to_string());
    app.commit_config_edit().await.expect("commit dns_fallback");
    assert_eq!(
        mgr.config_snapshot().global.dns_fallback.to_string(),
        "9.9.9.9:53"
    );
    assert_eq!(
        mgr.config_snapshot().global.log_level,
        LogLevel::Info,
        "live apply dragged the staged restart value along"
    );

    // `w` applies and persists everything, staged restart included.
    let report = app
        .save_config_and_reload_with_report()
        .await
        .expect("save and reload");
    assert!(report.restart_pending.contains(&"global.log_level"));
    assert_eq!(mgr.config_snapshot().global.log_level, LogLevel::Warn);
    assert_eq!(
        MainConfig::from_file(&toml_path)
            .expect("toml")
            .global
            .log_level,
        LogLevel::Warn
    );
    assert_eq!(
        MainConfig::from_file(&toml_path)
            .expect("toml")
            .global
            .dns_fallback
            .to_string(),
        "9.9.9.9:53"
    );

    let _ = mgr.stop().await;
}

#[test]
fn test_tui_config_editor_handles_server_redaction_sentinels() {
    use crate::config::{
        AuthMode, ListenerType, SharedListenerSettings, TunnelPoolSelection, TunnelPortOverride,
    };
    use crate::tui::ConfigField;

    let mut cfg = MainConfig::default();
    cfg.admin.auth_token = Some("[REDACTED]".to_string());
    cfg.shared_listeners.push(SharedListenerSettings {
        name: "s5".to_string(),
        listener_type: ListenerType::Socks5,
        bind: "127.0.0.1:1080".parse().expect("bind"),
        auth_mode: AuthMode::Global,
        global_password: Some("[SET]".to_string()),
        default_strategy: crate::config::PoolStrategy::RoundRobin,
        allow_anonymous: false,
        pool: TunnelPoolSelection::All,
        ip_mode: None,
    });
    cfg.per_tunnel.overrides.insert(
        "t1".to_string(),
        TunnelPortOverride {
            socks5_port: Some(10001),
            http_port: None,
            password: None,
        },
    );

    assert_eq!(ConfigField::AdminAuthToken.display_value(&cfg), "[SET]");
    assert_eq!(
        ConfigField::AdminAuthToken.initial_edit_buffer(&cfg),
        "[KEEP]"
    );

    for sentinel in ["[KEEP]", "[REDACTED]", "[SET]", "***REDACTED***"] {
        ConfigField::AdminAuthToken
            .apply_text(&mut cfg, sentinel)
            .expect("sentinel tolerated");
        assert_eq!(cfg.admin.auth_token.as_deref(), Some("[REDACTED]"));
    }

    let listener_buf = ConfigField::SharedListeners
        .initial_edit_buffer(&cfg)
        .replace("1080", "1085");
    ConfigField::SharedListeners
        .apply_text(&mut cfg, &listener_buf)
        .expect("remote listener sentinel");
    assert_eq!(
        cfg.shared_listeners[0].global_password.as_deref(),
        Some("[SET]")
    );
    assert_eq!(cfg.shared_listeners[0].bind.port(), 1085);

    ConfigField::PerTunnelOverrides
        .apply_text(
            &mut cfg,
            r#"{"t1":{"socks5_port":10002,"http_port":null,"password":"[KEEP]"}}"#,
        )
        .expect("remote override sentinel");
    assert_eq!(
        cfg.per_tunnel.overrides["t1"].password.as_deref(),
        Some("[REDACTED]")
    );
}

fn build_remote_tui_test_config(conf_dir: &std::path::Path) -> MainConfig {
    use crate::config::{
        AuthMode, ListenerType, SharedListenerSettings, TunnelPoolSelection, TunnelPortOverride,
    };

    let mut cfg = MainConfig::default();
    cfg.global.config_dir = conf_dir.to_path_buf();
    cfg.per_tunnel.enabled = false;
    cfg.admin.enabled = true;
    cfg.admin.bind = "0.0.0.0:9090".parse().expect("bind");
    cfg.admin.auth_token = Some("remote-tok-123".to_string());
    cfg.shared_listeners.push(SharedListenerSettings {
        name: "s5-remote".to_string(),
        listener_type: ListenerType::Socks5,
        bind: "127.0.0.1:10900".parse().expect("bind"),
        auth_mode: AuthMode::Global,
        global_password: Some("remote-s5-pass".to_string()),
        default_strategy: crate::config::PoolStrategy::RoundRobin,
        allow_anonymous: false,
        pool: TunnelPoolSelection::All,
        ip_mode: None,
    });
    cfg.per_tunnel.overrides.insert(
        "t1".to_string(),
        TunnelPortOverride {
            socks5_port: Some(12001),
            http_port: None,
            password: Some("remote-ov-pass".to_string()),
        },
    );
    cfg
}

#[tokio::test]
async fn test_tui_remote_http_config_preserves_redacted_secrets_and_auth() {
    use crate::api::AdminServer;
    use crate::config::load_tunnel_configs_from_dir;
    use crate::tui::{ConfigField, TuiTab};

    let temp = tempfile::TempDir::new().expect("temp");
    let conf_dir = temp.path().join("conf.d");
    std::fs::create_dir_all(&conf_dir).expect("mkdir");
    write_test_wg_conf(&conf_dir, "t1", "172.16.0.2/32", "127.0.0.1:51820");
    let tunnels = load_tunnel_configs_from_dir(&conf_dir).expect("load");
    let toml_path = temp.path().join("wpmulti.toml");

    let cfg = build_remote_tui_test_config(&conf_dir);
    std::fs::write(&toml_path, toml::to_string_pretty(&cfg).expect("toml")).expect("write");

    let mgr = Arc::new(TunnelManager::new(cfg, tunnels).expect("mgr"));
    mgr.set_config_path(toml_path.clone());
    let server = AdminServer::new(
        "127.0.0.1:0".parse().expect("addr"),
        Arc::clone(&mgr),
        Some("remote-tok-123".to_string()),
    );
    let addr = server.start().await.expect("start admin");

    let mut app = TuiApp::new(
        TuiDataSource {
            admin_url: format!("http://{addr}"),
            auth_token: Some("remote-tok-123".to_string()),
        },
        TuiSortField::Id,
    );
    app.set_tab(TuiTab::Config);
    app.refresh().await.expect("fetch redacted config");

    select_config_field(&mut app, ConfigField::GlobalMaxActiveTunnels);
    app.config_editing = Some("55".to_string());
    app.commit_config_edit()
        .await
        .expect("edit max_active_tunnels");

    select_config_field(&mut app, ConfigField::AdminAuthToken);
    app.config_editing = Some("[REDACTED]".to_string());
    app.commit_config_edit()
        .await
        .expect("sentinel admin token");

    select_config_field(&mut app, ConfigField::SharedListeners);
    let l_json = serde_json::json!([{
        "name": "s5-remote",
        "type": "socks5",
        "bind": "127.0.0.1:10901",
        "auth_mode": "global",
        "global_password": "[REDACTED]",
        "default_strategy": "random",
        "allow_anonymous": false,
        "pool": "all",
        "ip_mode": null
    }]);
    app.config_editing = Some(l_json.to_string());
    app.commit_config_edit()
        .await
        .expect("remote listeners sentinel");

    select_config_field(&mut app, ConfigField::PerTunnelOverrides);
    app.config_editing =
        Some(r#"{"t1":{"socks5_port":12002,"http_port":null,"password":"[KEEP]"}}"#.to_string());
    app.commit_config_edit()
        .await
        .expect("remote override sentinel");

    app.save_config_and_reload_with_report()
        .await
        .expect("remote save");
    app.refresh()
        .await
        .expect("subsequent remote refresh stays authenticated");

    for snap in [
        mgr.config_snapshot(),
        MainConfig::from_file(&toml_path).expect("toml"),
    ] {
        assert_eq!(snap.global.max_active_tunnels, 55);
        assert_eq!(snap.admin.auth_token.as_deref(), Some("remote-tok-123"));
        assert_eq!(snap.shared_listeners[0].bind.port(), 10901);
        assert_eq!(
            snap.shared_listeners[0].global_password.as_deref(),
            Some("remote-s5-pass")
        );
        assert_eq!(snap.per_tunnel.overrides["t1"].socks5_port, Some(12002));
        assert_eq!(
            snap.per_tunnel.overrides["t1"].password.as_deref(),
            Some("remote-ov-pass")
        );
    }

    select_config_field(&mut app, ConfigField::AdminAuthToken);
    app.config_editing = Some("remote-tok-rotated".to_string());
    app.commit_config_edit().await.expect("rotate remote token");
    app.save_config_and_reload_with_report()
        .await
        .expect("save rotated");
    app.refresh().await.expect("refresh after token rotation");
    assert_eq!(
        MainConfig::from_file(&toml_path)
            .expect("toml")
            .admin
            .auth_token
            .as_deref(),
        Some("remote-tok-rotated")
    );

    server.stop().await;
}
