//! Unit tests for Milestone 5: CLI argument handling & dispatch.

use std::fs;
use std::path::PathBuf;

use clap::Parser;
use tempfile::tempdir;

use crate::cli::commands::{admin_api_call_error, cmd_run, cmd_validate, discover_local_config_in};
use crate::cli::{Cli, Commands};

#[test]
fn test_cli_parse_run_defaults() {
    let args = vec!["wpmulti", "run"];
    let cli = Cli::try_parse_from(args).expect("parse run");
    assert_eq!(
        cli.command,
        Commands::Run {
            config: None,
            dir: None,
            tui: false,
        }
    );
}

#[test]
fn test_cli_parse_run_options() {
    let args = vec![
        "wpmulti",
        "run",
        "--config",
        "/etc/wpmulti/wpmulti.toml",
        "--dir",
        "/etc/wireguard",
        "--tui",
    ];
    let cli = Cli::try_parse_from(args).expect("parse run with options");
    assert_eq!(
        cli.command,
        Commands::Run {
            config: Some(PathBuf::from("/etc/wpmulti/wpmulti.toml")),
            dir: Some(PathBuf::from("/etc/wireguard")),
            tui: true,
        }
    );
}

#[test]
fn test_cli_parse_top() {
    // Default admin URL
    let args_default = vec!["wpmulti", "top"];
    let cli_default = Cli::try_parse_from(args_default).expect("parse top default");
    assert_eq!(
        cli_default.command,
        Commands::Top {
            admin_url: "http://127.0.0.1:9090".to_string(),
            auth_token: None,
        }
    );

    // Custom admin URL
    let args_custom = vec!["wpmulti", "top", "--admin-url", "http://10.0.0.1:8080"];
    let cli_custom = Cli::try_parse_from(args_custom).expect("parse top custom");
    assert_eq!(
        cli_custom.command,
        Commands::Top {
            admin_url: "http://10.0.0.1:8080".to_string(),
            auth_token: None,
        }
    );
}

#[test]
fn test_cli_parse_validate() {
    let args = vec![
        "wpmulti",
        "validate",
        "--config",
        "test.toml",
        "--dir",
        "configs/",
    ];
    let cli = Cli::try_parse_from(args).expect("parse validate");
    assert_eq!(
        cli.command,
        Commands::Validate {
            config: Some(PathBuf::from("test.toml")),
            dir: Some(PathBuf::from("configs/")),
        }
    );
}

#[test]
fn test_cli_parse_status() {
    let args = vec!["wpmulti", "status", "--admin-url", "http://127.0.0.1:9090"];
    let cli = Cli::try_parse_from(args).expect("parse status");
    assert_eq!(
        cli.command,
        Commands::Status {
            admin_url: "http://127.0.0.1:9090".to_string(),
            auth_token: None,
        }
    );
}

#[test]
fn test_cli_validate_command_execution() {
    let dir = tempdir().expect("tempdir");
    let conf_path = dir.path().join("wgcf-01.conf");
    fs::write(
        &conf_path,
        r#"
[Interface]
PrivateKey = 0OaUaQd4uJq5m8eN8uJq5m8eN8uJq5m8eN8uJq5m8eM=
Address = 172.16.0.2/32

[Peer]
PublicKey = bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo=
Endpoint = 198.51.100.1:51820
AllowedIPs = 0.0.0.0/0
"#,
    )
    .expect("write wg conf");

    let count = cmd_validate(None, Some(dir.path().to_path_buf())).expect("cmd_validate");
    assert_eq!(count, 1);
}

#[test]
fn test_cli_validate_config_path_resolves_config_dir_against_toml() {
    // A relative `config_dir` in the TOML file is resolved against the
    // directory containing that TOML file, not the process working
    // directory: `validate -c /some/dir/wpmulti.toml` used to fail with
    // "Tunnel directory './my-confs' does not exist" when run from
    // anywhere else, even though the directory sits next to the TOML.
    let dir = tempdir().expect("tempdir");
    let conf_dir = dir.path().join("my-confs");
    fs::create_dir(&conf_dir).expect("create conf dir");
    fs::write(
        conf_dir.join("wgcf-01.conf"),
        r#"
[Interface]
PrivateKey = 0OaUaQd4uJq5m8eN8uJq5m8eN8uJq5m8eN8uJq5m8eM=
Address = 172.16.0.2/32

[Peer]
PublicKey = bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo=
Endpoint = 198.51.100.1:51820
AllowedIPs = 0.0.0.0/0
"#,
    )
    .expect("write wg conf");
    let toml_path = dir.path().join("wpmulti.toml");
    fs::write(&toml_path, "[global]\nconfig_dir = \"./my-confs\"\n").expect("write toml");

    // The test process runs with its working directory at the repo root,
    // which has no ./my-confs — only the TOML-relative resolution finds it.
    let count = cmd_validate(Some(toml_path), None).expect("cmd_validate -c");
    assert_eq!(count, 1);
}

#[test]
fn test_discover_local_config_finds_wpmulti_toml_in_dir() {
    // `run` without `-c`/`-d` uses a `wpmulti.toml` in the working
    // directory instead of the compiled-in defaults — but only when one
    // is actually there.
    let dir = tempdir().expect("tempdir");
    assert_eq!(discover_local_config_in(dir.path()), None);

    let toml_path = dir.path().join("wpmulti.toml");
    fs::write(&toml_path, "[global]\n").expect("write toml");
    assert_eq!(
        discover_local_config_in(dir.path()),
        Some(toml_path.clone())
    );

    // A differently-named file does not count.
    let other = tempdir().expect("tempdir");
    fs::write(other.path().join("wpmulti.toml.example"), "[global]\n").expect("write example");
    assert_eq!(discover_local_config_in(other.path()), None);
}

#[test]
fn test_cli_parse_probe_options() {
    let args = vec![
        "wpmulti",
        "probe",
        "-c",
        "profile.conf",
        "--json",
        "--timeout",
        "10s",
    ];
    let cli = Cli::try_parse_from(args).expect("parse probe");
    assert_eq!(
        cli.command,
        Commands::Probe {
            config: Some(PathBuf::from("profile.conf")),
            dir: None,
            json: true,
            timeout: "10s".to_string(),
        }
    );

    let args_dir = vec!["wpmulti", "probe", "-d", "/etc/wireguard"];
    let cli_dir = Cli::try_parse_from(args_dir).expect("parse probe dir");
    assert_eq!(
        cli_dir.command,
        Commands::Probe {
            config: None,
            dir: Some(PathBuf::from("/etc/wireguard")),
            json: false,
            timeout: "5s".to_string(),
        }
    );
}

#[tokio::test]
async fn test_cli_probe_command_execution() {
    use crate::cli::cmd_probe;

    let dir = tempdir().expect("tempdir");
    let conf_path = dir.path().join("probe-01.conf");
    fs::write(
        &conf_path,
        r#"
[Interface]
PrivateKey = 0OaUaQd4uJq5m8eN8uJq5m8eN8uJq5m8eN8uJq5m8eM=
Address = 172.16.0.2/32

[Peer]
PublicKey = bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo=
Endpoint = 192.0.2.1:51820
AllowedIPs = 0.0.0.0/0
"#,
    )
    .expect("write wg conf");

    // Probe single with short timeout (unreachable test endpoint will fail/timeout without panicking)
    let results = cmd_probe(Some(conf_path), None, true, "100ms".to_string())
        .await
        .expect("cmd_probe");

    assert_eq!(results.len(), 1);
    assert_eq!(results[0].id, "probe-01");
    assert_eq!(results[0].endpoint, "192.0.2.1:51820");
    assert!(!results[0].healthy);
    assert!(results[0].error.is_some());
}

#[test]
fn test_cli_parse_disable_enable() {
    let cli_disable = Cli::try_parse_from(["wpmulti", "disable", "1-200"]).expect("parse disable");
    match cli_disable.command {
        Commands::Disable { target, .. } => assert_eq!(target, "1-200"),
        other => panic!("expected Disable, got {:?}", other),
    }

    let cli_enable = Cli::try_parse_from(["wpmulti", "enable", "wgcf-001"]).expect("parse enable");
    match cli_enable.command {
        Commands::Enable { target, .. } => assert_eq!(target, "wgcf-001"),
        other => panic!("expected Enable, got {:?}", other),
    }
}

#[tokio::test]
async fn test_graceful_shutdown_orders_stop_and_bounds_hanging_connections() {
    use std::net::SocketAddr;
    use std::sync::Arc;
    use std::time::{Duration, Instant};

    use crate::api::AdminServer;
    use crate::cli::commands::graceful_shutdown;
    use crate::config::{
        LifecycleMode, ListenerType, MainConfig, SharedListenerSettings, TunnelConfig,
        load_tunnel_config_from_str,
    };
    use crate::core::{TunnelManager, TunnelState};

    let free_port = {
        let std_l = std::net::TcpListener::bind("127.0.0.1:0").expect("bind ephemeral port");
        std_l.local_addr().unwrap().port()
    };
    let proxy_bind: SocketAddr = format!("127.0.0.1:{free_port}").parse().unwrap();

    let mut cfg = MainConfig::default();
    cfg.per_tunnel.enabled = false;
    cfg.lifecycle.mode = LifecycleMode::Eager;
    cfg.health_check.probe_interval = Duration::from_millis(50);
    cfg.health_check.probe_timeout = Duration::from_secs(5);
    cfg.shared_listeners.push(SharedListenerSettings {
        name: "shutdown-socks5".to_string(),
        listener_type: ListenerType::Socks5,
        bind: proxy_bind,
        auth_mode: crate::config::AuthMode::None,
        global_password: None,
        default_strategy: crate::config::PoolStrategy::RoundRobin,
        allow_anonymous: true,
        pool: crate::config::TunnelPoolSelection::All,
        ip_mode: None,
    });

    let wg_conf = r#"
[Interface]
PrivateKey = 0OaUaQd4uJq5m8eN8uJq5m8eN8uJq5m8eN8uJq5m8eM=
Address = 172.16.0.2/32

[Peer]
PublicKey = bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo=
Endpoint = 192.0.2.1:51820
AllowedIPs = 0.0.0.0/0
"#;
    let tunnel: TunnelConfig = load_tunnel_config_from_str("graceful-tun", wg_conf).unwrap();
    let manager = Arc::new(TunnelManager::new(cfg, vec![tunnel]).unwrap());

    let admin_server = AdminServer::new("127.0.0.1:0".parse().unwrap(), Arc::clone(&manager), None);
    let admin_addr = admin_server.start().await.unwrap();
    manager.start().await.unwrap();

    // Give ActiveProber a tick to start probing the unreachable peer
    tokio::time::sleep(Duration::from_millis(70)).await;

    // Hold open stalled connections on both proxy listener and Admin API
    let _stalled_proxy = tokio::net::TcpStream::connect(proxy_bind).await.unwrap();
    let _stalled_admin = tokio::net::TcpStream::connect(admin_addr).await.unwrap();

    let drain_timeout = Duration::from_millis(150);
    let t0 = Instant::now();
    tokio::time::timeout(
        Duration::from_secs(2),
        graceful_shutdown(&manager, Some(&admin_server), drain_timeout),
    )
    .await
    .expect("graceful_shutdown must complete within bounded timeout");
    let elapsed = t0.elapsed();
    assert!(
        elapsed >= drain_timeout.saturating_sub(Duration::from_millis(30)),
        "expected bounded drain window before aborting stalled clients (elapsed: {elapsed:?})"
    );

    // Listeners and Admin API must refuse new connections immediately
    assert!(tokio::net::TcpStream::connect(proxy_bind).await.is_err());
    assert!(tokio::net::TcpStream::connect(admin_addr).await.is_err());

    // Tunnel & netstack must be cleanly closed and dormant
    let entry = manager.registry().get("graceful-tun").unwrap();
    assert_eq!(*entry.state.read(), TunnelState::Dormant);
    assert!(entry.active.read().is_none());
}

#[test]
fn test_cli_tracing_subscriber_disables_ansi_for_json_and_captures_writer() {
    use std::sync::{Arc, Mutex};

    assert!(!super::cli_log_ansi_enabled(true, true));
    assert!(!super::cli_log_ansi_enabled(true, false));
    assert!(!super::cli_log_ansi_enabled(false, false));
    assert!(super::cli_log_ansi_enabled(false, true));

    #[derive(Clone)]
    struct VecMakeWriter(Arc<Mutex<Vec<u8>>>);

    struct VecWriter(Arc<Mutex<Vec<u8>>>);

    impl std::io::Write for VecWriter {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(buf);
            Ok(buf.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for VecMakeWriter {
        type Writer = VecWriter;

        fn make_writer(&'a self) -> Self::Writer {
            VecWriter(Arc::clone(&self.0))
        }
    }

    let captured = Arc::new(Mutex::new(Vec::new()));
    let subscriber = super::build_cli_tracing_subscriber(
        tracing::Level::INFO,
        super::cli_log_ansi_enabled(true, true),
        VecMakeWriter(Arc::clone(&captured)),
    );

    tracing::subscriber::with_default(subscriber, || {
        tracing::info!(tunnel = "wgcf-001", "Peer added");
    });

    let rendered = String::from_utf8(captured.lock().unwrap().clone()).unwrap();
    assert!(rendered.contains("Peer added"));
    assert!(rendered.contains("wgcf-001"));
    assert!(
        !rendered.contains("\x1b["),
        "ANSI escapes must be disabled in json mode: {rendered:?}"
    );
}

#[test]
fn test_write_probe_json_produces_pure_json_for_empty_and_populated_results() {
    let mut empty_buf = Vec::new();
    super::commands::write_probe_json(&mut empty_buf, &[]).unwrap();
    let parsed_empty: Vec<super::ProbeResult> = serde_json::from_slice(&empty_buf).unwrap();
    assert!(parsed_empty.is_empty());

    let sample = super::ProbeResult {
        id: "wgcf-001".to_string(),
        config_file: "wgcf-001.conf".to_string(),
        endpoint: "162.159.192.1:2408".to_string(),
        healthy: true,
        rtt_ms: Some(12.5),
        exit_ip: Some("104.28.1.1".to_string()),
        error: None,
    };
    let mut populated_buf = Vec::new();
    super::commands::write_probe_json(&mut populated_buf, &[sample]).unwrap();
    let parsed: Vec<super::ProbeResult> = serde_json::from_slice(&populated_buf).unwrap();
    assert_eq!(parsed.len(), 1);
    assert_eq!(parsed[0].id, "wgcf-001");
    assert_eq!(parsed[0].exit_ip.as_deref(), Some("104.28.1.1"));
}

#[tokio::test]
async fn test_cli_probe_empty_dir_json_returns_empty_results() {
    let dir = tempfile::tempdir().unwrap();
    let results = super::cmd_probe(None, Some(dir.path().to_path_buf()), true, "1s".to_string())
        .await
        .unwrap();
    assert!(results.is_empty());
}

#[tokio::test]
async fn test_cmd_run_refuses_zero_tunnels() {
    let dir = tempfile::tempdir().unwrap();
    let err = cmd_run(None, Some(dir.path().to_path_buf()), false)
        .await
        .expect_err("run with 0 tunnels must fail");
    assert!(err.to_string().contains("0 tunnels"), "error was: {err}");

    // A missing tunnel directory refuses the same way.
    let missing = dir.path().join("does-not-exist");
    let err = cmd_run(None, Some(missing), false)
        .await
        .expect_err("run with missing dir must fail");
    assert!(err.to_string().contains("0 tunnels"), "error was: {err}");
}

#[test]
fn test_probe_table_prints_full_error_text() {
    let long_error = "handshake failed: i/o error: Operation not permitted (os error 1) while contacting 203.0.113.1:51820";
    let results = vec![super::ProbeResult {
        id: "test-001".to_string(),
        config_file: "test-001.conf".to_string(),
        endpoint: "203.0.113.1:51820".to_string(),
        healthy: false,
        rtt_ms: None,
        exit_ip: None,
        error: Some(long_error.to_string()),
    }];
    let mut out = Vec::new();
    super::commands::print_probe_table_to(&mut out, &results);
    let text = String::from_utf8(out).expect("utf8");
    // The fixed-width table truncates the error column; the full text must
    // still appear below it so the failure can be diagnosed without --json.
    assert!(
        text.contains(long_error),
        "full error missing from:\n{text}"
    );
    assert!(
        text.contains("Failed probe errors"),
        "details section missing from:\n{text}"
    );
}

#[test]
fn test_udp_blocked_hint_printed_only_for_permission_errors() {
    let eperm = vec![super::ProbeResult {
        id: "test-001".to_string(),
        config_file: "test-001.conf".to_string(),
        endpoint: "203.0.113.1:51820".to_string(),
        healthy: false,
        rtt_ms: None,
        exit_ip: None,
        error: Some(
            "handshake failed: i/o error: Operation not permitted (os error 1)".to_string(),
        ),
    }];
    let mut out = Vec::new();
    super::commands::write_udp_blocked_hint(&mut out, &eperm);
    let text = String::from_utf8(out).expect("utf8");
    assert!(
        text.contains("UDP appears to be blocked"),
        "hint missing from:\n{text}"
    );

    // A timeout says nothing about the environment, so the hint stays silent.
    let timeout = vec![super::ProbeResult {
        id: "test-002".to_string(),
        config_file: "test-002.conf".to_string(),
        endpoint: "192.0.2.1:51820".to_string(),
        healthy: false,
        rtt_ms: None,
        exit_ip: None,
        error: Some("handshake timed out after 5s".to_string()),
    }];
    let mut out = Vec::new();
    super::commands::write_udp_blocked_hint(&mut out, &timeout);
    assert!(out.is_empty(), "hint must stay silent for timeouts");
}

#[test]
fn test_admin_api_call_error_wording() {
    // An HTTP status means the API was reached and refused the request:
    // say so, instead of claiming the API could not be reached.
    assert_eq!(
        admin_api_call_error("HTTP 404: Tunnel target not found: wgcf-999".to_string()),
        "Admin API returned HTTP 404: Tunnel target not found: wgcf-999"
    );
    // A connection error already names the Admin API: pass it through
    // instead of wrapping it a second time.
    assert_eq!(
        admin_api_call_error(
            "Failed to connect to Admin API at 'http://127.0.0.1:9090': Connection refused (os error 111)"
                .to_string()
        ),
        "Failed to connect to Admin API at 'http://127.0.0.1:9090': Connection refused (os error 111)"
    );
    assert_eq!(
        admin_api_call_error(
            "Timed out connecting to Admin API at 'http://127.0.0.1:9090'".to_string()
        ),
        "Timed out connecting to Admin API at 'http://127.0.0.1:9090'"
    );
    // Anything else is a genuine reachability failure.
    assert_eq!(
        admin_api_call_error("boom".to_string()),
        "Failed to reach Admin API: boom"
    );
}
