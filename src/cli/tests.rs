//! Unit tests for Milestone 5: CLI argument handling & dispatch.

use std::fs;
use std::path::PathBuf;

use clap::Parser;
use tempfile::tempdir;

use crate::cli::commands::cmd_validate;
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
