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
        }
    );

    // Custom admin URL
    let args_custom = vec!["wpmulti", "top", "--admin-url", "http://10.0.0.1:8080"];
    let cli_custom = Cli::try_parse_from(args_custom).expect("parse top custom");
    assert_eq!(
        cli_custom.command,
        Commands::Top {
            admin_url: "http://10.0.0.1:8080".to_string(),
        }
    );
}

#[test]
fn test_cli_parse_validate() {
    let args = vec!["wpmulti", "validate", "--config", "test.toml", "--dir", "configs/"];
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
