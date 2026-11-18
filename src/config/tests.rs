use super::*;
use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, Ipv4Addr};
use std::path::PathBuf;
use std::time::Duration;

const VALID_PRIVATE_KEY: &str = "0OaUaQd4uJq5m8eN8uJq5m8eN8uJq5m8eN8uJq5m8eM=";
const VALID_PUBLIC_KEY: &str = "bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo=";

// =========================================================================
// 1. Valid WireGuard .conf with Full Options
// =========================================================================
#[test]
fn test_wg_conf_full_options() {
    let conf = format!(
        r#"
        [Interface]
        PrivateKey = {VALID_PRIVATE_KEY}
        Address = 10.200.1.2/32, fd00:cafe:face::2/128
        DNS = 1.1.1.1, 8.8.8.8, 2606:4700:4700::1111
        ListenPort = 51820
        MTU = 1380

        [Peer]
        PublicKey = {VALID_PUBLIC_KEY}
        Endpoint = 198.51.100.1:51820
        AllowedIPs = 0.0.0.0/0, ::/0
        PresharedKey = {VALID_PRIVATE_KEY}
        PersistentKeepalive = 25

        [Peer]
        PublicKey = {VALID_PUBLIC_KEY}
        Endpoint = [2001:db8::1]:51820
        AllowedIPs = 10.0.0.0/8
        "#
    );

    let tunnel = load_tunnel_config_from_str("wg-full", &conf).expect("parse full wg conf");
    assert_eq!(tunnel.id, "wg-full");
    assert_eq!(tunnel.interface.addresses.len(), 2);
    assert_eq!(tunnel.interface.dns.len(), 3);
    assert_eq!(tunnel.interface.listen_port, Some(51820));
    assert_eq!(tunnel.interface.mtu, 1380);

    assert_eq!(tunnel.peers.len(), 2);
    assert_eq!(tunnel.peers[0].endpoint, "198.51.100.1:51820");
    assert_eq!(tunnel.peers[0].allowed_ips.len(), 2);
    assert!(tunnel.peers[0].preshared_key.is_some());
    assert_eq!(tunnel.peers[0].persistent_keepalive, Some(25));

    assert_eq!(tunnel.peers[1].endpoint, "[2001:db8::1]:51820");
    assert_eq!(tunnel.peers[1].allowed_ips.len(), 1);
    assert!(tunnel.peers[1].preshared_key.is_none());
    assert!(tunnel.peers[1].persistent_keepalive.is_none());
}

// =========================================================================
// 2. Minimal WireGuard .conf & Default Fallbacks
// =========================================================================
#[test]
fn test_wg_conf_minimal() {
    let conf = format!(
        r#"
        [Interface]
        PrivateKey = {VALID_PRIVATE_KEY}
        Address = 10.0.0.2/24

        [Peer]
        PublicKey = {VALID_PUBLIC_KEY}
        Endpoint = 192.0.2.1:51820
        AllowedIPs = 0.0.0.0/0
        "#
    );

    let tunnel = load_tunnel_config_from_str("wg-min", &conf).expect("parse minimal wg conf");
    assert_eq!(tunnel.id, "wg-min");
    assert_eq!(tunnel.interface.addresses.len(), 1);
    assert!(tunnel.interface.dns.is_empty());
    assert_eq!(tunnel.interface.listen_port, None);
    assert_eq!(tunnel.interface.mtu, 1420); // default MTU

    assert_eq!(tunnel.peers.len(), 1);
    assert!(tunnel.peers[0].preshared_key.is_none());
    assert!(tunnel.peers[0].persistent_keepalive.is_none());
}

// =========================================================================
// 3. wg-quick Directives Tolerance
// =========================================================================
#[test]
fn test_wg_conf_wg_quick_directives_tolerance() {
    let conf = format!(
        r#"
        [Interface]
        PrivateKey = {VALID_PRIVATE_KEY}
        Address = 10.0.0.2/32
        Table = auto
        PostUp = iptables -A FORWARD -i %i -j ACCEPT
        PreDown = iptables -D FORWARD -i %i -j ACCEPT
        SaveConfig = true
        FwMark = 0x51820

        [Peer]
        PublicKey = {VALID_PUBLIC_KEY}
        Endpoint = 192.0.2.1:51820
        AllowedIPs = 0.0.0.0/0
        "#
    );

    let res = load_tunnel_config_from_str("wg-quick-test", &conf);
    assert!(
        res.is_ok(),
        "Parser must tolerate wg-quick directives without error"
    );
}

// =========================================================================
// 4. Comments and Formatting (Full-line, Inline, Case Insensitivity)
// =========================================================================
#[test]
fn test_wg_conf_comments_and_formatting() {
    let conf = format!(
        r#"
        # Header Comment
        ; Semicolon Comment
        [iNtErFaCe]
        privatekey = {VALID_PRIVATE_KEY} # inline hash comment
        ADDRESS = 10.0.0.2/32 ; inline semicolon comment
        mtu = 1400

        [pEeR] # Peer inline comment
        PUBLICKEY = {VALID_PUBLIC_KEY}
        endpoint = 192.0.2.1:51820
        allowedips = 0.0.0.0/0
        "#
    );

    let tunnel = load_tunnel_config_from_str("wg-case-comment", &conf)
        .expect("case and comments must be tolerated");
    assert_eq!(tunnel.interface.mtu, 1400);
    assert_eq!(tunnel.peers.len(), 1);
}

// =========================================================================
// 5. Invalid WireGuard .conf Error Handling
// =========================================================================
#[test]
fn test_wg_conf_invalid_cases() {
    // Missing [Interface]
    let no_iface = format!(
        "[Peer]\nPublicKey = {VALID_PUBLIC_KEY}\nEndpoint = 1.1.1.1:51820\nAllowedIPs = 0.0.0.0/0\n"
    );
    assert!(load_tunnel_config_from_str("err1", &no_iface).is_err());

    // Missing PrivateKey
    let no_key = "[Interface]\nAddress = 10.0.0.1/32\n[Peer]\nPublicKey = abc\n";
    assert!(load_tunnel_config_from_str("err2", no_key).is_err());

    // Corrupted Base64 PrivateKey
    let bad_b64 = "[Interface]\nPrivateKey = !!!not_base64!!!\nAddress = 10.0.0.1/32\n";
    assert!(load_tunnel_config_from_str("err3", bad_b64).is_err());

    // Invalid key byte length
    let short_key = "[Interface]\nPrivateKey = AAAA\nAddress = 10.0.0.1/32\n";
    assert!(load_tunnel_config_from_str("err4", short_key).is_err());

    // Invalid CIDR address
    let bad_cidr =
        format!("[Interface]\nPrivateKey = {VALID_PRIVATE_KEY}\nAddress = 999.999.999.999/24\n");
    assert!(load_tunnel_config_from_str("err5", &bad_cidr).is_err());

    // Missing [Peer]
    let no_peer = format!("[Interface]\nPrivateKey = {VALID_PRIVATE_KEY}\nAddress = 10.0.0.1/32\n");
    assert!(load_tunnel_config_from_str("err6", &no_peer).is_err());

    // Malformed endpoint (no port)
    let bad_ep = format!(
        "[Interface]\nPrivateKey = {VALID_PRIVATE_KEY}\nAddress = 10.0.0.1/32\n[Peer]\nPublicKey = {VALID_PUBLIC_KEY}\nEndpoint = 1.1.1.1\nAllowedIPs = 0.0.0.0/0\n"
    );
    assert!(load_tunnel_config_from_str("err7", &bad_ep).is_err());

    // Empty tunnel ID
    let valid_conf = format!(
        "[Interface]\nPrivateKey = {VALID_PRIVATE_KEY}\nAddress = 10.0.0.1/32\n[Peer]\nPublicKey = {VALID_PUBLIC_KEY}\nEndpoint = 1.1.1.1:51820\n"
    );
    assert!(load_tunnel_config_from_str("", &valid_conf).is_err());
}

#[test]
fn test_wg_conf_invalid_base64_offset_points_at_first_bad_byte() {
    // `!!!bad!!!` is 9 bytes long, so the base64 crate's trailing-byte
    // check reports the last byte (offset 8) although the first bad
    // byte is at offset 0.
    let bad_first = "[Interface]\nPrivateKey = !!!bad!!!\nAddress = 10.0.0.1/32\n";
    let err = load_tunnel_config_from_str("errb640", bad_first).unwrap_err();
    assert!(
        err.to_string().contains("offset 0."),
        "expected offset 0, got: {err}"
    );

    // A bad byte in the middle keeps its true offset.
    let bad_mid = "[Interface]\nPrivateKey = AAAA!AAA\nAddress = 10.0.0.1/32\n";
    let err = load_tunnel_config_from_str("errb644", bad_mid).unwrap_err();
    assert!(
        err.to_string().contains("offset 4."),
        "expected offset 4, got: {err}"
    );

    // Misplaced padding is the culprit at its own position.
    let bad_pad = "[Interface]\nPrivateKey = AA=AAAAA\nAddress = 10.0.0.1/32\n";
    let err = load_tunnel_config_from_str("errb642", bad_pad).unwrap_err();
    assert!(
        err.to_string().contains("offset 2."),
        "expected offset 2, got: {err}"
    );
}

// =========================================================================
// 6. Main wpmulti.toml Parsing with Full Schema
// =========================================================================
#[test]
fn test_toml_config_full_schema() {
    let toml_str = r#"
        [global]
        config_dir = "/etc/wpmulti/conf.d"
        bind_address = "127.0.0.1"
        log_level = "debug"
        dns_fallback = "1.1.1.1:53"
        dns_strategy = "tunnel_only"
        max_active_tunnels = 500

        [lifecycle]
        mode = "lazy"
        idle_timeout = "5m"
        handshake_timeout = "15s"
        eager_tunnels = ["wg-primary", "wg-backup"]

        [per_tunnel]
        enabled = true
        base_socks5_port = 10000
        base_http_port = 20000

        [per_tunnel.overrides."wg-gateway"]
        socks5_port = 1081
        http_port = 8081

        [[shared_listener]]
        name = "shared-socks5"
        type = "socks5"
        bind = "0.0.0.0:1080"
        auth_mode = "global"
        global_password = "SecretPassword123"
        default_strategy = "round-robin"
        allow_anonymous = false
        pool = "all"

        [[shared_listener]]
        name = "shared-http"
        type = "http"
        bind = "127.0.0.1:8080"
        auth_mode = "none"
        default_strategy = "least-conn"
        allow_anonymous = true
        pool = ["wg0", "wg1"]

        [admin]
        enabled = true
        bind = "127.0.0.1:9090"
        auth_token = "admin-secret-token"

        [tui]
        refresh_rate_ms = 250
        default_sort = "conns"

        [health_check]
        threshold = 5
        cooldown = "45s"
        probe_interval = "1m"
        probe_timeout = "10s"
        probe_concurrency = 24
        probe_attempts = 2
    "#;

    let cfg = MainConfig::from_toml_str(toml_str).expect("parse full toml");
    assert_eq!(cfg.global.config_dir, PathBuf::from("/etc/wpmulti/conf.d"));
    assert_eq!(cfg.global.log_level, LogLevel::Debug);
    assert_eq!(cfg.global.max_active_tunnels, 500);

    assert_eq!(cfg.lifecycle.mode, LifecycleMode::Lazy);
    assert_eq!(cfg.lifecycle.idle_timeout, Duration::from_secs(300));
    assert_eq!(cfg.lifecycle.handshake_timeout, Duration::from_secs(15));
    assert_eq!(cfg.lifecycle.eager_tunnels, vec!["wg-primary", "wg-backup"]);

    assert!(cfg.per_tunnel.enabled);
    assert_eq!(cfg.per_tunnel.base_socks5_port, Some(10000));
    assert_eq!(cfg.per_tunnel.base_http_port, Some(20000));
    assert_eq!(
        cfg.per_tunnel.overrides.get("wg-gateway"),
        Some(&TunnelPortOverride {
            socks5_port: Some(1081),
            http_port: Some(8081),
            password: None,
        })
    );

    assert_full_schema_listeners_and_admin(&cfg);
}

fn assert_full_schema_listeners_and_admin(cfg: &MainConfig) {
    assert_eq!(cfg.shared_listeners.len(), 2);
    assert_eq!(cfg.shared_listeners[0].name, "shared-socks5");
    assert_eq!(cfg.shared_listeners[0].listener_type, ListenerType::Socks5);
    assert_eq!(cfg.shared_listeners[0].auth_mode, AuthMode::Global);
    assert_eq!(cfg.shared_listeners[0].pool, TunnelPoolSelection::All);

    assert_eq!(cfg.shared_listeners[1].name, "shared-http");
    assert_eq!(cfg.shared_listeners[1].listener_type, ListenerType::Http);
    assert_eq!(cfg.shared_listeners[1].auth_mode, AuthMode::None);
    assert_eq!(
        cfg.shared_listeners[1].pool,
        TunnelPoolSelection::Selected(vec!["wg0".into(), "wg1".into()])
    );

    assert!(cfg.admin.enabled);
    assert_eq!(cfg.admin.bind, "127.0.0.1:9090".parse().unwrap());
    assert_eq!(cfg.admin.auth_token, Some("admin-secret-token".into()));

    assert_eq!(cfg.tui.refresh_rate_ms, 250);
    assert_eq!(cfg.tui.default_sort, TuiSortField::Conns);

    assert_health_check(
        cfg,
        &HealthCheckSettings {
            threshold: 5,
            cooldown: Duration::from_secs(45),
            probe_interval: Duration::from_secs(60),
            probe_timeout: Duration::from_secs(10),
            probe_concurrency: 24,
            probe_attempts: 2,
        },
    );
}

/// Assert every `[health_check]` field in one place so the callers that
/// check a full config stay under the cognitive-complexity limit.
fn assert_health_check(cfg: &MainConfig, expected: &HealthCheckSettings) {
    assert_eq!(cfg.health_check, *expected);
}

// =========================================================================
// 7. Main wpmulti.toml Parsing with Minimal Config & Defaults
// =========================================================================
#[test]
fn test_toml_config_minimal_and_defaults() {
    let empty_toml = "";
    let cfg = MainConfig::from_toml_str(empty_toml).expect("empty toml should parse with defaults");

    assert_eq!(
        cfg.global.bind_address,
        IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1))
    );
    assert_eq!(cfg.global.log_level, LogLevel::Info);
    assert_health_check(&cfg, &HealthCheckSettings::default());
    assert_eq!(cfg.global.max_active_tunnels, 1000);
    assert_eq!(cfg.global.dns_strategy, DnsStrategy::TunnelOnly);
    assert_eq!(cfg.lifecycle.mode, LifecycleMode::Lazy);
    assert_eq!(cfg.lifecycle.idle_timeout, Duration::from_secs(300));
    assert_eq!(cfg.lifecycle.handshake_timeout, Duration::from_secs(10));
    assert!(cfg.lifecycle.eager_tunnels.is_empty());
    assert!(cfg.per_tunnel.enabled);
    assert_eq!(cfg.per_tunnel.base_socks5_port, Some(10000));
    assert_eq!(cfg.per_tunnel.base_http_port, Some(20000));
    assert!(cfg.shared_listeners.is_empty());
    assert!(!cfg.admin.enabled);
    assert_eq!(cfg.tui.refresh_rate_ms, 500);
    assert_eq!(cfg.tui.default_sort, TuiSortField::Id);
}

// =========================================================================
// 8. TOML Validation Failures
// =========================================================================
#[test]
fn test_toml_config_validation_failures() {
    // Zero max active tunnels
    let bad_max = "[global]\nmax_active_tunnels = 0\n";
    assert!(MainConfig::from_toml_str(bad_max).is_err());

    // Zero handshake timeout
    let zero_timeout = "[lifecycle]\nhandshake_timeout = \"0s\"\n";
    assert!(MainConfig::from_toml_str(zero_timeout).is_err());

    // Missing global_password with auth_mode = "global"
    let missing_pwd = r#"
        [[shared_listener]]
        name = "bad-auth"
        bind = "127.0.0.1:1080"
        auth_mode = "global"
    "#;
    assert!(MainConfig::from_toml_str(missing_pwd).is_err());

    // Duplicate shared listener names
    let dup_listener = r#"
        [[shared_listener]]
        name = "listen-1"
        bind = "127.0.0.1:1080"

        [[shared_listener]]
        name = "listen-1"
        bind = "127.0.0.1:1081"
    "#;
    assert!(MainConfig::from_toml_str(dup_listener).is_err());

    // Conflicting bind addresses
    let port_collision = r#"
        [[shared_listener]]
        name = "listen-1"
        bind = "127.0.0.1:1080"

        [[shared_listener]]
        name = "listen-2"
        bind = "127.0.0.1:1080"
    "#;
    assert!(MainConfig::from_toml_str(port_collision).is_err());

    // TUI refresh rate too low (< 50ms)
    let low_tui = "[tui]\nrefresh_rate_ms = 10\n";
    assert!(MainConfig::from_toml_str(low_tui).is_err());
}

#[test]
fn test_none_mode_password_is_rejected_and_dedicated_fallback() {
    // Audit run-1 (low): auth_mode = "none" with a password configured is
    // a fail-open — the password is never checked — so it must fail at load.
    let none_with_password = r#"
        [[shared_listener]]
        name = "plain"
        bind = "127.0.0.1:1080"
        auth_mode = "none"
        global_password = "s3cret"
    "#;
    let err = MainConfig::from_toml_str(none_with_password).expect_err("none + password must fail");
    assert!(err.to_string().contains("none"), "{err}");

    // Same listener without a password is fine.
    let none_without_password = r#"
        [[shared_listener]]
        name = "plain"
        bind = "127.0.0.1:1080"
        auth_mode = "none"
    "#;
    assert!(MainConfig::from_toml_str(none_without_password).is_ok());

    // Audit run-1 (high): dedicated listeners fall back to the single
    // enforced global password.
    let one_global = r#"
        [[shared_listener]]
        name = "shared"
        bind = "127.0.0.1:1080"
        auth_mode = "global"
        global_password = "s3cret"
    "#;
    let cfg = MainConfig::from_toml_str(one_global).expect("one global password parses");
    assert_eq!(cfg.dedicated_fallback_password().as_deref(), Some("s3cret"));

    // Two listeners enforcing the same password still yield one fallback.
    let same_password = r#"
        [[shared_listener]]
        name = "socks"
        bind = "127.0.0.1:1080"
        auth_mode = "global"
        global_password = "s3cret"

        [[shared_listener]]
        name = "http"
        bind = "127.0.0.1:8080"
        auth_mode = "per_tunnel"
        global_password = "s3cret"
    "#;
    let cfg = MainConfig::from_toml_str(same_password).expect("same password parses");
    assert_eq!(cfg.dedicated_fallback_password().as_deref(), Some("s3cret"));

    // Two listeners enforcing distinct passwords are ambiguous: a
    // dedicated listener cannot choose one, so the config must fail.
    let distinct_passwords = r#"
        [[shared_listener]]
        name = "socks"
        bind = "127.0.0.1:1080"
        auth_mode = "global"
        global_password = "one"

        [[shared_listener]]
        name = "http"
        bind = "127.0.0.1:8080"
        auth_mode = "global"
        global_password = "two"
    "#;
    assert!(MainConfig::from_toml_str(distinct_passwords).is_err());
}

#[test]
fn test_toml_config_rejects_unknown_keys() {
    // A misspelled key in [global] must fail loudly instead of being
    // silently ignored — otherwise a user can spend hours wondering why
    // their setting has no effect. The error names the bad key.
    let typo = "[global]\nlog_leve = \"debug\"\n";
    let err = MainConfig::from_toml_str(typo).expect_err("typo key must fail");
    assert!(
        err.to_string().contains("log_leve"),
        "error must name the unknown key, got: {err}"
    );

    // An unknown top-level key fails the same way.
    let unknown_top = "unknown_section = true\n";
    let err = MainConfig::from_toml_str(unknown_top).expect_err("unknown key must fail");
    assert!(
        err.to_string().contains("unknown_section"),
        "error must name the unknown key, got: {err}"
    );

    // An unknown key inside a section fails too.
    let unknown_nested = "[health_check]\nprobe_intervall = 30\n";
    let err = MainConfig::from_toml_str(unknown_nested).expect_err("unknown key must fail");
    assert!(
        err.to_string().contains("probe_intervall"),
        "error must name the unknown key, got: {err}"
    );

    // A correctly spelled key still parses.
    let ok = "[global]\nlog_level = \"debug\"\n";
    MainConfig::from_toml_str(ok).expect("correct key must parse");
}

#[test]
fn test_resolve_config_dir_keeps_bare_filename_verbatim() {
    // `Path::parent` of a bare filename is `Some("")`, not `None`, so
    // the resolver used to join it and silently normalize `./confs`
    // to `confs` — a save then rewrote a value the user never touched.
    // A TOML in the working directory keeps its `config_dir` verbatim;
    // only a TOML in another directory resolves against that directory.
    let mut cfg = MainConfig::default();
    cfg.global.config_dir = PathBuf::from("./confs");
    cfg.resolve_config_dir_against(std::path::Path::new("wpmulti.toml"));
    assert_eq!(cfg.global.config_dir, PathBuf::from("./confs"));

    let mut cfg = MainConfig::default();
    cfg.global.config_dir = PathBuf::from("./confs");
    cfg.resolve_config_dir_against(std::path::Path::new("sub/wpmulti.toml"));
    assert_eq!(cfg.global.config_dir, PathBuf::from("sub/confs"));

    let mut cfg = MainConfig::default();
    cfg.global.config_dir = PathBuf::from("./confs");
    cfg.resolve_config_dir_against(std::path::Path::new("/abs/wpmulti.toml"));
    assert_eq!(cfg.global.config_dir, PathBuf::from("/abs/confs"));

    let mut cfg = MainConfig::default();
    cfg.global.config_dir = PathBuf::from("/etc/wpmulti/conf.d");
    cfg.resolve_config_dir_against(std::path::Path::new("/abs/wpmulti.toml"));
    assert_eq!(cfg.global.config_dir, PathBuf::from("/etc/wpmulti/conf.d"));
}

#[test]
fn test_config_save_preserves_comments() {
    // Saving a config used to rewrite the whole file from the parsed
    // model, silently destroying every comment the user wrote in it.
    // A save must overlay the new values onto the existing text: header
    // warnings, section comments, and trailing per-key comments survive.
    let existing = "\
# My production config - DO NOT EDIT BY HAND
# Contact: ops team, see ticket #1234
disabled_tunnels = []  # tunnels go here when broken
[global]
config_dir = \"./confs\"  # where the wgcf files live
log_level = \"info\"  # keep at info in prod
";
    let mut cfg = MainConfig::default();
    cfg.global.config_dir = PathBuf::from("./confs");
    cfg.disabled_tunnels = vec!["wgcf-001".to_string()];
    let fresh = toml::to_string_pretty(&cfg).expect("serialize new config");

    let merged =
        merge_config_preserving_comments(existing, &fresh).expect("commented file must merge");
    assert!(
        merged.contains("# My production config - DO NOT EDIT BY HAND"),
        "header comment lost:\n{merged}"
    );
    assert!(
        merged.contains("# Contact: ops team, see ticket #1234"),
        "contact comment lost:\n{merged}"
    );
    assert!(
        merged.contains("# tunnels go here when broken"),
        "trailing comment on disabled_tunnels lost:\n{merged}"
    );
    assert!(
        merged.contains("# where the wgcf files live"),
        "trailing comment on config_dir lost:\n{merged}"
    );
    assert!(
        merged.contains("# keep at info in prod"),
        "trailing comment on log_level lost:\n{merged}"
    );
    assert!(
        merged.contains("disabled_tunnels = [\"wgcf-001\"]"),
        "new disabled_tunnels value missing:\n{merged}"
    );
    let reparsed: MainConfig = toml::from_str(&merged).expect("merged text must parse");
    assert_eq!(reparsed, cfg);
}

#[test]
fn test_config_save_merge_drops_removed_listeners_and_unknown_keys() {
    // Keys the new config no longer contains must leave the file, or
    // the file drifts from the model (e.g. a listener removed via
    // POST /config would come back on the next restart).
    let existing = "\
[[shared_listener]]
name = \"shared-socks\"
type = \"socks5\"
bind = \"127.0.0.1:1080\"

[[shared_listener]]
name = \"shared-http\"
type = \"http\"
bind = \"127.0.0.1:8080\"

mystery_key = true
";
    let cfg = MainConfig {
        shared_listeners: vec![SharedListenerSettings {
            name: "shared-socks".to_string(),
            listener_type: ListenerType::Socks5,
            bind: "127.0.0.1:1080".parse().expect("bind"),
            auth_mode: AuthMode::Global,
            global_password: None,
            default_strategy: PoolStrategy::RoundRobin,
            allow_anonymous: true,
            pool: TunnelPoolSelection::All,
            ip_mode: None,
        }],
        ..Default::default()
    };
    let fresh = toml::to_string_pretty(&cfg).expect("serialize new config");

    let merged = merge_config_preserving_comments(existing, &fresh).expect("merge must succeed");
    assert!(
        !merged.contains("shared-http"),
        "removed listener must leave the file:\n{merged}"
    );
    assert!(
        !merged.contains("mystery_key"),
        "unknown key must leave the file:\n{merged}"
    );
    let reparsed: MainConfig = toml::from_str(&merged).expect("merged text must parse");
    assert_eq!(reparsed, cfg);
}

#[test]
fn test_config_save_merge_falls_back_on_garbage() {
    // Unparsable existing text must not break the save: the merge
    // returns None and the caller uses the plain dump instead.
    let cfg = MainConfig::default();
    let fresh = toml::to_string_pretty(&cfg).expect("serialize new config");
    assert!(
        merge_config_preserving_comments("this is [[[ not toml", &fresh).is_none(),
        "garbage existing text must refuse the merge"
    );
    assert!(
        merge_config_preserving_comments("", &fresh).is_some(),
        "empty existing text merges as a plain dump"
    );
}

#[test]
fn test_toml_config_rejects_unknown_tunnel_references() {
    let known: HashSet<String> = ["wgcf-001".to_string(), "wgcf-002".to_string()]
        .into_iter()
        .collect();
    let mut cfg = MainConfig::from_toml_str(
        r#"
        [[shared_listener]]
        name = "shared-socks"
        type = "socks5"
        bind = "127.0.0.1:1080"
        pool = ["wgcf-001"]
        "#,
    )
    .expect("base config");
    cfg.validate_tunnel_references(&known)
        .expect("a config with only real references passes");

    // One ghost in each of the four referencing fields; each error must
    // name the ghost id and where it was referenced.
    cfg.disabled_tunnels = vec!["wgcf-999".to_string()];
    let err = cfg
        .validate_tunnel_references(&known)
        .expect_err("ghost disabled id must fail");
    assert!(err.to_string().contains("wgcf-999"), "got: {err}");
    assert!(err.to_string().contains("disabled_tunnels"), "got: {err}");
    cfg.disabled_tunnels.clear();

    cfg.lifecycle.eager_tunnels = vec!["wgcf-999".to_string()];
    let err = cfg
        .validate_tunnel_references(&known)
        .expect_err("ghost eager id must fail");
    assert!(
        err.to_string().contains("lifecycle.eager_tunnels"),
        "got: {err}"
    );
    cfg.lifecycle.eager_tunnels.clear();

    cfg.per_tunnel
        .overrides
        .insert("wgcf-999".to_string(), TunnelPortOverride::default());
    let err = cfg
        .validate_tunnel_references(&known)
        .expect_err("ghost override key must fail");
    assert!(
        err.to_string().contains("per_tunnel.overrides.wgcf-999"),
        "got: {err}"
    );
    cfg.per_tunnel.overrides.clear();

    cfg.shared_listeners[0].pool = TunnelPoolSelection::Selected(vec!["wgcf-999".to_string()]);
    let err = cfg
        .validate_tunnel_references(&known)
        .expect_err("ghost pool id must fail");
    assert!(err.to_string().contains("wgcf-999"), "got: {err}");
    assert!(err.to_string().contains("shared_listener"), "got: {err}");

    // A pool naming a real tunnel passes, and so does the "all" pool.
    cfg.shared_listeners[0].pool = TunnelPoolSelection::Selected(vec!["wgcf-002".to_string()]);
    cfg.validate_tunnel_references(&known)
        .expect("real pool ids pass");
    cfg.shared_listeners[0].pool = TunnelPoolSelection::All;
    cfg.validate_tunnel_references(&known)
        .expect("pool all passes");
}

// =========================================================================
// 9. Cloned Config Simulation: 245 Identical wgcf Configs with Unique IDs
// =========================================================================
#[test]
fn test_cloned_wgcf_simulation_245_instances() {
    // Sample Cloudflare WARP wgcf configuration
    let wgcf_conf_content = format!(
        r#"
        [Interface]
        PrivateKey = {VALID_PRIVATE_KEY}
        Address = 172.16.0.2/32, 2606:4700:110:8f81:dead:beef:cafe:0001/128
        DNS = 1.1.1.1, 2606:4700:4700::1111
        MTU = 1280

        [Peer]
        PublicKey = {VALID_PUBLIC_KEY}
        AllowedIPs = 0.0.0.0/0, ::/0
        Endpoint = engage.cloudflareclient.com:2408
        PersistentKeepalive = 25
        "#
    );

    let mut tunnel_registry: HashMap<String, TunnelConfig> = HashMap::new();

    // Simulate 245 identical cloned configs
    for i in 1..=245 {
        let tunnel_id = format!("wgcf-{:03}", i);
        let config = load_tunnel_config_from_str(&tunnel_id, &wgcf_conf_content)
            .expect("parse cloned wgcf config");

        assert_eq!(config.id, tunnel_id);
        // Verify keys and addresses match exactly across all 245 instances
        assert_eq!(config.interface.addresses.len(), 2);
        assert_eq!(config.peers.len(), 1);

        let old = tunnel_registry.insert(tunnel_id, config);
        assert!(old.is_none(), "No ID collision should occur");
    }

    assert_eq!(
        tunnel_registry.len(),
        245,
        "Registry must contain exactly 245 unique tunnels without collision"
    );

    // Verify retrieval of arbitrary tunnel IDs
    assert!(tunnel_registry.contains_key("wgcf-001"));
    assert!(tunnel_registry.contains_key("wgcf-100"));
    assert!(tunnel_registry.contains_key("wgcf-245"));
}

// =========================================================================
// 10. Directory Loading Helper & Duplicate Detection
// =========================================================================
#[test]
fn test_load_tunnel_configs_from_dir() {
    let temp_dir = tempfile::tempdir().expect("create temp dir");
    let dir_path = temp_dir.path();

    let conf_content = format!(
        "[Interface]\nPrivateKey = {VALID_PRIVATE_KEY}\nAddress = 10.0.0.2/32\n[Peer]\nPublicKey = {VALID_PUBLIC_KEY}\nEndpoint = 1.1.1.1:51820\nAllowedIPs = 0.0.0.0/0\n"
    );

    // Write 3 valid .conf files out of alphabetical order
    std::fs::write(dir_path.join("wg-beta.conf"), &conf_content).unwrap();
    std::fs::write(dir_path.join("wg-alpha.conf"), &conf_content).unwrap();
    std::fs::write(dir_path.join("wgcf-001.conf"), &conf_content).unwrap();

    // Write a non-conf file to verify filtering
    std::fs::write(dir_path.join("notes.txt"), "some notes").unwrap();

    let configs = load_tunnel_configs_from_dir(dir_path).expect("load configs from dir");

    assert_eq!(configs.len(), 3, "Only .conf files must be loaded");
    // Verify sorted ordering: wg-alpha, wg-beta, wgcf-001
    assert_eq!(configs[0].id, "wg-alpha");
    assert_eq!(configs[1].id, "wg-beta");
    assert_eq!(configs[2].id, "wgcf-001");
}

#[test]
fn test_load_tunnel_configs_from_dir_not_found() {
    let non_existent = PathBuf::from("/non/existent/wpmulti/dir");
    let res = load_tunnel_configs_from_dir(non_existent);
    assert!(matches!(res, Err(ConfigError::DirectoryNotFound(_))));
}

#[test]
fn test_load_tunnel_configs_from_dir_reports_every_broken_file() {
    // Loading used to stop at the first broken `.conf`, so a directory
    // with several bad files only ever reported one of them and the user
    // had to fix-and-rerun one file at a time.
    let temp_dir = tempfile::tempdir().expect("create temp dir");
    let dir_path = temp_dir.path();

    let valid = format!(
        "[Interface]\nPrivateKey = {VALID_PRIVATE_KEY}\nAddress = 10.0.0.2/32\n[Peer]\nPublicKey = {VALID_PUBLIC_KEY}\nEndpoint = 1.1.1.1:51820\nAllowedIPs = 0.0.0.0/0\n"
    );
    let broken_a = valid.replace(VALID_PRIVATE_KEY, "!!!bad!!!");
    let broken_b = valid.replace(VALID_PRIVATE_KEY, "AAAA!AAA");
    std::fs::write(dir_path.join("a-broken.conf"), &broken_a).unwrap();
    std::fs::write(dir_path.join("b-broken.conf"), &broken_b).unwrap();
    std::fs::write(dir_path.join("c-good.conf"), &valid).unwrap();

    let err = load_tunnel_configs_from_dir(dir_path).expect_err("two broken files must fail");
    let msg = err.to_string();
    assert!(
        msg.contains("a-broken.conf") && msg.contains("b-broken.conf"),
        "expected both broken files in one error, got: {msg}"
    );
    // Each failure keeps its own precise offset (round-11 fix), not a
    // generic "multiple files failed".
    assert!(msg.contains("offset 0"), "got: {msg}");
    assert!(msg.contains("offset 4"), "got: {msg}");
}

// =========================================================================
// 11. IpMode Parsing, Helpers & Validation
// =========================================================================
#[test]
fn test_ip_mode_helpers_and_parsing() {
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    let v4 = IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1));
    let v6 = IpAddr::V6(Ipv6Addr::new(0x2606, 0x4700, 0x4700, 0, 0, 0, 0, 0x1111));

    assert!(IpMode::DualStack.allows_ip(v4));
    assert!(IpMode::DualStack.allows_ip(v6));
    assert!(IpMode::Ipv4Only.allows_ip(v4));
    assert!(!IpMode::Ipv4Only.allows_ip(v6));
    assert!(!IpMode::Ipv6Only.allows_ip(v4));
    assert!(IpMode::Ipv6Only.allows_ip(v6));

    assert_eq!(
        IpMode::effective_with_global(Some(IpMode::Ipv6Only), IpMode::DualStack),
        Ok(IpMode::Ipv6Only)
    );
    assert_eq!(
        IpMode::effective_with_global(None, IpMode::Ipv4Only),
        Ok(IpMode::Ipv4Only)
    );

    let toml_str = r#"
        [global]
        ip_mode = "ipv6_only"
    "#;
    let cfg: MainConfig = toml::from_str(toml_str).expect("parse ip_mode");
    assert_eq!(cfg.global.ip_mode, IpMode::Ipv6Only);
    cfg.validate()
        .expect("global ipv6_only without listener override is valid");
}

#[test]
fn test_ip_mode_listener_validation() {
    // Valid: global dual_stack with ipv4_only listener override
    let valid_toml = r#"
        [global]
        ip_mode = "dual_stack"

        [[shared_listener]]
        name = "v4-socks"
        type = "socks5"
        bind = "127.0.0.1:1080"
        ip_mode = "ipv4_only"
    "#;
    let cfg: MainConfig = toml::from_str(valid_toml).unwrap();
    cfg.validate()
        .expect("dual_stack global allows ipv4_only listener");

    // Invalid: global ipv4_only with ipv6_only listener override
    let conflict_toml = r#"
        [global]
        ip_mode = "ipv4_only"

        [[shared_listener]]
        name = "bad-socks"
        type = "socks5"
        bind = "127.0.0.1:1080"
        ip_mode = "ipv6_only"
    "#;
    let cfg: MainConfig = toml::from_str(conflict_toml).unwrap();
    assert!(
        cfg.validate().is_err(),
        "conflicting ip_mode must fail validation"
    );

    // Invalid: global ipv6_only with dual_stack listener override (cannot loosen)
    let loosen_toml = r#"
        [global]
        ip_mode = "ipv6_only"

        [[shared_listener]]
        name = "loosen-socks"
        type = "socks5"
        bind = "127.0.0.1:1080"
        ip_mode = "dual_stack"
    "#;
    let cfg: MainConfig = toml::from_str(loosen_toml).unwrap();
    assert!(
        cfg.validate().is_err(),
        "loosening global ip_mode must fail validation"
    );
}

#[test]
fn test_health_check_settings_and_validation() {
    let mut cfg = MainConfig::default();
    assert_eq!(cfg.health_check.threshold, 3);
    assert_eq!(cfg.health_check.cooldown, Duration::from_secs(30));
    assert_eq!(cfg.health_check.probe_interval, Duration::from_secs(30));
    assert_eq!(cfg.health_check.probe_timeout, Duration::from_secs(5));
    assert_eq!(cfg.health_check.probe_concurrency, 16);
    assert_eq!(cfg.health_check.probe_attempts, 1);
    assert!(cfg.validate().is_ok());

    cfg.health_check.threshold = 0;
    assert!(cfg.validate().is_err());

    cfg.health_check.threshold = 3;
    cfg.health_check.cooldown = Duration::ZERO;
    assert!(cfg.validate().is_err());

    cfg.health_check.cooldown = Duration::from_secs(10);
    cfg.health_check.probe_interval = Duration::ZERO;
    assert!(cfg.validate().is_err());

    cfg.health_check.probe_interval = Duration::from_secs(10);
    cfg.health_check.probe_timeout = Duration::ZERO;
    assert!(cfg.validate().is_err());

    cfg.health_check.probe_timeout = Duration::from_secs(5);
    cfg.health_check.probe_concurrency = 0;
    assert!(cfg.validate().is_err());

    cfg.health_check.probe_concurrency = 16;
    cfg.health_check.probe_attempts = 0;
    assert!(cfg.validate().is_err());
}

#[test]
fn test_admin_non_loopback_requires_auth_token() {
    let mut cfg = MainConfig::default();
    cfg.admin.enabled = true;
    cfg.admin.bind = "0.0.0.0:9090".parse().unwrap();
    cfg.admin.auth_token = None;
    assert!(
        cfg.validate().is_err(),
        "non-loopback admin.bind without auth_token must fail validation"
    );

    cfg.admin.auth_token = Some("strong-secret-token".to_string());
    assert!(
        cfg.validate().is_ok(),
        "non-loopback admin.bind with auth_token must pass validation"
    );
}

#[test]
fn test_wg_conf_mtu_bounds_duplicate_keys_oversized_and_secret_redaction() {
    use crate::config::wg_conf::{MAX_WG_CONF_SIZE, MIN_WG_MTU, WgConfError};

    // 1. MTU = 0 or < MIN_WG_MTU (68) must be rejected; MTU = 68 and 65535 accepted
    for bad_mtu in ["0", "67"] {
        let conf = format!(
            "[Interface]\nPrivateKey = {VALID_PRIVATE_KEY}\nAddress = 10.0.0.2/32\nMTU = {bad_mtu}\n[Peer]\nPublicKey = {VALID_PUBLIC_KEY}\nEndpoint = 1.1.1.1:51820\n"
        );
        assert!(
            matches!(parse_wg_conf(&conf), Err(WgConfError::InvalidMtu { .. })),
            "MTU {bad_mtu} must be rejected"
        );
    }
    for ok_mtu in [MIN_WG_MTU, 65535] {
        let conf = format!(
            "[Interface]\nPrivateKey = {VALID_PRIVATE_KEY}\nAddress = 10.0.0.2/32\nMTU = {ok_mtu}\n[Peer]\nPublicKey = {VALID_PUBLIC_KEY}\nEndpoint = 1.1.1.1:51820\n"
        );
        let (iface, _) = parse_wg_conf(&conf).expect("valid boundary MTU must parse");
        assert_eq!(iface.mtu, ok_mtu);
    }

    // 2. Duplicate critical keys must be rejected deterministically
    let dup_priv = format!(
        "[Interface]\nPrivateKey = {VALID_PRIVATE_KEY}\nPrivateKey = {VALID_PRIVATE_KEY}\nAddress = 10.0.0.2/32\n[Peer]\nPublicKey = {VALID_PUBLIC_KEY}\nEndpoint = 1.1.1.1:51820\n"
    );
    assert!(matches!(
        parse_wg_conf(&dup_priv),
        Err(WgConfError::DuplicateKey {
            key: "PrivateKey",
            ..
        })
    ));
    let dup_ep = format!(
        "[Interface]\nPrivateKey = {VALID_PRIVATE_KEY}\nAddress = 10.0.0.2/32\n[Peer]\nPublicKey = {VALID_PUBLIC_KEY}\nEndpoint = 1.1.1.1:51820\nEndpoint = 1.1.1.2:51820\n"
    );
    assert!(matches!(
        parse_wg_conf(&dup_ep),
        Err(WgConfError::DuplicateKey {
            key: "Endpoint",
            ..
        })
    ));

    // 3. Oversized input (> MAX_WG_CONF_SIZE) must be rejected
    let huge = "#".repeat(MAX_WG_CONF_SIZE + 1);
    assert!(matches!(
        parse_wg_conf(&huge),
        Err(WgConfError::InputTooLarge { .. })
    ));

    // 4. Secret redaction in Debug output and parse errors
    let psk = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";
    let valid_with_psk = format!(
        "[Interface]\nPrivateKey = {VALID_PRIVATE_KEY}\nAddress = 10.0.0.2/32\n[Peer]\nPublicKey = {VALID_PUBLIC_KEY}\nPresharedKey = {psk}\nEndpoint = 1.1.1.1:51820\n"
    );
    let tunnel = load_tunnel_config_from_str("redact-test", &valid_with_psk).unwrap();
    let dbg_str = format!("{tunnel:?}");
    assert!(!dbg_str.contains(VALID_PRIVATE_KEY));
    assert!(!dbg_str.contains(psk));
    assert!(dbg_str.contains("[REDACTED]"));

    let malformed_secret_line = format!("PrivateKey {VALID_PRIVATE_KEY}\n[Interface]\n");
    let err_msg = parse_wg_conf(&malformed_secret_line)
        .unwrap_err()
        .to_string();
    assert!(!err_msg.contains(VALID_PRIVATE_KEY));
    assert!(err_msg.contains("[REDACTED SECRET LINE]"));

    let bare_long_secret = format!("{VALID_PRIVATE_KEY}\n[Interface]\n");
    let err_msg2 = parse_wg_conf(&bare_long_secret).unwrap_err().to_string();
    assert!(!err_msg2.contains(VALID_PRIVATE_KEY));
}

#[test]
fn test_validate_detects_internal_port_conflicts() {
    let toml_conflict = r#"
[global]
bind_address = "127.0.0.1"

[per_tunnel]
enabled = true
base_socks5_port = 20000
base_http_port = 21000

[per_tunnel.overrides.peer1]
socks5_port = 18080

[[shared_listener]]
name = "shared-socks"
type = "socks5"
bind = "127.0.0.1:18080"
auth_mode = "none"
"#;
    let cfg: MainConfig = toml::from_str(toml_conflict).unwrap();
    let err = cfg.validate().unwrap_err();
    let msg = err.to_string();
    assert!(
        msg.contains("peer1") && msg.contains("shared-socks"),
        "expected conflict error naming peer1 and shared-socks, got: {msg}"
    );

    let base_conflict = r#"
[global]
bind_address = "127.0.0.1"

[per_tunnel]
enabled = true
base_socks5_port = 11080
base_http_port = 21000

[[shared_listener]]
name = "shared-socks"
type = "socks5"
bind = "127.0.0.1:11080"
auth_mode = "none"
"#;
    let base_cfg: MainConfig = toml::from_str(base_conflict).unwrap();
    let base_err = base_cfg.validate().unwrap_err().to_string();
    assert!(
        base_err.contains("base_socks5_port") && base_err.contains("shared-socks"),
        "expected conflict error naming base_socks5_port and shared-socks, got: {base_err}"
    );
}
