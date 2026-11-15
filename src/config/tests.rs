use super::*;
use std::collections::HashMap;
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
        socks5_port = 1080
        http_port = 8080

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
            socks5_port: Some(1080),
            http_port: Some(8080),
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

    assert_eq!(cfg.health_check.threshold, 5);
    assert_eq!(cfg.health_check.cooldown, Duration::from_secs(45));
    assert_eq!(cfg.health_check.probe_interval, Duration::from_secs(60));
    assert_eq!(cfg.health_check.probe_timeout, Duration::from_secs(10));
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
    assert_eq!(cfg.health_check.threshold, 3);
    assert_eq!(cfg.health_check.cooldown, Duration::from_secs(30));
    assert_eq!(cfg.health_check.probe_interval, Duration::from_secs(30));
    assert_eq!(cfg.health_check.probe_timeout, Duration::from_secs(5));
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
}
