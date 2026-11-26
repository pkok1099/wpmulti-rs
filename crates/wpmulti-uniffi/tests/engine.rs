//! Integration tests for the UniFFI `Engine` adapter.
//!
//! The `.conf` texts below use synthetic keys only (32 bytes of 0x2a /
//! 0x63, base64-encoded). They are not real tunnel credentials.

use wpmulti_uniffi::{Engine, EngineError, SocketProtector, TunnelConfInput, TunnelState};

const TEST_TOML: &str = r#"
[global]
max_active_tunnels = 1000
[lifecycle]
mode = "lazy"
"#;

fn test_conf(id: &str) -> TunnelConfInput {
    TunnelConfInput {
        id: id.to_string(),
        content: "[Interface]\nPrivateKey = KioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKio=\nAddress = 172.16.0.2/32\nDNS = 1.1.1.1\nMTU = 1420\n\n[Peer]\nPublicKey = Y2NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2M=\nEndpoint = 127.0.0.1:51820\nAllowedIPs = 0.0.0.0/0, ::/0\nPersistentKeepalive = 25\n"
            .to_string(),
    }
}

#[test]
fn engine_new_applies_phone_defaults() {
    let engine = Engine::new(TEST_TOML.to_string(), vec![test_conf("wgcf-001")])
        .expect("engine should build from valid config");
    let status = engine.status();
    assert!(!status.started);
    assert_eq!(status.tunnel_count, 1);
    assert_eq!(status.active_tunnel_count, 0);
    let config = engine.get_config();
    assert_eq!(config.max_active_tunnels, 8);
    let tunnels = engine.list_tunnels();
    assert_eq!(tunnels.len(), 1);
    assert_eq!(tunnels[0].id, "wgcf-001");
    assert!(!tunnels[0].disabled);
}

#[test]
fn engine_new_rejects_invalid_conf() {
    let bad = TunnelConfInput {
        id: "bad-001".to_string(),
        content: "[Interface]\nPrivateKey = not-a-key\n".to_string(),
    };
    let err = Engine::new(String::new(), vec![bad]).expect_err("bad conf must fail");
    assert!(
        matches!(err, EngineError::InvalidConfig(_)),
        "expected InvalidConfig, got {err:?}"
    );
}

#[test]
fn engine_new_with_no_tunnels_succeeds() {
    let engine = Engine::new(String::new(), vec![]).expect("empty tunnel set should build");
    assert_eq!(engine.status().tunnel_count, 0);
    assert_eq!(engine.list_tunnels().len(), 0);
}

#[tokio::test]
async fn engine_attach_tun_rejects_bad_fd() {
    let engine = Engine::new(String::new(), vec![]).expect("engine should build");
    let err = engine
        .attach_tun(-1, 1500)
        .await
        .expect_err("negative fd must fail");
    assert!(
        matches!(err, EngineError::InvalidConfig(_)),
        "expected InvalidConfig, got {err:?}"
    );
    let err = engine
        .attach_tun(3, 0)
        .await
        .expect_err("zero MTU must fail");
    assert!(
        matches!(err, EngineError::InvalidConfig(_)),
        "expected InvalidConfig, got {err:?}"
    );
}

#[tokio::test]
async fn engine_attach_tun_accepts_real_fd() {
    use std::os::unix::io::AsRawFd;
    use std::os::unix::net::UnixStream;

    // A socketpair stands in for the Android TUN fd: the endpoint only
    // reads/writes raw bytes, so any byte-stream fd works for the test.
    // `forget` transfers ownership of the fd to the engine, mirroring
    // the VpnService handover (no double close).
    let (tun_side, _other_side) = UnixStream::pair().expect("socketpair");
    let fd = tun_side.as_raw_fd();
    std::mem::forget(tun_side);

    let engine = Engine::new(String::new(), vec![]).expect("engine should build");
    engine
        .attach_tun(fd, 1500)
        .await
        .expect("attach_tun with a real fd must succeed");
    assert!(
        !engine.status().started,
        "attach alone must not start the engine"
    );

    // Second attach is an error and must not take ownership of the fd.
    let err = engine
        .attach_tun(9999, 1500)
        .await
        .expect_err("second attach must fail");
    assert!(
        matches!(err, EngineError::OperationFailed(_)),
        "expected OperationFailed, got {err:?}"
    );

    engine.stop().await.expect("stop must close the TUN fd");
}

#[tokio::test]
async fn engine_set_tunnel_disabled_rejects_batch_selectors() {
    // Audit run-1, `uniffi:set-tunnel-disabled-batch-selector`: the
    // single-ID wrapper must never disable a whole fleet, so batch
    // selector syntax and unknown IDs are rejected before any call
    // into the batch resolver.
    let engine = Engine::new(
        TEST_TOML.to_string(),
        vec![test_conf("wgcf-001"), test_conf("wgcf-002")],
    )
    .expect("engine should build");
    for selector in ["all", "ALL", "*", "1", "1-2", "wgcf-001,wgcf-002"] {
        let err = engine
            .set_tunnel_disabled(selector.to_string(), true)
            .await
            .expect_err("batch selector must be rejected");
        assert!(
            matches!(err, EngineError::InvalidConfig(_)),
            "expected InvalidConfig for '{selector}', got {err:?}"
        );
    }
    let err = engine
        .set_tunnel_disabled("wgcf-999".to_string(), true)
        .await
        .expect_err("unknown id must be rejected");
    assert!(
        matches!(err, EngineError::TunnelNotFound(_)),
        "expected TunnelNotFound, got {err:?}"
    );
    engine
        .set_tunnel_disabled("wgcf-001".to_string(), true)
        .await
        .expect("one exact registered id must disable");
    assert!(
        engine.list_tunnels()[0].disabled,
        "wgcf-001 must be disabled"
    );
    assert!(
        !engine.list_tunnels()[1].disabled,
        "wgcf-002 must stay enabled"
    );
}

#[tokio::test]
async fn engine_attach_tun_migrates_active_tunnel_to_vpn() {
    // Audit run-1,
    // `uniffi:attach-order-pre-attach-proxy-boot-never-migrates-to-tun`:
    // a tunnel activated before attach_tun must migrate to VPN mode
    // on attach, and the attach is refused up front when no socket
    // protector is installed yet.
    use std::os::unix::io::AsRawFd;
    use std::os::unix::net::UnixStream;

    #[derive(Debug)]
    struct AcceptProtector;
    impl SocketProtector for AcceptProtector {
        fn protect(&self, _fd: i32) -> bool {
            true
        }
    }

    let engine = Engine::new(TEST_TOML.to_string(), vec![test_conf("wgcf-001")])
        .expect("engine should build");
    engine
        .activate_tunnel("wgcf-001".to_string())
        .await
        .expect("proxy activation must succeed");

    let (tun_side, _other_side) = UnixStream::pair().expect("socketpair");
    let fd = tun_side.as_raw_fd();
    std::mem::forget(tun_side);
    let err = engine
        .attach_tun(fd, 1500)
        .await
        .expect_err("attach with active tunnels and no protector must fail");
    assert!(
        matches!(err, EngineError::InvalidConfig(_)),
        "expected InvalidConfig naming the protector, got {err:?}"
    );

    engine.set_socket_protector(Box::new(AcceptProtector));
    let (tun_side, _other_side) = UnixStream::pair().expect("socketpair");
    let fd = tun_side.as_raw_fd();
    std::mem::forget(tun_side);
    engine
        .attach_tun(fd, 1500)
        .await
        .expect("attach with a protector must migrate the active tunnel");
    assert_eq!(
        engine.list_tunnels()[0].state,
        TunnelState::Active,
        "migrated tunnel must stay active"
    );

    engine.stop().await.expect("stop must close the TUN fd");
}

#[tokio::test]
async fn engine_start_and_stop_without_listeners() {
    let engine = Engine::new(TEST_TOML.to_string(), vec![test_conf("wgcf-001")])
        .expect("engine should build");
    engine.start().await.expect("start should succeed");
    assert!(engine.status().started);
    assert!(
        matches!(engine.start().await, Err(EngineError::AlreadyStarted)),
        "second start must fail with AlreadyStarted"
    );
    engine.stop().await.expect("stop should succeed");
    assert!(!engine.status().started);
    engine.stop().await.expect("stop is idempotent");
}
