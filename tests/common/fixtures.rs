use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone)]
pub struct WgPeerFixture {
    pub public_key: String,
    pub endpoint: String,
    pub allowed_ips: Vec<String>,
    pub preshared_key: Option<String>,
    pub persistent_keepalive: Option<u16>,
}

impl WgPeerFixture {
    pub fn new(public_key: &str, endpoint: &str) -> Self {
        Self {
            public_key: public_key.to_string(),
            endpoint: endpoint.to_string(),
            allowed_ips: vec!["0.0.0.0/0".to_string(), "::/0".to_string()],
            preshared_key: None,
            persistent_keepalive: Some(25),
        }
    }

    pub fn allowed_ips(mut self, ips: &[&str]) -> Self {
        self.allowed_ips = ips.iter().map(|s| s.to_string()).collect();
        self
    }

    pub fn preshared_key(mut self, psk: &str) -> Self {
        self.preshared_key = Some(psk.to_string());
        self
    }

    pub fn persistent_keepalive(mut self, keepalive: u16) -> Self {
        self.persistent_keepalive = Some(keepalive);
        self
    }
}

#[derive(Debug, Clone)]
pub struct WgConfBuilder {
    pub private_key: String,
    pub addresses: Vec<String>,
    pub dns: Vec<String>,
    pub listen_port: Option<u16>,
    pub mtu: Option<u16>,
    pub peers: Vec<WgPeerFixture>,
    pub extra_directives: Vec<String>,
}

impl Default for WgConfBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl WgConfBuilder {
    pub fn new() -> Self {
        Self {
            private_key: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=".to_string(),
            addresses: vec!["10.0.0.2/32".to_string()],
            dns: vec!["1.1.1.1".to_string()],
            listen_port: None,
            mtu: Some(1420),
            peers: Vec::new(),
            extra_directives: Vec::new(),
        }
    }

    pub fn private_key(mut self, key: &str) -> Self {
        self.private_key = key.to_string();
        self
    }

    pub fn addresses(mut self, addrs: &[&str]) -> Self {
        self.addresses = addrs.iter().map(|s| s.to_string()).collect();
        self
    }

    pub fn dns(mut self, dns_servers: &[&str]) -> Self {
        self.dns = dns_servers.iter().map(|s| s.to_string()).collect();
        self
    }

    pub fn listen_port(mut self, port: u16) -> Self {
        self.listen_port = Some(port);
        self
    }

    pub fn mtu(mut self, mtu: u16) -> Self {
        self.mtu = Some(mtu);
        self
    }

    pub fn add_peer(mut self, peer: WgPeerFixture) -> Self {
        self.peers.push(peer);
        self
    }

    pub fn add_extra_directive(mut self, directive: &str) -> Self {
        self.extra_directives.push(directive.to_string());
        self
    }

    pub fn build_ini(&self) -> String {
        let mut out = String::new();
        out.push_str("[Interface]\n");
        out.push_str(&format!("PrivateKey = {}\n", self.private_key));
        if !self.addresses.is_empty() {
            out.push_str(&format!("Address = {}\n", self.addresses.join(", ")));
        }
        if !self.dns.is_empty() {
            out.push_str(&format!("DNS = {}\n", self.dns.join(", ")));
        }
        if let Some(port) = self.listen_port {
            out.push_str(&format!("ListenPort = {}\n", port));
        }
        if let Some(mtu) = self.mtu {
            out.push_str(&format!("MTU = {}\n", mtu));
        }
        for extra in &self.extra_directives {
            out.push_str(&format!("{}\n", extra));
        }

        for peer in &self.peers {
            out.push_str("\n[Peer]\n");
            out.push_str(&format!("PublicKey = {}\n", peer.public_key));
            out.push_str(&format!("Endpoint = {}\n", peer.endpoint));
            if !peer.allowed_ips.is_empty() {
                out.push_str(&format!("AllowedIPs = {}\n", peer.allowed_ips.join(", ")));
            }
            if let Some(psk) = &peer.preshared_key {
                out.push_str(&format!("PresharedKey = {}\n", psk));
            }
            if let Some(ka) = peer.persistent_keepalive {
                out.push_str(&format!("PersistentKeepalive = {}\n", ka));
            }
        }
        out
    }
}

#[derive(Debug, Clone)]
pub struct SharedListenerFixture {
    pub name: String,
    pub proto_type: String, // "socks5" | "http"
    pub bind: SocketAddr,
    pub auth_mode: String,  // "none" | "global" | "per_tunnel"
    pub global_password: Option<String>,
    pub default_strategy: String, // "round-robin" | "random" | "least-conn"
    pub allow_anonymous: bool,
    pub pool: String,
}

#[derive(Debug, Clone)]
pub struct WpMultiTomlBuilder {
    pub config_dir: PathBuf,
    pub bind_address: String,
    pub log_level: String,
    pub dns_fallback: String,
    pub dns_strategy: String,
    pub max_active_tunnels: usize,
    pub lifecycle_mode: String,
    pub idle_timeout: String,
    pub handshake_timeout: String,
    pub eager_tunnels: Vec<String>,
    pub per_tunnel_enabled: bool,
    pub base_socks5_port: Option<u16>,
    pub base_http_port: Option<u16>,
    pub overrides: HashMap<String, (Option<u16>, Option<u16>)>,
    pub shared_listeners: Vec<SharedListenerFixture>,
    pub admin_enabled: bool,
    pub admin_bind: Option<SocketAddr>,
    pub admin_token: Option<String>,
}

impl WpMultiTomlBuilder {
    pub fn new(config_dir: PathBuf) -> Self {
        Self {
            config_dir,
            bind_address: "127.0.0.1".to_string(),
            log_level: "info".to_string(),
            dns_fallback: "1.1.1.1:53".to_string(),
            dns_strategy: "tunnel_only".to_string(),
            max_active_tunnels: 1000,
            lifecycle_mode: "lazy".to_string(),
            idle_timeout: "5m".to_string(),
            handshake_timeout: "10s".to_string(),
            eager_tunnels: Vec::new(),
            per_tunnel_enabled: true,
            base_socks5_port: Some(10000),
            base_http_port: Some(20000),
            overrides: HashMap::new(),
            shared_listeners: Vec::new(),
            admin_enabled: true,
            admin_bind: Some("127.0.0.1:9090".parse().unwrap()),
            admin_token: None,
        }
    }

    pub fn bind_address(mut self, addr: &str) -> Self {
        self.bind_address = addr.to_string();
        self
    }

    pub fn log_level(mut self, level: &str) -> Self {
        self.log_level = level.to_string();
        self
    }

    pub fn lifecycle_mode(mut self, mode: &str) -> Self {
        self.lifecycle_mode = mode.to_string();
        self
    }

    pub fn idle_timeout(mut self, timeout: &str) -> Self {
        self.idle_timeout = timeout.to_string();
        self
    }

    pub fn base_ports(mut self, socks5: Option<u16>, http: Option<u16>) -> Self {
        self.base_socks5_port = socks5;
        self.base_http_port = http;
        self
    }

    pub fn add_override(mut self, tunnel_id: &str, socks5: Option<u16>, http: Option<u16>) -> Self {
        self.overrides.insert(tunnel_id.to_string(), (socks5, http));
        self
    }

    pub fn add_shared_listener(mut self, listener: SharedListenerFixture) -> Self {
        self.shared_listeners.push(listener);
        self
    }

    pub fn admin(mut self, enabled: bool, bind: Option<SocketAddr>, token: Option<&str>) -> Self {
        self.admin_enabled = enabled;
        self.admin_bind = bind;
        self.admin_token = token.map(|s| s.to_string());
        self
    }

    pub fn build_toml(&self) -> String {
        let mut out = String::new();
        out.push_str("[global]\n");
        out.push_str(&format!("config_dir = \"{}\"\n", self.config_dir.display()));
        out.push_str(&format!("bind_address = \"{}\"\n", self.bind_address));
        out.push_str(&format!("log_level = \"{}\"\n", self.log_level));
        out.push_str(&format!("dns_fallback = \"{}\"\n", self.dns_fallback));
        out.push_str(&format!("dns_strategy = \"{}\"\n", self.dns_strategy));
        out.push_str(&format!("max_active_tunnels = {}\n\n", self.max_active_tunnels));

        out.push_str("[lifecycle]\n");
        out.push_str(&format!("mode = \"{}\"\n", self.lifecycle_mode));
        out.push_str(&format!("idle_timeout = \"{}\"\n", self.idle_timeout));
        out.push_str(&format!("handshake_timeout = \"{}\"\n", self.handshake_timeout));
        if !self.eager_tunnels.is_empty() {
            let eager_list = self
                .eager_tunnels
                .iter()
                .map(|s| format!("\"{}\"", s))
                .collect::<Vec<_>>()
                .join(", ");
            out.push_str(&format!("eager_tunnels = [{}]\n", eager_list));
        }
        out.push('\n');

        out.push_str("[per_tunnel]\n");
        out.push_str(&format!("enabled = {}\n", self.per_tunnel_enabled));
        if let Some(p) = self.base_socks5_port {
            out.push_str(&format!("base_socks5_port = {}\n", p));
        }
        if let Some(p) = self.base_http_port {
            out.push_str(&format!("base_http_port = {}\n", p));
        }

        for (id, (s5, http)) in &self.overrides {
            out.push_str(&format!("\n[per_tunnel.overrides.\"{}\"]\n", id));
            if let Some(p) = s5 {
                out.push_str(&format!("socks5_port = {}\n", p));
            }
            if let Some(p) = http {
                out.push_str(&format!("http_port = {}\n", p));
            }
        }
        out.push('\n');

        for listener in &self.shared_listeners {
            out.push_str("[[shared_listener]]\n");
            out.push_str(&format!("name = \"{}\"\n", listener.name));
            out.push_str(&format!("type = \"{}\"\n", listener.proto_type));
            out.push_str(&format!("bind = \"{}\"\n", listener.bind));
            out.push_str(&format!("auth_mode = \"{}\"\n", listener.auth_mode));
            if let Some(pass) = &listener.global_password {
                out.push_str(&format!("global_password = \"{}\"\n", pass));
            }
            out.push_str(&format!("default_strategy = \"{}\"\n", listener.default_strategy));
            out.push_str(&format!("allow_anonymous = {}\n", listener.allow_anonymous));
            out.push_str(&format!("pool = \"{}\"\n\n", listener.pool));
        }

        if self.admin_enabled {
            out.push_str("[admin]\n");
            out.push_str("enabled = true\n");
            if let Some(bind) = self.admin_bind {
                out.push_str(&format!("bind = \"{}\"\n", bind));
            }
            if let Some(tok) = &self.admin_token {
                out.push_str(&format!("auth_token = \"{}\"\n", tok));
            }
        }

        out
    }
}

#[derive(Debug)]
pub struct WgcfFixtureSet {
    pub config_dir: PathBuf,
    pub tunnel_ids: Vec<String>,
    pub file_paths: Vec<PathBuf>,
    pub private_key: String,
    pub endpoint: SocketAddr,
    pub peer_public_key: String,
    pub addresses: Vec<String>,
}

/// Generates 245 identical cloned wgcf configs indexed by unique tunnel IDs (wgcf-001 to wgcf-245)
pub fn generate_245_cloned_wgcf_configs(
    target_dir: &Path,
    mock_endpoint: SocketAddr,
    mock_peer_pubkey: &str,
) -> std::io::Result<WgcfFixtureSet> {
    std::fs::create_dir_all(target_dir)?;

    // Authoritative Cloudflare WARP wgcf profile parameters
    // Same private key, same IPv4 (172.16.0.2/32), same IPv6 (2606:4700:110:8524:5b27:35a3:e0e7:4816/128)
    let private_key = "0OaUaQd4uJq5m8eN8uJq5m8eN8uJq5m8eN8uJq5m8eM=".to_string();
    let addresses = vec![
        "172.16.0.2/32".to_string(),
        "2606:4700:110:8524:5b27:35a3:e0e7:4816/128".to_string(),
    ];
    let dns = ["1.1.1.1".to_string()];

    let mut tunnel_ids = Vec::with_capacity(245);
    let mut file_paths = Vec::with_capacity(245);

    for i in 1..=245 {
        let tunnel_id = format!("wgcf-{:03}", i);
        let filename = format!("{}.conf", tunnel_id);
        let path = target_dir.join(&filename);

        let conf_content = format!(
            "# Cloudflare WARP wgcf cloned config index {}\n\
            [Interface]\n\
            PrivateKey = {}\n\
            Address = {}\n\
            DNS = {}\n\
            MTU = 1280\n\
            \n\
            [Peer]\n\
            PublicKey = {}\n\
            Endpoint = {}\n\
            AllowedIPs = 0.0.0.0/0, ::/0\n\
            PersistentKeepalive = 25\n",
            i,
            private_key,
            addresses.join(", "),
            dns.join(", "),
            mock_peer_pubkey,
            mock_endpoint
        );

        std::fs::write(&path, conf_content)?;
        tunnel_ids.push(tunnel_id);
        file_paths.push(path);
    }

    Ok(WgcfFixtureSet {
        config_dir: target_dir.to_path_buf(),
        tunnel_ids,
        file_paths,
        private_key,
        endpoint: mock_endpoint,
        peer_public_key: mock_peer_pubkey.to_string(),
        addresses,
    })
}

/// Allocates a single guaranteed available ephemeral TCP/UDP port
pub fn allocate_ephemeral_port() -> u16 {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("failed to bind ephemeral port");
    let port = listener.local_addr().expect("failed to get local addr").port();
    drop(listener);
    port
}

/// Allocates a contiguous block of available ports for per-config listeners
pub fn allocate_ephemeral_port_range(count: u16) -> u16 {
    for base in 30000..60000 {
        let mut listeners = Vec::new();
        let mut success = true;
        for offset in 0..count {
            match std::net::TcpListener::bind(format!("127.0.0.1:{}", base + offset)) {
                Ok(l) => listeners.push(l),
                Err(_) => {
                    success = false;
                    break;
                }
            }
        }
        if success {
            drop(listeners);
            return base;
        }
    }
    panic!("could not find available port range of size {}", count);
}

/// RAII Test Environment managing isolated filesystem state
pub struct TestEnvironment {
    root_dir: PathBuf,
    conf_dir: PathBuf,
}

impl TestEnvironment {
    pub fn new(prefix: &str) -> std::io::Result<Self> {
        let unique_id = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root_dir = std::env::temp_dir().join(format!("wpmulti_test_{}_{}", prefix, unique_id));
        let conf_dir = root_dir.join("conf.d");
        std::fs::create_dir_all(&conf_dir)?;
        Ok(Self { root_dir, conf_dir })
    }

    pub fn conf_dir(&self) -> &Path {
        &self.conf_dir
    }

    pub fn root_dir(&self) -> &Path {
        &self.root_dir
    }

    pub fn write_conf(&self, filename: &str, content: &str) -> std::io::Result<PathBuf> {
        let path = self.conf_dir.join(filename);
        std::fs::write(&path, content)?;
        Ok(path)
    }

    pub fn write_toml(&self, filename: &str, content: &str) -> std::io::Result<PathBuf> {
        let path = self.root_dir.join(filename);
        std::fs::write(&path, content)?;
        Ok(path)
    }
}

impl Drop for TestEnvironment {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.root_dir);
    }
}
