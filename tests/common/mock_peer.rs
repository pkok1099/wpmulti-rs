use std::{
    collections::HashMap,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
    time::Instant,
};

use etherparse::{PacketBuilder, SlicedPacket, TransportSlice};
use gotatun::{
    noise::{
        Tunn, TunnResult, handshake::parse_handshake_anon, index_table::IndexTable,
        rate_limiter::RateLimiter,
    },
    packet::{Packet, WgKind},
    x25519,
};
use tokio::{
    net::UdpSocket,
    sync::{Mutex, RwLock, watch},
    task::JoinHandle,
};
use zerocopy::IntoBytes;

/// Statistics counters exposed as an E2E test oracle.
#[derive(Debug, Default)]
pub struct MockPeerStats {
    pub handshakes_received: AtomicU64,
    pub handshakes_completed: AtomicU64,
    pub data_packets_received: AtomicU64,
    pub keepalives_received: AtomicU64,
    pub tcp_syn_received: AtomicU64,
    pub tcp_bytes_echoed: AtomicU64,
    pub tcp_closed: AtomicU64,
    pub udp_echo_packets: AtomicU64,
    pub dns_queries_answered: AtomicU64,
    pub ipv4_packets: AtomicU64,
    pub ipv6_packets: AtomicU64,
}

/// Adversarial fault-injection controls.
#[derive(Debug, Default)]
pub struct MockPeerControls {
    pub drop_handshakes: AtomicBool,
    pub drop_data: AtomicBool,
    pub drop_dns: AtomicBool,
}

/// Session entry mapped by local receiver_idx.
struct PeerSession {
    tunn: Tunn,
    peer_addr: SocketAddr,
    peer_pub: [u8; 32],
    peer_idx: u32,
    last_seen: Instant,
}

/// In-Process Mock WireGuard Peer for End-to-End Testing.
pub struct MockWireGuardPeer {
    endpoint: SocketAddr,
    public_key: [u8; 32],
    stats: Arc<MockPeerStats>,
    controls: Arc<MockPeerControls>,
    shutdown_tx: Option<watch::Sender<bool>>,
    task_handle: Option<JoinHandle<()>>,
}

impl MockWireGuardPeer {
    /// Start listening on an ephemeral port on 127.0.0.1 with a random private key.
    pub async fn start_ephemeral() -> eyre::Result<Self> {
        let secret = x25519::StaticSecret::from(rand::random::<[u8; 32]>());
        Self::start("127.0.0.1:0".parse().unwrap(), secret.to_bytes(), None).await
    }

    /// Start mock peer on designated address and private key.
    pub async fn start(
        listen_addr: SocketAddr,
        private_key: [u8; 32],
        preshared_key: Option<[u8; 32]>,
    ) -> eyre::Result<Self> {
        let socket = UdpSocket::bind(listen_addr).await?;
        let endpoint = socket.local_addr()?;

        let static_private = x25519::StaticSecret::from(private_key);
        let static_public = x25519::PublicKey::from(&static_private);
        let public_key = *static_public.as_bytes();

        let stats = Arc::new(MockPeerStats::default());
        let controls = Arc::new(MockPeerControls::default());
        let (shutdown_tx, shutdown_rx) = watch::channel(false);

        let stats_clone = Arc::clone(&stats);
        let controls_clone = Arc::clone(&controls);

        let task_handle = tokio::spawn(async move {
            run_mock_peer_loop(
                socket,
                static_private,
                static_public,
                preshared_key,
                stats_clone,
                controls_clone,
                shutdown_rx,
            )
            .await;
        });

        Ok(Self {
            endpoint,
            public_key,
            stats,
            controls,
            shutdown_tx: Some(shutdown_tx),
            task_handle: Some(task_handle),
        })
    }

    pub fn endpoint(&self) -> SocketAddr {
        self.endpoint
    }

    pub fn public_key(&self) -> [u8; 32] {
        self.public_key
    }

    pub fn stats(&self) -> &MockPeerStats {
        &self.stats
    }

    pub fn controls(&self) -> &MockPeerControls {
        &self.controls
    }

    pub async fn stop(mut self) {
        if let Some(tx) = self.shutdown_tx.take() {
            let _ = tx.send(true);
        }
        if let Some(handle) = self.task_handle.take() {
            let _ = handle.await;
        }
    }
}

impl Drop for MockWireGuardPeer {
    fn drop(&mut self) {
        if let Some(tx) = self.shutdown_tx.take() {
            let _ = tx.send(true);
        }
        if let Some(handle) = self.task_handle.take() {
            handle.abort();
        }
    }
}

struct MockPeerContext {
    socket: UdpSocket,
    server_private: x25519::StaticSecret,
    server_public: x25519::PublicKey,
    preshared_key: Option<[u8; 32]>,
    index_table: IndexTable,
    rate_limiter: Arc<RateLimiter>,
    sessions: Arc<RwLock<HashMap<u32, Arc<Mutex<PeerSession>>>>>,
    ip_engine: Arc<Mutex<MockIpEngine>>,
    stats: Arc<MockPeerStats>,
    controls: Arc<MockPeerControls>,
}

impl MockPeerContext {
    async fn handle_packet(&self, packet: &[u8], src_addr: SocketAddr) {
        if packet.len() < 4 {
            return;
        }
        match packet[0] {
            // Type 1: WgHandshakeInit (148 bytes)
            1 if packet.len() == 148 => self.handle_handshake_init(packet, src_addr).await,
            // Type 4: WgData (>= 32 bytes)
            4 if packet.len() >= 32 => self.handle_data_packet(packet, src_addr).await,
            _ => {}
        }
    }

    async fn handle_handshake_init(&self, packet: &[u8], src_addr: SocketAddr) {
        self.stats
            .handshakes_received
            .fetch_add(1, Ordering::Relaxed);
        if self.controls.drop_handshakes.load(Ordering::Relaxed) {
            return;
        }

        let raw_packet = Packet::copy_from(packet);
        let init_kind = match raw_packet.try_into_wg() {
            Ok(k) => k,
            Err(e) => {
                tracing::debug!("Failed to convert packet to WgKind: {e}");
                return;
            }
        };
        let WgKind::HandshakeInit(init_packet) = init_kind else {
            return;
        };
        let hh = match parse_handshake_anon(&self.server_private, &self.server_public, &init_packet)
        {
            Ok(hh) => hh,
            Err(e) => {
                tracing::debug!("Failed to parse handshake anon: {e:?}");
                return;
            }
        };

        let peer_pub = x25519::PublicKey::from(hh.peer_static_public);
        let mut tunn = Tunn::new(
            self.server_private.clone(),
            peer_pub,
            self.preshared_key,
            None,
            self.index_table.clone(),
            self.rate_limiter.clone(),
        );

        if let TunnResult::WriteToNetwork(WgKind::HandshakeResp(resp)) =
            tunn.handle_incoming_packet(WgKind::HandshakeInit(init_packet))
        {
            let local_idx = resp.sender_idx.get();
            let resp_bytes = (*resp).as_bytes();
            if self.socket.send_to(resp_bytes, src_addr).await.is_ok() {
                self.stats
                    .handshakes_completed
                    .fetch_add(1, Ordering::Relaxed);
                let mut w = self.sessions.write().await;
                w.insert(
                    local_idx,
                    Arc::new(Mutex::new(PeerSession {
                        tunn,
                        peer_addr: src_addr,
                        peer_pub: hh.peer_static_public,
                        peer_idx: hh.peer_index,
                        last_seen: Instant::now(),
                    })),
                );
            }
        }
    }

    async fn handle_data_packet(&self, packet: &[u8], src_addr: SocketAddr) {
        self.stats
            .data_packets_received
            .fetch_add(1, Ordering::Relaxed);
        if self.controls.drop_data.load(Ordering::Relaxed) {
            return;
        }

        let receiver_idx = u32::from_le_bytes(packet[4..8].try_into().unwrap());
        let session_arc = {
            let r = self.sessions.read().await;
            r.get(&receiver_idx).cloned()
        };
        let Some(session_arc) = session_arc else {
            tracing::trace!("Session not found for receiver_idx {receiver_idx}");
            return;
        };

        let mut session = session_arc.lock().await;
        session.peer_addr = src_addr;
        session.last_seen = Instant::now();

        let raw_packet = Packet::copy_from(packet);
        let data_kind = match raw_packet.try_into_wg() {
            Ok(k) => k,
            Err(e) => {
                tracing::trace!("Failed to parse data packet: {e}");
                return;
            }
        };
        let WgKind::Data(data_packet) = data_kind else {
            return;
        };

        match session
            .tunn
            .handle_incoming_packet(WgKind::Data(data_packet))
        {
            TunnResult::WriteToTunnel(ip_packet) => {
                if ip_packet.is_empty() {
                    self.stats
                        .keepalives_received
                        .fetch_add(1, Ordering::Relaxed);
                    return;
                }
                let reply_bytes = {
                    let mut engine = self.ip_engine.lock().await;
                    engine.process_packet(ip_packet.as_ref(), &self.controls)
                };
                if let Some(reply) = reply_bytes {
                    let pkt = Packet::copy_from(reply.as_slice());
                    if let Ok(encap) = session.tunn.encapsulate_with_session(pkt) {
                        let encap_bytes = encap.into_bytes();
                        let _ = self
                            .socket
                            .send_to(encap_bytes.as_ref(), session.peer_addr)
                            .await;
                    }
                }
            }
            TunnResult::WriteToNetwork(pkt) => {
                let network_bytes = wg_kind_to_bytes(pkt);
                let _ = self.socket.send_to(&network_bytes, session.peer_addr).await;
            }
            _ => {}
        }
    }
}

fn wg_kind_to_bytes(pkt: WgKind) -> Vec<u8> {
    match pkt {
        WgKind::HandshakeInit(p) => (*p).as_bytes().to_vec(),
        WgKind::HandshakeResp(p) => (*p).as_bytes().to_vec(),
        WgKind::CookieReply(p) => (*p).as_bytes().to_vec(),
        WgKind::Data(p) => p.into_bytes().as_ref().to_vec(),
    }
}

async fn run_mock_peer_loop(
    socket: UdpSocket,
    server_private: x25519::StaticSecret,
    server_public: x25519::PublicKey,
    preshared_key: Option<[u8; 32]>,
    stats: Arc<MockPeerStats>,
    controls: Arc<MockPeerControls>,
    mut shutdown_rx: watch::Receiver<bool>,
) {
    let rate_limiter = Arc::new(RateLimiter::new(&server_public, 1000));
    let ip_engine = Arc::new(Mutex::new(MockIpEngine::new(
        Ipv4Addr::new(10, 0, 0, 1),
        "2606:4700:4700::1111".parse().unwrap(),
        Arc::clone(&stats),
    )));
    let ctx = MockPeerContext {
        socket,
        server_private,
        server_public,
        preshared_key,
        index_table: IndexTable::from_os_rng(),
        rate_limiter,
        sessions: Arc::new(RwLock::new(HashMap::new())),
        ip_engine,
        stats,
        controls,
    };

    let mut buf = vec![0u8; 65536];

    loop {
        tokio::select! {
            _ = shutdown_rx.changed() => {
                if *shutdown_rx.borrow() {
                    break;
                }
            }
            res = ctx.socket.recv_from(&mut buf) => {
                match res {
                    Ok((len, src_addr)) => ctx.handle_packet(&buf[..len], src_addr).await,
                    Err(e) => tracing::warn!("Mock peer UDP recv error: {e}"),
                }
            }
        }
    }
}

fn strip_wg_padding(ip_bytes: &[u8]) -> &[u8] {
    // Strip trailing WireGuard 16-byte padding using IPv4 total_len / IPv6 payload_len
    let true_len = match ip_bytes[0] >> 4 {
        4 if ip_bytes.len() >= 20 => {
            (u16::from_be_bytes([ip_bytes[2], ip_bytes[3]]) as usize).min(ip_bytes.len())
        }
        6 if ip_bytes.len() >= 40 => {
            (40 + u16::from_be_bytes([ip_bytes[4], ip_bytes[5]]) as usize).min(ip_bytes.len())
        }
        _ => ip_bytes.len(),
    };
    &ip_bytes[..true_len]
}

struct TcpConnState {
    server_seq: u32,
    client_seq: u32,
}

/// Parameters for building one synthetic TCP packet (reply direction).
struct TcpPacketSpec<'a> {
    src: SocketAddr,
    dst: SocketAddr,
    seq: u32,
    ack: Option<u32>,
    syn: bool,
    fin: bool,
    psh: bool,
    payload: &'a [u8],
}

pub struct MockIpEngine {
    mock_ipv4: Ipv4Addr,
    mock_ipv6: Ipv6Addr,
    stats: Arc<MockPeerStats>,
    tcp_conns: HashMap<(IpAddr, u16, IpAddr, u16), TcpConnState>,
}

impl MockIpEngine {
    pub fn new(mock_ipv4: Ipv4Addr, mock_ipv6: Ipv6Addr, stats: Arc<MockPeerStats>) -> Self {
        Self {
            mock_ipv4,
            mock_ipv6,
            stats,
            tcp_conns: HashMap::new(),
        }
    }

    pub fn process_packet(
        &mut self,
        ip_bytes: &[u8],
        controls: &MockPeerControls,
    ) -> Option<Vec<u8>> {
        if ip_bytes.is_empty() {
            return None;
        }
        let sliced = SlicedPacket::from_ip(strip_wg_padding(ip_bytes)).ok()?;
        let (src_ip, dst_ip) = self.extract_ip_endpoints(sliced.net?)?;

        match sliced.transport? {
            TransportSlice::Tcp(tcp) => self.process_tcp_packet(src_ip, dst_ip, &tcp),
            TransportSlice::Udp(udp) => self.process_udp_packet(src_ip, dst_ip, &udp, controls),
            _ => None,
        }
    }

    fn extract_ip_endpoints(&self, net: etherparse::NetSlice<'_>) -> Option<(IpAddr, IpAddr)> {
        match net {
            etherparse::NetSlice::Ipv4(v4) => {
                self.stats.ipv4_packets.fetch_add(1, Ordering::Relaxed);
                Some((
                    IpAddr::V4(v4.header().source_addr()),
                    IpAddr::V4(v4.header().destination_addr()),
                ))
            }
            etherparse::NetSlice::Ipv6(v6) => {
                self.stats.ipv6_packets.fetch_add(1, Ordering::Relaxed);
                Some((
                    IpAddr::V6(v6.header().source_addr()),
                    IpAddr::V6(v6.header().destination_addr()),
                ))
            }
            _ => None,
        }
    }

    fn process_tcp_packet(
        &mut self,
        src_ip: IpAddr,
        dst_ip: IpAddr,
        tcp: &etherparse::TcpSlice<'_>,
    ) -> Option<Vec<u8>> {
        let src_port = tcp.source_port();
        let dst_port = tcp.destination_port();
        let key = (src_ip, src_port, dst_ip, dst_port);

        if tcp.syn() && !tcp.ack() {
            self.stats.tcp_syn_received.fetch_add(1, Ordering::Relaxed);
            let server_isn: u32 = rand::random();
            let client_seq = tcp.sequence_number().wrapping_add(1);
            self.tcp_conns.insert(
                key,
                TcpConnState {
                    server_seq: server_isn.wrapping_add(1),
                    client_seq,
                },
            );
            return self.build_tcp(TcpPacketSpec {
                src: SocketAddr::new(dst_ip, dst_port),
                dst: SocketAddr::new(src_ip, src_port),
                seq: server_isn,
                ack: Some(client_seq),
                syn: true,
                fin: false,
                psh: false,
                payload: &[],
            });
        }

        if tcp.fin() {
            self.stats.tcp_closed.fetch_add(1, Ordering::Relaxed);
            let server_seq = self.tcp_conns.remove(&key).map_or(1000, |st| st.server_seq);
            let client_seq = tcp.sequence_number().wrapping_add(1);
            return self.build_tcp(TcpPacketSpec {
                src: SocketAddr::new(dst_ip, dst_port),
                dst: SocketAddr::new(src_ip, src_port),
                seq: server_seq,
                ack: Some(client_seq),
                syn: false,
                fin: true,
                psh: false,
                payload: &[],
            });
        }

        if tcp.rst() {
            self.tcp_conns.remove(&key);
            return None;
        }

        let payload = tcp.payload();
        if payload.is_empty() {
            return None;
        }

        self.stats
            .tcp_bytes_echoed
            .fetch_add(payload.len() as u64, Ordering::Relaxed);
        let (server_seq, client_seq) = if let Some(st) = self.tcp_conns.get_mut(&key) {
            let s = st.server_seq;
            st.client_seq = tcp.sequence_number().wrapping_add(payload.len() as u32);
            st.server_seq = s.wrapping_add(payload.len() as u32);
            (s, st.client_seq)
        } else {
            (
                1000,
                tcp.sequence_number().wrapping_add(payload.len() as u32),
            )
        };

        self.build_tcp(TcpPacketSpec {
            src: SocketAddr::new(dst_ip, dst_port),
            dst: SocketAddr::new(src_ip, src_port),
            seq: server_seq,
            ack: Some(client_seq),
            syn: false,
            fin: false,
            psh: true,
            payload,
        })
    }

    fn process_udp_packet(
        &self,
        src_ip: IpAddr,
        dst_ip: IpAddr,
        udp: &etherparse::UdpSlice<'_>,
        controls: &MockPeerControls,
    ) -> Option<Vec<u8>> {
        let src_port = udp.source_port();
        let dst_port = udp.destination_port();

        if dst_port == 53 {
            if controls.drop_dns.load(Ordering::Relaxed) {
                return None;
            }
            self.stats
                .dns_queries_answered
                .fetch_add(1, Ordering::Relaxed);
            let resp = self.handle_dns_query(udp.payload())?;
            self.build_udp(dst_ip, src_ip, dst_port, src_port, &resp)
        } else {
            self.stats.udp_echo_packets.fetch_add(1, Ordering::Relaxed);
            self.build_udp(dst_ip, src_ip, dst_port, src_port, udp.payload())
        }
    }

    fn handle_dns_query(&self, query: &[u8]) -> Option<Vec<u8>> {
        if query.len() < 12 {
            return None;
        }
        let tx_id = &query[0..2];
        let mut pos = 12;
        while pos < query.len() && query[pos] != 0 {
            pos += (query[pos] as usize) + 1;
        }
        pos += 1; // null label
        if pos + 4 > query.len() {
            return None;
        }

        let qtype = u16::from_be_bytes([query[pos], query[pos + 1]]);
        let question_section = &query[12..pos + 4];

        let mut resp = Vec::with_capacity(64);
        resp.extend_from_slice(tx_id);
        resp.extend_from_slice(&0x8180u16.to_be_bytes()); // Standard response, No error, Recursion desired/available
        resp.extend_from_slice(&1u16.to_be_bytes()); // QDCOUNT: 1
        resp.extend_from_slice(&1u16.to_be_bytes()); // ANCOUNT: 1
        resp.extend_from_slice(&0u16.to_be_bytes()); // NSCOUNT: 0
        resp.extend_from_slice(&0u16.to_be_bytes()); // ARCOUNT: 0
        resp.extend_from_slice(question_section);

        // Answer Record
        resp.extend_from_slice(&[0xc0, 0x0c]); // Pointer to QNAME
        resp.extend_from_slice(&qtype.to_be_bytes()); // Type
        resp.extend_from_slice(&1u16.to_be_bytes()); // Class: IN
        resp.extend_from_slice(&60u32.to_be_bytes()); // TTL: 60s

        if qtype == 28 {
            // AAAA (IPv6)
            resp.extend_from_slice(&16u16.to_be_bytes());
            resp.extend_from_slice(&self.mock_ipv6.octets());
        } else {
            // A (IPv4) default
            resp.extend_from_slice(&4u16.to_be_bytes());
            resp.extend_from_slice(&self.mock_ipv4.octets());
        }

        Some(resp)
    }

    fn build_tcp(&self, spec: TcpPacketSpec<'_>) -> Option<Vec<u8>> {
        let mut buf = Vec::new();
        // Both builders produce the same `PacketBuilderStep<TcpHeader>`, so
        // the IP version only selects the step; flags apply once below.
        let mut b = match (spec.src, spec.dst) {
            (SocketAddr::V4(s), SocketAddr::V4(d)) => PacketBuilder::ipv4(
                s.ip().octets(),
                d.ip().octets(),
                64,
            )
            .tcp(s.port(), d.port(), spec.seq, 65535),
            (SocketAddr::V6(s), SocketAddr::V6(d)) => PacketBuilder::ipv6(
                s.ip().octets(),
                d.ip().octets(),
                64,
            )
            .tcp(s.port(), d.port(), spec.seq, 65535),
            _ => return None,
        };
        if spec.syn {
            b = b.syn();
        }
        if let Some(ack) = spec.ack {
            b = b.ack(ack);
        }
        if spec.fin {
            b = b.fin();
        }
        if spec.psh {
            b = b.psh();
        }
        buf.reserve(b.size(spec.payload.len()));
        b.write(&mut buf, spec.payload).ok()?;
        Some(buf)
    }

    fn build_udp(
        &self,
        src_ip: IpAddr,
        dst_ip: IpAddr,
        src_port: u16,
        dst_port: u16,
        payload: &[u8],
    ) -> Option<Vec<u8>> {
        let mut buf = Vec::new();
        match (src_ip, dst_ip) {
            (IpAddr::V4(s), IpAddr::V4(d)) => {
                let b = PacketBuilder::ipv4(s.octets(), d.octets(), 64).udp(src_port, dst_port);
                buf.reserve(b.size(payload.len()));
                b.write(&mut buf, payload).ok()?;
            }
            (IpAddr::V6(s), IpAddr::V6(d)) => {
                let b = PacketBuilder::ipv6(s.octets(), d.octets(), 64).udp(src_port, dst_port);
                buf.reserve(b.size(payload.len()));
                b.write(&mut buf, payload).ok()?;
            }
            _ => return None,
        }
        Some(buf)
    }
}
