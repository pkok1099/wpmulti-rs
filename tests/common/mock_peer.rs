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
    #[allow(dead_code)]
    peer_pub: [u8; 32],
    #[allow(dead_code)]
    peer_idx: u32,
    #[allow(dead_code)]
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

async fn run_mock_peer_loop(
    socket: UdpSocket,
    server_private: x25519::StaticSecret,
    server_public: x25519::PublicKey,
    preshared_key: Option<[u8; 32]>,
    stats: Arc<MockPeerStats>,
    controls: Arc<MockPeerControls>,
    mut shutdown_rx: watch::Receiver<bool>,
) {
    let index_table = IndexTable::from_os_rng();
    let rate_limiter = Arc::new(RateLimiter::new(&server_public, 1000));
    let sessions: Arc<RwLock<HashMap<u32, Arc<Mutex<PeerSession>>>>> =
        Arc::new(RwLock::new(HashMap::new()));
    let ip_engine = Arc::new(Mutex::new(MockIpEngine::new(
        Ipv4Addr::new(10, 0, 0, 1),
        "2606:4700:4700::1111".parse().unwrap(),
        Arc::clone(&stats),
    )));

    let mut buf = vec![0u8; 65536];

    loop {
        tokio::select! {
            _ = shutdown_rx.changed() => {
                if *shutdown_rx.borrow() {
                    break;
                }
            }
            res = socket.recv_from(&mut buf) => {
                let (len, src_addr) = match res {
                    Ok(pair) => pair,
                    Err(e) => {
                        tracing::warn!("Mock peer UDP recv error: {e}");
                        continue;
                    }
                };

                if len < 4 {
                    continue;
                }
                let packet_type = buf[0];

                match packet_type {
                    // Type 1: WgHandshakeInit (148 bytes)
                    1 if len == 148 => {
                        stats.handshakes_received.fetch_add(1, Ordering::Relaxed);
                        if controls.drop_handshakes.load(Ordering::Relaxed) {
                            continue;
                        }

                        let raw_packet = Packet::copy_from(&buf[..len]);
                        let init_kind = match raw_packet.try_into_wg() {
                            Ok(k) => k,
                            Err(e) => {
                                tracing::debug!("Failed to convert packet to WgKind: {e}");
                                continue;
                            }
                        };

                        let init_packet = match init_kind {
                            WgKind::HandshakeInit(p) => p,
                            _ => continue,
                        };

                        let hh = match parse_handshake_anon(&server_private, &server_public, &init_packet) {
                            Ok(hh) => hh,
                            Err(e) => {
                                tracing::debug!("Failed to parse handshake anon: {e:?}");
                                continue;
                            }
                        };

                        let peer_pub = x25519::PublicKey::from(hh.peer_static_public);
                        let mut tunn = Tunn::new(
                            server_private.clone(),
                            peer_pub,
                            preshared_key,
                            None,
                            index_table.clone(),
                            rate_limiter.clone(),
                        );

                        if let TunnResult::WriteToNetwork(WgKind::HandshakeResp(resp)) =
                            tunn.handle_incoming_packet(WgKind::HandshakeInit(init_packet))
                        {
                            let local_idx = resp.sender_idx.get();
                            let resp_bytes = (*resp).as_bytes();
                            if socket.send_to(resp_bytes, src_addr).await.is_ok() {
                                stats.handshakes_completed.fetch_add(1, Ordering::Relaxed);
                                let mut w = sessions.write().await;
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

                    // Type 4: WgData (>= 32 bytes)
                    4 if len >= 32 => {
                        stats.data_packets_received.fetch_add(1, Ordering::Relaxed);
                        if controls.drop_data.load(Ordering::Relaxed) {
                            continue;
                        }

                        let receiver_idx = u32::from_le_bytes(buf[4..8].try_into().unwrap());
                        let session_arc = {
                            let r = sessions.read().await;
                            r.get(&receiver_idx).cloned()
                        };

                        let Some(session_arc) = session_arc else {
                            tracing::trace!("Session not found for receiver_idx {receiver_idx}");
                            continue;
                        };

                        let mut session = session_arc.lock().await;
                        session.peer_addr = src_addr;
                        session.last_seen = Instant::now();

                        let raw_packet = Packet::copy_from(&buf[..len]);
                        let data_kind = match raw_packet.try_into_wg() {
                            Ok(k) => k,
                            Err(e) => {
                                tracing::trace!("Failed to parse data packet: {e}");
                                continue;
                            }
                        };

                        let data_packet = match data_kind {
                            WgKind::Data(d) => d,
                            _ => continue,
                        };

                        match session.tunn.handle_incoming_packet(WgKind::Data(data_packet)) {
                            TunnResult::WriteToTunnel(ip_packet) => {
                                if ip_packet.is_empty() {
                                    stats.keepalives_received.fetch_add(1, Ordering::Relaxed);
                                    continue;
                                }

                                let reply_bytes = {
                                    let mut engine = ip_engine.lock().await;
                                    engine.process_packet(ip_packet.as_ref(), &controls)
                                };

                                if let Some(reply) = reply_bytes {
                                    let pkt = Packet::copy_from(reply.as_slice());
                                    if let Ok(encap) = session.tunn.encapsulate_with_session(pkt) {
                                        let encap_bytes = encap.into_bytes();
                                        let _ = socket.send_to(encap_bytes.as_ref(), session.peer_addr).await;
                                    }
                                }
                            }
                            TunnResult::WriteToNetwork(pkt) => {
                                let network_bytes = match pkt {
                                    WgKind::HandshakeInit(p) => (*p).as_bytes().to_vec(),
                                    WgKind::HandshakeResp(p) => (*p).as_bytes().to_vec(),
                                    WgKind::CookieReply(p) => (*p).as_bytes().to_vec(),
                                    WgKind::Data(p) => p.into_bytes().as_ref().to_vec(),
                                };
                                let _ = socket.send_to(&network_bytes, session.peer_addr).await;
                            }
                            _ => {}
                        }
                    }

                    _ => {}
                }
            }
        }
    }
}

struct TcpConnState {
    server_seq: u32,
    #[allow(dead_code)]
    client_seq: u32,
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
        let sliced = SlicedPacket::from_ip(&ip_bytes[..true_len]).ok()?;

        let (src_ip, dst_ip) = match sliced.net? {
            etherparse::NetSlice::Ipv4(v4) => {
                self.stats.ipv4_packets.fetch_add(1, Ordering::Relaxed);
                (
                    IpAddr::V4(v4.header().source_addr()),
                    IpAddr::V4(v4.header().destination_addr()),
                )
            }
            etherparse::NetSlice::Ipv6(v6) => {
                self.stats.ipv6_packets.fetch_add(1, Ordering::Relaxed);
                (
                    IpAddr::V6(v6.header().source_addr()),
                    IpAddr::V6(v6.header().destination_addr()),
                )
            }
            _ => return None,
        };

        match sliced.transport? {
            TransportSlice::Tcp(tcp) => {
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

                    // Synthesize SYN | ACK
                    self.build_tcp(
                        dst_ip,
                        src_ip,
                        dst_port,
                        src_port,
                        server_isn,
                        client_seq,
                        true,
                        true,
                        false,
                        false,
                        &[],
                    )
                } else if tcp.fin() {
                    self.stats.tcp_closed.fetch_add(1, Ordering::Relaxed);
                    let (server_seq, client_seq) = if let Some(st) = self.tcp_conns.remove(&key) {
                        (st.server_seq, tcp.sequence_number().wrapping_add(1))
                    } else {
                        (1000, tcp.sequence_number().wrapping_add(1))
                    };
                    // Synthesize FIN | ACK
                    self.build_tcp(
                        dst_ip,
                        src_ip,
                        dst_port,
                        src_port,
                        server_seq,
                        client_seq,
                        false,
                        true,
                        true,
                        false,
                        &[],
                    )
                } else if tcp.rst() {
                    self.tcp_conns.remove(&key);
                    None
                } else if !tcp.payload().is_empty() {
                    let payload = tcp.payload();
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

                    // TCP Echo: PSH | ACK
                    self.build_tcp(
                        dst_ip, src_ip, dst_port, src_port, server_seq, client_seq, false, true,
                        false, true, payload,
                    )
                } else {
                    None // Pure ACK
                }
            }

            TransportSlice::Udp(udp) => {
                let src_port = udp.source_port();
                let dst_port = udp.destination_port();

                if dst_port == 53 {
                    // RFC 1035 DNS Query
                    if controls.drop_dns.load(Ordering::Relaxed) {
                        return None;
                    }
                    self.stats
                        .dns_queries_answered
                        .fetch_add(1, Ordering::Relaxed);
                    let resp = self.handle_dns_query(udp.payload())?;
                    self.build_udp(dst_ip, src_ip, dst_port, src_port, &resp)
                } else {
                    // UDP Echo
                    self.stats.udp_echo_packets.fetch_add(1, Ordering::Relaxed);
                    self.build_udp(dst_ip, src_ip, dst_port, src_port, udp.payload())
                }
            }
            _ => None,
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

    #[allow(clippy::too_many_arguments)]
    fn build_tcp(
        &self,
        src_ip: IpAddr,
        dst_ip: IpAddr,
        src_port: u16,
        dst_port: u16,
        seq: u32,
        ack: u32,
        syn: bool,
        ack_flag: bool,
        fin: bool,
        psh: bool,
        payload: &[u8],
    ) -> Option<Vec<u8>> {
        let mut buf = Vec::new();
        match (src_ip, dst_ip) {
            (IpAddr::V4(s), IpAddr::V4(d)) => {
                let mut b = PacketBuilder::ipv4(s.octets(), d.octets(), 64)
                    .tcp(src_port, dst_port, seq, 65535);
                if syn {
                    b = b.syn();
                }
                if ack_flag {
                    b = b.ack(ack);
                }
                if fin {
                    b = b.fin();
                }
                if psh {
                    b = b.psh();
                }
                buf.reserve(b.size(payload.len()));
                b.write(&mut buf, payload).ok()?;
            }
            (IpAddr::V6(s), IpAddr::V6(d)) => {
                let mut b = PacketBuilder::ipv6(s.octets(), d.octets(), 64)
                    .tcp(src_port, dst_port, seq, 65535);
                if syn {
                    b = b.syn();
                }
                if ack_flag {
                    b = b.ack(ack);
                }
                if fin {
                    b = b.fin();
                }
                if psh {
                    b = b.psh();
                }
                buf.reserve(b.size(payload.len()));
                b.write(&mut buf, payload).ok()?;
            }
            _ => return None,
        }
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
