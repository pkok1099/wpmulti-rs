//! Virtual network bridge connecting gotatun and smoltcp in userspace.
//!
//! Provides [`VirtualTunBridge`] implementing [`smoltcp::phy::Device`],
//! [`BridgeIpSend`] implementing [`gotatun::tun::IpSend`], and
//! [`BridgeIpRecv`] implementing [`gotatun::tun::IpRecv`].

use std::collections::HashMap;
use std::io;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::time::{Duration, Instant as StdInstant};

use parking_lot::Mutex;
use tokio::sync::{Notify, mpsc};

use gotatun::packet::{Ip, Packet, PacketBufPool};
use gotatun::tun::{IpRecv, IpSend, MtuWatcher};
use smoltcp::phy::{Device, DeviceCapabilities, Medium, RxToken, TxToken};
use smoltcp::time::Instant;
use zerocopy::IntoBytes;

/// Default MTU for WireGuard tunnels (IPv4 WireGuard overhead: 80 bytes; 1500 - 80 = 1420).
pub const DEFAULT_MTU: u16 = 1420;

/// Default capacity of packet channels between WireGuard and smoltcp.
pub const DEFAULT_CHANNEL_CAPACITY: usize = 1024;

/// Maximum batch size when draining outbound packets in `IpRecv::recv`.
pub const MAX_DRAIN_BATCH_SIZE: usize = 16;

/// How long an outbound SYN (source port, sequence number) is remembered
/// for retransmit detection: well past the 1 s smoltcp RTO and its first
/// backoff, short enough that a later connection reusing the port is not
/// mistaken for a retransmit of the first.
const SYN_RETRANSMIT_WINDOW: Duration = Duration::from_secs(65);

/// Cap on remembered SYNs: one entry per outbound connection attempt;
/// pruning runs only when the cap is hit, so the steady-state cost is a
/// single hash lookup per SYN.
const MAX_REMEMBERED_SYNS: usize = 4096;

/// A `BridgeIpSend::send` that waits longer than this for RX channel
/// capacity counts as a backpressure episode (M4 in the P=64 probe).
const IPSEND_WAIT_THRESHOLD_MS: u64 = 10;

/// Per-stack observation counters for the P=64 probe.
///
/// Instrumentation only — no behaviour change. Every field is an
/// atomic: the bridge runs in the reactor task while the metrics
/// endpoint reads from proxy tasks.
///
/// gotatun's handshake rate limiter deliberately has NO counter here:
/// it is a private field of gotatun's `Device` with no accessor, and
/// `verify_packet` passes data packets through untouched — it can only
/// drop or cookie-reply handshake packets, so it cannot explain
/// data-path loss (verified in gotatun 0.10.3 `noise/rate_limiter.rs`).
#[derive(Debug, Default)]
pub struct BridgeCounters {
    /// Outgoing TCP SYNs repeating a (source port, sequence number)
    /// seen within [`SYN_RETRANSMIT_WINDOW`]: smoltcp RTO retransmits
    /// of a lost or delayed SYN (M1 in the P=64 probe).
    pub syn_retransmits: AtomicU64,
    /// Episodes where `Device::receive` returned `None` because the TX
    /// channel was full — the TX-full → RX-stall coupling (M3).
    /// Counted per episode (entering the full state), not per poll.
    pub tx_full_rx_stall_episodes: AtomicU64,
    /// Outbound packets dropped in `TxToken::consume` because the TX
    /// channel was full or closed.
    pub tx_full_drops: AtomicU64,
    /// Total time `BridgeIpSend::send` spent awaiting RX channel
    /// capacity, in milliseconds (M4 backpressure).
    pub ipsend_wait_ms_total: AtomicU64,
    /// Sends that waited longer than [`IPSEND_WAIT_THRESHOLD_MS`] for
    /// RX channel capacity.
    pub ipsend_waits_over_10ms: AtomicU64,
    /// Deepest RX channel occupancy observed (packets waiting for smoltcp).
    pub rx_depth_max: AtomicUsize,
    /// Outbound SYNs seen recently, for retransmit detection.
    syn_seen: Mutex<HashMap<(u16, u32), StdInstant>>,
}

/// Point-in-time copy of [`BridgeCounters`] for tests.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct BridgeCountersSnapshot {
    pub syn_retransmits: u64,
    pub tx_full_rx_stall_episodes: u64,
    pub tx_full_drops: u64,
    pub ipsend_wait_ms_total: u64,
    pub ipsend_waits_over_10ms: u64,
    pub rx_depth_max: usize,
}

impl BridgeCounters {
    /// Read all counters at once.
    pub fn snapshot(&self) -> BridgeCountersSnapshot {
        BridgeCountersSnapshot {
            syn_retransmits: self.syn_retransmits.load(Ordering::Relaxed),
            tx_full_rx_stall_episodes: self.tx_full_rx_stall_episodes.load(Ordering::Relaxed),
            tx_full_drops: self.tx_full_drops.load(Ordering::Relaxed),
            ipsend_wait_ms_total: self.ipsend_wait_ms_total.load(Ordering::Relaxed),
            ipsend_waits_over_10ms: self.ipsend_waits_over_10ms.load(Ordering::Relaxed),
            rx_depth_max: self.rx_depth_max.load(Ordering::Relaxed),
        }
    }

    /// Inspect one outgoing IP packet (smoltcp → WireGuard) for a
    /// retransmitted TCP SYN. Only pure SYNs (flags exactly `0x02`)
    /// are tracked: a retransmit repeats the source port and sequence
    /// number, so a SYN matching a recent entry is an RTO firing, not
    /// a new dial. IPv4 and IPv6 are both parsed; anything else is
    /// ignored. The parse is a few bounds-checked reads — no work is
    /// done for non-SYN packets beyond the flag check.
    pub fn note_outgoing_packet(&self, bytes: &[u8]) {
        let Some((src_port, seq)) = parse_tcp_syn(bytes) else {
            return;
        };
        let now = StdInstant::now();
        let mut seen = self.syn_seen.lock();
        if let Some(first) = seen.get(&(src_port, seq))
            && first.elapsed() < SYN_RETRANSMIT_WINDOW
        {
            self.syn_retransmits.fetch_add(1, Ordering::Relaxed);
            return;
        }
        if seen.len() >= MAX_REMEMBERED_SYNS {
            seen.retain(|_, first| first.elapsed() < SYN_RETRANSMIT_WINDOW);
        }
        seen.insert((src_port, seq), now);
    }
}

fn be_u16(bytes: &[u8], at: usize) -> Option<u16> {
    Some(u16::from_be_bytes([*bytes.get(at)?, *bytes.get(at + 1)?]))
}

fn be_u32(bytes: &[u8], at: usize) -> Option<u32> {
    Some(u32::from_be_bytes([
        *bytes.get(at)?,
        *bytes.get(at + 1)?,
        *bytes.get(at + 2)?,
        *bytes.get(at + 3)?,
    ]))
}

/// Parse an outgoing IP packet, returning the (source port, sequence
/// number) when it is a pure TCP SYN (flags exactly `0x02`).
fn parse_tcp_syn(bytes: &[u8]) -> Option<(u16, u32)> {
    let version = bytes.first().copied()? >> 4;
    let tcp_start = match version {
        6 => {
            if bytes.len() < 60 || bytes.get(6).copied()? != 6 {
                return None;
            }
            40
        }
        4 => {
            let ihl = usize::from(bytes.first().copied()? & 0x0f) * 4;
            if bytes.len() < ihl + 20 || bytes.get(9).copied()? != 6 {
                return None;
            }
            ihl
        }
        _ => return None,
    };
    if bytes.get(tcp_start + 13).copied()? != 0x02 {
        return None;
    }
    Some((be_u16(bytes, tcp_start)?, be_u32(bytes, tcp_start + 4)?))
}

/// Number of packet buffers retained by the bridge's own [`PacketBufPool`].
///
/// The pool only bounds *retained* buffers; [`PacketBufPool::get`] allocates a
/// fresh buffer when the pool is empty, so this never blocks the TX path.
/// Kept small (16 x 4 KiB = 64 KiB per stack): a retained buffer only
/// avoids one allocation on the next packet, while every active and
/// suspended tunnel holds its own pool for the daemon's lifetime.
const BRIDGE_PACKET_POOL_CAPACITY: usize = 16;

/// Userspace virtual network device implementing [`smoltcp::phy::Device`].
pub struct VirtualTunBridge {
    mtu: u16,
    rx_receiver: mpsc::Receiver<Packet<Ip>>,
    tx_sender: mpsc::Sender<Packet<[u8]>>,
    notify: Arc<Notify>,
    packet_pool: PacketBufPool,
    counters: Arc<BridgeCounters>,
    /// Whether the last `receive` hit the TX-full gate: the stall
    /// episode is counted on entry, not on every poll while full.
    tx_full_active: bool,
}

impl std::fmt::Debug for VirtualTunBridge {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("VirtualTunBridge")
            .field("mtu", &self.mtu)
            .finish_non_exhaustive()
    }
}

/// Inbound handle passed to `gotatun` (`ip_tx`) implementing [`gotatun::tun::IpSend`].
#[derive(Clone)]
pub struct BridgeIpSend {
    rx_sender: mpsc::Sender<Packet<Ip>>,
    notify: Arc<Notify>,
    counters: Arc<BridgeCounters>,
    /// Bound of the RX channel, for depth accounting in [`IpSend::send`].
    rx_capacity: usize,
}

impl std::fmt::Debug for BridgeIpSend {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BridgeIpSend").finish_non_exhaustive()
    }
}

/// Outbound handle passed to `gotatun` (`ip_rx`) implementing [`gotatun::tun::IpRecv`].
pub struct BridgeIpRecv {
    tx_receiver: mpsc::Receiver<Packet<[u8]>>,
    mtu: MtuWatcher,
    notify: Arc<Notify>,
}

impl std::fmt::Debug for BridgeIpRecv {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BridgeIpRecv").finish_non_exhaustive()
    }
}

impl VirtualTunBridge {
    /// Create a new virtual bridge pair.
    ///
    /// Returns:
    /// - `VirtualTunBridge`: for the smoltcp `Interface` / event loop.
    /// - `BridgeIpSend`: for gotatun WireGuard incoming packet handling (`ip_tx`).
    /// - `BridgeIpRecv`: for gotatun WireGuard outgoing packet handling (`ip_rx`).
    pub fn new(mtu: u16, channel_capacity: usize) -> (Self, BridgeIpSend, BridgeIpRecv) {
        let cap = channel_capacity.max(1);
        let (rx_sender, rx_receiver) = mpsc::channel(cap);
        let (tx_sender, tx_receiver) = mpsc::channel(cap);
        let notify = Arc::new(Notify::new());
        // The bridge owns its own pool: gotatun's pool is only handed to
        // `IpRecv::recv`, so the TX token cannot draw from it. Buffers drawn
        // here return to this pool on drop via `Packet`'s return-to-pool hook.
        let packet_pool = PacketBufPool::new(BRIDGE_PACKET_POOL_CAPACITY);
        let counters = Arc::new(BridgeCounters::default());

        let bridge = Self {
            mtu,
            rx_receiver,
            tx_sender,
            notify: Arc::clone(&notify),
            packet_pool,
            counters: Arc::clone(&counters),
            tx_full_active: false,
        };

        let ip_send = BridgeIpSend {
            rx_sender,
            notify: Arc::clone(&notify),
            counters,
            rx_capacity: cap,
        };

        let ip_recv = BridgeIpRecv {
            tx_receiver,
            mtu: MtuWatcher::new(mtu),
            notify,
        };

        (bridge, ip_send, ip_recv)
    }

    /// Access the event loop wakeup notification handle.
    pub fn notify(&self) -> Arc<Notify> {
        Arc::clone(&self.notify)
    }

    /// Alias for accessing notification handle.
    pub fn notify_handle(&self) -> Arc<Notify> {
        self.notify()
    }

    /// Get the configured MTU.
    pub const fn mtu(&self) -> u16 {
        self.mtu
    }

    /// Shared probe counters for this stack's bridge.
    pub fn counters(&self) -> Arc<BridgeCounters> {
        Arc::clone(&self.counters)
    }
}

// ---------------------------------------------------------------------------
// smoltcp::phy::Device Implementation
// ---------------------------------------------------------------------------

impl Device for VirtualTunBridge {
    type RxToken<'a>
        = VirtualTunRxToken
    where
        Self: 'a;
    type TxToken<'a>
        = VirtualTunTxToken<'a>
    where
        Self: 'a;

    fn capabilities(&self) -> DeviceCapabilities {
        let mut caps = DeviceCapabilities::default();
        caps.medium = Medium::Ip;
        caps.max_transmission_unit = self.mtu as usize;
        caps
    }

    fn receive(&mut self, _timestamp: Instant) -> Option<(Self::RxToken<'_>, Self::TxToken<'_>)> {
        if self.tx_sender.capacity() == 0 {
            // A full TX channel blocks RX processing entirely (smoltcp
            // gets no RxToken while it cannot also get a TxToken), so
            // SYN-ACKs and DNS replies stall with it. Counted per
            // episode, not per poll.
            if !self.tx_full_active {
                self.tx_full_active = true;
                self.counters
                    .tx_full_rx_stall_episodes
                    .fetch_add(1, Ordering::Relaxed);
            }
            return None;
        }
        self.tx_full_active = false;
        match self.rx_receiver.try_recv() {
            Ok(packet) => {
                let rx = VirtualTunRxToken { packet };
                let tx = VirtualTunTxToken {
                    tx_sender: &self.tx_sender,
                    packet_pool: self.packet_pool.clone(),
                    counters: Arc::clone(&self.counters),
                };
                Some((rx, tx))
            }
            Err(mpsc::error::TryRecvError::Empty) => None,
            Err(mpsc::error::TryRecvError::Disconnected) => {
                tracing::debug!("VirtualTunBridge rx_receiver disconnected");
                None
            }
        }
    }

    fn transmit(&mut self, _timestamp: Instant) -> Option<Self::TxToken<'_>> {
        (self.tx_sender.capacity() > 0).then(|| VirtualTunTxToken {
            tx_sender: &self.tx_sender,
            packet_pool: self.packet_pool.clone(),
            counters: Arc::clone(&self.counters),
        })
    }
}

/// Token representing an incoming IP packet from WireGuard to smoltcp.
pub struct VirtualTunRxToken {
    packet: Packet<Ip>,
}

impl std::fmt::Debug for VirtualTunRxToken {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("VirtualTunRxToken").finish_non_exhaustive()
    }
}

impl RxToken for VirtualTunRxToken {
    fn consume<R, F>(self, f: F) -> R
    where
        F: FnOnce(&[u8]) -> R,
    {
        // Zero-copy: self.packet implements Deref<Target = Ip>.
        // Ip implements IntoBytes via zerocopy, providing &[u8] directly.
        f((*self.packet).as_bytes())
    }
}

/// Token representing an outgoing transmission slot from smoltcp to WireGuard.
///
/// Holds a clone of the bridge's [`PacketBufPool`]; the buffer is drawn from
/// the pool only when smoltcp actually calls `consume`, so a token that is
/// dropped without being consumed costs nothing.
pub struct VirtualTunTxToken<'a> {
    tx_sender: &'a mpsc::Sender<Packet<[u8]>>,
    packet_pool: PacketBufPool,
    counters: Arc<BridgeCounters>,
}

impl std::fmt::Debug for VirtualTunTxToken<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("VirtualTunTxToken").finish_non_exhaustive()
    }
}

impl TxToken for VirtualTunTxToken<'_> {
    fn consume<R, F>(self, len: usize, f: F) -> R
    where
        F: FnOnce(&mut [u8]) -> R,
    {
        // Draw a pooled buffer and hand it straight to smoltcp: no zero-fill
        // (smoltcp overwrites all `len` bytes) and no copy afterwards — the
        // same `Packet` travels on to gotatun via `BridgeIpRecv`.
        // `resize` only zero-fills when the packet exceeds the pool buffer
        // (MTU > 4096): then the buffer detaches from the pool allocation and
        // the pool keeps recycling its own buffer, as gotatun's pool does.
        let mut packet = self.packet_pool.get();
        packet.buf_mut().resize(len, 0);
        let result = f(packet.buf_mut());
        // The filled buffer is the outgoing IP packet: check it for a
        // retransmitted SYN before it leaves for WireGuard.
        self.counters.note_outgoing_packet(packet.buf_mut());
        if self.tx_sender.try_send(packet).is_err() {
            self.counters.tx_full_drops.fetch_add(1, Ordering::Relaxed);
            tracing::warn!("VirtualTunBridge TX channel full or closed; dropping outbound packet");
        }
        result
    }
}

impl BridgeIpSend {
    /// Clone the notification handle.
    pub fn notify_clone(&self) -> Arc<Notify> {
        Arc::clone(&self.notify)
    }
}

// ---------------------------------------------------------------------------
// gotatun::tun::IpSend Implementation (WireGuard -> smoltcp)
// ---------------------------------------------------------------------------

impl IpSend for BridgeIpSend {
    async fn send(&mut self, packet: Packet<Ip>) -> io::Result<()> {
        // Time the wait for RX channel capacity: when the channel is
        // full this await stalls gotatun's reader, which stops reading
        // its UDP socket and lets the kernel drop WireGuard packets
        // silently (M4 backpressure in the P=64 probe).
        let start = StdInstant::now();
        let result = self.rx_sender.send(packet).await;
        let waited_ms = u64::try_from(start.elapsed().as_millis()).unwrap_or(u64::MAX);
        if waited_ms > 0 {
            self.counters
                .ipsend_wait_ms_total
                .fetch_add(waited_ms, Ordering::Relaxed);
            if waited_ms > IPSEND_WAIT_THRESHOLD_MS {
                self.counters
                    .ipsend_waits_over_10ms
                    .fetch_add(1, Ordering::Relaxed);
            }
        }
        result.map_err(|_| {
            io::Error::new(
                io::ErrorKind::BrokenPipe,
                "VirtualTunBridge netstack rx channel closed",
            )
        })?;
        let depth = self.rx_capacity.saturating_sub(self.rx_sender.capacity());
        if depth > self.counters.rx_depth_max.load(Ordering::Relaxed) {
            self.counters
                .rx_depth_max
                .fetch_max(depth, Ordering::Relaxed);
        }
        self.notify.notify_one();
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// gotatun::tun::IpRecv Implementation (smoltcp -> WireGuard)
// ---------------------------------------------------------------------------

impl IpRecv for BridgeIpRecv {
    async fn recv<'a>(
        &'a mut self,
        _pool: &mut PacketBufPool,
    ) -> io::Result<impl Iterator<Item = Packet<Ip>> + Send + 'a> {
        // The channel already carries pooled `Packet<[u8]>` from the bridge,
        // so no copy is needed here: `try_into_ip` validates the header and
        // reinterprets the same buffer. Gotatun's `pool` is unused by this
        // implementation; the bridge recycles its own pool on packet drop.
        let mut packets = Vec::with_capacity(MAX_DRAIN_BATCH_SIZE);
        loop {
            let first = self.tx_receiver.recv().await.ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "VirtualTunBridge netstack tx channel closed",
                )
            })?;
            match first.try_into_ip() {
                Ok(pkt) => {
                    packets.push(pkt);
                    break;
                }
                Err(e) => {
                    tracing::warn!("Dropping malformed outbound IP packet from smoltcp: {e}");
                }
            }
        }

        // Opportunistic batch draining up to MAX_DRAIN_BATCH_SIZE
        while packets.len() < MAX_DRAIN_BATCH_SIZE {
            match self.tx_receiver.try_recv() {
                Ok(next) => match next.try_into_ip() {
                    Ok(pkt) => packets.push(pkt),
                    Err(e) => {
                        tracing::warn!("Dropping malformed outbound IP packet from smoltcp: {e}");
                    }
                },
                Err(_) => break,
            }
        }

        // Signal smoltcp event loop that space is freed in TX queue
        self.notify.notify_one();

        Ok(packets.into_iter())
    }

    fn mtu(&self) -> MtuWatcher {
        self.mtu.clone()
    }
}
