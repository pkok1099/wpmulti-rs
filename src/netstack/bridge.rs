//! Virtual network bridge connecting gotatun and smoltcp in userspace.
//!
//! Provides [`VirtualTunBridge`] implementing [`smoltcp::phy::Device`],
//! [`BridgeIpSend`] implementing [`gotatun::tun::IpSend`], and
//! [`BridgeIpRecv`] implementing [`gotatun::tun::IpRecv`].

use std::io;
use std::sync::Arc;
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

        let bridge = Self {
            mtu,
            rx_receiver,
            tx_sender,
            notify: Arc::clone(&notify),
            packet_pool,
        };

        let ip_send = BridgeIpSend {
            rx_sender,
            notify: Arc::clone(&notify),
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
            return None;
        }
        match self.rx_receiver.try_recv() {
            Ok(packet) => {
                let rx = VirtualTunRxToken { packet };
                let tx = VirtualTunTxToken {
                    tx_sender: &self.tx_sender,
                    packet_pool: self.packet_pool.clone(),
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
        if self.tx_sender.try_send(packet).is_err() {
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
        self.rx_sender.send(packet).await.map_err(|_| {
            io::Error::new(
                io::ErrorKind::BrokenPipe,
                "VirtualTunBridge netstack rx channel closed",
            )
        })?;
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
