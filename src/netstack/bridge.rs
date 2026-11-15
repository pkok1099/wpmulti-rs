//! Virtual network bridge connecting gotatun and smoltcp in userspace.
//!
//! Provides [`VirtualTunBridge`] implementing [`smoltcp::phy::Device`],
//! [`BridgeIpSend`] implementing [`gotatun::tun::IpSend`], and
//! [`BridgeIpRecv`] implementing [`gotatun::tun::IpRecv`].

use parking_lot::Mutex;
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

/// Userspace virtual network device implementing [`smoltcp::phy::Device`].
pub struct VirtualTunBridge {
    mtu: u16,
    rx_receiver: mpsc::Receiver<Packet<Ip>>,
    tx_sender: mpsc::Sender<Vec<u8>>,
    notify: Arc<Notify>,
    buf_pool: Arc<Mutex<Vec<Vec<u8>>>>,
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
    tx_receiver: mpsc::Receiver<Vec<u8>>,
    mtu: MtuWatcher,
    notify: Arc<Notify>,
    buf_pool: Arc<Mutex<Vec<Vec<u8>>>>,
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
        let (rx_sender, rx_receiver) = mpsc::channel(channel_capacity);
        let (tx_sender, tx_receiver) = mpsc::channel(channel_capacity);
        let notify = Arc::new(Notify::new());
        let buf_pool = Arc::new(Mutex::new(Vec::with_capacity(64)));

        let bridge = Self {
            mtu,
            rx_receiver,
            tx_sender,
            notify: Arc::clone(&notify),
            buf_pool: Arc::clone(&buf_pool),
        };

        let ip_send = BridgeIpSend {
            rx_sender,
            notify: Arc::clone(&notify),
        };

        let ip_recv = BridgeIpRecv {
            tx_receiver,
            mtu: MtuWatcher::new(mtu),
            notify,
            buf_pool,
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
        match self.rx_receiver.try_recv() {
            Ok(packet) => {
                let rx = VirtualTunRxToken { packet };
                let tx = VirtualTunTxToken {
                    tx_sender: &self.tx_sender,
                    buf_pool: &self.buf_pool,
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
        if self.tx_sender.capacity() > 0 {
            Some(VirtualTunTxToken {
                tx_sender: &self.tx_sender,
                buf_pool: &self.buf_pool,
            })
        } else {
            // Infallible token rule in smoltcp 0.14: return None to retain socket TX queue
            None
        }
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
#[derive(Debug)]
pub struct VirtualTunTxToken<'a> {
    tx_sender: &'a mpsc::Sender<Vec<u8>>,
    buf_pool: &'a Mutex<Vec<Vec<u8>>>,
}

impl TxToken for VirtualTunTxToken<'_> {
    fn consume<R, F>(self, len: usize, f: F) -> R
    where
        F: FnOnce(&mut [u8]) -> R,
    {
        let mut buffer = self
            .buf_pool
            .lock()
            .pop()
            .unwrap_or_else(|| Vec::with_capacity(len.max(1500)));
        buffer.resize(len, 0);
        let result = f(&mut buffer);
        if let Err(e) = self.tx_sender.try_send(buffer) {
            tracing::warn!("VirtualTunBridge TX channel full or closed: {e}");
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
        pool: &mut PacketBufPool,
    ) -> io::Result<impl Iterator<Item = Packet<Ip>> + Send + 'a> {
        let first = self.tx_receiver.recv().await.ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "VirtualTunBridge netstack tx channel closed",
            )
        })?;

        let mut packets = Vec::with_capacity(MAX_DRAIN_BATCH_SIZE);
        packets.push(Self::to_packet_and_recycle(first, pool, &self.buf_pool)?);

        // Opportunistic batch draining up to MAX_DRAIN_BATCH_SIZE
        while packets.len() < MAX_DRAIN_BATCH_SIZE {
            match self.tx_receiver.try_recv() {
                Ok(next) => packets.push(Self::to_packet_and_recycle(next, pool, &self.buf_pool)?),
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

impl BridgeIpRecv {
    /// Convert raw bytes from smoltcp into a pooled [`Packet<Ip>`].
    #[inline]
    pub fn to_packet_pub(raw: &[u8], pool: &PacketBufPool) -> io::Result<Packet<Ip>> {
        Self::to_packet(raw, pool)
    }

    #[inline]
    fn to_packet_and_recycle(
        mut raw: Vec<u8>,
        pool: &PacketBufPool,
        buf_pool: &Arc<Mutex<Vec<Vec<u8>>>>,
    ) -> io::Result<Packet<Ip>> {
        let mut pkt = pool.get();
        pkt.truncate(raw.len());
        pkt.copy_from_slice(&raw);
        raw.clear();
        let mut p = buf_pool.lock();
        if p.len() < 64 {
            p.push(raw);
        }
        drop(p);
        pkt.try_into_ip().map_err(|e| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("Malformed IP packet from smoltcp: {e}"),
            )
        })
    }

    #[inline]
    fn to_packet(raw: &[u8], pool: &PacketBufPool) -> io::Result<Packet<Ip>> {
        let mut pkt = pool.get();
        pkt.truncate(raw.len());
        pkt.copy_from_slice(raw);
        pkt.try_into_ip().map_err(|e| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("Malformed IP packet from smoltcp: {e}"),
            )
        })
    }
}
