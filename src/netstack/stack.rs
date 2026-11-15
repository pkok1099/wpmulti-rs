//! Virtual smoltcp network stack and Tokio reactor event loop.
//!
//! Provides [`VirtualNetworkStack`], managing the userspace Layer 3 smoltcp interface,
//! IP routing table, socket set, and asynchronous reactor background task.

use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::atomic::{AtomicU16, Ordering};
use std::sync::Arc;
use std::time::Duration as StdDuration;

use parking_lot::Mutex;
use smoltcp::iface::{Config, Interface, SocketSet};
use smoltcp::socket::tcp::{self, Socket as TcpSocket, SocketBuffer as TcpSocketBuffer};
use smoltcp::socket::udp::{PacketBuffer as UdpPacketBuffer, PacketMetadata as UdpPacketMetadata, Socket as UdpSocket};
use smoltcp::time::Instant as SmolInstant;
use smoltcp::wire::{HardwareAddress, IpCidr, IpEndpoint, Ipv4Address, Ipv4Cidr, Ipv6Address, Ipv6Cidr};
use tokio::sync::{watch, Notify};
use tokio::task::JoinHandle;

use crate::config::WgInterfaceConfig;
use crate::netstack::bridge::VirtualTunBridge;
use crate::netstack::dns::InTunnelDnsResolver;
use crate::netstack::stream::{to_smoltcp_endpoint, VirtualTcpStream, VirtualUdpSocket};

/// Default TCP socket receive buffer size (64 KiB).
pub const TCP_RX_BUF_SIZE: usize = 65536;
/// Default TCP socket transmit buffer size (64 KiB).
pub const TCP_TX_BUF_SIZE: usize = 65536;
/// Default UDP socket packet queue capacity (16 datagrams).
pub const UDP_PACKET_QUEUE_CAPACITY: usize = 16;
/// Default UDP payload buffer size (64 KiB).
pub const UDP_PAYLOAD_BUF_SIZE: usize = 65536;
/// Default connection timeout.
pub const DEFAULT_CONNECT_TIMEOUT: StdDuration = StdDuration::from_secs(15);

/// Shared inner network stack state protected by a fast synchronous mutex.
pub struct StackInner {
    pub iface: Interface,
    pub sockets: SocketSet<'static>,
}

/// Userspace virtual network stack attached to a WireGuard tunnel.
pub struct VirtualNetworkStack {
    inner: Arc<Mutex<StackInner>>,
    notify: Arc<Notify>,
    shutdown_tx: watch::Sender<bool>,
    reactor_handle: Mutex<Option<JoinHandle<()>>>,
    local_v4: Option<Ipv4Addr>,
    local_v6: Option<Ipv6Addr>,
    next_ephemeral_port: AtomicU16,
    dns_resolver: InTunnelDnsResolver,
}

impl VirtualNetworkStack {
    /// Construct a new virtual network stack from WireGuard interface configuration
    /// and a [`VirtualTunBridge`] in `DualStack` mode.
    pub async fn new(config: &WgInterfaceConfig, bridge: VirtualTunBridge) -> Result<Self, io::Error> {
        Self::new_with_mode(config, bridge, crate::config::IpMode::DualStack, false).await
    }

    /// Construct a new virtual network stack with an explicit [`IpMode`] and IPv6 DNS preference.
    pub async fn new_with_mode(
        config: &WgInterfaceConfig,
        mut bridge: VirtualTunBridge,
        ip_mode: crate::config::IpMode,
        prefer_ipv6: bool,
    ) -> Result<Self, io::Error> {
        let notify = bridge.notify_handle();

        // 1. Configure smoltcp interface with Medium::Ip
        let mut iface_config = Config::new(HardwareAddress::Ip);
        iface_config.random_seed = rand::random::<u64>();

        let mut iface = Interface::new(iface_config, &mut bridge, SmolInstant::now());

        // 2. Configure IP addresses filtered by IpMode
        let mut local_v4 = None;
        let mut local_v6 = None;

        if config.addresses.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "interface has no IP addresses configured",
            ));
        }

        iface.update_ip_addrs(|ip_addrs| {
            for net in &config.addresses {
                match net {
                    ipnetwork::IpNetwork::V4(v4) if ip_mode != crate::config::IpMode::Ipv6Only => {
                        let smol_addr = v4.ip();
                        let cidr = IpCidr::Ipv4(Ipv4Cidr::new(smol_addr, v4.prefix()));
                        if ip_addrs.push(cidr).is_err() {
                            tracing::warn!("Failed to add IPv4 address {}: interface address list full", v4);
                        } else if local_v4.is_none() {
                            local_v4 = Some(v4.ip());
                        }
                    }
                    ipnetwork::IpNetwork::V6(v6) if ip_mode != crate::config::IpMode::Ipv4Only => {
                        let smol_addr = v6.ip();
                        let cidr = IpCidr::Ipv6(Ipv6Cidr::new(smol_addr, v6.prefix()));
                        if ip_addrs.push(cidr).is_err() {
                            tracing::warn!("Failed to add IPv6 address {}: interface address list full", v6);
                        } else if local_v6.is_none() {
                            local_v6 = Some(v6.ip());
                        }
                    }
                    _ => {}
                }
            }
        });

        if local_v4.is_none() && local_v6.is_none() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("interface has no usable IP addresses for ip_mode {:?}", ip_mode),
            ));
        }

        // 3. Configure point-to-point default routes
        if let Some(v4_ip) = local_v4 {
            let octets = v4_ip.octets();
            let gateway = if octets[3] == 1 {
                Ipv4Address::new(octets[0], octets[1], octets[2], 2)
            } else {
                Ipv4Address::new(octets[0], octets[1], octets[2], 1)
            };
            iface.routes_mut()
                .add_default_ipv4_route(gateway)
                .map_err(|e| io::Error::other(format!("add default ipv4 route failed: {:?}", e)))?;
        }

        if local_v6.is_some() {
            let gateway = Ipv6Address::new(0xfe80, 0, 0, 0, 0, 0, 0, 1);
            iface.routes_mut()
                .add_default_ipv6_route(gateway)
                .map_err(|e| io::Error::other(format!("add default ipv6 route failed: {:?}", e)))?;
        }

        // 4. Initialize SocketSet with owned storage
        let sockets = SocketSet::new(vec![]);
        let inner = Arc::new(Mutex::new(StackInner { iface, sockets }));

        // 5. Spawn background reactor event loop
        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        let reactor_inner = Arc::clone(&inner);
        let reactor_notify = Arc::clone(&notify);

        let reactor_handle = tokio::spawn(async move {
            run_reactor(reactor_inner, bridge, reactor_notify, shutdown_rx).await;
        });

        let initial_port = 49152 + (rand::random::<u16>() % 1000);
        let resolver = InTunnelDnsResolver::new(&config.dns);
        resolver.set_ip_mode(ip_mode);
        resolver.set_prefer_ipv6(prefer_ipv6);

        Ok(Self {
            inner,
            notify,
            shutdown_tx,
            reactor_handle: Mutex::new(Some(reactor_handle)),
            local_v4,
            local_v6,
            next_ephemeral_port: AtomicU16::new(initial_port),
            dns_resolver: resolver,
        })
    }

    /// Access the shared inner stack state.
    pub fn inner(&self) -> &Arc<Mutex<StackInner>> {
        &self.inner
    }

    /// Configure whether dual-stack domain resolution prefers IPv6 (`AAAA`) over IPv4 (`A`).
    pub fn set_prefer_ipv6(&self, prefer: bool) {
        self.dns_resolver.set_prefer_ipv6(prefer);
    }

    /// Access the wakeup notification handle.
    pub fn notify(&self) -> &Arc<Notify> {
        &self.notify
    }

    /// Primary configured IPv4 address, if any.
    pub fn local_v4(&self) -> Option<Ipv4Addr> {
        self.local_v4
    }

    /// Primary configured IPv6 address, if any.
    pub fn local_v6(&self) -> Option<Ipv6Addr> {
        self.local_v6
    }

    /// Allocate the next local ephemeral port in range [49152..=65535].
    pub fn alloc_ephemeral_port(&self) -> u16 {
        let val = self.next_ephemeral_port.fetch_add(1, Ordering::Relaxed);
        49152 + (val % 16384)
    }

    /// Initiate an asynchronous TCP connection to the destination address.
    pub async fn tcp_connect(&self, dst: SocketAddr) -> Result<VirtualTcpStream, io::Error> {
        // Validate protocol compatibility
        let local_addr = match dst {
            SocketAddr::V4(_) => {
                let v4 = self.local_v4.ok_or_else(|| {
                    io::Error::new(
                        io::ErrorKind::AddrNotAvailable,
                        "interface does not have an IPv4 address configured",
                    )
                })?;
                let port = self.alloc_ephemeral_port();
                SocketAddr::new(IpAddr::V4(v4), port)
            }
            SocketAddr::V6(_) => {
                let v6 = self.local_v6.ok_or_else(|| {
                    io::Error::new(
                        io::ErrorKind::AddrNotAvailable,
                        "interface does not have an IPv6 address configured",
                    )
                })?;
                let port = self.alloc_ephemeral_port();
                SocketAddr::new(IpAddr::V6(v6), port)
            }
        };

        // Allocate socket buffers
        let rx_buf = TcpSocketBuffer::new(vec![0u8; TCP_RX_BUF_SIZE]);
        let tx_buf = TcpSocketBuffer::new(vec![0u8; TCP_TX_BUF_SIZE]);
        let mut socket = TcpSocket::new(rx_buf, tx_buf);

        // Low latency configuration
        socket.set_nagle_enabled(false);
        socket.set_ack_delay(None);

        let local_port = local_addr.port();
        let remote_endpoint: IpEndpoint = to_smoltcp_endpoint(dst);

        // Initiate connection under lock
        let handle = {
            let mut inner = self.inner.lock();
            let cx = inner.iface.context();
            socket
                .connect(cx, remote_endpoint, local_port)
                .map_err(|e| io::Error::other(format!("tcp connect failed: {:?}", e)))?;
            inner.sockets.add(socket)
        };

        // Wake reactor to transmit SYN packet
        self.notify.notify_one();

        // Wait for connection handshake completion (with timeout)
        let inner_clone = Arc::clone(&self.inner);
        let connect_fut = std::future::poll_fn(|cx| {
            let mut inner = inner_clone.lock();
            let sock = inner.sockets.get_mut::<TcpSocket>(handle);
            match sock.state() {
                tcp::State::Established => std::task::Poll::Ready(Ok(())),
                tcp::State::SynSent => {
                    sock.register_send_waker(cx.waker());
                    std::task::Poll::Pending
                }
                tcp::State::Closed => {
                    std::task::Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::ConnectionRefused,
                        "connection refused by peer",
                    )))
                }
                state => {
                    std::task::Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::ConnectionReset,
                        format!("connection failed in state: {:?}", state),
                    )))
                }
            }
        });

        match tokio::time::timeout(DEFAULT_CONNECT_TIMEOUT, connect_fut).await {
            Ok(Ok(())) => Ok(VirtualTcpStream::new(handle, Arc::clone(&self.inner), Arc::clone(&self.notify), local_addr, dst)),
            Ok(Err(e)) => {
                let mut inner = self.inner.lock();
                let exists = inner.sockets.iter().any(|(h, _)| h == handle);
                if exists {
                    inner.sockets.remove(handle);
                }
                self.notify.notify_one();
                Err(e)
            }
            Err(_) => {
                let mut inner = self.inner.lock();
                let exists = inner.sockets.iter().any(|(h, _)| h == handle);
                if exists {
                    let sock = inner.sockets.get_mut::<TcpSocket>(handle);
                    sock.abort();
                    inner.sockets.remove(handle);
                }
                self.notify.notify_one();
                Err(io::Error::new(io::ErrorKind::TimedOut, "connection timed out"))
            }
        }
    }

    /// Bind a virtual UDP socket to the specified local port with custom buffer sizing.
    pub async fn udp_bind_with_size(
        &self,
        local_port: u16,
        rx_buf_size: usize,
        tx_buf_size: usize,
        queue_capacity: usize,
    ) -> Result<VirtualUdpSocket, io::Error> {
        let port = if local_port == 0 {
            self.alloc_ephemeral_port()
        } else {
            local_port
        };

        let rx_meta = vec![UdpPacketMetadata::EMPTY; queue_capacity];
        let rx_buf = vec![0u8; rx_buf_size];
        let tx_meta = vec![UdpPacketMetadata::EMPTY; queue_capacity];
        let tx_buf = vec![0u8; tx_buf_size];

        let rx_buffer = UdpPacketBuffer::new(rx_meta, rx_buf);
        let tx_buffer = UdpPacketBuffer::new(tx_meta, tx_buf);
        let mut socket = UdpSocket::new(rx_buffer, tx_buffer);

        socket
            .bind(port)
            .map_err(|e| io::Error::new(io::ErrorKind::AddrInUse, format!("udp bind failed: {:?}", e)))?;

        let handle = {
            let mut inner = self.inner.lock();
            inner.sockets.add(socket)
        };

        self.notify.notify_one();
        Ok(VirtualUdpSocket::new(
            handle,
            Arc::clone(&self.inner),
            Arc::clone(&self.notify),
            port,
            self.dns_resolver.ip_mode(),
        ))
    }

    /// Bind a virtual UDP socket to the specified local port using default buffer sizes.
    pub async fn udp_bind(&self, local_port: u16) -> Result<VirtualUdpSocket, io::Error> {
        self.udp_bind_with_size(
            local_port,
            UDP_PAYLOAD_BUF_SIZE,
            UDP_PAYLOAD_BUF_SIZE,
            UDP_PACKET_QUEUE_CAPACITY,
        )
        .await
    }

    /// Resolve a domain name inside the WireGuard tunnel.
    pub async fn resolve_in_tunnel(&self, domain: &str) -> Result<IpAddr, io::Error> {
        self.dns_resolver.resolve(self, domain).await
    }

    /// Resolve a domain name inside the WireGuard tunnel using an explicit [`IpMode`].
    pub async fn resolve_in_tunnel_with_mode(
        &self,
        domain: &str,
        mode: crate::config::IpMode,
    ) -> Result<IpAddr, io::Error> {
        self.dns_resolver.resolve_with_mode(self, domain, mode).await
    }

    /// Cleanly shutdown the virtual network stack and stop the reactor.
    pub async fn close(&self) {
        let _ = self.shutdown_tx.send(true);
        self.notify.notify_one();

        let handle = self.reactor_handle.lock().take();
        if let Some(h) = handle {
            let _ = h.await;
        }
    }
}

impl Drop for VirtualNetworkStack {
    fn drop(&mut self) {
        let _ = self.shutdown_tx.send(true);
        self.notify.notify_one();
        if let Some(h) = self.reactor_handle.lock().take() {
            h.abort();
        }
    }
}

/// Core Tokio reactor loop driving smoltcp `Interface::poll`.
async fn run_reactor(
    inner: Arc<Mutex<StackInner>>,
    mut device: VirtualTunBridge,
    notify: Arc<Notify>,
    mut shutdown_rx: watch::Receiver<bool>,
) {
    tracing::debug!("smoltcp reactor loop started");

    loop {
        let now = SmolInstant::now();

        // 1. Poll the interface under lock
        let delay = {
            let mut guard = inner.lock();
            let StackInner { iface, sockets } = &mut *guard;
            let _ = iface.poll(now, &mut device, sockets);
            iface.poll_delay(now, sockets)
        };

        // 2. Determine sleep or wait action
        match delay {
            Some(smol_dur) => {
                let micros = smol_dur.total_micros();
                if micros == 0 {
                    tokio::select! {
                        biased;
                        _ = shutdown_rx.changed() => {
                            if *shutdown_rx.borrow() {
                                break;
                            }
                        }
                        _ = tokio::task::yield_now() => {}
                    }
                    continue;
                }

                // Sleep until smoltcp timer expires or external event arrives.
                // Cap sleep at 500ms ceiling to ensure liveness, with a minimum of 1ms.
                let wait_ms = smol_dur.total_millis().clamp(1, 500);
                let sleep_dur = StdDuration::from_millis(wait_ms);

                tokio::select! {
                    biased;
                    _ = shutdown_rx.changed() => {
                        if *shutdown_rx.borrow() {
                            break;
                        }
                    }
                    _ = notify.notified() => {
                        // Incoming packet or socket write woke us up
                    }
                    _ = tokio::time::sleep(sleep_dur) => {
                        // Timer expired
                    }
                }
            }
            None => {
                // No pending timers. The stack is completely idle.
                // Zero CPU consumption: parked until external activity or shutdown!
                tokio::select! {
                    biased;
                    _ = shutdown_rx.changed() => {
                        if *shutdown_rx.borrow() {
                            break;
                        }
                    }
                    _ = notify.notified() => {
                        // Woken by packet arrival or socket egress
                    }
                }
            }
        }
    }

    tracing::debug!("smoltcp reactor loop stopped");
}
