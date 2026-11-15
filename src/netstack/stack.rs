//! Virtual smoltcp network stack and Tokio reactor event loop.
//!
//! Provides [`VirtualNetworkStack`], managing the userspace Layer 3 smoltcp interface,
//! IP routing table, socket set, and asynchronous reactor background task.

use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::{AtomicU16, Ordering};
use std::time::Duration as StdDuration;

use parking_lot::Mutex;
use smoltcp::iface::{Config, Interface, SocketSet};
use smoltcp::socket::tcp::{self, Socket as TcpSocket, SocketBuffer as TcpSocketBuffer};
use smoltcp::socket::udp::{
    PacketBuffer as UdpPacketBuffer, PacketMetadata as UdpPacketMetadata, Socket as UdpSocket,
};
use smoltcp::time::Instant as SmolInstant;
use smoltcp::wire::{
    HardwareAddress, IpCidr, IpEndpoint, Ipv4Address, Ipv4Cidr, Ipv6Address, Ipv6Cidr,
};
use tokio::sync::{Notify, watch};
use tokio::task::JoinHandle;

use crate::config::WgInterfaceConfig;
use crate::netstack::bridge::VirtualTunBridge;
use crate::netstack::dns::InTunnelDnsResolver;
use crate::netstack::stream::{VirtualTcpStream, VirtualUdpSocket, to_smoltcp_endpoint};

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

impl std::fmt::Debug for StackInner {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("StackInner").finish_non_exhaustive()
    }
}

/// Userspace virtual network stack attached to a WireGuard tunnel.
#[derive(Debug)]
pub struct VirtualNetworkStack {
    inner: Arc<Mutex<StackInner>>,
    notify: Arc<Notify>,
    shutdown_tx: watch::Sender<bool>,
    reactor_handle: Mutex<Option<JoinHandle<()>>>,
    local_v4: Option<Ipv4Addr>,
    local_v6: Option<Ipv6Addr>,
    next_ephemeral_port: AtomicU16,
    dns_resolver: InTunnelDnsResolver,
    connect_timeout: StdDuration,
}

impl VirtualNetworkStack {
    /// Construct a new virtual network stack from WireGuard interface configuration
    /// and a [`VirtualTunBridge`] in `DualStack` mode.
    pub async fn new(
        config: &WgInterfaceConfig,
        bridge: VirtualTunBridge,
    ) -> Result<Self, io::Error> {
        Self::new_with_mode(config, bridge, crate::config::IpMode::DualStack, false).await
    }

    /// Construct a new virtual network stack with an explicit [`IpMode`] and IPv6 DNS preference.
    pub async fn new_with_mode(
        config: &WgInterfaceConfig,
        bridge: VirtualTunBridge,
        ip_mode: crate::config::IpMode,
        prefer_ipv6: bool,
    ) -> Result<Self, io::Error> {
        Self::new_with_options(
            config,
            bridge,
            ip_mode,
            prefer_ipv6,
            (
                SocketAddr::new(IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)), 53),
                crate::config::toml_config::DnsStrategy::TunnelOnly,
            ),
            DEFAULT_CONNECT_TIMEOUT,
        )
        .await
    }

    /// Construct a new [`VirtualNetworkStack`] with explicit IP mode, DNS fallback/strategy,
    /// and connection timeout.
    #[allow(clippy::unused_async)]
    pub async fn new_with_options(
        config: &WgInterfaceConfig,
        mut bridge: VirtualTunBridge,
        ip_mode: crate::config::IpMode,
        prefer_ipv6: bool,
        (dns_fallback, dns_strategy): (SocketAddr, crate::config::toml_config::DnsStrategy),
        connect_timeout: StdDuration,
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
                            tracing::warn!(
                                "Failed to add IPv4 address {}: interface address list full",
                                v4
                            );
                        } else if local_v4.is_none() {
                            local_v4 = Some(v4.ip());
                        }
                    }
                    ipnetwork::IpNetwork::V6(v6) if ip_mode != crate::config::IpMode::Ipv4Only => {
                        let smol_addr = v6.ip();
                        let cidr = IpCidr::Ipv6(Ipv6Cidr::new(smol_addr, v6.prefix()));
                        if ip_addrs.push(cidr).is_err() {
                            tracing::warn!(
                                "Failed to add IPv6 address {}: interface address list full",
                                v6
                            );
                        } else if local_v6.is_none() {
                            local_v6 = Some(v6.ip());
                        }
                    }
                    ipnetwork::IpNetwork::V4(_) | ipnetwork::IpNetwork::V6(_) => {}
                }
            }
        });

        if local_v4.is_none() && local_v6.is_none() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("interface has no usable IP addresses for ip_mode {ip_mode:?}"),
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
            iface
                .routes_mut()
                .add_default_ipv4_route(gateway)
                .map_err(|e| io::Error::other(format!("add default ipv4 route failed: {e:?}")))?;
        }

        if let Some(v6_ip) = local_v6 {
            let default_gw = Ipv6Address::new(0xfe80, 0, 0, 0, 0, 0, 0, 1);
            let gateway = if v6_ip == default_gw {
                Ipv6Address::new(0xfe80, 0, 0, 0, 0, 0, 0, 2)
            } else {
                default_gw
            };
            iface
                .routes_mut()
                .add_default_ipv6_route(gateway)
                .map_err(|e| io::Error::other(format!("add default ipv6 route failed: {e:?}")))?;
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
        let resolver = InTunnelDnsResolver::with_fallback(&config.dns, dns_fallback);
        resolver.set_ip_mode(ip_mode);
        resolver.set_prefer_ipv6(prefer_ipv6);
        resolver.set_dns_strategy(dns_strategy);

        Ok(Self {
            inner,
            notify,
            shutdown_tx,
            reactor_handle: Mutex::new(Some(reactor_handle)),
            local_v4,
            local_v6,
            next_ephemeral_port: AtomicU16::new(initial_port),
            dns_resolver: resolver,
            connect_timeout,
        })
    }

    /// Access the shared inner stack state.
    pub const fn inner(&self) -> &Arc<Mutex<StackInner>> {
        &self.inner
    }

    /// Configure whether dual-stack domain resolution prefers IPv6 (`AAAA`) over IPv4 (`A`).
    pub fn set_prefer_ipv6(&self, prefer: bool) {
        self.dns_resolver.set_prefer_ipv6(prefer);
    }

    /// Configure the DNS resolution strategy (`TunnelOnly`, `TunnelFirst`, `Host`).
    pub fn set_dns_strategy(&self, strategy: crate::config::toml_config::DnsStrategy) {
        self.dns_resolver.set_dns_strategy(strategy);
    }

    /// Access the wakeup notification handle.
    pub const fn notify(&self) -> &Arc<Notify> {
        &self.notify
    }

    /// Primary configured IPv4 address, if any.
    pub const fn local_v4(&self) -> Option<Ipv4Addr> {
        self.local_v4
    }

    /// Primary configured IPv6 address, if any.
    pub const fn local_v6(&self) -> Option<Ipv6Addr> {
        self.local_v6
    }

    /// Allocate the next local ephemeral port in range [49152..=65535].
    pub fn alloc_ephemeral_port(&self) -> u16 {
        let val = self.next_ephemeral_port.fetch_add(1, Ordering::Relaxed);
        49152 + (val % 16384)
    }

    /// Check if `port` is currently bound or in use by any socket in `sockets`.
    #[allow(
        clippy::wildcard_enum_match_arm,
        clippy::match_wildcard_for_single_variants
    )]
    fn is_port_in_use(sockets: &SocketSet<'_>, port: u16) -> bool {
        sockets.iter().any(|(_, sock)| match sock {
            smoltcp::socket::Socket::Tcp(tcp_sock) => {
                tcp_sock.local_endpoint().is_some_and(|ep| ep.port == port)
            }
            smoltcp::socket::Socket::Udp(udp_sock) => udp_sock.endpoint().port == port,
            _ => false,
        })
    }

    /// Allocate an ephemeral port that is not currently used by any socket in `sockets`.
    fn alloc_free_ephemeral_port(&self, sockets: &SocketSet<'_>) -> u16 {
        for _ in 0..16384 {
            let port = self.alloc_ephemeral_port();
            if !Self::is_port_in_use(sockets, port) {
                return port;
            }
        }
        self.alloc_ephemeral_port()
    }

    /// Initiate an asynchronous TCP connection to the destination address.
    pub async fn tcp_connect(&self, dst: SocketAddr) -> Result<VirtualTcpStream, io::Error> {
        // Validate protocol compatibility
        let local_ip = match dst {
            SocketAddr::V4(_) => IpAddr::V4(self.local_v4.ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::AddrNotAvailable,
                    "interface does not have an IPv4 address configured",
                )
            })?),
            SocketAddr::V6(_) => IpAddr::V6(self.local_v6.ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::AddrNotAvailable,
                    "interface does not have an IPv6 address configured",
                )
            })?),
        };

        // Allocate socket buffers
        let rx_buf = TcpSocketBuffer::new(vec![0u8; TCP_RX_BUF_SIZE]);
        let tx_buf = TcpSocketBuffer::new(vec![0u8; TCP_TX_BUF_SIZE]);
        let mut socket = TcpSocket::new(rx_buf, tx_buf);

        // Low latency configuration
        socket.set_nagle_enabled(false);
        socket.set_ack_delay(None);

        let remote_endpoint: IpEndpoint = to_smoltcp_endpoint(dst);

        // Initiate connection under lock with collision-free ephemeral port
        let (handle, local_port) = {
            let mut inner = self.inner.lock();
            let port = self.alloc_free_ephemeral_port(&inner.sockets);
            let cx = inner.iface.context();
            socket
                .connect(cx, remote_endpoint, port)
                .map_err(|e| io::Error::other(format!("tcp connect failed: {e:?}")))?;
            (inner.sockets.add(socket), port)
        };
        let local_addr = SocketAddr::new(local_ip, local_port);

        // Wake reactor to transmit SYN packet
        self.notify.notify_one();

        // Wait for connection handshake completion (with timeout)
        let inner_clone = Arc::clone(&self.inner);
        let connect_fut = std::future::poll_fn(|cx| {
            let mut inner = inner_clone.lock();
            let sock = inner.sockets.get_mut::<TcpSocket<'_>>(handle);
            let poll_res = match sock.state() {
                tcp::State::Established => std::task::Poll::Ready(Ok(())),
                tcp::State::SynSent => {
                    sock.register_send_waker(cx.waker());
                    std::task::Poll::Pending
                }
                tcp::State::Closed => std::task::Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::ConnectionRefused,
                    "connection refused by peer",
                ))),
                state @ (tcp::State::Listen
                | tcp::State::SynReceived
                | tcp::State::FinWait1
                | tcp::State::FinWait2
                | tcp::State::CloseWait
                | tcp::State::Closing
                | tcp::State::LastAck
                | tcp::State::TimeWait) => std::task::Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::ConnectionReset,
                    format!("connection failed in state: {state:?}"),
                ))),
            };
            drop(inner);
            poll_res
        });

        match tokio::time::timeout(self.connect_timeout, connect_fut).await {
            Ok(Ok(())) => Ok(VirtualTcpStream::new(
                handle,
                Arc::clone(&self.inner),
                Arc::clone(&self.notify),
                local_addr,
                dst,
            )),
            Ok(Err(e)) => {
                {
                    let mut inner = self.inner.lock();
                    let exists = inner.sockets.iter().any(|(h, _)| h == handle);
                    if exists {
                        inner.sockets.remove(handle);
                    }
                }
                self.notify.notify_one();
                Err(e)
            }
            Err(_) => {
                {
                    let mut inner = self.inner.lock();
                    let exists = inner.sockets.iter().any(|(h, _)| h == handle);
                    if exists {
                        let sock = inner.sockets.get_mut::<TcpSocket<'_>>(handle);
                        sock.abort();
                        inner.sockets.remove(handle);
                    }
                }
                self.notify.notify_one();
                Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "connection timed out",
                ))
            }
        }
    }

    /// Bind a virtual UDP socket to the specified local port with custom buffer sizing.
    #[allow(clippy::unused_async)]
    pub async fn udp_bind_with_size(
        &self,
        local_port: u16,
        rx_buf_size: usize,
        tx_buf_size: usize,
        queue_capacity: usize,
    ) -> Result<VirtualUdpSocket, io::Error> {
        let rx_meta = vec![UdpPacketMetadata::EMPTY; queue_capacity];
        let rx_buf = vec![0u8; rx_buf_size];
        let tx_meta = vec![UdpPacketMetadata::EMPTY; queue_capacity];
        let tx_buf = vec![0u8; tx_buf_size];

        let rx_buffer = UdpPacketBuffer::new(rx_meta, rx_buf);
        let tx_buffer = UdpPacketBuffer::new(tx_meta, tx_buf);
        let mut socket = UdpSocket::new(rx_buffer, tx_buffer);

        let (handle, port) = {
            let mut inner = self.inner.lock();
            let port = if local_port == 0 {
                self.alloc_free_ephemeral_port(&inner.sockets)
            } else {
                local_port
            };
            socket.bind(port).map_err(|e| {
                io::Error::new(io::ErrorKind::AddrInUse, format!("udp bind failed: {e:?}"))
            })?;
            (inner.sockets.add(socket), port)
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
        self.dns_resolver
            .resolve_with_mode(self, domain, mode)
            .await
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
        let handle = self.reactor_handle.lock().take();
        if let Some(h) = handle {
            h.abort();
        }
    }
}

async fn wait_reactor_step(
    delay: Option<smoltcp::time::Duration>,
    notify: &Notify,
    shutdown_rx: &mut watch::Receiver<bool>,
) -> bool {
    match delay {
        Some(smol_dur) if smol_dur.total_micros() == 0 => {
            tokio::select! {
                biased;
                _ = shutdown_rx.changed() => !*shutdown_rx.borrow(),
                () = tokio::task::yield_now() => true,
            }
        }
        Some(smol_dur) => {
            let wait_ms = smol_dur.total_millis().clamp(1, 500);
            let sleep_dur = StdDuration::from_millis(wait_ms);
            tokio::select! {
                biased;
                _ = shutdown_rx.changed() => !*shutdown_rx.borrow(),
                () = notify.notified() => true,
                () = tokio::time::sleep(sleep_dur) => true,
            }
        }
        None => {
            tokio::select! {
                biased;
                _ = shutdown_rx.changed() => !*shutdown_rx.borrow(),
                () = notify.notified() => true,
            }
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
        let delay = {
            let mut guard = inner.lock();
            let StackInner { iface, sockets } = &mut *guard;
            let _ = iface.poll(now, &mut device, sockets);
            let d = iface.poll_delay(now, sockets);
            drop(guard);
            d
        };

        if !wait_reactor_step(delay, &notify, &mut shutdown_rx).await {
            break;
        }
    }

    tracing::debug!("smoltcp reactor loop stopped");
}
