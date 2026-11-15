use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

pub const SOCKS5_VERSION: u8 = 0x05;
pub const RFC1929_VERSION: u8 = 0x01;

// Authentication Methods (RFC 1928 Section 3)
pub const METHOD_NO_AUTH: u8 = 0x00;
pub const METHOD_GSSAPI: u8 = 0x01;
pub const METHOD_USER_PASS: u8 = 0x02;
pub const METHOD_NO_ACCEPTABLE: u8 = 0xFF;

// Command Codes (RFC 1928 Section 4)
pub const CMD_CONNECT: u8 = 0x01;
pub const CMD_BIND: u8 = 0x02;
pub const CMD_UDP_ASSOCIATE: u8 = 0x03;

// Address Types (RFC 1928 Section 5)
pub const ATYP_IPV4: u8 = 0x01;
pub const ATYP_DOMAIN: u8 = 0x03;
pub const ATYP_IPV6: u8 = 0x04;

// Reply Codes (RFC 1928 Section 6)
pub const REP_SUCCESS: u8 = 0x00;
pub const REP_GENERAL_FAILURE: u8 = 0x01;
pub const REP_CONN_NOT_ALLOWED: u8 = 0x02;
pub const REP_NETWORK_UNREACHABLE: u8 = 0x03;
pub const REP_HOST_UNREACHABLE: u8 = 0x04;
pub const REP_CONN_REFUSED: u8 = 0x05;
pub const REP_TTL_EXPIRED: u8 = 0x06;
pub const REP_CMD_NOT_SUPPORTED: u8 = 0x07;
pub const REP_COMMAND_NOT_SUPPORTED: u8 = 0x07;
pub const REP_ADDR_NOT_SUPPORTED: u8 = 0x08;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Socks5Target {
    Ip(SocketAddr),
    Domain(String, u16),
}

impl Socks5Target {
    pub fn encode(&self, buf: &mut Vec<u8>) {
        match self {
            Socks5Target::Ip(SocketAddr::V4(v4)) => {
                buf.push(ATYP_IPV4);
                buf.extend_from_slice(&v4.ip().octets());
                buf.extend_from_slice(&v4.port().to_be_bytes());
            }
            Socks5Target::Ip(SocketAddr::V6(v6)) => {
                buf.push(ATYP_IPV6);
                buf.extend_from_slice(&v6.ip().octets());
                buf.extend_from_slice(&v6.port().to_be_bytes());
            }
            Socks5Target::Domain(domain, port) => {
                buf.push(ATYP_DOMAIN);
                let bytes = domain.as_bytes();
                buf.push(bytes.len() as u8);
                buf.extend_from_slice(bytes);
                buf.extend_from_slice(&port.to_be_bytes());
            }
        }
    }

    pub fn decode(buf: &[u8]) -> std::io::Result<(Self, usize)> {
        if buf.is_empty() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "empty atyp",
            ));
        }
        match buf[0] {
            ATYP_IPV4 => {
                if buf.len() < 1 + 4 + 2 {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::UnexpectedEof,
                        "truncated ipv4",
                    ));
                }
                let ip = Ipv4Addr::new(buf[1], buf[2], buf[3], buf[4]);
                let port = u16::from_be_bytes([buf[5], buf[6]]);
                Ok((
                    Socks5Target::Ip(SocketAddr::V4(SocketAddrV4::new(ip, port))),
                    7,
                ))
            }
            ATYP_IPV6 => {
                if buf.len() < 1 + 16 + 2 {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::UnexpectedEof,
                        "truncated ipv6",
                    ));
                }
                let mut octets = [0u8; 16];
                octets.copy_from_slice(&buf[1..17]);
                let ip = Ipv6Addr::from(octets);
                let port = u16::from_be_bytes([buf[17], buf[18]]);
                Ok((
                    Socks5Target::Ip(SocketAddr::V6(SocketAddrV6::new(ip, port, 0, 0))),
                    19,
                ))
            }
            ATYP_DOMAIN => {
                if buf.len() < 2 {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::UnexpectedEof,
                        "truncated domain len",
                    ));
                }
                let len = buf[1] as usize;
                if buf.len() < 2 + len + 2 {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::UnexpectedEof,
                        "truncated domain payload",
                    ));
                }
                let domain = String::from_utf8_lossy(&buf[2..2 + len]).to_string();
                let port = u16::from_be_bytes([buf[2 + len], buf[3 + len]]);
                Ok((Socks5Target::Domain(domain, port), 2 + len + 2))
            }
            other => Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("unsupported atyp: 0x{:02X}", other),
            )),
        }
    }
}

pub struct Socks5TestClient {
    stream: tokio::net::TcpStream,
    proxy_addr: SocketAddr,
}

impl Socks5TestClient {
    /// Connect to SOCKS5 proxy
    pub async fn connect(proxy_addr: SocketAddr) -> std::io::Result<Self> {
        let stream = tokio::net::TcpStream::connect(proxy_addr).await?;
        Ok(Self { stream, proxy_addr })
    }

    /// Perform RFC 1928 greeting handshake with custom offered methods
    pub async fn greeting(&mut self, methods: &[u8]) -> std::io::Result<u8> {
        let mut req = Vec::with_capacity(2 + methods.len());
        req.push(SOCKS5_VERSION);
        req.push(methods.len() as u8);
        req.extend_from_slice(methods);
        self.stream.write_all(&req).await?;

        let mut resp = [0u8; 2];
        self.stream.read_exact(&mut resp).await?;
        if resp[0] != SOCKS5_VERSION {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "invalid socks5 version in greeting",
            ));
        }
        Ok(resp[1])
    }

    /// Authenticate via RFC 1929 username/password subnegotiation
    pub async fn authenticate(&mut self, username: &str, password: &str) -> std::io::Result<()> {
        let u_bytes = username.as_bytes();
        let p_bytes = password.as_bytes();
        if u_bytes.len() > 255 || p_bytes.len() > 255 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "username/password too long",
            ));
        }

        let mut req = Vec::with_capacity(3 + u_bytes.len() + p_bytes.len());
        req.push(RFC1929_VERSION);
        req.push(u_bytes.len() as u8);
        req.extend_from_slice(u_bytes);
        req.push(p_bytes.len() as u8);
        req.extend_from_slice(p_bytes);
        self.stream.write_all(&req).await?;

        let mut resp = [0u8; 2];
        self.stream.read_exact(&mut resp).await?;
        if resp[0] != RFC1929_VERSION {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "invalid rfc1929 version in auth response",
            ));
        }
        if resp[1] != 0x00 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                format!("socks5 auth failed, status 0x{:02X}", resp[1]),
            ));
        }
        Ok(())
    }

    /// Send CONNECT command and obtain transparent TCP stream to destination
    pub async fn cmd_connect(
        mut self,
        target: Socks5Target,
    ) -> std::io::Result<tokio::net::TcpStream> {
        let (rep, _bound_addr) = self.send_command(CMD_CONNECT, &target).await?;
        if rep != REP_SUCCESS {
            return Err(std::io::Error::new(
                std::io::ErrorKind::ConnectionRefused,
                format!("socks5 connect command failed with rep: 0x{:02X}", rep),
            ));
        }
        Ok(self.stream)
    }

    /// Helper: CONNECT to IPv4 target
    pub async fn cmd_connect_ipv4(
        self,
        ip: Ipv4Addr,
        port: u16,
    ) -> std::io::Result<tokio::net::TcpStream> {
        self.cmd_connect(Socks5Target::Ip(SocketAddr::V4(SocketAddrV4::new(
            ip, port,
        ))))
        .await
    }

    /// Helper: CONNECT to Domain target
    pub async fn cmd_connect_domain(
        self,
        domain: &str,
        port: u16,
    ) -> std::io::Result<tokio::net::TcpStream> {
        self.cmd_connect(Socks5Target::Domain(domain.to_string(), port))
            .await
    }

    /// Helper: CONNECT to IPv6 target
    pub async fn cmd_connect_ipv6(
        self,
        ip: Ipv6Addr,
        port: u16,
    ) -> std::io::Result<tokio::net::TcpStream> {
        self.cmd_connect(Socks5Target::Ip(SocketAddr::V6(SocketAddrV6::new(
            ip, port, 0, 0,
        ))))
        .await
    }

    /// Send UDP ASSOCIATE command and obtain a managed UDP relay session
    pub async fn cmd_udp_associate(
        mut self,
        client_bind_addr: Option<SocketAddr>,
    ) -> std::io::Result<Socks5UdpSession> {
        let bind_target = match client_bind_addr {
            Some(addr) => Socks5Target::Ip(addr),
            None => Socks5Target::Ip("0.0.0.0:0".parse().unwrap()),
        };

        let (rep, bound_addr) = self.send_command(CMD_UDP_ASSOCIATE, &bind_target).await?;
        if rep != REP_SUCCESS {
            return Err(std::io::Error::new(
                std::io::ErrorKind::ConnectionRefused,
                format!("socks5 udp associate failed with rep: 0x{:02X}", rep),
            ));
        }

        // Resolve relay address: if bound IP is unspecified (0.0.0.0 or ::), use proxy host IP
        let relay_ip = match bound_addr.ip() {
            ip if ip.is_unspecified() => self.proxy_addr.ip(),
            ip => ip,
        };
        let relay_addr = SocketAddr::new(relay_ip, bound_addr.port());

        // Bind client UDP socket on ephemeral port matching address family of relay
        let client_udp = match relay_addr {
            SocketAddr::V4(_) => tokio::net::UdpSocket::bind("0.0.0.0:0").await?,
            SocketAddr::V6(_) => tokio::net::UdpSocket::bind("[::]:0").await?,
        };

        Ok(Socks5UdpSession {
            _tcp_control: self.stream,
            udp_socket: client_udp,
            relay_addr,
        })
    }

    /// Low-level command sender used by CONNECT, UDP ASSOCIATE, and negative/boundary tests
    pub async fn send_command(
        &mut self,
        cmd: u8,
        target: &Socks5Target,
    ) -> std::io::Result<(u8, SocketAddr)> {
        let mut req = vec![SOCKS5_VERSION, cmd, 0x00];
        target.encode(&mut req);
        self.stream.write_all(&req).await?;

        let mut header = [0u8; 4];
        self.stream.read_exact(&mut header).await?;
        if header[0] != SOCKS5_VERSION {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "invalid version in cmd response",
            ));
        }
        let rep = header[1];
        let atyp = header[3];

        let bound_addr = match atyp {
            ATYP_IPV4 => {
                let mut buf = [0u8; 6];
                self.stream.read_exact(&mut buf).await?;
                let ip = Ipv4Addr::new(buf[0], buf[1], buf[2], buf[3]);
                let port = u16::from_be_bytes([buf[4], buf[5]]);
                SocketAddr::V4(SocketAddrV4::new(ip, port))
            }
            ATYP_IPV6 => {
                let mut buf = [0u8; 18];
                self.stream.read_exact(&mut buf).await?;
                let mut octets = [0u8; 16];
                octets.copy_from_slice(&buf[0..16]);
                let ip = Ipv6Addr::from(octets);
                let port = u16::from_be_bytes([buf[16], buf[17]]);
                SocketAddr::V6(SocketAddrV6::new(ip, port, 0, 0))
            }
            ATYP_DOMAIN => {
                let mut len_buf = [0u8; 1];
                self.stream.read_exact(&mut len_buf).await?;
                let len = len_buf[0] as usize;
                let mut buf = vec![0u8; len + 2];
                self.stream.read_exact(&mut buf).await?;
                let port = u16::from_be_bytes([buf[len], buf[len + 1]]);
                SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, port))
            }
            other => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!("unsupported atyp in response: 0x{:02X}", other),
                ));
            }
        };

        Ok((rep, bound_addr))
    }
}

pub struct Socks5UdpSession {
    _tcp_control: tokio::net::TcpStream, // Holds control connection open
    udp_socket: tokio::net::UdpSocket,
    relay_addr: SocketAddr,
}

impl Socks5UdpSession {
    pub fn relay_addr(&self) -> SocketAddr {
        self.relay_addr
    }

    pub fn local_addr(&self) -> std::io::Result<SocketAddr> {
        self.udp_socket.local_addr()
    }

    /// Send encapsulated UDP datagram through SOCKS5 relay to destination
    pub async fn send_to(&self, target: &Socks5Target, payload: &[u8]) -> std::io::Result<usize> {
        let mut pkt = Vec::with_capacity(10 + payload.len());
        pkt.push(0x00); // RSV
        pkt.push(0x00); // RSV
        pkt.push(0x00); // FRAG: Standalone
        target.encode(&mut pkt);
        pkt.extend_from_slice(payload);

        self.udp_socket.send_to(&pkt, self.relay_addr).await
    }

    /// Receive and decapsulate UDP datagram from SOCKS5 relay
    pub async fn recv_from(&self, buf: &mut [u8]) -> std::io::Result<(usize, Socks5Target)> {
        let mut raw_buf = [0u8; 65536];
        let (n, from_addr) = self.udp_socket.recv_from(&mut raw_buf).await?;
        if from_addr != self.relay_addr {
            return Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                format!("received packet from unknown relay address: {}", from_addr),
            ));
        }

        if n < 4 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "truncated socks5 udp packet",
            ));
        }

        let frag = raw_buf[2];
        if frag != 0x00 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "fragmented socks5 udp packets not supported",
            ));
        }

        let (src_target, header_len) = Socks5Target::decode(&raw_buf[3..n])?;
        let total_header_len = 3 + header_len;
        let payload_len = n - total_header_len;

        if buf.len() < payload_len {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "buffer too small for udp payload",
            ));
        }

        buf[..payload_len].copy_from_slice(&raw_buf[total_header_len..n]);
        Ok((payload_len, src_target))
    }

    /// Send request and await matching response with timeout
    pub async fn query_echo(
        &self,
        target: &Socks5Target,
        payload: &[u8],
        timeout: std::time::Duration,
    ) -> std::io::Result<Vec<u8>> {
        self.send_to(target, payload).await?;
        let mut resp_buf = vec![0u8; 65536];
        tokio::time::timeout(timeout, self.recv_from(&mut resp_buf))
            .await
            .map_err(|_| {
                std::io::Error::new(std::io::ErrorKind::TimedOut, "udp echo response timed out")
            })?
            .map(|(len, _)| {
                resp_buf.truncate(len);
                resp_buf
            })
    }
}
