//! HTTP & HTTPS CONNECT Proxy Engine (RFC 9110 & RFC 7617).
//!
//! Implements RFC 9110 Section 9.3.6 `CONNECT` method tunneling, RFC 7617 Basic Proxy Authentication,
//! and RFC 9110 Forward Proxying for absolute-URI requests.

use std::collections::HashMap;
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;

use base64::Engine;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::proxy::router::{DynStream, ProxyTunnelTarget, TunnelRouter, TunnelSelector};

const MAX_HEADER_SIZE: usize = 16384;

/// Parses authority-form string `host:port` or `[ipv6]:port`.
pub fn parse_authority(authority: &str) -> Option<(String, u16)> {
    let auth = authority.trim();
    if auth.starts_with('[') {
        let close = auth.find(']')?;
        let host = auth[1..close].to_string();
        let colon = auth[close..].find(':')? + close;
        let port: u16 = auth[colon + 1..].parse().ok()?;
        Some((host, port))
    } else {
        let (host, port_str) = auth.split_once(':')?;
        let port: u16 = port_str.parse().ok()?;
        Some((host.to_string(), port))
    }
}

/// Extracts and decodes RFC 7617 Basic credentials from `Proxy-Authorization` header.
pub fn extract_basic_auth<S: std::hash::BuildHasher>(
    headers: &HashMap<String, String, S>,
) -> Option<(String, String)> {
    let header_val = headers.get("proxy-authorization")?;
    let b64 = header_val
        .strip_prefix("Basic ")
        .or_else(|| header_val.strip_prefix("basic "))?;
    let decoded = base64::prelude::BASE64_STANDARD.decode(b64.trim()).ok()?;
    let s = String::from_utf8(decoded).ok()?;
    let (user, pass) = s.split_once(':')?;
    Some((user.to_string(), pass.to_string()))
}

/// Reads HTTP request line and headers using buffered chunked reads.
///
/// Returns `(method, uri, version, headers, leftover_bytes)`.
pub async fn read_http_request_headers_buffered<R: AsyncRead + Unpin>(
    reader: &mut R,
) -> io::Result<(String, String, String, HashMap<String, String>, Vec<u8>)> {
    let mut buf = Vec::with_capacity(1024);
    let mut chunk = [0u8; 1024];

    while buf.len() < MAX_HEADER_SIZE {
        let n = reader.read(&mut chunk).await?;
        if n == 0 {
            if buf.is_empty() {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "connection closed before request",
                ));
            }
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "request truncated",
            ));
        }
        if let Some(received) = chunk.get(..n) {
            buf.extend_from_slice(received);
        }
        if let Some(pos) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
            let header_bytes = buf.get(..pos + 4).unwrap_or_default();
            let (method, uri, version, headers) = parse_header_bytes(header_bytes)?;
            let leftover = buf.get(pos + 4..).unwrap_or_default().to_vec();
            return Ok((method, uri, version, headers, leftover));
        }
    }

    Err(io::Error::new(
        io::ErrorKind::InvalidData,
        "HTTP request headers too large",
    ))
}

type ParsedHttpHeaders = (String, String, String, HashMap<String, String>);

fn parse_header_bytes(header_bytes: &[u8]) -> io::Result<ParsedHttpHeaders> {
    let header_str = String::from_utf8_lossy(header_bytes);
    let mut lines = header_str.split("\r\n");

    let req_line = lines
        .next()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "missing request line"))?;

    let mut parts = req_line.split_whitespace();
    let (Some(method), Some(uri), Some(version)) = (parts.next(), parts.next(), parts.next())
    else {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "malformed request line",
        ));
    };

    let method = method.to_string();
    let uri = uri.to_string();
    let version = version.to_string();

    let mut headers = HashMap::new();
    for line in lines {
        if line.is_empty() {
            break;
        }
        if let Some((k, v)) = line.split_once(':') {
            headers.insert(k.trim().to_ascii_lowercase(), v.trim().to_string());
        }
    }

    Ok((method, uri, version, headers))
}

/// Reads HTTP request line and headers using buffered chunked reads up to `\r\n\r\n`.
pub async fn read_http_request_headers<R: AsyncRead + Unpin>(
    reader: &mut R,
) -> io::Result<(String, String, String, HashMap<String, String>)> {
    let (method, uri, version, headers, _) = read_http_request_headers_buffered(reader).await?;
    Ok((method, uri, version, headers))
}

/// Core HTTP proxy connection handler.
///
/// Handles `CONNECT` tunneling (RFC 9110 Section 9.3.6), Basic Authentication challenges (RFC 7617),
/// and forward proxy requests for absolute URIs.
pub async fn handle_http<S>(mut stream: S, router: Arc<dyn TunnelRouter>) -> io::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    // 1. Read HTTP request line and headers using buffered chunked reads
    let (method, uri, version, headers, leftover) =
        match read_http_request_headers_buffered(&mut stream).await {
            Ok(res) => res,
            Err(e) => {
                if e.kind() == io::ErrorKind::UnexpectedEof
                    && e.to_string().contains("before request")
                {
                    return Ok(());
                }
                send_response(&mut stream, "400 Bad Request", "text/plain", b"Bad Request").await?;
                return Err(e);
            }
        };

    // 2. Validate Basic Authentication if required
    let credentials = extract_basic_auth(&headers);
    let cred_refs = credentials.as_ref().map(|(u, p)| (u.as_str(), p.as_str()));

    let Ok(selector) = router.authenticate(cred_refs) else {
        let resp = "HTTP/1.1 407 Proxy Authentication Required\r\n\
                    Proxy-Authenticate: Basic realm=\"wpmulti\"\r\n\
                    Content-Length: 0\r\n\r\n";
        stream.write_all(resp.as_bytes()).await?;
        stream.flush().await?;
        return Ok(());
    };

    // 3. Dispatch based on HTTP method and URI form
    if method.eq_ignore_ascii_case("CONNECT") {
        handle_http_connect(stream, router, &selector, &uri, leftover).await
    } else if uri.starts_with("http://") || uri.starts_with("https://") {
        let req = ForwardRequest {
            method,
            uri,
            version,
            headers,
        };
        handle_http_forward(stream, router, &selector, req, leftover).await
    } else {
        // Non-CONNECT origin-form requests received on forward proxy port
        send_response(
            &mut stream,
            "400 Bad Request",
            "text/plain",
            b"Invalid Request",
        )
        .await?;
        Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "unsupported or non-proxy HTTP request",
        ))
    }
}

/// Executes RFC 9110 Section 9.3.6 `CONNECT` TCP stream tunneling.
async fn handle_http_connect<S: AsyncRead + AsyncWrite + Unpin>(
    mut stream: S,
    router: Arc<dyn TunnelRouter>,
    selector: &TunnelSelector,
    authority: &str,
    leftover: Vec<u8>,
) -> io::Result<()> {
    let Some((host, port)) = parse_authority(authority) else {
        send_response(
            &mut stream,
            "400 Bad Request",
            "text/plain",
            b"Invalid Authority",
        )
        .await?;
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "invalid authority in CONNECT request",
        ));
    };

    // Resolve tunnel target
    let target_tunnel = match router.select_tunnel(selector).await {
        Ok(t) => t,
        Err(e) => {
            tracing::warn!("Failed to select tunnel for HTTP CONNECT: {:?}", e);
            send_response(&mut stream, "502 Bad Gateway", "text/plain", b"Bad Gateway").await?;
            return Err(e);
        }
    };

    // Resolve destination IP address
    let dst_addr = if let Ok(ip) = host.parse::<IpAddr>() {
        SocketAddr::new(ip, port)
    } else {
        match target_tunnel.resolve_in_tunnel(&host).await {
            Ok(ip) => SocketAddr::new(ip, port),
            Err(e) => {
                tracing::warn!("Failed to resolve host '{}' in tunnel: {:?}", host, e);
                send_response(
                    &mut stream,
                    "502 Bad Gateway",
                    "text/plain",
                    b"DNS Resolution Failed",
                )
                .await?;
                return Err(e);
            }
        }
    };

    // Connect to target via tunnel connector
    let mut tunnel_stream: DynStream = match target_tunnel.tcp_connect(dst_addr).await {
        Ok(s) => s,
        Err(e) => {
            tracing::warn!("Failed to connect to target {}: {:?}", dst_addr, e);
            send_response(
                &mut stream,
                "502 Bad Gateway",
                "text/plain",
                b"Connection Failed",
            )
            .await?;
            return Err(e);
        }
    };

    // Respond 200 Connection Established
    stream
        .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
        .await?;
    stream.flush().await?;

    // Forward any pipelined leftover bytes
    if !leftover.is_empty() {
        tunnel_stream.write_all(&leftover).await?;
        tunnel_stream.flush().await?;
    }

    // Bidirectional byte streaming
    tokio::io::copy_bidirectional(&mut stream, &mut tunnel_stream).await?;

    Ok(())
}

struct ForwardRequest {
    method: String,
    uri: String,
    version: String,
    headers: HashMap<String, String>,
}

fn parse_forward_uri(uri: &str) -> io::Result<(String, u16, String)> {
    let rest = uri
        .strip_prefix("http://")
        .or_else(|| uri.strip_prefix("https://"))
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "invalid absolute URI"))?;

    let (authority, path) = match rest.split_once('/') {
        Some((auth, p)) => (auth, format!("/{p}")),
        None => (rest, "/".to_string()),
    };

    let (host, port) = if authority.starts_with('[') {
        if authority.ends_with(']') {
            (authority[1..authority.len() - 1].to_string(), 80)
        } else {
            parse_authority(authority)
                .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "invalid authority"))?
        }
    } else if let Some((h, p_str)) = authority.split_once(':') {
        let p = p_str.parse::<u16>().map_err(|_| {
            io::Error::new(io::ErrorKind::InvalidInput, "invalid port in authority")
        })?;
        (h.to_string(), p)
    } else {
        (authority.to_string(), 80)
    };

    Ok((host, port, path))
}

/// Executes RFC 9110 Forward Proxy request forwarding for absolute URIs.
async fn handle_http_forward<S: AsyncRead + AsyncWrite + Unpin>(
    mut stream: S,
    router: Arc<dyn TunnelRouter>,
    selector: &TunnelSelector,
    req: ForwardRequest,
    leftover: Vec<u8>,
) -> io::Result<()> {
    let (host, port, path) = match parse_forward_uri(&req.uri) {
        Ok(parsed) => parsed,
        Err(e) => {
            send_response(
                &mut stream,
                "400 Bad Request",
                "text/plain",
                b"Invalid Absolute URI",
            )
            .await?;
            return Err(e);
        }
    };

    // Resolve tunnel target
    let target_tunnel = match router.select_tunnel(selector).await {
        Ok(t) => t,
        Err(e) => {
            send_response(&mut stream, "502 Bad Gateway", "text/plain", b"Bad Gateway").await?;
            return Err(e);
        }
    };

    // Resolve destination IP address
    let dst_addr = if let Ok(ip) = host.parse::<IpAddr>() {
        SocketAddr::new(ip, port)
    } else {
        match target_tunnel.resolve_in_tunnel(&host).await {
            Ok(ip) => SocketAddr::new(ip, port),
            Err(e) => {
                send_response(
                    &mut stream,
                    "502 Bad Gateway",
                    "text/plain",
                    b"DNS Resolution Failed",
                )
                .await?;
                return Err(e);
            }
        }
    };

    // Connect to destination server via tunnel
    let mut tunnel_stream: DynStream = match target_tunnel.tcp_connect(dst_addr).await {
        Ok(s) => s,
        Err(e) => {
            send_response(
                &mut stream,
                "502 Bad Gateway",
                "text/plain",
                b"Connection Failed",
            )
            .await?;
            return Err(e);
        }
    };

    // Rewrite request line with relative path, filter hop-by-hop headers, and inject Connection: close
    let mut req_buf = format!("{} {} {}\r\n", req.method, path, req.version);
    for (k, v) in &req.headers {
        if k == "proxy-authorization"
            || k == "proxy-connection"
            || k == "proxy-authenticate"
            || k == "connection"
        {
            continue;
        }
        let _ = std::fmt::Write::write_fmt(&mut req_buf, format_args!("{k}: {v}\r\n"));
    }
    req_buf.push_str("connection: close\r\n\r\n");

    // Forward request line and headers to destination server
    tunnel_stream.write_all(req_buf.as_bytes()).await?;
    if !leftover.is_empty() {
        tunnel_stream.write_all(&leftover).await?;
    }
    tunnel_stream.flush().await?;

    // Bidirectional copy: streams any request payload (e.g. POST) and response back to client
    tokio::io::copy_bidirectional(&mut stream, &mut tunnel_stream).await?;

    Ok(())
}

/// Helper to write standard HTTP error / status responses.
async fn send_response<W: AsyncWrite + Unpin>(
    writer: &mut W,
    status: &str,
    content_type: &str,
    body: &[u8],
) -> io::Result<()> {
    let resp = format!(
        "HTTP/1.1 {}\r\nContent-Type: {}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        status,
        content_type,
        body.len()
    );
    writer.write_all(resp.as_bytes()).await?;
    if !body.is_empty() {
        writer.write_all(body).await?;
    }
    writer.flush().await
}
