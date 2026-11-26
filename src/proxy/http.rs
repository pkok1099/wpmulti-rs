//! HTTP & HTTPS CONNECT Proxy Engine (RFC 9110 & RFC 7617).
//!
//! Implements RFC 9110 Section 9.3.6 `CONNECT` method tunneling, RFC 7617 Basic Proxy Authentication,
//! and RFC 9110 Forward Proxying for absolute-URI requests.

use std::collections::HashMap;
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use base64::Engine;
use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::proxy::router::{
    DynStream, RouterConnectError, TargetAddr, TunnelRouter, TunnelSelector, connect_via_router,
    is_forbidden_destination_ip, is_valid_target_domain, parse_domain_ip_literal,
};

const MAX_HEADER_SIZE: usize = 16384;
const HEADER_READ_TIMEOUT: Duration = Duration::from_secs(30);
/// Idle bound for each read step while forwarding a proxied HTTP
/// request/response: no byte may stall longer than this (audit run-1,
/// `src/proxy/http.rs:forward_upstream_response-unbounded-copy-no-timeout`).
/// 30 s matches the header-read timeout.
const FORWARD_IDLE_TIMEOUT: Duration = Duration::from_secs(30);
/// Total-size bound for one forwarded upstream response and for one
/// forwarded request body (audit run-1,
/// `src/proxy/http.rs:forward_upstream_response-unbounded-copy-no-timeout`):
/// generous enough for large legitimate downloads/uploads, but a
/// never-ending stream can no longer hold a listener permit forever.
const MAX_FORWARD_BODY_BYTES: u64 = 1 << 30;

/// Copy from `reader` to `writer` until EOF or `limit` bytes, aborting
/// when no byte arrives within `idle_timeout`. Each read is capped at
/// the remaining limit, so a reader offering more than the limit (e.g.
/// body bytes already buffered past a declared Content-Length) stops
/// the copy at exactly `limit` instead of failing. Returns the bytes
/// copied.
pub(crate) async fn copy_limited_idle<R: AsyncRead + Unpin, W: AsyncWrite + Unpin>(
    reader: &mut R,
    writer: &mut W,
    limit: u64,
    idle_timeout: Duration,
) -> io::Result<u64> {
    // Heap buffer: an 8 KiB stack buffer would push this future (and
    // every caller awaiting it) toward the large-future threshold.
    let mut buf = Box::new([0u8; 8192]);
    let mut copied: u64 = 0;
    loop {
        if copied >= limit {
            break;
        }
        let read_len = (limit - copied).min(buf.len() as u64) as usize;
        let Some(read_buf) = buf.get_mut(..read_len) else {
            break;
        };
        let n = match tokio::time::timeout(idle_timeout, reader.read(read_buf)).await {
            Ok(Ok(0)) => break,
            Ok(Ok(n)) => n,
            Ok(Err(e)) => return Err(e),
            Err(_) => {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "forward copy idle timed out",
                ));
            }
        };
        let n_u64 = n as u64;
        let Some(chunk) = buf.get(..n) else {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "forward copy read overran its buffer",
            ));
        };
        writer.write_all(chunk).await?;
        copied += n_u64;
    }
    writer.flush().await?;
    Ok(copied)
}

/// Parses authority-form string `host:port` or `[ipv6]:port`.
pub fn parse_authority(authority: &str) -> Option<(String, u16)> {
    let auth = authority.trim();
    if auth.contains('@') {
        return None;
    }
    if let Some(rest) = auth.strip_prefix('[') {
        let (host, port_str) = rest.split_once("]:")?;
        if host.is_empty() || host.parse::<std::net::Ipv6Addr>().is_err() {
            return None;
        }
        let port: u16 = port_str.parse().ok()?;
        if port == 0 {
            return None;
        }
        Some((host.to_string(), port))
    } else {
        let (host, port_str) = auth.split_once(':')?;
        if host.is_empty() || host.contains('[') || host.contains(']') {
            return None;
        }
        let port: u16 = port_str.parse().ok()?;
        if port == 0 {
            return None;
        }
        Some((host.to_string(), port))
    }
}

fn decode_basic_auth_header(header_val: &str) -> Option<(String, String)> {
    let b64 = header_val
        .strip_prefix("Basic ")
        .or_else(|| header_val.strip_prefix("basic "))?;
    let decoded = base64::prelude::BASE64_STANDARD.decode(b64.trim()).ok()?;
    let mut s = String::from_utf8(decoded).ok()?;
    // Split the single decoded buffer in place instead of copying
    // user and password out of it (two extra allocations per request).
    let idx = s.find(':')?;
    let pass = s.split_off(idx + 1);
    s.truncate(idx);
    Some((s, pass))
}

/// Extracts and decodes RFC 7617 Basic credentials from `Proxy-Authorization` header.
pub fn extract_basic_auth<S: std::hash::BuildHasher>(
    headers: &HashMap<String, String, S>,
) -> Option<(String, String)> {
    let header_val = headers.get("proxy-authorization")?;
    decode_basic_auth_header(header_val)
}

fn extract_basic_auth_vec(headers: &[(String, String)]) -> Option<(String, String)> {
    let (_, val) = headers.iter().find(|(k, _)| k == "proxy-authorization")?;
    decode_basic_auth_header(val)
}

type ParsedHttpHeadersVec = (String, String, String, Vec<(String, String)>);

async fn read_http_request_headers_raw<R: AsyncRead + Unpin>(
    reader: &mut R,
) -> io::Result<(String, String, String, Vec<(String, String)>, Vec<u8>)> {
    let mut buf = Vec::with_capacity(1024);
    let mut chunk = [0u8; 1024];

    let read_fut = async {
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
                let (method, uri, version, headers) = parse_header_bytes_vec(header_bytes)?;
                let leftover = buf.get(pos + 4..).unwrap_or_default().to_vec();
                return Ok((method, uri, version, headers, leftover));
            }
        }

        Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "HTTP request headers too large",
        ))
    };

    tokio::time::timeout(HEADER_READ_TIMEOUT, read_fut)
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "HTTP header read timed out"))?
}

/// Reads HTTP request line and headers using buffered chunked reads.
///
/// Returns `(method, uri, version, headers, leftover_bytes)`.
pub async fn read_http_request_headers_buffered<R: AsyncRead + Unpin>(
    reader: &mut R,
) -> io::Result<(String, String, String, HashMap<String, String>, Vec<u8>)> {
    let (method, uri, version, headers_vec, leftover) =
        read_http_request_headers_raw(reader).await?;
    let headers: HashMap<String, String> = headers_vec.into_iter().collect();
    Ok((method, uri, version, headers, leftover))
}

fn validate_request_framing(headers: &[(String, String)]) -> io::Result<()> {
    let mut has_transfer_encoding = false;
    let mut content_length: Option<u64> = None;
    let mut host_count: usize = 0;

    for (name, val) in headers {
        if name == "host" {
            host_count += 1;
            if host_count > 1 {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "duplicate Host header",
                ));
            }
        }
        if name == "connection"
            && val.split(',').any(|t| {
                let t = t.trim();
                t.eq_ignore_ascii_case("content-length")
                    || t.eq_ignore_ascii_case("transfer-encoding")
                    || t.eq_ignore_ascii_case("host")
            })
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Connection header cannot reference end-to-end framing headers",
            ));
        }
        if name == "transfer-encoding" {
            if !val.trim().eq_ignore_ascii_case("chunked") {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "unsupported Transfer-Encoding",
                ));
            }
            has_transfer_encoding = true;
        } else if name == "content-length" {
            if val.is_empty() || !val.bytes().all(|b| b.is_ascii_digit()) {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "invalid Content-Length header",
                ));
            }
            let parsed = val.parse::<u64>().map_err(|_| {
                io::Error::new(io::ErrorKind::InvalidData, "Content-Length overflow")
            })?;
            if let Some(prev) = content_length
                && prev != parsed
            {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "conflicting Content-Length headers",
                ));
            }
            content_length = Some(parsed);
        } else {
            // Other headers are not framing headers.
        }
    }

    if has_transfer_encoding && content_length.is_some() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "both Transfer-Encoding and Content-Length present",
        ));
    }

    Ok(())
}

fn parse_header_bytes_vec(header_bytes: &[u8]) -> io::Result<ParsedHttpHeadersVec> {
    let header_str = std::str::from_utf8(header_bytes).map_err(|_| {
        io::Error::new(io::ErrorKind::InvalidData, "non-UTF-8 HTTP request headers")
    })?;
    let mut lines = header_str.split("\r\n");

    let req_line = lines
        .next()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "missing request line"))?;
    if req_line.contains(['\r', '\n', '\0', '\t']) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid control character in request line",
        ));
    }

    let mut parts = req_line.split(' ');
    let (Some(method), Some(uri), Some(version), None) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "malformed request line",
        ));
    };
    if method.is_empty()
        || uri.is_empty()
        || uri.chars().any(char::is_control)
        || (version != "HTTP/1.1" && version != "HTTP/1.0")
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid method, URI, or HTTP version",
        ));
    }

    let mut headers = Vec::new();
    for line in lines {
        if line.is_empty() {
            break;
        }
        if line.contains('\r') || line.contains('\n') || line.contains('\0') {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "invalid control character in header",
            ));
        }
        let Some((k, v)) = line.split_once(':') else {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "malformed header line",
            ));
        };
        if k.is_empty() || k.chars().any(char::is_whitespace) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "invalid header field name",
            ));
        }
        headers.push((k.to_ascii_lowercase(), v.trim().to_string()));
    }

    validate_request_framing(&headers)?;

    Ok((
        method.to_string(),
        uri.to_string(),
        version.to_string(),
        headers,
    ))
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
    let (method, uri, version, headers, leftover) = match read_http_request_headers_raw(&mut stream)
        .await
    {
        Ok(res) => res,
        Err(e) => {
            if e.kind() == io::ErrorKind::UnexpectedEof && e.to_string().contains("before request")
            {
                return Ok(());
            }
            if e.kind() == io::ErrorKind::TimedOut {
                send_response(
                    &mut stream,
                    "408 Request Timeout",
                    "text/plain",
                    b"Request Timeout",
                )
                .await?;
            } else {
                send_response(&mut stream, "400 Bad Request", "text/plain", b"Bad Request").await?;
            }
            return Err(e);
        }
    };

    // 2. Validate Basic Authentication if required
    let credentials = extract_basic_auth_vec(&headers);
    let cred_refs = credentials.as_ref().map(|(u, p)| (u.as_str(), p.as_str()));

    let Ok(selector) = router.authenticate(cred_refs) else {
        let resp = "HTTP/1.1 407 Proxy Authentication Required\r\n\
                    Proxy-Authenticate: Basic realm=\"wpmulti\"\r\n\
                    Content-Length: 0\r\n\
                    Connection: close\r\n\r\n";
        stream.write_all(resp.as_bytes()).await?;
        stream.flush().await?;
        return Ok(());
    };

    // 3. Dispatch based on HTTP method and URI form
    if method.eq_ignore_ascii_case("CONNECT") {
        handle_http_connect(stream, router, &selector, &uri, leftover, cred_refs).await
    } else if uri
        .get(..7)
        .is_some_and(|s| s.eq_ignore_ascii_case("http://"))
    {
        let req = ForwardRequest {
            method,
            uri,
            version,
            headers,
        };
        handle_http_forward(stream, router, &selector, req, leftover, cred_refs).await
    } else if uri
        .get(..8)
        .is_some_and(|s| s.eq_ignore_ascii_case("https://"))
    {
        send_response(
            &mut stream,
            "501 Not Implemented",
            "text/plain",
            b"HTTPS absolute-URI forwarding is not supported; use CONNECT",
        )
        .await?;
        Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "plaintext forwarding of https:// absolute-URI is disallowed",
        ))
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
    credentials: Option<(&str, &str)>,
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

    let mut tunnel_stream =
        resolve_and_connect_http_target(&mut stream, &router, selector, &host, port, credentials)
            .await?;

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

    // Bidirectional byte streaming, ending when either side closes or
    // the session idles past CONNECT_IDLE_TIMEOUT (audit run-1,
    // `wpmulti/proxy:established-connect-no-idle-timeout`).
    crate::proxy::copy_bidirectional_with_idle_timeout(
        &mut stream,
        &mut tunnel_stream,
        crate::proxy::CONNECT_IDLE_TIMEOUT,
    )
    .await?;

    Ok(())
}

struct ForwardRequest {
    method: String,
    uri: String,
    version: String,
    headers: Vec<(String, String)>,
}

fn parse_forward_uri(uri: &str) -> io::Result<(String, u16, String)> {
    let (default_port, rest) = uri
        .get(..7)
        .filter(|s| s.eq_ignore_ascii_case("http://"))
        .and_then(|_| uri.get(7..))
        .map(|r| (80u16, r))
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "invalid absolute URI"))?;

    let (authority, path) = rest.find(['/', '?', '#']).map_or_else(
        || (rest, "/".to_string()),
        |idx| {
            let auth = rest.get(..idx).unwrap_or(rest);
            let suffix = rest.get(idx..).unwrap_or("");
            let without_fragment = suffix.split('#').next().unwrap_or("");
            let path = if without_fragment.starts_with('/') {
                without_fragment.to_string()
            } else if without_fragment.starts_with('?') {
                format!("/{without_fragment}")
            } else {
                "/".to_string()
            };
            (auth, path)
        },
    );

    if authority.contains('@') {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "userinfo not allowed in proxy URI authority",
        ));
    }

    let (host, port) = if let Some(inner) = authority
        .strip_prefix('[')
        .and_then(|s| s.strip_suffix(']'))
    {
        if inner.is_empty() || inner.parse::<std::net::Ipv6Addr>().is_err() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid IPv6 host",
            ));
        }
        (inner.to_string(), default_port)
    } else if authority.starts_with('[') {
        parse_authority(authority)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "invalid authority"))?
    } else if let Some((h, p_str)) = authority.split_once(':') {
        let p = p_str.parse::<u16>().map_err(|_| {
            io::Error::new(io::ErrorKind::InvalidInput, "invalid port in authority")
        })?;
        if h.is_empty() || p == 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid host or port in authority",
            ));
        }
        (h.to_string(), p)
    } else {
        if authority.is_empty() {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "empty host"));
        }
        (authority.to_string(), default_port)
    };

    Ok((host, port, path))
}

fn parse_host_header(val: &str) -> Option<(String, u16)> {
    let trimmed = val.trim();
    if trimmed.is_empty() || trimmed.contains('@') || trimmed.chars().any(char::is_whitespace) {
        return None;
    }
    if let Some(rest) = trimmed.strip_prefix('[') {
        if let Some((h, port_str)) = rest.split_once("]:") {
            let port = port_str.parse::<u16>().ok().filter(|&p| p != 0)?;
            h.parse::<std::net::Ipv6Addr>().ok()?;
            Some((h.to_string(), port))
        } else if let Some(h) = rest.strip_suffix(']') {
            h.parse::<std::net::Ipv6Addr>().ok()?;
            Some((h.to_string(), 80))
        } else {
            None
        }
    } else if let Some((h, port_str)) = trimmed.split_once(':') {
        if h.is_empty() || h.contains('[') || h.contains(']') {
            return None;
        }
        let port = port_str.parse::<u16>().ok().filter(|&p| p != 0)?;
        Some((h.to_string(), port))
    } else {
        Some((trimmed.to_string(), 80))
    }
}

fn hosts_match(a: &str, b: &str) -> bool {
    if a.eq_ignore_ascii_case(b) {
        return true;
    }
    if let (Ok(ip_a), Ok(ip_b)) = (a.parse::<IpAddr>(), b.parse::<IpAddr>()) {
        return ip_a == ip_b;
    }
    false
}

fn validate_forward_host_header(
    headers: &[(String, String)],
    uri_host: &str,
    uri_port: u16,
) -> io::Result<Option<String>> {
    if let Some((_, host_val)) = headers.iter().find(|(k, _)| k == "host") {
        let Some((hdr_host, hdr_port)) = parse_host_header(host_val) else {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid Host header",
            ));
        };
        if !hosts_match(&hdr_host, uri_host) || hdr_port != uri_port {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "Host header does not match request-target authority",
            ));
        }
        Ok(None)
    } else {
        let authority = if uri_host.contains(':') {
            if uri_port == 80 {
                format!("[{uri_host}]")
            } else {
                format!("[{uri_host}]:{uri_port}")
            }
        } else if uri_port == 80 {
            uri_host.to_string()
        } else {
            format!("{uri_host}:{uri_port}")
        };
        Ok(Some(authority))
    }
}

async fn read_crlf_line<R: tokio::io::AsyncBufRead + Unpin>(
    reader: &mut R,
    max_len: usize,
) -> io::Result<Vec<u8>> {
    let mut line = Vec::new();
    loop {
        let n = reader.read_until(b'\n', &mut line).await?;
        if n == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "unexpected EOF in chunked body",
            ));
        }
        if line.len() > max_len {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "chunked header or trailer line too long",
            ));
        }
        if line.ends_with(b"\r\n") {
            return Ok(line);
        }
        if line.ends_with(b"\n") {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "bare LF in chunked body",
            ));
        }
    }
}

/// Read one CRLF-terminated line with an idle deadline: a stalled
/// chunked sender cannot hold the forwarding task (audit run-1,
/// `src/proxy/http.rs:forward_upstream_response-unbounded-copy-no-timeout`).
async fn read_crlf_line_timeout<R: tokio::io::AsyncBufRead + Unpin>(
    reader: &mut R,
    max_len: usize,
) -> io::Result<Vec<u8>> {
    tokio::time::timeout(FORWARD_IDLE_TIMEOUT, read_crlf_line(reader, max_len))
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "chunked body read idle timed out"))?
}

async fn forward_chunked_body<R: AsyncRead + Unpin, W: AsyncWrite + Unpin>(
    reader: R,
    writer: &mut W,
    leftover: &[u8],
    limit: u64,
) -> io::Result<()> {
    let chained = io::Cursor::new(leftover).chain(reader);
    let mut buf_reader = tokio::io::BufReader::new(chained);
    // Aggregate body bound: a chunked sender declaring endless chunks
    // cannot grow the forwarded body without bound.
    let mut total: u64 = 0;

    loop {
        let size_line = read_crlf_line_timeout(&mut buf_reader, 4096).await?;
        let line_str = std::str::from_utf8(
            size_line
                .get(..size_line.len().saturating_sub(2))
                .unwrap_or_default(),
        )
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "non-UTF-8 chunk size"))?;
        let size_hex = line_str.split(';').next().unwrap_or("").trim();
        let chunk_size = u64::from_str_radix(size_hex, 16)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "invalid chunk size"))?;

        writer.write_all(&size_line).await?;

        if chunk_size == 0 {
            loop {
                let trailer = read_crlf_line_timeout(&mut buf_reader, 8192).await?;
                writer.write_all(&trailer).await?;
                if trailer == b"\r\n" {
                    break;
                }
            }
            writer.flush().await?;
            return Ok(());
        }

        total = total.saturating_add(chunk_size);
        if total > limit {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "forward chunked body size limit exceeded",
            ));
        }
        let copied = copy_limited_idle(
            &mut (&mut buf_reader).take(chunk_size),
            writer,
            chunk_size,
            FORWARD_IDLE_TIMEOUT,
        )
        .await?;
        if copied != chunk_size {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "truncated chunk payload",
            ));
        }
        let mut crlf = [0u8; 2];
        match tokio::time::timeout(FORWARD_IDLE_TIMEOUT, buf_reader.read_exact(&mut crlf)).await {
            Ok(res) => {
                res?;
            }
            Err(_) => {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "chunked body read idle timed out",
                ));
            }
        }
        if crlf != *b"\r\n" {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "missing CRLF after chunk payload",
            ));
        }
        writer.write_all(&crlf).await?;
    }
}

async fn forward_request_body<R: AsyncRead + Unpin, W: AsyncWrite + Unpin>(
    mut client_read: R,
    upstream_write: &mut W,
    leftover: &[u8],
    content_length: Option<u64>,
    is_chunked: bool,
) -> io::Result<()> {
    if is_chunked {
        forward_chunked_body(
            client_read,
            upstream_write,
            leftover,
            MAX_FORWARD_BODY_BYTES,
        )
        .await?;
    } else if let Some(cl) = content_length
        && cl > 0
    {
        if cl > MAX_FORWARD_BODY_BYTES {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "request body exceeds size limit",
            ));
        }
        let from_leftover = (leftover.len() as u64).min(cl) as usize;
        if let Some(slice) = leftover.get(..from_leftover)
            && !slice.is_empty()
        {
            upstream_write.write_all(slice).await?;
        }
        let remaining = cl - from_leftover as u64;
        if remaining > 0 {
            let copied = copy_limited_idle(
                &mut (&mut client_read).take(remaining),
                upstream_write,
                remaining,
                FORWARD_IDLE_TIMEOUT,
            )
            .await?;
            if copied != remaining {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "truncated HTTP request body",
                ));
            }
        }
        upstream_write.flush().await?;
    } else {
        // No body to forward.
    }
    Ok(())
}

fn build_forward_request_head(
    req: &ForwardRequest,
    path: &str,
    synthesized_host: Option<&str>,
) -> String {
    // Borrowed token slices: header names are already lowercased at
    // parse time, so compare case-insensitively instead of allocating
    // a lowercased String per token.
    let conn_tokens: Vec<&str> = req
        .headers
        .iter()
        .filter(|(k, _)| k == "connection")
        .flat_map(|(_, v)| v.split(','))
        .map(str::trim)
        .filter(|t| !t.is_empty())
        .collect();

    let mut req_buf = format!("{} {} {}\r\n", req.method, path, req.version);
    if let Some(synth_host) = synthesized_host {
        let _ = std::fmt::Write::write_fmt(&mut req_buf, format_args!("host: {synth_host}\r\n"));
    }
    for (k, v) in &req.headers {
        if matches!(
            k.as_str(),
            "proxy-authorization"
                | "proxy-connection"
                | "proxy-authenticate"
                | "connection"
                | "keep-alive"
                | "te"
                | "upgrade"
                | "trailer"
        ) || (!matches!(k.as_str(), "content-length" | "transfer-encoding" | "host")
            && conn_tokens
                .iter()
                .any(|t| t.eq_ignore_ascii_case(k.as_str())))
        {
            continue;
        }
        let _ = std::fmt::Write::write_fmt(&mut req_buf, format_args!("{k}: {v}\r\n"));
    }
    req_buf.push_str("connection: close\r\n\r\n");
    req_buf
}

async fn validate_target_host_before_routing<S: AsyncWrite + Unpin>(
    stream: &mut S,
    host: &str,
) -> io::Result<Option<IpAddr>> {
    let literal_ip = parse_domain_ip_literal(host);
    if let Some(ip) = literal_ip {
        if is_forbidden_destination_ip(ip) {
            send_response(
                stream,
                "403 Forbidden",
                "text/plain",
                b"Forbidden Destination",
            )
            .await?;
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                format!("blocked forbidden destination IP: {ip}"),
            ));
        }
    } else if !is_valid_target_domain(host) {
        send_response(stream, "400 Bad Request", "text/plain", b"Invalid Host").await?;
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "invalid domain in proxy target",
        ));
    } else {
        // Valid domain; continue to routing.
    }
    Ok(literal_ip)
}

async fn resolve_and_connect_http_target<S: AsyncWrite + Unpin>(
    stream: &mut S,
    router: &Arc<dyn TunnelRouter>,
    selector: &TunnelSelector,
    host: &str,
    port: u16,
    credentials: Option<(&str, &str)>,
) -> io::Result<DynStream> {
    let literal_ip = validate_target_host_before_routing(stream, host).await?;
    let target = literal_ip.map_or_else(
        || TargetAddr::Domain(host.to_string(), port),
        |ip| TargetAddr::Ip(SocketAddr::new(ip, port)),
    );

    match connect_via_router(router, selector, &target, credentials).await {
        Ok(s) => Ok(s),
        Err(RouterConnectError::SelectTunnel(e)) => {
            // Log exactly like the SOCKS5 path: docs §4 promises this
            // line for the pool-empty case, and without it an HTTP user
            // has no daemon-side trace of why the request got a 503.
            tracing::warn!("Failed to select tunnel for {:?}: {}", selector, e);
            // A bad tunnel name (`NotFound`) is 404; a valid selector
            // whose pool is empty right now (`NotConnected` — no healthy
            // tunnel to attempt) is 503, so a client can tell "you
            // mistyped the name" apart from "all tunnels are down". A
            // dead tunnel stays 502 below. The body still carries the
            // exact error.
            let (status, prefix) = if e.kind() == io::ErrorKind::NotConnected {
                ("503 Service Unavailable", "No Healthy Tunnel")
            } else {
                ("404 Not Found", "Tunnel Not Found")
            };
            let msg = format!("{prefix}: {e}\n");
            send_response(stream, status, "text/plain", msg.as_bytes()).await?;
            Err(e)
        }
        Err(RouterConnectError::ForbiddenDestination(e)) => {
            send_response(
                stream,
                "403 Forbidden",
                "text/plain",
                b"Forbidden Destination\n",
            )
            .await?;
            Err(e)
        }
        Err(RouterConnectError::DnsResolution(e)) => {
            let msg = format!("DNS Resolution Failed: {e}\n");
            send_response(stream, "502 Bad Gateway", "text/plain", msg.as_bytes()).await?;
            Err(e)
        }
        Err(RouterConnectError::TcpConnect(e)) => {
            let msg = format!("Connection Failed: {e}\n");
            send_response(stream, "502 Bad Gateway", "text/plain", msg.as_bytes()).await?;
            Err(e)
        }
    }
}

/// How an upstream response body is framed (audit run-1,
/// `src/proxy/http.rs:forward_upstream_response-verbatim-no-framing-validation`).
pub(crate) enum ResponseBodyFraming {
    /// Exactly `n` body bytes follow the head.
    ContentLength(u64),
    /// Chunked transfer coding; ends at the terminal chunk.
    Chunked,
    /// No framing: the body runs until the upstream closes.
    UntilClose,
}

/// Parse an upstream response head (status line + headers, up to and
/// including the trailing blank line) into its status code and body
/// framing. Rejects a malformed status line, duplicate/conflicting
/// Content-Length, Content-Length combined with Transfer-Encoding, and
/// any Transfer-Encoding other than `chunked`.
/// Parse an upstream response status line (`HTTP/1.1 200 OK`) into its
/// status code, rejecting an unsupported version or a malformed code.
fn parse_response_status_line(status_line: &str) -> io::Result<u16> {
    let mut parts = status_line.splitn(3, ' ');
    let version = parts.next().unwrap_or("");
    let Some(code_str) = parts.next() else {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "malformed upstream status line",
        ));
    };
    if version != "HTTP/1.1" && version != "HTTP/1.0" {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "unsupported upstream HTTP version",
        ));
    }
    if code_str.len() != 3 || !code_str.bytes().all(|b| b.is_ascii_digit()) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "malformed upstream status code",
        ));
    }
    code_str
        .parse()
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "malformed upstream status code"))
}

pub(crate) fn parse_response_head(head: &[u8]) -> io::Result<(u16, ResponseBodyFraming)> {
    let head_str = std::str::from_utf8(head).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "non-UTF-8 upstream response head",
        )
    })?;
    let mut lines = head_str.split("\r\n");
    let status_line = lines.next().ok_or_else(|| {
        io::Error::new(io::ErrorKind::InvalidData, "missing upstream status line")
    })?;
    let status = parse_response_status_line(status_line)?;

    let mut content_length: Option<u64> = None;
    let mut chunked = false;
    for line in lines {
        if line.is_empty() {
            break;
        }
        let Some((k, v)) = line.split_once(':') else {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "malformed upstream header line",
            ));
        };
        if k.is_empty() || k.chars().any(char::is_whitespace) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "invalid upstream header field name",
            ));
        }
        if k.eq_ignore_ascii_case("content-length") {
            let val = v.trim();
            if val.is_empty() || !val.bytes().all(|b| b.is_ascii_digit()) {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "invalid upstream Content-Length",
                ));
            }
            let parsed: u64 = val.parse().map_err(|_| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    "upstream Content-Length overflow",
                )
            })?;
            if let Some(prev) = content_length
                && prev != parsed
            {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "conflicting upstream Content-Length headers",
                ));
            }
            content_length = Some(parsed);
        } else if k.eq_ignore_ascii_case("transfer-encoding") {
            if chunked || !v.trim().eq_ignore_ascii_case("chunked") {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "unsupported upstream Transfer-Encoding",
                ));
            }
            chunked = true;
        } else {
            // Other headers are not framing headers.
        }
    }
    if content_length.is_some() && chunked {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "upstream Content-Length and Transfer-Encoding both present",
        ));
    }

    // 204/304 never have a body; 1xx heads are interim (the caller
    // forwards them and reads the final head).
    let framing = if status == 204 || status == 304 || (100..200).contains(&status) {
        ResponseBodyFraming::ContentLength(0)
    } else if let Some(len) = content_length {
        ResponseBodyFraming::ContentLength(len)
    } else if chunked {
        ResponseBodyFraming::Chunked
    } else {
        ResponseBodyFraming::UntilClose
    };
    Ok((status, framing))
}

/// Read one upstream response head (up to `MAX_HEADER_SIZE` bytes),
/// returning the head bytes (including the trailing blank line) and any
/// body bytes already read past it. Each read is bounded by
/// `FORWARD_IDLE_TIMEOUT`.
async fn read_response_head<R: AsyncRead + Unpin>(
    reader: &mut R,
) -> io::Result<(Vec<u8>, Vec<u8>)> {
    let mut buf = Vec::with_capacity(4096);
    // Heap chunk: a 4 KiB stack buffer would push this future (and
    // every caller awaiting it) toward the large-future threshold.
    let mut chunk = Box::new([0u8; 4096]);
    loop {
        if let Some(pos) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
            let head = buf.get(..pos + 4).unwrap_or_default().to_vec();
            let leftover = buf.get(pos + 4..).unwrap_or_default().to_vec();
            return Ok((head, leftover));
        }
        if buf.len() >= MAX_HEADER_SIZE {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "upstream response head too large",
            ));
        }
        let n = match tokio::time::timeout(FORWARD_IDLE_TIMEOUT, reader.read(&mut chunk[..])).await
        {
            Ok(Ok(0)) => {
                if buf.is_empty() {
                    return Err(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        "upstream closed without sending response",
                    ));
                }
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "truncated upstream response head",
                ));
            }
            Ok(Ok(n)) => n,
            Ok(Err(e)) => return Err(e),
            Err(_) => {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "upstream response head read timed out",
                ));
            }
        };
        if let Some(slice) = chunk.get(..n) {
            buf.extend_from_slice(slice);
        }
        if buf.len() > MAX_HEADER_SIZE {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "upstream response head too large",
            ));
        }
    }
}

async fn forward_upstream_response<R: AsyncRead + Unpin, W: AsyncWrite + Unpin>(
    mut upstream_read: R,
    mut client_write: W,
) -> io::Result<()> {
    // Validate the response head before copying any body: the status
    // line and Content-Length / Transfer-Encoding framing are parsed,
    // and the copy stops at the end of the first declared response, so
    // bytes past its framing are never forwarded to the client (audit
    // run-1, `...-verbatim-no-framing-validation`). The connection is
    // closed when this returns, so no pipelined second response can
    // ride on the same connection either.
    let mut interim_heads = 0;
    loop {
        let (head, leftover) = match read_response_head(&mut upstream_read).await {
            Ok(res) => res,
            Err(e) => {
                let body = if e.kind() == io::ErrorKind::UnexpectedEof {
                    b"Empty Upstream Response".as_slice()
                } else {
                    b"Upstream Read Failed".as_slice()
                };
                let _ =
                    send_response(&mut client_write, "502 Bad Gateway", "text/plain", body).await;
                return Err(e);
            }
        };
        let (status, framing) = match parse_response_head(&head) {
            Ok(parsed) => parsed,
            Err(e) => {
                let _ = send_response(
                    &mut client_write,
                    "502 Bad Gateway",
                    "text/plain",
                    b"Upstream Read Failed",
                )
                .await;
                return Err(e);
            }
        };
        client_write.write_all(&head).await?;
        if (100..200).contains(&status) {
            // Interim head: forward it and read the final head. Bytes
            // after an interim head cannot be a body, so any are a
            // framing violation.
            if !leftover.is_empty() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "bytes after upstream interim response head",
                ));
            }
            interim_heads += 1;
            if interim_heads > 4 {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "too many upstream interim responses",
                ));
            }
            continue;
        }
        // Body budget: the head already counts toward the total bound.
        let budget = MAX_FORWARD_BODY_BYTES.saturating_sub(head.len() as u64);
        match framing {
            ResponseBodyFraming::ContentLength(len) => {
                let mut body_reader = io::Cursor::new(leftover).chain(upstream_read);
                // EOF before `len` ends the response: the upstream
                // closed the connection, and the client detects the
                // short body from the declared length.
                copy_limited_idle(
                    &mut body_reader,
                    &mut client_write,
                    len.min(budget),
                    FORWARD_IDLE_TIMEOUT,
                )
                .await?;
            }
            ResponseBodyFraming::Chunked => {
                forward_chunked_body(upstream_read, &mut client_write, &leftover, budget).await?;
            }
            ResponseBodyFraming::UntilClose => {
                let mut body_reader = io::Cursor::new(leftover).chain(upstream_read);
                copy_limited_idle(
                    &mut body_reader,
                    &mut client_write,
                    budget,
                    FORWARD_IDLE_TIMEOUT,
                )
                .await?;
            }
        }
        client_write.flush().await?;
        return Ok(());
    }
}

/// Executes RFC 9110 Forward Proxy request forwarding for absolute URIs.
async fn handle_http_forward<S: AsyncRead + AsyncWrite + Unpin>(
    mut stream: S,
    router: Arc<dyn TunnelRouter>,
    selector: &TunnelSelector,
    req: ForwardRequest,
    leftover: Vec<u8>,
    credentials: Option<(&str, &str)>,
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

    let synthesized_host = match validate_forward_host_header(&req.headers, &host, port) {
        Ok(h) => h,
        Err(e) => {
            send_response(
                &mut stream,
                "400 Bad Request",
                "text/plain",
                b"Invalid or Mismatched Host Header",
            )
            .await?;
            return Err(e);
        }
    };

    let mut tunnel_stream =
        resolve_and_connect_http_target(&mut stream, &router, selector, &host, port, credentials)
            .await?;

    let content_length = req
        .headers
        .iter()
        .find(|(k, _)| k == "content-length")
        .and_then(|(_, v)| v.parse::<u64>().ok());
    let is_chunked = req
        .headers
        .iter()
        .any(|(k, v)| k == "transfer-encoding" && v.trim().eq_ignore_ascii_case("chunked"));

    let req_buf = build_forward_request_head(&req, &path, synthesized_host.as_deref());

    // Forward request line and headers to destination server
    if let Err(e) = tunnel_stream.write_all(req_buf.as_bytes()).await {
        let _ = send_response(
            &mut stream,
            "502 Bad Gateway",
            "text/plain",
            b"Upstream Write Failed",
        )
        .await;
        return Err(e);
    }
    if let Err(e) = tunnel_stream.flush().await {
        let _ = send_response(
            &mut stream,
            "502 Bad Gateway",
            "text/plain",
            b"Upstream Flush Failed",
        )
        .await;
        return Err(e);
    }

    let (client_read, client_write) = tokio::io::split(stream);
    let (upstream_read, mut upstream_write) = tokio::io::split(tunnel_stream);

    let req_fut = forward_request_body(
        client_read,
        &mut upstream_write,
        &leftover,
        content_length,
        is_chunked,
    );
    let resp_fut = forward_upstream_response(upstream_read, client_write);

    tokio::try_join!(req_fut, resp_fut)?;

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
