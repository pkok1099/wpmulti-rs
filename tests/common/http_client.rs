use std::collections::HashMap;
use std::net::SocketAddr;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

#[derive(Debug, Clone)]
pub struct HttpResponse {
    pub status_code: u16,
    pub reason: String,
    pub headers: HashMap<String, String>,
    pub body: Vec<u8>,
}

impl HttpResponse {
    pub fn is_success(&self) -> bool {
        (200..300).contains(&self.status_code)
    }

    pub fn is_proxy_auth_required(&self) -> bool {
        self.status_code == 407
    }
}

/// Helper to read HTTP status line and headers terminated by \r\n\r\n without consuming tunnel bytes
pub async fn read_http_headers<R: tokio::io::AsyncRead + Unpin>(
    reader: &mut R,
) -> std::io::Result<(u16, String, HashMap<String, String>, Vec<u8>)> {
    let mut header_bytes = Vec::new();
    let mut byte_buf = [0u8; 1];

    while header_bytes.len() < 16384 {
        reader.read_exact(&mut byte_buf).await?;
        header_bytes.push(byte_buf[0]);
        if header_bytes.ends_with(b"\r\n\r\n") {
            break;
        }
    }

    if !header_bytes.ends_with(b"\r\n\r\n") {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "http header too large or truncated",
        ));
    }

    let header_str = String::from_utf8_lossy(&header_bytes);
    let mut lines = header_str.split("\r\n");
    let status_line = lines
        .next()
        .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::InvalidData, "empty status line"))?;

    let parts: Vec<&str> = status_line.splitn(3, ' ').collect();
    if parts.len() < 2 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "invalid status line",
        ));
    }
    let status_code: u16 = parts[1]
        .parse()
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
    let reason = parts.get(2).unwrap_or(&"").to_string();

    let mut headers = HashMap::new();
    for line in lines {
        if line.is_empty() {
            break;
        }
        if let Some((k, v)) = line.split_once(':') {
            headers.insert(k.trim().to_ascii_lowercase(), v.trim().to_string());
        }
    }

    // Read remaining body if Content-Length specified
    let mut body = Vec::new();
    if let Some(len_str) = headers.get("content-length")
        && let Ok(content_len) = len_str.parse::<usize>()
        && content_len > 0
    {
        body.resize(content_len, 0);
        reader.read_exact(&mut body).await?;
    }

    Ok((status_code, reason, headers, body))
}

pub struct HttpProxyTestClient;

impl HttpProxyTestClient {
    /// Formats RFC 7617 Basic Proxy-Authorization header value
    pub fn basic_auth_header(username: &str, password: &str) -> String {
        use base64::Engine;
        let credentials = format!("{}:{}", username, password);
        let encoded = base64::prelude::BASE64_STANDARD.encode(credentials.as_bytes());
        format!("Basic {}", encoded)
    }

    /// Establishes RFC 9110 CONNECT tunnel to authority target, returning raw TcpStream on 200
    pub async fn connect_tunnel(
        proxy_addr: SocketAddr,
        target: &str, // authority-form: "host:port"
        auth: Option<(&str, &str)>,
    ) -> std::io::Result<tokio::net::TcpStream> {
        let mut stream = tokio::net::TcpStream::connect(proxy_addr).await?;

        let mut req = format!(
            "CONNECT {} HTTP/1.1\r\nHost: {}\r\nProxy-Connection: keep-alive\r\nUser-Agent: wpmulti-test-client/0.1.0\r\n",
            target, target
        );
        if let Some((user, pass)) = auth {
            req.push_str(&format!(
                "Proxy-Authorization: {}\r\n",
                Self::basic_auth_header(user, pass)
            ));
        }
        req.push_str("\r\n");

        stream.write_all(req.as_bytes()).await?;

        let (status, reason, _headers, _body) = read_http_headers(&mut stream).await?;
        if status != 200 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::ConnectionRefused,
                format!("http connect proxy failed: status {} {}", status, reason),
            ));
        }

        Ok(stream)
    }

    /// Tests 407 challenge and response flow
    pub async fn connect_tunnel_with_challenge(
        proxy_addr: SocketAddr,
        target: &str,
        user: &str,
        pass: &str,
    ) -> std::io::Result<tokio::net::TcpStream> {
        // Step 1: Send unauthenticated request -> expect 407
        let mut stream = tokio::net::TcpStream::connect(proxy_addr).await?;
        let unauth_req = format!("CONNECT {} HTTP/1.1\r\nHost: {}\r\n\r\n", target, target);
        stream.write_all(unauth_req.as_bytes()).await?;

        let (status, _, headers, _) = read_http_headers(&mut stream).await?;
        if status != 407 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("expected 407 proxy authentication required, got {}", status),
            ));
        }
        if !headers.contains_key("proxy-authenticate") {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "missing Proxy-Authenticate header in 407 response",
            ));
        }

        // Step 2: Re-connect with credentials
        Self::connect_tunnel(proxy_addr, target, Some((user, pass))).await
    }

    /// Executes raw CONNECT request for negative/boundary testing (e.g. malformed URI, missing port, bad auth)
    pub async fn send_raw(
        proxy_addr: SocketAddr,
        raw_request: &str,
    ) -> std::io::Result<(HttpResponse, tokio::net::TcpStream)> {
        let mut stream = tokio::net::TcpStream::connect(proxy_addr).await?;
        stream.write_all(raw_request.as_bytes()).await?;

        let (status_code, reason, headers, body) = read_http_headers(&mut stream).await?;
        Ok((
            HttpResponse {
                status_code,
                reason,
                headers,
                body,
            },
            stream,
        ))
    }

    /// Executes forward proxy request (GET http://... HTTP/1.1)
    pub async fn forward_request(
        proxy_addr: SocketAddr,
        method: &str,
        uri: &str, // absolute-URI e.g. "http://example.com/api/test"
        auth: Option<(&str, &str)>,
    ) -> std::io::Result<HttpResponse> {
        let mut stream = tokio::net::TcpStream::connect(proxy_addr).await?;

        let mut req = format!("{} {} HTTP/1.1\r\nConnection: close\r\n", method, uri);
        if let Some((user, pass)) = auth {
            req.push_str(&format!(
                "Proxy-Authorization: {}\r\n",
                Self::basic_auth_header(user, pass)
            ));
        }
        req.push_str("\r\n");

        stream.write_all(req.as_bytes()).await?;
        let (status_code, reason, headers, body) = read_http_headers(&mut stream).await?;

        Ok(HttpResponse {
            status_code,
            reason,
            headers,
            body,
        })
    }
}
