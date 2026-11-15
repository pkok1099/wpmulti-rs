use std::net::SocketAddr;
use tokio::io::AsyncWriteExt;

use super::http_client::read_http_headers;

pub struct AdminTestClient {
    admin_addr: SocketAddr,
    auth_token: Option<String>,
}

impl AdminTestClient {
    pub fn new(admin_addr: SocketAddr, auth_token: Option<String>) -> Self {
        Self {
            admin_addr,
            auth_token,
        }
    }

    pub fn admin_addr(&self) -> SocketAddr {
        self.admin_addr
    }

    /// Send HTTP request and parse JSON response body
    async fn request_json(
        &self,
        method: &str,
        path: &str,
        body_json: Option<&serde_json::Value>,
    ) -> std::io::Result<(u16, serde_json::Value)> {
        let mut stream = tokio::net::TcpStream::connect(self.admin_addr).await?;

        let mut req = format!(
            "{} {} HTTP/1.1\r\nHost: {}\r\nConnection: close\r\n",
            method, path, self.admin_addr
        );
        if let Some(token) = &self.auth_token {
            req.push_str(&format!("Authorization: Bearer {}\r\n", token));
        }

        let body_bytes = match body_json {
            Some(v) => {
                let bytes = serde_json::to_vec(v)
                    .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidInput, e))?;
                req.push_str(&format!(
                    "Content-Type: application/json\r\nContent-Length: {}\r\n\r\n",
                    bytes.len()
                ));
                bytes
            }
            None => {
                req.push_str("Content-Length: 0\r\n\r\n");
                Vec::new()
            }
        };

        stream.write_all(req.as_bytes()).await?;
        if !body_bytes.is_empty() {
            stream.write_all(&body_bytes).await?;
        }

        let (status, _reason, _headers, body) = read_http_headers(&mut stream).await?;
        let json_val = if !body.is_empty() {
            serde_json::from_slice(&body)
                .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?
        } else {
            serde_json::Value::Null
        };

        Ok((status, json_val))
    }

    /// GET /health
    pub async fn get_health(&self) -> std::io::Result<serde_json::Value> {
        let (status, val) = self.request_json("GET", "/health", None).await?;
        if status != 200 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::Other,
                format!("health returned status {}", status),
            ));
        }
        Ok(val)
    }

    /// GET /status
    pub async fn get_status(&self) -> std::io::Result<serde_json::Value> {
        let (status, val) = self.request_json("GET", "/status", None).await?;
        if status != 200 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::Other,
                format!("status returned status {}", status),
            ));
        }
        Ok(val)
    }

    /// GET /tunnels with optional query string
    pub async fn list_tunnels(&self, query: Option<&str>) -> std::io::Result<serde_json::Value> {
        let path = match query {
            Some(q) => format!("/tunnels?{}", q),
            None => "/tunnels".to_string(),
        };
        let (status, val) = self.request_json("GET", &path, None).await?;
        if status != 200 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::Other,
                format!("list tunnels returned status {}", status),
            ));
        }
        Ok(val)
    }

    /// GET /tunnels/:id
    pub async fn get_tunnel(&self, id: &str) -> std::io::Result<serde_json::Value> {
        let path = format!("/tunnels/{}", id);
        let (status, val) = self.request_json("GET", &path, None).await?;
        if status != 200 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                format!("tunnel {} returned status {}", id, status),
            ));
        }
        Ok(val)
    }

    /// POST /tunnels/:id/activate
    pub async fn activate_tunnel(&self, id: &str) -> std::io::Result<serde_json::Value> {
        let path = format!("/tunnels/{}/activate", id);
        let (status, val) = self.request_json("POST", &path, None).await?;
        if status != 200 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::Other,
                format!("activate returned status {}", status),
            ));
        }
        Ok(val)
    }

    /// POST /tunnels/:id/deactivate
    pub async fn deactivate_tunnel(&self, id: &str) -> std::io::Result<serde_json::Value> {
        let path = format!("/tunnels/{}/deactivate", id);
        let (status, val) = self.request_json("POST", &path, None).await?;
        if status != 200 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::Other,
                format!("deactivate returned status {}", status),
            ));
        }
        Ok(val)
    }

    /// POST /reload
    pub async fn trigger_reload(&self) -> std::io::Result<serde_json::Value> {
        let (status, val) = self.request_json("POST", "/reload", None).await?;
        if status != 200 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::Other,
                format!("reload returned status {}", status),
            ));
        }
        Ok(val)
    }

    /// GET /metrics (Prometheus exposition format)
    pub async fn get_metrics(&self) -> std::io::Result<String> {
        let mut stream = tokio::net::TcpStream::connect(self.admin_addr).await?;

        let mut req = format!(
            "GET /metrics HTTP/1.1\r\nHost: {}\r\nConnection: close\r\n",
            self.admin_addr
        );
        if let Some(token) = &self.auth_token {
            req.push_str(&format!("Authorization: Bearer {}\r\n", token));
        }
        req.push_str("\r\n");

        stream.write_all(req.as_bytes()).await?;
        let (status, _reason, _headers, body) = read_http_headers(&mut stream).await?;
        if status != 200 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::Other,
                format!("metrics returned status {}", status),
            ));
        }
        Ok(String::from_utf8_lossy(&body).to_string())
    }

    /// Scrapes metrics and extracts a metric value matching name and label criteria
    pub async fn get_metric_value(&self, metric_name: &str, labels: &[(&str, &str)]) -> std::io::Result<f64> {
        let text = self.get_metrics().await?;
        Self::parse_metric_from_text(&text, metric_name, labels).ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::NotFound,
                format!("metric {} with labels {:?} not found", metric_name, labels),
            )
        })
    }

    /// Static parser for Prometheus metric output text
    pub fn parse_metric_from_text(text: &str, metric_name: &str, labels: &[(&str, &str)]) -> Option<f64> {
        for line in text.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            if let Some((metric_part, val_part)) = line.split_once(' ') {
                if metric_part.starts_with(metric_name) {
                    let mut matched = true;
                    for &(k, v) in labels {
                        let needle = format!("{}=\"{}\"", k, v);
                        if !metric_part.contains(&needle) {
                            matched = false;
                            break;
                        }
                    }
                    if matched {
                        if let Ok(val) = val_part.trim().parse::<f64>() {
                            return Some(val);
                        }
                    }
                }
            }
        }
        None
    }
}
