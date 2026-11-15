//! Application state and business logic for the interactive TUI monitor.

use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::config::TuiSortField;
use crate::core::{ReloadReport, TunnelManager, TunnelState, TunnelSummary};

/// Data source powering the TUI dashboard: either an in-process manager or a remote Admin API.
#[derive(Clone)]
pub enum TuiDataSource {
    InProcess(Arc<TunnelManager>),
    Remote {
        admin_url: String,
        auth_token: Option<String>,
    },
}

impl TuiDataSource {
    /// Retrieve list of all tunnels from the data source.
    pub async fn fetch_tunnels(&self) -> Result<Vec<TunnelSummary>, String> {
        match self {
            TuiDataSource::InProcess(mgr) => Ok(mgr.get_tunnel_stats()),
            TuiDataSource::Remote {
                admin_url,
                auth_token,
            } => {
                let url = admin_url.trim_end_matches('/');
                let host_port = url
                    .strip_prefix("http://")
                    .or_else(|| url.strip_prefix("https://"))
                    .unwrap_or(url);

                let mut stream = tokio::net::TcpStream::connect(host_port)
                    .await
                    .map_err(|e| format!("Failed to connect to Admin API at '{}': {}", url, e))?;

                let mut req = format!(
                    "GET /tunnels HTTP/1.1\r\nHost: {}\r\nConnection: close\r\n",
                    host_port
                );
                if let Some(token) = auth_token {
                    req.push_str(&format!("Authorization: Bearer {}\r\n", token));
                }
                req.push_str("\r\n");

                stream
                    .write_all(req.as_bytes())
                    .await
                    .map_err(|e| format!("Write failed: {}", e))?;

                let mut resp_buf = Vec::new();
                stream
                    .read_to_end(&mut resp_buf)
                    .await
                    .map_err(|e| format!("Read failed: {}", e))?;

                let body_offset = resp_buf
                    .windows(4)
                    .position(|w| w == b"\r\n\r\n")
                    .map(|p| p + 4)
                    .unwrap_or(0);

                let tunnels: Vec<TunnelSummary> = serde_json::from_slice(&resp_buf[body_offset..])
                    .map_err(|e| format!("Failed to deserialize tunnels response: {}", e))?;
                Ok(tunnels)
            }
        }
    }

    /// Activate a dormant or suspended tunnel.
    pub async fn activate_tunnel(&self, id: &str) -> Result<(), String> {
        match self {
            TuiDataSource::InProcess(mgr) => mgr
                .activate_tunnel(id)
                .await
                .map(|_| ())
                .map_err(|e| e.to_string()),
            TuiDataSource::Remote {
                admin_url,
                auth_token,
            } => {
                let url = admin_url.trim_end_matches('/');
                let host_port = url
                    .strip_prefix("http://")
                    .or_else(|| url.strip_prefix("https://"))
                    .unwrap_or(url);

                let mut stream = tokio::net::TcpStream::connect(host_port)
                    .await
                    .map_err(|e| e.to_string())?;

                let mut req = format!(
                    "POST /tunnels/{}/activate HTTP/1.1\r\nHost: {}\r\nContent-Length: 0\r\nConnection: close\r\n",
                    id, host_port
                );
                if let Some(tok) = auth_token {
                    req.push_str(&format!("Authorization: Bearer {}\r\n", tok));
                }
                req.push_str("\r\n");

                stream.write_all(req.as_bytes()).await.map_err(|e| e.to_string())?;
                let mut buf = Vec::new();
                stream.read_to_end(&mut buf).await.map_err(|e| e.to_string())?;
                Ok(())
            }
        }
    }

    /// Suspend an active tunnel.
    pub async fn suspend_tunnel(&self, id: &str) -> Result<(), String> {
        match self {
            TuiDataSource::InProcess(mgr) => mgr
                .suspend_tunnel(id)
                .await
                .map_err(|e| e.to_string()),
            TuiDataSource::Remote {
                admin_url,
                auth_token,
            } => {
                let url = admin_url.trim_end_matches('/');
                let host_port = url
                    .strip_prefix("http://")
                    .or_else(|| url.strip_prefix("https://"))
                    .unwrap_or(url);

                let mut stream = tokio::net::TcpStream::connect(host_port)
                    .await
                    .map_err(|e| e.to_string())?;

                let mut req = format!(
                    "POST /tunnels/{}/suspend HTTP/1.1\r\nHost: {}\r\nContent-Length: 0\r\nConnection: close\r\n",
                    id, host_port
                );
                if let Some(tok) = auth_token {
                    req.push_str(&format!("Authorization: Bearer {}\r\n", tok));
                }
                req.push_str("\r\n");

                stream.write_all(req.as_bytes()).await.map_err(|e| e.to_string())?;
                let mut buf = Vec::new();
                stream.read_to_end(&mut buf).await.map_err(|e| e.to_string())?;
                Ok(())
            }
        }
    }

    /// Trigger configuration reload.
    pub async fn reload(&self) -> Result<ReloadReport, String> {
        match self {
            TuiDataSource::InProcess(mgr) => mgr
                .reload()
                .await
                .map_err(|e| e.to_string()),
            TuiDataSource::Remote {
                admin_url,
                auth_token,
            } => {
                let url = admin_url.trim_end_matches('/');
                let host_port = url
                    .strip_prefix("http://")
                    .or_else(|| url.strip_prefix("https://"))
                    .unwrap_or(url);

                let mut stream = tokio::net::TcpStream::connect(host_port)
                    .await
                    .map_err(|e| e.to_string())?;

                let mut req = format!(
                    "POST /reload HTTP/1.1\r\nHost: {}\r\nContent-Length: 0\r\nConnection: close\r\n",
                    host_port
                );
                if let Some(tok) = auth_token {
                    req.push_str(&format!("Authorization: Bearer {}\r\n", tok));
                }
                req.push_str("\r\n");

                stream.write_all(req.as_bytes()).await.map_err(|e| e.to_string())?;
                let mut buf = Vec::new();
                stream.read_to_end(&mut buf).await.map_err(|e| e.to_string())?;

                let body_offset = buf
                    .windows(4)
                    .position(|w| w == b"\r\n\r\n")
                    .map(|p| p + 4)
                    .unwrap_or(0);

                #[derive(serde::Deserialize)]
                struct ReloadResp {
                    report: Option<ReloadReport>,
                }
                let parsed: ReloadResp = serde_json::from_slice(&buf[body_offset..])
                    .map_err(|e| format!("Failed to parse reload response: {}", e))?;
                Ok(parsed.report.unwrap_or_default())
            }
        }
    }
}

/// Central state model for the TUI monitor dashboard.
pub struct TuiApp {
    pub data_source: TuiDataSource,
    pub tunnels: Vec<TunnelSummary>,
    pub filtered_indices: Vec<usize>,
    pub selected_index: usize,
    pub scroll_offset: usize,
    pub search_query: String,
    pub is_searching: bool,
    pub sort_field: TuiSortField,
    pub sort_ascending: bool,
    pub status_message: Option<(String, Instant)>,
    pub running: bool,
}

impl TuiApp {
    /// Construct a new [`TuiApp`] with the given data source and initial sort field.
    pub fn new(data_source: TuiDataSource, sort_field: TuiSortField) -> Self {
        Self {
            data_source,
            tunnels: Vec::new(),
            filtered_indices: Vec::new(),
            selected_index: 0,
            scroll_offset: 0,
            search_query: String::new(),
            is_searching: false,
            sort_field,
            sort_ascending: true,
            status_message: None,
            running: true,
        }
    }

    /// Update tunnel dataset and refresh filtered/sorted view.
    pub fn set_tunnels(&mut self, tunnels: Vec<TunnelSummary>) {
        let prev_selected_id = self.selected_tunnel().map(|t| t.id.clone());
        self.tunnels = tunnels;
        self.apply_filter_and_sort();

        // Restore selection by ID if possible
        if let Some(id) = prev_selected_id
            && let Some(pos) = self
                .filtered_indices
                .iter()
                .position(|&idx| self.tunnels[idx].id == id)
            {
                self.selected_index = pos;
            }
    }

    /// Re-filter and sort active indices based on search query and sort criteria.
    pub fn apply_filter_and_sort(&mut self) {
        let q = self.search_query.trim().to_lowercase();
        let mut indices: Vec<usize> = self
            .tunnels
            .iter()
            .enumerate()
            .filter(|(_, t)| {
                if q.is_empty() {
                    true
                } else {
                    t.id.to_lowercase().contains(&q)
                        || t.endpoint
                            .as_deref()
                            .unwrap_or("")
                            .to_lowercase()
                            .contains(&q)
                }
            })
            .map(|(i, _)| i)
            .collect();

        // Sort indices
        let tunnels = &self.tunnels;
        let field = self.sort_field;
        let ascending = self.sort_ascending;

        indices.sort_by(|&a, &b| {
            let ta = &tunnels[a];
            let tb = &tunnels[b];
            let ord = match field {
                TuiSortField::Id => ta.id.cmp(&tb.id),
                TuiSortField::Status => {
                    let rank = |s: &TunnelState| match s {
                        TunnelState::Active => 0,
                        TunnelState::Activating => 1,
                        TunnelState::Suspended => 2,
                        TunnelState::Dormant => 3,
                    };
                    rank(&ta.state).cmp(&rank(&tb.state))
                }
                TuiSortField::Conns => ta.active_conns.cmp(&tb.active_conns),
                TuiSortField::Rx => ta.rx_bytes.cmp(&tb.rx_bytes),
                TuiSortField::Tx => ta.tx_bytes.cmp(&tb.tx_bytes),
            };

            if ascending {
                ord
            } else {
                ord.reverse()
            }
        });

        self.filtered_indices = indices;
        if self.filtered_indices.is_empty() {
            self.selected_index = 0;
            self.scroll_offset = 0;
        } else if self.selected_index >= self.filtered_indices.len() {
            self.selected_index = self.filtered_indices.len() - 1;
        }
    }

    /// Move selection down by 1.
    pub fn select_next(&mut self) {
        if !self.filtered_indices.is_empty() && self.selected_index + 1 < self.filtered_indices.len() {
            self.selected_index += 1;
        }
    }

    /// Move selection up by 1.
    pub fn select_prev(&mut self) {
        if self.selected_index > 0 {
            self.selected_index -= 1;
        }
    }

    /// Page down by specified row count.
    pub fn page_down(&mut self, page_size: usize) {
        if !self.filtered_indices.is_empty() {
            self.selected_index = (self.selected_index + page_size).min(self.filtered_indices.len() - 1);
        }
    }

    /// Page up by specified row count.
    pub fn page_up(&mut self, page_size: usize) {
        self.selected_index = self.selected_index.saturating_sub(page_size);
    }

    /// Jump directly to top of tunnel list.
    pub fn scroll_to_top(&mut self) {
        self.selected_index = 0;
    }

    /// Jump directly to bottom of tunnel list.
    pub fn scroll_to_bottom(&mut self) {
        if !self.filtered_indices.is_empty() {
            self.selected_index = self.filtered_indices.len() - 1;
        }
    }

    /// Cycle sort field through Id -> Status -> Conns -> Rx -> Tx -> Id.
    pub fn cycle_sort(&mut self) {
        self.sort_field = match self.sort_field {
            TuiSortField::Id => TuiSortField::Status,
            TuiSortField::Status => TuiSortField::Conns,
            TuiSortField::Conns => TuiSortField::Rx,
            TuiSortField::Rx => TuiSortField::Tx,
            TuiSortField::Tx => TuiSortField::Id,
        };
        self.apply_filter_and_sort();
    }

    /// Invert current sorting direction.
    pub fn toggle_sort_direction(&mut self) {
        self.sort_ascending = !self.sort_ascending;
        self.apply_filter_and_sort();
    }

    /// Currently selected tunnel summary snapshot.
    pub fn selected_tunnel(&self) -> Option<&TunnelSummary> {
        self.filtered_indices
            .get(self.selected_index)
            .and_then(|&idx| self.tunnels.get(idx))
    }

    /// Set ephemeral status banner message.
    pub fn set_status(&mut self, msg: impl Into<String>) {
        self.status_message = Some((msg.into(), Instant::now()));
    }

    /// Clear status message if it has been displayed longer than `max_age`.
    pub fn clear_status_if_expired(&mut self, max_age: Duration) {
        if let Some((_, ts)) = &self.status_message
            && ts.elapsed() > max_age {
                self.status_message = None;
            }
    }

    /// Fetch latest tunnel states from data source.
    pub async fn refresh(&mut self) -> Result<(), String> {
        let list = self.data_source.fetch_tunnels().await?;
        self.set_tunnels(list);
        Ok(())
    }

    /// Activate currently selected tunnel.
    pub async fn activate_selected(&mut self) -> Result<(), String> {
        if let Some(t) = self.selected_tunnel() {
            let id = t.id.clone();
            self.data_source.activate_tunnel(&id).await?;
            self.set_status(format!("Activated tunnel '{}'", id));
            self.refresh().await?;
            Ok(())
        } else {
            Err("No tunnel selected".to_string())
        }
    }

    /// Suspend currently selected tunnel.
    pub async fn suspend_selected(&mut self) -> Result<(), String> {
        if let Some(t) = self.selected_tunnel() {
            let id = t.id.clone();
            self.data_source.suspend_tunnel(&id).await?;
            self.set_status(format!("Suspended tunnel '{}'", id));
            self.refresh().await?;
            Ok(())
        } else {
            Err("No tunnel selected".to_string())
        }
    }

    /// Trigger hot-reload of configurations.
    pub async fn trigger_reload(&mut self) -> Result<ReloadReport, String> {
        let rep = self.data_source.reload().await?;
        self.set_status(format!(
            "Reloaded: {} added, {} removed, {} updated, {} total",
            rep.added, rep.removed, rep.updated, rep.total
        ));
        self.refresh().await?;
        Ok(rep)
    }

    /// Adjust viewport scroll offset so selected row is guaranteed visible.
    pub fn update_scroll(&mut self, viewport_height: usize) {
        if viewport_height == 0 || self.filtered_indices.is_empty() {
            self.scroll_offset = 0;
            return;
        }

        if self.selected_index < self.scroll_offset {
            self.scroll_offset = self.selected_index;
        } else if self.selected_index >= self.scroll_offset + viewport_height {
            self.scroll_offset = self.selected_index + 1 - viewport_height;
        }
    }
}
