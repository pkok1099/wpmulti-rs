//! Terminal UI rendering and ANSI formatting.

use std::fmt::Write;
use std::io::{self, stdout, IsTerminal, Read, Write as IoWrite};
use std::time::Duration;

use crate::config::TuiSortField;
use crate::core::{HealthStatus, TunnelState};
use crate::tui::app::TuiApp;

// ANSI escape sequences
pub const ANSI_CLEAR: &str = "\x1b[2J\x1b[H";
pub const ANSI_HIDE_CURSOR: &str = "\x1b[?25l";
pub const ANSI_SHOW_CURSOR: &str = "\x1b[?25h";
pub const ANSI_RESET: &str = "\x1b[0m";
pub const ANSI_BOLD: &str = "\x1b[1m";
pub const ANSI_DIM: &str = "\x1b[2m";
pub const ANSI_REVERSE: &str = "\x1b[7m";
pub const ANSI_RED: &str = "\x1b[31m";
pub const ANSI_GREEN: &str = "\x1b[32m";
pub const ANSI_YELLOW: &str = "\x1b[33m";
pub const ANSI_BLUE: &str = "\x1b[34m";
pub const ANSI_MAGENTA: &str = "\x1b[35m";
pub const ANSI_CYAN: &str = "\x1b[36m";
pub const ANSI_WHITE: &str = "\x1b[37m";
pub const ANSI_BG_BLUE: &str = "\x1b[44m";

/// Format a byte count into human-readable string (B, KB, MB, GB).
pub fn format_bytes(bytes: u64) -> String {
    const KB: u64 = 1024;
    const MB: u64 = 1024 * KB;
    const GB: u64 = 1024 * MB;

    if bytes >= GB {
        format!("{:.2} GB", bytes as f64 / GB as f64)
    } else if bytes >= MB {
        format!("{:.2} MB", bytes as f64 / MB as f64)
    } else if bytes >= KB {
        format!("{:.2} KB", bytes as f64 / KB as f64)
    } else {
        format!("{} B", bytes)
    }
}

/// Truncate a string to at most `max_chars` characters, appending `…` when clipped.
fn truncate_chars(s: &str, max_chars: usize) -> String {
    if max_chars == 0 {
        return String::new();
    }
    let count = s.chars().count();
    if count <= max_chars {
        return s.to_string();
    }
    if max_chars == 1 {
        return "…".to_string();
    }
    let mut out: String = s.chars().take(max_chars - 1).collect();
    out.push('…');
    out
}

/// Format a boxed line padded/clipped to `width` total columns.
fn write_box_line(buf: &mut String, content: &str, visible_len: usize, width: usize) {
    let inner_max = width.saturating_sub(2);
    if visible_len > inner_max {
        let clipped = truncate_chars(content, inner_max);
        let _ = writeln!(buf, "│{}│", clipped);
    } else {
        let pad = inner_max - visible_len;
        let _ = writeln!(buf, "│{}{}│", content, " ".repeat(pad));
    }
}

/// Render the complete TUI dashboard into an ANSI-formatted String.
pub fn render_dashboard(app: &mut TuiApp, width: usize, height: usize) -> String {
    let width = width.max(24);
    let height = height.max(8);
    let mut buf = String::with_capacity(8192);

    let total = app.tunnels.len();
    let active = app.tunnels.iter().filter(|t| t.state == TunnelState::Active).count();
    let suspended = app.tunnels.iter().filter(|t| t.state == TunnelState::Suspended).count();
    let dormant = app.tunnels.iter().filter(|t| t.state == TunnelState::Dormant).count();
    let healthy = app.tunnels.iter().filter(|t| t.health == HealthStatus::Healthy).count();
    let unhealthy = app.tunnels.iter().filter(|t| t.health == HealthStatus::Unhealthy).count();
    let total_conns: usize = app.tunnels.iter().map(|t| t.active_conns).sum();
    let total_rx: u64 = app.tunnels.iter().map(|t| t.rx_bytes).sum();
    let total_tx: u64 = app.tunnels.iter().map(|t| t.tx_bytes).sum();

    let compact_height = height < 15;

    // 1. Header Box (or compact 1-line header on very short terminals)
    let header_lines = if compact_height {
        let summary = format!(
            " wpmulti v{} | T:{} A:{} H:{} U:{} | RX:{} TX:{} | C:{}",
            env!("CARGO_PKG_VERSION"),
            total,
            active,
            healthy,
            unhealthy,
            format_bytes(total_rx),
            format_bytes(total_tx),
            total_conns
        );
        let _ = writeln!(
            buf,
            "{}{}{}{}",
            ANSI_BOLD,
            ANSI_CYAN,
            truncate_chars(&summary, width),
            ANSI_RESET
        );
        1
    } else {
        let inner_w = width.saturating_sub(2);
        let _ = writeln!(buf, "{}{}┌{}┐", ANSI_BOLD, ANSI_CYAN, "─".repeat(inner_w));
        let title = format!(
            "  ⚡ wpmulti v{} — High-Concurrency Multi-Tunnel Monitor",
            env!("CARGO_PKG_VERSION")
        );
        write_box_line(&mut buf, &title, title.chars().count(), width);

        let stats_raw = format!(
            "  Tunnels: Total: {} | Active: {} | Healthy: {} | Unhealthy: {} | Suspended: {} | Dormant: {}",
            total, active, healthy, unhealthy, suspended, dormant
        );
        let stats_raw_len = stats_raw.chars().count();
        if stats_raw_len <= inner_w {
            let stats_colored = format!(
                "  Tunnels: Total: {} | Active: {}{}{} | Healthy: {}{}{} | Unhealthy: {}{}{} | Suspended: {}{}{} | Dormant: {}",
                total, ANSI_GREEN, active, ANSI_CYAN, ANSI_GREEN, healthy, ANSI_CYAN, ANSI_RED, unhealthy, ANSI_CYAN, ANSI_MAGENTA, suspended, ANSI_CYAN, dormant
            );
            write_box_line(&mut buf, &stats_colored, stats_raw_len, width);
        } else {
            write_box_line(&mut buf, &stats_raw, stats_raw_len, width);
        }

        let traffic_line = format!(
            "  Traffic: RX: {} | TX: {} | Active Conns: {}",
            format_bytes(total_rx),
            format_bytes(total_tx),
            total_conns
        );
        write_box_line(&mut buf, &traffic_line, traffic_line.chars().count(), width);
        let _ = writeln!(buf, "└{}┘{}", "─".repeat(inner_w), ANSI_RESET);
        5
    };

    // 2. Navigation / Key Hints Bar
    let sort_name = match app.sort_field {
        TuiSortField::Id => "ID",
        TuiSortField::Status => "Status",
        TuiSortField::Conns => "Conns",
        TuiSortField::Rx => "RX",
        TuiSortField::Tx => "TX",
    };
    let dir = if app.sort_ascending { "▲" } else { "▼" };
    let hints = format!(
        " [q] Quit  [r] Reload  [a] Activate  [s] Suspend  [/] Search  [Tab] Sort:{}{}  [↑↓/jk] Move",
        sort_name, dir
    );
    let _ = writeln!(
        buf,
        "{}{}{}",
        ANSI_DIM,
        truncate_chars(&hints, width),
        ANSI_RESET
    );

    // 3. Search Bar
    if app.is_searching || !app.search_query.is_empty() {
        let cursor_ch = if app.is_searching { "█" } else { "" };
        let search_line = format!("Search: {}{}", app.search_query, cursor_ch);
        let _ = writeln!(
            buf,
            "{}{}{}{}",
            ANSI_BOLD,
            ANSI_YELLOW,
            truncate_chars(&search_line, width),
            ANSI_RESET
        );
    } else {
        let _ = writeln!(buf);
    }

    // 4. Adaptive Table Columns based on terminal width
    // Layout modes: Full (>= 96), Medium (68..96), Compact (< 68)
    let (show_port, show_tx, show_endpoint, state_w, id_w, port_w, conns_w, bytes_w, endp_w) =
        if width >= 96 {
            let fixed = 10 + 22 + 7 + 6 + 11 + 11 + 6; // columns + spaces
            let ep_w = width.saturating_sub(fixed).max(12);
            (true, true, true, 10, 22, 7, 6, 11, ep_w)
        } else if width >= 68 {
            let fixed = 10 + 7 + 5 + 10 + 10 + 5;
            let id_w = width.saturating_sub(fixed).max(12);
            (true, true, false, 10, id_w, 7, 5, 10, 0)
        } else {
            let state_w = 7;
            let conns_w = 4;
            let bytes_w = 8;
            let fixed = state_w + conns_w + bytes_w + 3;
            let id_w = width.saturating_sub(fixed).max(4);
            (false, false, false, state_w, id_w, 0, conns_w, bytes_w, 0)
        };

    // Table Header
    let mut hdr = format!(
        "{:<state_w$} {:<id_w$}",
        truncate_chars("STATE", state_w),
        truncate_chars("TUNNEL ID", id_w),
    );
    if show_port {
        let _ = write!(hdr, " {:<port_w$}", truncate_chars("PORT", port_w));
    }
    let _ = write!(hdr, " {:<conns_w$} {:<bytes_w$}", "CONNS", "RX");
    if show_tx {
        let _ = write!(hdr, " {:<bytes_w$}", "TX");
    }
    if show_endpoint {
        let _ = write!(hdr, " {:<endp_w$}", truncate_chars("ENDPOINT", endp_w));
    }
    let _ = writeln!(
        buf,
        "{}{}{}{}",
        ANSI_BOLD,
        ANSI_BG_BLUE,
        truncate_chars(&hdr, width),
        ANSI_RESET
    );

    // 5. Table Rows
    // Reserved: header_lines + hint (1) + search (1) + table header (1) + footer (2)
    let reserved_lines = header_lines + 5;
    let table_height = height.saturating_sub(reserved_lines).max(1);

    app.update_scroll(table_height);

    let start = app.scroll_offset;
    let end = (start + table_height).min(app.filtered_indices.len());

    if app.filtered_indices.is_empty() {
        let msg = if app.search_query.is_empty() {
            "  (No tunnels registered)"
        } else {
            "  (No tunnels match search query)"
        };
        let _ = writeln!(
            buf,
            "{}{}{}",
            ANSI_DIM,
            truncate_chars(msg, width),
            ANSI_RESET
        );
    } else {
        for row_pos in start..end {
            let tunnel_idx = app.filtered_indices[row_pos];
            let t = &app.tunnels[tunnel_idx];
            let is_selected = row_pos == app.selected_index;

            let (state_color, state_str) = match (t.health, t.state) {
                (HealthStatus::Unhealthy, _) => (ANSI_RED, "Unhealthy"),
                (HealthStatus::HalfOpen, _) => (ANSI_YELLOW, "HalfOpen"),
                (HealthStatus::Healthy, TunnelState::Active) => (ANSI_GREEN, "Active"),
                (HealthStatus::Healthy, TunnelState::Activating) => (ANSI_CYAN, "Activating"),
                (HealthStatus::Healthy, TunnelState::Suspended) => (ANSI_MAGENTA, "Suspended"),
                (HealthStatus::Healthy, TunnelState::Dormant) => (ANSI_DIM, "Dormant"),
            };

            let port_str = t
                .assigned_port
                .map(|p| p.to_string())
                .unwrap_or_else(|| "-".to_string());
            let endpoint_str = if t.health == HealthStatus::Unhealthy {
                format!(
                    "{} (fails:{}, {}s)",
                    t.endpoint.as_deref().unwrap_or("-"),
                    t.consecutive_failures,
                    t.cooldown_remaining_secs
                )
            } else if t.health == HealthStatus::HalfOpen {
                format!("{} (probe)", t.endpoint.as_deref().unwrap_or("-"))
            } else {
                t.endpoint.clone().unwrap_or_else(|| "-".to_string())
            };

            if is_selected {
                let _ = write!(buf, "{}{}", ANSI_REVERSE, ANSI_BOLD);
            }

            let state_cell = truncate_chars(state_str, state_w);
            let id_cell = truncate_chars(&t.id, id_w);
            let mut tail = format!("{:<id_w$}", id_cell);
            if show_port {
                let _ = write!(tail, " {:<port_w$}", truncate_chars(&port_str, port_w));
            }
            let _ = write!(
                tail,
                " {:<conns_w$} {:<bytes_w$}",
                t.active_conns,
                truncate_chars(&format_bytes(t.rx_bytes), bytes_w),
            );
            if show_tx {
                let _ = write!(
                    tail,
                    " {:<bytes_w$}",
                    truncate_chars(&format_bytes(t.tx_bytes), bytes_w),
                );
            }
            if show_endpoint {
                let _ = write!(tail, " {:<endp_w$}", truncate_chars(&endpoint_str, endp_w));
            }

            let tail_max = width.saturating_sub(state_w + 1);
            let _ = write!(
                buf,
                "{}{:<state_w$}{} {}",
                state_color,
                state_cell,
                if is_selected { "" } else { ANSI_RESET },
                truncate_chars(&tail, tail_max),
            );

            if is_selected {
                let _ = writeln!(buf, "{}", ANSI_RESET);
            } else {
                let _ = writeln!(buf);
            }
        }
    }

    // 6. Footer / Status Message (no trailing newline to avoid 1-line terminal scroll)
    let _ = writeln!(buf);
    if let Some((msg, _)) = &app.status_message {
        let line = format!(">>> {}", msg);
        let _ = write!(
            buf,
            "{}{}{}{}",
            ANSI_BOLD,
            ANSI_GREEN,
            truncate_chars(&line, width),
            ANSI_RESET
        );
    } else {
        let current_pos = if app.filtered_indices.is_empty() {
            0
        } else {
            app.selected_index + 1
        };
        let footer = format!(
            "Tunnel {} of {} matching ({} total)",
            current_pos,
            app.filtered_indices.len(),
            app.tunnels.len()
        );
        let _ = write!(
            buf,
            "{}{}{}",
            ANSI_DIM,
            truncate_chars(&footer, width),
            ANSI_RESET
        );
    }

    buf
}

/// Parsed keyboard input events for the TUI.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TuiKey {
    Up,
    Down,
    PageUp,
    PageDown,
    Home,
    End,
    Esc,
    Char(char),
}

/// Parse the next key event from `bytes`, returning `(event, bytes_consumed)`.
/// Returns `(None, 0)` only when `bytes` is empty or contains an incomplete UTF-8/CSI prefix.
pub fn parse_next_key(bytes: &[u8]) -> (Option<TuiKey>, usize) {
    if bytes.is_empty() {
        return (None, 0);
    }
    if bytes[0] == 0x1b {
        if bytes.len() == 1 {
            return (Some(TuiKey::Esc), 1);
        }
        if bytes[1] == b'[' || bytes[1] == b'O' {
            if bytes.len() < 3 {
                return (None, 0);
            }
            match bytes[2] {
                b'A' => return (Some(TuiKey::Up), 3),
                b'B' => return (Some(TuiKey::Down), 3),
                b'H' => return (Some(TuiKey::Home), 3),
                b'F' => return (Some(TuiKey::End), 3),
                b'1' | b'4' | b'5' | b'6' | b'7' | b'8' => {
                    if bytes.len() < 4 {
                        return (None, 0);
                    }
                    if bytes[3] == b'~' {
                        let key = match bytes[2] {
                            b'1' | b'7' => TuiKey::Home,
                            b'4' | b'8' => TuiKey::End,
                            b'5' => TuiKey::PageUp,
                            b'6' => TuiKey::PageDown,
                            _ => unreachable!(),
                        };
                        return (Some(key), 4);
                    }
                    return (None, 4);
                }
                _ => return (None, 3),
            }
        }
        return (None, 2);
    }

    // Decode UTF-8 character
    if let Ok(s) = std::str::from_utf8(bytes) {
        if let Some(ch) = s.chars().next() {
            return (Some(TuiKey::Char(ch)), ch.len_utf8());
        }
    } else {
        // Find valid UTF-8 prefix or drop invalid byte
        let len = bytes.len().min(4);
        for end in 1..=len {
            if let Ok(s) = std::str::from_utf8(&bytes[..end])
                && let Some(ch) = s.chars().next() {
                    return (Some(TuiKey::Char(ch)), ch.len_utf8());
                }
        }
        if bytes.len() < 4 && (bytes[0] & 0xC0) == 0xC0 {
            return (None, 0);
        }
    }
    (None, 1)
}

/// Parse a raw stdin byte slice (including coalesced/UTF-8 sequences) into [`TuiKey`] events.
pub fn parse_keys_from_bytes(bytes: &[u8]) -> Vec<TuiKey> {
    let mut keys = Vec::new();
    let mut offset = 0;
    while offset < bytes.len() {
        let (key, consumed) = parse_next_key(&bytes[offset..]);
        if consumed == 0 {
            break;
        }
        if let Some(k) = key {
            keys.push(k);
        }
        offset += consumed;
    }
    keys
}

/// Parse a single raw stdin byte slice into a [`TuiKey`].
pub fn parse_key_sequence(bytes: &[u8]) -> Option<TuiKey> {
    parse_next_key(bytes).0
}

/// Query current terminal `(width, height)` via `TIOCGWINSZ`, falling back to `(100, 28)`.
pub fn get_terminal_size() -> (usize, usize) {
    #[cfg(unix)]
    {
        let mut ws: libc::winsize = unsafe { std::mem::zeroed() };
        let rc = unsafe { libc::ioctl(libc::STDOUT_FILENO, libc::TIOCGWINSZ, &mut ws) };
        if rc == 0 && ws.ws_col > 0 && ws.ws_row > 0 {
            return ((ws.ws_col as usize).max(24), (ws.ws_row as usize).max(8));
        }
    }
    (100, 28)
}

/// RAII guard enabling raw/non-canonical stdin mode and alternate screen, restoring on drop.
struct RawTerminalGuard {
    #[cfg(unix)]
    orig_termios: Option<libc::termios>,
    is_tty: bool,
}

impl RawTerminalGuard {
    fn enter(is_tty: bool) -> Self {
        #[cfg(unix)]
        let orig_termios = if is_tty {
            unsafe {
                let mut orig: libc::termios = std::mem::zeroed();
                if libc::tcgetattr(libc::STDIN_FILENO, &mut orig) == 0 {
                    let mut raw = orig;
                    raw.c_lflag &= !(libc::ICANON | libc::ECHO);
                    raw.c_cc[libc::VMIN] = 1;
                    raw.c_cc[libc::VTIME] = 0;
                    let _ = libc::tcsetattr(libc::STDIN_FILENO, libc::TCSANOW, &raw);
                    Some(orig)
                } else {
                    None
                }
            }
        } else {
            None
        };

        if is_tty {
            print!("{}\x1b[?1049h{}", ANSI_CLEAR, ANSI_HIDE_CURSOR);
            let _ = stdout().flush();
        }

        Self {
            #[cfg(unix)]
            orig_termios,
            is_tty,
        }
    }
}

impl Drop for RawTerminalGuard {
    fn drop(&mut self) {
        #[cfg(unix)]
        if let Some(ref orig) = self.orig_termios {
            unsafe {
                let _ = libc::tcsetattr(libc::STDIN_FILENO, libc::TCSANOW, orig);
            }
        }
        if self.is_tty {
            print!("{}\x1b[?1049l{}", ANSI_SHOW_CURSOR, ANSI_RESET);
            let _ = stdout().flush();
        }
    }
}

/// Write a rendered frame to stdout without full-screen clear flicker.
fn write_frame(rendered: &str) {
    let mut out = stdout().lock();
    let _ = out.write_all(b"\x1b[H");
    let mut lines = rendered.split('\n').peekable();
    while let Some(line) = lines.next() {
        let _ = out.write_all(line.as_bytes());
        let _ = out.write_all(b"\x1b[K");
        if lines.peek().is_some() {
            let _ = out.write_all(b"\n");
        }
    }
    let _ = out.write_all(b"\x1b[J");
    let _ = out.flush();
}

/// Poll stdin with `timeout_ms` on Unix; returns `true` if bytes are ready to read.
#[cfg(unix)]
fn poll_stdin(timeout_ms: i32) -> bool {
    let mut pfd = libc::pollfd {
        fd: libc::STDIN_FILENO,
        events: libc::POLLIN,
        revents: 0,
    };
    let rc = unsafe { libc::poll(&mut pfd, 1, timeout_ms) };
    rc > 0 && (pfd.revents & libc::POLLIN) != 0
}

/// Run the interactive terminal event loop for the TUI dashboard.
pub async fn run_terminal_tui(mut app: TuiApp, refresh_rate_ms: u64) -> Result<(), io::Error> {
    // Initial fetch of tunnel state
    let _ = app.refresh().await;

    let is_tty = io::stdin().is_terminal() && stdout().is_terminal();
    if !is_tty {
        let (w, h) = get_terminal_size();
        let rendered = render_dashboard(&mut app, w, h);
        println!("{}", rendered);
        return Ok(());
    }

    let refresh_interval = Duration::from_millis(refresh_rate_ms.max(50));
    let mut interval = tokio::time::interval(refresh_interval);

    let (key_tx, mut key_rx) = tokio::sync::mpsc::channel::<TuiKey>(64);
    let stop_reader = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let stop_flag = std::sync::Arc::clone(&stop_reader);

    let reader_handle = tokio::task::spawn_blocking(move || {
        let mut stdin = io::stdin();
        let mut pending: Vec<u8> = Vec::with_capacity(64);
        let mut buf = [0u8; 64];

        while !stop_flag.load(std::sync::atomic::Ordering::Relaxed) {
            #[cfg(unix)]
            if !poll_stdin(200) {
                continue;
            }
            match stdin.read(&mut buf) {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    pending.extend_from_slice(&buf[..n]);
                    // If a lone ESC arrived, wait briefly (50ms) to distinguish Esc vs split CSI sequence
                    #[cfg(unix)]
                    if pending == [0x1b] && poll_stdin(50)
                        && let Ok(m) = stdin.read(&mut buf)
                            && m > 0 {
                                pending.extend_from_slice(&buf[..m]);
                            }

                    let mut offset = 0;
                    while offset < pending.len() {
                        let (key, consumed) = parse_next_key(&pending[offset..]);
                        if consumed == 0 {
                            break;
                        }
                        if let Some(k) = key
                            && key_tx.blocking_send(k).is_err() {
                                return;
                            }
                        offset += consumed;
                    }
                    if offset > 0 {
                        pending.drain(..offset);
                    }
                }
            }
        }
    });

    // Enter raw mode & alternate screen with RAII restoration
    let _term_guard = RawTerminalGuard::enter(true);

    #[cfg(unix)]
    let mut sigwinch = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::window_change())?;
    #[cfg(unix)]
    let mut sigint = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::interrupt())?;
    #[cfg(unix)]
    let mut sigterm = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;

    while app.running {
        tokio::select! {
            _ = interval.tick() => {
                let _ = app.refresh().await;
                app.clear_status_if_expired(Duration::from_secs(3));
                let (w, h) = get_terminal_size();
                let rendered = render_dashboard(&mut app, w, h);
                write_frame(&rendered);
            }
            _ = sigwinch.recv() => {
                let (w, h) = get_terminal_size();
                let rendered = render_dashboard(&mut app, w, h);
                write_frame(&rendered);
            }
            _ = sigint.recv() => {
                app.running = false;
            }
            _ = sigterm.recv() => {
                app.running = false;
            }
            Some(key) = key_rx.recv() => {
                let (w, h) = get_terminal_size();
                let reserved = if h < 15 { 6 } else { 10 };
                let page_size = h.saturating_sub(reserved).max(1);
                match key {
                    TuiKey::Up => {
                        app.select_prev();
                    }
                    TuiKey::Down => {
                        app.select_next();
                    }
                    TuiKey::PageUp => {
                        app.page_up(page_size);
                    }
                    TuiKey::PageDown => {
                        app.page_down(page_size);
                    }
                    TuiKey::Home => {
                        app.scroll_to_top();
                    }
                    TuiKey::End => {
                        app.scroll_to_bottom();
                    }
                    TuiKey::Esc => {
                        app.is_searching = false;
                        app.search_query.clear();
                        app.apply_filter_and_sort();
                    }
                    TuiKey::Char(ch) => match ch {
                        '\x03' => {
                            app.running = false;
                        }
                        'q' | 'Q' if !app.is_searching => {
                            app.running = false;
                        }
                        '/' if !app.is_searching => {
                            app.is_searching = true;
                            app.search_query.clear();
                            app.apply_filter_and_sort();
                        }
                        '\n' | '\r' => {
                            app.is_searching = false;
                        }
                        '\x08' | '\x7f' => {
                            if app.is_searching {
                                app.search_query.pop();
                                app.apply_filter_and_sort();
                            }
                        }
                        'a' | 'A' if !app.is_searching => {
                            let _ = app.activate_selected().await;
                        }
                        's' | 'S' if !app.is_searching => {
                            let _ = app.suspend_selected().await;
                        }
                        'r' | 'R' if !app.is_searching => {
                            let _ = app.trigger_reload().await;
                        }
                        '\t' if !app.is_searching => {
                            app.cycle_sort();
                        }
                        'j' if !app.is_searching => {
                            app.select_next();
                        }
                        'k' if !app.is_searching => {
                            app.select_prev();
                        }
                        'g' if !app.is_searching => {
                            app.scroll_to_top();
                        }
                        'G' if !app.is_searching => {
                            app.scroll_to_bottom();
                        }
                        other => {
                            if app.is_searching && !other.is_control() {
                                app.search_query.push(other);
                                app.apply_filter_and_sort();
                            }
                        }
                    },
                }
                let rendered = render_dashboard(&mut app, w, h);
                write_frame(&rendered);
            }
        }
    }

    stop_reader.store(true, std::sync::atomic::Ordering::Relaxed);
    let _ = reader_handle.await;

    Ok(())
}
