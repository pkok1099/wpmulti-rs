//! Terminal UI rendering and ANSI formatting.

use std::fmt::Write;
use std::io::{self, stdout, IsTerminal, Read, Write as IoWrite};
use std::time::Duration;

use crate::config::TuiSortField;
use crate::core::TunnelState;
use crate::tui::app::TuiApp;

// ANSI escape sequences
pub const ANSI_CLEAR: &str = "\x1b[2J\x1b[H";
pub const ANSI_HIDE_CURSOR: &str = "\x1b[?25l";
pub const ANSI_SHOW_CURSOR: &str = "\x1b[?25h";
pub const ANSI_RESET: &str = "\x1b[0m";
pub const ANSI_BOLD: &str = "\x1b[1m";
pub const ANSI_DIM: &str = "\x1b[2m";
pub const ANSI_REVERSE: &str = "\x1b[7m";
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

/// Render the complete TUI dashboard into an ANSI-formatted String.
pub fn render_dashboard(app: &mut TuiApp, width: usize, height: usize) -> String {
    let mut buf = String::with_capacity(8192);

    let total = app.tunnels.len();
    let active = app.tunnels.iter().filter(|t| t.state == TunnelState::Active).count();
    let suspended = app.tunnels.iter().filter(|t| t.state == TunnelState::Suspended).count();
    let dormant = app.tunnels.iter().filter(|t| t.state == TunnelState::Dormant).count();
    let total_conns: usize = app.tunnels.iter().map(|t| t.active_conns).sum();
    let total_rx: u64 = app.tunnels.iter().map(|t| t.rx_bytes).sum();
    let total_tx: u64 = app.tunnels.iter().map(|t| t.tx_bytes).sum();

    // 1. Header Box
    let _ = writeln!(buf, "{}{}", ANSI_BOLD, ANSI_CYAN);
    let _ = writeln!(buf, "┌{}┐", "─".repeat(width.saturating_sub(2)));
    let title_line = format!(
        "│  ⚡ wpmulti v{} — High-Concurrency Multi-Tunnel Monitor",
        env!("CARGO_PKG_VERSION")
    );
    let pad_title = width.saturating_sub(title_line.chars().count() + 1);
    let _ = writeln!(buf, "{}{}│", title_line, " ".repeat(pad_title));

    let stats_line_1 = format!(
        "│  Tunnels: Total: {} | Active: {}{}{} | Suspended: {}{}{} | Dormant: {}",
        total,
        ANSI_GREEN, active, ANSI_CYAN,
        ANSI_MAGENTA, suspended, ANSI_CYAN,
        dormant
    );
    let raw_len_1 = format!(
        "│  Tunnels: Total: {} | Active: {} | Suspended: {} | Dormant: {}",
        total, active, suspended, dormant
    ).chars().count();
    let pad_1 = width.saturating_sub(raw_len_1 + 1);
    let _ = writeln!(buf, "{}{}│", stats_line_1, " ".repeat(pad_1));

    let stats_line_2 = format!(
        "│  Traffic: RX: {} | TX: {} | Active Conns: {}",
        format_bytes(total_rx),
        format_bytes(total_tx),
        total_conns
    );
    let pad_2 = width.saturating_sub(stats_line_2.chars().count() + 1);
    let _ = writeln!(buf, "{}{}│", stats_line_2, " ".repeat(pad_2));
    let _ = writeln!(buf, "└{}┘{}", "─".repeat(width.saturating_sub(2)), ANSI_RESET);

    // 2. Navigation / Key Hints Bar
    let sort_name = match app.sort_field {
        TuiSortField::Id => "ID",
        TuiSortField::Status => "Status",
        TuiSortField::Conns => "Conns",
        TuiSortField::Rx => "RX",
        TuiSortField::Tx => "TX",
    };
    let dir = if app.sort_ascending { "▲" } else { "▼" };
    let _ = writeln!(
        buf,
        "{} [q] Quit  [r] Reload  [a] Activate  [s] Suspend  [/] Search  [Tab] Sort: {}{}  [↑↓] Move{}",
        ANSI_DIM, sort_name, dir, ANSI_RESET
    );

    // 3. Search Bar
    if app.is_searching || !app.search_query.is_empty() {
        let cursor_ch = if app.is_searching { "█" } else { "" };
        let _ = writeln!(
            buf,
            "{}{}Search: {}{}{}{}",
            ANSI_BOLD, ANSI_YELLOW, app.search_query, cursor_ch, ANSI_RESET, " ".repeat(10)
        );
    } else {
        let _ = writeln!(buf);
    }

    // 4. Table Header
    let _ = writeln!(
        buf,
        "{}{}{:<12} {:<24} {:<8} {:<8} {:<12} {:<12} {:<24}{}",
        ANSI_BOLD,
        ANSI_BG_BLUE,
        "STATE",
        "TUNNEL ID",
        "PORT",
        "CONNS",
        "RX BYTES",
        "TX BYTES",
        "ENDPOINT",
        ANSI_RESET
    );

    // 5. Table Rows
    // Reserve header (5 lines), hint (1 line), search (1 line), table header (1 line), footer (2 lines)
    let reserved_lines = 10;
    let table_height = height.saturating_sub(reserved_lines).max(1);

    app.update_scroll(table_height);

    let start = app.scroll_offset;
    let end = (start + table_height).min(app.filtered_indices.len());

    if app.filtered_indices.is_empty() {
        let _ = writeln!(
            buf,
            "{}{}{}",
            ANSI_DIM,
            if app.search_query.is_empty() {
                "  (No tunnels registered)"
            } else {
                "  (No tunnels match search query)"
            },
            ANSI_RESET
        );
    } else {
        for row_pos in start..end {
            let tunnel_idx = app.filtered_indices[row_pos];
            let t = &app.tunnels[tunnel_idx];
            let is_selected = row_pos == app.selected_index;

            let (state_color, state_str) = match t.state {
                TunnelState::Active => (ANSI_GREEN, "Active"),
                TunnelState::Activating => (ANSI_CYAN, "Activating"),
                TunnelState::Suspended => (ANSI_MAGENTA, "Suspended"),
                TunnelState::Dormant => (ANSI_DIM, "Dormant"),
            };

            let port_str = t
                .assigned_port
                .map(|p| p.to_string())
                .unwrap_or_else(|| "-".to_string());
            let endpoint_str = t.endpoint.as_deref().unwrap_or("-");

            if is_selected {
                let _ = write!(buf, "{}{}", ANSI_REVERSE, ANSI_BOLD);
            }

            let _ = write!(
                buf,
                "{}{:<12}{} {:<24} {:<8} {:<8} {:<12} {:<12} {:<24}",
                state_color,
                state_str,
                if is_selected { "" } else { ANSI_RESET },
                t.id,
                port_str,
                t.active_conns,
                format_bytes(t.rx_bytes),
                format_bytes(t.tx_bytes),
                endpoint_str
            );

            if is_selected {
                let _ = writeln!(buf, "{}", ANSI_RESET);
            } else {
                let _ = writeln!(buf);
            }
        }
    }

    // 6. Footer / Status Message
    let _ = writeln!(buf);
    if let Some((msg, _)) = &app.status_message {
        let _ = writeln!(buf, "{}{}>>> {}{}", ANSI_BOLD, ANSI_GREEN, msg, ANSI_RESET);
    } else {
        let current_pos = if app.filtered_indices.is_empty() {
            0
        } else {
            app.selected_index + 1
        };
        let _ = writeln!(
            buf,
            "{}Tunnel {} of {} matching ({} total){}",
            ANSI_DIM,
            current_pos,
            app.filtered_indices.len(),
            app.tunnels.len(),
            ANSI_RESET
        );
    }

    buf
}

/// Run the interactive terminal event loop for the TUI dashboard.
pub async fn run_terminal_tui(mut app: TuiApp, refresh_rate_ms: u64) -> Result<(), io::Error> {
    // Initial fetch of tunnel state
    let _ = app.refresh().await;

    let refresh_interval = Duration::from_millis(refresh_rate_ms.max(50));
    let mut interval = tokio::time::interval(refresh_interval);

    let (key_tx, mut key_rx) = tokio::sync::mpsc::channel::<char>(64);

    // Spawn non-blocking stdin reader task
    let is_tty = io::stdin().is_terminal();
    if is_tty {
        tokio::task::spawn_blocking(move || {
            let mut stdin = io::stdin();
            let mut buf = [0u8; 1];
            while let Ok(1) = stdin.read(&mut buf) {
                let ch = buf[0] as char;
                if key_tx.blocking_send(ch).is_err() {
                    break;
                }
            }
        });
    }

    // Enter alternative buffer & hide cursor if interactive
    if is_tty {
        print!("{}\x1b[?1049h{}", ANSI_CLEAR, ANSI_HIDE_CURSOR);
        let _ = stdout().flush();
    }

    while app.running {
        tokio::select! {
            _ = interval.tick() => {
                let _ = app.refresh().await;
                app.clear_status_if_expired(Duration::from_secs(3));
                let rendered = render_dashboard(&mut app, 100, 28);
                print!("{}{}", ANSI_CLEAR, rendered);
                let _ = stdout().flush();
            }
            Some(ch) = key_rx.recv() => {
                match ch {
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
                    '\x1b' => { // Escape key
                        app.is_searching = false;
                        app.search_query.clear();
                        app.apply_filter_and_sort();
                    }
                    '\x08' | '\x7f' => { // Backspace
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
                    other => {
                        if app.is_searching && other.is_ascii_graphic() || other == ' ' {
                            app.search_query.push(other);
                            app.apply_filter_and_sort();
                        }
                    }
                }
                let rendered = render_dashboard(&mut app, 100, 28);
                print!("{}{}", ANSI_CLEAR, rendered);
                let _ = stdout().flush();
            }
        }

        // If running non-interactively without TTY, refresh once and exit cleanly
        if !is_tty {
            let rendered = render_dashboard(&mut app, 100, 28);
            println!("{}", rendered);
            break;
        }
    }

    // Restore terminal
    if is_tty {
        print!("{}\x1b[?1049l{}", ANSI_SHOW_CURSOR, ANSI_RESET);
        let _ = stdout().flush();
    }

    Ok(())
}
