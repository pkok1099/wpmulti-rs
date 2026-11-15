//! Ratatui + Crossterm terminal UI renderer and interactive event loop for `wpmulti`.

use std::io;
use std::time::{Duration, Instant};

use crossterm::event::{self, Event, KeyCode, KeyEventKind, KeyModifiers};
use crossterm::execute;
use crossterm::terminal::{
    disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen,
};
use ratatui::backend::{CrosstermBackend, TestBackend};
use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Cell, Paragraph, Row, Sparkline, Table, Tabs};
use ratatui::{Frame, Terminal};

use crate::core::health::HealthStatus;
use crate::core::TunnelState;
use crate::tui::app::{TuiApp, TuiTab};

/// Format a byte count into a human-readable string (`B`, `KB`, `MB`, `GB`).
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

/// Decoded terminal input key used by `wpmulti` TUI handlers and tests.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TuiKey {
    Char(char),
    Up,
    Down,
    Left,
    Right,
    PageUp,
    PageDown,
    Home,
    End,
    Enter,
    Backspace,
    Tab,
    Esc,
}

/// Parse a single key sequence from raw bytes (retained for unit tests).
pub fn parse_key_sequence(bytes: &[u8]) -> Option<TuiKey> {
    parse_next_key(bytes).0
}

/// Parse the next key from `bytes` and return `(Option<TuiKey>, consumed_bytes)`.
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
            return match bytes[2] {
                b'A' => (Some(TuiKey::Up), 3),
                b'B' => (Some(TuiKey::Down), 3),
                b'C' => (Some(TuiKey::Right), 3),
                b'D' => (Some(TuiKey::Left), 3),
                b'H' => (Some(TuiKey::Home), 3),
                b'F' => (Some(TuiKey::End), 3),
                b'5' if bytes.get(3) == Some(&b'~') => (Some(TuiKey::PageUp), 4),
                b'6' if bytes.get(3) == Some(&b'~') => (Some(TuiKey::PageDown), 4),
                b'7' if bytes.get(3) == Some(&b'~') => (Some(TuiKey::Home), 4),
                b'8' if bytes.get(3) == Some(&b'~') => (Some(TuiKey::End), 4),
                _ => (Some(TuiKey::Esc), 1),
            };
        }
        return (Some(TuiKey::Esc), 1);
    }
    match bytes[0] {
        b'\r' | b'\n' => (Some(TuiKey::Enter), 1),
        0x7f | 0x08 => (Some(TuiKey::Backspace), 1),
        b'\t' => (Some(TuiKey::Tab), 1),
        _ => {
            if let Ok(s) = std::str::from_utf8(bytes)
                && let Some(ch) = s.chars().next()
            {
                return (Some(TuiKey::Char(ch)), ch.len_utf8());
            }
            (None, 1)
        }
    }
}

/// Parse all coalesced keys from a byte slice.
pub fn parse_keys_from_bytes(bytes: &[u8]) -> Vec<TuiKey> {
    let mut keys = Vec::new();
    let mut offset = 0;
    while offset < bytes.len() {
        let (maybe_key, consumed) = parse_next_key(&bytes[offset..]);
        if consumed == 0 {
            break;
        }
        if let Some(k) = maybe_key {
            keys.push(k);
        }
        offset += consumed;
    }
    keys
}

/// Render the complete TUI dashboard into a plain-text String via `ratatui::TestBackend`.
pub fn render_dashboard(app: &mut TuiApp, width: usize, height: usize) -> String {
    let w = width.max(24) as u16;
    let h = height.max(8) as u16;
    let backend = TestBackend::new(w, h);
    let mut terminal = Terminal::new(backend).expect("test terminal");
    terminal
        .draw(|f| draw_dashboard(f, app))
        .expect("draw test dashboard");

    let buf = terminal.backend().buffer();
    let mut lines = Vec::with_capacity(h as usize);
    for y in 0..h {
        let mut row = String::with_capacity(w as usize);
        for x in 0..w {
            row.push_str(buf[(x, y)].symbol());
        }
        lines.push(row.trim_end().to_string());
    }
    lines.join("\n")
}

/// Draw the full 5-tab `nyx`-style dashboard onto a `ratatui::Frame`.
pub fn draw_dashboard(f: &mut Frame, app: &mut TuiApp) {
    let area = f.area();
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3), // Header + Tabs
            Constraint::Min(3),    // Active Tab Body
            Constraint::Length(2), // Footer / Status
        ])
        .split(area);

    draw_header_and_tabs(f, app, chunks[0]);

    match app.active_tab {
        TuiTab::Tunnels => draw_tunnels_tab(f, app, chunks[1]),
        TuiTab::Logs => draw_logs_tab(f, app, chunks[1]),
        TuiTab::Listeners => draw_listeners_tab(f, app, chunks[1]),
        TuiTab::Config => draw_config_tab(f, app, chunks[1]),
        TuiTab::Probe => draw_probe_tab(f, app, chunks[1]),
    }

    draw_footer(f, app, chunks[2]);
}

fn draw_header_and_tabs(f: &mut Frame, app: &TuiApp, area: Rect) {
    let active_count = app
        .tunnels
        .iter()
        .filter(|t| t.state == TunnelState::Active)
        .count();
    let total_conns: usize = app.tunnels.iter().map(|t| t.active_conns).sum();
    let title = if area.width < 60 {
        format!(" wpmulti v{} ", env!("CARGO_PKG_VERSION"))
    } else {
        format!(
            " wpmulti v{} | Tunnels: {} ({} active) | Conns: {} ",
            env!("CARGO_PKG_VERSION"),
            app.tunnels.len(),
            active_count,
            total_conns
        )
    };

    let tab_titles: Vec<Line> = TuiTab::ALL
        .iter()
        .map(|t| Line::from(t.label()))
        .collect();
    let selected_idx = TuiTab::ALL
        .iter()
        .position(|t| *t == app.active_tab)
        .unwrap_or(0);

    let tabs = Tabs::new(tab_titles)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title(Span::styled(
                    title,
                    Style::default()
                        .fg(Color::Cyan)
                        .add_modifier(Modifier::BOLD),
                )),
        )
        .select(selected_idx)
        .style(Style::default().fg(Color::Gray))
        .highlight_style(
            Style::default()
                .fg(Color::Black)
                .bg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        );
    f.render_widget(tabs, area);
}

fn draw_tunnels_tab(f: &mut Frame, app: &mut TuiApp, area: Rect) {
    let show_sparkline = area.height >= 10 && area.width >= 40;
    let (spark_area, table_area) = if show_sparkline {
        let split = Layout::default()
            .direction(Direction::Vertical)
            .constraints([Constraint::Length(3), Constraint::Min(3)])
            .split(area);
        (Some(split[0]), split[1])
    } else {
        (None, area)
    };

    if let Some(s_area) = spark_area {
        let cols = Layout::default()
            .direction(Direction::Horizontal)
            .constraints([Constraint::Percentage(50), Constraint::Percentage(50)])
            .split(s_area);

        let rx_data: Vec<u64> = app.rx_rates.iter().copied().collect();
        let tx_data: Vec<u64> = app.tx_rates.iter().copied().collect();

        let rx_spark = Sparkline::default()
            .block(
                Block::default()
                    .borders(Borders::ALL)
                    .title(format!(" RX {}/s ", format_bytes(app.current_rx_bps))),
            )
            .data(&rx_data)
            .style(Style::default().fg(Color::Green));
        let tx_spark = Sparkline::default()
            .block(
                Block::default()
                    .borders(Borders::ALL)
                    .title(format!(" TX {}/s ", format_bytes(app.current_tx_bps))),
            )
            .data(&tx_data)
            .style(Style::default().fg(Color::Yellow));

        f.render_widget(rx_spark, cols[0]);
        f.render_widget(tx_spark, cols[1]);
    }

    let w = table_area.width;
    let show_endpoint = w >= 92;
    let show_port = w >= 66;
    let show_tx = w >= 58;

    let mut headers = vec!["ID", "STATE", "HEALTH", "CONNS", "RX"];
    if show_tx {
        headers.push("TX");
    }
    if show_port {
        headers.push("PORT");
    }
    if show_endpoint {
        headers.push("ENDPOINT");
    }

    let header_row = Row::new(headers).style(
        Style::default()
            .fg(Color::Cyan)
            .add_modifier(Modifier::BOLD),
    );

    let total_visible = app.filtered_indices.len();
    let visible_rows = table_area.height.saturating_sub(3) as usize;
    app.update_scroll(visible_rows.max(1));

    let rows: Vec<Row> = app
        .filtered_indices
        .iter()
        .enumerate()
        .skip(app.scroll_offset)
        .take(visible_rows.max(1))
        .map(|(vis_idx, &orig_idx)| {
            let t = &app.tunnels[orig_idx];
            let state_str = format!("{:?}", t.state);
            let health_str = match t.health {
                HealthStatus::Healthy => "Healthy",
                HealthStatus::HalfOpen => "HalfOpen",
                HealthStatus::Unhealthy => "Unhealthy",
            };
            let mut cells = vec![
                Cell::from(t.id.clone()),
                Cell::from(state_str).style(state_style(t.state)),
                Cell::from(health_str).style(health_style(t.health)),
                Cell::from(t.active_conns.to_string()),
                Cell::from(format_bytes(t.rx_bytes)),
            ];
            if show_tx {
                cells.push(Cell::from(format_bytes(t.tx_bytes)));
            }
            if show_port {
                let port = t
                    .assigned_port
                    .map(|p| p.to_string())
                    .unwrap_or_else(|| "-".to_string());
                cells.push(Cell::from(port));
            }
            if show_endpoint {
                cells.push(Cell::from(
                    t.endpoint.clone().unwrap_or_else(|| "-".to_string()),
                ));
            }
            let row = Row::new(cells);
            if vis_idx == app.selected_index {
                row.style(
                    Style::default()
                        .bg(Color::DarkGray)
                        .add_modifier(Modifier::BOLD),
                )
            } else {
                row
            }
        })
        .collect();

    let mut widths = vec![
        Constraint::Min(14),
        Constraint::Length(10),
        Constraint::Length(10),
        Constraint::Length(6),
        Constraint::Length(9),
    ];
    if show_tx {
        widths.push(Constraint::Length(9));
    }
    if show_port {
        widths.push(Constraint::Length(6));
    }
    if show_endpoint {
        widths.push(Constraint::Min(18));
    }

    let pos_title = if total_visible == 0 {
        " Tunnels (0) ".to_string()
    } else {
        format!(" Tunnel {} of {} ", app.selected_index + 1, total_visible)
    };

    let table = Table::new(rows, widths)
        .header(header_row)
        .block(Block::default().borders(Borders::ALL).title(pos_title));
    f.render_widget(table, table_area);
}

fn draw_logs_tab(f: &mut Frame, app: &TuiApp, area: Rect) {
    let filter_label = app.log_level_filter.as_deref().unwrap_or("ALL");
    let logs = app.filtered_logs();
    let visible = area.height.saturating_sub(2) as usize;
    let total = logs.len();
    let max_scroll = total.saturating_sub(visible);
    let scroll = app.log_scroll.min(max_scroll);
    let start = total.saturating_sub(visible + scroll);
    let end = total.saturating_sub(scroll);

    let lines: Vec<Line> = if logs.is_empty() {
        vec![Line::from(Span::styled(
            "No logs captured yet (live logs are captured in `wpmulti run --tui`).",
            Style::default().fg(Color::DarkGray),
        ))]
    } else {
        logs[start..end]
            .iter()
            .map(|l| {
                let style = if l.contains("ERROR") {
                    Style::default().fg(Color::Red)
                } else if l.contains("WARN") {
                    Style::default().fg(Color::Yellow)
                } else if l.contains("INFO") {
                    Style::default().fg(Color::Green)
                } else if l.contains("DEBUG") {
                    Style::default().fg(Color::Cyan)
                } else {
                    Style::default()
                };
                Line::from(Span::styled(l.as_str(), style))
            })
            .collect()
    };

    let block = Block::default()
        .borders(Borders::ALL)
        .title(format!(" Live Logs [Filter: {}] ({} lines) ", filter_label, total));
    f.render_widget(Paragraph::new(lines).block(block), area);
}

fn draw_listeners_tab(f: &mut Frame, app: &TuiApp, area: Rect) {
    let header = Row::new(vec!["NAME", "TYPE", "ADDRESS", "MODE", "TUNNEL"]).style(
        Style::default()
            .fg(Color::Cyan)
            .add_modifier(Modifier::BOLD),
    );
    let visible = area.height.saturating_sub(3) as usize;
    let rows: Vec<Row> = app
        .listeners
        .iter()
        .skip(app.listener_scroll)
        .take(visible.max(1))
        .map(|l| {
            Row::new(vec![
                l.name.clone(),
                format!("{:?}", l.listener_type),
                l.address.to_string(),
                if l.is_shared { "Shared" } else { "Dedicated" }.to_string(),
                l.tunnel_id.clone().unwrap_or_else(|| "-".to_string()),
            ])
        })
        .collect();

    let table = Table::new(
        rows,
        [
            Constraint::Min(16),
            Constraint::Length(10),
            Constraint::Min(18),
            Constraint::Length(10),
            Constraint::Min(14),
        ],
    )
    .header(header)
    .block(
        Block::default()
            .borders(Borders::ALL)
            .title(format!(" Active Listeners ({}) ", app.listeners.len())),
    );
    f.render_widget(table, area);
}

fn draw_config_tab(f: &mut Frame, app: &TuiApp, area: Rect) {
    let Some(cfg) = &app.config_snapshot else {
        let block = Block::default()
            .borders(Borders::ALL)
            .title(" Runtime Config ");
        f.render_widget(
            Paragraph::new("Loading config from daemon...").block(block),
            area,
        );
        return;
    };

    let header = Row::new(vec!["SETTING", "VALUE", "ACTION"]).style(
        Style::default()
            .fg(Color::Cyan)
            .add_modifier(Modifier::BOLD),
    );

    let visible = (area.height.saturating_sub(3) as usize).max(1);
    let total = TuiApp::CONFIG_ROW_COUNT;
    let start = app
        .config_selected
        .saturating_sub(visible.saturating_sub(1))
        .min(total.saturating_sub(visible));

    let rows: Vec<Row> = (start..total)
        .take(visible)
        .map(|idx| {
            let (label, val, is_cycle) = TuiApp::config_row_display(cfg, idx);
            let display_val = if idx == app.config_selected {
                if let Some(edit_buf) = &app.config_editing {
                    format!("{}_", edit_buf)
                } else {
                    val
                }
            } else {
                val
            };
            let action = if is_cycle {
                "Enter/Space: cycle"
            } else {
                "Enter: edit"
            };
            let row = Row::new(vec![label.to_string(), display_val, action.to_string()]);
            if idx == app.config_selected {
                row.style(
                    Style::default()
                        .bg(Color::DarkGray)
                        .add_modifier(Modifier::BOLD),
                )
            } else {
                row
            }
        })
        .collect();

    let path_label = app
        .config_path
        .as_ref()
        .map(|p| p.display().to_string())
        .unwrap_or_else(|| "remote/in-memory".to_string());

    let table = Table::new(
        rows,
        [
            Constraint::Min(28),
            Constraint::Min(16),
            Constraint::Length(20),
        ],
    )
    .header(header)
    .block(
        Block::default()
            .borders(Borders::ALL)
            .title(format!(" Config ({}) ", path_label)),
    );
    f.render_widget(table, area);
}

fn draw_probe_tab(f: &mut Frame, app: &TuiApp, area: Rect) {
    if app.probe_results.is_empty() {
        let block = Block::default()
            .borders(Borders::ALL)
            .title(" Handshake Probe (0) ");
        f.render_widget(
            Paragraph::new(
                "No probe results yet. Press 'p' to probe selected tunnel or 'P' to probe all tunnels.",
            )
            .block(block),
            area,
        );
        return;
    }

    let header = Row::new(vec!["TUNNEL", "ENDPOINT", "STATUS", "RTT", "MESSAGE"]).style(
        Style::default()
            .fg(Color::Cyan)
            .add_modifier(Modifier::BOLD),
    );
    let visible = area.height.saturating_sub(3) as usize;
    let rows: Vec<Row> = app
        .probe_results
        .iter()
        .skip(app.probe_scroll)
        .take(visible.max(1))
        .map(|r| {
            let status_cell = if r.ok {
                Cell::from("OK").style(Style::default().fg(Color::Green))
            } else {
                Cell::from("FAIL").style(Style::default().fg(Color::Red))
            };
            let rtt = r
                .rtt_ms
                .map(|ms| format!("{}ms", ms))
                .unwrap_or_else(|| "-".to_string());
            Row::new(vec![
                Cell::from(r.id.clone()),
                Cell::from(r.endpoint.clone()),
                status_cell,
                Cell::from(rtt),
                Cell::from(r.message.clone()),
            ])
        })
        .collect();

    let table = Table::new(
        rows,
        [
            Constraint::Min(14),
            Constraint::Min(20),
            Constraint::Length(6),
            Constraint::Length(8),
            Constraint::Min(20),
        ],
    )
    .header(header)
    .block(
        Block::default()
            .borders(Borders::ALL)
            .title(format!(" Handshake Probe ({}) ", app.probe_results.len())),
    );
    f.render_widget(table, area);
}

fn draw_footer(f: &mut Frame, app: &TuiApp, area: Rect) {
    let help = match app.active_tab {
        TuiTab::Tunnels => {
            "1-5/Tab:Tabs  j/k:Nav  /:Search  s:Sort  a:Activate  d:Suspend  r:Reload  q:Quit"
        }
        TuiTab::Logs => "1-5/Tab:Tabs  j/k:Scroll  f:Filter Level  c:Clear  q:Quit",
        TuiTab::Listeners => "1-5/Tab:Tabs  j/k:Scroll  q:Quit",
        TuiTab::Config => "1-5/Tab:Tabs  j/k:Select  Enter:Edit/Cycle  w:Save+Reload  q:Quit",
        TuiTab::Probe => "1-5/Tab:Tabs  p:Probe Selected  P:Probe All  j/k:Scroll  q:Quit",
    };

    let mut lines = Vec::new();
    if app.is_searching {
        lines.push(Line::from(Span::styled(
            format!("Search: {}_", app.search_query),
            Style::default().fg(Color::Yellow),
        )));
    } else if let Some((msg, at)) = &app.status_message
        && at.elapsed() < Duration::from_secs(5)
    {
        lines.push(Line::from(Span::styled(
            format!(">>> {}", msg),
            Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        )));
    }
    if lines.is_empty() {
        lines.push(Line::from(""));
    }
    lines.push(Line::from(Span::styled(
        help,
        Style::default().fg(Color::DarkGray),
    )));

    f.render_widget(Paragraph::new(lines), area);
}

fn state_style(state: TunnelState) -> Style {
    match state {
        TunnelState::Active => Style::default().fg(Color::Green),
        TunnelState::Dormant => Style::default().fg(Color::DarkGray),
        TunnelState::Activating => Style::default().fg(Color::Yellow),
        TunnelState::Suspended => Style::default().fg(Color::Red),
    }
}

fn health_style(health: HealthStatus) -> Style {
    match health {
        HealthStatus::Healthy => Style::default().fg(Color::Green),
        HealthStatus::HalfOpen => Style::default().fg(Color::Yellow),
        HealthStatus::Unhealthy => Style::default().fg(Color::Red),
    }
}

struct TerminalGuard;

impl Drop for TerminalGuard {
    fn drop(&mut self) {
        let _ = disable_raw_mode();
        let _ = execute!(io::stdout(), LeaveAlternateScreen);
    }
}

/// Run the interactive terminal TUI loop using `ratatui` + `crossterm`.
pub async fn run_terminal_tui(mut app: TuiApp, refresh_rate_ms: u64) -> io::Result<()> {
    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen)?;
    let _guard = TerminalGuard;

    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    let _ = app.refresh().await;
    let mut last_refresh = Instant::now();
    let refresh_interval = Duration::from_millis(refresh_rate_ms.max(100));

    while app.running {
        terminal.draw(|f| draw_dashboard(f, &mut app))?;

        if event::poll(Duration::from_millis(100))?
            && let Event::Key(key) = event::read()?
            && key.kind == KeyEventKind::Press
        {
            if key.modifiers.contains(KeyModifiers::CONTROL)
                && key.code == KeyCode::Char('c')
            {
                app.running = false;
                break;
            }
            if let Some(tui_key) = map_crossterm_key(key.code) {
                handle_tui_key(&mut app, tui_key).await;
            }
        }

        if last_refresh.elapsed() >= refresh_interval {
            let _ = app.refresh().await;
            last_refresh = Instant::now();
        }
    }

    Ok(())
}

fn map_crossterm_key(code: KeyCode) -> Option<TuiKey> {
    match code {
        KeyCode::Char(c) => Some(TuiKey::Char(c)),
        KeyCode::Up => Some(TuiKey::Up),
        KeyCode::Down => Some(TuiKey::Down),
        KeyCode::Left => Some(TuiKey::Left),
        KeyCode::Right => Some(TuiKey::Right),
        KeyCode::PageUp => Some(TuiKey::PageUp),
        KeyCode::PageDown => Some(TuiKey::PageDown),
        KeyCode::Home => Some(TuiKey::Home),
        KeyCode::End => Some(TuiKey::End),
        KeyCode::Enter => Some(TuiKey::Enter),
        KeyCode::Backspace => Some(TuiKey::Backspace),
        KeyCode::Tab => Some(TuiKey::Tab),
        KeyCode::Esc => Some(TuiKey::Esc),
        _ => None,
    }
}

async fn handle_tui_key(app: &mut TuiApp, key: TuiKey) {
    if app.is_searching {
        match key {
            TuiKey::Esc | TuiKey::Enter => app.is_searching = false,
            TuiKey::Backspace => {
                app.search_query.pop();
                app.apply_filter_and_sort();
            }
            TuiKey::Char(c) => {
                app.search_query.push(c);
                app.apply_filter_and_sort();
            }
            _ => {}
        }
        return;
    }

    if app.active_tab == TuiTab::Config && app.config_editing.is_some() {
        match key {
            TuiKey::Esc => app.config_editing = None,
            TuiKey::Enter => {
                if let Err(e) = app.commit_config_edit().await {
                    app.set_status(format!("Config error: {}", e));
                }
            }
            TuiKey::Backspace => {
                if let Some(buf) = &mut app.config_editing {
                    buf.pop();
                }
            }
            TuiKey::Char(c) => {
                if let Some(buf) = &mut app.config_editing {
                    buf.push(c);
                }
            }
            _ => {}
        }
        return;
    }

    match key {
        TuiKey::Char('q') => app.running = false,
        TuiKey::Char('1') => app.set_tab(TuiTab::Tunnels),
        TuiKey::Char('2') => app.set_tab(TuiTab::Logs),
        TuiKey::Char('3') => app.set_tab(TuiTab::Listeners),
        TuiKey::Char('4') => app.set_tab(TuiTab::Config),
        TuiKey::Char('5') => app.set_tab(TuiTab::Probe),
        TuiKey::Tab | TuiKey::Right => app.next_tab(),
        TuiKey::Left => app.prev_tab(),
        _ => match app.active_tab {
            TuiTab::Tunnels => match key {
                TuiKey::Up | TuiKey::Char('k') => app.select_prev(),
                TuiKey::Down | TuiKey::Char('j') => app.select_next(),
                TuiKey::PageUp => app.page_up(10),
                TuiKey::PageDown => app.page_down(10),
                TuiKey::Home => app.scroll_to_top(),
                TuiKey::End => app.scroll_to_bottom(),
                TuiKey::Char('/') => app.is_searching = true,
                TuiKey::Char('s') => app.cycle_sort(),
                TuiKey::Char('a') => {
                    if let Err(e) = app.activate_selected().await {
                        app.set_status(format!("Activate error: {}", e));
                    }
                }
                TuiKey::Char('d') => {
                    if let Err(e) = app.suspend_selected().await {
                        app.set_status(format!("Suspend error: {}", e));
                    }
                }
                TuiKey::Char('r') => {
                    if let Err(e) = app.trigger_reload().await {
                        app.set_status(format!("Reload error: {}", e));
                    }
                }
                _ => {}
            },
            TuiTab::Logs => match key {
                TuiKey::Up | TuiKey::Char('k') => app.log_scroll = app.log_scroll.saturating_add(1),
                TuiKey::Down | TuiKey::Char('j') => {
                    app.log_scroll = app.log_scroll.saturating_sub(1);
                }
                TuiKey::Char('f') => app.cycle_log_filter(),
                TuiKey::Char('c') => {
                    if let Some(buf) = &app.log_buffer {
                        buf.clear();
                    }
                    app.log_scroll = 0;
                    app.set_status("Logs cleared");
                }
                _ => {}
            },
            TuiTab::Listeners => match key {
                TuiKey::Up | TuiKey::Char('k') => {
                    app.listener_scroll = app.listener_scroll.saturating_sub(1);
                }
                TuiKey::Down | TuiKey::Char('j')
                    if app.listener_scroll + 1 < app.listeners.len() =>
                {
                    app.listener_scroll += 1;
                }
                _ => {}
            },
            TuiTab::Config => match key {
                TuiKey::Up | TuiKey::Char('k') => {
                    app.config_selected = app.config_selected.saturating_sub(1);
                }
                TuiKey::Down | TuiKey::Char('j') => {
                    if app.config_selected + 1 < TuiApp::CONFIG_ROW_COUNT {
                        app.config_selected += 1;
                    }
                }
                TuiKey::Enter | TuiKey::Char(' ') => {
                    if let Err(e) = app.activate_config_row().await {
                        app.set_status(format!("Config error: {}", e));
                    }
                }
                TuiKey::Char('w') => {
                    if let Err(e) = app.save_config_and_reload().await {
                        app.set_status(format!("Save error: {}", e));
                    }
                }
                _ => {}
            },
            TuiTab::Probe => match key {
                TuiKey::Up | TuiKey::Char('k') => {
                    app.probe_scroll = app.probe_scroll.saturating_sub(1);
                }
                TuiKey::Down | TuiKey::Char('j') => {
                    if app.probe_scroll + 1 < app.probe_results.len() {
                        app.probe_scroll += 1;
                    }
                }
                TuiKey::Char('p') => app.probe_selected_tunnel().await,
                TuiKey::Char('P') => app.probe_all_tunnels().await,
                _ => {}
            },
        },
    }
}
