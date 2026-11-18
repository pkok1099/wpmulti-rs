//! Ratatui + Crossterm terminal UI renderer and interactive event loop for `wpmulti`.

use std::io::{self, IsTerminal};
use std::time::{Duration, Instant};

use crossterm::event::{
    self, DisableMouseCapture, EnableMouseCapture, Event, KeyCode, KeyEventKind, KeyModifiers,
    MouseButton, MouseEventKind,
};
use crossterm::execute;
use crossterm::terminal::{
    EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode, enable_raw_mode,
};
use ratatui::backend::{CrosstermBackend, TestBackend};
use ratatui::layout::{Constraint, Direction, Flex, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::symbols::Marker;
use ratatui::text::{Line, Span};
use ratatui::widgets::{
    Axis, Bar, BarChart, BarGroup, Block, BorderType, Borders, Cell, Chart, Clear, Dataset, Gauge,
    GraphType, Paragraph, Row, Scrollbar, ScrollbarOrientation, ScrollbarState, Table, Tabs,
};
use ratatui::{Frame, Terminal};

const ACCENT_CYAN: Color = Color::Rgb(0, 215, 255);
const RX_EMERALD: Color = Color::Rgb(80, 250, 123);
const TX_AMBER: Color = Color::Rgb(255, 184, 108);
const MUTED_SLATE: Color = Color::Rgb(98, 114, 164);
const SPINNER_FRAMES: [char; 10] = ['⠋', '⠙', '⠹', '⠸', '⠼', '⠴', '⠦', '⠧', '⠇', '⠏'];

use crate::core::health::HealthStatus;
use crate::core::{TunnelState, TunnelSummary};
use crate::tui::app::{TuiApp, TuiOverlay, TuiTab};
use crate::tui::config_editor::{ConfigApplyScope, ConfigField};

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
        format!("{bytes} B")
    }
}

/// Compact byte count for the "Top 5 Tunnels" bar values.
///
/// Ratatui only draws a bar's `text_value` when it fits the 7-cell bar
/// width, so a value like "12.50 MB" (8 chars) silently vanishes once
/// traffic grows. Precision shrinks with magnitude so the result never
/// exceeds 7 chars ("1.23 MB", "12.3 MB", "123 MB", "1.00 GB");
/// rounding that would push it over (e.g. 9.99 -> "10.00") steps down
/// one more decimal.
pub fn format_bytes_compact(bytes: u64) -> String {
    const KB: u64 = 1024;
    const MB: u64 = 1024 * KB;
    const GB: u64 = 1024 * MB;
    const TB: u64 = 1024 * GB;
    let (value, unit) = if bytes >= TB {
        (bytes as f64 / TB as f64, "TB")
    } else if bytes >= GB {
        (bytes as f64 / GB as f64, "GB")
    } else if bytes >= MB {
        (bytes as f64 / MB as f64, "MB")
    } else if bytes >= KB {
        (bytes as f64 / KB as f64, "KB")
    } else {
        return format!("{bytes} B");
    };
    let two_decimals = format!("{value:.2} {unit}");
    if value < 10.0 && two_decimals.len() <= 7 {
        two_decimals
    } else if value < 100.0 {
        let one_decimal = format!("{value:.1} {unit}");
        if one_decimal.len() <= 7 {
            one_decimal
        } else {
            format!("{value:.0} {unit}")
        }
    } else {
        format!("{value:.0} {unit}")
    }
}

/// Human age of a Unix timestamp, for the tunnel detail popup
/// ("12s ago", "3m ago", "2h ago", "5d ago"). `None` means the event
/// never happened.
pub fn format_ago(timestamp: Option<u64>) -> String {
    let Some(ts) = timestamp else {
        return "never".to_string();
    };
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs());
    let secs = now.saturating_sub(ts);
    if secs < 60 {
        format!("{secs}s ago")
    } else if secs < 3_600 {
        format!("{}m ago", secs / 60)
    } else if secs < 86_400 {
        format!("{}h ago", secs / 3_600)
    } else {
        format!("{}d ago", secs / 86_400)
    }
}

/// Shortest byte count, at most 4 chars ("1.5M", "639K", "104K", "0B").
///
/// Used for Top 5 bar values when the bars are too narrow for the
/// compact form. The unit is promoted while the value would round to
/// 1000 or more, so the result stays within 4 chars for any traffic
/// below a petabyte.
pub fn format_bytes_tiny(bytes: u64) -> String {
    const KB: f64 = 1024.0;
    let mut value = bytes as f64;
    let mut unit = "B";
    for next in ["K", "M", "G", "T"] {
        if value < 999.5 {
            break;
        }
        value /= KB;
        unit = next;
    }
    if unit == "B" {
        format!("{bytes}B")
    } else if value < 10.0 {
        format!("{value:.1}{unit}")
    } else {
        format!("{value:.0}{unit}")
    }
}

/// Top 5 bar value label that fits `width` cells.
///
/// The full compact form ("1.52 MB") when it fits, then the space
/// dropped ("1.52MB"), then the tiny form ("1.5M"), and empty when
/// even that does not fit — the bar still draws, and the exact value
/// is in the tunnel table.
pub fn format_bar_value(bytes: u64, width: u16) -> String {
    let width = width as usize;
    let compact = format_bytes_compact(bytes);
    if compact.len() <= width {
        return compact;
    }
    let nospace: String = compact.chars().filter(|c| *c != ' ').collect();
    if nospace.len() <= width {
        return nospace;
    }
    let tiny = format_bytes_tiny(bytes);
    if tiny.len() <= width {
        return tiny;
    }
    String::new()
}

/// (bar width, bar gap) so exactly five Top 5 bars fit `inner_width`.
///
/// `inner_width` is the panel width minus its borders: full 7-wide
/// bars with a 1-cell gap when there is room, shrinking to fit when
/// the panel is narrow. Below 9 cells even 1-wide bars with a gap do
/// not fit, so the gap drops to 0.
pub fn top_bar_dims(inner_width: u16) -> (u16, u16) {
    if inner_width >= 39 {
        (7, 1)
    } else if inner_width >= 9 {
        (((inner_width - 4) / 5).max(1), 1)
    } else {
        ((inner_width / 5).max(1), 0)
    }
}

/// Pool Health gauge label that fits `width` cells (the panel width
/// including its borders): the full "173/199 (87%)" when it fits,
/// then just the counts, then just the percentage.
pub fn gauge_label(width: u16, healthy: usize, total: usize, ratio: f64) -> String {
    if width >= 16 {
        format!("{healthy}/{total} ({:.0}%)", ratio * 100.0)
    } else if width >= 9 {
        format!("{healthy}/{total}")
    } else {
        format!("{:.0}%", ratio * 100.0)
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
    let Some(&first) = bytes.first() else {
        return (None, 0);
    };
    if first == 0x1b {
        let Some(&second) = bytes.get(1) else {
            return (Some(TuiKey::Esc), 1);
        };
        if second == b'[' || second == b'O' {
            let Some(&third) = bytes.get(2) else {
                return (None, 0);
            };
            return match third {
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
    match first {
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
    while let Some(rest) = bytes.get(offset..)
        && !rest.is_empty()
    {
        let (maybe_key, consumed) = parse_next_key(rest);
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
    let w = width.clamp(24, u16::MAX as usize) as u16;
    let h = height.clamp(8, u16::MAX as usize) as u16;
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
pub fn draw_dashboard(f: &mut Frame<'_>, app: &mut TuiApp) {
    let area = f.area();
    let [header_area, body_area, footer_area] = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3), // Header + Tabs
            Constraint::Min(3),    // Active Tab Body
            Constraint::Length(2), // Footer / Status
        ])
        .areas(area);

    draw_header_and_tabs(f, app, header_area);

    match app.active_tab {
        TuiTab::Tunnels => draw_tunnels_tab(f, app, body_area),
        TuiTab::Logs => draw_logs_tab(f, app, body_area),
        TuiTab::Listeners => draw_listeners_tab(f, app, body_area),
        TuiTab::Config => draw_config_tab(f, app, body_area),
        TuiTab::Probe => draw_probe_tab(f, app, body_area),
    }

    draw_footer(f, app, footer_area);

    // Overlays render last so they sit on top of the active tab.
    match app.overlay {
        TuiOverlay::Help => draw_help_popup(f, area),
        TuiOverlay::TunnelDetail => draw_tunnel_detail_popup(f, app, area),
        TuiOverlay::None => {}
    }
}

fn draw_header_and_tabs(f: &mut Frame<'_>, app: &TuiApp, area: Rect) {
    let active_count = app
        .tunnels
        .iter()
        .filter(|t| t.state == TunnelState::Active)
        .count();
    let total_conns: usize = app.tunnels.iter().map(|t| t.active_conns).sum();
    let spinner = SPINNER_FRAMES
        .get((app.anim_tick as usize) % SPINNER_FRAMES.len())
        .copied()
        .unwrap_or('-');
    let live_dot = if (app.anim_tick / 5).is_multiple_of(2) {
        "● LIVE"
    } else {
        "○ LIVE"
    };
    let title = if area.width < 60 {
        format!(" {} wpmulti v{} ", spinner, env!("CARGO_PKG_VERSION"))
    } else if app.data_source_error.is_some() {
        // A dead data source must not look like a healthy daemon with
        // no tunnels: show unknown counts, not 0. The footer carries
        // the error itself.
        format!(
            " {} {} wpmulti v{} | Tunnels: ? | Conns: ? (data source error) ",
            spinner,
            live_dot,
            env!("CARGO_PKG_VERSION"),
        )
    } else {
        format!(
            " {} {} wpmulti v{} | Tunnels: {} ({} active) | Conns: {} ",
            spinner,
            live_dot,
            env!("CARGO_PKG_VERSION"),
            app.tunnels.len(),
            active_count,
            total_conns
        )
    };

    let tab_titles: Vec<Line<'_>> = TuiTab::ALL.iter().map(|t| Line::from(t.label())).collect();
    let selected_idx = TuiTab::ALL
        .iter()
        .position(|t| *t == app.active_tab)
        .unwrap_or(0);

    let tabs = Tabs::new(tab_titles)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .border_type(BorderType::Rounded)
                .border_style(Style::default().fg(MUTED_SLATE))
                .title(Span::styled(
                    title,
                    Style::default()
                        .fg(ACCENT_CYAN)
                        .add_modifier(Modifier::BOLD),
                )),
        )
        .select(selected_idx)
        .divider(" │ ")
        .style(Style::default().fg(Color::Gray))
        .highlight_style(
            Style::default()
                .fg(Color::Black)
                .bg(ACCENT_CYAN)
                .add_modifier(Modifier::BOLD),
        );
    f.render_widget(tabs, area);
}

/// Bandwidth chart: RX and TX as two line series on one shared B/s
/// axis. The two sparklines it replaces had no scale at all — the only
/// numbers were the current rates in their titles — so a reader could
/// not tell whether a spike was 1 KB/s or 1 GB/s. `Chart` draws a real
/// Y axis with byte-rate labels; the block title keeps the live rates.
fn draw_overview_chart(f: &mut Frame<'_>, app: &TuiApp, chart_col: Rect) {
    let rx_points: Vec<(f64, f64)> = app
        .rx_rates
        .iter()
        .enumerate()
        .map(|(i, rate)| (i as f64, *rate as f64))
        .collect();
    let tx_points: Vec<(f64, f64)> = app
        .tx_rates
        .iter()
        .enumerate()
        .map(|(i, rate)| (i as f64, *rate as f64))
        .collect();
    let max_rate = app
        .rx_rates
        .iter()
        .chain(app.tx_rates.iter())
        .copied()
        .max()
        .unwrap_or(0)
        .max(1);

    // The Y labels sit evenly spaced from the bottom (first) to the top
    // (last) of the axis, so [0, mid, max] lines up with bounds [0, max].
    let y_labels = vec![
        Span::raw(format_bytes_compact(0)),
        Span::raw(format_bytes_compact(max_rate / 2)),
        Span::raw(format_bytes_compact(max_rate)),
    ];
    let title = Line::from(vec![
        Span::styled(
            " ▼ RX ",
            Style::default().fg(RX_EMERALD).add_modifier(Modifier::BOLD),
        ),
        Span::raw(format!("{}/s ", format_bytes(app.current_rx_bps))),
        Span::styled(
            "▲ TX ",
            Style::default().fg(TX_AMBER).add_modifier(Modifier::BOLD),
        ),
        Span::raw(format!("{}/s ", format_bytes(app.current_tx_bps))),
    ]);

    let chart = Chart::new(vec![
        Dataset::default()
            .marker(Marker::Braille)
            .graph_type(GraphType::Line)
            .style(Style::default().fg(RX_EMERALD))
            .data(&rx_points),
        Dataset::default()
            .marker(Marker::Braille)
            .graph_type(GraphType::Line)
            .style(Style::default().fg(TX_AMBER))
            .data(&tx_points),
    ])
    .block(
        Block::default()
            .borders(Borders::ALL)
            .border_type(BorderType::Rounded)
            .border_style(Style::default().fg(MUTED_SLATE))
            .title(title),
    )
    .x_axis(Axis::default().bounds([0.0, 64.0]))
    .y_axis(
        Axis::default()
            .bounds([0.0, max_rate as f64])
            .labels(y_labels),
    );
    f.render_widget(chart, chart_col);
}

/// Longest common prefix of the given strings, compared char by char.
pub(crate) fn common_prefix(strs: &[&str]) -> String {
    let mut prefix: Vec<char> = strs.first().map_or(Vec::new(), |s| s.chars().collect());
    for s in strs.iter().skip(1) {
        let kept = prefix
            .iter()
            .zip(s.chars())
            .take_while(|(a, b)| a == &b)
            .count();
        prefix.truncate(kept);
        if prefix.is_empty() {
            break;
        }
    }
    prefix.into_iter().collect()
}

/// Short label for a bar in the "Top 5 Tunnels" chart. Bars are 7
/// cells wide, so a label longer than that is clipped by the chart —
/// with a plain first-7-chars truncation, IDs sharing a prefix
/// (`wgcf-001`, `wgcf-002`) rendered identically as `wgcf-00`. The
/// shared prefix is stripped first; if that leaves fewer than 3
/// chars, the last 3 chars of the full ID are shown instead, so the
/// bars stay distinguishable.
pub(crate) fn short_bar_label(id: &str, common: &str) -> String {
    let stripped = id.strip_prefix(common).unwrap_or(id);
    if stripped.chars().count() >= 3 {
        stripped.chars().take(7).collect()
    } else {
        let chars: Vec<char> = id.chars().collect();
        let skip = chars.len().saturating_sub(3);
        chars.iter().skip(skip).collect()
    }
}

fn draw_tunnels_overview(f: &mut Frame<'_>, app: &TuiApp, t_area: Rect) {
    // The column split adapts to width. The 42/36/22 split only gives
    // the Top 5 room for five bars at width >= 73; below that the Top
    // 5 gets a fixed 26 and the gauge a fixed 14, so five thin bars
    // still fit and the gauge label is not clipped. The two layouts
    // meet at width 73 (both give the Top 5 26 cells), so there is no
    // jump at the breakpoint.
    let [chart_col, bar_col, gauge_col] = if t_area.width >= 73 {
        Layout::default()
            .direction(Direction::Horizontal)
            .constraints([
                Constraint::Percentage(42),
                Constraint::Percentage(36),
                Constraint::Percentage(22),
            ])
            .areas(t_area)
    } else {
        Layout::default()
            .direction(Direction::Horizontal)
            .constraints([
                Constraint::Fill(1),
                Constraint::Length(26),
                Constraint::Length(14),
            ])
            .areas(t_area)
    };

    draw_overview_chart(f, app, chart_col);

    let top = app.top_tunnels(5);
    let ids: Vec<&str> = top.iter().map(|(id, _)| *id).collect();
    let common = common_prefix(&ids);
    let (bar_width, bar_gap) = top_bar_dims(bar_col.width.saturating_sub(2));
    let bars: Vec<Bar<'_>> = top
        .iter()
        .map(|(id, total)| {
            Bar::default()
                .value(*total)
                .label(Line::from(short_bar_label(id, &common)))
                .text_value(format_bar_value(*total, bar_width))
                .style(Style::default().fg(ACCENT_CYAN))
        })
        .collect();
    let barchart = BarChart::default()
        .block(
            Block::default()
                .borders(Borders::ALL)
                .border_type(BorderType::Rounded)
                .border_style(Style::default().fg(MUTED_SLATE))
                .title(Span::styled(
                    " Top 5 Tunnels ",
                    Style::default()
                        .fg(ACCENT_CYAN)
                        .add_modifier(Modifier::BOLD),
                )),
        )
        .data(BarGroup::default().bars(&bars))
        .bar_width(bar_width)
        .bar_gap(bar_gap)
        .value_style(Style::default().fg(Color::White))
        .label_style(Style::default().fg(Color::Gray));
    f.render_widget(barchart, bar_col);

    let total = app.tunnels.len().max(1);
    let healthy = app
        .tunnels
        .iter()
        .filter(|t| t.health == HealthStatus::Healthy)
        .count();
    let ratio = (healthy as f64 / total as f64).clamp(0.0, 1.0);
    let gauge_color = if ratio >= 0.8 {
        RX_EMERALD
    } else if ratio >= 0.4 {
        TX_AMBER
    } else {
        Color::Rgb(255, 85, 85)
    };
    let gauge = Gauge::default()
        .block(
            Block::default()
                .borders(Borders::ALL)
                .border_type(BorderType::Rounded)
                .border_style(Style::default().fg(MUTED_SLATE))
                .title(" Pool Health "),
        )
        .gauge_style(Style::default().fg(gauge_color).bg(Color::Rgb(40, 42, 54)))
        .ratio(ratio)
        .label(gauge_label(
            gauge_col.width,
            healthy,
            app.tunnels.len(),
            ratio,
        ));
    f.render_widget(gauge, gauge_col);
}

#[derive(Clone, Copy)]
struct TableColumns {
    tx: bool,
    port: bool,
    endpoint: bool,
}

fn build_tunnel_table_rows(
    app: &TuiApp,
    visible_rows: usize,
    cols: TableColumns,
) -> Vec<Row<'static>> {
    app.filtered_indices
        .iter()
        .enumerate()
        .skip(app.scroll_offset)
        .take(visible_rows.max(1))
        .filter_map(|(vis_idx, &orig_idx)| {
            let t = app.tunnels.get(orig_idx)?;
            let (state_str, st_style) = if t.disabled {
                (
                    "Disabled".to_string(),
                    Style::default().fg(Color::Rgb(255, 85, 85)),
                )
            } else {
                (format!("{:?}", t.state), state_style(t.state))
            };
            let health_str = match t.health {
                HealthStatus::Untested => "Untested",
                HealthStatus::Healthy => "Healthy",
                HealthStatus::HalfOpen => "HalfOpen",
                HealthStatus::Unhealthy => "Unhealthy",
                HealthStatus::Dead => "Dead",
            };
            let mut cells = vec![
                Cell::from(sanitize_terminal_text(&t.id)),
                Cell::from(state_str).style(st_style),
                Cell::from(health_str).style(health_style(t.health)),
                Cell::from(t.active_conns.to_string()),
                Cell::from(format_bytes(t.rx_bytes)),
            ];
            if cols.tx {
                cells.push(Cell::from(format_bytes(t.tx_bytes)));
            }
            if cols.port {
                let port = t
                    .assigned_port
                    .map_or_else(|| "-".to_string(), |p| p.to_string());
                cells.push(Cell::from(port));
            }
            if cols.endpoint {
                let ep = t
                    .endpoint
                    .as_deref()
                    .map_or_else(|| "-".to_string(), sanitize_terminal_text);
                cells.push(Cell::from(ep));
            }
            let row = Row::new(cells);
            if vis_idx == app.selected_index {
                Some(
                    row.style(
                        Style::default()
                            .bg(Color::DarkGray)
                            .add_modifier(Modifier::BOLD),
                    ),
                )
            } else {
                Some(row)
            }
        })
        .collect()
}

fn draw_tunnels_tab(f: &mut Frame<'_>, app: &mut TuiApp, area: Rect) {
    let show_top = area.height >= 15 && area.width >= 56;
    let (top_area, table_area) = if show_top {
        let [top, tbl] = Layout::default()
            .direction(Direction::Vertical)
            .constraints([Constraint::Length(8), Constraint::Min(4)])
            .areas(area);
        (Some(top), tbl)
    } else {
        (None, area)
    };

    if let Some(t_area) = top_area {
        draw_tunnels_overview(f, app, t_area);
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

    let rows = build_tunnel_table_rows(
        app,
        visible_rows,
        TableColumns {
            tx: show_tx,
            port: show_port,
            endpoint: show_endpoint,
        },
    );

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

    let table = Table::new(rows, widths).header(header_row).block(
        Block::default()
            .borders(Borders::ALL)
            .border_type(BorderType::Rounded)
            .border_style(Style::default().fg(Color::DarkGray))
            .title(pos_title),
    );
    f.render_widget(table, table_area);

    if total_visible > visible_rows.max(1) {
        let mut sb_state = ScrollbarState::new(total_visible).position(app.selected_index);
        f.render_stateful_widget(
            Scrollbar::new(ScrollbarOrientation::VerticalRight),
            table_area,
            &mut sb_state,
        );
    }
}

fn draw_logs_tab(f: &mut Frame<'_>, app: &TuiApp, area: Rect) {
    let filter_label = app.log_level_filter.as_deref().unwrap_or("ALL");
    let logs = app.filtered_logs();
    let visible = area.height.saturating_sub(2) as usize;
    let total = logs.len();
    let max_scroll = total.saturating_sub(visible);
    let scroll = app.log_scroll.min(max_scroll);
    let start = total.saturating_sub(visible + scroll);
    let end = total.saturating_sub(scroll);

    let lines: Vec<Line<'_>> = logs
        .get(start..end)
        .filter(|slice| !slice.is_empty())
        .map_or_else(
            || {
                vec![Line::from(Span::styled(
                    "No logs captured yet (the daemon keeps a ring buffer; `top` reads it via the Admin API).",
                    Style::default().fg(Color::DarkGray),
                ))]
            },
            |slice| {
                slice
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
                        Line::from(Span::styled(sanitize_terminal_text(l), style))
                    })
                    .collect()
            },
        );

    let block = Block::default().borders(Borders::ALL).title(format!(
        " Live Logs [Filter: {filter_label}] ({total} lines) "
    ));
    f.render_widget(Paragraph::new(lines).block(block), area);
}

fn draw_listeners_tab(f: &mut Frame<'_>, app: &TuiApp, area: Rect) {
    let header = Row::new(vec!["NAME", "TYPE", "ADDRESS", "MODE", "TUNNEL"]).style(
        Style::default()
            .fg(Color::Cyan)
            .add_modifier(Modifier::BOLD),
    );
    let visible = area.height.saturating_sub(3) as usize;
    let rows: Vec<Row<'_>> = app
        .listeners
        .iter()
        .skip(app.listener_scroll)
        .take(visible.max(1))
        .map(|l| {
            Row::new(vec![
                sanitize_terminal_text(&l.name),
                format!("{:?}", l.listener_type),
                l.address.to_string(),
                if l.is_shared { "Shared" } else { "Dedicated" }.to_string(),
                l.tunnel_id
                    .as_deref()
                    .map_or_else(|| "-".to_string(), sanitize_terminal_text),
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

/// Show the tail of a Config edit buffer, so the cursor — always at the
/// end, because editing is append-only (`Backspace` pops the last
/// character) — stays visible. A long JSON used to be cut off at the
/// right edge of the VALUE column with no way to see its end (`End` and
/// the arrow keys do nothing while editing); now the head is replaced by
/// "…" and the last characters plus the cursor are shown.
pub(crate) fn visible_edit_tail(buf: &str, width: usize) -> String {
    let chars: Vec<char> = buf.chars().collect();
    if chars.len() < width {
        return format!("{buf}_");
    }
    let shown = width.saturating_sub(2).max(1).min(chars.len());
    let tail: String = chars
        .get(chars.len() - shown..)
        .unwrap_or(&[])
        .iter()
        .collect();
    format!("…{tail}_")
}

fn build_config_table_row<'a>(
    app: &TuiApp,
    cfg: &crate::config::MainConfig,
    idx: usize,
    value_width: usize,
) -> Row<'a> {
    let field = ConfigField::from_index(idx).unwrap_or(ConfigField::DisabledTunnels);
    let scope = field.scope();
    let scope_cell = match scope {
        ConfigApplyScope::Live => Cell::from(scope.tag()).style(
            Style::default()
                .fg(Color::Green)
                .add_modifier(Modifier::BOLD),
        ),
        ConfigApplyScope::Restart => Cell::from(scope.tag()).style(
            Style::default()
                .fg(Color::Yellow)
                .add_modifier(Modifier::BOLD),
        ),
    };

    let val = field.display_value(cfg);
    let is_modified = app
        .config_saved_baseline
        .as_ref()
        .is_some_and(|saved| field.differs(saved, cfg));
    let is_restart_pending = scope == ConfigApplyScope::Restart
        && app
            .config_startup_baseline
            .as_ref()
            .is_some_and(|start| field.differs(start, cfg));

    let display_val = if idx == app.config_selected && app.config_editing.is_some() {
        app.config_editing
            .as_ref()
            .map_or(val, |edit_buf| visible_edit_tail(edit_buf, value_width))
    } else if is_modified {
        format!("{val} *")
    } else {
        val
    };

    let val_style = if is_restart_pending {
        Style::default().fg(Color::Yellow)
    } else if is_modified {
        Style::default().fg(Color::Cyan)
    } else {
        Style::default()
    };

    let action = if field.is_cycle() {
        "Enter/Spc:cyc"
    } else {
        "Enter: edit"
    };

    let row = Row::new(vec![
        scope_cell,
        Cell::from(field.key()),
        Cell::from(sanitize_terminal_text(&display_val)).style(val_style),
        Cell::from(action),
    ]);
    if idx == app.config_selected {
        row.style(
            Style::default()
                .bg(Color::DarkGray)
                .add_modifier(Modifier::BOLD),
        )
    } else {
        row
    }
}

fn draw_config_tab(f: &mut Frame<'_>, app: &TuiApp, area: Rect) {
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

    let header = Row::new(vec!["SCOPE", "SETTING", "VALUE", "ACTION"]).style(
        Style::default()
            .fg(Color::Cyan)
            .add_modifier(Modifier::BOLD),
    );

    let visible = (area.height.saturating_sub(3) as usize).max(1);
    let total = ConfigField::ALL.len();
    let start = app
        .config_selected
        .saturating_sub(visible.saturating_sub(1))
        .min(total.saturating_sub(visible));

    let rows: Vec<Row<'_>> = (start..total)
        .take(visible)
        .map(|idx| {
            // SCOPE(10) + SETTING(28) + ACTION(14) + borders and cell
            // spacing: the VALUE column gets the rest of the width.
            let value_width = (area.width as usize).saturating_sub(57).max(18);
            build_config_table_row(app, cfg, idx, value_width)
        })
        .collect();

    let path_label = app.config_path.as_ref().map_or_else(
        || "remote/in-memory".to_string(),
        |p| p.display().to_string(),
    );
    let diff = app.config_diff_vs_saved();
    let pending_restart = app.config_pending_restart();
    let unsaved = diff.live_changed.len() + diff.restart_changed.len();
    let mut flags = Vec::new();
    if unsaved > 0 {
        flags.push(format!("{unsaved} unsaved"));
    }
    if !pending_restart.is_empty() {
        flags.push(format!("{} restart pending", pending_restart.len()));
    }
    let title = if flags.is_empty() {
        format!(
            " Config ({path_label}) [{}/{} rows] ",
            app.config_selected + 1,
            total
        )
    } else {
        format!(
            " Config ({path_label}) [{}] [{}/{} rows] ",
            flags.join(", "),
            app.config_selected + 1,
            total
        )
    };

    let table = Table::new(
        rows,
        [
            Constraint::Length(10),
            // Length, not Min: with Min the solver grew SETTING past
            // 28 and starved VALUE, so at 110 cols the
            // `shared_listener` summary was clipped right after
            // `anon` even though the `value_width` math above assumes
            // SETTING is exactly 28. The longest setting key is 27
            // chars (`per_tunnel.base_socks5_port`), so 28 fits.
            Constraint::Length(28),
            Constraint::Min(18),
            Constraint::Length(14),
        ],
    )
    .header(header)
    .block(Block::default().borders(Borders::ALL).title(title));
    f.render_widget(table, area);
}

fn draw_probe_tab(f: &mut Frame<'_>, app: &TuiApp, area: Rect) {
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
    let rows: Vec<Row<'_>> = app
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
                .map_or_else(|| "-".to_string(), |ms| format!("{ms}ms"));
            Row::new(vec![
                Cell::from(sanitize_terminal_text(&r.id)),
                Cell::from(sanitize_terminal_text(&r.endpoint)),
                status_cell,
                Cell::from(rtt),
                Cell::from(sanitize_terminal_text(&r.message)),
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

fn draw_footer(f: &mut Frame<'_>, app: &TuiApp, area: Rect) {
    let help = match app.active_tab {
        TuiTab::Tunnels => {
            // When a search filter is active, say on-screen how to clear
            // it — before this, the only clue was "Tunnel 1 of 1" in the
            // table title and `Esc` silently did nothing.
            if app.search_query.is_empty() {
                "?:Help  1-5/Tab:Tabs  j/k:Nav  /:Search  s:Sort  a:Activate  d:Suspend  x:Toggle  X:Batch  r:Reload  q:Quit"
            } else {
                "?:Help  1-5/Tab:Tabs  j/k:Nav  /:Search  Esc:Clear filter  s:Sort  a:Activate  d:Suspend  x:Toggle  X:Batch  r:Reload  q:Quit"
            }
        }
        TuiTab::Logs => "1-5/Tab:Tabs  j/k:Scroll  f:Filter Level  c:Clear  q:Quit",
        TuiTab::Listeners => "1-5/Tab:Tabs  j/k:Scroll  q:Quit",
        TuiTab::Config => "1-5/Tab:Tabs  j/k/PgUp/PgDn:Nav  Enter:Edit/Cycle  w:Save+Apply  q:Quit",
        TuiTab::Probe => "1-5/Tab:Tabs  p:Probe Selected  P:Probe All  j/k:Scroll  q:Quit",
    };

    let mut lines = Vec::new();
    if let Some(buf) = &app.batch_prompt {
        lines.push(Line::from(Span::styled(
            format!("Batch [+/-]target (e.g. -1-200, +1-50, A, all): {buf}_"),
            Style::default().fg(Color::Yellow),
        )));
    } else if app.is_searching {
        lines.push(Line::from(Span::styled(
            format!("Search: {}_", app.search_query),
            Style::default().fg(Color::Yellow),
        )));
    } else if app.config_editing.is_some() {
        // While a Config value is being edited every typed character,
        // including `q`, goes into the editor; say so before the user
        // discovers it by losing a quit keystroke.
        lines.push(Line::from(Span::styled(
            "Editing value: Enter confirms, Esc cancels",
            Style::default().fg(Color::Yellow),
        )));
    } else if let Some(err) = &app.data_source_error {
        // A dead data source must not look like an empty daemon. This
        // outranks the transient status message (it is persistent until
        // a fetch succeeds) but not an interactive prompt above.
        lines.push(Line::from(Span::styled(
            format!("⚠ {}", sanitize_terminal_text(err)),
            Style::default().fg(Color::Red).add_modifier(Modifier::BOLD),
        )));
    } else if let Some((msg, at)) = &app.status_message
        && at.elapsed() < Duration::from_secs(8)
    {
        lines.push(Line::from(Span::styled(
            format!(">>> {}", sanitize_terminal_text(msg)),
            Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        )));
    } else {
        // No status line to show.
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

/// Centered rectangle for popups: a fixed-size area clamped to the
/// frame and centered with `Flex::Center`, so the popup adapts to any
/// terminal size instead of being anchored to a corner.
fn popup_area(area: Rect, width: u16, height: u16) -> Rect {
    let width = width.min(area.width);
    let height = height.min(area.height);
    let [area] = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(height)])
        .flex(Flex::Center)
        .areas(area);
    let [area] = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Length(width)])
        .flex(Flex::Center)
        .areas(area);
    area
}

/// Render a popup on top of the dashboard: `Clear` wipes the cells
/// underneath so the popup does not smear over the table, then a
/// bordered `Paragraph` carries the content. The size follows the
/// content, so a short popup is small and a long one grows.
fn draw_popup(f: &mut Frame<'_>, area: Rect, title: &str, lines: Vec<Line<'_>>) {
    let height = (lines.len() as u16).saturating_add(2);
    let width = lines
        .iter()
        .map(|line| line.width() as u16)
        .max()
        .unwrap_or(0)
        .saturating_add(4);
    let popup = popup_area(area, width, height);
    f.render_widget(Clear, popup);
    f.render_widget(
        Paragraph::new(lines).block(
            Block::default()
                .borders(Borders::ALL)
                .border_type(BorderType::Rounded)
                .border_style(Style::default().fg(ACCENT_CYAN))
                .title(Span::styled(
                    format!(" {title} "),
                    Style::default()
                        .fg(ACCENT_CYAN)
                        .add_modifier(Modifier::BOLD),
                )),
        ),
        popup,
    );
}

fn help_popup_lines() -> Vec<Line<'static>> {
    vec![
        Line::from(" 1-5 / Tab   switch tabs    j/k  move    PgUp/PgDn  page "),
        Line::from(" Tunnels: / search · s sort · a activate · d suspend "),
        Line::from("          x toggle disabled · X batch · r reload "),
        Line::from("          Enter  tunnel details "),
        Line::from(" Logs: f filter level · c clear "),
        Line::from(" Config: Enter edit / cycle · w save + apply "),
        Line::from(" Probe: p probe selected · P probe all "),
        Line::from(" ? this help · q quit "),
    ]
}

fn draw_help_popup(f: &mut Frame<'_>, area: Rect) {
    draw_popup(f, area, "Help", help_popup_lines());
}

fn detail_popup_lines(tunnel: &TunnelSummary) -> Vec<Line<'static>> {
    let endpoint = tunnel.endpoint.as_deref().unwrap_or("—");
    let port = tunnel
        .assigned_port
        .map_or_else(|| "—".to_string(), |p| p.to_string());
    vec![
        Line::from(format!(" ID: {}", tunnel.id)),
        Line::from(format!(
            " State: {:?}  ·  Health: {:?}",
            tunnel.state, tunnel.health
        )),
        Line::from(format!(
            " Mode: {:?}  ·  Conns: {} active / {} total",
            tunnel.mode, tunnel.active_conns, tunnel.total_conns
        )),
        Line::from(format!(
            " RX: {}  ·  TX: {}",
            format_bytes(tunnel.rx_bytes),
            format_bytes(tunnel.tx_bytes)
        )),
        Line::from(format!(" Endpoint: {endpoint}")),
        Line::from(format!(" Port: {port}")),
        Line::from(format!(
            " Last handshake: {}",
            format_ago(tunnel.last_handshake)
        )),
    ]
}

fn draw_tunnel_detail_popup(f: &mut Frame<'_>, app: &TuiApp, area: Rect) {
    let Some(tunnel) = app.selected_tunnel() else {
        return;
    };
    draw_popup(f, area, "Tunnel Detail", detail_popup_lines(tunnel));
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
        HealthStatus::Untested => Style::default().fg(Color::Gray),
        HealthStatus::Healthy => Style::default().fg(Color::Green),
        HealthStatus::HalfOpen => Style::default().fg(Color::Yellow),
        HealthStatus::Unhealthy => Style::default().fg(Color::Red),
        HealthStatus::Dead => Style::default().fg(Color::Magenta),
    }
}

fn sanitize_terminal_text(s: &str) -> String {
    s.chars()
        .filter_map(|c| {
            if c == '\t' {
                Some(' ')
            } else if c.is_control() {
                None
            } else {
                Some(c)
            }
        })
        .collect()
}

struct TerminalGuard;

impl Drop for TerminalGuard {
    fn drop(&mut self) {
        let _ = disable_raw_mode();
        let _ = execute!(io::stdout(), LeaveAlternateScreen, DisableMouseCapture);
    }
}

fn install_terminal_panic_hook() {
    static PANIC_HOOK_INIT: std::sync::Once = std::sync::Once::new();
    PANIC_HOOK_INIT.call_once(|| {
        let prev = std::panic::take_hook();
        std::panic::set_hook(Box::new(move |info| {
            let _ = disable_raw_mode();
            let _ = execute!(io::stdout(), LeaveAlternateScreen, DisableMouseCapture);
            prev(info);
        }));
    });
}

async fn process_terminal_event(app: &mut TuiApp, ev: Event) {
    match ev {
        Event::Key(key) if key.kind == KeyEventKind::Press => {
            if key.modifiers.contains(KeyModifiers::CONTROL) && key.code == KeyCode::Char('c') {
                app.running = false;
                return;
            }
            if let Some(tui_key) = map_crossterm_key(key.code) {
                handle_tui_key(app, tui_key).await;
            }
        }
        Event::Mouse(mouse) => match mouse.kind {
            MouseEventKind::ScrollDown => handle_tui_key(app, TuiKey::Down).await,
            MouseEventKind::ScrollUp => handle_tui_key(app, TuiKey::Up).await,
            MouseEventKind::Down(MouseButton::Left) if mouse.row == 1 => {
                if let Some(tab) = tab_at_column(mouse.column as usize) {
                    app.set_tab(tab);
                }
            }
            MouseEventKind::Down(_)
            | MouseEventKind::Up(_)
            | MouseEventKind::Drag(_)
            | MouseEventKind::Moved
            | MouseEventKind::ScrollLeft
            | MouseEventKind::ScrollRight => {}
        },
        Event::Key(_)
        | Event::FocusGained
        | Event::FocusLost
        | Event::Paste(_)
        | Event::Resize(_, _) => {}
    }
}

/// Run the interactive terminal TUI loop using `ratatui` + `crossterm`.
pub async fn run_terminal_tui(mut app: TuiApp, refresh_rate_ms: u64) -> io::Result<()> {
    if !io::stdin().is_terminal() || !io::stdout().is_terminal() {
        return Err(io::Error::other(
            "TUI requires an interactive terminal (TTY). Run this command in a terminal, or use `wpmulti status` / the Admin API to inspect the daemon instead.",
        ));
    }
    install_terminal_panic_hook();
    enable_raw_mode()?;
    let _guard = TerminalGuard;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen, EnableMouseCapture)?;

    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    let _ = app.refresh().await;
    let mut last_refresh = Instant::now();
    let mut last_anim = Instant::now();

    #[cfg(unix)]
    let mut sigterm =
        tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()).ok();

    while app.running {
        let refresh_interval = app.effective_refresh_interval(refresh_rate_ms);
        if last_anim.elapsed() >= Duration::from_millis(100) {
            app.anim_tick = app.anim_tick.wrapping_add(1);
            last_anim = Instant::now();
        }
        terminal.draw(|f| draw_dashboard(f, &mut app))?;

        let poll_fut = tokio::task::spawn_blocking(|| -> io::Result<Option<Event>> {
            if event::poll(Duration::from_millis(100))? {
                Ok(Some(event::read()?))
            } else {
                Ok(None)
            }
        });

        let term_fut = async {
            #[cfg(unix)]
            if let Some(ref mut s) = sigterm {
                s.recv().await;
                return;
            }
            std::future::pending::<()>().await;
        };

        let maybe_event = tokio::select! {
            _ = tokio::signal::ctrl_c() => {
                app.running = false;
                break;
            }
            () = term_fut => {
                app.running = false;
                break;
            }
            res = poll_fut => {
                match res {
                    Ok(Ok(ev)) => ev,
                    Ok(Err(e)) => return Err(e),
                    Err(_) => None,
                }
            }
        };

        if let Some(ev) = maybe_event {
            process_terminal_event(&mut app, ev).await;
            if !app.running {
                break;
            }
        }

        if last_refresh.elapsed() >= refresh_interval {
            let _ = app.refresh().await;
            last_refresh = Instant::now();
        }
    }

    Ok(())
}

/// Map a terminal column inside the Tabs row (`row == 1`) to the matching [`TuiTab`].
fn tab_at_column(col: usize) -> Option<TuiTab> {
    // Tabs widget renders inside left border (col 1) with default " " padding and " │ " divider.
    let mut cursor = 1usize;
    for (idx, &tab) in TuiTab::ALL.iter().enumerate() {
        let label_len = tab.label().chars().count() + 2;
        if col >= cursor && col < cursor + label_len {
            return Some(tab);
        }
        cursor += label_len;
        if idx + 1 < TuiTab::ALL.len() {
            cursor += 3; // " │ "
        }
    }
    None
}

// `crossterm::event::KeyCode` is a large external input enum; unmapped keys return `None`.
#[allow(
    clippy::wildcard_enum_match_arm,
    reason = "crossterm KeyCode is a large external input enum; unmapped keys return None"
)]
const fn map_crossterm_key(code: KeyCode) -> Option<TuiKey> {
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

async fn handle_prompt_key(app: &mut TuiApp, key: TuiKey) -> bool {
    if app.batch_prompt.is_some() {
        match key {
            TuiKey::Esc => app.batch_prompt = None,
            TuiKey::Enter => {
                if let Err(e) = app.commit_batch_toggle().await {
                    app.set_status(format!("Batch error: {e}"));
                }
            }
            TuiKey::Backspace => {
                if let Some(buf) = &mut app.batch_prompt {
                    buf.pop();
                }
            }
            TuiKey::Char(c) => {
                if let Some(buf) = &mut app.batch_prompt {
                    buf.push(c);
                }
            }
            TuiKey::Up
            | TuiKey::Down
            | TuiKey::Left
            | TuiKey::Right
            | TuiKey::PageUp
            | TuiKey::PageDown
            | TuiKey::Home
            | TuiKey::End
            | TuiKey::Tab => {}
        }
        return true;
    }

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
            TuiKey::Up
            | TuiKey::Down
            | TuiKey::Left
            | TuiKey::Right
            | TuiKey::PageUp
            | TuiKey::PageDown
            | TuiKey::Home
            | TuiKey::End
            | TuiKey::Tab => {}
        }
        return true;
    }

    if app.active_tab == TuiTab::Config && app.config_editing.is_some() {
        match key {
            TuiKey::Esc => app.config_editing = None,
            TuiKey::Enter => {
                if let Err(e) = app.commit_config_edit().await {
                    app.set_status(format!("Config error: {e}"));
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
            TuiKey::Up
            | TuiKey::Down
            | TuiKey::Left
            | TuiKey::Right
            | TuiKey::PageUp
            | TuiKey::PageDown
            | TuiKey::Home
            | TuiKey::End
            | TuiKey::Tab => {}
        }
        return true;
    }

    false
}

async fn handle_tunnels_tab_key(app: &mut TuiApp, key: TuiKey) {
    match key {
        TuiKey::Up | TuiKey::Char('k') => app.select_prev(),
        TuiKey::Down | TuiKey::Char('j') => app.select_next(),
        TuiKey::PageUp => app.page_up(10),
        TuiKey::PageDown => app.page_down(10),
        TuiKey::Home => app.scroll_to_top(),
        TuiKey::End => app.scroll_to_bottom(),
        // A fresh search starts from an empty query: the previous query
        // is NOT carried over, so `/` + `Enter` with nothing typed clears
        // the filter instead of silently keeping the old one.
        TuiKey::Char('/') => {
            app.search_query.clear();
            app.apply_filter_and_sort();
            app.is_searching = true;
        }
        // `Esc` with no prompt open clears an active search filter. Before
        // this, `Esc` did nothing once a filter was applied, and the only
        // way out was re-opening `/` and backspacing the old query — which
        // no docs or on-screen hint ever said.
        TuiKey::Esc => {
            if !app.search_query.is_empty() {
                app.search_query.clear();
                app.apply_filter_and_sort();
            }
        }
        TuiKey::Char('s') => app.cycle_sort(),
        TuiKey::Char('a') => {
            if let Err(e) = app.activate_selected().await {
                app.set_status(format!("Activate error: {e}"));
            }
        }
        TuiKey::Char('d') => {
            if let Err(e) = app.suspend_selected().await {
                app.set_status(format!("Suspend error: {e}"));
            }
        }
        TuiKey::Char('x') => {
            if let Err(e) = app.toggle_selected_disabled().await {
                app.set_status(format!("Toggle error: {e}"));
            }
        }
        TuiKey::Char('X') => {
            app.batch_prompt = Some(String::new());
        }
        TuiKey::Char('r') => {
            if let Err(e) = app.trigger_reload().await {
                app.set_status(format!("Reload error: {e}"));
            }
        }
        // `Enter` opens the tunnel detail overlay for the selected row.
        // It is a no-op when nothing is selected (empty daemon).
        TuiKey::Enter => {
            if app.selected_tunnel().is_some() {
                app.overlay = TuiOverlay::TunnelDetail;
            }
        }
        TuiKey::Char(_) | TuiKey::Left | TuiKey::Right | TuiKey::Backspace | TuiKey::Tab => {}
    }
}

fn handle_logs_tab_key(app: &mut TuiApp, key: TuiKey) {
    match key {
        TuiKey::Up | TuiKey::Char('k') => app.log_scroll = app.log_scroll.saturating_add(1),
        TuiKey::Down | TuiKey::Char('j') => {
            app.log_scroll = app.log_scroll.saturating_sub(1);
        }
        TuiKey::Char('f') => app.cycle_log_filter(),
        TuiKey::Char('c') => {
            app.clear_logs();
            app.log_scroll = 0;
            app.set_status("Logs cleared");
        }
        TuiKey::Char(_)
        | TuiKey::Left
        | TuiKey::Right
        | TuiKey::PageUp
        | TuiKey::PageDown
        | TuiKey::Home
        | TuiKey::End
        | TuiKey::Enter
        | TuiKey::Backspace
        | TuiKey::Tab
        | TuiKey::Esc => {}
    }
}

const fn handle_listeners_tab_key(app: &mut TuiApp, key: TuiKey) {
    match key {
        TuiKey::Up | TuiKey::Char('k') => {
            app.listener_scroll = app.listener_scroll.saturating_sub(1);
        }
        TuiKey::Down | TuiKey::Char('j') if app.listener_scroll + 1 < app.listeners.len() => {
            app.listener_scroll += 1;
        }
        TuiKey::Char(_)
        | TuiKey::Down
        | TuiKey::Left
        | TuiKey::Right
        | TuiKey::PageUp
        | TuiKey::PageDown
        | TuiKey::Home
        | TuiKey::End
        | TuiKey::Enter
        | TuiKey::Backspace
        | TuiKey::Tab
        | TuiKey::Esc => {}
    }
}

async fn handle_config_tab_key(app: &mut TuiApp, key: TuiKey) {
    let last_idx = TuiApp::CONFIG_ROW_COUNT.saturating_sub(1);
    match key {
        TuiKey::Up | TuiKey::Char('k') => {
            app.config_selected = app.config_selected.saturating_sub(1);
        }
        TuiKey::Down | TuiKey::Char('j') if app.config_selected < last_idx => {
            app.config_selected += 1;
        }
        TuiKey::PageUp => {
            app.config_selected = app.config_selected.saturating_sub(10);
        }
        TuiKey::PageDown => {
            app.config_selected = (app.config_selected + 10).min(last_idx);
        }
        TuiKey::Home => app.config_selected = 0,
        TuiKey::End => app.config_selected = last_idx,
        TuiKey::Enter | TuiKey::Char(' ') => {
            if let Err(e) = app.activate_config_row().await {
                app.set_status(format!("Config error: {e}"));
            }
        }
        TuiKey::Char('w') => {
            if let Err(e) = app.save_config_and_reload().await {
                app.set_status(format!("Save error: {e}"));
            }
        }
        TuiKey::Char(_)
        | TuiKey::Down
        | TuiKey::Left
        | TuiKey::Right
        | TuiKey::Backspace
        | TuiKey::Tab
        | TuiKey::Esc => {}
    }
}

async fn handle_probe_tab_key(app: &mut TuiApp, key: TuiKey) {
    match key {
        TuiKey::Up | TuiKey::Char('k') => {
            app.probe_scroll = app.probe_scroll.saturating_sub(1);
        }
        TuiKey::Down | TuiKey::Char('j') if app.probe_scroll + 1 < app.probe_results.len() => {
            app.probe_scroll += 1;
        }
        TuiKey::Char('p') => app.probe_selected_tunnel().await,
        TuiKey::Char('P') => app.probe_all_tunnels().await,
        TuiKey::Char(_)
        | TuiKey::Down
        | TuiKey::Left
        | TuiKey::Right
        | TuiKey::PageUp
        | TuiKey::PageDown
        | TuiKey::Home
        | TuiKey::End
        | TuiKey::Enter
        | TuiKey::Backspace
        | TuiKey::Tab
        | TuiKey::Esc => {}
    }
}

pub(crate) async fn handle_tui_key(app: &mut TuiApp, key: TuiKey) {
    if handle_prompt_key(app, key).await {
        return;
    }

    // While an overlay is open it owns the keyboard: only its close
    // keys do anything, so `q` closes the overlay instead of quitting
    // and `j`/`k` do not move the selection underneath it.
    if app.overlay == TuiOverlay::Help {
        if matches!(key, TuiKey::Esc | TuiKey::Char('?' | 'q')) {
            app.overlay = TuiOverlay::None;
        }
        return;
    }
    if app.overlay == TuiOverlay::TunnelDetail {
        if matches!(key, TuiKey::Esc | TuiKey::Enter | TuiKey::Char('q')) {
            app.overlay = TuiOverlay::None;
        }
        return;
    }

    match key {
        TuiKey::Char('?') => app.overlay = TuiOverlay::Help,
        TuiKey::Char('q') => app.running = false,
        TuiKey::Char('1') => app.set_tab(TuiTab::Tunnels),
        TuiKey::Char('2') => app.set_tab(TuiTab::Logs),
        TuiKey::Char('3') => app.set_tab(TuiTab::Listeners),
        TuiKey::Char('4') => app.set_tab(TuiTab::Config),
        TuiKey::Char('5') => app.set_tab(TuiTab::Probe),
        TuiKey::Tab | TuiKey::Right => app.next_tab(),
        TuiKey::Left => app.prev_tab(),
        TuiKey::Char(_)
        | TuiKey::Up
        | TuiKey::Down
        | TuiKey::PageUp
        | TuiKey::PageDown
        | TuiKey::Home
        | TuiKey::End
        | TuiKey::Enter
        | TuiKey::Backspace
        | TuiKey::Esc => match app.active_tab {
            TuiTab::Tunnels => handle_tunnels_tab_key(app, key).await,
            TuiTab::Logs => handle_logs_tab_key(app, key),
            TuiTab::Listeners => handle_listeners_tab_key(app, key),
            TuiTab::Config => handle_config_tab_key(app, key).await,
            TuiTab::Probe => handle_probe_tab_key(app, key).await,
        },
    }
}
