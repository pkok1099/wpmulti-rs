//! In-memory ring-buffer log writer for the TUI Live Logs tab.

use std::collections::VecDeque;
use std::io::{self, Write};
use std::sync::Arc;

use parking_lot::Mutex;
use tracing_subscriber::fmt::MakeWriter;

/// Thread-safe bounded ring buffer capturing `tracing` log lines for TUI display.
#[derive(Clone, Debug)]
pub struct TuiLogBuffer {
    lines: Arc<Mutex<VecDeque<String>>>,
    max_lines: usize,
}

impl TuiLogBuffer {
    /// Create a new log buffer retaining at most `max_lines` entries.
    pub fn new(max_lines: usize) -> Self {
        Self {
            lines: Arc::new(Mutex::new(VecDeque::with_capacity(max_lines.min(1024)))),
            max_lines: max_lines.max(1),
        }
    }

    /// Push a single formatted log line into the ring buffer.
    pub fn push_line(&self, line: String) {
        let trimmed = line.trim_end_matches(['\r', '\n']);
        if trimmed.is_empty() {
            return;
        }
        let mut guard = self.lines.lock();
        if guard.len() >= self.max_lines {
            guard.pop_front();
        }
        guard.push_back(trimmed.to_string());
    }

    /// Return a snapshot of captured log lines (oldest to newest).
    pub fn snapshot(&self) -> Vec<String> {
        self.lines.lock().iter().cloned().collect()
    }

    /// Clear all buffered log lines.
    pub fn clear(&self) {
        self.lines.lock().clear();
    }
}

/// Line-buffered writer passed to `tracing_subscriber` for each log event.
pub struct TuiLogWriter {
    buffer: TuiLogBuffer,
    pending: Vec<u8>,
}

impl Write for TuiLogWriter {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.pending.extend_from_slice(buf);
        while let Some(pos) = self.pending.iter().position(|&b| b == b'\n') {
            let line_bytes: Vec<u8> = self.pending.drain(..=pos).collect();
            let line = String::from_utf8_lossy(&line_bytes).into_owned();
            self.buffer.push_line(line);
        }
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        if !self.pending.is_empty() {
            let line = String::from_utf8_lossy(&self.pending).into_owned();
            self.pending.clear();
            self.buffer.push_line(line);
        }
        Ok(())
    }
}

impl Drop for TuiLogWriter {
    fn drop(&mut self) {
        let _ = self.flush();
    }
}

impl<'a> MakeWriter<'a> for TuiLogBuffer {
    type Writer = TuiLogWriter;

    fn make_writer(&'a self) -> Self::Writer {
        TuiLogWriter {
            buffer: self.clone(),
            pending: Vec::with_capacity(128),
        }
    }
}
