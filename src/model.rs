use std::{collections::BTreeMap, path::PathBuf, time::Duration};

use serde::{Deserialize, Serialize};

pub const MAX_COMMAND_BYTES: usize = 1024 * 1024;
pub const MAX_ARGV_ITEMS: usize = 4096;
pub const MAX_ARG_BYTES: usize = 256 * 1024;
pub const MAX_ARGV_BYTES: usize = 4 * 1024 * 1024;
pub const MAX_ENV_ITEMS: usize = 4096;
pub const MAX_ENV_BYTES: usize = 4 * 1024 * 1024;
pub const MAX_STDIN_BYTES: usize = 4 * 1024 * 1024;
pub const MAX_PATH_BYTES: usize = 64 * 1024;

const MAX_SNAPSHOT_COMMAND_CHARS: usize = 2_048;
const MAX_SNAPSHOT_ARG_ITEMS: usize = 32;
const MAX_SNAPSHOT_ARG_CHARS: usize = 256;
const MAX_DISPLAY_NAME_CHARS: usize = 160;

#[derive(Debug, Clone, Copy, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum ExecutionMode {
    /// Return the final result. Long-running commands may transparently become MCP Tasks.
    #[default]
    Foreground,
    /// Return a process handle immediately so the model can continue and inspect it later.
    Background,
    /// Allocate a PTY and return a process handle for an interactive terminal session.
    Interactive,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ShellRequest {
    #[serde(default)]
    pub command: Option<String>,
    #[serde(default)]
    pub argv: Option<Vec<String>>,
    #[serde(default)]
    pub cwd: Option<PathBuf>,
    #[serde(default)]
    pub env: BTreeMap<String, String>,
    #[serde(default)]
    pub stdin: Option<String>,
    #[serde(default)]
    pub execution: ExecutionMode,
    #[serde(default)]
    pub pty: bool,
    #[serde(default)]
    pub yield_ms: Option<u64>,
    #[serde(default)]
    pub timeout_ms: Option<u64>,
    #[serde(default)]
    pub rows: Option<u16>,
    #[serde(default)]
    pub cols: Option<u16>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ReadRequest {
    pub process_id: String,
    #[serde(default)]
    pub cursor: u64,
    #[serde(default)]
    pub wait_ms: Option<u64>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct WriteRequest {
    pub process_id: String,
    #[serde(default)]
    pub data: Option<String>,
    #[serde(default)]
    pub append_newline: bool,
    #[serde(default)]
    pub close_stdin: bool,
}

#[derive(Debug, Clone, Copy, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SignalKind {
    Int,
    Term,
    Kill,
}

impl SignalKind {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Int => "INT",
            Self::Term => "TERM",
            Self::Kill => "KILL",
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SignalRequest {
    pub process_id: String,
    pub signal: SignalKind,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ResizeRequest {
    pub process_id: String,
    pub rows: u16,
    pub cols: u16,
}

#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ProcessStatus {
    Running,
    Exited,
    Signaled,
    TimedOut,
    Cancelled,
    Failed,
}

impl ProcessStatus {
    pub const fn is_terminal(self) -> bool {
        !matches!(self, Self::Running)
    }
}

#[derive(Debug, Clone, Copy, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum OutputStream {
    Stdout,
    Stderr,
    Pty,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct OutputEvent {
    pub cursor: u64,
    pub stream: OutputStream,
    pub data: String,
    pub at_ms: u64,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ProcessSnapshot {
    pub process_id: String,
    pub status: ProcessStatus,
    pub pid: Option<u32>,
    pub mode: String,
    pub execution: ExecutionMode,
    pub pty: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rows: Option<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cols: Option<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub command: Option<String>,
    pub command_truncated: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub argv: Option<Vec<String>>,
    pub argv_truncated: bool,
    pub cwd: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub exit_code: Option<i32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signal: Option<String>,
    pub events: Vec<OutputEvent>,
    /// Cursor to pass to the next shell_read call.
    pub next_cursor: u64,
    /// More retained output exists after nextCursor.
    pub has_more: bool,
    /// The requested cursor was older than the retained ring buffer.
    pub cursor_lost: bool,
    pub elapsed_ms: u64,
    pub idle_ms: u64,
    pub truncated: bool,
    pub dropped_bytes: u64,
    pub message: String,
}

#[derive(Debug, Clone)]
pub struct CommandSpec {
    pub mode: CommandMode,
    pub execution: ExecutionMode,
    pub cwd: PathBuf,
    pub env: BTreeMap<String, String>,
    pub initial_stdin: Option<String>,
    pub pty: bool,
    pub rows: u16,
    pub cols: u16,
    pub timeout: Duration,
}

#[derive(Debug, Clone)]
pub enum CommandMode {
    Shell {
        shell: PathBuf,
        command: String,
    },
    Direct {
        argv: Vec<String>,
        executable: PathBuf,
    },
}

impl CommandSpec {
    pub const fn display_mode(&self) -> &'static str {
        match self.mode {
            CommandMode::Shell { .. } => "shell",
            CommandMode::Direct { .. } => "direct",
        }
    }

    pub fn command_text(&self) -> (Option<String>, bool) {
        match &self.mode {
            CommandMode::Shell { command, .. } => {
                let (command, truncated) = truncate_chars(command, MAX_SNAPSHOT_COMMAND_CHARS);
                (Some(command), truncated)
            }
            CommandMode::Direct { .. } => (None, false),
        }
    }

    pub fn argv(&self) -> (Option<Vec<String>>, bool) {
        match &self.mode {
            CommandMode::Direct { argv, .. } => {
                let mut truncated = argv.len() > MAX_SNAPSHOT_ARG_ITEMS;
                let values = argv
                    .iter()
                    .take(MAX_SNAPSHOT_ARG_ITEMS)
                    .map(|argument| {
                        let (argument, was_truncated) =
                            truncate_chars(argument, MAX_SNAPSHOT_ARG_CHARS);
                        truncated |= was_truncated;
                        argument
                    })
                    .collect();
                (Some(values), truncated)
            }
            CommandMode::Shell { .. } => (None, false),
        }
    }

    pub fn display_name(&self) -> String {
        match &self.mode {
            CommandMode::Shell { command, .. } => truncate_chars(command, MAX_DISPLAY_NAME_CHARS).0,
            CommandMode::Direct { argv, .. } => {
                let mut display = String::new();
                let mut remaining = MAX_DISPLAY_NAME_CHARS;
                for argument in argv {
                    if remaining == 0 {
                        break;
                    }
                    if !display.is_empty() {
                        display.push(' ');
                        remaining = remaining.saturating_sub(1);
                    }
                    for ch in argument.chars().take(remaining) {
                        display.push(ch);
                        remaining -= 1;
                    }
                }
                display
            }
        }
    }
}

fn truncate_chars(input: &str, max_chars: usize) -> (String, bool) {
    let mut chars = input.chars();
    let mut output: String = chars.by_ref().take(max_chars).collect();
    let truncated = chars.next().is_some();
    if truncated {
        output.push('…');
    }
    (output, truncated)
}
