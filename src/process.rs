use std::{
    collections::VecDeque,
    io::{Read, Write},
    sync::{Arc, Mutex as StdMutex},
    time::{Duration, Instant},
};

use anyhow::{Context, bail};
use dashmap::DashMap;
use portable_pty::{CommandBuilder, MasterPty, PtySize, native_pty_system};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWriteExt},
    process::Command,
    sync::{Mutex, Notify, OwnedSemaphorePermit, Semaphore},
    task::{JoinHandle, JoinSet},
};
use tracing::{debug, warn};
use uuid::Uuid;

const MAX_OUTPUT_EVENT_BYTES: usize = 8 * 1024;

use crate::{
    config::Config,
    model::{
        CommandMode, CommandSpec, OutputEvent, OutputStream, ProcessReadResult, ProcessStatus,
        ResizeResult, ShellResult, SignalKind, SignalResult, WriteResult,
    },
};

#[derive(Debug, Clone)]
struct TerminationIntent {
    status: ProcessStatus,
    marker: String,
}

#[derive(Debug, Clone)]
struct ProcessState {
    status: ProcessStatus,
    root_exited: bool,
    exit_code: Option<i32>,
    signal: Option<String>,
    finished_at: Option<Instant>,
    termination_intent: Option<TerminationIntent>,
}

impl Default for ProcessState {
    fn default() -> Self {
        Self {
            status: ProcessStatus::Running,
            root_exited: false,
            exit_code: None,
            signal: None,
            finished_at: None,
            termination_intent: None,
        }
    }
}

#[derive(Debug)]
struct OutputBuffer {
    events: VecDeque<OutputEvent>,
    retained_bytes: usize,
    max_bytes: usize,
    max_event_bytes: usize,
    next_cursor: u64,
    dropped_bytes: u64,
    truncated: bool,
    last_output: Instant,
}

impl OutputBuffer {
    fn new(max_bytes: usize, max_event_bytes: usize, started: Instant) -> Self {
        Self {
            events: VecDeque::new(),
            retained_bytes: 0,
            max_bytes,
            max_event_bytes: max_event_bytes.max(1).min(max_bytes.max(1)),
            next_cursor: 1,
            dropped_bytes: 0,
            truncated: false,
            last_output: started,
        }
    }

    fn append(&mut self, stream: OutputStream, text: &str) {
        if text.is_empty() {
            return;
        }
        let mut start = 0;
        while start < text.len() {
            let mut end = start.saturating_add(self.max_event_bytes).min(text.len());
            while end > start && !text.is_char_boundary(end) {
                end -= 1;
            }
            if end == start {
                end = text[start..]
                    .char_indices()
                    .nth(1)
                    .map_or(text.len(), |(offset, _)| start + offset);
            }
            self.push_event(stream, text[start..end].to_string());
            start = end;
        }
    }

    fn push_event(&mut self, stream: OutputStream, data: String) {
        let event_bytes = data.len();
        let cursor = self.next_cursor;
        self.next_cursor = self.next_cursor.saturating_add(1);
        self.last_output = Instant::now();
        self.retained_bytes = self.retained_bytes.saturating_add(event_bytes);
        self.events.push_back(OutputEvent {
            cursor,
            stream,
            data,
        });

        while self.retained_bytes > self.max_bytes {
            let Some(old) = self.events.pop_front() else {
                break;
            };
            let bytes = old.data.len();
            self.retained_bytes = self.retained_bytes.saturating_sub(bytes);
            self.dropped_bytes = self.dropped_bytes.saturating_add(bytes as u64);
            self.truncated = true;
        }
    }

    fn read_since(&self, cursor: u64, max_bytes: usize) -> (Vec<OutputEvent>, u64, bool, bool) {
        let first_available = self
            .events
            .front()
            .map_or(self.next_cursor, |event| event.cursor);
        let cursor_lost = cursor < first_available.saturating_sub(1);
        let mut events = Vec::new();
        let mut used = 0usize;
        let mut next_cursor = cursor;
        let mut has_more = false;

        for event in self.events.iter().filter(|event| event.cursor > cursor) {
            let size = event.data.len();
            if used.saturating_add(size) > max_bytes {
                has_more = true;
                break;
            }
            used = used.saturating_add(size);
            next_cursor = event.cursor;
            events.push(event.clone());
        }

        if self.events.iter().any(|event| event.cursor > next_cursor) {
            has_more = true;
        }
        (events, next_cursor, cursor_lost, has_more)
    }

    fn recent_excerpt(&self) -> Option<String> {
        self.events
            .iter()
            .rev()
            .flat_map(|event| event.data.lines().rev())
            .map(str::trim)
            .find(|line| !line.is_empty())
            .map(|line| truncate_chars(&sanitize_status(line), 200))
    }

    fn tail(&self, max_bytes: usize) -> (String, bool, u64) {
        let mut remaining = max_bytes;
        let mut reverse_chunks = Vec::new();
        for event in self.events.iter().rev() {
            if remaining == 0 {
                break;
            }
            let data = &event.data;
            if data.len() <= remaining {
                reverse_chunks.push(data.as_str());
                remaining -= data.len();
            } else {
                let mut start = data.len() - remaining;
                while start < data.len() && !data.is_char_boundary(start) {
                    start += 1;
                }
                reverse_chunks.push(&data[start..]);
                remaining = 0;
            }
        }
        reverse_chunks.reverse();
        let output = reverse_chunks.concat();
        let truncated = self.truncated || output.len() < self.retained_bytes;
        (output, truncated, self.newest_cursor())
    }

    fn newest_cursor(&self) -> u64 {
        self.next_cursor.saturating_sub(1)
    }
}

#[derive(Default)]
struct Utf8StreamDecoder {
    pending: Vec<u8>,
}

impl Utf8StreamDecoder {
    fn push(&mut self, bytes: &[u8]) -> String {
        self.pending.extend_from_slice(bytes);
        let mut output = String::new();

        loop {
            match std::str::from_utf8(&self.pending) {
                Ok(valid) => {
                    output.push_str(valid);
                    self.pending.clear();
                    break;
                }
                Err(error) => {
                    let valid_up_to = error.valid_up_to();
                    if valid_up_to > 0 {
                        let valid = std::str::from_utf8(&self.pending[..valid_up_to])
                            .expect("Utf8Error::valid_up_to guarantees a valid prefix");
                        output.push_str(valid);
                        self.pending.drain(..valid_up_to);
                    }
                    if let Some(error_len) = error.error_len() {
                        output.push('\u{fffd}');
                        self.pending.drain(..error_len.min(self.pending.len()));
                    } else {
                        break;
                    }
                }
            }
        }
        output
    }

    fn finish(&mut self) -> String {
        if self.pending.is_empty() {
            return String::new();
        }
        let output = String::from_utf8_lossy(&self.pending).into_owned();
        self.pending.clear();
        output
    }
}

pub(crate) fn sanitize_output(input: &str) -> String {
    input
        .chars()
        .filter(|ch| !ch.is_control() || matches!(ch, '\n' | '\r' | '\t'))
        .collect()
}

fn sanitize_status(input: &str) -> String {
    let mut output = String::new();
    let mut chars = input.chars().peekable();
    while let Some(ch) = chars.next() {
        if ch != '\u{1b}' {
            if !ch.is_control() || matches!(ch, '\n' | '\r' | '\t') {
                output.push(ch);
            }
            continue;
        }
        match chars.peek().copied() {
            Some('[') => {
                chars.next();
                for next in chars.by_ref() {
                    if ('@'..='~').contains(&next) {
                        break;
                    }
                }
            }
            Some(']') => {
                chars.next();
                let mut escaped = false;
                for next in chars.by_ref() {
                    if next == '\u{7}' || (escaped && next == '\\') {
                        break;
                    }
                    escaped = next == '\u{1b}';
                }
            }
            Some(_) => {
                chars.next();
            }
            None => {}
        }
    }
    output
}

enum ProcessInput {
    Pipe(tokio::process::ChildStdin),
    Pty(Arc<StdMutex<Box<dyn Write + Send>>>),
    Closed,
}

#[derive(Clone)]
struct ProcessControl {
    pid: Option<u32>,
    pty_killer: Option<Arc<StdMutex<Box<dyn portable_pty::ChildKiller + Send + Sync>>>>,
    pty_master: Option<Arc<StdMutex<Box<dyn MasterPty + Send>>>>,
    #[cfg(unix)]
    process_group: Option<i32>,
}

pub struct ManagedProcess {
    id: String,
    spec: CommandSpec,
    pid: Option<u32>,
    started: Instant,
    state: StdMutex<ProcessState>,
    output: StdMutex<OutputBuffer>,
    input: Mutex<ProcessInput>,
    control: ProcessControl,
    pty_size: StdMutex<(u16, u16)>,
    max_response_output: usize,
    notify: Notify,
    running_slot: StdMutex<Option<OwnedSemaphorePermit>>,
    _handle_slot: OwnedSemaphorePermit,
}

impl ManagedProcess {
    #[allow(clippy::too_many_arguments)]
    fn new(
        spec: CommandSpec,
        pid: Option<u32>,
        input: ProcessInput,
        control: ProcessControl,
        max_output: usize,
        max_response_output: usize,
        running_slot: OwnedSemaphorePermit,
        handle_slot: OwnedSemaphorePermit,
    ) -> Arc<Self> {
        let started = Instant::now();
        let rows = spec.rows;
        let cols = spec.cols;
        Arc::new(Self {
            id: format!("p_{}", Uuid::new_v4().simple()),
            spec,
            pid,
            started,
            state: StdMutex::new(ProcessState::default()),
            output: StdMutex::new(OutputBuffer::new(
                max_output,
                max_response_output.min(MAX_OUTPUT_EVENT_BYTES),
                started,
            )),
            input: Mutex::new(input),
            control,
            pty_size: StdMutex::new((rows, cols)),
            max_response_output,
            notify: Notify::new(),
            running_slot: StdMutex::new(Some(running_slot)),
            _handle_slot: handle_slot,
        })
    }

    pub fn id(&self) -> &str {
        &self.id
    }

    pub fn is_running(&self) -> bool {
        self.status() == ProcessStatus::Running
    }

    pub fn status(&self) -> ProcessStatus {
        self.state.lock().expect("state mutex poisoned").status
    }

    fn root_exited(&self) -> bool {
        self.state.lock().expect("state mutex poisoned").root_exited
    }

    fn mark_root_exited(&self) {
        let mut state = self.state.lock().expect("state mutex poisoned");
        if state.status == ProcessStatus::Running && !state.root_exited {
            state.root_exited = true;
            drop(state);
            self.notify.notify_waiters();
        }
    }

    fn append_output(&self, stream: OutputStream, text: &str) {
        self.output
            .lock()
            .expect("output mutex poisoned")
            .append(stream, text);
        self.notify.notify_waiters();
    }

    fn set_termination_intent(&self, status: ProcessStatus, marker: impl Into<String>) {
        let mut state = self.state.lock().expect("state mutex poisoned");
        if state.status == ProcessStatus::Running && state.termination_intent.is_none() {
            state.termination_intent = Some(TerminationIntent {
                status,
                marker: marker.into(),
            });
        }
    }

    fn finish(
        &self,
        natural_status: ProcessStatus,
        exit_code: Option<i32>,
        signal: Option<String>,
    ) {
        let mut state = self.state.lock().expect("state mutex poisoned");
        if state.status != ProcessStatus::Running {
            return;
        }
        let intent = state.termination_intent.take();
        state.status = intent
            .as_ref()
            .map_or(natural_status, |intent| intent.status);
        state.exit_code = exit_code;
        state.signal = intent.map(|intent| intent.marker).or(signal);
        state.finished_at = Some(Instant::now());
        drop(state);
        self.running_slot
            .lock()
            .expect("process slot mutex poisoned")
            .take();
        self.notify.notify_waiters();
    }

    pub async fn write(&self, data: &[u8]) -> anyhow::Result<()> {
        if !self.is_running() {
            bail!("process {} is not running", self.id);
        }
        let mut input = self.input.lock().await;
        match &mut *input {
            ProcessInput::Pipe(stdin) => {
                stdin
                    .write_all(data)
                    .await
                    .context("failed to write process stdin")?;
                stdin
                    .flush()
                    .await
                    .context("failed to flush process stdin")?;
            }
            ProcessInput::Pty(writer) => {
                let writer = Arc::clone(writer);
                let bytes = data.to_vec();
                tokio::task::spawn_blocking(move || -> anyhow::Result<()> {
                    let mut writer = writer
                        .lock()
                        .map_err(|_| anyhow::anyhow!("PTY writer mutex poisoned"))?;
                    writer.write_all(&bytes).context("failed to write PTY")?;
                    writer.flush().context("failed to flush PTY")?;
                    Ok(())
                })
                .await
                .context("PTY writer task failed")??;
            }
            ProcessInput::Closed => bail!("process stdin is closed"),
        }
        Ok(())
    }

    pub async fn close_stdin(&self) {
        let mut input = self.input.lock().await;
        *input = ProcessInput::Closed;
    }

    pub async fn resize(&self, rows: u16, cols: u16) -> anyhow::Result<()> {
        if rows == 0 || cols == 0 {
            bail!("PTY rows and cols must be greater than zero");
        }
        if rows > 1000 || cols > 2000 {
            bail!("PTY rows/cols exceed the supported maximum of 1000x2000");
        }
        let Some(master) = &self.control.pty_master else {
            bail!("process {} does not have a PTY", self.id);
        };
        let master = Arc::clone(master);
        tokio::task::spawn_blocking(move || -> anyhow::Result<()> {
            master
                .lock()
                .map_err(|_| anyhow::anyhow!("PTY master mutex poisoned"))?
                .resize(PtySize {
                    rows,
                    cols,
                    pixel_width: 0,
                    pixel_height: 0,
                })
                .context("failed to resize PTY")?;
            Ok(())
        })
        .await
        .context("PTY resize task failed")??;
        *self.pty_size.lock().expect("PTY size mutex poisoned") = (rows, cols);
        Ok(())
    }

    pub async fn signal(&self, signal: SignalKind) -> anyhow::Result<()> {
        debug!(process_id = %self.id, signal = signal.as_str(), "signaling process");
        if self.is_running() {
            signal_tree(&self.control, signal).await?;
        }
        Ok(())
    }

    pub async fn terminate(
        &self,
        status: ProcessStatus,
        marker: &str,
        grace: Duration,
    ) -> anyhow::Result<()> {
        if !self.is_running() {
            return Ok(());
        }
        // Once the root child has exited, only bounded descendant cleanup/output
        // draining remains. Do not overwrite a natural terminal result with a
        // late timeout/cancel, but also never report success while state is still
        // transiently Running. The cleanup path is intentionally bounded below.
        if self.root_exited() {
            const POST_EXIT_CLEANUP_WAIT: Duration = Duration::from_millis(500);
            if tokio::time::timeout(POST_EXIT_CLEANUP_WAIT, self.wait_until_terminal())
                .await
                .is_err()
                && self.is_running()
            {
                bail!(
                    "process {} root exited but cleanup did not reach terminal state",
                    self.id
                );
            }
            return Ok(());
        }
        self.set_termination_intent(status, marker.to_string());

        let term_error = signal_tree(&self.control, SignalKind::Term).await.err();
        if tokio::time::timeout(grace, self.wait_until_terminal())
            .await
            .is_ok()
        {
            return Ok(());
        }

        if self.is_running() {
            signal_tree(&self.control, SignalKind::Kill)
                .await
                .with_context(|| match term_error {
                    Some(ref error) => format!("TERM failed ({error}); KILL also failed"),
                    None => "failed to escalate process termination to KILL".to_string(),
                })?;
            if tokio::time::timeout(grace, self.wait_until_terminal())
                .await
                .is_err()
                && self.is_running()
            {
                bail!(
                    "process {} did not exit after TERM/KILL escalation",
                    self.id
                );
            }
        }
        Ok(())
    }

    pub async fn wait_for_notification(&self) {
        let notified = self.notify.notified();
        if !self.is_running() {
            return;
        }
        notified.await;
    }

    pub async fn wait_until_terminal(&self) {
        loop {
            // Register before checking state so a finish notification cannot be
            // lost between the state check and waiter registration.
            let notified = self.notify.notified();
            if !self.is_running() {
                return;
            }
            notified.await;
        }
    }

    pub async fn wait_for_change(&self, cursor: u64, max_wait: Duration) {
        if self.has_change_since(cursor) || !self.is_running() {
            return;
        }
        let notified = self.notify.notified();
        if self.has_change_since(cursor) || !self.is_running() {
            return;
        }
        let _ = tokio::time::timeout(max_wait, notified).await;
    }

    fn has_change_since(&self, cursor: u64) -> bool {
        self.output
            .lock()
            .expect("output mutex poisoned")
            .newest_cursor()
            > cursor
    }

    pub fn start_result(&self) -> ShellResult {
        let (rows, cols) = *self.pty_size.lock().expect("PTY size mutex poisoned");
        ShellResult {
            process_id: self.id.clone(),
            status: self.status(),
            pid: self.pid,
            pty: self.spec.pty,
            rows: self.spec.pty.then_some(rows),
            cols: self.spec.pty.then_some(cols),
            exit_code: None,
            signal: None,
            elapsed_ms: None,
            output: None,
            output_truncated: None,
            next_cursor: 0,
        }
    }

    pub fn completion_result(&self, max_output_bytes: usize) -> ShellResult {
        let state = self.state.lock().expect("state mutex poisoned").clone();
        let output = self.output.lock().expect("output mutex poisoned");
        let (tail, output_truncated, next_cursor) =
            output.tail(max_output_bytes.min(self.max_response_output));
        let (rows, cols) = *self.pty_size.lock().expect("PTY size mutex poisoned");
        ShellResult {
            process_id: self.id.clone(),
            status: state.status,
            pid: self.pid,
            pty: self.spec.pty,
            rows: self.spec.pty.then_some(rows),
            cols: self.spec.pty.then_some(cols),
            exit_code: state.exit_code,
            signal: state.signal.map(|value| sanitize_status(&value)),
            elapsed_ms: Some(millis(self.started.elapsed())),
            output: Some(tail),
            output_truncated: Some(output_truncated),
            next_cursor,
        }
    }

    pub fn read_result(&self, cursor: u64) -> anyhow::Result<ProcessReadResult> {
        let state = self.state.lock().expect("state mutex poisoned").clone();
        let output = self.output.lock().expect("output mutex poisoned");
        let newest_cursor = output.newest_cursor();
        if cursor > newest_cursor {
            bail!("cursor {cursor} is ahead of the newest cursor {newest_cursor}");
        }
        let (events, next_cursor, cursor_lost, has_more) =
            output.read_since(cursor, self.max_response_output);
        let terminal = state.status.is_terminal();
        Ok(ProcessReadResult {
            process_id: self.id.clone(),
            status: state.status,
            events,
            next_cursor,
            has_more,
            cursor_lost,
            exit_code: terminal.then_some(state.exit_code).flatten(),
            signal: terminal
                .then_some(state.signal)
                .flatten()
                .map(|value| sanitize_status(&value)),
            elapsed_ms: terminal.then_some(millis(self.started.elapsed())),
        })
    }

    pub fn validate_cursor(&self, cursor: u64) -> anyhow::Result<()> {
        let newest_cursor = self
            .output
            .lock()
            .expect("output mutex poisoned")
            .newest_cursor();
        if cursor > newest_cursor {
            bail!("cursor {cursor} is ahead of the newest cursor {newest_cursor}");
        }
        Ok(())
    }

    pub fn write_result(&self, accepted_bytes: usize, stdin_closed: bool) -> WriteResult {
        WriteResult {
            process_id: self.id.clone(),
            accepted_bytes,
            stdin_closed,
            status: self.status(),
        }
    }

    pub fn signal_result(&self, signal: SignalKind, accepted: bool) -> SignalResult {
        SignalResult {
            process_id: self.id.clone(),
            signal: signal.as_str().to_ascii_lowercase(),
            accepted,
            status: self.status(),
        }
    }

    pub fn resize_result(&self, rows: u16, cols: u16) -> ResizeResult {
        ResizeResult {
            process_id: self.id.clone(),
            rows,
            cols,
            status: self.status(),
        }
    }

    pub fn progress_message(&self) -> String {
        let state = self.state.lock().expect("state mutex poisoned").clone();
        let output = self.output.lock().expect("output mutex poisoned");
        let elapsed = self.started.elapsed();
        let idle = Instant::now().duration_since(output.last_output);
        let activity = output.recent_excerpt().unwrap_or_else(|| {
            if state.status == ProcessStatus::Running {
                format!("idle {}", human_duration(idle))
            } else {
                truncate_chars(&sanitize_status(&self.spec.display_name()), 100)
            }
        });
        let mut message = match state.status {
            ProcessStatus::Running => {
                format!("Running · {} · {activity}", human_duration(elapsed))
            }
            _ => format!(
                "{} · {activity}",
                status_message(state.status, state.exit_code, elapsed)
            ),
        };
        if output.truncated {
            message.push_str(" · output truncated");
        }
        truncate_chars(&message, 240)
    }

    fn finished_for(&self) -> Option<Duration> {
        self.state
            .lock()
            .expect("state mutex poisoned")
            .finished_at
            .map(|finished| finished.elapsed())
    }
}

#[derive(Clone)]
pub struct ProcessManager {
    processes: Arc<DashMap<String, Arc<ManagedProcess>>>,
    process_slots: Arc<Semaphore>,
    handle_slots: Arc<Semaphore>,
    config: Arc<Config>,
}

impl ProcessManager {
    pub fn new(config: Arc<Config>) -> Self {
        Self {
            processes: Arc::new(DashMap::new()),
            process_slots: Arc::new(Semaphore::new(config.max_processes)),
            handle_slots: Arc::new(Semaphore::new(config.max_process_handles)),
            config,
        }
    }

    pub async fn spawn(&self, spec: CommandSpec) -> anyhow::Result<Arc<ManagedProcess>> {
        self.prune();
        let handle_slot = self.acquire_handle_slot()?;
        let running_slot = Arc::clone(&self.process_slots)
            .try_acquire_owned()
            .map_err(|_| anyhow::anyhow!("maximum concurrent process limit reached"))?;
        let process = if spec.pty {
            self.spawn_pty(spec, running_slot, handle_slot).await?
        } else {
            self.spawn_piped(spec, running_slot, handle_slot).await?
        };
        let timeout = process.spec.timeout;
        let process_for_timeout = Arc::clone(&process);
        let grace = self.config.termination_grace;
        tokio::spawn(async move {
            tokio::select! {
                () = tokio::time::sleep(timeout) => {
                    if process_for_timeout.is_running()
                        && !process_for_timeout.root_exited()
                        && let Err(error) = process_for_timeout
                            .terminate(ProcessStatus::TimedOut, "TIMEOUT", grace)
                            .await
                    {
                        warn!(process_id = %process_for_timeout.id, %error, "failed to terminate timed-out process");
                    }
                }
                () = process_for_timeout.wait_until_terminal() => {}
            }
        });

        if let Some(initial_stdin) = process.spec.initial_stdin.clone()
            && !initial_stdin.is_empty()
            && let Err(error) = process.write(initial_stdin.as_bytes()).await
        {
            if let Err(termination_error) = process
                .terminate(
                    ProcessStatus::Cancelled,
                    "INITIAL_STDIN_FAILED",
                    self.config.termination_grace,
                )
                .await
            {
                warn!(
                    process_id = %process.id,
                    %termination_error,
                    "failed to terminate process after initial stdin failure"
                );
            }
            return Err(error).context("failed to write initial stdin");
        }

        // Publish the handle only after all spawn-time setup has succeeded.
        // A failed initial-stdin write must never leave an unreachable handle
        // consuming the retained-handle budget.
        self.processes
            .insert(process.id.clone(), Arc::clone(&process));
        Ok(process)
    }

    fn acquire_handle_slot(&self) -> anyhow::Result<OwnedSemaphorePermit> {
        loop {
            if let Ok(slot) = Arc::clone(&self.handle_slots).try_acquire_owned() {
                return Ok(slot);
            }
            if !self.evict_oldest_completed() {
                bail!("maximum retained process-handle limit reached");
            }
        }
    }

    fn evict_oldest_completed(&self) -> bool {
        let oldest = self
            .processes
            .iter()
            .filter_map(|entry| {
                entry
                    .value()
                    .finished_for()
                    .map(|elapsed| (entry.key().clone(), elapsed))
            })
            .max_by_key(|(_, elapsed)| *elapsed)
            .map(|(id, _)| id);
        oldest.is_some_and(|id| self.processes.remove(&id).is_some())
    }

    pub fn get(&self, id: &str) -> anyhow::Result<Arc<ManagedProcess>> {
        if !valid_process_id(id) {
            bail!("invalid processId");
        }
        self.prune();
        self.processes
            .get(id)
            .map(|entry| Arc::clone(entry.value()))
            .ok_or_else(|| anyhow::anyhow!("unknown or expired processId '{id}'"))
    }

    pub async fn shutdown(&self) -> anyhow::Result<()> {
        let processes: Vec<_> = self
            .processes
            .iter()
            .map(|entry| Arc::clone(entry.value()))
            .collect();
        let mut terminations = JoinSet::new();
        for process in processes {
            if process.is_running() {
                let grace = self.config.termination_grace;
                terminations.spawn(async move {
                    let process_id = process.id.clone();
                    let result = process
                        .terminate(ProcessStatus::Cancelled, "SERVER_SHUTDOWN", grace)
                        .await;
                    (process_id, result)
                });
            }
        }
        while let Some(joined) = terminations.join_next().await {
            match joined {
                Ok((process_id, Ok(()))) => {
                    debug!(%process_id, "process stopped during shutdown");
                }
                Ok((process_id, Err(error))) => {
                    warn!(%process_id, %error, "failed to terminate process during shutdown");
                }
                Err(error) => warn!(%error, "process shutdown task failed"),
            }
        }
        Ok(())
    }

    fn prune(&self) {
        let retention = self.config.process_retention;
        self.processes.retain(|_, process| {
            process
                .finished_for()
                .is_none_or(|elapsed| elapsed < retention)
        });
    }

    async fn spawn_piped(
        &self,
        spec: CommandSpec,
        running_slot: OwnedSemaphorePermit,
        handle_slot: OwnedSemaphorePermit,
    ) -> anyhow::Result<Arc<ManagedProcess>> {
        let mut command = command_for_spec(&spec)?;
        command
            .current_dir(&spec.cwd)
            .envs(&spec.env)
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped());
        configure_process_group(&mut command);

        let mut child = command
            .spawn()
            .with_context(|| format!("failed to spawn {}", spec.display_name()))?;
        let pid = child.id();
        let stdin = child
            .stdin
            .take()
            .map_or(ProcessInput::Closed, ProcessInput::Pipe);
        let stdout = match child.stdout.take() {
            Some(stdout) => stdout,
            None => {
                let _ = child.kill().await;
                let _ = child.wait().await;
                bail!("child stdout pipe missing after piped spawn");
            }
        };
        let stderr = match child.stderr.take() {
            Some(stderr) => stderr,
            None => {
                let _ = child.kill().await;
                let _ = child.wait().await;
                bail!("child stderr pipe missing after piped spawn");
            }
        };
        let control = ProcessControl {
            pid,
            pty_killer: None,
            pty_master: None,
            #[cfg(unix)]
            process_group: pid.map(|value| value as i32),
        };
        let process = ManagedProcess::new(
            spec,
            pid,
            stdin,
            control,
            self.config.max_output,
            self.config.max_response_output,
            running_slot,
            handle_slot,
        );
        let stdout_task = spawn_async_drain(Arc::clone(&process), stdout, OutputStream::Stdout);
        let stderr_task = spawn_async_drain(Arc::clone(&process), stderr, OutputStream::Stderr);
        let wait_process = Arc::clone(&process);

        tokio::spawn(async move {
            let waited = child.wait().await;
            if waited.is_ok() {
                wait_process.mark_root_exited();
            }
            cleanup_descendants(&wait_process.control).await;
            drain_pair(stdout_task, stderr_task, Duration::from_millis(250)).await;
            match waited {
                Ok(status) => {
                    #[cfg(unix)]
                    let signal = {
                        use std::os::unix::process::ExitStatusExt;
                        status.signal().map(|value| format!("SIG{value}"))
                    };
                    #[cfg(not(unix))]
                    let signal: Option<String> = None;
                    let final_status = if signal.is_some() {
                        ProcessStatus::Signaled
                    } else {
                        ProcessStatus::Exited
                    };
                    wait_process.finish(final_status, status.code(), signal);
                }
                Err(error) => {
                    wait_process.append_output(
                        OutputStream::Stderr,
                        &format!("shellvibe wait error: {error}\n"),
                    );
                    wait_process.finish(ProcessStatus::Failed, None, None);
                }
            }
        });
        Ok(process)
    }

    async fn spawn_pty(
        &self,
        spec: CommandSpec,
        running_slot: OwnedSemaphorePermit,
        handle_slot: OwnedSemaphorePermit,
    ) -> anyhow::Result<Arc<ManagedProcess>> {
        let pty_system = native_pty_system();
        let pair = pty_system
            .openpty(PtySize {
                rows: spec.rows,
                cols: spec.cols,
                pixel_width: 0,
                pixel_height: 0,
            })
            .context("failed to open PTY")?;
        let mut builder = pty_command_for_spec(&spec)?;
        builder.cwd(&spec.cwd);
        for (key, value) in &spec.env {
            builder.env(key, value);
        }
        let mut child = pair
            .slave
            .spawn_command(builder)
            .context("failed to spawn command in PTY")?;
        drop(pair.slave);

        let pid = child.process_id();
        let killer = Arc::new(StdMutex::new(child.clone_killer()));
        #[cfg(unix)]
        let process_group = pair
            .master
            .process_group_leader()
            .or(pid.map(|value| value as i32));

        let mut reader = match pair.master.try_clone_reader() {
            Ok(reader) => reader,
            Err(error) => {
                kill_portable_child(Arc::clone(&killer)).await;
                let _ = tokio::task::spawn_blocking(move || child.wait()).await;
                return Err(error).context("failed to clone PTY reader");
            }
        };
        let writer = match pair.master.take_writer() {
            Ok(writer) => writer,
            Err(error) => {
                kill_portable_child(Arc::clone(&killer)).await;
                let _ = tokio::task::spawn_blocking(move || child.wait()).await;
                return Err(error).context("failed to take PTY writer");
            }
        };
        let master = Arc::new(StdMutex::new(pair.master));
        let cleanup_killer = Arc::clone(&killer);

        let control = ProcessControl {
            pid,
            pty_killer: Some(killer),
            pty_master: Some(master),
            #[cfg(unix)]
            process_group,
        };
        let process = ManagedProcess::new(
            spec,
            pid,
            ProcessInput::Pty(Arc::new(StdMutex::new(writer))),
            control,
            self.config.max_output,
            self.config.max_response_output,
            running_slot,
            handle_slot,
        );

        // Bounded bridge gives backpressure to the blocking PTY reader instead of
        // allowing an unbounded queue to grow if the async runtime is busy.
        let (tx, mut rx) = tokio::sync::mpsc::channel::<Vec<u8>>(32);
        let reader_thread = std::thread::Builder::new()
            .name(format!("shellvibe-pty-read-{}", process.id()))
            .spawn(move || {
                let mut buf = [0_u8; 8192];
                loop {
                    match reader.read(&mut buf) {
                        Ok(0) => break,
                        Ok(n) => {
                            if tx.blocking_send(buf[..n].to_vec()).is_err() {
                                break;
                            }
                        }
                        Err(_) => break,
                    }
                }
            });
        if let Err(error) = reader_thread {
            kill_portable_child(cleanup_killer).await;
            let _ = tokio::task::spawn_blocking(move || child.wait()).await;
            return Err(error).context("failed to spawn PTY reader thread");
        }

        let output_process = Arc::clone(&process);
        let output_task = tokio::spawn(async move {
            let mut decoder = Utf8StreamDecoder::default();
            while let Some(chunk) = rx.recv().await {
                let text = decoder.push(&chunk);
                output_process.append_output(OutputStream::Pty, &text);
            }
            let tail = decoder.finish();
            output_process.append_output(OutputStream::Pty, &tail);
        });

        let wait_process = Arc::clone(&process);
        tokio::spawn(async move {
            let waited = tokio::task::spawn_blocking(move || child.wait()).await;
            if matches!(&waited, Ok(Ok(_))) {
                wait_process.mark_root_exited();
            }
            cleanup_descendants(&wait_process.control).await;
            drain_one(output_task, Duration::from_millis(250)).await;
            match waited {
                Ok(Ok(status)) => {
                    let signal = status.signal().map(ToOwned::to_owned);
                    let final_status = if signal.is_some() {
                        ProcessStatus::Signaled
                    } else {
                        ProcessStatus::Exited
                    };
                    wait_process.finish(final_status, Some(status.exit_code() as i32), signal);
                }
                Ok(Err(error)) => {
                    wait_process.append_output(
                        OutputStream::Pty,
                        &format!("\r\nshellvibe wait error: {error}\r\n"),
                    );
                    wait_process.finish(ProcessStatus::Failed, None, None);
                }
                Err(error) => {
                    wait_process.append_output(
                        OutputStream::Pty,
                        &format!("\r\nshellvibe PTY wait task failed: {error}\r\n"),
                    );
                    wait_process.finish(ProcessStatus::Failed, None, None);
                }
            }
        });
        Ok(process)
    }
}

async fn kill_portable_child(
    killer: Arc<StdMutex<Box<dyn portable_pty::ChildKiller + Send + Sync>>>,
) {
    let _ = tokio::task::spawn_blocking(move || {
        if let Ok(mut killer) = killer.lock() {
            let _ = killer.kill();
        }
    })
    .await;
}

async fn drain_pair(mut first: JoinHandle<()>, mut second: JoinHandle<()>, grace: Duration) {
    let completed = tokio::time::timeout(grace, async {
        let _ = (&mut first).await;
        let _ = (&mut second).await;
    })
    .await
    .is_ok();
    if !completed {
        first.abort();
        second.abort();
    }
}

async fn drain_one(mut task: JoinHandle<()>, grace: Duration) {
    if tokio::time::timeout(grace, &mut task).await.is_err() {
        task.abort();
    }
}

#[cfg(unix)]
async fn cleanup_descendants(control: &ProcessControl) {
    use nix::{
        errno::Errno,
        sys::signal::{Signal, killpg},
        unistd::Pid,
    };

    let Some(pgid) = control.process_group else {
        return;
    };
    match killpg(Pid::from_raw(pgid), Signal::SIGTERM) {
        Ok(()) => {
            tokio::time::sleep(Duration::from_millis(75)).await;
            if let Err(error) = killpg(Pid::from_raw(pgid), Signal::SIGKILL)
                && error != Errno::ESRCH
            {
                debug!(%error, pgid, "failed to kill lingering process-group descendants");
            }
        }
        Err(Errno::ESRCH) => {}
        Err(error) => {
            debug!(%error, pgid, "failed to terminate lingering process-group descendants")
        }
    }
}

#[cfg(not(unix))]
async fn cleanup_descendants(_control: &ProcessControl) {}

fn valid_process_id(id: &str) -> bool {
    id.len() == 34
        && id.starts_with("p_")
        && id[2..]
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}

fn command_for_spec(spec: &CommandSpec) -> anyhow::Result<Command> {
    match &spec.mode {
        CommandMode::Shell { shell, command } => {
            let mut cmd = Command::new(shell);
            #[cfg(windows)]
            cmd.args(["/D", "/S", "/C", command]);
            #[cfg(not(windows))]
            cmd.args(["-c", command]);
            Ok(cmd)
        }
        CommandMode::Direct { argv, executable } => {
            if argv.is_empty() {
                bail!("argv must contain an executable");
            }
            let mut cmd = Command::new(executable);
            cmd.args(&argv[1..]);
            Ok(cmd)
        }
    }
}

fn pty_command_for_spec(spec: &CommandSpec) -> anyhow::Result<CommandBuilder> {
    match &spec.mode {
        CommandMode::Shell { shell, command } => {
            let mut builder = CommandBuilder::new(shell);
            #[cfg(windows)]
            {
                builder.arg("/D");
                builder.arg("/S");
                builder.arg("/C");
                builder.arg(command);
            }
            #[cfg(not(windows))]
            {
                builder.arg("-c");
                builder.arg(command);
            }
            Ok(builder)
        }
        CommandMode::Direct { argv, executable } => {
            if argv.is_empty() {
                bail!("argv must contain an executable");
            }
            let mut builder = CommandBuilder::new(executable);
            for arg in &argv[1..] {
                builder.arg(arg);
            }
            Ok(builder)
        }
    }
}

fn spawn_async_drain<R>(
    process: Arc<ManagedProcess>,
    mut reader: R,
    stream: OutputStream,
) -> JoinHandle<()>
where
    R: AsyncRead + Unpin + Send + 'static,
{
    tokio::spawn(async move {
        let mut buf = [0_u8; 8192];
        let mut decoder = Utf8StreamDecoder::default();
        loop {
            match reader.read(&mut buf).await {
                Ok(0) => break,
                Ok(n) => {
                    let text = decoder.push(&buf[..n]);
                    process.append_output(stream, &text);
                }
                Err(error) => {
                    debug!(process_id = %process.id, %error, "output drain stopped");
                    break;
                }
            }
        }
        let tail = decoder.finish();
        process.append_output(stream, &tail);
    })
}

fn configure_process_group(command: &mut Command) {
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        command.as_std_mut().process_group(0);
    }
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        const CREATE_NEW_PROCESS_GROUP: u32 = 0x0000_0200;
        command.creation_flags(CREATE_NEW_PROCESS_GROUP);
    }
}

async fn signal_tree(control: &ProcessControl, signal: SignalKind) -> anyhow::Result<()> {
    #[cfg(unix)]
    {
        use nix::{
            sys::signal::{Signal, kill, killpg},
            unistd::Pid,
        };
        let native = match signal {
            SignalKind::Int => Signal::SIGINT,
            SignalKind::Term => Signal::SIGTERM,
            SignalKind::Kill => Signal::SIGKILL,
        };
        if let Some(pgid) = control.process_group {
            match killpg(Pid::from_raw(pgid), native) {
                Ok(()) | Err(nix::errno::Errno::ESRCH) => return Ok(()),
                Err(error) => {
                    debug!(%error, pgid, "process-group signal failed; trying PID fallback")
                }
            }
        }
        if let Some(pid) = control.pid {
            let pid = i32::try_from(pid).context("process id does not fit platform pid_t")?;
            match kill(Pid::from_raw(pid), native) {
                Ok(()) | Err(nix::errno::Errno::ESRCH) => return Ok(()),
                Err(error) => debug!(%error, pid, "PID signal failed; trying PTY fallback"),
            }
        }
    }

    #[cfg(windows)]
    if let Some(pid) = control.pid {
        let pid_text = pid.to_string();
        let mut args = vec!["/PID", pid_text.as_str(), "/T"];
        if matches!(signal, SignalKind::Kill) {
            args.push("/F");
        }
        let status = tokio::process::Command::new("taskkill")
            .args(args)
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
            .await
            .context("failed to invoke taskkill")?;
        if status.success() {
            return Ok(());
        }
        debug!(%pid, ?status, "taskkill failed; trying PTY fallback");
    }

    if let Some(killer) = &control.pty_killer {
        let killer = Arc::clone(killer);
        tokio::task::spawn_blocking(move || {
            killer
                .lock()
                .map_err(|_| anyhow::anyhow!("PTY killer mutex poisoned"))?
                .kill()
                .context("PTY child kill failed")
        })
        .await
        .context("PTY killer task failed")??;
        return Ok(());
    }

    if control.pid.is_none() {
        bail!("process has no OS process identifier");
    }
    #[cfg(unix)]
    bail!("failed to signal process tree using both process-group and PID signalling");
    #[cfg(windows)]
    bail!("taskkill failed to signal the process tree");
    #[cfg(not(any(unix, windows)))]
    bail!("process signalling is not supported on this platform");
}

fn status_message(status: ProcessStatus, exit_code: Option<i32>, elapsed: Duration) -> String {
    match status {
        ProcessStatus::Running => format!("Running · {}", human_duration(elapsed)),
        ProcessStatus::Exited => format!(
            "Exited with code {} · {}",
            exit_code.unwrap_or(-1),
            human_duration(elapsed)
        ),
        ProcessStatus::Signaled => format!("Terminated by signal · {}", human_duration(elapsed)),
        ProcessStatus::TimedOut => format!("Timed out · {}", human_duration(elapsed)),
        ProcessStatus::Cancelled => format!("Cancelled · {}", human_duration(elapsed)),
        ProcessStatus::Failed => format!("Process failed · {}", human_duration(elapsed)),
    }
}

fn human_duration(duration: Duration) -> String {
    let ms = duration.as_millis();
    if ms < 1000 {
        format!("{ms}ms")
    } else if ms < 60_000 {
        format!("{:.1}s", duration.as_secs_f64())
    } else {
        format!("{:.1}m", duration.as_secs_f64() / 60.0)
    }
}

fn millis(duration: Duration) -> u64 {
    duration.as_millis().min(u128::from(u64::MAX)) as u64
}

fn truncate_chars(input: &str, max: usize) -> String {
    let mut out: String = input.chars().take(max).collect();
    if input.chars().count() > max {
        out.push('…');
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn output_buffer_is_bounded_and_paginated() {
        let mut buffer = OutputBuffer::new(8, 4, Instant::now());
        buffer.append(OutputStream::Stdout, "1234");
        buffer.append(OutputStream::Stderr, "5678");
        buffer.append(OutputStream::Stdout, "90");
        assert!(buffer.truncated);
        let (events, cursor, _, has_more) = buffer.read_since(0, 4);
        assert!(!events.is_empty());
        assert!(cursor > 0);
        assert!(has_more);
    }

    #[test]
    fn utf8_decoder_preserves_split_code_points() {
        let bytes = "x🙂y".as_bytes();
        let mut decoder = Utf8StreamDecoder::default();
        let first = decoder.push(&bytes[..3]);
        let second = decoder.push(&bytes[3..]);
        let tail = decoder.finish();
        assert_eq!(format!("{first}{second}{tail}"), "x🙂y");
    }

    #[test]
    fn output_events_respect_response_chunk_budget() {
        let mut buffer = OutputBuffer::new(32, 4, Instant::now());
        buffer.append(OutputStream::Stdout, "abcdefgh");
        let (events, _, _, has_more) = buffer.read_since(0, 4);
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].data, "abcd");
        assert!(has_more);
    }

    #[test]
    fn output_tail_is_bounded_and_preserves_final_text() {
        let mut buffer = OutputBuffer::new(64, 16, Instant::now());
        buffer.append(OutputStream::Stdout, "0123456789");
        buffer.append(OutputStream::Stderr, "final-line\n");
        let (tail, truncated, cursor) = buffer.tail(11);
        assert_eq!(tail, "final-line\n");
        assert!(truncated);
        assert_eq!(cursor, 2);
    }

    #[test]
    fn retained_pty_output_keeps_terminal_sequences() {
        let mut buffer = OutputBuffer::new(64, 64, Instant::now());
        buffer.append(OutputStream::Pty, "\u{1b}[31mred\u{1b}[0m\n");
        let (events, _, _, _) = buffer.read_since(0, 64);
        assert_eq!(events[0].data, "\u{1b}[31mred\u{1b}[0m\n");
        assert_eq!(sanitize_status(&events[0].data), "red\n");
        assert_eq!(buffer.recent_excerpt().as_deref(), Some("red"));
    }

    #[test]
    fn evicted_initial_cursor_is_reported_lost() {
        let mut buffer = OutputBuffer::new(4, 4, Instant::now());
        buffer.append(OutputStream::Stdout, "old!");
        buffer.append(OutputStream::Stdout, "new!");
        let (_, _, cursor_lost, _) = buffer.read_since(0, 4);
        assert!(cursor_lost);
    }

    #[test]
    fn process_id_validation_is_strict() {
        assert!(valid_process_id("p_0123456789abcdef0123456789abcdef"));
        assert!(!valid_process_id("p_ABCDEF0123456789abcdef0123456789"));
        assert!(!valid_process_id("../../process"));
    }
}
