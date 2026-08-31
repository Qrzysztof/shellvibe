use std::{
    borrow::Cow,
    collections::VecDeque,
    sync::{Arc, Mutex as StdMutex},
    time::{Duration, Instant},
};

use anyhow::{Context, bail};
use rmcp::{
    ErrorData, RoleServer, ServerHandler,
    model::{
        CacheScope, CallToolRequestParams, CallToolResponse, CallToolResult, CancelTaskParams,
        ClientCapabilities, CreateTaskResult, GetTaskParams, GetTaskResult, Implementation,
        ListToolsResult, ProgressNotificationParam, ProgressToken, ProtocolVersion,
        RequestParamsMeta, ServerCapabilities, ServerInfo, Tool, UpdateTaskParams,
    },
    service::RequestContext,
    task_manager::{TaskContext, TaskExit, TaskManager, TaskOptions},
};
use serde::{Serialize, de::DeserializeOwned};
use serde_json::{Map, Value, json};
use tracing::debug;

const MAX_TOOL_ERROR_CHARS: usize = 2_048;
const MAX_TOOL_NAME_CHARS: usize = 128;

use crate::{
    config::{Config, duration_ms},
    model::{
        CommandMode, CommandSpec, ExecutionMode, MAX_ARG_BYTES, MAX_ARGV_BYTES, MAX_ARGV_ITEMS,
        MAX_COMMAND_BYTES, MAX_ENV_BYTES, MAX_ENV_ITEMS, MAX_PATH_BYTES, MAX_STDIN_BYTES,
        MIN_READ_PAGE_BYTES, ProcessStatus, ReadRequest, ResizeRequest, ShellRequest, ShellResult,
        SignalRequest, WriteRequest,
    },
    process::{ManagedProcess, ProcessManager, sanitize_output},
    schema,
};

#[derive(Clone)]
pub struct ShellVibe {
    config: Arc<Config>,
    manager: ProcessManager,
    tasks: TaskManager,
    tool_limiter: Arc<SlidingWindowLimiter>,
}

#[derive(Debug)]
struct SlidingWindowLimiter {
    limit: usize,
    window: Duration,
    hits: StdMutex<VecDeque<Instant>>,
}

impl SlidingWindowLimiter {
    fn per_minute(limit: usize) -> Self {
        Self {
            limit,
            window: Duration::from_secs(60),
            hits: StdMutex::new(VecDeque::with_capacity(limit.min(4096))),
        }
    }

    fn check(&self) -> anyhow::Result<()> {
        let now = Instant::now();
        let mut hits = self.hits.lock().expect("tool rate-limit mutex poisoned");
        while hits
            .front()
            .is_some_and(|timestamp| now.duration_since(*timestamp) >= self.window)
        {
            hits.pop_front();
        }
        if hits.len() >= self.limit {
            bail!("tool invocation rate limit exceeded; retry later");
        }
        hits.push_back(now);
        Ok(())
    }
}

fn validate_shell_request(request: &ShellRequest) -> anyhow::Result<()> {
    if let Some(command) = &request.command {
        if command.len() > MAX_COMMAND_BYTES {
            bail!("command exceeds the maximum size of {MAX_COMMAND_BYTES} bytes");
        }
        if command.contains('\0') {
            bail!("command must not contain NUL bytes");
        }
    }

    if let Some(argv) = &request.argv {
        if argv.len() > MAX_ARGV_ITEMS {
            bail!("argv contains too many items (maximum {MAX_ARGV_ITEMS})");
        }
        let mut total = 0usize;
        for argument in argv {
            if argument.len() > MAX_ARG_BYTES {
                bail!("an argv item exceeds the maximum size of {MAX_ARG_BYTES} bytes");
            }
            if argument.contains('\0') {
                bail!("argv items must not contain NUL bytes");
            }
            total = total.saturating_add(argument.len());
        }
        if total > MAX_ARGV_BYTES {
            bail!("argv exceeds the maximum aggregate size of {MAX_ARGV_BYTES} bytes");
        }
    }

    if request.env.len() > MAX_ENV_ITEMS {
        bail!("env contains too many variables (maximum {MAX_ENV_ITEMS})");
    }
    let mut env_bytes = 0usize;
    for (key, value) in &request.env {
        if key.is_empty() || key.contains('\0') || key.contains('=') {
            bail!("environment variable names must be non-empty and contain neither NUL nor '='");
        }
        if value.contains('\0') {
            bail!("environment variable values must not contain NUL bytes");
        }
        env_bytes = env_bytes
            .saturating_add(key.len())
            .saturating_add(value.len());
    }
    if env_bytes > MAX_ENV_BYTES {
        bail!("env exceeds the maximum aggregate size of {MAX_ENV_BYTES} bytes");
    }

    if let Some(cwd) = &request.cwd {
        let cwd = cwd.to_string_lossy();
        if cwd.len() > MAX_PATH_BYTES {
            bail!("cwd exceeds the maximum size of {MAX_PATH_BYTES} bytes");
        }
        if cwd.contains('\0') {
            bail!("cwd must not contain NUL bytes");
        }
    }

    if request
        .stdin
        .as_ref()
        .is_some_and(|stdin| stdin.len() > MAX_STDIN_BYTES)
    {
        bail!("stdin exceeds the maximum size of {MAX_STDIN_BYTES} bytes");
    }
    Ok(())
}

impl ShellVibe {
    pub fn new(config: Config) -> Self {
        let config = Arc::new(config);
        let manager = ProcessManager::new(Arc::clone(&config));
        let tool_limiter = Arc::new(SlidingWindowLimiter::per_minute(
            config.max_tool_calls_per_minute,
        ));
        Self {
            config,
            manager,
            tasks: TaskManager::new(),
            tool_limiter,
        }
    }

    pub fn policy_name(&self) -> &'static str {
        self.config.policy.name()
    }

    pub async fn shutdown(&self) {
        // ProcessManager owns OS process lifetime. Stop processes first so task
        // futures can observe terminal state, then clear the protocol task store.
        if let Err(error) = self.manager.shutdown().await {
            tracing::error!(%error, "failed to stop managed processes during shutdown");
        }
        self.tasks.shutdown();
    }

    fn build_spec(&self, request: ShellRequest) -> anyhow::Result<(CommandSpec, Duration)> {
        validate_shell_request(&request)?;
        let cwd = request.cwd.unwrap_or_else(|| self.config.workdir.clone());
        if !cwd.is_dir() {
            bail!(
                "cwd does not exist or is not a directory: {}",
                cwd.display()
            );
        }
        let cwd = std::fs::canonicalize(&cwd)
            .with_context(|| format!("failed to canonicalize cwd {}", cwd.display()))?;

        let mode = if self.config.policy.is_restricted() {
            if request.command.is_some() {
                bail!("this shellvibe instance is restricted; use argv, not command");
            }
            let argv = request
                .argv
                .context("argv is required in restricted mode")?;
            if argv.is_empty() {
                bail!("argv must contain at least argv[0]");
            }
            let executable = self.config.policy.authorize(&argv[0], &cwd)?;
            CommandMode::Direct { argv, executable }
        } else {
            if request.argv.is_some() {
                bail!("this shellvibe instance is unrestricted; use command, not argv");
            }
            let command = request.command.context("command is required")?;
            if command.trim().is_empty() {
                bail!("command must not be empty");
            }
            CommandMode::Shell {
                shell: self.config.shell.clone(),
                command,
            }
        };

        let timeout = match request.timeout_ms {
            Some(0) => bail!("timeoutMs must be greater than zero"),
            Some(milliseconds) => Duration::from_millis(milliseconds).min(self.config.max_runtime),
            None => self.config.max_runtime,
        };

        let yield_after = request
            .yield_ms
            .map(Duration::from_millis)
            .unwrap_or(self.config.yield_after);
        if yield_after.is_zero() {
            bail!("yieldMs must be greater than zero");
        }

        let execution = request.execution;
        let pty = request.pty || execution == ExecutionMode::Interactive;
        let rows = request.rows.unwrap_or(24);
        let cols = request.cols.unwrap_or(80);
        if rows == 0 || cols == 0 {
            bail!("PTY rows and cols must be greater than zero");
        }
        if rows > 1000 || cols > 2000 {
            bail!("PTY rows/cols exceed the supported maximum of 1000x2000");
        }

        Ok((
            CommandSpec {
                mode,
                execution,
                cwd,
                env: request.env,
                initial_stdin: request.stdin,
                pty,
                rows,
                cols,
                timeout,
            },
            yield_after,
        ))
    }

    async fn call_shell(
        &self,
        request: ShellRequest,
        progress_token: Option<ProgressToken>,
        context: RequestContext<RoleServer>,
    ) -> CallToolResponse {
        match self
            .call_shell_inner(request, progress_token, context)
            .await
        {
            Ok(response) => response,
            Err(error) => CallToolResponse::Complete(tool_error(error)),
        }
    }

    async fn call_shell_inner(
        &self,
        request: ShellRequest,
        progress_token: Option<ProgressToken>,
        context: RequestContext<RoleServer>,
    ) -> anyhow::Result<CallToolResponse> {
        let (spec, yield_after) = self.build_spec(request)?;
        let execution = spec.execution;
        let process = self.manager.spawn(spec).await?;

        match execution {
            ExecutionMode::Background | ExecutionMode::Interactive => Ok(
                CallToolResponse::Complete(success_result(process.start_result())),
            ),
            ExecutionMode::Foreground => {
                self.run_foreground(process, yield_after, progress_token, context)
                    .await
            }
        }
    }

    async fn run_foreground(
        &self,
        process: Arc<ManagedProcess>,
        yield_after: Duration,
        progress_token: Option<ProgressToken>,
        context: RequestContext<RoleServer>,
    ) -> anyhow::Result<CallToolResponse> {
        // Tasks are a 2026-07-28 extension and are only legal when the client
        // negotiated that protocol revision and explicitly declared the extension.
        let supports_tasks = context
            .protocol_version()
            .as_ref()
            .is_some_and(|version| version == &ProtocolVersion::V_2026_07_28)
            && context
                .client_capabilities()
                .is_some_and(|capabilities| capabilities.supports_tasks());

        let deadline = tokio::time::sleep(yield_after);
        tokio::pin!(deadline);
        let mut interval = tokio::time::interval(self.config.progress_interval);
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        // Consume tokio::interval's immediate first tick; progress should describe
        // actual elapsed work, not fire at t=0.
        interval.tick().await;
        let mut progress_counter = 0_f64;

        loop {
            if !process.is_running() {
                return Ok(CallToolResponse::Complete(result_for_shell(
                    process.completion_result(self.completion_output_budget()),
                )));
            }

            tokio::select! {
                () = context.ct.cancelled() => {
                    process
                        .terminate(
                            ProcessStatus::Cancelled,
                            "REQUEST_CANCELLED",
                            self.config.termination_grace,
                        )
                        .await?;
                    return Ok(CallToolResponse::Complete(result_for_shell(
                        process.completion_result(self.completion_output_budget()),
                    )));
                }
                _ = &mut deadline => {
                    if !process.is_running() {
                        return Ok(CallToolResponse::Complete(result_for_shell(
                            process.completion_result(self.completion_output_budget()),
                        )));
                    }
                    if supports_tasks {
                        return Ok(self.create_process_task(process));
                    }
                    return Ok(CallToolResponse::Complete(success_result(process.start_result())));
                }
                _ = process.wait_for_notification() => {
                    if !process.is_running() {
                        return Ok(CallToolResponse::Complete(result_for_shell(
                            process.completion_result(self.completion_output_budget()),
                        )));
                    }
                }
                _ = interval.tick() => {
                    if let Some(token) = progress_token.clone() {
                        progress_counter += 1.0;
                        let notification = ProgressNotificationParam::new(token, progress_counter)
                            .with_message(process.progress_message());
                        if let Err(error) = context.peer.notify_progress(notification).await {
                            debug!(%error, "client rejected progress notification");
                        }
                    }
                }
            }
        }
    }

    fn create_process_task(&self, process: Arc<ManagedProcess>) -> CallToolResponse {
        let initial_message = process.progress_message();
        let poll_ms = duration_ms(self.config.task_poll_interval).max(1);
        let ttl_ms = duration_ms(self.config.task_ttl).max(1);
        let status_interval = self.config.progress_interval;
        let termination_grace = self.config.termination_grace;
        let max_completion_output = self.config.max_completion_output;

        let task = self.tasks.spawn(
            TaskOptions::new()
                .with_ttl_ms(Some(ttl_ms))
                .with_poll_interval_ms(poll_ms)
                .with_status_message(initial_message),
            move |task_context| {
                Box::pin(run_process_task(
                    process,
                    task_context,
                    status_interval,
                    termination_grace,
                    max_completion_output,
                ))
            },
        );

        CallToolResponse::Task(CreateTaskResult::new(task))
    }

    fn completion_output_budget(&self) -> usize {
        self.config.max_completion_output
    }

    async fn call_read(&self, request: ReadRequest) -> CallToolResult {
        let result = async {
            let process = self.manager.get(&request.process_id)?;
            process.validate_cursor(request.cursor)?;
            let max_bytes = request.max_bytes.unwrap_or(self.config.max_response_output);
            if max_bytes < MIN_READ_PAGE_BYTES {
                bail!("maxBytes must be at least {MIN_READ_PAGE_BYTES} bytes");
            }
            let max_bytes = max_bytes.min(self.config.max_response_output);
            let wait =
                Duration::from_millis(request.wait_ms.unwrap_or(0)).min(self.config.max_read_wait);
            if !wait.is_zero() {
                process.wait_for_change(request.cursor, wait).await;
            }
            process.read_result(request.cursor, max_bytes)
        }
        .await;
        match result {
            Ok(snapshot) => success_result(snapshot),
            Err(error) => tool_error(error),
        }
    }

    async fn call_write(&self, request: WriteRequest) -> CallToolResult {
        let result = async {
            if request.data.is_none() && !request.close_stdin {
                bail!("shell_write requires data and/or closeStdin=true");
            }
            let process = self.manager.get(&request.process_id)?;
            if request.data.as_ref().is_some_and(|data| {
                data.len()
                    .saturating_add(if request.append_newline { 1 } else { 0 })
                    > MAX_STDIN_BYTES
            }) {
                bail!("shell_write data exceeds the maximum size of {MAX_STDIN_BYTES} bytes");
            }
            let mut accepted_bytes = 0;
            if let Some(mut data) = request.data {
                if request.append_newline {
                    data.push('\n');
                }
                accepted_bytes = data.len();
                process.write(data.as_bytes()).await?;
            }
            if request.close_stdin {
                process.close_stdin().await;
            }
            Ok::<_, anyhow::Error>(process.write_result(accepted_bytes, request.close_stdin))
        }
        .await;
        match result {
            Ok(snapshot) => success_result(snapshot),
            Err(error) => tool_error(error),
        }
    }

    async fn call_signal(&self, request: SignalRequest) -> CallToolResult {
        let result = async {
            let process = self.manager.get(&request.process_id)?;
            let accepted = process.is_running();
            process.signal(request.signal).await?;
            Ok::<_, anyhow::Error>(process.signal_result(request.signal, accepted))
        }
        .await;
        match result {
            Ok(snapshot) => success_result(snapshot),
            Err(error) => tool_error(error),
        }
    }

    async fn call_resize(&self, request: ResizeRequest) -> CallToolResult {
        let result = async {
            let process = self.manager.get(&request.process_id)?;
            process.resize(request.rows, request.cols).await?;
            Ok::<_, anyhow::Error>(process.resize_result(request.rows, request.cols))
        }
        .await;
        match result {
            Ok(snapshot) => success_result(snapshot),
            Err(error) => tool_error(error),
        }
    }
}

struct TaskProcessGuard {
    process: Arc<ManagedProcess>,
    termination_grace: Duration,
    armed: bool,
}

impl TaskProcessGuard {
    fn new(process: Arc<ManagedProcess>, termination_grace: Duration) -> Self {
        Self {
            process,
            termination_grace,
            armed: true,
        }
    }

    fn disarm(&mut self) {
        self.armed = false;
    }
}

impl Drop for TaskProcessGuard {
    fn drop(&mut self) {
        if !self.armed || !self.process.is_running() {
            return;
        }
        let process = Arc::clone(&self.process);
        let grace = self.termination_grace;
        // TaskManager may abort a task future when its TTL expires. The OS process
        // must never outlive that abandoned protocol lifecycle invisibly.
        if let Ok(handle) = tokio::runtime::Handle::try_current() {
            handle.spawn(async move {
                let _ = process
                    .terminate(ProcessStatus::Cancelled, "TASK_ABORTED", grace)
                    .await;
            });
        }
    }
}

async fn run_process_task(
    process: Arc<ManagedProcess>,
    task_context: TaskContext,
    status_interval: Duration,
    termination_grace: Duration,
    max_completion_output: usize,
) -> Result<CallToolResult, TaskExit> {
    let mut guard = TaskProcessGuard::new(Arc::clone(&process), termination_grace);
    let mut interval = tokio::time::interval(status_interval);
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    interval.tick().await;

    loop {
        if !process.is_running() {
            guard.disarm();
            return Ok(result_for_shell(
                process.completion_result(max_completion_output),
            ));
        }

        tokio::select! {
            () = task_context.cancelled() => {
                if let Err(error) = process
                    .terminate(ProcessStatus::Cancelled, "TASK_CANCELLED", termination_grace)
                    .await
                {
                    return Err(TaskExit::Error(ErrorData::internal_error(
                        format!("failed to terminate cancelled process: {error}"),
                        None,
                    )));
                }
                let snapshot = process.completion_result(max_completion_output);
                if snapshot.status == ProcessStatus::Cancelled {
                    return Err(TaskExit::Cancelled);
                }
                // A timeout or another terminal condition may have won the race
                // with cancellation. Preserve that real terminal outcome instead
                // of masking it as a cancelled Task.
                guard.disarm();
                return Ok(result_for_shell(snapshot));
            }
            _ = process.wait_for_notification() => {
                if !process.is_running() {
                    return Ok(result_for_shell(
                        process.completion_result(max_completion_output),
                    ));
                }
            }
            _ = interval.tick() => {
                task_context.set_status_message(process.progress_message());
            }
        }
    }
}

impl ServerHandler for ShellVibe {
    fn supported_protocol_versions(&self) -> Cow<'static, [ProtocolVersion]> {
        Cow::Owned(vec![ProtocolVersion::V_2026_07_28])
    }

    fn get_info(&self) -> ServerInfo {
        let instructions = if self.config.policy.is_restricted() {
            format!(
                "shellvibe provides direct process execution under the '{}' executable policy. Use shell with argv; shell syntax is intentionally unavailable. foreground commands may transparently use MCP Tasks when the client supports io.modelcontextprotocol/tasks. Use background/interactive plus shell_read/shell_write/shell_signal/shell_resize for explicit process control. Executable policy is a top-level guardrail, not an OS sandbox. Task IDs remain available only for the lifetime of this shellvibe server process.",
                self.config.policy.name()
            )
        } else {
            "shellvibe provides unrestricted local shell access with the permissions of the user running this MCP server. Commands can be destructive and may access files, processes, and the network. foreground commands may transparently use MCP Tasks when supported; background/interactive return explicit process handles. Task IDs remain available only for the lifetime of this shellvibe server process."
                .to_string()
        };

        ServerInfo::new(
            ServerCapabilities::builder()
                .enable_tools()
                .enable_tasks()
                .build(),
        )
        .with_protocol_version(ProtocolVersion::V_2026_07_28)
        .with_server_info(
            Implementation::new("shellvibe", env!("CARGO_PKG_VERSION"))
                .with_title("shellvibe")
                .with_description("Observable shell and process lifecycle access for MCP agents"),
        )
        .with_instructions(instructions)
    }

    fn get_tool(&self, name: &str) -> Option<Tool> {
        schema::get_tool(&self.config.policy, name)
    }

    async fn list_tools(
        &self,
        _request: Option<rmcp::model::PaginatedRequestParams>,
        _context: RequestContext<RoleServer>,
    ) -> Result<ListToolsResult, ErrorData> {
        Ok(
            ListToolsResult::with_all_items(schema::tools(&self.config.policy))
                .with_ttl_ms(60_000)
                .with_cache_scope(CacheScope::Private),
        )
    }

    async fn call_tool(
        &self,
        request: CallToolRequestParams,
        context: RequestContext<RoleServer>,
    ) -> Result<CallToolResponse, ErrorData> {
        let progress_token = request.progress_token();
        let name = request.name.to_string();
        let arguments = request.arguments.unwrap_or_default();

        if schema::get_tool(&self.config.policy, &name).is_none() {
            let safe_name = bounded_text(&sanitize_output(&name), MAX_TOOL_NAME_CHARS);
            return Err(ErrorData::invalid_params(
                format!("unknown tool '{safe_name}'"),
                None,
            ));
        }

        if let Err(error) = self.tool_limiter.check() {
            return Ok(CallToolResponse::Complete(tool_error(error)));
        }

        let response = match name.as_str() {
            "shell" => {
                let args = match decode::<ShellRequest>(arguments) {
                    Ok(args) => args,
                    Err(error) => return Ok(CallToolResponse::Complete(tool_error(error))),
                };
                self.call_shell(args, progress_token, context).await
            }
            "shell_read" => {
                let args = match decode::<ReadRequest>(arguments) {
                    Ok(args) => args,
                    Err(error) => return Ok(CallToolResponse::Complete(tool_error(error))),
                };
                tokio::select! {
                    result = self.call_read(args) => CallToolResponse::Complete(result),
                    () = context.ct.cancelled() => CallToolResponse::Complete(request_cancelled()),
                }
            }
            "shell_write" => {
                let args = match decode::<WriteRequest>(arguments) {
                    Ok(args) => args,
                    Err(error) => return Ok(CallToolResponse::Complete(tool_error(error))),
                };
                tokio::select! {
                    result = self.call_write(args) => CallToolResponse::Complete(result),
                    () = context.ct.cancelled() => CallToolResponse::Complete(request_cancelled()),
                }
            }
            "shell_signal" => {
                let args = match decode::<SignalRequest>(arguments) {
                    Ok(args) => args,
                    Err(error) => return Ok(CallToolResponse::Complete(tool_error(error))),
                };
                tokio::select! {
                    result = self.call_signal(args) => CallToolResponse::Complete(result),
                    () = context.ct.cancelled() => CallToolResponse::Complete(request_cancelled()),
                }
            }
            "shell_resize" => {
                let args = match decode::<ResizeRequest>(arguments) {
                    Ok(args) => args,
                    Err(error) => return Ok(CallToolResponse::Complete(tool_error(error))),
                };
                tokio::select! {
                    result = self.call_resize(args) => CallToolResponse::Complete(result),
                    () = context.ct.cancelled() => CallToolResponse::Complete(request_cancelled()),
                }
            }
            _ => unreachable!("tool existence was checked before dispatch"),
        };
        Ok(response)
    }

    async fn get_task(
        &self,
        request: GetTaskParams,
        context: RequestContext<RoleServer>,
    ) -> Result<GetTaskResult, ErrorData> {
        require_tasks(&context)?;
        self.tasks
            .get_task(&request.task_id)
            .map(GetTaskResult::new)
    }

    async fn update_task(
        &self,
        request: UpdateTaskParams,
        context: RequestContext<RoleServer>,
    ) -> Result<(), ErrorData> {
        require_tasks(&context)?;
        self.tasks
            .update_task(&request.task_id, request.input_responses)
    }

    async fn cancel_task(
        &self,
        request: CancelTaskParams,
        context: RequestContext<RoleServer>,
    ) -> Result<(), ErrorData> {
        require_tasks(&context)?;
        self.tasks.cancel_task(&request.task_id)
    }
}

fn require_tasks(context: &RequestContext<RoleServer>) -> Result<(), ErrorData> {
    let supported = context
        .protocol_version()
        .as_ref()
        .is_some_and(|version| version == &ProtocolVersion::V_2026_07_28)
        && context
            .client_capabilities()
            .is_some_and(|capabilities| capabilities.supports_tasks());
    if supported {
        Ok(())
    } else {
        Err(ErrorData::missing_required_client_capability(
            ClientCapabilities::builder().enable_tasks().build(),
        ))
    }
}

fn decode<T: DeserializeOwned>(arguments: Map<String, Value>) -> anyhow::Result<T> {
    serde_json::from_value(Value::Object(arguments)).context("invalid tool arguments")
}

fn result_for_shell(result: ShellResult) -> CallToolResult {
    let is_failure = result.status.is_terminal()
        && !(result.status == ProcessStatus::Exited && result.exit_code == Some(0));
    if is_failure {
        shell_result(result, true)
    } else {
        shell_result(result, false)
    }
}

fn success_result<T: Serialize>(result: T) -> CallToolResult {
    structured_result(result, false)
}

fn shell_result(result: ShellResult, is_error: bool) -> CallToolResult {
    structured_result(result, is_error)
}

fn structured_result<T: Serialize>(result: T, is_error: bool) -> CallToolResult {
    let structured = serde_json::to_value(result).expect("tool result serialization is infallible");
    if is_error {
        CallToolResult::structured_error(structured)
    } else {
        CallToolResult::structured(structured)
    }
}

fn tool_error(error: anyhow::Error) -> CallToolResult {
    let message = bounded_text(&sanitize_output(&error.to_string()), MAX_TOOL_ERROR_CHARS);
    CallToolResult::structured_error(json!({
        "error": "shellvibe_error",
        "message": message,
    }))
}

fn request_cancelled() -> CallToolResult {
    CallToolResult::structured_error(json!({
        "error": "shellvibe_error",
        "message": "request cancelled",
    }))
}

fn bounded_text(input: &str, max_chars: usize) -> String {
    let mut chars = input.chars();
    let mut output: String = chars.by_ref().take(max_chars).collect();
    if chars.next().is_some() {
        output.push('…');
    }
    output
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::ExecPolicy;
    use rmcp::{
        ServiceExt,
        model::{ClientInfo, ResultType, TaskPayload},
    };

    fn test_config() -> Config {
        Config {
            policy: ExecPolicy::Unrestricted,
            workdir: std::env::current_dir().unwrap(),
            shell: "/bin/sh".into(),
            yield_after: Duration::from_millis(20),
            max_runtime: Duration::from_secs(10),
            max_output: 2 * 1024 * 1024,
            max_response_output: 32 * 1024,
            max_completion_output: 12 * 1024,
            max_processes: 8,
            max_process_handles: 16,
            max_tool_calls_per_minute: 100,
            progress_interval: Duration::from_millis(10),
            max_read_wait: Duration::from_secs(1),
            process_retention: Duration::from_secs(5),
            task_ttl: Duration::from_secs(10),
            task_poll_interval: Duration::from_millis(10),
            termination_grace: Duration::from_millis(100),
        }
    }

    fn arguments(value: Value) -> Map<String, Value> {
        value.as_object().unwrap().clone()
    }

    fn complete_value(response: CallToolResponse) -> Value {
        let CallToolResponse::Complete(result) = response else {
            panic!("expected complete tool response");
        };
        result.structured_content.unwrap()
    }

    #[test]
    fn tool_errors_have_structured_output() {
        let result = tool_error(anyhow::anyhow!("boom"));
        assert_eq!(result.is_error, Some(true));
        assert_eq!(
            result.structured_content,
            Some(json!({"error": "shellvibe_error", "message": "boom"}))
        );
    }

    #[test]
    fn tool_rate_limiter_is_bounded() {
        let limiter = SlidingWindowLimiter::per_minute(2);
        assert!(limiter.check().is_ok());
        assert!(limiter.check().is_ok());
        assert!(limiter.check().is_err());
    }

    #[test]
    fn command_limit_is_enforced_in_utf8_bytes() {
        let exact = ShellRequest {
            command: Some("é".repeat(MAX_COMMAND_BYTES / 2)),
            argv: None,
            cwd: None,
            env: Default::default(),
            stdin: None,
            execution: ExecutionMode::Foreground,
            pty: false,
            yield_ms: None,
            timeout_ms: None,
            rows: None,
            cols: None,
        };
        assert_eq!(
            exact.command.as_ref().unwrap().chars().count(),
            MAX_COMMAND_BYTES / 2
        );
        assert_eq!(exact.command.as_ref().unwrap().len(), MAX_COMMAND_BYTES);
        assert!(validate_shell_request(&exact).is_ok());

        let over = ShellRequest {
            command: Some("界".repeat(MAX_COMMAND_BYTES / 3 + 1)),
            ..exact
        };
        assert!(over.command.as_ref().unwrap().chars().count() < MAX_COMMAND_BYTES);
        assert!(over.command.as_ref().unwrap().len() > MAX_COMMAND_BYTES);
        assert!(
            validate_shell_request(&over)
                .unwrap_err()
                .to_string()
                .contains("bytes")
        );
    }

    #[cfg(unix)]
    async fn spawn_test_process(server: &ShellVibe, command: &str) -> Arc<ManagedProcess> {
        let request = decode::<ShellRequest>(arguments(json!({
            "command": command,
            "execution": "background"
        })))
        .unwrap();
        let (spec, _) = server.build_spec(request).unwrap();
        server.manager.spawn(spec).await.unwrap()
    }

    #[cfg(unix)]
    fn read_value(result: CallToolResult) -> Value {
        result.structured_content.unwrap()
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn shell_read_returns_terminal_state_when_a_silent_process_exits() {
        let server = ShellVibe::new(test_config());
        let process = spawn_test_process(&server, "sleep 0.08").await;

        let result = read_value(
            server
                .call_read(ReadRequest {
                    process_id: process.id().to_string(),
                    cursor: 0,
                    wait_ms: Some(1_000),
                    max_bytes: None,
                })
                .await,
        );

        assert_eq!(result["status"], "exited");
        assert_eq!(result["exitCode"], 0);
        assert!(result["events"].as_array().unwrap().is_empty());
        server.shutdown().await;
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn spurious_notifications_do_not_end_shell_read_early() {
        let server = ShellVibe::new(test_config());
        let process = spawn_test_process(&server, "sleep 0.5").await;
        let reader = server.clone();
        let process_id = process.id().to_string();
        let started = Instant::now();
        let read = tokio::spawn(async move {
            reader
                .call_read(ReadRequest {
                    process_id,
                    cursor: 0,
                    wait_ms: Some(150),
                    max_bytes: None,
                })
                .await
        });

        tokio::time::sleep(Duration::from_millis(20)).await;
        process.notify_for_test();
        tokio::time::sleep(Duration::from_millis(40)).await;
        assert!(!read.is_finished());

        let result = read_value(read.await.unwrap());
        assert!(started.elapsed() >= Duration::from_millis(120));
        assert_eq!(result["status"], "running");
        assert_eq!(result["hasMore"], false);
        assert!(result["events"].as_array().unwrap().is_empty());
        server.shutdown().await;
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn shell_read_max_bytes_is_configurable_and_server_capped() {
        let server = ShellVibe::new(test_config());
        let process = spawn_test_process(
            &server,
            "yes 0123456789abcdef | head -c 131072; printf 'PAGE-END'",
        )
        .await;
        process.wait_until_terminal().await;

        let first = read_value(
            server
                .call_read(ReadRequest {
                    process_id: process.id().to_string(),
                    cursor: 0,
                    wait_ms: None,
                    max_bytes: Some(12 * 1024),
                })
                .await,
        );
        let first_bytes: usize = first["events"]
            .as_array()
            .unwrap()
            .iter()
            .map(|event| event["data"].as_str().unwrap().len())
            .sum();
        assert!(first_bytes <= 12 * 1024);
        assert!(
            first["events"]
                .as_array()
                .unwrap()
                .iter()
                .all(|event| event["data"].as_str().unwrap().len() <= 12 * 1024)
        );
        assert_eq!(first["hasMore"], true);

        let capped = read_value(
            server
                .call_read(ReadRequest {
                    process_id: process.id().to_string(),
                    cursor: first["nextCursor"].as_u64().unwrap(),
                    wait_ms: None,
                    max_bytes: Some(1024 * 1024),
                })
                .await,
        );
        let capped_bytes: usize = capped["events"]
            .as_array()
            .unwrap()
            .iter()
            .map(|event| event["data"].as_str().unwrap().len())
            .sum();
        assert!(capped_bytes <= 32 * 1024);
        assert!(capped_bytes > 12 * 1024);
        server.shutdown().await;
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn restricted_rustup_proxies_preserve_the_requested_executable_identity() {
        let mut config = test_config();
        config.policy = ExecPolicy::allow(
            vec!["cargo".to_string(), "rustc".to_string()],
            &config.workdir,
        )
        .unwrap();
        let server = ShellVibe::new(config);
        let shutdown = server.clone();
        let (server_transport, client_transport) = tokio::io::duplex(64 * 1024);
        let server_task = tokio::spawn(async move {
            server
                .serve(server_transport)
                .await
                .unwrap()
                .waiting()
                .await
                .unwrap();
        });
        let client = ClientInfo::new(
            ClientCapabilities::default(),
            Implementation::new("shellvibe-test", "0"),
        )
        .serve(client_transport)
        .await
        .unwrap();

        for executable in ["cargo", "rustc"] {
            let result = complete_value(
                client
                    .call_tool_once(
                        CallToolRequestParams::new("shell").with_arguments(arguments(json!({
                            "argv": [executable, "--version"],
                            "yieldMs": 5000
                        }))),
                    )
                    .await
                    .unwrap(),
            );
            assert_eq!(result["status"], "exited");
            assert_eq!(result["exitCode"], 0);
            let output = result["output"].as_str().unwrap();
            let expected_prefix = format!("{executable} ");
            assert!(
                output.starts_with(&expected_prefix),
                "{executable} proxy produced unexpected output: {output:?}"
            );
        }

        client.cancel().await.unwrap();
        shutdown.shutdown().await;
        server_task.abort();
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn tasks_are_negotiated_on_the_real_tool_call() {
        let server = ShellVibe::new(test_config());
        let shutdown = server.clone();
        let (server_transport, client_transport) = tokio::io::duplex(64 * 1024);
        let server_task = tokio::spawn(async move {
            server
                .serve(server_transport)
                .await
                .unwrap()
                .waiting()
                .await
                .unwrap();
        });
        let client = ClientInfo::new(
            ClientCapabilities::builder().enable_tasks().build(),
            Implementation::new("shellvibe-test", "0"),
        )
        .serve(client_transport)
        .await
        .unwrap();

        let fast = client
            .call_tool_once(
                CallToolRequestParams::new("shell")
                    .with_arguments(arguments(json!({"command": "printf fast"}))),
            )
            .await
            .unwrap();
        assert!(matches!(fast, CallToolResponse::Complete(_)));

        let long = client
            .call_tool_once(
                CallToolRequestParams::new("shell").with_arguments(arguments(json!({
                    "command": "yes 0123456789 | head -c 65536; sleep 0.15; printf task-final",
                    "yieldMs": 20
                }))),
            )
            .await
            .unwrap();
        let CallToolResponse::Task(created) = long else {
            panic!("expected Tasks-capable call to return a Task");
        };
        assert_eq!(created.result_type, ResultType::TASK);

        let completed = loop {
            tokio::time::sleep(Duration::from_millis(10)).await;
            let task = client
                .peer()
                .get_task(GetTaskParams::new(created.task.task_id.clone()))
                .await
                .unwrap()
                .task;
            if task.status().is_terminal() {
                break task;
            }
        };
        let TaskPayload::Completed { result } = completed.payload else {
            panic!("expected completed Task payload");
        };
        let result: CallToolResult = serde_json::from_value(Value::Object(result)).unwrap();
        let structured = result.structured_content.unwrap();
        let output = structured["output"].as_str().unwrap();
        assert!(output.len() > 8 * 1024);
        assert!(output.len() <= 12 * 1024);
        assert!(output.ends_with("task-final"));
        assert_eq!(structured["outputTruncated"], true);

        let cancellable = client
            .call_tool_once(
                CallToolRequestParams::new("shell").with_arguments(arguments(json!({
                    "command": "sleep 5",
                    "yieldMs": 20
                }))),
            )
            .await
            .unwrap();
        let CallToolResponse::Task(cancellable) = cancellable else {
            panic!("expected cancellable call to return a Task");
        };
        client
            .peer()
            .cancel_task(CancelTaskParams::new(cancellable.task.task_id.clone()))
            .await
            .unwrap();
        loop {
            tokio::time::sleep(Duration::from_millis(10)).await;
            let task = client
                .peer()
                .get_task(GetTaskParams::new(cancellable.task.task_id.clone()))
                .await
                .unwrap()
                .task;
            if task.status().is_terminal() {
                assert_eq!(task.status(), rmcp::model::TaskStatus::Cancelled);
                break;
            }
        }
        tokio::time::timeout(Duration::from_secs(1), async {
            while shutdown.manager.running_count_for_test() != 0 {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("task cancellation left its OS process running");

        client.cancel().await.unwrap();
        shutdown.shutdown().await;
        server_task.abort();
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn fallback_and_control_results_are_compact() {
        let server = ShellVibe::new(test_config());
        let shutdown = server.clone();
        let (server_transport, client_transport) = tokio::io::duplex(64 * 1024);
        let server_task = tokio::spawn(async move {
            server
                .serve(server_transport)
                .await
                .unwrap()
                .waiting()
                .await
                .unwrap();
        });
        let client = ClientInfo::new(
            ClientCapabilities::default(),
            Implementation::new("shellvibe-test", "0"),
        )
        .serve(client_transport)
        .await
        .unwrap();

        let fallback = complete_value(
            client
                .call_tool_once(
                    CallToolRequestParams::new("shell").with_arguments(arguments(json!({
                        "command": "sleep 5",
                        "yieldMs": 20
                    }))),
                )
                .await
                .unwrap(),
        );
        assert_eq!(fallback["status"], "running");
        let fallback_id = fallback["processId"].as_str().unwrap();
        let _ = client
            .call_tool_once(
                CallToolRequestParams::new("shell_signal").with_arguments(arguments(json!({
                    "processId": fallback_id,
                    "signal": "kill"
                }))),
            )
            .await
            .unwrap();

        let background = complete_value(
            client
                .call_tool_once(
                    CallToolRequestParams::new("shell").with_arguments(arguments(json!({
                        "command": "printf background-ready; sleep 5",
                        "execution": "background"
                    }))),
                )
                .await
                .unwrap(),
        );
        assert_eq!(background["nextCursor"], 0);
        let background_id = background["processId"].as_str().unwrap();
        let background_read = complete_value(
            client
                .call_tool_once(
                    CallToolRequestParams::new("shell_read").with_arguments(arguments(json!({
                        "processId": background_id,
                        "cursor": 0,
                        "waitMs": 500
                    }))),
                )
                .await
                .unwrap(),
        );
        let background_output: String = background_read["events"]
            .as_array()
            .unwrap()
            .iter()
            .map(|event| event["data"].as_str().unwrap())
            .collect();
        assert!(background_output.contains("background-ready"));
        let _ = client
            .call_tool_once(
                CallToolRequestParams::new("shell_signal").with_arguments(arguments(json!({
                    "processId": background_id,
                    "signal": "kill"
                }))),
            )
            .await
            .unwrap();

        let started = complete_value(
            client
                .call_tool_once(
                    CallToolRequestParams::new("shell").with_arguments(arguments(json!({
                        "command": "printf interactive-ready; cat",
                        "execution": "interactive"
                    }))),
                )
                .await
                .unwrap(),
        );
        assert_eq!(started["nextCursor"], 0);
        let process_id = started["processId"].as_str().unwrap();

        let early_output = complete_value(
            client
                .call_tool_once(
                    CallToolRequestParams::new("shell_read").with_arguments(arguments(json!({
                        "processId": process_id,
                        "cursor": 0,
                        "waitMs": 500
                    }))),
                )
                .await
                .unwrap(),
        );
        let early_output: String = early_output["events"]
            .as_array()
            .unwrap()
            .iter()
            .map(|event| event["data"].as_str().unwrap())
            .collect();
        assert!(early_output.contains("interactive-ready"));

        let future_cursor = complete_value(
            client
                .call_tool_once(
                    CallToolRequestParams::new("shell_read").with_arguments(arguments(json!({
                        "processId": process_id,
                        "cursor": 999,
                        "waitMs": 1000
                    }))),
                )
                .await
                .unwrap(),
        );
        assert_eq!(future_cursor["error"], "shellvibe_error");
        assert!(future_cursor["message"].as_str().unwrap().contains("ahead"));

        let write = complete_value(
            client
                .call_tool_once(CallToolRequestParams::new("shell_write").with_arguments(
                    arguments(json!({
                        "processId": process_id,
                        "data": "hello",
                        "appendNewline": true
                    })),
                ))
                .await
                .unwrap(),
        );
        assert_eq!(write["acceptedBytes"], 6);
        assert!(write.get("events").is_none());
        assert!(write.get("output").is_none());

        let resize = complete_value(
            client
                .call_tool_once(CallToolRequestParams::new("shell_resize").with_arguments(
                    arguments(json!({
                        "processId": process_id,
                        "rows": 30,
                        "cols": 100
                    })),
                ))
                .await
                .unwrap(),
        );
        assert_eq!(resize["rows"], 30);
        assert!(resize.get("events").is_none());

        let signal = complete_value(
            client
                .call_tool_once(CallToolRequestParams::new("shell_signal").with_arguments(
                    arguments(json!({
                        "processId": process_id,
                        "signal": "term"
                    })),
                ))
                .await
                .unwrap(),
        );
        assert_eq!(signal["accepted"], true);
        assert!(signal.get("events").is_none());

        let mut cursor = 0;
        let terminal = loop {
            let read = complete_value(
                client
                    .call_tool_once(CallToolRequestParams::new("shell_read").with_arguments(
                        arguments(json!({
                            "processId": process_id,
                            "cursor": cursor,
                            "waitMs": 500
                        })),
                    ))
                    .await
                    .unwrap(),
            );
            if read["status"] != "running" {
                break read;
            }
            cursor = read["nextCursor"].as_u64().unwrap();
        };
        assert_eq!(terminal["status"], "signaled");
        assert_eq!(terminal["signal"], "SIGTERM");
        assert!(terminal.get("exitCode").is_none());

        client.cancel().await.unwrap();
        shutdown.shutdown().await;
        server_task.abort();
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn foreground_large_output_returns_a_bounded_tail() {
        let server = ShellVibe::new(test_config());
        let shutdown = server.clone();
        let (server_transport, client_transport) = tokio::io::duplex(64 * 1024);
        let server_task = tokio::spawn(async move {
            server
                .serve(server_transport)
                .await
                .unwrap()
                .waiting()
                .await
                .unwrap();
        });
        let client = ClientInfo::new(
            ClientCapabilities::default(),
            Implementation::new("shellvibe-test", "0"),
        )
        .serve(client_transport)
        .await
        .unwrap();

        let result = complete_value(
            client
                .call_tool_once(
                    CallToolRequestParams::new("shell").with_arguments(arguments(json!({
                        "command": "yes 0123456789 | head -c 1048576; printf '\\nFINAL\\n'",
                        "yieldMs": 5000
                    }))),
                )
                .await
                .unwrap(),
        );
        let output = result["output"].as_str().unwrap();
        assert!(output.len() > 8 * 1024);
        assert!(output.len() <= 12 * 1024);
        assert!(output.ends_with("FINAL\n"));
        assert_eq!(result["outputTruncated"], true);
        assert!(serde_json::to_vec(&result).unwrap().len() < 15 * 1024);
        let process_id = result["processId"].as_str().unwrap();
        let mut cursor = 0_u64;
        let mut previous_event_cursor = 0_u64;
        let mut pages = 0;
        let mut retained_output = String::new();
        loop {
            let retained = complete_value(
                client
                    .call_tool_once(CallToolRequestParams::new("shell_read").with_arguments(
                        arguments(json!({
                            "processId": process_id,
                            "cursor": cursor
                        })),
                    ))
                    .await
                    .unwrap(),
            );
            pages += 1;
            assert_eq!(retained["cursorLost"], false);
            let events = retained["events"].as_array().unwrap();
            assert!(!events.is_empty());
            let page_bytes: usize = events
                .iter()
                .map(|event| event["data"].as_str().unwrap().len())
                .sum();
            assert!(page_bytes <= 32 * 1024);
            assert!(
                events
                    .iter()
                    .all(|event| event["data"].as_str().unwrap().len() <= 32 * 1024)
            );
            assert!(serde_json::to_vec(&retained).unwrap().len() < 36 * 1024);
            for event in events {
                let event_cursor = event["cursor"].as_u64().unwrap();
                assert_eq!(event_cursor, previous_event_cursor + 1);
                previous_event_cursor = event_cursor;
                retained_output.push_str(event["data"].as_str().unwrap());
            }
            let next_cursor = retained["nextCursor"].as_u64().unwrap();
            assert_eq!(next_cursor, previous_event_cursor);
            assert!(next_cursor > cursor);
            cursor = next_cursor;
            if retained["hasMore"] == false {
                break;
            }
        }
        assert!(pages > 1);
        assert!(retained_output.len() >= 1024 * 1024);
        assert!(retained_output.ends_with("FINAL\n"));

        client.cancel().await.unwrap();
        shutdown.shutdown().await;
        server_task.abort();
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn shell_read_reports_evicted_history_and_returns_retained_suffix() {
        let mut config = test_config();
        config.max_output = 16 * 1024;
        config.max_response_output = 8 * 1024;
        config.max_completion_output = 8 * 1024;
        let server = ShellVibe::new(config);
        let shutdown = server.clone();
        let (server_transport, client_transport) = tokio::io::duplex(64 * 1024);
        let server_task = tokio::spawn(async move {
            server
                .serve(server_transport)
                .await
                .unwrap()
                .waiting()
                .await
                .unwrap();
        });
        let client = ClientInfo::new(
            ClientCapabilities::default(),
            Implementation::new("shellvibe-test", "0"),
        )
        .serve(client_transport)
        .await
        .unwrap();

        let completed = complete_value(
            client
                .call_tool_once(
                    CallToolRequestParams::new("shell").with_arguments(arguments(json!({
                        "command": "yes eviction-data | head -c 131072; printf 'EVICTED-END'",
                        "yieldMs": 5000
                    }))),
                )
                .await
                .unwrap(),
        );
        let process_id = completed["processId"].as_str().unwrap();
        let retained = complete_value(
            client
                .call_tool_once(
                    CallToolRequestParams::new("shell_read").with_arguments(arguments(json!({
                        "processId": process_id,
                        "cursor": 0
                    }))),
                )
                .await
                .unwrap(),
        );
        assert_eq!(retained["cursorLost"], true);
        assert!(!retained["events"].as_array().unwrap().is_empty());
        assert!(retained["nextCursor"].as_u64().unwrap() > 0);

        client.cancel().await.unwrap();
        shutdown.shutdown().await;
        server_task.abort();
    }
}
