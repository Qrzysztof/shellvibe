use std::{path::PathBuf, time::Duration};

use anyhow::{Context, bail};
use clap::{ArgAction, Parser};

use crate::policy::ExecPolicy;

#[derive(Debug, Parser)]
#[command(
    name = "shellvibe",
    version,
    about = "Observable local shell access for MCP agents",
    long_about = None
)]
pub struct Cli {
    /// Only permit these exact top-level executables. Repeating creates an allowlist.
    /// Bare names are resolved through shellvibe's startup PATH and pinned to canonical paths.
    #[arg(
        long = "allow-exec",
        value_name = "EXEC",
        action = ArgAction::Append,
        conflicts_with_all = ["deny_exec", "unrestricted"]
    )]
    pub allow_exec: Vec<String>,

    /// Permit all top-level executables except these names/paths. Guardrail only, not a sandbox.
    #[arg(
        long = "deny-exec",
        value_name = "EXEC",
        action = ArgAction::Append,
        conflicts_with_all = ["allow_exec", "unrestricted"]
    )]
    pub deny_exec: Vec<String>,

    /// Explicitly permit unrestricted shell execution. This must be opted into.
    #[arg(
        long,
        action = ArgAction::SetTrue,
        conflicts_with_all = ["allow_exec", "deny_exec"]
    )]
    pub unrestricted: bool,

    /// Default working directory. Individual tool calls may override it.
    #[arg(long = "workdir", value_name = "DIR")]
    pub workdir: Option<PathBuf>,

    /// Shell executable used only in unrestricted mode.
    #[arg(long = "shell", value_name = "PATH")]
    pub shell: Option<PathBuf>,

    /// Foreground grace period before a still-running command becomes an MCP Task
    /// (when supported) or a process-handle fallback.
    #[arg(long = "yield-after", default_value = "10s", value_parser = parse_duration)]
    pub yield_after: Duration,

    /// Hard runtime limit for every managed process.
    #[arg(long = "max-runtime", default_value = "1h", value_parser = parse_duration)]
    pub max_runtime: Duration,

    /// Retained output ring-buffer budget per process.
    #[arg(long = "max-output", default_value = "4MiB", value_parser = parse_bytes)]
    pub max_output: usize,

    /// Maximum retained event-data budget returned by one MCP tool result.
    #[arg(long = "max-response-output", default_value = "256KiB", value_parser = parse_bytes)]
    pub max_response_output: usize,

    /// Maximum event-data budget persisted in a completed MCP Task result.
    #[arg(long = "max-task-result-output", default_value = "16KiB", value_parser = parse_bytes)]
    pub max_task_result_output: usize,

    /// Maximum number of simultaneously managed OS processes.
    #[arg(long = "max-processes", default_value_t = 16)]
    pub max_processes: usize,

    /// Maximum retained process handles, including completed handles awaiting expiry.
    #[arg(long = "max-process-handles", default_value_t = 64)]
    pub max_process_handles: usize,

    /// Maximum tools/call requests accepted in a rolling one-minute window.
    #[arg(long = "max-tool-calls-per-minute", default_value_t = 600)]
    pub max_tool_calls_per_minute: usize,

    /// Progress heartbeat interval while the initial foreground call is open.
    #[arg(long = "progress-interval", default_value = "2s", value_parser = parse_duration)]
    pub progress_interval: Duration,

    /// Maximum long-poll duration accepted by shell_read.
    #[arg(long = "max-read-wait", default_value = "30s", value_parser = parse_duration)]
    pub max_read_wait: Duration,

    /// How long completed process handles remain readable before lazy cleanup.
    #[arg(long = "process-retention", default_value = "5m", value_parser = parse_duration)]
    pub process_retention: Duration,

    /// MCP Task TTL. Tasks are bounded so abandoned task state cannot live forever.
    #[arg(long = "task-ttl", default_value = "1h", value_parser = parse_duration)]
    pub task_ttl: Duration,

    /// Suggested tasks/get polling interval advertised to clients.
    #[arg(long = "task-poll-interval", default_value = "1s", value_parser = parse_duration)]
    pub task_poll_interval: Duration,

    /// Grace after TERM before shellvibe escalates cancellation/timeout to KILL.
    #[arg(long = "termination-grace", default_value = "2s", value_parser = parse_duration)]
    pub termination_grace: Duration,
}

#[derive(Debug, Clone)]
pub struct Config {
    pub policy: ExecPolicy,
    pub workdir: PathBuf,
    pub shell: PathBuf,
    pub yield_after: Duration,
    pub max_runtime: Duration,
    pub max_output: usize,
    pub max_response_output: usize,
    pub max_task_result_output: usize,
    pub max_processes: usize,
    pub max_process_handles: usize,
    pub max_tool_calls_per_minute: usize,
    pub progress_interval: Duration,
    pub max_read_wait: Duration,
    pub process_retention: Duration,
    pub task_ttl: Duration,
    pub task_poll_interval: Duration,
    pub termination_grace: Duration,
}

impl TryFrom<Cli> for Config {
    type Error = anyhow::Error;

    fn try_from(cli: Cli) -> Result<Self, Self::Error> {
        let workdir = match cli.workdir {
            Some(path) => path,
            None => std::env::current_dir().context("cannot determine current directory")?,
        };
        if !workdir.is_dir() {
            bail!(
                "workdir does not exist or is not a directory: {}",
                workdir.display()
            );
        }
        let workdir = std::fs::canonicalize(&workdir)
            .with_context(|| format!("failed to canonicalize workdir {}", workdir.display()))?;

        let policy = if !cli.allow_exec.is_empty() {
            ExecPolicy::allow(cli.allow_exec, &workdir)?
        } else if !cli.deny_exec.is_empty() {
            ExecPolicy::deny(cli.deny_exec, &workdir)?
        } else if cli.unrestricted {
            ExecPolicy::Unrestricted
        } else {
            bail!(
                "execution policy is required; pass --allow-exec, --deny-exec, or explicitly opt in with --unrestricted"
            );
        };

        if policy.is_restricted() && cli.shell.is_some() {
            bail!("--shell is only valid together with --unrestricted");
        }

        for (name, value) in [
            ("--yield-after", cli.yield_after),
            ("--progress-interval", cli.progress_interval),
            ("--max-read-wait", cli.max_read_wait),
            ("--process-retention", cli.process_retention),
            ("--task-ttl", cli.task_ttl),
            ("--task-poll-interval", cli.task_poll_interval),
            ("--termination-grace", cli.termination_grace),
        ] {
            if value.is_zero() {
                bail!("{name} must be greater than zero");
            }
        }
        if cli.max_output < 4096 {
            bail!("--max-output must be at least 4KiB");
        }
        if cli.max_response_output < 8192 {
            bail!("--max-response-output must be at least 8KiB");
        }
        if cli.max_response_output > cli.max_output {
            bail!("--max-response-output cannot exceed --max-output");
        }
        if cli.max_task_result_output < 8192 {
            bail!("--max-task-result-output must be at least 8KiB");
        }
        if cli.max_task_result_output > cli.max_response_output {
            bail!("--max-task-result-output cannot exceed --max-response-output");
        }
        if cli.max_runtime.is_zero() {
            bail!("--max-runtime must be greater than zero");
        }
        if cli.max_runtime > cli.task_ttl {
            bail!("--task-ttl must be greater than or equal to --max-runtime");
        }
        if cli.max_processes == 0 {
            bail!("--max-processes must be greater than zero");
        }
        if cli.max_processes > 4096 {
            bail!("--max-processes must not exceed 4096");
        }
        if cli.max_process_handles < cli.max_processes {
            bail!("--max-process-handles must be greater than or equal to --max-processes");
        }
        if cli.max_process_handles > 65_536 {
            bail!("--max-process-handles must not exceed 65536");
        }
        if cli.max_tool_calls_per_minute == 0 {
            bail!("--max-tool-calls-per-minute must be greater than zero");
        }
        if cli.max_tool_calls_per_minute > 1_000_000 {
            bail!("--max-tool-calls-per-minute must not exceed 1000000");
        }
        if cli.task_poll_interval > cli.task_ttl {
            bail!("--task-poll-interval cannot exceed --task-ttl");
        }

        Ok(Self {
            policy,
            workdir,
            shell: cli.shell.unwrap_or_else(default_shell),
            yield_after: cli.yield_after,
            max_runtime: cli.max_runtime,
            max_output: cli.max_output,
            max_response_output: cli.max_response_output,
            max_task_result_output: cli.max_task_result_output,
            max_processes: cli.max_processes,
            max_process_handles: cli.max_process_handles,
            max_tool_calls_per_minute: cli.max_tool_calls_per_minute,
            progress_interval: cli.progress_interval,
            max_read_wait: cli.max_read_wait,
            process_retention: cli.process_retention,
            task_ttl: cli.task_ttl,
            task_poll_interval: cli.task_poll_interval,
            termination_grace: cli.termination_grace,
        })
    }
}

#[cfg(unix)]
fn default_shell() -> PathBuf {
    // Prefer the platform's stable POSIX command interpreter over the user's
    // interactive login shell, whose `-c` syntax may differ (fish, csh, etc.).
    PathBuf::from("/bin/sh")
}

#[cfg(windows)]
fn default_shell() -> PathBuf {
    std::env::var_os("COMSPEC")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("cmd.exe"))
}

#[cfg(not(any(unix, windows)))]
fn default_shell() -> PathBuf {
    PathBuf::from("sh")
}

fn parse_decimal_ratio(number: &str) -> Result<(u128, u128), String> {
    if number.is_empty() {
        return Err("number must not be empty".into());
    }
    let mut parts = number.split('.');
    let whole = parts.next().unwrap_or_default();
    let fraction = parts.next();
    if parts.next().is_some() {
        return Err(format!("invalid decimal number: {number}"));
    }
    if whole.is_empty() && fraction.is_none_or(str::is_empty) {
        return Err(format!("invalid decimal number: {number}"));
    }
    if !whole.bytes().all(|byte| byte.is_ascii_digit())
        || fraction.is_some_and(|value| !value.bytes().all(|byte| byte.is_ascii_digit()))
    {
        return Err(format!("invalid decimal number: {number}"));
    }

    let fraction = fraction.unwrap_or_default();
    let scale = 10_u128
        .checked_pow(u32::try_from(fraction.len()).map_err(|_| "decimal precision is too large")?)
        .ok_or_else(|| "decimal precision is too large".to_string())?;
    let whole = if whole.is_empty() {
        0
    } else {
        whole
            .parse::<u128>()
            .map_err(|_| format!("number is too large: {number}"))?
    };
    let fraction = if fraction.is_empty() {
        0
    } else {
        fraction
            .parse::<u128>()
            .map_err(|_| format!("number is too large: {number}"))?
    };
    let numerator = whole
        .checked_mul(scale)
        .and_then(|value| value.checked_add(fraction))
        .ok_or_else(|| format!("number is too large: {number}"))?;
    Ok((numerator, scale))
}

pub fn parse_duration(input: &str) -> Result<Duration, String> {
    let input = input.trim();
    if input.is_empty() {
        return Err("duration must not be empty".into());
    }
    let split = input
        .find(|c: char| !c.is_ascii_digit() && c != '.')
        .unwrap_or(input.len());
    let (number, unit) = input.split_at(split);
    let (numerator, scale) =
        parse_decimal_ratio(number).map_err(|error| format!("invalid duration: {error}"))?;
    let nanos_per_unit: u128 = match unit {
        "ms" => 1_000_000,
        "s" | "" => 1_000_000_000,
        "m" => 60 * 1_000_000_000,
        "h" => 3_600 * 1_000_000_000,
        _ => {
            return Err(format!(
                "unsupported duration unit '{unit}'; use ms, s, m, or h"
            ));
        }
    };
    let total_nanos = numerator
        .checked_mul(nanos_per_unit)
        .ok_or_else(|| "duration is too large".to_string())?
        / scale;
    let seconds = total_nanos / 1_000_000_000;
    if seconds > u128::from(u64::MAX) {
        return Err("duration is too large".into());
    }
    let nanos = (total_nanos % 1_000_000_000) as u32;
    Ok(Duration::new(seconds as u64, nanos))
}

pub fn parse_bytes(input: &str) -> Result<usize, String> {
    let input = input.trim();
    if input.is_empty() {
        return Err("byte count must not be empty".into());
    }
    let split = input
        .find(|c: char| !c.is_ascii_digit() && c != '.')
        .unwrap_or(input.len());
    let (number, unit) = input.split_at(split);
    let (numerator, scale) =
        parse_decimal_ratio(number).map_err(|error| format!("invalid byte count: {error}"))?;
    let multiplier: u128 = match unit.to_ascii_lowercase().as_str() {
        "" | "b" => 1,
        "kb" => 1_000,
        "kib" => 1_024,
        "mb" => 1_000_000,
        "mib" => 1_024 * 1_024,
        "gb" => 1_000_000_000,
        "gib" => 1_024 * 1_024 * 1_024,
        _ => return Err(format!("unsupported size unit '{unit}'")),
    };
    let bytes = numerator
        .checked_mul(multiplier)
        .ok_or_else(|| "byte count is too large for this platform".to_string())?
        / scale;
    if bytes > usize::MAX as u128 {
        return Err("byte count is too large for this platform".into());
    }
    Ok(bytes as usize)
}

pub fn duration_ms(duration: Duration) -> u64 {
    duration.as_millis().min(u128::from(u64::MAX)) as u64
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn duration_parser_supports_common_units() {
        assert_eq!(parse_duration("250ms").unwrap(), Duration::from_millis(250));
        assert_eq!(parse_duration("10s").unwrap(), Duration::from_secs(10));
        assert_eq!(parse_duration("2m").unwrap(), Duration::from_secs(120));
    }

    #[test]
    fn byte_parser_supports_binary_units() {
        assert_eq!(parse_bytes("4KiB").unwrap(), 4096);
        assert_eq!(parse_bytes("16MiB").unwrap(), 16 * 1024 * 1024);
    }

    #[test]
    fn parsers_support_fractional_values_without_float_rounding() {
        assert_eq!(parse_duration("1.5s").unwrap(), Duration::from_millis(1500));
        assert_eq!(parse_bytes("1.5KiB").unwrap(), 1536);
    }

    #[test]
    fn parsers_reject_empty_values() {
        assert!(parse_duration("").is_err());
        assert!(parse_bytes("").is_err());
    }

    #[test]
    fn configuration_requires_an_explicit_execution_policy() {
        let cli = Cli::try_parse_from(["shellvibe"]).unwrap();
        assert!(Config::try_from(cli).is_err());
    }
}
