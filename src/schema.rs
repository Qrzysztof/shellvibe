use std::sync::Arc;

use rmcp::model::{JsonObject, Tool, ToolAnnotations};
use serde_json::{Value, json};

use crate::{
    model::{
        MAX_ARG_BYTES, MAX_ARGV_ITEMS, MAX_COMMAND_BYTES, MAX_ENV_ITEMS, MAX_PATH_BYTES,
        MAX_STDIN_BYTES,
    },
    policy::ExecPolicy,
};

pub fn tools(policy: &ExecPolicy) -> Vec<Tool> {
    vec![
        shell_tool(policy),
        read_tool(),
        write_tool(),
        signal_tool(),
        resize_tool(),
    ]
}

pub fn get_tool(policy: &ExecPolicy, name: &str) -> Option<Tool> {
    match name {
        "shell" => Some(shell_tool(policy)),
        "shell_read" => Some(read_tool()),
        "shell_write" => Some(write_tool()),
        "shell_signal" => Some(signal_tool()),
        "shell_resize" => Some(resize_tool()),
        _ => None,
    }
}

fn shell_tool(policy: &ExecPolicy) -> Tool {
    let (description, primary) = if policy.is_restricted() {
        (
            "Execute one permitted top-level program directly without a shell interpreter. Pass argv with the executable as argv[0]. Shell operators (|, &&, redirects, globbing, command substitution) are unavailable. foreground is the default and asks for the final result; a long foreground command transparently becomes an MCP Task on MCP 2026-07-28 when the client declares Tasks, otherwise it yields a processId fallback. background returns a processId immediately. interactive allocates a PTY and returns a processId. The executable policy is a top-level guardrail, not an OS sandbox.",
            json!({
                "argv": {
                    "type": "array",
                    "minItems": 1,
                    "maxItems": MAX_ARGV_ITEMS,
                    "items": {"type": "string", "maxLength": MAX_ARG_BYTES},
                    "description": "Executable and arguments. argv[0] is resolved and checked against the startup policy."
                }
            }),
        )
    } else {
        (
            "Execute an unrestricted shell command with the permissions of the user running shellvibe. foreground is the default and asks for the final result; a long foreground command transparently becomes an MCP Task when the client supports Tasks, otherwise it yields a processId fallback. background returns a processId immediately. interactive allocates a PTY and returns a processId for shell_read/shell_write/shell_signal/shell_resize.",
            json!({
                "command": {
                    "type": "string",
                    "minLength": 1,
                    "maxLength": MAX_COMMAND_BYTES,
                    "description": "Command passed to the configured shell using -c (or cmd.exe /C on Windows)."
                }
            }),
        )
    };

    let mut properties = primary
        .as_object()
        .expect("primary schema must be object")
        .clone();
    properties.extend(common_shell_properties());
    let required = if policy.is_restricted() {
        json!(["argv"])
    } else {
        json!(["command"])
    };

    let schema = json!({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "type": "object",
        "additionalProperties": false,
        "required": required,
        "properties": properties
    });

    Tool::new("shell", description, arc_object(schema))
        .with_title("Run shell process")
        .with_raw_output_schema(arc_object(tool_output_schema()))
        .with_annotations(
            ToolAnnotations::new()
                .read_only(false)
                .destructive(true)
                .idempotent(false)
                .open_world(true),
        )
}

fn common_shell_properties() -> JsonObject {
    serde_json::from_value(json!({
        "cwd": {"type": "string", "maxLength": MAX_PATH_BYTES, "description": "Working directory for this process."},
        "env": {
            "type": "object",
            "maxProperties": MAX_ENV_ITEMS,
            "propertyNames": {"minLength": 1, "pattern": "^[^=]+$"},
            "additionalProperties": {"type": "string", "maxLength": MAX_STDIN_BYTES},
            "description": "Environment variables added or overridden for the child process. Top-level executable policy resolution uses shellvibe's own startup PATH."
        },
        "stdin": {"type": "string", "maxLength": MAX_STDIN_BYTES, "description": "Optional UTF-8 input written immediately after spawn."},
        "execution": {
            "type": "string",
            "enum": ["foreground", "background", "interactive"],
            "default": "foreground",
            "description": "foreground asks for the final result and may transparently use MCP Tasks; background returns a process handle; interactive forces a PTY and returns a process handle."
        },
        "pty": {"type": "boolean", "default": false, "description": "Allocate a pseudo-terminal. interactive mode always enables PTY."},
        "yieldMs": {"type": "integer", "minimum": 1, "description": "Override the foreground grace period before a long command becomes a Task or process-handle fallback."},
        "timeoutMs": {"type": "integer", "minimum": 1, "description": "Optional per-call runtime limit. Values above the server --max-runtime ceiling are clamped."},
        "rows": {"type": "integer", "minimum": 1, "maximum": 1000, "default": 24, "description": "Initial PTY rows."},
        "cols": {"type": "integer", "minimum": 1, "maximum": 2000, "default": 80, "description": "Initial PTY columns."}
    })).expect("common schema is an object")
}

fn read_tool() -> Tool {
    Tool::new(
        "shell_read",
        "Read retained output from a process using a monotonic cursor. If no new output exists and the process is still running, wait up to waitMs. nextCursor is the cursor to pass on the next call; hasMore means another immediate read is useful.",
        arc_object(json!({
            "$schema": "https://json-schema.org/draft/2020-12/schema",
            "type": "object",
            "additionalProperties": false,
            "required": ["processId"],
            "properties": {
                "processId": {"type": "string", "pattern": "^p_[0-9a-f]{32}$"},
                "cursor": {"type": "integer", "minimum": 0, "default": 0},
                "waitMs": {"type": "integer", "minimum": 0, "default": 0}
            }
        })),
    )
    .with_title("Read process output")
    .with_raw_output_schema(arc_object(tool_output_schema()))
    .with_annotations(
        ToolAnnotations::new()
            .read_only(true)
            .destructive(false)
            .idempotent(true)
            .open_world(false),
    )
}

fn write_tool() -> Tool {
    Tool::new(
        "shell_write",
        "Write UTF-8 input to a running process stdin/PTY and optionally close stdin to deliver EOF. Use terminal input here; do not use MCP MRTR to guess arbitrary terminal prompts.",
        arc_object(json!({
            "$schema": "https://json-schema.org/draft/2020-12/schema",
            "type": "object",
            "additionalProperties": false,
            "required": ["processId"],
            "properties": {
                "processId": {"type": "string", "pattern": "^p_[0-9a-f]{32}$"},
                "data": {"type": "string", "maxLength": MAX_STDIN_BYTES},
                "appendNewline": {"type": "boolean", "default": false},
                "closeStdin": {"type": "boolean", "default": false, "description": "Drop the stdin/PTY writer after any data is written, delivering EOF where supported."}
            },
            "anyOf": [
                {"required": ["data"]},
                {"properties": {"closeStdin": {"const": true}}, "required": ["closeStdin"]}
            ]
        })),
    )
    .with_title("Write process input")
    .with_raw_output_schema(arc_object(tool_output_schema()))
    .with_annotations(
        ToolAnnotations::new()
            .read_only(false)
            .destructive(true)
            .idempotent(false)
            .open_world(false),
    )
}

fn signal_tool() -> Tool {
    Tool::new(
        "shell_signal",
        "Send INT, TERM, or KILL to the managed process tree. On Unix these map to POSIX signals. On Windows INT/TERM request non-forced tree termination via taskkill and KILL requests forced termination. shellvibe uses TERM followed by KILL escalation for server-managed cancellation/timeouts.",
        arc_object(json!({
            "$schema": "https://json-schema.org/draft/2020-12/schema",
            "type": "object",
            "additionalProperties": false,
            "required": ["processId", "signal"],
            "properties": {
                "processId": {"type": "string", "pattern": "^p_[0-9a-f]{32}$"},
                "signal": {"type": "string", "enum": ["int", "term", "kill"]}
            }
        })),
    )
    .with_title("Signal process")
    .with_raw_output_schema(arc_object(tool_output_schema()))
    .with_annotations(
        ToolAnnotations::new()
            .read_only(false)
            .destructive(true)
            .idempotent(false)
            .open_world(false),
    )
}

fn resize_tool() -> Tool {
    Tool::new(
        "shell_resize",
        "Resize a running PTY. This updates the kernel terminal size and lets terminal-aware programs react to the resize.",
        arc_object(json!({
            "$schema": "https://json-schema.org/draft/2020-12/schema",
            "type": "object",
            "additionalProperties": false,
            "required": ["processId", "rows", "cols"],
            "properties": {
                "processId": {"type": "string", "pattern": "^p_[0-9a-f]{32}$"},
                "rows": {"type": "integer", "minimum": 1, "maximum": 1000},
                "cols": {"type": "integer", "minimum": 1, "maximum": 2000}
            }
        })),
    )
    .with_title("Resize PTY")
    .with_raw_output_schema(arc_object(tool_output_schema()))
    .with_annotations(
        ToolAnnotations::new()
            .read_only(false)
            .destructive(false)
            .idempotent(true)
            .open_world(false),
    )
}

fn tool_output_schema() -> Value {
    json!({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "oneOf": [
            process_snapshot_schema(),
            {
                "type": "object",
                "additionalProperties": false,
                "required": ["error", "message"],
                "properties": {
                    "error": {"const": "shellvibe_error"},
                    "message": {"type": "string"}
                }
            }
        ]
    })
}

fn process_snapshot_schema() -> Value {
    json!({
        "type": "object",
        "additionalProperties": false,
        "required": ["processId", "status", "pid", "mode", "execution", "pty", "commandTruncated", "argvTruncated", "cwd", "events", "nextCursor", "hasMore", "cursorLost", "elapsedMs", "idleMs", "truncated", "droppedBytes", "message"],
        "properties": {
            "processId": {"type": "string", "pattern": "^p_[0-9a-f]{32}$"},
            "status": {"type": "string", "enum": ["running", "exited", "signaled", "timed_out", "cancelled", "failed"]},
            "pid": {"type": ["integer", "null"], "minimum": 0},
            "mode": {"type": "string", "enum": ["shell", "direct"]},
            "execution": {"type": "string", "enum": ["foreground", "background", "interactive"]},
            "pty": {"type": "boolean"},
            "rows": {"type": "integer", "minimum": 1},
            "cols": {"type": "integer", "minimum": 1},
            "command": {"type": "string", "description": "Bounded diagnostic echo of the shell command."},
            "commandTruncated": {"type": "boolean"},
            "argv": {"type": "array", "items": {"type": "string"}, "description": "Bounded diagnostic echo of direct-execution arguments."},
            "argvTruncated": {"type": "boolean"},
            "cwd": {"type": "string"},
            "exitCode": {"type": "integer"},
            "signal": {"type": "string"},
            "events": {
                "type": "array",
                "items": {
                    "type": "object",
                    "additionalProperties": false,
                    "required": ["cursor", "stream", "data", "atMs"],
                    "properties": {
                        "cursor": {"type": "integer", "minimum": 1},
                        "stream": {"type": "string", "enum": ["stdout", "stderr", "pty"]},
                        "data": {"type": "string"},
                        "atMs": {"type": "integer", "minimum": 0}
                    }
                }
            },
            "nextCursor": {"type": "integer", "minimum": 0},
            "hasMore": {"type": "boolean"},
            "cursorLost": {"type": "boolean"},
            "elapsedMs": {"type": "integer", "minimum": 0},
            "idleMs": {"type": "integer", "minimum": 0},
            "truncated": {"type": "boolean"},
            "droppedBytes": {"type": "integer", "minimum": 0},
            "message": {"type": "string"}
        }
    })
}

fn arc_object(value: Value) -> Arc<JsonObject> {
    Arc::new(
        value
            .as_object()
            .expect("schema must be a JSON object")
            .clone(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unrestricted_schema_exposes_command_not_argv() {
        let tool = shell_tool(&ExecPolicy::Unrestricted);
        let properties = tool
            .input_schema
            .get("properties")
            .unwrap()
            .as_object()
            .unwrap();
        assert!(properties.contains_key("command"));
        assert!(!properties.contains_key("argv"));
    }

    #[test]
    fn restricted_schema_exposes_argv_not_command() {
        let policy = ExecPolicy::Deny {
            names: Default::default(),
            paths: Default::default(),
        };
        let tool = shell_tool(&policy);
        let properties = tool
            .input_schema
            .get("properties")
            .unwrap()
            .as_object()
            .unwrap();
        assert!(properties.contains_key("argv"));
        assert!(!properties.contains_key("command"));
    }
}
