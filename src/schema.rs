use std::sync::Arc;

use rmcp::model::{JsonObject, Tool, ToolAnnotations};
use serde_json::{Value, json};

use crate::{
    model::{
        MAX_ARG_BYTES, MAX_ARGV_ITEMS, MAX_COMMAND_BYTES, MAX_ENV_ITEMS, MAX_PATH_BYTES,
        MAX_STDIN_BYTES, MIN_READ_PAGE_BYTES,
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
                    "items": {"type": "string", "minLength": 1, "maxLength": MAX_ARG_BYTES},
                    "description": "Executable and arguments. argv[0] is resolved and checked against the startup policy. Runtime size limits are authoritative and count UTF-8 bytes, while JSON Schema maxLength counts characters."
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
                    "description": "Non-whitespace command passed to the configured shell using -c (or cmd.exe /C on Windows). Runtime size limits are authoritative and count UTF-8 bytes, while JSON Schema maxLength counts characters."
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
        .with_raw_output_schema(arc_object(tool_output_schema(shell_result_schema())))
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
        "cwd": {"type": "string", "maxLength": MAX_PATH_BYTES, "description": "Working directory for this process. The runtime limit counts UTF-8 bytes; JSON Schema maxLength counts characters."},
        "env": {
            "type": "object",
            "maxProperties": MAX_ENV_ITEMS,
            "propertyNames": {"minLength": 1, "pattern": "^[^=\\u0000]+$"},
            "additionalProperties": {"type": "string", "maxLength": MAX_STDIN_BYTES},
            "description": "Environment variables added or overridden for the child process. Runtime aggregate size limits count UTF-8 bytes; JSON Schema maxLength counts characters. Top-level executable policy resolution uses shellvibe's own startup PATH."
        },
        "stdin": {"type": "string", "maxLength": MAX_STDIN_BYTES, "description": "Optional UTF-8 input written immediately after spawn. The runtime limit counts UTF-8 bytes; JSON Schema maxLength counts characters."},
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
        "Canonical paginated output retrieval for a managed process. Returns retained output events after cursor. waitMs is only the maximum long-poll duration: a read returns on new output, terminal process state, or timeout. nextCursor is an output-event cursor for the next read, not a byte or line offset. hasMore=false means no additional buffered page is currently available; it does not imply that the process exited. cursorLost=true means output history requested by cursor was evicted.",
        arc_object(json!({
            "$schema": "https://json-schema.org/draft/2020-12/schema",
            "type": "object",
            "additionalProperties": false,
            "required": ["processId"],
            "properties": {
                "processId": {"type": "string", "pattern": "^p_[0-9a-f]{32}$"},
                "cursor": {"type": "integer", "minimum": 0, "default": 0, "description": "Output-event cursor returned as nextCursor by the previous read; not a byte or line offset."},
                "waitMs": {"type": "integer", "minimum": 0, "default": 0, "description": "Maximum long-poll duration only. The read returns earlier for new output or terminal process state; the server caps this value."},
                "maxBytes": {"type": "integer", "minimum": MIN_READ_PAGE_BYTES, "description": "Maximum output event-data bytes requested for this page. The server caps this value at its configured response maximum."}
            }
        })),
    )
    .with_title("Read process output")
    .with_raw_output_schema(arc_object(tool_output_schema(read_result_schema())))
    .with_annotations(
        ToolAnnotations::new()
            .read_only(true)
            .destructive(false)
            .idempotent(true)
            .open_world(true),
    )
}

fn write_tool() -> Tool {
    Tool::new(
        "shell_write",
        "Send UTF-8 input to a running process stdin/PTY and optionally close stdin to deliver EOF. This returns an acknowledgement and does not wait for resulting output; use shell_read to observe output.",
        arc_object(json!({
            "$schema": "https://json-schema.org/draft/2020-12/schema",
            "type": "object",
            "additionalProperties": false,
            "required": ["processId"],
            "properties": {
                "processId": {"type": "string", "pattern": "^p_[0-9a-f]{32}$"},
                "data": {"type": "string", "maxLength": MAX_STDIN_BYTES, "description": "Runtime size validation counts UTF-8 bytes, including an appended newline; JSON Schema maxLength counts characters."},
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
    .with_raw_output_schema(arc_object(tool_output_schema(write_result_schema())))
    .with_annotations(
        ToolAnnotations::new()
            .read_only(false)
            .destructive(true)
            .idempotent(false)
            .open_world(true),
    )
}

fn signal_tool() -> Tool {
    Tool::new(
        "shell_signal",
        "Send INT, TERM, or KILL to the managed process tree. The acknowledgement confirms the request was sent, not that the process has exited; use shell_read with waitMs to observe terminal state.",
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
    .with_raw_output_schema(arc_object(tool_output_schema(signal_result_schema())))
    .with_annotations(
        ToolAnnotations::new()
            .read_only(false)
            .destructive(true)
            .idempotent(false)
            .open_world(true),
    )
}

fn resize_tool() -> Tool {
    Tool::new(
        "shell_resize",
        "Resize a running PTY. This returns only the new dimensions and current status; accumulated terminal output remains available through shell_read.",
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
    .with_raw_output_schema(arc_object(tool_output_schema(resize_result_schema())))
    .with_annotations(
        ToolAnnotations::new()
            .read_only(false)
            .destructive(false)
            .idempotent(true)
            .open_world(true),
    )
}

fn tool_output_schema(success: Value) -> Value {
    json!({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "oneOf": [
            success,
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

fn shell_result_schema() -> Value {
    json!({
        "type": "object",
        "additionalProperties": false,
        "required": ["processId", "status", "pty", "nextCursor"],
        "properties": {
            "processId": {"type": "string", "pattern": "^p_[0-9a-f]{32}$"},
            "status": {"type": "string", "enum": ["running", "exited", "signaled", "timed_out", "cancelled", "failed"]},
            "pid": {"type": "integer", "minimum": 0},
            "pty": {"type": "boolean"},
            "rows": {"type": "integer", "minimum": 1},
            "cols": {"type": "integer", "minimum": 1},
            "exitCode": {"type": "integer"},
            "signal": {"type": "string"},
            "elapsedMs": {"type": "integer", "minimum": 0, "description": "Total process lifetime in milliseconds, not tool-call or read latency."},
            "output": {"type": "string", "description": "Bounded ordered output tail present for direct foreground completions and completed MCP Task results."},
            "outputTruncated": {"type": "boolean", "description": "Whether completion output was truncated. When true, retained output can be retrieved with shell_read(cursor=0) while the process handle remains available."},
            "nextCursor": {"type": "integer", "minimum": 0, "description": "Output-event cursor following output represented by this result, not a byte or line offset. Handle-only running results use 0 because they contain no output; read from cursor 0 to retrieve retained output."}
        }
    })
}

fn read_result_schema() -> Value {
    json!({
        "type": "object",
        "additionalProperties": false,
        "required": ["processId", "status", "events", "nextCursor", "hasMore", "cursorLost"],
        "properties": {
            "processId": {"type": "string", "pattern": "^p_[0-9a-f]{32}$"},
            "status": {"type": "string", "enum": ["running", "exited", "signaled", "timed_out", "cancelled", "failed"]},
            "events": {
                "type": "array",
                "items": {
                    "type": "object",
                    "additionalProperties": false,
                    "required": ["cursor", "stream", "data"],
                    "properties": {
                        "cursor": {"type": "integer", "minimum": 1},
                        "stream": {"type": "string", "enum": ["stdout", "stderr", "pty"]},
                        "data": {"type": "string"}
                    }
                }
            },
            "nextCursor": {"type": "integer", "minimum": 0, "description": "Output-event cursor to pass to the next read; not a byte or line offset."},
            "hasMore": {"type": "boolean", "description": "Whether another buffered page is immediately available. false does not imply that the process exited."},
            "cursorLost": {"type": "boolean", "description": "true when output history requested by cursor was evicted from retention."},
            "exitCode": {"type": "integer"},
            "signal": {"type": "string"},
            "elapsedMs": {"type": "integer", "minimum": 0, "description": "Total process lifetime in milliseconds, not shell_read latency."}
        }
    })
}

fn write_result_schema() -> Value {
    json!({
        "type": "object",
        "additionalProperties": false,
        "required": ["processId", "acceptedBytes", "stdinClosed", "status"],
        "properties": {
            "processId": {"type": "string", "pattern": "^p_[0-9a-f]{32}$"},
            "acceptedBytes": {"type": "integer", "minimum": 0},
            "stdinClosed": {"type": "boolean"},
            "status": {"type": "string", "enum": ["running", "exited", "signaled", "timed_out", "cancelled", "failed"]}
        }
    })
}

fn signal_result_schema() -> Value {
    json!({
        "type": "object",
        "additionalProperties": false,
        "required": ["processId", "signal", "accepted", "status"],
        "properties": {
            "processId": {"type": "string", "pattern": "^p_[0-9a-f]{32}$"},
            "signal": {"type": "string", "enum": ["int", "term", "kill"]},
            "accepted": {"type": "boolean"},
            "status": {"type": "string", "enum": ["running", "exited", "signaled", "timed_out", "cancelled", "failed"]}
        }
    })
}

fn resize_result_schema() -> Value {
    json!({
        "type": "object",
        "additionalProperties": false,
        "required": ["processId", "rows", "cols", "status"],
        "properties": {
            "processId": {"type": "string", "pattern": "^p_[0-9a-f]{32}$"},
            "rows": {"type": "integer", "minimum": 1, "maximum": 1000},
            "cols": {"type": "integer", "minimum": 1, "maximum": 2000},
            "status": {"type": "string", "enum": ["running", "exited", "signaled", "timed_out", "cancelled", "failed"]}
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
        assert_eq!(properties["argv"]["items"]["minLength"], json!(1));
        assert!(
            properties["argv"]["description"]
                .as_str()
                .unwrap()
                .contains("UTF-8 bytes")
        );
    }

    #[test]
    fn read_schema_exposes_bounded_page_controls_and_cursor_semantics() {
        let tool = read_tool();
        let properties = tool
            .input_schema
            .get("properties")
            .unwrap()
            .as_object()
            .unwrap();
        assert_eq!(
            properties["maxBytes"]["minimum"],
            json!(MIN_READ_PAGE_BYTES)
        );
        assert!(
            properties["waitMs"]["description"]
                .as_str()
                .unwrap()
                .contains("Maximum long-poll duration only")
        );

        let output = tool.output_schema.unwrap();
        let success = &output["oneOf"][0];
        assert!(
            success["properties"]["hasMore"]["description"]
                .as_str()
                .unwrap()
                .contains("does not imply")
        );
        assert!(
            success["properties"]["cursorLost"]["description"]
                .as_str()
                .unwrap()
                .contains("evicted")
        );
    }

    #[test]
    fn process_tools_are_annotated_as_open_world() {
        for tool in [read_tool(), write_tool(), signal_tool(), resize_tool()] {
            assert_eq!(tool.annotations.unwrap().open_world_hint, Some(true));
        }
    }

    #[test]
    fn schema_describes_runtime_byte_validation_without_custom_keywords() {
        let tool = shell_tool(&ExecPolicy::Unrestricted);
        let command = &tool.input_schema["properties"]["command"];
        assert_eq!(command["maxLength"], json!(MAX_COMMAND_BYTES));
        assert!(
            command["description"]
                .as_str()
                .unwrap()
                .contains("UTF-8 bytes")
        );
        assert!(command.get("maxByteLength").is_none());

        let common = common_shell_properties();
        assert_eq!(
            common["env"]["propertyNames"]["pattern"],
            json!("^[^=\\u0000]+$")
        );
    }
}
