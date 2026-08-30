# shellvibe

`Shellvibe` is a local stdio MCP server that exposes observable process execution, bounded output, process lifecycle controls, PTY sessions, and MCP Tasks.

```bash
cargo install shellvibe
```

```json
{
  "mcpServers": {
    "shellvibe": {
      "command": "shellvibe",
      "args": ["--deny-exec", "rm", "--deny-exec", "sudo"]
    }
  }
}
```
