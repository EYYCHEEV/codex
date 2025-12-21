# Configuration

For basic configuration instructions, see [this documentation](https://developers.openai.com/codex/config-basic).

For advanced configuration instructions, see [this documentation](https://developers.openai.com/codex/config-advanced).

For a full configuration reference, see [this documentation](https://developers.openai.com/codex/config-reference).

## Connecting to MCP servers

Codex can connect to MCP servers configured in `~/.codex/config.toml`. See the configuration reference for the latest MCP server options:

- https://developers.openai.com/codex/config-reference

## Apps (Connectors)

Use `$` in the composer to insert a ChatGPT connector; the popover lists accessible
apps. The `/apps` command lists available and installed apps. Connected apps appear first
and are labeled as connected; others are marked as can be installed.

## Notify

Codex can run a notification hook when the agent finishes a turn. See the configuration reference for the latest notification settings:

- https://developers.openai.com/codex/config-reference

## Hooks

Codex can run hooks before tool execution. Configure them in `~/.codex/config.toml`:

```toml
[[hooks.pre_tool_use]]
matcher = "shell*" # "*", "shell", "shell*", etc.
command = ["python3", "/Users/you/.codex/hooks/block-dangerous.py"]
timeout_sec = 5 # default: 5
on_failure = "deny" # default: "deny"; set "allow" for audit-only hooks
```

Notes:

- Use absolute paths in `command` (no `~` expansion).
- Hooks read JSON on stdin and write JSON on stdout. The `decision` can be `allow`, `deny`, or `ask` (treated as deny).

## JSON Schema

The generated JSON Schema for `config.toml` lives at `codex-rs/core/config.schema.json`.

## Notices

Codex stores "do not show again" flags for some UI prompts under the `[notice]` table.

Ctrl+C/Ctrl+D quitting uses a ~1 second double-press hint (`ctrl + c again to quit`).
