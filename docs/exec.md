# Non-interactive mode

For information about non-interactive mode, see [this documentation](https://developers.openai.com/codex/noninteractive).

## Diagnosing Responses WebSocket disconnects

Use `codex exec --websocket-diagnostic "Reply with exactly: ok"` to run one read-only turn with request retries, stream retries, and HTTPS fallback disabled.
The command requires a WebSocket-capable model provider and cannot be combined with ephemeral or unrestricted sandbox modes.

If the server closes the stream before `response.completed`, Codex stores a bounded typed envelope named `responses_websocket_close_diagnostic` in that session's rollout JSONL.
The payload includes sanitized close details, thread/turn/session/model identifiers, a shortened account fingerprint, account and selection revisions, handshake and request binding fingerprints, whether the connection was reused, whether output had already committed, and the selected recovery decision.
Successful WebSocket turns do not add this diagnostic payload.
