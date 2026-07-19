<h1 align="center">Stronk Codex</h1>

<p align="center">
  <strong>Codex without the orchestration dead ends.</strong>
</p>

<p align="center">
  Automatic multi-account management · Observable subagents · Fail-closed safety hooks · Replay-safe WebSocket recovery
</p>

<p align="center">
  <a href="https://github.com/EYYCHEEV/codex/releases/latest">Download</a> ·
  <a href="https://developers.openai.com/codex">Codex docs</a> ·
  <a href="https://github.com/EYYCHEEV/codex/issues">Issues</a>
</p>

Stronk Codex is a focused fork of [OpenAI Codex CLI](https://github.com/openai/codex) for people who rely on agents all day.
It addresses the failures that hurt most in long-running work: a subagent that looks frozen during Model Context Protocol (MCP) startup, a safety hook that fails open, a WebSocket that drops at the wrong moment, or another manual account shuffle when quota runs out.

## What stops being your problem

### Multiple ChatGPT accounts, managed automatically

Sign in to each account once.
Stronk Codex keeps them in one local pool, selects a usable account automatically, keeps each thread on one identity, and performs safe failover only before output is committed.
Normal use no longer requires a logout/login rotation dance.

```zsh
# Repeat once for each account you want in the pool.
codex login

# See every account, current selection, and usage.
codex login status
```

Credentials stay inside Codex's configured local authentication storage: the operating-system keyring or encrypted local storage where configured, with the standard `CODEX_HOME/auth.json` file mode still supported.
The fork adds no hosted account broker and remains compatible with API keys, external ChatGPT authentication, and upstream account flows.

### Subagents that do not disappear into startup silence

The parent can see each child's live MCP startup state, including the server that is starting, ready, or failed.
The stable v1 wait path is bounded to three minutes and exposes sampled `latest_status` plus `mcp_startup`, so an MCP stall is visible instead of looking like an endless model loop.

### Safety hooks that can actually fail closed

`PreToolUse` command hooks support opt-in `onFailure = "deny"` behavior.
If a required policy hook crashes or returns an invalid decision, the tool call is blocked rather than silently allowed.

### WebSocket recovery without accidental replay

Sampling turns use bounded reconnects and safe HTTPS/Server-Sent Events fallback before output.
After durable output or tool delivery, Stronk Codex does not replay the turn.
For hard failures, `codex exec --websocket-diagnostic "your prompt"` produces a bounded, sanitized diagnostic.

## Install

Fork releases contain a matched `codex` and `codex-code-mode-host` pair.
Keep both executables from the same release in the same directory.

### macOS Apple Silicon

Using the [GitHub CLI](https://cli.github.com/):

```zsh
release_dir="$(mktemp -d)"
install_dir="$HOME/.local/bin"

gh release download \
  --repo EYYCHEEV/codex \
  --dir "$release_dir" \
  --pattern 'codex-aarch64-apple-darwin' \
  --pattern 'codex-code-mode-host-aarch64-apple-darwin' \
  --pattern 'SHA256SUMS.txt'

(
  cd "$release_dir"
  grep 'aarch64-apple-darwin$' SHA256SUMS.txt > selected-SHA256SUMS.txt
  test "$(wc -l < selected-SHA256SUMS.txt | tr -d ' ')" = 2
  shasum -a 256 -c selected-SHA256SUMS.txt
)

mkdir -p "$install_dir"
install -m 755 "$release_dir/codex-aarch64-apple-darwin" "$install_dir/codex"
install -m 755 \
  "$release_dir/codex-code-mode-host-aarch64-apple-darwin" \
  "$install_dir/codex-code-mode-host"

"$install_dir/codex" --version
```

Make sure `~/.local/bin` is on your `PATH`, or use a directory that already is.
Check the [latest release](https://github.com/EYYCHEEV/codex/releases/latest) for other targets and its `RELEASE_MANIFEST.json` for exact provenance.
Linux assets are optional per release; npm and Homebrew install upstream Codex, not this fork.

## More forked reliability

- `codex exec --json` emits `mcp.startup.update` and `mcp.startup.complete` for automation.
- Host-owned `codex_apps` starts lazily instead of blocking normal startup.
- App-server, unified-exec, code-mode output, remote compaction, managed network state, and rollout lookup have fork-specific stability guards.
- Skills, plugins, and app mentions survive trusted goal continuations.
- Every release audits the fork boundary, tests both binaries from one commit, verifies SHA-256 provenance, and runs isolated canaries before publication.

<details>
<summary><strong>Exact active fork contract map</strong></summary>

- Multi-agent control: `native-child-mcp-startup-parent-telemetry`, `v1-wait-agent-latest-status-bounded-waits`, `collab-agent-metadata`, `session-turn-multi-agent-lifecycle`
- Accounts and identity: `managed-chatgpt-multi-account-pool`, `managed-auth-account-repair`, `openai-auth-provider-identity`
- WebSocket transport: `responses-websocket-close-diagnostics`, `responses-websocket-sse-recovery`
- MCP, goals, and automation: `mcp-startup-jsonl-events`, `lazy-codex-apps-startup`, `responses-api-namespace-description-merge`, `goal-capability-mention-propagation`, `unified-exec-lifecycle`
- Hooks, permissions, and network state: `hook-runtime-tool-contract`, `exec-permission-preapproval-safety`, `managed-network-runtime`
- Runtime and app server: `app-server-stack-overflow-fixes`, `profile-config-api`, `remote-compaction-context-budget`, `code-mode-output-budget-preservation`, `rollout-state-db-path-repair`
- Release verification: `fork-release-pipeline`, `fork-integration-test-stability`

</details>

## Upstream alignment

Standard Codex commands, configuration, authentication choices, and editor integrations continue to follow the [upstream documentation](https://developers.openai.com/codex).
Fork releases are rebased onto authenticated stable upstream tags and fail their release gate if a required fork contract disappears or an unknown delta is introduced.

Stronk Codex is an independent distribution based on [OpenAI Codex](https://github.com/openai/codex), licensed under [Apache-2.0](LICENSE), and supported through this repository's [issue tracker](https://github.com/EYYCHEEV/codex/issues).
