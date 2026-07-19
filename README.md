<p align="center">
  <strong>Stronk Codex</strong>
</p>

<p align="center">
  A focused fork of <a href="https://github.com/openai/codex">OpenAI Codex CLI</a> for reliable multi-agent work, managed ChatGPT accounts, safer hooks, and resilient automation.
</p>

<p align="center">
  <a href="https://github.com/EYYCHEEV/codex/releases/latest">Latest fork release</a> ·
  <a href="https://developers.openai.com/codex">Upstream Codex docs</a> ·
  <a href="https://github.com/EYYCHEEV/codex/issues">Report an issue</a>
</p>

> [!IMPORTANT]
> Stronk Codex is an independent fork, not an official OpenAI distribution.
> The upstream installer, Homebrew cask, and `@openai/codex` npm package install upstream Codex, not this fork.

## Why this fork exists

Stronk Codex keeps the familiar Codex experience while preserving a small set of behavior needed by agent-heavy workstation workflows:

- observable and reliable multi-agent orchestration
- managed use of multiple ChatGPT accounts
- safer failure handling for `PreToolUse` hooks
- replay-safe WebSocket recovery and diagnostics
- stable JSONL, Model Context Protocol (MCP), app-server, and code-mode automation
- authenticated fork releases that ship the required binary pair together

If you only need standard Codex, use the [official OpenAI distribution](https://github.com/openai/codex).
Use Stronk Codex when the forked behavior below matters to your workflow.

## Install

Fork releases contain raw executables rather than an installer.
Install both binaries from the same release into the same directory:

- `codex` is the command-line interface.
- `codex-code-mode-host` is its required code-mode companion.

### macOS Apple Silicon

The simplest verified path uses the [GitHub CLI](https://cli.github.com/).
The commands download the latest release, verify the selected assets against `SHA256SUMS.txt`, and install the pair into `~/.local/bin`.

```zsh
download_dir="$(mktemp -d)"
install_dir="$HOME/.local/bin"

gh release download \
  --repo EYYCHEEV/codex \
  --dir "$download_dir" \
  --pattern 'codex-aarch64-apple-darwin' \
  --pattern 'codex-code-mode-host-aarch64-apple-darwin' \
  --pattern 'RELEASE_MANIFEST.json' \
  --pattern 'SHA256SUMS.txt'

(
  cd "$download_dir"
  grep -E \
    '  (RELEASE_MANIFEST\.json|codex-aarch64-apple-darwin|codex-code-mode-host-aarch64-apple-darwin)$' \
    SHA256SUMS.txt > selected-SHA256SUMS.txt
  test "$(wc -l < selected-SHA256SUMS.txt | tr -d ' ')" = 3
  shasum -a 256 -c selected-SHA256SUMS.txt
)

mkdir -p "$install_dir"
install -m 755 "$download_dir/codex-aarch64-apple-darwin" "$install_dir/codex"
install -m 755 \
  "$download_dir/codex-code-mode-host-aarch64-apple-darwin" \
  "$install_dir/codex-code-mode-host"

"$install_dir/codex" --version
```

Make sure `~/.local/bin` is on your `PATH`, or replace `install_dir` with a directory that already is.

For another platform, check the [latest release](https://github.com/EYYCHEEV/codex/releases/latest) and its `RELEASE_MANIFEST.json` first.
Linux artifacts are optional per release, and npm packages are not currently supported.
Never mix `codex` and `codex-code-mode-host` from different releases.

## Get started

Run the CLI and sign in with ChatGPT:

```zsh
codex
```

You can also use an API key through the standard [Codex authentication flow](https://developers.openai.com/codex/auth#sign-in-with-an-api-key).
Unless this README says otherwise, normal Codex commands and configuration follow the [upstream documentation](https://developers.openai.com/codex).

## Forked areas

| Area | What Stronk Codex adds or preserves | How you use it |
| --- | --- | --- |
| Multi-agent control | Parent-visible child MCP startup state, bounded waits, sampled `latest_status`, agent role metadata, and stable turn wakeups | Delegate normally. On a timed-out v1 `wait_agent`, inspect `latest_status` and `mcp_startup` before waiting again. |
| Managed ChatGPT accounts | Versioned account storage, sticky account selection, pre-output failover, account-bound transport state, and stale account-ID repair | Run `codex login` again to add accounts, `codex login status` to inspect them, and targeted logout commands to remove them. |
| WebSocket reliability | Bounded reconnects, safe HTTPS/Server-Sent Events fallback, no replay after durable delivery, and sanitized failure diagnostics | Recovery is automatic. Use `codex exec --websocket-diagnostic "your prompt"` for a read-only diagnostic turn with retries and fallback disabled. |
| MCP and automation | JSONL MCP startup events, lazy `codex_apps` startup, preserved tool namespace descriptions, goal capability mentions, and stable unified-exec output | Use `codex exec --json`; automation can consume `mcp.startup.update` and `mcp.startup.complete`. |
| Hooks and permissions | Opt-in fail-closed `PreToolUse` hooks and protection against reusing implicit permission grants without explicit preapproval | Set `onFailure` to `deny` on a `PreToolUse` command hook when a broken policy check must block the tool call. |
| Runtime and app server | Stack-safety guards, profile visibility, managed-network restoration, context-budget accounting, code-mode output-budget preservation, and rollout-path repair | These protections are automatic and keep long-running or integrated workflows stable. |
| Releases | Fork-boundary auditing, paired binaries, commit and SHA-256 provenance, isolated canaries, and exact release-asset reconciliation | Install and update only from fork releases, keep the pair together, and verify `SHA256SUMS.txt`. |

### Multiple ChatGPT accounts

```zsh
# Add another account.
codex login

# Show every managed account and its usage.
codex login status

# Remove one account or all accounts.
codex logout --account '<identity>'
codex logout --all
```

Each thread stays on one usable account.
The fork changes accounts only before output is committed and only for an authentication or quota failure that is safe to retry.

<details>
<summary><strong>Complete active fork contract map</strong></summary>

The public summary above groups these current fork-boundary contracts:

- Multi-agent control: `native-child-mcp-startup-parent-telemetry`, `v1-wait-agent-latest-status-bounded-waits`, `collab-agent-metadata`, `session-turn-multi-agent-lifecycle`
- Managed accounts and identity: `managed-chatgpt-multi-account-pool`, `managed-auth-account-repair`, `openai-auth-provider-identity`
- WebSocket transport: `responses-websocket-close-diagnostics`, `responses-websocket-sse-recovery`
- MCP, goals, and automation: `mcp-startup-jsonl-events`, `lazy-codex-apps-startup`, `responses-api-namespace-description-merge`, `goal-capability-mention-propagation`, `unified-exec-lifecycle`
- Hooks, permissions, and network state: `hook-runtime-tool-contract`, `exec-permission-preapproval-safety`, `managed-network-runtime`
- Runtime and app server: `app-server-stack-overflow-fixes`, `profile-config-api`, `remote-compaction-context-budget`, `code-mode-output-budget-preservation`, `rollout-state-db-path-repair`
- Release verification: `fork-release-pipeline`, `fork-integration-test-stability`

</details>

## How upgrades stay safe

Maintainers upgrade from an authenticated stable upstream `rust-vX.Y.Z` tag.
Before a fork release is published, the upgrade workflow:

1. audits every changed path against the fork-boundary contract
2. builds and tests `codex` with `codex-code-mode-host` from the same commit
3. runs fork-specific smoke tests and an isolated deployed-hook canary
4. verifies installed binary commits and SHA-256 digests
5. writes immutable upgrade, rollback, and publication evidence
6. requires a separate, content-addressed authorization before publishing

Unknown fork deltas and missing required contracts fail the release gate instead of being silently accepted.

## Compatibility and support

- Base Codex behavior follows upstream as closely as the active fork contracts allow.
- Upstream documentation is the reference for standard CLI, editor, app, configuration, and API behavior.
- Fork-specific installation and release issues belong in this repository's [issue tracker](https://github.com/EYYCHEEV/codex/issues).
- Upstream security guidance and the [Apache-2.0 license](LICENSE) still apply.

## Project links

- [Fork releases](https://github.com/EYYCHEEV/codex/releases)
- [Upstream Codex documentation](https://developers.openai.com/codex)
- [Contributing](./docs/contributing.md)
- [Security policy](./SECURITY.md)

Stronk Codex is based on [OpenAI Codex](https://github.com/openai/codex) and is licensed under the [Apache-2.0 License](LICENSE).
