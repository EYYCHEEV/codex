# Codex ChatGPT Multi-Account Pool

## Objective

Implement managed ChatGPT OAuth multi-account support across Codex CLI, login/auth storage, request routing, app-server protocol, and TUI status.
Repeated browser or device-code login must add or update one account without revoking unrelated accounts.
Logout must target one account when several are stored.
Status must list every stored ChatGPT account and its usage windows.
Requests must select a usable account, remain thread-sticky while healthy, and rotate safely when the account is exhausted or invalid.

## Scope

- Managed ChatGPT OAuth credentials stored by Codex.
- Browser and device-code login.
- File, keyring, auto, and ephemeral auth storage behavior.
- CLI `codex login`, `codex login status`, and `codex logout`.
- Login/auth manager account selection, refresh, mutation serialization, and legacy migration.
- Core/model-provider request auth, HTTP/SSE/WebSocket account binding, rate-limit state, and replay-safe failover.
- App-server account, login, logout, status, usage, notifications, and generated protocol bindings.
- TUI `/status` account and usage presentation.

Out of scope:

- Pooling API keys, personal access tokens, Agent Identity credentials, Amazon Bedrock credentials, or externally managed ChatGPT auth.
- Remote auth-broker functionality.
- Commit, push, release, or installation workflows.

## Confirmed Product Contract

- Account identity uses normalized email first and ChatGPT account ID as fallback; request headers always use the selected token's `chatgpt_account_id`.
- Re-login of the same identity replaces that account's tokens only; siblings remain stored.
- Thread-scoped requests deterministically choose among healthy accounts and stay pinned until rotation is required.
- Definitive account quota/auth failures may rotate to a sibling only before replay-unsafe output is emitted.
- Generic transient throttling or server errors do not mark an account exhausted.
- One-account interactive logout removes it directly.
- Multi-account interactive logout presents a picker.
- Non-interactive logout supports explicit `--account <identity>` and `--all`; ambiguous non-interactive logout fails with guidance.
- CLI and TUI status show all accounts, active/thread selection where meaningful, plan, 5-hour and weekly/additional windows, reset time, and stale/unavailable usage labels.
- Unknown usage is not treated as exhausted.

## Structural Design

### Ownership and deep modules

The `codex-login` crate owns one deep managed-ChatGPT account-pool module behind `AuthManager`.
It is the only owner of persisted membership, identity deduplication, selected-account refresh replacement, mutation serialization, deterministic thread selection, account cooldowns, usage-cache persistence, and legacy single-account migration.
The pool does not fetch network usage itself: dependency direction prevents `codex-login` from depending on the backend/client layers.
App-server keeps its existing backend-client usage adapter, CLI adds a direct `codex-backend-client` adapter for `login status`, and core submits only response-derived rate windows and classified failures; all map into neutral account-keyed pool snapshots.
API keys, external ChatGPT tokens, Agent Identity, Personal Access Tokens, Bedrock, and realtime API-key auth remain non-pooled compatibility paths with unchanged precedence.

### Persistence contract

Add `managed_chatgpt: { version: 1, accounts: [...] }` to `AuthDotJson` without removing schema support for non-ChatGPT auth variants.
Each account entry stores immutable `identity_key`, identity aliases, normalized email, raw `chatgpt_account_id`, `TokenData`, account revision, last refresh, OAuth-derived API key, account-specific Agent Identity record, optional persisted refresh lease, optional persisted block, and optional observed-at neutral usage snapshot.
New identity keys are namespaced (`email:<normalized>` when email exists, otherwise `account:<raw-id>`); request headers and workspace checks continue to use the raw selected account ID.
New OAuth upsert rejects credentials where both normalized email and raw account ID are absent before any write.
Upsert normalizes email by trim plus Unicode-insensitive lowercase and retains a matched row's immutable key.
When incoming email exists, match the same normalized email first and merge only fallback-only rows with the same raw account ID; a different non-empty email remains a distinct identity even when the raw account ID matches.
When incoming email is absent, use raw account ID only when it identifies one row; an ambiguous raw-ID match fails without writing.
Incoming OAuth tokens increment account revision and clear refresh leases plus auth-invalid blocks; same-raw-account relogin rebinds quota/usage metadata to the new credential revision, while a raw account ID change clears quota, usage, and Agent Identity metadata.
Legacy singular ChatGPT fields migrate transactionally and clear on canonical write; an unidentifiable token set receives one persisted random `legacy:<opaque-id>` key.
An identifiable login always adds its own row and never absorbs opaque legacy credentials; only a refresh of that exact legacy row under expected revision/token may upgrade its key when refreshed claims supply identity.
Legacy `last_refresh`, `agent_identity`, and OAuth-derived top-level `OPENAI_API_KEY` move into the row, while top-level `OPENAI_API_KEY` remains unchanged for actual API-key auth.
Preserve mode-transition behavior: the first managed login replaces active API-key/PAT/standalone-AgentIdentity/Bedrock file auth as today's login does, any of those non-pooled logins replaces the managed pool, and removing the last managed account leaves no dormant fallback credential.
All file, direct-keyring, secrets-keyring, auto, and ephemeral mutations pass through one object-safe storage mutation seam that locks, reloads, compares the expected account revision and refresh token, and saves the complete result.
Persistent modes share a `CODEX_HOME` cross-process lock; file writes use an fsynced same-directory temporary plus atomic rename, keyring writes occur under the same lock, and auto mode must never leave a stale successful keyring value shadowing a newer file fallback.
Rotating refresh acquires a durable per-account mutation lease under that lock before the network call; peers and same-identity upserts wait/reload instead of replaying a single-use refresh token, and the lease owner commits by expected revision/token after the call or releases/expires the lease on failure.
Targeted logout waits for any active lease, reloads and tombstones the latest account revision/token under lock, revokes that latest token, then commits removal; refresh cannot resurrect a tombstoned row, and overlapping upsert linearizes before or after the removal lease.
The tombstone stores operation ID plus latest credential revision/token, is permanently non-selectable, and never expires back to active; the next manager load/mutation resumes idempotent best-effort revoke and final deletion so crashes before or after revoke cannot strand or resurrect the row.
Ephemeral mode remains process-local but uses the same mutation semantics.
Managed-pool loading preserves current environment/external-auth precedence and never reads through or overwrites externally supplied ephemeral ChatGPT auth.
App-server external ChatGPT auth remains an ephemeral overlay: unscoped logout clears only that overlay and reloads the persistent managed pool, while targeted managed operations never mutate the overlay or let the old global logout path delete hidden pool rows.
Forced-workspace policy validates every incoming or identity-upgraded account before write; load and selection retain but exclude disallowed rows, continue with allowed siblings, and preserve the current auth error when none are allowed.
Agent Identity association, proactive refresh state, and permanent refresh failures are account-scoped; listing with refresh requested attempts every due account independently and reports per-account failures without aborting siblings.

### Selection and request contract

`AuthManager` exposes account list/upsert/targeted remove/logout-all, scoped immutable snapshot, account refresh, neutral usage/rate recording, and one `recover_failed_attempt(snapshot, failure, committed) -> RecoveryDecision` facade.
Backend-neutral pool DTOs live in private `codex-login::auth::account_pool` types exported only through the `AuthManager` facade; app-server protocol DTOs are leaf wire mappings, not persistence or policy types.
The neutral `ManagedChatgptSelectionScope` lives in `codex-login` and contains optional thread/session identity plus model text only; it imports no model-provider or core types.
`ManagedChatgptAuthSnapshot` contains stable identity key, account revision, immutable `CodexAuth`, selection revision, and `TransportAuthBinding { identity_key, raw_account_id, fedramp, auth_mode, route_generation }`.
`AuthManager::auth()` remains a deterministic default-account compatibility projection for non-request legacy readers; every model request, connector/session cache, telemetry path, account usage request, and status mutation migrates to an explicit snapshot or account identity.
Selection uses a pure deterministic hash over sorted stable identity keys plus an in-memory thread-to-identity pin; pins do not persist across process restart and are invalidated by membership/block revision changes.
The pool publishes one revision watch covering membership, selected pins, refresh, blocks, and usage so account-bound consumers can invalidate caches.
Selection excludes active definitive quota/auth cooldowns and assigns deterministic tickets over accounts sorted by stable key.
Fresh weight is `100 + min_remaining_percent` across canonical default/Codex primary and secondary windows; unknown usage weighs 100, stale usage weighs 50, and the stable scope hash selects from cumulative tickets.
Additional limit IDs remain visible in status but do not influence v1 ranking until the backend exposes a concrete model-to-limit mapping.
Usage is fresh for five minutes; stale snapshots remain displayable, empty snapshots are unknown, reset timestamps bound quota blocks, and a definitive quota without reset uses a 60-second fallback block.
A thread remains sticky while its account is usable; permanent selected-account auth failure and `RateLimitReachedType::RateLimitReached` may rotate before commitment.
Workspace owner/member credit or usage limits block every pool entry sharing the selected raw ChatGPT workspace/account ID and rotate only to a distinct workspace, preventing futile sibling retries.
Generic transport throttling, server overload, empty rate-limit snapshots, and transient 429/5xx errors retain existing retry behavior and never persist account exhaustion.
Recovery validates the failed snapshot revision, classifies scope, persists any block, invalidates only affected pins, and chooses the next snapshot in one owner decision; callers never sequence separate mark-and-rotate policy calls.

The model-provider seam resolves exactly one immutable selected-auth snapshot per attempt.
Provider mode, endpoint provider, bearer, raw ChatGPT account ID, FedRAMP headers, and transport binding derive atomically from that snapshot instead of the current three independent auth reads.
Agent Identity resolution, dynamic same-account header refresh, and unauthorized recovery receive the selected identity key plus account/selection revisions and may never fall back to unscoped `AuthManager::auth()`.
HTTP, Server-Sent Events (SSE), WebSocket, remote compaction, and usage adapters carry the stable selected account key and transport binding through response metadata.
WebSocket connections, previous-response state, sticky turn state, and latest rate-limit snapshots are keyed by the full transport binding or cleared before reuse; access-token-only refresh may retain the binding, while raw workspace ID, FedRAMP, auth mode, route generation, or selected identity changes invalidate it.
The existing sampling and compaction retry loops own failover: they may rotate only before observable output or committed history, then rebuild account-bound auth and transport state before retrying.
Once text, thinking, tool activity, output items, or history are committed, neither ordinary retry nor account failover may replay the request.

### CLI contract

Managed browser and device-code login no longer call `clear_existing_auth_before_login`; OAuth completion upserts exactly one identity through `AuthManager`.
`codex login status` renders one account-pool snapshot with every managed account, selected state, plan, usage windows, reset time, and stale/unavailable labels.
`codex logout` removes the only account directly, shows an interactive picker only when multiple accounts and a terminal are available, accepts `--account <identity>` or `--all`, and fails an ambiguous non-interactive invocation with guidance.
Targeted revoke receives the selected account snapshot and never deletes or refreshes a sibling.

### App-server and TUI contract

Keep the existing singular `account/read`, `account/rateLimits/read`, and `account/usage/read` routes as derived default-selected compatibility projections, never independent stores.
Register a new canonical `account/list` route with `ListAccountsParams { thread_id: Option<ThreadId>, model: Option<String>, refresh_tokens: bool, refresh_usage: bool }` and `ListAccountsResponse { accounts: Vec<ManagedChatgptAccountView>, selected_account_id: Option<String>, pool_revision: u64, selection_revision: Option<u64> }`; a scoped TUI request reports that thread's pin plus selection revision, while an unscoped CLI-equivalent request reports deterministic default selection with no persistent selection revision.
For each account, `refresh_tokens` completes first and produces a new immutable snapshot; only then may `refresh_usage` fetch with that snapshot. Both operations continue across per-account failure and return per-account failure/staleness rather than aborting the list.
`ManagedChatgptAccountView.refresh_status` is a structured, non-secret outcome: `healthy`, `transient_unavailable { observed_at }`, or `relogin_required { reason_code, observed_at }`; it never carries raw backend error text, and one account's transient or permanent refresh failure never suppresses healthy sibling rows.
Change `account/logout` wire params from unit to optional `LogoutAccountParams { account_id: Option<String>, all: bool }` and response to `{ removed_account_ids, accounts, selected_account_id }`; missing params preserve old single-account/non-pooled behavior but fail with guidance when multiple managed accounts make the target ambiguous.
Global `AccountPoolUpdatedNotification` carries `pool_revision` plus membership, usage, block, and per-row `account_revision` data only, never a thread-selected identity; `pool_revision` orders all membership or row-state changes and excludes pin-only selection changes.
Thread-scoped `AccountSelectionUpdatedNotification { thread_id, selected_account_id, selection_revision }` emits on the first scoped `auth_snapshot` pin through core `EventMsg`→app-server, and after scoped list selection, block-driven rotation, or selected-account removal; TUI consumers reject older pool, row-state, or selection revisions independently.
`AccountRateLimitsUpdatedNotification` adds optional stable account ID plus optional `account_revision` (`None` preserves singular non-pooled compatibility); managed-only `AccountUsageUpdatedNotification` requires stable account ID plus `account_revision`. Account-level updates use the global/account-subscriber sender, sparse managed updates are rejected when their account revision is older than the cached row, and thread token-activity notifications remain thread-scoped.
The app-server adapter fetches every requested managed `CodexAuth::Chatgpt` account independently with the same immutable per-account snapshot, calls `AuthManager::record_account_usage` and `record_account_rate_limits`, and publishes the owner-returned view.
One app-server lifecycle task subscribes to the `AuthManager` pool revision watch, coalesces revisions, reads the owner view, and sends global `AccountPoolUpdated`; login/logout/usage handlers only mutate the owner and never hand-build a competing snapshot.
The subscription starts per app-server runtime, tears down with it, and reconnecting clients bootstrap through `account/list` rather than depending on missed notifications.
Per-account timeout, backend failure, or absent/empty rate headers update that row's unavailable/stale state without failing the list, erasing prior known data, affecting siblings, or marking exhaustion.
Register every new route and notification in the app-server protocol request/notification enums, request dispatcher, account processor, outgoing-message path, and one v1 `account-pool` serialization scope covering login/upsert, targeted or all logout, and mutating token/usage refresh list operations; pure non-mutating list snapshots may run concurrently.
Do not reuse the dormant schema-only `AccountSessions*` types.
`ManagedChatgptAccountView` is managed-OAuth-specific and carries stable public key, raw account ID where existing clients require it, email, plan, eligibility plus reason, cooldown, per-account rate windows, token-usage summary, observation time, and stale/unavailable state; selection exists only in response/selection notifications, and non-pooled modes remain only in the singular compatibility projection.
TUI bootstrap and `AccountUpdated` keep using singular `account/read` for effective auth mode, onboarding, API key, external auth, PAT, standalone Agent Identity, and Bedrock compatibility.
For managed ChatGPT, bootstrap and `/status` additionally consume `account/list`; rolling rate-limit cache and `/logout` use account-keyed payloads, targeted logout refreshes the list and keeps the running session alive, and `--all`/explicit user exit retain current exit behavior.
The separate thread token-activity `/usage` surface and `ThreadTokenUsageUpdated` notification remain unchanged and must not be conflated with account quota/usage.
Protocol Rust types are the source of truth; generated JSON and TypeScript artifacts are regenerated with the existing fixture generator after route registration.
### Preserved contracts

- Preserve existing auth precedence and behavior for every non-pooled auth mode.
- Preserve forced ChatGPT workspace allowlist validation.
- Preserve account-mismatch guards as immutable per-attempt invariants.
- Do not create a second source of truth for account selection, usage, refresh, or cooldown state.
- Avoid index-based persisted or public identity.
- Keep external ChatGPT auth host-managed and singly selected.
- Keep realtime on its existing API-key path.
- Follow existing Rust formatting, lint, targeted test, and generated-artifact workflows.

## Implementation Checklist

- [x] Add versioned account schema, legacy migration, account-scoped Agent Identity, and serialized compare-safe storage mutation in `codex-login`
- [x] Add `AuthManager` account-list, upsert, targeted revoke/delete, selected refresh, cooldown, usage recording, and scoped deterministic selection APIs
- [x] Route browser/device OAuth completion through managed account upsert and remove pre-login global revoke
- [x] Add CLI parser and terminal-aware multi-account login status/logout flows
- [x] Make model-provider request setup resolve one selected snapshot atomically
- [x] Carry selected account identity through HTTP/SSE/WebSocket responses, usage, rate-limit, and token-count events
- [x] Key or invalidate WebSocket, previous-response, sticky turn, and rate-limit state on account rotation
- [x] Integrate definitive pre-commit account failover into existing sampling and compaction retry loops
- [x] Register app-server account-list, targeted logout/usage routes and account-keyed notifications through producer, dispatcher, handler, and serialization scopes
- [x] Regenerate protocol schemas/TypeScript from registered Rust protocol types
- [x] Convert TUI bootstrap, `/status`, rolling usage cache, and `/logout` to account-keyed public payloads
- [x] Run focused migration, concurrency, identity, refresh, routing, replay-safety, protocol, CLI, app-server, and TUI tests
- [x] Smoke test two-account upsert, status, deterministic distribution, safe failover, and targeted logout end to end

## Verification Contract

Runtime proof must demonstrate:

1. Two distinct ChatGPT account fixtures survive sequential login/upsert.
2. Re-login of one identity replaces only that identity.
3. Targeted logout removes one account and leaves its sibling usable.
4. Status returns and renders both accounts, including stale/unavailable usage.
5. Two thread identities distribute deterministically and remain sticky.
6. A definitive usage-limit failure blocks the selected account and rotates before observable output.
7. Generic transient failures do not rotate or persist an exhausted block.
8. Account rotation rebuilds account-bound WebSocket and rate-limit state.
9. Legacy single-account auth loads and is written in the new format without credential loss.
10. Existing API key, external auth, forced-workspace, refresh, logout, and app-server account behaviors remain valid.
11. Two concurrent managers refresh one rotating token with one authority call and preserve a concurrent sibling upsert.
12. Successful re-login clears auth-invalid state, retains only same-account quota/usage state, and leaves siblings unchanged.
13. Neither ordinary retry nor account failover replays after observable output or committed compaction history.
14. Global pool updates omit thread selection, while scoped selection updates identify the correct thread/account and targeted TUI logout does not exit.
15. Identityless legacy account A plus identifiable login B preserves both rows; only A's own refresh may upgrade A's opaque key.
16. Refresh racing targeted logout makes one authority refresh, revokes the latest token, and leaves the row absent; restart before/after revoke resumes tombstone deletion without resurrection.
17. Same-email re-login changing raw workspace ID, FedRAMP, or route generation rebuilds WebSocket transport binding and clears previous-response/turn state.
18. Thread-selected account A while default account B remains current resolves Agent Identity and 401 recovery only against A.
19. Mixed forced-workspace pools retain disallowed rows but select only allowed rows; rejected OAuth performs no write.
20. External overlay logout reveals and preserves the persistent managed pool.
21. API-key and external-auth TUI bootstrap plus non-pooled rate-limit notification behavior remain unchanged.
22. Ranking fixtures cover fresh, unknown, stale, multiple primary/secondary windows, and deterministic tickets.
23. Per-account transient and permanent refresh outcomes are structured and non-secret, preserve healthy sibling rows, and serialize every mutating account-pool operation through the v1 scope.
24. Out-of-order pool, per-account state, and thread-selection notifications are rejected by their independent monotonic revisions; selection-only changes do not advance the global pool revision.

## Risks

- Flat file/keyring read-modify-write can lose concurrent refresh or login updates without explicit serialization and compare-safe replacement.
- Existing rate-limit and WebSocket caches are singular and can leak state across account switches.
- Public protocol types currently omit a stable ChatGPT account identity.
- Existing login deliberately revokes stored auth before OAuth; preserving siblings requires a clean replacement of that lifecycle.
- Existing usage endpoints are account-authenticated and can be unavailable; selection must degrade without treating missing data as exhaustion.

## Open Questions

None. Product defaults were confirmed on 2026-07-13.
