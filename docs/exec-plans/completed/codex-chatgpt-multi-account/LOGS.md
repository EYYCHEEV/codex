# Project Log: Codex ChatGPT Multi-Account Pool
Created: 2026-07-13T18:31:50+08:00
Plan: ./PLAN.md
Workspace: docs/exec-plans/completed/codex-chatgpt-multi-account/

## Progress
- [x] Design and expose the account-pool seam
- [x] Migrate persistence and OAuth login to account upsert
- [x] Add account-scoped selection, refresh, backoff, and safe rotation
- [x] Add CLI multi-account login, logout, and status flows
- [x] Extend app-server account protocol, handlers, and notifications
- [x] Render all ChatGPT accounts and usage in TUI status
- [x] Smoke test end-to-end multi-account behavior

## Session History
- [2026-07-13] Created the ExecPlan from the confirmed intent and started architecture preflight before implementation.
- [2026-07-13] Completed architecture pressure analysis and rewrote the plan around one `codex-login::AuthManager` account-pool owner, account-keyed protocol/state, atomic selected-auth resolution, and existing retry-loop integration.
- [2026-07-13] Architecture advisor returned `ADVICE=proceed` after the revised owner, persistence, request binding, protocol, notification, and compatibility contracts closed every required orientation gap.
- [2026-07-13] Registered and generated the additive account-pool app-server protocol; focused Rust/TypeScript tests passed and independent protocol review returned PASS after refresh/revision ordering repairs.
- [2026-07-13] Added the shared committed-attempt outcome to sampling and compaction retries; reviewer-found terminal budget/context bookkeeping was repaired and replay-safety review returned PASS.
- [2026-07-13] Completed the CLI multi-account slice; independent re-review returned PASS after revision-bound owner observation, overlay-preserving logout, precedence, and first-fetch unavailable-label repairs. Focused execution remains gated on the in-progress provider/core integration compiling.
- [2026-07-13] The first login-pool executor hit its runtime limit after partial implementation; reclaimed the path and started a recovery integrator from compiler evidence rather than discarding correct work.
- [2026-07-13] The first TUI executor hit its runtime limit after implementing substantial status, revision-cache, unavailable-state, and logout work; reclaimed `codex-rs/tui` and started a recovery integrator to finish and verify the slice.
- [2026-07-13] The long-running login and app-server recovery passes reached their runtime limits while executing focused checks after substantial repairs; preserved the work, released both Symphony leases, and started narrow finalizers from compiler evidence.
- [2026-07-13] The provider/core snapshot executor reached its runtime limit during final transport-binding checks; preserved its atomic setup and cache-binding work, released the lease, and started a narrow compiler-driven finalizer.
- [2026-07-13] Completed the compiler-driven integration passes: request-scoped provider/auth snapshots, replay-safe sampling and compaction failover, managed MCP runtime rebinding, account-bound WebSocket invalidation, canonical HTTP/WebSocket/memory rate-limit propagation, non-pooled app notifications, and CLI/TUI projection fixes.
- [2026-07-13] Closed verification with passing full library suites for `codex-login` (268), `codex-cli` (90), `codex-app-server` (269), `codex-tui` (337), `codex-api` (125), `codex-model-provider` (62), and `codex-core` (2,046 passed; 3 ignored), plus the CLI login integration suite (22).
- [2026-07-13] Reconciled every verification-contract behavior against focused fixtures for migration, concurrent refresh, deterministic selection, targeted logout, replay gates, transport rebinding, MCP scope, monotonic notifications, external overlay compatibility, and non-pooled auth compatibility.

## Decisions
- [2026-07-13] Decision: Pool only Codex-managed ChatGPT OAuth credentials because API keys, external auth, Agent Identity, PAT, and Bedrock have different ownership and lifecycle contracts.
- [2026-07-13] Decision: Use deterministic thread stickiness with safe failover because per-request round-robin would invalidate prompt-cache and WebSocket continuity.
- [2026-07-13] Decision: Use normalized email first and ChatGPT account ID as fallback identity because this mirrors the proven Oh My Pi account-deduplication behavior.
- [2026-07-13] Decision: Preserve account-mismatch checks as immutable per-attempt guards and explicitly rebuild account-bound state during rotation.
- [2026-07-13] Decision: Keep network usage fetching in core/CLI/app-server adapters because `codex-login` cannot depend upward on backend/client crates; the pool owns only account-keyed usage state and ranking.
- [2026-07-13] Decision: Make the request setup snapshot atomic because current client setup reads auth/provider/header state independently and can mix accounts during rotation.
- [2026-07-13] Decision: Associate Agent Identity, refresh failures, cooldowns, and usage with each managed account because every one of these is currently singular and would otherwise cross-contaminate siblings.
- [2026-07-13] Decision: Integrate rotation into existing sampling/compaction retry loops and fail closed after observable or committed output to prevent duplicate model output and tool execution.
- [2026-07-13] Decision: Persist `managed_chatgpt.version = 1`; migrate legacy tokens, refresh time, Agent Identity, and OAuth-derived API key into one account entry while preserving actual API-key auth fields.
- [2026-07-13] Decision: Keep a matched account's namespaced public key immutable and preserve aliases; email-bearing identities only merge fallback-only raw-ID rows, matching Oh My Pi's email-first semantics.
- [2026-07-13] Decision: Use one cross-process `CODEX_HOME` mutation lock for every persistent backend and atomic replacement for file storage because process-local app-server serialization cannot protect CLI/browser/refresh writers.
- [2026-07-13] Decision: Keep selection pins in memory over a deterministic stable-key hash; do not persist indices or thread mappings.
- [2026-07-13] Decision: Add canonical `account/list` plus account-keyed global notifications while preserving existing singular app-server routes as selected-account projections.
- [2026-07-13] Decision: Use durable refresh leases and non-expiring logout tombstones with restart recovery because cross-process single-use token rotation cannot be protected by compare-after-network alone.
- [2026-07-13] Decision: Bind WebSocket and previous-response state to identity, raw workspace, FedRAMP, auth mode, and route generation because stable email identity alone does not preserve transport routing.
- [2026-07-13] Decision: Capture MCP auth, transport binding, credential revision, and connector cache identity from the same startup or turn-scoped account snapshot; refresh a new immutable runtime only when that full key changes.
- [2026-07-13] Decision: Parse successful HTTP and WebSocket handshake rate-limit headers through the canonical multi-window parser, then persist compare-safe observations through the attempt's bound account revision.

## Blockers

## Open Questions

## Field Notes
- Oh My Pi uses identity-aware credential upsert, persistent account blocks, session-sticky usage ranking, targeted logout, and replay-safe sibling rotation.
- Codex currently stores and caches one ChatGPT token set, exposes one account in app-server/TUI, and retains unkeyed rate-limit and WebSocket state.
- Dormant `AccountSessions*` protocol structs are schema hints only; they are not registered RPCs or implemented dispatch paths.
- Direct OAuth persistence, CLI pre-login revoke, app-server singular reads, and doctor diagnostics are migration consumers; leaving any one as a whole-document writer would reintroduce lost-update races.
- WebSocket cache, previous-response state, sticky turn state, and rate-limit maps are currently unkeyed and must be rebound or invalidated on selected-account changes.
- External ChatGPT auth and realtime API-key auth remain explicit non-pooled paths.
- Managed account protocol now carries structured non-secret refresh status plus monotonic pool, selection, and account revisions; dependent consumers must reject stale sparse updates.
- Partial observation success must merge rate and token dimensions independently; absence in one fetch cannot erase the other dimension.

## Artifacts
- [Execution plan](./PLAN.md)

## Client Feedback
- [2026-07-13] Confirmed the proposed routing, logout, usage, identity, and scope defaults and authorized end-to-end file mutation.
