# codex-api

Typed clients for Codex/OpenAI APIs built on top of the generic transport in `codex-client`.

- Hosts the request/response models and request builders for Responses and Compact APIs.
- Owns provider configuration (base URLs, headers, query params), auth header injection, retry tuning, and stream idle settings.
- Parses SSE streams into `ResponseEvent`/`ResponseStream`, including rate-limit snapshots and API-specific error mapping.
- Serves as the wire-level layer consumed by `codex-core`; higher layers handle auth refresh and business logic.

## Core interface

The public interface of this crate is intentionally small and uniform:

- **Responses endpoint**
  - Input:
    - `ResponsesApiRequest` for the request body (`model`, `instructions`, `input`, `tools`, `parallel_tool_calls`, reasoning/text controls).
    - `ResponsesOptions` for transport/header concerns (`conversation_id`, `session_source`, `extra_headers`, `compression`, `turn_state`).
  - Output: a `ResponseStream` of `ResponseEvent` (both re-exported from `common`).

- **Compaction endpoint**
  - Input: `CompactionInput<'a>` (re-exported as `codex_api::CompactionInput`):
    - `model: &str`.
    - `input: &[ResponseItem]` – history to compact.
    - `instructions: &str` – fully-resolved compaction instructions.
  - Output: `ApiCompactResponse`, containing compacted `output: Vec<ResponseItem>` and optional response-header `rate_limits`.
  - `CompactClient::compact_input(&CompactionInput, extra_headers)` wraps the JSON encoding and retry/telemetry wiring.

- **Memory summarize endpoint**
  - Input: `MemorySummarizeInput` (re-exported as `codex_api::MemorySummarizeInput`):
    - `model: String`.
    - `raw_memories: Vec<RawMemory>` (serialized as `traces` for wire compatibility).
      - `RawMemory` includes `id`, `metadata.source_path`, and normalized `items`.
    - `reasoning: Option<Reasoning>`.
  - Output: `ApiMemoryResponse`, containing `output: Vec<MemorySummarizeOutput>` and optional response-header `rate_limits`.
  - `MemoriesClient::summarize_input(&MemorySummarizeInput, extra_headers)` wraps JSON encoding and retry/telemetry wiring.

All HTTP details (URLs, headers, retry/backoff policies, SSE framing) are encapsulated in `codex-api` and `codex-client`. Callers construct prompts/inputs using protocol types and work with typed streams of `ResponseEvent` or typed endpoint response wrappers.

## Responses WebSocket disconnect diagnostics

When a Responses WebSocket closes before `response.completed`, the endpoint emits one failure-only tracing event with the close code, a redacted close reason, whether the connection was reused, the number of response events seen, and whether response output had started.
Successful streams do not emit this diagnostic.
The wire layer preserves the close metadata in `ApiError::WebsocketClosed`; higher layers remain responsible for deciding whether an attempt is safe to replay after observable output.
