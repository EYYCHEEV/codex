use std::sync::Arc;
use std::time::Instant;

use crate::Prompt;
use crate::ResponseStream;
use crate::client::CurrentClientSetup;
use crate::client::ModelClientSession;
use crate::client_common::ResponseEvent;
use crate::context::world_state::WorldState;
use crate::hook_runtime::PostCompactHookOutcome;
use crate::hook_runtime::PreCompactHookOutcome;
use crate::hook_runtime::run_post_compact_hooks;
use crate::hook_runtime::run_pre_compact_hooks;
use crate::responses_metadata::CodexResponsesMetadata;
use crate::responses_metadata::CodexResponsesRequestKind;
use crate::responses_metadata::CompactionTurnMetadata;
#[cfg(test)]
use crate::session::PreviousTurnSettings;
use crate::session::session::Session;
use crate::session::step_context::StepContext;
use crate::session::turn::AttemptOutcome;
use crate::session::turn::get_last_assistant_message_from_turn;
use crate::session::turn_context::TurnContext;
use crate::state::AutoCompactWindowIds;
use crate::util::backoff;
use codex_analytics::CodexCompactionEvent;
use codex_analytics::CompactionImplementation;
use codex_analytics::CompactionPhase;
use codex_analytics::CompactionReason;
use codex_analytics::CompactionStatus;
use codex_analytics::CompactionStrategy;
use codex_analytics::CompactionTrigger;
use codex_analytics::now_unix_seconds;
use codex_protocol::error::CodexErr;
use codex_protocol::error::CodexErrorDetails;
use codex_protocol::error::Result as CodexResult;
use codex_protocol::items::ContextCompactionItem;
use codex_protocol::items::TurnItem;
use codex_protocol::models::AgentMessageInputContent;
use codex_protocol::models::ContentItem;
use codex_protocol::models::InternalChatMessageMetadataPassthrough;
use codex_protocol::models::ResponseInputItem;
use codex_protocol::models::ResponseItem;
use codex_protocol::protocol::EventMsg;
use codex_protocol::protocol::RawResponseCompletedEvent;
use codex_protocol::protocol::TurnStartedEvent;
use codex_protocol::protocol::WarningEvent;
use codex_protocol::user_input::UserInput;
use codex_rollout_trace::InferenceTraceContext;
use codex_utils_output_truncation::TruncationPolicy;
use codex_utils_output_truncation::approx_token_count;
use codex_utils_output_truncation::truncate_text;
use futures::prelude::*;
use tracing::error;

pub use codex_prompts::SUMMARIZATION_PROMPT;
pub use codex_prompts::SUMMARY_PREFIX;
const COMPACT_USER_MESSAGE_MAX_TOKENS: usize = 20_000;

/// Controls whether compaction replacement history must include initial context.
///
/// Pre-turn/manual compaction variants use `DoNotInject`: they replace history with a summary and
/// clear `reference_context_item`, so the next regular turn will fully reinject initial context
/// after compaction.
///
/// Mid-turn compaction must use `BeforeLastUserMessage` because the model is trained to see the
/// compaction summary as the last item in history after mid-turn compaction; we therefore inject
/// initial context into the replacement history just above the last real user message.
pub(crate) enum InitialContextInjection {
    BeforeLastUserMessage {
        world_state: Arc<WorldState>,
        step_context: Arc<StepContext>,
    },
    DoNotInject,
}

/// Metadata for a new compaction checkpoint, kept separate from its replacement history.
///
/// `Session::replace_compacted_history` assigns missing item IDs before constructing the persisted
/// `CompactedItem`, ensuring the live and persisted histories remain identical.
pub(crate) struct CompactedHistoryMetadata {
    pub(crate) message: String,
    pub(crate) window_number: u64,
    pub(crate) window_ids: AutoCompactWindowIds,
}

pub(crate) async fn build_compaction_initial_context(
    sess: &Session,
    initial_context_injection: &InitialContextInjection,
) -> (Vec<ResponseItem>, Option<Arc<WorldState>>) {
    // Return the rendered state with its items so history and its baseline stay identical.
    match initial_context_injection {
        InitialContextInjection::BeforeLastUserMessage {
            world_state,
            step_context,
        } => {
            let items = sess
                .build_initial_context_with_world_state(
                    step_context.turn.as_ref(),
                    world_state.as_ref(),
                )
                .await;
            (items, Some(Arc::clone(world_state)))
        }
        InitialContextInjection::DoNotInject => (Vec::new(), None),
    }
}

pub(crate) async fn run_inline_auto_compact_task(
    sess: Arc<Session>,
    turn_context: Arc<TurnContext>,
    initial_context_injection: InitialContextInjection,
    reason: CompactionReason,
    phase: CompactionPhase,
) -> CodexResult<()> {
    let prompt = turn_context
        .config
        .compact_prompt
        .as_deref()
        .unwrap_or(SUMMARIZATION_PROMPT)
        .to_string();
    let input = vec![UserInput::Text {
        text: prompt,
        // Compaction prompt is synthesized; no UI element ranges to preserve.
        text_elements: Vec::new(),
    }];

    run_compact_task_inner(
        sess,
        turn_context,
        input,
        initial_context_injection,
        CompactionTrigger::Auto,
        reason,
        phase,
    )
    .await?;
    Ok(())
}

pub(crate) async fn run_compact_task(
    sess: Arc<Session>,
    turn_context: Arc<TurnContext>,
    input: Vec<UserInput>,
) -> CodexResult<()> {
    let start_event = EventMsg::TurnStarted(TurnStartedEvent {
        turn_id: turn_context.sub_id.clone(),
        trace_id: turn_context.trace_id.clone(),
        started_at: turn_context.turn_timing_state.started_at_unix_secs().await,
        model_context_window: turn_context.model_context_window(),
        collaboration_mode_kind: turn_context.mode,
    });
    sess.send_event(&turn_context, start_event).await;
    run_compact_task_inner(
        sess.clone(),
        turn_context,
        input,
        InitialContextInjection::DoNotInject,
        CompactionTrigger::Manual,
        CompactionReason::UserRequested,
        CompactionPhase::StandaloneTurn,
    )
    .await?;
    Ok(())
}

async fn run_compact_task_inner(
    sess: Arc<Session>,
    turn_context: Arc<TurnContext>,
    input: Vec<UserInput>,
    initial_context_injection: InitialContextInjection,
    trigger: CompactionTrigger,
    reason: CompactionReason,
    phase: CompactionPhase,
) -> CodexResult<()> {
    let compaction_metadata =
        CompactionTurnMetadata::new(trigger, reason, CompactionImplementation::Responses, phase);
    let attempt = CompactionAnalyticsAttempt::begin(
        sess.as_ref(),
        turn_context.as_ref(),
        trigger,
        reason,
        CompactionImplementation::Responses,
        phase,
    )
    .await;
    let pre_compact_outcome = run_pre_compact_hooks(&sess, &turn_context, trigger).await;
    match pre_compact_outcome {
        PreCompactHookOutcome::Continue => {}
        PreCompactHookOutcome::Stopped => {
            let error = CodexErr::TurnAborted;
            attempt
                .track(
                    sess.as_ref(),
                    CompactionStatus::Interrupted,
                    Some(&error),
                    CompactionAnalyticsDetails::default(),
                )
                .await;
            return Err(error);
        }
    }
    let result = run_compact_task_inner_impl(
        Arc::clone(&sess),
        Arc::clone(&turn_context),
        input,
        initial_context_injection,
        compaction_metadata,
    )
    .await;
    let status = compaction_status_from_result(&result);
    let codex_error = result.as_ref().err();
    if result.is_ok() {
        let post_compact_outcome = run_post_compact_hooks(&sess, &turn_context, trigger).await;
        if let PostCompactHookOutcome::Stopped = post_compact_outcome {
            attempt
                .track(
                    sess.as_ref(),
                    status,
                    codex_error,
                    CompactionAnalyticsDetails::default(),
                )
                .await;
            return Err(CodexErr::TurnAborted);
        }
    }
    attempt
        .track(
            sess.as_ref(),
            status,
            codex_error,
            CompactionAnalyticsDetails::default(),
        )
        .await;
    result.map(|_| ())
}

async fn run_compact_task_inner_impl(
    sess: Arc<Session>,
    turn_context: Arc<TurnContext>,
    input: Vec<UserInput>,
    initial_context_injection: InitialContextInjection,
    compaction_metadata: CompactionTurnMetadata,
) -> CodexResult<String> {
    let compaction_item = TurnItem::ContextCompaction(ContextCompactionItem::new());
    sess.emit_turn_item_started(&turn_context, &compaction_item)
        .await;
    let initial_input_for_turn: ResponseInputItem = ResponseInputItem::from(input);

    let mut history = sess.clone_history().await;
    history.record_items(
        &[initial_input_for_turn.into()],
        turn_context.model_info.truncation_policy.into(),
    );

    let max_retries = turn_context.provider.info().stream_max_retries();
    let mut retries = 0;
    let mut client_session = sess.services.model_client.new_session();
    // Reuse one client session so turn-scoped state (sticky routing, websocket incremental
    // request tracking)
    // survives retries within this compact turn.
    let window_id = sess.current_window_id().await;
    let responses_metadata = turn_context.turn_metadata_state.to_responses_metadata(
        sess.installation_id.clone(),
        window_id,
        CodexResponsesRequestKind::Compaction(compaction_metadata),
    );

    loop {
        let request_setup = sess
            .services
            .model_client
            .current_client_setup(
                Some(&turn_context.model_info.slug),
                Some(responses_metadata.session_id.as_str()),
            )
            .await?;
        // Ensure every retry refreshes account-bound MCP/runtime state before model transport.
        let _attempt_step_context = sess
            .capture_step_context_for_setup(Arc::clone(&turn_context), &request_setup)
            .await?;
        // Clone is required because of the loop
        let turn_input = history
            .clone()
            .for_prompt(&turn_context.model_info.input_modalities);
        let turn_input_len = turn_input.len();
        let prompt = Prompt {
            input: turn_input,
            base_instructions: sess.get_base_instructions().await,
            ..Default::default()
        };
        let AttemptOutcome {
            result: attempt_result,
            replay_state,
        } = drain_to_completed(
            &sess,
            turn_context.as_ref(),
            &mut client_session,
            &responses_metadata,
            &prompt,
            request_setup,
        )
        .await;
        let committed = replay_state.is_committed();

        if let Err(error) = &attempt_result
            && !committed
            && client_session
                .recover_last_managed_attempt(error, committed)
                .await
        {
            continue;
        }

        match attempt_result {
            Ok(()) => {
                break;
            }
            Err(err)
                if matches!(
                    err.details(),
                    CodexErrorDetails::Interrupted | CodexErrorDetails::TurnAborted
                ) =>
            {
                return Err(err);
            }
            Err(e) if matches!(e.details(), CodexErrorDetails::SessionBudgetExceeded) => {
                sess.track_turn_codex_error(turn_context.as_ref(), &e);
                let event = EventMsg::Error(e.to_error_event(/*message_prefix*/ None));
                sess.send_event(&turn_context, event).await;
                return Err(e);
            }
            Err(e)
                if committed && matches!(e.details(), CodexErrorDetails::ContextWindowExceeded) =>
            {
                sess.set_total_tokens_full(turn_context.as_ref()).await;
                sess.track_turn_codex_error(turn_context.as_ref(), &e);
                let event = EventMsg::Error(e.to_error_event(/*message_prefix*/ None));
                sess.send_event(&turn_context, event).await;
                return Err(e);
            }
            Err(e) if matches!(e.details(), CodexErrorDetails::ContextWindowExceeded) => {
                if turn_input_len > 1 {
                    // Trim from the beginning to preserve cache (prefix-based) and keep recent messages intact.
                    error!(
                        "Context window exceeded while compacting; removing oldest history item. Error: {e}"
                    );
                    history.remove_first_item();
                    retries = 0;
                    continue;
                }
                sess.set_total_tokens_full(turn_context.as_ref()).await;
                sess.track_turn_codex_error(turn_context.as_ref(), &e);
                let event = EventMsg::Error(e.to_error_event(/*message_prefix*/ None));
                sess.send_event(&turn_context, event).await;
                return Err(e);
            }
            Err(e) if committed => {
                sess.track_turn_codex_error(turn_context.as_ref(), &e);
                let event = EventMsg::Error(e.to_error_event(/*message_prefix*/ None));
                sess.send_event(&turn_context, event).await;
                return Err(e);
            }
            Err(e) => {
                if retries < max_retries {
                    retries += 1;
                    let delay = backoff(retries);
                    sess.notify_stream_error(
                        turn_context.as_ref(),
                        format!("Reconnecting... {retries}/{max_retries}"),
                        e,
                    )
                    .await;
                    tokio::time::sleep(delay).await;
                    continue;
                } else {
                    sess.track_turn_codex_error(turn_context.as_ref(), &e);
                    let event = EventMsg::Error(e.to_error_event(/*message_prefix*/ None));
                    sess.send_event(&turn_context, event).await;
                    return Err(e);
                }
            }
        }
    }

    let history_snapshot = sess.clone_history().await;
    let history_items = history_snapshot.raw_items();
    let summary_suffix = get_last_assistant_message_from_turn(history_items).unwrap_or_default();
    let summary_text = format!("{SUMMARY_PREFIX}\n{summary_suffix}");
    let user_messages = collect_user_messages(history_items);

    let mut new_history = build_compacted_history(Vec::new(), &user_messages, &summary_text);
    if let Some(summary_item) = new_history.last_mut() {
        // This replacement history skips `record_conversation_items`; only the appended summary
        // belongs to this compaction turn.
        summary_item.set_turn_id_if_missing(&turn_context.sub_id);
    }
    let (window_number, window_ids) = sess.advance_auto_compact_window().await;

    let (initial_context, world_state_baseline) =
        build_compaction_initial_context(sess.as_ref(), &initial_context_injection).await;
    if !initial_context.is_empty() {
        new_history =
            insert_initial_context_before_last_real_user_or_summary(new_history, initial_context);
    }
    let reference_context_item = match initial_context_injection {
        InitialContextInjection::DoNotInject => None,
        InitialContextInjection::BeforeLastUserMessage { .. } => {
            Some(turn_context.to_turn_context_item())
        }
    };
    sess.replace_compacted_history(
        new_history,
        reference_context_item,
        world_state_baseline,
        CompactedHistoryMetadata {
            message: summary_text,
            window_number,
            window_ids,
        },
    )
    .await;
    sess.recompute_token_usage(&turn_context).await;

    sess.emit_turn_item_completed(&turn_context, compaction_item)
        .await;
    let warning = EventMsg::Warning(WarningEvent {
        message: "Heads up: Long threads and multiple compactions can cause the model to be less accurate. Start a new thread when possible to keep threads small and targeted.".to_string(),
    });
    sess.send_event(&turn_context, warning).await;
    Ok(summary_suffix)
}

pub(crate) struct CompactionAnalyticsAttempt {
    thread_id: String,
    turn_id: String,
    trigger: CompactionTrigger,
    reason: CompactionReason,
    implementation: CompactionImplementation,
    phase: CompactionPhase,
    active_context_tokens_before: i64,
    started_at: u64,
    start_instant: Instant,
}

#[derive(Clone, Copy, Default)]
pub(crate) struct CompactionAnalyticsDetails {
    pub(crate) active_context_tokens_before: Option<i64>,
    pub(crate) retained_image_count: Option<usize>,
    pub(crate) compaction_summary_tokens: Option<i64>,
    pub(crate) cached_input_tokens: Option<i64>,
    pub(crate) cache_write_input_tokens: Option<i64>,
}

impl CompactionAnalyticsAttempt {
    pub(crate) async fn begin(
        sess: &Session,
        turn_context: &TurnContext,
        trigger: CompactionTrigger,
        reason: CompactionReason,
        implementation: CompactionImplementation,
        phase: CompactionPhase,
    ) -> Self {
        let active_context_tokens_before = sess.get_total_token_usage().await;
        Self {
            thread_id: sess.thread_id.to_string(),
            turn_id: turn_context.sub_id.clone(),
            trigger,
            reason,
            implementation,
            phase,
            active_context_tokens_before,
            started_at: now_unix_seconds(),
            start_instant: Instant::now(),
        }
    }

    pub(crate) async fn track(
        self,
        sess: &Session,
        status: CompactionStatus,
        codex_error: Option<&CodexErr>,
        details: CompactionAnalyticsDetails,
    ) {
        let CompactionAnalyticsDetails {
            active_context_tokens_before,
            retained_image_count,
            compaction_summary_tokens,
            cached_input_tokens,
            cache_write_input_tokens,
        } = details;
        let active_context_tokens_before =
            active_context_tokens_before.unwrap_or(self.active_context_tokens_before);
        let active_context_tokens_after = sess.get_total_token_usage().await;
        sess.services
            .analytics_events_client
            .track_compaction(CodexCompactionEvent {
                thread_id: self.thread_id,
                turn_id: self.turn_id,
                trigger: self.trigger,
                reason: self.reason,
                implementation: self.implementation,
                phase: self.phase,
                strategy: CompactionStrategy::Memento,
                status,
                codex_error_kind: codex_error.map(Into::into),
                codex_error_http_status_code: codex_error
                    .and_then(CodexErr::http_status_code_value),
                active_context_tokens_before,
                active_context_tokens_after,
                retained_image_count,
                compaction_summary_tokens,
                cached_input_tokens,
                cache_write_input_tokens,
                started_at: self.started_at,
                completed_at: now_unix_seconds(),
                duration_ms: Some(
                    u64::try_from(self.start_instant.elapsed().as_millis()).unwrap_or(u64::MAX),
                ),
            });
    }
}

pub(crate) fn compaction_status_from_result<T>(result: &CodexResult<T>) -> CompactionStatus {
    match result {
        Ok(_) => CompactionStatus::Completed,
        Err(err)
            if matches!(
                err.details(),
                CodexErrorDetails::Interrupted | CodexErrorDetails::TurnAborted
            ) =>
        {
            CompactionStatus::Interrupted
        }
        Err(_) => CompactionStatus::Failed,
    }
}

pub fn content_items_to_text(content: &[ContentItem]) -> Option<String> {
    let mut pieces = Vec::new();
    for item in content {
        match item {
            ContentItem::InputText { text } | ContentItem::OutputText { text } => {
                if !text.is_empty() {
                    pieces.push(text.as_str());
                }
            }
            ContentItem::InputImage { .. } | ContentItem::InputAudio { .. } => {}
        }
    }
    if pieces.is_empty() {
        None
    } else {
        Some(pieces.join("\n"))
    }
}

#[derive(Clone, Debug, PartialEq)]
pub(crate) struct CompactedUserMessage {
    message: String,
    internal_chat_message_metadata_passthrough: Option<InternalChatMessageMetadataPassthrough>,
}

pub(crate) fn collect_user_messages(items: &[ResponseItem]) -> Vec<CompactedUserMessage> {
    items
        .iter()
        .filter_map(|item| match crate::event_mapping::parse_turn_item(item) {
            Some(TurnItem::UserMessage(user)) => {
                if is_summary_message(&user.message()) {
                    None
                } else {
                    Some(CompactedUserMessage {
                        message: user.message(),
                        internal_chat_message_metadata_passthrough: match item {
                            ResponseItem::Message {
                                internal_chat_message_metadata_passthrough,
                                ..
                            } => internal_chat_message_metadata_passthrough.clone(),
                            _ => None,
                        },
                    })
                }
            }
            _ => None,
        })
        .collect()
}

pub(crate) fn is_summary_message(message: &str) -> bool {
    message.starts_with(format!("{SUMMARY_PREFIX}\n").as_str())
}

/// Inserts canonical initial context into compacted replacement history at the
/// model-expected boundary.
///
/// Placement rules:
/// - Prefer immediately before the last real user or agent message.
/// - If no real user messages remain, insert before the compaction summary so
///   the summary stays last.
/// - If there are no user messages, insert before the last compaction item so
///   that item remains last (remote compaction may return only compaction items).
/// - If there are no user messages or compaction items, append the context.
pub(crate) fn insert_initial_context_before_last_real_user_or_summary(
    mut compacted_history: Vec<ResponseItem>,
    initial_context: Vec<ResponseItem>,
) -> Vec<ResponseItem> {
    let mut last_user_or_summary_index = None;
    let mut last_real_user_index = None;
    for (i, item) in compacted_history.iter().enumerate().rev() {
        if let ResponseItem::AgentMessage { content, .. } = item
            && !matches!(
                content.first(),
                Some(AgentMessageInputContent::InputText { text })
                    if text.starts_with("Message Type: FINAL_ANSWER\n")
            )
        {
            last_real_user_index = Some(i);
            break;
        }
        let Some(TurnItem::UserMessage(user)) = crate::event_mapping::parse_turn_item(item) else {
            continue;
        };
        // Compaction summaries are encoded as user messages, so track both:
        // the last real user message (preferred insertion point) and the last
        // user-message-like item (fallback summary insertion point).
        last_user_or_summary_index.get_or_insert(i);
        if !is_summary_message(&user.message()) {
            last_real_user_index = Some(i);
            break;
        }
    }
    let last_compaction_index = compacted_history
        .iter()
        .enumerate()
        .rev()
        .find_map(|(i, item)| {
            matches!(
                item,
                ResponseItem::Compaction { .. } | ResponseItem::ContextCompaction { .. }
            )
            .then_some(i)
        });
    let insertion_index = last_real_user_index
        .or(last_user_or_summary_index)
        .or(last_compaction_index);

    // Re-inject canonical context from the current session since we stripped it
    // from the pre-compaction history. Prefer placing it before the last real
    // user message; if there is no real user message left, place it before the
    // summary or compaction item so the compaction item remains last.
    if let Some(insertion_index) = insertion_index {
        compacted_history.splice(insertion_index..insertion_index, initial_context);
    } else {
        compacted_history.extend(initial_context);
    }

    compacted_history
}

pub(crate) fn build_compacted_history(
    initial_context: Vec<ResponseItem>,
    user_messages: &[CompactedUserMessage],
    summary_text: &str,
) -> Vec<ResponseItem> {
    build_compacted_history_with_limit(
        initial_context,
        user_messages,
        summary_text,
        COMPACT_USER_MESSAGE_MAX_TOKENS,
    )
}

fn build_compacted_history_with_limit(
    mut history: Vec<ResponseItem>,
    user_messages: &[CompactedUserMessage],
    summary_text: &str,
    max_tokens: usize,
) -> Vec<ResponseItem> {
    let mut selected_messages: Vec<CompactedUserMessage> = Vec::new();
    if max_tokens > 0 {
        let mut remaining = max_tokens;
        for message in user_messages.iter().rev() {
            if remaining == 0 {
                break;
            }
            let tokens = approx_token_count(&message.message);
            if tokens <= remaining {
                selected_messages.push(message.clone());
                remaining = remaining.saturating_sub(tokens);
            } else {
                let truncated =
                    truncate_text(&message.message, TruncationPolicy::Tokens(remaining));
                selected_messages.push(CompactedUserMessage {
                    message: truncated,
                    internal_chat_message_metadata_passthrough: message
                        .internal_chat_message_metadata_passthrough
                        .clone(),
                });
                break;
            }
        }
        selected_messages.reverse();
    }

    for message in &selected_messages {
        history.push(ResponseItem::Message {
            id: None,
            role: "user".to_string(),
            content: vec![ContentItem::InputText {
                text: message.message.clone(),
            }],
            phase: None,
            internal_chat_message_metadata_passthrough: message
                .internal_chat_message_metadata_passthrough
                .clone(),
        });
    }

    let summary_text = if summary_text.is_empty() {
        "(no summary available)".to_string()
    } else {
        summary_text.to_string()
    };

    history.push(ResponseItem::Message {
        id: None,
        role: "user".to_string(),
        content: vec![ContentItem::InputText { text: summary_text }],
        phase: None,
        internal_chat_message_metadata_passthrough: None,
    });

    history
}

async fn drain_to_completed(
    sess: &Session,
    turn_context: &TurnContext,
    client_session: &mut ModelClientSession,
    responses_metadata: &CodexResponsesMetadata,
    prompt: &Prompt,
    request_setup: CurrentClientSetup,
) -> AttemptOutcome<()> {
    let stream_result = client_session
        .stream_attempt_with_setup(
            prompt,
            &turn_context.model_info,
            &turn_context.session_telemetry,
            turn_context.reasoning_effort.clone(),
            turn_context.reasoning_summary,
            turn_context.config.service_tier.clone(),
            responses_metadata,
            // Rollout tracing currently models remote compaction only; local compaction streams
            // are left untraced until the reducer has a first-class local compaction lifecycle.
            &InferenceTraceContext::disabled(),
            request_setup,
        )
        .await;
    crate::compact_remote::emit_managed_selection_updates(sess, turn_context, client_session).await;
    let managed_rate_limit_binding = client_session.managed_rate_limit_binding();
    sess.observe_managed_rate_limit_binding(managed_rate_limit_binding.as_ref())
        .await;
    if let Err(error) = &stream_result
        && let CodexErrorDetails::UsageLimitReached(error) = error.details()
        && let Some(rate_limits) = error.rate_limits.as_ref()
    {
        sess.update_rate_limits(
            turn_context,
            (**rate_limits).clone(),
            managed_rate_limit_binding.clone(),
        )
        .await;
    }
    let stream = match stream_result {
        Ok(stream) => stream,
        Err(err) => return AttemptOutcome::uncommitted(Err(err)),
    };
    drain_compaction_stream(sess, turn_context, stream, managed_rate_limit_binding).await
}

async fn drain_compaction_stream(
    sess: &Session,
    turn_context: &TurnContext,
    mut stream: ResponseStream,
    managed_rate_limit_binding: Option<crate::state::ManagedRateLimitBinding>,
) -> AttemptOutcome<()> {
    let mut replay_state = crate::session::turn::AttemptReplayState::Uncommitted;
    loop {
        let maybe_event = stream.next().await;
        let Some(event) = maybe_event else {
            return AttemptOutcome::new(
                Err(CodexErr::Stream(
                    "stream closed before response.completed".into(),
                )),
                replay_state,
            );
        };
        match event {
            Ok(event) => {
                replay_state = std::cmp::max(
                    replay_state,
                    crate::session::turn::response_event_replay_state(&event),
                );
                match event {
                    ResponseEvent::OutputItemDone(item) => {
                        sess.record_conversation_items(turn_context, std::slice::from_ref(&item))
                            .await;
                    }
                    ResponseEvent::ServerReasoningIncluded(included) => {
                        sess.set_server_reasoning_included(included).await;
                    }
                    ResponseEvent::RateLimits(snapshot) => {
                        sess.update_rate_limits(
                            turn_context,
                            snapshot,
                            managed_rate_limit_binding.clone(),
                        )
                        .await;
                    }
                    ResponseEvent::Completed {
                        response_id,
                        token_usage,
                        ..
                    } => {
                        sess.send_event(
                            turn_context,
                            EventMsg::RawResponseCompleted(RawResponseCompletedEvent {
                                response_id,
                                token_usage: token_usage.clone(),
                            }),
                        )
                        .await;
                        let result = sess
                            .update_token_usage_info(turn_context, token_usage.as_ref())
                            .await;
                        return AttemptOutcome::new(result, replay_state);
                    }
                    _ => continue,
                }
            }
            Err(e) => return AttemptOutcome::new(Err(e), replay_state),
        }
    }
}

#[cfg(test)]
mod replay_safety_tests {
    use super::*;
    use std::collections::VecDeque;
    use tokio::sync::mpsc;
    use tokio_util::sync::CancellationToken;

    fn response_stream(events: Vec<CodexResult<ResponseEvent>>) -> ResponseStream {
        let (tx_event, rx_event) = mpsc::channel(events.len().max(1));
        for event in events {
            tx_event
                .try_send(event)
                .expect("event should fit in compact test stream");
        }
        drop(tx_event);
        ResponseStream {
            rx_event,
            consumer_dropped: CancellationToken::new(),
        }
    }

    fn compact_output(id: &str) -> ResponseItem {
        ResponseItem::Message {
            id: Some(codex_protocol::ResponseItemId::from_server(id.to_string())),
            role: "assistant".to_string(),
            content: vec![ContentItem::OutputText {
                text: "partial summary".to_string(),
            }],
            phase: None,
            internal_chat_message_metadata_passthrough: None,
        }
    }

    fn completed() -> ResponseEvent {
        ResponseEvent::Completed {
            response_id: "completed".to_string(),
            token_usage: None,
            end_turn: Some(true),
        }
    }

    async fn run_retryable_streams(
        session: &Session,
        turn_context: &TurnContext,
        streams: Vec<ResponseStream>,
    ) -> (CodexResult<()>, usize) {
        let mut streams = VecDeque::from(streams);
        let mut attempts = 0;
        loop {
            let stream = streams
                .pop_front()
                .expect("test retry loop exhausted its response streams");
            attempts += 1;
            let outcome = drain_compaction_stream(session, turn_context, stream, None).await;
            match outcome.result {
                Ok(()) => return (Ok(()), attempts),
                Err(err) if outcome.replay_state.is_committed() || !err.is_retryable() => {
                    return (Err(err), attempts);
                }
                Err(_) => continue,
            }
        }
    }

    async fn history_item_count(session: &Session, expected_id: &str) -> usize {
        let history = session.clone_history().await;
        history
            .raw_items()
            .iter()
            .filter(|item| {
                matches!(
                    item,
                    ResponseItem::Message { id: Some(id), .. } if id.as_str() == expected_id
                )
            })
            .count()
    }

    #[tokio::test]
    async fn compact_partial_history_failure_does_not_start_second_attempt() {
        let (session, turn_context) = crate::session::tests::make_session_and_context().await;
        let first = response_stream(vec![
            Ok(ResponseEvent::OutputItemDone(compact_output(
                "partial-compaction",
            ))),
            Err(CodexErr::Stream("retryable committed failure".to_string())),
        ]);
        let should_not_run = response_stream(vec![Ok(completed())]);

        let (result, attempts) =
            run_retryable_streams(&session, &turn_context, vec![first, should_not_run]).await;

        assert!(result.is_err());
        assert_eq!(attempts, 1);
        assert_eq!(history_item_count(&session, "partial-compaction").await, 1);
    }

    #[tokio::test]
    async fn compact_pre_output_failure_retries_and_succeeds_once() {
        let (session, turn_context) = crate::session::tests::make_session_and_context().await;
        let first = response_stream(vec![Err(CodexErr::Stream(
            "retryable uncommitted failure".to_string(),
        ))]);
        let second = response_stream(vec![
            Ok(ResponseEvent::OutputItemDone(compact_output(
                "successful-compaction",
            ))),
            Ok(completed()),
        ]);

        let (result, attempts) =
            run_retryable_streams(&session, &turn_context, vec![first, second]).await;

        assert!(result.is_ok());
        assert_eq!(attempts, 2);
        assert_eq!(
            history_item_count(&session, "successful-compaction").await,
            1
        );
    }
}

#[cfg(test)]
#[path = "compact_tests.rs"]
mod tests;
