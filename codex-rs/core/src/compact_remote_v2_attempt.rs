use std::sync::Arc;

use super::RemoteCompactionV2Output;
use super::run_remote_compaction_request_v2;
use crate::Prompt;
use crate::client::ModelClientSession;
use crate::compact::CompactionAnalyticsDetails;
use crate::compact_remote::estimate_model_visible_tool_tokens;
use crate::compact_remote::trim_function_call_history_to_fit_context_window;
use crate::responses_metadata::CodexResponsesRequestKind;
use crate::responses_metadata::CompactionTurnMetadata;
use crate::responses_retry::ResponsesStreamRequest;
use crate::responses_retry::handle_retryable_response_stream_error;
use crate::session::session::Session;
use crate::session::step_context::StepContext;
use crate::session::turn::AttemptOutcome;
use codex_protocol::error::Result as CodexResult;
use codex_protocol::models::ResponseItem;
use codex_protocol::protocol::EventMsg;
use codex_protocol::protocol::RawResponseCompletedEvent;
use codex_protocol::protocol::TokenUsage;
use codex_rollout_trace::CompactionTraceContext;
use tracing::info;

pub(super) struct RemoteCompactV2Attempt {
    pub(super) trace_input_history: Option<Vec<ResponseItem>>,
    pub(super) prompt_input: Vec<ResponseItem>,
    pub(super) compaction_output: ResponseItem,
    pub(super) token_usage: Option<TokenUsage>,
    /// Keeps a session created for standalone compaction alive through lifecycle completion.
    pub(super) owned_client_session: Option<ModelClientSession>,
}

pub(super) async fn run_remote_compact_v2_attempt(
    sess: &Arc<Session>,
    step_context: &Arc<StepContext>,
    client_session: Option<&mut ModelClientSession>,
    compaction_trace: &CompactionTraceContext,
    compaction_metadata: CompactionTurnMetadata,
    analytics_details: &mut CompactionAnalyticsDetails,
) -> CodexResult<RemoteCompactV2Attempt> {
    let turn_context = &step_context.turn;
    let window_id = sess.current_window_id().await;
    let responses_metadata = turn_context.turn_metadata_state.to_responses_metadata(
        sess.installation_id.clone(),
        window_id,
        CodexResponsesRequestKind::Compaction(compaction_metadata),
    );
    let mut owned_client_session = None;
    let client_session = match client_session {
        Some(client_session) => client_session,
        None => owned_client_session.insert(sess.services.model_client.new_session()),
    };
    let max_retries = turn_context
        .provider
        .info()
        .stream_max_retries()
        .min(super::MAX_REMOTE_COMPACTION_V2_STREAM_RETRIES);
    let mut retries = 0;
    let active_context_tokens_before = analytics_details.active_context_tokens_before;
    loop {
        let request_setup = sess
            .services
            .model_client
            .current_client_setup(
                Some(&turn_context.model_info.slug),
                Some(responses_metadata.session_id.as_str()),
            )
            .await?;
        let attempt_step_context = sess
            .capture_step_context_for_setup(Arc::clone(turn_context), &request_setup)
            .await?;
        let mut history = sess.clone_history().await;
        let base_instructions = sess.get_base_instructions().await;
        let tools = attempt_step_context.tool_router.model_visible_specs();
        let (rewritten_outputs, estimated_deleted_tokens) =
            trim_function_call_history_to_fit_context_window(
                &mut history,
                turn_context.as_ref(),
                &base_instructions,
                estimate_model_visible_tool_tokens(&tools),
            );
        if rewritten_outputs > 0 {
            info!(
                turn_id = %turn_context.sub_id,
                rewritten_outputs,
                "rewrote history outputs before remote compaction v2"
            );
        }
        if estimated_deleted_tokens > 0 {
            let max_local_deleted_tokens = sess
                .estimated_tokens_after_last_model_generated_item()
                .await;
            analytics_details.active_context_tokens_before =
                active_context_tokens_before.map(|active_context_tokens_before| {
                    active_context_tokens_before
                        .saturating_sub(estimated_deleted_tokens.min(max_local_deleted_tokens))
                });
        }

        let trace_input_history = compaction_trace
            .is_enabled()
            .then(|| history.raw_items().to_vec());
        let mut input = history.for_prompt(&turn_context.model_info.input_modalities);
        input.push(ResponseItem::CompactionTrigger {});
        let prompt = Prompt {
            input,
            tools,
            parallel_tool_calls: turn_context.model_info.supports_parallel_tool_calls,
            base_instructions,
            output_schema: None,
            output_schema_strict: true,
        };
        let trace_attempt = compaction_trace.start_attempt(&serde_json::json!({
            "model": turn_context.model_info.slug.as_str(),
            "instructions": prompt.base_instructions.text.as_str(),
            "input": &prompt.input,
            "parallel_tool_calls": prompt.parallel_tool_calls,
        }));
        let AttemptOutcome {
            result,
            replay_state,
        } = run_remote_compaction_request_v2(
            sess,
            turn_context.as_ref(),
            client_session,
            &prompt,
            &responses_metadata,
            request_setup,
        )
        .await;
        let committed = replay_state.is_committed();
        trace_attempt.record_result(
            result
                .as_ref()
                .map(|output| std::slice::from_ref(&output.compaction_output)),
        );
        match result {
            Ok(RemoteCompactionV2Output {
                compaction_output,
                response_id,
                token_usage,
            }) => {
                sess.send_event(
                    turn_context,
                    EventMsg::RawResponseCompleted(RawResponseCompletedEvent {
                        response_id,
                        token_usage: token_usage.clone(),
                    }),
                )
                .await;
                let mut prompt_input = prompt.input;
                prompt_input.pop();
                return Ok(RemoteCompactV2Attempt {
                    trace_input_history,
                    prompt_input,
                    compaction_output,
                    token_usage,
                    owned_client_session,
                });
            }
            Err(error)
                if client_session
                    .recover_last_managed_attempt(&error, committed)
                    .await =>
            {
                continue;
            }
            Err(error) if committed || !error.is_retryable() => return Err(error),
            Err(error) => {
                handle_retryable_response_stream_error(
                    &mut retries,
                    max_retries,
                    error,
                    client_session,
                    sess,
                    turn_context,
                    ResponsesStreamRequest::RemoteCompactionV2,
                )
                .await?;
            }
        }
    }
}
