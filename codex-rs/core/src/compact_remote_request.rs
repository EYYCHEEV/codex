use std::sync::Arc;

use super::estimate_model_visible_tool_tokens;
use super::trim_function_call_history_to_fit_context_window;
use crate::Prompt;
use crate::client::CompactConversationRequestSettings;
use crate::client::ModelClientSession;
use crate::compact::CompactionAnalyticsDetails;
use crate::compact_remote::emit_managed_selection_updates;
use crate::responses_metadata::CodexResponsesRequestKind;
use crate::responses_metadata::CompactionTurnMetadata;
use crate::session::session::Session;
use crate::session::step_context::StepContext;
use codex_protocol::auth::AuthMode;
use codex_protocol::error::CodexErrorDetails;
use codex_protocol::error::Result as CodexResult;
use codex_protocol::models::ResponseItem;
use codex_rollout_trace::CompactionTraceContext;
use tracing::info;

pub(super) struct RemoteCompactAttempt {
    pub(super) new_history: Vec<ResponseItem>,
    pub(super) trace_input_history: Option<Vec<ResponseItem>>,
}

pub(super) async fn run_remote_compact_attempt(
    sess: &Arc<Session>,
    step_context: &Arc<StepContext>,
    client_session: &mut ModelClientSession,
    compaction_trace: &CompactionTraceContext,
    compaction_metadata: CompactionTurnMetadata,
    analytics_details: &mut CompactionAnalyticsDetails,
) -> CodexResult<RemoteCompactAttempt> {
    let turn_context = &step_context.turn;
    let responses_metadata = sess
        .responses_metadata(
            turn_context.as_ref(),
            CodexResponsesRequestKind::Compaction(compaction_metadata),
        )
        .await;
    let active_context_tokens_before = analytics_details.active_context_tokens_before;
    loop {
        let request_setup = sess
            .services
            .model_client
            .current_client_setup(
                Some(&turn_context.model_info().slug),
                Some(responses_metadata.session_id.as_str()),
            )
            .await?;
        let attempt_step_context = sess
            .capture_speculative_step_context_for_setup(Arc::clone(turn_context), &request_setup)
            .await?;
        let mut history = sess.clone_history().await;
        let base_instructions = sess.get_prompt_base_instructions().await;
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
                "rewrote history outputs before remote compaction"
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
            .then(|| history.raw_items().cloned().collect());
        let prompt_input = history.for_prompt(&turn_context.model_info().input_modalities);
        let prompt = Prompt {
            input: prompt_input,
            tools,
            parallel_tool_calls: true,
            base_instructions,
            output_schema: None,
            output_schema_strict: true,
            cyber_access_program: turn_context.cyber_access_program,
        };
        let service_tier = if request_setup
            .effective_auth
            .as_ref()
            .is_some_and(|auth| auth.auth_mode() == AuthMode::ApiKey)
        {
            None
        } else {
            attempt_step_context.settings.service_tier.clone()
        };
        let result = sess
            .services
            .model_client
            .compact_conversation_history(
                &prompt,
                turn_context.model_info(),
                client_session,
                CompactConversationRequestSettings {
                    effort: turn_context.reasoning_effort().cloned(),
                    summary: turn_context.reasoning_summary(),
                    service_tier,
                },
                &turn_context.session_telemetry,
                compaction_trace,
                &responses_metadata,
                Some(request_setup),
            )
            .await;
        let attempt_binding = client_session.managed_rate_limit_binding();
        sess.observe_managed_rate_limit_binding(attempt_binding.as_ref())
            .await;
        emit_managed_selection_updates(sess.as_ref(), turn_context.as_ref(), client_session).await;
        if let Err(error) = &result
            && let CodexErrorDetails::UsageLimitReached(error) = error.details()
            && let Some(rate_limits) = error.rate_limits.as_ref()
        {
            sess.update_rate_limits(
                turn_context,
                (**rate_limits).clone(),
                attempt_binding.clone(),
            )
            .await;
        }
        match result {
            Ok(compact_result) => {
                if let Some(rate_limits) = compact_result.rate_limits {
                    sess.update_rate_limits(turn_context, rate_limits, attempt_binding)
                        .await;
                }
                return Ok(RemoteCompactAttempt {
                    new_history: compact_result.output,
                    trace_input_history,
                });
            }
            Err(error)
                if client_session
                    .recover_last_managed_attempt(&error, /*committed*/ false)
                    .await =>
            {
                continue;
            }
            Err(error) => return Err(error),
        }
    }
}
