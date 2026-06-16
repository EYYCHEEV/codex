use std::path::Path;
use std::path::PathBuf;

use codex_config::types::HookFailurePolicy;
use codex_protocol::ThreadId;
use codex_protocol::protocol::HookCompletedEvent;
use codex_protocol::protocol::HookEventName;
use codex_protocol::protocol::HookOutputEntry;
use codex_protocol::protocol::HookOutputEntryKind;
use codex_protocol::protocol::HookRunStatus;
use codex_protocol::protocol::HookRunSummary;
use codex_utils_absolute_path::AbsolutePathBuf;
use futures::StreamExt;
use futures::stream::FuturesUnordered;
use serde::Deserialize;
use serde::Serialize;
use serde_json::Value;

use super::common;
use crate::engine::CommandShell;
use crate::engine::ConfiguredHandler;
use crate::engine::ConfiguredHandlerBehavior;
use crate::engine::HandlerExecution;
use crate::engine::command_runner::CommandRunResult;
use crate::engine::command_runner::run_command;
use crate::engine::dispatcher;
use crate::engine::output_parser;
use crate::events::common::matches_matcher;
use crate::output_spill::AdditionalContext;
use crate::output_spill::HookOutputSpiller;
use crate::schema::PreToolUseCommandInput;
use crate::schema::SubagentCommandInputFields;

#[derive(Debug, Clone)]
pub struct PreToolUseRequest {
    pub session_id: ThreadId,
    pub turn_id: String,
    pub subagent: Option<common::SubagentHookContext>,
    pub cwd: AbsolutePathBuf,
    pub transcript_path: Option<PathBuf>,
    pub model: String,
    pub permission_mode: String,
    pub tool_name: String,
    pub matcher_aliases: Vec<String>,
    pub allow_canonical_handlers: bool,
    pub tool_use_id: String,
    pub tool_input: Value,
}

#[derive(Debug)]
pub struct PreToolUseOutcome {
    pub hook_events: Vec<HookCompletedEvent>,
    pub should_block: bool,
    pub block_reason: Option<String>,
    pub additional_contexts: Vec<String>,
    pub updated_input: Option<Value>,
}

#[derive(Debug, Default, PartialEq, Eq)]
struct PreToolUseHandlerData {
    should_block: bool,
    block_reason: Option<String>,
    additional_contexts_for_model: Vec<AdditionalContext>,
    updated_input: Option<Value>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PreToolUseInputKind {
    Canonical,
    Legacy,
}

#[derive(Debug, Clone)]
struct MatchedPreToolUseHandler {
    handler: ConfiguredHandler,
    input_kind: PreToolUseInputKind,
}

#[derive(Debug, Serialize)]
struct LegacyPreToolUseInput {
    session_id: String,
    turn_id: String,
    transcript_path: crate::schema::NullableString,
    cwd: String,
    hook_event_name: String,
    model: String,
    permission_mode: String,
    tool_name: String,
    tool_input: Value,
    tool_use_id: String,
}

#[derive(Debug, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
struct LegacyPreToolUseOutput {
    #[serde(default)]
    hook_specific_output: Option<LegacyPreToolUseHookSpecificOutput>,
    #[serde(default)]
    decision: Option<LegacyPreToolUseDecision>,
    #[serde(default)]
    reason: Option<String>,
}

#[derive(Debug, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
struct LegacyPreToolUseHookSpecificOutput {
    #[serde(default)]
    permission_decision: Option<LegacyPreToolUseDecision>,
    #[serde(default)]
    permission_decision_reason: Option<String>,
}

#[derive(Debug, Deserialize, Clone, Copy, PartialEq, Eq, Default)]
#[serde(rename_all = "lowercase")]
enum LegacyPreToolUseDecision {
    #[default]
    #[serde(alias = "approve")]
    Allow,
    #[serde(alias = "block")]
    Deny,
    Ask,
}

impl LegacyPreToolUseOutput {
    fn decision(&self) -> LegacyPreToolUseDecision {
        if let Some(hook_specific_output) = self.hook_specific_output.as_ref()
            && let Some(permission_decision) = hook_specific_output.permission_decision
        {
            return permission_decision;
        }
        self.decision.unwrap_or_default()
    }

    fn reason(&self) -> Option<String> {
        if let Some(hook_specific_output) = self.hook_specific_output.as_ref()
            && hook_specific_output.permission_decision_reason.is_some()
        {
            return hook_specific_output.permission_decision_reason.clone();
        }
        self.reason.clone()
    }
}

pub(crate) fn preview(
    handlers: &[ConfiguredHandler],
    request: &PreToolUseRequest,
) -> Vec<HookRunSummary> {
    matched_handlers(handlers, request)
        .into_iter()
        .map(|matched| {
            common::hook_run_for_tool_use(
                dispatcher::running_summary(&matched.handler),
                &request.tool_use_id,
            )
        })
        .collect()
}

pub(crate) async fn run(
    handlers: &[ConfiguredHandler],
    shell: &CommandShell,
    output_spiller: &HookOutputSpiller,
    request: PreToolUseRequest,
) -> PreToolUseOutcome {
    let session_id = request.session_id;
    let matched = matched_handlers(handlers, &request);
    if matched.is_empty() {
        return PreToolUseOutcome {
            hook_events: Vec::new(),
            should_block: false,
            block_reason: None,
            additional_contexts: Vec::new(),
            updated_input: None,
        };
    }

    let canonical_input = matched
        .iter()
        .any(|matched| matched.input_kind == PreToolUseInputKind::Canonical)
        .then(|| {
            command_input_json(&request)
                .map_err(|error| format!("failed to serialize pre tool use hook input: {error}"))
        });
    let legacy_input = matched
        .iter()
        .any(|matched| matched.input_kind == PreToolUseInputKind::Legacy)
        .then(|| legacy_input_json(&request));

    let outcome = collect_outcome(
        execute_handlers(
            shell,
            matched,
            canonical_input,
            legacy_input,
            request.cwd.as_path(),
            Some(request.turn_id.clone()),
            &request.tool_use_id,
        )
        .await,
        &request.tool_use_id,
    );

    PreToolUseOutcome {
        hook_events: outcome.hook_events,
        should_block: outcome.should_block,
        block_reason: outcome.block_reason,
        additional_contexts: outcome.additional_contexts,
        updated_input: outcome.updated_input,
    }
}

struct CollectedOutcome {
    hook_events: Vec<HookCompletedEvent>,
    should_block: bool,
    block_reason: Option<String>,
    additional_contexts: Vec<String>,
    updated_input: Option<Value>,
}

fn collect_outcome(
    results: Vec<dispatcher::ParsedHandler<PreToolUseHandlerData>>,
    tool_use_id: &str,
) -> CollectedOutcome {
    let should_block = results.iter().any(|result| result.data.should_block);
    let block_reason = results
        .iter()
        .find_map(|result| result.data.block_reason.clone());
    let additional_contexts = common::flatten_additional_contexts(
        results
            .iter()
            .map(|result| result.data.additional_contexts_for_model.as_slice()),
    );
    let additional_contexts = output_spiller
        .maybe_spill_additional_contexts(session_id, additional_contexts)
        .await;
    let updated_input = if should_block {
        None
    } else {
        latest_updated_input(&results)
    };
    let hook_events = results
        .into_iter()
        .map(|result| common::hook_completed_for_tool_use(result.completed, tool_use_id))
        .collect();

    CollectedOutcome {
        hook_events,
        should_block,
        block_reason,
        additional_contexts,
        updated_input,
    }
}

/// Chooses the rewrite from the hook that actually finished last.
///
/// Hook results stay in configured order for stable reporting, but the
/// `PreToolUse` contract resolves competing rewrites by completion order.
fn latest_updated_input(
    results: &[dispatcher::ParsedHandler<PreToolUseHandlerData>],
) -> Option<Value> {
    results
        .iter()
        .filter_map(|result| {
            result
                .data
                .updated_input
                .clone()
                .map(|updated_input| (result.completion_order, updated_input))
        })
        .max_by_key(|(completion_order, _)| *completion_order)
        .map(|(_, updated_input)| updated_input)
}

async fn execute_handlers(
    shell: &CommandShell,
    handlers: Vec<MatchedPreToolUseHandler>,
    canonical_input: Option<Result<String, String>>,
    legacy_input: Option<Result<String, String>>,
    cwd: &Path,
    turn_id: Option<String>,
    tool_use_id: &str,
) -> Vec<dispatcher::ParsedHandler<PreToolUseHandlerData>> {
    let mut pending = FuturesUnordered::new();
    for (configured_order, handler) in handlers.into_iter().enumerate() {
        let canonical_input = canonical_input.clone();
        let legacy_input = legacy_input.clone();
        let turn_id = turn_id.clone();
        let tool_use_id = tool_use_id.to_string();
        pending.push(async move {
            let input_json =
                input_json_for_handler(handler.input_kind, &canonical_input, &legacy_input);
            let handler = handler.handler;
            let parsed = match input_json {
                Ok(input_json) => {
                    let run_result = if legacy_handler_has_empty_command(&handler) {
                        CommandRunResult {
                            started_at: chrono::Utc::now().timestamp(),
                            completed_at: chrono::Utc::now().timestamp(),
                            duration_ms: 0,
                            exit_code: None,
                            stdout: String::new(),
                            stderr: String::new(),
                            error: Some("Hook misconfigured: empty command".to_string()),
                        }
                    } else {
                        run_command(shell, &handler, &input_json, cwd).await
                    };
                    parse_completed(&handler, run_result, turn_id)
                }
                Err(error) => serialization_failure_result(handler, turn_id, error, &tool_use_id),
            };
            (configured_order, parsed)
        });
    }

    let mut completed = Vec::new();
    let mut completion_order = 0;
    while let Some((configured_order, mut parsed)) = pending.next().await {
        parsed.completion_order = completion_order;
        completion_order += 1;
        completed.push((configured_order, parsed));
    }
    completed.sort_by_key(|(configured_order, _)| *configured_order);
    completed.into_iter().map(|(_, parsed)| parsed).collect()
}

fn matched_handlers(
    handlers: &[ConfiguredHandler],
    request: &PreToolUseRequest,
) -> Vec<MatchedPreToolUseHandler> {
    let matcher_inputs = common::matcher_inputs(&request.tool_name, &request.matcher_aliases);

    handlers
        .iter()
        .filter(|handler| handler.event_name == HookEventName::PreToolUse)
        .filter(|handler| {
            if matcher_inputs.is_empty() {
                matches_matcher(handler.matcher.as_deref(), None)
            } else {
                matcher_inputs
                    .iter()
                    .any(|input| matches_matcher(handler.matcher.as_deref(), Some(input)))
            }
        })
        .filter_map(|handler| match &handler.behavior {
            ConfiguredHandlerBehavior::Canonical => {
                request
                    .allow_canonical_handlers
                    .then(|| MatchedPreToolUseHandler {
                        handler: handler.clone(),
                        input_kind: PreToolUseInputKind::Canonical,
                    })
            }
            ConfiguredHandlerBehavior::LegacyPreToolUse { .. } => Some(MatchedPreToolUseHandler {
                handler: handler.clone(),
                input_kind: PreToolUseInputKind::Legacy,
            }),
        })
        .collect()
}

/// Serializes command stdin for a selected `PreToolUse` hook.
///
/// Handler selection may include internal matcher aliases, but hook stdin keeps
/// the canonical `tool_name` so audit logs and downstream policy decisions stay
/// stable. Shell-like tools pass `{ "command": ... }` as `tool_input`; MCP
/// tools pass their resolved JSON arguments.
fn command_input_json(request: &PreToolUseRequest) -> Result<String, serde_json::Error> {
    let subagent = SubagentCommandInputFields::from(request.subagent.as_ref());
    serde_json::to_string(&PreToolUseCommandInput {
        session_id: request.session_id.to_string(),
        turn_id: request.turn_id.clone(),
        agent_id: subagent.agent_id,
        agent_type: subagent.agent_type,
        transcript_path: crate::schema::NullableString::from_path(request.transcript_path.clone()),
        cwd: request.cwd.display().to_string(),
        hook_event_name: "PreToolUse".to_string(),
        model: request.model.clone(),
        permission_mode: request.permission_mode.clone(),
        tool_name: request.tool_name.clone(),
        tool_input: request.tool_input.clone(),
        tool_use_id: request.tool_use_id.clone(),
    })
}

fn legacy_input_json(request: &PreToolUseRequest) -> Result<String, String> {
    serde_json::to_string(&LegacyPreToolUseInput {
        session_id: request.session_id.to_string(),
        turn_id: request.turn_id.clone(),
        transcript_path: crate::schema::NullableString::from_path(request.transcript_path.clone()),
        cwd: request.cwd.display().to_string(),
        hook_event_name: "PreToolUse".to_string(),
        model: request.model.clone(),
        permission_mode: request.permission_mode.clone(),
        tool_name: request.tool_name.clone(),
        tool_input: request.tool_input.clone(),
        tool_use_id: request.tool_use_id.clone(),
    })
    .map_err(|error| format!("failed to serialize legacy pre tool use hook input: {error}"))
}

fn input_json_for_handler(
    input_kind: PreToolUseInputKind,
    canonical_input: &Option<Result<String, String>>,
    legacy_input: &Option<Result<String, String>>,
) -> Result<String, String> {
    match input_kind {
        PreToolUseInputKind::Canonical => canonical_input
            .clone()
            .unwrap_or_else(|| Err("missing canonical handler input".to_string())),
        PreToolUseInputKind::Legacy => legacy_input
            .clone()
            .unwrap_or_else(|| Err("missing legacy handler input".to_string())),
    }
}

fn parse_completed(
    handler: &ConfiguredHandler,
    run_result: CommandRunResult,
    turn_id: Option<String>,
) -> dispatcher::ParsedHandler<PreToolUseHandlerData> {
    match &handler.behavior {
        ConfiguredHandlerBehavior::Canonical => {
            parse_completed_canonical(handler, run_result, turn_id)
        }
        ConfiguredHandlerBehavior::LegacyPreToolUse { on_failure } => {
            parse_completed_legacy(handler, run_result, turn_id, *on_failure)
        }
    }
}

fn parse_completed_canonical(
    handler: &ConfiguredHandler,
    run_result: CommandRunResult,
    turn_id: Option<String>,
) -> dispatcher::ParsedHandler<PreToolUseHandlerData> {
    let mut entries = Vec::new();
    let mut status = HookRunStatus::Completed;
    let mut should_block = false;
    let mut block_reason = None;
    let mut additional_contexts_for_model = Vec::new();
    let mut updated_input = None;

    match run_result.error.as_deref() {
        Some(error) => {
            status = HookRunStatus::Failed;
            entries.push(HookOutputEntry {
                kind: HookOutputEntryKind::Error,
                text: error.to_string(),
            });
        }
        None => match run_result.exit_code {
            Some(0) => {
                let trimmed_stdout = run_result.stdout.trim();
                if trimmed_stdout.is_empty() {
                } else if let Some(parsed) = output_parser::parse_pre_tool_use(&run_result.stdout) {
                    if let Some(system_message) = parsed.universal.system_message {
                        entries.push(HookOutputEntry {
                            kind: HookOutputEntryKind::Warning,
                            text: system_message,
                        });
                    }
                    if let Some(invalid_reason) = parsed.invalid_reason {
                        status = HookRunStatus::Failed;
                        entries.push(HookOutputEntry {
                            kind: HookOutputEntryKind::Error,
                            text: invalid_reason,
                        });
                    } else {
                        if let Some(additional_context) = parsed.additional_context {
                            common::append_additional_context(
                                &mut entries,
                                &mut additional_contexts_for_model,
                                handler,
                                additional_context,
                            );
                        }
                        if let Some(reason) = parsed.block_reason {
                            status = HookRunStatus::Blocked;
                            should_block = true;
                            block_reason = Some(reason.clone());
                            entries.push(HookOutputEntry {
                                kind: HookOutputEntryKind::Feedback,
                                text: reason,
                            });
                        }
                        if !should_block {
                            updated_input = parsed.updated_input;
                        }
                    }
                } else if output_parser::looks_like_json(&run_result.stdout) {
                    status = HookRunStatus::Failed;
                    entries.push(HookOutputEntry {
                        kind: HookOutputEntryKind::Error,
                        text: "hook returned invalid pre-tool-use JSON output".to_string(),
                    });
                }
            }
            Some(2) => {
                if let Some(reason) = common::trimmed_non_empty(&run_result.stderr) {
                    status = HookRunStatus::Blocked;
                    should_block = true;
                    block_reason = Some(reason.clone());
                    entries.push(HookOutputEntry {
                        kind: HookOutputEntryKind::Feedback,
                        text: reason,
                    });
                } else {
                    status = HookRunStatus::Failed;
                    entries.push(HookOutputEntry {
                        kind: HookOutputEntryKind::Error,
                        text: "PreToolUse hook exited with code 2 but did not write a blocking reason to stderr".to_string(),
                    });
                }
            }
            Some(exit_code) => {
                status = HookRunStatus::Failed;
                entries.push(HookOutputEntry {
                    kind: HookOutputEntryKind::Error,
                    text: format!("hook exited with code {exit_code}"),
                });
            }
            None => {
                status = HookRunStatus::Failed;
                entries.push(HookOutputEntry {
                    kind: HookOutputEntryKind::Error,
                    text: "hook exited without a status code".to_string(),
                });
            }
        },
    }

    build_completed(
        handler,
        run_result,
        turn_id,
        status,
        entries,
        should_block,
        block_reason,
        additional_contexts_for_model,
        updated_input,
    )
}

fn parse_completed_legacy(
    handler: &ConfiguredHandler,
    run_result: CommandRunResult,
    turn_id: Option<String>,
    on_failure: HookFailurePolicy,
) -> dispatcher::ParsedHandler<PreToolUseHandlerData> {
    let mut entries = Vec::new();
    let mut status = HookRunStatus::Completed;
    let mut should_block = false;
    let mut block_reason = None;

    match run_result.error.as_deref() {
        Some(error) => apply_legacy_failure_policy(
            on_failure,
            error,
            &mut status,
            &mut entries,
            &mut should_block,
            &mut block_reason,
        ),
        None => match run_result.exit_code {
            Some(0) => match parse_legacy_output(&run_result.stdout) {
                Ok(None) => {}
                Ok(Some(output)) => match output.decision() {
                    LegacyPreToolUseDecision::Allow => {}
                    LegacyPreToolUseDecision::Deny | LegacyPreToolUseDecision::Ask => {
                        let reason = output
                            .reason()
                            .unwrap_or_else(|| "Blocked by PreToolUse hook".to_string());
                        status = HookRunStatus::Blocked;
                        should_block = true;
                        block_reason = Some(reason.clone());
                        entries.push(HookOutputEntry {
                            kind: HookOutputEntryKind::Feedback,
                            text: reason,
                        });
                    }
                },
                Err(error) => apply_legacy_failure_policy(
                    on_failure,
                    &error,
                    &mut status,
                    &mut entries,
                    &mut should_block,
                    &mut block_reason,
                ),
            },
            Some(2) => {
                let reason = common::trimmed_non_empty(&run_result.stderr)
                    .unwrap_or_else(|| "Hook blocked command (exit code 2)".to_string());
                status = HookRunStatus::Blocked;
                should_block = true;
                block_reason = Some(reason.clone());
                entries.push(HookOutputEntry {
                    kind: HookOutputEntryKind::Feedback,
                    text: reason,
                });
            }
            Some(exit_code) => {
                let message = common::trimmed_non_empty(&run_result.stderr).map_or_else(
                    || format!("Hook exited with code {exit_code}"),
                    |stderr| format!("Hook failed: {stderr}"),
                );
                apply_legacy_failure_policy(
                    on_failure,
                    &message,
                    &mut status,
                    &mut entries,
                    &mut should_block,
                    &mut block_reason,
                );
            }
            None => apply_legacy_failure_policy(
                on_failure,
                "hook exited without a status code",
                &mut status,
                &mut entries,
                &mut should_block,
                &mut block_reason,
            ),
        },
    }

    build_completed(
        handler,
        run_result,
        turn_id,
        status,
        entries,
        should_block,
        block_reason,
        Vec::new(),
        None,
    )
}

fn build_completed(
    handler: &ConfiguredHandler,
    run_result: CommandRunResult,
    turn_id: Option<String>,
    status: HookRunStatus,
    entries: Vec<HookOutputEntry>,
    should_block: bool,
    block_reason: Option<String>,
    additional_contexts_for_model: Vec<String>,
    updated_input: Option<Value>,
) -> dispatcher::ParsedHandler<PreToolUseHandlerData> {
    let completed = HookCompletedEvent {
        turn_id,
        run: dispatcher::completed_summary(handler, &run_result, status, entries),
    };

    dispatcher::ParsedHandler {
        completed,
        data: PreToolUseHandlerData {
            should_block,
            block_reason,
            additional_contexts_for_model,
            updated_input,
        },
        completion_order: 0,
    }
}

fn apply_legacy_failure_policy(
    on_failure: HookFailurePolicy,
    failure_message: &str,
    status: &mut HookRunStatus,
    entries: &mut Vec<HookOutputEntry>,
    should_block: &mut bool,
    block_reason: &mut Option<String>,
) {
    match on_failure {
        HookFailurePolicy::Deny => {
            let reason = format!("Hook failed (fail-closed): {failure_message}");
            *status = HookRunStatus::Blocked;
            *should_block = true;
            *block_reason = Some(reason.clone());
            entries.push(HookOutputEntry {
                kind: HookOutputEntryKind::Feedback,
                text: reason,
            });
        }
        HookFailurePolicy::Allow => {
            *status = HookRunStatus::Failed;
            entries.push(HookOutputEntry {
                kind: HookOutputEntryKind::Error,
                text: failure_message.to_string(),
            });
        }
    }
}

fn parse_legacy_output(stdout: &str) -> Result<Option<LegacyPreToolUseOutput>, String> {
    let trimmed = stdout.trim();
    if trimmed.is_empty() {
        return Ok(None);
    }

    serde_json::from_str(trimmed).map(Some).map_err(|error| {
        let preview = &trimmed[..trimmed.len().min(200)];
        format!("Parse hook output: {error} (got: {preview})")
    })
}

fn legacy_handler_has_empty_command(handler: &ConfiguredHandler) -> bool {
    matches!(&handler.execution, HandlerExecution::Argv(argv) if argv.is_empty())
}

fn serialization_failure_result(
    handler: ConfiguredHandler,
    turn_id: Option<String>,
    error_message: String,
    tool_use_id: &str,
) -> dispatcher::ParsedHandler<PreToolUseHandlerData> {
    let completed = common::hook_completed_for_tool_use(
        common::serialization_failure_hook_events(vec![handler], turn_id, error_message).remove(0),
        tool_use_id,
    );

    dispatcher::ParsedHandler {
        completed,
        data: PreToolUseHandlerData::default(),
        completion_order: 0,
    }
}

#[cfg(test)]
mod tests {
    use codex_config::types::HookFailurePolicy;
    use codex_protocol::ThreadId;
    use codex_protocol::protocol::HookEventName;
    use codex_protocol::protocol::HookOutputEntry;
    use codex_protocol::protocol::HookOutputEntryKind;
    use codex_protocol::protocol::HookRunStatus;
    use codex_utils_absolute_path::test_support::PathBufExt;
    use codex_utils_absolute_path::test_support::test_path_buf;
    use pretty_assertions::assert_eq;

    use super::PreToolUseHandlerData;
    use super::command_input_json;
    use super::latest_updated_input;
    use super::parse_completed;
    use super::preview;
    use crate::engine::ConfiguredHandler;
    use crate::engine::ConfiguredHandlerBehavior;
    use crate::engine::HandlerExecution;
    use crate::engine::command_runner::CommandRunResult;
    use crate::events::common;
    use crate::output_spill::AdditionalContext;
    use crate::output_spill::AdditionalContextLimit;

    #[test]
    fn command_input_uses_request_tool_name() {
        let mut request = request_for_tool_use("call-apply-patch");
        request.tool_name = "apply_patch".to_string();

        let input_json = command_input_json(&request).expect("serialize command input");
        let input: serde_json::Value =
            serde_json::from_str(&input_json).expect("parse command input");

        assert_eq!(input["tool_name"], "apply_patch");
    }

    #[test]
    fn permission_decision_deny_blocks_processing() {
        let parsed = parse_completed(
            &canonical_handler(),
            run_result(
                Some(0),
                r#"{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"deny","permissionDecisionReason":"do not run that"}}"#,
                "",
            ),
            Some("turn-1".to_string()),
        );

        assert_eq!(
            parsed.data,
            PreToolUseHandlerData {
                should_block: true,
                block_reason: Some("do not run that".to_string()),
                additional_contexts_for_model: Vec::new(),
                updated_input: None,
            }
        );
        assert_eq!(parsed.completed.run.status, HookRunStatus::Blocked);
        assert_eq!(
            parsed.completed.run.entries,
            vec![HookOutputEntry {
                kind: HookOutputEntryKind::Feedback,
                text: "do not run that".to_string(),
            }]
        );
    }

    #[test]
    fn permission_decision_allow_can_update_input() {
        let parsed = parse_completed(
            &handler(),
            run_result(
                Some(0),
                r#"{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"allow","updatedInput":{"command":"echo rewritten"}}}"#,
                "",
            ),
            Some("turn-1".to_string()),
        );

        assert_eq!(
            parsed.data,
            PreToolUseHandlerData {
                should_block: false,
                block_reason: None,
                additional_contexts_for_model: Vec::new(),
                updated_input: Some(serde_json::json!({ "command": "echo rewritten" })),
            }
        );
        assert_eq!(parsed.completed.run.status, HookRunStatus::Completed);
        assert_eq!(parsed.completed.run.entries, vec![]);
    }

    #[test]
    fn last_completed_updated_input_wins() {
        let mut later_configured = parse_completed(
            &handler(),
            run_result(
                Some(0),
                r#"{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"allow","updatedInput":{"command":"echo configured later"}}}"#,
                "",
            ),
            Some("turn-1".to_string()),
        );
        later_configured.completion_order = 0;
        let mut earlier_configured = parse_completed(
            &handler(),
            run_result(
                Some(0),
                r#"{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"allow","updatedInput":{"command":"echo finished later"}}}"#,
                "",
            ),
            Some("turn-1".to_string()),
        );
        earlier_configured.completion_order = 1;

        assert_eq!(
            latest_updated_input(&[later_configured, earlier_configured]),
            Some(serde_json::json!({ "command": "echo finished later" }))
        );
    }

    #[test]
    fn permission_decision_allow_without_updated_input_fails_open() {
        let parsed = parse_completed(
            &handler(),
            run_result(
                Some(0),
                r#"{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"allow"}}"#,
                "",
            ),
            Some("turn-1".to_string()),
        );

        assert_eq!(
            parsed.data,
            PreToolUseHandlerData {
                should_block: false,
                block_reason: None,
                additional_contexts_for_model: Vec::new(),
                updated_input: None,
            }
        );
        assert_eq!(parsed.completed.run.status, HookRunStatus::Failed);
        assert_eq!(
            parsed.completed.run.entries,
            vec![HookOutputEntry {
                kind: HookOutputEntryKind::Error,
                text: "PreToolUse hook returned unsupported permissionDecision:allow".to_string(),
            }]
        );
    }

    #[test]
    fn deprecated_block_decision_blocks_processing() {
        let parsed = parse_completed(
            &canonical_handler(),
            run_result(
                Some(0),
                r#"{"decision":"block","reason":"do not run that"}"#,
                "",
            ),
            Some("turn-1".to_string()),
        );

        assert_eq!(
            parsed.data,
            PreToolUseHandlerData {
                should_block: true,
                block_reason: Some("do not run that".to_string()),
                additional_contexts_for_model: Vec::new(),
                updated_input: None,
            }
        );
        assert_eq!(parsed.completed.run.status, HookRunStatus::Blocked);
        assert_eq!(
            parsed.completed.run.entries,
            vec![HookOutputEntry {
                kind: HookOutputEntryKind::Feedback,
                text: "do not run that".to_string(),
            }]
        );
    }

    #[test]
    fn deprecated_block_decision_with_additional_context_blocks_processing() {
        let parsed = parse_completed(
            &handler(),
            run_result(
                Some(0),
                r#"{"decision":"block","reason":"do not run that","hookSpecificOutput":{"hookEventName":"PreToolUse","additionalContext":"remember this"}}"#,
                "",
            ),
            Some("turn-1".to_string()),
        );

        assert_eq!(
            parsed.data,
            PreToolUseHandlerData {
                should_block: true,
                block_reason: Some("do not run that".to_string()),
                additional_contexts_for_model: vec![AdditionalContext {
                    text: "remember this".to_string(),
                    limit: Default::default(),
                }],
                updated_input: None,
            }
        );
        assert_eq!(parsed.completed.run.status, HookRunStatus::Blocked);
        assert_eq!(
            parsed.completed.run.entries,
            vec![
                HookOutputEntry {
                    kind: HookOutputEntryKind::Context,
                    text: "remember this".to_string(),
                },
                HookOutputEntry {
                    kind: HookOutputEntryKind::Feedback,
                    text: "do not run that".to_string(),
                },
            ]
        );
    }

    #[test]
    fn unsupported_permission_decision_fails_open() {
        let parsed = parse_completed(
            &canonical_handler(),
            run_result(
                Some(0),
                r#"{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"ask","permissionDecisionReason":"please confirm"}}"#,
                "",
            ),
            Some("turn-1".to_string()),
        );

        assert_eq!(
            parsed.data,
            PreToolUseHandlerData {
                should_block: false,
                block_reason: None,
                additional_contexts_for_model: Vec::new(),
                updated_input: None,
            }
        );
        assert_eq!(parsed.completed.run.status, HookRunStatus::Failed);
        assert_eq!(
            parsed.completed.run.entries,
            vec![HookOutputEntry {
                kind: HookOutputEntryKind::Error,
                text: "PreToolUse hook returned unsupported permissionDecision:ask".to_string(),
            }]
        );
    }

    #[test]
    fn deprecated_approve_decision_fails_open() {
        let parsed = parse_completed(
            &canonical_handler(),
            run_result(Some(0), r#"{"decision":"approve"}"#, ""),
            Some("turn-1".to_string()),
        );

        assert_eq!(
            parsed.data,
            PreToolUseHandlerData {
                should_block: false,
                block_reason: None,
                additional_contexts_for_model: Vec::new(),
                updated_input: None,
            }
        );
        assert_eq!(parsed.completed.run.status, HookRunStatus::Failed);
        assert_eq!(
            parsed.completed.run.entries,
            vec![HookOutputEntry {
                kind: HookOutputEntryKind::Error,
                text: "PreToolUse hook returned unsupported decision:approve".to_string(),
            }]
        );
    }

    #[test]
    fn additional_context_is_recorded() {
        let mut handler = handler();
        handler.additional_context_limit = AdditionalContextLimit::from_config(Some(13));
        let parsed = parse_completed(
            &handler,
            run_result(
                Some(0),
                r#"{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"deny","permissionDecisionReason":"do not run that","additionalContext":"nope"}}"#,
                "",
            ),
            Some("turn-1".to_string()),
        );

        assert_eq!(
            parsed.data,
            PreToolUseHandlerData {
                should_block: true,
                block_reason: Some("do not run that".to_string()),
                additional_contexts_for_model: vec![AdditionalContext {
                    text: "nope".to_string(),
                    limit: AdditionalContextLimit::from_config(Some(13)),
                }],
                updated_input: None,
            }
        );
        assert_eq!(parsed.completed.run.status, HookRunStatus::Blocked);
        assert_eq!(
            parsed.completed.run.entries,
            vec![
                HookOutputEntry {
                    kind: HookOutputEntryKind::Context,
                    text: "nope".to_string(),
                },
                HookOutputEntry {
                    kind: HookOutputEntryKind::Feedback,
                    text: "do not run that".to_string(),
                },
            ]
        );
    }

    #[test]
    fn plain_stdout_is_ignored() {
        let parsed = parse_completed(
            &canonical_handler(),
            run_result(Some(0), "hook ran successfully\n", ""),
            Some("turn-1".to_string()),
        );

        assert_eq!(
            parsed.data,
            PreToolUseHandlerData {
                should_block: false,
                block_reason: None,
                additional_contexts_for_model: Vec::new(),
                updated_input: None,
            }
        );
        assert_eq!(parsed.completed.run.status, HookRunStatus::Completed);
        assert_eq!(parsed.completed.run.entries, vec![]);
    }

    #[test]
    fn invalid_json_like_stdout_fails_instead_of_becoming_noop() {
        let parsed = parse_completed(
            &canonical_handler(),
            run_result(Some(0), "{\"decision\":\n", ""),
            Some("turn-1".to_string()),
        );

        assert_eq!(
            parsed.data,
            PreToolUseHandlerData {
                should_block: false,
                block_reason: None,
                additional_contexts_for_model: Vec::new(),
                updated_input: None,
            }
        );
        assert_eq!(parsed.completed.run.status, HookRunStatus::Failed);
        assert_eq!(
            parsed.completed.run.entries,
            vec![HookOutputEntry {
                kind: HookOutputEntryKind::Error,
                text: "hook returned invalid pre-tool-use JSON output".to_string(),
            }]
        );
    }

    #[test]
    fn exit_code_two_blocks_processing() {
        let parsed = parse_completed(
            &canonical_handler(),
            run_result(Some(2), "", "blocked by policy\n"),
            Some("turn-1".to_string()),
        );

        assert_eq!(
            parsed.data,
            PreToolUseHandlerData {
                should_block: true,
                block_reason: Some("blocked by policy".to_string()),
                additional_contexts_for_model: Vec::new(),
                updated_input: None,
            }
        );
        assert_eq!(parsed.completed.run.status, HookRunStatus::Blocked);
        assert_eq!(
            parsed.completed.run.entries,
            vec![HookOutputEntry {
                kind: HookOutputEntryKind::Feedback,
                text: "blocked by policy".to_string(),
            }]
        );
    }

    #[test]
    fn legacy_ask_blocks_processing() {
        let parsed = parse_completed(
            &legacy_handler(HookFailurePolicy::Allow),
            run_result(
                Some(0),
                r#"{"decision":"ask","reason":"legacy ask should still block"}"#,
                "",
            ),
            Some("turn-1".to_string()),
        );

        assert_eq!(
            parsed.data,
            PreToolUseHandlerData {
                should_block: true,
                block_reason: Some("legacy ask should still block".to_string()),
                additional_contexts_for_model: Vec::new(),
                updated_input: None,
            }
        );
        assert_eq!(parsed.completed.run.status, HookRunStatus::Blocked);
    }

    #[test]
    fn legacy_fail_closed_blocks_on_failure() {
        let parsed = parse_completed(
            &legacy_handler(HookFailurePolicy::Deny),
            run_result(Some(1), "", "legacy hook exploded"),
            Some("turn-1".to_string()),
        );

        assert_eq!(
            parsed.data,
            PreToolUseHandlerData {
                should_block: true,
                block_reason: Some(
                    "Hook failed (fail-closed): Hook failed: legacy hook exploded".to_string()
                ),
                additional_contexts_for_model: Vec::new(),
                updated_input: None,
            }
        );
        assert_eq!(parsed.completed.run.status, HookRunStatus::Blocked);
    }

    #[test]
    fn preview_only_considers_legacy_handlers_when_canonical_handlers_are_disabled() {
        let mut request = request_for_tool_use("tool-call-123");
        request.tool_name = "update_plan".to_string();
        request.allow_canonical_handlers = false;
        let runs = preview(
            &[
                ConfiguredHandler {
                    matcher: None,
                    display_order: 0,
                    ..canonical_handler()
                },
                ConfiguredHandler {
                    matcher: None,
                    display_order: 1,
                    ..legacy_handler(HookFailurePolicy::Allow)
                },
            ],
            &request,
        );

        assert_eq!(runs.len(), 1);
        assert!(runs[0].id.contains("pre-tool-use:1:"));
    }

    #[test]
    fn legacy_handler_matches_exec_command_alias_when_canonical_handlers_are_disabled() {
        let mut request = request_for_tool_use("tool-call-123");
        request.tool_name = "Bash".to_string();
        request.matcher_aliases = vec!["exec_command".to_string()];
        request.allow_canonical_handlers = false;

        let runs = preview(&[legacy_handler(HookFailurePolicy::Allow)], &request);

        assert_eq!(runs.len(), 1);
        assert!(runs[0].id.contains("pre-tool-use:0:"));
    }

    #[test]
    fn preview_and_completed_run_ids_include_tool_use_id() {
        let request = request_for_tool_use("tool-call-123");
        let runs = preview(&[canonical_handler()], &request);

        assert_eq!(runs.len(), 1);
        assert_eq!(
            runs[0].id,
            format!(
                "pre-tool-use:0:{}:tool-call-123",
                test_path_buf("/tmp/hooks.json").display()
            )
        );

        let parsed = parse_completed(
            &canonical_handler(),
            run_result(Some(0), "", ""),
            Some("turn-1".to_string()),
        );
        let completed = common::hook_completed_for_tool_use(parsed.completed, &request.tool_use_id);

        assert_eq!(completed.run.id, runs[0].id);
    }

    #[test]
    fn serialization_failure_run_ids_include_tool_use_id() {
        let request = request_for_tool_use("tool-call-123");
        let runs = preview(&[canonical_handler()], &request);

        let completed = common::serialization_failure_hook_events_for_tool_use(
            vec![canonical_handler()],
            Some(request.turn_id.clone()),
            "serialize failed".into(),
            &request.tool_use_id,
        );

        assert_eq!(completed.len(), 1);
        assert_eq!(completed[0].run.id, runs[0].id);
    }

    fn handler() -> ConfiguredHandler {
        canonical_handler()
    }

    fn canonical_handler() -> ConfiguredHandler {
        ConfiguredHandler {
            event_name: HookEventName::PreToolUse,
            matcher: Some("^Bash$".to_string()),
            command: "echo hook".to_string(),
            execution: HandlerExecution::ShellCommand,
            behavior: ConfiguredHandlerBehavior::Canonical,
            timeout_sec: 5,
            status_message: None,
            additional_context_limit: Default::default(),
            source_path: test_path_buf("/tmp/hooks.json").abs(),
            source: codex_protocol::protocol::HookSource::User,
            display_order: 0,
            env: std::collections::HashMap::new(),
        }
    }

    fn legacy_handler(on_failure: HookFailurePolicy) -> ConfiguredHandler {
        ConfiguredHandler {
            event_name: HookEventName::PreToolUse,
            matcher: Some("^exec_command$".to_string()),
            command: "python3 hook.py".to_string(),
            execution: HandlerExecution::Argv(vec!["python3".to_string(), "hook.py".to_string()]),
            behavior: ConfiguredHandlerBehavior::LegacyPreToolUse { on_failure },
            timeout_sec: 5,
            status_message: None,
            source_path: test_path_buf("/tmp/legacy-config.toml").abs(),
            source: codex_protocol::protocol::HookSource::User,
            display_order: 0,
            env: std::collections::HashMap::new(),
        }
    }

    fn run_result(exit_code: Option<i32>, stdout: &str, stderr: &str) -> CommandRunResult {
        CommandRunResult {
            started_at: 1,
            completed_at: 2,
            duration_ms: 1,
            exit_code,
            stdout: stdout.to_string(),
            stderr: stderr.to_string(),
            error: None,
        }
    }

    fn request_for_tool_use(tool_use_id: &str) -> super::PreToolUseRequest {
        super::PreToolUseRequest {
            session_id: ThreadId::new(),
            turn_id: "turn-1".to_string(),
            subagent: None,
            cwd: test_path_buf("/tmp").abs(),
            transcript_path: None,
            model: "gpt-test".to_string(),
            permission_mode: "default".to_string(),
            tool_name: "Bash".to_string(),
            matcher_aliases: Vec::new(),
            allow_canonical_handlers: true,
            tool_use_id: tool_use_id.to_string(),
            tool_input: serde_json::json!({ "command": "echo hello" }),
        }
    }
}
