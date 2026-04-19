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
use futures::future::join_all;
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
use crate::schema::PreToolUseCommandInput;
use crate::schema::PreToolUseToolInput;

#[derive(Debug, Clone)]
pub struct PreToolUseRequest {
    pub session_id: ThreadId,
    pub turn_id: String,
    pub cwd: AbsolutePathBuf,
    pub transcript_path: Option<PathBuf>,
    pub model: String,
    pub permission_mode: String,
    pub tool_name: String,
    pub canonical_tool_name: Option<String>,
    pub canonical_command: Option<String>,
    pub tool_use_id: String,
    pub tool_input: Value,
}

#[derive(Debug)]
pub struct PreToolUseOutcome {
    pub hook_events: Vec<HookCompletedEvent>,
    pub should_block: bool,
    pub block_reason: Option<String>,
}

#[derive(Debug, Default, PartialEq, Eq)]
struct PreToolUseHandlerData {
    should_block: bool,
    block_reason: Option<String>,
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
    request: PreToolUseRequest,
) -> PreToolUseOutcome {
    let matched = matched_handlers(handlers, &request);
    if matched.is_empty() {
        return PreToolUseOutcome {
            hook_events: Vec::new(),
            should_block: false,
            block_reason: None,
        };
    }

    let canonical_input = matched
        .iter()
        .any(|matched| matched.input_kind == PreToolUseInputKind::Canonical)
        .then(|| canonical_input_json(&request));
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
    }
}

struct CollectedOutcome {
    hook_events: Vec<HookCompletedEvent>,
    should_block: bool,
    block_reason: Option<String>,
}

fn collect_outcome(
    results: Vec<dispatcher::ParsedHandler<PreToolUseHandlerData>>,
    tool_use_id: &str,
) -> CollectedOutcome {
    let should_block = results.iter().any(|result| result.data.should_block);
    let block_reason = results
        .iter()
        .find_map(|result| result.data.block_reason.clone());
    let hook_events = results
        .into_iter()
        .map(|result| common::hook_completed_for_tool_use(result.completed, tool_use_id))
        .collect();
    CollectedOutcome {
        hook_events,
        should_block,
        block_reason,
    }
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
    join_all(handlers.into_iter().map(|handler| {
        let canonical_input = canonical_input.clone();
        let legacy_input = legacy_input.clone();
        let turn_id = turn_id.clone();
        let tool_use_id = tool_use_id.to_string();
        async move {
            let input_json =
                input_json_for_handler(handler.input_kind, &canonical_input, &legacy_input);
            let handler = handler.handler;
            match input_json {
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
            }
        }
    }))
    .await
}

fn matched_handlers(
    handlers: &[ConfiguredHandler],
    request: &PreToolUseRequest,
) -> Vec<MatchedPreToolUseHandler> {
    handlers
        .iter()
        .filter(|handler| handler.event_name == HookEventName::PreToolUse)
        .filter_map(|handler| match &handler.behavior {
            ConfiguredHandlerBehavior::Canonical => request
                .canonical_tool_name
                .as_deref()
                .filter(|tool_name| matches_matcher(handler.matcher.as_deref(), Some(tool_name)))
                .map(|_| MatchedPreToolUseHandler {
                    handler: handler.clone(),
                    input_kind: PreToolUseInputKind::Canonical,
                }),
            ConfiguredHandlerBehavior::LegacyPreToolUse { .. } => {
                matches_matcher(handler.matcher.as_deref(), Some(&request.tool_name)).then(|| {
                    MatchedPreToolUseHandler {
                        handler: handler.clone(),
                        input_kind: PreToolUseInputKind::Legacy,
                    }
                })
            }
        })
        .collect()
}

fn canonical_input_json(request: &PreToolUseRequest) -> Result<String, String> {
    let canonical_tool_name = request
        .canonical_tool_name
        .clone()
        .ok_or_else(|| "missing canonical tool name for PreToolUse hook".to_string())?;
    let command = request
        .canonical_command
        .as_deref()
        .ok_or_else(|| "missing canonical command for PreToolUse hook".to_string())?;

    serde_json::to_string(&PreToolUseCommandInput {
        session_id: request.session_id.to_string(),
        turn_id: request.turn_id.clone(),
        transcript_path: crate::schema::NullableString::from_path(request.transcript_path.clone()),
        cwd: request.cwd.display().to_string(),
        hook_event_name: "PreToolUse".to_string(),
        model: request.model.clone(),
        permission_mode: request.permission_mode.clone(),
        tool_name: canonical_tool_name,
        tool_input: PreToolUseToolInput {
            command: command.to_string(),
        },
        tool_use_id: request.tool_use_id.clone(),
    })
    .map_err(|error| format!("failed to serialize pre tool use hook input: {error}"))
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
                    } else if let Some(reason) = parsed.block_reason {
                        status = HookRunStatus::Blocked;
                        should_block = true;
                        block_reason = Some(reason.clone());
                        entries.push(HookOutputEntry {
                            kind: HookOutputEntryKind::Feedback,
                            text: reason,
                        });
                    }
                } else if trimmed_stdout.starts_with('{') || trimmed_stdout.starts_with('[') {
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
        },
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
    use codex_utils_absolute_path::AbsolutePathBuf;
    use codex_utils_absolute_path::test_support::PathBufExt;
    use codex_utils_absolute_path::test_support::test_path_buf;
    use pretty_assertions::assert_eq;
    use serde_json::json;
    use tempfile::tempdir;

    use super::PreToolUseHandlerData;
    use super::canonical_input_json;
    use super::parse_completed;
    use super::preview;
    use super::run;
    use crate::engine::CommandShell;
    use crate::engine::ConfiguredHandler;
    use crate::engine::ConfiguredHandlerBehavior;
    use crate::engine::HandlerExecution;
    use crate::engine::command_runner::CommandRunResult;
    use crate::events::common;

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
            }
        );
        assert_eq!(parsed.completed.run.status, HookRunStatus::Blocked);
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
    fn unsupported_additional_context_fails_open() {
        let parsed = parse_completed(
            &canonical_handler(),
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
                should_block: false,
                block_reason: None,
            }
        );
        assert_eq!(parsed.completed.run.status, HookRunStatus::Failed);
    }

    #[test]
    fn legacy_ask_blocks_processing() {
        let parsed = parse_completed(
            &legacy_handler(HookFailurePolicy::Deny),
            run_result(
                Some(0),
                r#"{"hookSpecificOutput":{"permissionDecision":"ask","permissionDecisionReason":"confirm manually"}}"#,
                "",
            ),
            Some("turn-1".to_string()),
        );

        assert_eq!(
            parsed.data,
            PreToolUseHandlerData {
                should_block: true,
                block_reason: Some("confirm manually".to_string()),
            }
        );
        assert_eq!(parsed.completed.run.status, HookRunStatus::Blocked);
    }

    #[test]
    fn legacy_invalid_json_denies_when_fail_closed() {
        let parsed = parse_completed(
            &legacy_handler(HookFailurePolicy::Deny),
            run_result(Some(0), "{", ""),
            Some("turn-1".to_string()),
        );

        assert_eq!(parsed.completed.run.status, HookRunStatus::Blocked);
        assert_eq!(
            parsed.data.block_reason,
            Some(
                "Hook failed (fail-closed): Parse hook output: EOF while parsing an object at line 1 column 1 (got: {)".to_string()
            )
        );
    }

    #[test]
    fn legacy_invalid_json_allows_when_fail_open() {
        let parsed = parse_completed(
            &legacy_handler(HookFailurePolicy::Allow),
            run_result(Some(0), "{", ""),
            Some("turn-1".to_string()),
        );

        assert_eq!(parsed.completed.run.status, HookRunStatus::Failed);
        assert_eq!(
            parsed.data,
            PreToolUseHandlerData {
                should_block: false,
                block_reason: None,
            }
        );
    }

    #[test]
    fn legacy_empty_command_denies_by_default() {
        let parsed = parse_completed(
            &ConfiguredHandler {
                execution: HandlerExecution::Argv(Vec::new()),
                ..legacy_handler(HookFailurePolicy::Deny)
            },
            CommandRunResult {
                started_at: 1,
                completed_at: 1,
                duration_ms: 0,
                exit_code: None,
                stdout: String::new(),
                stderr: String::new(),
                error: Some("Hook misconfigured: empty command".to_string()),
            },
            Some("turn-1".to_string()),
        );

        assert_eq!(parsed.completed.run.status, HookRunStatus::Blocked);
        assert_eq!(
            parsed.data.block_reason,
            Some("Hook failed (fail-closed): Hook misconfigured: empty command".to_string())
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
            }
        );
        assert_eq!(parsed.completed.run.status, HookRunStatus::Blocked);
    }

    #[test]
    fn legacy_preview_matches_actual_tool_name() {
        let request = super::PreToolUseRequest {
            session_id: ThreadId::new(),
            turn_id: "turn-1".to_string(),
            cwd: test_path_buf("/tmp").abs(),
            transcript_path: None,
            model: "gpt-test".to_string(),
            permission_mode: "default".to_string(),
            tool_name: "exec_command".to_string(),
            canonical_tool_name: None,
            canonical_command: None,
            tool_use_id: "tool-call-123".to_string(),
            tool_input: json!({"command": "rm -rf /"}),
        };

        let runs = preview(&[legacy_handler(HookFailurePolicy::Deny)], &request);
        assert_eq!(runs.len(), 1);
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

    #[test]
    fn canonical_input_prefers_canonical_command() {
        let mut request = request_for_tool_use("tool-call-123");
        request.canonical_command = Some("printf '%s\\n' 'hello world'".to_string());
        request.tool_input = json!({"command": "printf %s\\n hello world"});

        let input: serde_json::Value = serde_json::from_str(
            &canonical_input_json(&request).expect("canonical input should serialize"),
        )
        .expect("canonical input should parse");

        assert_eq!(
            input["tool_input"]["command"],
            "printf '%s\\n' 'hello world'"
        );
    }

    #[tokio::test]
    async fn mixed_handlers_preserve_match_order_for_block_reason_and_events() {
        let temp_dir = tempdir().expect("tempdir");
        let request = request_for_tool_use("tool-call-123");
        let shell = CommandShell {
            program: "zsh".to_string(),
            args: vec!["-lc".to_string()],
        };
        let handlers = vec![
            legacy_handler_with(
                "^shell_command$",
                0,
                HookFailurePolicy::Deny,
                vec![
                    "python3".to_string(),
                    "-c".to_string(),
                    "import json; print(json.dumps({'decision':'deny','reason':'legacy first'}))"
                        .to_string(),
                ],
            ),
            canonical_handler_with(
                1,
                "python3 -c \"import json; print(json.dumps({'decision':'block','reason':'canonical second'}))\"",
            ),
        ];

        let outcome = run(
            &handlers,
            &shell,
            super::PreToolUseRequest {
                cwd: AbsolutePathBuf::from_absolute_path(temp_dir.path())
                    .expect("tempdir path should be absolute"),
                ..request
            },
        )
        .await;

        assert!(outcome.should_block);
        assert_eq!(outcome.block_reason, Some("legacy first".to_string()));
        assert_eq!(
            outcome
                .hook_events
                .iter()
                .map(|event| event.run.display_order)
                .collect::<Vec<_>>(),
            vec![0, 1]
        );
    }

    fn canonical_handler() -> ConfiguredHandler {
        canonical_handler_with(0, "echo hook")
    }

    fn canonical_handler_with(display_order: i64, command: &str) -> ConfiguredHandler {
        ConfiguredHandler {
            event_name: HookEventName::PreToolUse,
            matcher: Some("^Bash$".to_string()),
            command: command.to_string(),
            execution: HandlerExecution::ShellCommand,
            behavior: ConfiguredHandlerBehavior::Canonical,
            timeout_sec: 5,
            status_message: None,
            source_path: test_path_buf("/tmp/hooks.json").abs(),
            display_order,
        }
    }

    fn legacy_handler(on_failure: HookFailurePolicy) -> ConfiguredHandler {
        legacy_handler_with(
            "^exec_command$",
            0,
            on_failure,
            vec!["python3".to_string(), "/tmp/hook.py".to_string()],
        )
    }

    fn legacy_handler_with(
        matcher: &str,
        display_order: i64,
        on_failure: HookFailurePolicy,
        command: Vec<String>,
    ) -> ConfiguredHandler {
        ConfiguredHandler {
            event_name: HookEventName::PreToolUse,
            matcher: Some(matcher.to_string()),
            command: command.join(" "),
            execution: HandlerExecution::Argv(command),
            behavior: ConfiguredHandlerBehavior::LegacyPreToolUse { on_failure },
            timeout_sec: 5,
            status_message: None,
            source_path: test_path_buf("/tmp/config.toml").abs(),
            display_order,
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
            cwd: test_path_buf("/tmp").abs(),
            transcript_path: None,
            model: "gpt-test".to_string(),
            permission_mode: "default".to_string(),
            tool_name: "shell_command".to_string(),
            canonical_tool_name: Some("Bash".to_string()),
            canonical_command: Some("echo hello".to_string()),
            tool_use_id: tool_use_id.to_string(),
            tool_input: json!({"command": "echo hello"}),
        }
    }
}
