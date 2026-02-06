use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;
use std::time::Instant;

use crate::client_common::tools::ToolSpec;
use crate::function_tool::FunctionCallError;
use crate::hooks::run_pre_tool_use_hooks;
use crate::protocol::SandboxPolicy;
use crate::sandbox_tags::sandbox_tag;
use crate::tools::context::ToolInvocation;
use crate::tools::context::ToolOutput;
use crate::tools::context::ToolPayload;
use async_trait::async_trait;
use codex_hooks::HookEvent;
use codex_hooks::HookEventAfterToolUse;
use codex_hooks::HookPayload;
use codex_hooks::HookToolInput;
use codex_hooks::HookToolInputLocalShell;
use codex_hooks::HookToolKind;
use codex_protocol::models::ResponseInputItem;
use codex_utils_readiness::Readiness;
use tracing::warn;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ToolKind {
    Function,
    Mcp,
}

#[async_trait]
pub trait ToolHandler: Send + Sync {
    fn kind(&self) -> ToolKind;

    fn matches_kind(&self, payload: &ToolPayload) -> bool {
        matches!(
            (self.kind(), payload),
            (ToolKind::Function, ToolPayload::Function { .. })
                | (ToolKind::Mcp, ToolPayload::Mcp { .. })
        )
    }

    /// Returns `true` if the [ToolInvocation] *might* mutate the environment of the
    /// user (through file system, OS operations, ...).
    /// This function must remains defensive and return `true` if a doubt exist on the
    /// exact effect of a ToolInvocation.
    async fn is_mutating(&self, _invocation: &ToolInvocation) -> bool {
        false
    }

    /// Perform the actual [ToolInvocation] and returns a [ToolOutput] containing
    /// the final output to return to the model.
    async fn handle(&self, invocation: ToolInvocation) -> Result<ToolOutput, FunctionCallError>;
}

pub struct ToolRegistry {
    handlers: HashMap<String, Arc<dyn ToolHandler>>,
}

impl ToolRegistry {
    pub fn new(handlers: HashMap<String, Arc<dyn ToolHandler>>) -> Self {
        Self { handlers }
    }

    pub fn handler(&self, name: &str) -> Option<Arc<dyn ToolHandler>> {
        self.handlers.get(name).map(Arc::clone)
    }

    // TODO(jif) for dynamic tools.
    // pub fn register(&mut self, name: impl Into<String>, handler: Arc<dyn ToolHandler>) {
    //     let name = name.into();
    //     if self.handlers.insert(name.clone(), handler).is_some() {
    //         warn!("overwriting handler for tool {name}");
    //     }
    // }

    pub async fn dispatch(
        &self,
        invocation: ToolInvocation,
    ) -> Result<ResponseInputItem, FunctionCallError> {
        let tool_name = invocation.tool_name.clone();
        let call_id_owned = invocation.call_id.clone();
        let otel = invocation.turn.otel_manager.clone();
        let payload_for_response = invocation.payload.clone();
        let log_payload = payload_for_response.log_payload();
        let metric_tags = [
            (
                "sandbox",
                sandbox_tag(
                    &invocation.turn.sandbox_policy,
                    invocation.turn.windows_sandbox_level,
                ),
            ),
            (
                "sandbox_policy",
                sandbox_policy_tag(&invocation.turn.sandbox_policy),
            ),
        ];

        let handler = match self.handler(tool_name.as_ref()) {
            Some(handler) => handler,
            None => {
                let message =
                    unsupported_tool_call_message(&invocation.payload, tool_name.as_ref());
                otel.tool_result_with_tags(
                    tool_name.as_ref(),
                    &call_id_owned,
                    log_payload.as_ref(),
                    Duration::ZERO,
                    false,
                    &message,
                    &metric_tags,
                );
                return Err(FunctionCallError::RespondToModel(message));
            }
        };

        if !handler.matches_kind(&invocation.payload) {
            let message = format!("tool {tool_name} invoked with incompatible payload");
            otel.tool_result_with_tags(
                tool_name.as_ref(),
                &call_id_owned,
                log_payload.as_ref(),
                Duration::ZERO,
                false,
                &message,
                &metric_tags,
            );
            return Err(FunctionCallError::Fatal(message));
        }

        let is_mutating = handler.is_mutating(&invocation).await;

        // --- PreToolUse hooks (after validation, before execution) ---
        // IMPORTANT: Bind Arc to variable first to avoid lifetime issues
        let config = Arc::clone(&invocation.turn.config);
        if !config.hooks.pre_tool_use.is_empty() {
            let tool_input = extract_tool_input_for_hooks(&invocation.payload);
            let session_id = invocation.session.conversation_id().to_string();
            let cwd = invocation.turn.cwd.to_string_lossy().to_string();

            // Transcript path: history.jsonl in codex_home
            let transcript_path = config
                .codex_home
                .join("history.jsonl")
                .to_string_lossy()
                .to_string();

            let hook_started = Instant::now();
            if let Err(reason) = run_pre_tool_use_hooks(
                &config.hooks,
                &tool_name,
                tool_input,
                &call_id_owned,
                &session_id,
                &cwd,
                &transcript_path,
            )
            .await
            {
                otel.tool_result_with_tags(
                    tool_name.as_ref(),
                    &call_id_owned,
                    log_payload.as_ref(),
                    hook_started.elapsed(),
                    false,
                    &reason,
                    &metric_tags,
                );
                return Err(FunctionCallError::RespondToModel(reason));
            }
        }
        // --- END PreToolUse hooks ---

        let output_cell = tokio::sync::Mutex::new(None);
        let invocation_for_tool = invocation.clone();

        let started = Instant::now();
        let result = otel
            .log_tool_result_with_tags(
                tool_name.as_ref(),
                &call_id_owned,
                log_payload.as_ref(),
                &metric_tags,
                || {
                    let handler = handler.clone();
                    let output_cell = &output_cell;
                    async move {
                        if is_mutating {
                            tracing::trace!("waiting for tool gate");
                            invocation_for_tool.turn.tool_call_gate.wait_ready().await;
                            tracing::trace!("tool gate released");
                        }
                        match handler.handle(invocation_for_tool).await {
                            Ok(output) => {
                                let preview = output.log_preview();
                                let success = output.success_for_logging();
                                let mut guard = output_cell.lock().await;
                                *guard = Some(output);
                                Ok((preview, success))
                            }
                            Err(err) => Err(err),
                        }
                    }
                },
            )
            .await;
        let duration = started.elapsed();
        let (output_preview, success) = match &result {
            Ok((preview, success)) => (preview.clone(), *success),
            Err(err) => (err.to_string(), false),
        };
        dispatch_after_tool_use_hook(AfterToolUseHookDispatch {
            invocation: &invocation,
            output_preview,
            success,
            executed: true,
            duration,
            mutating: is_mutating,
        })
        .await;

        match result {
            Ok(_) => {
                let mut guard = output_cell.lock().await;
                let output = guard.take().ok_or_else(|| {
                    FunctionCallError::Fatal("tool produced no output".to_string())
                })?;
                Ok(output.into_response(&call_id_owned, &payload_for_response))
            }
            Err(err) => Err(err),
        }
    }
}

#[derive(Debug, Clone)]
pub struct ConfiguredToolSpec {
    pub spec: ToolSpec,
    pub supports_parallel_tool_calls: bool,
}

impl ConfiguredToolSpec {
    pub fn new(spec: ToolSpec, supports_parallel_tool_calls: bool) -> Self {
        Self {
            spec,
            supports_parallel_tool_calls,
        }
    }
}

pub struct ToolRegistryBuilder {
    handlers: HashMap<String, Arc<dyn ToolHandler>>,
    specs: Vec<ConfiguredToolSpec>,
}

impl ToolRegistryBuilder {
    pub fn new() -> Self {
        Self {
            handlers: HashMap::new(),
            specs: Vec::new(),
        }
    }

    pub fn push_spec(&mut self, spec: ToolSpec) {
        self.push_spec_with_parallel_support(spec, false);
    }

    pub fn push_spec_with_parallel_support(
        &mut self,
        spec: ToolSpec,
        supports_parallel_tool_calls: bool,
    ) {
        self.specs
            .push(ConfiguredToolSpec::new(spec, supports_parallel_tool_calls));
    }

    pub fn register_handler(&mut self, name: impl Into<String>, handler: Arc<dyn ToolHandler>) {
        let name = name.into();
        if self
            .handlers
            .insert(name.clone(), handler.clone())
            .is_some()
        {
            warn!("overwriting handler for tool {name}");
        }
    }

    // TODO(jif) for dynamic tools.
    // pub fn register_many<I>(&mut self, names: I, handler: Arc<dyn ToolHandler>)
    // where
    //     I: IntoIterator,
    //     I::Item: Into<String>,
    // {
    //     for name in names {
    //         let name = name.into();
    //         if self
    //             .handlers
    //             .insert(name.clone(), handler.clone())
    //             .is_some()
    //         {
    //             warn!("overwriting handler for tool {name}");
    //         }
    //     }
    // }

    pub fn build(self) -> (Vec<ConfiguredToolSpec>, ToolRegistry) {
        let registry = ToolRegistry::new(self.handlers);
        (self.specs, registry)
    }
}

fn unsupported_tool_call_message(payload: &ToolPayload, tool_name: &str) -> String {
    match payload {
        ToolPayload::Custom { .. } => format!("unsupported custom tool call: {tool_name}"),
        _ => format!("unsupported call: {tool_name}"),
    }
}

fn sandbox_policy_tag(policy: &SandboxPolicy) -> &'static str {
    match policy {
        SandboxPolicy::ReadOnly { .. } => "read-only",
        SandboxPolicy::WorkspaceWrite { .. } => "workspace-write",
        SandboxPolicy::DangerFullAccess => "danger-full-access",
        SandboxPolicy::ExternalSandbox { .. } => "external-sandbox",
    }
}

// Hooks use a separate wire-facing input type so hook payload JSON stays stable
// and decoupled from core's internal tool runtime representation.
impl From<&ToolPayload> for HookToolInput {
    fn from(payload: &ToolPayload) -> Self {
        match payload {
            ToolPayload::Function { arguments } => HookToolInput::Function {
                arguments: arguments.clone(),
            },
            ToolPayload::Custom { input } => HookToolInput::Custom {
                input: input.clone(),
            },
            ToolPayload::LocalShell { params } => HookToolInput::LocalShell {
                params: HookToolInputLocalShell {
                    command: params.command.clone(),
                    workdir: params.workdir.clone(),
                    timeout_ms: params.timeout_ms,
                    sandbox_permissions: params.sandbox_permissions,
                    prefix_rule: params.prefix_rule.clone(),
                    justification: params.justification.clone(),
                },
            },
            ToolPayload::Mcp {
                server,
                tool,
                raw_arguments,
            } => HookToolInput::Mcp {
                server: server.clone(),
                tool: tool.clone(),
                arguments: raw_arguments.clone(),
            },
        }
    }
}

fn hook_tool_kind(tool_input: &HookToolInput) -> HookToolKind {
    match tool_input {
        HookToolInput::Function { .. } => HookToolKind::Function,
        HookToolInput::Custom { .. } => HookToolKind::Custom,
        HookToolInput::LocalShell { .. } => HookToolKind::LocalShell,
        HookToolInput::Mcp { .. } => HookToolKind::Mcp,
    }
}

struct AfterToolUseHookDispatch<'a> {
    invocation: &'a ToolInvocation,
    output_preview: String,
    success: bool,
    executed: bool,
    duration: Duration,
    mutating: bool,
}

async fn dispatch_after_tool_use_hook(dispatch: AfterToolUseHookDispatch<'_>) {
    let AfterToolUseHookDispatch { invocation, .. } = dispatch;
    let session = invocation.session.as_ref();
    let turn = invocation.turn.as_ref();
    let tool_input = HookToolInput::from(&invocation.payload);
    session
        .hooks()
        .dispatch(HookPayload {
            session_id: session.conversation_id,
            cwd: turn.cwd.clone(),
            triggered_at: chrono::Utc::now(),
            hook_event: HookEvent::AfterToolUse {
                event: HookEventAfterToolUse {
                    turn_id: turn.sub_id.clone(),
                    call_id: invocation.call_id.clone(),
                    tool_name: invocation.tool_name.clone(),
                    tool_kind: hook_tool_kind(&tool_input),
                    tool_input,
                    executed: dispatch.executed,
                    success: dispatch.success,
                    duration_ms: u64::try_from(dispatch.duration.as_millis()).unwrap_or(u64::MAX),
                    mutating: dispatch.mutating,
                    sandbox: sandbox_tag(&turn.sandbox_policy, turn.windows_sandbox_level)
                        .to_string(),
                    sandbox_policy: sandbox_policy_tag(&turn.sandbox_policy).to_string(),
                    output_preview: dispatch.output_preview.clone(),
                },
            },
        })
        .await;
}

/// Extract tool input as JSON Value for PreToolUse hooks.
/// Normalizes shell command arrays to strings for Claude hook compatibility.
fn extract_tool_input_for_hooks(payload: &ToolPayload) -> serde_json::Value {
    match payload {
        ToolPayload::Function { arguments } => {
            // Parse and normalize: if command is array, join to string
            if let Ok(mut value) = serde_json::from_str::<serde_json::Value>(arguments) {
                normalize_command_to_string(&mut value);
                value
            } else {
                serde_json::Value::Null
            }
        }
        ToolPayload::LocalShell { params } => {
            // LocalShell: command is Vec<String>, join to string
            serde_json::json!({
                "command": params.command.join(" "),
            })
        }
        ToolPayload::Mcp { raw_arguments, .. } => {
            serde_json::from_str(raw_arguments).unwrap_or(serde_json::Value::Null)
        }
        ToolPayload::Custom { input } => serde_json::Value::String(input.clone()),
    }
}

/// Normalize command field to string if it's an array, and map `cmd` to
/// `command` when `command` is absent.
/// This enables Claude's hook scripts that expect tool_input.command as string.
fn normalize_command_to_string(value: &mut serde_json::Value) {
    if let serde_json::Value::Object(obj) = value {
        let cmd_alias = obj
            .get("cmd")
            .and_then(|value| value.as_str())
            .map(ToOwned::to_owned);
        if !obj.contains_key("command")
            && let Some(cmd_alias) = cmd_alias
        {
            obj.insert("command".to_string(), serde_json::Value::String(cmd_alias));
        }

        if let Some(command) = obj.get_mut("command")
            && let serde_json::Value::Array(command) = command
        {
            let joined = command
                .iter()
                .filter_map(|value| value.as_str())
                .collect::<Vec<_>>()
                .join(" ");
            *command = serde_json::Value::String(joined);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::normalize_command_to_string;
    use pretty_assertions::assert_eq;
    use serde_json::json;

    #[test]
    fn normalize_command_array_to_string() {
        let mut value = json!({
            "command": ["echo", "hello"],
        });

        normalize_command_to_string(&mut value);

        assert_eq!(
            value,
            json!({
                "command": "echo hello",
            })
        );
    }

    #[test]
    fn normalize_cmd_alias_to_command() {
        let mut value = json!({
            "cmd": "echo hello",
        });

        normalize_command_to_string(&mut value);

        assert_eq!(
            value,
            json!({
                "cmd": "echo hello",
                "command": "echo hello",
            })
        );
    }

    #[test]
    fn normalize_preserves_existing_command_when_cmd_exists() {
        let mut value = json!({
            "cmd": "echo hello",
            "command": "echo from command",
        });

        normalize_command_to_string(&mut value);

        assert_eq!(
            value,
            json!({
                "cmd": "echo hello",
                "command": "echo from command",
            })
        );
    }
}
