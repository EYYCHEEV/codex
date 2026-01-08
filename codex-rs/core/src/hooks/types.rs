//! Claude-compatible JSON protocol types for hooks.

use serde::Deserialize;
use serde::Serialize;

/// Input sent to hook via stdin (Claude-compatible snake_case).
#[derive(Serialize, Debug)]
pub struct HookInput {
    /// Always "PreToolUse" for this hook type.
    pub hook_event_name: &'static str,
    /// Name of the tool being called.
    pub tool_name: String,
    /// Tool arguments as JSON.
    pub tool_input: serde_json::Value,
    /// Unique identifier for this tool call.
    pub tool_use_id: String,
    /// Session/conversation identifier.
    pub session_id: String,
    /// Current working directory.
    pub cwd: String,
    /// Path to session transcript/history file.
    pub transcript_path: String,
}

/// Output from hook - Claude-compatible structure.
/// Supports both legacy top-level and nested hookSpecificOutput.
#[derive(Deserialize, Debug, Default)]
#[serde(rename_all = "camelCase")]
pub struct HookOutput {
    // --- Claude's preferred nested structure ---
    #[serde(default)]
    pub hook_specific_output: Option<HookSpecificOutput>,

    // --- Legacy top-level fields (deprecated but supported) ---
    /// Legacy: use hookSpecificOutput.permissionDecision instead
    #[serde(default)]
    pub decision: Option<HookDecision>,
    /// Legacy: use hookSpecificOutput.permissionDecisionReason instead
    #[serde(default)]
    pub reason: Option<String>,
}

/// Nested output structure (Claude's preferred format).
#[derive(Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct HookSpecificOutput {
    #[serde(default)]
    pub permission_decision: Option<HookDecision>,
    #[serde(default)]
    pub permission_decision_reason: Option<String>,
    // Note: Claude also supports updatedInput for input mutation.
    // This implementation accepts but ignores that field (read-only hook model).
}

impl HookOutput {
    /// Get effective decision (prefers hookSpecificOutput over legacy top-level).
    pub fn decision(&self) -> HookDecision {
        // First: check hookSpecificOutput.permissionDecision (Claude preferred)
        if let Some(ref hso) = self.hook_specific_output
            && let Some(ref d) = hso.permission_decision
        {
            return d.clone();
        }
        // Fallback: legacy top-level decision field
        self.decision.clone().unwrap_or_default()
    }

    /// Get effective reason (prefers hookSpecificOutput over legacy top-level).
    pub fn reason(&self) -> Option<String> {
        // First: hookSpecificOutput.permissionDecisionReason
        if let Some(ref hso) = self.hook_specific_output
            && hso.permission_decision_reason.is_some()
        {
            return hso.permission_decision_reason.clone();
        }
        // Fallback: legacy top-level reason field
        self.reason.clone()
    }
}

/// Hook decision for whether to allow or deny the tool call.
#[derive(Deserialize, Debug, Clone, PartialEq, Default)]
#[serde(rename_all = "lowercase")]
pub enum HookDecision {
    #[default]
    #[serde(alias = "approve")] // Claude legacy: "approve" → Allow
    Allow,
    #[serde(alias = "block")] // Claude legacy: "block" → Deny
    Deny,
    /// Treated as Deny (Codex doesn't have Claude's approval flow).
    Ask,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hook_output_default_allows() {
        let output = HookOutput::default();
        assert_eq!(output.decision(), HookDecision::Allow);
    }

    #[test]
    fn test_legacy_decision_parsing() {
        let json = r#"{"decision": "deny", "reason": "blocked"}"#;
        let output: HookOutput = serde_json::from_str(json).unwrap();
        assert_eq!(output.decision(), HookDecision::Deny);
        assert_eq!(output.reason(), Some("blocked".to_string()));
    }

    #[test]
    fn test_nested_decision_parsing() {
        let json = r#"{
            "hookSpecificOutput": {
                "permissionDecision": "deny",
                "permissionDecisionReason": "dangerous command"
            }
        }"#;
        let output: HookOutput = serde_json::from_str(json).unwrap();
        assert_eq!(output.decision(), HookDecision::Deny);
        assert_eq!(output.reason(), Some("dangerous command".to_string()));
    }

    #[test]
    fn test_nested_takes_precedence() {
        let json = r#"{
            "decision": "allow",
            "reason": "legacy",
            "hookSpecificOutput": {
                "permissionDecision": "deny",
                "permissionDecisionReason": "nested"
            }
        }"#;
        let output: HookOutput = serde_json::from_str(json).unwrap();
        assert_eq!(output.decision(), HookDecision::Deny);
        assert_eq!(output.reason(), Some("nested".to_string()));
    }

    #[test]
    fn test_legacy_aliases() {
        // Test "block" alias for deny
        let json = r#"{"decision": "block"}"#;
        let output: HookOutput = serde_json::from_str(json).unwrap();
        assert_eq!(output.decision(), HookDecision::Deny);

        // Test "approve" alias for allow
        let json = r#"{"decision": "approve"}"#;
        let output: HookOutput = serde_json::from_str(json).unwrap();
        assert_eq!(output.decision(), HookDecision::Allow);
    }
}
