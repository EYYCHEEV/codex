//! Hook-facing tool names and matcher compatibility aliases.
//!
//! Hook stdin exposes one canonical `tool_name`, but matcher selection may also
//! need to recognize names from adjacent tool ecosystems. Keeping those two
//! concepts together prevents handlers from accidentally serializing a
//! compatibility alias, such as `Write`, as the stable hook payload name.

/// Identifies a tool in hook payloads and hook matcher selection.
///
/// `name` is the canonical value serialized into hook stdin. Matcher aliases are
/// internal-only compatibility names that may select the same hook handlers but
/// must not change the payload seen by hook processes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct HookToolName {
    name: String,
    matcher_aliases: Vec<String>,
}

impl HookToolName {
    /// Builds a hook tool name with no matcher aliases.
    pub(crate) fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            matcher_aliases: Vec::new(),
        }
    }

    /// Returns the hook identity for file edits performed through `apply_patch`.
    ///
    /// The serialized name remains `apply_patch` so logs and policies can key
    /// off the actual Codex tool. `Write` and `Edit` are accepted as matcher
    /// aliases for compatibility with hook configurations that describe edits
    /// using Claude Code-style names.
    pub(crate) fn apply_patch() -> Self {
        Self {
            name: "apply_patch".to_string(),
            matcher_aliases: vec!["Write".to_string(), "Edit".to_string()],
        }
    }

    /// Returns the hook identity for spawning sub-agents.
    ///
    /// The serialized name remains `spawn_agent`, while `Agent` is accepted as
    /// a matcher alias for compatibility with hook configurations that describe
    /// sub-agent creation using Claude Code-style names.
    pub(crate) fn spawn_agent() -> Self {
        Self {
            name: "spawn_agent".to_string(),
            matcher_aliases: vec!["Agent".to_string()],
        }
    }

    /// Returns the hook identity historically used for permission hooks on
    /// shell-like tools.
    pub(crate) fn bash() -> Self {
        Self {
            name: "Bash".to_string(),
            matcher_aliases: vec![
                "shell_command".to_string(),
                "exec_command".to_string(),
                "local_shell".to_string(),
            ],
        }
    }

    /// Returns the hook identity for a shell-family tool call.
    ///
    /// Hook stdin preserves the actual invoked Codex tool name
    /// (`shell_command`, `exec_command`, `local_shell`, or `shell`) while hook
    /// matcher selection also accepts the sibling shell tool names plus the
    /// historical `Bash` matcher.
    pub(crate) fn shell(name: impl Into<String>) -> Self {
        let name = name.into();
        let mut matcher_aliases = vec![
            "Bash".to_string(),
            "shell".to_string(),
            "shell_command".to_string(),
            "exec_command".to_string(),
            "local_shell".to_string(),
        ];
        matcher_aliases.retain(|alias| alias != &name);
        Self {
            name,
            matcher_aliases,
        }
    }

    /// Returns the canonical hook name serialized into hook stdin.
    pub(crate) fn name(&self) -> &str {
        &self.name
    }

    /// Returns additional matcher inputs that should select the same handlers.
    pub(crate) fn matcher_aliases(&self) -> &[String] {
        &self.matcher_aliases
    }

    pub(crate) fn is_shell_family(&self) -> bool {
        matches!(
            self.name.as_str(),
            "Bash" | "shell" | "shell_command" | "exec_command" | "local_shell"
        )
    }
}
