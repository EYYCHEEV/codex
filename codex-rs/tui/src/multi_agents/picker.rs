//! Presentation data and formatting helpers for the `/agent` picker.

use codex_protocol::ThreadId;
use codex_protocol::openai_models::ReasoningEffort as ReasoningEffortConfig;
use ratatui::style::Stylize;
use ratatui::text::Span;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct AgentPickerThreadEntry {
    /// Human-friendly nickname shown in picker rows and footer labels.
    pub(crate) agent_nickname: Option<String>,
    /// Agent type shown in brackets when present, for example `worker`.
    pub(crate) agent_role: Option<String>,
    /// Canonical v2 agent path, when the thread was observed through v2 activity.
    pub(crate) agent_path: Option<String>,
    /// Effective model selected by core for this agent, when observed.
    pub(crate) model: Option<String>,
    /// Effective reasoning effort selected by core for this agent, when observed.
    pub(crate) reasoning_effort: Option<ReasoningEffortConfig>,
    /// Whether the latest liveness refresh says the agent thread is actively working.
    pub(crate) is_running: bool,
    /// Whether the thread has emitted a close event and should render dimmed.
    pub(crate) is_closed: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct SubAgentActivityDisplay {
    pub(crate) thread_id: ThreadId,
    pub(crate) agent_path: String,
    pub(crate) agent_type: Option<String>,
    pub(crate) model: Option<String>,
    pub(crate) reasoning_effort: Option<ReasoningEffortConfig>,
    pub(crate) is_running_hint: bool,
}

pub(crate) fn agent_picker_status_dot_spans(is_closed: bool) -> Vec<Span<'static>> {
    let dot = if is_closed {
        "•".into()
    } else {
        "•".green()
    };
    vec![dot, " ".into()]
}

pub(crate) fn format_agent_picker_item_name(
    agent_nickname: Option<&str>,
    agent_role: Option<&str>,
    is_primary: bool,
) -> String {
    if is_primary {
        return "Main [default]".to_string();
    }

    let agent_nickname = agent_nickname
        .map(str::trim)
        .filter(|nickname| !nickname.is_empty());
    let agent_role = agent_role.map(str::trim).filter(|role| !role.is_empty());
    match (agent_nickname, agent_role) {
        (Some(agent_nickname), Some(agent_role)) => format!("{agent_nickname} [{agent_role}]"),
        (Some(agent_nickname), None) => agent_nickname.to_string(),
        (None, Some(agent_role)) => format!("[{agent_role}]"),
        (None, None) => "Agent".to_string(),
    }
}

pub(crate) fn format_agent_picker_entry_name(
    agent_path: Option<&str>,
    agent_nickname: Option<&str>,
    agent_role: Option<&str>,
    is_primary: bool,
) -> String {
    if is_primary {
        return format_agent_picker_item_name(agent_nickname, agent_role, /*is_primary*/ true);
    }

    let agent_path = agent_path
        .map(str::trim)
        .filter(|agent_path| !agent_path.is_empty());
    let agent_role = agent_role.map(str::trim).filter(|role| !role.is_empty());
    match (agent_path, agent_role) {
        (Some(agent_path), Some(agent_role)) => format!("{agent_path} [{agent_role}]"),
        (Some(agent_path), None) => agent_path.to_string(),
        (None, _) => format_agent_picker_item_name(agent_nickname, agent_role, false),
    }
}

pub(crate) fn format_agent_picker_item_description(
    agent_role: Option<&str>,
    model: Option<&str>,
    reasoning_effort: Option<&ReasoningEffortConfig>,
    is_running: bool,
    is_closed: bool,
) -> String {
    let status = if is_closed {
        "closed"
    } else if is_running {
        "running"
    } else {
        "idle"
    };
    let route = [
        agent_role
            .map(str::trim)
            .filter(|agent_role| !agent_role.is_empty())
            .map(|agent_role| format!("[{agent_role}]")),
        model
            .map(str::trim)
            .filter(|model| !model.is_empty())
            .map(str::to_string),
        reasoning_effort.map(|effort| effort.as_str().to_string()),
    ]
    .into_iter()
    .flatten()
    .collect::<Vec<_>>()
    .join(" ");
    if route.is_empty() {
        status.to_string()
    } else {
        format!("{route}  {status}")
    }
}
