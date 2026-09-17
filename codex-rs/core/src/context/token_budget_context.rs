use super::ContextualUserFragment;
use super::world_state::PreviousSectionState;
use super::world_state::WorldStateSection;
use codex_protocol::AgentPath;
use codex_protocol::models::ContentItemKind;
use codex_protocol::protocol::CONTEXT_WINDOW_CLOSE_TAG;
use codex_protocol::protocol::CONTEXT_WINDOW_GUIDANCE_CLOSE_TAG;
use codex_protocol::protocol::CONTEXT_WINDOW_GUIDANCE_OPEN_TAG;
use codex_protocol::protocol::CONTEXT_WINDOW_OPEN_TAG;
use uuid::Uuid;

// Keep the fully rendered and later-stamped context item below the 1K-token
// manual-review threshold. Each candidate includes its exact turn ID; reserve
// conservative framing allowance for the response-item ID and creation time
// that the history boundary attaches later.
const MAX_THREAD_HINT_ITEM_TOKENS: usize = 1_000;
const THREAD_HINT_STAMPING_HEADROOM_TOKENS: usize = 128;
const MAX_UNSTAMPED_THREAD_HINT_ITEM_BYTES: usize =
    (MAX_THREAD_HINT_ITEM_TOKENS - THREAD_HINT_STAMPING_HEADROOM_TOKENS) * 4;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct TokenBudgetContext {
    agent_path: AgentPath,
    first_window_id: Uuid,
    previous_window_id: Option<Uuid>,
    window_id: Uuid,
    thread_hint: Option<String>,
}

impl TokenBudgetContext {
    pub(crate) fn new(
        agent_path: AgentPath,
        first_window_id: Uuid,
        previous_window_id: Option<Uuid>,
        window_id: Uuid,
        turn_id: &str,
        thread_hint: Option<String>,
    ) -> Self {
        let mut context = Self {
            agent_path,
            first_window_id,
            previous_window_id,
            window_id,
            thread_hint: None,
        };
        context.thread_hint = thread_hint.and_then(|thread_hint| {
            truncate_thread_hint_to_item_budget(&context, turn_id, thread_hint)
        });
        context
    }
}

fn truncate_thread_hint_to_item_budget(
    context: &TokenBudgetContext,
    turn_id: &str,
    mut thread_hint: String,
) -> Option<String> {
    let max_raw_bytes = MAX_THREAD_HINT_ITEM_TOKENS * 4;
    if thread_hint.len() > max_raw_bytes {
        let mut end = max_raw_bytes;
        while !thread_hint.is_char_boundary(end) {
            end -= 1;
        }
        thread_hint.truncate(end);
    }

    if rendered_context_fits_item_budget(context, turn_id, &thread_hint) {
        return Some(thread_hint);
    }

    let boundaries = std::iter::once(0)
        .chain(
            thread_hint
                .char_indices()
                .skip(1)
                .map(|(boundary, _)| boundary),
        )
        .chain(std::iter::once(thread_hint.len()))
        .collect::<Vec<_>>();
    if !rendered_context_fits_item_budget(context, turn_id, "") {
        return None;
    }

    let mut fitting = 0;
    let mut too_large = boundaries.len() - 1;
    while fitting < too_large {
        let candidate = (fitting + too_large).div_ceil(2);
        if rendered_context_fits_item_budget(
            context,
            turn_id,
            &thread_hint[..boundaries[candidate]],
        ) {
            fitting = candidate;
        } else {
            too_large = candidate - 1;
        }
    }
    thread_hint.truncate(boundaries[fitting]);
    (!thread_hint.is_empty()).then_some(thread_hint)
}

fn rendered_context_fits_item_budget(
    context: &TokenBudgetContext,
    turn_id: &str,
    thread_hint: &str,
) -> bool {
    let mut candidate = context.clone();
    candidate.thread_hint = Some(thread_hint.to_string());
    let mut item = codex_protocol::models::ResponseItem::from(candidate.render_fragment());
    item.set_turn_id_if_missing(turn_id);
    serde_json::to_vec(&item)
        .is_ok_and(|serialized| serialized.len() <= MAX_UNSTAMPED_THREAD_HINT_ITEM_BYTES)
}

impl ContextualUserFragment for TokenBudgetContext {
    fn content_kind(&self) -> ContentItemKind {
        ContentItemKind("token_budget.context_window".to_string())
    }

    fn role(&self) -> &'static str {
        "developer"
    }

    fn requires_separate_message(&self) -> bool {
        true
    }

    fn markers(&self) -> (&'static str, &'static str) {
        Self::type_markers()
    }

    fn type_markers() -> (&'static str, &'static str) {
        (CONTEXT_WINDOW_OPEN_TAG, CONTEXT_WINDOW_CLOSE_TAG)
    }

    fn body(&self) -> String {
        let first_window_id = self.first_window_id;
        let window_id = self.window_id;
        let mut lines = vec![
            format!("Agent name: {}", self.agent_path),
            format!("First context window id: {first_window_id}"),
            format!("Current context window id: {window_id}"),
        ];
        if let Some(previous_window_id) = self.previous_window_id {
            lines.push(format!("Previous context window id: {previous_window_id}"));
        }
        if let Some(thread_hint) = &self.thread_hint {
            lines.push(thread_hint.clone());
        }
        format!("\n{}\n", lines.join("\n"))
    }
}

impl WorldStateSection for TokenBudgetContext {
    const ID: &'static str = "context_window";
    type Snapshot = AgentPath;

    fn snapshot(&self) -> Self::Snapshot {
        self.agent_path.clone()
    }

    fn render_diff(
        &self,
        previous: PreviousSectionState<'_, Self::Snapshot>,
    ) -> Option<Box<dyn ContextualUserFragment>> {
        matches!(previous, PreviousSectionState::Known(agent_path) if agent_path != &self.agent_path)
            .then(|| Box::new(self.clone()) as Box<dyn ContextualUserFragment>)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ContextWindowGuidance {
    message: String,
}

impl ContextWindowGuidance {
    pub(crate) fn new(message: &str) -> Self {
        Self {
            message: message.to_string(),
        }
    }
}

impl ContextualUserFragment for ContextWindowGuidance {
    fn content_kind(&self) -> ContentItemKind {
        ContentItemKind("token_budget.context_window_guidance".to_string())
    }

    fn role(&self) -> &'static str {
        "developer"
    }

    fn markers(&self) -> (&'static str, &'static str) {
        Self::type_markers()
    }

    fn type_markers() -> (&'static str, &'static str) {
        (
            CONTEXT_WINDOW_GUIDANCE_OPEN_TAG,
            CONTEXT_WINDOW_GUIDANCE_CLOSE_TAG,
        )
    }

    fn body(&self) -> String {
        format!("\n{}\n", self.message)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct TokenBudgetRemainingContext {
    tokens_left: Option<i64>,
}

impl TokenBudgetRemainingContext {
    pub(crate) fn new(tokens_left: i64) -> Self {
        Self {
            tokens_left: Some(tokens_left),
        }
    }

    pub(crate) fn unknown() -> Self {
        Self { tokens_left: None }
    }
}

impl ContextualUserFragment for TokenBudgetRemainingContext {
    fn content_kind(&self) -> ContentItemKind {
        ContentItemKind("token_budget.remaining_tokens".to_string())
    }

    fn role(&self) -> &'static str {
        "developer"
    }

    fn markers(&self) -> (&'static str, &'static str) {
        Self::type_markers()
    }

    fn type_markers() -> (&'static str, &'static str) {
        ("", "")
    }

    fn body(&self) -> String {
        match self.tokens_left {
            Some(tokens_left) => {
                format!("You have {tokens_left} tokens left in this context window.")
            }
            None => "You have unknown tokens left in this context window.".to_string(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct TokenBudgetReminder {
    message: String,
}

impl TokenBudgetReminder {
    pub(crate) fn new(message_template: &str, n_remaining: i64) -> Self {
        Self {
            message: message_template.replace("{n_remaining}", &n_remaining.to_string()),
        }
    }
}

impl ContextualUserFragment for TokenBudgetReminder {
    fn content_kind(&self) -> ContentItemKind {
        ContentItemKind("token_budget.reminder".to_string())
    }

    fn role(&self) -> &'static str {
        "developer"
    }

    fn markers(&self) -> (&'static str, &'static str) {
        Self::type_markers()
    }

    fn type_markers() -> (&'static str, &'static str) {
        ("", "")
    }

    fn body(&self) -> String {
        self.message.clone()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct AutoCompactFallbackPrompt {
    message: String,
}

impl AutoCompactFallbackPrompt {
    pub(crate) fn new(message: &str) -> Self {
        Self {
            message: message.to_string(),
        }
    }
}

impl ContextualUserFragment for AutoCompactFallbackPrompt {
    fn content_kind(&self) -> ContentItemKind {
        ContentItemKind("compaction.auto_fallback_prompt".to_string())
    }

    fn role(&self) -> &'static str {
        "developer"
    }

    fn markers(&self) -> (&'static str, &'static str) {
        Self::type_markers()
    }

    fn type_markers() -> (&'static str, &'static str) {
        ("", "")
    }

    fn body(&self) -> String {
        self.message.clone()
    }
}

#[cfg(test)]
#[path = "token_budget_context_tests.rs"]
mod tests;
