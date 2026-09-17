use super::MAX_THREAD_HINT_ITEM_TOKENS;
use super::THREAD_HINT_STAMPING_HEADROOM_TOKENS;
use super::TokenBudgetContext;
use crate::context::ContextualUserFragment;
use crate::context_manager::estimate_item_token_count;
use codex_protocol::AgentPath;
use codex_protocol::ResponseItemId;
use codex_protocol::models::ResponseItem;
use serde_json::Number;
use uuid::Uuid;

const TEST_TURN_ID: &str = "turn-id";

fn context_with_hint(thread_hint: String) -> TokenBudgetContext {
    TokenBudgetContext::new(
        AgentPath::root(),
        Uuid::nil(),
        None,
        Uuid::nil(),
        TEST_TURN_ID,
        Some(thread_hint),
    )
}

#[test]
fn aggregate_thread_hint_is_bounded() {
    let context = context_with_hint("x".repeat(MAX_THREAD_HINT_ITEM_TOKENS * 8));
    let mut item = ResponseItem::from(context.render_fragment());
    item.set_turn_id_if_missing(TEST_TURN_ID);

    assert!(
        estimate_item_token_count(&item)
            <= i64::try_from(MAX_THREAD_HINT_ITEM_TOKENS - THREAD_HINT_STAMPING_HEADROOM_TOKENS)
                .unwrap_or(i64::MAX)
    );
    assert!(context.thread_hint.is_some());
}

#[test]
fn aggregate_thread_hint_accounts_for_final_stamps_and_long_turn_id() {
    let turn_id = "turn-".to_string() + &"x".repeat(1_024);
    let context = TokenBudgetContext::new(
        AgentPath::root(),
        Uuid::nil(),
        None,
        Uuid::nil(),
        &turn_id,
        Some("x".repeat(MAX_THREAD_HINT_ITEM_TOKENS * 8)),
    );
    let mut item = ResponseItem::from(context.render_fragment());
    item.set_turn_id_if_missing(&turn_id);
    item.set_create_time_if_missing(Number::from_f64(9_999_999_999.999).expect("finite timestamp"));
    item.set_id(Some(ResponseItemId::with_suffix("msg", Uuid::nil())));

    let serialized = serde_json::to_vec(&item).expect("serialize stamped context item");
    assert!(serialized.len() <= MAX_THREAD_HINT_ITEM_TOKENS * 4);
    assert!(context.thread_hint.is_some());
}

#[test]
fn aggregate_thread_hint_is_truncated_at_a_utf8_boundary() {
    let thread_hint = "étail".repeat(MAX_THREAD_HINT_ITEM_TOKENS);
    let context = context_with_hint(thread_hint.clone());
    let truncated = context.thread_hint.expect("bounded thread hint");

    assert!(thread_hint.starts_with(&truncated));
    assert!(truncated.len() < thread_hint.len());
}
