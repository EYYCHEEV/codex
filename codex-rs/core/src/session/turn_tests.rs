use super::*;
use crate::context::ContextualUserFragment;
use crate::context::InternalContextSource;
use crate::context::InternalModelContextFragment;
use codex_extension_api::ExtensionData;
use codex_extension_api::TurnItemContributor;
use codex_protocol::ResponseItemId;
use codex_protocol::AgentPath;
use codex_protocol::items::AgentMessageContent;
use codex_protocol::protocol::InterAgentCommunication;
use pretty_assertions::assert_eq;
use std::sync::Arc;
use tracing_subscriber::prelude::*;

struct RewriteAgentMessageContributor;

impl TurnItemContributor for RewriteAgentMessageContributor {
    fn contribute<'a>(
        &'a self,
        _thread_store: &'a ExtensionData,
        _turn_store: &'a ExtensionData,
        item: &'a mut TurnItem,
    ) -> codex_extension_api::ExtensionFuture<'a, Result<(), String>> {
        Box::pin(async move {
            if let TurnItem::AgentMessage(agent_message) = item {
                agent_message.content = vec![AgentMessageContent::Text {
                    text: "plan contributed assistant text".to_string(),
                }];
            }
            Ok(())
        })
    }
}

fn assistant_output_text(text: &str) -> ResponseItem {
    ResponseItem::Message {
        id: Some(ResponseItemId::with_suffix("msg", "1")),
        role: "assistant".to_string(),
        content: vec![ContentItem::OutputText {
            text: text.to_string(),
        }],
        phase: None,
        internal_chat_message_metadata_passthrough: None,
    }
}

#[test]
fn post_sampling_token_estimate_is_disabled_by_always_on_sinks() {
    let feedback = codex_feedback::CodexFeedback::new();
    let subscriber = tracing_subscriber::registry()
        .with(feedback.logger_layer())
        .with(tracing_subscriber::fmt::layer().with_filter(codex_state::log_db::default_filter()));

    tracing::subscriber::with_default(subscriber, || {
        assert!(!tracing::event_enabled!(
            target: POST_SAMPLING_TOKEN_ESTIMATE_TARGET,
            tracing::Level::TRACE,
            turn_id,
            estimated_token_count,
            message
        ));
    });
}

#[tokio::test]
async fn plan_mode_uses_contributed_turn_item_for_last_agent_message() {
    let (mut session, turn_context) = crate::session::tests::make_session_and_context().await;
    let mut builder = codex_extension_api::ExtensionRegistryBuilder::new();
    builder.turn_item_contributor(Arc::new(RewriteAgentMessageContributor));
    session.services.extensions = Arc::new(builder.build());
    let turn_store = ExtensionData::new(turn_context.sub_id.clone());
    let mut state = PlanModeStreamState::new(&turn_context.sub_id);
    let mut last_agent_message = None;
    let item = assistant_output_text("original assistant text");

    let handled = handle_assistant_item_done_in_plan_mode(
        &session,
        &turn_context,
        &turn_store,
        &item,
        &mut state,
        /*previously_active_item*/ None,
        &mut last_agent_message,
    )
    .await;

    assert!(handled);
    assert_eq!(
        last_agent_message.as_deref(),
        Some("plan contributed assistant text")
    );
}

#[test]
fn capability_mentions_include_only_user_and_trusted_goal_inputs() {
    let ordinary_user_inputs = vec![
        UserInput::Text {
            text: "Run the explicitly requested capability.".to_string(),
            text_elements: Vec::new(),
        },
        UserInput::Mention {
            name: "selected-plugin".to_string(),
            path: "plugin://selected-plugin@local".to_string(),
        },
    ];
    let goal_body = "Continue the trusted goal with $upgrade-codex.";
    let goal_context: ResponseItem = ContextualUserFragment::into(
        InternalModelContextFragment::new(InternalContextSource::from_static("goal"), goal_body),
    );
    let identical_extension_context: ResponseItem =
        ContextualUserFragment::into(InternalModelContextFragment::new(
            InternalContextSource::from_static("extension"),
            goal_body,
        ));
    let other_extension_context: ResponseItem =
        ContextualUserFragment::into(InternalModelContextFragment::new(
            InternalContextSource::from_static("extension"),
            "Do not resolve $extension-only.",
        ));
    let generated_user_context = ResponseItem::Message {
        id: None,
        role: "user".to_string(),
        content: vec![ContentItem::InputText {
            text: "Do not resolve $generated-response.".to_string(),
        }],
        phase: None,
        internal_chat_message_metadata_passthrough: None,
    };
    let inter_agent_context = InterAgentCommunication::new(
        AgentPath::root()
            .join("worker")
            .expect("worker agent path must be valid"),
        AgentPath::root(),
        Vec::new(),
        "Do not resolve $inter-agent.".to_string(),
        true,
    );

    let collected = collect_capability_mention_inputs(&[
        TurnInput::UserInput {
            content: ordinary_user_inputs.clone(),
            client_id: Some("client-message-id".to_string()),
        },
        TurnInput::ResponseItem(identical_extension_context),
        TurnInput::ResponseItem(goal_context),
        TurnInput::ResponseItem(other_extension_context),
        TurnInput::ResponseItem(generated_user_context),
        TurnInput::ResponseItem(assistant_output_text("Do not resolve $assistant-output.")),
        TurnInput::InterAgentCommunication(inter_agent_context),
    ]);

    let mut expected = ordinary_user_inputs;
    expected.push(UserInput::Text {
        text: goal_body.to_string(),
        text_elements: Vec::new(),
    });
    assert_eq!(collected, expected);
}
