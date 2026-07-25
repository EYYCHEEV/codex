use super::*;
use codex_config::Constrained;
use codex_config::LoaderOverrides;
use codex_config::McpServerConfig;
use codex_config::McpServerTransportConfig;
use codex_core::config::ConfigBuilder;
use codex_protocol::SessionId;
use codex_protocol::ThreadId;
use codex_protocol::protocol::AskForApproval;
use pretty_assertions::assert_eq;
use serde_json::json;
use std::collections::HashMap;
use tempfile::tempdir;

fn mcp_server_config(enabled: bool) -> McpServerConfig {
    McpServerConfig {
        transport: McpServerTransportConfig::Stdio {
            command: "unused".to_string(),
            args: Vec::new(),
            env: None,
            env_vars: Vec::new(),
            cwd: None,
        },
        auth: Default::default(),
        environment_id: codex_config::DEFAULT_MCP_SERVER_ENVIRONMENT_ID.to_string(),
        enabled,
        required: false,
        supports_parallel_tool_calls: false,
        disabled_reason: None,
        startup_timeout_sec: None,
        tool_timeout_sec: None,
        default_tools_approval_mode: None,
        enabled_tools: None,
        disabled_tools: None,
        scopes: None,
        oauth: None,
        oauth_resource: None,
        tools: HashMap::new(),
    }
}

#[tokio::test]
async fn disabled_mcp_server_does_not_block_startup_complete() {
    let servers = HashMap::from([
        ("enabled-1".to_string(), mcp_server_config(true)),
        ("enabled-2".to_string(), mcp_server_config(true)),
        ("disabled".to_string(), mcp_server_config(false)),
    ]);
    let codex_home = tempdir().expect("create codex home");
    let mut config = ConfigBuilder::default()
        .codex_home(codex_home.path().to_path_buf())
        .fallback_cwd(Some(codex_home.path().to_path_buf()))
        .loader_overrides(LoaderOverrides::without_managed_config_for_tests())
        .build()
        .await
        .expect("build default config");
    config.mcp_servers = Constrained::allow_any(servers);
    let mut processor = EventProcessorWithJsonOutput::new(/*last_message_path*/ None);
    processor.print_config_summary(
        &config,
        "",
        &SessionConfiguredEvent {
            session_id: SessionId::new(),
            thread_id: ThreadId::new(),
            forked_from_id: None,
            parent_thread_id: None,
            thread_source: None,
            thread_name: None,
            model: "test-model".to_string(),
            model_provider_id: config.model_provider_id.clone(),
            service_tier: None,
            approval_policy: AskForApproval::Never,
            approvals_reviewer: config.approvals_reviewer,
            permission_profile: config.permissions.effective_permission_profile(),
            active_permission_profile: None,
            cwd: config.cwd.clone(),
            reasoning_effort: None,
            initial_messages: None,
            network_proxy: None,
            rollout_path: None,
        },
    );
    let ready_notification = |name: &str| {
        ServerNotification::McpServerStatusUpdated(
            codex_app_server_protocol::McpServerStatusUpdatedNotification {
                thread_id: None,
                name: name.to_string(),
                status: codex_app_server_protocol::McpServerStartupState::Ready,
                error: None,
                failure_reason: None,
            },
        )
    };
    let first = processor.collect_thread_events(ready_notification("enabled-1"));
    assert_eq!(
        first,
        CollectedThreadEvents {
            events: vec![ThreadEvent::McpStartupUpdate(
                protocol::McpStartupUpdateEvent {
                    server: "enabled-1".to_string(),
                    status: protocol::McpStartupStatus::Ready,
                },
            )],
            status: CodexStatus::Running,
        }
    );

    let second = processor.collect_thread_events(ready_notification("enabled-2"));
    assert_eq!(
        second,
        CollectedThreadEvents {
            events: vec![
                ThreadEvent::McpStartupUpdate(protocol::McpStartupUpdateEvent {
                    server: "enabled-2".to_string(),
                    status: protocol::McpStartupStatus::Ready,
                }),
                ThreadEvent::McpStartupComplete(protocol::McpStartupCompleteEvent {
                    ready: vec!["enabled-1".to_string(), "enabled-2".to_string()],
                    failed: Vec::new(),
                    cancelled: Vec::new(),
                }),
            ],
            status: CodexStatus::Running,
        }
    );

    let repeated = processor.collect_thread_events(ready_notification("enabled-2"));
    assert_eq!(
        repeated,
        CollectedThreadEvents {
            events: vec![ThreadEvent::McpStartupUpdate(
                protocol::McpStartupUpdateEvent {
                    server: "enabled-2".to_string(),
                    status: protocol::McpStartupStatus::Ready,
                },
            )],
            status: CodexStatus::Running,
        }
    );
}

#[test]
fn failed_turn_does_not_overwrite_output_last_message_file() {
    let tempdir = tempdir().expect("create tempdir");
    let output_path = tempdir.path().join("last-message.txt");
    std::fs::write(&output_path, "keep existing contents").expect("seed output file");

    let mut processor = EventProcessorWithJsonOutput::new(Some(output_path.clone()));

    let collected = processor.collect_thread_events(ServerNotification::ItemCompleted(
        codex_app_server_protocol::ItemCompletedNotification {
            item: ThreadItem::AgentMessage {
                id: "msg-1".to_string(),
                text: "partial answer".to_string(),
                phase: None,
                memory_citation: None,
            },
            thread_id: "thread-1".to_string(),
            turn_id: "turn-1".to_string(),
            completed_at_ms: 0,
        },
    ));

    assert_eq!(collected.status, CodexStatus::Running);
    assert_eq!(processor.final_message(), Some("partial answer"));

    let status = processor.process_server_notification(ServerNotification::TurnCompleted(
        codex_app_server_protocol::TurnCompletedNotification {
            thread_id: "thread-1".to_string(),
            turn: codex_app_server_protocol::Turn {
                id: "turn-1".to_string(),
                items_view: codex_app_server_protocol::TurnItemsView::Full,
                items: Vec::new(),
                status: TurnStatus::Failed,
                error: Some(codex_app_server_protocol::TurnError {
                    message: "turn failed".to_string(),
                    additional_details: None,
                    codex_error_info: None,
                }),
                started_at: None,
                completed_at: Some(0),
                duration_ms: None,
            },
        },
    ));

    assert_eq!(status, CodexStatus::InitiateShutdown);
    assert_eq!(processor.final_message(), None);

    EventProcessor::print_final_output(&mut processor);

    assert_eq!(
        std::fs::read_to_string(&output_path).expect("read output file"),
        "keep existing contents"
    );
}

#[test]
fn runtime_warning_emits_a_non_fatal_error_item() {
    let mut processor = EventProcessorWithJsonOutput::new(/*last_message_path*/ None);

    let collected = processor.collect_thread_events(ServerNotification::Warning(
        codex_app_server_protocol::WarningNotification {
            thread_id: Some("thread-1".to_string()),
            message: "invalid global instructions".to_string(),
        },
    ));

    assert_eq!(
        collected,
        CollectedThreadEvents {
            events: vec![ThreadEvent::ItemCompleted(ItemCompletedEvent {
                item: ExecThreadItem {
                    id: "item_0".to_string(),
                    details: ThreadItemDetails::Error(ErrorItem {
                        message: "invalid global instructions".to_string(),
                    }),
                },
            })],
            status: CodexStatus::Running,
        }
    );
}

#[test]
fn v2_subagent_activity_emits_an_auditable_collab_event() {
    let mut processor = EventProcessorWithJsonOutput::new(/*last_message_path*/ None);
    let collected = processor.collect_thread_events(ServerNotification::ItemCompleted(
        codex_app_server_protocol::ItemCompletedNotification {
            item: ThreadItem::SubAgentActivity {
                id: "spawn-1".to_string(),
                kind: SubAgentActivityKind::Started,
                agent_thread_id: "thread-child".to_string(),
                agent_path: "/root/worker".to_string(),
                agent_type: Some("scout".to_string()),
                model: Some("gpt-5.6-terra".to_string()),
                reasoning_effort: Some(codex_protocol::openai_models::ReasoningEffort::Medium),
            },
            thread_id: "thread-parent".to_string(),
            turn_id: "turn-1".to_string(),
            completed_at_ms: 0,
        },
    ));

    let [ThreadEvent::ItemCompleted(ItemCompletedEvent { item })] = collected.events.as_slice()
    else {
        panic!("expected one completed collaboration event");
    };
    let ThreadItemDetails::CollabToolCall(call) = &item.details else {
        panic!("expected a collaboration tool call");
    };
    assert_eq!(
        (
            &call.tool,
            call.sender_thread_id.as_str(),
            call.receiver_thread_ids.as_slice(),
            &call.agents_states["thread-child"].status,
            &call.status,
        ),
        (
            &CollabTool::SpawnAgent,
            "thread-parent",
            ["thread-child".to_string()].as_slice(),
            &CollabAgentStatus::Running,
            &CollabToolCallStatus::Completed,
        )
    );
}

#[test]
fn mcp_tool_call_result_preserves_meta_in_jsonl_event() {
    let mut processor = EventProcessorWithJsonOutput::new(/*last_message_path*/ None);

    let collected = processor.collect_thread_events(ServerNotification::ItemCompleted(
        codex_app_server_protocol::ItemCompletedNotification {
            item: ThreadItem::McpToolCall {
                id: "mcp-1".to_string(),
                server: "search service".to_string(),
                tool: "web_run".to_string(),
                status: McpToolCallStatus::Completed,
                arguments: json!({"search_query": [{"q": "OpenAI Codex CLI documentation"}]}),
                app_context: None,
                mcp_app_resource_uri: None,
                plugin_id: None,
                result: Some(Box::new(codex_app_server_protocol::McpToolCallResult {
                    content: vec![json!({"type": "text", "text": "search result"})],
                    structured_content: None,
                    meta: Some(json!({"raw_messages": [{"ref_id": "turn0search0"}]})),
                })),
                error: None,
                duration_ms: Some(42),
            },
            thread_id: "thread-1".to_string(),
            turn_id: "turn-1".to_string(),
            completed_at_ms: 0,
        },
    ));

    assert_eq!(collected.status, CodexStatus::Running);
    assert_eq!(collected.events.len(), 1);

    let ThreadEvent::ItemCompleted(ItemCompletedEvent { item }) = &collected.events[0] else {
        panic!("expected item.completed event");
    };
    let ThreadItemDetails::McpToolCall(item) = &item.details else {
        panic!("expected MCP tool call item");
    };
    let result = item.result.as_ref().expect("expected MCP tool result");
    assert_eq!(
        result.meta,
        Some(json!({"raw_messages": [{"ref_id": "turn0search0"}]}))
    );

    let serialized = serde_json::to_value(&collected.events[0]).expect("serialize event");
    assert_eq!(
        serialized["item"]["result"]["_meta"],
        json!({"raw_messages": [{"ref_id": "turn0search0"}]})
    );
    assert!(serialized["item"]["result"].get("meta").is_none());
}
