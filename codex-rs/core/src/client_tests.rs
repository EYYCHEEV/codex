use super::AuthRequestTelemetryContext;
use super::MAX_WEBSOCKET_DIAGNOSTIC_TEXT_BYTES;
use super::ModelClient;
use super::PendingUnauthorizedRetry;
use super::Prompt;
use super::UnauthorizedRecoveryExecution;
use super::X_CODEX_INSTALLATION_ID_HEADER;
use super::X_CODEX_PARENT_THREAD_ID_HEADER;
use super::X_CODEX_TURN_METADATA_HEADER;
use super::X_CODEX_WINDOW_ID_HEADER;
use super::X_OPENAI_SUBAGENT_HEADER;
use super::bounded_websocket_diagnostic_text;
use crate::AttestationContext;
use crate::AttestationProvider;
use crate::GenerateAttestationFuture;
use crate::responses_metadata::CodexResponsesMetadata;
use crate::test_support::TestCodexResponsesRequestKind;
use crate::test_support::responses_metadata as test_responses_metadata;
use base64::Engine;
use chrono::Utc;
use codex_api::AgentIdentityTelemetry;
use codex_api::ApiError;
use codex_api::ResponseEvent;
use codex_api::ResponsesEndpoint;
use codex_api::TransportError;
use codex_http_client::HttpClientFactory;
use codex_http_client::OutboundProxyPolicy;
use codex_login::AuthManager;
use codex_login::CodexAuth;
use codex_login::ManagedChatgptBlockKindView;
use codex_login::ManagedChatgptFailure;
use codex_login::ManagedChatgptOauthCredentials;
use codex_login::TokenData;
use codex_login::auth::AgentIdentityAuthPolicy;
use codex_login::token_data::IdTokenInfo;
use codex_model_provider::BearerAuthProvider;
use codex_model_provider::ModelProvider;
use codex_model_provider::ModelProviderFuture;
use codex_model_provider::ProviderAccountResult;
use codex_model_provider::ProviderAuthRecoveryMessages;
use codex_model_provider::ProviderUnauthorizedRecovery;
use codex_model_provider::SharedModelProvider;
use codex_model_provider::create_model_provider;
use codex_model_provider_info::CHATGPT_CODEX_BASE_URL;
use codex_model_provider_info::ModelProviderInfo;
use codex_model_provider_info::WireApi;
use codex_model_provider_info::create_oss_provider_with_base_url;
use codex_models_manager::manager::SharedModelsManager;
use codex_otel::SessionTelemetry;
use codex_protocol::ThreadId;
use codex_protocol::auth::AuthMode;
use codex_protocol::error::CodexErr;
use codex_protocol::error::CodexErrorDetails;
use codex_protocol::error::UnexpectedResponseError;
use codex_protocol::error::UsageLimitReachedError;
use codex_protocol::error::WebsocketCloseDetails;
use codex_protocol::models::BaseInstructions;
use codex_protocol::models::ContentItem;
use codex_protocol::models::ExecutedToolCall;
use codex_protocol::models::FunctionCallOutputPayload;
use codex_protocol::models::ResponseInputItem;
use codex_protocol::models::ResponseItem;
use codex_protocol::models::ToolResultMetadata;
use codex_protocol::models::ToolResultSource;
use codex_protocol::models::ToolResultSources;
use codex_protocol::openai_models::ModelInfo;
use codex_protocol::openai_models::ModelsResponse;
use codex_protocol::openai_models::ReasoningEffort;
use codex_protocol::openai_models::ReasoningEffortPreset;
use codex_protocol::protocol::InternalSessionSource;
use codex_protocol::protocol::RateLimitReachedType;
use codex_protocol::protocol::ResponsesWebsocketCloseRecovery;
use codex_protocol::protocol::SessionSource;
use codex_protocol::protocol::SubAgentSource;
use codex_rollout_trace::ExecutionStatus;
use codex_rollout_trace::InferenceTraceAttempt;
use codex_rollout_trace::InferenceTraceContext;
use codex_rollout_trace::RawTraceEventPayload;
use codex_rollout_trace::RolloutTrace;
use codex_rollout_trace::TraceWriter;
use codex_rollout_trace::replay_bundle;
use futures::StreamExt;
use pretty_assertions::assert_eq;
use serde_json::json;
use std::collections::BTreeMap;
use std::collections::VecDeque;
use std::path::PathBuf;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::atomic::AtomicUsize;
use std::sync::atomic::Ordering;
use std::task::Context;
use std::task::Poll;
use std::time::Duration;
use tempfile::TempDir;
use tokio::sync::Notify;
use tracing::Event;
use tracing::Subscriber;
use tracing::field::Visit;
use tracing_subscriber::Layer;
use tracing_subscriber::layer::Context as LayerContext;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::registry::LookupSpan;
use tracing_subscriber::util::SubscriberInitExt;
use wiremock::Mock;
use wiremock::MockServer;
use wiremock::ResponseTemplate;
use wiremock::matchers::method;
use wiremock::matchers::path;

const TEST_INSTALLATION_ID: &str = "11111111-1111-4111-8111-111111111111";

fn managed_id_token(email: &str, account_id: &str) -> String {
    let header = json!({"alg": "none", "typ": "JWT"});
    let payload = json!({
        "email": email,
        "email_verified": true,
        "https://api.openai.com/auth": {
            "chatgpt_user_id": format!("user-{account_id}"),
            "user_id": format!("user-{account_id}"),
            "chatgpt_plan_type": "pro",
            "chatgpt_account_id": account_id,
        },
    });
    let encode = |bytes: &[u8]| base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes);
    format!(
        "{}.{}.{}",
        encode(&serde_json::to_vec(&header).expect("serialize JWT header")),
        encode(&serde_json::to_vec(&payload).expect("serialize JWT payload")),
        encode(b"sig"),
    )
}

fn test_model_client(session_source: SessionSource) -> ModelClient {
    test_model_client_with_thread_id(ThreadId::new(), session_source)
}

fn test_model_client_with_thread_id(
    thread_id: ThreadId,
    session_source: SessionSource,
) -> ModelClient {
    let provider = create_oss_provider_with_base_url("https://example.com/v1", WireApi::Responses);
    ModelClient::new(
        /*auth_manager*/ None,
        AgentIdentityAuthPolicy::JwtOnly,
        thread_id,
        provider,
        session_source,
        "test_originator".to_string(),
        /*model_verbosity*/ None,
        /*content_item_kinds_enabled*/ true,
        /*enable_request_compression*/ false,
        /*include_timing_metrics*/ false,
        /*beta_features_header*/ None,
        /*concurrent_reasoning_summaries_enabled*/ false,
        /*attestation_provider*/ None,
        HttpClientFactory::new(OutboundProxyPolicy::ReqwestDefault),
    )
}

async fn managed_accounts_model_client(
    codex_home: &TempDir,
    base_url: &str,
    accounts: &[(&str, &str)],
) -> anyhow::Result<(ModelClient, Arc<AuthManager>)> {
    let auth_manager = AuthManager::shared(
        codex_home.path().to_path_buf(),
        /*enable_codex_api_key_env*/ false,
        AuthCredentialsStoreMode::File,
        /*forced_chatgpt_workspace_id*/ None,
        /*chatgpt_base_url*/ None,
        AuthKeyringBackendKind::Direct,
        /*auth_route_config*/ None,
    )
    .await;
    for &(email, account_id) in accounts {
        auth_manager
            .upsert_managed_chatgpt_oauth(ManagedChatgptOauthCredentials {
                tokens: TokenData {
                    id_token: IdTokenInfo {
                        email: Some(email.to_string()),
                        chatgpt_account_id: Some(account_id.to_string()),
                        raw_jwt: managed_id_token(email, account_id),
                        ..Default::default()
                    },
                    access_token: format!("access-{account_id}"),
                    refresh_token: format!("refresh-{account_id}"),
                    account_id: Some(account_id.to_string()),
                },
                last_refresh: Utc::now(),
                oauth_api_key: None,
            })
            .await?;
    }
    let mut provider = ModelProviderInfo::create_openai_provider(/*base_url*/ None);
    provider.base_url = Some(format!("{base_url}/v1"));
    provider.supports_websockets = false;
    let client = ModelClient::new(
        Some(Arc::clone(&auth_manager)),
        AgentIdentityAuthPolicy::JwtOnly,
        ThreadId::new(),
        provider,
        SessionSource::Cli,
        "test_originator".to_string(),
        /*model_verbosity*/ None,
        /*enable_request_compression*/ false,
        /*include_timing_metrics*/ false,
        /*beta_features_header*/ None,
        /*item_ids_enabled*/ false,
        /*concurrent_reasoning_summaries_enabled*/ false,
        /*attestation_provider*/ None,
        HttpClientFactory::new(OutboundProxyPolicy::ReqwestDefault),
    );
    Ok((client, auth_manager))
}

async fn two_account_model_client(
    codex_home: &TempDir,
    base_url: &str,
) -> anyhow::Result<(ModelClient, Arc<AuthManager>)> {
    managed_accounts_model_client(
        codex_home,
        base_url,
        &[
            ("a@example.com", "account-a"),
            ("b@example.com", "account-b"),
        ],
    )
    .await
}

#[test]
fn websocket_diagnostic_text_is_utf8_safe_and_bounded() {
    let value = "模型".repeat(100);
    let bounded = bounded_websocket_diagnostic_text(&value);
    assert!(bounded.len() <= MAX_WEBSOCKET_DIAGNOSTIC_TEXT_BYTES);
    assert!(bounded.ends_with("..."));
}

#[tokio::test]
async fn websocket_close_diagnostic_captures_single_and_pooled_account_snapshots()
-> anyhow::Result<()> {
    let account_sets: [&[(&str, &str)]; 2] = [
        &[("single@example.com", "account-single")],
        &[
            ("a@example.com", "account-a"),
            ("b@example.com", "account-b"),
        ],
    ];

    for accounts in account_sets {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/v1/responses"))
            .respond_with(
                ResponseTemplate::new(/*status*/ 200)
                    .insert_header("content-type", "text/event-stream")
                    .set_body_string(concat!(
                        "data: {\"type\":\"response.created\",\"response\":{\"id\":\"r1\"}}\n\n",
                        "data: {\"type\":\"response.completed\",\"response\":{\"id\":\"r1\"}}\n\n",
                    )),
            )
            .expect(/*requests*/ 1)
            .mount(&server)
            .await;

        let codex_home = TempDir::new()?;
        let (client, _auth_manager) =
            managed_accounts_model_client(&codex_home, &server.uri(), accounts).await?;
        let mut client_session = client.new_session();
        let prompt = Prompt {
            input: vec![ResponseItem::Message {
                id: None,
                role: "user".to_string(),
                content: vec![ContentItem::InputText {
                    text: "hello".to_string(),
                }],
                phase: None,
                internal_chat_message_metadata_passthrough: None,
            }],
            base_instructions: BaseInstructions {
                text: "base instructions".to_string(),
            },
            ..Default::default()
        };
        let responses_metadata = test_responses_metadata_for_client(
            &client,
            Some("turn-1"),
            format!("{}:0", client.state.thread_id),
            /*parent_thread_id*/ None,
            TestCodexResponsesRequestKind::Turn,
        );
        let model_info = test_model_info();
        let telemetry = test_session_telemetry();
        let mut stream = client_session
            .stream(
                &prompt,
                &model_info,
                &telemetry,
                /*effort*/ None,
                codex_protocol::config_types::ReasoningSummary::None,
                /*service_tier*/ None,
                &responses_metadata,
                &InferenceTraceContext::disabled(),
            )
            .await?;
        let mut completed = false;
        while let Some(event) = stream.next().await {
            if matches!(event?, ResponseEvent::Completed { .. }) {
                completed = true;
                break;
            }
        }
        assert!(completed);

        let diagnostic = client_session
            .websocket_close_diagnostic_context(
                &CodexErr::WebsocketClosed(Box::new(WebsocketCloseDetails {
                    code: Some(4001),
                    reason: Some("maintenance".to_string()),
                    reason_redacted: false,
                })),
                "turn-1",
                responses_metadata.session_id.as_str(),
                model_info.slug.as_str(),
                /*output_committed*/ false,
            )
            .expect("typed websocket close diagnostic")
            .finish(
                /*attempt_number*/ 1,
                /*max_retries*/ 1,
                ResponsesWebsocketCloseRecovery::ReconnectWebsocket,
            );
        assert_eq!(diagnostic.close_code, Some(4001));
        assert_eq!(diagnostic.thread_id, client.state.thread_id.to_string());
        assert_eq!(diagnostic.turn_id, "turn-1");
        assert_eq!(diagnostic.session_id, responses_metadata.session_id);
        assert_eq!(diagnostic.model, model_info.slug);
        assert!(!diagnostic.output_committed);
        assert_eq!(diagnostic.attempt_number, 1);
        assert_eq!(diagnostic.max_retries, 1);
        assert_eq!(diagnostic.close_reason.as_deref(), Some("maintenance"));
        assert!(!diagnostic.connection_reused);
        assert_eq!(diagnostic.binding_matched, Some(true));
        assert_eq!(
            diagnostic.recovery_decision,
            ResponsesWebsocketCloseRecovery::ReconnectWebsocket
        );

        let account_fingerprint = diagnostic
            .account_fingerprint
            .as_deref()
            .expect("managed account fingerprint");
        assert!(account_fingerprint.starts_with("acct-"));
        assert!(accounts.iter().all(|(email, account_id)| {
            !account_fingerprint.contains(email) && !account_fingerprint.contains(account_id)
        }));
        let serialized = serde_json::to_string(&diagnostic)?;
        assert!(accounts.iter().all(|(email, account_id)| {
            !serialized.contains(email) && !serialized.contains(account_id)
        }));
        assert!(diagnostic.credential_revision.is_some());
        assert!(diagnostic.account_state_revision.is_some());
        assert!(diagnostic.pool_revision.is_some());
        assert!(diagnostic.selection_revision.is_some());
        assert!(diagnostic.route_generation.is_some());
        assert!(
            diagnostic
                .request_binding_fingerprint
                .as_deref()
                .is_some_and(|fingerprint| fingerprint.starts_with("bind-"))
        );
    }

    Ok(())
}

#[tokio::test]
async fn response_stream_attempt_rotates_before_replay_after_account_quota() -> anyhow::Result<()> {
    let server = MockServer::start().await;
    let attempt_count = Arc::new(AtomicUsize::new(0));
    let response_attempt_count = Arc::clone(&attempt_count);
    Mock::given(method("POST"))
        .and(path("/v1/responses"))
        .respond_with(move |_request: &wiremock::Request| {
            if response_attempt_count.fetch_add(1, Ordering::SeqCst) == 0 {
                ResponseTemplate::new(/*status*/ 429).set_body_json(json!({
                    "error": {
                        "type": "usage_limit_reached",
                        "plan_type": "pro"
                    }
                }))
            } else {
                ResponseTemplate::new(/*status*/ 200)
                    .insert_header("content-type", "text/event-stream")
                    .set_body_string(concat!(
                        "data: {\"type\":\"response.created\",\"response\":{\"id\":\"r1\"}}\n\n",
                        "data: {\"type\":\"response.completed\",\"response\":{\"id\":\"r1\"}}\n\n",
                    ))
            }
        })
        .expect(/*requests*/ 2)
        .mount(&server)
        .await;

    let codex_home = TempDir::new()?;
    let (client, auth_manager) = two_account_model_client(&codex_home, &server.uri()).await?;
    let mut client_session = client.new_session();
    let prompt = Prompt {
        input: vec![ResponseItem::Message {
            id: None,
            role: "user".to_string(),
            content: vec![ContentItem::InputText {
                text: "hello".to_string(),
            }],
            phase: None,
            internal_chat_message_metadata_passthrough: None,
        }],
        base_instructions: BaseInstructions {
            text: "base instructions".to_string(),
        },
        ..Default::default()
    };
    let responses_metadata = test_responses_metadata_for_client(
        &client,
        /*turn_id*/ None,
        format!("{}:0", client.state.thread_id),
        /*parent_thread_id*/ None,
        TestCodexResponsesRequestKind::Turn,
    );
    let model_info = test_model_info();
    let telemetry = test_session_telemetry();
    let first = client_session
        .stream(
            &prompt,
            &model_info,
            &telemetry,
            /*effort*/ None,
            codex_protocol::config_types::ReasoningSummary::None,
            /*service_tier*/ None,
            &responses_metadata,
            &InferenceTraceContext::disabled(),
        )
        .await;
    let first_error = match first {
        Ok(_) => panic!("first account should be quota blocked"),
        Err(error) => error,
    };
    assert!(matches!(first_error, CodexErr::UsageLimitReached(_)));
    assert!(
        client_session
            .recover_last_managed_attempt(&first_error, /*committed*/ false)
            .await
    );

    let mut stream = client_session
        .stream(
            &prompt,
            &model_info,
            &telemetry,
            /*effort*/ None,
            codex_protocol::config_types::ReasoningSummary::None,
            /*service_tier*/ None,
            &responses_metadata,
            &InferenceTraceContext::disabled(),
        )
        .await?;
    let first_selection = client_session
        .take_managed_selection_update()
        .expect("first managed request setup should retain its selection signal");
    assert_eq!(
        first_selection.session_id.as_deref(),
        Some(responses_metadata.session_id.as_str())
    );
    assert_eq!(
        first_selection.model.as_deref(),
        Some(model_info.slug.as_str())
    );
    let rotated_selection = client_session
        .take_managed_selection_update()
        .expect("managed failover should publish the rotated selection");
    assert_ne!(
        rotated_selection.selected_account_id,
        first_selection.selected_account_id
    );
    assert!(
        rotated_selection.selection_revision > first_selection.selection_revision,
        "rotation must advance the scoped selection revision"
    );
    assert_eq!(rotated_selection.session_id, first_selection.session_id);
    assert_eq!(rotated_selection.model, first_selection.model);
    assert!(
        client_session.take_managed_selection_update().is_none(),
        "first-pin and rotation signals should each be emitted exactly once"
    );
    let mut completed = false;
    while let Some(event) = stream.next().await {
        if matches!(event?, ResponseEvent::Completed { .. }) {
            completed = true;
            break;
        }
    }
    assert!(completed);
    assert_eq!(
        auth_manager
            .managed_chatgpt_accounts()?
            .iter()
            .filter(|account| account.block_kind == Some(ManagedChatgptBlockKindView::Quota))
            .count(),
        1
    );
    let requests = server
        .received_requests()
        .await
        .expect("server should record requests");
    let account_ids: Vec<_> = requests
        .iter()
        .filter(|request| request.url.path() == "/v1/responses")
        .map(|request| {
            request
                .headers
                .get("ChatGPT-Account-ID")
                .expect("managed account header")
                .to_str()
                .expect("account header text")
                .to_string()
        })
        .collect();
    assert_eq!(account_ids.len(), 2);
    assert_ne!(account_ids[0], account_ids[1]);

    Ok(())
}
fn test_model_provider() -> SharedModelProvider {
    test_model_client(SessionSource::Cli).state.provider.clone()
}

fn test_responses_metadata_for_client(
    client: &ModelClient,
    turn_id: Option<&str>,
    window_id: String,
    parent_thread_id: Option<ThreadId>,
    request_kind: TestCodexResponsesRequestKind,
) -> CodexResponsesMetadata {
    let thread_id = client.state.thread_id.to_string();
    test_responses_metadata(
        TEST_INSTALLATION_ID,
        &thread_id,
        &thread_id,
        turn_id,
        window_id,
        &client.state.session_source,
        parent_thread_id,
        request_kind,
    )
}

fn test_model_info() -> ModelInfo {
    serde_json::from_value(json!({
        "slug": "gpt-test",
        "display_name": "gpt-test",
        "description": "desc",
        "default_reasoning_level": "medium",
        "supported_reasoning_levels": [
            {"effort": "medium", "description": "medium"}
        ],
        "shell_type": "shell_command",
        "visibility": "list",
        "supported_in_api": true,
        "priority": 1,
        "upgrade": null,
        "model_messages": null,
        "support_verbosity": false,
        "default_verbosity": null,
        "apply_patch_tool_type": null,
        "truncation_policy": {"mode": "bytes", "limit": 10000},
        "supports_image_detail_original": false,
        "context_window": 272000,
        "auto_compact_token_limit": null,
        "experimental_supported_tools": []
    }))
    .expect("deserialize test model info")
}

fn output_with_tool_result_metadata(metadata: ToolResultMetadata) -> ResponseItem {
    let mut call = ExecutedToolCall::new("test_tool".to_string(), json!({ "query": "keep" }));
    call.set_tool_result_sources(ToolResultSources::new(vec![ToolResultSource {
        r#type: "test_resource".to_string(),
        id: "R1".to_string(),
    }]));
    call.set_tool_result_metadata(metadata);
    let mut output = ResponseItem::from(ResponseInputItem::FunctionCallOutput {
        call_id: "tool-call".to_string(),
        output: FunctionCallOutputPayload::from_text("unchanged tool result".to_string()),
    });
    output.append_executed_tool_calls(vec![call]);
    output.mark_tool_calls_complete();
    output
}

#[test]
fn responses_request_limits_raw_tool_metadata_to_resolved_first_party_https_endpoint()
-> anyhow::Result<()> {
    let provider =
        ModelProviderInfo::create_openai_provider(Some("https://api.openai.com/v1".to_string()));
    let mut api_provider = provider.to_api_provider(/*auth_mode*/ None)?;
    let mut client = test_model_client(SessionSource::Cli);
    Arc::get_mut(&mut client.state)
        .expect("test client should have unique session state")
        .provider = create_model_provider(provider, /*auth_manager*/ None);
    let output = output_with_tool_result_metadata(ToolResultMetadata::new(&json!({
        "private": { "resource": "raw-result-metadata" },
    })));
    let without_raw_metadata = output_with_tool_result_metadata(ToolResultMetadata::default());
    let prompt = Prompt {
        input: vec![output.clone()],
        ..Default::default()
    };
    let responses_metadata = test_responses_metadata_for_client(
        &client,
        /*turn_id*/ None,
        format!("{}:0", client.state.thread_id),
        /*parent_thread_id*/ None,
        TestCodexResponsesRequestKind::Turn,
    );
    for (base_url, allowed) in [
        ("https://api.openai.com/v1", true),
        ("https://chatgpt.com/backend-api/codex", true),
        ("https://api.chatgpt-staging.com/v1", true),
        ("https://proxy.example.com/v1", false),
        ("http://api.openai.com/v1", false),
        ("https://api.openai.com.evil.example/v1", false),
        ("https://chatgpt.com.evil.example/v1", false),
        ("https://api.openai.com@proxy.example.com/v1", false),
        ("not a URL", false),
    ] {
        api_provider.base_url = base_url.to_string();
        for responses_lite in [false, true] {
            let mut model = test_model_info();
            model.use_responses_lite = responses_lite;
            let mut request = client.build_responses_request(
                &prompt,
                &model,
                /*effort*/ None,
                codex_protocol::config_types::ReasoningSummary::None,
                /*service_tier*/ None,
                &responses_metadata,
            )?;
            ModelClient::filter_tool_result_metadata(&mut request.input, &api_provider);
            assert_eq!(
                request.input.last(),
                Some(if allowed {
                    &output
                } else {
                    &without_raw_metadata
                }),
                "resolved endpoint: {base_url}, responses_lite: {responses_lite}",
            );
            assert_eq!(prompt.input, vec![output.clone()]);
        }
    }
    Ok(())
}

#[tokio::test]
async fn responses_http_omits_raw_tool_metadata_for_openai_named_custom_endpoint()
-> anyhow::Result<()> {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/v1/responses"))
        .respond_with(
            ResponseTemplate::new(/*status*/ 200)
                .insert_header("content-type", "text/event-stream")
                .set_body_string(concat!(
                    "data: {\"type\":\"response.created\",\"response\":{\"id\":\"resp-1\"}}\n\n",
                    "data: {\"type\":\"response.completed\",\"response\":{\"id\":\"resp-1\"}}\n\n",
                )),
        )
        .expect(/*requests*/ 1)
        .mount(&server)
        .await;
    let mut provider =
        ModelProviderInfo::create_openai_provider(Some(format!("{}/v1", server.uri())));
    provider.requires_openai_auth = false;
    provider.supports_websockets = false;
    let mut client = test_model_client(SessionSource::Cli);
    Arc::get_mut(&mut client.state)
        .expect("test client should have unique session state")
        .provider = create_model_provider(provider, /*auth_manager*/ None);
    let output = output_with_tool_result_metadata(ToolResultMetadata::new(&json!({
        "private": "raw-result-metadata",
    })));
    let prompt = Prompt {
        input: vec![output.clone()],
        ..Default::default()
    };
    let responses_metadata = test_responses_metadata_for_client(
        &client,
        /*turn_id*/ None,
        format!("{}:0", client.state.thread_id),
        /*parent_thread_id*/ None,
        TestCodexResponsesRequestKind::Turn,
    );
    let mut session = client.new_session();
    let mut stream = session
        .stream(
            &prompt,
            &test_model_info(),
            &test_session_telemetry(),
            /*effort*/ None,
            codex_protocol::config_types::ReasoningSummary::None,
            /*service_tier*/ None,
            &responses_metadata,
            &InferenceTraceContext::disabled(),
        )
        .await?;
    let mut completed = false;
    while let Some(event) = stream.next().await {
        if let ResponseEvent::Completed { response_id, .. } = event? {
            assert_eq!(response_id, "resp-1");
            completed = true;
        }
    }
    assert!(completed);
    let requests = server.received_requests().await.expect("received requests");
    assert_eq!(requests.len(), 1);
    let body: serde_json::Value = serde_json::from_slice(&requests[0].body)?;
    assert_eq!(
        body["input"],
        serde_json::to_value(vec![output_with_tool_result_metadata(
            ToolResultMetadata::default(),
        )])?,
    );
    assert_eq!(prompt.input, vec![output]);
    Ok(())
}

#[test]
fn responses_lite_prefix_ids_track_thread_and_payload() -> anyhow::Result<()> {
    let thread_id = ThreadId::new();
    let client = test_model_client_with_thread_id(thread_id, SessionSource::Cli);
    let mut model = test_model_info();
    model.use_responses_lite = true;
    let mut prompt = Prompt {
        base_instructions: BaseInstructions {
            text: "base instructions".to_string(),
            provenance: None,
        },
        ..Default::default()
    };
    let build = |client: &ModelClient, prompt: &Prompt| {
        client.build_responses_request(
            prompt,
            &model,
            /*effort*/ None,
            codex_protocol::config_types::ReasoningSummary::None,
            /*service_tier*/ None,
            &test_responses_metadata_for_client(
                client,
                /*turn_id*/ None,
                format!("{}:0", client.state.thread_id),
                /*parent_thread_id*/ None,
                TestCodexResponsesRequestKind::Turn,
            ),
        )
    };

    let original = build(&client, &prompt)?;
    assert_eq!(build(&client, &prompt)?, original);

    prompt.base_instructions.text.push_str(" with an update");
    let changed_instructions = build(&client, &prompt)?;
    assert_eq!(changed_instructions.input[0], original.input[0]);
    assert_ne!(changed_instructions.input[1].id(), original.input[1].id());

    prompt.tools = vec![codex_tools::ToolSpec::Freeform(codex_tools::FreeformTool {
        name: "exec".to_string(),
        description: "Execute JavaScript.".to_string(),
        defer_loading: None,
        format: codex_tools::FreeformToolFormat {
            r#type: "grammar".to_string(),
            syntax: "lark".to_string(),
            definition: "start: /.+/".to_string(),
        },
    })]
    .into();
    let changed_tools = build(&client, &prompt)?;
    assert_ne!(
        changed_tools.input[0].id(),
        changed_instructions.input[0].id()
    );
    assert_eq!(changed_tools.input[1], changed_instructions.input[1]);

    let independent = build(
        &test_model_client_with_thread_id(ThreadId::new(), SessionSource::Cli),
        &prompt,
    )?;
    assert_ne!(independent.input[0].id(), changed_tools.input[0].id());
    assert_ne!(independent.input[1].id(), changed_tools.input[1].id());
    Ok(())
}

fn test_session_telemetry() -> SessionTelemetry {
    SessionTelemetry::new(
        ThreadId::new(),
        "gpt-test",
        "gpt-test",
        /*account_id*/ None,
        /*account_email*/ None,
        /*auth_mode*/ None,
        "test-originator".to_string(),
        /*log_user_prompts*/ false,
        "test-terminal".to_string(),
        SessionSource::Cli,
    )
}

fn spawned_session_source() -> SessionSource {
    SessionSource::SubAgent(SubAgentSource::ThreadSpawn {
        parent_thread_id: ThreadId::new(),
        depth: 1,
        agent_path: None,
        agent_nickname: None,
        agent_role: None,
    })
}

fn reasoning_effort_in_request(
    model_info: &ModelInfo,
    session_source: SessionSource,
    effort: ReasoningEffort,
) -> ReasoningEffort {
    let client = test_model_client(session_source);
    client
        .build_responses_request(
            &Prompt::default(),
            model_info,
            Some(effort),
            codex_protocol::config_types::ReasoningSummary::None,
            /*service_tier*/ None,
            &test_responses_metadata_for_client(
                &client,
                /*turn_id*/ None,
                format!("{}:0", client.state.thread_id),
                /*parent_thread_id*/ None,
                TestCodexResponsesRequestKind::Turn,
            ),
        )
        .expect("build responses request")
        .reasoning
        .expect("request should include reasoning")
        .effort
        .expect("request should include reasoning effort")
}

#[test]
fn reasoning_effort_for_requests_uses_multi_agent_override_for_ultra() {
    let mut model_info = test_model_info();
    model_info.multi_agent_reasoning_effort = Some(ReasoningEffort::High);
    model_info
        .supported_reasoning_levels
        .push(ReasoningEffortPreset {
            effort: ReasoningEffort::High,
            description: "high".to_string(),
        });

    let actual = [SessionSource::Cli, spawned_session_source()].map(|session_source| {
        reasoning_effort_in_request(&model_info, session_source, ReasoningEffort::Ultra)
    });

    assert_eq!(actual, [ReasoningEffort::High, ReasoningEffort::High]);
}

#[test]
fn reasoning_effort_for_requests_falls_back_for_missing_or_invalid_override() {
    let mut model_info = test_model_info();
    model_info.supported_reasoning_levels = vec![
        ReasoningEffortPreset {
            effort: ReasoningEffort::Low,
            description: "low".to_string(),
        },
        ReasoningEffortPreset {
            effort: ReasoningEffort::XHigh,
            description: "xhigh".to_string(),
        },
        ReasoningEffortPreset {
            effort: ReasoningEffort::Ultra,
            description: "ultra".to_string(),
        },
    ];

    let actual = [
        None,
        Some(ReasoningEffort::Ultra),
        Some(ReasoningEffort::High),
    ]
    .map(|multi_agent_reasoning_effort| {
        model_info.multi_agent_reasoning_effort = multi_agent_reasoning_effort;
        reasoning_effort_in_request(&model_info, SessionSource::Cli, ReasoningEffort::Ultra)
    });

    assert_eq!(
        actual,
        [
            ReasoningEffort::XHigh,
            ReasoningEffort::XHigh,
            ReasoningEffort::XHigh,
        ]
    );

    model_info.multi_agent_reasoning_effort = None;
    model_info.supported_reasoning_levels.insert(
        1,
        ReasoningEffortPreset {
            effort: ReasoningEffort::Max,
            description: "max".to_string(),
        },
    );
    assert_eq!(
        reasoning_effort_in_request(&model_info, SessionSource::Cli, ReasoningEffort::Ultra),
        ReasoningEffort::Max
    );

    model_info.supported_reasoning_levels.clear();
    assert_eq!(
        reasoning_effort_in_request(&model_info, SessionSource::Cli, ReasoningEffort::Ultra),
        ReasoningEffort::Medium
    );
}

#[test]
fn reasoning_effort_for_requests_preserves_non_ultra_and_persistent_behavior() {
    let mut model_info = test_model_info();
    model_info.multi_agent_reasoning_effort = Some(ReasoningEffort::Low);

    assert_eq!(
        (
            reasoning_effort_in_request(&model_info, SessionSource::Cli, ReasoningEffort::High,),
            reasoning_effort_in_request(
                &model_info,
                SessionSource::Cli,
                ReasoningEffort::Persistent,
            ),
        ),
        (
            ReasoningEffort::High,
            ReasoningEffort::Custom("disabled".to_string()),
        )
    );
}

#[derive(Default)]
struct TagCollectorVisitor {
    tags: BTreeMap<String, String>,
}

impl Visit for TagCollectorVisitor {
    fn record_str(&mut self, field: &tracing::field::Field, value: &str) {
        self.tags
            .insert(field.name().to_string(), value.to_string());
    }

    fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
        self.tags
            .insert(field.name().to_string(), format!("{value:?}"));
    }
}

#[derive(Clone)]
struct TagCollectorLayer {
    tags: Arc<Mutex<BTreeMap<String, String>>>,
}

impl<S> Layer<S> for TagCollectorLayer
where
    S: Subscriber + for<'a> LookupSpan<'a>,
{
    fn on_event(&self, event: &Event<'_>, _ctx: LayerContext<'_, S>) {
        if event.metadata().target() != "feedback_tags" {
            return;
        }
        let mut visitor = TagCollectorVisitor::default();
        event.record(&mut visitor);
        self.tags.lock().unwrap().extend(visitor.tags);
    }
}

fn started_inference_attempt(temp: &TempDir) -> anyhow::Result<InferenceTraceAttempt> {
    let writer = Arc::new(TraceWriter::create(
        temp.path(),
        "trace-1".to_string(),
        "rollout-1".to_string(),
        "thread-root".to_string(),
    )?);
    writer.append(RawTraceEventPayload::ThreadStarted {
        thread_id: "thread-root".to_string(),
        agent_path: "/root".to_string(),
        metadata_payload: None,
    })?;
    writer.append(RawTraceEventPayload::CodexTurnStarted {
        codex_turn_id: "turn-1".to_string(),
        thread_id: "thread-root".to_string(),
    })?;

    let inference_trace = InferenceTraceContext::enabled(
        writer,
        "thread-root".to_string(),
        "turn-1".to_string(),
        "gpt-test".to_string(),
        "test-provider".to_string(),
    );
    let attempt = inference_trace.start_attempt();
    attempt.record_started(&json!({
        "model": "gpt-test",
        "input": [{
            "type": "message",
            "role": "user",
            "content": [{"type": "input_text", "text": "hello"}]
        }],
    }));
    Ok(attempt)
}

fn output_message(id: &str, text: &str) -> ResponseItem {
    ResponseItem::Message {
        id: Some(codex_protocol::ResponseItemId::with_suffix("msg", id)),
        role: "assistant".to_string(),
        content: vec![ContentItem::OutputText {
            text: text.to_string(),
        }],
        phase: None,
        internal_chat_message_metadata_passthrough: None,
    }
}

async fn replay_until_cancelled(temp: &TempDir) -> anyhow::Result<RolloutTrace> {
    let mut rollout = replay_bundle(temp.path())?;
    for _ in 0..50 {
        let inference = rollout
            .inference_calls
            .values()
            .next()
            .expect("inference should be reduced");
        if inference.execution.status == ExecutionStatus::Cancelled {
            return Ok(rollout);
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
        rollout = replay_bundle(temp.path())?;
    }
    Ok(rollout)
}

struct NotifyAfterEventStream {
    events: VecDeque<ResponseEvent>,
    yielded: usize,
    notify_after: usize,
    notify: Arc<Notify>,
}

impl futures::Stream for NotifyAfterEventStream {
    type Item = std::result::Result<ResponseEvent, ApiError>;

    fn poll_next(mut self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let Some(event) = self.events.pop_front() else {
            return Poll::Pending;
        };
        self.yielded += 1;
        if self.yielded == self.notify_after {
            self.notify.notify_one();
        }
        Poll::Ready(Some(Ok(event)))
    }
}

#[test]
fn build_subagent_headers_sets_other_subagent_label() {
    let client = test_model_client(SessionSource::SubAgent(SubAgentSource::Other(
        "memory_consolidation".to_string(),
    )));
    let headers = client.build_subagent_headers();
    let value = headers
        .get(X_OPENAI_SUBAGENT_HEADER)
        .and_then(|value| value.to_str().ok());
    assert_eq!(value, Some("memory_consolidation"));
}

#[test]
fn internal_session_prompt_cache_key_is_scoped_to_parent_thread() {
    let parent_thread_id = ThreadId::new();
    let client = test_model_client(SessionSource::Internal(InternalSessionSource::Guardian));
    let metadata = test_responses_metadata_for_client(
        &client,
        Some("turn-123"),
        "window-1".to_string(),
        Some(parent_thread_id),
        TestCodexResponsesRequestKind::Turn,
    );

    assert_eq!(
        client.prompt_cache_key(&metadata),
        format!("guardian:{parent_thread_id}")
    );
}

#[test]
fn build_subagent_headers_sets_internal_memory_consolidation_label() {
    let client = test_model_client(SessionSource::Internal(
        InternalSessionSource::MemoryConsolidation,
    ));
    let headers = client.build_subagent_headers();
    let value = headers
        .get(X_OPENAI_SUBAGENT_HEADER)
        .and_then(|value| value.to_str().ok());
    assert_eq!(value, Some("memory_consolidation"));
    assert_eq!(
        headers.get("originator"),
        Some(&http::HeaderValue::from_static("test_originator"))
    );
}

#[test]
fn build_ws_client_metadata_includes_window_lineage_and_turn_metadata() {
    let parent_thread_id = ThreadId::new();
    let client = test_model_client(SessionSource::SubAgent(SubAgentSource::ThreadSpawn {
        parent_thread_id,
        depth: 2,
        agent_path: None,
        agent_nickname: None,
        agent_role: None,
    }));

    let thread_id = client.state.thread_id.to_string();
    let expected_window_id = format!("{thread_id}:1");
    let responses_metadata = test_responses_metadata_for_client(
        &client,
        Some("turn-123"),
        expected_window_id.clone(),
        Some(parent_thread_id),
        TestCodexResponsesRequestKind::Turn,
    );
    let client_metadata =
        client.build_ws_client_metadata(&responses_metadata, /*use_responses_lite*/ false);
    let parent_thread_id = parent_thread_id.to_string();
    let turn_metadata: serde_json::Value = serde_json::from_str(
        client_metadata
            .get(X_CODEX_TURN_METADATA_HEADER)
            .expect("turn metadata"),
    )
    .expect("valid turn metadata");
    for (client_key, metadata_key, expected) in [
        (
            X_CODEX_INSTALLATION_ID_HEADER,
            "installation_id",
            "11111111-1111-4111-8111-111111111111",
        ),
        ("session_id", "session_id", thread_id.as_str()),
        ("thread_id", "thread_id", thread_id.as_str()),
        ("turn_id", "turn_id", "turn-123"),
        (
            X_CODEX_WINDOW_ID_HEADER,
            "window_id",
            expected_window_id.as_str(),
        ),
        (
            X_CODEX_PARENT_THREAD_ID_HEADER,
            "parent_thread_id",
            parent_thread_id.as_str(),
        ),
    ] {
        assert_eq!(
            client_metadata.get(client_key).map(String::as_str),
            Some(expected)
        );
        assert_eq!(turn_metadata[metadata_key].as_str(), Some(expected));
    }
    assert_eq!(
        client_metadata
            .get(X_OPENAI_SUBAGENT_HEADER)
            .map(String::as_str),
        Some("collab_spawn")
    );
}

#[tokio::test]
async fn summarize_memories_returns_empty_for_empty_input() {
    let client = test_model_client(SessionSource::Cli);
    let model_info = test_model_info();
    let session_telemetry = test_session_telemetry();

    let output = client
        .summarize_memories(
            Vec::new(),
            &model_info,
            /*effort*/ None,
            &session_telemetry,
        )
        .await
        .expect("empty summarize request should succeed");
    assert_eq!(output.len(), 0);
}

#[tokio::test]
async fn dropped_response_stream_traces_cancelled_partial_output() -> anyhow::Result<()> {
    let temp = TempDir::new()?;
    let attempt = started_inference_attempt(&temp)?;

    // The provider has produced one complete output item, but no terminal
    // response.completed event. The harness has enough information to keep this
    // item in history, so the trace should preserve it when the stream is
    // abandoned.
    let item = output_message("1", "partial answer");
    let api_stream = futures::stream::iter([Ok(ResponseEvent::OutputItemDone(item))])
        .chain(futures::stream::pending());
    let (mut stream, _) = super::map_response_events(
        /*upstream_request_id*/ None,
        api_stream,
        test_session_telemetry(),
        attempt,
        test_model_provider(),
    );

    let observed = stream
        .next()
        .await
        .expect("mapped stream should yield output item")?;
    assert!(matches!(observed, ResponseEvent::OutputItemDone(_)));

    // Dropping the consumer is how turn interruption/preemption stops polling
    // the provider stream. The mapper task observes that drop asynchronously
    // and records cancellation using the output items it has already seen.
    drop(stream);

    // Cancellation is recorded by the mapper task after Drop wakes it, so the
    // replay may need a short wait before the terminal event appears on disk.
    let rollout = replay_until_cancelled(&temp).await?;
    let inference = rollout
        .inference_calls
        .values()
        .next()
        .expect("inference should be reduced");

    assert_eq!(inference.execution.status, ExecutionStatus::Cancelled);
    assert_eq!(inference.response_item_ids.len(), 1);
    assert_eq!(rollout.raw_payloads.len(), 2);

    Ok(())
}

#[tokio::test]
async fn response_stream_records_last_model_feedback_ids() {
    let tags = Arc::new(Mutex::new(BTreeMap::new()));
    let _guard = tracing_subscriber::registry()
        .with(TagCollectorLayer { tags: tags.clone() })
        .set_default();

    let api_stream = futures::stream::iter([
        Ok(ResponseEvent::Created { response_id: None }),
        Ok(ResponseEvent::Completed {
            response_id: "resp-123".to_string(),
            token_usage: None,
            usage_metadata: None,
            end_turn: Some(true),
        }),
    ]);
    let (mut stream, _) = super::map_response_events(
        Some("req-123".to_string()),
        api_stream,
        test_session_telemetry(),
        InferenceTraceAttempt::disabled(),
        test_model_provider(),
    );

    while stream.next().await.is_some() {}

    let tags = tags.lock().unwrap().clone();
    assert_eq!(
        tags.get("last_model_request_id").map(String::as_str),
        Some("\"req-123\"")
    );
    assert_eq!(
        tags.get("last_model_response_id").map(String::as_str),
        Some("\"resp-123\"")
    );
}

#[tokio::test]
async fn bedrock_unauthorized_error_uses_provider_mapping() {
    let provider = create_model_provider(
        ModelProviderInfo::create_amazon_bedrock_provider(/*aws*/ None),
        /*auth_manager*/ None,
    );
    let mut auth_recovery = None;
    let mut provider_auth_recovery_attempted = false;
    let url = "https://bedrock-mantle.us-east-2.api.aws/openai/v1/responses";
    let error = super::handle_unauthorized(
        TransportError::Http {
            status: http::StatusCode::UNAUTHORIZED,
            url: Some(url.to_string()),
            headers: None,
            body: Some(
                "Signature expired: 20260609T133205Z is now earlier than 20260614T062525Z"
                    .to_string(),
            ),
        },
        &mut auth_recovery,
        &mut provider_auth_recovery_attempted,
        &test_session_telemetry(),
        &provider,
        /*event_sender*/ None,
        /*turn_id*/ None,
    )
    .await
    .expect_err("expired Bedrock signature should fail");

    assert_eq!(
        error.to_string(),
        format!(
            "Amazon Bedrock rejected the request because its AWS signature has expired. Refresh your AWS credentials and retry. If `AWS_BEARER_TOKEN_BEDROCK` is set, update or unset it, then restart Codex, url: {url}"
        )
    );
}

#[derive(Debug)]
struct TestRecoveryProvider {
    inner: SharedModelProvider,
    should_fail: bool,
    attempts: Arc<AtomicUsize>,
}

impl ModelProvider for TestRecoveryProvider {
    fn info(&self) -> &ModelProviderInfo {
        self.inner.info()
    }

    fn auth_manager(&self) -> Option<Arc<AuthManager>> {
        None
    }

    fn auth(&self) -> ModelProviderFuture<'_, Option<CodexAuth>> {
        self.inner.auth()
    }

    fn account_state(&self) -> ProviderAccountResult {
        self.inner.account_state()
    }

    fn auth_recovery_messages(&self) -> Option<ProviderAuthRecoveryMessages> {
        Some(ProviderAuthRecoveryMessages {
            started: "Refreshing provider authentication.",
            succeeded: "Provider authentication recovered.",
        })
    }

    fn recover_from_unauthorized(
        &self,
    ) -> ModelProviderFuture<'_, codex_protocol::error::Result<ProviderUnauthorizedRecovery>> {
        self.attempts.fetch_add(1, Ordering::Relaxed);
        Box::pin(async move {
            if self.should_fail {
                Err(CodexErr::Io(std::io::Error::other(
                    "provider recovery failed",
                )))
            } else {
                Ok(ProviderUnauthorizedRecovery::Recovered)
            }
        })
    }

    fn models_manager(
        &self,
        codex_home: PathBuf,
        config_model_catalog: Option<ModelsResponse>,
    ) -> SharedModelsManager {
        self.inner.models_manager(codex_home, config_model_catalog)
    }
}

#[tokio::test]
async fn provider_owned_auth_recovery_is_bounded_and_preserves_unauthorized_failures() {
    for should_fail in [false, true] {
        let attempts = Arc::new(AtomicUsize::new(0));
        let provider: SharedModelProvider = Arc::new(TestRecoveryProvider {
            inner: test_model_provider(),
            should_fail,
            attempts: Arc::clone(&attempts),
        });
        assert!(provider.auth_manager().is_none());

        let unauthorized = || TransportError::Http {
            status: http::StatusCode::UNAUTHORIZED,
            url: Some("https://example.com/v1/responses".to_string()),
            headers: None,
            body: Some("unauthorized".to_string()),
        };
        let mut auth_recovery = None;
        let mut provider_auth_recovery_attempted = false;
        let telemetry = test_session_telemetry();
        let (event_sender, event_receiver) = async_channel::unbounded();
        let result = super::handle_unauthorized(
            unauthorized(),
            &mut auth_recovery,
            &mut provider_auth_recovery_attempted,
            &telemetry,
            &provider,
            Some(&event_sender),
            Some("turn-1"),
        )
        .await;

        let error = if should_fail {
            result.expect_err("failed provider recovery should return the original error")
        } else {
            let recovered = result.expect("provider recovery should succeed without AuthManager");
            assert_eq!(
                (recovered.mode, recovered.phase),
                ("provider", "provider_refresh")
            );
            super::handle_unauthorized(
                unauthorized(),
                &mut auth_recovery,
                &mut provider_auth_recovery_attempted,
                &telemetry,
                &provider,
                Some(&event_sender),
                Some("turn-1"),
            )
            .await
            .expect_err("provider recovery should not run more than once")
        };

        match error.details() {
            CodexErrorDetails::UnexpectedStatus(response) => {
                assert_eq!(response.status, http::StatusCode::UNAUTHORIZED);
                assert_eq!(response.body, "unauthorized");
            }
            other => panic!("unexpected error after provider recovery: {other}"),
        }
        assert_eq!(attempts.load(Ordering::Relaxed), 1);

        let events = std::iter::from_fn(|| event_receiver.try_recv().ok())
            .map(|event| serde_json::to_value(event).expect("recovery event should serialize"))
            .collect::<Vec<_>>();
        let mut expected = vec![json!({
            "id": "turn-1",
            "msg": {
                "type": "auth_recovery_started",
                "provider": provider.info().name,
                "message": "Refreshing provider authentication.",
            }
        })];
        if !should_fail {
            expected.push(json!({
                "id": "turn-1",
                "msg": {
                    "type": "auth_recovery_completed",
                    "provider": provider.info().name,
                    "message": "Provider authentication recovered.",
                }
            }));
        }
        assert_eq!(events, expected);
    }
}

#[tokio::test]
async fn dropped_backpressured_response_stream_traces_cancelled_partial_output()
-> anyhow::Result<()> {
    let temp = TempDir::new()?;
    let attempt = started_inference_attempt(&temp)?;
    let backpressured_item_yielded = Arc::new(Notify::new());
    let mut events = VecDeque::new();
    for _ in 0..super::RESPONSE_STREAM_CHANNEL_CAPACITY {
        events.push_back(ResponseEvent::Created { response_id: None });
    }
    events.push_back(ResponseEvent::OutputItemDone(output_message(
        "1",
        "partial answer",
    )));
    let api_stream = NotifyAfterEventStream {
        events,
        yielded: 0,
        notify_after: super::RESPONSE_STREAM_CHANNEL_CAPACITY + 1,
        notify: Arc::clone(&backpressured_item_yielded),
    };

    let (stream, _) = super::map_response_events(
        /*upstream_request_id*/ None,
        api_stream,
        test_session_telemetry(),
        attempt,
        test_model_provider(),
    );

    // Fill the mapper channel with non-terminal events, then yield one output
    // item. The mapper has observed that item and is blocked trying to send it
    // downstream, so dropping the consumer covers the send-failure path rather
    // than the `consumer_dropped` select branch.
    backpressured_item_yielded.notified().await;
    drop(stream);

    let rollout = replay_until_cancelled(&temp).await?;
    let inference = rollout
        .inference_calls
        .values()
        .next()
        .expect("inference should be reduced");

    assert_eq!(inference.execution.status, ExecutionStatus::Cancelled);
    assert_eq!(inference.response_item_ids.len(), 1);
    assert_eq!(rollout.raw_payloads.len(), 2);

    Ok(())
}

#[test]
fn auth_request_telemetry_context_tracks_attached_auth_and_retry_phase() {
    let auth_context = AuthRequestTelemetryContext::new(
        Some(AuthMode::Chatgpt),
        &BearerAuthProvider::for_test(Some("access-token"), Some("workspace-123")),
        /*agent_identity_telemetry*/ None,
        PendingUnauthorizedRetry::from_recovery(UnauthorizedRecoveryExecution {
            mode: "managed",
            phase: "refresh_token",
        }),
    );

    assert_eq!(auth_context.auth_mode, Some("Chatgpt"));
    assert!(auth_context.auth_header_attached);
    assert_eq!(auth_context.auth_header_name, Some("authorization"));
    assert!(auth_context.retry_after_unauthorized);
    assert_eq!(auth_context.recovery_mode, Some("managed"));
    assert_eq!(auth_context.recovery_phase, Some("refresh_token"));
}

#[test]
fn auth_request_telemetry_context_tracks_agent_identity_ids() {
    let auth_context = AuthRequestTelemetryContext::new(
        Some(AuthMode::Chatgpt),
        &BearerAuthProvider::for_test(/*token*/ None, /*account_id*/ None),
        Some(AgentIdentityTelemetry {
            agent_id: "agent-runtime-context".to_string(),
            task_id: "task-run-context".to_string(),
        }),
        PendingUnauthorizedRetry::default(),
    );

    assert_eq!(
        auth_context.agent_identity_telemetry(),
        Some(&AgentIdentityTelemetry {
            agent_id: "agent-runtime-context".to_string(),
            task_id: "task-run-context".to_string(),
        })
    );
}

fn model_client_with_counting_attestation(
    include_attestation: bool,
) -> (ModelClient, Arc<AtomicUsize>) {
    #[derive(Debug)]
    struct CountingAttestationProvider {
        calls: Arc<AtomicUsize>,
    }

    impl AttestationProvider for CountingAttestationProvider {
        fn header_for_request(
            &self,
            _context: AttestationContext,
        ) -> GenerateAttestationFuture<'_> {
            let calls = self.calls.clone();
            Box::pin(async move {
                let call = calls.fetch_add(1, Ordering::Relaxed) + 1;
                Some(http::HeaderValue::from_bytes(format!("v1.header-{call}").as_bytes()).unwrap())
            })
        }
    }

    let attestation_calls = Arc::new(AtomicUsize::new(0));
    let (auth_manager, provider) = if include_attestation {
        (
            Some(AuthManager::from_auth_for_testing(
                CodexAuth::create_dummy_chatgpt_auth_for_testing(),
            )),
            ModelProviderInfo::create_openai_provider(Some(CHATGPT_CODEX_BASE_URL.to_string())),
        )
    } else {
        (
            None,
            create_oss_provider_with_base_url("https://example.com/v1", WireApi::Responses),
        )
    };
    let model_client = ModelClient::new(
        auth_manager,
        AgentIdentityAuthPolicy::JwtOnly,
        ThreadId::new(),
        provider,
        SessionSource::Exec,
        "test_originator".to_string(),
        /*model_verbosity*/ None,
        /*content_item_kinds_enabled*/ true,
        /*enable_request_compression*/ false,
        /*include_timing_metrics*/ false,
        /*beta_features_header*/ None,
        /*concurrent_reasoning_summaries_enabled*/ false,
        Some(Arc::new(CountingAttestationProvider {
            calls: attestation_calls.clone(),
        })),
        HttpClientFactory::new(OutboundProxyPolicy::ReqwestDefault),
    );
    (model_client, attestation_calls)
}

#[test]
fn guardian_reviewer_uses_dedicated_endpoint_only_with_codex_backend_auth() {
    let (mut model_client, _) =
        model_client_with_counting_attestation(/*include_attestation*/ true);
    Arc::get_mut(&mut model_client.state)
        .expect("test client should have unique session state")
        .session_source = SessionSource::SubAgent(SubAgentSource::Other("guardian".to_owned()));

    assert_eq!(
        model_client.responses_endpoint(
            Some(&CodexAuth::create_dummy_chatgpt_auth_for_testing()),
            "codex-auto-review",
        ),
        ResponsesEndpoint::Responses
    );

    model_client = model_client.with_free_guardian_enabled(/*free_guardian_enabled*/ true);
    assert_eq!(
        model_client.responses_endpoint(
            Some(&CodexAuth::create_dummy_chatgpt_auth_for_testing()),
            "codex-auto-review",
        ),
        ResponsesEndpoint::Guardian
    );
    assert_eq!(
        model_client.responses_endpoint(
            Some(&CodexAuth::create_dummy_chatgpt_auth_for_testing()),
            "required-reviewer-model",
        ),
        ResponsesEndpoint::Responses
    );
    assert_eq!(
        model_client.responses_endpoint(
            Some(&CodexAuth::create_dummy_chatgpt_auth_for_testing()),
            "parent-fallback-model",
        ),
        ResponsesEndpoint::Responses
    );
    assert_eq!(
        model_client.responses_endpoint(
            Some(&CodexAuth::from_api_key("test-api-key")),
            "codex-auto-review",
        ),
        ResponsesEndpoint::Responses
    );

    Arc::get_mut(&mut model_client.state)
        .expect("test client should have unique session state")
        .provider = create_model_provider(
        ModelProviderInfo::create_openai_provider(Some("https://proxy.example.com/v1".to_owned())),
        Some(AuthManager::from_auth_for_testing(
            CodexAuth::create_dummy_chatgpt_auth_for_testing(),
        )),
    );
    assert_eq!(
        model_client.responses_endpoint(
            Some(&CodexAuth::create_dummy_chatgpt_auth_for_testing()),
            "codex-auto-review",
        ),
        ResponsesEndpoint::Responses
    );

    Arc::get_mut(&mut model_client.state)
        .expect("test client should have unique session state")
        .session_source = SessionSource::Exec;
    assert_eq!(
        model_client.responses_endpoint(
            Some(&CodexAuth::create_dummy_chatgpt_auth_for_testing()),
            "codex-auto-review",
        ),
        ResponsesEndpoint::Responses
    );
}

#[tokio::test]
async fn websocket_handshake_includes_attestation_for_chatgpt_codex_responses() {
    let (model_client, attestation_calls) =
        model_client_with_counting_attestation(/*include_attestation*/ true);
    let responses_metadata = test_responses_metadata_for_client(
        &model_client,
        /*turn_id*/ None,
        format!("{}:0", model_client.state.thread_id),
        /*parent_thread_id*/ None,
        TestCodexResponsesRequestKind::WebsocketConnection,
    );

    let headers = model_client
        .build_websocket_headers(&responses_metadata)
        .await;

    assert_eq!(
        headers
            .get(crate::attestation::X_OAI_ATTESTATION_HEADER)
            .and_then(|value| value.to_str().ok()),
        Some("v1.header-1"),
    );
    assert_eq!(attestation_calls.load(Ordering::Relaxed), 1);
}

#[tokio::test]
async fn existing_call_sideband_headers_include_attestation() {
    let (model_client, attestation_calls) =
        model_client_with_counting_attestation(/*include_attestation*/ true);

    let headers = model_client
        .realtime_sideband_headers(http::HeaderMap::new())
        .await
        .expect("existing call sideband headers should build");

    assert_eq!(
        headers
            .get(crate::attestation::X_OAI_ATTESTATION_HEADER)
            .and_then(|value| value.to_str().ok()),
        Some("v1.header-1"),
    );
    assert_eq!(attestation_calls.load(Ordering::Relaxed), 1);
}

#[tokio::test]
async fn non_chatgpt_codex_endpoints_omit_attestation_generation() {
    let (model_client, attestation_calls) =
        model_client_with_counting_attestation(/*include_attestation*/ false);
    let mut response_headers = http::HeaderMap::new();

    if let Some(header_value) = model_client.generate_attestation_header_for().await {
        response_headers.insert(crate::attestation::X_OAI_ATTESTATION_HEADER, header_value);
    }
    let mut compaction_headers = http::HeaderMap::new();
    if let Some(header_value) = model_client.generate_attestation_header_for().await {
        compaction_headers.insert(crate::attestation::X_OAI_ATTESTATION_HEADER, header_value);
    }
    let mut realtime_headers = http::HeaderMap::new();
    if let Some(header_value) = model_client.generate_attestation_header_for().await {
        realtime_headers.insert(crate::attestation::X_OAI_ATTESTATION_HEADER, header_value);
    }

    assert_eq!(
        response_headers.get(crate::attestation::X_OAI_ATTESTATION_HEADER),
        None,
    );
    assert_eq!(
        compaction_headers.get(crate::attestation::X_OAI_ATTESTATION_HEADER),
        None,
    );
    assert_eq!(
        realtime_headers.get(crate::attestation::X_OAI_ATTESTATION_HEADER),
        None,
    );
    assert_eq!(attestation_calls.load(Ordering::Relaxed), 0);
}

#[test]
fn managed_account_failure_classification_is_narrow() {
    let unauthorized = CodexErr::UnexpectedStatus(UnexpectedResponseError {
        status: reqwest::StatusCode::UNAUTHORIZED,
        body: String::new(),
        user_message: None,
        url: None,
        cf_ray: None,
        request_id: None,
        identity_authorization_error: None,
        identity_error_code: None,
    });
    assert_eq!(
        super::managed_chatgpt_failure(&unauthorized),
        Some(ManagedChatgptFailure::AuthInvalid)
    );

    let generic_quota = CodexErr::UsageLimitReached(UsageLimitReachedError {
        plan_type: None,
        resets_at: None,
        rate_limits: None,
        promo_message: None,
        rate_limit_reached_type: Some(RateLimitReachedType::RateLimitReached),
    });
    assert_eq!(
        super::managed_chatgpt_failure(&generic_quota),
        Some(ManagedChatgptFailure::Quota { reset_at: None })
    );

    let workspace_quota = CodexErr::UsageLimitReached(UsageLimitReachedError {
        plan_type: None,
        resets_at: None,
        rate_limits: None,
        promo_message: None,
        rate_limit_reached_type: Some(RateLimitReachedType::WorkspaceMemberUsageLimitReached),
    });
    assert_eq!(
        super::managed_chatgpt_failure(&workspace_quota),
        Some(ManagedChatgptFailure::WorkspaceQuota { reset_at: None })
    );
}
