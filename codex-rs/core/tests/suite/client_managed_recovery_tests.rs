use super::*;
use base64::Engine as _;
use pretty_assertions::assert_eq;
use std::sync::atomic::AtomicUsize;
use std::sync::atomic::Ordering;
use wiremock::Respond;

#[derive(Clone, Copy, Debug)]
enum RetryOwner {
    Client,
    ExplicitSetup,
    Memories,
    Websocket,
    FreshRequests,
}

#[serial_test::serial(refresh_token_url_override)]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn managed_401_refresh_does_not_replenish_request_budget() -> anyhow::Result<()> {
    skip_if_no_network!(Ok(()));
    assert_managed_401_budget(RetryOwner::Client).await
}

#[serial_test::serial(refresh_token_url_override)]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn managed_explicit_setup_401_budget_survives_refresh() -> anyhow::Result<()> {
    skip_if_no_network!(Ok(()));
    assert_managed_401_budget(RetryOwner::ExplicitSetup).await
}

#[serial_test::serial(refresh_token_url_override)]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn managed_memories_401_budget_survives_refresh() -> anyhow::Result<()> {
    skip_if_no_network!(Ok(()));
    assert_managed_401_budget(RetryOwner::Memories).await
}

#[serial_test::serial(refresh_token_url_override)]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn managed_websocket_401_budget_survives_refresh() -> anyhow::Result<()> {
    skip_if_no_network!(Ok(()));
    assert_managed_401_budget(RetryOwner::Websocket).await
}

#[serial_test::serial(refresh_token_url_override)]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn managed_new_logical_request_gets_fresh_401_budget() -> anyhow::Result<()> {
    skip_if_no_network!(Ok(()));
    assert_managed_401_budget(RetryOwner::FreshRequests).await
}

async fn assert_managed_401_budget(retry_owner: RetryOwner) -> anyhow::Result<()> {
    struct UnauthorizedThenSentinel {
        calls: AtomicUsize,
        unauthorized_calls: usize,
    }

    impl Respond for UnauthorizedThenSentinel {
        fn respond(&self, request: &wiremock::Request) -> ResponseTemplate {
            if self.calls.fetch_add(/*val*/ 1, Ordering::SeqCst) < self.unauthorized_calls {
                ResponseTemplate::new(401).set_body_string("unauthorized")
            } else if request.method.as_str() == "GET" {
                ResponseTemplate::new(426)
            } else {
                // Bound defective recovery with an observable success, not a timeout.
                sse_response(sse(vec![
                    ev_response_created("unexpected-recovery-sentinel"),
                    ev_completed("unexpected-recovery-sentinel"),
                ]))
            }
        }
    }

    let encode = |value: &serde_json::Value| {
        serde_json::to_vec(value)
            .map(|bytes| base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes))
    };
    let header = encode(&json!({ "alg": "none", "typ": "JWT" }))?;
    let claims = encode(&json!({
        "email": "user@example.com",
        "https://api.openai.com/auth": {
            "chatgpt_plan_type": "pro",
            "chatgpt_user_id": "user-budget",
            "chatgpt_account_id": "workspace-budget"
        }
    }))?;
    let id_token = format!("{header}.{claims}.c2ln");

    let server = MockServer::start().await;
    let logical_requests = if matches!(retry_owner, RetryOwner::FreshRequests) {
        2
    } else {
        1
    };
    let model_path = if matches!(retry_owner, RetryOwner::Memories) {
        "/v1/memories/trace_summarize"
    } else {
        "/v1/responses"
    };
    let _refresh_url_guard = EnvGuard::set(
        codex_login::REFRESH_TOKEN_URL_OVERRIDE_ENV_VAR,
        format!("{}/oauth/token", server.uri()),
    );
    Mock::given(path(model_path))
        .respond_with(UnauthorizedThenSentinel {
            calls: AtomicUsize::new(/*v*/ 0),
            unauthorized_calls: 3 * logical_requests,
        })
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/oauth/token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "id_token": id_token,
            "access_token": "refreshed-access-token",
            "refresh_token": "refreshed-refresh-token"
        })))
        .mount(&server)
        .await;

    let codex_home = TempDir::new()?;
    let auth_manager = AuthManager::shared(
        codex_home.path().to_path_buf(),
        /*enable_codex_api_key_env*/ false,
        AuthCredentialsStoreMode::File,
        /*forced_chatgpt_workspace_id*/ None,
        /*chatgpt_base_url*/ None,
        AuthKeyringBackendKind::Direct,
        codex_login::test_support::transport_default_auth_route_config(),
    )
    .await;
    auth_manager
        .upsert_managed_chatgpt_oauth(ManagedChatgptOauthCredentials {
            tokens: TokenData {
                id_token: codex_login::token_data::parse_chatgpt_jwt_claims(&id_token)?,
                access_token: "initial-access-token".to_string(),
                refresh_token: "initial-refresh-token".to_string(),
                account_id: Some("workspace-budget".to_string()),
            },
            // Prevent an age-triggered refresh before the first model request.
            last_refresh: Utc::now(),
            oauth_api_key: None,
        })
        .await?;

    let provider = ModelProviderInfo {
        base_url: Some(format!("{}/v1", server.uri())),
        supports_websockets: matches!(retry_owner, RetryOwner::Websocket),
        ..built_in_model_providers(/*openai_base_url*/ None)["openai"].clone()
    };
    let mut config = load_default_config_for_test(&codex_home).await;
    config.model_provider_id = provider.name.clone();
    config.model_provider = provider.clone();
    let model = codex_core::test_support::get_model_offline(config.model.as_deref());
    config.model = Some(model.clone());
    let model_info =
        codex_core::test_support::construct_model_info_offline(model.as_str(), &config);
    let thread_id = ThreadId::new();
    let session_telemetry = SessionTelemetry::new(
        thread_id,
        model.as_str(),
        model_info.slug.as_str(),
        /*account_id*/ None,
        Some("user@example.com".to_string()),
        /*auth_mode*/ None,
        "test_originator".to_string(),
        /*log_user_prompts*/ false,
        "test".to_string(),
        SessionSource::Exec,
    );
    let client = ModelClient::new(
        Some(auth_manager),
        AgentIdentityAuthPolicy::JwtOnly,
        thread_id,
        provider,
        SessionSource::Exec,
        "test_originator".to_string(),
        config.model_verbosity,
        config.features.enabled(Feature::ContentItemKinds),
        config.features.enabled(Feature::ReasoningEffortOverride),
        /*enable_request_compression*/ false,
        /*include_timing_metrics*/ false,
        /*beta_features_header*/ None,
        config
            .features
            .enabled(Feature::ConcurrentReasoningSummaries),
        /*attestation_provider*/ None,
        config.http_client_factory(),
        config.workspace_routing_context(),
    );
    let responses_metadata = test_turn_responses_metadata(&client, thread_id);
    let mut client_session = client.new_session();
    let mut prompt = Prompt::default();
    prompt.input.push(ResponseItem::Message {
        id: None,
        role: "user".to_string(),
        content: vec![ContentItem::InputText {
            text: "hello".to_string(),
        }],
        phase: None,
        internal_chat_message_metadata_passthrough: None,
    });
    let effort = config.model_reasoning_effort.clone();
    let summary = config
        .model_reasoning_summary
        .unwrap_or(ReasoningSummary::Auto);
    let inference_trace = codex_rollout_trace::InferenceTraceContext::disabled();
    let mut outcomes = Vec::new();
    for _ in 0..logical_requests {
        client_session.begin_request();
        let result: codex_protocol::error::Result<Option<String>> = async {
            if matches!(retry_owner, RetryOwner::Memories) {
                return client
                    .summarize_memories(
                        vec![codex_api::RawMemory {
                            id: "raw-memory".to_string(),
                            metadata: codex_api::RawMemoryMetadata {
                                source_path: "synthetic-rollout".to_string(),
                            },
                            items: vec![json!({ "role": "user", "content": "remember this" })],
                        }],
                        &model_info,
                        effort.clone(),
                        &session_telemetry,
                    )
                    .await
                    .map(|_| None);
            }
            let mut stream = match retry_owner {
                RetryOwner::Client | RetryOwner::Websocket | RetryOwner::FreshRequests => {
                    client_session
                        .stream(
                            &prompt,
                            &model_info,
                            &session_telemetry,
                            effort.clone(),
                            summary,
                            /*service_tier*/ None,
                            &responses_metadata,
                            &inference_trace,
                        )
                        .await?
                }
                RetryOwner::ExplicitSetup => loop {
                    let setup = client_session
                        .current_client_setup(
                            Some(model_info.slug.as_str()),
                            /*session_id*/ None,
                        )
                        .await?;
                    match client_session
                        .stream_attempt_with_setup(
                            &prompt,
                            &model_info,
                            &session_telemetry,
                            effort.clone(),
                            summary,
                            /*service_tier*/ None,
                            &responses_metadata,
                            &inference_trace,
                            setup,
                        )
                        .await
                    {
                        Ok(stream) => break stream,
                        Err(error)
                            if client_session
                                .recover_last_managed_attempt(&error, /*committed*/ false)
                                .await => {}
                        Err(error) => return Err(error),
                    }
                },
                RetryOwner::Memories => unreachable!("unary request handled above"),
            };
            while let Some(event) = stream.next().await {
                if let ResponseEvent::Completed { response_id, .. } = event? {
                    return Ok(Some(response_id));
                }
            }
            Ok(None)
        }
        .await;
        let outcome = match result {
            Ok(response_id) => json!({ "completed": response_id }),
            Err(error) => match error.details() {
                CodexErrorDetails::UnexpectedStatus(response) => json!({
                    "status": response.status.as_u16(),
                    "body": response.body
                }),
                _ => json!({ "unexpected_error": error.to_string() }),
            },
        };
        outcomes.push(outcome);
    }
    let requests = server.received_requests().await.expect("recorded requests");
    let model_requests: Vec<_> = requests
        .iter()
        .filter(|request| request.url.path() == model_path)
        .map(|request| {
            json!({
                "method": request.method.as_str(),
                "authorization": request.headers.get("authorization").and_then(|v| v.to_str().ok()),
                "workspace": request.headers.get("chatgpt-account-id").and_then(|v| v.to_str().ok())
            })
        })
        .collect();
    let refresh_requests = requests
        .iter()
        .filter(|request| request.url.path() == "/oauth/token")
        .count();
    let method = if matches!(retry_owner, RetryOwner::Websocket) {
        "GET"
    } else {
        "POST"
    };
    let mut expected_model_requests = vec![
        json!({ "method": method, "authorization": "Bearer initial-access-token", "workspace": "workspace-budget" }),
        json!({ "method": method, "authorization": "Bearer initial-access-token", "workspace": "workspace-budget" }),
        json!({ "method": method, "authorization": "Bearer refreshed-access-token", "workspace": "workspace-budget" }),
    ];
    if logical_requests == 2 {
        expected_model_requests.extend(std::iter::repeat_n(
            json!({ "method": method, "authorization": "Bearer refreshed-access-token", "workspace": "workspace-budget" }),
            3,
        ));
    }
    assert_eq!(
        json!({
            "outcomes": outcomes,
            "model_requests": model_requests,
            "refresh_requests": refresh_requests
        }),
        json!({
            "outcomes": vec![json!({ "status": 401, "body": "unauthorized" }); logical_requests],
            "model_requests": expected_model_requests,
            "refresh_requests": logical_requests
        }),
        "successful credential refresh must not replenish the {retry_owner:?} request's 401 allowance"
    );
    Ok(())
}
