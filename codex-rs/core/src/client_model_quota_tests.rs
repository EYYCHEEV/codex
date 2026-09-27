use super::*;
use codex_login::ManagedChatgptEligibility;
use pretty_assertions::assert_eq;

enum RetrySetup {
    Explicit,
    Implicit,
}

#[tokio::test]
async fn managed_named_model_quota_rotates_without_blocking_other_models() -> anyhow::Result<()> {
    assert_named_model_quota_recovery(RetrySetup::Explicit).await
}

#[tokio::test]
async fn managed_named_model_quota_implicit_http_retry_preserves_exclusions() -> anyhow::Result<()>
{
    assert_named_model_quota_recovery(RetrySetup::Implicit).await
}

async fn assert_named_model_quota_recovery(retry_setup: RetrySetup) -> anyhow::Result<()> {
    let server = MockServer::start().await;
    let attempts = Arc::new(AtomicUsize::new(/*v*/ 0));
    let response_attempts = Arc::clone(&attempts);
    let reset = Utc::now() + chrono::Duration::hours(1);
    Mock::given(method("POST"))
        .and(path("/v1/responses"))
        .respond_with(move |request: &wiremock::Request| {
            let body: serde_json::Value = request.body_json().expect("request JSON");
            let account = request
                .headers
                .get("chatgpt-account-id")
                .and_then(|value| value.to_str().ok());
            let response_id = match (
                response_attempts.fetch_add(1, Ordering::SeqCst),
                account,
                body["model"].as_str(),
            ) {
                (0, Some("account-a"), Some("modelX")) => {
                    return ResponseTemplate::new(/*status*/ 429)
                        .insert_header("x-codex-active-limit", "codex_bengalfox")
                        .insert_header("x-codex-bengalfox-limit-name", "modelX")
                        .insert_header("x-codex-bengalfox-primary-used-percent", "100")
                        .set_body_json(json!({
                            "error": {
                                "type": "usage_limit_reached",
                                "plan_type": "pro",
                                "resets_at": reset.timestamp()
                            }
                        }));
                }
                (1, Some("account-b"), Some("modelX")) => "model-x-complete",
                (2, Some("account-a"), Some("modelY")) => "model-y-complete",
                // Unexpected routing terminates with a distinct completion instead of
                // feeding another recoverable failure into the retry loop.
                _ => "unexpected-request",
            };
            ResponseTemplate::new(/*status*/ 200)
                .insert_header("content-type", "text/event-stream")
                .set_body_string(format!(
                    "data: {}\n\ndata: {}\n\n",
                    json!({"type": "response.created", "response": {"id": response_id}}),
                    json!({"type": "response.completed", "response": {"id": response_id}}),
                ))
        })
        .mount(&server)
        .await;

    let home = TempDir::new()?;
    // Install both identities before streaming so the request freezes a two-account budget.
    let (client, manager) = two_account_model_client(&home, &server.uri()).await?;
    let accounts = manager.managed_chatgpt_accounts()?;
    let mut initial_accounts: Vec<_> = accounts
        .iter()
        .map(|account| {
            (
                account.chatgpt_account_id.as_deref(),
                account.eligibility.clone(),
                account.block_kind,
            )
        })
        .collect();
    initial_accounts.sort_by_key(|account| account.0);
    assert_eq!(
        initial_accounts,
        vec![
            (Some("account-a"), ManagedChatgptEligibility::Eligible, None),
            (Some("account-b"), ManagedChatgptEligibility::Eligible, None),
        ]
    );
    let mut session = client.new_session();
    let prompt = Prompt {
        input: vec![ResponseItem::Message {
            id: None,
            role: "user".to_string(),
            content: vec![ContentItem::InputText {
                text: "model-scoped quota recovery".to_string(),
            }],
            phase: None,
            internal_chat_message_metadata_passthrough: None,
        }],
        ..Default::default()
    };
    let metadata = test_responses_metadata_for_client(
        &client,
        /*turn_id*/ None,
        format!("{}:0", client.state.thread_id),
        /*parent_thread_id*/ None,
        TestCodexResponsesRequestKind::Turn,
    );
    let mut model = test_model_info();
    model.slug = "modelX".to_string();
    let telemetry = test_session_telemetry();
    let mut completed = None;
    session.begin_request();
    // This in-memory restriction only controls selection in the temporary fixture.
    manager.set_forced_chatgpt_workspace_id(Some(vec!["account-a".to_string()]));
    for attempt in 0..2 {
        let result = if attempt == 1 && matches!(retry_setup, RetrySetup::Implicit) {
            session
                .stream(
                    &prompt,
                    &model,
                    &telemetry,
                    /*effort*/ None,
                    codex_protocol::config_types::ReasoningSummary::None,
                    /*service_tier*/ None,
                    &metadata,
                    &InferenceTraceContext::disabled(),
                )
                .await
        } else {
            let setup = session
                .current_client_setup(Some(&model.slug), Some(&metadata.session_id))
                .await?;
            if attempt == 0 {
                assert_eq!(
                    setup
                        .effective_auth
                        .as_ref()
                        .and_then(CodexAuth::get_account_id),
                    Some("account-a".to_string())
                );
                // The captured A setup remains valid, and B is available before budget capture.
                manager.set_forced_chatgpt_workspace_id(None);
            }
            session
                .stream_attempt_with_setup(
                    &prompt,
                    &model,
                    &telemetry,
                    /*effort*/ None,
                    codex_protocol::config_types::ReasoningSummary::None,
                    /*service_tier*/ None,
                    &metadata,
                    &InferenceTraceContext::disabled(),
                    setup,
                )
                .await
        };
        match result {
            Ok(mut stream) => {
                while let Some(event) = stream.next().await {
                    if let ResponseEvent::Completed { response_id, .. } = event? {
                        completed = Some(response_id);
                    }
                }
                break;
            }
            Err(error) => {
                assert_eq!(attempt, 0, "only A/modelX may fail before completion");
                let CodexErrorDetails::UsageLimitReached(quota) = error.details() else {
                    panic!("expected a named model quota error, got {error}");
                };
                assert_eq!(
                    quota
                        .rate_limits
                        .as_ref()
                        .and_then(|limits| limits.limit_name.as_deref()),
                    Some("modelX")
                );
                assert!(
                    !session
                        .recover_last_managed_attempt(&error, /*committed*/ true)
                        .await,
                    "committed output must never authorize account replay"
                );
                assert!(
                    session
                        .recover_last_managed_attempt(&error, /*committed*/ false)
                        .await,
                    "modelX quota must permit recovery to B in the same request"
                );
            }
        }
    }
    let request_pair = |request: &wiremock::Request| {
        let body: serde_json::Value = request.body_json().expect("request JSON");
        (
            request.headers["chatgpt-account-id"]
                .to_str()
                .unwrap()
                .to_string(),
            body["model"].as_str().unwrap().to_string(),
        )
    };
    let requests = server.received_requests().await.expect("recorded requests");
    assert_eq!(
        (
            completed.as_deref(),
            requests.iter().map(&request_pair).collect::<Vec<_>>(),
        ),
        (
            Some("model-x-complete"),
            vec![
                ("account-a".to_string(), "modelX".to_string()),
                ("account-b".to_string(), "modelX".to_string()),
            ],
        )
    );

    // Observe the unrestricted owner before selecting A for the next model.
    let accounts = manager.managed_chatgpt_accounts()?;
    let account_a = accounts
        .iter()
        .find(|account| account.chatgpt_account_id.as_deref() == Some("account-a"))
        .expect("A remains in the managed pool");
    assert_eq!(
        (
            &account_a.eligibility,
            account_a.block_kind,
            account_a.block_reset_at,
        ),
        (&ManagedChatgptEligibility::Eligible, None, None),
        "a named model quota must not create a durable account-wide block"
    );

    session.begin_request();
    model.slug = "modelY".to_string();
    manager.set_forced_chatgpt_workspace_id(Some(vec!["account-a".to_string()]));
    let setup = session
        .current_client_setup(Some(&model.slug), Some(&metadata.session_id))
        .await?;
    assert_eq!(
        setup
            .effective_auth
            .as_ref()
            .and_then(CodexAuth::get_account_id),
        Some("account-a".to_string())
    );
    let mut stream = session
        .stream_attempt_with_setup(
            &prompt,
            &model,
            &telemetry,
            /*effort*/ None,
            codex_protocol::config_types::ReasoningSummary::None,
            /*service_tier*/ None,
            &metadata,
            &InferenceTraceContext::disabled(),
            setup,
        )
        .await?;
    let mut completed = None;
    while let Some(event) = stream.next().await {
        if let ResponseEvent::Completed { response_id, .. } = event? {
            completed = Some(response_id);
        }
    }
    manager.set_forced_chatgpt_workspace_id(None);
    let requests = server.received_requests().await.expect("recorded requests");
    assert_eq!(
        (
            completed.as_deref(),
            requests.iter().map(request_pair).collect::<Vec<_>>(),
        ),
        (
            Some("model-y-complete"),
            vec![
                ("account-a".to_string(), "modelX".to_string()),
                ("account-b".to_string(), "modelX".to_string()),
                ("account-a".to_string(), "modelY".to_string()),
            ],
        )
    );
    Ok(())
}
