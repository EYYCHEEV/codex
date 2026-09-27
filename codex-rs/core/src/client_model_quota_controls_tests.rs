use super::*;
use codex_login::ManagedChatgptEligibility;
use pretty_assertions::assert_eq;

#[derive(Clone, Copy)]
enum QuotaPool {
    Single,
    Pair,
    RestrictedPair,
}

#[test_case::test_case("codex_bengalfox", Some("modelX"), None, QuotaPool::Pair, None; "named_model")]
#[test_case::test_case("codex_bengalfox", Some("  modelX  "), None, QuotaPool::Pair, None; "trimmed_name")]
#[test_case::test_case("codex_bengalfox", Some("modelX"), None, QuotaPool::Single, None; "no_alternate")]
#[test_case::test_case("codex_bengalfox", Some("modelX"), None, QuotaPool::RestrictedPair, None; "alternate_disallowed")]
#[test_case::test_case("codex_bengalfox", None, None, QuotaPool::Pair, Some(ManagedChatgptBlockKindView::Quota); "custom_id_only")]
#[test_case::test_case("codex_bengalfox", Some("  "), None, QuotaPool::Pair, Some(ManagedChatgptBlockKindView::Quota); "blank_name")]
#[test_case::test_case("codex", None, None, QuotaPool::Pair, Some(ManagedChatgptBlockKindView::Quota); "canonical_without_name")]
#[test_case::test_case("codex", Some("modelX"), None, QuotaPool::Pair, Some(ManagedChatgptBlockKindView::Quota); "canonical_id_veto")]
#[test_case::test_case("gpt_reserve", Some("modelX"), None, QuotaPool::Pair, Some(ManagedChatgptBlockKindView::Quota); "normalized_reserve_id_veto")]
#[test_case::test_case("codex_bengalfox", Some("CoDeX"), None, QuotaPool::Pair, Some(ManagedChatgptBlockKindView::Quota); "canonical_name")]
#[test_case::test_case("codex_bengalfox", Some("gpt-reserve"), None, QuotaPool::Pair, Some(ManagedChatgptBlockKindView::Quota); "reserve_name")]
#[test_case::test_case("codex_bengalfox", Some("gpt_reserve"), None, QuotaPool::Pair, Some(ManagedChatgptBlockKindView::Quota); "normalized_reserve_name")]
#[test_case::test_case("codex_bengalfox", Some("modelX"), Some("workspace_owner_credits_depleted"), QuotaPool::Pair, Some(ManagedChatgptBlockKindView::Workspace); "workspace_overrides_name")]
#[tokio::test]
async fn managed_quota_scope_controls(
    limit_id: &str,
    limit_name: Option<&str>,
    reached_type: Option<&str>,
    pool: QuotaPool,
    expected_block: Option<ManagedChatgptBlockKindView>,
) -> anyhow::Result<()> {
    let server = MockServer::start().await;
    let reset = Utc::now() + chrono::Duration::hours(1);
    let prefix = limit_id.replace('_', "-");
    let mut response = ResponseTemplate::new(/*status*/ 429)
        .insert_header("x-codex-active-limit", limit_id)
        .insert_header(format!("x-{prefix}-primary-used-percent"), "100")
        .set_body_json(json!({
            "error": {"type": "usage_limit_reached", "plan_type": "pro", "resets_at": reset.timestamp()}
        }));
    if let Some(limit_name) = limit_name {
        response = response.insert_header(format!("x-{prefix}-limit-name"), limit_name);
    }
    if let Some(reached_type) = reached_type {
        response = response.insert_header("x-codex-rate-limit-reached-type", reached_type);
    }
    Mock::given(method("POST"))
        .and(path("/v1/responses"))
        .respond_with(response)
        .expect(1)
        .mount(&server)
        .await;
    let home = TempDir::new()?;
    let identities = match pool {
        QuotaPool::Single => &[("a@example.com", "account-a")][..],
        QuotaPool::Pair | QuotaPool::RestrictedPair => &[
            ("a@example.com", "account-a"),
            ("b@example.com", "account-b"),
        ][..],
    };
    let (client, manager) = managed_accounts_model_client(&home, &server.uri(), identities).await?;
    let mut session = client.new_session();
    let mut model = test_model_info();
    model.slug = "modelX".to_string();
    let metadata = test_responses_metadata_for_client(
        &client,
        /*turn_id*/ None,
        format!("{}:0", client.state.thread_id),
        /*parent_thread_id*/ None,
        TestCodexResponsesRequestKind::Turn,
    );
    session.begin_request();
    manager.set_forced_chatgpt_workspace_id(Some(vec!["account-a".to_string()]));
    let setup = session
        .current_client_setup(Some(&model.slug), Some(&metadata.session_id))
        .await?;
    if !matches!(pool, QuotaPool::RestrictedPair) {
        manager.set_forced_chatgpt_workspace_id(None);
    }
    let Err(error) = session
        .stream_attempt_with_setup(
            &Prompt::default(),
            &model,
            &test_session_telemetry(),
            /*effort*/ None,
            codex_protocol::config_types::ReasoningSummary::None,
            /*service_tier*/ None,
            &metadata,
            &InferenceTraceContext::disabled(),
            setup,
        )
        .await
    else {
        panic!("fixture must return a quota error");
    };
    assert!(matches!(
        error.details(),
        CodexErrorDetails::UsageLimitReached(_)
    ));
    let recovered = session
        .recover_last_managed_attempt(&error, /*committed*/ false)
        .await;
    let accounts = manager.managed_chatgpt_accounts()?;
    let account_a = accounts
        .iter()
        .find(|account| account.chatgpt_account_id.as_deref() == Some("account-a"))
        .expect("A remains in the pool");
    assert_eq!(
        (
            recovered,
            &account_a.eligibility,
            account_a.block_kind,
            account_a.block_reset_at.is_some()
        ),
        (
            matches!(pool, QuotaPool::Pair),
            if expected_block.is_some() {
                &ManagedChatgptEligibility::Blocked
            } else {
                &ManagedChatgptEligibility::Eligible
            },
            expected_block,
            expected_block.is_some(),
        )
    );
    Ok(())
}

#[tokio::test]
async fn managed_named_model_quota_memory_retry_preserves_exclusions() -> anyhow::Result<()> {
    let server = MockServer::start().await;
    let home = TempDir::new()?;
    let (client, manager) = two_account_model_client(&home, &server.uri()).await?;
    let response_manager = Arc::clone(&manager);
    let attempts = Arc::new(AtomicUsize::new(/*v*/ 0));
    let response_attempts = Arc::clone(&attempts);
    Mock::given(method("POST"))
        .and(path("/v1/memories/trace_summarize"))
        .respond_with(move |request: &wiremock::Request| {
            let account = request.headers["chatgpt-account-id"].to_str().unwrap();
            match (response_attempts.fetch_add(1, Ordering::SeqCst), account) {
                (0, "account-a") => {
                    response_manager.set_forced_chatgpt_workspace_id(None);
                    ResponseTemplate::new(/*status*/ 429)
                        .insert_header("x-codex-active-limit", "codex_bengalfox")
                        .insert_header("x-codex-bengalfox-limit-name", "modelX")
                        .insert_header("x-codex-bengalfox-primary-used-percent", "100")
                        .set_body_json(json!({
                            "error": {
                                "type": "usage_limit_reached",
                                "plan_type": "pro",
                                "resets_at": (Utc::now() + chrono::Duration::hours(1)).timestamp()
                            }
                        }))
                }
                (1, "account-b") => ResponseTemplate::new(/*status*/ 200).set_body_json(json!({
                    "output": [{"trace_summary": "raw summary", "memory_summary": "modelX summary"}]
                })),
                _ => {
                    ResponseTemplate::new(/*status*/ 400).set_body_string("unexpected memory retry")
                }
            }
        })
        .mount(&server)
        .await;
    let mut model = test_model_info();
    model.slug = "modelX".to_string();
    // Both identities already exist; release this fixture restriction when A's request arrives.
    manager.set_forced_chatgpt_workspace_id(Some(vec!["account-a".to_string()]));
    let output = client
        .summarize_memories(
            vec![codex_api::RawMemory {
                id: "raw-memory".to_string(),
                metadata: codex_api::RawMemoryMetadata {
                    source_path: "synthetic-rollout".to_string(),
                },
                items: vec![json!({"role": "user", "content": "remember this"})],
            }],
            &model,
            /*effort*/ None,
            &test_session_telemetry(),
        )
        .await?;
    assert_eq!(
        output,
        vec![codex_api::MemorySummarizeOutput {
            raw_memory: "raw summary".to_string(),
            memory_summary: "modelX summary".to_string(),
        }]
    );
    let requests = server.received_requests().await.expect("recorded requests");
    let sequence: Vec<_> = requests
        .iter()
        .map(|request| {
            let body: serde_json::Value = request.body_json().expect("request JSON");
            (
                request.headers["chatgpt-account-id"]
                    .to_str()
                    .unwrap()
                    .to_string(),
                body["model"].clone(),
            )
        })
        .collect();
    assert_eq!(
        sequence,
        vec![
            ("account-a".to_string(), json!("modelX")),
            ("account-b".to_string(), json!("modelX"))
        ]
    );
    assert!(manager.managed_chatgpt_accounts()?.iter().all(|account| {
        account.eligibility == ManagedChatgptEligibility::Eligible && account.block_kind.is_none()
    }));
    Ok(())
}

#[tokio::test]
async fn managed_named_model_quota_websocket_retry_and_http_fallback_preserve_exclusions()
-> anyhow::Result<()> {
    let server = MockServer::start().await;
    let home = TempDir::new()?;
    let (mut client, manager) = two_account_model_client(&home, &server.uri()).await?;
    let mut provider = client.state.provider.info().clone();
    provider.supports_websockets = true;
    Arc::get_mut(&mut client.state)
        .expect("unique fixture client")
        .provider = create_model_provider(provider, Some(Arc::clone(&manager)));
    let attempts = Arc::new(AtomicUsize::new(/*v*/ 0));
    let response_attempts = Arc::clone(&attempts);
    Mock::given(path("/v1/responses"))
        .respond_with(move |request: &wiremock::Request| {
            let account = request.headers["chatgpt-account-id"].to_str().unwrap();
            match (response_attempts.fetch_add(1, Ordering::SeqCst), request.method.as_str(), account) {
                (0, "GET", "account-a") => ResponseTemplate::new(/*status*/ 429)
                    .insert_header("x-codex-active-limit", "codex_bengalfox")
                    .insert_header("x-codex-bengalfox-limit-name", "modelX")
                    .insert_header("x-codex-bengalfox-primary-used-percent", "100")
                    .set_body_json(json!({
                        "error": {
                            "type": "usage_limit_reached",
                            "plan_type": "pro",
                            "resets_at": (Utc::now() + chrono::Duration::hours(1)).timestamp()
                        }
                    })),
                (1, "GET", "account-b") => ResponseTemplate::new(/*status*/ 426),
                (2, "POST", "account-b") => ResponseTemplate::new(/*status*/ 200)
                    .insert_header("content-type", "text/event-stream")
                    .set_body_string(concat!(
                        "data: {\"type\":\"response.created\",\"response\":{\"id\":\"fallback-complete\"}}\n\n",
                        "data: {\"type\":\"response.completed\",\"response\":{\"id\":\"fallback-complete\"}}\n\n",
                    )),
                _ => ResponseTemplate::new(/*status*/ 400).set_body_string("unexpected websocket retry"),
            }
        })
        .mount(&server)
        .await;
    let mut session = client.new_session();
    let mut model = test_model_info();
    model.slug = "modelX".to_string();
    let metadata = test_responses_metadata_for_client(
        &client,
        /*turn_id*/ None,
        format!("{}:0", client.state.thread_id),
        /*parent_thread_id*/ None,
        TestCodexResponsesRequestKind::Turn,
    );
    session.begin_request();
    manager.set_forced_chatgpt_workspace_id(Some(vec!["account-a".to_string()]));
    let setup = session
        .current_client_setup(Some(&model.slug), Some(&metadata.session_id))
        .await?;
    manager.set_forced_chatgpt_workspace_id(None);
    let Err(error) = session
        .stream_attempt_with_setup(
            &Prompt::default(),
            &model,
            &test_session_telemetry(),
            /*effort*/ None,
            codex_protocol::config_types::ReasoningSummary::None,
            /*service_tier*/ None,
            &metadata,
            &InferenceTraceContext::disabled(),
            setup,
        )
        .await
    else {
        panic!("A's handshake must return a quota error");
    };
    assert!(matches!(
        error.details(),
        CodexErrorDetails::UsageLimitReached(_)
    ));
    assert!(
        session
            .recover_last_managed_attempt(&error, /*committed*/ false)
            .await
    );
    let mut stream = session
        .stream(
            &Prompt::default(),
            &model,
            &test_session_telemetry(),
            /*effort*/ None,
            codex_protocol::config_types::ReasoningSummary::None,
            /*service_tier*/ None,
            &metadata,
            &InferenceTraceContext::disabled(),
        )
        .await?;
    let mut completed = None;
    while let Some(event) = stream.next().await {
        if let ResponseEvent::Completed { response_id, .. } = event? {
            completed = Some(response_id);
        }
    }
    assert_eq!(completed.as_deref(), Some("fallback-complete"));
    let requests = server.received_requests().await.expect("recorded requests");
    let sequence: Vec<_> = requests
        .iter()
        .map(|request| {
            (
                request.method.as_str(),
                request.headers["chatgpt-account-id"].to_str().unwrap(),
            )
        })
        .collect();
    assert_eq!(
        sequence,
        vec![
            ("GET", "account-a"),
            ("GET", "account-b"),
            ("POST", "account-b")
        ]
    );
    assert_eq!(
        requests[2].body_json::<serde_json::Value>()?["model"],
        json!("modelX")
    );
    assert!(manager.managed_chatgpt_accounts()?.iter().all(|account| {
        account.eligibility == ManagedChatgptEligibility::Eligible && account.block_kind.is_none()
    }));
    Ok(())
}

#[tokio::test]
async fn managed_durable_failure_does_not_reselect_a_model_excluded_account() -> anyhow::Result<()>
{
    let server = MockServer::start().await;
    let home = TempDir::new()?;
    let (client, manager) = managed_accounts_model_client(
        &home,
        &server.uri(),
        &[
            ("a@example.com", "account-a"),
            ("b@example.com", "account-b"),
            ("c@example.com", "account-c"),
        ],
    )
    .await?;
    let attempts = Arc::new(AtomicUsize::new(/*v*/ 0));
    let response_attempts = Arc::clone(&attempts);
    Mock::given(method("POST"))
        .and(path("/v1/responses"))
        .respond_with(move |request: &wiremock::Request| {
            let account = request.headers["chatgpt-account-id"].to_str().unwrap();
            let attempt = response_attempts.fetch_add(1, Ordering::SeqCst);
            if !matches!((attempt, account), (0, "account-a") | (1, "account-b")) {
                return ResponseTemplate::new(/*status*/ 400).set_body_string("unexpected retry");
            }
            let response = ResponseTemplate::new(/*status*/ 429).set_body_json(json!({
                "error": {
                    "type": "usage_limit_reached",
                    "plan_type": "pro",
                    "resets_at": (Utc::now() + chrono::Duration::hours(1)).timestamp()
                }
            }));
            if attempt == 0 {
                response
                    .insert_header("x-codex-active-limit", "codex_bengalfox")
                    .insert_header("x-codex-bengalfox-limit-name", "modelX")
                    .insert_header("x-codex-bengalfox-primary-used-percent", "100")
            } else {
                response
            }
        })
        .mount(&server)
        .await;
    let mut session = client.new_session();
    let mut model = test_model_info();
    model.slug = "modelX".to_string();
    let metadata = test_responses_metadata_for_client(
        &client,
        /*turn_id*/ None,
        format!("{}:0", client.state.thread_id),
        /*parent_thread_id*/ None,
        TestCodexResponsesRequestKind::Turn,
    );
    session.begin_request();
    for (account, recovery_candidate, expected_recovery) in [
        ("account-a", "account-b", true),
        ("account-b", "account-a", false),
    ] {
        manager.set_forced_chatgpt_workspace_id(Some(vec![account.to_string()]));
        let setup = session
            .current_client_setup(Some(&model.slug), Some(&metadata.session_id))
            .await?;
        manager.set_forced_chatgpt_workspace_id(None);
        let Err(error) = session
            .stream_attempt_with_setup(
                &Prompt::default(),
                &model,
                &test_session_telemetry(),
                /*effort*/ None,
                codex_protocol::config_types::ReasoningSummary::None,
                /*service_tier*/ None,
                &metadata,
                &InferenceTraceContext::disabled(),
                setup,
            )
            .await
        else {
            panic!("both fixture attempts must return quota errors");
        };
        assert!(matches!(
            error.details(),
            CodexErrorDetails::UsageLimitReached(_)
        ));
        // N=3 leaves another rotation after A. Only exclusion, not exhaustion,
        // prevents B's durable failure from rotating back to A.
        manager.set_forced_chatgpt_workspace_id(Some(vec![
            account.to_string(),
            recovery_candidate.to_string(),
        ]));
        assert_eq!(
            session
                .recover_last_managed_attempt(&error, /*committed*/ false)
                .await,
            expected_recovery
        );
    }
    manager.set_forced_chatgpt_workspace_id(None);
    let accounts = manager.managed_chatgpt_accounts()?;
    let mut status: Vec<_> = accounts
        .iter()
        .map(|account| {
            (
                account.chatgpt_account_id.as_deref(),
                account.eligibility.clone(),
                account.block_kind,
            )
        })
        .collect();
    status.sort_by_key(|account| account.0);
    assert_eq!(
        status,
        vec![
            (Some("account-a"), ManagedChatgptEligibility::Eligible, None),
            (
                Some("account-b"),
                ManagedChatgptEligibility::Blocked,
                Some(ManagedChatgptBlockKindView::Quota)
            ),
            (Some("account-c"), ManagedChatgptEligibility::Eligible, None),
        ]
    );
    assert_eq!(attempts.load(Ordering::SeqCst), 2);
    Ok(())
}

#[tokio::test]
async fn managed_named_model_quota_stale_credentials_do_not_rotate() -> anyhow::Result<()> {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/v1/responses"))
        .respond_with(
            ResponseTemplate::new(/*status*/ 429)
                .insert_header("x-codex-active-limit", "codex_bengalfox")
                .insert_header("x-codex-bengalfox-limit-name", "modelX")
                .insert_header("x-codex-bengalfox-primary-used-percent", "100")
                .set_body_json(json!({
                    "error": {
                        "type": "usage_limit_reached",
                        "plan_type": "pro",
                        "resets_at": (Utc::now() + chrono::Duration::hours(1)).timestamp()
                    }
                })),
        )
        .expect(1)
        .mount(&server)
        .await;
    let home = TempDir::new()?;
    let (client, manager) = two_account_model_client(&home, &server.uri()).await?;
    let mut session = client.new_session();
    let mut model = test_model_info();
    model.slug = "modelX".to_string();
    let metadata = test_responses_metadata_for_client(
        &client,
        /*turn_id*/ None,
        format!("{}:0", client.state.thread_id),
        /*parent_thread_id*/ None,
        TestCodexResponsesRequestKind::Turn,
    );
    session.begin_request();
    manager.set_forced_chatgpt_workspace_id(Some(vec!["account-a".to_string()]));
    let setup = session
        .current_client_setup(Some(&model.slug), Some(&metadata.session_id))
        .await?;
    let identity = setup.managed_id.clone().expect("A's managed identity");
    let original_revision = setup
        .credential_revision
        .expect("captured credential revision");
    let mut replacement_tokens = setup
        .effective_auth
        .as_ref()
        .expect("A's captured synthetic credentials")
        .get_token_data()?;
    assert_eq!(replacement_tokens.account_id.as_deref(), Some("account-a"));
    manager.set_forced_chatgpt_workspace_id(None);
    let Err(error) = session
        .stream_attempt_with_setup(
            &Prompt::default(),
            &model,
            &test_session_telemetry(),
            /*effort*/ None,
            codex_protocol::config_types::ReasoningSummary::None,
            /*service_tier*/ None,
            &metadata,
            &InferenceTraceContext::disabled(),
            setup,
        )
        .await
    else {
        panic!("A's captured attempt must fail with the named-model quota");
    };
    assert!(matches!(
        error.details(),
        CodexErrorDetails::UsageLimitReached(_)
    ));

    // Replace credentials only after the old request has received its quota error.
    replacement_tokens.access_token = "replacement-access-account-a".to_string();
    replacement_tokens.refresh_token = "replacement-refresh-account-a".to_string();
    let replaced_identity = manager
        .upsert_managed_chatgpt_oauth(ManagedChatgptOauthCredentials {
            tokens: replacement_tokens,
            last_refresh: Utc::now(),
            oauth_api_key: None,
        })
        .await?;
    assert_eq!(replaced_identity, identity);
    let accounts = manager.managed_chatgpt_accounts()?;
    let account_a = accounts
        .iter()
        .find(|account| account.identity_key == identity)
        .expect("replaced A remains in the pool");
    assert!(account_a.credential_revision > original_revision);
    assert_eq!(accounts.len(), 2);
    assert!(accounts.iter().all(|account| {
        account.eligibility == ManagedChatgptEligibility::Eligible && account.block_kind.is_none()
    }));
    assert!(
        !session
            .recover_last_managed_attempt(&error, /*committed*/ false)
            .await,
        "a quota response from superseded credentials must not rotate away from the replacement"
    );
    assert!(manager.managed_chatgpt_accounts()?.iter().all(|account| {
        account.eligibility == ManagedChatgptEligibility::Eligible && account.block_kind.is_none()
    }));
    assert_eq!(
        server
            .received_requests()
            .await
            .expect("recorded requests")
            .len(),
        1
    );
    Ok(())
}
