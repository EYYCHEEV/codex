use super::*;
use codex_login::ManagedChatgptEligibility;
use codex_protocol::protocol::RateLimitReachedType;
use pretty_assertions::assert_eq;

#[derive(Clone, Copy)]
enum LimitScope {
    Identity,
    Workspace,
}

#[derive(Clone, Copy)]
enum ModelLimitEvidence {
    Absent,
    ExhaustedNamedModel,
}

#[tokio::test]
async fn managed_workspace_owner_spend_cap_preserves_healthy_sibling() -> anyhow::Result<()> {
    assert_workspace_cap_scope(
        "workspace_owner_usage_limit_reached",
        LimitScope::Identity,
        ModelLimitEvidence::Absent,
    )
    .await
}

#[tokio::test]
async fn managed_workspace_member_spend_cap_preserves_healthy_sibling() -> anyhow::Result<()> {
    assert_workspace_cap_scope(
        "workspace_member_usage_limit_reached",
        LimitScope::Identity,
        ModelLimitEvidence::Absent,
    )
    .await
}

#[tokio::test]
async fn managed_workspace_owner_credits_block_same_workspace_sibling() -> anyhow::Result<()> {
    assert_workspace_cap_scope(
        "workspace_owner_credits_depleted",
        LimitScope::Workspace,
        ModelLimitEvidence::Absent,
    )
    .await
}

#[tokio::test]
async fn managed_workspace_member_credits_block_same_workspace_sibling() -> anyhow::Result<()> {
    assert_workspace_cap_scope(
        "workspace_member_credits_depleted",
        LimitScope::Workspace,
        ModelLimitEvidence::Absent,
    )
    .await
}

#[tokio::test]
async fn managed_workspace_owner_spend_cap_overrides_named_model_limit() -> anyhow::Result<()> {
    assert_workspace_cap_scope(
        "workspace_owner_usage_limit_reached",
        LimitScope::Identity,
        ModelLimitEvidence::ExhaustedNamedModel,
    )
    .await
}

#[tokio::test]
async fn managed_workspace_member_spend_cap_overrides_named_model_limit() -> anyhow::Result<()> {
    assert_workspace_cap_scope(
        "workspace_member_usage_limit_reached",
        LimitScope::Identity,
        ModelLimitEvidence::ExhaustedNamedModel,
    )
    .await
}

async fn assert_workspace_cap_scope(
    code: &'static str,
    scope: LimitScope,
    model_limit_evidence: ModelLimitEvidence,
) -> anyhow::Result<()> {
    let server = MockServer::start().await;
    let home = TempDir::new()?;
    let (client, manager) = managed_accounts_model_client(&home, &server.uri(), &[]).await?;
    for email in ["a@example.com", "b@example.com"] {
        let encode = |value: &serde_json::Value| {
            serde_json::to_vec(value)
                .map(|bytes| base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes))
        };
        let header = encode(&json!({ "alg": "none", "typ": "JWT" }))?;
        let claims = encode(&json!({
            "email": email,
            "email_verified": true,
            "https://api.openai.com/auth": {
                "chatgpt_user_id": format!("user-{email}"),
                "chatgpt_account_id": "shared-workspace",
                "chatgpt_plan_type": "pro"
            }
        }))?;
        let jwt = format!("{header}.{claims}.c2ln");
        manager
            .upsert_managed_chatgpt_oauth(ManagedChatgptOauthCredentials {
                tokens: TokenData {
                    id_token: codex_login::token_data::parse_chatgpt_jwt_claims(&jwt)?,
                    access_token: format!("access-{email}"),
                    refresh_token: format!("refresh-{email}"),
                    account_id: Some("shared-workspace".to_string()),
                },
                last_refresh: Utc::now(),
                oauth_api_key: None,
            })
            .await?;
    }
    let initial_accounts = manager.managed_chatgpt_accounts()?;
    let mut initial_state: Vec<_> = initial_accounts
        .iter()
        .map(|account| {
            (
                account.normalized_email.as_deref(),
                account.chatgpt_account_id.as_deref(),
                account.eligibility.clone(),
                account.block_kind,
            )
        })
        .collect();
    initial_state.sort_by_key(|account| account.0);
    assert_eq!(
        initial_state,
        vec![
            (
                Some("a@example.com"),
                Some("shared-workspace"),
                ManagedChatgptEligibility::Eligible,
                None,
            ),
            (
                Some("b@example.com"),
                Some("shared-workspace"),
                ManagedChatgptEligibility::Eligible,
                None,
            ),
        ],
    );
    assert_ne!(
        initial_accounts[0].identity_key,
        initial_accounts[1].identity_key
    );

    let mut session = client.new_session();
    session.begin_request();
    let mut model = test_model_info();
    model.slug = "workspace-cap-model".to_string();
    let telemetry = test_session_telemetry();
    let metadata = test_responses_metadata_for_client(
        &client,
        /*turn_id*/ None,
        format!("{}:0", client.state.thread_id),
        /*parent_thread_id*/ None,
        TestCodexResponsesRequestKind::Turn,
    );
    let first_setup = session
        .current_client_setup(Some(&model.slug), Some(&metadata.session_id))
        .await?;
    let failed_identity = first_setup
        .managed_id
        .as_ref()
        .expect("managed setup identity");
    let first_account = initial_accounts
        .iter()
        .find(|account| &account.identity_key == failed_identity)
        .expect("selected identity belongs to the temporary pool");
    let sibling = initial_accounts
        .iter()
        .find(|account| &account.identity_key != failed_identity)
        .expect("distinct same-workspace sibling");
    let first_bearer = format!(
        "Bearer access-{}",
        first_account
            .normalized_email
            .as_deref()
            .expect("first email")
    );
    let sibling_bearer = format!(
        "Bearer access-{}",
        sibling.normalized_email.as_deref().expect("sibling email")
    );
    let failed_identity = failed_identity.clone();
    let response_sibling_bearer = sibling_bearer.clone();
    let reset = Utc::now() + chrono::Duration::hours(/*hours*/ 1);
    let attempts = AtomicUsize::new(/*v*/ 0);
    Mock::given(method("POST"))
        .and(path("/v1/responses"))
        .respond_with(move |request: &wiremock::Request| {
            let call = attempts.fetch_add(/*val*/ 1, Ordering::SeqCst);
            if call == 0 {
                let response = ResponseTemplate::new(/*status*/ 429)
                    .insert_header("x-codex-rate-limit-reached-type", code)
                    .set_body_json(json!({
                        "error": {
                            "type": "usage_limit_reached",
                            "plan_type": "pro",
                            "resets_at": reset.timestamp()
                        }
                    }));
                return match model_limit_evidence {
                    ModelLimitEvidence::Absent => response,
                    ModelLimitEvidence::ExhaustedNamedModel => response
                        .insert_header("x-codex-active-limit", "codex_bengalfox")
                        .insert_header("x-codex-bengalfox-limit-name", "workspace-cap-model")
                        .insert_header("x-codex-bengalfox-primary-used-percent", "100"),
                };
            }
            let body: serde_json::Value = request.body_json().expect("model request JSON");
            let bearer = request
                .headers
                .get("authorization")
                .and_then(|v| v.to_str().ok());
            let workspace = request
                .headers
                .get("chatgpt-account-id")
                .and_then(|v| v.to_str().ok());
            let response_id = if call == 1
                && bearer == Some(response_sibling_bearer.as_str())
                && workspace == Some("shared-workspace")
                && body["model"] == "workspace-cap-model"
            {
                "healthy-sibling-completed"
            } else {
                // Terminate unexpected recovery without a timeout or another quota failure.
                "unexpected-recovery-sentinel"
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
    let prompt = Prompt {
        input: vec![ResponseItem::Message {
            id: None,
            role: "user".to_string(),
            content: vec![ContentItem::InputText {
                text: "test workspace spend cap scope".to_string(),
            }],
            phase: None,
            internal_chat_message_metadata_passthrough: None,
        }],
        ..Default::default()
    };
    let mut setup = Some(first_setup);
    let mut completion = None;
    let mut terminal_quota = false;
    loop {
        let current_setup = match setup.take() {
            Some(setup) => setup,
            None => {
                session
                    .current_client_setup(Some(&model.slug), Some(&metadata.session_id))
                    .await?
            }
        };
        match session
            .stream_attempt_with_setup(
                &prompt,
                &model,
                &telemetry,
                /*effort*/ None,
                codex_protocol::config_types::ReasoningSummary::None,
                /*service_tier*/ None,
                &metadata,
                &InferenceTraceContext::disabled(),
                current_setup,
            )
            .await
        {
            Ok(mut stream) => {
                while let Some(event) = stream.next().await {
                    if let ResponseEvent::Completed { response_id, .. } = event? {
                        completion = Some(response_id);
                        break;
                    }
                }
                break;
            }
            Err(error) => {
                let CodexErrorDetails::UsageLimitReached(quota) = error.details() else {
                    return Err(error.into());
                };
                let expected_code: RateLimitReachedType = serde_json::from_value(json!(code))?;
                let expected_model_limit = match model_limit_evidence {
                    ModelLimitEvidence::Absent => None,
                    ModelLimitEvidence::ExhaustedNamedModel => Some("workspace-cap-model"),
                };
                assert_eq!(
                    (
                        quota.rate_limit_reached_type,
                        quota
                            .rate_limits
                            .as_ref()
                            .and_then(|limits| limits.limit_name.as_deref()),
                    ),
                    (Some(expected_code), expected_model_limit),
                );
                if !session
                    .recover_last_managed_attempt(&error, /*committed*/ false)
                    .await
                {
                    terminal_quota = true;
                    break;
                }
            }
        }
    }

    let requests = server.received_requests().await.expect("recorded requests");
    let observed_requests: Vec<_> = requests
        .iter()
        .map(|request| {
            let body: serde_json::Value = request.body_json().expect("request JSON");
            (
                request.method.as_str().to_string(),
                request.url.path().to_string(),
                request.headers["authorization"]
                    .to_str()
                    .expect("bearer header")
                    .to_string(),
                request.headers["chatgpt-account-id"]
                    .to_str()
                    .expect("workspace header")
                    .to_string(),
                body["model"].as_str().expect("model name").to_string(),
            )
        })
        .collect();
    let expected_request = |bearer| {
        (
            "POST".to_string(),
            "/v1/responses".to_string(),
            bearer,
            "shared-workspace".to_string(),
            "workspace-cap-model".to_string(),
        )
    };
    let (expected_completion, expected_terminal, expected_requests) = match scope {
        LimitScope::Identity => (
            Some("healthy-sibling-completed".to_string()),
            false,
            vec![
                expected_request(first_bearer),
                expected_request(sibling_bearer),
            ],
        ),
        LimitScope::Workspace => (None, true, vec![expected_request(first_bearer)]),
    };
    let mut expected_accounts: Vec<_> = initial_accounts
        .iter()
        .map(|account| {
            let (eligibility, block) = match scope {
                LimitScope::Identity if account.identity_key == failed_identity => (
                    ManagedChatgptEligibility::Blocked,
                    Some(ManagedChatgptBlockKindView::Quota),
                ),
                LimitScope::Identity => (ManagedChatgptEligibility::Eligible, None),
                LimitScope::Workspace => (
                    ManagedChatgptEligibility::Blocked,
                    Some(ManagedChatgptBlockKindView::Workspace),
                ),
            };
            (account.identity_key.clone(), eligibility, block)
        })
        .collect();
    expected_accounts.sort_by(|a, b| a.0.cmp(&b.0));
    let mut observed_accounts: Vec<_> = manager
        .managed_chatgpt_accounts()?
        .into_iter()
        .map(|account| {
            (
                account.identity_key,
                account.eligibility,
                account.block_kind,
            )
        })
        .collect();
    observed_accounts.sort_by(|a, b| a.0.cmp(&b.0));
    assert_eq!(
        (
            completion,
            terminal_quota,
            observed_requests,
            observed_accounts
        ),
        (
            expected_completion,
            expected_terminal,
            expected_requests,
            expected_accounts
        ),
        "{code} must block only the documented quota scope"
    );
    Ok(())
}
