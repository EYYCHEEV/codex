//! Selected workspace policy must gate the exact managed identity used by a resumed turn.

use super::*;
use codex_app_server_protocol::ClientRequest;
use codex_app_server_protocol::ThreadClosedNotification;
use codex_app_server_protocol::ThreadUnsubscribeParams;
use codex_app_server_protocol::ThreadUnsubscribeResponse;
use codex_app_server_protocol::ThreadUnsubscribeStatus;
use pretty_assertions::assert_eq;
use test_case::test_case;

const PROVIDER_CHANGED: &str = "Your organization's required model provider settings changed. Restart Codex to apply them; this request was not sent";

#[derive(Clone, Copy)]
enum Policy {
    IncompatibleProvider,
    RequiredUnavailable,
    TransientAfterRefresh,
    NonrequiredUnavailable,
}

#[test_case(Policy::IncompatibleProvider; "selected_b_supported_provider_policy_denies")]
#[test_case(Policy::RequiredUnavailable; "selected_b_required_policy_without_lkg_denies")]
#[test_case(Policy::NonrequiredUnavailable; "nonrequired_a_remains_usable_when_cloud_unavailable")]
#[test_case(Policy::TransientAfterRefresh; "selected_b_lkg_survives_identity_preserving_refresh")]
#[tokio::test]
async fn selected_policy_gates_resumed_turn(policy: Policy) -> Result<()> {
    let home = tempfile::tempdir()?;
    let backend = MockServer::start().await;
    let request_limit = if matches!(policy, Policy::TransientAfterRefresh) {
        2
    } else {
        1
    };
    let tls = TlsResponse::start_with_request_limit(
        responses::sse(vec![
            responses::ev_response_created("selected-policy-response"),
            responses::ev_assistant_message("selected-policy-message", "policy allowed this turn"),
            responses::ev_completed("selected-policy-response"),
        ]),
        request_limit,
    )?;
    let certificate_path = home.path().join("routing-ca.pem");
    std::fs::write(&certificate_path, &tls.certificate)?;
    std::fs::write(
        home.path().join("config.toml"),
        format!(
            "model = 'gpt-5.1'\nmodel_provider = 'fixture'\ncli_auth_credentials_store = 'file'\n\
             chatgpt_base_url = '{0}/backend-api'\nthread_unload_delay_secs = 0\n\
             [model_providers.fixture]\nname = 'OpenAI'\nrequires_openai_auth = true\n\
             wire_api = 'responses'\nbase_url = '{0}/backend-api/codex'\nsupports_websockets = false\n\
             request_max_retries = 0\nstream_max_retries = 0\n\
             [model_providers.other]\nname = 'OpenAI'\nrequires_openai_auth = true\n\
             wire_api = 'responses'\nbase_url = '{0}/backend-api/codex'\nsupports_websockets = false\n\
             request_max_retries = 0\nstream_max_retries = 0\n",
            backend.uri()
        ),
    )?;
    // The control has only A so it exercises the same fixed thread scope without
    // relying on a second independently chosen rendezvous-hash winner.
    let accounts: &[(&str, &str)] = match policy {
        Policy::IncompatibleProvider
        | Policy::RequiredUnavailable
        | Policy::TransientAfterRefresh => &[
            ("a-scoped@example.test", "workspace-scoped"),
            ("z-global@example.test", "workspace-global"),
        ],
        Policy::NonrequiredUnavailable => &[("z-global@example.test", "workspace-global")],
    };
    seed_managed_accounts(home.path(), accounts).await?;
    let auth_path = home.path().join("auth.json");
    let mut auth: Value = serde_json::from_slice(&std::fs::read(&auth_path)?)?;
    for row in auth["managed_chatgpt"]["accounts"]
        .as_array_mut()
        .expect("managed accounts")
    {
        let (label, email, workspace, plan) =
            if row["identity_key"] == "email:a-scoped@example.test" {
                (
                    "scoped",
                    "a-scoped@example.test",
                    "workspace-scoped",
                    "enterprise",
                )
            } else {
                ("global", "z-global@example.test", "workspace-global", "pro")
            };
        row["tokens"]["id_token"] = json!(encode_id_token(
            &ChatGptIdTokenClaims::new()
                .email(email)
                .chatgpt_user_id(format!("user-{label}"))
                .chatgpt_account_id(workspace)
                .plan_type(plan),
        )?);
        row["tokens"]["access_token"] = json!(format!("access-{label}"));
        row["tokens"]["refresh_token"] = json!(format!("refresh-{label}"));
    }
    std::fs::write(&auth_path, serde_json::to_vec(&auth)?)?;
    let (selected_email, selected_workspace, selected_user, selected_token) = match policy {
        Policy::IncompatibleProvider
        | Policy::RequiredUnavailable
        | Policy::TransientAfterRefresh => (
            "a-scoped@example.test",
            "workspace-scoped",
            "user-scoped",
            "access-scoped",
        ),
        Policy::NonrequiredUnavailable => (
            "z-global@example.test",
            "workspace-global",
            "user-global",
            "access-global",
        ),
    };
    let selected_plan = match policy {
        Policy::IncompatibleProvider
        | Policy::RequiredUnavailable
        | Policy::TransientAfterRefresh => "enterprise",
        Policy::NonrequiredUnavailable => "pro",
    };
    let manager = AuthManager::shared(
        home.path().to_path_buf(),
        /*enable_codex_api_key_env*/ false,
        AuthCredentialsStoreMode::File,
        /*forced_chatgpt_workspace_id*/ None,
        /*chatgpt_base_url*/ None,
        AuthKeyringBackendKind::Direct,
        transport_default_auth_route_config(),
    )
    .await;
    let selected = manager
        .managed_chatgpt_auth_snapshot(&ManagedChatgptSelectionScope {
            thread_id: Some(THREAD_ID.into()),
            session_id: Some(THREAD_ID.into()),
            model: Some("gpt-5.1".into()),
            ..Default::default()
        })
        .await?
        .expect("selected managed identity");
    let global = manager.auth_cached().expect("global managed identity");
    assert_eq!(
        (
            global.get_account_email().as_deref(),
            global.get_account_id().as_deref(),
            global.get_chatgpt_user_id().as_deref(),
            global
                .get_token_data()?
                .id_token
                .get_chatgpt_plan_type_raw()
                .as_deref(),
            selected.identity_key.as_str(),
            selected.auth.get_account_id().as_deref(),
            selected.auth.get_chatgpt_user_id().as_deref(),
            selected.auth.get_token()?.as_str(),
            selected
                .auth
                .get_token_data()?
                .id_token
                .get_chatgpt_plan_type_raw()
                .as_deref(),
        ),
        (
            Some("z-global@example.test"),
            Some("workspace-global"),
            Some("user-global"),
            Some("pro"),
            format!("email:{selected_email}").as_str(),
            Some(selected_workspace),
            Some(selected_user),
            selected_token,
            Some(selected_plan),
        ),
        "the request scope and complete policy owner identity are fixture preconditions"
    );
    drop(manager);

    let timestamp = "2025-01-05T12-00-00";
    let generated = create_fake_rollout(
        home.path(),
        timestamp,
        "2025-01-05T12:00:00Z",
        "saved user message",
        Some("fixture"),
        /*git_info*/ None,
    )?;
    let generated_path = rollout_path(home.path(), timestamp, &generated);
    let saved = std::fs::read_to_string(&generated_path)?.replace(&generated, THREAD_ID);
    let saved_path = rollout_path(home.path(), timestamp, THREAD_ID);
    std::fs::rename(generated_path, &saved_path)?;
    std::fs::write(saved_path, saved)?;
    write_models_cache(home.path()).await?;

    // Cloud requirements support provider selection and full definitions. Do not
    // use chatgpt_base_url here: cloud authentication fields are intentionally stripped.
    let (required_id, required_name, required_path) = match policy {
        Policy::TransientAfterRefresh => ("fixture", "OpenAI", "/backend-api/codex"),
        Policy::IncompatibleProvider
        | Policy::RequiredUnavailable
        | Policy::NonrequiredUnavailable => {
            ("required", "Required workspace provider", "/required/codex")
        }
    };
    let required_provider = format!(
        "model_provider = '{required_id}'\n\
         [model_providers.{required_id}]\nname = '{required_name}'\n\
         requires_openai_auth = true\nwire_api = 'responses'\n\
         base_url = '{}{required_path}'\nsupports_websockets = false\n\
         request_max_retries = 0\nstream_max_retries = 0\n",
        backend.uri()
    );
    let bundle_response = match policy {
        Policy::IncompatibleProvider | Policy::TransientAfterRefresh => {
            ResponseTemplate::new(/*s*/ 200).set_body_json(json!({
                "requirements_toml": {"enterprise_managed": [{
                    "id": "selected-provider", "name": "Selected workspace provider",
                    "contents": required_provider,
                }]},
            }))
        }
        Policy::RequiredUnavailable | Policy::NonrequiredUnavailable => {
            ResponseTemplate::new(/*s*/ 503)
        }
    };
    let bundle_calls = Arc::new(AtomicUsize::new(/*v*/ 0));
    let received_bundle_calls = Arc::clone(&bundle_calls);
    Mock::given(method("GET"))
        .and(path("/backend-api/wham/config/bundle"))
        .and(header("authorization", format!("Bearer {selected_token}")))
        .and(header("chatgpt-account-id", selected_workspace))
        .respond_with(move |_: &wiremock::Request| {
            received_bundle_calls.fetch_add(1, Ordering::Relaxed);
            bundle_response.clone()
        })
        .mount(&backend)
        .await;
    let refreshed_bundle_calls = Arc::new(AtomicUsize::new(/*v*/ 0));
    let refreshed_fetch_after_initial_policy = Arc::new(AtomicBool::new(/*v*/ false));
    let refresh_failed = Arc::new(tokio::sync::Notify::new());
    if matches!(policy, Policy::TransientAfterRefresh) {
        let initial_calls = Arc::clone(&bundle_calls);
        let refreshed_calls = Arc::clone(&refreshed_bundle_calls);
        let ordered_fetch = Arc::clone(&refreshed_fetch_after_initial_policy);
        let failed = Arc::clone(&refresh_failed);
        Mock::given(method("GET"))
            .and(path("/backend-api/wham/config/bundle"))
            .and(header("authorization", "Bearer access-refreshed-scoped"))
            .and(header("chatgpt-account-id", "workspace-scoped"))
            .respond_with(move |_: &wiremock::Request| {
                ordered_fetch.store(initial_calls.load(Ordering::Relaxed) > 0, Ordering::Relaxed);
                refreshed_calls.fetch_add(1, Ordering::Relaxed);
                failed.notify_one();
                ResponseTemplate::new(/*s*/ 503)
            })
            .mount(&backend)
            .await;
        Mock::given(method("GET"))
            .and(path("/backend-api/wham/accounts/check"))
            .and(header("authorization", "Bearer access-scoped"))
            .and(header("chatgpt-account-id", "workspace-scoped"))
            .respond_with(ResponseTemplate::new(/*s*/ 401))
            .expect(/*r*/ 2)
            .mount(&backend)
            .await;
        let refreshed_id = encode_id_token(
            &ChatGptIdTokenClaims::new()
                .email("a-scoped@example.test")
                .chatgpt_user_id("user-scoped")
                .chatgpt_account_id("workspace-scoped")
                .plan_type("enterprise"),
        )?;
        Mock::given(method("POST"))
            .and(path("/oauth/token"))
            .and(body_partial_json(
                json!({"refresh_token": "refresh-scoped"}),
            ))
            .respond_with(ResponseTemplate::new(/*s*/ 200).set_body_json(json!({
                "id_token": refreshed_id,
                "access_token": "access-refreshed-scoped",
                "refresh_token": "refresh-refreshed-scoped",
            })))
            .expect(/*r*/ 1)
            .mount(&backend)
            .await;
    }
    let scoped_discovery_token = if matches!(policy, Policy::TransientAfterRefresh) {
        "access-refreshed-scoped"
    } else {
        "access-scoped"
    };
    // Global account/read must remain A, independently of B's required-policy state.
    for (token, workspace, routing) in [
        ("access-global", "workspace-global", "us"),
        (scoped_discovery_token, "workspace-scoped", "us_cr"),
    ] {
        Mock::given(method("GET"))
            .and(path("/backend-api/wham/accounts/check"))
            .and(header("authorization", format!("Bearer {token}")))
            .and(header("chatgpt-account-id", workspace))
            .respond_with(
                ResponseTemplate::new(/*s*/ 200).set_body_json(json!({"accounts": [{
                    "id": workspace, "workspace_backend_origin": tls.origin,
                    "account_routing_override": routing,
                }]})),
            )
            .mount(&backend)
            .await;
    }
    let certificate_path = certificate_path.to_string_lossy();
    let refresh_url = format!("{}/oauth/token", backend.uri());
    let mut env = vec![
        ("OPENAI_API_KEY", None),
        ("CODEX_API_KEY", None),
        ("CODEX_CA_CERTIFICATE", Some(certificate_path.as_ref())),
        (
            REFRESH_TOKEN_URL_OVERRIDE_ENV_VAR,
            Some(refresh_url.as_str()),
        ),
    ];
    env.extend(
        codex_network_proxy::PROXY_ENV_KEYS
            .iter()
            .map(|key| (*key, None)),
    );
    let mut app = TestAppServer::builder()
        .with_codex_home(home.path())
        .with_env_overrides(&env)
        .build_initialized_with_timeout(WAIT)
        .await?;
    let read_id = app
        .send_get_account_request(GetAccountParams {
            refresh_token: false,
        })
        .await?;
    let before: Value = timeout(WAIT, app.read_response(read_id)).await??;
    assert_eq!(before["account"]["email"], json!("z-global@example.test"));
    assert_eq!(
        before["workspaceRouting"],
        json!({
            "chatgptAccountId": "workspace-global", "backendOrigin": tls.origin,
            "accountRoutingOverride": "us",
        })
    );
    let resume_id = app
        .send_thread_resume_request(ThreadResumeParams {
            thread_id: THREAD_ID.into(),
            model: Some("gpt-5.1".into()),
            cwd: Some(home.path().to_string_lossy().into_owned()),
            ..Default::default()
        })
        .await?;
    let resumed: ThreadResumeResponse = timeout(WAIT, app.read_response(resume_id)).await??;
    assert_eq!(
        (
            resumed.thread.id.as_str(),
            resumed.thread.session_id.as_str()
        ),
        (THREAD_ID, THREAD_ID)
    );
    let turn_id = app
        .send_turn_start_request(TurnStartParams {
            thread_id: resumed.thread.id,
            input: vec![UserInput::Text {
                text: "continue".into(),
                text_elements: Vec::new(),
            }],
            ..Default::default()
        })
        .await?;
    // Pin the atomic selected-request setup boundary, not any unrelated RPC failure.
    let _: TurnStartResponse = timeout(WAIT, app.read_response(turn_id)).await??;
    let completed: TurnCompletedNotification =
        timeout(WAIT, app.read_notification("turn/completed")).await??;
    match policy {
        Policy::IncompatibleProvider | Policy::RequiredUnavailable => {
            assert_eq!(completed.turn.status, TurnStatus::Failed);
            let expected = match policy {
                Policy::IncompatibleProvider => PROVIDER_CHANGED,
                Policy::RequiredUnavailable => "failed to load workspace requirements",
                Policy::NonrequiredUnavailable | Policy::TransientAfterRefresh => unreachable!(),
            };
            let error = completed
                .turn
                .error
                .expect("selected policy must reject the turn");
            assert!(
                error.message.contains(expected),
                "wrong denial: {}",
                error.message
            );
            assert_eq!(
                tls.requests.load(Ordering::Relaxed),
                0,
                "policy denial must precede model traffic"
            );
            assert!(
                bundle_calls.load(Ordering::Relaxed) > 0,
                "B's policy must actually be fetched"
            );
            if matches!(policy, Policy::RequiredUnavailable) {
                let guidance = error.message.to_ascii_lowercase();
                assert!(
                    guidance.contains("automatically")
                        && ["retry", "try again", "wait"]
                            .iter()
                            .any(|&action| guidance.contains(action)),
                    "a cold-start policy outage must explain automatic, time-based recovery: {}",
                    error.message,
                );
                assert!(
                    !["sign in", "log in", "log out"]
                        .iter()
                        .any(|&action| guidance.contains(action)),
                    "a temporary policy outage must not demand replacement credentials: {}",
                    error.message,
                );
            }
        }
        Policy::NonrequiredUnavailable | Policy::TransientAfterRefresh => {
            assert_eq!(
                (completed.turn.status, completed.turn.error),
                (TurnStatus::Completed, None)
            );
            assert_eq!(tls.requests.load(Ordering::Relaxed), 1);
            let request = tls
                .request_headers
                .lock()
                .expect("TLS request headers")
                .first()
                .expect("completed model request")
                .clone();
            let mut lines = request.lines();
            assert_eq!(
                lines.next(),
                Some("POST /backend-api/codex/responses HTTP/1.1")
            );
            let headers: HashMap<_, _> = lines
                .filter_map(|line| line.split_once(':'))
                .map(|(key, value)| (key.to_ascii_lowercase(), value.trim().to_string()))
                .collect();
            let (expected_bearer, expected_workspace, expected_route) = match policy {
                Policy::TransientAfterRefresh => (
                    "Bearer access-refreshed-scoped",
                    "workspace-scoped",
                    "us_cr",
                ),
                Policy::NonrequiredUnavailable => {
                    ("Bearer access-global", "workspace-global", "us")
                }
                Policy::IncompatibleProvider | Policy::RequiredUnavailable => unreachable!(),
            };
            assert_eq!(
                (
                    headers.get("authorization").map(String::as_str),
                    headers.get("chatgpt-account-id").map(String::as_str),
                    headers
                        .get("x-openai-account-routing-override")
                        .map(String::as_str),
                ),
                (
                    Some(expected_bearer),
                    Some(expected_workspace),
                    Some(expected_route)
                )
            );
            if matches!(policy, Policy::TransientAfterRefresh) {
                assert!(
                    bundle_calls.load(Ordering::Relaxed) > 0,
                    "B's initial policy was fetched"
                );
                // The selected cache may serve LKG immediately while refreshing
                // in the background. Wait for a real failed refreshed-token fetch,
                // not an elapsed delay or a successful use of an untouched cache.
                timeout(WAIT, refresh_failed.notified()).await?;
                assert!(
                    refreshed_bundle_calls.load(Ordering::Relaxed) > 0,
                    "B's refreshed-token fetch returned 503"
                );
                assert!(
                    refreshed_fetch_after_initial_policy.load(Ordering::Relaxed),
                    "503 must follow the initial B policy"
                );

                // Cold-resume the same fixed scope with a different retained
                // provider selection but identical transport settings. This keeps
                // discovery/model availability out of the restrictive-policy proof.
                // The cached requirement still mandates the "fixture" selection.
                let unsubscribe: ThreadUnsubscribeResponse = timeout(
                    WAIT,
                    app.request(|request_id| ClientRequest::ThreadUnsubscribe {
                        request_id,
                        params: ThreadUnsubscribeParams {
                            thread_id: THREAD_ID.into(),
                        },
                    }),
                )
                .await??;
                assert_eq!(unsubscribe.status, ThreadUnsubscribeStatus::Unsubscribed);
                let closed: ThreadClosedNotification =
                    timeout(WAIT, app.read_notification("thread/closed")).await??;
                assert_eq!(
                    closed,
                    ThreadClosedNotification {
                        thread_id: THREAD_ID.into()
                    }
                );
                let resume_id = app
                    .send_thread_resume_request(ThreadResumeParams {
                        thread_id: THREAD_ID.into(),
                        model: Some("gpt-5.1".into()),
                        model_provider: Some("other".into()),
                        cwd: Some(home.path().to_string_lossy().into_owned()),
                        ..Default::default()
                    })
                    .await?;
                let resumed: ThreadResumeResponse =
                    timeout(WAIT, app.read_response(resume_id)).await??;
                assert_eq!(
                    (
                        resumed.thread.id.as_str(),
                        resumed.thread.session_id.as_str(),
                        resumed.model_provider.as_str()
                    ),
                    (THREAD_ID, THREAD_ID, "other"),
                    "the second retained session must differ from B's cached required provider"
                );
                assert!(
                    !tls.worker.as_ref().expect("TLS worker").is_finished(),
                    "model listener must remain healthy"
                );
                let turn_id = app
                    .send_turn_start_request(TurnStartParams {
                        thread_id: resumed.thread.id,
                        input: vec![UserInput::Text {
                            text: "continue with changed provider".into(),
                            text_elements: Vec::new(),
                        }],
                        ..Default::default()
                    })
                    .await?;
                let _: TurnStartResponse = timeout(WAIT, app.read_response(turn_id)).await??;
                let completed: TurnCompletedNotification =
                    timeout(WAIT, app.read_notification("turn/completed")).await??;
                assert_eq!(completed.turn.status, TurnStatus::Failed);
                let error = completed
                    .turn
                    .error
                    .expect("restrictive LKG must reject the changed provider");
                assert!(
                    error.message.contains(PROVIDER_CHANGED),
                    "wrong LKG denial: {}",
                    error.message
                );
                assert_eq!(
                    tls.requests.load(Ordering::Relaxed),
                    1,
                    "restrictive LKG must prevent a second model request"
                );
                assert!(
                    !tls.worker.as_ref().expect("TLS worker").is_finished(),
                    "a stopped model listener must not fake policy denial"
                );
            } else {
                assert_eq!(
                    bundle_calls.load(Ordering::Relaxed),
                    0,
                    "pro A does not require a cloud policy fetch"
                );
            }
        }
    }
    let read_id = app
        .send_get_account_request(GetAccountParams {
            refresh_token: false,
        })
        .await?;
    let after: Value = timeout(WAIT, app.read_response(read_id)).await??;
    assert_eq!(
        after, before,
        "selected policy must not alter global account/read"
    );
    backend.verify().await;
    Ok(())
}
