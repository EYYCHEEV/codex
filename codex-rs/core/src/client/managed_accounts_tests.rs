use super::super::*;
use base64::Engine;
use codex_login::AuthCredentialsStoreMode;
use codex_login::AuthKeyringBackendKind;
use codex_login::ManagedChatgptOauthCredentials;
use codex_login::TokenData;
use codex_login::token_data::IdTokenInfo;
use codex_protocol::protocol::RateLimitWindow;
use tempfile::tempdir;

fn managed_id_token(email: &str, account_id: &str) -> String {
    let header = serde_json::json!({"alg": "none", "typ": "JWT"});
    let payload = serde_json::json!({
        "email": email,
        "email_verified": true,
        "https://api.openai.com/auth": {
            "chatgpt_user_id": format!("user-{account_id}"),
            "user_id": format!("user-{account_id}"),
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

fn credentials(email: &str, account_id: &str) -> ManagedChatgptOauthCredentials {
    ManagedChatgptOauthCredentials {
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
        last_refresh: chrono::Utc::now(),
        oauth_api_key: None,
    }
}

#[tokio::test]
async fn rate_limit_recorder_distinguishes_absent_and_empty_snapshots() {
    let codex_home = tempdir().expect("tempdir");
    let auth_manager = AuthManager::shared(
        codex_home.path().to_path_buf(),
        /*enable_codex_api_key_env*/ false,
        AuthCredentialsStoreMode::File,
        /*forced_chatgpt_workspace_id*/ None,
        /*chatgpt_base_url*/ None,
        AuthKeyringBackendKind::default(),
        /*auth_route_config*/ None,
    )
    .await;
    let first_id = auth_manager
        .upsert_managed_chatgpt_oauth(credentials("a@example.com", "workspace-a"))
        .await
        .expect("insert first account");
    let second_id = auth_manager
        .upsert_managed_chatgpt_oauth(credentials("b@example.com", "workspace-b"))
        .await
        .expect("insert second account");
    let provider = create_model_provider(
        ModelProviderInfo::create_openai_provider(/*base_url*/ None),
        Some(Arc::clone(&auth_manager)),
    );
    let setup = provider
        .request_setup(ProviderAuthScope {
            agent_identity_policy: AgentIdentityAuthPolicy::JwtOnly,
            session_source: SessionSource::Cli,
            agent_identity_session_fallback: AgentIdentitySessionFallback::default(),
            thread_id: Some("thread-rate-observation".to_string()),
            session_id: Some("session-rate-observation".to_string()),
            model: Some("gpt-test".to_string()),
        })
        .await
        .expect("selected setup");
    let selected_id = setup.managed_id.clone().expect("managed selection");
    assert!(selected_id == first_id || selected_id == second_id);

    let snapshot = RateLimitSnapshot {
        limit_id: Some("codex".to_string()),
        limit_name: Some("Codex".to_string()),
        primary: Some(RateLimitWindow {
            used_percent: 25.0,
            window_minutes: Some(60),
            resets_at: Some(1_800_000_000),
        }),
        secondary: None,
        credits: None,
        individual_limit: None,
        plan_type: None,
        rate_limit_reached_type: None,
    };
    let mut recorder =
        ManagedRateLimitRecorder::for_setup(Some(&auth_manager), &setup).expect("recorder");
    recorder.flush();
    assert!(
        auth_manager
            .managed_chatgpt_accounts()
            .expect("managed accounts")
            .iter()
            .all(|account| account.usage.is_none())
    );
    recorder.observe(&snapshot);
    recorder.observe(&RateLimitSnapshot {
        primary: Some(RateLimitWindow {
            used_percent: 15.0,
            window_minutes: Some(60),
            resets_at: Some(1_800_000_010),
        }),
        secondary: Some(RateLimitWindow {
            used_percent: 45.0,
            window_minutes: Some(300),
            resets_at: Some(1_800_000_020),
        }),
        ..snapshot.clone()
    });
    recorder.observe(&RateLimitSnapshot {
        limit_id: Some("codex_other".to_string()),
        limit_name: Some("Other".to_string()),
        primary: Some(RateLimitWindow {
            used_percent: 40.0,
            window_minutes: Some(120),
            resets_at: Some(1_800_000_100),
        }),
        secondary: None,
        credits: None,
        individual_limit: None,
        plan_type: None,
        rate_limit_reached_type: None,
    });
    recorder.observe(&RateLimitSnapshot {
        limit_id: Some("codex_other".to_string()),
        limit_name: Some("Other".to_string()),
        primary: Some(RateLimitWindow {
            used_percent: 30.0,
            window_minutes: Some(120),
            resets_at: Some(1_800_000_200),
        }),
        secondary: None,
        credits: None,
        individual_limit: None,
        plan_type: None,
        rate_limit_reached_type: None,
    });
    recorder.flush();

    let accounts = auth_manager
        .managed_chatgpt_accounts()
        .expect("managed accounts");
    let selected = accounts
        .iter()
        .find(|account| account.identity_key == selected_id)
        .expect("selected account");
    let usage = selected.usage.as_ref().expect("recorded selected usage");
    assert_eq!(usage.rate_windows.len(), 3);
    assert_eq!(usage.rate_windows[0].remaining_percent, Some(85.0));
    assert_eq!(usage.rate_windows[1].limit_id, "codex");
    assert_eq!(
        usage.rate_windows[1].kind,
        ManagedChatgptLimitKind::Secondary
    );
    assert_eq!(usage.rate_windows[1].remaining_percent, Some(55.0));
    assert_eq!(usage.rate_windows[2].limit_id, "codex_other:primary");
    assert_eq!(usage.rate_windows[2].remaining_percent, Some(70.0));
    assert!(
        accounts
            .iter()
            .filter(|account| account.identity_key != selected_id)
            .all(|account| account.usage.is_none())
    );
    let empty = RateLimitSnapshot {
        limit_id: None,
        limit_name: None,
        primary: None,
        secondary: None,
        credits: None,
        individual_limit: None,
        plan_type: None,
        rate_limit_reached_type: None,
    };
    recorder.observe(&empty);
    recorder.flush();
    let accounts = auth_manager
        .managed_chatgpt_accounts()
        .expect("managed accounts after empty snapshot");
    let selected = accounts
        .iter()
        .find(|account| account.identity_key == selected_id)
        .expect("selected account after empty snapshot");
    assert_eq!(
        selected
            .usage
            .as_ref()
            .expect("retained selected usage")
            .rate_windows
            .len(),
        3
    );
    assert_eq!(
        selected.usage_unavailable_reason.as_deref(),
        Some("rate limit usage was absent from the response")
    );
    drop(recorder);
    let setup = provider
        .request_setup(ProviderAuthScope {
            agent_identity_policy: AgentIdentityAuthPolicy::JwtOnly,
            session_source: SessionSource::Cli,
            agent_identity_session_fallback: AgentIdentitySessionFallback::default(),
            thread_id: Some("thread-rate-observation".to_string()),
            session_id: Some("session-rate-observation".to_string()),
            model: Some("gpt-test".to_string()),
        })
        .await
        .expect("selected setup after unavailable observation");
    assert_eq!(setup.managed_id.as_deref(), Some(selected_id.as_str()));
    let mut recorder =
        ManagedRateLimitRecorder::for_setup(Some(&auth_manager), &setup).expect("recorder");
    recorder.observe(&RateLimitSnapshot {
        limit_id: Some("codex_other".to_string()),
        limit_name: Some("Other".to_string()),
        primary: Some(RateLimitWindow {
            used_percent: 5.0,
            window_minutes: Some(120),
            resets_at: Some(1_800_000_300),
        }),
        secondary: None,
        credits: None,
        individual_limit: None,
        plan_type: None,
        rate_limit_reached_type: None,
    });
    recorder.flush();
    let selected = auth_manager
        .managed_chatgpt_accounts()
        .expect("managed accounts after sparse observation")
        .into_iter()
        .find(|account| account.identity_key == selected_id)
        .expect("selected account after sparse observation");
    let windows = &selected
        .usage
        .as_ref()
        .expect("usage after sparse observation")
        .rate_windows;
    assert_eq!(windows.len(), 3);
    assert_eq!(windows[0].remaining_percent, Some(85.0));
    assert_eq!(windows[1].remaining_percent, Some(55.0));
    assert_eq!(windows[2].remaining_percent, Some(95.0));
    assert!(selected.usage_unavailable_reason.is_none());
    let unavailable_observed_at = selected.usage_unavailable_observed_at;
    recorder.flush();
    let selected = auth_manager
        .managed_chatgpt_accounts()
        .expect("managed accounts after unobserved flush")
        .into_iter()
        .find(|account| account.identity_key == selected_id)
        .expect("selected account after unobserved flush");
    assert_eq!(
        selected.usage_unavailable_observed_at,
        unavailable_observed_at
    );
}
#[tokio::test]
async fn rate_limit_recorder_publishes_exact_revision_and_ignores_stale_discard() {
    let codex_home = tempdir().expect("tempdir");
    let auth_manager = AuthManager::shared(
        codex_home.path().to_path_buf(),
        /*enable_codex_api_key_env*/ false,
        AuthCredentialsStoreMode::File,
        /*forced_chatgpt_workspace_id*/ None,
        /*chatgpt_base_url*/ None,
        AuthKeyringBackendKind::default(),
        /*auth_route_config*/ None,
    )
    .await;
    auth_manager
        .upsert_managed_chatgpt_oauth(credentials("a@example.com", "workspace-a"))
        .await
        .expect("insert account");
    let provider = create_model_provider(
        ModelProviderInfo::create_openai_provider(/*base_url*/ None),
        Some(Arc::clone(&auth_manager)),
    );
    let scope = || ProviderAuthScope {
        agent_identity_policy: AgentIdentityAuthPolicy::JwtOnly,
        session_source: SessionSource::Cli,
        agent_identity_session_fallback: AgentIdentitySessionFallback::default(),
        thread_id: Some("thread-revision-observation".to_string()),
        session_id: Some("session-revision-observation".to_string()),
        model: Some("gpt-test".to_string()),
    };
    let setup = provider
        .request_setup(scope())
        .await
        .expect("selected setup");
    let initial_revision = setup
        .account_state_revision
        .expect("account state revision");
    let shared_revision = Arc::new(AtomicU64::new(initial_revision));
    let binding = ManagedRateLimitBinding {
        managed_account_id: setup.managed_id.clone().expect("managed id"),
        account_state_revision: initial_revision,
        transport_binding: setup.transport_auth_binding.clone(),
        shared_account_state_revision: Some(Arc::clone(&shared_revision)),
    };
    let mut recorder = ManagedRateLimitRecorder::for_setup_with_revision(
        Some(&auth_manager),
        &setup,
        Some(Arc::clone(&shared_revision)),
    )
    .expect("recorder");
    recorder.observe(&RateLimitSnapshot {
        limit_id: Some("codex".to_string()),
        limit_name: None,
        primary: Some(RateLimitWindow {
            used_percent: 20.0,
            window_minutes: Some(60),
            resets_at: Some(1_800_000_000),
        }),
        secondary: None,
        credits: None,
        individual_limit: None,
        plan_type: None,
        rate_limit_reached_type: None,
    });
    recorder.flush();
    let persisted_revision = auth_manager
        .managed_chatgpt_accounts()
        .expect("managed accounts")
        .into_iter()
        .find(|account| account.identity_key == binding.managed_account_id)
        .expect("selected account")
        .revision;
    assert!(persisted_revision > initial_revision);
    assert_eq!(shared_revision.load(Ordering::Acquire), persisted_revision);
    assert_eq!(
        binding.refreshed().account_state_revision,
        persisted_revision
    );

    let stale_setup = provider
        .request_setup(scope())
        .await
        .expect("selected setup for stale observation");
    let stale_revision = stale_setup
        .account_state_revision
        .expect("stale setup revision");
    let stale_shared_revision = Arc::new(AtomicU64::new(stale_revision));
    let mut stale_recorder = ManagedRateLimitRecorder::for_setup_with_revision(
        Some(&auth_manager),
        &stale_setup,
        Some(Arc::clone(&stale_shared_revision)),
    )
    .expect("stale recorder");
    let concurrent = auth_manager
        .record_managed_chatgpt_status_observation(
            stale_setup.managed_id.as_deref().expect("managed id"),
            stale_setup
                .credential_revision
                .expect("credential revision"),
            stale_revision,
            ManagedChatgptStatusObservation {
                observed_at: chrono::Utc::now(),
                rate: ManagedChatgptRateObservation::Unavailable {
                    reason: "concurrent observation".to_string(),
                },
                token: ManagedChatgptTokenObservation::NotObserved,
            },
        )
        .expect("record concurrent observation")
        .expect("current observation");
    assert!(concurrent.revision > stale_revision);
    stale_recorder.observe(&RateLimitSnapshot {
        limit_id: Some("codex".to_string()),
        limit_name: None,
        primary: Some(RateLimitWindow {
            used_percent: 10.0,
            window_minutes: Some(60),
            resets_at: Some(1_800_000_100),
        }),
        secondary: None,
        credits: None,
        individual_limit: None,
        plan_type: None,
        rate_limit_reached_type: None,
    });
    stale_recorder.flush();
    assert_eq!(
        stale_shared_revision.load(Ordering::Acquire),
        stale_revision
    );
    assert_eq!(
        auth_manager
            .managed_chatgpt_accounts()
            .expect("managed accounts after stale discard")
            .into_iter()
            .find(|account| account.identity_key == binding.managed_account_id)
            .expect("selected account after stale discard")
            .revision,
        concurrent.revision
    );
}
