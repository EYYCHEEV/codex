use super::*;
use codex_login::ManagedChatgptFailure;
use codex_login::ManagedChatgptSelectionScope;
use codex_login::REVOKE_TOKEN_URL_OVERRIDE_ENV_VAR;
use pretty_assertions::assert_eq;
use test_case::test_case;

#[derive(Clone, Copy)]
enum SavedAuth {
    QuotaBlocked,
    SignedOut,
}

#[test_case("account/rateLimits/read", SavedAuth::QuotaBlocked; "rate_limits_all_accounts_blocked")]
#[test_case("account/usage/read", SavedAuth::QuotaBlocked; "token_usage_all_accounts_blocked")]
#[test_case("account/rateLimits/read", SavedAuth::SignedOut; "rate_limits_signed_out")]
#[test_case("account/usage/read", SavedAuth::SignedOut; "token_usage_signed_out")]
#[tokio::test]
async fn singular_usage_distinguishes_unavailable_pool_from_signed_out(
    rpc_method: &str,
    saved_auth: SavedAuth,
) -> Result<()> {
    let home = TempDir::new()?;
    let backend = MockServer::start().await;
    create_config_toml(
        home.path(),
        CreateConfigTomlParams {
            requires_openai_auth: Some(true),
            base_url: Some(format!("{}/v1", backend.uri())),
            chatgpt_base_url: Some(format!("{}/backend-api", backend.uri())),
            ..Default::default()
        },
    )?;
    let config_path = home.path().join("config.toml");
    let contents = std::fs::read_to_string(&config_path)?;
    std::fs::write(
        config_path,
        format!("cli_auth_credentials_store = \"file\"\n{contents}"),
    )?;
    write_models_cache(home.path()).await?;
    app_test_support::mount_workspace_routing(&backend).await;
    Mock::given(method("GET"))
        .and(path("/backend-api/wham/config/bundle"))
        .respond_with(ResponseTemplate::new(/*status*/ 200).set_body_json(json!({})))
        .mount(&backend)
        .await;
    let refresh_url = format!("{}/oauth/refresh", backend.uri());
    let revoke_url = format!("{}/oauth/revoke", backend.uri());
    Mock::given(method("POST"))
        .and(path("/oauth/refresh"))
        .respond_with(ResponseTemplate::new(/*status*/ 500))
        .expect(0)
        .mount(&backend)
        .await;

    if let SavedAuth::QuotaBlocked = saved_auth {
        seed_managed_accounts(
            home.path(),
            &[
                ("quota-a@example.com", WORKSPACE_ID_INITIAL),
                ("quota-b@example.com", WORKSPACE_ID_DEVICE),
            ],
        )
        .await?;
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
        let scope = ManagedChatgptSelectionScope::default();
        // A long reset horizon keeps the persisted cooldown active throughout
        // server startup and both public inventory/error observations.
        let reset_at = Utc::now() + ChronoDuration::hours(/*hours*/ 1);
        for identity in ["email:quota-a@example.com", "email:quota-b@example.com"] {
            let snapshot = manager
                .managed_chatgpt_auth_snapshot_for_identity(identity)
                .await?
                .expect("seeded managed account");
            manager
                .recover_failed_attempt(
                    &snapshot,
                    ManagedChatgptFailure::Quota {
                        reset_at: Some(reset_at),
                    },
                    /*committed*/ false,
                    &scope,
                )
                .await?;
        }
    }

    let mut server = TestAppServer::builder()
        .with_codex_home(home.path())
        .without_auto_env()
        .with_env_overrides(&[
            ("OPENAI_API_KEY", None),
            ("CODEX_API_KEY", None),
            ("CODEX_ACCESS_TOKEN", None),
            ("NO_PROXY", Some("127.0.0.1,localhost")),
            ("no_proxy", Some("127.0.0.1,localhost")),
            (
                REFRESH_TOKEN_URL_OVERRIDE_ENV_VAR,
                Some(refresh_url.as_str()),
            ),
            (REVOKE_TOKEN_URL_OVERRIDE_ENV_VAR, Some(revoke_url.as_str())),
        ])
        .build_initialized_with_timeout(DEFAULT_READ_TIMEOUT)
        .await?;
    let request = server
        .send_list_accounts_request(json!({
            "refreshTokens": false,
            "refreshUsage": false,
        }))
        .await?;
    let inventory: ListAccountsResponse =
        timeout(DEFAULT_READ_TIMEOUT, server.read_response(request)).await??;
    assert_eq!(inventory.selected_account_id, None);
    match saved_auth {
        SavedAuth::QuotaBlocked => {
            assert_eq!(
                inventory
                    .accounts
                    .iter()
                    .map(|account| account.managed_account_id.as_str())
                    .collect::<Vec<_>>(),
                vec!["email:quota-a@example.com", "email:quota-b@example.com"]
            );
            assert_eq!(
                inventory
                    .accounts
                    .iter()
                    .map(|account| (
                        account.eligible,
                        account.block.as_ref().map(|block| block.reason.as_str()),
                    ))
                    .collect::<Vec<_>>(),
                vec![(false, Some("quota")), (false, Some("quota"))]
            );
        }
        SavedAuth::SignedOut => assert!(inventory.accounts.is_empty()),
    }

    let request = server.send_request(rpc_method, /*params*/ None).await?;
    let error = timeout(
        DEFAULT_READ_TIMEOUT,
        server.read_stream_until_error_message(RequestId::Integer(request)),
    )
    .await??;
    assert_eq!(error.error.code, -32_600);
    let message = error.error.message.to_ascii_lowercase();
    match saved_auth {
        SavedAuth::QuotaBlocked => {
            assert!(
                message.contains("saved")
                    && message.contains("unavailable")
                    && message.contains("account/list"),
                "{rpc_method} must explain that saved accounts are unavailable and direct the caller to account/list: {message}"
            );
            assert!(!message.contains("authentication required"));
        }
        SavedAuth::SignedOut => {
            assert!(
                message.contains("authentication required"),
                "{rpc_method} must still request authentication when no accounts are saved: {message}"
            );
        }
    }
    backend.verify().await;
    Ok(())
}
