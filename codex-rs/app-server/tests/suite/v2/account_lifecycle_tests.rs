use super::*;
use codex_app_server_protocol::AccountPoolUpdatedNotification;
use codex_app_server_protocol::ConfigRequirementsReadResponse;
use codex_login::REVOKE_TOKEN_URL_OVERRIDE_ENV_VAR;
use pretty_assertions::assert_eq;
use test_case::test_case;

async fn lifecycle_fixture(mut config: CreateConfigTomlParams) -> Result<(TempDir, MockServer)> {
    let home = TempDir::new()?;
    let backend = MockServer::start().await;
    config.requires_openai_auth = Some(true);
    config.base_url = Some(format!("{}/v1", backend.uri()));
    config.chatgpt_base_url = Some(format!("{}/backend-api", backend.uri()));
    create_config_toml(home.path(), config)?;
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
        .with_priority(/*priority*/ 10)
        .mount(&backend)
        .await;
    Mock::given(method("POST"))
        .and(path("/oauth/revoke"))
        .respond_with(ResponseTemplate::new(/*status*/ 200))
        .mount(&backend)
        .await;
    Ok((home, backend))
}

async fn start_lifecycle_server(home: &Path, backend: &MockServer) -> Result<TestAppServer> {
    let issuer = backend.uri();
    let refresh_url = format!("{issuer}/oauth/refresh");
    let revoke_url = format!("{issuer}/oauth/revoke");
    TestAppServer::builder()
        .with_codex_home(home)
        // These account-only tests do not start an execution environment. Keeping
        // the home reusable also exercises an actual restart in the logout test.
        .without_auto_env()
        .with_env_overrides(&[
            ("OPENAI_API_KEY", None),
            ("CODEX_API_KEY", None),
            ("CODEX_ACCESS_TOKEN", None),
            ("NO_PROXY", Some("127.0.0.1,localhost")),
            ("no_proxy", Some("127.0.0.1,localhost")),
            (LOGIN_ISSUER_ENV_VAR, Some(issuer.as_str())),
            (
                REFRESH_TOKEN_URL_OVERRIDE_ENV_VAR,
                Some(refresh_url.as_str()),
            ),
            (REVOKE_TOKEN_URL_OVERRIDE_ENV_VAR, Some(revoke_url.as_str())),
        ])
        .build_initialized_with_timeout(DEFAULT_READ_TIMEOUT)
        .await
}

#[tokio::test]
async fn second_device_login_publishes_new_managed_inventory() -> Result<()> {
    let (home, backend) = lifecycle_fixture(CreateConfigTomlParams::default()).await?;
    seed_managed_accounts(
        home.path(),
        &[("account-a@example.com", WORKSPACE_ID_INITIAL)],
    )
    .await?;
    mock_device_code_usercode(&backend, /*interval_seconds*/ 0).await;
    mock_device_code_token_success(&backend).await;
    let id_token = encode_id_token(
        &ChatGptIdTokenClaims::new()
            .email("account-b@example.com")
            .plan_type("pro")
            .chatgpt_user_id("account-b-user")
            .chatgpt_account_id(WORKSPACE_ID_DEVICE),
    )?;
    mock_oauth_token(&backend, &id_token).await;
    let mut server = start_lifecycle_server(home.path(), &backend).await?;
    let request = server
        .send_list_accounts_request(json!({
            "refreshTokens": false,
            "refreshUsage": false,
        }))
        .await?;
    let before: ListAccountsResponse =
        timeout(DEFAULT_READ_TIMEOUT, server.read_response(request)).await??;
    assert_eq!(
        before
            .accounts
            .iter()
            .map(|row| row.managed_account_id.as_str())
            .collect::<Vec<_>>(),
        vec!["email:account-a@example.com"]
    );
    assert_eq!(
        before.selected_account_id.as_deref(),
        Some("email:account-a@example.com")
    );

    let request = server
        .send_login_account_chatgpt_device_code_request()
        .await?;
    let login: LoginAccountResponse =
        timeout(DEFAULT_READ_TIMEOUT, server.read_response(request)).await??;
    let LoginAccountResponse::ChatgptDeviceCode { login_id, .. } = login else {
        bail!("unexpected login response: {login:?}");
    };
    let completed: AccountLoginCompletedNotification = timeout(
        DEFAULT_READ_TIMEOUT,
        server.read_notification("account/login/completed"),
    )
    .await??;
    assert_eq!(
        completed,
        AccountLoginCompletedNotification {
            login_id: Some(login_id),
            success: true,
            error: None,
            onboarding_entrypoint: None,
            managed_account_id: Some("email:account-b@example.com".to_string()),
        }
    );

    // Completion must wake the running server's inventory observer even if its
    // effective auth owner does not change. Do not use account/list to trigger it.
    let pool = timeout(DEFAULT_READ_TIMEOUT, async {
        loop {
            let pool: AccountPoolUpdatedNotification =
                server.read_notification("account/pool/updated").await?;
            if pool.pool_revision > before.pool_revision {
                return Ok::<_, anyhow::Error>(pool);
            }
        }
    })
    .await??;
    assert_eq!(
        pool.accounts
            .iter()
            .map(|row| row.managed_account_id.as_str())
            .collect::<Vec<_>>(),
        vec!["email:account-a@example.com", "email:account-b@example.com"]
    );
    assert!(pool.pool_revision > before.pool_revision);
    let request = server
        .send_list_accounts_request(json!({
            "refreshTokens": false,
            "refreshUsage": false,
        }))
        .await?;
    let after: ListAccountsResponse =
        timeout(DEFAULT_READ_TIMEOUT, server.read_response(request)).await??;
    assert_eq!(after.accounts, pool.accounts);
    assert_eq!(after.pool_revision, pool.pool_revision);
    // Adding an account is not a request to select it. Selection is checked
    // against the public unscoped list, rather than assuming the new row wins.
    let account = read_account(&mut server).await?;
    let selected = after
        .accounts
        .iter()
        .find(|row| Some(&row.managed_account_id) == after.selected_account_id.as_ref())
        .expect("the durable inventory has an effective default");
    let Account::Chatgpt { email, .. } = account.account.expect("managed ChatGPT account") else {
        bail!("expected managed ChatGPT authentication");
    };
    assert_eq!(email.as_deref(), selected.email.as_deref());
    Ok(())
}

#[test_case("account-b@example.com", &["email:account-b@example.com"]; "targeted_logout")]
#[test_case("missing@example.com", &[]; "unknown_selector_noop")]
#[tokio::test]
async fn partial_logout_preserves_surviving_cloud_requirements(
    selector: &str,
    removed: &[&str],
) -> Result<()> {
    let (home, backend) = lifecycle_fixture(CreateConfigTomlParams {
        // Keep A the effective owner independently of weighted account selection.
        // B remains stored and can still be explicitly removed by account/logout.
        forced_workspace_id: Some(WORKSPACE_ID_INITIAL.to_string()),
        ..Default::default()
    })
    .await?;
    write_chatgpt_auth(
        home.path(),
        ChatGptAuthFixture::new("enterprise-a-access")
            .account_id(WORKSPACE_ID_INITIAL)
            .chatgpt_account_id(WORKSPACE_ID_INITIAL)
            .chatgpt_user_id("enterprise-a-user")
            .email("account-a@example.com")
            .plan_type("enterprise"),
        AuthCredentialsStoreMode::File,
    )?;
    seed_managed_accounts(
        home.path(),
        &[("account-b@example.com", WORKSPACE_ID_DEVICE)],
    )
    .await?;
    Mock::given(method("GET"))
        .and(path("/backend-api/wham/config/bundle"))
        .and(header("chatgpt-account-id", WORKSPACE_ID_INITIAL))
        .respond_with(ResponseTemplate::new(/*status*/ 200).set_body_json(json!({
            "requirements_toml": {
                "enterprise_managed": [{
                    "id": "surviving-account-policy",
                    "name": "Surviving account policy",
                    "contents": "allow_remote_control = false\n",
                }],
            },
        })))
        .with_priority(/*priority*/ 1)
        .expect(1..)
        .mount(&backend)
        .await;
    let mut server = start_lifecycle_server(home.path(), &backend).await?;
    assert!(matches!(
        read_account(&mut server).await?.account,
        Some(Account::Chatgpt {
            email: Some(email),
            plan_type: AccountPlanType::Enterprise,
        })
            if email == "account-a@example.com"
    ));
    let request = server.send_config_requirements_read_request().await?;
    let before: ConfigRequirementsReadResponse =
        timeout(DEFAULT_READ_TIMEOUT, server.read_response(request)).await??;
    assert_eq!(
        before
            .requirements
            .as_ref()
            .and_then(|requirements| requirements.allow_remote_control),
        Some(false),
        "the constraint must have been delivered by A's loopback cloud bundle"
    );

    let request = server
        .send_list_accounts_request(json!({
            "refreshTokens": false,
            "refreshUsage": false,
        }))
        .await?;
    let inventory: ListAccountsResponse =
        timeout(DEFAULT_READ_TIMEOUT, server.read_response(request)).await??;
    assert_eq!(
        inventory
            .accounts
            .iter()
            .map(|row| row.managed_account_id.as_str())
            .collect::<Vec<_>>(),
        vec!["email:account-a@example.com", "email:account-b@example.com"]
    );
    assert_eq!(
        inventory.selected_account_id.as_deref(),
        Some("email:account-a@example.com")
    );

    let request = server
        .send_logout_account_request_with_params(json!({
            "accountId": selector,
            "all": false,
        }))
        .await?;
    let logout: LogoutAccountResponse =
        timeout(DEFAULT_READ_TIMEOUT, server.read_response(request)).await??;
    assert_eq!(logout.removed_account_ids, removed);
    assert_eq!(
        logout
            .accounts
            .iter()
            .map(|row| row.managed_account_id.as_str())
            .collect::<Vec<_>>(),
        if removed.is_empty() {
            vec!["email:account-a@example.com", "email:account-b@example.com"]
        } else {
            vec!["email:account-a@example.com"]
        }
    );

    // Read requirements before account/read can repair a discarded cloud loader.
    let request = server.send_config_requirements_read_request().await?;
    let after: ConfigRequirementsReadResponse =
        timeout(DEFAULT_READ_TIMEOUT, server.read_response(request)).await??;
    assert_eq!(
        after, before,
        "partial/no-op logout must retain the surviving owner's requirements"
    );
    backend.verify().await;
    Ok(())
}

#[tokio::test]
async fn logout_all_removes_stored_api_key_beneath_external_overlay_across_restart() -> Result<()> {
    let (home, backend) = lifecycle_fixture(CreateConfigTomlParams::default()).await?;
    login_with_api_key(
        home.path(),
        "sk-synthetic-stored-key",
        AuthCredentialsStoreMode::File,
        AuthKeyringBackendKind::Direct,
    )?;
    let mut server = start_lifecycle_server(home.path(), &backend).await?;
    assert_eq!(
        read_account(&mut server).await?.account,
        Some(Account::ApiKey {})
    );
    let access_token = encode_id_token(
        &ChatGptIdTokenClaims::new()
            .email("external@example.com")
            .chatgpt_account_id(WORKSPACE_ID_EMBEDDED),
    )?;
    let request = server
        .send_chatgpt_auth_tokens_login_request(
            access_token,
            WORKSPACE_ID_EMBEDDED.to_string(),
            Some("pro".to_string()),
        )
        .await?;
    let login: LoginAccountResponse =
        timeout(DEFAULT_READ_TIMEOUT, server.read_response(request)).await??;
    assert_eq!(login, LoginAccountResponse::ChatgptAuthTokens {});
    let _: AccountUpdatedNotification = timeout(
        DEFAULT_READ_TIMEOUT,
        server.read_notification("account/updated"),
    )
    .await??;
    assert!(matches!(
        read_account(&mut server).await?.account,
        Some(Account::Chatgpt { email: Some(email), .. }) if email == "external@example.com"
    ));

    let request = server
        .send_logout_account_request_with_params(json!({"all": true}))
        .await?;
    let logout: LogoutAccountResponse =
        timeout(DEFAULT_READ_TIMEOUT, server.read_response(request)).await??;
    assert_eq!(
        logout,
        LogoutAccountResponse {
            removed_account_ids: Vec::new(),
            accounts: Vec::new(),
            selected_account_id: None,
        }
    );
    let updated: AccountUpdatedNotification = timeout(
        DEFAULT_READ_TIMEOUT,
        server.read_notification("account/updated"),
    )
    .await??;
    let after_logout = read_account(&mut server).await?;
    let status = timeout(DEFAULT_READ_TIMEOUT, server.shutdown_gracefully()).await??;
    assert!(status.success());
    let mut restarted = start_lifecycle_server(home.path(), &backend).await?;
    let after_restart = read_account(&mut restarted).await?;
    // Collect both reads before asserting so this checks durable cleanup even
    // when the running server already exposes the resurrected stored API key.
    let signed_out = GetAccountResponse {
        account: None,
        requires_openai_auth: true,
        workspace_routing: None,
    };
    assert_eq!(
        (updated, after_logout, after_restart),
        (
            AccountUpdatedNotification {
                auth_mode: None,
                plan_type: None,
            },
            signed_out.clone(),
            signed_out,
        )
    );
    Ok(())
}
