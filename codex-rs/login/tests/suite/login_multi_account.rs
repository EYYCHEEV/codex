//! OAuth callbacks must add and refresh accounts without replacing their siblings.

use super::*;
use codex_login::AuthManager;
use codex_login::ManagedChatgptOauthCredentials;
use pretty_assertions::assert_eq;

#[tokio::test]
async fn oauth_callback_adds_account_and_relogin_preserves_sibling_after_restart() -> Result<()> {
    let home = tempdir()?;
    let manager = AuthManager::shared(
        home.path().to_path_buf(),
        /*enable_codex_api_key_env*/ false,
        AuthCredentialsStoreMode::File,
        /*forced_chatgpt_workspace_id*/ None,
        /*chatgpt_base_url*/ None,
        AuthKeyringBackendKind::Direct,
        codex_login::test_support::transport_default_auth_route_config(),
    )
    .await;
    manager
        .upsert_managed_chatgpt_oauth(ManagedChatgptOauthCredentials {
            tokens: serde_json::from_value(serde_json::json!({
                "id_token": test_id_token("sibling@example.com", "sibling-workspace"),
                "access_token": "sibling-access",
                "refresh_token": "sibling-refresh",
                "account_id": "sibling-workspace",
            }))?,
            last_refresh: chrono::Utc::now(),
            oauth_api_key: None,
        })
        .await?;
    drop(manager);

    let (issuer_addr, issuer_handle) = start_mock_issuer(WORKSPACE_ID_ALLOWED);
    let issuer = format!("http://{issuer_addr}");
    for _ in 0..2 {
        let server = run_login_server(ServerOptions {
            codex_home: home.path().to_path_buf(),
            cli_auth_credentials_store_mode: AuthCredentialsStoreMode::File,
            auth_route_config: codex_login::test_support::transport_default_auth_route_config(),
            client_id: codex_login::CLIENT_ID.to_string(),
            issuer: issuer.clone(),
            port: 0,
            open_browser: false,
            force_state: Some("multi-account-state".to_string()),
            forced_chatgpt_workspace_id: None,
            codex_streamlined_login: false,
            auth_keyring_backend_kind: AuthKeyringBackendKind::Direct,
            login_success_page: LoginSuccessPage::Local,
        })?;
        let client = HttpClientBuilder::new()
            .without_redirects()
            .build_direct()?;
        let callback_url = format!(
            "http://127.0.0.1:{}/auth/callback?code=abc&state=multi-account-state",
            server.actual_port,
        );
        let response = client.get(callback_url).send().await?;
        assert_eq!(response.status(), 302);
        let success_url = Url::parse(response.headers()["location"].to_str()?)?;
        assert!(client.get(success_url).send().await?.status().is_success());
        let callback = server.block_until_done_with_callback_result().await?;
        assert_eq!(
            callback.managed_account_id.as_deref(),
            Some("email:user@example.com")
        );

        let restarted = AuthManager::shared(
            home.path().to_path_buf(),
            /*enable_codex_api_key_env*/ false,
            AuthCredentialsStoreMode::File,
            /*forced_chatgpt_workspace_id*/ None,
            /*chatgpt_base_url*/ None,
            AuthKeyringBackendKind::Direct,
            codex_login::test_support::transport_default_auth_route_config(),
        )
        .await;
        let mut identities = restarted
            .stored_managed_chatgpt_accounts()?
            .into_iter()
            .map(|account| account.identity_key)
            .collect::<Vec<_>>();
        identities.sort();
        assert_eq!(
            identities,
            vec!["email:sibling@example.com", "email:user@example.com"]
        );
        let sibling = restarted
            .managed_chatgpt_auth_snapshot_for_identity("email:sibling@example.com")
            .await?
            .expect("sibling survives login");
        assert_eq!(
            sibling.auth.get_account_id().as_deref(),
            Some("sibling-workspace")
        );
    }
    drop(issuer_handle);
    Ok(())
}
