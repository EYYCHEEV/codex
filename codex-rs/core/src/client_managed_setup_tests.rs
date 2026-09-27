use super::*;
use codex_login::ManagedChatgptLimitKind;
use codex_login::ManagedChatgptRateObservation;
use codex_login::ManagedChatgptRateWindowView;
use codex_login::ManagedChatgptStatusObservation;
use codex_login::ManagedChatgptTokenObservation;
use pretty_assertions::assert_eq;

#[derive(Clone, Copy, Debug)]
enum DuringRouting {
    UsageObservation,
    LegacyUsageObservation,
    CredentialRefresh,
}

#[derive(Debug)]
struct ManagedSetupUpdateProvider {
    inner: SharedModelProvider,
    update: DuringRouting,
    setup_calls: AtomicUsize,
}

impl ModelProvider for ManagedSetupUpdateProvider {
    fn info(&self) -> &ModelProviderInfo {
        self.inner.info()
    }

    fn auth_manager(&self) -> Option<Arc<AuthManager>> {
        self.inner.auth_manager()
    }

    fn auth(&self) -> ModelProviderFuture<'_, Option<CodexAuth>> {
        self.inner.auth()
    }

    fn account_state(&self) -> ProviderAccountResult {
        self.inner.account_state()
    }

    fn route_request_setup<'a>(
        &'a self,
        routing_context: &'a codex_model_provider::WorkspaceRoutingContext,
        setup: &'a mut codex_model_provider::ProviderRequestSetup,
    ) -> ModelProviderFuture<'a, codex_protocol::error::Result<()>> {
        Box::pin(async move {
            let call = self.setup_calls.fetch_add(1, Ordering::SeqCst);
            let manager = self.inner.auth_manager().expect("managed auth manager");
            let identity = setup
                .managed_id
                .as_deref()
                .expect("selected managed account");
            match self.update {
                DuringRouting::UsageObservation | DuringRouting::LegacyUsageObservation => {
                    // Every route observes new usage. Retrying setup cannot make
                    // this unrelated account-status traffic stop.
                    let saved = manager.record_managed_chatgpt_status_observation(
                        identity,
                        setup.credential_revision.expect("credential revision"),
                        setup
                            .account_state_revision
                            .expect("account state revision"),
                        ManagedChatgptStatusObservation {
                            observed_at: Utc::now(),
                            rate: ManagedChatgptRateObservation::Available(vec![
                                ManagedChatgptRateWindowView {
                                    limit_id: "codex".to_string(),
                                    kind: ManagedChatgptLimitKind::Primary,
                                    remaining_percent: Some(90.0 - call as f64),
                                    reset_at: Some(Utc::now() + chrono::Duration::hours(1)),
                                    window_duration_mins: Some(60),
                                },
                            ]),
                            token: ManagedChatgptTokenObservation::NotObserved,
                        },
                    )?;
                    assert!(saved.is_some(), "usage observation must actually be saved");
                }
                DuringRouting::CredentialRefresh => {
                    if call == 0 {
                        let mut tokens = setup
                            .effective_auth
                            .as_ref()
                            .expect("selected managed credentials")
                            .get_token_data()?;
                        tokens.access_token = "refreshed-setup-token".to_string();
                        let refreshed_identity = manager
                            .upsert_managed_chatgpt_oauth(ManagedChatgptOauthCredentials {
                                tokens,
                                last_refresh: Utc::now(),
                                oauth_api_key: None,
                            })
                            .await?;
                        assert_eq!(refreshed_identity, identity);
                    }
                }
            }
            self.inner.route_request_setup(routing_context, setup).await
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

#[test_case::test_case(DuringRouting::UsageObservation; "usage_only")]
#[test_case::test_case(DuringRouting::LegacyUsageObservation; "legacy_usage_only")]
#[test_case::test_case(DuringRouting::CredentialRefresh; "credential_refresh")]
#[tokio::test]
async fn client_setup_handles_managed_pool_changes_during_routing(
    update: DuringRouting,
) -> anyhow::Result<()> {
    let home = TempDir::new()?;
    let (mut client, manager) = managed_accounts_model_client(
        &home,
        "http://127.0.0.1:1",
        &[("setup@example.com", "setup-account")],
    )
    .await?;
    if let DuringRouting::LegacyUsageObservation = update {
        let auth_path = home.path().join("auth.json");
        let mut auth: serde_json::Value = serde_json::from_slice(&std::fs::read(&auth_path)?)?;
        let account = auth["managed_chatgpt"]["accounts"][0]
            .as_object_mut()
            .expect("temporary managed account");
        assert!(account.remove("credential_revision").is_some());
        std::fs::write(&auth_path, serde_json::to_vec(&auth)?)?;
        manager.reload().await;
    }
    let provider = Arc::new(ManagedSetupUpdateProvider {
        inner: Arc::clone(&client.state.provider),
        update,
        setup_calls: AtomicUsize::new(/*v*/ 0),
    });
    Arc::get_mut(&mut client.state)
        .expect("unique test client state")
        .provider = provider.clone();

    let setup = client
        .current_client_setup(/*model*/ None, /*session_id*/ None)
        .await
        .expect("usage observations must not invalidate unchanged request credentials");
    let mut headers = http::HeaderMap::new();
    setup.api_auth.add_auth_headers(&mut headers);
    let (expected_token, expected_calls) = match update {
        DuringRouting::UsageObservation | DuringRouting::LegacyUsageObservation => {
            ("access-setup-account", 1)
        }
        DuringRouting::CredentialRefresh => ("refreshed-setup-token", 2),
    };
    assert_eq!(
        headers
            .get(http::header::AUTHORIZATION)
            .expect("bearer auth"),
        &format!("Bearer {expected_token}")
    );
    assert_eq!(
        setup.effective_auth.expect("managed auth").get_account_id(),
        Some("setup-account".to_string())
    );
    assert_eq!(provider.setup_calls.load(Ordering::SeqCst), expected_calls);
    if matches!(
        update,
        DuringRouting::UsageObservation | DuringRouting::LegacyUsageObservation
    ) {
        let accounts = manager.managed_chatgpt_accounts()?;
        assert_eq!(accounts.len(), 1);
        let usage = accounts[0].usage.as_ref().expect("saved usage is visible");
        assert_eq!(usage.rate_windows.len(), 1);
        assert_eq!(usage.rate_windows[0].remaining_percent, Some(90.0));
    }
    Ok(())
}
