//! Catalog identity must follow the request's selected account, not the legacy projection.

use super::*;
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use codex_http_client::OutboundProxyPolicy;
use codex_login::AuthCredentialsStoreMode;
use codex_login::AuthKeyringBackendKind;
use codex_login::ManagedChatgptFailure;
use codex_login::ManagedChatgptOauthCredentials;
use codex_login::ManagedChatgptSelectionScope;
use codex_login::TokenData;
use codex_login::token_data::IdTokenInfo;
use codex_models_manager::manager::ModelsManager;
use codex_models_manager::manager::OpenAiModelsManager;
use codex_models_manager::manager::RefreshStrategy;
use codex_protocol::openai_models::ModelsResponse;
use pretty_assertions::assert_eq;
use wiremock::Mock;
use wiremock::MockServer;
use wiremock::ResponseTemplate;
use wiremock::matchers::header;
use wiremock::matchers::method;
use wiremock::matchers::path;

fn credentials(account: &str) -> ManagedChatgptOauthCredentials {
    let email = format!("{account}@example.com");
    let payload = serde_json::json!({
        "email": email,
        "https://api.openai.com/auth": {
            "chatgpt_user_id": format!("user-{account}"),
            "chatgpt_account_id": account,
        },
    });
    ManagedChatgptOauthCredentials {
        tokens: TokenData {
            id_token: IdTokenInfo {
                email: Some(email),
                chatgpt_account_id: Some(account.to_string()),
                raw_jwt: format!(
                    "e30.{}.signature",
                    URL_SAFE_NO_PAD.encode(serde_json::to_vec(&payload).unwrap())
                ),
                ..Default::default()
            },
            access_token: format!("access-{account}"),
            refresh_token: format!("refresh-{account}"),
            account_id: Some(account.to_string()),
        },
        last_refresh: chrono::Utc::now(),
        oauth_api_key: None,
    }
}

#[tokio::test]
async fn managed_pool_catalog_follows_selected_account_and_invalidates_on_pool_change() {
    let codex_home = tempfile::tempdir().unwrap();
    let auth = AuthManager::shared(
        codex_home.path().to_path_buf(),
        /*enable_codex_api_key_env*/ false,
        AuthCredentialsStoreMode::File,
        /*forced_chatgpt_workspace_id*/ None,
        /*chatgpt_base_url*/ None,
        AuthKeyringBackendKind::default(),
        codex_login::test_support::transport_default_auth_route_config(),
    )
    .await;
    for account in ["catalog-a", "catalog-b"] {
        auth.upsert_managed_chatgpt_oauth(credentials(account))
            .await
            .unwrap();
    }
    let projected_account = auth.auth_cached().unwrap().get_account_id().unwrap();
    let projected_identity = auth
        .stored_managed_chatgpt_accounts()
        .unwrap()
        .into_iter()
        .find(|account| account.chatgpt_account_id.as_ref() == Some(&projected_account))
        .unwrap()
        .identity_key;
    let projected_snapshot = auth
        .managed_chatgpt_auth_snapshot_for_identity(&projected_identity)
        .await
        .unwrap()
        .unwrap();
    let scope = ManagedChatgptSelectionScope::default();
    auth.recover_failed_attempt(
        &projected_snapshot,
        ManagedChatgptFailure::AuthInvalid,
        /*committed*/ false,
        &scope,
    )
    .await
    .unwrap();
    let selected = auth
        .managed_chatgpt_auth_snapshot(&scope)
        .await
        .unwrap()
        .unwrap();
    let selected_account = selected.auth.get_account_id().unwrap();
    assert_ne!(selected_account, projected_account);

    let server = MockServer::start().await;
    let model = codex_protocol::openai_models::ModelInfo {
        used_fallback_model_metadata: false,
        ..codex_models_manager::model_info::model_info_from_slug("pool-only-model")
    };
    Mock::given(method("GET"))
        .and(path("/models"))
        .and(header("chatgpt-account-id", selected_account.as_str()))
        .respond_with(ResponseTemplate::new(200).set_body_json(ModelsResponse {
            models: vec![model.clone()],
        }))
        .expect(1)
        .mount(&server)
        .await;
    let manager = OpenAiModelsManager::new_without_cache(
        Arc::new(OpenAiModelsEndpoint::new(
            ModelProviderInfo::create_openai_provider(Some(server.uri())),
            Some(Arc::clone(&auth)),
            /*gateway_auth_manager*/ None,
        )),
        Some(Arc::clone(&auth)),
    );
    let catalog = manager
        .raw_model_catalog(
            RefreshStrategy::Online,
            HttpClientFactory::new(OutboundProxyPolicy::ReqwestDefault),
        )
        .await;
    assert_eq!(
        catalog
            .models
            .iter()
            .find(|candidate| candidate.slug == model.slug),
        Some(&model)
    );
    auth.recover_failed_attempt(
        &selected,
        ManagedChatgptFailure::AuthInvalid,
        /*committed*/ false,
        &scope,
    )
    .await
    .unwrap();
    assert_eq!(
        manager.get_remote_models().await,
        codex_models_manager::bundled_models_response()
            .unwrap()
            .models
    );
}

#[tokio::test]
async fn independent_catalog_uses_selected_policy_at_the_owners_backend() {
    struct PolicyOwner(std::sync::atomic::AtomicUsize);
    impl codex_login::WorkspaceRoutingResolver for PolicyOwner {
        fn resolve<'a>(
            &'a self,
            _request: codex_login::WorkspaceRoutingRequest<'a>,
        ) -> std::pin::Pin<
            Box<
                dyn Future<Output = std::io::Result<Option<codex_login::WorkspaceRouting>>>
                    + Send
                    + 'a,
            >,
        > {
            Box::pin(async { panic!("catalog admission must not perform workspace routing") })
        }

        fn network_policy_for_managed_snapshot<'a>(
            &'a self,
            snapshot: &'a codex_login::ManagedChatgptAuthSnapshot,
            backend: &'a str,
            _session: Option<Arc<codex_login::WorkspaceRoutingSession>>,
        ) -> std::pin::Pin<
            Box<dyn Future<Output = std::io::Result<codex_http_client::NetworkPolicy>> + Send + 'a>,
        > {
            Box::pin(async move {
                assert_eq!(
                    (snapshot.auth.get_account_id().as_deref(), backend),
                    (
                        Some("catalog-selected"),
                        "https://policy.example/backend-api"
                    ),
                );
                self.0.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                let controller = codex_http_client::NetworkPolicyController::default();
                let policy = controller.policy().for_current_account();
                assert!(controller.publish(
                    policy.revision(),
                    codex_http_client::DestinationPolicy::Restricted {
                        allowed_hosts: Default::default(),
                    },
                ));
                Ok(policy)
            })
        }
    }

    let home = tempfile::tempdir().unwrap();
    let manager = AuthManager::shared(
        home.path().to_path_buf(),
        /*enable_codex_api_key_env*/ false,
        AuthCredentialsStoreMode::File,
        /*forced_chatgpt_workspace_id*/ None,
        Some("https://policy.example/backend-api".into()),
        AuthKeyringBackendKind::default(),
        codex_login::test_support::transport_default_auth_route_config(),
    )
    .await;
    manager
        .upsert_managed_chatgpt_oauth(credentials("catalog-selected"))
        .await
        .unwrap();
    let owner = Arc::new(PolicyOwner(std::sync::atomic::AtomicUsize::new(
        /*v*/ 0,
    )));
    let resolver: Arc<dyn codex_login::WorkspaceRoutingResolver> = owner.clone();
    manager.set_workspace_routing_resolver(Arc::downgrade(&resolver));
    let server = MockServer::start().await;
    let mut provider = ModelProviderInfo::create_openai_provider(/*base_url*/ None);
    provider.model_catalog_url = Some(format!("{}/independent-catalog", server.uri()).into());
    let endpoint =
        OpenAiModelsEndpoint::new(provider, Some(manager), /*gateway_auth_manager*/ None);
    let error = endpoint
        .list_models(
            "0.0.0",
            HttpClientFactory::new(OutboundProxyPolicy::ReqwestDefault),
        )
        .await
        .expect_err("selected policy must deny catalog content");
    assert!(error.to_string().contains("destination"));
    assert_eq!(owner.0.load(std::sync::atomic::Ordering::SeqCst), 1);
    assert!(server.received_requests().await.unwrap().is_empty());
}
