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
