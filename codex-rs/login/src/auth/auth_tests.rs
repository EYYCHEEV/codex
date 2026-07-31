use super::*;
use crate::auth::storage::FileAuthStorage;
use crate::auth::storage::ManagedChatgptTombstone;
use crate::auth::storage::get_auth_file;
use crate::login_with_bedrock_api_key;
use crate::token_data::IdTokenInfo;
use codex_protocol::account::PlanType as AccountPlanType;
use codex_protocol::auth::AuthMode;
use codex_protocol::auth::KnownPlan as InternalKnownPlan;
use codex_protocol::auth::PlanType as InternalPlanType;
use codex_protocol::protocol::SessionSource;

use base64::Engine;
use codex_protocol::config_types::ForcedLoginMethod;
use codex_protocol::config_types::ModelProviderAuthInfo;
use pretty_assertions::assert_eq;
use serde::Serialize;
use serde_json::json;
use std::sync::Arc;
use std::sync::atomic::AtomicUsize;
use std::sync::atomic::Ordering;
use tempfile::TempDir;
use tempfile::tempdir;
use wiremock::Mock;
use wiremock::MockServer;
use wiremock::ResponseTemplate;
use wiremock::matchers::body_partial_json;
use wiremock::matchers::header;
use wiremock::matchers::method;
use wiremock::matchers::path;

const WORKSPACE_ID_ALLOWED: &str = "123e4567-e89b-42d3-a456-426614174000";
const WORKSPACE_ID_SECOND_ALLOWED: &str = "123e4567-e89b-42d3-a456-426614174001";
const WORKSPACE_ID_DISALLOWED: &str = "123e4567-e89b-42d3-a456-426614174002";

#[tokio::test]
async fn refresh_without_id_token() {
    let codex_home = tempdir().unwrap();
    let fake_jwt = fake_jwt_for_auth_file_params(&AuthFileParams {
        openai_api_key: None,
        chatgpt_plan_type: Some("pro".to_string()),
        chatgpt_account_id: Some("workspace-a".to_string()),
    })
    .expect("failed to create JWT");
    let auth_dot_json = AuthDotJson {
        auth_mode: Some(AuthMode::Chatgpt),
        openai_api_key: None,
        tokens: Some(TokenData {
            id_token: crate::token_data::parse_chatgpt_jwt_claims(&fake_jwt)
                .expect("JWT should parse"),
            access_token: "test-access-token".to_string(),
            refresh_token: "test-refresh-token".to_string(),
            account_id: Some("stale-workspace".to_string()),
        }),
        last_refresh: Some(Utc::now()),
        agent_identity: None,
        personal_access_token: None,
        bedrock_api_key: None,
        managed_chatgpt: None,
    };
    save_auth(
        codex_home.path(),
        &auth_dot_json,
        AuthCredentialsStoreMode::File,
        AuthKeyringBackendKind::default(),
    )
    .expect("failed to write auth file");

    let storage = create_auth_storage(
        codex_home.path().to_path_buf(),
        AuthCredentialsStoreMode::File,
        AuthKeyringBackendKind::default(),
    );
    let updated = super::persist_tokens(
        &storage,
        /*id_token*/ None,
        Some("new-access-token".to_string()),
        Some("new-refresh-token".to_string()),
    )
    .expect("update_tokens should succeed");

    let tokens = updated.tokens.expect("tokens should exist");
    assert_eq!(tokens.id_token.raw_jwt, fake_jwt);
    assert_eq!(tokens.access_token, "new-access-token");
    assert_eq!(tokens.refresh_token, "new-refresh-token");
    assert_eq!(
        tokens.id_token.chatgpt_account_id.as_deref(),
        Some("workspace-a")
    );
    assert_eq!(tokens.account_id.as_deref(), Some("workspace-a"));
}

#[tokio::test]
async fn refresh_with_new_id_token_updates_account_id() {
    let codex_home = tempdir().unwrap();
    let initial_jwt = fake_jwt_for_auth_file_params(&AuthFileParams {
        openai_api_key: None,
        chatgpt_plan_type: Some("pro".to_string()),
        chatgpt_account_id: Some("workspace-a".to_string()),
    })
    .expect("failed to create initial JWT");
    let refreshed_jwt = fake_jwt_for_auth_file_params(&AuthFileParams {
        openai_api_key: None,
        chatgpt_plan_type: Some("pro".to_string()),
        chatgpt_account_id: Some("workspace-b".to_string()),
    })
    .expect("failed to create refreshed JWT");
    let auth_dot_json = AuthDotJson {
        auth_mode: Some(AuthMode::Chatgpt),
        openai_api_key: None,
        tokens: Some(TokenData {
            id_token: crate::token_data::parse_chatgpt_jwt_claims(&initial_jwt)
                .expect("JWT should parse"),
            access_token: "test-access-token".to_string(),
            refresh_token: "test-refresh-token".to_string(),
            account_id: Some("workspace-a".to_string()),
        }),
        last_refresh: Some(Utc::now()),
        agent_identity: None,
        personal_access_token: None,
        bedrock_api_key: None,
        managed_chatgpt: None,
    };
    save_auth(
        codex_home.path(),
        &auth_dot_json,
        AuthCredentialsStoreMode::File,
        AuthKeyringBackendKind::default(),
    )
    .expect("failed to write auth file");

    let storage = create_auth_storage(
        codex_home.path().to_path_buf(),
        AuthCredentialsStoreMode::File,
        AuthKeyringBackendKind::default(),
    );
    let updated = super::persist_tokens(
        &storage,
        Some(refreshed_jwt.clone()),
        Some("new-access-token".to_string()),
        Some("new-refresh-token".to_string()),
    )
    .expect("update_tokens should succeed");

    let tokens = updated.tokens.expect("tokens should exist");
    assert_eq!(tokens.id_token.raw_jwt, refreshed_jwt);
    assert_eq!(tokens.access_token, "new-access-token");
    assert_eq!(tokens.refresh_token, "new-refresh-token");
    assert_eq!(
        tokens.id_token.chatgpt_account_id.as_deref(),
        Some("workspace-b")
    );
    assert_eq!(tokens.account_id.as_deref(), Some("workspace-b"));
}

#[tokio::test]
async fn load_auth_repairs_stale_account_id_for_managed_chatgpt_auth() {
    let codex_home = tempdir().unwrap();
    let fake_jwt = fake_jwt_for_auth_file_params(&AuthFileParams {
        openai_api_key: None,
        chatgpt_plan_type: Some("pro".to_string()),
        chatgpt_account_id: Some("workspace-a".to_string()),
    })
    .expect("failed to create JWT");
    let auth_dot_json = AuthDotJson {
        auth_mode: Some(AuthMode::Chatgpt),
        openai_api_key: None,
        tokens: Some(TokenData {
            id_token: crate::token_data::parse_chatgpt_jwt_claims(&fake_jwt)
                .expect("JWT should parse"),
            access_token: "test-access-token".to_string(),
            refresh_token: "test-refresh-token".to_string(),
            account_id: Some("stale-workspace".to_string()),
        }),
        last_refresh: Some(Utc::now()),
        agent_identity: None,
        personal_access_token: None,
        bedrock_api_key: None,
        managed_chatgpt: None,
    };
    save_auth(
        codex_home.path(),
        &auth_dot_json,
        AuthCredentialsStoreMode::File,
        AuthKeyringBackendKind::default(),
    )
    .expect("failed to write auth file");

    let auth = super::load_auth(
        codex_home.path(),
        /*enable_codex_api_key_env*/ false,
        AuthCredentialsStoreMode::File,
        /*forced_chatgpt_workspace_id*/ None,
        /*chatgpt_base_url*/ None,
        AuthKeyringBackendKind::default(),
        /*agent_identity_authapi_base_url*/ None,
        &crate::test_support::transport_default_auth_route_config(),
    )
    .await
    .expect("load_auth should succeed")
    .expect("auth should exist");
    assert_eq!(auth.get_account_id().as_deref(), Some("workspace-a"));

    let repaired = load_auth_dot_json(
        codex_home.path(),
        AuthCredentialsStoreMode::File,
        AuthKeyringBackendKind::default(),
    )
    .expect("load_auth_dot_json should succeed")
    .expect("auth.json should exist");
    assert!(repaired.tokens.is_none());
    let pool = repaired.managed_chatgpt.expect("managed pool should exist");
    assert_eq!(pool.accounts.len(), 1);
    let tokens = &pool.accounts[0].tokens;
    assert_eq!(
        tokens.id_token.chatgpt_account_id.as_deref(),
        Some("workspace-a")
    );
    assert_eq!(tokens.account_id.as_deref(), Some("workspace-a"));
}

#[test]
fn login_with_api_key_overwrites_existing_auth_json() {
    let dir = tempdir().unwrap();
    let auth_path = dir.path().join("auth.json");
    let stale_auth = json!({
        "OPENAI_API_KEY": "sk-old",
        "tokens": {
            "id_token": managed_id_token("stale@example.com", "stale-account"),
            "access_token": "stale-access",
            "refresh_token": "stale-refresh",
            "account_id": "stale-acc"
        }
    });
    std::fs::write(
        &auth_path,
        serde_json::to_string_pretty(&stale_auth).unwrap(),
    )
    .unwrap();

    super::login_with_api_key(
        dir.path(),
        "sk-new",
        AuthCredentialsStoreMode::File,
        AuthKeyringBackendKind::default(),
    )
    .expect("login_with_api_key should succeed");

    let storage = FileAuthStorage::new(dir.path().to_path_buf());
    let auth = storage
        .try_read_auth_json(&auth_path)
        .expect("auth.json should parse");
    assert_eq!(auth.openai_api_key.as_deref(), Some("sk-new"));
    assert!(auth.tokens.is_none(), "tokens should be cleared");
}

#[tokio::test]
async fn login_with_access_token_writes_agent_identity_jwt() {
    let dir = tempdir().unwrap();
    let auth_path = dir.path().join("auth.json");
    let record = agent_identity_record(WORKSPACE_ID_ALLOWED);
    let agent_identity =
        signed_agent_identity_jwt(&record, json!(record.plan_type)).expect("signed agent identity");
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/backend-api/wham/agent-identities/jwks"))
        .respond_with(ResponseTemplate::new(200).set_body_json(test_jwks_body()))
        .expect(1)
        .mount(&server)
        .await;
    let authapi_base_url = server.uri();
    let chatgpt_base_url = format!("{authapi_base_url}/backend-api");

    super::login_with_access_token(
        dir.path(),
        &agent_identity,
        AuthCredentialsStoreMode::File,
        /*forced_chatgpt_workspace_id*/ None,
        Some(&chatgpt_base_url),
        AuthKeyringBackendKind::default(),
        &crate::test_support::transport_default_auth_route_config(),
    )
    .await
    .expect("login_with_access_token should succeed");

    let storage = FileAuthStorage::new(dir.path().to_path_buf());
    let auth = storage
        .try_read_auth_json(&auth_path)
        .expect("auth.json should parse");
    assert_eq!(auth.auth_mode, Some(AuthMode::AgentIdentity));
    assert_eq!(
        auth.agent_identity,
        Some(AgentIdentityStorage::Jwt(agent_identity))
    );
    assert!(auth.tokens.is_none(), "tokens should be cleared");
    assert!(auth.openai_api_key.is_none(), "API key should be cleared");
    server.verify().await;
}

#[tokio::test]
async fn login_with_agent_identity_jwt_enforces_workspace_before_write() {
    let dir = tempdir().expect("tempdir");
    super::login_with_api_key(
        dir.path(),
        "sk-existing",
        AuthCredentialsStoreMode::File,
        AuthKeyringBackendKind::Direct,
    )
    .expect("seed existing auth");
    let auth_path = get_auth_file(dir.path());
    let before = std::fs::read(&auth_path).expect("read seeded auth");
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/backend-api/wham/agent-identities/jwks"))
        .respond_with(ResponseTemplate::new(200).set_body_json(test_jwks_body()))
        .expect(2)
        .mount(&server)
        .await;
    let chatgpt_base_url = format!("{}/backend-api", server.uri());
    let allowed = vec![WORKSPACE_ID_ALLOWED.to_string()];

    for account_id in [WORKSPACE_ID_DISALLOWED, ""] {
        let record = agent_identity_record(account_id);
        let jwt = signed_agent_identity_jwt(&record, json!(record.plan_type))
            .expect("signed agent identity");
        let err = super::login_with_access_token(
            dir.path(),
            &jwt,
            AuthCredentialsStoreMode::File,
            Some(&allowed),
            Some(&chatgpt_base_url),
            AuthKeyringBackendKind::Direct,
            &crate::test_support::transport_default_auth_route_config(),
        )
        .await
        .expect_err("disallowed workspace must be rejected");
        assert_eq!(err.kind(), std::io::ErrorKind::PermissionDenied);
        assert_eq!(
            std::fs::read(&auth_path).expect("read preserved auth"),
            before
        );
    }
    server.verify().await;
}

#[tokio::test]
async fn login_with_agent_identity_jwt_allows_same_workspace_when_fedramp() {
    let dir = tempdir().expect("tempdir");
    let mut record = agent_identity_record(WORKSPACE_ID_ALLOWED);
    record.chatgpt_account_is_fedramp = true;
    let jwt =
        signed_agent_identity_jwt(&record, json!(record.plan_type)).expect("signed agent identity");
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/backend-api/wham/agent-identities/jwks"))
        .respond_with(ResponseTemplate::new(200).set_body_json(test_jwks_body()))
        .expect(1)
        .mount(&server)
        .await;
    let allowed = vec![WORKSPACE_ID_ALLOWED.to_string()];

    super::login_with_access_token(
        dir.path(),
        &jwt,
        AuthCredentialsStoreMode::File,
        Some(&allowed),
        Some(&format!("{}/backend-api", server.uri())),
        AuthKeyringBackendKind::Direct,
        &crate::test_support::transport_default_auth_route_config(),
    )
    .await
    .expect("same workspace FedRAMP JWT should be allowed");

    let stored = load_auth_dot_json(
        dir.path(),
        AuthCredentialsStoreMode::File,
        AuthKeyringBackendKind::Direct,
    )
    .expect("load auth")
    .expect("stored auth");
    assert_eq!(stored.agent_identity, Some(AgentIdentityStorage::Jwt(jwt)));
    server.verify().await;
}

#[tokio::test]
#[serial(codex_auth_env)]
async fn env_agent_identity_jwt_rejects_workspace_before_task_registration() {
    let codex_home = tempdir().expect("tempdir");
    let record = agent_identity_record(WORKSPACE_ID_DISALLOWED);
    let jwt =
        signed_agent_identity_jwt(&record, json!(record.plan_type)).expect("signed agent identity");
    let _access_token_guard = EnvVarGuard::set(CODEX_ACCESS_TOKEN_ENV_VAR, &jwt);
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/backend-api/wham/agent-identities/jwks"))
        .respond_with(ResponseTemplate::new(200).set_body_json(test_jwks_body()))
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(500))
        .expect(0)
        .mount(&server)
        .await;
    let allowed = vec![WORKSPACE_ID_ALLOWED.to_string()];
    let authapi_base_url = server.uri();
    let err = super::load_auth(
        codex_home.path(),
        false,
        AuthCredentialsStoreMode::File,
        Some(&allowed),
        Some(&format!("{authapi_base_url}/backend-api")),
        AuthKeyringBackendKind::Direct,
        Some(&authapi_base_url),
        &crate::test_support::transport_default_auth_route_config(),
    )
    .await
    .expect_err("disallowed env JWT must fail");
    assert_eq!(err.kind(), std::io::ErrorKind::PermissionDenied);
    assert!(!get_auth_file(codex_home.path()).exists());
    server.verify().await;
}

#[tokio::test]
#[serial(codex_auth_env)]
async fn persisted_agent_identity_jwt_rejects_workspace_without_mutation_or_registration() {
    let _access_token_guard = remove_access_token_env_var();
    let codex_home = tempdir().expect("tempdir");
    let record = agent_identity_record(WORKSPACE_ID_DISALLOWED);
    let jwt =
        signed_agent_identity_jwt(&record, json!(record.plan_type)).expect("signed agent identity");
    let document = AuthDotJson {
        auth_mode: Some(AuthMode::AgentIdentity),
        openai_api_key: None,
        tokens: None,
        last_refresh: None,
        agent_identity: Some(AgentIdentityStorage::Jwt(jwt)),
        managed_chatgpt: None,
        personal_access_token: None,
        bedrock_api_key: None,
    };
    save_auth(
        codex_home.path(),
        &document,
        AuthCredentialsStoreMode::File,
        AuthKeyringBackendKind::Direct,
    )
    .expect("seed persisted JWT");
    let before = std::fs::read(get_auth_file(codex_home.path())).expect("read seeded JWT");
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/backend-api/wham/agent-identities/jwks"))
        .respond_with(ResponseTemplate::new(200).set_body_json(test_jwks_body()))
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(500))
        .expect(0)
        .mount(&server)
        .await;
    let allowed = vec![WORKSPACE_ID_ALLOWED.to_string()];
    let authapi_base_url = server.uri();
    let err = super::load_auth(
        codex_home.path(),
        false,
        AuthCredentialsStoreMode::File,
        Some(&allowed),
        Some(&format!("{authapi_base_url}/backend-api")),
        AuthKeyringBackendKind::Direct,
        Some(&authapi_base_url),
        &crate::test_support::transport_default_auth_route_config(),
    )
    .await
    .expect_err("disallowed persisted JWT must fail");
    assert_eq!(err.kind(), std::io::ErrorKind::PermissionDenied);
    assert_eq!(
        std::fs::read(get_auth_file(codex_home.path())).expect("read preserved JWT"),
        before
    );
    server.verify().await;
}

#[tokio::test]
#[serial(codex_auth_env)]
async fn stored_agent_identity_jwt_keeps_auth_json_unchanged() -> anyhow::Result<()> {
    let _access_token_guard = remove_access_token_env_var();
    let codex_home = tempdir()?;
    let record = agent_identity_record(WORKSPACE_ID_ALLOWED);
    let agent_identity =
        signed_agent_identity_jwt(&record, json!(record.plan_type)).expect("signed agent identity");
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/backend-api/wham/agent-identities/jwks"))
        .respond_with(ResponseTemplate::new(200).set_body_json(test_jwks_body()))
        .expect(1)
        .mount(&server)
        .await;
    mock_agent_task_registration(&server, "", &record.agent_runtime_id, "task-id").await;
    let authapi_base_url = server.uri();
    let chatgpt_base_url = format!("{authapi_base_url}/backend-api");
    save_auth(
        codex_home.path(),
        &AuthDotJson {
            auth_mode: Some(AuthMode::AgentIdentity),
            openai_api_key: None,
            tokens: None,
            last_refresh: None,
            agent_identity: Some(AgentIdentityStorage::Jwt(agent_identity.clone())),
            personal_access_token: None,
            bedrock_api_key: None,
            managed_chatgpt: None,
        },
        AuthCredentialsStoreMode::File,
        AuthKeyringBackendKind::Direct,
    )?;

    let auth = super::load_auth(
        codex_home.path(),
        /*enable_codex_api_key_env*/ false,
        AuthCredentialsStoreMode::File,
        /*allowed_login_methods*/ None,
        /*forced_chatgpt_workspace_id*/ None,
        Some(&chatgpt_base_url),
        AuthKeyringBackendKind::Direct,
        Some(&authapi_base_url),
        &crate::test_support::transport_default_auth_route_config(),
    )
    .await?
    .expect("auth should load");

    let CodexAuth::AgentIdentity(agent_identity_auth) = auth else {
        panic!("stored JWT should load as agent identity auth");
    };
    assert_eq!(agent_identity_auth.run_task_id(), "task-id");
    let storage = FileAuthStorage::new(codex_home.path().to_path_buf());
    let auth = storage
        .try_read_auth_json(&get_auth_file(codex_home.path()))
        .expect("auth.json should parse");
    assert_eq!(
        auth.agent_identity,
        Some(AgentIdentityStorage::Jwt(agent_identity))
    );
    server.verify().await;
    Ok(())
}

#[tokio::test]
#[serial(codex_auth_env)]
async fn login_with_access_token_writes_only_personal_access_token() {
    let dir = tempdir().unwrap();
    let auth_path = dir.path().join("auth.json");
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/v1/user-auth-credential/whoami"))
        .and(header("authorization", "Bearer at-login-test"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(personal_access_token_whoami(WORKSPACE_ID_ALLOWED)),
        )
        .expect(1)
        .mount(&server)
        .await;
    let _authapi_guard = EnvVarGuard::set("CODEX_AUTHAPI_BASE_URL", &server.uri());
    let allowed_workspaces = [WORKSPACE_ID_ALLOWED.to_string()];
    super::login_with_access_token(
        dir.path(),
        "at-login-test",
        AuthCredentialsStoreMode::File,
        Some(&allowed_workspaces),
        /*chatgpt_base_url*/ None,
        AuthKeyringBackendKind::default(),
        &crate::test_support::transport_default_auth_route_config(),
    )
    .await
    .expect("personal access token login should succeed");

    let storage = FileAuthStorage::new(dir.path().to_path_buf());
    let auth = storage
        .try_read_auth_json(&auth_path)
        .expect("auth.json should parse");
    assert_eq!(
        auth,
        AuthDotJson {
            auth_mode: None,
            openai_api_key: None,
            tokens: None,
            last_refresh: None,
            agent_identity: None,
            managed_chatgpt: None,
            personal_access_token: Some("at-login-test".to_string()),
            bedrock_api_key: None,
        }
    );
    assert_eq!(auth.resolved_mode(), AuthMode::PersonalAccessToken);
    let persisted: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(auth_path).unwrap()).unwrap();
    assert!(persisted.get("auth_mode").is_none());
    server.verify().await;
}

#[tokio::test]
#[serial(codex_auth_env)]
async fn login_with_access_token_rejects_personal_access_token_workspace_mismatch() {
    let dir = tempdir().unwrap();
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/v1/user-auth-credential/whoami"))
        .and(header("authorization", "Bearer at-workspace-mismatch"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(personal_access_token_whoami(WORKSPACE_ID_DISALLOWED)),
        )
        .expect(1)
        .mount(&server)
        .await;
    let _authapi_guard = EnvVarGuard::set("CODEX_AUTHAPI_BASE_URL", &server.uri());
    let allowed_workspaces = [WORKSPACE_ID_ALLOWED.to_string()];

    let err = super::login_with_access_token(
        dir.path(),
        "at-workspace-mismatch",
        AuthCredentialsStoreMode::File,
        Some(&allowed_workspaces),
        /*chatgpt_base_url*/ None,
        AuthKeyringBackendKind::default(),
        &crate::test_support::transport_default_auth_route_config(),
    )
    .await
    .expect_err("personal access token workspace mismatch should fail");

    assert_eq!(err.kind(), std::io::ErrorKind::PermissionDenied);
    assert!(
        !get_auth_file(dir.path()).exists(),
        "workspace mismatch should not write auth.json"
    );
    server.verify().await;
}

#[tokio::test]
#[serial(codex_auth_env)]
async fn login_with_access_token_rejects_invalid_personal_access_token() {
    let dir = tempdir().unwrap();
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/v1/user-auth-credential/whoami"))
        .respond_with(ResponseTemplate::new(403))
        .expect(1)
        .mount(&server)
        .await;
    let _authapi_guard = EnvVarGuard::set("CODEX_AUTHAPI_BASE_URL", &server.uri());

    let err = super::login_with_access_token(
        dir.path(),
        "at-invalid-login",
        AuthCredentialsStoreMode::File,
        /*forced_chatgpt_workspace_id*/ None,
        /*chatgpt_base_url*/ None,
        AuthKeyringBackendKind::default(),
        &crate::test_support::transport_default_auth_route_config(),
    )
    .await
    .expect_err("invalid personal access token should fail");

    assert_eq!(err.kind(), std::io::ErrorKind::Other);
    assert!(
        !get_auth_file(dir.path()).exists(),
        "invalid personal access token should not write auth.json"
    );
    server.verify().await;
}

#[tokio::test]
async fn login_with_access_token_rejects_invalid_jwt() {
    let dir = tempdir().unwrap();

    let err = super::login_with_access_token(
        dir.path(),
        "not-a-jwt",
        AuthCredentialsStoreMode::File,
        /*forced_chatgpt_workspace_id*/ None,
        /*chatgpt_base_url*/ None,
        AuthKeyringBackendKind::default(),
        &crate::test_support::transport_default_auth_route_config(),
    )
    .await
    .expect_err("invalid access token should fail");

    assert_eq!(err.kind(), std::io::ErrorKind::Other);
    assert!(
        !get_auth_file(dir.path()).exists(),
        "invalid access token should not write auth.json"
    );
}

#[tokio::test]
#[serial(codex_auth_env)]
async fn chatgpt_auth_registers_agent_identity_when_enabled() -> anyhow::Result<()> {
    let codex_home = tempdir()?;
    write_auth_file(
        AuthFileParams {
            openai_api_key: None,
            chatgpt_plan_type: Some("pro".to_string()),
            chatgpt_account_id: Some("account-123".to_string()),
        },
        codex_home.path(),
    )?;
    let auth = super::load_auth(
        codex_home.path(),
        /*enable_codex_api_key_env*/ false,
        AuthCredentialsStoreMode::File,
        /*allowed_login_methods*/ None,
        /*forced_chatgpt_workspace_id*/ None,
        /*chatgpt_base_url*/ None,
        AuthKeyringBackendKind::Direct,
        /*agent_identity_authapi_base_url*/ None,
        &crate::test_support::transport_default_auth_route_config(),
    )
    .await?
    .expect("auth should load");

    assert!(
        auth.agent_identity_auth(
            AgentIdentityAuthPolicy::JwtOnly,
            /*agent_identity_authapi_base_url*/ None,
            /*forced_chatgpt_workspace_id*/ None,
            &crate::test_support::transport_default_auth_route_config(),
            SessionSource::Cli,
        )
        .await?
        .is_none()
    );

    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/v1/agent/register"))
        .and(header("authorization", "Bearer test-access-token"))
        .and(body_partial_json(json!({
            "abom": {
                "agent_harness_id": "codex-cli",
            },
            "capabilities": ["responsesapi"],
            "ttl": null,
        })))
        .respond_with(ResponseTemplate::new(/*s*/ 200).set_body_json(json!({
            "agent_runtime_id": "agent-runtime-123",
        })))
        .expect(/*r*/ 1)
        .mount(&server)
        .await;
    mock_agent_task_registration(&server, "", "agent-runtime-123", "task-123").await;

    let agent_auth = auth
        .agent_identity_auth(
            AgentIdentityAuthPolicy::ChatGptAuth,
            Some(&server.uri()),
            /*forced_chatgpt_workspace_id*/ None,
            &crate::test_support::transport_default_auth_route_config(),
            SessionSource::Cli,
        )
        .await?
        .expect("agent identity should register");
    let reused = auth
        .agent_identity_auth(
            AgentIdentityAuthPolicy::ChatGptAuth,
            Some(&server.uri()),
            /*forced_chatgpt_workspace_id*/ None,
            &crate::test_support::transport_default_auth_route_config(),
            SessionSource::Cli,
        )
        .await?
        .expect("agent identity should be reused");

    assert_eq!(
        agent_auth.record().agent_runtime_id,
        reused.record().agent_runtime_id
    );
    assert_eq!(agent_auth.run_task_id(), "task-123");
    assert_eq!(reused.run_task_id(), "task-123");
    assert_eq!(agent_auth.record().agent_runtime_id, "agent-runtime-123");
    assert_eq!(agent_auth.record().account_id, "account-123");
    assert_eq!(agent_auth.record().chatgpt_user_id, "user-12345");
    assert_eq!(agent_auth.record().task_id.as_deref(), Some("task-123"));
    assert_eq!(reused.record().task_id.as_deref(), Some("task-123"));
    let persisted = auth
        .stored_managed_chatgpt_agent_identity_record("account-123")
        .expect("identity should persist");
    assert_eq!(persisted.agent_runtime_id, "agent-runtime-123");
    assert_eq!(persisted.task_id.as_deref(), Some("task-123"));

    let reloaded = super::load_auth(
        codex_home.path(),
        /*enable_codex_api_key_env*/ false,
        AuthCredentialsStoreMode::File,
        /*allowed_login_methods*/ None,
        /*forced_chatgpt_workspace_id*/ None,
        /*chatgpt_base_url*/ None,
        AuthKeyringBackendKind::Direct,
        /*agent_identity_authapi_base_url*/ None,
        &crate::test_support::transport_default_auth_route_config(),
    )
    .await?
    .expect("auth should reload");
    let reloaded_agent_auth = reloaded
        .agent_identity_auth(
            AgentIdentityAuthPolicy::ChatGptAuth,
            Some(&server.uri()),
            /*forced_chatgpt_workspace_id*/ None,
            &crate::test_support::transport_default_auth_route_config(),
            SessionSource::Cli,
        )
        .await?
        .expect("agent identity should reload from storage");
    assert_eq!(
        reloaded_agent_auth.record().agent_runtime_id,
        "agent-runtime-123"
    );
    assert_eq!(reloaded_agent_auth.run_task_id(), "task-123");
    Ok(())
}

#[tokio::test]
#[serial(codex_auth_env)]
async fn chatgpt_auth_retries_transient_agent_identity_registration() -> anyhow::Result<()> {
    let codex_home = tempdir()?;
    write_auth_file(
        AuthFileParams {
            openai_api_key: None,
            chatgpt_plan_type: Some("pro".to_string()),
            chatgpt_account_id: Some("account-123".to_string()),
        },
        codex_home.path(),
    )?;
    let auth = super::load_auth(
        codex_home.path(),
        /*enable_codex_api_key_env*/ false,
        AuthCredentialsStoreMode::File,
        /*allowed_login_methods*/ None,
        /*forced_chatgpt_workspace_id*/ None,
        /*chatgpt_base_url*/ None,
        AuthKeyringBackendKind::Direct,
        /*agent_identity_authapi_base_url*/ None,
        &crate::test_support::transport_default_auth_route_config(),
    )
    .await?
    .expect("auth should load");

    let server = MockServer::start().await;
    let registration_count = Arc::new(AtomicUsize::new(0));
    let response_count = Arc::clone(&registration_count);
    Mock::given(method("POST"))
        .and(path("/v1/agent/register"))
        .respond_with(move |_request: &wiremock::Request| {
            if response_count.fetch_add(1, Ordering::SeqCst) < 2 {
                ResponseTemplate::new(/*status*/ 503)
            } else {
                ResponseTemplate::new(/*status*/ 200).set_body_json(json!({
                    "agent_runtime_id": "agent-runtime-123",
                }))
            }
        })
        .expect(/*requests*/ 3)
        .mount(&server)
        .await;
    mock_agent_task_registration(&server, "", "agent-runtime-123", "task-123").await;

    let agent_auth = auth
        .agent_identity_auth(
            AgentIdentityAuthPolicy::ChatGptAuth,
            Some(&server.uri()),
            /*forced_chatgpt_workspace_id*/ None,
            &crate::test_support::transport_default_auth_route_config(),
            SessionSource::Cli,
        )
        .await?
        .expect("agent identity should register after retries");

    assert_eq!(registration_count.load(Ordering::SeqCst), 3);
    assert_eq!(agent_auth.record().agent_runtime_id, "agent-runtime-123");
    assert_eq!(agent_auth.record().task_id.as_deref(), Some("task-123"));
    assert_eq!(
        auth.stored_managed_chatgpt_agent_identity_record("account-123")
            .and_then(|record| record.task_id),
        Some("task-123".to_string())
    );
    Ok(())
}

#[tokio::test]
#[serial(codex_auth_env)]
async fn chatgpt_auth_registration_retry_exhaustion_is_fallback_eligible() -> anyhow::Result<()> {
    let codex_home = tempdir()?;
    write_auth_file(
        AuthFileParams {
            openai_api_key: None,
            chatgpt_plan_type: Some("pro".to_string()),
            chatgpt_account_id: Some("account-123".to_string()),
        },
        codex_home.path(),
    )?;
    let auth = super::load_auth(
        codex_home.path(),
        /*enable_codex_api_key_env*/ false,
        AuthCredentialsStoreMode::File,
        /*allowed_login_methods*/ None,
        /*forced_chatgpt_workspace_id*/ None,
        /*chatgpt_base_url*/ None,
        AuthKeyringBackendKind::Direct,
        /*agent_identity_authapi_base_url*/ None,
        &crate::test_support::transport_default_auth_route_config(),
    )
    .await?
    .expect("auth should load");

    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/v1/agent/register"))
        .respond_with(ResponseTemplate::new(/*status*/ 503))
        .expect(/*requests*/ 3)
        .mount(&server)
        .await;

    let err = auth
        .agent_identity_auth(
            AgentIdentityAuthPolicy::ChatGptAuth,
            Some(&server.uri()),
            /*forced_chatgpt_workspace_id*/ None,
            &crate::test_support::transport_default_auth_route_config(),
            SessionSource::Cli,
        )
        .await
        .expect_err("retry exhaustion should return an error");

    assert!(AgentIdentityAuthError::bootstrap_unavailable(&err).is_some());
    assert!(
        auth.stored_managed_chatgpt_agent_identity_record("account-123")
            .is_none()
    );
    Ok(())
}

#[tokio::test]
#[serial(codex_auth_env)]
async fn chatgpt_auth_task_registration_retry_exhaustion_is_fallback_eligible() -> anyhow::Result<()>
{
    let codex_home = tempdir()?;
    write_auth_file(
        AuthFileParams {
            openai_api_key: None,
            chatgpt_plan_type: Some("pro".to_string()),
            chatgpt_account_id: Some("account-123".to_string()),
        },
        codex_home.path(),
    )?;
    let mut record = agent_identity_record("account-123");
    record.chatgpt_user_id = "user-12345".to_string();
    record.email = Some("user@example.com".to_string());
    let storage = FileAuthStorage::new(codex_home.path().to_path_buf());
    let auth_path = get_auth_file(codex_home.path());
    let mut auth_json = storage.try_read_auth_json(&auth_path)?;
    auth_json.agent_identity = Some(AgentIdentityStorage::Record(record.clone()));
    storage.save(&auth_json)?;
    let auth = super::load_auth(
        codex_home.path(),
        /*enable_codex_api_key_env*/ false,
        AuthCredentialsStoreMode::File,
        /*allowed_login_methods*/ None,
        /*forced_chatgpt_workspace_id*/ None,
        /*chatgpt_base_url*/ None,
        AuthKeyringBackendKind::Direct,
        /*agent_identity_authapi_base_url*/ None,
        &crate::test_support::transport_default_auth_route_config(),
    )
    .await?
    .expect("auth should load");

    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path(format!(
            "/v1/agent/{}/task/register",
            record.agent_runtime_id
        )))
        .respond_with(ResponseTemplate::new(/*status*/ 503))
        .expect(/*requests*/ 3)
        .mount(&server)
        .await;

    let err = auth
        .agent_identity_auth(
            AgentIdentityAuthPolicy::ChatGptAuth,
            Some(&server.uri()),
            /*forced_chatgpt_workspace_id*/ None,
            &crate::test_support::transport_default_auth_route_config(),
            SessionSource::Cli,
        )
        .await
        .expect_err("task retry exhaustion should return an error");

    assert!(AgentIdentityAuthError::bootstrap_unavailable(&err).is_some());
    record.task_id = None;
    assert_eq!(
        auth.stored_managed_chatgpt_agent_identity_record("account-123"),
        Some(record)
    );
    Ok(())
}

#[tokio::test]
#[serial(codex_auth_env)]
async fn chatgpt_auth_non_retryable_registration_error_is_hard_failure() -> anyhow::Result<()> {
    let codex_home = tempdir()?;
    write_auth_file(
        AuthFileParams {
            openai_api_key: None,
            chatgpt_plan_type: Some("pro".to_string()),
            chatgpt_account_id: Some("account-123".to_string()),
        },
        codex_home.path(),
    )?;
    let auth = super::load_auth(
        codex_home.path(),
        /*enable_codex_api_key_env*/ false,
        AuthCredentialsStoreMode::File,
        /*allowed_login_methods*/ None,
        /*forced_chatgpt_workspace_id*/ None,
        /*chatgpt_base_url*/ None,
        AuthKeyringBackendKind::Direct,
        /*agent_identity_authapi_base_url*/ None,
        &crate::test_support::transport_default_auth_route_config(),
    )
    .await?
    .expect("auth should load");

    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/v1/agent/register"))
        .respond_with(ResponseTemplate::new(/*status*/ 403))
        .expect(/*requests*/ 1)
        .mount(&server)
        .await;

    let err = auth
        .agent_identity_auth(
            AgentIdentityAuthPolicy::ChatGptAuth,
            Some(&server.uri()),
            /*forced_chatgpt_workspace_id*/ None,
            &crate::test_support::transport_default_auth_route_config(),
            SessionSource::Cli,
        )
        .await
        .expect_err("hard registration failure should return an error");

    assert!(AgentIdentityAuthError::bootstrap_unavailable(&err).is_none());
    assert!(
        auth.stored_managed_chatgpt_agent_identity_record("account-123")
            .is_none()
    );
    Ok(())
}

#[tokio::test]
async fn agent_identity_jwt_task_registration_retry_exhaustion_is_strict() -> anyhow::Result<()> {
    let record = agent_identity_record(WORKSPACE_ID_ALLOWED);
    let agent_identity =
        signed_agent_identity_jwt(&record, json!(record.plan_type)).expect("signed agent identity");
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/backend-api/wham/agent-identities/jwks"))
        .respond_with(ResponseTemplate::new(200).set_body_json(test_jwks_body()))
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path(format!(
            "/v1/agent/{}/task/register",
            record.agent_runtime_id
        )))
        .respond_with(ResponseTemplate::new(/*status*/ 503))
        .expect(/*requests*/ 3)
        .mount(&server)
        .await;
    let authapi_base_url = server.uri();
    let chatgpt_base_url = format!("{authapi_base_url}/backend-api");

    let err = CodexAuth::from_agent_identity_jwt_with_authapi_base_url(
        &agent_identity,
        Some(&chatgpt_base_url),
        &authapi_base_url,
        &crate::test_support::transport_default_auth_route_config(),
    )
    .await
    .expect_err("agent identity jwt task retry exhaustion should fail");

    assert!(AgentIdentityAuthError::bootstrap_unavailable(&err).is_none());
    Ok(())
}

#[tokio::test]
async fn login_with_access_token_rejects_unsigned_jwt() {
    let dir = tempdir().unwrap();
    let record = agent_identity_record(WORKSPACE_ID_ALLOWED);
    let agent_identity = fake_agent_identity_jwt(&record).expect("fake agent identity");
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/backend-api/wham/agent-identities/jwks"))
        .respond_with(ResponseTemplate::new(200).set_body_json(test_jwks_body()))
        .expect(1)
        .mount(&server)
        .await;
    let authapi_base_url = server.uri();
    let chatgpt_base_url = format!("{authapi_base_url}/backend-api");

    super::login_with_access_token(
        dir.path(),
        &agent_identity,
        AuthCredentialsStoreMode::File,
        /*forced_chatgpt_workspace_id*/ None,
        Some(&chatgpt_base_url),
        AuthKeyringBackendKind::default(),
        &crate::test_support::transport_default_auth_route_config(),
    )
    .await
    .expect_err("unsigned access token should fail");

    assert!(
        !get_auth_file(dir.path()).exists(),
        "unsigned access token should not write auth.json"
    );
    server.verify().await;
}

#[tokio::test]
#[serial(codex_auth_env)]
async fn missing_auth_json_returns_none() {
    let dir = tempdir().unwrap();
    let _access_token_guard = remove_access_token_env_var();
    let auth = CodexAuth::from_auth_storage(
        dir.path(),
        AuthCredentialsStoreMode::File,
        /*chatgpt_base_url*/ None,
        AuthKeyringBackendKind::default(),
        &crate::test_support::transport_default_auth_route_config(),
    )
    .await
    .expect("call should succeed");
    assert_eq!(auth, None);
}

#[tokio::test]
#[serial(codex_auth_env)]
async fn pro_account_with_no_api_key_uses_chatgpt_auth() {
    let codex_home = tempdir().unwrap();
    let _access_token_guard = remove_access_token_env_var();
    let fake_jwt = write_auth_file(
        AuthFileParams {
            openai_api_key: None,
            chatgpt_plan_type: Some("pro".to_string()),
            chatgpt_account_id: None,
        },
        codex_home.path(),
    )
    .expect("failed to write auth file");

    let auth = super::load_auth(
        codex_home.path(),
        /*enable_codex_api_key_env*/ false,
        AuthCredentialsStoreMode::File,
        /*allowed_login_methods*/ None,
        /*forced_chatgpt_workspace_id*/ None,
        /*chatgpt_base_url*/ None,
        AuthKeyringBackendKind::Direct,
        /*agent_identity_authapi_base_url*/ None,
        &crate::test_support::transport_default_auth_route_config(),
    )
    .await
    .unwrap()
    .unwrap();
    assert_eq!(None, auth.api_key());
    assert_eq!(AuthMode::Chatgpt, auth.auth_mode());
    assert_eq!(auth.get_chatgpt_user_id().as_deref(), Some("user-12345"));

    let auth_dot_json = auth
        .get_current_auth_json()
        .expect("AuthDotJson should exist");
    let last_refresh = auth_dot_json
        .last_refresh
        .expect("last_refresh should be recorded");

    assert_eq!(
        AuthDotJson {
            auth_mode: Some(AuthMode::Chatgpt),
            openai_api_key: None,
            tokens: Some(TokenData {
                id_token: IdTokenInfo {
                    email: Some("user@example.com".to_string()),
                    chatgpt_plan_type: Some(InternalPlanType::Known(InternalKnownPlan::Pro)),
                    chatgpt_user_id: Some("user-12345".to_string()),
                    chatgpt_account_id: None,
                    chatgpt_account_is_fedramp: false,
                    raw_jwt: fake_jwt,
                },
                access_token: "test-access-token".to_string(),
                refresh_token: "test-refresh-token".to_string(),
                account_id: None,
            }),
            last_refresh: Some(last_refresh),
            agent_identity: None,
            managed_chatgpt: None,
            personal_access_token: None,
            bedrock_api_key: None,
        },
        auth_dot_json
    );
}

#[tokio::test]
#[serial(codex_auth_env)]
async fn loads_api_key_from_auth_json() {
    let dir = tempdir().unwrap();
    let _access_token_guard = remove_access_token_env_var();
    let auth_file = dir.path().join("auth.json");
    std::fs::write(
        auth_file,
        r#"{"OPENAI_API_KEY":"sk-test-key","tokens":null,"last_refresh":null}"#,
    )
    .unwrap();

    let auth = super::load_auth(
        dir.path(),
        /*enable_codex_api_key_env*/ false,
        AuthCredentialsStoreMode::File,
        /*allowed_login_methods*/ None,
        /*forced_chatgpt_workspace_id*/ None,
        /*chatgpt_base_url*/ None,
        AuthKeyringBackendKind::Direct,
        /*agent_identity_authapi_base_url*/ None,
        &crate::test_support::transport_default_auth_route_config(),
    )
    .await
    .unwrap()
    .unwrap();
    assert_eq!(auth.auth_mode(), AuthMode::ApiKey);
    assert_eq!(auth.api_key(), Some("sk-test-key"));

    assert!(auth.get_token_data().is_err());
}

#[test]
fn logout_removes_auth_file() -> Result<(), std::io::Error> {
    let dir = tempdir()?;
    let auth_dot_json = AuthDotJson {
        auth_mode: Some(AuthMode::ApiKey),
        openai_api_key: Some("sk-test-key".to_string()),
        tokens: None,
        last_refresh: None,
        agent_identity: None,
        personal_access_token: None,
        bedrock_api_key: None,
        managed_chatgpt: None,
    };
    super::save_auth(
        dir.path(),
        &auth_dot_json,
        AuthCredentialsStoreMode::File,
        AuthKeyringBackendKind::default(),
    )?;
    let auth_file = get_auth_file(dir.path());
    assert!(auth_file.exists());
    assert!(logout(
        dir.path(),
        AuthCredentialsStoreMode::File,
        AuthKeyringBackendKind::default(),
    )?);
    assert!(!auth_file.exists());
    Ok(())
}

#[tokio::test]
#[serial(codex_auth_env)]
async fn unauthorized_recovery_reports_mode_and_step_names() {
    let dir = tempdir().unwrap();
    let manager = AuthManager::shared(
        dir.path().to_path_buf(),
        /*enable_codex_api_key_env*/ false,
        AuthCredentialsStoreMode::File,
        /*forced_chatgpt_workspace_id*/ None,
        /*chatgpt_base_url*/ None,
        AuthKeyringBackendKind::default(),
        crate::test_support::transport_default_auth_route_config(),
    )
    .await;
    let managed = UnauthorizedRecovery {
        manager: Arc::clone(&manager),
        step: UnauthorizedRecoveryStep::Reload,
        expected_account_id: None,
        mode: UnauthorizedRecoveryMode::Managed,
        managed_identity_key: None,
        managed_account_revision: None,
    };
    assert_eq!(managed.mode_name(), "managed");
    assert_eq!(managed.step_name(), "reload");

    let external = UnauthorizedRecovery {
        manager,
        step: UnauthorizedRecoveryStep::ExternalRefresh,
        expected_account_id: None,
        mode: UnauthorizedRecoveryMode::External,
        managed_identity_key: None,
        managed_account_revision: None,
    };
    assert_eq!(external.mode_name(), "external");
    assert_eq!(external.step_name(), "external_refresh");
}

#[tokio::test]
#[serial(codex_auth_env)]
async fn refresh_failure_is_scoped_to_the_matching_auth_snapshot() {
    let codex_home = tempdir().unwrap();
    let _access_token_guard = remove_access_token_env_var();
    write_auth_file(
        AuthFileParams {
            openai_api_key: None,
            chatgpt_plan_type: Some("pro".to_string()),
            chatgpt_account_id: Some(WORKSPACE_ID_ALLOWED.to_string()),
        },
        codex_home.path(),
    )
    .expect("failed to write auth file");

    let auth = super::load_auth(
        codex_home.path(),
        /*enable_codex_api_key_env*/ false,
        AuthCredentialsStoreMode::File,
        /*allowed_login_methods*/ None,
        /*forced_chatgpt_workspace_id*/ None,
        /*chatgpt_base_url*/ None,
        AuthKeyringBackendKind::Direct,
        /*agent_identity_authapi_base_url*/ None,
        &crate::test_support::transport_default_auth_route_config(),
    )
    .await
    .expect("load auth")
    .expect("auth available");
    let mut updated_auth_dot_json = auth
        .get_current_auth_json()
        .expect("AuthDotJson should exist");
    let updated_tokens = updated_auth_dot_json
        .tokens
        .as_mut()
        .expect("tokens should exist");
    updated_tokens.access_token = "new-access-token".to_string();
    updated_tokens.refresh_token = "new-refresh-token".to_string();
    let updated_auth = CodexAuth::from_auth_dot_json(
        codex_home.path(),
        updated_auth_dot_json,
        AuthCredentialsStoreMode::File,
        /*forced_chatgpt_workspace_id*/ None,
        /*chatgpt_base_url*/ None,
        AuthKeyringBackendKind::Direct,
        /*agent_identity_authapi_base_url*/ None,
        &crate::test_support::transport_default_auth_route_config(),
    )
    .await
    .expect("updated auth should parse");

    let manager = AuthManager::from_auth_for_testing(auth.clone());
    let error = RefreshTokenFailedError::new(
        RefreshTokenFailedReason::Exhausted,
        "refresh token already used",
    );
    manager.record_permanent_refresh_failure_if_unchanged(&auth, &error);

    assert_eq!(manager.refresh_failure_for_auth(&auth), Some(error));
    assert_eq!(manager.refresh_failure_for_auth(&updated_auth), None);
}

#[tokio::test]
async fn external_bearer_only_auth_manager_uses_cached_provider_token() {
    let script = ProviderAuthScript::new(&["provider-token", "next-token"]).unwrap();
    let manager = AuthManager::external_bearer_only(script.auth_config());

    let first = manager
        .auth()
        .await
        .and_then(|auth| auth.api_key().map(str::to_string));
    let second = manager
        .auth()
        .await
        .and_then(|auth| auth.api_key().map(str::to_string));

    assert_eq!(first.as_deref(), Some("provider-token"));
    assert_eq!(second.as_deref(), Some("provider-token"));
    assert_eq!(manager.auth_mode(), Some(AuthMode::ApiKey));
    assert_eq!(manager.get_api_auth_mode(), Some(AuthMode::ApiKey));
}

#[tokio::test]
async fn external_bearer_only_auth_manager_disables_auto_refresh_when_interval_is_zero() {
    let script = ProviderAuthScript::new(&["provider-token", "next-token"]).unwrap();
    let mut auth_config = script.auth_config();
    auth_config.refresh_interval_ms = 0;
    let manager = AuthManager::external_bearer_only(auth_config);

    let first = manager
        .auth()
        .await
        .and_then(|auth| auth.api_key().map(str::to_string));
    let second = manager
        .auth()
        .await
        .and_then(|auth| auth.api_key().map(str::to_string));

    assert_eq!(first.as_deref(), Some("provider-token"));
    assert_eq!(second.as_deref(), Some("provider-token"));
}

#[tokio::test]
async fn external_bearer_only_auth_manager_returns_none_when_command_fails() {
    let script = ProviderAuthScript::new_failing().unwrap();
    let manager = AuthManager::external_bearer_only(script.auth_config());

    assert_eq!(manager.auth().await, None);
}

#[tokio::test]
async fn unauthorized_recovery_uses_external_refresh_for_bearer_manager() {
    let script = ProviderAuthScript::new(&["provider-token", "refreshed-provider-token"]).unwrap();
    let mut auth_config = script.auth_config();
    auth_config.refresh_interval_ms = 0;
    let manager = AuthManager::external_bearer_only(auth_config);
    let mut recovery = manager.unauthorized_recovery();
    let initial_token = manager
        .auth()
        .await
        .and_then(|auth| auth.api_key().map(str::to_string));

    assert!(recovery.has_next());
    assert_eq!(recovery.mode_name(), "external");
    assert_eq!(recovery.step_name(), "external_refresh");

    let result = recovery
        .next()
        .await
        .expect("external refresh should succeed");

    assert_eq!(result.auth_state_changed(), Some(true));
    let refreshed_token = manager
        .auth()
        .await
        .and_then(|auth| auth.api_key().map(str::to_string));
    assert_eq!(initial_token.as_deref(), Some("provider-token"));
    assert_eq!(refreshed_token.as_deref(), Some("refreshed-provider-token"));
}

#[derive(Clone)]
struct StaticExternalAuth(CodexAuth);

impl ExternalAuth for StaticExternalAuth {
    fn resolve(&self) -> ExternalAuthFuture<'_, CodexAuth> {
        Box::pin(async { Ok(self.0.clone()) })
    }

    fn refresh(&self, _context: ExternalAuthRefreshContext) -> ExternalAuthFuture<'_, CodexAuth> {
        Box::pin(async { Ok(self.0.clone()) })
    }
}

#[tokio::test]
async fn external_auth_provider_can_install_headers() {
    let mut headers = http::HeaderMap::new();
    headers.insert(
        http::header::AUTHORIZATION,
        http::HeaderValue::from_static("Bearer external"),
    );
    headers.insert("x-external-auth", http::HeaderValue::from_static("enabled"));
    let auth = CodexAuth::Headers(AuthHeaders::new(headers));
    let codex_home = tempdir().expect("tempdir");
    let manager = AuthManager::new(
        codex_home.path().to_path_buf(),
        /*enable_codex_api_key_env*/ false,
        AuthCredentialsStoreMode::Ephemeral,
        /*forced_chatgpt_workspace_id*/ None,
        /*chatgpt_base_url*/ None,
        AuthKeyringBackendKind::default(),
        crate::test_support::transport_default_auth_route_config(),
    )
    .await;

    manager
        .set_external_auth(Arc::new(StaticExternalAuth(auth.clone())))
        .await
        .expect("external auth should install");

    assert_eq!(manager.auth_cached(), Some(auth));
    assert!(
        manager
            .auth_cached()
            .is_some_and(|auth| auth.uses_codex_backend())
    );
    assert!(
        !manager
            .auth_cached()
            .is_some_and(|auth| auth.is_chatgpt_auth())
    );
}

struct ProviderAuthScript {
    tempdir: TempDir,
    command: String,
    args: Vec<String>,
}

impl ProviderAuthScript {
    fn new(tokens: &[&str]) -> std::io::Result<Self> {
        let tempdir = tempfile::tempdir()?;
        let token_file = tempdir.path().join("tokens.txt");
        // `cmd.exe`'s `set /p` treats LF-only input as one line, so use CRLF on Windows.
        let token_line_ending = if cfg!(windows) { "\r\n" } else { "\n" };
        let mut token_file_contents = String::new();
        for token in tokens {
            token_file_contents.push_str(token);
            token_file_contents.push_str(token_line_ending);
        }
        std::fs::write(&token_file, token_file_contents)?;

        #[cfg(unix)]
        let (command, args) = {
            let script_path = tempdir.path().join("print-token.sh");
            std::fs::write(
                &script_path,
                r#"#!/bin/sh
first_line=$(sed -n '1p' tokens.txt)
printf '%s\n' "$first_line"
tail -n +2 tokens.txt > tokens.next
mv tokens.next tokens.txt
"#,
            )?;
            let mut permissions = std::fs::metadata(&script_path)?.permissions();
            {
                use std::os::unix::fs::PermissionsExt;
                permissions.set_mode(0o755);
            }
            std::fs::set_permissions(&script_path, permissions)?;
            ("./print-token.sh".to_string(), Vec::new())
        };

        #[cfg(windows)]
        let (command, args) = {
            let script_path = tempdir.path().join("print-token.cmd");
            std::fs::write(
                &script_path,
                r#"@echo off
setlocal EnableExtensions DisableDelayedExpansion
set "first_line="
<tokens.txt set /p "first_line="
if not defined first_line exit /b 1
setlocal EnableDelayedExpansion
echo(!first_line!
endlocal
more +1 tokens.txt > tokens.next
move /y tokens.next tokens.txt >nul
"#,
            )?;
            (
                "cmd.exe".to_string(),
                vec![
                    "/d".to_string(),
                    "/s".to_string(),
                    "/c".to_string(),
                    ".\\print-token.cmd".to_string(),
                ],
            )
        };

        Ok(Self {
            tempdir,
            command,
            args,
        })
    }

    fn new_failing() -> std::io::Result<Self> {
        let tempdir = tempfile::tempdir()?;

        #[cfg(unix)]
        let (command, args) = {
            let script_path = tempdir.path().join("fail.sh");
            std::fs::write(
                &script_path,
                r#"#!/bin/sh
exit 1
"#,
            )?;
            let mut permissions = std::fs::metadata(&script_path)?.permissions();
            {
                use std::os::unix::fs::PermissionsExt;
                permissions.set_mode(0o755);
            }
            std::fs::set_permissions(&script_path, permissions)?;
            ("./fail.sh".to_string(), Vec::new())
        };

        #[cfg(windows)]
        let (command, args) = (
            "cmd.exe".to_string(),
            vec![
                "/d".to_string(),
                "/s".to_string(),
                "/c".to_string(),
                "exit /b 1".to_string(),
            ],
        );

        Ok(Self {
            tempdir,
            command,
            args,
        })
    }

    fn auth_config(&self) -> ModelProviderAuthInfo {
        serde_json::from_value(json!({
            "command": self.command,
            "args": self.args,
            // Process startup can be slow on loaded Windows CI workers, so leave enough slack to
            // avoid turning these auth-cache assertions into a process-launch timing test.
            "timeout_ms": 10_000,
            "refresh_interval_ms": 60000,
            "cwd": self.tempdir.path(),
        }))
        .expect("provider auth config should deserialize")
    }
}

struct AuthFileParams {
    openai_api_key: Option<String>,
    chatgpt_plan_type: Option<String>,
    chatgpt_account_id: Option<String>,
}

fn write_auth_file(params: AuthFileParams, codex_home: &Path) -> std::io::Result<String> {
    let fake_jwt = fake_jwt_for_auth_file_params(&params)?;
    let auth_file = get_auth_file(codex_home);
    let auth_json_data = json!({
        "OPENAI_API_KEY": params.openai_api_key,
        "tokens": {
            "id_token": fake_jwt,
            "access_token": "test-access-token",
            "refresh_token": "test-refresh-token"
        },
        "last_refresh": Utc::now(),
    });
    let auth_json = serde_json::to_string_pretty(&auth_json_data)?;
    std::fs::write(auth_file, auth_json)?;
    Ok(fake_jwt)
}

fn fake_jwt_for_auth_file_params(params: &AuthFileParams) -> std::io::Result<String> {
    #[derive(Serialize)]
    struct Header {
        alg: &'static str,
        typ: &'static str,
    }

    let header = Header {
        alg: "none",
        typ: "JWT",
    };
    let mut auth_payload = serde_json::json!({
        "chatgpt_user_id": "user-12345",
        "user_id": "user-12345",
    });

    if let Some(chatgpt_plan_type) = params.chatgpt_plan_type.as_ref() {
        auth_payload["chatgpt_plan_type"] = serde_json::Value::String(chatgpt_plan_type.clone());
    }

    if let Some(chatgpt_account_id) = params.chatgpt_account_id.as_ref() {
        auth_payload["chatgpt_account_id"] = serde_json::Value::String(chatgpt_account_id.clone());
    }

    let payload = serde_json::json!({
        "email": "user@example.com",
        "email_verified": true,
        "https://api.openai.com/auth": auth_payload,
    });
    let b64 = |b: &[u8]| base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(b);
    let header_b64 = b64(&serde_json::to_vec(&header)?);
    let payload_b64 = b64(&serde_json::to_vec(&payload)?);
    let signature_b64 = b64(b"sig");
    Ok(format!("{header_b64}.{payload_b64}.{signature_b64}"))
}

async fn build_config(
    codex_home: &Path,
    forced_login_method: Option<ForcedLoginMethod>,
    forced_chatgpt_workspace_id: Option<Vec<String>>,
) -> AuthConfig {
    AuthConfig {
        codex_home: codex_home.to_path_buf(),
        auth_credentials_store_mode: AuthCredentialsStoreMode::File,
        keyring_backend_kind: AuthKeyringBackendKind::Direct,
        forced_login_method,
        forced_chatgpt_workspace_id,
        managed_auth_policy: ManagedAuthPolicy::default(),
        chatgpt_base_url: None,
        auth_route_config: crate::test_support::transport_default_auth_route_config(),
    }
}

/// Use sparingly.
/// TODO (gpeal): replace this with an injectable env var provider.
#[cfg(test)]
struct EnvVarGuard {
    key: &'static str,
    original: Option<std::ffi::OsString>,
}

#[cfg(test)]
impl EnvVarGuard {
    fn set(key: &'static str, value: &str) -> Self {
        let original = env::var_os(key);
        unsafe {
            env::set_var(key, value);
        }
        Self { key, original }
    }

    fn remove(key: &'static str) -> Self {
        let original = env::var_os(key);
        unsafe {
            env::remove_var(key);
        }
        Self { key, original }
    }
}

#[cfg(test)]
impl Drop for EnvVarGuard {
    fn drop(&mut self) {
        unsafe {
            match &self.original {
                Some(value) => env::set_var(self.key, value),
                None => env::remove_var(self.key),
            }
        }
    }
}

fn remove_access_token_env_var() -> EnvVarGuard {
    EnvVarGuard::remove(CODEX_ACCESS_TOKEN_ENV_VAR)
}

#[tokio::test]
#[serial(codex_auth_env)]
async fn load_auth_reads_access_token_from_env() {
    let codex_home = tempdir().unwrap();
    let mut expected_record = agent_identity_record(WORKSPACE_ID_ALLOWED);
    let agent_identity =
        signed_agent_identity_jwt(&expected_record, json!(expected_record.plan_type))
            .expect("signed agent identity");
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/backend-api/wham/agent-identities/jwks"))
        .respond_with(ResponseTemplate::new(200).set_body_json(test_jwks_body()))
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/v1/agent/agent-runtime-id/task/register"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "task_id": "task-123",
        })))
        .expect(1)
        .mount(&server)
        .await;
    expected_record.task_id = Some("task-123".to_string());
    let _access_token_guard = EnvVarGuard::set(CODEX_ACCESS_TOKEN_ENV_VAR, &agent_identity);

    let authapi_base_url = server.uri();
    let chatgpt_base_url = format!("{authapi_base_url}/backend-api");
    let auth = super::load_auth(
        codex_home.path(),
        /*enable_codex_api_key_env*/ false,
        AuthCredentialsStoreMode::File,
        /*allowed_login_methods*/ None,
        /*forced_chatgpt_workspace_id*/ None,
        Some(&chatgpt_base_url),
        AuthKeyringBackendKind::Direct,
        Some(&authapi_base_url),
        &crate::test_support::transport_default_auth_route_config(),
    )
    .await
    .expect("env auth should load")
    .expect("env auth should be present");

    let CodexAuth::AgentIdentity(agent_identity) = auth else {
        panic!("env auth should load as agent identity");
    };
    assert_eq!(agent_identity.record(), &expected_record);
    assert_eq!(agent_identity.run_task_id(), "task-123");
    assert!(
        !get_auth_file(codex_home.path()).exists(),
        "env auth should not write auth.json"
    );
    server.verify().await;
}

#[tokio::test]
#[serial(codex_auth_env)]
async fn load_auth_reads_personal_access_token_from_env() {
    let codex_home = tempdir().unwrap();
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/v1/user-auth-credential/whoami"))
        .and(header("authorization", "Bearer at-env-test"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(personal_access_token_whoami(WORKSPACE_ID_ALLOWED)),
        )
        .expect(2)
        .mount(&server)
        .await;
    let _authapi_guard = EnvVarGuard::set("CODEX_AUTHAPI_BASE_URL", &server.uri());
    let _access_token_guard = EnvVarGuard::set(CODEX_ACCESS_TOKEN_ENV_VAR, "at-env-test");

    for auth_credentials_store_mode in [
        AuthCredentialsStoreMode::File,
        AuthCredentialsStoreMode::Ephemeral,
    ] {
        let auth = super::load_auth(
            codex_home.path(),
            /*enable_codex_api_key_env*/ false,
            auth_credentials_store_mode,
            /*allowed_login_methods*/ None,
            /*forced_chatgpt_workspace_id*/ None,
            /*chatgpt_base_url*/ None,
            AuthKeyringBackendKind::default(),
            /*agent_identity_authapi_base_url*/ None,
            &crate::test_support::transport_default_auth_route_config(),
        )
        .await
        .expect("env auth should load")
        .expect("env auth should be present");

        assert_eq!(auth.api_auth_mode(), AuthMode::PersonalAccessToken);
        assert_eq!(
            auth.get_token()
                .expect("personal access token should be exposed"),
            "at-env-test"
        );
        assert_eq!(auth.get_account_id().as_deref(), Some(WORKSPACE_ID_ALLOWED));
        assert_eq!(auth.get_chatgpt_user_id().as_deref(), Some("user-123"));
        assert_eq!(
            auth.get_account_email().as_deref(),
            Some("user@example.com")
        );
        assert_eq!(auth.account_plan_type(), Some(AccountPlanType::Business));
        assert!(auth.is_fedramp_account());
    }
    assert!(
        !get_auth_file(codex_home.path()).exists(),
        "env auth should not write auth.json"
    );
    server.verify().await;
}

#[tokio::test]
#[serial(codex_auth_env)]
async fn auth_manager_rejects_env_personal_access_token_workspace_mismatch() {
    let codex_home = tempdir().unwrap();
    let _clean_access_token = remove_access_token_env_var();
    let stored_manager = file_pool_manager(codex_home.path()).await;
    stored_manager
        .upsert_managed_chatgpt_oauth(managed_oauth_credentials(
            "stored@example.com",
            WORKSPACE_ID_ALLOWED,
            "stored-refresh",
        ))
        .await
        .expect("stored managed pool");
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/v1/user-auth-credential/whoami"))
        .and(header("authorization", "Bearer at-env-workspace-mismatch"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(personal_access_token_whoami(WORKSPACE_ID_DISALLOWED)),
        )
        .expect(1)
        .mount(&server)
        .await;
    let _authapi_guard = EnvVarGuard::set("CODEX_AUTHAPI_BASE_URL", &server.uri());
    let _access_token_guard =
        EnvVarGuard::set(CODEX_ACCESS_TOKEN_ENV_VAR, "at-env-workspace-mismatch");

    let manager = AuthManager::new(
        codex_home.path().to_path_buf(),
        /*enable_codex_api_key_env*/ false,
        AuthCredentialsStoreMode::File,
        Some(vec![WORKSPACE_ID_ALLOWED.to_string()]),
        /*chatgpt_base_url*/ None,
        AuthKeyringBackendKind::default(),
        crate::test_support::transport_default_auth_route_config(),
    )
    .await;

    assert_eq!(manager.auth().await, None);
    let error = manager
        .auth_cached_result()
        .expect_err("higher-precedence env policy failure must remain observable");
    assert!(!error.is_empty());
    server.verify().await;
}

#[tokio::test]
#[serial(codex_auth_env)]
async fn auth_manager_rejects_stored_personal_access_token_workspace_mismatch() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/v1/user-auth-credential/whoami"))
        .and(header(
            "authorization",
            "Bearer at-stored-workspace-mismatch",
        ))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(personal_access_token_whoami(WORKSPACE_ID_DISALLOWED)),
        )
        .expect(4)
        .mount(&server)
        .await;
    let _authapi_guard = EnvVarGuard::set("CODEX_AUTHAPI_BASE_URL", &server.uri());
    let _access_token_guard = remove_access_token_env_var();

    for auth_credentials_store_mode in [
        AuthCredentialsStoreMode::File,
        AuthCredentialsStoreMode::Ephemeral,
    ] {
        let codex_home = tempdir().unwrap();
        super::login_with_access_token(
            codex_home.path(),
            "at-stored-workspace-mismatch",
            auth_credentials_store_mode,
            /*forced_chatgpt_workspace_id*/ None,
            /*chatgpt_base_url*/ None,
            AuthKeyringBackendKind::default(),
            &crate::test_support::transport_default_auth_route_config(),
        )
        .await
        .expect("personal access token login should succeed");

        let manager = AuthManager::new(
            codex_home.path().to_path_buf(),
            /*enable_codex_api_key_env*/ false,
            auth_credentials_store_mode,
            Some(vec![WORKSPACE_ID_ALLOWED.to_string()]),
            /*chatgpt_base_url*/ None,
            AuthKeyringBackendKind::default(),
            crate::test_support::transport_default_auth_route_config(),
        )
        .await;

        assert_eq!(manager.auth().await, None);
    }
    server.verify().await;
}

#[tokio::test]
#[serial(codex_auth_env)]
async fn personal_access_token_does_not_offer_unauthorized_recovery() {
    let codex_home = tempdir().unwrap();
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/v1/user-auth-credential/whoami"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(personal_access_token_whoami(WORKSPACE_ID_ALLOWED)),
        )
        .expect(1)
        .mount(&server)
        .await;
    let _authapi_guard = EnvVarGuard::set("CODEX_AUTHAPI_BASE_URL", &server.uri());
    let _access_token_guard =
        EnvVarGuard::set(CODEX_ACCESS_TOKEN_ENV_VAR, "at-no-unauthorized-recovery");
    let manager = Arc::new(
        AuthManager::new(
            codex_home.path().to_path_buf(),
            /*enable_codex_api_key_env*/ false,
            AuthCredentialsStoreMode::File,
            /*forced_chatgpt_workspace_id*/ None,
            /*chatgpt_base_url*/ None,
            AuthKeyringBackendKind::default(),
            crate::test_support::transport_default_auth_route_config(),
        )
        .await,
    );

    let recovery = manager.unauthorized_recovery();

    assert!(!recovery.has_next());
    assert_eq!(recovery.unavailable_reason(), "not_refreshable_auth");
    manager
        .refresh_token_from_authority()
        .await
        .expect("personal access tokens do not use OAuth refresh");
    server.verify().await;
}

#[tokio::test]
#[serial(codex_auth_env)]
async fn load_auth_keeps_codex_api_key_env_precedence() {
    let codex_home = tempdir().unwrap();
    let record = agent_identity_record(WORKSPACE_ID_ALLOWED);
    let agent_identity = fake_agent_identity_jwt(&record).expect("fake agent identity");
    let _access_token_guard = EnvVarGuard::set(CODEX_ACCESS_TOKEN_ENV_VAR, &agent_identity);
    let _api_key_guard = EnvVarGuard::set(CODEX_API_KEY_ENV_VAR, "sk-env");

    let auth = super::load_auth(
        codex_home.path(),
        /*enable_codex_api_key_env*/ true,
        AuthCredentialsStoreMode::File,
        /*allowed_login_methods*/ None,
        /*forced_chatgpt_workspace_id*/ None,
        /*chatgpt_base_url*/ None,
        AuthKeyringBackendKind::Direct,
        /*agent_identity_authapi_base_url*/ None,
        &crate::test_support::transport_default_auth_route_config(),
    )
    .await
    .expect("env auth should load")
    .expect("env auth should be present");

    assert_eq!(auth.api_key(), Some("sk-env"));
}

#[tokio::test]
#[serial(codex_auth_env)]
async fn enforce_login_restrictions_logs_out_for_method_mismatch() {
    let codex_home = tempdir().unwrap();
    let _access_token_guard = remove_access_token_env_var();
    login_with_api_key(
        codex_home.path(),
        "sk-test",
        AuthCredentialsStoreMode::File,
        AuthKeyringBackendKind::default(),
    )
    .expect("seed api key");

    let config = build_config(
        codex_home.path(),
        Some(ForcedLoginMethod::Chatgpt),
        /*forced_chatgpt_workspace_id*/ None,
    )
    .await;

    let err = super::enforce_login_restrictions(&config)
        .await
        .expect_err("expected method mismatch to error");
    assert!(err.to_string().contains("ChatGPT login is required"));
    assert!(
        !codex_home.path().join("auth.json").exists(),
        "auth.json should be removed on mismatch"
    );
}

#[tokio::test]
#[serial(codex_auth_env)]
async fn forced_login_restriction_clears_external_overlay_and_multi_account_file_store() {
    let codex_home = tempdir().expect("tempdir");
    let _access_token_guard = remove_access_token_env_var();
    let manager = file_pool_manager(codex_home.path()).await;
    for (email, workspace, refresh) in [
        ("a@example.com", "workspace-a", "refresh-a"),
        ("b@example.com", "workspace-b", "refresh-b"),
    ] {
        manager
            .upsert_managed_chatgpt_oauth(managed_oauth_credentials(email, workspace, refresh))
            .await
            .expect("managed login");
    }
    login_with_chatgpt_auth_tokens(
        codex_home.path(),
        &managed_id_token("external@example.com", "external-workspace"),
        "external-workspace",
        Some("pro"),
    )
    .expect("external overlay");
    let config = build_config(
        codex_home.path(),
        Some(ForcedLoginMethod::Api),
        /*forced_chatgpt_workspace_id*/ None,
    )
    .await;

    super::enforce_login_restrictions(&config)
        .await
        .expect_err("forced API login should reject ChatGPT auth");

    assert!(
        load_external_chatgpt_auth(codex_home.path())
            .expect("load external auth")
            .is_none()
    );
    assert!(
        load_auth_dot_json(
            codex_home.path(),
            AuthCredentialsStoreMode::File,
            AuthKeyringBackendKind::Direct,
        )
        .expect("load file auth")
        .is_none()
    );
}

#[tokio::test]
#[serial(codex_auth_env)]
async fn forced_login_restriction_removes_malformed_configured_store() {
    let codex_home = tempdir().expect("tempdir");
    let _access_token_guard = remove_access_token_env_var();
    std::fs::write(codex_home.path().join("auth.json"), b"{not-json")
        .expect("write malformed configured auth");
    login_with_chatgpt_auth_tokens(
        codex_home.path(),
        &managed_id_token("external@example.com", "external-workspace"),
        "external-workspace",
        Some("pro"),
    )
    .expect("external overlay");
    let config = build_config(
        codex_home.path(),
        Some(ForcedLoginMethod::Api),
        /*forced_chatgpt_workspace_id*/ None,
    )
    .await;

    super::enforce_login_restrictions(&config)
        .await
        .expect_err("forced API login should reject ChatGPT auth");

    assert!(!codex_home.path().join("auth.json").exists());
    assert!(
        load_external_chatgpt_auth(codex_home.path())
            .expect("load external auth")
            .is_none()
    );
}

#[tokio::test]
#[serial(codex_auth_env)]
async fn forced_login_restriction_clears_external_overlay_and_ephemeral_pool() {
    let codex_home = tempdir().expect("tempdir");
    let _access_token_guard = remove_access_token_env_var();
    let manager = AuthManager::shared(
        codex_home.path().to_path_buf(),
        false,
        AuthCredentialsStoreMode::Ephemeral,
        None,
        None,
        AuthKeyringBackendKind::default(),
        crate::test_support::transport_default_auth_route_config(),
    )
    .await;
    manager
        .upsert_managed_chatgpt_oauth(managed_oauth_credentials(
            "a@example.com",
            "workspace-a",
            "refresh-a",
        ))
        .await
        .expect("managed login");
    login_with_chatgpt_auth_tokens(
        codex_home.path(),
        &managed_id_token("external@example.com", "external-workspace"),
        "external-workspace",
        Some("pro"),
    )
    .expect("external overlay");
    let config = AuthConfig {
        codex_home: codex_home.path().to_path_buf(),
        auth_credentials_store_mode: AuthCredentialsStoreMode::Ephemeral,
        keyring_backend_kind: AuthKeyringBackendKind::default(),
        forced_login_method: Some(ForcedLoginMethod::Api),
        forced_chatgpt_workspace_id: None,
        chatgpt_base_url: None,
        auth_route_config: crate::test_support::transport_default_auth_route_config(),
    };

    super::enforce_login_restrictions(&config)
        .await
        .expect_err("forced API login should reject ChatGPT auth");

    assert!(
        load_external_chatgpt_auth(codex_home.path())
            .expect("load external auth")
            .is_none()
    );
    assert!(
        load_auth_dot_json(
            codex_home.path(),
            AuthCredentialsStoreMode::Ephemeral,
            AuthKeyringBackendKind::default(),
        )
        .expect("load ephemeral auth")
        .is_none()
    );
}

#[tokio::test]
#[serial(codex_auth_env)]
async fn enforce_login_restrictions_logs_out_for_workspace_mismatch() {
    let codex_home = tempdir().unwrap();
    let _access_token_guard = remove_access_token_env_var();
    let _jwt = write_auth_file(
        AuthFileParams {
            openai_api_key: None,
            chatgpt_plan_type: Some("pro".to_string()),
            chatgpt_account_id: Some(WORKSPACE_ID_DISALLOWED.to_string()),
        },
        codex_home.path(),
    )
    .expect("failed to write auth file");

    let config = build_config(
        codex_home.path(),
        /*forced_login_method*/ None,
        Some(vec![WORKSPACE_ID_ALLOWED.to_string()]),
    )
    .await;

    let err = super::enforce_login_restrictions(&config)
        .await
        .expect_err("expected workspace mismatch to error");
    assert!(
        err.to_string()
            .contains(&format!("workspace(s) {WORKSPACE_ID_ALLOWED}"))
    );
    assert!(
        !codex_home.path().join("auth.json").exists(),
        "auth.json should be removed on mismatch"
    );
}

#[tokio::test]
#[serial(codex_auth_env)]
async fn enforce_login_restrictions_logs_out_for_personal_access_token_workspace_mismatch() {
    let codex_home = tempdir().unwrap();
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/v1/user-auth-credential/whoami"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(personal_access_token_whoami(WORKSPACE_ID_DISALLOWED)),
        )
        .expect(2)
        .mount(&server)
        .await;
    let _access_token_guard = remove_access_token_env_var();
    let _authapi_guard = EnvVarGuard::set("CODEX_AUTHAPI_BASE_URL", &server.uri());
    super::login_with_access_token(
        codex_home.path(),
        "at-workspace-mismatch",
        AuthCredentialsStoreMode::File,
        /*forced_chatgpt_workspace_id*/ None,
        /*chatgpt_base_url*/ None,
        AuthKeyringBackendKind::default(),
        &crate::test_support::transport_default_auth_route_config(),
    )
    .await
    .expect("personal access token login should succeed");

    let config = AuthConfig {
        codex_home: codex_home.path().to_path_buf(),
        auth_credentials_store_mode: AuthCredentialsStoreMode::File,
        keyring_backend_kind: AuthKeyringBackendKind::default(),
        forced_login_method: None,
        forced_chatgpt_workspace_id: Some(vec![WORKSPACE_ID_ALLOWED.to_string()]),
        managed_auth_policy: ManagedAuthPolicy::default(),
        chatgpt_base_url: None,
        auth_route_config: crate::test_support::transport_default_auth_route_config(),
    };

    let err = super::enforce_login_restrictions(&config)
        .await
        .expect_err("expected workspace mismatch to error");
    assert!(err.to_string().contains(&format!(
        "current credentials belong to {WORKSPACE_ID_DISALLOWED}"
    )));
    assert!(
        !codex_home.path().join("auth.json").exists(),
        "auth.json should be removed on mismatch"
    );
    server.verify().await;
}

#[tokio::test]
#[serial(codex_auth_env)]
async fn enforce_login_restrictions_allows_matching_workspace() {
    let codex_home = tempdir().unwrap();
    let _access_token_guard = remove_access_token_env_var();
    let _jwt = write_auth_file(
        AuthFileParams {
            openai_api_key: None,
            chatgpt_plan_type: Some("pro".to_string()),
            chatgpt_account_id: Some(WORKSPACE_ID_ALLOWED.to_string()),
        },
        codex_home.path(),
    )
    .expect("failed to write auth file");

    let config = build_config(
        codex_home.path(),
        /*forced_login_method*/ None,
        Some(vec![WORKSPACE_ID_ALLOWED.to_string()]),
    )
    .await;

    super::enforce_login_restrictions(&config)
        .await
        .expect("matching workspace should succeed");
    assert!(
        codex_home.path().join("auth.json").exists(),
        "auth.json should remain when restrictions pass"
    );
}

#[tokio::test]
#[serial(codex_auth_env)]
async fn enforce_login_restrictions_allows_any_matching_workspace_in_list() {
    let codex_home = tempdir().unwrap();
    let _jwt = write_auth_file(
        AuthFileParams {
            openai_api_key: None,
            chatgpt_plan_type: Some("pro".to_string()),
            chatgpt_account_id: Some(WORKSPACE_ID_ALLOWED.to_string()),
        },
        codex_home.path(),
    )
    .expect("failed to write auth file");

    let config = build_config(
        codex_home.path(),
        /*forced_login_method*/ None,
        Some(vec![
            WORKSPACE_ID_SECOND_ALLOWED.to_string(),
            WORKSPACE_ID_ALLOWED.to_string(),
        ]),
    )
    .await;

    super::enforce_login_restrictions(&config)
        .await
        .expect("any matching workspace in the allowed list should succeed");
}

#[tokio::test]
#[serial(codex_auth_env)]
async fn enforce_login_restrictions_logs_out_for_agent_identity_workspace_mismatch() {
    let codex_home = tempdir().unwrap();
    let _access_token_guard = remove_access_token_env_var();
    let record = agent_identity_record(WORKSPACE_ID_DISALLOWED);
    let agent_identity =
        signed_agent_identity_jwt(&record, json!(record.plan_type)).expect("signed agent identity");
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/backend-api/wham/agent-identities/jwks"))
        .respond_with(ResponseTemplate::new(200).set_body_json(test_jwks_body()))
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/v1/agent/agent-runtime-id/task/register"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "task_id": "task-123",
        })))
        .expect(1)
        .mount(&server)
        .await;
    let authapi_base_url = server.uri();
    let chatgpt_base_url = format!("{authapi_base_url}/backend-api");
    save_auth(
        codex_home.path(),
        &AuthDotJson {
            auth_mode: Some(AuthMode::AgentIdentity),
            openai_api_key: None,
            tokens: None,
            last_refresh: None,
            agent_identity: Some(AgentIdentityStorage::Jwt(agent_identity)),
            personal_access_token: None,
            bedrock_api_key: None,
            managed_chatgpt: None,
        },
        AuthCredentialsStoreMode::File,
        AuthKeyringBackendKind::default(),
    )
    .expect("seed agent identity auth");

    let config = AuthConfig {
        codex_home: codex_home.path().to_path_buf(),
        auth_credentials_store_mode: AuthCredentialsStoreMode::File,
        keyring_backend_kind: AuthKeyringBackendKind::Direct,
        forced_login_method: None,
        forced_chatgpt_workspace_id: Some(vec![WORKSPACE_ID_ALLOWED.to_string()]),
        managed_auth_policy: ManagedAuthPolicy::default(),
        chatgpt_base_url: Some(chatgpt_base_url),
        auth_route_config: crate::test_support::transport_default_auth_route_config(),
    };

    let err = super::enforce_login_restrictions_with_agent_identity_authapi_base_url(
        &config,
        Some(&authapi_base_url),
    )
    .await
    .expect_err("expected workspace mismatch to error");
    let message = err.to_string();
    assert!(
        message.contains(&format!(
            "current credentials belong to {WORKSPACE_ID_DISALLOWED}"
        )),
        "{message}"
    );
    assert!(
        !codex_home.path().join("auth.json").exists(),
        "auth.json should be removed on mismatch"
    );
    server.verify().await;
}

#[tokio::test]
#[serial(codex_auth_env)]
async fn enforce_login_restrictions_allows_api_key_if_login_method_not_set_but_forced_chatgpt_workspace_id_is_set()
 {
    let codex_home = tempdir().unwrap();
    let _access_token_guard = remove_access_token_env_var();
    login_with_api_key(
        codex_home.path(),
        "sk-test",
        AuthCredentialsStoreMode::File,
        AuthKeyringBackendKind::default(),
    )
    .expect("seed api key");

    let config = build_config(
        codex_home.path(),
        /*forced_login_method*/ None,
        Some(vec![WORKSPACE_ID_ALLOWED.to_string()]),
    )
    .await;

    super::enforce_login_restrictions(&config)
        .await
        .expect("matching workspace should succeed");
    assert!(
        codex_home.path().join("auth.json").exists(),
        "auth.json should remain when restrictions pass"
    );
}

#[tokio::test]
#[serial(codex_auth_env)]
async fn enforce_login_restrictions_blocks_env_api_key_when_chatgpt_required() {
    let _guard = EnvVarGuard::set(CODEX_API_KEY_ENV_VAR, "sk-env");
    let _access_token_guard = remove_access_token_env_var();
    let codex_home = tempdir().unwrap();

    let config = build_config(
        codex_home.path(),
        Some(ForcedLoginMethod::Chatgpt),
        /*forced_chatgpt_workspace_id*/ None,
    )
    .await;

    let err = super::enforce_login_restrictions(&config)
        .await
        .expect_err("environment API key should not satisfy forced ChatGPT login");
    assert!(
        err.to_string()
            .contains("ChatGPT login is required, but an API key is currently being used.")
    );
}

fn agent_identity_record(account_id: &str) -> AgentIdentityAuthRecord {
    let key_material =
        codex_agent_identity::generate_agent_key_material().expect("generate agent key material");
    AgentIdentityAuthRecord {
        agent_runtime_id: "agent-runtime-id".to_string(),
        agent_private_key: key_material.private_key_pkcs8_base64,
        account_id: account_id.to_string(),
        chatgpt_user_id: "user-id".to_string(),
        email: Some("user@example.com".to_string()),
        plan_type: AccountPlanType::Pro,
        chatgpt_account_is_fedramp: false,
        task_id: None,
    }
}

async fn mock_agent_task_registration(
    server: &MockServer,
    path_prefix: &str,
    agent_runtime_id: &str,
    task_id: &str,
) {
    Mock::given(method("POST"))
        .and(path(format!(
            "{path_prefix}/v1/agent/{agent_runtime_id}/task/register"
        )))
        .respond_with(ResponseTemplate::new(/*s*/ 200).set_body_json(json!({
            "task_id": task_id,
        })))
        .expect(/*r*/ 1)
        .mount(server)
        .await;
}

fn fake_agent_identity_jwt(record: &AgentIdentityAuthRecord) -> std::io::Result<String> {
    fake_agent_identity_jwt_with_plan_type(record, serde_json::to_value(record.plan_type)?)
}

fn fake_agent_identity_jwt_with_plan_type(
    record: &AgentIdentityAuthRecord,
    plan_type: serde_json::Value,
) -> std::io::Result<String> {
    let encode = |bytes: &[u8]| base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes);
    let header_b64 = encode(br#"{"alg":"EdDSA","typ":"JWT"}"#);
    let payload = json!({
        "iss": "https://chatgpt.com/codex-backend/agent-identity",
        "aud": "codex-app-server",
        "iat": 1_700_000_000usize,
        "exp": 4_000_000_000usize,
        "agent_runtime_id": record.agent_runtime_id,
        "agent_private_key": record.agent_private_key,
        "account_id": record.account_id,
        "chatgpt_user_id": record.chatgpt_user_id,
        "email": record.email,
        "plan_type": plan_type,
        "chatgpt_account_is_fedramp": record.chatgpt_account_is_fedramp,
    });
    let payload_b64 = encode(&serde_json::to_vec(&payload)?);
    let signature_b64 = encode(b"sig");
    Ok(format!("{header_b64}.{payload_b64}.{signature_b64}"))
}

fn signed_agent_identity_jwt(
    record: &AgentIdentityAuthRecord,
    plan_type: serde_json::Value,
) -> jsonwebtoken::errors::Result<String> {
    let mut header = jsonwebtoken::Header::new(jsonwebtoken::Algorithm::RS256);
    header.kid = Some("test-key".to_string());
    jsonwebtoken::encode(
        &header,
        &json!({
            "iss": "https://chatgpt.com/codex-backend/agent-identity",
            "aud": "codex-app-server",
            "iat": 1_700_000_000usize,
            "exp": 4_000_000_000usize,
            "agent_runtime_id": record.agent_runtime_id,
            "agent_private_key": record.agent_private_key,
            "account_id": record.account_id,
            "chatgpt_user_id": record.chatgpt_user_id,
            "email": record.email,
            "plan_type": plan_type,
            "chatgpt_account_is_fedramp": record.chatgpt_account_is_fedramp,
        }),
        &jsonwebtoken::EncodingKey::from_rsa_pem(TEST_AGENT_IDENTITY_RSA_PRIVATE_KEY_PEM)?,
    )
}

fn test_jwks_body() -> serde_json::Value {
    json!({
        "keys": [{
            "kty": "RSA",
            "kid": "test-key",
            "use": "sig",
            "alg": "RS256",
            "n": "1qQF2MqTrGAMDm7wXbjJP5sWqGA83tAGUs2ksy7iJXLJdhCg4AtwGm4SFl4f6kxhCSzlN1QdXuZjvRT2wZZiGUi9xUE28rf4WLrTxSnwqLuTy5knMP08yC0t_0YU_FGPZMcWb14hG05IvZr8UbmRaVagxSR8H4rSIymRoVwwmFSrqz068XrWGSYNIfLEASyo5GdAaqmk1JALINHgYGQJVxMxtwcvDxoVKmC7eltUNymMNBZhsv4E8sx9YNLpBoEibznfEpDU_DGzrM5eZCsQzaqbhBOlGd427ifud_Nnd9cPqzgCUc23-0FXSPfpbgksCXAwAmD0OFjQWrgqVdKL6Q",
            "e": "AQAB",
        }]
    })
}

fn personal_access_token_whoami(account_id: &str) -> serde_json::Value {
    json!({
        "email": "user@example.com",
        "chatgpt_user_id": "user-123",
        "chatgpt_account_id": account_id,
        "chatgpt_plan_type": "business",
        "chatgpt_account_is_fedramp": true,
    })
}

const TEST_AGENT_IDENTITY_RSA_PRIVATE_KEY_PEM: &[u8] = br#"-----BEGIN PRIVATE KEY-----
MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQDWpAXYypOsYAwO
bvBduMk/mxaoYDze0AZSzaSzLuIlcsl2EKDgC3AabhIWXh/qTGEJLOU3VB1e5mO9
FPbBlmIZSL3FQTbyt/hYutPFKfCou5PLmScw/TzILS3/RhT8UY9kxxZvXiEbTki9
mvxRuZFpVqDFJHwfitIjKZGhXDCYVKurPTrxetYZJg0h8sQBLKjkZ0BqqaTUkAsg
0eBgZAlXEzG3By8PGhUqYLt6W1Q3KYw0FmGy/gTyzH1g0ukGgSJvOd8SkNT8MbOs
zl5kKxDNqpuEE6UZ3jbuJ+5382d31w+rOAJRzbf7QVdI9+luCSwJcDACYPQ4WNBa
uCpV0ovpAgMBAAECggEAVu84LwZdqYN9XpswX8VoPYrjMm9IODapWQBRpQFoNyK2
1ksF3bjEPvA2Azk8U/l7k+vLKw22l6lY3EyRZPcz5GnB8xLm3ogE3mtNOp4yCyVu
RxhQ91aaN7mU17/a4BdorLi2LYVCg3zBmYociD1Q2AluNGsCmwPu+K7tfR2J0Sg8
NjqiTbDG1XDpR/icwgC9t6vh8lZpCHDhF4tbQfLLVLeA/OdcuzXDyMCXbmdVIdBQ
rm4aIFmr2e1/2ctTbCg85S6AGFTH+pSLjrwTzyvf+F6NW5uNjLQAQLFj+EznBDxj
Xdx90cySrjsKK6PVWQF4RiTvkSW8eWL7R6B2FZbGwQKBgQDuVQRj72hWloR7mbEL
aUEEv3pIXTMXWEsoMBNczos/1L1RnAN1AI44TurznasPZAWvQj+kVbLDR+TAeZrL
iA8HIWswQUI18hFmgKzSkwIXGtubcKVrgsKeS4lMDKCM/Ef6WAYdeq6ronoY5lCN
YrJFmGp81W5zcV7lyiycgbSiGwKBgQDmjWYf6pZjrK7Z+OJ3X1AZfi2vss15SCvL
3fPgzIDbViztpGyQhc3DQZIsBNIu0xZp/veGce9TEeTds2ro9NfdJFeou8+fC7Pq
sOsM3amGFFi+ZW/9BWyjZEM88bgWWAjqLHbpfHDxjAf5CSxddqxgHlbP0Ytyb1Vg
gmPDn9YKSwKBgQDbTi3hC35WFuDHn0/zcSHcDZmnFuOZeqyFyV83yfMGhGrEuqvP
sPgtRikajJ3IZsB4WZyYSidZXEFY/0z6NjOl2xF38MTNQPbT/FmK1q1Yt2UWrlv5
BvSwlk87RG9D7C0LZo4R+D7cPoDdgqjiwMvMEIkEX5zn641oI1ZTmWKuuwKBgQCD
KF+3unnRvHRAVoFnTZbA2fJdqMeRvogD04GhGlYX8V9f1hFY6nXTJaNlXVzA/J8c
r8ra9kgjJuPfZ+ljG58OFFW2DRohLcQtuHYPfK6rMzoFHqnl9EcIcMp7ijuionR3
29HOJFgQYgxLFXfit9d6WugiE+BTupiEbckZif13HwKBgE/lAlkVHP6YahOO2Ljc
J1bwkqKZTB5dHolX9A58e/xXnfZ5P8f3Z83+Izap3FwqQulk7b1WO1MQcHuVg2NN
5da0D4h2rYOXnbYIg0BVu4spQbaM6ewsp66b8+MzLOBvj8SzWdt1Oyw0q/MRyQAR
8U4M2TSWCKUY/A6sT4W8+mT9
-----END PRIVATE KEY-----"#;

#[tokio::test]
#[serial(codex_auth_env)]
async fn agent_identity_plan_type_maps_raw_enterprise_alias() {
    assert_agent_identity_plan_alias(json!("hc"), AccountPlanType::Enterprise).await;
}

#[tokio::test]
#[serial(codex_auth_env)]
async fn agent_identity_plan_type_maps_raw_education_alias() {
    assert_agent_identity_plan_alias(json!("education"), AccountPlanType::Edu).await;
}

async fn assert_agent_identity_plan_alias(
    plan_type: serde_json::Value,
    expected_plan_type: AccountPlanType,
) {
    let record = agent_identity_record("account-id");
    let jwt = signed_agent_identity_jwt(&record, plan_type).expect("agent identity jwt");
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/backend-api/wham/agent-identities/jwks"))
        .respond_with(ResponseTemplate::new(200).set_body_json(test_jwks_body()))
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/v1/agent/agent-runtime-id/task/register"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "task_id": "task-123",
        })))
        .expect(1)
        .mount(&server)
        .await;
    let authapi_base_url = server.uri();
    let chatgpt_base_url = format!("{authapi_base_url}/backend-api");
    let auth = CodexAuth::from_agent_identity_jwt_with_authapi_base_url(
        &jwt,
        Some(&chatgpt_base_url),
        &authapi_base_url,
        &crate::test_support::transport_default_auth_route_config(),
    )
    .await
    .expect("agent identity auth");

    pretty_assertions::assert_eq!(auth.account_plan_type(), Some(expected_plan_type));
    server.verify().await;
}

#[tokio::test]
#[serial(codex_auth_env)]
async fn plan_type_maps_known_plan() {
    let codex_home = tempdir().unwrap();
    let _access_token_guard = remove_access_token_env_var();
    let _jwt = write_auth_file(
        AuthFileParams {
            openai_api_key: None,
            chatgpt_plan_type: Some("pro".to_string()),
            chatgpt_account_id: None,
        },
        codex_home.path(),
    )
    .expect("failed to write auth file");

    let auth = super::load_auth(
        codex_home.path(),
        /*enable_codex_api_key_env*/ false,
        AuthCredentialsStoreMode::File,
        /*allowed_login_methods*/ None,
        /*forced_chatgpt_workspace_id*/ None,
        /*chatgpt_base_url*/ None,
        AuthKeyringBackendKind::Direct,
        /*agent_identity_authapi_base_url*/ None,
        &crate::test_support::transport_default_auth_route_config(),
    )
    .await
    .expect("load auth")
    .expect("auth available");

    pretty_assertions::assert_eq!(auth.account_plan_type(), Some(AccountPlanType::Pro));
}

#[tokio::test]
#[serial(codex_auth_env)]
async fn plan_type_maps_self_serve_business_usage_based_plan() {
    let codex_home = tempdir().unwrap();
    let _access_token_guard = remove_access_token_env_var();
    let _jwt = write_auth_file(
        AuthFileParams {
            openai_api_key: None,
            chatgpt_plan_type: Some("self_serve_business_usage_based".to_string()),
            chatgpt_account_id: None,
        },
        codex_home.path(),
    )
    .expect("failed to write auth file");

    let auth = super::load_auth(
        codex_home.path(),
        /*enable_codex_api_key_env*/ false,
        AuthCredentialsStoreMode::File,
        /*allowed_login_methods*/ None,
        /*forced_chatgpt_workspace_id*/ None,
        /*chatgpt_base_url*/ None,
        AuthKeyringBackendKind::Direct,
        /*agent_identity_authapi_base_url*/ None,
        &crate::test_support::transport_default_auth_route_config(),
    )
    .await
    .expect("load auth")
    .expect("auth available");

    pretty_assertions::assert_eq!(
        auth.account_plan_type(),
        Some(AccountPlanType::SelfServeBusinessUsageBased)
    );
}

#[tokio::test]
#[serial(codex_auth_env)]
async fn plan_type_maps_enterprise_cbp_usage_based_plan() {
    let codex_home = tempdir().unwrap();
    let _access_token_guard = remove_access_token_env_var();
    let _jwt = write_auth_file(
        AuthFileParams {
            openai_api_key: None,
            chatgpt_plan_type: Some("enterprise_cbp_usage_based".to_string()),
            chatgpt_account_id: None,
        },
        codex_home.path(),
    )
    .expect("failed to write auth file");

    let auth = super::load_auth(
        codex_home.path(),
        /*enable_codex_api_key_env*/ false,
        AuthCredentialsStoreMode::File,
        /*allowed_login_methods*/ None,
        /*forced_chatgpt_workspace_id*/ None,
        /*chatgpt_base_url*/ None,
        AuthKeyringBackendKind::Direct,
        /*agent_identity_authapi_base_url*/ None,
        &crate::test_support::transport_default_auth_route_config(),
    )
    .await
    .expect("load auth")
    .expect("auth available");

    pretty_assertions::assert_eq!(
        auth.account_plan_type(),
        Some(AccountPlanType::EnterpriseCbpUsageBased)
    );
}

#[tokio::test]
#[serial(codex_auth_env)]
async fn plan_type_maps_unknown_to_unknown() {
    let codex_home = tempdir().unwrap();
    let _access_token_guard = remove_access_token_env_var();
    let _jwt = write_auth_file(
        AuthFileParams {
            openai_api_key: None,
            chatgpt_plan_type: Some("mystery-tier".to_string()),
            chatgpt_account_id: None,
        },
        codex_home.path(),
    )
    .expect("failed to write auth file");

    let auth = super::load_auth(
        codex_home.path(),
        /*enable_codex_api_key_env*/ false,
        AuthCredentialsStoreMode::File,
        /*allowed_login_methods*/ None,
        /*forced_chatgpt_workspace_id*/ None,
        /*chatgpt_base_url*/ None,
        AuthKeyringBackendKind::Direct,
        /*agent_identity_authapi_base_url*/ None,
        &crate::test_support::transport_default_auth_route_config(),
    )
    .await
    .expect("load auth")
    .expect("auth available");

    pretty_assertions::assert_eq!(auth.account_plan_type(), Some(AccountPlanType::Unknown));
}

#[tokio::test]
#[serial(codex_auth_env)]
async fn missing_plan_type_maps_to_unknown() {
    let codex_home = tempdir().unwrap();
    let _access_token_guard = remove_access_token_env_var();
    let _jwt = write_auth_file(
        AuthFileParams {
            openai_api_key: None,
            chatgpt_plan_type: None,
            chatgpt_account_id: None,
        },
        codex_home.path(),
    )
    .expect("failed to write auth file");

    let auth = super::load_auth(
        codex_home.path(),
        /*enable_codex_api_key_env*/ false,
        AuthCredentialsStoreMode::File,
        /*allowed_login_methods*/ None,
        /*forced_chatgpt_workspace_id*/ None,
        /*chatgpt_base_url*/ None,
        AuthKeyringBackendKind::Direct,
        /*agent_identity_authapi_base_url*/ None,
        &crate::test_support::transport_default_auth_route_config(),
    )
    .await
    .expect("load auth")
    .expect("auth available");

    pretty_assertions::assert_eq!(auth.account_plan_type(), Some(AccountPlanType::Unknown));
}

fn managed_id_token(email: &str, account_id: &str) -> String {
    managed_id_token_for_user(email, account_id, "user-12345")
}

fn managed_id_token_for_user(email: &str, account_id: &str, user_id: &str) -> String {
    let header = serde_json::json!({"alg": "none", "typ": "JWT"});
    let payload = serde_json::json!({
        "email": email,
        "email_verified": true,
        "https://api.openai.com/auth": {
            "chatgpt_user_id": user_id,
            "user_id": user_id,
            "chatgpt_account_id": account_id,
        },
    });
    let b64 = |bytes: &[u8]| base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes);
    format!(
        "{}.{}.{}",
        b64(&serde_json::to_vec(&header).expect("serialize JWT header")),
        b64(&serde_json::to_vec(&payload).expect("serialize JWT payload")),
        b64(b"sig"),
    )
}

fn managed_oauth_credentials(
    email: &str,
    account_id: &str,
    refresh_token: &str,
) -> ManagedChatgptOauthCredentials {
    ManagedChatgptOauthCredentials {
        tokens: TokenData {
            id_token: IdTokenInfo {
                email: Some(email.to_string()),
                chatgpt_account_id: Some(account_id.to_string()),
                raw_jwt: managed_id_token(email, account_id),
                ..Default::default()
            },
            access_token: format!("access-{account_id}"),
            refresh_token: refresh_token.to_string(),
            account_id: Some(account_id.to_string()),
        },
        last_refresh: Utc::now(),
        oauth_api_key: None,
    }
}

async fn file_pool_manager(codex_home: &std::path::Path) -> Arc<AuthManager> {
    AuthManager::shared(
        codex_home.to_path_buf(),
        false,
        AuthCredentialsStoreMode::File,
        None,
        None,
        AuthKeyringBackendKind::Direct,
        crate::test_support::transport_default_auth_route_config(),
    )
    .await
}

#[tokio::test]
#[serial(codex_auth_env)]
async fn agent_identity_bootstrap_cooldown_is_scoped_to_managed_identity_and_user() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/v1/agent/register"))
        .respond_with(ResponseTemplate::new(503))
        .expect(6)
        .mount(&server)
        .await;
    let codex_home = tempdir().expect("tempdir");
    let manager = file_pool_manager(codex_home.path()).await;
    let identity_a = manager
        .upsert_managed_chatgpt_oauth(managed_oauth_credentials(
            "a@example.com",
            "workspace-a",
            "refresh-a",
        ))
        .await
        .expect("login A");
    let mut credentials_b = managed_oauth_credentials("b@example.com", "workspace-b", "refresh-b");
    credentials_b.tokens.id_token = parse_chatgpt_jwt_claims(&managed_id_token_for_user(
        "b@example.com",
        "workspace-b",
        "user-b",
    ))
    .expect("parse user B token");
    let identity_b = manager
        .upsert_managed_chatgpt_oauth(credentials_b)
        .await
        .expect("login B");
    let mut stored = load_auth_dot_json(
        codex_home.path(),
        AuthCredentialsStoreMode::File,
        AuthKeyringBackendKind::Direct,
    )
    .expect("load auth")
    .expect("stored auth");
    for identity in [&identity_a, &identity_b] {
        let account = row_mut(&mut stored, identity).expect("managed account");
        account.chatgpt_account_id = Some("shared-workspace".to_string());
        account.tokens.account_id = Some("shared-workspace".to_string());
        account.tokens.id_token.chatgpt_account_id = Some("shared-workspace".to_string());
    }
    save_auth(
        codex_home.path(),
        &stored,
        AuthCredentialsStoreMode::File,
        AuthKeyringBackendKind::Direct,
    )
    .expect("persist shared raw workspace");
    let snapshot_a = manager
        .managed_chatgpt_auth_snapshot_for_identity(&identity_a)
        .await
        .expect("snapshot A")
        .expect("account A");
    let snapshot_b = manager
        .managed_chatgpt_auth_snapshot_for_identity(&identity_b)
        .await
        .expect("snapshot B")
        .expect("account B");
    let manager = AuthManager::from_auth_for_testing_with_home_and_agent_identity_authapi_base_url(
        snapshot_a.auth.clone(),
        codex_home.path().to_path_buf(),
        server.uri(),
    );

    manager
        .agent_identity_auth_for_snapshot(
            &snapshot_a,
            AgentIdentityAuthPolicy::ChatGptAuth,
            SessionSource::Cli,
        )
        .await
        .expect_err("bootstrap A fails after retries");
    manager
        .agent_identity_auth_for_snapshot(
            &snapshot_b,
            AgentIdentityAuthPolicy::ChatGptAuth,
            SessionSource::Cli,
        )
        .await
        .expect_err("bootstrap B independently retries");
    manager
        .agent_identity_auth_for_snapshot(
            &snapshot_a,
            AgentIdentityAuthPolicy::ChatGptAuth,
            SessionSource::Cli,
        )
        .await
        .expect_err("bootstrap A remains cooled down");
    server.verify().await;
}

#[tokio::test]
async fn uncommitted_auth_failure_rotates_but_committed_failure_does_not() {
    let codex_home = tempdir().expect("tempdir");
    let manager = file_pool_manager(codex_home.path()).await;
    manager
        .upsert_managed_chatgpt_oauth(managed_oauth_credentials(
            "a@example.com",
            "workspace-a",
            "refresh-a",
        ))
        .await
        .expect("first login");
    manager
        .upsert_managed_chatgpt_oauth(managed_oauth_credentials(
            "b@example.com",
            "workspace-b",
            "refresh-b",
        ))
        .await
        .expect("second login");
    let scope = ManagedChatgptSelectionScope {
        thread_id: Some("thread-a".to_string()),
        session_id: Some("session-a".to_string()),
        model: Some("gpt-test".to_string()),
    };
    let selected = manager
        .managed_chatgpt_auth_snapshot(&scope)
        .await
        .expect("select account")
        .expect("managed account");

    let committed = manager
        .recover_failed_attempt(
            &selected,
            ManagedChatgptFailure::AuthInvalid,
            /*committed*/ true,
            &scope,
        )
        .await
        .expect("committed recovery");
    let ManagedChatgptRecoveryDecision::Keep(committed) = committed else {
        panic!("committed attempt must keep its account");
    };
    assert_eq!(committed.identity_key, selected.identity_key);
    assert!(
        manager
            .managed_chatgpt_accounts()
            .expect("list after committed failure")
            .iter()
            .all(|account| account.block_kind.is_none())
    );

    let recovered = manager
        .recover_failed_attempt(
            &selected,
            ManagedChatgptFailure::AuthInvalid,
            /*committed*/ false,
            &scope,
        )
        .await
        .expect("uncommitted recovery");
    let ManagedChatgptRecoveryDecision::Rotate(rotated) = recovered else {
        panic!("uncommitted auth failure must rotate to a sibling");
    };
    assert_ne!(rotated.identity_key, selected.identity_key);
    let accounts = manager
        .managed_chatgpt_accounts()
        .expect("list after rotation");
    let failed = accounts
        .iter()
        .find(|account| account.identity_key == selected.identity_key)
        .expect("failed account");
    assert_eq!(
        failed.block_kind,
        Some(ManagedChatgptBlockKindView::AuthInvalid)
    );
}

#[tokio::test]
async fn status_observation_state_advance_still_recovers_and_rotates() {
    let codex_home = tempdir().expect("tempdir");
    let manager = file_pool_manager(codex_home.path()).await;
    for (email, workspace, refresh) in [
        ("a@example.com", "workspace-a", "refresh-a"),
        ("b@example.com", "workspace-b", "refresh-b"),
    ] {
        manager
            .upsert_managed_chatgpt_oauth(managed_oauth_credentials(email, workspace, refresh))
            .await
            .expect("managed login");
    }
    let scope = ManagedChatgptSelectionScope {
        thread_id: Some("status-before-failure".to_string()),
        session_id: Some("session-a".to_string()),
        model: Some("gpt-test".to_string()),
    };
    let selected = manager
        .managed_chatgpt_auth_snapshot(&scope)
        .await
        .expect("select account")
        .expect("managed account");
    let observed = manager
        .record_managed_chatgpt_status_observation(
            &selected.identity_key,
            selected.account_revision,
            selected.account_state_revision,
            ManagedChatgptStatusObservation {
                observed_at: Utc::now(),
                rate: ManagedChatgptRateObservation::Unavailable {
                    reason: "response status recorder".to_string(),
                },
                token: ManagedChatgptTokenObservation::NotObserved,
            },
        )
        .expect("record response status")
        .expect("matching status snapshot");
    assert_eq!(
        observed.revision,
        selected.account_state_revision.saturating_add(1)
    );
    assert_eq!(observed.credential_revision, selected.account_revision);

    let recovered = manager
        .recover_failed_attempt(
            &selected,
            ManagedChatgptFailure::Quota { reset_at: None },
            /*committed*/ false,
            &scope,
        )
        .await
        .expect("recover usage-limit failure");
    let ManagedChatgptRecoveryDecision::Rotate(rotated) = recovered else {
        panic!("usage-limit failure after a status write must rotate");
    };
    assert_ne!(rotated.identity_key, selected.identity_key);
    let failed = manager
        .managed_chatgpt_accounts()
        .expect("list after recovery")
        .into_iter()
        .find(|account| account.identity_key == selected.identity_key)
        .expect("failed account retained");
    assert_eq!(failed.block_kind, Some(ManagedChatgptBlockKindView::Quota));
}

#[tokio::test]
async fn recovery_from_before_relogin_stops_without_blocking_new_credentials() {
    let codex_home = tempdir().expect("tempdir");
    let manager = file_pool_manager(codex_home.path()).await;
    let identity = manager
        .upsert_managed_chatgpt_oauth(managed_oauth_credentials(
            "a@example.com",
            "workspace-a",
            "refresh-a1",
        ))
        .await
        .expect("first login");
    let scope = ManagedChatgptSelectionScope::default();
    let stale = manager
        .managed_chatgpt_auth_snapshot_for_identity(&identity)
        .await
        .expect("load first credentials")
        .expect("first snapshot");
    manager
        .upsert_managed_chatgpt_oauth(managed_oauth_credentials(
            "a@example.com",
            "workspace-a",
            "refresh-a2",
        ))
        .await
        .expect("relogin");

    assert!(matches!(
        manager
            .recover_failed_attempt(
                &stale,
                ManagedChatgptFailure::AuthInvalid,
                /*committed*/ false,
                &scope,
            )
            .await
            .expect("stale recovery"),
        ManagedChatgptRecoveryDecision::Stop
    ));
    let current = manager
        .managed_chatgpt_accounts()
        .expect("current account")
        .into_iter()
        .find(|account| account.identity_key == identity)
        .expect("relogged account");
    assert!(current.credential_revision > stale.account_revision);
    assert!(current.block_kind.is_none());
}

#[tokio::test]
async fn managed_agent_identity_persistence_accepts_state_only_advancement_at_actual_key() {
    let codex_home = tempdir().expect("tempdir");
    let manager = file_pool_manager(codex_home.path()).await;
    let identity = manager
        .upsert_managed_chatgpt_oauth(managed_oauth_credentials(
            "a@example.com",
            "workspace-a",
            "refresh-a",
        ))
        .await
        .expect("managed login");
    let snapshot = manager
        .managed_chatgpt_auth_snapshot_for_identity(&identity)
        .await
        .expect("load snapshot")
        .expect("managed snapshot");
    manager
        .record_managed_chatgpt_status_observation(
            &identity,
            snapshot.account_revision,
            snapshot.account_state_revision,
            ManagedChatgptStatusObservation {
                observed_at: Utc::now(),
                rate: ManagedChatgptRateObservation::Unavailable {
                    reason: "state-only update".to_string(),
                },
                token: ManagedChatgptTokenObservation::NotObserved,
            },
        )
        .expect("status CAS")
        .expect("status persisted");
    let binding = ManagedIdentityPersistenceBinding {
        identity_key: identity.clone(),
        credential_revision: snapshot.account_revision,
        raw_account_id: snapshot.transport.raw_account_id,
    };
    let state = Arc::new(Mutex::new(None));
    let storage = manager.managed_chatgpt_storage();
    let record = agent_identity_record("workspace-a");
    persist_agent_identity_record(&state, &storage, Some(&binding), record.clone())
        .expect("state-only advancement must not invalidate bootstrap");

    let stored = load_auth_dot_json(
        codex_home.path(),
        AuthCredentialsStoreMode::File,
        AuthKeyringBackendKind::Direct,
    )
    .expect("load persisted identity")
    .expect("stored pool");
    let account = stored
        .managed_chatgpt
        .expect("managed pool")
        .accounts
        .into_iter()
        .find(|account| account.identity_key == identity)
        .expect("actual identity-key row");
    assert_eq!(
        account
            .agent_identity
            .as_ref()
            .and_then(AgentIdentityStorage::as_record),
        Some(&record)
    );
}

#[tokio::test]
async fn delayed_managed_agent_identity_persistence_rejects_relogin() {
    let codex_home = tempdir().expect("tempdir");
    let manager = file_pool_manager(codex_home.path()).await;
    let identity = manager
        .upsert_managed_chatgpt_oauth(managed_oauth_credentials(
            "a@example.com",
            "workspace-a",
            "refresh-a1",
        ))
        .await
        .expect("initial login");
    let snapshot = manager
        .managed_chatgpt_auth_snapshot_for_identity(&identity)
        .await
        .expect("load snapshot")
        .expect("managed snapshot");
    let binding = ManagedIdentityPersistenceBinding {
        identity_key: identity.clone(),
        credential_revision: snapshot.account_revision,
        raw_account_id: snapshot.transport.raw_account_id.clone(),
    };
    manager
        .upsert_managed_chatgpt_oauth(managed_oauth_credentials(
            "a@example.com",
            "workspace-a",
            "refresh-a2",
        ))
        .await
        .expect("relogin");
    let state = Arc::new(Mutex::new(None));
    let storage = manager.managed_chatgpt_storage();
    let error = persist_agent_identity_record(
        &state,
        &storage,
        Some(&binding),
        agent_identity_record("workspace-a"),
    )
    .expect_err("old bootstrap must not write into relogged credentials");
    assert!(
        error
            .to_string()
            .contains("changed during Agent Identity bootstrap")
    );
    let stored = load_auth_dot_json(
        codex_home.path(),
        AuthCredentialsStoreMode::File,
        AuthKeyringBackendKind::Direct,
    )
    .expect("load after rejected persistence")
    .expect("stored pool");
    assert!(
        stored
            .managed_chatgpt
            .expect("managed pool")
            .accounts
            .into_iter()
            .find(|account| account.identity_key == identity)
            .expect("relogged row")
            .agent_identity
            .is_none()
    );
}

#[tokio::test]
async fn stale_observation_from_before_relogin_is_rejected() {
    let codex_home = tempdir().expect("tempdir");
    let manager = file_pool_manager(codex_home.path()).await;
    let identity = manager
        .upsert_managed_chatgpt_oauth(managed_oauth_credentials(
            "a@example.com",
            "workspace-a",
            "refresh-a1",
        ))
        .await
        .expect("first login");
    let old = manager.managed_chatgpt_accounts().expect("list pool")[0].clone();
    manager
        .upsert_managed_chatgpt_oauth(managed_oauth_credentials(
            "a@example.com",
            "workspace-a",
            "refresh-a2",
        ))
        .await
        .expect("relogin");

    let result = manager
        .record_managed_chatgpt_status_observation(
            &identity,
            old.credential_revision,
            old.revision,
            ManagedChatgptStatusObservation {
                observed_at: Utc::now(),
                rate: ManagedChatgptRateObservation::Unavailable {
                    reason: "stale response".to_string(),
                },
                token: ManagedChatgptTokenObservation::NotObserved,
            },
        )
        .expect("observation CAS");
    assert!(result.is_none());
    assert!(
        manager.managed_chatgpt_accounts().expect("list pool")[0]
            .usage
            .is_none()
    );
}

#[tokio::test]
async fn concurrent_distinct_oauth_upserts_preserve_both_rows() {
    let codex_home = tempdir().expect("tempdir");
    let manager = file_pool_manager(codex_home.path()).await;
    let (a, b) = tokio::join!(
        manager.upsert_managed_chatgpt_oauth(managed_oauth_credentials(
            "a@example.com",
            "workspace-a",
            "refresh-a",
        )),
        manager.upsert_managed_chatgpt_oauth(managed_oauth_credentials(
            "b@example.com",
            "workspace-b",
            "refresh-b",
        )),
    );
    assert_ne!(a.expect("first upsert"), b.expect("second upsert"));
    assert_eq!(
        manager.managed_chatgpt_accounts().expect("list pool").len(),
        2
    );
}

#[tokio::test]
#[serial(codex_auth_env)]
async fn targeted_logout_persists_tombstone_until_revocation_finishes() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/oauth/revoke"))
        .respond_with(ResponseTemplate::new(200).set_delay(std::time::Duration::from_millis(250)))
        .expect(1)
        .mount(&server)
        .await;
    let _revoke_guard = EnvVarGuard::set(
        REVOKE_TOKEN_URL_OVERRIDE_ENV_VAR,
        &format!("{}/oauth/revoke", server.uri()),
    );
    let codex_home = tempdir().expect("tempdir");
    let manager = file_pool_manager(codex_home.path()).await;
    let identity = manager
        .upsert_managed_chatgpt_oauth(managed_oauth_credentials(
            "a@example.com",
            "workspace-a",
            "refresh-a",
        ))
        .await
        .expect("login");
    let scope = ManagedChatgptSelectionScope {
        thread_id: Some("thread-a".to_string()),
        session_id: Some("session-a".to_string()),
        model: Some("gpt-test".to_string()),
    };
    let selected_before = manager
        .list_managed_chatgpt_accounts(&scope)
        .await
        .expect("select account before removal");
    assert_eq!(
        selected_before.selected_account_id.as_deref(),
        Some(identity.as_str())
    );
    let selection_revision_before = selected_before.selection_revision;
    let removing = tokio::spawn({
        let manager = Arc::clone(&manager);
        let identity = identity.clone();
        async move { manager.remove_managed_chatgpt_account(&identity).await }
    });
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    let stored = load_auth_dot_json(
        codex_home.path(),
        AuthCredentialsStoreMode::File,
        AuthKeyringBackendKind::Direct,
    )
    .expect("load tombstone")
    .expect("stored auth");
    let tombstoned_pool = stored.managed_chatgpt.expect("pool");
    assert!(tombstoned_pool.accounts[0].tombstone.is_some());
    let tombstoned_revision = tombstoned_pool.revision;
    assert!(
        removing
            .await
            .expect("logout task")
            .expect("targeted logout")
    );
    let stored_after = load_auth_dot_json(
        codex_home.path(),
        AuthCredentialsStoreMode::File,
        AuthKeyringBackendKind::Direct,
    )
    .expect("load after logout")
    .expect("empty pool must preserve its revision");
    let pool_after = stored_after.managed_chatgpt.expect("pool after logout");
    assert!(pool_after.accounts.is_empty());
    assert!(pool_after.revision > tombstoned_revision);
    let selected_after = manager
        .list_managed_chatgpt_accounts(&scope)
        .await
        .expect("list after removal");
    assert!(selected_after.selected_account_id.is_none());
    assert!(selected_after.selection_revision > selection_revision_before);
}

#[tokio::test]
#[serial(codex_auth_env)]
async fn recover_and_restarted_list_resume_persisted_tombstones() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/oauth/revoke"))
        .respond_with(ResponseTemplate::new(200))
        .expect(2)
        .mount(&server)
        .await;
    let _revoke_guard = EnvVarGuard::set(
        REVOKE_TOKEN_URL_OVERRIDE_ENV_VAR,
        &format!("{}/oauth/revoke", server.uri()),
    );
    let codex_home = tempdir().expect("tempdir");
    let manager = file_pool_manager(codex_home.path()).await;
    for (email, workspace, refresh) in [
        ("a@example.com", "workspace-a", "refresh-a"),
        ("b@example.com", "workspace-b", "refresh-b"),
    ] {
        manager
            .upsert_managed_chatgpt_oauth(managed_oauth_credentials(email, workspace, refresh))
            .await
            .expect("managed login");
    }
    let stale = manager
        .managed_chatgpt_auth_snapshot(&ManagedChatgptSelectionScope::default())
        .await
        .expect("select before tombstone")
        .expect("selected snapshot");
    let mut stored = load_auth_dot_json(
        codex_home.path(),
        AuthCredentialsStoreMode::File,
        AuthKeyringBackendKind::Direct,
    )
    .expect("load pool")
    .expect("stored pool");
    let stale_row = stored
        .managed_chatgpt
        .as_mut()
        .expect("managed pool")
        .accounts
        .iter_mut()
        .find(|account| account.identity_key == stale.identity_key)
        .expect("selected row");
    stale_row.tombstone = Some(ManagedChatgptTombstone {
        operation_id: "persisted-recover-tombstone".to_string(),
        revision: stale.account_revision,
        refresh_token: stale_row.tokens.refresh_token.clone(),
    });
    stale_row.revision = stale_row.revision.saturating_add(1);
    save_auth(
        codex_home.path(),
        &stored,
        AuthCredentialsStoreMode::File,
        AuthKeyringBackendKind::Direct,
    )
    .expect("persist first tombstone");

    assert!(matches!(
        manager
            .recover_failed_attempt(
                &stale,
                ManagedChatgptFailure::Transport,
                /*committed*/ true,
                &ManagedChatgptSelectionScope::default(),
            )
            .await
            .expect("recover after tombstone"),
        ManagedChatgptRecoveryDecision::Stop
    ));
    let remaining = manager
        .managed_chatgpt_accounts()
        .expect("remaining account")
        .into_iter()
        .next()
        .expect("sibling remains");
    let mut stored = load_auth_dot_json(
        codex_home.path(),
        AuthCredentialsStoreMode::File,
        AuthKeyringBackendKind::Direct,
    )
    .expect("reload pool")
    .expect("stored sibling");
    let remaining_row = stored
        .managed_chatgpt
        .as_mut()
        .expect("managed pool")
        .accounts
        .iter_mut()
        .find(|account| account.identity_key == remaining.identity_key)
        .expect("remaining row");
    remaining_row.tombstone = Some(ManagedChatgptTombstone {
        operation_id: "persisted-list-tombstone".to_string(),
        revision: remaining.credential_revision,
        refresh_token: remaining_row.tokens.refresh_token.clone(),
    });
    remaining_row.revision = remaining_row.revision.saturating_add(1);
    save_auth(
        codex_home.path(),
        &stored,
        AuthCredentialsStoreMode::File,
        AuthKeyringBackendKind::Direct,
    )
    .expect("persist second tombstone");
    drop(manager);

    let restarted = file_pool_manager(codex_home.path()).await;
    let listed = restarted
        .list_managed_chatgpt_accounts(&ManagedChatgptSelectionScope::default())
        .await
        .expect("restart list resumes tombstone");
    assert!(listed.accounts.is_empty());
    assert!(listed.selected_account_id.is_none());
    server.verify().await;
}

#[tokio::test]
#[serial(codex_auth_env)]
async fn refresh_remove_and_relogin_never_reuses_credential_revision() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/oauth/token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "access_token": "refreshed-access",
            "refresh_token": "refreshed-token"
        })))
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/oauth/revoke"))
        .respond_with(ResponseTemplate::new(200))
        .expect(1)
        .mount(&server)
        .await;
    let _refresh_guard = EnvVarGuard::set(
        REFRESH_TOKEN_URL_OVERRIDE_ENV_VAR,
        &format!("{}/oauth/token", server.uri()),
    );
    let _revoke_guard = EnvVarGuard::set(
        REVOKE_TOKEN_URL_OVERRIDE_ENV_VAR,
        &format!("{}/oauth/revoke", server.uri()),
    );
    let codex_home = tempdir().expect("tempdir");
    let manager = file_pool_manager(codex_home.path()).await;
    let mut initial = managed_oauth_credentials("a@example.com", "workspace-a", "refresh-a");
    initial.last_refresh = Utc::now() - chrono::Duration::days(10);
    let identity = manager
        .upsert_managed_chatgpt_oauth(initial)
        .await
        .expect("initial login");
    let pre_refresh = manager
        .managed_chatgpt_auth_snapshot_for_identity(&identity)
        .await
        .expect("load pre-refresh account")
        .expect("pre-refresh snapshot");
    assert!(matches!(
        manager
            .recover_failed_attempt(
                &pre_refresh,
                ManagedChatgptFailure::Quota { reset_at: None },
                /*committed*/ false,
                &ManagedChatgptSelectionScope::default(),
            )
            .await
            .expect("apply quota block"),
        ManagedChatgptRecoveryDecision::Stop
    ));
    let refreshed_revision = manager
        .refresh_managed_chatgpt_account(&identity)
        .await
        .expect("successful refresh")
        .account_revision;
    let stored_after_refresh = load_auth_dot_json(
        codex_home.path(),
        AuthCredentialsStoreMode::File,
        AuthKeyringBackendKind::Direct,
    )
    .expect("load after refresh")
    .expect("stored refreshed pool");
    let retained_block = stored_after_refresh
        .managed_chatgpt
        .expect("managed pool")
        .accounts
        .into_iter()
        .find(|account| account.identity_key == identity)
        .and_then(|account| account.block)
        .expect("same-workspace quota block retained");
    assert_eq!(retained_block.kind, ManagedChatgptBlockKind::Quota);
    assert_eq!(retained_block.credential_revision, refreshed_revision);
    assert!(
        manager
            .remove_managed_chatgpt_account(&identity)
            .await
            .expect("remove refreshed account")
    );
    let relogged_identity = manager
        .upsert_managed_chatgpt_oauth(managed_oauth_credentials(
            "a@example.com",
            "workspace-a",
            "refresh-after-remove",
        ))
        .await
        .expect("relogin");
    let relogged = manager
        .managed_chatgpt_auth_snapshot_for_identity(&relogged_identity)
        .await
        .expect("load relogged account")
        .expect("relogged snapshot");
    assert!(relogged.account_revision > refreshed_revision);
    server.verify().await;
}

#[tokio::test]
#[serial(codex_auth_env)]
async fn blank_managed_refresh_token_response_preserves_existing_credentials() {
    for (access_token, refresh_token, blank_field, returned_token) in [
        (
            "",
            "replacement-refresh",
            "access_token",
            "replacement-refresh",
        ),
        (
            "replacement-access",
            "",
            "refresh_token",
            "replacement-access",
        ),
    ] {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/oauth/token"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "access_token": access_token,
                "refresh_token": refresh_token
            })))
            .expect(1)
            .mount(&server)
            .await;
        let _refresh_guard = EnvVarGuard::set(
            REFRESH_TOKEN_URL_OVERRIDE_ENV_VAR,
            &format!("{}/oauth/token", server.uri()),
        );
        let codex_home = tempdir().expect("tempdir");
        let manager = file_pool_manager(codex_home.path()).await;
        let mut credentials =
            managed_oauth_credentials("a@example.com", "workspace-a", "original-refresh");
        credentials.last_refresh = Utc::now() - chrono::Duration::days(10);
        let identity = manager
            .upsert_managed_chatgpt_oauth(credentials)
            .await
            .expect("login");
        let expected_tokens = load_auth_dot_json(
            codex_home.path(),
            AuthCredentialsStoreMode::File,
            AuthKeyringBackendKind::Direct,
        )
        .expect("load before rejected refresh")
        .expect("stored auth")
        .managed_chatgpt
        .expect("pool")
        .accounts
        .into_iter()
        .find(|account| account.identity_key == identity)
        .expect("managed account")
        .tokens;

        let error = manager
            .refresh_managed_chatgpt_account(&identity)
            .await
            .expect_err("blank token must reject the entire refresh response");
        let error_message = error.to_string();
        assert!(error_message.contains(blank_field));
        assert!(
            !error_message.contains(returned_token),
            "refresh error must not disclose a returned token"
        );

        let stored = load_auth_dot_json(
            codex_home.path(),
            AuthCredentialsStoreMode::File,
            AuthKeyringBackendKind::Direct,
        )
        .expect("load after rejected refresh")
        .expect("stored auth");
        let account = stored
            .managed_chatgpt
            .expect("pool")
            .accounts
            .into_iter()
            .find(|account| account.identity_key == identity)
            .expect("managed account");
        assert_eq!(account.tokens, expected_tokens);
        assert!(account.mutation_lease.is_none());
        let failure = account
            .refresh_failure
            .expect("refresh failure should persist");
        assert_eq!(
            failure.reason_code.as_deref(),
            Some("token_refresh_unavailable")
        );
        server.verify().await;
    }
}

#[tokio::test]
#[serial(codex_auth_env)]
async fn failed_managed_refresh_clears_persisted_lease() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/oauth/token"))
        .respond_with(ResponseTemplate::new(500))
        .expect(1)
        .mount(&server)
        .await;
    let _refresh_guard = EnvVarGuard::set(
        REFRESH_TOKEN_URL_OVERRIDE_ENV_VAR,
        &format!("{}/oauth/token", server.uri()),
    );
    let codex_home = tempdir().expect("tempdir");
    let manager = file_pool_manager(codex_home.path()).await;
    let mut credentials = managed_oauth_credentials("a@example.com", "workspace-a", "refresh-a");
    credentials.last_refresh = Utc::now() - chrono::Duration::days(10);
    let identity = manager
        .upsert_managed_chatgpt_oauth(credentials)
        .await
        .expect("login");
    let initial_revision = manager.managed_chatgpt_accounts().expect("list pool")[0].revision;

    manager
        .refresh_managed_chatgpt_account(&identity)
        .await
        .expect_err("authority failure must fail refresh");

    let stored = load_auth_dot_json(
        codex_home.path(),
        AuthCredentialsStoreMode::File,
        AuthKeyringBackendKind::Direct,
    )
    .expect("load after failed refresh")
    .expect("stored auth");
    let account = &stored.managed_chatgpt.expect("pool").accounts[0];
    assert!(account.mutation_lease.is_none());
    assert!(
        account
            .refresh_failure
            .as_ref()
            .is_some_and(|failure| !failure.permanent)
    );
    assert!(account.revision > initial_revision);
    server.verify().await;
}

#[tokio::test]
#[serial(codex_auth_env)]
async fn disallowed_managed_refresh_does_not_lease_mutate_or_call_authority() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/oauth/token"))
        .respond_with(ResponseTemplate::new(500))
        .expect(0)
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/oauth/revoke"))
        .respond_with(ResponseTemplate::new(500))
        .expect(0)
        .mount(&server)
        .await;
    let _refresh_guard = EnvVarGuard::set(
        REFRESH_TOKEN_URL_OVERRIDE_ENV_VAR,
        &format!("{}/oauth/token", server.uri()),
    );
    let _revoke_guard = EnvVarGuard::set(
        REVOKE_TOKEN_URL_OVERRIDE_ENV_VAR,
        &format!("{}/oauth/revoke", server.uri()),
    );
    let codex_home = tempdir().expect("tempdir");
    let manager = file_pool_manager(codex_home.path()).await;
    let mut disallowed =
        managed_oauth_credentials("a@example.com", "workspace-disallowed", "refresh-a");
    disallowed.last_refresh = Utc::now() - chrono::Duration::days(10);
    let identity = manager
        .upsert_managed_chatgpt_oauth(disallowed)
        .await
        .expect("disallowed row login before policy");
    manager
        .upsert_managed_chatgpt_oauth(managed_oauth_credentials(
            "b@example.com",
            "workspace-allowed",
            "refresh-b",
        ))
        .await
        .expect("healthy sibling login");
    manager.set_forced_chatgpt_workspace_id(Some(vec!["workspace-allowed".to_string()]));
    let before = load_auth_dot_json(
        codex_home.path(),
        AuthCredentialsStoreMode::File,
        AuthKeyringBackendKind::Direct,
    )
    .expect("load before refresh")
    .expect("stored pool");

    let err = manager
        .refresh_managed_chatgpt_account(&identity)
        .await
        .expect_err("forced workspace policy must reject refresh");
    assert!(
        err.to_string().contains("forced workspace policy")
            || err.to_string().contains("no eligible")
    );
    let after = load_auth_dot_json(
        codex_home.path(),
        AuthCredentialsStoreMode::File,
        AuthKeyringBackendKind::Direct,
    )
    .expect("load after refresh")
    .expect("stored pool");
    assert_eq!(after, before);
    server.verify().await;
}

#[tokio::test]
async fn long_lived_managers_observe_external_chatgpt_overlay_replacement() {
    let codex_home = tempdir().expect("tempdir");
    let file_manager = AuthManager::shared(
        codex_home.path().to_path_buf(),
        false,
        AuthCredentialsStoreMode::File,
        None,
        None,
        AuthKeyringBackendKind::Direct,
        crate::test_support::transport_default_auth_route_config(),
    )
    .await;
    let ephemeral_manager = AuthManager::shared(
        codex_home.path().to_path_buf(),
        false,
        AuthCredentialsStoreMode::Ephemeral,
        None,
        None,
        AuthKeyringBackendKind::Direct,
        crate::test_support::transport_default_auth_route_config(),
    )
    .await;

    login_with_chatgpt_auth_tokens(
        codex_home.path(),
        &managed_id_token("external-a@example.com", "external-workspace-a"),
        "external-workspace-a",
        Some("pro"),
    )
    .expect("install external overlay A");
    for manager in [&file_manager, &ephemeral_manager] {
        assert_eq!(
            manager
                .auth()
                .await
                .and_then(|auth| auth.get_account_id())
                .as_deref(),
            Some("external-workspace-a")
        );
    }

    login_with_chatgpt_auth_tokens(
        codex_home.path(),
        &managed_id_token("external-b@example.com", "external-workspace-b"),
        "external-workspace-b",
        Some("team"),
    )
    .expect("atomically replace external overlay A with B");
    for manager in [&file_manager, &ephemeral_manager] {
        assert!(
            manager.auth_cached().is_none(),
            "a stale overlay snapshot must not be served after replacement"
        );
        assert_eq!(
            manager
                .auth()
                .await
                .and_then(|auth| auth.get_account_id())
                .as_deref(),
            Some("external-workspace-b")
        );
    }

    assert!(
        logout(
            codex_home.path(),
            AuthCredentialsStoreMode::File,
            AuthKeyringBackendKind::Direct,
        )
        .expect("remove external overlay B")
    );
    for manager in [&file_manager, &ephemeral_manager] {
        assert!(manager.auth_cached().is_none());
        assert!(manager.auth().await.is_none());
    }
}

#[tokio::test]
async fn direct_refresh_accepts_reloaded_external_overlay_replacement() {
    let codex_home = tempdir().expect("tempdir");
    login_with_chatgpt_auth_tokens(
        codex_home.path(),
        &managed_id_token("external-a@example.com", "external-workspace-a"),
        "external-workspace-a",
        Some("pro"),
    )
    .expect("install external overlay A");
    let manager = AuthManager::shared(
        codex_home.path().to_path_buf(),
        false,
        AuthCredentialsStoreMode::File,
        None,
        None,
        AuthKeyringBackendKind::Direct,
        crate::test_support::transport_default_auth_route_config(),
    )
    .await;
    assert_eq!(
        manager
            .auth_cached()
            .and_then(|auth| auth.get_account_id())
            .as_deref(),
        Some("external-workspace-a")
    );

    login_with_chatgpt_auth_tokens(
        codex_home.path(),
        &managed_id_token("external-b@example.com", "external-workspace-b"),
        "external-workspace-b",
        Some("team"),
    )
    .expect("replace external overlay A with B");
    assert!(
        manager.auth_cached().is_none(),
        "overlay replacement must invalidate the stale cached snapshot"
    );

    manager
        .refresh_token()
        .await
        .expect("guarded reload should accept replacement overlay B");
    assert_eq!(
        manager
            .auth_cached()
            .and_then(|auth| auth.get_account_id())
            .as_deref(),
        Some("external-workspace-b")
    );
}

#[tokio::test]
async fn external_chatgpt_overlay_logout_preserves_persistent_pool() {
    let codex_home = tempdir().expect("tempdir");
    let file_manager = file_pool_manager(codex_home.path()).await;
    file_manager
        .upsert_managed_chatgpt_oauth(managed_oauth_credentials(
            "a@example.com",
            "workspace-a",
            "refresh-a",
        ))
        .await
        .expect("persistent login");
    let ephemeral_manager = AuthManager::shared(
        codex_home.path().to_path_buf(),
        false,
        AuthCredentialsStoreMode::Ephemeral,
        None,
        None,
        AuthKeyringBackendKind::Direct,
        crate::test_support::transport_default_auth_route_config(),
    )
    .await;
    let ephemeral_identity = ephemeral_manager
        .upsert_managed_chatgpt_oauth(managed_oauth_credentials(
            "ephemeral@example.com",
            "ephemeral-workspace",
            "ephemeral-refresh",
        ))
        .await
        .expect("ephemeral managed login");
    let external_access_token = managed_id_token("external@example.com", "external-workspace");
    login_with_chatgpt_auth_tokens(
        codex_home.path(),
        &external_access_token,
        "external-workspace",
        Some("pro"),
    )
    .expect("install external overlay");
    let overlay_manager = AuthManager::shared(
        codex_home.path().to_path_buf(),
        false,
        AuthCredentialsStoreMode::Ephemeral,
        None,
        None,
        AuthKeyringBackendKind::Direct,
        crate::test_support::transport_default_auth_route_config(),
    )
    .await;
    assert!(overlay_manager.is_external_chatgpt_auth_active());
    assert!(
        file_manager
            .auth()
            .await
            .is_some_and(|auth| auth.is_external_chatgpt_tokens()),
        "a manager constructed before the overlay must observe it before serving auth"
    );
    assert!(file_manager.managed_chatgpt_accounts().unwrap().is_empty());
    let stored_inventory = file_manager
        .stored_managed_chatgpt_account_list()
        .expect("stored owner inventory");
    assert_eq!(stored_inventory.accounts.len(), 1);
    assert!(stored_inventory.pool_revision > 0);
    assert!(stored_inventory.selected_account_id.is_none());
    assert!(
        overlay_manager
            .managed_chatgpt_auth_snapshot_for_identity(&ephemeral_identity)
            .await
            .expect("targeted managed lookup")
            .is_none(),
        "external overlay must hide every managed identity"
    );
    assert!(
        logout(
            codex_home.path(),
            AuthCredentialsStoreMode::File,
            AuthKeyringBackendKind::Direct,
        )
        .expect("free logout clears overlay")
    );
    assert!(
        load_auth_dot_json(
            codex_home.path(),
            AuthCredentialsStoreMode::File,
            AuthKeyringBackendKind::Direct,
        )
        .unwrap()
        .and_then(|auth| auth.managed_chatgpt)
        .is_some(),
        "free logout must preserve the hidden persistent pool"
    );
    login_with_chatgpt_auth_tokens(
        codex_home.path(),
        &external_access_token,
        "external-workspace",
        Some("pro"),
    )
    .expect("reinstall external overlay");
    assert!(overlay_manager.logout().await.expect("external logout"));
    assert_eq!(
        overlay_manager
            .auth_cached()
            .and_then(|auth| auth.get_account_id())
            .as_deref(),
        Some("ephemeral-workspace"),
        "clearing the overlay must reveal the underlying ephemeral pool"
    );
    let persistent = load_auth_dot_json(
        codex_home.path(),
        AuthCredentialsStoreMode::File,
        AuthKeyringBackendKind::Direct,
    )
    .expect("load persistent pool")
    .expect("persistent auth");
    assert_eq!(
        persistent
            .managed_chatgpt
            .expect("persistent pool")
            .accounts
            .len(),
        1
    );
}

#[tokio::test]
#[serial(codex_auth_env)]
async fn free_logout_with_revoke_revokes_canonical_pool_credentials() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/oauth/revoke"))
        .and(body_partial_json(json!({ "token": "refresh-a" })))
        .respond_with(ResponseTemplate::new(200))
        .expect(1)
        .mount(&server)
        .await;
    let _revoke_guard = EnvVarGuard::set(
        REVOKE_TOKEN_URL_OVERRIDE_ENV_VAR,
        &format!("{}/oauth/revoke", server.uri()),
    );
    let codex_home = tempdir().expect("tempdir");
    let manager = file_pool_manager(codex_home.path()).await;
    manager
        .upsert_managed_chatgpt_oauth(managed_oauth_credentials(
            "a@example.com",
            "workspace-a",
            "refresh-a",
        ))
        .await
        .expect("managed login");

    assert!(
        logout_with_revoke(
            codex_home.path(),
            AuthCredentialsStoreMode::File,
            AuthKeyringBackendKind::Direct,
            &crate::test_support::transport_default_auth_route_config(),
        )
        .await
        .expect("free logout with revoke")
    );
    assert!(
        load_auth_dot_json(
            codex_home.path(),
            AuthCredentialsStoreMode::File,
            AuthKeyringBackendKind::Direct,
        )
        .unwrap()
        .is_none()
    );
    server.verify().await;
}

#[tokio::test]
#[serial(codex_auth_env)]
async fn logout_all_clears_external_overlay_and_hidden_managed_pool() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/oauth/revoke"))
        .respond_with(ResponseTemplate::new(200))
        .expect(3)
        .mount(&server)
        .await;
    let _revoke_guard = EnvVarGuard::set(
        REVOKE_TOKEN_URL_OVERRIDE_ENV_VAR,
        &format!("{}/oauth/revoke", server.uri()),
    );
    let codex_home = tempdir().expect("tempdir");
    let manager = file_pool_manager(codex_home.path()).await;
    for (email, workspace, refresh) in [
        ("a@example.com", "workspace-a", "refresh-a"),
        ("b@example.com", "workspace-b", "refresh-b"),
    ] {
        manager
            .upsert_managed_chatgpt_oauth(managed_oauth_credentials(email, workspace, refresh))
            .await
            .expect("managed login");
    }
    login_with_chatgpt_auth_tokens(
        codex_home.path(),
        &managed_id_token("external@example.com", "external-workspace"),
        "external-workspace",
        Some("pro"),
    )
    .expect("external overlay");
    assert!(manager.managed_chatgpt_accounts().unwrap().is_empty());

    let mut removed = manager
        .logout_all_managed_chatgpt()
        .await
        .expect("logout all");
    removed.sort();
    assert_eq!(removed.len(), 2);
    assert!(!manager.is_external_chatgpt_auth_active());
    let stored = load_auth_dot_json(
        codex_home.path(),
        AuthCredentialsStoreMode::File,
        AuthKeyringBackendKind::Direct,
    )
    .unwrap()
    .expect("empty pool generation remains");
    assert!(
        stored
            .managed_chatgpt
            .expect("pool generation")
            .accounts
            .is_empty()
    );
    server.verify().await;
}
#[tokio::test]
#[serial(codex_auth_env)]
async fn bounded_refresh_timeout_revises_row_pool_and_watch() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/oauth/token"))
        .respond_with(ResponseTemplate::new(200).set_delay(std::time::Duration::from_secs(60)))
        .expect(1)
        .mount(&server)
        .await;
    let _refresh_guard = EnvVarGuard::set(
        REFRESH_TOKEN_URL_OVERRIDE_ENV_VAR,
        &format!("{}/oauth/token", server.uri()),
    );
    let codex_home = tempdir().expect("tempdir");
    let manager = file_pool_manager(codex_home.path()).await;
    let observer = file_pool_manager(codex_home.path()).await;
    let mut credentials = managed_oauth_credentials("a@example.com", "workspace-a", "refresh-a");
    credentials.last_refresh = Utc::now() - chrono::Duration::days(10);
    let identity = manager
        .upsert_managed_chatgpt_oauth(credentials)
        .await
        .expect("login");
    let before = manager
        .stored_managed_chatgpt_account_list()
        .expect("initial list");
    let mut changes = manager.auth_change_receiver();
    let initial_change_revision = *changes.borrow();

    let error = manager
        .refresh_managed_chatgpt_account_bounded(&identity, std::time::Duration::from_millis(100))
        .await
        .expect_err("refresh must time out");
    assert!(matches!(
        &error,
        RefreshTokenError::Transient(error)
            if error.kind() == std::io::ErrorKind::TimedOut
    ));

    let after = manager
        .stored_managed_chatgpt_account_list()
        .expect("updated list");
    assert_eq!(after.accounts[0].revision, before.accounts[0].revision + 2);
    assert_eq!(after.pool_revision, before.pool_revision + 2);
    assert!(matches!(
        &after.accounts[0].refresh_status,
        ManagedChatgptRefreshStatus::TransientUnavailable { .. }
    ));
    let stored = load_auth_dot_json(
        codex_home.path(),
        AuthCredentialsStoreMode::File,
        AuthKeyringBackendKind::Direct,
    )
    .expect("load after timeout")
    .expect("stored auth");
    let failure = stored
        .managed_chatgpt
        .expect("pool")
        .accounts
        .into_iter()
        .find(|account| account.identity_key == identity)
        .and_then(|account| account.refresh_failure)
        .expect("timeout failure");
    assert_eq!(
        failure.reason_code.as_deref(),
        Some("token_refresh_timeout")
    );
    changes.changed().await.expect("timeout notification");
    assert_eq!(*changes.borrow(), initial_change_revision + 2);
    let observed = observer
        .stored_managed_chatgpt_account_list()
        .expect("observer list");
    assert_eq!(observed.pool_revision, after.pool_revision);
    assert_eq!(observed.accounts[0].revision, after.accounts[0].revision);
    server.verify().await;
}

#[tokio::test]
async fn delayed_timeout_for_operation_a_cannot_relabel_cancellation_b() {
    let codex_home = tempdir().expect("tempdir");
    let manager = file_pool_manager(codex_home.path()).await;
    let identity = manager
        .upsert_managed_chatgpt_oauth(managed_oauth_credentials(
            "a@example.com",
            "workspace-a",
            "refresh-a",
        ))
        .await
        .expect("login");
    let mut stored = load_auth_dot_json(
        codex_home.path(),
        AuthCredentialsStoreMode::File,
        AuthKeyringBackendKind::Direct,
    )
    .expect("load auth")
    .expect("stored auth");
    let account = row_mut(&mut stored, &identity).expect("managed account");
    account.refresh_failure = Some(ManagedChatgptRefreshFailure {
        observed_at: Utc::now(),
        permanent: false,
        reason_code: Some("token_refresh_cancelled".to_string()),
        operation_id: Some("refresh-b".to_string()),
    });
    save_auth(
        codex_home.path(),
        &stored,
        AuthCredentialsStoreMode::File,
        AuthKeyringBackendKind::Direct,
    )
    .expect("persist cancellation B");
    let before = manager
        .stored_managed_chatgpt_account_list()
        .expect("list before delayed A timeout");
    let storage = create_auth_storage(
        codex_home.path().to_path_buf(),
        AuthCredentialsStoreMode::File,
        AuthKeyringBackendKind::Direct,
    );

    assert_eq!(
        persist_managed_refresh_failure(
            &storage,
            &identity,
            Some("refresh-a"),
            "token_refresh_timeout",
            false,
        )
        .expect("record delayed A timeout"),
        (false, false)
    );
    let after = manager
        .stored_managed_chatgpt_account_list()
        .expect("list after delayed A timeout");
    assert_eq!(after.pool_revision, before.pool_revision);
    assert_eq!(after.accounts[0].revision, before.accounts[0].revision);
    assert!(matches!(
        &after.accounts[0].refresh_status,
        ManagedChatgptRefreshStatus::TransientUnavailable { .. }
    ));
    let stored = storage
        .load()
        .expect("load after delayed timeout")
        .expect("stored auth");
    let failure = stored
        .managed_chatgpt
        .expect("pool")
        .accounts
        .into_iter()
        .find(|account| account.identity_key == identity)
        .and_then(|account| account.refresh_failure)
        .expect("refresh failure");
    assert_eq!(
        failure.reason_code.as_deref(),
        Some("token_refresh_cancelled")
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[serial(codex_auth_env)]
async fn concurrent_permanent_refresh_failure_posts_once_and_shares_owner_outcome() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/oauth/token"))
        .respond_with(
            ResponseTemplate::new(401)
                .set_delay(std::time::Duration::from_millis(150))
                .set_body_json(json!({"error": {"code": "refresh_token_reused"}})),
        )
        .expect(1)
        .mount(&server)
        .await;
    let _refresh_guard = EnvVarGuard::set(
        REFRESH_TOKEN_URL_OVERRIDE_ENV_VAR,
        &format!("{}/oauth/token", server.uri()),
    );
    let codex_home = tempdir().expect("tempdir");
    let manager = file_pool_manager(codex_home.path()).await;
    let mut credentials = managed_oauth_credentials("a@example.com", "workspace-a", "refresh-a");
    credentials.last_refresh = Utc::now() - chrono::Duration::days(10);
    let identity = manager
        .upsert_managed_chatgpt_oauth(credentials)
        .await
        .expect("login");

    let (owner, waiter) = tokio::join!(
        manager.refresh_managed_chatgpt_account(&identity),
        manager.refresh_managed_chatgpt_account(&identity),
    );
    for outcome in [owner, waiter] {
        assert!(matches!(
            outcome,
            Err(RefreshTokenError::Permanent(error))
                if error.reason == RefreshTokenFailedReason::Exhausted
        ));
    }
    server.verify().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[serial(codex_auth_env)]
async fn concurrent_post_authority_commit_error_posts_once_and_shares_owner_outcome() {
    let server = MockServer::start().await;
    let disallowed_id_token = managed_id_token("a@example.com", "workspace-disallowed");
    Mock::given(method("POST"))
        .and(path("/oauth/token"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_delay(std::time::Duration::from_millis(150))
                .set_body_json(json!({
                    "access_token": "refreshed-access",
                    "refresh_token": "refreshed-token",
                    "id_token": disallowed_id_token,
                })),
        )
        .expect(1)
        .mount(&server)
        .await;
    let _refresh_guard = EnvVarGuard::set(
        REFRESH_TOKEN_URL_OVERRIDE_ENV_VAR,
        &format!("{}/oauth/token", server.uri()),
    );
    let codex_home = tempdir().expect("tempdir");
    let manager = file_pool_manager(codex_home.path()).await;
    let mut credentials =
        managed_oauth_credentials("a@example.com", "workspace-allowed", "refresh");
    credentials.last_refresh = Utc::now() - chrono::Duration::days(10);
    let identity = manager
        .upsert_managed_chatgpt_oauth(credentials)
        .await
        .expect("login");
    manager.set_forced_chatgpt_workspace_id(Some(vec!["workspace-allowed".to_string()]));

    let (owner, waiter) = tokio::join!(
        manager.refresh_managed_chatgpt_account(&identity),
        manager.refresh_managed_chatgpt_account(&identity),
    );
    assert!(matches!(owner, Err(RefreshTokenError::Transient(_))));
    assert!(matches!(waiter, Err(RefreshTokenError::Transient(_))));
    let stored = load_auth_dot_json(
        codex_home.path(),
        AuthCredentialsStoreMode::File,
        AuthKeyringBackendKind::Direct,
    )
    .expect("load auth")
    .expect("stored auth");
    let account = row(&stored, &identity).expect("managed account");
    assert!(account.mutation_lease.is_none());
    assert!(matches!(
        account.refresh_failure.as_ref(),
        Some(ManagedChatgptRefreshFailure {
            permanent: false,
            reason_code: Some(reason),
            ..
        }) if reason == "token_refresh_commit_failed"
    ));
    server.verify().await;
}

#[tokio::test]
async fn global_logout_rejects_ambiguous_managed_pool_without_deleting_siblings() {
    let codex_home = tempdir().expect("tempdir");
    let manager = file_pool_manager(codex_home.path()).await;
    for (email, workspace, refresh) in [
        ("a@example.com", "workspace-a", "refresh-a"),
        ("b@example.com", "workspace-b", "refresh-b"),
    ] {
        manager
            .upsert_managed_chatgpt_oauth(managed_oauth_credentials(email, workspace, refresh))
            .await
            .expect("managed login");
    }

    let error = manager
        .logout()
        .await
        .expect_err("global logout must reject an ambiguous pool");
    assert!(error.to_string().contains("ambiguous"));
    assert_eq!(
        manager
            .managed_chatgpt_accounts()
            .expect("pool remains")
            .len(),
        2
    );
}

#[tokio::test]
async fn managed_to_api_key_preserves_monotonic_empty_pool_revision() {
    let codex_home = tempdir().expect("tempdir");
    let manager = file_pool_manager(codex_home.path()).await;
    manager
        .upsert_managed_chatgpt_oauth(managed_oauth_credentials(
            "a@example.com",
            "workspace-a",
            "refresh-a",
        ))
        .await
        .expect("managed login");
    manager
        .upsert_managed_chatgpt_oauth(managed_oauth_credentials(
            "b@example.com",
            "workspace-b",
            "refresh-b",
        ))
        .await
        .expect("second managed login");
    let scope = ManagedChatgptSelectionScope {
        session_id: Some("cutover-session".to_string()),
        ..Default::default()
    };
    let before = manager
        .list_managed_chatgpt_accounts(&scope)
        .await
        .expect("list managed pool");
    let selection_revision_before = before.selection_revision;
    let mut changes = manager.auth_change_receiver();
    let watch_revision_before = *changes.borrow();
    let next_account_revision = load_auth_dot_json(
        codex_home.path(),
        AuthCredentialsStoreMode::File,
        AuthKeyringBackendKind::Direct,
    )
    .unwrap()
    .unwrap()
    .managed_chatgpt
    .unwrap()
    .next_account_revision;

    login_with_api_key(
        codex_home.path(),
        "sk-test",
        AuthCredentialsStoreMode::File,
        AuthKeyringBackendKind::Direct,
    )
    .expect("api key login");
    assert!(manager.reload().await);
    let after = manager
        .list_managed_chatgpt_accounts(&scope)
        .await
        .expect("list cleared pool");
    assert!(after.accounts.is_empty());
    assert!(after.pool_revision > before.pool_revision);
    assert_ne!(after.pool_revision, 0);
    assert!(after.selected_account_id.is_none());
    assert!(after.selection_revision > selection_revision_before);
    changes.changed().await.expect("cutover notification");
    assert!(*changes.borrow() > watch_revision_before);
    let stored = load_auth_dot_json(
        codex_home.path(),
        AuthCredentialsStoreMode::File,
        AuthKeyringBackendKind::Direct,
    )
    .unwrap()
    .unwrap();
    assert_eq!(stored.auth_mode, Some(AuthMode::ApiKey));
    let ledger = stored.managed_chatgpt.expect("empty generation ledger");
    assert!(ledger.accounts.is_empty());
    assert_eq!(ledger.next_account_revision, next_account_revision);
    let reloaded = file_pool_manager(codex_home.path()).await;
    assert_eq!(reloaded.auth_mode(), Some(AuthMode::ApiKey));
    assert!(
        reloaded
            .auth_cached()
            .is_some_and(|auth| auth.api_key() == Some("sk-test"))
    );
}

#[tokio::test]
async fn managed_to_bedrock_reload_uses_declared_nonpooled_mode() {
    let codex_home = tempdir().expect("tempdir");
    let manager = file_pool_manager(codex_home.path()).await;
    manager
        .upsert_managed_chatgpt_oauth(managed_oauth_credentials(
            "a@example.com",
            "workspace-a",
            "refresh-a",
        ))
        .await
        .expect("managed login");

    login_with_bedrock_api_key(
        codex_home.path(),
        "bedrock-test-key",
        "us-east-1",
        AuthCredentialsStoreMode::File,
        AuthKeyringBackendKind::Direct,
    )
    .expect("Bedrock login");

    let stored = load_auth_dot_json(
        codex_home.path(),
        AuthCredentialsStoreMode::File,
        AuthKeyringBackendKind::Direct,
    )
    .expect("load Bedrock cutover")
    .expect("stored auth");
    assert_eq!(stored.auth_mode, Some(AuthMode::BedrockApiKey));
    assert!(
        stored
            .managed_chatgpt
            .as_ref()
            .is_some_and(|pool| pool.accounts.is_empty())
    );

    let reloaded = file_pool_manager(codex_home.path()).await;
    assert_eq!(reloaded.auth_mode(), Some(AuthMode::BedrockApiKey));
    assert!(matches!(
        reloaded.auth_cached(),
        Some(CodexAuth::BedrockApiKey(BedrockApiKeyAuth {
            api_key,
            region,
        })) if api_key == "bedrock-test-key" && region == "us-east-1"
    ));
}
