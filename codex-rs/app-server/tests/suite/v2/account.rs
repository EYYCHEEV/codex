use anyhow::Result;
use anyhow::bail;
use app_test_support::TestAppServer;
use app_test_support::to_response;

use super::connection_handling_websocket::connect_websocket;
use super::connection_handling_websocket::read_notification_for_method;
use super::connection_handling_websocket::read_response_for_id;
use super::connection_handling_websocket::send_initialize_request;
use super::connection_handling_websocket::send_request;
use super::connection_handling_websocket::spawn_websocket_server_with_env;
use app_test_support::ChatGptAuthFixture;
use app_test_support::ChatGptIdTokenClaims;
use app_test_support::DEFAULT_CLIENT_NAME;
use app_test_support::encode_id_token;
use app_test_support::write_chatgpt_auth;
use app_test_support::write_models_cache;
use chrono::Duration as ChronoDuration;
use chrono::Utc;
use codex_app_server_protocol::Account;
use codex_app_server_protocol::AccountLoginCompletedNotification;
use codex_app_server_protocol::AccountUpdatedNotification;
use codex_app_server_protocol::AuthMode;
use codex_app_server_protocol::CancelLoginAccountParams;
use codex_app_server_protocol::CancelLoginAccountResponse;
use codex_app_server_protocol::CancelLoginAccountStatus;
use codex_app_server_protocol::ChatgptAuthTokensRefreshReason;
use codex_app_server_protocol::ChatgptAuthTokensRefreshResponse;
use codex_app_server_protocol::ClientInfo;
use codex_app_server_protocol::DesktopOnboardingEntrypoint;
use codex_app_server_protocol::GetAccountParams;
use codex_app_server_protocol::GetAccountResponse;
use codex_app_server_protocol::GetAuthStatusParams;
use codex_app_server_protocol::GetAuthStatusResponse;
use codex_app_server_protocol::InitializeCapabilities;
use codex_app_server_protocol::JSONRPCError;
use codex_app_server_protocol::JSONRPCErrorError;
use codex_app_server_protocol::JSONRPCMessage;
use codex_app_server_protocol::JSONRPCNotification;
use codex_app_server_protocol::JSONRPCResponse;
use codex_app_server_protocol::ListAccountsResponse;
use codex_app_server_protocol::LoginAccountResponse;
use codex_app_server_protocol::LogoutAccountResponse;
use codex_app_server_protocol::ManagedChatgptAccountRefreshStatus;
use codex_app_server_protocol::ManagedChatgptAccountUsageState;
use codex_app_server_protocol::RequestId;
use codex_app_server_protocol::ServerNotification;
use codex_app_server_protocol::ServerRequest;
use codex_app_server_protocol::TurnCompletedNotification;
use codex_app_server_protocol::TurnStatus;
use codex_config::types::AuthCredentialsStoreMode;
use codex_login::AuthDotJson;
use codex_login::AuthKeyringBackendKind;
use codex_login::AuthManager;
use codex_login::CLIENT_ID_OVERRIDE_ENV_VAR;
use codex_login::ManagedChatgptOauthCredentials;
use codex_login::REFRESH_TOKEN_URL_OVERRIDE_ENV_VAR;
use codex_login::TokenData;
use codex_login::auth::BedrockApiKeyAuth;
use codex_login::load_auth_dot_json;
use codex_login::login_with_api_key;
use codex_login::login_with_bedrock_api_key;
use codex_login::save_auth;
use codex_protocol::account::AmazonBedrockCredentialSource;
use codex_protocol::account::PlanType as AccountPlanType;
use codex_protocol::auth::AuthMode as DomainAuthMode;
use core_test_support::responses;
use pretty_assertions::assert_eq;
use serde_json::json;
use serial_test::serial;
use std::path::Path;
use std::time::Duration;
use tempfile::TempDir;
use tokio::time::timeout;
use url::Url;
use wiremock::Mock;
use wiremock::MockServer;
use wiremock::ResponseTemplate;
use wiremock::matchers::header;
use wiremock::matchers::method;
use wiremock::matchers::path;

const DEFAULT_READ_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(60);
const LOGIN_ISSUER_ENV_VAR: &str = "CODEX_APP_SERVER_LOGIN_ISSUER";
const LOGIN_OPEN_APP_URL_ENV_VAR: &str = "CODEX_APP_SERVER_DEV_OPEN_APP_URL";
const WORKSPACE_ID_ALLOWED: &str = "123e4567-e89b-42d3-a456-426614174000";
const WORKSPACE_ID_SECOND_ALLOWED: &str = "123e4567-e89b-42d3-a456-426614174001";
const WORKSPACE_ID_DISALLOWED: &str = "123e4567-e89b-42d3-a456-426614174002";
const WORKSPACE_ID_EMBEDDED: &str = "123e4567-e89b-42d3-a456-426614174010";
const WORKSPACE_ID_INITIAL: &str = "123e4567-e89b-42d3-a456-426614174011";
const WORKSPACE_ID_REFRESHED: &str = "123e4567-e89b-42d3-a456-426614174012";
const WORKSPACE_ID_DEVICE: &str = "123e4567-e89b-42d3-a456-426614174013";
const WORKSPACE_ID_STALE: &str = "123e4567-e89b-42d3-a456-426614174014";

// Helper to create a minimal config.toml for the app server
#[derive(Default)]
struct CreateConfigTomlParams {
    forced_method: Option<String>,
    forced_workspace_id: Option<String>,
    forced_workspace_ids: Option<Vec<String>>,
    requires_openai_auth: Option<bool>,
    base_url: Option<String>,
    chatgpt_base_url: Option<String>,
    model_provider_id: Option<String>,
    extra_provider_config: Option<String>,
}

fn create_config_toml(codex_home: &Path, params: CreateConfigTomlParams) -> std::io::Result<()> {
    let config_toml = codex_home.join("config.toml");
    let base_url = params
        .base_url
        .unwrap_or_else(|| "http://127.0.0.1:0/v1".to_string());
    let forced_line = if let Some(method) = params.forced_method {
        format!("forced_login_method = \"{method}\"\n")
    } else {
        String::new()
    };
    let forced_workspace_line = if let Some(ws) = params.forced_workspace_id {
        format!("forced_chatgpt_workspace_id = \"{ws}\"\n")
    } else if let Some(workspaces) = params.forced_workspace_ids {
        let workspaces = workspaces
            .into_iter()
            .map(|workspace_id| format!("\"{workspace_id}\""))
            .collect::<Vec<_>>()
            .join(", ");
        format!("forced_chatgpt_workspace_id = [{workspaces}]\n")
    } else {
        String::new()
    };
    let requires_line = match params.requires_openai_auth {
        Some(true) => "requires_openai_auth = true\n".to_string(),
        Some(false) => String::new(),
        None => String::new(),
    };
    let chatgpt_base_url_line = params
        .chatgpt_base_url
        .map(|url| format!("chatgpt_base_url = \"{url}\"\n"))
        .unwrap_or_default();
    let model_provider_id = params
        .model_provider_id
        .unwrap_or_else(|| "mock_provider".to_string());
    let provider_section = if model_provider_id == "mock_provider" {
        format!(
            r#"[model_providers.mock_provider]
name = "Mock provider for test"
base_url = "{base_url}"
wire_api = "responses"
request_max_retries = 0
stream_max_retries = 0
{requires_line}
"#
        )
    } else {
        params.extra_provider_config.unwrap_or_default()
    };
    let contents = format!(
        r#"
model = "mock-model"
approval_policy = "never"
sandbox_mode = "danger-full-access"
{chatgpt_base_url_line}
{forced_line}
{forced_workspace_line}
{chatgpt_base_url_line}

model_provider = "{model_provider_id}"

[features]
shell_snapshot = false

{provider_section}
"#
    );
    std::fs::write(config_toml, contents)
}

fn read_config_toml(codex_home: &Path) -> Result<toml::Value> {
    Ok(toml::from_str(&std::fs::read_to_string(
        codex_home.join("config.toml"),
    )?)?)
}

fn load_file_auth(codex_home: &Path) -> Result<Option<AuthDotJson>> {
    Ok(load_auth_dot_json(
        codex_home,
        AuthCredentialsStoreMode::File,
        AuthKeyringBackendKind::default(),
    )?)
}

fn aws_managed_bedrock_config() -> CreateConfigTomlParams {
    CreateConfigTomlParams {
        model_provider_id: Some("amazon-bedrock".to_string()),
        extra_provider_config: Some(
            r#"[model_providers.amazon-bedrock.aws]
profile = "codex-bedrock"
region = "us-west-2"
"#
            .to_string(),
        ),
        ..Default::default()
    }
}

async fn read_account(mcp: &mut TestAppServer) -> Result<GetAccountResponse> {
    let request_id = mcp
        .send_get_account_request(GetAccountParams {
            refresh_token: false,
        })
        .await?;
    timeout(DEFAULT_READ_TIMEOUT, mcp.read_response(request_id)).await?
}

async fn assert_account_updated(
    mcp: &mut TestAppServer,
    auth_mode: Option<AuthMode>,
) -> Result<()> {
    let payload: AccountUpdatedNotification = timeout(
        DEFAULT_READ_TIMEOUT,
        mcp.read_notification("account/updated"),
    )
    .await??;
    assert_eq!(
        payload,
        AccountUpdatedNotification {
            auth_mode,
            plan_type: None,
        }
    );
    Ok(())
}

pub(super) async fn seed_managed_accounts(
    codex_home: &Path,
    accounts: &[(&str, &str)],
) -> Result<()> {
    let manager = AuthManager::shared(
        codex_home.to_path_buf(),
        false,
        AuthCredentialsStoreMode::File,
        None,
        None,
        AuthKeyringBackendKind::Direct,
        None,
    )
    .await;
    for (email, workspace_id) in accounts {
        let mut tokens = TokenData::default();
        tokens.id_token.email = Some((*email).to_string());
        tokens.id_token.chatgpt_account_id = Some((*workspace_id).to_string());
        tokens.id_token.raw_jwt = encode_id_token(
            &ChatGptIdTokenClaims::new()
                .email(*email)
                .chatgpt_account_id(*workspace_id),
        )?;
        tokens.access_token = format!("access-{workspace_id}");
        tokens.refresh_token = format!("refresh-{workspace_id}");
        tokens.account_id = Some((*workspace_id).to_string());
        manager
            .upsert_managed_chatgpt_oauth(ManagedChatgptOauthCredentials {
                tokens,
                last_refresh: Utc::now(),
                oauth_api_key: None,
            })
            .await?;
    }
    Ok(())
}

fn managed_rate_response(used_percent: i64, window_seconds: i64) -> serde_json::Value {
    json!({
        "plan_type": "pro",
        "rate_limit": {
            "allowed": true,
            "limit_reached": false,
            "primary_window": {
                "used_percent": used_percent,
                "limit_window_seconds": window_seconds,
                "reset_after_seconds": 60,
                "reset_at": 1_800_000_000
            }
        }
    })
}

fn managed_token_profile(lifetime_tokens: i64) -> serde_json::Value {
    json!({
        "stats": {
            "lifetime_tokens": lifetime_tokens,
            "peak_daily_tokens": lifetime_tokens,
            "longest_running_turn_sec": 1,
            "current_streak_days": 1,
            "longest_streak_days": 1
        }
    })
}

async fn mock_device_code_usercode(server: &MockServer, interval_seconds: u64) {
    Mock::given(method("POST"))
        .and(path("/api/accounts/deviceauth/usercode"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "device_auth_id": "device-auth-123",
            "user_code": "CODE-12345",
            "interval": interval_seconds.to_string(),
        })))
        .mount(server)
        .await;
}

async fn mock_device_code_usercode_failure(server: &MockServer, status: u16) {
    Mock::given(method("POST"))
        .and(path("/api/accounts/deviceauth/usercode"))
        .respond_with(ResponseTemplate::new(status))
        .mount(server)
        .await;
}

async fn mock_device_code_token_success(server: &MockServer) {
    Mock::given(method("POST"))
        .and(path("/api/accounts/deviceauth/token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "authorization_code": "poll-code-321",
            "code_challenge": "code-challenge-321",
            "code_verifier": "code-verifier-321",
        })))
        .mount(server)
        .await;
}

async fn mock_device_code_token_failure(server: &MockServer, status: u16) {
    Mock::given(method("POST"))
        .and(path("/api/accounts/deviceauth/token"))
        .respond_with(ResponseTemplate::new(status))
        .mount(server)
        .await;
}

async fn mock_oauth_token(server: &MockServer, id_token: &str) {
    Mock::given(method("POST"))
        .and(path("/oauth/token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "id_token": id_token,
            "access_token": "access-token-123",
            "refresh_token": "refresh-token-123",
        })))
        .mount(server)
        .await;
}

#[tokio::test]
async fn logout_account_removes_auth_and_notifies() -> Result<()> {
    let codex_home = TempDir::new()?;
    create_config_toml(codex_home.path(), CreateConfigTomlParams::default())?;

    login_with_api_key(
        codex_home.path(),
        "sk-test-key",
        AuthCredentialsStoreMode::File,
        AuthKeyringBackendKind::default(),
    )?;
    assert!(codex_home.path().join("auth.json").exists());

    let mut mcp = TestAppServer::builder()
        .with_codex_home(codex_home.path())
        .without_auto_env()
        .with_env_overrides(&[("OPENAI_API_KEY", None)])
        .build_initialized_with_timeout(DEFAULT_READ_TIMEOUT)
        .await?;

    let id = mcp.send_logout_account_request().await?;
    let _ok: LogoutAccountResponse = timeout(DEFAULT_READ_TIMEOUT, mcp.read_response(id)).await??;

    let note = timeout(
        DEFAULT_READ_TIMEOUT,
        mcp.read_stream_until_notification_message("account/updated"),
    )
    .await??;
    let parsed: ServerNotification = note.try_into()?;
    let ServerNotification::AccountUpdated(payload) = parsed else {
        bail!("unexpected notification: {parsed:?}");
    };
    assert!(
        payload.auth_mode.is_none(),
        "auth_method should be None after logout"
    );
    assert_eq!(payload.plan_type, None);

    assert!(
        !codex_home.path().join("auth.json").exists(),
        "auth.json should be deleted"
    );

    let get_id = mcp
        .send_get_account_request(GetAccountParams {
            refresh_token: false,
        })
        .await?;
    let account: GetAccountResponse =
        timeout(DEFAULT_READ_TIMEOUT, mcp.read_response(get_id)).await??;
    assert_eq!(account.account, None);
    Ok(())
}

#[tokio::test]
async fn logout_account_succeeds_when_config_reload_fails() -> Result<()> {
    let codex_home = TempDir::new()?;
    create_config_toml(codex_home.path(), CreateConfigTomlParams::default())?;
    login_with_api_key(
        codex_home.path(),
        "sk-test-key",
        AuthCredentialsStoreMode::File,
        AuthKeyringBackendKind::default(),
    )?;

    let mut mcp = TestAppServer::builder()
        .with_codex_home(codex_home.path())
        .without_auto_env()
        .with_env_overrides(&[("OPENAI_API_KEY", None)])
        .build_initialized_with_timeout(DEFAULT_READ_TIMEOUT)
        .await?;

    std::fs::write(codex_home.path().join("config.toml"), "invalid = [")?;

    let request_id = mcp.send_logout_account_request().await?;
    let response = timeout(
        DEFAULT_READ_TIMEOUT,
        mcp.read_stream_until_response_message(RequestId::Integer(request_id)),
    )
    .await??;
    assert_eq!(
        to_response::<LogoutAccountResponse>(response)?,
        LogoutAccountResponse {}
    );
    assert_eq!(load_file_auth(codex_home.path())?, None);
    assert_account_updated(&mut mcp, /*auth_mode*/ None).await?;

    Ok(())
}

#[tokio::test]
async fn scoped_account_list_notifies_selection_and_targeted_logout_returns_stable_id() -> Result<()>
{
    let codex_home = TempDir::new()?;
    create_config_toml(codex_home.path(), CreateConfigTomlParams::default())?;
    write_chatgpt_auth(
        codex_home.path(),
        ChatGptAuthFixture::new("access-token")
            .account_id(WORKSPACE_ID_INITIAL)
            .email("Managed.User@Example.com")
            .plan_type("pro"),
        AuthCredentialsStoreMode::File,
    )?;

    let mut mcp = TestAppServer::builder()
        .with_codex_home(codex_home.path())
        .without_auto_env()
        .with_env_overrides(&[("OPENAI_API_KEY", None)])
        .build()
        .await?;
    timeout(DEFAULT_READ_TIMEOUT, mcp.initialize()).await??;

    let model_only_id = mcp
        .send_list_accounts_request(json!({
            "model": "mock-model",
            "refreshTokens": false,
            "refreshUsage": false
        }))
        .await?;
    let model_only_resp: JSONRPCResponse = timeout(
        DEFAULT_READ_TIMEOUT,
        mcp.read_stream_until_response_message(RequestId::Integer(model_only_id)),
    )
    .await??;
    let model_only: ListAccountsResponse = to_response(model_only_resp)?;
    assert_eq!(model_only.accounts.len(), 1);
    assert_eq!(
        model_only.selection_revision, None,
        "model-only account/list must remain unscoped"
    );
    assert!(
        timeout(Duration::from_millis(250), mcp.read_stream_message())
            .await
            .is_err(),
        "model-only account/list must not publish a selection notification"
    );
    let thread_request_id = mcp
        .send_thread_start_request(codex_app_server_protocol::ThreadStartParams {
            model: Some("mock-model".to_string()),
            environments: Some(Vec::new()),
            ..Default::default()
        })
        .await?;
    let thread_response: JSONRPCResponse = timeout(
        DEFAULT_READ_TIMEOUT,
        mcp.read_stream_until_response_message(RequestId::Integer(thread_request_id)),
    )
    .await??;
    let thread =
        to_response::<codex_app_server_protocol::ThreadStartResponse>(thread_response)?.thread;

    let list_id = mcp
        .send_list_accounts_request(json!({
            "threadId": thread.id,
            "model": "mock-model",
            "refreshTokens": false,
            "refreshUsage": false
        }))
        .await?;
    let list_resp: JSONRPCResponse = timeout(
        DEFAULT_READ_TIMEOUT,
        mcp.read_stream_until_response_message(RequestId::Integer(list_id)),
    )
    .await??;
    let list: ListAccountsResponse = to_response(list_resp)?;
    assert_eq!(list.accounts.len(), 1);
    let managed_id = list.accounts[0].managed_account_id.clone();
    assert_eq!(managed_id, "email:managed.user@example.com");
    assert!(list.accounts[0].credential_revision > 0);
    assert!(
        list.accounts[0].account_revision >= list.accounts[0].credential_revision,
        "mutable account state must never precede its credential generation"
    );
    assert_eq!(
        list.selected_account_id.as_deref(),
        Some(managed_id.as_str())
    );
    let selection_revision = list
        .selection_revision
        .expect("scoped account list should carry a selection revision");
    let pool_revision = list.pool_revision;

    let note = timeout(
        DEFAULT_READ_TIMEOUT,
        mcp.read_stream_until_notification_message("account/selection/updated"),
    )
    .await??;
    let parsed: ServerNotification = note.try_into()?;
    let ServerNotification::AccountSelectionUpdated(payload) = parsed else {
        bail!("unexpected notification: {parsed:?}");
    };
    assert_eq!(payload.thread_id, thread.id.to_string());
    assert_eq!(
        payload.selected_account_id.as_deref(),
        Some(managed_id.as_str())
    );
    assert_eq!(payload.selection_revision, selection_revision);

    let logout_id = mcp
        .send_logout_account_request_with_params(json!({
            "accountId": "  MANAGED.USER@EXAMPLE.COM  ",
            "all": false
        }))
        .await?;
    let logout_resp: JSONRPCResponse = timeout(
        DEFAULT_READ_TIMEOUT,
        mcp.read_stream_until_response_message(RequestId::Integer(logout_id)),
    )
    .await??;
    let logout: LogoutAccountResponse = to_response(logout_resp)?;
    assert_eq!(logout.removed_account_ids, vec![managed_id]);
    assert!(logout.accounts.is_empty());
    assert_eq!(logout.selected_account_id, None);

    let note = timeout(
        DEFAULT_READ_TIMEOUT,
        mcp.read_stream_until_notification_message("account/pool/updated"),
    )
    .await??;
    let parsed: ServerNotification = note.try_into()?;
    let ServerNotification::AccountPoolUpdated(payload) = parsed else {
        bail!("unexpected notification: {parsed:?}");
    };
    assert!(payload.accounts.is_empty());
    assert!(payload.pool_revision > pool_revision);

    let note = timeout(
        DEFAULT_READ_TIMEOUT,
        mcp.read_stream_until_notification_message("account/selection/updated"),
    )
    .await??;
    let parsed: ServerNotification = note.try_into()?;
    let ServerNotification::AccountSelectionUpdated(payload) = parsed else {
        bail!("unexpected notification: {parsed:?}");
    };
    assert_eq!(payload.thread_id, thread.id.to_string());
    assert_eq!(payload.selected_account_id, None);
    assert!(payload.selection_revision > selection_revision);
    Ok(())
}

#[tokio::test]
async fn managed_to_api_key_login_publishes_monotonic_pool_clearing() -> Result<()> {
    let codex_home = TempDir::new()?;
    create_config_toml(codex_home.path(), CreateConfigTomlParams::default())?;
    write_chatgpt_auth(
        codex_home.path(),
        ChatGptAuthFixture::new("access-token")
            .account_id(WORKSPACE_ID_INITIAL)
            .email("managed@example.com")
            .plan_type("pro"),
        AuthCredentialsStoreMode::File,
    )?;

    let mut mcp = TestAppServer::builder()
        .with_codex_home(codex_home.path())
        .without_auto_env()
        .with_env_overrides(&[("OPENAI_API_KEY", None)])
        .build()
        .await?;
    timeout(DEFAULT_READ_TIMEOUT, mcp.initialize()).await??;

    let thread_request_id = mcp
        .send_thread_start_request(codex_app_server_protocol::ThreadStartParams {
            model: Some("mock-model".to_string()),
            environments: Some(Vec::new()),
            ..Default::default()
        })
        .await?;
    let thread_response = timeout(
        DEFAULT_READ_TIMEOUT,
        mcp.read_stream_until_response_message(RequestId::Integer(thread_request_id)),
    )
    .await??;
    let thread =
        to_response::<codex_app_server_protocol::ThreadStartResponse>(thread_response)?.thread;
    let list_id = mcp
        .send_list_accounts_request(json!({
            "threadId": thread.id,
            "model": "mock-model",
            "refreshTokens": false,
            "refreshUsage": false
        }))
        .await?;
    let before: ListAccountsResponse = to_response(
        timeout(
            DEFAULT_READ_TIMEOUT,
            mcp.read_stream_until_response_message(RequestId::Integer(list_id)),
        )
        .await??,
    )?;
    assert_eq!(before.accounts.len(), 1);
    assert!(before.selected_account_id.is_some());
    let selection_revision = before
        .selection_revision
        .expect("managed scoped list must expose a selection revision");
    let initial_selection = timeout(
        DEFAULT_READ_TIMEOUT,
        mcp.read_stream_until_notification_message("account/selection/updated"),
    )
    .await??;
    let parsed: ServerNotification = initial_selection.try_into()?;
    let ServerNotification::AccountSelectionUpdated(initial_selection) = parsed else {
        bail!("unexpected notification: {parsed:?}");
    };
    assert_eq!(initial_selection.selection_revision, selection_revision);
    let login_id = mcp
        .send_login_account_api_key_request("sk-replacement-key")
        .await?;
    let mut login_response = None;
    let mut account_updated = false;
    let mut login_completed = false;
    let mut clearing = None;
    let mut selection_removal = None;
    timeout(DEFAULT_READ_TIMEOUT, async {
        while login_response.is_none()
            || !account_updated
            || !login_completed
            || clearing.is_none()
            || selection_removal.is_none()
        {
            match mcp.read_stream_message().await? {
                JSONRPCMessage::Response(response)
                    if response.id == RequestId::Integer(login_id) =>
                {
                    login_response = Some(response);
                }
                JSONRPCMessage::Notification(notification)
                    if notification.method == "account/login/completed" =>
                {
                    login_completed = true;
                }
                JSONRPCMessage::Notification(notification)
                    if notification.method == "account/updated" =>
                {
                    account_updated = true;
                }
                JSONRPCMessage::Notification(notification)
                    if notification.method == "account/pool/updated" =>
                {
                    let parsed: ServerNotification = notification.try_into()?;
                    let ServerNotification::AccountPoolUpdated(payload) = parsed else {
                        unreachable!("method matched account/pool/updated");
                    };
                    clearing = Some(payload);
                }
                JSONRPCMessage::Notification(notification)
                    if notification.method == "account/selection/updated" =>
                {
                    let parsed: ServerNotification = notification.try_into()?;
                    let ServerNotification::AccountSelectionUpdated(payload) = parsed else {
                        unreachable!("method matched account/selection/updated");
                    };
                    selection_removal = Some(payload);
                }
                message => {
                    bail!("unexpected message during managed-to-API-key cutover: {message:?}")
                }
            }
        }
        Ok::<(), anyhow::Error>(())
    })
    .await??;
    let _: LoginAccountResponse = to_response(login_response.expect("login response observed"))?;
    let clearing = clearing.expect("pool clearing notification observed");
    assert!(clearing.accounts.is_empty());
    assert!(
        clearing.pool_revision > before.pool_revision,
        "managed-to-nonmanaged cutover must advance the durable pool generation"
    );
    let selection_removal = selection_removal.expect("selection removal notification observed");
    assert_eq!(selection_removal.thread_id, thread.id.to_string());
    assert_eq!(selection_removal.selected_account_id, None);
    assert!(
        selection_removal.selection_revision > selection_revision,
        "managed-to-nonmanaged cutover must advance the scoped selection generation"
    );
    assert!(
        timeout(Duration::from_millis(250), mcp.read_stream_message())
            .await
            .is_err(),
        "managed-to-API-key cutover must publish one clearing pool update"
    );

    let scoped_id = mcp
        .send_list_accounts_request(json!({
            "threadId": thread.id,
            "model": "mock-model",
            "refreshTokens": false,
            "refreshUsage": false
        }))
        .await?;
    let after: ListAccountsResponse = to_response(
        timeout(
            DEFAULT_READ_TIMEOUT,
            mcp.read_stream_until_response_message(RequestId::Integer(scoped_id)),
        )
        .await??,
    )?;
    assert!(after.accounts.is_empty());
    assert_eq!(after.pool_revision, clearing.pool_revision);
    assert_eq!(after.selection_revision, None);
    assert!(
        timeout(Duration::from_millis(250), mcp.read_stream_message())
            .await
            .is_err(),
        "scoped nonpooled list must not publish a selection update"
    );
    Ok(())
}

#[tokio::test]
async fn external_auth_overlay_hides_and_preserves_managed_account_pool() -> Result<()> {
    let codex_home = TempDir::new()?;
    create_config_toml(codex_home.path(), CreateConfigTomlParams::default())?;
    seed_managed_accounts(
        codex_home.path(),
        &[("persistent@example.com", WORKSPACE_ID_INITIAL)],
    )
    .await?;

    let mut mcp = TestAppServer::builder()
        .with_codex_home(codex_home.path())
        .without_auto_env()
        .with_env_overrides(&[("OPENAI_API_KEY", None)])
        .build()
        .await?;
    timeout(DEFAULT_READ_TIMEOUT, mcp.initialize()).await??;
    let before_id = mcp
        .send_list_accounts_request(json!({
            "refreshTokens": false,
            "refreshUsage": false
        }))
        .await?;
    let before: ListAccountsResponse = to_response(
        timeout(
            DEFAULT_READ_TIMEOUT,
            mcp.read_stream_until_response_message(RequestId::Integer(before_id)),
        )
        .await??,
    )?;
    assert_eq!(before.accounts.len(), 1);

    let access_token = encode_id_token(
        &ChatGptIdTokenClaims::new()
            .email("external@example.com")
            .chatgpt_account_id(WORKSPACE_ID_EMBEDDED),
    )?;
    let set_id = mcp
        .send_chatgpt_auth_tokens_login_request(
            access_token,
            WORKSPACE_ID_EMBEDDED.to_string(),
            Some("pro".to_string()),
        )
        .await?;
    let set_resp: JSONRPCResponse = timeout(
        DEFAULT_READ_TIMEOUT,
        mcp.read_stream_until_response_message(RequestId::Integer(set_id)),
    )
    .await??;
    let response: LoginAccountResponse = to_response(set_resp)?;
    assert_eq!(response, LoginAccountResponse::ChatgptAuthTokens {});
    let _updated = timeout(
        DEFAULT_READ_TIMEOUT,
        mcp.read_stream_until_notification_message("account/updated"),
    )
    .await??;

    assert!(
        timeout(
            Duration::from_millis(250),
            mcp.read_stream_until_notification_message("account/pool/updated"),
        )
        .await
        .is_err(),
        "external overlay activation must not publish hidden managed rows"
    );

    let list_id = mcp
        .send_list_accounts_request(json!({
            "threadId": "external-overlay-thread",
            "refreshTokens": true,
            "refreshUsage": true
        }))
        .await?;
    let list_resp: JSONRPCResponse = timeout(
        DEFAULT_READ_TIMEOUT,
        mcp.read_stream_until_response_message(RequestId::Integer(list_id)),
    )
    .await??;
    let hidden: ListAccountsResponse = to_response(list_resp)?;
    assert!(hidden.accounts.is_empty());
    assert_eq!(hidden.selected_account_id, None);
    assert_eq!(hidden.selection_revision, None);
    assert_eq!(
        hidden.pool_revision, before.pool_revision,
        "the hidden overlay response must preserve the durable stored pool revision"
    );

    let logout_id = mcp.send_logout_account_request().await?;
    let logout_resp: JSONRPCResponse = timeout(
        DEFAULT_READ_TIMEOUT,
        mcp.read_stream_until_response_message(RequestId::Integer(logout_id)),
    )
    .await??;
    let logout: LogoutAccountResponse = to_response(logout_resp)?;
    assert!(logout.removed_account_ids.is_empty());
    assert_eq!(logout.accounts.len(), 1);
    assert_eq!(
        logout.accounts[0].managed_account_id,
        "email:persistent@example.com"
    );

    let reveal_id = mcp
        .send_list_accounts_request(json!({
            "refreshTokens": false,
            "refreshUsage": false
        }))
        .await?;
    let reveal_resp: JSONRPCResponse = timeout(
        DEFAULT_READ_TIMEOUT,
        mcp.read_stream_until_response_message(RequestId::Integer(reveal_id)),
    )
    .await??;
    let revealed: ListAccountsResponse = to_response(reveal_resp)?;
    assert_eq!(revealed.accounts.len(), 1);
    assert_eq!(
        revealed.accounts[0].managed_account_id,
        "email:persistent@example.com"
    );
    Ok(())
}

#[tokio::test]
async fn targeted_logout_resolves_stored_alias_raw_id_and_unicode_email_under_overlay() -> Result<()>
{
    let codex_home = TempDir::new()?;
    create_config_toml(codex_home.path(), CreateConfigTomlParams::default())?;
    seed_managed_accounts(
        codex_home.path(),
        &[
            ("legacy@example.com", WORKSPACE_ID_INITIAL),
            ("Current@Example.com", WORKSPACE_ID_INITIAL),
            ("raw@example.com", WORKSPACE_ID_ALLOWED),
            ("Üser@Example.com", WORKSPACE_ID_SECOND_ALLOWED),
        ],
    )
    .await?;
    let mut stored = load_auth_dot_json(
        codex_home.path(),
        AuthCredentialsStoreMode::File,
        AuthKeyringBackendKind::Direct,
    )?
    .expect("seeded managed auth");
    let pool = stored
        .managed_chatgpt
        .as_mut()
        .expect("seeded managed pool");
    pool.accounts
        .retain(|account| account.identity_key != "email:legacy@example.com");
    pool.accounts
        .iter_mut()
        .find(|account| account.identity_key == "email:current@example.com")
        .expect("current managed identity")
        .identity_aliases
        .push("email:legacy@example.com".to_string());
    save_auth(
        codex_home.path(),
        &stored,
        AuthCredentialsStoreMode::File,
        AuthKeyringBackendKind::Direct,
    )?;

    let mut mcp = TestAppServer::builder()
        .with_codex_home(codex_home.path())
        .without_auto_env()
        .with_env_overrides(&[("OPENAI_API_KEY", None)])
        .build()
        .await?;
    timeout(DEFAULT_READ_TIMEOUT, mcp.initialize()).await??;

    let access_token = encode_id_token(
        &ChatGptIdTokenClaims::new()
            .email("external@example.com")
            .chatgpt_account_id(WORKSPACE_ID_EMBEDDED),
    )?;
    let set_id = mcp
        .send_chatgpt_auth_tokens_login_request(
            access_token,
            WORKSPACE_ID_EMBEDDED.to_string(),
            Some("pro".to_string()),
        )
        .await?;
    let _: LoginAccountResponse = to_response(
        timeout(
            DEFAULT_READ_TIMEOUT,
            mcp.read_stream_until_response_message(RequestId::Integer(set_id)),
        )
        .await??,
    )?;
    timeout(
        DEFAULT_READ_TIMEOUT,
        mcp.read_stream_until_notification_message("account/updated"),
    )
    .await??;

    let alias_id = mcp
        .send_logout_account_request_with_params(json!({
            "accountId": "email:legacy@example.com",
            "all": false
        }))
        .await?;
    let alias_logout: LogoutAccountResponse = to_response(
        timeout(
            DEFAULT_READ_TIMEOUT,
            mcp.read_stream_until_response_message(RequestId::Integer(alias_id)),
        )
        .await??,
    )?;
    assert_eq!(
        alias_logout.removed_account_ids,
        vec!["email:current@example.com"]
    );
    assert_eq!(
        alias_logout
            .accounts
            .iter()
            .map(|account| account.managed_account_id.as_str())
            .collect::<Vec<_>>(),
        vec!["email:raw@example.com", "email:üser@example.com"]
    );
    assert_eq!(alias_logout.selected_account_id, None);

    let raw_id = mcp
        .send_logout_account_request_with_params(json!({
            "accountId": WORKSPACE_ID_ALLOWED,
            "all": false
        }))
        .await?;
    let raw_logout: LogoutAccountResponse = to_response(
        timeout(
            DEFAULT_READ_TIMEOUT,
            mcp.read_stream_until_response_message(RequestId::Integer(raw_id)),
        )
        .await??,
    )?;
    assert_eq!(
        raw_logout.removed_account_ids,
        vec!["email:raw@example.com"]
    );
    assert_eq!(raw_logout.accounts.len(), 1);
    assert_eq!(
        raw_logout.accounts[0].managed_account_id,
        "email:üser@example.com"
    );

    let unicode_email_id = mcp
        .send_logout_account_request_with_params(json!({
            "accountId": "ÜSER@EXAMPLE.COM",
            "all": false
        }))
        .await?;
    let unicode_logout: LogoutAccountResponse = to_response(
        timeout(
            DEFAULT_READ_TIMEOUT,
            mcp.read_stream_until_response_message(RequestId::Integer(unicode_email_id)),
        )
        .await??,
    )?;
    assert_eq!(
        unicode_logout.removed_account_ids,
        vec!["email:üser@example.com"]
    );
    assert!(unicode_logout.accounts.is_empty());
    assert_eq!(unicode_logout.selected_account_id, None);
    Ok(())
}

#[tokio::test]
async fn account_list_timeout_does_not_suppress_a_healthy_sibling() -> Result<()> {
    let codex_home = TempDir::new()?;
    let mock_server = MockServer::start().await;
    create_config_toml(
        codex_home.path(),
        CreateConfigTomlParams {
            base_url: Some(mock_server.uri()),
            chatgpt_base_url: Some(mock_server.uri()),
            ..Default::default()
        },
    )?;
    seed_managed_accounts(
        codex_home.path(),
        &[
            ("a@example.com", WORKSPACE_ID_ALLOWED),
            ("b@example.com", WORKSPACE_ID_SECOND_ALLOWED),
        ],
    )
    .await?;

    Mock::given(method("GET"))
        .and(path("/api/codex/usage"))
        .and(header(
            "authorization",
            format!("Bearer access-{WORKSPACE_ID_ALLOWED}"),
        ))
        .respond_with(
            ResponseTemplate::new(200)
                .set_delay(Duration::from_secs(30))
                .set_body_json(managed_rate_response(90, 900)),
        )
        .expect(1)
        .mount(&mock_server)
        .await;
    Mock::given(method("GET"))
        .and(path("/api/codex/profiles/me"))
        .and(header(
            "authorization",
            format!("Bearer access-{WORKSPACE_ID_ALLOWED}"),
        ))
        .respond_with(ResponseTemplate::new(200).set_body_json(managed_token_profile(10)))
        .expect(1)
        .mount(&mock_server)
        .await;
    Mock::given(method("GET"))
        .and(path("/api/codex/usage"))
        .and(header(
            "authorization",
            format!("Bearer access-{WORKSPACE_ID_SECOND_ALLOWED}"),
        ))
        .respond_with(ResponseTemplate::new(200).set_body_json(managed_rate_response(20, 3600)))
        .expect(1)
        .mount(&mock_server)
        .await;
    Mock::given(method("GET"))
        .and(path("/api/codex/profiles/me"))
        .and(header(
            "authorization",
            format!("Bearer access-{WORKSPACE_ID_SECOND_ALLOWED}"),
        ))
        .respond_with(ResponseTemplate::new(200).set_body_json(managed_token_profile(20)))
        .expect(1)
        .mount(&mock_server)
        .await;

    let mut mcp = TestAppServer::builder()
        .with_codex_home(codex_home.path())
        .without_auto_env()
        .with_env_overrides(&[("OPENAI_API_KEY", None)])
        .build()
        .await?;
    timeout(DEFAULT_READ_TIMEOUT, mcp.initialize()).await??;

    let request_id = mcp
        .send_list_accounts_request(json!({
            "refreshTokens": false,
            "refreshUsage": true
        }))
        .await?;
    let response: JSONRPCResponse = timeout(
        Duration::from_secs(25),
        mcp.read_stream_until_response_message(RequestId::Integer(request_id)),
    )
    .await??;
    let response: ListAccountsResponse = to_response(response)?;
    assert_eq!(response.accounts.len(), 2);
    let healthy = response
        .accounts
        .iter()
        .find(|account| account.managed_account_id == "email:b@example.com")
        .expect("healthy sibling must remain in the response");
    assert_eq!(healthy.usage.state, ManagedChatgptAccountUsageState::Fresh);
    assert_eq!(healthy.usage.rate_limits.len(), 1);
    assert_eq!(
        healthy.usage.rate_limits[0]
            .primary
            .as_ref()
            .and_then(|window| window.window_duration_mins),
        Some(60)
    );
    assert_eq!(
        healthy
            .usage
            .token_usage
            .as_ref()
            .and_then(|usage| usage.lifetime_tokens),
        Some(20)
    );
    Ok(())
}

#[tokio::test]
async fn account_list_refresh_timeout_is_globally_observable() -> Result<()> {
    let codex_home = TempDir::new()?;
    let mock_server = MockServer::start().await;
    create_config_toml(
        codex_home.path(),
        CreateConfigTomlParams {
            base_url: Some(mock_server.uri()),
            chatgpt_base_url: Some(mock_server.uri()),
            ..Default::default()
        },
    )?;

    seed_managed_accounts(
        codex_home.path(),
        &[("zz-startup@example.com", WORKSPACE_ID_SECOND_ALLOWED)],
    )
    .await?;
    let mut tokens = TokenData::default();
    tokens.id_token.email = Some("timeout@example.com".to_string());
    tokens.id_token.chatgpt_account_id = Some(WORKSPACE_ID_ALLOWED.to_string());
    tokens.id_token.raw_jwt = encode_id_token(
        &ChatGptIdTokenClaims::new()
            .email("timeout@example.com")
            .chatgpt_account_id(WORKSPACE_ID_ALLOWED),
    )?;
    tokens.access_token = "expired-access-token".to_string();
    tokens.refresh_token = "refresh-timeout".to_string();
    tokens.account_id = Some(WORKSPACE_ID_ALLOWED.to_string());
    let manager = AuthManager::shared(
        codex_home.path().to_path_buf(),
        false,
        AuthCredentialsStoreMode::File,
        None,
        None,
        AuthKeyringBackendKind::Direct,
        None,
    )
    .await;
    manager
        .upsert_managed_chatgpt_oauth(ManagedChatgptOauthCredentials {
            tokens,
            last_refresh: Utc::now() - ChronoDuration::days(9),
            oauth_api_key: None,
        })
        .await?;
    let startup_selection = manager
        .list_managed_chatgpt_accounts(&codex_login::ManagedChatgptSelectionScope::default())
        .await?;
    assert_eq!(
        startup_selection.selected_account_id.as_deref(),
        Some("email:zz-startup@example.com"),
        "startup must select the fresh account so the RPC owns the stale refresh"
    );
    drop(manager);

    Mock::given(method("POST"))
        .and(path("/oauth/token"))
        .respond_with(ResponseTemplate::new(200).set_delay(Duration::from_secs(30)))
        .expect(1..=2)
        .mount(&mock_server)
        .await;
    let refresh_url = format!("{}/oauth/token", mock_server.uri());
    let (mut process, bind_addr) = spawn_websocket_server_with_env(
        codex_home.path(),
        &[
            (REFRESH_TOKEN_URL_OVERRIDE_ENV_VAR, refresh_url.as_str()),
            ("OPENAI_API_KEY", ""),
        ],
    )
    .await?;
    let mut requester = connect_websocket(bind_addr).await?;
    let mut observer = connect_websocket(bind_addr).await?;
    send_initialize_request(&mut requester, 1, "refresh_requester").await?;
    read_response_for_id(&mut requester, 1).await?;
    send_initialize_request(&mut observer, 2, "refresh_observer").await?;
    read_response_for_id(&mut observer, 2).await?;

    send_request(
        &mut requester,
        "account/list",
        3,
        Some(json!({
            "refreshTokens": true,
            "refreshUsage": false
        })),
    )
    .await?;
    let notification = timeout(
        Duration::from_secs(25),
        read_notification_for_method(&mut observer, "account/pool/updated"),
    )
    .await??;
    let parsed: ServerNotification = notification.try_into()?;
    let ServerNotification::AccountPoolUpdated(payload) = parsed else {
        bail!("unexpected notification: {parsed:?}");
    };
    assert_eq!(payload.accounts.len(), 2);
    let timeout_status = payload
        .accounts
        .iter()
        .find(|account| account.email.as_deref() == Some("timeout@example.com"))
        .expect("timed out account must remain in the notification")
        .refresh_status
        .clone();
    assert!(matches!(
        &timeout_status,
        ManagedChatgptAccountRefreshStatus::TransientUnavailable { .. }
    ));

    let first: ListAccountsResponse = to_response(
        timeout(
            Duration::from_secs(25),
            read_response_for_id(&mut requester, 3),
        )
        .await??,
    )?;
    assert_eq!(first.accounts.len(), 2);
    assert_eq!(
        first
            .accounts
            .iter()
            .find(|account| account.email.as_deref() == Some("timeout@example.com"))
            .expect("timed out account must remain in the response")
            .refresh_status,
        timeout_status
    );

    send_request(
        &mut observer,
        "account/list",
        4,
        Some(json!({
            "refreshTokens": false,
            "refreshUsage": false
        })),
    )
    .await?;
    let next: ListAccountsResponse =
        to_response(timeout(DEFAULT_READ_TIMEOUT, read_response_for_id(&mut observer, 4)).await??)?;
    assert_eq!(next.accounts.len(), 2);
    assert_eq!(
        next.accounts
            .iter()
            .find(|account| account.email.as_deref() == Some("timeout@example.com"))
            .expect("timed out account must remain globally observable")
            .refresh_status,
        timeout_status
    );

    mock_server.verify().await;
    process.kill().await?;
    Ok(())
}

#[tokio::test]
async fn account_list_usage_only_skips_oauth_and_maps_missing_plan_to_unknown() -> Result<()> {
    let codex_home = TempDir::new()?;
    let mock_server = MockServer::start().await;
    create_config_toml(
        codex_home.path(),
        CreateConfigTomlParams {
            base_url: Some(mock_server.uri()),
            chatgpt_base_url: Some(mock_server.uri()),
            ..Default::default()
        },
    )?;
    let manager = AuthManager::shared(
        codex_home.path().to_path_buf(),
        false,
        AuthCredentialsStoreMode::File,
        None,
        None,
        AuthKeyringBackendKind::Direct,
        None,
    )
    .await;
    let mut tokens = TokenData::default();
    tokens.id_token.email = Some("usage-only@example.com".to_string());
    tokens.id_token.chatgpt_account_id = Some(WORKSPACE_ID_ALLOWED.to_string());
    tokens.id_token.raw_jwt = encode_id_token(
        &ChatGptIdTokenClaims::new()
            .email("usage-only@example.com")
            .chatgpt_account_id(WORKSPACE_ID_ALLOWED),
    )?;
    tokens.access_token = "expired-usage-access-token".to_string();
    tokens.refresh_token = "unused-refresh-token".to_string();
    tokens.account_id = Some(WORKSPACE_ID_ALLOWED.to_string());
    manager
        .upsert_managed_chatgpt_oauth(ManagedChatgptOauthCredentials {
            tokens,
            last_refresh: Utc::now() - ChronoDuration::days(9),
            oauth_api_key: None,
        })
        .await?;
    drop(manager);

    Mock::given(method("POST"))
        .and(path("/oauth/token"))
        .respond_with(ResponseTemplate::new(500))
        .expect(2)
        .mount(&mock_server)
        .await;

    let refresh_url = format!("{}/oauth/token", mock_server.uri());
    let (mut process, bind_addr) = spawn_websocket_server_with_env(
        codex_home.path(),
        &[
            (REFRESH_TOKEN_URL_OVERRIDE_ENV_VAR, refresh_url.as_str()),
            ("OPENAI_API_KEY", ""),
        ],
    )
    .await?;
    let mut requester = connect_websocket(bind_addr).await?;
    send_initialize_request(&mut requester, 1, "usage_only_requester").await?;
    read_response_for_id(&mut requester, 1).await?;
    timeout(DEFAULT_READ_TIMEOUT, async {
        loop {
            if mock_server
                .received_requests()
                .await
                .is_some_and(|requests| requests.len() >= 2)
            {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await?;
    mock_server.reset().await;
    Mock::given(method("POST"))
        .and(path("/oauth/token"))
        .respond_with(ResponseTemplate::new(500))
        .expect(0)
        .mount(&mock_server)
        .await;
    Mock::given(method("GET"))
        .and(path("/api/codex/usage"))
        .respond_with(ResponseTemplate::new(200).set_body_json(managed_rate_response(15, 3600)))
        .expect(1)
        .mount(&mock_server)
        .await;
    Mock::given(method("GET"))
        .and(path("/api/codex/profiles/me"))
        .respond_with(ResponseTemplate::new(200).set_body_json(managed_token_profile(42)))
        .expect(1)
        .mount(&mock_server)
        .await;
    send_request(
        &mut requester,
        "account/list",
        2,
        Some(json!({
            "refreshTokens": false,
            "refreshUsage": true
        })),
    )
    .await?;
    let response: ListAccountsResponse = to_response(
        timeout(
            DEFAULT_READ_TIMEOUT,
            read_response_for_id(&mut requester, 2),
        )
        .await??,
    )?;
    assert_eq!(response.accounts.len(), 1);
    assert_eq!(response.accounts[0].plan_type, AccountPlanType::Unknown);
    assert_eq!(
        response.accounts[0].usage.state,
        ManagedChatgptAccountUsageState::Fresh
    );
    assert_eq!(
        response.accounts[0]
            .usage
            .token_usage
            .as_ref()
            .and_then(|usage| usage.lifetime_tokens),
        Some(42)
    );
    mock_server.verify().await;
    process.kill().await?;
    Ok(())
}

#[tokio::test]
async fn account_list_transient_refresh_preserves_prior_usage() -> Result<()> {
    let codex_home = TempDir::new()?;
    let mock_server = MockServer::start().await;
    create_config_toml(
        codex_home.path(),
        CreateConfigTomlParams {
            base_url: Some(mock_server.uri()),
            chatgpt_base_url: Some(mock_server.uri()),
            ..Default::default()
        },
    )?;
    seed_managed_accounts(
        codex_home.path(),
        &[("preserved@example.com", WORKSPACE_ID_ALLOWED)],
    )
    .await?;
    Mock::given(method("GET"))
        .and(path("/api/codex/usage"))
        .respond_with(ResponseTemplate::new(200).set_body_json(managed_rate_response(25, 3600)))
        .expect(1)
        .mount(&mock_server)
        .await;
    Mock::given(method("GET"))
        .and(path("/api/codex/profiles/me"))
        .respond_with(ResponseTemplate::new(200).set_body_json(managed_token_profile(25)))
        .expect(1)
        .mount(&mock_server)
        .await;

    let mut mcp = TestAppServer::builder()
        .with_codex_home(codex_home.path())
        .without_auto_env()
        .with_env_overrides(&[("OPENAI_API_KEY", None)])
        .build()
        .await?;
    timeout(DEFAULT_READ_TIMEOUT, mcp.initialize()).await??;
    let request_id = mcp
        .send_list_accounts_request(json!({
            "refreshTokens": false,
            "refreshUsage": true
        }))
        .await?;
    let note = timeout(
        DEFAULT_READ_TIMEOUT,
        mcp.read_stream_until_notification_message("account/usage/updated"),
    )
    .await??;
    let parsed: ServerNotification = note.try_into()?;
    let ServerNotification::AccountUsageUpdated(payload) = parsed else {
        bail!("unexpected notification: {parsed:?}");
    };
    assert_eq!(payload.managed_account_id, "email:preserved@example.com");
    assert!(
        !payload.usage.rate_limits.is_empty(),
        "the row-revision update must carry refreshed rate limits with usage"
    );
    let response: JSONRPCResponse = timeout(
        DEFAULT_READ_TIMEOUT,
        mcp.read_stream_until_response_message(RequestId::Integer(request_id)),
    )
    .await??;
    let first: ListAccountsResponse = to_response(response)?;
    let known_usage = first.accounts[0].usage.clone();
    assert_eq!(known_usage.state, ManagedChatgptAccountUsageState::Fresh);

    mock_server.reset().await;
    Mock::given(method("GET"))
        .and(path("/api/codex/usage"))
        .respond_with(ResponseTemplate::new(503))
        .expect(1)
        .mount(&mock_server)
        .await;
    Mock::given(method("GET"))
        .and(path("/api/codex/profiles/me"))
        .respond_with(ResponseTemplate::new(503))
        .expect(1)
        .mount(&mock_server)
        .await;

    let request_id = mcp
        .send_list_accounts_request(json!({
            "refreshTokens": false,
            "refreshUsage": true
        }))
        .await?;
    let response: JSONRPCResponse = timeout(
        DEFAULT_READ_TIMEOUT,
        mcp.read_stream_until_response_message(RequestId::Integer(request_id)),
    )
    .await??;
    let second: ListAccountsResponse = to_response(response)?;
    assert_eq!(second.accounts.len(), 1);
    assert_eq!(
        second.accounts[0].usage.rate_limits,
        known_usage.rate_limits
    );
    assert_eq!(
        second.accounts[0].usage.token_usage,
        known_usage.token_usage
    );
    assert_eq!(
        second.accounts[0].usage.state,
        ManagedChatgptAccountUsageState::Unavailable
    );
    Ok(())
}

#[tokio::test]
async fn set_auth_token_updates_account_and_notifies() -> Result<()> {
    let codex_home = TempDir::new()?;
    let mock_server = MockServer::start().await;
    create_config_toml(
        codex_home.path(),
        CreateConfigTomlParams {
            requires_openai_auth: Some(true),
            base_url: Some(format!("{}/v1", mock_server.uri())),
            ..Default::default()
        },
    )?;
    write_models_cache(codex_home.path())?;

    let access_token = encode_id_token(
        &ChatGptIdTokenClaims::new()
            .email("embedded@example.com")
            .plan_type("pro")
            .chatgpt_account_id(WORKSPACE_ID_EMBEDDED),
    )?;

    let mut mcp = TestAppServer::builder()
        .with_codex_home(codex_home.path())
        .without_auto_env()
        .with_env_overrides(&[("OPENAI_API_KEY", None)])
        .build_initialized_with_timeout(DEFAULT_READ_TIMEOUT)
        .await?;

    let set_id = mcp
        .send_chatgpt_auth_tokens_login_request(
            access_token,
            WORKSPACE_ID_EMBEDDED.to_string(),
            Some("pro".to_string()),
        )
        .await?;
    let response: LoginAccountResponse =
        timeout(DEFAULT_READ_TIMEOUT, mcp.read_response(set_id)).await??;
    assert_eq!(response, LoginAccountResponse::ChatgptAuthTokens {});

    let note = timeout(
        DEFAULT_READ_TIMEOUT,
        mcp.read_stream_until_notification_message("account/updated"),
    )
    .await??;
    let parsed: ServerNotification = note.try_into()?;
    let ServerNotification::AccountUpdated(payload) = parsed else {
        bail!("unexpected notification: {parsed:?}");
    };
    assert_eq!(payload.auth_mode, Some(AuthMode::ChatgptAuthTokens));
    assert_eq!(payload.plan_type, Some(AccountPlanType::Pro));

    let get_id = mcp
        .send_get_account_request(GetAccountParams {
            refresh_token: false,
        })
        .await?;
    let account: GetAccountResponse =
        timeout(DEFAULT_READ_TIMEOUT, mcp.read_response(get_id)).await??;
    assert_eq!(
        account,
        GetAccountResponse {
            account: Some(Account::Chatgpt {
                email: Some("embedded@example.com".to_string()),
                plan_type: AccountPlanType::Pro,
            }),
            requires_openai_auth: true,
        }
    );

    let logout_id = mcp.send_logout_account_request().await?;
    let _: LogoutAccountResponse =
        timeout(DEFAULT_READ_TIMEOUT, mcp.read_response(logout_id)).await??;

    let get_id = mcp
        .send_get_account_request(GetAccountParams {
            refresh_token: false,
        })
        .await?;
    let account: GetAccountResponse =
        timeout(DEFAULT_READ_TIMEOUT, mcp.read_response(get_id)).await??;
    assert_eq!(account.account, None);

    Ok(())
}

#[tokio::test]
async fn account_read_refresh_token_is_noop_in_external_mode() -> Result<()> {
    let codex_home = TempDir::new()?;
    create_config_toml(
        codex_home.path(),
        CreateConfigTomlParams {
            requires_openai_auth: Some(true),
            ..Default::default()
        },
    )?;
    write_models_cache(codex_home.path())?;

    let access_token = encode_id_token(
        &ChatGptIdTokenClaims::new()
            .email("embedded@example.com")
            .plan_type("pro")
            .chatgpt_account_id(WORKSPACE_ID_EMBEDDED),
    )?;

    let mut mcp = TestAppServer::builder()
        .with_codex_home(codex_home.path())
        .without_auto_env()
        .with_env_overrides(&[("OPENAI_API_KEY", None)])
        .build_initialized_with_timeout(DEFAULT_READ_TIMEOUT)
        .await?;

    let set_id = mcp
        .send_chatgpt_auth_tokens_login_request(
            access_token,
            WORKSPACE_ID_EMBEDDED.to_string(),
            Some("pro".to_string()),
        )
        .await?;
    let response: LoginAccountResponse =
        timeout(DEFAULT_READ_TIMEOUT, mcp.read_response(set_id)).await??;
    assert_eq!(response, LoginAccountResponse::ChatgptAuthTokens {});
    let _updated = timeout(
        DEFAULT_READ_TIMEOUT,
        mcp.read_stream_until_notification_message("account/updated"),
    )
    .await??;

    let get_id = mcp
        .send_get_account_request(GetAccountParams {
            refresh_token: true,
        })
        .await?;
    let account: GetAccountResponse =
        timeout(DEFAULT_READ_TIMEOUT, mcp.read_response(get_id)).await??;
    assert_eq!(
        account,
        GetAccountResponse {
            account: Some(Account::Chatgpt {
                email: Some("embedded@example.com".to_string()),
                plan_type: AccountPlanType::Pro,
            }),
            requires_openai_auth: true,
        }
    );

    let refresh_request = timeout(
        Duration::from_millis(250),
        mcp.read_stream_until_request_message(),
    )
    .await;
    assert!(
        refresh_request.is_err(),
        "external mode should not emit account/chatgptAuthTokens/refresh for refreshToken=true"
    );

    Ok(())
}

async fn respond_to_refresh_request(
    mcp: &mut TestAppServer,
    access_token: &str,
    chatgpt_account_id: &str,
    chatgpt_plan_type: Option<&str>,
) -> Result<()> {
    let refresh_req: ServerRequest = timeout(
        DEFAULT_READ_TIMEOUT,
        mcp.read_stream_until_request_message(),
    )
    .await??;
    let ServerRequest::ChatgptAuthTokensRefresh { request_id, params } = refresh_req else {
        bail!("expected account/chatgptAuthTokens/refresh request, got {refresh_req:?}");
    };
    assert_eq!(params.reason, ChatgptAuthTokensRefreshReason::Unauthorized);
    let response = ChatgptAuthTokensRefreshResponse {
        access_token: access_token.to_string(),
        chatgpt_account_id: chatgpt_account_id.to_string(),
        chatgpt_plan_type: chatgpt_plan_type.map(str::to_string),
    };
    mcp.send_response(request_id, serde_json::to_value(response)?)
        .await?;
    Ok(())
}

async fn mount_disabled_attribution_settings(mock_server: &MockServer) {
    Mock::given(method("GET"))
        .and(path("/backend-api/wham/settings/user"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "commit_attribution_enabled": false,
        })))
        .mount(mock_server)
        .await;
}

#[tokio::test]
// 401 response triggers account/chatgptAuthTokens/refresh and retries with new tokens.
async fn external_auth_refreshes_on_unauthorized() -> Result<()> {
    let codex_home = TempDir::new()?;
    let mock_server = MockServer::start().await;
    create_config_toml(
        codex_home.path(),
        CreateConfigTomlParams {
            requires_openai_auth: Some(true),
            base_url: Some(format!("{}/v1", mock_server.uri())),
            chatgpt_base_url: Some(format!("{}/backend-api", mock_server.uri())),
            ..Default::default()
        },
    )?;
    write_models_cache(codex_home.path())?;

    let success_sse = responses::sse(vec![
        responses::ev_response_created("resp-turn"),
        responses::ev_assistant_message("msg-turn", "turn ok"),
        responses::ev_completed("resp-turn"),
    ]);
    let unauthorized = ResponseTemplate::new(401).set_body_json(json!({
        "error": { "message": "unauthorized" }
    }));
    let responses_mock = responses::mount_response_sequence(
        &mock_server,
        vec![unauthorized, responses::sse_response(success_sse)],
    )
    .await;
    mount_disabled_attribution_settings(&mock_server).await;

    let initial_access_token = encode_id_token(
        &ChatGptIdTokenClaims::new()
            .email("initial@example.com")
            .plan_type("pro")
            .chatgpt_account_id(WORKSPACE_ID_INITIAL),
    )?;
    let refreshed_access_token = encode_id_token(
        &ChatGptIdTokenClaims::new()
            .email("refreshed@example.com")
            .plan_type("pro")
            .chatgpt_account_id(WORKSPACE_ID_REFRESHED),
    )?;

    let mut mcp = TestAppServer::builder()
        .with_codex_home(codex_home.path())
        .with_env_overrides(&[("OPENAI_API_KEY", None)])
        .build_initialized_with_timeout(DEFAULT_READ_TIMEOUT)
        .await?;

    let set_id = mcp
        .send_chatgpt_auth_tokens_login_request(
            initial_access_token.clone(),
            WORKSPACE_ID_INITIAL.to_string(),
            Some("pro".to_string()),
        )
        .await?;
    let response: LoginAccountResponse =
        timeout(DEFAULT_READ_TIMEOUT, mcp.read_response(set_id)).await??;
    assert_eq!(response, LoginAccountResponse::ChatgptAuthTokens {});
    let _updated = timeout(
        DEFAULT_READ_TIMEOUT,
        mcp.read_stream_until_notification_message("account/updated"),
    )
    .await??;

    let thread_req = mcp
        .send_thread_start_request_with_auto_env(codex_app_server_protocol::ThreadStartParams {
            model: Some("mock-model".to_string()),
            ..Default::default()
        })
        .await?;
    let thread: codex_app_server_protocol::ThreadStartResponse =
        timeout(DEFAULT_READ_TIMEOUT, mcp.read_response(thread_req)).await??;

    let turn_req = mcp
        .send_turn_start_request(codex_app_server_protocol::TurnStartParams {
            thread_id: thread.thread.id,
            client_user_message_id: None,
            input: vec![codex_app_server_protocol::UserInput::Text {
                text: "Hello".to_string(),
                text_elements: Vec::new(),
            }],
            ..Default::default()
        })
        .await?;
    respond_to_refresh_request(
        &mut mcp,
        &refreshed_access_token,
        WORKSPACE_ID_REFRESHED,
        Some("pro"),
    )
    .await?;
    let _: codex_app_server_protocol::TurnStartResponse =
        timeout(DEFAULT_READ_TIMEOUT, mcp.read_response(turn_req)).await??;
    let _turn_completed = timeout(
        DEFAULT_READ_TIMEOUT,
        mcp.read_stream_until_notification_message("turn/completed"),
    )
    .await??;

    let requests = responses_mock.requests();
    assert_eq!(requests.len(), 2);
    assert_eq!(
        requests[0].header("authorization"),
        Some(format!("Bearer {initial_access_token}"))
    );
    assert_eq!(
        requests[1].header("authorization"),
        Some(format!("Bearer {refreshed_access_token}"))
    );

    Ok(())
}

#[tokio::test]
// Client returns JSON-RPC error to refresh; turn fails.
async fn external_auth_refresh_error_fails_turn() -> Result<()> {
    let codex_home = TempDir::new()?;
    let mock_server = MockServer::start().await;
    create_config_toml(
        codex_home.path(),
        CreateConfigTomlParams {
            requires_openai_auth: Some(true),
            base_url: Some(format!("{}/v1", mock_server.uri())),
            chatgpt_base_url: Some(format!("{}/backend-api", mock_server.uri())),
            ..Default::default()
        },
    )?;
    write_models_cache(codex_home.path())?;

    let unauthorized = ResponseTemplate::new(401).set_body_json(json!({
        "error": { "message": "unauthorized" }
    }));
    let _responses_mock =
        responses::mount_response_sequence(&mock_server, vec![unauthorized]).await;
    mount_disabled_attribution_settings(&mock_server).await;

    let initial_access_token = encode_id_token(
        &ChatGptIdTokenClaims::new()
            .email("initial@example.com")
            .plan_type("pro")
            .chatgpt_account_id(WORKSPACE_ID_INITIAL),
    )?;

    let mut mcp = TestAppServer::builder()
        .with_codex_home(codex_home.path())
        .with_env_overrides(&[("OPENAI_API_KEY", None)])
        .build_initialized_with_timeout(DEFAULT_READ_TIMEOUT)
        .await?;

    let set_id = mcp
        .send_chatgpt_auth_tokens_login_request(
            initial_access_token,
            WORKSPACE_ID_INITIAL.to_string(),
            Some("pro".to_string()),
        )
        .await?;
    let response: LoginAccountResponse =
        timeout(DEFAULT_READ_TIMEOUT, mcp.read_response(set_id)).await??;
    assert_eq!(response, LoginAccountResponse::ChatgptAuthTokens {});
    let _updated = timeout(
        DEFAULT_READ_TIMEOUT,
        mcp.read_stream_until_notification_message("account/updated"),
    )
    .await??;

    let thread_req = mcp
        .send_thread_start_request_with_auto_env(codex_app_server_protocol::ThreadStartParams {
            model: Some("mock-model".to_string()),
            ..Default::default()
        })
        .await?;
    let thread: codex_app_server_protocol::ThreadStartResponse =
        timeout(DEFAULT_READ_TIMEOUT, mcp.read_response(thread_req)).await??;

    let turn_req = mcp
        .send_turn_start_request(codex_app_server_protocol::TurnStartParams {
            thread_id: thread.thread.id.clone(),
            client_user_message_id: None,
            input: vec![codex_app_server_protocol::UserInput::Text {
                text: "Hello".to_string(),
                text_elements: Vec::new(),
            }],
            ..Default::default()
        })
        .await?;

    let refresh_req: ServerRequest = timeout(
        DEFAULT_READ_TIMEOUT,
        mcp.read_stream_until_request_message(),
    )
    .await??;
    let ServerRequest::ChatgptAuthTokensRefresh { request_id, .. } = refresh_req else {
        bail!("expected account/chatgptAuthTokens/refresh request, got {refresh_req:?}");
    };

    mcp.send_error(
        request_id,
        JSONRPCErrorError {
            code: -32_000,
            message: "refresh failed".to_string(),
            data: None,
        },
    )
    .await?;

    let _: codex_app_server_protocol::TurnStartResponse =
        timeout(DEFAULT_READ_TIMEOUT, mcp.read_response(turn_req)).await??;
    let completed_notif: JSONRPCNotification = timeout(
        DEFAULT_READ_TIMEOUT,
        mcp.read_stream_until_notification_message("turn/completed"),
    )
    .await??;
    let completed: TurnCompletedNotification = serde_json::from_value(
        completed_notif
            .params
            .expect("turn/completed params must be present"),
    )?;
    assert_eq!(completed.turn.status, TurnStatus::Failed);
    assert!(completed.turn.error.is_some());

    Ok(())
}

#[tokio::test]
// Refresh returns tokens for the wrong workspace; turn fails.
async fn external_auth_refresh_mismatched_workspace_fails_turn() -> Result<()> {
    let codex_home = TempDir::new()?;
    let mock_server = MockServer::start().await;
    create_config_toml(
        codex_home.path(),
        CreateConfigTomlParams {
            forced_workspace_id: Some(WORKSPACE_ID_ALLOWED.to_string()),
            requires_openai_auth: Some(true),
            base_url: Some(format!("{}/v1", mock_server.uri())),
            chatgpt_base_url: Some(format!("{}/backend-api", mock_server.uri())),
            ..Default::default()
        },
    )?;
    write_models_cache(codex_home.path())?;

    let unauthorized = ResponseTemplate::new(401).set_body_json(json!({
        "error": { "message": "unauthorized" }
    }));
    let _responses_mock =
        responses::mount_response_sequence(&mock_server, vec![unauthorized]).await;
    mount_disabled_attribution_settings(&mock_server).await;

    let initial_access_token = encode_id_token(
        &ChatGptIdTokenClaims::new()
            .email("initial@example.com")
            .plan_type("pro")
            .chatgpt_account_id(WORKSPACE_ID_ALLOWED),
    )?;
    let refreshed_access_token = encode_id_token(
        &ChatGptIdTokenClaims::new()
            .email("refreshed@example.com")
            .plan_type("pro")
            .chatgpt_account_id(WORKSPACE_ID_DISALLOWED),
    )?;

    let mut mcp = TestAppServer::builder()
        .with_codex_home(codex_home.path())
        .with_env_overrides(&[("OPENAI_API_KEY", None)])
        .build_initialized_with_timeout(DEFAULT_READ_TIMEOUT)
        .await?;

    let set_id = mcp
        .send_chatgpt_auth_tokens_login_request(
            initial_access_token,
            WORKSPACE_ID_ALLOWED.to_string(),
            Some("pro".to_string()),
        )
        .await?;
    let response: LoginAccountResponse =
        timeout(DEFAULT_READ_TIMEOUT, mcp.read_response(set_id)).await??;
    assert_eq!(response, LoginAccountResponse::ChatgptAuthTokens {});
    let _updated = timeout(
        DEFAULT_READ_TIMEOUT,
        mcp.read_stream_until_notification_message("account/updated"),
    )
    .await??;

    let thread_req = mcp
        .send_thread_start_request_with_auto_env(codex_app_server_protocol::ThreadStartParams {
            model: Some("mock-model".to_string()),
            ..Default::default()
        })
        .await?;
    let thread: codex_app_server_protocol::ThreadStartResponse =
        timeout(DEFAULT_READ_TIMEOUT, mcp.read_response(thread_req)).await??;

    let turn_req = mcp
        .send_turn_start_request(codex_app_server_protocol::TurnStartParams {
            thread_id: thread.thread.id.clone(),
            client_user_message_id: None,
            input: vec![codex_app_server_protocol::UserInput::Text {
                text: "Hello".to_string(),
                text_elements: Vec::new(),
            }],
            ..Default::default()
        })
        .await?;

    let refresh_req: ServerRequest = timeout(
        DEFAULT_READ_TIMEOUT,
        mcp.read_stream_until_request_message(),
    )
    .await??;
    let ServerRequest::ChatgptAuthTokensRefresh { request_id, .. } = refresh_req else {
        bail!("expected account/chatgptAuthTokens/refresh request, got {refresh_req:?}");
    };

    mcp.send_response(
        request_id,
        serde_json::to_value(ChatgptAuthTokensRefreshResponse {
            access_token: refreshed_access_token,
            chatgpt_account_id: WORKSPACE_ID_DISALLOWED.to_string(),
            chatgpt_plan_type: Some("pro".to_string()),
        })?,
    )
    .await?;

    let _: codex_app_server_protocol::TurnStartResponse =
        timeout(DEFAULT_READ_TIMEOUT, mcp.read_response(turn_req)).await??;
    let completed_notif: JSONRPCNotification = timeout(
        DEFAULT_READ_TIMEOUT,
        mcp.read_stream_until_notification_message("turn/completed"),
    )
    .await??;
    let completed: TurnCompletedNotification = serde_json::from_value(
        completed_notif
            .params
            .expect("turn/completed params must be present"),
    )?;
    assert_eq!(completed.turn.status, TurnStatus::Failed);
    assert!(completed.turn.error.is_some());

    Ok(())
}

#[tokio::test]
// Refresh returns a malformed access token; turn fails.
async fn external_auth_refresh_invalid_access_token_fails_turn() -> Result<()> {
    let codex_home = TempDir::new()?;
    let mock_server = MockServer::start().await;
    create_config_toml(
        codex_home.path(),
        CreateConfigTomlParams {
            requires_openai_auth: Some(true),
            base_url: Some(format!("{}/v1", mock_server.uri())),
            chatgpt_base_url: Some(format!("{}/backend-api", mock_server.uri())),
            ..Default::default()
        },
    )?;
    write_models_cache(codex_home.path())?;

    let unauthorized = ResponseTemplate::new(401).set_body_json(json!({
        "error": { "message": "unauthorized" }
    }));
    let _responses_mock =
        responses::mount_response_sequence(&mock_server, vec![unauthorized]).await;
    mount_disabled_attribution_settings(&mock_server).await;

    let initial_access_token = encode_id_token(
        &ChatGptIdTokenClaims::new()
            .email("initial@example.com")
            .plan_type("pro")
            .chatgpt_account_id(WORKSPACE_ID_INITIAL),
    )?;

    let mut mcp = TestAppServer::builder()
        .with_codex_home(codex_home.path())
        .with_env_overrides(&[("OPENAI_API_KEY", None)])
        .build_initialized_with_timeout(DEFAULT_READ_TIMEOUT)
        .await?;

    let set_id = mcp
        .send_chatgpt_auth_tokens_login_request(
            initial_access_token,
            WORKSPACE_ID_INITIAL.to_string(),
            Some("pro".to_string()),
        )
        .await?;
    let response: LoginAccountResponse =
        timeout(DEFAULT_READ_TIMEOUT, mcp.read_response(set_id)).await??;
    assert_eq!(response, LoginAccountResponse::ChatgptAuthTokens {});
    let _updated = timeout(
        DEFAULT_READ_TIMEOUT,
        mcp.read_stream_until_notification_message("account/updated"),
    )
    .await??;

    let thread_req = mcp
        .send_thread_start_request_with_auto_env(codex_app_server_protocol::ThreadStartParams {
            model: Some("mock-model".to_string()),
            ..Default::default()
        })
        .await?;
    let thread: codex_app_server_protocol::ThreadStartResponse =
        timeout(DEFAULT_READ_TIMEOUT, mcp.read_response(thread_req)).await??;

    let turn_req = mcp
        .send_turn_start_request(codex_app_server_protocol::TurnStartParams {
            thread_id: thread.thread.id.clone(),
            client_user_message_id: None,
            input: vec![codex_app_server_protocol::UserInput::Text {
                text: "Hello".to_string(),
                text_elements: Vec::new(),
            }],
            ..Default::default()
        })
        .await?;

    let refresh_req: ServerRequest = timeout(
        DEFAULT_READ_TIMEOUT,
        mcp.read_stream_until_request_message(),
    )
    .await??;
    let ServerRequest::ChatgptAuthTokensRefresh { request_id, .. } = refresh_req else {
        bail!("expected account/chatgptAuthTokens/refresh request, got {refresh_req:?}");
    };

    mcp.send_response(
        request_id,
        serde_json::to_value(ChatgptAuthTokensRefreshResponse {
            access_token: "not-a-jwt".to_string(),
            chatgpt_account_id: WORKSPACE_ID_INITIAL.to_string(),
            chatgpt_plan_type: Some("pro".to_string()),
        })?,
    )
    .await?;

    let _: codex_app_server_protocol::TurnStartResponse =
        timeout(DEFAULT_READ_TIMEOUT, mcp.read_response(turn_req)).await??;
    let completed_notif: JSONRPCNotification = timeout(
        DEFAULT_READ_TIMEOUT,
        mcp.read_stream_until_notification_message("turn/completed"),
    )
    .await??;
    let completed: TurnCompletedNotification = serde_json::from_value(
        completed_notif
            .params
            .expect("turn/completed params must be present"),
    )?;
    assert_eq!(completed.turn.status, TurnStatus::Failed);
    assert!(completed.turn.error.is_some());

    Ok(())
}

#[tokio::test]
async fn login_account_api_key_succeeds_and_notifies() -> Result<()> {
    let codex_home = TempDir::new()?;
    create_config_toml(codex_home.path(), CreateConfigTomlParams::default())?;

    let mut mcp = TestAppServer::builder()
        .with_codex_home(codex_home.path())
        .without_auto_env()
        .build_initialized_with_timeout(DEFAULT_READ_TIMEOUT)
        .await?;

    let req_id = mcp
        .send_login_account_api_key_request("sk-test-key")
        .await?;
    let login: LoginAccountResponse =
        timeout(DEFAULT_READ_TIMEOUT, mcp.read_response(req_id)).await??;
    assert_eq!(login, LoginAccountResponse::ApiKey {});

    let note = timeout(
        DEFAULT_READ_TIMEOUT,
        mcp.read_stream_until_notification_message("account/login/completed"),
    )
    .await??;
    let parsed: ServerNotification = note.try_into()?;
    let ServerNotification::AccountLoginCompleted(payload) = parsed else {
        bail!("unexpected notification: {parsed:?}");
    };
    pretty_assertions::assert_eq!(payload.login_id, None);
    pretty_assertions::assert_eq!(payload.success, true);
    pretty_assertions::assert_eq!(payload.error, None);

    let note = timeout(
        DEFAULT_READ_TIMEOUT,
        mcp.read_stream_until_notification_message("account/updated"),
    )
    .await??;
    let parsed: ServerNotification = note.try_into()?;
    let ServerNotification::AccountUpdated(payload) = parsed else {
        bail!("unexpected notification: {parsed:?}");
    };
    pretty_assertions::assert_eq!(payload.auth_mode, Some(AuthMode::ApiKey));
    pretty_assertions::assert_eq!(payload.plan_type, None);

    assert!(codex_home.path().join("auth.json").exists());
    Ok(())
}

#[tokio::test]
async fn login_amazon_bedrock_replaces_primary_auth_and_persists_provider() -> Result<()> {
    let codex_home = TempDir::new()?;
    create_config_toml(codex_home.path(), CreateConfigTomlParams::default())?;
    login_with_api_key(
        codex_home.path(),
        "sk-test-key",
        AuthCredentialsStoreMode::File,
        AuthKeyringBackendKind::default(),
    )?;
    let mut mcp = TestAppServer::builder()
        .with_codex_home(codex_home.path())
        .without_auto_env()
        .with_env_overrides(&[("OPENAI_API_KEY", None)])
        .build_initialized_with_timeout(DEFAULT_READ_TIMEOUT)
        .await?;
    let mut expected_config = read_config_toml(codex_home.path())?;
    expected_config
        .as_table_mut()
        .expect("config should be a table")
        .insert(
            "model_provider".to_string(),
            toml::Value::String("amazon-bedrock".to_string()),
        );
    let request_id = mcp
        .send_login_account_amazon_bedrock_request(" managed-bedrock-api-key ", " us-west-2 ")
        .await?;
    let response: JSONRPCResponse = timeout(
        DEFAULT_READ_TIMEOUT,
        mcp.read_stream_until_response_message(RequestId::Integer(request_id)),
    )
    .await??;
    assert_eq!(
        to_response::<LoginAccountResponse>(response)?,
        LoginAccountResponse::AmazonBedrock {}
    );

    assert_eq!(
        load_file_auth(codex_home.path())?,
        Some(AuthDotJson {
            auth_mode: Some(DomainAuthMode::BedrockApiKey),
            openai_api_key: None,
            tokens: None,
            last_refresh: None,
            agent_identity: None,
            personal_access_token: None,
            bedrock_api_key: Some(BedrockApiKeyAuth {
                api_key: "managed-bedrock-api-key".to_string(),
                region: "us-west-2".to_string(),
            }),
        })
    );
    assert_eq!(read_config_toml(codex_home.path())?, expected_config);

    let notification = timeout(
        DEFAULT_READ_TIMEOUT,
        mcp.read_stream_until_notification_message("account/login/completed"),
    )
    .await??;
    let ServerNotification::AccountLoginCompleted(payload) = notification.try_into()? else {
        bail!("unexpected notification")
    };
    assert_eq!(
        payload,
        AccountLoginCompletedNotification {
            login_id: None,
            success: true,
            error: None,
            onboarding_entrypoint: None,
            managed_account_id: None,
        }
    );
    assert_account_updated(&mut mcp, Some(AuthMode::BedrockApiKey)).await?;

    Ok(())
}

#[tokio::test]
async fn login_amazon_bedrock_rejects_non_bedrock_provider_override_without_changes() -> Result<()>
{
    let codex_home = TempDir::new()?;
    create_config_toml(codex_home.path(), CreateConfigTomlParams::default())?;
    login_with_api_key(
        codex_home.path(),
        "sk-test-key",
        AuthCredentialsStoreMode::File,
        AuthKeyringBackendKind::default(),
    )?;
    let expected_auth = load_file_auth(codex_home.path())?;

    let mut mcp = TestAppServer::builder()
        .with_codex_home(codex_home.path())
        .without_auto_env()
        .with_env_overrides(&[("OPENAI_API_KEY", None)])
        .with_args(&["-c", "model_provider=\"mock_provider\""])
        .build_initialized_with_timeout(DEFAULT_READ_TIMEOUT)
        .await?;
    let expected_config = read_config_toml(codex_home.path())?;

    let request_id = mcp
        .send_login_account_amazon_bedrock_request("managed-bedrock-api-key", "us-west-2")
        .await?;
    let error = timeout(
        DEFAULT_READ_TIMEOUT,
        mcp.read_stream_until_error_message(RequestId::Integer(request_id)),
    )
    .await??;
    assert_eq!(
        error.error.message,
        "Amazon Bedrock login cannot select `amazon-bedrock` because session-flags sets `model_provider` to \"mock_provider\""
    );
    assert_eq!(load_file_auth(codex_home.path())?, expected_auth);
    assert_eq!(read_config_toml(codex_home.path())?, expected_config);

    let maybe_completed = timeout(
        Duration::from_millis(500),
        mcp.read_stream_until_notification_message("account/login/completed"),
    )
    .await;
    assert!(
        maybe_completed.is_err(),
        "account/login/completed should not be emitted when the provider is overridden"
    );
    let maybe_updated = timeout(
        Duration::from_millis(500),
        mcp.read_stream_until_notification_message("account/updated"),
    )
    .await;
    assert!(
        maybe_updated.is_err(),
        "account/updated should not be emitted when the provider is overridden"
    );

    Ok(())
}

#[tokio::test]
async fn login_amazon_bedrock_allows_bedrock_provider_override() -> Result<()> {
    let codex_home = TempDir::new()?;
    create_config_toml(codex_home.path(), CreateConfigTomlParams::default())?;
    let mut expected_config = read_config_toml(codex_home.path())?;
    expected_config
        .as_table_mut()
        .expect("config should be a table")
        .insert(
            "model_provider".to_string(),
            toml::Value::String("amazon-bedrock".to_string()),
        );

    let mut mcp = TestAppServer::builder()
        .with_codex_home(codex_home.path())
        .without_auto_env()
        .with_env_overrides(&[("OPENAI_API_KEY", None)])
        .with_args(&["-c", "model_provider=\"amazon-bedrock\""])
        .build_initialized_with_timeout(DEFAULT_READ_TIMEOUT)
        .await?;

    let request_id = mcp
        .send_login_account_amazon_bedrock_request("managed-bedrock-api-key", "us-west-2")
        .await?;
    let response = timeout(
        DEFAULT_READ_TIMEOUT,
        mcp.read_stream_until_response_message(RequestId::Integer(request_id)),
    )
    .await??;
    assert_eq!(
        to_response::<LoginAccountResponse>(response)?,
        LoginAccountResponse::AmazonBedrock {}
    );
    assert_eq!(
        load_file_auth(codex_home.path())?,
        Some(AuthDotJson {
            auth_mode: Some(DomainAuthMode::BedrockApiKey),
            openai_api_key: None,
            tokens: None,
            last_refresh: None,
            agent_identity: None,
            personal_access_token: None,
            bedrock_api_key: Some(BedrockApiKeyAuth {
                api_key: "managed-bedrock-api-key".to_string(),
                region: "us-west-2".to_string(),
            }),
        })
    );
    assert_eq!(read_config_toml(codex_home.path())?, expected_config);
    timeout(
        DEFAULT_READ_TIMEOUT,
        mcp.read_stream_until_notification_message("account/login/completed"),
    )
    .await??;
    assert_account_updated(&mut mcp, Some(AuthMode::BedrockApiKey)).await?;

    Ok(())
}

#[tokio::test]
async fn logout_managed_bedrock_restores_default_account() -> Result<()> {
    let codex_home = TempDir::new()?;
    create_config_toml(codex_home.path(), CreateConfigTomlParams::default())?;
    let mut expected_config = read_config_toml(codex_home.path())?;
    expected_config
        .as_table_mut()
        .expect("config should be a table")
        .remove("model_provider");

    let mut mcp = TestAppServer::builder()
        .with_codex_home(codex_home.path())
        .without_auto_env()
        .with_env_overrides(&[("OPENAI_API_KEY", None)])
        .build_initialized_with_timeout(DEFAULT_READ_TIMEOUT)
        .await?;
    let request_id = mcp
        .send_login_account_amazon_bedrock_request("managed-bedrock-api-key", "us-west-2")
        .await?;
    let response = timeout(
        DEFAULT_READ_TIMEOUT,
        mcp.read_stream_until_response_message(RequestId::Integer(request_id)),
    )
    .await??;
    assert_eq!(
        to_response::<LoginAccountResponse>(response)?,
        LoginAccountResponse::AmazonBedrock {}
    );
    timeout(
        DEFAULT_READ_TIMEOUT,
        mcp.read_stream_until_notification_message("account/login/completed"),
    )
    .await??;
    assert_account_updated(&mut mcp, Some(AuthMode::BedrockApiKey)).await?;
    assert_eq!(
        read_account(&mut mcp).await?,
        GetAccountResponse {
            account: Some(Account::AmazonBedrock {
                uses_codex_managed_credentials: true,
            }),
            requires_openai_auth: false,
        }
    );

    let request_id = mcp.send_logout_account_request().await?;
    let response = timeout(
        DEFAULT_READ_TIMEOUT,
        mcp.read_stream_until_response_message(RequestId::Integer(request_id)),
    )
    .await??;
    assert_eq!(
        to_response::<LogoutAccountResponse>(response)?,
        LogoutAccountResponse {}
    );
    assert_eq!(load_file_auth(codex_home.path())?, None);
    assert_eq!(read_config_toml(codex_home.path())?, expected_config);
    assert_account_updated(&mut mcp, /*auth_mode*/ None).await?;
    assert_eq!(
        read_account(&mut mcp).await?,
        GetAccountResponse {
            account: None,
            requires_openai_auth: true,
        }
    );
    Ok(())
}

#[tokio::test]
async fn logout_aws_managed_bedrock_errors_without_changing_auth_or_config() -> Result<()> {
    let codex_home = TempDir::new()?;
    create_config_toml(codex_home.path(), aws_managed_bedrock_config())?;
    login_with_api_key(
        codex_home.path(),
        "sk-test-key",
        AuthCredentialsStoreMode::File,
        AuthKeyringBackendKind::default(),
    )?;
    let expected_auth = load_file_auth(codex_home.path())?;

    let mut mcp = TestAppServer::builder()
        .with_codex_home(codex_home.path())
        .without_auto_env()
        .with_env_overrides(&[("OPENAI_API_KEY", None)])
        .build_initialized_with_timeout(DEFAULT_READ_TIMEOUT)
        .await?;
    let expected_config = read_config_toml(codex_home.path())?;
    let request_id = mcp.send_logout_account_request().await?;
    let error = timeout(
        DEFAULT_READ_TIMEOUT,
        mcp.read_stream_until_error_message(RequestId::Integer(request_id)),
    )
    .await??;
    assert_eq!(error.error.code, -32600);
    assert_eq!(
        error.error.message,
        "cannot log out while Amazon Bedrock is using AWS-managed credentials; manage those credentials through AWS or switch model providers before logging out Codex authentication"
    );
    assert_eq!(load_file_auth(codex_home.path())?, expected_auth);
    assert_eq!(read_config_toml(codex_home.path())?, expected_config);
    Ok(())
}

#[tokio::test]
async fn logout_managed_bedrock_preserves_changed_provider_without_experimental_api() -> Result<()>
{
    let codex_home = TempDir::new()?;
    create_config_toml(codex_home.path(), aws_managed_bedrock_config())?;
    login_with_bedrock_api_key(
        codex_home.path(),
        "managed-bedrock-api-key",
        "us-west-2",
        AuthCredentialsStoreMode::File,
        AuthKeyringBackendKind::default(),
    )?;

    let mut mcp = TestAppServer::builder()
        .with_codex_home(codex_home.path())
        .without_auto_env()
        .build()
        .await?;
    let initialized = mcp
        .initialize_with_capabilities(
            ClientInfo {
                name: DEFAULT_CLIENT_NAME.to_string(),
                title: None,
                version: "0.1.0".to_string(),
            },
            Some(InitializeCapabilities {
                experimental_api: false,
                ..Default::default()
            }),
        )
        .await?;
    assert!(matches!(initialized, JSONRPCMessage::Response(_)));

    create_config_toml(codex_home.path(), CreateConfigTomlParams::default())?;
    let expected_config = read_config_toml(codex_home.path())?;

    let request_id = mcp.send_logout_account_request().await?;
    let response = timeout(
        DEFAULT_READ_TIMEOUT,
        mcp.read_stream_until_response_message(RequestId::Integer(request_id)),
    )
    .await??;
    assert_eq!(
        to_response::<LogoutAccountResponse>(response)?,
        LogoutAccountResponse {}
    );
    assert_eq!(load_file_auth(codex_home.path())?, None);
    assert_eq!(read_config_toml(codex_home.path())?, expected_config);
    assert_account_updated(&mut mcp, /*auth_mode*/ None).await?;
    assert_eq!(
        read_account(&mut mcp).await?,
        GetAccountResponse {
            account: None,
            requires_openai_auth: false,
        }
    );
    Ok(())
}

#[tokio::test]
async fn managed_bedrock_login_requires_experimental_api() -> Result<()> {
    let codex_home = TempDir::new()?;
    create_config_toml(codex_home.path(), CreateConfigTomlParams::default())?;
    let mut mcp = TestAppServer::builder()
        .with_codex_home(codex_home.path())
        .without_auto_env()
        .build()
        .await?;
    let initialized = mcp
        .initialize_with_capabilities(
            ClientInfo {
                name: DEFAULT_CLIENT_NAME.to_string(),
                title: None,
                version: "0.1.0".to_string(),
            },
            Some(InitializeCapabilities {
                experimental_api: false,
                ..Default::default()
            }),
        )
        .await?;
    assert!(matches!(initialized, JSONRPCMessage::Response(_)));

    let request_id = mcp
        .send_login_account_amazon_bedrock_request("managed-bedrock-api-key", "us-west-2")
        .await?;
    let error = timeout(
        DEFAULT_READ_TIMEOUT,
        mcp.read_stream_until_error_message(RequestId::Integer(request_id)),
    )
    .await??;
    assert_eq!(
        error.error.message,
        "account/login/start.amazonBedrock requires experimentalApi capability"
    );
    assert_eq!(load_file_auth(codex_home.path())?, None);
    Ok(())
}

#[tokio::test]
async fn login_managed_bedrock_updates_active_bedrock_account() -> Result<()> {
    let codex_home = TempDir::new()?;
    create_config_toml(codex_home.path(), CreateConfigTomlParams::default())?;

    let mut mcp = TestAppServer::builder()
        .with_codex_home(codex_home.path())
        .without_auto_env()
        .with_env_overrides(&[("OPENAI_API_KEY", None)])
        .build_initialized_with_timeout(DEFAULT_READ_TIMEOUT)
        .await?;
    let request_id = mcp
        .send_login_account_amazon_bedrock_request("managed-bedrock-api-key", "us-west-2")
        .await?;
    let response: JSONRPCResponse = timeout(
        DEFAULT_READ_TIMEOUT,
        mcp.read_stream_until_response_message(RequestId::Integer(request_id)),
    )
    .await??;
    assert_eq!(
        to_response::<LoginAccountResponse>(response)?,
        LoginAccountResponse::AmazonBedrock {}
    );
    timeout(
        DEFAULT_READ_TIMEOUT,
        mcp.read_stream_until_notification_message("account/login/completed"),
    )
    .await??;
    assert_account_updated(&mut mcp, Some(AuthMode::BedrockApiKey)).await?;
    assert_eq!(
        read_account(&mut mcp).await?,
        GetAccountResponse {
            account: Some(Account::AmazonBedrock {
                uses_codex_managed_credentials: true,
            }),
            requires_openai_auth: false,
        }
    );

    assert!(codex_home.path().join("auth.json").exists());
    Ok(())
}

#[tokio::test]
async fn login_account_amazon_bedrock_rejects_invalid_credentials_without_changes() -> Result<()> {
    let codex_home = TempDir::new()?;
    create_config_toml(codex_home.path(), CreateConfigTomlParams::default())?;

    let mut mcp = TestAppServer::builder()
        .with_codex_home(codex_home.path())
        .without_auto_env()
        .with_env_overrides(&[("OPENAI_API_KEY", None)])
        .build_initialized_with_timeout(DEFAULT_READ_TIMEOUT)
        .await?;
    let expected_config = read_config_toml(codex_home.path())?;

    let request_id = mcp
        .send_login_account_amazon_bedrock_request("  ", "us-west-2")
        .await?;
    let error = timeout(
        DEFAULT_READ_TIMEOUT,
        mcp.read_stream_until_error_message(RequestId::Integer(request_id)),
    )
    .await??;
    assert_eq!(
        error.error.message,
        "Amazon Bedrock API key must not be empty."
    );

    let request_id = mcp
        .send_login_account_amazon_bedrock_request("managed-bedrock-api-key", "us-west-1")
        .await?;
    let error = timeout(
        DEFAULT_READ_TIMEOUT,
        mcp.read_stream_until_error_message(RequestId::Integer(request_id)),
    )
    .await??;
    assert_eq!(
        error.error.message,
        "Amazon Bedrock Mantle does not support region `us-west-1`"
    );
    assert_eq!(load_file_auth(codex_home.path())?, None);
    assert_eq!(read_config_toml(codex_home.path())?, expected_config);

    Ok(())
}

#[tokio::test]
async fn login_account_amazon_bedrock_rejected_when_forced_chatgpt() -> Result<()> {
    let codex_home = TempDir::new()?;
    create_config_toml(
        codex_home.path(),
        CreateConfigTomlParams {
            forced_method: Some("chatgpt".to_string()),
            ..Default::default()
        },
    )?;

    let mut mcp = TestAppServer::builder()
        .with_codex_home(codex_home.path())
        .without_auto_env()
        .build_initialized_with_timeout(DEFAULT_READ_TIMEOUT)
        .await?;
    let request_id = mcp
        .send_login_account_amazon_bedrock_request("managed-bedrock-api-key", "us-west-2")
        .await?;
    let error = timeout(
        DEFAULT_READ_TIMEOUT,
        mcp.read_stream_until_error_message(RequestId::Integer(request_id)),
    )
    .await??;

    assert_eq!(
        error.error.message,
        "Amazon Bedrock login is disabled. Use ChatGPT login instead."
    );
    assert_eq!(load_file_auth(codex_home.path())?, None);
    Ok(())
}

#[tokio::test]
async fn login_account_amazon_bedrock_rejected_with_external_chatgpt_auth() -> Result<()> {
    let codex_home = TempDir::new()?;
    create_config_toml(codex_home.path(), CreateConfigTomlParams::default())?;
    let access_token = encode_id_token(
        &ChatGptIdTokenClaims::new()
            .email("embedded@example.com")
            .plan_type("pro")
            .chatgpt_account_id(WORKSPACE_ID_EMBEDDED),
    )?;

    let mut mcp = TestAppServer::builder()
        .with_codex_home(codex_home.path())
        .without_auto_env()
        .build_initialized_with_timeout(DEFAULT_READ_TIMEOUT)
        .await?;
    let set_id = mcp
        .send_chatgpt_auth_tokens_login_request(
            access_token,
            WORKSPACE_ID_EMBEDDED.to_string(),
            Some("pro".to_string()),
        )
        .await?;
    let set_response = timeout(
        DEFAULT_READ_TIMEOUT,
        mcp.read_stream_until_response_message(RequestId::Integer(set_id)),
    )
    .await??;
    assert_eq!(
        to_response::<LoginAccountResponse>(set_response)?,
        LoginAccountResponse::ChatgptAuthTokens {}
    );
    timeout(
        DEFAULT_READ_TIMEOUT,
        mcp.read_stream_until_notification_message("account/updated"),
    )
    .await??;

    let request_id = mcp
        .send_login_account_amazon_bedrock_request("managed-bedrock-api-key", "us-west-2")
        .await?;
    let error = timeout(
        DEFAULT_READ_TIMEOUT,
        mcp.read_stream_until_error_message(RequestId::Integer(request_id)),
    )
    .await??;
    assert_eq!(
        error.error.message,
        "External auth is active. Use account/login/start (chatgptAuthTokens) to update it or account/logout to clear it."
    );
    assert_eq!(load_file_auth(codex_home.path())?, None);
    Ok(())
}

#[tokio::test]
async fn login_account_api_key_rejected_when_forced_chatgpt() -> Result<()> {
    let codex_home = TempDir::new()?;
    create_config_toml(
        codex_home.path(),
        CreateConfigTomlParams {
            forced_method: Some("chatgpt".to_string()),
            ..Default::default()
        },
    )?;

    let mut mcp = TestAppServer::builder()
        .with_codex_home(codex_home.path())
        .without_auto_env()
        .build_initialized_with_timeout(DEFAULT_READ_TIMEOUT)
        .await?;

    let request_id = mcp
        .send_login_account_api_key_request("sk-test-key")
        .await?;
    let err: JSONRPCError = timeout(
        DEFAULT_READ_TIMEOUT,
        mcp.read_stream_until_error_message(RequestId::Integer(request_id)),
    )
    .await??;

    assert_eq!(
        err.error.message,
        "API key login is disabled. Use ChatGPT login instead."
    );
    Ok(())
}

#[tokio::test]
async fn login_account_chatgpt_rejected_when_forced_api() -> Result<()> {
    let codex_home = TempDir::new()?;
    create_config_toml(
        codex_home.path(),
        CreateConfigTomlParams {
            forced_method: Some("api".to_string()),
            ..Default::default()
        },
    )?;

    let mut mcp = TestAppServer::builder()
        .with_codex_home(codex_home.path())
        .without_auto_env()
        .build_initialized_with_timeout(DEFAULT_READ_TIMEOUT)
        .await?;

    let request_id = mcp.send_login_account_chatgpt_request().await?;
    let err: JSONRPCError = timeout(
        DEFAULT_READ_TIMEOUT,
        mcp.read_stream_until_error_message(RequestId::Integer(request_id)),
    )
    .await??;

    assert_eq!(
        err.error.message,
        "ChatGPT login is disabled. Use API key login instead."
    );
    Ok(())
}

#[tokio::test]
async fn login_account_chatgpt_device_code_returns_error_when_disabled() -> Result<()> {
    let codex_home = TempDir::new()?;
    let mock_server = MockServer::start().await;
    create_config_toml(
        codex_home.path(),
        CreateConfigTomlParams {
            requires_openai_auth: Some(true),
            base_url: Some(format!("{}/v1", mock_server.uri())),
            ..Default::default()
        },
    )?;
    write_models_cache(codex_home.path())?;
    mock_device_code_usercode_failure(&mock_server, /*status*/ 404).await;

    let issuer = mock_server.uri();
    let mut mcp = TestAppServer::builder()
        .with_codex_home(codex_home.path())
        .without_auto_env()
        .with_env_overrides(&[
            ("OPENAI_API_KEY", None),
            (LOGIN_ISSUER_ENV_VAR, Some(issuer.as_str())),
        ])
        .build_initialized_with_timeout(DEFAULT_READ_TIMEOUT)
        .await?;

    let request_id = mcp.send_login_account_chatgpt_device_code_request().await?;
    let err: JSONRPCError = timeout(
        DEFAULT_READ_TIMEOUT,
        mcp.read_stream_until_error_message(RequestId::Integer(request_id)),
    )
    .await??;
    assert!(
        err.error
            .message
            .contains("device code login is not enabled"),
        "unexpected error: {:?}",
        err.error.message
    );

    let maybe_completed = timeout(
        Duration::from_millis(500),
        mcp.read_stream_until_notification_message("account/login/completed"),
    )
    .await;
    assert!(
        maybe_completed.is_err(),
        "account/login/completed should not be emitted when device code start fails"
    );
    assert!(
        !codex_home.path().join("auth.json").exists(),
        "auth.json should not be created when device code start fails"
    );
    Ok(())
}

#[tokio::test]
async fn login_account_chatgpt_device_code_succeeds_and_notifies() -> Result<()> {
    let codex_home = TempDir::new()?;
    let mock_server = MockServer::start().await;
    create_config_toml(
        codex_home.path(),
        CreateConfigTomlParams {
            requires_openai_auth: Some(true),
            base_url: Some(format!("{}/v1", mock_server.uri())),
            ..Default::default()
        },
    )?;
    write_models_cache(codex_home.path())?;

    mock_device_code_usercode(&mock_server, /*interval_seconds*/ 0).await;
    mock_device_code_token_success(&mock_server).await;
    let id_token = encode_id_token(
        &ChatGptIdTokenClaims::new()
            .email("device@example.com")
            .plan_type("pro")
            .chatgpt_account_id(WORKSPACE_ID_DEVICE),
    )?;
    mock_oauth_token(&mock_server, &id_token).await;

    let issuer = mock_server.uri();
    let mut mcp = TestAppServer::builder()
        .with_codex_home(codex_home.path())
        .without_auto_env()
        .with_env_overrides(&[
            ("OPENAI_API_KEY", None),
            (LOGIN_ISSUER_ENV_VAR, Some(issuer.as_str())),
        ])
        .build_initialized_with_timeout(DEFAULT_READ_TIMEOUT)
        .await?;

    let request_id = mcp.send_login_account_chatgpt_device_code_request().await?;
    let login: LoginAccountResponse =
        timeout(DEFAULT_READ_TIMEOUT, mcp.read_response(request_id)).await??;
    let LoginAccountResponse::ChatgptDeviceCode {
        login_id,
        verification_url,
        user_code,
    } = login
    else {
        bail!("unexpected login response: {login:?}");
    };
    assert_eq!(verification_url, format!("{issuer}/codex/device"));
    assert_eq!(user_code, "CODE-12345");

    let note = timeout(
        DEFAULT_READ_TIMEOUT,
        mcp.read_stream_until_notification_message("account/login/completed"),
    )
    .await??;
    let parsed: ServerNotification = note.try_into()?;
    let ServerNotification::AccountLoginCompleted(payload) = parsed else {
        bail!("unexpected notification: {parsed:?}");
    };
    assert_eq!(payload.login_id, Some(login_id));
    assert_eq!(payload.success, true);
    assert_eq!(payload.error, None);

    let note = timeout(
        DEFAULT_READ_TIMEOUT,
        mcp.read_stream_until_notification_message("account/updated"),
    )
    .await??;
    let parsed: ServerNotification = note.try_into()?;
    let ServerNotification::AccountUpdated(payload) = parsed else {
        bail!("unexpected notification: {parsed:?}");
    };
    assert_eq!(payload.auth_mode, Some(AuthMode::Chatgpt));
    assert_eq!(payload.plan_type, Some(AccountPlanType::Pro));

    let note = timeout(
        DEFAULT_READ_TIMEOUT,
        mcp.read_stream_until_notification_message("account/pool/updated"),
    )
    .await??;
    let parsed: ServerNotification = note.try_into()?;
    let ServerNotification::AccountPoolUpdated(payload) = parsed else {
        bail!("unexpected notification: {parsed:?}");
    };
    assert_eq!(payload.accounts.len(), 1);
    assert_eq!(
        payload.accounts[0].managed_account_id,
        "email:device@example.com"
    );
    assert!(payload.pool_revision > 0);
    assert!(
        codex_home.path().join("auth.json").exists(),
        "auth.json should be created when device code login succeeds"
    );
    Ok(())
}

#[tokio::test]
async fn login_account_chatgpt_device_code_failure_notifies_without_account_update() -> Result<()> {
    let codex_home = TempDir::new()?;
    let mock_server = MockServer::start().await;
    create_config_toml(
        codex_home.path(),
        CreateConfigTomlParams {
            requires_openai_auth: Some(true),
            base_url: Some(format!("{}/v1", mock_server.uri())),
            ..Default::default()
        },
    )?;
    write_models_cache(codex_home.path())?;

    mock_device_code_usercode(&mock_server, /*interval_seconds*/ 0).await;
    mock_device_code_token_failure(&mock_server, /*status*/ 500).await;

    let issuer = mock_server.uri();
    let mut mcp = TestAppServer::builder()
        .with_codex_home(codex_home.path())
        .without_auto_env()
        .with_env_overrides(&[
            ("OPENAI_API_KEY", None),
            (LOGIN_ISSUER_ENV_VAR, Some(issuer.as_str())),
        ])
        .build_initialized_with_timeout(DEFAULT_READ_TIMEOUT)
        .await?;

    let request_id = mcp.send_login_account_chatgpt_device_code_request().await?;
    let login: LoginAccountResponse =
        timeout(DEFAULT_READ_TIMEOUT, mcp.read_response(request_id)).await??;
    let LoginAccountResponse::ChatgptDeviceCode { login_id, .. } = login else {
        bail!("unexpected login response: {login:?}");
    };

    let note = timeout(
        DEFAULT_READ_TIMEOUT,
        mcp.read_stream_until_notification_message("account/login/completed"),
    )
    .await??;
    let parsed: ServerNotification = note.try_into()?;
    let ServerNotification::AccountLoginCompleted(payload) = parsed else {
        bail!("unexpected notification: {parsed:?}");
    };
    assert_eq!(payload.login_id, Some(login_id));
    assert_eq!(payload.success, false);
    assert!(
        payload
            .error
            .as_deref()
            .is_some_and(|error| error.contains("device auth failed with status")),
        "unexpected error: {:?}",
        payload.error
    );

    let maybe_updated = timeout(
        Duration::from_millis(500),
        mcp.read_stream_until_notification_message("account/updated"),
    )
    .await;
    assert!(
        maybe_updated.is_err(),
        "account/updated should not be emitted when device code login fails"
    );
    assert!(
        !codex_home.path().join("auth.json").exists(),
        "auth.json should not be created when device code login fails"
    );
    Ok(())
}

#[tokio::test]
async fn login_account_chatgpt_device_code_can_be_cancelled() -> Result<()> {
    let codex_home = TempDir::new()?;
    let mock_server = MockServer::start().await;
    create_config_toml(
        codex_home.path(),
        CreateConfigTomlParams {
            requires_openai_auth: Some(true),
            base_url: Some(format!("{}/v1", mock_server.uri())),
            ..Default::default()
        },
    )?;
    write_models_cache(codex_home.path())?;

    mock_device_code_usercode(&mock_server, /*interval_seconds*/ 1).await;
    mock_device_code_token_failure(&mock_server, /*status*/ 404).await;

    let issuer = mock_server.uri();
    let mut mcp = TestAppServer::builder()
        .with_codex_home(codex_home.path())
        .without_auto_env()
        .with_env_overrides(&[
            ("OPENAI_API_KEY", None),
            (LOGIN_ISSUER_ENV_VAR, Some(issuer.as_str())),
        ])
        .build_initialized_with_timeout(DEFAULT_READ_TIMEOUT)
        .await?;

    let request_id = mcp.send_login_account_chatgpt_device_code_request().await?;
    let login: LoginAccountResponse =
        timeout(DEFAULT_READ_TIMEOUT, mcp.read_response(request_id)).await??;
    let LoginAccountResponse::ChatgptDeviceCode { login_id, .. } = login else {
        bail!("unexpected login response: {login:?}");
    };

    let cancel_id = mcp
        .send_cancel_login_account_request(CancelLoginAccountParams {
            login_id: login_id.clone(),
        })
        .await?;
    let cancel: CancelLoginAccountResponse =
        timeout(DEFAULT_READ_TIMEOUT, mcp.read_response(cancel_id)).await??;
    assert_eq!(cancel.status, CancelLoginAccountStatus::Canceled);

    let note = timeout(
        DEFAULT_READ_TIMEOUT,
        mcp.read_stream_until_notification_message("account/login/completed"),
    )
    .await??;
    let parsed: ServerNotification = note.try_into()?;
    let ServerNotification::AccountLoginCompleted(payload) = parsed else {
        bail!("unexpected notification: {parsed:?}");
    };
    assert_eq!(payload.login_id, Some(login_id));
    assert_eq!(payload.success, false);
    assert!(
        payload.error.is_some(),
        "expected a non-empty error on device code cancel"
    );

    let maybe_updated = timeout(
        Duration::from_millis(500),
        mcp.read_stream_until_notification_message("account/updated"),
    )
    .await;
    assert!(
        maybe_updated.is_err(),
        "account/updated should not be emitted when device code login is cancelled"
    );
    assert!(
        !codex_home.path().join("auth.json").exists(),
        "auth.json should not be created when device code login is cancelled"
    );
    Ok(())
}

#[tokio::test]
// Serialize tests that launch the login server since it binds to a fixed port.
#[serial(login_port)]
async fn login_account_chatgpt_start_can_be_cancelled() -> Result<()> {
    let codex_home = TempDir::new()?;
    create_config_toml(codex_home.path(), CreateConfigTomlParams::default())?;

    let mut mcp = TestAppServer::builder()
        .with_codex_home(codex_home.path())
        .without_auto_env()
        .build_initialized_with_timeout(DEFAULT_READ_TIMEOUT)
        .await?;

    let request_id = mcp.send_login_account_chatgpt_request().await?;
    let login: LoginAccountResponse =
        timeout(DEFAULT_READ_TIMEOUT, mcp.read_response(request_id)).await??;
    let LoginAccountResponse::Chatgpt { login_id, auth_url } = login else {
        bail!("unexpected login response: {login:?}");
    };
    assert!(
        auth_url.contains("redirect_uri=http%3A%2F%2Flocalhost"),
        "auth_url should contain a redirect_uri to localhost"
    );

    let cancel_id = mcp
        .send_cancel_login_account_request(CancelLoginAccountParams {
            login_id: login_id.clone(),
        })
        .await?;
    let _ok: CancelLoginAccountResponse =
        timeout(DEFAULT_READ_TIMEOUT, mcp.read_response(cancel_id)).await??;

    let note = timeout(
        DEFAULT_READ_TIMEOUT,
        mcp.read_stream_until_notification_message("account/login/completed"),
    )
    .await??;
    let parsed: ServerNotification = note.try_into()?;
    let ServerNotification::AccountLoginCompleted(payload) = parsed else {
        bail!("unexpected notification: {parsed:?}");
    };
    pretty_assertions::assert_eq!(payload.login_id, Some(login_id));
    pretty_assertions::assert_eq!(payload.success, false);
    assert!(
        payload.error.is_some(),
        "expected a non-empty error on cancel"
    );

    let maybe_updated = timeout(
        Duration::from_millis(500),
        mcp.read_stream_until_notification_message("account/updated"),
    )
    .await;
    assert!(
        maybe_updated.is_err(),
        "account/updated should not be emitted when login is cancelled"
    );
    Ok(())
}

#[tokio::test]
// Serialize tests that launch the login server since it binds to a fixed port.
#[serial(login_port)]
async fn login_account_chatgpt_uses_debug_oauth_overrides() -> Result<()> {
    let codex_home = TempDir::new()?;
    create_config_toml(codex_home.path(), CreateConfigTomlParams::default())?;

    let mut mcp = TestAppServer::builder()
        .with_codex_home(codex_home.path())
        .without_auto_env()
        .with_env_overrides(&[
            (CLIENT_ID_OVERRIDE_ENV_VAR, Some("staging-client")),
            (LOGIN_ISSUER_ENV_VAR, Some("https://auth.example.com")),
        ])
        .build_initialized_with_timeout(DEFAULT_READ_TIMEOUT)
        .await?;

    let request_id = mcp.send_login_account_chatgpt_request().await?;
    let login: LoginAccountResponse =
        timeout(DEFAULT_READ_TIMEOUT, mcp.read_response(request_id)).await??;
    let LoginAccountResponse::Chatgpt { login_id, auth_url } = login else {
        bail!("unexpected login response: {login:?}");
    };
    let auth_url = Url::parse(&auth_url)?;
    assert_eq!(
        auth_url.origin().ascii_serialization(),
        "https://auth.example.com"
    );
    assert_eq!(
        auth_url
            .query_pairs()
            .find_map(|(key, value)| (key == "client_id").then_some(value.into_owned())),
        Some("staging-client".to_string())
    );

    let cancel_id = mcp
        .send_cancel_login_account_request(CancelLoginAccountParams { login_id })
        .await?;
    let _: CancelLoginAccountResponse =
        timeout(DEFAULT_READ_TIMEOUT, mcp.read_response(cancel_id)).await??;
    Ok(())
}

#[tokio::test]
// Serialize tests that launch the login server since it binds to a fixed port.
#[serial(login_port)]
async fn login_account_chatgpt_redirects_to_hosted_success_page() -> Result<()> {
    let codex_home = TempDir::new()?;
    create_config_toml(codex_home.path(), CreateConfigTomlParams::default())?;
    let mock_server = MockServer::start().await;
    let id_token = encode_id_token(
        &ChatGptIdTokenClaims::new()
            .email("hosted@example.com")
            .plan_type("pro")
            .chatgpt_account_id(WORKSPACE_ID_EMBEDDED),
    )?;
    mock_oauth_token(&mock_server, &id_token).await;
    let issuer = mock_server.uri();

    let mut mcp = TestAppServer::builder()
        .with_codex_home(codex_home.path())
        .without_auto_env()
        .with_env_overrides(&[
            (LOGIN_ISSUER_ENV_VAR, Some(issuer.as_str())),
            (
                LOGIN_OPEN_APP_URL_ENV_VAR,
                Some("http://localhost:3000/codex/open-app"),
            ),
        ])
        .build_initialized_with_timeout(DEFAULT_READ_TIMEOUT)
        .await?;

    let request_id = mcp
        .send_login_account_request(json!({
            "type": "chatgpt",
            "appBrand": "chatgpt",
            "useHostedLoginSuccessPage": true,
        }))
        .await?;
    let login: LoginAccountResponse =
        timeout(DEFAULT_READ_TIMEOUT, mcp.read_response(request_id)).await??;
    let LoginAccountResponse::Chatgpt { login_id, auth_url } = login else {
        bail!("unexpected login response: {login:?}");
    };
    let auth_url = Url::parse(&auth_url)?;
    let callback_url = auth_url
        .query_pairs()
        .find_map(|(key, value)| (key == "redirect_uri").then(|| value.into_owned()))
        .ok_or_else(|| anyhow::anyhow!("missing redirect_uri"))?;
    let state = auth_url
        .query_pairs()
        .find_map(|(key, value)| (key == "state").then(|| value.into_owned()))
        .ok_or_else(|| anyhow::anyhow!("missing state"))?;
    let client = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()?;

    let token_redirect_uri = callback_url.clone();
    let mut callback_url = Url::parse(&callback_url)?;
    let callback_state = format!("{state}.onboarding_entrypoint=life_sciences");
    callback_url
        .query_pairs_mut()
        .append_pair("code", "test-code")
        .append_pair("state", &callback_state);
    let response = client.get(callback_url).send().await?;

    assert_eq!(response.status(), 302);
    assert_eq!(
        response.headers()["location"].to_str()?,
        "http://localhost:3000/codex/open-app?source=login&app_brand=chatgpt"
    );
    let requests = mock_server
        .received_requests()
        .await
        .ok_or_else(|| anyhow::anyhow!("failed to read OAuth requests"))?;
    let token_request = requests
        .iter()
        .find(|request| request.url.path() == "/oauth/token")
        .ok_or_else(|| anyhow::anyhow!("missing OAuth token request"))?;
    let token_form: std::collections::HashMap<_, _> =
        url::form_urlencoded::parse(&token_request.body)
            .into_owned()
            .collect();
    assert_eq!(token_form.get("redirect_uri"), Some(&token_redirect_uri),);
    let notification = timeout(
        DEFAULT_READ_TIMEOUT,
        mcp.read_stream_until_notification_message("account/login/completed"),
    )
    .await??;
    let ServerNotification::AccountLoginCompleted(payload) = notification.try_into()? else {
        bail!("unexpected notification")
    };
    assert_eq!(
        payload,
        AccountLoginCompletedNotification {
            login_id: Some(login_id),
            success: true,
            error: None,
            onboarding_entrypoint: Some(DesktopOnboardingEntrypoint::LifeSciences),
            managed_account_id: Some("email:user@example.com".to_string()),
        }
    );
    Ok(())
}

#[tokio::test]
// Serialize tests that launch the login server since it binds to a fixed port.
#[serial(login_port)]
async fn set_auth_token_cancels_active_chatgpt_login() -> Result<()> {
    let codex_home = TempDir::new()?;
    create_config_toml(codex_home.path(), CreateConfigTomlParams::default())?;

    let mut mcp = TestAppServer::builder()
        .with_codex_home(codex_home.path())
        .without_auto_env()
        .build_initialized_with_timeout(DEFAULT_READ_TIMEOUT)
        .await?;

    // Initiate the ChatGPT login flow
    let request_id = mcp.send_login_account_chatgpt_request().await?;
    let login: LoginAccountResponse =
        timeout(DEFAULT_READ_TIMEOUT, mcp.read_response(request_id)).await??;
    let LoginAccountResponse::Chatgpt { login_id, .. } = login else {
        bail!("unexpected login response: {login:?}");
    };

    let access_token = encode_id_token(
        &ChatGptIdTokenClaims::new()
            .email("embedded@example.com")
            .plan_type("pro")
            .chatgpt_account_id(WORKSPACE_ID_EMBEDDED),
    )?;
    // Set an external auth token instead of completing the ChatGPT login flow.
    // This should cancel the active login attempt.
    let set_id = mcp
        .send_chatgpt_auth_tokens_login_request(
            access_token,
            WORKSPACE_ID_EMBEDDED.to_string(),
            Some("pro".to_string()),
        )
        .await?;
    let response: LoginAccountResponse =
        timeout(DEFAULT_READ_TIMEOUT, mcp.read_response(set_id)).await??;
    assert_eq!(response, LoginAccountResponse::ChatgptAuthTokens {});
    let _updated = timeout(
        DEFAULT_READ_TIMEOUT,
        mcp.read_stream_until_notification_message("account/updated"),
    )
    .await??;

    // Verify that the active login attempt was cancelled.
    // We check this by trying to cancel it and expecting a not found error.
    let cancel_id = mcp
        .send_cancel_login_account_request(CancelLoginAccountParams {
            login_id: login_id.clone(),
        })
        .await?;
    let cancel: CancelLoginAccountResponse =
        timeout(DEFAULT_READ_TIMEOUT, mcp.read_response(cancel_id)).await??;
    assert_eq!(cancel.status, CancelLoginAccountStatus::NotFound);

    Ok(())
}

#[tokio::test]
#[serial(login_port)]
async fn targeted_logout_does_not_cancel_an_unrelated_active_login() -> Result<()> {
    let codex_home = TempDir::new()?;
    create_config_toml(codex_home.path(), CreateConfigTomlParams::default())?;

    let mut mcp = TestAppServer::builder()
        .with_codex_home(codex_home.path())
        .without_auto_env()
        .build()
        .await?;
    timeout(DEFAULT_READ_TIMEOUT, mcp.initialize()).await??;

    let login_request_id = mcp.send_login_account_chatgpt_request().await?;
    let login_resp: JSONRPCResponse = timeout(
        DEFAULT_READ_TIMEOUT,
        mcp.read_stream_until_response_message(RequestId::Integer(login_request_id)),
    )
    .await??;
    let login: LoginAccountResponse = to_response(login_resp)?;
    let LoginAccountResponse::Chatgpt { login_id, .. } = login else {
        bail!("unexpected login response: {login:?}");
    };

    let logout_id = mcp
        .send_logout_account_request_with_params(json!({
            "accountId": "email:other@example.com",
            "all": false
        }))
        .await?;
    let logout_resp: JSONRPCResponse = timeout(
        DEFAULT_READ_TIMEOUT,
        mcp.read_stream_until_response_message(RequestId::Integer(logout_id)),
    )
    .await??;
    let logout: LogoutAccountResponse = to_response(logout_resp)?;
    assert!(logout.removed_account_ids.is_empty());

    let cancel_id = mcp
        .send_cancel_login_account_request(CancelLoginAccountParams {
            login_id: login_id.clone(),
        })
        .await?;
    let cancel_resp: JSONRPCResponse = timeout(
        DEFAULT_READ_TIMEOUT,
        mcp.read_stream_until_response_message(RequestId::Integer(cancel_id)),
    )
    .await??;
    let cancel: CancelLoginAccountResponse = to_response(cancel_resp)?;
    assert_eq!(cancel.status, CancelLoginAccountStatus::Canceled);
    Ok(())
}

#[tokio::test]
// Serialize tests that launch the login server since it binds to a fixed port.
#[serial(login_port)]
async fn login_account_chatgpt_includes_forced_workspace_query_param() -> Result<()> {
    let codex_home = TempDir::new()?;
    create_config_toml(
        codex_home.path(),
        CreateConfigTomlParams {
            forced_workspace_id: Some(WORKSPACE_ID_ALLOWED.to_string()),
            ..Default::default()
        },
    )?;

    let mut mcp = TestAppServer::builder()
        .with_codex_home(codex_home.path())
        .without_auto_env()
        .build_initialized_with_timeout(DEFAULT_READ_TIMEOUT)
        .await?;

    let request_id = mcp.send_login_account_chatgpt_request().await?;
    let login: LoginAccountResponse =
        timeout(DEFAULT_READ_TIMEOUT, mcp.read_response(request_id)).await??;
    let LoginAccountResponse::Chatgpt { auth_url, .. } = login else {
        bail!("unexpected login response: {login:?}");
    };
    assert!(
        auth_url.contains(&format!("allowed_workspace_id={WORKSPACE_ID_ALLOWED}")),
        "auth URL should include forced workspace"
    );
    Ok(())
}

#[tokio::test]
// Serialize tests that launch the login server since it binds to a fixed port.
#[serial(login_port)]
async fn login_account_chatgpt_includes_forced_workspace_allowlist_query_param() -> Result<()> {
    let codex_home = TempDir::new()?;
    create_config_toml(
        codex_home.path(),
        CreateConfigTomlParams {
            forced_workspace_ids: Some(vec![
                WORKSPACE_ID_ALLOWED.to_string(),
                WORKSPACE_ID_SECOND_ALLOWED.to_string(),
            ]),
            ..Default::default()
        },
    )?;

    let mut mcp = TestAppServer::builder()
        .with_codex_home(codex_home.path())
        .without_auto_env()
        .build_initialized_with_timeout(DEFAULT_READ_TIMEOUT)
        .await?;

    let request_id = mcp.send_login_account_chatgpt_request().await?;
    let login: LoginAccountResponse =
        timeout(DEFAULT_READ_TIMEOUT, mcp.read_response(request_id)).await??;
    let LoginAccountResponse::Chatgpt { auth_url, .. } = login else {
        bail!("unexpected login response: {login:?}");
    };
    let auth_url = Url::parse(&auth_url)?;
    let allowed_workspace_ids = auth_url
        .query_pairs()
        .filter_map(|(key, value)| (key == "allowed_workspace_id").then(|| value.into_owned()))
        .collect::<Vec<_>>();
    assert_eq!(
        allowed_workspace_ids,
        vec![format!(
            "{WORKSPACE_ID_ALLOWED},{WORKSPACE_ID_SECOND_ALLOWED}"
        )]
    );
    Ok(())
}

#[tokio::test]
async fn get_account_no_auth() -> Result<()> {
    let codex_home = TempDir::new()?;
    create_config_toml(
        codex_home.path(),
        CreateConfigTomlParams {
            requires_openai_auth: Some(true),
            ..Default::default()
        },
    )?;

    let mut mcp = TestAppServer::builder()
        .with_codex_home(codex_home.path())
        .without_auto_env()
        .with_env_overrides(&[("OPENAI_API_KEY", None)])
        .build_initialized_with_timeout(DEFAULT_READ_TIMEOUT)
        .await?;

    let params = GetAccountParams {
        refresh_token: false,
    };
    let request_id = mcp.send_get_account_request(params).await?;

    let account: GetAccountResponse =
        timeout(DEFAULT_READ_TIMEOUT, mcp.read_response(request_id)).await??;

    assert_eq!(account.account, None, "expected no account");
    assert_eq!(account.requires_openai_auth, true);
    Ok(())
}

#[tokio::test]
async fn get_account_with_api_key() -> Result<()> {
    let codex_home = TempDir::new()?;
    create_config_toml(
        codex_home.path(),
        CreateConfigTomlParams {
            requires_openai_auth: Some(true),
            ..Default::default()
        },
    )?;

    let mut mcp = TestAppServer::builder()
        .with_codex_home(codex_home.path())
        .without_auto_env()
        .build_initialized_with_timeout(DEFAULT_READ_TIMEOUT)
        .await?;

    let req_id = mcp
        .send_login_account_api_key_request("sk-test-key")
        .await?;
    let resp: JSONRPCResponse = timeout(
        DEFAULT_READ_TIMEOUT,
        mcp.read_stream_until_response_message(RequestId::Integer(req_id)),
    )
    .await??;
    let _login_ok = to_response::<LoginAccountResponse>(resp)?;
    let mut login_completed = false;
    let mut account_updated = false;
    for _ in 0..2 {
        let message = timeout(DEFAULT_READ_TIMEOUT, mcp.read_stream_message()).await??;
        let JSONRPCMessage::Notification(notification) = message else {
            bail!("expected API key login notification, got {message:?}");
        };
        match notification.method.as_str() {
            "account/login/completed" => login_completed = true,
            "account/updated" => account_updated = true,
            method => bail!("unexpected notification after API key login: {method}"),
        }
    }
    assert!(login_completed);
    assert!(account_updated);
    assert!(
        timeout(Duration::from_millis(250), mcp.read_stream_message())
            .await
            .is_err(),
        "API key login must not publish a managed account pool notification"
    );

    let list_id = mcp
        .send_list_accounts_request(json!({
            "threadId": "api-key-thread",
            "model": "mock-model",
            "refreshTokens": false,
            "refreshUsage": false
        }))
        .await?;
    let list_resp: JSONRPCResponse = timeout(
        DEFAULT_READ_TIMEOUT,
        mcp.read_stream_until_response_message(RequestId::Integer(list_id)),
    )
    .await??;
    let list: ListAccountsResponse = to_response(list_resp)?;
    assert!(list.accounts.is_empty());
    assert_eq!(list.pool_revision, 0);
    assert_eq!(list.selected_account_id, None);
    assert_eq!(list.selection_revision, None);
    assert!(
        timeout(Duration::from_millis(250), mcp.read_stream_message())
            .await
            .is_err(),
        "scoped account/list in API key mode must not publish a selection notification"
    );

    let params = GetAccountParams {
        refresh_token: false,
    };
    let request_id = mcp.send_get_account_request(params).await?;

    let received: GetAccountResponse =
        timeout(DEFAULT_READ_TIMEOUT, mcp.read_response(request_id)).await??;

    let expected = GetAccountResponse {
        account: Some(Account::ApiKey {}),
        requires_openai_auth: true,
    };
    assert_eq!(received, expected);
    Ok(())
}

#[tokio::test]
async fn scoped_account_list_is_singular_in_personal_access_token_mode() -> Result<()> {
    let codex_home = TempDir::new()?;
    let mock_server = MockServer::start().await;
    create_config_toml(codex_home.path(), CreateConfigTomlParams::default())?;
    save_auth(
        codex_home.path(),
        &AuthDotJson {
            auth_mode: None,
            openai_api_key: None,
            tokens: None,
            last_refresh: None,
            agent_identity: None,
            managed_chatgpt: None,
            personal_access_token: Some("at-app-server-test".to_string()),
            bedrock_api_key: None,
        },
        AuthCredentialsStoreMode::File,
        AuthKeyringBackendKind::Direct,
    )?;
    Mock::given(method("GET"))
        .and(path("/v1/user-auth-credential/whoami"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "email": "pat@example.com",
            "chatgpt_user_id": "user-123",
            "chatgpt_account_id": WORKSPACE_ID_ALLOWED,
            "chatgpt_plan_type": "pro",
            "chatgpt_account_is_fedramp": false
        })))
        .expect(1..=2)
        .mount(&mock_server)
        .await;
    let authapi_base_url = mock_server.uri();
    let mut mcp = TestAppServer::builder()
        .with_codex_home(codex_home.path())
        .without_auto_env()
        .with_env_overrides(&[
            ("OPENAI_API_KEY", None),
            ("CODEX_AUTHAPI_BASE_URL", Some(authapi_base_url.as_str())),
        ])
        .build()
        .await?;
    timeout(DEFAULT_READ_TIMEOUT, mcp.initialize()).await??;

    let list_id = mcp
        .send_list_accounts_request(json!({
            "threadId": "pat-thread",
            "model": "mock-model",
            "refreshTokens": false,
            "refreshUsage": false
        }))
        .await?;
    let list: ListAccountsResponse = to_response(
        timeout(
            DEFAULT_READ_TIMEOUT,
            mcp.read_stream_until_response_message(RequestId::Integer(list_id)),
        )
        .await??,
    )?;
    assert!(list.accounts.is_empty());
    assert_eq!(list.pool_revision, 0);
    assert_eq!(list.selection_revision, None);
    assert!(
        timeout(Duration::from_millis(250), mcp.read_stream_message())
            .await
            .is_err(),
        "scoped account/list in PAT mode must not publish managed notifications"
    );
    mock_server.verify().await;
    Ok(())
}

#[tokio::test]
async fn get_account_when_auth_not_required() -> Result<()> {
    let codex_home = TempDir::new()?;
    create_config_toml(
        codex_home.path(),
        CreateConfigTomlParams {
            requires_openai_auth: Some(false),
            ..Default::default()
        },
    )?;

    let mut mcp = TestAppServer::builder()
        .with_codex_home(codex_home.path())
        .without_auto_env()
        .build_initialized_with_timeout(DEFAULT_READ_TIMEOUT)
        .await?;

    let params = GetAccountParams {
        refresh_token: false,
    };
    let request_id = mcp.send_get_account_request(params).await?;

    let received: GetAccountResponse =
        timeout(DEFAULT_READ_TIMEOUT, mcp.read_response(request_id)).await??;

    let expected = GetAccountResponse {
        account: None,
        requires_openai_auth: false,
    };
    assert_eq!(received, expected);
    Ok(())
}

#[tokio::test]
async fn get_account_with_aws_provider() -> Result<()> {
    let codex_home = TempDir::new()?;
    create_config_toml(
        codex_home.path(),
        CreateConfigTomlParams {
            model_provider_id: Some("amazon-bedrock".to_string()),
            extra_provider_config: Some(
                r#"[model_providers.amazon-bedrock.aws]
profile = "codex-bedrock"
region = "us-west-2"
"#
                .to_string(),
            ),
            ..Default::default()
        },
    )?;

    let mut mcp = TestAppServer::builder()
        .with_codex_home(codex_home.path())
        .without_auto_env()
        .build_initialized_with_timeout(DEFAULT_READ_TIMEOUT)
        .await?;

    let params = GetAccountParams {
        refresh_token: false,
    };
    let request_id = mcp.send_get_account_request(params).await?;

    let received: GetAccountResponse =
        timeout(DEFAULT_READ_TIMEOUT, mcp.read_response(request_id)).await??;

    let expected = GetAccountResponse {
        account: Some(Account::AmazonBedrock {
            uses_codex_managed_credentials: false,
        }),
        requires_openai_auth: false,
    };
    assert_eq!(received, expected);
    Ok(())
}

#[tokio::test]
async fn get_account_with_user_managed_bedrock_provider() -> Result<()> {
    let codex_home = TempDir::new()?;
    create_config_toml(
        codex_home.path(),
        CreateConfigTomlParams {
            model_provider_id: Some("amazon-bedrock".to_string()),
            extra_provider_config: Some(
                r#"[model_providers.amazon-bedrock]
base_url = "https://bedrock.example.com/v1"

[model_providers.amazon-bedrock.auth]
command = "print-token"
"#
                .to_string(),
            ),
            ..Default::default()
        },
    )?;

    let mut mcp = TestAppServer::builder()
        .with_codex_home(codex_home.path())
        .without_auto_env()
        .build_initialized_with_timeout(DEFAULT_READ_TIMEOUT)
        .await?;

    assert_eq!(
        read_account(&mut mcp).await?,
        GetAccountResponse {
            account: Some(Account::AmazonBedrock {
                uses_codex_managed_credentials: false,
            }),
            requires_openai_auth: false,
        }
    );
    Ok(())
}

#[tokio::test]
async fn account_reads_use_startup_config_when_config_reload_fails() -> Result<()> {
    let codex_home = TempDir::new()?;
    create_config_toml(
        codex_home.path(),
        CreateConfigTomlParams {
            model_provider_id: Some("amazon-bedrock".to_string()),
            extra_provider_config: Some(
                r#"[model_providers.amazon-bedrock.aws]
profile = "codex-bedrock"
region = "us-west-2"
"#
                .to_string(),
            ),
            ..Default::default()
        },
    )?;

    let mut mcp = TestAppServer::builder()
        .with_codex_home(codex_home.path())
        .without_auto_env()
        .build_initialized_with_timeout(DEFAULT_READ_TIMEOUT)
        .await?;

    std::fs::write(codex_home.path().join("config.toml"), "invalid = [")?;

    assert_eq!(
        read_account(&mut mcp).await?,
        GetAccountResponse {
            account: Some(Account::AmazonBedrock {
                uses_codex_managed_credentials: false,
            }),
            requires_openai_auth: false,
        }
    );

    let request_id = mcp
        .send_get_auth_status_request(GetAuthStatusParams {
            include_token: Some(false),
            refresh_token: Some(false),
        })
        .await?;
    let response = timeout(
        DEFAULT_READ_TIMEOUT,
        mcp.read_stream_until_response_message(RequestId::Integer(request_id)),
    )
    .await??;
    assert_eq!(
        to_response::<GetAuthStatusResponse>(response)?,
        GetAuthStatusResponse {
            auth_method: None,
            auth_token: None,
            requires_openai_auth: Some(false),
        }
    );

    Ok(())
}

#[tokio::test]
async fn get_account_with_managed_bedrock_provider() -> Result<()> {
    let codex_home = TempDir::new()?;
    create_config_toml(
        codex_home.path(),
        CreateConfigTomlParams {
            model_provider_id: Some("amazon-bedrock".to_string()),
            ..Default::default()
        },
    )?;
    login_with_bedrock_api_key(
        codex_home.path(),
        "managed-bedrock-api-key",
        "us-west-2",
        AuthCredentialsStoreMode::File,
        AuthKeyringBackendKind::default(),
    )?;

    let mut mcp = TestAppServer::builder()
        .with_codex_home(codex_home.path())
        .without_auto_env()
        .build_initialized_with_timeout(DEFAULT_READ_TIMEOUT)
        .await?;

    let request_id = mcp
        .send_get_account_request(GetAccountParams {
            refresh_token: false,
        })
        .await?;
    let received: GetAccountResponse =
        timeout(DEFAULT_READ_TIMEOUT, mcp.read_response(request_id)).await??;

    assert_eq!(
        received,
        GetAccountResponse {
            account: Some(Account::AmazonBedrock {
                uses_codex_managed_credentials: true,
            }),
            requires_openai_auth: false,
        }
    );

    let list_id = mcp
        .send_list_accounts_request(json!({
            "threadId": "bedrock-thread",
            "model": "mock-model",
            "refreshTokens": false,
            "refreshUsage": false
        }))
        .await?;
    let list: ListAccountsResponse = to_response(
        timeout(
            DEFAULT_READ_TIMEOUT,
            mcp.read_stream_until_response_message(RequestId::Integer(list_id)),
        )
        .await??,
    )?;
    assert!(list.accounts.is_empty());
    assert_eq!(list.pool_revision, 0);
    assert_eq!(list.selection_revision, None);
    assert!(
        timeout(Duration::from_millis(250), mcp.read_stream_message())
            .await
            .is_err(),
        "scoped account/list in Bedrock mode must not publish managed notifications"
    );
    Ok(())
}

#[tokio::test]
async fn get_account_with_chatgpt() -> Result<()> {
    let codex_home = TempDir::new()?;
    create_config_toml(
        codex_home.path(),
        CreateConfigTomlParams {
            requires_openai_auth: Some(true),
            ..Default::default()
        },
    )?;
    write_chatgpt_auth(
        codex_home.path(),
        ChatGptAuthFixture::new("access-chatgpt")
            .email("user@example.com")
            .plan_type("pro"),
        AuthCredentialsStoreMode::File,
    )?;

    let mut mcp = TestAppServer::builder()
        .with_codex_home(codex_home.path())
        .without_auto_env()
        .with_env_overrides(&[("OPENAI_API_KEY", None)])
        .build_initialized_with_timeout(DEFAULT_READ_TIMEOUT)
        .await?;

    let params = GetAccountParams {
        refresh_token: false,
    };
    let request_id = mcp.send_get_account_request(params).await?;

    let received: GetAccountResponse =
        timeout(DEFAULT_READ_TIMEOUT, mcp.read_response(request_id)).await??;

    let expected = GetAccountResponse {
        account: Some(Account::Chatgpt {
            email: Some("user@example.com".to_string()),
            plan_type: AccountPlanType::Pro,
        }),
        requires_openai_auth: true,
    };
    assert_eq!(received, expected);
    Ok(())
}

#[tokio::test]
async fn get_account_with_business_prolite_returns_plan_type() -> Result<()> {
    let codex_home = TempDir::new()?;
    create_config_toml(
        codex_home.path(),
        CreateConfigTomlParams {
            requires_openai_auth: Some(true),
            ..Default::default()
        },
    )?;
    write_chatgpt_auth(
        codex_home.path(),
        ChatGptAuthFixture::new("access-chatgpt")
            .email("user@example.com")
            .plan_type("self_serve_business_prolite"),
        AuthCredentialsStoreMode::File,
    )?;

    let mut mcp = TestAppServer::builder()
        .with_codex_home(codex_home.path())
        .without_auto_env()
        .with_env_overrides(&[("OPENAI_API_KEY", None)])
        .build_initialized_with_timeout(DEFAULT_READ_TIMEOUT)
        .await?;

    let request_id = mcp
        .send_get_account_request(GetAccountParams {
            refresh_token: false,
        })
        .await?;
    let received: GetAccountResponse =
        timeout(DEFAULT_READ_TIMEOUT, mcp.read_response(request_id)).await??;

    assert_eq!(
        received,
        GetAccountResponse {
            account: Some(Account::Chatgpt {
                email: Some("user@example.com".to_string()),
                plan_type: AccountPlanType::SelfServeBusinessProLite,
            }),
            requires_openai_auth: true,
        }
    );
    Ok(())
}

#[tokio::test]
async fn get_account_with_chatgpt_without_email() -> Result<()> {
    let codex_home = TempDir::new()?;
    create_config_toml(
        codex_home.path(),
        CreateConfigTomlParams {
            requires_openai_auth: Some(true),
            ..Default::default()
        },
    )?;
    write_chatgpt_auth(
        codex_home.path(),
        ChatGptAuthFixture::new("access-chatgpt").plan_type("pro"),
        AuthCredentialsStoreMode::File,
    )?;

    let mut mcp = TestAppServer::builder()
        .with_codex_home(codex_home.path())
        .without_auto_env()
        .with_env_overrides(&[("OPENAI_API_KEY", None)])
        .build_initialized_with_timeout(DEFAULT_READ_TIMEOUT)
        .await?;

    let request_id = mcp
        .send_get_account_request(GetAccountParams {
            refresh_token: false,
        })
        .await?;
    let received: GetAccountResponse =
        timeout(DEFAULT_READ_TIMEOUT, mcp.read_response(request_id)).await??;

    assert_eq!(
        received,
        GetAccountResponse {
            account: Some(Account::Chatgpt {
                email: None,
                plan_type: AccountPlanType::Pro,
            }),
            requires_openai_auth: true,
        }
    );
    Ok(())
}

#[tokio::test]
async fn get_account_omits_chatgpt_after_permanent_refresh_failure() -> Result<()> {
    let codex_home = TempDir::new()?;
    create_config_toml(
        codex_home.path(),
        CreateConfigTomlParams {
            requires_openai_auth: Some(true),
            ..Default::default()
        },
    )?;
    write_chatgpt_auth(
        codex_home.path(),
        ChatGptAuthFixture::new("stale-access-token")
            .refresh_token("stale-refresh-token")
            .account_id(WORKSPACE_ID_STALE)
            .email("user@example.com")
            .plan_type("pro")
            .last_refresh(Some(Utc::now() - ChronoDuration::days(9))),
        AuthCredentialsStoreMode::File,
    )?;

    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/oauth/token"))
        .respond_with(ResponseTemplate::new(401).set_body_json(serde_json::json!({
            "error": {
                "code": "refresh_token_reused"
            }
        })))
        .expect(1..=2)
        .mount(&server)
        .await;

    let refresh_url = format!("{}/oauth/token", server.uri());
    let mut mcp = TestAppServer::builder()
        .with_codex_home(codex_home.path())
        .without_auto_env()
        .with_env_overrides(&[
            ("OPENAI_API_KEY", None),
            (
                REFRESH_TOKEN_URL_OVERRIDE_ENV_VAR,
                Some(refresh_url.as_str()),
            ),
        ])
        .build_initialized_with_timeout(DEFAULT_READ_TIMEOUT)
        .await?;

    let auth_status_request_id = mcp
        .send_get_auth_status_request(GetAuthStatusParams {
            include_token: Some(true),
            refresh_token: Some(true),
        })
        .await?;
    let _: GetAuthStatusResponse = timeout(
        DEFAULT_READ_TIMEOUT,
        mcp.read_response(auth_status_request_id),
    )
    .await??;

    let request_id = mcp
        .send_get_account_request(GetAccountParams {
            refresh_token: false,
        })
        .await?;

    let received: GetAccountResponse =
        timeout(DEFAULT_READ_TIMEOUT, mcp.read_response(request_id)).await??;

    assert_eq!(
        received,
        GetAccountResponse {
            account: None,
            requires_openai_auth: true,
        }
    );
    server.verify().await;
    Ok(())
}

#[tokio::test]
async fn get_account_with_chatgpt_missing_plan_claim_returns_unknown() -> Result<()> {
    let codex_home = TempDir::new()?;
    create_config_toml(
        codex_home.path(),
        CreateConfigTomlParams {
            requires_openai_auth: Some(true),
            ..Default::default()
        },
    )?;
    write_chatgpt_auth(
        codex_home.path(),
        ChatGptAuthFixture::new("access-chatgpt").email("user@example.com"),
        AuthCredentialsStoreMode::File,
    )?;

    let mut mcp = TestAppServer::builder()
        .with_codex_home(codex_home.path())
        .without_auto_env()
        .with_env_overrides(&[("OPENAI_API_KEY", None)])
        .build_initialized_with_timeout(DEFAULT_READ_TIMEOUT)
        .await?;

    let params = GetAccountParams {
        refresh_token: false,
    };
    let request_id = mcp.send_get_account_request(params).await?;

    let received: GetAccountResponse =
        timeout(DEFAULT_READ_TIMEOUT, mcp.read_response(request_id)).await??;

    let expected = GetAccountResponse {
        account: Some(Account::Chatgpt {
            email: Some("user@example.com".to_string()),
            plan_type: AccountPlanType::Unknown,
        }),
        requires_openai_auth: true,
    };
    assert_eq!(received, expected);
    Ok(())
}
