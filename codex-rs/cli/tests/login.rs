use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::AtomicUsize;
use std::sync::atomic::Ordering;
use std::time::Duration;
use std::time::Instant;

use anyhow::Context;
use anyhow::Result;
use app_test_support::ChatGptAuthFixture;
use app_test_support::ChatGptIdTokenClaims;
use app_test_support::encode_id_token;
use app_test_support::write_chatgpt_auth;
use codex_config::types::AuthCredentialsStoreMode;
use codex_core::config::ConfigBuilder;
use codex_login::AuthKeyringBackendKind;
use codex_login::AuthManager;
use codex_login::CODEX_ACCESS_TOKEN_ENV_VAR;
use codex_login::ManagedChatgptOauthCredentials;
use codex_login::ManagedChatgptSelectionScope;
use codex_login::OPENAI_API_KEY_ENV_VAR;
use codex_login::REVOKE_TOKEN_URL_OVERRIDE_ENV_VAR;
use codex_login::TokenData;
use codex_login::token_data::IdTokenInfo;
use predicates::str::contains;
use pretty_assertions::assert_eq;
use serde_json::Value;
use serde_json::json;
use tempfile::TempDir;
use wiremock::Mock;
use wiremock::MockServer;
use wiremock::ResponseTemplate;
use wiremock::matchers::body_string_contains;
use wiremock::matchers::header;
use wiremock::matchers::method;
use wiremock::matchers::path;

fn codex_command(codex_home: &Path) -> Result<assert_cmd::Command> {
    let mut cmd = assert_cmd::Command::new(codex_utils_cargo_bin::cargo_bin("codex")?);
    cmd.env("CODEX_HOME", codex_home);
    Ok(cmd)
}

fn write_file_auth_config(codex_home: &Path) -> Result<()> {
    std::fs::write(
        codex_home.join("config.toml"),
        "cli_auth_credentials_store = \"file\"\n",
    )?;
    Ok(())
}

fn read_auth_json(codex_home: &Path) -> Result<Value> {
    let auth_json = std::fs::read_to_string(codex_home.join("auth.json"))?;
    Ok(serde_json::from_str(&auth_json)?)
}

fn managed_credentials(
    email: &str,
    account_id: &str,
    access_token: &str,
    refresh_token: &str,
) -> Result<ManagedChatgptOauthCredentials> {
    Ok(ManagedChatgptOauthCredentials {
        tokens: TokenData {
            id_token: IdTokenInfo {
                email: Some(email.to_string()),
                chatgpt_account_id: Some(account_id.to_string()),
                raw_jwt: "e30.e30.c2ln".to_string(),
                ..Default::default()
            },
            access_token: access_token.to_string(),
            refresh_token: refresh_token.to_string(),
            account_id: Some(account_id.to_string()),
        },
        last_refresh: chrono::DateTime::parse_from_rfc3339("2026-07-14T00:00:00Z")?
            .with_timezone(&chrono::Utc),
        oauth_api_key: None,
    })
}

async fn seed_managed_account(codex_home: &Path) -> Result<std::sync::Arc<AuthManager>> {
    let manager = AuthManager::shared(
        codex_home.to_path_buf(),
        false,
        AuthCredentialsStoreMode::File,
        None,
        None,
        AuthKeyringBackendKind::Direct,
        codex_login::test_support::transport_default_auth_route_config(),
    )
    .await;
    manager
        .upsert_managed_chatgpt_oauth(managed_credentials(
            "managed@example.com",
            "managed-workspace",
            "managed-access",
            "managed-refresh",
        )?)
        .await
        .context("seed managed account")?;
    Ok(manager)
}

#[test]
fn login_with_api_key_reads_stdin_and_writes_auth_json() -> Result<()> {
    let codex_home = TempDir::new()?;
    write_file_auth_config(codex_home.path())?;

    let mut cmd = codex_command(codex_home.path())?;
    cmd.args([
        "-c",
        "forced_login_method=\"api\"",
        "login",
        "--with-api-key",
    ])
    .write_stdin("sk-test\n")
    .assert()
    .success()
    .stderr(contains("Successfully logged in"));

    let auth = read_auth_json(codex_home.path())?;
    assert_eq!(auth["OPENAI_API_KEY"], "sk-test");
    assert!(auth.get("tokens").is_none());
    assert!(auth.get("agent_identity").is_none());

    Ok(())
}

#[tokio::test]
async fn login_status_prefers_environment_api_key_over_managed_pool() -> Result<()> {
    let codex_home = TempDir::new()?;
    write_file_auth_config(codex_home.path())?;
    let manager = seed_managed_account(codex_home.path()).await?;

    let mut cmd = codex_command(codex_home.path())?;
    cmd.env(OPENAI_API_KEY_ENV_VAR, "sk-env-1234567890ABCDE")
        .env_remove("CODEX_ACCESS_TOKEN")
        .args(["login", "status"])
        .assert()
        .success()
        .stdout(predicates::str::is_empty())
        .stderr(contains("Logged in using an API key - sk-env-1***ABCDE"));

    assert_eq!(
        manager
            .list_managed_chatgpt_accounts(&ManagedChatgptSelectionScope::default())
            .await?
            .accounts
            .len(),
        1
    );
    Ok(())
}

#[tokio::test]
async fn doctor_reports_environment_api_key_over_managed_pool() -> Result<()> {
    let codex_home = TempDir::new()?;
    write_file_auth_config(codex_home.path())?;
    let manager = seed_managed_account(codex_home.path()).await?;

    let output = codex_command(codex_home.path())?
        .env(OPENAI_API_KEY_ENV_VAR, "sk-env-doctor")
        .env_remove(CODEX_ACCESS_TOKEN_ENV_VAR)
        .env_remove("CODEX_API_KEY")
        .args(["doctor", "--json"])
        .output()?;
    let report: Value =
        serde_json::from_slice(&output.stdout).context("parse doctor JSON report")?;

    assert_eq!(
        report["checks"]["auth.credentials"]["details"]["effective auth mode"],
        "api_key"
    );
    assert_eq!(
        manager
            .list_managed_chatgpt_accounts(&ManagedChatgptSelectionScope::default())
            .await?
            .accounts
            .len(),
        1
    );
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn login_status_surfaces_disallowed_env_token_over_managed_pool() -> Result<()> {
    let codex_home = TempDir::new()?;
    std::fs::write(
        codex_home.path().join("config.toml"),
        "cli_auth_credentials_store = \"file\"\nforced_chatgpt_workspace_id = [\"allowed-workspace\"]\n",
    )?;
    let manager = seed_managed_account(codex_home.path()).await?;
    let authapi = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/v1/user-auth-credential/whoami"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "email": "override@example.com",
            "chatgpt_user_id": "override-user",
            "chatgpt_account_id": "disallowed-workspace",
            "chatgpt_plan_type": "plus",
            "chatgpt_account_is_fedramp": false
        })))
        .expect(1)
        .mount(&authapi)
        .await;

    let assert = codex_command(codex_home.path())?
        .env(CODEX_ACCESS_TOKEN_ENV_VAR, "at-workspace-mismatch")
        .env("CODEX_AUTHAPI_BASE_URL", authapi.uri())
        .env_remove(OPENAI_API_KEY_ENV_VAR)
        .env_remove("CODEX_API_KEY")
        .args(["login", "status"])
        .assert()
        .failure()
        .stdout(predicates::str::is_empty());
    let stderr = String::from_utf8_lossy(&assert.get_output().stderr);
    assert!(
        stderr.contains("restricted to workspace id(s) allowed-workspace"),
        "{stderr}"
    );
    assert!(!stderr.contains("managed@example.com"), "{stderr}");
    assert_eq!(
        manager
            .list_managed_chatgpt_accounts(&ManagedChatgptSelectionScope::default())
            .await?
            .accounts
            .len(),
        1
    );
    authapi.verify().await;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn login_status_bounds_stalled_refresh_and_continues_healthy_sibling() -> Result<()> {
    const STALLED_REFRESH_TOKEN: &str = "stalled-refresh-secret";
    const HEALTHY_REFRESH_TOKEN: &str = "healthy-refresh-secret";
    const HEALTHY_ACCESS_TOKEN: &str = "healthy-access-secret";
    const HEALTHY_REFRESHED_ACCESS_TOKEN: &str = "healthy-refreshed-access-secret";
    const HEALTHY_REFRESHED_TOKEN: &str = "healthy-refreshed-secret";
    const ZERO_RESET_ACCESS_TOKEN: &str = "zero-reset-access-secret";
    const RESET_CREDIT_ID: &str = "reset-credit-id-secret";

    let codex_home = TempDir::new()?;
    let server = MockServer::start().await;
    std::fs::write(
        codex_home.path().join("config.toml"),
        format!(
            "cli_auth_credentials_store = \"file\"\nchatgpt_base_url = \"{}/backend-api\"\n\
             [features]\napps = false\nplugins = false\n",
            server.uri()
        ),
    )?;
    let manager = AuthManager::shared(
        codex_home.path().to_path_buf(),
        false,
        AuthCredentialsStoreMode::File,
        None,
        None,
        AuthKeyringBackendKind::Direct,
        codex_login::test_support::transport_default_auth_route_config(),
    )
    .await;
    let mut stalled_credentials = managed_credentials(
        "stalled@example.com",
        "stalled-workspace",
        "stalled-access-secret",
        STALLED_REFRESH_TOKEN,
    )?;
    stalled_credentials.last_refresh = chrono::Utc::now() - chrono::Duration::days(9);
    manager
        .upsert_managed_chatgpt_oauth(stalled_credentials)
        .await?;
    let mut healthy_credentials = managed_credentials(
        "healthy@example.com",
        "healthy-workspace",
        HEALTHY_ACCESS_TOKEN,
        HEALTHY_REFRESH_TOKEN,
    )?;
    healthy_credentials.last_refresh = chrono::Utc::now() - chrono::Duration::days(9);
    manager
        .upsert_managed_chatgpt_oauth(healthy_credentials)
        .await?;
    let mut zero_reset_credentials = managed_credentials(
        "zero-reset@example.com",
        "zero-reset-workspace",
        ZERO_RESET_ACCESS_TOKEN,
        "zero-reset-refresh-secret",
    )?;
    zero_reset_credentials.last_refresh = chrono::Utc::now();
    manager
        .upsert_managed_chatgpt_oauth(zero_reset_credentials)
        .await?;

    Mock::given(method("POST"))
        .and(path("/oauth/token"))
        .and(body_string_contains(format!(
            "\"refresh_token\":\"{STALLED_REFRESH_TOKEN}\""
        )))
        .respond_with(
            ResponseTemplate::new(200)
                .set_delay(Duration::from_secs(8))
                .set_body_json(json!({
                    "access_token": "stalled-refreshed-secret",
                    "refresh_token": "stalled-rotated-secret",
                })),
        )
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/backend-api/wham/usage"))
        .and(header(
            "authorization",
            format!("Bearer {ZERO_RESET_ACCESS_TOKEN}"),
        ))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "plan_type": "plus",
            "rate_limit": {
                "allowed": true,
                "limit_reached": false,
                "primary_window": {
                    "used_percent": 10,
                    "limit_window_seconds": 18000,
                    "reset_after_seconds": 18000,
                    "reset_at": 1_774_000_000,
                },
                "secondary_window": {
                    "used_percent": 20,
                    "limit_window_seconds": 604800,
                    "reset_after_seconds": 604800,
                    "reset_at": 1_774_400_000,
                }
            },
            "rate_limit_reset_credits": { "available_count": 0 }
        })))
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/oauth/token"))
        .and(body_string_contains(format!(
            "\"refresh_token\":\"{HEALTHY_REFRESH_TOKEN}\""
        )))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "access_token": HEALTHY_REFRESHED_ACCESS_TOKEN,
            "refresh_token": HEALTHY_REFRESHED_TOKEN,
        })))
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/backend-api/wham/rate-limit-reset-credits"))
        .and(header(
            "authorization",
            format!("Bearer {ZERO_RESET_ACCESS_TOKEN}"),
        ))
        .respond_with(ResponseTemplate::new(500))
        .expect(0)
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/backend-api/wham/usage"))
        .and(header(
            "authorization",
            format!("Bearer {HEALTHY_REFRESHED_ACCESS_TOKEN}"),
        ))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "plan_type": "pro",
            "rate_limit": {
                "allowed": true,
                "limit_reached": false,
                "primary_window": {
                    "used_percent": 25,
                    "limit_window_seconds": 18000,
                    "reset_after_seconds": 18000,
                    "reset_at": 1_774_000_000,
                },
                "secondary_window": {
                    "used_percent": 50,
                    "limit_window_seconds": 604800,
                    "reset_after_seconds": 604800,
                    "reset_at": 1_774_400_000,
                }
            },
            "rate_limit_reset_credits": { "available_count": 1 }
        })))
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/backend-api/wham/rate-limit-reset-credits"))
        .and(header(
            "authorization",
            format!("Bearer {HEALTHY_REFRESHED_ACCESS_TOKEN}"),
        ))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "credits": [{
                "id": RESET_CREDIT_ID,
                "reset_type": "codex_rate_limits",
                "status": "available",
                "granted_at": "2026-07-20T00:00:00Z",
                "expires_at": "2026-07-28T00:00:00Z"
            }],
            "available_count": 1
        })))
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/backend-api/wham/profiles/me"))
        .and(header(
            "authorization",
            format!("Bearer {HEALTHY_REFRESHED_ACCESS_TOKEN}"),
        ))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "stats": {
                "lifetime_tokens": 123,
                "peak_daily_tokens": 12,
                "longest_running_turn_sec": 34,
                "current_streak_days": 5,
                "longest_streak_days": 6,
                "daily_usage_buckets": null
            }
        })))
        .expect(0)
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/backend-api/wham/profiles/me"))
        .and(header(
            "authorization",
            format!("Bearer {ZERO_RESET_ACCESS_TOKEN}"),
        ))
        .respond_with(ResponseTemplate::new(500))
        .expect(0)
        .mount(&server)
        .await;

    let started = Instant::now();
    let output = codex_command(codex_home.path())?
        .env(
            codex_login::REFRESH_TOKEN_URL_OVERRIDE_ENV_VAR,
            format!("{}/oauth/token", server.uri()),
        )
        .env("NO_PROXY", "127.0.0.1,localhost")
        .env("no_proxy", "127.0.0.1,localhost")
        .env_remove(OPENAI_API_KEY_ENV_VAR)
        .env_remove(CODEX_ACCESS_TOKEN_ENV_VAR)
        .args(["login", "status"])
        .output()?;
    let elapsed = started.elapsed();

    assert!(output.status.success(), "status command failed");
    assert!(elapsed >= Duration::from_secs(4), "{elapsed:?}");
    assert!(elapsed < Duration::from_secs(10), "{elapsed:?}");
    let stdout = String::from_utf8(output.stdout)?;
    let stderr = String::from_utf8(output.stderr)?;
    let request_paths = server
        .received_requests()
        .await
        .context("failed to read managed status requests")?
        .iter()
        .map(|request| format!("{} {}", request.method, request.url.path()))
        .collect::<Vec<_>>();
    assert!(stderr.is_empty(), "{stderr}");
    assert!(stdout.contains("stalled@example.com"), "{stdout}");
    assert!(
        stdout.contains("refresh temporarily unavailable"),
        "{stdout}"
    );
    assert!(stdout.contains("healthy@example.com"), "{stdout}");
    assert!(
        stdout.contains("1 saved reset"),
        "{stdout}\nrequests: {request_paths:?}"
    );
    assert!(stdout.contains("zero-reset@example.com"), "{stdout}");
    assert!(stdout.contains("0 saved resets"), "{stdout}");
    assert!(!stdout.contains("profiles/me"), "{stdout}");
    assert!(!stdout.contains("lifetime 123"), "{stdout}");
    for secret in [
        STALLED_REFRESH_TOKEN,
        HEALTHY_REFRESH_TOKEN,
        HEALTHY_ACCESS_TOKEN,
        HEALTHY_REFRESHED_ACCESS_TOKEN,
        HEALTHY_REFRESHED_TOKEN,
        ZERO_RESET_ACCESS_TOKEN,
        "zero-reset-refresh-secret",
        "stalled-access-secret",
        "stalled-refreshed-secret",
        "stalled-rotated-secret",
        "refresh_token",
        RESET_CREDIT_ID,
    ] {
        assert!(!stdout.contains(secret), "stdout leaked {secret}: {stdout}");
        assert!(!stderr.contains(secret), "stderr leaked {secret}: {stderr}");
    }
    let auth = read_auth_json(codex_home.path())?;
    let stalled = auth["managed_chatgpt"]["accounts"]
        .as_array()
        .context("managed account rows")?
        .iter()
        .find(|account| account["normalized_email"] == "stalled@example.com")
        .context("stalled account row")?;
    assert_eq!(
        stalled["refresh_failure"]["reason_code"],
        "token_refresh_timeout"
    );
    server.verify().await;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn logout_with_env_access_token_keeps_two_row_pool_for_explicit_selection() -> Result<()> {
    let codex_home = TempDir::new()?;
    write_file_auth_config(codex_home.path())?;
    let manager = seed_managed_account(codex_home.path()).await?;
    manager
        .upsert_managed_chatgpt_oauth(managed_credentials(
            "second@example.com",
            "second-workspace",
            "second-access",
            "second-refresh",
        )?)
        .await?;

    let authapi = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/v1/user-auth-credential/whoami"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "email": "override@example.com",
            "chatgpt_user_id": "override-user",
            "chatgpt_account_id": "override-workspace",
            "chatgpt_plan_type": "plus",
            "chatgpt_account_is_fedramp": false
        })))
        .mount(&authapi)
        .await;

    let mut logout = codex_command(codex_home.path())?;
    logout
        .env(CODEX_ACCESS_TOKEN_ENV_VAR, "at-env-override")
        .env("CODEX_AUTHAPI_BASE_URL", authapi.uri())
        .args(["logout"])
        .assert()
        .failure()
        .stderr(contains(
            "Multiple managed ChatGPT accounts are logged in; rerun with `codex logout --account <identity>` or `codex logout --all`.",
        ));

    assert_eq!(
        manager
            .list_managed_chatgpt_accounts(&ManagedChatgptSelectionScope::default())
            .await?
            .accounts
            .len(),
        2
    );
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn targeted_logout_removes_only_selected_managed_account() -> Result<()> {
    let codex_home = TempDir::new()?;
    write_file_auth_config(codex_home.path())?;
    let manager = seed_managed_account(codex_home.path()).await?;
    manager
        .upsert_managed_chatgpt_oauth(managed_credentials(
            "second@example.com",
            "second-workspace",
            "second-access",
            "second-refresh",
        )?)
        .await?;
    let accounts = manager
        .list_managed_chatgpt_accounts(&ManagedChatgptSelectionScope::default())
        .await?
        .accounts;
    let target = accounts
        .iter()
        .find(|account| account.normalized_email.as_deref() == Some("managed@example.com"))
        .context("target managed account")?
        .identity_key
        .clone();

    let revoke = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/oauth/revoke"))
        .respond_with(ResponseTemplate::new(200))
        .expect(1)
        .mount(&revoke)
        .await;

    let mut logout = codex_command(codex_home.path())?;
    logout
        .env(
            REVOKE_TOKEN_URL_OVERRIDE_ENV_VAR,
            format!("{}/oauth/revoke", revoke.uri()),
        )
        .env_remove(OPENAI_API_KEY_ENV_VAR)
        .env_remove(CODEX_ACCESS_TOKEN_ENV_VAR)
        .args(["logout", "--account", &target])
        .assert()
        .success()
        .stderr(contains("Successfully logged out"));

    let remaining = manager
        .list_managed_chatgpt_accounts(&ManagedChatgptSelectionScope::default())
        .await?
        .accounts;
    assert_eq!(remaining.len(), 1);
    assert_eq!(
        remaining[0].normalized_email.as_deref(),
        Some("second@example.com")
    );
    revoke.verify().await;
    Ok(())
}

#[test]
fn logout_all_clears_non_pooled_api_key_auth() -> Result<()> {
    let codex_home = TempDir::new()?;
    write_file_auth_config(codex_home.path())?;
    let mut login = codex_command(codex_home.path())?;
    login
        .args([
            "-c",
            "forced_login_method=\"api\"",
            "login",
            "--with-api-key",
        ])
        .write_stdin("sk-test\n")
        .assert()
        .success();

    let mut logout = codex_command(codex_home.path())?;
    logout
        .args(["logout", "--all"])
        .assert()
        .success()
        .stderr(contains("Successfully logged out"));

    let mut status = codex_command(codex_home.path())?;
    status
        .env_remove(OPENAI_API_KEY_ENV_VAR)
        .env_remove("CODEX_ACCESS_TOKEN")
        .args(["login", "status"])
        .assert()
        .failure()
        .stderr(contains("Not logged in"));
    Ok(())
}

#[test]
fn login_status_reports_auth_storage_errors() -> Result<()> {
    let codex_home = TempDir::new()?;
    write_file_auth_config(codex_home.path())?;
    std::fs::write(codex_home.path().join("auth.json"), "{invalid json")?;

    codex_command(codex_home.path())?
        .args(["login", "status"])
        .assert()
        .failure()
        .stderr(contains("Error checking login status:"));

    Ok(())
}

#[test]
fn login_with_access_token_rejects_invalid_jwt() -> Result<()> {
    let codex_home = TempDir::new()?;
    write_file_auth_config(codex_home.path())?;

    let mut cmd = codex_command(codex_home.path())?;
    cmd.args(["login", "--with-access-token"])
        .write_stdin("not-a-jwt\n")
        .assert()
        .failure()
        .stderr(contains("Error logging in with access token"));

    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn debug_prompt_input_follows_authenticated_attribution_setting() -> Result<()> {
    let server = MockServer::start().await;
    let codex_home = TempDir::new()?;
    std::fs::write(
        codex_home.path().join("config.toml"),
        format!(
            "cli_auth_credentials_store = \"file\"\nchatgpt_base_url = \"{}/backend-api\"\n",
            server.uri()
        ),
    )?;
    let config = ConfigBuilder::default()
        .codex_home(codex_home.path().to_path_buf())
        .build()
        .await?;
    assert_eq!(
        config.chatgpt_base_url,
        format!("{}/backend-api", server.uri())
    );
    let workspace_id = config
        .forced_chatgpt_workspace_id
        .as_ref()
        .and_then(|workspace_ids| workspace_ids.first())
        .cloned()
        .unwrap_or_else(|| "workspace-123".to_string());
    let request_count = Arc::new(AtomicUsize::new(0));
    Mock::given(method("GET"))
        .and(path("/backend-api/wham/settings/user"))
        .and(header("chatgpt-account-id", workspace_id.clone()))
        .respond_with({
            let request_count = Arc::clone(&request_count);
            move |_request: &wiremock::Request| {
                ResponseTemplate::new(200).set_body_json(json!({
                    "commit_attribution_enabled": request_count.fetch_add(1, Ordering::SeqCst) == 0,
                }))
            }
        })
        .expect(2)
        .mount(&server)
        .await;
    let access_token = encode_id_token(
        &ChatGptIdTokenClaims::new()
            .email("user@example.com")
            .chatgpt_account_id(&workspace_id)
            .plan_type("enterprise"),
    )?;
    Mock::given(method("POST"))
        .and(path("/oauth/token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "access_token": access_token.clone(),
            "refresh_token": "refresh-token",
        })))
        .mount(&server)
        .await;
    write_chatgpt_auth(
        codex_home.path(),
        ChatGptAuthFixture::new(access_token)
            .account_id(&workspace_id)
            .chatgpt_account_id(&workspace_id)
            .email("user@example.com")
            .plan_type("enterprise"),
        AuthCredentialsStoreMode::File,
    )?;
    for enabled in [true, false] {
        let output = codex_command(codex_home.path())?
            .env(
                codex_login::REFRESH_TOKEN_URL_OVERRIDE_ENV_VAR,
                format!("{}/oauth/token", server.uri()),
            )
            .env("NO_PROXY", "127.0.0.1,localhost")
            .env("no_proxy", "127.0.0.1,localhost")
            .env_remove("CODEX_ACCESS_TOKEN")
            .env_remove("OPENAI_API_KEY")
            .args(["debug", "prompt-input"])
            .output()?;
        assert!(
            output.status.success(),
            "enabled={enabled}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        let prompt = String::from_utf8(output.stdout)?;
        assert_eq!(
            prompt.contains("Co-authored-by: Codex <noreply@openai.com>"),
            enabled,
            "enabled={enabled}"
        );
        assert!(!prompt.contains("attribution is disabled for the current workspace"));
    }
    server.verify().await;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn device_login_preserves_existing_auth_until_new_tokens_arrive() -> Result<()> {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/oauth/revoke"))
        .respond_with(ResponseTemplate::new(200))
        .expect(0)
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/api/accounts/deviceauth/usercode"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "device_auth_id": "device-auth-123",
            "user_code": "CODE-12345",
            "interval": "0",
        })))
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/api/accounts/deviceauth/token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "authorization_code": "authorization-code-123",
            "code_challenge": "code-challenge-123",
            "code_verifier": "code-verifier-123",
        })))
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/oauth/token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "id_token": "eyJhbGciOiJub25lIn0.eyJlbWFpbCI6Im5ld0BleGFtcGxlLmNvbSIsImh0dHBzOi8vYXBpLm9wZW5haS5jb20vYXV0aCI6eyJjaGF0Z3B0X3VzZXJfaWQiOiJ1c2VyLW5ldyIsInVzZXJfaWQiOiJ1c2VyLW5ldyIsImNoYXRncHRfYWNjb3VudF9pZCI6Im5ldy1hY2NvdW50IiwiY2hhdGdwdF9wbGFuX3R5cGUiOiJwbHVzIn19.c2ln",
            "access_token": "new-access",
            "refresh_token": "new-refresh",
        })))
        .expect(1)
        .mount(&server)
        .await;

    let codex_home = TempDir::new()?;
    write_file_auth_config(codex_home.path())?;
    std::fs::write(
        codex_home.path().join("auth.json"),
        serde_json::to_vec(&json!({
            "auth_mode": "chatgpt",
            "OPENAI_API_KEY": null,
            "tokens": {
                "id_token": "eyJhbGciOiJub25lIn0.e30.c2ln",
                "access_token": "old-access",
                "refresh_token": "old-refresh",
                "account_id": "old-account",
            },
        }))?,
    )?;

    let issuer = server.uri();
    let mut cmd = codex_command(codex_home.path())?;
    cmd.env(
        REVOKE_TOKEN_URL_OVERRIDE_ENV_VAR,
        format!("{issuer}/oauth/revoke"),
    )
    .env("NO_PROXY", "127.0.0.1,localhost")
    .env("no_proxy", "127.0.0.1,localhost")
    .env_remove("CODEX_ACCESS_TOKEN")
    .env_remove("OPENAI_API_KEY")
    .args(["login", "--device-auth", "--experimental_issuer", &issuer])
    .assert()
    .success()
    .stderr(contains("Successfully logged in"));

    let requests = server
        .received_requests()
        .await
        .context("failed to read mock OAuth requests")?;
    let paths: Vec<&str> = requests.iter().map(|request| request.url.path()).collect();
    assert_eq!(
        paths,
        vec![
            "/api/accounts/deviceauth/usercode",
            "/api/accounts/deviceauth/token",
            "/oauth/token",
        ]
    );

    let auth = read_auth_json(codex_home.path())?;
    assert!(auth["tokens"].is_null());
    let accounts = auth["managed_chatgpt"]["accounts"]
        .as_array()
        .context("managed account rows")?;
    assert_eq!(accounts.len(), 2);
    assert!(accounts.iter().any(|account| {
        account["tokens"]["refresh_token"] == "old-refresh"
            && account["tokens"]["account_id"] == "old-account"
    }));
    assert!(accounts.iter().any(|account| {
        account["tokens"]["refresh_token"] == "new-refresh"
            && account["tokens"]["account_id"] == "new-account"
    }));
    Ok(())
}
