//! A fresh authoritative usage check must restore requests, not merely refresh the pool display.

use super::account::seed_managed_accounts;
use anyhow::Result;
use app_test_support::TestAppServer;
use app_test_support::mount_workspace_routing;
use app_test_support::write_models_cache;
use chrono::Duration as ChronoDuration;
use chrono::Utc;
use codex_app_server_protocol::ListAccountsResponse;
use codex_app_server_protocol::ThreadStartParams;
use codex_app_server_protocol::ThreadStartResponse;
use codex_app_server_protocol::TurnCompletedNotification;
use codex_app_server_protocol::TurnStartParams;
use codex_app_server_protocol::TurnStartResponse;
use codex_app_server_protocol::TurnStatus;
use codex_app_server_protocol::UserInput;
use core_test_support::responses;
use pretty_assertions::assert_eq;
use serde_json::Value;
use serde_json::json;
use std::time::Duration;
use tokio::time::timeout;
use wiremock::Mock;
use wiremock::MockServer;
use wiremock::ResponseTemplate;
use wiremock::matchers::header;
use wiremock::matchers::method;
use wiremock::matchers::path;

#[tokio::test]
async fn fresh_usage_recovers_persisted_quota_and_completes_a_turn() -> Result<()> {
    let home = tempfile::tempdir()?;
    let backend = MockServer::start().await;
    std::fs::write(
        home.path().join("config.toml"),
        format!(
            "model = \"gpt-5.1\"\nmodel_provider = \"fixture\"\ncli_auth_credentials_store = \"file\"\n\
         chatgpt_base_url = \"{}/backend-api\"\n\
         [model_providers.fixture]\nname = \"OpenAI\"\nrequires_openai_auth = true\n\
         wire_api = \"responses\"\nbase_url = \"{}/v1\"\nsupports_websockets = false\n",
            backend.uri(),
            backend.uri(),
        ),
    )?;
    seed_managed_accounts(
        home.path(),
        &[("recovered@example.test", "workspace-recovered")],
    )
    .await?;
    let auth_path = home.path().join("auth.json");
    let mut auth: Value = serde_json::from_slice(&std::fs::read(&auth_path)?)?;
    let row = &mut auth["managed_chatgpt"]["accounts"][0];
    let tokens = row["tokens"].clone();
    let credential_revision = row["credential_revision"].clone();
    row["block"] = json!({"kind": "quota", "blocked_at": Utc::now() - ChronoDuration::minutes(10),
        "reset_at": Utc::now() + ChronoDuration::days(1), "credential_revision": credential_revision});
    std::fs::write(&auth_path, serde_json::to_vec(&auth)?)?;
    write_models_cache(home.path()).await?;
    mount_workspace_routing(&backend).await;
    Mock::given(method("GET"))
        .and(path("/backend-api/wham/config/bundle"))
        .respond_with(ResponseTemplate::new(/*s*/ 200).set_body_json(json!({})))
        .mount(&backend)
        .await;
    Mock::given(method("GET"))
        .and(path("/backend-api/wham/usage"))
        .and(header("authorization", "Bearer access-workspace-recovered"))
        .respond_with(ResponseTemplate::new(/*s*/ 200).set_body_json(json!({
            "plan_type": "pro", "account_id": "workspace-recovered", "rate_limit": {
                "allowed": true, "limit_reached": false,
                "primary_window": {"used_percent": 15, "limit_window_seconds": 604800,
                    "reset_after_seconds": 86400, "reset_at": 2_000_000_000}
            }
        })))
        .expect(/*r*/ 1)
        .mount(&backend)
        .await;
    Mock::given(method("GET"))
        .and(path("/backend-api/wham/profiles/me"))
        .respond_with(
            ResponseTemplate::new(/*s*/ 200)
                .set_body_json(json!({"stats": {"lifetime_tokens": 42}})),
        )
        .expect(/*r*/ 1)
        .mount(&backend)
        .await;
    Mock::given(method("POST"))
        .and(path("/oauth/token"))
        .respond_with(ResponseTemplate::new(/*s*/ 500))
        .expect(/*r*/ 0)
        .mount(&backend)
        .await;
    let completion = responses::mount_sse_once(
        &backend,
        responses::sse(vec![
            responses::ev_response_created("recovered-response"),
            responses::ev_assistant_message("recovered-message", "quota recovery works"),
            responses::ev_completed("recovered-response"),
        ]),
    )
    .await;
    let mut app = TestAppServer::builder()
        .with_codex_home(home.path())
        .with_env_overrides(&[("OPENAI_API_KEY", None)])
        .build_initialized()
        .await?;
    let wait = Duration::from_secs(/*secs*/ 30);
    let before_id = app
        .send_raw_request("account/list", Some(json!({})))
        .await?;
    let before: ListAccountsResponse = timeout(wait, app.read_response(before_id)).await??;
    assert_eq!(
        (
            before.accounts.len(),
            before.selected_account_id,
            before.accounts[0].eligible
        ),
        (1, None, false)
    );
    let refresh_id = app
        .send_raw_request(
            "account/list",
            Some(json!({"refreshUsage": true, "refreshTokens": false})),
        )
        .await?;
    let refreshed: ListAccountsResponse = timeout(wait, app.read_response(refresh_id)).await??;
    assert_eq!(
        (
            refreshed.accounts[0].eligible,
            refreshed.accounts[0].block.clone()
        ),
        (true, None)
    );
    assert_eq!(
        refreshed.selected_account_id.as_deref(),
        Some("email:recovered@example.test")
    );
    let thread_id = app
        .send_thread_start_request_with_auto_env(ThreadStartParams::default())
        .await?;
    let thread: ThreadStartResponse = timeout(wait, app.read_response(thread_id)).await??;
    let turn_id = app
        .send_turn_start_request(TurnStartParams {
            thread_id: thread.thread.id,
            input: vec![UserInput::Text {
                text: "hi".to_string(),
                text_elements: Vec::new(),
            }],
            ..Default::default()
        })
        .await?;
    let _: TurnStartResponse = timeout(wait, app.read_response(turn_id)).await??;
    let completed: TurnCompletedNotification =
        timeout(wait, app.read_notification("turn/completed")).await??;
    assert_eq!(
        (completed.turn.status, completed.turn.error),
        (TurnStatus::Completed, None)
    );
    assert_eq!(
        completion
            .single_request()
            .header("chatgpt-account-id")
            .as_deref(),
        Some("workspace-recovered")
    );
    let persisted: Value = serde_json::from_slice(&std::fs::read(&auth_path)?)?;
    let recovered = &persisted["managed_chatgpt"]["accounts"][0];
    assert_eq!(
        (
            &recovered["tokens"],
            &recovered["credential_revision"],
            recovered.get("block")
        ),
        (&tokens, &credential_revision, None)
    );
    Ok(())
}
