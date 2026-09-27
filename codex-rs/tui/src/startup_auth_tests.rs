use super::get_login_status;
use crate::LoginStatus;
use crate::app_server_session::AppServerSession;
use crate::app_server_session::ThreadParamsMode;
use crate::history_cell::HistoryCell;
use crate::legacy_core::config::ConfigBuilder;
use crate::status::ManagedAccountsState;
use crate::status::StatusAccountDisplay;
use crate::token_usage::TokenUsage;
use codex_app_server_protocol::GetAccountResponse;
use codex_app_server_protocol::JSONRPCMessage;
use codex_app_server_protocol::ListAccountsResponse;
use codex_config::LoaderOverrides;
use codex_protocol::auth::AuthMode;
use color_eyre::Result;
use futures::SinkExt;
use futures::StreamExt;
use pretty_assertions::assert_eq;
use serde_json::Value;
use serde_json::json;
use tokio::net::TcpListener;
use tokio::task::JoinHandle;
use tokio_tungstenite::tungstenite::Message;

fn quota_account(id: &str) -> Value {
    json!({
        "managedAccountId": id, "chatgptAccountId": "workspace", "email": id,
        "planType": "plus", "eligible": false, "eligibilityReason": "blocked",
        "accountRevision": 2, "credentialRevision": 1,
        "refreshStatus": {"type": "healthy"},
        "block": {"reason": "quota", "blockedUntil": null},
        "usage": {"state": "unknown", "rateLimits": [], "tokenUsage": null,
            "observedAt": null, "unavailableReason": null, "unavailableObservedAt": null}
    })
}

fn inventory(accounts: Vec<Value>) -> Value {
    json!({"accounts": accounts, "selectedAccountId": null,
        "selectionRevision": null, "poolRevision": 3})
}

async fn auth_server(
    account: Value,
    list_reply: Value,
) -> Result<(AppServerSession, JoinHandle<Result<Vec<String>>>)> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let endpoint = crate::resolve_remote_addr(&format!("ws://{}", listener.local_addr()?))?;
    let server = tokio::spawn(async move {
        let (stream, _) = listener.accept().await?;
        let mut socket = tokio_tungstenite::accept_async(stream).await?;
        let mut auth_requests = Vec::new();
        while let Some(Ok(Message::Text(text))) = socket.next().await {
            let JSONRPCMessage::Request(request) = serde_json::from_str(&text)? else {
                continue;
            };
            let mut reply = match request.method.as_str() {
                "initialize" => json!({"result": {"userAgent": "startup-auth-test"}}),
                "account/read" => {
                    assert_eq!(request.params, Some(json!({})));
                    auth_requests.push(request.method);
                    json!({"result": account})
                }
                "account/list" => {
                    // No credential refresh; bootstrap waits for usage recovery before dispatch.
                    let model = (auth_requests.len() > 1).then_some("gpt-5.6-sol");
                    let mut params = json!({"threadId": null, "model": model});
                    if model.is_some() {
                        params["refreshUsage"] = json!(true);
                    }
                    assert_eq!(request.params, Some(params));
                    auth_requests.push(request.method);
                    list_reply.clone()
                }
                "model/list" => json!({"result": {"data": [], "nextCursor": null}}),
                "configRequirements/read" => json!({"result": {"requirements": null}}),
                "collaborationMode/list" => json!({"result": {"data": []}}),
                method => panic!("unexpected request: {method}"),
            };
            reply["id"] = json!(request.id);
            socket.send(Message::Text(reply.to_string().into())).await?;
        }
        Ok(auth_requests)
    });
    let session = AppServerSession::new(
        crate::connect_remote_app_server(endpoint).await?,
        ThreadParamsMode::Remote,
    );
    Ok((session, server))
}

#[tokio::test]
async fn startup_keeps_quota_blocked_pool_out_of_login() -> Result<()> {
    let saved = inventory(vec![
        quota_account("first@example.test"),
        quota_account("second@example.test"),
    ]);
    let read = json!({"account": null, "requiresOpenaiAuth": true, "workspaceRouting": null});
    let (mut session, server) = auth_server(read.clone(), json!({"result": saved})).await?;
    let result = get_login_status(&mut session).await?;
    assert_eq!(
        result,
        (
            LoginStatus::AuthMode(AuthMode::Chatgpt),
            serde_json::from_value::<GetAccountResponse>(read)?
        )
    );
    assert!(!crate::should_show_login_screen(
        result.0,
        result.1.requires_openai_auth
    ));

    let home = tempfile::tempdir()?;
    let mut config = ConfigBuilder::default()
        .codex_home(home.path().to_path_buf())
        .loader_overrides(LoaderOverrides::without_managed_config_for_tests())
        .build()
        .await?;
    config.model = Some("gpt-5.6-sol".to_string());
    let bootstrap = session.bootstrap_with_account(&config, result.1).await?;
    let expected = StatusAccountDisplay::ManagedChatGpt(ManagedAccountsState::from_response(
        serde_json::from_value::<ListAccountsResponse>(saved)?,
    ));
    assert_eq!(bootstrap.status_account_display.as_ref(), Some(&expected));
    assert!(bootstrap.has_chatgpt_account);
    assert_eq!(bootstrap.auth_mode, None);

    let status = crate::status::new_status_output(
        &config,
        bootstrap.status_account_display.as_ref(),
        /*token_info*/ None,
        &TokenUsage::default(),
        /*session_id*/ &None,
        /*thread_name*/ None,
        /*forked_from*/ None,
        /*rate_limits*/ None,
        /*_plan_type*/ None,
        chrono::Local::now(),
        &bootstrap.default_model,
        /*collaboration_mode*/ None,
        /*reasoning_effort_override*/ None,
    );
    let pool_lines = status
        .display_lines(/*width*/ 80)
        .into_iter()
        .map(|line| line.to_string())
        .skip_while(|line| !line.contains("first@example.test"))
        .collect::<Vec<_>>()
        .join("\n");
    insta::assert_snapshot!("startup_quota_blocked_pool_status", pool_lines);
    session.shutdown().await?;
    assert_eq!(
        server.await??,
        ["account/read", "account/list", "account/list"]
    );
    Ok(())
}

#[tokio::test]
async fn startup_keeps_eligible_timeout_uncertain_pool_out_of_login() -> Result<()> {
    let accounts = ["first@example.test", "second@example.test"]
        .into_iter()
        .map(|id| {
            let mut account = quota_account(id);
            account["eligible"] = json!(true);
            account["eligibilityReason"] = Value::Null;
            account["block"] = Value::Null;
            account["refreshStatus"] = json!({
                "type": "reloginRequired", "reasonCode": "token_refresh_timeout", "observedAt": 1
            });
            account
        })
        .collect();
    let read = json!({"account": null, "requiresOpenaiAuth": true, "workspaceRouting": null});
    let (mut session, server) =
        auth_server(read.clone(), json!({"result": inventory(accounts)})).await?;
    let (status, account) = get_login_status(&mut session).await?;
    session.shutdown().await?;
    assert_eq!(server.await??, ["account/read", "account/list"]);
    assert!(
        !crate::should_show_login_screen(status, account.requires_openai_auth),
        "an uncertain refresh exchange does not invalidate the owner's eligible access token"
    );
    assert_eq!(
        (status, account),
        (
            LoginStatus::AuthMode(AuthMode::Chatgpt),
            serde_json::from_value::<GetAccountResponse>(read)?
        )
    );
    Ok(())
}

#[tokio::test]
async fn startup_distinguishes_cooldowns_from_required_reauthentication() -> Result<()> {
    let healthy = quota_account("saved@example.test");
    let mut workspace = healthy.clone();
    workspace["block"]["reason"] = json!("workspace");
    let mut transient = healthy.clone();
    transient["refreshStatus"] = json!({"type": "transientUnavailable", "observedAt": 1});
    let mut invalid = healthy.clone();
    invalid["block"]["reason"] = json!("auth_invalid");
    let mut relogin = healthy.clone();
    relogin["refreshStatus"] =
        json!({"type": "reloginRequired", "reasonCode": "refresh_token_reused", "observedAt": 1});
    let mut restricted = healthy.clone();
    restricted["eligibilityReason"] = json!("forced_workspace_disallowed");
    let mut removed = healthy.clone();
    removed["eligibilityReason"] = json!("pending_removal");
    let mut restricted_timeout = restricted.clone();
    restricted_timeout["refreshStatus"] =
        json!({"type": "reloginRequired", "reasonCode": "token_refresh_timeout", "observedAt": 1});
    let mut unknown = healthy.clone();
    unknown["block"]["reason"] = json!("future_block_reason");
    let mut available = healthy.clone();
    available["eligible"] = json!(true);
    available["eligibilityReason"] = Value::Null;
    available["block"] = Value::Null;
    for (label, accounts, expected) in [
        ("workspace quota", vec![workspace], false),
        ("transient refresh", vec![transient], false),
        ("invalid credentials", vec![invalid.clone()], true),
        ("permanent refresh failure", vec![relogin], true),
        ("workspace restriction", vec![restricted], true),
        (
            "restricted uncertain refresh",
            vec![restricted_timeout],
            true,
        ),
        ("pending removal", vec![removed], true),
        ("unknown block", vec![unknown], true),
        ("empty pool", vec![], true),
        ("eligible after account read", vec![available], false),
        ("healthy sibling", vec![invalid, healthy], false),
    ] {
        let read = json!({"account": null, "requiresOpenaiAuth": true});
        let (mut session, server) =
            auth_server(read, json!({"result": inventory(accounts)})).await?;
        let (status, account) = get_login_status(&mut session).await?;
        assert_eq!(
            crate::should_show_login_screen(status, account.requires_openai_auth),
            expected,
            "{label}"
        );
        session.shutdown().await?;
        assert_eq!(server.await??, ["account/read", "account/list"], "{label}");
    }
    Ok(())
}

#[tokio::test]
async fn startup_preserves_singular_auth_and_non_auth_providers() -> Result<()> {
    for (account, requires_auth, expected) in [
        (
            json!({"type": "apiKey"}),
            true,
            LoginStatus::AuthMode(AuthMode::ApiKey),
        ),
        (
            json!({"type": "chatgpt", "email": "saved@example.test", "planType": "plus"}),
            true,
            LoginStatus::AuthMode(AuthMode::Chatgpt),
        ),
        (Value::Null, false, LoginStatus::NotAuthenticated),
    ] {
        let read = json!({"account": account, "requiresOpenaiAuth": requires_auth});
        let (mut session, server) = auth_server(
            read,
            json!({"error": {"code": -32601, "message": "unsupported"}}),
        )
        .await?;
        assert_eq!(get_login_status(&mut session).await?.0, expected);
        session.shutdown().await?;
        assert_eq!(server.await??, ["account/read"]);
    }
    Ok(())
}

#[tokio::test]
async fn startup_falls_back_only_when_account_inventory_is_unsupported() -> Result<()> {
    for (reply, unsupported) in [
        (
            json!({"error": {"code": -32601, "message": "method not found"}}),
            true,
        ),
        (
            json!({"error": {"code": -32600, "message": "unknown variant `account/list`, expected `account/read`"}}),
            true,
        ),
        (
            json!({"error": {"code": -32000, "message": "credential storage unavailable"}}),
            false,
        ),
        (
            json!({"error": {"code": -32600, "message": "account/list is forbidden by policy"}}),
            false,
        ),
        (json!({"result": {}}), false),
    ] {
        let (mut session, server) =
            auth_server(json!({"account": null, "requiresOpenaiAuth": true}), reply).await?;
        let result = get_login_status(&mut session).await;
        if unsupported {
            assert_eq!(result?.0, LoginStatus::NotAuthenticated);
        } else {
            assert!(
                result.is_err(),
                "inventory errors must not be treated as signed out"
            );
        }
        session.shutdown().await?;
        assert_eq!(server.await??, ["account/read", "account/list"]);
    }
    Ok(())
}
