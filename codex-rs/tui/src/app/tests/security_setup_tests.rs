//! Exercises the authenticated reminder transport against a local HTTP fixture.
use super::disconnect::serve_reconnect_requests;
use super::*;
use crate::app_server_session::ThreadParamsMode;
use app_test_support::ChatGptAuthFixture;
use app_test_support::write_chatgpt_auth;
use codex_app_server_protocol::AuthMode;
use codex_login::AuthCredentialsStoreMode;
use pretty_assertions::assert_eq;
use serde_json::json;
use tokio::net::TcpListener;

#[tokio::test]
async fn security_setup_skips_eligibility_fetch_for_managed_pool() -> Result<()> {
    let (mut app, _events, _ops) = make_test_app_with_channels().await;
    let backend = wiremock::MockServer::start().await;
    app.config.chatgpt_base_url = backend.uri();
    app.config.cli_auth_credentials_store_mode = AuthCredentialsStoreMode::File;
    std::fs::write(
        app.config.codex_home.join("config.toml"),
        format!("chatgpt_base_url = {:?}\n", backend.uri()),
    )?;
    write_chatgpt_auth(
        &app.config.codex_home,
        ChatGptAuthFixture::new("test-token")
            .account_id("account")
            .chatgpt_user_id("user"),
        AuthCredentialsStoreMode::File,
    )
    .expect("write synthetic auth");
    app_test_support::mount_workspace_routing(&backend).await;
    let server = crate::start_embedded_app_server_for_picker(&app.config).await?;
    let accounts: codex_app_server_protocol::ListAccountsResponse = server
        .request_handle()
        .request_typed(codex_app_server_protocol::ClientRequest::ListAccounts {
            request_id: AppServerRequestId::Integer(1),
            params: codex_app_server_protocol::ListAccountsParams::default(),
        })
        .await?;
    assert_eq!(accounts.accounts.len(), 1);
    wiremock::Mock::given(wiremock::matchers::path("/wham/security-setup"))
        .respond_with(
            wiremock::ResponseTemplate::new(/*s*/ 200).set_body_json(json!({
                "notice": {
                    "title": "Keep using Daybreak mode", "description": "Set up security.",
                    "action": {"label": "Set up security", "url": "https://chatgpt.com/cyber"}
                }
            })),
        )
        .expect(/*r*/ 0)
        .mount(&backend)
        .await;
    let (tx, mut events) = mpsc::unbounded_channel();
    crate::security_setup::prefetch(
        &app.config,
        &server,
        AppEventSender::new(tx),
        app.chat_widget.security_setup_request_id,
    );
    assert!(
        tokio::time::timeout(Duration::from_secs(/*secs*/ 5), events.recv())
            .await?
            .is_none()
    );
    assert!(!render_bottom_popup(&app.chat_widget, /*width*/ 70).contains("Set up security"));
    backend.verify().await;
    server.shutdown().await?;
    Ok(())
}

#[tokio::test]
async fn security_setup_skips_fetch_when_server_auth_does_not_match_saved_login() -> Result<()> {
    for (auth_method, auth_token) in [
        (
            Some(AuthMode::ChatgptAuthTokens),
            Some("other-account-token"),
        ),
        (Some(AuthMode::ChatgptAuthTokens), Some("saved-token")),
        (Some(AuthMode::Chatgpt), Some("other-account-token")),
        (Some(AuthMode::Chatgpt), None),
        (None, None),
    ] {
        let (mut app, _events, _ops) = make_test_app_with_channels().await;
        let backend = wiremock::MockServer::start().await;
        app.config.chatgpt_base_url = backend.uri();
        app.config.cli_auth_credentials_store_mode = AuthCredentialsStoreMode::File;
        write_chatgpt_auth(
            &app.config.codex_home,
            ChatGptAuthFixture::new("saved-token")
                .account_id("saved-account")
                .chatgpt_user_id("saved-user"),
            AuthCredentialsStoreMode::File,
        )
        .expect("write synthetic auth");
        wiremock::Mock::given(wiremock::matchers::path("/wham/security-setup"))
            .respond_with(wiremock::ResponseTemplate::new(200).set_body_json(json!({
                "notice": {
                    "title": "Keep using Daybreak mode", "description": "Set up security.",
                    "action": {"label": "Set up security", "url": "https://chatgpt.com/cyber"}
                }
            })))
            .expect(0)
            .mount(&backend)
            .await;

        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let endpoint = crate::resolve_remote_addr(&format!("ws://{}", listener.local_addr()?))?;
        let daemon = tokio::spawn(async move {
            let (stream, _) = listener.accept().await?;
            serve_reconnect_requests(tokio_tungstenite::accept_async(stream).await?, |request| {
                if request.method == "account/list" {
                    return std::future::ready(Some(json!({"result": {
                        "accounts": [], "selectedAccountId": null, "selectionRevision": null, "poolRevision": 0
                    }})));
                }
                assert_eq!(request.method, "getAuthStatus");
                assert_eq!(
                    request.params,
                    Some(json!({"includeToken": true, "refreshToken": false}))
                );
                std::future::ready(Some(json!({"result": {
                    "authMethod": auth_method, "authToken": auth_token,
                    "requiresOpenaiAuth": true
                }})))
            })
            .await
        });
        let server = AppServerSession::new(
            crate::connect_remote_app_server(endpoint).await?,
            ThreadParamsMode::Embedded,
        );
        let (tx, mut events) = mpsc::unbounded_channel();
        crate::security_setup::prefetch(
            &app.config,
            &server,
            AppEventSender::new(tx),
            app.chat_widget.security_setup_request_id,
        );
        // The fetch owns the only sender, so channel closure proves it completed.
        assert!(
            tokio::time::timeout(Duration::from_secs(5), events.recv())
                .await?
                .is_none()
        );
        backend.verify().await;
        server.shutdown().await?;
        let methods = daemon.await??;
        assert!(methods.iter().any(|method| method == "getAuthStatus"));
    }
    Ok(())
}
