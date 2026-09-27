use super::*;
use base64::Engine as _;
use chrono::Utc;
use codex_login::ManagedChatgptOauthCredentials;
use codex_login::TokenData;
use codex_login::token_data::IdTokenInfo;
use pretty_assertions::assert_eq;

#[derive(Clone, Copy)]
enum AccountUpdate {
    UsageOnly,
    LegacyUsageOnly,
    CredentialChange,
}

#[test_case::test_case(AccountUpdate::UsageOnly; "usage_only")]
#[test_case::test_case(AccountUpdate::LegacyUsageOnly; "legacy_usage_only")]
#[test_case::test_case(AccountUpdate::CredentialChange; "credential_change")]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn managed_pool_websocket_continuation_after_usage(update: AccountUpdate) {
    skip_if_no_network!();

    let reset_at = (Utc::now() + chrono::Duration::hours(1)).timestamp();
    let first_response = vec![
        ev_response_created("resp-1"),
        json!({
            "type": "codex.rate_limits",
            "plan_type": "plus",
            "rate_limits": {
                "allowed": true,
                "limit_reached": false,
                "primary": {
                    "used_percent": 42,
                    "window_minutes": 60,
                    "reset_at": reset_at
                },
                "secondary": null
            }
        }),
        ev_assistant_message("msg_1", "assistant output"),
        ev_completed("resp-1"),
    ];
    let second_response = vec![ev_response_created("resp-2"), ev_completed("resp-2")];
    // Keep the first socket open for a second request. A fallback connection also
    // succeeds, so an unwanted reconnect fails our assertions rather than timing out.
    let server = start_websocket_server(vec![
        vec![first_response, second_response.clone()],
        vec![second_response],
    ])
    .await;
    let harness = websocket_harness_for_codex_backend(&server).await;
    let claims = json!({
        "email": "managed-ws@example.com",
        "https://api.openai.com/auth": {
            "chatgpt_account_id": "managed-ws-account",
            "chatgpt_plan_type": "plus"
        }
    });
    let encoded_claims = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .encode(serde_json::to_vec(&claims).expect("encode synthetic claims"));
    let mut credentials = ManagedChatgptOauthCredentials {
        tokens: TokenData {
            id_token: IdTokenInfo {
                email: Some("managed-ws@example.com".to_string()),
                chatgpt_account_id: Some("managed-ws-account".to_string()),
                raw_jwt: format!("e30.{encoded_claims}.sig"),
                ..Default::default()
            },
            access_token: "managed-ws-original-token".to_string(),
            refresh_token: "managed-ws-refresh-token".to_string(),
            account_id: Some("managed-ws-account".to_string()),
        },
        last_refresh: Utc::now(),
        oauth_api_key: None,
    };
    let identity = harness
        .auth_manager
        .upsert_managed_chatgpt_oauth(credentials.clone())
        .await
        .expect("insert synthetic managed account");
    if let AccountUpdate::LegacyUsageOnly = update {
        let auth_path = harness.codex_home.path().join("auth.json");
        let mut auth: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&auth_path).expect("read temporary auth"))
                .expect("parse temporary auth");
        let account = auth["managed_chatgpt"]["accounts"][0]
            .as_object_mut()
            .expect("temporary managed account");
        assert!(account.remove("credential_revision").is_some());
        std::fs::write(
            &auth_path,
            serde_json::to_vec(&auth).expect("encode legacy fixture"),
        )
        .expect("write temporary legacy auth");
        harness.auth_manager.reload().await;
    }
    let mut observer = harness.auth_manager.auth_change_receiver();
    observer.borrow_and_update();
    let mut client_session = harness.client.new_session();
    let prompt_one = prompt_with_input(vec![message_item("hello")]);
    let prompt_two = prompt_with_input(vec![
        message_item("hello"),
        assistant_message_item("1", "assistant output"),
        message_item("second"),
    ]);

    stream_until_complete_with_model_info(
        &mut client_session,
        &harness,
        &prompt_one,
        &harness.model_info,
        "resp-1",
    )
    .await;
    let accounts = harness
        .auth_manager
        .managed_chatgpt_accounts()
        .expect("read recorded usage");
    assert_eq!(accounts.len(), 1);
    assert_eq!(accounts[0].identity_key, identity);
    let usage = accounts[0]
        .usage
        .as_ref()
        .expect("response usage was recorded");
    assert_eq!(usage.rate_windows.len(), 1);
    assert_eq!(usage.rate_windows[0].remaining_percent, Some(58.0));
    assert!(observer.has_changed().expect("pool observer stays open"));

    if let AccountUpdate::CredentialChange = update {
        credentials.tokens.access_token = "managed-ws-refreshed-token".to_string();
        assert_eq!(
            harness
                .auth_manager
                .upsert_managed_chatgpt_oauth(credentials)
                .await
                .expect("replace synthetic credential"),
            identity
        );
    }
    stream_until_complete_with_model_info(
        &mut client_session,
        &harness,
        &prompt_two,
        &harness.model_info,
        "resp-2",
    )
    .await;

    let connections = server.connections();
    let handshakes = server.handshakes();
    server.shutdown().await;
    match update {
        AccountUpdate::UsageOnly | AccountUpdate::LegacyUsageOnly => {
            assert_eq!(connections.len(), 1, "usage must not reconnect the socket");
            assert_eq!(connections[0].len(), 2);
            let second = connections[0][1].body_json();
            assert_eq!(second["previous_response_id"], json!("resp-1"));
            assert_eq!(
                second["input"],
                serde_json::to_value(&prompt_two.input[2..]).expect("encode incremental input")
            );
            assert_eq!(handshakes.len(), 1);
        }
        AccountUpdate::CredentialChange => {
            assert_eq!(connections.len(), 2, "new credentials must reconnect");
            assert_eq!(connections[1].len(), 1);
            let second = connections[1][0].body_json();
            assert_eq!(second.get("previous_response_id"), None);
            assert_eq!(
                second["input"],
                serde_json::to_value(&prompt_two.input).expect("encode full input")
            );
            assert_eq!(handshakes.len(), 2);
            assert_eq!(
                handshakes[1].header("authorization"),
                Some("Bearer managed-ws-refreshed-token".to_string())
            );
        }
    }
    assert_eq!(
        handshakes[0].header("authorization"),
        Some("Bearer managed-ws-original-token".to_string())
    );
    for handshake in handshakes {
        assert_eq!(
            handshake.header("chatgpt-account-id"),
            Some("managed-ws-account".to_string())
        );
    }
}
