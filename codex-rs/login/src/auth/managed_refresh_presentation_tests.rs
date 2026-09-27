use super::*;
use pretty_assertions::assert_eq;
use std::time::Duration;
use tokio::sync::Notify;

#[derive(Clone, Copy)]
enum RefreshOutcome {
    Timeout,
    Cancelled,
    CommitFailed,
    OrdinaryTransient,
}

#[tokio::test]
#[serial(codex_auth_env)]
async fn timed_out_refresh_requires_relogin_without_replaying_exchange() {
    assert_refresh_presentation(RefreshOutcome::Timeout).await;
}

#[tokio::test]
#[serial(codex_auth_env)]
async fn cancelled_refresh_requires_relogin_without_replaying_exchange() {
    assert_refresh_presentation(RefreshOutcome::Cancelled).await;
}

#[tokio::test]
#[serial(codex_auth_env)]
async fn uncertain_commit_requires_relogin_without_replaying_exchange() {
    assert_refresh_presentation(RefreshOutcome::CommitFailed).await;
}

#[tokio::test]
#[serial(codex_auth_env)]
async fn ordinary_transient_refresh_remains_retryable_without_relogin() {
    assert_refresh_presentation(RefreshOutcome::OrdinaryTransient).await;
}

async fn assert_refresh_presentation(outcome: RefreshOutcome) {
    let server = MockServer::start().await;
    let arrived = Arc::new(Notify::new());
    let response = match outcome {
        RefreshOutcome::Timeout | RefreshOutcome::Cancelled => {
            ResponseTemplate::new(/*status*/ 200).set_delay(Duration::from_secs(/*secs*/ 30))
        }
        RefreshOutcome::CommitFailed => {
            ResponseTemplate::new(/*status*/ 200).set_body_json(json!({
                "access_token": "refreshed-access",
                "refresh_token": "refreshed-token",
                "id_token": managed_id_token("presentation@example.test", "workspace-disallowed"),
            }))
        }
        RefreshOutcome::OrdinaryTransient => ResponseTemplate::new(/*status*/ 503)
            .set_body_json(json!({"error": {"code": "temporarily_unavailable"}})),
    };
    let expected_posts = if matches!(outcome, RefreshOutcome::OrdinaryTransient) {
        2
    } else {
        1
    };
    Mock::given(method("POST"))
        .and(path("/oauth/token"))
        .respond_with({
            let arrived = arrived.clone();
            move |_: &wiremock::Request| {
                arrived.notify_one();
                response.clone()
            }
        })
        .expect(expected_posts)
        .mount(&server)
        .await;
    let _refresh_guard = EnvVarGuard::set(
        REFRESH_TOKEN_URL_OVERRIDE_ENV_VAR,
        &format!("{}/oauth/token", server.uri()),
    );
    let home = tempdir().expect("isolated managed auth home");
    let manager = file_pool_manager(home.path()).await;
    let mut credentials = managed_oauth_credentials(
        "presentation@example.test",
        "workspace-allowed",
        "original-refresh",
    );
    credentials.last_refresh = Utc::now() - chrono::Duration::days(10);
    let identity = manager
        .upsert_managed_chatgpt_oauth(credentials)
        .await
        .expect("initial managed login");
    if matches!(outcome, RefreshOutcome::CommitFailed) {
        manager.set_forced_chatgpt_workspace_id(Some(vec!["workspace-allowed".to_string()]));
    }

    let refreshing = tokio::spawn({
        let manager = manager.clone();
        let identity = identity.clone();
        async move {
            manager
                .refresh_managed_chatgpt_account_bounded(&identity, Duration::from_secs(/*secs*/ 1))
                .await
        }
    });
    tokio::time::timeout(Duration::from_secs(/*secs*/ 5), arrived.notified())
        .await
        .expect("fixture must observe the real refresh exchange");
    if matches!(outcome, RefreshOutcome::Cancelled) {
        // Abort only after OAuth has received the request, so dropping the real
        // refresh future persists an uncertain cancellation through its guard.
        refreshing.abort();
        assert!(
            tokio::time::timeout(Duration::from_secs(/*secs*/ 5), refreshing)
                .await
                .expect("cancelled refresh must finish dropping its lease guard")
                .expect_err("refresh task was cancelled")
                .is_cancelled()
        );
    } else {
        let error = tokio::time::timeout(Duration::from_secs(/*secs*/ 5), refreshing)
            .await
            .expect("refresh outcome must complete")
            .expect("refresh task")
            .expect_err("fixture must produce a refresh failure");
        let RefreshTokenError::Transient(error) = error else {
            panic!("these outcomes are not permanent OAuth rejections");
        };
        if matches!(outcome, RefreshOutcome::Timeout) {
            assert_eq!(error.kind(), std::io::ErrorKind::TimedOut);
        }
    }
    let first = manager
        .stored_managed_chatgpt_account_list()
        .expect("public account inventory after refresh failure");
    let status = first.accounts[0].refresh_status.clone();
    let observed_at = match &status {
        ManagedChatgptRefreshStatus::TransientUnavailable { observed_at }
        | ManagedChatgptRefreshStatus::ReloginRequired { observed_at, .. } => *observed_at,
        ManagedChatgptRefreshStatus::Healthy => panic!("failed refresh must not appear healthy"),
    };

    let retry = tokio::time::timeout(
        Duration::from_secs(/*secs*/ 5),
        manager.refresh_managed_chatgpt_account(&identity),
    )
    .await
    .expect("repeated refresh must complete without hanging");
    assert!(matches!(retry, Err(RefreshTokenError::Transient(_))));
    assert_eq!(
        server.received_requests().await.unwrap().len(),
        expected_posts as usize
    );
    if !matches!(outcome, RefreshOutcome::OrdinaryTransient) {
        assert_eq!(
            manager.stored_managed_chatgpt_account_list().unwrap(),
            first,
            "suppressed retry must preserve the original uncertain outcome",
        );
    }

    let relogged = manager
        .upsert_managed_chatgpt_oauth(managed_oauth_credentials(
            "presentation@example.test",
            "workspace-allowed",
            "fresh-refresh",
        ))
        .await
        .expect("fresh login clears uncertain refresh state");
    assert_eq!(relogged, identity);
    let after_login = manager.stored_managed_chatgpt_account_list().unwrap();
    assert_eq!(
        after_login.accounts[0].refresh_status,
        ManagedChatgptRefreshStatus::Healthy
    );
    let usable = tokio::time::timeout(
        Duration::from_secs(/*secs*/ 5),
        manager.refresh_managed_chatgpt_account(&identity),
    )
    .await
    .expect("fresh credentials must not start another exchange")
    .expect("fresh credentials remain usable without another exchange");
    assert_eq!(
        usable.auth.get_token_data().unwrap().refresh_token,
        "fresh-refresh"
    );
    assert_eq!(
        server.received_requests().await.unwrap().len(),
        expected_posts as usize
    );
    server.verify().await;

    // Assert presentation after exercising suppression and recovery, so the red
    // result identifies the misleading status rather than an untested remedy.
    let expected = match outcome {
        RefreshOutcome::Timeout => ManagedChatgptRefreshStatus::ReloginRequired {
            observed_at,
            reason_code: Some("token_refresh_timeout".to_string()),
        },
        RefreshOutcome::Cancelled => ManagedChatgptRefreshStatus::ReloginRequired {
            observed_at,
            reason_code: Some("token_refresh_cancelled".to_string()),
        },
        RefreshOutcome::CommitFailed => ManagedChatgptRefreshStatus::ReloginRequired {
            observed_at,
            reason_code: Some("token_refresh_commit_failed".to_string()),
        },
        RefreshOutcome::OrdinaryTransient => {
            ManagedChatgptRefreshStatus::TransientUnavailable { observed_at }
        }
    };
    assert_eq!(status, expected);
}
