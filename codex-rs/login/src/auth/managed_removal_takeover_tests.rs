use super::*;
use pretty_assertions::assert_eq;
use std::pin::Pin;
use std::task::Context;
use std::task::Waker;

const ORPHAN_POOL_HOME: &str = "CODEX_TEST_ORPHAN_POOL_HOME";

// This child represents a separate owner that commits removal and then exits.
#[test]
fn persist_orphaned_managed_removal_child() {
    let Some(home) = std::env::var_os(ORPHAN_POOL_HOME) else {
        return;
    };
    let home = std::path::PathBuf::from(home);
    let mut stored = load_auth_dot_json(
        &home,
        AuthCredentialsStoreMode::File,
        AuthKeyringBackendKind::Direct,
    )
    .unwrap()
    .unwrap();
    let account = &mut stored.managed_chatgpt.as_mut().unwrap().accounts[0];
    account.tombstone = Some(ManagedChatgptTombstone {
        operation_id: "orphaned-removal".to_string(),
        revision: account.credential_revision,
        refresh_token: account.tokens.refresh_token.clone(),
    });
    account.mutation_lease = Some(ManagedChatgptMutationLease {
        operation_id: "orphaned-removal".to_string(),
        kind: ManagedChatgptMutationKind::Remove,
        expected_revision: account.credential_revision,
        expected_refresh_token: account.tokens.refresh_token.clone(),
        expires_at: Utc::now() - chrono::Duration::seconds(1),
    });
    account.revision += 1;
    save_auth(
        &home,
        &stored,
        AuthCredentialsStoreMode::File,
        AuthKeyringBackendKind::Direct,
    )
    .unwrap();
}

#[derive(Clone, Copy, Debug)]
enum WaitingOperation {
    Logout,
    Relogin,
}

#[derive(Clone, Copy)]
enum RemovalLease {
    Expired,
    LiveThenExpired,
}

#[tokio::test]
#[serial(codex_auth_env)]
async fn expired_foreign_removal_does_not_strand_waiting_logout() {
    assert_waiter_finishes_after_orphaned_removal(WaitingOperation::Logout, RemovalLease::Expired)
        .await;
}

#[tokio::test]
#[serial(codex_auth_env)]
async fn expired_foreign_removal_does_not_strand_waiting_relogin() {
    assert_waiter_finishes_after_orphaned_removal(WaitingOperation::Relogin, RemovalLease::Expired)
        .await;
}

#[tokio::test]
#[serial(codex_auth_env)]
async fn live_foreign_removal_blocks_waiting_logout_until_expiry() {
    assert_waiter_finishes_after_orphaned_removal(
        WaitingOperation::Logout,
        RemovalLease::LiveThenExpired,
    )
    .await;
}

#[tokio::test]
#[serial(codex_auth_env)]
async fn live_foreign_removal_blocks_waiting_relogin_until_expiry() {
    assert_waiter_finishes_after_orphaned_removal(
        WaitingOperation::Relogin,
        RemovalLease::LiveThenExpired,
    )
    .await;
}

async fn assert_waiter_finishes_after_orphaned_removal(
    operation: WaitingOperation,
    lease: RemovalLease,
) {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/oauth/revoke"))
        .respond_with(ResponseTemplate::new(/*status*/ 200))
        .mount(&server)
        .await;
    let _revoke_guard = EnvVarGuard::set(
        REVOKE_TOKEN_URL_OVERRIDE_ENV_VAR,
        &format!("{}/oauth/revoke", server.uri()),
    );
    let home = tempdir().unwrap();
    let manager = file_pool_manager(home.path()).await;
    let identity = manager
        .upsert_managed_chatgpt_oauth(managed_oauth_credentials(
            "waiter@example.test",
            "workspace-waiter",
            "old-refresh",
        ))
        .await
        .unwrap();
    let mut stored = load_auth_dot_json(
        home.path(),
        AuthCredentialsStoreMode::File,
        AuthKeyringBackendKind::Direct,
    )
    .unwrap()
    .unwrap();
    let account = &mut stored.managed_chatgpt.as_mut().unwrap().accounts[0];
    account.mutation_lease = Some(ManagedChatgptMutationLease {
        operation_id: "prior-refresh".to_string(),
        kind: ManagedChatgptMutationKind::Refresh,
        expected_revision: account.credential_revision,
        expected_refresh_token: account.tokens.refresh_token.clone(),
        expires_at: Utc::now() + chrono::Duration::minutes(5),
    });
    save_auth(
        home.path(),
        &stored,
        AuthCredentialsStoreMode::File,
        AuthKeyringBackendKind::Direct,
    )
    .unwrap();

    let mut waiting: Pin<Box<dyn Future<Output = std::io::Result<()>>>> = Box::pin(async {
        match operation {
            WaitingOperation::Logout => {
                assert!(manager.remove_managed_chatgpt_account(&identity).await?);
            }
            WaitingOperation::Relogin => {
                let relogged = manager
                    .upsert_managed_chatgpt_oauth(managed_oauth_credentials(
                        "waiter@example.test",
                        "workspace-waiter",
                        "new-refresh",
                    ))
                    .await?;
                assert_eq!(relogged, identity);
            }
        }
        Ok(())
    });
    // No local lock is contended. Polling reaches the durable foreign-lease wait,
    // after logout captured its operation ID or login finished its initial resume.
    assert!(
        waiting
            .as_mut()
            .poll(&mut Context::from_waker(Waker::noop()))
            .is_pending()
    );
    let child = std::process::Command::new(std::env::current_exe().unwrap())
        .arg("--exact")
        .arg("auth::manager::tests::managed_removal_takeover_tests::persist_orphaned_managed_removal_child")
        .env(ORPHAN_POOL_HOME, home.path())
        .output()
        .unwrap();
    assert!(
        child.status.success(),
        "synthetic removal owner must commit and exit"
    );
    assert!(String::from_utf8_lossy(&child.stdout).contains("1 passed"));
    if matches!(lease, RemovalLease::LiveThenExpired) {
        let mut live = load_auth_dot_json(
            home.path(),
            AuthCredentialsStoreMode::File,
            AuthKeyringBackendKind::Direct,
        )
        .unwrap()
        .unwrap();
        row_mut(&mut live, &identity)
            .unwrap()
            .mutation_lease
            .as_mut()
            .unwrap()
            .expires_at = Utc::now() + chrono::Duration::minutes(5);
        save_auth(
            home.path(),
            &live,
            AuthCredentialsStoreMode::File,
            AuthKeyringBackendKind::Direct,
        )
        .unwrap();
        live = load_auth_dot_json(
            home.path(),
            AuthCredentialsStoreMode::File,
            AuthKeyringBackendKind::Direct,
        )
        .unwrap()
        .unwrap();
        assert!(
            tokio::time::timeout(
                std::time::Duration::from_millis(/*millis*/ 150),
                waiting.as_mut()
            )
            .await
            .is_err(),
            "a live foreign removal must keep the waiter blocked"
        );
        assert_eq!(server.received_requests().await.unwrap().len(), 0);
        assert_eq!(
            load_auth_dot_json(
                home.path(),
                AuthCredentialsStoreMode::File,
                AuthKeyringBackendKind::Direct,
            )
            .unwrap(),
            Some(live.clone()),
            "waiting must not rewrite a live foreign removal"
        );
        row_mut(&mut live, &identity)
            .unwrap()
            .mutation_lease
            .as_mut()
            .unwrap()
            .expires_at = Utc::now() - chrono::Duration::seconds(1);
        save_auth(
            home.path(),
            &live,
            AuthCredentialsStoreMode::File,
            AuthKeyringBackendKind::Direct,
        )
        .unwrap();
    }
    tokio::time::timeout(std::time::Duration::from_secs(/*secs*/ 2), waiting)
        .await
        .expect("expired foreign removal must not leave a waiter looping forever")
        .unwrap();
    assert_eq!(server.received_requests().await.unwrap().len(), 1);
    let accounts = manager.managed_chatgpt_accounts().unwrap();
    match operation {
        WaitingOperation::Logout => assert!(accounts.is_empty()),
        WaitingOperation::Relogin => {
            assert_eq!(accounts.len(), 1);
            let snapshot = manager
                .managed_chatgpt_auth_snapshot_for_identity(&identity)
                .await
                .unwrap()
                .unwrap();
            assert_eq!(
                snapshot.auth.get_token_data().unwrap().refresh_token,
                "new-refresh"
            );
        }
    }
}
