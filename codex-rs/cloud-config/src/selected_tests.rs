use super::*;
use crate::cache::CloudConfigBundleCache;
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use codex_config::AbsolutePathBuf;
use codex_config::CloudConfigBundle;
use codex_config::types::AuthCredentialsStoreMode;
use codex_login::AuthKeyringBackendKind;
use pretty_assertions::assert_eq;
use serde_json::json;
use std::io::Read;
use std::io::Write;
use std::net::TcpListener;
use std::path::Path;
use std::sync::atomic::AtomicBool;
use std::sync::atomic::AtomicUsize;
use std::sync::atomic::Ordering;
use std::time::Duration;
use tempfile::tempdir;
use tokio::sync::Notify;

// A loopback-only backend keeps these tests independent of live credentials/services.
struct Backend {
    url: String,
    fail: Arc<AtomicBool>,
    requests: Arc<AtomicUsize>,
    refreshed_failure: Arc<Notify>,
    stop: Arc<AtomicBool>,
    thread: Option<std::thread::JoinHandle<()>>,
}

impl Backend {
    fn new(body: serde_json::Value) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!("http://{}/backend-api", listener.local_addr().unwrap());
        listener.set_nonblocking(true).unwrap();
        let fail = Arc::new(AtomicBool::new(false));
        let requests = Arc::new(AtomicUsize::new(0));
        let refreshed_failure = Arc::new(Notify::new());
        let stop = Arc::new(AtomicBool::new(false));
        let state = (
            fail.clone(),
            requests.clone(),
            refreshed_failure.clone(),
            stop.clone(),
        );
        let thread = std::thread::spawn(move || {
            let (fail, requests, refreshed_failure, stop) = state;
            while !stop.load(Ordering::SeqCst) {
                let Ok((mut stream, _)) = listener.accept() else {
                    std::thread::sleep(Duration::from_millis(1));
                    continue;
                };
                stream
                    .set_read_timeout(Some(Duration::from_secs(2)))
                    .unwrap();
                let mut request = Vec::new();
                let mut buffer = [0; 2048];
                while !request.windows(4).any(|window| window == b"\r\n\r\n") {
                    match stream.read(&mut buffer) {
                        Ok(0) | Err(_) => break,
                        Ok(n) => request.extend_from_slice(&buffer[..n]),
                    }
                }
                let refreshed = String::from_utf8_lossy(&request).contains("Bearer selected-new");
                let failing = fail.load(Ordering::SeqCst);
                let (status, body) = if failing {
                    ("503 Service Unavailable", "{}".to_owned())
                } else {
                    ("200 OK", body.to_string())
                };
                let response = format!(
                    "HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
                requests.fetch_add(1, Ordering::SeqCst);
                if stream.write_all(response.as_bytes()).is_ok() && refreshed && failing {
                    refreshed_failure.notify_one();
                }
            }
        });
        Self {
            url,
            fail,
            requests,
            refreshed_failure,
            stop,
            thread: Some(thread),
        }
    }

    async fn wait_for_refreshed_failure(&self) {
        tokio::time::timeout(Duration::from_secs(10), self.refreshed_failure.notified())
            .await
            .expect("new credentials should receive a failing policy response");
    }
}

impl Drop for Backend {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        self.thread.take().unwrap().join().unwrap();
    }
}

async fn snapshot(
    home: &Path,
    user: &str,
    token: &str,
) -> (Arc<AuthManager>, ManagedChatgptAuthSnapshot) {
    snapshot_with_optional_user(home, Some(user), token).await
}

async fn snapshot_with_optional_user(
    home: &Path,
    user: Option<&str>,
    token: &str,
) -> (Arc<AuthManager>, ManagedChatgptAuthSnapshot) {
    let mut claims = json!({"https://api.openai.com/auth": {
        "chatgpt_plan_type": "enterprise",
        "chatgpt_account_id": "shared-workspace"
    }});
    if let Some(user) = user {
        claims["https://api.openai.com/auth"]["chatgpt_user_id"] = json!(user);
    }
    let jwt = format!(
        "e30.{}.signature",
        URL_SAFE_NO_PAD.encode(claims.to_string())
    );
    std::fs::write(
        home.join("auth.json"),
        json!({
            "tokens": {"id_token": jwt, "access_token": token,
                "refresh_token": "synthetic-refresh", "account_id": "shared-workspace"},
            "last_refresh": chrono::Utc::now().to_rfc3339(),
        })
        .to_string(),
    )
    .unwrap();
    let manager = Arc::new(
        AuthManager::new(
            home.to_path_buf(),
            /*enable_codex_api_key_env*/ false,
            AuthCredentialsStoreMode::File,
            /*forced_chatgpt_workspace_id*/ None,
            /*chatgpt_base_url*/ None,
            AuthKeyringBackendKind::default(),
            codex_login::test_support::transport_default_auth_route_config(),
        )
        .await,
    );
    let selected = manager
        .managed_chatgpt_auth_snapshot(&Default::default())
        .await
        .unwrap()
        .expect("stored selected identity");
    (manager, selected)
}

fn http() -> HttpClientFactory {
    codex_login::test_support::transport_default_auth_route_config()
        .http_client_factory()
        .clone()
}

#[tokio::test]
async fn selected_lkg_survives_new_credentials_and_transient_failure_including_empty_policy() {
    for body in [
        json!({}),
        json!({"requirements_toml": {"enterprise_managed": [{
            "id": "policy", "name": "Selected policy", "contents": "allowed_approval_policies = ['never']"
        }]}}),
    ] {
        let has_policy = body.get("requirements_toml").is_some();
        let backend = Backend::new(body);
        let home = tempdir().unwrap();
        let (manager, selected) = snapshot(home.path(), "selected-user", "selected-old").await;
        let registry = SelectedCloudConfigBundles::new(manager, home.path().to_path_buf());
        let first = registry
            .loader_for(&selected, backend.url.clone(), http())
            .await;
        let expected = first.get().await.unwrap();
        assert_eq!(expected.is_some(), has_policy);
        assert_eq!(
            registry
                .loader_for(&selected, backend.url.clone(), http())
                .await
                .get()
                .await
                .unwrap(),
            expected,
        );
        assert_eq!(backend.requests.load(Ordering::SeqCst), 1);
        backend.fail.store(true, Ordering::SeqCst);
        let refreshed_home = tempdir().unwrap();
        let (_, mut refreshed) =
            snapshot(refreshed_home.path(), "selected-user", "selected-new").await;
        refreshed.account_revision = 2;
        let replacement = registry
            .loader_for(&refreshed, backend.url.clone(), http())
            .await;
        // A seeded loader returns before the failing revalidation can complete.
        assert_eq!(replacement.get().await.unwrap(), expected);
        backend.wait_for_refreshed_failure().await;
        assert_eq!(replacement.get().await.unwrap(), expected);
        let old = registry
            .loader_for(&selected, backend.url.clone(), http())
            .await;
        assert_eq!(old.get().await.unwrap(), expected);
        // A subsequent current-credential lookup still sees the selected policy
        // after the older snapshot has obtained its own loader.
        assert_eq!(
            registry
                .loader_for(&refreshed, backend.url.clone(), http())
                .await
                .get()
                .await
                .unwrap(),
            expected,
        );
    }
}

#[tokio::test]
async fn selected_policy_isolates_users_backends_and_ignores_signed_disk_cache() {
    let backend = Backend::new(json!({}));
    let home = tempdir().unwrap();
    let (manager, selected) = snapshot(home.path(), "first-user", "selected-old").await;
    let registry = SelectedCloudConfigBundles::new(manager, home.path().to_path_buf());
    assert_eq!(
        registry
            .loader_for(&selected, backend.url.clone(), http())
            .await
            .get()
            .await
            .unwrap(),
        None
    );
    let cache =
        CloudConfigBundleCache::new(AbsolutePathBuf::from_absolute_path(home.path()).unwrap());
    cache
        .save(
            Some("second-user".into()),
            Some("shared-workspace".into()),
            CloudConfigBundle::default(),
        )
        .await
        .unwrap();
    backend.fail.store(true, Ordering::SeqCst);
    let other_home = tempdir().unwrap();
    let (_, mut other) = snapshot(other_home.path(), "second-user", "selected-old").await;
    // Deliberately retain the selected identity key: user identity is a separate boundary.
    other.identity_key = selected.identity_key.clone();
    assert!(
        registry
            .loader_for(&other, backend.url.clone(), http())
            .await
            .get()
            .await
            .is_err()
    );
    assert!(
        registry
            .loader_for(&selected, format!("{}/different", backend.url), http())
            .await
            .get()
            .await
            .is_err()
    );
    assert_eq!(
        registry
            .loader_for(&selected, backend.url.clone(), http())
            .await
            .get()
            .await
            .unwrap(),
        None
    );
}

#[tokio::test]
async fn selected_policy_does_not_inherit_lkg_across_credentials_without_user_identity() {
    let backend = Backend::new(json!({"requirements_toml": {"enterprise_managed": [{
        "id": "policy", "name": "Selected policy", "contents": "allowed_approval_policies = ['never']"
    }]}}));
    let home = tempdir().unwrap();
    let (manager, selected) =
        snapshot_with_optional_user(home.path(), /*user*/ None, "selected-old").await;
    assert_eq!(selected.auth.get_chatgpt_user_id(), None);
    let registry = SelectedCloudConfigBundles::new(manager, home.path().to_path_buf());
    let first = registry
        .loader_for(&selected, backend.url.clone(), http())
        .await;
    assert!(first.get().await.unwrap().is_some());
    assert_eq!(backend.requests.load(Ordering::SeqCst), 1);

    backend.fail.store(true, Ordering::SeqCst);
    let refreshed_home = tempdir().unwrap();
    let (_, mut refreshed) =
        snapshot_with_optional_user(refreshed_home.path(), /*user*/ None, "selected-new").await;
    refreshed.account_revision = 2;
    assert_eq!(refreshed.auth.get_chatgpt_user_id(), None);
    assert_eq!(refreshed.identity_key, selected.identity_key);
    assert_eq!(
        refreshed.auth.get_account_id(),
        selected.auth.get_account_id()
    );
    let replacement = registry
        .loader_for(&refreshed, backend.url.clone(), http())
        .await;
    let result = replacement.get().await;
    backend.wait_for_refreshed_failure().await;
    assert!(
        result.is_err(),
        "replacement credentials without a user identity must fetch their own policy, not inherit an unproven same-user LKG",
    );
}

#[tokio::test]
async fn selected_policy_logout_stops_periodic_polls_with_retained_loaders() {
    let home = tempdir().unwrap();
    let (manager, selected) = snapshot(home.path(), "removed-user", "selected-old").await;
    let registry = SelectedCloudConfigBundles::new(manager.clone(), home.path().to_path_buf());
    let backend = Backend::new(json!({}));
    let other_backend = Backend::new(json!({}));
    let retained = registry
        .loader_for(&selected, backend.url.clone(), http())
        .await;
    let retained_other_backend = registry
        .loader_for(&selected, other_backend.url.clone(), http())
        .await;
    assert_eq!(retained.get().await.unwrap(), None);
    assert_eq!(retained_other_backend.get().await.unwrap(), None);

    // A separate still-signed-in owner proves that the periodic refresh deadline
    // actually ran. Keep every loader alive: dropping only the registry's clone
    // must not leave a removed identity's refresh worker using captured tokens.
    let control_home = tempdir().unwrap();
    let (control_manager, control_selected) =
        snapshot(control_home.path(), "retained-user", "selected-new").await;
    let control_registry =
        SelectedCloudConfigBundles::new(control_manager, control_home.path().to_path_buf());
    let control_backend = Backend::new(json!({}));
    let control = control_registry
        .loader_for(&control_selected, control_backend.url.clone(), http())
        .await;
    assert_eq!(control.get().await.unwrap(), None);
    tokio::task::yield_now().await;
    assert_eq!(
        (
            backend.requests.load(Ordering::SeqCst),
            other_backend.requests.load(Ordering::SeqCst),
            control_backend.requests.load(Ordering::SeqCst),
        ),
        (1, 1, 1),
    );

    // This owner API removes local credentials without making a revocation call.
    // No subsequent model request or loader lookup should be needed for cleanup.
    assert!(manager.logout().await.unwrap());
    assert!(
        manager
            .stored_managed_chatgpt_accounts()
            .unwrap()
            .is_empty()
    );
    tokio::task::yield_now().await;
    tokio::time::pause();
    tokio::time::advance(Duration::from_secs(16 * 60)).await;
    tokio::time::resume();
    tokio::time::timeout(Duration::from_secs(5), async {
        while control_backend.requests.load(Ordering::SeqCst) < 2 {
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
    })
    .await
    .expect("a retained owner's scheduled policy refresh must run");
    // Allow loopback response processing to settle after the positive control.
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert_eq!(
        (
            backend.requests.load(Ordering::SeqCst),
            other_backend.requests.load(Ordering::SeqCst),
            control_backend.requests.load(Ordering::SeqCst),
        ),
        (1, 1, 2),
        "logout must stop every backend's selected-policy polling, even while callers retain loaders",
    );
    drop((retained, retained_other_backend, control));
}

#[tokio::test]
async fn selected_policy_pruning_preserves_lkg_on_inventory_errors_but_not_removal() {
    let home = tempdir().unwrap();
    let (manager, selected) = snapshot(home.path(), "selected-user", "selected-old").await;
    let registry = SelectedCloudConfigBundles::new(manager.clone(), home.path().to_path_buf());
    let backend = Backend::new(json!({"requirements_toml": {"enterprise_managed": [{
        "id": "policy", "name": "Selected policy", "contents": "allowed_approval_policies = ['never']"
    }]}}));
    let retained = registry
        .loader_for(&selected, backend.url.clone(), http())
        .await;
    let policy = retained.get().await.unwrap();
    assert!(policy.is_some());
    let auth_path = home.path().join("auth.json");
    let stored_auth = std::fs::read(&auth_path).unwrap();
    std::fs::write(&auth_path, b"unreadable synthetic inventory").unwrap();
    backend.fail.store(true, Ordering::SeqCst);
    assert!(registry.prune_removed_accounts().await.is_err());
    assert_eq!(
        registry
            .loader_for(&selected, backend.url.clone(), http())
            .await
            .get()
            .await
            .unwrap(),
        policy,
        "unreadable inventory is not evidence that the policy owner was removed",
    );
    std::fs::write(&auth_path, &stored_auth).unwrap();
    assert!(manager.logout().await.unwrap());
    registry.prune_removed_accounts().await.unwrap();

    // Recreate the same owner/revision to distinguish actual eviction from a
    // worker that merely stopped polling while its cached policy stayed indexed.
    std::fs::write(&auth_path, stored_auth).unwrap();
    manager.reload().await;
    assert!(
        registry
            .loader_for(&selected, backend.url.clone(), http())
            .await
            .get()
            .await
            .is_err(),
        "a removed owner's indexed policy must not survive re-creation during an outage",
    );
    drop(retained);
}
