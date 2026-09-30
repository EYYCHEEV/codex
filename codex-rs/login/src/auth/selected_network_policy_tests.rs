use super::*;
use codex_http_client::DestinationPolicy;
use codex_http_client::NetworkPolicy;
use codex_http_client::NetworkPolicyController;
use codex_http_client::NetworkPolicyDenied;
use pretty_assertions::assert_eq;
use std::future::Future;
use std::pin::Pin;

struct SelectedPolicyOwner {
    identity: String,
    policy: NetworkPolicy,
    account_change: Option<Arc<AuthManager>>,
}

impl WorkspaceRoutingResolver for SelectedPolicyOwner {
    fn resolve<'a>(
        &'a self,
        _request: WorkspaceRoutingRequest<'a>,
    ) -> Pin<Box<dyn Future<Output = std::io::Result<Option<WorkspaceRouting>>> + Send + 'a>> {
        Box::pin(async { panic!("policy admission must not perform routing discovery") })
    }

    fn network_policy_for_managed_snapshot<'a>(
        &'a self,
        snapshot: &'a ManagedChatgptAuthSnapshot,
        chatgpt_base_url: &'a str,
        _session: Option<Arc<WorkspaceRoutingSession>>,
    ) -> Pin<Box<dyn Future<Output = std::io::Result<NetworkPolicy>> + Send + 'a>> {
        Box::pin(async move {
            assert_eq!(
                (snapshot.identity_key.as_str(), chatgpt_base_url),
                (
                    self.identity.as_str(),
                    "https://selected.example/backend-api"
                )
            );
            if let Some(manager) = &self.account_change {
                manager.set_cached_auth(None);
            }
            Ok(self.policy.clone())
        })
    }
}

async fn selected_fixture() -> (TempDir, Arc<AuthManager>, ManagedChatgptAuthSnapshot) {
    let home = tempdir().unwrap();
    let manager = file_pool_manager(home.path()).await;
    let identity = manager
        .upsert_managed_chatgpt_oauth(managed_oauth_credentials(
            "selected@example.com",
            "selected-workspace",
            "selected-refresh",
        ))
        .await
        .unwrap();
    let ambient_identity = manager
        .upsert_managed_chatgpt_oauth(managed_oauth_credentials(
            "ambient@example.com",
            "ambient-workspace",
            "ambient-refresh",
        ))
        .await
        .unwrap();
    let snapshot = manager
        .managed_chatgpt_auth_snapshot_for_identity(&identity)
        .await
        .unwrap()
        .unwrap();
    let ambient = manager
        .managed_chatgpt_auth_snapshot_for_identity(&ambient_identity)
        .await
        .unwrap()
        .unwrap();
    manager.set_cached_auth(Some(ambient.auth));
    assert_eq!(
        manager.auth_cached().unwrap().get_account_id().as_deref(),
        Some("ambient-workspace")
    );
    (home, manager, snapshot)
}

#[tokio::test]
#[serial(codex_auth_env)]
async fn selected_policy_admission_does_not_reselect_or_inherit_ambient_policy() {
    let (_home, manager, snapshot) = selected_fixture().await;
    let controller = NetworkPolicyController::default();
    let policy = controller.policy();
    assert!(controller.publish(
        policy.revision(),
        DestinationPolicy::Restricted {
            allowed_hosts: ["selected.example".to_string()].into(),
        },
    ));
    let owner: Arc<dyn WorkspaceRoutingResolver> = Arc::new(SelectedPolicyOwner {
        identity: snapshot.identity_key.clone(),
        policy,
        account_change: None,
    });
    manager.set_workspace_routing_resolver(Arc::downgrade(&owner));
    let admitted = manager
        .network_policy_for_managed_snapshot(
            &snapshot,
            "https://selected.example/backend-api",
            /*session*/ None,
        )
        .await
        .unwrap();
    assert_eq!(
        ["https://selected.example/", "https://ambient.example/"]
            .map(|url| admitted.acquire(&url.parse().unwrap()).map(|_| ())),
        [Ok(()), Err(NetworkPolicyDenied::Destination)],
    );
    assert_eq!(
        manager.auth_cached().unwrap().get_account_id().as_deref(),
        Some("ambient-workspace")
    );
}

#[tokio::test]
#[serial(codex_auth_env)]
async fn selected_policy_admission_rejects_account_change_while_loading() {
    let (_home, manager, snapshot) = selected_fixture().await;
    let owner: Arc<dyn WorkspaceRoutingResolver> = Arc::new(SelectedPolicyOwner {
        identity: snapshot.identity_key.clone(),
        policy: NetworkPolicy::default(),
        account_change: Some(manager.clone()),
    });
    manager.set_workspace_routing_resolver(Arc::downgrade(&owner));
    assert!(
        manager
            .network_policy_for_managed_snapshot(
                &snapshot,
                "https://selected.example/backend-api",
                /*session*/ None,
            )
            .await
            .is_err()
    );
}

#[tokio::test]
#[serial(codex_auth_env)]
async fn selected_policy_requires_owner_only_for_managed_application_policy() {
    let (_home, mut manager, snapshot) = selected_fixture().await;
    assert!(
        manager
            .network_policy_for_managed_snapshot(
                &snapshot,
                "https://selected.example/backend-api",
                /*session*/ None,
            )
            .await
            .is_ok()
    );
    let controller = NetworkPolicyController::default();
    let factory = manager
        .http_client_factory()
        .with_network_policy(controller.policy());
    Arc::get_mut(&mut manager).unwrap().auth_route_config =
        AuthRouteConfig::from_http_client_factory(factory);
    let error = manager
        .network_policy_for_managed_snapshot(
            &snapshot,
            "https://selected.example/backend-api",
            /*session*/ None,
        )
        .await
        .unwrap_err();
    assert!(error.to_string().contains("policy owner is unavailable"));
}
