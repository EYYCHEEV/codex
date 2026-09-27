//! Selected policy lives with its identity and backend, not a credential revision.
//! Disk entries lack backend provenance, so selected services use memory only.

use crate::backend::BackendBundleClient;
use crate::bundle_loader::cloud_config_bundle_loader_for_shared_service;
use crate::service::CLOUD_CONFIG_BUNDLE_TIMEOUT;
use crate::service::CloudConfigBundleService;
use codex_config::CloudConfigBundleLoader;
use codex_http_client::HttpClientFactory;
use codex_login::AuthManager;
use codex_login::ManagedChatgptAuthSnapshot;
use codex_login::ManagedChatgptEligibility;
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::Mutex;
use tokio::task::AbortHandle;

#[derive(Hash, PartialEq, Eq)]
struct PolicyOwner {
    identity: String,
    user: Option<String>,
    workspace: Option<String>,
    backend: String,
}

struct Entry {
    revision: u64,
    service: Arc<CloudConfigBundleService<BackendBundleClient>>,
    loader: CloudConfigBundleLoader,
    refresh_task: AbortHandle,
}

impl Drop for Entry {
    fn drop(&mut self) {
        self.refresh_task.abort();
    }
}

/// App-server-owned selected policy services. Never changes default authentication.
pub struct SelectedCloudConfigBundles {
    auth_manager: Arc<AuthManager>,
    codex_home: PathBuf,
    entries: Mutex<HashMap<PolicyOwner, Entry>>,
}

impl SelectedCloudConfigBundles {
    pub fn new(auth_manager: Arc<AuthManager>, codex_home: PathBuf) -> Self {
        Self {
            auth_manager,
            codex_home,
            entries: Mutex::new(HashMap::new()),
        }
    }

    /// Stops policy refreshes for removed identities without changing retained policies.
    pub async fn prune_removed_accounts(&self) -> std::io::Result<()> {
        let mut entries = self.entries.lock().await;
        if entries.is_empty() {
            return Ok(());
        }
        let accounts = self.auth_manager.stored_managed_chatgpt_accounts()?;
        entries.retain(|owner, _| {
            accounts.iter().any(|account| {
                account.identity_key == owner.identity
                    && account.eligibility != ManagedChatgptEligibility::PendingRemoval
            })
        });
        Ok(())
    }

    pub async fn loader_for(
        &self,
        snapshot: &ManagedChatgptAuthSnapshot,
        backend: String,
        http: HttpClientFactory,
    ) -> CloudConfigBundleLoader {
        let key = PolicyOwner {
            identity: snapshot.identity_key.clone(),
            user: snapshot.auth.get_chatgpt_user_id(),
            workspace: snapshot.auth.get_account_id(),
            backend: backend.clone(),
        };
        let mut entries = self.entries.lock().await;
        let previous = entries.get(&key);
        if let Some(entry) = previous
            && entry.revision == snapshot.account_revision
        {
            return entry.loader.clone();
        }
        let mut service = CloudConfigBundleService::new(
            self.auth_manager.clone(),
            Arc::new(BackendBundleClient::new(backend, http)),
            self.codex_home.clone(),
            CLOUD_CONFIG_BUNDLE_TIMEOUT,
        )
        .for_snapshot(snapshot.clone());
        // This only reads initialized state; never wait for startup/network under the map lock.
        if key.user.is_some()
            && key.workspace.is_some()
            && let Some(entry) = previous
            && let Some(bundle) = entry.service.latest_success().await
        {
            service = service.with_latest_success(bundle);
        }
        let service = Arc::new(service);
        let (loader, refresh_task) = cloud_config_bundle_loader_for_shared_service(service.clone());
        // An old in-flight request may finish, but cannot replace newer credentials.
        if previous.is_none_or(|entry| entry.revision < snapshot.account_revision) {
            entries.insert(
                key,
                Entry {
                    revision: snapshot.account_revision,
                    service,
                    loader: loader.clone(),
                    refresh_task,
                },
            );
        }
        loader
    }
}

#[cfg(test)]
#[path = "selected_tests.rs"]
mod tests;
