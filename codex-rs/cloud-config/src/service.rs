//! Cloud config bundle lifecycle orchestration.
//!
//! Startup loads a shared bundle from cache or backend, and background refresh
//! updates both the on-disk cache and the bundle observed by future config loads.
//! One-shot network loads can disable disk-cache reads and writes.

use crate::backend::BundleClient;
use crate::backend::BundleRequestError;
use crate::backend::RetryableFailureKind;
use crate::cache::CacheLoadStatus;
use crate::cache::CloudConfigBundleCache;
use crate::metrics::emit_fetch_attempt_metric;
use crate::metrics::emit_fetch_final_metric;
use crate::metrics::emit_load_metric;
use crate::validation::validate_bundle;
use codex_async_utils::backoff;
use codex_config::AbsolutePathBuf;
use codex_config::CloudConfigBundle;
use codex_config::CloudConfigBundleLoadError;
use codex_config::CloudConfigBundleLoadErrorCode;
use codex_login::AuthManager;
use codex_login::CodexAuth;
use codex_login::ManagedChatgptAuthSnapshot;
use codex_login::ManagedChatgptEligibility;
use codex_login::RefreshTokenError;
use codex_login::UnauthorizedRecovery;
use codex_protocol::account::PlanType;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;
use std::time::Instant;
use tokio::sync::Mutex;
use tokio::sync::OnceCell;
use tokio::time::sleep;
use tokio::time::timeout;

pub(crate) const CLOUD_CONFIG_BUNDLE_TIMEOUT: Duration = Duration::from_secs(20);
const CLOUD_CONFIG_BUNDLE_MAX_ATTEMPTS: usize = 5;
const CLOUD_CONFIG_BUNDLE_CACHE_REFRESH_INTERVAL: Duration = Duration::from_secs(15 * 60);
const CLOUD_CONFIG_BUNDLE_TIMEOUT_RETRY_INTERVAL: Duration = Duration::from_secs(5);
const CLOUD_CONFIG_BUNDLE_LOAD_FAILED_MESSAGE: &str =
    "Failed to load cloud config bundle (workspace-managed policies).";
const CLOUD_CONFIG_BUNDLE_AUTH_RECOVERY_FAILED_MESSAGE: &str = concat!(
    "Your authentication session could not be refreshed automatically. ",
    "Please log out and sign in again."
);

fn auth_identity(auth: &CodexAuth) -> (Option<String>, Option<String>) {
    (auth.get_chatgpt_user_id(), auth.get_account_id())
}

fn cloud_config_eligible_auth(auth: &CodexAuth) -> bool {
    let Some(plan_type) = auth.account_plan_type() else {
        return false;
    };
    auth.uses_codex_backend()
        && (plan_type.is_business_like()
            || plan_type.is_education_like()
            || plan_type == PlanType::Enterprise)
}

fn optional_bundle(bundle: CloudConfigBundle) -> Option<CloudConfigBundle> {
    if bundle.is_empty() {
        None
    } else {
        Some(bundle)
    }
}

enum CachedBundleLookup {
    Hit(Option<CloudConfigBundle>),
    Miss,
}

enum UnauthorizedRecoveryAction {
    RetrySameAttempt,
    RetryNextAttempt,
}

pub(crate) struct CloudConfigBundleService<C> {
    auth_manager: Arc<AuthManager>,
    managed_snapshot: Option<ManagedChatgptAuthSnapshot>,
    revalidate_immediately: bool,
    client: Arc<C>,
    cache: CloudConfigBundleCache,
    cache_enabled: bool,
    codex_home: AbsolutePathBuf,
    timeout: Duration,
    latest_bundle: OnceCell<Mutex<Result<Option<CloudConfigBundle>, CloudConfigBundleLoadError>>>,
}

impl<C> CloudConfigBundleService<C>
where
    C: BundleClient + 'static,
{
    pub(crate) fn new(
        auth_manager: Arc<AuthManager>,
        client: Arc<C>,
        codex_home: PathBuf,
        timeout: Duration,
    ) -> Self {
        let codex_home = AbsolutePathBuf::resolve_path_against_base(codex_home, "/");
        Self {
            auth_manager,
            managed_snapshot: None,
            revalidate_immediately: false,
            client,
            cache: CloudConfigBundleCache::new(codex_home.clone()),
            cache_enabled: true,
            codex_home,
            timeout,
            latest_bundle: OnceCell::new(),
        }
    }

    pub(crate) fn without_cache(mut self) -> Self {
        self.cache_enabled = false;
        self
    }

    pub(crate) fn for_snapshot(mut self, snapshot: ManagedChatgptAuthSnapshot) -> Self {
        self.managed_snapshot = Some(snapshot);
        self.without_cache()
    }

    pub(crate) async fn latest_success(&self) -> Option<Option<CloudConfigBundle>> {
        self.latest_bundle
            .get()?
            .lock()
            .await
            .as_ref()
            .ok()
            .cloned()
    }

    pub(crate) fn with_latest_success(mut self, bundle: Option<CloudConfigBundle>) -> Self {
        if self
            .managed_snapshot
            .as_ref()
            .is_some_and(|snapshot| !cloud_config_eligible_auth(&snapshot.auth))
        {
            return self;
        }
        self.latest_bundle = OnceCell::new_with(Some(Mutex::new(Ok(bundle))));
        self.revalidate_immediately = true;
        self
    }

    async fn auth(&self) -> Option<CodexAuth> {
        match &self.managed_snapshot {
            Some(snapshot) => Some(snapshot.auth.clone()),
            None => self.auth_manager.auth().await,
        }
    }

    fn selected_identity_is_retained(&self) -> std::io::Result<bool> {
        let Some(snapshot) = &self.managed_snapshot else {
            return Ok(true);
        };
        Ok(self
            .auth_manager
            .stored_managed_chatgpt_accounts()?
            .iter()
            .any(|account| {
                account.identity_key == snapshot.identity_key
                    && account.eligibility != ManagedChatgptEligibility::PendingRemoval
            }))
    }

    async fn recovered_auth(&self) -> Option<CodexAuth> {
        match &self.managed_snapshot {
            Some(snapshot) => self
                .auth_manager
                .managed_chatgpt_auth_snapshot_for_identity(&snapshot.identity_key)
                .await
                .ok()
                .flatten()
                .filter(|current| {
                    current.identity_key == snapshot.identity_key
                        && auth_identity(&current.auth) == auth_identity(&snapshot.auth)
                })
                .map(|current| current.auth),
            None => self.auth_manager.auth().await,
        }
    }

    pub(crate) async fn get_latest(
        &self,
    ) -> Result<Option<CloudConfigBundle>, CloudConfigBundleLoadError> {
        self.latest_bundle
            .get_or_init(|| async { Mutex::new(self.load_startup_bundle_with_timeout().await) })
            .await
            .lock()
            .await
            .clone()
    }

    pub(crate) async fn load_startup_bundle_with_timeout(
        &self,
    ) -> Result<Option<CloudConfigBundle>, CloudConfigBundleLoadError> {
        let _timer =
            codex_otel::start_global_timer("codex.cloud_config_bundle.fetch.duration_ms", &[]);
        let started_at = Instant::now();
        let load_result = timeout(self.timeout, self.load_startup_bundle())
            .await
            .inspect_err(|_| {
                let message = format!(
                    "Timed out waiting for cloud config bundle after {}s",
                    self.timeout.as_secs()
                );
                tracing::error!("{message}");
                emit_load_metric("startup", "error", /*bundle*/ None);
            })
            .map_err(|_| {
                CloudConfigBundleLoadError::new(
                    CloudConfigBundleLoadErrorCode::Timeout,
                    /*status_code*/ None,
                    format!(
                        "timed out waiting for cloud config bundle after {}s",
                        self.timeout.as_secs()
                    ),
                )
            })?;

        let result = match load_result {
            Ok(result) => result,
            Err(err) => {
                emit_load_metric("startup", "error", /*bundle*/ None);
                return Err(err);
            }
        };

        match result.as_ref() {
            Some(bundle) => {
                tracing::info!(
                    elapsed_ms = started_at.elapsed().as_millis(),
                    config_fragments = bundle.config_toml.enterprise_managed.len(),
                    requirements_fragments = bundle.requirements_toml.enterprise_managed.len(),
                    "Cloud config bundle load completed"
                );
                emit_load_metric("startup", "success", Some(bundle));
            }
            None => {
                tracing::info!(
                    elapsed_ms = started_at.elapsed().as_millis(),
                    "Cloud config bundle load completed (none)"
                );
                emit_load_metric("startup", "success", /*bundle*/ None);
            }
        }

        Ok(result)
    }

    async fn load_startup_bundle(
        &self,
    ) -> Result<Option<CloudConfigBundle>, CloudConfigBundleLoadError> {
        let Some(auth) = self.auth().await else {
            return Ok(None);
        };
        if !cloud_config_eligible_auth(&auth) {
            return Ok(None);
        }

        if self.cache_enabled {
            // Startup prefers a valid, identity-matched cache entry. The backend is
            // only consulted on cache miss or invalid cache contents.
            let (chatgpt_user_id, account_id) = auth_identity(&auth);
            match self
                .load_valid_cached_bundle(chatgpt_user_id.as_deref(), account_id.as_deref())
                .await
            {
                CachedBundleLookup::Hit(bundle) => return Ok(bundle),
                CachedBundleLookup::Miss => {}
            }
        }

        self.fetch_remote_bundle_and_update_cache_with_retries(auth, "startup")
            .await
    }

    async fn load_valid_cached_bundle(
        &self,
        chatgpt_user_id: Option<&str>,
        account_id: Option<&str>,
    ) -> CachedBundleLookup {
        match self.cache.load(chatgpt_user_id, account_id).await {
            Ok(signed_payload) => {
                if let Err(err) = validate_bundle(&signed_payload.bundle, &self.codex_home) {
                    tracing::warn!(
                        path = %self.cache.path().display(),
                        error = %err,
                        "Ignoring invalid cached cloud config bundle"
                    );
                    self.cache
                        .log_load_status(&CacheLoadStatus::CacheInvalidBundle);
                    CachedBundleLookup::Miss
                } else {
                    tracing::info!(
                        path = %self.cache.path().display(),
                        "Using cached cloud config bundle"
                    );
                    CachedBundleLookup::Hit(optional_bundle(signed_payload.bundle))
                }
            }
            Err(cache_load_status) => {
                self.cache.log_load_status(&cache_load_status);
                CachedBundleLookup::Miss
            }
        }
    }

    async fn fetch_remote_bundle_and_update_cache_with_retries(
        &self,
        mut auth: CodexAuth,
        trigger: &'static str,
    ) -> Result<Option<CloudConfigBundle>, CloudConfigBundleLoadError> {
        let mut attempt = 1;
        let mut last_status_code: Option<u16> = None;
        let mut auth_recovery = match &self.managed_snapshot {
            Some(snapshot) => self
                .auth_manager
                .unauthorized_recovery_for_snapshot(snapshot),
            None => self.auth_manager.unauthorized_recovery(),
        };

        while attempt <= CLOUD_CONFIG_BUNDLE_MAX_ATTEMPTS {
            // Captured credentials do not outlive their stored account owner.
            // Check each attempt as removal can occur during retry backoff.
            if !self.selected_identity_is_retained().map_err(|_| {
                CloudConfigBundleLoadError::new(
                    CloudConfigBundleLoadErrorCode::Internal,
                    /*status_code*/ None,
                    "Could not verify the selected policy account's stored ownership.",
                )
            })? {
                return Err(CloudConfigBundleLoadError::new(
                    CloudConfigBundleLoadErrorCode::Auth,
                    /*status_code*/ None,
                    "The selected policy account has been removed.",
                ));
            }
            match self.client.get_bundle(&auth).await {
                Ok(bundle) => {
                    return self
                        .validate_and_cache_remote_bundle(&auth, trigger, attempt, bundle)
                        .await;
                }
                Err(BundleRequestError::Policy(denied)) => {
                    return Err(CloudConfigBundleLoadError::new(
                        CloudConfigBundleLoadErrorCode::RequestFailed,
                        /*status_code*/ None,
                        denied.to_string(),
                    ));
                }
                Err(BundleRequestError::Retryable(status)) => {
                    last_status_code = status.status_code();
                    if self
                        .retry_after_request_failure(trigger, attempt, status)
                        .await
                    {
                        attempt += 1;
                        continue;
                    }
                }
                Err(BundleRequestError::Unauthorized {
                    status_code,
                    message,
                }) => {
                    last_status_code = status_code;
                    match self
                        .handle_unauthorized(
                            &mut auth,
                            &mut auth_recovery,
                            trigger,
                            attempt,
                            status_code,
                            &message,
                        )
                        .await?
                    {
                        UnauthorizedRecoveryAction::RetrySameAttempt => continue,
                        UnauthorizedRecoveryAction::RetryNextAttempt => {
                            attempt += 1;
                            continue;
                        }
                    }
                }
            }

            break;
        }

        emit_fetch_final_metric(
            trigger,
            "error",
            "request_retry_exhausted",
            CLOUD_CONFIG_BUNDLE_MAX_ATTEMPTS,
            last_status_code,
            /*bundle*/ None,
        );
        tracing::error!(
            path = %self.cache.path().display(),
            "{CLOUD_CONFIG_BUNDLE_LOAD_FAILED_MESSAGE}"
        );
        Err(CloudConfigBundleLoadError::new(
            CloudConfigBundleLoadErrorCode::RequestFailed,
            last_status_code,
            CLOUD_CONFIG_BUNDLE_LOAD_FAILED_MESSAGE,
        ))
    }

    async fn validate_and_cache_remote_bundle(
        &self,
        auth: &CodexAuth,
        trigger: &'static str,
        attempt: usize,
        bundle: CloudConfigBundle,
    ) -> Result<Option<CloudConfigBundle>, CloudConfigBundleLoadError> {
        emit_fetch_attempt_metric(trigger, attempt, "success", /*status_code*/ None);
        if let Err(err) = validate_bundle(&bundle, &self.codex_home) {
            emit_fetch_final_metric(
                trigger,
                "error",
                "invalid_bundle",
                attempt,
                /*status_code*/ None,
                /*bundle*/ None,
            );
            return Err(err);
        }

        let (chatgpt_user_id, account_id) = auth_identity(auth);
        if self.cache_enabled
            && let Err(err) = self
                .cache
                .save(chatgpt_user_id, account_id, bundle.clone())
                .await
        {
            tracing::warn!(
                error = %err,
                "Failed to write cloud config bundle cache"
            );
        }

        emit_fetch_final_metric(
            trigger,
            "success",
            "none",
            attempt,
            /*status_code*/ None,
            Some(&bundle),
        );
        Ok(optional_bundle(bundle))
    }

    async fn retry_after_request_failure(
        &self,
        trigger: &'static str,
        attempt: usize,
        status: RetryableFailureKind,
    ) -> bool {
        let status_code = status.status_code();
        emit_fetch_attempt_metric(trigger, attempt, "error", status_code);
        if attempt < CLOUD_CONFIG_BUNDLE_MAX_ATTEMPTS {
            tracing::warn!(
                status = ?status,
                attempt,
                max_attempts = CLOUD_CONFIG_BUNDLE_MAX_ATTEMPTS,
                "Failed to fetch cloud config bundle; retrying"
            );
            sleep(backoff(attempt as u64)).await;
            true
        } else {
            false
        }
    }

    async fn handle_unauthorized(
        &self,
        auth: &mut CodexAuth,
        auth_recovery: &mut UnauthorizedRecovery,
        trigger: &'static str,
        attempt: usize,
        status_code: Option<u16>,
        message: &str,
    ) -> Result<UnauthorizedRecoveryAction, CloudConfigBundleLoadError> {
        emit_fetch_attempt_metric(trigger, attempt, "unauthorized", status_code);
        if auth_recovery.has_next() {
            tracing::warn!(
                attempt,
                max_attempts = CLOUD_CONFIG_BUNDLE_MAX_ATTEMPTS,
                "Cloud config bundle request was unauthorized; attempting auth recovery"
            );
            match auth_recovery.next().await {
                Ok(_) => {
                    let Some(refreshed_auth) = self.recovered_auth().await else {
                        tracing::error!(
                            "Auth recovery succeeded but no auth is available for cloud config bundle"
                        );
                        emit_fetch_final_metric(
                            trigger,
                            "error",
                            "auth_recovery_missing_auth",
                            attempt,
                            status_code,
                            /*bundle*/ None,
                        );
                        return Err(CloudConfigBundleLoadError::new(
                            CloudConfigBundleLoadErrorCode::Auth,
                            status_code,
                            CLOUD_CONFIG_BUNDLE_AUTH_RECOVERY_FAILED_MESSAGE,
                        ));
                    };
                    *auth = refreshed_auth;
                    return Ok(UnauthorizedRecoveryAction::RetrySameAttempt);
                }
                Err(RefreshTokenError::Policy(error)) => {
                    return Err(CloudConfigBundleLoadError::new(
                        CloudConfigBundleLoadErrorCode::Auth,
                        status_code,
                        error.to_string(),
                    ));
                }
                Err(RefreshTokenError::Permanent(failed)) => {
                    tracing::warn!(
                        error = %failed,
                        "Failed to recover from unauthorized cloud config bundle request"
                    );
                    emit_fetch_final_metric(
                        trigger,
                        "error",
                        "auth_recovery_unrecoverable",
                        attempt,
                        status_code,
                        /*bundle*/ None,
                    );
                    return Err(CloudConfigBundleLoadError::new(
                        CloudConfigBundleLoadErrorCode::Auth,
                        status_code,
                        failed.message,
                    ));
                }
                Err(RefreshTokenError::Transient(recovery_err)) => {
                    if attempt < CLOUD_CONFIG_BUNDLE_MAX_ATTEMPTS {
                        tracing::warn!(
                            error = %recovery_err,
                            attempt,
                            max_attempts = CLOUD_CONFIG_BUNDLE_MAX_ATTEMPTS,
                            "Failed to recover from unauthorized cloud config bundle request; retrying"
                        );
                        sleep(backoff(attempt as u64)).await;
                    }
                    return Ok(UnauthorizedRecoveryAction::RetryNextAttempt);
                }
            }
        }

        tracing::warn!(
            error = %message,
            "Cloud config bundle request was unauthorized and no auth recovery is available"
        );
        emit_fetch_final_metric(
            trigger,
            "error",
            "auth_recovery_unavailable",
            attempt,
            status_code,
            /*bundle*/ None,
        );
        Err(CloudConfigBundleLoadError::new(
            CloudConfigBundleLoadErrorCode::Auth,
            status_code,
            CLOUD_CONFIG_BUNDLE_AUTH_RECOVERY_FAILED_MESSAGE,
        ))
    }

    pub(crate) async fn refresh_cache_in_background(&self) {
        let mut revalidate_immediately = self.revalidate_immediately;
        loop {
            let mut refresh_interval = CLOUD_CONFIG_BUNDLE_CACHE_REFRESH_INTERVAL;
            if let Some(latest_bundle) = self.latest_bundle.get()
                && matches!(
                    &*latest_bundle.lock().await,
                    Err(error) if error.code() == CloudConfigBundleLoadErrorCode::Timeout
                )
            {
                // Recover startup timeouts through this worker without making
                // readers fetch concurrently or extending the startup deadline.
                refresh_interval = CLOUD_CONFIG_BUNDLE_TIMEOUT_RETRY_INTERVAL;
            }
            if !std::mem::take(&mut revalidate_immediately) {
                sleep(refresh_interval).await;
            }
            match timeout(self.timeout, self.refresh_cache_once()).await {
                Ok(true) => {}
                Ok(false) => break,
                Err(_) => {
                    tracing::error!(
                        "Timed out refreshing cloud config bundle cache from remote; keeping existing cache"
                    );
                    emit_load_metric("refresh", "error", /*bundle*/ None);
                    self.publish_refresh_result(Err(CloudConfigBundleLoadError::new(
                        CloudConfigBundleLoadErrorCode::Timeout,
                        /*status_code*/ None,
                        "timed out refreshing cloud config bundle",
                    )))
                    .await;
                }
            }
        }
    }

    async fn refresh_cache_once(&self) -> bool {
        let Some(auth) = self.auth().await else {
            return false;
        };
        if !cloud_config_eligible_auth(&auth) {
            return false;
        }

        match self
            .fetch_remote_bundle_and_update_cache_with_retries(auth, "refresh")
            .await
        {
            Ok(bundle) => {
                emit_load_metric("refresh", "success", bundle.as_ref());
                self.publish_refresh_result(Ok(bundle)).await;
            }
            Err(err) => {
                if matches!(self.selected_identity_is_retained(), Ok(false)) {
                    return false;
                }
                tracing::error!(
                    path = %self.cache.path().display(),
                    error = %err,
                    "Failed to refresh cloud config bundle cache from remote"
                );
                emit_load_metric("refresh", "error", /*bundle*/ None);
                self.publish_refresh_result(Err(err)).await;
            }
        }
        true
    }

    async fn publish_refresh_result(
        &self,
        result: Result<Option<CloudConfigBundle>, CloudConfigBundleLoadError>,
    ) {
        let Some(latest) = self.latest_bundle.get() else {
            return;
        };
        let mut latest = latest.lock().await;
        if result.is_ok() || latest.is_err() {
            *latest = result;
        }
    }
}

#[cfg(test)]
#[path = "service_tests.rs"]
mod tests;
