use super::bedrock_auth::clear_user_model_provider_if_bedrock;
use super::bedrock_auth::set_user_model_provider_to_bedrock;
use super::*;
use crate::auth_mode::auth_mode_to_api;
use crate::external_auth::ExternalAuthBridge;
use chrono::DateTime;
#[cfg(test)]
use chrono::Utc;
use codex_app_server_protocol::DesktopOnboardingEntrypoint;
use codex_login::LoginOnboardingEntrypoint;
use codex_model_provider::is_supported_amazon_bedrock_region;

mod managed_accounts;
mod rate_limit_resets;
mod selection_observer;

#[cfg(test)]
use managed_accounts::managed_rate_observation;
pub(crate) use selection_observer::AccountSelectionObserver;
use selection_observer::AccountSelectionObserverState;
#[cfg(test)]
use selection_observer::ObservedSelection;
use selection_observer::PoolUpdateWatcherShutdown;
use selection_observer::SelectionNotificationRoute;
#[cfg(test)]
use selection_observer::send_pool_update_unless_shutdown;
#[cfg(test)]
use selection_observer::should_emit_pool_update;
use selection_observer::start_pool_update_watcher;

pub(super) async fn remove_thread_account_selection_state(
    thread_state_manager: &ThreadStateManager,
    account_selection_observer: &AccountSelectionObserver,
    thread_id: ThreadId,
) {
    thread_state_manager.remove_thread_state(thread_id).await;
    account_selection_observer
        .remove_thread(&thread_id.to_string())
        .await;
}

// Duration before a browser ChatGPT login attempt is abandoned.
const LOGIN_CHATGPT_TIMEOUT: Duration = Duration::from_secs(10 * 60);
const ACCOUNT_RATE_LIMIT_FETCH_TIMEOUT: Duration = Duration::from_secs(/*secs*/ 10);
const ACCOUNT_TOKEN_REFRESH_TIMEOUT: Duration = Duration::from_secs(/*secs*/ 10);
const ACCOUNT_TOKEN_USAGE_FETCH_TIMEOUT: Duration = Duration::from_secs(/*secs*/ 10);
const ACCOUNT_WORKSPACE_MESSAGES_FETCH_TIMEOUT: Duration =
    Duration::from_millis(/*millis*/ 1000);
// Login overrides are intentionally available only in debug builds.
#[cfg(debug_assertions)]
const LOGIN_ISSUER_OVERRIDE_ENV_VAR: &str = "CODEX_APP_SERVER_LOGIN_ISSUER";
#[cfg(debug_assertions)]
const LOGIN_OPEN_APP_URL_OVERRIDE_ENV_VAR: &str = "CODEX_APP_SERVER_DEV_OPEN_APP_URL";

enum ActiveLogin {
    Browser {
        shutdown_handle: ShutdownHandle,
        login_id: Uuid,
    },
    DeviceCode {
        cancel: CancellationToken,
        login_id: Uuid,
    },
}

impl ActiveLogin {
    fn login_id(&self) -> Uuid {
        match self {
            ActiveLogin::Browser { login_id, .. } | ActiveLogin::DeviceCode { login_id, .. } => {
                *login_id
            }
        }
    }

    fn cancel(&self) {
        match self {
            ActiveLogin::Browser {
                shutdown_handle, ..
            } => shutdown_handle.shutdown(),
            ActiveLogin::DeviceCode { cancel, .. } => cancel.cancel(),
        }
    }
}

#[derive(Clone, Copy, Debug)]
enum CancelLoginError {
    NotFound,
}

impl Drop for ActiveLogin {
    fn drop(&mut self) {
        self.cancel();
    }
}

#[derive(Clone)]
pub(crate) struct AccountRequestProcessor {
    auth_manager: Arc<AuthManager>,
    thread_manager: Arc<ThreadManager>,
    thread_state_manager: ThreadStateManager,
    outgoing: Arc<OutgoingMessageSender>,
    config: Arc<Config>,
    config_manager: ConfigManager,
    active_login: Arc<Mutex<Option<ActiveLogin>>>,
    selection_observer_state: Arc<Mutex<AccountSelectionObserverState>>,
    pool_update_shutdown: Arc<PoolUpdateWatcherShutdown>,
}

impl AccountRequestProcessor {
    pub(crate) fn new(
        auth_manager: Arc<AuthManager>,
        thread_manager: Arc<ThreadManager>,
        thread_state_manager: ThreadStateManager,
        outgoing: Arc<OutgoingMessageSender>,
        config: Arc<Config>,
        config_manager: ConfigManager,
    ) -> Self {
        let (selection_observer_state, pool_update_shutdown) =
            start_pool_update_watcher(&auth_manager, &outgoing);
        Self {
            auth_manager,
            thread_manager,
            thread_state_manager,
            outgoing,
            config,
            config_manager,
            active_login: Arc::new(Mutex::new(None)),
            selection_observer_state,
            pool_update_shutdown,
        }
    }

    pub(crate) async fn login_account(
        &self,
        request_id: ConnectionRequestId,
        params: LoginAccountParams,
    ) -> Result<Option<ClientResponsePayload>, JSONRPCErrorError> {
        self.login_v2(request_id, params).await.map(|()| None)
    }

    pub(crate) async fn list_accounts(
        &self,
        request_id: ConnectionRequestId,
        params: ListAccountsParams,
    ) -> Result<Option<ClientResponsePayload>, JSONRPCErrorError> {
        let scope = self.selection_scope_for_list(&params).await;
        let selection_scope = params.thread_id.is_some().then(|| scope.clone());
        let list_registration = match selection_scope
            .as_ref()
            .and_then(|scope| scope.thread_id.as_deref())
        {
            Some(thread_id) => Some(
                self.selection_observer()
                    .capture_list_registration(thread_id, request_id.connection_id)
                    .await,
            ),
            None => None,
        };
        let connection_id = request_id.connection_id;
        let result = self.list_accounts_response(params, scope).await;
        let selection_result = result.as_ref().ok().and_then(|response| {
            response.selection_revision.map(|selection_revision| {
                (response.selected_account_id.clone(), selection_revision)
            })
        });
        self.outgoing.send_result(request_id, result).await;

        let is_still_subscribed = match selection_scope
            .as_ref()
            .and_then(|scope| scope.thread_id.as_deref())
            .and_then(|thread_id| ThreadId::from_string(thread_id).ok())
        {
            Some(thread_id) => self
                .thread_state_manager
                .subscribed_connection_ids(thread_id)
                .await
                .contains(&connection_id),
            None => false,
        };
        let selection_update = match (list_registration, selection_scope, selection_result) {
            (Some(registration), Some(scope), Some((selected_account_id, selection_revision)))
                if is_still_subscribed =>
            {
                self.selection_observer()
                    .record_list_response(
                        registration,
                        scope,
                        selected_account_id,
                        selection_revision,
                        SelectionNotificationRoute::for_connection(
                            Arc::clone(&self.outgoing),
                            connection_id,
                        ),
                    )
                    .await
            }
            _ => None,
        };
        if let Some((selection_update, routes)) = selection_update {
            for route in routes {
                route.send(selection_update.clone()).await;
            }
        }
        Ok(None)
    }

    pub(crate) async fn logout_account(
        &self,
        request_id: ConnectionRequestId,
        params: Option<LogoutAccountParams>,
    ) -> Result<Option<ClientResponsePayload>, JSONRPCErrorError> {
        self.logout_v2(request_id, params).await.map(|()| None)
    }

    pub(crate) async fn cancel_login_account(
        &self,
        params: CancelLoginAccountParams,
    ) -> Result<Option<ClientResponsePayload>, JSONRPCErrorError> {
        self.cancel_login_response(params)
            .await
            .map(|response| Some(response.into()))
    }

    pub(crate) async fn get_account(
        &self,
        params: GetAccountParams,
    ) -> Result<Option<ClientResponsePayload>, JSONRPCErrorError> {
        self.get_account_response(params)
            .await
            .map(|response| Some(response.into()))
    }

    pub(crate) async fn get_auth_status(
        &self,
        params: GetAuthStatusParams,
    ) -> Result<Option<ClientResponsePayload>, JSONRPCErrorError> {
        self.get_auth_status_response(params)
            .await
            .map(|response| Some(response.into()))
    }

    pub(crate) async fn get_account_rate_limits(
        &self,
    ) -> Result<Option<ClientResponsePayload>, JSONRPCErrorError> {
        self.get_account_rate_limits_response()
            .await
            .map(|response| Some(response.into()))
    }

    pub(crate) async fn get_account_token_usage(
        &self,
    ) -> Result<Option<ClientResponsePayload>, JSONRPCErrorError> {
        self.get_account_token_usage_response()
            .await
            .map(|response| Some(response.into()))
    }

    pub(crate) async fn get_workspace_messages(
        &self,
    ) -> Result<Option<ClientResponsePayload>, JSONRPCErrorError> {
        self.get_workspace_messages_response()
            .await
            .map(|response| Some(response.into()))
    }

    pub(crate) async fn send_add_credits_nudge_email(
        &self,
        params: SendAddCreditsNudgeEmailParams,
    ) -> Result<Option<ClientResponsePayload>, JSONRPCErrorError> {
        self.send_add_credits_nudge_email_response(params)
            .await
            .map(|response| Some(response.into()))
    }

    pub(crate) async fn cancel_active_login(&self) {
        let mut guard = self.active_login.lock().await;
        if let Some(active_login) = guard.take() {
            drop(active_login);
        }
    }

    pub(crate) fn clear_external_auth(&self) {
        self.pool_update_shutdown.cancel();
        self.auth_manager.clear_external_auth();
        self.thread_manager
            .plugins_manager()
            .set_auth_mode(self.auth_manager.get_api_auth_mode());
    }

    fn current_account_updated_notification(&self) -> AccountUpdatedNotification {
        let auth = self.auth_manager.auth_cached();
        AccountUpdatedNotification {
            auth_mode: auth
                .as_ref()
                .map(CodexAuth::api_auth_mode)
                .map(auth_mode_to_api),
            plan_type: auth.as_ref().and_then(CodexAuth::account_plan_type),
        }
    }

    async fn load_latest_config(&self) -> Config {
        match self
            .config_manager
            .load_latest_config(/*fallback_cwd*/ None)
            .await
        {
            Ok(config) => config,
            Err(err) => {
                tracing::warn!("failed to reload config, using startup config: {err}");
                self.config.as_ref().clone()
            }
        }
    }

    async fn maybe_refresh_plugin_caches_for_current_config(
        config_manager: &ConfigManager,
        thread_manager: &Arc<ThreadManager>,
        auth: Option<CodexAuth>,
    ) {
        thread_manager
            .plugins_manager()
            .set_auth_mode(auth.as_ref().map(CodexAuth::api_auth_mode));
        thread_manager
            .plugins_manager()
            .clear_recommended_plugins_cache();

        match config_manager
            .load_latest_config(/*fallback_cwd*/ None)
            .await
        {
            Ok(config) => {
                Self::spawn_effective_plugins_changed_task(
                    Arc::clone(thread_manager),
                    config_manager.clone(),
                );
                let plugins_config = config.plugins_config_input();
                let refresh_thread_manager = Arc::clone(thread_manager);
                let refresh_config_manager = config_manager.clone();
                let on_effective_plugins_changed: Arc<
                    dyn Fn(codex_core_plugins::EffectivePluginsChange) + Send + Sync,
                > = Arc::new(move |_change| {
                    Self::spawn_effective_plugins_changed_task(
                        Arc::clone(&refresh_thread_manager),
                        refresh_config_manager.clone(),
                    );
                });
                thread_manager
                    .plugins_manager()
                    .maybe_start_curated_repo_sync_for_config(
                        &plugins_config,
                        Some(Arc::clone(&on_effective_plugins_changed)),
                    );
                thread_manager
                    .plugins_manager()
                    .maybe_start_remote_plugin_caches_refresh(
                        &plugins_config,
                        auth,
                        Some(on_effective_plugins_changed),
                    );
            }
            Err(err) => {
                warn!(
                    "failed to reload config after account changed, skipping remote installed plugins cache refresh: {err}"
                );
            }
        }
    }

    fn spawn_effective_plugins_changed_task(
        thread_manager: Arc<ThreadManager>,
        config_manager: ConfigManager,
    ) {
        tokio::spawn(async move {
            thread_manager.plugins_manager().clear_cache();
            thread_manager.skills_service().clear_cache();
            crate::mcp_refresh::reload_mcp_config_best_effort(&thread_manager, &config_manager)
                .await;
            thread_manager.invalidate_mcp_runtimes().await;
        });
    }

    async fn login_v2(
        &self,
        request_id: ConnectionRequestId,
        params: LoginAccountParams,
    ) -> Result<(), JSONRPCErrorError> {
        match params {
            LoginAccountParams::ApiKey { api_key } => {
                self.login_api_key_v2(request_id, LoginApiKeyParams { api_key })
                    .await;
            }
            LoginAccountParams::Chatgpt {
                app_brand,
                codex_streamlined_login,
                use_hosted_login_success_page,
            } => {
                let login_success_page = if use_hosted_login_success_page {
                    let app_brand = match app_brand.unwrap_or_default() {
                        LoginAppBrand::Codex => LoginSuccessPageBrand::Codex,
                        LoginAppBrand::Chatgpt => LoginSuccessPageBrand::Chatgpt,
                    };
                    LoginSuccessPage::Hosted {
                        url: CODEX_OPEN_APP_URL.parse().map_err(|err| {
                            internal_error(format!("invalid Codex open app URL: {err}"))
                        })?,
                        app_brand,
                    }
                } else {
                    LoginSuccessPage::default()
                };
                self.login_chatgpt_v2(request_id, codex_streamlined_login, login_success_page)
                    .await;
            }
            LoginAccountParams::ChatgptDeviceCode => {
                self.login_chatgpt_device_code_v2(request_id).await;
            }
            LoginAccountParams::ChatgptAuthTokens {
                access_token,
                chatgpt_account_id,
                chatgpt_plan_type,
            } => {
                self.login_chatgpt_auth_tokens(
                    request_id,
                    access_token,
                    chatgpt_account_id,
                    chatgpt_plan_type,
                )
                .await;
            }
            LoginAccountParams::AmazonBedrock { api_key, region } => {
                self.login_amazon_bedrock_v2(request_id, api_key, region)
                    .await;
            }
        }
        Ok(())
    }

    fn external_auth_active_error(&self) -> JSONRPCErrorError {
        invalid_request(
            "External auth is active. Use account/login/start (chatgptAuthTokens) to update it or account/logout to clear it.",
        )
    }

    async fn login_api_key_common(
        &self,
        params: &LoginApiKeyParams,
    ) -> std::result::Result<(), JSONRPCErrorError> {
        if self.auth_manager.is_external_chatgpt_auth_active() {
            return Err(self.external_auth_active_error());
        }

        if !self
            .auth_manager
            .is_login_method_allowed(ForcedLoginMethod::Api)
        {
            return Err(invalid_request(
                "API key login is disabled. Use ChatGPT login instead.",
            ));
        }

        // Cancel any active login attempt.
        {
            let mut guard = self.active_login.lock().await;
            if let Some(active) = guard.take() {
                drop(active);
            }
        }

        match login_with_api_key(
            &self.config.codex_home,
            &params.api_key,
            self.config.cli_auth_credentials_store_mode,
            self.config.auth_keyring_backend_kind(),
        ) {
            Ok(()) => {
                self.auth_manager.reload().await;
                Ok(())
            }
            Err(err) => Err(internal_error(format!("failed to save api key: {err}"))),
        }
    }

    async fn login_api_key_v2(&self, request_id: ConnectionRequestId, params: LoginApiKeyParams) {
        let result = self
            .login_api_key_common(&params)
            .await
            .map(|()| LoginAccountResponse::ApiKey {});
        let logged_in = result.is_ok();
        self.outgoing.send_result(request_id, result).await;

        if logged_in {
            self.send_login_success_notifications(/*login_id*/ None)
                .await;
        }
    }

    async fn login_amazon_bedrock_v2(
        &self,
        request_id: ConnectionRequestId,
        api_key: String,
        region: String,
    ) {
        let result = async {
            if self.auth_manager.is_external_chatgpt_auth_active() {
                return Err(self.external_auth_active_error());
            }
            if !self
                .auth_manager
                .is_login_method_allowed(ForcedLoginMethod::Api)
            {
                return Err(invalid_request(
                    "Amazon Bedrock login is disabled. Use ChatGPT login instead.",
                ));
            }

            let api_key = api_key.trim();
            if api_key.is_empty() {
                return Err(invalid_request("Amazon Bedrock API key must not be empty."));
            }
            let region = region.trim();
            if !is_supported_amazon_bedrock_region(region) {
                return Err(invalid_request(format!(
                    "Amazon Bedrock Mantle does not support region `{region}`"
                )));
            }

            {
                let mut guard = self.active_login.lock().await;
                if let Some(active) = guard.take() {
                    drop(active);
                }
            }

            set_user_model_provider_to_bedrock(&self.config_manager).await?;
            login_with_bedrock_api_key(
                &self.config.codex_home,
                api_key,
                region,
                self.config.cli_auth_credentials_store_mode,
                self.config.auth_keyring_backend_kind(),
            )
            .map_err(|err| internal_error(format!("failed to save Amazon Bedrock auth: {err}")))?;
            self.auth_manager.reload().await;
            Ok(LoginAccountResponse::AmazonBedrock {})
        }
        .await;
        let logged_in = result.is_ok();
        self.outgoing.send_result(request_id, result).await;

        if logged_in {
            self.send_login_success_notifications(/*login_id*/ None)
                .await;
        }
    }

    // Build options for a ChatGPT login attempt; performs validation.
    async fn login_chatgpt_common(
        &self,
        codex_streamlined_login: bool,
        login_success_page: LoginSuccessPage,
    ) -> std::result::Result<LoginServerOptions, JSONRPCErrorError> {
        let config = self.config.as_ref();

        if self.auth_manager.is_external_chatgpt_auth_active() {
            return Err(self.external_auth_active_error());
        }

        if !self
            .auth_manager
            .is_login_method_allowed(ForcedLoginMethod::Chatgpt)
        {
            return Err(invalid_request(
                "ChatGPT login is disabled. Use API key login instead.",
            ));
        }

        let opts = LoginServerOptions {
            open_browser: false,
            codex_streamlined_login,
            login_success_page,
            ..LoginServerOptions::new(
                config.codex_home.to_path_buf(),
                oauth_client_id(),
                self.auth_manager.effective_chatgpt_workspaces(),
                config.cli_auth_credentials_store_mode,
                config.auth_keyring_backend_kind(),
                config.auth_route_config(),
            )
        };
        #[cfg(debug_assertions)]
        let opts = {
            let mut opts = opts;
            if let Ok(issuer) = std::env::var(LOGIN_ISSUER_OVERRIDE_ENV_VAR)
                && !issuer.trim().is_empty()
            {
                opts.issuer = issuer;
            }
            if let LoginSuccessPage::Hosted { url, .. } = &mut opts.login_success_page
                && let Ok(open_app_url) = std::env::var(LOGIN_OPEN_APP_URL_OVERRIDE_ENV_VAR)
                && !open_app_url.trim().is_empty()
            {
                *url = open_app_url
                    .parse()
                    .map_err(|err| internal_error(format!("invalid Codex open app URL: {err}")))?;
            }
            opts
        };

        Ok(opts)
    }

    fn login_chatgpt_device_code_start_error(err: IoError) -> JSONRPCErrorError {
        let is_not_found = err.kind() == std::io::ErrorKind::NotFound;
        if is_not_found {
            invalid_request(err.to_string())
        } else {
            internal_error(format!("failed to request device code: {err}"))
        }
    }

    async fn login_chatgpt_v2(
        &self,
        request_id: ConnectionRequestId,
        codex_streamlined_login: bool,
        login_success_page: LoginSuccessPage,
    ) {
        let result = self
            .login_chatgpt_response(codex_streamlined_login, login_success_page)
            .await;
        self.outgoing.send_result(request_id, result).await;
    }

    async fn login_chatgpt_response(
        &self,
        codex_streamlined_login: bool,
        login_success_page: LoginSuccessPage,
    ) -> Result<LoginAccountResponse, JSONRPCErrorError> {
        let opts = self
            .login_chatgpt_common(codex_streamlined_login, login_success_page)
            .await?;
        let server = run_login_server(opts)
            .map_err(|err| internal_error(format!("failed to start login server: {err}")))?;
        let login_id = Uuid::new_v4();
        let shutdown_handle = server.cancel_handle();

        // Replace active login if present.
        {
            let mut guard = self.active_login.lock().await;
            if let Some(existing) = guard.take() {
                drop(existing);
            }
            *guard = Some(ActiveLogin::Browser {
                shutdown_handle: shutdown_handle.clone(),
                login_id,
            });
        }

        let outgoing_clone = self.outgoing.clone();
        let config_manager = self.config_manager.clone();
        let thread_manager = Arc::clone(&self.thread_manager);
        let config = Arc::clone(&self.config);
        let active_login = self.active_login.clone();
        let auth_url = server.auth_url.clone();
        tokio::spawn(async move {
            let (success, error_msg, onboarding_entrypoint, managed_account_id) =
                match tokio::time::timeout(
                    LOGIN_CHATGPT_TIMEOUT,
                    server.block_until_done_with_callback_result(),
                )
                .await
                {
                    Ok(Ok(result)) => (
                        true,
                        None,
                        result.onboarding_entrypoint.map(
                            |LoginOnboardingEntrypoint::LifeSciences| {
                                DesktopOnboardingEntrypoint::LifeSciences
                            },
                        ),
                        result.managed_account_id,
                    ),
                    Ok(Err(err)) => (
                        false,
                        Some(format!("Login server error: {err}")),
                        None,
                        None,
                    ),
                    Err(_elapsed) => {
                        shutdown_handle.shutdown();
                        (false, Some("Login timed out".to_string()), None, None)
                    }
                };

            Self::send_chatgpt_login_completion_notifications(
                &outgoing_clone,
                config_manager,
                thread_manager,
                config,
                AccountLoginCompletedNotification {
                    login_id: Some(login_id.to_string()),
                    success,
                    error: error_msg,
                    onboarding_entrypoint,
                    managed_account_id,
                },
            )
            .await;

            // Clear the active login if it matches this attempt. It may have been replaced or cancelled.
            let mut guard = active_login.lock().await;
            if guard.as_ref().map(ActiveLogin::login_id) == Some(login_id) {
                *guard = None;
            }
        });

        Ok(LoginAccountResponse::Chatgpt {
            login_id: login_id.to_string(),
            auth_url,
        })
    }

    async fn login_chatgpt_device_code_v2(&self, request_id: ConnectionRequestId) {
        let result = self.login_chatgpt_device_code_response().await;
        self.outgoing.send_result(request_id, result).await;
    }

    async fn login_chatgpt_device_code_response(
        &self,
    ) -> Result<LoginAccountResponse, JSONRPCErrorError> {
        let opts = self
            .login_chatgpt_common(
                /*codex_streamlined_login*/ false,
                LoginSuccessPage::default(),
            )
            .await?;
        let device_code = request_device_code(&opts)
            .await
            .map_err(Self::login_chatgpt_device_code_start_error)?;
        let login_id = Uuid::new_v4();
        let cancel = CancellationToken::new();

        {
            let mut guard = self.active_login.lock().await;
            if let Some(existing) = guard.take() {
                drop(existing);
            }
            *guard = Some(ActiveLogin::DeviceCode {
                cancel: cancel.clone(),
                login_id,
            });
        }

        let verification_url = device_code.verification_url.clone();
        let user_code = device_code.user_code.clone();

        let outgoing_clone = self.outgoing.clone();
        let config_manager = self.config_manager.clone();
        let thread_manager = Arc::clone(&self.thread_manager);
        let config = Arc::clone(&self.config);
        let active_login = self.active_login.clone();
        tokio::spawn(async move {
            let (success, error_msg, managed_account_id) = tokio::select! {
                _ = cancel.cancelled() => {
                    (false, Some("Login was not completed".to_string()), None)
                }
                result = complete_device_code_login(opts, device_code) => {
                    match result {
                        Ok(managed_account_id) => (true, None, Some(managed_account_id)),
                        Err(err) => (false, Some(err.to_string()), None),
                    }
                }
            };

            Self::send_chatgpt_login_completion_notifications(
                &outgoing_clone,
                config_manager,
                thread_manager,
                config,
                AccountLoginCompletedNotification {
                    login_id: Some(login_id.to_string()),
                    success,
                    error: error_msg,
                    onboarding_entrypoint: None,
                    managed_account_id,
                },
            )
            .await;

            let mut guard = active_login.lock().await;
            if guard.as_ref().map(ActiveLogin::login_id) == Some(login_id) {
                *guard = None;
            }
        });

        Ok(LoginAccountResponse::ChatgptDeviceCode {
            login_id: login_id.to_string(),
            verification_url,
            user_code,
        })
    }

    async fn cancel_login_chatgpt_common(
        &self,
        login_id: Uuid,
    ) -> std::result::Result<(), CancelLoginError> {
        let mut guard = self.active_login.lock().await;
        if guard.as_ref().map(ActiveLogin::login_id) == Some(login_id) {
            if let Some(active) = guard.take() {
                drop(active);
            }
            Ok(())
        } else {
            Err(CancelLoginError::NotFound)
        }
    }

    async fn cancel_login_response(
        &self,
        params: CancelLoginAccountParams,
    ) -> Result<CancelLoginAccountResponse, JSONRPCErrorError> {
        let login_id = params.login_id;
        let uuid = Uuid::parse_str(&login_id)
            .map_err(|_| invalid_request(format!("invalid login id: {login_id}")))?;
        let status = match self.cancel_login_chatgpt_common(uuid).await {
            Ok(()) => CancelLoginAccountStatus::Canceled,
            Err(CancelLoginError::NotFound) => CancelLoginAccountStatus::NotFound,
        };
        Ok(CancelLoginAccountResponse { status })
    }

    async fn login_chatgpt_auth_tokens(
        &self,
        request_id: ConnectionRequestId,
        access_token: String,
        chatgpt_account_id: String,
        chatgpt_plan_type: Option<String>,
    ) {
        let result = self
            .login_chatgpt_auth_tokens_response(access_token, chatgpt_account_id, chatgpt_plan_type)
            .await;
        let logged_in = result.is_ok();
        self.outgoing.send_result(request_id, result).await;

        if logged_in {
            self.send_login_success_notifications(/*login_id*/ None)
                .await;
        }
    }

    async fn login_chatgpt_auth_tokens_response(
        &self,
        access_token: String,
        chatgpt_account_id: String,
        chatgpt_plan_type: Option<String>,
    ) -> Result<LoginAccountResponse, JSONRPCErrorError> {
        if !self
            .auth_manager
            .is_login_method_allowed(ForcedLoginMethod::Chatgpt)
        {
            return Err(invalid_request(
                "External ChatGPT auth is disabled. Use API key login instead.",
            ));
        }

        // Cancel any active login attempt to avoid persisting managed auth state.
        {
            let mut guard = self.active_login.lock().await;
            if let Some(active) = guard.take() {
                drop(active);
            }
        }

        if let Some(expected_workspaces) = self.auth_manager.effective_chatgpt_workspaces()
            && !expected_workspaces.contains(&chatgpt_account_id)
        {
            return Err(invalid_request(format!(
                "External auth must use one of workspace(s) {expected_workspaces:?}, but received {chatgpt_account_id:?}.",
            )));
        }

        let auth = CodexAuth::from_external_chatgpt_tokens(
            &access_token,
            &chatgpt_account_id,
            chatgpt_plan_type.as_deref(),
        )
        .map_err(|err| internal_error(format!("failed to set external auth: {err}")))?;
        self.auth_manager
            .set_external_auth(Arc::new(ExternalAuthBridge::new(
                Arc::clone(&self.outgoing),
                auth,
            )))
            .await
            .map_err(|err| internal_error(format!("failed to set external auth: {err}")))?;
        self.config_manager.replace_cloud_config_bundle_loader(
            self.auth_manager.clone(),
            self.config.chatgpt_base_url.clone(),
            self.config.http_client_factory(),
        );
        self.config_manager
            .sync_default_client_residency_requirement()
            .await;

        Ok(LoginAccountResponse::ChatgptAuthTokens {})
    }

    async fn send_login_success_notifications(&self, login_id: Option<Uuid>) {
        Self::maybe_refresh_plugin_caches_for_current_config(
            &self.config_manager,
            &self.thread_manager,
            self.auth_manager.auth_cached(),
        )
        .await;

        let payload_login_completed = AccountLoginCompletedNotification {
            login_id: login_id.map(|id| id.to_string()),
            success: true,
            error: None,
            onboarding_entrypoint: None,
            managed_account_id: None,
        };
        self.outgoing
            .send_server_notification(ServerNotification::AccountLoginCompleted(
                payload_login_completed,
            ))
            .await;

        self.outgoing
            .send_server_notification(ServerNotification::AccountUpdated(
                self.current_account_updated_notification(),
            ))
            .await;
    }

    async fn send_chatgpt_login_completion_notifications(
        outgoing: &OutgoingMessageSender,
        config_manager: ConfigManager,
        thread_manager: Arc<ThreadManager>,
        config: Arc<Config>,
        payload_v2: AccountLoginCompletedNotification,
    ) {
        let success = payload_v2.success;
        outgoing
            .send_server_notification(ServerNotification::AccountLoginCompleted(payload_v2))
            .await;

        if success {
            let auth_manager = thread_manager.auth_manager();
            auth_manager.reload().await;
            config_manager.replace_cloud_config_bundle_loader(
                auth_manager.clone(),
                config.chatgpt_base_url.clone(),
                config.http_client_factory(),
            );
            config_manager
                .sync_default_client_residency_requirement()
                .await;

            let auth = auth_manager.auth_cached();
            Self::maybe_refresh_plugin_caches_for_current_config(
                &config_manager,
                &thread_manager,
                auth.clone(),
            )
            .await;
            let payload_v2 = AccountUpdatedNotification {
                auth_mode: auth
                    .as_ref()
                    .map(CodexAuth::api_auth_mode)
                    .map(auth_mode_to_api),
                plan_type: auth.as_ref().and_then(CodexAuth::account_plan_type),
            };
            outgoing
                .send_server_notification(ServerNotification::AccountUpdated(payload_v2))
                .await;
        }
    }

    async fn refresh_token_if_requested(&self, do_refresh: bool) {
        if self.auth_manager.is_external_chatgpt_auth_active() {
            return;
        }
        if do_refresh
            && let Err(err) = self.auth_manager.refresh_token().await
            && err.failed_reason().is_none()
        {
            tracing::warn!("failed to refresh token while getting account: {err}");
        }
    }

    async fn get_auth_status_response(
        &self,
        params: GetAuthStatusParams,
    ) -> Result<GetAuthStatusResponse, JSONRPCErrorError> {
        let include_token = params.include_token.unwrap_or(false);
        let do_refresh = params.refresh_token.unwrap_or(false);

        self.refresh_token_if_requested(do_refresh).await;

        // Determine whether auth is required based on the active model provider.
        // If a custom provider is configured with `requires_openai_auth == false`,
        // then no auth step is required; otherwise, default to requiring auth.
        let config = self.load_latest_config().await;
        let requires_openai_auth = config.model_provider.requires_openai_auth;

        let response = if !requires_openai_auth {
            GetAuthStatusResponse {
                auth_method: None,
                auth_token: None,
                requires_openai_auth: Some(false),
            }
        } else {
            let mut auth = if do_refresh {
                self.auth_manager.auth_cached()
            } else {
                self.auth_manager.auth().await
            };
            if auth.is_none() {
                self.auth_manager.reload().await;
                auth = self.auth_manager.auth_cached();
            }
            let has_managed_chatgpt_accounts = auth.is_none()
                && !self
                    .auth_manager
                    .stored_managed_chatgpt_accounts()
                    .map_err(|err| {
                        internal_error(format!("failed to read managed accounts: {err}"))
                    })?
                    .is_empty();
            match auth {
                Some(auth) => {
                    let permanent_refresh_failure =
                        self.auth_manager.refresh_failure_for_auth(&auth).is_some();
                    let auth_mode = auth_mode_to_api(auth.api_auth_mode());
                    let (reported_auth_method, token_opt) = if matches!(
                        auth,
                        CodexAuth::Headers(_)
                            | CodexAuth::AgentIdentity(_)
                            | CodexAuth::PersonalAccessToken(_)
                    ) || include_token
                        && permanent_refresh_failure
                    {
                        // This response cannot represent the metadata needed to reuse these
                        // credentials.
                        (Some(auth_mode), None)
                    } else {
                        match auth.get_token() {
                            Ok(token) if !token.is_empty() => {
                                let tok = if include_token { Some(token) } else { None };
                                (Some(auth_mode), tok)
                            }
                            Ok(_) => (None, None),
                            Err(err) => {
                                tracing::warn!("failed to get token for auth status: {err}");
                                (None, None)
                            }
                        }
                    };
                    GetAuthStatusResponse {
                        auth_method: reported_auth_method,
                        auth_token: token_opt,
                        requires_openai_auth: Some(true),
                    }
                }
                None => GetAuthStatusResponse {
                    auth_method: has_managed_chatgpt_accounts
                        .then_some(codex_app_server_protocol::AuthMode::Chatgpt),
                    auth_token: None,
                    requires_openai_auth: Some(true),
                },
            }
        };

        Ok(response)
    }

    async fn get_account_response(
        &self,
        params: GetAccountParams,
    ) -> Result<GetAccountResponse, JSONRPCErrorError> {
        let do_refresh = params.refresh_token;

        self.refresh_token_if_requested(do_refresh).await;

        let config = self.load_latest_config().await;
        let provider =
            create_model_provider(config.model_provider, Some(self.auth_manager.clone()));
        let account_state = match provider.account_state() {
            Ok(account_state) => account_state,
            Err(err) => return Err(invalid_request(err.to_string())),
        };
        let account = account_state.account.map(Account::from);

        Ok(GetAccountResponse {
            account,
            requires_openai_auth: account_state.requires_openai_auth,
        })
    }

    async fn get_account_rate_limits_response(
        &self,
    ) -> Result<GetAccountRateLimitsResponse, JSONRPCErrorError> {
        let Some(auth) = self.auth_manager.auth().await else {
            return Err(invalid_request(
                "codex account authentication required to read rate limits",
            ));
        };

        if !auth.uses_codex_backend() {
            return Err(invalid_request(
                "chatgpt authentication required to read rate limits",
            ));
        }

        let client = BackendClient::from_auth(
            self.config.chatgpt_base_url.clone(),
            &auth,
            self.config.http_client_factory(),
        );

        let (response, detailed_rate_limit_reset_credits) = tokio::join!(
            client.get_rate_limits_with_reset_credits(),
            Self::detailed_rate_limit_reset_credits(&client),
        );
        let response = response
            .map_err(|err| internal_error(format!("failed to fetch codex rate limits: {err}")))?;
        if response.rate_limits.is_empty() {
            return Err(internal_error(
                "failed to fetch codex rate limits: no snapshots returned",
            ));
        }

        let rate_limits_by_limit_id: HashMap<_, _> = response
            .rate_limits
            .iter()
            .cloned()
            .map(|snapshot| {
                let limit_id = snapshot
                    .limit_id
                    .clone()
                    .unwrap_or_else(|| "codex".to_string());
                (limit_id, snapshot)
            })
            .collect();
        let rate_limits = response
            .rate_limits
            .iter()
            .find(|snapshot| snapshot.limit_id.as_deref() == Some("codex"))
            .cloned()
            .unwrap_or_else(|| response.rate_limits[0].clone());

        let rate_limit_reset_credits = detailed_rate_limit_reset_credits.or_else(|| {
            response
                .rate_limit_reset_credits
                .map(|summary| RateLimitResetCreditsSummary {
                    available_count: summary.available_count,
                    credits: None,
                })
        });

        Ok(GetAccountRateLimitsResponse {
            rate_limits: rate_limits.into(),
            rate_limits_by_limit_id: Some(
                rate_limits_by_limit_id
                    .into_iter()
                    .map(|(limit_id, snapshot)| (limit_id, snapshot.into()))
                    .collect(),
            ),
            rate_limit_reset_credits,
        })
    }

    async fn get_account_token_usage_response(
        &self,
    ) -> Result<GetAccountTokenUsageResponse, JSONRPCErrorError> {
        let Some(auth) = self.auth_manager.auth().await else {
            return Err(invalid_request(
                "codex account authentication required to read token usage",
            ));
        };

        if !auth.uses_codex_backend() {
            return Err(invalid_request(
                "chatgpt authentication required to read token usage",
            ));
        }

        let client = BackendClient::from_auth(
            self.config.chatgpt_base_url.clone(),
            &auth,
            self.config.http_client_factory(),
        );
        let profile = tokio::time::timeout(
            ACCOUNT_TOKEN_USAGE_FETCH_TIMEOUT,
            client.get_token_usage_profile(),
        )
        .await
        .map_err(|_| internal_error("token usage profile fetch timed out"))?
        .map_err(|err| internal_error(format!("failed to fetch token usage profile: {err}")))?;
        Ok(Self::account_token_usage_response(profile))
    }

    async fn get_workspace_messages_response(
        &self,
    ) -> Result<GetWorkspaceMessagesResponse, JSONRPCErrorError> {
        let Some(auth) = self.auth_manager.auth().await else {
            return Err(invalid_request(
                "codex account authentication required to read workspace messages",
            ));
        };

        if !auth.uses_codex_backend() {
            return Err(invalid_request(
                "chatgpt authentication required to read workspace messages",
            ));
        }

        let client = BackendClient::from_auth(
            self.config.chatgpt_base_url.clone(),
            &auth,
            self.config.http_client_factory(),
        );
        let messages = tokio::time::timeout(
            ACCOUNT_WORKSPACE_MESSAGES_FETCH_TIMEOUT,
            client.list_workspace_messages(),
        )
        .await
        .map_err(|_| internal_error("workspace messages fetch timed out"))?;

        match messages {
            Ok(messages) => {
                Self::workspace_messages_response(messages, /*feature_enabled*/ true)
            }
            Err(err) if workspace_messages_feature_disabled(&err) => {
                Self::workspace_messages_response(
                    BackendWorkspaceMessagesResponse {
                        messages: Vec::new(),
                    },
                    /*feature_enabled*/ false,
                )
            }
            Err(err) => Err(internal_error(format!(
                "failed to fetch workspace messages: {err}"
            ))),
        }
    }

    fn account_token_usage_response(profile: TokenUsageProfile) -> GetAccountTokenUsageResponse {
        let stats = profile.stats;
        GetAccountTokenUsageResponse {
            summary: AccountTokenUsageSummary {
                lifetime_tokens: stats.lifetime_tokens,
                peak_daily_tokens: stats.peak_daily_tokens,
                longest_running_turn_sec: stats.longest_running_turn_sec,
                current_streak_days: stats.current_streak_days,
                longest_streak_days: stats.longest_streak_days,
            },
            daily_usage_buckets: stats.daily_usage_buckets.map(|buckets| {
                buckets
                    .into_iter()
                    .map(|bucket| AccountTokenUsageDailyBucket {
                        start_date: bucket.start_date,
                        tokens: bucket.tokens,
                    })
                    .collect()
            }),
        }
    }

    fn workspace_messages_response(
        messages: BackendWorkspaceMessagesResponse,
        feature_enabled: bool,
    ) -> Result<GetWorkspaceMessagesResponse, JSONRPCErrorError> {
        Ok(GetWorkspaceMessagesResponse {
            feature_enabled,
            messages: messages
                .messages
                .into_iter()
                .map(workspace_message_from_backend)
                .collect::<Result<Vec<_>, _>>()?,
        })
    }

    async fn send_add_credits_nudge_email_response(
        &self,
        params: SendAddCreditsNudgeEmailParams,
    ) -> Result<SendAddCreditsNudgeEmailResponse, JSONRPCErrorError> {
        self.send_add_credits_nudge_email_inner(params)
            .await
            .map(|status| SendAddCreditsNudgeEmailResponse { status })
    }

    async fn send_add_credits_nudge_email_inner(
        &self,
        params: SendAddCreditsNudgeEmailParams,
    ) -> Result<AddCreditsNudgeEmailStatus, JSONRPCErrorError> {
        let Some(auth) = self.auth_manager.auth().await else {
            return Err(invalid_request(
                "codex account authentication required to notify workspace owner",
            ));
        };

        if !auth.uses_codex_backend() {
            return Err(invalid_request(
                "chatgpt authentication required to notify workspace owner",
            ));
        }

        let client = BackendClient::from_auth(
            self.config.chatgpt_base_url.clone(),
            &auth,
            self.config.http_client_factory(),
        );

        match client
            .send_add_credits_nudge_email(Self::backend_credit_type(params.credit_type))
            .await
        {
            Ok(()) => Ok(AddCreditsNudgeEmailStatus::Sent),
            Err(err) if err.status().is_some_and(|status| status.as_u16() == 429) => {
                Ok(AddCreditsNudgeEmailStatus::CooldownActive)
            }
            Err(err) => Err(internal_error(format!(
                "failed to notify workspace owner: {err}"
            ))),
        }
    }

    fn backend_credit_type(value: AddCreditsNudgeCreditType) -> BackendAddCreditsNudgeCreditType {
        match value {
            AddCreditsNudgeCreditType::Credits => BackendAddCreditsNudgeCreditType::Credits,
            AddCreditsNudgeCreditType::UsageLimit => BackendAddCreditsNudgeCreditType::UsageLimit,
        }
    }
}

fn workspace_message_from_backend(
    message: BackendWorkspaceMessage,
) -> Result<WorkspaceMessage, JSONRPCErrorError> {
    Ok(WorkspaceMessage {
        message_id: message.message_id,
        message_type: workspace_message_type_from_backend(message.message_type),
        message_body: message.message_body,
        created_at: workspace_message_timestamp_from_backend(message.created_at)?,
        archived_at: workspace_message_timestamp_from_backend(message.archived_at)?,
    })
}

fn workspace_message_timestamp_from_backend(
    timestamp: Option<String>,
) -> Result<Option<i64>, JSONRPCErrorError> {
    timestamp
        .map(|timestamp| {
            DateTime::parse_from_rfc3339(&timestamp)
                .map(|timestamp| timestamp.timestamp())
                .map_err(|err| {
                    internal_error(format!(
                        "failed to parse workspace message timestamp `{timestamp}`: {err}"
                    ))
                })
        })
        .transpose()
}

fn workspace_message_type_from_backend(
    message_type: BackendWorkspaceMessageType,
) -> WorkspaceMessageType {
    match message_type {
        BackendWorkspaceMessageType::Headline => WorkspaceMessageType::Headline,
        BackendWorkspaceMessageType::Announcement => WorkspaceMessageType::Announcement,
        BackendWorkspaceMessageType::Unknown => WorkspaceMessageType::Unknown,
    }
}

fn workspace_messages_feature_disabled(err: &BackendRequestError) -> bool {
    err.status().is_some_and(|status| status.as_u16() == 404)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::outgoing_message::OutgoingEnvelope;
    use codex_backend_client::TokenUsageProfileDailyBucket;
    use codex_backend_client::TokenUsageProfileStats;
    use codex_protocol::protocol::RateLimitSnapshot;
    use codex_protocol::protocol::RateLimitWindow;
    use pretty_assertions::assert_eq;
    use tokio::sync::mpsc;

    #[test]
    fn account_token_usage_response_maps_profile_stats_and_daily_buckets() {
        let response = AccountRequestProcessor::account_token_usage_response(TokenUsageProfile {
            stats: TokenUsageProfileStats {
                lifetime_tokens: Some(123),
                peak_daily_tokens: Some(45),
                longest_running_turn_sec: Some(67),
                current_streak_days: Some(8),
                longest_streak_days: Some(9),
                daily_usage_buckets: Some(vec![TokenUsageProfileDailyBucket {
                    start_date: "2026-05-29".to_string(),
                    tokens: 10,
                }]),
            },
        });

        assert_eq!(
            response,
            GetAccountTokenUsageResponse {
                summary: AccountTokenUsageSummary {
                    lifetime_tokens: Some(123),
                    peak_daily_tokens: Some(45),
                    longest_running_turn_sec: Some(67),
                    current_streak_days: Some(8),
                    longest_streak_days: Some(9),
                },
                daily_usage_buckets: Some(vec![AccountTokenUsageDailyBucket {
                    start_date: "2026-05-29".to_string(),
                    tokens: 10,
                }]),
            }
        );
    }

    #[test]
    fn workspace_messages_response_maps_backend_messages() {
        let response = AccountRequestProcessor::workspace_messages_response(
            BackendWorkspaceMessagesResponse {
                messages: vec![BackendWorkspaceMessage {
                    message_id: "headline-id".to_string(),
                    message_type: BackendWorkspaceMessageType::Headline,
                    message_body: "Headline body".to_string(),
                    created_at: Some("2026-06-14T00:00:00Z".to_string()),
                    archived_at: Some("2026-06-15T00:00:00Z".to_string()),
                }],
            },
            /*feature_enabled*/ true,
        )
        .expect("workspace message timestamps should parse");

        assert_eq!(
            response,
            GetWorkspaceMessagesResponse {
                feature_enabled: true,
                messages: vec![WorkspaceMessage {
                    message_id: "headline-id".to_string(),
                    message_type: WorkspaceMessageType::Headline,
                    message_body: "Headline body".to_string(),
                    created_at: Some(1_781_395_200),
                    archived_at: Some(1_781_481_600),
                }],
            }
        );
    }

    #[test]
    fn persisted_refresh_status_maps_without_an_explicit_refresh_attempt() {
        let observed_at = DateTime::from_timestamp(1_700_000_000, 0).expect("valid timestamp");
        assert_eq!(
            AccountRequestProcessor::refresh_status_from_owner(
                ManagedChatgptRefreshStatus::TransientUnavailable { observed_at },
                None,
                observed_at,
            ),
            ManagedChatgptAccountRefreshStatus::TransientUnavailable {
                observed_at: 1_700_000_000,
            }
        );
        assert_eq!(
            AccountRequestProcessor::refresh_status_from_owner(
                ManagedChatgptRefreshStatus::ReloginRequired {
                    observed_at,
                    reason_code: Some("refresh_token_expired".to_string()),
                },
                None,
                observed_at,
            ),
            ManagedChatgptAccountRefreshStatus::ReloginRequired {
                reason_code: "refresh_token_expired".to_string(),
                observed_at: 1_700_000_000,
            }
        );
        assert_eq!(
            AccountRequestProcessor::refresh_status_from_owner(
                ManagedChatgptRefreshStatus::Healthy,
                Some(ManagedChatgptBlockKindView::AuthInvalid),
                observed_at,
            ),
            ManagedChatgptAccountRefreshStatus::ReloginRequired {
                reason_code: "auth_invalid".to_string(),
                observed_at: 1_700_000_000,
            }
        );
    }

    #[test]
    fn managed_rate_observation_uses_first_or_codex_snapshot_as_canonical() {
        let observation = managed_rate_observation(vec![
            RateLimitSnapshot {
                limit_id: None,
                limit_name: None,
                primary: Some(RateLimitWindow {
                    used_percent: 10.0,
                    window_minutes: Some(15),
                    resets_at: Some(1_700_000_000),
                }),
                secondary: None,
                credits: None,
                individual_limit: None,
                spend_control_reached: None,
                plan_type: None,
                rate_limit_reached_type: None,
            },
            RateLimitSnapshot {
                limit_id: Some("other".to_string()),
                limit_name: None,
                primary: Some(RateLimitWindow {
                    used_percent: 20.0,
                    window_minutes: Some(30),
                    resets_at: Some(1_700_000_100),
                }),
                secondary: None,
                credits: None,
                individual_limit: None,
                spend_control_reached: None,
                plan_type: None,
                rate_limit_reached_type: None,
            },
            RateLimitSnapshot {
                limit_id: Some("codex".to_string()),
                limit_name: None,
                primary: Some(RateLimitWindow {
                    used_percent: 30.0,
                    window_minutes: Some(60),
                    resets_at: Some(1_700_000_200),
                }),
                secondary: Some(RateLimitWindow {
                    used_percent: 40.0,
                    window_minutes: Some(120),
                    resets_at: Some(1_700_000_300),
                }),
                credits: None,
                individual_limit: None,
                spend_control_reached: None,
                plan_type: None,
                rate_limit_reached_type: None,
            },
        ]);

        let ManagedChatgptRateObservation::Available(windows) = observation else {
            panic!("expected available rate windows");
        };
        assert_eq!(windows.len(), 4);
        assert_eq!(windows[0].limit_id, "codex");
        assert_eq!(windows[0].kind, ManagedChatgptLimitKind::Primary);
        assert_eq!(windows[1].limit_id, "other:primary");
        assert_eq!(windows[1].kind, ManagedChatgptLimitKind::Additional);
        assert_eq!(windows[2].limit_id, "codex");
        assert_eq!(windows[2].kind, ManagedChatgptLimitKind::Primary);
        assert_eq!(windows[3].limit_id, "codex");
        assert_eq!(windows[3].kind, ManagedChatgptLimitKind::Secondary);
        assert_eq!(windows[2].window_duration_mins, Some(60));
        assert_eq!(windows[3].window_duration_mins, Some(120));
        assert_eq!(
            windows[3].reset_at.map(|reset_at| reset_at.timestamp()),
            Some(1_700_000_300)
        );
    }

    #[test]
    fn managed_rate_observation_without_actual_windows_is_unavailable() {
        let observation = managed_rate_observation(vec![RateLimitSnapshot {
            limit_id: Some("codex".to_string()),
            limit_name: None,
            primary: None,
            secondary: None,
            credits: None,
            individual_limit: None,
            spend_control_reached: None,
            plan_type: None,
            rate_limit_reached_type: None,
        }]);

        assert_eq!(
            observation,
            ManagedChatgptRateObservation::Unavailable {
                reason: "rate_limit_windows_empty".to_string(),
            }
        );
    }

    #[test]
    fn workspace_messages_feature_disabled_only_for_not_found() {
        let cases = [
            (reqwest::StatusCode::NOT_FOUND, true),
            (reqwest::StatusCode::UNAUTHORIZED, false),
            (reqwest::StatusCode::FORBIDDEN, false),
        ];

        for (status, expected) in cases {
            let err = BackendRequestError::UnexpectedStatus {
                method: "GET".to_string(),
                url: "https://example.test/api/codex/workspace-messages".to_string(),
                status,
                content_type: "application/json".to_string(),
                body: "{}".to_string(),
            };
            assert_eq!(workspace_messages_feature_disabled(&err), expected);
        }
    }

    #[test]
    fn scoped_list_reuses_core_selected_scope_before_considering_siblings() {
        let params = ListAccountsParams {
            thread_id: Some("thread-1".to_string()),
            model: Some("requested-model".to_string()),
            ..Default::default()
        };
        let core_scope = ManagedChatgptSelectionScope {
            thread_id: Some("thread-1".to_string()),
            session_id: Some("root-session-1".to_string()),
            model: Some("turn-model".to_string()),
        };
        let observed = ObservedSelection {
            scope: core_scope.clone(),
            selected_account_id: Some("email:managed-a@example.com".to_string()),
            selection_revision: 8,
            lifecycle_generation: 0,
            routes: Vec::new(),
        };

        assert_eq!(
            AccountRequestProcessor::selection_scope_from_observed(&params, Some(&observed), None,),
            ManagedChatgptSelectionScope {
                model: Some("requested-model".to_string()),
                ..core_scope
            },
            "a scoped list must reuse the core pin identity while honoring a request model override"
        );
        let configured = ManagedChatgptSelectionScope {
            thread_id: Some("thread-1".to_string()),
            session_id: Some("root-session-1".to_string()),
            model: Some("configured-model".to_string()),
        };
        let without_model_override = ListAccountsParams {
            model: None,
            ..params.clone()
        };
        assert_eq!(
            AccountRequestProcessor::selection_scope_from_observed(
                &without_model_override,
                None,
                Some(&configured),
            ),
            configured,
            "a cold observer must recover canonical session and model identity from thread metadata"
        );
        assert_eq!(
            AccountRequestProcessor::selection_scope_from_observed(&params, None, None).session_id,
            None,
            "a cold observer must not assume that a child thread id is its root session id"
        );
    }

    #[test]
    fn model_only_list_scope_is_unscoped() {
        let params = ListAccountsParams {
            model: Some("requested-model".to_string()),
            ..Default::default()
        };
        let configured = ManagedChatgptSelectionScope {
            thread_id: Some("thread-1".to_string()),
            session_id: Some("root-session-1".to_string()),
            model: Some("configured-model".to_string()),
        };

        assert_eq!(
            AccountRequestProcessor::selection_scope_from_observed(
                &params,
                None,
                Some(&configured),
            ),
            ManagedChatgptSelectionScope::default(),
            "a model without an explicit thread must not create an invisible selection pin"
        );
    }

    #[test]
    fn refresh_failure_tracks_credential_generation_not_row_revision() {
        let failure = ManagedChatgptAccountRefreshStatus::ReloginRequired {
            reason_code: "token_refresh_failed".to_string(),
            observed_at: 123,
        };
        let attempted_last_refresh = Utc::now();
        let refresh_statuses = HashMap::from([(
            "email:user@example.com".to_string(),
            (attempted_last_refresh, failure.clone()),
        )]);

        assert_eq!(
            AccountRequestProcessor::refresh_status_for_account(
                &refresh_statuses,
                "email:user@example.com",
                attempted_last_refresh,
            ),
            Some(failure),
            "a usage or lease row-revision bump must retain this list call's refresh failure"
        );

        assert_eq!(
            AccountRequestProcessor::refresh_status_for_account(
                &refresh_statuses,
                "email:user@example.com",
                attempted_last_refresh + chrono::Duration::seconds(1),
            ),
            None,
            "a relogin that replaced the attempted credentials must not inherit their failure"
        );
    }

    #[test]
    fn pool_update_coalesces_duplicate_ticks_but_emits_monotonic_empty_cutover() {
        let mut last_pool_revision = None;
        assert!(!should_emit_pool_update(&mut last_pool_revision, 0, true,));
        assert!(should_emit_pool_update(&mut last_pool_revision, 7, false,));
        assert!(!should_emit_pool_update(&mut last_pool_revision, 7, false,));
        assert!(should_emit_pool_update(&mut last_pool_revision, 8, true,));
        assert!(!should_emit_pool_update(&mut last_pool_revision, 8, true,));
    }

    #[tokio::test]
    async fn delayed_list_registration_is_rejected_after_cleanup() {
        let (tx, mut rx) = mpsc::channel(/*buffer*/ 4);
        let outgoing = Arc::new(OutgoingMessageSender::new(
            tx,
            codex_analytics::AnalyticsEventsClient::disabled(),
        ));
        let observer = AccountSelectionObserver::for_test(Arc::clone(&outgoing));
        let scope = ManagedChatgptSelectionScope {
            thread_id: Some("thread-1".to_string()),
            session_id: None,
            model: None,
        };

        observer.activate_thread("thread-1").await;
        let unsubscribed_registration = observer
            .capture_list_registration("thread-1", ConnectionId(1))
            .await;
        observer
            .remove_connection_from_thread("thread-1", ConnectionId(1))
            .await;
        assert!(
            observer
                .record_list_response(
                    unsubscribed_registration,
                    scope.clone(),
                    Some("managed-a".to_string()),
                    8,
                    SelectionNotificationRoute::for_connection(
                        Arc::clone(&outgoing),
                        ConnectionId(1),
                    ),
                )
                .await
                .is_none()
        );
        {
            let state = observer.state.lock().await;
            assert!(state.observed_selections.is_empty());
            assert!(state.route_generations.is_empty());
            assert!(state.connection_generations.is_empty());
            assert_eq!(state.lifecycle_generations.len(), 1);
        }

        let removed_thread_registration = observer
            .capture_list_registration("thread-1", ConnectionId(1))
            .await;
        observer.remove_thread("thread-1").await;
        assert!(
            observer
                .record_list_response(
                    removed_thread_registration,
                    scope,
                    Some("managed-a".to_string()),
                    8,
                    SelectionNotificationRoute::for_connection(outgoing, ConnectionId(1)),
                )
                .await
                .is_none()
        );
        assert!(observer.observed_scope_for_test("thread-1").await.is_none());
        assert!(
            rx.try_recv().is_err(),
            "cleanup must prevent both stale observer state and notifications"
        );
    }

    #[expect(
        clippy::await_holding_invalid_type,
        reason = "test holds the observer lock to verify teardown ordering"
    )]
    #[tokio::test]
    async fn thread_teardown_removes_subscriptions_before_observer_invalidation() {
        let (tx, mut rx) = mpsc::channel(/*buffer*/ 4);
        let outgoing = Arc::new(OutgoingMessageSender::new(
            tx,
            codex_analytics::AnalyticsEventsClient::disabled(),
        ));
        let observer = AccountSelectionObserver::for_test(Arc::clone(&outgoing));
        let manager = ThreadStateManager::new();
        let thread_id = ThreadId::new();
        let connection_id = ConnectionId(1);
        manager
            .connection_initialized(connection_id, ConnectionCapabilities::default())
            .await;
        manager
            .try_ensure_connection_subscribed(
                thread_id,
                connection_id,
                /*experimental_raw_events*/ false,
            )
            .await
            .expect("connection should be live");
        observer
            .activate_thread(&thread_id.to_string())
            .await
            .capture_event()
            .await
            .expect("active listener registration")
            .notify_if_changed(
                ManagedChatgptSelectionScope {
                    thread_id: Some(thread_id.to_string()),
                    session_id: None,
                    model: None,
                },
                "managed-a".to_string(),
                8,
                &ThreadScopedOutgoingMessageSender::new(outgoing, vec![connection_id], thread_id),
            )
            .await;
        rx.recv().await.expect("initial selection notification");

        let observer_state = Arc::clone(&observer.state);
        let observer_guard = observer_state.lock().await;
        let manager_for_cleanup = manager.clone();
        let observer_for_cleanup = observer.clone();
        let cleanup = tokio::spawn(async move {
            remove_thread_account_selection_state(
                &manager_for_cleanup,
                &observer_for_cleanup,
                thread_id,
            )
            .await;
        });
        tokio::time::timeout(Duration::from_secs(1), async {
            while !manager
                .subscribed_connection_ids(thread_id)
                .await
                .is_empty()
            {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("thread subscriptions must be removed before observer invalidation blocks");
        assert!(
            observer_guard
                .observed_selections
                .contains_key(&thread_id.to_string()),
            "observer invalidation is intentionally blocked by this interleaving"
        );
        drop(observer_guard);
        cleanup.await.expect("teardown task");
        assert!(
            observer
                .observed_scope_for_test(&thread_id.to_string())
                .await
                .is_none(),
            "no observer route may survive thread-state removal"
        );
    }

    #[tokio::test]
    async fn queued_selection_event_is_rejected_after_teardown_but_resume_reactivates() {
        let (tx, mut rx) = mpsc::channel(/*buffer*/ 4);
        let outgoing = Arc::new(OutgoingMessageSender::new(
            tx,
            codex_analytics::AnalyticsEventsClient::disabled(),
        ));
        let scoped_outgoing = ThreadScopedOutgoingMessageSender::new(
            Arc::clone(&outgoing),
            vec![ConnectionId(1)],
            ThreadId::new(),
        );
        let observer = AccountSelectionObserver::for_test(outgoing);
        let scope = ManagedChatgptSelectionScope {
            thread_id: Some("thread-1".to_string()),
            session_id: Some("session-1".to_string()),
            model: Some("gpt-5".to_string()),
        };

        let removed_listener = observer.activate_thread("thread-1").await;
        let queued_event = removed_listener
            .capture_event()
            .await
            .expect("active listener registration");
        observer.remove_thread("thread-1").await;
        queued_event
            .notify_if_changed(scope.clone(), "managed-a".to_string(), 8, &scoped_outgoing)
            .await;
        assert!(observer.observed_scope_for_test("thread-1").await.is_none());
        assert!(
            rx.try_recv().is_err(),
            "a queued event from the removed listener must be silent"
        );

        let resumed_listener = observer.activate_thread("thread-1").await;
        resumed_listener
            .capture_event()
            .await
            .expect("resumed listener registration")
            .notify_if_changed(scope.clone(), "managed-b".to_string(), 9, &scoped_outgoing)
            .await;
        assert_eq!(
            observer.observed_scope_for_test("thread-1").await,
            Some(scope)
        );
        assert!(
            rx.recv().await.is_some(),
            "the same persisted thread must reactivate observation after resume"
        );
    }

    #[tokio::test]
    async fn queued_selection_event_filters_unsubscribed_and_closed_connections() {
        let (tx, mut rx) = mpsc::channel(/*buffer*/ 8);
        let outgoing = Arc::new(OutgoingMessageSender::new(
            tx,
            codex_analytics::AnalyticsEventsClient::disabled(),
        ));
        let scoped_outgoing = ThreadScopedOutgoingMessageSender::new(
            Arc::clone(&outgoing),
            vec![ConnectionId(1), ConnectionId(2), ConnectionId(3)],
            ThreadId::new(),
        );
        let observer = AccountSelectionObserver::for_test(outgoing);
        let scope = ManagedChatgptSelectionScope {
            thread_id: Some("thread-1".to_string()),
            session_id: None,
            model: None,
        };
        let listener = observer.activate_thread("thread-1").await;
        let queued_event = listener
            .capture_event()
            .await
            .expect("active listener registration");

        observer
            .remove_connection_from_thread("thread-1", ConnectionId(1))
            .await;
        observer.remove_connection(ConnectionId(2)).await;
        queued_event
            .notify_if_changed(scope, "managed-a".to_string(), 8, &scoped_outgoing)
            .await;

        let OutgoingEnvelope::ToConnection { connection_id, .. } =
            rx.recv().await.expect("current connection notification")
        else {
            panic!("expected connection-scoped notification");
        };
        assert_eq!(connection_id, ConnectionId(3));
        assert!(
            rx.try_recv().is_err(),
            "stale thread and connection routes must not receive notifications"
        );
        let state = observer.state.lock().await;
        let routes = &state
            .observed_selections
            .get("thread-1")
            .expect("current route remains observed")
            .routes;
        assert_eq!(routes.len(), 1);
        assert_eq!(routes[0].connection_ids_for_test(), vec![ConnectionId(3)]);
    }

    #[tokio::test]
    async fn stale_selection_updates_do_not_mutate_or_duplicate_routes() {
        let (tx, mut rx) = mpsc::channel(/*buffer*/ 8);
        let outgoing = Arc::new(OutgoingMessageSender::new(
            tx,
            codex_analytics::AnalyticsEventsClient::disabled(),
        ));
        let scoped_outgoing = ThreadScopedOutgoingMessageSender::new(
            Arc::clone(&outgoing),
            vec![ConnectionId(1), ConnectionId(2)],
            ThreadId::new(),
        );
        let observer = AccountSelectionObserver::for_test(Arc::clone(&outgoing));
        let scope = ManagedChatgptSelectionScope {
            thread_id: Some("thread-1".to_string()),
            session_id: None,
            model: None,
        };
        let listener = observer.activate_thread("thread-1").await;
        let event_route = listener
            .capture_event()
            .await
            .expect("active listener registration");
        event_route
            .notify_if_changed(scope.clone(), "managed-a".to_string(), 8, &scoped_outgoing)
            .await;
        rx.recv()
            .await
            .expect("initial notification for connection 1");
        rx.recv()
            .await
            .expect("initial notification for connection 2");

        event_route
            .notify_if_changed(scope.clone(), "stale".to_string(), 7, &scoped_outgoing)
            .await;
        let equal_list_registration = observer
            .capture_list_registration("thread-1", ConnectionId(1))
            .await;
        assert!(
            observer
                .record_list_response(
                    equal_list_registration,
                    scope.clone(),
                    Some("managed-a".to_string()),
                    8,
                    SelectionNotificationRoute::for_connection(
                        Arc::clone(&outgoing),
                        ConnectionId(1),
                    ),
                )
                .await
                .is_none()
        );
        {
            let state = observer.state.lock().await;
            let routes = &state
                .observed_selections
                .get("thread-1")
                .expect("observed selection")
                .routes;
            assert_eq!(routes.len(), 1);
            assert_eq!(
                routes[0].connection_ids_for_test(),
                vec![ConnectionId(1), ConnectionId(2)]
            );
        }

        listener
            .capture_event()
            .await
            .expect("current listener registration")
            .notify_if_changed(scope, "managed-b".to_string(), 9, &scoped_outgoing)
            .await;
        let mut connection_ids = Vec::new();
        for _ in 0..2 {
            let OutgoingEnvelope::ToConnection { connection_id, .. } =
                rx.recv().await.expect("newer selection notification")
            else {
                panic!("expected connection-scoped notification");
            };
            connection_ids.push(connection_id);
        }
        connection_ids.sort_by_key(|connection_id| connection_id.0);
        assert_eq!(connection_ids, vec![ConnectionId(1), ConnectionId(2)]);
        assert!(
            rx.try_recv().is_err(),
            "each connection must receive the newer selection exactly once"
        );
    }

    #[tokio::test]
    async fn list_registration_survives_sibling_cleanup_and_catches_up_stale_response() {
        let (tx, mut rx) = mpsc::channel(/*buffer*/ 8);
        let outgoing = Arc::new(OutgoingMessageSender::new(
            tx,
            codex_analytics::AnalyticsEventsClient::disabled(),
        ));
        let observer = AccountSelectionObserver::for_test(Arc::clone(&outgoing));
        let scope = ManagedChatgptSelectionScope {
            thread_id: Some("thread-1".to_string()),
            session_id: None,
            model: None,
        };
        let listener = observer.activate_thread("thread-1").await;
        listener
            .capture_event()
            .await
            .expect("active listener registration")
            .notify_if_changed(
                scope.clone(),
                "managed-current".to_string(),
                9,
                &ThreadScopedOutgoingMessageSender::new(
                    Arc::clone(&outgoing),
                    vec![ConnectionId(1)],
                    ThreadId::new(),
                ),
            )
            .await;
        rx.recv().await.expect("initial notification");

        let connection_two = observer
            .capture_list_registration("thread-1", ConnectionId(2))
            .await;
        observer
            .remove_connection_from_thread("thread-1", ConnectionId(1))
            .await;
        observer.remove_connection(ConnectionId(1)).await;
        let (catch_up, routes) = observer
            .record_list_response(
                connection_two,
                scope.clone(),
                Some("managed-stale".to_string()),
                8,
                SelectionNotificationRoute::for_connection(Arc::clone(&outgoing), ConnectionId(2)),
            )
            .await
            .expect("sibling cleanup must not invalidate connection two");
        assert_eq!(
            catch_up.selected_account_id.as_deref(),
            Some("managed-current")
        );
        assert_eq!(catch_up.selection_revision, 9);
        assert_eq!(routes.len(), 1);
        assert_eq!(routes[0].connection_ids_for_test(), vec![ConnectionId(2)]);

        let connection_three = observer
            .capture_list_registration("thread-1", ConnectionId(3))
            .await;
        assert!(
            observer
                .record_list_response(
                    connection_three,
                    scope,
                    Some("managed-current".to_string()),
                    9,
                    SelectionNotificationRoute::for_connection(outgoing, ConnectionId(3)),
                )
                .await
                .is_none(),
            "an equal response registers the route without replaying the same revision"
        );
        let state = observer.state.lock().await;
        let routes = &state
            .observed_selections
            .get("thread-1")
            .expect("observed selection")
            .routes;
        let mut connection_ids = routes
            .iter()
            .flat_map(SelectionNotificationRoute::connection_ids_for_test)
            .collect::<Vec<_>>();
        connection_ids.sort_by_key(|connection_id| connection_id.0);
        assert_eq!(connection_ids, vec![ConnectionId(2), ConnectionId(3)]);
    }

    #[tokio::test]
    async fn blocked_targeted_send_is_cancelled_before_unsubscribe_returns() {
        let (tx, mut rx) = mpsc::channel(/*buffer*/ 1);
        let capacity_probe = tx.clone();
        let outgoing = Arc::new(OutgoingMessageSender::new(
            tx,
            codex_analytics::AnalyticsEventsClient::disabled(),
        ));
        let observer = AccountSelectionObserver::for_test(Arc::clone(&outgoing));
        let scope = ManagedChatgptSelectionScope {
            thread_id: Some("thread-1".to_string()),
            session_id: None,
            model: None,
        };
        let event_observer = observer.activate_thread("thread-1").await;
        let registration = observer
            .capture_event_registration(&event_observer)
            .await
            .expect("active event registration");
        let (notification, routes) = observer
            .record_if_changed(
                registration,
                scope,
                Some("managed-a".to_string()),
                8,
                SelectionNotificationRoute::from_thread(&ThreadScopedOutgoingMessageSender::new(
                    Arc::clone(&outgoing),
                    vec![ConnectionId(1), ConnectionId(2)],
                    ThreadId::new(),
                )),
            )
            .await
            .expect("new selection should record both targets");

        let send = tokio::spawn({
            let route = routes[0].clone();
            async move { route.send(notification).await }
        });
        tokio::time::timeout(Duration::from_secs(1), async {
            while capacity_probe.capacity() != 0 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("first target must fill the bounded channel");
        assert!(!send.is_finished(), "second target must be blocked");

        observer
            .remove_connection_from_thread("thread-1", ConnectionId(2))
            .await;
        tokio::time::timeout(Duration::from_secs(1), send)
            .await
            .expect("invalidating the blocked target must release the send")
            .expect("send task");

        let OutgoingEnvelope::ToConnection { connection_id, .. } =
            rx.recv().await.expect("first target notification")
        else {
            panic!("expected connection-scoped notification");
        };
        assert_eq!(connection_id, ConnectionId(1));
        assert!(
            rx.try_recv().is_err(),
            "the invalidated blocked target must never enter the channel"
        );
    }

    #[tokio::test]
    async fn list_capture_does_not_allocate_and_same_id_recreation_stays_stale() {
        let (tx, _rx) = mpsc::channel(/*buffer*/ 4);
        let outgoing = Arc::new(OutgoingMessageSender::new(
            tx,
            codex_analytics::AnalyticsEventsClient::disabled(),
        ));
        let observer = AccountSelectionObserver::for_test(Arc::clone(&outgoing));

        for id in 0..128 {
            observer
                .capture_list_registration(&format!("arbitrary-thread-{id}"), ConnectionId(id))
                .await;
        }
        {
            let state = observer.state.lock().await;
            assert_eq!(state.next_generation, 1);
            assert!(state.lifecycle_generations.is_empty());
            assert!(state.route_generations.is_empty());
            assert!(state.connection_generations.is_empty());
            assert!(state.observed_selections.is_empty());
        }

        let stale_scope = ManagedChatgptSelectionScope {
            thread_id: Some("thread-0".to_string()),
            session_id: None,
            model: None,
        };
        observer.activate_thread("thread-0").await;
        let stale_registration = observer
            .capture_list_registration("thread-0", ConnectionId(0))
            .await;
        for id in 1..128 {
            observer
                .capture_list_registration("thread-0", ConnectionId(id))
                .await;
        }
        {
            let state = observer.state.lock().await;
            assert_eq!(state.lifecycle_generations.len(), 1);
            assert!(state.route_generations.is_empty());
            assert!(state.connection_generations.is_empty());
            assert!(state.observed_selections.is_empty());
        }

        observer.remove_thread("thread-0").await;
        observer.activate_thread("thread-0").await;
        let recreated = observer
            .capture_list_registration("thread-0", ConnectionId(0))
            .await;
        assert_ne!(
            stale_registration.lifecycle_generation,
            recreated.lifecycle_generation
        );
        assert!(
            observer
                .record_list_response(
                    stale_registration,
                    stale_scope,
                    Some("managed-stale".to_string()),
                    8,
                    SelectionNotificationRoute::for_connection(outgoing, ConnectionId(0)),
                )
                .await
                .is_none(),
            "a captured registration must remain stale after same-ID recreation"
        );
    }

    #[tokio::test]
    async fn saturated_pool_update_send_exits_on_shutdown() {
        let (tx, mut rx) = mpsc::channel(/*buffer*/ 1);
        let outgoing = Arc::new(OutgoingMessageSender::new(
            tx,
            codex_analytics::AnalyticsEventsClient::disabled(),
        ));
        let first_shutdown = CancellationToken::new();
        assert!(
            send_pool_update_unless_shutdown(
                &outgoing,
                &first_shutdown,
                AccountPoolUpdatedNotification {
                    accounts: Vec::new(),
                    pool_revision: 1,
                },
            )
            .await
        );

        let shutdown = CancellationToken::new();
        let blocked_outgoing = Arc::clone(&outgoing);
        let blocked_shutdown = shutdown.clone();
        let blocked = tokio::spawn(async move {
            send_pool_update_unless_shutdown(
                &blocked_outgoing,
                &blocked_shutdown,
                AccountPoolUpdatedNotification {
                    accounts: Vec::new(),
                    pool_revision: 2,
                },
            )
            .await
        });
        tokio::task::yield_now().await;
        shutdown.cancel();
        assert!(
            !tokio::time::timeout(Duration::from_secs(1), blocked)
                .await
                .expect("blocked pool send must stop on shutdown")
                .expect("pool send task must not panic")
        );
        assert!(rx.recv().await.is_some());
        assert!(
            rx.try_recv().is_err(),
            "cancelled pool update must not enter the saturated channel"
        );
    }

    #[test]
    fn pool_update_watcher_shutdown_cancels_when_last_owner_drops() {
        let token = CancellationToken::new();
        let shutdown = Arc::new(PoolUpdateWatcherShutdown(token.clone()));
        let second_owner = Arc::clone(&shutdown);
        drop(shutdown);
        assert!(!token.is_cancelled());
        drop(second_owner);
        assert!(token.is_cancelled());
    }
}
