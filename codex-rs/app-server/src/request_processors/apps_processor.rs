use super::*;
use crate::app_info::app_info_to_api;
use codex_connectors::AppToolPolicyEvaluator;

mod installed;
mod read;

pub(super) use read::APP_READ_MAX_IDS;

pub(crate) struct AppsRequestProcessor {
    auth_manager: Arc<AuthManager>,
    thread_manager: Arc<ThreadManager>,
    outgoing: Arc<OutgoingMessageSender>,
    config_manager: ConfigManager,
    workspace_settings_cache: Arc<workspace_settings::WorkspaceSettingsCache>,
    shutdown_token: CancellationToken,
    _shutdown_drop_guard: DropGuard,
}

impl AppsRequestProcessor {
    pub(crate) fn new(
        auth_manager: Arc<AuthManager>,
        thread_manager: Arc<ThreadManager>,
        outgoing: Arc<OutgoingMessageSender>,
        config_manager: ConfigManager,
        workspace_settings_cache: Arc<workspace_settings::WorkspaceSettingsCache>,
        shutdown_token: CancellationToken,
    ) -> Self {
        let shutdown_drop_guard = shutdown_token.clone().drop_guard();
        Self {
            auth_manager,
            thread_manager,
            outgoing,
            config_manager,
            workspace_settings_cache,
            shutdown_token,
            _shutdown_drop_guard: shutdown_drop_guard,
        }
    }

    pub(crate) async fn apps_list(
        &self,
        request_id: &ConnectionRequestId,
        params: AppsListParams,
    ) -> Result<Option<ClientResponsePayload>, JSONRPCErrorError> {
        self.apps_list_inner(request_id, params)
            .await
            .map(|response| response.map(Into::into))
    }

    async fn apps_list_inner(
        &self,
        request_id: &ConnectionRequestId,
        params: AppsListParams,
    ) -> Result<Option<AppsListResponse>, JSONRPCErrorError> {
        let installed_start = Instant::now();
        let reload = params.force_refetch;
        let thread = if let Some(thread_id) = params.thread_id.as_deref() {
            let (_, loaded_thread) = self.load_thread(thread_id).await?;
            Some(loaded_thread)
        } else {
            None
        };
        let fallback_cwd = match thread.as_ref() {
            Some(thread) => Some(thread.config_snapshot().await.cwd().to_path_buf()),
            None => None,
        };
        let mut config = self.load_latest_config(fallback_cwd).await?;

        if let Some(thread) = thread.as_ref() {
            let _ = config
                .features
                .set_enabled(Feature::Apps, thread.enabled(Feature::Apps));
        }
        let scoped_runtime = match thread.as_ref() {
            Some(thread) => Some(thread.current_runtime_snapshot().await.map_err(|err| {
                internal_error(format!("failed to capture thread runtime: {err}"))
            })?),
            None => None,
        };
        if let Some(snapshot) = scoped_runtime.as_ref() {
            config.chatgpt_base_url = snapshot.mcp.config().chatgpt_base_url.clone();
            config.apps_mcp_product_sku = snapshot.mcp.config().apps_mcp_product_sku.clone();
        }
        let (auth, directory_cache_key) = match scoped_runtime.as_ref() {
            Some(snapshot) => {
                let auth = snapshot.effective_auth.clone();
                let cache_key = snapshot.connector_directory_cache_key.clone();
                (auth, cache_key)
            }
            None => {
                self.threadless_auth_and_connector_directory_cache_key(&config.chatgpt_base_url)
                    .await?
            }
        };
        let scoped_mcp_runtime = scoped_runtime.map(|snapshot| snapshot.mcp);
        if !config
            .features
            .apps_enabled_for_auth(auth.as_ref().is_some_and(CodexAuth::uses_codex_backend))
        {
            let response = AppsListResponse {
                data: Vec::new(),
                next_cursor: None,
            };
            record_legacy_apps_installed_duration(installed_start, reload);
            return Ok(Some(response));
        }

        if !self
            .workspace_codex_plugins_enabled(&config, auth.as_ref())
            .await
        {
            let response = AppsListResponse {
                data: Vec::new(),
                next_cursor: None,
            };
            record_legacy_apps_installed_duration(installed_start, reload);
            return Ok(Some(response));
        }

        if scoped_mcp_runtime.is_some() && directory_cache_key.is_none() {
            return Err(internal_error(
                "thread-scoped apps/list requires an exact connector cache binding",
            ));
        }

        let request = request_id.clone();
        let outgoing = Arc::clone(&self.outgoing);
        let mcp_manager = scoped_mcp_runtime
            .is_none()
            .then(|| self.thread_manager.mcp_manager());
        let environment_manager = self.thread_manager.environment_manager();
        let plugins_manager = self.thread_manager.plugins_manager();
        let shutdown_token = self.shutdown_token.child_token();
        tokio::spawn(async move {
            tokio::select! {
                _ = shutdown_token.cancelled() => {}
                _ = Self::apps_list_task(
                    outgoing,
                    request,
                    params,
                    config,
                    environment_manager,
                    mcp_manager,
                    plugins_manager,
                    auth,
                    scoped_mcp_runtime,
                    directory_cache_key,
                    installed_start,
                ) => {}
            }
        });
        Ok(None)
    }

    pub(crate) fn shutdown(&self) {
        self.shutdown_token.cancel();
    }

    #[allow(clippy::too_many_arguments)]
    async fn apps_list_task(
        outgoing: Arc<OutgoingMessageSender>,
        request_id: ConnectionRequestId,
        params: AppsListParams,
        config: Config,
        environment_manager: Arc<EnvironmentManager>,
        mcp_manager: Option<Arc<McpManager>>,
        plugins_manager: Arc<PluginsManager>,
        auth: Option<CodexAuth>,
        scoped_mcp_runtime: Option<Arc<codex_mcp::McpBinding>>,
        directory_cache_key: Option<ConnectorDirectoryCacheKey>,
        installed_start: Instant,
    ) {
        let reload = params.force_refetch;
        let retry_params = params.clone();
        let retry_config = config.clone();
        let retry_environment_manager = Arc::clone(&environment_manager);
        let retry_mcp_manager = mcp_manager.clone();
        let retry_plugins_manager = Arc::clone(&plugins_manager);
        let retry_auth = auth.clone();
        let retry_scoped_mcp_runtime = scoped_mcp_runtime.clone();
        let retry_directory_cache_key = directory_cache_key.clone();
        let result = Self::apps_list_response(
            &outgoing,
            params,
            config,
            environment_manager,
            mcp_manager,
            plugins_manager,
            auth,
            scoped_mcp_runtime,
            directory_cache_key,
        )
        .await;
        if result.is_ok() {
            record_legacy_apps_installed_duration(installed_start, reload);
        }
        let should_retry = result
            .as_ref()
            .is_ok_and(|(_, codex_apps_ready)| !codex_apps_ready);
        outgoing
            .send_result(request_id, result.map(|(response, _)| response))
            .await;

        if should_retry && !retry_params.force_refetch {
            let mut retry_params = retry_params;
            retry_params.force_refetch = true;
            if let Err(err) = Self::apps_list_response(
                &outgoing,
                retry_params,
                retry_config,
                retry_environment_manager,
                retry_mcp_manager,
                retry_plugins_manager,
                retry_auth,
                retry_scoped_mcp_runtime,
                retry_directory_cache_key,
            )
            .await
            {
                warn!("failed to refresh app list after codex-apps readiness retry: {err:?}");
            }
        }
    }

    async fn apps_list_response(
        outgoing: &Arc<OutgoingMessageSender>,
        params: AppsListParams,
        config: Config,
        environment_manager: Arc<EnvironmentManager>,
        mcp_manager: Option<Arc<McpManager>>,
        plugins_manager: Arc<PluginsManager>,
        auth: Option<CodexAuth>,
        scoped_mcp_runtime: Option<Arc<codex_mcp::McpBinding>>,
        directory_cache_key: Option<ConnectorDirectoryCacheKey>,
    ) -> Result<(AppsListResponse, bool), JSONRPCErrorError> {
        let AppsListParams {
            cursor,
            limit,
            thread_id: _,
            force_refetch,
        } = params;
        let start = match cursor {
            Some(cursor) => match cursor.parse::<usize>() {
                Ok(idx) => idx,
                Err(_) => return Err(invalid_request(format!("invalid cursor: {cursor}"))),
            },
            None => 0,
        };

        let loaded_plugins = plugins_manager
            .plugins_for_config(&config.plugins_config_input())
            .await;
        let connector_snapshot =
            codex_connectors::ConnectorSnapshot::from_plugin_capability_summaries(
                loaded_plugins.capability_summaries(),
            );
        let plugin_apps = connector_snapshot.connector_ids().to_vec();
        let (mut accessible_connectors, mut all_connectors) = if scoped_mcp_runtime.is_some() {
            let all_connectors =
                auth.as_ref()
                    .zip(directory_cache_key.clone())
                    .and_then(|(auth, cache_key)| {
                        connectors::list_cached_all_connectors_with_auth(
                            &config,
                            auth,
                            cache_key,
                            &plugin_apps,
                        )
                    });
            (None, all_connectors)
        } else {
            tokio::join!(
                connectors::list_cached_accessible_connectors_from_mcp_tools(&config),
                connectors::list_cached_all_connectors(&config, &plugin_apps)
            )
        };
        let cached_all_connectors = all_connectors.clone();

        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();

        let accessible_config = config.clone();
        let accessible_directory_cache_key = directory_cache_key.clone();
        let accessible_tx = tx.clone();
        tokio::spawn(async move {
            let result = match scoped_mcp_runtime {
                Some(runtime) => {
                    codex_core::connectors::list_accessible_connectors_from_mcp_runtime(
                        runtime.as_ref(),
                        accessible_directory_cache_key
                            .expect("thread-scoped runtime has an exact connector cache binding"),
                        force_refetch,
                    )
                    .await
                }
                None => match mcp_manager {
                    Some(mcp_manager) => {
                        connectors::list_accessible_connectors_from_mcp_tools_with_mcp_manager(
                            &accessible_config,
                            force_refetch,
                            Arc::clone(&environment_manager),
                            mcp_manager,
                        )
                        .await
                    }
                    None => Err(anyhow::anyhow!(
                        "legacy apps/list requires the ambient MCP manager"
                    )),
                },
            }
            .map_err(|err| format!("failed to load accessible apps: {err}"));
            let _ = accessible_tx.send(AppListLoadResult::Accessible(result));
        });

        let all_config = config.clone();
        let all_plugin_apps = plugin_apps.clone();
        tokio::spawn(async move {
            let result = match (auth.as_ref(), directory_cache_key) {
                (Some(auth), Some(cache_key)) => {
                    connectors::list_all_connectors_with_auth(
                        &all_config,
                        auth,
                        cache_key,
                        force_refetch,
                        &all_plugin_apps,
                    )
                    .await
                }
                _ => {
                    connectors::list_all_connectors_with_options(
                        &all_config,
                        force_refetch,
                        &all_plugin_apps,
                    )
                    .await
                }
            }
            .map_err(|err| format!("failed to list apps: {err}"));
            let _ = tx.send(AppListLoadResult::Directory(result));
        });

        let app_list_deadline = tokio::time::Instant::now() + APP_LIST_LOAD_TIMEOUT;
        let mut accessible_loaded = false;
        let mut all_loaded = false;
        let mut codex_apps_ready = true;
        let mut last_notified_apps = None;
        let mut sent_app_list_update = false;
        let app_policy = AppToolPolicyEvaluator::new(&config.config_layer_stack);

        if accessible_connectors.is_some() || all_connectors.is_some() {
            let merged = app_policy.apply_app_enabled_state(merge_loaded_apps(
                all_connectors.as_deref(),
                accessible_connectors.as_deref(),
            ));
            if !force_refetch {
                last_notified_apps = Some(merged);
            } else if should_send_app_list_updated_notification(
                merged.as_slice(),
                accessible_loaded,
                all_loaded,
            ) {
                send_app_list_updated_notification(outgoing, merged.clone()).await;
                last_notified_apps = Some(merged);
                sent_app_list_update = true;
            }
        }

        loop {
            let result = match tokio::time::timeout_at(app_list_deadline, rx.recv()).await {
                Ok(Some(result)) => result,
                Ok(None) => {
                    return Err(internal_error("failed to load app lists"));
                }
                Err(_) => {
                    let timeout_seconds = APP_LIST_LOAD_TIMEOUT.as_secs();
                    return Err(internal_error(format!(
                        "timed out waiting for app lists after {timeout_seconds} seconds"
                    )));
                }
            };

            match result {
                AppListLoadResult::Accessible(Ok(status)) => {
                    accessible_connectors = Some(status.connectors);
                    accessible_loaded = true;
                    codex_apps_ready = status.codex_apps_ready;
                }
                AppListLoadResult::Accessible(Err(err)) => {
                    return Err(internal_error(err));
                }
                AppListLoadResult::Directory(Ok(connectors)) => {
                    all_connectors = Some(connectors);
                    all_loaded = true;
                }
                AppListLoadResult::Directory(Err(err)) => {
                    return Err(internal_error(err));
                }
            }

            let showing_interim_force_refetch = force_refetch && !(accessible_loaded && all_loaded);
            let all_connectors_for_update =
                if showing_interim_force_refetch && cached_all_connectors.is_some() {
                    cached_all_connectors.as_deref()
                } else {
                    all_connectors.as_deref()
                };
            let accessible_connectors_for_update =
                if showing_interim_force_refetch && !accessible_loaded {
                    None
                } else {
                    accessible_connectors.as_deref()
                };
            let merged = app_policy.apply_app_enabled_state(merge_loaded_apps(
                all_connectors_for_update,
                accessible_connectors_for_update,
            ));
            if should_send_app_list_updated_notification(
                merged.as_slice(),
                accessible_loaded,
                all_loaded,
            ) && (last_notified_apps.as_ref() != Some(&merged)
                || (!force_refetch
                    && start == 0
                    && accessible_loaded
                    && all_loaded
                    && !sent_app_list_update))
            {
                send_app_list_updated_notification(outgoing, merged.clone()).await;
                last_notified_apps = Some(merged.clone());
                sent_app_list_update = true;
            }

            if accessible_loaded && all_loaded {
                let response = paginate_apps(merged.as_slice(), start, limit)?;
                return Ok((response, codex_apps_ready));
            }
        }
    }

    async fn load_thread(
        &self,
        thread_id: &str,
    ) -> Result<(ThreadId, Arc<CodexThread>), JSONRPCErrorError> {
        let thread_id = ThreadId::from_string(thread_id)
            .map_err(|err| invalid_request(format!("invalid thread id: {err}")))?;

        let thread = self
            .thread_manager
            .get_thread(thread_id)
            .await
            .map_err(|_| invalid_request(format!("thread not found: {thread_id}")))?;

        Ok((thread_id, thread))
    }

    async fn threadless_auth_and_connector_directory_cache_key(
        &self,
        chatgpt_base_url: &str,
    ) -> Result<(Option<CodexAuth>, Option<ConnectorDirectoryCacheKey>), JSONRPCErrorError> {
        let managed_snapshot = self
            .auth_manager
            .managed_chatgpt_auth_snapshot(&codex_login::ManagedChatgptSelectionScope::default())
            .await
            .map_err(|err| {
                internal_error(format!(
                    "failed to resolve threadless managed account snapshot: {err}"
                ))
            })?;
        if let Some(snapshot) = managed_snapshot {
            let cache_key = ConnectorDirectoryCacheKey::from_transport_binding(
                chatgpt_base_url.to_string(),
                snapshot.transport,
                snapshot.account_revision,
                snapshot.auth.is_workspace_account(),
            );
            return Ok((Some(snapshot.auth), Some(cache_key)));
        }

        let auth = self.auth_manager.auth().await;
        let cache_key = auth.as_ref().map(|auth| {
            ConnectorDirectoryCacheKey::new(
                chatgpt_base_url.to_string(),
                auth.get_account_id(),
                auth.get_chatgpt_user_id(),
                auth.is_workspace_account(),
            )
        });
        Ok((auth, cache_key))
    }

    async fn load_latest_config(
        &self,
        fallback_cwd: Option<PathBuf>,
    ) -> Result<Config, JSONRPCErrorError> {
        self.config_manager
            .load_latest_config(fallback_cwd)
            .await
            .map_err(|err| internal_error(format!("failed to reload config: {err}")))
    }

    async fn workspace_codex_plugins_enabled(
        &self,
        config: &Config,
        auth: Option<&CodexAuth>,
    ) -> bool {
        match workspace_settings::codex_plugins_enabled_for_workspace(
            config,
            auth,
            Some(&self.workspace_settings_cache),
        )
        .await
        {
            Ok(enabled) => enabled,
            Err(err) => {
                warn!(
                    "failed to fetch workspace Codex plugins setting; allowing Codex plugins: {err:#}"
                );
                true
            }
        }
    }
}

const APP_LIST_LOAD_TIMEOUT: Duration = Duration::from_secs(90);
// `app/list` is the legacy request-path baseline for the `app/installed` endpoint;
// `path=legacy` keeps it separate from the new snapshot-backed implementation in dashboards.
const APPS_INSTALLED_DURATION_METRIC: &str = "codex.apps.installed.duration_ms";

fn record_legacy_apps_installed_duration(started_at: Instant, reload: bool) {
    let reload = if reload { "true" } else { "false" };
    if let Some(metrics) = codex_otel::global() {
        let _ = metrics.record_duration(
            APPS_INSTALLED_DURATION_METRIC,
            started_at.elapsed(),
            &[("path", "legacy"), ("reload", reload)],
        );
    }
}
enum AppListLoadResult {
    Accessible(Result<AccessibleConnectorsStatus, String>),
    Directory(Result<Vec<AppInfo>, String>),
}

fn merge_loaded_apps(
    all_connectors: Option<&[AppInfo]>,
    accessible_connectors: Option<&[AppInfo]>,
) -> Vec<AppInfo> {
    let all_connectors_loaded = all_connectors.is_some();
    let all = all_connectors.map_or_else(Vec::new, <[AppInfo]>::to_vec);
    let accessible = accessible_connectors.map_or_else(Vec::new, <[AppInfo]>::to_vec);
    connectors::merge_connectors_with_accessible(all, accessible, all_connectors_loaded)
}

fn should_send_app_list_updated_notification(
    connectors: &[AppInfo],
    accessible_loaded: bool,
    all_loaded: bool,
) -> bool {
    connectors.iter().any(|connector| connector.is_accessible) || (accessible_loaded && all_loaded)
}

fn paginate_apps(
    connectors: &[AppInfo],
    start: usize,
    limit: Option<u32>,
) -> Result<AppsListResponse, JSONRPCErrorError> {
    let total = connectors.len();
    if start > total {
        return Err(invalid_request(format!(
            "cursor {start} exceeds total apps {total}"
        )));
    }

    let effective_limit = limit.unwrap_or(total as u32).max(1) as usize;
    let end = start.saturating_add(effective_limit).min(total);
    let data = connectors[start..end]
        .iter()
        .cloned()
        .map(app_info_to_api)
        .collect();
    let next_cursor = if end < total {
        Some(end.to_string())
    } else {
        None
    };

    Ok(AppsListResponse { data, next_cursor })
}

async fn send_app_list_updated_notification(
    outgoing: &Arc<OutgoingMessageSender>,
    data: Vec<AppInfo>,
) {
    let data = data.into_iter().map(app_info_to_api).collect();
    outgoing
        .send_server_notification(ServerNotification::AppListUpdated(
            AppListUpdatedNotification { data },
        ))
        .await;
}
