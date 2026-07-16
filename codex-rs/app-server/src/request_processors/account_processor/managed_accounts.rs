use super::*;
use chrono::DateTime;
use chrono::Utc;
use codex_model_provider::BearerAuthProvider;

pub(super) type RefreshStatusByIdentity =
    HashMap<String, (DateTime<Utc>, ManagedChatgptAccountRefreshStatus)>;

impl AccountRequestProcessor {
    async fn logout_common(
        &self,
        params: Option<LogoutAccountParams>,
    ) -> Result<LogoutAccountResponse, JSONRPCErrorError> {
        let managed_bedrock_auth = matches!(
            self.auth_manager.auth_cached(),
            Some(CodexAuth::BedrockApiKey(_))
        );
        let config = self.load_latest_config().await;
        if config.model_provider.is_amazon_bedrock() && !managed_bedrock_auth {
            return Err(invalid_request(
                "cannot log out while Amazon Bedrock is using AWS-managed credentials; manage those credentials through AWS or switch model providers before logging out Codex authentication",
            ));
        }

        if params
            .as_ref()
            .is_some_and(|params| params.all && params.account_id.is_some())
        {
            return Err(invalid_request(
                "account/logout accepts either accountId or all, not both",
            ));
        }

        if params
            .as_ref()
            .is_none_or(|params| params.account_id.is_none())
        {
            let mut guard = self.active_login.lock().await;
            if let Some(active) = guard.take() {
                drop(active);
            }
        }

        let listed_accounts = match params.as_ref() {
            Some(LogoutAccountParams {
                account_id: Some(_),
                all: false,
            }) => Some(
                self.auth_manager
                    .stored_managed_chatgpt_account_list()
                    .map_err(|err| internal_error(format!("logout failed: {err}")))?
                    .accounts,
            ),
            Some(LogoutAccountParams {
                account_id: None,
                all: false,
            })
            | None
                if !self.auth_manager.is_external_chatgpt_auth_active() =>
            {
                Some(
                    self.auth_manager
                        .list_managed_chatgpt_accounts(&ManagedChatgptSelectionScope::default())
                        .await
                        .map_err(|err| internal_error(format!("logout failed: {err}")))?
                        .accounts,
                )
            }
            _ => None,
        };

        let mut removed_account_ids = Vec::new();
        match params {
            Some(LogoutAccountParams {
                account_id: Some(account_id),
                all: false,
            }) => {
                let selector = account_id.trim();
                let normalized_selector = selector.to_lowercase();
                let canonical_id = listed_accounts
                    .as_ref()
                    .ok_or_else(|| internal_error("managed account list was not loaded"))?
                    .iter()
                    .find(|account| {
                        account.identity_key.trim() == selector
                            || account
                                .identity_aliases
                                .iter()
                                .any(|alias| alias.trim() == selector)
                            || account.chatgpt_account_id.as_deref().map(str::trim)
                                == Some(selector)
                            || account.normalized_email.as_deref()
                                == Some(normalized_selector.as_str())
                    })
                    .map(|account| account.identity_key.clone())
                    .unwrap_or_else(|| selector.to_string());
                if self
                    .auth_manager
                    .remove_managed_chatgpt_account(selector)
                    .await
                    .map_err(|err| internal_error(format!("logout failed: {err}")))?
                {
                    removed_account_ids.push(canonical_id);
                }
            }
            Some(LogoutAccountParams {
                account_id: None,
                all: true,
            }) => {
                removed_account_ids = self
                    .auth_manager
                    .logout_all_managed_chatgpt()
                    .await
                    .map_err(|err| internal_error(format!("logout failed: {err}")))?;
            }
            Some(LogoutAccountParams {
                account_id: None,
                all: false,
            })
            | None => {
                if self.auth_manager.is_external_chatgpt_auth_active() {
                    self.auth_manager
                        .logout_with_revoke()
                        .await
                        .map_err(|err| internal_error(format!("logout failed: {err}")))?;
                } else {
                    let accounts = listed_accounts
                        .as_ref()
                        .ok_or_else(|| internal_error("managed account list was not loaded"))?;
                    match accounts.as_slice() {
                        [] => {
                            self.auth_manager
                                .logout_with_revoke()
                                .await
                                .map_err(|err| internal_error(format!("logout failed: {err}")))?;
                        }
                        [account] => {
                            let identity = account.identity_key.clone();
                            if self
                                .auth_manager
                                .remove_managed_chatgpt_account(&identity)
                                .await
                                .map_err(|err| internal_error(format!("logout failed: {err}")))?
                            {
                                removed_account_ids.push(identity);
                            }
                        }
                        _ => {
                            return Err(invalid_request(
                                "multiple managed ChatGPT accounts are present; specify accountId or all",
                            ));
                        }
                    }
                }
            }
            Some(LogoutAccountParams {
                account_id: Some(_),
                all: true,
            }) => unreachable!("validated above"),
        }

        if managed_bedrock_auth {
            clear_user_model_provider_if_bedrock(&self.config_manager).await?;
        }

        Self::maybe_refresh_plugin_caches_for_current_config(
            &self.config_manager,
            &self.thread_manager,
            self.auth_manager.auth_cached(),
        )
        .await;
        let list = if self.auth_manager.is_external_chatgpt_auth_active() {
            self.auth_manager
                .stored_managed_chatgpt_account_list()
                .map_err(|err| internal_error(format!("failed to list managed accounts: {err}")))?
        } else {
            self.auth_manager
                .list_managed_chatgpt_accounts(&ManagedChatgptSelectionScope::default())
                .await
                .map_err(|err| internal_error(format!("failed to list managed accounts: {err}")))?
        };
        let response = Self::list_accounts_response_from_owner(list, false, &HashMap::new());
        Ok(LogoutAccountResponse {
            removed_account_ids,
            accounts: response.accounts,
            selected_account_id: response.selected_account_id,
        })
    }

    pub(super) async fn logout_v2(
        &self,
        request_id: ConnectionRequestId,
        params: Option<LogoutAccountParams>,
    ) -> Result<(), JSONRPCErrorError> {
        let result = self.logout_common(params).await;
        let succeeded = result.is_ok();
        self.outgoing.send_result(request_id, result).await;
        if succeeded {
            self.outgoing
                .send_server_notification(ServerNotification::AccountUpdated(
                    self.current_account_updated_notification(),
                ))
                .await;
        }
        Ok(())
    }

    pub(super) async fn list_accounts_response(
        &self,
        params: ListAccountsParams,
        scope: ManagedChatgptSelectionScope,
    ) -> Result<ListAccountsResponse, JSONRPCErrorError> {
        if self.auth_manager.is_external_chatgpt_auth_active() {
            let hidden_pool = self
                .auth_manager
                .stored_managed_chatgpt_account_list()
                .map_err(|err| {
                    internal_error(format!("failed to read hidden managed account pool: {err}"))
                })?;
            return Ok(ListAccountsResponse {
                accounts: Vec::new(),
                selected_account_id: None,
                selection_revision: None,
                pool_revision: hidden_pool.pool_revision,
            });
        }
        let initial = self
            .auth_manager
            .list_managed_chatgpt_accounts(&scope)
            .await
            .map_err(|err| internal_error(format!("failed to list managed accounts: {err}")))?;
        let mut refresh_statuses = HashMap::new();

        for account in initial.accounts {
            let attempted_last_refresh = account.last_refresh;
            let identity = account.identity_key;
            let snapshot = if params.refresh_tokens {
                match self
                    .auth_manager
                    .refresh_managed_chatgpt_account_bounded(
                        &identity,
                        ACCOUNT_TOKEN_REFRESH_TIMEOUT,
                    )
                    .await
                {
                    Ok(snapshot) => Some(snapshot),
                    Err(err) => {
                        warn!("failed to refresh managed account: {err}");
                        None
                    }
                }
            } else {
                match self
                    .auth_manager
                    .managed_chatgpt_auth_snapshot_for_identity(&identity)
                    .await
                {
                    Ok(snapshot) => snapshot,
                    Err(err) => {
                        warn!("failed to resolve managed account: {err}");
                        refresh_statuses.insert(
                            identity.clone(),
                            (
                                attempted_last_refresh,
                                ManagedChatgptAccountRefreshStatus::TransientUnavailable {
                                    observed_at: Utc::now().timestamp(),
                                },
                            ),
                        );
                        None
                    }
                }
            };

            if !params.refresh_usage {
                continue;
            }
            let Some(snapshot) = snapshot else {
                continue;
            };
            let client = match snapshot
                .auth
                .get_token()
                .map_err(|err| err.to_string())
                .map(|token| {
                    BackendClient::new(
                        self.config.chatgpt_base_url.clone(),
                        self.config.http_client_factory(),
                    )
                    .with_auth_provider(Arc::new(BearerAuthProvider {
                        token: Some(token),
                        account_id: snapshot.transport.raw_account_id.clone(),
                        is_fedramp_account: snapshot.transport.fedramp,
                    }))
                }) {
                Ok(client) => client,
                Err(err) => {
                    warn!("failed to construct managed account backend client: {err}");
                    let observation = ManagedChatgptStatusObservation {
                        observed_at: Utc::now(),
                        rate: ManagedChatgptRateObservation::Unavailable {
                            reason: "backend_client_unavailable".to_string(),
                        },
                        token: ManagedChatgptTokenObservation::Unavailable {
                            reason: "backend_client_unavailable".to_string(),
                        },
                    };
                    match self.auth_manager.record_managed_chatgpt_status_observation(
                        &snapshot.identity_key,
                        snapshot.account_revision,
                        snapshot.account_state_revision,
                        observation,
                    ) {
                        Ok(Some(account)) => {
                            self.send_managed_usage_notification(account).await;
                        }
                        Ok(None) => {
                            warn!("discarded stale managed account status");
                        }
                        Err(err) => {
                            warn!("failed to record managed account status: {err}");
                        }
                    }
                    continue;
                }
            };

            let (rate_result, token_result) = tokio::join!(
                tokio::time::timeout(
                    ACCOUNT_RATE_LIMIT_FETCH_TIMEOUT,
                    client.get_rate_limits_with_reset_credits(),
                ),
                tokio::time::timeout(
                    ACCOUNT_TOKEN_USAGE_FETCH_TIMEOUT,
                    client.get_token_usage_profile(),
                ),
            );
            let rate = match rate_result {
                Ok(Ok(response)) => managed_rate_observation(response.rate_limits),
                Ok(Err(err)) => {
                    warn!("failed to fetch managed account rate limits: {err}");
                    ManagedChatgptRateObservation::Unavailable {
                        reason: "rate_limits_unavailable".to_string(),
                    }
                }
                Err(_) => ManagedChatgptRateObservation::Unavailable {
                    reason: "rate_limits_timeout".to_string(),
                },
            };
            let token = match token_result {
                Ok(Ok(profile)) => {
                    let stats = profile.stats;
                    ManagedChatgptTokenObservation::Available(ManagedChatgptTokenUsageSummary {
                        lifetime_tokens: stats.lifetime_tokens,
                        peak_daily_tokens: stats.peak_daily_tokens,
                        longest_running_turn_sec: stats.longest_running_turn_sec,
                        current_streak_days: stats.current_streak_days,
                        longest_streak_days: stats.longest_streak_days,
                    })
                }
                Ok(Err(err)) => {
                    warn!("failed to fetch managed account token usage: {err}");
                    ManagedChatgptTokenObservation::Unavailable {
                        reason: "token_usage_unavailable".to_string(),
                    }
                }
                Err(_) => ManagedChatgptTokenObservation::Unavailable {
                    reason: "token_usage_timeout".to_string(),
                },
            };
            let observation = ManagedChatgptStatusObservation {
                observed_at: Utc::now(),
                rate,
                token,
            };
            match self.auth_manager.record_managed_chatgpt_status_observation(
                &snapshot.identity_key,
                snapshot.account_revision,
                snapshot.account_state_revision,
                observation,
            ) {
                Ok(Some(account)) => {
                    self.send_managed_usage_notification(account).await;
                }
                Ok(None) => {
                    warn!("discarded stale managed account status");
                }
                Err(err) => {
                    warn!("failed to record managed account status: {err}");
                }
            }
        }

        let list = self
            .auth_manager
            .list_managed_chatgpt_accounts(&scope)
            .await
            .map_err(|err| internal_error(format!("failed to list managed accounts: {err}")))?;
        Ok(Self::list_accounts_response_from_owner(
            list,
            params.thread_id.is_some(),
            &refresh_statuses,
        ))
    }

    pub(super) fn list_accounts_response_from_owner(
        list: codex_login::ManagedChatgptAccountList,
        scoped: bool,
        refresh_statuses: &RefreshStatusByIdentity,
    ) -> ListAccountsResponse {
        let has_managed_pool = !list.accounts.is_empty();
        ListAccountsResponse {
            accounts: list
                .accounts
                .into_iter()
                .map(|account| {
                    let refresh_status = Self::refresh_status_for_account(
                        refresh_statuses,
                        &account.identity_key,
                        account.last_refresh,
                    );
                    Self::managed_account_view_from_owner(account, refresh_status)
                })
                .collect(),
            selected_account_id: list.selected_account_id,
            selection_revision: (scoped && has_managed_pool).then_some(list.selection_revision),
            pool_revision: list.pool_revision,
        }
    }

    pub(super) fn refresh_status_for_account(
        refresh_statuses: &RefreshStatusByIdentity,
        identity: &str,
        account_last_refresh: DateTime<Utc>,
    ) -> Option<ManagedChatgptAccountRefreshStatus> {
        refresh_statuses
            .get(identity)
            .and_then(|(attempted_last_refresh, status)| {
                (*attempted_last_refresh == account_last_refresh).then(|| status.clone())
            })
    }

    pub(super) fn refresh_status_from_owner(
        refresh_status: ManagedChatgptRefreshStatus,
        block_kind: Option<ManagedChatgptBlockKindView>,
        last_refresh: DateTime<Utc>,
    ) -> ManagedChatgptAccountRefreshStatus {
        if block_kind == Some(ManagedChatgptBlockKindView::AuthInvalid) {
            return ManagedChatgptAccountRefreshStatus::ReloginRequired {
                reason_code: "auth_invalid".to_string(),
                observed_at: last_refresh.timestamp(),
            };
        }
        match refresh_status {
            ManagedChatgptRefreshStatus::Healthy => ManagedChatgptAccountRefreshStatus::Healthy,
            ManagedChatgptRefreshStatus::TransientUnavailable { observed_at, .. } => {
                ManagedChatgptAccountRefreshStatus::TransientUnavailable {
                    observed_at: observed_at.timestamp(),
                }
            }
            ManagedChatgptRefreshStatus::ReloginRequired {
                observed_at,
                reason_code,
            } => ManagedChatgptAccountRefreshStatus::ReloginRequired {
                reason_code: reason_code.unwrap_or_else(|| "token_refresh_failed".to_string()),
                observed_at: observed_at.timestamp(),
            },
        }
    }

    fn managed_account_view_from_owner(
        account: ManagedChatgptAccountView,
        refresh_status: Option<ManagedChatgptAccountRefreshStatus>,
    ) -> ApiManagedChatgptAccountView {
        let mut rate_limits = std::collections::BTreeMap::new();
        if let Some(usage) = account.usage.as_ref() {
            for window in &usage.rate_windows {
                let snapshot = rate_limits
                    .entry(window.limit_id.clone())
                    .or_insert_with(|| ApiRateLimitSnapshot {
                        limit_id: Some(window.limit_id.clone()),
                        limit_name: None,
                        primary: None,
                        secondary: None,
                        credits: None,
                        individual_limit: None,
                        spend_control_reached: None,
                        plan_type: None,
                        rate_limit_reached_type: None,
                    });
                let wire_window = ApiRateLimitWindow {
                    used_percent: window
                        .remaining_percent
                        .map(|remaining| (100.0 - remaining).round() as i32)
                        .unwrap_or(0),
                    window_duration_mins: window.window_duration_mins,
                    resets_at: window.reset_at.map(|value| value.timestamp()),
                };
                match window.kind {
                    ManagedChatgptLimitKind::Primary | ManagedChatgptLimitKind::Additional => {
                        snapshot.primary = Some(wire_window);
                    }
                    ManagedChatgptLimitKind::Secondary => {
                        snapshot.secondary = Some(wire_window);
                    }
                }
            }
        }
        let token_usage = account
            .usage
            .as_ref()
            .and_then(|usage| usage.token_usage.as_ref())
            .map(|summary| AccountTokenUsageSummary {
                lifetime_tokens: summary.lifetime_tokens,
                peak_daily_tokens: summary.peak_daily_tokens,
                longest_running_turn_sec: summary.longest_running_turn_sec,
                current_streak_days: summary.current_streak_days,
                longest_streak_days: summary.longest_streak_days,
            });
        let usage_state = match account.usage_state {
            ManagedChatgptUsageState::Unknown => ManagedChatgptAccountUsageState::Unknown,
            ManagedChatgptUsageState::Fresh => ManagedChatgptAccountUsageState::Fresh,
            ManagedChatgptUsageState::Stale => ManagedChatgptAccountUsageState::Stale,
            ManagedChatgptUsageState::Unavailable => ManagedChatgptAccountUsageState::Unavailable,
        };
        let refresh_status = refresh_status.unwrap_or_else(|| {
            Self::refresh_status_from_owner(
                account.refresh_status,
                account.block_kind,
                account.last_refresh,
            )
        });
        let (eligible, eligibility_reason) = match account.eligibility {
            ManagedChatgptEligibility::Eligible => (true, None),
            ManagedChatgptEligibility::Blocked => (false, Some("blocked".to_string())),
            ManagedChatgptEligibility::ForcedWorkspaceDisallowed => {
                (false, Some("forced_workspace_disallowed".to_string()))
            }
            ManagedChatgptEligibility::PendingRemoval => {
                (false, Some("pending_removal".to_string()))
            }
        };
        let block = account.block_kind.map(|kind| ManagedChatgptAccountBlock {
            reason: match kind {
                ManagedChatgptBlockKindView::AuthInvalid => "auth_invalid",
                ManagedChatgptBlockKindView::Quota => "quota",
                ManagedChatgptBlockKindView::Workspace => "workspace",
            }
            .to_string(),
            blocked_until: account.block_reset_at.map(|value| value.timestamp()),
        });
        let plan_type = match account.plan.as_deref() {
            Some("go") => PlanType::Go,
            Some("plus") => PlanType::Plus,
            Some("pro") => PlanType::Pro,
            Some("prolite" | "pro_lite") => PlanType::ProLite,
            Some("team") => PlanType::Team,
            Some("self_serve_business_usage_based") => PlanType::SelfServeBusinessUsageBased,
            Some("business") => PlanType::Business,
            Some("enterprise_cbp_usage_based") => PlanType::EnterpriseCbpUsageBased,
            Some("enterprise") => PlanType::Enterprise,
            Some("edu") => PlanType::Edu,
            Some("free") => PlanType::Free,
            Some(_) | None => PlanType::Unknown,
        };
        let observed_at = account
            .usage
            .as_ref()
            .map(|usage| usage.observed_at.timestamp())
            .or_else(|| {
                (account.token_observed_at.timestamp() > 0)
                    .then_some(account.token_observed_at.timestamp())
            });
        let unavailable_observed_at = if account.usage_unavailable_reason.is_some() {
            account
                .usage_unavailable_observed_at
                .map(|observed_at| observed_at.timestamp())
        } else {
            account
                .token_unavailable_observed_at
                .map(|observed_at| observed_at.timestamp())
        };
        ApiManagedChatgptAccountView {
            managed_account_id: account.identity_key,
            chatgpt_account_id: account.chatgpt_account_id,
            email: account.normalized_email,
            plan_type,
            eligible,
            eligibility_reason,
            account_revision: account.revision,
            credential_revision: account.credential_revision,
            refresh_status,
            block,
            usage: ManagedChatgptAccountUsage {
                state: usage_state,
                rate_limits: rate_limits.into_values().collect(),
                token_usage,
                observed_at,
                unavailable_reason: account
                    .usage_unavailable_reason
                    .or(account.token_unavailable_reason),
                unavailable_observed_at,
            },
        }
    }

    async fn send_managed_usage_notification(&self, account: ManagedChatgptAccountView) {
        let account = Self::managed_account_view_from_owner(account, None);
        self.outgoing
            .send_server_notification(ServerNotification::AccountUsageUpdated(
                AccountUsageUpdatedNotification {
                    managed_account_id: account.managed_account_id.clone(),
                    account_revision: account.account_revision,
                    usage: account.usage.clone(),
                },
            ))
            .await;
    }
}

pub(super) fn managed_rate_observation(
    rate_limits: Vec<codex_protocol::protocol::RateLimitSnapshot>,
) -> ManagedChatgptRateObservation {
    if rate_limits.is_empty() {
        return ManagedChatgptRateObservation::Unavailable {
            reason: "rate_limits_empty".to_string(),
        };
    }
    let mut windows = Vec::new();
    for (snapshot_index, snapshot) in rate_limits.into_iter().enumerate() {
        let limit_id = snapshot.limit_id.unwrap_or_else(|| "codex".to_string());
        let canonical = snapshot_index == 0 || limit_id == "codex";
        for (kind, suffix, window) in [
            (
                if canonical {
                    ManagedChatgptLimitKind::Primary
                } else {
                    ManagedChatgptLimitKind::Additional
                },
                "primary",
                snapshot.primary,
            ),
            (
                if canonical {
                    ManagedChatgptLimitKind::Secondary
                } else {
                    ManagedChatgptLimitKind::Additional
                },
                "secondary",
                snapshot.secondary,
            ),
        ] {
            let Some(window) = window else {
                continue;
            };
            windows.push(ManagedChatgptRateWindowView {
                limit_id: if canonical {
                    limit_id.clone()
                } else {
                    format!("{limit_id}:{suffix}")
                },
                kind,
                remaining_percent: Some((100.0 - window.used_percent).clamp(0.0, 100.0)),
                reset_at: window
                    .resets_at
                    .and_then(|value| DateTime::from_timestamp(value, 0)),
                window_duration_mins: window.window_minutes,
            });
        }
    }
    if windows.is_empty() {
        ManagedChatgptRateObservation::Unavailable {
            reason: "rate_limit_windows_empty".to_string(),
        }
    } else {
        ManagedChatgptRateObservation::Available(windows)
    }
}
