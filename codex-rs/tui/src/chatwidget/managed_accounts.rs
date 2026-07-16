//! Managed-account cache, selection, and usage coordination for `ChatWidget`.
use codex_app_server_protocol::AccountRateLimitsUpdatedNotification;
use codex_app_server_protocol::AccountUsageUpdatedNotification;
use codex_app_server_protocol::ListAccountsResponse;

use super::*;
use crate::chatwidget::rate_limits::RATE_LIMIT_SWITCH_PROMPT_VIEW_ID;

impl ChatWidget {
    pub(crate) fn managed_accounts(&self) -> Option<&crate::status::ManagedAccountsState> {
        match self.status_account_display.as_ref() {
            Some(StatusAccountDisplay::ManagedChatGpt(accounts)) => Some(accounts),
            _ => None,
        }
    }

    pub(crate) fn clear_managed_accounts_cache(&mut self) {
        self.pending_managed_account_selection = None;
        self.managed_account_updates_enabled = false;
        if matches!(
            self.status_account_display,
            Some(StatusAccountDisplay::ManagedChatGpt(_))
        ) {
            self.status_account_display = None;
        }
    }

    pub(crate) fn enable_managed_account_updates(&mut self) {
        self.managed_account_updates_enabled = true;
    }

    pub(crate) fn suspend_managed_account_updates(&mut self) {
        self.managed_account_updates_enabled = false;
    }

    pub(crate) fn clear_managed_account_selection_scope(&mut self) {
        if let Some(StatusAccountDisplay::ManagedChatGpt(accounts)) =
            self.status_account_display.as_mut()
        {
            accounts.reset_selection_scope();
        }
        self.clear_account_bound_state();
        self.refresh_status_surfaces();
    }

    pub(crate) fn replace_managed_accounts(&mut self, response: ListAccountsResponse) {
        let previous_selected_binding = self
            .managed_accounts()
            .and_then(crate::status::ManagedAccountsState::selected_account_binding_key);
        let updated = match self.status_account_display.as_mut() {
            Some(StatusAccountDisplay::ManagedChatGpt(accounts)) => {
                accounts.replace_from_response(response)
            }
            _ => {
                self.status_account_display = Some(StatusAccountDisplay::ManagedChatGpt(
                    crate::status::ManagedAccountsState::from_response(response),
                ));
                true
            }
        };
        let selected_binding_changed = previous_selected_binding
            != self
                .managed_accounts()
                .and_then(crate::status::ManagedAccountsState::selected_account_binding_key);
        if selected_binding_changed {
            self.clear_account_bound_state();
        }
        if updated || selected_binding_changed {
            self.project_selected_managed_rate_limits();
            self.refresh_status_surfaces();
        }
        self.apply_pending_managed_account_selection();
    }

    pub(crate) fn replace_managed_accounts_after_logout(
        &mut self,
        accounts: Vec<codex_app_server_protocol::ManagedChatgptAccountView>,
        selected_account_id: Option<String>,
    ) {
        let previous_selected_binding = self
            .managed_accounts()
            .and_then(crate::status::ManagedAccountsState::selected_account_binding_key);
        let selected_binding_changed = if let Some(StatusAccountDisplay::ManagedChatGpt(state)) =
            self.status_account_display.as_mut()
        {
            state.replace_accounts_after_logout(accounts, selected_account_id);
            previous_selected_binding != state.selected_account_binding_key()
        } else {
            return;
        };
        if selected_binding_changed {
            self.clear_account_bound_state();
            self.project_selected_managed_rate_limits();
        }
        self.refresh_status_surfaces();
    }

    pub(crate) fn apply_account_pool_update(
        &mut self,
        accounts: Vec<codex_app_server_protocol::ManagedChatgptAccountView>,
        pool_revision: u64,
    ) -> bool {
        if !self.managed_account_updates_enabled {
            return false;
        }
        let previous_selected_binding = self
            .managed_accounts()
            .and_then(crate::status::ManagedAccountsState::selected_account_binding_key);
        let updated = match self.status_account_display.as_mut() {
            Some(StatusAccountDisplay::ManagedChatGpt(state)) => {
                state.replace_accounts(accounts, pool_revision)
            }
            Some(StatusAccountDisplay::ChatGpt { .. }) | None
                if !accounts.is_empty() && self.config.model_provider.requires_openai_auth =>
            {
                self.status_account_display = Some(StatusAccountDisplay::ManagedChatGpt(
                    crate::status::ManagedAccountsState::from_response(ListAccountsResponse {
                        accounts,
                        selected_account_id: None,
                        selection_revision: None,
                        pool_revision,
                    }),
                ));
                self.has_chatgpt_account = true;
                true
            }
            _ => false,
        };
        let selected_binding_changed = previous_selected_binding
            != self
                .managed_accounts()
                .and_then(crate::status::ManagedAccountsState::selected_account_binding_key);
        if selected_binding_changed {
            self.clear_account_bound_state();
        }
        if updated || selected_binding_changed {
            self.project_selected_managed_rate_limits();
            self.refresh_status_surfaces();
        }
        let selection_updated = self.apply_pending_managed_account_selection();
        updated || selection_updated
    }

    pub(crate) fn apply_account_selection_update(
        &mut self,
        thread_id: &str,
        selected_account_id: Option<String>,
        selection_revision: u64,
    ) -> bool {
        if !self.managed_account_updates_enabled {
            return false;
        }
        let current_thread_id = self.thread_id.map(|id| id.to_string());
        if current_thread_id
            .as_deref()
            .is_some_and(|current| current != thread_id)
        {
            return false;
        }
        let should_buffer = self.pending_managed_account_selection.as_ref().is_none_or(
            |(pending_thread_id, _, pending_revision)| {
                pending_thread_id != thread_id || selection_revision > *pending_revision
            },
        );
        if !should_buffer {
            return false;
        }
        self.pending_managed_account_selection = Some((
            thread_id.to_string(),
            selected_account_id.clone(),
            selection_revision,
        ));
        if current_thread_id.as_deref() != Some(thread_id) {
            return false;
        }
        let Some(StatusAccountDisplay::ManagedChatGpt(accounts)) =
            self.status_account_display.as_mut()
        else {
            return false;
        };
        let previous_selected_binding = accounts.selected_account_binding_key();
        let updated = accounts.set_selected_account_id(selected_account_id, selection_revision);
        let selected_binding_changed =
            previous_selected_binding != accounts.selected_account_binding_key();
        if updated {
            self.pending_managed_account_selection = None;
            if selected_binding_changed {
                self.clear_account_bound_state();
                self.project_selected_managed_rate_limits();
            }
            self.refresh_status_surfaces();
        }
        updated
    }

    pub(crate) fn apply_pending_managed_account_selection(&mut self) -> bool {
        let Some((thread_id, selected_account_id, selection_revision)) =
            self.pending_managed_account_selection.take()
        else {
            return false;
        };
        self.apply_account_selection_update(
            thread_id.as_str(),
            selected_account_id,
            selection_revision,
        )
    }

    pub(crate) fn apply_managed_rate_limits_update(
        &mut self,
        notification: &AccountRateLimitsUpdatedNotification,
    ) -> bool {
        let updates_selected_account = self
            .managed_accounts()
            .and_then(|accounts| accounts.selected_account_id())
            == notification.managed_account_id.as_deref();
        let Some(StatusAccountDisplay::ManagedChatGpt(accounts)) =
            self.status_account_display.as_mut()
        else {
            return false;
        };
        let updated = accounts.apply_rate_limits_update(notification);
        if updated {
            if updates_selected_account {
                self.project_selected_managed_rate_limits();
            }
            self.refresh_status_surfaces();
        }
        updated
    }

    pub(crate) fn apply_managed_usage_update(
        &mut self,
        notification: &AccountUsageUpdatedNotification,
    ) -> bool {
        let updates_selected_account = self
            .managed_accounts()
            .and_then(|accounts| accounts.selected_account_id())
            == Some(notification.managed_account_id.as_str());
        let Some(StatusAccountDisplay::ManagedChatGpt(accounts)) =
            self.status_account_display.as_mut()
        else {
            return false;
        };
        let updated = accounts.apply_usage_update(notification);
        if updated {
            if updates_selected_account {
                self.project_selected_managed_rate_limits();
            }
            self.refresh_status_surfaces();
        }
        updated
    }

    fn clear_account_bound_state(&mut self) {
        self.clear_pending_token_activity_refreshes();
        self.clear_pending_rate_limit_reset_requests();
        self.add_credits_nudge_email_in_flight = None;
        self.status_line_workspace_headline = None;
        self.status_line_workspace_headline_pending_request_id = None;
        self.status_line_workspace_headline_last_requested_at = None;
        self.status_line_workspace_messages_disabled = false;
        self.plan_type = None;
        self.codex_rate_limit_reached_type = None;
        self.codex_spend_control_reached = None;
        self.rate_limit_warnings = RateLimitWarningState::default();
        self.rate_limit_switch_prompt = RateLimitSwitchPromptState::Idle;
        self.bottom_pane
            .dismiss_view_by_id(RATE_LIMIT_SWITCH_PROMPT_VIEW_ID);
        let had_refreshing_status_outputs = !self.refreshing_status_outputs.is_empty();
        let now = Local::now();
        for (_, handle) in self.refreshing_status_outputs.drain(..) {
            handle.finish_rate_limit_refresh(&[], now);
        }
        if had_refreshing_status_outputs {
            self.request_redraw();
        }
    }

    pub(super) fn project_selected_managed_rate_limits(&mut self) {
        let selected = self
            .managed_accounts()
            .and_then(|accounts| accounts.selected_account())
            .map(|account| (account.plan_type, account.usage.rate_limits.clone()));
        self.rate_limit_snapshots_by_limit_id.clear();
        self.plan_type = None;
        if let Some((plan_type, snapshots)) = selected {
            for snapshot in snapshots {
                self.on_rate_limit_snapshot(Some(snapshot));
            }
            self.plan_type = Some(plan_type);
        }
    }

    pub(crate) fn update_account_state(
        &mut self,
        status_account_display: Option<StatusAccountDisplay>,
        plan_type: Option<PlanType>,
        has_chatgpt_account: bool,
        has_codex_backend_auth: bool,
    ) {
        // Account-update notifications are the identity boundary. The visible account fields can
        // be identical across two accounts, so always invalidate account-scoped requests and data.
        self.clear_account_bound_state();
        let preserve_managed_accounts = has_chatgpt_account
            && matches!(
                &status_account_display,
                Some(StatusAccountDisplay::ChatGpt { .. })
            )
            && matches!(
                &self.status_account_display,
                Some(StatusAccountDisplay::ManagedChatGpt(_))
            );
        if preserve_managed_accounts {
            self.project_selected_managed_rate_limits();
        } else {
            self.status_account_display = status_account_display;
            self.plan_type = plan_type;
        }
        self.has_chatgpt_account = has_chatgpt_account;
        self.has_codex_backend_auth = has_codex_backend_auth;
        self.bottom_pane
            .set_connectors_enabled(self.connectors_enabled());
        self.bottom_pane
            .set_token_activity_command_enabled(has_codex_backend_auth);
        self.refresh_status_surfaces();
    }
}
