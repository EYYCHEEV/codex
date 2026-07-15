//! Runtime settings state and model/collaboration coordination for `ChatWidget`.
use codex_app_server_protocol::AccountRateLimitsUpdatedNotification;
use codex_app_server_protocol::AccountUsageUpdatedNotification;
use codex_app_server_protocol::ListAccountsResponse;

use super::*;
use crate::app_event::AppEvent;
use crate::chatwidget::rate_limits::RATE_LIMIT_SWITCH_PROMPT_VIEW_ID;

impl ChatWidget {
    /// Set the approval policy in the widget's config copy.
    pub(crate) fn set_approval_policy(&mut self, policy: AskForApproval) {
        if let Err(err) = self
            .config
            .permissions
            .approval_policy
            .set(policy.to_core())
        {
            tracing::warn!(%err, "failed to set approval_policy on chat config");
        } else {
            self.refresh_status_surfaces();
        }
    }

    #[cfg_attr(not(target_os = "windows"), allow(dead_code))]
    pub(crate) fn set_permission_profile_from_session_snapshot(
        &mut self,
        snapshot: PermissionProfileSnapshot,
    ) -> ConstraintResult<()> {
        self.config
            .permissions
            .set_permission_profile_from_session_snapshot(snapshot)?;
        self.refresh_status_surfaces();
        Ok(())
    }

    pub(crate) fn set_permission_profile_with_active_profile(
        &mut self,
        profile: PermissionProfile,
        active_permission_profile: Option<ActivePermissionProfile>,
    ) -> ConstraintResult<()> {
        self.config
            .permissions
            .set_permission_profile_from_session_snapshot(
                PermissionProfileSnapshot::from_session_snapshot(
                    profile,
                    active_permission_profile,
                ),
            )?;
        self.refresh_status_surfaces();
        Ok(())
    }

    pub(crate) fn set_permission_network(
        &mut self,
        network: Option<crate::legacy_core::config::NetworkProxySpec>,
    ) {
        self.config.permissions.network = network;
    }

    #[cfg_attr(not(target_os = "windows"), allow(dead_code))]
    pub(crate) fn set_windows_sandbox_mode(&mut self, mode: Option<WindowsSandboxModeToml>) {
        self.config.permissions.windows_sandbox_mode = mode;
        #[cfg(target_os = "windows")]
        self.bottom_pane
            .set_windows_degraded_sandbox_active(matches!(
                crate::windows_sandbox::level_from_config(&self.config),
                WindowsSandboxLevel::RestrictedToken
            ));
    }

    #[cfg_attr(not(target_os = "windows"), allow(dead_code))]
    pub(crate) fn set_feature_enabled(&mut self, feature: Feature, enabled: bool) -> bool {
        if let Err(err) = self.config.features.set_enabled(feature, enabled) {
            tracing::warn!(
                error = %err,
                feature = feature.key(),
                "failed to update constrained chat widget feature state"
            );
        }
        let enabled = self.config.features.enabled(feature);
        if feature == Feature::FastMode {
            self.refresh_effective_service_tier();
            self.sync_service_tier_commands();
        }
        if feature == Feature::Personality {
            self.sync_personality_command_enabled();
        }
        if feature == Feature::Plugins {
            self.sync_plugins_command_enabled();
            self.refresh_plugin_mentions();
        }
        if feature == Feature::Goals {
            self.sync_goal_command_enabled();
            if !enabled {
                self.current_goal_status_indicator = None;
                self.current_goal_status = None;
                self.turn_lifecycle.goal_status_active_turn_started_at = None;
                self.turn_lifecycle.budget_limited_turn_ids.clear();
                self.update_collaboration_mode_indicator();
            }
        }
        if feature == Feature::MentionsV2 {
            self.sync_mentions_v2_enabled();
        }
        if feature == Feature::PreventIdleSleep {
            self.turn_lifecycle.set_prevent_idle_sleep(enabled);
        }
        #[cfg(target_os = "windows")]
        if matches!(
            feature,
            Feature::WindowsSandbox | Feature::WindowsSandboxElevated
        ) {
            self.bottom_pane
                .set_windows_degraded_sandbox_active(matches!(
                    crate::windows_sandbox::level_from_config(&self.config),
                    WindowsSandboxLevel::RestrictedToken
                ));
        }
        enabled
    }

    pub(crate) fn set_approvals_reviewer(&mut self, policy: ApprovalsReviewer) {
        self.config.approvals_reviewer = policy;
        self.refresh_status_surfaces();
    }

    pub(crate) fn set_world_writable_warning_acknowledged(&mut self, acknowledged: bool) {
        self.config.notices.hide_world_writable_warning = Some(acknowledged);
    }

    #[cfg_attr(not(target_os = "windows"), allow(dead_code))]
    pub(crate) fn world_writable_warning_hidden(&self) -> bool {
        self.config
            .notices
            .hide_world_writable_warning
            .unwrap_or(false)
    }

    /// Override the reasoning effort used when Plan mode is active.
    ///
    /// When the active mask is already Plan, the override is applied immediately
    /// so the footer reflects it without waiting for the next mode switch.
    /// Passing `None` resets to the Plan-mode preset default.
    pub(crate) fn set_plan_mode_reasoning_effort(&mut self, effort: Option<ReasoningEffortConfig>) {
        self.config.plan_mode_reasoning_effort = effort.clone();
        if self.collaboration_modes_enabled()
            && let Some(mask) = self.active_collaboration_mask.as_mut()
            && mask.mode == Some(ModeKind::Plan)
        {
            if let Some(effort) = effort {
                mask.reasoning_effort = Some(Some(effort));
            } else if let Some(plan_mask) =
                collaboration_modes::plan_mask(self.model_catalog.as_ref())
            {
                mask.reasoning_effort = plan_mask.reasoning_effort;
            }
        }
        self.refresh_model_dependent_surfaces();
    }

    /// Set the reasoning effort for the non-Plan collaboration mode.
    ///
    /// Does not touch the active Plan mask — Plan reasoning is controlled
    /// exclusively by the Plan preset and `set_plan_mode_reasoning_effort`.
    pub(crate) fn set_reasoning_effort(&mut self, effort: Option<ReasoningEffortConfig>) {
        self.current_collaboration_mode = self.current_collaboration_mode.with_updates(
            /*model*/ None,
            Some(effort.clone()),
            /*developer_instructions*/ None,
        );
        if self.collaboration_modes_enabled()
            && let Some(mask) = self.active_collaboration_mask.as_mut()
            && mask.mode != Some(ModeKind::Plan)
        {
            // Generic "global default" updates should not mutate the active Plan mask.
            // Plan reasoning is controlled by the Plan preset and Plan-only override updates.
            mask.reasoning_effort = Some(effort);
        }
        self.refresh_model_dependent_surfaces();
    }

    /// Set the personality in the widget's config copy.
    pub(crate) fn set_personality(&mut self, personality: Personality) {
        self.config.personality = Some(personality);
    }

    pub(crate) fn status_account_display(&self) -> Option<&StatusAccountDisplay> {
        self.status_account_display.as_ref()
    }

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
            .and_then(|accounts| accounts.selected_account_binding_key());
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
                .and_then(|accounts| accounts.selected_account_binding_key());
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
            .and_then(|state| state.selected_account_binding_key());
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
            .and_then(|state| state.selected_account_binding_key());
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
                .and_then(|state| state.selected_account_binding_key());
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

    pub(crate) fn runtime_model_provider_base_url(&self) -> Option<&str> {
        self.runtime_model_provider_base_url.as_deref()
    }

    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) fn model_catalog(&self) -> Arc<ModelCatalog> {
        self.model_catalog.clone()
    }

    pub(crate) fn current_plan_type(&self) -> Option<PlanType> {
        self.plan_type
    }

    pub(crate) fn has_chatgpt_account(&self) -> bool {
        self.has_chatgpt_account
    }

    pub(crate) fn has_codex_backend_auth(&self) -> bool {
        self.has_codex_backend_auth
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

    /// Set the syntax theme override in the widget's config copy.
    pub(crate) fn set_tui_theme(&mut self, theme: Option<String>) {
        self.config.tui_theme = theme;
    }

    /// Set the model in the widget's config copy and stored collaboration mode.
    pub(crate) fn set_model(&mut self, model: &str) {
        self.current_collaboration_mode = self.current_collaboration_mode.with_updates(
            Some(model.to_string()),
            /*effort*/ None,
            /*developer_instructions*/ None,
        );
        if self.collaboration_modes_enabled()
            && let Some(mask) = self.active_collaboration_mask.as_mut()
        {
            mask.model = Some(model.to_string());
        }
        self.refresh_effective_service_tier();
        self.refresh_model_dependent_surfaces();
    }

    pub(crate) fn current_model(&self) -> &str {
        if !self.collaboration_modes_enabled() {
            return self.current_collaboration_mode.model();
        }
        self.active_collaboration_mask
            .as_ref()
            .and_then(|mask| mask.model.as_deref())
            .unwrap_or_else(|| self.current_collaboration_mode.model())
    }

    pub(super) fn sync_personality_command_enabled(&mut self) {
        self.bottom_pane
            .set_personality_command_enabled(self.config.features.enabled(Feature::Personality));
    }

    pub(super) fn sync_plugins_command_enabled(&mut self) {
        self.bottom_pane
            .set_plugins_command_enabled(self.config.features.enabled(Feature::Plugins));
    }

    pub(super) fn sync_goal_command_enabled(&mut self) {
        self.bottom_pane
            .set_goal_command_enabled(self.config.features.enabled(Feature::Goals));
    }

    pub(super) fn sync_mentions_v2_enabled(&mut self) {
        self.bottom_pane
            .set_mentions_v2_enabled(self.config.features.enabled(Feature::MentionsV2));
    }

    pub(super) fn current_model_supports_personality(&self) -> bool {
        let model = self.current_model();
        self.model_catalog
            .try_list_models()
            .ok()
            .and_then(|models| {
                models
                    .into_iter()
                    .find(|preset| preset.model == model)
                    .map(|preset| preset.supports_personality)
            })
            .unwrap_or(false)
    }

    /// Return whether the effective model currently advertises image-input support.
    ///
    /// We intentionally default to `true` when model metadata cannot be read so transient catalog
    /// failures do not hard-block user input in the UI.
    pub(super) fn current_model_supports_images(&self) -> bool {
        let model = self.current_model();
        self.model_catalog
            .try_list_models()
            .ok()
            .and_then(|models| {
                models
                    .into_iter()
                    .find(|preset| preset.model == model)
                    .map(|preset| preset.input_modalities.contains(&InputModality::Image))
            })
            .unwrap_or(true)
    }

    pub(super) fn sync_image_paste_enabled(&mut self) {
        let enabled = self.current_model_supports_images();
        self.bottom_pane.set_image_paste_enabled(enabled);
    }

    pub(super) fn image_inputs_not_supported_message(&self) -> String {
        format!(
            "Model {} does not support image inputs. Remove images or switch models.",
            self.current_model()
        )
    }

    pub(crate) fn current_collaboration_mode(&self) -> &CollaborationMode {
        &self.current_collaboration_mode
    }

    pub(crate) fn current_reasoning_effort(&self) -> Option<ReasoningEffortConfig> {
        self.effective_reasoning_effort()
    }

    pub(crate) fn on_thread_settings_updated(
        &mut self,
        notification: ThreadSettingsUpdatedNotification,
    ) {
        let Ok(thread_id) = ThreadId::from_string(&notification.thread_id) else {
            tracing::warn!(
                thread_id = notification.thread_id,
                "ignoring app-server ThreadSettingsUpdated with invalid thread_id"
            );
            return;
        };
        if self.thread_id != Some(thread_id) {
            return;
        }

        self.apply_thread_settings(notification.thread_settings);
    }

    #[cfg(test)]
    pub(crate) fn active_collaboration_mode_kind(&self) -> ModeKind {
        self.active_mode_kind()
    }

    pub(super) fn is_session_configured(&self) -> bool {
        self.thread_id.is_some()
    }

    pub(super) fn collaboration_modes_enabled(&self) -> bool {
        true
    }

    /// Returns the dismissal scope that applies to the currently visible draft.
    fn plan_mode_nudge_scope(&self) -> PlanModeNudgeScope {
        self.thread_id
            .map_or(PlanModeNudgeScope::NewThread, PlanModeNudgeScope::Thread)
    }

    /// Returns whether the current draft should replace the normal footer with the Plan-mode nudge.
    ///
    /// `ChatWidget` owns this policy because it can combine lexical draft matching with mode
    /// availability, interaction state, and thread-scoped dismissal. `ChatComposer` only renders
    /// the resulting visibility bit. Keeping slash and shell drafts out here avoids advertising a
    /// mode switch while the user is intentionally composing another local command.
    pub(super) fn should_show_plan_mode_nudge(&self) -> bool {
        let text = self.bottom_pane.composer_text();
        let trimmed = text.trim_start();
        self.collaboration_modes_enabled()
            && collaboration_modes::plan_mask(self.model_catalog.as_ref()).is_some()
            && self.active_mode_kind() != ModeKind::Plan
            && self.bottom_pane.composer_input_enabled()
            && !self.bottom_pane.is_task_running()
            && self.bottom_pane.no_modal_or_popup_active()
            && !trimmed.starts_with('/')
            && !trimmed.starts_with('!')
            && contains_plan_keyword(&text)
            && !self
                .dismissed_plan_mode_nudge_scopes
                .contains(&self.plan_mode_nudge_scope())
    }

    /// Synchronizes the footer presentation with the current Plan-mode nudge policy.
    pub(super) fn refresh_plan_mode_nudge(&mut self) {
        self.bottom_pane
            .set_plan_mode_nudge_visible(self.should_show_plan_mode_nudge());
    }

    /// Hides the nudge for the current thread scope until the user changes conversation context.
    pub(super) fn dismiss_plan_mode_nudge(&mut self) {
        self.dismissed_plan_mode_nudge_scopes
            .insert(self.plan_mode_nudge_scope());
        self.refresh_plan_mode_nudge();
    }

    pub(super) fn initial_collaboration_mask(
        _config: &Config,
        model_catalog: &ModelCatalog,
        model_override: Option<&str>,
    ) -> Option<CollaborationModeMask> {
        let mut mask = collaboration_modes::default_mask(model_catalog)?;
        if let Some(model_override) = model_override {
            mask.model = Some(model_override.to_string());
        }
        Some(mask)
    }

    pub(super) fn active_mode_kind(&self) -> ModeKind {
        self.active_collaboration_mask
            .as_ref()
            .and_then(|mask| mask.mode)
            .unwrap_or(ModeKind::Default)
    }

    pub(super) fn effective_reasoning_effort(&self) -> Option<ReasoningEffortConfig> {
        if !self.collaboration_modes_enabled() {
            return self.current_collaboration_mode.reasoning_effort();
        }
        let current_effort = self.current_collaboration_mode.reasoning_effort();
        self.active_collaboration_mask
            .as_ref()
            .and_then(|mask| mask.reasoning_effort.clone())
            .unwrap_or(current_effort)
    }

    pub(crate) fn effective_collaboration_mode(&self) -> CollaborationMode {
        if !self.collaboration_modes_enabled() {
            return self.current_collaboration_mode.clone();
        }
        self.active_collaboration_mask.as_ref().map_or_else(
            || self.current_collaboration_mode.clone(),
            |mask| self.current_collaboration_mode.apply_mask(mask),
        )
    }

    pub(super) fn refresh_model_display(&mut self) {
        let effective = self.effective_collaboration_mode();
        self.session_header.set_model(effective.model());
        // Keep composer paste affordances aligned with the currently effective model.
        self.sync_image_paste_enabled();
        self.sync_service_tier_commands();
        self.refresh_terminal_title();
        let effort = self.effective_reasoning_effort();
        self.bottom_pane
            .set_active_reasoning_effort(effort.as_ref());
    }

    /// Refresh every UI surface that depends on the effective model, reasoning
    /// effort, or collaboration mode.
    ///
    /// Call this at the end of any setter that mutates `current_collaboration_mode`,
    /// `active_collaboration_mask`, or per-mode reasoning-effort overrides.
    /// Consolidating both refreshes here prevents the bug where callers update the
    /// header/title (`refresh_model_display`) but forget the footer status line
    /// (`refresh_status_line`).
    pub(super) fn refresh_model_dependent_surfaces(&mut self) {
        self.refresh_model_display();
        self.refresh_status_line();
    }

    fn apply_thread_settings(&mut self, mut settings: ThreadSettings) {
        let cwd_changed = self.config.cwd != settings.cwd;
        self.apply_thread_settings_cwd(settings.cwd.clone());
        self.config.model_provider_id = settings.model_provider.clone();
        self.set_service_tier(settings.service_tier.clone());
        self.set_approval_policy(settings.approval_policy);
        self.set_approvals_reviewer(settings.approvals_reviewer.to_core());
        self.config.personality = settings.personality;

        let permission_profile = PermissionProfile::from_legacy_sandbox_policy_for_cwd(
            &settings.sandbox_policy.to_core(),
            settings.cwd.as_path(),
        );
        let permission_snapshot = PermissionProfileSnapshot::from_session_snapshot(
            permission_profile,
            settings.active_permission_profile.take().map(Into::into),
        );
        if let Err(err) = self
            .config
            .permissions
            .set_permission_profile_from_session_snapshot(permission_snapshot.clone())
        {
            tracing::warn!(%err, "failed to sync permissions from ThreadSettingsUpdated");
            if let Err(replace_err) = self
                .config
                .permissions
                .replace_permission_profile_from_session_snapshot(permission_snapshot)
            {
                tracing::error!(
                    %replace_err,
                    "failed to replace permissions from ThreadSettingsUpdated after constraint fallback"
                );
            }
        }

        settings.collaboration_mode.settings.model = settings.model;
        settings.collaboration_mode.settings.reasoning_effort = settings.effort;
        self.set_effective_collaboration_mode(settings.collaboration_mode);
        self.refresh_effective_service_tier();
        self.refresh_status_surfaces();
        self.sync_service_tier_commands();
        self.sync_personality_command_enabled();
        if cwd_changed {
            self.refresh_skills_for_current_cwd(/*force_reload*/ true);
        }
        self.refresh_plugin_mentions();
        self.request_redraw();
    }

    fn apply_thread_settings_cwd(&mut self, cwd: AbsolutePathBuf) {
        let previous_cwd = std::mem::replace(&mut self.config.cwd, cwd.clone());
        self.current_cwd = Some(cwd.to_path_buf());
        self.status_line_project_root_name_cache = None;

        if !self.config.workspace_roots.contains(&previous_cwd) {
            return;
        }

        let previous_roots = std::mem::take(&mut self.config.workspace_roots);
        self.config.workspace_roots.push(cwd);
        for root in previous_roots {
            if root != previous_cwd && !self.config.workspace_roots.contains(&root) {
                self.config.workspace_roots.push(root);
            }
        }
        self.config
            .permissions
            .set_workspace_roots(self.config.workspace_roots.clone());
    }

    pub(super) fn set_effective_collaboration_mode(&mut self, mode: CollaborationMode) {
        let mode_kind = mode.mode;
        let settings = mode.settings;
        if mode_kind == ModeKind::Default {
            self.current_collaboration_mode = CollaborationMode {
                mode: ModeKind::Default,
                settings: settings.clone(),
            };
        }
        self.active_collaboration_mask = Some(CollaborationModeMask {
            name: mode_kind.display_name().to_string(),
            mode: Some(mode_kind),
            model: Some(settings.model.clone()),
            reasoning_effort: Some(settings.reasoning_effort.clone()),
            developer_instructions: Some(settings.developer_instructions),
        });
        self.update_collaboration_mode_indicator();
        self.refresh_plan_mode_nudge();
        self.refresh_model_dependent_surfaces();
    }

    pub(super) fn model_display_name(&self) -> &str {
        let model = self.current_model();
        if model.is_empty() {
            DEFAULT_MODEL_DISPLAY_NAME
        } else {
            model
        }
    }

    /// Get the label for the current collaboration mode.
    pub(super) fn collaboration_mode_label(&self) -> Option<&'static str> {
        if !self.collaboration_modes_enabled() {
            return None;
        }
        let active_mode = self.active_mode_kind();
        active_mode
            .is_tui_visible()
            .then_some(active_mode.display_name())
    }

    fn collaboration_mode_indicator(&self) -> Option<CollaborationModeIndicator> {
        if !self.collaboration_modes_enabled() {
            return None;
        }
        match self.active_mode_kind() {
            ModeKind::Plan => Some(CollaborationModeIndicator::Plan),
            ModeKind::Default => None,
        }
    }

    pub(super) fn update_collaboration_mode_indicator(&mut self) {
        let indicator = self.collaboration_mode_indicator();
        let goal_indicator = if indicator.is_none() {
            self.goal_status_indicator(Instant::now())
        } else {
            None
        };
        self.current_goal_status_indicator = goal_indicator.clone();
        self.bottom_pane.set_collaboration_mode_indicator(indicator);
        self.bottom_pane.set_goal_status_indicator(goal_indicator);
    }

    pub(super) fn refresh_goal_status_indicator_for_time_tick(&mut self) {
        if self.collaboration_mode_indicator().is_some() {
            return;
        }
        let goal_indicator = self.goal_status_indicator(Instant::now());
        if goal_indicator != self.current_goal_status_indicator {
            self.current_goal_status_indicator = goal_indicator.clone();
            self.bottom_pane.set_goal_status_indicator(goal_indicator);
        }
    }

    fn goal_status_indicator(&self, now: Instant) -> Option<GoalStatusIndicator> {
        if !self.config.features.enabled(Feature::Goals) {
            return None;
        }
        self.current_goal_status.as_ref().and_then(|state| {
            state.indicator(now, self.turn_lifecycle.goal_status_active_turn_started_at)
        })
    }

    pub(super) fn on_thread_goal_updated(&mut self, goal: AppThreadGoal, turn_id: Option<String>) {
        if let Some(active_thread_id) = self.thread_id
            && active_thread_id.to_string() != goal.thread_id
        {
            return;
        }
        if !self.config.features.enabled(Feature::Goals) {
            self.current_goal_status_indicator = None;
            self.current_goal_status = None;
            self.update_collaboration_mode_indicator();
            return;
        }
        if goal.status == AppThreadGoalStatus::BudgetLimited
            && let Some(turn_id) = turn_id
        {
            self.turn_lifecycle.mark_budget_limited(turn_id);
        }
        self.current_goal_status = Some(GoalStatusState::new(goal, Instant::now()));
        self.update_collaboration_mode_indicator();
    }

    /// Cycle to the next collaboration mode variant (Plan -> Default -> Plan).
    pub(super) fn cycle_collaboration_mode(&mut self) {
        if !self.collaboration_modes_enabled() {
            return;
        }

        if let Some(next_mask) = collaboration_modes::next_mask(
            self.model_catalog.as_ref(),
            self.active_collaboration_mask.as_ref(),
        ) {
            self.set_collaboration_mask_from_user_action(next_mask);
        }
    }

    pub(crate) fn set_collaboration_mask_from_user_action(&mut self, mask: CollaborationModeMask) {
        self.set_collaboration_mask(mask);
        self.submit_collaboration_mode_settings_update();
    }

    /// Update the active collaboration mask.
    ///
    /// When collaboration modes are enabled and a preset is selected,
    /// the current mode is attached to submissions as `Op::UserTurn { collaboration_mode: Some(...) }`.
    pub(crate) fn set_collaboration_mask(&mut self, mut mask: CollaborationModeMask) {
        if !self.collaboration_modes_enabled() {
            return;
        }
        let previous_mode = self.active_mode_kind();
        let previous_model = self.current_model().to_string();
        let previous_effort = self.effective_reasoning_effort();
        if mask.mode == Some(ModeKind::Plan)
            && let Some(effort) = self.config.plan_mode_reasoning_effort.clone()
        {
            mask.reasoning_effort = Some(Some(effort));
        }
        if mask.mode == Some(ModeKind::Plan) {
            self.dismissed_plan_mode_nudge_scopes
                .insert(self.plan_mode_nudge_scope());
        }
        self.active_collaboration_mask = Some(mask);
        self.update_collaboration_mode_indicator();
        self.refresh_plan_mode_nudge();
        self.refresh_model_dependent_surfaces();
        let next_mode = self.active_mode_kind();
        let next_model = self.current_model();
        let next_effort = self.effective_reasoning_effort();
        if previous_mode != next_mode
            && (previous_model != next_model || previous_effort != next_effort)
        {
            let mut message = format!("Model changed to {next_model}");
            if !next_model.starts_with("codex-auto-") {
                let reasoning_label = match next_effort.as_ref() {
                    None | Some(ReasoningEffortConfig::None) => "default",
                    Some(effort) => effort.as_str(),
                };
                message.push(' ');
                message.push_str(reasoning_label);
            }
            message.push_str(" for ");
            message.push_str(next_mode.display_name());
            message.push_str(" mode.");
            self.add_info_message(message, /*hint*/ None);
        }
        self.request_redraw();
    }

    fn submit_collaboration_mode_settings_update(&self) {
        let Some(thread_id) = self.thread_id else {
            return;
        };
        self.app_event_tx.send(AppEvent::SubmitThreadOp {
            thread_id,
            op: AppCommand::override_turn_context(
                /*cwd*/ None,
                /*approval_policy*/ None,
                /*approvals_reviewer*/ None,
                /*permission_profile*/ None,
                /*active_permission_profile*/ None,
                /*windows_sandbox_level*/ None,
                /*model*/ None,
                /*effort*/ None,
                /*summary*/ None,
                /*service_tier*/ None,
                Some(self.effective_collaboration_mode()),
                /*personality*/ None,
            ),
        });
    }
}
