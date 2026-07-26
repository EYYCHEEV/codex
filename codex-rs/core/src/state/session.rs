//! Session-wide mutable state.

use codex_protocol::models::AdditionalPermissionProfile;
use codex_protocol::models::ResponseItem;
use codex_sandboxing::policy_transforms::merge_permission_profiles;
use std::collections::HashMap;
use std::collections::HashSet;
use std::collections::VecDeque;
use std::sync::Arc;
use std::sync::atomic::AtomicU64;
use std::sync::atomic::Ordering;

use super::AdditionalContextStore;
use super::auto_compact_window::AutoCompactWindow;
use super::auto_compact_window::AutoCompactWindowIds;
use super::auto_compact_window::AutoCompactWindowSnapshot;
use crate::context_manager::ContextManager;
use crate::session::PreviousTurnSettings;
use crate::session::session::SessionConfiguration;
use crate::session::time_reminder::CurrentTimeReminderState;
use crate::session_startup_prewarm::SessionStartupPrewarmHandle;
use codex_login::TransportAuthBinding;
use codex_protocol::protocol::RateLimitSnapshot;
use codex_protocol::protocol::TokenUsage;
use codex_protocol::protocol::TokenUsageInfo;
use codex_protocol::protocol::TurnContextItem;
use codex_utils_output_truncation::TruncationPolicy;

#[derive(Clone, Debug)]
pub(crate) struct ManagedRateLimitBinding {
    pub(crate) managed_account_id: String,
    pub(crate) account_state_revision: u64,
    pub(crate) transport_binding: TransportAuthBinding,
    pub(crate) shared_account_state_revision: Option<Arc<AtomicU64>>,
}

impl ManagedRateLimitBinding {
    fn effective_account_state_revision(&self) -> u64 {
        self.shared_account_state_revision
            .as_ref()
            .map_or(self.account_state_revision, |revision| {
                revision.load(Ordering::Acquire)
            })
    }

    pub(crate) fn refreshed(&self) -> Self {
        let mut binding = self.clone();
        binding.account_state_revision = self.effective_account_state_revision();
        binding
    }
}

impl PartialEq for ManagedRateLimitBinding {
    fn eq(&self, other: &Self) -> bool {
        if self.managed_account_id != other.managed_account_id
            || self.transport_binding != other.transport_binding
        {
            return false;
        }
        match (
            self.shared_account_state_revision.as_ref(),
            other.shared_account_state_revision.as_ref(),
        ) {
            (Some(left), Some(right)) if Arc::ptr_eq(left, right) => true,
            _ => {
                self.effective_account_state_revision() == other.effective_account_state_revision()
            }
        }
    }
}

impl Eq for ManagedRateLimitBinding {}

#[derive(Clone)]
pub(crate) struct LatestRateLimits {
    pub(crate) snapshot: RateLimitSnapshot,
    pub(crate) managed_binding: Option<ManagedRateLimitBinding>,
}
#[derive(Clone)]
struct PendingManagedRateLimits {
    snapshot: RateLimitSnapshot,
    managed_account_id: String,
    account_state_revision: u64,
    transport_binding: Option<TransportAuthBinding>,
}

/// Persistent, session-scoped state previously stored directly on `Session`.
pub(crate) struct SessionState {
    pub(crate) session_configuration: SessionConfiguration,
    pub(crate) history: ContextManager,
    pub(crate) latest_rate_limits: Option<LatestRateLimits>,
    current_managed_rate_limit_binding: Option<ManagedRateLimitBinding>,
    pending_managed_rate_limits: Option<PendingManagedRateLimits>,
    pub(crate) server_reasoning_included: bool,
    pub(crate) mcp_dependency_prompted: HashSet<String>,
    pub(crate) additional_context: AdditionalContextStore,
    /// Settings used by the latest regular user turn, used for turn-to-turn
    /// model/realtime handling on subsequent regular turns (including full-context
    /// reinjection after resume or `/compact`).
    previous_turn_settings: Option<PreviousTurnSettings>,
    /// Runtime accounting state for the active auto-compaction window.
    auto_compact_window: AutoCompactWindow,
    /// Startup prewarmed session prepared during session initialization.
    pub(crate) startup_prewarm: Option<SessionStartupPrewarmHandle>,
    pub(crate) current_time_reminder: CurrentTimeReminderState,
    pub(crate) active_connector_selection: HashSet<String>,
    pub(crate) pending_session_start_sources: VecDeque<codex_hooks::SessionStartSource>,
    granted_permissions_by_environment_id: HashMap<String, AdditionalPermissionProfile>,
    next_turn_is_first: bool,
}

impl SessionState {
    /// Create a new session state mirroring previous `State::default()` semantics.
    #[cfg(test)]
    pub(crate) fn new(session_configuration: SessionConfiguration) -> Self {
        Self::new_with_auto_compact_window_ids(
            session_configuration,
            AutoCompactWindowIds::new_initial(),
        )
    }

    pub(crate) fn new_with_auto_compact_window_ids(
        session_configuration: SessionConfiguration,
        auto_compact_window_ids: AutoCompactWindowIds,
    ) -> Self {
        let history = ContextManager::new();
        Self {
            session_configuration,
            history,
            latest_rate_limits: None,
            current_managed_rate_limit_binding: None,
            pending_managed_rate_limits: None,
            server_reasoning_included: false,
            mcp_dependency_prompted: HashSet::new(),
            additional_context: AdditionalContextStore::default(),
            previous_turn_settings: None,
            auto_compact_window: AutoCompactWindow::new_with_ids(auto_compact_window_ids),
            startup_prewarm: None,
            current_time_reminder: CurrentTimeReminderState::default(),
            active_connector_selection: HashSet::new(),
            pending_session_start_sources: VecDeque::new(),
            granted_permissions_by_environment_id: HashMap::new(),
            next_turn_is_first: true,
        }
    }

    // History helpers
    pub(crate) fn record_items<I>(&mut self, items: I, policy: TruncationPolicy)
    where
        I: IntoIterator,
        I::Item: std::ops::Deref<Target = ResponseItem>,
    {
        self.history.record_items(items, policy);
    }

    pub(crate) fn previous_turn_settings(&self) -> Option<PreviousTurnSettings> {
        self.previous_turn_settings.clone()
    }
    pub(crate) fn set_previous_turn_settings(
        &mut self,
        previous_turn_settings: Option<PreviousTurnSettings>,
    ) {
        self.previous_turn_settings = previous_turn_settings;
    }

    pub(crate) fn set_next_turn_is_first(&mut self, value: bool) {
        self.next_turn_is_first = value;
    }

    pub(crate) fn take_next_turn_is_first(&mut self) -> bool {
        let is_first_turn = self.next_turn_is_first;
        self.next_turn_is_first = false;
        is_first_turn
    }

    pub(crate) fn clone_history(&self) -> ContextManager {
        self.history.clone()
    }

    pub(crate) fn replace_history(
        &mut self,
        items: Vec<ResponseItem>,
        reference_context_item: Option<TurnContextItem>,
    ) {
        self.history.replace(items);
        self.history
            .set_reference_context_item(reference_context_item);
        self.auto_compact_window.clear_prefill();
    }

    pub(crate) fn set_token_info(&mut self, info: Option<TokenUsageInfo>) {
        self.history.set_token_info(info);
    }

    pub(crate) fn set_reference_context_item(&mut self, item: Option<TurnContextItem>) {
        self.history.set_reference_context_item(item);
    }

    pub(crate) fn reference_context_item(&self) -> Option<TurnContextItem> {
        self.history.reference_context_item()
    }

    // Token/rate limit helpers
    pub(crate) fn update_token_info_from_usage(
        &mut self,
        usage: &TokenUsage,
        model_context_window: Option<i64>,
    ) {
        self.history.update_token_info(usage, model_context_window);
    }

    pub(crate) fn ensure_auto_compact_window_server_prefill_from_usage(
        &mut self,
        usage: &TokenUsage,
    ) {
        self.auto_compact_window
            .ensure_server_observed_prefill_from_usage(usage);
    }

    pub(crate) fn set_auto_compact_window_estimated_prefill(&mut self, tokens: i64) {
        self.auto_compact_window.set_estimated_prefill(tokens);
    }

    pub(crate) fn auto_compact_window_snapshot(&self) -> AutoCompactWindowSnapshot {
        self.auto_compact_window.snapshot()
    }

    pub(crate) fn claim_token_budget_reminder(&mut self) -> bool {
        self.auto_compact_window.claim_token_budget_reminder()
    }

    pub(crate) fn claim_auto_compact_fallback(&mut self) -> bool {
        self.auto_compact_window.claim_auto_compact_fallback()
    }

    pub(crate) fn auto_compact_window_number(&self) -> u64 {
        self.auto_compact_window.window_number()
    }

    pub(crate) fn auto_compact_window_ids(&self) -> AutoCompactWindowIds {
        self.auto_compact_window.ids()
    }

    pub(crate) fn restore_auto_compact_window(
        &mut self,
        window_number: u64,
        ids: AutoCompactWindowIds,
    ) {
        self.auto_compact_window.restore(window_number, ids);
    }

    pub(crate) fn advance_auto_compact_window(&mut self) -> (u64, AutoCompactWindowIds) {
        self.auto_compact_window.advance()
    }

    pub(crate) fn request_new_context_window(&mut self) {
        self.auto_compact_window.request_new_context_window();
    }

    pub(crate) fn take_new_context_window_request(&mut self) -> bool {
        self.auto_compact_window.take_new_context_window_request()
    }

    pub(crate) fn start_new_context_window(&mut self) -> (u64, AutoCompactWindowIds) {
        let window = self.auto_compact_window.advance();
        self.auto_compact_window.clear_prefill();
        window
    }

    pub(crate) fn token_info(&self) -> Option<TokenUsageInfo> {
        self.history.token_info()
    }

    pub(crate) fn observe_managed_rate_limit_binding(
        &mut self,
        binding: Option<&ManagedRateLimitBinding>,
    ) {
        let Some(binding) = binding else {
            self.pending_managed_rate_limits = None;
            if self
                .latest_rate_limits
                .as_ref()
                .is_some_and(|latest| latest.managed_binding.is_some())
            {
                self.latest_rate_limits = None;
            }
            self.current_managed_rate_limit_binding = None;
            return;
        };
        if let Some(pending) = self.pending_managed_rate_limits.take()
            && pending.managed_account_id == binding.managed_account_id
            && pending.account_state_revision == binding.effective_account_state_revision()
            && pending.transport_binding.as_ref() == Some(&binding.transport_binding)
        {
            self.latest_rate_limits = Some(LatestRateLimits {
                snapshot: pending.snapshot,
                managed_binding: Some(binding.clone()),
            });
        }
        if self
            .latest_rate_limits
            .as_ref()
            .is_some_and(|latest| latest.managed_binding.as_ref() != Some(binding))
        {
            self.latest_rate_limits = None;
        }
        self.current_managed_rate_limit_binding = Some(binding.clone());
    }

    pub(crate) fn set_rate_limits(
        &mut self,
        mut snapshot: RateLimitSnapshot,
        managed_binding: Option<ManagedRateLimitBinding>,
    ) {
        normalize_rate_limit_snapshot(&mut snapshot);
        let previous = self.latest_rate_limits.as_ref().and_then(|latest| {
            (latest.managed_binding == managed_binding).then_some(&latest.snapshot)
        });
        if snapshot.limit_id.as_deref() != Some("codex")
            && let Some(prior) = previous.filter(|prior| prior.limit_id.as_deref() == Some("codex"))
        {
            let mut canonical = prior.clone();
            if snapshot.credits.is_some() {
                canonical.credits = snapshot.credits;
            }
            if snapshot.individual_limit.is_some() {
                canonical.individual_limit = snapshot.individual_limit;
            }
            if snapshot.spend_control_reached.is_some() {
                canonical.spend_control_reached = snapshot.spend_control_reached;
            }
            if snapshot.plan_type.is_some() {
                canonical.plan_type = snapshot.plan_type;
            }
            self.current_managed_rate_limit_binding = managed_binding.clone();
            self.latest_rate_limits = Some(LatestRateLimits {
                snapshot: canonical,
                managed_binding,
            });
            return;
        }
        self.current_managed_rate_limit_binding = managed_binding.clone();
        self.latest_rate_limits = Some(LatestRateLimits {
            snapshot: merge_rate_limit_fields(previous, snapshot),
            managed_binding,
        });
    }

    pub(crate) fn token_info_and_rate_limits(
        &self,
    ) -> (
        Option<TokenUsageInfo>,
        Option<RateLimitSnapshot>,
        Option<ManagedRateLimitBinding>,
    ) {
        let latest = self.latest_rate_limits.as_ref();
        (
            self.token_info(),
            latest.map(|latest| latest.snapshot.clone()),
            self.current_managed_rate_limit_binding
                .as_ref()
                .map(ManagedRateLimitBinding::refreshed),
        )
    }

    pub(crate) fn restore_rate_limits(
        &mut self,
        mut snapshot: RateLimitSnapshot,
        managed_binding: Option<ManagedRateLimitBinding>,
    ) {
        normalize_rate_limit_snapshot(&mut snapshot);
        self.current_managed_rate_limit_binding = managed_binding.clone();
        self.latest_rate_limits = Some(LatestRateLimits {
            snapshot,
            managed_binding,
        });
    }
    pub(crate) fn restore_pending_managed_rate_limits(
        &mut self,
        mut snapshot: RateLimitSnapshot,
        managed_account_id: String,
        account_state_revision: u64,
        transport_binding: Option<TransportAuthBinding>,
    ) {
        normalize_rate_limit_snapshot(&mut snapshot);
        self.pending_managed_rate_limits = Some(PendingManagedRateLimits {
            snapshot,
            managed_account_id,
            account_state_revision,
            transport_binding,
        });
    }

    pub(crate) fn set_token_usage_full(&mut self, context_window: i64) {
        self.history.set_token_usage_full(context_window);
    }

    pub(crate) fn get_total_token_usage(&self, server_reasoning_included: bool) -> i64 {
        self.history
            .get_total_token_usage(server_reasoning_included)
    }

    pub(crate) fn set_server_reasoning_included(&mut self, included: bool) {
        self.server_reasoning_included = included;
    }

    pub(crate) fn server_reasoning_included(&self) -> bool {
        self.server_reasoning_included
    }

    pub(crate) fn record_mcp_dependency_prompted<I>(&mut self, names: I)
    where
        I: IntoIterator<Item = String>,
    {
        self.mcp_dependency_prompted.extend(names);
    }

    pub(crate) fn mcp_dependency_prompted(&self) -> HashSet<String> {
        self.mcp_dependency_prompted.clone()
    }

    pub(crate) fn set_session_startup_prewarm(
        &mut self,
        startup_prewarm: SessionStartupPrewarmHandle,
    ) {
        self.startup_prewarm = Some(startup_prewarm);
    }

    pub(crate) fn take_session_startup_prewarm(&mut self) -> Option<SessionStartupPrewarmHandle> {
        self.startup_prewarm.take()
    }

    // Adds connector IDs to the active set and returns the merged selection.
    pub(crate) fn merge_connector_selection<I>(&mut self, connector_ids: I) -> HashSet<String>
    where
        I: IntoIterator<Item = String>,
    {
        self.active_connector_selection.extend(connector_ids);
        self.active_connector_selection.clone()
    }

    // Returns the current connector selection tracked on session state.
    pub(crate) fn get_connector_selection(&self) -> HashSet<String> {
        self.active_connector_selection.clone()
    }

    // Removes all currently tracked connector selections.
    pub(crate) fn clear_connector_selection(&mut self) {
        self.active_connector_selection.clear();
    }

    pub(crate) fn queue_pending_session_start_source(
        &mut self,
        value: codex_hooks::SessionStartSource,
    ) {
        self.pending_session_start_sources.push_back(value);
    }

    pub(crate) fn take_pending_session_start_source(
        &mut self,
    ) -> Option<codex_hooks::SessionStartSource> {
        self.pending_session_start_sources.pop_front()
    }

    pub(crate) fn record_granted_permissions(
        &mut self,
        environment_id: &str,
        permissions: AdditionalPermissionProfile,
    ) {
        let granted_permissions = merge_permission_profiles(
            self.granted_permissions_by_environment_id
                .get(environment_id),
            Some(&permissions),
        );
        if let Some(granted_permissions) = granted_permissions {
            self.granted_permissions_by_environment_id
                .insert(environment_id.to_string(), granted_permissions);
        }
    }

    pub(crate) fn granted_permissions(
        &self,
        environment_id: &str,
    ) -> Option<AdditionalPermissionProfile> {
        self.granted_permissions_by_environment_id
            .get(environment_id)
            .cloned()
    }
}

fn normalize_rate_limit_snapshot(snapshot: &mut RateLimitSnapshot) {
    if snapshot.limit_id.is_none() {
        snapshot.limit_id = Some("codex".to_string());
    }
}

// Sparse snapshots omit fields that were not present on a response. Preserve
// per-window data only within the same limit bucket, while account-level
// metadata remains shared across buckets.
fn merge_rate_limit_fields(
    previous: Option<&RateLimitSnapshot>,
    mut snapshot: RateLimitSnapshot,
) -> RateLimitSnapshot {
    let previous_same_limit = previous.filter(|prior| prior.limit_id == snapshot.limit_id);
    if snapshot.limit_name.is_none() {
        snapshot.limit_name = previous_same_limit.and_then(|prior| prior.limit_name.clone());
    }
    if snapshot.primary.is_none() {
        snapshot.primary = previous_same_limit.and_then(|prior| prior.primary.clone());
    }
    if snapshot.secondary.is_none() {
        snapshot.secondary = previous_same_limit.and_then(|prior| prior.secondary.clone());
    }
    if snapshot.credits.is_none() {
        snapshot.credits = previous.and_then(|prior| prior.credits.clone());
    }
    if snapshot.individual_limit.is_none() {
        snapshot.individual_limit = previous.and_then(|prior| prior.individual_limit.clone());
    }
    if snapshot.spend_control_reached.is_none() {
        snapshot.spend_control_reached = previous.and_then(|prior| prior.spend_control_reached);
    }
    if snapshot.plan_type.is_none() {
        snapshot.plan_type = previous.and_then(|prior| prior.plan_type);
    }
    if snapshot.rate_limit_reached_type.is_none() {
        snapshot.rate_limit_reached_type =
            previous_same_limit.and_then(|prior| prior.rate_limit_reached_type);
    }
    snapshot
}

#[cfg(test)]
#[path = "session_tests.rs"]
mod tests;
