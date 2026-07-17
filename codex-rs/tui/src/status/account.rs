use codex_app_server_protocol::AccountRateLimitsUpdatedNotification;
use codex_app_server_protocol::AccountUsageUpdatedNotification;
use codex_app_server_protocol::ListAccountsResponse;
use codex_app_server_protocol::ManagedChatgptAccountUsageState;
use codex_app_server_protocol::ManagedChatgptAccountView;
use codex_app_server_protocol::RateLimitSnapshot;
use std::collections::BTreeMap;

#[derive(Debug, Clone, PartialEq)]
pub(crate) struct ManagedAccountsState {
    accounts_by_id: BTreeMap<String, ManagedChatgptAccountView>,
    rate_limit_revision_by_account_id: BTreeMap<String, u64>,
    usage_revision_by_account_id: BTreeMap<String, u64>,
    selected_account_id: Option<String>,
    pending_selected_account_id: Option<String>,
    pool_revision: u64,
    selection_revision: u64,
}

impl ManagedAccountsState {
    pub(crate) fn from_response(response: ListAccountsResponse) -> Self {
        let selection_revision = response.selection_revision.unwrap_or(0);
        Self {
            accounts_by_id: response
                .accounts
                .into_iter()
                .map(|account| (account.managed_account_id.clone(), account))
                .collect(),
            rate_limit_revision_by_account_id: BTreeMap::new(),
            usage_revision_by_account_id: BTreeMap::new(),
            selected_account_id: response.selected_account_id,
            pending_selected_account_id: None,
            pool_revision: response.pool_revision,
            selection_revision,
        }
    }

    pub(crate) fn replace_accounts(
        &mut self,
        accounts: Vec<ManagedChatgptAccountView>,
        pool_revision: u64,
    ) -> bool {
        if pool_revision <= self.pool_revision {
            return false;
        }
        self.replace_accounts_preserving_newer_rows(accounts);
        self.pool_revision = pool_revision;
        true
    }

    pub(crate) fn replace_accounts_after_logout(
        &mut self,
        accounts: Vec<ManagedChatgptAccountView>,
        selected_account_id: Option<String>,
    ) {
        let previous_selected_account_id = self.selected_account_id.clone();
        self.replace_accounts_preserving_newer_rows(accounts);
        self.selected_account_id = previous_selected_account_id
            .filter(|selected| self.accounts_by_id.contains_key(selected))
            .or_else(|| {
                selected_account_id.filter(|selected| self.accounts_by_id.contains_key(selected))
            });
        self.pending_selected_account_id = None;
    }

    pub(crate) fn replace_from_response(&mut self, response: ListAccountsResponse) -> bool {
        let pool_updated = self.replace_accounts(response.accounts, response.pool_revision);
        let selection_updated = match response.selection_revision {
            Some(selection_revision) => {
                self.set_selected_account_id(response.selected_account_id, selection_revision)
            }
            None if pool_updated && self.selection_revision == 0 => {
                self.selected_account_id = response
                    .selected_account_id
                    .filter(|selected| self.accounts_by_id.contains_key(selected));
                true
            }
            None => false,
        };
        pool_updated || selection_updated
    }

    pub(crate) fn reset_selection_scope(&mut self) -> bool {
        let updated = self.selected_account_id.is_some()
            || self.pending_selected_account_id.is_some()
            || self.selection_revision != 0;
        self.selected_account_id = None;
        self.pending_selected_account_id = None;
        self.selection_revision = 0;
        updated
    }

    pub(crate) fn set_selected_account_id(
        &mut self,
        selected_account_id: Option<String>,
        selection_revision: u64,
    ) -> bool {
        if selection_revision <= self.selection_revision {
            return false;
        }
        match selected_account_id {
            Some(selected) if self.accounts_by_id.contains_key(&selected) => {
                self.selected_account_id = Some(selected);
                self.pending_selected_account_id = None;
            }
            Some(selected) => {
                self.selected_account_id = None;
                self.pending_selected_account_id = Some(selected);
            }
            None => {
                self.selected_account_id = None;
                self.pending_selected_account_id = None;
            }
        }
        self.selection_revision = selection_revision;
        true
    }

    fn replace_accounts_preserving_newer_rows(&mut self, accounts: Vec<ManagedChatgptAccountView>) {
        let previous = std::mem::take(&mut self.accounts_by_id);
        self.accounts_by_id = accounts
            .into_iter()
            .map(|incoming| {
                let managed_account_id = incoming.managed_account_id.clone();
                let account = previous
                    .get(&managed_account_id)
                    .filter(|current| current.account_revision > incoming.account_revision)
                    .cloned()
                    .unwrap_or(incoming);
                (managed_account_id, account)
            })
            .collect();
        self.rate_limit_revision_by_account_id
            .retain(|managed_account_id, _| self.accounts_by_id.contains_key(managed_account_id));
        self.usage_revision_by_account_id
            .retain(|managed_account_id, _| self.accounts_by_id.contains_key(managed_account_id));
        if let Some(pending) = self.pending_selected_account_id.as_ref()
            && self.accounts_by_id.contains_key(pending)
        {
            self.selected_account_id = self.pending_selected_account_id.take();
        } else if self
            .selected_account_id
            .as_ref()
            .is_some_and(|selected| !self.accounts_by_id.contains_key(selected))
        {
            self.selected_account_id = None;
        }
    }

    pub(crate) fn apply_rate_limits_update(
        &mut self,
        notification: &AccountRateLimitsUpdatedNotification,
    ) -> bool {
        let Some(managed_account_id) = notification.managed_account_id.as_ref() else {
            return false;
        };
        let Some(account_revision) = notification.account_revision else {
            return false;
        };
        let Some(account) = self.accounts_by_id.get_mut(managed_account_id) else {
            return false;
        };
        if account_revision < account.account_revision
            || self
                .rate_limit_revision_by_account_id
                .get(managed_account_id)
                .is_some_and(|last_revision| *last_revision >= account_revision)
        {
            return false;
        }
        let rate_limits_unavailable = notification.rate_limits.primary.is_none()
            && notification.rate_limits.secondary.is_none();
        merge_rate_limit_snapshot(
            &mut account.usage.rate_limits,
            notification.rate_limits.clone(),
        );
        if rate_limits_unavailable {
            account.usage.state = ManagedChatgptAccountUsageState::Unavailable;
            account.usage.unavailable_reason =
                Some("rate limit usage was absent from the response".to_string());
            account.usage.unavailable_observed_at = Some(chrono::Utc::now().timestamp());
        }
        account.account_revision = account_revision;
        self.rate_limit_revision_by_account_id
            .insert(managed_account_id.clone(), account_revision);
        true
    }

    pub(crate) fn apply_usage_update(
        &mut self,
        notification: &AccountUsageUpdatedNotification,
    ) -> bool {
        let Some(account) = self
            .accounts_by_id
            .get_mut(&notification.managed_account_id)
        else {
            return false;
        };
        if notification.account_revision < account.account_revision
            || self
                .usage_revision_by_account_id
                .get(&notification.managed_account_id)
                .is_some_and(|last_revision| *last_revision >= notification.account_revision)
        {
            return false;
        }
        let mut usage = notification.usage.clone();
        if usage.rate_limits.is_empty() {
            usage.rate_limits = account.usage.rate_limits.clone();
        }
        if usage.token_usage.is_none() {
            usage.token_usage = account.usage.token_usage.clone();
        }
        if usage.observed_at.is_none() {
            usage.observed_at = account.usage.observed_at;
        }
        account.usage = usage;
        account.account_revision = notification.account_revision;
        self.usage_revision_by_account_id.insert(
            notification.managed_account_id.clone(),
            notification.account_revision,
        );
        true
    }

    pub(crate) fn accounts(&self) -> impl ExactSizeIterator<Item = &ManagedChatgptAccountView> {
        self.accounts_by_id.values()
    }

    pub(crate) fn len(&self) -> usize {
        self.accounts_by_id.len()
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.accounts_by_id.is_empty()
    }

    pub(crate) fn selected_account_id(&self) -> Option<&str> {
        self.selected_account_id.as_deref()
    }

    pub(crate) fn selected_account(&self) -> Option<&ManagedChatgptAccountView> {
        self.selected_account_id
            .as_ref()
            .and_then(|selected| self.accounts_by_id.get(selected))
    }

    pub(crate) fn selected_account_binding_key(&self) -> Option<(String, Option<String>, u64)> {
        self.selected_account().map(|account| {
            (
                account.managed_account_id.clone(),
                account.chatgpt_account_id.clone(),
                account.credential_revision,
            )
        })
    }
}

pub(crate) fn managed_account_label(account: &ManagedChatgptAccountView) -> String {
    account
        .email
        .clone()
        .filter(|email| !email.trim().is_empty())
        .unwrap_or_else(|| format!("Managed account {}", account.managed_account_id))
}

fn merge_rate_limit_snapshot(
    snapshots: &mut Vec<RateLimitSnapshot>,
    mut incoming: RateLimitSnapshot,
) {
    let incoming_limit_id = incoming.limit_id.as_deref().unwrap_or("codex");
    let matching_index = snapshots
        .iter()
        .position(|snapshot| snapshot.limit_id.as_deref().unwrap_or("codex") == incoming_limit_id);
    if let Some(index) = matching_index {
        let previous = &snapshots[index];
        if incoming.limit_id.is_none() {
            incoming.limit_id.clone_from(&previous.limit_id);
        }
        if incoming.limit_name.is_none() {
            incoming.limit_name.clone_from(&previous.limit_name);
        }
        if incoming.primary.is_none() {
            incoming.primary.clone_from(&previous.primary);
        }
        if incoming.secondary.is_none() {
            incoming.secondary.clone_from(&previous.secondary);
        }
        if incoming.credits.is_none() {
            incoming.credits.clone_from(&previous.credits);
        }
        if incoming.individual_limit.is_none() {
            incoming
                .individual_limit
                .clone_from(&previous.individual_limit);
        }
        if incoming.plan_type.is_none() {
            incoming.plan_type = previous.plan_type;
        }
        if incoming.rate_limit_reached_type.is_none() {
            incoming.rate_limit_reached_type = previous.rate_limit_reached_type;
        }
        snapshots[index] = incoming;
    } else {
        snapshots.push(incoming);
    }
}

#[derive(Debug, Clone, PartialEq)]
pub(crate) enum StatusAccountDisplay {
    ChatGpt {
        email: Option<String>,
        plan: Option<String>,
    },
    ManagedChatGpt(ManagedAccountsState),
    ApiKey,
}

#[cfg(test)]
mod tests {
    use super::*;
    use codex_app_server_protocol::AccountTokenUsageSummary;
    use codex_app_server_protocol::ManagedChatgptAccountRefreshStatus;
    use codex_app_server_protocol::ManagedChatgptAccountUsage;
    use codex_app_server_protocol::ManagedChatgptAccountUsageState;
    use codex_app_server_protocol::RateLimitWindow;
    use codex_protocol::account::PlanType;

    fn account(id: &str, revision: u64) -> ManagedChatgptAccountView {
        ManagedChatgptAccountView {
            managed_account_id: id.to_string(),
            chatgpt_account_id: None,
            email: Some(format!("{id}@example.com")),
            plan_type: PlanType::Plus,
            eligible: true,
            eligibility_reason: None,
            account_revision: revision,
            credential_revision: 1,
            refresh_status: ManagedChatgptAccountRefreshStatus::Healthy,
            block: None,
            usage: ManagedChatgptAccountUsage {
                state: ManagedChatgptAccountUsageState::Unknown,
                rate_limits: Vec::new(),
                token_usage: None,
                observed_at: None,
                unavailable_reason: None,
                unavailable_observed_at: None,
            },
        }
    }

    #[test]
    fn pool_updates_preserve_selection_and_reject_stale_pool_and_row_revisions() {
        let mut state = ManagedAccountsState::from_response(ListAccountsResponse {
            accounts: vec![account("a", 2), account("b", 1)],
            selected_account_id: Some("a".to_string()),
            selection_revision: Some(1),
            pool_revision: 5,
        });

        assert!(state.replace_accounts(vec![account("a", 3), account("b", 2)], 6));
        assert_eq!(state.selected_account_id(), Some("a"));
        assert_eq!(
            state
                .accounts()
                .find(|account| account.managed_account_id == "a")
                .map(|account| account.account_revision),
            Some(3)
        );

        assert!(!state.replace_accounts(vec![account("b", 1)], 4));
        assert_eq!(state.len(), 2);
        assert_eq!(state.selected_account_id(), Some("a"));

        assert!(state.replace_accounts(vec![account("a", 2), account("b", 3)], 7));
        assert_eq!(
            state
                .accounts()
                .find(|account| account.managed_account_id == "a")
                .map(|account| account.account_revision),
            Some(3)
        );
    }

    #[test]
    fn selection_updates_reject_older_revisions_independently() {
        let mut state = ManagedAccountsState::from_response(ListAccountsResponse {
            accounts: vec![account("a", 1), account("b", 1)],
            selected_account_id: Some("a".to_string()),
            selection_revision: Some(1),
            pool_revision: 5,
        });

        assert!(state.set_selected_account_id(Some("b".to_string()), 9));
        assert!(!state.set_selected_account_id(Some("a".to_string()), 8));
        assert_eq!(state.selected_account_id(), Some("b"));
        assert!(state.replace_from_response(ListAccountsResponse {
            accounts: vec![account("a", 1), account("b", 1)],
            selected_account_id: Some("a".to_string()),
            selection_revision: Some(10),
            pool_revision: 5,
        }));
        assert_eq!(state.selected_account_id(), Some("a"));
    }

    #[test]
    fn selection_before_pool_preserves_pending_identity_until_matching_pool_arrives() {
        let mut state = ManagedAccountsState::from_response(ListAccountsResponse {
            accounts: vec![account("a", 1)],
            selected_account_id: Some("a".to_string()),
            selection_revision: Some(1),
            pool_revision: 5,
        });

        assert!(state.set_selected_account_id(Some("b".to_string()), 9));
        assert_eq!(state.selected_account_id(), None);
        assert_eq!(state.pending_selected_account_id.as_deref(), Some("b"));

        assert!(!state.replace_accounts(vec![account("a", 2)], 4));
        assert_eq!(state.pending_selected_account_id.as_deref(), Some("b"));
        assert!(!state.set_selected_account_id(Some("a".to_string()), 8));

        assert!(state.replace_accounts(vec![account("a", 2)], 6));
        assert_eq!(state.selected_account_id(), None);
        assert_eq!(state.pending_selected_account_id.as_deref(), Some("b"));

        assert!(state.replace_accounts(vec![account("a", 2), account("b", 1)], 7));
        assert_eq!(state.selected_account_id(), Some("b"));
        assert_eq!(state.pending_selected_account_id, None);
    }

    #[test]
    fn sparse_account_updates_reject_older_account_revisions() {
        let mut state = ManagedAccountsState::from_response(ListAccountsResponse {
            accounts: vec![account("a", 2)],
            selected_account_id: Some("a".to_string()),
            selection_revision: Some(1),
            pool_revision: 5,
        });
        let rate_limits = |account_revision| AccountRateLimitsUpdatedNotification {
            managed_account_id: Some("a".to_string()),
            account_revision: Some(account_revision),
            rate_limits: RateLimitSnapshot {
                limit_id: Some("codex".to_string()),
                limit_name: None,
                primary: None,
                secondary: None,
                credits: None,
                individual_limit: None,
                spend_control_reached: None,
                plan_type: None,
                rate_limit_reached_type: None,
            },
        };

        assert!(!state.apply_rate_limits_update(&rate_limits(1)));
        assert!(state.apply_rate_limits_update(&rate_limits(3)));
        assert!(!state.apply_rate_limits_update(&rate_limits(3)));
        assert_eq!(
            state
                .accounts()
                .next()
                .map(|account| account.account_revision),
            Some(3)
        );

        let usage = |account_revision, usage_state| AccountUsageUpdatedNotification {
            managed_account_id: "a".to_string(),
            account_revision,
            usage: ManagedChatgptAccountUsage {
                state: usage_state,
                rate_limits: Vec::new(),
                token_usage: None,
                observed_at: Some(1_700_000_000),
                unavailable_reason: None,
                unavailable_observed_at: None,
            },
        };
        assert!(
            !state.apply_usage_update(&usage(2, ManagedChatgptAccountUsageState::Unavailable,))
        );
        assert!(state.apply_usage_update(&usage(4, ManagedChatgptAccountUsageState::Fresh,)));
        assert!(
            !state.apply_usage_update(&usage(4, ManagedChatgptAccountUsageState::Unavailable,))
        );
        assert_eq!(
            state.accounts().next().map(|account| account.usage.state),
            Some(ManagedChatgptAccountUsageState::Fresh)
        );
        assert_eq!(
            state
                .accounts()
                .next()
                .map(|account| account.usage.rate_limits.len()),
            Some(1)
        );
    }

    #[test]
    fn full_pool_row_wins_when_sparse_rate_event_with_equal_revision_arrives_first() {
        let mut state = ManagedAccountsState::from_response(ListAccountsResponse {
            accounts: vec![account("a", 1)],
            selected_account_id: Some("a".to_string()),
            selection_revision: Some(1),
            pool_revision: 1,
        });
        assert!(
            state.apply_rate_limits_update(&AccountRateLimitsUpdatedNotification {
                managed_account_id: Some("a".to_string()),
                account_revision: Some(2),
                rate_limits: RateLimitSnapshot {
                    limit_id: Some("codex".to_string()),
                    limit_name: None,
                    primary: None,
                    secondary: None,
                    credits: None,
                    individual_limit: None,
                    spend_control_reached: None,
                    plan_type: None,
                    rate_limit_reached_type: None,
                },
            })
        );

        let mut full = account("a", 2);
        full.usage.state = ManagedChatgptAccountUsageState::Fresh;
        full.usage.observed_at = Some(1_700_000_000);
        assert!(state.replace_accounts(vec![full], 2));

        let merged = state.accounts().next().expect("full account row");
        assert_eq!(merged.account_revision, 2);
        assert_eq!(merged.usage.state, ManagedChatgptAccountUsageState::Fresh);
        assert_eq!(merged.usage.observed_at, Some(1_700_000_000));
    }

    #[test]
    fn equal_sparse_rate_event_after_full_row_merges_once_without_replacing_full_fields() {
        let mut full = account("a", 2);
        full.eligible = false;
        full.eligibility_reason = Some("workspace policy".to_string());
        full.usage.state = ManagedChatgptAccountUsageState::Fresh;
        full.usage.observed_at = Some(1_700_000_000);
        full.usage.rate_limits = vec![RateLimitSnapshot {
            limit_id: Some("codex".to_string()),
            limit_name: Some("Codex".to_string()),
            primary: Some(RateLimitWindow {
                used_percent: 25,
                window_duration_mins: Some(60),
                resets_at: Some(1_800_000_000),
            }),
            secondary: None,
            credits: None,
            individual_limit: None,
            spend_control_reached: None,
            plan_type: None,
            rate_limit_reached_type: None,
        }];
        let mut state = ManagedAccountsState::from_response(ListAccountsResponse {
            accounts: vec![full],
            selected_account_id: Some("a".to_string()),
            selection_revision: Some(1),
            pool_revision: 2,
        });
        let notification = AccountRateLimitsUpdatedNotification {
            managed_account_id: Some("a".to_string()),
            account_revision: Some(2),
            rate_limits: RateLimitSnapshot {
                limit_id: Some("codex".to_string()),
                limit_name: None,
                primary: None,
                secondary: None,
                credits: None,
                individual_limit: None,
                spend_control_reached: None,
                plan_type: None,
                rate_limit_reached_type: None,
            },
        };

        assert!(state.apply_rate_limits_update(&notification));
        assert!(!state.apply_rate_limits_update(&notification));
        let merged = state.accounts().next().expect("full account row");
        assert!(!merged.eligible);
        assert_eq!(
            merged.eligibility_reason.as_deref(),
            Some("workspace policy")
        );
        assert_eq!(
            merged.usage.state,
            ManagedChatgptAccountUsageState::Unavailable
        );
        assert_eq!(merged.usage.observed_at, Some(1_700_000_000));
        assert_eq!(
            merged.usage.unavailable_reason.as_deref(),
            Some("rate limit usage was absent from the response")
        );
        assert!(merged.usage.unavailable_observed_at.is_some());
        assert_eq!(merged.usage.rate_limits.len(), 1);
        assert_eq!(
            merged.usage.rate_limits[0]
                .primary
                .as_ref()
                .map(|window| window.used_percent),
            Some(25)
        );
        assert!(state.apply_usage_update(&AccountUsageUpdatedNotification {
            managed_account_id: "a".to_string(),
            account_revision: 2,
            usage: ManagedChatgptAccountUsage {
                state: ManagedChatgptAccountUsageState::Fresh,
                rate_limits: Vec::new(),
                token_usage: Some(AccountTokenUsageSummary {
                    lifetime_tokens: Some(99),
                    peak_daily_tokens: None,
                    longest_running_turn_sec: None,
                    current_streak_days: None,
                    longest_streak_days: None,
                }),
                observed_at: Some(1_700_000_100),
                unavailable_reason: None,
                unavailable_observed_at: None,
            },
        }));
        let merged = state.accounts().next().expect("equal revision usage merge");
        assert_eq!(merged.usage.state, ManagedChatgptAccountUsageState::Fresh);
        assert_eq!(merged.usage.rate_limits.len(), 1);
        assert_eq!(
            merged
                .usage
                .token_usage
                .as_ref()
                .and_then(|summary| summary.lifetime_tokens),
            Some(99)
        );
    }

    #[test]
    fn newer_sparse_usage_retains_cached_limits_and_token_summary() {
        let mut initial = account("a", 2);
        initial.usage.rate_limits = vec![RateLimitSnapshot {
            limit_id: Some("codex".to_string()),
            limit_name: Some("Codex".to_string()),
            primary: None,
            secondary: None,
            credits: None,
            individual_limit: None,
            spend_control_reached: None,
            plan_type: None,
            rate_limit_reached_type: None,
        }];
        initial.usage.token_usage = Some(AccountTokenUsageSummary {
            lifetime_tokens: Some(42),
            peak_daily_tokens: Some(12),
            longest_running_turn_sec: None,
            current_streak_days: None,
            longest_streak_days: None,
        });
        initial.usage.observed_at = Some(1_700_000_000);
        let mut state = ManagedAccountsState::from_response(ListAccountsResponse {
            accounts: vec![initial],
            selected_account_id: Some("a".to_string()),
            selection_revision: Some(1),
            pool_revision: 5,
        });

        let sparse = AccountUsageUpdatedNotification {
            managed_account_id: "a".to_string(),
            account_revision: 3,
            usage: ManagedChatgptAccountUsage {
                state: ManagedChatgptAccountUsageState::Unavailable,
                rate_limits: Vec::new(),
                token_usage: None,
                observed_at: None,
                unavailable_reason: Some("refresh failed".to_string()),
                unavailable_observed_at: Some(1_700_000_001),
            },
        };

        assert!(state.apply_usage_update(&sparse));
        let updated = state.accounts().next().expect("managed account");
        assert_eq!(updated.account_revision, 3);
        assert_eq!(
            updated.usage.state,
            ManagedChatgptAccountUsageState::Unavailable
        );
        assert_eq!(updated.usage.rate_limits.len(), 1);
        assert_eq!(
            updated
                .usage
                .token_usage
                .as_ref()
                .and_then(|summary| summary.lifetime_tokens),
            Some(42)
        );
        assert_eq!(updated.usage.observed_at, Some(1_700_000_000));

        let mut equal_revision = sparse.clone();
        equal_revision.usage.state = ManagedChatgptAccountUsageState::Fresh;
        assert!(!state.apply_usage_update(&equal_revision));
        let mut stale_revision = equal_revision;
        stale_revision.account_revision = 2;
        assert!(!state.apply_usage_update(&stale_revision));
        let retained = state.accounts().next().expect("managed account");
        assert_eq!(
            retained.usage.state,
            ManagedChatgptAccountUsageState::Unavailable
        );
        assert_eq!(retained.usage.rate_limits.len(), 1);
        assert_eq!(
            retained
                .usage
                .token_usage
                .as_ref()
                .and_then(|summary| summary.lifetime_tokens),
            Some(42)
        );
    }

    #[test]
    fn logout_response_updates_membership_and_thread_selection() {
        let mut state = ManagedAccountsState::from_response(ListAccountsResponse {
            accounts: vec![account("a", 1), account("b", 1)],
            selected_account_id: Some("a".to_string()),
            selection_revision: Some(5),
            pool_revision: 5,
        });

        state.replace_accounts_after_logout(vec![account("b", 2)], Some("b".to_string()));

        assert_eq!(state.selected_account_id(), Some("b"));
        assert_eq!(
            state
                .accounts()
                .map(|account| account.managed_account_id.as_str())
                .collect::<Vec<_>>(),
            vec!["b"]
        );
        assert!(!state.set_selected_account_id(Some("a".to_string()), 5));
        assert_eq!(state.selected_account_id(), Some("b"));
        assert!(state.set_selected_account_id(Some("b".to_string()), 6));
        assert_eq!(state.selected_account_id(), Some("b"));
    }
    #[test]
    fn nonselected_logout_preserves_thread_pin_before_scoped_list_supersedes_it() {
        let mut state = ManagedAccountsState::from_response(ListAccountsResponse {
            accounts: vec![account("a", 1), account("b", 1), account("c", 1)],
            selected_account_id: Some("a".to_string()),
            selection_revision: Some(5),
            pool_revision: 5,
        });

        state.replace_accounts_after_logout(
            vec![account("a", 2), account("c", 2)],
            Some("c".to_string()),
        );
        assert_eq!(state.selected_account_id(), Some("a"));

        assert!(state.replace_from_response(ListAccountsResponse {
            accounts: vec![account("a", 2), account("c", 2)],
            selected_account_id: Some("c".to_string()),
            selection_revision: Some(6),
            pool_revision: 6,
        }));
        assert_eq!(state.selected_account_id(), Some("c"));
    }

    #[test]
    fn empty_newer_pool_clears_rows_and_selected_marker() {
        let mut state = ManagedAccountsState::from_response(ListAccountsResponse {
            accounts: vec![account("a", 2)],
            selected_account_id: Some("a".to_string()),
            selection_revision: Some(7),
            pool_revision: 4,
        });

        assert!(state.replace_accounts(Vec::new(), 5));
        assert!(state.is_empty());
        assert_eq!(state.selected_account_id(), None);
        assert!(!state.replace_accounts(vec![account("a", 3)], 4));
        assert!(state.is_empty());
    }

    #[test]
    fn new_thread_scope_drops_prior_selection_revision() {
        let mut state = ManagedAccountsState::from_response(ListAccountsResponse {
            accounts: vec![account("a", 1), account("b", 1)],
            selected_account_id: Some("a".to_string()),
            selection_revision: Some(99),
            pool_revision: 4,
        });

        assert!(state.reset_selection_scope());
        assert_eq!(state.selected_account_id(), None);
        assert!(state.set_selected_account_id(Some("b".to_string()), 1));
        assert_eq!(state.selected_account_id(), Some("b"));
    }

    #[test]
    fn sparse_updates_require_the_matching_managed_account() {
        let mut state = ManagedAccountsState::from_response(ListAccountsResponse {
            accounts: vec![account("a", 1)],
            selected_account_id: Some("a".to_string()),
            selection_revision: Some(1),
            pool_revision: 1,
        });
        let notification = AccountUsageUpdatedNotification {
            managed_account_id: "b".to_string(),
            account_revision: 2,
            usage: ManagedChatgptAccountUsage {
                state: ManagedChatgptAccountUsageState::Fresh,
                rate_limits: Vec::new(),
                token_usage: None,
                observed_at: Some(1_700_000_000),
                unavailable_reason: None,
                unavailable_observed_at: None,
            },
        };

        assert!(!state.apply_usage_update(&notification));
        assert_eq!(
            state
                .accounts()
                .next()
                .map(|account| account.account_revision),
            Some(1)
        );
    }
}
