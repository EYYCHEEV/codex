//! Periodic recovery observes quota blocks and eligible uncertain refreshes without refreshing tokens.

use super::*;
use crate::status::ManagedAccountsState;
use codex_app_server_protocol::ManagedChatgptAccountRefreshStatus;
use std::time::Instant;

impl App {
    fn managed_pool_needs_recovery(&self) -> bool {
        self.chat_widget.managed_accounts().is_some_and(|pool| {
            // An uncertain refresh exchange can leave the existing access token eligible.
            // Observe its usage without replaying that exchange or changing healthy polling.
            let has_eligible_uncertain_refresh = pool.accounts().any(|account| {
                account.eligible
                    && matches!(
                        &account.refresh_status,
                        ManagedChatgptAccountRefreshStatus::ReloginRequired { reason_code, .. }
                            if matches!(
                                reason_code.as_str(),
                                "token_refresh_timeout"
                                    | "token_refresh_cancelled"
                                    | "token_refresh_commit_failed"
                            )
                    )
            });
            if has_eligible_uncertain_refresh {
                return true;
            }
            !pool.accounts().any(|account| account.eligible)
                && pool.accounts().any(|account| {
                    account.eligibility_reason.as_deref() == Some("blocked")
                        && account
                            .block
                            .as_ref()
                            .is_some_and(|block| block.reason == "quota")
                        && !matches!(
                            account.refresh_status,
                            ManagedChatgptAccountRefreshStatus::ReloginRequired { .. }
                        )
                })
        })
    }

    pub(super) fn rate_limit_poll_deadline(&mut self) -> Option<Instant> {
        if self
            .rate_limit_refresh_state
            .managed_usage
            .as_ref()
            .is_some_and(|origin| !self.is_current_managed_account_request(origin))
        {
            self.rate_limit_refresh_state.cancel_managed_usage();
        }
        if self.reconnect.offline {
            return None;
        }
        let interval = self.chat_widget.rate_limit_refresh_interval()?;
        if self.managed_pool_needs_recovery() {
            self.rate_limit_refresh_state
                .managed_poll_deadline(Instant::now())
        } else {
            self.rate_limit_refresh_state.reset_managed_backoff();
            self.rate_limit_refresh_state.poll_deadline(interval)
        }
    }

    pub(super) fn refresh_periodic_managed_pool(&mut self, app_server: &AppServerSession) -> bool {
        let Some(deadline) = self.rate_limit_poll_deadline() else {
            return true;
        };
        if !self.managed_pool_needs_recovery() {
            return false;
        }
        if deadline <= Instant::now() {
            self.refresh_managed_accounts_usage_cache(app_server);
        }
        true
    }

    pub(super) fn managed_usage_read_is_current(&self) -> bool {
        self.rate_limit_refresh_state
            .managed_usage
            .as_ref()
            .is_some_and(|origin| self.is_current_managed_account_request(origin))
    }

    pub(super) fn finish_managed_usage_read(&mut self, origin: &ManagedAccountRequestOrigin) {
        if self.rate_limit_refresh_state.managed_usage.as_ref() != Some(origin) {
            return;
        }
        if self.is_current_managed_account_request(origin) {
            let retry_needed = self.managed_pool_needs_recovery();
            self.rate_limit_refresh_state
                .finish_managed_usage(retry_needed, Instant::now());
        } else {
            self.rate_limit_refresh_state.cancel_managed_usage();
        }
    }

    pub(super) fn on_managed_observation_binding_changed(&mut self, app_server: &AppServerSession) {
        // A full usage read covers its own pool/selection notifications in either arrival order.
        // Still invalidate singular account-bound state, but do not stale that covering response.
        let covered = self.managed_usage_read_is_current();
        if !covered {
            self.invalidate_managed_account_requests();
        }
        // Notice prefetch reads singular auth and can proactively refresh OAuth even with
        // refreshToken=false. An automatic observation must only invalidate that notice.
        self.invalidate_managed_account_binding();
        if !covered {
            self.refresh_managed_accounts_usage_cache(app_server);
        }
    }

    pub(super) fn managed_usage_timeout(&self) -> Duration {
        // Accounts are processed serially, with two concurrent ten-second usage/profile GETs
        // per account. Allow overhead per row and for final owner selection, not just one GET.
        let accounts = self
            .chat_widget
            .managed_accounts()
            .map_or(/*default*/ 1, ManagedAccountsState::len) as u64;
        Duration::from_secs(15_u64.saturating_add(accounts.saturating_mul(20)))
    }
}
