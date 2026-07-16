use super::account::AccountTokenUsageSummary;
use super::account::RateLimitSnapshot;
use crate::JsonSchema;
use crate::TS;
use codex_protocol::account::PlanType;
use serde::Deserialize;
use serde::Serialize;

/// Parameters for the canonical managed ChatGPT account-pool listing.
#[derive(Serialize, Deserialize, Debug, Default, Clone, PartialEq, Eq, JsonSchema, TS)]
#[serde(rename_all = "camelCase")]
#[ts(export_to = "v2/")]
pub struct ListAccountsParams {
    /// Selects the account pinned to this thread when present.
    #[serde(default)]
    #[ts(optional = nullable)]
    pub thread_id: Option<String>,
    /// Model used when computing a scoped account selection.
    #[serde(default)]
    #[ts(optional = nullable)]
    pub model: Option<String>,
    /// Refresh due managed OAuth tokens before returning the list.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub refresh_tokens: bool,
    /// Refresh account usage before returning the list.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub refresh_usage: bool,
}

/// Outcome of the most recent managed OAuth token refresh.
///
/// This is intentionally separate from selection eligibility, account blocks,
/// and usage freshness. Failure variants contain only stable, non-secret
/// metadata and never carry backend error text.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq, JsonSchema, TS)]
#[serde(tag = "type", rename_all = "camelCase")]
#[ts(tag = "type")]
#[ts(export_to = "v2/")]
pub enum ManagedChatgptAccountRefreshStatus {
    Healthy,
    #[serde(rename_all = "camelCase")]
    #[ts(rename_all = "camelCase")]
    TransientUnavailable {
        /// Unix timestamp in seconds when the refresh outcome was observed.
        #[ts(type = "number")]
        observed_at: i64,
    },
    #[serde(rename_all = "camelCase")]
    #[ts(rename_all = "camelCase")]
    ReloginRequired {
        /// Stable machine-readable classification; never raw backend text.
        reason_code: String,
        /// Unix timestamp in seconds when the refresh outcome was observed.
        #[ts(type = "number")]
        observed_at: i64,
    },
}

/// Public managed-OAuth account view.
///
/// `managed_account_id` is the stable identity used to key every other field in
/// this row. Consumers must not join account data by array position, email, or
/// the optional raw ChatGPT account ID.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, JsonSchema, TS)]
#[serde(rename_all = "camelCase")]
#[ts(export_to = "v2/")]
pub struct ManagedChatgptAccountView {
    pub managed_account_id: String,
    pub chatgpt_account_id: Option<String>,
    pub email: Option<String>,
    pub plan_type: PlanType,
    pub eligible: bool,
    pub eligibility_reason: Option<String>,
    #[ts(type = "number")]
    pub account_revision: u64,
    /// Monotonic revision of the credential generation backing this account.
    ///
    /// Unlike `account_revision`, status and usage observations do not change it.
    #[ts(type = "number")]
    pub credential_revision: u64,
    pub refresh_status: ManagedChatgptAccountRefreshStatus,
    pub block: Option<ManagedChatgptAccountBlock>,
    pub usage: ManagedChatgptAccountUsage,
}

/// An active account block or cooldown.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq, JsonSchema, TS)]
#[serde(rename_all = "camelCase")]
#[ts(export_to = "v2/")]
pub struct ManagedChatgptAccountBlock {
    /// Stable machine-readable classification supplied by the account-pool owner.
    pub reason: String,
    /// Unix timestamp in seconds when the cooldown expires. `null` means the
    /// block has no known automatic expiry.
    #[ts(type = "number | null")]
    pub blocked_until: Option<i64>,
}

/// Freshness and availability of a managed account's usage observation.
#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq, JsonSchema, TS)]
#[serde(rename_all = "camelCase")]
#[ts(export_to = "v2/", rename_all = "camelCase")]
pub enum ManagedChatgptAccountUsageState {
    /// No usage observation has been recorded.
    Unknown,
    /// The observation is current.
    Fresh,
    /// The last known observation is older than the freshness window.
    Stale,
    /// A refresh was attempted but usage could not be obtained.
    Unavailable,
}

/// Account-keyed usage data. Rate-limit entries carry their own `limitId`, so
/// additional metered limits cannot be mistaken for the singular compatibility
/// projection returned by `account/rateLimits/read`.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, JsonSchema, TS)]
#[serde(rename_all = "camelCase")]
#[ts(export_to = "v2/")]
pub struct ManagedChatgptAccountUsage {
    pub state: ManagedChatgptAccountUsageState,
    pub rate_limits: Vec<RateLimitSnapshot>,
    pub token_usage: Option<AccountTokenUsageSummary>,
    /// Unix timestamp in seconds for the retained observation.
    #[ts(type = "number | null")]
    pub observed_at: Option<i64>,
    /// Diagnostic text for `unavailable`, or `null` for other states.
    pub unavailable_reason: Option<String>,
    /// Unix timestamp in seconds for the failed refresh represented by
    /// `unavailable_reason`. This is independent from the retained successful
    /// observation timestamp.
    #[ts(type = "number | null")]
    pub unavailable_observed_at: Option<i64>,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, JsonSchema, TS)]
#[serde(rename_all = "camelCase")]
#[ts(export_to = "v2/")]
pub struct ListAccountsResponse {
    pub accounts: Vec<ManagedChatgptAccountView>,
    pub selected_account_id: Option<String>,
    /// Scoped selected-account revision when the list was requested for a thread,
    /// or `null` for an unscoped list.
    #[ts(type = "number | null")]
    pub selection_revision: Option<u64>,
    /// Monotonic revision of global account-pool membership and account data.
    #[ts(type = "number")]
    pub pool_revision: u64,
}

#[derive(Serialize, Deserialize, Debug, Default, Clone, PartialEq, Eq, JsonSchema, TS)]
#[serde(rename_all = "camelCase")]
#[ts(export_to = "v2/")]
pub struct LogoutAccountParams {
    #[serde(default)]
    #[ts(optional = nullable)]
    pub account_id: Option<String>,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub all: bool,
}

#[derive(Serialize, Deserialize, Debug, Default, Clone, PartialEq, JsonSchema, TS)]
#[serde(rename_all = "camelCase")]
#[ts(export_to = "v2/")]
pub struct LogoutAccountResponse {
    #[serde(default)]
    pub removed_account_ids: Vec<String>,
    #[serde(default)]
    pub accounts: Vec<ManagedChatgptAccountView>,
    #[serde(default)]
    pub selected_account_id: Option<String>,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, JsonSchema, TS)]
#[serde(rename_all = "camelCase")]
#[ts(export_to = "v2/")]
pub struct AccountPoolUpdatedNotification {
    pub accounts: Vec<ManagedChatgptAccountView>,
    /// Monotonic revision of global account-pool membership and account data.
    #[ts(type = "number")]
    pub pool_revision: u64,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq, JsonSchema, TS)]
#[serde(rename_all = "camelCase")]
#[ts(export_to = "v2/")]
pub struct AccountSelectionUpdatedNotification {
    pub thread_id: String,
    pub selected_account_id: Option<String>,
    /// Monotonic revision of this thread's selected-account state.
    #[ts(type = "number")]
    pub selection_revision: u64,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, JsonSchema, TS)]
#[serde(rename_all = "camelCase")]
#[ts(export_to = "v2/")]
pub struct AccountUsageUpdatedNotification {
    pub managed_account_id: String,
    /// Revision of the managed account row carrying this usage observation.
    #[ts(type = "number")]
    pub account_revision: u64,
    pub usage: ManagedChatgptAccountUsage,
}
