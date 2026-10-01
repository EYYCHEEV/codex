use crate::JsonSchema;
use crate::TS;
use codex_protocol::account::PlanType;
use serde::Deserialize;
use serde::Serialize;
use serde_json::Value;

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, JsonSchema, TS)]
#[serde(rename_all = "camelCase")]
#[ts(export_to = "v2/")]
pub struct AccountAnalyticsReadParams {
    #[ts(optional = nullable)]
    pub thread_id: Option<String>,
    #[ts(optional = nullable)]
    pub expected_binding: Option<AccountAnalyticsBinding>,
    pub query: AccountAnalyticsQuery,
}

/// Non-secret identity of a captured account, credential generation, and policy.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq, Hash, JsonSchema, TS)]
#[serde(rename_all = "camelCase")]
#[ts(export_to = "v2/")]
pub struct AccountAnalyticsBinding {
    pub thread_id: Option<String>,
    pub session_id: Option<String>,
    pub managed_account_id: Option<String>,
    pub account_id: String,
    pub user_id: String,
    #[ts(type = "number | null")]
    pub credential_revision: Option<u64>,
    #[ts(type = "number")]
    pub routing_revision: u64,
    #[ts(type = "number")]
    pub policy_revision: u64,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, JsonSchema, TS)]
#[serde(rename_all = "camelCase")]
#[ts(export_to = "v2/")]
pub struct AccountAnalyticsReadResponse {
    pub binding: AccountAnalyticsBinding,
    pub email: Option<String>,
    pub plan_type: Option<PlanType>,
    /// Validated backend report data; the upstream report's field names are retained.
    pub data: Value,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, JsonSchema, TS)]
#[serde(tag = "type", rename_all = "camelCase")]
#[ts(tag = "type", rename_all = "camelCase", export_to = "v2/")]
pub enum AccountAnalyticsQuery {
    Validate,
    Account,
    Profile,
    PlanHistory,
    History {
        report: AccountAnalyticsReport,
        /// Inclusive UTC dates in YYYY-MM-DD form.
        start: String,
        end: String,
    },
    Threads {
        ids: Vec<String>,
    },
    Tasks {
        threads: Vec<AccountAnalyticsTaskParams>,
    },
}

#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq, Hash, JsonSchema, TS)]
#[serde(tag = "type", rename_all = "camelCase")]
#[ts(tag = "type", rename_all = "camelCase", export_to = "v2/")]
pub enum AccountAnalyticsReport {
    Usage,
    EnterpriseTokens,
    Credits,
    WorkspaceCredits,
    EnterpriseCredits {
        breakdown: AccountAnalyticsCreditBreakdown,
    },
    Messages,
    Plugins {
        limit: u8,
    },
    Skills {
        limit: u8,
    },
}

#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq, Hash, JsonSchema, TS)]
#[serde(rename_all = "camelCase")]
#[ts(rename_all = "camelCase", export_to = "v2/")]
pub enum AccountAnalyticsCreditBreakdown {
    Product,
    Model,
    Speed,
    ReasoningEffort,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq, JsonSchema, TS)]
#[serde(rename_all = "camelCase")]
#[ts(export_to = "v2/")]
pub struct AccountAnalyticsTaskParams {
    pub thread_id: String,
    #[ts(optional = nullable)]
    pub created_at: Option<String>,
    pub descendant_thread_ids: Vec<String>,
}
