//! Reports use the connected server's selected account, credentials, and admitted network policy.
//! Cached responses belong to the captured account and credential generation.
//! Every report uses the view's captured end date until refresh replaces the session.

use super::models::AccountAnalyticsGrouping as Grouping;
use super::models::AccountAnalyticsReport as Report;
use super::models::AccountKind;
use super::report_data::AnalyticsData;
use codex_app_server_client::AppServerRequestHandle;
use codex_app_server_client::TypedRequestError;
use codex_app_server_protocol::AccountAnalyticsCreditBreakdown as Breakdown;
use codex_app_server_protocol::AccountAnalyticsQuery as Query;
use codex_app_server_protocol::AccountAnalyticsReadParams;
use codex_app_server_protocol::AccountAnalyticsReadResponse;
use codex_app_server_protocol::AccountAnalyticsReport as AnalyticsReport;
use codex_app_server_protocol::ClientRequest;
use codex_app_server_protocol::RequestId;
use codex_backend_client::AnalyticsResponse;
use codex_protocol::account::PlanType;
use serde::de::DeserializeOwned;
use std::collections::HashMap;
use tokio::sync::Mutex;
use tokio::sync::OnceCell;

pub(super) struct Live {
    pub(super) identity_invalidated: std::sync::atomic::AtomicBool,
    handle: AppServerRequestHandle,
    thread_id: Option<String>,
    end_date: chrono::NaiveDate,
    session: OnceCell<Session>,
    token_models: std::sync::RwLock<Vec<String>>,
    attributed_usage: std::sync::atomic::AtomicBool,
}

pub(super) struct Session {
    pub(super) kind: AccountKind,
    pub(super) account: AccountAnalyticsReadResponse,
    handle: AppServerRequestHandle,
    credit_groups: Vec<usize>,
    cache: Mutex<HashMap<(AnalyticsReport, String, String), AnalyticsData>>,
}

impl Session {
    pub(super) async fn request<T: DeserializeOwned>(
        &self,
        query: Query,
    ) -> Result<T, TypedRequestError> {
        let response: AccountAnalyticsReadResponse = self
            .handle
            .request_typed(ClientRequest::AccountAnalyticsRead {
                request_id: RequestId::String(uuid::Uuid::new_v4().to_string()),
                params: AccountAnalyticsReadParams {
                    thread_id: self.account.binding.thread_id.clone(),
                    expected_binding: Some(self.account.binding.clone()),
                    query,
                },
            })
            .await?;
        serde_json::from_value(response.data).map_err(|source| TypedRequestError::Deserialize {
            method: "account/analytics/read".into(),
            source,
        })
    }
}

impl Live {
    pub(super) fn new(
        handle: AppServerRequestHandle,
        thread_id: Option<String>,
        end_date: chrono::NaiveDate,
    ) -> Self {
        Self {
            identity_invalidated: std::sync::atomic::AtomicBool::new(/*v*/ false),
            handle,
            thread_id,
            end_date,
            session: OnceCell::new(),
            token_models: std::sync::RwLock::new(Vec::new()),
            attributed_usage: std::sync::atomic::AtomicBool::new(/*v*/ true),
        }
    }

    pub(super) fn account_label(&self) -> Option<String> {
        let session = self.session.get()?;
        session.account.email.clone()
    }

    pub(super) fn credit_groups(&self) -> &[usize] {
        self.session
            .get()
            .map_or(&[0], |session| &session.credit_groups)
    }

    pub(super) fn attributed_usage(&self) -> bool {
        self.attributed_usage
            .load(std::sync::atomic::Ordering::Relaxed)
    }

    pub(super) fn token_models(&self) -> Vec<String> {
        self.token_models
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
    }

    pub(super) async fn session(&self) -> Result<&Session, String> {
        self.session
            .get_or_try_init(|| async {
                let account: AccountAnalyticsReadResponse = self
                    .handle
                    .request_typed(ClientRequest::AccountAnalyticsRead {
                        request_id: RequestId::String(uuid::Uuid::new_v4().to_string()),
                        params: AccountAnalyticsReadParams {
                            thread_id: self.thread_id.clone(),
                            expected_binding: None,
                            query: Query::Account,
                        },
                    })
                    .await
                    .map_err(|error| {
                        let message = request_error(error);
                        if message == "Report request failed. Press R to retry." {
                            "Couldn't load account plan. Press R to retry Analytics.".into()
                        } else {
                            message
                        }
                    })?;
                let credit_groups = Grouping::credit_groupings(account.plan_type)
                    .iter()
                    .filter_map(|group| {
                        super::data::GROUPINGS
                            .iter()
                            .position(|candidate| candidate == group)
                    })
                    .collect();
                Ok(Session {
                    kind: AccountKind::from(account.plan_type),
                    credit_groups,
                    account,
                    handle: self.handle.clone(),
                    cache: Mutex::new(HashMap::new()),
                })
            })
            .await
    }

    /// Every report shares the same privacy boundary, including cached report loads.
    pub(super) async fn ensure_identity(&self) -> Result<(), String> {
        let identity = match self.session().await {
            Ok(session) => session
                .request::<serde_json::Value>(Query::Validate)
                .await
                .map(|_| ())
                .map_err(request_error),
            Err(error) => Err(error),
        };
        if identity.is_err() {
            self.identity_invalidated
                .store(/*val*/ true, std::sync::atomic::Ordering::Relaxed);
        }
        identity
    }

    pub(super) async fn plan_history(&self) -> Result<Option<super::plan::Report>, String> {
        let session = self.session().await?;
        if session.kind != AccountKind::Consumer {
            return Ok(None);
        }
        let history = session
            .request::<Option<codex_backend_client::PlanLimitHistory>>(Query::PlanHistory)
            .await;
        self.ensure_identity().await?;
        history
            .map_err(request_error)?
            .map(super::plan::Report::parse)
            .transpose()
            .map(Option::flatten)
    }

    pub(super) async fn history(
        &self,
        report: Report,
        days: u32,
        grouping: Grouping,
    ) -> Result<Option<super::models::AccountAnalyticsHistory>, String> {
        self.filtered_history(report, days, grouping, /*model_filter*/ None)
            .await
    }

    pub(super) async fn filtered_history(
        &self,
        report: Report,
        days: u32,
        grouping: Grouping,
        model_filter: Option<&str>,
    ) -> Result<Option<super::models::AccountAnalyticsHistory>, String> {
        let end = self.end_date;
        let start = days
            .checked_sub(/*rhs*/ 1)
            .and_then(|offset| end.checked_sub_days(chrono::Days::new(u64::from(offset))))
            .ok_or("Invalid analytics date range.")?;
        let session = self.session().await?;
        self.ensure_identity().await?;
        let enterprise_tokens = report == Report::Usage
            && matches!(
                session.kind,
                AccountKind::Enterprise | AccountKind::Business
            );
        let grouping =
            if enterprise_tokens && !matches!(grouping, Grouping::Model | Grouping::TokenType) {
                Grouping::TokenType
            } else {
                grouping
            };
        let route = route(report, grouping, session.account.plan_type).ok_or_else(|| {
            "This credit breakdown is not supported for this account type.".to_string()
        })?;
        // Credit events have no range parameters. Other grouping changes reuse the same payload.
        let key = if route == AnalyticsReport::Credits {
            (route, String::new(), String::new())
        } else {
            (route, start.to_string(), end.to_string())
        };
        let cached = session.cache.lock().await.get(&key).cloned();
        let response = if let Some(response) = cached {
            Ok(response)
        } else {
            session
                .request::<AnalyticsResponse>(Query::History {
                    report: route,
                    start: key.1.clone(),
                    end: key.2.clone(),
                })
                .await
                .map(AnalyticsData::from)
        };
        self.ensure_identity().await?;
        let response = response.map_err(request_error)?;
        let history = (|| {
            if enterprise_tokens {
                let models = super::tokens::history(response.clone(), Grouping::Model, start, end)?;
                *self
                    .token_models
                    .write()
                    .unwrap_or_else(std::sync::PoisonError::into_inner) =
                    super::render::categories(&models)
                        .into_iter()
                        .map(|model| model.key)
                        .collect();
                super::tokens::filtered_history(
                    response.clone(),
                    grouping,
                    start,
                    end,
                    model_filter,
                )
                .map(Some)
            } else {
                let grouping = if report == Report::Usage {
                    let attributed =
                        super::normalize::has_complete_attribution(&response, start, end)?;
                    self.attributed_usage
                        .store(attributed, std::sync::atomic::Ordering::Relaxed);
                    if !attributed && matches!(grouping, Grouping::Feature | Grouping::TaskStart) {
                        Grouping::Surface
                    } else {
                        grouping
                    }
                } else {
                    grouping
                };
                super::normalize::history(response.clone(), report, grouping, start, end)
            }
        })();
        let mut cache = session.cache.lock().await;
        if history.is_ok() {
            cache.insert(key, response);
        } else {
            cache.remove(&key);
        }
        history
    }
}

// Account type selects billing semantics, never activity-report eligibility.
fn route(report: Report, grouping: Grouping, plan: Option<PlanType>) -> Option<AnalyticsReport> {
    let kind = AccountKind::from(plan);
    let enterprise = kind == AccountKind::Enterprise;
    Some(match report {
        Report::Usage if enterprise => AnalyticsReport::EnterpriseTokens,
        Report::Usage if kind == AccountKind::Business => AnalyticsReport::WorkspaceCredits,
        Report::Usage => AnalyticsReport::Usage,
        Report::Messages => AnalyticsReport::Messages,
        Report::Credits if !Grouping::credit_groupings(plan).contains(&grouping) => return None,
        Report::Credits if enterprise => AnalyticsReport::EnterpriseCredits {
            breakdown: match grouping {
                Grouping::Surface => Breakdown::Product,
                Grouping::Model => Breakdown::Model,
                Grouping::Speed => Breakdown::Speed,
                Grouping::Reasoning => Breakdown::ReasoningEffort,
                Grouping::Feature | Grouping::TaskStart | Grouping::TokenType => return None,
            },
        },
        Report::Credits if kind == AccountKind::Business => AnalyticsReport::WorkspaceCredits,
        Report::Credits => AnalyticsReport::Credits,
        Report::Plugins => AnalyticsReport::Plugins {
            limit: if enterprise { 8 } else { 10 },
        },
        Report::Skills => AnalyticsReport::Skills {
            limit: if enterprise { 6 } else { 10 },
        },
    })
}

pub(super) fn request_status(error: &TypedRequestError) -> Option<u64> {
    match error {
        TypedRequestError::Server { source, .. } => {
            source.data.as_ref()?.get("httpStatus")?.as_u64()
        }
        TypedRequestError::Transport { .. } | TypedRequestError::Deserialize { .. } => None,
    }
}

pub(super) fn request_error(error: TypedRequestError) -> String {
    if let TypedRequestError::Server { source, .. } = &error
        && source.message == "Account changed. Press R to refresh Analytics."
    {
        return source.message.clone();
    }
    match request_status(&error) {
        Some(401) => "Sign in again to load this report.",
        Some(403) => "Access denied for this report.",
        Some(404) => "This report endpoint is unavailable. Press R to retry.",
        _ => "Report request failed. Press R to retry.",
    }
    .into()
}

#[cfg(test)]
#[path = "client_tests.rs"]
pub(super) mod tests;

#[cfg(test)]
#[path = "connection_tests.rs"]
mod connection_tests;

#[cfg(test)]
#[path = "account_plan_tests.rs"]
mod account_plan_tests;
