use super::*;
use codex_app_server_protocol::AccountAnalyticsBinding;
use codex_app_server_protocol::AccountAnalyticsCreditBreakdown;
use codex_app_server_protocol::AccountAnalyticsQuery;
use codex_app_server_protocol::AccountAnalyticsReadParams;
use codex_app_server_protocol::AccountAnalyticsReadResponse;
use codex_app_server_protocol::AccountAnalyticsReport;
use codex_backend_client::AnalyticsReport;
use codex_backend_client::RequestError;
use codex_backend_client::TaskUsageThread;
use serde::Serialize;
use serde_json::Value;

struct Capture {
    config: Config,
    auth: CodexAuth,
    binding: AccountAnalyticsBinding,
}

impl AccountRequestProcessor {
    async fn capture_analytics(
        &self,
        thread_id: Option<&str>,
    ) -> Result<Capture, JSONRPCErrorError> {
        self.auth_manager.reload().await;
        let unavailable = || invalid_request("The selected Analytics account is unavailable.");
        let mut config = self.load_latest_config().await;
        let (auth, key, session_id) = if let Some(id) = thread_id {
            let thread = self
                .thread_manager
                .get_thread(ThreadId::from_string(id).map_err(|_| unavailable())?)
                .await
                .map_err(|_| unavailable())?;
            let snapshot = thread
                .current_runtime_snapshot()
                .await
                .map_err(|_| unavailable())?;
            config.chatgpt_base_url = snapshot.mcp.config().chatgpt_base_url.clone();
            config.application_network_policy = snapshot.application_network_policy;
            (
                snapshot.effective_auth,
                snapshot.codex_apps_tools_cache_key,
                Some(thread.startup_metadata().session_id.to_string()),
            )
        } else {
            let (auth, _, key) = codex_core::connectors::capture_threadless_connector_auth(
                &mut config,
                &self.auth_manager,
            )
            .await
            .map_err(|_| unavailable())?;
            (auth, key, None)
        };
        let auth = auth
            .filter(CodexAuth::is_chatgpt_auth)
            .ok_or_else(unavailable)?;
        let transport = key.transport_binding();
        let binding = AccountAnalyticsBinding {
            thread_id: thread_id.map(str::to_string),
            session_id,
            managed_account_id: key.is_managed().then_some(transport.identity_key),
            account_id: auth.get_account_id().ok_or_else(unavailable)?,
            user_id: auth.get_chatgpt_user_id().ok_or_else(unavailable)?,
            credential_revision: key.credential_revision(),
            routing_revision: transport.route_generation,
            policy_revision: config.application_network_policy.revision().generation(),
        };
        // Cache validation is also a policy check, even when no HTTP request is needed.
        config
            .application_network_policy
            .acquire(&config.chatgpt_base_url.parse().map_err(|_| unavailable())?)
            .map_err(|_| unavailable())?;
        Ok(Capture {
            config,
            auth,
            binding,
        })
    }

    pub(crate) async fn read_analytics(
        &self,
        params: AccountAnalyticsReadParams,
    ) -> Result<Option<ClientResponsePayload>, JSONRPCErrorError> {
        // Match the existing Analytics load deadline, including auth, body reads and validation.
        tokio::time::timeout(Duration::from_secs(/*secs*/ 30), async {
            let captured = self.capture_analytics(params.thread_id.as_deref()).await?;
            if params
                .expected_binding
                .as_ref()
                .is_some_and(|expected| expected != &captured.binding)
            {
                return Err(invalid_request(
                    "Account changed. Press R to refresh Analytics.",
                ));
            }
            let client = || {
                BackendClient::new_without_redirects(
                    &captured.config.chatgpt_base_url,
                    captured.config.http_client_factory(),
                )
                .with_auth_provider(codex_model_provider::auth_provider_from_auth(
                    &captured.auth,
                ))
            };
            let mut plan_type = None;
            let data = match params.query {
                AccountAnalyticsQuery::Validate => Value::Null,
                AccountAnalyticsQuery::Account => {
                    let client = client();
                    let accounts = client.get_accounts_check().await;
                    let accounts = if accounts.as_ref().is_err_and(RequestError::is_unauthorized) {
                        self.auth_manager.reload().await;
                        client.get_accounts_check().await
                    } else {
                        accounts
                    }
                    .map_err(analytics_error)?;
                    plan_type = Some(
                        accounts
                            .accounts
                            .into_iter()
                            .find(|account| account.id == captured.binding.account_id)
                            .and_then(|account| account.plan_type)
                            .ok_or_else(|| {
                                internal_error(
                                    "Couldn't load account plan. Press R to retry Analytics.",
                                )
                            })?,
                    );
                    Value::Null
                }
                AccountAnalyticsQuery::Profile => {
                    report_value(client().get_account_profile().await)?
                }
                AccountAnalyticsQuery::PlanHistory => {
                    report_value(client().get_plan_limit_history().await)?
                }
                AccountAnalyticsQuery::History { report, start, end } => {
                    if !matches!(report, AccountAnalyticsReport::Credits) {
                        let first = start
                            .parse::<chrono::NaiveDate>()
                            .map_err(|_| invalid_request("Invalid Analytics dates."))?;
                        let last = end
                            .parse::<chrono::NaiveDate>()
                            .map_err(|_| invalid_request("Invalid Analytics dates."))?;
                        if !(0..30).contains(&(last - first).num_days()) {
                            return Err(invalid_request(
                                "Analytics supports up to 30 inclusive days.",
                            ));
                        }
                    }
                    let report = match report {
                        AccountAnalyticsReport::Usage => AnalyticsReport::Usage,
                        AccountAnalyticsReport::EnterpriseTokens => {
                            AnalyticsReport::EnterpriseTokens
                        }
                        AccountAnalyticsReport::Credits => AnalyticsReport::Credits,
                        AccountAnalyticsReport::WorkspaceCredits => {
                            AnalyticsReport::WorkspaceCredits
                        }
                        AccountAnalyticsReport::EnterpriseCredits { breakdown } => {
                            AnalyticsReport::EnterpriseCredits {
                                breakdown: match breakdown {
                                    AccountAnalyticsCreditBreakdown::Product => "product",
                                    AccountAnalyticsCreditBreakdown::Model => "model",
                                    AccountAnalyticsCreditBreakdown::Speed => "speed",
                                    AccountAnalyticsCreditBreakdown::ReasoningEffort => {
                                        "reasoning_effort"
                                    }
                                },
                            }
                        }
                        AccountAnalyticsReport::Messages => AnalyticsReport::Messages,
                        AccountAnalyticsReport::Plugins { limit } if (1..=10).contains(&limit) => {
                            AnalyticsReport::Plugins { limit }
                        }
                        AccountAnalyticsReport::Skills { limit } if (1..=10).contains(&limit) => {
                            AnalyticsReport::Skills { limit }
                        }
                        AccountAnalyticsReport::Plugins { .. }
                        | AccountAnalyticsReport::Skills { .. } => {
                            return Err(invalid_request(
                                "Analytics supports at most 10 ranked entries.",
                            ));
                        }
                    };
                    report_value(client().get_account_analytics(report, &start, &end).await)?
                }
                AccountAnalyticsQuery::Threads { ids } => report_value(
                    client()
                        .get_threads_usage(&ids.iter().map(String::as_str).collect::<Vec<_>>())
                        .await,
                )?,
                AccountAnalyticsQuery::Tasks { threads } => {
                    let threads = threads
                        .into_iter()
                        .map(|thread| TaskUsageThread {
                            thread_id: thread.thread_id,
                            created_at: thread.created_at,
                            descendant_thread_ids: thread.descendant_thread_ids,
                        })
                        .collect::<Vec<_>>();
                    report_value(client().get_task_usage(&threads).await)?
                }
            };
            let current = self.capture_analytics(params.thread_id.as_deref()).await?;
            if current.binding != captured.binding {
                return Err(invalid_request(
                    "Account changed. Press R to refresh Analytics.",
                ));
            }
            Ok(Some(
                AccountAnalyticsReadResponse {
                    binding: captured.binding,
                    email: captured.auth.get_account_email(),
                    plan_type,
                    data,
                }
                .into(),
            ))
        })
        .await
        .map_err(|_| internal_error("Analytics request timed out. Press R to retry."))?
    }
}

fn report_value<T: Serialize>(result: Result<T, RequestError>) -> Result<Value, JSONRPCErrorError> {
    serde_json::to_value(result.map_err(analytics_error)?)
        .map_err(|_| internal_error("Invalid Analytics report."))
}

fn analytics_error(error: RequestError) -> JSONRPCErrorError {
    let mut response = internal_error("Analytics report request failed.");
    response.data =
        Some(serde_json::json!({ "httpStatus": error.status().map(|status| status.as_u16()) }));
    response
}
