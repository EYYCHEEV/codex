use std::fmt;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

use codex_api::AgentIdentityTelemetry;
use codex_api::ApiError;
use codex_api::ModelsClient;
use codex_api::RequestTelemetry;
use codex_api::ReqwestTransport;
use codex_api::TransportError;
use codex_api::auth_header_telemetry;
use codex_api::map_api_error;
use codex_feedback::FeedbackRequestTags;
use codex_feedback::emit_feedback_request_tags_with_auth_env;
use codex_http_client::ClientRouteClass;
use codex_http_client::HttpClientFactory;
use codex_login::AuthEnvTelemetry;
use codex_login::AuthManager;
use codex_login::CodexAuth;
use codex_login::auth::AgentIdentityAuthPolicy;
use codex_login::collect_auth_env_telemetry;
use codex_login::default_client::create_client_for_route_async;
use codex_model_provider_info::ModelProviderInfo;
use codex_models_manager::manager::ModelsEndpointClient;
use codex_models_manager::manager::ModelsEndpointFuture;
use codex_otel::TelemetryAuthMode;
use codex_protocol::error::CodexErr;
use codex_protocol::error::Result as CoreResult;
use codex_protocol::openai_models::ModelInfo;
use codex_protocol::protocol::SessionSource;
use codex_response_debug_context::extract_response_debug_context;
use codex_response_debug_context::telemetry_transport_error_message;
use http::HeaderMap;
use http::StatusCode;
use tokio::time::timeout;

use crate::auth::AgentIdentitySessionFallback;
use crate::auth::ProviderAuthScope;
use crate::provider::provider_uses_first_party_auth_path;
use crate::provider::resolve_provider_request_setup;

const MODELS_REFRESH_TIMEOUT: Duration = Duration::from_secs(5);
const MODELS_ENDPOINT: &str = "/models";

/// Provider-owned OpenAI-compatible `/models` endpoint.
#[derive(Debug)]
pub(crate) struct OpenAiModelsEndpoint {
    provider_info: ModelProviderInfo,
    auth_manager: Option<Arc<AuthManager>>,
    transport_builder: Arc<dyn ModelsTransportBuilder>,
}

impl OpenAiModelsEndpoint {
    pub(crate) fn new(
        provider_info: ModelProviderInfo,
        auth_manager: Option<Arc<AuthManager>>,
    ) -> Self {
        Self {
            provider_info,
            auth_manager,
            transport_builder: Arc::new(RouteAwareModelsTransportBuilder),
        }
    }

    async fn request_setup(&self) -> CoreResult<crate::provider::ProviderRequestSetup> {
        resolve_provider_request_setup(
            self.auth_manager.clone(),
            &self.provider_info,
            ProviderAuthScope {
                agent_identity_policy: AgentIdentityAuthPolicy::JwtOnly,
                session_source: SessionSource::Unknown,
                agent_identity_session_fallback: AgentIdentitySessionFallback::default(),
                thread_id: None,
                session_id: None,
                model: None,
            },
        )
        .await
    }

    async fn uses_codex_backend(&self) -> bool {
        if self.provider_info.experimental_bearer_token.is_some() {
            // This predicate also gates provider-owned `/models` refreshes. A static
            // provider bearer authorizes that endpoint without manager-backed auth.
            return true;
        }

        if provider_uses_first_party_auth_path(&self.provider_info) {
            return self
                .request_setup()
                .await
                .ok()
                .and_then(|setup| setup.effective_auth)
                .as_ref()
                .is_some_and(CodexAuth::uses_codex_backend);
        }

        match self.auth_manager.as_ref() {
            Some(auth_manager) => auth_manager
                .auth()
                .await
                .as_ref()
                .is_some_and(CodexAuth::uses_codex_backend),
            None => false,
        }
    }

    async fn list_models(
        &self,
        client_version: &str,
        http_client_factory: HttpClientFactory,
    ) -> CoreResult<(Vec<ModelInfo>, Option<String>)> {
        let _timer =
            codex_otel::start_global_timer("codex.remote_models.fetch_update.duration_ms", &[]);
        let mut setup = self.request_setup().await?;
        let mut auth_recovery = self.auth_manager.as_ref().map(|manager| {
            setup.managed_snapshot.as_ref().map_or_else(
                || manager.unauthorized_recovery(),
                |snapshot| manager.unauthorized_recovery_for_snapshot(snapshot),
            )
        });
        timeout(MODELS_REFRESH_TIMEOUT, async {
            loop {
                let auth_mode = setup.effective_auth.as_ref().map(CodexAuth::auth_mode);
                let request_url = ModelsClient::<ReqwestTransport>::request_url(
                    &setup.api_provider,
                    client_version,
                );
                let auth_telemetry = auth_header_telemetry(setup.api_auth.as_ref());
                let agent_identity_telemetry = setup.agent_identity_telemetry.clone();
                let request_telemetry: Arc<dyn RequestTelemetry> =
                    Arc::new(ModelsRequestTelemetry {
                        auth_mode: auth_mode.map(|mode| TelemetryAuthMode::from(mode).to_string()),
                        auth_header_attached: auth_telemetry.attached,
                        auth_header_name: auth_telemetry.name,
                        agent_identity_telemetry,
                        auth_env: self.auth_env(),
                    });
                let transport = self
                    .transport_builder
                    .build(http_client_factory.clone(), request_url.clone())
                    .await?;
                let client = ModelsClient::new(transport, setup.api_provider, setup.api_auth)
                    .with_telemetry(Some(request_telemetry));
                match client.list_models(request_url, HeaderMap::new()).await {
                    Err(ApiError::Transport(
                        unauthorized @ TransportError::Http { status, .. },
                    )) if status == StatusCode::UNAUTHORIZED => {
                        let Some(recovery) = auth_recovery.as_mut() else {
                            return Err(map_api_error(ApiError::Transport(unauthorized)));
                        };
                        if !recovery.has_next() {
                            return Err(map_api_error(ApiError::Transport(unauthorized)));
                        }
                        recovery
                            .next()
                            .await
                            .map_err(|err| CodexErr::Io(err.into()))?;
                        setup = self.request_setup().await?;
                    }
                    result => return result.map_err(map_api_error),
                }
            }
        })
        .await
        .map_err(|_| CodexErr::Timeout)?
    }

    fn auth_env(&self) -> AuthEnvTelemetry {
        let codex_api_key_env_enabled = self
            .auth_manager
            .as_ref()
            .is_some_and(|auth_manager| auth_manager.codex_api_key_env_enabled());
        collect_auth_env_telemetry(&self.provider_info, codex_api_key_env_enabled)
    }
}

impl ModelsEndpointClient for OpenAiModelsEndpoint {
    fn has_command_auth(&self) -> bool {
        self.provider_info.has_command_auth()
    }

    fn uses_codex_backend(&self) -> ModelsEndpointFuture<'_, bool> {
        Box::pin(OpenAiModelsEndpoint::uses_codex_backend(self))
    }

    fn list_models<'a>(
        &'a self,
        client_version: &'a str,
        http_client_factory: HttpClientFactory,
    ) -> ModelsEndpointFuture<'a, CoreResult<(Vec<ModelInfo>, Option<String>)>> {
        Box::pin(OpenAiModelsEndpoint::list_models(
            self,
            client_version,
            http_client_factory,
        ))
    }
}

type ModelsTransportFuture<'a> =
    Pin<Box<dyn Future<Output = std::io::Result<ReqwestTransport>> + Send + 'a>>;

/// Builds the concrete transport selected for one models request.
///
/// Implementations must honor the supplied request-time client factory and exact request URL.
trait ModelsTransportBuilder: fmt::Debug + Send + Sync {
    fn build(
        &self,
        http_client_factory: HttpClientFactory,
        request_url: String,
    ) -> ModelsTransportFuture<'_>;
}

#[derive(Debug)]
struct RouteAwareModelsTransportBuilder;

impl ModelsTransportBuilder for RouteAwareModelsTransportBuilder {
    fn build(
        &self,
        http_client_factory: HttpClientFactory,
        request_url: String,
    ) -> ModelsTransportFuture<'_> {
        Box::pin(async move {
            create_client_for_route_async(http_client_factory, request_url, ClientRouteClass::Api)
                .await
                .map(ReqwestTransport::from_http_client)
        })
    }
}

#[derive(Clone)]
struct ModelsRequestTelemetry {
    auth_mode: Option<String>,
    auth_header_attached: bool,
    auth_header_name: Option<&'static str>,
    agent_identity_telemetry: Option<AgentIdentityTelemetry>,
    auth_env: AuthEnvTelemetry,
}

impl RequestTelemetry for ModelsRequestTelemetry {
    fn on_request(
        &self,
        attempt: u64,
        status: Option<http::StatusCode>,
        error: Option<&TransportError>,
        duration: Duration,
    ) {
        let success = status.is_some_and(|code| code.is_success()) && error.is_none();
        let error_message = error.map(telemetry_transport_error_message);
        let response_debug = error
            .map(extract_response_debug_context)
            .unwrap_or_default();
        let status = status.map(|status| status.as_u16());
        tracing::event!(
            target: "codex_otel.log_only",
            tracing::Level::INFO,
            event.name = "codex.api_request",
            duration_ms = %duration.as_millis(),
            http.response.status_code = status,
            success = success,
            error.message = error_message.as_deref(),
            attempt = attempt,
            endpoint = MODELS_ENDPOINT,
            auth.header_attached = self.auth_header_attached,
            auth.header_name = self.auth_header_name,
            auth.env_openai_api_key_present = self.auth_env.openai_api_key_env_present,
            auth.env_codex_api_key_present = self.auth_env.codex_api_key_env_present,
            auth.env_codex_api_key_enabled = self.auth_env.codex_api_key_env_enabled,
            auth.env_provider_key_name = self.auth_env.provider_env_key_name.as_deref(),
            auth.env_provider_key_present = self.auth_env.provider_env_key_present,
            auth.env_refresh_token_url_override_present = self.auth_env.refresh_token_url_override_present,
            auth.request_id = response_debug.request_id.as_deref(),
            auth.cf_ray = response_debug.cf_ray.as_deref(),
            auth.error = response_debug.auth_error.as_deref(),
            auth.error_code = response_debug.auth_error_code.as_deref(),
            auth.mode = self.auth_mode.as_deref(),
            auth.agent_id = self.agent_identity_telemetry.as_ref().map(|metadata| metadata.agent_id.as_str()),
            auth.task_id = self.agent_identity_telemetry.as_ref().map(|metadata| metadata.task_id.as_str()),
        );
        tracing::event!(
            target: "codex_otel.trace_safe",
            tracing::Level::INFO,
            event.name = "codex.api_request",
            duration_ms = %duration.as_millis(),
            http.response.status_code = status,
            success = success,
            error.message = error_message.as_deref(),
            attempt = attempt,
            endpoint = MODELS_ENDPOINT,
            auth.header_attached = self.auth_header_attached,
            auth.header_name = self.auth_header_name,
            auth.env_openai_api_key_present = self.auth_env.openai_api_key_env_present,
            auth.env_codex_api_key_present = self.auth_env.codex_api_key_env_present,
            auth.env_codex_api_key_enabled = self.auth_env.codex_api_key_env_enabled,
            auth.env_provider_key_name = self.auth_env.provider_env_key_name.as_deref(),
            auth.env_provider_key_present = self.auth_env.provider_env_key_present,
            auth.env_refresh_token_url_override_present = self.auth_env.refresh_token_url_override_present,
            auth.request_id = response_debug.request_id.as_deref(),
            auth.cf_ray = response_debug.cf_ray.as_deref(),
            auth.error = response_debug.auth_error.as_deref(),
            auth.error_code = response_debug.auth_error_code.as_deref(),
            auth.mode = self.auth_mode.as_deref(),
            auth.agent_id = self.agent_identity_telemetry.as_ref().map(|metadata| metadata.agent_id.as_str()),
            auth.task_id = self.agent_identity_telemetry.as_ref().map(|metadata| metadata.task_id.as_str()),
        );
        emit_feedback_request_tags_with_auth_env(
            &FeedbackRequestTags {
                endpoint: MODELS_ENDPOINT,
                auth_header_attached: self.auth_header_attached,
                auth_header_name: self.auth_header_name,
                auth_mode: self.auth_mode.as_deref(),
                auth_retry_after_unauthorized: None,
                auth_recovery_mode: None,
                auth_recovery_phase: None,
                auth_connection_reused: None,
                auth_request_id: response_debug.request_id.as_deref(),
                auth_cf_ray: response_debug.cf_ray.as_deref(),
                auth_error: response_debug.auth_error.as_deref(),
                auth_error_code: response_debug.auth_error_code.as_deref(),
                auth_recovery_followup_success: None,
                auth_recovery_followup_status: None,
            },
            &self.auth_env,
        );
    }
}

#[cfg(test)]
mod tests {
    use std::num::NonZeroU64;
    use std::sync::Mutex;

    use super::*;
    use codex_http_client::OutboundProxyPolicy;
    use codex_login::default_client::create_client;
    use codex_protocol::config_types::ModelProviderAuthInfo;
    use codex_protocol::openai_models::ModelsResponse;
    use pretty_assertions::assert_eq;
    use wiremock::Mock;
    use wiremock::MockServer;
    use wiremock::ResponseTemplate;
    use wiremock::matchers::method;
    use wiremock::matchers::path;
    use wiremock::matchers::query_param;

    #[derive(Debug)]
    struct RecordingTransportBuilder {
        observed_request: Arc<Mutex<Option<(OutboundProxyPolicy, String)>>>,
    }

    impl ModelsTransportBuilder for RecordingTransportBuilder {
        fn build(
            &self,
            http_client_factory: HttpClientFactory,
            request_url: String,
        ) -> ModelsTransportFuture<'_> {
            let observed_request = Arc::clone(&self.observed_request);
            Box::pin(async move {
                *observed_request
                    .lock()
                    .expect("observed request lock should not be poisoned") =
                    Some((http_client_factory.outbound_proxy_policy(), request_url));
                Ok(ReqwestTransport::from_http_client(create_client()))
            })
        }
    }

    fn provider_info_with_command_auth() -> ModelProviderInfo {
        ModelProviderInfo {
            auth: Some(ModelProviderAuthInfo {
                command: "print-token".to_string(),
                args: Vec::new(),
                timeout_ms: NonZeroU64::new(5_000).expect("timeout should be non-zero"),
                refresh_interval_ms: 300_000,
                cwd: std::env::current_dir()
                    .expect("current dir should be available")
                    .try_into()
                    .expect("current dir should be absolute"),
            }),
            requires_openai_auth: false,
            ..ModelProviderInfo::create_openai_provider(/*base_url*/ None)
        }
    }

    #[test]
    fn command_auth_provider_reports_command_auth_without_cached_auth() {
        let endpoint = OpenAiModelsEndpoint::new(
            provider_info_with_command_auth(),
            /*auth_manager*/ None,
        );

        assert!(endpoint.has_command_auth());
    }

    #[test]
    fn provider_without_command_auth_reports_no_command_auth() {
        let endpoint = OpenAiModelsEndpoint::new(
            ModelProviderInfo::create_openai_provider(/*base_url*/ None),
            /*auth_manager*/ None,
        );

        assert!(!endpoint.has_command_auth());
    }

    #[tokio::test]
    async fn static_provider_token_authorizes_models_refresh_without_auth_manager() {
        let mut provider_info = ModelProviderInfo::create_openai_provider(/*base_url*/ None);
        provider_info.experimental_bearer_token = Some("provider-token".to_string());
        let endpoint = OpenAiModelsEndpoint::new(provider_info, /*auth_manager*/ None);

        assert!(endpoint.uses_codex_backend().await);
    }

    #[tokio::test]
    async fn model_request_uses_request_time_proxy_policy_and_exact_url() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/models"))
            .and(query_param("client_version", "0.0.0"))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(ModelsResponse { models: Vec::new() }),
            )
            .expect(1)
            .mount(&server)
            .await;

        let observed_request = Arc::new(Mutex::new(None));
        let endpoint = OpenAiModelsEndpoint {
            provider_info: ModelProviderInfo::create_openai_provider(Some(server.uri())),
            auth_manager: None,
            transport_builder: Arc::new(RecordingTransportBuilder {
                observed_request: Arc::clone(&observed_request),
            }),
        };

        endpoint
            .list_models(
                "0.0.0",
                HttpClientFactory::new(OutboundProxyPolicy::RespectSystemProxy),
            )
            .await
            .expect("models request should succeed");

        assert_eq!(
            *observed_request
                .lock()
                .expect("observed request lock should not be poisoned"),
            Some((
                OutboundProxyPolicy::RespectSystemProxy,
                format!("{}/models?client_version=0.0.0", server.uri()),
            ))
        );
    }
}
