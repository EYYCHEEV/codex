use std::fmt;
use std::future::Future;
use std::path::PathBuf;
use std::pin::Pin;
use std::sync::Arc;

use codex_api::AgentIdentityTelemetry;
use codex_api::ApiError;
use codex_api::Provider;
use codex_api::SharedAuthProvider;
use codex_api::is_azure_responses_provider;
use codex_login::AuthManager;
use codex_login::CodexAuth;
use codex_login::ManagedChatgptAuthSnapshot;
use codex_login::ManagedChatgptSelectionScope;
use codex_login::TransportAuthBinding;
use codex_model_provider_info::ModelProviderInfo;
use codex_models_manager::cache::ModelsCache;
use codex_models_manager::manager::OpenAiModelsManager;
use codex_models_manager::manager::SharedModelsManager;
use codex_models_manager::manager::StaticModelsManager;
use codex_protocol::account::ProviderAccount;
use codex_protocol::error::CodexErr;
use codex_protocol::openai_models::ModelsResponse;

use crate::amazon_bedrock::AmazonBedrockModelProvider;
use crate::auth::ProviderAuthScope;
use crate::auth::ResolvedProviderAuth;
use crate::auth::auth_manager_for_provider;
use crate::auth::resolve_provider_auth;
use crate::auth::resolve_provider_auth_for_scope;
use crate::models_endpoint::OpenAiModelsEndpoint;

/// Remote context-compaction protocols supported by a model provider.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RemoteCompactionSupport {
    /// The provider does not support remote compaction.
    Unsupported,
    /// The provider supports only the dedicated `/v1/responses/compact` endpoint.
    V1,
    /// The provider supports both the dedicated endpoint and `compaction_trigger` items.
    V2,
}

/// Optional provider-backed features that Codex may expose at runtime.
///
/// These capabilities are a provider-owned upper bound. Callers can disable
/// more functionality through normal config, but should not expose a feature
/// that the active provider marks unsupported here.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProviderCapabilities {
    pub namespace_tools: bool,
    pub image_generation: bool,
    pub web_search: bool,
    pub external_web_access: bool,
    pub remote_compaction: RemoteCompactionSupport,
}

impl Default for ProviderCapabilities {
    fn default() -> Self {
        Self {
            namespace_tools: true,
            image_generation: true,
            web_search: true,
            external_web_access: true,
            remote_compaction: RemoteCompactionSupport::V2,
        }
    }
}

/// Current app-visible account state for a model provider.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProviderAccountState {
    pub account: Option<ProviderAccount>,
    pub requires_openai_auth: bool,
}

/// Atomic provider, authentication, and account binding selected for one request attempt.
#[derive(Clone)]
pub struct ProviderRequestSetup {
    pub effective_auth: Option<CodexAuth>,
    pub api_provider: Provider,
    pub api_auth: SharedAuthProvider,
    pub agent_identity_telemetry: Option<AgentIdentityTelemetry>,
    pub managed_snapshot: Option<ManagedChatgptAuthSnapshot>,
    pub managed_id: Option<String>,
    pub credential_revision: Option<u64>,
    pub account_state_revision: Option<u64>,
    pub selection_revision: Option<u64>,
    pub transport_auth_binding: TransportAuthBinding,
}

/// Error returned when a provider cannot construct its app-visible account state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProviderAccountError {
    MissingChatgptAccountDetails,
    UnsupportedBedrockApiKeyAuth,
}

impl fmt::Display for ProviderAccountError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MissingChatgptAccountDetails => {
                write!(f, "plan type is required for chatgpt authentication")
            }
            Self::UnsupportedBedrockApiKeyAuth => {
                write!(
                    f,
                    "Bedrock API key auth is only supported by the Amazon Bedrock model provider"
                )
            }
        }
    }
}

impl std::error::Error for ProviderAccountError {}

pub type ProviderAccountResult = std::result::Result<ProviderAccountState, ProviderAccountError>;

/// Default model used for automatic approval review when a provider does not
/// require a backend-specific model ID.
pub const DEFAULT_APPROVAL_REVIEW_PREFERRED_MODEL: &str = "codex-auto-review";

const API_KEY_APPROVAL_REVIEW_PREFERRED_MODEL: &str = "gpt-5.6-luna";

/// Default model used for memory extraction when a provider does not require a
/// backend-specific model ID.
pub const DEFAULT_MEMORY_EXTRACTION_PREFERRED_MODEL: &str = "gpt-5.6-luna";

/// Default model used for memory consolidation when a provider does not require
/// a backend-specific model ID.
pub const DEFAULT_MEMORY_CONSOLIDATION_PREFERRED_MODEL: &str = "gpt-5.6-terra";

/// Runtime provider abstraction used by model execution.
///
/// Implementations own provider-specific behavior for a model backend. The
/// `ModelProviderInfo` returned by `info` is the serialized/configured provider
/// metadata used by the default OpenAI-compatible implementation.
pub trait ModelProvider: fmt::Debug + Send + Sync {
    /// Returns the configured provider metadata.
    fn info(&self) -> &ModelProviderInfo;

    /// Returns the provider-owned capability upper bounds.
    fn capabilities(&self) -> ProviderCapabilities {
        ProviderCapabilities::default()
    }

    /// Returns the preferred model used for automatic approval review.
    ///
    /// Providers that require backend-specific model IDs should override this.
    fn approval_review_preferred_model(&self) -> &'static str {
        DEFAULT_APPROVAL_REVIEW_PREFERRED_MODEL
    }

    /// Returns the preferred model used for memory extraction.
    ///
    /// Providers that require backend-specific model IDs should override this.
    fn memory_extraction_preferred_model(&self) -> &'static str {
        DEFAULT_MEMORY_EXTRACTION_PREFERRED_MODEL
    }

    /// Returns the preferred model used for memory consolidation.
    ///
    /// Providers that require backend-specific model IDs should override this.
    fn memory_consolidation_preferred_model(&self) -> &'static str {
        DEFAULT_MEMORY_CONSOLIDATION_PREFERRED_MODEL
    }

    /// Returns whether requests made through this provider should include attestation.
    fn supports_attestation(&self) -> bool {
        false
    }

    /// Returns the provider-scoped auth manager, when this provider uses one.
    ///
    /// TODO(celia-oai): Make auth manager access internal to this crate so callers
    /// resolve provider-specific auth only through `ModelProvider`. We first need
    /// to think through whether Codex should have a unified provider-specific auth
    /// manager throughout the codebase; that is a larger refactor than this change.
    fn auth_manager(&self) -> Option<Arc<AuthManager>>;

    /// Returns the current provider-scoped auth value, if one is configured.
    fn auth(&self) -> ModelProviderFuture<'_, Option<CodexAuth>>;

    /// Returns the current app-visible account state for this provider.
    fn account_state(&self) -> ProviderAccountResult;

    /// Maps an API client error into the provider's user-facing error representation.
    fn map_api_error(&self, error: ApiError) -> CodexErr {
        codex_api::map_api_error(error)
    }

    /// Returns provider configuration adapted for the API client.
    fn api_provider(&self) -> ModelProviderFuture<'_, codex_protocol::error::Result<Provider>> {
        Box::pin(async move {
            let auth = self.auth().await;
            self.info()
                .to_api_provider(auth.as_ref().map(CodexAuth::auth_mode))
        })
    }

    /// Returns the provider base URL that will be used at request time.
    fn runtime_base_url(
        &self,
    ) -> ModelProviderFuture<'_, codex_protocol::error::Result<Option<String>>> {
        Box::pin(async { Ok(self.info().base_url.clone()) })
    }

    /// Returns the auth provider used to attach request credentials.
    fn api_auth(
        &self,
    ) -> ModelProviderFuture<'_, codex_protocol::error::Result<SharedAuthProvider>> {
        Box::pin(async move {
            let auth = self.auth().await;
            resolve_provider_auth(auth.as_ref(), self.info())
        })
    }

    /// Returns request credentials, optionally scoped to a Codex session task.
    fn api_auth_for_scope(
        &self,
        scope: ProviderAuthScope,
    ) -> ModelProviderFuture<'_, codex_protocol::error::Result<ResolvedProviderAuth>> {
        Box::pin(async move {
            if !provider_uses_first_party_auth_path(self.info()) {
                let auth = self.auth().await;
                return resolve_provider_auth(auth.as_ref(), self.info())
                    .map(|resolved| ResolvedProviderAuth::new(resolved, auth));
            }
            let setup =
                resolve_provider_request_setup(self.auth_manager(), self.info(), scope).await?;
            Ok(ResolvedProviderAuth {
                auth: setup.api_auth,
                effective_auth: setup.effective_auth,
                agent_identity_telemetry: setup.agent_identity_telemetry,
            })
        })
    }

    /// Atomically selects every provider/auth value used by one request attempt.
    fn request_setup(
        &self,
        scope: ProviderAuthScope,
    ) -> ModelProviderFuture<'_, codex_protocol::error::Result<ProviderRequestSetup>> {
        Box::pin(async move {
            resolve_provider_request_setup(self.auth_manager(), self.info(), scope).await
        })
    }

    /// Creates the model manager implementation appropriate for this provider.
    fn models_manager(
        &self,
        codex_home: PathBuf,
        config_model_catalog: Option<ModelsResponse>,
    ) -> SharedModelsManager;

    /// Creates a model manager with caching disabled.
    ///
    /// Providers that fetch model catalogs should override this method. The default uses an
    /// authoritative in-memory catalog so hosted callers cannot accidentally write to disk.
    fn models_manager_without_cache(
        &self,
        config_model_catalog: Option<ModelsResponse>,
    ) -> SharedModelsManager {
        let model_catalog = config_model_catalog
            .or_else(|| codex_models_manager::bundled_models_response().ok())
            .unwrap_or_default();
        Arc::new(StaticModelsManager::new(self.auth_manager(), model_catalog))
    }

    /// Creates a model manager that can use a caller-provided cache for remote catalogs.
    ///
    /// Providers with remote catalogs should override this method. The default preserves the
    /// authoritative catalog returned by [`ModelProvider::models_manager_without_cache`] and does
    /// not consult `cache`. Implementations should likewise ignore the cache when
    /// `config_model_catalog` supplies an authoritative static catalog.
    fn models_manager_with_cache(
        &self,
        config_model_catalog: Option<ModelsResponse>,
        cache: Arc<dyn ModelsCache>,
    ) -> SharedModelsManager {
        drop(cache);
        self.models_manager_without_cache(config_model_catalog)
    }
}

pub type ModelProviderFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// Shared runtime model provider handle.
pub type SharedModelProvider = Arc<dyn ModelProvider>;

pub(crate) fn provider_uses_first_party_auth_path(provider: &ModelProviderInfo) -> bool {
    provider.requires_openai_auth
        && provider.env_key.is_none()
        && provider.experimental_bearer_token.is_none()
        && provider.auth.is_none()
        && provider.aws.is_none()
}

pub(crate) async fn resolve_provider_request_setup(
    auth_manager: Option<Arc<AuthManager>>,
    provider: &ModelProviderInfo,
    scope: ProviderAuthScope,
) -> codex_protocol::error::Result<ProviderRequestSetup> {
    let first_party_auth = provider_uses_first_party_auth_path(provider);
    let effective_manager_auth = if first_party_auth || provider.has_command_auth() {
        match auth_manager.as_ref() {
            Some(manager) => match manager.auth_cached() {
                Some(auth) => Some(auth),
                None => manager.auth().await,
            },
            None => None,
        }
    } else {
        None
    };
    let managed_chatgpt_mode = if first_party_auth {
        match auth_manager.as_ref() {
            Some(manager) if manager.has_external_auth() => false,
            Some(manager) => match effective_manager_auth.as_ref() {
                Some(auth) => {
                    auth.auth_mode() == codex_protocol::auth::AuthMode::Chatgpt
                        && !auth.is_external_chatgpt_tokens()
                }
                None => !manager
                    .stored_managed_chatgpt_accounts()
                    .map_err(CodexErr::Io)?
                    .is_empty(),
            },
            None => false,
        }
    } else {
        false
    };
    let selection_scope = ManagedChatgptSelectionScope {
        thread_id: scope.thread_id.clone(),
        session_id: scope.session_id.clone(),
        model: scope.model.clone(),
    };
    let managed_snapshot = if managed_chatgpt_mode {
        match auth_manager.as_ref() {
            Some(manager) => manager
                .managed_chatgpt_auth_snapshot(&selection_scope)
                .await
                .map_err(CodexErr::Io)?,
            None => None,
        }
    } else {
        None
    };
    let selected_auth = match managed_snapshot.as_ref() {
        Some(snapshot) => Some(snapshot.auth.clone()),
        None => match auth_manager.as_ref() {
            Some(manager)
                if managed_chatgpt_mode
                    && !manager.has_external_auth()
                    && !effective_manager_auth
                        .as_ref()
                        .is_some_and(CodexAuth::is_external_chatgpt_tokens)
                    && !manager
                        .managed_chatgpt_accounts()
                        .map_err(CodexErr::Io)?
                        .is_empty() =>
            {
                return Err(CodexErr::Io(std::io::Error::other(
                    "managed ChatGPT account pool has no eligible account for this request",
                )));
            }
            Some(_) => effective_manager_auth,
            None => None,
        },
    };
    let resolved = resolve_provider_auth_for_scope(
        auth_manager,
        managed_snapshot.as_ref(),
        selected_auth.as_ref(),
        provider,
        scope,
    )
    .await?;
    let effective_auth = resolved.effective_auth;
    let api_provider =
        provider.to_api_provider(effective_auth.as_ref().map(CodexAuth::auth_mode))?;
    let transport_auth_binding = managed_snapshot.as_ref().map_or_else(
        || transport_binding_for_auth(effective_auth.as_ref()),
        |snapshot| {
            let mut binding = snapshot.transport.clone();
            if let Some(auth) = effective_auth.as_ref() {
                binding.raw_account_id = auth.get_account_id();
                binding.fedramp = auth.is_fedramp_account();
                binding.auth_mode = auth.auth_mode();
            }
            binding
        },
    );
    Ok(ProviderRequestSetup {
        effective_auth,
        api_provider,
        api_auth: resolved.auth,
        agent_identity_telemetry: resolved.agent_identity_telemetry,
        managed_id: managed_snapshot
            .as_ref()
            .map(|snapshot| snapshot.identity_key.clone()),
        credential_revision: managed_snapshot
            .as_ref()
            .map(|snapshot| snapshot.account_revision),
        account_state_revision: managed_snapshot
            .as_ref()
            .map(|snapshot| snapshot.account_state_revision),
        selection_revision: managed_snapshot
            .as_ref()
            .map(|snapshot| snapshot.selection_revision),
        transport_auth_binding,
        managed_snapshot,
    })
}

pub(crate) fn transport_binding_for_auth(auth: Option<&CodexAuth>) -> TransportAuthBinding {
    let identity_key = auth
        .and_then(CodexAuth::get_chatgpt_user_id)
        .or_else(|| auth.and_then(CodexAuth::get_account_id))
        .unwrap_or_else(|| {
            auth.map(|auth| auth.auth_mode().to_string())
                .unwrap_or_else(|| "unauthenticated".to_string())
        });
    TransportAuthBinding {
        identity_key,
        raw_account_id: auth.and_then(CodexAuth::get_account_id),
        fedramp: auth.is_some_and(CodexAuth::is_fedramp_account),
        auth_mode: auth
            .map(CodexAuth::auth_mode)
            .unwrap_or(codex_protocol::auth::AuthMode::ApiKey),
        route_generation: 0,
    }
}

/// Creates the default runtime model provider for configured provider metadata.
pub fn create_model_provider(
    provider_info: ModelProviderInfo,
    auth_manager: Option<Arc<AuthManager>>,
) -> SharedModelProvider {
    if provider_info.is_amazon_bedrock() {
        Arc::new(AmazonBedrockModelProvider::new(provider_info, auth_manager))
    } else {
        Arc::new(ConfiguredModelProvider::new(provider_info, auth_manager))
    }
}

/// Runtime model provider backed by configured `ModelProviderInfo`.
#[derive(Clone, Debug)]
struct ConfiguredModelProvider {
    info: ModelProviderInfo,
    auth_manager: Option<Arc<AuthManager>>,
}

impl ConfiguredModelProvider {
    fn new(provider_info: ModelProviderInfo, auth_manager: Option<Arc<AuthManager>>) -> Self {
        let auth_manager = auth_manager_for_provider(auth_manager, &provider_info);
        Self {
            info: provider_info,
            auth_manager,
        }
    }
}

impl ModelProvider for ConfiguredModelProvider {
    fn info(&self) -> &ModelProviderInfo {
        &self.info
    }

    fn capabilities(&self) -> ProviderCapabilities {
        let remote_compaction = if self.info.is_openai()
            || is_azure_responses_provider(&self.info.name, self.info.base_url.as_deref())
        {
            RemoteCompactionSupport::V2
        } else {
            RemoteCompactionSupport::Unsupported
        };

        ProviderCapabilities {
            remote_compaction,
            ..ProviderCapabilities::default()
        }
    }

    fn approval_review_preferred_model(&self) -> &'static str {
        if self
            .auth_manager
            .as_ref()
            .and_then(|auth_manager| auth_manager.auth_cached())
            .is_some_and(|auth| auth.is_api_key_auth())
        {
            API_KEY_APPROVAL_REVIEW_PREFERRED_MODEL
        } else {
            DEFAULT_APPROVAL_REVIEW_PREFERRED_MODEL
        }
    }

    fn auth_manager(&self) -> Option<Arc<AuthManager>> {
        self.auth_manager.clone()
    }

    fn supports_attestation(&self) -> bool {
        self.auth_manager
            .as_ref()
            .and_then(|auth_manager| auth_manager.auth_cached())
            .is_some_and(|auth| auth.is_chatgpt_auth())
    }

    fn auth(&self) -> ModelProviderFuture<'_, Option<CodexAuth>> {
        Box::pin(async move {
            match self.auth_manager.as_ref() {
                Some(auth_manager) => auth_manager.auth().await,
                None => None,
            }
        })
    }

    fn account_state(&self) -> ProviderAccountResult {
        let account = if self.info.requires_openai_auth {
            self.auth_manager
                .as_ref()
                .and_then(|auth_manager| {
                    let auth = auth_manager.auth_cached()?;
                    if auth_manager.refresh_failure_for_auth(&auth).is_some() {
                        return None;
                    }
                    if matches!(auth, CodexAuth::Headers(_)) {
                        return None;
                    }
                    Some(auth)
                })
                .map(|auth| match &auth {
                    CodexAuth::ApiKey(_) => Ok(ProviderAccount::ApiKey),
                    CodexAuth::BedrockApiKey(_) => {
                        Err(ProviderAccountError::UnsupportedBedrockApiKeyAuth)
                    }
                    CodexAuth::Chatgpt(_)
                    | CodexAuth::ChatgptAuthTokens(_)
                    | CodexAuth::Headers(_)
                    | CodexAuth::AgentIdentity(_)
                    | CodexAuth::PersonalAccessToken(_) => {
                        let email = auth.get_account_email();
                        let plan_type = auth.account_plan_type();

                        plan_type
                            .map(|plan_type| ProviderAccount::Chatgpt { email, plan_type })
                            .ok_or(ProviderAccountError::MissingChatgptAccountDetails)
                    }
                })
                .transpose()?
        } else {
            None
        };

        Ok(ProviderAccountState {
            account,
            requires_openai_auth: self.info.requires_openai_auth,
        })
    }

    fn models_manager(
        &self,
        codex_home: PathBuf,
        config_model_catalog: Option<ModelsResponse>,
    ) -> SharedModelsManager {
        match config_model_catalog {
            Some(model_catalog) => Arc::new(StaticModelsManager::new(
                self.auth_manager.clone(),
                model_catalog,
            )),
            None => {
                let endpoint = Arc::new(OpenAiModelsEndpoint::new(
                    self.info.clone(),
                    self.auth_manager.clone(),
                ));
                Arc::new(OpenAiModelsManager::new(
                    codex_home,
                    endpoint,
                    self.auth_manager.clone(),
                ))
            }
        }
    }

    fn models_manager_without_cache(
        &self,
        config_model_catalog: Option<ModelsResponse>,
    ) -> SharedModelsManager {
        match config_model_catalog {
            Some(model_catalog) => Arc::new(StaticModelsManager::new(
                self.auth_manager.clone(),
                model_catalog,
            )),
            None => {
                let endpoint = Arc::new(OpenAiModelsEndpoint::new(
                    self.info.clone(),
                    self.auth_manager.clone(),
                ));
                Arc::new(OpenAiModelsManager::new_without_cache(
                    endpoint,
                    self.auth_manager.clone(),
                ))
            }
        }
    }

    fn models_manager_with_cache(
        &self,
        config_model_catalog: Option<ModelsResponse>,
        cache: Arc<dyn ModelsCache>,
    ) -> SharedModelsManager {
        match config_model_catalog {
            Some(model_catalog) => Arc::new(StaticModelsManager::new(
                self.auth_manager.clone(),
                model_catalog,
            )),
            None => {
                let endpoint = Arc::new(OpenAiModelsEndpoint::new(
                    self.info.clone(),
                    self.auth_manager.clone(),
                ));
                Arc::new(OpenAiModelsManager::new_with_cache(
                    cache,
                    endpoint,
                    self.auth_manager.clone(),
                ))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use base64::Engine;
    use chrono::Utc;
    use std::num::NonZeroU64;

    use codex_http_client::HttpClientFactory;
    use codex_http_client::OutboundProxyPolicy;
    use codex_login::AuthCredentialsStoreMode;
    use codex_login::AuthKeyringBackendKind;
    use codex_login::ManagedChatgptFailure;
    use codex_login::ManagedChatgptOauthCredentials;
    use codex_login::ManagedChatgptRateObservation;
    use codex_login::ManagedChatgptStatusObservation;
    use codex_login::ManagedChatgptTokenObservation;
    use codex_login::TokenData;
    use codex_login::auth::AgentIdentityAuthPolicy;
    use codex_login::auth::BedrockApiKeyAuth;
    use codex_login::auth::login_with_chatgpt_auth_tokens;
    use codex_login::token_data::IdTokenInfo;
    use codex_model_provider_info::ModelProviderAwsAuthInfo;
    use codex_model_provider_info::WireApi;
    use codex_model_provider_info::create_oss_provider_with_base_url;
    use codex_models_manager::manager::RefreshStrategy;
    use codex_protocol::account::PlanType;
    use codex_protocol::config_types::ModelProviderAuthInfo;
    use codex_protocol::openai_models::ModelInfo;
    use codex_protocol::openai_models::ModelsResponse;
    use codex_protocol::protocol::SessionSource;
    use pretty_assertions::assert_eq;
    use serde_json::json;
    use wiremock::Mock;
    use wiremock::MockServer;
    use wiremock::ResponseTemplate;
    use wiremock::matchers::header_regex;
    use wiremock::matchers::method;
    use wiremock::matchers::path;

    use super::*;
    use tempfile::tempdir;
    fn request_scope() -> ProviderAuthScope {
        ProviderAuthScope {
            agent_identity_policy: AgentIdentityAuthPolicy::JwtOnly,
            session_source: SessionSource::Cli,
            agent_identity_session_fallback: AgentIdentitySessionFallback::default(),
            thread_id: Some("thread-1".to_string()),
            session_id: Some("session-1".to_string()),
            model: Some("gpt-test".to_string()),
        }
    }

    fn managed_id_token(email: &str, account_id: &str) -> String {
        let header = serde_json::json!({"alg": "none", "typ": "JWT"});
        let payload = serde_json::json!({
            "email": email,
            "email_verified": true,
            "https://api.openai.com/auth": {
                "chatgpt_user_id": "user-12345",
                "user_id": "user-12345",
                "chatgpt_account_id": account_id,
            },
        });
        let encode = |bytes: &[u8]| base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes);
        format!(
            "{}.{}.{}",
            encode(&serde_json::to_vec(&header).expect("serialize JWT header")),
            encode(&serde_json::to_vec(&payload).expect("serialize JWT payload")),
            encode(b"sig"),
        )
    }

    fn managed_credentials(email: &str, account_id: &str) -> ManagedChatgptOauthCredentials {
        managed_credentials_with_access_token(email, account_id, "managed-access-token")
    }

    fn managed_credentials_with_access_token(
        email: &str,
        account_id: &str,
        access_token: &str,
    ) -> ManagedChatgptOauthCredentials {
        ManagedChatgptOauthCredentials {
            tokens: TokenData {
                id_token: IdTokenInfo {
                    email: Some(email.to_string()),
                    chatgpt_account_id: Some(account_id.to_string()),
                    raw_jwt: managed_id_token(email, account_id),
                    ..Default::default()
                },
                access_token: access_token.to_string(),
                refresh_token: format!("refresh-{access_token}"),
                account_id: Some(account_id.to_string()),
            },
            last_refresh: Utc::now(),
            oauth_api_key: None,
        }
    }

    use crate::auth::AgentIdentitySessionFallback;

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

    fn test_codex_home() -> std::path::PathBuf {
        std::env::temp_dir().join(format!("codex-model-provider-test-{}", std::process::id()))
    }

    fn provider_for(base_url: String) -> ModelProviderInfo {
        ModelProviderInfo {
            name: "mock".into(),
            base_url: Some(base_url),
            env_key: None,
            env_key_instructions: None,
            experimental_bearer_token: None,
            auth: None,
            aws: None,
            wire_api: WireApi::Responses,
            query_params: None,
            http_headers: None,
            env_http_headers: None,
            request_max_retries: Some(0),
            stream_max_retries: Some(0),
            stream_idle_timeout_ms: Some(5_000),
            websocket_connect_timeout_ms: None,
            requires_openai_auth: false,
            supports_websockets: false,
            supports_standalone_web_search: false,
        }
    }

    fn remote_model(slug: &str) -> ModelInfo {
        serde_json::from_value(json!({
            "slug": slug,
            "display_name": slug,
            "description": null,
            "default_reasoning_level": "medium",
            "supported_reasoning_levels": [],
            "shell_type": "shell_command",
            "visibility": "list",
            "supported_in_api": true,
            "priority": 0,
            "upgrade": null,
            "support_verbosity": false,
            "default_verbosity": null,
            "apply_patch_tool_type": null,
            "truncation_policy": {"mode": "bytes", "limit": 10_000},
            "supports_parallel_tool_calls": false,
            "supports_image_detail_original": false,
            "context_window": 272_000,
            "max_context_window": 272_000,
            "experimental_supported_tools": [],
        }))
        .expect("valid model")
    }

    fn bedrock_api_key_auth() -> CodexAuth {
        CodexAuth::BedrockApiKey(BedrockApiKeyAuth {
            api_key: "bedrock-api-key-test".to_string(),
            region: "us-east-1".to_string(),
        })
    }

    #[tokio::test]
    async fn request_setup_keeps_managed_selection_auth_headers_and_binding_atomic() {
        let codex_home = tempdir().expect("tempdir");
        let auth_manager = AuthManager::shared(
            codex_home.path().to_path_buf(),
            /*enable_codex_api_key_env*/ false,
            AuthCredentialsStoreMode::File,
            /*forced_chatgpt_workspace_id*/ None,
            /*chatgpt_base_url*/ None,
            AuthKeyringBackendKind::default(),
            codex_login::test_support::transport_default_auth_route_config(),
        )
        .await;
        let managed_id = auth_manager
            .upsert_managed_chatgpt_oauth(managed_credentials(
                "managed@example.com",
                "workspace-123",
            ))
            .await
            .expect("insert managed account");
        let provider = create_model_provider(
            ModelProviderInfo::create_openai_provider(/*base_url*/ None),
            Some(Arc::clone(&auth_manager)),
        );

        let setup = provider
            .request_setup(request_scope())
            .await
            .expect("resolve managed request setup");
        let snapshot = setup
            .managed_snapshot
            .as_ref()
            .expect("managed snapshot should be retained");

        assert_eq!(setup.managed_id.as_deref(), Some(managed_id.as_str()));
        assert_eq!(setup.credential_revision, Some(snapshot.account_revision));
        assert_eq!(
            setup.account_state_revision,
            Some(snapshot.account_state_revision)
        );
        assert_eq!(setup.selection_revision, Some(snapshot.selection_revision));
        assert_eq!(setup.transport_auth_binding, snapshot.transport);
        assert_eq!(
            setup.transport_auth_binding.raw_account_id.as_deref(),
            Some("workspace-123")
        );
        assert!(!setup.transport_auth_binding.fedramp);
        assert_eq!(
            setup
                .api_auth
                .to_auth_headers()
                .get("ChatGPT-Account-ID")
                .expect("raw account header"),
            "workspace-123"
        );
        assert_eq!(setup.effective_auth, Some(snapshot.auth.clone()));
    }

    #[tokio::test]
    async fn managed_dynamic_auth_rejects_same_identity_credential_revision_change() {
        let codex_home = tempdir().expect("tempdir");
        let auth_manager = AuthManager::shared(
            codex_home.path().to_path_buf(),
            /*enable_codex_api_key_env*/ false,
            AuthCredentialsStoreMode::File,
            /*forced_chatgpt_workspace_id*/ None,
            /*chatgpt_base_url*/ None,
            AuthKeyringBackendKind::default(),
            codex_login::test_support::transport_default_auth_route_config(),
        )
        .await;
        let identity = auth_manager
            .upsert_managed_chatgpt_oauth(managed_credentials_with_access_token(
                "managed@example.com",
                "workspace-123",
                "first-token",
            ))
            .await
            .expect("insert managed account");
        let snapshot = auth_manager
            .managed_chatgpt_auth_snapshot_for_identity(&identity)
            .await
            .expect("read managed account")
            .expect("managed account exists");
        let provider = crate::auth::auth_provider_from_auth_manager(
            Arc::clone(&auth_manager),
            &snapshot.auth,
            snapshot.transport.clone(),
            Some(snapshot.account_revision),
        );
        assert_eq!(
            provider.to_auth_headers().get(http::header::AUTHORIZATION),
            Some(&http::HeaderValue::from_static("Bearer first-token"))
        );

        auth_manager
            .upsert_managed_chatgpt_oauth(managed_credentials_with_access_token(
                "managed@example.com",
                "workspace-123",
                "second-token",
            ))
            .await
            .expect("refresh managed credential");

        assert!(
            provider.to_auth_headers().is_empty(),
            "a provider scoped to credential revision r1 must fail closed after r2"
        );
    }
    #[tokio::test]
    async fn managed_dynamic_auth_survives_account_state_revision_change() {
        let codex_home = tempdir().expect("tempdir");
        let auth_manager = AuthManager::shared(
            codex_home.path().to_path_buf(),
            /*enable_codex_api_key_env*/ false,
            AuthCredentialsStoreMode::File,
            /*forced_chatgpt_workspace_id*/ None,
            /*chatgpt_base_url*/ None,
            AuthKeyringBackendKind::default(),
            codex_login::test_support::transport_default_auth_route_config(),
        )
        .await;
        let identity = auth_manager
            .upsert_managed_chatgpt_oauth(managed_credentials_with_access_token(
                "managed@example.com",
                "workspace-123",
                "first-token",
            ))
            .await
            .expect("insert managed account");
        let snapshot = auth_manager
            .managed_chatgpt_auth_snapshot_for_identity(&identity)
            .await
            .expect("read managed account")
            .expect("managed account exists");
        let provider = crate::auth::auth_provider_from_auth_manager(
            Arc::clone(&auth_manager),
            &snapshot.auth,
            snapshot.transport.clone(),
            Some(snapshot.account_revision),
        );

        auth_manager
            .record_managed_chatgpt_status_observation(
                &identity,
                snapshot.account_revision,
                snapshot.account_state_revision,
                ManagedChatgptStatusObservation {
                    observed_at: Utc::now(),
                    rate: ManagedChatgptRateObservation::Unavailable {
                        reason: "state-only observation".to_string(),
                    },
                    token: ManagedChatgptTokenObservation::NotObserved,
                },
            )
            .expect("record status observation")
            .expect("state revision should advance");

        assert_eq!(
            provider.to_auth_headers().get(http::header::AUTHORIZATION),
            Some(&http::HeaderValue::from_static("Bearer first-token")),
            "state-only observations must not invalidate dynamic auth"
        );
    }

    #[tokio::test]
    async fn request_setup_refreshes_pinned_identity_without_using_default_sibling() {
        let codex_home = tempdir().expect("tempdir");
        let pool_manager = AuthManager::shared(
            codex_home.path().to_path_buf(),
            /*enable_codex_api_key_env*/ false,
            AuthCredentialsStoreMode::File,
            /*forced_chatgpt_workspace_id*/ None,
            /*chatgpt_base_url*/ None,
            AuthKeyringBackendKind::default(),
            codex_login::test_support::transport_default_auth_route_config(),
        )
        .await;
        let first_id = pool_manager
            .upsert_managed_chatgpt_oauth(managed_credentials_with_access_token(
                "first@example.com",
                "workspace-first",
                "first-old",
            ))
            .await
            .expect("insert first account");
        let second_id = pool_manager
            .upsert_managed_chatgpt_oauth(managed_credentials_with_access_token(
                "second@example.com",
                "workspace-second",
                "second-old",
            ))
            .await
            .expect("insert second account");
        let selection_scope = ManagedChatgptSelectionScope {
            thread_id: Some("thread-1".to_string()),
            session_id: Some("session-1".to_string()),
            model: Some("gpt-test".to_string()),
        };
        let selected_snapshot = pool_manager
            .managed_chatgpt_auth_snapshot(&selection_scope)
            .await
            .expect("select managed account")
            .expect("eligible selected account");
        let sibling_id = if selected_snapshot.identity_key == first_id {
            &second_id
        } else {
            &first_id
        };
        let sibling_auth = pool_manager
            .managed_chatgpt_auth_snapshot_for_identity(sibling_id)
            .await
            .expect("resolve sibling")
            .expect("sibling snapshot")
            .auth;
        let request_manager = AuthManager::from_auth_for_testing_with_home(
            sibling_auth,
            codex_home.path().to_path_buf(),
        );
        assert_ne!(
            request_manager
                .auth_cached()
                .expect("singular default")
                .get_account_id(),
            selected_snapshot.auth.get_account_id()
        );
        let provider = create_model_provider(
            ModelProviderInfo::create_openai_provider(/*base_url*/ None),
            Some(request_manager),
        );
        let initial = provider
            .request_setup(request_scope())
            .await
            .expect("resolve initially selected account");
        let initial_revision = initial
            .credential_revision
            .expect("selected credential revision should be retained");
        let (selected_email, selected_account, old_bearer) =
            if selected_snapshot.identity_key == first_id {
                ("first@example.com", "workspace-first", "first-old")
            } else {
                ("second@example.com", "workspace-second", "second-old")
            };

        pool_manager
            .upsert_managed_chatgpt_oauth(managed_credentials_with_access_token(
                selected_email,
                selected_account,
                "selected-refreshed",
            ))
            .await
            .expect("refresh selected account");
        let refreshed = provider
            .request_setup(request_scope())
            .await
            .expect("resolve refreshed selected account");
        let refreshed_headers = refreshed.api_auth.to_auth_headers();

        assert_eq!(
            refreshed.managed_id.as_deref(),
            Some(selected_snapshot.identity_key.as_str())
        );
        assert!(
            refreshed
                .credential_revision
                .is_some_and(|revision| revision > initial_revision)
        );
        assert_eq!(
            refreshed_headers
                .get(http::header::AUTHORIZATION)
                .expect("selected bearer"),
            "Bearer selected-refreshed"
        );
        assert_eq!(
            refreshed_headers
                .get("ChatGPT-Account-ID")
                .expect("selected raw account"),
            selected_account
        );
        assert_eq!(
            initial
                .api_auth
                .to_auth_headers()
                .get(http::header::AUTHORIZATION)
                .expect("initial attempt bearer")
                .to_str()
                .expect("initial attempt bearer text"),
            format!("Bearer {old_bearer}")
        );
        assert_eq!(
            refreshed.transport_auth_binding.identity_key,
            initial.transport_auth_binding.identity_key
        );
        assert_eq!(
            refreshed.transport_auth_binding.raw_account_id,
            initial.transport_auth_binding.raw_account_id
        );
        assert_eq!(
            refreshed.transport_auth_binding.fedramp,
            initial.transport_auth_binding.fedramp
        );
        assert_eq!(
            refreshed.transport_auth_binding.auth_mode,
            initial.transport_auth_binding.auth_mode
        );
        assert_eq!(refreshed.api_provider.name, initial.api_provider.name);
        assert_eq!(
            refreshed.api_provider.base_url,
            initial.api_provider.base_url
        );
    }

    #[tokio::test]
    async fn request_setup_keeps_api_key_precedence_when_managed_pool_persists() {
        let codex_home = tempdir().expect("tempdir");
        let pool_manager = AuthManager::shared(
            codex_home.path().to_path_buf(),
            /*enable_codex_api_key_env*/ false,
            AuthCredentialsStoreMode::File,
            /*forced_chatgpt_workspace_id*/ None,
            /*chatgpt_base_url*/ None,
            AuthKeyringBackendKind::default(),
            codex_login::test_support::transport_default_auth_route_config(),
        )
        .await;
        pool_manager
            .upsert_managed_chatgpt_oauth(managed_credentials(
                "preserved@example.com",
                "workspace-preserved",
            ))
            .await
            .expect("persist managed account pool");
        let auth_manager = AuthManager::from_auth_for_testing_with_home(
            CodexAuth::from_api_key("env-api-key"),
            codex_home.path().to_path_buf(),
        );
        let provider = create_model_provider(
            ModelProviderInfo::create_openai_provider(/*base_url*/ None),
            Some(auth_manager),
        );

        let setup = provider
            .request_setup(request_scope())
            .await
            .expect("API key request setup");

        assert_eq!(
            setup
                .api_auth
                .to_auth_headers()
                .get(http::header::AUTHORIZATION)
                .expect("API key bearer"),
            "Bearer env-api-key"
        );
        assert_eq!(
            setup.effective_auth.as_ref().map(CodexAuth::auth_mode),
            Some(codex_protocol::auth::AuthMode::ApiKey)
        );
        assert!(setup.managed_snapshot.is_none());
        assert!(setup.managed_id.is_none());
        assert_eq!(
            setup.transport_auth_binding.identity_key,
            codex_protocol::auth::AuthMode::ApiKey.to_string()
        );
    }

    #[tokio::test]
    async fn request_setup_reloads_replaced_external_overlay_before_pool_selection() {
        let codex_home = tempdir().expect("tempdir");
        let auth_manager = AuthManager::shared(
            codex_home.path().to_path_buf(),
            /*enable_codex_api_key_env*/ false,
            AuthCredentialsStoreMode::File,
            /*forced_chatgpt_workspace_id*/ None,
            /*chatgpt_base_url*/ None,
            AuthKeyringBackendKind::default(),
            codex_login::test_support::transport_default_auth_route_config(),
        )
        .await;
        auth_manager
            .upsert_managed_chatgpt_oauth(managed_credentials(
                "managed@example.com",
                "workspace-managed",
            ))
            .await
            .expect("persist managed account pool");
        let overlay_a_token = managed_id_token("external-a@example.com", "workspace-external-a");
        login_with_chatgpt_auth_tokens(
            codex_home.path(),
            &overlay_a_token,
            "workspace-external-a",
            Some("team"),
        )
        .expect("install external overlay A");
        assert!(
            auth_manager
                .auth()
                .await
                .is_some_and(|auth| auth.is_external_chatgpt_tokens()),
            "overlay A must be cached before replacement"
        );

        let overlay_b_token = managed_id_token("external-b@example.com", "workspace-external-b");
        login_with_chatgpt_auth_tokens(
            codex_home.path(),
            &overlay_b_token,
            "workspace-external-b",
            Some("enterprise"),
        )
        .expect("replace external overlay A with B");
        assert!(
            auth_manager.auth_cached().is_none(),
            "overlay replacement must invalidate cached overlay A"
        );
        let provider = create_model_provider(
            ModelProviderInfo::create_openai_provider(/*base_url*/ None),
            Some(auth_manager),
        );

        let setup = provider
            .request_setup(request_scope())
            .await
            .expect("request setup must reload overlay B");
        let auth_headers = setup.api_auth.to_auth_headers();
        let authorization = auth_headers
            .get(http::header::AUTHORIZATION)
            .expect("external overlay bearer");

        assert!(
            authorization.as_bytes() == format!("Bearer {overlay_b_token}").as_bytes(),
            "request setup must use the exact overlay B bearer"
        );
        assert_eq!(setup.transport_auth_binding.identity_key, "user-12345");
        assert_eq!(
            setup.transport_auth_binding.raw_account_id.as_deref(),
            Some("workspace-external-b")
        );
        assert!(setup.managed_snapshot.is_none());
        assert!(setup.managed_id.is_none());
    }

    #[tokio::test]
    async fn request_setup_rejects_managed_pool_without_an_eligible_snapshot() {
        let codex_home = tempdir().expect("tempdir");
        let auth_manager = AuthManager::shared(
            codex_home.path().to_path_buf(),
            /*enable_codex_api_key_env*/ false,
            AuthCredentialsStoreMode::File,
            /*forced_chatgpt_workspace_id*/ None,
            /*chatgpt_base_url*/ None,
            AuthKeyringBackendKind::default(),
            codex_login::test_support::transport_default_auth_route_config(),
        )
        .await;
        auth_manager
            .upsert_managed_chatgpt_oauth(managed_credentials(
                "managed@example.com",
                "workspace-123",
            ))
            .await
            .expect("insert managed account");
        let selection_scope = ManagedChatgptSelectionScope {
            thread_id: Some("thread-1".to_string()),
            session_id: Some("session-1".to_string()),
            model: Some("gpt-test".to_string()),
        };
        let snapshot = auth_manager
            .managed_chatgpt_auth_snapshot(&selection_scope)
            .await
            .expect("select managed account")
            .expect("eligible managed account");
        auth_manager
            .recover_failed_attempt(
                &snapshot,
                ManagedChatgptFailure::Quota { reset_at: None },
                /*committed*/ false,
                &selection_scope,
            )
            .await
            .expect("block the only account");
        let provider = create_model_provider(
            ModelProviderInfo::create_openai_provider(/*base_url*/ None),
            Some(auth_manager),
        );

        let error = match provider.request_setup(request_scope()).await {
            Ok(_) => panic!("blocked managed pool must not fall back to singular auth"),
            Err(error) => error,
        };
        assert!(
            error
                .to_string()
                .contains("managed ChatGPT account pool has no eligible account")
        );
    }

    #[tokio::test]
    async fn request_setup_gives_explicit_provider_bearer_precedence_over_managed_auth() {
        let mut provider_info = ModelProviderInfo::create_openai_provider(/*base_url*/ None);
        provider_info.experimental_bearer_token = Some("provider-token".to_string());
        let provider = create_model_provider(
            provider_info,
            Some(AuthManager::from_auth_for_testing(
                CodexAuth::create_dummy_chatgpt_auth_for_testing(),
            )),
        );
        assert!(
            provider.auth_manager().is_none(),
            "static provider bearer must not inherit the managed auth manager"
        );
        assert!(!provider.supports_attestation());

        let setup = provider
            .request_setup(request_scope())
            .await
            .expect("resolve external provider setup");

        assert!(setup.effective_auth.is_none());
        assert!(setup.managed_snapshot.is_none());
        assert!(setup.managed_id.is_none());
        assert!(setup.credential_revision.is_none());
        assert!(setup.account_state_revision.is_none());
        assert!(setup.selection_revision.is_none());
        assert_eq!(
            setup
                .api_auth
                .to_auth_headers()
                .get(http::header::AUTHORIZATION)
                .expect("provider bearer header"),
            "Bearer provider-token"
        );
        assert_eq!(setup.transport_auth_binding.identity_key, "unauthenticated");
    }

    #[tokio::test]
    async fn request_setup_preserves_non_pooled_api_key_auth() {
        let auth = CodexAuth::from_api_key("openai-api-key");
        let provider = create_model_provider(
            ModelProviderInfo::create_openai_provider(/*base_url*/ None),
            Some(AuthManager::from_auth_for_testing(auth.clone())),
        );

        let setup = provider
            .request_setup(request_scope())
            .await
            .expect("resolve API key setup");

        assert_eq!(setup.effective_auth, Some(auth));
        assert!(setup.managed_snapshot.is_none());
        assert_eq!(
            setup
                .api_auth
                .to_auth_headers()
                .get(http::header::AUTHORIZATION)
                .expect("API key header"),
            "Bearer openai-api-key"
        );
    }

    #[tokio::test]
    async fn bedrock_request_setup_preserves_managed_bedrock_auth() {
        let auth = bedrock_api_key_auth();
        let provider = create_model_provider(
            ModelProviderInfo::create_amazon_bedrock_provider(/*aws*/ None),
            Some(AuthManager::from_auth_for_testing(auth.clone())),
        );

        let setup = provider
            .request_setup(request_scope())
            .await
            .expect("resolve Bedrock request setup");

        assert_eq!(setup.effective_auth, Some(auth));
        assert!(setup.managed_snapshot.is_none());
        assert!(setup.managed_id.is_none());
    }

    #[tokio::test]
    async fn scoped_auth_ignores_scope_for_non_openai_provider() {
        let provider = create_model_provider(
            create_oss_provider_with_base_url("http://localhost:11434/v1", WireApi::Responses),
            /*auth_manager*/ None,
        );

        let auth = provider
            .api_auth_for_scope(ProviderAuthScope {
                agent_identity_policy: AgentIdentityAuthPolicy::JwtOnly,
                session_source: SessionSource::Cli,
                agent_identity_session_fallback: AgentIdentitySessionFallback::default(),
                thread_id: None,
                session_id: None,
                model: None,
            })
            .await
            .expect("auth should resolve");

        assert!(auth.auth.to_auth_headers().is_empty());
    }

    #[test]
    fn configured_provider_uses_default_capabilities() {
        let provider = create_model_provider(
            ModelProviderInfo::create_openai_provider(/*base_url*/ None),
            /*auth_manager*/ None,
        );

        assert_eq!(provider.capabilities(), ProviderCapabilities::default());
    }

    #[test]
    fn configured_provider_remote_compaction_matches_provider_support() {
        let cases = [
            (
                ModelProviderInfo::create_openai_provider(/*base_url*/ None),
                RemoteCompactionSupport::V2,
            ),
            (
                ModelProviderInfo {
                    name: "Azure".to_string(),
                    base_url: Some("https://example.com/openai".to_string()),
                    ..ModelProviderInfo::default()
                },
                RemoteCompactionSupport::V2,
            ),
            (
                ModelProviderInfo {
                    name: "Custom".to_string(),
                    base_url: Some("https://example.openai.azure.com/openai/v1".to_string()),
                    ..ModelProviderInfo::default()
                },
                RemoteCompactionSupport::V2,
            ),
            (
                provider_for("https://example.test/v1".to_string()),
                RemoteCompactionSupport::Unsupported,
            ),
        ];

        for (provider_info, expected) in cases {
            let provider = create_model_provider(provider_info, /*auth_manager*/ None);
            assert_eq!(provider.capabilities().remote_compaction, expected);
        }
    }

    #[test]
    fn configured_provider_uses_default_approval_review_preferred_model() {
        let provider = create_model_provider(
            ModelProviderInfo::create_openai_provider(/*base_url*/ None),
            /*auth_manager*/ None,
        );

        assert_eq!(
            provider.approval_review_preferred_model(),
            DEFAULT_APPROVAL_REVIEW_PREFERRED_MODEL
        );
    }

    #[test]
    fn configured_provider_uses_luna_for_approval_review_with_api_key_auth() {
        let provider = create_model_provider(
            ModelProviderInfo::create_openai_provider(/*base_url*/ None),
            Some(AuthManager::from_auth_for_testing(CodexAuth::from_api_key(
                "openai-api-key",
            ))),
        );

        assert_eq!(provider.approval_review_preferred_model(), "gpt-5.6-luna");
    }

    #[test]
    fn configured_provider_uses_default_approval_review_model_with_chatgpt_auth() {
        let provider = create_model_provider(
            ModelProviderInfo::create_openai_provider(/*base_url*/ None),
            Some(AuthManager::from_auth_for_testing(
                CodexAuth::create_dummy_chatgpt_auth_for_testing(),
            )),
        );

        assert_eq!(
            provider.approval_review_preferred_model(),
            DEFAULT_APPROVAL_REVIEW_PREFERRED_MODEL
        );
    }

    #[tokio::test]
    async fn configured_provider_runtime_base_url_uses_configured_base_url() {
        let provider = create_model_provider(
            provider_for("https://example.test/v1".to_string()),
            /*auth_manager*/ None,
        );

        assert_eq!(
            provider
                .runtime_base_url()
                .await
                .expect("runtime base URL should resolve"),
            Some("https://example.test/v1".to_string())
        );
    }

    #[test]
    fn create_model_provider_builds_command_auth_manager_without_base_manager() {
        let provider = create_model_provider(
            provider_info_with_command_auth(),
            /*auth_manager*/ None,
        );

        let auth_manager = provider
            .auth_manager()
            .expect("command auth provider should have an auth manager");

        assert!(auth_manager.has_external_auth());
    }

    #[test]
    fn create_model_provider_does_not_use_openai_auth_manager_for_amazon_bedrock_provider() {
        let provider = create_model_provider(
            ModelProviderInfo::create_amazon_bedrock_provider(Some(ModelProviderAwsAuthInfo {
                profile: Some("codex-bedrock".to_string()),
                region: None,
            })),
            Some(AuthManager::from_auth_for_testing(CodexAuth::from_api_key(
                "openai-api-key",
            ))),
        );

        assert!(provider.auth_manager().is_none());
    }

    #[tokio::test]
    async fn create_model_provider_uses_managed_auth_for_amazon_bedrock_provider() {
        let auth = bedrock_api_key_auth();
        let provider = create_model_provider(
            ModelProviderInfo::create_amazon_bedrock_provider(/*aws*/ None),
            Some(AuthManager::from_auth_for_testing(auth.clone())),
        );

        assert_eq!(provider.auth().await, Some(auth));
    }

    #[test]
    fn openai_provider_returns_unauthenticated_openai_account_state() {
        let provider = create_model_provider(
            ModelProviderInfo::create_openai_provider(/*base_url*/ None),
            /*auth_manager*/ None,
        );

        assert_eq!(
            provider.account_state(),
            Ok(ProviderAccountState {
                account: None,
                requires_openai_auth: true,
            })
        );
    }

    #[test]
    fn openai_provider_returns_api_key_account_state() {
        let provider = create_model_provider(
            ModelProviderInfo::create_openai_provider(/*base_url*/ None),
            Some(AuthManager::from_auth_for_testing(CodexAuth::from_api_key(
                "openai-api-key",
            ))),
        );

        assert_eq!(
            provider.account_state(),
            Ok(ProviderAccountState {
                account: Some(ProviderAccount::ApiKey),
                requires_openai_auth: true,
            })
        );
    }

    #[test]
    fn openai_provider_returns_chatgpt_account_state_without_email() {
        let provider = create_model_provider(
            ModelProviderInfo::create_openai_provider(/*base_url*/ None),
            Some(AuthManager::from_auth_for_testing(
                CodexAuth::create_dummy_chatgpt_auth_for_testing(),
            )),
        );

        assert_eq!(
            provider.account_state(),
            Ok(ProviderAccountState {
                account: Some(ProviderAccount::Chatgpt {
                    email: None,
                    plan_type: PlanType::Unknown,
                }),
                requires_openai_auth: true,
            })
        );
    }

    #[test]
    fn openai_provider_rejects_bedrock_api_key_account_state() {
        let provider = create_model_provider(
            ModelProviderInfo::create_openai_provider(/*base_url*/ None),
            Some(AuthManager::from_auth_for_testing(bedrock_api_key_auth())),
        );

        assert_eq!(
            provider.account_state(),
            Err(ProviderAccountError::UnsupportedBedrockApiKeyAuth)
        );
    }

    #[test]
    fn custom_non_openai_provider_returns_no_account_state() {
        let provider = create_model_provider(
            ModelProviderInfo {
                name: "Custom".to_string(),
                base_url: Some("http://localhost:1234/v1".to_string()),
                wire_api: WireApi::Responses,
                requires_openai_auth: false,
                ..Default::default()
            },
            /*auth_manager*/ None,
        );

        assert_eq!(
            provider.account_state(),
            Ok(ProviderAccountState {
                account: None,
                requires_openai_auth: false,
            })
        );
    }

    #[test]
    fn amazon_bedrock_provider_returns_bedrock_account_state() {
        let provider = create_model_provider(
            ModelProviderInfo::create_amazon_bedrock_provider(/*aws*/ None),
            /*auth_manager*/ None,
        );

        assert_eq!(
            provider.account_state(),
            Ok(ProviderAccountState {
                account: Some(ProviderAccount::AmazonBedrock {
                    uses_codex_managed_credentials: false,
                }),
                requires_openai_auth: false,
            })
        );
    }

    #[tokio::test]
    async fn amazon_bedrock_provider_creates_static_models_manager() {
        let provider = create_model_provider(
            ModelProviderInfo::create_amazon_bedrock_provider(/*aws*/ None),
            /*auth_manager*/ None,
        );
        let manager =
            provider.models_manager(test_codex_home(), /*config_model_catalog*/ None);
        let uncached_manager =
            provider.models_manager_without_cache(/*config_model_catalog*/ None);

        let catalog = manager
            .raw_model_catalog(
                RefreshStrategy::Online,
                HttpClientFactory::new(OutboundProxyPolicy::ReqwestDefault),
            )
            .await;
        let uncached_catalog = uncached_manager
            .raw_model_catalog(
                RefreshStrategy::Online,
                HttpClientFactory::new(OutboundProxyPolicy::ReqwestDefault),
            )
            .await;
        assert_eq!(uncached_catalog, catalog);
        let models = catalog
            .models
            .iter()
            .map(|model| (model.slug.as_str(), model.display_name.as_str()))
            .collect::<Vec<_>>();

        assert_eq!(
            models,
            vec![
                ("openai.gpt-5.6-sol", "GPT-5.6 Sol"),
                ("openai.gpt-5.6-terra", "GPT-5.6 Terra"),
                ("openai.gpt-5.6-luna", "GPT-5.6 Luna"),
                ("openai.gpt-5.5", "GPT-5.5"),
                ("openai.gpt-5.4", "GPT-5.4"),
            ]
        );

        let available_models = manager
            .list_models(
                RefreshStrategy::Online,
                HttpClientFactory::new(OutboundProxyPolicy::ReqwestDefault),
            )
            .await;
        assert_eq!(
            available_models
                .iter()
                .map(|preset| preset.model.as_str())
                .collect::<Vec<_>>(),
            vec![
                "openai.gpt-5.6-sol",
                "openai.gpt-5.6-terra",
                "openai.gpt-5.6-luna",
                "openai.gpt-5.5",
                "openai.gpt-5.4",
            ]
        );

        let default_model = available_models
            .iter()
            .find(|preset| preset.is_default)
            .expect("Bedrock catalog should have a default model");

        assert_eq!(default_model.model, "openai.gpt-5.6-sol");
    }

    #[tokio::test]
    async fn configured_bedrock_catalog_only_allows_default_service_tier() {
        let configured_model = codex_models_manager::bundled_models_response()
            .expect("bundled models should parse")
            .models
            .into_iter()
            .find(|model| model.slug == "gpt-5.5")
            .expect("bundled models should include GPT-5.5");
        assert!(!configured_model.additional_speed_tiers.is_empty());
        assert!(!configured_model.service_tiers.is_empty());

        let provider = create_model_provider(
            ModelProviderInfo::create_amazon_bedrock_provider(/*aws*/ None),
            /*auth_manager*/ None,
        );
        let manager = provider.models_manager(
            test_codex_home(),
            Some(ModelsResponse {
                models: vec![configured_model],
            }),
        );

        let catalog = manager
            .raw_model_catalog(
                RefreshStrategy::Online,
                HttpClientFactory::new(OutboundProxyPolicy::ReqwestDefault),
            )
            .await;

        assert_eq!(catalog.models.len(), 1);
        assert_eq!(catalog.models[0].slug, "gpt-5.5");
        assert_eq!(
            catalog.models[0].additional_speed_tiers,
            Vec::<String>::new()
        );
        assert_eq!(catalog.models[0].service_tiers, Vec::new());
        assert_eq!(catalog.models[0].default_service_tier, None);
    }

    #[tokio::test]
    async fn configured_provider_models_manager_uses_provider_bearer_token() {
        let server = MockServer::start().await;
        let remote_models = vec![remote_model("provider-model")];

        Mock::given(method("GET"))
            .and(path("/models"))
            .and(header_regex("Authorization", "Bearer provider-token"))
            .respond_with(
                ResponseTemplate::new(200)
                    .insert_header("content-type", "application/json")
                    .set_body_json(ModelsResponse {
                        models: remote_models.clone(),
                    }),
            )
            .expect(1)
            .mount(&server)
            .await;

        let mut provider_info = provider_for(server.uri());
        provider_info.experimental_bearer_token = Some("provider-token".to_string());
        let provider = create_model_provider(
            provider_info,
            Some(AuthManager::from_auth_for_testing(
                CodexAuth::create_dummy_chatgpt_auth_for_testing(),
            )),
        );

        let codex_home = tempdir().expect("codex home");
        let manager = provider.models_manager(
            codex_home.path().to_path_buf(),
            /*config_model_catalog*/ None,
        );
        let catalog = manager
            .raw_model_catalog(
                RefreshStrategy::Online,
                HttpClientFactory::new(OutboundProxyPolicy::ReqwestDefault),
            )
            .await;

        let requests = server
            .received_requests()
            .await
            .expect("recorded model requests");
        assert_eq!(requests.len(), 1, "expected one provider models request");
        assert_eq!(
            requests[0].headers.get(http::header::AUTHORIZATION),
            Some(&http::HeaderValue::from_static("Bearer provider-token"))
        );

        assert!(
            catalog
                .models
                .iter()
                .any(|model| model.slug == "provider-model")
        );
    }
}
