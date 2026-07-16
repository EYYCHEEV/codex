use chrono::Utc;
use http::StatusCode;
use rand::Rng;
use serde::Deserialize;
use serde::Serialize;
#[cfg(test)]
use serial_test::serial;
use sha2::Digest;
use sha2::Sha256;
use std::env;
use std::fmt::Debug;
use std::future::Future;
use std::path::Path;
use std::path::PathBuf;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::RwLock;
use std::sync::atomic::AtomicU64;
use std::sync::atomic::Ordering;
use std::time::Duration;
use std::time::Instant;
use tokio::sync::Semaphore;
use tokio::sync::watch;
use tracing::instrument;

use codex_agent_identity::ChatGptEnvironment;
use codex_protocol::auth::AuthMode;
use codex_protocol::config_types::ForcedLoginMethod;
use codex_protocol::config_types::ModelProviderAuthInfo;

use super::access_token::CodexAccessToken;
use super::access_token::classify_codex_access_token;
pub use super::account_pool::ManagedChatgptAccountList;
pub use super::account_pool::ManagedChatgptAccountView;
pub use super::account_pool::ManagedChatgptAuthSnapshot;
pub use super::account_pool::ManagedChatgptBlockKindView;
pub use super::account_pool::ManagedChatgptEligibility;
pub use super::account_pool::ManagedChatgptFailure;
pub use super::account_pool::ManagedChatgptOauthCredentials;
pub use super::account_pool::ManagedChatgptRateObservation;
pub use super::account_pool::ManagedChatgptRateWindowView;
pub use super::account_pool::ManagedChatgptRecoveryDecision;
pub use super::account_pool::ManagedChatgptRefreshStatus;
pub use super::account_pool::ManagedChatgptSelectionScope;
pub use super::account_pool::ManagedChatgptStatusObservation;
pub use super::account_pool::ManagedChatgptTokenObservation;
pub use super::account_pool::ManagedChatgptTokenState;
pub use super::account_pool::ManagedChatgptUsageState;
pub use super::account_pool::ManagedChatgptUsageView;
use super::account_pool::SelectionPins;
pub use super::account_pool::TransportAuthBinding;
use super::account_pool::allocate_account_revision;
use super::account_pool::apply_failure;
use super::account_pool::credential_revision;
use super::account_pool::migrate_document;
use super::account_pool::rebind_refreshed_identity;
use super::account_pool::record_status_observation;
use super::account_pool::resolve_identity;
use super::account_pool::row;
use super::account_pool::row_mut;
use super::account_pool::select;
use super::account_pool::singular_document;
use super::account_pool::upsert;
use super::account_pool::validate_document;
use super::account_pool::views;
use super::agent_identity::ManagedChatGptAgentIdentityBinding;
use super::agent_identity::agent_identity_authapi_base_url;
use super::agent_identity::classify_bootstrap_error;
use super::agent_identity::record_matches_managed_chatgpt_binding;
use super::agent_identity::record_needs_task_registration;
use super::agent_identity::register_managed_chatgpt_agent_identity;
use super::agent_identity::require_agent_identity_authapi_base_url;
use super::agent_identity::verified_record_from_jwt;
use super::external_bearer::BearerTokenRefresher;
use super::revoke::revoke_auth_tokens;
use crate::auth::AuthHeaders;
pub use crate::auth::agent_identity::AgentIdentityAuth;
pub use crate::auth::agent_identity::AgentIdentityAuthError;
pub use crate::auth::bedrock_api_key::BedrockApiKeyAuth;
pub use crate::auth::personal_access_token::PersonalAccessTokenAuth;
pub use crate::auth::storage::AgentIdentityAuthRecord;
pub use crate::auth::storage::AgentIdentityStorage;
pub use crate::auth::storage::AuthDotJson;
pub use crate::auth::storage::AuthKeyringBackendKind;
use crate::auth::storage::AuthStorageBackend;
use crate::auth::storage::AuthStorageMutation;
use crate::auth::storage::ManagedChatgptBlock;
use crate::auth::storage::ManagedChatgptBlockKind;
pub use crate::auth::storage::ManagedChatgptLimitKind;
use crate::auth::storage::ManagedChatgptMutationKind;
use crate::auth::storage::ManagedChatgptMutationLease;
use crate::auth::storage::ManagedChatgptRefreshFailure;
pub use crate::auth::storage::ManagedChatgptTokenUsageSummary;
use crate::auth::storage::ManagedChatgptTombstone;
use crate::auth::storage::create_auth_storage;
use crate::auth::storage::delete_external_chatgpt_auth;
use crate::auth::storage::load_external_chatgpt_auth;
use crate::auth::storage::save_external_chatgpt_auth;
use crate::auth::util::try_parse_error_message;
use crate::default_client::create_client;
use crate::default_client::create_default_auth_client;
use crate::outbound_proxy::AuthRouteConfig;
use crate::token_data::TokenData;
use crate::token_data::parse_chatgpt_jwt_claims;
use crate::token_data::parse_jwt_expiration;
use codex_config::ManagedAuthPolicy;
use codex_config::types::AuthCredentialsStoreMode;
use codex_http_client::HttpClient;
use codex_http_client::HttpClientFactory;
use codex_http_client::OutboundProxyPolicy;
use codex_protocol::account::PlanType as AccountPlanType;
use codex_protocol::auth::PlanType as InternalPlanType;
use codex_protocol::auth::RefreshTokenFailedError;
use codex_protocol::auth::RefreshTokenFailedReason;
use codex_protocol::protocol::SessionSource;
use serde_json::Value;
use thiserror::Error;

#[path = "managed_accounts.rs"]
mod managed_accounts;
#[cfg(test)]
use managed_accounts::persist_managed_refresh_failure;

/// Authentication mechanism used by the current user.
#[derive(Debug, Clone)]
pub enum CodexAuth {
    ApiKey(ApiKeyAuth),
    Chatgpt(ChatgptAuth),
    ChatgptAuthTokens(ChatgptAuthTokens),
    Headers(AuthHeaders),
    AgentIdentity(AgentIdentityAuth),
    PersonalAccessToken(PersonalAccessTokenAuth),
    BedrockApiKey(BedrockApiKeyAuth),
}

/// Policy for resolving Agent Identity auth from a broader Codex auth snapshot.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AgentIdentityAuthPolicy {
    /// Use Agent Identity auth only when the current auth is already Agent Identity.
    JwtOnly,
    /// Allow managed ChatGPT auth to register or reuse Agent Identity auth.
    ChatGptAuth,
}

const AGENT_IDENTITY_BOOTSTRAP_FAILURE_COOLDOWN: Duration = Duration::from_secs(60 * 60);

#[derive(Debug, Clone, PartialEq, Eq)]
struct AgentIdentityBootstrapCooldownKey {
    identity_key: String,
    chatgpt_user_id: String,
    account_id: String,
    authapi_base_url: String,
}

#[derive(Debug)]
struct CachedAgentIdentityBootstrapFailure {
    key: AgentIdentityBootstrapCooldownKey,
    retry_at: Instant,
    error: AgentIdentityAuthError,
}

#[derive(Debug, Default)]
struct AgentIdentityBootstrapCooldown {
    failures: Vec<CachedAgentIdentityBootstrapFailure>,
}

impl AgentIdentityBootstrapCooldown {
    fn error_for(
        &mut self,
        key: &AgentIdentityBootstrapCooldownKey,
        now: Instant,
    ) -> Option<AgentIdentityAuthError> {
        self.failures.retain(|failure| failure.retry_at > now);
        self.failures
            .iter()
            .find(|failure| failure.key == *key)
            .map(|failure| failure.error.clone())
    }

    fn record_failure(
        &mut self,
        key: AgentIdentityBootstrapCooldownKey,
        error: AgentIdentityAuthError,
        now: Instant,
        capacity: usize,
    ) {
        self.failures.retain(|failure| failure.retry_at > now);
        self.failures.retain(|failure| failure.key != key);
        self.failures.push(CachedAgentIdentityBootstrapFailure {
            key,
            retry_at: now + AGENT_IDENTITY_BOOTSTRAP_FAILURE_COOLDOWN,
            error,
        });
        let excess = self.failures.len().saturating_sub(capacity.max(1));
        self.failures.drain(..excess);
    }

    fn clear(&mut self, key: &AgentIdentityBootstrapCooldownKey) {
        self.failures.retain(|failure| failure.key != *key);
    }
}

impl PartialEq for CodexAuth {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::Headers(a), Self::Headers(b)) => a == b,
            (Self::PersonalAccessToken(a), Self::PersonalAccessToken(b)) => a == b,
            (Self::BedrockApiKey(a), Self::BedrockApiKey(b)) => a == b,
            _ => self.api_auth_mode() == other.api_auth_mode(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct ApiKeyAuth {
    api_key: String,
}

#[derive(Debug, Clone)]
struct ManagedIdentityPersistenceBinding {
    identity_key: String,
    credential_revision: u64,
    raw_account_id: Option<String>,
}

#[derive(Debug, Clone)]
pub struct ChatgptAuth {
    state: ChatgptAuthState,
    storage: Arc<dyn AuthStorageBackend>,
    identity_key: Option<String>,
    managed_identity_binding: Option<ManagedIdentityPersistenceBinding>,
}

#[derive(Debug, Clone)]
pub struct ChatgptAuthTokens {
    state: ChatgptAuthState,
}

#[derive(Debug, Clone)]
struct ChatgptAuthState {
    auth_dot_json: Arc<Mutex<Option<AuthDotJson>>>,
    client: HttpClient,
}

const TOKEN_REFRESH_INTERVAL: i64 = 8;
const CHATGPT_ACCESS_TOKEN_REFRESH_WINDOW_MINUTES: i64 = 5;

const REFRESH_TOKEN_EXPIRED_MESSAGE: &str = "Your access token could not be refreshed because your refresh token has expired. Please log out and sign in again.";
const REFRESH_TOKEN_REUSED_MESSAGE: &str = "Your access token could not be refreshed because your refresh token was already used. Please log out and sign in again.";
const REFRESH_TOKEN_INVALIDATED_MESSAGE: &str = "Your access token could not be refreshed because your refresh token was revoked. Please log out and sign in again.";
const REFRESH_TOKEN_UNKNOWN_MESSAGE: &str =
    "Your access token could not be refreshed. Please log out and sign in again.";
const REFRESH_TOKEN_ACCOUNT_MISMATCH_MESSAGE: &str = "Your access token could not be refreshed because you have since logged out or signed in to another account. Please sign in again.";
const REFRESH_TOKEN_URL: &str = "https://auth.openai.com/oauth/token";
pub(super) const REVOKE_TOKEN_URL: &str = "https://auth.openai.com/oauth/revoke";
pub const REFRESH_TOKEN_URL_OVERRIDE_ENV_VAR: &str = "CODEX_REFRESH_TOKEN_URL_OVERRIDE";
pub const REVOKE_TOKEN_URL_OVERRIDE_ENV_VAR: &str = "CODEX_REVOKE_TOKEN_URL_OVERRIDE";
pub const CLIENT_ID_OVERRIDE_ENV_VAR: &str = "CODEX_APP_SERVER_LOGIN_CLIENT_ID";
static NEXT_DUMMY_AUTH_ID: AtomicU64 = AtomicU64::new(1);

#[derive(Debug, Error)]
pub enum RefreshTokenError {
    #[error("{0}")]
    Permanent(#[from] RefreshTokenFailedError),
    #[error(transparent)]
    Transient(#[from] std::io::Error),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ExternalAuthRefreshReason {
    Unauthorized,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExternalAuthRefreshContext {
    pub reason: ExternalAuthRefreshReason,
    pub previous_account_id: Option<String>,
}

/// Pluggable auth provider used by `AuthManager` for externally managed auth flows.
///
/// Implementations own the current auth value and any source-specific refresh mechanism.
pub trait ExternalAuth: Send + Sync {
    /// Returns the provider's current auth value.
    fn resolve(&self) -> ExternalAuthFuture<'_, CodexAuth>;

    /// Refreshes auth and makes the returned value current for future `resolve()` calls.
    fn refresh(&self, context: ExternalAuthRefreshContext) -> ExternalAuthFuture<'_, CodexAuth>;
}

pub type ExternalAuthFuture<'a, T> = Pin<Box<dyn Future<Output = std::io::Result<T>> + Send + 'a>>;

impl RefreshTokenError {
    pub fn failed_reason(&self) -> Option<RefreshTokenFailedReason> {
        match self {
            Self::Permanent(error) => Some(error.reason),
            Self::Transient(_) => None,
        }
    }
}

impl From<RefreshTokenError> for std::io::Error {
    fn from(err: RefreshTokenError) -> Self {
        match err {
            RefreshTokenError::Permanent(failed) => std::io::Error::other(failed),
            RefreshTokenError::Transient(inner) => inner,
        }
    }
}

impl CodexAuth {
    async fn from_auth_dot_json(
        codex_home: &Path,
        mut auth_dot_json: AuthDotJson,
        auth_credentials_store_mode: AuthCredentialsStoreMode,
        forced_chatgpt_workspace_id: Option<&[String]>,
        chatgpt_base_url: Option<&str>,
        keyring_backend_kind: AuthKeyringBackendKind,
        agent_identity_authapi_base_url: Option<&str>,
        auth_route_config: &AuthRouteConfig,
    ) -> std::io::Result<Self> {
        let auth_mode = auth_dot_json.resolved_mode();
        if auth_mode == AuthMode::ApiKey {
            let Some(api_key) = auth_dot_json.openai_api_key.as_deref() else {
                return Err(std::io::Error::other("API key auth is missing a key."));
            };
            return Ok(Self::from_api_key(api_key));
        }
        if auth_mode == AuthMode::AgentIdentity {
            let Some(agent_identity) = auth_dot_json.agent_identity.clone() else {
                return Err(std::io::Error::other(
                    "agent identity auth is missing agent identity auth material.",
                ));
            };
            let base_url = chatgpt_base_url
                .unwrap_or(ChatGptEnvironment::default().chatgpt_base_url())
                .trim_end_matches('/')
                .to_string();
            let agent_identity_authapi_base_url =
                require_agent_identity_authapi_base_url(agent_identity_authapi_base_url)?;
            match agent_identity {
                AgentIdentityStorage::Jwt(jwt) => {
                    let record =
                        verified_record_from_jwt(&jwt, &base_url, auth_route_config).await?;
                    ensure_agent_identity_record_workspace_allowed(
                        forced_chatgpt_workspace_id,
                        &record,
                    )?;
                    let auth = AgentIdentityAuth::from_record(
                        record,
                        agent_identity_authapi_base_url,
                        auth_route_config,
                    )
                    .await?;
                    return Ok(Self::AgentIdentity(auth));
                }
                AgentIdentityStorage::Record(record) => {
                    ensure_agent_identity_record_workspace_allowed(
                        forced_chatgpt_workspace_id,
                        &record,
                    )?;
                    let auth = AgentIdentityAuth::from_record(
                        record,
                        agent_identity_authapi_base_url,
                        auth_route_config,
                    )
                    .await?;
                    return Ok(Self::AgentIdentity(auth));
                }
            }
        }
        if auth_mode == AuthMode::PersonalAccessToken {
            let Some(personal_access_token) = auth_dot_json.personal_access_token.as_deref() else {
                return Err(std::io::Error::other(
                    "personal access token auth is missing a personal access token.",
                ));
            };
            return Self::from_personal_access_token(personal_access_token, auth_route_config)
                .await;
        }
        if auth_mode == AuthMode::BedrockApiKey {
            let Some(auth) = auth_dot_json.bedrock_api_key else {
                return Err(std::io::Error::other(
                    "Bedrock API key auth is missing a Bedrock API key.",
                ));
            };
            return Ok(Self::BedrockApiKey(auth));
        }
        if auth_mode == AuthMode::Headers {
            return Err(std::io::Error::other(
                "externally provided auth cannot be loaded from auth storage.",
            ));
        }

        let storage_mode = auth_dot_json.storage_mode(auth_credentials_store_mode);
        let client = create_default_auth_client(&refresh_token_endpoint(), auth_route_config)?;
        let storage =
            create_auth_storage(codex_home.to_path_buf(), storage_mode, keyring_backend_kind);
        if auth_mode == AuthMode::Chatgpt
            && normalize_managed_chatgpt_account_id(&mut auth_dot_json)
            && let Err(err) = storage.mutate(&mut |current| {
                let Some(mut current) = current else {
                    return Ok(AuthStorageMutation::Keep(None));
                };
                if current.managed_chatgpt.is_none()
                    && current.resolved_mode() == AuthMode::Chatgpt
                    && normalize_managed_chatgpt_account_id(&mut current)
                {
                    Ok(AuthStorageMutation::Save(current))
                } else {
                    Ok(AuthStorageMutation::Keep(Some(current)))
                }
            })
        {
            tracing::warn!(
                ?err,
                "failed to persist normalized managed ChatGPT account_id"
            );
        }
        let state = ChatgptAuthState {
            auth_dot_json: Arc::new(Mutex::new(Some(auth_dot_json))),
            client,
        };

        match auth_mode {
            AuthMode::Chatgpt => Ok(Self::Chatgpt(ChatgptAuth {
                state,
                storage,
                managed_identity_binding: None,
                identity_key: None,
            })),
            AuthMode::ChatgptAuthTokens => Ok(Self::ChatgptAuthTokens(ChatgptAuthTokens { state })),
            AuthMode::ApiKey => unreachable!("api key mode is handled above"),
            AuthMode::Headers => {
                unreachable!("externally provided auth is never loaded from auth storage")
            }
            AuthMode::AgentIdentity => unreachable!("agent identity mode is handled above"),
            AuthMode::PersonalAccessToken => {
                unreachable!("personal access token mode is handled above")
            }
            AuthMode::BedrockApiKey => unreachable!("bedrock api key mode is handled above"),
        }
    }

    async fn from_managed_account(
        codex_home: &Path,
        account: &crate::auth::storage::ManagedChatgptAccount,
        auth_credentials_store_mode: AuthCredentialsStoreMode,
        chatgpt_base_url: Option<&str>,
        keyring_backend_kind: AuthKeyringBackendKind,
        agent_identity_authapi_base_url: Option<&str>,
        auth_route_config: &AuthRouteConfig,
    ) -> std::io::Result<Self> {
        let managed_identity_binding = ManagedIdentityPersistenceBinding {
            identity_key: account.identity_key.clone(),
            credential_revision: credential_revision(account),
            raw_account_id: account.chatgpt_account_id.clone(),
        };
        let mut auth = Self::from_auth_dot_json(
            codex_home,
            singular_document(account),
            auth_credentials_store_mode,
            /*forced_chatgpt_workspace_id*/ None,
            chatgpt_base_url,
            keyring_backend_kind,
            agent_identity_authapi_base_url,
            auth_route_config,
        )
        .await?;
        if let Self::Chatgpt(chatgpt) = &mut auth {
            chatgpt.managed_identity_binding = Some(managed_identity_binding);
            chatgpt.identity_key = Some(account.identity_key.clone());
        }
        Ok(auth)
    }

    pub async fn from_auth_storage(
        codex_home: &Path,
        auth_credentials_store_mode: AuthCredentialsStoreMode,
        chatgpt_base_url: Option<&str>,
        keyring_backend_kind: AuthKeyringBackendKind,
        auth_route_config: &AuthRouteConfig,
    ) -> std::io::Result<Option<Self>> {
        let agent_identity_authapi_base_url =
            agent_identity_authapi_base_url(chatgpt_base_url).ok();
        load_auth(
            codex_home,
            /*enable_codex_api_key_env*/ false,
            auth_credentials_store_mode,
            /*allowed_login_methods*/ None,
            /*forced_chatgpt_workspace_id*/ None,
            chatgpt_base_url,
            keyring_backend_kind,
            agent_identity_authapi_base_url.as_deref(),
            auth_route_config,
        )
        .await
    }

    pub async fn from_agent_identity_jwt(
        jwt: &str,
        chatgpt_base_url: Option<&str>,
        auth_route_config: &AuthRouteConfig,
    ) -> std::io::Result<Self> {
        let agent_identity_authapi_base_url = agent_identity_authapi_base_url(chatgpt_base_url)?;
        Self::from_agent_identity_jwt_with_authapi_base_url(
            jwt,
            chatgpt_base_url,
            &agent_identity_authapi_base_url,
            auth_route_config,
        )
        .await
    }

    async fn from_agent_identity_jwt_with_authapi_base_url(
        jwt: &str,
        chatgpt_base_url: Option<&str>,
        agent_identity_authapi_base_url: &str,
        auth_route_config: &AuthRouteConfig,
    ) -> std::io::Result<Self> {
        let base_url = chatgpt_base_url
            .unwrap_or(ChatGptEnvironment::default().chatgpt_base_url())
            .trim_end_matches('/')
            .to_string();
        Ok(Self::AgentIdentity(
            AgentIdentityAuth::from_jwt(
                jwt,
                &base_url,
                agent_identity_authapi_base_url,
                auth_route_config,
            )
            .await?,
        ))
    }

    pub async fn from_personal_access_token(
        access_token: &str,
        auth_route_config: &AuthRouteConfig,
    ) -> std::io::Result<Self> {
        Ok(Self::PersonalAccessToken(
            PersonalAccessTokenAuth::load(access_token, auth_route_config).await?,
        ))
    }

    /// Returns the effective backend auth mode.
    ///
    /// Externally managed ChatGPT tokens are normalized to [`AuthMode::Chatgpt`].
    pub fn auth_mode(&self) -> AuthMode {
        match self {
            Self::ApiKey(_) => AuthMode::ApiKey,
            Self::Chatgpt(_) | Self::ChatgptAuthTokens(_) => AuthMode::Chatgpt,
            Self::Headers(_) => AuthMode::Headers,
            Self::AgentIdentity(_) => AuthMode::AgentIdentity,
            Self::PersonalAccessToken(_) => AuthMode::PersonalAccessToken,
            Self::BedrockApiKey(_) => AuthMode::BedrockApiKey,
        }
    }

    /// Returns the precise kind of credentials backing this authentication.
    pub fn api_auth_mode(&self) -> AuthMode {
        match self {
            Self::ApiKey(_) => AuthMode::ApiKey,
            Self::Chatgpt(_) => AuthMode::Chatgpt,
            Self::ChatgptAuthTokens(_) => AuthMode::ChatgptAuthTokens,
            Self::Headers(_) => AuthMode::Headers,
            Self::AgentIdentity(_) => AuthMode::AgentIdentity,
            Self::PersonalAccessToken(_) => AuthMode::PersonalAccessToken,
            Self::BedrockApiKey(_) => AuthMode::BedrockApiKey,
        }
    }

    pub fn is_api_key_auth(&self) -> bool {
        self.auth_mode() == AuthMode::ApiKey
    }

    pub fn is_personal_access_token_auth(&self) -> bool {
        self.auth_mode() == AuthMode::PersonalAccessToken
    }

    pub fn is_chatgpt_auth(&self) -> bool {
        self.api_auth_mode().has_chatgpt_account()
    }

    pub fn uses_codex_backend(&self) -> bool {
        self.api_auth_mode().uses_codex_backend()
    }

    pub fn is_external_chatgpt_tokens(&self) -> bool {
        matches!(self, Self::ChatgptAuthTokens(_))
    }

    fn supports_unauthorized_recovery(&self) -> bool {
        matches!(
            self,
            Self::Chatgpt(_) | Self::ChatgptAuthTokens(_) | Self::Headers(_)
        )
    }

    /// Returns `None` if `auth_mode() != AuthMode::ApiKey`.
    pub fn api_key(&self) -> Option<&str> {
        match self {
            Self::ApiKey(auth) => Some(auth.api_key.as_str()),
            Self::Chatgpt(_)
            | Self::ChatgptAuthTokens(_)
            | Self::Headers(_)
            | Self::AgentIdentity(_)
            | Self::PersonalAccessToken(_)
            | Self::BedrockApiKey(_) => None,
        }
    }

    /// Returns `Err` if token-backed ChatGPT auth is unavailable.
    pub fn get_token_data(&self) -> Result<TokenData, std::io::Error> {
        let auth_dot_json: Option<AuthDotJson> = self.get_current_auth_json();
        match auth_dot_json {
            Some(AuthDotJson {
                tokens: Some(tokens),
                last_refresh: Some(_),
                ..
            }) => Ok(tokens),
            _ => Err(std::io::Error::other("Token data is not available.")),
        }
    }

    /// Returns the token string used for bearer authentication.
    pub fn get_token(&self) -> Result<String, std::io::Error> {
        match self {
            Self::ApiKey(auth) => Ok(auth.api_key.clone()),
            Self::Chatgpt(_) | Self::ChatgptAuthTokens(_) => {
                let access_token = self.get_token_data()?.access_token;
                Ok(access_token)
            }
            Self::AgentIdentity(_) => Err(std::io::Error::other(
                "agent identity auth does not expose a bearer token",
            )),
            Self::Headers(_) => Err(std::io::Error::other(
                "header auth does not expose a bearer token",
            )),
            Self::PersonalAccessToken(auth) => Ok(auth.access_token().to_string()),
            Self::BedrockApiKey(_) => Err(std::io::Error::other(
                "Bedrock API key auth does not expose a Codex bearer token",
            )),
        }
    }

    /// Returns `None` if Codex backend auth does not expose an account id.
    pub fn get_account_id(&self) -> Option<String> {
        match self {
            Self::Headers(_) => None,
            Self::AgentIdentity(auth) => Some(auth.account_id().to_string()),
            Self::PersonalAccessToken(auth) => Some(auth.account_id().to_string()),
            _ => self.get_current_token_data().and_then(|t| t.account_id),
        }
    }

    /// Returns false if Codex backend auth omits the FedRAMP claim.
    pub fn is_fedramp_account(&self) -> bool {
        match self {
            Self::Headers(_) => false,
            Self::AgentIdentity(auth) => auth.is_fedramp_account(),
            Self::PersonalAccessToken(auth) => auth.is_fedramp_account(),
            _ => self
                .get_current_token_data()
                .is_some_and(|t| t.id_token.is_fedramp_account()),
        }
    }

    /// Returns `None` if Codex backend auth does not expose an account email.
    pub fn get_account_email(&self) -> Option<String> {
        match self {
            Self::Headers(_) => None,
            Self::AgentIdentity(auth) => auth.email().map(str::to_string),
            Self::PersonalAccessToken(auth) => auth.email().map(str::to_string),
            _ => self.get_current_token_data().and_then(|t| t.id_token.email),
        }
    }

    /// Returns `None` if Codex backend auth does not expose a ChatGPT user id.
    pub fn get_chatgpt_user_id(&self) -> Option<String> {
        match self {
            Self::Headers(_) => None,
            Self::AgentIdentity(auth) => Some(auth.chatgpt_user_id().to_string()),
            Self::PersonalAccessToken(auth) => Some(auth.chatgpt_user_id().to_string()),
            _ => self
                .get_current_token_data()
                .and_then(|t| t.id_token.chatgpt_user_id),
        }
    }

    /// Account-facing plan classification derived from the current auth.
    /// Returns a high-level `AccountPlanType` (e.g., Free/Plus/Pro/Team/…)
    /// for UI or product decisions based on the user's subscription.
    pub fn account_plan_type(&self) -> Option<AccountPlanType> {
        if matches!(self, Self::Headers(_)) {
            return None;
        }
        if let Self::AgentIdentity(auth) = self {
            return Some(auth.plan_type());
        }
        if let Self::PersonalAccessToken(auth) = self {
            return Some(auth.plan_type());
        }

        self.get_current_token_data().map(|t| {
            t.id_token
                .chatgpt_plan_type
                .map(AccountPlanType::from)
                .unwrap_or(AccountPlanType::Unknown)
        })
    }

    pub fn is_workspace_account(&self) -> bool {
        self.account_plan_type()
            .is_some_and(AccountPlanType::is_workspace_account)
    }

    /// Returns `None` if token-backed ChatGPT auth is unavailable.
    fn get_current_auth_json(&self) -> Option<AuthDotJson> {
        let state = match self {
            Self::Chatgpt(auth) => &auth.state,
            Self::ChatgptAuthTokens(auth) => &auth.state,
            Self::ApiKey(_)
            | Self::Headers(_)
            | Self::AgentIdentity(_)
            | Self::PersonalAccessToken(_)
            | Self::BedrockApiKey(_) => return None,
        };
        #[expect(clippy::unwrap_used)]
        state.auth_dot_json.lock().unwrap().clone()
    }

    /// Returns `None` if token-backed ChatGPT auth is unavailable.
    fn get_current_token_data(&self) -> Option<TokenData> {
        self.get_current_auth_json().and_then(|t| t.tokens)
    }

    fn stored_managed_chatgpt_agent_identity_record(
        &self,
        account_id: &str,
    ) -> Option<AgentIdentityAuthRecord> {
        self.get_current_auth_json()
            .and_then(|auth| auth.agent_identity)
            .and_then(|identity| identity.as_record().cloned())
            .filter(|identity| identity.account_id == account_id)
    }

    fn persist_managed_chatgpt_agent_identity_record(
        &self,
        record: AgentIdentityAuthRecord,
    ) -> std::io::Result<()> {
        if let Self::Chatgpt(chatgpt_auth) = self {
            chatgpt_auth.persist_agent_identity_record(record)?;
        }
        Ok(())
    }

    async fn agent_identity_auth(
        &self,
        policy: AgentIdentityAuthPolicy,
        agent_identity_authapi_base_url: Option<&str>,
        forced_chatgpt_workspace_id: Option<Vec<String>>,
        auth_route_config: &AuthRouteConfig,
        session_source: SessionSource,
    ) -> std::io::Result<Option<AgentIdentityAuth>> {
        match self {
            Self::AgentIdentity(auth) => Ok(Some(auth.clone())),
            Self::ApiKey(_)
            | Self::ChatgptAuthTokens(_)
            | Self::Headers(_)
            | Self::PersonalAccessToken(_)
            | Self::BedrockApiKey(_) => Ok(None),
            Self::Chatgpt(_) => {
                if policy == AgentIdentityAuthPolicy::JwtOnly {
                    return Ok(None);
                }
                self.ensure_managed_chatgpt_agent_identity(
                    require_agent_identity_authapi_base_url(agent_identity_authapi_base_url)?,
                    forced_chatgpt_workspace_id,
                    auth_route_config,
                    session_source,
                )
                .await
                .map(Some)
            }
        }
    }

    async fn ensure_managed_chatgpt_agent_identity(
        &self,
        agent_identity_authapi_base_url: &str,
        forced_chatgpt_workspace_id: Option<Vec<String>>,
        auth_route_config: &AuthRouteConfig,
        session_source: SessionSource,
    ) -> std::io::Result<AgentIdentityAuth> {
        let binding =
            ManagedChatGptAgentIdentityBinding::from_auth(self, forced_chatgpt_workspace_id)
                .ok_or_else(|| std::io::Error::other("ChatGPT auth is unavailable"))?;

        // JWT auth is loaded as CodexAuth::AgentIdentity; this path only reuses
        // records created by the managed ChatGPT Agent Identity bootstrap.
        if let Some(record) = self.stored_managed_chatgpt_agent_identity_record(&binding.account_id)
            && record_matches_managed_chatgpt_binding(&record, &binding)
        {
            let should_persist = record_needs_task_registration(&record);
            let auth = AgentIdentityAuth::from_record(
                record,
                agent_identity_authapi_base_url,
                auth_route_config,
            )
            .await
            .map_err(|err| classify_bootstrap_error("agent task registration", err))?;
            if should_persist {
                self.persist_managed_chatgpt_agent_identity_record(auth.record().clone())?;
            }
            return Ok(auth);
        }

        let auth = register_managed_chatgpt_agent_identity(
            binding,
            agent_identity_authapi_base_url,
            session_source,
            auth_route_config,
        )
        .await?;
        self.persist_managed_chatgpt_agent_identity_record(auth.record().clone())?;
        Ok(auth)
    }

    /// Consider this private to integration tests.
    pub fn create_dummy_chatgpt_auth_for_testing() -> Self {
        let auth_dot_json = AuthDotJson {
            auth_mode: Some(AuthMode::Chatgpt),
            openai_api_key: None,
            tokens: Some(TokenData {
                id_token: Default::default(),
                access_token: "Access Token".to_string(),
                refresh_token: "test".to_string(),
                account_id: Some("account_id".to_string()),
            }),
            last_refresh: Some(Utc::now()),
            agent_identity: None,
            managed_chatgpt: None,
            personal_access_token: None,
            bedrock_api_key: None,
        };

        let state = ChatgptAuthState {
            auth_dot_json: Arc::new(Mutex::new(Some(auth_dot_json))),
            client: create_client(),
        };
        let dummy_auth_id = NEXT_DUMMY_AUTH_ID.fetch_add(1, Ordering::Relaxed);
        let storage = create_auth_storage(
            PathBuf::from(format!("dummy-chatgpt-auth-{dummy_auth_id}")),
            AuthCredentialsStoreMode::Ephemeral,
            AuthKeyringBackendKind::default(),
        );
        Self::Chatgpt(ChatgptAuth {
            state,
            storage,
            identity_key: None,
            managed_identity_binding: None,
        })
    }

    /// Constructs in-memory ChatGPT auth from externally managed tokens.
    pub fn from_external_chatgpt_tokens(
        access_token: &str,
        chatgpt_account_id: &str,
        chatgpt_plan_type: Option<&str>,
    ) -> std::io::Result<Self> {
        let auth_dot_json = AuthDotJson::from_external_access_token(
            access_token,
            chatgpt_account_id,
            chatgpt_plan_type,
        )?;
        let state = ChatgptAuthState {
            auth_dot_json: Arc::new(Mutex::new(Some(auth_dot_json))),
            client: create_client(),
        };
        Ok(Self::ChatgptAuthTokens(ChatgptAuthTokens { state }))
    }

    pub fn from_api_key(api_key: &str) -> Self {
        Self::ApiKey(ApiKeyAuth {
            api_key: api_key.to_owned(),
        })
    }
}

impl ManagedChatGptAgentIdentityBinding {
    fn from_auth(auth: &CodexAuth, forced_workspace_id: Option<Vec<String>>) -> Option<Self> {
        if !auth.is_chatgpt_auth() {
            return None;
        }

        let token_data = auth.get_token_data().ok()?;
        let forced_workspace_id =
            forced_workspace_id
                .as_deref()
                .and_then(|workspace_ids| match workspace_ids {
                    [workspace_id] if !workspace_id.is_empty() => Some(workspace_id.clone()),
                    _ => None,
                });
        let account_id = forced_workspace_id
            .or(token_data
                .account_id
                .clone()
                .filter(|value| !value.is_empty()))
            .or(token_data.id_token.chatgpt_account_id.clone())?;
        let chatgpt_user_id = token_data
            .id_token
            .chatgpt_user_id
            .clone()
            .filter(|value| !value.is_empty())?;

        Some(Self {
            account_id,
            chatgpt_user_id,
            email: token_data.id_token.email.clone(),
            plan_type: auth.account_plan_type().unwrap_or(AccountPlanType::Unknown),
            chatgpt_account_is_fedramp: auth.is_fedramp_account(),
            access_token: token_data.access_token,
        })
    }
}

impl ChatgptAuth {
    fn current_auth_json(&self) -> Option<AuthDotJson> {
        #[expect(clippy::unwrap_used)]
        self.state.auth_dot_json.lock().unwrap().clone()
    }

    fn current_token_data(&self) -> Option<TokenData> {
        self.current_auth_json().and_then(|auth| auth.tokens)
    }

    fn storage(&self) -> &Arc<dyn AuthStorageBackend> {
        &self.storage
    }

    fn client(&self) -> &HttpClient {
        &self.state.client
    }

    fn persist_agent_identity_record(
        &self,
        record: AgentIdentityAuthRecord,
    ) -> std::io::Result<()> {
        persist_agent_identity_record(
            &self.state.auth_dot_json,
            &self.storage,
            self.managed_identity_binding.as_ref(),
            record,
        )
    }
}

fn persist_agent_identity_record(
    auth_dot_json: &Arc<Mutex<Option<AuthDotJson>>>,
    storage: &Arc<dyn AuthStorageBackend>,
    managed_identity_binding: Option<&ManagedIdentityPersistenceBinding>,
    record: AgentIdentityAuthRecord,
) -> std::io::Result<()> {
    let mut guard = auth_dot_json
        .lock()
        .map_err(|_| std::io::Error::other("failed to lock auth state"))?;
    if let Some(binding) = managed_identity_binding {
        let mut projected = None;
        storage.mutate(&mut |current| {
            let Some(mut auth) = current else {
                return Err(std::io::Error::other("auth data is not available"));
            };
            validate_document(&auth)?;
            let account = auth
                .managed_chatgpt
                .as_mut()
                .and_then(|pool| {
                    pool.accounts
                        .iter_mut()
                        .find(|account| account.identity_key == binding.identity_key)
                })
                .ok_or_else(|| std::io::Error::other("managed ChatGPT account is not available"))?;
            if account.tombstone.is_some()
                || credential_revision(account) != binding.credential_revision
                || account.chatgpt_account_id != binding.raw_account_id
            {
                return Err(std::io::Error::other(
                    "managed ChatGPT account changed during Agent Identity bootstrap",
                ));
            }
            account.agent_identity = Some(AgentIdentityStorage::Record(record.clone()));
            account.revision = account.revision.saturating_add(1);
            projected = Some(singular_document(account));
            Ok(AuthStorageMutation::Save(auth))
        })?;
        *guard = projected;
        return Ok(());
    }
    let mut committed = None;
    storage.mutate(&mut |current| {
        let mut auth = current
            .or_else(|| guard.clone())
            .ok_or_else(|| std::io::Error::other("auth data is not available"))?;
        auth.agent_identity = Some(AgentIdentityStorage::Record(record.clone()));
        committed = Some(auth.clone());
        Ok(AuthStorageMutation::Save(auth))
    })?;
    *guard = committed;
    Ok(())
}

fn sync_chatgpt_account_id(tokens: &mut TokenData) {
    let account_id = tokens
        .id_token
        .chatgpt_account_id
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_string)
        .or_else(|| {
            tokens
                .account_id
                .as_deref()
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .map(str::to_string)
        });
    tokens.account_id = account_id;
}

fn normalize_managed_chatgpt_account_id(auth_dot_json: &mut AuthDotJson) -> bool {
    let Some(tokens) = auth_dot_json.tokens.as_mut() else {
        return false;
    };
    let expected_account_id = tokens
        .id_token
        .chatgpt_account_id
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_string)
        .or_else(|| {
            tokens
                .account_id
                .as_deref()
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .map(str::to_string)
        });
    if tokens.account_id == expected_account_id {
        return false;
    }
    sync_chatgpt_account_id(tokens);
    true
}

pub const OPENAI_API_KEY_ENV_VAR: &str = "OPENAI_API_KEY";
pub const CODEX_API_KEY_ENV_VAR: &str = "CODEX_API_KEY";
pub const CODEX_ACCESS_TOKEN_ENV_VAR: &str = "CODEX_ACCESS_TOKEN";

pub fn read_openai_api_key_from_env() -> Option<String> {
    env::var(OPENAI_API_KEY_ENV_VAR)
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
}

pub fn read_codex_api_key_from_env() -> Option<String> {
    read_non_empty_env_var(CODEX_API_KEY_ENV_VAR)
}

pub fn read_codex_access_token_from_env() -> Option<String> {
    read_non_empty_env_var(CODEX_ACCESS_TOKEN_ENV_VAR)
}

fn read_non_empty_env_var(key: &str) -> Option<String> {
    env::var(key)
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
}

/// Delete the auth.json file inside `codex_home` if it exists. Returns `Ok(true)`
/// if a file was removed, `Ok(false)` if no auth file was present.
pub fn logout(
    codex_home: &Path,
    auth_credentials_store_mode: AuthCredentialsStoreMode,
    keyring_backend_kind: AuthKeyringBackendKind,
) -> std::io::Result<bool> {
    if delete_external_chatgpt_auth(codex_home)? {
        return Ok(true);
    }
    let storage = create_auth_storage(
        codex_home.to_path_buf(),
        auth_credentials_store_mode,
        keyring_backend_kind,
    );
    let mut removed = false;
    storage.mutate(&mut |current| {
        if current
            .as_ref()
            .and_then(|auth| auth.managed_chatgpt.as_ref())
            .is_some_and(|pool| pool.accounts.len() > 1)
        {
            return Err(std::io::Error::other(
                "global logout is ambiguous for a multi-account ChatGPT pool; select an account or use logout-all",
            ));
        }
        removed = current.is_some();
        Ok(AuthStorageMutation::Delete)
    })?;
    Ok(removed)
}

pub async fn logout_with_revoke(
    codex_home: &Path,
    auth_credentials_store_mode: AuthCredentialsStoreMode,
    keyring_backend_kind: AuthKeyringBackendKind,
    auth_route_config: &AuthRouteConfig,
) -> std::io::Result<bool> {
    if let Some(overlay) = load_external_chatgpt_auth(codex_home)? {
        if let Err(err) = revoke_auth_tokens(Some(&overlay), auth_route_config).await {
            tracing::warn!("failed to revoke external ChatGPT auth during logout: {err}");
        }
        return delete_external_chatgpt_auth(codex_home);
    }
    let auth_dot_json = match load_auth_dot_json(
        codex_home,
        auth_credentials_store_mode,
        keyring_backend_kind,
    ) {
        Ok(auth_dot_json) => auth_dot_json,
        Err(err) => {
            tracing::warn!("failed to load stored auth during logout: {err}");
            None
        }
    };
    if auth_dot_json
        .as_ref()
        .and_then(|auth| auth.managed_chatgpt.as_ref())
        .is_some_and(|pool| pool.accounts.len() > 1)
    {
        return Err(std::io::Error::other(
            "global logout is ambiguous for a multi-account ChatGPT pool; select an account or use logout-all",
        ));
    }
    if let Err(err) = revoke_auth_tokens(auth_dot_json.as_ref(), auth_route_config).await {
        tracing::warn!("failed to revoke auth tokens during logout: {err}");
    }
    logout_all_stores(
        codex_home,
        auth_credentials_store_mode,
        keyring_backend_kind,
    )
}

/// Writes an `auth.json` that contains only the API key.
pub fn login_with_api_key(
    codex_home: &Path,
    api_key: &str,
    auth_credentials_store_mode: AuthCredentialsStoreMode,
    keyring_backend_kind: AuthKeyringBackendKind,
) -> std::io::Result<()> {
    let auth_dot_json = AuthDotJson {
        auth_mode: Some(AuthMode::ApiKey),
        openai_api_key: Some(api_key.to_string()),
        tokens: None,
        last_refresh: None,
        agent_identity: None,
        managed_chatgpt: None,
        personal_access_token: None,
        bedrock_api_key: None,
    };
    save_auth(
        codex_home,
        &auth_dot_json,
        auth_credentials_store_mode,
        keyring_backend_kind,
    )
}

/// Writes an `auth.json` that contains only the access token.
pub async fn login_with_access_token(
    codex_home: &Path,
    access_token: &str,
    auth_credentials_store_mode: AuthCredentialsStoreMode,
    forced_chatgpt_workspace_id: Option<&[String]>,
    chatgpt_base_url: Option<&str>,
    keyring_backend_kind: AuthKeyringBackendKind,
    auth_route_config: &AuthRouteConfig,
) -> std::io::Result<()> {
    let auth_dot_json = match classify_codex_access_token(access_token) {
        CodexAccessToken::PersonalAccessToken(access_token) => {
            let auth = PersonalAccessTokenAuth::load(access_token, auth_route_config).await?;
            ensure_auth_workspace_allowed(forced_chatgpt_workspace_id, auth.account_id())?;
            AuthDotJson {
                // Infer PAT auth from the credential field so older Codex builds can still
                // deserialize auth.json after a rollback.
                auth_mode: None,
                openai_api_key: None,
                tokens: None,
                last_refresh: None,
                agent_identity: None,
                managed_chatgpt: None,
                personal_access_token: Some(access_token.to_string()),
                bedrock_api_key: None,
            }
        }
        CodexAccessToken::AgentIdentityJwt(jwt) => {
            let record = AgentIdentityAuthRecord::from_agent_identity_jwt(jwt)?;
            ensure_auth_workspace_allowed(forced_chatgpt_workspace_id, &record.account_id)?;
            let base_url = chatgpt_base_url
                .unwrap_or(ChatGptEnvironment::default().chatgpt_base_url())
                .trim_end_matches('/')
                .to_string();
            let record = verified_record_from_jwt(jwt, &base_url, auth_route_config).await?;
            ensure_agent_identity_record_workspace_allowed(forced_chatgpt_workspace_id, &record)?;
            AuthDotJson {
                auth_mode: Some(AuthMode::AgentIdentity),
                openai_api_key: None,
                tokens: None,
                last_refresh: None,
                agent_identity: Some(AgentIdentityStorage::Jwt(jwt.to_string())),
                managed_chatgpt: None,
                personal_access_token: None,
                bedrock_api_key: None,
            }
        }
    };
    save_auth(
        codex_home,
        &auth_dot_json,
        auth_credentials_store_mode,
        keyring_backend_kind,
    )
}

fn ensure_auth_workspace_allowed(
    expected_workspace_ids: Option<&[String]>,
    account_id: &str,
) -> std::io::Result<()> {
    crate::server::ensure_workspace_account_allowed(expected_workspace_ids, account_id)
        .map_err(|message| std::io::Error::new(std::io::ErrorKind::PermissionDenied, message))
}

fn ensure_agent_identity_workspace_allowed(
    expected_workspace_ids: Option<&[String]>,
    agent_identity: &AgentIdentityStorage,
) -> std::io::Result<()> {
    let Some(expected_workspace_ids) = expected_workspace_ids else {
        return Ok(());
    };

    match agent_identity {
        AgentIdentityStorage::Jwt(jwt) => {
            let record = AgentIdentityAuthRecord::from_agent_identity_jwt(jwt)?;
            ensure_auth_workspace_allowed(Some(expected_workspace_ids), &record.account_id)
        }
        AgentIdentityStorage::Record(record) => {
            ensure_auth_workspace_allowed(Some(expected_workspace_ids), &record.account_id)
        }
    }
}

fn ensure_agent_identity_record_workspace_allowed(
    expected_workspace_ids: Option<&[String]>,
    record: &AgentIdentityAuthRecord,
) -> std::io::Result<()> {
    crate::server::ensure_workspace_account_allowed(expected_workspace_ids, &record.account_id)
        .map_err(|message| std::io::Error::new(std::io::ErrorKind::PermissionDenied, message))
}

/// Writes an in-memory auth payload for externally managed ChatGPT tokens.
pub fn login_with_chatgpt_auth_tokens(
    codex_home: &Path,
    access_token: &str,
    chatgpt_account_id: &str,
    chatgpt_plan_type: Option<&str>,
) -> std::io::Result<()> {
    let chatgpt_account_id = chatgpt_account_id.trim();
    if chatgpt_account_id.is_empty() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "external ChatGPT account ID must not be empty",
        ));
    }
    let auth_dot_json = AuthDotJson::from_external_access_token(
        access_token,
        chatgpt_account_id,
        chatgpt_plan_type,
    )?;
    save_external_chatgpt_auth(codex_home, &auth_dot_json)
}

/// Persist the provided auth payload using the specified backend.
pub fn save_auth(
    codex_home: &Path,
    auth: &AuthDotJson,
    auth_credentials_store_mode: AuthCredentialsStoreMode,
    keyring_backend_kind: AuthKeyringBackendKind,
) -> std::io::Result<()> {
    let storage = create_auth_storage(
        codex_home.to_path_buf(),
        auth_credentials_store_mode,
        keyring_backend_kind,
    );
    storage.mutate(&mut |current| {
        let mut replacement = auth.clone();
        if replacement.managed_chatgpt.is_none()
            && replacement.resolved_mode() != AuthMode::Chatgpt
            && let Some(mut pool) = current.and_then(|current| current.managed_chatgpt)
        {
            if !pool.accounts.is_empty() {
                pool.accounts.clear();
                pool.revision = pool.revision.saturating_add(1);
            }
            replacement.managed_chatgpt = Some(pool);
        }
        Ok(AuthStorageMutation::Save(replacement))
    })?;
    Ok(())
}

/// Load the raw stored auth payload without applying environment overrides.
///
/// Returns `None` when no credentials are stored. Prefer `AuthManager` for
/// ordinary production reads; this helper is for tests and write-side
/// maintenance that must inspect the exact payload in storage.
pub fn load_auth_dot_json(
    codex_home: &Path,
    auth_credentials_store_mode: AuthCredentialsStoreMode,
    keyring_backend_kind: AuthKeyringBackendKind,
) -> std::io::Result<Option<AuthDotJson>> {
    let storage = create_auth_storage(
        codex_home.to_path_buf(),
        auth_credentials_store_mode,
        keyring_backend_kind,
    );
    storage.load()
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthConfig {
    pub codex_home: PathBuf,
    pub auth_credentials_store_mode: AuthCredentialsStoreMode,
    pub keyring_backend_kind: AuthKeyringBackendKind,
    pub forced_login_method: Option<ForcedLoginMethod>,
    pub chatgpt_base_url: Option<String>,
    pub forced_chatgpt_workspace_id: Option<Vec<String>>,
    pub managed_auth_policy: ManagedAuthPolicy,
    pub auth_route_config: AuthRouteConfig,
}

impl AuthConfig {
    pub fn is_login_method_allowed(&self, method: ForcedLoginMethod) -> bool {
        self.managed_auth_policy.allows_login_method(
            method,
            self.forced_login_method,
            self.forced_chatgpt_workspace_id.as_deref(),
        )
    }

    pub fn effective_chatgpt_workspaces(&self) -> Option<Vec<String>> {
        self.managed_auth_policy
            .effective_chatgpt_workspaces(self.forced_chatgpt_workspace_id.as_deref())
    }

    pub fn validate(&self) -> std::io::Result<()> {
        if self.is_login_method_allowed(ForcedLoginMethod::Api)
            || self.is_login_method_allowed(ForcedLoginMethod::Chatgpt)
        {
            Ok(())
        } else {
            Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "authentication requirements do not permit any usable login method",
            ))
        }
    }

    pub fn allows_auth(&self, auth: &CodexAuth) -> bool {
        let allowed_login_methods = self.allowed_login_methods();
        let workspaces = self.effective_chatgpt_workspaces();
        validate_auth_restrictions(Some(&allowed_login_methods), workspaces.as_deref(), auth)
            .is_ok()
    }

    pub async fn load_auth(
        &self,
        enable_codex_api_key_env: bool,
    ) -> std::io::Result<Option<CodexAuth>> {
        let allowed_login_methods = self.allowed_login_methods();
        let workspaces = self.effective_chatgpt_workspaces();
        let agent_identity_authapi_base_url =
            agent_identity_authapi_base_url(self.chatgpt_base_url.as_deref()).ok();
        let auth = load_auth(
            &self.codex_home,
            enable_codex_api_key_env,
            self.auth_credentials_store_mode,
            Some(&allowed_login_methods),
            workspaces.as_deref(),
            self.chatgpt_base_url.as_deref(),
            self.keyring_backend_kind,
            agent_identity_authapi_base_url.as_deref(),
            &self.auth_route_config,
        )
        .await?;
        Ok(auth.filter(|auth| self.allows_auth(auth)))
    }

    fn allowed_login_methods(&self) -> Vec<ForcedLoginMethod> {
        self.managed_auth_policy.allowed_login_methods(
            self.forced_login_method,
            self.forced_chatgpt_workspace_id.as_deref(),
        )
    }
}

fn auth_mode_is_allowed(
    allowed_login_methods: Option<&[ForcedLoginMethod]>,
    mode: AuthMode,
) -> bool {
    let method = if mode.uses_codex_backend() {
        ForcedLoginMethod::Chatgpt
    } else {
        ForcedLoginMethod::Api
    };
    allowed_login_methods.is_none_or(|allowed| allowed.contains(&method))
}

fn validate_auth_restrictions(
    allowed_login_methods: Option<&[ForcedLoginMethod]>,
    expected_workspaces: Option<&[String]>,
    auth: &CodexAuth,
) -> Result<(), String> {
    if !auth_mode_is_allowed(allowed_login_methods, auth.auth_mode()) {
        return Err(match allowed_login_methods {
            Some(methods) if methods.contains(&ForcedLoginMethod::Api) => {
                "API key login is required".to_string()
            }
            Some(_) => "ChatGPT login is required".to_string(),
            None => unreachable!("unrestricted login methods accept every auth mode"),
        });
    }

    let Some(expected_workspaces) = expected_workspaces else {
        return Ok(());
    };
    if matches!(
        auth,
        CodexAuth::ApiKey(_) | CodexAuth::Headers(_) | CodexAuth::BedrockApiKey(_)
    ) {
        return Ok(());
    }

    let actual_workspace = auth.get_account_id().or_else(|| {
        auth.get_token_data()
            .ok()
            .and_then(|tokens| tokens.id_token.chatgpt_account_id)
    });
    if actual_workspace
        .as_ref()
        .is_some_and(|workspace| expected_workspaces.contains(workspace))
    {
        Ok(())
    } else {
        let actual = actual_workspace.unwrap_or_else(|| "unknown".to_string());
        Err(format!(
            "Login is restricted to workspace(s) {}, but current credentials belong to {actual}",
            expected_workspaces.join(", ")
        ))
    }
}

/// Enforces configured login restrictions using auth-owned HTTP settings.
pub async fn enforce_login_restrictions(config: &AuthConfig) -> std::io::Result<()> {
    let agent_identity_authapi_base_url =
        agent_identity_authapi_base_url(config.chatgpt_base_url.as_deref()).ok();
    enforce_login_restrictions_with_agent_identity_authapi_base_url(
        config,
        agent_identity_authapi_base_url.as_deref(),
    )
    .await
}

async fn enforce_login_restrictions_with_agent_identity_authapi_base_url(
    config: &AuthConfig,
    agent_identity_authapi_base_url: Option<&str>,
) -> std::io::Result<()> {
    // Managed-only restrictions are enforced by AuthManager.
    if config.forced_login_method.is_none() && config.forced_chatgpt_workspace_id.is_none() {
        return Ok(());
    }

    let Some(auth) = load_auth(
        &config.codex_home,
        /*enable_codex_api_key_env*/ true,
        config.auth_credentials_store_mode,
        /*allowed_login_methods*/ None,
        /*forced_chatgpt_workspace_id*/ None,
        config.chatgpt_base_url.as_deref(),
        config.keyring_backend_kind,
        agent_identity_authapi_base_url,
        &config.auth_route_config,
    )
    .await?
    else {
        return Ok(());
    };

    if let Some(required_method) = config.forced_login_method {
        let method_violation = match (required_method, auth.auth_mode()) {
            (ForcedLoginMethod::Api, AuthMode::ApiKey)
            | (ForcedLoginMethod::Api, AuthMode::BedrockApiKey) => None,
            (ForcedLoginMethod::Chatgpt, AuthMode::Chatgpt)
            | (ForcedLoginMethod::Chatgpt, AuthMode::ChatgptAuthTokens)
            | (ForcedLoginMethod::Chatgpt, AuthMode::Headers)
            | (ForcedLoginMethod::Chatgpt, AuthMode::AgentIdentity)
            | (ForcedLoginMethod::Chatgpt, AuthMode::PersonalAccessToken) => None,
            (ForcedLoginMethod::Api, AuthMode::Chatgpt)
            | (ForcedLoginMethod::Api, AuthMode::ChatgptAuthTokens)
            | (ForcedLoginMethod::Api, AuthMode::Headers)
            | (ForcedLoginMethod::Api, AuthMode::AgentIdentity)
            | (ForcedLoginMethod::Api, AuthMode::PersonalAccessToken) => Some(
                "API key login is required, but ChatGPT is currently being used. Logging out."
                    .to_string(),
            ),
            (ForcedLoginMethod::Chatgpt, AuthMode::ApiKey)
            | (ForcedLoginMethod::Chatgpt, AuthMode::BedrockApiKey) => Some(
                "ChatGPT login is required, but an API key is currently being used. Logging out."
                    .to_string(),
            ),
        };

        if let Some(message) = method_violation {
            return logout_with_message(
                &config.codex_home,
                message,
                config.auth_credentials_store_mode,
                config.keyring_backend_kind,
            );
        }
    }

    if let Some(expected_account_ids) = config.forced_chatgpt_workspace_id.as_deref() {
        let chatgpt_account_id = match &auth {
            CodexAuth::ApiKey(_) | CodexAuth::Headers(_) | CodexAuth::BedrockApiKey(_) => {
                return Ok(());
            }
            CodexAuth::AgentIdentity(_) | CodexAuth::PersonalAccessToken(_) => {
                auth.get_account_id()
            }
            CodexAuth::Chatgpt(_) | CodexAuth::ChatgptAuthTokens(_) => {
                let token_data = match auth.get_token_data() {
                    Ok(data) => data,
                    Err(err) => {
                        return logout_with_message(
                            &config.codex_home,
                            format!(
                                "Failed to load ChatGPT credentials while enforcing workspace restrictions: {err}. Logging out."
                            ),
                            config.auth_credentials_store_mode,
                            config.keyring_backend_kind,
                        );
                    }
                };
                token_data.id_token.chatgpt_account_id
            }
        };

        // workspace is the external identifier for account id.
        let chatgpt_account_id = chatgpt_account_id.as_deref();
        if !chatgpt_account_id.is_some_and(|actual| {
            expected_account_ids
                .iter()
                .any(|expected| expected == actual)
        }) {
            let expected_workspaces = expected_account_ids.join(", ");
            let message = match chatgpt_account_id {
                Some(actual) => format!(
                    "Login is restricted to workspace(s) {expected_workspaces}, but current credentials belong to {actual}. Logging out."
                ),
                None => format!(
                    "Login is restricted to workspace(s) {expected_workspaces}, but current credentials lack a workspace identifier. Logging out."
                ),
            };
            return logout_with_message(
                &config.codex_home,
                message,
                config.auth_credentials_store_mode,
                config.keyring_backend_kind,
            );
        }
    }

    Ok(())
}

fn logout_with_message(
    codex_home: &Path,
    message: String,
    auth_credentials_store_mode: AuthCredentialsStoreMode,
    keyring_backend_kind: AuthKeyringBackendKind,
) -> std::io::Result<()> {
    // Forced policy enforcement must remove every auth source without the interactive
    // ambiguity guard used by a user-initiated global logout.
    let removal_result = force_logout_all_stores(
        codex_home,
        auth_credentials_store_mode,
        keyring_backend_kind,
    );
    let error_message = match removal_result {
        Ok(_) => message,
        Err(err) => format!("{message}. Failed to remove auth.json: {err}"),
    };
    Err(std::io::Error::other(error_message))
}

fn force_logout_all_stores(
    codex_home: &Path,
    auth_credentials_store_mode: AuthCredentialsStoreMode,
    keyring_backend_kind: AuthKeyringBackendKind,
) -> std::io::Result<bool> {
    let removed_external = delete_external_chatgpt_auth(codex_home)?;
    let removed_ephemeral = delete_auth_store(
        codex_home,
        AuthCredentialsStoreMode::Ephemeral,
        AuthKeyringBackendKind::default(),
    )?;
    let removed_configured = if auth_credentials_store_mode == AuthCredentialsStoreMode::Ephemeral {
        false
    } else {
        delete_auth_store(
            codex_home,
            auth_credentials_store_mode,
            keyring_backend_kind,
        )?
    };
    Ok(removed_external || removed_ephemeral || removed_configured)
}

fn delete_auth_store(
    codex_home: &Path,
    auth_credentials_store_mode: AuthCredentialsStoreMode,
    keyring_backend_kind: AuthKeyringBackendKind,
) -> std::io::Result<bool> {
    let storage = create_auth_storage(
        codex_home.to_path_buf(),
        auth_credentials_store_mode,
        keyring_backend_kind,
    );
    storage.delete_locked()
}

fn logout_all_stores(
    codex_home: &Path,
    auth_credentials_store_mode: AuthCredentialsStoreMode,
    keyring_backend_kind: AuthKeyringBackendKind,
) -> std::io::Result<bool> {
    if auth_credentials_store_mode != AuthCredentialsStoreMode::Ephemeral {
        let stored = load_auth_dot_json(
            codex_home,
            auth_credentials_store_mode,
            keyring_backend_kind,
        )?;
        if stored
            .as_ref()
            .and_then(|auth| auth.managed_chatgpt.as_ref())
            .is_some_and(|pool| pool.accounts.len() > 1)
        {
            return Err(std::io::Error::other(
                "global logout is ambiguous for a multi-account ChatGPT pool; select an account or use logout-all",
            ));
        }
    }
    if auth_credentials_store_mode == AuthCredentialsStoreMode::Ephemeral {
        return logout(
            codex_home,
            AuthCredentialsStoreMode::Ephemeral,
            AuthKeyringBackendKind::default(),
        );
    }
    let removed_ephemeral = logout(
        codex_home,
        AuthCredentialsStoreMode::Ephemeral,
        AuthKeyringBackendKind::default(),
    )?;
    let removed_managed = logout(
        codex_home,
        auth_credentials_store_mode,
        keyring_backend_kind,
    )?;
    Ok(removed_ephemeral || removed_managed)
}

#[allow(clippy::too_many_arguments)]
async fn load_auth(
    codex_home: &Path,
    enable_codex_api_key_env: bool,
    auth_credentials_store_mode: AuthCredentialsStoreMode,
    allowed_login_methods: Option<&[ForcedLoginMethod]>,
    forced_chatgpt_workspace_id: Option<&[String]>,
    chatgpt_base_url: Option<&str>,
    keyring_backend_kind: AuthKeyringBackendKind,
    agent_identity_authapi_base_url: Option<&str>,
    auth_route_config: &AuthRouteConfig,
) -> std::io::Result<Option<CodexAuth>> {
    // API key via env var takes precedence over any other auth method.
    if enable_codex_api_key_env
        && auth_mode_is_allowed(allowed_login_methods, AuthMode::ApiKey)
        && let Some(api_key) = read_codex_api_key_from_env()
    {
        return Ok(Some(CodexAuth::from_api_key(api_key.as_str())));
    }

    // The external ChatGPT overlay is a dedicated process-local slot. It takes
    // precedence over every configured store without overwriting ephemeral
    // managed credentials underneath it.
    if let Some(auth_dot_json) = load_external_chatgpt_auth(codex_home)?
        && auth_mode_is_allowed(allowed_login_methods, auth_dot_json.resolved_mode())
    {
        let auth = CodexAuth::from_auth_dot_json(
            codex_home,
            auth_dot_json,
            AuthCredentialsStoreMode::Ephemeral,
            forced_chatgpt_workspace_id,
            chatgpt_base_url,
            keyring_backend_kind,
            agent_identity_authapi_base_url,
            auth_route_config,
        )
        .await?;
        if let CodexAuth::PersonalAccessToken(auth) = &auth {
            ensure_auth_workspace_allowed(forced_chatgpt_workspace_id, auth.account_id())?;
        }
        if let Some(expected_workspace_ids) = forced_chatgpt_workspace_id
            && !auth
                .get_account_id()
                .is_some_and(|account_id| expected_workspace_ids.contains(&account_id))
        {
            return Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "external ChatGPT account is not in an allowed workspace",
            ));
        }
        return Ok(Some(auth));
    }

    if auth_mode_is_allowed(allowed_login_methods, AuthMode::AgentIdentity)
        && let Some(access_token) = read_codex_access_token_from_env()
    {
        return match classify_codex_access_token(&access_token) {
            CodexAccessToken::PersonalAccessToken(access_token) => {
                let auth = PersonalAccessTokenAuth::load(access_token, auth_route_config).await?;
                ensure_auth_workspace_allowed(forced_chatgpt_workspace_id, auth.account_id())?;
                Ok(Some(CodexAuth::PersonalAccessToken(auth)))
            }
            CodexAccessToken::AgentIdentityJwt(jwt) => {
                let base_url = chatgpt_base_url
                    .unwrap_or(ChatGptEnvironment::default().chatgpt_base_url())
                    .trim_end_matches('/')
                    .to_string();
                let record = verified_record_from_jwt(jwt, &base_url, auth_route_config).await?;
                ensure_agent_identity_record_workspace_allowed(
                    forced_chatgpt_workspace_id,
                    &record,
                )?;
                AgentIdentityAuth::from_record(
                    record,
                    require_agent_identity_authapi_base_url(agent_identity_authapi_base_url)?,
                    auth_route_config,
                )
                .await
                .map(CodexAuth::AgentIdentity)
                .map(Some)
            }
        };
    }

    // Fall back to the configured persistent or ephemeral managed store.
    let storage = create_auth_storage(
        codex_home.to_path_buf(),
        auth_credentials_store_mode,
        keyring_backend_kind,
    );
    let auth_dot_json = storage.mutate(&mut |current| {
        let Some(mut auth) = current else {
            return Ok(AuthStorageMutation::Keep(None));
        };
        validate_document(&auth)?;
        if migrate_document(&mut auth, Utc::now()) {
            Ok(AuthStorageMutation::Save(auth))
        } else {
            Ok(AuthStorageMutation::Keep(Some(auth)))
        }
    })?;
    let Some(auth_dot_json) = auth_dot_json else {
        return Ok(None);
    };
    if !auth_mode_is_allowed(allowed_login_methods, auth_dot_json.resolved_mode()) {
        return Ok(None);
    }
    if let Some(agent_identity) = auth_dot_json.agent_identity.as_ref() {
        ensure_agent_identity_workspace_allowed(forced_chatgpt_workspace_id, agent_identity)?;
    }

    let resolved_mode = auth_dot_json.resolved_mode();
    if resolved_mode == AuthMode::Chatgpt
        && auth_dot_json
            .managed_chatgpt
            .as_ref()
            .is_some_and(|pool| pool.accounts.is_empty())
    {
        return Ok(None);
    }
    let auth = if resolved_mode == AuthMode::Chatgpt && auth_dot_json.managed_chatgpt.is_some() {
        let pins = SelectionPins::default();
        let Some(account) = select(
            &auth_dot_json,
            &ManagedChatgptSelectionScope::default(),
            &pins,
            forced_chatgpt_workspace_id,
            Utc::now(),
        ) else {
            return Err(std::io::Error::other(
                "no eligible managed ChatGPT account is available",
            ));
        };
        CodexAuth::from_managed_account(
            codex_home,
            account,
            auth_credentials_store_mode,
            chatgpt_base_url,
            keyring_backend_kind,
            agent_identity_authapi_base_url,
            auth_route_config,
        )
        .await?
    } else {
        CodexAuth::from_auth_dot_json(
            codex_home,
            auth_dot_json,
            auth_credentials_store_mode,
            forced_chatgpt_workspace_id,
            chatgpt_base_url,
            keyring_backend_kind,
            agent_identity_authapi_base_url,
            auth_route_config,
        )
        .await?
    };
    if let CodexAuth::PersonalAccessToken(auth) = &auth {
        ensure_auth_workspace_allowed(forced_chatgpt_workspace_id, auth.account_id())?;
    }
    Ok(Some(auth))
}

// Persist refreshed tokens into auth storage and update last_refresh.
fn persist_tokens(
    storage: &Arc<dyn AuthStorageBackend>,
    id_token: Option<String>,
    access_token: Option<String>,
    refresh_token: Option<String>,
) -> std::io::Result<AuthDotJson> {
    storage
        .mutate(&mut |current| {
            let mut auth_dot_json =
                current.ok_or(std::io::Error::other("Token data is not available."))?;
            let tokens = auth_dot_json.tokens.get_or_insert_with(TokenData::default);
            if let Some(id_token) = id_token.clone() {
                tokens.id_token =
                    parse_chatgpt_jwt_claims(&id_token).map_err(std::io::Error::other)?;
            }
            sync_chatgpt_account_id(tokens);
            if let Some(access_token) = access_token.clone() {
                tokens.access_token = access_token;
            }
            if let Some(refresh_token) = refresh_token.clone() {
                tokens.refresh_token = refresh_token;
            }
            auth_dot_json.last_refresh = Some(Utc::now());
            Ok(AuthStorageMutation::Save(auth_dot_json))
        })?
        .ok_or(std::io::Error::other("Token data is not available."))
}

// Requests refreshed ChatGPT OAuth tokens from the auth service using a refresh token.
// The caller is responsible for persisting any returned tokens.
async fn request_chatgpt_token_refresh(
    refresh_token: String,
    client: &HttpClient,
) -> Result<RefreshResponse, RefreshTokenError> {
    let refresh_request = RefreshRequest {
        client_id: oauth_client_id(),
        grant_type: "refresh_token",
        refresh_token,
    };
    let endpoint = refresh_token_endpoint();

    // Use shared client factory to include standard headers
    let response = client
        .post(endpoint.as_str())
        .header("Content-Type", "application/json")
        .json(&refresh_request)
        .send()
        .await
        .map_err(|err| RefreshTokenError::Transient(std::io::Error::other(err)))?;

    let status = response.status();
    if status.is_success() {
        let refresh_response = response
            .json::<RefreshResponse>()
            .await
            .map_err(|err| RefreshTokenError::Transient(std::io::Error::other(err)))?;
        Ok(refresh_response)
    } else {
        let body = response.text().await.unwrap_or_default();
        tracing::error!("Failed to refresh token: {status}: {body}");
        let failed = classify_refresh_token_failure(&body);
        if status == StatusCode::UNAUTHORIZED || failed.reason != RefreshTokenFailedReason::Other {
            Err(RefreshTokenError::Permanent(failed))
        } else {
            let message = try_parse_error_message(&body);
            Err(RefreshTokenError::Transient(std::io::Error::other(
                format!("Failed to refresh token: {status}: {message}"),
            )))
        }
    }
}

fn classify_refresh_token_failure(body: &str) -> RefreshTokenFailedError {
    let code = extract_refresh_token_error_code(body);

    let normalized_code = code.as_deref().map(str::to_ascii_lowercase);
    let reason = match normalized_code.as_deref() {
        Some("refresh_token_expired") => RefreshTokenFailedReason::Expired,
        Some("refresh_token_reused") => RefreshTokenFailedReason::Exhausted,
        Some("refresh_token_invalidated") => RefreshTokenFailedReason::Revoked,
        _ => RefreshTokenFailedReason::Other,
    };

    if reason == RefreshTokenFailedReason::Other {
        tracing::warn!(
            backend_code = normalized_code.as_deref(),
            backend_body = body,
            "Encountered unknown response while refreshing token"
        );
    }

    let message = match reason {
        RefreshTokenFailedReason::Expired => REFRESH_TOKEN_EXPIRED_MESSAGE.to_string(),
        RefreshTokenFailedReason::Exhausted => REFRESH_TOKEN_REUSED_MESSAGE.to_string(),
        RefreshTokenFailedReason::Revoked => REFRESH_TOKEN_INVALIDATED_MESSAGE.to_string(),
        RefreshTokenFailedReason::Other => REFRESH_TOKEN_UNKNOWN_MESSAGE.to_string(),
    };

    RefreshTokenFailedError::new(reason, message)
}

fn extract_refresh_token_error_code(body: &str) -> Option<String> {
    if body.trim().is_empty() {
        return None;
    }

    let Value::Object(map) = serde_json::from_str::<Value>(body).ok()? else {
        return None;
    };

    if let Some(error_value) = map.get("error") {
        match error_value {
            Value::Object(obj) => {
                if let Some(code) = obj.get("code").and_then(Value::as_str) {
                    return Some(code.to_string());
                }
            }
            Value::String(code) => {
                return Some(code.to_string());
            }
            _ => {}
        }
    }

    map.get("code").and_then(Value::as_str).map(str::to_string)
}

#[derive(Serialize)]
struct RefreshRequest {
    client_id: String,
    grant_type: &'static str,
    refresh_token: String,
}

#[derive(Deserialize, Clone)]
struct RefreshResponse {
    id_token: Option<String>,
    access_token: Option<String>,
    refresh_token: Option<String>,
}

// Shared constant for token refresh (client id used for oauth token refresh flow)
pub const CLIENT_ID: &str = "app_EMoamEEZ73f0CkXaXp7hrann";

pub fn oauth_client_id() -> String {
    std::env::var(CLIENT_ID_OVERRIDE_ENV_VAR)
        .ok()
        .filter(|client_id| !client_id.trim().is_empty())
        .unwrap_or_else(|| CLIENT_ID.to_string())
}

fn refresh_token_endpoint() -> String {
    std::env::var(REFRESH_TOKEN_URL_OVERRIDE_ENV_VAR)
        .unwrap_or_else(|_| REFRESH_TOKEN_URL.to_string())
}

impl AuthDotJson {
    fn from_external_access_token(
        access_token: &str,
        chatgpt_account_id: &str,
        chatgpt_plan_type: Option<&str>,
    ) -> std::io::Result<Self> {
        let mut token_info =
            parse_chatgpt_jwt_claims(access_token).map_err(std::io::Error::other)?;
        token_info.chatgpt_account_id = Some(chatgpt_account_id.to_string());
        token_info.chatgpt_plan_type = chatgpt_plan_type
            .map(InternalPlanType::from_raw_value)
            .or(token_info.chatgpt_plan_type)
            .or(Some(InternalPlanType::Unknown("unknown".to_string())));
        let tokens = TokenData {
            id_token: token_info,
            access_token: access_token.to_string(),
            refresh_token: String::new(),
            account_id: Some(chatgpt_account_id.to_string()),
        };

        Ok(Self {
            auth_mode: Some(AuthMode::ChatgptAuthTokens),
            openai_api_key: None,
            tokens: Some(tokens),
            last_refresh: Some(Utc::now()),
            agent_identity: None,
            managed_chatgpt: None,
            personal_access_token: None,
            bedrock_api_key: None,
        })
    }

    pub(super) fn resolved_mode(&self) -> AuthMode {
        if let Some(mode) = self.auth_mode {
            return mode;
        }
        if self.personal_access_token.is_some() {
            return AuthMode::PersonalAccessToken;
        }
        if self.bedrock_api_key.is_some() {
            return AuthMode::BedrockApiKey;
        }
        if self.openai_api_key.is_some() {
            return AuthMode::ApiKey;
        }
        AuthMode::Chatgpt
    }

    fn storage_mode(
        &self,
        auth_credentials_store_mode: AuthCredentialsStoreMode,
    ) -> AuthCredentialsStoreMode {
        if self.resolved_mode() == AuthMode::ChatgptAuthTokens {
            AuthCredentialsStoreMode::Ephemeral
        } else {
            auth_credentials_store_mode
        }
    }
}

type ExternalChatgptAuthFingerprint = [u8; 32];

fn external_chatgpt_auth_fingerprint(
    auth: Option<&AuthDotJson>,
) -> Option<ExternalChatgptAuthFingerprint> {
    let auth = auth?;
    let encoded = serde_json::to_vec(auth).ok()?;
    Some(Sha256::digest(encoded).into())
}

fn auth_external_chatgpt_fingerprint(
    auth: Option<&CodexAuth>,
) -> Option<ExternalChatgptAuthFingerprint> {
    let auth = auth.filter(|auth| auth.is_external_chatgpt_tokens())?;
    external_chatgpt_auth_fingerprint(auth.get_current_auth_json().as_ref())
}

/// Internal cached auth state.
#[derive(Clone)]
struct CachedAuth {
    auth: Option<CodexAuth>,
    /// Content fingerprint of the external ChatGPT overlay represented by `auth`.
    /// This tracks replacements without retaining another copy of token material.
    external_chatgpt_fingerprint: Option<ExternalChatgptAuthFingerprint>,
    /// Permanent refresh failure cached for the current auth snapshot so
    /// later refresh attempts for the same credentials fail fast without network.
    permanent_refresh_failure: Option<AuthScopedRefreshFailure>,
    /// Initial effective-auth load error retained for non-destructive callers
    /// that must not fall through to lower-precedence stored credentials.
    load_error: Option<String>,
}

#[derive(Clone)]
struct AuthScopedRefreshFailure {
    auth: CodexAuth,
    error: RefreshTokenFailedError,
}

impl Debug for CachedAuth {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CachedAuth")
            .field(
                "auth_mode",
                &self.auth.as_ref().map(CodexAuth::api_auth_mode),
            )
            .field(
                "permanent_refresh_failure",
                &self
                    .permanent_refresh_failure
                    .as_ref()
                    .map(|failure| failure.error.reason),
            )
            .finish()
    }
}

enum UnauthorizedRecoveryStep {
    Reload,
    RefreshToken,
    ExternalRefresh,
    Done,
}

enum ReloadOutcome {
    /// Reload was performed and the cached auth changed
    ReloadedChanged,
    /// Reload was performed and the cached auth remained the same
    ReloadedNoChange,
    /// Reload was skipped (missing or mismatched account id)
    Skipped,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum UnauthorizedRecoveryMode {
    Managed,
    External,
}

// UnauthorizedRecovery is a state machine that handles an attempt to refresh the authentication when requests
// to API fail with 401 status code.
// The client calls next() every time it encounters a 401 error, one time per retry.
// For API key based authentication, we don't do anything and let the error bubble to the user.
//
// For ChatGPT based authentication, we:
// 1. Attempt to reload the auth data from disk. We only reload if the account id matches the one the current process is running as.
// 2. Attempt to refresh the token using OAuth token refresh flow.
// If after both steps the server still responds with 401 we let the error bubble to the user.
//
// For external auth sources, UnauthorizedRecovery retries once by asking the
// configured provider to refresh and caching the returned auth through the same
// path used by other auth sources.
pub struct UnauthorizedRecovery {
    manager: Arc<AuthManager>,
    step: UnauthorizedRecoveryStep,
    expected_account_id: Option<String>,
    mode: UnauthorizedRecoveryMode,
    managed_identity_key: Option<String>,
    managed_account_revision: Option<u64>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct UnauthorizedRecoveryStepResult {
    auth_state_changed: Option<bool>,
}

impl UnauthorizedRecoveryStepResult {
    pub fn auth_state_changed(&self) -> Option<bool> {
        self.auth_state_changed
    }
}

impl UnauthorizedRecovery {
    fn new(manager: Arc<AuthManager>) -> Self {
        let cached_auth = manager.auth_cached();
        let expected_account_id = cached_auth.as_ref().and_then(CodexAuth::get_account_id);
        let mode = if manager.has_external_auth() {
            UnauthorizedRecoveryMode::External
        } else {
            UnauthorizedRecoveryMode::Managed
        };
        let step = match mode {
            UnauthorizedRecoveryMode::Managed => UnauthorizedRecoveryStep::Reload,
            UnauthorizedRecoveryMode::External => UnauthorizedRecoveryStep::ExternalRefresh,
        };
        Self {
            manager,
            step,
            expected_account_id,
            mode,
            managed_identity_key: None,
            managed_account_revision: None,
        }
    }

    fn new_for_snapshot(manager: Arc<AuthManager>, snapshot: &ManagedChatgptAuthSnapshot) -> Self {
        Self {
            manager,
            step: UnauthorizedRecoveryStep::Reload,
            expected_account_id: snapshot.auth.get_account_id(),
            mode: UnauthorizedRecoveryMode::Managed,
            managed_identity_key: Some(snapshot.identity_key.clone()),
            managed_account_revision: Some(snapshot.account_revision),
        }
    }

    pub fn has_next(&self) -> bool {
        if self.manager.has_external_api_key_auth() {
            return !matches!(self.step, UnauthorizedRecoveryStep::Done);
        }
        if self.managed_identity_key.is_some() {
            return !matches!(self.step, UnauthorizedRecoveryStep::Done);
        }

        if !self
            .manager
            .auth_cached()
            .as_ref()
            .is_some_and(CodexAuth::supports_unauthorized_recovery)
        {
            return false;
        }

        if self.mode == UnauthorizedRecoveryMode::External && !self.manager.has_external_auth() {
            return false;
        }

        !matches!(self.step, UnauthorizedRecoveryStep::Done)
    }

    pub fn unavailable_reason(&self) -> &'static str {
        if self.manager.has_external_api_key_auth() {
            return if matches!(self.step, UnauthorizedRecoveryStep::Done) {
                "recovery_exhausted"
            } else {
                "ready"
            };
        }
        if self.managed_identity_key.is_some() {
            return if matches!(self.step, UnauthorizedRecoveryStep::Done) {
                "recovery_exhausted"
            } else {
                "ready"
            };
        }

        if self
            .manager
            .auth_cached()
            .as_ref()
            .is_some_and(CodexAuth::is_personal_access_token_auth)
        {
            return "not_refreshable_auth";
        }

        if !self
            .manager
            .auth_cached()
            .as_ref()
            .is_some_and(CodexAuth::supports_unauthorized_recovery)
        {
            return "not_chatgpt_auth";
        }

        if self.mode == UnauthorizedRecoveryMode::External && !self.manager.has_external_auth() {
            return "no_external_auth";
        }

        if matches!(self.step, UnauthorizedRecoveryStep::Done) {
            return "recovery_exhausted";
        }

        "ready"
    }

    pub fn mode_name(&self) -> &'static str {
        match self.mode {
            UnauthorizedRecoveryMode::Managed => "managed",
            UnauthorizedRecoveryMode::External => "external",
        }
    }

    pub fn step_name(&self) -> &'static str {
        match self.step {
            UnauthorizedRecoveryStep::Reload => "reload",
            UnauthorizedRecoveryStep::RefreshToken => "refresh_token",
            UnauthorizedRecoveryStep::ExternalRefresh => "external_refresh",
            UnauthorizedRecoveryStep::Done => "done",
        }
    }

    pub async fn next(&mut self) -> Result<UnauthorizedRecoveryStepResult, RefreshTokenError> {
        if !self.has_next() {
            return Err(RefreshTokenError::Permanent(RefreshTokenFailedError::new(
                RefreshTokenFailedReason::Other,
                "No more recovery steps available.",
            )));
        }

        match self.step {
            UnauthorizedRecoveryStep::Reload => {
                if let Some(identity) = self.managed_identity_key.as_deref() {
                    let current = self
                        .manager
                        .managed_chatgpt_auth_snapshot_for_identity(identity)
                        .await
                        .map_err(RefreshTokenError::Transient)?;
                    let Some(current) = current.filter(|snapshot| {
                        snapshot.auth.get_account_id() == self.expected_account_id
                    }) else {
                        self.step = UnauthorizedRecoveryStep::Done;
                        return Err(RefreshTokenError::Permanent(RefreshTokenFailedError::new(
                            RefreshTokenFailedReason::Other,
                            REFRESH_TOKEN_ACCOUNT_MISMATCH_MESSAGE.to_string(),
                        )));
                    };
                    let changed = self.managed_account_revision != Some(current.account_revision);
                    self.managed_account_revision = Some(current.account_revision);
                    self.step = UnauthorizedRecoveryStep::RefreshToken;
                    return Ok(UnauthorizedRecoveryStepResult {
                        auth_state_changed: Some(changed),
                    });
                }
                match self
                    .manager
                    .reload_if_account_id_matches(self.expected_account_id.as_deref())
                    .await
                {
                    ReloadOutcome::ReloadedChanged => {
                        self.step = UnauthorizedRecoveryStep::RefreshToken;
                        return Ok(UnauthorizedRecoveryStepResult {
                            auth_state_changed: Some(true),
                        });
                    }
                    ReloadOutcome::ReloadedNoChange => {
                        self.step = UnauthorizedRecoveryStep::RefreshToken;
                        return Ok(UnauthorizedRecoveryStepResult {
                            auth_state_changed: Some(false),
                        });
                    }
                    ReloadOutcome::Skipped => {
                        self.step = UnauthorizedRecoveryStep::Done;
                        return Err(RefreshTokenError::Permanent(RefreshTokenFailedError::new(
                            RefreshTokenFailedReason::Other,
                            REFRESH_TOKEN_ACCOUNT_MISMATCH_MESSAGE.to_string(),
                        )));
                    }
                }
            }
            UnauthorizedRecoveryStep::RefreshToken => {
                if let Some(identity) = self.managed_identity_key.as_deref() {
                    self.manager
                        .refresh_managed_chatgpt_account_bounded_impl(
                            identity,
                            true,
                            MANAGED_REFRESH_MAX_DURATION,
                        )
                        .await?;
                } else {
                    self.manager.refresh_token_from_authority().await?;
                }
                self.step = UnauthorizedRecoveryStep::Done;
                return Ok(UnauthorizedRecoveryStepResult {
                    auth_state_changed: Some(true),
                });
            }
            UnauthorizedRecoveryStep::ExternalRefresh => {
                self.manager.refresh_token_from_authority().await?;
                self.step = UnauthorizedRecoveryStep::Done;
                return Ok(UnauthorizedRecoveryStepResult {
                    auth_state_changed: Some(true),
                });
            }
            UnauthorizedRecoveryStep::Done => {}
        }
        Ok(UnauthorizedRecoveryStepResult {
            auth_state_changed: None,
        })
    }
}

const MANAGED_REFRESH_MAX_DURATION: Duration = Duration::from_secs(4 * 60);

/// Central manager providing a single source of truth for auth.json derived
/// authentication data. It loads once (or on preference change) and then
/// hands out cloned `CodexAuth` values so the rest of the program has a
/// consistent snapshot.
pub struct AuthManager {
    codex_home: PathBuf,
    inner: RwLock<CachedAuth>,
    auth_change_tx: watch::Sender<u64>,
    enable_codex_api_key_env: bool,
    auth_credentials_store_mode: AuthCredentialsStoreMode,
    keyring_backend_kind: AuthKeyringBackendKind,
    forced_login_method: Option<ForcedLoginMethod>,
    forced_chatgpt_workspace_id: RwLock<Option<Vec<String>>>,
    managed_auth_policy: ManagedAuthPolicy,
    chatgpt_base_url: Option<String>,
    agent_identity_authapi_base_url: Option<String>,
    refresh_lock: Semaphore,
    agent_identity_lock: Semaphore,
    agent_identity_bootstrap_cooldown: Mutex<AgentIdentityBootstrapCooldown>,
    external_auth: RwLock<Option<Arc<dyn ExternalAuth>>>,
    auth_route_config: AuthRouteConfig,
    managed_lifecycle_lock: Semaphore,
    selection_pins: SelectionPins,
}

/// Configuration view required to construct a shared [`AuthManager`].
///
/// Implementations should return the auth-related config values for the
/// already-resolved runtime configuration. The primary implementation is
/// `codex_core::config::Config`, but this trait keeps `codex-login` independent
/// from `codex-core`.
pub trait AuthManagerConfig {
    /// Returns the Codex home directory used for auth storage.
    fn codex_home(&self) -> PathBuf;

    /// Returns the CLI auth credential storage mode for auth loading.
    fn cli_auth_credentials_store_mode(&self) -> AuthCredentialsStoreMode;

    /// Returns the backend to use when CLI auth keyring storage is selected.
    fn auth_keyring_backend_kind(&self) -> AuthKeyringBackendKind;

    /// Returns the resolved login-method restriction, if any.
    fn forced_login_method(&self) -> Option<ForcedLoginMethod>;

    /// Returns the workspace IDs that ChatGPT auth should be restricted to, if any.
    fn forced_chatgpt_workspace_id(&self) -> Option<Vec<String>>;

    /// Returns administrator-managed authentication restrictions.
    fn managed_auth_policy(&self) -> ManagedAuthPolicy;

    /// Returns the ChatGPT backend base URL used for first-party backend authorization.
    fn chatgpt_base_url(&self) -> String;

    /// Returns route-selection settings for auth-owned clients.
    fn auth_route_config(&self) -> AuthRouteConfig;
}

impl Debug for AuthManager {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AuthManager")
            .field("codex_home", &self.codex_home)
            .field("inner", &self.inner)
            .field("enable_codex_api_key_env", &self.enable_codex_api_key_env)
            .field(
                "auth_credentials_store_mode",
                &self.auth_credentials_store_mode,
            )
            .field("keyring_backend_kind", &self.keyring_backend_kind)
            .field("forced_login_method", &self.forced_login_method)
            .field(
                "forced_chatgpt_workspace_id",
                &self.forced_chatgpt_workspace_id,
            )
            .field("managed_auth_policy", &self.managed_auth_policy)
            .field("chatgpt_base_url", &self.chatgpt_base_url)
            .field("auth_route_config", &self.auth_route_config)
            .field("has_external_auth", &self.has_external_auth())
            .finish_non_exhaustive()
    }
}

fn default_agent_identity_authapi_base_url() -> Option<String> {
    agent_identity_authapi_base_url(/*chatgpt_base_url*/ None).ok()
}

impl AuthManager {
    /// Create a new manager loading the initial effective auth source.
    /// `auth()` retains its legacy optional contract; callers that must preserve
    /// higher-precedence hydration or policy failures use `auth_cached_result()`.
    pub async fn new(
        codex_home: PathBuf,
        enable_codex_api_key_env: bool,
        auth_credentials_store_mode: AuthCredentialsStoreMode,
        forced_chatgpt_workspace_id: Option<Vec<String>>,
        chatgpt_base_url: Option<String>,
        keyring_backend_kind: AuthKeyringBackendKind,
        auth_route_config: AuthRouteConfig,
    ) -> Self {
        Self::new_from_auth_config(
            AuthConfig {
                codex_home,
                auth_credentials_store_mode,
                keyring_backend_kind,
                forced_login_method: None,
                chatgpt_base_url,
                forced_chatgpt_workspace_id,
                managed_auth_policy: ManagedAuthPolicy::default(),
                auth_route_config,
            },
            enable_codex_api_key_env,
        )
        .await
    }

    async fn new_from_auth_config(auth_config: AuthConfig, enable_codex_api_key_env: bool) -> Self {
        let load_result = auth_config.load_auth(enable_codex_api_key_env).await;
        let AuthConfig {
            codex_home,
            auth_credentials_store_mode,
            keyring_backend_kind,
            forced_login_method,
            chatgpt_base_url,
            forced_chatgpt_workspace_id,
            managed_auth_policy,
            auth_route_config,
        } = auth_config;
        let agent_identity_authapi_base_url =
            agent_identity_authapi_base_url(chatgpt_base_url.as_deref()).ok();
        let (managed_auth, load_error) = match load_result {
            Ok(auth) => (auth, None),
            Err(err) => (None, Some(err.to_string())),
        };
        let (auth_change_tx, _auth_change_rx) = watch::channel(0);
        let manager = Self {
            codex_home,
            inner: RwLock::new(CachedAuth {
                external_chatgpt_fingerprint: auth_external_chatgpt_fingerprint(
                    managed_auth.as_ref(),
                ),
                auth: managed_auth,
                permanent_refresh_failure: None,
                load_error,
            }),
            auth_change_tx,
            enable_codex_api_key_env,
            auth_credentials_store_mode,
            keyring_backend_kind,
            forced_login_method,
            forced_chatgpt_workspace_id: RwLock::new(forced_chatgpt_workspace_id),
            managed_auth_policy,
            chatgpt_base_url,
            agent_identity_authapi_base_url,
            refresh_lock: Semaphore::new(/*permits*/ 1),
            agent_identity_lock: Semaphore::new(/*permits*/ 1),
            managed_lifecycle_lock: Semaphore::new(/*permits*/ 1),
            agent_identity_bootstrap_cooldown: Mutex::default(),
            external_auth: RwLock::new(None),
            auth_route_config,
            selection_pins: SelectionPins::default(),
        };
        if let Err(err) = manager.resume_managed_chatgpt_tombstones().await {
            tracing::warn!("failed to resume pending managed ChatGPT logout: {err}");
        }
        manager
    }

    /// Create an AuthManager with a specific CodexAuth, for testing only.
    pub fn from_auth_for_testing(auth: CodexAuth) -> Arc<Self> {
        let cached = CachedAuth {
            external_chatgpt_fingerprint: auth_external_chatgpt_fingerprint(Some(&auth)),
            auth: Some(auth),
            permanent_refresh_failure: None,
            load_error: None,
        };
        let (auth_change_tx, _auth_change_rx) = watch::channel(0);

        Arc::new(Self {
            codex_home: PathBuf::from("non-existent"),
            inner: RwLock::new(cached),
            auth_change_tx,
            enable_codex_api_key_env: false,
            auth_credentials_store_mode: AuthCredentialsStoreMode::File,
            keyring_backend_kind: AuthKeyringBackendKind::default(),
            forced_login_method: None,
            forced_chatgpt_workspace_id: RwLock::new(None),
            managed_auth_policy: ManagedAuthPolicy::default(),
            chatgpt_base_url: None,
            agent_identity_authapi_base_url: default_agent_identity_authapi_base_url(),
            refresh_lock: Semaphore::new(/*permits*/ 1),
            agent_identity_lock: Semaphore::new(/*permits*/ 1),
            managed_lifecycle_lock: Semaphore::new(/*permits*/ 1),
            agent_identity_bootstrap_cooldown: Mutex::default(),
            external_auth: RwLock::new(None),
            auth_route_config: crate::test_support::transport_default_auth_route_config(),
            selection_pins: SelectionPins::default(),
        })
    }

    /// Create an AuthManager with a specific CodexAuth and codex home, for testing only.
    pub fn from_auth_for_testing_with_home(auth: CodexAuth, codex_home: PathBuf) -> Arc<Self> {
        let cached = CachedAuth {
            external_chatgpt_fingerprint: auth_external_chatgpt_fingerprint(Some(&auth)),
            auth: Some(auth),
            permanent_refresh_failure: None,
            load_error: None,
        };
        let (auth_change_tx, _auth_change_rx) = watch::channel(0);
        Arc::new(Self {
            codex_home,
            inner: RwLock::new(cached),
            auth_change_tx,
            enable_codex_api_key_env: false,
            auth_credentials_store_mode: AuthCredentialsStoreMode::File,
            keyring_backend_kind: AuthKeyringBackendKind::default(),
            forced_login_method: None,
            forced_chatgpt_workspace_id: RwLock::new(None),
            managed_auth_policy: ManagedAuthPolicy::default(),
            chatgpt_base_url: None,
            agent_identity_authapi_base_url: default_agent_identity_authapi_base_url(),
            refresh_lock: Semaphore::new(/*permits*/ 1),
            agent_identity_lock: Semaphore::new(/*permits*/ 1),
            managed_lifecycle_lock: Semaphore::new(/*permits*/ 1),
            agent_identity_bootstrap_cooldown: Mutex::default(),
            external_auth: RwLock::new(None),
            auth_route_config: crate::test_support::transport_default_auth_route_config(),
            selection_pins: SelectionPins::default(),
        })
    }

    /// Create an AuthManager with a specific CodexAuth and Agent Identity AuthAPI base URL, for testing only.
    #[doc(hidden)]
    pub fn from_auth_for_testing_with_agent_identity_authapi_base_url(
        auth: CodexAuth,
        agent_identity_authapi_base_url: String,
    ) -> Arc<Self> {
        Self::from_auth_for_testing_with_home_and_agent_identity_authapi_base_url(
            auth,
            PathBuf::from("non-existent"),
            agent_identity_authapi_base_url,
        )
    }

    fn from_auth_for_testing_with_home_and_agent_identity_authapi_base_url(
        auth: CodexAuth,
        codex_home: PathBuf,
        agent_identity_authapi_base_url: String,
    ) -> Arc<Self> {
        let cached = CachedAuth {
            external_chatgpt_fingerprint: auth_external_chatgpt_fingerprint(Some(&auth)),
            auth: Some(auth),
            permanent_refresh_failure: None,
            load_error: None,
        };
        let (auth_change_tx, _auth_change_rx) = watch::channel(0);
        Arc::new(Self {
            codex_home,
            inner: RwLock::new(cached),
            auth_change_tx,
            enable_codex_api_key_env: false,
            auth_credentials_store_mode: AuthCredentialsStoreMode::File,
            keyring_backend_kind: AuthKeyringBackendKind::default(),
            forced_login_method: None,
            forced_chatgpt_workspace_id: RwLock::new(None),
            managed_auth_policy: ManagedAuthPolicy::default(),
            chatgpt_base_url: None,
            agent_identity_authapi_base_url: Some(
                agent_identity_authapi_base_url
                    .trim_end_matches('/')
                    .to_string(),
            ),
            refresh_lock: Semaphore::new(/*permits*/ 1),
            agent_identity_lock: Semaphore::new(/*permits*/ 1),
            managed_lifecycle_lock: Semaphore::new(/*permits*/ 1),
            agent_identity_bootstrap_cooldown: Mutex::default(),
            external_auth: RwLock::new(None),
            auth_route_config: crate::test_support::transport_default_auth_route_config(),
            selection_pins: SelectionPins::default(),
        })
    }

    pub fn external_bearer_only(config: ModelProviderAuthInfo) -> Arc<Self> {
        let (auth_change_tx, _auth_change_rx) = watch::channel(0);
        Arc::new(Self {
            codex_home: PathBuf::from("non-existent"),
            inner: RwLock::new(CachedAuth {
                auth: None,
                external_chatgpt_fingerprint: None,
                permanent_refresh_failure: None,
                load_error: None,
            }),
            auth_change_tx,
            enable_codex_api_key_env: false,
            auth_credentials_store_mode: AuthCredentialsStoreMode::File,
            keyring_backend_kind: AuthKeyringBackendKind::default(),
            forced_login_method: None,
            forced_chatgpt_workspace_id: RwLock::new(None),
            managed_auth_policy: ManagedAuthPolicy::default(),
            chatgpt_base_url: None,
            agent_identity_authapi_base_url: default_agent_identity_authapi_base_url(),
            refresh_lock: Semaphore::new(/*permits*/ 1),
            agent_identity_lock: Semaphore::new(/*permits*/ 1),
            managed_lifecycle_lock: Semaphore::new(/*permits*/ 1),
            agent_identity_bootstrap_cooldown: Mutex::default(),
            external_auth: RwLock::new(Some(
                Arc::new(BearerTokenRefresher::new(config)) as Arc<dyn ExternalAuth>
            )),
            // External bearer auth refreshes by running the provider's command and never makes
            // auth-owned HTTP requests, so this route is intentionally inert.
            auth_route_config: AuthRouteConfig::from_http_client_factory(HttpClientFactory::new(
                OutboundProxyPolicy::ReqwestDefault,
            )),
            selection_pins: SelectionPins::default(),
        })
    }

    /// Current cached auth (clone) without attempting a refresh. A process-local
    /// overlay fingerprint mismatch never serves a stale or lower-precedence snapshot.
    pub fn auth_cached(&self) -> Option<CodexAuth> {
        let cached = self.inner.read().ok()?;
        let auth = cached.auth.clone()?;
        let overlay_fingerprint = load_external_chatgpt_auth(&self.codex_home)
            .ok()
            .and_then(|overlay| external_chatgpt_auth_fingerprint(overlay.as_ref()));
        if overlay_fingerprint != cached.external_chatgpt_fingerprint {
            return None;
        }
        Some(auth)
    }

    /// Returns the cached effective auth while preserving an initial
    /// higher-precedence load, hydration, or policy failure.
    pub fn auth_cached_result(&self) -> Result<Option<CodexAuth>, String> {
        let cached = self
            .inner
            .read()
            .map_err(|_| "failed to lock cached auth".to_string())?;
        if let Some(error) = cached.load_error.as_ref() {
            return Err(error.clone());
        }
        drop(cached);
        Ok(self.auth_cached())
    }

    /// Subscribes to cached auth changes that can affect request recovery.
    pub fn auth_change_receiver(&self) -> watch::Receiver<u64> {
        self.auth_change_tx.subscribe()
    }

    pub fn refresh_failure_for_auth(&self, auth: &CodexAuth) -> Option<RefreshTokenFailedError> {
        self.inner.read().ok().and_then(|cached| {
            cached
                .permanent_refresh_failure
                .as_ref()
                .filter(|failure| Self::auths_equal_for_refresh(Some(auth), Some(&failure.auth)))
                .map(|failure| failure.error.clone())
        })
    }

    /// Current cached auth (clone). May be `None` if not logged in or load failed.
    /// For managed ChatGPT auth that needs a proactive refresh, first performs
    /// a guarded reload and then refreshes only if the on-disk auth is unchanged.
    #[instrument(level = "trace", skip_all)]
    pub async fn auth(&self) -> Option<CodexAuth> {
        let overlay_fingerprint = load_external_chatgpt_auth(&self.codex_home)
            .ok()
            .and_then(|overlay| external_chatgpt_auth_fingerprint(overlay.as_ref()));
        let cached_overlay_fingerprint = self
            .inner
            .read()
            .ok()
            .and_then(|cached| cached.external_chatgpt_fingerprint);
        if self.has_external_auth() || overlay_fingerprint != cached_overlay_fingerprint {
            self.reload().await;
            return self.auth_cached();
        }
        if let Err(err) = self.resume_managed_chatgpt_tombstones().await {
            tracing::error!("Failed to resume pending managed ChatGPT logout: {err}");
            return None;
        }

        let auth = self.auth_cached()?;
        if Self::should_refresh_proactively(&auth)
            && let Err(err) = self.refresh_token().await
        {
            tracing::error!("Failed to refresh token: {}", err);
            return Some(auth);
        }
        self.auth_cached()
    }

    pub async fn agent_identity_auth(
        &self,
        policy: AgentIdentityAuthPolicy,
        session_source: SessionSource,
    ) -> std::io::Result<Option<AgentIdentityAuth>> {
        let Some(auth) = self.auth().await else {
            return Ok(None);
        };
        self.agent_identity_auth_for_selected_auth(auth, policy, session_source)
            .await
    }

    /// Resolves Agent Identity strictly from an immutable managed-account snapshot.
    ///
    /// A snapshot from before re-login, refresh, removal, or selection replacement
    /// is rejected rather than silently falling back to the manager's default auth.
    pub async fn agent_identity_auth_for_snapshot(
        &self,
        snapshot: &ManagedChatgptAuthSnapshot,
        policy: AgentIdentityAuthPolicy,
        session_source: SessionSource,
    ) -> std::io::Result<Option<AgentIdentityAuth>> {
        let document = self
            .load_managed_chatgpt_document()?
            .ok_or_else(|| std::io::Error::other("managed ChatGPT account pool is unavailable"))?;
        let current = row(&document, &snapshot.identity_key)
            .filter(|account| {
                account.tombstone.is_none()
                    && credential_revision(account) == snapshot.account_revision
            })
            .ok_or_else(|| {
                std::io::Error::other(
                    "managed ChatGPT auth snapshot no longer matches the selected account",
                )
            })?;
        if current.chatgpt_account_id != snapshot.transport.raw_account_id {
            return Err(std::io::Error::other(
                "managed ChatGPT transport binding no longer matches the selected account",
            ));
        }
        self.agent_identity_auth_for_selected_auth(snapshot.auth.clone(), policy, session_source)
            .await
    }

    async fn agent_identity_auth_for_selected_auth(
        &self,
        auth: CodexAuth,
        policy: AgentIdentityAuthPolicy,
        session_source: SessionSource,
    ) -> std::io::Result<Option<AgentIdentityAuth>> {
        if policy == AgentIdentityAuthPolicy::ChatGptAuth && matches!(auth, CodexAuth::Chatgpt(_)) {
            let _bootstrap_permit = self
                .agent_identity_lock
                .acquire()
                .await
                .map_err(std::io::Error::other)?;
            let effective_chatgpt_workspaces = self.effective_chatgpt_workspaces();
            let forced_chatgpt_workspace_id = self.forced_chatgpt_workspace_id();
            let cooldown_key = match (
                &auth,
                ManagedChatGptAgentIdentityBinding::from_auth(
                    &auth,
                    forced_chatgpt_workspace_id.clone(),
                ),
                self.agent_identity_authapi_base_url.as_ref(),
            ) {
                (CodexAuth::Chatgpt(chatgpt), Some(binding), Some(authapi_base_url)) => chatgpt
                    .identity_key
                    .as_ref()
                    .map(|identity_key| AgentIdentityBootstrapCooldownKey {
                        identity_key: identity_key.clone(),
                        chatgpt_user_id: binding.chatgpt_user_id,
                        account_id: binding.account_id,
                        authapi_base_url: authapi_base_url.clone(),
                    }),
                _ => None,
            };
            if let Some(cooldown_key) = cooldown_key.as_ref()
                && let Ok(mut cooldown) = self.agent_identity_bootstrap_cooldown.lock()
                && let Some(error) = cooldown.error_for(cooldown_key, Instant::now())
            {
                tracing::warn!("agent identity bootstrap retry suppressed during shared cooldown");
                return Err(std::io::Error::other(error));
            }

            let result = auth
                .agent_identity_auth(
                    policy,
                    self.agent_identity_authapi_base_url.as_deref(),
                    effective_chatgpt_workspaces,
                    &self.auth_route_config,
                    session_source,
                )
                .await;
            if let (Ok(mut cooldown), Some(cooldown_key)) = (
                self.agent_identity_bootstrap_cooldown.lock(),
                cooldown_key.as_ref(),
            ) {
                if let Err(err) = &result
                    && let Some(error) = AgentIdentityAuthError::bootstrap_unavailable(err).cloned()
                {
                    let capacity = self
                        .load_managed_chatgpt_document()
                        .ok()
                        .flatten()
                        .and_then(|auth| auth.managed_chatgpt.map(|pool| pool.accounts.len()))
                        .unwrap_or(1);
                    cooldown.record_failure(cooldown_key.clone(), error, Instant::now(), capacity);
                } else {
                    cooldown.clear(cooldown_key);
                }
            }
            return result;
        }
        auth.agent_identity_auth(
            policy,
            self.agent_identity_authapi_base_url.as_deref(),
            self.effective_chatgpt_workspaces(),
            &self.auth_route_config,
            session_source,
        )
        .await
    }

    /// Reloads auth from the active source. Returns whether the auth value changed.
    pub async fn reload(&self) -> bool {
        tracing::info!("Reloading auth");
        let new_auth = self.load_auth().await;
        self.set_cached_auth(new_auth)
    }

    async fn reload_if_account_id_matches(
        &self,
        expected_account_id: Option<&str>,
    ) -> ReloadOutcome {
        let expected_account_id = match expected_account_id {
            Some(account_id) => account_id,
            None => {
                tracing::info!("Skipping auth reload because no account id is available.");
                return ReloadOutcome::Skipped;
            }
        };

        let new_auth = self.load_auth().await;
        let new_account_id = new_auth.as_ref().and_then(CodexAuth::get_account_id);

        if new_account_id.as_deref() != Some(expected_account_id) {
            let found_account_id = new_account_id.as_deref().unwrap_or("unknown");
            tracing::info!(
                "Skipping auth reload due to account id mismatch (expected: {expected_account_id}, found: {found_account_id})"
            );
            return ReloadOutcome::Skipped;
        }

        tracing::info!("Reloading auth for account {expected_account_id}");
        let cached_before_reload = self.auth_cached();
        let auth_changed =
            !Self::auths_equal_for_refresh(cached_before_reload.as_ref(), new_auth.as_ref());
        self.set_cached_auth(new_auth);
        if auth_changed {
            ReloadOutcome::ReloadedChanged
        } else {
            ReloadOutcome::ReloadedNoChange
        }
    }

    fn auths_equal_for_refresh(a: Option<&CodexAuth>, b: Option<&CodexAuth>) -> bool {
        match (a, b) {
            (None, None) => true,
            (Some(a), Some(b)) => match (a.api_auth_mode(), b.api_auth_mode()) {
                (AuthMode::ApiKey, AuthMode::ApiKey) => a.api_key() == b.api_key(),
                (AuthMode::Chatgpt, AuthMode::Chatgpt)
                | (AuthMode::ChatgptAuthTokens, AuthMode::ChatgptAuthTokens) => {
                    a.get_current_auth_json() == b.get_current_auth_json()
                }
                (AuthMode::Headers, AuthMode::Headers) => a == b,
                (AuthMode::AgentIdentity, AuthMode::AgentIdentity) => match (a, b) {
                    (CodexAuth::AgentIdentity(a), CodexAuth::AgentIdentity(b)) => {
                        a.record() == b.record()
                    }
                    _ => false,
                },
                (AuthMode::PersonalAccessToken, AuthMode::PersonalAccessToken) => a == b,
                (AuthMode::BedrockApiKey, AuthMode::BedrockApiKey) => a == b,
                _ => false,
            },
            _ => false,
        }
    }

    fn auths_equal(a: Option<&CodexAuth>, b: Option<&CodexAuth>) -> bool {
        match (a, b) {
            (None, None) => true,
            (Some(a), Some(b)) => a == b,
            _ => false,
        }
    }

    /// Records a permanent refresh failure only if the failed refresh was
    /// attempted against the auth snapshot that is still cached.
    fn record_permanent_refresh_failure_if_unchanged(
        &self,
        attempted_auth: &CodexAuth,
        error: &RefreshTokenFailedError,
    ) {
        if let Ok(mut guard) = self.inner.write() {
            let current_auth_matches =
                Self::auths_equal_for_refresh(Some(attempted_auth), guard.auth.as_ref());
            if current_auth_matches {
                guard.permanent_refresh_failure = Some(AuthScopedRefreshFailure {
                    auth: attempted_auth.clone(),
                    error: error.clone(),
                });
            }
        }
    }

    async fn load_auth(&self) -> Option<CodexAuth> {
        if let Some(external_auth) = self.external_auth() {
            return match self.resolve_external_auth(&external_auth).await {
                Ok(auth) => Some(auth),
                Err(err) => {
                    tracing::error!("Failed to resolve external auth: {err}");
                    None
                }
            };
        }

        let allowed_login_methods = self.allowed_login_methods();
        let effective_chatgpt_workspaces = self.effective_chatgpt_workspaces();
        load_auth(
            &self.codex_home,
            self.enable_codex_api_key_env,
            self.auth_credentials_store_mode,
            Some(&allowed_login_methods),
            effective_chatgpt_workspaces.as_deref(),
            self.chatgpt_base_url.as_deref(),
            self.keyring_backend_kind,
            self.agent_identity_authapi_base_url.as_deref(),
            &self.auth_route_config,
        )
        .await
        .ok()
        .flatten()
        .filter(|auth| {
            validate_auth_restrictions(
                Some(&allowed_login_methods),
                effective_chatgpt_workspaces.as_deref(),
                auth,
            )
            .is_ok()
        })
    }

    fn set_cached_auth(&self, new_auth: Option<CodexAuth>) -> bool {
        if let Ok(mut guard) = self.inner.write() {
            let previous = guard.auth.as_ref();
            let changed = !AuthManager::auths_equal(previous, new_auth.as_ref());
            let auth_changed_for_refresh =
                !Self::auths_equal_for_refresh(previous, new_auth.as_ref());
            let managed_to_nonpooled = matches!(
                previous,
                Some(CodexAuth::Chatgpt(ChatgptAuth {
                    identity_key: Some(_),
                    ..
                }))
            ) && !matches!(
                new_auth.as_ref(),
                Some(CodexAuth::Chatgpt(ChatgptAuth {
                    identity_key: Some(_),
                    ..
                }))
            );
            let selection_revision = self.selection_pins.revision();
            if managed_to_nonpooled {
                self.selection_pins.clear();
            }
            let selection_changed = self.selection_pins.revision() != selection_revision;
            if auth_changed_for_refresh {
                guard.permanent_refresh_failure = None;
            }
            tracing::info!("Reloaded auth, changed: {changed}");
            guard.external_chatgpt_fingerprint =
                auth_external_chatgpt_fingerprint(new_auth.as_ref());
            guard.auth = new_auth;
            guard.load_error = None;
            if auth_changed_for_refresh || selection_changed {
                self.auth_change_tx.send_modify(|revision| *revision += 1);
            }
            changed
        } else {
            false
        }
    }

    pub async fn set_external_auth(
        &self,
        external_auth: Arc<dyn ExternalAuth>,
    ) -> Result<(), RefreshTokenError> {
        let auth = self.resolve_external_auth(&external_auth).await?;
        *self.external_auth.write().map_err(|_| {
            RefreshTokenError::Transient(std::io::Error::other("external auth lock is poisoned"))
        })? = Some(external_auth);
        self.commit_external_auth(auth)
    }

    pub fn clear_external_auth(&self) {
        if let Ok(mut external_auth) = self.external_auth.write() {
            external_auth.take();
        }
        if let Err(err) = delete_external_chatgpt_auth(&self.codex_home) {
            tracing::warn!("failed to clear external ChatGPT auth overlay: {err}");
        }
        self.set_cached_auth(/*new_auth*/ None);
    }

    pub fn set_forced_chatgpt_workspace_id(&self, workspace_id: Option<Vec<String>>) {
        if let Ok(mut guard) = self.forced_chatgpt_workspace_id.write()
            && *guard != workspace_id
        {
            *guard = workspace_id;
        }
    }

    pub fn forced_chatgpt_workspace_id(&self) -> Option<Vec<String>> {
        self.forced_chatgpt_workspace_id
            .read()
            .ok()
            .and_then(|guard| guard.clone())
    }

    pub fn effective_chatgpt_workspaces(&self) -> Option<Vec<String>> {
        self.managed_auth_policy
            .effective_chatgpt_workspaces(self.forced_chatgpt_workspace_id().as_deref())
    }

    pub fn is_login_method_allowed(&self, method: ForcedLoginMethod) -> bool {
        self.managed_auth_policy.allows_login_method(
            method,
            self.forced_login_method,
            self.forced_chatgpt_workspace_id().as_deref(),
        )
    }

    fn allowed_login_methods(&self) -> Vec<ForcedLoginMethod> {
        self.managed_auth_policy.allowed_login_methods(
            self.forced_login_method,
            self.forced_chatgpt_workspace_id().as_deref(),
        )
    }

    pub fn has_external_auth(&self) -> bool {
        self.external_auth().is_some()
    }

    pub fn is_external_chatgpt_auth_active(&self) -> bool {
        load_external_chatgpt_auth(&self.codex_home)
            .map(|auth| auth.is_some())
            .unwrap_or_else(|_| {
                self.auth_cached()
                    .as_ref()
                    .is_some_and(CodexAuth::is_external_chatgpt_tokens)
            })
    }

    pub fn codex_api_key_env_enabled(&self) -> bool {
        self.enable_codex_api_key_env
    }

    /// Convenience constructor returning an `Arc` wrapper.
    pub async fn shared(
        codex_home: PathBuf,
        enable_codex_api_key_env: bool,
        auth_credentials_store_mode: AuthCredentialsStoreMode,
        forced_chatgpt_workspace_id: Option<Vec<String>>,
        chatgpt_base_url: Option<String>,
        keyring_backend_kind: AuthKeyringBackendKind,
        auth_route_config: AuthRouteConfig,
    ) -> Arc<Self> {
        Arc::new(
            Self::new(
                codex_home,
                enable_codex_api_key_env,
                auth_credentials_store_mode,
                forced_chatgpt_workspace_id,
                chatgpt_base_url,
                keyring_backend_kind,
                auth_route_config,
            )
            .await,
        )
    }

    /// Convenience constructor returning an `Arc` wrapper from resolved config.
    pub async fn shared_from_config(
        config: &impl AuthManagerConfig,
        enable_codex_api_key_env: bool,
    ) -> Arc<Self> {
        Self::shared_from_auth_config(
            AuthConfig {
                codex_home: config.codex_home(),
                auth_credentials_store_mode: config.cli_auth_credentials_store_mode(),
                keyring_backend_kind: config.auth_keyring_backend_kind(),
                forced_login_method: config.forced_login_method(),
                chatgpt_base_url: Some(config.chatgpt_base_url()),
                forced_chatgpt_workspace_id: config.forced_chatgpt_workspace_id(),
                managed_auth_policy: config.managed_auth_policy(),
                auth_route_config: config.auth_route_config(),
            },
            enable_codex_api_key_env,
        )
        .await
    }

    /// Builds a shared manager using restrictions resolved before authentication.
    pub async fn shared_from_auth_config(
        auth_config: AuthConfig,
        enable_codex_api_key_env: bool,
    ) -> Arc<Self> {
        Arc::new(Self::new_from_auth_config(auth_config, enable_codex_api_key_env).await)
    }

    pub fn unauthorized_recovery(self: &Arc<Self>) -> UnauthorizedRecovery {
        UnauthorizedRecovery::new(Arc::clone(self))
    }

    pub fn unauthorized_recovery_for_snapshot(
        self: &Arc<Self>,
        snapshot: &ManagedChatgptAuthSnapshot,
    ) -> UnauthorizedRecovery {
        UnauthorizedRecovery::new_for_snapshot(Arc::clone(self), snapshot)
    }

    fn external_auth(&self) -> Option<Arc<dyn ExternalAuth>> {
        self.external_auth
            .read()
            .ok()
            .and_then(|external_auth| external_auth.as_ref().map(Arc::clone))
    }

    fn has_external_api_key_auth(&self) -> bool {
        self.has_external_auth()
            && self
                .auth_cached()
                .as_ref()
                .is_some_and(CodexAuth::is_api_key_auth)
    }

    async fn resolve_external_auth(
        &self,
        external_auth: &Arc<dyn ExternalAuth>,
    ) -> Result<CodexAuth, RefreshTokenError> {
        let auth = external_auth
            .resolve()
            .await
            .map_err(RefreshTokenError::Transient)?;
        self.validate_external_auth(&auth)?;
        Ok(auth)
    }

    /// Attempt to refresh the token by first performing a guarded reload from
    /// the active auth source. If the loaded token differs from the cached token,
    /// we can assume that the source already refreshed it. Otherwise, ask the
    /// token authority to refresh.
    pub async fn refresh_token(&self) -> Result<(), RefreshTokenError> {
        let _refresh_guard = self.refresh_lock.acquire().await.map_err(|_| {
            RefreshTokenError::Permanent(RefreshTokenFailedError::new(
                RefreshTokenFailedReason::Other,
                REFRESH_TOKEN_UNKNOWN_MESSAGE.to_string(),
            ))
        })?;
        let mut auth_before_reload = self.auth_cached();
        if auth_before_reload.is_none() {
            self.reload().await;
            auth_before_reload = self.auth_cached();
            if auth_before_reload.is_some() {
                tracing::info!(
                    "Skipping token refresh because auth became available after guarded reload."
                );
                return Ok(());
            }
        }
        if auth_before_reload
            .as_ref()
            .is_some_and(|auth| auth.is_api_key_auth() || auth.is_personal_access_token_auth())
        {
            return Ok(());
        }
        let expected_account_id = auth_before_reload
            .as_ref()
            .and_then(CodexAuth::get_account_id);

        match self
            .reload_if_account_id_matches(expected_account_id.as_deref())
            .await
        {
            ReloadOutcome::ReloadedChanged => {
                tracing::info!("Skipping token refresh because auth changed after guarded reload.");
                Ok(())
            }
            ReloadOutcome::ReloadedNoChange => self.refresh_token_from_authority_impl().await,
            ReloadOutcome::Skipped => {
                Err(RefreshTokenError::Permanent(RefreshTokenFailedError::new(
                    RefreshTokenFailedReason::Other,
                    REFRESH_TOKEN_ACCOUNT_MISMATCH_MESSAGE.to_string(),
                )))
            }
        }
    }

    /// Attempt to refresh the current auth token from the authority that issued
    /// it and update the shared cache. If the token refresh fails, returns the
    /// error to the caller.
    pub async fn refresh_token_from_authority(&self) -> Result<(), RefreshTokenError> {
        let _refresh_guard = self.refresh_lock.acquire().await.map_err(|_| {
            RefreshTokenError::Permanent(RefreshTokenFailedError::new(
                RefreshTokenFailedReason::Other,
                REFRESH_TOKEN_UNKNOWN_MESSAGE.to_string(),
            ))
        })?;
        self.refresh_token_from_authority_impl().await
    }

    async fn refresh_token_from_authority_impl(&self) -> Result<(), RefreshTokenError> {
        tracing::info!("Refreshing token");

        let auth = match self.auth_cached() {
            Some(auth) => auth,
            None => return Ok(()),
        };
        if let Some(error) = self.refresh_failure_for_auth(&auth) {
            return Err(RefreshTokenError::Permanent(error));
        }

        let attempted_auth = auth.clone();
        let result = if self.has_external_auth() {
            self.refresh_external_auth(ExternalAuthRefreshReason::Unauthorized)
                .await
        } else {
            match auth {
                CodexAuth::Chatgpt(chatgpt_auth) => {
                    if let Some(identity) = chatgpt_auth.identity_key.as_deref() {
                        self.refresh_managed_chatgpt_account_bounded_impl(
                            identity,
                            true,
                            MANAGED_REFRESH_MAX_DURATION,
                        )
                        .await
                        .map(|_| ())
                    } else {
                        let token_data = chatgpt_auth.current_token_data().ok_or_else(|| {
                            RefreshTokenError::Transient(std::io::Error::other(
                                "Token data is not available.",
                            ))
                        })?;
                        self.refresh_and_persist_chatgpt_token(
                            &chatgpt_auth,
                            token_data.refresh_token,
                        )
                        .await
                    }
                }
                CodexAuth::ApiKey(_)
                | CodexAuth::ChatgptAuthTokens(_)
                | CodexAuth::Headers(_)
                | CodexAuth::AgentIdentity(_)
                | CodexAuth::PersonalAccessToken(_)
                | CodexAuth::BedrockApiKey(_) => Ok(()),
            }
        };
        if let Err(RefreshTokenError::Permanent(error)) = &result {
            self.record_permanent_refresh_failure_if_unchanged(&attempted_auth, error);
        }
        result
    }

    /// Log out by deleting the on‑disk auth.json (if present). Returns Ok(true)
    /// if a file was removed, Ok(false) if no auth file existed. On success,
    /// reloads the in‑memory auth cache so callers immediately observe the
    /// unauthenticated state.
    pub async fn logout(&self) -> std::io::Result<bool> {
        if self.has_external_auth() || self.is_external_chatgpt_auth_active() {
            let removed = delete_external_chatgpt_auth(&self.codex_home)?;
            self.clear_external_auth();
            self.reload().await;
            return Ok(removed);
        }
        self.resume_managed_chatgpt_tombstones().await?;
        self.ensure_global_logout_unambiguous()?;
        self.selection_pins.clear();
        let removed = logout_all_stores(
            &self.codex_home,
            self.auth_credentials_store_mode,
            self.keyring_backend_kind,
        )?;
        // Always reload to clear any cached auth (even if file absent).
        self.clear_external_auth();
        self.reload().await;
        Ok(removed)
    }

    fn ensure_global_logout_unambiguous(&self) -> std::io::Result<()> {
        if self
            .load_managed_chatgpt_document()?
            .and_then(|auth| auth.managed_chatgpt)
            .is_some_and(|pool| pool.accounts.len() > 1)
        {
            return Err(std::io::Error::other(
                "global logout is ambiguous for a multi-account ChatGPT pool; select an account or use logout-all",
            ));
        }
        Ok(())
    }

    pub async fn logout_with_revoke(&self) -> std::io::Result<bool> {
        let overlay = load_external_chatgpt_auth(&self.codex_home)?;
        if overlay.is_none() && !self.has_external_auth() {
            self.resume_managed_chatgpt_tombstones().await?;
            self.ensure_global_logout_unambiguous()?;
        }
        let auth_dot_json = overlay.or_else(|| {
            self.auth_cached()
                .and_then(|auth| auth.get_current_auth_json())
        });
        if let Err(err) = revoke_auth_tokens(auth_dot_json.as_ref(), &self.auth_route_config).await
        {
            tracing::warn!("failed to revoke auth tokens during logout: {err}");
        }
        if self.has_external_auth()
            || auth_dot_json
                .as_ref()
                .is_some_and(|auth| auth.auth_mode == Some(AuthMode::ChatgptAuthTokens))
        {
            let removed = delete_external_chatgpt_auth(&self.codex_home)?;
            self.clear_external_auth();
            self.reload().await;
            return Ok(removed);
        }
        self.selection_pins.clear();
        let result = logout_all_stores(
            &self.codex_home,
            self.auth_credentials_store_mode,
            self.keyring_backend_kind,
        )?;
        // Always reload to clear any cached auth (even if file absent).
        self.clear_external_auth();
        self.reload().await;
        Ok(result)
    }

    /// Returns the precise kind of credentials backing the current authentication.
    pub fn get_api_auth_mode(&self) -> Option<AuthMode> {
        self.auth_cached().as_ref().map(CodexAuth::api_auth_mode)
    }

    /// Returns the effective backend auth mode for the current authentication.
    pub fn auth_mode(&self) -> Option<AuthMode> {
        self.auth_cached().as_ref().map(CodexAuth::auth_mode)
    }

    pub fn current_auth_uses_codex_backend(&self) -> bool {
        self.get_api_auth_mode()
            .is_some_and(AuthMode::uses_codex_backend)
    }

    fn should_refresh_proactively(auth: &CodexAuth) -> bool {
        let chatgpt_auth = match auth {
            CodexAuth::Chatgpt(chatgpt_auth) => chatgpt_auth,
            _ => return false,
        };

        let auth_dot_json = match chatgpt_auth.current_auth_json() {
            Some(auth_dot_json) => auth_dot_json,
            None => return false,
        };
        if let Some(tokens) = auth_dot_json.tokens.as_ref()
            && let Ok(Some(expires_at)) = parse_jwt_expiration(&tokens.access_token)
        {
            return expires_at
                <= Utc::now()
                    + chrono::Duration::minutes(CHATGPT_ACCESS_TOKEN_REFRESH_WINDOW_MINUTES);
        }
        let last_refresh = match auth_dot_json.last_refresh {
            Some(last_refresh) => last_refresh,
            None => return false,
        };
        last_refresh < Utc::now() - chrono::Duration::days(TOKEN_REFRESH_INTERVAL)
    }

    async fn refresh_external_auth(
        &self,
        reason: ExternalAuthRefreshReason,
    ) -> Result<(), RefreshTokenError> {
        let Some(external_auth) = self.external_auth() else {
            return Err(RefreshTokenError::Transient(std::io::Error::other(
                "external auth is not configured",
            )));
        };
        let previous_account_id = self
            .auth_cached()
            .as_ref()
            .and_then(CodexAuth::get_account_id);
        let context = ExternalAuthRefreshContext {
            reason,
            previous_account_id,
        };

        let refreshed = external_auth
            .refresh(context)
            .await
            .map_err(RefreshTokenError::Transient)?;
        self.validate_external_auth(&refreshed)?;
        self.commit_external_auth(refreshed)?;
        Ok(())
    }

    fn commit_external_auth(&self, auth: CodexAuth) -> Result<(), RefreshTokenError> {
        if auth.is_external_chatgpt_tokens() {
            let auth_dot_json = auth.get_current_auth_json().ok_or_else(|| {
                RefreshTokenError::Transient(std::io::Error::other(
                    "external ChatGPT auth tokens are missing auth state",
                ))
            })?;
            // App/connectors paths still construct independent AuthManagers from Config. Mirror
            // external ChatGPT auth into its dedicated process-local overlay.
            save_external_chatgpt_auth(&self.codex_home, &auth_dot_json)
                .map_err(RefreshTokenError::Transient)?;
        }

        self.set_cached_auth(Some(auth));
        Ok(())
    }

    fn validate_external_auth(&self, auth: &CodexAuth) -> Result<(), RefreshTokenError> {
        let allowed_login_methods = self.allowed_login_methods();
        validate_auth_restrictions(
            Some(&allowed_login_methods),
            self.effective_chatgpt_workspaces().as_deref(),
            auth,
        )
        .map_err(std::io::Error::other)?;
        Ok(())
    }

    // Refreshes ChatGPT OAuth tokens, persists the updated auth state, and
    // reloads the in-memory cache so callers immediately observe new tokens.
    async fn refresh_and_persist_chatgpt_token(
        &self,
        auth: &ChatgptAuth,
        refresh_token: String,
    ) -> Result<(), RefreshTokenError> {
        let refresh_response = request_chatgpt_token_refresh(refresh_token, auth.client()).await?;

        persist_tokens(
            auth.storage(),
            refresh_response.id_token,
            refresh_response.access_token,
            refresh_response.refresh_token,
        )
        .map_err(RefreshTokenError::from)?;
        self.reload().await;

        Ok(())
    }
}

#[cfg(test)]
#[path = "auth_tests.rs"]
mod tests;
