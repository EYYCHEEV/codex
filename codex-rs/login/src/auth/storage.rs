use chrono::DateTime;
use chrono::Utc;
use rand::Rng;
use serde::Deserialize;
use serde::Serialize;
use sha2::Digest;
use sha2::Sha256;
use std::collections::HashMap;
use std::fmt::Debug;
use std::fs::File;
use std::fs::OpenOptions;
use std::io::Read;
use std::io::Write;
#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::Mutex;
use tracing::warn;

use super::BedrockApiKeyAuth;
use crate::token_data::TokenData;
use codex_agent_identity::AgentIdentityJwtClaims;
use codex_agent_identity::decode_agent_identity_jwt;
use codex_config::types::AuthCredentialsStoreMode;
pub use codex_config::types::AuthKeyringBackendKind;
use codex_keyring_store::DefaultKeyringStore;
use codex_keyring_store::KeyringStore;
use codex_protocol::account::PlanType as AccountPlanType;
use codex_protocol::auth::AuthMode;
use codex_secrets::LocalSecretsNamespace;
use codex_secrets::SecretName;
use codex_secrets::SecretScope;
use codex_secrets::SecretsBackendKind;
use codex_secrets::SecretsManager;
use once_cell::sync::Lazy;

/// Expected structure for $CODEX_HOME/auth.json.
#[derive(Deserialize, Serialize, Clone, Debug, PartialEq)]
pub struct AuthDotJson {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub auth_mode: Option<AuthMode>,

    #[serde(rename = "OPENAI_API_KEY")]
    pub openai_api_key: Option<String>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tokens: Option<TokenData>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_refresh: Option<DateTime<Utc>>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub agent_identity: Option<AgentIdentityStorage>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub managed_chatgpt: Option<ManagedChatgptStorage>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub personal_access_token: Option<String>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bedrock_api_key: Option<BedrockApiKeyAuth>,
}

#[derive(Deserialize, Serialize, Clone, Debug, PartialEq)]
pub struct ManagedChatgptStorage {
    pub version: u32,
    #[serde(default)]
    pub revision: u64,
    /// Next durable per-account generation. This survives row deletion so a
    /// remove/re-add cycle cannot make stale snapshots current again.
    #[serde(default)]
    pub next_account_revision: u64,
    #[serde(default)]
    pub accounts: Vec<ManagedChatgptAccount>,
}

#[derive(Deserialize, Serialize, Clone, Debug, PartialEq)]
pub struct ManagedChatgptAccount {
    pub identity_key: String,
    #[serde(default)]
    pub identity_aliases: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub normalized_email: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub chatgpt_account_id: Option<String>,
    pub tokens: TokenData,
    /// Monotonic row-state revision used to order account notifications.
    pub revision: u64,
    /// Changes only when credential or identity-bearing transport data changes.
    #[serde(default)]
    pub credential_revision: u64,
    pub last_refresh: DateTime<Utc>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub oauth_api_key: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub agent_identity: Option<AgentIdentityStorage>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mutation_lease: Option<ManagedChatgptMutationLease>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tombstone: Option<ManagedChatgptTombstone>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub block: Option<ManagedChatgptBlock>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub observed_usage: Option<ManagedChatgptObservedUsage>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub token_unavailable: Option<ManagedChatgptUnavailableObservation>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub refresh_failure: Option<ManagedChatgptRefreshFailure>,
}

#[derive(Deserialize, Serialize, Clone, Debug, PartialEq, Eq)]
pub struct ManagedChatgptMutationLease {
    pub operation_id: String,
    pub kind: ManagedChatgptMutationKind,
    pub expected_revision: u64,
    pub expected_refresh_token: String,
    pub expires_at: DateTime<Utc>,
}

#[derive(Deserialize, Serialize, Clone, Copy, Debug, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ManagedChatgptMutationKind {
    Refresh,
    Remove,
    Upsert,
}

#[derive(Deserialize, Serialize, Clone, Debug, PartialEq, Eq)]
pub struct ManagedChatgptTombstone {
    pub operation_id: String,
    pub revision: u64,
    pub refresh_token: String,
}

#[derive(Deserialize, Serialize, Clone, Copy, Debug, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ManagedChatgptBlockKind {
    AuthInvalid,
    Quota,
    Workspace,
}

#[derive(Deserialize, Serialize, Clone, Debug, PartialEq, Eq)]
pub struct ManagedChatgptBlock {
    pub kind: ManagedChatgptBlockKind,
    pub blocked_at: DateTime<Utc>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reset_at: Option<DateTime<Utc>>,
    pub credential_revision: u64,
}

#[derive(Deserialize, Serialize, Clone, Copy, Debug, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ManagedChatgptLimitKind {
    Primary,
    Secondary,
    Additional,
}

#[derive(Deserialize, Serialize, Clone, Debug, PartialEq)]
pub struct ManagedChatgptRateWindow {
    pub limit_id: String,
    pub kind: ManagedChatgptLimitKind,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub remaining_percent: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reset_at: Option<DateTime<Utc>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub window_duration_mins: Option<i64>,
}

#[derive(Deserialize, Serialize, Clone, Debug, PartialEq, Eq)]
pub struct ManagedChatgptUnavailableObservation {
    pub observed_at: DateTime<Utc>,
    pub reason: String,
}

#[derive(Deserialize, Serialize, Clone, Debug, PartialEq, Eq)]
pub struct ManagedChatgptRefreshFailure {
    pub observed_at: DateTime<Utc>,
    pub permanent: bool,
    /// Stable, secret-free classification suitable for persistence and UI mapping.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason_code: Option<String>,
    /// Identifies the refresh lease that produced this failure. Older documents
    /// omit it; new transitions use it to make cancellation idempotent.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub operation_id: Option<String>,
}

#[derive(Deserialize, Serialize, Clone, Debug, PartialEq, Eq)]
pub struct ManagedChatgptTokenUsageSummary {
    pub lifetime_tokens: Option<i64>,
    pub peak_daily_tokens: Option<i64>,
    pub longest_running_turn_sec: Option<i64>,
    pub current_streak_days: Option<i64>,
    pub longest_streak_days: Option<i64>,
}

#[derive(Deserialize, Serialize, Clone, Debug, PartialEq)]
pub struct ManagedChatgptObservedUsage {
    pub observed_at: DateTime<Utc>,
    #[serde(default)]
    pub rate_windows: Vec<ManagedChatgptRateWindow>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub unavailable: Option<ManagedChatgptUnavailableObservation>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub token_usage: Option<ManagedChatgptTokenUsageSummary>,
}

#[derive(Deserialize, Serialize, Clone, Debug, PartialEq, Eq)]
#[serde(untagged)]
pub enum AgentIdentityStorage {
    Jwt(String),
    Record(AgentIdentityAuthRecord),
}

impl AgentIdentityStorage {
    pub fn has_auth_material(&self) -> bool {
        match self {
            Self::Jwt(jwt) => !jwt.trim().is_empty(),
            Self::Record(record) => {
                !record.agent_runtime_id.trim().is_empty()
                    && !record.agent_private_key.trim().is_empty()
            }
        }
    }

    pub(crate) fn as_record(&self) -> Option<&AgentIdentityAuthRecord> {
        match self {
            Self::Jwt(_) => None,
            Self::Record(record) => Some(record),
        }
    }
}

#[derive(Deserialize, Serialize, Clone, Debug, PartialEq, Eq)]
pub struct AgentIdentityAuthRecord {
    pub agent_runtime_id: String,
    pub agent_private_key: String,
    pub account_id: String,
    pub chatgpt_user_id: String,
    #[serde(
        default,
        deserialize_with = "deserialize_optional_non_empty_string",
        serialize_with = "serialize_optional_string_as_empty"
    )]
    pub email: Option<String>,
    pub plan_type: AccountPlanType,
    pub chatgpt_account_is_fedramp: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub task_id: Option<String>,
}

fn deserialize_optional_non_empty_string<'de, D>(
    deserializer: D,
) -> Result<Option<String>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    Option::<String>::deserialize(deserializer).map(|value| value.filter(|value| !value.is_empty()))
}

fn serialize_optional_string_as_empty<S>(
    value: &Option<String>,
    serializer: S,
) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    value.as_deref().unwrap_or_default().serialize(serializer)
}

impl AgentIdentityAuthRecord {
    pub(crate) fn from_agent_identity_jwt(jwt: &str) -> std::io::Result<Self> {
        let claims =
            decode_agent_identity_jwt(jwt, /*jwks*/ None).map_err(std::io::Error::other)?;

        Ok(claims.into())
    }
}

impl From<AgentIdentityJwtClaims> for AgentIdentityAuthRecord {
    fn from(claims: AgentIdentityJwtClaims) -> Self {
        Self {
            agent_runtime_id: claims.agent_runtime_id,
            agent_private_key: claims.agent_private_key,
            account_id: claims.account_id,
            chatgpt_user_id: claims.chatgpt_user_id,
            email: claims.email,
            plan_type: claims.plan_type.into(),
            chatgpt_account_is_fedramp: claims.chatgpt_account_is_fedramp,
            task_id: None,
        }
    }
}

pub(super) fn get_auth_file(codex_home: &Path) -> PathBuf {
    codex_home.join("auth.json")
}

pub(super) fn delete_file_if_exists(codex_home: &Path) -> std::io::Result<bool> {
    let auth_file = get_auth_file(codex_home);
    match std::fs::remove_file(&auth_file) {
        Ok(()) => Ok(true),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(err) => Err(err),
    }
}

pub(super) enum AuthStorageMutation {
    Save(AuthDotJson),
    /// Persists coordination metadata without publishing another pool generation.
    /// Callers must not change credentials or begin a new public state transition.
    SaveInternalState(AuthDotJson),
    Keep(Option<AuthDotJson>),
    Delete,
}

fn prepare_managed_save(
    auth: &mut AuthDotJson,
    previous_pool_revision: u64,
    previous_next_account_revision: u64,
) {
    let Some(pool) = auth.managed_chatgpt.as_mut() else {
        return;
    };
    pool.revision = pool.revision.max(previous_pool_revision.saturating_add(1));
    let row_floor = pool
        .accounts
        .iter()
        .map(|row| row.revision.max(row.credential_revision))
        .max()
        .unwrap_or(0)
        .saturating_add(1);
    pool.next_account_revision = pool
        .next_account_revision
        .max(previous_next_account_revision)
        .max(row_floor)
        .max(1);
    if auth.auth_mode == Some(AuthMode::Chatgpt) {
        auth.openai_api_key = None;
        auth.tokens = None;
        auth.last_refresh = None;
        auth.agent_identity = None;
        auth.personal_access_token = None;
        auth.bedrock_api_key = None;
    }
}

pub(super) trait AuthStorageBackend: Debug + Send + Sync {
    fn load(&self) -> std::io::Result<Option<AuthDotJson>>;
    fn save(&self, auth: &AuthDotJson) -> std::io::Result<()>;
    fn delete(&self) -> std::io::Result<bool>;
    fn codex_home(&self) -> &Path;
    fn delete_locked(&self) -> std::io::Result<bool> {
        with_codex_home_lock(self.codex_home(), || self.delete())
    }

    fn mutate(
        &self,
        action: &mut dyn FnMut(Option<AuthDotJson>) -> std::io::Result<AuthStorageMutation>,
    ) -> std::io::Result<Option<AuthDotJson>> {
        with_codex_home_lock(self.codex_home(), || {
            let current = self.load()?;
            let previous_pool_revision = current
                .as_ref()
                .and_then(|auth| auth.managed_chatgpt.as_ref())
                .map(|pool| pool.revision)
                .unwrap_or(0);
            let previous_next_account_revision = current
                .as_ref()
                .and_then(|auth| auth.managed_chatgpt.as_ref())
                .map(|pool| pool.next_account_revision)
                .unwrap_or(0);
            match action(current)? {
                AuthStorageMutation::Save(mut auth) => {
                    prepare_managed_save(
                        &mut auth,
                        previous_pool_revision,
                        previous_next_account_revision,
                    );
                    self.save(&auth)?;
                    Ok(Some(auth))
                }
                AuthStorageMutation::SaveInternalState(auth) => {
                    self.save(&auth)?;
                    Ok(Some(auth))
                }
                AuthStorageMutation::Keep(auth) => Ok(auth),
                AuthStorageMutation::Delete => {
                    self.delete()?;
                    Ok(None)
                }
            }
        })
    }
}

fn with_codex_home_lock<T>(
    codex_home: &Path,
    action: impl FnOnce() -> std::io::Result<T>,
) -> std::io::Result<T> {
    std::fs::create_dir_all(codex_home)?;
    let lock_path = codex_home.join(".auth.json.lock");
    let lock_file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .open(lock_path)?;
    lock_file.lock()?;
    let result = action();
    let unlock_result = lock_file.unlock();
    match (result, unlock_result) {
        (Ok(value), Ok(())) => Ok(value),
        (Err(err), _) | (Ok(_), Err(err)) => Err(err),
    }
}

fn save_file_atomically(path: &Path, contents: &[u8]) -> std::io::Result<()> {
    let parent = path
        .parent()
        .ok_or_else(|| std::io::Error::other("auth file has no parent directory"))?;
    std::fs::create_dir_all(parent)?;
    let random: u64 = rand::rng().random();
    let temp_path = parent.join(format!(".auth.json.{random:016x}.tmp"));
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    options.mode(0o600);
    let mut temp_file = options.open(&temp_path)?;
    let write_result = (|| {
        temp_file.write_all(contents)?;
        temp_file.sync_all()?;
        std::fs::rename(&temp_path, path)?;
        File::open(parent)?.sync_all()
    })();
    if write_result.is_err() {
        let _ = std::fs::remove_file(temp_path);
    }
    write_result
}

#[derive(Clone, Debug)]
pub(super) struct FileAuthStorage {
    codex_home: PathBuf,
}

impl FileAuthStorage {
    pub(super) fn new(codex_home: PathBuf) -> Self {
        Self { codex_home }
    }

    /// Attempt to read and parse the `auth.json` file in the given `CODEX_HOME` directory.
    /// Returns the full AuthDotJson structure.
    pub(super) fn try_read_auth_json(&self, auth_file: &Path) -> std::io::Result<AuthDotJson> {
        let mut file = File::open(auth_file)?;
        let mut contents = String::new();
        file.read_to_string(&mut contents)?;
        let auth_dot_json: AuthDotJson = serde_json::from_str(&contents)?;

        Ok(auth_dot_json)
    }
}

impl AuthStorageBackend for FileAuthStorage {
    fn load(&self) -> std::io::Result<Option<AuthDotJson>> {
        let auth_file = get_auth_file(&self.codex_home);
        let auth_dot_json = match self.try_read_auth_json(&auth_file) {
            Ok(auth) => auth,
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(err) => return Err(err),
        };
        Ok(Some(auth_dot_json))
    }

    fn codex_home(&self) -> &Path {
        &self.codex_home
    }

    fn save(&self, auth_dot_json: &AuthDotJson) -> std::io::Result<()> {
        let auth_file = get_auth_file(&self.codex_home);
        let json_data = serde_json::to_vec_pretty(auth_dot_json)?;
        save_file_atomically(&auth_file, &json_data)
    }

    fn delete(&self) -> std::io::Result<bool> {
        delete_file_if_exists(&self.codex_home)
    }
}

static CODEX_AUTH_SECRET_NAME: Lazy<SecretName> =
    Lazy::new(|| match SecretName::new("CODEX_AUTH") {
        Ok(name) => name,
        Err(err) => unreachable!("CODEX_AUTH should be a valid secret name: {err}"),
    });
const KEYRING_SERVICE: &str = "Codex Auth";

// turns codex_home path into a stable, short key string
fn compute_store_key(codex_home: &Path) -> std::io::Result<String> {
    let canonical = codex_home
        .canonicalize()
        .unwrap_or_else(|_| codex_home.to_path_buf());
    let path_str = canonical.to_string_lossy();
    let mut hasher = Sha256::new();
    hasher.update(path_str.as_bytes());
    let digest = hasher.finalize();
    let hex = format!("{digest:x}");
    let truncated = hex.get(..16).unwrap_or(&hex);
    Ok(format!("cli|{truncated}"))
}

#[derive(Clone, Debug)]
struct DirectKeyringAuthStorage {
    codex_home: PathBuf,
    keyring_store: Arc<dyn KeyringStore>,
}

impl DirectKeyringAuthStorage {
    fn new(codex_home: PathBuf, keyring_store: Arc<dyn KeyringStore>) -> Self {
        Self {
            codex_home,
            keyring_store,
        }
    }

    fn load_from_keyring(&self, key: &str) -> std::io::Result<Option<AuthDotJson>> {
        match self.keyring_store.load(KEYRING_SERVICE, key) {
            Ok(Some(serialized)) => serde_json::from_str(&serialized).map(Some).map_err(|err| {
                std::io::Error::other(format!(
                    "failed to deserialize CLI auth from keyring: {err}"
                ))
            }),
            Ok(None) => Ok(None),
            Err(error) => Err(std::io::Error::other(format!(
                "failed to load CLI auth from keyring: {}",
                error.message()
            ))),
        }
    }

    fn save_to_keyring(&self, key: &str, value: &str) -> std::io::Result<()> {
        match self.keyring_store.save(KEYRING_SERVICE, key, value) {
            Ok(()) => Ok(()),
            Err(error) => {
                let message = format!(
                    "failed to write OAuth tokens to keyring: {}",
                    error.message()
                );
                warn!("{message}");
                Err(std::io::Error::other(message))
            }
        }
    }
}

impl AuthStorageBackend for DirectKeyringAuthStorage {
    fn load(&self) -> std::io::Result<Option<AuthDotJson>> {
        let key = compute_store_key(&self.codex_home)?;
        self.load_from_keyring(&key)
    }

    fn save(&self, auth: &AuthDotJson) -> std::io::Result<()> {
        let key = compute_store_key(&self.codex_home)?;
        // Simpler error mapping per style: prefer method reference over closure
        let serialized = serde_json::to_string(auth).map_err(std::io::Error::other)?;
        self.save_to_keyring(&key, &serialized)?;
        delete_file_if_exists(&self.codex_home)?;
        Ok(())
    }

    fn codex_home(&self) -> &Path {
        &self.codex_home
    }

    fn delete(&self) -> std::io::Result<bool> {
        let key = compute_store_key(&self.codex_home)?;
        let keyring_result = self
            .keyring_store
            .delete(KEYRING_SERVICE, &key)
            .map_err(|err| {
                std::io::Error::other(format!("failed to delete auth from keyring: {err}"))
            });
        let file_result = delete_file_if_exists(&self.codex_home);
        let removed = keyring_result.as_ref().copied().unwrap_or(false)
            || file_result.as_ref().copied().unwrap_or(false);
        keyring_result?;
        file_result?;
        Ok(removed)
    }
}

#[derive(Clone)]
struct SecretsKeyringAuthStorage {
    codex_home: PathBuf,
    direct_storage: DirectKeyringAuthStorage,
    secrets_manager: SecretsManager,
}

impl Debug for SecretsKeyringAuthStorage {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SecretsKeyringAuthStorage")
            .field("codex_home", &self.codex_home)
            .finish_non_exhaustive()
    }
}

impl SecretsKeyringAuthStorage {
    fn new(codex_home: PathBuf, keyring_store: Arc<dyn KeyringStore>) -> Self {
        let direct_storage =
            DirectKeyringAuthStorage::new(codex_home.clone(), Arc::clone(&keyring_store));
        let secrets_manager = SecretsManager::new_with_keyring_store_and_namespace(
            codex_home.clone(),
            SecretsBackendKind::Local,
            keyring_store,
            LocalSecretsNamespace::CodexAuth,
        );
        Self {
            codex_home,
            direct_storage,
            secrets_manager,
        }
    }
}

impl AuthStorageBackend for SecretsKeyringAuthStorage {
    fn load(&self) -> std::io::Result<Option<AuthDotJson>> {
        match self
            .secrets_manager
            .get(&SecretScope::Global, &CODEX_AUTH_SECRET_NAME)
            .map_err(|err| {
                std::io::Error::other(format!(
                    "failed to load CLI auth from encrypted auth storage: {err}"
                ))
            })? {
            Some(serialized) => serde_json::from_str(&serialized).map(Some).map_err(|err| {
                std::io::Error::other(format!(
                    "failed to deserialize CLI auth from encrypted auth storage: {err}"
                ))
            }),
            None => Ok(None),
        }
    }

    fn save(&self, auth: &AuthDotJson) -> std::io::Result<()> {
        let serialized = serde_json::to_string(auth).map_err(std::io::Error::other)?;
        self.secrets_manager
            .set(&SecretScope::Global, &CODEX_AUTH_SECRET_NAME, &serialized)
            .map_err(|err| {
                let message =
                    format!("failed to write OAuth tokens to encrypted auth storage: {err}");
                warn!("{message}");
                std::io::Error::other(message)
            })?;
        delete_file_if_exists(&self.codex_home)?;
        Ok(())
    }

    fn codex_home(&self) -> &Path {
        &self.codex_home
    }

    fn delete(&self) -> std::io::Result<bool> {
        let secrets_result = self
            .secrets_manager
            .delete(&SecretScope::Global, &CODEX_AUTH_SECRET_NAME)
            .map_err(|err| {
                std::io::Error::other(format!(
                    "failed to delete auth from encrypted auth storage: {err}"
                ))
            });
        let file_result = delete_file_if_exists(&self.codex_home);
        let direct_result = self.direct_storage.delete();
        let removed = secrets_result.as_ref().copied().unwrap_or(false)
            || file_result.as_ref().copied().unwrap_or(false)
            || direct_result.as_ref().copied().unwrap_or(false);
        secrets_result?;
        file_result?;
        direct_result?;
        Ok(removed)
    }
}

#[derive(Clone, Debug)]
struct AutoAuthStorage {
    keyring_storage: Arc<dyn AuthStorageBackend>,
    file_storage: Arc<FileAuthStorage>,
}

impl AutoAuthStorage {
    fn new(
        codex_home: PathBuf,
        keyring_store: Arc<dyn KeyringStore>,
        keyring_backend_kind: AuthKeyringBackendKind,
    ) -> Self {
        Self {
            keyring_storage: create_keyring_auth_storage(
                codex_home.clone(),
                keyring_store,
                keyring_backend_kind,
            ),
            file_storage: Arc::new(FileAuthStorage::new(codex_home)),
        }
    }

    fn load_reconciled_under_lock(&self) -> std::io::Result<Option<AuthDotJson>> {
        // A successful keyring save removes the fallback file. A present file
        // is therefore newer file-mode/fallback state and must not be shadowed
        // when an old keyring value becomes readable again.
        if let Some(file_auth) = self.file_storage.load()? {
            if let Err(err) = self.keyring_storage.save(&file_auth) {
                warn!("failed to reconcile newer file auth into keyring: {err}");
            }
            return Ok(Some(file_auth));
        }
        match self.keyring_storage.load() {
            Ok(auth) => Ok(auth),
            Err(err) => {
                warn!("failed to load CLI auth from keyring, falling back to file storage: {err}");
                Ok(None)
            }
        }
    }
}

impl AuthStorageBackend for AutoAuthStorage {
    fn load(&self) -> std::io::Result<Option<AuthDotJson>> {
        with_codex_home_lock(self.codex_home(), || self.load_reconciled_under_lock())
    }

    fn save(&self, auth: &AuthDotJson) -> std::io::Result<()> {
        match self.keyring_storage.save(auth) {
            Ok(()) => Ok(()),
            Err(err) => {
                warn!("failed to save auth to keyring, falling back to file storage: {err}");
                self.keyring_storage.delete().map_err(|delete_err| {
                    std::io::Error::other(format!(
                        "failed to save auth to keyring ({err}) and could not remove the stale keyring credential before file fallback: {delete_err}"
                    ))
                })?;
                self.file_storage.save(auth)
            }
        }
    }

    fn delete(&self) -> std::io::Result<bool> {
        // Keyring storage will delete from disk as well
        self.keyring_storage.delete()
    }

    fn codex_home(&self) -> &Path {
        self.file_storage.codex_home()
    }

    fn mutate(
        &self,
        action: &mut dyn FnMut(Option<AuthDotJson>) -> std::io::Result<AuthStorageMutation>,
    ) -> std::io::Result<Option<AuthDotJson>> {
        with_codex_home_lock(self.codex_home(), || {
            let current = self.load_reconciled_under_lock()?;
            let previous_pool_revision = current
                .as_ref()
                .and_then(|auth| auth.managed_chatgpt.as_ref())
                .map(|pool| pool.revision)
                .unwrap_or(0);
            let previous_next_account_revision = current
                .as_ref()
                .and_then(|auth| auth.managed_chatgpt.as_ref())
                .map(|pool| pool.next_account_revision)
                .unwrap_or(0);
            match action(current)? {
                AuthStorageMutation::Save(mut auth) => {
                    prepare_managed_save(
                        &mut auth,
                        previous_pool_revision,
                        previous_next_account_revision,
                    );
                    self.save(&auth)?;
                    Ok(Some(auth))
                }
                AuthStorageMutation::SaveInternalState(auth) => {
                    self.save(&auth)?;
                    Ok(Some(auth))
                }
                AuthStorageMutation::Keep(auth) => Ok(auth),
                AuthStorageMutation::Delete => {
                    self.delete()?;
                    Ok(None)
                }
            }
        })
    }
}

// A global in-memory store for mapping codex_home -> AuthDotJson.
static EPHEMERAL_AUTH_STORE: Lazy<Mutex<HashMap<String, AuthDotJson>>> =
    Lazy::new(|| Mutex::new(HashMap::new()));

static EXTERNAL_CHATGPT_AUTH_STORE: Lazy<Mutex<HashMap<String, AuthDotJson>>> =
    Lazy::new(|| Mutex::new(HashMap::new()));

pub(super) fn load_external_chatgpt_auth(
    codex_home: &Path,
) -> std::io::Result<Option<AuthDotJson>> {
    let key = compute_store_key(codex_home)?;
    EXTERNAL_CHATGPT_AUTH_STORE
        .lock()
        .map_err(|_| std::io::Error::other("failed to lock external ChatGPT auth storage"))
        .map(|store| store.get(&key).cloned())
}

pub(super) fn save_external_chatgpt_auth(
    codex_home: &Path,
    auth: &AuthDotJson,
) -> std::io::Result<()> {
    let key = compute_store_key(codex_home)?;
    EXTERNAL_CHATGPT_AUTH_STORE
        .lock()
        .map_err(|_| std::io::Error::other("failed to lock external ChatGPT auth storage"))?
        .insert(key, auth.clone());
    Ok(())
}

pub(super) fn delete_external_chatgpt_auth(codex_home: &Path) -> std::io::Result<bool> {
    let key = compute_store_key(codex_home)?;
    Ok(EXTERNAL_CHATGPT_AUTH_STORE
        .lock()
        .map_err(|_| std::io::Error::other("failed to lock external ChatGPT auth storage"))?
        .remove(&key)
        .is_some())
}

#[derive(Clone, Debug)]
struct EphemeralAuthStorage {
    codex_home: PathBuf,
}

impl EphemeralAuthStorage {
    fn new(codex_home: PathBuf) -> Self {
        Self { codex_home }
    }

    fn with_store<F, T>(&self, action: F) -> std::io::Result<T>
    where
        F: FnOnce(&mut HashMap<String, AuthDotJson>, String) -> std::io::Result<T>,
    {
        let key = compute_store_key(&self.codex_home)?;
        let mut store = EPHEMERAL_AUTH_STORE
            .lock()
            .map_err(|_| std::io::Error::other("failed to lock ephemeral auth storage"))?;
        action(&mut store, key)
    }
}

impl AuthStorageBackend for EphemeralAuthStorage {
    fn load(&self) -> std::io::Result<Option<AuthDotJson>> {
        self.with_store(|store, key| Ok(store.get(&key).cloned()))
    }

    fn save(&self, auth: &AuthDotJson) -> std::io::Result<()> {
        self.with_store(|store, key| {
            store.insert(key, auth.clone());
            Ok(())
        })
    }

    fn codex_home(&self) -> &Path {
        &self.codex_home
    }

    fn delete(&self) -> std::io::Result<bool> {
        self.with_store(|store, key| Ok(store.remove(&key).is_some()))
    }
    fn delete_locked(&self) -> std::io::Result<bool> {
        self.delete()
    }

    fn mutate(
        &self,
        action: &mut dyn FnMut(Option<AuthDotJson>) -> std::io::Result<AuthStorageMutation>,
    ) -> std::io::Result<Option<AuthDotJson>> {
        self.with_store(|store, key| {
            let current = store.get(&key).cloned();
            let previous_pool_revision = current
                .as_ref()
                .and_then(|auth| auth.managed_chatgpt.as_ref())
                .map(|pool| pool.revision)
                .unwrap_or(0);
            let previous_next_account_revision = current
                .as_ref()
                .and_then(|auth| auth.managed_chatgpt.as_ref())
                .map(|pool| pool.next_account_revision)
                .unwrap_or(0);
            match action(current)? {
                AuthStorageMutation::Save(mut auth) => {
                    prepare_managed_save(
                        &mut auth,
                        previous_pool_revision,
                        previous_next_account_revision,
                    );
                    store.insert(key, auth.clone());
                    Ok(Some(auth))
                }
                AuthStorageMutation::SaveInternalState(auth) => {
                    store.insert(key, auth.clone());
                    Ok(Some(auth))
                }
                AuthStorageMutation::Keep(auth) => Ok(auth),
                AuthStorageMutation::Delete => {
                    store.remove(&key);
                    Ok(None)
                }
            }
        })
    }
}

pub(super) fn create_auth_storage(
    codex_home: PathBuf,
    mode: AuthCredentialsStoreMode,
    keyring_backend_kind: AuthKeyringBackendKind,
) -> Arc<dyn AuthStorageBackend> {
    let keyring_store: Arc<dyn KeyringStore> = Arc::new(DefaultKeyringStore);
    create_auth_storage_with_store(codex_home, mode, keyring_store, keyring_backend_kind)
}

fn create_auth_storage_with_store(
    codex_home: PathBuf,
    mode: AuthCredentialsStoreMode,
    keyring_store: Arc<dyn KeyringStore>,
    keyring_backend_kind: AuthKeyringBackendKind,
) -> Arc<dyn AuthStorageBackend> {
    match mode {
        AuthCredentialsStoreMode::File => Arc::new(FileAuthStorage::new(codex_home)),
        AuthCredentialsStoreMode::Keyring => {
            create_keyring_auth_storage(codex_home, keyring_store, keyring_backend_kind)
        }
        AuthCredentialsStoreMode::Auto => Arc::new(AutoAuthStorage::new(
            codex_home,
            keyring_store,
            keyring_backend_kind,
        )),
        AuthCredentialsStoreMode::Ephemeral => Arc::new(EphemeralAuthStorage::new(codex_home)),
    }
}

fn create_keyring_auth_storage(
    codex_home: PathBuf,
    keyring_store: Arc<dyn KeyringStore>,
    keyring_backend_kind: AuthKeyringBackendKind,
) -> Arc<dyn AuthStorageBackend> {
    match keyring_backend_kind {
        AuthKeyringBackendKind::Direct => {
            Arc::new(DirectKeyringAuthStorage::new(codex_home, keyring_store))
        }
        AuthKeyringBackendKind::Secrets => {
            Arc::new(SecretsKeyringAuthStorage::new(codex_home, keyring_store))
        }
    }
}

#[cfg(test)]
#[path = "storage_tests.rs"]
mod tests;
