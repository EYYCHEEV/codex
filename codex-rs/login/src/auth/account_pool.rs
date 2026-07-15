use chrono::DateTime;
use chrono::Duration;
use chrono::Utc;
use rand::Rng;
use serde::Deserialize;
use serde::Serialize;
use sha2::Digest;
use sha2::Sha256;
use std::collections::HashMap;
use std::sync::Mutex;
use std::sync::atomic::AtomicU64;
use std::sync::atomic::Ordering;

use super::manager::CodexAuth;
use super::storage::AuthDotJson;
use super::storage::ManagedChatgptAccount;
use super::storage::ManagedChatgptBlock;
use super::storage::ManagedChatgptBlockKind;
use super::storage::ManagedChatgptLimitKind;
use super::storage::ManagedChatgptObservedUsage;
use super::storage::ManagedChatgptRateWindow;
use super::storage::ManagedChatgptStorage;
use super::storage::ManagedChatgptTokenUsageSummary;
use super::storage::ManagedChatgptUnavailableObservation;
use crate::token_data::TokenData;
use codex_protocol::auth::AuthMode;

const STORAGE_VERSION: u32 = 1;
const USAGE_FRESHNESS: Duration = Duration::minutes(5);
const DEFAULT_QUOTA_BLOCK: Duration = Duration::seconds(60);

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ManagedChatgptSelectionScope {
    pub thread_id: Option<String>,
    pub session_id: Option<String>,
    pub model: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum ManagedChatgptEligibility {
    Eligible,
    Blocked,
    ForcedWorkspaceDisallowed,
    PendingRemoval,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum ManagedChatgptBlockKindView {
    AuthInvalid,
    Quota,
    Workspace,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ManagedChatgptRateWindowView {
    pub limit_id: String,
    pub kind: ManagedChatgptLimitKind,
    pub remaining_percent: Option<f64>,
    pub reset_at: Option<DateTime<Utc>>,
    pub window_duration_mins: Option<i64>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ManagedChatgptUsageView {
    pub observed_at: DateTime<Utc>,
    pub stale: bool,
    pub token_usage: Option<ManagedChatgptTokenUsageSummary>,
    pub rate_windows: Vec<ManagedChatgptRateWindowView>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum ManagedChatgptUsageState {
    Unknown,
    Fresh,
    Stale,
    Unavailable,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum ManagedChatgptTokenState {
    Available,
    Unavailable,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum ManagedChatgptRefreshStatus {
    Healthy,
    TransientUnavailable {
        observed_at: DateTime<Utc>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        reason_code: Option<String>,
    },
    ReloginRequired {
        observed_at: DateTime<Utc>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        reason_code: Option<String>,
    },
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ManagedChatgptAccountView {
    pub identity_key: String,
    pub identity_aliases: Vec<String>,
    pub normalized_email: Option<String>,
    pub chatgpt_account_id: Option<String>,
    pub revision: u64,
    pub credential_revision: u64,
    pub last_refresh: DateTime<Utc>,
    pub plan: Option<String>,
    pub fedramp: bool,
    pub eligibility: ManagedChatgptEligibility,
    pub block_kind: Option<ManagedChatgptBlockKindView>,
    pub block_reset_at: Option<DateTime<Utc>>,
    pub usage_state: ManagedChatgptUsageState,
    pub token_state: ManagedChatgptTokenState,
    pub refresh_status: ManagedChatgptRefreshStatus,
    pub usage_unavailable_reason: Option<String>,
    pub usage_unavailable_observed_at: Option<DateTime<Utc>>,
    pub token_unavailable_reason: Option<String>,
    pub token_unavailable_observed_at: Option<DateTime<Utc>>,
    pub token_observed_at: DateTime<Utc>,
    pub usage: Option<ManagedChatgptUsageView>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ManagedChatgptAccountList {
    pub accounts: Vec<ManagedChatgptAccountView>,
    pub selected_account_id: Option<String>,
    pub pool_revision: u64,
    pub selection_revision: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ManagedChatgptAvailabilityObservation {
    pub observed_at: DateTime<Utc>,
    pub reason: String,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ManagedChatgptUsageObservation {
    pub observed_at: DateTime<Utc>,
    pub rate_windows: Vec<ManagedChatgptRateWindowView>,
    pub token_usage: Option<ManagedChatgptTokenUsageSummary>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ManagedChatgptStatusObservation {
    pub observed_at: DateTime<Utc>,
    pub rate: ManagedChatgptRateObservation,
    pub token: ManagedChatgptTokenObservation,
}

#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub enum ManagedChatgptRateObservation {
    #[default]
    NotObserved,
    Available(Vec<ManagedChatgptRateWindowView>),
    Unavailable {
        reason: String,
    },
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub enum ManagedChatgptTokenObservation {
    #[default]
    NotObserved,
    Available(ManagedChatgptTokenUsageSummary),
    Unavailable {
        reason: String,
    },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum ManagedChatgptFailure {
    AuthInvalid,
    Quota { reset_at: Option<DateTime<Utc>> },
    WorkspaceQuota { reset_at: Option<DateTime<Utc>> },
    Transport,
    Server,
    TransientRateLimit,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TransportAuthBinding {
    pub identity_key: String,
    pub raw_account_id: Option<String>,
    pub fedramp: bool,
    pub auth_mode: AuthMode,
    pub route_generation: u64,
}

impl TransportAuthBinding {
    /// Builds the secret-free route identity for compatibility and external auth.
    ///
    /// Managed account snapshots carry a stronger binding with monotonic route generation and
    /// must use their captured `transport` value instead.
    pub fn for_nonmanaged_auth(auth: Option<&CodexAuth>) -> Self {
        let auth_mode = auth.map_or(AuthMode::Chatgpt, CodexAuth::api_auth_mode);
        let raw_account_id = auth.and_then(CodexAuth::get_account_id);
        let identity_key = auth
            .and_then(CodexAuth::get_chatgpt_user_id)
            .or_else(|| raw_account_id.clone())
            .unwrap_or_else(|| format!("nonpooled:{auth_mode}"));
        Self {
            identity_key,
            raw_account_id,
            fedramp: auth.is_some_and(CodexAuth::is_fedramp_account),
            auth_mode,
            route_generation: 0,
        }
    }

    /// Stable, secret-free identifier for correlating transport bindings in local diagnostics.
    pub fn diagnostic_fingerprint(&self) -> String {
        let mut digest = Sha256::new();
        for component in [
            self.identity_key.as_bytes(),
            self.raw_account_id.as_deref().unwrap_or("").as_bytes(),
            self.auth_mode.to_string().as_bytes(),
        ] {
            digest.update(component.len().to_be_bytes());
            digest.update(component);
        }
        digest.update([u8::from(self.fedramp)]);
        digest.update(self.route_generation.to_be_bytes());
        let hex = format!("{:x}", digest.finalize());
        format!("bind-{}", &hex[..12])
    }
}

#[derive(Clone, Debug)]
pub struct ManagedChatgptAuthSnapshot {
    pub identity_key: String,
    pub account_revision: u64,
    pub account_state_revision: u64,
    pub auth: CodexAuth,
    pub pool_revision: u64,
    pub selection_revision: u64,
    pub transport: TransportAuthBinding,
}

impl ManagedChatgptAuthSnapshot {
    /// Stable, secret-free identifier for correlating one managed account across failed attempts.
    pub fn diagnostic_account_fingerprint(&self) -> String {
        let digest = Sha256::digest(self.identity_key.as_bytes());
        let hex = format!("{digest:x}");
        format!("acct-{}", &hex[..12])
    }
}

#[derive(Clone, Debug)]
pub enum ManagedChatgptRecoveryDecision {
    Keep(ManagedChatgptAuthSnapshot),
    Rotate(ManagedChatgptAuthSnapshot),
    Stop,
}

#[derive(Clone, Debug)]
pub struct ManagedChatgptOauthCredentials {
    pub tokens: TokenData,
    pub last_refresh: DateTime<Utc>,
    pub oauth_api_key: Option<String>,
}

#[derive(Clone, Debug)]
struct SelectionPin {
    identity: String,
    candidate_signature: u64,
}

#[derive(Debug, Default)]
pub(super) struct SelectionPins {
    pins: Mutex<HashMap<String, SelectionPin>>,
    revision: AtomicU64,
}

impl SelectionPins {
    pub(super) fn clear(&self) {
        if let Ok(mut pins) = self.pins.lock()
            && !pins.is_empty()
        {
            pins.clear();
            self.revision.fetch_add(1, Ordering::Relaxed);
        }
    }

    fn get(&self, key: &str, candidate_signature: u64) -> Option<String> {
        self.pins.lock().ok().and_then(|pins| {
            pins.get(key)
                .filter(|pin| pin.candidate_signature == candidate_signature)
                .map(|pin| pin.identity.clone())
        })
    }

    pub(super) fn revision(&self) -> u64 {
        self.revision.load(Ordering::Relaxed)
    }

    fn insert(&self, key: String, identity: String, candidate_signature: u64) {
        if let Ok(mut pins) = self.pins.lock() {
            let changed = pins.get(&key).is_none_or(|pin| {
                pin.identity != identity || pin.candidate_signature != candidate_signature
            });
            pins.insert(
                key,
                SelectionPin {
                    identity,
                    candidate_signature,
                },
            );
            if changed {
                self.revision.fetch_add(1, Ordering::Relaxed);
            }
        }
    }
}

pub(super) fn normalize_email(email: Option<&str>) -> Option<String> {
    email
        .map(str::trim)
        .filter(|email| !email.is_empty())
        .map(str::to_lowercase)
}

fn non_empty(value: Option<&str>) -> Option<String> {
    value
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_string)
}

pub(super) fn credential_revision(row: &ManagedChatgptAccount) -> u64 {
    if row.credential_revision == 0 {
        row.revision
    } else {
        row.credential_revision
    }
}

pub(super) fn allocate_account_revision(pool: &mut ManagedChatgptStorage) -> u64 {
    let current_max = pool
        .accounts
        .iter()
        .map(|row| row.revision.max(credential_revision(row)))
        .max()
        .unwrap_or(0);
    let revision = pool
        .next_account_revision
        .max(current_max.saturating_add(1))
        .max(1);
    pool.next_account_revision = revision.saturating_add(1);
    revision
}

fn random_key(prefix: &str) -> String {
    let value: u128 = rand::rng().random();
    format!("{prefix}:{value:032x}")
}

pub(super) fn validate_document(auth: &AuthDotJson) -> std::io::Result<()> {
    if let Some(pool) = auth.managed_chatgpt.as_ref()
        && pool.version != STORAGE_VERSION
    {
        return Err(std::io::Error::other(format!(
            "unsupported managed ChatGPT storage version {}",
            pool.version
        )));
    }
    Ok(())
}

fn canonical_key(email: Option<&str>, account_id: Option<&str>) -> Option<String> {
    normalize_email(email)
        .map(|email| format!("email:{email}"))
        .or_else(|| non_empty(account_id).map(|id| format!("account:{id}")))
}

pub(super) fn migrate_document(auth: &mut AuthDotJson, now: DateTime<Utc>) -> bool {
    if auth.managed_chatgpt.is_some() {
        return false;
    }
    let is_singular_chatgpt = auth.tokens.is_some()
        && (matches!(auth.auth_mode, Some(AuthMode::Chatgpt))
            || auth.auth_mode.is_none()
                && auth.openai_api_key.is_none()
                && auth.agent_identity.is_none()
                && auth.personal_access_token.is_none()
                && auth.bedrock_api_key.is_none());
    if !is_singular_chatgpt {
        return false;
    }
    let Some(mut tokens) = auth.tokens.take() else {
        return false;
    };
    let email = normalize_email(tokens.id_token.email.as_deref());
    let account_id = non_empty(
        tokens
            .id_token
            .chatgpt_account_id
            .as_deref()
            .or(tokens.account_id.as_deref()),
    );
    tokens.account_id = account_id.clone();
    let identity_key = canonical_key(email.as_deref(), account_id.as_deref())
        .unwrap_or_else(|| random_key("legacy"));
    let row = ManagedChatgptAccount {
        identity_key,
        identity_aliases: Vec::new(),
        normalized_email: email,
        chatgpt_account_id: account_id,
        tokens,
        revision: 1,
        credential_revision: 1,
        last_refresh: auth.last_refresh.take().unwrap_or(now),
        oauth_api_key: auth.openai_api_key.take(),
        agent_identity: auth.agent_identity.take(),
        mutation_lease: None,
        tombstone: None,
        block: None,
        observed_usage: None,
        token_unavailable: None,
        refresh_failure: None,
    };
    auth.auth_mode = Some(AuthMode::Chatgpt);
    auth.managed_chatgpt = Some(ManagedChatgptStorage {
        version: STORAGE_VERSION,
        revision: 0,
        next_account_revision: 2,
        accounts: vec![row],
    });
    true
}

pub(super) fn upsert(
    auth: &mut AuthDotJson,
    mut credentials: ManagedChatgptOauthCredentials,
    forced_workspace_ids: Option<&[String]>,
) -> std::io::Result<String> {
    if credentials.tokens.access_token.trim().is_empty() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "managed ChatGPT OAuth access token is blank",
        ));
    }
    if credentials.tokens.refresh_token.trim().is_empty() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "managed ChatGPT OAuth refresh token is blank",
        ));
    }
    migrate_document(auth, credentials.last_refresh);
    let email = normalize_email(credentials.tokens.id_token.email.as_deref());
    let account_id = non_empty(
        credentials
            .tokens
            .id_token
            .chatgpt_account_id
            .as_deref()
            .or(credentials.tokens.account_id.as_deref()),
    );
    credentials.tokens.account_id = account_id.clone();
    if email.is_none() && account_id.is_none() {
        return Err(std::io::Error::other(
            "managed ChatGPT OAuth credentials have no account identity",
        ));
    }
    if let Some(allowed) = forced_workspace_ids
        && !account_id
            .as_ref()
            .is_some_and(|id| allowed.iter().any(|allowed_id| allowed_id == id))
    {
        return Err(std::io::Error::other(
            "ChatGPT account is not in an allowed workspace",
        ));
    }

    let pool = auth
        .managed_chatgpt
        .get_or_insert_with(|| ManagedChatgptStorage {
            version: STORAGE_VERSION,
            revision: 0,
            next_account_revision: 1,
            accounts: Vec::new(),
        });
    if pool.version != STORAGE_VERSION {
        return Err(std::io::Error::other(format!(
            "unsupported managed ChatGPT storage version {}",
            pool.version
        )));
    }

    let incoming_canonical = canonical_key(email.as_deref(), account_id.as_deref());
    let mut matches = Vec::new();
    if let Some(email) = email.as_deref() {
        matches.extend(
            pool.accounts
                .iter()
                .enumerate()
                .filter(|(_, row)| {
                    row.normalized_email.as_deref() == Some(email)
                        || incoming_canonical.as_ref().is_some_and(|key| {
                            row.identity_key == *key || row.identity_aliases.contains(key)
                        })
                })
                .map(|(index, _)| index),
        );
        if matches.is_empty()
            && let Some(account_id) = account_id.as_deref()
        {
            matches.extend(
                pool.accounts
                    .iter()
                    .enumerate()
                    .filter(|(_, row)| {
                        row.normalized_email.is_none()
                            && !row.identity_key.starts_with("legacy:")
                            && row.chatgpt_account_id.as_deref() == Some(account_id)
                    })
                    .map(|(index, _)| index),
            );
        }
    } else if let Some(account_id) = account_id.as_deref() {
        matches.extend(
            pool.accounts
                .iter()
                .enumerate()
                .filter(|(_, row)| row.chatgpt_account_id.as_deref() == Some(account_id))
                .map(|(index, _)| index),
        );
        if matches.len() > 1 {
            return Err(std::io::Error::other(
                "managed ChatGPT account ID matches more than one identity",
            ));
        }
    }

    matches.sort_unstable();
    matches.dedup();
    if matches.len() > 1 {
        return Err(std::io::Error::other(
            "managed ChatGPT identity matches more than one account",
        ));
    }
    let identity_key = if let Some(index) = matches.first().copied() {
        if pool.accounts[index].tombstone.is_some()
            || pool.accounts[index]
                .mutation_lease
                .as_ref()
                .is_some_and(|lease| lease.expires_at > Utc::now())
        {
            return Err(std::io::Error::from(std::io::ErrorKind::WouldBlock));
        }
        let revision = allocate_account_revision(pool);
        let row = &mut pool.accounts[index];
        let same_raw_account = row.chatgpt_account_id == account_id;
        let fedramp_changed = row.tokens.id_token.chatgpt_account_is_fedramp
            != credentials.tokens.id_token.chatgpt_account_is_fedramp;
        if let Some(new_alias) = canonical_key(email.as_deref(), account_id.as_deref())
            && new_alias != row.identity_key
            && !row.identity_aliases.contains(&new_alias)
        {
            row.identity_aliases.push(new_alias);
            row.identity_aliases.sort();
        }
        row.token_unavailable = None;
        row.refresh_failure = None;
        if email.is_some() {
            row.normalized_email = email;
        }
        row.chatgpt_account_id = account_id;
        row.tokens = credentials.tokens;
        row.credential_revision = revision;
        row.revision = revision;
        row.last_refresh = credentials.last_refresh;
        row.oauth_api_key = credentials.oauth_api_key;
        row.mutation_lease = None;
        if let Some(block) = row.block.as_mut() {
            block.credential_revision = revision;
        }
        if row.block.as_ref().is_some_and(|block| {
            block.kind == ManagedChatgptBlockKind::AuthInvalid || !same_raw_account
        }) {
            row.block = None;
        }
        if !same_raw_account {
            row.observed_usage = None;
            row.refresh_failure = None;
            row.agent_identity = None;
            row.block = None;
        } else if fedramp_changed {
            row.agent_identity = None;
        }
        row.identity_key.clone()
    } else {
        let identity_key = canonical_key(email.as_deref(), account_id.as_deref())
            .expect("validated managed account identity");
        let revision = allocate_account_revision(pool);
        pool.accounts.push(ManagedChatgptAccount {
            identity_key: identity_key.clone(),
            identity_aliases: Vec::new(),
            normalized_email: email,
            chatgpt_account_id: account_id,
            tokens: credentials.tokens,
            revision,
            credential_revision: revision,
            last_refresh: credentials.last_refresh,
            oauth_api_key: credentials.oauth_api_key,
            agent_identity: None,
            mutation_lease: None,
            tombstone: None,
            block: None,
            observed_usage: None,
            token_unavailable: None,
            refresh_failure: None,
        });
        identity_key
    };
    pool.accounts
        .sort_by(|left, right| left.identity_key.cmp(&right.identity_key));
    auth.auth_mode = Some(AuthMode::Chatgpt);
    auth.openai_api_key = None;
    auth.tokens = None;
    auth.last_refresh = None;
    auth.agent_identity = None;
    auth.personal_access_token = None;
    auth.bedrock_api_key = None;
    Ok(identity_key)
}

pub(super) fn rebind_refreshed_identity(
    auth: &mut AuthDotJson,
    identity: &str,
    mut tokens: TokenData,
    forced_workspace_ids: Option<&[String]>,
) -> std::io::Result<String> {
    let refreshed_email = normalize_email(tokens.id_token.email.as_deref());
    let account_id = non_empty(
        tokens
            .id_token
            .chatgpt_account_id
            .as_deref()
            .or(tokens.account_id.as_deref()),
    );
    if let Some(allowed) = forced_workspace_ids
        && !account_id
            .as_ref()
            .is_some_and(|id| allowed.iter().any(|allowed_id| allowed_id == id))
    {
        return Err(std::io::Error::other(
            "refreshed ChatGPT account is not in an allowed workspace",
        ));
    }
    tokens.account_id = account_id.clone();
    let pool = auth
        .managed_chatgpt
        .as_mut()
        .ok_or_else(|| std::io::Error::other("managed ChatGPT account pool is unavailable"))?;
    let index = pool
        .accounts
        .iter()
        .position(|account| account.identity_key == identity)
        .ok_or_else(|| std::io::Error::other("managed ChatGPT account is unavailable"))?;
    let email = refreshed_email
        .clone()
        .or_else(|| pool.accounts[index].normalized_email.clone());
    let canonical = canonical_key(email.as_deref(), account_id.as_deref());
    let conflicts = pool
        .accounts
        .iter()
        .enumerate()
        .any(|(other_index, account)| {
            other_index != index
                && (canonical.as_ref().is_some_and(|canonical| {
                    account.identity_key == *canonical
                        || account.identity_aliases.contains(canonical)
                }) || email
                    .as_ref()
                    .is_some_and(|email| account.normalized_email.as_ref() == Some(email))
                    || account_id.as_ref().is_some_and(|account_id| {
                        account.chatgpt_account_id.as_ref() == Some(account_id)
                            && (email.is_none() || account.normalized_email.is_none())
                    }))
        });
    if conflicts {
        return Err(std::io::Error::other(
            "refreshed managed ChatGPT identity conflicts with an existing account",
        ));
    }
    let row = &mut pool.accounts[index];
    let raw_changed = row.chatgpt_account_id != account_id;
    let fedramp_changed = row.tokens.id_token.chatgpt_account_is_fedramp
        != tokens.id_token.chatgpt_account_is_fedramp;
    let email_changed = refreshed_email.is_some() && row.normalized_email != refreshed_email;
    if identity.starts_with("legacy:")
        && let Some(canonical) = canonical
    {
        row.identity_aliases.push(row.identity_key.clone());
        row.identity_aliases.sort();
        row.identity_aliases.dedup();
        row.identity_key = canonical;
    } else if let Some(alias) = canonical
        && alias != row.identity_key
        && !row.identity_aliases.contains(&alias)
    {
        row.identity_aliases.push(alias);
        row.identity_aliases.sort();
    }
    if refreshed_email.is_some() {
        row.normalized_email = refreshed_email;
    }
    row.chatgpt_account_id = account_id;
    row.tokens = tokens;
    if raw_changed {
        row.observed_usage = None;
        row.token_unavailable = None;
        row.refresh_failure = None;
        row.block = None;
    }
    if raw_changed || fedramp_changed || email_changed {
        row.agent_identity = None;
    }
    Ok(row.identity_key.clone())
}

pub(super) fn resolve_identity(
    auth: &AuthDotJson,
    selector: &str,
) -> std::io::Result<Option<String>> {
    let Some(pool) = auth.managed_chatgpt.as_ref() else {
        return Ok(None);
    };
    let selector = selector.trim();
    if let Some(account) = pool
        .accounts
        .iter()
        .find(|account| account.identity_key.trim() == selector)
    {
        return Ok(Some(account.identity_key.clone()));
    }
    let normalized = selector.to_lowercase();
    let matches: Vec<_> = pool
        .accounts
        .iter()
        .filter(|account| {
            account.normalized_email.as_deref() == Some(normalized.as_str())
                || account.chatgpt_account_id.as_deref().map(str::trim) == Some(selector)
                || account
                    .identity_aliases
                    .iter()
                    .any(|alias| alias.trim() == selector)
        })
        .collect();
    match matches.as_slice() {
        [] => Ok(None),
        [account] => Ok(Some(account.identity_key.clone())),
        _ => Err(std::io::Error::other(format!(
            "managed ChatGPT account selector {selector:?} is ambiguous"
        ))),
    }
}

pub(super) fn row<'a>(auth: &'a AuthDotJson, identity: &str) -> Option<&'a ManagedChatgptAccount> {
    auth.managed_chatgpt.as_ref()?.accounts.iter().find(|row| {
        row.identity_key == identity || row.identity_aliases.iter().any(|alias| alias == identity)
    })
}

pub(super) fn row_mut<'a>(
    auth: &'a mut AuthDotJson,
    identity: &str,
) -> Option<&'a mut ManagedChatgptAccount> {
    auth.managed_chatgpt
        .as_mut()?
        .accounts
        .iter_mut()
        .find(|row| {
            row.identity_key == identity
                || row.identity_aliases.iter().any(|alias| alias == identity)
        })
}

fn block_is_active(row: &ManagedChatgptAccount, now: DateTime<Utc>) -> bool {
    row.block.as_ref().is_some_and(|block| {
        block.credential_revision == credential_revision(row)
            && block.reset_at.is_none_or(|reset_at| reset_at > now)
    })
}

fn eligibility(
    row: &ManagedChatgptAccount,
    forced_workspace_ids: Option<&[String]>,
    now: DateTime<Utc>,
) -> ManagedChatgptEligibility {
    if row.tombstone.is_some() {
        return ManagedChatgptEligibility::PendingRemoval;
    }
    if let Some(allowed) = forced_workspace_ids
        && !row
            .chatgpt_account_id
            .as_ref()
            .is_some_and(|id| allowed.iter().any(|allowed_id| allowed_id == id))
    {
        return ManagedChatgptEligibility::ForcedWorkspaceDisallowed;
    }
    if block_is_active(row, now) {
        return ManagedChatgptEligibility::Blocked;
    }
    ManagedChatgptEligibility::Eligible
}

pub(super) fn views(
    auth: &AuthDotJson,
    forced_workspace_ids: Option<&[String]>,
    now: DateTime<Utc>,
) -> Vec<ManagedChatgptAccountView> {
    let mut result: Vec<ManagedChatgptAccountView> = auth
        .managed_chatgpt
        .as_ref()
        .map(|pool| {
            pool.accounts
                .iter()
                .map(|row| ManagedChatgptAccountView {
                    identity_key: row.identity_key.clone(),
                    identity_aliases: row.identity_aliases.clone(),
                    normalized_email: row.normalized_email.clone(),
                    chatgpt_account_id: row.chatgpt_account_id.clone(),
                    revision: row.revision,
                    credential_revision: credential_revision(row),
                    last_refresh: row.last_refresh,
                    plan: row.tokens.id_token.get_chatgpt_plan_type_raw(),
                    fedramp: row.tokens.id_token.chatgpt_account_is_fedramp,
                    eligibility: eligibility(row, forced_workspace_ids, now),
                    block_kind: row.block.as_ref().map(|block| match block.kind {
                        ManagedChatgptBlockKind::AuthInvalid => {
                            ManagedChatgptBlockKindView::AuthInvalid
                        }
                        ManagedChatgptBlockKind::Quota => ManagedChatgptBlockKindView::Quota,
                        ManagedChatgptBlockKind::Workspace => {
                            ManagedChatgptBlockKindView::Workspace
                        }
                    }),
                    refresh_status: match row.refresh_failure.as_ref() {
                        Some(failure) if failure.permanent => {
                            ManagedChatgptRefreshStatus::ReloginRequired {
                                observed_at: failure.observed_at,
                                reason_code: failure.reason_code.clone(),
                            }
                        }
                        Some(failure) => ManagedChatgptRefreshStatus::TransientUnavailable {
                            observed_at: failure.observed_at,
                            reason_code: failure.reason_code.clone(),
                        },
                        None => ManagedChatgptRefreshStatus::Healthy,
                    },
                    block_reset_at: row.block.as_ref().and_then(|block| block.reset_at),
                    usage_state: match row.observed_usage.as_ref() {
                        Some(usage) if usage.unavailable.is_some() => {
                            ManagedChatgptUsageState::Unavailable
                        }
                        None => ManagedChatgptUsageState::Unknown,
                        Some(usage)
                            if now.signed_duration_since(usage.observed_at) > USAGE_FRESHNESS =>
                        {
                            ManagedChatgptUsageState::Stale
                        }
                        Some(_) => ManagedChatgptUsageState::Fresh,
                    },
                    token_state: if row.token_unavailable.is_some()
                        || row.block.as_ref().is_some_and(|block| {
                            block.kind == ManagedChatgptBlockKind::AuthInvalid
                                && block_is_active(row, now)
                        }) {
                        ManagedChatgptTokenState::Unavailable
                    } else {
                        ManagedChatgptTokenState::Available
                    },
                    usage_unavailable_reason: row
                        .observed_usage
                        .as_ref()
                        .and_then(|usage| usage.unavailable.as_ref())
                        .map(|unavailable| unavailable.reason.clone()),
                    usage_unavailable_observed_at: row
                        .observed_usage
                        .as_ref()
                        .and_then(|usage| usage.unavailable.as_ref())
                        .map(|unavailable| unavailable.observed_at),
                    token_unavailable_reason: row
                        .token_unavailable
                        .as_ref()
                        .map(|unavailable| unavailable.reason.clone()),
                    token_unavailable_observed_at: row
                        .token_unavailable
                        .as_ref()
                        .map(|unavailable| unavailable.observed_at),
                    token_observed_at: row.last_refresh,
                    usage: row
                        .observed_usage
                        .as_ref()
                        .map(|usage| ManagedChatgptUsageView {
                            observed_at: usage.observed_at,
                            stale: now.signed_duration_since(usage.observed_at) > USAGE_FRESHNESS,
                            token_usage: usage.token_usage.clone(),
                            rate_windows: usage
                                .rate_windows
                                .iter()
                                .map(|window| ManagedChatgptRateWindowView {
                                    limit_id: window.limit_id.clone(),
                                    kind: window.kind,
                                    remaining_percent: window.remaining_percent,
                                    reset_at: window.reset_at,
                                    window_duration_mins: window.window_duration_mins,
                                })
                                .collect(),
                        }),
                })
                .collect()
        })
        .unwrap_or_default();
    result.sort_by(|left, right| left.identity_key.cmp(&right.identity_key));
    result
}

fn selection_key(scope: &ManagedChatgptSelectionScope) -> String {
    fn append_part(key: &mut String, value: Option<&str>) {
        match value {
            Some(value) => {
                key.push('1');
                key.push_str(&value.len().to_string());
                key.push(':');
                key.push_str(value);
            }
            None => key.push_str("0:"),
        }
    }
    let mut key = String::new();
    append_part(&mut key, scope.thread_id.as_deref());
    append_part(&mut key, scope.session_id.as_deref());
    append_part(&mut key, scope.model.as_deref());
    key
}

fn weight(row: &ManagedChatgptAccount, now: DateTime<Utc>) -> u64 {
    let Some(usage) = row.observed_usage.as_ref() else {
        return 100;
    };
    if now.signed_duration_since(usage.observed_at) > USAGE_FRESHNESS {
        return 50;
    }
    let remaining = usage
        .rate_windows
        .iter()
        .filter(|window| {
            window.limit_id == "codex"
                && matches!(
                    window.kind,
                    ManagedChatgptLimitKind::Primary | ManagedChatgptLimitKind::Secondary
                )
        })
        .filter_map(|window| window.remaining_percent)
        .reduce(f64::min);
    remaining
        .map(|remaining| 100 + remaining.clamp(0.0, 100.0).round() as u64)
        .unwrap_or(100)
}

fn candidate_signature(candidates: &[&ManagedChatgptAccount]) -> u64 {
    let mut digest = Sha256::new();
    for row in candidates {
        digest.update(row.identity_key.len().to_be_bytes());
        digest.update(row.identity_key.as_bytes());
    }
    let digest = digest.finalize();
    let mut bytes = [0_u8; 8];
    bytes.copy_from_slice(&digest[..8]);
    u64::from_be_bytes(bytes)
}

pub(super) fn select<'a>(
    auth: &'a AuthDotJson,
    scope: &ManagedChatgptSelectionScope,
    pins: &SelectionPins,
    _pool_revision: u64,
    forced_workspace_ids: Option<&[String]>,
    now: DateTime<Utc>,
) -> Option<&'a ManagedChatgptAccount> {
    let pool = auth.managed_chatgpt.as_ref()?;
    let mut candidates: Vec<_> = pool
        .accounts
        .iter()
        .filter(|row| {
            eligibility(row, forced_workspace_ids, now) == ManagedChatgptEligibility::Eligible
        })
        .collect();
    candidates.sort_by(|left, right| left.identity_key.cmp(&right.identity_key));
    let candidate_signature = candidate_signature(&candidates);
    let scoped = scope.thread_id.is_some() || scope.session_id.is_some() || scope.model.is_some();
    let pin_key = selection_key(scope);
    if scoped
        && let Some(identity) = pins.get(&pin_key, candidate_signature)
        && let Some(pinned) = candidates.iter().find(|row| row.identity_key == identity)
    {
        return Some(*pinned);
    }
    let total: u64 = candidates.iter().map(|row| weight(row, now)).sum();
    if total == 0 {
        return None;
    }
    let digest = Sha256::digest(pin_key.as_bytes());
    let mut ticket_bytes = [0_u8; 8];
    ticket_bytes.copy_from_slice(&digest[..8]);
    let mut ticket = u64::from_be_bytes(ticket_bytes) % total;
    let selected = candidates.into_iter().find(|row| {
        let row_weight = weight(row, now);
        if ticket < row_weight {
            true
        } else {
            ticket -= row_weight;
            false
        }
    })?;
    if scoped {
        pins.insert(pin_key, selected.identity_key.clone(), candidate_signature);
    }
    Some(selected)
}

pub(super) fn record_status_observation(
    row: &mut ManagedChatgptAccount,
    observation: ManagedChatgptStatusObservation,
) -> bool {
    let newest_observation = row
        .observed_usage
        .as_ref()
        .map(|usage| usage.observed_at)
        .into_iter()
        .chain(
            row.observed_usage
                .as_ref()
                .and_then(|usage| usage.unavailable.as_ref())
                .map(|unavailable| unavailable.observed_at),
        )
        .chain(
            row.token_unavailable
                .as_ref()
                .map(|unavailable| unavailable.observed_at),
        )
        .max();
    if newest_observation.is_some_and(|observed_at| observed_at > observation.observed_at) {
        return false;
    }
    let previous_usage = row.observed_usage.clone();
    let previous_token_unavailable = row.token_unavailable.clone();
    match observation.rate {
        ManagedChatgptRateObservation::NotObserved => {}
        ManagedChatgptRateObservation::Available(rate_windows) if rate_windows.is_empty() => {
            let unavailable = ManagedChatgptUnavailableObservation {
                observed_at: observation.observed_at,
                reason: "rate limit usage was absent from the response".to_string(),
            };
            match row.observed_usage.as_mut() {
                Some(usage) => usage.unavailable = Some(unavailable),
                None => {
                    row.observed_usage = Some(ManagedChatgptObservedUsage {
                        observed_at: observation.observed_at,
                        rate_windows: Vec::new(),
                        unavailable: Some(unavailable),
                        token_usage: None,
                    });
                }
            }
        }
        ManagedChatgptRateObservation::Available(rate_windows) => {
            let token_usage = row
                .observed_usage
                .as_ref()
                .and_then(|usage| usage.token_usage.clone());
            row.observed_usage = Some(ManagedChatgptObservedUsage {
                observed_at: observation.observed_at,
                unavailable: None,
                token_usage,
                rate_windows: rate_windows
                    .into_iter()
                    .map(|window| ManagedChatgptRateWindow {
                        limit_id: window.limit_id,
                        kind: window.kind,
                        remaining_percent: window.remaining_percent,
                        reset_at: window.reset_at,
                        window_duration_mins: window.window_duration_mins,
                    })
                    .collect(),
            });
        }
        ManagedChatgptRateObservation::Unavailable { reason } => {
            let unavailable = ManagedChatgptUnavailableObservation {
                observed_at: observation.observed_at,
                reason,
            };
            match row.observed_usage.as_mut() {
                Some(usage) => {
                    usage.unavailable = Some(unavailable);
                }
                None => {
                    row.observed_usage = Some(ManagedChatgptObservedUsage {
                        observed_at: observation.observed_at,
                        rate_windows: Vec::new(),
                        unavailable: Some(unavailable),
                        token_usage: None,
                    });
                }
            }
        }
    }

    match observation.token {
        ManagedChatgptTokenObservation::NotObserved => {}
        ManagedChatgptTokenObservation::Available(token_usage) => {
            match row.observed_usage.as_mut() {
                Some(usage) => {
                    usage.observed_at = observation.observed_at;
                    usage.token_usage = Some(token_usage);
                }
                None => {
                    row.observed_usage = Some(ManagedChatgptObservedUsage {
                        observed_at: observation.observed_at,
                        rate_windows: Vec::new(),
                        unavailable: None,
                        token_usage: Some(token_usage),
                    });
                }
            }
            row.token_unavailable = None;
        }
        ManagedChatgptTokenObservation::Unavailable { reason } => {
            row.token_unavailable = Some(ManagedChatgptUnavailableObservation {
                observed_at: observation.observed_at,
                reason,
            });
        }
    }
    previous_usage != row.observed_usage || previous_token_unavailable != row.token_unavailable
}

pub(super) fn apply_failure(
    auth: &mut AuthDotJson,
    identity: &str,
    expected_revision: u64,
    failure: ManagedChatgptFailure,
    now: DateTime<Utc>,
) -> bool {
    if matches!(
        failure,
        ManagedChatgptFailure::Transport
            | ManagedChatgptFailure::Server
            | ManagedChatgptFailure::TransientRateLimit
    ) {
        return false;
    }
    let Some(selected) = row(auth, identity) else {
        return false;
    };
    if selected.tombstone.is_some() {
        return false;
    }
    if credential_revision(selected) != expected_revision {
        return false;
    }
    let raw_id = selected.chatgpt_account_id.clone();
    let (kind, reset_at, workspace_wide) = match failure {
        ManagedChatgptFailure::AuthInvalid => (ManagedChatgptBlockKind::AuthInvalid, None, false),
        ManagedChatgptFailure::Quota { reset_at } => (
            ManagedChatgptBlockKind::Quota,
            Some(reset_at.unwrap_or(now + DEFAULT_QUOTA_BLOCK)),
            false,
        ),
        ManagedChatgptFailure::WorkspaceQuota { reset_at } => (
            ManagedChatgptBlockKind::Workspace,
            Some(reset_at.unwrap_or(now + DEFAULT_QUOTA_BLOCK)),
            true,
        ),
        ManagedChatgptFailure::Transport
        | ManagedChatgptFailure::Server
        | ManagedChatgptFailure::TransientRateLimit => return false,
    };
    let Some(pool) = auth.managed_chatgpt.as_mut() else {
        return false;
    };
    for row in &mut pool.accounts {
        if row.identity_key == identity
            || workspace_wide && row.chatgpt_account_id == raw_id && raw_id.is_some()
        {
            row.block = Some(ManagedChatgptBlock {
                kind,
                blocked_at: now,
                reset_at,
                credential_revision: credential_revision(row),
            });
            row.revision = row.revision.saturating_add(1);
        }
    }
    true
}

pub(super) fn singular_document(row: &ManagedChatgptAccount) -> AuthDotJson {
    let mut tokens = row.tokens.clone();
    tokens.account_id = non_empty(tokens.id_token.chatgpt_account_id.as_deref())
        .or_else(|| non_empty(tokens.account_id.as_deref()))
        .or_else(|| row.chatgpt_account_id.clone());
    AuthDotJson {
        auth_mode: Some(AuthMode::Chatgpt),
        openai_api_key: row.oauth_api_key.clone(),
        tokens: Some(tokens),
        last_refresh: Some(row.last_refresh),
        agent_identity: row.agent_identity.clone(),
        managed_chatgpt: None,
        personal_access_token: None,
        bedrock_api_key: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::token_data::IdTokenInfo;

    fn empty_document() -> AuthDotJson {
        AuthDotJson {
            auth_mode: None,
            openai_api_key: None,
            tokens: None,
            last_refresh: None,
            agent_identity: None,
            managed_chatgpt: None,
            personal_access_token: None,
            bedrock_api_key: None,
        }
    }

    fn credentials(
        email: Option<&str>,
        account_id: Option<&str>,
        refresh: &str,
        now: DateTime<Utc>,
    ) -> ManagedChatgptOauthCredentials {
        ManagedChatgptOauthCredentials {
            tokens: TokenData {
                id_token: IdTokenInfo {
                    email: email.map(str::to_string),
                    chatgpt_account_id: account_id.map(str::to_string),
                    raw_jwt: "id-token".to_string(),
                    ..Default::default()
                },
                access_token: format!("access-{refresh}"),
                refresh_token: refresh.to_string(),
                account_id: account_id.map(str::to_string),
            },
            last_refresh: now,
            oauth_api_key: None,
        }
    }

    #[test]
    fn upsert_rejects_blank_managed_tokens_without_mutating_document() {
        let now = Utc::now();
        let invalid_tokens = [
            ("", "valid-refresh"),
            (" \t\n", "valid-refresh"),
            ("valid-access", ""),
            ("valid-access", " \t\n"),
        ];

        for (access_token, refresh_token) in invalid_tokens {
            let mut auth = empty_document();
            let before = auth.clone();
            let mut incoming = credentials(Some("a@example.com"), Some("workspace"), "unused", now);
            incoming.tokens.access_token = access_token.to_string();
            incoming.tokens.refresh_token = refresh_token.to_string();

            let error = upsert(&mut auth, incoming, None).expect_err("reject blank token");

            assert_eq!(error.kind(), std::io::ErrorKind::InvalidInput);
            assert_eq!(auth, before);
        }
    }

    #[test]
    fn rejected_managed_token_replacement_preserves_credentials_and_revision() {
        let now = Utc::now();
        let mut auth = empty_document();
        let identity = upsert(
            &mut auth,
            credentials(
                Some("a@example.com"),
                Some("workspace"),
                "initial-refresh",
                now,
            ),
            None,
        )
        .expect("initial account");
        let before = auth.clone();
        let prior = row(&auth, &identity).expect("initial row");
        let prior_tokens = prior.tokens.clone();
        let prior_revision = prior.revision;
        let prior_credential_revision = prior.credential_revision;

        for (access_token, refresh_token) in [
            ("", "replacement-refresh"),
            (" \t\n", "replacement-refresh"),
            ("replacement-access", ""),
            ("replacement-access", " \t\n"),
        ] {
            let mut replacement = credentials(
                Some("a@example.com"),
                Some("workspace"),
                "unused",
                now + Duration::seconds(1),
            );
            replacement.tokens.access_token = access_token.to_string();
            replacement.tokens.refresh_token = refresh_token.to_string();

            let error =
                upsert(&mut auth, replacement, None).expect_err("reject blank replacement token");

            assert_eq!(error.kind(), std::io::ErrorKind::InvalidInput);
            assert_eq!(auth, before);
            let preserved = row(&auth, &identity).expect("preserved row");
            assert_eq!(preserved.tokens, prior_tokens);
            assert_eq!(preserved.revision, prior_revision);
            assert_eq!(preserved.credential_revision, prior_credential_revision);
        }
    }

    #[test]
    fn sequential_upsert_and_relogin_preserve_siblings() {
        let now = Utc::now();
        let mut auth = empty_document();
        let a = upsert(
            &mut auth,
            credentials(Some(" A@Example.com "), Some("wa"), "ra1", now),
            None,
        )
        .expect("first account");
        let b = upsert(
            &mut auth,
            credentials(Some("b@example.com"), Some("wb"), "rb1", now),
            None,
        )
        .expect("second account");
        upsert(
            &mut auth,
            credentials(Some("a@example.com"), Some("wa"), "ra2", now),
            None,
        )
        .expect("relogin");
        let pool = auth.managed_chatgpt.as_ref().expect("pool");
        assert_eq!(pool.accounts.len(), 2);
        assert_eq!(row(&auth, &a).expect("a").tokens.refresh_token, "ra2");
        assert_eq!(row(&auth, &b).expect("b").tokens.refresh_token, "rb1");
        assert_eq!(row(&auth, &a).expect("a").identity_key, a);
    }

    #[test]
    fn opaque_legacy_is_not_absorbed_by_identifiable_login() {
        let now = Utc::now();
        let mut auth = empty_document();
        auth.auth_mode = Some(AuthMode::Chatgpt);
        auth.tokens = Some(credentials(None, None, "legacy-refresh", now).tokens);
        assert!(migrate_document(&mut auth, now));
        let legacy_key = auth.managed_chatgpt.as_ref().unwrap().accounts[0]
            .identity_key
            .clone();
        assert!(legacy_key.starts_with("legacy:"));
        let b = upsert(
            &mut auth,
            credentials(Some("b@example.com"), Some("wb"), "rb", now),
            None,
        )
        .expect("identifiable login");
        assert_eq!(auth.managed_chatgpt.as_ref().unwrap().accounts.len(), 2);
        assert_eq!(
            row(&auth, &legacy_key).unwrap().tokens.refresh_token,
            "legacy-refresh"
        );
        assert_eq!(row(&auth, &b).unwrap().tokens.refresh_token, "rb");
    }

    #[test]
    fn opaque_legacy_refresh_promotes_key_without_duplicating_row() {
        let now = Utc::now();
        let mut auth = empty_document();
        auth.auth_mode = Some(AuthMode::Chatgpt);
        auth.tokens = Some(credentials(None, None, "legacy-refresh", now).tokens);
        assert!(migrate_document(&mut auth, now));
        let legacy_key = auth.managed_chatgpt.as_ref().unwrap().accounts[0]
            .identity_key
            .clone();

        let promoted = rebind_refreshed_identity(
            &mut auth,
            &legacy_key,
            credentials(Some("a@example.com"), Some("wa"), "refreshed", now).tokens,
            None,
        )
        .expect("promote opaque row");

        assert_eq!(promoted, "email:a@example.com");
        let pool = auth.managed_chatgpt.as_ref().expect("pool");
        assert_eq!(pool.accounts.len(), 1);
        assert_eq!(pool.accounts[0].identity_aliases, vec![legacy_key]);
        assert_eq!(pool.accounts[0].tokens.refresh_token, "refreshed");
        assert_eq!(pool.accounts[0].tokens.account_id.as_deref(), Some("wa"));
    }

    #[test]
    fn refreshed_identity_validation_rejects_without_mutation() {
        let now = Utc::now();
        let mut auth = empty_document();
        let identity = upsert(
            &mut auth,
            credentials(Some("a@example.com"), Some("wa"), "initial", now),
            None,
        )
        .expect("initial account");
        let before = auth.clone();

        assert!(
            rebind_refreshed_identity(
                &mut auth,
                &identity,
                credentials(Some("a@example.com"), Some("wb"), "refreshed", now).tokens,
                Some(&["wa".to_string()]),
            )
            .is_err()
        );
        assert_eq!(auth, before);
    }

    #[test]
    fn refreshed_nonlegacy_identity_collision_is_rejected_without_mutation() {
        let now = Utc::now();
        let mut auth = empty_document();
        let a = upsert(
            &mut auth,
            credentials(Some("a@example.com"), Some("wa"), "ra", now),
            None,
        )
        .unwrap();
        upsert(
            &mut auth,
            credentials(Some("b@example.com"), Some("wb"), "rb", now),
            None,
        )
        .unwrap();
        let before = auth.clone();

        let refreshed = credentials(Some("b@example.com"), Some("wb"), "refreshed", now).tokens;
        assert!(rebind_refreshed_identity(&mut auth, &a, refreshed, None).is_err());
        assert_eq!(auth, before);
    }

    #[test]
    fn identityless_oauth_and_forced_workspace_rejection_do_not_mutate() {
        let now = Utc::now();
        let mut auth = empty_document();
        let before = auth.clone();
        assert!(upsert(&mut auth, credentials(None, None, "r", now), None).is_err());
        assert_eq!(auth, before);
        assert!(
            upsert(
                &mut auth,
                credentials(Some("a@example.com"), Some("wa"), "r", now),
                Some(&["allowed".to_string()]),
            )
            .is_err()
        );
        assert_eq!(auth, before);
    }

    #[test]
    fn shared_raw_workspace_is_distinct_by_email_but_raw_only_is_ambiguous() {
        let now = Utc::now();
        let mut auth = empty_document();
        let a = upsert(
            &mut auth,
            credentials(Some("a@example.com"), Some("shared"), "ra", now),
            None,
        )
        .expect("first email identity");
        let b = upsert(
            &mut auth,
            credentials(Some("b@example.com"), Some("shared"), "rb", now),
            None,
        )
        .expect("second email identity");
        assert_ne!(a, b);
        assert_eq!(auth.managed_chatgpt.as_ref().unwrap().accounts.len(), 2);

        let before = auth.clone();
        let error = upsert(
            &mut auth,
            credentials(None, Some("shared"), "raw-only", now),
            None,
        )
        .expect_err("raw-only identity cannot choose between distinct emails");
        assert!(error.to_string().contains("more than one"));
        assert_eq!(auth, before);
    }

    #[test]
    fn status_observation_merges_dimensions_without_erasing_known_data() {
        let now = Utc::now();
        let mut auth = empty_document();
        let identity = upsert(
            &mut auth,
            credentials(Some("a@example.com"), Some("wa"), "r", now),
            None,
        )
        .unwrap();
        let account = row_mut(&mut auth, &identity).unwrap();
        record_status_observation(
            account,
            ManagedChatgptStatusObservation {
                observed_at: now,
                rate: ManagedChatgptRateObservation::Available(vec![
                    ManagedChatgptRateWindowView {
                        limit_id: "codex-primary".to_string(),
                        kind: ManagedChatgptLimitKind::Primary,
                        remaining_percent: Some(80.0),
                        reset_at: None,
                        window_duration_mins: None,
                    },
                ]),
                token: ManagedChatgptTokenObservation::Available(ManagedChatgptTokenUsageSummary {
                    lifetime_tokens: Some(10),
                    peak_daily_tokens: None,
                    longest_running_turn_sec: None,
                    current_streak_days: None,
                    longest_streak_days: None,
                }),
            },
        );
        record_status_observation(
            account,
            ManagedChatgptStatusObservation {
                observed_at: now + Duration::seconds(1),
                rate: ManagedChatgptRateObservation::Unavailable {
                    reason: "rate unavailable".to_string(),
                },
                token: ManagedChatgptTokenObservation::NotObserved,
            },
        );
        let usage = account.observed_usage.as_ref().unwrap();
        assert_eq!(usage.rate_windows.len(), 1);
        assert_eq!(
            usage.token_usage.as_ref().unwrap().lifetime_tokens,
            Some(10)
        );
        record_status_observation(
            account,
            ManagedChatgptStatusObservation {
                observed_at: now + Duration::seconds(2),
                rate: ManagedChatgptRateObservation::NotObserved,
                token: ManagedChatgptTokenObservation::Available(ManagedChatgptTokenUsageSummary {
                    lifetime_tokens: Some(20),
                    peak_daily_tokens: None,
                    longest_running_turn_sec: None,
                    current_streak_days: None,
                    longest_streak_days: None,
                }),
            },
        );
        assert!(account.token_unavailable.is_none());
        assert_eq!(
            account
                .observed_usage
                .as_ref()
                .unwrap()
                .token_usage
                .as_ref()
                .unwrap()
                .lifetime_tokens,
            Some(20)
        );
        assert!(
            account
                .observed_usage
                .as_ref()
                .unwrap()
                .unavailable
                .is_some()
        );
    }

    #[test]
    fn stale_failure_revision_is_rejected_and_workspace_failure_is_scoped() {
        let now = Utc::now();
        let mut auth = empty_document();
        let a = upsert(
            &mut auth,
            credentials(Some("a@example.com"), Some("shared"), "ra", now),
            None,
        )
        .unwrap();
        let b = upsert(
            &mut auth,
            credentials(Some("b@example.com"), Some("shared"), "rb", now),
            None,
        )
        .unwrap();
        let revision = row(&auth, &a).unwrap().revision;
        assert!(!apply_failure(
            &mut auth,
            &a,
            revision - 1,
            ManagedChatgptFailure::AuthInvalid,
            now,
        ));
        assert!(row(&auth, &a).unwrap().block.is_none());
        assert!(apply_failure(
            &mut auth,
            &a,
            revision,
            ManagedChatgptFailure::WorkspaceQuota { reset_at: None },
            now,
        ));
        assert!(row(&auth, &a).unwrap().block.is_some());
        assert!(row(&auth, &b).unwrap().block.is_some());
    }

    #[test]
    fn ranking_is_deterministic_and_ignores_additional_limits() {
        let now = Utc::now();
        let mut auth = empty_document();
        for (email, account, refresh) in
            [("a@example.com", "wa", "ra"), ("b@example.com", "wb", "rb")]
        {
            let identity = upsert(
                &mut auth,
                credentials(Some(email), Some(account), refresh, now),
                None,
            )
            .unwrap();
            row_mut(&mut auth, &identity).unwrap().observed_usage =
                Some(ManagedChatgptObservedUsage {
                    observed_at: now,
                    rate_windows: vec![ManagedChatgptRateWindow {
                        limit_id: "additional".to_string(),
                        kind: ManagedChatgptLimitKind::Additional,
                        remaining_percent: Some(0.0),
                        reset_at: None,
                        window_duration_mins: None,
                    }],
                    unavailable: None,
                    token_usage: None,
                });
        }
        let scope = ManagedChatgptSelectionScope {
            thread_id: Some("thread-1".to_string()),
            session_id: None,
            model: Some("codex".to_string()),
        };
        let first_pins = SelectionPins::default();
        let second_pins = SelectionPins::default();
        let first = select(&auth, &scope, &first_pins, 1, None, now)
            .unwrap()
            .identity_key
            .clone();
        let second = select(&auth, &scope, &second_pins, 1, None, now)
            .unwrap()
            .identity_key
            .clone();
        assert_eq!(first, second);
    }
    #[test]
    fn selection_pin_tracks_candidate_membership_not_pool_or_status_revisions() {
        let now = Utc::now();
        let mut auth = empty_document();
        let a = upsert(
            &mut auth,
            credentials(Some("a@example.com"), Some("wa"), "ra", now),
            None,
        )
        .unwrap();
        let b = upsert(
            &mut auth,
            credentials(Some("b@example.com"), Some("wb"), "rb", now),
            None,
        )
        .unwrap();
        let scope = ManagedChatgptSelectionScope {
            thread_id: Some("stable-thread".to_string()),
            session_id: None,
            model: Some("codex".to_string()),
        };
        let pins = SelectionPins::default();
        select(&auth, &scope, &pins, 1, None, now).expect("initial selection");
        let initial_pin_revision = pins.revision();

        row_mut(&mut auth, &a).unwrap().observed_usage = Some(ManagedChatgptObservedUsage {
            observed_at: now,
            rate_windows: vec![],
            unavailable: Some(ManagedChatgptUnavailableObservation {
                observed_at: now,
                reason: "status-only".to_string(),
            }),
            token_usage: None,
        });
        select(&auth, &scope, &pins, 999, None, now).expect("selection after status write");
        assert_eq!(
            pins.revision(),
            initial_pin_revision,
            "status and unrelated pool revision churn must preserve the pin"
        );

        let c = upsert(
            &mut auth,
            credentials(Some("c@example.com"), Some("wc"), "rc", now),
            None,
        )
        .unwrap();
        select(&auth, &scope, &pins, 1000, None, now).expect("selection after sibling added");
        let after_sibling = pins.revision();
        assert!(after_sibling > initial_pin_revision);

        let c_revision = credential_revision(row(&auth, &c).unwrap());
        assert!(apply_failure(
            &mut auth,
            &c,
            c_revision,
            ManagedChatgptFailure::AuthInvalid,
            now,
        ));
        select(&auth, &scope, &pins, 1001, None, now).expect("selection after sibling blocked");
        let after_block = pins.revision();
        assert!(after_block > after_sibling);

        select(&auth, &scope, &pins, 1002, Some(&["wa".to_string()]), now)
            .expect("selection under workspace policy");
        assert!(pins.revision() > after_block);
        assert!(row(&auth, &b).is_some());
    }

    #[test]
    fn empty_rate_observation_marks_usage_unavailable_without_erasing_usage() {
        let now = Utc::now();
        let mut auth = empty_document();
        let identity = upsert(
            &mut auth,
            credentials(Some("a@example.com"), Some("wa"), "ra", now),
            None,
        )
        .unwrap();
        let account = row_mut(&mut auth, &identity).unwrap();
        record_status_observation(
            account,
            ManagedChatgptStatusObservation {
                observed_at: now,
                rate: ManagedChatgptRateObservation::Available(vec![
                    ManagedChatgptRateWindowView {
                        limit_id: "primary".to_string(),
                        kind: ManagedChatgptLimitKind::Primary,
                        remaining_percent: Some(75.0),
                        reset_at: None,
                        window_duration_mins: None,
                    },
                ]),
                token: ManagedChatgptTokenObservation::Available(ManagedChatgptTokenUsageSummary {
                    lifetime_tokens: Some(42),
                    peak_daily_tokens: None,
                    longest_running_turn_sec: None,
                    current_streak_days: None,
                    longest_streak_days: None,
                }),
            },
        );
        record_status_observation(
            account,
            ManagedChatgptStatusObservation {
                observed_at: now + Duration::seconds(1),
                rate: ManagedChatgptRateObservation::Available(Vec::new()),
                token: ManagedChatgptTokenObservation::NotObserved,
            },
        );
        let usage = account.observed_usage.as_ref().unwrap();
        assert!(usage.unavailable.is_some());
        assert_eq!(usage.rate_windows.len(), 1);
        assert_eq!(
            usage.token_usage.as_ref().unwrap().lifetime_tokens,
            Some(42)
        );

        let mut fresh = empty_document();
        let fresh_identity = upsert(
            &mut fresh,
            credentials(Some("b@example.com"), Some("wb"), "rb", now),
            None,
        )
        .unwrap();
        record_status_observation(
            row_mut(&mut fresh, &fresh_identity).unwrap(),
            ManagedChatgptStatusObservation {
                observed_at: now,
                rate: ManagedChatgptRateObservation::Available(Vec::new()),
                token: ManagedChatgptTokenObservation::NotObserved,
            },
        );
        let view = views(&fresh, None, now).pop().unwrap();
        assert_eq!(view.usage_state, ManagedChatgptUsageState::Unavailable);
    }

    #[test]
    fn unresolved_mode_does_not_migrate_tokens_mixed_with_nonpooled_credentials() {
        use crate::auth::bedrock_api_key::BedrockApiKeyAuth;
        use crate::auth::storage::AgentIdentityStorage;

        let now = Utc::now();
        let template = credentials(Some("stale@example.com"), Some("stale"), "stale", now).tokens;
        let mut documents = Vec::new();
        let mut api_key = empty_document();
        api_key.tokens = Some(template.clone());
        api_key.openai_api_key = Some("api-key".to_string());
        documents.push(api_key);
        let mut pat = empty_document();
        pat.tokens = Some(template.clone());
        pat.personal_access_token = Some("pat".to_string());
        documents.push(pat);
        let mut agent_identity = empty_document();
        agent_identity.tokens = Some(template.clone());
        agent_identity.agent_identity = Some(AgentIdentityStorage::Jwt("jwt".to_string()));
        documents.push(agent_identity);
        let mut bedrock = empty_document();
        bedrock.tokens = Some(template);
        bedrock.bedrock_api_key = Some(BedrockApiKeyAuth {
            api_key: "bedrock".to_string(),
            region: "us-east-1".to_string(),
        });
        documents.push(bedrock);

        for mut document in documents {
            let before = document.clone();
            assert!(!migrate_document(&mut document, now));
            assert_eq!(document, before);
        }
    }

    #[test]
    fn refresh_without_email_preserves_identity_and_agent_binding() {
        use crate::auth::storage::AgentIdentityStorage;

        let now = Utc::now();
        let mut auth = empty_document();
        let identity = upsert(
            &mut auth,
            credentials(Some("kept@example.com"), Some("workspace"), "initial", now),
            None,
        )
        .unwrap();
        row_mut(&mut auth, &identity).unwrap().agent_identity =
            Some(AgentIdentityStorage::Jwt("agent-jwt".to_string()));
        let rebound = rebind_refreshed_identity(
            &mut auth,
            &identity,
            credentials(None, Some("workspace"), "refreshed", now).tokens,
            None,
        )
        .unwrap();
        assert_eq!(rebound, identity);
        let row = row(&auth, &identity).unwrap();
        assert_eq!(row.normalized_email.as_deref(), Some("kept@example.com"));
        assert_eq!(
            row.agent_identity,
            Some(AgentIdentityStorage::Jwt("agent-jwt".to_string()))
        );

        let distinct = upsert(
            &mut auth,
            credentials(
                Some("distinct@example.com"),
                Some("workspace"),
                "distinct",
                now,
            ),
            None,
        )
        .unwrap();
        assert_ne!(distinct, identity);
        assert_eq!(auth.managed_chatgpt.as_ref().unwrap().accounts.len(), 2);
    }
}
