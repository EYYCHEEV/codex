use chrono::DateTime;
use chrono::Utc;
use serde::Deserialize;
use serde::Serialize;
use sha2::Digest;
use sha2::Sha256;
use std::collections::HashMap;
use std::sync::Mutex;
use std::sync::atomic::AtomicU64;
use std::sync::atomic::Ordering;

use super::super::manager::CodexAuth;
use super::super::storage::ManagedChatgptLimitKind;
use super::super::storage::ManagedChatgptTokenUsageSummary;
use crate::token_data::TokenData;
use codex_protocol::auth::AuthMode;

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
pub(in crate::auth) struct SelectionPins {
    pins: Mutex<HashMap<String, SelectionPin>>,
    revision: AtomicU64,
}

impl SelectionPins {
    pub(in crate::auth) fn clear(&self) {
        if let Ok(mut pins) = self.pins.lock()
            && !pins.is_empty()
        {
            pins.clear();
            self.revision.fetch_add(1, Ordering::Relaxed);
        }
    }

    pub(in crate::auth) fn get(&self, key: &str, candidate_signature: u64) -> Option<String> {
        self.pins.lock().ok().and_then(|pins| {
            pins.get(key)
                .filter(|pin| pin.candidate_signature == candidate_signature)
                .map(|pin| pin.identity.clone())
        })
    }

    pub(in crate::auth) fn revision(&self) -> u64 {
        self.revision.load(Ordering::Relaxed)
    }

    pub(in crate::auth) fn insert(&self, key: String, identity: String, candidate_signature: u64) {
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
