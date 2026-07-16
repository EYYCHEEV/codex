use chrono::DateTime;
use chrono::Duration;
use chrono::Utc;
use sha2::Digest;
use sha2::Sha256;

use super::super::storage::AuthDotJson;
use super::super::storage::ManagedChatgptAccount;
use super::super::storage::ManagedChatgptBlock;
use super::super::storage::ManagedChatgptBlockKind;
use super::super::storage::ManagedChatgptLimitKind;
use super::super::storage::ManagedChatgptObservedUsage;
use super::super::storage::ManagedChatgptRateWindow;
use super::super::storage::ManagedChatgptUnavailableObservation;
use super::mutation::credential_revision;
use super::mutation::non_empty;
use super::mutation::row;
use super::types::ManagedChatgptAccountView;
use super::types::ManagedChatgptBlockKindView;
use super::types::ManagedChatgptEligibility;
use super::types::ManagedChatgptFailure;
use super::types::ManagedChatgptRateObservation;
use super::types::ManagedChatgptRateWindowView;
use super::types::ManagedChatgptRefreshStatus;
use super::types::ManagedChatgptSelectionScope;
use super::types::ManagedChatgptStatusObservation;
use super::types::ManagedChatgptTokenObservation;
use super::types::ManagedChatgptTokenState;
use super::types::ManagedChatgptUsageState;
use super::types::ManagedChatgptUsageView;
use super::types::SelectionPins;
use codex_protocol::auth::AuthMode;

const USAGE_FRESHNESS: Duration = Duration::minutes(5);
const DEFAULT_QUOTA_BLOCK: Duration = Duration::seconds(60);

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

pub(in crate::auth) fn views(
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

pub(in crate::auth) fn select<'a>(
    auth: &'a AuthDotJson,
    scope: &ManagedChatgptSelectionScope,
    pins: &SelectionPins,
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

pub(in crate::auth) fn record_status_observation(
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

pub(in crate::auth) fn apply_failure(
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

pub(in crate::auth) fn singular_document(row: &ManagedChatgptAccount) -> AuthDotJson {
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
