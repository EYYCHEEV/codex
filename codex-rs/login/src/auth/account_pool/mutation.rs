use chrono::DateTime;
use chrono::Utc;
use rand::Rng;

use super::super::storage::AuthDotJson;
use super::super::storage::ManagedChatgptAccount;
use super::super::storage::ManagedChatgptBlockKind;
use super::super::storage::ManagedChatgptStorage;
use super::types::ManagedChatgptOauthCredentials;
use crate::token_data::TokenData;
use codex_protocol::auth::AuthMode;

const STORAGE_VERSION: u32 = 1;

pub(in crate::auth) fn normalize_email(email: Option<&str>) -> Option<String> {
    email
        .map(str::trim)
        .filter(|email| !email.is_empty())
        .map(str::to_lowercase)
}

pub(in crate::auth) fn non_empty(value: Option<&str>) -> Option<String> {
    value
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_string)
}

pub(in crate::auth) fn credential_revision(row: &ManagedChatgptAccount) -> u64 {
    if row.credential_revision == 0 {
        row.revision
    } else {
        row.credential_revision
    }
}

pub(in crate::auth) fn allocate_account_revision(pool: &mut ManagedChatgptStorage) -> u64 {
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

pub(in crate::auth) fn validate_document(auth: &AuthDotJson) -> std::io::Result<()> {
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

pub(in crate::auth) fn migrate_document(auth: &mut AuthDotJson, now: DateTime<Utc>) -> bool {
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

pub(in crate::auth) fn upsert(
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
    validate_document(auth)?;
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
    let incoming_canonical =
        canonical_key(email.as_deref(), account_id.as_deref()).ok_or_else(|| {
            std::io::Error::other("managed ChatGPT OAuth credentials have no account identity")
        })?;
    let mut matches = Vec::new();
    if let Some(email) = email.as_deref() {
        matches.extend(
            pool.accounts
                .iter()
                .enumerate()
                .filter(|(_, row)| {
                    row.normalized_email.as_deref() == Some(email)
                        || row.identity_key == incoming_canonical
                        || row.identity_aliases.contains(&incoming_canonical)
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
        if incoming_canonical != row.identity_key
            && !row.identity_aliases.contains(&incoming_canonical)
        {
            row.identity_aliases.push(incoming_canonical.clone());
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
        let identity_key = incoming_canonical;
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

pub(in crate::auth) fn rebind_refreshed_identity(
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

pub(in crate::auth) fn resolve_identity(
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

pub(in crate::auth) fn row<'a>(
    auth: &'a AuthDotJson,
    identity: &str,
) -> Option<&'a ManagedChatgptAccount> {
    auth.managed_chatgpt.as_ref()?.accounts.iter().find(|row| {
        row.identity_key == identity || row.identity_aliases.iter().any(|alias| alias == identity)
    })
}

pub(in crate::auth) fn row_mut<'a>(
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
