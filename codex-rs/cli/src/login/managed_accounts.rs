use super::load_config_or_exit;
use super::safe_format_key;
use crate::load_cli_auth_projection;
#[path = "managed_accounts_status.rs"]
mod status;

use codex_backend_client::Client as BackendClient;
#[cfg(test)]
use codex_config::types::AuthCredentialsStoreMode;
#[cfg(test)]
use codex_login::AuthKeyringBackendKind;
use codex_login::AuthManager;
use codex_login::CodexAuth;
use codex_login::ManagedChatgptAccountView;
use codex_login::ManagedChatgptLimitKind;
use codex_login::ManagedChatgptRateObservation;
use codex_login::ManagedChatgptRateWindowView;
use codex_login::ManagedChatgptSelectionScope;
use codex_login::ManagedChatgptStatusObservation;
use codex_login::ManagedChatgptTokenObservation;
use codex_protocol::auth::AuthMode;
use codex_protocol::protocol::RateLimitSnapshot;
use codex_utils_cli::CliConfigOverrides;
use status::ResetCreditPresentation;
use status::format_managed_login_status;
#[cfg(test)]
use status::format_managed_login_status_at;
use std::collections::HashMap;
use std::future::Future;
use std::io::BufRead;
use std::io::IsTerminal;
use std::io::Write;
use std::sync::Arc;
use tokio::task::JoinSet;

fn rate_windows_from_backend(
    snapshots: Vec<RateLimitSnapshot>,
) -> Vec<ManagedChatgptRateWindowView> {
    let mut windows = Vec::new();
    for (snapshot_index, snapshot) in snapshots.into_iter().enumerate() {
        let limit_id = snapshot.limit_id.unwrap_or_else(|| "codex".to_string());
        let canonical = snapshot_index == 0 || limit_id == "codex";
        for (kind, suffix, window) in [
            (
                if canonical {
                    ManagedChatgptLimitKind::Primary
                } else {
                    ManagedChatgptLimitKind::Additional
                },
                "primary",
                snapshot.primary,
            ),
            (
                if canonical {
                    ManagedChatgptLimitKind::Secondary
                } else {
                    ManagedChatgptLimitKind::Additional
                },
                "secondary",
                snapshot.secondary,
            ),
        ] {
            let Some(window) = window else {
                continue;
            };
            windows.push(ManagedChatgptRateWindowView {
                limit_id: if canonical {
                    limit_id.clone()
                } else {
                    format!("{limit_id}:{suffix}")
                },
                kind,
                remaining_percent: Some((100.0 - window.used_percent).clamp(0.0, 100.0)),
                window_duration_mins: window.window_minutes,
                reset_at: window
                    .resets_at
                    .and_then(|timestamp| chrono::DateTime::from_timestamp(timestamp, 0)),
            });
        }
    }
    windows
}

struct ManagedStatusFetch {
    identity: String,
    credential_revision: u64,
    state_revision: u64,
    observation: ManagedChatgptStatusObservation,
    reset_credits: Option<ResetCreditPresentation>,
}

async fn run_bounded<I, F, Fut, T>(items: I, limit: usize, mut task: F) -> Vec<T>
where
    I: IntoIterator,
    I::Item: Send + 'static,
    F: FnMut(I::Item) -> Fut,
    Fut: Future<Output = T> + Send + 'static,
    T: Send + 'static,
{
    let mut items = items.into_iter().enumerate();
    let mut tasks = JoinSet::new();
    for _ in 0..limit.max(1) {
        let Some((index, item)) = items.next() else {
            break;
        };
        let future = task(item);
        tasks.spawn(async move { (index, future.await) });
    }

    let mut completed = Vec::new();
    while let Some(result) = tasks.join_next().await {
        if let Ok(result) = result {
            completed.push(result);
        }
        if let Some((index, item)) = items.next() {
            let future = task(item);
            tasks.spawn(async move { (index, future.await) });
        }
    }
    completed.sort_by_key(|(index, _)| *index);
    completed.into_iter().map(|(_, value)| value).collect()
}

async fn fetch_managed_login_status_account(
    auth_manager: Arc<AuthManager>,
    chatgpt_base_url: &str,
    http_client_factory: codex_http_client::HttpClientFactory,
    account: ManagedChatgptAccountView,
) -> Option<ManagedStatusFetch> {
    const FETCH_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);
    let snapshot = match auth_manager
        .refresh_managed_chatgpt_account_bounded(&account.identity_key, FETCH_TIMEOUT)
        .await
    {
        Ok(snapshot) => snapshot,
        Err(_) => {
            let snapshot = auth_manager
                .managed_chatgpt_auth_snapshot_for_identity(&account.identity_key)
                .await
                .ok()
                .flatten()?;
            return Some(ManagedStatusFetch {
                identity: snapshot.identity_key,
                credential_revision: snapshot.account_revision,
                state_revision: snapshot.account_state_revision,
                observation: ManagedChatgptStatusObservation {
                    observed_at: chrono::Utc::now(),
                    rate: ManagedChatgptRateObservation::Unavailable {
                        reason: "managed token refresh failed".to_string(),
                    },
                    token: ManagedChatgptTokenObservation::NotObserved,
                },
                reset_credits: None,
            });
        }
    };
    let identity = snapshot.identity_key.clone();
    let client = BackendClient::from_auth(
        chatgpt_base_url.to_string(),
        &snapshot.auth,
        http_client_factory,
    );

    let (rate, reset_credits) = match tokio::time::timeout(
        FETCH_TIMEOUT,
        client.get_rate_limits_with_reset_credits(),
    )
    .await
    {
        Ok(Ok(response)) => {
            let windows = rate_windows_from_backend(response.rate_limits);
            let rate = if windows.is_empty() {
                ManagedChatgptRateObservation::Unavailable {
                    reason: "rate limit usage unavailable".to_string(),
                }
            } else {
                ManagedChatgptRateObservation::Available(windows)
            };
            let reset_credits =
                response
                    .rate_limit_reset_credits
                    .map(|summary| ResetCreditPresentation {
                        available_count: summary.available_count.max(0),
                        soonest_expiry: None,
                    });
            let reset_credits = if reset_credits
                .as_ref()
                .is_some_and(|summary| summary.available_count > 0)
            {
                match tokio::time::timeout(FETCH_TIMEOUT, client.list_rate_limit_reset_credits())
                    .await
                {
                    Ok(Ok(details)) => Some(ResetCreditPresentation {
                        available_count: reset_credits
                            .as_ref()
                            .map_or(0, |summary| summary.available_count),
                        soonest_expiry: details
                            .credits
                            .iter()
                            .filter(|credit| credit.status.eq_ignore_ascii_case("available"))
                            .filter_map(|credit| credit.expires_at.as_deref())
                            .filter_map(|expiry| chrono::DateTime::parse_from_rfc3339(expiry).ok())
                            .map(|expiry| expiry.with_timezone(&chrono::Utc))
                            .min(),
                    }),
                    Ok(Err(_)) | Err(_) => reset_credits,
                }
            } else {
                reset_credits
            };
            (rate, reset_credits)
        }
        Ok(Err(_)) | Err(_) => (
            ManagedChatgptRateObservation::Unavailable {
                reason: "rate limit usage unavailable".to_string(),
            },
            None,
        ),
    };

    Some(ManagedStatusFetch {
        identity,
        credential_revision: snapshot.account_revision,
        state_revision: snapshot.account_state_revision,
        observation: ManagedChatgptStatusObservation {
            observed_at: chrono::Utc::now(),
            rate,
            token: ManagedChatgptTokenObservation::NotObserved,
        },
        reset_credits,
    })
}

async fn refresh_managed_login_status(
    auth_manager: Arc<AuthManager>,
    chatgpt_base_url: &str,
    http_client_factory: codex_http_client::HttpClientFactory,
    accounts: &[ManagedChatgptAccountView],
) -> HashMap<String, ResetCreditPresentation> {
    const CONCURRENCY_LIMIT: usize = 3;
    let base_url = chatgpt_base_url.to_string();
    let task_auth_manager = Arc::clone(&auth_manager);
    let fetched = run_bounded(accounts.to_vec(), CONCURRENCY_LIMIT, move |account| {
        let auth_manager = Arc::clone(&task_auth_manager);
        let base_url = base_url.clone();
        let http_client_factory = http_client_factory.clone();
        async move {
            fetch_managed_login_status_account(
                auth_manager,
                &base_url,
                http_client_factory,
                account,
            )
            .await
        }
    })
    .await;
    let mut reset_credits = HashMap::new();
    for fetch in fetched.into_iter().flatten() {
        if let Ok(Some(updated)) = auth_manager.record_managed_chatgpt_status_observation(
            &fetch.identity,
            fetch.credential_revision,
            fetch.state_revision,
            fetch.observation,
        ) && let Some(summary) = fetch.reset_credits
        {
            reset_credits.insert(updated.identity_key, summary);
        }
    }
    reset_credits
}

fn is_managed_api_auth_mode(mode: AuthMode) -> bool {
    mode == AuthMode::Chatgpt
}

fn non_pooled_login_status(auth: &CodexAuth) -> Result<String, String> {
    match auth.auth_mode() {
        AuthMode::ApiKey => auth
            .get_token()
            .map(|api_key| format!("Logged in using an API key - {}", safe_format_key(&api_key)))
            .map_err(|err| format!("Unexpected error retrieving API key: {err}")),
        AuthMode::Chatgpt | AuthMode::ChatgptAuthTokens => {
            let tokens = auth
                .get_token_data()
                .map_err(|err| format!("Unexpected error retrieving ChatGPT credentials: {err}"))?;
            if tokens.access_token.trim().is_empty() {
                return Err("ChatGPT credentials are incomplete: access token is empty".to_string());
            }
            if matches!(auth, CodexAuth::Chatgpt(_)) && tokens.refresh_token.trim().is_empty() {
                return Err(
                    "ChatGPT credentials are incomplete: refresh token is empty".to_string()
                );
            }
            if matches!(auth, CodexAuth::ChatgptAuthTokens(_))
                && tokens
                    .account_id
                    .as_deref()
                    .is_none_or(|account_id| account_id.trim().is_empty())
            {
                return Err("ChatGPT credentials are incomplete: account id is empty".to_string());
            }
            Ok("Logged in using ChatGPT".to_string())
        }
        AuthMode::Headers => unreachable!("header auth cannot be loaded from auth storage"),
        AuthMode::AgentIdentity => Ok("Logged in using access token".to_string()),
        AuthMode::PersonalAccessToken => Ok("Logged in using personal access token".to_string()),
        AuthMode::BedrockApiKey => Ok("Logged in using Amazon Bedrock API key".to_string()),
    }
}

fn singular_login_status(
    auth_manager: &AuthManager,
    effective_auth: Option<&CodexAuth>,
) -> Option<Result<String, String>> {
    let auth = effective_auth?;
    (auth_manager.is_external_chatgpt_auth_active()
        || !is_managed_api_auth_mode(auth.api_auth_mode()))
    .then(|| non_pooled_login_status(auth))
}

pub async fn run_login_status(cli_config_overrides: CliConfigOverrides) -> ! {
    let config = load_config_or_exit(cli_config_overrides).await;
    let auth_projection = load_cli_auth_projection(&config).await;
    let effective_auth = match auth_projection.effective_auth() {
        Ok(auth) => auth,
        Err(err) => {
            eprintln!("Error checking login status: {err}");
            std::process::exit(1);
        }
    };
    let auth_manager = auth_projection.auth_manager.as_ref();
    if let Some(status) = singular_login_status(auth_manager, effective_auth) {
        match status {
            Ok(status) => {
                if auth_manager.is_external_chatgpt_auth_active()
                    && let Ok(accounts) = auth_manager.stored_managed_chatgpt_accounts()
                    && !accounts.is_empty()
                {
                    println!("{status}");
                    println!(
                        "External ChatGPT auth is active; preserved managed accounts are inactive."
                    );
                    print!(
                        "{}",
                        format_managed_login_status(&accounts, None, &HashMap::new())
                    );
                } else {
                    eprintln!("{status}");
                }
                std::process::exit(0);
            }
            Err(err) => {
                eprintln!("{err}");
                std::process::exit(1);
            }
        }
    }
    let scope = ManagedChatgptSelectionScope::default();
    let managed = match auth_manager.list_managed_chatgpt_accounts(&scope).await {
        Ok(managed) => managed,
        Err(err) => {
            eprintln!("Error checking login status: {err}");
            std::process::exit(1);
        }
    };
    if !managed.accounts.is_empty() {
        let reset_credits = refresh_managed_login_status(
            Arc::clone(&auth_projection.auth_manager),
            &config.chatgpt_base_url,
            config.http_client_factory(),
            &managed.accounts,
        )
        .await;
        let refreshed = auth_manager
            .list_managed_chatgpt_accounts(&scope)
            .await
            .unwrap_or(managed);
        print!(
            "{}",
            format_managed_login_status(
                &refreshed.accounts,
                refreshed.selected_account_id.as_deref(),
                &reset_credits,
            )
        );
        std::process::exit(0);
    }

    match auth_manager.auth().await {
        Some(auth) => match non_pooled_login_status(&auth) {
            Ok(status) => {
                eprintln!("{status}");
                std::process::exit(0);
            }
            Err(err) => {
                eprintln!("{err}");
                std::process::exit(1);
            }
        },
        None => {
            eprintln!("Not logged in");
            std::process::exit(1);
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
enum UnscopedLogoutTarget {
    Legacy,
    Managed(String),
    Cancelled,
}

const AMBIGUOUS_LOGOUT_GUIDANCE: &str = "Multiple managed ChatGPT accounts are logged in; rerun with `codex logout --account <identity>` or `codex logout --all`.";

fn pick_logout_account(
    accounts: &[ManagedChatgptAccountView],
    input: &mut dyn BufRead,
    prompt: &mut dyn Write,
) -> std::io::Result<Option<String>> {
    writeln!(prompt, "Choose a ChatGPT account to log out:")?;
    for (index, account) in accounts.iter().enumerate() {
        let label = account
            .normalized_email
            .as_deref()
            .or(account.chatgpt_account_id.as_deref())
            .unwrap_or(&account.identity_key);
        writeln!(
            prompt,
            "  {}. {} ({})",
            index + 1,
            label,
            account.identity_key
        )?;
    }
    write!(prompt, "Account number (or q to cancel): ")?;
    prompt.flush()?;

    let mut answer = String::new();
    if input.read_line(&mut answer)? == 0 {
        return Ok(None);
    }
    let answer = answer.trim();
    if answer.is_empty() || answer.eq_ignore_ascii_case("q") {
        return Ok(None);
    }
    let choice = answer.parse::<usize>().map_err(|_| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "invalid account selection; enter a listed number or q",
        )
    })?;
    let account = choice
        .checked_sub(1)
        .and_then(|index| accounts.get(index))
        .ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "invalid account selection; enter a listed number or q",
            )
        })?;
    Ok(Some(account.identity_key.clone()))
}

fn select_unscoped_logout_target(
    accounts: &[ManagedChatgptAccountView],
    interactive_terminal: bool,
    input: &mut dyn BufRead,
    prompt: &mut dyn Write,
) -> std::io::Result<UnscopedLogoutTarget> {
    match accounts {
        [] => Ok(UnscopedLogoutTarget::Legacy),
        [account] => Ok(UnscopedLogoutTarget::Managed(account.identity_key.clone())),
        _ if !interactive_terminal => Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            AMBIGUOUS_LOGOUT_GUIDANCE,
        )),
        _ => Ok(match pick_logout_account(accounts, input, prompt)? {
            Some(identity) => UnscopedLogoutTarget::Managed(identity),
            None => UnscopedLogoutTarget::Cancelled,
        }),
    }
}

async fn select_persistent_unscoped_logout_target(
    auth_manager: &AuthManager,
    interactive_terminal: bool,
    input: &mut dyn BufRead,
    prompt: &mut dyn Write,
) -> std::io::Result<UnscopedLogoutTarget> {
    let accounts = auth_manager
        .list_managed_chatgpt_accounts(&ManagedChatgptSelectionScope::default())
        .await?
        .accounts;
    select_unscoped_logout_target(&accounts, interactive_terminal, input, prompt)
}

async fn logout_all_auth(auth_manager: &AuthManager) -> std::io::Result<bool> {
    let mut removed_any = false;
    if auth_manager.is_external_chatgpt_auth_active() {
        removed_any |= auth_manager.logout_with_revoke().await?;
    }

    removed_any |= !auth_manager.logout_all_managed_chatgpt().await?.is_empty();

    // Removing an external overlay or the managed pool can reveal credentials
    // from the persistent store. Recompute from the reloaded cache rather than
    // relying on the auth mode that was visible when logout-all started.
    auth_manager.reload().await;
    if auth_manager.auth_cached().is_some() {
        removed_any |= auth_manager.logout_with_revoke().await?;
    }
    Ok(removed_any)
}

pub async fn run_logout(
    cli_config_overrides: CliConfigOverrides,
    account: Option<String>,
    all: bool,
) -> ! {
    let config = load_config_or_exit(cli_config_overrides).await;
    let auth_manager =
        AuthManager::shared_from_config(&config, /*enable_codex_api_key_env*/ false).await;
    let result = async {
        if all {
            return logout_all_auth(auth_manager.as_ref()).await;
        }
        if let Some(identity) = account {
            return auth_manager.remove_managed_chatgpt_account(&identity).await;
        }
        let stdin = std::io::stdin();
        let stderr = std::io::stderr();
        let interactive_terminal = stdin.is_terminal() && stderr.is_terminal();
        let mut input = stdin.lock();
        let mut prompt = stderr.lock();
        match select_persistent_unscoped_logout_target(
            auth_manager.as_ref(),
            interactive_terminal,
            &mut input,
            &mut prompt,
        )
        .await?
        {
            UnscopedLogoutTarget::Legacy => auth_manager.logout_with_revoke().await,
            UnscopedLogoutTarget::Managed(identity) => {
                auth_manager.remove_managed_chatgpt_account(&identity).await
            }
            UnscopedLogoutTarget::Cancelled => {
                eprintln!("Logout cancelled");
                std::process::exit(0);
            }
        }
    }
    .await;

    match result {
        Ok(true) => {
            eprintln!("Successfully logged out");
            std::process::exit(0);
        }
        Ok(false) => {
            eprintln!("Not logged in");
            std::process::exit(0);
        }
        Err(err) => {
            eprintln!("Error logging out: {err}");
            std::process::exit(1);
        }
    }
}

#[cfg(test)]
#[path = "managed_accounts_tests.rs"]
mod tests;
