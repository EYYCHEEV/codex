use super::load_config_or_exit;
use super::safe_format_key;
use crate::load_cli_auth_projection;
use codex_backend_client::Client as BackendClient;
use codex_backend_client::TokenUsageProfile;
#[cfg(test)]
use codex_config::types::AuthCredentialsStoreMode;
#[cfg(test)]
use codex_login::AuthKeyringBackendKind;
use codex_login::AuthManager;
use codex_login::CodexAuth;
use codex_login::ManagedChatgptAccountView;
use codex_login::ManagedChatgptBlockKindView;
use codex_login::ManagedChatgptEligibility;
use codex_login::ManagedChatgptLimitKind;
use codex_login::ManagedChatgptRateObservation;
use codex_login::ManagedChatgptRateWindowView;
use codex_login::ManagedChatgptSelectionScope;
use codex_login::ManagedChatgptStatusObservation;
use codex_login::ManagedChatgptTokenObservation;
use codex_login::ManagedChatgptTokenState;
use codex_login::ManagedChatgptTokenUsageSummary;
use codex_login::ManagedChatgptUsageState;
use codex_protocol::auth::AuthMode;
use codex_protocol::protocol::RateLimitSnapshot;
use codex_utils_cli::CliConfigOverrides;
use std::io::BufRead;
use std::io::IsTerminal;
use std::io::Write;

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

fn token_usage_summary(profile: &TokenUsageProfile) -> ManagedChatgptTokenUsageSummary {
    ManagedChatgptTokenUsageSummary {
        lifetime_tokens: profile.stats.lifetime_tokens,
        peak_daily_tokens: profile.stats.peak_daily_tokens,
        longest_running_turn_sec: profile.stats.longest_running_turn_sec,
        current_streak_days: profile.stats.current_streak_days,
        longest_streak_days: profile.stats.longest_streak_days,
    }
}

async fn refresh_managed_login_status(
    auth_manager: &AuthManager,
    chatgpt_base_url: &str,
    accounts: &[ManagedChatgptAccountView],
) {
    const FETCH_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);
    for account in accounts {
        let snapshot = match auth_manager
            .refresh_managed_chatgpt_account_bounded(&account.identity_key, FETCH_TIMEOUT)
            .await
        {
            Ok(snapshot) => snapshot,
            Err(_) => {
                let current_revisions = auth_manager
                    .managed_chatgpt_auth_snapshot_for_identity(&account.identity_key)
                    .await
                    .ok()
                    .flatten()
                    .map(|snapshot| (snapshot.account_revision, snapshot.account_state_revision));
                if let Some((credential_revision, state_revision)) = current_revisions {
                    let _ = auth_manager.record_managed_chatgpt_status_observation(
                        &account.identity_key,
                        credential_revision,
                        state_revision,
                        ManagedChatgptStatusObservation {
                            observed_at: chrono::Utc::now(),
                            rate: ManagedChatgptRateObservation::Unavailable {
                                reason: "managed token refresh failed".to_string(),
                            },
                            token: ManagedChatgptTokenObservation::Unavailable {
                                reason: "managed token refresh failed".to_string(),
                            },
                        },
                    );
                }
                continue;
            }
        };
        let identity = snapshot.identity_key.clone();
        let client = match BackendClient::from_auth(chatgpt_base_url.to_string(), &snapshot.auth) {
            Ok(client) => client,
            Err(_) => {
                let _ = auth_manager.record_managed_chatgpt_status_observation(
                    &identity,
                    snapshot.account_revision,
                    snapshot.account_state_revision,
                    ManagedChatgptStatusObservation {
                        observed_at: chrono::Utc::now(),
                        rate: ManagedChatgptRateObservation::Unavailable {
                            reason: "backend client unavailable".to_string(),
                        },
                        token: ManagedChatgptTokenObservation::Unavailable {
                            reason: "backend client unavailable".to_string(),
                        },
                    },
                );
                continue;
            }
        };

        let rate = match tokio::time::timeout(FETCH_TIMEOUT, client.get_rate_limits_many()).await {
            Ok(Ok(snapshots)) => {
                let windows = rate_windows_from_backend(snapshots);
                if windows.is_empty() {
                    ManagedChatgptRateObservation::Unavailable {
                        reason: "rate limit usage unavailable".to_string(),
                    }
                } else {
                    ManagedChatgptRateObservation::Available(windows)
                }
            }
            Ok(Err(_)) | Err(_) => ManagedChatgptRateObservation::Unavailable {
                reason: "rate limit usage unavailable".to_string(),
            },
        };

        let token =
            match tokio::time::timeout(FETCH_TIMEOUT, client.get_token_usage_profile()).await {
                Ok(Ok(profile)) => {
                    ManagedChatgptTokenObservation::Available(token_usage_summary(&profile))
                }
                Ok(Err(_)) | Err(_) => ManagedChatgptTokenObservation::Unavailable {
                    reason: "token usage unavailable".to_string(),
                },
            };

        let _ = auth_manager.record_managed_chatgpt_status_observation(
            &identity,
            snapshot.account_revision,
            snapshot.account_state_revision,
            ManagedChatgptStatusObservation {
                observed_at: chrono::Utc::now(),
                rate,
                token,
            },
        );
    }
}

fn format_managed_login_status(
    accounts: &[ManagedChatgptAccountView],
    selected_account_id: Option<&str>,
) -> String {
    let mut output = String::from("Logged in using managed ChatGPT accounts\n");
    for account in accounts {
        let marker = if selected_account_id == Some(account.identity_key.as_str()) {
            "*"
        } else {
            " "
        };
        let label = account
            .normalized_email
            .as_deref()
            .or(account.chatgpt_account_id.as_deref())
            .unwrap_or(&account.identity_key);
        output.push_str(&format!("{marker} {label} ({})\n", account.identity_key));
        output.push_str(&format!(
            "  account: {}\n",
            account.chatgpt_account_id.as_deref().unwrap_or("unknown")
        ));
        output.push_str(&format!(
            "  plan: {}\n",
            account.plan.as_deref().unwrap_or("unknown")
        ));
        let (eligibility, block) = match &account.eligibility {
            ManagedChatgptEligibility::Eligible => ("eligible", "none".to_string()),
            ManagedChatgptEligibility::Blocked => {
                let kind = match account.block_kind {
                    Some(ManagedChatgptBlockKindView::AuthInvalid) => "auth invalid",
                    Some(ManagedChatgptBlockKindView::Quota) => "quota",
                    Some(ManagedChatgptBlockKindView::Workspace) => "workspace quota",
                    None => "active",
                };
                let reset = account
                    .block_reset_at
                    .map(|reset| format!(", resets {}", reset.to_rfc3339()))
                    .unwrap_or_default();
                ("ineligible: blocked", format!("{kind}{reset}"))
            }
            ManagedChatgptEligibility::ForcedWorkspaceDisallowed => {
                ("ineligible: workspace not allowed", "none".to_string())
            }
            ManagedChatgptEligibility::PendingRemoval => {
                ("ineligible: pending removal", "pending removal".to_string())
            }
        };
        output.push_str(&format!("  eligibility: {eligibility}\n"));
        output.push_str(&format!("  block: {block}\n"));
        let refresh_unavailable = match account.refresh_status {
            codex_login::ManagedChatgptRefreshStatus::Healthy => {
                output.push_str("  refresh: healthy\n");
                false
            }
            codex_login::ManagedChatgptRefreshStatus::TransientUnavailable {
                observed_at, ..
            } => {
                output.push_str(&format!(
                    "  refresh: temporarily unavailable, observed {}\n",
                    observed_at.to_rfc3339()
                ));
                true
            }
            codex_login::ManagedChatgptRefreshStatus::ReloginRequired { observed_at, .. } => {
                output.push_str(&format!(
                    "  refresh: relogin required, observed {}\n",
                    observed_at.to_rfc3339()
                ));
                true
            }
        };

        let usage_label = match account.usage_state {
            ManagedChatgptUsageState::Unknown if refresh_unavailable => "unavailable",
            ManagedChatgptUsageState::Unknown => "unknown",
            ManagedChatgptUsageState::Fresh if refresh_unavailable => "fresh (refresh unavailable)",
            ManagedChatgptUsageState::Fresh => "fresh",
            ManagedChatgptUsageState::Stale if refresh_unavailable => "stale (refresh unavailable)",
            ManagedChatgptUsageState::Stale => "stale",
            ManagedChatgptUsageState::Unavailable
                if account
                    .usage
                    .as_ref()
                    .is_some_and(|usage| usage.stale && !usage.rate_windows.is_empty()) =>
            {
                "stale (refresh unavailable)"
            }
            ManagedChatgptUsageState::Unavailable
                if account
                    .usage
                    .as_ref()
                    .is_some_and(|usage| !usage.rate_windows.is_empty()) =>
            {
                "fresh (refresh unavailable)"
            }
            ManagedChatgptUsageState::Unavailable => "unavailable",
        };
        if let Some(usage) = account
            .usage
            .as_ref()
            .filter(|usage| !usage.rate_windows.is_empty() || usage.token_usage.is_some())
        {
            output.push_str(&format!("  observed: {}\n", usage.observed_at.to_rfc3339()));
        }
        output.push_str(&format!("  usage: {usage_label}\n"));
        if let Some(observed_at) = account.usage_unavailable_observed_at {
            output.push_str(&format!(
                "  usage unavailable observed: {}\n",
                observed_at.to_rfc3339()
            ));
        }
        if let Some(reason) = &account.usage_unavailable_reason {
            output.push_str(&format!("  usage unavailable reason: {reason}\n"));
        }
        if let Some(usage) = &account.usage {
            for window in &usage.rate_windows {
                let duration = match window.window_duration_mins {
                    Some(300) => Some("5h".to_string()),
                    Some(10_080) => Some("weekly".to_string()),
                    Some(minutes) if minutes % 1_440 == 0 => Some(format!("{}d", minutes / 1_440)),
                    Some(minutes) if minutes % 60 == 0 => Some(format!("{}h", minutes / 60)),
                    Some(minutes) => Some(format!("{minutes}m")),
                    None => None,
                };
                let label = match (window.kind, duration) {
                    (ManagedChatgptLimitKind::Primary, Some(duration)) => {
                        format!("primary {duration}")
                    }
                    (ManagedChatgptLimitKind::Primary, None) => "primary".to_string(),
                    (ManagedChatgptLimitKind::Secondary, Some(duration)) => {
                        format!("secondary {duration}")
                    }
                    (ManagedChatgptLimitKind::Secondary, None) => "secondary".to_string(),
                    (ManagedChatgptLimitKind::Additional, Some(duration)) => {
                        format!("additional {} {duration}", window.limit_id)
                    }
                    (ManagedChatgptLimitKind::Additional, None) => {
                        format!("additional {}", window.limit_id)
                    }
                };
                let remaining = window
                    .remaining_percent
                    .map(|percent| format!("{percent:.0}% remaining"))
                    .unwrap_or_else(|| "unknown remaining".to_string());
                let reset = window
                    .reset_at
                    .map(|reset| reset.to_rfc3339())
                    .unwrap_or_else(|| "unknown".to_string());
                output.push_str(&format!("  {label}: {remaining}, resets {reset}\n"));
            }
        }
        let token_unavailable = account.token_state == ManagedChatgptTokenState::Unavailable;
        let token_usage = account
            .usage
            .as_ref()
            .and_then(|usage| usage.token_usage.as_ref());
        if let Some(stats) = token_usage {
            let value = |value: Option<i64>| {
                value
                    .map(|value| value.to_string())
                    .unwrap_or_else(|| "unknown".to_string())
            };
            let status = if token_unavailable {
                " (refresh unavailable)"
            } else {
                ""
            };
            output.push_str(&format!(
                "  tokens: lifetime {}, peak daily {}, longest turn {}s, streak {}d{status}\n",
                value(stats.lifetime_tokens),
                value(stats.peak_daily_tokens),
                value(stats.longest_running_turn_sec),
                value(stats.longest_streak_days),
            ));
        } else if token_unavailable {
            output.push_str("  tokens: unavailable\n");
        } else {
            output.push_str("  tokens: unknown\n");
        }
        if let Some(observed_at) = account.token_unavailable_observed_at {
            output.push_str(&format!(
                "  token unavailable observed: {}\n",
                observed_at.to_rfc3339()
            ));
        }
        if let Some(reason) = &account.token_unavailable_reason {
            output.push_str(&format!("  token unavailable reason: {reason}\n"));
        }
    }
    output
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
                    print!("{}", format_managed_login_status(&accounts, None));
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
        refresh_managed_login_status(auth_manager, &config.chatgpt_base_url, &managed.accounts)
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
