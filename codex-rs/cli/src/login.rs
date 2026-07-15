//! CLI login commands and their direct-user observability surfaces.
//!
//! The TUI path already installs a broader tracing stack with feedback, OpenTelemetry, and other
//! interactive-session layers. Direct `codex login` intentionally does less: it preserves the
//! existing stderr/browser UX and adds only a small file-backed tracing layer for login-specific
//! targets. Keeping that setup local avoids pulling the TUI's session-oriented logging machinery
//! into a one-shot CLI command while still producing a durable `codex-login.log` artifact that
//! support can request from users.

use crate::load_cli_auth_projection;
use codex_backend_client::Client as BackendClient;
use codex_backend_client::TokenUsageProfile;
use codex_config::types::AuthCredentialsStoreMode;
use codex_core::config::Config;
use codex_login::AuthKeyringBackendKind;
use codex_login::AuthManager;
use codex_login::AuthRouteConfig;
use codex_login::CLIENT_ID;
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
use codex_login::ServerOptions;
use codex_login::login_with_access_token;
use codex_login::login_with_api_key;
use codex_login::run_device_code_login;
use codex_login::run_login_server;
use codex_protocol::auth::AuthMode;
use codex_protocol::config_types::ForcedLoginMethod;
use codex_protocol::protocol::RateLimitSnapshot;
use codex_utils_cli::CliConfigOverrides;
use std::fs::OpenOptions;
use std::io::BufRead;
use std::io::IsTerminal;
use std::io::Read;
use std::io::Write;
use std::path::PathBuf;
use tracing_appender::non_blocking;
use tracing_appender::non_blocking::WorkerGuard;
use tracing_subscriber::EnvFilter;
use tracing_subscriber::Layer;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;

const CHATGPT_LOGIN_DISABLED_MESSAGE: &str =
    "ChatGPT login is disabled. Use API key login instead.";
const API_KEY_LOGIN_DISABLED_MESSAGE: &str =
    "API key login is disabled. Use ChatGPT login instead.";
const ACCESS_TOKEN_LOGIN_DISABLED_MESSAGE: &str =
    "Access token login is disabled. Use API key login instead.";
const LOGIN_SUCCESS_MESSAGE: &str = "Successfully logged in";

/// Installs a small file-backed tracing layer for direct `codex login` flows.
///
/// This deliberately duplicates a narrow slice of the TUI logging setup instead of reusing it
/// wholesale. The TUI stack includes session-oriented layers that are valuable for interactive
/// runs but unnecessary for a one-shot login command. Keeping the direct CLI path local lets this
/// command produce a durable `codex-login.log` artifact without coupling it to the TUI's broader
/// telemetry and feedback initialization.
fn init_login_file_logging(config: &Config) -> Option<WorkerGuard> {
    let log_dir = match codex_core::config::log_dir(config) {
        Ok(log_dir) => log_dir,
        Err(err) => {
            eprintln!("Warning: failed to resolve login log directory: {err}");
            return None;
        }
    };

    if let Err(err) = std::fs::create_dir_all(&log_dir) {
        eprintln!(
            "Warning: failed to create login log directory {}: {err}",
            log_dir.display()
        );
        return None;
    }

    let mut log_file_opts = OpenOptions::new();
    log_file_opts.create(true).append(true);

    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        log_file_opts.mode(0o600);
    }

    let log_path = log_dir.join("codex-login.log");
    let log_file = match log_file_opts.open(&log_path) {
        Ok(log_file) => log_file,
        Err(err) => {
            eprintln!(
                "Warning: failed to open login log file {}: {err}",
                log_path.display()
            );
            return None;
        }
    };

    let (non_blocking, guard) = non_blocking(log_file);
    let env_filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new("codex_cli=info,codex_core=info,codex_login=info"));
    let file_layer = tracing_subscriber::fmt::layer()
        .with_writer(non_blocking)
        .with_target(true)
        .with_ansi(false)
        .with_filter(env_filter);

    // Direct `codex login` otherwise relies on ephemeral stderr and browser output.
    // Persist the same login targets to a file so support can inspect auth failures
    // without reproducing them through TUI or app-server.
    if let Err(err) = tracing_subscriber::registry().with(file_layer).try_init() {
        eprintln!(
            "Warning: failed to initialize login log file {}: {err}",
            log_path.display()
        );
        return None;
    }

    Some(guard)
}

fn print_login_server_start(actual_port: u16, auth_url: &str) {
    eprintln!(
        "Starting local login server on http://localhost:{actual_port}.\nIf your browser did not open, navigate to this URL to authenticate:\n\n{auth_url}\n\nOn a remote or headless machine? Use `codex login --device-auth` instead."
    );
}

pub async fn login_with_chatgpt(
    codex_home: PathBuf,
    forced_chatgpt_workspace_id: Option<Vec<String>>,
    cli_auth_credentials_store_mode: AuthCredentialsStoreMode,
    auth_keyring_backend_kind: AuthKeyringBackendKind,
    auth_route_config: AuthRouteConfig,
) -> std::io::Result<()> {
    let opts = ServerOptions::new(
        codex_home,
        CLIENT_ID.to_string(),
        forced_chatgpt_workspace_id,
        cli_auth_credentials_store_mode,
        auth_keyring_backend_kind,
        auth_route_config,
    );
    let server = run_login_server(opts)?;

    print_login_server_start(server.actual_port, &server.auth_url);

    server.block_until_done().await.map(|_| ())
}

pub async fn run_login_with_chatgpt(cli_config_overrides: CliConfigOverrides) -> ! {
    let config = load_config_or_exit(cli_config_overrides).await;
    let _login_log_guard = init_login_file_logging(&config);
    tracing::info!("starting browser login flow");

    if matches!(config.forced_login_method, Some(ForcedLoginMethod::Api)) {
        eprintln!("{CHATGPT_LOGIN_DISABLED_MESSAGE}");
        std::process::exit(1);
    }

    let forced_chatgpt_workspace_id = config.forced_chatgpt_workspace_id.clone();
    match login_with_chatgpt(
        config.codex_home.to_path_buf(),
        forced_chatgpt_workspace_id,
        config.cli_auth_credentials_store_mode,
        config.auth_keyring_backend_kind(),
        config.auth_route_config(),
    )
    .await
    {
        Ok(_) => {
            eprintln!("{LOGIN_SUCCESS_MESSAGE}");
            std::process::exit(0);
        }
        Err(e) => {
            eprintln!("Error logging in: {e}");
            std::process::exit(1);
        }
    }
}

pub async fn run_login_with_api_key(
    cli_config_overrides: CliConfigOverrides,
    api_key: String,
) -> ! {
    let config = load_config_or_exit(cli_config_overrides).await;
    let _login_log_guard = init_login_file_logging(&config);
    tracing::info!("starting api key login flow");

    if matches!(config.forced_login_method, Some(ForcedLoginMethod::Chatgpt)) {
        eprintln!("{API_KEY_LOGIN_DISABLED_MESSAGE}");
        std::process::exit(1);
    }

    match login_with_api_key(
        &config.codex_home,
        &api_key,
        config.cli_auth_credentials_store_mode,
        config.auth_keyring_backend_kind(),
    ) {
        Ok(_) => {
            eprintln!("{LOGIN_SUCCESS_MESSAGE}");
            std::process::exit(0);
        }
        Err(e) => {
            eprintln!("Error logging in: {e}");
            std::process::exit(1);
        }
    }
}

pub async fn run_login_with_access_token(
    cli_config_overrides: CliConfigOverrides,
    access_token: String,
) -> ! {
    let config = load_config_or_exit(cli_config_overrides).await;
    let _login_log_guard = init_login_file_logging(&config);
    tracing::info!("starting access token login flow");

    if matches!(config.forced_login_method, Some(ForcedLoginMethod::Api)) {
        eprintln!("{ACCESS_TOKEN_LOGIN_DISABLED_MESSAGE}");
        std::process::exit(1);
    }

    let auth_route_config = config.auth_route_config();
    match login_with_access_token(
        &config.codex_home,
        &access_token,
        config.cli_auth_credentials_store_mode,
        config.forced_chatgpt_workspace_id.as_deref(),
        Some(&config.chatgpt_base_url),
        config.auth_keyring_backend_kind(),
        &auth_route_config,
    )
    .await
    {
        Ok(_) => {
            eprintln!("{LOGIN_SUCCESS_MESSAGE}");
            std::process::exit(0);
        }
        Err(e) => {
            eprintln!("Error logging in with access token: {e}");
            std::process::exit(1);
        }
    }
}

pub fn read_api_key_from_stdin() -> String {
    read_stdin_secret(
        "--with-api-key expects the API key on stdin. Try piping it, e.g. `printenv OPENAI_API_KEY | codex login --with-api-key`.",
        "Reading API key from stdin...",
        "No API key provided via stdin.",
    )
}

pub fn read_access_token_from_stdin() -> String {
    read_stdin_secret(
        "--with-access-token expects the access token on stdin. Try piping it, e.g. `printenv CODEX_ACCESS_TOKEN | codex login --with-access-token`.",
        "Reading access token from stdin...",
        "No access token provided via stdin.",
    )
}

fn read_stdin_secret(terminal_message: &str, reading_message: &str, empty_message: &str) -> String {
    let mut stdin = std::io::stdin();

    if stdin.is_terminal() {
        eprintln!("{terminal_message}");
        std::process::exit(1);
    }

    eprintln!("{reading_message}");

    let mut buffer = String::new();
    if let Err(err) = stdin.read_to_string(&mut buffer) {
        eprintln!("Failed to read stdin: {err}");
        std::process::exit(1);
    }

    let secret = buffer.trim().to_string();
    if secret.is_empty() {
        eprintln!("{empty_message}");
        std::process::exit(1);
    }

    secret
}

/// Login using the OAuth device code flow.
pub async fn run_login_with_device_code(
    cli_config_overrides: CliConfigOverrides,
    issuer_base_url: Option<String>,
    client_id: Option<String>,
) -> ! {
    let config = load_config_or_exit(cli_config_overrides).await;
    let _login_log_guard = init_login_file_logging(&config);
    tracing::info!("starting device code login flow");
    if matches!(config.forced_login_method, Some(ForcedLoginMethod::Api)) {
        eprintln!("{CHATGPT_LOGIN_DISABLED_MESSAGE}");
        std::process::exit(1);
    }
    let auth_route_config = config.auth_route_config();
    let forced_chatgpt_workspace_id = config.forced_chatgpt_workspace_id.clone();
    let mut opts = ServerOptions::new(
        config.codex_home.to_path_buf(),
        client_id.unwrap_or(CLIENT_ID.to_string()),
        forced_chatgpt_workspace_id,
        config.cli_auth_credentials_store_mode,
        config.auth_keyring_backend_kind(),
        auth_route_config,
    );
    if let Some(iss) = issuer_base_url {
        opts.issuer = iss;
    }
    match run_device_code_login(opts).await {
        Ok(_) => {
            eprintln!("{LOGIN_SUCCESS_MESSAGE}");
            std::process::exit(0);
        }
        Err(e) => {
            eprintln!("Error logging in with device code: {e}");
            std::process::exit(1);
        }
    }
}

/// Prefers device-code login (with `open_browser = false`) when headless environment is detected, but keeps
/// `codex login` working in environments where device-code may be disabled/feature-gated.
/// If `run_device_code_login` returns `ErrorKind::NotFound` ("device-code unsupported"), this
/// falls back to starting the local browser login server.
pub async fn run_login_with_device_code_fallback_to_browser(
    cli_config_overrides: CliConfigOverrides,
    issuer_base_url: Option<String>,
    client_id: Option<String>,
) -> ! {
    let config = load_config_or_exit(cli_config_overrides).await;
    let _login_log_guard = init_login_file_logging(&config);
    tracing::info!("starting login flow with device code fallback");
    if matches!(config.forced_login_method, Some(ForcedLoginMethod::Api)) {
        eprintln!("{CHATGPT_LOGIN_DISABLED_MESSAGE}");
        std::process::exit(1);
    }
    let auth_route_config = config.auth_route_config();
    let forced_chatgpt_workspace_id = config.forced_chatgpt_workspace_id.clone();
    let mut opts = ServerOptions::new(
        config.codex_home.to_path_buf(),
        client_id.unwrap_or(CLIENT_ID.to_string()),
        forced_chatgpt_workspace_id,
        config.cli_auth_credentials_store_mode,
        config.auth_keyring_backend_kind(),
        auth_route_config,
    );
    if let Some(iss) = issuer_base_url {
        opts.issuer = iss;
    }
    opts.open_browser = false;

    match run_device_code_login(opts.clone()).await {
        Ok(_) => {
            eprintln!("{LOGIN_SUCCESS_MESSAGE}");
            std::process::exit(0);
        }
        Err(e) => {
            if e.kind() == std::io::ErrorKind::NotFound {
                eprintln!("Device code login is not enabled; falling back to browser login.");
                match run_login_server(opts) {
                    Ok(server) => {
                        print_login_server_start(server.actual_port, &server.auth_url);
                        match server.block_until_done().await {
                            Ok(_) => {
                                eprintln!("{LOGIN_SUCCESS_MESSAGE}");
                                std::process::exit(0);
                            }
                            Err(e) => {
                                eprintln!("Error logging in: {e}");
                                std::process::exit(1);
                            }
                        }
                    }
                    Err(e) => {
                        eprintln!("Error logging in: {e}");
                        std::process::exit(1);
                    }
                }
            } else {
                eprintln!("Error logging in with device code: {e}");
                std::process::exit(1);
            }
        }
    }
}

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

async fn load_config_or_exit(cli_config_overrides: CliConfigOverrides) -> Config {
    let cli_overrides = match cli_config_overrides.parse_overrides() {
        Ok(v) => v,
        Err(e) => {
            eprintln!("Error parsing -c overrides: {e}");
            std::process::exit(1);
        }
    };

    match Config::load_with_cli_overrides(cli_overrides).await {
        Ok(config) => config,
        Err(e) => {
            eprintln!("Error loading configuration: {e}");
            std::process::exit(1);
        }
    }
}

fn safe_format_key(key: &str) -> String {
    if key.len() <= 13 {
        return "***".to_string();
    }
    let prefix = &key[..8];
    let suffix = &key[key.len() - 5..];
    format!("{prefix}***{suffix}")
}

#[cfg(test)]
mod tests {
    use chrono::Utc;
    use codex_backend_client::TokenUsageProfile;
    use codex_backend_client::TokenUsageProfileStats;
    use codex_login::ManagedChatgptEligibility;
    use codex_login::ManagedChatgptLimitKind;
    use codex_login::ManagedChatgptOauthCredentials;
    use codex_login::ManagedChatgptRateWindowView;
    use codex_login::ManagedChatgptRefreshStatus;
    use codex_login::ManagedChatgptTokenState;
    use codex_login::ManagedChatgptUsageState;
    use codex_login::ManagedChatgptUsageView;
    use codex_login::TokenData;
    use codex_login::token_data::IdTokenInfo;
    use codex_protocol::protocol::RateLimitSnapshot;
    use codex_protocol::protocol::RateLimitWindow;
    use pretty_assertions::assert_eq;
    use std::io::Cursor;
    use tempfile::tempdir;

    use super::AMBIGUOUS_LOGOUT_GUIDANCE;
    use super::AuthMode;
    use super::CodexAuth;
    use super::ManagedChatgptAccountView;
    use super::UnscopedLogoutTarget;
    use super::format_managed_login_status;
    use super::is_managed_api_auth_mode;
    use super::logout_all_auth;
    use super::non_pooled_login_status;
    use super::pick_logout_account;
    use super::rate_windows_from_backend;
    use super::safe_format_key;
    use super::select_persistent_unscoped_logout_target;
    use super::select_unscoped_logout_target;
    use super::singular_login_status;
    use super::token_usage_summary;

    fn account(identity_key: &str, email: &str) -> ManagedChatgptAccountView {
        ManagedChatgptAccountView {
            identity_key: identity_key.to_string(),
            identity_aliases: vec![email.to_string()],
            usage_state: ManagedChatgptUsageState::Unknown,
            token_state: ManagedChatgptTokenState::Available,
            refresh_status: ManagedChatgptRefreshStatus::Healthy,
            token_observed_at: Utc::now(),
            usage_unavailable_reason: None,
            token_unavailable_reason: None,
            usage_unavailable_observed_at: None,
            token_unavailable_observed_at: None,
            normalized_email: Some(email.to_string()),
            chatgpt_account_id: None,
            revision: 1,
            credential_revision: 1,
            last_refresh: Utc::now(),
            plan: Some("plus".to_string()),
            fedramp: false,
            eligibility: ManagedChatgptEligibility::Eligible,
            block_kind: None,
            block_reset_at: None,
            usage: None,
        }
    }

    fn managed_oauth_credentials(
        email: &str,
        account_id: &str,
        access_token: &str,
        refresh_token: &str,
    ) -> ManagedChatgptOauthCredentials {
        ManagedChatgptOauthCredentials {
            tokens: TokenData {
                id_token: IdTokenInfo {
                    email: Some(email.to_string()),
                    chatgpt_account_id: Some(account_id.to_string()),
                    raw_jwt: "e30.e30.c2ln".to_string(),
                    ..Default::default()
                },
                access_token: access_token.to_string(),
                refresh_token: refresh_token.to_string(),
                account_id: Some(account_id.to_string()),
            },
            last_refresh: Utc::now(),
            oauth_api_key: None,
        }
    }

    #[test]
    fn multi_account_picker_selects_number() {
        let accounts = [
            account("email:first@example.com", "first@example.com"),
            account("email:second@example.com", "second@example.com"),
        ];
        let mut input = Cursor::new(b"2\n");
        let mut prompt = Vec::new();

        let selected = pick_logout_account(&accounts, &mut input, &mut prompt)
            .expect("picker should read selection");

        assert_eq!(selected.as_deref(), Some("email:second@example.com"));
        let prompt = String::from_utf8(prompt).expect("prompt is utf-8");
        assert!(prompt.contains("1. first@example.com (email:first@example.com)"));
        assert!(prompt.contains("2. second@example.com (email:second@example.com)"));
    }

    #[test]
    fn multi_account_picker_can_cancel() {
        let accounts = [account("email:first@example.com", "first@example.com")];
        let mut input = Cursor::new(b"q\n");
        let mut prompt = Vec::new();

        assert_eq!(
            pick_logout_account(&accounts, &mut input, &mut prompt)
                .expect("picker should accept cancellation"),
            None
        );
    }

    #[test]
    fn multi_account_picker_rejects_invalid_input() {
        let accounts = [account("email:first@example.com", "first@example.com")];
        let mut input = Cursor::new(b"9\n");
        let mut prompt = Vec::new();

        let error = pick_logout_account(&accounts, &mut input, &mut prompt)
            .expect_err("out-of-range selection must fail");

        assert_eq!(error.kind(), std::io::ErrorKind::InvalidInput);
    }

    #[test]
    fn backend_token_usage_maps_to_owner_summary() {
        let profile = TokenUsageProfile {
            stats: TokenUsageProfileStats {
                lifetime_tokens: Some(100),
                peak_daily_tokens: Some(20),
                longest_running_turn_sec: Some(30),
                current_streak_days: Some(4),
                longest_streak_days: Some(5),
                daily_usage_buckets: None,
            },
        };

        let summary = token_usage_summary(&profile);

        assert_eq!(summary.lifetime_tokens, Some(100));
        assert_eq!(summary.peak_daily_tokens, Some(20));
        assert_eq!(summary.longest_running_turn_sec, Some(30));
        assert_eq!(summary.current_streak_days, Some(4));
        assert_eq!(summary.longest_streak_days, Some(5));
    }

    #[test]
    fn backend_rate_windows_preserve_duration_and_additional_identity() {
        let snapshots = vec![
            RateLimitSnapshot {
                limit_id: Some("codex".to_string()),
                limit_name: Some("Codex".to_string()),
                primary: Some(RateLimitWindow {
                    used_percent: 25.0,
                    window_minutes: Some(300),
                    resets_at: None,
                }),
                secondary: Some(RateLimitWindow {
                    used_percent: 60.0,
                    window_minutes: Some(10_080),
                    resets_at: None,
                }),
                credits: None,
                individual_limit: None,
                plan_type: None,
                rate_limit_reached_type: None,
            },
            RateLimitSnapshot {
                limit_id: Some("research".to_string()),
                limit_name: Some("Research".to_string()),
                primary: Some(RateLimitWindow {
                    used_percent: 10.0,
                    window_minutes: Some(60),
                    resets_at: None,
                }),
                secondary: Some(RateLimitWindow {
                    used_percent: 90.0,
                    window_minutes: Some(1_440),
                    resets_at: None,
                }),
                credits: None,
                individual_limit: None,
                plan_type: None,
                rate_limit_reached_type: None,
            },
        ];

        let windows = rate_windows_from_backend(snapshots);

        assert_eq!(windows.len(), 4);
        assert_eq!(windows[0].limit_id, "codex");
        assert_eq!(windows[0].kind, ManagedChatgptLimitKind::Primary);
        assert_eq!(windows[0].remaining_percent, Some(75.0));
        assert_eq!(windows[0].window_duration_mins, Some(300));
        assert_eq!(windows[1].limit_id, "codex");
        assert_eq!(windows[1].kind, ManagedChatgptLimitKind::Secondary);
        assert_eq!(windows[1].remaining_percent, Some(40.0));
        assert_eq!(windows[1].window_duration_mins, Some(10_080));
        assert_eq!(windows[2].limit_id, "research:primary");
        assert_eq!(windows[2].kind, ManagedChatgptLimitKind::Additional);
        assert_eq!(windows[2].remaining_percent, Some(90.0));
        assert_eq!(windows[2].window_duration_mins, Some(60));
        assert_eq!(windows[3].limit_id, "research:secondary");
        assert_eq!(windows[3].kind, ManagedChatgptLimitKind::Additional);
        assert_eq!(windows[3].remaining_percent, Some(10.0));
        assert_eq!(windows[3].window_duration_mins, Some(1_440));
    }

    #[test]
    fn managed_status_formats_two_accounts_and_usage_freshness() {
        let retained_observed_at = chrono::DateTime::parse_from_rfc3339("2026-07-13T10:00:00Z")
            .expect("valid timestamp")
            .with_timezone(&Utc);
        let unavailable_observed_at = chrono::DateTime::parse_from_rfc3339("2026-07-14T11:00:00Z")
            .expect("valid timestamp")
            .with_timezone(&Utc);
        let mut first = account("email:first@example.com", "first@example.com");
        first.chatgpt_account_id = Some("workspace-first".to_string());
        first.usage_state = ManagedChatgptUsageState::Fresh;
        first.usage = Some(ManagedChatgptUsageView {
            observed_at: Utc::now(),

            stale: false,
            token_usage: None,
            rate_windows: vec![ManagedChatgptRateWindowView {
                limit_id: "codex".to_string(),
                kind: ManagedChatgptLimitKind::Primary,
                remaining_percent: Some(75.0),
                window_duration_mins: Some(300),
                reset_at: None,
            }],
        });
        let mut second = account("email:second@example.com", "second@example.com");
        second.usage_state = ManagedChatgptUsageState::Unavailable;
        second.usage_unavailable_reason = Some("rate limit usage unavailable".to_string());
        second.usage_unavailable_observed_at = Some(unavailable_observed_at);
        second.token_state = ManagedChatgptTokenState::Unavailable;
        second.token_unavailable_reason = Some("token usage unavailable".to_string());
        second.token_unavailable_observed_at = Some(unavailable_observed_at);
        second.usage = Some(ManagedChatgptUsageView {
            observed_at: retained_observed_at,
            stale: true,
            token_usage: None,
            rate_windows: vec![ManagedChatgptRateWindowView {
                limit_id: "codex".to_string(),
                kind: ManagedChatgptLimitKind::Secondary,
                remaining_percent: Some(25.0),
                window_duration_mins: Some(10_080),
                reset_at: None,
            }],
        });

        let output = format_managed_login_status(&[first, second], Some("email:first@example.com"));

        assert!(output.contains("* first@example.com (email:first@example.com)"));
        assert!(output.contains("  account: workspace-first"));
        assert!(output.contains("  usage: fresh"));
        assert!(output.contains("  primary 5h: 75% remaining"));
        assert!(output.contains("  second@example.com (email:second@example.com)"));
        assert!(output.contains("  usage: stale (refresh unavailable)"));
        assert!(output.contains("  secondary weekly: 25% remaining"));
        assert!(output.contains(&format!(
            "  observed: {}",
            retained_observed_at.to_rfc3339()
        )));
        assert!(output.contains(&format!(
            "  usage unavailable observed: {}",
            unavailable_observed_at.to_rfc3339()
        )));
        assert!(output.contains("  usage unavailable reason: rate limit usage unavailable"));
        assert!(output.contains(&format!(
            "  token unavailable observed: {}",
            unavailable_observed_at.to_rfc3339()
        )));
        assert!(output.contains("  token unavailable reason: token usage unavailable"));
    }

    #[test]
    fn managed_status_uses_duration_for_primary_window_label() {
        let mut account = account("email:first@example.com", "first@example.com");
        account.usage_state = ManagedChatgptUsageState::Fresh;
        account.usage = Some(ManagedChatgptUsageView {
            observed_at: Utc::now(),
            stale: false,
            token_usage: None,
            rate_windows: vec![ManagedChatgptRateWindowView {
                limit_id: "codex".to_string(),
                kind: ManagedChatgptLimitKind::Primary,
                remaining_percent: Some(95.0),
                window_duration_mins: Some(10_080),
                reset_at: None,
            }],
        });

        let output = format_managed_login_status(&[account], None);

        assert!(output.contains("  primary weekly: 95% remaining"));
        assert!(!output.contains("  5-hour:"));
    }

    #[test]
    fn managed_status_labels_unknown_usage_without_exhaustion() {
        let account = account("email:first@example.com", "first@example.com");

        let output = format_managed_login_status(&[account], None);

        assert!(output.contains("  usage: unknown"));
        assert!(output.contains("  block: none"));
    }

    #[test]
    fn managed_status_labels_first_usage_failure_unavailable() {
        let mut account = account("email:first@example.com", "first@example.com");
        account.usage_state = ManagedChatgptUsageState::Unavailable;
        account.usage_unavailable_reason = Some("rate limit usage unavailable".to_string());
        let unavailable_observed_at = Utc::now();
        account.usage_unavailable_observed_at = Some(unavailable_observed_at);
        account.usage = Some(ManagedChatgptUsageView {
            observed_at: Utc::now(),
            stale: false,
            token_usage: None,
            rate_windows: Vec::new(),
        });

        let output = format_managed_login_status(&[account], None);

        assert!(output.contains("  usage: unavailable"));
        assert!(!output.contains("  usage: fresh (refresh unavailable)"));
        assert!(!output.contains("  observed:"));
        assert!(output.contains(&format!(
            "  usage unavailable observed: {}",
            unavailable_observed_at.to_rfc3339()
        )));
        assert!(output.contains("  usage unavailable reason: rate limit usage unavailable"));
    }

    #[test]
    fn managed_status_surfaces_transient_refresh_failure() {
        let observed_at = Utc::now();
        let mut account = account("email:first@example.com", "first@example.com");
        account.usage_state = ManagedChatgptUsageState::Fresh;
        account.refresh_status = codex_login::ManagedChatgptRefreshStatus::TransientUnavailable {
            observed_at,
            reason_code: None,
        };

        let output = format_managed_login_status(&[account], None);

        assert!(output.contains(&format!(
            "  refresh: temporarily unavailable, observed {}",
            observed_at.to_rfc3339()
        )));
        assert!(output.contains("  usage: fresh (refresh unavailable)"));
    }

    #[test]
    fn managed_status_surfaces_permanent_refresh_failure() {
        let observed_at = Utc::now();
        let mut account = account("email:first@example.com", "first@example.com");
        account.usage_state = ManagedChatgptUsageState::Stale;
        account.refresh_status = codex_login::ManagedChatgptRefreshStatus::ReloginRequired {
            observed_at,
            reason_code: None,
        };

        let output = format_managed_login_status(&[account], None);

        assert!(output.contains(&format!(
            "  refresh: relogin required, observed {}",
            observed_at.to_rfc3339()
        )));
        assert!(output.contains("  usage: stale (refresh unavailable)"));
    }

    #[test]
    fn non_pooled_api_key_status_remains_compatible() {
        let auth = CodexAuth::from_api_key("sk-proj-1234567890ABCDE");

        assert_eq!(
            non_pooled_login_status(&auth).expect("API key status"),
            "Logged in using an API key - sk-proj-***ABCDE"
        );
    }

    #[tokio::test]
    async fn malformed_chatgpt_tokens_do_not_report_logged_in() {
        let codex_home = tempdir().expect("temporary CODEX_HOME");
        std::fs::write(
            codex_home.path().join("auth.json"),
            r#"{"auth_mode":"chatgpt","tokens":null,"last_refresh":null}"#,
        )
        .expect("write malformed auth");
        let manager = super::AuthManager::shared(
            codex_home.path().to_path_buf(),
            false,
            super::AuthCredentialsStoreMode::File,
            None,
            None,
            super::AuthKeyringBackendKind::Direct,
            None,
        )
        .await;
        let auth = manager
            .auth_cached_result()
            .expect("auth document loads")
            .expect("ChatGPT auth is projected");

        assert!(singular_login_status(manager.as_ref(), Some(&auth)).is_none());
        assert!(
            manager
                .list_managed_chatgpt_accounts(&super::ManagedChatgptSelectionScope::default())
                .await
                .expect("list managed accounts")
                .accounts
                .is_empty()
        );
        let error = non_pooled_login_status(&auth).expect_err("missing token data must not log in");
        assert!(error.contains("Token data is not available"));
        assert!(!error.contains("Logged in using ChatGPT"));

        let valid = CodexAuth::create_dummy_chatgpt_auth_for_testing();
        assert_eq!(
            non_pooled_login_status(&valid).expect("valid ChatGPT status"),
            "Logged in using ChatGPT"
        );
    }

    #[test]
    fn only_managed_chatgpt_mode_reveals_the_pool() {
        assert!(is_managed_api_auth_mode(AuthMode::Chatgpt));
        for mode in [
            AuthMode::ApiKey,
            AuthMode::ChatgptAuthTokens,
            AuthMode::AgentIdentity,
            AuthMode::PersonalAccessToken,
            AuthMode::BedrockApiKey,
        ] {
            assert!(!is_managed_api_auth_mode(mode), "{mode:?}");
        }
    }

    #[tokio::test]
    async fn external_chatgpt_status_hides_preserved_managed_pool() {
        let codex_home = tempdir().expect("temporary CODEX_HOME");
        let persistent_manager = super::AuthManager::shared(
            codex_home.path().to_path_buf(),
            false,
            super::AuthCredentialsStoreMode::File,
            None,
            None,
            super::AuthKeyringBackendKind::Direct,
            None,
        )
        .await;
        let managed = managed_oauth_credentials(
            "managed@example.com",
            "managed-workspace",
            "managed-access",
            "managed-refresh",
        );
        persistent_manager
            .upsert_managed_chatgpt_oauth(managed)
            .await
            .expect("persist managed account");
        let sibling = managed_oauth_credentials(
            "sibling@example.com",
            "sibling-workspace",
            "sibling-access",
            "sibling-refresh",
        );
        persistent_manager
            .upsert_managed_chatgpt_oauth(sibling)
            .await
            .expect("persist sibling account");
        let persistent = persistent_manager
            .list_managed_chatgpt_accounts(&super::ManagedChatgptSelectionScope::default())
            .await
            .expect("list persistent accounts");
        assert_eq!(persistent.accounts.len(), 2);

        codex_login::auth::login_with_chatgpt_auth_tokens(
            codex_home.path(),
            "e30.e30.c2ln",
            "external-workspace",
            None,
        )
        .expect("install external overlay");
        let overlay_manager = super::AuthManager::shared(
            codex_home.path().to_path_buf(),
            false,
            super::AuthCredentialsStoreMode::File,
            None,
            None,
            super::AuthKeyringBackendKind::Direct,
            None,
        )
        .await;

        assert!(overlay_manager.is_external_chatgpt_auth_active());
        let overlay_auth = overlay_manager.auth_cached();
        assert_eq!(
            singular_login_status(overlay_manager.as_ref(), overlay_auth.as_ref())
                .expect("external status")
                .expect("status text"),
            "Logged in using ChatGPT"
        );
        assert!(
            persistent_manager
                .list_managed_chatgpt_accounts(&super::ManagedChatgptSelectionScope::default())
                .await
                .expect("external overlay hides persistent pool")
                .accounts
                .is_empty()
        );
        assert_eq!(
            overlay_manager
                .stored_managed_chatgpt_accounts()
                .expect("status inventory reads preserved pool")
                .len(),
            2
        );
        let stored = codex_login::load_auth_dot_json(
            codex_home.path(),
            super::AuthCredentialsStoreMode::File,
            super::AuthKeyringBackendKind::Direct,
        )
        .expect("load persistent auth")
        .expect("persistent auth remains");
        assert_eq!(
            stored
                .managed_chatgpt
                .expect("persistent managed pool remains")
                .accounts
                .len(),
            2
        );
        assert!(
            logout_all_auth(overlay_manager.as_ref())
                .await
                .expect("logout overlay and managed pool")
        );
        assert!(!overlay_manager.is_external_chatgpt_auth_active());
        assert!(
            persistent_manager
                .list_managed_chatgpt_accounts(&super::ManagedChatgptSelectionScope::default())
                .await
                .expect("managed pool cleared")
                .accounts
                .is_empty()
        );
    }

    #[tokio::test]
    async fn logout_all_removes_file_api_key_revealed_by_external_overlay() {
        let codex_home = tempdir().expect("temporary CODEX_HOME");
        codex_login::login_with_api_key(
            codex_home.path(),
            "sk-under-overlay",
            super::AuthCredentialsStoreMode::File,
            super::AuthKeyringBackendKind::Direct,
        )
        .expect("persist API key");
        codex_login::auth::login_with_chatgpt_auth_tokens(
            codex_home.path(),
            "e30.e30.c2ln",
            "external-workspace",
            None,
        )
        .expect("install external overlay");
        let manager = super::AuthManager::shared(
            codex_home.path().to_path_buf(),
            false,
            super::AuthCredentialsStoreMode::File,
            None,
            None,
            super::AuthKeyringBackendKind::Direct,
            None,
        )
        .await;

        assert!(manager.is_external_chatgpt_auth_active());
        assert!(
            logout_all_auth(manager.as_ref())
                .await
                .expect("logout overlay and underlying API key")
        );
        assert!(!manager.is_external_chatgpt_auth_active());
        assert!(manager.auth_cached().is_none());
        assert!(!codex_home.path().join("auth.json").exists());
    }

    #[test]
    fn one_account_logout_never_prompts() {
        let accounts = [account("email:first@example.com", "first@example.com")];
        let mut input = Cursor::new(Vec::<u8>::new());
        let mut prompt = Vec::new();

        let target = select_unscoped_logout_target(&accounts, false, &mut input, &mut prompt)
            .expect("one account is unambiguous");

        assert_eq!(
            target,
            UnscopedLogoutTarget::Managed("email:first@example.com".to_string())
        );
        assert!(prompt.is_empty());
    }

    #[tokio::test]
    async fn cached_non_pooled_auth_does_not_bypass_terminal_pool_picker() {
        let codex_home = tempdir().expect("temporary CODEX_HOME");
        let persistent_manager = super::AuthManager::shared(
            codex_home.path().to_path_buf(),
            false,
            super::AuthCredentialsStoreMode::File,
            None,
            None,
            super::AuthKeyringBackendKind::Direct,
            None,
        )
        .await;
        for credentials in [
            managed_oauth_credentials(
                "first@example.com",
                "first-workspace",
                "first-access",
                "first-refresh",
            ),
            managed_oauth_credentials(
                "second@example.com",
                "second-workspace",
                "second-access",
                "second-refresh",
            ),
        ] {
            persistent_manager
                .upsert_managed_chatgpt_oauth(credentials)
                .await
                .expect("persist managed account");
        }
        let override_manager = super::AuthManager::from_auth_for_testing_with_home(
            CodexAuth::from_api_key("sk-cached-override"),
            codex_home.path().to_path_buf(),
        );
        let mut input = Cursor::new(b"2\n");
        let mut prompt = Vec::new();

        let target = select_persistent_unscoped_logout_target(
            override_manager.as_ref(),
            true,
            &mut input,
            &mut prompt,
        )
        .await
        .expect("terminal should offer the persistent managed-account picker");

        assert!(matches!(target, UnscopedLogoutTarget::Managed(_)));
        assert!(
            String::from_utf8(prompt)
                .expect("prompt is utf-8")
                .contains("Choose a ChatGPT account to log out:")
        );
    }

    #[test]
    fn multiple_accounts_without_terminal_fail_with_guidance() {
        let accounts = [
            account("email:first@example.com", "first@example.com"),
            account("email:second@example.com", "second@example.com"),
        ];
        let mut input = Cursor::new(Vec::<u8>::new());
        let mut prompt = Vec::new();

        let error = select_unscoped_logout_target(&accounts, false, &mut input, &mut prompt)
            .expect_err("automation must not choose or prompt");

        assert_eq!(error.kind(), std::io::ErrorKind::InvalidInput);
        assert_eq!(error.to_string(), AMBIGUOUS_LOGOUT_GUIDANCE);
        assert!(prompt.is_empty());
    }

    #[test]
    fn formats_long_key() {
        let key = "sk-proj-1234567890ABCDE";
        assert_eq!(safe_format_key(key), "sk-proj-***ABCDE");
    }

    #[test]
    fn short_key_returns_stars() {
        let key = "sk-proj-12345";
        assert_eq!(safe_format_key(key), "***");
    }
}
