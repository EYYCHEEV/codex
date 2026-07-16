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
    account.refresh_status =
        codex_login::ManagedChatgptRefreshStatus::TransientUnavailable { observed_at };

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
