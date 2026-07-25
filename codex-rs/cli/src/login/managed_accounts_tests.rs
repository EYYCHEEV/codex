use chrono::Utc;
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
use std::sync::Arc;
use tempfile::tempdir;
use tokio::sync::Notify;

use super::AMBIGUOUS_LOGOUT_GUIDANCE;
use super::AuthMode;
use super::CodexAuth;
use super::ManagedChatgptAccountView;
use super::ResetCreditPresentation;
use super::UnscopedLogoutTarget;
use super::format_managed_login_status_at;
use super::is_managed_api_auth_mode;
use super::logout_all_auth;
use super::non_pooled_login_status;
use super::pick_logout_account;
use super::rate_windows_from_backend;
use super::run_bounded;
use super::safe_format_key;
use super::select_persistent_unscoped_logout_target;
use super::select_unscoped_logout_target;
use super::singular_login_status;

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
            spend_control_reached: None,
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
            spend_control_reached: None,
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
fn managed_status_renders_compact_usage_without_internal_identifiers() {
    let now = chrono::DateTime::parse_from_rfc3339("2026-07-21T12:00:01.100Z")
        .expect("valid timestamp")
        .with_timezone(&Utc);
    let observed_at = chrono::DateTime::parse_from_rfc3339("2026-07-21T12:00:00Z")
        .expect("valid timestamp")
        .with_timezone(&Utc);
    let reset_at = chrono::DateTime::parse_from_rfc3339("2026-07-26T03:00:00Z")
        .expect("valid timestamp")
        .with_timezone(&Utc);
    let expires_at = chrono::DateTime::parse_from_rfc3339("2026-07-28T00:00:00Z")
        .expect("valid timestamp")
        .with_timezone(&Utc);
    let mut account = account("internal-identity-secret", "account@example.com");
    account.plan = Some("pro".to_string());
    account.usage_state = ManagedChatgptUsageState::Fresh;
    account.usage = Some(ManagedChatgptUsageView {
        observed_at,
        stale: false,
        token_usage: None,
        rate_windows: vec![
            ManagedChatgptRateWindowView {
                limit_id: "codex".to_string(),
                kind: ManagedChatgptLimitKind::Secondary,
                remaining_percent: Some(19.0),
                window_duration_mins: Some(10_080),
                reset_at: Some(reset_at),
            },
            ManagedChatgptRateWindowView {
                limit_id: "codex_bengalfox:secondary".to_string(),
                kind: ManagedChatgptLimitKind::Additional,
                remaining_percent: Some(100.0),
                window_duration_mins: Some(10_080),
                reset_at: Some(expires_at),
            },
        ],
    });
    let reset_credits = std::collections::HashMap::from([(
        account.identity_key.clone(),
        ResetCreditPresentation {
            available_count: 4,
            soonest_expiry: Some(expires_at),
        },
    )]);

    let output = format_managed_login_status_at(
        &[account],
        Some("internal-identity-secret"),
        &reset_credits,
        now,
    );

    assert_eq!(
        output,
        concat!(
            "Usage - fetched 1.1s ago\n\n",
            "OpenAI Codex - 1 account\n",
            "● account@example.com - plan: pro - selected - 4 saved resets - soonest expires in 6d11h\n",
            "  ● 7 days          ███████████████████████░░░░░  81.0% used - resets in 4d14h\n",
            "  ● 7 days (Spark)  ░░░░░░░░░░░░░░░░░░░░░░░░░░░░   0.0% used - resets in 6d11h\n",
            "capacity: 7d -> 0.81/1 account used (0.19x quota left)\n",
        )
    );
    assert!(!output.contains("internal-identity-secret"));
    assert!(!output.contains("credit"));
    assert!(!output.contains("token"));
}

#[test]
fn managed_status_capacity_uses_only_clamped_reporting_account_maxima() {
    let now = chrono::DateTime::parse_from_rfc3339("2026-07-21T12:00:00Z")
        .expect("valid timestamp")
        .with_timezone(&Utc);
    let make_account = |identity: &str, remaining: Vec<Option<f64>>| {
        let mut account = account(identity, identity);
        account.usage_state = ManagedChatgptUsageState::Fresh;
        account.usage = Some(ManagedChatgptUsageView {
            observed_at: now,
            stale: false,
            token_usage: None,
            rate_windows: remaining
                .into_iter()
                .map(|remaining_percent| ManagedChatgptRateWindowView {
                    limit_id: "codex".to_string(),
                    kind: ManagedChatgptLimitKind::Secondary,
                    remaining_percent,
                    window_duration_mins: Some(10_080),
                    reset_at: None,
                })
                .collect(),
        });
        account
    };
    let accounts = [
        make_account("duplicate@example.com", vec![Some(80.0), Some(40.0)]),
        make_account("over@example.com", vec![Some(120.0)]),
        make_account("under@example.com", vec![Some(-20.0)]),
        make_account("unknown@example.com", vec![None]),
    ];

    let output = format_managed_login_status_at(&accounts, None, &Default::default(), now);

    assert!(output.contains("capacity: 7d -> 1.60/3 accounts used (1.40x quota left)"));
    assert!(output.contains("????????????????????????????  unknown used"));
    assert!(output.contains("  0.0% used"));
    assert!(output.contains("100.0% used"));
    let unknown = output
        .split("● unknown@example.com")
        .nth(1)
        .expect("unknown account section");
    assert!(unknown.contains("unknown used"));
    assert!(!unknown.contains("% used"));
}

#[tokio::test]
async fn bounded_runner_starts_only_up_to_the_limit_and_preserves_order() {
    let gates = Arc::new((0..4).map(|_| Arc::new(Notify::new())).collect::<Vec<_>>());
    let (started_tx, mut started_rx) = tokio::sync::mpsc::unbounded_channel();
    let runner = tokio::spawn(run_bounded(0..4, 2, {
        let gates = Arc::clone(&gates);
        move |index| {
            let gates = Arc::clone(&gates);
            let started_tx = started_tx.clone();
            async move {
                started_tx.send(index).expect("observe task start");
                gates[index].notified().await;
                index
            }
        }
    }));

    let mut first_batch = [
        started_rx.recv().await.expect("first task starts"),
        started_rx.recv().await.expect("second task starts"),
    ];
    first_batch.sort_unstable();
    assert_eq!(first_batch, [0, 1]);
    assert!(started_rx.try_recv().is_err());

    gates[1].notify_one();
    assert_eq!(started_rx.recv().await, Some(2));
    for gate in gates.iter() {
        gate.notify_waiters();
        gate.notify_one();
    }

    assert_eq!(
        runner.await.expect("bounded runner completes"),
        vec![0, 1, 2, 3]
    );
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
