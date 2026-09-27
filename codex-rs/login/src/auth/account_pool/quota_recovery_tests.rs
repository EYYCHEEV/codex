use super::*;
use crate::auth::storage::AuthDotJson;
use crate::auth::storage::ManagedChatgptLimitKind;
use crate::token_data::IdTokenInfo;
use crate::token_data::TokenData;
use chrono::Duration;
use chrono::Utc;
use pretty_assertions::assert_eq;

fn blocked_pool(failure: ManagedChatgptFailure, blocked_at: DateTime<Utc>) -> AuthDotJson {
    let mut document: AuthDotJson = serde_json::from_str("{}").unwrap();
    let identity = upsert(
        &mut document,
        ManagedChatgptOauthCredentials {
            tokens: TokenData {
                id_token: IdTokenInfo {
                    email: Some("quota@example.test".to_string()),
                    chatgpt_account_id: Some("workspace".to_string()),
                    ..Default::default()
                },
                access_token: "access-fixture".to_string(),
                refresh_token: "refresh-fixture".to_string(),
                account_id: Some("workspace".to_string()),
            },
            last_refresh: blocked_at,
            oauth_api_key: None,
        },
        /*forced_workspace_ids*/ None,
    )
    .unwrap();
    let revision = document.managed_chatgpt.as_ref().unwrap().accounts[0].credential_revision;
    assert!(apply_failure(
        &mut document,
        &identity,
        revision,
        failure,
        blocked_at
    ));
    document
}

fn healthy_windows() -> Vec<ManagedChatgptRateWindowView> {
    vec![ManagedChatgptRateWindowView {
        limit_id: "codex".to_string(),
        kind: ManagedChatgptLimitKind::Primary,
        remaining_percent: Some(80.0),
        reset_at: Some(Utc::now() + Duration::days(1)),
        window_duration_mins: Some(10080),
    }]
}

#[test]
fn authoritative_usage_recovers_quota_without_changing_credentials() {
    let now = Utc::now();
    let mut document = blocked_pool(
        ManagedChatgptFailure::Quota {
            reset_at: Some(now + Duration::days(1)),
        },
        now - Duration::minutes(10),
    );
    let scope = ManagedChatgptSelectionScope::default();
    let pins = SelectionPins::default();
    assert!(
        select(
            &document, &scope, &pins, /*forced_workspace_ids*/ None, now
        )
        .is_none()
    );
    let account = &mut document.managed_chatgpt.as_mut().unwrap().accounts[0];
    let before_credentials = (account.tokens.clone(), account.credential_revision);
    let windows = healthy_windows();
    let mut observation = ManagedChatgptStatusObservation {
        observed_at: now,
        rate: ManagedChatgptRateObservation::Available(windows.clone()),
        token: ManagedChatgptTokenObservation::NotObserved,
    };
    assert!(record_status_observation(account, observation.clone()));
    assert!(
        account.block.is_some(),
        "partial windows must not heal a quota block"
    );
    let previous_usage = account.observed_usage.clone();
    observation.rate = ManagedChatgptRateObservation::AuthoritativeAvailable(windows);
    assert!(record_status_observation(account, observation));
    assert_eq!(
        (account.block.clone(), account.observed_usage.clone()),
        (None, previous_usage)
    );
    assert_eq!(
        (account.tokens.clone(), account.credential_revision),
        before_credentials
    );
    assert!(
        select(
            &document, &scope, &pins, /*forced_workspace_ids*/ None, now
        )
        .is_some()
    );
    assert!(
        select(
            &document,
            &scope,
            &pins,
            Some(&["another-workspace".to_string()]),
            now
        )
        .is_none()
    );
}

#[test]
fn quota_recovery_rejects_untrusted_stale_or_incomplete_evidence() {
    let now = Utc::now();
    let quota = ManagedChatgptFailure::Quota {
        reset_at: Some(now + Duration::days(1)),
    };
    let mut exhausted = healthy_windows();
    exhausted.push(ManagedChatgptRateWindowView {
        kind: ManagedChatgptLimitKind::Secondary,
        remaining_percent: Some(0.0),
        ..exhausted[0].clone()
    });
    let mut additional_only = healthy_windows();
    additional_only[0].kind = ManagedChatgptLimitKind::Additional;
    let mut invalid_number = healthy_windows();
    invalid_number[0].remaining_percent = Some(f64::NAN);
    let mut unknown = healthy_windows();
    unknown[0].remaining_percent = None;
    for (label, failure, blocked_at, observed_at, rate) in [
        (
            "auth failure",
            ManagedChatgptFailure::AuthInvalid,
            now - Duration::hours(1),
            now,
            ManagedChatgptRateObservation::AuthoritativeAvailable(healthy_windows()),
        ),
        (
            "workspace quota",
            ManagedChatgptFailure::WorkspaceQuota {
                reset_at: Some(now + Duration::days(1)),
            },
            now - Duration::hours(1),
            now,
            ManagedChatgptRateObservation::AuthoritativeAvailable(healthy_windows()),
        ),
        (
            "recent quota failure",
            quota,
            now - Duration::minutes(1),
            now,
            ManagedChatgptRateObservation::AuthoritativeAvailable(healthy_windows()),
        ),
        (
            "stale probe",
            quota,
            now - Duration::hours(1),
            now - Duration::minutes(10),
            ManagedChatgptRateObservation::AuthoritativeAvailable(healthy_windows()),
        ),
        (
            "future probe",
            quota,
            now - Duration::hours(1),
            now + Duration::hours(1),
            ManagedChatgptRateObservation::AuthoritativeAvailable(healthy_windows()),
        ),
        (
            "empty probe",
            quota,
            now - Duration::hours(1),
            now,
            ManagedChatgptRateObservation::AuthoritativeAvailable(vec![]),
        ),
        (
            "exhausted secondary",
            quota,
            now - Duration::hours(1),
            now,
            ManagedChatgptRateObservation::AuthoritativeAvailable(exhausted),
        ),
        (
            "unrelated meter",
            quota,
            now - Duration::hours(1),
            now,
            ManagedChatgptRateObservation::AuthoritativeAvailable(additional_only),
        ),
        (
            "invalid percentage",
            quota,
            now - Duration::hours(1),
            now,
            ManagedChatgptRateObservation::AuthoritativeAvailable(invalid_number),
        ),
        (
            "unknown percentage",
            quota,
            now - Duration::hours(1),
            now,
            ManagedChatgptRateObservation::AuthoritativeAvailable(unknown),
        ),
        (
            "ordinary windows",
            quota,
            now - Duration::hours(1),
            now,
            ManagedChatgptRateObservation::Available(healthy_windows()),
        ),
        (
            "no rate observation",
            quota,
            now - Duration::hours(1),
            now,
            ManagedChatgptRateObservation::NotObserved,
        ),
    ] {
        let mut document = blocked_pool(failure, blocked_at);
        let account = &mut document.managed_chatgpt.as_mut().unwrap().accounts[0];
        let block = account.block.clone();
        record_status_observation(
            account,
            ManagedChatgptStatusObservation {
                observed_at,
                rate,
                token: ManagedChatgptTokenObservation::NotObserved,
            },
        );
        assert_eq!(account.block, block, "{label}");
    }
}
