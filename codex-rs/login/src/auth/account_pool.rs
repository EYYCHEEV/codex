mod mutation;
mod selection;
mod types;

pub(super) use mutation::allocate_account_revision;
pub(super) use mutation::credential_revision;
pub(super) use mutation::migrate_document;
pub(super) use mutation::rebind_refreshed_identity;
pub(super) use mutation::resolve_identity;
pub(super) use mutation::row;
pub(super) use mutation::row_mut;
pub(super) use mutation::upsert;
pub(super) use mutation::validate_document;
pub(super) use selection::apply_failure;
pub(super) use selection::record_status_observation;
pub(super) use selection::select;
pub(super) use selection::singular_document;
pub(super) use selection::views;
pub use types::ManagedChatgptAccountList;
pub use types::ManagedChatgptAccountView;
pub use types::ManagedChatgptAuthSnapshot;
pub use types::ManagedChatgptBlockKindView;
pub use types::ManagedChatgptEligibility;
pub use types::ManagedChatgptFailure;
pub use types::ManagedChatgptOauthCredentials;
pub use types::ManagedChatgptRateObservation;
pub use types::ManagedChatgptRateWindowView;
pub use types::ManagedChatgptRecoveryDecision;
pub use types::ManagedChatgptRefreshStatus;
pub use types::ManagedChatgptSelectionScope;
pub use types::ManagedChatgptStatusObservation;
pub use types::ManagedChatgptTokenObservation;
pub use types::ManagedChatgptTokenState;
pub use types::ManagedChatgptUsageState;
pub use types::ManagedChatgptUsageView;
pub(super) use types::SelectionPins;
pub use types::TransportAuthBinding;

#[cfg(test)]
use super::storage::AuthDotJson;
#[cfg(test)]
use super::storage::ManagedChatgptLimitKind;
#[cfg(test)]
use super::storage::ManagedChatgptObservedUsage;
#[cfg(test)]
use super::storage::ManagedChatgptRateWindow;
#[cfg(test)]
use super::storage::ManagedChatgptTokenUsageSummary;
#[cfg(test)]
use super::storage::ManagedChatgptUnavailableObservation;
#[cfg(test)]
use crate::token_data::TokenData;
#[cfg(test)]
use chrono::DateTime;
#[cfg(test)]
use chrono::Duration;
#[cfg(test)]
use chrono::Utc;
#[cfg(test)]
use codex_protocol::auth::AuthMode;

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
        let first = select(&auth, &scope, &first_pins, None, now)
            .unwrap()
            .identity_key
            .clone();
        let second = select(&auth, &scope, &second_pins, None, now)
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
        select(&auth, &scope, &pins, None, now).expect("initial selection");
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
        select(&auth, &scope, &pins, None, now).expect("selection after status write");
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
        select(&auth, &scope, &pins, None, now).expect("selection after sibling added");
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
        select(&auth, &scope, &pins, None, now).expect("selection after sibling blocked");
        let after_block = pins.revision();
        assert!(after_block > after_sibling);

        select(&auth, &scope, &pins, Some(&["wa".to_string()]), now)
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
