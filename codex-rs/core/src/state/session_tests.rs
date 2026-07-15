use super::*;
use crate::session::tests::make_session_configuration_for_tests;
use crate::state::AutoCompactWindowSnapshot;
use codex_protocol::protocol::CreditsSnapshot;
use codex_protocol::protocol::RateLimitWindow;
use codex_protocol::protocol::SpendControlLimitSnapshot;
use pretty_assertions::assert_eq;

#[tokio::test]
// Verifies connector merging deduplicates repeated IDs.
async fn merge_connector_selection_deduplicates_entries() {
    let session_configuration = make_session_configuration_for_tests().await;
    let mut state = SessionState::new(session_configuration);
    let merged = state.merge_connector_selection([
        "calendar".to_string(),
        "calendar".to_string(),
        "drive".to_string(),
    ]);

    assert_eq!(
        merged,
        HashSet::from(["calendar".to_string(), "drive".to_string()])
    );
}

#[tokio::test]
// Verifies clearing connector selection removes all saved IDs.
async fn clear_connector_selection_removes_entries() {
    let session_configuration = make_session_configuration_for_tests().await;
    let mut state = SessionState::new(session_configuration);
    state.merge_connector_selection(["calendar".to_string()]);

    state.clear_connector_selection();

    assert_eq!(state.get_connector_selection(), HashSet::new());
}

#[tokio::test]
async fn set_rate_limits_defaults_limit_id_to_codex_when_missing() {
    let session_configuration = make_session_configuration_for_tests().await;
    let mut state = SessionState::new(session_configuration);

    state.set_rate_limits(
        RateLimitSnapshot {
            limit_id: None,
            limit_name: None,
            primary: Some(RateLimitWindow {
                used_percent: 12.0,
                window_minutes: Some(60),
                resets_at: Some(100),
            }),
            secondary: None,
            credits: None,
            individual_limit: None,
            spend_control_reached: None,
            plan_type: None,
            rate_limit_reached_type: None,
        },
        None,
    );

    assert_eq!(
        state
            .latest_rate_limits
            .as_ref()
            .and_then(|v| v.snapshot.limit_id.clone()),
        Some("codex".to_string())
    );
}

#[tokio::test]
async fn replace_history_clears_auto_compact_window_prefill() {
    let session_configuration = make_session_configuration_for_tests().await;
    let mut state = SessionState::new(session_configuration);

    state.set_auto_compact_window_estimated_prefill(/*tokens*/ 100);
    state.replace_history(Vec::new(), /*reference_context_item*/ None);

    assert_eq!(
        state.auto_compact_window_snapshot(),
        AutoCompactWindowSnapshot {
            prefill_input_tokens: None,
        }
    );
}

#[tokio::test]
async fn set_rate_limits_defaults_to_codex_when_limit_id_missing_after_other_bucket() {
    let session_configuration = make_session_configuration_for_tests().await;
    let mut state = SessionState::new(session_configuration);

    state.set_rate_limits(
        RateLimitSnapshot {
            limit_id: Some("codex_other".to_string()),
            limit_name: Some("codex_other".to_string()),
            primary: Some(RateLimitWindow {
                used_percent: 20.0,
                window_minutes: Some(60),
                resets_at: Some(200),
            }),
            secondary: None,
            credits: None,
            individual_limit: None,
            spend_control_reached: None,
            plan_type: None,
            rate_limit_reached_type: None,
        },
        None,
    );
    state.set_rate_limits(
        RateLimitSnapshot {
            limit_id: None,
            limit_name: None,
            primary: Some(RateLimitWindow {
                used_percent: 30.0,
                window_minutes: Some(60),
                resets_at: Some(300),
            }),
            secondary: None,
            credits: None,
            individual_limit: None,
            spend_control_reached: None,
            plan_type: None,
            rate_limit_reached_type: None,
        },
        None,
    );

    assert_eq!(
        state
            .latest_rate_limits
            .as_ref()
            .and_then(|v| v.snapshot.limit_id.clone()),
        Some("codex".to_string())
    );
}

#[tokio::test]
async fn set_rate_limits_preserves_canonical_snapshot_after_additional_snapshot() {
    let session_configuration = make_session_configuration_for_tests().await;
    let mut state = SessionState::new(session_configuration);

    let initial = RateLimitSnapshot {
        limit_id: Some("codex".to_string()),
        limit_name: Some("codex".to_string()),
        primary: Some(RateLimitWindow {
            used_percent: 10.0,
            window_minutes: Some(60),
            resets_at: Some(100),
        }),
        secondary: None,
        credits: Some(CreditsSnapshot {
            has_credits: true,
            unlimited: false,
            balance: Some("50".to_string()),
        }),
        individual_limit: Some(SpendControlLimitSnapshot {
            limit: "25000".to_string(),
            used: "8000".to_string(),
            remaining_percent: 68,
            resets_at: 300,
        }),
        spend_control_reached: Some(true),
        plan_type: Some(codex_protocol::account::PlanType::Plus),
        rate_limit_reached_type: None,
    };
    state.set_rate_limits(initial.clone(), None);

    state.set_rate_limits(
        RateLimitSnapshot {
            limit_id: Some("codex_other".to_string()),
            limit_name: None,
            primary: Some(RateLimitWindow {
                used_percent: 30.0,
                window_minutes: Some(120),
                resets_at: Some(200),
            }),
            secondary: None,
            credits: Some(CreditsSnapshot {
                has_credits: true,
                unlimited: false,
                balance: Some("40".to_string()),
            }),
            individual_limit: Some(SpendControlLimitSnapshot {
                limit: "25000".to_string(),
                used: "9000".to_string(),
                remaining_percent: 64,
                resets_at: 300,
            }),
            spend_control_reached: None,
            plan_type: Some(codex_protocol::account::PlanType::Pro),
            rate_limit_reached_type: None,
        },
        None,
    );

    let mut expected = initial;
    expected.limit_id = Some("codex".to_string());
    expected.credits = Some(CreditsSnapshot {
        has_credits: true,
        unlimited: false,
        balance: Some("40".to_string()),
    });
    expected.individual_limit = Some(SpendControlLimitSnapshot {
        limit: "25000".to_string(),
        used: "9000".to_string(),
        remaining_percent: 64,
        resets_at: 300,
    });
    expected.plan_type = Some(codex_protocol::account::PlanType::Pro);
    assert_eq!(
        state
            .latest_rate_limits
            .as_ref()
            .map(|latest| &latest.snapshot),
        Some(&expected)
    );

    state.set_rate_limits(
        RateLimitSnapshot {
            limit_id: Some("codex_other".to_string()),
            limit_name: None,
            primary: None,
            secondary: None,
            credits: None,
            individual_limit: None,
            spend_control_reached: Some(false),
            plan_type: None,
            rate_limit_reached_type: None,
        },
        None,
    );
    expected.spend_control_reached = Some(false);
    assert_eq!(
        state
            .latest_rate_limits
            .as_ref()
            .map(|latest| &latest.snapshot),
        Some(&expected)
    );

    state.set_rate_limits(
        RateLimitSnapshot {
            limit_id: None,
            limit_name: None,
            primary: None,
            secondary: None,
            credits: None,
            individual_limit: None,
            spend_control_reached: None,
            plan_type: None,
            rate_limit_reached_type: None,
        },
        None,
    );
    assert_eq!(
        state.latest_rate_limits.map(|latest| latest.snapshot),
        Some(expected)
    );
}

fn managed_binding(raw_account_id: &str, route_generation: u64) -> ManagedRateLimitBinding {
    ManagedRateLimitBinding {
        managed_account_id: "email:managed@example.com".to_string(),
        account_state_revision: 7,
        transport_binding: TransportAuthBinding {
            identity_key: "email:managed@example.com".to_string(),
            raw_account_id: Some(raw_account_id.to_string()),
            fedramp: false,
            auth_mode: codex_protocol::auth::AuthMode::Chatgpt,
            route_generation,
        },
        shared_account_state_revision: None,
    }
}

fn empty_rate_limit_snapshot() -> RateLimitSnapshot {
    RateLimitSnapshot {
        limit_id: Some("codex".to_string()),
        limit_name: None,
        primary: None,
        secondary: None,
        credits: None,
        individual_limit: None,
        spend_control_reached: None,
        plan_type: None,
        rate_limit_reached_type: None,
    }
}

#[tokio::test]
async fn pending_managed_rate_limits_restore_only_for_full_transport_binding_match() {
    let session_configuration = make_session_configuration_for_tests().await;
    let mut state = SessionState::new(session_configuration);
    let binding = managed_binding("workspace-a", 11);
    let snapshot = empty_rate_limit_snapshot();
    state.restore_pending_managed_rate_limits(
        snapshot.clone(),
        binding.managed_account_id.clone(),
        binding.account_state_revision,
        Some(binding.transport_binding.clone()),
    );

    state.observe_managed_rate_limit_binding(Some(&binding));

    assert_eq!(
        state.latest_rate_limits.map(|latest| latest.snapshot),
        Some(snapshot)
    );
}

#[tokio::test]
async fn restore_rate_limits_defaults_missing_limit_id_to_codex() {
    let session_configuration = make_session_configuration_for_tests().await;
    let mut state = SessionState::new(session_configuration);
    let mut snapshot = empty_rate_limit_snapshot();
    snapshot.limit_id = None;

    state.restore_rate_limits(snapshot, None);

    assert_eq!(
        state
            .latest_rate_limits
            .and_then(|latest| latest.snapshot.limit_id),
        Some("codex".to_string())
    );
}

#[tokio::test]
async fn pending_managed_rate_limits_defaults_missing_limit_id_to_codex() {
    let session_configuration = make_session_configuration_for_tests().await;
    let mut state = SessionState::new(session_configuration);
    let binding = managed_binding("workspace-a", 11);
    let mut snapshot = empty_rate_limit_snapshot();
    snapshot.limit_id = None;
    state.restore_pending_managed_rate_limits(
        snapshot,
        binding.managed_account_id.clone(),
        binding.account_state_revision,
        Some(binding.transport_binding.clone()),
    );

    state.observe_managed_rate_limit_binding(Some(&binding));

    assert_eq!(
        state
            .latest_rate_limits
            .and_then(|latest| latest.snapshot.limit_id),
        Some("codex".to_string())
    );
}

#[tokio::test]
async fn token_count_state_reads_persisted_managed_binding_revision() {
    let session_configuration = make_session_configuration_for_tests().await;
    let mut state = SessionState::new(session_configuration);
    let revision = Arc::new(AtomicU64::new(7));
    let mut binding = managed_binding("workspace-a", 11);
    binding.shared_account_state_revision = Some(Arc::clone(&revision));
    let shared_clone = binding.clone();
    state.observe_managed_rate_limit_binding(Some(&binding));

    revision.store(19, Ordering::Release);
    assert_eq!(binding, binding);
    assert_eq!(binding, shared_clone);

    let (_, _, emitted_binding) = state.token_info_and_rate_limits();
    assert_eq!(
        emitted_binding.map(|binding| binding.account_state_revision),
        Some(19)
    );
}

#[tokio::test]
async fn pending_managed_rate_limits_reject_and_clear_full_binding_mismatch() {
    let session_configuration = make_session_configuration_for_tests().await;
    let mut state = SessionState::new(session_configuration);
    let pending_binding = managed_binding("workspace-a", 11);
    let current_binding = managed_binding("workspace-b", 12);
    state.restore_pending_managed_rate_limits(
        empty_rate_limit_snapshot(),
        pending_binding.managed_account_id,
        pending_binding.account_state_revision,
        Some(pending_binding.transport_binding),
    );

    state.observe_managed_rate_limit_binding(Some(&current_binding));

    assert!(state.latest_rate_limits.is_none());
    assert!(state.pending_managed_rate_limits.is_none());
    assert_eq!(
        state.current_managed_rate_limit_binding,
        Some(current_binding)
    );
}
