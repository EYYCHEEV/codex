use super::*;
use crate::status::ManagedAccountsState;
use crate::status::managed_accounts::managed_account_lines;
use insta::assert_snapshot;
use pretty_assertions::assert_eq;

#[test]
fn managed_refresh_status_preserves_owner_eligibility_after_uncertain_refresh() {
    let accounts = [
        ("eligible-cancelled", "token_refresh_cancelled", true),
        (
            "eligible-commit-failed",
            "token_refresh_commit_failed",
            true,
        ),
        ("eligible-timeout", "token_refresh_timeout", true),
        ("permanent-rejection", "refresh_token_reused", false),
    ]
    .into_iter()
    .map(|(id, reason_code, eligible)| ManagedChatgptAccountView {
        managed_account_id: id.to_string(),
        chatgpt_account_id: Some(format!("workspace-{id}")),
        email: Some(format!("{id}@example.test")),
        plan_type: PlanType::Plus,
        // These are authoritative owner flags. An uncertain refresh does not invalidate
        // otherwise usable current access credentials; a permanent rejection does.
        eligible,
        eligibility_reason: (!eligible).then(|| "blocked".to_string()),
        account_revision: 2,
        credential_revision: 1,
        refresh_status: ManagedChatgptAccountRefreshStatus::ReloginRequired {
            reason_code: reason_code.to_string(),
            observed_at: 1_704_164_645,
        },
        block: (!eligible).then(|| ManagedChatgptAccountBlock {
            reason: "auth_invalid".to_string(),
            blocked_until: None,
        }),
        usage: ManagedChatgptAccountUsage {
            state: ManagedChatgptAccountUsageState::Unknown,
            rate_limits: Vec::new(),
            token_usage: None,
            observed_at: None,
            unavailable_reason: None,
            unavailable_observed_at: None,
        },
    })
    .collect();
    let pool = ManagedAccountsState::from_response(ListAccountsResponse {
        accounts,
        selected_account_id: Some("eligible-timeout".to_string()),
        selection_revision: Some(1),
        pool_revision: 2,
    });
    let rendered = managed_account_lines(&pool, /*available_inner_width*/ 110)
        .iter()
        .map(ToString::to_string)
        .collect::<Vec<_>>();
    let eligibility = rendered
        .iter()
        .map(|line| line.trim())
        .filter(|line| line.starts_with("Eligibility:"))
        .collect::<Vec<_>>();

    assert_eq!(
        eligibility,
        [
            "Eligibility: eligible (sign-in required for credential refresh)",
            "Eligibility: eligible (sign-in required for credential refresh)",
            "Eligibility: eligible (sign-in required for credential refresh)",
            "Eligibility: ineligible (sign-in required)",
        ]
    );
    assert_eq!(
        rendered
            .iter()
            .filter(|line| line.contains("Credential: sign-in required"))
            .count(),
        4
    );
    assert_snapshot!(
        "managed_refresh_status_owner_eligibility",
        rendered.join("\n")
    );
}
