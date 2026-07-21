use codex_login::ManagedChatgptAccountView;
use codex_login::ManagedChatgptEligibility;
use codex_login::ManagedChatgptLimitKind;
use codex_login::ManagedChatgptRateWindowView;
use codex_login::ManagedChatgptUsageState;
use std::collections::HashMap;

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct ResetCreditPresentation {
    pub(super) available_count: i64,
    pub(super) soonest_expiry: Option<chrono::DateTime<chrono::Utc>>,
}

fn relative_time(
    now: chrono::DateTime<chrono::Utc>,
    then: chrono::DateTime<chrono::Utc>,
) -> String {
    let seconds = then.signed_duration_since(now).num_seconds().max(0);
    let days = seconds / 86_400;
    let hours = seconds % 86_400 / 3_600;
    let minutes = seconds % 3_600 / 60;
    if days > 0 {
        format!("{days}d{hours}h")
    } else if hours > 0 {
        format!("{hours}h{minutes}m")
    } else {
        format!("{minutes}m")
    }
}

fn fetched_age(
    now: chrono::DateTime<chrono::Utc>,
    observed_at: chrono::DateTime<chrono::Utc>,
) -> String {
    let millis = now
        .signed_duration_since(observed_at)
        .num_milliseconds()
        .max(0);
    if millis < 60_000 {
        format!("{:.1}s", millis as f64 / 1_000.0)
    } else {
        relative_time(observed_at, now)
    }
}

fn window_label(window: &ManagedChatgptRateWindowView) -> String {
    let duration = match window.window_duration_mins {
        Some(10_080) => "7 days".to_string(),
        Some(minutes) if minutes % 1_440 == 0 => format!("{} days", minutes / 1_440),
        Some(minutes) if minutes % 60 == 0 => format!("{}h", minutes / 60),
        Some(minutes) => format!("{minutes}m"),
        None => "usage".to_string(),
    };
    if window.kind != ManagedChatgptLimitKind::Additional {
        return duration;
    }
    let id = window.limit_id.split(':').next().unwrap_or_default();
    if id == "codex_bengalfox" {
        format!("{duration} (Spark)")
    } else {
        let id = id
            .chars()
            .map(|character| {
                if character.is_ascii_alphanumeric() || character == '-' {
                    character
                } else {
                    ' '
                }
            })
            .collect::<String>();
        let id = id.trim();
        format!(
            "{duration} ({})",
            if id.is_empty() { "Additional" } else { id }
        )
    }
}

fn usage_bar(used_percent: f64) -> String {
    const WIDTH: usize = 28;
    let filled = ((used_percent.clamp(0.0, 100.0) / 100.0) * WIDTH as f64).round() as usize;
    format!("{}{}", "█".repeat(filled), "░".repeat(WIDTH - filled))
}

fn account_observed_at(
    account: &ManagedChatgptAccountView,
) -> Option<chrono::DateTime<chrono::Utc>> {
    match (
        account.usage.as_ref().map(|usage| usage.observed_at),
        account.usage_unavailable_observed_at,
    ) {
        (Some(usage), Some(unavailable)) => Some(usage.max(unavailable)),
        (usage, unavailable) => usage.or(unavailable),
    }
}

fn account_label(account: &ManagedChatgptAccountView) -> &str {
    account
        .normalized_email
        .as_deref()
        .or(account.chatgpt_account_id.as_deref())
        .unwrap_or(&account.identity_key)
}

pub(super) fn format_managed_login_status(
    accounts: &[ManagedChatgptAccountView],
    selected_account_id: Option<&str>,
    reset_credits: &HashMap<String, ResetCreditPresentation>,
) -> String {
    format_managed_login_status_at(
        accounts,
        selected_account_id,
        reset_credits,
        chrono::Utc::now(),
    )
}

pub(super) fn format_managed_login_status_at(
    accounts: &[ManagedChatgptAccountView],
    selected_account_id: Option<&str>,
    reset_credits: &HashMap<String, ResetCreditPresentation>,
    now: chrono::DateTime<chrono::Utc>,
) -> String {
    let fetched_at = accounts.iter().filter_map(account_observed_at).max();
    let mut output = match fetched_at {
        Some(observed_at) => format!("Usage - fetched {} ago\n\n", fetched_age(now, observed_at)),
        None => "Usage - unavailable\n\n".to_string(),
    };
    output.push_str(&format!(
        "OpenAI Codex - {} account{}\n",
        accounts.len(),
        if accounts.len() == 1 { "" } else { "s" }
    ));

    let mut ordered = accounts.iter().collect::<Vec<_>>();
    ordered.sort_by(|left, right| account_label(left).cmp(account_label(right)));
    for account in ordered {
        let label = account_label(account);
        output.push_str(&format!(
            "● {label} - plan: {}",
            account.plan.as_deref().unwrap_or("unknown")
        ));
        if selected_account_id == Some(account.identity_key.as_str()) {
            output.push_str(" - selected");
        }
        if let Some(summary) = reset_credits.get(&account.identity_key) {
            output.push_str(&format!(
                " - {} saved reset{}",
                summary.available_count,
                if summary.available_count == 1 {
                    ""
                } else {
                    "s"
                }
            ));
            if let Some(expiry) = summary.soonest_expiry {
                output.push_str(&format!(
                    " - soonest expires in {}",
                    relative_time(now, expiry)
                ));
            }
        }
        output.push('\n');

        match account.eligibility {
            ManagedChatgptEligibility::Eligible => {}
            ManagedChatgptEligibility::Blocked => output.push_str("  warning: account blocked\n"),
            ManagedChatgptEligibility::ForcedWorkspaceDisallowed => {
                output.push_str("  warning: workspace not allowed\n");
            }
            ManagedChatgptEligibility::PendingRemoval => {
                output.push_str("  warning: pending removal\n");
            }
        }
        match account.refresh_status {
            codex_login::ManagedChatgptRefreshStatus::Healthy => {}
            codex_login::ManagedChatgptRefreshStatus::TransientUnavailable { .. } => {
                output.push_str("  warning: refresh temporarily unavailable\n");
            }
            codex_login::ManagedChatgptRefreshStatus::ReloginRequired { .. } => {
                output.push_str("  warning: relogin required\n");
            }
        }
        match account.usage_state {
            ManagedChatgptUsageState::Fresh => {}
            ManagedChatgptUsageState::Stale => {
                if let Some(observed_at) = account_observed_at(account) {
                    output.push_str(&format!(
                        "  warning: usage stale - fetched {} ago\n",
                        fetched_age(now, observed_at)
                    ));
                } else {
                    output.push_str("  warning: usage stale\n");
                }
            }
            ManagedChatgptUsageState::Unavailable => {
                output.push_str("  warning: usage unavailable");
                if let Some(reason) = &account.usage_unavailable_reason {
                    output.push_str(&format!(" - {reason}"));
                }
                if let Some(usage) = account.usage.as_ref().filter(|usage| usage.stale) {
                    output.push_str(&format!(
                        " - cached data fetched {} ago",
                        fetched_age(now, usage.observed_at)
                    ));
                }
                output.push('\n');
            }
            ManagedChatgptUsageState::Unknown => output.push_str("  warning: usage unknown\n"),
        }

        if let Some(usage) = &account.usage {
            let mut windows = usage.rate_windows.iter().collect::<Vec<_>>();
            windows.sort_by(|left, right| {
                (left.kind == ManagedChatgptLimitKind::Additional)
                    .cmp(&(right.kind == ManagedChatgptLimitKind::Additional))
                    .then_with(|| left.window_duration_mins.cmp(&right.window_duration_mins))
                    .then_with(|| left.limit_id.cmp(&right.limit_id))
            });
            for window in windows {
                let reset = window
                    .reset_at
                    .map(|reset| format!(" - resets in {}", relative_time(now, reset)))
                    .unwrap_or_default();
                match window.remaining_percent {
                    Some(remaining) => {
                        let used = (100.0 - remaining).clamp(0.0, 100.0);
                        output.push_str(&format!(
                            "  ● {:<15} {}  {:>4.1}% used{reset}\n",
                            window_label(window),
                            usage_bar(used),
                            used,
                        ));
                    }
                    None => output.push_str(&format!(
                        "  ● {:<15} {}  unknown used{reset}\n",
                        window_label(window),
                        "?".repeat(28),
                    )),
                }
            }
        }
    }

    let canonical_duration = accounts
        .iter()
        .filter_map(|account| account.usage.as_ref())
        .flat_map(|usage| usage.rate_windows.iter())
        .filter(|window| {
            window.kind != ManagedChatgptLimitKind::Additional && window.limit_id == "codex"
        })
        .filter(|window| window.remaining_percent.is_some())
        .filter_map(|window| window.window_duration_mins)
        .max();
    if let Some(duration) = canonical_duration {
        let reported = accounts
            .iter()
            .filter_map(|account| {
                account
                    .usage
                    .as_ref()?
                    .rate_windows
                    .iter()
                    .filter(|window| {
                        window.kind != ManagedChatgptLimitKind::Additional
                            && window.limit_id == "codex"
                            && window.window_duration_mins == Some(duration)
                    })
                    .filter_map(|window| window.remaining_percent)
                    .map(|remaining| ((100.0 - remaining) / 100.0).clamp(0.0, 1.0))
                    .max_by(f64::total_cmp)
            })
            .collect::<Vec<_>>();
        if reported.is_empty() {
            return output;
        }
        let used = reported.iter().sum::<f64>();
        let reporting_accounts = reported.len();
        let duration = if duration % 1_440 == 0 {
            format!("{}d", duration / 1_440)
        } else if duration % 60 == 0 {
            format!("{}h", duration / 60)
        } else {
            format!("{duration}m")
        };
        output.push_str(&format!(
            "capacity: {duration} -> {used:.2}/{} account{} used ({:.2}x quota left)\n",
            reporting_accounts,
            if reporting_accounts == 1 { "" } else { "s" },
            reporting_accounts as f64 - used,
        ));
    }
    output
}
