use chrono::Utc;
use ratatui::prelude::*;
use ratatui::style::Stylize;

use super::account::ManagedAccountsState;
use super::format::truncate_line_to_width;
use super::helpers::format_tokens_compact;

pub(super) fn managed_account_lines(
    accounts: &ManagedAccountsState,
    available_inner_width: usize,
) -> Vec<Line<'static>> {
    if accounts.is_empty() {
        return wrap_managed_detail(
            "Accounts",
            "none available; run codex login to add one".to_string(),
            available_inner_width,
        );
    }
    let mut lines = Vec::new();
    for account in accounts.accounts() {
        let selected = accounts.selected_account_id() == Some(account.managed_account_id.as_str());
        let marker = if selected { "› " } else { "  " };
        let label = super::managed_account_label(account);
        let mut heading = vec![
            Span::from(marker).cyan(),
            Span::from(label).bold(),
            Span::from(" · ").dim(),
            Span::from(super::plan_type_display_name(account.plan_type)),
        ];
        if selected {
            heading.push(Span::from(" · selected").cyan());
        }
        lines.push(truncate_line_to_width(
            Line::from(heading),
            available_inner_width,
        ));

        lines.extend(wrap_managed_detail(
            "Credential",
            format_refresh_status(&account.refresh_status),
            available_inner_width,
        ));

        let eligibility = match &account.refresh_status {
            codex_app_server_protocol::ManagedChatgptAccountRefreshStatus::Healthy => {
                if account.eligible {
                    match account.eligibility_reason.as_deref() {
                        Some(reason) if !reason.is_empty() => format!("eligible ({reason})"),
                        _ => "eligible".to_string(),
                    }
                } else {
                    match account.eligibility_reason.as_deref() {
                        Some(reason) if !reason.is_empty() => format!("ineligible ({reason})"),
                        _ => "ineligible (reason unknown)".to_string(),
                    }
                }
            }
            codex_app_server_protocol::ManagedChatgptAccountRefreshStatus::TransientUnavailable {
                ..
            } => "temporarily unavailable (credential refresh failed)".to_string(),
            codex_app_server_protocol::ManagedChatgptAccountRefreshStatus::ReloginRequired {
                ..
            } => "ineligible (sign-in required)".to_string(),
        };
        lines.extend(wrap_managed_detail(
            "Eligibility",
            eligibility,
            available_inner_width,
        ));

        let account_state = match account.block.as_ref() {
            Some(block) => {
                let expiry = block
                    .blocked_until
                    .and_then(format_observed_at)
                    .map(|value| format!("until {value}"))
                    .unwrap_or_else(|| "no known reset time".to_string());
                format!("{} ({expiry})", block.reason)
            }
            None => "none".to_string(),
        };
        lines.extend(wrap_managed_detail(
            "Cooldown",
            account_state,
            available_inner_width,
        ));

        let usage_state = managed_usage_state_label(account.usage.state);
        if account.usage.rate_limits.is_empty() {
            let quota = match account.usage.state {
                codex_app_server_protocol::ManagedChatgptAccountUsageState::Unknown => {
                    "unknown; no quota observation".to_string()
                }
                codex_app_server_protocol::ManagedChatgptAccountUsageState::Fresh => {
                    "not reported in the latest observation".to_string()
                }
                codex_app_server_protocol::ManagedChatgptAccountUsageState::Stale => {
                    "stale; no retained quota windows".to_string()
                }
                codex_app_server_protocol::ManagedChatgptAccountUsageState::Unavailable => {
                    "unavailable; no retained quota windows".to_string()
                }
            };
            lines.extend(wrap_managed_detail("Quota", quota, available_inner_width));
        } else {
            for snapshot in &account.usage.rate_limits {
                let name = snapshot
                    .limit_name
                    .as_deref()
                    .or(snapshot.limit_id.as_deref())
                    .unwrap_or("Codex");
                let quota = format!(
                    "{name} ({usage_state}) — primary {}; secondary {}",
                    format_managed_window(snapshot.primary.as_ref()),
                    format_managed_window(snapshot.secondary.as_ref()),
                );
                lines.extend(wrap_managed_detail("Quota", quota, available_inner_width));
            }
        }

        let mut usage_parts = vec![usage_state.to_string()];
        if let Some(reason) = account
            .usage
            .unavailable_reason
            .as_deref()
            .filter(|reason| !reason.is_empty())
        {
            usage_parts.push(reason.to_string());
        }
        if let Some(summary) = account.usage.token_usage.as_ref() {
            if let Some(tokens) = summary.lifetime_tokens {
                usage_parts.push(format!("{} lifetime tokens", format_tokens_compact(tokens)));
            }
            if let Some(tokens) = summary.peak_daily_tokens {
                usage_parts.push(format!("{} peak daily", format_tokens_compact(tokens)));
            }
            if let Some(days) = summary.current_streak_days {
                usage_parts.push(format!("{days}-day current streak"));
            }
            if let Some(seconds) = summary.longest_running_turn_sec {
                usage_parts.push(format!("{seconds}s longest turn"));
            }
        } else {
            usage_parts.push("summary not reported".to_string());
        }
        lines.extend(wrap_managed_detail(
            "Usage",
            usage_parts.join(" · "),
            available_inner_width,
        ));
        let observed = account
            .usage
            .observed_at
            .and_then(format_observed_at)
            .unwrap_or_else(|| "unknown".to_string());
        lines.extend(wrap_managed_detail(
            "Observed",
            observed,
            available_inner_width,
        ));
        lines.push(Line::default());
    }
    if lines.last().is_some_and(|line| line.spans.is_empty()) {
        lines.pop();
    }
    lines
}

fn wrap_managed_detail(
    label: &str,
    value: String,
    available_inner_width: usize,
) -> Vec<Line<'static>> {
    let initial_indent = format!("    {label}: ");
    let subsequent_indent = "      ".to_string();
    let text = format!("{initial_indent}{value}");
    textwrap::wrap(
        text.as_str(),
        textwrap::Options::new(available_inner_width.max(1))
            .break_words(false)
            .initial_indent("")
            .subsequent_indent(subsequent_indent.as_str()),
    )
    .into_iter()
    .map(|line| Line::from(line.into_owned()))
    .collect()
}

fn managed_usage_state_label(
    state: codex_app_server_protocol::ManagedChatgptAccountUsageState,
) -> &'static str {
    match state {
        codex_app_server_protocol::ManagedChatgptAccountUsageState::Unknown => "unknown",
        codex_app_server_protocol::ManagedChatgptAccountUsageState::Fresh => "fresh",
        codex_app_server_protocol::ManagedChatgptAccountUsageState::Stale => "stale",
        codex_app_server_protocol::ManagedChatgptAccountUsageState::Unavailable => "unavailable",
    }
}

fn format_refresh_status(
    status: &codex_app_server_protocol::ManagedChatgptAccountRefreshStatus,
) -> String {
    match status {
        codex_app_server_protocol::ManagedChatgptAccountRefreshStatus::Healthy => {
            "healthy".to_string()
        }
        codex_app_server_protocol::ManagedChatgptAccountRefreshStatus::TransientUnavailable {
            observed_at,
        } => format!(
            "temporarily unavailable (observed {})",
            format_observed_at(*observed_at).unwrap_or_else(|| "at an unknown time".to_string())
        ),
        codex_app_server_protocol::ManagedChatgptAccountRefreshStatus::ReloginRequired {
            reason_code,
            observed_at,
        } => format!(
            "sign-in required ({reason_code}; observed {})",
            format_observed_at(*observed_at).unwrap_or_else(|| "at an unknown time".to_string())
        ),
    }
}

fn format_managed_window(window: Option<&codex_app_server_protocol::RateLimitWindow>) -> String {
    let Some(window) = window else {
        return "unavailable".to_string();
    };
    let label = match window.window_duration_mins {
        Some(300) => "5h".to_string(),
        Some(10_080) => "weekly".to_string(),
        Some(minutes) if minutes % 1_440 == 0 => format!("{}d", minutes / 1_440),
        Some(minutes) if minutes % 60 == 0 => format!("{}h", minutes / 60),
        Some(minutes) => format!("{minutes}m"),
        None => "window".to_string(),
    };
    let remaining = (100 - window.used_percent).clamp(0, 100);
    let reset = window
        .resets_at
        .and_then(format_observed_at)
        .map(|value| format!(", resets {value}"))
        .unwrap_or_else(|| ", reset unknown".to_string());
    format!("{label}: {remaining}% left{reset}")
}

fn format_observed_at(timestamp: i64) -> Option<String> {
    chrono::DateTime::<Utc>::from_timestamp(timestamp, 0)
        .map(|value| value.format("%Y-%m-%d %H:%M UTC").to_string())
}
