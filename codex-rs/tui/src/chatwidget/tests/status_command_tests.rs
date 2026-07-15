use super::*;
use assert_matches::assert_matches;
use codex_utils_path_uri::PathUri;

fn managed_status_account() -> codex_app_server_protocol::ManagedChatgptAccountView {
    codex_app_server_protocol::ManagedChatgptAccountView {
        managed_account_id: "managed-b".to_string(),
        chatgpt_account_id: Some("workspace-b".to_string()),
        email: Some("b@example.com".to_string()),
        plan_type: codex_protocol::account::PlanType::Plus,
        eligible: true,
        eligibility_reason: None,
        account_revision: 1,
        credential_revision: 1,
        refresh_status: codex_app_server_protocol::ManagedChatgptAccountRefreshStatus::Healthy,
        block: None,
        usage: codex_app_server_protocol::ManagedChatgptAccountUsage {
            state: codex_app_server_protocol::ManagedChatgptAccountUsageState::Fresh,
            rate_limits: Vec::new(),
            token_usage: None,
            observed_at: None,
            unavailable_reason: None,
            unavailable_observed_at: None,
        },
    }
}

fn install_managed_status_account(chat: &mut ChatWidget) {
    chat.replace_managed_accounts(codex_app_server_protocol::ListAccountsResponse {
        accounts: vec![managed_status_account()],
        selected_account_id: Some("managed-b".to_string()),
        pool_revision: 1,
        selection_revision: Some(1),
    });
}

#[tokio::test]
async fn status_command_renders_immediately_and_refreshes_rate_limits_for_chatgpt_auth() {
    let (mut chat, mut rx, _op_rx) = make_chatwidget_manual(/*model_override*/ None).await;
    set_chatgpt_auth(&mut chat);

    chat.dispatch_command(SlashCommand::Status);
    let rendered = match rx.try_recv() {
        Ok(AppEvent::InsertHistoryCell(cell)) => {
            lines_to_single_string(&cell.display_lines(/*width*/ 80))
        }
        other => panic!("expected immediate status output, got {other:?}"),
    };
    assert_matches!(
        rx.try_recv(),
        Ok(AppEvent::RefreshRateLimits {
            origin: RateLimitRefreshOrigin::StatusCommand { .. }
        })
    );
    assert!(
        !rendered.contains("refreshing limits"),
        "expected /status to avoid transient refresh text in terminal history, got: {rendered}"
    );
}

#[tokio::test]
async fn status_command_refresh_updates_cached_limits_for_future_status_outputs() {
    let (mut chat, mut rx, _op_rx) = make_chatwidget_manual(/*model_override*/ None).await;
    set_chatgpt_auth(&mut chat);
    install_managed_status_account(&mut chat);

    chat.dispatch_command(SlashCommand::Status);
    assert_matches!(rx.try_recv(), Ok(AppEvent::RefreshManagedAccountsForStatus));
    chat.add_status_output(
        /*refreshing_rate_limits*/ false, /*request_id*/ None,
    );
    match rx.try_recv() {
        Ok(AppEvent::InsertHistoryCell(_)) => {}
        other => panic!("expected status output after account refresh, got {other:?}"),
    }
    let mut refreshed_account = managed_status_account();
    refreshed_account.account_revision = 2;
    refreshed_account.usage.rate_limits = vec![snapshot(/*percent*/ 92.0)];
    chat.replace_managed_accounts(codex_app_server_protocol::ListAccountsResponse {
        accounts: vec![refreshed_account],
        selected_account_id: Some("managed-b".to_string()),
        pool_revision: 2,
        selection_revision: Some(1),
    });
    drain_insert_history(&mut rx);

    chat.dispatch_command(SlashCommand::Status);
    assert_matches!(rx.try_recv(), Ok(AppEvent::RefreshManagedAccountsForStatus));
    chat.add_status_output(
        /*refreshing_rate_limits*/ false, /*request_id*/ None,
    );
    let refreshed = match rx.try_recv() {
        Ok(AppEvent::InsertHistoryCell(cell)) => {
            lines_to_single_string(&cell.display_lines(/*width*/ 80))
        }
        other => panic!("expected refreshed status output, got {other:?}"),
    };
    assert!(
        refreshed.contains("8% left"),
        "expected a future /status output to use refreshed cached limits, got: {refreshed}"
    );
}

#[tokio::test]
async fn status_command_renders_immediately_without_rate_limit_refresh() {
    let (mut chat, mut rx, _op_rx) = make_chatwidget_manual(/*model_override*/ None).await;

    chat.dispatch_command(SlashCommand::Status);

    assert_matches!(rx.try_recv(), Ok(AppEvent::InsertHistoryCell(_)));
    assert!(
        !std::iter::from_fn(|| rx.try_recv().ok())
            .any(|event| matches!(event, AppEvent::RefreshRateLimits { .. })),
        "non-ChatGPT sessions should not request a rate-limit refresh for /status"
    );
}

#[tokio::test]
async fn status_command_uses_catalog_default_reasoning_when_config_empty() {
    let (mut chat, mut rx, _op_rx) = make_chatwidget_manual(Some("gpt-5.4")).await;
    chat.config.model_reasoning_effort = None;

    chat.dispatch_command(SlashCommand::Status);

    let rendered = match rx.try_recv() {
        Ok(AppEvent::InsertHistoryCell(cell)) => {
            lines_to_single_string(&cell.display_lines(/*width*/ 80))
        }
        other => panic!("expected status output, got {other:?}"),
    };
    assert!(
        rendered.contains("gpt-5.4 (reasoning medium, summaries auto)"),
        "expected /status to render the catalog default reasoning effort, got: {rendered}"
    );
}

#[tokio::test]
async fn status_command_renders_native_and_foreign_instruction_sources() {
    let (mut chat, mut rx, _op_rx) = make_chatwidget_manual(/*model_override*/ None).await;
    let (foreign_source, foreign_display) = if cfg!(windows) {
        (
            PathUri::parse("file:///remote/AGENTS.md").expect("POSIX instruction source"),
            "/remote/AGENTS.md",
        )
    } else {
        (
            PathUri::parse("file:///C:/remote/AGENTS.md").expect("Windows instruction source"),
            r"C:\remote\AGENTS.md",
        )
    };
    chat.instruction_source_paths = vec![
        PathUri::from_abs_path(&chat.config.cwd.join("AGENTS.md")),
        foreign_source,
    ];

    chat.dispatch_command(SlashCommand::Status);

    let rendered = match rx.try_recv() {
        Ok(AppEvent::InsertHistoryCell(cell)) => {
            lines_to_single_string(&cell.display_lines(/*width*/ 80))
        }
        other => panic!("expected status output, got {other:?}"),
    };
    assert!(
        rendered.contains(&format!("AGENTS.md, {foreign_display}")),
        "expected /status to show native-relative and environment-native foreign paths, got: {rendered}"
    );
    assert!(
        !rendered.contains("Agents.md  <none>"),
        "expected /status to avoid stale <none> when app-server provided instruction sources, got: {rendered}"
    );
}

#[tokio::test]
async fn status_command_overlapping_managed_refreshes_render_each_output() {
    let (mut chat, mut rx, _op_rx) = make_chatwidget_manual(/*model_override*/ None).await;
    set_chatgpt_auth(&mut chat);
    install_managed_status_account(&mut chat);

    chat.dispatch_command(SlashCommand::Status);
    assert_matches!(rx.try_recv(), Ok(AppEvent::RefreshManagedAccountsForStatus));
    chat.add_status_output(
        /*refreshing_rate_limits*/ false, /*request_id*/ None,
    );
    match rx.try_recv() {
        Ok(AppEvent::InsertHistoryCell(_)) => {}
        other => panic!("expected first status output, got {other:?}"),
    }

    chat.dispatch_command(SlashCommand::Status);
    assert_matches!(rx.try_recv(), Ok(AppEvent::RefreshManagedAccountsForStatus));
    chat.add_status_output(
        /*refreshing_rate_limits*/ false, /*request_id*/ None,
    );
    let second_rendered = match rx.try_recv() {
        Ok(AppEvent::InsertHistoryCell(cell)) => {
            lines_to_single_string(&cell.display_lines(/*width*/ 80))
        }
        other => panic!("expected second status output, got {other:?}"),
    };
    assert!(
        !second_rendered.contains("refreshing limits"),
        "expected /status to avoid transient refresh text in terminal history, got: {second_rendered}"
    );
    assert!(chat.refreshing_status_outputs.is_empty());
}

#[tokio::test]
async fn account_update_clears_stale_status_rate_limit_snapshots() {
    let (mut chat, mut rx, _op_rx) = make_chatwidget_manual(/*model_override*/ None).await;
    set_chatgpt_auth(&mut chat);
    install_managed_status_account(&mut chat);
    chat.dispatch_command(SlashCommand::Status);
    assert_matches!(rx.try_recv(), Ok(AppEvent::RefreshManagedAccountsForStatus));
    chat.add_status_output(
        /*refreshing_rate_limits*/ false, /*request_id*/ None,
    );
    assert_matches!(rx.try_recv(), Ok(AppEvent::InsertHistoryCell(_)));
    chat.on_rate_limit_snapshot(Some(snapshot(/*percent*/ 92.0)));

    chat.update_account_state(
        /*status_account_display*/ None, /*plan_type*/ None,
        /*has_chatgpt_account*/ true, /*has_codex_backend_auth*/ true,
    );

    assert!(chat.rate_limit_snapshots_by_limit_id.is_empty());
}
