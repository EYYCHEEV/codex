use super::*;
use crate::app_server_session::ThreadParamsMode;
use codex_app_server_client::AppServerEvent;
use codex_app_server_protocol::AccountPoolUpdatedNotification;
use codex_app_server_protocol::AccountSelectionUpdatedNotification;
use codex_app_server_protocol::JSONRPCMessage;
use codex_app_server_protocol::ListAccountsParams;
use codex_app_server_protocol::ListAccountsResponse;
use futures::SinkExt;
use futures::StreamExt;
use pretty_assertions::assert_eq;
use serde_json::Value;
use serde_json::json;
use tokio::net::TcpListener;
use tokio::sync::oneshot;
use tokio::task::JoinHandle;
use tokio_tungstenite::tungstenite::Message;

fn quota_account(id: &str) -> Value {
    json!({
        "managedAccountId": id, "chatgptAccountId": "workspace", "email": id,
        "planType": "plus", "eligible": false, "eligibilityReason": "blocked",
        "accountRevision": 2, "credentialRevision": 1,
        "refreshStatus": {"type": "healthy"},
        "block": {"reason": "quota", "blockedUntil": null},
        "usage": {"state": "unknown", "rateLimits": [], "tokenUsage": null,
            "observedAt": null, "unavailableReason": null, "unavailableObservedAt": null}
    })
}

fn blocked_inventory() -> Value {
    json!({
        "accounts": [quota_account("saved@example.test")],
        "selectedAccountId": null, "selectionRevision": null, "poolRevision": 3
    })
}

fn recovered_inventory() -> ListAccountsResponse {
    let mut inventory = blocked_inventory();
    let account = &mut inventory["accounts"][0];
    account["eligible"] = json!(true);
    account["eligibilityReason"] = Value::Null;
    account["block"] = Value::Null;
    account["accountRevision"] = json!(3);
    account["usage"]["state"] = json!("fresh");
    account["usage"]["rateLimits"] = json!([{
        "limitId": "codex", "limitName": "codex",
        "primary": {"usedPercent": 95, "windowDurationMins": 300, "resetsAt": null}
    }]);
    inventory["selectedAccountId"] = json!("saved@example.test");
    inventory["selectionRevision"] = json!(1);
    inventory["poolRevision"] = json!(4);
    serde_json::from_value(inventory).expect("recovered owner response")
}

async fn pool_app(inventory: Value) -> (Box<App>, tokio::sync::mpsc::UnboundedReceiver<AppEvent>) {
    let (mut app, events, _ops) = make_test_app_with_channels().await;
    let thread_id = ThreadId::new();
    app.active_thread_id = Some(thread_id);
    app.chat_widget
        .handle_thread_session(test_thread_session(thread_id, app.config.cwd.to_path_buf()));
    app.chat_widget.set_model("gpt-5.6-sol");
    set_chatgpt_auth(&mut app.chat_widget);
    app.chat_widget.enable_managed_account_updates();
    app.chat_widget
        .replace_managed_accounts(serde_json::from_value(inventory).expect("managed inventory"));
    (app, events)
}

struct HeldUsageServer {
    session: AppServerSession,
    server: JoinHandle<Result<Vec<Value>>>,
    first_request_rx: oneshot::Receiver<()>,
    release_tx: oneshot::Sender<()>,
}

async fn held_usage_server(list_reply: Value) -> Result<HeldUsageServer> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let endpoint = crate::resolve_remote_addr(&format!("ws://{}", listener.local_addr()?))?;
    let (first_request_tx, first_request_rx) = oneshot::channel();
    let (release_tx, release_rx) = oneshot::channel();
    let server = tokio::spawn(async move {
        let (stream, _) = listener.accept().await?;
        let mut socket = tokio_tungstenite::accept_async(stream).await?;
        let mut requests = Vec::new();
        let mut first_request_tx = Some(first_request_tx);
        let mut release_rx = Some(release_rx);
        while let Some(Ok(Message::Text(text))) = socket.next().await {
            let JSONRPCMessage::Request(request) = serde_json::from_str(&text)? else {
                continue;
            };
            let mut reply = match request.method.as_str() {
                "initialize" => json!({"result": {"userAgent": "managed-pool-recovery-test"}}),
                "account/read" => json!({"result": {
                    "account": null, "requiresOpenaiAuth": true, "workspaceRouting": null
                }}),
                _ => {
                    requests.push(json!({"method": request.method, "params": request.params}));
                    if let Some(sender) = first_request_tx.take() {
                        let _ = sender.send(());
                        release_rx.take().expect("first request barrier").await?;
                    }
                    match request.method.as_str() {
                        "account/list" => list_reply.clone(),
                        // Answer the wrong method too, so regressions fail assertions, not time out.
                        "account/rateLimits/read" => json!({"result": {
                            "rateLimits": {}, "rateLimitsByLimitId": null,
                            "rateLimitResetCredits": null
                        }}),
                        "account/logout" => json!({"result": {
                            "accounts": [], "selectedAccountId": null
                        }}),
                        _ => json!({"error": {"code": -32000, "message": "unexpected test RPC"}}),
                    }
                }
            };
            reply["id"] = json!(request.id);
            socket.send(Message::Text(reply.to_string().into())).await?;
        }
        Ok(requests)
    });
    let session = AppServerSession::new(
        crate::connect_remote_app_server(endpoint).await?,
        ThreadParamsMode::Embedded,
    );
    Ok(HeldUsageServer {
        session,
        server,
        first_request_rx,
        release_tx,
    })
}

async fn next_usage_event(
    events: &mut tokio::sync::mpsc::UnboundedReceiver<AppEvent>,
) -> Result<AppEvent> {
    Ok(tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            let event = events.recv().await.expect("refresh completion event");
            if matches!(
                event,
                AppEvent::RateLimitsLoaded { .. }
                    | AppEvent::ManagedAccountsLoadedForCache { .. }
                    | AppEvent::ManagedAccountsLoadedForStatus { .. }
            ) {
                break event;
            }
        }
    })
    .await?)
}

async fn captured_requests(
    mut session: AppServerSession,
    server: JoinHandle<Result<Vec<Value>>>,
) -> Result<Vec<Value>> {
    tokio::time::timeout(Duration::from_secs(5), async {
        session.read_account().await?;
        session.shutdown().await?;
        server.await?
    })
    .await?
}

async fn periodic_requests(inventory: Value) -> Result<(Vec<Value>, ListAccountsParams)> {
    tokio::time::timeout(Duration::from_secs(/*secs*/ 10), async {
        let (mut app, mut events) = pool_app(inventory.clone()).await;
        let expected_params = ListAccountsParams {
            thread_id: app.chat_widget.thread_id().map(|id| id.to_string()),
            model: Some(app.chat_widget.current_model().to_string()),
            refresh_tokens: false,
            refresh_usage: true,
        };
        let interval = app
            .chat_widget
            .rate_limit_refresh_interval()
            .expect("ChatGPT pool should retain its periodic polling opportunity");
        assert!(
            app.rate_limit_refresh_state
                .poll_deadline(interval)
                .is_some()
        );
        while events.try_recv().is_ok() {}

        let HeldUsageServer {
            session,
            server,
            first_request_rx,
            release_tx,
        } = held_usage_server(json!({"result": inventory})).await?;

        // This is the production periodic timer dispatch in app/startup.rs, not a direct
        // managed-list helper. The wire reply remains held while subsequent ticks fire.
        app.refresh_rate_limits(&session, RateLimitRefreshOrigin::Periodic);
        first_request_rx.await?;
        for _ in 0..3 {
            app.refresh_rate_limits(&session, RateLimitRefreshOrigin::Periodic);
        }
        let coalesced_deadline = app.rate_limit_refresh_state.poll_deadline(interval);
        release_tx.send(()).expect("release held usage reply");
        let event = next_usage_event(&mut events).await?;
        match event {
            AppEvent::RateLimitsLoaded { result, .. } => assert!(result.is_ok()),
            AppEvent::ManagedAccountsLoadedForCache { result, .. } => assert!(result.is_ok()),
            _ => panic!("unexpected completion"),
        }
        let requests = captured_requests(session, server).await?;
        assert!(
            coalesced_deadline.is_none(),
            "pending usage read must suppress timer ticks"
        );
        Ok((requests, expected_params))
    })
    .await?
}

#[tokio::test]
async fn managed_pool_recovery_periodic_tick_uses_scoped_usage_only_list_and_coalesces()
-> Result<()> {
    let (requests, expected_params) = periodic_requests(json!({
        "accounts": [quota_account("saved@example.test")],
        "selectedAccountId": null, "selectionRevision": null, "poolRevision": 3
    }))
    .await?;
    assert_eq!(
        requests
            .iter()
            .map(|request| request["method"].as_str().unwrap())
            .collect::<Vec<_>>(),
        ["account/list"],
        "a saved quota-blocked pool needs one usage-only managed read, not singular usage"
    );
    // False is omitted on the wire. Deserialize instead of demanding a literal false key.
    assert_eq!(
        serde_json::from_value::<ListAccountsParams>(requests[0]["params"].clone())?,
        expected_params
    );
    Ok(())
}

#[tokio::test]
async fn managed_pool_recovery_eligible_timeout_uncertain_row_gets_usage_only_probe() -> Result<()>
{
    let mut uncertain = quota_account("uncertain@example.test");
    uncertain["eligible"] = json!(true);
    uncertain["eligibilityReason"] = Value::Null;
    uncertain["block"] = Value::Null;
    uncertain["refreshStatus"] = json!({
        "type": "reloginRequired", "reasonCode": "token_refresh_timeout", "observedAt": 1
    });
    let mut healthy = uncertain.clone();
    healthy["managedAccountId"] = json!("healthy@example.test");
    healthy["email"] = json!("healthy@example.test");
    healthy["refreshStatus"] = json!({"type": "healthy"});
    for accounts in [vec![uncertain.clone()], vec![uncertain, healthy]] {
        let (requests, expected_params) = periodic_requests(json!({
            "accounts": accounts, "selectedAccountId": "uncertain@example.test",
            "selectionRevision": 1, "poolRevision": 3
        }))
        .await?;
        assert_eq!(
            requests,
            vec![json!({
                "method": "account/list",
                "params": serde_json::to_value(expected_params)?
            })],
            "eligible uncertain credentials need one coalesced usage-only pool probe, even with a healthy sibling"
        );
    }
    Ok(())
}

#[tokio::test]
async fn managed_pool_recovery_healthy_pool_keeps_single_normal_periodic_read() -> Result<()> {
    let (requests, _) = periodic_requests(serde_json::to_value(recovered_inventory())?).await?;
    assert_eq!(
        requests,
        vec![json!({
            "method": "account/rateLimits/read",
            "params": {"supportsLunaReserve": true, "excludeResetCreditDetails": true}
        })]
    );
    Ok(())
}

#[tokio::test]
async fn managed_pool_recovery_eligible_sibling_keeps_single_healthy_periodic_read() -> Result<()> {
    let mut eligible = quota_account("eligible@example.test");
    eligible["eligible"] = json!(true);
    eligible["eligibilityReason"] = Value::Null;
    eligible["block"] = Value::Null;
    // Eligibility is reported by the owner, not reconstructed from usage percentages.
    let (requests, _) = periodic_requests(json!({
        "accounts": [quota_account("blocked@example.test"), eligible],
        "selectedAccountId": "eligible@example.test", "selectionRevision": 1, "poolRevision": 3
    }))
    .await?;
    assert_eq!(
        requests,
        vec![json!({
            "method": "account/rateLimits/read",
            "params": {"supportsLunaReserve": true, "excludeResetCreditDetails": true}
        })]
    );
    Ok(())
}

async fn recovery_notifications(
    app: &mut App,
    session: &AppServerSession,
    response: &ListAccountsResponse,
) {
    let notifications = [
        ServerNotification::AccountPoolUpdated(AccountPoolUpdatedNotification {
            accounts: response.accounts.clone(),
            pool_revision: response.pool_revision,
        }),
        ServerNotification::AccountSelectionUpdated(AccountSelectionUpdatedNotification {
            thread_id: app.chat_widget.thread_id().unwrap().to_string(),
            selected_account_id: response.selected_account_id.clone(),
            selection_revision: response.selection_revision.unwrap(),
        }),
    ];
    for notification in notifications {
        app.handle_app_server_event(
            session,
            AppServerEvent::ServerNotification(Box::new(notification)),
        )
        .await;
    }
}

fn managed_status(
    app: &mut App,
    events: &mut tokio::sync::mpsc::UnboundedReceiver<AppEvent>,
) -> String {
    while events.try_recv().is_ok() {}
    app.chat_widget.add_status_output(
        /*refreshing_rate_limits*/ false, /*request_id*/ None,
    );
    loop {
        if let AppEvent::InsertHistoryCell(cell) = events.try_recv().expect("status output") {
            return cell
                .display_lines(100)
                .iter()
                .map(ToString::to_string)
                .skip_while(|line| !line.contains("saved@example.test"))
                .collect::<Vec<_>>()
                .join("\n");
        }
    }
}

#[tokio::test]
async fn managed_pool_recovery_settles_both_notification_orders_without_token_followups()
-> Result<()> {
    for notifications_first in [true, false] {
        let (mut app, mut events) = pool_app(blocked_inventory()).await;
        let recovered = recovered_inventory();
        let HeldUsageServer {
            mut session,
            server,
            first_request_rx,
            release_tx,
        } = held_usage_server(json!({"result": recovered})).await?;
        let mut tui = crate::tui::test_support::make_test_tui()?;
        let before = managed_status(&mut app, &mut events);
        app.refresh_rate_limits(&session, RateLimitRefreshOrigin::Periodic);
        tokio::time::timeout(Duration::from_secs(5), first_request_rx).await??;
        let origin = app.rate_limit_refresh_state.managed_usage.clone().unwrap();
        if notifications_first {
            recovery_notifications(&mut app, &session, &recovered).await;
            assert_eq!(
                app.rate_limit_refresh_state.managed_usage.as_ref(),
                Some(&origin)
            );
            app.refresh_rate_limits(&session, RateLimitRefreshOrigin::Periodic);
            assert!(app.rate_limit_poll_deadline().is_none());
        }
        release_tx.send(()).unwrap();
        let loaded = next_usage_event(&mut events).await?;
        assert_matches!(
            &loaded,
            AppEvent::ManagedAccountsLoadedForCache { result: Ok(_), .. }
        );
        app.handle_event(&mut tui, &mut session, loaded).await?;
        if !notifications_first {
            recovery_notifications(&mut app, &session, &recovered).await;
        }
        assert_eq!(
            app.chat_widget.managed_accounts(),
            Some(&crate::status::ManagedAccountsState::from_response(
                recovered
            ))
        );
        assert!(!app.managed_usage_read_is_current());
        assert_eq!(
            app.chat_widget.rate_limit_refresh_interval(),
            Some(Duration::from_secs(15))
        );
        assert!(app.rate_limit_poll_deadline().unwrap() > std::time::Instant::now());
        let after = managed_status(&mut app, &mut events);
        insta::assert_snapshot!(
            "managed_pool_periodic_recovery_status",
            format!("Before:\n{before}\n\nAfter:\n{after}")
        );
        let requests = captured_requests(session, server).await?;
        assert_eq!(
            requests.len(),
            1,
            "settlement must not add an automatic list"
        );
        assert_eq!(requests[0]["method"], "account/list");
        let params: ListAccountsParams = serde_json::from_value(requests[0]["params"].clone())?;
        assert!(params.refresh_usage);
        assert!(!params.refresh_tokens);
    }
    Ok(())
}

#[tokio::test]
async fn managed_pool_recovery_failures_and_timeouts_release_slot_with_completion_backoff()
-> Result<()> {
    for timeout in [false, true] {
        let mut inventory = blocked_inventory();
        if timeout {
            inventory["accounts"] = json!([
                quota_account("first@example.test"),
                quota_account("second@example.test"),
                quota_account("third@example.test"),
            ]);
        }
        let (mut app, mut events) = pool_app(inventory).await;
        let HeldUsageServer {
            mut session,
            server,
            first_request_rx,
            release_tx,
        } = held_usage_server(json!({"error": {"code": -32000, "message": "usage unavailable"}}))
            .await?;
        let mut tui = crate::tui::test_support::make_test_tui()?;
        app.refresh_rate_limits(&session, RateLimitRefreshOrigin::Periodic);
        tokio::time::timeout(Duration::from_secs(5), first_request_rx).await??;
        let mut release_tx = Some(release_tx);
        if timeout {
            // Advance only the Tokio RPC timeout, never the std::Instant retry scheduler.
            tokio::time::pause();
            tokio::time::advance(Duration::from_secs(36)).await;
            tokio::task::yield_now().await;
            while let Ok(event) = events.try_recv() {
                assert!(
                    !matches!(event, AppEvent::ManagedAccountsLoadedForCache { .. }),
                    "three accounts need more than a single-account timeout budget"
                );
            }
            tokio::time::advance(app.managed_usage_timeout() + Duration::from_secs(1)).await;
            tokio::time::resume();
        } else {
            release_tx.take().unwrap().send(()).unwrap();
        }
        let loaded = next_usage_event(&mut events).await?;
        assert_matches!(
            &loaded,
            AppEvent::ManagedAccountsLoadedForCache { result: Err(_), .. }
        );
        let before = std::time::Instant::now();
        app.handle_event(&mut tui, &mut session, loaded).await?;
        let after = std::time::Instant::now();
        assert!(!app.managed_usage_read_is_current());
        let deadline = app.rate_limit_poll_deadline().unwrap();
        assert!(deadline >= before + Duration::from_secs(60));
        assert!(deadline <= after + Duration::from_secs(60));
        for _ in 0..3 {
            app.refresh_rate_limits(&session, RateLimitRefreshOrigin::Periodic);
        }
        if timeout {
            // The client timeout does not cancel server work; a late reply must not trigger OAuth.
            release_tx.take().unwrap().send(()).unwrap();
            recovery_notifications(&mut app, &session, &recovered_inventory()).await;
            let followup = next_usage_event(&mut events).await?;
            app.handle_event(&mut tui, &mut session, followup).await?;
        }
        let requests = captured_requests(session, server).await?;
        assert_eq!(
            requests.len(),
            if timeout { 2 } else { 1 },
            "only the late binding notification may request another observation"
        );
        for request in requests {
            assert_eq!(
                request["method"], "account/list",
                "no singular auth or notice reads"
            );
            let params: ListAccountsParams = serde_json::from_value(request["params"].clone())?;
            assert!(params.refresh_usage);
            assert!(!params.refresh_tokens);
        }
    }
    Ok(())
}

#[test]
fn managed_pool_recovery_backoff_is_completion_based_capped_and_resets() {
    let mut state = crate::app::rate_limit_refresh::RateLimitRefreshState::default();
    let mut now = std::time::Instant::now();
    let origin = ManagedAccountRequestOrigin {
        thread_id: Some(ThreadId::new()),
        model: "gpt-5.6-sol".into(),
        scope_generation: 1,
        request_id: 1,
    };
    for seconds in [60, 120, 240, 300, 300] {
        state.managed_usage = Some(origin.clone());
        assert_eq!(state.managed_poll_deadline(now), None);
        // Completing at an explicit time tests the same deadline owner used by the real timer.
        state.finish_managed_usage(/*retry_needed*/ true, now);
        let deadline = now + Duration::from_secs(seconds);
        assert_eq!(state.managed_poll_deadline(now), Some(deadline));
        now = deadline;
    }
    state.finish_managed_usage(/*retry_needed*/ false, now);
    assert_eq!(
        state.poll_deadline(Duration::from_secs(60)),
        Some(now + Duration::from_secs(60))
    );
    state.finish_managed_usage(/*retry_needed*/ true, now);
    assert_eq!(
        state.managed_poll_deadline(now),
        Some(now + Duration::from_secs(60))
    );
}

#[tokio::test]
async fn managed_pool_recovery_rejects_late_results_after_scope_logout_and_disconnect() -> Result<()>
{
    for change in ["model", "thread", "logout", "disconnect"] {
        let (mut app, mut events) = pool_app(blocked_inventory()).await;
        let HeldUsageServer {
            mut session,
            server,
            first_request_rx,
            release_tx,
        } = held_usage_server(json!({"result": recovered_inventory()})).await?;
        let mut tui = crate::tui::test_support::make_test_tui()?;
        app.refresh_rate_limits(&session, RateLimitRefreshOrigin::Periodic);
        tokio::time::timeout(Duration::from_secs(5), first_request_rx).await??;
        release_tx.send(()).unwrap();
        let loaded = next_usage_event(&mut events).await?;
        match change {
            "model" => app.chat_widget.set_model("other-model"),
            "thread" => {
                let thread_id = ThreadId::new();
                app.active_thread_id = Some(thread_id);
                app.chat_widget.handle_thread_session(test_thread_session(
                    thread_id,
                    app.config.cwd.to_path_buf(),
                ));
            }
            "logout" => {
                app.handle_event(
                    &mut tui,
                    &mut session,
                    AppEvent::LogoutManagedAccount {
                        managed_account_id: "saved@example.test".into(),
                    },
                )
                .await?;
            }
            "disconnect" => {
                app.app_server_target = crate::AppServerTarget::Remote {
                    endpoint: crate::resolve_remote_addr("ws://127.0.0.1:1")?,
                };
                app.handle_app_server_event(
                    &session,
                    AppServerEvent::Disconnected {
                        message: "synthetic disconnect".into(),
                    },
                )
                .await;
                assert!(app.rate_limit_poll_deadline().is_none());
            }
            _ => unreachable!(),
        }
        app.handle_event(&mut tui, &mut session, loaded).await?;
        assert!(!app.managed_usage_read_is_current(), "{change}");
        assert!(
            app.chat_widget
                .managed_accounts()
                .is_none_or(|pool| { !pool.accounts().any(|account| account.eligible) }),
            "stale recovery must not install rows after {change}"
        );
        for request in captured_requests(session, server).await? {
            if request["method"] == "account/list" {
                let params: ListAccountsParams = serde_json::from_value(request["params"].clone())?;
                assert!(!params.refresh_tokens, "{change}");
            }
        }
    }
    Ok(())
}

#[tokio::test]
async fn managed_pool_recovery_does_not_probe_permanently_ineligible_or_empty_pools() -> Result<()>
{
    let blocked = quota_account("saved@example.test");
    let mut relogin = blocked.clone();
    relogin["refreshStatus"] =
        json!({"type": "reloginRequired", "reasonCode": "refresh_token_reused", "observedAt": 1});
    let mut restricted = blocked.clone();
    restricted["eligibilityReason"] = json!("forced_workspace_disallowed");
    let mut restricted_timeout = restricted.clone();
    restricted_timeout["refreshStatus"] =
        json!({"type": "reloginRequired", "reasonCode": "token_refresh_timeout", "observedAt": 1});
    let mut removed = blocked.clone();
    removed["eligibilityReason"] = json!("pending_removal");
    let mut invalid = blocked.clone();
    invalid["block"]["reason"] = json!("auth_invalid");
    // Personal quota observations cannot prove that shared workspace credits recovered.
    let mut workspace = blocked;
    workspace["block"]["reason"] = json!("workspace");
    for accounts in [
        vec![],
        vec![relogin],
        vec![restricted],
        vec![restricted_timeout],
        vec![removed],
        vec![invalid],
        vec![workspace],
    ] {
        let (requests, _) = periodic_requests(json!({
            "accounts": accounts, "selectedAccountId": null,
            "selectionRevision": null, "poolRevision": 3
        }))
        .await?;
        assert_eq!(requests.len(), 1);
        assert_eq!(requests[0]["method"], "account/rateLimits/read");
    }
    Ok(())
}

#[tokio::test]
async fn managed_pool_recovery_coalesces_with_manual_status_usage_read() -> Result<()> {
    let (mut app, mut events) = pool_app(blocked_inventory()).await;
    let HeldUsageServer {
        mut session,
        server,
        first_request_rx,
        release_tx,
    } = held_usage_server(json!({"result": blocked_inventory()})).await?;
    let mut tui = crate::tui::test_support::make_test_tui()?;
    app.handle_event(
        &mut tui,
        &mut session,
        AppEvent::RefreshManagedAccountsForStatus,
    )
    .await?;
    tokio::time::timeout(Duration::from_secs(5), first_request_rx).await??;
    for _ in 0..3 {
        app.refresh_rate_limits(&session, RateLimitRefreshOrigin::Periodic);
    }
    assert!(app.rate_limit_poll_deadline().is_none());
    release_tx.send(()).unwrap();
    let loaded = next_usage_event(&mut events).await?;
    assert_matches!(
        &loaded,
        AppEvent::ManagedAccountsLoadedForStatus { result: Ok(_), .. }
    );
    app.handle_event(&mut tui, &mut session, loaded).await?;
    assert!(app.rate_limit_poll_deadline().unwrap() > std::time::Instant::now());
    let requests = captured_requests(session, server).await?;
    assert_eq!(requests.len(), 1);
    let params: ListAccountsParams = serde_json::from_value(requests[0]["params"].clone())?;
    assert!(params.refresh_usage);
    assert!(
        params.refresh_tokens,
        "explicit /status retains its credential-refresh behavior"
    );
    Ok(())
}
