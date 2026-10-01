use super::*;
use app_test_support::ChatGptIdTokenClaims;
use app_test_support::create_fake_rollout;
use app_test_support::encode_id_token;
use app_test_support::rollout_path;
use app_test_support::write_models_cache;
use codex_app_server_client::AppServerEvent;
use codex_app_server_protocol::AccountAnalyticsQuery;
use codex_app_server_protocol::AccountAnalyticsReadParams;
use codex_app_server_protocol::AccountAnalyticsReadResponse;
use codex_app_server_protocol::AccountPoolUpdatedNotification;
use codex_app_server_protocol::AccountSelectionUpdatedNotification;
use codex_app_server_protocol::ClientRequest;
use codex_app_server_protocol::ListAccountsParams;
use codex_app_server_protocol::ListAccountsResponse;
use codex_http_client::NetworkPolicyController;
use codex_login::ManagedChatgptOauthCredentials;
use codex_login::ManagedChatgptSelectionScope;
use codex_login::token_data::TokenData;
use codex_login::token_data::parse_chatgpt_jwt_claims;
use pretty_assertions::assert_eq;
use serde_json::json;
use wiremock::Mock;
use wiremock::MockServer;
use wiremock::ResponseTemplate;
use wiremock::matchers::method;
use wiremock::matchers::path;
use wiremock::matchers::path_regex;

const THREAD: &str = "00000000-0000-4000-8000-000000000002";

struct Fixture {
    app: App,
    server: AppServerSession,
    tui: tui::Tui,
    backend: MockServer,
}

async fn fixture() -> Result<Fixture> {
    let mut app = super::super::test_support::make_test_app().await;
    let home = app.config.codex_home.to_path_buf();
    let backend = MockServer::start().await;
    std::fs::write(
        home.join("config.toml"),
        format!(
            "model = 'gpt-5.1'\nmodel_provider = 'fixture'\ncli_auth_credentials_store = 'file'\n\
             chatgpt_base_url = '{0}/backend-api'\nmcp_oauth_credentials_store = 'file'\n\
             [features]\nremote_models = false\nresponses_websockets_v2 = false\n\
             [model_providers.fixture]\nname = 'OpenAI'\nrequires_openai_auth = true\n\
             wire_api = 'responses'\nbase_url = '{0}/backend-api/codex'\nsupports_websockets = false\n",
            backend.uri()
        ),
    )?;
    let workspace = home.join("workspace");
    std::fs::create_dir(&workspace)?;
    crate::legacy_core::config::set_project_trust_level(
        &home,
        &workspace,
        codex_protocol::config_types::TrustLevel::Trusted,
    )
    .map_err(std::io::Error::other)?;
    app.config = ConfigBuilder::default()
        .codex_home(home.clone())
        .harness_overrides(ConfigOverrides {
            cwd: Some(workspace.clone()),
            ..Default::default()
        })
        .loader_overrides(LoaderOverrides::without_managed_config_for_tests())
        .build()
        .await?;
    app.launch_cwd = workspace;
    for (email, account, user, token) in [
        (
            "a-scoped@example.test",
            "workspace-scoped",
            "user-b",
            "access-b",
        ),
        (
            "z-global@example.test",
            "workspace-global",
            "user-a",
            "access-a",
        ),
    ] {
        let jwt = encode_id_token(
            &ChatGptIdTokenClaims::new()
                .email(email)
                .chatgpt_account_id(account)
                .chatgpt_user_id(user)
                .plan_type("plus"),
        )
        .expect("encode synthetic identity");
        app_test_support::upsert_managed_chatgpt_oauth(
            &app.config,
            ManagedChatgptOauthCredentials {
                tokens: TokenData {
                    id_token: parse_chatgpt_jwt_claims(&jwt)?,
                    access_token: token.to_string(),
                    refresh_token: format!("refresh-{token}"),
                    account_id: Some(account.to_string()),
                },
                last_refresh: chrono::Utc::now(),
                oauth_api_key: None,
            },
        )
        .await?;
    }
    let emails = app_test_support::managed_chatgpt_selection_emails(
        &app.config,
        &ManagedChatgptSelectionScope {
            thread_id: Some(THREAD.into()),
            session_id: Some(THREAD.into()),
            model: Some("gpt-5.1".into()),
            ..Default::default()
        },
    )
    .await?;
    assert_eq!(
        emails,
        (
            Some("z-global@example.test".into()),
            Some("a-scoped@example.test".into())
        ),
    );
    Mock::given(method("GET"))
        .and(path_regex("^/(backend-api/wham|api/codex)/accounts/check$"))
        .respond_with(|request: &wiremock::Request| {
            let account = request.headers.get("chatgpt-account-id").map(|value| value.to_str().unwrap())
                .unwrap_or_else(|| match request.headers.get("authorization").unwrap().to_str().unwrap() {
                    "Bearer access-b" => "workspace-scoped",
                    "Bearer access-a" => "workspace-global",
                    _ => panic!("unexpected synthetic account credential"),
                });
            ResponseTemplate::new(/*s*/ 200).set_body_json(json!({"accounts": [{
                "id": account, "plan_type": "plus", "workspace_backend_origin": "https://chatgpt.com",
                "account_routing_override": "NO_CONSTRAINT",
            }]}))
        })
        .mount(&backend)
        .await;
    Mock::given(method("GET"))
        .and(path("/backend-api/wham/config/bundle"))
        .respond_with(ResponseTemplate::new(/*s*/ 200).set_body_json(json!({})))
        .mount(&backend)
        .await;
    Mock::given(method("GET"))
        .and(path("/backend-api/wham/profiles/me"))
        .respond_with(ResponseTemplate::new(/*s*/ 200).set_body_json(json!({"stats": {}})))
        .mount(&backend)
        .await;
    Mock::given(method("GET"))
        .and(path_regex("^/backend-api/wham/(usage|analytics)/"))
        .respond_with(ResponseTemplate::new(/*s*/ 200).set_body_json(json!({"data": []})))
        .mount(&backend)
        .await;
    let timestamp = "2025-01-05T12-00-00";
    let generated = create_fake_rollout(
        &home,
        timestamp,
        "2025-01-05T12:00:00Z",
        "Analytics fixture",
        Some("fixture"),
        /*git_info*/ None,
    )
    .expect("create synthetic rollout");
    let generated_path = rollout_path(&home, timestamp, &generated);
    let saved = std::fs::read_to_string(&generated_path)?.replace(&generated, THREAD);
    let saved_path = rollout_path(&home, timestamp, THREAD);
    std::fs::rename(generated_path, &saved_path)?;
    std::fs::write(&saved_path, saved)?;
    write_models_cache(&home).await?;
    let mut server = crate::start_embedded_app_server_for_picker(&app.config).await?;
    let mut tui = crate::tui::test_support::make_test_tui()?;
    app.harness_overrides.cwd = Some(app.config.cwd.to_path_buf());
    app.resume_target_session(
        &mut tui,
        &mut server,
        crate::resume_picker::SessionTarget {
            path: Some(saved_path),
            thread_id: ThreadId::from_string(THREAD)?,
            cwd: None,
            history_mode: None,
        },
    )
    .await?;
    let list: ListAccountsResponse = server
        .request_handle()
        .request_typed(ClientRequest::ListAccounts {
            request_id: AppServerRequestId::Integer(17),
            params: ListAccountsParams {
                thread_id: Some(THREAD.into()),
                ..Default::default()
            },
        })
        .await?;
    assert_eq!(
        list.selected_account_id.as_deref(),
        Some("email:a-scoped@example.test")
    );
    assert_eq!(
        app.chat_widget.thread_id(),
        Some(ThreadId::from_string(THREAD)?)
    );
    app.chat_widget
        .apply_account_pool_update(list.accounts, list.pool_revision);
    app.chat_widget.apply_account_selection_update(
        THREAD,
        list.selected_account_id,
        list.selection_revision.unwrap(),
    );
    // The local default-account route is unavailable. Only the connected server's
    // admitted selected-account policy may carry Analytics requests.
    let local_default_policy = NetworkPolicyController::default();
    app.config.application_network_policy = local_default_policy.policy();
    Ok(Fixture {
        app,
        server,
        tui,
        backend,
    })
}

#[tokio::test]
async fn analytics_uses_session_selected_account_and_policy_not_local_default() -> Result<()> {
    let Fixture {
        mut app,
        mut server,
        mut tui,
        backend,
        ..
    } = fixture().await?;
    app.handle_event(
        &mut tui,
        &mut server,
        AppEvent::OpenAnalytics { view: None },
    )
    .await?;
    let screen = tokio::time::timeout(Duration::from_secs(/*secs*/ 10), async {
        loop {
            let Some(Overlay::Analytics(view)) = app.overlay.as_mut() else {
                panic!("Analytics overlay");
            };
            view.handle_event(&mut tui, TuiEvent::Draw)?;
            let buffer = crate::custom_terminal::test_support::last_rendered_buffer(&tui.terminal);
            let screen = buffer
                .content()
                .chunks(usize::from(buffer.area.width))
                .map(|row| {
                    row.iter()
                        .map(ratatui::buffer::Cell::symbol)
                        .collect::<String>()
                        .trim_end()
                        .to_string()
                })
                .collect::<Vec<_>>()
                .join("\n");
            let reports_started = backend
                .received_requests()
                .await
                .unwrap()
                .iter()
                .any(|request| request.url.path().contains("/profiles/me"));
            if (screen.contains("@example.test") && reports_started)
                || screen.contains("Couldn't load account plan")
            {
                break Ok::<_, std::io::Error>(screen);
            }
            tokio::time::sleep(Duration::from_millis(/*millis*/ 5)).await;
        }
    })
    .await??;
    assert!(
        screen.contains("a-scoped@example.test"),
        "selected B header missing:\n{screen}"
    );
    assert!(!screen.contains("z-global@example.test"));
    let requests = backend.received_requests().await.unwrap();
    let analytics_requests = requests
        .iter()
        .filter(|request| {
            request.url.path().contains("/usage/") || request.url.path().contains("/profiles/me")
        })
        .collect::<Vec<_>>();
    assert!(!analytics_requests.is_empty());
    for request in analytics_requests {
        assert_eq!(
            (
                request.headers.get("authorization").unwrap().to_str()?,
                request
                    .headers
                    .get("chatgpt-account-id")
                    .unwrap()
                    .to_str()?
            ),
            ("Bearer access-b", "workspace-scoped"),
        );
    }
    insta::assert_snapshot!(
        "analytics_selected_account_header",
        screen.lines().next().unwrap()
    );
    app.overlay = None;
    server.shutdown().await?;
    Ok(())
}

fn draw(fixture: &mut Fixture) -> Result<String> {
    let Some(Overlay::Analytics(view)) = fixture.app.overlay.as_mut() else {
        panic!("Analytics overlay");
    };
    view.handle_event(&mut fixture.tui, TuiEvent::Draw)?;
    let buffer = crate::custom_terminal::test_support::last_rendered_buffer(&fixture.tui.terminal);
    Ok(buffer
        .content()
        .chunks(usize::from(buffer.area.width))
        .map(|row| {
            row.iter()
                .map(ratatui::buffer::Cell::symbol)
                .collect::<String>()
                .trim_end()
                .to_string()
        })
        .collect::<Vec<_>>()
        .join("\n"))
}

async fn wait_for_screen(fixture: &mut Fixture, account: &str, report: &str) -> Result<String> {
    tokio::time::timeout(Duration::from_secs(/*secs*/ 10), async {
        loop {
            let screen = draw(fixture)?;
            if screen.contains(account) && screen.contains(report) && !screen.contains("Loading") {
                return Ok(screen);
            }
            tokio::time::sleep(Duration::from_millis(/*millis*/ 5)).await;
        }
    })
    .await?
}

fn key(fixture: &mut Fixture, key: char) -> Result<()> {
    let Some(Overlay::Analytics(view)) = fixture.app.overlay.as_mut() else {
        panic!("Analytics overlay");
    };
    view.handle_event(
        &mut fixture.tui,
        TuiEvent::Key(KeyEvent::new(KeyCode::Char(key), KeyModifiers::NONE)),
    )?;
    Ok(())
}

async fn rotate(fixture: &Fixture, from: &str, to: &str) -> Result<()> {
    let scope = ManagedChatgptSelectionScope {
        thread_id: Some(THREAD.into()),
        session_id: Some(THREAD.into()),
        model: Some("gpt-5.1".into()),
        ..Default::default()
    };
    let emails = app_test_support::invalidate_managed_chatgpt_account(
        &fixture.app.config,
        &format!("email:{from}"),
        &scope,
    )
    .await?;
    assert_eq!(emails, (Some(from.into()), Some(to.into())));
    Ok(())
}

async fn observe_selection(fixture: &mut Fixture, expected: &str) -> Result<()> {
    let list: ListAccountsResponse = fixture
        .server
        .request_handle()
        .request_typed(ClientRequest::ListAccounts {
            request_id: AppServerRequestId::String(uuid::Uuid::new_v4().to_string()),
            params: ListAccountsParams {
                thread_id: Some(THREAD.into()),
                ..Default::default()
            },
        })
        .await?;
    assert_eq!(list.selected_account_id.as_deref(), Some(expected));
    for notification in [
        ServerNotification::AccountPoolUpdated(AccountPoolUpdatedNotification {
            accounts: list.accounts,
            pool_revision: list.pool_revision,
        }),
        ServerNotification::AccountSelectionUpdated(AccountSelectionUpdatedNotification {
            thread_id: THREAD.into(),
            selected_account_id: list.selected_account_id,
            selection_revision: list.selection_revision.unwrap(),
        }),
    ] {
        fixture
            .app
            .handle_app_server_event(
                &fixture.server,
                AppServerEvent::ServerNotification(Box::new(notification)),
            )
            .await;
    }
    Ok(())
}

#[tokio::test]
async fn analytics_refresh_after_session_switch_never_labels_a_cached_report_as_b() -> Result<()> {
    let mut fixture = fixture().await?;
    rotate(&fixture, "a-scoped@example.test", "z-global@example.test").await?;
    observe_selection(&mut fixture, "email:z-global@example.test").await?;
    Mock::given(method("GET"))
        .and(path("/backend-api/wham/usage/daily-token-usage-breakdown"))
        .respond_with(|request: &wiremock::Request| {
            let amount = match request
                .headers
                .get("chatgpt-account-id")
                .unwrap()
                .to_str()
                .unwrap()
            {
                "workspace-global" => 120,
                "workspace-scoped" => 240,
                _ => panic!("unexpected account"),
            };
            ResponseTemplate::new(/*s*/ 200).set_body_json(json!({"data": [{
                "date": chrono::Utc::now().date_naive().to_string(),
                "product_surface_usage_values": {"cli": amount},
            }]}))
        })
        .with_priority(/*p*/ 1)
        .mount(&fixture.backend)
        .await;
    let captured_a: AccountAnalyticsReadResponse = fixture
        .server
        .request_handle()
        .request_typed(ClientRequest::AccountAnalyticsRead {
            request_id: AppServerRequestId::Integer(21),
            params: AccountAnalyticsReadParams {
                thread_id: Some(THREAD.into()),
                expected_binding: None,
                query: AccountAnalyticsQuery::Account,
            },
        })
        .await?;
    fixture
        .app
        .handle_event(
            &mut fixture.tui,
            &mut fixture.server,
            AppEvent::OpenAnalytics { view: None },
        )
        .await?;
    wait_for_screen(&mut fixture, "z-global@example.test", "Overview").await?;
    key(&mut fixture, '2')?;
    wait_for_screen(&mut fixture, "z-global@example.test", "120").await?;
    key(&mut fixture, 'g')?;
    key(&mut fixture, 'g')?;
    wait_for_screen(&mut fixture, "z-global@example.test", "120").await?;
    let before = fixture.backend.received_requests().await.unwrap();
    assert_eq!(
        before
            .iter()
            .filter(|request| request.url.path().ends_with("daily-token-usage-breakdown"))
            .count(),
        1,
        "changing grouping must reuse A's cached payload"
    );

    let jwt = encode_id_token(
        &ChatGptIdTokenClaims::new()
            .email("a-scoped@example.test")
            .chatgpt_account_id("workspace-scoped")
            .chatgpt_user_id("user-b")
            .plan_type("plus"),
    )
    .expect("synthetic relogin");
    app_test_support::upsert_managed_chatgpt_oauth(
        &fixture.app.config,
        ManagedChatgptOauthCredentials {
            tokens: TokenData {
                id_token: parse_chatgpt_jwt_claims(&jwt)?,
                access_token: "access-b".into(),
                refresh_token: "refresh-access-b".into(),
                account_id: Some("workspace-scoped".into()),
            },
            last_refresh: chrono::Utc::now(),
            oauth_api_key: None,
        },
    )
    .await?;
    rotate(&fixture, "z-global@example.test", "a-scoped@example.test").await?;
    observe_selection(&mut fixture, "email:a-scoped@example.test").await?;
    let cleared = draw(&mut fixture)?;
    assert!(
        !cleared.contains("z-global@example.test") && !cleared.contains("120"),
        "{cleared}"
    );
    let stale: std::result::Result<AccountAnalyticsReadResponse, _> = fixture
        .server
        .request_handle()
        .request_typed(ClientRequest::AccountAnalyticsRead {
            request_id: AppServerRequestId::Integer(22),
            params: AccountAnalyticsReadParams {
                thread_id: Some(THREAD.into()),
                expected_binding: Some(captured_a.binding.clone()),
                query: AccountAnalyticsQuery::Validate,
            },
        })
        .await;
    assert!(
        stale.is_err(),
        "A's captured identity and credential cache key must be rejected"
    );
    key(&mut fixture, 'R')?;
    let screen = wait_for_screen(&mut fixture, "a-scoped@example.test", "240").await?;
    assert!(
        !screen.contains("z-global@example.test") && !screen.contains("120"),
        "{screen}"
    );
    let after = fixture.backend.received_requests().await.unwrap();
    let new_usage = after
        .iter()
        .skip(before.len())
        .filter(|request| request.url.path().ends_with("daily-token-usage-breakdown"))
        .collect::<Vec<_>>();
    assert!(!new_usage.is_empty());
    assert!(new_usage.iter().all(|request| request.headers.get("chatgpt-account-id").unwrap() == "workspace-scoped"));
    insta::assert_snapshot!(
        "analytics_account_switch_header",
        screen.lines().next().unwrap()
    );
    fixture.app.overlay = None;
    fixture.server.shutdown().await?;
    Ok(())
}

#[tokio::test]
async fn pool_security_reminder_never_displays_default_a_eligibility_for_selected_b() -> Result<()>
{
    let mut fixture = fixture().await?;
    fixture.app.config.model_provider_id = "openai".into();
    Mock::given(path("/backend-api/wham/security-setup"))
        .respond_with(
            ResponseTemplate::new(/*s*/ 200).set_body_json(json!({"notice": {
                "title": "A eligible security setup", "description": "Account A only",
                "action": {"label": "Set up A", "url": "https://chatgpt.com/cyber"},
            }})),
        )
        .expect(/*r*/ 0)
        .mount(&fixture.backend)
        .await;
    let (tx, mut events) = mpsc::unbounded_channel();
    let request_id = fixture.app.chat_widget.security_setup_request_id;
    crate::security_setup::prefetch(
        &fixture.app.config,
        &fixture.server,
        AppEventSender::new(tx),
        request_id,
    );
    assert!(
        tokio::time::timeout(Duration::from_secs(/*secs*/ 5), events.recv())
            .await?
            .is_none(),
        "pool eligibility must fail closed before querying default A"
    );
    fixture
        .app
        .handle_event(
            &mut fixture.tui,
            &mut fixture.server,
            AppEvent::SecuritySetupLoaded {
                request_id,
                identity: crate::security_setup::Identity {
                    account: "workspace-global".into(),
                    user: "user-a".into(),
                },
                notice: crate::security_setup::Notice {
                    title: "A eligible security setup".into(),
                    description: "Account A only".into(),
                    action: crate::security_setup::Action {
                        label: "Set up A".into(),
                        url: "https://chatgpt.com/cyber".into(),
                    },
                },
            },
        )
        .await?;
    let screen = render_bottom_popup(&fixture.app.chat_widget, /*width*/ 80);
    assert!(
        !screen.contains("A eligible security setup") && !screen.contains("Set up A"),
        "{screen}"
    );
    fixture.backend.verify().await;
    fixture.server.shutdown().await?;
    Ok(())
}
