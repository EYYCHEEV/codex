//! Exercise server-owned Analytics over the remote transport, including report recovery.

use super::tests::live;
use super::tests::sign_in;
use codex_app_server_client::AppServerRequestHandle;
use codex_app_server_client::RemoteAppServerClient;
use codex_app_server_client::RemoteAppServerConnectArgs;
use codex_app_server_client::RemoteAppServerEndpoint;
use futures::SinkExt;
use futures::StreamExt;
use pretty_assertions::assert_eq;
use serde_json::Value;
use serde_json::json;
use tokio::net::TcpListener;
use tokio::net::TcpStream;
use tokio_tungstenite::WebSocketStream;
use tokio_tungstenite::tungstenite::Message;
use wiremock::Mock;
use wiremock::ResponseTemplate;
use wiremock::matchers::header;
use wiremock::matchers::method;

async fn read(socket: &mut WebSocketStream<TcpStream>) -> Value {
    let frame = socket.next().await.unwrap().unwrap();
    serde_json::from_str(frame.to_text().unwrap()).unwrap()
}

async fn remote(
    owner: AppServerRequestHandle,
) -> (RemoteAppServerClient, tokio::task::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        let mut socket = tokio_tungstenite::accept_async(stream).await.unwrap();
        let initialize = read(&mut socket).await;
        assert_eq!(initialize["method"], "initialize");
        socket
            .send(Message::Text(
                json!({"id": initialize["id"], "result": {
                    "userAgent": "analytics-test", "codexHome": "/server/.codex",
                }})
                .to_string()
                .into(),
            ))
            .await
            .unwrap();
        assert_eq!(read(&mut socket).await["method"], "initialized");
        while let Some(frame) = socket.next().await {
            let frame = frame.unwrap();
            if frame.is_close() {
                break;
            }
            let request: Value = serde_json::from_str(frame.to_text().unwrap()).unwrap();
            assert_eq!(request["method"], "account/analytics/read");
            let result = owner
                .request_typed::<Value>(serde_json::from_value(request.clone()).unwrap())
                .await;
            let response = match result {
                Ok(result) => json!({"id":request["id"],"result":result}),
                Err(codex_app_server_client::TypedRequestError::Server { source, .. }) => {
                    json!({"id":request["id"],"error":source})
                }
                Err(error) => panic!("{error}"),
            };
            socket
                .send(Message::Text(response.to_string().into()))
                .await
                .unwrap();
        }
    });
    let client = RemoteAppServerClient::connect(RemoteAppServerConnectArgs {
        endpoint: RemoteAppServerEndpoint::WebSocket {
            websocket_url: format!("ws://{address}"),
            auth_token: None,
        },
        client_name: "analytics-test".into(),
        client_version: "0.0.0-test".into(),
        experimental_api: true,
        mcp_server_openai_form_elicitation: false,
        opt_out_notification_methods: Vec::new(),
        channel_capacity: 8,
    })
    .await
    .unwrap();
    (client, server)
}

#[tokio::test]
async fn remote_reports_use_server_auth_without_local_login_and_recover_errors() {
    use crate::analytics::AnalyticsView;
    use crate::analytics::data::Load;
    use crate::analytics::sections::Section;

    let http = crate::analytics::test_support::server().await;
    let (home, local) = live(&http, "enterprise").await;
    let (client, server) = remote(local.handle.clone()).await;
    let failed_profile = Mock::given(method("GET"))
        .and(wiremock::matchers::path("/backend-api/wham/profiles/me"))
        .and(header("chatgpt-account-id", "account-a"))
        .respond_with(ResponseTemplate::new(/*s*/ 503))
        .expect(/*r*/ 1)
        .mount_as_scoped(&http)
        .await;
    let frontend_home = tempfile::tempdir().unwrap();
    let mut frontend_config = crate::legacy_core::config::ConfigBuilder::default()
        .codex_home(frontend_home.path().to_path_buf())
        .loader_overrides(codex_config::LoaderOverrides::without_managed_config_for_tests())
        .build()
        .await
        .unwrap();
    frontend_config.cli_auth_credentials_store_mode = codex_login::AuthCredentialsStoreMode::File;
    let mut view = AnalyticsView::new(crate::keymap::RuntimeKeymap::defaults().list);
    view.open(
        AppServerRequestHandle::Remote(client.request_handle()),
        crate::tui::FrameRequester::test_dummy(),
        Vec::new(),
        std::sync::Arc::new(frontend_config),
        /*thread_id*/ None,
    );
    crate::analytics::test_support::settle(&mut view).await;
    assert_eq!(
        view.live.as_ref().unwrap().account_label().as_deref(),
        Some("analytics@example.test")
    );
    assert_eq!(
        view.visible_sections(),
        &[
            Section::Summary,
            Section::Credits,
            Section::Usage,
            Section::Plugins,
            Section::Skills,
        ]
    );
    assert!(matches!(view.profile, Load::Error(_)));
    for section in view.visible_sections() {
        if section.report().is_some() {
            assert!(view.sections[*section].history.ready().is_some());
        }
    }
    drop(failed_profile);

    let profile = json!({
        "profile":{"display_name":"Local account","username":"local-user"},
        "stats":{"lifetime_tokens":12345,"peak_daily_tokens":12345,
            "daily_usage_buckets":[{"start_date":"2026-09-09","tokens":12345}]}
    });
    Mock::given(method("GET"))
        .and(wiremock::matchers::path("/backend-api/wham/profiles/me"))
        .and(header("chatgpt-account-id", "account-a"))
        .respond_with(ResponseTemplate::new(/*s*/ 200).set_body_json(profile.clone()))
        .expect(/*r*/ 1)
        .mount(&http)
        .await;
    view.refresh();
    crate::analytics::test_support::settle(&mut view).await;
    assert_eq!(
        view.profile.ready(),
        Some(&serde_json::from_value(profile).unwrap())
    );
    for request in http
        .received_requests()
        .await
        .unwrap()
        .into_iter()
        .filter(|request| request.url.path().starts_with("/backend-api/wham/"))
    {
        assert_eq!(
            request.headers.get("chatgpt-account-id").unwrap(),
            "account-a"
        );
    }
    Mock::given(method("GET"))
        .and(wiremock::matchers::path("/backend-api/wham/accounts/check"))
        .and(header("chatgpt-account-id", "account-b"))
        .respond_with(ResponseTemplate::new(/*s*/ 200).set_body_json(json!({
            "accounts": [{"id": "account-b", "plan_type": "enterprise"}]
        })))
        .with_priority(/*p*/ 1)
        .expect(/*r*/ 1)
        .mount(&http)
        .await;
    sign_in(home.path(), "account-b", "user-b", "enterprise");
    assert!(
        view.live
            .as_ref()
            .unwrap()
            .history(
                super::Report::Usage,
                /*days*/ 7,
                super::Grouping::Surface
            )
            .await
            .is_err()
    );
    view.poll_reports();
    assert!(matches!(view.account, Load::Loading(_)));
    assert!(matches!(view.profile, Load::Unavailable));
    assert!(
        view.sections
            .0
            .iter()
            .all(|section| matches!(section.history, Load::Unavailable))
    );
    crate::analytics::test_support::settle(&mut view).await;
    assert_eq!(
        view.account.ready(),
        Some(&codex_protocol::account::PlanType::Enterprise)
    );
    for section in view.visible_sections() {
        if section.report().is_some() {
            assert!(view.sections[*section].history.ready().is_some());
        }
    }
    http.verify().await;
    view.cancel_loads();
    client.shutdown().await.unwrap();
    server.await.unwrap();
}

#[tokio::test]
async fn account_lookup_failure_recovers_on_refresh_with_the_server_plan() {
    use crate::analytics::AnalyticsView;
    use crate::analytics::data::Load;
    use crate::analytics::sections::Section;

    let http = crate::analytics::test_support::server().await;
    let (home, local) = live(&http, "plus").await;
    let (client, server) = remote(local.handle.clone()).await;
    Mock::given(method("GET"))
        .and(wiremock::matchers::path("/backend-api/wham/accounts/check"))
        .respond_with(ResponseTemplate::new(/*s*/ 503))
        .with_priority(/*p*/ 1)
        .expect(/*r*/ 1)
        .up_to_n_times(/*n*/ 1)
        .mount(&http)
        .await;
    let preceding_requests = http.received_requests().await.unwrap().len();
    let mut view = AnalyticsView::new(crate::keymap::RuntimeKeymap::defaults().list);
    view.open(
        AppServerRequestHandle::Remote(client.request_handle()),
        crate::tui::FrameRequester::test_dummy(),
        Vec::new(),
        std::sync::Arc::clone(&home.config),
        /*thread_id*/ None,
    );
    crate::analytics::test_support::settle(&mut view).await;
    assert!(matches!(view.account, Load::Error(_)));
    assert_eq!(
        http.received_requests()
            .await
            .unwrap()
            .iter()
            .skip(preceding_requests)
            .filter(|request| request.url.path().starts_with("/backend-api/wham/"))
            .map(|request| request.url.path())
            .collect::<Vec<_>>(),
        ["/backend-api/wham/accounts/check"]
    );
    Mock::given(method("GET"))
        .and(wiremock::matchers::path("/backend-api/wham/accounts/check"))
        .and(header("chatgpt-account-id", "account-a"))
        .respond_with(ResponseTemplate::new(/*s*/ 200).set_body_json(json!({
            "accounts": [{"id": "account-a", "plan_type": "enterprise"}]
        })))
        .with_priority(/*p*/ 1)
        .expect(/*r*/ 1)
        .mount(&http)
        .await;
    Mock::given(method("GET"))
        .and(wiremock::matchers::path("/backend-api/wham/profiles/me"))
        .respond_with(ResponseTemplate::new(/*s*/ 200).set_body_json(json!({"stats": {}})))
        .mount(&http)
        .await;
    view.handle_key(crossterm::event::KeyEvent::new(
        crossterm::event::KeyCode::Char('R'),
        crossterm::event::KeyModifiers::NONE,
    ));
    crate::analytics::test_support::settle(&mut view).await;
    assert_eq!(
        view.visible_sections(),
        &[
            Section::Summary,
            Section::Credits,
            Section::Usage,
            Section::Plugins,
            Section::Skills,
        ]
    );
    assert_eq!(
        view.account.ready(),
        Some(&codex_protocol::account::PlanType::Enterprise)
    );
    for section in view.visible_sections() {
        if section.report().is_some() {
            assert!(view.sections[*section].history.ready().is_some());
        }
    }
    http.verify().await;
    view.cancel_loads();
    client.shutdown().await.unwrap();
    server.await.unwrap();
}
