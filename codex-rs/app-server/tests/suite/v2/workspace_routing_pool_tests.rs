//! Resumed turns route with their scoped managed identity, not the global account.

use super::account::seed_managed_accounts;
use anyhow::Result;
use app_test_support::ChatGptIdTokenClaims;
use app_test_support::TestAppServer;
use app_test_support::create_fake_rollout;
use app_test_support::encode_id_token;
use app_test_support::rollout_path;
use app_test_support::write_models_cache;
use codex_app_server_protocol::GetAccountParams;
use codex_app_server_protocol::ThreadResumeParams;
use codex_app_server_protocol::ThreadResumeResponse;
use codex_app_server_protocol::TurnCompletedNotification;
use codex_app_server_protocol::TurnStartParams;
use codex_app_server_protocol::TurnStartResponse;
use codex_app_server_protocol::TurnStatus;
use codex_app_server_protocol::UserInput;
use codex_config::types::AuthCredentialsStoreMode;
use codex_login::AuthKeyringBackendKind;
use codex_login::AuthManager;
use codex_login::ManagedChatgptSelectionScope;
use codex_login::REFRESH_TOKEN_URL_OVERRIDE_ENV_VAR;
use codex_login::test_support::transport_default_auth_route_config;
use core_test_support::responses;
use pretty_assertions::assert_eq;
use serde_json::Value;
use serde_json::json;
use std::collections::HashMap;
use std::io::BufRead;
use std::io::Read;
use std::io::Write;
use std::sync::Arc;
use std::sync::atomic::AtomicBool;
use std::sync::atomic::AtomicUsize;
use std::sync::atomic::Ordering;
use std::time::Duration;
use test_case::test_case;
use tokio::time::timeout;
use wiremock::Mock;
use wiremock::MockServer;
use wiremock::ResponseTemplate;
use wiremock::matchers::body_partial_json;
use wiremock::matchers::header;
use wiremock::matchers::method;
use wiremock::matchers::path;

const WAIT: Duration = Duration::from_secs(/*secs*/ 30);
const THREAD_ID: &str = "00000000-0000-4000-8000-000000000002";

#[path = "workspace_routing_selected_policy_tests.rs"]
mod selected_policy;

// Routing requires HTTPS. Keep real certificate verification and trust this fixture
// only in the child app-server; plaintext model mocks would bypass the route guard.
struct TlsResponse {
    origin: String,
    certificate: String,
    stop: Arc<AtomicBool>,
    requests: Arc<AtomicUsize>,
    request_headers: Arc<std::sync::Mutex<Vec<String>>>,
    worker: Option<std::thread::JoinHandle<Result<String>>>,
}

impl TlsResponse {
    fn start(body: String) -> Result<Self> {
        Self::start_with_request_limit(body, /*request_limit*/ 1)
    }

    fn start_with_request_limit(body: String, request_limit: usize) -> Result<Self> {
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
        let rcgen::CertifiedKey { cert, signing_key } =
            rcgen::generate_simple_self_signed(vec!["127.0.0.1".into()])?;
        let certificate = cert.pem();
        let config = Arc::new(
            rustls::ServerConfig::builder()
                .with_no_client_auth()
                .with_single_cert(vec![cert.der().clone()], signing_key.into())?,
        );
        let listener = std::net::TcpListener::bind(("127.0.0.1", 0))?;
        let origin = format!("https://{}", listener.local_addr()?);
        listener.set_nonblocking(true)?;
        let stop = Arc::new(AtomicBool::new(/*v*/ false));
        let shutdown = Arc::clone(&stop);
        let requests = Arc::new(AtomicUsize::new(/*v*/ 0));
        let received = Arc::clone(&requests);
        let request_headers = Arc::new(std::sync::Mutex::new(Vec::new()));
        let recorded_headers = Arc::clone(&request_headers);
        let worker = std::thread::spawn(move || -> Result<String> {
            loop {
                let socket = loop {
                    anyhow::ensure!(!shutdown.load(Ordering::Relaxed), "TLS fixture stopped");
                    match listener.accept() {
                        Ok((socket, _)) => break socket,
                        Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                            std::thread::sleep(Duration::from_millis(/*millis*/ 10));
                        }
                        Err(error) => return Err(error.into()),
                    }
                };
                socket.set_nonblocking(false)?;
                socket.set_read_timeout(Some(WAIT))?;
                socket.set_write_timeout(Some(WAIT))?;
                let connection = rustls::ServerConnection::new(Arc::clone(&config))?;
                let mut stream =
                    std::io::BufReader::new(rustls::StreamOwned::new(connection, socket));
                let mut headers = String::new();
                loop {
                    let start = headers.len();
                    anyhow::ensure!(
                        stream.read_line(&mut headers)? > 0,
                        "incomplete HTTP headers"
                    );
                    anyhow::ensure!(headers.len() < 65_536, "oversized HTTP headers");
                    if &headers[start..] == "\r\n" {
                        break;
                    }
                }
                let request_count = received.fetch_add(1, Ordering::Relaxed) + 1;
                let length = headers
                    .lines()
                    .find_map(|line| {
                        let (name, value) = line.split_once(':')?;
                        name.eq_ignore_ascii_case("content-length")
                            .then_some(value.trim())
                    })
                    .ok_or_else(|| anyhow::anyhow!("missing model request length"))?
                    .parse::<usize>()?;
                anyhow::ensure!(length < 2_000_000, "oversized model request");
                stream.read_exact(&mut vec![0; length])?;
                recorded_headers
                    .lock()
                    .expect("TLS request headers")
                    .push(headers.clone());
                write!(
                    stream.get_mut(),
                    "HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                )?;
                stream.get_mut().flush()?;
                if request_count >= request_limit {
                    return Ok(headers);
                }
            }
        });
        Ok(Self {
            origin,
            certificate,
            stop,
            requests,
            request_headers,
            worker: Some(worker),
        })
    }
}

impl Drop for TlsResponse {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(worker) = self.worker.take() {
            let _ = worker.join();
        }
    }
}

#[derive(Clone, Copy)]
enum Discovery {
    CachedGlobal,
    Unauthorized,
    SharedWorkspace,
}

#[test_case(Discovery::CachedGlobal; "selected_identity_differs_from_global")]
#[test_case(Discovery::Unauthorized; "discovery_401_refreshes_selected_identity")]
#[test_case(Discovery::SharedWorkspace; "shared_workspace_does_not_share_identity_cache")]
#[tokio::test]
async fn resumed_turn_preserves_managed_routing_identity(discovery: Discovery) -> Result<()> {
    let home = tempfile::tempdir()?;
    let backend = MockServer::start().await;
    let mut tls = TlsResponse::start(responses::sse(vec![
        responses::ev_response_created("resumed-response"),
        responses::ev_assistant_message("resumed-message", "resumed with scoped identity"),
        responses::ev_completed("resumed-response"),
    ]))?;
    let certificate_path = home.path().join("routing-ca.pem");
    std::fs::write(&certificate_path, &tls.certificate)?;
    std::fs::write(
        home.path().join("config.toml"),
        format!(
            "model = 'gpt-5.1'\nmodel_provider = 'fixture'\ncli_auth_credentials_store = 'file'\n\
         chatgpt_base_url = '{0}/backend-api'\n\
         [model_providers.fixture]\nname = 'OpenAI'\nrequires_openai_auth = true\n\
         wire_api = 'responses'\nbase_url = '{0}/backend-api/codex'\nsupports_websockets = false\n\
         request_max_retries = 0\nstream_max_retries = 0\n",
            backend.uri()
        ),
    )?;
    let scoped_workspace = match discovery {
        Discovery::SharedWorkspace => "workspace-global",
        Discovery::CachedGlobal | Discovery::Unauthorized => "workspace-scoped",
    };
    seed_managed_accounts(
        home.path(),
        &[
            ("a-scoped@example.test", scoped_workspace),
            ("z-global@example.test", "workspace-global"),
        ],
    )
    .await?;
    // Distinct synthetic credentials also distinguish identities sharing a workspace.
    let auth_path = home.path().join("auth.json");
    let mut auth: Value = serde_json::from_slice(&std::fs::read(&auth_path)?)?;
    for row in auth["managed_chatgpt"]["accounts"]
        .as_array_mut()
        .expect("managed accounts")
    {
        let label = if row["identity_key"] == "email:a-scoped@example.test" {
            "scoped"
        } else {
            "global"
        };
        row["tokens"]["access_token"] = json!(format!("access-{label}"));
        row["tokens"]["refresh_token"] = json!(format!("refresh-{label}"));
    }
    std::fs::write(&auth_path, serde_json::to_vec(&auth)?)?;
    let manager = AuthManager::shared(
        home.path().to_path_buf(),
        /*enable_codex_api_key_env*/ false,
        AuthCredentialsStoreMode::File,
        /*forced_chatgpt_workspace_id*/ None,
        /*chatgpt_base_url*/ None,
        AuthKeyringBackendKind::Direct,
        transport_default_auth_route_config(),
    )
    .await;
    let owner = manager
        .auth_change_state_receiver()
        .borrow()
        .owner_generation;
    let scoped = manager
        .managed_chatgpt_auth_snapshot(&ManagedChatgptSelectionScope {
            thread_id: Some(THREAD_ID.into()),
            session_id: Some(THREAD_ID.into()),
            model: Some("gpt-5.1".into()),
            ..Default::default()
        })
        .await?
        .expect("scoped managed auth");
    let global = manager.auth_cached().expect("global managed auth");
    assert_eq!(
        (
            global.get_account_email().as_deref(),
            global.get_account_id().as_deref(),
            scoped.identity_key.as_str(),
            scoped.auth.get_account_id().as_deref()
        ),
        (
            Some("z-global@example.test"),
            Some("workspace-global"),
            "email:a-scoped@example.test",
            Some(scoped_workspace)
        ),
        "fixed resume scope must select B while global cached auth remains A"
    );
    assert_eq!(
        manager
            .auth_change_state_receiver()
            .borrow()
            .owner_generation,
        owner
    );
    drop(manager);

    let timestamp = "2025-01-05T12-00-00";
    let generated = create_fake_rollout(
        home.path(),
        timestamp,
        "2025-01-05T12:00:00Z",
        "saved user message",
        Some("fixture"),
        /*git_info*/ None,
    )?;
    let generated_path = rollout_path(home.path(), timestamp, &generated);
    let saved = std::fs::read_to_string(&generated_path)?.replace(&generated, THREAD_ID);
    let saved_path = rollout_path(home.path(), timestamp, THREAD_ID);
    std::fs::rename(generated_path, &saved_path)?;
    std::fs::write(saved_path, saved)?;
    write_models_cache(home.path()).await?;
    Mock::given(method("GET"))
        .and(path("/backend-api/wham/config/bundle"))
        .respond_with(ResponseTemplate::new(/*s*/ 200).set_body_json(json!({})))
        .mount(&backend)
        .await;
    for (bearer, workspace, routing) in [
        ("access-global", "workspace-global", "us"),
        (
            if matches!(discovery, Discovery::Unauthorized) {
                "access-refreshed-scoped"
            } else {
                "access-scoped"
            },
            scoped_workspace,
            "us_cr",
        ),
    ] {
        Mock::given(method("GET")).and(path("/backend-api/wham/accounts/check"))
            .and(header("authorization", format!("Bearer {bearer}")))
            .and(header("chatgpt-account-id", workspace))
            .respond_with(ResponseTemplate::new(/*s*/ 200).set_body_json(json!({"accounts": [{
                "id": workspace, "workspace_backend_origin": tls.origin, "account_routing_override": routing,
            }]}))).expect(1..).mount(&backend).await;
    }
    if matches!(discovery, Discovery::Unauthorized) {
        Mock::given(method("GET"))
            .and(path("/backend-api/wham/accounts/check"))
            .and(header("authorization", "Bearer access-scoped"))
            .and(header("chatgpt-account-id", scoped_workspace))
            .respond_with(ResponseTemplate::new(/*s*/ 401))
            .expect(/*r*/ 2)
            .mount(&backend)
            .await;
    }
    let refreshed_id = encode_id_token(
        &ChatGptIdTokenClaims::new()
            .email("a-scoped@example.test")
            .chatgpt_account_id(scoped_workspace),
    )?;
    Mock::given(method("POST")).and(path("/oauth/token"))
        .and(body_partial_json(json!({"refresh_token": "refresh-scoped"})))
        .respond_with(ResponseTemplate::new(/*s*/ 200).set_body_json(json!({
            "id_token": refreshed_id, "access_token": "access-refreshed-scoped", "refresh_token": "refresh-refreshed-scoped",
        }))).expect(if matches!(discovery, Discovery::Unauthorized) { 1 } else { 0 }).mount(&backend).await;
    let refresh_url = format!("{}/oauth/token", backend.uri());
    let certificate_path = certificate_path.to_string_lossy();
    let mut env = vec![
        ("OPENAI_API_KEY", None),
        ("CODEX_API_KEY", None),
        ("CODEX_CA_CERTIFICATE", Some(certificate_path.as_ref())),
        (
            REFRESH_TOKEN_URL_OVERRIDE_ENV_VAR,
            Some(refresh_url.as_str()),
        ),
    ];
    env.extend(
        codex_network_proxy::PROXY_ENV_KEYS
            .iter()
            .map(|key| (*key, None)),
    );
    let mut app = TestAppServer::builder()
        .with_codex_home(home.path())
        .with_env_overrides(&env)
        .build_initialized_with_timeout(WAIT)
        .await?;
    let read_id = app
        .send_get_account_request(GetAccountParams {
            refresh_token: false,
        })
        .await?;
    let before: Value = timeout(WAIT, app.read_response(read_id)).await??;
    assert_eq!(before["account"]["email"], json!("z-global@example.test"));
    assert_eq!(
        before["workspaceRouting"],
        json!({"chatgptAccountId": "workspace-global",
        "backendOrigin": tls.origin, "accountRoutingOverride": "us"})
    );

    let resume_id = app
        .send_thread_resume_request(ThreadResumeParams {
            thread_id: THREAD_ID.into(),
            model: Some("gpt-5.1".into()),
            cwd: Some(home.path().to_string_lossy().into_owned()),
            ..Default::default()
        })
        .await?;
    let resumed: ThreadResumeResponse = timeout(WAIT, app.read_response(resume_id)).await??;
    assert_eq!(
        (
            resumed.thread.id.as_str(),
            resumed.thread.session_id.as_str()
        ),
        (THREAD_ID, THREAD_ID)
    );
    let turn_id = app
        .send_turn_start_request(TurnStartParams {
            thread_id: resumed.thread.id,
            input: vec![UserInput::Text {
                text: "continue".into(),
                text_elements: Vec::new(),
            }],
            ..Default::default()
        })
        .await?;
    let _: TurnStartResponse = timeout(WAIT, app.read_response(turn_id)).await??;
    let completed: TurnCompletedNotification =
        timeout(WAIT, app.read_notification("turn/completed")).await??;
    assert_eq!(
        (completed.turn.status, completed.turn.error),
        (TurnStatus::Completed, None)
    );
    let request = tls
        .worker
        .take()
        .expect("TLS worker")
        .join()
        .expect("TLS worker panicked")?;
    let mut lines = request.lines();
    assert_eq!(
        lines.next(),
        Some("POST /backend-api/codex/responses HTTP/1.1")
    );
    let headers: HashMap<_, _> = lines
        .filter_map(|line| line.split_once(':'))
        .map(|(key, value)| (key.to_ascii_lowercase(), value.trim().to_string()))
        .collect();
    let expected_bearer = if matches!(discovery, Discovery::Unauthorized) {
        "Bearer access-refreshed-scoped"
    } else {
        "Bearer access-scoped"
    };
    assert_eq!(
        (
            headers.get("authorization").map(String::as_str),
            headers.get("chatgpt-account-id").map(String::as_str),
            headers
                .get("x-openai-account-routing-override")
                .map(String::as_str)
        ),
        (Some(expected_bearer), Some(scoped_workspace), Some("us_cr"))
    );
    let read_id = app
        .send_get_account_request(GetAccountParams {
            refresh_token: false,
        })
        .await?;
    let after: Value = timeout(WAIT, app.read_response(read_id)).await??;
    assert_eq!(
        after, before,
        "model routing must not replace the global account or its cached route"
    );
    backend.verify().await;
    Ok(())
}
