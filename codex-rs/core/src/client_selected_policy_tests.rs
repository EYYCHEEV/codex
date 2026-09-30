use super::*;
use codex_client::HttpTransport;
use codex_http_client::DestinationPolicy;
use codex_http_client::NetworkPolicy;
use codex_http_client::NetworkPolicyController;
use codex_http_client::NetworkPolicyDenied;
use codex_login::ManagedChatgptAuthSnapshot;
use codex_login::WorkspaceRouting;
use codex_login::WorkspaceRoutingRequest;
use codex_login::WorkspaceRoutingResolver;
use codex_login::WorkspaceRoutingSession;
use pretty_assertions::assert_eq;
use tokio::sync::Mutex;
use tokio_tungstenite::tungstenite::extensions::compression::deflate::DeflateConfig;
use tokio_tungstenite::tungstenite::protocol::WebSocketConfig;

struct SelectedPolicyOwner(Mutex<NetworkPolicy>);

impl WorkspaceRoutingResolver for SelectedPolicyOwner {
    fn resolve<'a>(
        &'a self,
        _request: WorkspaceRoutingRequest<'a>,
    ) -> Pin<Box<dyn Future<Output = std::io::Result<Option<WorkspaceRouting>>> + Send + 'a>> {
        Box::pin(async { Ok(None) })
    }

    fn network_policy_for_managed_snapshot<'a>(
        &'a self,
        snapshot: &'a ManagedChatgptAuthSnapshot,
        _chatgpt_base_url: &'a str,
        _session: Option<Arc<WorkspaceRoutingSession>>,
    ) -> Pin<Box<dyn Future<Output = std::io::Result<NetworkPolicy>> + Send + 'a>> {
        Box::pin(async move {
            assert_eq!(
                snapshot.auth.get_account_id().as_deref(),
                Some("selected-workspace")
            );
            Ok(self.0.lock().await.clone())
        })
    }
}

#[tokio::test]
async fn managed_http_uses_selected_policy_and_retains_live_revocation() -> anyhow::Result<()> {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(/*status*/ 200))
        .expect(1)
        .mount(&server)
        .await;
    let home = TempDir::new()?;
    let (client, manager) = managed_accounts_model_client(
        &home,
        &server.uri(),
        &[("selected@example.com", "selected-workspace")],
    )
    .await?;
    let controller = NetworkPolicyController::default();
    let policy = controller.policy().for_current_account();
    assert!(controller.publish(policy.revision(), DestinationPolicy::Unrestricted));
    let owner: Arc<dyn WorkspaceRoutingResolver> =
        Arc::new(SelectedPolicyOwner(Mutex::new(policy.clone())));
    manager.set_workspace_routing_resolver(Arc::downgrade(&owner));

    let setup = client
        .current_client_setup(/*model*/ None, /*session_id*/ None)
        .await?;
    let transport = client.build_api_transport(&setup, "/responses").await?;
    let request = || {
        setup
            .api_provider
            .build_request(http::Method::POST, "/responses")
            .with_json(&json!({"input": "selected account content"}))
    };
    assert_eq!(
        transport.execute(request()).await?.status,
        http::StatusCode::OK
    );
    assert!(controller.publish(
        policy.revision(),
        DestinationPolicy::Restricted {
            allowed_hosts: Default::default()
        },
    ));
    assert!(matches!(
        transport.execute(request()).await,
        Err(TransportError::Policy(
            NetworkPolicyDenied::Revoked | NetworkPolicyDenied::Destination
        ))
    ));
    let next = client
        .current_client_setup(/*model*/ None, /*session_id*/ None)
        .await?;
    assert_eq!(
        client.http_client_factory_for_setup(&setup)?,
        client.http_client_factory_for_setup(&next)?,
        "same-owner policy changes stay live without changing transport identity",
    );
    let (_, sideband_factory) = client
        .realtime_sideband_auth(http::HeaderMap::new())
        .await?;
    assert_eq!(
        sideband_factory,
        client.http_client_factory_for_setup(&next)?,
        "configured-provider realtime admission must carry the selected policy without URL routing",
    );
    let next_transport = client.build_api_transport(&next, "/responses").await?;
    assert!(matches!(
        next_transport.execute(request()).await,
        Err(TransportError::Policy(NetworkPolicyDenied::Destination))
    ));
    assert_eq!(server.received_requests().await.unwrap().len(), 1);
    Ok(())
}

#[tokio::test]
async fn websocket_reuses_only_the_same_selected_policy_owner() -> anyhow::Result<()> {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let base_url = format!("http://{}", listener.local_addr()?);
    let (accepted, mut handshakes) = tokio::sync::mpsc::unbounded_channel();
    let (stop, stopped) = tokio::sync::oneshot::channel();
    let server = tokio::spawn(async move {
        let mut sockets = Vec::new();
        for count in 1..=2 {
            let (socket, _) = listener.accept().await?;
            let mut config = WebSocketConfig::default();
            config.extensions.permessage_deflate = Some(DeflateConfig::default());
            sockets.push(tokio_tungstenite::accept_async_with_config(socket, Some(config)).await?);
            accepted.send(count)?;
        }
        let _ = stopped.await;
        Ok::<_, anyhow::Error>(())
    });
    let home = TempDir::new()?;
    let (mut client, manager) = managed_accounts_model_client(
        &home,
        &base_url,
        &[("selected@example.com", "selected-workspace")],
    )
    .await?;
    let mut provider = client.state.provider.info().clone();
    provider.supports_websockets = true;
    Arc::get_mut(&mut client.state).unwrap().provider =
        create_model_provider(provider, Some(manager.clone()));
    let first = NetworkPolicyController::default();
    assert!(first.publish(first.policy().revision(), DestinationPolicy::Unrestricted));
    let owner = Arc::new(SelectedPolicyOwner(Mutex::new(
        first.policy().for_current_account(),
    )));
    let resolver: Arc<dyn WorkspaceRoutingResolver> = owner.clone();
    manager.set_workspace_routing_resolver(Arc::downgrade(&resolver));
    let metadata = test_responses_metadata_for_client(
        &client,
        Some("turn-1"),
        format!("{}:0", client.state.thread_id),
        /*parent_thread_id*/ None,
        TestCodexResponsesRequestKind::Turn,
    );
    let mut session = client.new_session();
    let model = test_model_info();
    let telemetry = test_session_telemetry();
    session
        .preconnect_websocket(&model, /*service_tier*/ None, &telemetry, &metadata)
        .await?;
    assert_eq!(
        tokio::time::timeout(Duration::from_secs(/*secs*/ 5), handshakes.recv()).await?,
        Some(1)
    );
    session
        .preconnect_websocket(&model, /*service_tier*/ None, &telemetry, &metadata)
        .await?;
    assert!(
        handshakes.try_recv().is_err(),
        "same-owner policy must reuse the socket"
    );

    let replacement = NetworkPolicyController::default();
    assert!(replacement.publish(
        replacement.policy().revision(),
        DestinationPolicy::Unrestricted
    ));
    *owner.0.lock().await = replacement.policy().for_current_account();
    session
        .preconnect_websocket(&model, /*service_tier*/ None, &telemetry, &metadata)
        .await?;
    assert_eq!(
        tokio::time::timeout(Duration::from_secs(/*secs*/ 5), handshakes.recv()).await?,
        Some(2),
        "a different policy owner must not inherit the old socket",
    );
    drop(session);
    drop(client);
    let _ = stop.send(());
    server.await??;
    Ok(())
}
