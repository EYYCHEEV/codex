use super::McpRuntimeContext;
use codex_config::McpServerConfig;
use codex_exec_server::HttpRedirectPolicy;
use codex_exec_server::HttpRequestParams;
use codex_exec_server_test_support::environment_manager_without_environments;
use codex_http_client::DestinationPolicy;
use codex_http_client::NetworkPolicyController;
use codex_http_client::NetworkPolicyDenied;
use std::sync::Arc;
use std::sync::atomic::AtomicUsize;
use std::sync::atomic::Ordering;
use tokio::io::AsyncReadExt;
use tokio::io::AsyncWriteExt;

#[tokio::test]
async fn local_mcp_http_enforces_selected_policy_and_retains_revoked_account() -> anyhow::Result<()>
{
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let url = format!("http://{}/mcp", listener.local_addr()?);
    let requests = Arc::new(AtomicUsize::new(/*v*/ 0));
    let observed = Arc::clone(&requests);
    let (stop, mut stopped) = tokio::sync::oneshot::channel();
    let server = tokio::spawn(async move {
        loop {
            let (mut socket, _) = tokio::select! {
                _ = &mut stopped => return Ok::<_, anyhow::Error>(()),
                accepted = listener.accept() => accepted?,
            };
            let mut request = Vec::new();
            while !request
                .windows(b"tools/call".len())
                .any(|part| part == b"tools/call")
            {
                let mut buffer = [0_u8; 4096];
                let len = socket.read(&mut buffer).await?;
                anyhow::ensure!(len > 0 && request.len() < 65_536, "incomplete tool request");
                request.extend_from_slice(&buffer[..len]);
            }
            observed.fetch_add(1, Ordering::SeqCst);
            let body = r#"{"jsonrpc":"2.0","id":1,"result":{}}"#;
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len(),
            );
            socket.write_all(response.as_bytes()).await?;
        }
    });
    let controller = NetworkPolicyController::default();
    let policy = controller.policy().for_current_account();
    let context = McpRuntimeContext::new_with_network_policy(
        Arc::new(environment_manager_without_environments()),
        std::env::temp_dir(),
        policy.clone(),
    );
    let config: McpServerConfig = serde_json::from_value(serde_json::json!({
        "url": url,
    }))
    .expect("local HTTP configuration");
    let client = context
        .resolve_http_client("selected-policy", &config)
        .expect("local HTTP capability");
    let request = |redirect_policy| {
        HttpRequestParams {
        method: "POST".to_string(),
        url: url.clone(),
        headers: Vec::new(),
        body: Some(br#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"fixture","arguments":{}}}"#.to_vec().into()),
        timeout_ms: Some(500),
        redirect_policy,
        request_id: "selected-policy".to_string(),
        stream_response: false,
    }
    };
    assert!(controller.publish(policy.revision(), DestinationPolicy::Unrestricted));
    client
        .http_request(request(HttpRedirectPolicy::Follow))
        .await?;
    drop(
        client
            .http_request_stream(request(HttpRedirectPolicy::Stop))
            .await?,
    );
    assert_eq!(
        requests.load(Ordering::SeqCst),
        2,
        "the tool transport fixture must be reachable"
    );
    controller.unavailable(policy.revision());

    for expected in [
        NetworkPolicyDenied::Unavailable,
        NetworkPolicyDenied::Destination,
        NetworkPolicyDenied::Revoked,
    ] {
        match expected {
            NetworkPolicyDenied::Unavailable => {}
            NetworkPolicyDenied::Destination => {
                assert!(controller.publish(
                    policy.revision(),
                    DestinationPolicy::Restricted {
                        allowed_hosts: Default::default(),
                    },
                ));
            }
            NetworkPolicyDenied::Revoked => {
                policy.invalidate();
                assert!(controller.publish(policy.revision(), DestinationPolicy::Unrestricted));
            }
            NetworkPolicyDenied::UnsupportedTransport => unreachable!(),
        }
        for redirect_policy in [HttpRedirectPolicy::Follow, HttpRedirectPolicy::Stop] {
            let error = client
                .http_request(request(redirect_policy))
                .await
                .expect_err("policy denial");
            assert!(error.to_string().contains(&expected.to_string()), "{error}");
            let error = client
                .http_request_stream(request(redirect_policy))
                .await
                .err()
                .expect("streaming policy denial");
            assert!(error.to_string().contains(&expected.to_string()), "{error}");
        }
    }
    assert_eq!(
        requests.load(Ordering::SeqCst),
        2,
        "denied tool payloads must not reach HTTP"
    );
    let _ = stop.send(());
    server.await??;
    Ok(())
}
