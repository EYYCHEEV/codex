//! A stalled catalog reply must not hold the editable startup screen forever.

use super::*;
use crate::app_event::AppEvent;
use crate::history_cell::HistoryCell;
use crate::history_cell::SessionHeaderHistoryCell;
use crate::legacy_core::config::ConfigBuilder;
use codex_app_server_protocol::JSONRPCMessage;
use futures::SinkExt;
use futures::StreamExt;
use pretty_assertions::assert_eq;
use serde_json::json;
use std::path::PathBuf;
use tokio::net::TcpListener;
use tokio_tungstenite::tungstenite::Message;

#[tokio::test]
async fn bootstrap_uses_bundled_models_when_catalog_request_stalls() -> Result<()> {
    let codex_home = tempfile::tempdir()?;
    let mut config = ConfigBuilder::default()
        .codex_home(codex_home.path().to_path_buf())
        .build()
        .await?;
    config.model = Some("gpt-5.6-sol".to_string());
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let endpoint = crate::resolve_remote_addr(&format!("ws://{}", listener.local_addr()?))?;
    let server = tokio::spawn(async move {
        let (stream, _) = listener.accept().await?;
        let mut socket = tokio_tungstenite::accept_async(stream).await?;
        let mut model_requests = 0;
        while let Some(Ok(Message::Text(text))) = socket.next().await {
            let JSONRPCMessage::Request(request) = serde_json::from_str(&text)? else {
                continue;
            };
            let mut reply = match request.method.as_str() {
                "initialize" => json!({"result": {"userAgent": "stalled-model-test/1.0.0"}}),
                "model/list" => {
                    model_requests += 1;
                    if model_requests == 1 {
                        continue;
                    }
                    json!({"result": {"data": [], "nextCursor": null}})
                }
                "configRequirements/read" => json!({"result": {"requirements": null}}),
                "collaborationMode/list" => json!({"result": {"data": []}}),
                method => panic!("unexpected request: {method}"),
            };
            reply["id"] = json!(request.id);
            socket.send(Message::Text(reply.to_string().into())).await?;
        }
        Ok::<_, color_eyre::Report>(model_requests)
    });
    let mut session = AppServerSession::new(
        crate::connect_remote_app_server(endpoint).await?,
        ThreadParamsMode::Remote,
    );
    let account = GetAccountResponse {
        account: None,
        requires_openai_auth: false,
        workspace_routing: None,
    };
    let bootstrap = tokio::time::timeout(
        Duration::from_secs(/*secs*/ 7),
        session.bootstrap_with_account(&config, account),
    )
    .await??;
    assert_eq!(bootstrap.default_model, "gpt-5.6-sol");
    assert!(
        bootstrap
            .available_models
            .iter()
            .any(|model| model.show_in_picker)
    );

    let header = SessionHeaderHistoryCell::new(
        bootstrap.default_model.clone(),
        /*reasoning_effort*/ None,
        /*show_fast_status*/ false,
        PathBuf::from("project"),
        "test",
    );
    let lines = header.display_lines(/*width*/ 60);
    let rendered = lines
        .iter()
        .map(|line| {
            line.spans
                .iter()
                .map(|span| span.content.as_ref())
                .collect::<String>()
        })
        .collect::<Vec<_>>()
        .join("\n");
    insta::assert_snapshot!("startup_model_fallback_header", rendered);

    // A late response to the cancelled startup request must not break a later picker fetch.
    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
    let request_id = Uuid::new_v4();
    session.fetch_models(request_id, AppEventSender::new(tx));
    let event = tokio::time::timeout(Duration::from_secs(/*secs*/ 1), rx.recv()).await?;
    assert!(
        matches!(event, Some(AppEvent::ModelsLoaded { request_id: id, result: Ok(_models) }) if id == request_id)
    );

    session.shutdown().await?;
    assert_eq!(server.await??, 2);
    Ok(())
}
