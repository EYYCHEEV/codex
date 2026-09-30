//! A server-declared failure keeps its meaning if its stream later disconnects.

use crate::ApiError;
use crate::sse::spawn_response_stream;
use bytes::Bytes;
use codex_client::StreamResponse;
use codex_client::TransportError;
use futures::StreamExt;
use futures::stream;
use std::time::Duration;

fn semantic_failure_bytes() -> Bytes {
    Bytes::from_static(
        b"data: {\"type\":\"response.failed\",\"response\":{\"error\":{\"code\":\"invalid_prompt\",\"message\":\"semantic failure\"}}}\n\n",
    )
}

#[tokio::test]
async fn transport_loss_does_not_replace_server_declared_failure() {
    let stream = stream::iter(vec![
        Ok(semantic_failure_bytes()),
        Err(TransportError::Network("connection lost".to_string())),
    ]);
    let response = spawn_response_stream(
        StreamResponse {
            status: http::StatusCode::OK,
            headers: http::HeaderMap::new(),
            bytes: Box::pin(stream),
        },
        Duration::from_secs(1),
        /*telemetry*/ None,
        /*turn_state*/ None,
    );
    let result = response
        .filter(|event| futures::future::ready(event.is_err()))
        .next()
        .await;
    assert!(
        matches!(&result, Some(Err(ApiError::InvalidPrompt { message })) if message == "semantic failure"),
        "server failure was replaced: {result:?}",
    );
}

#[tokio::test]
async fn idle_timeout_does_not_replace_server_declared_failure() {
    let stream = stream::iter(vec![Ok(semantic_failure_bytes())]).chain(stream::pending());
    let response = spawn_response_stream(
        StreamResponse {
            status: http::StatusCode::OK,
            headers: http::HeaderMap::new(),
            bytes: Box::pin(stream),
        },
        Duration::from_millis(10),
        /*telemetry*/ None,
        /*turn_state*/ None,
    );
    let result = response
        .filter(|event| futures::future::ready(event.is_err()))
        .next()
        .await;
    assert!(
        matches!(&result, Some(Err(ApiError::InvalidPrompt { message })) if message == "semantic failure"),
        "server failure was replaced: {result:?}",
    );
}
