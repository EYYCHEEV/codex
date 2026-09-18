//! Recovery through the public turn/events and persisted-history boundaries.

use anyhow::Context;
use codex_core::TurnInputRequest;
use codex_protocol::protocol::CodexErrorInfo;
use codex_protocol::protocol::ErrorEvent;
use codex_protocol::protocol::EventMsg;
use codex_protocol::protocol::Op;
use codex_protocol::user_input::UserInput;
use core_test_support::responses::ev_assistant_message;
use core_test_support::responses::ev_completed;
use core_test_support::responses::ev_exec_command_call;
use core_test_support::responses::ev_message_item_added;
use core_test_support::responses::ev_output_text_delta;
use core_test_support::responses::ev_response_created;
use core_test_support::responses::mount_sse_sequence;
use core_test_support::responses::sse;
use core_test_support::responses::start_mock_server;
use core_test_support::streaming_sse::StreamingSseChunk;
use core_test_support::streaming_sse::start_streaming_sse_server;
use core_test_support::test_codex::TestCodex;
use core_test_support::test_codex::test_codex;
use core_test_support::wait_for_event;
use pretty_assertions::assert_eq;
use serde_json::json;
use std::time::Duration;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn sse_stream_loss_replaces_provisional_output_and_resumes_clean_history() {
    let server = start_mock_server().await;
    let requests = mount_sse_sequence(
        &server,
        vec![
            sse(vec![
                ev_response_created("lost-response"),
                ev_message_item_added("lost-message", ""),
                ev_output_text_delta("discarded provisional text"),
            ]),
            sse(vec![
                ev_response_created("replacement-response"),
                ev_assistant_message("replacement-message", "durable replacement"),
                ev_completed("replacement-response"),
            ]),
            sse(vec![
                ev_response_created("followup-response"),
                ev_assistant_message("followup-message", "followup complete"),
                ev_completed("followup-response"),
            ]),
        ],
    )
    .await;
    let mut builder = test_codex().with_config(|config| {
        config.model_provider.request_max_retries = Some(0);
        config.model_provider.stream_max_retries = Some(1);
        config.model_provider.supports_websockets = false;
    });
    let test = builder.build_with_auto_env(&server).await.unwrap();
    test.codex
        .start_or_steer_turn(TurnInputRequest::user_input(vec![UserInput::Text {
            text: "recover this SSE turn".into(),
            text_elements: Vec::new(),
        }]))
        .await
        .unwrap();
    let resets = tokio::time::timeout(Duration::from_secs(60), async {
        let mut resets = 0;
        loop {
            match test.codex.next_event().await.unwrap().msg {
                EventMsg::ResponseAttemptReset(_) => resets += 1,
                EventMsg::Error(error) => panic!("recoverable SSE loss failed: {error:?}"),
                EventMsg::TurnComplete(_) => break resets,
                _ => {}
            }
        }
    })
    .await
    .expect("recovery must finish within its bounded attempt budget");
    assert_eq!(resets, 1);
    test.codex.flush_rollout().await.unwrap();
    let resumed = builder.restart(&server, &test).await.unwrap();
    resumed
        .submit_turn("continue from the recovered answer")
        .await
        .unwrap();
    resumed.codex.flush_rollout().await.unwrap();
    let requests = requests.requests();
    assert_eq!(requests.len(), 3);
    for request in &requests[1..] {
        assert!(
            !request
                .body_json()
                .to_string()
                .contains("discarded provisional text")
        );
    }
    assert!(
        requests[2]
            .body_json()
            .to_string()
            .contains("durable replacement")
    );
    let rollout = std::fs::read_to_string(resumed.codex.rollout_path().unwrap()).unwrap();
    assert!(!rollout.contains("discarded provisional text"));
    assert!(rollout.contains("durable replacement"));
    assert!(rollout.contains("followup complete"));
}

async fn submit_until_error(test: &TestCodex) -> anyhow::Result<(usize, usize, ErrorEvent)> {
    test.codex
        .start_or_steer_turn(TurnInputRequest::user_input(vec![UserInput::Text {
            text: "exercise bounded stream recovery".into(),
            text_elements: Vec::new(),
        }]))
        .await?;
    tokio::time::timeout(Duration::from_secs(60), async {
        let mut resets = 0;
        let mut exec_starts = 0;
        loop {
            match test.codex.next_event().await?.msg {
                EventMsg::ResponseAttemptReset(_) => resets += 1,
                EventMsg::ExecCommandBegin(_) => exec_starts += 1,
                EventMsg::Error(error) => break Ok((resets, exec_starts, error)),
                EventMsg::TurnComplete(_) => panic!("failed stream must report its terminal error"),
                _ => {}
            }
        }
    })
    .await
    .context("stream recovery must terminate within its bounded attempt budget")?
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn sse_stream_loss_replacement_is_bounded_and_discards_deferred_messages() {
    let server = start_mock_server().await;
    let requests = mount_sse_sequence(
        &server,
        vec![
            sse(vec![
                ev_response_created("first"),
                ev_assistant_message("first-msg", "discarded first message"),
            ]),
            sse(vec![
                ev_response_created("second"),
                ev_assistant_message("second-msg", "discarded second message"),
            ]),
        ],
    )
    .await;
    let test = test_codex()
        .with_config(|config| {
            config.model_provider.request_max_retries = Some(0);
            config.model_provider.stream_max_retries = Some(3);
            config.model_provider.supports_websockets = false;
        })
        .build_with_auto_env(&server)
        .await
        .unwrap();
    let (resets, exec_starts, error) = submit_until_error(&test).await.unwrap();
    assert_eq!((resets, exec_starts), (1, 0));
    assert_eq!(
        error.codex_error_info,
        Some(CodexErrorInfo::ResponseStreamDisconnected {
            http_status_code: None
        })
    );
    assert_eq!(requests.requests().len(), 2);
    assert!(
        !requests.requests()[1]
            .body_json()
            .to_string()
            .contains("discarded first message")
    );
    test.codex.flush_rollout().await.unwrap();
    let rollout = std::fs::read_to_string(test.codex.rollout_path().unwrap()).unwrap();
    assert!(!rollout.contains("discarded first message"));
    assert!(!rollout.contains("discarded second message"));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn sse_server_declared_failure_after_output_does_not_reset_or_replay() {
    let server = start_mock_server().await;
    let requests = mount_sse_sequence(&server, vec![sse(vec![
        ev_response_created("semantic-failure"),
        ev_message_item_added("message", ""),
        ev_output_text_delta("provisional text"),
        json!({"type":"response.failed","response":{"id":"semantic-failure","error":{"code":"invalid_prompt","message":"semantic failure sentinel"}}}),
    ])]).await;
    let test = test_codex()
        .with_config(|config| {
            config.model_provider.request_max_retries = Some(0);
            config.model_provider.stream_max_retries = Some(3);
            config.model_provider.supports_websockets = false;
        })
        .build_with_auto_env(&server)
        .await
        .unwrap();
    let (resets, exec_starts, error) = submit_until_error(&test).await.unwrap();
    assert_eq!((resets, exec_starts), (0, 0));
    assert!(error.message.contains("semantic failure sentinel"));
    assert_eq!(requests.requests().len(), 1);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn sse_zero_retry_budget_does_not_replace_partial_output() {
    let server = start_mock_server().await;
    let requests = mount_sse_sequence(
        &server,
        vec![sse(vec![
            ev_response_created("diagnostic"),
            ev_message_item_added("message", ""),
            ev_output_text_delta("provisional text"),
        ])],
    )
    .await;
    let test = test_codex()
        .with_config(|config| {
            config.model_provider.request_max_retries = Some(0);
            config.model_provider.stream_max_retries = Some(0);
            config.model_provider.supports_websockets = false;
        })
        .build_with_auto_env(&server)
        .await
        .unwrap();
    let (resets, exec_starts, error) = submit_until_error(&test).await.unwrap();
    assert_eq!((resets, exec_starts), (0, 0));
    assert_eq!(
        error.codex_error_info,
        Some(CodexErrorInfo::ResponseStreamDisconnected {
            http_status_code: None
        })
    );
    assert_eq!(requests.requests().len(), 1);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn sse_stream_loss_after_tool_delivery_does_not_replay() {
    let server = start_mock_server().await;
    let requests = mount_sse_sequence(
        &server,
        vec![sse(vec![
            ev_response_created("tool-response"),
            ev_exec_command_call("tool-call", "printf tool-once"),
        ])],
    )
    .await;
    let test = test_codex()
        .with_config(|config| {
            config.model_provider.request_max_retries = Some(0);
            config.model_provider.stream_max_retries = Some(3);
            config.model_provider.supports_websockets = false;
        })
        .build_with_auto_env(&server)
        .await
        .unwrap();
    let (resets, exec_starts, error) = submit_until_error(&test).await.unwrap();
    assert_eq!((resets, exec_starts), (0, 1));
    assert_eq!(
        error.codex_error_info,
        Some(CodexErrorInfo::ResponseStreamDisconnected {
            http_status_code: None
        })
    );
    assert_eq!(requests.requests().len(), 1);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn sse_operator_cancellation_does_not_reset_or_replay() {
    let (release, hold) = tokio::sync::oneshot::channel();
    let (server, _) = start_streaming_sse_server(vec![vec![
        StreamingSseChunk {
            gate: None,
            body: sse(vec![
                ev_response_created("cancelled"),
                ev_message_item_added("message", ""),
                ev_output_text_delta("provisional text"),
            ]),
        },
        StreamingSseChunk {
            gate: Some(hold),
            body: String::new(),
        },
    ]])
    .await;
    let test = test_codex()
        .with_config(|config| {
            config.model_provider.request_max_retries = Some(0);
            config.model_provider.stream_max_retries = Some(3);
            config.model_provider.supports_websockets = false;
        })
        .build_with_streaming_server(&server)
        .await
        .unwrap();
    test.codex
        .start_or_steer_turn(TurnInputRequest::user_input(vec![UserInput::Text {
            text: "cancel this streaming turn".to_string(),
            text_elements: Vec::new(),
        }]))
        .await
        .unwrap();
    wait_for_event(&test.codex, |event| {
        matches!(event, EventMsg::AgentMessageContentDelta(_))
    })
    .await;
    test.codex.submit(Op::Interrupt).await.unwrap();
    tokio::time::timeout(Duration::from_secs(60), async {
        loop {
            match test.codex.next_event().await.unwrap().msg {
                EventMsg::ResponseAttemptReset(_) => panic!("operator cancellation must win"),
                EventMsg::TurnAborted(_) => break,
                _ => {}
            }
        }
    })
    .await
    .expect("cancellation must finish");
    assert_eq!(server.requests().await.len(), 1);
    let _ = release.send(());
    server.shutdown().await;
}
