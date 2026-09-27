use super::*;
use pretty_assertions::assert_eq;

#[tokio::test]
async fn managed_quota_rotation_stops_after_request_pool_budget() -> anyhow::Result<()> {
    let server = MockServer::start().await;
    let attempts = Arc::new(AtomicUsize::new(/*v*/ 0));
    let response_attempts = Arc::clone(&attempts);
    let first_reset = Arc::new(std::sync::OnceLock::new());
    let response_first_reset = Arc::clone(&first_reset);
    Mock::given(method("POST"))
        .and(path("/v1/responses"))
        .respond_with(move |_request: &wiremock::Request| {
            match response_attempts.fetch_add(1, Ordering::SeqCst) {
                0 => {
                    let reset = Utc::now() + chrono::Duration::seconds(3);
                    response_first_reset.set(reset).unwrap();
                    ResponseTemplate::new(/*status*/ 429).set_body_json(json!({
                        "error": {
                            "type": "usage_limit_reached",
                            "plan_type": "pro",
                            "resets_at": reset.timestamp()
                        }
                    }))
                }
                1 => {
                    let reset = *response_first_reset.get().unwrap();
                    let wait = (reset - Utc::now()).to_std().unwrap_or_default()
                        + Duration::from_millis(100);
                    // B is selected while A is blocked. Deliver B's failure only
                    // after A's cooldown expires, without altering any credentials.
                    ResponseTemplate::new(/*status*/ 429)
                        .set_delay(wait)
                        .set_body_json(json!({
                            "error": {
                                "type": "usage_limit_reached",
                                "plan_type": "pro",
                                "resets_at": (reset + chrono::Duration::minutes(10)).timestamp()
                            }
                        }))
                }
                _ => ResponseTemplate::new(/*status*/ 200)
                    .insert_header("content-type", "text/event-stream")
                    .set_body_string(concat!(
                        "data: {\"type\":\"response.created\",\"response\":{\"id\":\"sentinel\"}}\n\n",
                        "data: {\"type\":\"response.completed\",\"response\":{\"id\":\"sentinel\"}}\n\n",
                    )),
            }
        })
        .mount(&server)
        .await;
    let home = TempDir::new()?;
    let (client, _manager) = two_account_model_client(&home, &server.uri()).await?;
    let mut session = client.new_session();
    let prompt = Prompt {
        input: vec![ResponseItem::Message {
            id: None,
            role: "user".to_string(),
            content: vec![ContentItem::InputText {
                text: "bounded quota recovery".to_string(),
            }],
            phase: None,
            internal_chat_message_metadata_passthrough: None,
        }],
        ..Default::default()
    };
    let metadata = test_responses_metadata_for_client(
        &client,
        /*turn_id*/ None,
        format!("{}:0", client.state.thread_id),
        /*parent_thread_id*/ None,
        TestCodexResponsesRequestKind::Turn,
    );
    let model = test_model_info();
    let telemetry = test_session_telemetry();
    let terminal_quota = loop {
        match session
            .stream(
                &prompt,
                &model,
                &telemetry,
                /*effort*/ None,
                codex_protocol::config_types::ReasoningSummary::None,
                /*service_tier*/ None,
                &metadata,
                &InferenceTraceContext::disabled(),
            )
            .await
        {
            Ok(mut stream) => {
                while let Some(event) = stream.next().await {
                    if matches!(event?, ResponseEvent::Completed { .. }) {
                        break;
                    }
                }
                break false;
            }
            Err(error) => {
                assert!(matches!(
                    error.details(),
                    CodexErrorDetails::UsageLimitReached(_)
                ));
                assert!(
                    !session
                        .recover_last_managed_attempt(&error, /*committed*/ true)
                        .await,
                    "committed output must never authorize account replay"
                );
                if !session
                    .recover_last_managed_attempt(&error, /*committed*/ false)
                    .await
                {
                    break true;
                }
            }
        }
    };
    let requests = server.received_requests().await.unwrap();
    let account_ids: Vec<_> = requests
        .iter()
        .map(|request| request.headers["chatgpt-account-id"].to_str().unwrap())
        .collect();
    assert!(
        account_ids.len() >= 2,
        "fixture must rotate to the second account"
    );
    assert_ne!(account_ids[0], account_ids[1]);
    assert!(Utc::now() >= *first_reset.get().unwrap());
    assert_eq!(
        (terminal_quota, attempts.load(Ordering::SeqCst)),
        (true, 2),
        "cooldown expiry must not replenish a logical request's account budget"
    );
    // Exhaustion belongs to the finished request, not the now-eligible first account.
    session.begin_request();
    let mut stream = session
        .stream(
            &prompt,
            &model,
            &telemetry,
            /*effort*/ None,
            codex_protocol::config_types::ReasoningSummary::None,
            /*service_tier*/ None,
            &metadata,
            &InferenceTraceContext::disabled(),
        )
        .await?;
    let mut completed = false;
    while let Some(event) = stream.next().await {
        if matches!(event?, ResponseEvent::Completed { .. }) {
            completed = true;
        }
    }
    let next_requests = server.received_requests().await.unwrap();
    assert_eq!(
        (
            completed,
            attempts.load(Ordering::SeqCst),
            next_requests[2].headers["chatgpt-account-id"].to_str()?,
        ),
        (true, 3, account_ids[0]),
        "a fresh logical request can use the account whose cooldown expired"
    );
    Ok(())
}
