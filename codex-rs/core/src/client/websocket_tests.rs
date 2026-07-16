use super::*;

fn binding(
    raw_account_id: Option<&str>,
    fedramp: bool,
    auth_mode: AuthMode,
    route_generation: u64,
) -> TransportAuthBinding {
    TransportAuthBinding {
        identity_key: "managed:user".to_string(),
        raw_account_id: raw_account_id.map(str::to_string),
        fedramp,
        auth_mode,
        route_generation,
    }
}

#[test]
fn binding_change_invalidates_connection_and_previous_response_state() {
    let initial = binding(Some("workspace-a"), false, AuthMode::Chatgpt, 4);
    let mut session = WebsocketSession::default();
    assert!(session.ensure_binding(&initial));

    let (_last_response_tx, last_response_rx) = oneshot::channel();
    session.last_response_rx = Some(last_response_rx);
    session.last_response_from_untraced_warmup = true;
    assert!(!session.ensure_binding(&initial));
    assert!(session.last_response_rx.is_some());

    let changed = binding(Some("workspace-a"), false, AuthMode::Chatgpt, 5);
    assert!(session.ensure_binding(&changed));
    assert!(session.connection.is_none());
    assert!(session.last_request.is_none());
    assert!(session.last_response_rx.is_none());
    assert!(!session.last_response_from_untraced_warmup);
    assert!(!session.connection_reused());

    assert!(session.ensure_binding(&binding(Some("workspace-b"), false, AuthMode::Chatgpt, 5,)));
    assert!(session.ensure_binding(&binding(Some("workspace-b"), true, AuthMode::Chatgpt, 5,)));
    assert!(session.ensure_binding(&binding(Some("workspace-b"), true, AuthMode::ApiKey, 5,)));
}
