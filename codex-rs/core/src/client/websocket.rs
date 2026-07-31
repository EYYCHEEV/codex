use super::*;

pub(super) const MAX_WEBSOCKET_DIAGNOSTIC_TEXT_BYTES: usize = 128;

pub(super) fn bounded_websocket_diagnostic_text(value: &str) -> String {
    if value.len() <= MAX_WEBSOCKET_DIAGNOSTIC_TEXT_BYTES {
        return value.to_string();
    }
    let mut end = MAX_WEBSOCKET_DIAGNOSTIC_TEXT_BYTES.saturating_sub(3);
    while !value.is_char_boundary(end) {
        end = end.saturating_sub(1);
    }
    format!("{}...", &value[..end])
}

#[derive(Clone, Debug)]
pub(crate) struct WebsocketCloseDiagnosticContext {
    details: WebsocketCloseDetails,
    thread_id: String,
    turn_id: String,
    session_id: String,
    model: String,
    account_fingerprint: Option<String>,
    credential_revision: Option<u64>,
    account_state_revision: Option<u64>,
    pool_revision: Option<u64>,
    selection_revision: Option<u64>,
    route_generation: Option<u64>,
    handshake_binding_fingerprint: Option<String>,
    request_binding_fingerprint: Option<String>,
    binding_matched: Option<bool>,
    connection_reused: bool,
    output_committed: bool,
}

impl WebsocketCloseDiagnosticContext {
    pub(crate) fn finish(
        self,
        attempt_number: u64,
        max_retries: u64,
        recovery_decision: ResponsesWebsocketCloseRecovery,
    ) -> ResponsesWebsocketCloseDiagnostic {
        ResponsesWebsocketCloseDiagnostic {
            close_code: self.details.code,
            close_reason: self.details.reason,
            close_reason_redacted: self.details.reason_redacted,
            thread_id: self.thread_id,
            turn_id: self.turn_id,
            session_id: self.session_id,
            model: self.model,
            account_fingerprint: self.account_fingerprint,
            credential_revision: self.credential_revision,
            account_state_revision: self.account_state_revision,
            pool_revision: self.pool_revision,
            selection_revision: self.selection_revision,
            route_generation: self.route_generation,
            handshake_binding_fingerprint: self.handshake_binding_fingerprint,
            request_binding_fingerprint: self.request_binding_fingerprint,
            binding_matched: self.binding_matched,
            connection_reused: self.connection_reused,
            output_committed: self.output_committed,
            attempt_number,
            max_retries,
            recovery_decision,
        }
    }
}

impl WebsocketSession {
    pub(super) fn set_connection_reused(&self, connection_reused: bool) {
        *self
            .connection_reused
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = connection_reused;
    }

    pub(super) fn connection_reused(&self) -> bool {
        *self
            .connection_reused
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    pub(super) fn reset_transport_state(&mut self) {
        self.connection = None;
        self.last_request = None;
        self.last_response_rx = None;
        self.last_response_from_untraced_warmup = false;
        self.set_connection_reused(/*connection_reused*/ false);
    }

    pub(super) fn ensure_binding(&mut self, binding: &TransportAuthBinding) -> bool {
        if self.binding.as_ref() == Some(binding) {
            return false;
        }
        self.reset_transport_state();
        self.binding = Some(binding.clone());
        true
    }
}

impl ModelClient {
    /// Whether a failed WebSocket attempt may replay over the HTTPS transport.
    ///
    /// A zero stream retry budget means the initial WebSocket attempt is the only transport
    /// attempt, which is required by the diagnostic exec mode.
    pub(crate) fn websocket_http_fallback_allowed(&self) -> bool {
        self.state.provider.info().stream_max_retries() > 0
    }
}

impl ModelClientSession {
    pub(crate) fn websocket_http_fallback_allowed(&self) -> bool {
        self.client.websocket_http_fallback_allowed()
    }

    pub(crate) fn rewindable_websocket_fallback_allowed(&self) -> bool {
        self.client.responses_websocket_enabled() && self.websocket_http_fallback_allowed()
    }

    pub(super) fn reset_websocket_session(&mut self) {
        self.websocket_session.reset_transport_state();
    }

    pub(super) fn reset_account_bound_state(&mut self) {
        self.websocket_session.reset_transport_state();
        self.websocket_session.binding = None;
        self.turn_state = Arc::new(OnceLock::new());
    }

    pub(crate) fn websocket_close_diagnostic_context(
        &self,
        error: &CodexErr,
        turn_id: &str,
        session_id: &str,
        model: &str,
        output_committed: bool,
    ) -> Option<Box<WebsocketCloseDiagnosticContext>> {
        let CodexErrorDetails::WebsocketClosed(details) = error.details() else {
            return None;
        };
        let attempt = self.managed_attempt.as_ref();
        let request_binding = attempt
            .map(|attempt| &attempt.transport_binding)
            .or(self.websocket_session.binding.as_ref());
        let handshake_binding = self.websocket_session.binding.as_ref();
        let binding_matched = match (handshake_binding, request_binding) {
            (Some(handshake), Some(request)) => Some(handshake == request),
            _ => None,
        };
        Some(Box::new(WebsocketCloseDiagnosticContext {
            details: details.as_ref().clone(),
            thread_id: self.client.state.thread_id.to_string(),
            turn_id: bounded_websocket_diagnostic_text(turn_id),
            session_id: bounded_websocket_diagnostic_text(session_id),
            model: bounded_websocket_diagnostic_text(model),
            account_fingerprint: attempt
                .map(|attempt| attempt.snapshot.diagnostic_account_fingerprint()),
            credential_revision: attempt.map(|attempt| attempt.snapshot.account_revision),
            account_state_revision: attempt.map(|attempt| attempt.snapshot.account_state_revision),
            pool_revision: attempt.map(|attempt| attempt.snapshot.pool_revision),
            selection_revision: attempt.map(|attempt| attempt.snapshot.selection_revision),
            route_generation: request_binding.map(|binding| binding.route_generation),
            handshake_binding_fingerprint: handshake_binding
                .map(TransportAuthBinding::diagnostic_fingerprint),
            request_binding_fingerprint: request_binding
                .map(TransportAuthBinding::diagnostic_fingerprint),
            binding_matched,
            connection_reused: self.websocket_session.connection_reused(),
            output_committed,
        }))
    }

    pub(super) fn ensure_transport_binding(&mut self, binding: &TransportAuthBinding) -> bool {
        if !self.websocket_session.ensure_binding(binding) {
            return false;
        }
        self.turn_state = Arc::new(OnceLock::new());
        true
    }
}
impl ModelClientSession {
    /// Streams a turn via the Responses API over WebSocket transport.
    #[allow(clippy::too_many_arguments)]
    #[instrument(
        name = "model_client.stream_responses_websocket",
        level = "info",
        skip_all,
        fields(
            model = %model_info.slug,
            wire_api = %self.client.state.provider.info().wire_api,
            transport = "responses_websocket",
            api.path = "responses",
            turn.has_metadata_header = responses_metadata.has_turn_metadata(),
            websocket.warmup = warmup
        )
    )]
    pub(super) async fn stream_responses_websocket(
        &mut self,
        prompt: &Prompt,
        model_info: &ModelInfo,
        session_telemetry: &SessionTelemetry,
        effort: Option<ReasoningEffortConfig>,
        summary: ReasoningSummaryConfig,
        service_tier: Option<String>,
        responses_metadata: &CodexResponsesMetadata,
        warmup: bool,
        request_trace: Option<W3cTraceContext>,
        inference_trace: &InferenceTraceContext,
        mut request_setup: Option<CurrentClientSetup>,
    ) -> Result<WebsocketStreamOutcome> {
        let auth_manager = self.client.state.provider.auth_manager();
        let mut auth_recovery = None;
        let mut auth_recovery_key = None;
        let mut pending_retry = PendingUnauthorizedRetry::default();
        let explicit_setup = request_setup.is_some();
        loop {
            let client_setup = match request_setup.take() {
                Some(setup) => setup,
                None => {
                    self.client
                        .current_client_setup(
                            Some(model_info.slug.as_str()),
                            Some(responses_metadata.session_id.as_str()),
                        )
                        .await?
                }
            };
            self.observe_managed_selection(
                &client_setup,
                Some(model_info.slug.as_str()),
                Some(responses_metadata.session_id.as_str()),
            );
            self.ensure_transport_binding(&client_setup.transport_auth_binding);
            self.update_managed_rate_limit_binding(&client_setup);
            self.managed_attempt = self.client.managed_attempt_context(
                &client_setup,
                Some(model_info.slug.as_str()),
                Some(responses_metadata.session_id.as_str()),
            );
            let recovery_key = UnauthorizedRecoveryKey::for_setup(&client_setup);
            if !explicit_setup && auth_recovery_key.as_ref() != Some(&recovery_key) {
                auth_recovery =
                    unauthorized_recovery_for_setup(auth_manager.as_ref(), &client_setup);
                auth_recovery_key = Some(recovery_key.clone());
                pending_retry = PendingUnauthorizedRetry::default();
            }
            let mut fresh_request_scope_recovery = if explicit_setup {
                unauthorized_recovery_for_setup(auth_manager.as_ref(), &client_setup)
            } else {
                None
            };
            let request_auth_context = AuthRequestTelemetryContext::new(
                client_setup
                    .effective_auth
                    .as_ref()
                    .map(CodexAuth::auth_mode),
                client_setup.api_auth.as_ref(),
                client_setup.agent_identity_telemetry.clone(),
                pending_retry,
            );
            let mut request = self.client.build_responses_request(
                &client_setup.api_provider,
                prompt,
                model_info,
                effort.clone(),
                summary,
                service_tier.clone(),
                responses_metadata,
            )?;
            let request_session_telemetry = if warmup {
                // `generate=false` prewarm is connection setup, not an inference request.
                session_telemetry.clone()
            } else {
                session_telemetry_for_request(session_telemetry, &request)
            };
            let mut client_metadata = self
                .client
                .build_ws_client_metadata(responses_metadata, model_info.use_responses_lite);
            if let Some(turn_state) = self.turn_state.get() {
                client_metadata.insert(X_CODEX_TURN_STATE_HEADER.to_string(), turn_state.clone());
            }
            let mut rate_limit_recorder = ManagedRateLimitRecorder::for_setup_with_revision(
                auth_manager.as_ref(),
                &client_setup,
                self.managed_rate_limit_binding
                    .as_ref()
                    .and_then(|binding| binding.shared_account_state_revision.clone()),
            );
            match self
                .websocket_connection(WebsocketConnectParams {
                    session_telemetry,
                    api_provider: client_setup.api_provider,
                    api_auth: client_setup.api_auth,
                    binding: client_setup.transport_auth_binding,
                    responses_metadata,
                    auth_context: request_auth_context,
                    request_route_telemetry: RequestRouteTelemetry::for_endpoint(
                        RESPONSES_ENDPOINT,
                    ),
                })
                .await
            {
                Ok(_) => {}
                Err(ApiError::Transport(TransportError::Http { status, .. }))
                    if status == StatusCode::UPGRADE_REQUIRED =>
                {
                    return Ok(WebsocketStreamOutcome::FallbackToHttp);
                }
                Err(ApiError::Transport(
                    unauthorized_transport @ TransportError::Http { status, .. },
                )) if status == StatusCode::UNAUTHORIZED => {
                    if explicit_setup {
                        return Err(self
                            .refresh_request_scope_after_unauthorized(
                                unauthorized_transport,
                                recovery_key.clone(),
                                fresh_request_scope_recovery.take(),
                                session_telemetry,
                            )
                            .await);
                    }
                    pending_retry = PendingUnauthorizedRetry::from_recovery(
                        handle_unauthorized(
                            unauthorized_transport,
                            &mut auth_recovery,
                            session_telemetry,
                            &self.client.state.provider,
                        )
                        .await?,
                    );
                    continue;
                }
                Err(err) => {
                    let err = self.client.state.provider.map_api_error(err);
                    if let Some(recorder) = rate_limit_recorder.as_mut() {
                        recorder.observe_error(&err);
                        recorder.flush();
                    }
                    return Err(err);
                }
            }

            let (incremental_request, previous_response_id_from_untraced_warmup) =
                self.prepare_websocket_request(&request);
            let inference_trace_attempt = if warmup {
                // Prewarm sends `generate=false`; it is connection setup, not a
                // model inference attempt that should appear in rollout traces.
                InferenceTraceAttempt::disabled()
            } else {
                inference_trace.start_attempt()
            };
            if previous_response_id_from_untraced_warmup {
                // The transport can reuse an untraced warmup response id and omit the
                // already-sent input, but rollout replay needs the logical model-visible
                // request rather than the compressed websocket delta.
                inference_trace_attempt.record_started(&request);
            }

            let (previous_response_id, mut incremental_items) = match incremental_request {
                Some((response_id, items)) => (Some(response_id), Some(items)),
                None => (None, None),
            };
            let original_item_ids = if let Some(incremental_items) = &mut incremental_items {
                self.client
                    .prepare_response_items_for_request(incremental_items);
                None
            } else {
                let original_item_ids = request
                    .input
                    .iter()
                    .map(|item| item.id().cloned())
                    .collect::<Vec<_>>();
                self.client
                    .prepare_response_items_for_request(&mut request.input);
                Some(original_item_ids)
            };
            let ws_payload = ResponseCreateWsRequest {
                previous_response_id,
                input: incremental_items.as_deref().unwrap_or(&request.input),
                generate: if warmup { Some(false) } else { None },
                client_metadata: response_create_client_metadata(
                    Some(client_metadata),
                    request_trace.as_ref(),
                ),
                ..ResponseCreateWsRequest::from(&request)
            };
            let mut ws_request = ResponsesWsRequest::ResponseCreate(ws_payload);
            stamp_ws_stream_request_start_ms(&mut ws_request);
            if !previous_response_id_from_untraced_warmup {
                inference_trace_attempt.record_started(&ws_request);
            }

            let websocket_connection =
                self.websocket_session.connection.as_ref().ok_or_else(|| {
                    self.client.state.provider.map_api_error(ApiError::Stream(
                        "websocket connection is unavailable".to_string(),
                    ))
                })?;
            let raw_stream_result = websocket_connection
                .stream_request(
                    ws_request,
                    self.websocket_session.connection_reused(),
                    Some(Arc::clone(&self.turn_state)),
                )
                .await;
            if let Some(original_item_ids) = original_item_ids {
                for (item, original_item_id) in request.input.iter_mut().zip(original_item_ids) {
                    item.set_id(original_item_id);
                }
            }
            self.websocket_session.last_request = Some(request);
            self.websocket_session.last_response_from_untraced_warmup = warmup;
            let stream_result = match raw_stream_result {
                Ok(stream) => stream,
                Err(ApiError::Transport(
                    unauthorized_transport @ TransportError::Http { status, .. },
                )) if status == StatusCode::UNAUTHORIZED => {
                    if explicit_setup {
                        return Err(self
                            .refresh_request_scope_after_unauthorized(
                                unauthorized_transport,
                                recovery_key.clone(),
                                fresh_request_scope_recovery.take(),
                                session_telemetry,
                            )
                            .await);
                    }
                    self.reset_websocket_session();
                    pending_retry = PendingUnauthorizedRetry::from_recovery(
                        handle_unauthorized(
                            unauthorized_transport,
                            &mut auth_recovery,
                            session_telemetry,
                            &self.client.state.provider,
                        )
                        .await?,
                    );
                    continue;
                }
                Err(err) => {
                    let response_debug_context =
                        extract_response_debug_context_from_api_error(&err);
                    let err = self.client.state.provider.map_api_error(err);
                    if let Some(recorder) = rate_limit_recorder.as_mut() {
                        recorder.observe_error(&err);
                        recorder.flush();
                    }
                    inference_trace_attempt.record_failed(
                        &err,
                        response_debug_context.request_id.as_deref(),
                        /*output_items*/ &[],
                    );
                    return Err(err);
                }
            };
            let codex_api::ResponseStream {
                rx_event,
                upstream_request_id,
            } = stream_result;
            let mut api_stream = codex_api::ResponseStream {
                rx_event,
                upstream_request_id: None,
            };
            let first_event = match api_stream.next().await {
                Some(Err(ApiError::Transport(
                    unauthorized_transport @ TransportError::Http { status, .. },
                ))) if status == StatusCode::UNAUTHORIZED => {
                    let response_debug_context =
                        extract_response_debug_context(&unauthorized_transport);
                    inference_trace_attempt.record_failed(
                        &unauthorized_transport,
                        response_debug_context.request_id.as_deref(),
                        /*output_items*/ &[],
                    );
                    if explicit_setup {
                        return Err(self
                            .refresh_request_scope_after_unauthorized(
                                unauthorized_transport,
                                recovery_key,
                                fresh_request_scope_recovery.take(),
                                session_telemetry,
                            )
                            .await);
                    }
                    self.reset_websocket_session();
                    pending_retry = PendingUnauthorizedRetry::from_recovery(
                        handle_unauthorized(
                            unauthorized_transport,
                            &mut auth_recovery,
                            session_telemetry,
                            &self.client.state.provider,
                        )
                        .await?,
                    );
                    continue;
                }
                first_event => first_event,
            };
            let api_stream = futures::stream::iter(first_event).chain(api_stream);
            let (stream, last_request_rx) = map_response_events_with_rate_recorder(
                upstream_request_id,
                api_stream,
                request_session_telemetry,
                inference_trace_attempt,
                Arc::clone(&self.client.state.provider),
                rate_limit_recorder,
            );
            self.websocket_session.last_response_rx = Some(last_request_rx);
            if explicit_setup {
                self.request_scope_auth_recovery = None;
            }
            return Ok(WebsocketStreamOutcome::Stream(stream));
        }
    }
}

#[cfg(test)]
#[path = "websocket_tests.rs"]
mod tests;
