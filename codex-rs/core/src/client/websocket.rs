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
    pub(super) fn reset(&mut self, reason: Option<&'static str>) {
        let continuation_reset_reason = self
            .continuation_reset_reason
            .or_else(|| self.last_request.as_ref().and(reason));
        *self = Self {
            auth_owner_generation: self.auth_owner_generation,
            continuation_reset_reason,
            ..Default::default()
        };
    }

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
        self.endpoint = None;
        self.connection_key = None;
        self.responses_headers.clear();
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
        self.websocket_session.endpoint = None;
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
            api.path = tracing::field::Empty,
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
        let after_prewarm = !warmup && self.websocket_session.last_response_from_untraced_warmup;
        let provider = Arc::clone(&self.client.state.provider);
        let auth_manager = provider.auth_manager();
        let explicit_setup = request_setup.is_some();
        loop {
            let client_setup = match request_setup.take() {
                Some(setup) => setup,
                None => {
                    self.current_client_setup(
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
            let allowance = self
                .request_recovery
                .prepare(auth_manager.as_ref(), &client_setup);
            let include_internal = self
                .client
                .state
                .provider
                .include_internal_metadata(&client_setup.api_provider);
            let endpoint = self
                .client
                .responses_endpoint(client_setup.effective_auth.as_ref(), &model_info.slug);
            let responses_headers = self
                .client
                .responses_headers(client_setup.effective_auth.as_ref(), &model_info.slug);
            tracing::Span::current().record("api.path", endpoint.path());
            let request_auth_context = AuthRequestTelemetryContext::new(
                client_setup
                    .effective_auth
                    .as_ref()
                    .map(CodexAuth::auth_mode),
                client_setup.api_auth.as_ref(),
                client_setup.agent_identity_telemetry.clone(),
                self.request_recovery.pending_retry,
            );
            let mut request = self.client.build_responses_request(
                prompt,
                model_info,
                effort.clone(),
                summary,
                service_tier.clone(),
                responses_metadata,
                include_internal,
            )?;
            if endpoint == ResponsesEndpoint::Guardian || is_guardian_reviewer(&responses_headers) {
                request.service_tier = None;
            }
            request.access_programs = cyber_access_program::for_auth(
                client_setup.effective_auth.as_ref(),
                prompt.cyber_access_program,
            );
            let mut websocket_metadata = responses_metadata.clone();
            websocket_metadata.routing_hint = self.client.build_routing_hint_header(
                client_setup.effective_auth.as_ref(),
                &responses_headers,
                &request.model,
                request.service_tier.as_deref(),
            );
            let request_session_telemetry = if warmup {
                // `generate=false` prewarm is connection setup, not an inference request.
                session_telemetry.clone()
            } else {
                session_telemetry_for_request(session_telemetry, &request)
            };
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
                    auth_revision: client_setup
                        .credential_revision
                        .or(client_setup.auth_revision),
                    api_auth: client_setup.api_auth,
                    auth_owner_generation: client_setup.auth_owner_generation,
                    binding: client_setup.transport_auth_binding,
                    responses_metadata: &websocket_metadata,
                    auth_context: request_auth_context,
                    request_route_telemetry: RequestRouteTelemetry::for_endpoint(endpoint.path()),
                    responses_headers: &responses_headers,
                    endpoint,
                })
                .await
            {
                Ok(_) => {}
                Err(ApiError::Transport(TransportError::Http { status, .. }))
                    if status == StatusCode::UPGRADE_REQUIRED =>
                {
                    return Ok(WebsocketStreamOutcome::FallbackToHttp);
                }
                Err(ApiError::Transport(unauthorized_transport))
                    if provider.is_recoverable_auth_error(&unauthorized_transport) =>
                {
                    if explicit_setup {
                        return Err(self
                            .refresh_request_scope_after_unauthorized(
                                unauthorized_transport,
                                allowance,
                                session_telemetry,
                            )
                            .await);
                    }
                    self.request_recovery
                        .recover_unauthorized(
                            unauthorized_transport,
                            allowance,
                            session_telemetry,
                            &self.client,
                            responses_metadata.turn_id.as_deref(),
                        )
                        .await?;
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
    
            // Measure the complete logical request, not only the websocket delta.
            if !warmup
                && crate::guardian::is_basic_session_source(&self.client.state.session_source)
            {
                crate::guardian::observe_guardian_request(session_telemetry, &request);
            }
            let mut client_metadata = self.client.build_ws_client_metadata(
                responses_metadata,
                include_internal,
                model_info.use_responses_lite,
            );
            if let Some(turn_state) = self.turn_state.get() {
                client_metadata.insert(X_CODEX_TURN_STATE_HEADER.to_string(), turn_state.clone());
            }
            let continuation = self.prepare_websocket_request(&request);
            let (mode, reason) = if continuation.is_some() {
                ("incremental", "incremental")
            } else {
                let reason = self
                    .websocket_session
                    .continuation_reset_reason
                    .take()
                    .unwrap_or(if self.websocket_session.last_request.is_some() {
                        "other"
                    } else if self.client.restored_history {
                        "restored_history"
                    } else {
                        "no_previous_request"
                    });
                ("full", reason)
            };
            let previous_response_id_from_untraced_warmup = continuation
                .as_ref()
                .is_some_and(|c| c.from_untraced_warmup);
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
    
            let (previous_response_id, mut incremental_items) = match continuation {
                Some(WebsocketContinuation {
                    response_id, items, ..
                }) => (Some(response_id), Some(items)),
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
            let mut ws_payload = ResponseCreateWsRequest {
                previous_response_id,
                input: incremental_items.as_deref().unwrap_or(&request.input),
                generate: if warmup { Some(false) } else { None },
                client_metadata: response_create_client_metadata(
                    Some(client_metadata),
                    request_trace.as_ref(),
                ),
                ..ResponseCreateWsRequest::from(&request)
            };
            self.client.set_guardian_metadata(
                &mut ws_payload.client_metadata,
                responses_metadata.parent_response_id.as_deref(),
                client_setup.effective_auth.as_ref(),
                endpoint,
                &responses_headers,
            );
            let interceptors = crate::model_request::prepare(
                &self.client.request_contributors,
                &self.client.state.thread_id.to_string(),
                &model_info.slug,
                if warmup {
                    codex_extension_api::ModelRequestKind::Warmup
                } else {
                    codex_extension_api::ModelRequestKind::Generation
                },
                &mut ws_payload.client_metadata,
            );
            let mut ws_request = ResponsesWsRequest::ResponseCreate(ws_payload);
            stamp_ws_stream_request_start_ms(&mut ws_request);
            let ResponsesWsRequest::ResponseCreate(payload) = &ws_request;
            let bounded_input = tool_metadata::bounded_input(&ws_request, payload.input);
            if let Some(input) = bounded_input.as_deref() {
                if let Some(recorder) = &self.client.executed_tool_calls {
                    recorder.invalidate_wire_inventory_loss(payload.input, input);
                }
                let ResponsesWsRequest::ResponseCreate(payload) = &mut ws_request;
                payload.input = input;
            }
            if !previous_response_id_from_untraced_warmup {
                inference_trace_attempt.record_started(&ws_request);
            }
    
            let websocket_connection =
                self.websocket_session.connection.as_ref().ok_or_else(|| {
                    self.client.state.provider.map_api_error(ApiError::Stream(
                        "websocket connection is unavailable".to_string(),
                    ))
                })?;
            request_session_telemetry.counter(
                WEBSOCKET_CONTINUATION_COUNT_METRIC,
                /*inc*/ 1,
                &[
                    ("mode", mode),
                    ("reason", reason),
                    ("phase", if warmup { "warmup" } else { "generation" }),
                    (
                        "after_prewarm",
                        if after_prewarm { "true" } else { "false" },
                    ),
                ],
            );
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
                                allowance,
                                session_telemetry,
                            )
                            .await);
                    }
                    self.reset_websocket_session();
                    self.request_recovery
                        .recover_unauthorized(
                            unauthorized_transport,
                            allowance,
                            session_telemetry,
                            &self.client,
                            responses_metadata.turn_id.as_deref(),
                        )
                        .await?;
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
            let mut api_stream = stream_result;
            let upstream_request_id = api_stream.upstream_request_id.take();
            let interrupt = api_stream.interrupt.take();
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
                                allowance,
                                session_telemetry,
                            )
                            .await);
                    }
                    self.reset_websocket_session();
                    self.request_recovery
                        .recover_unauthorized(
                            unauthorized_transport,
                            allowance,
                            session_telemetry,
                            &self.client,
                            responses_metadata.turn_id.as_deref(),
                        )
                        .await?;
                    continue;
                }
                first_event => first_event,
            };
            let api_stream = futures::stream::iter(first_event).chain(api_stream);
            let (mut stream, last_request_rx) = map_response_events_with_rate_recorder(
                upstream_request_id,
                crate::model_request::intercept_stream(Box::pin(api_stream), interceptors),
                request_session_telemetry,
                inference_trace_attempt,
                Arc::clone(&self.client.state.provider),
                rate_limit_recorder,
            );
            self.websocket_session.last_response_rx = Some(last_request_rx);
            stream.interrupt = interrupt;
            return Ok(WebsocketStreamOutcome::Stream(stream));
        }
    }
}

#[cfg(test)]
#[path = "websocket_tests.rs"]
mod tests;
