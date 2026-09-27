use super::*;

#[derive(Clone)]
pub(super) struct ManagedChatgptAttemptContext {
    pub(super) snapshot: ManagedChatgptAuthSnapshot,
    pub(super) transport_binding: TransportAuthBinding,
    pub(super) scope: ManagedChatgptSelectionScope,
}

pub(super) fn managed_chatgpt_failure(error: &CodexErr) -> Option<ManagedChatgptFailure> {
    match error.details() {
        CodexErrorDetails::RefreshTokenFailed(_) => Some(ManagedChatgptFailure::AuthInvalid),
        CodexErrorDetails::UnexpectedStatus(error) if error.status == StatusCode::UNAUTHORIZED => {
            Some(ManagedChatgptFailure::AuthInvalid)
        }
        CodexErrorDetails::UsageLimitReached(error) => match error.rate_limit_reached_type {
            None
            | Some(
                RateLimitReachedType::RateLimitReached
                | RateLimitReachedType::WorkspaceOwnerUsageLimitReached
                | RateLimitReachedType::WorkspaceMemberUsageLimitReached,
            ) => Some(ManagedChatgptFailure::Quota {
                reset_at: error.resets_at,
            }),
            Some(
                RateLimitReachedType::WorkspaceOwnerCreditsDepleted
                | RateLimitReachedType::WorkspaceMemberCreditsDepleted,
            ) => Some(ManagedChatgptFailure::WorkspaceQuota {
                reset_at: error.resets_at,
            }),
        },
        CodexErrorDetails::QuotaExceeded => Some(ManagedChatgptFailure::Quota { reset_at: None }),
        _ => None,
    }
}

pub(super) struct ManagedRateLimitRecorder {
    auth_manager: Arc<AuthManager>,
    managed_id: String,
    credential_revision: u64,
    account_state_revision: u64,
    shared_account_state_revision: Option<Arc<AtomicU64>>,
    observed_snapshot: bool,
    windows: Vec<ManagedChatgptRateWindowView>,
    retained_windows: Vec<ManagedChatgptRateWindowView>,
}

impl ManagedRateLimitRecorder {
    pub(super) fn for_setup(
        auth_manager: Option<&Arc<AuthManager>>,
        setup: &ProviderRequestSetup,
    ) -> Option<Self> {
        Self::for_setup_with_revision(auth_manager, setup, None)
    }

    pub(super) fn for_setup_with_revision(
        auth_manager: Option<&Arc<AuthManager>>,
        setup: &ProviderRequestSetup,
        shared_account_state_revision: Option<Arc<AtomicU64>>,
    ) -> Option<Self> {
        let auth_manager = Arc::clone(auth_manager?);
        let managed_id = setup.managed_id.clone()?;
        let credential_revision = setup.credential_revision?;
        let setup_account_state_revision = setup.account_state_revision?;
        let account_state_revision = shared_account_state_revision
            .as_ref()
            .map_or(setup_account_state_revision, |revision| {
                revision.load(Ordering::Acquire)
            });
        let retained_windows = auth_manager
            .managed_chatgpt_accounts()
            .ok()
            .and_then(|accounts| {
                accounts.into_iter().find(|account| {
                    account.identity_key == managed_id && account.revision == account_state_revision
                })
            })
            .and_then(|account| account.usage)
            .map_or_else(Vec::new, |usage| usage.rate_windows);
        Some(Self {
            auth_manager,
            managed_id,
            credential_revision,
            account_state_revision,
            shared_account_state_revision,
            observed_snapshot: false,
            retained_windows,
            windows: Vec::new(),
        })
    }

    fn replace_window(
        windows: &mut Vec<ManagedChatgptRateWindowView>,
        observed: ManagedChatgptRateWindowView,
    ) {
        if let Some(existing) = windows.iter_mut().find(|existing| {
            existing.kind == observed.kind && existing.limit_id == observed.limit_id
        }) {
            *existing = observed;
        } else {
            windows.push(observed);
        }
    }

    pub(super) fn observe(&mut self, snapshot: &RateLimitSnapshot) {
        self.observed_snapshot = true;
        let limit_id = snapshot
            .limit_id
            .clone()
            .unwrap_or_else(|| "codex".to_string());
        let canonical = limit_id == "codex";
        for (kind, suffix, window) in [
            (
                if canonical {
                    ManagedChatgptLimitKind::Primary
                } else {
                    ManagedChatgptLimitKind::Additional
                },
                "primary",
                snapshot.primary.as_ref(),
            ),
            (
                if canonical {
                    ManagedChatgptLimitKind::Secondary
                } else {
                    ManagedChatgptLimitKind::Additional
                },
                "secondary",
                snapshot.secondary.as_ref(),
            ),
        ] {
            let Some(window) = window else {
                continue;
            };
            Self::replace_window(
                &mut self.windows,
                ManagedChatgptRateWindowView {
                    limit_id: if canonical {
                        limit_id.clone()
                    } else {
                        format!("{limit_id}:{suffix}")
                    },
                    kind,
                    remaining_percent: Some((100.0 - window.used_percent).clamp(0.0, 100.0)),
                    window_duration_mins: window.window_minutes,
                    reset_at: window
                        .resets_at
                        .and_then(|timestamp| chrono::DateTime::from_timestamp(timestamp, 0)),
                },
            );
        }
    }

    pub(super) fn observe_error(&mut self, error: &CodexErr) {
        if let CodexErrorDetails::UsageLimitReached(error) = error.details()
            && let Some(snapshot) = error.rate_limits.as_deref()
        {
            self.observe(snapshot);
        }
    }

    pub(super) fn flush(&mut self) {
        if !std::mem::take(&mut self.observed_snapshot) {
            return;
        }
        let rate = if self.windows.is_empty() {
            ManagedChatgptRateObservation::Unavailable {
                reason: "rate limit usage was absent from the response".to_string(),
            }
        } else {
            for window in std::mem::take(&mut self.windows) {
                Self::replace_window(&mut self.retained_windows, window);
            }
            ManagedChatgptRateObservation::Available(self.retained_windows.clone())
        };
        let observation = ManagedChatgptStatusObservation {
            observed_at: chrono::Utc::now(),
            rate,
            token: ManagedChatgptTokenObservation::NotObserved,
        };
        match self.auth_manager.record_managed_chatgpt_status_observation(
            &self.managed_id,
            self.credential_revision,
            self.account_state_revision,
            observation,
        ) {
            Ok(Some(account)) => {
                self.account_state_revision = account.revision;
                if let Some(revision) = self.shared_account_state_revision.as_ref() {
                    revision.fetch_max(account.revision, Ordering::AcqRel);
                }
            }
            Ok(None) => trace!(
                account_state_revision = self.account_state_revision,
                "discarded stale managed account rate-limit observation"
            ),
            Err(err) => warn!(
                account_state_revision = self.account_state_revision,
                "failed to record managed account rate-limit observation: {err}"
            ),
        }
    }
}

impl Drop for ManagedRateLimitRecorder {
    fn drop(&mut self) {
        self.flush();
    }
}

impl ModelClient {
    pub(super) fn managed_attempt_context(
        &self,
        setup: &ProviderRequestSetup,
        model: Option<&str>,
        session_id: Option<&str>,
    ) -> Option<ManagedChatgptAttemptContext> {
        Some(ManagedChatgptAttemptContext {
            snapshot: setup.managed_snapshot.clone()?,
            transport_binding: setup.transport_auth_binding.clone(),
            scope: ManagedChatgptSelectionScope {
                thread_id: Some(self.state.thread_id.to_string()),
                session_id: session_id.map(str::to_owned),
                model: model.map(str::to_owned),
                ..Default::default()
            },
        })
    }
}

impl ModelClientSession {
    pub(super) fn observe_managed_selection(
        &mut self,
        setup: &ProviderRequestSetup,
        model: Option<&str>,
        session_id: Option<&str>,
    ) {
        let Some(snapshot) = setup.managed_snapshot.as_ref() else {
            return;
        };
        let selection = ManagedAccountSelectedEvent {
            selected_account_id: snapshot.identity_key.clone(),
            selection_revision: snapshot.selection_revision,
            session_id: session_id.map(str::to_owned),
            model: model.map(str::to_owned),
        };
        if self.last_managed_selection.as_ref() == Some(&selection) {
            return;
        }
        self.last_managed_selection = Some(selection.clone());
        self.pending_managed_selections.push_back(selection);
    }
    pub(crate) fn take_managed_selection_update(&mut self) -> Option<ManagedAccountSelectedEvent> {
        self.pending_managed_selections.pop_front()
    }
    pub(crate) fn managed_rate_limit_binding(&self) -> Option<ManagedRateLimitBinding> {
        self.managed_rate_limit_binding
            .as_ref()
            .map(ManagedRateLimitBinding::refreshed)
    }

    pub(super) fn update_managed_rate_limit_binding(&mut self, setup: &ProviderRequestSetup) {
        let next_identity = setup.managed_id.clone().zip(setup.account_state_revision);
        self.managed_rate_limit_binding =
            next_identity.map(|(managed_account_id, account_state_revision)| {
                let shared_account_state_revision = self
                    .managed_rate_limit_binding
                    .as_ref()
                    .filter(|current| {
                        current.managed_account_id == managed_account_id
                            && current.transport_binding == setup.transport_auth_binding
                    })
                    .and_then(|binding| binding.shared_account_state_revision.as_ref())
                    .map(|revision| {
                        revision.fetch_max(account_state_revision, Ordering::AcqRel);
                        Arc::clone(revision)
                    })
                    .unwrap_or_else(|| Arc::new(AtomicU64::new(account_state_revision)));
                ManagedRateLimitBinding {
                    managed_account_id,
                    account_state_revision,
                    transport_binding: setup.transport_auth_binding.clone(),
                    shared_account_state_revision: Some(shared_account_state_revision),
                }
            });
    }

    pub(crate) fn request_scope_refresh_pending(&self) -> bool {
        self.request_scope_refresh_pending
    }

    pub async fn recover_last_managed_attempt(
        &mut self,
        error: &CodexErr,
        committed: bool,
    ) -> bool {
        if std::mem::take(&mut self.request_scope_refresh_pending) && !committed {
            self.reset_account_bound_state();
            return true;
        }
        let Some(attempt) = self.managed_attempt.clone() else {
            return false;
        };
        if !self
            .request_recovery
            .recover_managed_attempt(&self.client, &attempt, error, committed)
            .await
        {
            return false;
        }
        self.reset_account_bound_state();
        true
    }
}
impl ModelClientSession {
    pub(super) async fn refresh_request_scope_after_unauthorized(
        &mut self,
        transport: TransportError,
        allowance: usize,
        session_telemetry: &SessionTelemetry,
    ) -> CodexErr {
        match self
            .request_recovery
            .recover_unauthorized(
                transport,
                allowance,
                session_telemetry,
                &self.client,
                /*turn_id*/ None,
            )
            .await
        {
            Ok(()) => {
                self.request_scope_refresh_pending = true;
                CodexErr::Stream("request authentication refreshed".to_string())
            }
            Err(error) => error,
        }
    }

    /// Streams a turn via the OpenAI Responses API.
    ///
    /// Handles reasoning summaries, verbosity, and the `text` controls used for output schemas.
    #[allow(clippy::too_many_arguments)]
    #[instrument(
        name = "model_client.stream_responses_api",
        level = "info",
        skip_all,
        fields(
            model = %model_info.slug,
            wire_api = %self.client.state.provider.info().wire_api,
            transport = "responses_http",
            http.method = "POST",
            api.path = "responses",
            turn.has_metadata_header = responses_metadata.has_turn_metadata()
        )
    )]
    async fn stream_responses_api(
        &mut self,
        prompt: &Prompt,
        model_info: &ModelInfo,
        session_telemetry: &SessionTelemetry,
        effort: Option<ReasoningEffortConfig>,
        summary: ReasoningSummaryConfig,
        service_tier: Option<String>,
        responses_metadata: &CodexResponsesMetadata,
        inference_trace: &InferenceTraceContext,
        mut request_setup: Option<CurrentClientSetup>,
    ) -> Result<ResponseStream> {
        let auth_manager = self.client.state.provider.auth_manager();

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
            let transport = self
                .client
                .build_api_transport(
                    &client_setup.api_provider,
                    endpoint.path(),
                    client_setup.redirect_policy,
                )
                .await?;
            let request_auth_context = AuthRequestTelemetryContext::new(
                client_setup
                    .effective_auth
                    .as_ref()
                    .map(CodexAuth::auth_mode),
                client_setup.api_auth.as_ref(),
                client_setup.agent_identity_telemetry.clone(),
                self.request_recovery.pending_retry,
            );
            let (request_telemetry, sse_telemetry) = Self::build_streaming_telemetry(
                session_telemetry,
                request_auth_context,
                RequestRouteTelemetry::for_endpoint(endpoint.path()),
                self.client.state.auth_env_telemetry.clone(),
            );
            let compression =
                self.responses_request_compression(client_setup.effective_auth.as_ref());
            let mut options = self
                .build_responses_options(
                    responses_metadata,
                    compression,
                    model_info.use_responses_lite,
                )
                .await;
    
            let mut request = self.client.build_responses_request(
                prompt,
                model_info,
                effort.clone(),
                summary,
                service_tier.clone(),
                responses_metadata,
                include_internal,
            )?;

            self.client.set_guardian_metadata(
                &mut request.client_metadata,
                responses_metadata.parent_response_id.as_deref(),
                client_setup.effective_auth.as_ref(),
                endpoint,
                &responses_headers,
            );
            if endpoint == ResponsesEndpoint::Guardian || is_guardian_reviewer(&responses_headers) {
                request.service_tier = None;
            }
            if let Some(header_value) = self.client.build_routing_hint_header(
                client_setup.effective_auth.as_ref(),
                &responses_headers,
                &request.model,
                request.service_tier.as_deref(),
            ) {
                options
                    .extra_headers
                    .insert(X_CODEX_ROUTING_HINT_HEADER, header_value);
            }
            request.access_programs = cyber_access_program::for_auth(
                client_setup.effective_auth.as_ref(),
                prompt.cyber_access_program,
            );
            self.client
                .prepare_response_items_for_request(&mut request.input);
            if crate::guardian::is_basic_session_source(&self.client.state.session_source) {
                crate::guardian::observe_guardian_request(session_telemetry, &request);
            }
            let request_session_telemetry =
                session_telemetry_for_request(session_telemetry, &request);
            options.extra_headers.extend(responses_headers);
            let interceptors = crate::model_request::prepare(
                &self.client.request_contributors,
                &self.client.state.thread_id.to_string(),
                &model_info.slug,
                codex_extension_api::ModelRequestKind::Generation,
                &mut request.client_metadata,
            );
            let inference_trace_attempt = inference_trace.start_attempt();
            inference_trace_attempt.add_request_headers(&mut options.extra_headers);
            if let Some(input) = tool_metadata::bounded_input(&request, &request.input) {
                if let Some(recorder) = &self.client.executed_tool_calls {
                    recorder.invalidate_wire_inventory_loss(&request.input, &input);
                }
                request.input = input;
            }
            inference_trace_attempt.record_started(&request);
            let mut rate_limit_recorder = ManagedRateLimitRecorder::for_setup_with_revision(
                auth_manager.as_ref(),
                &client_setup,
                self.managed_rate_limit_binding
                    .as_ref()
                    .and_then(|binding| binding.shared_account_state_revision.clone()),
            );
            let client = ApiResponsesClient::new(
                transport,
                client_setup.api_provider,
                client_setup.api_auth,
            )
            .with_telemetry(Some(request_telemetry), Some(sse_telemetry));
            let stream_result = client.stream_request(request, options).await;
    
            match stream_result {
                Ok(stream) => {
                    let (stream, _) = map_response_stream(
                        stream,
                        request_session_telemetry,
                        inference_trace_attempt,
                        Arc::clone(&self.client.state.provider),
                        interceptors,
                        rate_limit_recorder,
                    );
                    return Ok(stream);
                }
                Err(ApiError::Transport(unauthorized_transport))
                    if self
                        .client
                        .state
                        .provider
                        .is_recoverable_auth_error(&unauthorized_transport) =>
                {
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
                    if let CodexErrorDetails::UsageLimitReached(rate_error) = err.details()
                        && let Some(rate_limits) = rate_error.rate_limits.as_ref()
                        && let Some(recorder) = rate_limit_recorder.as_mut()
                    {
                        recorder.observe(rate_limits);
                    }
                    inference_trace_attempt.record_failed(
                        &err,
                        response_debug_context.request_id.as_deref(),
                        /*output_items*/ &[],
                    );
                    return Err(err);
                }
            }
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn stream_attempt_with_setup(
        &mut self,
        prompt: &Prompt,
        model_info: &ModelInfo,
        session_telemetry: &SessionTelemetry,
        effort: Option<ReasoningEffortConfig>,
        summary: ReasoningSummaryConfig,
        service_tier: Option<String>,
        responses_metadata: &CodexResponsesMetadata,
        inference_trace: &InferenceTraceContext,
        request_setup: CurrentClientSetup,
    ) -> Result<ResponseStream> {
        self.stream_inner(
            prompt,
            model_info,
            session_telemetry,
            effort,
            summary,
            service_tier,
            responses_metadata,
            inference_trace,
            Some(request_setup),
        )
        .await
    }

    #[allow(clippy::too_many_arguments)]
    pub(super) async fn stream_inner(
        &mut self,
        prompt: &Prompt,
        model_info: &ModelInfo,
        session_telemetry: &SessionTelemetry,
        effort: Option<ReasoningEffortConfig>,
        summary: ReasoningSummaryConfig,
        service_tier: Option<String>,
        responses_metadata: &CodexResponsesMetadata,
        inference_trace: &InferenceTraceContext,
        request_setup: Option<CurrentClientSetup>,
    ) -> Result<ResponseStream> {
        self.managed_attempt = None;
        self.managed_rate_limit_binding = None;
        let wire_api = self.client.state.provider.info().wire_api;
        match wire_api {
            WireApi::Responses => {
                if self.client.responses_websocket_enabled() {
                    let request_trace = current_span_w3c_trace_context();
                    match self
                        .stream_responses_websocket(
                            prompt,
                            model_info,
                            session_telemetry,
                            effort.clone(),
                            summary,
                            service_tier.clone(),
                            responses_metadata,
                            /*warmup*/ false,
                            request_trace,
                            inference_trace,
                            request_setup.clone(),
                        )
                        .await?
                    {
                        WebsocketStreamOutcome::Stream(stream) => return Ok(stream),
                        WebsocketStreamOutcome::FallbackToHttp
                            if self.websocket_http_fallback_allowed() =>
                        {
                            self.try_switch_fallback_transport(session_telemetry, model_info);
                        }
                        WebsocketStreamOutcome::FallbackToHttp => {
                            return Err(CodexErr::Stream(
                                "websocket unavailable and HTTPS fallback is disabled".to_string(),
                            ));
                        }
                    }
                }

                self.stream_responses_api(
                    prompt,
                    model_info,
                    session_telemetry,
                    effort,
                    summary,
                    service_tier,
                    responses_metadata,
                    inference_trace,
                    request_setup,
                )
                .await
            }
        }
    }
}

#[cfg(test)]
#[path = "managed_accounts_tests.rs"]
mod tests;
