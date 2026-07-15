use crate::auth::SharedAuthProvider;
use crate::common::ResponseEvent;
use crate::common::ResponseStream;
use crate::common::ResponsesWsRequest;
use crate::common::SafetyBufferingTreatment;
use crate::common::WS_REQUEST_HEADER_TRACEPARENT_CLIENT_METADATA_KEY;
use crate::error::ApiError;
use crate::provider::Provider;
use crate::rate_limits::parse_all_rate_limits;
use crate::rate_limits::parse_rate_limit_event;
use crate::safety_buffering::treatment_from_headers;
use crate::sse::ResponsesStreamEvent;
use crate::sse::process_responses_event;
use crate::telemetry::WebsocketTelemetry;
use codex_client::TransportError;
use codex_http_client::HttpClientFactory;
use codex_protocol::error::WebsocketCloseDetails;
use codex_protocol::protocol::RateLimitSnapshot;
use codex_websocket_client::WebSocketConnection;
use codex_websocket_client::WebSocketConnector;
use futures::SinkExt;
use futures::StreamExt;
use http::HeaderMap;
use http::HeaderName;
use http::HeaderValue;
use http::StatusCode;
use serde::Deserialize;
use serde_json::Value;
use serde_json::map::Map as JsonMap;
use std::sync::Arc;
use std::sync::OnceLock;
use std::time::Duration;
use tokio::sync::Mutex;
use tokio::sync::mpsc;
use tokio::sync::oneshot;
use tokio::time::Instant;
use tokio_tungstenite::tungstenite::Error as WsError;
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::tungstenite::client::IntoClientRequest;
use tokio_tungstenite::tungstenite::error::ProtocolError;
use tokio_tungstenite::tungstenite::protocol::CloseFrame;
use tracing::Instrument;
use tracing::Span;
use tracing::debug;
use tracing::error;
use tracing::info;
use tracing::instrument;
use tungstenite::extensions::ExtensionsConfig;
use tungstenite::extensions::compression::deflate::DeflateConfig;
use tungstenite::protocol::WebSocketConfig;
use url::Url;

struct WsStream {
    tx_command: mpsc::Sender<WsCommand>,
    rx_message: mpsc::UnboundedReceiver<Result<Message, WsError>>,
    pump_task: tokio::task::JoinHandle<()>,
}

enum WsCommand {
    Send {
        message: Message,
        tx_result: oneshot::Sender<Result<(), WsError>>,
    },
}

impl WsStream {
    fn new(inner: WebSocketConnection) -> Self {
        let (tx_command, mut rx_command) = mpsc::channel::<WsCommand>(32);
        let (tx_message, rx_message) = mpsc::unbounded_channel::<Result<Message, WsError>>();

        let pump_task = tokio::spawn(async move {
            let mut inner = inner;
            loop {
                tokio::select! {
                    command = rx_command.recv() => {
                        let Some(command) = command else {
                            break;
                        };
                        match command {
                            WsCommand::Send { message, tx_result } => {
                                let result = inner.send(message).await;
                                let should_break = result.is_err();
                                let _ = tx_result.send(result);
                                if should_break {
                                    break;
                                }
                            }
                        }
                    }
                    message = inner.next() => {
                        let Some(message) = message else {
                            break;
                        };
                        match message {
                            Ok(Message::Ping(payload)) => {
                                if let Err(err) = inner.send(Message::Pong(payload)).await {
                                    let _ = tx_message.send(Err(err));
                                    break;
                                }
                            }
                            Ok(Message::Pong(_)) => {}
                            Ok(message @ (Message::Text(_)
                            | Message::Binary(_)
                            | Message::Close(_)
                            | Message::Frame(_))) => {
                                let is_close = matches!(message, Message::Close(_));
                                if tx_message.send(Ok(message)).is_err() {
                                    break;
                                }
                                if is_close {
                                    break;
                                }
                            }
                            Err(err) => {
                                let _ = tx_message.send(Err(err));
                                break;
                            }
                        }
                    }
                }
            }
        });

        Self {
            tx_command,
            rx_message,
            pump_task,
        }
    }

    async fn request(
        &self,
        make_command: impl FnOnce(oneshot::Sender<Result<(), WsError>>) -> WsCommand,
    ) -> Result<(), WsError> {
        let (tx_result, rx_result) = oneshot::channel();
        if self.tx_command.send(make_command(tx_result)).await.is_err() {
            return Err(WsError::ConnectionClosed);
        }
        rx_result.await.unwrap_or(Err(WsError::ConnectionClosed))
    }

    async fn send(&self, message: Message) -> Result<(), WsError> {
        self.request(|tx_result| WsCommand::Send { message, tx_result })
            .await
    }

    async fn next(&mut self) -> Option<Result<Message, WsError>> {
        self.rx_message.recv().await
    }
}

impl Drop for WsStream {
    fn drop(&mut self) {
        self.pump_task.abort();
    }
}

const X_CODEX_TURN_STATE_HEADER: &str = "x-codex-turn-state";
const X_MODELS_ETAG_HEADER: &str = "x-models-etag";
const X_REASONING_INCLUDED_HEADER: &str = "x-reasoning-included";
const OPENAI_MODEL_HEADER: &str = "openai-model";
const WEBSOCKET_CONNECTION_LIMIT_REACHED_CODE: &str = "websocket_connection_limit_reached";
const WEBSOCKET_CONNECTION_LIMIT_REACHED_MESSAGE: &str = "Responses websocket connection limit reached (60 minutes). Create a new websocket connection to continue.";
const PREVIOUS_RESPONSE_NOT_FOUND_CODE: &str = "previous_response_not_found";
const PREVIOUS_RESPONSE_NOT_FOUND_MESSAGE: &str =
    "Previous response was not found. Retrying the full request.";
const RESPONSES_WEBSOCKET_TIMING_KIND: &str = "responsesapi.websocket_timing";
const RESPONSES_WEBSOCKET_TIMING_EVENT_TARGET: &str = "codex_api::responses_websocket_timing";
const SESSION_ID_CLIENT_METADATA_KEY: &str = "session_id";
const THREAD_ID_CLIENT_METADATA_KEY: &str = "thread_id";
const TURN_ID_CLIENT_METADATA_KEY: &str = "turn_id";
const WS_STREAM_REQUEST_START_MS_CLIENT_METADATA_KEY: &str = "x-codex-ws-stream-request-start-ms";

struct ResponsesWebsocketTimingLogContext {
    model: String,
    session_id: Option<String>,
    thread_id: Option<String>,
    turn_id: Option<String>,
    traceparent: Option<String>,
    previous_response_id: Option<String>,
    request_start_ms: Option<String>,
    warmup: bool,
    connection_reused: bool,
}

pub struct ResponsesWebsocketConnection {
    stream: Arc<Mutex<Option<WsStream>>>,
    // TODO (pakrym): is this the right place for timeout?
    idle_timeout: Duration,
    server_reasoning_included: bool,
    models_etag: Option<String>,
    handshake_rate_limits: Mutex<Option<Vec<RateLimitSnapshot>>>,
    server_model: Option<String>,
    telemetry: Option<Arc<dyn WebsocketTelemetry>>,
}

impl std::fmt::Debug for ResponsesWebsocketConnection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ResponsesWebsocketConnection")
            .field("stream", &"<ws-stream>")
            .field("idle_timeout", &self.idle_timeout)
            .field("server_reasoning_included", &self.server_reasoning_included)
            .field("models_etag", &self.models_etag)
            .field("server_model", &self.server_model)
            .field(
                "handshake_rate_limits",
                &"<rate-limit-snapshots-pending-first-generated-request>",
            )
            .field("telemetry", &self.telemetry.as_ref().map(|_| "<telemetry>"))
            .finish()
    }
}

impl ResponsesWebsocketConnection {
    fn new(
        stream: WsStream,
        idle_timeout: Duration,
        server_reasoning_included: bool,
        models_etag: Option<String>,
        server_model: Option<String>,
        handshake_rate_limits: Vec<RateLimitSnapshot>,
        telemetry: Option<Arc<dyn WebsocketTelemetry>>,
    ) -> Self {
        Self {
            stream: Arc::new(Mutex::new(Some(stream))),
            idle_timeout,
            server_reasoning_included,
            models_etag,
            server_model,
            handshake_rate_limits: Mutex::new(Some(handshake_rate_limits)),
            telemetry,
        }
    }

    pub async fn is_closed(&self) -> bool {
        self.stream.lock().await.is_none()
    }

    #[instrument(
        name = "responses_websocket.stream_request",
        level = "info",
        skip_all,
        fields(transport = "responses_websocket", api.path = "responses")
    )]
    pub async fn stream_request(
        &self,
        request: ResponsesWsRequest<'_>,
        connection_reused: bool,
        turn_state: Option<Arc<OnceLock<String>>>,
    ) -> Result<ResponseStream, ApiError> {
        let (tx_event, rx_event) =
            mpsc::channel::<std::result::Result<ResponseEvent, ApiError>>(1600);
        let stream = Arc::clone(&self.stream);
        let idle_timeout = self.idle_timeout;
        let server_reasoning_included = self.server_reasoning_included;
        let models_etag = self.models_etag.clone();
        let server_model = self.server_model.clone();
        let telemetry = self.telemetry.clone();
        let ResponsesWsRequest::ResponseCreate(ws_request) = &request;
        let client_metadata = ws_request.client_metadata.as_ref();
        let timing_log_context = ResponsesWebsocketTimingLogContext {
            model: ws_request.model.to_string(),
            session_id: client_metadata
                .and_then(|metadata| metadata.get(SESSION_ID_CLIENT_METADATA_KEY))
                .cloned(),
            thread_id: client_metadata
                .and_then(|metadata| metadata.get(THREAD_ID_CLIENT_METADATA_KEY))
                .cloned(),
            turn_id: client_metadata
                .and_then(|metadata| metadata.get(TURN_ID_CLIENT_METADATA_KEY))
                .cloned(),
            traceparent: client_metadata
                .and_then(|metadata| {
                    metadata.get(WS_REQUEST_HEADER_TRACEPARENT_CLIENT_METADATA_KEY)
                })
                .cloned(),
            previous_response_id: ws_request.previous_response_id.clone(),
            request_start_ms: client_metadata
                .and_then(|metadata| metadata.get(WS_STREAM_REQUEST_START_MS_CLIENT_METADATA_KEY))
                .cloned(),
            warmup: ws_request.generate == Some(false),
            connection_reused,
        };
        let request_text = serialize_websocket_request(&request)?;
        let generate = match &request {
            ResponsesWsRequest::ResponseCreate(request) => request.generate,
        };
        let handshake_rate_limits =
            take_handshake_rate_limits(&self.handshake_rate_limits, generate).await;

        let current_span = Span::current();
        tokio::spawn(
            #[expect(
                clippy::await_holding_invalid_type,
                reason = "the guard serializes exclusive use of the websocket stream for the lifetime of the response stream"
            )]
            async move {
                for snapshot in handshake_rate_limits {
                    let _ = tx_event.send(Ok(ResponseEvent::RateLimits(snapshot))).await;
                }
                if let Some(model) = server_model {
                    let _ = tx_event.send(Ok(ResponseEvent::ServerModel(model))).await;
                }
                if let Some(etag) = models_etag {
                    let _ = tx_event.send(Ok(ResponseEvent::ModelsEtag(etag))).await;
                }
                if server_reasoning_included {
                    let _ = tx_event
                        .send(Ok(ResponseEvent::ServerReasoningIncluded(true)))
                        .await;
                }
                let mut guard = stream.lock().await;
                let result = {
                    let Some(ws_stream) = guard.as_mut() else {
                        let _ = tx_event
                            .send(Err(ApiError::WebsocketClosed(Box::new(
                                websocket_close_details(None),
                            ))))
                            .await;
                        return;
                    };

                    run_websocket_response_stream(
                        ws_stream,
                        tx_event.clone(),
                        request_text,
                        idle_timeout,
                        telemetry,
                        turn_state.as_deref(),
                        &timing_log_context,
                    )
                    .await
                };

                if let Err(err) = result {
                    // A terminal stream error should reach the caller immediately. Waiting for a
                    // graceful close handshake here can stall indefinitely and mask the error.
                    let failed_stream = guard.take();
                    drop(guard);
                    drop(failed_stream);
                    let _ = tx_event.send(Err(err)).await;
                }
            }
            .instrument(current_span),
        );

        Ok(ResponseStream {
            rx_event,
            upstream_request_id: None,
        })
    }
}

/// Client for connecting to the Responses WebSocket endpoint for one provider.
pub struct ResponsesWebsocketClient {
    provider: Provider,
    auth: SharedAuthProvider,
}

/// Sanitized close information captured by a handshake probe.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResponsesWebsocketClose {
    /// Whether the peer sent a close frame. `false` identifies stream EOF.
    pub frame_received: bool,
    /// WebSocket close code returned by the server, when present.
    pub code: Option<u16>,
    /// Allowlisted close reason, or `[redacted]` when a reason was unsafe.
    pub reason: Option<String>,
    /// Whether the server supplied a reason that was replaced with `[redacted]`.
    pub reason_redacted: bool,
}

/// Result of a handshake-only Responses WebSocket probe.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResponsesWebsocketProbe {
    /// Redacted by callers before displaying or serializing support reports.
    pub url: String,
    /// HTTP status returned by the successful WebSocket upgrade.
    pub status: StatusCode,
    /// Whether the server reported reasoning support in the upgrade response.
    pub reasoning_included: bool,
    /// Whether the server returned a model catalog ETag in the upgrade response.
    pub models_etag_present: bool,
    /// Whether the server returned a server-selected model in the upgrade response.
    pub server_model_present: bool,
    /// Immediate closure observed after upgrade. EOF and frameless close frames
    /// are represented explicitly; `None` means the grace interval elapsed.
    pub immediate_close: Option<ResponsesWebsocketClose>,
}

impl ResponsesWebsocketClient {
    /// Creates a Responses WebSocket client for an already-resolved provider and auth source.
    pub fn new(provider: Provider, auth: SharedAuthProvider) -> Self {
        Self { provider, auth }
    }

    #[instrument(
        name = "responses_websocket.connect",
        level = "info",
        skip_all,
        fields(transport = "responses_websocket", api.path = "responses")
    )]
    pub async fn connect(
        &self,
        http_client_factory: &HttpClientFactory,
        extra_headers: HeaderMap,
        default_headers: HeaderMap,
        turn_state: Option<Arc<OnceLock<String>>>,
        telemetry: Option<Arc<dyn WebsocketTelemetry>>,
    ) -> Result<ResponsesWebsocketConnection, ApiError> {
        let ws_url = self
            .provider
            .websocket_url_for_path("responses")
            .map_err(|err| ApiError::Stream(format!("failed to build websocket URL: {err}")))?;

        let mut headers =
            merge_request_headers(&self.provider.headers, extra_headers, default_headers);
        self.auth.add_auth_headers(&mut headers);

        let (
            stream,
            _status,
            server_reasoning_included,
            models_etag,
            server_model,
            handshake_rate_limits,
        ) = connect_websocket(ws_url, headers, http_client_factory, turn_state.clone()).await?;
        Ok(ResponsesWebsocketConnection::new(
            stream,
            self.provider.stream_idle_timeout,
            server_reasoning_included,
            models_etag,
            server_model,
            handshake_rate_limits,
            telemetry,
        ))
    }

    /// Opens a WebSocket connection long enough to validate the upgrade response.
    ///
    /// The probe uses the same URL construction, headers, authentication, TLS,
    /// and custom-CA path as a real Responses WebSocket connection, but it does
    /// not send a request frame. After the HTTP 101 upgrade succeeds, it waits
    /// briefly for an immediate server close frame so diagnostics can distinguish
    /// a usable connection from a policy rejection that closes right away.
    pub async fn probe_handshake(
        &self,
        http_client_factory: &HttpClientFactory,
        extra_headers: HeaderMap,
        default_headers: HeaderMap,
        immediate_close_timeout: Duration,
    ) -> Result<ResponsesWebsocketProbe, ApiError> {
        let ws_url = self
            .provider
            .websocket_url_for_path("responses")
            .map_err(|err| ApiError::Stream(format!("failed to build websocket URL: {err}")))?;

        let mut headers =
            merge_request_headers(&self.provider.headers, extra_headers, default_headers);
        self.auth.add_auth_headers(&mut headers);

        let (
            mut stream,
            status,
            reasoning_included,
            models_etag,
            server_model,
            _handshake_rate_limits,
        ) = connect_websocket(
            ws_url.clone(),
            headers,
            http_client_factory,
            /*turn_state*/ None,
        )
        .await?;
        let immediate_close = immediate_close_from_probe_read(
            tokio::time::timeout(immediate_close_timeout, stream.next()).await,
        )?;

        Ok(ResponsesWebsocketProbe {
            url: ws_url.to_string(),
            status,
            reasoning_included,
            models_etag_present: models_etag.is_some(),
            server_model_present: server_model.is_some(),
            immediate_close,
        })
    }
}

fn immediate_close_from_probe_read(
    read: Result<Option<Result<Message, WsError>>, tokio::time::error::Elapsed>,
) -> Result<Option<ResponsesWebsocketClose>, ApiError> {
    match read {
        Err(_) => Ok(None),
        Ok(None) => Ok(Some(close_details_to_probe(
            false,
            websocket_close_details(None),
        ))),
        Ok(Some(Ok(Message::Close(frame)))) => {
            let details = websocket_close_details(frame);
            Ok(Some(close_details_to_probe(true, details)))
        }
        Ok(Some(Ok(_))) => Ok(None),
        Ok(Some(Err(err))) if websocket_error_is_disconnect(&err) => Ok(Some(
            close_details_to_probe(false, websocket_close_details(None)),
        )),
        Ok(Some(Err(err))) => Err(ApiError::Stream(format!(
            "failed to read websocket probe event: {err}"
        ))),
    }
}

fn close_details_to_probe(
    frame_received: bool,
    details: WebsocketCloseDetails,
) -> ResponsesWebsocketClose {
    ResponsesWebsocketClose {
        frame_received,
        code: details.code,
        reason: details.reason,
        reason_redacted: details.reason_redacted,
    }
}

fn merge_request_headers(
    provider_headers: &HeaderMap,
    extra_headers: HeaderMap,
    default_headers: HeaderMap,
) -> HeaderMap {
    let mut headers = provider_headers.clone();
    headers.extend(extra_headers);
    for (name, value) in &default_headers {
        if let http::header::Entry::Vacant(entry) = headers.entry(name) {
            entry.insert(value.clone());
        }
    }
    headers
}

async fn connect_websocket(
    url: Url,
    headers: HeaderMap,
    http_client_factory: &HttpClientFactory,
    turn_state: Option<Arc<OnceLock<String>>>,
) -> Result<
    (
        WsStream,
        StatusCode,
        bool,
        Option<String>,
        Option<String>,
        Vec<RateLimitSnapshot>,
    ),
    ApiError,
> {
    info!("connecting to websocket: {url}");

    let mut request = url
        .as_str()
        .into_client_request()
        .map_err(|err| ApiError::Stream(format!("failed to build websocket request: {err}")))?;
    request.headers_mut().extend(headers);

    let connector = WebSocketConnector::new(http_client_factory)
        .map_err(|err| ApiError::Stream(format!("failed to configure websocket TLS: {err}")))?;
    let response = connector.connect(request, websocket_config()).await;

    let (stream, response) = match response {
        Ok((stream, response)) => {
            info!(
                "successfully connected to websocket: {url}, headers: {:?}",
                response.headers()
            );
            (stream, response)
        }
        Err(err) => {
            error!("failed to connect to websocket: {err}, url: {url}");
            return Err(map_ws_error(err, &url));
        }
    };

    let reasoning_included = response.headers().contains_key(X_REASONING_INCLUDED_HEADER);
    let models_etag = response
        .headers()
        .get(X_MODELS_ETAG_HEADER)
        .and_then(|value| value.to_str().ok())
        .map(ToString::to_string);
    let server_model = response
        .headers()
        .get(OPENAI_MODEL_HEADER)
        .and_then(|value| value.to_str().ok())
        .map(ToString::to_string);
    let rate_limits = parse_all_rate_limits(response.headers());
    if let Some(turn_state) = turn_state
        && let Some(header_value) = response
            .headers()
            .get(X_CODEX_TURN_STATE_HEADER)
            .and_then(|value| value.to_str().ok())
    {
        let _ = turn_state.set(header_value.to_string());
    }
    Ok((
        WsStream::new(stream),
        response.status(),
        reasoning_included,
        models_etag,
        server_model,
        rate_limits,
    ))
}

fn websocket_config() -> WebSocketConfig {
    let mut extensions = ExtensionsConfig::default();
    extensions.permessage_deflate = Some(DeflateConfig::default());

    let mut config = WebSocketConfig::default();
    config.extensions = extensions;
    config
}

fn map_ws_error(err: WsError, url: &Url) -> ApiError {
    match err {
        WsError::Http(response) => {
            let status = response.status();
            let headers = response.headers().clone();
            let body = response
                .body()
                .as_ref()
                .and_then(|bytes| String::from_utf8(bytes.clone()).ok());
            ApiError::Transport(TransportError::Http {
                status,
                url: Some(url.to_string()),
                headers: Some(headers),
                body,
            })
        }
        WsError::ConnectionClosed | WsError::AlreadyClosed => {
            ApiError::Stream("websocket closed".to_string())
        }
        WsError::Io(err) => ApiError::Transport(TransportError::Network(err.to_string())),
        other => ApiError::Transport(TransportError::Network(other.to_string())),
    }
}

#[derive(Debug, Deserialize)]
struct WrappedWebsocketError {
    code: Option<String>,
    message: Option<String>,
}

#[derive(Debug, Deserialize)]
struct WrappedWebsocketErrorEvent {
    #[serde(rename = "type")]
    kind: String,
    #[serde(alias = "status_code")]
    status: Option<u16>,
    #[serde(default)]
    error: Option<WrappedWebsocketError>,
    #[serde(default)]
    headers: Option<JsonMap<String, Value>>,
}

fn parse_wrapped_websocket_error_event(payload: &str) -> Option<WrappedWebsocketErrorEvent> {
    let event: WrappedWebsocketErrorEvent = serde_json::from_str(payload).ok()?;
    if event.kind != "error" {
        return None;
    }
    Some(event)
}

fn map_wrapped_websocket_error_event(
    event: WrappedWebsocketErrorEvent,
    original_payload: String,
) -> Option<ApiError> {
    let WrappedWebsocketErrorEvent {
        status,
        error,
        headers,
        ..
    } = event;

    if let Some(error) = error.as_ref()
        && let Some(code) = error.code.as_deref()
        && let Some(fallback_message) = match code {
            WEBSOCKET_CONNECTION_LIMIT_REACHED_CODE => {
                Some(WEBSOCKET_CONNECTION_LIMIT_REACHED_MESSAGE)
            }
            PREVIOUS_RESPONSE_NOT_FOUND_CODE => Some(PREVIOUS_RESPONSE_NOT_FOUND_MESSAGE),
            _ => None,
        }
    {
        return Some(ApiError::Retryable {
            message: error
                .message
                .clone()
                .unwrap_or_else(|| fallback_message.to_string()),
            delay: None,
        });
    }

    let status = StatusCode::from_u16(status?).ok()?;
    if status.is_success() {
        return None;
    }

    Some(ApiError::Transport(TransportError::Http {
        status,
        url: None,
        headers: headers.as_ref().map(json_headers_to_http_headers),
        body: Some(original_payload),
    }))
}

fn json_headers_to_http_headers(headers: &JsonMap<String, Value>) -> HeaderMap {
    let mut mapped = HeaderMap::new();
    for (name, value) in headers {
        let Ok(header_name) = HeaderName::from_bytes(name.as_bytes()) else {
            continue;
        };
        let Some(header_value) = json_header_value(value) else {
            continue;
        };
        mapped.insert(header_name, header_value);
    }
    mapped
}

fn json_header_value(value: &Value) -> Option<HeaderValue> {
    let value = match value {
        Value::String(value) => value.clone(),
        Value::Number(value) => value.to_string(),
        Value::Bool(value) => value.to_string(),
        _ => return None,
    };
    HeaderValue::from_str(&value).ok()
}

async fn run_websocket_response_stream(
    ws_stream: &mut WsStream,
    tx_event: mpsc::Sender<std::result::Result<ResponseEvent, ApiError>>,
    request_text: String,
    idle_timeout: Duration,
    telemetry: Option<Arc<dyn WebsocketTelemetry>>,
    turn_state: Option<&OnceLock<String>>,
    timing_log_context: &ResponsesWebsocketTimingLogContext,
) -> Result<(), ApiError> {
    let mut last_server_model: Option<String> = None;
    let mut safety_buffering_treatment = SafetyBufferingTreatment::default();
    send_websocket_request(
        ws_stream,
        request_text,
        idle_timeout,
        telemetry.as_ref(),
        timing_log_context.connection_reused,
    )
    .await?;

    loop {
        let poll_start = Instant::now();
        let response = tokio::time::timeout(idle_timeout, ws_stream.next())
            .await
            .map_err(|_| ApiError::Stream("idle timeout waiting for websocket".into()));
        if let Some(t) = telemetry.as_ref() {
            t.on_ws_event(&response, poll_start.elapsed());
        }
        let message = match response {
            Ok(Some(Ok(msg))) => msg,
            Ok(Some(Err(error))) if websocket_error_is_disconnect(&error) => {
                return Err(ApiError::WebsocketClosed(Box::new(
                    websocket_close_details(None),
                )));
            }
            Ok(Some(Err(error))) => {
                return Err(ApiError::Stream(error.to_string()));
            }
            Ok(None) => {
                return Err(ApiError::WebsocketClosed(Box::new(
                    websocket_close_details(None),
                )));
            }
            Err(err) => {
                return Err(err);
            }
        };

        match message {
            Message::Text(text) => {
                if let Some(wrapped_error) = parse_wrapped_websocket_error_event(&text)
                    && let Some(error) =
                        map_wrapped_websocket_error_event(wrapped_error, text.to_string())
                {
                    return Err(error);
                }

                let event = match serde_json::from_str::<ResponsesStreamEvent>(&text) {
                    Ok(event) => event,
                    Err(err) => {
                        debug!("failed to parse websocket event: {err}, data: {text}");
                        continue;
                    }
                };
                emit_responses_websocket_timing_event(
                    event.kind(),
                    text.as_str(),
                    timing_log_context,
                );
                if let Some(response_turn_state) = event.turn_state()
                    && let Some(turn_state) = turn_state
                {
                    let _ = turn_state.set(response_turn_state);
                }
                let model_verifications = event.model_verifications();
                let turn_moderation_metadata = event.turn_moderation_metadata();
                let safety_buffering =
                    safety_buffering_for_event(&event, &mut safety_buffering_treatment);
                if event.kind() == "codex.rate_limits" {
                    if let Some(snapshot) = parse_rate_limit_event(&text) {
                        let _ = tx_event.send(Ok(ResponseEvent::RateLimits(snapshot))).await;
                    }
                    continue;
                }
                if let Some(model) = event.response_model()
                    && last_server_model.as_deref() != Some(model.as_str())
                {
                    let _ = tx_event
                        .send(Ok(ResponseEvent::ServerModel(model.clone())))
                        .await;
                    last_server_model = Some(model);
                }
                if let Some(verifications) = model_verifications
                    && tx_event
                        .send(Ok(ResponseEvent::ModelVerifications(verifications)))
                        .await
                        .is_err()
                {
                    return Err(ApiError::Stream(
                        "response event consumer dropped".to_string(),
                    ));
                }
                if let Some(metadata) = turn_moderation_metadata
                    && tx_event
                        .send(Ok(ResponseEvent::TurnModerationMetadata(metadata)))
                        .await
                        .is_err()
                {
                    return Err(ApiError::Stream(
                        "response event consumer dropped".to_string(),
                    ));
                }
                if let Some(buffering) = safety_buffering
                    && tx_event
                        .send(Ok(ResponseEvent::SafetyBuffering(buffering)))
                        .await
                        .is_err()
                {
                    return Err(ApiError::Stream(
                        "response event consumer dropped".to_string(),
                    ));
                }
                match process_responses_event(event) {
                    Ok(Some(event)) => {
                        let is_completed = matches!(event, ResponseEvent::Completed { .. });
                        let _ = tx_event.send(Ok(event)).await;
                        if is_completed {
                            break;
                        }
                    }
                    Ok(None) => {}
                    Err(error) => {
                        return Err(error.into_api_error());
                    }
                }
            }
            Message::Binary(_) => {
                return Err(ApiError::Stream("unexpected binary websocket event".into()));
            }
            Message::Close(frame) => {
                return Err(ApiError::WebsocketClosed(Box::new(
                    websocket_close_details(frame),
                )));
            }
            Message::Frame(_) => {}
            Message::Ping(_) | Message::Pong(_) => {}
        }
    }

    Ok(())
}

fn emit_responses_websocket_timing_event(
    kind: &str,
    payload: &str,
    context: &ResponsesWebsocketTimingLogContext,
) {
    if kind != RESPONSES_WEBSOCKET_TIMING_KIND {
        return;
    }

    // This full payload is excluded from always-on sinks. Opt in with
    // `RUST_LOG='codex_api::responses_websocket_timing=trace'`.
    tracing::event!(
        name: RESPONSES_WEBSOCKET_TIMING_KIND,
        target: RESPONSES_WEBSOCKET_TIMING_EVENT_TARGET,
        tracing::Level::TRACE,
        model = context.model.as_str(),
        session_id = context.session_id.as_deref().unwrap_or_default(),
        thread_id = context.thread_id.as_deref().unwrap_or_default(),
        turn_id = context.turn_id.as_deref().unwrap_or_default(),
        traceparent = context.traceparent.as_deref().unwrap_or_default(),
        previous_response_id = context.previous_response_id.as_deref().unwrap_or_default(),
        request_start_ms = context.request_start_ms.as_deref().unwrap_or_default(),
        warmup = context.warmup,
        connection_reused = context.connection_reused,
        payload,
        "responses websocket timing"
    );
}

const MAX_WEBSOCKET_CLOSE_REASON_BYTES: usize = 160;

fn websocket_close_details(frame: Option<CloseFrame>) -> WebsocketCloseDetails {
    let Some(frame) = frame else {
        return WebsocketCloseDetails {
            code: None,
            reason: None,
            reason_redacted: false,
        };
    };
    let reason = frame.reason.trim();
    let normalized = reason.to_ascii_lowercase();
    let reason_is_allowlisted = [
        "going away",
        "maintenance",
        "restart",
        "server restart",
        "service restart",
        "drain",
    ]
    .contains(&normalized.as_str());
    let (reason, reason_redacted) = if reason.is_empty() {
        (None, false)
    } else if !reason_is_allowlisted || reason.len() > MAX_WEBSOCKET_CLOSE_REASON_BYTES {
        (Some("[redacted]".to_string()), true)
    } else {
        (Some(reason.to_string()), false)
    };
    WebsocketCloseDetails {
        code: Some(u16::from(frame.code)),
        reason,
        reason_redacted,
    }
}

fn safety_buffering_for_event(
    event: &ResponsesStreamEvent,
    treatment: &mut SafetyBufferingTreatment,
) -> Option<crate::common::SafetyBuffering> {
    if let Some(headers) = event.headers.as_ref().and_then(Value::as_object)
        && let Some(updated_treatment) =
            treatment_from_headers(&json_headers_to_http_headers(headers))
    {
        *treatment = updated_treatment;
    }
    event.safety_buffering(treatment)
}

async fn take_handshake_rate_limits(
    pending: &Mutex<Option<Vec<RateLimitSnapshot>>>,
    generate: Option<bool>,
) -> Vec<RateLimitSnapshot> {
    if generate == Some(false) {
        return Vec::new();
    }
    pending.lock().await.take().unwrap_or_default()
}

fn websocket_error_is_disconnect(error: &WsError) -> bool {
    match error {
        WsError::AlreadyClosed
        | WsError::ConnectionClosed
        | WsError::Protocol(ProtocolError::ResetWithoutClosingHandshake) => true,
        WsError::Io(error) => matches!(
            error.kind(),
            std::io::ErrorKind::BrokenPipe
                | std::io::ErrorKind::ConnectionAborted
                | std::io::ErrorKind::ConnectionReset
                | std::io::ErrorKind::NotConnected
                | std::io::ErrorKind::UnexpectedEof
        ),
        _ => false,
    }
}

const MAX_PENDING_WEBSOCKET_MESSAGES_TO_INSPECT: usize = 32;

fn pending_websocket_close(ws_stream: &mut WsStream) -> Option<ResponsesWebsocketClose> {
    for _ in 0..MAX_PENDING_WEBSOCKET_MESSAGES_TO_INSPECT {
        match ws_stream.rx_message.try_recv() {
            Ok(Ok(Message::Close(frame))) => {
                return Some(close_details_to_probe(true, websocket_close_details(frame)));
            }
            Ok(_) => {}
            Err(_) => break,
        }
    }
    None
}

async fn send_websocket_request(
    ws_stream: &mut WsStream,
    request_text: String,
    idle_timeout: Duration,
    telemetry: Option<&Arc<dyn WebsocketTelemetry>>,
    connection_reused: bool,
) -> Result<(), ApiError> {
    let request_start = Instant::now();
    let result = match tokio::time::timeout(
        idle_timeout,
        ws_stream.send(Message::Text(request_text.into())),
    )
    .await
    {
        Err(_) => Err(ApiError::Stream(
            "idle timeout sending websocket request".into(),
        )),
        Ok(Ok(())) => Ok(()),
        Ok(Err(error)) => {
            let pending_close = pending_websocket_close(ws_stream);
            if websocket_error_is_disconnect(&error) || pending_close.is_some() {
                let details = pending_close
                    .map(|close| WebsocketCloseDetails {
                        code: close.code,
                        reason: close.reason,
                        reason_redacted: close.reason_redacted,
                    })
                    .unwrap_or_else(|| websocket_close_details(None));
                Err(ApiError::WebsocketClosed(Box::new(details)))
            } else {
                Err(ApiError::Stream(error.to_string()))
            }
        }
    };

    if let Some(t) = telemetry.as_ref() {
        t.on_ws_request(
            request_start.elapsed(),
            result.as_ref().err(),
            connection_reused,
        );
    }

    result?;

    Ok(())
}

fn serialize_websocket_request(request: &ResponsesWsRequest<'_>) -> Result<String, ApiError> {
    serde_json::to_string(request)
        .map_err(|err| ApiError::Stream(format!("failed to encode websocket request: {err}")))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::common::ResponseCreateWsRequest;
    use crate::common::ResponsesApiRequest;
    use codex_protocol::ResponseItemId;
    use codex_protocol::models::ContentItem;
    use codex_protocol::models::ResponseItem;
    use pretty_assertions::assert_eq;
    use serde_json::json;
    use serde_json::value::RawValue;
    use serde_json::value::to_raw_value;
    use std::collections::HashMap;
    use std::sync::Arc;

    fn test_websocket_request() -> ResponsesWsRequest {
        ResponsesWsRequest::ResponseCreate(ResponseCreateWsRequest {
            model: "gpt-test".to_string(),
            instructions: "test".to_string(),
            previous_response_id: None,
            input: Vec::new(),
            tools: None,
            tool_choice: "auto".to_string(),
            parallel_tool_calls: false,
            reasoning: None,
            store: false,
            stream: true,
            stream_options: None,
            include: Vec::new(),
            service_tier: None,
            prompt_cache_key: None,
            text: None,
            generate: Some(true),
            client_metadata: None,
        })
    }

    fn ws_stream_with_messages(messages: Vec<Result<Message, WsError>>) -> WsStream {
        let (tx_command, mut rx_command) = mpsc::channel(1);
        let (tx_message, rx_message) = mpsc::unbounded_channel();
        for message in messages {
            tx_message.send(message).expect("queue websocket message");
        }
        drop(tx_message);
        let pump_task = tokio::spawn(async move {
            while let Some(WsCommand::Send { tx_result, .. }) = rx_command.recv().await {
                let _ = tx_result.send(Ok(()));
            }
        });
        WsStream {
            tx_command,
            rx_message,
            pump_task,
        }
    }

    #[tokio::test]
    async fn response_stream_eof_is_websocket_closed() {
        let mut ws_stream = ws_stream_with_messages(Vec::new());
        let (tx_event, _rx_event) = mpsc::channel(1);

        let error = run_websocket_response_stream(
            &mut ws_stream,
            tx_event,
            "{}".to_string(),
            Duration::from_secs(1),
            None,
            false,
            None,
        )
        .await
        .expect_err("EOF before response.completed must fail");

        let ApiError::WebsocketClosed(details) = error else {
            panic!("expected typed websocket close, got {error:?}");
        };
        assert_eq!(*details, websocket_close_details(None));
    }

    #[tokio::test]
    async fn response_stream_preserves_non_close_websocket_error() {
        let protocol_error = ProtocolError::InvalidOpcode(0xff);
        let mut ws_stream = ws_stream_with_messages(vec![Err(WsError::Protocol(protocol_error))]);
        let (tx_event, _rx_event) = mpsc::channel(1);

        let error = run_websocket_response_stream(
            &mut ws_stream,
            tx_event,
            "{}".to_string(),
            Duration::from_secs(1),
            None,
            false,
            None,
        )
        .await
        .expect_err("non-close websocket error must fail");

        assert!(matches!(error, ApiError::Stream(message) if message.contains("opcode")));
    }

    #[tokio::test]
    async fn closed_connection_stream_request_returns_typed_close() {
        let connection = ResponsesWebsocketConnection {
            stream: Arc::new(Mutex::new(None)),
            idle_timeout: Duration::from_secs(1),
            server_reasoning_included: false,
            models_etag: None,
            handshake_rate_limits: Mutex::new(None),
            server_model: None,
            telemetry: None,
        };

        let mut response_stream = connection
            .stream_request(test_websocket_request(), false, None)
            .await
            .expect("stream request returns an asynchronous response stream");
        let error = response_stream
            .next()
            .await
            .expect("closed connection emits a terminal error")
            .expect_err("closed connection cannot send a request");

        let ApiError::WebsocketClosed(details) = error else {
            panic!("expected typed websocket close, got {error:?}");
        };
        assert_eq!(*details, websocket_close_details(None));
    }

    #[tokio::test]
    async fn websocket_probe_grace_timeout_is_success_without_close() {
        let read = tokio::time::timeout(
            Duration::ZERO,
            futures::future::pending::<Option<Result<Message, WsError>>>(),
        )
        .await;

        let immediate_close =
            immediate_close_from_probe_read(read).expect("grace timeout must not fail probe");

        assert_eq!(immediate_close, None);
    }

    #[test]
    fn websocket_probe_eof_is_an_explicit_immediate_close() {
        let close = immediate_close_from_probe_read(Ok(None))
            .expect("EOF is a legal probe result")
            .expect("EOF must be reported as an immediate close");

        assert!(!close.frame_received);
        assert_eq!(close.code, None);
        assert_eq!(close.reason, None);
        assert!(!close.reason_redacted);
    }

    #[test]
    fn websocket_probe_disconnect_error_is_an_explicit_immediate_close() {
        let close = immediate_close_from_probe_read(Ok(Some(Err(WsError::ConnectionClosed))))
            .expect("connection close is a legal probe result")
            .expect("connection close must be reported");

        assert!(!close.frame_received);
        assert_eq!(close.code, None);
        assert_eq!(close.reason, None);
        assert!(!close.reason_redacted);
    }

    #[test]
    fn websocket_probe_preserves_non_close_io_error() {
        let error = immediate_close_from_probe_read(Ok(Some(Err(WsError::Io(
            std::io::Error::new(std::io::ErrorKind::PermissionDenied, "permission denied"),
        )))))
        .expect_err("non-close I/O error must fail the probe");

        assert!(
            matches!(error, ApiError::Stream(message) if message.contains("permission denied"))
        );
    }

    #[test]
    fn websocket_probe_frameless_close_is_an_explicit_immediate_close() {
        let close = immediate_close_from_probe_read(Ok(Some(Ok(Message::Close(None)))))
            .expect("frameless close is a legal probe result")
            .expect("frameless close must be reported as an immediate close");

        assert!(close.frame_received);
        assert_eq!(close.code, None);
        assert_eq!(close.reason, None);
        assert!(!close.reason_redacted);
    }

    #[test]
    fn websocket_probe_close_reasons_use_public_diagnostic_policy() {
        let safe =
            immediate_close_from_probe_read(Ok(Some(Ok(Message::Close(Some(CloseFrame {
                code: tokio_tungstenite::tungstenite::protocol::frame::coding::CloseCode::Away,
                reason: "maintenance".into(),
            }))))))
            .expect("safe close is a legal probe result")
            .expect("close frame must be reported");
        assert_eq!(safe.reason.as_deref(), Some("maintenance"));
        assert!(!safe.reason_redacted);

        let raw_sensitive = "bearer sk-proj-sensitive-probe-value";
        let sensitive =
            immediate_close_from_probe_read(Ok(Some(Ok(Message::Close(Some(CloseFrame {
                code: tokio_tungstenite::tungstenite::protocol::frame::coding::CloseCode::Policy,
                reason: raw_sensitive.into(),
            }))))))
            .expect("sensitive close is a legal probe result")
            .expect("close frame must be reported");
        assert_eq!(sensitive.reason.as_deref(), Some("[redacted]"));
        assert!(sensitive.reason_redacted);
        assert!(
            !format!("{sensitive:?}").contains(raw_sensitive),
            "public probe result must not retain the raw reason"
        );

        let raw_long = "x".repeat(MAX_WEBSOCKET_CLOSE_REASON_BYTES + 1);
        let long =
            immediate_close_from_probe_read(Ok(Some(Ok(Message::Close(Some(CloseFrame {
                code: tokio_tungstenite::tungstenite::protocol::frame::coding::CloseCode::Away,
                reason: raw_long.clone().into(),
            }))))))
            .expect("long close is a legal probe result")
            .expect("close frame must be reported");
        let public_reason = long.reason.as_deref().expect("bounded public reason");
        assert!(public_reason.len() <= MAX_WEBSOCKET_CLOSE_REASON_BYTES);
        assert!(!public_reason.contains(&raw_long));
        assert!(long.reason_redacted);
    }

    #[test]
    fn websocket_close_details_are_bounded_and_redacted() {
        let missing = websocket_close_details(None);
        assert_eq!(missing.code, None);
        assert_eq!(missing.reason, None);
        assert!(!missing.reason_redacted);

        let safe = websocket_close_details(Some(CloseFrame {
            code: tokio_tungstenite::tungstenite::protocol::frame::coding::CloseCode::from(4001),
            reason: "maintenance".into(),
        }));
        assert_eq!(safe.code, Some(4001));
        assert_eq!(safe.reason.as_deref(), Some("maintenance"));
        assert!(!safe.reason_redacted);

        let sensitive = websocket_close_details(Some(CloseFrame {
            code: tokio_tungstenite::tungstenite::protocol::frame::coding::CloseCode::Policy,
            reason: "contact operator@example.com with bearer secret".into(),
        }));
        assert_eq!(sensitive.reason.as_deref(), Some("[redacted]"));
        assert!(sensitive.reason_redacted);

        let opaque_secret = websocket_close_details(Some(CloseFrame {
            code: tokio_tungstenite::tungstenite::protocol::frame::coding::CloseCode::Policy,
            reason: "sk-proj-abc123".into(),
        }));
        assert_eq!(opaque_secret.reason.as_deref(), Some("[redacted]"));
        assert!(opaque_secret.reason_redacted);

        let long = websocket_close_details(Some(CloseFrame {
            code: tokio_tungstenite::tungstenite::protocol::frame::coding::CloseCode::Away,
            reason: "x".repeat(MAX_WEBSOCKET_CLOSE_REASON_BYTES + 20).into(),
        }));
        assert!(
            long.reason.as_deref().expect("bounded reason").len()
                <= MAX_WEBSOCKET_CLOSE_REASON_BYTES
        );
    }

    #[test]
    fn websocket_error_classifier_preserves_non_disconnect_failures() {
        assert!(websocket_error_is_disconnect(&WsError::ConnectionClosed));
        assert!(websocket_error_is_disconnect(&WsError::AlreadyClosed));
        assert!(websocket_error_is_disconnect(&WsError::Io(
            std::io::Error::new(std::io::ErrorKind::UnexpectedEof, "socket EOF")
        )));
        assert!(websocket_error_is_disconnect(&WsError::Io(
            std::io::Error::new(std::io::ErrorKind::ConnectionReset, "connection reset")
        )));
        assert!(websocket_error_is_disconnect(&WsError::Protocol(
            ProtocolError::ResetWithoutClosingHandshake,
        )));
        assert!(!websocket_error_is_disconnect(&WsError::Io(
            std::io::Error::new(std::io::ErrorKind::PermissionDenied, "permission denied")
        )));
        assert!(!websocket_error_is_disconnect(&WsError::Io(
            std::io::Error::new(std::io::ErrorKind::InvalidData, "invalid data")
        )));
        assert!(!websocket_error_is_disconnect(&WsError::Io(
            std::io::Error::new(std::io::ErrorKind::TimedOut, "timed out")
        )));
        assert!(!websocket_error_is_disconnect(&WsError::Protocol(
            ProtocolError::InvalidOpcode(0xff),
        )));
    }

    #[tokio::test]
    async fn websocket_prewarm_preserves_handshake_rate_limits_for_generated_request() {
        let pending = Mutex::new(Some(Vec::new()));

        assert!(
            take_handshake_rate_limits(&pending, Some(false))
                .await
                .is_empty()
        );
        assert!(
            pending.lock().await.is_some(),
            "prewarm must not consume pending handshake metadata"
        );
        assert!(
            take_handshake_rate_limits(&pending, Some(true))
                .await
                .is_empty()
        );
        assert!(
            pending.lock().await.is_none(),
            "first generated request consumes pending handshake metadata"
        );
    }

    #[tokio::test]
    async fn pending_close_skips_stale_messages() {
        let (tx_command, _rx_command) = mpsc::channel(1);
        let (tx_message, rx_message) = mpsc::unbounded_channel::<Result<Message, WsError>>();
        let pump_task = tokio::spawn(async {});
        let mut ws_stream = WsStream {
            tx_command,
            rx_message,
            pump_task,
        };
        tx_message
            .send(Ok(Message::Text("stale response".into())))
            .expect("queue stale response");
        tx_message
            .send(Ok(Message::Close(Some(CloseFrame {
                code: tokio_tungstenite::tungstenite::protocol::frame::coding::CloseCode::from(
                    4001,
                ),
                reason: "maintenance".into(),
            }))))
            .expect("queue close frame");

        let close = pending_websocket_close(&mut ws_stream).expect("queued close frame");
        assert!(close.frame_received);
        assert_eq!(close.code, Some(4001));
        assert_eq!(close.reason.as_deref(), Some("maintenance"));
    }

    #[tokio::test]
    async fn send_error_with_pending_frameless_close_is_typed_close() {
        let (tx_command, mut rx_command) = mpsc::channel(1);
        let (tx_message, rx_message) = mpsc::unbounded_channel::<Result<Message, WsError>>();
        tx_message
            .send(Ok(Message::Close(None)))
            .expect("queue frameless close");
        let pump_task = tokio::spawn(async move {
            if let Some(WsCommand::Send { tx_result, .. }) = rx_command.recv().await {
                let _ = tx_result.send(Err(WsError::Io(std::io::Error::new(
                    std::io::ErrorKind::PermissionDenied,
                    "permission denied",
                ))));
            }
        });
        let mut ws_stream = WsStream {
            tx_command,
            rx_message,
            pump_task,
        };

        let error = send_websocket_request(
            &mut ws_stream,
            "{}".to_string(),
            Duration::from_secs(1),
            None,
            false,
        )
        .await
        .expect_err("queued close must type the send failure");

        let ApiError::WebsocketClosed(details) = error else {
            panic!("expected typed websocket close, got {error:?}");
        };
        assert_eq!(details.code, None);
        assert_eq!(details.reason, None);
        assert!(!details.reason_redacted);
    }

    #[test]
    fn direct_serialization_preserves_websocket_request_payload() {
        let api_request = ResponsesApiRequest {
            model: "gpt-test".to_string(),
            instructions: "Use the available tools.".to_string(),
            input: vec![ResponseItem::Message {
                id: Some(ResponseItemId::with_suffix("msg", "1")),
                role: "user".to_string(),
                content: vec![ContentItem::InputText {
                    text: "hello".to_string(),
                }],
                phase: None,
                internal_chat_message_metadata_passthrough: None,
            }],
            tools: Some(
                Arc::<RawValue>::from(
                    to_raw_value(&vec![json!({
                        "type": "function",
                        "name": "lookup",
                        "parameters": {"type": "object"}
                    })])
                    .expect("serialize tools"),
                )
                .into(),
            ),
            tool_choice: "auto".to_string(),
            parallel_tool_calls: true,
            reasoning: None,
            store: false,
            stream: true,
            stream_options: None,
            include: vec!["reasoning.encrypted_content".to_string()],
            service_tier: Some("priority".to_string()),
            prompt_cache_key: Some("cache-key".to_string()),
            text: None,
            client_metadata: Some(HashMap::from([(
                "traceparent".to_string(),
                "00-0123456789abcdef0123456789abcdef-0123456789abcdef-01".to_string(),
            )])),
        };
        let request = ResponsesWsRequest::ResponseCreate(ResponseCreateWsRequest {
            previous_response_id: Some("resp-1".to_string()),
            generate: Some(false),
            ..ResponseCreateWsRequest::from(&api_request)
        });

        let mut expected_payload =
            serde_json::to_value(&api_request).expect("serialize responses API request");
        expected_payload["type"] = json!("response.create");
        expected_payload["previous_response_id"] = json!("resp-1");
        expected_payload["generate"] = json!(false);
        let request_text =
            serialize_websocket_request(&request).expect("serialize websocket request");
        let wire_payload =
            serde_json::from_str::<Value>(&request_text).expect("parse websocket request");

        assert_eq!(wire_payload, expected_payload);
    }

    #[test]
    fn websocket_config_enables_permessage_deflate() {
        let config = websocket_config();
        assert!(config.extensions.permessage_deflate.is_some());
    }

    #[test]
    fn parse_wrapped_websocket_error_event_maps_to_transport_http() {
        let payload = json!({
            "type": "error",
            "status": 429,
            "error": {
                "type": "usage_limit_reached",
                "message": "The usage limit has been reached",
                "plan_type": "pro",
                "resets_at": 1738888888
            },
            "headers": {
                "x-codex-primary-used-percent": "100.0",
                "x-codex-primary-window-minutes": 15
            }
        })
        .to_string();

        let wrapped_error = parse_wrapped_websocket_error_event(&payload)
            .expect("expected websocket error payload to be parsed");
        let api_error = map_wrapped_websocket_error_event(wrapped_error, payload)
            .expect("expected websocket error payload to map to ApiError");

        let ApiError::Transport(TransportError::Http {
            status,
            headers,
            body,
            ..
        }) = api_error
        else {
            panic!("expected ApiError::Transport(Http)");
        };

        assert_eq!(status, StatusCode::TOO_MANY_REQUESTS);
        let headers = headers.expect("expected headers");
        assert_eq!(
            headers
                .get("x-codex-primary-used-percent")
                .and_then(|value| value.to_str().ok()),
            Some("100.0")
        );
        assert_eq!(
            headers
                .get("x-codex-primary-window-minutes")
                .and_then(|value| value.to_str().ok()),
            Some("15")
        );
        let body = body.expect("expected body");
        assert!(body.contains("usage_limit_reached"));
        assert!(body.contains("The usage limit has been reached"));
    }

    #[test]
    fn parse_wrapped_websocket_error_event_ignores_non_error_payloads() {
        let payload = json!({
            "type": "response.created",
            "response": {
                "id": "resp-1"
            }
        })
        .to_string();

        let wrapped_error = parse_wrapped_websocket_error_event(&payload);
        assert!(wrapped_error.is_none());
    }

    #[test]
    fn parse_wrapped_websocket_error_event_with_status_maps_invalid_request() {
        let payload = json!({
            "type": "error",
            "status": 400,
            "error": {
                "type": "invalid_request_error",
                "message": "Model does not support image inputs"
            }
        })
        .to_string();

        let wrapped_error = parse_wrapped_websocket_error_event(&payload)
            .expect("expected websocket error payload to be parsed");
        let api_error = map_wrapped_websocket_error_event(wrapped_error, payload)
            .expect("expected websocket error payload to map to ApiError");
        let ApiError::Transport(TransportError::Http { status, body, .. }) = api_error else {
            panic!("expected ApiError::Transport(Http)");
        };
        assert_eq!(status, StatusCode::BAD_REQUEST);
        let body = body.expect("expected body");
        assert!(body.contains("invalid_request_error"));
        assert!(body.contains("Model does not support image inputs"));
    }

    #[test]
    fn parse_wrapped_websocket_error_event_with_connection_limit_maps_retryable() {
        let payload = json!({
            "type": "error",
            "status": 400,
            "error": {
                "type": "invalid_request_error",
                "code": "websocket_connection_limit_reached",
                "message": "Responses websocket connection limit reached (60 minutes). Create a new websocket connection to continue."
            }
        })
        .to_string();

        let wrapped_error = parse_wrapped_websocket_error_event(&payload)
            .expect("expected websocket error payload to be parsed");
        let api_error = map_wrapped_websocket_error_event(wrapped_error, payload)
            .expect("expected websocket error payload to map to ApiError");
        let ApiError::Retryable { message, delay } = api_error else {
            panic!("expected ApiError::Retryable");
        };
        assert_eq!(message, WEBSOCKET_CONNECTION_LIMIT_REACHED_MESSAGE);
        assert_eq!(delay, None);
    }

    #[test]
    fn parse_wrapped_websocket_error_event_without_status_is_not_mapped() {
        let payload = json!({
            "type": "error",
            "error": {
                "type": "usage_limit_reached",
                "message": "The usage limit has been reached"
            },
            "headers": {
                "x-codex-primary-used-percent": "100.0",
                "x-codex-primary-window-minutes": 15
            }
        })
        .to_string();

        let wrapped_error = parse_wrapped_websocket_error_event(&payload)
            .expect("expected websocket error payload to be parsed");
        let api_error = map_wrapped_websocket_error_event(wrapped_error, payload);
        assert!(api_error.is_none());
    }

    #[test]
    fn merge_request_headers_matches_http_precedence() {
        let mut provider_headers = HeaderMap::new();
        provider_headers.insert(
            "originator",
            HeaderValue::from_static("provider-originator"),
        );
        provider_headers.insert("x-priority", HeaderValue::from_static("provider"));

        let mut extra_headers = HeaderMap::new();
        extra_headers.insert("x-priority", HeaderValue::from_static("extra"));

        let mut default_headers = HeaderMap::new();
        default_headers.insert("originator", HeaderValue::from_static("default-originator"));
        default_headers.insert("x-priority", HeaderValue::from_static("default"));
        default_headers.insert("x-default-only", HeaderValue::from_static("default-only"));

        let merged = merge_request_headers(&provider_headers, extra_headers, default_headers);

        assert_eq!(
            merged.get("originator"),
            Some(&HeaderValue::from_static("provider-originator"))
        );
        assert_eq!(
            merged.get("x-priority"),
            Some(&HeaderValue::from_static("extra"))
        );
        assert_eq!(
            merged.get("x-default-only"),
            Some(&HeaderValue::from_static("default-only"))
        );
    }

    #[test]
    fn websocket_safety_buffering_uses_event_before_header_fallback() {
        let metadata: ResponsesStreamEvent = serde_json::from_value(json!({
            "type": "codex.response.metadata",
            "headers": {
                "x-codex-safety-buffering-enabled": "true",
                "x-codex-safety-buffering-faster-model": "gpt-fast-header"
            }
        }))
        .expect("deserialize treatment metadata");
        let event: ResponsesStreamEvent = serde_json::from_value(json!({
            "type": "response.output_text.delta",
            "safety_buffering": {
                "use_cases": ["cyber"],
                "reasons": ["user_risk"],
                "retry_model": "gpt-fast-wire"
            }
        }))
        .expect("deserialize safety buffering event");
        let mut treatment = SafetyBufferingTreatment::default();

        assert!(safety_buffering_for_event(&metadata, &mut treatment).is_none());
        let buffering = safety_buffering_for_event(&event, &mut treatment)
            .expect("expected safety buffering payload");

        assert_eq!(
            buffering,
            crate::common::SafetyBuffering {
                use_cases: vec!["cyber".to_string()],
                reasons: vec!["user_risk".to_string()],
                show_buffering_ui: true,
                faster_model: Some("gpt-fast-wire".to_string()),
            }
        );
    }

    #[test]
    fn websocket_safety_buffering_event_controls_visibility_when_header_disables_it() {
        let metadata: ResponsesStreamEvent = serde_json::from_value(json!({
            "type": "codex.response.metadata",
            "headers": {
                "x-codex-safety-buffering-enabled": "false",
                "x-codex-safety-buffering-faster-model": "gpt-fast-header"
            }
        }))
        .expect("deserialize treatment metadata");
        let event: ResponsesStreamEvent = serde_json::from_value(json!({
            "type": "response.output_text.delta",
            "safety_buffering": {
                "use_cases": ["cyber"],
                "reasons": ["user_risk"]
            }
        }))
        .expect("deserialize safety buffering event");
        let mut treatment = SafetyBufferingTreatment::default();

        assert!(safety_buffering_for_event(&metadata, &mut treatment).is_none());
        let buffering = safety_buffering_for_event(&event, &mut treatment)
            .expect("expected safety buffering payload");

        assert_eq!(
            buffering,
            crate::common::SafetyBuffering {
                use_cases: vec!["cyber".to_string()],
                reasons: vec!["user_risk".to_string()],
                show_buffering_ui: true,
                faster_model: Some("gpt-fast-header".to_string()),
            }
        );
    }
}
