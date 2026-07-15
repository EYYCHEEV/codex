use crate::api_bridge::parse_rate_limit_headers;
use crate::auth::SharedAuthProvider;
use crate::common::CompactionInput;
use crate::endpoint::session::EndpointSession;
use crate::error::ApiError;
use crate::provider::Provider;
use crate::rate_limits::has_rate_limit_data;
use codex_client::HttpTransport;
use codex_client::RequestTelemetry;
use codex_protocol::models::ResponseItem;
use codex_protocol::protocol::RateLimitSnapshot;
use http::HeaderMap;
use http::Method;
use serde::Deserialize;
use std::sync::Arc;
use std::sync::OnceLock;
use std::time::Duration;

const X_CODEX_TURN_STATE_HEADER: &str = "x-codex-turn-state";

#[derive(Debug, Clone, PartialEq)]
pub struct ApiCompactResponse {
    pub output: Vec<ResponseItem>,
    pub rate_limits: Option<RateLimitSnapshot>,
}

pub struct CompactClient<T: HttpTransport> {
    session: EndpointSession<T>,
}

impl<T: HttpTransport> CompactClient<T> {
    pub fn new(transport: T, provider: Provider, auth: SharedAuthProvider) -> Self {
        Self {
            session: EndpointSession::new(transport, provider, auth),
        }
    }

    pub fn with_telemetry(self, request: Option<Arc<dyn RequestTelemetry>>) -> Self {
        Self {
            session: self.session.with_request_telemetry(request),
        }
    }

    fn path() -> &'static str {
        "responses/compact"
    }

    pub async fn compact(
        &self,
        body: serde_json::Value,
        extra_headers: HeaderMap,
        request_timeout: Duration,
        turn_state: Option<&OnceLock<String>>,
    ) -> Result<ApiCompactResponse, ApiError> {
        let resp = self
            .session
            .execute_with(
                Method::POST,
                Self::path(),
                extra_headers,
                Some(body),
                |req| {
                    req.timeout = Some(request_timeout);
                },
            )
            .await?;
        if let Some(turn_state) = turn_state
            && let Some(header_value) = resp
                .headers
                .get(X_CODEX_TURN_STATE_HEADER)
                .and_then(|value| value.to_str().ok())
        {
            let _ = turn_state.set(header_value.to_string());
        }
        let rate_limits = parse_rate_limit_headers(&resp.headers).filter(has_rate_limit_data);
        let parsed: CompactHistoryResponse =
            serde_json::from_slice(&resp.body).map_err(|e| ApiError::Stream(e.to_string()))?;
        Ok(ApiCompactResponse {
            output: parsed.output,
            rate_limits,
        })
    }

    pub async fn compact_input(
        &self,
        input: &CompactionInput<'_>,
        extra_headers: HeaderMap,
        request_timeout: Duration,
        turn_state: Option<&OnceLock<String>>,
    ) -> Result<ApiCompactResponse, ApiError> {
        let body = serde_json::to_value(input)
            .map_err(|e| ApiError::Stream(format!("failed to encode compaction input: {e}")))?;
        self.compact(body, extra_headers, request_timeout, turn_state)
            .await
    }
}

#[derive(Debug, Deserialize)]
struct CompactHistoryResponse {
    output: Vec<ResponseItem>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::AuthProvider;
    use crate::provider::RetryConfig;
    use codex_client::Request;
    use codex_client::Response;
    use codex_client::StreamResponse;
    use codex_client::TransportError;
    use http::StatusCode;

    #[derive(Clone, Default)]
    struct DummyTransport;

    impl HttpTransport for DummyTransport {
        async fn execute(&self, _req: Request) -> Result<Response, TransportError> {
            Err(TransportError::Build("execute should not run".to_string()))
        }

        async fn stream(&self, _req: Request) -> Result<StreamResponse, TransportError> {
            Err(TransportError::Build("stream should not run".to_string()))
        }
    }

    #[derive(Clone, Default)]
    struct ResponseTransport {
        headers: HeaderMap,
    }

    impl HttpTransport for ResponseTransport {
        async fn execute(&self, _req: Request) -> Result<Response, TransportError> {
            Ok(Response {
                status: StatusCode::OK,
                headers: self.headers.clone(),
                body: br#"{"output":[]}"#.to_vec().into(),
            })
        }

        async fn stream(&self, _req: Request) -> Result<StreamResponse, TransportError> {
            Err(TransportError::Build("stream should not run".to_string()))
        }
    }

    #[derive(Clone, Default)]
    struct DummyAuth;

    impl AuthProvider for DummyAuth {
        fn add_auth_headers(&self, _headers: &mut HeaderMap) {}
    }

    fn provider() -> Provider {
        Provider {
            name: "test".to_string(),
            base_url: "https://example.com/api/codex".to_string(),
            query_params: None,
            headers: HeaderMap::new(),
            retry: RetryConfig {
                max_attempts: 1,
                base_delay: Duration::from_millis(1),
                retry_429: false,
                retry_5xx: false,
                retry_transport: false,
            },
            stream_idle_timeout: Duration::from_secs(1),
        }
    }

    async fn compact_with_headers(headers: HeaderMap) -> ApiCompactResponse {
        CompactClient::new(
            ResponseTransport { headers },
            provider(),
            Arc::new(DummyAuth),
        )
        .compact(
            serde_json::json!({"model": "test", "input": []}),
            HeaderMap::new(),
            Duration::from_secs(1),
            None,
        )
        .await
        .expect("compact response")
    }

    #[tokio::test]
    async fn compact_returns_rate_limit_windows_from_response_headers() {
        let mut headers = HeaderMap::new();
        headers.insert(
            "x-codex-active-limit",
            http::HeaderValue::from_static("codex"),
        );
        headers.insert(
            "x-codex-primary-used-percent",
            http::HeaderValue::from_static("42.5"),
        );
        headers.insert(
            "x-codex-primary-window-minutes",
            http::HeaderValue::from_static("300"),
        );
        headers.insert(
            "x-codex-primary-reset-at",
            http::HeaderValue::from_static("1770000000"),
        );
        headers.insert(
            "x-codex-secondary-used-percent",
            http::HeaderValue::from_static("17"),
        );
        headers.insert(
            "x-codex-secondary-window-minutes",
            http::HeaderValue::from_static("10080"),
        );
        headers.insert(
            "x-codex-secondary-reset-at",
            http::HeaderValue::from_static("1770600000"),
        );

        let response = compact_with_headers(headers).await;
        assert!(response.output.is_empty());
        let rate_limits = response.rate_limits.expect("rate limit snapshot");
        assert_eq!(rate_limits.limit_id.as_deref(), Some("codex"));
        let primary = rate_limits.primary.expect("primary window");
        assert_eq!(primary.used_percent, 42.5);
        assert_eq!(primary.window_minutes, Some(300));
        assert_eq!(primary.resets_at, Some(1770000000));
        let secondary = rate_limits.secondary.expect("secondary window");
        assert_eq!(secondary.used_percent, 17.0);
        assert_eq!(secondary.window_minutes, Some(10080));
        assert_eq!(secondary.resets_at, Some(1770600000));
    }

    #[tokio::test]
    async fn compact_without_rate_limit_headers_remains_compatible() {
        let response = compact_with_headers(HeaderMap::new()).await;
        assert!(response.output.is_empty());
        assert_eq!(response.rate_limits, None);
    }

    #[test]
    fn path_is_responses_compact() {
        assert_eq!(CompactClient::<DummyTransport>::path(), "responses/compact");
    }
}
