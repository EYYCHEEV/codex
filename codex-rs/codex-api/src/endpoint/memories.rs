use crate::api_bridge::parse_rate_limit_headers;
use crate::auth::SharedAuthProvider;
use crate::common::MemorySummarizeInput;
use crate::common::MemorySummarizeOutput;
use crate::endpoint::session::EndpointSession;
use crate::error::ApiError;
use crate::provider::Provider;
use crate::rate_limits::has_rate_limit_data;
use codex_client::HttpTransport;
use codex_client::RequestTelemetry;
use codex_protocol::protocol::RateLimitSnapshot;
use http::HeaderMap;
use http::Method;
use serde::Deserialize;
use serde_json::to_value;
use std::sync::Arc;

#[derive(Debug, Clone, PartialEq)]
pub struct ApiMemoryResponse {
    pub output: Vec<MemorySummarizeOutput>,
    pub rate_limits: Option<RateLimitSnapshot>,
}

pub struct MemoriesClient<T: HttpTransport> {
    session: EndpointSession<T>,
}

impl<T: HttpTransport> MemoriesClient<T> {
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
        "memories/trace_summarize"
    }

    pub async fn summarize(
        &self,
        body: serde_json::Value,
        extra_headers: HeaderMap,
    ) -> Result<ApiMemoryResponse, ApiError> {
        let resp = self
            .session
            .execute(Method::POST, Self::path(), extra_headers, Some(body))
            .await?;
        let rate_limits = parse_rate_limit_headers(&resp.headers).filter(has_rate_limit_data);
        let parsed: SummarizeResponse =
            serde_json::from_slice(&resp.body).map_err(|e| ApiError::Stream(e.to_string()))?;
        Ok(ApiMemoryResponse {
            output: parsed.output,
            rate_limits,
        })
    }

    pub async fn summarize_input(
        &self,
        input: &MemorySummarizeInput,
        extra_headers: HeaderMap,
    ) -> Result<ApiMemoryResponse, ApiError> {
        let body = to_value(input).map_err(|e| {
            ApiError::Stream(format!("failed to encode memory summarize input: {e}"))
        })?;
        self.summarize(body, extra_headers).await
    }
}

#[derive(Debug, Deserialize)]
struct SummarizeResponse {
    output: Vec<MemorySummarizeOutput>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::AuthProvider;
    use crate::common::RawMemory;
    use crate::common::RawMemoryMetadata;
    use crate::provider::RetryConfig;
    use codex_client::Request;
    use codex_client::RequestBody;
    use codex_client::Response;
    use codex_client::StreamResponse;
    use codex_client::TransportError;
    use codex_protocol::error::CodexErr;
    use http::HeaderMap;
    use http::Method;
    use http::StatusCode;
    use pretty_assertions::assert_eq;
    use serde_json::json;
    use std::sync::Arc;
    use std::sync::Mutex;
    use std::time::Duration;

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
    struct DummyAuth;

    impl AuthProvider for DummyAuth {
        fn add_auth_headers(&self, _headers: &mut HeaderMap) {}
    }

    #[derive(Clone)]
    struct CapturingTransport {
        last_request: Arc<Mutex<Option<Request>>>,
        response_body: Arc<Vec<u8>>,
        response_headers: Arc<HeaderMap>,
    }

    impl CapturingTransport {
        fn new(response_body: Vec<u8>) -> Self {
            Self::with_headers(response_body, HeaderMap::new())
        }

        fn with_headers(response_body: Vec<u8>, response_headers: HeaderMap) -> Self {
            Self {
                last_request: Arc::new(Mutex::new(None)),
                response_body: Arc::new(response_body),
                response_headers: Arc::new(response_headers),
            }
        }
    }

    impl HttpTransport for CapturingTransport {
        async fn execute(&self, req: Request) -> Result<Response, TransportError> {
            *self.last_request.lock().expect("lock request store") = Some(req);
            Ok(Response {
                status: StatusCode::OK,
                headers: self.response_headers.as_ref().clone(),
                body: self.response_body.as_ref().clone().into(),
            })
        }

        async fn stream(&self, _req: Request) -> Result<StreamResponse, TransportError> {
            Err(TransportError::Build("stream should not run".to_string()))
        }
    }

    #[derive(Clone)]
    struct ErrorTransport {
        headers: HeaderMap,
        body: String,
    }

    impl HttpTransport for ErrorTransport {
        async fn execute(&self, _req: Request) -> Result<Response, TransportError> {
            Err(TransportError::Http {
                status: StatusCode::TOO_MANY_REQUESTS,
                url: Some("https://example.com/api/codex/memories/trace_summarize".to_string()),
                headers: Some(self.headers.clone()),
                body: Some(self.body.clone()),
            })
        }

        async fn stream(&self, _req: Request) -> Result<StreamResponse, TransportError> {
            Err(TransportError::Build("stream should not run".to_string()))
        }
    }

    fn provider(base_url: &str) -> Provider {
        Provider {
            name: "test".to_string(),
            base_url: base_url.to_string(),
            query_params: None,
            headers: HeaderMap::new(),
            retry: RetryConfig {
                max_attempts: 1,
                base_delay: Duration::from_millis(1),
                retry_429: false,
                retry_5xx: true,
                retry_transport: true,
            },
            stream_idle_timeout: Duration::from_secs(1),
        }
    }

    #[test]
    fn path_is_memories_trace_summarize_for_wire_compatibility() {
        assert_eq!(
            MemoriesClient::<DummyTransport>::path(),
            "memories/trace_summarize"
        );
    }

    #[tokio::test]
    async fn summarize_input_posts_expected_payload_and_parses_output() {
        let transport = CapturingTransport::new(
            serde_json::to_vec(&json!({
                "output": [
                    {
                        "trace_summary": "raw summary",
                        "memory_summary": "memory summary"
                    }
                ]
            }))
            .expect("serialize response"),
        );
        let client = MemoriesClient::new(
            transport.clone(),
            provider("https://example.com/api/codex"),
            Arc::new(DummyAuth),
        );

        let input = MemorySummarizeInput {
            model: "gpt-test".to_string(),
            raw_memories: vec![RawMemory {
                id: "trace-1".to_string(),
                metadata: RawMemoryMetadata {
                    source_path: "/tmp/trace.json".to_string(),
                },
                items: vec![json!({"type": "message", "role": "user", "content": []})],
            }],
            reasoning: None,
        };

        let response = client
            .summarize_input(&input, HeaderMap::new())
            .await
            .expect("summarize input request should succeed");
        assert_eq!(response.output.len(), 1);
        assert_eq!(response.output[0].raw_memory, "raw summary");
        assert_eq!(response.output[0].memory_summary, "memory summary");
        assert_eq!(response.rate_limits, None);

        let request = transport
            .last_request
            .lock()
            .expect("lock request store")
            .clone()
            .expect("request should be captured");
        assert_eq!(request.method, Method::POST);
        assert_eq!(
            request.url,
            "https://example.com/api/codex/memories/trace_summarize"
        );
        let body = request
            .body
            .as_ref()
            .and_then(RequestBody::json)
            .expect("request body should be JSON");
        assert_eq!(body["model"], "gpt-test");
        assert_eq!(body["traces"][0]["id"], "trace-1");
        assert_eq!(
            body["traces"][0]["metadata"]["source_path"],
            "/tmp/trace.json"
        );
    }

    #[tokio::test]
    async fn summarize_returns_active_rate_limit_from_success_headers() {
        let mut headers = HeaderMap::new();
        headers.insert(
            "x-codex-active-limit",
            http::HeaderValue::from_static("codex-other"),
        );
        headers.insert(
            "x-codex-other-primary-used-percent",
            http::HeaderValue::from_static("42.5"),
        );
        headers.insert(
            "x-codex-other-primary-window-minutes",
            http::HeaderValue::from_static("300"),
        );
        headers.insert(
            "x-codex-other-primary-reset-at",
            http::HeaderValue::from_static("1770000000"),
        );
        let transport = CapturingTransport::with_headers(br#"{"output":[]}"#.to_vec(), headers);
        let response = MemoriesClient::new(
            transport,
            provider("https://example.com/api/codex"),
            Arc::new(DummyAuth),
        )
        .summarize(json!({"model": "gpt-test", "traces": []}), HeaderMap::new())
        .await
        .expect("summarize request should succeed");

        assert!(response.output.is_empty());
        let rate_limits = response.rate_limits.expect("rate limit snapshot");
        assert_eq!(rate_limits.limit_id.as_deref(), Some("codex_other"));
        let primary = rate_limits.primary.expect("primary window");
        assert_eq!(primary.used_percent, 42.5);
        assert_eq!(primary.window_minutes, Some(300));
        assert_eq!(primary.resets_at, Some(1770000000));
    }

    #[tokio::test]
    async fn summarize_preserves_usage_limit_rate_snapshot() {
        let mut headers = HeaderMap::new();
        headers.insert(
            "x-codex-active-limit",
            http::HeaderValue::from_static("codex-other"),
        );
        headers.insert(
            "x-codex-other-primary-used-percent",
            http::HeaderValue::from_static("100"),
        );
        headers.insert(
            "x-codex-other-primary-window-minutes",
            http::HeaderValue::from_static("300"),
        );
        let body = json!({
            "error": {
                "type": "usage_limit_reached",
                "plan_type": "pro"
            }
        })
        .to_string();
        let error = MemoriesClient::new(
            ErrorTransport { headers, body },
            provider("https://example.com/api/codex"),
            Arc::new(DummyAuth),
        )
        .summarize(json!({"model": "gpt-test", "traces": []}), HeaderMap::new())
        .await
        .expect_err("summarize request should fail");

        let CodexErr::UsageLimitReached(usage_limit) = crate::map_api_error(error) else {
            panic!("expected usage limit error");
        };
        let rate_limits = usage_limit.rate_limits.expect("rate limit snapshot");
        assert_eq!(rate_limits.limit_id.as_deref(), Some("codex_other"));
        assert_eq!(
            rate_limits.primary.expect("primary window").used_percent,
            100.0
        );
    }
}
