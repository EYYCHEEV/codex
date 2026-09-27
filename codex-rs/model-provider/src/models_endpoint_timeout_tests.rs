use super::*;
use codex_http_client::OutboundProxyPolicy;
use codex_protocol::error::CodexErrorDetails;
use wiremock::Mock;
use wiremock::MockServer;
use wiremock::ResponseTemplate;
use wiremock::matchers::method;
use wiremock::matchers::path;

#[tokio::test]
async fn catalog_deadline_returns_request_timeout() {
    let server = MockServer::start().await;
    let mock = Mock::given(method("GET"))
        .and(path("/models"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(serde_json::json!({ "models": [] }))
                .set_delay(Duration::from_secs(/*secs*/ 60)),
        )
        .expect(1)
        .mount_as_scoped(&server)
        .await;
    let endpoint = OpenAiModelsEndpoint::new(
        ModelProviderInfo::create_openai_provider(Some(server.uri())),
        /*auth_manager*/ None,
        /*gateway_auth_manager*/ None,
    );

    let request = endpoint.list_models(
        "0.0.0",
        HttpClientFactory::new(OutboundProxyPolicy::ReqwestDefault),
    );
    tokio::pin!(request);
    let received = mock.wait_until_satisfied();
    tokio::pin!(received);
    tokio::time::timeout(MODELS_FETCH_TIMEOUT, async {
        tokio::select! {
            () = &mut received => {}
            result = &mut request => {
                panic!("catalog request finished before reaching the server: {result:?}");
            }
        }
    })
    .await
    .expect("server did not receive the catalog request");
    tokio::time::pause();
    tokio::time::advance(MODELS_REQUEST_TIMEOUT + Duration::from_millis(/*millis*/ 1)).await;
    let error = request
        .await
        .expect_err("delayed catalog request should time out");
    tokio::time::resume();

    assert!(
        matches!(error.details(), CodexErrorDetails::RequestTimeout),
        "{error}"
    );
}

#[derive(Debug)]
struct DelayedTransportBuilder {
    client: codex_http_client::HttpClient,
    delay: Duration,
}

impl ModelsTransportBuilder for DelayedTransportBuilder {
    fn build(
        &self,
        _http_client_factory: HttpClientFactory,
        _request_url: String,
    ) -> ModelsTransportFuture<'_> {
        Box::pin(async move {
            tokio::time::sleep(self.delay).await;
            Ok(ReqwestTransport::from_http_client(self.client.clone()))
        })
    }
}

#[tokio::test]
async fn slow_transport_setup_does_not_consume_request_deadline() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/models"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "models": []
        })))
        .expect(1)
        .mount(&server)
        .await;
    let mut endpoint = OpenAiModelsEndpoint::new(
        ModelProviderInfo::create_openai_provider(Some(server.uri())),
        /*auth_manager*/ None,
        /*gateway_auth_manager*/ None,
    );
    endpoint.transport_builder = Arc::new(DelayedTransportBuilder {
        client: codex_http_client::HttpClientBuilder::new()
            .build_direct()
            .expect("local test client should build"),
        delay: MODELS_REQUEST_TIMEOUT + Duration::from_millis(/*millis*/ 100),
    });

    let response = endpoint
        .list_models(
            "0.0.0",
            HttpClientFactory::new(OutboundProxyPolicy::ReqwestDefault),
        )
        .await
        .expect("catalog request should succeed after slow client setup");
    assert_eq!(response.models, Vec::new());
}

#[tokio::test(start_paused = true)]
async fn transport_setup_is_bounded() {
    let mut endpoint = OpenAiModelsEndpoint::new(
        ModelProviderInfo::create_openai_provider(Some("http://127.0.0.1:1".to_string())),
        /*auth_manager*/ None,
        /*gateway_auth_manager*/ None,
    );
    endpoint.transport_builder = Arc::new(DelayedTransportBuilder {
        client: codex_http_client::HttpClientBuilder::new()
            .build_direct()
            .expect("local test client should build"),
        delay: MODELS_FETCH_TIMEOUT + Duration::from_secs(/*secs*/ 1),
    });

    let error = endpoint
        .list_models(
            "0.0.0",
            HttpClientFactory::new(OutboundProxyPolicy::ReqwestDefault),
        )
        .await
        .expect_err("transport setup should be bounded");
    assert!(
        matches!(error.details(), CodexErrorDetails::RequestTimeout),
        "{error}"
    );
}
