//! Usage permission and earned-reset payloads, including compatibility with older backends.

use super::*;
use crate::types::ConsumeRateLimitResetCreditCode;
use crate::types::RateLimitResetCreditDetails;
use crate::types::RateLimitResetCreditsDetails;
use crate::types::RateLimitResetCreditsSummary;
use pretty_assertions::assert_eq;
use wiremock::Mock;
use wiremock::MockServer;
use wiremock::ResponseTemplate;
use wiremock::matchers::method;
use wiremock::matchers::path;

#[tokio::test]
async fn ordinary_usage_permission_comes_from_backend_not_display_percent() {
    for (allowed, used_percent) in [
        (Some(true), 100),
        (Some(true), 0),
        (Some(false), 0),
        (None, 0),
    ] {
        let server = MockServer::start().await;
        let rate_limit = allowed.map(|allowed| {
            serde_json::json!({
                "allowed": allowed, "limit_reached": !allowed,
                "primary_window": {"used_percent": used_percent, "limit_window_seconds": 300,
                    "reset_after_seconds": 60, "reset_at": 2000000000}
            })
        });
        Mock::given(method("GET"))
            .and(path("/api/codex/usage"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "plan_type": "plus", "rate_limit": rate_limit
            })))
            .expect(1)
            .mount(&server)
            .await;
        let response = test_client(&server.uri(), PathStyle::CodexApi)
            .get_rate_limits_with_reset_credits()
            .await
            .unwrap();
        assert_eq!(
            (
                response.ordinary_usage_allowed,
                response.quota_recovery_allowed
            ),
            (allowed, allowed == Some(true) && used_percent < 100),
        );
    }
}

#[tokio::test]
async fn quota_recovery_requires_complete_healthy_usage() {
    let window = serde_json::json!({
        "used_percent": 12, "limit_window_seconds": 300,
        "reset_after_seconds": 60, "reset_at": 2000000000
    });
    let meter = serde_json::json!({
        "allowed": true, "limit_reached": false,
        "primary_window": window, "secondary_window": null
    });
    let additional = serde_json::json!([{
        "limit_name": "Extra", "metered_feature": "extra",
        "normal_model_slug": "model", "rate_limit": meter
    }]);
    let spend_limit = serde_json::json!({
        "reached": false,
        "individual_limit": {
            "limit": "10", "used": "1", "remaining": "9",
            "used_percent": 10, "remaining_percent": 90,
            "reset_after_seconds": 60, "reset_at": 2000000000
        }
    });
    let mut exhausted_window = window.clone();
    exhausted_window["used_percent"] = serde_json::json!(100);
    let mut malformed_window = window.clone();
    malformed_window["limit_window_seconds"] = serde_json::json!(-1);
    let mut denied_additional = additional.clone();
    denied_additional[0]["rate_limit"]["allowed"] = serde_json::json!(false);
    let mut reached_additional = additional.clone();
    reached_additional[0]["rate_limit"]["limit_reached"] = serde_json::json!(true);
    let mut exhausted_additional = additional.clone();
    exhausted_additional[0]["rate_limit"]["secondary_window"] = exhausted_window.clone();
    let mut malformed_additional = additional.clone();
    malformed_additional[0]["rate_limit"]["primary_window"] = malformed_window.clone();
    let mut missing_additional_verdict = additional.clone();
    missing_additional_verdict[0]["rate_limit"] = serde_json::Value::Null;
    let mut missing_additional_window = additional.clone();
    missing_additional_window[0]["rate_limit"]["primary_window"] = serde_json::Value::Null;
    let mut exhausted_spend_limit = spend_limit.clone();
    exhausted_spend_limit["individual_limit"]["used_percent"] = serde_json::json!(100);
    let mut no_remaining_spend_limit = spend_limit.clone();
    no_remaining_spend_limit["individual_limit"]["remaining_percent"] = serde_json::json!(0);
    let cases = [
        (
            "primary only",
            "/rate_limit/primary_window",
            window.clone(),
            true,
        ),
        (
            "primary and secondary",
            "/rate_limit/secondary_window",
            window,
            true,
        ),
        (
            "denied",
            "/rate_limit/allowed",
            serde_json::json!(false),
            false,
        ),
        (
            "reached",
            "/rate_limit/limit_reached",
            serde_json::json!(true),
            false,
        ),
        (
            "missing canonical",
            "/rate_limit",
            serde_json::Value::Null,
            false,
        ),
        (
            "missing windows",
            "/rate_limit/primary_window",
            serde_json::Value::Null,
            false,
        ),
        (
            "exhausted primary",
            "/rate_limit/primary_window",
            exhausted_window.clone(),
            false,
        ),
        (
            "exhausted secondary",
            "/rate_limit/secondary_window",
            exhausted_window,
            false,
        ),
        (
            "malformed secondary",
            "/rate_limit/secondary_window",
            malformed_window,
            false,
        ),
        (
            "negative percent",
            "/rate_limit/primary_window/used_percent",
            serde_json::json!(-1),
            false,
        ),
        (
            "overfull percent",
            "/rate_limit/primary_window/used_percent",
            serde_json::json!(101),
            false,
        ),
        (
            "zero duration",
            "/rate_limit/primary_window/limit_window_seconds",
            serde_json::json!(0),
            false,
        ),
        (
            "negative reset delay",
            "/rate_limit/primary_window/reset_after_seconds",
            serde_json::json!(-1),
            false,
        ),
        (
            "invalid reset time",
            "/rate_limit/primary_window/reset_at",
            serde_json::json!(0),
            false,
        ),
        (
            "empty additional",
            "/additional_rate_limits",
            serde_json::json!([]),
            true,
        ),
        (
            "healthy additional",
            "/additional_rate_limits",
            additional,
            true,
        ),
        (
            "denied additional",
            "/additional_rate_limits",
            denied_additional,
            false,
        ),
        (
            "reached additional",
            "/additional_rate_limits",
            reached_additional,
            false,
        ),
        (
            "exhausted additional",
            "/additional_rate_limits",
            exhausted_additional,
            false,
        ),
        (
            "malformed additional",
            "/additional_rate_limits",
            malformed_additional,
            false,
        ),
        (
            "missing additional verdict",
            "/additional_rate_limits",
            missing_additional_verdict,
            false,
        ),
        (
            "missing additional window",
            "/additional_rate_limits",
            missing_additional_window,
            false,
        ),
        ("healthy spend control", "/spend_control", spend_limit, true),
        (
            "spend denial",
            "/spend_control",
            serde_json::json!({"reached": true}),
            false,
        ),
        (
            "exhausted spend limit",
            "/spend_control",
            exhausted_spend_limit,
            false,
        ),
        (
            "no remaining spend limit",
            "/spend_control",
            no_remaining_spend_limit,
            false,
        ),
        (
            "ordinary quota reached",
            "/rate_limit_reached_type",
            serde_json::json!({"type": "rate_limit_reached"}),
            false,
        ),
        (
            "workspace owner credits reached",
            "/rate_limit_reached_type",
            serde_json::json!({"type": "workspace_owner_credits_depleted"}),
            false,
        ),
        (
            "workspace member credits reached",
            "/rate_limit_reached_type",
            serde_json::json!({"type": "workspace_member_credits_depleted"}),
            false,
        ),
        (
            "workspace owner usage reached",
            "/rate_limit_reached_type",
            serde_json::json!({"type": "workspace_owner_usage_limit_reached"}),
            false,
        ),
        (
            "workspace member usage reached",
            "/rate_limit_reached_type",
            serde_json::json!({"type": "workspace_member_usage_limit_reached"}),
            false,
        ),
        (
            "unknown quota reached",
            "/rate_limit_reached_type",
            serde_json::json!({"type": "new_cap"}),
            false,
        ),
    ];
    for (name, pointer, value, expected) in cases {
        let server = MockServer::start().await;
        let mut body = serde_json::json!({
            "plan_type": "plus", "rate_limit": meter,
            "additional_rate_limits": null, "spend_control": null,
            "rate_limit_reached_type": null,
            "credits": {"has_credits": false, "unlimited": false, "balance": "0"},
            "rate_limit_reset_credits": {"available_count": 3},
            "account_id": "account", "user_id": "user",
            "rate_limit_upsell": {"banner": "preserved"}
        });
        *body.pointer_mut(pointer).unwrap() = value;
        let ordinary_usage_allowed = body["rate_limit"]["allowed"].as_bool();
        Mock::given(method("GET"))
            .and(path("/api/codex/usage"))
            .respond_with(ResponseTemplate::new(200).set_body_json(body))
            .expect(1)
            .mount(&server)
            .await;
        let response = test_client(&server.uri(), PathStyle::CodexApi)
            .get_rate_limits_with_reset_credits()
            .await
            .unwrap();
        assert_eq!(
            (
                response.quota_recovery_allowed,
                response.quota_recovery_allowed_for(Some("account")),
                response.quota_recovery_allowed_for(Some("another-account")),
                response.ordinary_usage_allowed,
                response.rate_limit_reset_credits,
                response.account_id,
                response.user_id,
                response.rate_limit_upsell,
            ),
            (
                expected,
                expected,
                false,
                ordinary_usage_allowed,
                Some(RateLimitResetCreditsSummary { available_count: 3 }),
                Some("account".to_string()),
                Some("user".to_string()),
                Some(serde_json::json!({"banner": "preserved"})),
            ),
            "{name}",
        );
    }
}

#[tokio::test]
async fn quota_recovery_rejects_incomplete_usage_payloads() {
    // Required verdict/window fields fail decoding rather than becoming recovery evidence.
    for (parent, field) in [
        ("/rate_limit", "allowed"),
        ("/rate_limit", "limit_reached"),
        ("/rate_limit/primary_window", "used_percent"),
        ("/rate_limit/primary_window", "limit_window_seconds"),
        ("/rate_limit/primary_window", "reset_after_seconds"),
        ("/rate_limit/primary_window", "reset_at"),
        ("/additional_rate_limits/0/rate_limit", "allowed"),
        ("/additional_rate_limits/0/rate_limit", "limit_reached"),
        ("/spend_control", "reached"),
    ] {
        let server = MockServer::start().await;
        let meter = serde_json::json!({
            "allowed": true, "limit_reached": false,
            "primary_window": {"used_percent": 0, "limit_window_seconds": 300,
                "reset_after_seconds": 60, "reset_at": 2000000000}
        });
        let mut body = serde_json::json!({
            "plan_type": "plus", "rate_limit": meter,
            "additional_rate_limits": [{
                "limit_name": "Extra", "metered_feature": "extra", "rate_limit": meter
            }],
            "spend_control": {"reached": false}
        });
        body.pointer_mut(parent)
            .unwrap()
            .as_object_mut()
            .unwrap()
            .remove(field);
        Mock::given(method("GET"))
            .and(path("/api/codex/usage"))
            .respond_with(ResponseTemplate::new(200).set_body_json(body))
            .expect(1)
            .mount(&server)
            .await;
        let response = test_client(&server.uri(), PathStyle::CodexApi)
            .get_rate_limits_with_reset_credits()
            .await;
        assert!(response.is_err(), "{parent}/{field}");
    }
}

#[test]
fn rate_limit_reset_contract_uses_expected_paths_and_payloads() {
    assert_eq!(
        test_client("https://example.test", PathStyle::CodexApi).rate_limit_status_url(),
        "https://example.test/api/codex/usage"
    );
    assert_eq!(
        test_client("https://example.test", PathStyle::CodexApi).rate_limit_reset_credits_url(),
        "https://example.test/api/codex/rate-limit-reset-credits"
    );
    assert_eq!(
        test_client("https://example.test", PathStyle::CodexApi)
            .consume_rate_limit_reset_credit_url(),
        "https://example.test/api/codex/rate-limit-reset-credits/consume"
    );
    assert_eq!(
        test_client("https://chatgpt.com/backend-api", PathStyle::ChatGptApi)
            .rate_limit_status_url(),
        "https://chatgpt.com/backend-api/wham/usage"
    );
    assert_eq!(
        test_client("https://chatgpt.com/backend-api", PathStyle::ChatGptApi)
            .rate_limit_reset_credits_url(),
        "https://chatgpt.com/backend-api/wham/rate-limit-reset-credits"
    );
    assert_eq!(
        test_client("https://chatgpt.com/backend-api", PathStyle::ChatGptApi)
            .consume_rate_limit_reset_credit_url(),
        "https://chatgpt.com/backend-api/wham/rate-limit-reset-credits/consume"
    );

    assert_eq!(
        serde_json::to_value(ConsumeRateLimitResetCreditRequest {
            redeem_request_id: "redeem-123",
            credit_id: None,
        })
        .unwrap(),
        serde_json::json!({ "redeem_request_id": "redeem-123" })
    );
    assert_eq!(
        serde_json::to_value(ConsumeRateLimitResetCreditRequest {
            redeem_request_id: "redeem-456",
            credit_id: Some("credit-123"),
        })
        .unwrap(),
        serde_json::json!({
            "redeem_request_id": "redeem-456",
            "credit_id": "credit-123",
        })
    );

    let status: RateLimitStatusWithResetCredits = serde_json::from_value(serde_json::json!({
        "plan_type": "plus",
        "rate_limit_reset_credits": { "available_count": 3 }
    }))
    .unwrap();
    assert_eq!(
        status.rate_limit_reset_credits,
        Some(RateLimitResetCreditsSummary { available_count: 3 })
    );

    let details: RateLimitResetCreditsDetails = serde_json::from_value(serde_json::json!({
        "credits": [
            {
                "id": "credit-1",
                "reset_type": "codex_rate_limits",
                "status": "available",
                "granted_at": "2026-06-17T00:00:00Z",
                "expires_at": "2026-07-17T00:00:00Z",
                "redeem_started_at": null,
                "redeemed_at": null,
                "profile_image_url": "https://example.test/avatar.png",
                "profile_user_id": "@friend",
                "title": "Full reset (Weekly + 5 hr)",
                "description": "Ready to redeem"
            },
            {
                "id": "credit-2",
                "reset_type": "codex_rate_limits",
                "status": "available",
                "granted_at": "2026-06-18T00:00:00Z",
                "expires_at": null
            }
        ],
        "available_count": 2,
        "total_earned_count": 4
    }))
    .unwrap();
    assert_eq!(
        details,
        RateLimitResetCreditsDetails {
            credits: vec![
                RateLimitResetCreditDetails {
                    id: "credit-1".to_string(),
                    reset_type: "codex_rate_limits".to_string(),
                    status: "available".to_string(),
                    granted_at: "2026-06-17T00:00:00Z".to_string(),
                    expires_at: Some("2026-07-17T00:00:00Z".to_string()),
                    title: Some("Full reset (Weekly + 5 hr)".to_string()),
                    description: Some("Ready to redeem".to_string()),
                },
                RateLimitResetCreditDetails {
                    id: "credit-2".to_string(),
                    reset_type: "codex_rate_limits".to_string(),
                    status: "available".to_string(),
                    granted_at: "2026-06-18T00:00:00Z".to_string(),
                    expires_at: None,
                    title: None,
                    description: None,
                },
            ],
            available_count: 2,
        }
    );

    let response: ConsumeRateLimitResetCreditResponse = serde_json::from_value(serde_json::json!({
        "code": "reset",
        "credit": { "id": "ignored-by-cli" },
        "windows_reset": 2
    }))
    .unwrap();
    assert_eq!(
        response,
        ConsumeRateLimitResetCreditResponse {
            code: ConsumeRateLimitResetCreditCode::Reset,
            windows_reset: 2,
        }
    );
}

fn test_client(base_url: &str, path_style: PathStyle) -> Client {
    Client {
        base_url: base_url.to_string(),
        http: codex_http_client::RouteAwareClientPool::new(
            codex_http_client::HttpClientFactory::new(
                codex_http_client::OutboundProxyPolicy::ReqwestDefault,
            ),
            codex_http_client::ClientRouteClass::Api,
        ),
        auth_provider: codex_model_provider::unauthenticated_auth_provider(),
        user_agent: None,
        chatgpt_account_id: None,
        chatgpt_account_is_fedramp: false,
        path_style,
    }
}
