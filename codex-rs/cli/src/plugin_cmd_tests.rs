use codex_core_plugins::apps_route_available;
use pretty_assertions::assert_eq;

use super::*;

#[test]
fn projected_api_key_mode_filters_app_routes() {
    let auth = CodexAuth::from_api_key("sk-test");

    let mode = cli_auth_mode_from_effective_auth(Ok(Some(&auth))).expect("project auth mode");

    assert_eq!(mode, Some(AuthMode::ApiKey));
    assert!(!apps_route_available(mode));
}

#[test]
fn projected_auth_error_is_not_replaced_by_managed_mode() {
    let error = cli_auth_mode_from_effective_auth(Err(
        "personal access token account is not in an allowed workspace",
    ))
    .expect_err("higher-precedence auth error");

    assert!(
        error
            .to_string()
            .contains("personal access token account is not in an allowed workspace")
    );
}
