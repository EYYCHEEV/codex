use codex_core_plugins::apps_route_available;
use codex_protocol::auth::AuthMode;
use pretty_assertions::assert_eq;

use super::*;

#[test]
fn openai_api_key_overrides_managed_auth() {
    let managed = CodexAuth::create_dummy_chatgpt_auth_for_testing();

    let projected = project_cli_auth(
        Some("sk-openai".to_string()),
        Ok(Some(managed)),
        /*forced_login_method*/ None,
    )
    .expect("projected auth")
    .expect("effective auth");

    assert_eq!(projected.api_auth_mode(), AuthMode::ApiKey);
    assert!(!apps_route_available(Some(projected.api_auth_mode())));
}

#[test]
fn openai_api_key_overrides_lower_precedence_load_error() {
    let projected = project_cli_auth(
        Some("sk-openai".to_string()),
        Err("stored auth load failed".to_string()),
        /*forced_login_method*/ None,
    )
    .expect("environment API key projection")
    .expect("effective auth");

    assert_eq!(projected.api_auth_mode(), AuthMode::ApiKey);
}

#[test]
fn managed_load_error_is_preserved_without_openai_api_key() {
    assert_eq!(
        project_cli_auth(
            None,
            Err("env token is disallowed".to_string()),
            /*forced_login_method*/ None,
        ),
        Err("env token is disallowed".to_string())
    );
}

#[test]
fn forced_chatgpt_ignores_openai_api_key_override() {
    let managed = CodexAuth::create_dummy_chatgpt_auth_for_testing();

    let projected = project_cli_auth(
        Some("sk-openai".to_string()),
        Ok(Some(managed)),
        Some(ForcedLoginMethod::Chatgpt),
    )
    .expect("projected auth")
    .expect("effective auth");

    assert_eq!(projected.api_auth_mode(), AuthMode::Chatgpt);
}
