use std::sync::Arc;

use codex_core::config::Config;
use codex_login::AuthManager;
use codex_login::CodexAuth;
use codex_login::read_openai_api_key_from_env;
use codex_protocol::config_types::ForcedLoginMethod;

/// The authentication state presented by CLI commands.
///
/// `OPENAI_API_KEY` is a CLI/provider override unless ChatGPT login is forced. `AuthManager`
/// owns the remaining precedence rules (including `CODEX_API_KEY`) and persistent pool.
pub struct CliAuthProjection {
    pub auth_manager: Arc<AuthManager>,
    effective_auth: Result<Option<CodexAuth>, String>,
}

impl CliAuthProjection {
    pub fn effective_auth(&self) -> Result<Option<&CodexAuth>, &str> {
        self.effective_auth
            .as_ref()
            .map(Option::as_ref)
            .map_err(String::as_str)
    }
}

fn project_cli_auth(
    openai_api_key: Option<String>,
    managed_auth: Result<Option<CodexAuth>, String>,
    forced_login_method: Option<ForcedLoginMethod>,
) -> Result<Option<CodexAuth>, String> {
    if forced_login_method == Some(ForcedLoginMethod::Chatgpt) {
        return managed_auth;
    }
    match openai_api_key {
        Some(api_key) => Ok(Some(CodexAuth::from_api_key(&api_key))),
        None => managed_auth,
    }
}

pub async fn load_cli_auth_projection(config: &Config) -> CliAuthProjection {
    let openai_api_key = read_openai_api_key_from_env();
    let auth_manager =
        AuthManager::shared_from_config(config, /*enable_codex_api_key_env*/ true).await;
    let effective_auth = project_cli_auth(
        openai_api_key,
        auth_manager.auth_cached_result(),
        config.forced_login_method,
    );

    CliAuthProjection {
        auth_manager,
        effective_auth,
    }
}

#[cfg(test)]
#[path = "auth_projection_tests.rs"]
mod tests;
