const LIFE_SCIENCES_OAUTH_STATE_SUFFIX: &str = ".onboarding_entrypoint=life_sciences";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LoginOnboardingEntrypoint {
    LifeSciences,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct LoginCallbackResult {
    pub onboarding_entrypoint: Option<LoginOnboardingEntrypoint>,
    pub managed_account_id: Option<String>,
}

pub(crate) fn login_callback_result_from_state(
    callback_state: &str,
    expected_state: &str,
) -> Option<LoginCallbackResult> {
    if callback_state == expected_state {
        return Some(LoginCallbackResult::default());
    }

    (callback_state.strip_suffix(LIFE_SCIENCES_OAUTH_STATE_SUFFIX) == Some(expected_state))
        .then_some(LoginCallbackResult {
            onboarding_entrypoint: Some(LoginOnboardingEntrypoint::LifeSciences),
            ..Default::default()
        })
}

#[cfg(test)]
#[path = "callback_params_tests.rs"]
mod tests;
