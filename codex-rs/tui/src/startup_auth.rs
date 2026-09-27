//! Distinguishes saved login state from the account selected for requests at startup.

use crate::LoginStatus;
use crate::app_server_session::AppServerSession;
use codex_app_server_client::TypedRequestError;
use codex_app_server_protocol::Account;
use codex_app_server_protocol::GetAccountResponse;
use codex_app_server_protocol::ManagedChatgptAccountRefreshStatus;
use codex_protocol::auth::AuthMode;

/// Preserves the singular account response for bootstrap without selecting an account in the UI.
pub(super) async fn get_login_status(
    app_server: &mut AppServerSession,
) -> color_eyre::Result<(LoginStatus, GetAccountResponse)> {
    let account = app_server.read_account().await?;
    let login_status = match &account.account {
        Some(Account::ApiKey {}) => LoginStatus::AuthMode(AuthMode::ApiKey),
        Some(Account::Chatgpt { .. }) => LoginStatus::AuthMode(AuthMode::Chatgpt),
        None if account.requires_openai_auth => {
            let inventory = app_server
                .list_accounts(
                    /*thread_id*/ None, /*model*/ None, /*refresh_tokens*/ false,
                    /*refresh_usage*/ false,
                )
                .await;
            match inventory {
                Ok(inventory) => {
                    let has_saved_login = inventory.accounts.iter().any(|account| {
                        !matches!(
                            account.refresh_status,
                            ManagedChatgptAccountRefreshStatus::ReloginRequired { .. }
                        ) && (account.eligible
                            || (account.eligibility_reason.as_deref() == Some("blocked")
                                && account.block.as_ref().is_some_and(|block| {
                                    matches!(block.reason.as_str(), "quota" | "workspace")
                                })))
                    });
                    if has_saved_login {
                        LoginStatus::AuthMode(AuthMode::Chatgpt)
                    } else {
                        LoginStatus::NotAuthenticated
                    }
                }
                // Upstream servers without the fork's pool API retain singular login behavior.
                Err(err)
                    if matches!(
                        err.downcast_ref::<TypedRequestError>(),
                        Some(TypedRequestError::Server { source, .. })
                            if source.code == -32601
                                || (source.code == -32600
                                    && source.message.contains("unknown variant `account/list`"))
                    ) =>
                {
                    LoginStatus::NotAuthenticated
                }
                Err(err) => return Err(err),
            }
        }
        Some(Account::AmazonBedrock { .. }) | None => LoginStatus::NotAuthenticated,
    };
    Ok((login_status, account))
}

#[cfg(test)]
#[path = "startup_auth_tests.rs"]
mod tests;
