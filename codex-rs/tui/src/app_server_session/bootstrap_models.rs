//! Bounded startup model discovery; picker refreshes still use the server catalog.

use super::bootstrap_request_error;
use super::model_preset_from_api_model;
use codex_app_server_client::AppServerClient;
use codex_app_server_protocol::Account;
use codex_app_server_protocol::ClientRequest;
use codex_app_server_protocol::GetAccountResponse;
use codex_app_server_protocol::ModelListParams;
use codex_app_server_protocol::ModelListResponse;
use codex_app_server_protocol::RequestId;
use codex_protocol::openai_models::ModelPreset;
use color_eyre::eyre::Result;
use color_eyre::eyre::WrapErr;
use std::time::Duration;

// The provider catalog fetch is already limited to five seconds. Allow a little time for
// RPC dispatch, then let the TUI start with its bundled catalog if the request is still pending.
const MODEL_LIST_BOOTSTRAP_TIMEOUT: Duration = Duration::from_secs(6);

pub(super) async fn load(
    client: &AppServerClient,
    request_id: RequestId,
    account: &GetAccountResponse,
) -> Result<Vec<ModelPreset>> {
    let request = client.request_typed::<ModelListResponse>(ClientRequest::ModelList {
        request_id,
        params: ModelListParams {
            cursor: None,
            limit: None,
            include_hidden: Some(true),
        },
    });
    match tokio::time::timeout(MODEL_LIST_BOOTSTRAP_TIMEOUT, request).await {
        Ok(Ok(response)) => Ok(response
            .data
            .into_iter()
            .map(model_preset_from_api_model)
            .collect()),
        Ok(Err(err)) => Err(bootstrap_request_error(
            "model/list failed during TUI bootstrap",
            err,
        )),
        Err(_) => {
            tracing::warn!("model/list timed out during TUI bootstrap; using bundled models");
            let mut models = codex_models_manager::bundled_models_response()
                .wrap_err("failed to load bundled models for TUI bootstrap")?
                .models;
            models.sort_by_key(|model| model.priority);
            let presets = models.into_iter().map(ModelPreset::from).collect();
            let mut presets = ModelPreset::filter_by_auth(
                presets,
                matches!(&account.account, Some(Account::Chatgpt { .. })),
            );
            ModelPreset::mark_default_by_picker_visibility(&mut presets);
            Ok(presets)
        }
    }
}
