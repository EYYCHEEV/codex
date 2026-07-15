use std::collections::HashMap;
use std::collections::HashSet;
use std::time::Duration;

use anyhow::Context;
use codex_login::default_client::create_client;

use codex_connectors::AppInfo;
use codex_connectors::ConnectorDirectoryCacheContext;
use codex_connectors::ConnectorDirectoryCacheKey;
use codex_connectors::DirectoryListResponse;
use codex_connectors::merge::merge_connectors;
use codex_connectors::merge::merge_plugin_connectors;
use codex_core::config::Config;
pub use codex_core::connectors::list_accessible_connectors_from_mcp_tools;
pub use codex_core::connectors::list_accessible_connectors_from_mcp_tools_with_environment_manager;
pub use codex_core::connectors::list_accessible_connectors_from_mcp_tools_with_mcp_manager;
pub use codex_core::connectors::list_accessible_connectors_from_mcp_tools_with_options;
pub use codex_core::connectors::list_accessible_connectors_from_mcp_tools_with_options_and_status;
pub use codex_core::connectors::list_cached_accessible_connectors_from_mcp_tools;
pub use codex_core::connectors::with_app_enabled_state;
use codex_login::AuthManager;
use codex_login::CodexAuth;
use codex_plugin::AppConnectorId;

const DIRECTORY_CONNECTORS_TIMEOUT: Duration = Duration::from_secs(60);

async fn apps_enabled(config: &Config) -> bool {
    let auth_manager =
        AuthManager::shared_from_config(config, /*enable_codex_api_key_env*/ false).await;
    let auth = auth_manager.auth().await;
    config
        .features
        .apps_enabled_for_auth(auth.as_ref().is_some_and(CodexAuth::uses_codex_backend))
}

async fn connector_auth_snapshot(
    config: &Config,
) -> anyhow::Result<(CodexAuth, ConnectorDirectoryCacheKey)> {
    let auth_manager =
        AuthManager::shared_from_config(config, /*enable_codex_api_key_env*/ false).await;
    if let Some(snapshot) = auth_manager
        .managed_chatgpt_auth_snapshot(&codex_login::ManagedChatgptSelectionScope::default())
        .await?
    {
        let cache_key = connector_directory_cache_key_from_managed_snapshot(config, &snapshot);
        return Ok((snapshot.auth, cache_key));
    }
    let auth = auth_manager
        .auth()
        .await
        .ok_or_else(|| anyhow::anyhow!("ChatGPT auth not available"))?;
    anyhow::ensure!(
        auth.uses_codex_backend(),
        "ChatGPT connectors require Codex backend auth"
    );
    let cache_key = connector_directory_cache_key(config, &auth);
    Ok((auth, cache_key))
}

pub async fn list_connectors(config: &Config) -> anyhow::Result<Vec<AppInfo>> {
    if !apps_enabled(config).await {
        return Ok(Vec::new());
    }
    let (connectors_result, accessible_result) = tokio::join!(
        list_all_connectors(config),
        list_accessible_connectors_from_mcp_tools(config),
    );
    let connectors = connectors_result?;
    let accessible = accessible_result?;
    Ok(with_app_enabled_state(
        merge_connectors_with_accessible(
            connectors, accessible, /*all_connectors_loaded*/ true,
        ),
        config,
    ))
}

pub async fn list_all_connectors(config: &Config) -> anyhow::Result<Vec<AppInfo>> {
    list_all_connectors_with_options(config, /*force_refetch*/ false, &[]).await
}

pub async fn list_cached_all_connectors(
    config: &Config,
    plugin_apps: &[AppConnectorId],
) -> Option<Vec<AppInfo>> {
    if !apps_enabled(config).await {
        return Some(Vec::new());
    }

    let (auth, cache_key) = connector_auth_snapshot(config).await.ok()?;
    list_cached_all_connectors_with_auth(config, &auth, cache_key, plugin_apps)
}

/// Lists cached connectors for an exact account snapshot without consulting ambient auth.
pub fn list_cached_all_connectors_with_auth(
    config: &Config,
    auth: &CodexAuth,
    cache_key: ConnectorDirectoryCacheKey,
    plugin_apps: &[AppConnectorId],
) -> Option<Vec<AppInfo>> {
    if !config
        .features
        .apps_enabled_for_auth(auth.uses_codex_backend())
    {
        return Some(Vec::new());
    }

    let cache_context = connector_directory_cache_context(config, cache_key);
    let connectors = codex_connectors::cached_directory_connectors(&cache_context)?;
    Some(merge_directory_and_plugin_connectors(
        connectors,
        plugin_apps,
    ))
}

pub async fn list_all_connectors_with_options(
    config: &Config,
    force_refetch: bool,
    plugin_apps: &[AppConnectorId],
) -> anyhow::Result<Vec<AppInfo>> {
    if !apps_enabled(config).await {
        return Ok(Vec::new());
    }
    let (auth, cache_key) = connector_auth_snapshot(config).await?;
    list_all_connectors_with_auth(config, &auth, cache_key, force_refetch, plugin_apps).await
}

/// Lists connectors for an exact account snapshot without consulting ambient auth.
pub async fn list_all_connectors_with_auth(
    config: &Config,
    auth: &CodexAuth,
    cache_key: ConnectorDirectoryCacheKey,
    force_refetch: bool,
    plugin_apps: &[AppConnectorId],
) -> anyhow::Result<Vec<AppInfo>> {
    if !config
        .features
        .apps_enabled_for_auth(auth.uses_codex_backend())
    {
        return Ok(Vec::new());
    }
    anyhow::ensure!(
        auth.uses_codex_backend(),
        "ChatGPT connectors require Codex backend auth"
    );
    anyhow::ensure!(
        auth.get_account_id().is_some(),
        "ChatGPT account ID not available, please re-run `codex login`"
    );

    let cache_context = connector_directory_cache_context(config, cache_key);
    let connectors = codex_connectors::list_all_connectors_with_options(
        cache_context,
        auth.is_workspace_account(),
        force_refetch,
        |path| fetch_directory_page_with_auth(config, auth, path),
    )
    .await?;
    Ok(merge_directory_and_plugin_connectors(
        connectors,
        plugin_apps,
    ))
}

async fn fetch_directory_page_with_auth(
    config: &Config,
    auth: &CodexAuth,
    path: String,
) -> anyhow::Result<DirectoryListResponse> {
    let url = format!(
        "{}/{}",
        config.chatgpt_base_url.trim_end_matches('/'),
        path.trim_start_matches('/')
    );
    let response = create_client()
        .get(url)
        .headers(codex_model_provider::auth_provider_from_auth(auth).to_auth_headers())
        .header("OAI-Product-Sku", "codex")
        .header("Content-Type", "application/json")
        .timeout(DIRECTORY_CONNECTORS_TIMEOUT)
        .send()
        .await
        .context("Failed to send request")?;
    if response.status().is_success() {
        return response
            .json()
            .await
            .context("Failed to parse JSON response");
    }
    let status = response.status();
    let body = response.text().await.unwrap_or_default();
    anyhow::bail!("Request failed with status {status}: {body}")
}

fn connector_directory_cache_key_from_managed_snapshot(
    config: &Config,
    snapshot: &codex_login::ManagedChatgptAuthSnapshot,
) -> ConnectorDirectoryCacheKey {
    ConnectorDirectoryCacheKey::from_transport_binding(
        config.chatgpt_base_url.clone(),
        snapshot.transport.clone(),
        snapshot.account_revision,
        snapshot.auth.is_workspace_account(),
    )
}

fn connector_directory_cache_key(config: &Config, auth: &CodexAuth) -> ConnectorDirectoryCacheKey {
    ConnectorDirectoryCacheKey::new(
        config.chatgpt_base_url.clone(),
        auth.get_account_id(),
        auth.get_chatgpt_user_id(),
        auth.is_workspace_account(),
    )
}

fn connector_directory_cache_context(
    config: &Config,
    cache_key: ConnectorDirectoryCacheKey,
) -> ConnectorDirectoryCacheContext {
    ConnectorDirectoryCacheContext::new(config.codex_home.to_path_buf(), cache_key)
}

fn merge_directory_and_plugin_connectors(
    connectors: Vec<AppInfo>,
    plugin_apps: &[AppConnectorId],
) -> Vec<AppInfo> {
    merge_plugin_connectors(
        connectors,
        plugin_apps
            .iter()
            .map(|connector_id| connector_id.0.clone()),
    )
}

pub fn connectors_for_plugin_apps(
    connectors: Vec<AppInfo>,
    plugin_apps: &[AppConnectorId],
) -> Vec<AppInfo> {
    let connectors = merge_plugin_connectors(
        connectors,
        plugin_apps
            .iter()
            .map(|connector_id| connector_id.0.clone()),
    );
    let mut connectors_by_id = connectors
        .into_iter()
        .map(|connector| (connector.id.clone(), connector))
        .collect::<HashMap<_, _>>();

    plugin_apps
        .iter()
        .filter_map(|connector_id| connectors_by_id.remove(connector_id.0.as_str()))
        .collect()
}

pub fn merge_connectors_with_accessible(
    connectors: Vec<AppInfo>,
    accessible_connectors: Vec<AppInfo>,
    all_connectors_loaded: bool,
) -> Vec<AppInfo> {
    let accessible_connectors = if all_connectors_loaded {
        let connector_ids: HashSet<&str> = connectors
            .iter()
            .map(|connector| connector.id.as_str())
            .collect();
        accessible_connectors
            .into_iter()
            .filter(|connector| connector_ids.contains(connector.id.as_str()))
            .collect()
    } else {
        accessible_connectors
    };
    merge_connectors(connectors, accessible_connectors)
}

#[cfg(test)]
mod tests {
    use super::*;
    use codex_connectors::metadata::connector_install_url;
    use codex_plugin::AppConnectorId;
    use pretty_assertions::assert_eq;
    use tempfile::TempDir;
    use tokio::io::AsyncReadExt;
    use tokio::io::AsyncWriteExt;
    use tokio::net::TcpListener;

    fn app(id: &str) -> AppInfo {
        AppInfo {
            id: id.to_string(),
            name: id.to_string(),
            description: None,
            logo_url: None,
            logo_url_dark: None,
            icon_assets: None,
            icon_dark_assets: None,
            distribution_channel: None,
            branding: None,
            app_metadata: None,
            labels: None,
            install_url: None,
            is_accessible: false,
            is_enabled: true,
            plugin_display_names: Vec::new(),
        }
    }

    fn merged_app(id: &str, is_accessible: bool) -> AppInfo {
        AppInfo {
            id: id.to_string(),
            name: id.to_string(),
            description: None,
            logo_url: None,
            logo_url_dark: None,
            icon_assets: None,
            icon_dark_assets: None,
            distribution_channel: None,
            branding: None,
            app_metadata: None,
            labels: None,
            install_url: Some(connector_install_url(id, id)),
            is_accessible,
            is_enabled: true,
            plugin_display_names: Vec::new(),
        }
    }

    async fn serve_directory_pages(
        listener: TcpListener,
        connector_ids: [&str; 2],
    ) -> anyhow::Result<Vec<String>> {
        let mut requests = Vec::new();
        for connector_id in connector_ids {
            let (mut socket, _) = listener.accept().await?;
            let mut request = Vec::new();
            loop {
                let mut chunk = [0_u8; 1024];
                let bytes_read = socket.read(&mut chunk).await?;
                if bytes_read == 0 {
                    break;
                }
                request.extend_from_slice(&chunk[..bytes_read]);
                if request.windows(4).any(|window| window == b"\r\n\r\n") {
                    break;
                }
            }
            requests.push(String::from_utf8(request)?);

            let body = serde_json::json!({
                "apps": [{"id": connector_id, "name": connector_id}],
                "next_token": null
            })
            .to_string();
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            );
            socket.write_all(response.as_bytes()).await?;
        }
        Ok(requests)
    }

    fn write_managed_auth(
        codex_home: &std::path::Path,
        identity_key: &str,
        email: &str,
        id_token: &str,
        access_token: &str,
        credential_revision: u64,
    ) -> anyhow::Result<()> {
        let auth = serde_json::json!({
            "auth_mode": "chatgpt",
            "OPENAI_API_KEY": null,
            "managed_chatgpt": {
                "version": 1,
                "revision": credential_revision,
                "next_account_revision": credential_revision + 1,
                "accounts": [{
                    "identity_key": identity_key,
                    "normalized_email": email,
                    "chatgpt_account_id": "shared-workspace",
                    "tokens": {
                        "id_token": id_token,
                        "access_token": access_token,
                        "refresh_token": format!("refresh-{identity_key}"),
                        "account_id": "shared-workspace"
                    },
                    "revision": credential_revision,
                    "credential_revision": credential_revision,
                    "last_refresh": "2099-01-01T00:00:00Z"
                }]
            }
        });
        std::fs::write(
            codex_home.join("auth.json"),
            serde_json::to_vec_pretty(&auth)?,
        )?;
        Ok(())
    }

    #[tokio::test]
    async fn threadless_managed_cache_isolates_same_raw_account_id_and_hits_same_identity()
    -> anyhow::Result<()> {
        const ID_TOKEN_A: &str = "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJlbWFpbCI6Im1hbmFnZWQtYUBleGFtcGxlLmNvbSIsImVtYWlsX3ZlcmlmaWVkIjp0cnVlLCJodHRwczovL2FwaS5vcGVuYWkuY29tL2F1dGgiOnsiY2hhdGdwdF91c2VyX2lkIjoic2FtZS11c2VyIiwidXNlcl9pZCI6InNhbWUtdXNlciIsImNoYXRncHRfYWNjb3VudF9pZCI6InNoYXJlZC13b3Jrc3BhY2UifX0.c2ln";
        const ID_TOKEN_B: &str = "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJlbWFpbCI6Im1hbmFnZWQtYkBleGFtcGxlLmNvbSIsImVtYWlsX3ZlcmlmaWVkIjp0cnVlLCJodHRwczovL2FwaS5vcGVuYWkuY29tL2F1dGgiOnsiY2hhdGdwdF91c2VyX2lkIjoic2FtZS11c2VyIiwidXNlcl9pZCI6InNhbWUtdXNlciIsImNoYXRncHRfYWNjb3VudF9pZCI6InNoYXJlZC13b3Jrc3BhY2UifX0.c2ln";

        let codex_home_a = TempDir::new()?;
        let codex_home_b = TempDir::new()?;
        write_managed_auth(
            codex_home_a.path(),
            "email:managed-a@example.com",
            "managed-a@example.com",
            ID_TOKEN_A,
            "access-managed-a",
            11,
        )?;
        write_managed_auth(
            codex_home_b.path(),
            "email:managed-b@example.com",
            "managed-b@example.com",
            ID_TOKEN_B,
            "access-managed-b",
            11,
        )?;

        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let base_url = format!("http://{}", listener.local_addr()?);
        let server = tokio::spawn(serve_directory_pages(listener, ["managed-a", "managed-b"]));
        let mut config_a = Config::load_default_with_cli_overrides_for_codex_home(
            codex_home_a.path().to_path_buf(),
            Vec::new(),
        )
        .await?;
        config_a.chatgpt_base_url = base_url.clone();
        let mut config_b = Config::load_default_with_cli_overrides_for_codex_home(
            codex_home_b.path().to_path_buf(),
            Vec::new(),
        )
        .await?;
        config_b.chatgpt_base_url = base_url;

        let fetched_a = list_all_connectors_with_options(&config_a, true, &[]).await?;
        let cached_a = list_all_connectors_with_options(&config_a, false, &[]).await?;
        let fetched_b = list_all_connectors_with_options(&config_b, false, &[]).await?;
        assert_eq!(
            fetched_a
                .iter()
                .map(|app| app.id.as_str())
                .collect::<Vec<_>>(),
            vec!["managed-a"]
        );
        assert_eq!(cached_a, fetched_a);
        assert_eq!(
            fetched_b
                .iter()
                .map(|app| app.id.as_str())
                .collect::<Vec<_>>(),
            vec!["managed-b"]
        );

        let requests = server.await??;
        assert_eq!(requests.len(), 2);
        assert!(
            requests[0]
                .to_ascii_lowercase()
                .contains("authorization: bearer access-managed-a")
        );
        assert!(
            requests[1]
                .to_ascii_lowercase()
                .contains("authorization: bearer access-managed-b")
        );
        for request in requests {
            let request = request.to_ascii_lowercase();
            assert!(request.contains("chatgpt-account-id: shared-workspace"));
            assert!(request.contains("oai-product-sku: codex"));
        }
        Ok(())
    }

    #[test]
    fn excludes_accessible_connectors_not_in_all_when_all_loaded() {
        let merged = merge_connectors_with_accessible(
            vec![app("alpha")],
            vec![app("alpha"), app("beta")],
            /*all_connectors_loaded*/ true,
        );
        assert_eq!(merged, vec![merged_app("alpha", /*is_accessible*/ true)]);
    }

    #[test]
    fn keeps_accessible_connectors_not_in_all_while_all_loading() {
        let merged = merge_connectors_with_accessible(
            vec![app("alpha")],
            vec![app("alpha"), app("beta")],
            /*all_connectors_loaded*/ false,
        );
        assert_eq!(
            merged,
            vec![
                merged_app("alpha", /*is_accessible*/ true),
                merged_app("beta", /*is_accessible*/ true)
            ]
        );
    }

    #[test]
    fn connectors_for_plugin_apps_returns_only_requested_plugin_apps() {
        let connectors = connectors_for_plugin_apps(
            vec![app("alpha"), app("beta")],
            &[
                AppConnectorId("gmail".to_string()),
                AppConnectorId("alpha".to_string()),
                AppConnectorId("gmail".to_string()),
            ],
        );
        assert_eq!(
            connectors,
            vec![merged_app("gmail", /*is_accessible*/ false), app("alpha")]
        );
    }

    #[test]
    fn connectors_for_plugin_apps_preserves_formerly_disallowed_plugin_apps() {
        let connector_id = "asdk_app_6938a94a61d881918ef32cb999ff937c";
        let connectors =
            connectors_for_plugin_apps(Vec::new(), &[AppConnectorId(connector_id.to_string())]);
        assert_eq!(
            connectors,
            vec![merged_app(connector_id, /*is_accessible*/ false)]
        );
    }
}
