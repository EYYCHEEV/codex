use super::EffectiveMcpServer;
use super::McpCredentialPolicy;
use super::McpServerConnectionIdentity;
use super::referenced_environment_variables;
use crate::McpProtocolMode;
use crate::runtime::McpRuntimeContext;
use crate::tool_catalog_cache::McpToolCatalogCache;
use codex_config::DEFAULT_MCP_SERVER_ENVIRONMENT_ID;
use codex_config::McpServerConfig;
use codex_config::types::AuthKeyringBackendKind;
use codex_config::types::OAuthCredentialsStoreMode;
use codex_exec_server_test_support::environment_manager_without_environments;
use codex_protocol::mcp::ClientMcpExtensions;
use codex_rmcp_client::McpOAuthRefreshMode;
use pretty_assertions::assert_eq;
use rmcp::model::ElicitationCapability;
use std::sync::Arc;

#[test]
fn remote_http_connections_track_host_headers_but_not_executor_bearer_tokens() {
    let mut config: McpServerConfig = serde_json::from_value(serde_json::json!({
        "url": "https://example.com/mcp",
        "environment_id": "executor-1",
        "bearer_token_env_var": "NODE_REPL_AUTH_TOKEN",
        "env_http_headers": {"X-Api-Key": "PATH"},
    }))
    .expect("remote MCP configuration should deserialize");

    assert_eq!(
        referenced_environment_variables(&config),
        vec![("PATH".to_string(), std::env::var_os("PATH"))],
    );

    let remote_host_bearer: McpServerConfig = serde_json::from_value(serde_json::json!({
        "url": "https://example.com/mcp",
        "environment_id": "executor-1",
        "bearer_token_env_var": "PATH",
    }))
    .expect("host-resolved remote MCP configuration should deserialize");
    assert_eq!(
        referenced_environment_variables(&remote_host_bearer),
        vec![("PATH".to_string(), std::env::var_os("PATH"))],
    );

    config.environment_id = DEFAULT_MCP_SERVER_ENVIRONMENT_ID.to_string();
    assert_eq!(
        referenced_environment_variables(&config),
        vec![
            (
                "NODE_REPL_AUTH_TOKEN".to_string(),
                std::env::var_os("NODE_REPL_AUTH_TOKEN"),
            ),
            ("PATH".to_string(), std::env::var_os("PATH")),
        ],
    );
}

fn runtime_context() -> McpRuntimeContext {
    McpRuntimeContext::new(
        Arc::new(environment_manager_without_environments()),
        std::env::temp_dir(),
    )
}

fn connection_identity(
    server: &EffectiveMcpServer,
    runtime_context: &McpRuntimeContext,
) -> McpServerConnectionIdentity {
    McpServerConnectionIdentity::new(
        "docs",
        server,
        /*host_plugin_root*/ None,
        OAuthCredentialsStoreMode::default(),
        AuthKeyringBackendKind::default(),
        McpOAuthRefreshMode::Legacy,
        &Ok(None),
        runtime_context,
        /*runtime_auth_provider*/ None,
        /*auth*/ None,
        /*codex_apps_cache_identity*/ None,
        ElicitationCapability::default(),
        ClientMcpExtensions::default(),
        /*previous_identity*/ None,
    )
}

fn explicit_authorization_server() -> EffectiveMcpServer {
    EffectiveMcpServer::from_host_config(
        serde_json::from_value(serde_json::json!({
            "url": "https://example.com/mcp",
            "environment_id": "executor-1",
            "http_headers": {"Authorization": "Bearer test-canary"},
        }))
        .expect("remote MCP configuration should deserialize"),
    )
}

#[test]
fn connection_identity_does_not_reuse_connections_across_credential_policies() {
    let runtime_context = runtime_context();
    let host_server = explicit_authorization_server();
    let executor_server = EffectiveMcpServer::from_config_with_policy(
        host_server.config().clone(),
        McpCredentialPolicy::ExecutorOnly,
    );
    let host_identity = connection_identity(&host_server, &runtime_context);
    let executor_identity = connection_identity(&executor_server, &runtime_context);

    assert!(
        host_identity
            .has_same_connection_config(&connection_identity(&host_server, &runtime_context,))
    );
    assert!(
        executor_identity
            .has_same_connection_config(&connection_identity(&executor_server, &runtime_context,))
    );
    assert!(!host_identity.has_same_connection_config(&executor_identity));
    assert!(!executor_identity.has_same_connection_config(&host_identity));
}

#[test]
fn executor_connection_identity_does_not_capture_host_environment_values() {
    let runtime_context = runtime_context();
    let host_server = EffectiveMcpServer::from_host_config(
        serde_json::from_value(serde_json::json!({
            "url": "https://example.com/mcp",
            "environment_id": "executor-1",
            "bearer_token_env_var": "PATH",
        }))
        .expect("remote MCP configuration should deserialize"),
    );
    let executor_server = EffectiveMcpServer::from_config_with_policy(
        host_server.config().clone(),
        McpCredentialPolicy::ExecutorOnly,
    );

    assert_eq!(
        connection_identity(&host_server, &runtime_context).referenced_environment_variables,
        vec![("PATH".to_string(), std::env::var_os("PATH"))],
    );
    assert_eq!(
        connection_identity(&executor_server, &runtime_context).referenced_environment_variables,
        Vec::new(),
    );
}

#[test]
fn tool_catalog_cache_does_not_reuse_catalogs_across_credential_policies() {
    let runtime_context = runtime_context();
    let host_server = explicit_authorization_server();
    let executor_server = EffectiveMcpServer::from_config_with_policy(
        host_server.config().clone(),
        McpCredentialPolicy::ExecutorOnly,
    );
    let host_identity = connection_identity(&host_server, &runtime_context);
    let executor_identity = connection_identity(&executor_server, &runtime_context);
    let cache = McpToolCatalogCache::default();
    let context = |identity| {
        cache
            .context(
                "docs",
                host_server.config(),
                &runtime_context,
                /*resolved_environment*/ None,
                (
                    &ElicitationCapability::default(),
                    &ClientMcpExtensions::default(),
                ),
                Some((identity, McpProtocolMode::Legacy, false)),
            )
            .expect("explicit authorization permits catalog caching")
    };
    let host_context = context(&host_identity);
    host_context.publish_if_newest(host_context.begin_fetch(), &[]);

    assert_eq!(context(&host_identity).current_tools(), Some(Vec::new()));
    assert_eq!(context(&executor_identity).current_tools(), None);
}

#[test]
fn local_http_connection_reuse_tracks_policy_owner_and_account_not_allowlist_updates() {
    let controller = codex_http_client::NetworkPolicyController::default();
    let policy = controller.policy().for_current_account();
    let manager = Arc::new(environment_manager_without_environments());
    let context = |policy| {
        McpRuntimeContext::new_with_network_policy(
            Arc::clone(&manager),
            std::env::temp_dir(),
            policy,
        )
    };
    let server = EffectiveMcpServer::from_host_config(
        serde_json::from_value(serde_json::json!({
            "url": "https://example.com/mcp",
            "http_headers": {"Authorization": "Bearer test-canary"},
        }))
        .expect("local HTTP configuration"),
    );
    let original = connection_identity(&server, &context(policy.clone()));
    let retained = connection_identity(&server, &context(policy.clone()));
    assert!(original.has_same_connection_config(&retained));
    assert!(original == retained);

    assert!(controller.publish(
        policy.revision(),
        codex_http_client::DestinationPolicy::Restricted {
            allowed_hosts: Default::default(),
        },
    ));
    let updated = connection_identity(&server, &context(policy.clone()));
    assert!(original.has_same_connection_config(&updated));
    assert!(original == updated);

    let other_owner = connection_identity(
        &server,
        &context(
            codex_http_client::NetworkPolicyController::default()
                .policy()
                .for_current_account(),
        ),
    );
    assert!(!original.has_same_connection_config(&other_owner));
    assert!(original != other_owner);

    policy.invalidate();
    let next_account =
        connection_identity(&server, &context(controller.policy().for_current_account()));
    assert!(!original.has_same_connection_config(&next_account));
    assert!(original != next_account);
}

#[tokio::test]
async fn host_policy_changes_do_not_replace_stdio_or_executor_http_connections() {
    let manager = Arc::new(
        codex_exec_server::EnvironmentManager::create_for_tests(
            Some("ws://127.0.0.1:8765".to_string()),
            /*local_runtime_paths*/ None,
        )
        .await,
    );
    let contexts = [
        codex_http_client::NetworkPolicyController::default(),
        codex_http_client::NetworkPolicyController::default(),
    ]
    .map(|controller| {
        McpRuntimeContext::new_with_network_policy(
            Arc::clone(&manager),
            std::env::temp_dir(),
            controller.policy().for_current_account(),
        )
    });
    for config in [
        serde_json::json!({"command": "unused-stdio-server"}),
        serde_json::json!({
            "url": "https://example.com/mcp",
            "environment_id": "remote",
            "http_headers": {"Authorization": "Bearer test-canary"},
        }),
    ] {
        let server = EffectiveMcpServer::from_host_config(
            serde_json::from_value(config).expect("MCP configuration"),
        );
        if !server.config().is_local_environment() {
            assert!(
                contexts[0]
                    .resolve_server_environment("docs", server.config())
                    .expect("remote environment resolves")
                    .expect("remote environment exists")
                    .is_remote()
            );
        }
        let identities = contexts.each_ref().map(|context| {
            McpServerConnectionIdentity::new(
                "docs",
                &server,
                /*host_plugin_root*/ None,
                OAuthCredentialsStoreMode::default(),
                AuthKeyringBackendKind::default(),
                McpOAuthRefreshMode::Legacy,
                &context.resolve_server_environment("docs", server.config()),
                context,
                /*runtime_auth_provider*/ None,
                /*auth*/ None,
                /*codex_apps_cache_identity*/ None,
                ElicitationCapability::default(),
                ClientMcpExtensions::default(),
                /*previous_identity*/ None,
            )
        });
        assert!(identities[0].has_same_connection_config(&identities[1]));
        assert!(identities[0] == identities[1]);
    }
}
