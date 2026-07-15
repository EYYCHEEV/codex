use sha1::Digest;
use sha1::Sha1;
use std::fmt;
use std::sync::Arc;

use codex_login::CodexAuth;
use codex_login::TransportAuthBinding;
use codex_mcp::McpConfig;
use codex_mcp::McpConnectionManager;
use codex_mcp::McpRuntimeContext;

/// MCP config, plugin availability, exact environment bindings, and manager for one request.
pub struct McpRuntimeSnapshot {
    config: Arc<McpConfig>,
    plugins_available: bool,
    manager: Arc<McpConnectionManager>,
    runtime_context: McpRuntimeContext,
    available_environment_ids: Vec<String>,
    transport_auth_binding: Option<TransportAuthBinding>,
    credential_revision: Option<u64>,
    effective_auth_fingerprint: Option<EffectiveAuthFingerprint>,
    effective_auth: Option<CodexAuth>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct EffectiveAuthFingerprint([u8; 20]);

impl EffectiveAuthFingerprint {
    pub(crate) fn for_auth(auth: Option<&CodexAuth>) -> Option<Self> {
        let CodexAuth::AgentIdentity(auth) = auth? else {
            return None;
        };
        let encoded = serde_json::to_vec(auth.record()).ok()?;
        Some(Self(Sha1::digest(encoded).into()))
    }
}

impl McpRuntimeSnapshot {
    pub(crate) fn new(
        config: Arc<McpConfig>,
        plugins_available: bool,
        manager: Arc<McpConnectionManager>,
        runtime_context: McpRuntimeContext,
        available_environment_ids: Vec<String>,
        transport_auth_binding: Option<TransportAuthBinding>,
        credential_revision: Option<u64>,
        effective_auth: Option<CodexAuth>,
    ) -> Self {
        let effective_auth_fingerprint =
            EffectiveAuthFingerprint::for_auth(effective_auth.as_ref());
        Self {
            config,
            plugins_available,
            manager,
            runtime_context,
            available_environment_ids,
            transport_auth_binding,
            credential_revision,
            effective_auth_fingerprint,
            effective_auth,
        }
    }

    pub fn config(&self) -> &McpConfig {
        self.config.as_ref()
    }

    pub(crate) fn plugins_available(&self) -> bool {
        self.plugins_available
    }

    pub fn manager(&self) -> &McpConnectionManager {
        self.manager.as_ref()
    }

    pub fn manager_arc(&self) -> Arc<McpConnectionManager> {
        Arc::clone(&self.manager)
    }

    pub fn runtime_context(&self) -> &McpRuntimeContext {
        &self.runtime_context
    }

    pub(crate) fn available_environment_ids(&self) -> &[String] {
        &self.available_environment_ids
    }
    pub(crate) fn transport_auth_binding(&self) -> Option<&TransportAuthBinding> {
        self.transport_auth_binding.as_ref()
    }
    pub(crate) fn credential_revision(&self) -> Option<u64> {
        self.credential_revision
    }
    pub(crate) fn effective_auth_fingerprint(&self) -> Option<EffectiveAuthFingerprint> {
        self.effective_auth_fingerprint
    }
    pub fn effective_auth(&self) -> Option<&CodexAuth> {
        self.effective_auth.as_ref()
    }
    pub fn connector_directory_cache_key(
        &self,
        chatgpt_base_url: impl Into<String>,
        auth: Option<&codex_login::CodexAuth>,
    ) -> Option<codex_connectors::ConnectorDirectoryCacheKey> {
        let transport_auth_binding = self.transport_auth_binding.clone()?;
        if self.credential_revision.is_none() && auth.is_none() {
            return None;
        }
        Some(
            codex_connectors::ConnectorDirectoryCacheKey::from_runtime_binding(
                chatgpt_base_url.into(),
                transport_auth_binding,
                self.credential_revision,
                auth.is_some_and(codex_login::CodexAuth::is_workspace_account),
            ),
        )
    }
    pub fn codex_apps_tools_cache_key(&self) -> Option<codex_mcp::CodexAppsToolsCacheKey> {
        Some(codex_mcp::CodexAppsToolsCacheKey::from_transport_binding(
            self.transport_auth_binding.clone()?,
            self.credential_revision?,
            self.config.chatgpt_base_url.clone(),
        ))
    }

    #[cfg(test)]
    pub(crate) fn new_uninitialized_for_test(config: &crate::config::Config) -> Arc<Self> {
        use codex_exec_server::EnvironmentManager;
        use codex_features::Feature;
        use codex_mcp::ResolvedMcpCatalog;
        use rmcp::model::ElicitationCapability;

        let mcp_config = McpConfig {
            chatgpt_base_url: config.chatgpt_base_url.clone(),
            apps_mcp_product_sku: config.apps_mcp_product_sku.clone(),
            codex_home: config.codex_home.to_path_buf(),
            mcp_oauth_credentials_store_mode: config.mcp_oauth_credentials_store_mode,
            auth_keyring_backend_kind: config.auth_keyring_backend_kind(),
            mcp_oauth_callback_port: config.mcp_oauth_callback_port,
            mcp_oauth_callback_url: config.mcp_oauth_callback_url.clone(),
            skill_mcp_dependency_install_enabled: config
                .features
                .enabled(Feature::SkillMcpDependencyInstall),
            approval_policy: config.permissions.approval_policy.clone(),
            codex_linux_sandbox_exe: config.codex_linux_sandbox_exe.clone(),
            use_legacy_landlock: config.features.use_legacy_landlock(),
            apps_enabled: config.features.enabled(Feature::Apps),
            prefix_mcp_tool_names: config.prefix_mcp_tool_names(),
            client_elicitation_capability: ElicitationCapability::default(),
            mcp_server_catalog: ResolvedMcpCatalog::default(),
            connector_snapshot: codex_connectors::ConnectorSnapshot::default(),
        };
        let manager = McpConnectionManager::new_uninitialized_with_permission_profile(
            &config.permissions.approval_policy,
            config.permissions.permission_profile(),
            config.prefix_mcp_tool_names(),
        );
        let runtime_context = McpRuntimeContext::new(
            Arc::new(EnvironmentManager::default_for_tests()),
            config.cwd.to_path_buf(),
        );
        Arc::new(Self::new(
            Arc::new(mcp_config),
            /*plugins_available*/ false,
            Arc::new(manager),
            runtime_context,
            Vec::new(),
            /*transport_auth_binding*/ None,
            /*credential_revision*/ None,
            /*effective_auth*/ None,
        ))
    }
}

impl fmt::Debug for McpRuntimeSnapshot {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("McpRuntimeSnapshot")
            .finish_non_exhaustive()
    }
}
