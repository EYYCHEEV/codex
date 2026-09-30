//! Reuses warning-free cloud catalogs until their Apps resource generation changes.
//! Changed same-turn bindings recapture through the same discovery owner.
//! Repeated captures of one binding do not retry failures or partial catalogs.
//! Snapshot readers never discover; same-auth failures may retain the previous catalog.

use codex_extension_api::ExtensionData;
use codex_extension_api::ExtensionFuture;
use codex_extension_api::TurnLifecycleContributor;
use codex_extension_api::TurnStartInput;
use codex_extension_api::TurnStartPhase;
use codex_mcp::CODEX_APPS_MCP_SERVER_NAME;
use codex_mcp::McpResourceClientAuthKey;
use codex_mcp::McpResourceClientCacheKey;
use codex_mcp::McpResourceServerCacheKey;

use super::SkillsExtension;
use crate::provider::SkillListQuery;
use crate::state::CloudSkillRefresh;
use crate::state::SkillsThreadState;
use crate::state::current_mcp_resource_client;

// Turn-start discovery precedes capture of the first immutable step binding.
// Retain its exact attempted authority, including on failure, so the first step
// can adopt only that authority without retrying a failed discovery.
struct CloudSkillsBinding {
    step: Option<McpResourceClientCacheKey>,
    resources: Option<McpResourceServerCacheKey>,
    auth: Option<McpResourceClientAuthKey>,
}

impl<C: Send + Sync + 'static> TurnLifecycleContributor for SkillsExtension<C> {
    fn turn_start_phase(&self, thread_store: &ExtensionData) -> TurnStartPhase {
        if self.providers.has_cloud_provider()
            && thread_store
                .get::<SkillsThreadState>()
                .is_some_and(|state| state.cloud_skill_enabled())
        {
            TurnStartPhase::RegularTaskStart
        } else {
            TurnStartPhase::BeforeTaskRegistration
        }
    }

    fn requires_mcp_runtime(&self, thread_store: &ExtensionData) -> bool {
        self.turn_start_phase(thread_store) == TurnStartPhase::RegularTaskStart
    }

    fn on_turn_start<'a>(&'a self, input: TurnStartInput<'a>) -> ExtensionFuture<'a, ()> {
        Box::pin(async move {
            self.prepare_cloud_skills(
                input.turn_id,
                input.session_store,
                input.thread_store,
                input.turn_store,
                CloudSkillRefresh::TurnStart,
            )
            .await;
        })
    }
}

impl<C> SkillsExtension<C> {
    pub(super) async fn prepare_cloud_skills(
        &self,
        turn_id: &str,
        session_store: &ExtensionData,
        thread_store: &ExtensionData,
        turn_store: &ExtensionData,
        refresh: CloudSkillRefresh,
    ) {
        let Some(state) = thread_store.get::<SkillsThreadState>() else {
            return;
        };
        if !state.cloud_skill_enabled() || !self.providers.has_cloud_provider() {
            return;
        }
        let mcp_resources =
            current_mcp_resource_client(Some(turn_store), thread_store, session_store);
        let binding = CloudSkillsBinding {
            step: match refresh {
                CloudSkillRefresh::TurnStart => None,
                CloudSkillRefresh::Step => mcp_resources.as_ref().map(|client| client.cache_key()),
            },
            resources: mcp_resources
                .as_ref()
                .and_then(|client| client.server_cache_key(CODEX_APPS_MCP_SERVER_NAME)),
            auth: mcp_resources
                .as_ref()
                .map(|client| client.auth_cache_key_for_server(CODEX_APPS_MCP_SERVER_NAME)),
        };
        if let CloudSkillRefresh::Step = refresh
            && let Some(previous) = turn_store.get::<CloudSkillsBinding>()
        {
            if previous.step.is_some() && previous.step == binding.step {
                return;
            }
            if previous.step.is_none()
                && previous.resources == binding.resources
                && previous.auth == binding.auth
            {
                turn_store.insert(binding);
                return;
            }
        }
        turn_store.insert(binding);
        let config = state.config();
        let query = SkillListQuery {
            turn_id: turn_id.to_string(),
            executor_roots: Vec::new(),
            resolved_executor_roots: Vec::new(),
            host_snapshot: None,
            include_host_skills: false,
            include_bundled_skills: config.bundled_skills_enabled,
            include_cloud_skills: true,
            mcp_resources,
            executor_capability_discovery: None,
        };
        let result = state
            .refresh_cloud_catalog(&self.providers, query, refresh)
            .await;
        if let Err(error) = result {
            self.emit_warning(
                thread_store.level_id(),
                Some(turn_id),
                format!(
                    "Cloud skill discovery failed; retaining any catalog from the same cloud auth scope: {error}"
                ),
            );
        }
    }
}
