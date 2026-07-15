use std::sync::Arc;
use std::sync::Weak;

use anyhow::Context;
use anyhow::Result;
use codex_protocol::mcp::Resource;
use codex_protocol::mcp::ResourceContent;
use rmcp::model::PaginatedRequestParams;
use rmcp::model::ReadResourceRequestParams;

use crate::McpConnectionManager;

/// One page of resources returned by an MCP server.
#[derive(Clone, Debug, PartialEq)]
pub struct McpResourcePage {
    /// Resources advertised on this page.
    pub resources: Vec<Resource>,
    /// Opaque cursor to supply when requesting the next page.
    pub next_cursor: Option<String>,
}

/// Contents returned after reading one MCP resource.
#[derive(Clone, Debug, PartialEq)]
pub struct McpResourceReadResult {
    /// Text or blob content returned for the requested resource.
    pub contents: Vec<ResourceContent>,
}

/// Session-scoped access to MCP resources through one captured manager.
///
/// The manager snapshot is selected by the runtime owner. Resource calls and
/// cache identity always use that same manager, even if a newer runtime is
/// published concurrently.
#[derive(Clone)]
pub struct McpResourceClient {
    manager: Arc<McpConnectionManager>,
}

/// Opaque identity for the manager currently used by an MCP resource client.
#[derive(Clone)]
pub struct McpResourceClientCacheKey(Weak<McpConnectionManager>);

impl PartialEq for McpResourceClientCacheKey {
    fn eq(&self, other: &Self) -> bool {
        self.0.ptr_eq(&other.0)
    }
}

impl Eq for McpResourceClientCacheKey {}

impl std::fmt::Debug for McpResourceClient {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("McpResourceClient")
            .finish_non_exhaustive()
    }
}

impl McpResourceClient {
    /// Creates a resource client backed by one exact MCP manager snapshot.
    pub fn new(manager: Arc<McpConnectionManager>) -> Self {
        Self { manager }
    }

    /// Returns the identity of the captured manager.
    pub fn cache_key(&self) -> McpResourceClientCacheKey {
        McpResourceClientCacheKey(Arc::downgrade(&self.manager))
    }

    /// Returns whether the captured manager contains the named server.
    ///
    /// This does not wait for server startup or imply that startup succeeded.
    pub async fn has_server(&self, server: &str) -> bool {
        self.manager.contains_server(server)
    }

    /// Lists one resource page from the named server.
    pub async fn list_resources(
        &self,
        server: &str,
        cursor: Option<String>,
    ) -> Result<McpResourcePage> {
        let params =
            cursor.map(|cursor| PaginatedRequestParams::default().with_cursor(Some(cursor)));
        let result = self.manager.list_resources(server, params).await?;
        let resources = result
            .resources
            .into_iter()
            .map(resource_from_rmcp)
            .collect::<Result<Vec<_>>>()?;
        Ok(McpResourcePage {
            resources,
            next_cursor: result.next_cursor,
        })
    }

    /// Reads one resource from the named server.
    pub async fn read_resource(&self, server: &str, uri: &str) -> Result<McpResourceReadResult> {
        let result = self
            .manager
            .read_resource(server, ReadResourceRequestParams::new(uri.to_string()))
            .await?;
        let contents = result
            .contents
            .into_iter()
            .map(resource_content_from_rmcp)
            .collect::<Result<Vec<_>>>()?;
        Ok(McpResourceReadResult { contents })
    }
}

fn resource_from_rmcp(resource: rmcp::model::Resource) -> Result<Resource> {
    let value = serde_json::to_value(resource).context("failed to serialize MCP resource")?;
    Resource::from_mcp_value(value).context("failed to convert MCP resource")
}

fn resource_content_from_rmcp(content: rmcp::model::ResourceContents) -> Result<ResourceContent> {
    let value =
        serde_json::to_value(content).context("failed to serialize MCP resource content")?;
    serde_json::from_value(value).context("failed to convert MCP resource content")
}

#[cfg(test)]
mod tests {
    use super::*;
    use codex_config::Constrained;
    use codex_protocol::models::PermissionProfile;
    use codex_protocol::protocol::AskForApproval;

    fn test_manager() -> Arc<McpConnectionManager> {
        Arc::new(
            McpConnectionManager::new_uninitialized_with_permission_profile(
                &Constrained::allow_any(AskForApproval::OnRequest),
                &PermissionProfile::default(),
                /*prefix_mcp_tool_names*/ true,
            ),
        )
    }

    #[tokio::test]
    async fn resource_client_retains_exact_manager_snapshot_and_cache_identity() {
        let first_manager = test_manager();
        let first = McpResourceClient::new(Arc::clone(&first_manager));
        let first_clone = first.clone();
        let replacement = McpResourceClient::new(test_manager());

        assert!(first.cache_key() == first_clone.cache_key());
        assert!(first.cache_key() != replacement.cache_key());

        drop(first_manager);
        assert!(first.cache_key().0.upgrade().is_some());
        assert!(!first.has_server("replacement-only").await);
    }
}
