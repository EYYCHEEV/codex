use std::sync::Arc;
use std::sync::Weak;

use anyhow::Context;
use anyhow::Result;
use codex_protocol::mcp::Resource;
use codex_protocol::mcp::ResourceContent;
use rmcp::model::PaginatedRequestParams;
use rmcp::model::ReadResourceRequestParams;

use crate::McpBinding;

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

/// Session-scoped access to MCP resources through one captured binding.
///
/// Resource calls and cache identity always use that same request binding, even if a newer runtime is
/// published concurrently.
#[derive(Clone)]
pub struct McpResourceClient {
    binding: Arc<McpBinding>,
}

/// Opaque identity for the connection set currently used by an MCP resource client.
#[derive(Clone)]
pub struct McpResourceClientCacheKey(Weak<crate::connection_manager::McpConnectionSet>);

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
    /// Creates a resource client backed by one exact request binding.
    pub fn new(binding: Arc<McpBinding>) -> Self {
        Self { binding }
    }

    /// Returns the identity of the captured connection set.
    pub fn cache_key(&self) -> McpResourceClientCacheKey {
        McpResourceClientCacheKey(self.binding.connection_cache_key())
    }

    /// Returns whether the captured binding contains the named server.
    ///
    /// This does not wait for server startup.
    pub async fn has_server(&self, server: &str) -> bool {
        self.binding.has_server(server)
    }

    /// Lists one resource page from the named server.
    pub async fn list_resources(
        &self,
        server: &str,
        cursor: Option<String>,
    ) -> Result<McpResourcePage> {
        let params =
            cursor.map(|cursor| PaginatedRequestParams::default().with_cursor(Some(cursor)));
        let result = self.binding.list_resources(server, params).await?;
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
        let params = ReadResourceRequestParams::new(uri.to_string());
        let result = self.binding.read_resource(server, params).await?;
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

    fn test_binding() -> Arc<McpBinding> {
        let config = crate::mcp::tests::test_mcp_config(
            std::env::temp_dir().join("codex-resource-client-test"),
        );
        Arc::new(McpBinding::empty(Arc::new(config)))
    }

    #[tokio::test]
    async fn resource_client_retains_exact_binding_and_cache_identity() {
        let first_binding = test_binding();
        let first = McpResourceClient::new(Arc::clone(&first_binding));
        let first_clone = first.clone();
        let replacement = McpResourceClient::new(test_binding());

        assert!(first.cache_key() == first_clone.cache_key());
        assert!(first.cache_key() != replacement.cache_key());

        drop(first_binding);
        assert!(first.cache_key().0.upgrade().is_some());
        assert!(!first.has_server("replacement-only").await);
    }
}
