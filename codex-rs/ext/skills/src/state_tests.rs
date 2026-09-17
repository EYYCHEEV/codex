use std::sync::Arc;

use codex_extension_api::ExtensionData;
use codex_mcp::McpResourceClient;
use codex_mcp::McpRuntime;

use super::SkillsSessionState;
use super::current_mcp_resource_client;

fn resource_client() -> McpResourceClient {
    McpResourceClient::new(Arc::new(McpRuntime::empty(
        /*prefix_mcp_tool_names*/ true,
    )))
}

fn assert_same_client(actual: &McpResourceClient, expected: &McpResourceClient) {
    assert!(actual.cache_key() == expected.cache_key());
}

#[test]
fn current_mcp_resource_client_uses_most_specific_direct_store_before_compatibility_state() {
    let session_store = ExtensionData::new("session");
    let thread_store = ExtensionData::new("thread");
    let request_store = ExtensionData::new("request");
    let compatibility_client = Arc::new(resource_client());
    session_store.insert(SkillsSessionState {
        mcp_resources: Some(Arc::clone(&compatibility_client)),
        extension_metrics: None,
    });

    let resolved = current_mcp_resource_client(None, &thread_store, &session_store)
        .expect("compatibility client should be available");
    assert_same_client(&resolved, &compatibility_client);

    let session_client = resource_client();
    session_store.insert(session_client.clone());
    let resolved = current_mcp_resource_client(None, &thread_store, &session_store)
        .expect("session client should be available");
    assert_same_client(&resolved, &session_client);

    let thread_client = resource_client();
    thread_store.insert(thread_client.clone());
    let resolved = current_mcp_resource_client(None, &thread_store, &session_store)
        .expect("thread client should be available");
    assert_same_client(&resolved, &thread_client);

    let request_client = resource_client();
    request_store.insert(request_client.clone());
    let resolved = current_mcp_resource_client(Some(&request_store), &thread_store, &session_store)
        .expect("request client should be available");
    assert_same_client(&resolved, &request_client);
}

#[test]
fn resolved_mcp_resource_client_keeps_its_request_identity_after_store_replacement() {
    let session_store = ExtensionData::new("session");
    let thread_store = ExtensionData::new("thread");
    let request_store = ExtensionData::new("request");
    request_store.insert(resource_client());

    let captured = current_mcp_resource_client(Some(&request_store), &thread_store, &session_store)
        .expect("request client should be captured");
    request_store.insert(resource_client());
    let replacement =
        current_mcp_resource_client(Some(&request_store), &thread_store, &session_store)
            .expect("replacement request client should be available");

    assert!(captured.cache_key() != replacement.cache_key());
}
