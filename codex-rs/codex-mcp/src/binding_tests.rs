use std::collections::HashMap;
use std::io;
use std::sync::Arc;
use std::sync::atomic::AtomicBool;
use std::sync::atomic::Ordering;

use codex_config::AppToolApproval;
use codex_config::Constrained;
use codex_config::types::ApprovalsReviewer;
use codex_protocol::mcp::McpServerInfo;
use codex_protocol::models::PermissionProfile;
use codex_protocol::protocol::AskForApproval;
use codex_rmcp_client::InProcessTransportFactory;
use codex_rmcp_client::RmcpClient;
use futures::FutureExt;
use pretty_assertions::assert_eq;
use rmcp::model::Icon;
use rmcp::model::JsonObject;
use rmcp::model::MetaObject;
use rmcp::model::Tool;
use rmcp::model::ToolAnnotations;
use tokio::io::DuplexStream;
use tokio::sync::Notify;

use super::McpBinding;
use super::PreparedMcpCall;
use crate::binding_clients::McpBindingClients;
use crate::client_tool_catalog::ClientToolCatalog;
use crate::connection_manager::McpConnectionSet;
use crate::rmcp_client::ManagedClient;
use crate::server::McpServerMetadata;
use crate::server::McpServerOrigin;
use crate::tools::ToolInfo;

const SERVER_NAME: &str = "docs";
const TOOL_NAME: &str = "search";

struct TestInProcessTransportFactory;

impl InProcessTransportFactory for TestInProcessTransportFactory {
    fn open(&self) -> futures::future::BoxFuture<'static, io::Result<DuplexStream>> {
        async {
            let (client_stream, _server_stream) = tokio::io::duplex(1);
            Ok(client_stream)
        }
        .boxed()
    }
}

struct TestStep {
    step: Arc<McpBinding>,
    client: Arc<RmcpClient>,
    tool_catalog: Arc<ClientToolCatalog>,
}

async fn test_step(
    label: &str,
    approval_mode: AppToolApproval,
    supports_sandbox_state_meta: bool,
) -> TestStep {
    let tool = ToolInfo {
        server_name: SERVER_NAME.to_string(),
        supports_parallel_tool_calls: false,
        server_origin: None,
        callable_name: TOOL_NAME.to_string(),
        callable_namespace: SERVER_NAME.to_string(),
        namespace_description: None,
        tool: Tool::new(
            TOOL_NAME.to_string(),
            format!("{label} catalog"),
            Arc::new(JsonObject::default()),
        ),
        openai_file_input_optional_fields: Default::default(),
        connector_id: None,
        connector_name: None,
        plugin_display_names: Vec::new(),
    };
    let client = Arc::new(
        RmcpClient::new_in_process_client(Arc::new(TestInProcessTransportFactory))
            .await
            .expect("create in-process MCP client"),
    );
    let tool_catalog = Arc::new(ClientToolCatalog::new(
        vec![tool.clone()],
        /*updates*/ None,
    ));
    let managed_client = Arc::new(ManagedClient {
        _auth_change_notifications: None,
        client: Arc::clone(&client),
        server_info: McpServerInfo {
            name: label.to_string(),
            title: Some(format!("{label} server")),
            version: "1.0.0".to_string(),
            description: None,
            icons: None,
            website_url: None,
        },
        tool_catalog: Arc::clone(&tool_catalog),
        tool_timeout: None,
        server_instructions: None,
        server_supports_sandbox_state_meta_capability: supports_sandbox_state_meta,
        codex_apps_tools_cache_context: None,
    });
    let clients = Arc::new(McpBindingClients::new(HashMap::from([(
        SERVER_NAME.to_string(),
        Arc::clone(&managed_client),
    )])));
    let connections = Arc::new(McpConnectionSet::empty(/*prefix_mcp_tool_names*/ true));
    let mut config = crate::mcp::tests::test_mcp_config(std::env::temp_dir());
    if label == "old" {
        config.approval_policy = Constrained::allow_any(AskForApproval::Never);
        config.permission_profile = PermissionProfile::Disabled;
    } else {
        config.approvals_reviewer = ApprovalsReviewer::AutoReview;
    }
    config
        .server_permission_profiles
        .insert(SERVER_NAME.to_string(), config.permission_profile.clone());
    let config = Arc::new(config);
    let prepared = PreparedMcpCall::new(
        Arc::clone(&connections),
        managed_client,
        Arc::clone(&config),
        /*catalog_revision*/ 0,
        tool.clone(),
        McpServerMetadata {
            environment_id: format!("{label}-environment"),
            pollutes_memory: label == "old",
            origin: Some(McpServerOrigin::StreamableHttp(format!(
                "https://{label}.example"
            ))),
            supports_parallel_tool_calls: false,
            default_tools_approval_mode: Some(approval_mode),
            tool_approval_modes: HashMap::new(),
        },
        Some(format!("{label}-plugin")),
        label == "old",
    )
    .expect("test call should retain its thread-owned permission profile");
    let calls = HashMap::from([((SERVER_NAME.to_string(), TOOL_NAME.to_string()), prepared)]);

    TestStep {
        step: Arc::new(McpBinding::new(
            connections,
            clients,
            config,
            /*plugins_available*/ false,
            vec![tool],
            calls,
            HashMap::new(),
        )),
        client,
        tool_catalog,
    }
}

#[tokio::test]
async fn prepared_call_keeps_captured_connection_and_authority_after_refresh() -> anyhow::Result<()>
{
    let old = test_step(
        "old",
        AppToolApproval::Prompt,
        /*supports_sandbox_state_meta*/ true,
    )
    .await;
    let old_call = old
        .step
        .prepare_call(SERVER_NAME, TOOL_NAME)
        .expect("old step should prepare the advertised tool");
    let old_connections = Arc::downgrade(&old.step.connections);

    let new = test_step(
        "new",
        AppToolApproval::Approve,
        /*supports_sandbox_state_meta*/ false,
    )
    .await;
    let new_call = new
        .step
        .prepare_call(SERVER_NAME, TOOL_NAME)
        .expect("new step should prepare the advertised tool");

    assert_eq!(
        (
            old.step.tools()[0].tool.description.as_deref(),
            old_call.tool_info().tool.description.as_deref(),
            old_call.server_origin(),
            old_call.server_environment_id(),
            old_call.server_pollutes_memory(),
            old_call.tool_approval_mode(),
            old_call.plugin_id(),
            old_call.is_selected_plugin_server(),
            old_call
                .server_supports_sandbox_state_meta_capability()
                .await?,
        ),
        (
            Some("old catalog"),
            Some("old catalog"),
            Some("https://old.example"),
            "old-environment",
            true,
            AppToolApproval::Prompt,
            Some("old-plugin"),
            true,
            true,
        )
    );
    assert_eq!(
        (
            new.step.tools()[0].tool.description.as_deref(),
            new_call.tool_info().tool.description.as_deref(),
            new_call.server_environment_id(),
            new_call.tool_approval_mode(),
        ),
        (
            Some("new catalog"),
            Some("new catalog"),
            "new-environment",
            AppToolApproval::Approve,
        )
    );
    assert!(Arc::ptr_eq(&old_call.client.client, &old.client));
    assert!(!Arc::ptr_eq(&old.client, &new.client));
    assert_eq!(
        (
            old_call.config().approval_policy.value(),
            old_call.permission_profile(),
            old_call.config().approvals_reviewer,
        ),
        (
            AskForApproval::Never,
            &PermissionProfile::Disabled,
            ApprovalsReviewer::User,
        )
    );
    assert_eq!(
        (
            new_call.config().approval_policy.value(),
            new_call.config().approvals_reviewer,
        ),
        (AskForApproval::OnRequest, ApprovalsReviewer::AutoReview)
    );

    drop(old.step);
    assert!(
        old_connections.upgrade().is_some(),
        "the prepared call should keep its captured connection set alive"
    );
    drop(old_call);
    assert!(
        old_connections.upgrade().is_none(),
        "the captured connection set should be released with the prepared call"
    );
    Ok(())
}

#[tokio::test]
async fn internal_call_can_prepare_a_tool_hidden_from_the_model() {
    let mut step = test_step(
        "hidden",
        AppToolApproval::Approve,
        /*supports_sandbox_state_meta*/ false,
    )
    .await;
    let binding = Arc::get_mut(&mut step.step).expect("test binding should be uniquely owned");
    let hidden_meta = MetaObject(
        serde_json::json!({ "ui": { "visibility": [] } })
            .as_object()
            .expect("metadata object")
            .clone(),
    );
    binding.tools[0].tool.meta = Some(hidden_meta.clone());
    binding
        .calls
        .get_mut(&(SERVER_NAME.to_string(), TOOL_NAME.to_string()))
        .expect("test call should be captured")
        .tool_info
        .tool
        .meta = Some(hidden_meta);

    assert!(step.step.prepare_call(SERVER_NAME, TOOL_NAME).is_none());
    assert!(
        step.step
            .prepare_internal_call(SERVER_NAME, TOOL_NAME)
            .is_some()
    );
}

#[tokio::test]
async fn called_tool_contract_ignores_presentation_and_derived_callable_identity() {
    let step = test_step(
        "contract",
        AppToolApproval::Approve,
        /*supports_sandbox_state_meta*/ false,
    )
    .await;
    let mut advertised = step.step.tools()[0].clone();
    advertised.tool.annotations = Some(
        ToolAnnotations::new()
            .read_only(true)
            .destructive(false)
            .idempotent(true)
            .open_world(false),
    );

    let mut live = advertised.clone();
    live.namespace_description = Some("live server instructions".to_string());
    live.callable_name = "globally_rederived_name".to_string();
    live.callable_namespace = "globally_rederived_namespace".to_string();
    live.connector_name = Some("Live connector".to_string());
    live.plugin_display_names = vec!["Live plugin".to_string()];
    live.tool.title = Some("Live title".to_string());
    live.tool.description = Some("Live description".into());
    live.tool.icons = Some(vec![Icon::new("https://example.com/live.png")]);
    live.tool
        .annotations
        .as_mut()
        .expect("tool annotations")
        .title = Some("Live annotation title".to_string());
    assert!(live.has_same_execution_contract(&advertised));

    let mut empty_annotations = advertised.clone();
    empty_annotations.tool.annotations = Some(ToolAnnotations::new());
    let mut missing_annotations = advertised.clone();
    missing_annotations.tool.annotations = None;
    assert!(empty_annotations.has_same_execution_contract(&missing_annotations));
    assert!(missing_annotations.has_same_execution_contract(&empty_annotations));
    for (policy_name, live_annotations) in [
        ("read_only", ToolAnnotations::new().read_only(true)),
        ("destructive", ToolAnnotations::new().destructive(true)),
        ("idempotent", ToolAnnotations::new().idempotent(true)),
        ("open_world", ToolAnnotations::new().open_world(true)),
    ] {
        let mut live_with_policy = missing_annotations.clone();
        live_with_policy.tool.annotations = Some(live_annotations);
        assert!(
            !live_with_policy.has_same_execution_contract(&empty_annotations),
            "known-empty cached annotations must reject a new {policy_name} policy"
        );
    }

    let mut cached_without_read_only_hint = advertised.clone();
    cached_without_read_only_hint
        .tool
        .annotations
        .as_mut()
        .expect("tool annotations")
        .read_only_hint = None;
    assert!(
        advertised.has_same_execution_contract(&cached_without_read_only_hint),
        "model-facing cached tools intentionally omit the live read-only hint"
    );

    let mut changed_name = advertised.clone();
    changed_name.tool.name = "changed".into();
    assert!(!changed_name.has_same_execution_contract(&advertised));

    let mut changed_schema = advertised.clone();
    changed_schema.tool.input_schema = Arc::new(
        serde_json::json!({"type": "object", "required": ["changed"]})
            .as_object()
            .expect("schema object")
            .clone(),
    );
    assert!(!changed_schema.has_same_execution_contract(&advertised));

    let mut changed_read_only = advertised.clone();
    changed_read_only
        .tool
        .annotations
        .as_mut()
        .expect("tool annotations")
        .read_only_hint = Some(false);
    assert!(!changed_read_only.has_same_execution_contract(&advertised));

    let mut changed_destructive = advertised.clone();
    changed_destructive
        .tool
        .annotations
        .as_mut()
        .expect("tool annotations")
        .destructive_hint = Some(true);
    assert!(!changed_destructive.has_same_execution_contract(&advertised));

    let mut changed_idempotent = advertised.clone();
    changed_idempotent
        .tool
        .annotations
        .as_mut()
        .expect("tool annotations")
        .idempotent_hint = Some(false);
    assert!(!changed_idempotent.has_same_execution_contract(&advertised));

    let mut changed_open_world = advertised.clone();
    changed_open_world
        .tool
        .annotations
        .as_mut()
        .expect("tool annotations")
        .open_world_hint = Some(true);
    assert!(!changed_open_world.has_same_execution_contract(&advertised));

    let mut changed_meta = advertised.clone();
    changed_meta.tool.meta = Some(MetaObject::new());
    assert!(!changed_meta.has_same_execution_contract(&advertised));

    let mut changed_policy = advertised.clone();
    changed_policy.supports_parallel_tool_calls = !advertised.supports_parallel_tool_calls;
    assert!(!changed_policy.has_same_execution_contract(&advertised));
}

#[tokio::test]
async fn prepared_call_does_not_reroute_after_captured_connection_closes() {
    let old = test_step(
        "old",
        AppToolApproval::Prompt,
        /*supports_sandbox_state_meta*/ true,
    )
    .await;
    let old_call = old
        .step
        .prepare_call(SERVER_NAME, TOOL_NAME)
        .expect("old step should prepare the advertised tool");
    let new = test_step(
        "new",
        AppToolApproval::Approve,
        /*supports_sandbox_state_meta*/ false,
    )
    .await;
    assert!(!Arc::ptr_eq(&old.client, &new.client));

    old.client.shutdown().await;

    let error = old_call
        .call(
            Some(serde_json::json!({"query": "codex"})),
            /*meta*/ None,
            /*timeout*/ None,
        )
        .await
        .expect_err("a call bound to a closed connection must fail");
    assert!(
        format!("{error:#}").contains("MCP client is shut down"),
        "the prepared call should fail on its captured client: {error:#}"
    );
}

#[tokio::test]
async fn prepared_call_is_rejected_after_catalog_refresh() {
    let step = test_step(
        "old",
        AppToolApproval::Prompt,
        /*supports_sandbox_state_meta*/ true,
    )
    .await;
    let prepared = step
        .step
        .prepare_call(SERVER_NAME, TOOL_NAME)
        .expect("step should prepare the advertised tool");

    step.tool_catalog
        .refresh(
            || async { Ok((step.step.tools().to_vec(), ())) },
            |_, ()| {},
        )
        .await
        .expect("refresh tool catalog");

    let error = prepared
        .call(
            Some(serde_json::json!({"query": "codex"})),
            /*meta*/ None,
            /*timeout*/ None,
        )
        .await
        .expect_err("a call from an older catalog must be rejected");
    assert!(
        format!("{error:#}").contains("catalog changed"),
        "unexpected error: {error:#}"
    );
}

#[tokio::test]
async fn stale_prepared_call_does_not_run_preparation() {
    let step = test_step(
        "old",
        AppToolApproval::Prompt,
        /*supports_sandbox_state_meta*/ true,
    )
    .await;
    let prepared = step
        .step
        .prepare_call(SERVER_NAME, TOOL_NAME)
        .expect("step should prepare the advertised tool");
    step.tool_catalog
        .refresh(
            || async { Ok((step.step.tools().to_vec(), ())) },
            |_, ()| {},
        )
        .await
        .expect("refresh tool catalog");
    let prepared_side_effect_ran = Arc::new(AtomicBool::new(false));
    let marker = Arc::clone(&prepared_side_effect_ran);

    prepared
        .call_with_preparation(/*requested_timeout*/ None, || async move {
            marker.store(true, Ordering::SeqCst);
            Ok((None, None))
        })
        .await
        .expect_err("a call from an older catalog must be rejected");

    assert!(!prepared_side_effect_ran.load(Ordering::SeqCst));
}

#[tokio::test]
async fn preparation_holds_catalog_authority_until_it_finishes() {
    let step = test_step(
        "old",
        AppToolApproval::Prompt,
        /*supports_sandbox_state_meta*/ true,
    )
    .await;
    let prepared = step
        .step
        .prepare_call(SERVER_NAME, TOOL_NAME)
        .expect("step should prepare the advertised tool");
    let preparation_started = Arc::new(Notify::new());
    let finish_preparation = Arc::new(Notify::new());
    let started = Arc::clone(&preparation_started);
    let finish = Arc::clone(&finish_preparation);
    let call = tokio::spawn(async move {
        prepared
            .call_with_preparation(/*requested_timeout*/ None, || async move {
                started.notify_one();
                finish.notified().await;
                Err(anyhow::anyhow!("stop after preparation"))
            })
            .await
    });

    preparation_started.notified().await;
    let refresh = step.tool_catalog.refresh(
        || async { Ok((step.step.tools().to_vec(), ())) },
        |_, ()| {},
    );
    tokio::pin!(refresh);
    assert!(
        futures::poll!(&mut refresh).is_pending(),
        "catalog replacement must wait for irreversible call preparation"
    );
    finish_preparation.notify_one();
    call.await
        .expect("call task should finish")
        .expect_err("the test preparation should stop the call");
    refresh
        .await
        .expect("catalog refresh should finish after preparation");
}
