//! Shared raw tool cache for the host-owned Codex Apps MCP server.
//!
//! Cache entries are process-local live state scoped by the active Codex auth
//! key. Disk is best-effort cold-start persistence; entries do not reread disk
//! after creation.

use std::collections::HashMap;
use std::path::Path;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::atomic::AtomicU64;
use std::sync::atomic::Ordering;
use std::time::Instant;

use anyhow::Context;
use arc_swap::ArcSwapOption;
use codex_login::CodexAuth;
use codex_login::TransportAuthBinding;
use codex_protocol::auth::AuthMode;
use codex_protocol::mcp::McpServerInfo;
use serde::Deserialize;
use serde::Serialize;
use sha1::Digest;
use sha1::Sha1;
use std::hash::Hash;
use std::hash::Hasher;
use tracing::instrument;

use crate::runtime::emit_duration;
use crate::tools::MCP_TOOLS_CACHE_WRITE_DURATION_METRIC;
use crate::tools::ToolInfo;

const MCP_TOOLS_CACHE_PUBLISH_DURATION_METRIC: &str = "codex.mcp.tools.cache_publish.duration_ms";

/// The complete account and route identity for one Codex Apps catalog.
///
/// This deliberately contains no bearer or refresh token material. Managed
/// callers should use [`CodexAppsToolsCacheKey::from_transport_binding`] so
/// catalog reuse follows the exact transport selected for the manager.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CodexAppsToolsCacheKey {
    transport: TransportAuthBinding,
    credential_revision: u64,
    base_url: String,
    managed: bool,
}

impl CodexAppsToolsCacheKey {
    /// Builds the exact identity for a managed account snapshot.
    ///
    /// A managed key must never be synthesized from compatibility auth: the
    /// credential revision and base URL are both required to bind the key to
    /// the selected account row and route.
    pub fn from_transport_binding(
        transport: TransportAuthBinding,
        credential_revision: u64,
        base_url: impl Into<String>,
    ) -> Self {
        assert!(
            credential_revision > 0,
            "managed Codex Apps keys require a credential revision"
        );
        let base_url = normalize_base_url(base_url.into());
        assert!(
            !base_url.is_empty(),
            "managed Codex Apps keys require a base URL"
        );
        Self {
            transport,
            credential_revision,
            base_url,
            managed: true,
        }
    }

    pub(crate) fn is_managed(&self) -> bool {
        self.managed
    }

    pub(crate) fn transport_binding(&self) -> TransportAuthBinding {
        self.transport.clone()
    }
}

impl Hash for CodexAppsToolsCacheKey {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.transport.identity_key.hash(state);
        self.transport.raw_account_id.hash(state);
        self.transport.fedramp.hash(state);
        auth_mode_tag(self.transport.auth_mode).hash(state);
        self.transport.route_generation.hash(state);
        self.credential_revision.hash(state);
        self.base_url.hash(state);
        self.managed.hash(state);
    }
}

/// Builds a compatibility key for non-snapshot callers.
///
/// Managed account-pool callers must instead pass their captured
/// [`TransportAuthBinding`] and credential revision to
/// [`CodexAppsToolsCacheKey::from_transport_binding`].
pub fn codex_apps_tools_cache_key(auth: Option<&CodexAuth>) -> CodexAppsToolsCacheKey {
    let auth_mode = auth.map_or(AuthMode::Chatgpt, CodexAuth::api_auth_mode);
    let raw_account_id = auth.and_then(CodexAuth::get_account_id);
    let identity_key = auth
        .and_then(CodexAuth::get_chatgpt_user_id)
        .or_else(|| raw_account_id.clone())
        .unwrap_or_else(|| format!("nonpooled:{auth_mode}"));
    CodexAppsToolsCacheKey {
        transport: TransportAuthBinding {
            identity_key,
            raw_account_id,
            fedramp: auth.is_some_and(CodexAuth::is_fedramp_account),
            auth_mode,
            route_generation: 0,
        },
        credential_revision: 0,
        base_url: String::new(),
        managed: false,
    }
}

fn normalize_base_url(base_url: String) -> String {
    base_url.trim().trim_end_matches('/').to_string()
}

fn auth_mode_tag(auth_mode: AuthMode) -> u8 {
    match auth_mode {
        AuthMode::ApiKey => 0,
        AuthMode::Chatgpt => 1,
        AuthMode::ChatgptAuthTokens => 2,
        AuthMode::Headers => 3,
        AuthMode::AgentIdentity => 4,
        AuthMode::PersonalAccessToken => 5,
        AuthMode::BedrockApiKey => 6,
    }
}

/// Process-scoped registry for shared Codex Apps raw tool snapshots.
///
/// Two clients share an entry only when they would read the same Codex Apps
/// catalog. New entries may seed from disk; live entries read from memory only.
#[derive(Clone, Default)]
pub struct CodexAppsToolsCache {
    entries: Arc<Mutex<HashMap<CodexAppsToolsCacheIdentity, Arc<CodexAppsToolsCacheEntry>>>>,
}

/// Handle to one shared Codex Apps tools cache entry.
///
/// The connection manager creates this from the auth key, then tool
/// reads and refreshes for that managed client use the same entry.
#[derive(Clone)]
pub(crate) struct CodexAppsToolsCacheContext {
    entry: Arc<CodexAppsToolsCacheEntry>,
}

impl CodexAppsToolsCacheContext {
    pub(crate) fn tools_cache_path(&self) -> PathBuf {
        self.entry
            .identity
            .cache_path_in(CODEX_APPS_TOOLS_CACHE_DIR)
    }

    pub(crate) fn server_info_cache_path(&self) -> PathBuf {
        self.entry
            .identity
            .cache_path_in(CODEX_APPS_SERVER_INFO_CACHE_DIR)
    }

    pub(crate) fn current_tools(&self) -> Option<Vec<ToolInfo>> {
        self.entry
            .current_tools
            .load_full()
            .map(|tools| tools.as_ref().clone())
    }

    pub(crate) fn has_current_tools(&self) -> bool {
        self.entry.current_tools.load_full().is_some()
    }

    pub(crate) fn begin_fetch(
        &self,
        source: CodexAppsToolsFetchSource,
    ) -> CodexAppsToolsFetchTicket {
        CodexAppsToolsFetchTicket {
            generation: self
                .entry
                .next_fetch_generation
                .fetch_add(1, Ordering::Relaxed)
                + 1,
            source,
        }
    }

    pub(crate) fn publish_if_newest_accepted(
        &self,
        ticket: CodexAppsToolsFetchTicket,
        server_info: &McpServerInfo,
        tools: Vec<ToolInfo>,
    ) -> Vec<ToolInfo> {
        let publish_start = Instant::now();
        let mut last_accepted_generation = lock_unpoisoned(&self.entry.last_accepted_generation);
        if ticket.generation <= *last_accepted_generation {
            emit_duration(
                MCP_TOOLS_CACHE_PUBLISH_DURATION_METRIC,
                publish_start.elapsed(),
                &[("source", ticket.source.as_str()), ("result", "stale")],
            );
            return self.current_tools().unwrap_or(tools);
        }

        *last_accepted_generation = ticket.generation;
        self.entry
            .current_tools
            .store(Some(Arc::new(tools.clone())));
        persist_codex_apps_cache(self, server_info, &tools);
        emit_duration(
            MCP_TOOLS_CACHE_PUBLISH_DURATION_METRIC,
            publish_start.elapsed(),
            &[("source", ticket.source.as_str()), ("result", "published")],
        );
        tools
    }

    #[cfg(test)]
    pub(crate) fn store_current_tools_for_test(&self, tools: Vec<ToolInfo>) {
        self.entry.current_tools.store(Some(Arc::new(tools)));
    }
}

impl CodexAppsToolsCache {
    pub(crate) fn context(
        &self,
        codex_home: PathBuf,
        auth_key: CodexAppsToolsCacheKey,
    ) -> CodexAppsToolsCacheContext {
        let identity = CodexAppsToolsCacheIdentity {
            codex_home,
            auth_key,
        };
        let mut entries = lock_unpoisoned(&self.entries);
        let entry = entries
            .entry(identity.clone())
            .or_insert_with(|| Arc::new(CodexAppsToolsCacheEntry::new(identity)))
            .clone();
        CodexAppsToolsCacheContext { entry }
    }
}

#[derive(Debug, Clone, Copy)]
pub(crate) enum CodexAppsToolsFetchSource {
    Startup,
    HardRefresh,
}

impl CodexAppsToolsFetchSource {
    fn as_str(self) -> &'static str {
        match self {
            Self::Startup => "startup",
            Self::HardRefresh => "hard_refresh",
        }
    }
}

pub(crate) struct CodexAppsToolsFetchTicket {
    generation: u64,
    source: CodexAppsToolsFetchSource,
}

struct CodexAppsToolsCacheEntry {
    identity: CodexAppsToolsCacheIdentity,
    current_tools: ArcSwapOption<Vec<ToolInfo>>,
    next_fetch_generation: AtomicU64,
    last_accepted_generation: Mutex<u64>,
}

impl CodexAppsToolsCacheEntry {
    fn new(identity: CodexAppsToolsCacheIdentity) -> Self {
        let current_tools = load_cached_codex_apps_tools_for_identity(&identity).map(Arc::new);
        Self {
            identity,
            current_tools: ArcSwapOption::from(current_tools),
            next_fetch_generation: AtomicU64::new(0),
            last_accepted_generation: Mutex::new(0),
        }
    }
}

/// Everything that decides whether two Codex Apps clients can share tools.
///
/// The auth key says whose catalog we are reading. `codex_home` keeps the
/// persisted cache under the right home directory.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct CodexAppsToolsCacheIdentity {
    codex_home: PathBuf,
    auth_key: CodexAppsToolsCacheKey,
}

impl CodexAppsToolsCacheIdentity {
    fn cache_path_in(&self, cache_dir: &str) -> PathBuf {
        // `codex_home` is already the parent directory. Keep it out of the
        // filename hash so non-UTF-8 Unix paths cannot collapse distinct auth
        // keys onto the same disk cache file.
        let identity_json = serde_json::to_string(&self.auth_key).unwrap_or_default();
        let identity_hash = sha1_hex(&identity_json);
        self.codex_home
            .join(cache_dir)
            .join(format!("{identity_hash}.json"))
    }
}

#[cfg(test)]
fn write_cached_codex_apps_tools_for_test(
    cache_context: &CodexAppsToolsCacheContext,
    server_info: &McpServerInfo,
    tools: &[ToolInfo],
) {
    cache_context
        .entry
        .current_tools
        .store(Some(Arc::new(tools.to_vec())));
    persist_codex_apps_cache(cache_context, server_info, tools);
}

pub(crate) fn load_startup_cached_codex_apps_server_info(
    cache_context: &CodexAppsToolsCacheContext,
) -> Option<McpServerInfo> {
    load_cached_codex_apps_server_info(cache_context)
}

#[cfg(test)]
fn read_cached_codex_apps_tools(
    cache_context: &CodexAppsToolsCacheContext,
) -> Option<Vec<ToolInfo>> {
    load_cached_codex_apps_tools_for_identity(&cache_context.entry.identity)
}

#[instrument(level = "trace", skip_all)]
fn load_cached_codex_apps_tools_for_identity(
    identity: &CodexAppsToolsCacheIdentity,
) -> Option<Vec<ToolInfo>> {
    let cache_path = identity.cache_path_in(CODEX_APPS_TOOLS_CACHE_DIR);
    let bytes = std::fs::read(cache_path).ok()?;
    let cache: CodexAppsToolsDiskCache = serde_json::from_slice(&bytes).ok()?;
    (cache.schema_version == CODEX_APPS_TOOLS_CACHE_SCHEMA_VERSION).then_some(cache.tools)
}

fn write_cached_codex_apps_tools(
    cache_context: &CodexAppsToolsCacheContext,
    tools: &[ToolInfo],
) -> anyhow::Result<()> {
    let cache_path = cache_context.tools_cache_path();
    let bytes = serde_json::to_vec_pretty(&CodexAppsToolsDiskCache {
        schema_version: CODEX_APPS_TOOLS_CACHE_SCHEMA_VERSION,
        tools: tools.to_vec(),
    })
    .context("failed to serialize Codex Apps tools cache")?;
    write_codex_apps_cache_file(&cache_path, "tools", bytes)
}

#[instrument(level = "trace", skip_all)]
fn load_cached_codex_apps_server_info(
    cache_context: &CodexAppsToolsCacheContext,
) -> Option<McpServerInfo> {
    let bytes = std::fs::read(cache_context.server_info_cache_path()).ok()?;
    let cache: CodexAppsServerInfoDiskCache = serde_json::from_slice(&bytes).ok()?;
    (cache.schema_version == CODEX_APPS_SERVER_INFO_CACHE_SCHEMA_VERSION)
        .then_some(cache.server_info)
}

fn write_cached_codex_apps_server_info(
    cache_context: &CodexAppsToolsCacheContext,
    server_info: &McpServerInfo,
) -> anyhow::Result<()> {
    let cache_path = cache_context.server_info_cache_path();
    let bytes = serde_json::to_vec_pretty(&CodexAppsServerInfoDiskCache {
        schema_version: CODEX_APPS_SERVER_INFO_CACHE_SCHEMA_VERSION,
        server_info: server_info.clone(),
    })
    .context("failed to serialize Codex Apps server info cache")?;
    write_codex_apps_cache_file(&cache_path, "server info", bytes)
}

fn write_codex_apps_cache_file(
    cache_path: &Path,
    cache_name: &str,
    bytes: Vec<u8>,
) -> anyhow::Result<()> {
    if let Some(parent) = cache_path.parent() {
        std::fs::create_dir_all(parent).with_context(|| {
            format!(
                "failed to create Codex Apps {cache_name} cache directory `{}`",
                parent.display()
            )
        })?;
    }
    std::fs::write(cache_path, bytes).with_context(|| {
        format!(
            "failed to write Codex Apps {cache_name} cache `{}`",
            cache_path.display()
        )
    })?;
    Ok(())
}

fn persist_codex_apps_cache(
    cache_context: &CodexAppsToolsCacheContext,
    server_info: &McpServerInfo,
    tools: &[ToolInfo],
) {
    let cache_write_start = Instant::now();
    let tools_result = write_cached_codex_apps_tools(cache_context, tools);
    if let Err(err) = &tools_result {
        tracing::warn!("failed to write Codex Apps tools cache: {err:#}");
    }
    let server_info_result = write_cached_codex_apps_server_info(cache_context, server_info);
    if let Err(err) = &server_info_result {
        tracing::warn!("failed to write Codex Apps server info cache: {err:#}");
    }
    let status = if tools_result.is_ok() && server_info_result.is_ok() {
        "success"
    } else {
        "failure"
    };
    emit_duration(
        MCP_TOOLS_CACHE_WRITE_DURATION_METRIC,
        cache_write_start.elapsed(),
        &[("status", status)],
    );
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct CodexAppsToolsDiskCache {
    schema_version: u8,
    tools: Vec<ToolInfo>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct CodexAppsServerInfoDiskCache {
    schema_version: u8,
    server_info: McpServerInfo,
}

const CODEX_APPS_TOOLS_CACHE_DIR: &str = "cache/codex_apps_tools";
const CODEX_APPS_TOOLS_CACHE_SCHEMA_VERSION: u8 = 4;

const CODEX_APPS_SERVER_INFO_CACHE_DIR: &str = "cache/codex_apps_server_info";
const CODEX_APPS_SERVER_INFO_CACHE_SCHEMA_VERSION: u8 = 1;

fn sha1_hex(s: &str) -> String {
    let mut hasher = Sha1::new();
    hasher.update(s.as_bytes());
    let sha1 = hasher.finalize();
    format!("{sha1:x}")
}

fn lock_unpoisoned<T>(mutex: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    mutex
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

#[cfg(test)]
#[path = "codex_apps_cache_tests.rs"]
mod tests;
