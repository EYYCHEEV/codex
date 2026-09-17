//! Parent model history and bounded host-owned context facts.
//! Compaction replaces only the model window. Snapshots include retained facts atomically;
//! checkpoint replay and source-call rollback share their live lifecycle.
//! Oversized instructions keep an incomplete excerpt for bounded root review, including
//! sources recovered from legacy Guardian checkpoints before their raw history is dropped.

#[path = "history_user_authorization.rs"]
mod user_authorization;

use crate::context::ContextualUserFragment;
use crate::context::world_state::WorldState;
use crate::context::world_state::WorldStateSnapshot;
use crate::context_manager::normalize;
use crate::event_mapping::has_non_contextual_dev_message_content;
use crate::event_mapping::is_contextual_dev_message_content;
use crate::event_mapping::is_contextual_user_message_content;
use crate::event_mapping::parse_turn_item;
use crate::guardian::GUARDIAN_MAX_ROOT_MESSAGE_TOKENS;
use crate::guardian::guardian_truncate_text;
use crate::session::turn_context::TurnContext;
use crate::utils::json::serialized_json_bytes;
use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use codex_context_fragments::AnnotatedContent;
use codex_context_fragments::set_annotated_content;
use codex_context_fragments::to_annotated_content;
use codex_extension_api::ConversationHistorySnapshot;
use codex_guardian_context::SectionHistory;
use codex_guardian_context::TranscriptHistory;
use codex_history::CodexHarnessMetadata;
use codex_history::GuardianHistoryCheckpoint;
use codex_history::ResponseItemEnvelope;
use codex_history::RetainedContext;
use codex_history::RetainedContextEvent;
use codex_history::RetainedInputSource;
use codex_protocol::items::TurnItem;
use codex_protocol::models::AgentMessageInputContent;
use codex_protocol::models::BaseInstructions;
use codex_protocol::models::ContentItem;
use codex_protocol::models::FunctionCallOutputBody;
use codex_protocol::models::FunctionCallOutputContentItem;
use codex_protocol::models::ImageDetail;
use codex_protocol::models::ResponseItem;
use codex_protocol::openai_models::InputModality;
use codex_protocol::protocol::InterAgentCommunication;
use codex_protocol::protocol::SessionSource;
use codex_protocol::protocol::TokenUsage;
use codex_protocol::protocol::TokenUsageInfo;
use codex_protocol::protocol::TurnContextItem;
use codex_protocol::protocol::WorldStateItem;
use codex_utils_audio::estimate_audio_token_count;
use codex_utils_cache::BlockingLruCache;
use codex_utils_cache::sha1_digest;
use codex_utils_output_truncation::TruncationPolicy;
use codex_utils_output_truncation::approx_bytes_for_tokens;
use codex_utils_output_truncation::approx_token_count;
use codex_utils_output_truncation::approx_tokens_from_byte_count_i64;
use codex_utils_output_truncation::truncate_function_output_payload;
use codex_utils_output_truncation::with_serialization_allowance;
use std::collections::HashSet;
use std::num::NonZeroUsize;
use std::ops::Deref;
use std::sync::Arc;
use std::sync::LazyLock;

use crate::context::GuardianContextMode;

const MODEL_VISIBLE_ITEM_MAX_TOKENS: usize = 10_000;
const MODEL_VISIBLE_ITEM_MAX_BYTES: usize = MODEL_VISIBLE_ITEM_MAX_TOKENS * 4;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum ToolPairKind {
    Function,
    ToolSearch,
    Custom,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum ToolPairSide {
    Call,
    Output,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct ToolPairKey {
    kind: ToolPairKind,
    call_id: String,
    side: ToolPairSide,
}

/// Transcript of thread history
#[derive(Debug, Clone, Default)]
pub(crate) struct ContextManager {
    /// The oldest items are at the beginning of the vector. Snapshots share the vector until a
    /// caller needs to mutate it, avoiding deep copies for read-only history consumers.
    items: Arc<Vec<ResponseItemEnvelope>>,
    /// Legacy-only history, started at first compaction. Thread-owned mode reads parent context.
    review_history: Option<TranscriptHistory>,
    /// Host facts independent of the model window; snapshots share immutable state.
    retained_context: Arc<RetainedContext>,
    /// Capture, replay, and snapshot selection share the immutable session mode.
    guardian_context_mode: GuardianContextMode,
    retain_inherited_user_messages: bool,
    /// Bumped whenever history is rewritten, such as compaction or rollback.
    history_version: u64,
    /// Monotonic user-input/reset revision, independent of compaction's history generation.
    user_message_revision: u64,
    token_info: Option<TokenUsageInfo>,
    /// Reference context snapshot used for diffing and producing model-visible
    /// settings update items.
    ///
    /// This is the baseline for the next regular model turn, and may already
    /// match the current turn after context updates are persisted.
    ///
    /// When this is `None`, settings diffing treats the next turn as having no
    /// baseline and emits a full reinjection of context state. Rollback may
    /// also clear this when it trims a mixed initial-context developer bundle
    /// whose non-diff fragments no longer exist in the surviving history.
    reference_context_item: Option<TurnContextItem>,
    /// World state most recently appended to model-visible history.
    world_state_baseline: Option<WorldStateSnapshot>,
    /// Oversized pair halves omitted while their counterpart has not arrived yet.
    omitted_tool_pairs: HashSet<ToolPairKey>,
}

struct SharedConversationHistory {
    items: Arc<Vec<ResponseItemEnvelope>>,
    review_history: Option<TranscriptHistory>,
    retained_context: Arc<RetainedContext>,
    guardian_context_mode: GuardianContextMode,
    history_version: u64,
    user_message_revision: u64,
}

pub(crate) enum HistoryReplacement {
    Compaction,
    Reset,
}

impl ConversationHistorySnapshot for SharedConversationHistory {
    fn latest_compaction_model_hash(&self) -> Option<&str> {
        self.items
            .iter()
            .rev()
            .find(|envelope| {
                matches!(
                    envelope.item,
                    ResponseItem::Compaction { .. } | ResponseItem::ContextCompaction { .. }
                )
            })
            .and_then(|envelope| envelope.metadata.as_ref())
            .and_then(|metadata| metadata.compaction_model_hash.as_deref())
    }

    fn retained_context(&self) -> Option<&RetainedContext> {
        (self.guardian_context_mode == GuardianContextMode::ThreadOwned)
            .then_some(&self.retained_context)
    }

    fn review_items(&self) -> Box<dyn Iterator<Item = &ResponseItem> + Send + '_> {
        match &self.review_history {
            Some(history) => history.items(),
            None => self.items(),
        }
    }

    fn review_history_version(&self) -> u64 {
        self.review_history
            .as_ref()
            .map_or(self.history_version, TranscriptHistory::generation)
    }

    fn history_version(&self) -> u64 {
        self.history_version
    }

    fn user_message_revision(&self) -> u64 {
        self.user_message_revision
    }

    fn items(&self) -> Box<dyn Iterator<Item = &ResponseItem> + Send + '_> {
        Box::new(
            self.items
                .iter()
                .map(|envelope| &envelope.item)
                .filter(|item| !is_contextual_user_item(item)),
        )
    }
}

impl ContextManager {
    pub(crate) fn new() -> Self {
        Self {
            items: Arc::new(Vec::new()),
            review_history: None,
            retained_context: Arc::default(),
            guardian_context_mode: GuardianContextMode::Legacy,
            retain_inherited_user_messages: false,
            history_version: 0,
            user_message_revision: 0,
            token_info: TokenUsageInfo::new_or_append(
                &None, &None, /*model_context_window*/ None,
            ),
            reference_context_item: None,
            world_state_baseline: None,
            omitted_tool_pairs: HashSet::new(),
        }
    }

    pub(crate) fn conversation_history_snapshot(&self) -> Arc<dyn ConversationHistorySnapshot> {
        Arc::new(SharedConversationHistory {
            items: Arc::clone(&self.items),
            review_history: self.review_history.clone(),
            retained_context: Arc::clone(&self.retained_context),
            guardian_context_mode: self.guardian_context_mode,
            history_version: self.history_version,
            user_message_revision: self.user_message_revision,
        })
    }

    pub(crate) fn retained_context(&self) -> &RetainedContext {
        &self.retained_context
    }

    pub(crate) fn with_guardian_context_mode(
        guardian_context_mode: GuardianContextMode,
        source: &SessionSource,
    ) -> Self {
        Self {
            guardian_context_mode,
            retain_inherited_user_messages: guardian_context_mode
                == GuardianContextMode::ThreadOwned
                && !source.is_non_root_agent(),
            ..Self::new()
        }
    }

    pub(crate) fn reserve_input_order(&mut self) -> u64 {
        Arc::make_mut(&mut self.retained_context).reserve_order()
    }

    pub(crate) fn record_retained_context(&mut self, event: &RetainedContextEvent) -> bool {
        if !Arc::make_mut(&mut self.retained_context).record(event) {
            return false;
        }
        self.user_message_revision = self.user_message_revision.saturating_add(1);
        true
    }

    pub(crate) fn guardian_history_checkpoint(&self) -> Option<GuardianHistoryCheckpoint> {
        if self.guardian_context_mode == GuardianContextMode::ThreadOwned {
            return None;
        }
        self.review_history
            .as_ref()
            .map(|history| GuardianHistoryCheckpoint(history.items().cloned().collect()))
    }

    pub(crate) fn restore_review_context(
        &mut self,
        retained_context: Option<&RetainedContext>,
        checkpoint: Option<&GuardianHistoryCheckpoint>,
    ) {
        self.restore_retained_context(retained_context);
        if self.guardian_context_mode == GuardianContextMode::ThreadOwned {
            // Older retained checkpoints cleared oversized instructions. Recover their
            // bounded root excerpts before discarding the legacy source transcript.
            let items = &self.items;
            Arc::make_mut(&mut self.retained_context).recover_user_message_excerpts(|id| {
                // Prefer the backup over a compacted copy that retains the original ID.
                let original = checkpoint
                    .into_iter()
                    .flat_map(|checkpoint| &checkpoint.0)
                    .chain(items.iter().map(|envelope| &envelope.item))
                    .find(|item| item.id().is_some_and(|item_id| item_id.as_str() == id));
                let Some(TurnItem::UserMessage(original)) = original.and_then(parse_turn_item)
                else {
                    return None;
                };
                Some(
                    guardian_truncate_text(&original.message(), GUARDIAN_MAX_ROOT_MESSAGE_TOKENS).0,
                )
            });
            self.review_history = None;
            return;
        }
        let generation = self
            .review_history
            .as_ref()
            .map_or(self.history_version, TranscriptHistory::generation)
            .saturating_add(1);
        self.review_history = checkpoint.map(|checkpoint| {
            let mut history = TranscriptHistory::new(generation);
            history.reset(checkpoint.0.iter());
            history
        });
    }

    pub(crate) fn token_info(&self) -> Option<TokenUsageInfo> {
        self.token_info.clone()
    }

    pub(crate) fn set_token_info(&mut self, info: Option<TokenUsageInfo>) {
        self.token_info = info;
    }

    pub(crate) fn set_reference_context_item(&mut self, item: Option<TurnContextItem>) {
        self.reference_context_item = item;
    }

    pub(crate) fn reference_context_item(&self) -> Option<TurnContextItem> {
        self.reference_context_item.clone()
    }

    pub(crate) fn update_world_state(
        &mut self,
        world_state: &WorldState,
    ) -> (Vec<Box<dyn ContextualUserFragment>>, Option<WorldStateItem>) {
        let snapshot = world_state.snapshot();
        let fragments =
            world_state.render_history_diff(self.world_state_baseline.as_ref(), self.raw_items());
        let rollout_item = self.world_state_baseline.as_ref().map_or_else(
            || Some(WorldStateItem::full(snapshot.clone().into_object())),
            |previous| {
                snapshot
                    .merge_patch_from(previous)
                    .map(WorldStateItem::patch)
            },
        );
        self.world_state_baseline = Some(snapshot);
        (fragments, rollout_item)
    }

    pub(crate) fn set_world_state_baseline(&mut self, snapshot: WorldStateSnapshot) {
        self.world_state_baseline = Some(snapshot);
    }

    pub(crate) fn set_token_usage_full(&mut self, context_window: i64) {
        match &mut self.token_info {
            Some(info) => info.fill_to_context_window(context_window),
            None => {
                self.token_info = Some(TokenUsageInfo::full_context_window(context_window));
            }
        }
    }

    /// `items` is ordered from oldest to newest.
    pub(crate) fn record_items<I>(&mut self, items: I, policy: TruncationPolicy)
    where
        I: IntoIterator,
        I::Item: Deref<Target = ResponseItem>,
    {
        self.record_items_with_metadata(items.into_iter().map(|item| (item, None)), policy);
    }

    /// Records output while preserving its history-only metadata.
    pub(crate) fn record_annotated_items(
        &mut self,
        items: &[ResponseItemEnvelope],
        policy: TruncationPolicy,
    ) {
        self.record_items_with_metadata(
            items
                .iter()
                .map(|envelope| (&envelope.item, envelope.metadata.as_ref())),
            policy,
        );
    }

    fn record_items_with_metadata<'a, I, T>(&mut self, items: I, policy: TruncationPolicy)
    where
        I: IntoIterator<Item = (T, Option<&'a CodexHarnessMetadata>)>,
        T: Deref<Target = ResponseItem>,
    {
        for (item, metadata) in items {
            let item = item.deref();
            if !is_api_message(item, metadata) {
                continue;
            }

            let pair_key = tool_pair_key(item);
            if pair_key
                .as_ref()
                .is_some_and(|key| self.omitted_tool_pairs.remove(key))
            {
                continue;
            }

            let processed = Self::process_item(item, metadata, policy);
            if processed.is_empty() {
                Self::record_omitted_pair(
                    Arc::make_mut(&mut self.items),
                    &mut self.omitted_tool_pairs,
                    self.review_history.as_mut(),
                    item,
                    pair_key,
                );
                continue;
            }
            if let Some(review_history) = &mut self.review_history
                && is_projectable_message(item)
                && !is_contextual_user_item(item)
            {
                review_history.record(item);
            }
            for processed in processed {
                if let Some(review_history) = &mut self.review_history
                    && !is_projectable_message(item)
                {
                    review_history.record(&processed.item);
                }
                Arc::make_mut(&mut self.items).push(processed);
            }
            self.record_user_authorization(
                item,
                metadata,
                user_authorization::UserMessageSource::Original,
            );
        }
    }

    /// Returns the history prepared for sending to the model. This applies a proper
    /// normalization and drops un-suited items. Unsupported image and audio content
    /// is stripped from messages and tool outputs according to `input_modalities`.
    pub(crate) fn for_prompt(self, input_modalities: &[InputModality]) -> Vec<ResponseItem> {
        self.for_prompt_annotated(input_modalities)
            .into_iter()
            .map(ResponseItemEnvelope::into_item)
            .collect()
    }

    /// Returns normalized history envelopes for internal consumers that must retain metadata.
    pub(crate) fn for_prompt_annotated(
        mut self,
        input_modalities: &[InputModality],
    ) -> Vec<ResponseItemEnvelope> {
        self.normalize_history(input_modalities);
        let normalized = Arc::unwrap_or_clone(self.items);
        Self::bound_replacement_items(normalized).0
    }

    /// Iterates over raw response items without exposing their history envelopes.
    pub(crate) fn raw_items(
        &self,
    ) -> impl Clone + ExactSizeIterator<Item = &ResponseItem> + DoubleEndedIterator {
        self.items.iter().map(|envelope| &envelope.item)
    }

    /// Returns annotated history items without cloning their response payloads.
    pub(crate) fn annotated_items(&self) -> &[ResponseItemEnvelope] {
        &self.items
    }

    pub(crate) fn logical_items(&self) -> Vec<ResponseItem> {
        logical_items(&self.items)
    }

    pub(crate) fn logical_annotated_items(&self) -> Vec<ResponseItemEnvelope> {
        logical_envelopes(&self.items)
    }

    /// Returns raw items in the history and consumes the snapshot.
    pub(crate) fn into_raw_items(self) -> Vec<ResponseItem> {
        self.into_annotated_items()
            .into_iter()
            .map(ResponseItemEnvelope::into_item)
            .collect()
    }

    /// Returns annotated history items and consumes the snapshot.
    pub(crate) fn into_annotated_items(self) -> Vec<ResponseItemEnvelope> {
        Arc::unwrap_or_clone(self.items)
    }

    pub(crate) fn history_version(&self) -> u64 {
        self.history_version
    }

    // Estimate token usage using byte-based heuristics from the truncation helpers.
    // This is a coarse lower bound, not a tokenizer-accurate count.
    pub(crate) fn estimate_token_count(&self, turn_context: &TurnContext) -> Option<i64> {
        let model_info = &turn_context.model_info();
        let personality = turn_context
            .personality()
            .or(turn_context.config.personality);
        let base_instructions = BaseInstructions {
            text: model_info.get_model_instructions(personality),
            provenance: None,
        };
        self.estimate_token_count_with_base_instructions(&base_instructions)
    }

    pub(crate) fn estimate_token_count_with_base_instructions(
        &self,
        base_instructions: &BaseInstructions,
    ) -> Option<i64> {
        let base_tokens =
            i64::try_from(approx_token_count(&base_instructions.text)).unwrap_or(i64::MAX);

        let items_tokens = self
            .items
            .iter()
            .map(|envelope| estimate_item_token_count(&envelope.item))
            .fold(0i64, i64::saturating_add);

        Some(base_tokens.saturating_add(items_tokens))
    }

    pub(crate) fn remove_first_item(&mut self) {
        if !self.items.is_empty() {
            // Remove the oldest item (front of the list). Items are ordered from
            // oldest → newest, so index 0 is the first entry recorded.
            let items = Arc::make_mut(&mut self.items);
            let removed = items.remove(0);
            // If the removed item participates in a call/output pair, also remove
            // its corresponding counterpart to keep the invariants intact without
            // running a full normalization pass.
            let _ = normalize::remove_corresponding_for(items, &removed.item);
            if is_projectable_message(&removed.item)
                && removed
                    .metadata
                    .as_ref()
                    .is_some_and(|metadata| metadata.projected_content_indices.is_some())
            {
                while items.first().is_some_and(|envelope| {
                    envelope
                        .metadata
                        .as_ref()
                        .is_some_and(|metadata| metadata.history_only_continuation)
                }) {
                    items.remove(0);
                }
            }
            self.world_state_baseline = None;
        }
    }

    #[cfg(test)]
    pub(crate) fn replace(&mut self, items: Vec<ResponseItem>) {
        self.replace_annotated(items.into_iter().map(ResponseItemEnvelope::new).collect());
    }

    pub(crate) fn replace_annotated(&mut self, items: Vec<ResponseItemEnvelope>) {
        self.retained_context = Arc::default();
        self.user_message_revision = self.user_message_revision.saturating_add(1);
        let (items, omitted_tool_pairs) = Self::bound_replacement_items(items);
        self.omitted_tool_pairs = omitted_tool_pairs;
        if let Some(review_history) = &mut self.review_history {
            let logical_items = logical_items(&items);
            review_history.reset(
                logical_items
                    .iter()
                    .filter(|item| !is_contextual_user_item(item)),
            );
        }
        self.items = Arc::new(items);
        self.history_version = self.history_version.saturating_add(1);
        self.world_state_baseline = None;
    }

    /// Compaction changes the model's history without changing the user's authorization.
    pub(crate) fn replace_compacted(&mut self, items: Vec<ResponseItemEnvelope>) {
        if self.guardian_context_mode == GuardianContextMode::Legacy
            && self.review_history.is_none()
        {
            let mut retained = TranscriptHistory::new(self.history_version.saturating_add(1));
            for item in logical_items(&self.items)
                .iter()
                .filter(|item| !is_contextual_user_item(item))
            {
                retained.record(item);
            }
            self.review_history = Some(retained);
        }
        let (items, omitted_tool_pairs) = Self::bound_replacement_items(items);
        self.omitted_tool_pairs = omitted_tool_pairs;
        self.items = Arc::new(items);
        self.history_version = self.history_version.saturating_add(1);
        self.world_state_baseline = None;
    }

    /// Drop the last `num_turns` instruction turns from this history.
    ///
    /// Instruction turns are history messages that should behave like a new prompt boundary:
    /// ordinary user messages and structured assistant inter-agent instructions.
    ///
    /// This mirrors thread-rollback semantics:
    /// - `num_turns == 0` is a no-op
    /// - if there are no user turns, this is a no-op
    /// - if `num_turns` exceeds the number of user turns, all user turns are dropped while
    ///   preserving any items that occurred before the first user message.
    ///
    /// If rollback trims a pre-turn developer message that mixes contextual fragments with
    /// persistent developer text from `build_initial_context`, this also clears
    /// `reference_context_item`. The surviving history no longer contains the full bundle that
    /// established the prior baseline, so future turns must fall back to full reinjection instead
    /// of diffing against stale state.
    pub(crate) fn drop_last_n_user_turns(&mut self, num_turns: u32) {
        if num_turns == 0 {
            return;
        }

        let snapshot = self.items.clone();
        let user_positions = user_message_positions(&snapshot);
        let Some(&first_instruction_turn_idx) = user_positions.first() else {
            let retained_context = Arc::clone(&self.retained_context);
            self.replace_annotated(Arc::unwrap_or_clone(snapshot));
            self.retained_context = retained_context;
            return;
        };

        let n_from_end = usize::try_from(num_turns).unwrap_or(usize::MAX);
        let mut cut_idx = if n_from_end >= user_positions.len() {
            first_instruction_turn_idx
        } else {
            user_positions[user_positions.len() - n_from_end]
        };

        let first_removed_message_id = snapshot[cut_idx]
            .id()
            .map(codex_protocol::ResponseItemId::as_str);
        let rolled_back_turn_id = snapshot[cut_idx].turn_id().map(str::to_owned);
        let source = RetainedInputSource::from(snapshot[cut_idx].metadata.as_ref());
        let mut review_history = self.review_history.take();
        if let Some(history) = &mut review_history {
            history.truncate_before(&snapshot[cut_idx].item);
        }

        cut_idx =
            self.trim_pre_turn_context_updates(&snapshot, first_instruction_turn_idx, cut_idx);

        let mut retained_items = snapshot[..cut_idx].to_vec();
        if let Some(rolled_back_turn_id) = rolled_back_turn_id
            && !retained_items.iter().any(|item| {
                item.turn_id() == Some(rolled_back_turn_id.as_str())
                    && is_history_turn_boundary(item)
            })
        {
            retained_items.retain_mut(|item| {
                if item.turn_id() == Some(rolled_back_turn_id.as_str())
                    && matches!(&item.item, ResponseItem::Message { role, .. } if role == "developer")
                {
                    let projected_content_indices = item
                        .metadata
                        .as_ref()
                        .and_then(|metadata| metadata.projected_content_indices.as_ref())
                        .cloned();
                    let Some(mut content) = to_annotated_content(&mut item.item) else {
                        return false;
                    };
                    let mut retained_indices = Vec::with_capacity(content.len());
                    let original_content_len = content.len();
                    let mut content_index = 0;
                    content.retain(|content| {
                        // Rebuild these from the next step's model and effort after rollback.
                        let retain = !is_rolled_back_model_context_fragment(content);
                        if retain
                            && let Some(projected_index) = projected_content_indices
                                .as_ref()
                                .filter(|indices| indices.len() == original_content_len)
                                .and_then(|indices| indices.get(content_index))
                        {
                            retained_indices.push(*projected_index);
                        }
                        content_index += 1;
                        retain
                    });
                    if projected_content_indices
                        .as_ref()
                        .is_some_and(|indices| indices.len() == original_content_len)
                        && let Some(metadata) = &mut item.metadata
                    {
                        metadata.projected_content_indices = Some(retained_indices);
                    }
                    !content.is_empty() && set_annotated_content(&mut item.item, content).is_some()
                } else {
                    true
                }
            });
        }

        let mut retained_context = Arc::clone(&self.retained_context);
        let removed_turns = snapshot[cut_idx..]
            .iter()
            .filter_map(|item| item.turn_id())
            .collect::<Vec<_>>();
        if self.guardian_context_mode == GuardianContextMode::ThreadOwned {
            Arc::make_mut(&mut retained_context).rollback(
                &removed_turns,
                first_removed_message_id,
                source,
            );
        } else {
            Arc::make_mut(&mut retained_context).retain_answers(|answer| {
                // Legacy answers follow their original call, not later steers in the same turn.
                if let Some(source_index) = snapshot.iter().rposition(|item| {
                    item.turn_id() == Some(answer.turn_id.as_str())
                        && matches!(&item.item, ResponseItem::FunctionCall { call_id, .. }
                            if call_id == &answer.call_id)
                }) {
                    return source_index < cut_idx;
                }
                !removed_turns.contains(&answer.turn_id.as_str())
            });
        }
        self.replace_annotated(retained_items);
        self.retained_context = retained_context;
        self.review_history = review_history;
    }

    pub(crate) fn update_token_info(
        &mut self,
        usage: &TokenUsage,
        model_context_window: Option<i64>,
    ) {
        self.token_info = TokenUsageInfo::new_or_append(
            &self.token_info,
            &Some(usage.clone()),
            model_context_window,
        );
    }

    fn get_non_last_reasoning_items_tokens(&self) -> i64 {
        // Get reasoning items excluding all the ones after the last instruction boundary.
        let Some(last_user_index) = self.items.iter().rposition(is_history_turn_boundary) else {
            return 0;
        };

        self.items
            .iter()
            .take(last_user_index)
            .filter(|envelope| {
                matches!(
                    &envelope.item,
                    ResponseItem::Reasoning {
                        encrypted_content: Some(_),
                        ..
                    }
                )
            })
            .map(|envelope| estimate_item_token_count(&envelope.item))
            .fold(0i64, i64::saturating_add)
    }

    // These are local items added after the most recent model-emitted item.
    // They are not reflected in `last_token_usage.total_tokens`.
    fn items_after_last_model_generated_item(
        &self,
    ) -> impl Clone + ExactSizeIterator<Item = &ResponseItem> + DoubleEndedIterator {
        let start = self
            .items
            .iter()
            .rposition(|envelope| is_model_generated_item(&envelope.item))
            .map_or(self.items.len(), |index| index.saturating_add(1));
        self.items[start..].iter().map(|envelope| &envelope.item)
    }

    /// When true, the server already accounted for past reasoning tokens and
    /// the client should not re-estimate them.
    pub(crate) fn get_total_token_usage(&self, server_reasoning_included: bool) -> i64 {
        let last_tokens = self
            .token_info
            .as_ref()
            .map(|info| info.last_token_usage.total_tokens)
            .unwrap_or(0);
        let items_after_last_model_generated_tokens = self
            .items_after_last_model_generated_item()
            .map(estimate_item_token_count)
            .fold(0i64, i64::saturating_add);
        if server_reasoning_included {
            last_tokens.saturating_add(items_after_last_model_generated_tokens)
        } else {
            last_tokens
                .saturating_add(self.get_non_last_reasoning_items_tokens())
                .saturating_add(items_after_last_model_generated_tokens)
        }
    }

    pub(crate) fn estimated_tokens_after_last_model_generated_item(&self) -> i64 {
        self.items_after_last_model_generated_item()
            .map(estimate_item_token_count)
            .fold(0i64, i64::saturating_add)
    }

    /// This function enforces a couple of invariants on the in-memory history:
    /// 1. every call (function/custom) has a corresponding output entry
    /// 2. every output has a corresponding call entry or names an external tool event
    /// 3. unsupported image and audio content is stripped from messages and tool outputs
    fn normalize_history(&mut self, input_modalities: &[InputModality]) {
        let items = Arc::make_mut(&mut self.items);

        // all function/tool calls must have a corresponding output
        normalize::ensure_call_outputs_present(items);

        // Paired outputs must have a corresponding call; named external outputs stand alone.
        normalize::remove_orphan_outputs(items);

        // strip images when model does not support them
        normalize::strip_images_when_unsupported(input_modalities, items);

        // strip audio when model does not support it
        normalize::strip_audio_when_unsupported(input_modalities, items);
    }

    fn process_item(
        item: &ResponseItem,
        metadata: Option<&CodexHarnessMetadata>,
        policy: TruncationPolicy,
    ) -> Vec<ResponseItemEnvelope> {
        match item {
            ResponseItem::Message { .. } => return project_message(item, metadata),
            ResponseItem::AgentMessage { .. } => return project_agent_message(item, metadata),
            _ => {}
        }
        let mut processed = ResponseItemEnvelope {
            item: item.clone(),
            metadata: metadata.cloned(),
        };
        let original_output = match item {
            ResponseItem::FunctionCallOutput { output, .. }
            | ResponseItem::CustomToolCallOutput { output, .. } => Some(output),
            _ => None,
        };
        let Some(original_output) = original_output else {
            return model_visible_item_fits(&processed.item)
                .then_some(processed)
                .into_iter()
                .collect();
        };

        // The saved override already includes the tool's serialization allowance. Both it and
        // the model default remain subordinate to the hard per-item context ceiling.
        let configured_policy = metadata
            .and_then(|metadata| metadata.history_truncation_token_limit)
            .map(TruncationPolicy::Tokens)
            .unwrap_or_else(|| with_serialization_allowance(policy));
        let mut effective_policy = match configured_policy {
            TruncationPolicy::Bytes(bytes) => {
                TruncationPolicy::Bytes(bytes.min(MODEL_VISIBLE_ITEM_MAX_BYTES))
            }
            TruncationPolicy::Tokens(tokens) => {
                TruncationPolicy::Tokens(tokens.min(MODEL_VISIBLE_ITEM_MAX_TOKENS))
            }
        };

        for _ in 0..4 {
            let output = match &mut processed.item {
                ResponseItem::FunctionCallOutput { output, .. }
                | ResponseItem::CustomToolCallOutput { output, .. } => output,
                _ => unreachable!("tool output variant changed while truncating history"),
            };
            *output = original_output.clone();
            truncate_function_output_payload(output, effective_policy, estimate_audio_token_count);

            if serialized_json_bytes(&processed.item).is_err() {
                return Vec::new();
            }
            let model_visible_bytes = estimate_response_item_model_visible_bytes(&processed.item);
            let estimated_tokens = estimate_item_token_count(&processed.item);
            let max_bytes = i64::try_from(MODEL_VISIBLE_ITEM_MAX_BYTES).unwrap_or(i64::MAX);
            let max_tokens = i64::try_from(MODEL_VISIBLE_ITEM_MAX_TOKENS).unwrap_or(i64::MAX);
            if model_visible_bytes <= max_bytes && estimated_tokens <= max_tokens {
                return vec![processed];
            }
            let model_visible_excess_bytes = usize::try_from(
                model_visible_bytes
                    .saturating_sub(max_bytes)
                    .saturating_add(1),
            )
            .unwrap_or(usize::MAX);
            let estimated_excess_tokens = usize::try_from(
                estimated_tokens
                    .saturating_sub(max_tokens)
                    .saturating_add(1),
            )
            .unwrap_or(usize::MAX);
            let excess_bytes =
                model_visible_excess_bytes.max(approx_bytes_for_tokens(estimated_excess_tokens));
            let reduced_policy = match effective_policy {
                TruncationPolicy::Bytes(bytes) => {
                    TruncationPolicy::Bytes(bytes.saturating_sub(excess_bytes))
                }
                TruncationPolicy::Tokens(tokens) => {
                    TruncationPolicy::Tokens(tokens.saturating_sub(excess_bytes.div_ceil(4)))
                }
            };
            if reduced_policy == effective_policy {
                break;
            }
            effective_policy = reduced_policy;
        }

        // Identifiers, names, passthrough metadata, and untruncatable structured payloads count
        // too. Never rewrite them into a synthetic model-visible history item.
        model_visible_item_fits(&processed.item)
            .then_some(processed)
            .into_iter()
            .collect()
    }

    fn record_omitted_pair(
        items: &mut Vec<ResponseItemEnvelope>,
        omitted_tool_pairs: &mut HashSet<ToolPairKey>,
        review_history: Option<&mut TranscriptHistory>,
        item: &ResponseItem,
        pair_key: Option<ToolPairKey>,
    ) {
        let Some(mut pair_key) = pair_key else {
            return;
        };
        let removed = normalize::remove_corresponding_for(items, item);
        if let Some(removed) = removed {
            if let Some(review_history) = review_history {
                let mut removed_from_review = false;
                let retained = review_history
                    .items()
                    .filter(|review_item| {
                        if !removed_from_review && *review_item == &removed.item {
                            removed_from_review = true;
                            false
                        } else {
                            true
                        }
                    })
                    .cloned()
                    .collect::<Vec<_>>();
                if removed_from_review {
                    review_history.reset(retained.iter());
                }
            }
        } else {
            pair_key.side = match pair_key.side {
                ToolPairSide::Call => ToolPairSide::Output,
                ToolPairSide::Output => ToolPairSide::Call,
            };
            omitted_tool_pairs.insert(pair_key);
        }
    }

    fn bound_replacement_items(
        items: Vec<ResponseItemEnvelope>,
    ) -> (Vec<ResponseItemEnvelope>, HashSet<ToolPairKey>) {
        let mut bounded = Vec::with_capacity(items.len());
        let mut omitted_tool_pairs = HashSet::new();
        for envelope in items {
            let pair_key = tool_pair_key(&envelope.item);
            if pair_key
                .as_ref()
                .is_some_and(|key| omitted_tool_pairs.remove(key))
            {
                continue;
            }
            let processed = Self::process_item(
                &envelope.item,
                envelope.metadata.as_ref(),
                TruncationPolicy::Tokens(MODEL_VISIBLE_ITEM_MAX_TOKENS),
            );
            if processed.is_empty() {
                Self::record_omitted_pair(
                    &mut bounded,
                    &mut omitted_tool_pairs,
                    /*review_history*/ None,
                    &envelope.item,
                    pair_key,
                );
            } else {
                bounded.extend(processed);
            }
        }
        (bounded, omitted_tool_pairs)
    }

    /// Walk backward from a rollback cut and trim contiguous pre-turn context-update items.
    ///
    /// Returns the adjusted cut index after removing contextual developer/user items immediately
    /// above the rolled-back turn boundary.
    ///
    /// `first_instruction_turn_idx` is the earliest rollback-eligible instruction-turn boundary
    /// in `snapshot`; the trim walk never crosses it so any session-prefix items that predate the
    /// first real turn survive rollback.
    ///
    /// `cut_idx` is the tentative slice boundary after dropping the requested number of
    /// instruction turns, before stripping contextual pre-turn items that sit immediately above
    /// that boundary.
    ///
    /// If any trimmed developer message was a mixed `build_initial_context` bundle containing both
    /// rollback-trimmable contextual fragments and persistent developer text, this also clears the
    /// stored `reference_context_item` baseline so the next real turn falls back to full
    /// reinjection.
    fn trim_pre_turn_context_updates(
        &mut self,
        snapshot: &[ResponseItemEnvelope],
        first_instruction_turn_idx: usize,
        mut cut_idx: usize,
    ) -> usize {
        while cut_idx > first_instruction_turn_idx {
            match &snapshot[cut_idx - 1].item {
                ResponseItem::Message { role, content, .. }
                    if role == "developer" && is_contextual_dev_message_content(content) =>
                {
                    if has_non_contextual_dev_message_content(content) {
                        // Mixed `build_initial_context` bundles are not reconstructible from
                        // steady-state diffs once trimmed, so the next real turn must fully
                        // reinject context instead of diffing against a stale baseline.
                        self.reference_context_item = None;
                    }
                    cut_idx -= 1;
                }
                item if is_contextual_user_item(item) => {
                    cut_idx -= 1;
                }
                _ => break,
            }
        }
        cut_idx
    }
}

fn is_rolled_back_model_context_fragment(content: &AnnotatedContent) -> bool {
    match content.kind().0.as_str() {
        "model_switch.instructions" | "persistent_mode.instructions" => true,
        "" | "unknown" => {
            let ContentItem::InputText { text } = content.content() else {
                return false;
            };
            let text = text.trim_start();
            ["<model_switch>", "<persistent_mode>"]
                .iter()
                .any(|prefix| {
                    text.get(..prefix.len())
                        .is_some_and(|candidate| candidate.eq_ignore_ascii_case(prefix))
                })
        }
        _ => false,
    }
}

fn serialized_item_fits(item: &ResponseItem) -> bool {
    serialized_json_bytes(item).is_ok_and(|bytes| bytes <= MODEL_VISIBLE_ITEM_MAX_BYTES)
}

fn model_visible_item_fits(item: &ResponseItem) -> bool {
    serialized_item_fits(item)
        && estimate_item_token_count(item)
            <= i64::try_from(MODEL_VISIBLE_ITEM_MAX_TOKENS).unwrap_or(i64::MAX)
}

fn is_projectable_message(item: &ResponseItem) -> bool {
    matches!(
        item,
        ResponseItem::Message { .. } | ResponseItem::AgentMessage { .. }
    )
}

fn project_message(
    item: &ResponseItem,
    metadata: Option<&CodexHarnessMetadata>,
) -> Vec<ResponseItemEnvelope> {
    let ResponseItem::Message {
        id,
        role,
        content,
        phase,
        internal_chat_message_metadata_passthrough,
    } = item
    else {
        unreachable!("project_message requires a message item");
    };
    let max_tokens = i64::try_from(MODEL_VISIBLE_ITEM_MAX_TOKENS).unwrap_or(i64::MAX);
    if estimate_item_token_count(item) <= max_tokens {
        return vec![ResponseItemEnvelope {
            item: item.clone(),
            metadata: metadata.cloned(),
        }];
    }

    let is_contextual_user = is_contextual_user_item(item);
    let original_boundary = metadata
        .and_then(|metadata| metadata.turn_boundary_override)
        .unwrap_or_else(|| {
            if role == "user" {
                !is_contextual_user
            } else {
                is_user_turn_boundary(item)
            }
        });
    let already_continuation = metadata.is_some_and(|metadata| metadata.history_only_continuation);
    let source_indices = metadata.and_then(|metadata| metadata.projected_content_indices.as_ref());
    let make_envelope = |indexed_content: Vec<(ContentItem, usize)>, chunk_index: usize| {
        let mut chunk_metadata = metadata.cloned().unwrap_or_default();
        chunk_metadata.turn_boundary_override =
            Some(chunk_index == 0 && original_boundary && !already_continuation);
        chunk_metadata.history_only_continuation = already_continuation || chunk_index != 0;
        chunk_metadata.projected_content_indices = Some(
            indexed_content
                .iter()
                .map(|(_, original_index)| *original_index)
                .collect(),
        );
        let mut item_metadata = internal_chat_message_metadata_passthrough.clone();
        if let Some(item_metadata) = &mut item_metadata
            && let Some(kinds) = &internal_chat_message_metadata_passthrough
                .as_ref()
                .and_then(|metadata| metadata.content_item_kinds.as_ref())
            && kinds.len() == content.len()
        {
            item_metadata.content_item_kinds = Some(
                indexed_content
                    .iter()
                    .map(|(_, original_index)| {
                        let kind_index = source_indices
                            .and_then(|indices| {
                                indices.iter().position(|index| index == original_index)
                            })
                            .unwrap_or(*original_index);
                        kinds[kind_index].clone()
                    })
                    .collect(),
            );
        }
        ResponseItemEnvelope {
            item: ResponseItem::Message {
                id: (chunk_index == 0).then(|| id.clone()).flatten(),
                role: role.clone(),
                content: indexed_content
                    .into_iter()
                    .map(|(content, _)| content)
                    .collect(),
                phase: phase.clone(),
                internal_chat_message_metadata_passthrough: item_metadata,
            },
            metadata: Some(chunk_metadata),
        }
    };

    let mut chunks = Vec::new();
    let mut current = Vec::new();
    for (content_index, content_item) in content.iter().enumerate() {
        let source_index = source_indices
            .and_then(|indices| indices.get(content_index))
            .copied()
            .unwrap_or(content_index);
        if is_contextual_user {
            let chunk_index = chunks.len();
            let mut candidate = current.clone();
            candidate.push((content_item.clone(), source_index));
            if estimate_item_token_count(&make_envelope(candidate.clone(), chunk_index).item)
                <= max_tokens
            {
                current = candidate;
                continue;
            }
            if !current.is_empty() {
                chunks.push(make_envelope(std::mem::take(&mut current), chunk_index));
            }
            let chunk_index = chunks.len();
            let candidate = vec![(content_item.clone(), source_index)];
            if estimate_item_token_count(&make_envelope(candidate.clone(), chunk_index).item)
                > max_tokens
            {
                return Vec::new();
            }
            current = candidate;
            continue;
        }
        match content_item {
            ContentItem::InputText { text } | ContentItem::OutputText { text } => {
                let is_input = matches!(content_item, ContentItem::InputText { .. });
                if text.is_empty() {
                    let chunk_index = chunks.len();
                    let mut candidate = current.clone();
                    candidate.push((content_item.clone(), source_index));
                    if estimate_item_token_count(
                        &make_envelope(candidate.clone(), chunk_index).item,
                    ) <= max_tokens
                    {
                        current = candidate;
                        continue;
                    }
                    if !current.is_empty() {
                        chunks.push(make_envelope(std::mem::take(&mut current), chunk_index));
                    }
                    let chunk_index = chunks.len();
                    let candidate = vec![(content_item.clone(), source_index)];
                    if estimate_item_token_count(
                        &make_envelope(candidate.clone(), chunk_index).item,
                    ) > max_tokens
                    {
                        return Vec::new();
                    }
                    current = candidate;
                    continue;
                }
                let mut remaining = text.as_str();
                while !remaining.is_empty() {
                    let chunk_index = chunks.len();
                    let mut boundaries = remaining
                        .char_indices()
                        .map(|(index, _)| index)
                        .skip(1)
                        .collect::<Vec<_>>();
                    boundaries.push(remaining.len());
                    let mut low = 0;
                    let mut high = boundaries.len();
                    while low < high {
                        let mid = low + (high - low).div_ceil(2);
                        let prefix = &remaining[..boundaries[mid - 1]];
                        let mut candidate = current.clone();
                        candidate.push((
                            if is_input {
                                ContentItem::InputText {
                                    text: prefix.to_string(),
                                }
                            } else {
                                ContentItem::OutputText {
                                    text: prefix.to_string(),
                                }
                            },
                            source_index,
                        ));
                        if estimate_item_token_count(&make_envelope(candidate, chunk_index).item)
                            <= max_tokens
                        {
                            low = mid;
                        } else {
                            high = mid - 1;
                        }
                    }
                    if low == 0 {
                        if current.is_empty() {
                            return Vec::new();
                        }
                        chunks.push(make_envelope(std::mem::take(&mut current), chunk_index));
                        continue;
                    }
                    let split_at = boundaries[low - 1];
                    current.push((
                        if is_input {
                            ContentItem::InputText {
                                text: remaining[..split_at].to_string(),
                            }
                        } else {
                            ContentItem::OutputText {
                                text: remaining[..split_at].to_string(),
                            }
                        },
                        source_index,
                    ));
                    remaining = &remaining[split_at..];
                    if !remaining.is_empty() {
                        chunks.push(make_envelope(std::mem::take(&mut current), chunk_index));
                    }
                }
            }
            ContentItem::InputImage { .. } | ContentItem::InputAudio { .. } => {
                let chunk_index = chunks.len();
                let mut candidate = current.clone();
                candidate.push((content_item.clone(), source_index));
                if estimate_item_token_count(&make_envelope(candidate.clone(), chunk_index).item)
                    <= max_tokens
                {
                    current = candidate;
                    continue;
                }
                if !current.is_empty() {
                    chunks.push(make_envelope(std::mem::take(&mut current), chunk_index));
                }
                let chunk_index = chunks.len();
                let candidate = vec![(content_item.clone(), source_index)];
                if estimate_item_token_count(&make_envelope(candidate.clone(), chunk_index).item)
                    > max_tokens
                {
                    return Vec::new();
                }
                current = candidate;
            }
        }
    }
    if !current.is_empty() || content.is_empty() {
        chunks.push(make_envelope(current, chunks.len()));
    }
    if chunks
        .iter()
        .any(|envelope| estimate_item_token_count(&envelope.item) > max_tokens)
        || (is_contextual_user
            && chunks.iter().any(|envelope| {
                !matches!(&envelope.item, ResponseItem::Message { content, .. }
                    if is_contextual_user_message_content(content))
            }))
    {
        return Vec::new();
    }
    chunks
}

fn project_agent_message(
    item: &ResponseItem,
    metadata: Option<&CodexHarnessMetadata>,
) -> Vec<ResponseItemEnvelope> {
    let ResponseItem::AgentMessage {
        id,
        author,
        recipient,
        content,
        internal_chat_message_metadata_passthrough,
    } = item
    else {
        unreachable!("project_agent_message requires an agent message item");
    };
    let max_tokens = i64::try_from(MODEL_VISIBLE_ITEM_MAX_TOKENS).unwrap_or(i64::MAX);
    if estimate_item_token_count(item) <= max_tokens {
        return vec![ResponseItemEnvelope {
            item: item.clone(),
            metadata: metadata.cloned(),
        }];
    }

    let original_boundary = metadata
        .and_then(|metadata| metadata.turn_boundary_override)
        .unwrap_or(true);
    let already_continuation = metadata.is_some_and(|metadata| metadata.history_only_continuation);
    let source_indices = metadata.and_then(|metadata| metadata.projected_content_indices.as_ref());
    let make_envelope = |indexed_content: Vec<(AgentMessageInputContent, usize)>,
                         chunk_index: usize| {
        let mut chunk_metadata = metadata.cloned().unwrap_or_default();
        chunk_metadata.turn_boundary_override =
            Some(chunk_index == 0 && original_boundary && !already_continuation);
        chunk_metadata.history_only_continuation = already_continuation || chunk_index != 0;
        chunk_metadata.projected_content_indices = Some(
            indexed_content
                .iter()
                .map(|(_, original_index)| *original_index)
                .collect(),
        );
        let mut item_metadata = internal_chat_message_metadata_passthrough.clone();
        if let Some(item_metadata) = &mut item_metadata
            && let Some(kinds) = &internal_chat_message_metadata_passthrough
                .as_ref()
                .and_then(|metadata| metadata.content_item_kinds.as_ref())
            && kinds.len() == content.len()
        {
            item_metadata.content_item_kinds = Some(
                indexed_content
                    .iter()
                    .map(|(_, original_index)| {
                        let kind_index = source_indices
                            .and_then(|indices| {
                                indices.iter().position(|index| index == original_index)
                            })
                            .unwrap_or(*original_index);
                        kinds[kind_index].clone()
                    })
                    .collect(),
            );
        }
        ResponseItemEnvelope {
            item: ResponseItem::AgentMessage {
                id: (chunk_index == 0).then(|| id.clone()).flatten(),
                author: author.clone(),
                recipient: recipient.clone(),
                content: indexed_content
                    .into_iter()
                    .map(|(content, _)| content)
                    .collect(),
                internal_chat_message_metadata_passthrough: item_metadata,
            },
            metadata: Some(chunk_metadata),
        }
    };

    let mut chunks = Vec::new();
    let mut current = Vec::new();
    for (content_index, content_item) in content.iter().enumerate() {
        let source_index = source_indices
            .and_then(|indices| indices.get(content_index))
            .copied()
            .unwrap_or(content_index);
        match content_item {
            AgentMessageInputContent::InputText { text } if !text.is_empty() => {
                let mut remaining = text.as_str();
                while !remaining.is_empty() {
                    let chunk_index = chunks.len();
                    let mut boundaries = remaining
                        .char_indices()
                        .map(|(index, _)| index)
                        .skip(1)
                        .collect::<Vec<_>>();
                    boundaries.push(remaining.len());
                    let mut low = 0;
                    let mut high = boundaries.len();
                    while low < high {
                        let mid = low + (high - low).div_ceil(2);
                        let mut candidate = current.clone();
                        candidate.push((
                            AgentMessageInputContent::InputText {
                                text: remaining[..boundaries[mid - 1]].to_string(),
                            },
                            source_index,
                        ));
                        if estimate_item_token_count(&make_envelope(candidate, chunk_index).item)
                            <= max_tokens
                        {
                            low = mid;
                        } else {
                            high = mid - 1;
                        }
                    }
                    if low == 0 {
                        if current.is_empty() {
                            return Vec::new();
                        }
                        chunks.push(make_envelope(std::mem::take(&mut current), chunk_index));
                        continue;
                    }
                    let split_at = boundaries[low - 1];
                    current.push((
                        AgentMessageInputContent::InputText {
                            text: remaining[..split_at].to_string(),
                        },
                        source_index,
                    ));
                    remaining = &remaining[split_at..];
                    if !remaining.is_empty() {
                        chunks.push(make_envelope(std::mem::take(&mut current), chunk_index));
                    }
                }
            }
            AgentMessageInputContent::InputText { .. }
            | AgentMessageInputContent::EncryptedContent { .. } => {
                let chunk_index = chunks.len();
                let mut candidate = current.clone();
                candidate.push((content_item.clone(), source_index));
                if estimate_item_token_count(&make_envelope(candidate.clone(), chunk_index).item)
                    <= max_tokens
                {
                    current = candidate;
                    continue;
                }
                if !current.is_empty() {
                    chunks.push(make_envelope(std::mem::take(&mut current), chunk_index));
                }
                let chunk_index = chunks.len();
                let candidate = vec![(content_item.clone(), source_index)];
                if estimate_item_token_count(&make_envelope(candidate.clone(), chunk_index).item)
                    > max_tokens
                {
                    return Vec::new();
                }
                current = candidate;
            }
        }
    }
    if !current.is_empty() || content.is_empty() {
        chunks.push(make_envelope(current, chunks.len()));
    }
    if chunks
        .iter()
        .any(|envelope| estimate_item_token_count(&envelope.item) > max_tokens)
    {
        return Vec::new();
    }
    chunks
}

fn logical_items(items: &[ResponseItemEnvelope]) -> Vec<ResponseItem> {
    logical_envelopes(items)
        .into_iter()
        .map(ResponseItemEnvelope::into_item)
        .collect()
}

fn logical_envelopes(items: &[ResponseItemEnvelope]) -> Vec<ResponseItemEnvelope> {
    let mut logical = Vec::with_capacity(items.len());
    for envelope in items {
        if envelope
            .metadata
            .as_ref()
            .is_some_and(|metadata| metadata.history_only_continuation)
            && let (
                Some(ResponseItemEnvelope {
                    item:
                        ResponseItem::Message {
                            content: previous_content,
                            internal_chat_message_metadata_passthrough: previous_metadata,
                            ..
                        },
                    metadata: previous_harness_metadata,
                }),
                ResponseItem::Message {
                    content: continuation_content,
                    internal_chat_message_metadata_passthrough: continuation_metadata,
                    ..
                },
            ) = (logical.last_mut(), &envelope.item)
        {
            let previous_indices = previous_harness_metadata
                .as_mut()
                .and_then(|metadata| metadata.projected_content_indices.as_mut());
            let continuation_indices = envelope
                .metadata
                .as_ref()
                .and_then(|metadata| metadata.projected_content_indices.as_ref());
            let merge_first = previous_indices
                .as_deref()
                .and_then(|indices| indices.last())
                .zip(continuation_indices.and_then(|indices| indices.first()))
                .is_some_and(|(previous, continuation)| previous == continuation)
                && matches!(
                    (previous_content.last(), continuation_content.first()),
                    (
                        Some(ContentItem::InputText { .. }),
                        Some(ContentItem::InputText { .. })
                    ) | (
                        Some(ContentItem::OutputText { .. }),
                        Some(ContentItem::OutputText { .. })
                    )
                );
            if merge_first {
                match (previous_content.last_mut(), continuation_content.first()) {
                    (
                        Some(ContentItem::InputText { text: previous }),
                        Some(ContentItem::InputText { text: continuation }),
                    )
                    | (
                        Some(ContentItem::OutputText { text: previous }),
                        Some(ContentItem::OutputText { text: continuation }),
                    ) => previous.push_str(continuation),
                    _ => unreachable!("merge eligibility checked matching text variants"),
                }
            }
            if let (Some(previous_kinds), Some(continuation_kinds)) = (
                previous_metadata
                    .as_mut()
                    .and_then(|metadata| metadata.content_item_kinds.as_mut()),
                continuation_metadata
                    .as_ref()
                    .and_then(|metadata| metadata.content_item_kinds.as_ref()),
            ) {
                previous_kinds.extend(
                    continuation_kinds
                        .iter()
                        .skip(usize::from(merge_first))
                        .cloned(),
                );
            }
            previous_content.extend(
                continuation_content
                    .iter()
                    .skip(usize::from(merge_first))
                    .cloned(),
            );
            if let (Some(previous_indices), Some(continuation_indices)) =
                (previous_indices, continuation_indices)
            {
                previous_indices.extend(
                    continuation_indices
                        .iter()
                        .skip(usize::from(merge_first))
                        .copied(),
                );
            }
            continue;
        }
        if envelope
            .metadata
            .as_ref()
            .is_some_and(|metadata| metadata.history_only_continuation)
            && let (
                Some(ResponseItemEnvelope {
                    item:
                        ResponseItem::AgentMessage {
                            content: previous_content,
                            internal_chat_message_metadata_passthrough: previous_item_metadata,
                            ..
                        },
                    metadata: previous_harness_metadata,
                }),
                ResponseItem::AgentMessage {
                    content: continuation_content,
                    internal_chat_message_metadata_passthrough: continuation_item_metadata,
                    ..
                },
            ) = (logical.last_mut(), &envelope.item)
        {
            let previous_indices = previous_harness_metadata
                .as_mut()
                .and_then(|metadata| metadata.projected_content_indices.as_mut());
            let continuation_indices = envelope
                .metadata
                .as_ref()
                .and_then(|metadata| metadata.projected_content_indices.as_ref());
            let merge_first = previous_indices
                .as_deref()
                .and_then(|indices| indices.last())
                .zip(continuation_indices.and_then(|indices| indices.first()))
                .is_some_and(|(previous, continuation)| previous == continuation)
                && matches!(
                    (previous_content.last(), continuation_content.first()),
                    (
                        Some(AgentMessageInputContent::InputText { .. }),
                        Some(AgentMessageInputContent::InputText { .. })
                    )
                );
            if merge_first {
                match (previous_content.last_mut(), continuation_content.first()) {
                    (
                        Some(AgentMessageInputContent::InputText { text: previous }),
                        Some(AgentMessageInputContent::InputText { text: continuation }),
                    ) => previous.push_str(continuation),
                    _ => unreachable!("merge eligibility checked agent text variants"),
                }
            }
            if let (Some(previous_kinds), Some(continuation_kinds)) = (
                previous_item_metadata
                    .as_mut()
                    .and_then(|metadata| metadata.content_item_kinds.as_mut()),
                continuation_item_metadata
                    .as_ref()
                    .and_then(|metadata| metadata.content_item_kinds.as_ref()),
            ) {
                previous_kinds.extend(
                    continuation_kinds
                        .iter()
                        .skip(usize::from(merge_first))
                        .cloned(),
                );
            }
            previous_content.extend(
                continuation_content
                    .iter()
                    .skip(usize::from(merge_first))
                    .cloned(),
            );
            if let (Some(previous_indices), Some(continuation_indices)) =
                (previous_indices, continuation_indices)
            {
                previous_indices.extend(
                    continuation_indices
                        .iter()
                        .skip(usize::from(merge_first))
                        .copied(),
                );
            }
            continue;
        }
        logical.push(envelope.clone());
    }
    logical
}

fn tool_pair_key(item: &ResponseItem) -> Option<ToolPairKey> {
    let (kind, call_id, side) = match item {
        ResponseItem::FunctionCall { call_id, .. }
        | ResponseItem::LocalShellCall {
            call_id: Some(call_id),
            ..
        } => (ToolPairKind::Function, call_id, ToolPairSide::Call),
        ResponseItem::FunctionCallOutput {
            call_id: Some(call_id),
            ..
        } => (ToolPairKind::Function, call_id, ToolPairSide::Output),
        ResponseItem::ToolSearchCall {
            call_id: Some(call_id),
            ..
        } => (ToolPairKind::ToolSearch, call_id, ToolPairSide::Call),
        ResponseItem::ToolSearchOutput {
            call_id: Some(call_id),
            ..
        } => (ToolPairKind::ToolSearch, call_id, ToolPairSide::Output),
        ResponseItem::CustomToolCall { call_id, .. } => {
            (ToolPairKind::Custom, call_id, ToolPairSide::Call)
        }
        ResponseItem::CustomToolCallOutput { call_id, .. } => {
            (ToolPairKind::Custom, call_id, ToolPairSide::Output)
        }
        ResponseItem::AdditionalTools { .. }
        | ResponseItem::Message { .. }
        | ResponseItem::AgentMessage { .. }
        | ResponseItem::Reasoning { .. }
        | ResponseItem::LocalShellCall { .. }
        | ResponseItem::ToolSearchCall { .. }
        | ResponseItem::FunctionCallOutput { .. }
        | ResponseItem::ToolSearchOutput { .. }
        | ResponseItem::WebSearchCall { .. }
        | ResponseItem::ImageGenerationCall { .. }
        | ResponseItem::Compaction { .. }
        | ResponseItem::CompactionTrigger { .. }
        | ResponseItem::ContextCompaction { .. }
        | ResponseItem::ConfigurationUpdate { .. }
        | ResponseItem::Other => return None,
    };
    Some(ToolPairKey {
        kind,
        call_id: call_id.clone(),
        side,
    })
}

/// Configuration updates require harness provenance; raw system messages are never retained.
fn is_api_message(message: &ResponseItem, metadata: Option<&CodexHarnessMetadata>) -> bool {
    match message {
        ResponseItem::Message { role, .. } => role.as_str() != "system",
        ResponseItem::ConfigurationUpdate { .. } => {
            metadata.is_some_and(|metadata| metadata.harness_authored_configuration)
        }
        ResponseItem::AdditionalTools { .. }
        | ResponseItem::AgentMessage { .. }
        | ResponseItem::FunctionCallOutput { .. }
        | ResponseItem::FunctionCall { .. }
        | ResponseItem::ToolSearchCall { .. }
        | ResponseItem::ToolSearchOutput { .. }
        | ResponseItem::CustomToolCall { .. }
        | ResponseItem::CustomToolCallOutput { .. }
        | ResponseItem::LocalShellCall { .. }
        | ResponseItem::Reasoning { .. }
        | ResponseItem::WebSearchCall { .. }
        | ResponseItem::ImageGenerationCall { .. }
        | ResponseItem::Compaction { .. }
        | ResponseItem::ContextCompaction { .. } => true,
        ResponseItem::CompactionTrigger { .. } => false,
        ResponseItem::Other => false,
    }
}

fn estimate_reasoning_length(encoded_len: usize) -> usize {
    encoded_len
        .saturating_mul(3)
        .checked_div(4)
        .unwrap_or(0)
        .saturating_sub(650)
}

fn estimate_encrypted_function_output_length(encoded_len: usize) -> usize {
    encoded_len.saturating_mul(9).div_ceil(16)
}

/// Returns the same coarse, model-visible token estimate used for full history estimates.
///
/// Ordinary items are JSON-serialized, so callers estimating many items should reuse these
/// results instead of repeatedly estimating the full history.
pub(crate) fn estimate_item_token_count(item: &ResponseItem) -> i64 {
    let model_visible_bytes = estimate_response_item_model_visible_bytes(item);
    approx_tokens_from_byte_count_i64(model_visible_bytes)
}

/// Approximate model-visible byte cost for one image input.
///
/// The estimator later converts bytes to tokens using a 4-bytes/token heuristic
/// with ceiling division, so 7,373 bytes maps to approximately 1,844 tokens.
const RESIZED_IMAGE_BYTES_ESTIMATE: i64 = 7373;
// See https://platform.openai.com/docs/guides/images-vision#calculating-costs.
// Use a direct 32px patch count only for `detail: "original"`;
// all other image inputs continue to use `RESIZED_IMAGE_BYTES_ESTIMATE`.
const ORIGINAL_IMAGE_PATCH_SIZE: u32 = 32;
// See https://platform.openai.com/docs/guides/images-vision#model-sizing-behavior.
// Keep this hard-coded for now; move it into model capabilities if the patch
// budget starts changing often across model releases.
const ORIGINAL_IMAGE_MAX_PATCHES: usize = 10_000;
const ORIGINAL_IMAGE_ESTIMATE_CACHE_SIZE: usize = 32;

static ORIGINAL_IMAGE_ESTIMATE_CACHE: LazyLock<BlockingLruCache<[u8; 20], Option<i64>>> =
    LazyLock::new(|| {
        BlockingLruCache::new(
            NonZeroUsize::new(ORIGINAL_IMAGE_ESTIMATE_CACHE_SIZE).unwrap_or(NonZeroUsize::MIN),
        )
    });

fn estimate_response_item_model_visible_bytes(item: &ResponseItem) -> i64 {
    match item {
        ResponseItem::Reasoning {
            encrypted_content: Some(content),
            ..
        }
        | ResponseItem::Compaction {
            encrypted_content: content,
            ..
        }
        | ResponseItem::ContextCompaction {
            encrypted_content: Some(content),
            ..
        } => i64::try_from(estimate_reasoning_length(content.len())).unwrap_or(i64::MAX),
        item => {
            let raw = serialized_json_bytes(item)
                .map(|len| i64::try_from(len).unwrap_or(i64::MAX))
                .unwrap_or_default();
            let (image_payload_bytes, image_replacement_bytes) =
                image_data_url_estimate_adjustment(item);
            let (audio_payload_bytes, audio_replacement_bytes) =
                audio_data_url_estimate_adjustment(item);
            let (encrypted_payload_bytes, encrypted_replacement_bytes) =
                encrypted_function_output_estimate_adjustment(item);
            // Replace raw base64 payload bytes with per-modality estimates.
            // We intentionally preserve the data URL prefix and JSON
            // wrapper bytes already included in `raw`.
            let raw = raw
                .saturating_sub(image_payload_bytes)
                .saturating_add(image_replacement_bytes)
                .saturating_sub(audio_payload_bytes)
                .saturating_add(audio_replacement_bytes);
            raw.saturating_sub(encrypted_payload_bytes)
                .saturating_add(encrypted_replacement_bytes)
        }
    }
}

/// Returns the base64 payload byte length for inline image data URLs that are
/// eligible for token-estimation discounting.
///
/// We only discount payloads for `data:image/...;base64,...` URLs (case
/// insensitive markers) and leave everything else at raw serialized size.
fn parse_base64_image_data_url(url: &str) -> Option<&str> {
    parse_base64_data_url(url, "image/")
}

/// Returns the base64 payload for inline audio data URLs that are eligible for
/// token-estimation discounting.
fn parse_base64_audio_data_url(url: &str) -> Option<&str> {
    parse_base64_data_url(url, "audio/")
}

fn parse_base64_data_url<'a>(url: &'a str, media_type_prefix: &str) -> Option<&'a str> {
    if !url
        .get(.."data:".len())
        .is_some_and(|prefix| prefix.eq_ignore_ascii_case("data:"))
    {
        return None;
    }
    let comma_index = url.find(',')?;
    let metadata = &url[..comma_index];
    let payload = &url[comma_index + 1..];
    // Parse the media type and parameters without decoding. This keeps the
    // estimator cheap while ensuring we only apply modality heuristics to
    // appropriately typed base64 data URLs.
    let metadata_without_scheme = &metadata["data:".len()..];
    let mut metadata_parts = metadata_without_scheme.split(';');
    let mime_type = metadata_parts.next().unwrap_or_default();
    let has_base64_marker = metadata_parts.any(|part| part.eq_ignore_ascii_case("base64"));
    if !mime_type
        .get(..media_type_prefix.len())
        .is_some_and(|prefix| prefix.eq_ignore_ascii_case(media_type_prefix))
    {
        return None;
    }
    if !has_base64_marker {
        return None;
    }
    Some(payload)
}

fn estimate_original_image_bytes(image_url: &str) -> Option<i64> {
    let key = sha1_digest(image_url.as_bytes());
    ORIGINAL_IMAGE_ESTIMATE_CACHE.get_or_insert_with(key, || {
        let payload = match parse_base64_image_data_url(image_url) {
            Some(payload) => payload,
            None => {
                tracing::trace!("skipping original-detail estimate for non-base64 image data URL");
                return None;
            }
        };
        let bytes = match BASE64_STANDARD.decode(payload) {
            Ok(bytes) => bytes,
            Err(error) => {
                tracing::trace!("failed to decode original-detail image payload: {error}");
                return None;
            }
        };
        let dynamic = match image::load_from_memory(&bytes) {
            Ok(dynamic) => dynamic,
            Err(error) => {
                tracing::trace!("failed to decode original-detail image bytes: {error}");
                return None;
            }
        };
        let width = i64::from(dynamic.width());
        let height = i64::from(dynamic.height());
        let patch_size = i64::from(ORIGINAL_IMAGE_PATCH_SIZE);
        let patches_wide = width.saturating_add(patch_size.saturating_sub(1)) / patch_size;
        let patches_high = height.saturating_add(patch_size.saturating_sub(1)) / patch_size;
        let patch_count = patches_wide.saturating_mul(patches_high);
        let patch_count = usize::try_from(patch_count).unwrap_or(usize::MAX);
        let patch_count = patch_count.min(ORIGINAL_IMAGE_MAX_PATCHES);
        Some(i64::try_from(approx_bytes_for_tokens(patch_count)).unwrap_or(i64::MAX))
    })
}

/// Shared image estimate, excluding the data URL prefix and message framing.
pub(crate) fn estimate_image_bytes(image_url: &str, detail: Option<ImageDetail>) -> i64 {
    match detail {
        Some(ImageDetail::Original) => {
            estimate_original_image_bytes(image_url).unwrap_or(RESIZED_IMAGE_BYTES_ESTIMATE)
        }
        _ => RESIZED_IMAGE_BYTES_ESTIMATE,
    }
}

/// Scans one response item for discount-eligible inline image data URLs and
/// returns:
/// - total base64 payload bytes to subtract from raw serialized size
/// - total replacement byte estimate for those images
fn image_data_url_estimate_adjustment(item: &ResponseItem) -> (i64, i64) {
    let mut payload_bytes = 0i64;
    let mut replacement_bytes = 0i64;

    let mut accumulate = |image_url: &str, detail: Option<ImageDetail>| {
        if let Some(payload_len) = parse_base64_image_data_url(image_url).map(str::len) {
            payload_bytes =
                payload_bytes.saturating_add(i64::try_from(payload_len).unwrap_or(i64::MAX));
            replacement_bytes =
                replacement_bytes.saturating_add(estimate_image_bytes(image_url, detail));
        }
    };

    match item {
        ResponseItem::Message { content, .. } => {
            for content_item in content {
                if let ContentItem::InputImage { image_url, detail } = content_item {
                    accumulate(image_url, *detail);
                }
            }
        }
        ResponseItem::FunctionCallOutput { output, .. }
        | ResponseItem::CustomToolCallOutput { output, .. } => {
            if let FunctionCallOutputBody::ContentItems(items) = &output.body {
                for content_item in items {
                    if let FunctionCallOutputContentItem::InputImage { image_url, detail } =
                        content_item
                    {
                        accumulate(image_url, *detail);
                    }
                }
            }
        }
        _ => {}
    }

    (payload_bytes, replacement_bytes)
}

/// Scans one response item for inline base64 audio data URLs and returns:
/// - total base64 payload bytes to subtract from raw serialized size
/// - total replacement byte estimate for those audio inputs
fn audio_data_url_estimate_adjustment(item: &ResponseItem) -> (i64, i64) {
    let mut payload_bytes = 0i64;
    let mut replacement_bytes = 0i64;

    let mut accumulate = |audio_url: &str| {
        if let Some(payload_len) = parse_base64_audio_data_url(audio_url).map(str::len) {
            payload_bytes =
                payload_bytes.saturating_add(i64::try_from(payload_len).unwrap_or(i64::MAX));
            replacement_bytes = replacement_bytes.saturating_add(
                i64::try_from(approx_bytes_for_tokens(estimate_audio_token_count(
                    audio_url,
                )))
                .unwrap_or(i64::MAX),
            );
        }
    };

    match item {
        ResponseItem::Message { content, .. } => {
            for content_item in content {
                if let ContentItem::InputAudio { audio_url } = content_item {
                    accumulate(audio_url);
                }
            }
        }
        ResponseItem::FunctionCallOutput { output, .. }
        | ResponseItem::CustomToolCallOutput { output, .. } => {
            if let FunctionCallOutputBody::ContentItems(items) = &output.body {
                for content_item in items {
                    if let FunctionCallOutputContentItem::InputAudio { audio_url } = content_item {
                        accumulate(audio_url);
                    }
                }
            }
        }
        _ => {}
    }

    (payload_bytes, replacement_bytes)
}

fn encrypted_function_output_estimate_adjustment(item: &ResponseItem) -> (i64, i64) {
    let mut payload_bytes = 0i64;
    let mut replacement_bytes = 0i64;
    let mut accumulate = |encrypted_content: &str| {
        payload_bytes = payload_bytes
            .saturating_add(i64::try_from(encrypted_content.len()).unwrap_or(i64::MAX));
        replacement_bytes = replacement_bytes.saturating_add(
            i64::try_from(estimate_encrypted_function_output_length(
                encrypted_content.len(),
            ))
            .unwrap_or(i64::MAX),
        );
    };

    match item {
        ResponseItem::FunctionCallOutput { output, .. } => {
            if let FunctionCallOutputBody::ContentItems(items) = &output.body {
                for item in items {
                    if let FunctionCallOutputContentItem::EncryptedContent { encrypted_content } =
                        item
                    {
                        accumulate(encrypted_content);
                    }
                }
            }
        }
        ResponseItem::AgentMessage { content, .. } => {
            for item in content {
                if let AgentMessageInputContent::EncryptedContent { encrypted_content } = item {
                    accumulate(encrypted_content);
                }
            }
        }
        _ => {}
    }

    (payload_bytes, replacement_bytes)
}

fn is_model_generated_item(item: &ResponseItem) -> bool {
    match item {
        ResponseItem::Message { role, .. } => role == "assistant",
        ResponseItem::Reasoning { .. }
        | ResponseItem::FunctionCall { .. }
        | ResponseItem::ToolSearchCall { .. }
        | ResponseItem::WebSearchCall { .. }
        | ResponseItem::ImageGenerationCall { .. }
        | ResponseItem::CustomToolCall { .. }
        | ResponseItem::LocalShellCall { .. }
        | ResponseItem::Compaction { .. }
        | ResponseItem::ContextCompaction { .. } => true,
        ResponseItem::ConfigurationUpdate { .. } | ResponseItem::CompactionTrigger { .. } => false,
        ResponseItem::AdditionalTools { .. }
        | ResponseItem::FunctionCallOutput { .. }
        | ResponseItem::ToolSearchOutput { .. }
        | ResponseItem::CustomToolCallOutput { .. }
        | ResponseItem::AgentMessage { .. }
        | ResponseItem::Other => false,
    }
}

pub(crate) fn is_user_turn_boundary(item: &ResponseItem) -> bool {
    if matches!(item, ResponseItem::AgentMessage { .. }) {
        return true;
    }
    let ResponseItem::Message { role, content, .. } = item else {
        return false;
    };

    (role == "user" && !is_contextual_user_item(item))
        || (role == "assistant" && is_inter_agent_instruction_content(content))
}

fn is_contextual_user_item(item: &ResponseItem) -> bool {
    let ResponseItem::Message {
        role,
        content,
        internal_chat_message_metadata_passthrough,
        ..
    } = item
    else {
        return false;
    };
    if role != "user" || !is_contextual_user_message_content(content) {
        return false;
    }
    internal_chat_message_metadata_passthrough
        .as_ref()
        .and_then(|metadata| metadata.content_item_kinds.as_ref())
        .is_none_or(|kinds| {
            kinds.len() != content.len() || !kinds.iter().any(|kind| kind.0.starts_with("user."))
        })
}

pub(crate) fn is_history_turn_boundary(envelope: &ResponseItemEnvelope) -> bool {
    envelope
        .metadata
        .as_ref()
        .and_then(|metadata| metadata.turn_boundary_override)
        .unwrap_or_else(|| is_user_turn_boundary(&envelope.item))
}

fn is_inter_agent_instruction_content(content: &[ContentItem]) -> bool {
    InterAgentCommunication::is_message_content(content)
}

fn user_message_positions(items: &[ResponseItemEnvelope]) -> Vec<usize> {
    let mut positions = Vec::new();
    for (idx, envelope) in items.iter().enumerate() {
        if is_history_turn_boundary(envelope) {
            positions.push(idx);
        }
    }
    positions
}

#[cfg(test)]
#[path = "history_tests.rs"]
mod tests;
