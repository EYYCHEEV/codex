use std::sync::Mutex;

use codex_extension_api::ExtensionMetrics;
use codex_otel::THREAD_SKILLS_DESCRIPTION_TRUNCATED_CHARS_METRIC;
use codex_otel::THREAD_SKILLS_ENABLED_TOTAL_METRIC;
use codex_otel::THREAD_SKILLS_KEPT_TOTAL_METRIC;
use codex_otel::THREAD_SKILLS_TRUNCATED_METRIC;
use codex_protocol::ResponseItemId;
use codex_protocol::models::ResponseItem;
use codex_utils_string::approx_token_count;
use pretty_assertions::assert_eq;

use super::*;

#[derive(Default)]
struct RecordingMetrics {
    samples: Mutex<Vec<(String, i64)>>,
}

impl ExtensionMetrics for RecordingMetrics {
    fn counter(&self, name: &str, _inc: i64, _tags: &[(&str, &str)]) {
        panic!("unexpected counter: {name}");
    }

    fn histogram(&self, name: &str, value: i64, _tags: &[(&str, &str)]) {
        self.samples
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .push((name.to_string(), value));
    }
}

fn serialized_skill_tokens(fragment: &SkillInstructions) -> usize {
    let item = ResponseItem::from(fragment.render_fragment());
    let serialized = serde_json::to_string(&item).expect("skill response item should serialize");
    approx_token_count(&serialized)
}

fn stamped_serialized_skill_tokens(fragment: &SkillInstructions) -> usize {
    let mut item = ResponseItem::from(fragment.render_fragment());
    item.set_id(Some(ResponseItemId::with_suffix(
        "msg",
        "00000000-0000-7000-8000-000000000000",
    )));
    item.set_turn_id_if_missing("00000000-0000-7000-8000-000000000000");
    item.set_create_time_if_missing(
        serde_json::Number::from_f64(1_999_999_999.999_999)
            .expect("finite creation time should be representable"),
    );
    let serialized = serde_json::to_string(&item).expect("stamped skill item should serialize");
    approx_token_count(&serialized)
}

#[test]
fn skill_limit_reserves_headroom_for_history_stamps_with_escape_heavy_contents() {
    const ESCAPE_PATTERN: &str =
        "\"\u{0000}\u{0001}\u{0002}\u{0003}\u{0004}\u{0005}\u{0006}\u{0007}";

    let fragment_with_repeats = |repeats| SkillInstructions {
        name: "escape-\"heavy".to_string(),
        path: "/tmp/escape-\nheavy/SKILL.md".to_string(),
        contents: ESCAPE_PATTERN.repeat(repeats),
        resource_access: None,
    };

    // Find the escape-heavy boundary that the old unstamped check accepted.
    let mut low = 0_usize;
    let mut high = 40_000_usize;
    while low < high {
        let middle = low + (high - low).div_ceil(2);
        if serialized_skill_tokens(&fragment_with_repeats(middle)) <= MAX_SKILL_INSTRUCTION_TOKENS {
            low = middle;
        } else {
            high = middle - 1;
        }
    }

    let fragment = fragment_with_repeats(low);
    assert!(fragment.contents.len() <= 8_000);
    assert!(serialized_skill_tokens(&fragment) <= MAX_SKILL_INSTRUCTION_TOKENS);
    assert!(
        stamped_serialized_skill_tokens(&fragment) > MAX_SKILL_INSTRUCTION_TOKENS,
        "history stamping should expose the old boundary bug"
    );
    assert!(fragment.exceeds_model_visible_token_limit());

    let mut low = 0_usize;
    let mut high = 40_000_usize;
    while low < high {
        let middle = low + (high - low).div_ceil(2);
        if fragment_with_repeats(middle).exceeds_model_visible_token_limit() {
            high = middle - 1;
        } else {
            low = middle;
        }
    }

    let accepted_fragment = fragment_with_repeats(low);
    assert!(!accepted_fragment.exceeds_model_visible_token_limit());
    assert!(
        stamped_serialized_skill_tokens(&accepted_fragment) <= MAX_SKILL_INSTRUCTION_TOKENS,
        "an accepted skill must stay within the limit after history stamping"
    );
}

#[test]
fn empty_catalog_records_zero_metrics_without_a_fragment() {
    let metrics = RecordingMetrics::default();

    let rendered = render_catalog(
        Some(&metrics),
        CatalogSurface::ThreadContext,
        &SkillCatalog::default(),
        /*include_skills_usage_instructions*/ false,
        SkillCatalogRenderPolicy::ExtensionCompatible,
        SkillMetadataBudget::Characters(8_000),
    );

    assert!(rendered.fragment.is_none());
    assert_eq!(rendered.warning_message, None);

    assert_eq!(
        *metrics
            .samples
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner),
        vec![
            (THREAD_SKILLS_ENABLED_TOTAL_METRIC.to_string(), 0),
            (THREAD_SKILLS_KEPT_TOTAL_METRIC.to_string(), 0),
            (THREAD_SKILLS_TRUNCATED_METRIC.to_string(), 0),
            (
                THREAD_SKILLS_DESCRIPTION_TRUNCATED_CHARS_METRIC.to_string(),
                0,
            ),
        ]
    );
}
