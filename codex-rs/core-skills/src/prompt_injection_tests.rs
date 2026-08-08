use pretty_assertions::assert_eq;

use super::MAX_SKILL_PROMPT_BYTES;
use super::SkillInjection;
use super::bounded_skill_prompt_contents;
use super::exceeds_model_context_limit;
use crate::skill_instructions::MAX_SKILL_INSTRUCTION_TOKENS;
use crate::skill_instructions::SkillInstructions;
use codex_context_fragments::ContextualUserFragment;
use codex_utils_output_truncation::approx_token_count;

#[test]
fn serialized_skill_instructions_cannot_exceed_model_context_limit() {
    let injection = SkillInjection {
        name: "escape-heavy".to_string(),
        path: "/tmp/escape-heavy/SKILL.md".to_string(),
        contents: "\"".repeat(39_000),
    };

    assert!(
        approx_token_count(&SkillInstructions::from(&injection).render())
            <= MAX_SKILL_INSTRUCTION_TOKENS
    );
    assert!(exceeds_model_context_limit(&injection));
}

#[test]
fn skill_prompt_contents_are_bounded_at_utf8_boundaries() {
    let contents = format!("{}é", "a".repeat(MAX_SKILL_PROMPT_BYTES - 1));

    let (bounded, truncated) = bounded_skill_prompt_contents(&contents);

    assert_eq!(bounded.len(), MAX_SKILL_PROMPT_BYTES - 1);
    assert_eq!(truncated, true);
}
