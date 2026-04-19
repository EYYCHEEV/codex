use super::*;
use pretty_assertions::assert_eq;

#[test]
fn deserialize_skill_config_with_name_selector() {
    let cfg: SkillConfig = toml::from_str(
        r#"
            name = "github:yeet"
            enabled = false
        "#,
    )
    .expect("should deserialize skill config with name selector");

    assert_eq!(cfg.name.as_deref(), Some("github:yeet"));
    assert_eq!(cfg.path, None);
    assert!(!cfg.enabled);
}

#[test]
fn deserialize_skill_config_with_path_selector() {
    let tempdir = tempfile::tempdir().expect("tempdir");
    let skill_path = tempdir.path().join("skills").join("demo").join("SKILL.md");
    let cfg: SkillConfig = toml::from_str(&format!(
        r#"
            path = {path:?}
            enabled = false
        "#,
        path = skill_path.display().to_string(),
    ))
    .expect("should deserialize skill config with path selector");

    assert_eq!(
        cfg,
        SkillConfig {
            path: Some(
                AbsolutePathBuf::from_absolute_path(&skill_path)
                    .expect("skill path should be absolute"),
            ),
            name: None,
            enabled: false,
        }
    );
}

#[test]
fn memories_config_clamps_count_limits_to_nonzero_values() {
    let config = MemoriesConfig::from(MemoriesToml {
        max_raw_memories_for_consolidation: Some(0),
        max_rollouts_per_startup: Some(0),
        ..Default::default()
    });

    assert_eq!(
        config,
        MemoriesConfig {
            max_raw_memories_for_consolidation: 1,
            max_rollouts_per_startup: 1,
            ..MemoriesConfig::default()
        }
    );
}

#[test]
fn memories_config_clamps_rate_limit_remaining_threshold() {
    let config = MemoriesConfig::from(MemoriesToml {
        min_rate_limit_remaining_percent: Some(101),
        ..Default::default()
    });
    assert_eq!(
        config,
        MemoriesConfig {
            min_rate_limit_remaining_percent: 100,
            ..MemoriesConfig::default()
        }
    );

    let config = MemoriesConfig::from(MemoriesToml {
        min_rate_limit_remaining_percent: Some(-1),
        ..Default::default()
    });
    assert_eq!(
        config,
        MemoriesConfig {
            min_rate_limit_remaining_percent: 0,
            ..MemoriesConfig::default()
        }
    );
}

#[test]
fn deserialize_legacy_pre_tool_use_hook_config() {
    let cfg: LegacyHooksConfig = toml::from_str(
        r#"
            [[pre_tool_use]]
            matcher = "exec_command"
            command = ["python3", "/tmp/hook.py"]
        "#,
    )
    .expect("should deserialize legacy pre tool use hooks");

    assert_eq!(
        cfg,
        LegacyHooksConfig {
            pre_tool_use: vec![LegacyPreToolUseHookConfig {
                matcher: "exec_command".to_string(),
                command: vec!["python3".to_string(), "/tmp/hook.py".to_string()],
                timeout_sec: 5,
                on_failure: HookFailurePolicy::Deny,
            }],
        }
    );
}

#[test]
fn deserialize_legacy_pre_tool_use_hook_allows_failure_override() {
    let cfg: LegacyHooksConfig = toml::from_str(
        r#"
            [[pre_tool_use]]
            matcher = "*"
            command = ["python3", "/tmp/hook.py"]
            timeout_sec = 12
            on_failure = "allow"
        "#,
    )
    .expect("should deserialize legacy pre tool use hooks");

    assert_eq!(cfg.pre_tool_use.len(), 1);
    assert_eq!(cfg.pre_tool_use[0].timeout_sec, 12);
    assert_eq!(cfg.pre_tool_use[0].on_failure, HookFailurePolicy::Allow);
}
