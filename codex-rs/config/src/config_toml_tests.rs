use pretty_assertions::assert_eq;

use super::ConfigToml;
use crate::HookEventsToml;
use crate::HookHandlerConfig;
use crate::MatcherGroup;

#[test]
fn config_toml_deserializes_legacy_hooks_shape() {
    let parsed: ConfigToml = toml::from_str(
        r#"
[[hooks.pre_tool_use]]
matcher = "exec_command"
command = ["python3", "/tmp/hook.py"]
"#,
    )
    .expect("legacy hooks config should deserialize");

    let hooks = parsed.hooks.expect("hooks should deserialize");
    assert!(hooks.events.is_empty());
    assert_eq!(hooks.legacy.pre_tool_use.len(), 1);
    assert_eq!(hooks.legacy.pre_tool_use[0].matcher, "exec_command");
}

#[test]
fn config_toml_deserializes_canonical_and_legacy_hooks_together() {
    let parsed: ConfigToml = toml::from_str(
        r#"
[[hooks.PreToolUse]]
matcher = "^Bash$"

[[hooks.PreToolUse.hooks]]
type = "command"
command = "python3 /tmp/pre.py"

[[hooks.pre_tool_use]]
matcher = "*"
command = ["python3", "/tmp/legacy.py"]
"#,
    )
    .expect("mixed hooks config should deserialize");

    let hooks = parsed.hooks.expect("hooks should deserialize");
    assert_eq!(
        hooks.events,
        HookEventsToml {
            pre_tool_use: vec![MatcherGroup {
                matcher: Some("^Bash$".to_string()),
                hooks: vec![HookHandlerConfig::Command {
                    command: "python3 /tmp/pre.py".to_string(),
                    command_windows: None,
                    timeout_sec: None,
                    r#async: false,
                    status_message: None,
                }],
            }],
            ..Default::default()
        }
    );
    assert_eq!(hooks.legacy.pre_tool_use.len(), 1);
}
