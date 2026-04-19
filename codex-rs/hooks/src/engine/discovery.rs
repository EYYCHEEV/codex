use std::fs;

use codex_config::CONFIG_TOML_FILE;
use codex_config::ConfigLayerStack;
use codex_config::ConfigLayerStackOrdering;
use codex_config::types::LegacyHooksConfig;
use codex_protocol::protocol::HookEventName;
use codex_utils_absolute_path::AbsolutePathBuf;

use super::ConfiguredHandler;
use super::ConfiguredHandlerBehavior;
use super::HandlerExecution;
use super::config::HookHandlerConfig;
use super::config::HooksFile;
use super::config::MatcherGroup;
use crate::events::common::matcher_pattern_for_event;
use crate::events::common::validate_matcher_pattern;

pub(crate) struct DiscoveryResult {
    pub handlers: Vec<ConfiguredHandler>,
    pub warnings: Vec<String>,
}

pub(crate) fn discover_handlers(
    canonical_enabled: bool,
    legacy_pre_tool_use_enabled: bool,
    config_layer_stack: Option<&ConfigLayerStack>,
) -> DiscoveryResult {
    let Some(config_layer_stack) = config_layer_stack else {
        return DiscoveryResult {
            handlers: Vec::new(),
            warnings: Vec::new(),
        };
    };

    let mut handlers = Vec::new();
    let mut warnings = Vec::new();
    let mut display_order = 0_i64;

    for layer in config_layer_stack.get_layers(
        ConfigLayerStackOrdering::LowestPrecedenceFirst,
        /*include_disabled*/ false,
    ) {
        if canonical_enabled {
            append_handlers_from_hooks_file(
                &mut handlers,
                &mut warnings,
                &mut display_order,
                layer,
            );
        }
        if legacy_pre_tool_use_enabled {
            append_legacy_pre_tool_use_handlers(
                &mut handlers,
                &mut warnings,
                &mut display_order,
                layer,
            );
        }
    }

    DiscoveryResult { handlers, warnings }
}

fn append_handlers_from_hooks_file(
    handlers: &mut Vec<ConfiguredHandler>,
    warnings: &mut Vec<String>,
    display_order: &mut i64,
    layer: &codex_config::ConfigLayerEntry,
) {
    let Some(folder) = layer.config_folder() else {
        return;
    };
    let source_path = folder.join("hooks.json");
    if !source_path.as_path().is_file() {
        return;
    }

    let contents = match fs::read_to_string(source_path.as_path()) {
        Ok(contents) => contents,
        Err(err) => {
            warnings.push(format!(
                "failed to read hooks config {}: {err}",
                source_path.display()
            ));
            return;
        }
    };

    let parsed: HooksFile = match serde_json::from_str(&contents) {
        Ok(parsed) => parsed,
        Err(err) => {
            warnings.push(format!(
                "failed to parse hooks config {}: {err}",
                source_path.display()
            ));
            return;
        }
    };

    let super::config::HookEvents {
        pre_tool_use,
        post_tool_use,
        session_start,
        user_prompt_submit,
        stop,
    } = parsed.hooks;

    for (event_name, groups) in [
        (HookEventName::PreToolUse, pre_tool_use),
        (HookEventName::PostToolUse, post_tool_use),
        (HookEventName::SessionStart, session_start),
        (HookEventName::UserPromptSubmit, user_prompt_submit),
        (HookEventName::Stop, stop),
    ] {
        append_matcher_groups(
            handlers,
            warnings,
            display_order,
            &source_path,
            event_name,
            groups,
        );
    }
}

fn append_legacy_pre_tool_use_handlers(
    handlers: &mut Vec<ConfiguredHandler>,
    warnings: &mut Vec<String>,
    display_order: &mut i64,
    layer: &codex_config::ConfigLayerEntry,
) {
    let Some(raw_hooks) = layer.config.get("hooks").cloned() else {
        return;
    };
    let parsed: LegacyHooksConfig = match raw_hooks.try_into() {
        Ok(parsed) => parsed,
        Err(err) => {
            let source = layer
                .config_folder()
                .map(|folder| folder.join(CONFIG_TOML_FILE).display().to_string())
                .unwrap_or_else(|| "config.toml".to_string());
            warnings.push(format!(
                "failed to parse legacy hooks config {source}: {err}"
            ));
            return;
        }
    };
    if parsed.pre_tool_use.is_empty() {
        return;
    }

    let Some(source_path) = layer
        .config_folder()
        .map(|folder| folder.join(CONFIG_TOML_FILE))
    else {
        warnings.push("skipping legacy hooks in config layer without config folder".to_string());
        return;
    };

    for hook in parsed.pre_tool_use {
        if hook.command.is_empty() {
            warnings.push(format!(
                "skipping empty legacy pre-tool-use command in {}",
                source_path.display()
            ));
            continue;
        }
        handlers.push(ConfiguredHandler {
            event_name: HookEventName::PreToolUse,
            matcher: legacy_tool_matcher_to_regex(&hook.matcher),
            command: hook.command.join(" "),
            execution: HandlerExecution::Argv(hook.command),
            behavior: ConfiguredHandlerBehavior::LegacyPreToolUse {
                on_failure: hook.on_failure,
            },
            timeout_sec: hook.timeout_sec.max(1),
            status_message: None,
            source_path: source_path.clone(),
            display_order: *display_order,
        });
        *display_order += 1;
    }
}

fn legacy_tool_matcher_to_regex(matcher: &str) -> Option<String> {
    if matcher.is_empty() || matcher == "*" {
        return None;
    }

    let mut pattern = String::from("^");
    for ch in matcher.chars() {
        match ch {
            '*' => pattern.push_str(".*"),
            '?' => pattern.push('.'),
            _ => pattern.push_str(&regex::escape(&ch.to_string())),
        }
    }
    pattern.push('$');
    Some(pattern)
}

fn append_group_handlers(
    handlers: &mut Vec<ConfiguredHandler>,
    warnings: &mut Vec<String>,
    display_order: &mut i64,
    source_path: &AbsolutePathBuf,
    event_name: HookEventName,
    matcher: Option<&str>,
    group_handlers: Vec<HookHandlerConfig>,
) {
    if let Some(matcher) = matcher
        && let Err(err) = validate_matcher_pattern(matcher)
    {
        warnings.push(format!(
            "invalid matcher {matcher:?} in {}: {err}",
            source_path.display()
        ));
        return;
    }

    for handler in group_handlers {
        match handler {
            HookHandlerConfig::Command {
                command,
                timeout_sec,
                r#async,
                status_message,
            } => {
                if r#async {
                    warnings.push(format!(
                        "skipping async hook in {}: async hooks are not supported yet",
                        source_path.display()
                    ));
                    continue;
                }
                if command.trim().is_empty() {
                    warnings.push(format!(
                        "skipping empty hook command in {}",
                        source_path.display()
                    ));
                    continue;
                }
                let timeout_sec = timeout_sec.unwrap_or(600).max(1);
                handlers.push(ConfiguredHandler {
                    event_name,
                    matcher: matcher.map(ToOwned::to_owned),
                    command,
                    execution: HandlerExecution::ShellCommand,
                    behavior: ConfiguredHandlerBehavior::Canonical,
                    timeout_sec,
                    status_message,
                    source_path: source_path.clone(),
                    display_order: *display_order,
                });
                *display_order += 1;
            }
            HookHandlerConfig::Prompt {} => warnings.push(format!(
                "skipping prompt hook in {}: prompt hooks are not supported yet",
                source_path.display()
            )),
            HookHandlerConfig::Agent {} => warnings.push(format!(
                "skipping agent hook in {}: agent hooks are not supported yet",
                source_path.display()
            )),
        }
    }
}

fn append_matcher_groups(
    handlers: &mut Vec<ConfiguredHandler>,
    warnings: &mut Vec<String>,
    display_order: &mut i64,
    source_path: &AbsolutePathBuf,
    event_name: HookEventName,
    groups: Vec<MatcherGroup>,
) {
    for group in groups {
        append_group_handlers(
            handlers,
            warnings,
            display_order,
            source_path,
            event_name,
            matcher_pattern_for_event(event_name, group.matcher.as_deref()),
            group.hooks,
        );
    }
}

#[cfg(test)]
mod tests {
    use codex_protocol::protocol::HookEventName;
    use codex_utils_absolute_path::AbsolutePathBuf;
    use codex_utils_absolute_path::test_support::PathBufExt;
    use codex_utils_absolute_path::test_support::test_path_buf;
    use pretty_assertions::assert_eq;

    use super::ConfiguredHandler;
    use super::ConfiguredHandlerBehavior;
    use super::HandlerExecution;
    use super::HookHandlerConfig;
    use super::append_group_handlers;
    use super::legacy_tool_matcher_to_regex;
    use crate::events::common::matcher_pattern_for_event;

    fn source_path() -> AbsolutePathBuf {
        test_path_buf("/tmp/hooks.json").abs()
    }

    #[test]
    fn user_prompt_submit_ignores_invalid_matcher_during_discovery() {
        let mut handlers = Vec::new();
        let mut warnings = Vec::new();
        let mut display_order = 0;

        append_group_handlers(
            &mut handlers,
            &mut warnings,
            &mut display_order,
            &source_path(),
            HookEventName::UserPromptSubmit,
            matcher_pattern_for_event(HookEventName::UserPromptSubmit, Some("[")),
            vec![HookHandlerConfig::Command {
                command: "echo hello".to_string(),
                timeout_sec: None,
                r#async: false,
                status_message: None,
            }],
        );

        assert_eq!(warnings, Vec::<String>::new());
        assert_eq!(
            handlers,
            vec![ConfiguredHandler {
                event_name: HookEventName::UserPromptSubmit,
                matcher: None,
                command: "echo hello".to_string(),
                execution: HandlerExecution::ShellCommand,
                behavior: ConfiguredHandlerBehavior::Canonical,
                timeout_sec: 600,
                status_message: None,
                source_path: source_path(),
                display_order: 0,
            }]
        );
    }

    #[test]
    fn pre_tool_use_keeps_valid_matcher_during_discovery() {
        let mut handlers = Vec::new();
        let mut warnings = Vec::new();
        let mut display_order = 0;

        append_group_handlers(
            &mut handlers,
            &mut warnings,
            &mut display_order,
            &source_path(),
            HookEventName::PreToolUse,
            matcher_pattern_for_event(HookEventName::PreToolUse, Some("^Bash$")),
            vec![HookHandlerConfig::Command {
                command: "echo hello".to_string(),
                timeout_sec: None,
                r#async: false,
                status_message: None,
            }],
        );

        assert_eq!(warnings, Vec::<String>::new());
        assert_eq!(
            handlers,
            vec![ConfiguredHandler {
                event_name: HookEventName::PreToolUse,
                matcher: Some("^Bash$".to_string()),
                command: "echo hello".to_string(),
                execution: HandlerExecution::ShellCommand,
                behavior: ConfiguredHandlerBehavior::Canonical,
                timeout_sec: 600,
                status_message: None,
                source_path: source_path(),
                display_order: 0,
            }]
        );
    }

    #[test]
    fn pre_tool_use_treats_star_matcher_as_match_all() {
        let mut handlers = Vec::new();
        let mut warnings = Vec::new();
        let mut display_order = 0;

        append_group_handlers(
            &mut handlers,
            &mut warnings,
            &mut display_order,
            &source_path(),
            HookEventName::PreToolUse,
            matcher_pattern_for_event(HookEventName::PreToolUse, Some("*")),
            vec![HookHandlerConfig::Command {
                command: "echo hello".to_string(),
                timeout_sec: None,
                r#async: false,
                status_message: None,
            }],
        );

        assert_eq!(warnings, Vec::<String>::new());
        assert_eq!(handlers.len(), 1);
        assert_eq!(handlers[0].matcher.as_deref(), Some("*"));
    }

    #[test]
    fn post_tool_use_keeps_valid_matcher_during_discovery() {
        let mut handlers = Vec::new();
        let mut warnings = Vec::new();
        let mut display_order = 0;

        append_group_handlers(
            &mut handlers,
            &mut warnings,
            &mut display_order,
            &source_path(),
            HookEventName::PostToolUse,
            matcher_pattern_for_event(HookEventName::PostToolUse, Some("Edit|Write")),
            vec![HookHandlerConfig::Command {
                command: "echo hello".to_string(),
                timeout_sec: None,
                r#async: false,
                status_message: None,
            }],
        );

        assert_eq!(warnings, Vec::<String>::new());
        assert_eq!(handlers.len(), 1);
        assert_eq!(handlers[0].event_name, HookEventName::PostToolUse);
        assert_eq!(handlers[0].matcher.as_deref(), Some("Edit|Write"));
    }

    #[test]
    fn legacy_tool_matcher_converts_glob_to_regex() {
        assert_eq!(
            legacy_tool_matcher_to_regex("*shell*"),
            Some("^.*shell.*$".to_string())
        );
        assert_eq!(
            legacy_tool_matcher_to_regex("exec_command"),
            Some("^exec_command$".to_string())
        );
        assert_eq!(legacy_tool_matcher_to_regex("*"), None);
    }
}
