//! Hook execution with proper process management.

use std::process::Stdio;
use std::time::Duration;
use tokio::io::AsyncWriteExt;
use tokio::process::Command;
use tracing::debug;
use tracing::warn;

use crate::config::types::HookFailurePolicy;
use crate::config::types::HooksConfig;
use crate::config::types::PreToolUseHookConfig;

use super::matcher::matches_tool;
use super::types::HookDecision;
use super::types::HookInput;
use super::types::HookOutput;

/// Run all matching PreToolUse hooks. Returns Err(reason) if blocked.
pub async fn run_pre_tool_use_hooks(
    hooks_config: &HooksConfig,
    tool_name: &str,
    tool_input: serde_json::Value,
    tool_use_id: &str,
    session_id: &str,
    cwd: &str,
    transcript_path: &str,
) -> Result<(), String> {
    for hook in &hooks_config.pre_tool_use {
        if !matches_tool(&hook.matcher, tool_name) {
            continue;
        }

        // Treat empty command as hook failure (fail-closed by default)
        if hook.command.is_empty() {
            warn!(matcher = %hook.matcher, "Hook has empty command");
            match hook.on_failure {
                HookFailurePolicy::Deny => {
                    return Err("Hook misconfigured: empty command".to_string());
                }
                HookFailurePolicy::Allow => {
                    debug!("Empty command but on_failure=allow, continuing");
                    continue;
                }
            }
        }

        debug!(tool = tool_name, matcher = %hook.matcher, "Running PreToolUse hook");

        let result = execute_single_hook(
            hook,
            tool_name,
            &tool_input,
            tool_use_id,
            session_id,
            cwd,
            transcript_path,
        )
        .await;

        match result {
            Ok(output) => {
                let decision = output.decision();
                match decision {
                    HookDecision::Deny | HookDecision::Ask => {
                        // "ask" treated as deny (Codex doesn't have approval flow)
                        let reason = output
                            .reason()
                            .unwrap_or_else(|| "Blocked by PreToolUse hook".to_string());
                        return Err(reason);
                    }
                    HookDecision::Allow => continue,
                }
            }
            Err(e) => {
                warn!(error = %e, "Hook execution failed");
                match hook.on_failure {
                    HookFailurePolicy::Deny => {
                        return Err(format!("Hook failed (fail-closed): {e}"));
                    }
                    HookFailurePolicy::Allow => {
                        debug!("Hook failed but on_failure=allow, continuing");
                    }
                }
            }
        }
    }
    Ok(())
}

async fn execute_single_hook(
    hook: &PreToolUseHookConfig,
    tool_name: &str,
    tool_input: &serde_json::Value,
    tool_use_id: &str,
    session_id: &str,
    cwd: &str,
    transcript_path: &str,
) -> Result<HookOutput, String> {
    let input = HookInput {
        hook_event_name: "PreToolUse",
        tool_name: tool_name.to_string(),
        tool_input: tool_input.clone(),
        tool_use_id: tool_use_id.to_string(),
        session_id: session_id.to_string(),
        cwd: cwd.to_string(),
        transcript_path: transcript_path.to_string(),
    };

    let input_json =
        serde_json::to_string(&input).map_err(|e| format!("Serialize hook input: {e}"))?;

    let timeout = Duration::from_secs(hook.timeout_sec);

    // Spawn child process with working directory set
    let mut child = Command::new(&hook.command[0])
        .args(&hook.command[1..])
        .current_dir(cwd) // Run hook in tool's working directory
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true) // Ensure cleanup on timeout/drop
        .spawn()
        .map_err(|e| format!("Spawn hook: {e}"))?;

    // Write to stdin
    if let Some(mut stdin) = child.stdin.take() {
        stdin
            .write_all(input_json.as_bytes())
            .await
            .map_err(|e| format!("Write to hook stdin: {e}"))?;
        // Drop stdin to signal EOF
    }

    // Wait with timeout
    let result = tokio::time::timeout(timeout, child.wait_with_output()).await;

    match result {
        Ok(Ok(output)) => {
            let exit_code = output.status.code();

            // Claude semantics: exit code 2 = deny with stderr as reason
            if exit_code == Some(2) {
                let stderr = String::from_utf8_lossy(&output.stderr);
                let reason = if stderr.trim().is_empty() {
                    "Hook blocked command (exit code 2)".to_string()
                } else {
                    stderr.trim().to_string()
                };
                return Ok(HookOutput {
                    decision: Some(HookDecision::Deny),
                    reason: Some(reason),
                    hook_specific_output: None,
                });
            }

            // Non-zero exit (other than 2) = error
            if !output.status.success() {
                let stderr = String::from_utf8_lossy(&output.stderr);
                let msg = if stderr.trim().is_empty() {
                    format!("Hook exited with status: {}", output.status)
                } else {
                    format!("Hook failed: {}", stderr.trim())
                };
                return Err(msg);
            }

            // Parse stdout as JSON
            let stdout = String::from_utf8_lossy(&output.stdout);
            if stdout.trim().is_empty() {
                // No output = allow (hook just exited 0)
                return Ok(HookOutput::default());
            }

            serde_json::from_str(&stdout).map_err(|e| {
                let preview = &stdout[..stdout.len().min(200)];
                format!("Parse hook output: {e} (got: {preview})")
            })
        }
        Ok(Err(e)) => Err(format!("Wait for hook: {e}")),
        Err(_) => {
            // Timeout - child is killed by kill_on_drop(true)
            Err(format!("Hook timed out after {}s", hook.timeout_sec))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::types::PreToolUseHookConfig;

    fn make_test_config(command: Vec<String>) -> HooksConfig {
        HooksConfig {
            pre_tool_use: vec![PreToolUseHookConfig {
                matcher: "*".to_string(),
                command,
                timeout_sec: 5,
                on_failure: HookFailurePolicy::Deny,
            }],
        }
    }

    #[tokio::test]
    async fn test_empty_command_denies_by_default() {
        let config = make_test_config(vec![]);
        let result = run_pre_tool_use_hooks(
            &config,
            "shell",
            serde_json::json!({"command": "ls"}),
            "test-id",
            "session-id",
            "/tmp",
            "/tmp/transcript.jsonl",
        )
        .await;

        assert!(result.is_err());
        assert!(result.unwrap_err().contains("empty command"));
    }

    #[tokio::test]
    async fn test_no_matching_hooks_allows() {
        let config = HooksConfig {
            pre_tool_use: vec![PreToolUseHookConfig {
                matcher: "other_tool".to_string(),
                command: vec!["false".to_string()], // Would fail if matched
                timeout_sec: 5,
                on_failure: HookFailurePolicy::Deny,
            }],
        };
        let result = run_pre_tool_use_hooks(
            &config,
            "shell",
            serde_json::json!({"command": "ls"}),
            "test-id",
            "session-id",
            "/tmp",
            "/tmp/transcript.jsonl",
        )
        .await;

        assert!(result.is_ok());
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn test_hook_exit_0_allows() {
        let config = make_test_config(vec!["true".to_string()]);
        let result = run_pre_tool_use_hooks(
            &config,
            "shell",
            serde_json::json!({"command": "ls"}),
            "test-id",
            "session-id",
            "/tmp",
            "/tmp/transcript.jsonl",
        )
        .await;

        assert!(result.is_ok());
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn test_hook_exit_2_denies() {
        // Exit code 2 with message on stderr
        let config = make_test_config(vec![
            "sh".to_string(),
            "-c".to_string(),
            "echo 'Blocked by test' >&2; exit 2".to_string(),
        ]);
        let result = run_pre_tool_use_hooks(
            &config,
            "shell",
            serde_json::json!({"command": "rm -rf /"}),
            "test-id",
            "session-id",
            "/tmp",
            "/tmp/transcript.jsonl",
        )
        .await;

        assert!(result.is_err());
        assert!(result.unwrap_err().contains("Blocked by test"));
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn test_hook_json_deny_response() {
        // Hook that outputs JSON deny response
        let config = make_test_config(vec![
            "sh".to_string(),
            "-c".to_string(),
            r#"echo '{"decision": "deny", "reason": "JSON deny"}'"#.to_string(),
        ]);
        let result = run_pre_tool_use_hooks(
            &config,
            "shell",
            serde_json::json!({"command": "dangerous"}),
            "test-id",
            "session-id",
            "/tmp",
            "/tmp/transcript.jsonl",
        )
        .await;

        assert!(result.is_err());
        assert!(result.unwrap_err().contains("JSON deny"));
    }
}
