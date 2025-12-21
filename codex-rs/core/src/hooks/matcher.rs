//! Pattern matching for tool names against hook matchers.

use wildmatch::WildMatchPattern;

/// Match tool name against hook pattern.
/// Supports: exact match, "*" wildcard, glob patterns.
/// Uses case-insensitive matching (consistent with codebase usage).
pub fn matches_tool(pattern: &str, tool_name: &str) -> bool {
    if pattern == "*" {
        return true;
    }
    if pattern.contains('*') || pattern.contains('?') {
        // Use case-insensitive WildMatchPattern (same as existing codebase usage)
        let pat: WildMatchPattern<'*', '?'> = WildMatchPattern::new_case_insensitive(pattern);
        pat.matches(tool_name)
    } else {
        pattern.eq_ignore_ascii_case(tool_name)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_exact_match() {
        assert!(matches_tool("shell", "shell"));
        assert!(matches_tool("shell", "Shell")); // case-insensitive
        assert!(!matches_tool("shell", "shell_command"));
    }

    #[test]
    fn test_wildcard_all() {
        assert!(matches_tool("*", "anything"));
        assert!(matches_tool("*", "shell"));
        assert!(matches_tool("*", "mcp__playwright__click"));
    }

    #[test]
    fn test_glob_patterns() {
        assert!(matches_tool("shell*", "shell_command"));
        assert!(matches_tool("shell*", "shell"));
        assert!(matches_tool("mcp__*", "mcp__playwright__browser_click"));
        assert!(!matches_tool("shell*", "local_shell"));
    }

    #[test]
    fn test_question_mark_wildcard() {
        assert!(matches_tool("shel?", "shell"));
        assert!(!matches_tool("shel?", "shells"));
    }

    #[test]
    fn test_case_insensitive_glob() {
        assert!(matches_tool("Shell*", "shell_command"));
        assert!(matches_tool("SHELL*", "shell_command"));
    }
}
