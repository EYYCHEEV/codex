//! PreToolUse hooks for intercepting tool calls before execution.
//!
//! This module provides a Claude-compatible hook system that allows external
//! scripts to intercept and potentially block tool calls before they execute.

mod executor;
mod matcher;
mod types;

pub use executor::run_pre_tool_use_hooks;
pub use types::HookDecision;
pub use types::HookInput;
pub use types::HookOutput;
