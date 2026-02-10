//! lawctl-hook — Claude Code PreToolUse hook.
//!
//! This binary is called by Claude Code before every tool use.
//! It reads the tool call JSON from stdin, checks it against
//! the lawctl policy, and either:
//!   - Exits 0 (allow the action)
//!   - Exits 2 + stderr message (block the action)
//!
//! It also logs every decision to the audit log.
//!
//! This must be FAST — it runs on every tool call. Target: <5ms.
//!
//! Stdin format (from Claude Code):
//! {
//!   "session_id": "...",
//!   "cwd": "/project/path",
//!   "hook_event_name": "PreToolUse",
//!   "tool_name": "Bash",
//!   "tool_input": { "command": "rm -rf /" }
//! }

use lawctl::audit::AuditLogger;
use lawctl::audit::LogEntry;
use lawctl::policy::types::{Action, ActionContext, Decision};
use lawctl::policy::{parser, PolicyEngine};
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process;

/// Input from Claude Code's hook system.
#[derive(serde::Deserialize, Debug)]
struct HookInput {
    session_id: Option<String>,
    cwd: Option<String>,
    #[allow(dead_code)]
    hook_event_name: Option<String>,
    tool_name: String,
    tool_input: serde_json::Value,
}

fn main() {
    // Read stdin
    let mut input = String::new();
    if let Err(e) = std::io::stdin().read_to_string(&mut input) {
        eprintln!("[lawctl] Failed to read stdin: {}", e);
        // Don't block on read errors — fail open
        process::exit(0);
    }

    // Parse hook input
    let hook_input: HookInput = match serde_json::from_str(&input) {
        Ok(h) => h,
        Err(e) => {
            eprintln!("[lawctl] Failed to parse hook input: {}", e);
            // Don't block on parse errors — fail open
            process::exit(0);
        }
    };

    // Find the policy file (walk up from cwd)
    let cwd = hook_input
        .cwd
        .as_deref()
        .map(PathBuf::from)
        .unwrap_or_else(|| std::env::current_dir().unwrap_or_else(|_| PathBuf::from(".")));

    let policy_path = match find_policy(&cwd) {
        Some(p) => p,
        None => {
            // No policy file — lawctl not set up for this project, allow everything
            process::exit(0);
        }
    };

    // Parse policy + create engine
    let policy = match parser::parse_policy_file(&policy_path) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("[lawctl] Failed to parse policy: {}", e);
            // Bad policy — fail open, don't block the user
            process::exit(0);
        }
    };

    let engine = match PolicyEngine::new(policy) {
        Ok(e) => e,
        Err(e) => {
            eprintln!("[lawctl] Failed to create policy engine: {}", e);
            process::exit(0);
        }
    };

    // Map Claude Code tool to lawctl action(s) + context
    let actions = match map_tool_to_actions(&hook_input) {
        Some(a) => a,
        None => {
            // Tool we don't care about (Read, Glob, Grep, etc.) — allow
            process::exit(0);
        }
    };

    // Extract session_id before we borrow hook_input again
    let session_id = hook_input
        .session_id
        .clone()
        .unwrap_or_else(|| "claude-hook".to_string());

    // Evaluate ALL actions — if any is denied, block.
    // This handles dual-action commands like `rm -rf /` which is both
    // RunCmd (matches command-pattern rules) and Delete (matches path rules).
    //
    // When an action is approved by the user (e.g., GitPush), we skip
    // remaining checks — the user explicitly OK'd this command.
    let mut user_approved = false;

    for (action, context) in &actions {
        // If user already approved this command via a dialog, skip further checks.
        // e.g., user approved GitPush → don't also block the RunCmd for "git push".
        if user_approved {
            break;
        }

        let start = std::time::Instant::now();
        let decision = engine.evaluate(action, context);
        let eval_us = start.elapsed().as_micros() as u64;

        // Log every decision (best-effort)
        log_decision(&session_id, action, context, &decision, eval_us);

        match &decision {
            Decision::Denied { reason, .. } => {
                eprintln!(
                    "[lawctl] BLOCKED: {} — {}",
                    describe_action(action, &hook_input),
                    reason
                );
                process::exit(2);
            }
            Decision::RequiresApproval { reason, .. } => {
                let action_desc = describe_action(action, &hook_input);
                if prompt_native_approval(&action_desc, reason) {
                    eprintln!("[lawctl] APPROVED: {}", action_desc);
                    user_approved = true;
                } else {
                    eprintln!("[lawctl] DENIED: {} — user declined", action_desc);
                    process::exit(2);
                }
            }
            Decision::Allowed { .. } => {
                // This action is fine — continue checking the others
            }
        }
    }

    // All actions allowed — exit 0 (silent success)
    process::exit(0);
}

/// Prompt the user for approval via native OS dialog.
///
/// On macOS: uses osascript to show a native dialog with Approve/Deny buttons.
/// On Linux: falls back to blocking (no native dialog available).
///
/// Returns true if the user approved, false otherwise.
fn prompt_native_approval(action_desc: &str, reason: &str) -> bool {
    if cfg!(target_os = "macos") {
        prompt_macos_dialog(action_desc, reason)
    } else {
        // No native dialog on Linux — block by default
        eprintln!("[lawctl] Approval required but no UI available on this platform.");
        false
    }
}

/// Show a native macOS dialog using osascript.
/// Blocks until the user clicks Approve or Deny.
fn prompt_macos_dialog(action_desc: &str, reason: &str) -> bool {
    // Sanitize strings for AppleScript (escape backslashes and quotes)
    let safe_action = action_desc
        .replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace('\n', " ");
    let safe_reason = reason
        .replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace('\n', " ");

    let script = format!(
        r#"display dialog "lawctl — Approval Required\n\n{}\n\n{}" buttons {{"Deny", "Approve"}} default button "Deny" with title "lawctl" with icon caution"#,
        safe_action, safe_reason
    );

    match std::process::Command::new("osascript")
        .arg("-e")
        .arg(format!("button returned of ({})", script))
        .output()
    {
        Ok(output) => {
            if output.status.success() {
                let button = String::from_utf8_lossy(&output.stdout).trim().to_string();
                button == "Approve"
            } else {
                // User cancelled or error — treat as deny
                false
            }
        }
        Err(e) => {
            eprintln!("[lawctl] Failed to show approval dialog: {}", e);
            false
        }
    }
}

/// Map a Claude Code tool call to lawctl Action(s) + ActionContext.
/// Returns None for tools we don't need to check (read-only tools).
/// Some tools map to multiple actions (e.g., `rm` is both Delete and RunCmd).
fn map_tool_to_actions(input: &HookInput) -> Option<Vec<(Action, ActionContext)>> {
    match input.tool_name.as_str() {
        "Write" => {
            let file_path = input
                .tool_input
                .get("file_path")
                .and_then(|v| v.as_str())
                .unwrap_or("unknown");
            let content = input
                .tool_input
                .get("content")
                .and_then(|v| v.as_str())
                .unwrap_or("");

            let mut ctx = ActionContext::new(file_path);
            ctx = ctx.with_diff(content.to_string());
            Some(vec![(Action::Write, ctx)])
        }

        "Edit" => {
            let file_path = input
                .tool_input
                .get("file_path")
                .and_then(|v| v.as_str())
                .unwrap_or("unknown");
            let new_string = input
                .tool_input
                .get("new_string")
                .and_then(|v| v.as_str())
                .unwrap_or("");

            let mut ctx = ActionContext::new(file_path);
            ctx = ctx.with_diff(new_string.to_string());
            Some(vec![(Action::Write, ctx)])
        }

        "Bash" => {
            let command = input
                .tool_input
                .get("command")
                .and_then(|v| v.as_str())
                .unwrap_or("");

            let trimmed = command.trim();

            // Git push → check as GitPush + RunCmd
            // Check contains() not just starts_with() because Claude often chains:
            //   git add . && git commit -m "..." && git push origin main
            if trimmed.starts_with("git push")
                || trimmed.contains("&& git push")
                || trimmed.contains("; git push")
            {
                // Extract branch from the git push portion
                let push_part = if let Some(idx) = trimmed.find("git push") {
                    &trimmed[idx..]
                } else {
                    trimmed
                };
                let branch = push_part
                    .strip_prefix("git push")
                    .unwrap_or("")
                    .split_whitespace()
                    .last()
                    .unwrap_or("main");
                let cmd_ctx = ActionContext::new("shell").with_command(command.to_string());
                return Some(vec![
                    (Action::GitPush, ActionContext::new(branch)),
                    (Action::RunCmd, cmd_ctx),
                ]);
            }

            // rm commands → check as BOTH Delete AND RunCmd
            // This way `deny: run_cmd if_matches: ["rm -rf *"]` catches it,
            // AND `deny: delete unless_path: /tmp` also catches it.
            if trimmed.starts_with("rm ") || trimmed.starts_with("rm -") {
                let parts: Vec<&str> = trimmed.split_whitespace().collect();
                let targets: Vec<&str> = parts
                    .iter()
                    .skip(1)
                    .filter(|p| !p.starts_with('-'))
                    .copied()
                    .collect();

                let cmd_ctx = ActionContext::new("shell").with_command(command.to_string());
                let mut actions = vec![(Action::RunCmd, cmd_ctx)];

                if let Some(target) = targets.first() {
                    actions.push((Action::Delete, ActionContext::new(*target)));
                }
                return Some(actions);
            }

            // Normal command → just RunCmd
            let ctx = ActionContext::new("shell").with_command(command.to_string());
            Some(vec![(Action::RunCmd, ctx)])
        }

        "WebFetch" | "WebSearch" => {
            let url = input
                .tool_input
                .get("url")
                .and_then(|v| v.as_str())
                .unwrap_or("");
            let ctx = ActionContext::new(url).with_domain(extract_domain(url).unwrap_or_default());
            Some(vec![(Action::Network, ctx)])
        }

        "NotebookEdit" => {
            let notebook = input
                .tool_input
                .get("notebook_path")
                .and_then(|v| v.as_str())
                .unwrap_or("unknown");
            let content = input
                .tool_input
                .get("new_source")
                .and_then(|v| v.as_str())
                .unwrap_or("");
            let ctx = ActionContext::new(notebook).with_diff(content.to_string());
            Some(vec![(Action::Write, ctx)])
        }

        // Read-only tools — always allow, no policy check needed
        "Read" | "Glob" | "Grep" | "Task" | "TodoWrite" | "ExitPlanMode" => None,

        // Unknown tools — allow by default
        _ => None,
    }
}

/// Find .lawctl.yaml walking up from the given directory.
fn find_policy(start: &Path) -> Option<PathBuf> {
    let mut dir = start.to_path_buf();
    loop {
        let candidate = dir.join(".lawctl.yaml");
        if candidate.exists() {
            return Some(candidate);
        }
        if !dir.pop() {
            return None;
        }
    }
}

/// Describe what action we're checking (for error messages).
fn describe_action(action: &Action, input: &HookInput) -> String {
    let target = match input.tool_name.as_str() {
        "Write" | "Edit" => input
            .tool_input
            .get("file_path")
            .and_then(|v| v.as_str())
            .unwrap_or("unknown")
            .to_string(),
        "Bash" => input
            .tool_input
            .get("command")
            .and_then(|v| v.as_str())
            .unwrap_or("unknown")
            .chars()
            .take(80)
            .collect(),
        _ => input.tool_name.clone(),
    };
    format!("{} '{}'", action, target)
}

/// Extract domain from a URL.
fn extract_domain(url: &str) -> Option<String> {
    url.split("://")
        .nth(1)
        .and_then(|s| s.split('/').next())
        .map(|s| s.to_string())
}

/// Log a decision to the audit log (best-effort).
fn log_decision(
    session_id: &str,
    action: &Action,
    context: &ActionContext,
    decision: &Decision,
    eval_us: u64,
) {
    let mut logger = match AuditLogger::new(session_id) {
        Ok(l) => l,
        Err(_) => return, // Don't fail on log errors
    };

    let entry = LogEntry {
        timestamp: chrono::Utc::now(),
        session_id: session_id.to_string(),
        agent: "claude-code".to_string(),
        action: action.clone(),
        target: context.target.clone(),
        policy_rule: match decision {
            Decision::Allowed { matched_rule, .. } => matched_rule.clone(),
            Decision::Denied { matched_rule, .. } => matched_rule.clone(),
            Decision::RequiresApproval { matched_rule, .. } => matched_rule.clone(),
        },
        decision: decision.clone(),
        diff: context.diff.clone(),
        approved_by: None,
        eval_duration_us: Some(eval_us),
    };

    let _ = logger.log(&entry);
}
