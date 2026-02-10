//! Handler for git operations.
//!
//! Git operations are executed on the HOST side, not inside the container.
//! This means the agent never has direct access to git credentials.
//! The gateway receives "push to branch X" and executes it from the
//! host's real git context.

use anyhow::{Context, Result};
use std::path::Path;
use std::process::Command;

/// Execute a git push operation from the host side.
pub fn execute_git_push(workspace_root: &Path, branch: &str) -> Result<String> {
    let output = Command::new("git")
        .args(["push", "origin", branch])
        .current_dir(workspace_root)
        .output()
        .with_context(|| format!("Failed to execute git push to {}", branch))?;

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    if output.status.success() {
        Ok(format!(
            "Pushed to {}.\n{}{}",
            branch,
            stdout,
            if stderr.is_empty() {
                String::new()
            } else {
                format!("\n{}", stderr)
            }
        ))
    } else {
        anyhow::bail!("git push failed: {}", stderr)
    }
}

/// Get current git status for display in approval prompts.
pub fn get_git_status(workspace_root: &Path) -> Result<String> {
    let output = Command::new("git")
        .args(["status", "--short"])
        .current_dir(workspace_root)
        .output()
        .context("Failed to get git status")?;

    Ok(String::from_utf8_lossy(&output.stdout).to_string())
}

/// Get a diff summary for display in approval prompts.
pub fn get_git_diff_summary(workspace_root: &Path) -> Result<String> {
    let output = Command::new("git")
        .args(["diff", "--stat", "HEAD"])
        .current_dir(workspace_root)
        .output()
        .context("Failed to get git diff")?;

    Ok(String::from_utf8_lossy(&output.stdout).to_string())
}
