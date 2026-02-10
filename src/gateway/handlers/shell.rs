//! Handler for shell command execution.
//!
//! Runs commands in a controlled environment. In sandbox mode, commands
//! execute inside the container. In direct mode (for development),
//! they run on the host with the workspace as the working directory.

use anyhow::{Context, Result};
use std::path::Path;
use std::process::Command;

/// Result of a shell command execution.
#[derive(Debug)]
pub struct ShellResult {
    pub stdout: String,
    pub stderr: String,
    pub exit_code: i32,
}

impl ShellResult {
    /// Format as a combined output string for the gateway response.
    pub fn to_output(&self) -> String {
        let mut output = String::new();
        if !self.stdout.is_empty() {
            output.push_str(&self.stdout);
        }
        if !self.stderr.is_empty() {
            if !output.is_empty() {
                output.push('\n');
            }
            output.push_str("[stderr] ");
            output.push_str(&self.stderr);
        }
        if output.is_empty() {
            output = format!("(exit code: {})", self.exit_code);
        }
        output
    }
}

/// Execute a shell command in the workspace directory.
/// This is the host-side execution — in sandbox mode, this runs
/// inside the container via Docker exec.
pub fn execute_command(workspace_root: &Path, command: &str) -> Result<ShellResult> {
    let output = Command::new("sh")
        .arg("-c")
        .arg(command)
        .current_dir(workspace_root)
        .output()
        .with_context(|| format!("Failed to execute command: {}", command))?;

    Ok(ShellResult {
        stdout: String::from_utf8_lossy(&output.stdout).to_string(),
        stderr: String::from_utf8_lossy(&output.stderr).to_string(),
        exit_code: output.status.code().unwrap_or(-1),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn test_execute_simple_command() {
        let tmp = TempDir::new().unwrap();
        let result = execute_command(tmp.path(), "echo hello").unwrap();
        assert_eq!(result.stdout.trim(), "hello");
        assert_eq!(result.exit_code, 0);
    }

    #[test]
    fn test_execute_failing_command() {
        let tmp = TempDir::new().unwrap();
        let result = execute_command(tmp.path(), "false").unwrap();
        assert_ne!(result.exit_code, 0);
    }
}
