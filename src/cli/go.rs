//! `lawctl go` — the one command vibecoders need to remember.
//!
//! Smart defaults:
//! - If no command given, tries to detect and launch the agent
//! - Finds .lawctl.yaml automatically (walks up directories)
//! - If no policy exists, runs setup wizard first
//! - No flags needed for the common case

use crate::cli::run::RunOptions;
use anyhow::Result;
use colored::Colorize;
use std::path::{Path, PathBuf};

/// Auto-detect which agent is installed, in preference order.
fn detect_agent() -> Option<(&'static str, Vec<String>)> {
    let agents: &[(&str, &[&str])] = &[
        ("Claude Code", &["claude"]),
        ("Cursor", &["cursor"]),
        ("Codex", &["codex"]),
        ("Aider", &["aider"]),
    ];

    for (name, cmd_parts) in agents {
        let binary = cmd_parts[0];
        if which_exists(binary) {
            return Some((
                name,
                cmd_parts.iter().map(|s| s.to_string()).collect(),
            ));
        }
    }
    None
}

fn which_exists(binary: &str) -> bool {
    std::process::Command::new("which")
        .arg(binary)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

/// Find .lawctl.yaml by walking up from the current directory.
fn find_policy_file() -> Option<PathBuf> {
    let mut dir = std::env::current_dir().ok()?;
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

/// Run the `lawctl go` command.
pub async fn run_go(explicit_command: Vec<String>) -> Result<()> {
    // Step 1: Find or create policy
    let policy_path = match find_policy_file() {
        Some(path) => path,
        None => {
            // No policy found — run setup wizard
            println!();
            println!(
                "  {} No policy file found. Let's set one up first!",
                "ℹ".blue()
            );
            println!();
            crate::cli::setup::run_setup()?;

            // After setup, try to find the policy again
            find_policy_file().ok_or_else(|| {
                anyhow::anyhow!(
                    "Setup completed but no .lawctl.yaml was created. Try running lawctl setup."
                )
            })?
        }
    };

    // Step 2: Figure out what agent command to run
    let agent_command = if !explicit_command.is_empty() {
        explicit_command
    } else {
        // Try to auto-detect the agent
        match detect_agent() {
            Some((name, cmd)) => {
                println!();
                println!(
                    "  {} Detected {}, launching...",
                    "▶".green(),
                    name.bold()
                );
                cmd
            }
            None => {
                println!();
                println!(
                    "  {} Couldn't detect an agent on your system.",
                    "?".yellow()
                );
                println!();
                println!("  Run with your agent command:");
                println!("    {}", "lawctl go -- <your agent command>".bold());
                println!();
                println!("  Examples:");
                println!("    lawctl go -- claude");
                println!("    lawctl go -- cursor");
                println!("    lawctl go -- aider");
                println!();
                return Ok(());
            }
        }
    };

    // Step 3: Detect agent name from command for nicer logging
    let agent_name = agent_command
        .first()
        .map(|s| {
            Path::new(s)
                .file_name()
                .unwrap_or_default()
                .to_string_lossy()
                .to_string()
        })
        .unwrap_or_else(|| "agent".to_string());

    // Step 4: Run with standard options
    let options = RunOptions {
        policy_path,
        agent_command,
        agent_name,
        ..Default::default()
    };

    crate::cli::run::run_agent(options).await
}
