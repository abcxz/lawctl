//! `lawctl setup` — interactive onboarding wizard for non-dev users.
//!
//! This is the first thing a new user sees. It asks plain-English questions,
//! generates a policy file, and auto-installs agent hooks so protection
//! is invisible from that point on.
//!
//! Flow:
//!   1. Welcome message explaining what lawctl does
//!   2. "What agent are you using?" (auto-detect if possible)
//!   3. "How careful should we be?" (protection level)
//!   4. Generate policy + install agent hook
//!   5. Done — user just uses their agent normally

use anyhow::{Context, Result};
use colored::Colorize;
use std::io::{self, Write};
use std::path::{Path, PathBuf};

/// Protection levels — maps to policy templates.
#[derive(Debug, Clone, Copy)]
enum ProtectionLevel {
    Standard,
    Strict,
    Relaxed,
}

impl ProtectionLevel {
    fn template_name(&self) -> &str {
        match self {
            ProtectionLevel::Standard => "safe-dev",
            ProtectionLevel::Strict => "safe-ci",
            ProtectionLevel::Relaxed => "permissive",
        }
    }
}

/// Run the interactive setup wizard.
pub fn run_setup() -> Result<()> {
    let cwd = std::env::current_dir().context("Failed to get current directory")?;

    // Check if already set up
    let policy_path = cwd.join(".lawctl.yaml");
    if policy_path.exists() {
        println!();
        println!("  {} You're already set up!", "✓".green().bold());
        println!(
            "  Policy file: {}",
            policy_path.display().to_string().dimmed()
        );
        println!();
        println!("  Just use your agent normally — lawctl is watching.");
        println!();
        println!(
            "  To reconfigure, delete .lawctl.yaml and run {} again.",
            "lawctl setup".bold()
        );
        println!();
        return Ok(());
    }

    // ── Welcome ──
    print_welcome();

    // ── Step 1: Detect / ask about agent ──
    let agent = ask_agent()?;

    // ── Step 2: Ask protection level ──
    let level = ask_protection_level()?;

    // ── Step 3: Generate policy ──
    let template_name = level.template_name();
    let yaml_content = crate::policy::defaults::get_default_policy(template_name)
        .expect("Built-in template should always exist");

    std::fs::write(&policy_path, yaml_content)
        .with_context(|| format!("Failed to write {}", policy_path.display()))?;

    // ── Step 4: Install agent hook ──
    let hook_installed = match agent.as_deref() {
        Some("claude-code") => match install_claude_code_hook() {
            Ok(()) => true,
            Err(e) => {
                eprintln!(
                    "  {} Couldn't auto-install Claude Code hook: {}",
                    "⚠".yellow(),
                    e
                );
                false
            }
        },
        _ => false,
    };

    // ── Step 5: Show what we did ──
    print_setup_complete(&policy_path, level, agent.as_deref(), hook_installed);

    Ok(())
}

/// Print the welcome banner.
fn print_welcome() {
    println!();
    println!("  {}", "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━".dimmed());
    println!(
        "  {}  {}",
        "lawctl".bold(),
        "— keep your AI agent from breaking things".dimmed()
    );
    println!("  {}", "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━".dimmed());
    println!();
    println!("  Lawctl watches what your AI agent does and stops it from:");
    println!("    - Deleting important files");
    println!("    - Leaking your secrets (.env, API keys, SSH keys)");
    println!("    - Running dangerous commands");
    println!("    - Pushing code without your OK");
    println!();
    println!("  Let's set it up. This takes about 30 seconds.");
    println!();
}

/// Detect if an agent binary is on PATH.
fn agent_is_installed(cmd: &str) -> bool {
    std::process::Command::new("which")
        .arg(cmd)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

/// Ask which agent they're using.
fn ask_agent() -> Result<Option<String>> {
    // Show what we found
    let has_claude = agent_is_installed("claude");
    let has_cursor = agent_is_installed("cursor");

    if has_claude || has_cursor {
        println!("  {} Found on your machine:", "?".cyan().bold());
        if has_claude {
            println!("    {} Claude Code", "•".green());
        }
        if has_cursor {
            println!("    {} Cursor", "•".green());
        }
        println!();
    }

    println!("  {} What AI agent are you using?", "1".cyan().bold());
    println!();

    let options = [
        ("Claude Code", "claude-code"),
        ("Cursor", "cursor"),
        ("Codex (OpenAI)", "codex"),
        ("Aider", "aider"),
        ("Something else / not sure", "other"),
    ];

    for (i, (label, _)) in options.iter().enumerate() {
        let num = (i + 1).to_string();
        let marker = match label {
            &"Claude Code" if has_claude => num.green().bold().to_string(),
            &"Cursor" if has_cursor => num.green().bold().to_string(),
            _ => num.cyan().bold().to_string(),
        };
        println!("    {} {}", marker, label);
    }

    println!();
    let choice = read_number_choice(options.len())?;
    let agent_name = options[choice].1;

    if agent_name == "other" {
        println!();
        println!("    No problem — lawctl works with any agent.");
        Ok(None)
    } else {
        Ok(Some(agent_name.to_string()))
    }
}

/// Ask protection level.
fn ask_protection_level() -> Result<ProtectionLevel> {
    println!();
    println!("  {} How careful should lawctl be?", "2".cyan().bold());
    println!();
    println!(
        "    {} {}  {}",
        "1".cyan().bold(),
        "Standard".bold(),
        "(recommended)".dimmed()
    );
    println!("      Blocks dangerous stuff, asks before git push");
    println!();
    println!("    {} {}", "2".cyan().bold(), "Strict".bold());
    println!("      Locks things down more — for important projects");
    println!();
    println!("    {} {}", "3".cyan().bold(), "Relaxed".bold());
    println!("      Logs everything but doesn't block much — for trying it out");
    println!();

    let choice = read_number_choice(3)?;

    Ok(match choice {
        0 => ProtectionLevel::Standard,
        1 => ProtectionLevel::Strict,
        2 => ProtectionLevel::Relaxed,
        _ => ProtectionLevel::Standard,
    })
}

/// Read a 1-based number choice from the user.
fn read_number_choice(max: usize) -> Result<usize> {
    loop {
        print!("  {} ", "→".blue());
        io::stdout().flush()?;

        let mut input = String::new();
        let bytes_read = io::stdin().read_line(&mut input)?;

        if bytes_read == 0 {
            println!("1");
            return Ok(0);
        }

        let trimmed = input.trim();
        if let Ok(n) = trimmed.parse::<usize>() {
            if n >= 1 && n <= max {
                return Ok(n - 1);
            }
        }

        println!("    {} Pick a number 1-{}", "?".yellow(), max);
    }
}

// ── Claude Code Hook Installation ──────────────────────────────────────

/// Install lawctl-hook into Claude Code's user settings.
fn install_claude_code_hook() -> Result<()> {
    let settings_path = claude_code_settings_path()?;

    // Read existing settings or start fresh
    let mut settings: serde_json::Value = if settings_path.exists() {
        let content = std::fs::read_to_string(&settings_path)
            .with_context(|| format!("Failed to read {}", settings_path.display()))?;
        serde_json::from_str(&content)
            .with_context(|| "Failed to parse Claude Code settings.json")?
    } else {
        // Create the directory if needed
        if let Some(parent) = settings_path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        serde_json::json!({})
    };

    // Find the lawctl-hook binary
    let hook_binary = find_hook_binary()?;

    // Build the hook config
    let hook_entry = serde_json::json!({
        "type": "command",
        "command": hook_binary.to_string_lossy()
    });

    let pretool_rule = serde_json::json!({
        "matcher": "Bash|Write|Edit|NotebookEdit",
        "hooks": [hook_entry]
    });

    // Merge into settings — don't clobber existing hooks
    let hooks = settings
        .as_object_mut()
        .ok_or_else(|| anyhow::anyhow!("settings.json is not an object"))?
        .entry("hooks")
        .or_insert(serde_json::json!({}));

    let hooks_obj = hooks
        .as_object_mut()
        .ok_or_else(|| anyhow::anyhow!("hooks is not an object"))?;

    // Get or create the PreToolUse array
    let pretool = hooks_obj
        .entry("PreToolUse")
        .or_insert(serde_json::json!([]));

    let pretool_arr = pretool
        .as_array_mut()
        .ok_or_else(|| anyhow::anyhow!("PreToolUse is not an array"))?;

    // Check if lawctl hook is already installed
    let already_installed = pretool_arr.iter().any(|rule| {
        rule.get("hooks")
            .and_then(|h| h.as_array())
            .map(|hooks| {
                hooks.iter().any(|h| {
                    h.get("command")
                        .and_then(|c| c.as_str())
                        .map(|c| c.contains("lawctl-hook"))
                        .unwrap_or(false)
                })
            })
            .unwrap_or(false)
    });

    if already_installed {
        println!("  {} Claude Code hook already installed", "✓".green());
        return Ok(());
    }

    // Add our hook
    pretool_arr.push(pretool_rule);

    // Write back
    let content = serde_json::to_string_pretty(&settings)?;
    std::fs::write(&settings_path, content)
        .with_context(|| format!("Failed to write {}", settings_path.display()))?;

    println!("  {} Installed Claude Code hook", "✓".green());
    println!("    {}", settings_path.display().to_string().dimmed());

    Ok(())
}

/// Get the path to Claude Code's user settings.json
fn claude_code_settings_path() -> Result<PathBuf> {
    let home =
        dirs::home_dir().ok_or_else(|| anyhow::anyhow!("Could not determine home directory"))?;
    Ok(home.join(".claude").join("settings.json"))
}

/// Find the lawctl-hook binary.
fn find_hook_binary() -> Result<PathBuf> {
    // Check next to the current binary first
    if let Ok(exe) = std::env::current_exe() {
        if let Some(dir) = exe.parent() {
            let hook_path = dir.join("lawctl-hook");
            if hook_path.exists() {
                return Ok(hook_path);
            }
        }
    }

    // Check common install locations
    let candidates = ["/usr/local/bin/lawctl-hook", "/usr/bin/lawctl-hook"];

    for candidate in &candidates {
        let path = PathBuf::from(candidate);
        if path.exists() {
            return Ok(path);
        }
    }

    // Check HOME/.local/bin
    if let Some(home) = dirs::home_dir() {
        let path = home.join(".local/bin/lawctl-hook");
        if path.exists() {
            return Ok(path);
        }
    }

    // Last resort: assume it's on PATH
    Ok(PathBuf::from("lawctl-hook"))
}

// ── Completion Message ─────────────────────────────────────────────────

fn print_setup_complete(
    policy_path: &Path,
    level: ProtectionLevel,
    agent: Option<&str>,
    hook_installed: bool,
) {
    println!();
    println!("  {}", "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━".dimmed());
    println!("  {} You're protected!", "✓".green().bold());
    println!("  {}", "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━".dimmed());
    println!();

    match level {
        ProtectionLevel::Standard => {
            println!("  Lawctl will now:");
            println!(
                "    {} Block agents from touching your secrets",
                "•".green()
            );
            println!("    {} Stop accidental file deletions", "•".green());
            println!("    {} Block dangerous shell commands", "•".green());
            println!("    {} Ask you before any git push", "•".yellow());
            println!("    {} Log everything the agent does", "•".blue());
        }
        ProtectionLevel::Strict => {
            println!("  Lawctl will now:");
            println!("    {} Block all git pushes", "•".red());
            println!("    {} Only allow writes to build output dirs", "•".green());
            println!("    {} Block dangerous shell commands", "•".green());
            println!("    {} Restrict network to package registries", "•".green());
            println!("    {} Log everything the agent does", "•".blue());
        }
        ProtectionLevel::Relaxed => {
            println!("  Lawctl will now:");
            println!("    {} Log everything the agent does", "•".blue());
            println!("    {} Ask you before any git push", "•".yellow());
            println!(
                "    {}",
                "  Most actions are allowed — good for getting started.".dimmed()
            );
        }
    }

    println!();

    if hook_installed && agent == Some("claude-code") {
        // The golden path — nothing more to do
        println!("  {} That's it. Just use Claude Code normally.", "→".blue());
        println!("    Lawctl runs in the background on every action.");
        println!();
        println!("  {} If lawctl blocks something, you'll see:", "ℹ".blue());
        println!(
            "    {}",
            "[lawctl] BLOCKED: write '.env' — denied by policy".dimmed()
        );
    } else if agent == Some("cursor") {
        println!("  {} To use with Cursor:", "→".blue());
        println!("    Cursor extension coming soon. For now:");
        println!("    {}", "lawctl go -- cursor".bold());
    } else {
        println!("  {} To run your agent with protection:", "→".blue());
        println!();
        match agent {
            Some(name) => println!("    {}", format!("lawctl go -- {}", name).bold()),
            None => println!("    {}", "lawctl go -- <your agent command>".bold()),
        }
    }

    println!();
    println!("  {} To see what your agent did:", "→".blue());
    println!("    {}", "lawctl log".bold());
    println!();
    println!(
        "  Policy saved to: {}",
        policy_path.display().to_string().dimmed()
    );
    println!();
}
