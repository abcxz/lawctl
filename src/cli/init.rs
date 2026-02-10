//! `lawctl init` — generate a starter policy file.
//!
//! Creates a `.lawctl.yaml` in the current directory with a sensible default
//! policy. Auto-detects the project type and suggests appropriate settings.
//! Designed to be the very first thing a new user runs.

use crate::policy::defaults;
use anyhow::{Context, Result};
use colored::Colorize;
use std::path::{Path, PathBuf};

/// Detect what kind of project this is based on files present.
#[derive(Debug)]
enum ProjectType {
    Rust,
    Node,
    Python,
    Go,
    Unknown,
}

impl ProjectType {
    fn detect(dir: &Path) -> Self {
        if dir.join("Cargo.toml").exists() {
            ProjectType::Rust
        } else if dir.join("package.json").exists() {
            ProjectType::Node
        } else if dir.join("pyproject.toml").exists()
            || dir.join("setup.py").exists()
            || dir.join("requirements.txt").exists()
        {
            ProjectType::Python
        } else if dir.join("go.mod").exists() {
            ProjectType::Go
        } else {
            ProjectType::Unknown
        }
    }

    fn name(&self) -> &str {
        match self {
            ProjectType::Rust => "Rust",
            ProjectType::Node => "Node.js",
            ProjectType::Python => "Python",
            ProjectType::Go => "Go",
            ProjectType::Unknown => "Unknown",
        }
    }
}

/// Run the `lawctl init` command.
pub fn run_init(template: Option<&str>, output_path: Option<&str>) -> Result<()> {
    let cwd = std::env::current_dir().context("Failed to get current directory")?;
    let project_type = ProjectType::detect(&cwd);

    let output_file = output_path
        .map(PathBuf::from)
        .unwrap_or_else(|| cwd.join(".lawctl.yaml"));

    // Check if a policy file already exists
    if output_file.exists() {
        println!(
            "{} A policy file already exists at {}",
            "⚠".yellow(),
            output_file.display()
        );
        println!("  Use --force to overwrite it, or edit it directly.");
        return Ok(());
    }

    // Select template
    let template_name = template.unwrap_or("safe-dev");
    let yaml_content = defaults::get_default_policy(template_name).ok_or_else(|| {
        let available: Vec<String> = defaults::available_templates()
            .iter()
            .map(|(name, desc)| format!("  {} — {}", name.bold(), desc))
            .collect();
        anyhow::anyhow!(
            "Unknown template '{}'. Available templates:\n{}",
            template_name,
            available.join("\n")
        )
    })?;

    // Write the policy file
    std::fs::write(&output_file, yaml_content)
        .with_context(|| format!("Failed to write policy file: {}", output_file.display()))?;

    // Print friendly output
    println!();
    println!(
        "  {} Created {}",
        "✓".green().bold(),
        output_file.display().to_string().bold()
    );
    println!();
    println!("  Detected project type: {}", project_type.name().cyan());
    println!("  Template: {}", template_name.cyan());
    println!();
    println!("  {} What this policy does:", "ℹ".blue());

    match template_name {
        "safe-dev" => {
            println!("    • Blocks agents from touching your secrets (.env, .ssh, .pem files)");
            println!("    • Prevents accidental file deletions (except /tmp and build dirs)");
            println!("    • Blocks dangerous shell commands (rm -rf, curl|bash, etc.)");
            println!("    • Requires YOUR approval before any git push");
            println!("    • Allows writes to source and test directories");
        }
        "safe-ci" => {
            println!("    • Blocks all git push operations");
            println!("    • Only allows writes to build output directories");
            println!("    • Restricts network to package registries only");
            println!("    • Blocks all file deletions");
        }
        "permissive" => {
            println!("    • Allows all actions (except git push needs approval)");
            println!("    • Logs everything the agent does");
            println!("    • Good for testing — switch to safe-dev once comfortable");
        }
        _ => {}
    }

    println!();
    println!("  {} Next steps:", "→".blue());
    println!(
        "    1. Review the policy: {}",
        format!("cat {}", output_file.display()).dimmed()
    );
    println!(
        "    2. Run your agent through lawctl: {}",
        "lawctl run -- <your agent command>".dimmed()
    );
    println!("    3. Check what happened: {}", "lawctl log".dimmed());
    println!();

    Ok(())
}
