//! Lawctl — Universal Agent Firewall
//!
//! Keeps your AI coding agent from breaking things.
//!
//! Quick start:
//!   lawctl             # first time? setup wizard. already set up? shows status.
//!   lawctl go          # run your agent with protection
//!   lawctl log         # see what your agent did
//!
//! For more info: lawctl --help

// Suppress warnings for items that are public API (used by shim/tests)
#![allow(dead_code, unused_imports)]

mod approval;
mod audit;
mod cli;
mod gateway;
mod policy;
mod sandbox;
mod utils;

use clap::{Parser, Subcommand};
use colored::Colorize;
use std::path::PathBuf;

/// Lawctl — keeps your AI agent from breaking things.
///
/// Run any AI coding agent safely. Lawctl blocks dangerous actions,
/// asks your permission before risky ones, and logs everything.
#[derive(Parser)]
#[command(
    name = "lawctl",
    version,
    about = "Keep your AI agent from breaking things",
    long_about = "Lawctl watches what your AI agent does and stops it from\n\
                  deleting files, leaking secrets, or pushing bad code.\n\n\
                  Quick start:\n  \
                  lawctl              # set up (first time) or show status\n  \
                  lawctl go           # run your agent with protection\n  \
                  lawctl log          # see what your agent did"
)]
struct Cli {
    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Subcommand)]
enum Commands {
    /// Set up lawctl for your project (interactive wizard)
    Setup,

    /// Run your agent with protection (the main command)
    Go {
        /// The agent command to run (auto-detects if not given)
        #[arg(last = true, help = "The agent command (optional — auto-detects)")]
        command: Vec<String>,
    },

    /// See what your agent did
    Log {
        /// Show a specific session
        #[arg(short, long, help = "Session ID to view")]
        session: Option<String>,

        /// Filter by action type
        #[arg(
            short,
            long,
            help = "Filter: write, delete, run_cmd, git_push, network"
        )]
        action: Option<String>,

        /// Filter by decision
        #[arg(
            short,
            long,
            help = "Filter: allowed, denied, approved"
        )]
        decision: Option<String>,

        /// Limit number of entries shown
        #[arg(short, long, help = "Max entries to show")]
        limit: Option<usize>,

        /// Show only the summary
        #[arg(long, help = "Show only the session summary")]
        summary: bool,

        /// List all available sessions
        #[arg(long, help = "List all recorded sessions")]
        list: bool,
    },

    /// Validate your policy file
    Check {
        /// Path to policy file
        #[arg(default_value = ".lawctl.yaml")]
        policy: PathBuf,
    },

    // ── Power user commands (hidden from main help) ──

    /// Create a policy file from a template [advanced]
    #[command(hide = true)]
    Init {
        #[arg(short, long, default_value = "safe-dev")]
        template: String,
        #[arg(short, long)]
        output: Option<String>,
    },

    /// Run an agent with full control over options [advanced]
    #[command(hide = true)]
    Run {
        #[arg(short, long, default_value = ".lawctl.yaml")]
        policy: PathBuf,
        #[arg(long)]
        docker: bool,
        #[arg(long, default_value = "terminal")]
        approval: String,
        #[arg(long, default_value = "agent")]
        agent: String,
        #[arg(last = true, required = true)]
        command: Vec<String>,
    },
}

#[tokio::main]
async fn main() {
    // Set up tracing (only show at RUST_LOG=debug level to keep output clean)
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::from_default_env()
                .add_directive("lawctl=warn".parse().unwrap()),
        )
        .with_target(false)
        .without_time()
        .init();

    let cli = Cli::parse();

    let result = match cli.command {
        // ── No subcommand: smart default ──
        None => run_smart_default().await,

        // ── User-facing commands ──
        Some(Commands::Setup) => cli::setup::run_setup(),

        Some(Commands::Go { command }) => cli::go::run_go(command).await,

        Some(Commands::Log {
            session,
            action,
            decision,
            limit,
            summary,
            list,
        }) => {
            if list {
                cli::log::run_log_list()
            } else {
                cli::log::run_log(
                    session.as_deref(),
                    action.as_deref(),
                    decision.as_deref(),
                    limit,
                    summary,
                )
            }
        }

        Some(Commands::Check { policy }) => run_check(&policy),

        // ── Power user commands ──
        Some(Commands::Init { template, output }) => {
            cli::init::run_init(Some(&template), output.as_deref())
        }

        Some(Commands::Run {
            policy,
            docker,
            approval,
            agent,
            command,
        }) => {
            if command.is_empty() {
                eprintln!(
                    "  {} No agent command specified.",
                    "✗".red()
                );
                eprintln!("  Usage: lawctl run -- <agent command>");
                std::process::exit(1);
            }

            let options = cli::run::RunOptions {
                policy_path: policy,
                agent_command: command,
                use_docker: docker,
                approval_mode: approval,
                agent_name: agent,
                ..Default::default()
            };

            cli::run::run_agent(options).await
        }
    };

    if let Err(e) = result {
        eprintln!();
        eprintln!("  {} {}", "✗".red().bold(), e);
        for cause in e.chain().skip(1) {
            eprintln!("  {} {}", "caused by:".dimmed(), cause);
        }
        eprintln!();
        std::process::exit(1);
    }
}

/// When user just types `lawctl` with no arguments:
/// - No policy file? → run setup wizard
/// - Has policy? → show status + quick help
async fn run_smart_default() -> anyhow::Result<()> {
    let cwd = std::env::current_dir()?;
    let policy_path = find_policy_walking_up(&cwd);

    match policy_path {
        None => {
            // First time — run the wizard
            cli::setup::run_setup()
        }
        Some(path) => {
            // Already set up — show status
            show_status(&path)
        }
    }
}

/// Find .lawctl.yaml walking up the directory tree.
fn find_policy_walking_up(start: &std::path::Path) -> Option<PathBuf> {
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

/// Show project status — what's protected, recent activity.
fn show_status(policy_path: &std::path::Path) -> anyhow::Result<()> {
    let policy = policy::parser::parse_policy_file(policy_path)?;

    println!();
    println!(
        "  {}  {}",
        "lawctl".bold(),
        "— your project is protected".green()
    );
    println!(
        "  {}",
        "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━".dimmed()
    );
    println!();
    println!(
        "  Policy: {} ({} rules)",
        policy.law.cyan(),
        policy.rules.len()
    );
    println!(
        "  File:   {}",
        policy_path.display().to_string().dimmed()
    );

    // Show recent activity if any
    if let Ok(reader) = audit::AuditReader::new() {
        if let Ok(entries) = reader.read_latest_session() {
            if !entries.is_empty() {
                let summary = audit::AuditReader::summarize(&entries);
                println!();
                println!(
                    "  Last session: {} actions ({} allowed, {} denied)",
                    summary.total_actions.to_string().bold(),
                    summary.allowed.to_string().green(),
                    summary.denied.to_string().red(),
                );
            }
        }
    }

    println!();
    println!(
        "  {}",
        "Commands:".dimmed()
    );
    println!(
        "    {}          run your agent with protection",
        "lawctl go".bold()
    );
    println!(
        "    {}         see what your agent did",
        "lawctl log".bold()
    );
    println!(
        "    {}       validate your policy",
        "lawctl check".bold()
    );
    println!(
        "    {}       reconfigure from scratch",
        "lawctl setup".bold()
    );
    println!();

    Ok(())
}

/// Run the `lawctl check` command with linting.
fn run_check(policy_path: &std::path::Path) -> anyhow::Result<()> {
    match policy::parser::parse_policy_file(policy_path) {
        Ok(p) => {
            match policy::PolicyEngine::new(p.clone()) {
                Ok(_engine) => {
                    println!();
                    println!(
                        "  {} Policy is valid!",
                        "✓".green().bold()
                    );
                    println!("  Law:   {}", p.law.cyan());
                    println!("  Rules: {}", p.rules.len());
                    println!();
                    for (i, rule) in p.rules.iter().enumerate() {
                        println!(
                            "  {}. {}",
                            i + 1,
                            rule.describe()
                        );
                    }

                    // Run the linter
                    let warnings = policy::linter::lint_policy(&p);
                    if !warnings.is_empty() {
                        println!();
                        println!(
                            "  {} {} {}:",
                            "─".repeat(20).dimmed(),
                            warnings.len(),
                            if warnings.len() == 1 {
                                "suggestion"
                            } else {
                                "suggestions"
                            }
                        );
                        println!();
                        for warning in &warnings {
                            println!("{}", warning.display());
                        }
                    } else {
                        println!();
                        println!(
                            "  {} No issues found — policy looks solid.",
                            "✓".green()
                        );
                    }

                    println!();
                    Ok(())
                }
                Err(e) => Err(e.context("Policy parsed but has invalid glob patterns")),
            }
        }
        Err(e) => Err(e),
    }
}
