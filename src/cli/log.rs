//! `lawctl log` — browse and display audit logs.
//!
//! Shows what happened in a session: every action the agent attempted,
//! what was allowed, what was blocked, and what required approval.
//! This is the "what just happened?" command.

use crate::audit::{AuditReader, DecisionFilter, LogFilter};
use crate::policy::types::Action;
use anyhow::{Context, Result};
use colored::Colorize;

/// Run the `lawctl log` command.
pub fn run_log(
    session_id: Option<&str>,
    action_filter: Option<&str>,
    decision_filter: Option<&str>,
    limit: Option<usize>,
    summary_only: bool,
) -> Result<()> {
    let reader = AuditReader::new().context("Failed to initialize log reader")?;

    // Read entries
    let entries = if let Some(sid) = session_id {
        reader
            .read_session(sid)
            .with_context(|| format!("Failed to read session: {}", sid))?
    } else {
        let entries = reader.read_latest_session()?;
        if entries.is_empty() {
            println!();
            println!("  {} No audit logs found.", "ℹ".blue());
            println!("  Run an agent through lawctl first:");
            println!("    {}", "lawctl run -- <your agent command>".dimmed());
            println!();
            return Ok(());
        }
        entries
    };

    // Apply filters
    let filter = LogFilter {
        session_id: session_id.map(|s| s.to_string()),
        action: action_filter.and_then(Action::from_str_loose),
        decision_type: decision_filter.map(|d| match d.to_lowercase().as_str() {
            "allowed" | "allow" => DecisionFilter::Allowed,
            "denied" | "deny" => DecisionFilter::Denied,
            "approved" | "approval" => DecisionFilter::Approved,
            _ => DecisionFilter::Allowed, // fallback
        }),
        limit,
    };

    let filtered = AuditReader::filter_entries(&entries, &filter);

    if summary_only {
        // Just show the summary
        let summary = AuditReader::summarize(&entries);
        println!();
        println!(
            "  {} Session: {}",
            "📋".to_string().bold(),
            summary.session_id.cyan()
        );
        println!("  Agent: {}", summary.agent);
        println!();
        println!(
            "  {} total | {} allowed | {} denied | {} approved",
            summary.total_actions.to_string().bold(),
            summary.allowed.to_string().green().bold(),
            summary.denied.to_string().red().bold(),
            summary.approved.to_string().yellow().bold(),
        );

        if let (Some(start), Some(end)) = (summary.start_time, summary.end_time) {
            let duration = end - start;
            println!("  Duration: {}", format_duration(duration.num_seconds()));
        }
        println!();
    } else {
        // Show individual entries
        println!();
        if let Some(first) = filtered.first() {
            println!(
                "  Session: {} | Agent: {}",
                first.session_id.cyan(),
                first.agent
            );
            println!();
        }

        for entry in &filtered {
            println!("  {}", AuditReader::format_entry(entry));
        }

        // Show summary at the bottom
        let summary = AuditReader::summarize(&entries);
        println!();
        println!(
            "  {} {}",
            "─".repeat(40).dimmed(),
            summary.one_line().dimmed()
        );
        println!();
    }

    Ok(())
}

/// List available sessions.
pub fn run_log_list() -> Result<()> {
    let reader = AuditReader::new()?;
    let sessions = reader.list_sessions()?;

    if sessions.is_empty() {
        println!();
        println!("  {} No sessions found.", "ℹ".blue());
        println!();
        return Ok(());
    }

    println!();
    println!("  {} Available sessions:", "📋".to_string().bold());
    println!();
    for session in &sessions {
        println!("  • {}", session);
    }
    println!();
    println!("  View a session: {}", "lawctl log --session <id>".dimmed());
    println!();

    Ok(())
}

fn format_duration(seconds: i64) -> String {
    if seconds < 60 {
        format!("{}s", seconds)
    } else if seconds < 3600 {
        format!("{}m {}s", seconds / 60, seconds % 60)
    } else {
        format!("{}h {}m", seconds / 3600, (seconds % 3600) / 60)
    }
}
