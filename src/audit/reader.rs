//! Audit log reader — filter and display session logs.
//!
//! Reads JSONL log files and provides filtering, summarization,
//! and pretty-printing for the `lawctl log` command.

use crate::audit::types::*;
use anyhow::{Context, Result};
use colored::Colorize;
use std::fs;
use std::path::{Path, PathBuf};

/// Reads and queries audit log files.
pub struct AuditReader {
    log_dir: PathBuf,
}

impl AuditReader {
    /// Create a reader using the default log directory.
    pub fn new() -> Result<Self> {
        let log_dir = crate::audit::logger::AuditLogger::log_directory()?;
        Ok(Self { log_dir })
    }

    /// Create a reader for a specific directory (for testing).
    pub fn with_dir(dir: impl AsRef<Path>) -> Self {
        Self {
            log_dir: dir.as_ref().to_path_buf(),
        }
    }

    /// Read all entries from a session log file.
    pub fn read_session(&self, session_id: &str) -> Result<Vec<LogEntry>> {
        let path = self.log_dir.join(format!("{}.jsonl", session_id));
        self.read_file(&path)
    }

    /// Read entries from a specific log file.
    fn read_file(&self, path: &Path) -> Result<Vec<LogEntry>> {
        let content = fs::read_to_string(path)
            .with_context(|| format!("Failed to read log file: {}", path.display()))?;

        content
            .lines()
            .filter(|line| !line.trim().is_empty())
            .enumerate()
            .map(|(i, line)| {
                serde_json::from_str(line)
                    .with_context(|| format!("Failed to parse log entry at line {}", i + 1))
            })
            .collect()
    }

    /// Read entries from the most recent session.
    pub fn read_latest_session(&self) -> Result<Vec<LogEntry>> {
        let latest = self.find_latest_session()?;
        match latest {
            Some(path) => self.read_file(&path),
            None => Ok(Vec::new()),
        }
    }

    /// Find the most recent session log file.
    fn find_latest_session(&self) -> Result<Option<PathBuf>> {
        if !self.log_dir.exists() {
            return Ok(None);
        }

        let mut entries: Vec<PathBuf> = fs::read_dir(&self.log_dir)?
            .filter_map(|e| e.ok())
            .map(|e| e.path())
            .filter(|p| p.extension().map_or(false, |e| e == "jsonl"))
            .collect();

        // Sort by modification time, most recent first
        entries.sort_by(|a, b| {
            let a_time = fs::metadata(a).and_then(|m| m.modified()).ok();
            let b_time = fs::metadata(b).and_then(|m| m.modified()).ok();
            b_time.cmp(&a_time)
        });

        Ok(entries.into_iter().next())
    }

    /// List all available session IDs.
    pub fn list_sessions(&self) -> Result<Vec<String>> {
        if !self.log_dir.exists() {
            return Ok(Vec::new());
        }

        let mut sessions: Vec<String> = fs::read_dir(&self.log_dir)?
            .filter_map(|e| e.ok())
            .filter(|e| e.path().extension().map_or(false, |ext| ext == "jsonl"))
            .filter_map(|e| {
                e.path()
                    .file_stem()
                    .map(|s| s.to_string_lossy().to_string())
            })
            .collect();

        sessions.sort();
        Ok(sessions)
    }

    /// Filter entries based on criteria.
    pub fn filter_entries(entries: &[LogEntry], filter: &LogFilter) -> Vec<LogEntry> {
        entries
            .iter()
            .filter(|e| {
                if let Some(ref session) = filter.session_id {
                    if e.session_id != *session {
                        return false;
                    }
                }
                if let Some(ref action) = filter.action {
                    if e.action != *action {
                        return false;
                    }
                }
                if let Some(ref decision_filter) = filter.decision_type {
                    match decision_filter {
                        DecisionFilter::Allowed => {
                            if !e.decision.is_allowed() {
                                return false;
                            }
                        }
                        DecisionFilter::Denied => {
                            if !e.decision.is_denied() {
                                return false;
                            }
                        }
                        DecisionFilter::Approved => {
                            if e.approved_by.is_none() {
                                return false;
                            }
                        }
                    }
                }
                true
            })
            .take(filter.limit.unwrap_or(usize::MAX))
            .cloned()
            .collect()
    }

    /// Generate a summary for a set of log entries.
    pub fn summarize(entries: &[LogEntry]) -> SessionSummary {
        let mut summary = SessionSummary::default();

        if let Some(first) = entries.first() {
            summary.session_id = first.session_id.clone();
            summary.agent = first.agent.clone();
            summary.start_time = Some(first.timestamp);
        }
        if let Some(last) = entries.last() {
            summary.end_time = Some(last.timestamp);
        }

        summary.total_actions = entries.len();
        for entry in entries {
            match &entry.decision {
                crate::policy::Decision::Allowed { .. } => summary.allowed += 1,
                crate::policy::Decision::Denied { .. } => summary.denied += 1,
                crate::policy::Decision::RequiresApproval { .. } => {
                    if entry.approved_by.is_some() {
                        summary.approved += 1;
                    } else {
                        summary.denied += 1;
                    }
                }
            }
        }

        summary
    }

    /// Pretty-print a log entry for terminal display.
    pub fn format_entry(entry: &LogEntry) -> String {
        let timestamp = entry.timestamp.format("%H:%M:%S").to_string();
        let decision_str = match &entry.decision {
            crate::policy::Decision::Allowed { .. } => "ALLOWED".green().to_string(),
            crate::policy::Decision::Denied { .. } => "DENIED".red().to_string(),
            crate::policy::Decision::RequiresApproval { .. } => {
                if entry.approved_by.is_some() {
                    "APPROVED".yellow().to_string()
                } else {
                    "PENDING".yellow().to_string()
                }
            }
        };

        let action = format!("{}", entry.action);
        let mut line = format!(
            "[{}] {} {} -> {}",
            timestamp.dimmed(),
            decision_str,
            action.bold(),
            entry.target
        );

        if let Some(ref rule) = entry.policy_rule {
            line.push_str(&format!(" ({})", rule.dimmed()));
        }

        line
    }
}
