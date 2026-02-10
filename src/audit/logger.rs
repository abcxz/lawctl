//! Audit log writer — append-only JSONL files.
//!
//! Every action gets logged, even allowed ones. The log is the product's superpower.
//! Writes to `~/.lawctl/logs/{session_id}.jsonl` — one JSON object per line.
//! Flushes after every write for crash safety.

use crate::audit::types::LogEntry;
use anyhow::{Context, Result};
use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};

/// Append-only audit logger that writes JSONL files.
pub struct AuditLogger {
    /// Path to the log file
    log_path: PathBuf,
    /// Open file handle (kept open for the session lifetime)
    file: File,
    /// Number of entries written this session
    entry_count: usize,
}

impl AuditLogger {
    /// Create a new logger for a session.
    /// Creates the log directory and file if they don't exist.
    pub fn new(session_id: &str) -> Result<Self> {
        let log_dir = Self::log_directory()?;
        fs::create_dir_all(&log_dir)
            .with_context(|| format!("Failed to create log directory: {}", log_dir.display()))?;

        let log_path = log_dir.join(format!("{}.jsonl", session_id));
        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&log_path)
            .with_context(|| format!("Failed to open log file: {}", log_path.display()))?;

        Ok(Self {
            log_path,
            file,
            entry_count: 0,
        })
    }

    /// Create a logger writing to a specific path (for testing).
    pub fn with_path(path: impl AsRef<Path>) -> Result<Self> {
        let log_path = path.as_ref().to_path_buf();
        if let Some(parent) = log_path.parent() {
            fs::create_dir_all(parent)?;
        }
        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&log_path)?;

        Ok(Self {
            log_path,
            file,
            entry_count: 0,
        })
    }

    /// Log an action. Serializes to JSON and appends to the file.
    /// Flushes immediately for crash safety.
    pub fn log(&mut self, entry: &LogEntry) -> Result<()> {
        let json = serde_json::to_string(entry).context("Failed to serialize log entry")?;
        writeln!(self.file, "{}", json).context("Failed to write log entry")?;
        self.file.flush().context("Failed to flush log file")?;
        self.entry_count += 1;
        Ok(())
    }

    /// Get the path to the log file.
    pub fn log_path(&self) -> &Path {
        &self.log_path
    }

    /// Get the number of entries written this session.
    pub fn entry_count(&self) -> usize {
        self.entry_count
    }

    /// Get the default log directory (~/.lawctl/logs/).
    pub fn log_directory() -> Result<PathBuf> {
        let home = dirs::home_dir().context("Could not determine home directory")?;
        Ok(home.join(".lawctl").join("logs"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::audit::types::LogEntry;
    use crate::policy::types::{Action, Decision};
    use chrono::Utc;
    use tempfile::TempDir;

    #[test]
    fn test_write_and_read_log() {
        let tmp = TempDir::new().unwrap();
        let log_path = tmp.path().join("test.jsonl");
        let mut logger = AuditLogger::with_path(&log_path).unwrap();

        let entry = LogEntry {
            timestamp: Utc::now(),
            session_id: "test-session".to_string(),
            agent: "test-agent".to_string(),
            action: Action::Write,
            target: "src/main.rs".to_string(),
            policy_rule: Some("allow:write:if_path_matches:src/**".to_string()),
            decision: Decision::Allowed {
                matched_rule: Some("allow:write".to_string()),
            },
            diff: Some("+new line".to_string()),
            approved_by: None,
            eval_duration_us: Some(42),
        };

        logger.log(&entry).unwrap();
        assert_eq!(logger.entry_count(), 1);

        // Verify the file contains valid JSON
        let content = fs::read_to_string(&log_path).unwrap();
        let parsed: LogEntry = serde_json::from_str(content.trim()).unwrap();
        assert_eq!(parsed.session_id, "test-session");
        assert_eq!(parsed.target, "src/main.rs");
    }

    #[test]
    fn test_append_only() {
        let tmp = TempDir::new().unwrap();
        let log_path = tmp.path().join("test.jsonl");
        let mut logger = AuditLogger::with_path(&log_path).unwrap();

        for i in 0..3 {
            let entry = LogEntry {
                timestamp: Utc::now(),
                session_id: "test".to_string(),
                agent: "test".to_string(),
                action: Action::Write,
                target: format!("file_{}.rs", i),
                policy_rule: None,
                decision: Decision::Allowed {
                    matched_rule: None,
                },
                diff: None,
                approved_by: None,
                eval_duration_us: None,
            };
            logger.log(&entry).unwrap();
        }

        assert_eq!(logger.entry_count(), 3);

        let content = fs::read_to_string(&log_path).unwrap();
        let lines: Vec<&str> = content.trim().lines().collect();
        assert_eq!(lines.len(), 3);
    }
}
