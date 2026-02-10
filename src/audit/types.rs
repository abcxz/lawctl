//! Types for the Lawctl audit log system.
//!
//! Every action an agent attempts gets logged — allowed, denied, or approved.
//! The audit log is the product's superpower: full visibility into what happened.

use crate::policy::types::{Action, Decision};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// A single entry in the audit log.
/// One entry per agent action attempt.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogEntry {
    /// When this action was attempted
    pub timestamp: DateTime<Utc>,

    /// Session identifier (UUID, generated at `lawctl run` start)
    pub session_id: String,

    /// Which agent is running (e.g., "claude-code", "cursor", "codex")
    pub agent: String,

    /// What action was attempted
    pub action: Action,

    /// Target of the action (file path, git branch, URL, command string)
    pub target: String,

    /// Which policy rule matched (if any)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub policy_rule: Option<String>,

    /// The decision that was made
    pub decision: Decision,

    /// For file writes: the diff that was submitted
    #[serde(skip_serializing_if = "Option::is_none")]
    pub diff: Option<String>,

    /// For require_approval actions: who approved it
    #[serde(skip_serializing_if = "Option::is_none")]
    pub approved_by: Option<String>,

    /// How long the policy evaluation took (microseconds)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub eval_duration_us: Option<u64>,
}

/// Summary statistics for a session's audit log.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SessionSummary {
    pub session_id: String,
    pub agent: String,
    pub total_actions: usize,
    pub allowed: usize,
    pub denied: usize,
    pub approved: usize,
    pub start_time: Option<DateTime<Utc>>,
    pub end_time: Option<DateTime<Utc>>,
}

impl SessionSummary {
    /// Format as a human-readable one-liner for terminal output.
    pub fn one_line(&self) -> String {
        format!(
            "{} actions | {} allowed | {} denied | {} approved",
            self.total_actions, self.allowed, self.denied, self.approved
        )
    }
}

/// Filter criteria for querying audit logs.
#[derive(Debug, Clone, Default)]
pub struct LogFilter {
    pub session_id: Option<String>,
    pub action: Option<Action>,
    pub decision_type: Option<DecisionFilter>,
    pub limit: Option<usize>,
}

/// Filter for decision types in log queries.
#[derive(Debug, Clone)]
pub enum DecisionFilter {
    Allowed,
    Denied,
    Approved,
}
