//! Gateway IPC protocol types.
//!
//! Defines the JSON messages exchanged between the agent (inside the sandbox)
//! and the Lawctl gateway (on the host side) over a Unix domain socket.
//!
//! The agent sends GatewayRequests, Lawctl evaluates them against the policy,
//! and returns GatewayResponses.

use crate::policy::types::Action;
use serde::{Deserialize, Serialize};

/// A request from the agent to perform an action.
/// Sent over the Unix domain socket as a JSON line.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GatewayRequest {
    /// Unique request ID (for correlating responses)
    pub request_id: String,

    /// What action the agent wants to perform
    pub action: Action,

    /// Target of the action:
    /// - For file operations: the file path
    /// - For git_push: the branch name
    /// - For run_cmd: a description (the actual command goes in payload)
    /// - For network: the URL
    pub target: String,

    /// Additional payload:
    /// - For file_write: the diff content
    /// - For run_cmd: the full command string
    /// - For file_delete: None
    /// - For git_push: optional commit message
    #[serde(skip_serializing_if = "Option::is_none")]
    pub payload: Option<String>,
}

/// A response from Lawctl back to the agent.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GatewayResponse {
    /// Matches the request_id from the request
    pub request_id: String,

    /// Whether the action was allowed
    pub allowed: bool,

    /// If denied or pending: why
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,

    /// If allowed: the result of the action
    /// - For run_cmd: stdout + stderr
    /// - For file operations: "ok"
    /// - For git_push: push output
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result: Option<String>,
}

impl GatewayResponse {
    /// Create an "allowed" response with a result.
    pub fn allowed(request_id: String, result: impl Into<String>) -> Self {
        Self {
            request_id,
            allowed: true,
            error: None,
            result: Some(result.into()),
        }
    }

    /// Create a "denied" response with a reason.
    pub fn denied(request_id: String, reason: impl Into<String>) -> Self {
        Self {
            request_id,
            allowed: false,
            error: Some(reason.into()),
            result: None,
        }
    }

    /// Create an "error" response for internal failures.
    pub fn internal_error(request_id: String, error: impl Into<String>) -> Self {
        Self {
            request_id,
            allowed: false,
            error: Some(format!("Internal error: {}", error.into())),
            result: None,
        }
    }
}
