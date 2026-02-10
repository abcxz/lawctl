//! Types for the approval flow.

use crate::policy::types::Action;

/// A request for human approval, shown in the terminal UI.
#[derive(Debug, Clone)]
pub struct ApprovalRequest {
    /// What action requires approval
    pub action: Action,
    /// Target of the action
    pub target: String,
    /// Preview of the payload (truncated diff, command, etc.)
    pub payload_preview: Option<String>,
    /// Why approval is needed (from the policy rule)
    pub reason: String,
}

/// Response from the human reviewer.
#[derive(Debug, Clone)]
pub struct ApprovalResponse {
    /// Whether the action was approved
    pub approved: bool,
    /// Who approved it (e.g., "terminal", "webhook")
    pub approved_by: Option<String>,
}
