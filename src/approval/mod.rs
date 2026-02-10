pub mod terminal;
pub mod types;

use crate::approval::types::{ApprovalRequest, ApprovalResponse};
use anyhow::Result;
use async_trait::async_trait;

pub use terminal::{AutoApproval, AutoDeny, TerminalApproval};

/// Trait for approval handlers.
/// Implementations can be terminal-based, webhook-based, auto-approve, etc.
#[async_trait]
pub trait ApprovalHandler {
    async fn request_approval(&self, request: &ApprovalRequest) -> Result<ApprovalResponse>;
}
