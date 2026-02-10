//! Gateway server — the security boundary between agent and host.
//!
//! Listens on a Unix domain socket (mounted into the container at /tmp/lawctl.sock).
//! The agent sends JSON requests over this socket, and the gateway:
//! 1. Evaluates the request against the policy
//! 2. If allowed: executes the action on the host side
//! 3. If denied: returns an error to the agent
//! 4. If requires_approval: pauses and asks the human
//! 5. Logs everything regardless of outcome

use crate::approval::ApprovalHandler;
use crate::audit::{AuditLogger, LogEntry};
use crate::gateway::handlers;
use crate::gateway::protocol::{GatewayRequest, GatewayResponse};
use crate::policy::{ActionContext, Decision, PolicyEngine};
use anyhow::{Context, Result};
use chrono::Utc;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::UnixListener;
use tokio::sync::Mutex;

/// The gateway server that mediates all agent actions.
pub struct GatewayServer {
    /// Path to the Unix socket
    socket_path: PathBuf,
    /// The policy engine for evaluating actions
    engine: Arc<PolicyEngine>,
    /// Workspace root on the host filesystem
    workspace_root: PathBuf,
    /// Session ID for audit logging
    session_id: String,
    /// Agent name for logging
    agent_name: String,
    /// Audit logger
    logger: Arc<Mutex<AuditLogger>>,
    /// Approval handler for require_approval actions
    approval_handler: Arc<dyn ApprovalHandler + Send + Sync>,
}

impl GatewayServer {
    pub fn new(
        socket_path: impl AsRef<Path>,
        engine: PolicyEngine,
        workspace_root: impl AsRef<Path>,
        session_id: String,
        agent_name: String,
        logger: AuditLogger,
        approval_handler: Arc<dyn ApprovalHandler + Send + Sync>,
    ) -> Self {
        Self {
            socket_path: socket_path.as_ref().to_path_buf(),
            engine: Arc::new(engine),
            workspace_root: workspace_root.as_ref().to_path_buf(),
            session_id,
            agent_name,
            logger: Arc::new(Mutex::new(logger)),
            approval_handler,
        }
    }

    /// Start the gateway server. Listens for connections and handles requests.
    pub async fn run(&self) -> Result<()> {
        // Remove existing socket if present
        if self.socket_path.exists() {
            std::fs::remove_file(&self.socket_path)?;
        }

        let listener = UnixListener::bind(&self.socket_path)
            .with_context(|| format!("Failed to bind socket: {}", self.socket_path.display()))?;

        tracing::info!(
            "Gateway listening on {}",
            self.socket_path.display()
        );

        loop {
            match listener.accept().await {
                Ok((stream, _addr)) => {
                    let engine = self.engine.clone();
                    let workspace = self.workspace_root.clone();
                    let session_id = self.session_id.clone();
                    let agent_name = self.agent_name.clone();
                    let logger = self.logger.clone();
                    let approval = self.approval_handler.clone();

                    tokio::spawn(async move {
                        if let Err(e) = handle_connection(
                            stream,
                            engine,
                            workspace,
                            session_id,
                            agent_name,
                            logger,
                            approval,
                        )
                        .await
                        {
                            tracing::error!("Connection handler error: {}", e);
                        }
                    });
                }
                Err(e) => {
                    tracing::error!("Failed to accept connection: {}", e);
                }
            }
        }
    }
}

/// Handle a single connection from an agent.
async fn handle_connection(
    stream: tokio::net::UnixStream,
    engine: Arc<PolicyEngine>,
    workspace_root: PathBuf,
    session_id: String,
    agent_name: String,
    logger: Arc<Mutex<AuditLogger>>,
    approval_handler: Arc<dyn ApprovalHandler + Send + Sync>,
) -> Result<()> {
    let (reader, mut writer) = stream.into_split();
    let mut reader = BufReader::new(reader);
    let mut line = String::new();

    loop {
        line.clear();
        let bytes_read = reader.read_line(&mut line).await?;
        if bytes_read == 0 {
            break; // Connection closed
        }

        let request: GatewayRequest = match serde_json::from_str(line.trim()) {
            Ok(req) => req,
            Err(e) => {
                let error_response = GatewayResponse::internal_error(
                    "unknown".to_string(),
                    format!("Invalid request JSON: {}", e),
                );
                let json = serde_json::to_string(&error_response)?;
                writer.write_all(json.as_bytes()).await?;
                writer.write_all(b"\n").await?;
                continue;
            }
        };

        let response = process_request(
            &request,
            &engine,
            &workspace_root,
            &session_id,
            &agent_name,
            &logger,
            &approval_handler,
        )
        .await;

        let json = serde_json::to_string(&response)?;
        writer.write_all(json.as_bytes()).await?;
        writer.write_all(b"\n").await?;
        writer.flush().await?;
    }

    Ok(())
}

/// Process a single gateway request.
async fn process_request(
    request: &GatewayRequest,
    engine: &PolicyEngine,
    workspace_root: &Path,
    session_id: &str,
    agent_name: &str,
    logger: &Mutex<AuditLogger>,
    approval_handler: &Arc<dyn ApprovalHandler + Send + Sync>,
) -> GatewayResponse {
    // Build action context for policy evaluation
    let mut context = ActionContext::new(&request.target);
    if let Some(ref payload) = request.payload {
        match request.action {
            crate::policy::Action::Write => {
                context = context.with_diff(payload.clone());
            }
            crate::policy::Action::RunCmd => {
                context = context.with_command(payload.clone());
            }
            crate::policy::Action::Network => {
                if let Some(domain) =
                    handlers::network::extract_domain(payload)
                {
                    context = context.with_domain(domain);
                }
            }
            _ => {}
        }
    }

    // Evaluate against policy
    let start = std::time::Instant::now();
    let decision = engine.evaluate(&request.action, &context);
    let eval_duration = start.elapsed().as_micros() as u64;

    // Handle the decision
    let (response, final_decision, approved_by) = match &decision {
        Decision::Allowed { .. } => {
            let result = execute_action(request, workspace_root).await;
            match result {
                Ok(output) => (
                    GatewayResponse::allowed(request.request_id.clone(), output),
                    decision.clone(),
                    None,
                ),
                Err(e) => (
                    GatewayResponse::internal_error(
                        request.request_id.clone(),
                        e.to_string(),
                    ),
                    decision.clone(),
                    None,
                ),
            }
        }
        Decision::Denied { reason, .. } => (
            GatewayResponse::denied(request.request_id.clone(), reason.clone()),
            decision.clone(),
            None,
        ),
        Decision::RequiresApproval { reason, .. } => {
            // Ask the human
            let approval_request = crate::approval::types::ApprovalRequest {
                action: request.action.clone(),
                target: request.target.clone(),
                payload_preview: request
                    .payload
                    .as_ref()
                    .map(|p| truncate_preview(p, 500)),
                reason: reason.clone(),
            };

            match approval_handler.request_approval(&approval_request).await {
                Ok(approval_response) => {
                    if approval_response.approved {
                        let result = execute_action(request, workspace_root).await;
                        match result {
                            Ok(output) => (
                                GatewayResponse::allowed(request.request_id.clone(), output),
                                Decision::Allowed {
                                    matched_rule: Some("approved by human".to_string()),
                                },
                                Some(
                                    approval_response
                                        .approved_by
                                        .unwrap_or_else(|| "terminal".to_string()),
                                ),
                            ),
                            Err(e) => (
                                GatewayResponse::internal_error(
                                    request.request_id.clone(),
                                    e.to_string(),
                                ),
                                decision.clone(),
                                None,
                            ),
                        }
                    } else {
                        (
                            GatewayResponse::denied(
                                request.request_id.clone(),
                                "Denied by human reviewer",
                            ),
                            Decision::Denied {
                                reason: "Denied by human reviewer".to_string(),
                                matched_rule: Some("human review".to_string()),
                            },
                            None,
                        )
                    }
                }
                Err(e) => (
                    GatewayResponse::denied(
                        request.request_id.clone(),
                        format!("Approval flow error: {}", e),
                    ),
                    Decision::Denied {
                        reason: format!("Approval flow error: {}", e),
                        matched_rule: None,
                    },
                    None,
                ),
            }
        }
    };

    // Log the action (always, regardless of outcome)
    let entry = LogEntry {
        timestamp: Utc::now(),
        session_id: session_id.to_string(),
        agent: agent_name.to_string(),
        action: request.action.clone(),
        target: request.target.clone(),
        policy_rule: match &final_decision {
            Decision::Allowed { matched_rule, .. } => matched_rule.clone(),
            Decision::Denied { matched_rule, .. } => matched_rule.clone(),
            Decision::RequiresApproval { matched_rule, .. } => matched_rule.clone(),
        },
        decision: final_decision,
        diff: request.payload.clone(),
        approved_by,
        eval_duration_us: Some(eval_duration),
    };

    if let Err(e) = logger.lock().await.log(&entry) {
        tracing::error!("Failed to write audit log: {}", e);
    }

    response
}

/// Execute an allowed action on the host side.
async fn execute_action(request: &GatewayRequest, workspace_root: &Path) -> Result<String> {
    match request.action {
        crate::policy::Action::Write => {
            let content = request
                .payload
                .as_deref()
                .unwrap_or("");
            handlers::file_write::execute_write(workspace_root, &request.target, content)
        }
        crate::policy::Action::Delete => {
            handlers::file_delete::execute_delete(workspace_root, &request.target)
        }
        crate::policy::Action::RunCmd => {
            let command = request
                .payload
                .as_deref()
                .unwrap_or(&request.target);
            let result = handlers::shell::execute_command(workspace_root, command)?;
            Ok(result.to_output())
        }
        crate::policy::Action::GitPush => {
            handlers::git::execute_git_push(workspace_root, &request.target)
        }
        crate::policy::Action::Network => {
            let url = request
                .payload
                .as_deref()
                .unwrap_or(&request.target);
            handlers::network::validate_network_request(url)
        }
    }
}

/// Truncate a string for preview display.
fn truncate_preview(s: &str, max_len: usize) -> String {
    if s.len() <= max_len {
        s.to_string()
    } else {
        format!("{}... ({} chars total)", &s[..max_len], s.len())
    }
}
