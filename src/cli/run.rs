//! `lawctl run` — the main command that wraps an agent in the sandbox.
//!
//! This is the core user flow:
//! 1. Parse the policy file
//! 2. Start the gateway server (Unix socket)
//! 3. Start the sandbox (Docker or direct mode for development)
//! 4. Launch the agent command inside the sandbox
//! 5. Handle gateway requests until the agent exits
//! 6. Print session summary

use crate::approval::{AutoApproval, AutoDeny, TerminalApproval};
use crate::audit::AuditLogger;
use crate::gateway::GatewayServer;
use crate::policy::{parser, PolicyEngine};
use anyhow::{Context, Result};
use colored::Colorize;
use std::path::{Path, PathBuf};
use std::sync::Arc;

/// Options for the `lawctl run` command.
#[derive(Debug)]
pub struct RunOptions {
    /// Path to the policy file (default: .lawctl.yaml)
    pub policy_path: PathBuf,
    /// The agent command to run
    pub agent_command: Vec<String>,
    /// Workspace directory (default: current directory)
    pub workspace: PathBuf,
    /// Whether to use Docker sandbox (false = direct mode for dev)
    pub use_docker: bool,
    /// Approval mode: "terminal", "auto-approve", "auto-deny"
    pub approval_mode: String,
    /// Session ID override (default: auto-generated UUID)
    pub session_id: Option<String>,
    /// Agent name for logging
    pub agent_name: String,
}

impl Default for RunOptions {
    fn default() -> Self {
        Self {
            policy_path: PathBuf::from(".lawctl.yaml"),
            agent_command: vec![],
            workspace: std::env::current_dir().unwrap_or_else(|_| PathBuf::from(".")),
            use_docker: false, // Direct mode by default for v1
            approval_mode: "terminal".to_string(),
            session_id: None,
            agent_name: "unknown-agent".to_string(),
        }
    }
}

/// Run the `lawctl run` command.
pub async fn run_agent(options: RunOptions) -> Result<()> {
    // Generate session ID
    let session_id = options
        .session_id
        .clone()
        .unwrap_or_else(|| uuid::Uuid::new_v4().to_string());

    println!();
    println!(
        "  {} Lawctl v{}",
        "⚖".to_string().bold(),
        env!("CARGO_PKG_VERSION")
    );
    println!("  Session: {}", session_id[..8].cyan());

    // Step 1: Parse policy
    let policy_path = if options.policy_path.is_absolute() {
        options.policy_path.clone()
    } else {
        options.workspace.join(&options.policy_path)
    };

    println!(
        "  Policy:  {}",
        policy_path
            .file_name()
            .unwrap_or_default()
            .to_string_lossy()
            .cyan()
    );

    let policy = parser::parse_policy_file(&policy_path)?;
    let engine = PolicyEngine::new(policy)?;

    println!("  Law:     {}", engine.policy_name().cyan());
    println!("  Rules:   {}", engine.policy().rules.len());

    // Step 2: Set up audit logger
    let logger = AuditLogger::new(&session_id)?;
    println!(
        "  Log:     {}",
        logger.log_path().display().to_string().dimmed()
    );

    // Step 3: Set up approval handler
    let approval_handler: Arc<dyn crate::approval::ApprovalHandler + Send + Sync> =
        match options.approval_mode.as_str() {
            "auto-approve" | "auto" => Arc::new(AutoApproval),
            "auto-deny" | "deny" => Arc::new(AutoDeny),
            _ => Arc::new(TerminalApproval::new()),
        };

    // Step 4: Set up gateway socket
    let socket_path = PathBuf::from(format!("/tmp/lawctl-{}.sock", &session_id[..8]));

    println!("  Socket:  {}", socket_path.display().to_string().dimmed());
    println!();

    let gateway = GatewayServer::new(
        &socket_path,
        engine,
        &options.workspace,
        session_id.clone(),
        options.agent_name.clone(),
        logger,
        approval_handler,
    );

    // Step 5: Start gateway and agent
    if options.use_docker {
        println!("  {} Starting Docker sandbox...", "→".blue());
        run_with_docker(gateway, &options, &socket_path, &session_id).await?;
    } else {
        println!("  {} Running in direct mode (no sandbox)", "→".blue());
        println!(
            "  {}",
            "  For full isolation, use: lawctl run --docker -- <command>".dimmed()
        );
        println!();
        run_direct(gateway, &options, &socket_path).await?;
    }

    // Step 6: Print summary
    print_session_summary(&session_id)?;

    // Cleanup socket
    if socket_path.exists() {
        let _ = std::fs::remove_file(&socket_path);
    }

    Ok(())
}

/// Run agent in direct mode (no Docker — for development and quick use).
/// The gateway still enforces the policy, but the agent runs on the host directly.
async fn run_direct(
    gateway: GatewayServer,
    options: &RunOptions,
    socket_path: &Path,
) -> Result<()> {
    // Start the gateway in the background
    let gateway_handle = tokio::spawn(async move {
        if let Err(e) = gateway.run().await {
            tracing::error!("Gateway error: {}", e);
        }
    });

    // Wait a moment for the socket to be ready
    tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

    // Run the agent command
    let cmd = options.agent_command.join(" ");
    println!("  {} Running: {}", "▶".green(), cmd.bold());
    println!();

    let mut child = tokio::process::Command::new("sh")
        .arg("-c")
        .arg(&cmd)
        .env("LAWCTL_SOCKET", socket_path.to_string_lossy().as_ref())
        .env(
            "LAWCTL_WORKSPACE",
            options.workspace.to_string_lossy().as_ref(),
        )
        .current_dir(&options.workspace)
        .spawn()
        .with_context(|| format!("Failed to start agent: {}", cmd))?;

    let status = child.wait().await?;

    // Give gateway a moment to finish processing
    tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
    gateway_handle.abort();

    if !status.success() {
        println!(
            "\n  {} Agent exited with code: {}",
            "⚠".yellow(),
            status.code().unwrap_or(-1)
        );
    }

    Ok(())
}

/// Run agent inside a Docker sandbox.
async fn run_with_docker(
    gateway: GatewayServer,
    options: &RunOptions,
    socket_path: &Path,
    session_id: &str,
) -> Result<()> {
    use crate::sandbox::{DockerSandbox, SandboxConfig};

    let sandbox_config = SandboxConfig {
        workspace_path: options.workspace.clone(),
        socket_path: socket_path.to_path_buf(),
        command: vec![
            "sh".to_string(),
            "-c".to_string(),
            options.agent_command.join(" "),
        ],
        container_name: Some(format!("lawctl-{}", &session_id[..8])),
        ..Default::default()
    };

    let mut sandbox = DockerSandbox::new(sandbox_config)
        .await
        .context("Failed to initialize Docker sandbox")?;

    // Start gateway
    let gateway_handle = tokio::spawn(async move {
        if let Err(e) = gateway.run().await {
            tracing::error!("Gateway error: {}", e);
        }
    });

    // Start container
    let container_id = sandbox.start().await?;
    println!("  Container: {}", container_id[..12].dimmed());
    println!();

    // Wait for container to finish
    let exit_code = sandbox.wait().await?;

    // Cleanup
    sandbox.cleanup().await?;
    gateway_handle.abort();

    if exit_code != 0 {
        println!("\n  {} Agent exited with code: {}", "⚠".yellow(), exit_code);
    }

    Ok(())
}

/// Print the session summary after the agent finishes.
fn print_session_summary(session_id: &str) -> Result<()> {
    let reader = crate::audit::AuditReader::new()?;
    let entries = reader.read_session(session_id).unwrap_or_default();

    if entries.is_empty() {
        println!("\n  {} No actions were logged this session.", "ℹ".blue());
        return Ok(());
    }

    let summary = crate::audit::AuditReader::summarize(&entries);

    println!();
    println!("  {} Session complete", "─".repeat(40).dimmed());
    println!();
    println!(
        "  {} {} | {} {} | {} {} | {} {}",
        summary.total_actions.to_string().bold(),
        "actions",
        summary.allowed.to_string().green().bold(),
        "allowed",
        summary.denied.to_string().red().bold(),
        "denied",
        summary.approved.to_string().yellow().bold(),
        "approved",
    );
    println!();
    println!(
        "  View full log: {}",
        format!("lawctl log --session {}", session_id).dimmed()
    );
    println!();

    Ok(())
}
