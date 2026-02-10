//! Terminal-based approval prompt using crossterm.
//!
//! When a policy rule requires approval, this module displays a rich
//! terminal prompt showing what the agent wants to do and letting the
//! human approve or deny it.
//!
//! Uses crossterm directly (not ratatui) for the approval prompt —
//! ratatui is more than we need for a simple approve/deny dialog.

use crate::approval::types::{ApprovalRequest, ApprovalResponse};
use crate::approval::ApprovalHandler;
use anyhow::Result;
use async_trait::async_trait;
use crossterm::{
    event::{self, Event, KeyCode, KeyEvent},
    execute,
    style::{Color, Print, ResetColor, SetForegroundColor},
    terminal,
};
use std::io::Write;
use std::time::Duration;

/// Terminal-based approval handler.
/// Shows a prompt in the terminal and waits for the user to press A/D.
pub struct TerminalApproval {
    /// Timeout for approval (default: 5 minutes)
    timeout: Duration,
}

impl TerminalApproval {
    pub fn new() -> Self {
        Self {
            timeout: Duration::from_secs(300), // 5 minutes
        }
    }

    pub fn with_timeout(timeout: Duration) -> Self {
        Self { timeout }
    }
}

impl Default for TerminalApproval {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl ApprovalHandler for TerminalApproval {
    async fn request_approval(&self, request: &ApprovalRequest) -> Result<ApprovalResponse> {
        // We need to do the terminal I/O on a blocking thread since crossterm
        // uses synchronous I/O
        let request = request.clone();
        let timeout = self.timeout;

        tokio::task::spawn_blocking(move || show_approval_prompt(&request, timeout)).await?
    }
}

/// Display the approval prompt and wait for user input.
fn show_approval_prompt(request: &ApprovalRequest, timeout: Duration) -> Result<ApprovalResponse> {
    let mut stdout = std::io::stdout();

    // Draw the approval box
    execute!(
        stdout,
        Print("\n"),
        SetForegroundColor(Color::Yellow),
        Print("╔══════════════════════════════════════════════════════════╗\n"),
        Print("║              ⚠  APPROVAL REQUIRED                      ║\n"),
        Print("╠══════════════════════════════════════════════════════════╣\n"),
        ResetColor,
    )?;

    execute!(
        stdout,
        SetForegroundColor(Color::White),
        Print(format!(
            "║  Action:  {:<47}║\n",
            format!("{}", request.action)
        )),
        Print(format!("║  Target:  {:<47}║\n", truncate(&request.target, 47))),
    )?;

    if let Some(ref preview) = request.payload_preview {
        // Show first few lines of the payload
        execute!(
            stdout,
            Print("║  Preview:                                                ║\n"),
        )?;
        for line in preview.lines().take(5) {
            execute!(
                stdout,
                SetForegroundColor(Color::DarkGrey),
                Print(format!("║    {:<54}║\n", truncate(line, 54))),
            )?;
        }
    }

    execute!(
        stdout,
        SetForegroundColor(Color::Yellow),
        Print("║                                                          ║\n"),
        Print(format!(
            "║  Reason: {:<48}║\n",
            truncate(&request.reason, 48)
        )),
        Print("║                                                          ║\n"),
        SetForegroundColor(Color::Green),
        Print("║  [A] Approve    "),
        SetForegroundColor(Color::Red),
        Print("[D] Deny    "),
        SetForegroundColor(Color::Blue),
        Print("[V] View full payload         "),
        SetForegroundColor(Color::Yellow),
        Print("║\n"),
        Print("╚══════════════════════════════════════════════════════════╝\n"),
        ResetColor,
    )?;
    stdout.flush()?;

    // Enable raw mode to capture single keystrokes
    terminal::enable_raw_mode()?;

    let result = loop {
        if event::poll(timeout)? {
            if let Event::Key(KeyEvent { code, .. }) = event::read()? {
                match code {
                    KeyCode::Char('a') | KeyCode::Char('A') => {
                        break ApprovalResponse {
                            approved: true,
                            approved_by: Some("terminal".to_string()),
                        };
                    }
                    KeyCode::Char('d') | KeyCode::Char('D') | KeyCode::Esc => {
                        break ApprovalResponse {
                            approved: false,
                            approved_by: None,
                        };
                    }
                    KeyCode::Char('v') | KeyCode::Char('V') => {
                        // Show full payload (disable raw mode temporarily)
                        terminal::disable_raw_mode()?;
                        if let Some(ref preview) = request.payload_preview {
                            execute!(
                                stdout,
                                SetForegroundColor(Color::DarkGrey),
                                Print("\n--- Full payload ---\n"),
                                Print(preview),
                                Print("\n--- End payload ---\n"),
                                ResetColor,
                            )?;
                        } else {
                            execute!(stdout, Print("\n(no payload)\n"))?;
                        }
                        stdout.flush()?;
                        terminal::enable_raw_mode()?;
                        continue;
                    }
                    _ => continue,
                }
            }
        } else {
            // Timeout — deny by default
            break ApprovalResponse {
                approved: false,
                approved_by: None,
            };
        }
    };

    terminal::disable_raw_mode()?;

    // Show the decision
    if result.approved {
        execute!(
            stdout,
            SetForegroundColor(Color::Green),
            Print("\n  ✓ Approved\n\n"),
            ResetColor,
        )?;
    } else {
        execute!(
            stdout,
            SetForegroundColor(Color::Red),
            Print("\n  ✗ Denied\n\n"),
            ResetColor,
        )?;
    }
    stdout.flush()?;

    Ok(result)
}

fn truncate(s: &str, max: usize) -> String {
    if s.len() <= max {
        s.to_string()
    } else {
        format!("{}...", &s[..max.saturating_sub(3)])
    }
}

/// Auto-approve handler (for testing and CI).
/// Approves everything without prompting.
pub struct AutoApproval;

#[async_trait]
impl ApprovalHandler for AutoApproval {
    async fn request_approval(&self, _request: &ApprovalRequest) -> Result<ApprovalResponse> {
        Ok(ApprovalResponse {
            approved: true,
            approved_by: Some("auto".to_string()),
        })
    }
}

/// Auto-deny handler (for strict CI mode).
/// Denies everything that requires approval.
pub struct AutoDeny;

#[async_trait]
impl ApprovalHandler for AutoDeny {
    async fn request_approval(&self, _request: &ApprovalRequest) -> Result<ApprovalResponse> {
        Ok(ApprovalResponse {
            approved: false,
            approved_by: None,
        })
    }
}
