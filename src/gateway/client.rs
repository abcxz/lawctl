//! Gateway client — sends requests to the lawctl gateway over a Unix socket.
//!
//! Used by:
//! 1. The agent shim binary (`lawctl-shim`) to forward intercepted commands
//! 2. Integration/E2E tests to exercise the full gateway flow
//! 3. Any future MCP tool implementation

use crate::gateway::protocol::{GatewayRequest, GatewayResponse};
use crate::policy::types::Action;
use anyhow::{Context, Result};
use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use uuid::Uuid;

/// Client for communicating with the lawctl gateway.
pub struct GatewayClient {
    socket_path: PathBuf,
}

impl GatewayClient {
    /// Create a new client pointing to a gateway socket.
    pub fn new(socket_path: impl AsRef<Path>) -> Self {
        Self {
            socket_path: socket_path.as_ref().to_path_buf(),
        }
    }

    /// Create a client using the LAWCTL_SOCKET environment variable.
    pub fn from_env() -> Result<Self> {
        let socket_path = std::env::var("LAWCTL_SOCKET").context(
            "LAWCTL_SOCKET environment variable not set. Are you running inside lawctl?",
        )?;
        Ok(Self::new(socket_path))
    }

    /// Send a request and receive a response (synchronous).
    /// Each call opens a new connection — simple and reliable.
    pub fn send(&self, request: &GatewayRequest) -> Result<GatewayResponse> {
        let mut stream = UnixStream::connect(&self.socket_path).with_context(|| {
            format!(
                "Failed to connect to lawctl gateway at {}. Is lawctl running?",
                self.socket_path.display()
            )
        })?;

        // Send the request as a JSON line
        let json = serde_json::to_string(request)?;
        stream.write_all(json.as_bytes())?;
        stream.write_all(b"\n")?;
        stream.flush()?;

        // Read the response
        let mut reader = BufReader::new(stream);
        let mut response_line = String::new();
        reader.read_line(&mut response_line)?;

        let response: GatewayResponse = serde_json::from_str(response_line.trim())
            .context("Failed to parse gateway response")?;

        Ok(response)
    }

    /// Convenience: request to write a file.
    pub fn write_file(&self, path: &str, content: &str) -> Result<GatewayResponse> {
        let request = GatewayRequest {
            request_id: Uuid::new_v4().to_string(),
            action: Action::Write,
            target: path.to_string(),
            payload: Some(content.to_string()),
        };
        self.send(&request)
    }

    /// Convenience: request to delete a file.
    pub fn delete_file(&self, path: &str) -> Result<GatewayResponse> {
        let request = GatewayRequest {
            request_id: Uuid::new_v4().to_string(),
            action: Action::Delete,
            target: path.to_string(),
            payload: None,
        };
        self.send(&request)
    }

    /// Convenience: request to run a shell command.
    pub fn run_cmd(&self, command: &str) -> Result<GatewayResponse> {
        let request = GatewayRequest {
            request_id: Uuid::new_v4().to_string(),
            action: Action::RunCmd,
            target: "shell".to_string(),
            payload: Some(command.to_string()),
        };
        self.send(&request)
    }

    /// Convenience: request to git push.
    pub fn git_push(&self, branch: &str) -> Result<GatewayResponse> {
        let request = GatewayRequest {
            request_id: Uuid::new_v4().to_string(),
            action: Action::GitPush,
            target: branch.to_string(),
            payload: None,
        };
        self.send(&request)
    }

    /// Convenience: request a network action.
    pub fn network(&self, url: &str) -> Result<GatewayResponse> {
        let request = GatewayRequest {
            request_id: Uuid::new_v4().to_string(),
            action: Action::Network,
            target: url.to_string(),
            payload: Some(url.to_string()),
        };
        self.send(&request)
    }
}
