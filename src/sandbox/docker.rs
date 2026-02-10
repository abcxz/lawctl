//! Docker-based sandbox using the bollard crate.
//!
//! Creates a container with:
//! - Read-only mount of the project directory at /workspace
//! - Writable overlay for agent modifications
//! - Unix socket mounted for gateway IPC
//! - Controlled network (default deny)

use anyhow::{Context, Result};
use bollard::container::{
    Config, CreateContainerOptions, RemoveContainerOptions, StartContainerOptions,
    WaitContainerOptions,
};
use bollard::image::CreateImageOptions;
use bollard::models::{HostConfig, Mount, MountTypeEnum};
use bollard::Docker;
use futures_util::StreamExt;
use std::collections::HashMap;
use std::path::PathBuf;

/// Configuration for a sandbox container.
#[derive(Debug, Clone)]
pub struct SandboxConfig {
    /// Docker image to use (default: alpine:latest)
    pub image: String,
    /// Path to project directory on host
    pub workspace_path: PathBuf,
    /// Path to the gateway Unix socket on host
    pub socket_path: PathBuf,
    /// Environment variables to pass into the container
    pub env_vars: HashMap<String, String>,
    /// The command to run inside the container
    pub command: Vec<String>,
    /// Whether to enable network access
    pub network_enabled: bool,
    /// Container name (auto-generated if None)
    pub container_name: Option<String>,
}

impl Default for SandboxConfig {
    fn default() -> Self {
        Self {
            image: "alpine:latest".to_string(),
            workspace_path: PathBuf::new(),
            socket_path: PathBuf::from("/tmp/lawctl.sock"),
            env_vars: HashMap::new(),
            command: vec![],
            network_enabled: false,
            container_name: None,
        }
    }
}

/// Docker sandbox manager.
pub struct DockerSandbox {
    docker: Docker,
    container_id: Option<String>,
    config: SandboxConfig,
}

impl DockerSandbox {
    /// Create a new sandbox manager (connects to Docker daemon).
    pub async fn new(config: SandboxConfig) -> Result<Self> {
        let docker = Docker::connect_with_local_defaults()
            .context("Failed to connect to Docker daemon. Is Docker running?")?;

        // Verify Docker is accessible
        docker
            .ping()
            .await
            .context("Cannot reach Docker daemon. Make sure Docker Desktop is running.")?;

        Ok(Self {
            docker,
            container_id: None,
            config,
        })
    }

    /// Pull the base image if not present.
    pub async fn ensure_image(&self) -> Result<()> {
        let opts = CreateImageOptions {
            from_image: self.config.image.clone(),
            ..Default::default()
        };

        let mut stream = self.docker.create_image(Some(opts), None, None);
        while let Some(result) = stream.next().await {
            result.context("Failed to pull Docker image")?;
        }

        Ok(())
    }

    /// Create and start the sandbox container.
    pub async fn start(&mut self) -> Result<String> {
        self.ensure_image().await?;

        let container_name = self
            .config
            .container_name
            .clone()
            .unwrap_or_else(|| format!("lawctl-{}", &uuid::Uuid::new_v4().to_string()[..8]));

        // Build mount configuration
        let mut mounts = vec![
            // Project directory: read-only
            Mount {
                target: Some("/workspace".to_string()),
                source: Some(self.config.workspace_path.to_string_lossy().to_string()),
                typ: Some(MountTypeEnum::BIND),
                read_only: Some(true),
                ..Default::default()
            },
            // Gateway socket
            Mount {
                target: Some("/tmp/lawctl.sock".to_string()),
                source: Some(self.config.socket_path.to_string_lossy().to_string()),
                typ: Some(MountTypeEnum::BIND),
                read_only: Some(false),
                ..Default::default()
            },
        ];

        // Add a writable tmp directory for agent scratch space
        mounts.push(Mount {
            target: Some("/tmp/lawctl-scratch".to_string()),
            typ: Some(MountTypeEnum::TMPFS),
            ..Default::default()
        });

        // Build environment variables
        let env: Vec<String> = self
            .config
            .env_vars
            .iter()
            .map(|(k, v)| format!("{}={}", k, v))
            .chain(std::iter::once(
                "LAWCTL_SOCKET=/tmp/lawctl.sock".to_string(),
            ))
            .chain(std::iter::once("LAWCTL_WORKSPACE=/workspace".to_string()))
            .collect();

        let host_config = HostConfig {
            mounts: Some(mounts),
            network_mode: if self.config.network_enabled {
                None
            } else {
                Some("none".to_string())
            },
            // Security: drop all capabilities, add back only what's needed
            cap_drop: Some(vec!["ALL".to_string()]),
            // Read-only root filesystem
            readonly_rootfs: Some(false), // Allow writes to /tmp inside container
            ..Default::default()
        };

        let container_config = Config {
            image: Some(self.config.image.clone()),
            cmd: Some(self.config.command.clone()),
            working_dir: Some("/workspace".to_string()),
            env: Some(env),
            host_config: Some(host_config),
            ..Default::default()
        };

        let opts = CreateContainerOptions {
            name: container_name.clone(),
            ..Default::default()
        };

        let container = self
            .docker
            .create_container(Some(opts), container_config)
            .await
            .context("Failed to create sandbox container")?;

        self.docker
            .start_container(&container.id, None::<StartContainerOptions<String>>)
            .await
            .context("Failed to start sandbox container")?;

        self.container_id = Some(container.id.clone());
        tracing::info!("Sandbox container started: {}", container_name);

        Ok(container.id)
    }

    /// Wait for the container to finish and return the exit code.
    pub async fn wait(&self) -> Result<i64> {
        let container_id = self.container_id.as_ref().context("No container running")?;

        let opts = WaitContainerOptions {
            condition: "not-running",
        };

        let mut stream = self.docker.wait_container(container_id, Some(opts));
        if let Some(result) = stream.next().await {
            let response = result.context("Error waiting for container")?;
            Ok(response.status_code)
        } else {
            anyhow::bail!("Container wait stream ended unexpectedly")
        }
    }

    /// Stop and remove the container.
    pub async fn cleanup(&mut self) -> Result<()> {
        if let Some(ref container_id) = self.container_id {
            let opts = RemoveContainerOptions {
                force: true,
                ..Default::default()
            };

            self.docker
                .remove_container(container_id, Some(opts))
                .await
                .context("Failed to remove sandbox container")?;

            tracing::info!("Sandbox container removed");
            self.container_id = None;
        }
        Ok(())
    }

    /// Get the container ID (if running).
    pub fn container_id(&self) -> Option<&str> {
        self.container_id.as_deref()
    }
}

impl Drop for DockerSandbox {
    fn drop(&mut self) {
        // Best-effort cleanup on drop
        if self.container_id.is_some() {
            tracing::warn!("Sandbox container was not cleaned up properly");
        }
    }
}
