//! Filesystem mount configuration for the sandbox.
//!
//! Determines which paths are mounted read-only, which get a writable overlay,
//! and which are excluded entirely (secrets, credentials).

use std::path::{Path, PathBuf};

/// Paths that should NEVER be mounted into the sandbox.
/// These contain secrets, credentials, or system-critical files.
const EXCLUDED_PATHS: &[&str] = &[
    ".env",
    ".env.local",
    ".env.production",
    ".env.staging",
    ".ssh",
    ".git/credentials",
    ".git/config", // May contain tokens
    ".aws",
    ".gcloud",
    ".azure",
    ".docker/config.json",
    ".npmrc", // May contain auth tokens
    ".pypirc",
    ".cargo/credentials",
    ".cargo/credentials.toml",
    "*.pem",
    "*.key",
    "*.p12",
    "*.keystore",
];

/// Paths that should be mounted read-only (not writable by the agent).
const READONLY_PATHS: &[&str] = &[
    ".git", // Agent reads git state but can't modify directly
    "node_modules",
    ".venv",
    "vendor",
];

/// Determine mount configuration for a workspace.
pub struct MountConfig {
    /// The workspace root on the host
    pub workspace_root: PathBuf,
    /// Paths to exclude from the mount entirely
    pub excluded: Vec<PathBuf>,
    /// Paths to mount read-only
    pub readonly: Vec<PathBuf>,
}

impl MountConfig {
    /// Create a mount configuration for a workspace directory.
    pub fn for_workspace(workspace_root: impl AsRef<Path>) -> Self {
        let root = workspace_root.as_ref().to_path_buf();

        let excluded = EXCLUDED_PATHS
            .iter()
            .map(|p| root.join(p))
            .filter(|p| {
                // Only exclude paths that actually exist
                // (don't error on missing .aws, etc.)
                p.exists() || p.to_string_lossy().contains('*') // Keep glob patterns
            })
            .collect();

        let readonly = READONLY_PATHS
            .iter()
            .map(|p| root.join(p))
            .filter(|p| p.exists())
            .collect();

        Self {
            workspace_root: root,
            excluded,
            readonly,
        }
    }

    /// Check if a path should be excluded from the sandbox.
    pub fn is_excluded(&self, path: &Path) -> bool {
        self.excluded.iter().any(|excluded| {
            path.starts_with(excluded)
                || path.file_name().map_or(false, |name| {
                    let name = name.to_string_lossy();
                    EXCLUDED_PATHS.iter().any(|pattern| {
                        if pattern.starts_with('*') {
                            name.ends_with(&pattern[1..])
                        } else {
                            name.as_ref() == *pattern
                        }
                    })
                })
        })
    }

    /// Check if a path should be read-only in the sandbox.
    pub fn is_readonly(&self, path: &Path) -> bool {
        self.readonly
            .iter()
            .any(|ro_path| path.starts_with(ro_path))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn test_mount_config_creation() {
        let tmp = TempDir::new().unwrap();
        // Create some dirs that would be in a real project
        std::fs::create_dir_all(tmp.path().join(".git")).unwrap();
        std::fs::create_dir_all(tmp.path().join("node_modules")).unwrap();
        std::fs::write(tmp.path().join(".env"), "SECRET=foo").unwrap();

        let config = MountConfig::for_workspace(tmp.path());
        assert!(!config.readonly.is_empty());
        assert!(!config.excluded.is_empty());
    }
}
