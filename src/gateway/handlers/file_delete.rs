//! Handler for file delete operations.
//!
//! Receives a path from the agent, validates it's within the workspace,
//! and deletes if the policy allows it.

use anyhow::{Context, Result};
use std::fs;
use std::path::Path;

/// Execute a file deletion.
pub fn execute_delete(workspace_root: &Path, relative_path: &str) -> Result<String> {
    let target_path = workspace_root.join(relative_path);

    // Safety: ensure the resolved path is within the workspace
    let canonical_root = workspace_root
        .canonicalize()
        .with_context(|| format!("Workspace root not found: {}", workspace_root.display()))?;

    if !target_path.exists() {
        anyhow::bail!("File not found: {}", relative_path);
    }

    let canonical_target = target_path.canonicalize()?;
    if !canonical_target.starts_with(&canonical_root) {
        anyhow::bail!(
            "Path traversal detected: {} escapes workspace root",
            relative_path
        );
    }

    if canonical_target.is_dir() {
        fs::remove_dir_all(&canonical_target)
            .with_context(|| format!("Failed to delete directory: {}", relative_path))?;
    } else {
        fs::remove_file(&canonical_target)
            .with_context(|| format!("Failed to delete file: {}", relative_path))?;
    }

    Ok(format!("Deleted: {}", relative_path))
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn test_delete_file() {
        let tmp = TempDir::new().unwrap();
        fs::write(tmp.path().join("test.txt"), "content").unwrap();

        let result = execute_delete(tmp.path(), "test.txt");
        assert!(result.is_ok());
        assert!(!tmp.path().join("test.txt").exists());
    }

    #[test]
    fn test_delete_nonexistent() {
        let tmp = TempDir::new().unwrap();
        let result = execute_delete(tmp.path(), "nope.txt");
        assert!(result.is_err());
    }

    #[test]
    fn test_delete_path_traversal() {
        let tmp = TempDir::new().unwrap();
        let result = execute_delete(tmp.path(), "../../../etc/important");
        assert!(result.is_err());
    }
}
