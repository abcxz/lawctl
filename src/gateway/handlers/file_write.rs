//! Handler for file write operations.
//!
//! Receives a path + diff from the agent, validates against policy,
//! and applies the diff if allowed. The diff is preserved in the audit log.

use anyhow::{Context, Result};
use std::fs;
use std::path::Path;

/// Apply a file write operation.
/// The `workspace_root` is the real path on the host that the agent's
/// `/workspace` directory maps to.
pub fn execute_write(workspace_root: &Path, relative_path: &str, content: &str) -> Result<String> {
    let target_path = workspace_root.join(relative_path);

    // Safety: ensure the resolved path is still within the workspace
    let canonical_root = workspace_root
        .canonicalize()
        .with_context(|| format!("Workspace root not found: {}", workspace_root.display()))?;

    // Create parent directories if needed
    if let Some(parent) = target_path.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("Failed to create directory: {}", parent.display()))?;
    }

    let canonical_target = if target_path.exists() {
        target_path.canonicalize()?
    } else {
        // For new files, check that the parent is within workspace
        let parent = target_path
            .parent()
            .unwrap_or(workspace_root)
            .canonicalize()?;
        parent.join(target_path.file_name().unwrap_or_default())
    };

    if !canonical_target.starts_with(&canonical_root) {
        anyhow::bail!(
            "Path traversal detected: {} escapes workspace root",
            relative_path
        );
    }

    // Write the file
    fs::write(&target_path, content)
        .with_context(|| format!("Failed to write file: {}", target_path.display()))?;

    Ok(format!("Written: {}", relative_path))
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn test_write_new_file() {
        let tmp = TempDir::new().unwrap();
        let result = execute_write(tmp.path(), "test.txt", "hello world");
        assert!(result.is_ok());

        let content = fs::read_to_string(tmp.path().join("test.txt")).unwrap();
        assert_eq!(content, "hello world");
    }

    #[test]
    fn test_write_nested_file() {
        let tmp = TempDir::new().unwrap();
        let result = execute_write(tmp.path(), "src/deep/nested.rs", "fn main() {}");
        assert!(result.is_ok());
        assert!(tmp.path().join("src/deep/nested.rs").exists());
    }

    #[test]
    fn test_path_traversal_blocked() {
        let tmp = TempDir::new().unwrap();
        let result = execute_write(tmp.path(), "../../../etc/passwd", "hacked");
        assert!(result.is_err());
    }
}
