//! Linux namespace-based sandbox (fallback when Docker is not available).
//!
//! Uses Linux namespaces (user, mount, pid, net) to create a lightweight
//! sandbox without requiring Docker. Only works on Linux.
//!
//! This is a v1.1 feature — for now, it's a placeholder that explains
//! the limitation and suggests using Docker instead.

use anyhow::{bail, Result};

/// Check if namespace sandboxing is available on this system.
pub fn is_available() -> bool {
    #[cfg(target_os = "linux")]
    {
        // Check if we can create user namespaces
        std::path::Path::new("/proc/self/ns/user").exists()
    }
    #[cfg(not(target_os = "linux"))]
    {
        false
    }
}

/// Placeholder for namespace-based sandbox.
/// Returns an error with instructions to use Docker instead.
pub fn create_namespace_sandbox() -> Result<()> {
    if !is_available() {
        bail!(
            "Namespace sandboxing is only available on Linux.\n\
             On macOS, please use Docker Desktop.\n\
             Run: lawctl run --sandbox docker -- <your agent command>"
        );
    }

    bail!(
        "Namespace sandboxing is not yet implemented in v1.\n\
         Please use Docker-based sandboxing instead.\n\
         Run: lawctl run --sandbox docker -- <your agent command>"
    );
}
