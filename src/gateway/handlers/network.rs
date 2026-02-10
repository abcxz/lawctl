//! Handler for network requests (future implementation).
//!
//! In v1, network control is primarily handled at the Docker network level.
//! This handler exists for policy evaluation and logging.

use anyhow::Result;

/// Validate a network request against policy.
/// In v1, the actual enforcement happens at the container network level.
/// This function exists for logging and future fine-grained control.
pub fn validate_network_request(url: &str) -> Result<String> {
    // Extract domain for logging
    let domain = extract_domain(url).unwrap_or_else(|| url.to_string());
    Ok(format!("Network request to: {} (domain: {})", url, domain))
}

/// Extract the domain from a URL.
pub fn extract_domain(url: &str) -> Option<String> {
    // Simple extraction — handles http(s)://domain/path
    let url = url.strip_prefix("https://").or_else(|| url.strip_prefix("http://"))?;
    let domain = url.split('/').next()?;
    let domain = domain.split(':').next()?; // Remove port
    Some(domain.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_domain() {
        assert_eq!(
            extract_domain("https://github.com/repo/thing"),
            Some("github.com".to_string())
        );
        assert_eq!(
            extract_domain("http://localhost:3000/api"),
            Some("localhost".to_string())
        );
        assert_eq!(extract_domain("not-a-url"), None);
    }
}
