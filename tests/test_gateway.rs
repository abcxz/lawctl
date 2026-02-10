//! Integration tests for the gateway protocol.
//! Tests JSON serialization/deserialization of gateway messages.

use lawctl::gateway::protocol::{GatewayRequest, GatewayResponse};
use lawctl::policy::Action;

#[test]
fn test_request_serialization() {
    let request = GatewayRequest {
        request_id: "req-001".to_string(),
        action: Action::Write,
        target: "src/main.rs".to_string(),
        payload: Some("fn main() {}".to_string()),
    };

    let json = serde_json::to_string(&request).unwrap();
    let parsed: GatewayRequest = serde_json::from_str(&json).unwrap();

    assert_eq!(parsed.request_id, "req-001");
    assert_eq!(parsed.action, Action::Write);
    assert_eq!(parsed.target, "src/main.rs");
    assert_eq!(parsed.payload.as_deref(), Some("fn main() {}"));
}

#[test]
fn test_response_allowed() {
    let response = GatewayResponse::allowed("req-001".to_string(), "Written: src/main.rs");
    let json = serde_json::to_string(&response).unwrap();
    let parsed: GatewayResponse = serde_json::from_str(&json).unwrap();

    assert!(parsed.allowed);
    assert!(parsed.error.is_none());
    assert_eq!(parsed.result.as_deref(), Some("Written: src/main.rs"));
}

#[test]
fn test_response_denied() {
    let response = GatewayResponse::denied("req-002".to_string(), "Cannot write to .env");
    let json = serde_json::to_string(&response).unwrap();
    let parsed: GatewayResponse = serde_json::from_str(&json).unwrap();

    assert!(!parsed.allowed);
    assert_eq!(parsed.error.as_deref(), Some("Cannot write to .env"));
    assert!(parsed.result.is_none());
}

#[test]
fn test_all_action_types_serialize() {
    for action in &[
        Action::Write,
        Action::Delete,
        Action::RunCmd,
        Action::GitPush,
        Action::Network,
    ] {
        let request = GatewayRequest {
            request_id: "test".to_string(),
            action: action.clone(),
            target: "test".to_string(),
            payload: None,
        };
        let json = serde_json::to_string(&request).unwrap();
        let parsed: GatewayRequest = serde_json::from_str(&json).unwrap();
        assert_eq!(&parsed.action, action);
    }
}
