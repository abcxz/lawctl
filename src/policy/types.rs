//! Core types for the Lawctl policy engine.
//!
//! These types define the structure of policies, rules, actions, and decisions
//! that form the heart of Lawctl's security enforcement.

use serde::{Deserialize, Serialize};
use std::fmt;

/// Represents an action an AI agent is attempting to perform.
/// Every tool call from an agent maps to one of these variants.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Action {
    /// Writing content to a file (includes creating new files)
    Write,
    /// Deleting a file or directory
    Delete,
    /// Running a shell command
    RunCmd,
    /// Pushing to a git remote
    GitPush,
    /// Making a network request (future — included for policy completeness)
    Network,
}

impl fmt::Display for Action {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Action::Write => write!(f, "write"),
            Action::Delete => write!(f, "delete"),
            Action::RunCmd => write!(f, "run_cmd"),
            Action::GitPush => write!(f, "git_push"),
            Action::Network => write!(f, "network"),
        }
    }
}

impl Action {
    /// Parse an action from a string (used during YAML parsing).
    /// Accepts multiple aliases so policy files feel natural to write.
    pub fn from_str_loose(s: &str) -> Option<Action> {
        match s.to_lowercase().trim() {
            "write" | "write_file" | "file_write" => Some(Action::Write),
            "delete" | "delete_file" | "file_delete" | "rm" => Some(Action::Delete),
            "run_cmd" | "shell" | "exec" | "command" | "cmd" => Some(Action::RunCmd),
            "git_push" | "push" | "git" => Some(Action::GitPush),
            "network" | "net" | "http" | "fetch" => Some(Action::Network),
            _ => None,
        }
    }

    /// Whether this action is considered destructive by default.
    /// Destructive actions are denied unless explicitly allowed by policy.
    pub fn is_destructive(&self) -> bool {
        matches!(self, Action::Delete | Action::GitPush | Action::RunCmd)
    }
}

/// Conditions that narrow when a rule applies.
/// All specified conditions must match for the rule to trigger (AND logic).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Conditions {
    /// Rule applies only when the target path matches these glob patterns.
    /// Example: ["src/**", "tests/**"]
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub if_path_matches: Vec<String>,

    /// Rule does NOT apply when the target path matches these patterns.
    /// This is the "escape hatch" — e.g., "deny delete unless_path: /tmp"
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub unless_path: Vec<String>,

    /// For run_cmd: rule applies when the command matches these patterns.
    /// Supports glob-style matching: "rm -rf *", "curl * | bash"
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub if_matches: Vec<String>,

    /// Maximum number of diff lines allowed for file writes.
    /// Prevents agents from rewriting entire files in one shot.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_diff_lines: Option<usize>,

    /// For network rules: only allow these domains.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub unless_domain: Vec<String>,
}

impl Conditions {
    pub fn is_empty(&self) -> bool {
        self.if_path_matches.is_empty()
            && self.unless_path.is_empty()
            && self.if_matches.is_empty()
            && self.max_diff_lines.is_none()
            && self.unless_domain.is_empty()
    }
}

/// A single rule in a policy. Rules are evaluated in order — first match wins.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum Rule {
    /// Block this action (optionally with conditions).
    Deny {
        action: Action,
        #[serde(default)]
        conditions: Conditions,
        /// Human-readable reason shown to the agent when denied.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        reason: Option<String>,
    },
    /// Explicitly allow this action (optionally with conditions).
    Allow {
        action: Action,
        #[serde(default)]
        conditions: Conditions,
    },
    /// Pause and ask the human for approval before executing.
    RequireApproval {
        action: Action,
        #[serde(default)]
        conditions: Conditions,
        /// What to show the human in the approval prompt.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        prompt: Option<String>,
    },
}

impl Rule {
    /// Get the action this rule applies to.
    pub fn action(&self) -> &Action {
        match self {
            Rule::Deny { action, .. } => action,
            Rule::Allow { action, .. } => action,
            Rule::RequireApproval { action, .. } => action,
        }
    }

    /// Get the conditions for this rule.
    pub fn conditions(&self) -> &Conditions {
        match self {
            Rule::Deny { conditions, .. } => conditions,
            Rule::Allow { conditions, .. } => conditions,
            Rule::RequireApproval { conditions, .. } => conditions,
        }
    }

    /// Human-readable description of this rule (used in logs and approval prompts).
    pub fn describe(&self) -> String {
        match self {
            Rule::Deny {
                action, conditions, ..
            } => {
                let mut desc = format!("deny:{}", action);
                if !conditions.if_path_matches.is_empty() {
                    desc.push_str(&format!(
                        ":if_path_matches:{}",
                        conditions.if_path_matches.join(",")
                    ));
                }
                if !conditions.unless_path.is_empty() {
                    desc.push_str(&format!(
                        ":unless_path:{}",
                        conditions.unless_path.join(",")
                    ));
                }
                if !conditions.if_matches.is_empty() {
                    desc.push_str(&format!(":if_matches:{}", conditions.if_matches.join(",")));
                }
                desc
            }
            Rule::Allow {
                action, conditions, ..
            } => {
                let mut desc = format!("allow:{}", action);
                if !conditions.if_path_matches.is_empty() {
                    desc.push_str(&format!(
                        ":if_path_matches:{}",
                        conditions.if_path_matches.join(",")
                    ));
                }
                if let Some(max_lines) = conditions.max_diff_lines {
                    desc.push_str(&format!(":max_diff_lines:{}", max_lines));
                }
                desc
            }
            Rule::RequireApproval { action, .. } => {
                format!("require_approval:{}", action)
            }
        }
    }
}

/// A complete policy — a named set of rules that govern agent behavior.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Policy {
    /// Policy name/identifier (e.g., "safe-dev-v1")
    pub law: String,

    /// Optional human-readable description
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,

    /// Ordered list of rules. First match wins.
    pub rules: Vec<Rule>,
}

/// The result of evaluating an action against a policy.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "decision")]
pub enum Decision {
    /// Action is permitted — go ahead and execute.
    Allowed {
        /// Which rule allowed it (None = default allow)
        #[serde(skip_serializing_if = "Option::is_none")]
        matched_rule: Option<String>,
    },
    /// Action is blocked — do not execute, return error to agent.
    Denied {
        /// Why it was denied (shown to the agent)
        reason: String,
        /// Which rule denied it
        #[serde(skip_serializing_if = "Option::is_none")]
        matched_rule: Option<String>,
    },
    /// Action requires human approval before executing.
    RequiresApproval {
        /// What to show the human
        reason: String,
        /// Which rule triggered the approval requirement
        #[serde(skip_serializing_if = "Option::is_none")]
        matched_rule: Option<String>,
    },
}

impl Decision {
    pub fn is_allowed(&self) -> bool {
        matches!(self, Decision::Allowed { .. })
    }

    pub fn is_denied(&self) -> bool {
        matches!(self, Decision::Denied { .. })
    }

    pub fn is_requires_approval(&self) -> bool {
        matches!(self, Decision::RequiresApproval { .. })
    }
}

impl fmt::Display for Decision {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Decision::Allowed { .. } => write!(f, "allowed"),
            Decision::Denied { reason, .. } => write!(f, "denied: {}", reason),
            Decision::RequiresApproval { reason, .. } => {
                write!(f, "requires approval: {}", reason)
            }
        }
    }
}

/// Payload metadata passed alongside an action for richer policy evaluation.
#[derive(Debug, Clone, Default)]
pub struct ActionContext {
    /// The target path or resource (file path, git branch, URL, etc.)
    pub target: String,
    /// For file writes: the diff content
    pub diff: Option<String>,
    /// For run_cmd: the full command string
    pub command: Option<String>,
    /// For network: the target URL/domain
    pub domain: Option<String>,
    /// Number of diff lines (computed from diff if provided)
    pub diff_lines: Option<usize>,
}

impl ActionContext {
    pub fn new(target: impl Into<String>) -> Self {
        Self {
            target: target.into(),
            ..Default::default()
        }
    }

    pub fn with_diff(mut self, diff: impl Into<String>) -> Self {
        let d = diff.into();
        self.diff_lines = Some(d.lines().count());
        self.diff = Some(d);
        self
    }

    pub fn with_command(mut self, cmd: impl Into<String>) -> Self {
        self.command = Some(cmd.into());
        self
    }

    pub fn with_domain(mut self, domain: impl Into<String>) -> Self {
        self.domain = Some(domain.into());
        self
    }
}
