//! YAML policy parser for Lawctl.
//!
//! Parses human-friendly YAML policy files into the internal Policy struct.
//! The YAML format is intentionally simple — designed for vibe coders, not DevOps engineers.
//!
//! # Example policy file:
//! ```yaml
//! law: safe-dev-v1
//! rules:
//!   - deny: delete
//!     unless_path: /tmp
//!   - deny: write
//!     if_path_matches: ["*.env", ".ssh/*"]
//!   - require_approval: git_push
//!   - allow: write
//!     if_path_matches: ["src/**", "tests/**"]
//!     max_diff_lines: 500
//! ```

use crate::policy::types::*;
use anyhow::{bail, Context, Result};
use serde::Deserialize;
use std::path::Path;

/// Raw YAML representation before conversion to internal types.
/// This intermediate form handles the flexible YAML syntax.
#[derive(Debug, Deserialize)]
struct RawPolicy {
    law: String,
    #[serde(default)]
    description: Option<String>,
    rules: Vec<RawRule>,
}

/// A rule as it appears in the YAML file.
/// Supports three forms: deny, allow, require_approval.
#[derive(Debug, Deserialize)]
struct RawRule {
    #[serde(default)]
    deny: Option<String>,
    #[serde(default)]
    allow: Option<String>,
    #[serde(default)]
    require_approval: Option<String>,

    // Conditions — all optional
    #[serde(default)]
    if_path_matches: Option<StringOrVec>,
    #[serde(default)]
    unless_path: Option<StringOrVec>,
    #[serde(default)]
    if_matches: Option<StringOrVec>,
    #[serde(default)]
    max_diff_lines: Option<usize>,
    #[serde(default)]
    unless_domain: Option<StringOrVec>,
    #[serde(default)]
    reason: Option<String>,
    #[serde(default)]
    prompt: Option<String>,
}

/// Allows YAML fields to be either a single string or a list of strings.
/// This makes policies more ergonomic:
/// ```yaml
/// unless_path: /tmp          # single string — works
/// unless_path: [/tmp, /var]  # list — also works
/// ```
#[derive(Debug, Deserialize)]
#[serde(untagged)]
enum StringOrVec {
    Single(String),
    Multiple(Vec<String>),
}

impl StringOrVec {
    fn into_vec(self) -> Vec<String> {
        match self {
            StringOrVec::Single(s) => vec![s],
            StringOrVec::Multiple(v) => v,
        }
    }
}

/// Parse a YAML policy file from a file path.
pub fn parse_policy_file(path: impl AsRef<Path>) -> Result<Policy> {
    let path = path.as_ref();
    let content = std::fs::read_to_string(path)
        .with_context(|| format!("Failed to read policy file: {}", path.display()))?;
    parse_policy_str(&content)
        .with_context(|| format!("Failed to parse policy file: {}", path.display()))
}

/// Parse a YAML policy string into a Policy struct.
pub fn parse_policy_str(yaml: &str) -> Result<Policy> {
    let raw: RawPolicy =
        serde_yaml::from_str(yaml).context("Invalid YAML syntax in policy file")?;

    // Validate the law name
    if raw.law.trim().is_empty() {
        bail!("Policy must have a non-empty 'law' name");
    }

    // Convert raw rules to typed rules
    let mut rules = Vec::with_capacity(raw.rules.len());
    for (i, raw_rule) in raw.rules.into_iter().enumerate() {
        let rule = convert_rule(raw_rule, i)
            .with_context(|| format!("Invalid rule at position {} (0-indexed)", i))?;
        rules.push(rule);
    }

    if rules.is_empty() {
        bail!("Policy must have at least one rule");
    }

    Ok(Policy {
        law: raw.law,
        description: raw.description,
        rules,
    })
}

/// Convert a raw YAML rule into a typed Rule enum.
fn convert_rule(raw: RawRule, index: usize) -> Result<Rule> {
    // Exactly one of deny/allow/require_approval must be set
    let set_count = [
        raw.deny.is_some(),
        raw.allow.is_some(),
        raw.require_approval.is_some(),
    ]
    .iter()
    .filter(|&&b| b)
    .count();

    if set_count == 0 {
        bail!(
            "Rule {} must specify one of: deny, allow, or require_approval",
            index
        );
    }
    if set_count > 1 {
        bail!(
            "Rule {} specifies multiple rule types (deny/allow/require_approval) — pick one",
            index
        );
    }

    let conditions = Conditions {
        if_path_matches: raw
            .if_path_matches
            .map(|s| s.into_vec())
            .unwrap_or_default(),
        unless_path: raw.unless_path.map(|s| s.into_vec()).unwrap_or_default(),
        if_matches: raw.if_matches.map(|s| s.into_vec()).unwrap_or_default(),
        max_diff_lines: raw.max_diff_lines,
        unless_domain: raw.unless_domain.map(|s| s.into_vec()).unwrap_or_default(),
    };

    if let Some(action_str) = raw.deny {
        let action = Action::from_str_loose(&action_str)
            .ok_or_else(|| anyhow::anyhow!("Unknown action '{}' in deny rule", action_str))?;
        validate_conditions_for_action(&action, &conditions, index)?;
        Ok(Rule::Deny {
            action,
            conditions,
            reason: raw.reason,
        })
    } else if let Some(action_str) = raw.allow {
        let action = Action::from_str_loose(&action_str)
            .ok_or_else(|| anyhow::anyhow!("Unknown action '{}' in allow rule", action_str))?;
        validate_conditions_for_action(&action, &conditions, index)?;
        Ok(Rule::Allow { action, conditions })
    } else if let Some(action_str) = raw.require_approval {
        let action = Action::from_str_loose(&action_str).ok_or_else(|| {
            anyhow::anyhow!("Unknown action '{}' in require_approval rule", action_str)
        })?;
        validate_conditions_for_action(&action, &conditions, index)?;
        Ok(Rule::RequireApproval {
            action,
            conditions,
            prompt: raw.prompt,
        })
    } else {
        unreachable!()
    }
}

/// Validate that conditions make sense for the given action type.
/// For example, `if_path_matches` doesn't make sense for `run_cmd`.
fn validate_conditions_for_action(
    action: &Action,
    conditions: &Conditions,
    index: usize,
) -> Result<()> {
    match action {
        Action::RunCmd => {
            if !conditions.if_path_matches.is_empty() || !conditions.unless_path.is_empty() {
                bail!(
                    "Rule {}: 'if_path_matches' and 'unless_path' don't apply to run_cmd actions. \
                     Use 'if_matches' for command pattern matching.",
                    index
                );
            }
        }
        Action::GitPush => {
            if !conditions.if_matches.is_empty() {
                bail!(
                    "Rule {}: 'if_matches' doesn't apply to git_push. \
                     Use 'if_path_matches' for branch patterns.",
                    index
                );
            }
        }
        Action::Network => {
            if !conditions.if_path_matches.is_empty() || !conditions.unless_path.is_empty() {
                bail!(
                    "Rule {}: 'if_path_matches' and 'unless_path' don't apply to network actions. \
                     Use 'unless_domain' for domain allowlisting.",
                    index
                );
            }
        }
        Action::Write | Action::Delete => {
            if !conditions.unless_domain.is_empty() {
                bail!(
                    "Rule {}: 'unless_domain' only applies to network actions.",
                    index
                );
            }
        }
    }

    // Validate glob patterns are well-formed
    for pattern in &conditions.if_path_matches {
        globset::Glob::new(pattern)
            .with_context(|| format!("Rule {}: invalid glob pattern '{}'", index, pattern))?;
    }
    for pattern in &conditions.unless_path {
        // unless_path can be simple path prefixes, not just globs
        // We'll try to compile as glob, but also support plain paths
        if pattern.contains('*') || pattern.contains('?') || pattern.contains('[') {
            globset::Glob::new(pattern)
                .with_context(|| format!("Rule {}: invalid glob pattern '{}'", index, pattern))?;
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_basic_policy() {
        let yaml = r#"
law: test-policy
rules:
  - deny: delete
    unless_path: /tmp
  - allow: write
    if_path_matches: ["src/**"]
  - require_approval: git_push
"#;
        let policy = parse_policy_str(yaml).unwrap();
        assert_eq!(policy.law, "test-policy");
        assert_eq!(policy.rules.len(), 3);
    }

    #[test]
    fn test_parse_full_policy() {
        let yaml = r#"
law: safe-dev-v1
description: Default safety policy for development
rules:
  - deny: delete
    unless_path: /tmp
  - deny: write
    if_path_matches: ["*.env", ".ssh/*", "*.pem", "*.key"]
  - require_approval: git_push
  - deny: run_cmd
    if_matches: ["rm -rf *", "curl * | bash", "wget * | sh"]
  - allow: write
    if_path_matches: ["src/**", "tests/**"]
    max_diff_lines: 500
  - deny: network
    unless_domain: ["github.com", "npmjs.org"]
"#;
        let policy = parse_policy_str(yaml).unwrap();
        assert_eq!(policy.law, "safe-dev-v1");
        assert_eq!(policy.rules.len(), 6);

        // Check the deny delete rule
        match &policy.rules[0] {
            Rule::Deny {
                action, conditions, ..
            } => {
                assert_eq!(*action, Action::Delete);
                assert_eq!(conditions.unless_path, vec!["/tmp".to_string()]);
            }
            _ => panic!("Expected Deny rule"),
        }
    }

    #[test]
    fn test_single_string_or_vec() {
        // Single string form
        let yaml = r#"
law: test
rules:
  - deny: delete
    unless_path: /tmp
"#;
        let policy = parse_policy_str(yaml).unwrap();
        match &policy.rules[0] {
            Rule::Deny { conditions, .. } => {
                assert_eq!(conditions.unless_path, vec!["/tmp".to_string()]);
            }
            _ => panic!("Expected Deny"),
        }

        // Vec form
        let yaml = r#"
law: test
rules:
  - deny: delete
    unless_path: ["/tmp", "/var/tmp"]
"#;
        let policy = parse_policy_str(yaml).unwrap();
        match &policy.rules[0] {
            Rule::Deny { conditions, .. } => {
                assert_eq!(conditions.unless_path.len(), 2);
            }
            _ => panic!("Expected Deny"),
        }
    }

    #[test]
    fn test_reject_empty_law_name() {
        let yaml = r#"
law: ""
rules:
  - deny: delete
"#;
        assert!(parse_policy_str(yaml).is_err());
    }

    #[test]
    fn test_reject_no_rules() {
        let yaml = r#"
law: empty
rules: []
"#;
        assert!(parse_policy_str(yaml).is_err());
    }

    #[test]
    fn test_reject_unknown_action() {
        let yaml = r#"
law: test
rules:
  - deny: hack_the_planet
"#;
        assert!(parse_policy_str(yaml).is_err());
    }

    #[test]
    fn test_reject_multiple_rule_types() {
        let yaml = r#"
law: test
rules:
  - deny: delete
    allow: write
"#;
        assert!(parse_policy_str(yaml).is_err());
    }

    #[test]
    fn test_reject_path_conditions_on_run_cmd() {
        let yaml = r#"
law: test
rules:
  - deny: run_cmd
    if_path_matches: ["src/**"]
"#;
        assert!(parse_policy_str(yaml).is_err());
    }

    #[test]
    fn test_action_aliases() {
        // Test that various aliases all parse correctly
        for alias in &["write", "write_file", "file_write"] {
            let yaml = format!(
                "law: test\nrules:\n  - allow: {}\n    if_path_matches: [\"src/**\"]",
                alias
            );
            let policy = parse_policy_str(&yaml).unwrap();
            assert_eq!(*policy.rules[0].action(), Action::Write);
        }
    }
}
