//! Policy linter — detects common gaps and suggests improvements.
//!
//! When a user runs `lawctl check`, the linter scans their policy for:
//! - Missing coverage for common dangerous actions
//! - Rules that may conflict with each other
//! - Common patterns that vibe coders forget
//!
//! This is the "are you sure your policy is good?" check.

use crate::policy::types::*;
use colored::Colorize;

/// A lint warning — something the user should know about their policy.
#[derive(Debug)]
pub struct LintWarning {
    pub severity: Severity,
    pub message: String,
    pub suggestion: Option<String>,
}

#[derive(Debug)]
pub enum Severity {
    /// Something that could be dangerous
    Warning,
    /// A suggestion for improvement
    Info,
}

impl LintWarning {
    fn warn(msg: impl Into<String>) -> Self {
        Self {
            severity: Severity::Warning,
            message: msg.into(),
            suggestion: None,
        }
    }

    fn warn_with_fix(msg: impl Into<String>, fix: impl Into<String>) -> Self {
        Self {
            severity: Severity::Warning,
            message: msg.into(),
            suggestion: Some(fix.into()),
        }
    }

    fn info(msg: impl Into<String>) -> Self {
        Self {
            severity: Severity::Info,
            message: msg.into(),
            suggestion: None,
        }
    }

    /// Format for terminal output.
    pub fn display(&self) -> String {
        let icon = match self.severity {
            Severity::Warning => "⚠".yellow().to_string(),
            Severity::Info => "ℹ".blue().to_string(),
        };
        let mut out = format!("  {} {}", icon, self.message);
        if let Some(ref suggestion) = self.suggestion {
            out.push_str(&format!("\n    {}: {}", "Fix".green(), suggestion));
        }
        out
    }
}

/// Lint a policy and return warnings.
pub fn lint_policy(policy: &Policy) -> Vec<LintWarning> {
    let mut warnings = Vec::new();

    check_secrets_protection(policy, &mut warnings);
    check_delete_protection(policy, &mut warnings);
    check_dangerous_commands(policy, &mut warnings);
    check_git_protection(policy, &mut warnings);
    check_network_rules(policy, &mut warnings);
    check_rule_ordering(policy, &mut warnings);
    check_catch_all(policy, &mut warnings);

    warnings
}

/// Check: does the policy protect secrets files?
fn check_secrets_protection(policy: &Policy, warnings: &mut Vec<LintWarning>) {
    let has_secrets_deny = policy.rules.iter().any(|rule| {
        if let Rule::Deny {
            action,
            conditions,
            ..
        } = rule
        {
            *action == Action::Write
                && conditions.if_path_matches.iter().any(|p| {
                    p.contains(".env") || p.contains(".ssh") || p.contains(".pem") || p.contains(".key")
                })
        } else {
            false
        }
    });

    if !has_secrets_deny {
        warnings.push(LintWarning::warn_with_fix(
            "No rule protects secrets files (.env, .ssh, .pem, .key)",
            "Add: deny: write, if_path_matches: [\"*.env\", \".ssh/*\", \"*.pem\", \"*.key\"]",
        ));
    }
}

/// Check: does the policy restrict file deletions?
fn check_delete_protection(policy: &Policy, warnings: &mut Vec<LintWarning>) {
    let has_delete_rule = policy.rules.iter().any(|rule| {
        *rule.action() == Action::Delete
    });

    if !has_delete_rule {
        warnings.push(LintWarning::warn_with_fix(
            "No rules for file deletion — destructive deletes will be denied by default, but an explicit rule is clearer",
            "Add: deny: delete, unless_path: /tmp",
        ));
    }
}

/// Check: does the policy block known dangerous commands?
fn check_dangerous_commands(policy: &Policy, warnings: &mut Vec<LintWarning>) {
    let has_cmd_deny = policy.rules.iter().any(|rule| {
        if let Rule::Deny {
            action,
            conditions,
            ..
        } = rule
        {
            *action == Action::RunCmd && !conditions.if_matches.is_empty()
        } else {
            false
        }
    });

    if !has_cmd_deny {
        warnings.push(LintWarning::warn_with_fix(
            "No command denylist — agents could run dangerous shell commands",
            "Add: deny: run_cmd, if_matches: [\"rm -rf *\", \"curl * | bash\"]",
        ));
    }
}

/// Check: does the policy address git push?
fn check_git_protection(policy: &Policy, warnings: &mut Vec<LintWarning>) {
    let has_git_rule = policy.rules.iter().any(|rule| {
        *rule.action() == Action::GitPush
    });

    if !has_git_rule {
        warnings.push(LintWarning::warn_with_fix(
            "No rule for git push — pushes will be denied by default (it's destructive)",
            "Add: require_approval: git_push (recommended) or deny: git_push",
        ));
    }
}

/// Check: does the policy address network access?
fn check_network_rules(policy: &Policy, warnings: &mut Vec<LintWarning>) {
    let has_network_rule = policy.rules.iter().any(|rule| {
        *rule.action() == Action::Network
    });

    if !has_network_rule {
        warnings.push(LintWarning::info(
            "No network rules — network access is allowed by default. Consider adding domain restrictions for sensitive environments.",
        ));
    }
}

/// Check for rule ordering issues.
fn check_rule_ordering(policy: &Policy, warnings: &mut Vec<LintWarning>) {
    // Warn if a broad allow rule appears before a specific deny rule
    for (i, rule_a) in policy.rules.iter().enumerate() {
        if let Rule::Allow {
            action: action_a,
            conditions: cond_a,
            ..
        } = rule_a
        {
            for rule_b in policy.rules.iter().skip(i + 1) {
                if let Rule::Deny {
                    action: action_b,
                    conditions: cond_b,
                    ..
                } = rule_b
                {
                    if action_a == action_b
                        && cond_a.if_path_matches.is_empty()
                        && !cond_b.if_path_matches.is_empty()
                    {
                        warnings.push(LintWarning::warn(format!(
                            "Rule {} (allow:{}) is broad and appears before a specific deny rule — the deny rule will never match (first match wins)",
                            i + 1,
                            action_a
                        )));
                    }
                }
            }
        }
    }
}

/// Check: does the policy have any catch-all rules?
fn check_catch_all(policy: &Policy, warnings: &mut Vec<LintWarning>) {
    let has_write_allow = policy.rules.iter().any(|rule| {
        if let Rule::Allow {
            action,
            conditions,
            ..
        } = rule
        {
            *action == Action::Write && conditions.if_path_matches.is_empty()
        } else {
            false
        }
    });

    if has_write_allow {
        warnings.push(LintWarning::info(
            "Policy allows ALL writes (no path restriction). This is fine for permissive mode, but consider restricting to specific directories for better protection.",
        ));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::parser;

    #[test]
    fn test_lint_permissive_catches_issues() {
        let yaml = r#"
law: too-permissive
rules:
  - allow: write
  - allow: delete
  - allow: run_cmd
"#;
        let policy = parser::parse_policy_str(yaml).unwrap();
        let warnings = lint_policy(&policy);

        // Should warn about: no secrets protection, no cmd denylist,
        // no git rules, no network rules, catch-all write
        assert!(
            warnings.len() >= 3,
            "Expected multiple warnings, got {}",
            warnings.len()
        );
    }

    #[test]
    fn test_lint_safe_dev_minimal_warnings() {
        let yaml = crate::policy::defaults::SAFE_DEV_YAML;
        let policy = parser::parse_policy_str(yaml).unwrap();
        let warnings = lint_policy(&policy);

        // safe-dev should have minimal warnings (maybe just "no network rules" as info)
        let warning_count = warnings
            .iter()
            .filter(|w| matches!(w.severity, Severity::Warning))
            .count();
        assert!(
            warning_count == 0,
            "safe-dev should have no warnings, got {}: {:?}",
            warning_count,
            warnings.iter().map(|w| &w.message).collect::<Vec<_>>()
        );
    }

    #[test]
    fn test_lint_ordering_issue() {
        let yaml = r#"
law: bad-order
rules:
  - allow: write
  - deny: write
    if_path_matches: ["*.env"]
"#;
        let policy = parser::parse_policy_str(yaml).unwrap();
        let warnings = lint_policy(&policy);

        let has_order_warning = warnings
            .iter()
            .any(|w| w.message.contains("first match wins"));
        assert!(has_order_warning, "Should warn about rule ordering");
    }
}
