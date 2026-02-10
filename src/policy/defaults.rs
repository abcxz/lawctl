//! Built-in policy templates that ship with Lawctl.
//!
//! These provide sensible starting points for different use cases:
//! - `safe-dev`: For everyday development — blocks dangerous stuff, requires approval for pushes
//! - `safe-ci`: Stricter — for CI/CD pipelines where no human is watching
//! - `permissive`: Allow everything but log it all — for trust-building and testing

/// Default development policy.
/// Blocks destructive actions, protects secrets, requires approval for git push.
/// This is what most vibe coders should start with.
pub const SAFE_DEV_YAML: &str = r#"# Lawctl Policy: safe-dev
# A sensible default for everyday development.
# Blocks dangerous actions, protects your secrets, and asks before pushing code.

law: safe-dev-v1

description: >
  Default safety policy for development. Protects secrets, prevents
  accidental deletions, and requires your approval before pushing code.

rules:
  # -- Protect your secrets --
  # Never let an agent write to credential/key files
  - deny: write
    if_path_matches: ["*.env", "*.env.*", ".ssh/*", "*.pem", "*.key", "*.p12", "*.keystore"]
    reason: "Protected file — agents cannot modify secrets or credentials"

  # -- Prevent accidental deletions --
  # Only allow deleting files in /tmp or build output dirs
  - deny: delete
    unless_path: ["/tmp", "tmp/", "dist/", "build/", "target/", "node_modules/", ".next/", "__pycache__/"]

  # -- Block dangerous shell commands --
  - deny: run_cmd
    if_matches:
      - "rm -rf *"
      - "rm -r /*"
      - "curl * | bash"
      - "curl * | sh"
      - "wget * | bash"
      - "wget * | sh"
      - "chmod 777 *"
      - "chmod -R 777 *"
      - "> /dev/*"
      - "dd if=*"
      - "mkfs.*"
      - ":(){:|:&};:"
    reason: "Blocked — this command pattern is on the denylist"

  # -- Require approval for git operations --
  - require_approval: git_push
    prompt: "The AI agent wants to push code. Review the changes before approving."

  # -- Allow writes to common source directories --
  - allow: write
    if_path_matches: ["src/**", "lib/**", "app/**", "pages/**", "components/**", "tests/**", "test/**", "spec/**", "__tests__/**", "docs/**"]
    max_diff_lines: 500

  # -- Allow safe shell commands (anything not on the denylist) --
  - allow: run_cmd
    if_matches:
      - "cargo *"
      - "npm *"
      - "pnpm *"
      - "yarn *"
      - "pip *"
      - "python *"
      - "node *"
      - "go *"
      - "make *"
      - "ls *"
      - "cat *"
      - "grep *"
      - "find *"
      - "git status*"
      - "git diff*"
      - "git log*"
      - "git add*"
      - "git commit*"
      - "git branch*"
      - "git checkout*"
      - "git stash*"
"#;

/// Strict CI/CD policy.
/// Designed for automated pipelines — no human available for approvals.
pub const SAFE_CI_YAML: &str = r#"# Lawctl Policy: safe-ci
# Strict policy for CI/CD pipelines.
# No human is watching — deny anything risky, allow only build operations.

law: safe-ci-v1

description: >
  Strict policy for CI/CD pipelines. Denies all git push operations,
  restricts writes to build output directories, and blocks network
  access except to package registries.

rules:
  # -- Protect everything sensitive --
  - deny: write
    if_path_matches: ["*.env", "*.env.*", ".ssh/*", "*.pem", "*.key", "*.p12"]

  # -- No git push in CI (deploy tools handle this separately) --
  - deny: git_push
    reason: "Git push is not allowed in CI — use your deploy pipeline instead"

  # -- Only allow writes to build output --
  - allow: write
    if_path_matches: ["dist/**", "build/**", "target/**", "out/**", ".next/**"]

  # -- Block all dangerous commands --
  - deny: run_cmd
    if_matches:
      - "rm -rf *"
      - "curl * | bash"
      - "wget * | sh"
      - "chmod 777 *"

  # -- Allow only build/test commands --
  - allow: run_cmd
    if_matches:
      - "cargo *"
      - "npm *"
      - "pnpm *"
      - "yarn *"
      - "pip *"
      - "make *"
      - "go build*"
      - "go test*"

  # -- Restrict network to package registries --
  - deny: network
    unless_domain: ["github.com", "npmjs.org", "registry.npmjs.org", "pypi.org", "crates.io", "pkg.go.dev"]

  # -- No deletions in CI --
  - deny: delete
    reason: "File deletion is not allowed in CI pipelines"
"#;

/// Permissive policy — allow everything but log it all.
/// Useful for testing, trust-building, and understanding what an agent does.
pub const PERMISSIVE_YAML: &str = r#"# Lawctl Policy: permissive
# Allows everything, but logs every action.
# Use this to understand what an agent does before tightening the policy.
#
# WARNING: This provides NO protection. It's a monitoring-only policy.
# Switch to safe-dev once you're comfortable.

law: permissive-v1

description: >
  Allow all actions with full logging. Use this to audit what an agent
  does before creating a tighter policy. Not recommended for production use.

rules:
  # -- Allow all writes --
  - allow: write

  # -- Allow all deletes --
  - allow: delete

  # -- Allow all shell commands --
  - allow: run_cmd

  # -- Require approval only for git push (even in permissive mode) --
  - require_approval: git_push
    prompt: "Even in permissive mode, git push requires your OK."

  # -- Allow all network --
  - allow: network
"#;

/// Get the YAML content for a named default policy template.
pub fn get_default_policy(name: &str) -> Option<&'static str> {
    match name.to_lowercase().as_str() {
        "safe-dev" | "safe_dev" | "dev" => Some(SAFE_DEV_YAML),
        "safe-ci" | "safe_ci" | "ci" => Some(SAFE_CI_YAML),
        "permissive" | "allow-all" | "test" => Some(PERMISSIVE_YAML),
        _ => None,
    }
}

/// List all available default policy template names.
pub fn available_templates() -> Vec<(&'static str, &'static str)> {
    vec![
        (
            "safe-dev",
            "Sensible defaults for development — blocks dangerous stuff, protects secrets",
        ),
        (
            "safe-ci",
            "Strict policy for CI/CD — no git push, restricted writes and network",
        ),
        (
            "permissive",
            "Allow everything with logging — for testing and trust-building",
        ),
    ]
}
