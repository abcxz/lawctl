//! lawctl-shim — The agent interceptor binary.
//!
//! This binary gets injected into the sandbox container's PATH.
//! When an AI agent tries to execute commands, the shim intercepts
//! dangerous operations and routes them through the lawctl gateway
//! for policy enforcement.
//!
//! How it works:
//! 1. The shim is installed as symlinks: `rm` → lawctl-shim, `git` → lawctl-shim, etc.
//! 2. When called, it checks argv[0] to figure out which command was intercepted
//! 3. It builds a GatewayRequest and sends it over the Unix socket
//! 4. If the gateway allows it, the shim executes the real command
//! 5. If denied, it prints the error and exits with code 1
//!
//! Usage (automatic — set up by `lawctl run`):
//!   LAWCTL_SOCKET=/tmp/lawctl.sock lawctl-shim <action> [args...]
//!
//! Or invoke explicitly:
//!   lawctl-shim write <path> <content>
//!   lawctl-shim delete <path>
//!   lawctl-shim exec <command...>
//!   lawctl-shim git-push <branch>

use lawctl::gateway::client::GatewayClient;
use lawctl::gateway::protocol::GatewayResponse;
use std::env;
use std::process;

fn main() {
    let args: Vec<String> = env::args().collect();

    // Figure out what command we're intercepting
    let invoked_as = std::path::Path::new(&args[0])
        .file_name()
        .map(|n| n.to_string_lossy().to_string())
        .unwrap_or_else(|| "lawctl-shim".to_string());

    let result = match invoked_as.as_str() {
        // Symlink-based interception: called as `rm`, `git`, etc.
        "rm" => handle_rm(&args[1..]),
        "git" => handle_git(&args[1..]),

        // Direct invocation: lawctl-shim <subcommand> [args...]
        "lawctl-shim" => {
            if args.len() < 2 {
                print_usage();
                process::exit(1);
            }
            match args[1].as_str() {
                "write" => handle_write(&args[2..]),
                "delete" => handle_delete(&args[2..]),
                "exec" | "run" => handle_exec(&args[2..]),
                "git-push" | "push" => handle_git_push(&args[2..]),
                "help" | "--help" | "-h" => {
                    print_usage();
                    Ok(())
                }
                other => {
                    eprintln!("[lawctl] Unknown shim command: {}", other);
                    print_usage();
                    process::exit(1);
                }
            }
        }

        // Unknown invocation — pass through (not intercepted)
        _ => {
            eprintln!("[lawctl] Shim called as '{}' — not intercepted, passing through", invoked_as);
            handle_passthrough(&invoked_as, &args[1..])
        }
    };

    if let Err(e) = result {
        eprintln!("[lawctl] Error: {}", e);
        process::exit(1);
    }
}

/// Handle `rm` command interception.
/// Maps `rm <file>` → delete action, checks with gateway.
fn handle_rm(args: &[String]) -> anyhow::Result<()> {
    if args.is_empty() {
        eprintln!("rm: missing operand");
        process::exit(1);
    }

    let client = GatewayClient::from_env()?;

    // Check each file argument with the gateway
    for arg in args {
        // Skip flags
        if arg.starts_with('-') {
            continue;
        }

        let response = client.delete_file(arg)?;
        if !response.allowed {
            eprintln!(
                "[lawctl] BLOCKED: cannot delete '{}' — {}",
                arg,
                response.error.unwrap_or_else(|| "denied by policy".to_string())
            );
            process::exit(1);
        }
    }

    // If all files were approved, execute the real rm
    let full_command = format!("rm {}", args.join(" "));
    let response = client.run_cmd(&full_command)?;
    if response.allowed {
        if let Some(output) = response.result {
            if !output.is_empty() {
                print!("{}", output);
            }
        }
    }

    Ok(())
}

/// Handle `git` command interception.
/// Only intercepts `git push` — all other git commands pass through.
fn handle_git(args: &[String]) -> anyhow::Result<()> {
    if args.is_empty() {
        return handle_passthrough("git", args);
    }

    match args[0].as_str() {
        "push" => {
            let client = GatewayClient::from_env()?;

            // Extract branch from args (default: current branch)
            let branch = args.get(2) // git push <remote> <branch>
                .or(args.get(1))     // git push <branch>
                .map(|s| s.as_str())
                .unwrap_or("HEAD");

            let response = client.git_push(branch)?;
            if response.allowed {
                if let Some(output) = response.result {
                    println!("{}", output);
                }
                Ok(())
            } else {
                eprintln!(
                    "[lawctl] BLOCKED: git push denied — {}",
                    response.error.unwrap_or_else(|| "denied by policy".to_string())
                );
                process::exit(1);
            }
        }
        // All non-push git commands pass through
        _ => handle_passthrough("git", args),
    }
}

/// Handle explicit `lawctl-shim write <path> <content>`.
fn handle_write(args: &[String]) -> anyhow::Result<()> {
    if args.len() < 2 {
        eprintln!("Usage: lawctl-shim write <path> <content>");
        process::exit(1);
    }

    let path = &args[0];
    let content = &args[1..].join(" ");
    let client = GatewayClient::from_env()?;

    let response = client.write_file(path, content)?;
    handle_response(&response, "write", path)
}

/// Handle explicit `lawctl-shim delete <path>`.
fn handle_delete(args: &[String]) -> anyhow::Result<()> {
    if args.is_empty() {
        eprintln!("Usage: lawctl-shim delete <path>");
        process::exit(1);
    }

    let path = &args[0];
    let client = GatewayClient::from_env()?;

    let response = client.delete_file(path)?;
    handle_response(&response, "delete", path)
}

/// Handle explicit `lawctl-shim exec <command...>`.
fn handle_exec(args: &[String]) -> anyhow::Result<()> {
    if args.is_empty() {
        eprintln!("Usage: lawctl-shim exec <command...>");
        process::exit(1);
    }

    let command = args.join(" ");
    let client = GatewayClient::from_env()?;

    let response = client.run_cmd(&command)?;
    if response.allowed {
        if let Some(output) = response.result {
            print!("{}", output);
        }
        Ok(())
    } else {
        eprintln!(
            "[lawctl] BLOCKED: command denied — {}",
            response.error.unwrap_or_else(|| "denied by policy".to_string())
        );
        process::exit(1);
    }
}

/// Handle explicit `lawctl-shim git-push <branch>`.
fn handle_git_push(args: &[String]) -> anyhow::Result<()> {
    let branch = args.first().map(|s| s.as_str()).unwrap_or("main");
    let client = GatewayClient::from_env()?;

    let response = client.git_push(branch)?;
    handle_response(&response, "git push", branch)
}

/// Handle a gateway response — print result or error.
fn handle_response(response: &GatewayResponse, action: &str, target: &str) -> anyhow::Result<()> {
    if response.allowed {
        if let Some(ref output) = response.result {
            if !output.is_empty() {
                println!("{}", output);
            }
        }
        Ok(())
    } else {
        eprintln!(
            "[lawctl] BLOCKED: {} '{}' — {}",
            action,
            target,
            response
                .error
                .as_deref()
                .unwrap_or("denied by policy")
        );
        process::exit(1);
    }
}

/// Pass a command through to the real binary (not intercepted).
fn handle_passthrough(command: &str, args: &[String]) -> anyhow::Result<()> {
    // Find the real binary by checking PATH, skipping our shim
    let status = process::Command::new(format!("/usr/bin/{}", command))
        .args(args)
        .status();

    match status {
        Ok(s) => {
            if !s.success() {
                process::exit(s.code().unwrap_or(1));
            }
            Ok(())
        }
        Err(_) => {
            // Try without the /usr/bin prefix
            let status = process::Command::new(command)
                .args(args)
                .status()?;
            if !status.success() {
                process::exit(status.code().unwrap_or(1));
            }
            Ok(())
        }
    }
}

fn print_usage() {
    eprintln!(
        r#"lawctl-shim — Agent action interceptor

Usage:
  lawctl-shim write <path> <content>    Write a file through the gateway
  lawctl-shim delete <path>             Delete a file through the gateway
  lawctl-shim exec <command...>         Run a command through the gateway
  lawctl-shim git-push [branch]         Git push through the gateway
  lawctl-shim help                      Show this help

Environment:
  LAWCTL_SOCKET    Path to the gateway Unix socket (required)

The shim can also be symlinked as `rm` or `git` to transparently
intercept those commands."#
    );
}
