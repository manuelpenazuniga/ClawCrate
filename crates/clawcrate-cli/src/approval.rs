//! approval module (extracted from main.rs; see #277).

use std::collections::BTreeSet;
use std::io::{self, IsTerminal, Write};

use crate::{cli::*, output::*, support::*};
use anyhow::{anyhow, Result};
use clawcrate_audit::ArtifactWriter;
use clawcrate_types::{AuditEventKind, ExecutionPlan, NetLevel};

pub(crate) fn enforce_out_of_profile_approval(
    plan: &ExecutionPlan,
    args: &CommandArgs,
    output: &OutputOptions,
    writer: &ArtifactWriter,
) -> Result<()> {
    let requested = detect_out_of_profile_requests(plan);
    if requested.is_empty() {
        return Ok(());
    }

    if args.approve_out_of_profile {
        append_audit_event(
            writer,
            AuditEventKind::ApprovalDecision {
                requested,
                approved: true,
                automated: true,
            },
        )?;
        verbose_log(
            output,
            1,
            format!(
                "approval bypassed via --approve-out-of-profile for execution {}",
                plan.id
            ),
        );
        return Ok(());
    }

    let non_interactive = args.json || !io::stdin().is_terminal();
    if non_interactive {
        let requested_for_audit = requested.clone();
        append_audit_event(
            writer,
            AuditEventKind::ApprovalDecision {
                requested: requested_for_audit,
                approved: false,
                automated: true,
            },
        )?;
        return Err(anyhow!(
            "command appears to request permissions outside the active profile:\n{}\nre-run interactively to approve or use --approve-out-of-profile to proceed",
            requested
                .iter()
                .map(|item| format!("- {item}"))
                .collect::<Vec<_>>()
                .join("\n")
        ));
    }

    let approved = prompt_out_of_profile_approval(plan, &requested)?;
    append_audit_event(
        writer,
        AuditEventKind::ApprovalDecision {
            requested,
            approved,
            automated: false,
        },
    )?;
    if approved {
        Ok(())
    } else {
        Err(anyhow!("execution aborted: approval declined"))
    }
}

pub(crate) fn prompt_out_of_profile_approval(
    plan: &ExecutionPlan,
    requested: &[String],
) -> Result<bool> {
    println!(
        "Approval required for execution {} (profile: {}).",
        plan.id, plan.profile.name
    );
    println!("Detected requested permissions outside active profile:");
    for request in requested {
        println!("  - {request}");
    }
    print!("Approve and continue? [y/N]: ");
    io::stdout()
        .flush()
        .map_err(|source_error| anyhow!("failed to flush approval prompt: {source_error}"))?;

    let mut answer = String::new();
    io::stdin()
        .read_line(&mut answer)
        .map_err(|source_error| anyhow!("failed to read approval response: {source_error}"))?;
    let answer = answer.trim().to_ascii_lowercase();
    Ok(answer == "y" || answer == "yes")
}

pub(crate) fn detect_out_of_profile_requests(plan: &ExecutionPlan) -> Vec<String> {
    let mut requested = Vec::new();
    if !command_appears_to_need_network(&plan.command) {
        return requested;
    }

    match &plan.profile.net {
        NetLevel::None => {
            requested.push(
                "network access requested by command but profile network mode is `none`"
                    .to_string(),
            );
        }
        NetLevel::Open => {}
        NetLevel::Filtered { allowed_domains } => {
            let extracted_hosts = extract_hosts_from_command(&plan.command);
            if extracted_hosts.had_ambiguous_targets {
                requested.push(
                    "command appears to need network, but filtered-mode host extraction was ambiguous; explicit approval required"
                        .to_string(),
                );
            }

            if extracted_hosts.hosts.is_empty() {
                if requested.is_empty() {
                    requested.push(
                        "command appears to need network, but filtered-mode host extraction was ambiguous; explicit approval required"
                            .to_string(),
                    );
                }
                return requested;
            }

            let denied = extracted_hosts
                .hosts
                .into_iter()
                .filter(|host| !domain_allowed(host, allowed_domains))
                .collect::<Vec<_>>();
            if !denied.is_empty() {
                requested.push(format!(
                    "command references host(s) outside filtered allowlist: {}",
                    denied.join(", ")
                ));
            }
        }
    }

    requested
}

pub(crate) fn command_appears_to_need_network(command: &[String]) -> bool {
    if command.is_empty() {
        return false;
    }
    if command
        .iter()
        .any(|arg| extract_host_from_reference(arg).is_some())
    {
        return true;
    }

    let executable = command_basename(&command[0]);
    let first_arg = command.get(1).map(|arg| arg.to_ascii_lowercase());
    match executable.as_str() {
        "curl" | "wget" | "http" | "https" | "scp" | "ssh" | "rsync" => true,
        "git" => matches!(
            first_arg.as_deref(),
            Some("clone" | "fetch" | "pull" | "push" | "ls-remote" | "remote" | "submodule")
        ),
        "npm" | "pnpm" | "yarn" => matches!(
            first_arg.as_deref(),
            Some("install" | "add" | "update" | "upgrade" | "publish" | "login")
        ),
        "pip" | "pip3" | "poetry" | "uv" => matches!(
            first_arg.as_deref(),
            Some("install" | "add" | "update" | "publish" | "sync" | "lock" | "export")
        ),
        "cargo" => matches!(
            first_arg.as_deref(),
            Some(
                "add"
                    | "install"
                    | "search"
                    | "publish"
                    | "login"
                    | "owner"
                    | "yank"
                    | "fetch"
                    | "update"
            )
        ),
        "apt" | "apt-get" | "dnf" | "yum" | "apk" | "brew" => true,
        _ => false,
    }
}

#[derive(Debug, Default)]
pub(crate) struct CommandHostExtraction {
    pub(crate) hosts: Vec<String>,
    pub(crate) had_ambiguous_targets: bool,
}

pub(crate) fn extract_hosts_from_command(command: &[String]) -> CommandHostExtraction {
    let mut hosts = BTreeSet::new();
    let mut had_ambiguous_targets = false;
    for arg in command {
        if let Some(host) = extract_host_from_reference(arg) {
            hosts.insert(host);
            continue;
        }

        if is_ambiguous_network_reference(arg) {
            had_ambiguous_targets = true;
        }
    }

    CommandHostExtraction {
        hosts: hosts.into_iter().collect(),
        had_ambiguous_targets,
    }
}

pub(crate) fn extract_host_from_reference(value: &str) -> Option<String> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return None;
    }

    if let Some((_, assigned_value)) = trimmed.split_once('=') {
        if !assigned_value.is_empty() {
            if let Some(host) = extract_host_from_reference(assigned_value) {
                return Some(host);
            }
        }
    }

    for prefix in ["https://", "http://", "ssh://"] {
        if let Some(rest) = trimmed.strip_prefix(prefix) {
            return split_host_port(rest).map(normalize_host);
        }
    }

    if !trimmed.contains("://") {
        if let Some((authority, _path)) = trimmed.split_once(':') {
            if authority.contains('@') {
                return Some(normalize_host(authority));
            }
        }
    }

    None
}

pub(crate) fn is_ambiguous_network_reference(value: &str) -> bool {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return false;
    }

    let candidate = trimmed
        .rsplit_once('=')
        .map(|(_, rhs)| rhs.trim())
        .filter(|rhs| !rhs.is_empty())
        .unwrap_or(trimmed);

    if candidate.starts_with('-') {
        return false;
    }

    if candidate.starts_with('$') || candidate.contains("${") {
        return true;
    }

    if candidate.contains("://") {
        return true;
    }

    if candidate.contains('@') && candidate.contains(':') {
        return true;
    }

    if candidate.eq_ignore_ascii_case("localhost") || candidate.parse::<std::net::IpAddr>().is_ok()
    {
        return true;
    }

    if candidate.contains('/') || candidate.contains('\\') {
        return false;
    }

    candidate.contains('.') && candidate.chars().any(|ch| ch.is_ascii_alphabetic())
}

pub(crate) fn split_host_port(input: &str) -> Option<&str> {
    let host_port = input.split('/').next().unwrap_or_default();
    if host_port.is_empty() {
        return None;
    }

    let host_port = host_port
        .rsplit_once('@')
        .map(|(_, host)| host)
        .unwrap_or(host_port);

    if let Some(rest) = host_port.strip_prefix('[') {
        let (host, _tail) = rest.split_once(']')?;
        return Some(host);
    }

    if let Some((host, _port)) = host_port.rsplit_once(':') {
        if !host.is_empty() && host != host_port {
            return Some(host);
        }
    }
    Some(host_port)
}

pub(crate) fn domain_allowed(host: &str, allowed_domains: &[String]) -> bool {
    let host = normalize_host(host);
    allowed_domains.iter().any(|rule| {
        let rule = normalize_host(rule);
        if let Some(suffix) = rule.strip_prefix("*.") {
            host.ends_with(&format!(".{suffix}"))
        } else {
            host == rule
        }
    })
}

pub(crate) fn normalize_host(input: &str) -> String {
    let without_userinfo = input
        .trim()
        .rsplit_once('@')
        .map(|(_, host)| host)
        .unwrap_or(input.trim());

    without_userinfo
        .trim_start_matches('[')
        .trim_end_matches(']')
        .trim_end_matches('.')
        .to_ascii_lowercase()
}
