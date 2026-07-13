//! audit_export module (extracted from main.rs; see #277).

use crate::{cli::*, support::*};
use anyhow::{anyhow, Result};
use clawcrate_audit::AUDIT_NDJSON;
use clawcrate_types::{AuditEvent, AuditEventKind};
use serde::Deserialize;

#[derive(Debug, Deserialize)]
pub(crate) struct AuditNdjsonLine {
    #[serde(flatten)]
    pub(crate) event: AuditEvent,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum AuditExportSeverity {
    Low,
    Medium,
    High,
}

impl AuditExportSeverity {
    fn cef(self) -> u8 {
        match self {
            Self::Low => 2,
            Self::Medium => 5,
            Self::High => 8,
        }
    }

    fn syslog_severity(self) -> u8 {
        match self {
            Self::Low => 6,    // informational
            Self::Medium => 4, // warning
            Self::High => 3,   // error
        }
    }

    fn label(self) -> &'static str {
        match self {
            Self::Low => "low",
            Self::Medium => "medium",
            Self::High => "high",
        }
    }
}

pub(crate) fn handle_audit(args: AuditArgs) -> Result<()> {
    match args.command {
        AuditCommand::Export(args) => handle_audit_export(args),
    }
}

pub(crate) fn handle_audit_export(args: AuditExportArgs) -> Result<()> {
    let audit_path = runs_root()?.join(&args.run_id).join(AUDIT_NDJSON);
    let content = std::fs::read_to_string(&audit_path)
        .map_err(|source| anyhow!("failed to read {}: {source}", audit_path.display()))?;
    let exported = export_audit_content(&args.run_id, &content, args.format)?;
    print!("{exported}");
    Ok(())
}

pub(crate) fn export_audit_content(
    run_id: &str,
    content: &str,
    format: AuditExportFormat,
) -> Result<String> {
    if format == AuditExportFormat::Json {
        return Ok(content.to_string());
    }

    let events = parse_audit_events_for_export(content)?;
    match format {
        AuditExportFormat::Json => unreachable!("json passthrough handled above"),
        AuditExportFormat::Cef => Ok(events
            .iter()
            .map(|event| format_cef_event(run_id, event))
            .collect::<Vec<_>>()
            .join("\n")
            + "\n"),
        AuditExportFormat::Syslog => Ok(events
            .iter()
            .map(|event| format_syslog_event(run_id, event))
            .collect::<Vec<_>>()
            .join("\n")
            + "\n"),
        AuditExportFormat::Elastic => {
            let mut out = String::new();
            for event in &events {
                out.push_str(&format_elastic_event(run_id, event)?);
            }
            Ok(out)
        }
    }
}

pub(crate) fn parse_audit_events_for_export(content: &str) -> Result<Vec<AuditEvent>> {
    let mut events = Vec::new();
    for (index, line) in content.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let value: serde_json::Value = serde_json::from_str(line).map_err(|source| {
            anyhow!("failed to parse audit.ndjson line {}: {source}", index + 1)
        })?;
        if value
            .get("kind")
            .and_then(serde_json::Value::as_str)
            .is_some_and(|kind| kind == "BlockSignature")
        {
            continue;
        }
        let event = serde_json::from_value::<AuditNdjsonLine>(value)
            .map_err(|source| anyhow!("failed to parse audit event line {}: {source}", index + 1))?
            .event;
        events.push(event);
    }
    Ok(events)
}

pub(crate) fn audit_event_export_metadata(
    event: &AuditEventKind,
) -> (&'static str, &'static str, AuditExportSeverity) {
    match event {
        AuditEventKind::SandboxApplied { .. } => {
            ("sandbox_applied", "sandbox", AuditExportSeverity::Low)
        }
        AuditEventKind::EnvScrubbed { .. } => {
            ("env_scrubbed", "environment", AuditExportSeverity::Medium)
        }
        AuditEventKind::ProcessStarted { .. } => {
            ("process_started", "process", AuditExportSeverity::Low)
        }
        AuditEventKind::ProcessExited { exit_code, .. } if *exit_code == 0 => {
            ("process_exited", "process", AuditExportSeverity::Low)
        }
        AuditEventKind::ProcessExited { .. } => {
            ("process_exited", "process", AuditExportSeverity::Medium)
        }
        AuditEventKind::PermissionBlocked { .. } => {
            ("permission_blocked", "security", AuditExportSeverity::High)
        }
        AuditEventKind::ReplicaCreated { .. } => {
            ("replica_created", "workspace", AuditExportSeverity::Low)
        }
        AuditEventKind::ReplicaSyncBack { approved, .. } if *approved => (
            "replica_sync_back",
            "workspace",
            AuditExportSeverity::Medium,
        ),
        AuditEventKind::ReplicaSyncBack { .. } => {
            ("replica_sync_back", "workspace", AuditExportSeverity::Low)
        }
        AuditEventKind::ApprovalDecision { approved, .. } if *approved => {
            ("approval_decision", "approval", AuditExportSeverity::Medium)
        }
        AuditEventKind::ApprovalDecision { .. } => {
            ("approval_decision", "approval", AuditExportSeverity::High)
        }
    }
}

pub(crate) fn audit_event_message(event: &AuditEventKind) -> String {
    match event {
        AuditEventKind::SandboxApplied {
            backend,
            capabilities,
        } => format!(
            "sandbox applied using {backend} with {} capabilities",
            capabilities.len()
        ),
        AuditEventKind::EnvScrubbed { removed } => {
            format!("scrubbed {} environment variable(s)", removed.len())
        }
        AuditEventKind::ProcessStarted { pid, command } => {
            format!("process started pid={pid} command={}", command.join(" "))
        }
        AuditEventKind::ProcessExited {
            exit_code,
            duration_ms,
        } => format!("process exited code={exit_code} duration_ms={duration_ms}"),
        AuditEventKind::PermissionBlocked { resource, reason } => {
            format!("permission blocked resource={resource} reason={reason}")
        }
        AuditEventKind::ReplicaCreated {
            source,
            copy,
            excluded,
        } => format!(
            "replica created source={} copy={} excluded={}",
            source.display(),
            copy.display(),
            excluded.len()
        ),
        AuditEventKind::ReplicaSyncBack { approved, changes } => {
            format!("replica sync-back approved={approved} changes={changes}")
        }
        AuditEventKind::ApprovalDecision {
            requested,
            approved,
            automated,
        } => format!(
            "approval decision approved={approved} automated={automated} requested={}",
            requested.len()
        ),
    }
}

pub(crate) fn format_cef_event(run_id: &str, event: &AuditEvent) -> String {
    let (signature_id, category, severity) = audit_event_export_metadata(&event.event);
    let message = audit_event_message(&event.event);
    format!(
        "CEF:0|ClawCrate|clawcrate|{}|{}|{}|{}|rt={} cs1Label=run_id cs1={} cs2Label=category cs2={} msg={}",
        env!("CARGO_PKG_VERSION"),
        escape_cef_header(signature_id),
        escape_cef_header(signature_id),
        severity.cef(),
        event.timestamp.to_rfc3339(),
        escape_cef_extension(run_id),
        escape_cef_extension(category),
        escape_cef_extension(&message)
    )
}

pub(crate) fn format_syslog_event(run_id: &str, event: &AuditEvent) -> String {
    let (event_name, category, severity) = audit_event_export_metadata(&event.event);
    let pri = 8 + severity.syslog_severity(); // facility=user(1) * 8 + severity
    let message = audit_event_message(&event.event);
    format!(
        "<{pri}>1 {} - clawcrate {} {} [clawcrate@54531 run_id=\"{}\" category=\"{}\" severity=\"{}\"] {}",
        event.timestamp.to_rfc3339(),
        sanitize_syslog_token(run_id),
        sanitize_syslog_token(event_name),
        escape_syslog_param(run_id),
        escape_syslog_param(category),
        severity.label(),
        sanitize_syslog_message(&message)
    )
}

pub(crate) fn format_elastic_event(run_id: &str, event: &AuditEvent) -> Result<String> {
    let (event_name, category, severity) = audit_event_export_metadata(&event.event);
    let action = serde_json::json!({
        "index": {
            "_index": "clawcrate-audit",
        }
    });
    let source = serde_json::json!({
        "@timestamp": event.timestamp,
        "run_id": run_id,
        "event": {
            "kind": event_name,
            "category": category,
            "severity": severity.label(),
        },
        "message": audit_event_message(&event.event),
        "clawcrate": event,
    });
    Ok(format!(
        "{}\n{}\n",
        serde_json::to_string(&action)?,
        serde_json::to_string(&source)?
    ))
}

pub(crate) fn escape_cef_header(value: &str) -> String {
    value
        .replace('\\', r"\\")
        .replace('|', r"\|")
        .replace('\n', r"\n")
        .replace('\r', r"\r")
}

pub(crate) fn escape_cef_extension(value: &str) -> String {
    value
        .replace('\\', r"\\")
        .replace('=', r"\=")
        .replace('\n', r"\n")
        .replace('\r', r"\r")
}

pub(crate) fn sanitize_syslog_token(value: &str) -> String {
    let sanitized = value
        .chars()
        .filter(|ch| ch.is_ascii_graphic() && *ch != ']' && *ch != '"')
        .take(48)
        .collect::<String>();
    if sanitized.is_empty() {
        "-".to_string()
    } else {
        sanitized
    }
}

pub(crate) fn escape_syslog_param(value: &str) -> String {
    value
        .replace('\\', r"\\")
        .replace('"', r#"\""#)
        .replace(']', r"\]")
}

pub(crate) fn sanitize_syslog_message(value: &str) -> String {
    value.replace(['\n', '\r'], " ")
}
