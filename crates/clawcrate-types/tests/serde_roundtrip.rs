use std::fmt::Debug;
use std::path::PathBuf;

use chrono::{DateTime, Utc};
use clawcrate_types::{
    Actor, AuditEvent, AuditEventKind, DefaultMode, ExecutionPlan, ExecutionResult, NetLevel,
    Platform, ResolvedProfile, ResourceLimits, Status, SystemCapabilities, WorkspaceMode,
};
use serde::de::DeserializeOwned;
use serde::Serialize;

fn assert_json_roundtrip<T>(value: &T)
where
    T: Serialize + DeserializeOwned + PartialEq + Debug,
{
    let serialized = serde_json::to_string_pretty(value).expect("serialize value to json");
    let deserialized: T = serde_json::from_str(&serialized).expect("deserialize value from json");
    assert_eq!(*value, deserialized);
}

fn ts(input: &str) -> DateTime<Utc> {
    DateTime::parse_from_rfc3339(input)
        .expect("valid RFC3339 timestamp")
        .with_timezone(&Utc)
}

fn sample_resources() -> ResourceLimits {
    ResourceLimits {
        max_cpu_seconds: 600,
        max_memory_mb: 4096,
        max_open_files: 2048,
        max_processes: 256,
        max_output_bytes: 8 * 1024 * 1024,
    }
}

fn sample_profile() -> ResolvedProfile {
    ResolvedProfile {
        name: "build".to_string(),
        fs_read: vec![PathBuf::from("."), PathBuf::from("/usr")],
        fs_write: vec![PathBuf::from("./target")],
        fs_deny: vec![".env".to_string(), ".env.*".to_string()],
        net: NetLevel::None,
        env_scrub: vec!["AWS_*".to_string(), "*_SECRET*".to_string()],
        env_passthrough: vec!["HOME".to_string(), "PATH".to_string()],
        resources: sample_resources(),
        default_mode: DefaultMode::Direct,
    }
}

#[test]
fn resolved_profile_roundtrip() {
    let value = sample_profile();
    assert_json_roundtrip(&value);
}

#[test]
fn filtered_net_level_roundtrip() {
    let value = NetLevel::Filtered {
        allowed_domains: vec!["registry.npmjs.org".to_string(), "*.pkg.dev".to_string()],
    };
    assert_json_roundtrip(&value);
}

#[test]
fn execution_plan_roundtrip() {
    let value = ExecutionPlan {
        id: "0195a4d2-3f72-7a1b-b7af-a9fd8f24d9e2".to_string(),
        command: vec![
            "cargo".to_string(),
            "test".to_string(),
            "--workspace".to_string(),
        ],
        cwd: PathBuf::from("/work/clawcrate"),
        profile: sample_profile(),
        mode: WorkspaceMode::Replica {
            source: PathBuf::from("/work/clawcrate"),
            copy: PathBuf::from("/tmp/clawcrate/exec_123/workspace"),
        },
        actor: Actor::Agent {
            name: "codex".to_string(),
        },
        created_at: ts("2026-04-11T14:30:00Z"),
    };

    assert_json_roundtrip(&value);
}

#[test]
fn audit_event_roundtrip() {
    let value = AuditEvent {
        timestamp: ts("2026-04-11T14:31:00Z"),
        event: AuditEventKind::ReplicaCreated {
            source: PathBuf::from("/work/clawcrate"),
            copy: PathBuf::from("/tmp/clawcrate/exec_123/workspace"),
            excluded: vec![".env".to_string(), ".env.local".to_string()],
        },
    };

    assert_json_roundtrip(&value);
}

#[test]
fn approval_audit_event_roundtrip() {
    let value = AuditEvent {
        timestamp: ts("2026-04-11T14:32:00Z"),
        event: AuditEventKind::ApprovalDecision {
            requested: vec![
                "network: profile blocks network".to_string(),
                "domain: denied.example.com not in allowlist".to_string(),
            ],
            approved: false,
            automated: true,
        },
    };

    assert_json_roundtrip(&value);
}

#[test]
fn execution_result_roundtrip() {
    let value = ExecutionResult {
        id: "0195a4d2-3f72-7a1b-b7af-a9fd8f24d9e2".to_string(),
        exit_code: Some(0),
        status: Status::Success,
        duration_ms: 4217,
        artifacts_dir: PathBuf::from("/home/user/.clawcrate/runs/exec_0195a4d2"),
    };

    assert_json_roundtrip(&value);
}

#[test]
fn system_capabilities_roundtrip() {
    let value = SystemCapabilities {
        platform: Platform::Linux,
        landlock_abi: Some(4),
        seccomp_available: true,
        seatbelt_available: false,
        user_namespaces: true,
        macos_version: None,
        kernel_version: Some("6.8.0".to_string()),
    };

    assert_json_roundtrip(&value);
}
