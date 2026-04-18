#![forbid(unsafe_code)]

use std::path::PathBuf;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum DefaultMode {
    Direct,
    Replica,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum WorkspaceMode {
    Direct,
    Replica { source: PathBuf, copy: PathBuf },
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ResolvedProfile {
    pub name: String,
    pub fs_read: Vec<PathBuf>,
    pub fs_write: Vec<PathBuf>,
    pub fs_deny: Vec<String>,
    pub net: NetLevel,
    pub env_scrub: Vec<String>,
    pub env_passthrough: Vec<String>,
    pub resources: ResourceLimits,
    pub default_mode: DefaultMode,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ExecutionPlan {
    pub id: String,
    pub command: Vec<String>,
    pub cwd: PathBuf,
    pub profile: ResolvedProfile,
    pub mode: WorkspaceMode,
    pub actor: Actor,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum Actor {
    Human,
    Agent { name: String },
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum NetLevel {
    None,
    Open,
    Filtered { allowed_domains: Vec<String> },
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ResourceLimits {
    pub max_cpu_seconds: u64,
    pub max_memory_mb: u64,
    pub max_open_files: u64,
    pub max_processes: u64,
    pub max_output_bytes: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ExecutionResult {
    pub id: String,
    pub exit_code: Option<i32>,
    pub status: Status,
    pub duration_ms: u64,
    pub artifacts_dir: PathBuf,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum Status {
    Success,
    Failed,
    Timeout,
    Killed,
    SandboxError(String),
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AuditEvent {
    pub timestamp: DateTime<Utc>,
    pub event: AuditEventKind,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum AuditEventKind {
    SandboxApplied {
        backend: String,
        capabilities: Vec<String>,
    },
    EnvScrubbed {
        removed: Vec<String>,
    },
    ProcessStarted {
        pid: u32,
        command: Vec<String>,
    },
    ProcessExited {
        exit_code: i32,
        duration_ms: u64,
    },
    PermissionBlocked {
        resource: String,
        reason: String,
    },
    ReplicaCreated {
        source: PathBuf,
        copy: PathBuf,
        excluded: Vec<String>,
    },
    ReplicaSyncBack {
        approved: bool,
        changes: usize,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SystemCapabilities {
    pub platform: Platform,
    pub landlock_abi: Option<u8>,
    pub seccomp_available: bool,
    pub seatbelt_available: bool,
    pub user_namespaces: bool,
    pub macos_version: Option<String>,
    pub kernel_version: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum Platform {
    Linux,
    MacOS,
}

#[derive(thiserror::Error, Debug)]
pub enum ClawCrateError {
    #[error("Profile not found: {0}")]
    ProfileNotFound(String),
    #[error("Sandbox setup failed: {0}")]
    SandboxSetup(String),
    #[error("Command execution failed: {0}")]
    Execution(String),
    #[error("Replica mode failed: {0}")]
    Replica(String),
    #[error("System not supported: {0}")]
    Unsupported(String),
}
