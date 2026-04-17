#![forbid(unsafe_code)]

use std::fs::{self, File, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};

use clawcrate_types::{AuditEvent, ExecutionPlan, ExecutionResult};
use serde::Serialize;

pub const CRATE_NAME: &str = "clawcrate-audit";
pub const PLAN_JSON: &str = "plan.json";
pub const RESULT_JSON: &str = "result.json";
pub const AUDIT_NDJSON: &str = "audit.ndjson";
pub const FS_DIFF_JSON: &str = "fs-diff.json";

#[derive(Debug, Clone)]
pub struct ArtifactWriter {
    artifacts_dir: PathBuf,
}

impl ArtifactWriter {
    pub fn new(runs_root: &Path, execution_id: &str) -> Result<Self, ArtifactWriterError> {
        let artifacts_dir = runs_root.join(execution_id);
        Self::from_artifacts_dir(artifacts_dir)
    }

    pub fn from_artifacts_dir<P: Into<PathBuf>>(
        artifacts_dir: P,
    ) -> Result<Self, ArtifactWriterError> {
        let artifacts_dir = artifacts_dir.into();
        fs::create_dir_all(&artifacts_dir).map_err(|source| {
            ArtifactWriterError::CreateArtifactsDir {
                path: artifacts_dir.clone(),
                source,
            }
        })?;
        Ok(Self { artifacts_dir })
    }

    pub fn artifacts_dir(&self) -> &Path {
        &self.artifacts_dir
    }

    pub fn plan_path(&self) -> PathBuf {
        self.artifacts_dir.join(PLAN_JSON)
    }

    pub fn result_path(&self) -> PathBuf {
        self.artifacts_dir.join(RESULT_JSON)
    }

    pub fn audit_ndjson_path(&self) -> PathBuf {
        self.artifacts_dir.join(AUDIT_NDJSON)
    }

    pub fn fs_diff_path(&self) -> PathBuf {
        self.artifacts_dir.join(FS_DIFF_JSON)
    }

    pub fn write_plan(&self, plan: &ExecutionPlan) -> Result<(), ArtifactWriterError> {
        write_json_file(&self.plan_path(), plan)
    }

    pub fn write_result(&self, result: &ExecutionResult) -> Result<(), ArtifactWriterError> {
        write_json_file(&self.result_path(), result)
    }

    pub fn write_fs_diff<T: Serialize>(&self, fs_diff: &T) -> Result<(), ArtifactWriterError> {
        write_json_file(&self.fs_diff_path(), fs_diff)
    }

    pub fn append_audit_event(&self, event: &AuditEvent) -> Result<(), ArtifactWriterError> {
        let path = self.audit_ndjson_path();
        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&path)
            .map_err(|source| ArtifactWriterError::OpenFile {
                path: path.clone(),
                source,
            })?;
        serde_json::to_writer(&mut file, event).map_err(|source| {
            ArtifactWriterError::WriteJson {
                path: path.clone(),
                source,
            }
        })?;
        file.write_all(b"\n")
            .map_err(|source| ArtifactWriterError::WriteIo {
                path: path.clone(),
                source,
            })?;
        file.flush()
            .map_err(|source| ArtifactWriterError::WriteIo { path, source })?;
        Ok(())
    }
}

#[derive(Debug, thiserror::Error)]
pub enum ArtifactWriterError {
    #[error("failed to create artifacts directory at {path}: {source}")]
    CreateArtifactsDir {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error("failed to open file at {path}: {source}")]
    OpenFile {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error("failed to serialize/write JSON at {path}: {source}")]
    WriteJson {
        path: PathBuf,
        #[source]
        source: serde_json::Error,
    },
    #[error("failed to write file at {path}: {source}")]
    WriteIo {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
}

fn write_json_file<T: Serialize>(path: &Path, value: &T) -> Result<(), ArtifactWriterError> {
    let mut file = File::create(path).map_err(|source| ArtifactWriterError::OpenFile {
        path: path.to_path_buf(),
        source,
    })?;
    serde_json::to_writer_pretty(&mut file, value).map_err(|source| {
        ArtifactWriterError::WriteJson {
            path: path.to_path_buf(),
            source,
        }
    })?;
    file.write_all(b"\n")
        .map_err(|source| ArtifactWriterError::WriteIo {
            path: path.to_path_buf(),
            source,
        })?;
    file.flush()
        .map_err(|source| ArtifactWriterError::WriteIo {
            path: path.to_path_buf(),
            source,
        })?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::path::PathBuf;
    use std::time::{SystemTime, UNIX_EPOCH};

    use chrono::Utc;
    use clawcrate_types::{
        Actor, AuditEvent, AuditEventKind, DefaultMode, ExecutionPlan, ExecutionResult, NetLevel,
        ResolvedProfile, ResourceLimits, Status, WorkspaceMode,
    };
    use serde::{Deserialize, Serialize};

    use super::{ArtifactWriter, AUDIT_NDJSON, FS_DIFF_JSON, PLAN_JSON, RESULT_JSON};

    #[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
    struct FsDiffFixture {
        path: String,
        kind: String,
        size_bytes: Option<u64>,
    }

    fn unique_tmp_dir(prefix: &str) -> PathBuf {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system time after unix epoch")
            .as_nanos();
        let dir = std::env::temp_dir().join(format!("{prefix}_{nanos}_{}", std::process::id()));
        fs::create_dir_all(&dir).expect("create temp test directory");
        dir
    }

    fn test_plan() -> ExecutionPlan {
        ExecutionPlan {
            id: "exec-fixture".to_string(),
            command: vec!["echo".to_string(), "hello".to_string()],
            cwd: PathBuf::from("/tmp/workspace"),
            profile: ResolvedProfile {
                name: "safe".to_string(),
                fs_read: vec![PathBuf::from("/tmp/workspace")],
                fs_write: vec![PathBuf::from("/tmp/workspace")],
                fs_deny: vec![],
                net: NetLevel::None,
                env_scrub: vec!["*_TOKEN".to_string()],
                env_passthrough: vec!["HOME".to_string(), "PATH".to_string()],
                resources: ResourceLimits {
                    max_cpu_seconds: 60,
                    max_memory_mb: 256,
                    max_open_files: 512,
                    max_processes: 32,
                    max_output_bytes: 1_048_576,
                },
                default_mode: DefaultMode::Direct,
            },
            mode: WorkspaceMode::Direct,
            actor: Actor::Human,
            created_at: Utc::now(),
        }
    }

    fn test_result() -> ExecutionResult {
        ExecutionResult {
            id: "exec-fixture".to_string(),
            exit_code: Some(0),
            status: Status::Success,
            duration_ms: 123,
            artifacts_dir: PathBuf::from("/tmp/run/exec-fixture"),
        }
    }

    #[test]
    fn setup_creates_artifact_directory_and_paths() {
        let root = unique_tmp_dir("clawcrate_audit_setup");
        let writer = ArtifactWriter::new(&root, "exec-123").expect("create writer");

        assert!(writer.artifacts_dir().exists());
        assert_eq!(writer.plan_path(), root.join("exec-123").join(PLAN_JSON));
        assert_eq!(
            writer.result_path(),
            root.join("exec-123").join(RESULT_JSON)
        );
        assert_eq!(
            writer.audit_ndjson_path(),
            root.join("exec-123").join(AUDIT_NDJSON)
        );
        assert_eq!(
            writer.fs_diff_path(),
            root.join("exec-123").join(FS_DIFF_JSON)
        );
    }

    #[test]
    fn writes_plan_result_and_fs_diff_json_files() {
        let root = unique_tmp_dir("clawcrate_audit_write_json");
        let writer = ArtifactWriter::new(&root, "exec-456").expect("create writer");
        let plan = test_plan();
        let result = test_result();
        let fs_diff = vec![FsDiffFixture {
            path: "/tmp/workspace/file.txt".to_string(),
            kind: "Modified".to_string(),
            size_bytes: Some(42),
        }];

        writer.write_plan(&plan).expect("write plan");
        writer.write_result(&result).expect("write result");
        writer.write_fs_diff(&fs_diff).expect("write fs diff");

        let parsed_plan: ExecutionPlan =
            serde_json::from_str(&fs::read_to_string(writer.plan_path()).expect("read plan"))
                .expect("parse plan");
        let parsed_result: ExecutionResult =
            serde_json::from_str(&fs::read_to_string(writer.result_path()).expect("read result"))
                .expect("parse result");
        let parsed_diff: Vec<FsDiffFixture> =
            serde_json::from_str(&fs::read_to_string(writer.fs_diff_path()).expect("read fs diff"))
                .expect("parse fs diff");

        assert_eq!(parsed_plan.id, plan.id);
        assert_eq!(parsed_result.exit_code, result.exit_code);
        assert_eq!(parsed_diff, fs_diff);
    }

    #[test]
    fn appends_audit_events_as_ndjson_lines() {
        let root = unique_tmp_dir("clawcrate_audit_ndjson");
        let writer = ArtifactWriter::new(&root, "exec-789").expect("create writer");

        let event1 = AuditEvent {
            timestamp: Utc::now(),
            event: AuditEventKind::EnvScrubbed {
                removed: vec!["API_TOKEN".to_string()],
            },
        };
        let event2 = AuditEvent {
            timestamp: Utc::now(),
            event: AuditEventKind::ProcessStarted {
                pid: 4242,
                command: vec!["echo".to_string(), "hello".to_string()],
            },
        };

        writer.append_audit_event(&event1).expect("append event 1");
        writer.append_audit_event(&event2).expect("append event 2");

        let ndjson = fs::read_to_string(writer.audit_ndjson_path()).expect("read ndjson");
        let lines: Vec<&str> = ndjson.lines().collect();
        assert_eq!(lines.len(), 2);

        let parsed1: AuditEvent = serde_json::from_str(lines[0]).expect("parse first line");
        let parsed2: AuditEvent = serde_json::from_str(lines[1]).expect("parse second line");
        assert!(matches!(parsed1.event, AuditEventKind::EnvScrubbed { .. }));
        assert!(matches!(
            parsed2.event,
            AuditEventKind::ProcessStarted { .. }
        ));
    }
}
