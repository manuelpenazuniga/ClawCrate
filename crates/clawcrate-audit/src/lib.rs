#![forbid(unsafe_code)]

use std::fs::{self, File, OpenOptions};
use std::io::{self, BufRead, BufReader, Write};
use std::path::{Path, PathBuf};

use clawcrate_types::{AuditEvent, ExecutionPlan, ExecutionResult};
use rusqlite::{params, Connection};
use serde::Serialize;

pub const CRATE_NAME: &str = "clawcrate-audit";
pub const PLAN_JSON: &str = "plan.json";
pub const RESULT_JSON: &str = "result.json";
pub const AUDIT_NDJSON: &str = "audit.ndjson";
pub const FS_DIFF_JSON: &str = "fs-diff.json";
pub const DEFAULT_AUDIT_DB: &str = "audit-index.sqlite3";

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

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SqliteIndexedRun {
    pub execution_id: String,
    pub has_result: bool,
    pub event_count: usize,
}

#[derive(Debug)]
pub struct SqliteAuditIndex {
    db_path: PathBuf,
    connection: Connection,
}

impl SqliteAuditIndex {
    pub fn open(path: impl AsRef<Path>) -> Result<Self, SqliteAuditIndexError> {
        let db_path = path.as_ref().to_path_buf();
        if let Some(parent) = sqlite_db_parent_dir(&db_path) {
            fs::create_dir_all(parent).map_err(|source| {
                SqliteAuditIndexError::CreateParentDir {
                    path: parent.to_path_buf(),
                    source,
                }
            })?;
        }

        let connection =
            Connection::open(&db_path).map_err(|source| SqliteAuditIndexError::OpenDatabase {
                path: db_path.clone(),
                source,
            })?;

        connection.execute_batch(
            "PRAGMA foreign_keys = ON;
             PRAGMA journal_mode = WAL;
             CREATE TABLE IF NOT EXISTS executions (
               execution_id TEXT PRIMARY KEY,
               created_at TEXT NOT NULL,
               command_json TEXT NOT NULL,
               cwd TEXT NOT NULL,
               profile_name TEXT NOT NULL,
               mode_json TEXT NOT NULL,
               net_json TEXT NOT NULL,
               artifacts_dir TEXT,
               status TEXT,
               status_detail TEXT,
               exit_code INTEGER,
               duration_ms INTEGER,
               indexed_at TEXT NOT NULL
             );
             CREATE TABLE IF NOT EXISTS audit_events (
               execution_id TEXT NOT NULL,
               sequence INTEGER NOT NULL,
               timestamp TEXT NOT NULL,
               event_kind TEXT NOT NULL,
               payload_json TEXT NOT NULL,
               PRIMARY KEY(execution_id, sequence),
               FOREIGN KEY(execution_id) REFERENCES executions(execution_id) ON DELETE CASCADE
             );
             CREATE INDEX IF NOT EXISTS idx_audit_events_kind ON audit_events(event_kind);
             CREATE INDEX IF NOT EXISTS idx_audit_events_ts ON audit_events(execution_id, timestamp);",
        )
        .map_err(|source| SqliteAuditIndexError::MigrateDatabase {
            path: db_path.clone(),
            source,
        })?;

        Ok(Self {
            db_path,
            connection,
        })
    }

    pub fn db_path(&self) -> &Path {
        &self.db_path
    }

    pub fn index_artifacts_dir(
        &mut self,
        artifacts_dir: &Path,
    ) -> Result<SqliteIndexedRun, SqliteAuditIndexError> {
        let plan_path = artifacts_dir.join(PLAN_JSON);
        let result_path = artifacts_dir.join(RESULT_JSON);
        let audit_path = artifacts_dir.join(AUDIT_NDJSON);

        let plan: ExecutionPlan = read_json_file(&plan_path)?;
        let result = if result_path.exists() {
            Some(read_json_file::<ExecutionResult>(&result_path)?)
        } else {
            None
        };
        let audit_events = read_ndjson_audit_events(&audit_path)?;

        let mode_json = serde_json::to_string(&plan.mode).map_err(|source| {
            SqliteAuditIndexError::Serialize {
                path: plan_path.clone(),
                source,
            }
        })?;
        let net_json = serde_json::to_string(&plan.profile.net).map_err(|source| {
            SqliteAuditIndexError::Serialize {
                path: plan_path.clone(),
                source,
            }
        })?;
        let command_json = serde_json::to_string(&plan.command).map_err(|source| {
            SqliteAuditIndexError::Serialize {
                path: plan_path.clone(),
                source,
            }
        })?;

        let (status, status_detail, exit_code, duration_ms, artifacts_dir_value) = match &result {
            Some(value) => {
                let (status_label, detail) = result_status_columns(&value.status);
                (
                    Some(status_label),
                    detail,
                    value.exit_code,
                    Some(value.duration_ms as i64),
                    Some(value.artifacts_dir.display().to_string()),
                )
            }
            None => (None, None, None, None, None),
        };

        let tx = self.connection.transaction().map_err(|source| {
            SqliteAuditIndexError::WriteDatabase {
                path: self.db_path.clone(),
                source,
            }
        })?;

        tx.execute(
            "INSERT INTO executions (
               execution_id, created_at, command_json, cwd, profile_name, mode_json, net_json,
               artifacts_dir, status, status_detail, exit_code, duration_ms, indexed_at
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13)
             ON CONFLICT(execution_id) DO UPDATE SET
               created_at=excluded.created_at,
               command_json=excluded.command_json,
               cwd=excluded.cwd,
               profile_name=excluded.profile_name,
               mode_json=excluded.mode_json,
               net_json=excluded.net_json,
               artifacts_dir=excluded.artifacts_dir,
               status=excluded.status,
               status_detail=excluded.status_detail,
               exit_code=excluded.exit_code,
               duration_ms=excluded.duration_ms,
               indexed_at=excluded.indexed_at",
            params![
                plan.id,
                plan.created_at.to_rfc3339(),
                command_json,
                plan.cwd.display().to_string(),
                plan.profile.name,
                mode_json,
                net_json,
                artifacts_dir_value,
                status,
                status_detail,
                exit_code,
                duration_ms,
                chrono::Utc::now().to_rfc3339(),
            ],
        )
        .map_err(|source| SqliteAuditIndexError::WriteDatabase {
            path: self.db_path.clone(),
            source,
        })?;

        tx.execute(
            "DELETE FROM audit_events WHERE execution_id = ?1",
            params![plan.id],
        )
        .map_err(|source| SqliteAuditIndexError::WriteDatabase {
            path: self.db_path.clone(),
            source,
        })?;

        for (sequence, event) in audit_events.iter().enumerate() {
            let payload_json = serde_json::to_string(event).map_err(|source| {
                SqliteAuditIndexError::Serialize {
                    path: audit_path.clone(),
                    source,
                }
            })?;
            tx.execute(
                "INSERT INTO audit_events (
                   execution_id, sequence, timestamp, event_kind, payload_json
                 ) VALUES (?1, ?2, ?3, ?4, ?5)",
                params![
                    plan.id,
                    sequence as i64,
                    event.timestamp.to_rfc3339(),
                    audit_event_kind_label(&event.event),
                    payload_json
                ],
            )
            .map_err(|source| SqliteAuditIndexError::WriteDatabase {
                path: self.db_path.clone(),
                source,
            })?;
        }

        tx.commit()
            .map_err(|source| SqliteAuditIndexError::WriteDatabase {
                path: self.db_path.clone(),
                source,
            })?;

        Ok(SqliteIndexedRun {
            execution_id: plan.id,
            has_result: result.is_some(),
            event_count: audit_events.len(),
        })
    }
}

#[derive(Debug, thiserror::Error)]
pub enum SqliteAuditIndexError {
    #[error("failed to create SQLite parent directory {path}: {source}")]
    CreateParentDir {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error("failed to open SQLite index at {path}: {source}")]
    OpenDatabase {
        path: PathBuf,
        #[source]
        source: rusqlite::Error,
    },
    #[error("failed to migrate SQLite index at {path}: {source}")]
    MigrateDatabase {
        path: PathBuf,
        #[source]
        source: rusqlite::Error,
    },
    #[error("failed to write SQLite index at {path}: {source}")]
    WriteDatabase {
        path: PathBuf,
        #[source]
        source: rusqlite::Error,
    },
    #[error("failed to read artifact file {path}: {source}")]
    ReadArtifact {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error("failed to parse JSON artifact {path}: {source}")]
    ParseJson {
        path: PathBuf,
        #[source]
        source: serde_json::Error,
    },
    #[error("failed to parse audit event line {line} in {path}: {source}")]
    ParseNdjsonLine {
        path: PathBuf,
        line: usize,
        #[source]
        source: serde_json::Error,
    },
    #[error("failed to serialize index payload for {path}: {source}")]
    Serialize {
        path: PathBuf,
        #[source]
        source: serde_json::Error,
    },
    #[error("failed to read audit event line {line} in {path}: {source}")]
    ReadNdjsonLine {
        path: PathBuf,
        line: usize,
        #[source]
        source: io::Error,
    },
}

fn sqlite_db_parent_dir(path: &Path) -> Option<&Path> {
    let parent = path.parent()?;
    if parent.as_os_str().is_empty() {
        None
    } else {
        Some(parent)
    }
}

fn read_json_file<T: serde::de::DeserializeOwned>(path: &Path) -> Result<T, SqliteAuditIndexError> {
    let file = File::open(path).map_err(|source| SqliteAuditIndexError::ReadArtifact {
        path: path.to_path_buf(),
        source,
    })?;
    let reader = BufReader::new(file);
    serde_json::from_reader(reader).map_err(|source| SqliteAuditIndexError::ParseJson {
        path: path.to_path_buf(),
        source,
    })
}

fn read_ndjson_audit_events(path: &Path) -> Result<Vec<AuditEvent>, SqliteAuditIndexError> {
    if !path.exists() {
        return Ok(Vec::new());
    }
    let file = File::open(path).map_err(|source| SqliteAuditIndexError::ReadArtifact {
        path: path.to_path_buf(),
        source,
    })?;
    let reader = BufReader::new(file);

    let mut events = Vec::new();
    for (index, line) in reader.lines().enumerate() {
        let line = line.map_err(|source| SqliteAuditIndexError::ReadNdjsonLine {
            path: path.to_path_buf(),
            line: index + 1,
            source,
        })?;
        if line.trim().is_empty() {
            continue;
        }
        let event = serde_json::from_str::<AuditEvent>(&line).map_err(|source| {
            SqliteAuditIndexError::ParseNdjsonLine {
                path: path.to_path_buf(),
                line: index + 1,
                source,
            }
        })?;
        events.push(event);
    }
    Ok(events)
}

fn result_status_columns(status: &clawcrate_types::Status) -> (&'static str, Option<String>) {
    match status {
        clawcrate_types::Status::Success => ("success", None),
        clawcrate_types::Status::Failed => ("failed", None),
        clawcrate_types::Status::Timeout => ("timeout", None),
        clawcrate_types::Status::Killed => ("killed", None),
        clawcrate_types::Status::SandboxError(reason) => ("sandbox_error", Some(reason.clone())),
    }
}

fn audit_event_kind_label(event: &clawcrate_types::AuditEventKind) -> &'static str {
    match event {
        clawcrate_types::AuditEventKind::SandboxApplied { .. } => "sandbox_applied",
        clawcrate_types::AuditEventKind::EnvScrubbed { .. } => "env_scrubbed",
        clawcrate_types::AuditEventKind::ProcessStarted { .. } => "process_started",
        clawcrate_types::AuditEventKind::ProcessExited { .. } => "process_exited",
        clawcrate_types::AuditEventKind::PermissionBlocked { .. } => "permission_blocked",
        clawcrate_types::AuditEventKind::ReplicaCreated { .. } => "replica_created",
        clawcrate_types::AuditEventKind::ReplicaSyncBack { .. } => "replica_sync_back",
        clawcrate_types::AuditEventKind::ApprovalDecision { .. } => "approval_decision",
    }
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::path::{Path, PathBuf};
    use std::sync::Mutex;
    use std::time::{SystemTime, UNIX_EPOCH};

    use chrono::Utc;
    use clawcrate_types::{
        Actor, AuditEvent, AuditEventKind, DefaultMode, ExecutionPlan, ExecutionResult, NetLevel,
        ResolvedProfile, ResourceLimits, Status, WorkspaceMode,
    };
    use rusqlite::Connection;
    use serde::{Deserialize, Serialize};

    use super::{
        ArtifactWriter, SqliteAuditIndex, AUDIT_NDJSON, FS_DIFF_JSON, PLAN_JSON, RESULT_JSON,
    };

    static CWD_LOCK: Mutex<()> = Mutex::new(());

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

    #[test]
    fn sqlite_indexer_upserts_run_and_events_from_artifacts() {
        let root = unique_tmp_dir("clawcrate_audit_sqlite_index");
        let writer = ArtifactWriter::new(&root, "exec-001").expect("create writer");
        let plan = test_plan();
        let result = test_result();

        writer.write_plan(&plan).expect("write plan");
        writer.write_result(&result).expect("write result");
        writer
            .append_audit_event(&AuditEvent {
                timestamp: Utc::now(),
                event: AuditEventKind::SandboxApplied {
                    backend: "linux".to_string(),
                    capabilities: vec!["landlock".to_string(), "seccomp".to_string()],
                },
            })
            .expect("append event 1");
        writer
            .append_audit_event(&AuditEvent {
                timestamp: Utc::now(),
                event: AuditEventKind::ProcessExited {
                    exit_code: 0,
                    duration_ms: 55,
                },
            })
            .expect("append event 2");

        let db_path = root.join("audit-index.sqlite3");
        let mut index = SqliteAuditIndex::open(&db_path).expect("open sqlite index");
        let indexed = index
            .index_artifacts_dir(writer.artifacts_dir())
            .expect("index artifacts");
        assert_eq!(indexed.execution_id, plan.id);
        assert!(indexed.has_result);
        assert_eq!(indexed.event_count, 2);

        let conn = Connection::open(db_path).expect("open sqlite db");
        let (profile_name, status, event_count): (String, String, i64) = conn
            .query_row(
                "SELECT profile_name, status, (SELECT COUNT(*) FROM audit_events WHERE execution_id = executions.execution_id) FROM executions WHERE execution_id = ?1",
                [plan.id.as_str()],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .expect("query indexed execution");
        assert_eq!(profile_name, "safe");
        assert_eq!(status, "success");
        assert_eq!(event_count, 2);
    }

    #[test]
    fn sqlite_indexer_accepts_missing_result_and_audit_files() {
        let root = unique_tmp_dir("clawcrate_audit_sqlite_partial");
        let writer = ArtifactWriter::new(&root, "exec-002").expect("create writer");
        writer.write_plan(&test_plan()).expect("write plan");

        let db_path = root.join("audit-index.sqlite3");
        let mut index = SqliteAuditIndex::open(&db_path).expect("open sqlite index");
        let indexed = index
            .index_artifacts_dir(writer.artifacts_dir())
            .expect("index artifacts");
        assert!(!indexed.has_result);
        assert_eq!(indexed.event_count, 0);
    }

    #[test]
    fn sqlite_index_open_supports_bare_filename_path() {
        let _lock = CWD_LOCK.lock().expect("lock cwd test");
        let original_cwd = std::env::current_dir().expect("read current cwd");
        let root = unique_tmp_dir("clawcrate_audit_sqlite_bare_filename");
        std::env::set_current_dir(&root).expect("switch cwd to test dir");

        let open_result = SqliteAuditIndex::open(PathBuf::from("audit-index.sqlite3"));
        std::env::set_current_dir(&original_cwd).expect("restore cwd after test");

        let index = open_result.expect("open sqlite index with bare filename path");
        assert_eq!(index.db_path(), Path::new("audit-index.sqlite3"));
        assert!(root.join("audit-index.sqlite3").exists());
    }

    #[test]
    fn sqlite_indexer_handles_large_plan_and_ndjson_artifacts() {
        let root = unique_tmp_dir("clawcrate_audit_sqlite_large_artifacts");
        let writer = ArtifactWriter::new(&root, "exec-large").expect("create writer");
        let mut plan = test_plan();
        plan.id = "exec-large".to_string();
        plan.command = (0..8_000).map(|index| format!("arg-{index}")).collect();
        writer.write_plan(&plan).expect("write large plan");

        for index in 0..1_500 {
            writer
                .append_audit_event(&AuditEvent {
                    timestamp: Utc::now(),
                    event: AuditEventKind::ProcessStarted {
                        pid: 10_000 + index,
                        command: vec!["echo".to_string(), format!("event-{index}")],
                    },
                })
                .expect("append large audit event set");
        }

        let db_path = root.join("audit-index-large.sqlite3");
        let mut index = SqliteAuditIndex::open(&db_path).expect("open sqlite index");
        let indexed = index
            .index_artifacts_dir(writer.artifacts_dir())
            .expect("index large artifacts");

        assert_eq!(indexed.execution_id, "exec-large");
        assert_eq!(indexed.event_count, 1_500);
    }
}
