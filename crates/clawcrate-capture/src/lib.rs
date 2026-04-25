#![forbid(unsafe_code)]

use std::collections::BTreeMap;
use std::fs::{self, File};
use std::io::{self, BufWriter, Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStderr, ChildStdout, ExitStatus};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::UNIX_EPOCH;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use walkdir::WalkDir;

pub const CRATE_NAME: &str = "clawcrate-capture";

const STDOUT_LOG: &str = "stdout.log";
const STDERR_LOG: &str = "stderr.log";
const READ_CHUNK_SIZE: usize = 8192;

#[derive(Debug, Clone)]
pub struct CaptureConfig {
    pub artifacts_dir: PathBuf,
    pub max_output_bytes: u64,
}

impl CaptureConfig {
    pub fn stdout_log_path(&self) -> PathBuf {
        self.artifacts_dir.join(STDOUT_LOG)
    }

    pub fn stderr_log_path(&self) -> PathBuf {
        self.artifacts_dir.join(STDERR_LOG)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StreamKind {
    Stdout,
    Stderr,
}

impl StreamKind {
    fn label(self) -> &'static str {
        match self {
            StreamKind::Stdout => "stdout",
            StreamKind::Stderr => "stderr",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StreamCaptureStats {
    pub written_bytes: u64,
    pub dropped_bytes: u64,
}

impl StreamCaptureStats {
    fn truncated(self) -> bool {
        self.dropped_bytes > 0
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CaptureSummary {
    pub stdout: StreamCaptureStats,
    pub stderr: StreamCaptureStats,
    pub total_written_bytes: u64,
    pub total_dropped_bytes: u64,
    pub truncated: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CapturedChildOutput {
    pub status: ExitStatus,
    pub summary: CaptureSummary,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct FileFingerprint {
    pub size_bytes: u64,
    pub modified_unix_nanos: u128,
    pub sha256: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct FileSnapshot {
    pub entries: BTreeMap<PathBuf, FileFingerprint>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum FsChangeKind {
    Created,
    Modified,
    Deleted,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct FsChange {
    pub path: PathBuf,
    pub kind: FsChangeKind,
    pub size_bytes: Option<u64>,
}

#[derive(Debug, thiserror::Error)]
pub enum CaptureError {
    #[error("failed to create artifacts directory: {0}")]
    CreateArtifactsDir(#[source] io::Error),
    #[error("failed to create {stream} log file at {path}: {source}")]
    CreateLogFile {
        stream: &'static str,
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error("child stdout pipe was not available for capture")]
    MissingStdoutPipe,
    #[error("child stderr pipe was not available for capture")]
    MissingStderrPipe,
    #[error("failed while reading/writing {stream} stream: {source}")]
    StreamIo {
        stream: &'static str,
        #[source]
        source: io::Error,
    },
    #[error("stream capture thread panicked")]
    ThreadPanic,
    #[error("failed to wait for child process: {0}")]
    WaitChild(#[source] io::Error),
    #[error("failed to walk snapshot root {root}: {source}")]
    SnapshotWalk {
        root: PathBuf,
        #[source]
        source: walkdir::Error,
    },
    #[error("filesystem snapshot IO failed for {path}: {source}")]
    SnapshotIo {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
}

#[derive(Debug)]
struct SharedBudget {
    remaining: u64,
}

pub fn capture_streams<R1, R2>(
    stdout_reader: R1,
    stderr_reader: R2,
    config: &CaptureConfig,
) -> Result<CaptureSummary, CaptureError>
where
    R1: Read + Send + 'static,
    R2: Read + Send + 'static,
{
    fs::create_dir_all(&config.artifacts_dir).map_err(CaptureError::CreateArtifactsDir)?;

    let stdout_log_path = config.stdout_log_path();
    let stdout_log =
        File::create(&stdout_log_path).map_err(|source| CaptureError::CreateLogFile {
            stream: StreamKind::Stdout.label(),
            path: stdout_log_path,
            source,
        })?;

    let stderr_log_path = config.stderr_log_path();
    let stderr_log =
        File::create(&stderr_log_path).map_err(|source| CaptureError::CreateLogFile {
            stream: StreamKind::Stderr.label(),
            path: stderr_log_path,
            source,
        })?;

    let budget = Arc::new(Mutex::new(SharedBudget {
        remaining: config.max_output_bytes,
    }));

    let stdout_handle = spawn_capture_thread(
        stdout_reader,
        BufWriter::new(stdout_log),
        StreamKind::Stdout,
        Arc::clone(&budget),
    );
    let stderr_handle = spawn_capture_thread(
        stderr_reader,
        BufWriter::new(stderr_log),
        StreamKind::Stderr,
        Arc::clone(&budget),
    );

    let stdout_result = join_capture_thread(stdout_handle);
    let stderr_result = join_capture_thread(stderr_handle);

    let (stdout_stats, stderr_stats) = match (stdout_result, stderr_result) {
        (Ok(stdout_stats), Ok(stderr_stats)) => (stdout_stats, stderr_stats),
        (Err(capture_error), Ok(_)) => return Err(capture_error),
        (Ok(_), Err(capture_error)) => return Err(capture_error),
        (Err(capture_error), Err(_)) => return Err(capture_error),
    };

    let total_written_bytes = stdout_stats.written_bytes + stderr_stats.written_bytes;
    let total_dropped_bytes = stdout_stats.dropped_bytes + stderr_stats.dropped_bytes;

    Ok(CaptureSummary {
        stdout: stdout_stats,
        stderr: stderr_stats,
        total_written_bytes,
        total_dropped_bytes,
        truncated: stdout_stats.truncated() || stderr_stats.truncated(),
    })
}

pub fn capture_child_output(
    mut child: Child,
    config: &CaptureConfig,
) -> Result<CapturedChildOutput, CaptureError> {
    let stdout = child.stdout.take().ok_or(CaptureError::MissingStdoutPipe)?;
    let stderr = child.stderr.take().ok_or(CaptureError::MissingStderrPipe)?;

    capture_child_pipes(child, stdout, stderr, config)
}

fn capture_child_pipes(
    mut child: Child,
    stdout: ChildStdout,
    stderr: ChildStderr,
    config: &CaptureConfig,
) -> Result<CapturedChildOutput, CaptureError> {
    let summary = capture_streams(stdout, stderr, config);
    let status = child.wait().map_err(CaptureError::WaitChild);

    match (summary, status) {
        (Ok(summary), Ok(status)) => Ok(CapturedChildOutput { status, summary }),
        (Err(capture_error), Ok(_)) => Err(capture_error),
        (Ok(_), Err(wait_error)) => Err(wait_error),
        (Err(capture_error), Err(_wait_error)) => Err(capture_error),
    }
}

fn spawn_capture_thread<R, W>(
    mut reader: R,
    mut writer: W,
    stream: StreamKind,
    budget: Arc<Mutex<SharedBudget>>,
) -> thread::JoinHandle<Result<StreamCaptureStats, CaptureError>>
where
    R: Read + Send + 'static,
    W: Write + Send + 'static,
{
    thread::spawn(move || {
        let mut stats = StreamCaptureStats {
            written_bytes: 0,
            dropped_bytes: 0,
        };
        let mut buffer = [0u8; READ_CHUNK_SIZE];

        loop {
            let read = reader
                .read(&mut buffer)
                .map_err(|source| CaptureError::StreamIo {
                    stream: stream.label(),
                    source,
                })?;
            if read == 0 {
                break;
            }

            let write_len = {
                let mut budget = budget.lock().map_err(|_| CaptureError::ThreadPanic)?;
                let allowed = read.min(budget.remaining as usize);
                budget.remaining = budget.remaining.saturating_sub(allowed as u64);
                allowed
            };

            if write_len > 0 {
                writer.write_all(&buffer[..write_len]).map_err(|source| {
                    CaptureError::StreamIo {
                        stream: stream.label(),
                        source,
                    }
                })?;
                stats.written_bytes += write_len as u64;
            }

            if write_len < read {
                stats.dropped_bytes += (read - write_len) as u64;
            }
        }

        writer.flush().map_err(|source| CaptureError::StreamIo {
            stream: stream.label(),
            source,
        })?;
        Ok(stats)
    })
}

fn join_capture_thread(
    handle: thread::JoinHandle<Result<StreamCaptureStats, CaptureError>>,
) -> Result<StreamCaptureStats, CaptureError> {
    match handle.join() {
        Ok(result) => result,
        Err(_) => Err(CaptureError::ThreadPanic),
    }
}

pub fn snapshot_paths(paths: &[PathBuf]) -> Result<FileSnapshot, CaptureError> {
    let mut entries = BTreeMap::new();

    for root in paths {
        if !root.exists() {
            continue;
        }

        if root.is_file() {
            let fingerprint = fingerprint_path(root)?;
            entries.insert(root.clone(), fingerprint);
            continue;
        }

        for walk_entry in WalkDir::new(root).follow_links(false) {
            let walk_entry = walk_entry.map_err(|source| CaptureError::SnapshotWalk {
                root: root.clone(),
                source,
            })?;

            if !walk_entry.file_type().is_file() {
                continue;
            }

            let path = walk_entry.path().to_path_buf();
            let fingerprint = fingerprint_path(&path)?;
            entries.insert(path, fingerprint);
        }
    }

    Ok(FileSnapshot { entries })
}

pub fn diff_snapshots(before: &FileSnapshot, after: &FileSnapshot) -> Vec<FsChange> {
    let mut changes = Vec::new();

    for (path, before_fingerprint) in &before.entries {
        match after.entries.get(path) {
            None => changes.push(FsChange {
                path: path.clone(),
                kind: FsChangeKind::Deleted,
                size_bytes: Some(before_fingerprint.size_bytes),
            }),
            Some(after_fingerprint) if after_fingerprint != before_fingerprint => {
                changes.push(FsChange {
                    path: path.clone(),
                    kind: FsChangeKind::Modified,
                    size_bytes: Some(after_fingerprint.size_bytes),
                });
            }
            Some(_) => {}
        }
    }

    for (path, after_fingerprint) in &after.entries {
        if !before.entries.contains_key(path) {
            changes.push(FsChange {
                path: path.clone(),
                kind: FsChangeKind::Created,
                size_bytes: Some(after_fingerprint.size_bytes),
            });
        }
    }

    changes.sort_by(|left, right| left.path.cmp(&right.path));
    changes
}

fn fingerprint_path(path: &Path) -> Result<FileFingerprint, CaptureError> {
    let metadata = fs::metadata(path).map_err(|source| CaptureError::SnapshotIo {
        path: path.to_path_buf(),
        source,
    })?;
    let modified_unix_nanos = metadata
        .modified()
        .ok()
        .and_then(|modified| modified.duration_since(UNIX_EPOCH).ok())
        .map(|duration| duration.as_nanos())
        .unwrap_or(0);
    let sha256 = hash_sha256(path)?;

    Ok(FileFingerprint {
        size_bytes: metadata.len(),
        modified_unix_nanos,
        sha256,
    })
}

fn hash_sha256(path: &Path) -> Result<String, CaptureError> {
    let mut file = File::open(path).map_err(|source| CaptureError::SnapshotIo {
        path: path.to_path_buf(),
        source,
    })?;
    let mut hasher = Sha256::new();
    let mut buffer = [0u8; READ_CHUNK_SIZE];

    loop {
        let read = file
            .read(&mut buffer)
            .map_err(|source| CaptureError::SnapshotIo {
                path: path.to_path_buf(),
                source,
            })?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }

    let digest = hasher.finalize();
    Ok(digest.iter().map(|byte| format!("{byte:02x}")).collect())
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::io::{self, Cursor, Read};
    use std::path::PathBuf;
    use std::process::{Command, Stdio};
    use std::time::Duration;
    use std::time::{SystemTime, UNIX_EPOCH};

    use super::{
        capture_child_output, capture_streams, diff_snapshots, snapshot_paths, CaptureConfig,
        FsChangeKind,
    };

    fn unique_tmp_dir(prefix: &str) -> PathBuf {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system time after unix epoch")
            .as_nanos();
        let dir = std::env::temp_dir().join(format!("{prefix}_{nanos}_{}", std::process::id()));
        fs::create_dir_all(&dir).expect("create temp test directory");
        dir
    }

    #[test]
    fn capture_streams_writes_stdout_and_stderr_logs() {
        let tmp = unique_tmp_dir("clawcrate_capture_streams");
        let config = CaptureConfig {
            artifacts_dir: tmp.clone(),
            max_output_bytes: 1024,
        };

        let summary = capture_streams(
            Cursor::new(b"hello stdout\n".to_vec()),
            Cursor::new(b"hello stderr\n".to_vec()),
            &config,
        )
        .expect("capture streams");

        assert_eq!(summary.total_written_bytes, 26);
        assert!(!summary.truncated);
        assert_eq!(
            fs::read_to_string(config.stdout_log_path()).expect("read stdout log"),
            "hello stdout\n"
        );
        assert_eq!(
            fs::read_to_string(config.stderr_log_path()).expect("read stderr log"),
            "hello stderr\n"
        );
    }

    #[test]
    fn capture_streams_truncates_using_shared_total_budget() {
        let tmp = unique_tmp_dir("clawcrate_capture_truncate");
        let config = CaptureConfig {
            artifacts_dir: tmp.clone(),
            max_output_bytes: 6,
        };

        let summary = capture_streams(
            Cursor::new(b"AAAA".to_vec()),
            Cursor::new(b"BBBB".to_vec()),
            &config,
        )
        .expect("capture streams");

        let stdout_len = fs::read(config.stdout_log_path())
            .expect("read stdout log")
            .len() as u64;
        let stderr_len = fs::read(config.stderr_log_path())
            .expect("read stderr log")
            .len() as u64;

        assert_eq!(summary.total_written_bytes, 6);
        assert_eq!(summary.total_dropped_bytes, 2);
        assert!(summary.truncated);
        assert_eq!(stdout_len + stderr_len, 6);
    }

    #[test]
    fn capture_child_output_reads_pipes_and_returns_exit_status() {
        let tmp = unique_tmp_dir("clawcrate_capture_child");
        let config = CaptureConfig {
            artifacts_dir: tmp.clone(),
            max_output_bytes: 1024,
        };

        let mut command = Command::new("/bin/sh");
        command
            .arg("-c")
            .arg("printf 'hello-out'; printf 'hello-err' >&2");
        command.stdout(Stdio::piped());
        command.stderr(Stdio::piped());
        let child = command.spawn().expect("spawn shell");

        let captured = capture_child_output(child, &config).expect("capture child output");

        assert!(captured.status.success());
        assert!(!captured.summary.truncated);
        assert_eq!(
            fs::read_to_string(config.stdout_log_path()).expect("read stdout log"),
            "hello-out"
        );
        assert_eq!(
            fs::read_to_string(config.stderr_log_path()).expect("read stderr log"),
            "hello-err"
        );
    }

    #[test]
    fn capture_streams_joins_remaining_thread_when_other_stream_fails() {
        let tmp = unique_tmp_dir("clawcrate_capture_join_failure_path");
        let config = CaptureConfig {
            artifacts_dir: tmp.clone(),
            max_output_bytes: 1024,
        };

        let started_at = SystemTime::now();
        let result = capture_streams(
            FailingReader::new(io::ErrorKind::Other, "synthetic stdout failure"),
            DelayedEofReader::new(b"stderr-data".to_vec(), Duration::from_millis(200)),
            &config,
        );
        let elapsed = started_at.elapsed().expect("elapsed wall-clock time");

        assert!(
            matches!(
                result,
                Err(super::CaptureError::StreamIo {
                    stream: "stdout",
                    ..
                })
            ),
            "expected stdout stream IO failure, got: {result:?}"
        );
        assert!(
            elapsed >= Duration::from_millis(150),
            "capture_streams returned before joining delayed sibling stream thread: {elapsed:?}"
        );
        assert_eq!(
            fs::read_to_string(config.stderr_log_path()).expect("read stderr log"),
            "stderr-data"
        );
    }

    #[test]
    fn capture_child_output_waits_and_reaps_even_when_capture_setup_fails() {
        let tmp = unique_tmp_dir("clawcrate_capture_child_reap_failure_path");
        let occupied_path = tmp.join("occupied-file");
        fs::write(&occupied_path, "occupied").expect("write occupied path");
        let config = CaptureConfig {
            artifacts_dir: occupied_path,
            max_output_bytes: 1024,
        };

        let mut command = Command::new("/bin/sh");
        command.arg("-c").arg("sleep 0.2");
        command.stdout(Stdio::piped());
        command.stderr(Stdio::piped());
        let child = command.spawn().expect("spawn shell");

        let started_at = SystemTime::now();
        let result = capture_child_output(child, &config);
        let elapsed = started_at.elapsed().expect("elapsed wall-clock time");

        assert!(
            matches!(result, Err(super::CaptureError::CreateArtifactsDir(_))),
            "expected artifacts-dir creation error, got: {result:?}"
        );
        assert!(
            elapsed >= Duration::from_millis(150),
            "capture_child_output returned before child wait/reap on failure path: {elapsed:?}"
        );
    }

    #[test]
    fn snapshot_paths_captures_nested_files_with_hashes() {
        let tmp = unique_tmp_dir("clawcrate_snapshot_nested");
        let nested = tmp.join("workspace").join("src");
        fs::create_dir_all(&nested).expect("create nested directory");
        fs::write(tmp.join("workspace").join("root.txt"), "root").expect("write root file");
        fs::write(nested.join("lib.rs"), "fn main() {}").expect("write nested file");

        let snapshot = snapshot_paths(&[tmp.join("workspace")]).expect("snapshot paths");
        assert_eq!(snapshot.entries.len(), 2);
        for fingerprint in snapshot.entries.values() {
            assert_eq!(fingerprint.sha256.len(), 64);
            assert!(fingerprint.size_bytes > 0);
        }
    }

    #[test]
    fn diff_snapshots_detects_created_modified_and_deleted() {
        let tmp = unique_tmp_dir("clawcrate_snapshot_diff");
        let root = tmp.join("workspace");
        fs::create_dir_all(&root).expect("create workspace");

        let stable = root.join("stable.txt");
        let modified = root.join("modified.txt");
        let deleted = root.join("deleted.txt");
        let created = root.join("created.txt");

        fs::write(&stable, "same").expect("write stable");
        fs::write(&modified, "before").expect("write modified before");
        fs::write(&deleted, "remove me").expect("write deleted");

        let before = snapshot_paths(std::slice::from_ref(&root)).expect("snapshot before");

        fs::write(&modified, "after").expect("write modified after");
        fs::remove_file(&deleted).expect("delete file");
        fs::write(&created, "new").expect("write created");

        let after = snapshot_paths(&[root]).expect("snapshot after");
        let diff = diff_snapshots(&before, &after);

        assert!(diff
            .iter()
            .any(|change| change.path == modified && change.kind == FsChangeKind::Modified));
        assert!(diff
            .iter()
            .any(|change| change.path == deleted && change.kind == FsChangeKind::Deleted));
        assert!(diff
            .iter()
            .any(|change| change.path == created && change.kind == FsChangeKind::Created));
        assert!(!diff
            .iter()
            .any(|change| change.path == stable && change.kind != FsChangeKind::Modified));
    }

    #[test]
    fn snapshot_paths_ignores_missing_roots_and_preserves_existing_ones() {
        let tmp = unique_tmp_dir("clawcrate_snapshot_missing");
        let existing = tmp.join("existing");
        let missing = tmp.join("missing");
        fs::create_dir_all(&existing).expect("create existing directory");
        fs::write(existing.join("a.txt"), "a").expect("write existing file");

        let snapshot = snapshot_paths(&[missing, existing]).expect("snapshot with missing root");
        assert_eq!(snapshot.entries.len(), 1);
    }

    struct FailingReader {
        kind: io::ErrorKind,
        message: &'static str,
    }

    impl FailingReader {
        fn new(kind: io::ErrorKind, message: &'static str) -> Self {
            Self { kind, message }
        }
    }

    impl Read for FailingReader {
        fn read(&mut self, _buf: &mut [u8]) -> io::Result<usize> {
            Err(io::Error::new(self.kind, self.message))
        }
    }

    struct DelayedEofReader {
        chunk: Vec<u8>,
        delay: Duration,
        stage: u8,
    }

    impl DelayedEofReader {
        fn new(chunk: Vec<u8>, delay: Duration) -> Self {
            Self {
                chunk,
                delay,
                stage: 0,
            }
        }
    }

    impl Read for DelayedEofReader {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            match self.stage {
                0 => {
                    let len = self.chunk.len().min(buf.len());
                    buf[..len].copy_from_slice(&self.chunk[..len]);
                    self.stage = 1;
                    Ok(len)
                }
                1 => {
                    std::thread::sleep(self.delay);
                    self.stage = 2;
                    Ok(0)
                }
                _ => Ok(0),
            }
        }
    }
}
