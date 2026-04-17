#![forbid(unsafe_code)]

use std::path::{Path, PathBuf};
use std::process::{Child, ChildStderr, ChildStdout, ExitStatus};
use std::thread;
use std::time::{Duration, Instant};

use anyhow::{anyhow, Result};
use chrono::Utc;
use clap::{ArgAction, Args, Parser, Subcommand};
use clawcrate_audit::ArtifactWriter;
use clawcrate_capture::{
    capture_streams, diff_snapshots, snapshot_paths, CaptureConfig, CaptureError, CaptureSummary,
    FsChange,
};
use clawcrate_profiles::ProfileResolver;
#[cfg(target_os = "macos")]
use clawcrate_sandbox::darwin::DarwinSandbox;
#[cfg(target_os = "linux")]
use clawcrate_sandbox::linux::LinuxSandbox;
#[cfg(target_os = "linux")]
use clawcrate_sandbox::linux_probe::probe_linux_capabilities;
#[cfg(target_os = "macos")]
use clawcrate_sandbox::macos_probe::probe_macos_capabilities;
use clawcrate_types::{
    Actor, AuditEvent, AuditEventKind, DefaultMode, ExecutionPlan, ExecutionResult, Platform,
    Status, SystemCapabilities, WorkspaceMode,
};
use comfy_table::{Cell, Table};
#[cfg(unix)]
use nix::errno::Errno;
#[cfg(unix)]
use nix::sys::signal::{kill, Signal};
#[cfg(unix)]
use nix::unistd::Pid;
use serde::Serialize;
#[cfg(unix)]
use signal_hook::consts::signal::{SIGINT, SIGTERM};
#[cfg(unix)]
use signal_hook::iterator::Signals;
#[cfg(unix)]
use std::os::unix::process::ExitStatusExt;
use uuid::Uuid;

#[derive(Debug, Parser)]
#[command(
    name = "clawcrate",
    version,
    about = "Secure execution runtime for AI shell commands"
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Debug, Subcommand)]
enum Commands {
    /// Execute a command inside a sandbox
    Run(CommandArgs),
    /// Show execution plan without executing (dry-run)
    Plan(CommandArgs),
    /// Check system sandboxing capabilities
    Doctor(DoctorArgs),
}

#[derive(Debug, Args)]
struct CommandArgs {
    /// Built-in profile name (safe/build/install/open) or YAML file path
    #[arg(long)]
    profile: Option<String>,

    /// Force replica mode
    #[arg(long, action = ArgAction::SetTrue, conflicts_with = "direct")]
    replica: bool,

    /// Force direct mode
    #[arg(long, action = ArgAction::SetTrue, conflicts_with = "replica")]
    direct: bool,

    /// Machine-readable JSON output
    #[arg(long, action = ArgAction::SetTrue)]
    json: bool,

    /// Command to plan/execute (pass after --)
    #[arg(trailing_var_arg = true, num_args = 1.., required = true)]
    command: Vec<String>,
}

#[derive(Debug, Args)]
struct DoctorArgs {
    /// Machine-readable JSON output
    #[arg(long, action = ArgAction::SetTrue)]
    json: bool,
}

fn main() {
    if let Err(error) = run() {
        eprintln!("error: {error}");
        std::process::exit(1);
    }
}

fn run() -> Result<()> {
    let cli = Cli::parse();
    let resolver = ProfileResolver::default();

    match cli.command {
        Commands::Plan(args) => handle_plan(&resolver, args),
        Commands::Run(args) => handle_run(&resolver, args),
        Commands::Doctor(args) => handle_doctor(args),
    }
}

fn handle_plan(resolver: &ProfileResolver, args: CommandArgs) -> Result<()> {
    let cwd =
        std::env::current_dir().map_err(|source| anyhow!("failed to get current dir: {source}"))?;
    let plan = build_execution_plan(resolver, &cwd, &args)?;

    if args.json {
        println!("{}", serde_json::to_string_pretty(&plan)?);
    } else {
        print_human_plan(&plan);
    }

    Ok(())
}

#[derive(Debug)]
struct RunExecutionOutcome {
    backend: String,
    scrubbed_keys: Vec<String>,
    exit_status: ExitStatus,
    capture_summary: CaptureSummary,
    termination: RunTermination,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RunTermination {
    Exited,
    Interrupted,
    Timeout,
}

#[derive(Debug)]
struct RunPipelineResult {
    execution: RunExecutionOutcome,
    fs_diff: Vec<FsChange>,
}

#[derive(Debug, Serialize)]
struct RunSummary {
    result: ExecutionResult,
    backend: String,
    scrubbed_env_vars: usize,
    fs_changes: usize,
    output_truncated: bool,
    dropped_output_bytes: u64,
    stdout_log: PathBuf,
    stderr_log: PathBuf,
}

fn handle_run(resolver: &ProfileResolver, args: CommandArgs) -> Result<()> {
    let cwd =
        std::env::current_dir().map_err(|source| anyhow!("failed to get current dir: {source}"))?;
    let plan = build_execution_plan(resolver, &cwd, &args)?;
    let writer = ArtifactWriter::new(&runs_root()?, &plan.id)
        .map_err(|source| anyhow!("failed to initialize artifact writer: {source}"))?;

    writer
        .write_plan(&plan)
        .map_err(|source| anyhow!("failed to write plan artifact: {source}"))?;

    let started_at = Instant::now();
    let pipeline = match execute_run_pipeline(&plan, &writer) {
        Ok(pipeline) => pipeline,
        Err(error) => {
            persist_sandbox_error_result(
                &writer,
                &plan.id,
                started_at.elapsed().as_millis() as u64,
                &error,
            )?;
            return Err(error);
        }
    };

    writer
        .write_fs_diff(&pipeline.fs_diff)
        .map_err(|source| anyhow!("failed to write fs-diff artifact: {source}"))?;

    let duration_ms = started_at.elapsed().as_millis() as u64;
    append_audit_event(
        &writer,
        AuditEventKind::ProcessExited {
            exit_code: pipeline.execution.exit_status.code().unwrap_or(-1),
            duration_ms,
        },
    )?;

    let result = ExecutionResult {
        id: plan.id.clone(),
        exit_code: pipeline.execution.exit_status.code(),
        status: execution_status(
            &pipeline.execution.exit_status,
            pipeline.execution.termination,
        ),
        duration_ms,
        artifacts_dir: writer.artifacts_dir().to_path_buf(),
    };
    writer
        .write_result(&result)
        .map_err(|source| anyhow!("failed to write result artifact: {source}"))?;

    let summary = RunSummary {
        result,
        backend: pipeline.execution.backend,
        scrubbed_env_vars: pipeline.execution.scrubbed_keys.len(),
        fs_changes: pipeline.fs_diff.len(),
        output_truncated: pipeline.execution.capture_summary.truncated,
        dropped_output_bytes: pipeline.execution.capture_summary.total_dropped_bytes,
        stdout_log: writer.artifacts_dir().join("stdout.log"),
        stderr_log: writer.artifacts_dir().join("stderr.log"),
    };

    if args.json {
        println!("{}", serde_json::to_string_pretty(&summary)?);
    } else {
        print_human_run_summary(&summary);
    }

    Ok(())
}

fn execute_run_pipeline(
    plan: &ExecutionPlan,
    writer: &ArtifactWriter,
) -> Result<RunPipelineResult> {
    materialize_workspace_for_execution(plan, writer)?;
    let fs_diff_roots = resolve_fs_diff_roots(plan);
    let snapshot_before = snapshot_paths(&fs_diff_roots).map_err(|source| {
        anyhow!("failed to snapshot writable paths before execution: {source}")
    })?;

    let capture_config = CaptureConfig {
        artifacts_dir: writer.artifacts_dir().to_path_buf(),
        max_output_bytes: plan.profile.resources.max_output_bytes,
    };
    let execution = launch_and_capture(plan, writer, &capture_config)?;

    let snapshot_after = snapshot_paths(&fs_diff_roots)
        .map_err(|source| anyhow!("failed to snapshot writable paths after execution: {source}"))?;
    let fs_diff = diff_snapshots(&snapshot_before, &snapshot_after);

    Ok(RunPipelineResult { execution, fs_diff })
}

const REPLICA_DEFAULT_EXCLUSIONS: [&str; 3] = [".env", ".env.*", ".git/config"];

fn materialize_workspace_for_execution(
    plan: &ExecutionPlan,
    writer: &ArtifactWriter,
) -> Result<()> {
    let WorkspaceMode::Replica { source, copy } = &plan.mode else {
        return Ok(());
    };

    copy_workspace_with_default_exclusions(source, copy)?;
    append_audit_event(
        writer,
        AuditEventKind::ReplicaCreated {
            source: source.clone(),
            copy: copy.clone(),
            excluded: REPLICA_DEFAULT_EXCLUSIONS
                .iter()
                .map(|value| value.to_string())
                .collect(),
        },
    )?;
    Ok(())
}

fn copy_workspace_with_default_exclusions(source: &Path, copy: &Path) -> Result<()> {
    if !source.is_dir() {
        return Err(anyhow!(
            "replica source workspace does not exist or is not a directory: {}",
            source.display()
        ));
    }

    if copy.exists() {
        std::fs::remove_dir_all(copy).map_err(|source_error| {
            anyhow!(
                "failed to clean existing replica workspace at {}: {source_error}",
                copy.display()
            )
        })?;
    }
    std::fs::create_dir_all(copy).map_err(|source_error| {
        anyhow!(
            "failed to create replica workspace at {}: {source_error}",
            copy.display()
        )
    })?;

    copy_directory_recursive(source, copy, source)?;
    Ok(())
}

fn copy_directory_recursive(
    source_dir: &Path,
    target_dir: &Path,
    source_root: &Path,
) -> Result<()> {
    for entry in std::fs::read_dir(source_dir).map_err(|source_error| {
        anyhow!(
            "failed to read source workspace directory {}: {source_error}",
            source_dir.display()
        )
    })? {
        let entry = entry.map_err(|source_error| {
            anyhow!(
                "failed to read source workspace entry in {}: {source_error}",
                source_dir.display()
            )
        })?;
        let source_path = entry.path();
        let relative_path = source_path
            .strip_prefix(source_root)
            .map_err(|source_error| {
                anyhow!("failed to compute relative source path: {source_error}")
            })?;

        if should_exclude_replica_path(relative_path) {
            continue;
        }

        let target_path = target_dir.join(entry.file_name());
        let file_type = entry.file_type().map_err(|source_error| {
            anyhow!(
                "failed to inspect source entry type {}: {source_error}",
                source_path.display()
            )
        })?;

        if file_type.is_dir() {
            std::fs::create_dir_all(&target_path).map_err(|source_error| {
                anyhow!(
                    "failed to create replica directory {}: {source_error}",
                    target_path.display()
                )
            })?;
            copy_directory_recursive(&source_path, &target_path, source_root)?;
            continue;
        }

        if file_type.is_file() {
            std::fs::copy(&source_path, &target_path).map_err(|source_error| {
                anyhow!(
                    "failed to copy source file {} to {}: {source_error}",
                    source_path.display(),
                    target_path.display()
                )
            })?;
            continue;
        }

        if file_type.is_symlink() {
            copy_symlink(&source_path, &target_path)?;
        }
    }

    Ok(())
}

#[cfg(unix)]
fn copy_symlink(source_path: &Path, target_path: &Path) -> Result<()> {
    use std::os::unix::fs::symlink;

    let link_target = std::fs::read_link(source_path).map_err(|source_error| {
        anyhow!(
            "failed to read symlink target for {}: {source_error}",
            source_path.display()
        )
    })?;
    symlink(&link_target, target_path).map_err(|source_error| {
        anyhow!(
            "failed to recreate symlink {} -> {}: {source_error}",
            target_path.display(),
            link_target.display()
        )
    })?;
    Ok(())
}

#[cfg(not(unix))]
fn copy_symlink(source_path: &Path, target_path: &Path) -> Result<()> {
    std::fs::copy(source_path, target_path).map_err(|source_error| {
        anyhow!(
            "failed to copy symlink-like path {} to {}: {source_error}",
            source_path.display(),
            target_path.display()
        )
    })?;
    Ok(())
}

fn should_exclude_replica_path(relative_path: &Path) -> bool {
    if relative_path == Path::new(".git/config") {
        return true;
    }

    relative_path
        .file_name()
        .and_then(|name| name.to_str())
        .map(is_secret_env_filename)
        .unwrap_or(false)
}

fn is_secret_env_filename(file_name: &str) -> bool {
    file_name == ".env" || file_name.starts_with(".env.")
}

fn runs_root() -> Result<PathBuf> {
    if let Some(home) = std::env::var_os("HOME") {
        return Ok(PathBuf::from(home).join(".clawcrate").join("runs"));
    }
    let cwd = std::env::current_dir()
        .map_err(|source| anyhow!("failed to resolve current dir: {source}"))?;
    Ok(cwd.join(".clawcrate").join("runs"))
}

fn resolve_fs_diff_roots(plan: &ExecutionPlan) -> Vec<PathBuf> {
    plan.profile
        .fs_write
        .iter()
        .map(|path| resolve_execution_path(&plan.cwd, path))
        .collect()
}

fn resolve_execution_path(cwd: &Path, path: &Path) -> PathBuf {
    let expanded = expand_home(path);
    if expanded.is_absolute() {
        expanded
    } else {
        cwd.join(expanded)
    }
}

fn expand_home(path: &Path) -> PathBuf {
    let path_str = path.to_string_lossy();
    if path_str == "~" {
        if let Some(home) = std::env::var_os("HOME") {
            return PathBuf::from(home);
        }
    }
    if let Some(rest) = path_str.strip_prefix("~/") {
        if let Some(home) = std::env::var_os("HOME") {
            return PathBuf::from(home).join(rest);
        }
    }
    path.to_path_buf()
}

fn append_audit_event(writer: &ArtifactWriter, event: AuditEventKind) -> Result<()> {
    writer
        .append_audit_event(&AuditEvent {
            timestamp: Utc::now(),
            event,
        })
        .map_err(|source| anyhow!("failed to append audit event: {source}"))
}

fn persist_sandbox_error_result(
    writer: &ArtifactWriter,
    execution_id: &str,
    duration_ms: u64,
    error: &anyhow::Error,
) -> Result<()> {
    writer
        .write_fs_diff(&Vec::<FsChange>::new())
        .map_err(|source| anyhow!("failed to write empty fs-diff artifact: {source}"))?;

    let result = ExecutionResult {
        id: execution_id.to_string(),
        exit_code: None,
        status: Status::SandboxError(error.to_string()),
        duration_ms,
        artifacts_dir: writer.artifacts_dir().to_path_buf(),
    };
    writer
        .write_result(&result)
        .map_err(|source| anyhow!("failed to write sandbox error result: {source}"))?;
    Ok(())
}

#[cfg(target_os = "linux")]
fn launch_and_capture(
    plan: &ExecutionPlan,
    writer: &ArtifactWriter,
    capture_config: &CaptureConfig,
) -> Result<RunExecutionOutcome> {
    let sandbox = LinuxSandbox::new();
    let prepared = sandbox.prepare(plan);
    let scrubbed_keys = prepared.scrubbed_keys.clone();

    append_audit_event(
        writer,
        AuditEventKind::SandboxApplied {
            backend: "linux".to_string(),
            capabilities: vec![
                "rlimits".to_string(),
                "landlock".to_string(),
                "seccomp".to_string(),
            ],
        },
    )?;
    if !scrubbed_keys.is_empty() {
        append_audit_event(
            writer,
            AuditEventKind::EnvScrubbed {
                removed: scrubbed_keys.clone(),
            },
        )?;
    }

    let mut child = sandbox
        .launch(&prepared)
        .map_err(|source| anyhow!("failed to launch linux sandbox: {source}"))?;
    let pid = child.pid();
    append_audit_event(
        writer,
        AuditEventKind::ProcessStarted {
            pid,
            command: plan.command.clone(),
        },
    )?;

    let stdout = child
        .child_mut()
        .stdout
        .take()
        .ok_or(CaptureError::MissingStdoutPipe)
        .map_err(|source| anyhow!("failed to capture stdout pipe: {source}"))?;
    let stderr = child
        .child_mut()
        .stderr
        .take()
        .ok_or(CaptureError::MissingStderrPipe)
        .map_err(|source| anyhow!("failed to capture stderr pipe: {source}"))?;
    let monitored = run_monitored_child(
        child.child_mut(),
        stdout,
        stderr,
        capture_config,
        plan.profile.resources.max_cpu_seconds,
    )?;

    Ok(RunExecutionOutcome {
        backend: "linux".to_string(),
        scrubbed_keys,
        exit_status: monitored.exit_status,
        capture_summary: monitored.capture_summary,
        termination: monitored.termination,
    })
}

#[cfg(target_os = "macos")]
fn launch_and_capture(
    plan: &ExecutionPlan,
    writer: &ArtifactWriter,
    capture_config: &CaptureConfig,
) -> Result<RunExecutionOutcome> {
    let sandbox = DarwinSandbox::new();
    let prepared = sandbox.prepare(plan);
    let scrubbed_keys = prepared.scrubbed_keys.clone();

    append_audit_event(
        writer,
        AuditEventKind::SandboxApplied {
            backend: "macos-seatbelt".to_string(),
            capabilities: vec!["seatbelt".to_string()],
        },
    )?;
    if !scrubbed_keys.is_empty() {
        append_audit_event(
            writer,
            AuditEventKind::EnvScrubbed {
                removed: scrubbed_keys.clone(),
            },
        )?;
    }

    let mut child = sandbox
        .launch(&prepared)
        .map_err(|source| anyhow!("failed to launch macOS sandbox: {source}"))?;
    let pid = child.pid();
    append_audit_event(
        writer,
        AuditEventKind::ProcessStarted {
            pid,
            command: plan.command.clone(),
        },
    )?;

    let stdout = child
        .child_mut()
        .stdout
        .take()
        .ok_or(CaptureError::MissingStdoutPipe)
        .map_err(|source| anyhow!("failed to capture stdout pipe: {source}"))?;
    let stderr = child
        .child_mut()
        .stderr
        .take()
        .ok_or(CaptureError::MissingStderrPipe)
        .map_err(|source| anyhow!("failed to capture stderr pipe: {source}"))?;
    let monitored = run_monitored_child(
        child.child_mut(),
        stdout,
        stderr,
        capture_config,
        plan.profile.resources.max_cpu_seconds,
    )?;

    Ok(RunExecutionOutcome {
        backend: "macos-seatbelt".to_string(),
        scrubbed_keys,
        exit_status: monitored.exit_status,
        capture_summary: monitored.capture_summary,
        termination: monitored.termination,
    })
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
fn launch_and_capture(
    _plan: &ExecutionPlan,
    _writer: &ArtifactWriter,
    _capture_config: &CaptureConfig,
) -> Result<RunExecutionOutcome> {
    Err(anyhow!("unsupported platform for `run` command"))
}

#[derive(Debug)]
struct MonitoredChildResult {
    exit_status: ExitStatus,
    capture_summary: CaptureSummary,
    termination: RunTermination,
}

fn run_monitored_child(
    child: &mut Child,
    stdout: ChildStdout,
    stderr: ChildStderr,
    capture_config: &CaptureConfig,
    timeout_seconds: u64,
) -> Result<MonitoredChildResult> {
    const POLL_INTERVAL: Duration = Duration::from_millis(25);
    const INTERRUPT_GRACE_PERIOD: Duration = Duration::from_secs(2);

    let capture_config = capture_config.clone();
    let capture_handle = thread::spawn(move || capture_streams(stdout, stderr, &capture_config));

    #[cfg(unix)]
    let mut signals = Signals::new([SIGINT, SIGTERM])
        .map_err(|source| anyhow!("failed to install signal handlers: {source}"))?;

    let started_at = Instant::now();
    let mut interrupted = false;
    let mut timed_out = false;
    let mut interrupt_sent_at: Option<Instant> = None;
    let mut interrupt_forced_kill = false;

    let timeout_limit = (timeout_seconds > 0).then(|| Duration::from_secs(timeout_seconds));
    let exit_status = loop {
        #[cfg(unix)]
        if !interrupted {
            for signal in signals.pending() {
                if signal == SIGINT || signal == SIGTERM {
                    send_termination_signal(child)?;
                    interrupted = true;
                    interrupt_sent_at = Some(Instant::now());
                    break;
                }
            }
        }

        if !timed_out
            && timeout_limit
                .map(|timeout| started_at.elapsed() >= timeout)
                .unwrap_or(false)
        {
            send_kill_signal(child)?;
            timed_out = true;
        }

        if interrupted && !timed_out && !interrupt_forced_kill {
            if let Some(interrupt_at) = interrupt_sent_at {
                if interrupt_at.elapsed() >= INTERRUPT_GRACE_PERIOD {
                    send_kill_signal(child)?;
                    interrupt_forced_kill = true;
                }
            }
        }

        if let Some(status) = child
            .try_wait()
            .map_err(|source| anyhow!("failed while waiting for process exit: {source}"))?
        {
            break status;
        }

        thread::sleep(POLL_INTERVAL);
    };

    let capture_summary = match capture_handle.join() {
        Ok(Ok(summary)) => summary,
        Ok(Err(source)) => return Err(anyhow!("failed to capture process output: {source}")),
        Err(_) => return Err(anyhow!("stream capture thread panicked")),
    };

    let termination = if timed_out {
        RunTermination::Timeout
    } else if interrupted {
        RunTermination::Interrupted
    } else {
        RunTermination::Exited
    };

    Ok(MonitoredChildResult {
        exit_status,
        capture_summary,
        termination,
    })
}

#[cfg(unix)]
fn send_termination_signal(child: &Child) -> Result<()> {
    send_unix_signal(child, Signal::SIGTERM)
}

#[cfg(not(unix))]
fn send_termination_signal(child: &mut Child) -> Result<()> {
    child
        .kill()
        .map_err(|source| anyhow!("failed to terminate child process: {source}"))
}

#[cfg(unix)]
fn send_kill_signal(child: &Child) -> Result<()> {
    send_unix_signal(child, Signal::SIGKILL)
}

#[cfg(not(unix))]
fn send_kill_signal(child: &mut Child) -> Result<()> {
    child
        .kill()
        .map_err(|source| anyhow!("failed to kill child process: {source}"))
}

#[cfg(unix)]
fn send_unix_signal(child: &Child, signal: Signal) -> Result<()> {
    let pid = Pid::from_raw(child.id() as i32);
    match kill(pid, signal) {
        Ok(()) | Err(Errno::ESRCH) => Ok(()),
        Err(source) => Err(anyhow!(
            "failed to send {signal:?} to child {}: {source}",
            child.id()
        )),
    }
}

fn execution_status(status: &ExitStatus, termination: RunTermination) -> Status {
    match termination {
        RunTermination::Timeout => Status::Timeout,
        RunTermination::Interrupted => Status::Killed,
        RunTermination::Exited => execution_status_from_exit_status(status),
    }
}

fn execution_status_from_exit_status(status: &ExitStatus) -> Status {
    if status.success() {
        return Status::Success;
    }
    if terminated_by_signal(status) {
        return Status::Killed;
    }
    Status::Failed
}

#[cfg(unix)]
fn terminated_by_signal(status: &ExitStatus) -> bool {
    status.signal().is_some()
}

#[cfg(not(unix))]
fn terminated_by_signal(_status: &ExitStatus) -> bool {
    false
}

fn build_execution_plan(
    resolver: &ProfileResolver,
    cwd: &Path,
    args: &CommandArgs,
) -> Result<ExecutionPlan> {
    let profile = match args.profile.as_deref() {
        Some(explicit) => resolver.resolve(explicit),
        None => resolver.resolve_auto(cwd),
    }
    .map_err(|source| anyhow!("failed to resolve profile: {source}"))?;

    let effective_default_mode = select_default_mode(profile.default_mode.clone(), args);
    let execution_id = Uuid::now_v7().to_string();
    let mode = materialize_workspace_mode(cwd, effective_default_mode, &execution_id);
    let execution_cwd = match &mode {
        WorkspaceMode::Direct => cwd.to_path_buf(),
        WorkspaceMode::Replica { copy, .. } => copy.clone(),
    };

    Ok(ExecutionPlan {
        id: execution_id,
        command: args.command.clone(),
        cwd: execution_cwd,
        profile,
        mode,
        actor: Actor::Human,
        created_at: Utc::now(),
    })
}

fn select_default_mode(default_mode: DefaultMode, args: &CommandArgs) -> DefaultMode {
    if args.replica {
        DefaultMode::Replica
    } else if args.direct {
        DefaultMode::Direct
    } else {
        default_mode
    }
}

fn materialize_workspace_mode(
    source_cwd: &Path,
    effective_mode: DefaultMode,
    execution_id: &str,
) -> WorkspaceMode {
    match effective_mode {
        DefaultMode::Direct => WorkspaceMode::Direct,
        DefaultMode::Replica => WorkspaceMode::Replica {
            source: source_cwd.to_path_buf(),
            copy: std::env::temp_dir()
                .join("clawcrate")
                .join(format!("exec_{execution_id}"))
                .join("workspace"),
        },
    }
}

fn handle_doctor(args: DoctorArgs) -> Result<()> {
    let capabilities = probe_system_capabilities()?;

    if args.json {
        println!("{}", serde_json::to_string_pretty(&capabilities)?);
    } else {
        print_human_doctor(&capabilities);
    }

    Ok(())
}

#[cfg(target_os = "linux")]
fn probe_system_capabilities() -> Result<SystemCapabilities> {
    Ok(probe_linux_capabilities())
}

#[cfg(target_os = "macos")]
fn probe_system_capabilities() -> Result<SystemCapabilities> {
    Ok(probe_macos_capabilities())
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
fn probe_system_capabilities() -> Result<SystemCapabilities> {
    Err(anyhow!("unsupported platform for `doctor` command"))
}

fn print_human_doctor(capabilities: &SystemCapabilities) {
    let mut table = Table::new();
    table.set_header(vec!["Capability", "Status"]);
    for (name, status) in doctor_rows(capabilities) {
        table.add_row(vec![Cell::new(name), Cell::new(status)]);
    }
    println!("{table}");
}

fn doctor_rows(capabilities: &SystemCapabilities) -> Vec<(String, String)> {
    let kernel_version = capabilities
        .kernel_version
        .clone()
        .unwrap_or_else(|| "unknown".to_string());
    let macos_version = if capabilities.platform == Platform::MacOS {
        capabilities
            .macos_version
            .clone()
            .unwrap_or_else(|| "unknown".to_string())
    } else {
        "n/a".to_string()
    };

    let landlock_status = if capabilities.platform == Platform::Linux {
        capabilities
            .landlock_abi
            .map(|abi| format!("✅ ABI {abi}"))
            .unwrap_or_else(|| "❌ unavailable".to_string())
    } else {
        "n/a".to_string()
    };

    let seccomp_status = if capabilities.platform == Platform::Linux {
        bool_status(capabilities.seccomp_available)
    } else {
        "n/a".to_string()
    };

    let seatbelt_status = if capabilities.platform == Platform::MacOS {
        bool_status(capabilities.seatbelt_available)
    } else {
        "n/a".to_string()
    };

    let user_namespaces_status = if capabilities.platform == Platform::Linux {
        bool_status(capabilities.user_namespaces)
    } else {
        "n/a".to_string()
    };

    vec![
        (
            "Platform".to_string(),
            platform_label(&capabilities.platform),
        ),
        ("Kernel Version".to_string(), kernel_version),
        ("macOS Version".to_string(), macos_version),
        ("Landlock ABI".to_string(), landlock_status),
        ("seccomp".to_string(), seccomp_status),
        ("Seatbelt".to_string(), seatbelt_status),
        ("User Namespaces".to_string(), user_namespaces_status),
    ]
}

fn bool_status(enabled: bool) -> String {
    if enabled {
        "✅ available".to_string()
    } else {
        "❌ unavailable".to_string()
    }
}

fn platform_label(platform: &Platform) -> String {
    match platform {
        Platform::Linux => "Linux".to_string(),
        Platform::MacOS => "macOS".to_string(),
    }
}

fn print_human_run_summary(summary: &RunSummary) {
    let mut table = Table::new();
    table
        .set_header(vec!["Field", "Value"])
        .add_row(vec![
            Cell::new("Execution ID"),
            Cell::new(&summary.result.id),
        ])
        .add_row(vec![
            Cell::new("Status"),
            Cell::new(status_label(&summary.result.status)),
        ])
        .add_row(vec![
            Cell::new("Exit Code"),
            Cell::new(
                summary
                    .result
                    .exit_code
                    .map_or_else(|| "n/a".to_string(), |code| code.to_string()),
            ),
        ])
        .add_row(vec![
            Cell::new("Duration"),
            Cell::new(format!("{} ms", summary.result.duration_ms)),
        ])
        .add_row(vec![Cell::new("Backend"), Cell::new(&summary.backend)])
        .add_row(vec![
            Cell::new("Env Vars Scrubbed"),
            Cell::new(summary.scrubbed_env_vars.to_string()),
        ])
        .add_row(vec![
            Cell::new("FS Changes"),
            Cell::new(summary.fs_changes.to_string()),
        ])
        .add_row(vec![
            Cell::new("Output Truncated"),
            Cell::new(if summary.output_truncated {
                "yes"
            } else {
                "no"
            }),
        ])
        .add_row(vec![
            Cell::new("Dropped Output"),
            Cell::new(format!("{} bytes", summary.dropped_output_bytes)),
        ])
        .add_row(vec![
            Cell::new("Artifacts Directory"),
            Cell::new(summary.result.artifacts_dir.display().to_string()),
        ])
        .add_row(vec![
            Cell::new("stdout.log"),
            Cell::new(summary.stdout_log.display().to_string()),
        ])
        .add_row(vec![
            Cell::new("stderr.log"),
            Cell::new(summary.stderr_log.display().to_string()),
        ]);

    println!("{table}");
}

fn status_label(status: &Status) -> String {
    match status {
        Status::Success => "success".to_string(),
        Status::Failed => "failed".to_string(),
        Status::Timeout => "timeout".to_string(),
        Status::Killed => "killed".to_string(),
        Status::SandboxError(message) => format!("sandbox_error: {message}"),
    }
}

fn print_human_plan(plan: &ExecutionPlan) {
    let mut table = Table::new();
    table
        .set_header(vec!["Field", "Value"])
        .add_row(vec![Cell::new("Execution ID"), Cell::new(&plan.id)])
        .add_row(vec![Cell::new("Profile"), Cell::new(&plan.profile.name)])
        .add_row(vec![
            Cell::new("Workspace Mode"),
            Cell::new(match plan.mode {
                WorkspaceMode::Direct => "Direct",
                WorkspaceMode::Replica { .. } => "Replica",
            }),
        ])
        .add_row(vec![
            Cell::new("Command"),
            Cell::new(plan.command.join(" ")),
        ])
        .add_row(vec![
            Cell::new("Execution CWD"),
            Cell::new(plan.cwd.display().to_string()),
        ])
        .add_row(vec![
            Cell::new("Network"),
            Cell::new(match plan.profile.net {
                clawcrate_types::NetLevel::None => "none",
                clawcrate_types::NetLevel::Open => "open",
            }),
        ])
        .add_row(vec![
            Cell::new("Filesystem Read Paths"),
            Cell::new(plan.profile.fs_read.len().to_string()),
        ])
        .add_row(vec![
            Cell::new("Filesystem Write Paths"),
            Cell::new(plan.profile.fs_write.len().to_string()),
        ])
        .add_row(vec![
            Cell::new("Env Scrub Patterns"),
            Cell::new(plan.profile.env_scrub.len().to_string()),
        ]);

    println!("{table}");
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::path::{Path, PathBuf};
    use std::process::{Command, Stdio};
    use std::time::{SystemTime, UNIX_EPOCH};

    use super::{
        build_execution_plan, copy_workspace_with_default_exclusions, doctor_rows,
        execution_status, execution_status_from_exit_status, resolve_execution_path,
        run_monitored_child, select_default_mode, should_exclude_replica_path, CommandArgs,
        RunTermination,
    };
    use clap::Parser;
    use clawcrate_profiles::ProfileResolver;
    use clawcrate_types::{DefaultMode, Platform, Status, SystemCapabilities, WorkspaceMode};

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
    fn parses_plan_command_with_profile_and_command() {
        let cli = super::Cli::parse_from([
            "clawcrate",
            "plan",
            "--profile",
            "build",
            "--",
            "cargo",
            "test",
        ]);

        match cli.command {
            super::Commands::Plan(args) => {
                assert_eq!(args.profile.as_deref(), Some("build"));
                assert_eq!(args.command, vec!["cargo".to_string(), "test".to_string()]);
                assert!(!args.json);
            }
            _ => panic!("expected plan command"),
        }
    }

    #[test]
    fn parses_doctor_command_with_json() {
        let cli = super::Cli::parse_from(["clawcrate", "doctor", "--json"]);

        match cli.command {
            super::Commands::Doctor(args) => assert!(args.json),
            _ => panic!("expected doctor command"),
        }
    }

    #[test]
    fn profile_default_mode_is_overridden_by_flags() {
        let args = CommandArgs {
            profile: None,
            replica: true,
            direct: false,
            json: false,
            command: vec!["echo".to_string(), "hello".to_string()],
        };
        assert_eq!(
            select_default_mode(DefaultMode::Direct, &args),
            DefaultMode::Replica
        );
    }

    #[test]
    fn auto_detect_falls_back_to_safe_when_workspace_is_unknown() {
        let resolver = ProfileResolver::default();
        let cwd = unique_tmp_dir("clawcrate_cli_plan_safe");
        let args = CommandArgs {
            profile: None,
            replica: false,
            direct: false,
            json: false,
            command: vec!["echo".to_string(), "hello".to_string()],
        };

        let plan = build_execution_plan(&resolver, &cwd, &args).expect("build execution plan");
        assert_eq!(plan.profile.name, "safe");
        assert!(matches!(plan.mode, WorkspaceMode::Direct));
        assert_eq!(plan.cwd, cwd);
    }

    #[test]
    fn install_profile_materializes_replica_mode() {
        let resolver = ProfileResolver::default();
        let cwd = unique_tmp_dir("clawcrate_cli_plan_replica");
        fs::write(
            cwd.join("package.json"),
            "{ \"name\": \"demo\", \"version\": \"0.1.0\" }",
        )
        .expect("write package json");

        let args = CommandArgs {
            profile: Some("install".to_string()),
            replica: false,
            direct: false,
            json: false,
            command: vec!["npm".to_string(), "install".to_string()],
        };

        let plan = build_execution_plan(&resolver, &cwd, &args).expect("build execution plan");
        match &plan.mode {
            WorkspaceMode::Replica { source, copy } => {
                assert_eq!(source, &cwd);
                assert!(copy.starts_with(Path::new(&std::env::temp_dir())));
                assert_eq!(plan.cwd, *copy);
            }
            WorkspaceMode::Direct => panic!("install profile must default to replica"),
        }
    }

    #[test]
    fn doctor_rows_render_linux_specific_capabilities() {
        let capabilities = SystemCapabilities {
            platform: Platform::Linux,
            landlock_abi: Some(4),
            seccomp_available: true,
            seatbelt_available: false,
            user_namespaces: true,
            macos_version: None,
            kernel_version: Some("6.8.12".to_string()),
        };

        let rows = doctor_rows(&capabilities);
        assert!(rows
            .iter()
            .any(|(name, value)| name == "Platform" && value == "Linux"));
        assert!(rows
            .iter()
            .any(|(name, value)| name == "Landlock ABI" && value == "✅ ABI 4"));
        assert!(rows
            .iter()
            .any(|(name, value)| name == "seccomp" && value == "✅ available"));
        assert!(rows
            .iter()
            .any(|(name, value)| name == "Seatbelt" && value == "n/a"));
    }

    #[test]
    fn doctor_rows_render_macos_specific_capabilities() {
        let capabilities = SystemCapabilities {
            platform: Platform::MacOS,
            landlock_abi: None,
            seccomp_available: false,
            seatbelt_available: true,
            user_namespaces: false,
            macos_version: Some("14.5".to_string()),
            kernel_version: Some("23.5.0".to_string()),
        };

        let rows = doctor_rows(&capabilities);
        assert!(rows
            .iter()
            .any(|(name, value)| name == "Platform" && value == "macOS"));
        assert!(rows
            .iter()
            .any(|(name, value)| name == "macOS Version" && value == "14.5"));
        assert!(rows
            .iter()
            .any(|(name, value)| name == "Seatbelt" && value == "✅ available"));
        assert!(rows
            .iter()
            .any(|(name, value)| name == "Landlock ABI" && value == "n/a"));
    }

    #[test]
    fn resolve_execution_path_expands_relative_and_home_paths() {
        let cwd = PathBuf::from("/tmp/workspace");
        let relative = resolve_execution_path(&cwd, Path::new("./target"));
        assert_eq!(relative, PathBuf::from("/tmp/workspace/./target"));

        if let Some(home) = std::env::var_os("HOME") {
            let expected = PathBuf::from(home).join(".cargo");
            let resolved = resolve_execution_path(&cwd, Path::new("~/.cargo"));
            assert_eq!(resolved, expected);
        }
    }

    #[test]
    fn should_exclude_replica_defaults() {
        assert!(should_exclude_replica_path(Path::new(".env")));
        assert!(should_exclude_replica_path(Path::new(".env.local")));
        assert!(should_exclude_replica_path(Path::new(
            "nested/.env.production"
        )));
        assert!(should_exclude_replica_path(Path::new(".git/config")));
        assert!(!should_exclude_replica_path(Path::new(".git/HEAD")));
        assert!(!should_exclude_replica_path(Path::new("src/main.rs")));
    }

    #[test]
    fn replica_copy_excludes_default_secret_files() {
        let source = unique_tmp_dir("clawcrate_cli_replica_source");
        fs::create_dir_all(source.join(".git")).expect("create .git");
        fs::create_dir_all(source.join("nested")).expect("create nested");

        fs::write(source.join(".env"), "SECRET=1").expect("write .env");
        fs::write(source.join(".env.local"), "SECRET=2").expect("write .env.local");
        fs::write(source.join(".git/config"), "token = hidden").expect("write .git/config");
        fs::write(source.join(".git/HEAD"), "ref: refs/heads/main").expect("write .git/HEAD");
        fs::write(source.join("nested/.env.production"), "SECRET=3")
            .expect("write nested .env.production");
        fs::write(source.join("nested/app.txt"), "visible").expect("write visible file");

        let replica_root = unique_tmp_dir("clawcrate_cli_replica_copy_root");
        let replica = replica_root.join("workspace");
        copy_workspace_with_default_exclusions(&source, &replica).expect("copy workspace");

        assert!(!replica.join(".env").exists());
        assert!(!replica.join(".env.local").exists());
        assert!(!replica.join(".git/config").exists());
        assert!(!replica.join("nested/.env.production").exists());
        assert!(replica.join(".git/HEAD").exists());
        assert_eq!(
            fs::read_to_string(replica.join("nested/app.txt")).expect("read copied file"),
            "visible"
        );
    }

    #[test]
    fn execution_status_maps_process_outcome() {
        let success = Command::new("/bin/sh")
            .arg("-c")
            .arg("exit 0")
            .status()
            .expect("run success command");
        let failure = Command::new("/bin/sh")
            .arg("-c")
            .arg("exit 3")
            .status()
            .expect("run failure command");

        assert_eq!(execution_status_from_exit_status(&success), Status::Success);
        assert_eq!(execution_status_from_exit_status(&failure), Status::Failed);
    }

    #[test]
    fn execution_status_prefers_runtime_termination_reason() {
        let success = Command::new("/bin/sh")
            .arg("-c")
            .arg("exit 0")
            .status()
            .expect("run success command");

        assert_eq!(
            execution_status(&success, RunTermination::Interrupted),
            Status::Killed
        );
        assert_eq!(
            execution_status(&success, RunTermination::Timeout),
            Status::Timeout
        );
    }

    #[test]
    fn monitored_child_timeout_preserves_output_capture() {
        let artifacts_dir = unique_tmp_dir("clawcrate_cli_timeout_capture");
        let capture_config = super::CaptureConfig {
            artifacts_dir,
            max_output_bytes: 1024,
        };

        let mut command = Command::new("/bin/sh");
        command
            .arg("-c")
            .arg("printf 'before-timeout'; sleep 2")
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        let mut child = command.spawn().expect("spawn timeout child");
        let stdout = child.stdout.take().expect("take stdout");
        let stderr = child.stderr.take().expect("take stderr");

        let result =
            run_monitored_child(&mut child, stdout, stderr, &capture_config, 1).expect("monitor");

        assert_eq!(result.termination, RunTermination::Timeout);
        assert_eq!(
            execution_status(&result.exit_status, result.termination),
            Status::Timeout
        );
        assert_eq!(
            fs::read_to_string(capture_config.stdout_log_path()).expect("read stdout"),
            "before-timeout"
        );
    }
}
