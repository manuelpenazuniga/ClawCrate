//! run module (extracted from main.rs; see #277).

use std::path::{Path, PathBuf};
use std::process::{Child, ChildStderr, ChildStdout, ExitStatus};
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};

use crate::{approval::*, cli::*, output::*, replica::*, support::*};
use anyhow::{anyhow, Result};
use chrono::Utc;
use clawcrate_audit::ArtifactWriter;
use clawcrate_capture::{
    capture_streams, diff_snapshots, snapshot_paths, CaptureConfig, CaptureError, CaptureSummary,
    FsChange, StreamCaptureStats,
};
use clawcrate_profiles::ProfileResolver;
#[cfg(target_os = "macos")]
use clawcrate_sandbox::darwin::DarwinSandbox;
#[cfg(target_os = "linux")]
use clawcrate_sandbox::linux::LinuxSandbox;
use clawcrate_types::{
    Actor, AuditEventKind, ExecutionPlan, ExecutionResult, Status, WorkspaceMode,
};
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

pub(crate) fn handle_plan(
    resolver: &ProfileResolver,
    args: CommandArgs,
    output: &OutputOptions,
) -> Result<()> {
    let cwd =
        std::env::current_dir().map_err(|source| anyhow!("failed to get current dir: {source}"))?;
    let plan = build_execution_plan(resolver, &cwd, &args)?;
    verbose_log(
        output,
        1,
        format!(
            "plan built: profile={}, mode={:?}, cwd={}",
            plan.profile.name,
            plan.mode,
            plan.cwd.display()
        ),
    );

    if args.json {
        println!("{}", serde_json::to_string_pretty(&plan)?);
    } else {
        print_human_plan(&plan, output);
    }

    Ok(())
}

#[derive(Debug)]
pub(crate) struct RunExecutionOutcome {
    pub(crate) backend: String,
    pub(crate) scrubbed_keys: Vec<String>,
    pub(crate) exit_status: ExitStatus,
    pub(crate) capture_summary: CaptureSummary,
    pub(crate) termination: RunTermination,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RunTermination {
    Exited,
    Interrupted,
    Timeout,
}

#[derive(Debug)]
pub(crate) struct RunPipelineResult {
    pub(crate) execution: RunExecutionOutcome,
    pub(crate) fs_diff: Vec<FsChange>,
}

#[derive(Debug, Serialize)]
pub(crate) struct RunSummary {
    pub(crate) result: ExecutionResult,
    pub(crate) backend: String,
    pub(crate) scrubbed_env_vars: usize,
    pub(crate) fs_changes: usize,
    pub(crate) output_truncated: bool,
    pub(crate) dropped_output_bytes: u64,
    pub(crate) stdout_log: PathBuf,
    pub(crate) stderr_log: PathBuf,
}

pub(crate) fn handle_run(
    resolver: &ProfileResolver,
    args: CommandArgs,
    output: &OutputOptions,
) -> Result<()> {
    let cwd =
        std::env::current_dir().map_err(|source| anyhow!("failed to get current dir: {source}"))?;
    let plan = build_execution_plan(resolver, &cwd, &args)?;
    let mut sqlite_index = configure_optional_sqlite_index(output);
    verbose_log(
        output,
        1,
        format!(
            "run start: id={}, profile={}, mode={:?}",
            plan.id, plan.profile.name, plan.mode
        ),
    );
    let writer = ArtifactWriter::new(&runs_root()?, &plan.id)
        .map_err(|source| anyhow!("failed to initialize artifact writer: {source}"))?;
    verbose_log(
        output,
        2,
        format!(
            "artifacts dir initialized at {}",
            writer.artifacts_dir().display()
        ),
    );

    writer
        .write_plan(&plan)
        .map_err(|source| anyhow!("failed to write plan artifact: {source}"))?;

    let started_at = Instant::now();
    if let Err(error) = enforce_out_of_profile_approval(&plan, &args, output, &writer) {
        persist_sandbox_error_result(
            &writer,
            &plan.id,
            started_at.elapsed().as_millis() as u64,
            &error,
        )?;
        maybe_index_artifacts_in_sqlite(&mut sqlite_index, &writer, output);
        return Err(error);
    }

    let pipeline = match execute_run_pipeline(&plan, &writer) {
        Ok(pipeline) => pipeline,
        Err(error) => {
            persist_sandbox_error_result(
                &writer,
                &plan.id,
                started_at.elapsed().as_millis() as u64,
                &error,
            )?;
            maybe_index_artifacts_in_sqlite(&mut sqlite_index, &writer, output);
            return Err(error);
        }
    };

    writer
        .write_fs_diff(&pipeline.fs_diff)
        .map_err(|source| anyhow!("failed to write fs-diff artifact: {source}"))?;
    maybe_sync_back_replica(&plan, &writer, &args, &pipeline.fs_diff, output)?;

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
    maybe_index_artifacts_in_sqlite(&mut sqlite_index, &writer, output);

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
        print_human_run_summary(&summary, output);
    }

    Ok(())
}

pub(crate) fn execute_run_pipeline(
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

#[cfg(target_os = "linux")]
pub(crate) fn launch_and_capture(
    plan: &ExecutionPlan,
    writer: &ArtifactWriter,
    capture_config: &CaptureConfig,
) -> Result<RunExecutionOutcome> {
    let sandbox = LinuxSandbox::new();
    let mut prepared = sandbox.prepare(plan);
    let egress_proxy =
        maybe_start_filtered_egress_proxy(&plan.profile.net, &mut prepared.scrubbed_env)?;
    let scrubbed_keys = prepared.scrubbed_keys.clone();

    let mut capabilities = vec![
        "rlimits".to_string(),
        "landlock".to_string(),
        "seccomp".to_string(),
    ];
    if egress_proxy.is_some() {
        capabilities.push("egress-proxy".to_string());
    }
    append_audit_event(
        writer,
        AuditEventKind::SandboxApplied {
            backend: "linux".to_string(),
            capabilities,
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
        Some(pid as i32),
    )?;
    drop(egress_proxy);

    Ok(RunExecutionOutcome {
        backend: "linux".to_string(),
        scrubbed_keys,
        exit_status: monitored.exit_status,
        capture_summary: monitored.capture_summary,
        termination: monitored.termination,
    })
}

#[cfg(target_os = "macos")]
pub(crate) fn launch_and_capture(
    plan: &ExecutionPlan,
    writer: &ArtifactWriter,
    capture_config: &CaptureConfig,
) -> Result<RunExecutionOutcome> {
    let sandbox = DarwinSandbox::new();
    let mut prepared = sandbox.prepare(plan);
    let egress_proxy =
        maybe_start_filtered_egress_proxy(&plan.profile.net, &mut prepared.scrubbed_env)?;
    let scrubbed_keys = prepared.scrubbed_keys.clone();

    let mut capabilities = vec!["seatbelt".to_string()];
    if egress_proxy.is_some() {
        capabilities.push("egress-proxy".to_string());
    }
    append_audit_event(
        writer,
        AuditEventKind::SandboxApplied {
            backend: "macos-seatbelt".to_string(),
            capabilities,
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
        Some(pid as i32),
    )?;
    drop(egress_proxy);

    Ok(RunExecutionOutcome {
        backend: "macos-seatbelt".to_string(),
        scrubbed_keys,
        exit_status: monitored.exit_status,
        capture_summary: monitored.capture_summary,
        termination: monitored.termination,
    })
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
pub(crate) fn launch_and_capture(
    _plan: &ExecutionPlan,
    _writer: &ArtifactWriter,
    _capture_config: &CaptureConfig,
) -> Result<RunExecutionOutcome> {
    Err(anyhow!("unsupported platform for `run` command"))
}

#[derive(Debug)]
pub(crate) struct MonitoredChildResult {
    pub(crate) exit_status: ExitStatus,
    pub(crate) capture_summary: CaptureSummary,
    pub(crate) termination: RunTermination,
}

pub(crate) fn capture_summary(
    stdout: StreamCaptureStats,
    stderr: StreamCaptureStats,
) -> CaptureSummary {
    let total_written_bytes = stdout.written_bytes + stderr.written_bytes;
    let total_dropped_bytes = stdout.dropped_bytes + stderr.dropped_bytes;
    CaptureSummary {
        stdout,
        stderr,
        total_written_bytes,
        total_dropped_bytes,
        truncated: total_dropped_bytes > 0,
    }
}

pub(crate) fn run_monitored_child(
    child: &mut Child,
    stdout: ChildStdout,
    stderr: ChildStderr,
    capture_config: &CaptureConfig,
    timeout_seconds: u64,
    process_group_id: Option<i32>,
) -> Result<MonitoredChildResult> {
    #[cfg(unix)]
    let mut signals = Signals::new([SIGINT, SIGTERM])
        .map_err(|source| anyhow!("failed to install signal handlers: {source}"))?;

    #[cfg(unix)]
    let mut poll_pending_interrupts = || {
        signals
            .pending()
            .filter(|signal| *signal == SIGINT || *signal == SIGTERM)
            .count()
    };
    #[cfg(not(unix))]
    let mut poll_pending_interrupts = || 0usize;

    run_monitored_child_with_signal_poller(
        child,
        stdout,
        stderr,
        capture_config,
        timeout_seconds,
        process_group_id,
        &mut poll_pending_interrupts,
    )
}

pub(crate) fn run_monitored_child_with_signal_poller<F>(
    child: &mut Child,
    stdout: ChildStdout,
    stderr: ChildStderr,
    capture_config: &CaptureConfig,
    timeout_seconds: u64,
    process_group_id: Option<i32>,
    poll_pending_interrupts: &mut F,
) -> Result<MonitoredChildResult>
where
    F: FnMut() -> usize,
{
    const POLL_INTERVAL: Duration = Duration::from_millis(25);
    const INTERRUPT_GRACE_PERIOD: Duration = Duration::from_secs(2);
    const CAPTURE_DRAIN_GRACE_PERIOD: Duration = Duration::from_millis(250);
    const CAPTURE_DRAIN_MAX_WAIT: Duration = Duration::from_secs(2);

    let capture_config = capture_config.clone();
    let (capture_tx, capture_rx) = mpsc::sync_channel(1);
    thread::spawn(move || {
        let _ = capture_tx.send(capture_streams(stdout, stderr, &capture_config));
    });

    let started_at = Instant::now();
    let mut interrupted = false;
    let mut timed_out = false;
    let mut interrupt_sent_at: Option<Instant> = None;
    let mut interrupt_forced_kill = false;

    let timeout_limit = (timeout_seconds > 0).then(|| Duration::from_secs(timeout_seconds));
    let exit_status = loop {
        let pending_interrupts = poll_pending_interrupts();
        let was_interrupted = interrupted;
        if pending_interrupts > 0 {
            if !interrupted {
                send_termination_signal(child, process_group_id)?;
                interrupted = true;
                interrupt_sent_at = Some(Instant::now());
            }

            let repeated_interrupt = pending_interrupts > 1 || was_interrupted;
            if repeated_interrupt && !timed_out && !interrupt_forced_kill {
                send_kill_signal(child, process_group_id)?;
                interrupt_forced_kill = true;
            }
        }

        if !timed_out
            && timeout_limit
                .map(|timeout| started_at.elapsed() >= timeout)
                .unwrap_or(false)
        {
            send_kill_signal(child, process_group_id)?;
            timed_out = true;
        }

        if interrupted && !timed_out && !interrupt_forced_kill {
            if let Some(interrupt_at) = interrupt_sent_at {
                if interrupt_at.elapsed() >= INTERRUPT_GRACE_PERIOD {
                    send_kill_signal(child, process_group_id)?;
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

    let capture_wait_started = Instant::now();
    let mut capture_force_kill_sent = false;
    let capture_summary = loop {
        match capture_rx.recv_timeout(POLL_INTERVAL) {
            Ok(Ok(summary)) => break summary,
            Ok(Err(source)) => return Err(anyhow!("failed to capture process output: {source}")),
            Err(mpsc::RecvTimeoutError::Disconnected) => {
                return Err(anyhow!(
                    "stream capture thread disconnected before returning capture summary"
                ));
            }
            Err(mpsc::RecvTimeoutError::Timeout) => {
                if !capture_force_kill_sent
                    && capture_wait_started.elapsed() >= CAPTURE_DRAIN_GRACE_PERIOD
                {
                    send_kill_signal(child, process_group_id)?;
                    capture_force_kill_sent = true;
                }

                if capture_wait_started.elapsed() >= CAPTURE_DRAIN_MAX_WAIT {
                    return Err(anyhow!(
                        "timed out draining captured output; descendant process may be holding stdout/stderr open"
                    ));
                }
            }
        }
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
pub(crate) fn send_termination_signal(child: &Child, process_group_id: Option<i32>) -> Result<()> {
    send_unix_signal_with_group_fallback(child.id() as i32, process_group_id, Signal::SIGTERM)
}

#[cfg(not(unix))]
pub(crate) fn send_termination_signal(
    child: &mut Child,
    _process_group_id: Option<i32>,
) -> Result<()> {
    child
        .kill()
        .map_err(|source| anyhow!("failed to terminate child process: {source}"))
}

#[cfg(unix)]
pub(crate) fn send_kill_signal(child: &Child, process_group_id: Option<i32>) -> Result<()> {
    send_unix_signal_with_group_fallback(child.id() as i32, process_group_id, Signal::SIGKILL)
}

#[cfg(not(unix))]
pub(crate) fn send_kill_signal(child: &mut Child, _process_group_id: Option<i32>) -> Result<()> {
    child
        .kill()
        .map_err(|source| anyhow!("failed to kill child process: {source}"))
}

#[cfg(unix)]
pub(crate) fn send_unix_signal_to_pid(pid_raw: i32, signal: Signal) -> Result<()> {
    let pid = Pid::from_raw(pid_raw);
    match kill(pid, signal) {
        Ok(()) | Err(Errno::ESRCH) => Ok(()),
        Err(source) => Err(anyhow!(
            "failed to send {signal:?} to child process {pid_raw}: {source}"
        )),
    }
}

#[cfg(unix)]
pub(crate) fn send_unix_signal_to_process_group(
    process_group_id: i32,
    signal: Signal,
) -> Result<()> {
    let process_group = Pid::from_raw(-process_group_id);
    match kill(process_group, signal) {
        Ok(()) | Err(Errno::ESRCH) => Ok(()),
        Err(source) => Err(anyhow!(
            "failed to send {signal:?} to process group {process_group_id}: {source}"
        )),
    }
}

#[cfg(unix)]
pub(crate) fn eligible_process_group_id(process_group_id: Option<i32>) -> Option<i32> {
    process_group_id.filter(|group_id| *group_id > 1)
}

#[cfg(unix)]
pub(crate) fn send_unix_signal_with_group_fallback(
    pid_raw: i32,
    process_group_id: Option<i32>,
    signal: Signal,
) -> Result<()> {
    send_unix_signal_with_group_fallback_impl(
        pid_raw,
        process_group_id,
        signal,
        send_unix_signal_to_pid,
        send_unix_signal_to_process_group,
    )
}

#[cfg(unix)]
pub(crate) fn send_unix_signal_with_group_fallback_impl<F, G>(
    pid_raw: i32,
    process_group_id: Option<i32>,
    signal: Signal,
    send_pid: F,
    send_process_group: G,
) -> Result<()>
where
    F: Fn(i32, Signal) -> Result<()>,
    G: Fn(i32, Signal) -> Result<()>,
{
    let pid_result = send_pid(pid_raw, signal);
    let process_group_result = if let Some(group_id) = eligible_process_group_id(process_group_id) {
        send_process_group(group_id, signal).map(Some)
    } else {
        Ok(None)
    };

    match (pid_result, process_group_result) {
        (Ok(()), Ok(_)) => Ok(()),
        (Ok(()), Err(group_error)) => Err(group_error),
        (Err(_), Ok(Some(()))) => Ok(()),
        (Err(pid_error), Err(group_error)) => Err(anyhow!(
            "failed to send {signal:?} to pid {pid_raw} and process group fallback failed: pid_error={pid_error}; group_error={group_error}"
        )),
        (Err(pid_error), Ok(None)) => Err(pid_error),
    }
}

pub(crate) fn execution_status(status: &ExitStatus, termination: RunTermination) -> Status {
    match termination {
        RunTermination::Timeout => Status::Timeout,
        RunTermination::Interrupted => Status::Killed,
        RunTermination::Exited => execution_status_from_exit_status(status),
    }
}

pub(crate) fn execution_status_from_exit_status(status: &ExitStatus) -> Status {
    if status.success() {
        return Status::Success;
    }
    if terminated_by_signal(status) {
        return Status::Killed;
    }
    Status::Failed
}

#[cfg(unix)]
pub(crate) fn terminated_by_signal(status: &ExitStatus) -> bool {
    status.signal().is_some()
}

#[cfg(not(unix))]
pub(crate) fn terminated_by_signal(_status: &ExitStatus) -> bool {
    false
}

pub(crate) fn build_execution_plan(
    resolver: &ProfileResolver,
    cwd: &Path,
    args: &CommandArgs,
) -> Result<ExecutionPlan> {
    let mut profile = match args.profile.as_deref() {
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
    normalize_profile_filesystem_paths(&mut profile, &execution_cwd);

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
