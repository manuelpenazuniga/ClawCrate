//! mcp module (extracted from main.rs; see #277).

use std::fs::File;
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStderr, ChildStdout, ExitStatus, Stdio};
use std::sync::{mpsc, Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use crate::mcp_install;
use crate::{cli::*, output::*, replica::*, run::*, support::*};
use anyhow::{anyhow, Result};
use clawcrate_audit::ArtifactWriter;
use clawcrate_capture::{
    diff_snapshots, snapshot_paths, CaptureConfig, CaptureError, CaptureSummary, FsChange,
    StreamCaptureStats,
};
use clawcrate_profiles::ProfileResolver;
#[cfg(target_os = "macos")]
use clawcrate_sandbox::darwin::DarwinSandbox;
#[cfg(target_os = "linux")]
use clawcrate_sandbox::linux::LinuxSandbox;
use clawcrate_types::{AuditEventKind, ExecutionPlan, ExecutionResult};
#[cfg(unix)]
use signal_hook::consts::signal::{SIGINT, SIGTERM};
#[cfg(unix)]
use signal_hook::iterator::Signals;

pub(crate) fn handle_mcp(
    resolver: &ProfileResolver,
    args: McpArgs,
    output: &OutputOptions,
) -> Result<()> {
    match args.command {
        McpCommand::Wrap(args) => handle_mcp_wrap(resolver, args, output),
        McpCommand::Install(args) => mcp_install::handle_install(args, output),
        McpCommand::Uninstall(args) => mcp_install::handle_uninstall(args, output),
    }
}

pub(crate) fn handle_mcp_wrap(
    resolver: &ProfileResolver,
    args: McpWrapArgs,
    output: &OutputOptions,
) -> Result<()> {
    let cwd =
        std::env::current_dir().map_err(|source| anyhow!("failed to get current dir: {source}"))?;
    let plan = build_mcp_wrap_plan(resolver, &cwd, &args)?;
    let mut sqlite_index = configure_optional_sqlite_index(output);
    verbose_log(
        output,
        1,
        format!(
            "mcp wrap start: id={}, profile={}, mode={:?}, command={}",
            plan.id,
            plan.profile.name,
            plan.mode,
            plan.command.join(" ")
        ),
    );

    let writer = ArtifactWriter::new(&runs_root()?, &plan.id)
        .map_err(|source| anyhow!("failed to initialize artifact writer: {source}"))?;
    verbose_log(
        output,
        2,
        format!(
            "mcp artifacts dir initialized at {}",
            writer.artifacts_dir().display()
        ),
    );

    writer
        .write_plan(&plan)
        .map_err(|source| anyhow!("failed to write plan artifact: {source}"))?;

    let started_at = Instant::now();
    let pipeline = match execute_mcp_wrap_pipeline(&plan, &writer) {
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

    verbose_log(
        output,
        1,
        format!(
            "mcp wrap exit: id={}, backend={}, status={:?}, scrubbed_env_vars={}, output_truncated={}",
            plan.id,
            pipeline.execution.backend,
            result.status,
            pipeline.execution.scrubbed_keys.len(),
            pipeline.execution.relay_summary.truncated
        ),
    );

    if pipeline.execution.exit_status.success() {
        Ok(())
    } else {
        Err(anyhow!(
            "wrapped MCP server exited with status {}",
            pipeline.execution.exit_status
        ))
    }
}

#[derive(Debug)]
pub(crate) struct McpRelayExecutionOutcome {
    pub(crate) backend: String,
    pub(crate) scrubbed_keys: Vec<String>,
    pub(crate) exit_status: ExitStatus,
    pub(crate) relay_summary: CaptureSummary,
    pub(crate) termination: RunTermination,
}

#[derive(Debug)]
pub(crate) struct McpRelayPipelineResult {
    pub(crate) execution: McpRelayExecutionOutcome,
    pub(crate) fs_diff: Vec<FsChange>,
}

pub(crate) const AUTO_DETECTED_MCP_PROFILE: &str = "mcp-readonly";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum McpServerShapeDetection {
    OfficialPackage,
    ServerName,
    MarkerWithStdio,
}

pub(crate) fn execute_mcp_wrap_pipeline(
    plan: &ExecutionPlan,
    writer: &ArtifactWriter,
) -> Result<McpRelayPipelineResult> {
    materialize_workspace_for_execution(plan, writer)?;
    let fs_diff_roots = resolve_fs_diff_roots(plan);
    let snapshot_before = snapshot_paths(&fs_diff_roots).map_err(|source| {
        anyhow!("failed to snapshot writable paths before MCP execution: {source}")
    })?;

    let capture_config = CaptureConfig {
        artifacts_dir: writer.artifacts_dir().to_path_buf(),
        max_output_bytes: plan.profile.resources.max_output_bytes,
    };
    let execution = launch_and_relay_mcp(plan, writer, &capture_config)?;

    let snapshot_after = snapshot_paths(&fs_diff_roots).map_err(|source| {
        anyhow!("failed to snapshot writable paths after MCP execution: {source}")
    })?;
    let fs_diff = diff_snapshots(&snapshot_before, &snapshot_after);

    Ok(McpRelayPipelineResult { execution, fs_diff })
}

#[cfg(target_os = "linux")]
pub(crate) fn launch_and_relay_mcp(
    plan: &ExecutionPlan,
    writer: &ArtifactWriter,
    capture_config: &CaptureConfig,
) -> Result<McpRelayExecutionOutcome> {
    let sandbox = LinuxSandbox::new();
    let mut prepared = sandbox.prepare(plan);
    let egress_proxy =
        maybe_start_filtered_egress_proxy(&plan.profile.net, &mut prepared.scrubbed_env)?;
    let scrubbed_keys = prepared.scrubbed_keys.clone();

    let mut capabilities = vec![
        "rlimits".to_string(),
        "landlock".to_string(),
        "seccomp".to_string(),
        "stdio-relay".to_string(),
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
        .launch_with_stdio(&prepared, Stdio::inherit(), Stdio::piped(), Stdio::piped())
        .map_err(|source| anyhow!("failed to launch linux MCP sandbox: {source}"))?;
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
        .map_err(|source| anyhow!("failed to relay MCP stdout pipe: {source}"))?;
    let stderr = child
        .child_mut()
        .stderr
        .take()
        .ok_or(CaptureError::MissingStderrPipe)
        .map_err(|source| anyhow!("failed to relay MCP stderr pipe: {source}"))?;
    let monitored = run_mcp_relay_child(
        child.child_mut(),
        stdout,
        stderr,
        capture_config,
        plan.profile.resources.max_cpu_seconds,
        Some(pid as i32),
    )?;
    drop(egress_proxy);

    Ok(McpRelayExecutionOutcome {
        backend: "linux".to_string(),
        scrubbed_keys,
        exit_status: monitored.exit_status,
        relay_summary: monitored.capture_summary,
        termination: monitored.termination,
    })
}

#[cfg(target_os = "macos")]
pub(crate) fn launch_and_relay_mcp(
    plan: &ExecutionPlan,
    writer: &ArtifactWriter,
    capture_config: &CaptureConfig,
) -> Result<McpRelayExecutionOutcome> {
    let sandbox = DarwinSandbox::new();
    let mut prepared = sandbox.prepare(plan);
    let egress_proxy =
        maybe_start_filtered_egress_proxy(&plan.profile.net, &mut prepared.scrubbed_env)?;
    let scrubbed_keys = prepared.scrubbed_keys.clone();

    let mut capabilities = vec!["seatbelt".to_string(), "stdio-relay".to_string()];
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
        .launch_with_stdio(&prepared, Stdio::inherit(), Stdio::piped(), Stdio::piped())
        .map_err(|source| anyhow!("failed to launch macOS MCP sandbox: {source}"))?;
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
        .map_err(|source| anyhow!("failed to relay MCP stdout pipe: {source}"))?;
    let stderr = child
        .child_mut()
        .stderr
        .take()
        .ok_or(CaptureError::MissingStderrPipe)
        .map_err(|source| anyhow!("failed to relay MCP stderr pipe: {source}"))?;
    let monitored = run_mcp_relay_child(
        child.child_mut(),
        stdout,
        stderr,
        capture_config,
        plan.profile.resources.max_cpu_seconds,
        Some(pid as i32),
    )?;
    drop(egress_proxy);

    Ok(McpRelayExecutionOutcome {
        backend: "macos-seatbelt".to_string(),
        scrubbed_keys,
        exit_status: monitored.exit_status,
        relay_summary: monitored.capture_summary,
        termination: monitored.termination,
    })
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
pub(crate) fn launch_and_relay_mcp(
    _plan: &ExecutionPlan,
    _writer: &ArtifactWriter,
    _capture_config: &CaptureConfig,
) -> Result<McpRelayExecutionOutcome> {
    Err(anyhow!("unsupported platform for `mcp wrap` command"))
}

pub(crate) const MCP_RELAY_CHUNK_SIZE: usize = 8192;

pub(crate) fn run_mcp_relay_child(
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

    run_mcp_relay_child_with_signal_poller(
        child,
        stdout,
        stderr,
        capture_config,
        timeout_seconds,
        process_group_id,
        &mut poll_pending_interrupts,
    )
}

pub(crate) fn run_mcp_relay_child_with_signal_poller<F>(
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
    const RELAY_DRAIN_GRACE_PERIOD: Duration = Duration::from_millis(250);
    const RELAY_DRAIN_MAX_WAIT: Duration = Duration::from_secs(2);

    let capture_config = capture_config.clone();
    let (relay_tx, relay_rx) = mpsc::sync_channel(1);
    thread::spawn(move || {
        let _ = relay_tx.send(relay_mcp_streams(stdout, stderr, &capture_config));
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
            .map_err(|source| anyhow!("failed while waiting for MCP server exit: {source}"))?
        {
            break status;
        }

        thread::sleep(POLL_INTERVAL);
    };

    let relay_wait_started = Instant::now();
    let mut relay_force_kill_sent = false;
    let capture_summary = loop {
        match relay_rx.recv_timeout(POLL_INTERVAL) {
            Ok(Ok(summary)) => break summary,
            Ok(Err(source)) => return Err(source),
            Err(mpsc::RecvTimeoutError::Disconnected) => {
                return Err(anyhow!(
                    "MCP relay thread disconnected before returning capture summary"
                ));
            }
            Err(mpsc::RecvTimeoutError::Timeout) => {
                if !relay_force_kill_sent
                    && relay_wait_started.elapsed() >= RELAY_DRAIN_GRACE_PERIOD
                {
                    send_kill_signal(child, process_group_id)?;
                    relay_force_kill_sent = true;
                }

                if relay_wait_started.elapsed() >= RELAY_DRAIN_MAX_WAIT {
                    return Err(anyhow!(
                        "timed out draining MCP relay output; descendant process may be holding stdout/stderr open"
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

pub(crate) fn relay_mcp_streams(
    stdout: ChildStdout,
    stderr: ChildStderr,
    capture_config: &CaptureConfig,
) -> Result<CaptureSummary> {
    std::fs::create_dir_all(&capture_config.artifacts_dir).map_err(|source| {
        anyhow!(
            "failed to create MCP relay artifact directory {}: {source}",
            capture_config.artifacts_dir.display()
        )
    })?;
    let remaining_log_bytes = Arc::new(Mutex::new(capture_config.max_output_bytes));

    let stdout_log = capture_config.stdout_log_path();
    let stdout_budget = Arc::clone(&remaining_log_bytes);
    let stdout_handle = thread::spawn(move || {
        relay_stream_to_output_and_log(stdout, io::stdout(), stdout_log, stdout_budget)
    });

    let stderr_log = capture_config.stderr_log_path();
    let stderr_budget = Arc::clone(&remaining_log_bytes);
    let stderr_handle = thread::spawn(move || {
        relay_stream_to_output_and_log(stderr, io::stderr(), stderr_log, stderr_budget)
    });

    let stdout = join_relay_thread(stdout_handle)?;
    let stderr = join_relay_thread(stderr_handle)?;
    Ok(capture_summary(stdout, stderr))
}

pub(crate) fn relay_stream_to_output_and_log<R, W>(
    mut input: R,
    mut output: W,
    log_path: PathBuf,
    remaining_log_bytes: Arc<Mutex<u64>>,
) -> Result<StreamCaptureStats>
where
    R: Read,
    W: Write,
{
    let mut log = File::create(&log_path).map_err(|source| {
        anyhow!(
            "failed to create MCP relay log {}: {source}",
            log_path.display()
        )
    })?;
    let mut written_bytes = 0u64;
    let mut dropped_bytes = 0u64;
    let mut buffer = [0u8; MCP_RELAY_CHUNK_SIZE];

    loop {
        let read = input
            .read(&mut buffer)
            .map_err(|source| anyhow!("failed to read MCP relay stream: {source}"))?;
        if read == 0 {
            break;
        }

        if !write_mcp_relay_output(&mut output, &buffer[..read])? {
            break;
        }

        let log_bytes = {
            let mut remaining = remaining_log_bytes
                .lock()
                .map_err(|_| anyhow!("MCP relay output budget lock poisoned"))?;
            let allowed = (*remaining).min(read as u64) as usize;
            *remaining -= allowed as u64;
            allowed
        };

        if log_bytes > 0 {
            log.write_all(&buffer[..log_bytes])
                .map_err(|source| anyhow!("failed to write MCP relay log: {source}"))?;
            written_bytes += log_bytes as u64;
        }
        dropped_bytes += (read - log_bytes) as u64;
    }

    log.flush()
        .map_err(|source| anyhow!("failed to flush MCP relay log: {source}"))?;

    Ok(StreamCaptureStats {
        written_bytes,
        dropped_bytes,
    })
}

pub(crate) fn write_mcp_relay_output<W>(output: &mut W, bytes: &[u8]) -> Result<bool>
where
    W: Write,
{
    if let Err(source) = output.write_all(bytes) {
        if source.kind() == io::ErrorKind::BrokenPipe {
            return Ok(false);
        }
        return Err(anyhow!("failed to write MCP relay output: {source}"));
    }
    if let Err(source) = output.flush() {
        if source.kind() == io::ErrorKind::BrokenPipe {
            return Ok(false);
        }
        return Err(anyhow!("failed to flush MCP relay output: {source}"));
    }
    Ok(true)
}

pub(crate) fn join_relay_thread(
    handle: thread::JoinHandle<Result<StreamCaptureStats>>,
) -> Result<StreamCaptureStats> {
    handle
        .join()
        .map_err(|_| anyhow!("MCP relay stream thread panicked"))?
}

pub(crate) fn build_mcp_wrap_plan(
    resolver: &ProfileResolver,
    cwd: &Path,
    args: &McpWrapArgs,
) -> Result<ExecutionPlan> {
    let profile = match args.profile.as_deref() {
        Some(explicit) => explicit.to_string(),
        None => {
            if detect_stdio_mcp_server_shape(&args.command).is_some() {
                AUTO_DETECTED_MCP_PROFILE.to_string()
            } else {
                return Err(anyhow!(
                    "could not auto-detect a stdio MCP server shape for `{}`; pass `--profile mcp-readonly` for read-only servers or `--profile mcp-server` for workspace-writing servers",
                    args.command.join(" ")
                ));
            }
        }
    };

    let command_args = CommandArgs {
        profile: Some(profile),
        replica: args.replica,
        direct: args.direct,
        json: false,
        approve_out_of_profile: false,
        command: args.command.clone(),
    };

    build_execution_plan(resolver, cwd, &command_args)
}

pub(crate) fn detect_stdio_mcp_server_shape(command: &[String]) -> Option<McpServerShapeDetection> {
    if command.is_empty() {
        return None;
    }

    let tokens = command
        .iter()
        .map(|token| token.trim().to_ascii_lowercase())
        .filter(|token| !token.is_empty())
        .collect::<Vec<_>>();

    // Conservative command-shape heuristic only. A positive match never grants
    // broader policy: omitted profiles become mcp-readonly, and unknown shapes
    // require the user to choose an MCP profile explicitly.
    if tokens
        .iter()
        .any(|token| token.contains("@modelcontextprotocol/"))
    {
        return Some(McpServerShapeDetection::OfficialPackage);
    }

    if tokens
        .iter()
        .any(|token| token_has_mcp_server_name_marker(token))
    {
        return Some(McpServerShapeDetection::ServerName);
    }

    if command_has_stdio_transport_hint(&tokens)
        && tokens
            .iter()
            .any(|token| token.contains("modelcontextprotocol") || token_has_mcp_marker(token))
    {
        return Some(McpServerShapeDetection::MarkerWithStdio);
    }

    None
}

pub(crate) fn command_has_stdio_transport_hint(tokens: &[String]) -> bool {
    tokens.iter().any(|token| {
        matches!(token.as_str(), "stdio" | "--stdio" | "--transport=stdio")
            || token.ends_with("transport=stdio")
    }) || tokens
        .windows(2)
        .any(|pair| matches!(pair[0].as_str(), "--transport" | "transport") && pair[1] == "stdio")
}

pub(crate) fn token_has_mcp_marker(token: &str) -> bool {
    let name = normalized_mcp_token_name(token);

    name == "mcp" || name.ends_with("-mcp") || name.contains("-mcp-")
}

pub(crate) fn token_has_mcp_server_name_marker(token: &str) -> bool {
    let name = normalized_mcp_token_name(token);

    name == "mcp-server"
        || name.starts_with("mcp-server-")
        || name.ends_with("-mcp-server")
        || name.contains("-mcp-server-")
}

pub(crate) fn normalized_mcp_token_name(token: &str) -> String {
    let value = strip_cli_value_prefix(token);
    let name = token_basename(value);
    let name = strip_known_script_suffix(name);

    name.replace('_', "-")
}

pub(crate) fn strip_cli_value_prefix(token: &str) -> &str {
    ["--package=", "--from=", "-p="]
        .iter()
        .find_map(|prefix| token.strip_prefix(prefix))
        .unwrap_or(token)
}

pub(crate) fn token_basename(token: &str) -> &str {
    token.rsplit(['/', '\\']).next().unwrap_or(token)
}

pub(crate) fn strip_known_script_suffix(token: &str) -> &str {
    [".js", ".mjs", ".cjs", ".py", ".sh", ".exe"]
        .iter()
        .find_map(|suffix| token.strip_suffix(suffix))
        .unwrap_or(token)
}
