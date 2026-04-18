#![forbid(unsafe_code)]

use std::collections::BTreeSet;
use std::io::{self, IsTerminal, Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStderr, ChildStdout, Command, ExitStatus};
use std::thread;
use std::time::{Duration, Instant};

use anyhow::{anyhow, Result};
use chrono::Utc;
use clap::{ArgAction, Args, Parser, Subcommand};
use clawcrate_audit::{ArtifactWriter, SqliteAuditIndex, DEFAULT_AUDIT_DB};
use clawcrate_capture::{
    capture_streams, diff_snapshots, snapshot_paths, CaptureConfig, CaptureError, CaptureSummary,
    FsChange, FsChangeKind,
};
use clawcrate_profiles::ProfileResolver;
#[cfg(target_os = "macos")]
use clawcrate_sandbox::darwin::DarwinSandbox;
use clawcrate_sandbox::egress_proxy::{start_egress_proxy, EgressProxyConfig, EgressProxyHandle};
#[cfg(target_os = "linux")]
use clawcrate_sandbox::linux::LinuxSandbox;
#[cfg(target_os = "linux")]
use clawcrate_sandbox::linux_probe::probe_linux_capabilities;
#[cfg(target_os = "macos")]
use clawcrate_sandbox::macos_probe::probe_macos_capabilities;
use clawcrate_types::{
    Actor, AuditEvent, AuditEventKind, DefaultMode, ExecutionPlan, ExecutionResult, NetLevel,
    Platform, Status, SystemCapabilities, WorkspaceMode,
};
use comfy_table::{Cell, Table};
use ignore::gitignore::{Gitignore, GitignoreBuilder};
#[cfg(unix)]
use nix::errno::Errno;
#[cfg(unix)]
use nix::sys::signal::{kill, Signal};
#[cfg(unix)]
use nix::unistd::Pid;
use serde::{Deserialize, Serialize};
#[cfg(unix)]
use signal_hook::consts::signal::{SIGINT, SIGTERM};
#[cfg(unix)]
use signal_hook::iterator::Signals;
#[cfg(unix)]
use std::os::unix::process::ExitStatusExt;
use tiny_http::{Header, Method, Request, Response, Server, StatusCode};
use uuid::Uuid;

#[derive(Debug, Parser)]
#[command(
    name = "clawcrate",
    version,
    about = "Secure execution runtime for AI shell commands"
)]
struct Cli {
    #[command(flatten)]
    global: GlobalArgs,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Debug, Args, Clone, Copy)]
struct GlobalArgs {
    /// Increase diagnostic verbosity (-v, -vv)
    #[arg(short = 'v', long, action = ArgAction::Count, global = true)]
    verbose: u8,

    /// Disable ANSI colors in human-readable output
    #[arg(long, action = ArgAction::SetTrue, global = true)]
    no_color: bool,
}

#[derive(Debug, Clone, Copy)]
struct OutputOptions {
    verbose: u8,
    color: bool,
}

#[derive(Debug, Subcommand)]
enum Commands {
    /// Execute a command inside a sandbox
    Run(CommandArgs),
    /// Show execution plan without executing (dry-run)
    Plan(CommandArgs),
    /// Check system sandboxing capabilities
    Doctor(DoctorArgs),
    /// Serve local authenticated HTTP API for tool integrations
    Api(ApiArgs),
    /// Integration bridges for external agent tooling
    Bridge(BridgeArgs),
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

    /// Auto-approve detected permission requests outside the active profile
    #[arg(long, action = ArgAction::SetTrue)]
    approve_out_of_profile: bool,

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

#[derive(Debug, Args)]
struct ApiArgs {
    /// Bind address for local API server
    #[arg(long, default_value = "127.0.0.1:8787")]
    bind: String,

    /// Bearer token for API authentication (fallback: CLAWCRATE_API_TOKEN)
    #[arg(long)]
    token: Option<String>,
}

#[derive(Debug, Args)]
struct BridgeArgs {
    #[command(subcommand)]
    target: BridgeTarget,
}

#[derive(Debug, Subcommand)]
enum BridgeTarget {
    /// One-shot JSON bridge compatible with PennyPrompt shell-dispatch flow
    Pennyprompt(PennyPromptBridgeArgs),
}

#[derive(Debug, Args)]
struct PennyPromptBridgeArgs {
    /// Pretty-print JSON output
    #[arg(long, action = ArgAction::SetTrue)]
    pretty: bool,
}

fn main() {
    let cli = Cli::parse();
    let output = OutputOptions::from_global(&cli.global);
    if let Err(error) = run(cli, output) {
        print_cli_error(&error, output.verbose);
        std::process::exit(1);
    }
}

fn run(cli: Cli, output: OutputOptions) -> Result<()> {
    let resolver = ProfileResolver::default();

    match cli.command {
        Commands::Plan(args) => handle_plan(&resolver, args, &output),
        Commands::Run(args) => handle_run(&resolver, args, &output),
        Commands::Doctor(args) => handle_doctor(args, &output),
        Commands::Api(args) => handle_api(args, &output),
        Commands::Bridge(args) => handle_bridge(args, &output),
    }
}

impl OutputOptions {
    fn from_global(global: &GlobalArgs) -> Self {
        let no_color_env_set = std::env::var_os("NO_COLOR").is_some();
        let color = should_use_color(
            global.no_color,
            no_color_env_set,
            io::stdout().is_terminal(),
        );
        Self {
            verbose: global.verbose,
            color,
        }
    }
}

fn should_use_color(no_color_flag: bool, no_color_env_set: bool, stdout_is_terminal: bool) -> bool {
    !no_color_flag && !no_color_env_set && stdout_is_terminal
}

fn verbose_log(output: &OutputOptions, level: u8, message: impl AsRef<str>) {
    if output.verbose >= level {
        eprintln!("[verbose] {}", message.as_ref());
    }
}

fn print_cli_error(error: &anyhow::Error, verbose: u8) {
    eprintln!("error: {error}");
    if verbose > 0 {
        for cause in error.chain().skip(1) {
            eprintln!("  caused by: {cause}");
        }
    } else if error.chain().nth(1).is_some() {
        eprintln!("hint: re-run with `--verbose` to see the full error chain.");
    }

    if let Some(hint) = error_hint(error) {
        eprintln!("hint: {hint}");
    }
}

fn error_hint(error: &anyhow::Error) -> Option<&'static str> {
    let message = error.to_string();
    if message.contains("failed to resolve profile") {
        return Some("use `--profile <safe|build|install|open>` or a valid profile YAML path.");
    }
    if message.contains("unsupported platform") {
        return Some("`run` and `doctor` are supported on Linux and macOS only.");
    }
    if message.contains("failed to get current dir") {
        return Some("run clawcrate from an existing and accessible working directory.");
    }
    None
}

fn handle_plan(
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

fn handle_run(resolver: &ProfileResolver, args: CommandArgs, output: &OutputOptions) -> Result<()> {
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

#[derive(Debug)]
struct ReplicaIgnoreConfig {
    matcher: Gitignore,
    user_patterns: Vec<String>,
}

fn materialize_workspace_for_execution(
    plan: &ExecutionPlan,
    writer: &ArtifactWriter,
) -> Result<()> {
    let WorkspaceMode::Replica { source, copy } = &plan.mode else {
        return Ok(());
    };

    let ignore_config = load_replica_ignore_config(source)?;
    copy_workspace_with_default_exclusions(source, copy, &ignore_config)?;
    let mut excluded = REPLICA_DEFAULT_EXCLUSIONS
        .iter()
        .map(|value| value.to_string())
        .collect::<Vec<_>>();
    excluded.extend(ignore_config.user_patterns);
    append_audit_event(
        writer,
        AuditEventKind::ReplicaCreated {
            source: source.clone(),
            copy: copy.clone(),
            excluded,
        },
    )?;
    Ok(())
}

fn load_replica_ignore_config(source_root: &Path) -> Result<ReplicaIgnoreConfig> {
    let ignore_path = source_root.join(".clawcrateignore");
    let user_patterns = load_user_ignore_patterns(&ignore_path)?;

    let mut builder = GitignoreBuilder::new(source_root);
    if ignore_path.is_file() {
        if let Some(source) = builder.add(&ignore_path) {
            return Err(anyhow!(
                "failed to parse {}: {source}",
                ignore_path.display()
            ));
        }
    }

    let matcher = builder.build().map_err(|source| {
        anyhow!(
            "failed to build .clawcrateignore matcher from {}: {source}",
            ignore_path.display()
        )
    })?;

    Ok(ReplicaIgnoreConfig {
        matcher,
        user_patterns,
    })
}

fn load_user_ignore_patterns(ignore_path: &Path) -> Result<Vec<String>> {
    if !ignore_path.is_file() {
        return Ok(Vec::new());
    }

    let content = std::fs::read_to_string(ignore_path)
        .map_err(|source| anyhow!("failed to read {}: {source}", ignore_path.display()))?;
    Ok(content
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
        .map(ToString::to_string)
        .collect())
}

fn copy_workspace_with_default_exclusions(
    source: &Path,
    copy: &Path,
    ignore_config: &ReplicaIgnoreConfig,
) -> Result<()> {
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

    copy_directory_recursive(source, copy, source, ignore_config)?;
    Ok(())
}

fn copy_directory_recursive(
    source_dir: &Path,
    target_dir: &Path,
    source_root: &Path,
    ignore_config: &ReplicaIgnoreConfig,
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

        let target_path = target_dir.join(entry.file_name());
        let file_type = entry.file_type().map_err(|source_error| {
            anyhow!(
                "failed to inspect source entry type {}: {source_error}",
                source_path.display()
            )
        })?;
        if should_exclude_replica_path(
            relative_path,
            file_type.is_dir(),
            source_root,
            ignore_config,
        ) {
            continue;
        }

        if file_type.is_dir() {
            std::fs::create_dir_all(&target_path).map_err(|source_error| {
                anyhow!(
                    "failed to create replica directory {}: {source_error}",
                    target_path.display()
                )
            })?;
            copy_directory_recursive(&source_path, &target_path, source_root, ignore_config)?;
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

fn should_exclude_replica_path(
    relative_path: &Path,
    is_dir: bool,
    source_root: &Path,
    ignore_config: &ReplicaIgnoreConfig,
) -> bool {
    if should_exclude_default_replica_path(relative_path) {
        return true;
    }

    let full_path = source_root.join(relative_path);
    ignore_config
        .matcher
        .matched_path_or_any_parents(&full_path, is_dir)
        .is_ignore()
}

fn should_exclude_default_replica_path(relative_path: &Path) -> bool {
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

#[derive(Debug, Clone)]
struct ReplicaSyncChange {
    relative_path: PathBuf,
    kind: FsChangeKind,
}

fn maybe_sync_back_replica(
    plan: &ExecutionPlan,
    writer: &ArtifactWriter,
    args: &CommandArgs,
    fs_diff: &[FsChange],
    output: &OutputOptions,
) -> Result<()> {
    let WorkspaceMode::Replica { source, copy } = &plan.mode else {
        return Ok(());
    };

    let ignore_config = load_replica_ignore_config(source)?;
    let sync_changes = collect_syncable_replica_changes(copy, source, fs_diff, &ignore_config);
    let changes = sync_changes.len();

    if changes == 0 {
        append_audit_event(
            writer,
            AuditEventKind::ReplicaSyncBack {
                approved: false,
                changes: 0,
            },
        )?;
        return Ok(());
    }

    if args.json {
        verbose_log(
            output,
            1,
            format!(
                "replica sync-back skipped for execution {} because --json is enabled",
                plan.id
            ),
        );
        append_audit_event(
            writer,
            AuditEventKind::ReplicaSyncBack {
                approved: false,
                changes,
            },
        )?;
        return Ok(());
    }

    if !io::stdin().is_terminal() {
        println!(
            "Replica sync-back skipped (non-interactive stdin). Pending changes remain in {}",
            copy.display()
        );
        verbose_log(
            output,
            1,
            format!(
                "replica sync-back skipped for execution {} due to non-interactive stdin",
                plan.id
            ),
        );
        append_audit_event(
            writer,
            AuditEventKind::ReplicaSyncBack {
                approved: false,
                changes,
            },
        )?;
        return Ok(());
    }

    let approved = prompt_replica_sync_back(changes, source)?;
    if approved {
        apply_replica_sync_back(source, copy, &sync_changes)?;
        println!(
            "Replica sync-back complete: {} change(s) applied to {}",
            changes,
            source.display()
        );
        verbose_log(
            output,
            1,
            format!(
                "replica sync-back approved: {} change(s) applied for execution {}",
                changes, plan.id
            ),
        );
    } else {
        println!(
            "Replica sync-back skipped. Pending changes remain in {}",
            copy.display()
        );
        verbose_log(
            output,
            1,
            format!(
                "replica sync-back declined: {} pending change(s) for execution {}",
                changes, plan.id
            ),
        );
    }

    append_audit_event(
        writer,
        AuditEventKind::ReplicaSyncBack { approved, changes },
    )?;
    Ok(())
}

fn collect_syncable_replica_changes(
    copy_root: &Path,
    source_root: &Path,
    fs_diff: &[FsChange],
    ignore_config: &ReplicaIgnoreConfig,
) -> Vec<ReplicaSyncChange> {
    fs_diff
        .iter()
        .filter_map(|change| {
            let relative_path = change.path.strip_prefix(copy_root).ok()?;
            if relative_path.as_os_str().is_empty() {
                return None;
            }
            if should_exclude_replica_path(relative_path, false, source_root, ignore_config) {
                return None;
            }

            Some(ReplicaSyncChange {
                relative_path: relative_path.to_path_buf(),
                kind: change.kind,
            })
        })
        .collect()
}

fn prompt_replica_sync_back(changes: usize, source: &Path) -> Result<bool> {
    println!(
        "Replica run produced {changes} file change(s) eligible for sync-back to {}.",
        source.display()
    );
    print!("Sync back to the source workspace? [y/N]: ");
    io::stdout()
        .flush()
        .map_err(|source_error| anyhow!("failed to flush sync-back prompt: {source_error}"))?;

    let mut answer = String::new();
    io::stdin()
        .read_line(&mut answer)
        .map_err(|source_error| anyhow!("failed to read sync-back response: {source_error}"))?;
    let answer = answer.trim().to_ascii_lowercase();
    Ok(answer == "y" || answer == "yes")
}

fn apply_replica_sync_back(
    source_root: &Path,
    copy_root: &Path,
    changes: &[ReplicaSyncChange],
) -> Result<()> {
    for change in changes {
        let source_path = source_root.join(&change.relative_path);
        match change.kind {
            FsChangeKind::Created | FsChangeKind::Modified => {
                let replica_path = copy_root.join(&change.relative_path);
                if !replica_path.is_file() {
                    continue;
                }

                if let Some(parent) = source_path.parent() {
                    std::fs::create_dir_all(parent).map_err(|source_error| {
                        anyhow!(
                            "failed to prepare sync-back directory {}: {source_error}",
                            parent.display()
                        )
                    })?;
                }
                std::fs::copy(&replica_path, &source_path).map_err(|source_error| {
                    anyhow!(
                        "failed to sync-back file {} to {}: {source_error}",
                        replica_path.display(),
                        source_path.display()
                    )
                })?;
            }
            FsChangeKind::Deleted => {
                if source_path.exists() {
                    if source_path.is_dir() {
                        std::fs::remove_dir_all(&source_path).map_err(|source_error| {
                            anyhow!(
                                "failed to remove sync-back directory {}: {source_error}",
                                source_path.display()
                            )
                        })?;
                    } else {
                        std::fs::remove_file(&source_path).map_err(|source_error| {
                            anyhow!(
                                "failed to remove sync-back file {}: {source_error}",
                                source_path.display()
                            )
                        })?;
                    }
                }
            }
        }
    }

    Ok(())
}

fn runs_root() -> Result<PathBuf> {
    Ok(clawcrate_home_root()?.join("runs"))
}

fn clawcrate_home_root() -> Result<PathBuf> {
    if let Some(home) = std::env::var_os("HOME") {
        return Ok(PathBuf::from(home).join(".clawcrate"));
    }
    let cwd = std::env::current_dir()
        .map_err(|source| anyhow!("failed to resolve current dir: {source}"))?;
    Ok(cwd.join(".clawcrate"))
}

fn configure_optional_sqlite_index(output: &OutputOptions) -> Option<SqliteAuditIndex> {
    let explicit_path = std::env::var_os("CLAWCRATE_AUDIT_SQLITE_PATH").map(PathBuf::from);
    let enabled_by_flag = std::env::var("CLAWCRATE_AUDIT_SQLITE")
        .map(|value| matches!(value.as_str(), "1" | "true" | "TRUE" | "yes" | "YES"))
        .unwrap_or(false);
    let db_path = match explicit_path {
        Some(path) => path,
        None if enabled_by_flag => match clawcrate_home_root() {
            Ok(root) => root.join(DEFAULT_AUDIT_DB),
            Err(error) => {
                eprintln!("warning: failed to resolve default SQLite audit path: {error}");
                return None;
            }
        },
        None => return None,
    };

    match SqliteAuditIndex::open(&db_path) {
        Ok(index) => {
            verbose_log(
                output,
                1,
                format!(
                    "sqlite audit index enabled at {}",
                    index.db_path().display()
                ),
            );
            Some(index)
        }
        Err(error) => {
            eprintln!("warning: failed to initialize SQLite audit index: {error}");
            None
        }
    }
}

fn maybe_index_artifacts_in_sqlite(
    index: &mut Option<SqliteAuditIndex>,
    writer: &ArtifactWriter,
    output: &OutputOptions,
) {
    let Some(indexer) = index.as_mut() else {
        return;
    };

    match indexer.index_artifacts_dir(writer.artifacts_dir()) {
        Ok(indexed) => {
            verbose_log(
                output,
                2,
                format!(
                    "sqlite audit index updated: execution_id={}, events={}, has_result={}",
                    indexed.execution_id, indexed.event_count, indexed.has_result
                ),
            );
        }
        Err(error) => {
            eprintln!("warning: failed to index run artifacts in SQLite: {error}");
        }
    }
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

fn maybe_start_filtered_egress_proxy(
    net: &NetLevel,
    env: &mut Vec<(String, String)>,
) -> Result<Option<EgressProxyHandle>> {
    let NetLevel::Filtered { allowed_domains } = net else {
        return Ok(None);
    };

    let proxy = start_egress_proxy(EgressProxyConfig::from_allowed_domains(
        allowed_domains.clone(),
    ))
    .map_err(|source| anyhow!("failed to start filtered egress proxy: {source}"))?;
    upsert_env_vars(env, &proxy.proxy_env_vars());
    Ok(Some(proxy))
}

fn upsert_env_vars(env: &mut Vec<(String, String)>, values: &[(String, String)]) {
    for (key, value) in values {
        env.retain(|(existing_key, _)| existing_key != key);
        env.push((key.clone(), value.clone()));
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

fn enforce_out_of_profile_approval(
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

fn prompt_out_of_profile_approval(plan: &ExecutionPlan, requested: &[String]) -> Result<bool> {
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

fn detect_out_of_profile_requests(plan: &ExecutionPlan) -> Vec<String> {
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
            let hosts = extract_hosts_from_command(&plan.command);
            if hosts.is_empty() {
                return requested;
            }

            let denied = hosts
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

fn command_appears_to_need_network(command: &[String]) -> bool {
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

fn extract_hosts_from_command(command: &[String]) -> Vec<String> {
    let mut hosts = BTreeSet::new();
    for arg in command {
        if let Some(host) = extract_host_from_reference(arg) {
            hosts.insert(host);
        }
    }
    hosts.into_iter().collect()
}

fn extract_host_from_reference(value: &str) -> Option<String> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return None;
    }

    for prefix in ["https://", "http://", "ssh://"] {
        if let Some(rest) = trimmed.strip_prefix(prefix) {
            return split_host_port(rest).map(normalize_host);
        }
    }

    if let Some(rest) = trimmed.strip_prefix("git@") {
        let (host, _path) = rest.split_once(':')?;
        return Some(normalize_host(host));
    }

    None
}

fn split_host_port(input: &str) -> Option<&str> {
    let host_port = input.split('/').next().unwrap_or_default();
    if host_port.is_empty() {
        return None;
    }

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

fn domain_allowed(host: &str, allowed_domains: &[String]) -> bool {
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

fn normalize_host(input: &str) -> String {
    input
        .trim()
        .trim_start_matches('[')
        .trim_end_matches(']')
        .trim_end_matches('.')
        .to_ascii_lowercase()
}

fn command_basename(command: &str) -> String {
    Path::new(command)
        .file_name()
        .and_then(|value| value.to_str())
        .map_or_else(
            || command.to_ascii_lowercase(),
            |value| value.to_ascii_lowercase(),
        )
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
fn launch_and_capture(
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

fn handle_doctor(args: DoctorArgs, output: &OutputOptions) -> Result<()> {
    let capabilities = probe_system_capabilities()?;
    verbose_log(
        output,
        1,
        format!("doctor capabilities loaded for {:?}", capabilities.platform),
    );

    if args.json {
        println!("{}", serde_json::to_string_pretty(&capabilities)?);
    } else {
        print_human_doctor(&capabilities, output);
    }

    Ok(())
}

#[derive(Debug, Deserialize)]
struct ApiCommandRequest {
    profile: Option<String>,
    #[serde(default)]
    replica: bool,
    #[serde(default)]
    direct: bool,
    #[serde(default)]
    approve_out_of_profile: bool,
    command: Vec<String>,
}

#[derive(Debug)]
enum ApiRoute {
    Health,
    Doctor,
    Plan,
    Run,
}

#[derive(Debug, Serialize)]
struct ApiCommandError {
    error: String,
    exit_code: Option<i32>,
    stdout: String,
    stderr: String,
}

fn handle_api(args: ApiArgs, output: &OutputOptions) -> Result<()> {
    let token = resolve_api_token(&args)?;
    let server = Server::http(&args.bind)
        .map_err(|source| anyhow!("failed to bind local API on {}: {source}", args.bind))?;

    verbose_log(output, 1, format!("api server listening on {}", args.bind));
    println!("clawcrate api listening on http://{}", args.bind);

    for request in server.incoming_requests() {
        handle_api_request(request, &token, output);
    }

    Ok(())
}

fn resolve_api_token(args: &ApiArgs) -> Result<String> {
    let token = args
        .token
        .clone()
        .or_else(|| std::env::var("CLAWCRATE_API_TOKEN").ok())
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
        .ok_or_else(|| {
            anyhow!(
                "missing API token: provide --token or set CLAWCRATE_API_TOKEN for `clawcrate api`"
            )
        })?;
    Ok(token)
}

fn handle_api_request(mut request: Request, token: &str, output: &OutputOptions) {
    if !request_authorized(request.headers(), token) {
        respond_api_json(
            request,
            401,
            &serde_json::json!({ "error": "unauthorized" }),
        );
        return;
    }

    let Some(route) = resolve_api_route(request.method(), request.url()) else {
        respond_api_json(request, 404, &serde_json::json!({ "error": "not found" }));
        return;
    };

    match route {
        ApiRoute::Health => {
            respond_api_json(
                request,
                200,
                &serde_json::json!({
                    "status": "ok",
                    "version": env!("CARGO_PKG_VERSION")
                }),
            );
        }
        ApiRoute::Doctor => {
            let args = vec!["doctor".to_string(), "--json".to_string()];
            respond_api_with_cli_json(request, &args, output);
        }
        ApiRoute::Plan => {
            let payload = match parse_api_command_payload(&mut request) {
                Ok(payload) => payload,
                Err(error) => {
                    respond_api_json(request, 400, &serde_json::json!({ "error": error }));
                    return;
                }
            };
            let args = match build_api_cli_args("plan", &payload) {
                Ok(args) => args,
                Err(error) => {
                    respond_api_json(
                        request,
                        400,
                        &serde_json::json!({ "error": error.to_string() }),
                    );
                    return;
                }
            };
            respond_api_with_cli_json(request, &args, output);
        }
        ApiRoute::Run => {
            let payload = match parse_api_command_payload(&mut request) {
                Ok(payload) => payload,
                Err(error) => {
                    respond_api_json(request, 400, &serde_json::json!({ "error": error }));
                    return;
                }
            };
            let args = match build_api_cli_args("run", &payload) {
                Ok(args) => args,
                Err(error) => {
                    respond_api_json(
                        request,
                        400,
                        &serde_json::json!({ "error": error.to_string() }),
                    );
                    return;
                }
            };
            respond_api_with_cli_json(request, &args, output);
        }
    }
}

fn parse_api_command_payload(
    request: &mut Request,
) -> std::result::Result<ApiCommandRequest, String> {
    let mut body = String::new();
    request
        .as_reader()
        .read_to_string(&mut body)
        .map_err(|source| format!("failed to read request body: {source}"))?;
    serde_json::from_str::<ApiCommandRequest>(&body)
        .map_err(|source| format!("invalid JSON body: {source}"))
}

fn build_api_cli_args(action: &str, payload: &ApiCommandRequest) -> Result<Vec<String>> {
    if payload.command.is_empty() {
        return Err(anyhow!("`command` must contain at least one element"));
    }
    if payload.replica && payload.direct {
        return Err(anyhow!("`replica` and `direct` cannot be enabled together"));
    }

    let mut args = vec![action.to_string(), "--json".to_string()];
    if let Some(profile) = &payload.profile {
        args.push("--profile".to_string());
        args.push(profile.clone());
    }
    if payload.replica {
        args.push("--replica".to_string());
    }
    if payload.direct {
        args.push("--direct".to_string());
    }
    if action == "run" && payload.approve_out_of_profile {
        args.push("--approve-out-of-profile".to_string());
    }
    args.push("--".to_string());
    args.extend(payload.command.clone());

    Ok(args)
}

fn resolve_api_route(method: &Method, url: &str) -> Option<ApiRoute> {
    let path = url.split('?').next().unwrap_or(url);
    match (method, path) {
        (Method::Get, "/v1/health") => Some(ApiRoute::Health),
        (Method::Get, "/v1/doctor") => Some(ApiRoute::Doctor),
        (Method::Post, "/v1/plan") => Some(ApiRoute::Plan),
        (Method::Post, "/v1/run") => Some(ApiRoute::Run),
        _ => None,
    }
}

fn extract_bearer_token(headers: &[Header]) -> Option<String> {
    headers
        .iter()
        .find(|header| header.field.equiv("Authorization"))
        .and_then(|header| {
            let value = header.value.as_str();
            value
                .strip_prefix("Bearer ")
                .map(str::trim)
                .filter(|token| !token.is_empty())
        })
        .map(ToString::to_string)
}

fn request_authorized(headers: &[Header], expected_token: &str) -> bool {
    extract_bearer_token(headers)
        .as_deref()
        .map(|token| token == expected_token)
        .unwrap_or(false)
}

fn respond_api_with_cli_json(request: Request, args: &[String], output: &OutputOptions) {
    match execute_cli_json(args) {
        Ok(value) => {
            respond_api_json(request, 200, &value);
        }
        Err(error) => {
            verbose_log(
                output,
                1,
                format!(
                    "api delegated command failed: args={:?}, error={}",
                    args, error.error
                ),
            );
            respond_api_json(request, 422, &error);
        }
    }
}

fn execute_cli_json(args: &[String]) -> std::result::Result<serde_json::Value, ApiCommandError> {
    let exe = std::env::current_exe().map_err(|source| ApiCommandError {
        error: format!("failed to resolve clawcrate executable path: {source}"),
        exit_code: None,
        stdout: String::new(),
        stderr: String::new(),
    })?;

    let output = Command::new(exe)
        .args(args)
        .output()
        .map_err(|source| ApiCommandError {
            error: format!("failed to execute delegated clawcrate command: {source}"),
            exit_code: None,
            stdout: String::new(),
            stderr: String::new(),
        })?;

    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).to_string();
    if !output.status.success() {
        return Err(ApiCommandError {
            error: "delegated clawcrate command failed".to_string(),
            exit_code: output.status.code(),
            stdout,
            stderr,
        });
    }

    serde_json::from_str::<serde_json::Value>(&stdout).map_err(|source| ApiCommandError {
        error: format!("delegated clawcrate output was not valid JSON: {source}"),
        exit_code: output.status.code(),
        stdout,
        stderr,
    })
}

fn respond_api_json<T: Serialize>(request: Request, status_code: u16, payload: &T) {
    let body = match serde_json::to_string(payload) {
        Ok(value) => value,
        Err(source) => {
            format!(r#"{{"error":"failed to serialize API response","detail":"{source}"}}"#)
        }
    };
    let mut response = Response::from_string(body).with_status_code(StatusCode(status_code));
    if let Ok(header) = Header::from_bytes("Content-Type", "application/json; charset=utf-8") {
        response.add_header(header);
    }
    let _ = request.respond(response);
}

#[derive(Debug, Deserialize)]
struct PennyPromptBridgeRequest {
    action: String,
    profile: Option<String>,
    #[serde(default)]
    replica: bool,
    #[serde(default)]
    direct: bool,
    #[serde(default)]
    approve_out_of_profile: bool,
    #[serde(default)]
    command: Vec<String>,
}

#[derive(Debug, Serialize)]
struct PennyPromptBridgeResponse {
    ok: bool,
    action: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    data: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<PennyPromptBridgeError>,
}

#[derive(Debug, Serialize)]
struct PennyPromptBridgeError {
    message: String,
    exit_code: Option<i32>,
    stdout: String,
    stderr: String,
}

fn handle_bridge(args: BridgeArgs, _output: &OutputOptions) -> Result<()> {
    match args.target {
        BridgeTarget::Pennyprompt(config) => handle_pennyprompt_bridge(config),
    }
}

fn handle_pennyprompt_bridge(config: PennyPromptBridgeArgs) -> Result<()> {
    let mut input = String::new();
    io::stdin().read_to_string(&mut input).map_err(|source| {
        anyhow!("failed to read PennyPrompt bridge payload from stdin: {source}")
    })?;
    if input.trim().is_empty() {
        return Err(anyhow!(
            "missing PennyPrompt bridge payload: provide JSON on stdin"
        ));
    }

    let request: PennyPromptBridgeRequest = serde_json::from_str(&input)
        .map_err(|source| anyhow!("invalid PennyPrompt bridge payload JSON: {source}"))?;
    let action = normalize_action(&request.action);
    let delegated_args = build_pennyprompt_cli_args(&action, &request)?;

    let response = match execute_cli_json(&delegated_args) {
        Ok(data) => PennyPromptBridgeResponse {
            ok: true,
            action,
            data: Some(data),
            error: None,
        },
        Err(error) => PennyPromptBridgeResponse {
            ok: false,
            action,
            data: None,
            error: Some(PennyPromptBridgeError {
                message: error.error,
                exit_code: error.exit_code,
                stdout: error.stdout,
                stderr: error.stderr,
            }),
        },
    };

    if config.pretty {
        println!("{}", serde_json::to_string_pretty(&response)?);
    } else {
        println!("{}", serde_json::to_string(&response)?);
    }

    Ok(())
}

fn normalize_action(action: &str) -> String {
    action.trim().to_ascii_lowercase()
}

fn build_pennyprompt_cli_args(
    action: &str,
    request: &PennyPromptBridgeRequest,
) -> Result<Vec<String>> {
    match action {
        "doctor" => Ok(vec!["doctor".to_string(), "--json".to_string()]),
        "plan" | "run" => {
            let payload = ApiCommandRequest {
                profile: request.profile.clone(),
                replica: request.replica,
                direct: request.direct,
                approve_out_of_profile: request.approve_out_of_profile,
                command: request.command.clone(),
            };
            build_api_cli_args(action, &payload)
        }
        other => Err(anyhow!(
            "unsupported PennyPrompt action `{other}` (expected run, plan, or doctor)"
        )),
    }
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

fn print_human_doctor(capabilities: &SystemCapabilities, _output: &OutputOptions) {
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

fn print_human_run_summary(summary: &RunSummary, output: &OutputOptions) {
    let mut table = Table::new();
    table
        .set_header(vec!["Field", "Value"])
        .add_row(vec![
            Cell::new("Execution ID"),
            Cell::new(&summary.result.id),
        ])
        .add_row(vec![
            Cell::new("Status"),
            Cell::new(status_label(&summary.result.status, output.color)),
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

fn status_label(status: &Status, color: bool) -> String {
    match status {
        Status::Success => colorize("success", "32", color),
        Status::Failed => colorize("failed", "31", color),
        Status::Timeout => colorize("timeout", "33", color),
        Status::Killed => colorize("killed", "35", color),
        Status::SandboxError(message) => {
            if color {
                format!("\x1b[31msandbox_error: {message}\x1b[0m")
            } else {
                format!("sandbox_error: {message}")
            }
        }
    }
}

fn colorize(value: &str, code: &str, color: bool) -> String {
    if color {
        format!("\x1b[{code}m{value}\x1b[0m")
    } else {
        value.to_string()
    }
}

fn print_human_plan(plan: &ExecutionPlan, _output: &OutputOptions) {
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
                NetLevel::None => "none".to_string(),
                NetLevel::Open => "open".to_string(),
                NetLevel::Filtered {
                    ref allowed_domains,
                } => {
                    format!("filtered ({})", allowed_domains.len())
                }
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
        apply_replica_sync_back, build_api_cli_args, build_execution_plan,
        build_pennyprompt_cli_args, collect_syncable_replica_changes,
        command_appears_to_need_network, copy_workspace_with_default_exclusions,
        detect_out_of_profile_requests, doctor_rows, execution_status,
        execution_status_from_exit_status, extract_bearer_token, load_replica_ignore_config,
        resolve_api_route, resolve_execution_path, run_monitored_child, select_default_mode,
        should_exclude_default_replica_path, should_use_color, ApiCommandRequest, BridgeTarget,
        Cli, CommandArgs, Commands, PennyPromptBridgeRequest, ReplicaSyncChange, RunTermination,
    };
    use chrono::Utc;
    use clap::Parser;
    use clawcrate_capture::{FsChange, FsChangeKind};
    use clawcrate_profiles::ProfileResolver;
    use clawcrate_types::{
        Actor, DefaultMode, ExecutionPlan, NetLevel, Platform, ResolvedProfile, ResourceLimits,
        Status, SystemCapabilities, WorkspaceMode,
    };
    use tiny_http::{Header, Method};

    fn unique_tmp_dir(prefix: &str) -> PathBuf {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system time after unix epoch")
            .as_nanos();
        let dir = std::env::temp_dir().join(format!("{prefix}_{nanos}_{}", std::process::id()));
        fs::create_dir_all(&dir).expect("create temp test directory");
        dir
    }

    fn mock_plan(net: NetLevel, command: &[&str]) -> ExecutionPlan {
        let cwd = unique_tmp_dir("clawcrate_cli_approval_mock");
        ExecutionPlan {
            id: "exec-approval".to_string(),
            command: command.iter().map(|value| value.to_string()).collect(),
            cwd,
            profile: ResolvedProfile {
                name: "test".to_string(),
                fs_read: vec![PathBuf::from(".")],
                fs_write: vec![PathBuf::from("./target")],
                fs_deny: vec![],
                net,
                env_scrub: vec!["*_SECRET*".to_string()],
                env_passthrough: vec!["HOME".to_string(), "PATH".to_string()],
                resources: ResourceLimits {
                    max_cpu_seconds: 60,
                    max_memory_mb: 512,
                    max_open_files: 1024,
                    max_processes: 128,
                    max_output_bytes: 2 * 1024 * 1024,
                },
                default_mode: DefaultMode::Direct,
            },
            mode: WorkspaceMode::Direct,
            actor: Actor::Human,
            created_at: Utc::now(),
        }
    }

    #[test]
    fn parses_plan_command_with_profile_and_command() {
        let cli = Cli::parse_from([
            "clawcrate",
            "plan",
            "--profile",
            "build",
            "--",
            "cargo",
            "test",
        ]);

        match cli.command {
            Commands::Plan(args) => {
                assert_eq!(args.profile.as_deref(), Some("build"));
                assert_eq!(args.command, vec!["cargo".to_string(), "test".to_string()]);
                assert!(!args.json);
                assert!(!args.approve_out_of_profile);
            }
            _ => panic!("expected plan command"),
        }
    }

    #[test]
    fn parses_doctor_command_with_json() {
        let cli = Cli::parse_from(["clawcrate", "doctor", "--json"]);

        match cli.command {
            Commands::Doctor(args) => assert!(args.json),
            _ => panic!("expected doctor command"),
        }
    }

    #[test]
    fn parses_api_command_with_bind_and_token() {
        let cli = Cli::parse_from([
            "clawcrate",
            "api",
            "--bind",
            "127.0.0.1:9999",
            "--token",
            "super-secret",
        ]);

        match cli.command {
            Commands::Api(args) => {
                assert_eq!(args.bind, "127.0.0.1:9999");
                assert_eq!(args.token.as_deref(), Some("super-secret"));
            }
            _ => panic!("expected api command"),
        }
    }

    #[test]
    fn parses_bridge_pennyprompt_command() {
        let cli = Cli::parse_from(["clawcrate", "bridge", "pennyprompt", "--pretty"]);

        match cli.command {
            Commands::Bridge(args) => match args.target {
                BridgeTarget::Pennyprompt(config) => assert!(config.pretty),
            },
            _ => panic!("expected bridge command"),
        }
    }

    #[test]
    fn parses_global_verbose_and_no_color_flags() {
        let cli = Cli::parse_from([
            "clawcrate",
            "--verbose",
            "--no-color",
            "plan",
            "--",
            "echo",
            "hello",
        ]);
        assert_eq!(cli.global.verbose, 1);
        assert!(cli.global.no_color);
    }

    #[test]
    fn color_policy_respects_flag_env_and_tty() {
        assert!(!should_use_color(true, false, true));
        assert!(!should_use_color(false, true, true));
        assert!(!should_use_color(false, false, false));
        assert!(should_use_color(false, false, true));
    }

    #[test]
    fn resolve_api_route_matches_supported_paths() {
        assert!(matches!(
            resolve_api_route(&Method::Get, "/v1/health"),
            Some(super::ApiRoute::Health)
        ));
        assert!(matches!(
            resolve_api_route(&Method::Get, "/v1/doctor"),
            Some(super::ApiRoute::Doctor)
        ));
        assert!(matches!(
            resolve_api_route(&Method::Post, "/v1/plan"),
            Some(super::ApiRoute::Plan)
        ));
        assert!(matches!(
            resolve_api_route(&Method::Post, "/v1/run?verbose=1"),
            Some(super::ApiRoute::Run)
        ));
        assert!(resolve_api_route(&Method::Delete, "/v1/run").is_none());
    }

    #[test]
    fn extract_bearer_token_reads_authorization_header() {
        let header = Header::from_bytes("Authorization", "Bearer token-123")
            .expect("create authorization header");
        let missing = Header::from_bytes("X-Other", "value").expect("create random header");
        let headers = vec![missing, header];
        assert_eq!(extract_bearer_token(&headers).as_deref(), Some("token-123"));
    }

    #[test]
    fn build_api_cli_args_enforces_command_and_flags() {
        let valid = ApiCommandRequest {
            profile: Some("build".to_string()),
            replica: false,
            direct: false,
            approve_out_of_profile: true,
            command: vec!["cargo".to_string(), "test".to_string()],
        };
        let run_args = build_api_cli_args("run", &valid).expect("build args");
        assert_eq!(
            run_args,
            vec![
                "run",
                "--json",
                "--profile",
                "build",
                "--approve-out-of-profile",
                "--",
                "cargo",
                "test",
            ]
        );

        let invalid = ApiCommandRequest {
            profile: None,
            replica: true,
            direct: true,
            approve_out_of_profile: false,
            command: vec!["echo".to_string(), "hello".to_string()],
        };
        assert!(build_api_cli_args("plan", &invalid).is_err());
    }

    #[test]
    fn build_pennyprompt_cli_args_maps_supported_actions() {
        let doctor_request = PennyPromptBridgeRequest {
            action: "doctor".to_string(),
            profile: None,
            replica: false,
            direct: false,
            approve_out_of_profile: false,
            command: vec![],
        };
        assert_eq!(
            build_pennyprompt_cli_args("doctor", &doctor_request).expect("doctor args"),
            vec!["doctor", "--json"]
        );

        let run_request = PennyPromptBridgeRequest {
            action: "run".to_string(),
            profile: Some("build".to_string()),
            replica: false,
            direct: false,
            approve_out_of_profile: true,
            command: vec!["cargo".to_string(), "test".to_string()],
        };
        assert_eq!(
            build_pennyprompt_cli_args("run", &run_request).expect("run args"),
            vec![
                "run",
                "--json",
                "--profile",
                "build",
                "--approve-out-of-profile",
                "--",
                "cargo",
                "test",
            ]
        );
    }

    #[test]
    fn build_pennyprompt_cli_args_rejects_invalid_action() {
        let request = PennyPromptBridgeRequest {
            action: "unknown".to_string(),
            profile: None,
            replica: false,
            direct: false,
            approve_out_of_profile: false,
            command: vec!["echo".to_string()],
        };
        assert!(build_pennyprompt_cli_args("unknown", &request).is_err());
    }

    #[test]
    fn network_detector_identifies_obvious_network_commands() {
        assert!(command_appears_to_need_network(&[
            "curl".to_string(),
            "https://example.com".to_string()
        ]));
        assert!(command_appears_to_need_network(&[
            "git".to_string(),
            "clone".to_string(),
            "https://github.com/example/repo.git".to_string()
        ]));
        assert!(!command_appears_to_need_network(&[
            "echo".to_string(),
            "hello".to_string()
        ]));
    }

    #[test]
    fn approval_detection_flags_network_gap_for_none_profile() {
        let plan = mock_plan(
            NetLevel::None,
            &["curl", "https://registry.npmjs.org/some-package"],
        );
        let requests = detect_out_of_profile_requests(&plan);
        assert_eq!(requests.len(), 1);
        assert!(requests[0].contains("network mode is `none`"));
    }

    #[test]
    fn approval_detection_honors_filtered_allowlist_hosts() {
        let allowed_plan = mock_plan(
            NetLevel::Filtered {
                allowed_domains: vec!["registry.npmjs.org".to_string()],
            },
            &["curl", "https://registry.npmjs.org/some-package"],
        );
        assert!(detect_out_of_profile_requests(&allowed_plan).is_empty());

        let denied_plan = mock_plan(
            NetLevel::Filtered {
                allowed_domains: vec!["registry.npmjs.org".to_string()],
            },
            &["curl", "https://evil.example.com/payload"],
        );
        let requests = detect_out_of_profile_requests(&denied_plan);
        assert_eq!(requests.len(), 1);
        assert!(requests[0].contains("evil.example.com"));
    }

    #[test]
    fn profile_default_mode_is_overridden_by_flags() {
        let args = CommandArgs {
            profile: None,
            replica: true,
            direct: false,
            json: false,
            approve_out_of_profile: false,
            command: vec!["echo".to_string(), "hello".to_string()],
        };
        assert_eq!(
            select_default_mode(DefaultMode::Direct, &args),
            DefaultMode::Replica
        );

        let args = CommandArgs {
            profile: None,
            replica: false,
            direct: true,
            json: false,
            approve_out_of_profile: false,
            command: vec!["echo".to_string(), "hello".to_string()],
        };
        assert_eq!(
            select_default_mode(DefaultMode::Replica, &args),
            DefaultMode::Direct
        );

        let args = CommandArgs {
            profile: None,
            replica: false,
            direct: false,
            json: false,
            approve_out_of_profile: false,
            command: vec!["echo".to_string(), "hello".to_string()],
        };
        assert_eq!(
            select_default_mode(DefaultMode::Replica, &args),
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
            approve_out_of_profile: false,
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
            approve_out_of_profile: false,
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
    fn install_profile_can_be_forced_to_direct_mode() {
        let resolver = ProfileResolver::default();
        let cwd = unique_tmp_dir("clawcrate_cli_plan_install_direct");
        fs::write(
            cwd.join("package.json"),
            "{ \"name\": \"demo\", \"version\": \"0.1.0\" }",
        )
        .expect("write package json");

        let args = CommandArgs {
            profile: Some("install".to_string()),
            replica: false,
            direct: true,
            json: false,
            approve_out_of_profile: false,
            command: vec!["npm".to_string(), "install".to_string()],
        };

        let plan = build_execution_plan(&resolver, &cwd, &args).expect("build execution plan");
        assert!(matches!(plan.mode, WorkspaceMode::Direct));
        assert_eq!(plan.cwd, cwd);
    }

    #[test]
    fn build_profile_can_be_forced_to_replica_mode() {
        let resolver = ProfileResolver::default();
        let cwd = unique_tmp_dir("clawcrate_cli_plan_build_replica");
        fs::write(
            cwd.join("Cargo.toml"),
            "[package]\nname = \"demo\"\nversion = \"0.1.0\"\n",
        )
        .expect("write cargo toml");

        let args = CommandArgs {
            profile: Some("build".to_string()),
            replica: true,
            direct: false,
            json: false,
            approve_out_of_profile: false,
            command: vec!["cargo".to_string(), "check".to_string()],
        };

        let plan = build_execution_plan(&resolver, &cwd, &args).expect("build execution plan");
        match &plan.mode {
            WorkspaceMode::Replica { source, copy } => {
                assert_eq!(source, &cwd);
                assert!(copy.starts_with(Path::new(&std::env::temp_dir())));
                assert_eq!(plan.cwd, *copy);
            }
            WorkspaceMode::Direct => {
                panic!("--replica should override profile default direct mode")
            }
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
        assert!(should_exclude_default_replica_path(Path::new(".env")));
        assert!(should_exclude_default_replica_path(Path::new(".env.local")));
        assert!(should_exclude_default_replica_path(Path::new(
            "nested/.env.production"
        )));
        assert!(should_exclude_default_replica_path(Path::new(
            ".git/config"
        )));
        assert!(!should_exclude_default_replica_path(Path::new(".git/HEAD")));
        assert!(!should_exclude_default_replica_path(Path::new(
            "src/main.rs"
        )));
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
        let ignore_config = load_replica_ignore_config(&source).expect("load ignore config");
        copy_workspace_with_default_exclusions(&source, &replica, &ignore_config)
            .expect("copy workspace");

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
    fn replica_copy_applies_clawcrateignore_patterns() {
        let source = unique_tmp_dir("clawcrate_cli_replica_ignore_source");
        fs::create_dir_all(source.join("nested").join("tmp")).expect("create nested tmp");

        fs::write(source.join(".clawcrateignore"), "*.log\nnested/tmp/\n")
            .expect("write .clawcrateignore");
        fs::write(source.join("keep.txt"), "keep").expect("write keep file");
        fs::write(source.join("skip.log"), "skip").expect("write skipped log");
        fs::write(source.join("nested/tmp/skip.txt"), "skip").expect("write nested skip");
        fs::write(source.join("nested/keep.md"), "keep").expect("write nested keep");

        let replica_root = unique_tmp_dir("clawcrate_cli_replica_ignore_copy");
        let replica = replica_root.join("workspace");
        let ignore_config = load_replica_ignore_config(&source).expect("load ignore config");
        copy_workspace_with_default_exclusions(&source, &replica, &ignore_config)
            .expect("copy workspace with ignore rules");

        assert!(replica.join("keep.txt").exists());
        assert!(replica.join("nested/keep.md").exists());
        assert!(!replica.join("skip.log").exists());
        assert!(!replica.join("nested/tmp/skip.txt").exists());
    }

    #[test]
    fn collect_syncable_replica_changes_filters_exclusions_and_outside_paths() {
        let source = unique_tmp_dir("clawcrate_cli_sync_source");
        let copy = unique_tmp_dir("clawcrate_cli_sync_copy");
        fs::write(source.join(".clawcrateignore"), "*.log\n").expect("write .clawcrateignore");

        let fs_diff = vec![
            FsChange {
                path: copy.join("keep.txt"),
                kind: FsChangeKind::Created,
                size_bytes: Some(10),
            },
            FsChange {
                path: copy.join("drop.log"),
                kind: FsChangeKind::Created,
                size_bytes: Some(8),
            },
            FsChange {
                path: copy.join(".env"),
                kind: FsChangeKind::Created,
                size_bytes: Some(6),
            },
            FsChange {
                path: source.join("outside.txt"),
                kind: FsChangeKind::Created,
                size_bytes: Some(5),
            },
        ];

        let ignore_config = load_replica_ignore_config(&source).expect("load ignore config");
        let changes = collect_syncable_replica_changes(&copy, &source, &fs_diff, &ignore_config);

        assert_eq!(changes.len(), 1);
        assert_eq!(changes[0].relative_path, PathBuf::from("keep.txt"));
        assert_eq!(changes[0].kind, FsChangeKind::Created);
    }

    #[test]
    fn apply_replica_sync_back_applies_created_modified_and_deleted_files() {
        let source = unique_tmp_dir("clawcrate_cli_sync_apply_source");
        let copy = unique_tmp_dir("clawcrate_cli_sync_apply_copy");
        fs::create_dir_all(source.join("dir")).expect("create source dir");
        fs::create_dir_all(copy.join("dir")).expect("create copy dir");

        fs::write(source.join("dir/modified.txt"), "before").expect("write source modified before");
        fs::write(copy.join("dir/modified.txt"), "after").expect("write source modified after");

        fs::write(copy.join("new.txt"), "new").expect("write created file");
        fs::write(source.join("remove.txt"), "remove").expect("write deleted file");

        let changes = vec![
            ReplicaSyncChange {
                relative_path: PathBuf::from("dir/modified.txt"),
                kind: FsChangeKind::Modified,
            },
            ReplicaSyncChange {
                relative_path: PathBuf::from("new.txt"),
                kind: FsChangeKind::Created,
            },
            ReplicaSyncChange {
                relative_path: PathBuf::from("remove.txt"),
                kind: FsChangeKind::Deleted,
            },
        ];

        apply_replica_sync_back(&source, &copy, &changes).expect("apply sync-back");

        assert_eq!(
            fs::read_to_string(source.join("dir/modified.txt")).expect("read modified file"),
            "after"
        );
        assert_eq!(
            fs::read_to_string(source.join("new.txt")).expect("read new file"),
            "new"
        );
        assert!(!source.join("remove.txt").exists());
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
