//! output module (extracted from main.rs; see #277).

use std::io::{self, IsTerminal};

use crate::{cli::*, run::*};
use clawcrate_types::{ExecutionPlan, NetLevel, Status, WorkspaceMode};
use comfy_table::{Cell, Table};

#[derive(Debug, Clone, Copy)]
pub(crate) struct OutputOptions {
    pub(crate) verbose: u8,
    pub(crate) color: bool,
}

impl OutputOptions {
    pub(crate) fn from_global(global: &GlobalArgs) -> Self {
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

pub(crate) fn should_use_color(
    no_color_flag: bool,
    no_color_env_set: bool,
    stdout_is_terminal: bool,
) -> bool {
    !no_color_flag && !no_color_env_set && stdout_is_terminal
}

pub(crate) fn verbose_log(output: &OutputOptions, level: u8, message: impl AsRef<str>) {
    if output.verbose >= level {
        eprintln!("[verbose] {}", message.as_ref());
    }
}

pub(crate) fn print_cli_error(error: &anyhow::Error, verbose: u8) {
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

pub(crate) fn error_hint(error: &anyhow::Error) -> Option<&'static str> {
    let message = error.to_string();
    if message.contains("failed to resolve profile") {
        return Some(
            "use `--profile <safe|build|install|open|mcp-readonly|mcp-server>` or a valid profile YAML path.",
        );
    }
    if message.contains("unsupported platform") {
        return Some("`run` and `doctor` are supported on Linux and macOS only.");
    }
    if message.contains("failed to get current dir") {
        return Some("run clawcrate from an existing and accessible working directory.");
    }
    None
}

pub(crate) fn print_human_run_summary(summary: &RunSummary, output: &OutputOptions) {
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

pub(crate) fn status_label(status: &Status, color: bool) -> String {
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

pub(crate) fn colorize(value: &str, code: &str, color: bool) -> String {
    if color {
        format!("\x1b[{code}m{value}\x1b[0m")
    } else {
        value.to_string()
    }
}

pub(crate) fn print_human_plan(plan: &ExecutionPlan, _output: &OutputOptions) {
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
