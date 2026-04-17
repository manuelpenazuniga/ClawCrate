#![forbid(unsafe_code)]

use std::path::Path;

use anyhow::{anyhow, Result};
use chrono::Utc;
use clap::{ArgAction, Args, Parser, Subcommand};
use clawcrate_profiles::ProfileResolver;
#[cfg(target_os = "linux")]
use clawcrate_sandbox::linux_probe::probe_linux_capabilities;
#[cfg(target_os = "macos")]
use clawcrate_sandbox::macos_probe::probe_macos_capabilities;
use clawcrate_types::{
    Actor, DefaultMode, ExecutionPlan, Platform, SystemCapabilities, WorkspaceMode,
};
use comfy_table::{Cell, Table};
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
        Commands::Run(_) => Err(anyhow!(
            "`run` is not implemented yet. Use `clawcrate plan -- ...` for now."
        )),
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
    use std::time::{SystemTime, UNIX_EPOCH};

    use super::{build_execution_plan, doctor_rows, select_default_mode, CommandArgs};
    use clap::Parser;
    use clawcrate_profiles::ProfileResolver;
    use clawcrate_types::{DefaultMode, Platform, SystemCapabilities, WorkspaceMode};

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
}
