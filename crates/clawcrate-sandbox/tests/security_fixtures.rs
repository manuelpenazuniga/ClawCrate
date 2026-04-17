use std::io;
use std::path::PathBuf;
use std::sync::Arc;

use chrono::Utc;
#[cfg(target_os = "macos")]
use clawcrate_sandbox::darwin::DarwinSandbox;
use clawcrate_sandbox::linux::{
    EnforcementStep, LinuxEnforcer, LinuxSandbox, LinuxSandboxError, PreparedLinuxSandbox,
};
use clawcrate_types::{
    Actor, DefaultMode, ExecutionPlan, NetLevel, ResolvedProfile, ResourceLimits, WorkspaceMode,
};

#[derive(Debug)]
struct FixturePaths {
    workspace_root: PathBuf,
    workspace_env: PathBuf,
    workspace_public_file: PathBuf,
    home_root: PathBuf,
    home_ssh_key: PathBuf,
    home_aws_credentials: PathBuf,
}

fn fixture_paths() -> FixturePaths {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("fixtures")
        .join("security");
    FixturePaths {
        workspace_root: root.join("workspace"),
        workspace_env: root.join("workspace").join(".env"),
        workspace_public_file: root.join("workspace").join("public.txt"),
        home_root: root.join("home"),
        home_ssh_key: root.join("home").join(".ssh").join("id_rsa"),
        home_aws_credentials: root.join("home").join(".aws").join("credentials"),
    }
}

fn fixture_plan(paths: &FixturePaths, command: Vec<String>, net: NetLevel) -> ExecutionPlan {
    ExecutionPlan {
        id: "fixture-exec".to_string(),
        command,
        cwd: paths.workspace_root.clone(),
        profile: ResolvedProfile {
            name: "fixture-security".to_string(),
            fs_read: vec![paths.workspace_root.clone()],
            fs_write: vec![paths.workspace_root.clone()],
            fs_deny: vec![
                paths.workspace_env.to_string_lossy().to_string(),
                paths.home_ssh_key.to_string_lossy().to_string(),
                "**/*.pem".to_string(),
            ],
            net,
            env_scrub: vec!["*_SECRET*".to_string(), "*_TOKEN".to_string()],
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

#[derive(Debug)]
struct RejectRlimitEnforcer;

impl LinuxEnforcer for RejectRlimitEnforcer {
    fn apply_rlimits(
        &self,
        _limits: &ResourceLimits,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        Err(Box::new(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "fixture rejected process limits",
        )))
    }

    fn apply_landlock(
        &self,
        _prepared: &PreparedLinuxSandbox,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        Ok(())
    }

    fn apply_seccomp(
        &self,
        _prepared: &PreparedLinuxSandbox,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        Ok(())
    }
}

#[test]
fn security_fixture_files_exist_for_workspace_and_home() {
    let fixtures = fixture_paths();
    assert!(
        fixtures.workspace_env.exists(),
        "workspace .env fixture missing"
    );
    assert!(
        fixtures.workspace_public_file.exists(),
        "workspace public fixture missing"
    );
    assert!(
        fixtures.home_ssh_key.exists(),
        "home .ssh/id_rsa fixture missing"
    );
    assert!(
        fixtures.home_aws_credentials.exists(),
        "home .aws/credentials fixture missing"
    );
}

#[test]
fn fixture_env_scrubbing_removes_sensitive_variables() {
    let fixtures = fixture_paths();
    let plan = fixture_plan(
        &fixtures,
        vec!["/bin/echo".to_string(), "ok".to_string()],
        NetLevel::None,
    );
    let sandbox = LinuxSandbox::new();
    let prepared = sandbox.prepare_with_env(
        &plan,
        vec![
            (
                "HOME".to_string(),
                fixtures.home_root.to_string_lossy().to_string(),
            ),
            ("PATH".to_string(), "/usr/bin:/bin".to_string()),
            ("CI_SECRET_KEY".to_string(), "should-be-removed".to_string()),
            ("API_TOKEN".to_string(), "remove-me".to_string()),
            ("PUBLIC_VALUE".to_string(), "keep-me".to_string()),
        ],
    );

    assert!(prepared
        .scrubbed_keys
        .contains(&"CI_SECRET_KEY".to_string()));
    assert!(prepared.scrubbed_keys.contains(&"API_TOKEN".to_string()));
    assert!(prepared.scrubbed_env.iter().any(|(name, _)| name == "HOME"));
    assert!(prepared.scrubbed_env.iter().any(|(name, _)| name == "PATH"));
    assert!(prepared
        .scrubbed_env
        .iter()
        .any(|(name, value)| name == "PUBLIC_VALUE" && value == "keep-me"));
}

#[test]
fn fixture_process_restrictions_fail_early_when_rlimit_step_rejects() {
    let fixtures = fixture_paths();
    let plan = fixture_plan(
        &fixtures,
        vec!["/bin/echo".to_string(), "ok".to_string()],
        NetLevel::None,
    );
    let sandbox = LinuxSandbox::new_with_enforcer(Arc::new(RejectRlimitEnforcer));
    let prepared = sandbox.prepare_with_env(
        &plan,
        vec![
            (
                "HOME".to_string(),
                fixtures.home_root.to_string_lossy().to_string(),
            ),
            ("PATH".to_string(), "/usr/bin:/bin".to_string()),
        ],
    );

    match sandbox.launch(&prepared) {
        Ok(_) => panic!("launch should fail when rlimit enforcement rejects"),
        Err(LinuxSandboxError::Enforcement { step, .. }) => {
            assert_eq!(step, EnforcementStep::Rlimits)
        }
        Err(other) => panic!("unexpected launch error: {other}"),
    }
}

#[test]
fn fixture_network_policy_is_materialized_in_linux_prepare() {
    let fixtures = fixture_paths();
    let sandbox = LinuxSandbox::new();

    let plan_none = fixture_plan(
        &fixtures,
        vec!["/bin/echo".to_string(), "none".to_string()],
        NetLevel::None,
    );
    let prepared_none = sandbox.prepare_with_env(
        &plan_none,
        vec![
            (
                "HOME".to_string(),
                fixtures.home_root.to_string_lossy().to_string(),
            ),
            ("PATH".to_string(), "/usr/bin:/bin".to_string()),
        ],
    );
    assert_eq!(prepared_none.net, NetLevel::None);

    let plan_open = fixture_plan(
        &fixtures,
        vec!["/bin/echo".to_string(), "open".to_string()],
        NetLevel::Open,
    );
    let prepared_open = sandbox.prepare_with_env(
        &plan_open,
        vec![
            (
                "HOME".to_string(),
                fixtures.home_root.to_string_lossy().to_string(),
            ),
            ("PATH".to_string(), "/usr/bin:/bin".to_string()),
        ],
    );
    assert_eq!(prepared_open.net, NetLevel::Open);
}

#[cfg(target_os = "macos")]
#[test]
fn fixture_sbpl_blocks_secret_reads_and_reflects_network_policy() {
    let fixtures = fixture_paths();
    let sandbox = DarwinSandbox::new();

    let plan_none = fixture_plan(
        &fixtures,
        vec!["/bin/echo".to_string(), "ok".to_string()],
        NetLevel::None,
    );
    let prepared_none = sandbox.prepare_with_env(
        &plan_none,
        vec![
            (
                "HOME".to_string(),
                fixtures.home_root.to_string_lossy().to_string(),
            ),
            ("PATH".to_string(), "/usr/bin:/bin".to_string()),
        ],
    );

    assert!(prepared_none.sbpl_profile.contains("(deny network*)"));
    assert!(prepared_none.sbpl_profile.contains(".ssh"));
    assert!(prepared_none.sbpl_profile.contains("id_rsa"));
    assert!(prepared_none.sbpl_profile.contains(".env"));

    let plan_open = fixture_plan(
        &fixtures,
        vec!["/bin/echo".to_string(), "ok".to_string()],
        NetLevel::Open,
    );
    let prepared_open = sandbox.prepare_with_env(
        &plan_open,
        vec![
            (
                "HOME".to_string(),
                fixtures.home_root.to_string_lossy().to_string(),
            ),
            ("PATH".to_string(), "/usr/bin:/bin".to_string()),
        ],
    );
    assert!(prepared_open.sbpl_profile.contains("(allow network*)"));
    assert!(!prepared_open.sbpl_profile.contains("(deny network*)"));
}
