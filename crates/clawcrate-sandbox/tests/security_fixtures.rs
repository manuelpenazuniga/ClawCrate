#[cfg(target_os = "linux")]
use std::fs;
use std::io;
#[cfg(target_os = "linux")]
use std::path::Path;
use std::path::PathBuf;
use std::sync::Arc;
#[cfg(target_os = "linux")]
use std::time::{SystemTime, UNIX_EPOCH};

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

#[cfg(target_os = "linux")]
fn unique_tmp_path(prefix: &str) -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system time after unix epoch")
        .as_nanos();
    std::env::temp_dir().join(format!("{prefix}_{nanos}_{}", std::process::id()))
}

#[cfg(target_os = "linux")]
fn python3_path_for_linux_fixtures() -> Option<&'static str> {
    ["/usr/bin/python3", "/bin/python3"]
        .into_iter()
        .find(|candidate| Path::new(candidate).exists())
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

#[cfg(target_os = "linux")]
#[test]
fn fixture_linux_landlock_denies_write_outside_allowed_workspace() {
    let fixtures = fixture_paths();
    let workspace = unique_tmp_path("clawcrate_fixture_landlock_workspace");
    fs::create_dir_all(&workspace).expect("create temporary workspace");
    let denied_path = unique_tmp_path("clawcrate_fixture_landlock_denied");

    let mut plan = fixture_plan(
        &fixtures,
        vec![
            "/bin/sh".to_string(),
            "-c".to_string(),
            format!(
                "printf 'ok' > allowed.txt && printf 'denied' > {}",
                denied_path.display()
            ),
        ],
        NetLevel::None,
    );
    plan.cwd = workspace.clone();
    plan.profile.fs_read = vec![workspace.clone()];
    plan.profile.fs_write = vec![workspace.clone()];

    let sandbox = LinuxSandbox::new();
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

    let output = sandbox
        .launch(&prepared)
        .expect("launch fixture command")
        .wait_with_output()
        .expect("wait for fixture command");

    assert!(
        !output.status.success(),
        "writing outside allowed workspace should be denied"
    );
    let allowed = fs::read_to_string(workspace.join("allowed.txt")).expect("read allowed output");
    assert_eq!(allowed, "ok");
    assert!(!denied_path.exists(), "denied path should not be created");
}

#[cfg(target_os = "linux")]
#[test]
fn fixture_linux_seccomp_denies_socket_when_network_is_none() {
    let Some(python3) = python3_path_for_linux_fixtures() else {
        return;
    };

    let fixtures = fixture_paths();
    let workspace = unique_tmp_path("clawcrate_fixture_seccomp_workspace");
    fs::create_dir_all(&workspace).expect("create temporary workspace");

    let mut plan = fixture_plan(
        &fixtures,
        vec![
            python3.to_string(),
            "-c".to_string(),
            "import socket; socket.socket()".to_string(),
        ],
        NetLevel::None,
    );
    plan.cwd = workspace.clone();
    plan.profile.fs_read = vec![workspace.clone()];
    plan.profile.fs_write = vec![workspace.clone()];

    let sandbox = LinuxSandbox::new();
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

    let output = sandbox
        .launch(&prepared)
        .expect("launch fixture command")
        .wait_with_output()
        .expect("wait for fixture command");

    assert!(
        !output.status.success(),
        "socket syscall should be denied when network level is none"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("Operation not permitted") || stderr.contains("PermissionError"),
        "unexpected seccomp deny stderr: {stderr}"
    );
}

#[cfg(target_os = "linux")]
#[test]
fn fixture_linux_rlimit_file_size_denies_large_file_writes() {
    let fixtures = fixture_paths();
    let workspace = unique_tmp_path("clawcrate_fixture_rlimit_workspace");
    fs::create_dir_all(&workspace).expect("create temporary workspace");

    let mut plan = fixture_plan(
        &fixtures,
        vec![
            "/bin/sh".to_string(),
            "-c".to_string(),
            "dd if=/dev/zero of=too-big.bin bs=512 count=8".to_string(),
        ],
        NetLevel::None,
    );
    plan.cwd = workspace.clone();
    plan.profile.fs_read = vec![workspace.clone()];
    plan.profile.fs_write = vec![workspace.clone()];
    plan.profile.resources.max_output_bytes = 1024;

    let sandbox = LinuxSandbox::new();
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

    let output = sandbox
        .launch(&prepared)
        .expect("launch fixture command")
        .wait_with_output()
        .expect("wait for fixture command");

    assert!(
        !output.status.success(),
        "large writes should be denied by RLIMIT_FSIZE"
    );
    let written_size = fs::metadata(workspace.join("too-big.bin"))
        .map(|metadata| metadata.len())
        .unwrap_or(0);
    assert!(
        written_size <= 1024,
        "file should not exceed RLIMIT_FSIZE; got {written_size} bytes"
    );
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
