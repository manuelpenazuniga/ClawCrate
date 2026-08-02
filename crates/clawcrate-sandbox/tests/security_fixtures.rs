#[cfg(any(target_os = "linux", target_os = "macos"))]
#[cfg(target_os = "linux")]
use nix::libc;
use std::fs;
use std::io;
#[cfg(target_os = "linux")]
use std::os::unix::fs::symlink;
#[cfg(any(target_os = "linux", target_os = "macos"))]
use std::path::Path;
use std::path::PathBuf;
use std::process::Command;
use std::sync::Arc;
#[cfg(any(target_os = "linux", target_os = "macos"))]
use std::time::{SystemTime, UNIX_EPOCH};

use chrono::Utc;
#[cfg(target_os = "macos")]
use clawcrate_sandbox::darwin::DarwinSandbox;
#[cfg(target_os = "linux")]
use clawcrate_sandbox::linux::KernelEnforcer;
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
        read_isolation_enforced: None,
    }
}

#[derive(Debug)]
struct RejectRlimitEnforcer;

impl LinuxEnforcer for RejectRlimitEnforcer {
    fn apply_rlimits(
        &self,
        _command: &mut Command,
        _limits: &ResourceLimits,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        Err(Box::new(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "fixture rejected process limits",
        )))
    }

    fn apply_landlock(
        &self,
        _command: &mut Command,
        _prepared: &PreparedLinuxSandbox,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        Ok(())
    }

    fn apply_seccomp(
        &self,
        _command: &mut Command,
        _prepared: &PreparedLinuxSandbox,
    ) -> Result<Option<std::os::fd::OwnedFd>, Box<dyn std::error::Error + Send + Sync>> {
        Ok(None)
    }
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn unique_tmp_path(prefix: &str) -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system time after unix epoch")
        .as_nanos();
    std::env::temp_dir().join(format!("{prefix}_{nanos}_{}", std::process::id()))
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
#[derive(Debug)]
struct TempPathGuard {
    path: PathBuf,
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
impl TempPathGuard {
    fn new(prefix: &str) -> Self {
        Self {
            path: unique_tmp_path(prefix),
        }
    }

    fn path(&self) -> &Path {
        &self.path
    }
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
impl Drop for TempPathGuard {
    fn drop(&mut self) {
        match fs::symlink_metadata(&self.path) {
            Ok(metadata) => {
                let file_type = metadata.file_type();
                if file_type.is_dir() {
                    let _ = fs::remove_dir_all(&self.path);
                } else {
                    let _ = fs::remove_file(&self.path);
                }
            }
            Err(error) => {
                if error.kind() != io::ErrorKind::NotFound {
                    let _ = error;
                }
            }
        }
    }
}

#[cfg(target_os = "linux")]
fn python3_path_for_linux_fixtures() -> Option<&'static str> {
    ["/usr/bin/python3", "/bin/python3"]
        .into_iter()
        .find(|candidate| Path::new(candidate).exists())
}

#[cfg(target_os = "linux")]
fn require_python3_for_linux_fixtures() -> &'static str {
    python3_path_for_linux_fixtures().unwrap_or_else(|| {
        panic!("python3 is required for Linux seccomp security fixture tests on this runner")
    })
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
    let workspace = TempPathGuard::new("clawcrate_fixture_landlock_workspace");
    fs::create_dir_all(workspace.path()).expect("create temporary workspace");
    let denied_path = TempPathGuard::new("clawcrate_fixture_landlock_denied");

    let mut plan = fixture_plan(
        &fixtures,
        vec![
            "/bin/sh".to_string(),
            "-c".to_string(),
            format!(
                "printf 'ok' > allowed.txt && printf 'denied' > {}",
                denied_path.path().display()
            ),
        ],
        NetLevel::None,
    );
    plan.cwd = workspace.path().to_path_buf();
    plan.profile.fs_read = vec![workspace.path().to_path_buf()];
    plan.profile.fs_write = vec![workspace.path().to_path_buf()];

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
    let allowed =
        fs::read_to_string(workspace.path().join("allowed.txt")).expect("read allowed output");
    assert_eq!(allowed, "ok");
    assert!(
        !denied_path.path().exists(),
        "denied path should not be created"
    );
}

/// The Linux read-isolation landmark: a sandboxed process must not be able to
/// read secrets outside its workspace (mirrors the macOS Seatbelt fixture),
/// while workspace reads and the toolchain keep working.
#[cfg(target_os = "linux")]
#[test]
fn fixture_linux_landlock_denies_read_outside_allowed_workspace() {
    let fixtures = fixture_paths();
    let workspace = TempPathGuard::new("clawcrate_fixture_landlock_read_workspace");
    fs::create_dir_all(workspace.path()).expect("create temporary workspace");
    // Trailing newline matters: the shell's `read` builtin returns non-zero when
    // it reaches EOF without one, which would short-circuit the `&&` chain even
    // though the read itself succeeded.
    fs::write(workspace.path().join("public.txt"), "workspace-visible\n")
        .expect("write workspace file");

    let mut plan = fixture_plan(
        &fixtures,
        vec![
            "/bin/sh".to_string(),
            "-c".to_string(),
            format!(
                // Uses only shell builtins and redirections: RLIMIT_NPROC is a
                // per-UID limit, so forking an external binary is unreliable on
                // a busy CI runner. Reading the workspace file must succeed;
                // opening the secret outside the workspace must be denied.
                "read line < public.txt && printf 'workspace=%s;' \"$line\"; \
                 if read secret < {}; then printf 'leaked'; else printf 'denied'; fi",
                fixtures.home_ssh_key.display()
            ),
        ],
        NetLevel::None,
    );
    plan.cwd = workspace.path().to_path_buf();
    plan.profile.fs_read = vec![workspace.path().to_path_buf()];
    plan.profile.fs_write = vec![workspace.path().to_path_buf()];

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

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    assert!(
        output.status.success(),
        "fixture shell should run to completion\nstdout: {stdout}\nstderr: {stderr}"
    );
    assert!(
        stdout.contains("workspace=workspace-visible;"),
        "workspace file must stay readable inside the sandbox\nstdout: {stdout}\nstderr: {stderr}"
    );
    assert!(
        stdout.contains("denied"),
        "reading the out-of-workspace secret must be denied\nstdout: {stdout}\nstderr: {stderr}"
    );
    assert!(
        !stdout.contains("leaked"),
        "sandboxed process must not be able to read the out-of-workspace secret\nstdout: {stdout}"
    );
}

/// Regression guard: a profile read path that does not exist must not widen the
/// grant to its nearest existing ancestor. The built-in `build` profile lists
/// `~/.cargo` and `~/.rustup`, so on a machine without them an ancestor-walking
/// anchor would grant read access to the whole home directory.
#[cfg(target_os = "linux")]
#[test]
fn fixture_linux_landlock_missing_read_path_does_not_grant_home() {
    let fixtures = fixture_paths();
    let workspace = TempPathGuard::new("clawcrate_fixture_landlock_missing_read_workspace");
    fs::create_dir_all(workspace.path()).expect("create temporary workspace");
    fs::write(workspace.path().join("public.txt"), "workspace-visible\n")
        .expect("write workspace file");

    let mut plan = fixture_plan(
        &fixtures,
        vec![
            "/bin/sh".to_string(),
            "-c".to_string(),
            format!(
                "if read secret < {}; then printf 'leaked'; else printf 'denied'; fi",
                fixtures.home_ssh_key.display()
            ),
        ],
        NetLevel::None,
    );
    plan.cwd = workspace.path().to_path_buf();
    // A read path nested under the simulated home that does not exist: walking
    // up would land on the home directory holding `.ssh/id_rsa`.
    plan.profile.fs_read = vec![
        workspace.path().to_path_buf(),
        fixtures
            .home_root
            .join("missing-dir")
            .join("missing-child.txt"),
    ];
    plan.profile.fs_write = vec![workspace.path().to_path_buf()];

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

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    assert!(
        stdout.contains("denied"),
        "a missing read path must not widen the grant to its ancestor\nstdout: {stdout}\nstderr: {stderr}"
    );
    assert!(
        !stdout.contains("leaked"),
        "sandboxed process read a secret through an ancestor-widened grant\nstdout: {stdout}"
    );
}

#[cfg(target_os = "linux")]
#[test]
fn temp_path_guard_removes_symlink_without_deleting_target_directory() {
    let target_dir = TempPathGuard::new("clawcrate_fixture_temp_guard_target");
    fs::create_dir_all(target_dir.path()).expect("create target directory");

    let symlink_guard = TempPathGuard::new("clawcrate_fixture_temp_guard_symlink");
    let symlink_path = symlink_guard.path().to_path_buf();
    symlink(target_dir.path(), &symlink_path).expect("create symlink path");
    assert!(
        fs::symlink_metadata(&symlink_path)
            .expect("symlink metadata")
            .file_type()
            .is_symlink(),
        "test setup should create symlink"
    );

    drop(symlink_guard);

    assert!(
        fs::symlink_metadata(&symlink_path).is_err(),
        "symlink path should be removed by guard drop"
    );
    assert!(
        target_dir.path().is_dir(),
        "guard cleanup should not delete symlink target"
    );
}

#[cfg(target_os = "linux")]
#[test]
fn fixture_linux_seccomp_denies_socket_when_network_is_none() {
    let python3 = require_python3_for_linux_fixtures();

    let fixtures = fixture_paths();
    let workspace = TempPathGuard::new("clawcrate_fixture_seccomp_workspace");
    fs::create_dir_all(workspace.path()).expect("create temporary workspace");

    let mut plan = fixture_plan(
        &fixtures,
        vec![
            python3.to_string(),
            "-c".to_string(),
            "import socket; socket.socket()".to_string(),
        ],
        NetLevel::None,
    );
    plan.cwd = workspace.path().to_path_buf();
    plan.profile.fs_read = vec![workspace.path().to_path_buf()];
    plan.profile.fs_write = vec![workspace.path().to_path_buf()];

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

    let child = sandbox.launch(&prepared).expect("launch fixture command");
    // Taken before `wait_with_output` consumes the child; the supervisor is
    // joined during that call, so draining afterwards sees a complete record.
    let denial_log = child.denied_syscall_log();
    let output = child.wait_with_output().expect("wait for fixture command");

    assert!(
        !output.status.success(),
        "socket syscall should be denied when network level is none"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("Operation not permitted") || stderr.contains("PermissionError"),
        "unexpected seccomp deny stderr: {stderr}"
    );

    // Enforcement alone is not the whole job: the refusal has to be reportable,
    // or `audit.ndjson` cannot say what the sandbox stopped.
    let log = denial_log.expect("seccomp notification supervisor should be running");
    let (denials, dropped) = log.drain();
    assert_eq!(dropped, 0, "nothing should have been dropped");
    assert!(
        denials
            .iter()
            .any(|denial| denial.nr as i64 == libc::SYS_socket),
        "the refused socket syscall should have been recorded, got {denials:?}"
    );
}

#[cfg(target_os = "linux")]
/// Applies the real syscall filter while skipping Landlock.
///
/// Seccomp user notification needs only Linux 5.0, but Landlock needs a kernel
/// built with it, and ClawCrate fails closed when it is missing. Isolating the
/// two lets the notification path be tested wherever it actually works instead
/// of only where both happen to be present.
struct SeccompOnlyEnforcer;

#[cfg(target_os = "linux")]
impl LinuxEnforcer for SeccompOnlyEnforcer {
    fn apply_rlimits(
        &self,
        command: &mut Command,
        limits: &clawcrate_types::ResourceLimits,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        KernelEnforcer.apply_rlimits(command, limits)
    }

    fn apply_landlock(
        &self,
        _command: &mut Command,
        _prepared: &PreparedLinuxSandbox,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        Ok(())
    }

    fn apply_seccomp(
        &self,
        command: &mut Command,
        prepared: &PreparedLinuxSandbox,
    ) -> Result<Option<std::os::fd::OwnedFd>, Box<dyn std::error::Error + Send + Sync>> {
        KernelEnforcer.apply_seccomp(command, prepared)
    }
}

#[cfg(target_os = "linux")]
#[test]
fn fixture_linux_seccomp_records_the_syscall_it_denied() {
    // The point of the exercise: the child must be refused exactly as before,
    // AND the refusal must be recoverable, or `audit.ndjson` cannot report it.
    let workspace = TempPathGuard::new("clawcrate_fixture_notify_workspace");
    fs::create_dir_all(workspace.path()).expect("create temporary workspace");
    let fixtures = fixture_paths();

    let mut plan = fixture_plan(
        &fixtures,
        vec![
            "/bin/sh".to_string(),
            "-c".to_string(),
            // `chroot(2)` is not in the allowlist under any profile, and the
            // shell reports the errno without needing an interpreter present.
            "chroot / 2>&1; echo done".to_string(),
        ],
        NetLevel::None,
    );
    plan.cwd = workspace.path().to_path_buf();
    plan.profile.fs_read = vec![workspace.path().to_path_buf()];
    plan.profile.fs_write = vec![workspace.path().to_path_buf()];

    let sandbox = LinuxSandbox::new_with_enforcer(Arc::new(SeccompOnlyEnforcer));
    let prepared = sandbox.prepare_with_env(
        &plan,
        vec![
            (
                "HOME".to_string(),
                fixtures.home_root.to_string_lossy().to_string(),
            ),
            (
                "PATH".to_string(),
                "/usr/sbin:/usr/bin:/sbin:/bin".to_string(),
            ),
        ],
    );

    let child = sandbox.launch(&prepared).expect("launch fixture command");
    let denial_log = child
        .denied_syscall_log()
        .expect("the notification supervisor should be running");
    let output = child.wait_with_output().expect("wait for fixture command");

    let (denials, dropped) = denial_log.drain();
    assert_eq!(dropped, 0, "nothing should have been dropped");
    assert!(
        !denials.is_empty(),
        "a sandboxed shell attempting chroot must leave a record; stdout={:?} stderr={:?}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        denials
            .iter()
            .any(|denial| denial.nr as i64 == libc::SYS_chroot),
        "the refused chroot should be among the records, got {denials:?}"
    );
    // The child keeps running afterwards: the supervisor returns an error, it
    // does not kill. A denial that terminated the process would be a different
    // product.
    assert!(
        String::from_utf8_lossy(&output.stdout).contains("done"),
        "the shell should survive a denied syscall"
    );
}

#[cfg(target_os = "linux")]
#[test]
fn fixture_linux_rlimit_file_size_denies_large_file_writes() {
    let fixtures = fixture_paths();
    let workspace = TempPathGuard::new("clawcrate_fixture_rlimit_workspace");
    fs::create_dir_all(workspace.path()).expect("create temporary workspace");

    let mut plan = fixture_plan(
        &fixtures,
        vec![
            "/bin/sh".to_string(),
            "-c".to_string(),
            "dd if=/dev/zero of=too-big.bin bs=512 count=8".to_string(),
        ],
        NetLevel::None,
    );
    plan.cwd = workspace.path().to_path_buf();
    plan.profile.fs_read = vec![workspace.path().to_path_buf()];
    plan.profile.fs_write = vec![workspace.path().to_path_buf()];
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
    let written_size = fs::metadata(workspace.path().join("too-big.bin"))
        .map(|metadata| metadata.len())
        .unwrap_or(0);
    assert!(
        written_size <= 1024,
        "file should not exceed RLIMIT_FSIZE; got {written_size} bytes"
    );
}

/// The macOS counterpart of the Linux read-isolation landmark, and the coverage
/// that was missing: it launches a real process instead of only inspecting the
/// generated profile. A sandboxed command must be able to read its own
/// workspace while an out-of-workspace secret stays denied.
///
/// Asserting the successful read matters as much as the denial. Seatbelt matches
/// `subpath` textually, so a profile path that resolves to `<cwd>/.` grants
/// nothing and the sandbox silently becomes unusable — a failure no
/// SBPL-string assertion can see.
#[cfg(target_os = "macos")]
#[test]
fn fixture_macos_seatbelt_reads_workspace_and_denies_outside_secret() {
    let fixtures = fixture_paths();
    let workspace = TempPathGuard::new("clawcrate_fixture_seatbelt_read_workspace");
    fs::create_dir_all(workspace.path()).expect("create temporary workspace");
    fs::write(workspace.path().join("public.txt"), "workspace-visible\n")
        .expect("write workspace file");

    // Use the physical path, as a real run does: `current_dir()` resolves
    // symlinks, and on macOS the temp root is reached through `/var` ->
    // `/private/var`. Seatbelt matches `subpath` against the resolved path, so a
    // grant written with the symlinked prefix would match nothing.
    let workspace_path = fs::canonicalize(workspace.path()).expect("canonicalize workspace");

    let mut plan = fixture_plan(
        &fixtures,
        vec![
            "/bin/sh".to_string(),
            "-c".to_string(),
            format!(
                "cat public.txt; if cat {} >/dev/null 2>&1; then printf 'leaked'; \
                 else printf 'denied'; fi",
                fixtures.home_ssh_key.display()
            ),
        ],
        NetLevel::None,
    );
    plan.cwd = workspace_path.clone();
    // The shape every built-in profile uses: a relative read root.
    plan.profile.fs_read = vec![PathBuf::from(".")];
    plan.profile.fs_write = vec![];

    let sandbox = DarwinSandbox::new();
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

    // The resolved read root must be a clean directory path: a trailing `/.`
    // makes the `subpath` rule match nothing.
    assert!(
        !prepared
            .sbpl_profile
            .contains(&format!("{}/.\"", workspace_path.display())),
        "read root must not be emitted with a trailing `/.`\n{}",
        prepared.sbpl_profile
    );

    let output = sandbox
        .launch(&prepared)
        .expect("launch fixture command")
        .wait_with_output()
        .expect("wait for fixture command");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    assert!(
        stdout.contains("workspace-visible"),
        "the sandboxed process must be able to read its own workspace\nstdout: {stdout}\nstderr: {stderr}"
    );
    assert!(
        stdout.contains("denied"),
        "the out-of-workspace secret must stay denied\nstdout: {stdout}\nstderr: {stderr}"
    );
    assert!(
        !stdout.contains("leaked"),
        "sandboxed process read an out-of-workspace secret\nstdout: {stdout}"
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
