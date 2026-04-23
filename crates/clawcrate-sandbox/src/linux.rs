use std::io;
#[cfg(unix)]
use std::os::unix::process::CommandExt;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::Arc;

use crate::env_scrub::{scrub_current_environment, scrub_environment};
use clawcrate_types::{ExecutionPlan, NetLevel, ResourceLimits};
#[cfg(target_os = "linux")]
use nix::{errno::Errno, libc};
use thiserror::Error;

#[derive(Debug, Clone)]
pub struct PreparedLinuxSandbox {
    pub execution_id: String,
    pub command: Vec<String>,
    pub cwd: PathBuf,
    pub fs_read: Vec<PathBuf>,
    pub fs_write: Vec<PathBuf>,
    pub net: NetLevel,
    pub resource_limits: ResourceLimits,
    pub scrubbed_env: Vec<(String, String)>,
    pub scrubbed_keys: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EnforcementStep {
    Rlimits,
    Landlock,
    Seccomp,
}

#[derive(Debug, Error)]
pub enum LinuxSandboxError {
    #[error("command is empty")]
    EmptyCommand,
    #[error("failed to apply enforcement at step {step:?}: {source}")]
    Enforcement {
        step: EnforcementStep,
        #[source]
        source: Box<dyn std::error::Error + Send + Sync>,
    },
    #[error("failed to spawn process: {0}")]
    Spawn(#[source] io::Error),
}

#[cfg(target_os = "linux")]
const LINUX_RLIMIT_TARGET_COUNT: usize = 5;

#[cfg(target_os = "linux")]
#[derive(Clone, Copy, Debug)]
struct LinuxRlimitTarget {
    resource: libc::__rlimit_resource_t,
    desired_soft: libc::rlim_t,
}

#[cfg(target_os = "linux")]
fn build_linux_rlimit_targets(
    limits: &ResourceLimits,
) -> [LinuxRlimitTarget; LINUX_RLIMIT_TARGET_COUNT] {
    [
        LinuxRlimitTarget {
            resource: libc::RLIMIT_CPU,
            desired_soft: saturating_u64_to_rlim_t(limits.max_cpu_seconds),
        },
        LinuxRlimitTarget {
            resource: libc::RLIMIT_AS,
            desired_soft: saturating_u64_to_rlim_t(memory_mb_to_bytes(limits.max_memory_mb)),
        },
        LinuxRlimitTarget {
            resource: libc::RLIMIT_NOFILE,
            desired_soft: saturating_u64_to_rlim_t(limits.max_open_files),
        },
        LinuxRlimitTarget {
            resource: libc::RLIMIT_FSIZE,
            desired_soft: saturating_u64_to_rlim_t(limits.max_output_bytes),
        },
        LinuxRlimitTarget {
            resource: libc::RLIMIT_NPROC,
            desired_soft: saturating_u64_to_rlim_t(limits.max_processes),
        },
    ]
}

#[cfg(target_os = "linux")]
fn memory_mb_to_bytes(memory_mb: u64) -> u64 {
    memory_mb.saturating_mul(1024).saturating_mul(1024)
}

#[cfg(target_os = "linux")]
fn saturating_u64_to_rlim_t(value: u64) -> libc::rlim_t {
    libc::rlim_t::try_from(value).unwrap_or(libc::rlim_t::MAX)
}

pub trait LinuxEnforcer: Send + Sync {
    fn apply_rlimits(
        &self,
        limits: &ResourceLimits,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>>;
    fn apply_landlock(
        &self,
        prepared: &PreparedLinuxSandbox,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>>;
    fn apply_seccomp(
        &self,
        prepared: &PreparedLinuxSandbox,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>>;
}

#[derive(Debug, Clone, Copy)]
pub struct KernelEnforcer;

impl LinuxEnforcer for KernelEnforcer {
    fn apply_rlimits(
        &self,
        _limits: &ResourceLimits,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        // Linux rlimits are enforced in the child pre-exec hook installed in `launch`.
        // Keep this step wired for ordering/traceability while Landlock/seccomp are integrated.
        Ok(())
    }

    fn apply_landlock(
        &self,
        _prepared: &PreparedLinuxSandbox,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        // Landlock rule materialization is introduced in M2-02 with the prepare path.
        Ok(())
    }

    fn apply_seccomp(
        &self,
        _prepared: &PreparedLinuxSandbox,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        // Seccomp filter materialization is introduced in M2-02 with the prepare path.
        Ok(())
    }
}

pub struct LinuxSandbox {
    enforcer: Arc<dyn LinuxEnforcer>,
}

impl Default for LinuxSandbox {
    fn default() -> Self {
        Self::new_with_enforcer(Arc::new(KernelEnforcer))
    }
}

impl LinuxSandbox {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn new_with_enforcer(enforcer: Arc<dyn LinuxEnforcer>) -> Self {
        Self { enforcer }
    }

    pub fn prepare(&self, plan: &ExecutionPlan) -> PreparedLinuxSandbox {
        self.prepare_with_env(plan, std::env::vars())
    }

    pub fn prepare_with_env<I>(&self, plan: &ExecutionPlan, env_vars: I) -> PreparedLinuxSandbox
    where
        I: IntoIterator<Item = (String, String)>,
    {
        let scrubbed = scrub_environment(
            env_vars,
            &plan.profile.env_scrub,
            &plan.profile.env_passthrough,
        );

        PreparedLinuxSandbox {
            execution_id: plan.id.clone(),
            command: plan.command.clone(),
            cwd: plan.cwd.clone(),
            fs_read: plan.profile.fs_read.clone(),
            fs_write: plan.profile.fs_write.clone(),
            net: plan.profile.net.clone(),
            resource_limits: plan.profile.resources.clone(),
            scrubbed_env: scrubbed.kept,
            scrubbed_keys: scrubbed.removed,
        }
    }

    pub fn launch(
        &self,
        prepared: &PreparedLinuxSandbox,
    ) -> Result<LinuxSandboxedChild, LinuxSandboxError> {
        if prepared.command.is_empty() {
            return Err(LinuxSandboxError::EmptyCommand);
        }

        apply_enforcement_steps(self.enforcer.as_ref(), prepared)?;

        let mut command = Command::new(&prepared.command[0]);
        command.args(&prepared.command[1..]);
        command.current_dir(&prepared.cwd);
        command.stdin(Stdio::null());
        command.stdout(Stdio::piped());
        command.stderr(Stdio::piped());
        #[cfg(unix)]
        command.process_group(0);
        command.env_clear();
        command.envs(prepared.scrubbed_env.iter().cloned());
        #[cfg(target_os = "linux")]
        configure_linux_rlimit_pre_exec(&mut command, &prepared.resource_limits);

        let child = command.spawn().map_err(LinuxSandboxError::Spawn)?;
        Ok(LinuxSandboxedChild { child })
    }
}

pub struct LinuxSandboxedChild {
    child: Child,
}

impl LinuxSandboxedChild {
    pub fn pid(&self) -> u32 {
        self.child.id()
    }

    pub fn child_mut(&mut self) -> &mut Child {
        &mut self.child
    }

    pub fn wait(&mut self) -> Result<std::process::ExitStatus, io::Error> {
        self.child.wait()
    }

    pub fn wait_with_output(self) -> Result<std::process::Output, io::Error> {
        self.child.wait_with_output()
    }
}

pub(crate) fn apply_enforcement_steps(
    enforcer: &dyn LinuxEnforcer,
    prepared: &PreparedLinuxSandbox,
) -> Result<(), LinuxSandboxError> {
    enforcer
        .apply_rlimits(&prepared.resource_limits)
        .map_err(|source| LinuxSandboxError::Enforcement {
            step: EnforcementStep::Rlimits,
            source,
        })?;

    enforcer
        .apply_landlock(prepared)
        .map_err(|source| LinuxSandboxError::Enforcement {
            step: EnforcementStep::Landlock,
            source,
        })?;

    enforcer
        .apply_seccomp(prepared)
        .map_err(|source| LinuxSandboxError::Enforcement {
            step: EnforcementStep::Seccomp,
            source,
        })?;

    Ok(())
}

pub fn scrub_environment_for_profile(plan: &ExecutionPlan) -> (Vec<(String, String)>, Vec<String>) {
    let scrubbed =
        scrub_current_environment(&plan.profile.env_scrub, &plan.profile.env_passthrough);
    (scrubbed.kept, scrubbed.removed)
}

#[cfg(target_os = "linux")]
#[allow(unsafe_code)]
fn configure_linux_rlimit_pre_exec(command: &mut Command, limits: &ResourceLimits) {
    let targets = build_linux_rlimit_targets(limits);
    // SAFETY:
    // - The closure is installed before `spawn` and executed in the child post-fork/pre-exec.
    // - It performs only `getrlimit` / `setrlimit` syscalls and plain arithmetic over precomputed
    //   fixed-size targets, avoiding allocator use and non-async-signal-safe primitives.
    // - Any failure returns an `io::Error`, causing spawn/exec to fail closed.
    unsafe {
        command.pre_exec(move || apply_linux_rlimit_targets(&targets));
    }
}

#[cfg(target_os = "linux")]
#[allow(unsafe_code)]
fn apply_linux_rlimit_targets(
    targets: &[LinuxRlimitTarget; LINUX_RLIMIT_TARGET_COUNT],
) -> io::Result<()> {
    for target in targets {
        let mut current = libc::rlimit {
            rlim_cur: 0,
            rlim_max: 0,
        };

        // SAFETY: Arguments are valid pointers and resource IDs from libc constants.
        if unsafe { libc::getrlimit(target.resource, &mut current) } != 0 {
            return Err(io::Error::from_raw_os_error(Errno::last_raw()));
        }

        let effective_soft = if current.rlim_max == libc::RLIM_INFINITY {
            target.desired_soft
        } else {
            target.desired_soft.min(current.rlim_max)
        };
        if effective_soft == current.rlim_cur {
            continue;
        }

        let updated = libc::rlimit {
            rlim_cur: effective_soft,
            rlim_max: current.rlim_max,
        };
        // SAFETY: Arguments are valid pointers and resource IDs from libc constants.
        if unsafe { libc::setrlimit(target.resource, &updated) } != 0 {
            return Err(io::Error::from_raw_os_error(Errno::last_raw()));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;
    use std::sync::{Arc, Mutex};

    use chrono::Utc;
    use clawcrate_types::{
        Actor, DefaultMode, ExecutionPlan, NetLevel, ResolvedProfile, ResourceLimits, WorkspaceMode,
    };

    use super::{
        apply_enforcement_steps, EnforcementStep, LinuxEnforcer, LinuxSandbox, PreparedLinuxSandbox,
    };

    #[derive(Default)]
    struct MockEnforcer {
        calls: Mutex<Vec<EnforcementStep>>,
    }

    impl MockEnforcer {
        fn snapshot(&self) -> Vec<EnforcementStep> {
            self.calls.lock().expect("lock calls").clone()
        }
    }

    impl LinuxEnforcer for MockEnforcer {
        fn apply_rlimits(
            &self,
            _limits: &ResourceLimits,
        ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
            self.calls
                .lock()
                .expect("lock calls")
                .push(EnforcementStep::Rlimits);
            Ok(())
        }

        fn apply_landlock(
            &self,
            _prepared: &PreparedLinuxSandbox,
        ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
            self.calls
                .lock()
                .expect("lock calls")
                .push(EnforcementStep::Landlock);
            Ok(())
        }

        fn apply_seccomp(
            &self,
            _prepared: &PreparedLinuxSandbox,
        ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
            self.calls
                .lock()
                .expect("lock calls")
                .push(EnforcementStep::Seccomp);
            Ok(())
        }
    }

    fn test_plan(command: Vec<String>) -> ExecutionPlan {
        ExecutionPlan {
            id: "exec-test".to_string(),
            command,
            cwd: PathBuf::from("."),
            profile: ResolvedProfile {
                name: "build".to_string(),
                fs_read: vec![PathBuf::from(".")],
                fs_write: vec![PathBuf::from("./target")],
                fs_deny: vec![],
                net: NetLevel::None,
                env_scrub: vec!["*_SECRET*".to_string()],
                env_passthrough: vec!["HOME".to_string(), "PATH".to_string()],
                resources: ResourceLimits {
                    max_cpu_seconds: 120,
                    max_memory_mb: 512,
                    max_open_files: 1024,
                    max_processes: 64,
                    max_output_bytes: 1_048_576,
                },
                default_mode: DefaultMode::Direct,
            },
            mode: WorkspaceMode::Direct,
            actor: Actor::Human,
            created_at: Utc::now(),
        }
    }

    #[test]
    fn prepare_applies_env_scrubbing_rules() {
        let sandbox = LinuxSandbox::default();
        let plan = test_plan(vec!["/bin/echo".to_string(), "ok".to_string()]);
        let prepared = sandbox.prepare_with_env(
            &plan,
            vec![
                ("MY_SECRET_KEY".to_string(), "shh".to_string()),
                ("HOME".to_string(), "/tmp/home".to_string()),
                ("PATH".to_string(), "/usr/bin".to_string()),
            ],
        );

        assert!(prepared.scrubbed_env.iter().any(|(name, _)| name == "HOME"));
        assert!(prepared
            .scrubbed_keys
            .contains(&"MY_SECRET_KEY".to_string()));
    }

    #[test]
    fn enforcement_order_is_rlimits_then_landlock_then_seccomp() {
        let mock = Arc::new(MockEnforcer::default());
        let plan = test_plan(vec!["/bin/echo".to_string(), "ok".to_string()]);
        let sandbox = LinuxSandbox::new_with_enforcer(mock.clone());
        let prepared = sandbox.prepare_with_env(&plan, vec![]);

        apply_enforcement_steps(mock.as_ref(), &prepared).expect("apply enforcement steps");
        assert_eq!(
            mock.snapshot(),
            vec![
                EnforcementStep::Rlimits,
                EnforcementStep::Landlock,
                EnforcementStep::Seccomp
            ]
        );
    }

    #[test]
    fn launch_runs_command_with_scrubbed_environment() {
        let plan = test_plan(vec!["/usr/bin/env".to_string()]);
        let sandbox = LinuxSandbox::new();
        let prepared = sandbox.prepare_with_env(
            &plan,
            vec![
                ("HOME".to_string(), "/tmp/home".to_string()),
                ("PATH".to_string(), "/usr/bin".to_string()),
                ("MY_SECRET_KEY".to_string(), "should_be_removed".to_string()),
            ],
        );

        let output = sandbox
            .launch(&prepared)
            .expect("launch command")
            .wait_with_output()
            .expect("wait for command");

        assert!(output.status.success());
        let stdout = String::from_utf8(output.stdout).expect("utf8 output");
        assert!(stdout.contains("HOME=/tmp/home"));
        assert!(!stdout.contains("MY_SECRET_KEY=should_be_removed"));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn launch_applies_rlimits_in_child_pre_exec_path() {
        let mut plan = test_plan(vec![
            "/bin/sh".to_string(),
            "-c".to_string(),
            "ulimit -t; ulimit -n".to_string(),
        ]);
        plan.profile.resources.max_cpu_seconds = 1;
        plan.profile.resources.max_open_files = 64;

        let sandbox = LinuxSandbox::new();
        let prepared = sandbox.prepare_with_env(
            &plan,
            vec![
                ("HOME".to_string(), "/tmp/home".to_string()),
                ("PATH".to_string(), "/usr/bin:/bin".to_string()),
            ],
        );

        let output = sandbox
            .launch(&prepared)
            .expect("launch command")
            .wait_with_output()
            .expect("wait for command");

        assert!(output.status.success());
        let stdout = String::from_utf8(output.stdout).expect("utf8 output");
        let mut lines = stdout.lines();
        let cpu_seconds = lines
            .next()
            .expect("cpu limit line")
            .trim()
            .parse::<u64>()
            .expect("cpu limit as integer");
        let open_files = lines
            .next()
            .expect("open files limit line")
            .trim()
            .parse::<u64>()
            .expect("open files limit as integer");

        assert_eq!(cpu_seconds, 1);
        assert_eq!(open_files, 64);
    }
}
