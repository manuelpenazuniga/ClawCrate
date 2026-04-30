use std::io;
#[cfg(unix)]
use std::os::unix::process::CommandExt;
#[cfg(target_os = "linux")]
use std::path::Path;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::Arc;

use crate::env_scrub::{scrub_current_environment, scrub_environment};
use crate::path_normalize::{home_from_env_pairs, normalize_paths};
use clawcrate_types::{ExecutionPlan, NetLevel, ResourceLimits};
#[cfg(target_os = "linux")]
use nix::{errno::Errno, libc};
#[cfg(target_os = "linux")]
use seccompiler::{
    BpfProgram, Error as SeccompApplyError, SeccompAction, SeccompFilter, SeccompRule, TargetArch,
};
#[cfg(target_os = "linux")]
use std::collections::{BTreeMap, BTreeSet};
#[cfg(target_os = "linux")]
use std::convert::TryInto;
#[cfg(target_os = "linux")]
use std::ffi::CString;
#[cfg(target_os = "linux")]
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
#[cfg(target_os = "linux")]
use std::os::unix::ffi::OsStrExt;
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
#[cfg(all(target_os = "linux", target_env = "gnu"))]
type LinuxRlimitResource = libc::__rlimit_resource_t;
#[cfg(all(target_os = "linux", not(target_env = "gnu")))]
type LinuxRlimitResource = libc::c_int;
#[cfg(target_os = "linux")]
const LANDLOCK_RULE_PATH_BENEATH: u32 = 1;
#[cfg(target_os = "linux")]
const LANDLOCK_CREATE_RULESET_VERSION: u32 = 1 << 0;
#[cfg(target_os = "linux")]
const LANDLOCK_ACCESS_FS_WRITE_FILE: u64 = 1 << 1;
#[cfg(target_os = "linux")]
const LANDLOCK_ACCESS_FS_REMOVE_DIR: u64 = 1 << 4;
#[cfg(target_os = "linux")]
const LANDLOCK_ACCESS_FS_REMOVE_FILE: u64 = 1 << 5;
#[cfg(target_os = "linux")]
const LANDLOCK_ACCESS_FS_MAKE_CHAR: u64 = 1 << 6;
#[cfg(target_os = "linux")]
const LANDLOCK_ACCESS_FS_MAKE_DIR: u64 = 1 << 7;
#[cfg(target_os = "linux")]
const LANDLOCK_ACCESS_FS_MAKE_REG: u64 = 1 << 8;
#[cfg(target_os = "linux")]
const LANDLOCK_ACCESS_FS_MAKE_SOCK: u64 = 1 << 9;
#[cfg(target_os = "linux")]
const LANDLOCK_ACCESS_FS_MAKE_FIFO: u64 = 1 << 10;
#[cfg(target_os = "linux")]
const LANDLOCK_ACCESS_FS_MAKE_BLOCK: u64 = 1 << 11;
#[cfg(target_os = "linux")]
const LANDLOCK_ACCESS_FS_MAKE_SYM: u64 = 1 << 12;
#[cfg(target_os = "linux")]
const LANDLOCK_ACCESS_FS_REFER: u64 = 1 << 13;
#[cfg(target_os = "linux")]
const LANDLOCK_ACCESS_FS_TRUNCATE: u64 = 1 << 14;
#[cfg(target_os = "linux")]
const LANDLOCK_ACCESS_FS_BASE_WRITE: u64 = LANDLOCK_ACCESS_FS_WRITE_FILE
    | LANDLOCK_ACCESS_FS_REMOVE_DIR
    | LANDLOCK_ACCESS_FS_REMOVE_FILE
    | LANDLOCK_ACCESS_FS_MAKE_CHAR
    | LANDLOCK_ACCESS_FS_MAKE_DIR
    | LANDLOCK_ACCESS_FS_MAKE_REG
    | LANDLOCK_ACCESS_FS_MAKE_SOCK
    | LANDLOCK_ACCESS_FS_MAKE_FIFO
    | LANDLOCK_ACCESS_FS_MAKE_BLOCK
    | LANDLOCK_ACCESS_FS_MAKE_SYM;

#[cfg(target_os = "linux")]
#[derive(Clone, Copy, Debug)]
struct LinuxRlimitTarget {
    resource: LinuxRlimitResource,
    desired_soft: libc::rlim_t,
}

#[cfg(target_os = "linux")]
#[derive(Debug)]
struct LinuxLandlockContext {
    write_access_mask: u64,
    allowed_write_path_fds: Vec<OwnedFd>,
}

#[cfg(target_os = "linux")]
#[derive(Debug)]
struct LinuxSeccompContext {
    program: BpfProgram,
}

#[cfg(target_os = "linux")]
#[repr(C)]
#[derive(Clone, Copy)]
struct LandlockRulesetAttr {
    handled_access_fs: u64,
}

#[cfg(target_os = "linux")]
#[repr(C)]
#[derive(Clone, Copy)]
struct LandlockPathBeneathAttr {
    allowed_access: u64,
    parent_fd: i32,
}

#[cfg(target_os = "linux")]
fn build_linux_rlimit_targets(
    limits: &ResourceLimits,
) -> [LinuxRlimitTarget; LINUX_RLIMIT_TARGET_COUNT] {
    [
        LinuxRlimitTarget {
            resource: libc::RLIMIT_CPU as LinuxRlimitResource,
            desired_soft: saturating_u64_to_rlim_t(limits.max_cpu_seconds),
        },
        LinuxRlimitTarget {
            resource: libc::RLIMIT_AS as LinuxRlimitResource,
            desired_soft: saturating_u64_to_rlim_t(memory_mb_to_bytes(limits.max_memory_mb)),
        },
        LinuxRlimitTarget {
            resource: libc::RLIMIT_NOFILE as LinuxRlimitResource,
            desired_soft: saturating_u64_to_rlim_t(limits.max_open_files),
        },
        LinuxRlimitTarget {
            resource: libc::RLIMIT_FSIZE as LinuxRlimitResource,
            desired_soft: saturating_u64_to_rlim_t(limits.max_output_bytes),
        },
        LinuxRlimitTarget {
            resource: libc::RLIMIT_NPROC as LinuxRlimitResource,
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

#[cfg(target_os = "linux")]
fn prepare_linux_landlock_context(
    prepared: &PreparedLinuxSandbox,
) -> io::Result<LinuxLandlockContext> {
    let abi_version = probe_linux_landlock_abi()?;
    let write_access_mask = landlock_write_access_mask_for_abi(abi_version);
    let allowed_write_path_fds = open_linux_landlock_write_path_fds(prepared)?;
    Ok(LinuxLandlockContext {
        write_access_mask,
        allowed_write_path_fds,
    })
}

#[cfg(target_os = "linux")]
#[allow(unsafe_code)]
fn probe_linux_landlock_abi() -> io::Result<i32> {
    // SAFETY: syscall arguments follow landlock_create_ruleset ABI query contract.
    let abi = unsafe {
        libc::syscall(
            libc::SYS_landlock_create_ruleset,
            std::ptr::null::<libc::c_void>(),
            0usize,
            LANDLOCK_CREATE_RULESET_VERSION,
        )
    };
    if abi < 0 {
        return Err(io::Error::from_raw_os_error(Errno::last_raw()));
    }
    Ok(abi as i32)
}

#[cfg(target_os = "linux")]
fn landlock_write_access_mask_for_abi(abi_version: i32) -> u64 {
    let mut mask = LANDLOCK_ACCESS_FS_BASE_WRITE;
    if abi_version >= 2 {
        mask |= LANDLOCK_ACCESS_FS_REFER;
    }
    if abi_version >= 3 {
        mask |= LANDLOCK_ACCESS_FS_TRUNCATE;
    }
    mask
}

#[cfg(target_os = "linux")]
fn open_linux_landlock_write_path_fds(prepared: &PreparedLinuxSandbox) -> io::Result<Vec<OwnedFd>> {
    let mut unique_anchors = BTreeSet::new();
    for path in &prepared.fs_write {
        let resolved = if path.is_absolute() {
            path.clone()
        } else {
            prepared.cwd.join(path)
        };
        let anchor = nearest_existing_landlock_anchor(&resolved)?;
        unique_anchors.insert(anchor);
    }

    let mut fds = Vec::with_capacity(unique_anchors.len());
    for anchor in unique_anchors {
        fds.push(open_linux_landlock_path(&anchor)?);
    }
    Ok(fds)
}

#[cfg(target_os = "linux")]
fn nearest_existing_landlock_anchor(path: &Path) -> io::Result<PathBuf> {
    if path.exists() {
        return Ok(path.to_path_buf());
    }

    let mut current = path.parent();
    while let Some(candidate) = current {
        if candidate.exists() {
            return Ok(candidate.to_path_buf());
        }
        current = candidate.parent();
    }

    Err(io::Error::new(
        io::ErrorKind::NotFound,
        format!(
            "failed to resolve existing Landlock anchor path for {}",
            path.display()
        ),
    ))
}

#[cfg(target_os = "linux")]
#[allow(unsafe_code)]
fn open_linux_landlock_path(path: &Path) -> io::Result<OwnedFd> {
    let c_path = CString::new(path.as_os_str().as_bytes()).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!(
                "landlock path contains interior NUL byte: {}",
                path.display()
            ),
        )
    })?;

    // SAFETY: pointer is a valid NUL-terminated C string; flags are valid for `open(2)`.
    let raw_fd = unsafe { libc::open(c_path.as_ptr(), libc::O_PATH | libc::O_CLOEXEC) };
    if raw_fd < 0 {
        return Err(io::Error::from_raw_os_error(Errno::last_raw()));
    }

    // SAFETY: raw descriptor was returned by `open` and is uniquely owned here.
    Ok(unsafe { OwnedFd::from_raw_fd(raw_fd) })
}

#[cfg(target_os = "linux")]
fn prepare_linux_seccomp_context(
    prepared: &PreparedLinuxSandbox,
) -> io::Result<LinuxSeccompContext> {
    let target_arch: TargetArch = std::env::consts::ARCH.try_into().map_err(|source| {
        io::Error::new(
            io::ErrorKind::Unsupported,
            format!("unsupported seccomp target architecture: {source}"),
        )
    })?;
    let filter = SeccompFilter::new(
        build_linux_seccomp_rules(&prepared.net),
        SeccompAction::Allow,
        SeccompAction::Errno(libc::EPERM as u32),
        target_arch,
    )
    .map_err(|source| io::Error::other(format!("failed to build seccomp filter: {source}")))?;
    let program: BpfProgram = filter.try_into().map_err(|source| {
        io::Error::other(format!("failed to compile seccomp filter: {source}"))
    })?;
    Ok(LinuxSeccompContext { program })
}

#[cfg(target_os = "linux")]
fn build_linux_seccomp_rules(net: &NetLevel) -> BTreeMap<i64, Vec<SeccompRule>> {
    let mut rules = BTreeMap::new();
    for syscall in linux_default_seccomp_denied_syscalls() {
        rules.insert(*syscall, Vec::new());
    }
    if matches!(net, NetLevel::None) {
        for syscall in linux_none_net_seccomp_denied_syscalls() {
            rules.insert(*syscall, Vec::new());
        }
    }
    rules
}

#[cfg(target_os = "linux")]
fn linux_default_seccomp_denied_syscalls() -> &'static [i64] {
    &[
        libc::SYS_ptrace,
        libc::SYS_mount,
        libc::SYS_umount2,
        libc::SYS_reboot,
        libc::SYS_kexec_load,
        libc::SYS_swapon,
        libc::SYS_swapoff,
        libc::SYS_init_module,
        libc::SYS_finit_module,
        libc::SYS_delete_module,
    ]
}

#[cfg(target_os = "linux")]
fn linux_none_net_seccomp_denied_syscalls() -> &'static [i64] {
    &[
        libc::SYS_socket,
        libc::SYS_socketpair,
        libc::SYS_connect,
        libc::SYS_bind,
        libc::SYS_listen,
        libc::SYS_accept,
        libc::SYS_accept4,
    ]
}

pub trait LinuxEnforcer: Send + Sync {
    fn apply_rlimits(
        &self,
        command: &mut Command,
        limits: &ResourceLimits,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>>;
    fn apply_landlock(
        &self,
        command: &mut Command,
        prepared: &PreparedLinuxSandbox,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>>;
    fn apply_seccomp(
        &self,
        command: &mut Command,
        prepared: &PreparedLinuxSandbox,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>>;
}

#[derive(Debug, Clone, Copy)]
pub struct KernelEnforcer;

impl LinuxEnforcer for KernelEnforcer {
    fn apply_rlimits(
        &self,
        command: &mut Command,
        limits: &ResourceLimits,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        #[cfg(target_os = "linux")]
        configure_linux_rlimit_pre_exec(command, limits);
        #[cfg(not(target_os = "linux"))]
        let _ = (command, limits);
        Ok(())
    }

    fn apply_landlock(
        &self,
        command: &mut Command,
        prepared: &PreparedLinuxSandbox,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        #[cfg(target_os = "linux")]
        {
            let context = prepare_linux_landlock_context(prepared)?;
            configure_linux_landlock_pre_exec(command, context);
        }
        #[cfg(not(target_os = "linux"))]
        let _ = (command, prepared);
        Ok(())
    }

    fn apply_seccomp(
        &self,
        command: &mut Command,
        prepared: &PreparedLinuxSandbox,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        #[cfg(target_os = "linux")]
        {
            let context = prepare_linux_seccomp_context(prepared)?;
            configure_linux_seccomp_pre_exec(command, context);
        }
        #[cfg(not(target_os = "linux"))]
        let _ = (command, prepared);
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
        let home = home_from_env_pairs(&scrubbed.kept);

        PreparedLinuxSandbox {
            execution_id: plan.id.clone(),
            command: plan.command.clone(),
            cwd: plan.cwd.clone(),
            fs_read: normalize_paths(&plan.cwd, &plan.profile.fs_read, home.as_deref()),
            fs_write: normalize_paths(&plan.cwd, &plan.profile.fs_write, home.as_deref()),
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
        apply_enforcement_steps(self.enforcer.as_ref(), &mut command, prepared)?;

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
    command: &mut Command,
    prepared: &PreparedLinuxSandbox,
) -> Result<(), LinuxSandboxError> {
    enforcer
        .apply_rlimits(command, &prepared.resource_limits)
        .map_err(|source| LinuxSandboxError::Enforcement {
            step: EnforcementStep::Rlimits,
            source,
        })?;

    enforcer
        .apply_landlock(command, prepared)
        .map_err(|source| LinuxSandboxError::Enforcement {
            step: EnforcementStep::Landlock,
            source,
        })?;

    enforcer
        .apply_seccomp(command, prepared)
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
        let effective_hard = effective_soft;
        if effective_soft == current.rlim_cur && effective_hard == current.rlim_max {
            continue;
        }

        let updated = libc::rlimit {
            rlim_cur: effective_soft,
            rlim_max: effective_hard,
        };
        // SAFETY: Arguments are valid pointers and resource IDs from libc constants.
        if unsafe { libc::setrlimit(target.resource, &updated) } != 0 {
            return Err(io::Error::from_raw_os_error(Errno::last_raw()));
        }
    }
    Ok(())
}

#[cfg(target_os = "linux")]
#[allow(unsafe_code)]
fn configure_linux_landlock_pre_exec(command: &mut Command, context: LinuxLandlockContext) {
    // SAFETY:
    // - The closure runs in the child post-fork/pre-exec.
    // - The closure body only performs direct syscalls (`landlock_*`, `prctl`, `close`) and
    //   iteration over precomputed file descriptors prepared in the parent.
    // - Any error returns `io::Error`, aborting spawn/exec in fail-closed mode.
    unsafe {
        command.pre_exec(move || apply_linux_landlock_restrictions(&context));
    }
}

#[cfg(target_os = "linux")]
#[allow(unsafe_code)]
fn apply_linux_landlock_restrictions(context: &LinuxLandlockContext) -> io::Result<()> {
    let ruleset_attr = LandlockRulesetAttr {
        handled_access_fs: context.write_access_mask,
    };
    // SAFETY: syscall args follow landlock_create_ruleset ABI with valid pointer+size.
    let ruleset_fd = unsafe {
        libc::syscall(
            libc::SYS_landlock_create_ruleset,
            &ruleset_attr as *const LandlockRulesetAttr,
            std::mem::size_of::<LandlockRulesetAttr>(),
            0u32,
        )
    };
    if ruleset_fd < 0 {
        return Err(io::Error::from_raw_os_error(Errno::last_raw()));
    }
    let ruleset_fd = ruleset_fd as i32;

    for parent_fd in &context.allowed_write_path_fds {
        let path_rule = LandlockPathBeneathAttr {
            allowed_access: context.write_access_mask,
            parent_fd: parent_fd.as_raw_fd(),
        };
        // SAFETY: syscall args follow landlock_add_rule ABI with valid descriptors and pointer.
        let add_result = unsafe {
            libc::syscall(
                libc::SYS_landlock_add_rule,
                ruleset_fd,
                LANDLOCK_RULE_PATH_BENEATH,
                &path_rule as *const LandlockPathBeneathAttr,
                0u32,
            )
        };
        if add_result < 0 {
            let add_errno = Errno::last_raw();
            // SAFETY: closing best-effort descriptor obtained from create_ruleset.
            let _ = unsafe { libc::close(ruleset_fd) };
            return Err(io::Error::from_raw_os_error(add_errno));
        }
    }

    // SAFETY: prctl contract is satisfied for PR_SET_NO_NEW_PRIVS.
    let prctl_result = unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) };
    if prctl_result != 0 {
        let prctl_errno = Errno::last_raw();
        // SAFETY: closing best-effort descriptor obtained from create_ruleset.
        let _ = unsafe { libc::close(ruleset_fd) };
        return Err(io::Error::from_raw_os_error(prctl_errno));
    }

    // SAFETY: syscall args follow landlock_restrict_self ABI.
    let restrict_result =
        unsafe { libc::syscall(libc::SYS_landlock_restrict_self, ruleset_fd, 0u32) };
    let restrict_errno = if restrict_result < 0 {
        Some(Errno::last_raw())
    } else {
        None
    };
    // SAFETY: closing best-effort descriptor obtained from create_ruleset.
    let close_result = unsafe { libc::close(ruleset_fd) };
    let close_errno = if close_result != 0 {
        Some(Errno::last_raw())
    } else {
        None
    };
    if let Some(error) = landlock_errno_to_io_error(restrict_errno, close_errno) {
        return Err(error);
    }

    Ok(())
}

#[cfg(target_os = "linux")]
fn landlock_errno_to_io_error(
    primary_errno: Option<i32>,
    cleanup_errno: Option<i32>,
) -> Option<io::Error> {
    if let Some(errno) = primary_errno {
        return Some(io::Error::from_raw_os_error(errno));
    }
    cleanup_errno.map(io::Error::from_raw_os_error)
}

#[cfg(target_os = "linux")]
#[allow(unsafe_code)]
fn configure_linux_seccomp_pre_exec(command: &mut Command, context: LinuxSeccompContext) {
    // SAFETY:
    // - The closure runs in the child post-fork/pre-exec.
    // - The seccomp BPF program is fully materialized in the parent process.
    // - Any failure returns `io::Error`, aborting spawn/exec in fail-closed mode.
    unsafe {
        command.pre_exec(move || apply_linux_seccomp_filter(&context));
    }
}

#[cfg(target_os = "linux")]
#[allow(unsafe_code)]
fn apply_linux_seccomp_filter(context: &LinuxSeccompContext) -> io::Result<()> {
    // SAFETY: prctl contract is satisfied for PR_SET_NO_NEW_PRIVS.
    let prctl_result = unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) };
    if prctl_result != 0 {
        return Err(io::Error::from_raw_os_error(Errno::last_raw()));
    }

    seccompiler::apply_filter(context.program.as_slice()).map_err(seccomp_apply_error_as_io_error)
}

#[cfg(target_os = "linux")]
fn seccomp_apply_error_as_io_error(source: SeccompApplyError) -> io::Error {
    // Keep pre_exec failure conversion allocator-free: emit deterministic raw errno values instead
    // of formatted strings so the child post-fork path remains async-signal-safe.
    let errno = match &source {
        SeccompApplyError::Prctl(error) => error.raw_os_error().unwrap_or(libc::EINVAL),
        SeccompApplyError::Seccomp(error) => error.raw_os_error().unwrap_or(libc::EINVAL),
        SeccompApplyError::ThreadSync(_) => libc::EBUSY,
        SeccompApplyError::EmptyFilter => libc::EINVAL,
        SeccompApplyError::Backend(_) => libc::EINVAL,
    };
    // Intentionally leak this value post-fork to avoid running Drop glue in the child pre-exec
    // failure path, where touching allocator state is not async-signal-safe.
    std::mem::forget(source);
    io::Error::from_raw_os_error(errno)
}

#[cfg(test)]
mod tests {
    #[cfg(target_os = "linux")]
    use std::fs;
    #[cfg(target_os = "linux")]
    use std::path::Path;
    use std::path::PathBuf;
    use std::process::Command;
    use std::sync::{Arc, Mutex};
    #[cfg(target_os = "linux")]
    use std::time::{SystemTime, UNIX_EPOCH};

    use chrono::Utc;
    use clawcrate_types::{
        Actor, DefaultMode, ExecutionPlan, NetLevel, ResolvedProfile, ResourceLimits, WorkspaceMode,
    };

    use super::{
        apply_enforcement_steps, EnforcementStep, LinuxEnforcer, LinuxSandbox, PreparedLinuxSandbox,
    };
    #[cfg(target_os = "linux")]
    use super::{landlock_errno_to_io_error, seccomp_apply_error_as_io_error};

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
            _command: &mut Command,
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
            _command: &mut Command,
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
            _command: &mut Command,
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

    #[cfg(target_os = "linux")]
    fn unique_tmp_dir(prefix: &str) -> PathBuf {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system time after unix epoch")
            .as_nanos();
        let dir = std::env::temp_dir().join(format!("{prefix}_{nanos}_{}", std::process::id()));
        fs::create_dir_all(&dir).expect("create temp test directory");
        dir
    }

    #[cfg(target_os = "linux")]
    fn python3_path_for_seccomp_tests() -> Option<&'static str> {
        ["/usr/bin/python3", "/bin/python3"]
            .into_iter()
            .find(|candidate| Path::new(candidate).exists())
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
    fn prepare_normalizes_profile_paths_for_backend_enforcement() {
        let sandbox = LinuxSandbox::default();
        let mut plan = test_plan(vec!["/bin/echo".to_string(), "ok".to_string()]);
        plan.cwd = PathBuf::from("/tmp/workspace");
        plan.profile.fs_read = vec![
            PathBuf::from("relative-read"),
            PathBuf::from("~/.cargo/bin"),
        ];
        plan.profile.fs_write = vec![PathBuf::from("relative-write"), PathBuf::from("~/tmp")];

        let prepared = sandbox.prepare_with_env(
            &plan,
            vec![
                ("HOME".to_string(), "/tmp/home-user".to_string()),
                ("PATH".to_string(), "/usr/bin".to_string()),
            ],
        );

        assert_eq!(
            prepared.fs_read,
            vec![
                PathBuf::from("/tmp/workspace/relative-read"),
                PathBuf::from("/tmp/home-user/.cargo/bin")
            ]
        );
        assert_eq!(
            prepared.fs_write,
            vec![
                PathBuf::from("/tmp/workspace/relative-write"),
                PathBuf::from("/tmp/home-user/tmp")
            ]
        );
    }

    #[test]
    fn enforcement_order_is_rlimits_then_landlock_then_seccomp() {
        let mock = Arc::new(MockEnforcer::default());
        let plan = test_plan(vec!["/bin/echo".to_string(), "ok".to_string()]);
        let sandbox = LinuxSandbox::new_with_enforcer(mock.clone());
        let prepared = sandbox.prepare_with_env(&plan, vec![]);
        let mut command = Command::new("/bin/echo");

        apply_enforcement_steps(mock.as_ref(), &mut command, &prepared)
            .expect("apply enforcement steps");
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
            "ulimit -St; ulimit -Sn; ulimit -Ht; ulimit -Hn".to_string(),
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
        let soft_cpu_seconds = lines.next().expect("soft cpu limit line").trim();
        let soft_open_files = lines.next().expect("soft open files limit line").trim();
        let hard_cpu_seconds = lines.next().expect("hard cpu limit line").trim();
        let hard_open_files = lines.next().expect("hard open files limit line").trim();

        assert_eq!(soft_cpu_seconds, "1");
        assert_eq!(soft_open_files, "64");
        assert_eq!(hard_cpu_seconds, "1");
        assert_eq!(hard_open_files, "64");
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn launch_applies_landlock_write_restrictions_outside_allowed_paths() {
        let allowed_dir = unique_tmp_dir("clawcrate_linux_landlock_allowed");
        let denied_file = std::env::temp_dir().join(format!(
            "clawcrate_linux_landlock_denied_{}_{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("system time after unix epoch")
                .as_nanos()
        ));
        if denied_file.exists() {
            fs::remove_file(&denied_file).expect("remove stale denied file");
        }

        let mut plan = test_plan(vec![
            "/bin/sh".to_string(),
            "-c".to_string(),
            format!(
                "printf 'ok' > allowed.txt && printf 'denied' > {}",
                denied_file.display()
            ),
        ]);
        plan.cwd = allowed_dir.clone();
        plan.profile.fs_read = vec![allowed_dir.clone()];
        plan.profile.fs_write = vec![allowed_dir.clone()];

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

        assert!(
            !output.status.success(),
            "writing outside allowed path should be denied by Landlock"
        );
        let allowed_content =
            fs::read_to_string(allowed_dir.join("allowed.txt")).expect("read allowed output");
        assert_eq!(allowed_content, "ok");
        assert!(!denied_file.exists(), "denied file should not be created");
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn launch_applies_seccomp_network_deny_when_profile_net_is_none() {
        let Some(python3) = python3_path_for_seccomp_tests() else {
            return;
        };

        let mut plan = test_plan(vec![
            python3.to_string(),
            "-c".to_string(),
            "import socket; socket.socket()".to_string(),
        ]);
        plan.profile.net = NetLevel::None;

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

        assert!(
            !output.status.success(),
            "socket() should be denied by seccomp when net is none"
        );
        let stderr = String::from_utf8(output.stderr).expect("utf8 stderr");
        assert!(
            stderr.contains("Operation not permitted") || stderr.contains("PermissionError"),
            "unexpected socket() denial stderr: {stderr}"
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn launch_keeps_socket_available_when_profile_net_is_open() {
        let Some(python3) = python3_path_for_seccomp_tests() else {
            return;
        };

        let mut plan = test_plan(vec![
            python3.to_string(),
            "-c".to_string(),
            "import socket; socket.socket()".to_string(),
        ]);
        plan.profile.net = NetLevel::Open;

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

        assert!(
            output.status.success(),
            "net=open should keep socket() available under seccomp; stderr={}",
            String::from_utf8_lossy(&output.stderr)
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn seccomp_error_mapping_returns_deterministic_raw_errno_values() {
        let prctl_error = seccomp_apply_error_as_io_error(seccompiler::Error::Prctl(
            std::io::Error::from_raw_os_error(nix::libc::EPERM),
        ));
        assert_eq!(prctl_error.raw_os_error(), Some(nix::libc::EPERM));

        let seccomp_error = seccomp_apply_error_as_io_error(seccompiler::Error::Seccomp(
            std::io::Error::from_raw_os_error(nix::libc::EACCES),
        ));
        assert_eq!(seccomp_error.raw_os_error(), Some(nix::libc::EACCES));

        let thread_sync_error = seccomp_apply_error_as_io_error(seccompiler::Error::ThreadSync(42));
        assert_eq!(thread_sync_error.raw_os_error(), Some(nix::libc::EBUSY));

        let empty_filter_error = seccomp_apply_error_as_io_error(seccompiler::Error::EmptyFilter);
        assert_eq!(empty_filter_error.raw_os_error(), Some(nix::libc::EINVAL));

        let backend_error = seccomp_apply_error_as_io_error(seccompiler::Error::Backend(
            seccompiler::BackendError::InvalidArgumentNumber,
        ));
        assert_eq!(backend_error.raw_os_error(), Some(nix::libc::EINVAL));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn landlock_error_mapping_preserves_primary_errno_over_cleanup_errno() {
        let error = landlock_errno_to_io_error(Some(nix::libc::EPERM), Some(nix::libc::EBADF))
            .expect("primary errno must produce io error");
        assert_eq!(error.raw_os_error(), Some(nix::libc::EPERM));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn landlock_error_mapping_falls_back_to_cleanup_errno_when_primary_missing() {
        let error = landlock_errno_to_io_error(None, Some(nix::libc::EBADF))
            .expect("cleanup errno must produce io error");
        assert_eq!(error.raw_os_error(), Some(nix::libc::EBADF));
    }
}
