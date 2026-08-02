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
    BpfProgram, Error as SeccompApplyError, SeccompAction, SeccompCmpArgLen, SeccompCmpOp,
    SeccompCondition, SeccompFilter, SeccompRule, TargetArch,
};
#[cfg(target_os = "linux")]
use std::collections::{BTreeMap, BTreeSet};
#[cfg(target_os = "linux")]
use std::convert::TryInto;
#[cfg(target_os = "linux")]
use std::ffi::CString;
#[cfg(target_os = "linux")]
use std::os::fd::{AsRawFd, FromRawFd};
// `OwnedFd` appears in the enforcer trait, which is compiled on every platform.
use std::os::fd::OwnedFd;
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
const LANDLOCK_ACCESS_FS_READ_FILE: u64 = 1 << 2;
#[cfg(target_os = "linux")]
const LANDLOCK_ACCESS_FS_READ_DIR: u64 = 1 << 3;
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
const LANDLOCK_ACCESS_FS_BASE_READ: u64 =
    LANDLOCK_ACCESS_FS_READ_FILE | LANDLOCK_ACCESS_FS_READ_DIR;
/// Rights that are meaningful for a non-directory. Landlock rejects a rule
/// (`EINVAL`) that grants directory-only rights such as `READ_DIR`, `MAKE_*`,
/// or `REMOVE_*` on a regular file, so a rule anchored on a file must be masked
/// down to these bits.
#[cfg(target_os = "linux")]
const LANDLOCK_ACCESS_FS_FILE_APPLICABLE: u64 =
    LANDLOCK_ACCESS_FS_WRITE_FILE | LANDLOCK_ACCESS_FS_READ_FILE | LANDLOCK_ACCESS_FS_TRUNCATE;

/// System paths a sandboxed process must be able to read in order to start and
/// run at all: the dynamic loader, shared libraries, interpreters/toolchains,
/// and the minimal `/etc` entries used for name resolution and TLS trust.
///
/// This is deliberately a fixed, conservative allowlist of read-only system
/// locations rather than a blanket grant on `/`. Anything not listed here (in
/// particular `$HOME`, `/root`, and user data outside the workspace) stays
/// unreadable. Missing entries are skipped, so this list is safe across
/// distributions that do not ship every path.
///
/// Entries are enumerated rather than coarse: Landlock cannot deny a path
/// inside a granted one, so granting `/usr` would also grant `/usr/local/etc`,
/// and granting `/opt` would expose vendor software configuration. A toolchain
/// installed outside these prefixes must be declared by the profile, the way
/// the `build` profile already declares `~/.cargo` and `~/.rustup`.
#[cfg(target_os = "linux")]
const LINUX_SYSTEM_READ_PATHS: &[&str] = &[
    // Executables.
    "/bin",
    "/sbin",
    "/usr/bin",
    "/usr/sbin",
    "/usr/local/bin",
    // Dynamic loader and shared libraries. The architecture triplet directories
    // (for example `/usr/lib/x86_64-linux-gnu`) sit beneath these prefixes.
    "/lib",
    "/lib32",
    "/lib64",
    "/usr/lib",
    "/usr/lib64",
    "/usr/local/lib",
    "/usr/local/lib64",
    "/usr/libexec",
    // Read-only shared data: locale, timezone, terminfo, CA bundles.
    "/usr/share",
    // Name resolution. `/run/systemd/resolve` is required on systemd-resolved
    // distributions, otherwise DNS fails for network-enabled profiles.
    "/etc/resolv.conf",
    "/etc/hosts",
    "/etc/nsswitch.conf",
    "/etc/gai.conf",
    "/etc/services",
    "/run/systemd/resolve",
    // TLS trust stores.
    "/etc/ssl",
    "/etc/pki",
    "/etc/ca-certificates",
    "/etc/crypto-policies",
    // Loader configuration.
    "/etc/ld.so.cache",
    "/etc/ld.so.conf",
    "/etc/ld.so.conf.d",
    "/etc/alternatives",
    // Locale, timezone, and account lookups (`getpwuid`, `getgrgid`). Shadow
    // password material lives in `/etc/shadow`, which is not granted.
    "/etc/localtime",
    "/etc/timezone",
    "/etc/os-release",
    "/etc/terminfo",
    "/etc/passwd",
    "/etc/group",
    // Devices.
    "/dev/null",
    "/dev/zero",
    "/dev/urandom",
    "/dev/random",
    "/dev/full",
    "/dev/tty",
    // procfs: runtimes probe these to locate themselves and size thread pools.
    "/proc/self",
    "/proc/cpuinfo",
    "/proc/meminfo",
    "/proc/stat",
    "/proc/loadavg",
    "/proc/version",
    "/proc/filesystems",
];

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
    read_access_mask: u64,
    allowed_write_paths: Vec<LandlockPathGrant>,
    allowed_read_paths: Vec<LandlockPathGrant>,
}

/// An opened Landlock anchor plus whether it is a directory. Directory-only
/// rights must be stripped for non-directory anchors or `landlock_add_rule`
/// fails with `EINVAL`.
#[cfg(target_os = "linux")]
#[derive(Debug)]
struct LandlockPathGrant {
    fd: OwnedFd,
    is_dir: bool,
}

/// Mask an access set down to the rights valid for the anchor's file type.
#[cfg(target_os = "linux")]
fn landlock_access_for_path_type(access_mask: u64, is_dir: bool) -> u64 {
    if is_dir {
        access_mask
    } else {
        access_mask & LANDLOCK_ACCESS_FS_FILE_APPLICABLE
    }
}

#[cfg(target_os = "linux")]
#[derive(Debug)]
struct LinuxSeccompContext {
    program: BpfProgram,
    /// The child's end of the listener handover channel, when the filter was
    /// rewritten to notify. `None` means the plain `EPERM` filter, which denies
    /// exactly the same syscalls but records nothing.
    listener_channel_child: Option<OwnedFd>,
    /// The same program in the kernel's own layout, materialized here in the
    /// parent because the child half runs post-fork, where allocating is not
    /// async-signal-safe.
    notify_program: Vec<libc::sock_filter>,
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
    let read_access_mask = landlock_read_access_mask_for_abi(abi_version);
    let allowed_write_paths = open_linux_landlock_write_path_fds(prepared)?;
    let allowed_read_paths = open_linux_landlock_read_path_fds(prepared)?;
    Ok(LinuxLandlockContext {
        write_access_mask,
        read_access_mask,
        allowed_write_paths,
        allowed_read_paths,
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

/// Read rights handled by the ruleset. `ACCESS_FS_READ_FILE` and
/// `ACCESS_FS_READ_DIR` exist since Landlock ABI v1, so every kernel that
/// supports Landlock at all supports read-allowlisting; no ABI gating is
/// needed here (unlike `REFER`/`TRUNCATE` on the write mask).
#[cfg(target_os = "linux")]
fn landlock_read_access_mask_for_abi(_abi_version: i32) -> u64 {
    LANDLOCK_ACCESS_FS_BASE_READ
}

/// Open anchors for every path the sandboxed process may read: the profile's
/// `fs_read` set (and `fs_write`, since writable paths must remain readable),
/// plus the minimal system/toolchain locations from `LINUX_SYSTEM_READ_PATHS`.
///
/// System paths that do not exist on the host are skipped rather than treated
/// as an error, so the same allowlist works across distributions.
#[cfg(target_os = "linux")]
fn open_linux_landlock_read_path_fds(
    prepared: &PreparedLinuxSandbox,
) -> io::Result<Vec<LandlockPathGrant>> {
    let mut unique_anchors = BTreeSet::new();

    // Workspace/profile read set, plus write paths (an existing writable path
    // the process cannot read would break nearly every tool).
    //
    // A read anchor is used ONLY when the path itself exists. Unlike write
    // anchors, a missing read path must never walk up to its nearest existing
    // ancestor: a profile listing `~/.cargo` on a machine without it would
    // otherwise anchor on `$HOME` and grant read access to every secret in the
    // home directory. There is nothing to read at a path that does not exist,
    // so skipping is both safe and sufficient.
    for path in prepared.fs_read.iter().chain(prepared.fs_write.iter()) {
        let resolved = if path.is_absolute() {
            path.clone()
        } else {
            prepared.cwd.join(path)
        };
        if resolved.exists() {
            unique_anchors.insert(resolved);
        }
    }

    // Minimal system/toolchain read set. Missing entries are skipped.
    for path in LINUX_SYSTEM_READ_PATHS {
        let candidate = PathBuf::from(path);
        if candidate.exists() {
            unique_anchors.insert(candidate);
        }
    }

    let mut grants = Vec::with_capacity(unique_anchors.len());
    for anchor in unique_anchors {
        // A path can disappear between the existence check and the open; skip
        // it rather than failing the whole sandbox setup.
        match open_linux_landlock_grant(&anchor) {
            Ok(grant) => grants.push(grant),
            Err(error) if error.kind() == io::ErrorKind::NotFound => continue,
            Err(error) => return Err(error),
        }
    }
    Ok(grants)
}

#[cfg(target_os = "linux")]
fn open_linux_landlock_write_path_fds(
    prepared: &PreparedLinuxSandbox,
) -> io::Result<Vec<LandlockPathGrant>> {
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

    let mut grants = Vec::with_capacity(unique_anchors.len());
    for anchor in unique_anchors {
        grants.push(open_linux_landlock_grant(&anchor)?);
    }
    Ok(grants)
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

/// Open a Landlock anchor and record whether it is a directory, so the rule can
/// be masked to the rights valid for that file type.
///
/// The file type is read from the opened descriptor with `fstat`, not from the
/// path: querying the path first would leave a window in which the path could be
/// swapped between the check and the open, so the recorded type would not
/// describe the descriptor the rule is applied to.
#[cfg(target_os = "linux")]
#[allow(unsafe_code)]
fn open_linux_landlock_grant(path: &Path) -> io::Result<LandlockPathGrant> {
    let fd = open_linux_landlock_path(path)?;

    let mut stat = std::mem::MaybeUninit::<libc::stat>::uninit();
    // SAFETY: `fd` is a valid open descriptor (`O_PATH` supports `fstat`), and
    // the pointer refers to correctly sized, writable stack storage.
    let stat_result = unsafe { libc::fstat(fd.as_raw_fd(), stat.as_mut_ptr()) };
    if stat_result < 0 {
        return Err(io::Error::from_raw_os_error(Errno::last_raw()));
    }
    // SAFETY: `fstat` returned success, so the struct is fully initialized.
    let stat = unsafe { stat.assume_init() };
    let is_dir = (stat.st_mode & libc::S_IFMT) == libc::S_IFDIR;

    Ok(LandlockPathGrant { fd, is_dir })
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
    // The handover channel is created before the filter, because the filter has
    // to name it: the child sends the listener over this socket *after* the
    // filter is live, so that one `sendmsg` must be permitted or the child traps
    // on the very call that would summon its supervisor.
    let handover = crate::linux_notify::runtime::listener_channel().ok();

    let mut rules = build_linux_seccomp_rules(&prepared.net);
    if let Some(channel) = handover.as_ref() {
        allow_listener_handover_sendmsg(&mut rules, channel.child.as_raw_fd());
    }

    // Deny-by-default: syscalls in the rule set are allowed, everything else
    // returns EPERM. `EPERM` rather than `KillProcess` keeps a missing syscall
    // diagnosable — the program reports a permission error instead of dying
    // without explanation.
    let filter = SeccompFilter::new(
        rules,
        SeccompAction::Errno(libc::EPERM as u32),
        SeccompAction::Allow,
        target_arch,
    )
    .map_err(|source| io::Error::other(format!("failed to build seccomp filter: {source}")))?;
    let mut program: BpfProgram = filter.try_into().map_err(|source| {
        io::Error::other(format!("failed to compile seccomp filter: {source}"))
    })?;

    // Retarget the mismatch return so ClawCrate adjudicates the denial itself
    // and can record it. Enforcement is unchanged: the supervisor returns the
    // same `EPERM` this filter would have. Any failure here leaves the plain
    // filter in place, because a missing record is better than a stalled child.
    let listener_channel_child = handover.and_then(|channel| {
        let rewritten = rewrite_seccomp_mismatch_to_notify(&mut program);
        if rewritten == 0 {
            // The filter denies some other way than the mismatch action this
            // code expects. Supervising notifications that will never arrive
            // would leave the child unattended, so stay on the plain filter.
            return None;
        }
        LISTENER_CHANNEL_PARENT.with(|slot| slot.borrow_mut().replace(channel.parent));
        Some(channel.child)
    });

    let notify_program = if listener_channel_child.is_some() {
        program
            .iter()
            .map(|instruction| libc::sock_filter {
                code: instruction.code,
                jt: instruction.jt,
                jf: instruction.jf,
                k: instruction.k,
            })
            .collect()
    } else {
        Vec::new()
    };

    Ok(LinuxSeccompContext {
        program,
        listener_channel_child,
        notify_program,
    })
}

/// Retargets the filter's `EPERM` returns to user notification, reporting how
/// many were changed so the caller can refuse to supervise a filter that will
/// never notify.
#[cfg(target_os = "linux")]
fn rewrite_seccomp_mismatch_to_notify(program: &mut BpfProgram) -> usize {
    let mut rewritten = 0usize;
    for instruction in program.iter_mut() {
        if let Some(replacement) = crate::linux_notify::user_notif_replacement(
            instruction.code,
            instruction.k,
            libc::EPERM as u32,
        ) {
            instruction.k = replacement;
            rewritten += 1;
        }
    }
    rewritten
}

/// Permits the single `sendmsg` that hands the listener to the supervisor.
///
/// `sendmsg` is otherwise granted only when the profile allows network access,
/// which is exactly the case the sandbox is most careful about — and also the
/// case where a blanket allow would be a hole. So it is granted on one file
/// descriptor: the child's end of the handover channel, whose number is known
/// here because the socket is created before the filter is compiled.
///
/// Under `network: none` there is no way for the child to obtain a socket to
/// put on that descriptor: `socket` and `socketpair` are not in the allowlist,
/// so nothing connectable exists to redirect onto it.
#[cfg(target_os = "linux")]
fn allow_listener_handover_sendmsg(
    rules: &mut BTreeMap<i64, Vec<SeccompRule>>,
    handover_fd: std::os::fd::RawFd,
) {
    // An empty rule vector means "allow unconditionally"; if the profile
    // already grants sendmsg outright, narrowing it here would be a regression.
    if rules.get(&libc::SYS_sendmsg).is_some_and(Vec::is_empty) {
        return;
    }

    let condition = SeccompCondition::new(
        0,
        SeccompCmpArgLen::Dword,
        SeccompCmpOp::Eq,
        handover_fd as u64,
    );
    if let Ok(rule) = condition.and_then(|condition| SeccompRule::new(vec![condition])) {
        rules.entry(libc::SYS_sendmsg).or_default().push(rule);
    }
}

#[cfg(target_os = "linux")]
thread_local! {
    /// Hand-off slot between building the filter and configuring `pre_exec`,
    /// which run in the same call on the same thread.
    static LISTENER_CHANNEL_PARENT: std::cell::RefCell<Option<OwnedFd>> =
        const { std::cell::RefCell::new(None) };
}

#[cfg(target_os = "linux")]
fn build_linux_seccomp_rules(net: &NetLevel) -> BTreeMap<i64, Vec<SeccompRule>> {
    let mut rules = BTreeMap::new();
    // Rules describe the ALLOWED syscalls. Everything absent from this map hits
    // the filter's mismatch action (`EPERM`), so a syscall that is new, obscure,
    // or simply unforeseen is denied instead of silently permitted.
    for syscall in linux_seccomp_allowed_syscalls(net) {
        rules.insert(syscall, Vec::new());
    }
    restrict_prctl_from_installing_filters(&mut rules);
    rules
}

/// Narrows `prctl` so the sandboxed process cannot install a seccomp filter.
///
/// A child-installed filter can only ever restrict further, so this is not an
/// escape — but action precedence is not about restriction. `SECCOMP_RET_ERRNO`
/// outranks `SECCOMP_RET_USER_NOTIF`, so a child that installs an `EPERM`
/// filter of its own keeps being denied while ClawCrate stops being told: the
/// syscalls vanish from the audit trail instead of appearing in it.
///
/// `prctl` stays available for everything else, because programs legitimately
/// use it for thread names, dumpability and similar. Only the one operation
/// that would blind the record is refused.
#[cfg(target_os = "linux")]
fn restrict_prctl_from_installing_filters(rules: &mut BTreeMap<i64, Vec<SeccompRule>>) {
    // BPF can compare scalar arguments, and `prctl`'s option is its first, so
    // this is expressible in the filter itself rather than after the fact.
    let condition = SeccompCondition::new(
        0,
        SeccompCmpArgLen::Dword,
        SeccompCmpOp::Ne,
        libc::PR_SET_SECCOMP as u64,
    );
    let rule = condition.and_then(|condition| SeccompRule::new(vec![condition]));
    match rule {
        Ok(rule) => {
            rules.insert(libc::SYS_prctl, vec![rule]);
        }
        Err(_) => {
            // Expressing the condition failed, so the choice is between an
            // unconditional allow and no `prctl` at all. Deny-by-default says
            // remove it: a build that breaks is visible, a silenced audit trail
            // is not.
            rules.remove(&libc::SYS_prctl);
        }
    }
}

/// Syscalls a sandboxed process is allowed to make.
///
/// The posture is deny-by-default: this set is what the filter permits, and
/// anything else returns `EPERM`. The set is deliberately *generous* rather than
/// minimal. The security property being bought here is that unknown and future
/// syscalls are denied; it is not improved by withholding syscalls that ordinary
/// programs need, and withholding them would break real workloads for no gain.
///
/// What is deliberately absent is the dangerous surface: process inspection and
/// injection (`ptrace`, `process_vm_readv`/`writev`, `pidfd_getfd`, `kcmp`),
/// namespace and mount manipulation (`unshare`, `setns`, `mount`, `pivot_root`,
/// `chroot`, the `fsopen` family), kernel and module control (`init_module`,
/// `kexec_load`, `bpf`, `perf_event_open`, `iopl`, `syslog`), key management
/// (`add_key`, `keyctl`, `request_key`), host-wide time and identity
/// (`settimeofday`, `clock_settime`, `adjtimex`, `sethostname`), and the
/// asynchronous-execution surface (`io_uring_*`, `userfaultfd`).
#[cfg(target_os = "linux")]
fn linux_seccomp_allowed_syscalls(net: &NetLevel) -> Vec<i64> {
    let mut allowed: Vec<i64> = vec![
        // Process and thread lifecycle.
        libc::SYS_execve,
        libc::SYS_execveat,
        libc::SYS_exit,
        libc::SYS_exit_group,
        libc::SYS_clone,
        libc::SYS_wait4,
        libc::SYS_waitid,
        libc::SYS_set_tid_address,
        libc::SYS_set_robust_list,
        libc::SYS_get_robust_list,
        libc::SYS_gettid,
        libc::SYS_getpid,
        libc::SYS_getppid,
        libc::SYS_getpgid,
        libc::SYS_setpgid,
        libc::SYS_getsid,
        libc::SYS_setsid,
        libc::SYS_prctl,
        libc::SYS_rseq,
        libc::SYS_sched_yield,
        libc::SYS_sched_getaffinity,
        libc::SYS_sched_setaffinity,
        libc::SYS_sched_getparam,
        libc::SYS_sched_setparam,
        libc::SYS_sched_getscheduler,
        libc::SYS_sched_get_priority_max,
        libc::SYS_sched_get_priority_min,
        libc::SYS_getpriority,
        libc::SYS_setpriority,
        libc::SYS_capget,
        libc::SYS_membarrier,
        // Memory management.
        libc::SYS_brk,
        libc::SYS_mmap,
        libc::SYS_munmap,
        libc::SYS_mprotect,
        libc::SYS_mremap,
        libc::SYS_madvise,
        libc::SYS_msync,
        libc::SYS_mincore,
        libc::SYS_mlock,
        libc::SYS_munlock,
        libc::SYS_mlockall,
        libc::SYS_munlockall,
        libc::SYS_memfd_create,
        // File descriptors and I/O.
        libc::SYS_read,
        libc::SYS_write,
        libc::SYS_readv,
        libc::SYS_writev,
        libc::SYS_pread64,
        libc::SYS_pwrite64,
        libc::SYS_preadv,
        libc::SYS_pwritev,
        libc::SYS_openat,
        libc::SYS_close,
        libc::SYS_lseek,
        libc::SYS_dup,
        libc::SYS_dup3,
        libc::SYS_pipe2,
        libc::SYS_fcntl,
        libc::SYS_ioctl,
        libc::SYS_flock,
        libc::SYS_fsync,
        libc::SYS_fdatasync,
        libc::SYS_ftruncate,
        libc::SYS_truncate,
        libc::SYS_fallocate,
        libc::SYS_splice,
        libc::SYS_tee,
        libc::SYS_copy_file_range,
        // Metadata and directory traversal.
        libc::SYS_fstat,
        libc::SYS_newfstatat,
        libc::SYS_statx,
        libc::SYS_statfs,
        libc::SYS_fstatfs,
        libc::SYS_faccessat,
        libc::SYS_readlinkat,
        libc::SYS_getcwd,
        libc::SYS_chdir,
        libc::SYS_fchdir,
        libc::SYS_getdents64,
        libc::SYS_umask,
        libc::SYS_fchmod,
        libc::SYS_fchmodat,
        libc::SYS_fchown,
        libc::SYS_fchownat,
        libc::SYS_utimensat,
        // Namespace-local filesystem mutation (still gated by Landlock).
        libc::SYS_mkdirat,
        libc::SYS_unlinkat,
        libc::SYS_renameat2,
        libc::SYS_linkat,
        libc::SYS_symlinkat,
        libc::SYS_mknodat,
        // Extended attributes.
        libc::SYS_getxattr,
        libc::SYS_lgetxattr,
        libc::SYS_fgetxattr,
        libc::SYS_listxattr,
        libc::SYS_llistxattr,
        libc::SYS_flistxattr,
        libc::SYS_setxattr,
        libc::SYS_lsetxattr,
        libc::SYS_fsetxattr,
        libc::SYS_removexattr,
        libc::SYS_lremovexattr,
        libc::SYS_fremovexattr,
        // Signals.
        libc::SYS_rt_sigaction,
        libc::SYS_rt_sigprocmask,
        libc::SYS_rt_sigreturn,
        libc::SYS_rt_sigpending,
        libc::SYS_rt_sigsuspend,
        libc::SYS_rt_sigtimedwait,
        libc::SYS_rt_sigqueueinfo,
        libc::SYS_rt_tgsigqueueinfo,
        libc::SYS_sigaltstack,
        libc::SYS_kill,
        libc::SYS_tkill,
        libc::SYS_tgkill,
        libc::SYS_restart_syscall,
        libc::SYS_signalfd4,
        // Time.
        libc::SYS_clock_gettime,
        libc::SYS_clock_getres,
        libc::SYS_clock_nanosleep,
        libc::SYS_gettimeofday,
        libc::SYS_nanosleep,
        libc::SYS_times,
        libc::SYS_timer_create,
        libc::SYS_timer_settime,
        libc::SYS_timer_gettime,
        libc::SYS_timer_getoverrun,
        libc::SYS_timer_delete,
        libc::SYS_timerfd_create,
        libc::SYS_timerfd_settime,
        libc::SYS_timerfd_gettime,
        libc::SYS_setitimer,
        libc::SYS_getitimer,
        // Waiting and event notification.
        libc::SYS_futex,
        libc::SYS_ppoll,
        libc::SYS_pselect6,
        libc::SYS_epoll_create1,
        libc::SYS_epoll_ctl,
        libc::SYS_epoll_pwait,
        libc::SYS_eventfd2,
        libc::SYS_inotify_init1,
        libc::SYS_inotify_add_watch,
        libc::SYS_inotify_rm_watch,
        // Credentials (read-mostly; `NO_NEW_PRIVS` prevents escalation).
        libc::SYS_getuid,
        libc::SYS_geteuid,
        libc::SYS_getgid,
        libc::SYS_getegid,
        libc::SYS_getgroups,
        libc::SYS_getresuid,
        libc::SYS_getresgid,
        libc::SYS_setuid,
        libc::SYS_setgid,
        libc::SYS_setgroups,
        libc::SYS_setresuid,
        libc::SYS_setresgid,
        // Resource limits and accounting.
        libc::SYS_getrlimit,
        libc::SYS_setrlimit,
        libc::SYS_prlimit64,
        libc::SYS_getrusage,
        // System information and entropy.
        libc::SYS_uname,
        libc::SYS_sysinfo,
        libc::SYS_getrandom,
        // System V IPC (used by runtimes such as CPython's multiprocessing).
        libc::SYS_shmget,
        libc::SYS_shmat,
        libc::SYS_shmdt,
        libc::SYS_shmctl,
        libc::SYS_semget,
        libc::SYS_semop,
        libc::SYS_semctl,
        libc::SYS_msgget,
        libc::SYS_msgsnd,
        libc::SYS_msgrcv,
        libc::SYS_msgctl,
    ];

    // Syscalls the `libc` crate only exposes on x86_64. arm64 either provides
    // the `*at` variant listed above instead, or (for `sendfile`) simply does
    // not export the constant. Gating keeps the crate building for both release
    // targets; on arm64 a caller that invokes one of these directly receives
    // EPERM and is expected to fall back, as glibc and Go runtimes do.
    #[cfg(target_arch = "x86_64")]
    allowed.extend_from_slice(&[
        libc::SYS_sendfile,
        libc::SYS_open,
        libc::SYS_stat,
        libc::SYS_lstat,
        libc::SYS_access,
        libc::SYS_poll,
        libc::SYS_select,
        libc::SYS_pipe,
        libc::SYS_dup2,
        libc::SYS_fork,
        libc::SYS_vfork,
        libc::SYS_getdents,
        libc::SYS_readlink,
        libc::SYS_unlink,
        libc::SYS_rename,
        libc::SYS_rmdir,
        libc::SYS_mkdir,
        libc::SYS_link,
        libc::SYS_symlink,
        libc::SYS_chmod,
        libc::SYS_chown,
        libc::SYS_lchown,
        libc::SYS_utime,
        libc::SYS_utimes,
        libc::SYS_futimesat,
        libc::SYS_creat,
        libc::SYS_mknod,
        libc::SYS_epoll_create,
        libc::SYS_epoll_wait,
        libc::SYS_inotify_init,
        libc::SYS_eventfd,
        libc::SYS_signalfd,
        libc::SYS_alarm,
        libc::SYS_pause,
        libc::SYS_time,
        libc::SYS_getpgrp,
        libc::SYS_arch_prctl,
        libc::SYS_renameat,
    ]);

    // Network syscalls are granted only when the profile allows network access.
    // Under `NetLevel::None` they stay out of the allowlist, so socket creation
    // fails at the syscall layer.
    if !matches!(net, NetLevel::None) {
        allowed.extend_from_slice(&[
            libc::SYS_socket,
            libc::SYS_socketpair,
            libc::SYS_connect,
            libc::SYS_bind,
            libc::SYS_listen,
            libc::SYS_accept,
            libc::SYS_accept4,
            libc::SYS_getsockname,
            libc::SYS_getpeername,
            libc::SYS_setsockopt,
            libc::SYS_getsockopt,
            libc::SYS_sendto,
            libc::SYS_recvfrom,
            libc::SYS_sendmsg,
            libc::SYS_recvmsg,
            libc::SYS_sendmmsg,
            libc::SYS_recvmmsg,
            libc::SYS_shutdown,
        ]);
    }

    allowed
}

/// Syscalls that must never appear in the allowlist, whatever the profile.
///
/// With a deny-by-default filter these are already denied by omission; the list
/// exists so a regression that widens the allowlist is caught by a test rather
/// than by an incident. It covers the classes that matter for a sandbox escape:
/// process inspection and injection, namespace and mount manipulation, kernel
/// and module control, key management, host-wide time and identity, and the
/// asynchronous-execution surface.
#[cfg(all(target_os = "linux", test))]
fn linux_seccomp_forbidden_syscalls() -> Vec<i64> {
    let mut forbidden = vec![
        // Process inspection and injection.
        libc::SYS_ptrace,
        libc::SYS_process_vm_readv,
        libc::SYS_process_vm_writev,
        libc::SYS_kcmp,
        // Namespaces, mounts, and root pivoting.
        libc::SYS_mount,
        libc::SYS_umount2,
        libc::SYS_unshare,
        libc::SYS_setns,
        libc::SYS_pivot_root,
        libc::SYS_chroot,
        // Kernel and module control.
        libc::SYS_init_module,
        libc::SYS_finit_module,
        libc::SYS_delete_module,
        libc::SYS_kexec_load,
        libc::SYS_reboot,
        libc::SYS_swapon,
        libc::SYS_swapoff,
        libc::SYS_bpf,
        libc::SYS_perf_event_open,
        libc::SYS_syslog,
        // Key management.
        libc::SYS_add_key,
        libc::SYS_keyctl,
        libc::SYS_request_key,
        // Host-wide time and identity.
        libc::SYS_settimeofday,
        libc::SYS_clock_settime,
        libc::SYS_adjtimex,
        libc::SYS_sethostname,
        libc::SYS_setdomainname,
        // Asynchronous execution and descriptor stealing.
        libc::SYS_userfaultfd,
        libc::SYS_io_uring_setup,
        libc::SYS_io_uring_enter,
        libc::SYS_io_uring_register,
        libc::SYS_pidfd_getfd,
    ];
    forbidden.extend_from_slice(linux_seccomp_forbidden_arch_syscalls());
    forbidden
}

/// Architecture-specific additions to the forbidden set: x86_64 exposes direct
/// I/O-port and LDT manipulation that other architectures do not have.
#[cfg(all(target_os = "linux", test, target_arch = "x86_64"))]
fn linux_seccomp_forbidden_arch_syscalls() -> &'static [i64] {
    &[libc::SYS_iopl, libc::SYS_ioperm, libc::SYS_modify_ldt]
}

#[cfg(all(target_os = "linux", test, not(target_arch = "x86_64")))]
fn linux_seccomp_forbidden_arch_syscalls() -> &'static [i64] {
    &[]
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
    /// Applies the syscall filter.
    ///
    /// Returns the supervisor's end of the listener handover channel when the
    /// filter was built to notify rather than to return `EPERM` directly. The
    /// caller must keep it until the child has been spawned; `None` means the
    /// run uses the plain filter and produces no syscall denial records.
    fn apply_seccomp(
        &self,
        command: &mut Command,
        prepared: &PreparedLinuxSandbox,
    ) -> Result<Option<OwnedFd>, Box<dyn std::error::Error + Send + Sync>>;
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
    ) -> Result<Option<OwnedFd>, Box<dyn std::error::Error + Send + Sync>> {
        #[cfg(target_os = "linux")]
        {
            let context = prepare_linux_seccomp_context(prepared)?;
            Ok(configure_linux_seccomp_pre_exec(command, context))
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = (command, prepared);
            Ok(None)
        }
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
        self.launch_with_stdio(prepared, Stdio::null(), Stdio::piped(), Stdio::piped())
    }

    pub fn launch_with_stdio(
        &self,
        prepared: &PreparedLinuxSandbox,
        stdin: Stdio,
        stdout: Stdio,
        stderr: Stdio,
    ) -> Result<LinuxSandboxedChild, LinuxSandboxError> {
        if prepared.command.is_empty() {
            return Err(LinuxSandboxError::EmptyCommand);
        }

        let mut command = Command::new(&prepared.command[0]);
        command.args(&prepared.command[1..]);
        command.current_dir(&prepared.cwd);
        command.stdin(stdin);
        command.stdout(stdout);
        command.stderr(stderr);
        #[cfg(unix)]
        command.process_group(0);
        command.env_clear();
        command.envs(prepared.scrubbed_env.iter().cloned());
        let listener_channel =
            apply_enforcement_steps(self.enforcer.as_ref(), &mut command, prepared)?;

        // Started before spawning: the child waits in its pre-exec hook to be
        // acknowledged, and `spawn` does not return until the child execs, so
        // supervising afterwards would deadlock the two against each other.
        let notify_supervisor = start_seccomp_notify_supervisor(listener_channel);

        let child = command.spawn().map_err(LinuxSandboxError::Spawn)?;

        Ok(LinuxSandboxedChild {
            child,
            notify_supervisor,
        })
    }
}

#[cfg(target_os = "linux")]
fn start_seccomp_notify_supervisor(
    listener_channel: Option<OwnedFd>,
) -> Option<crate::linux_notify::runtime::NotifySupervisor> {
    let channel = listener_channel?;
    crate::linux_notify::runtime::NotifySupervisor::start(channel).ok()
}

#[cfg(not(target_os = "linux"))]
fn start_seccomp_notify_supervisor(listener_channel: Option<OwnedFd>) -> Option<()> {
    let _ = listener_channel;
    None
}

pub struct LinuxSandboxedChild {
    child: Child,
    /// Answers notifications for as long as this handle lives, which is why it
    /// is owned by the child rather than dropped at the end of `launch`.
    #[cfg(target_os = "linux")]
    notify_supervisor: Option<crate::linux_notify::runtime::NotifySupervisor>,
    // Off Linux there is no supervisor to hold; the field exists so the struct
    // has one shape and the launch path needs no platform branch.
    #[cfg(not(target_os = "linux"))]
    #[allow(dead_code)]
    notify_supervisor: Option<()>,
}

impl LinuxSandboxedChild {
    pub fn pid(&self) -> u32 {
        self.child.id()
    }

    /// Syscalls the supervisor refused, with the number of distinct records
    /// dropped past the retention cap. Empty when the run used the plain
    /// filter, which enforces identically but records nothing.
    pub fn drain_denied_syscalls(&self) -> (Vec<crate::linux_notify::DeniedSyscall>, usize) {
        self.denied_syscall_log()
            .map(|log| log.drain())
            .unwrap_or_default()
    }

    /// Handle onto the denial record that outlives this child.
    ///
    /// `wait_with_output` consumes the child, so a caller that needs both the
    /// output and the denials takes this first. The supervisor is joined while
    /// the child handle drops, which happens before `wait_with_output` returns,
    /// so draining afterwards sees a complete record.
    pub fn denied_syscall_log(&self) -> Option<crate::linux_notify::DeniedSyscallLog> {
        #[cfg(target_os = "linux")]
        {
            self.notify_supervisor
                .as_ref()
                .map(|supervisor| supervisor.log())
        }
        #[cfg(not(target_os = "linux"))]
        {
            None
        }
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
) -> Result<Option<OwnedFd>, LinuxSandboxError> {
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

    let listener_channel = enforcer
        .apply_seccomp(command, prepared)
        .map_err(|source| LinuxSandboxError::Enforcement {
            step: EnforcementStep::Seccomp,
            source,
        })?;

    Ok(listener_channel)
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
    // Landlock only mediates a right that is declared here. Declaring the read
    // rights alongside the write rights is what makes `fs_read` an actual
    // allowlist: anything not granted below becomes unreadable.
    let ruleset_attr = LandlockRulesetAttr {
        handled_access_fs: context.write_access_mask | context.read_access_mask,
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

    // Writable paths are granted read as well: a path the process may write but
    // not read would break nearly every tool.
    // Write rules carry write rights only. Read rights come from the read set,
    // which already contains every writable path that exists. Unioning read into
    // the write rules would leak reads whenever a missing write path anchored on
    // a broad ancestor (for example `./target` under a nonexistent parent).
    let rule_sets = [
        (&context.allowed_write_paths, context.write_access_mask),
        (&context.allowed_read_paths, context.read_access_mask),
    ];

    for (path_grants, allowed_access) in rule_sets {
        for grant in path_grants {
            // Directory-only rights on a non-directory anchor are rejected with
            // EINVAL, so mask the access set down to the anchor's file type.
            let allowed_access = landlock_access_for_path_type(allowed_access, grant.is_dir);
            if allowed_access == 0 {
                continue;
            }
            let path_rule = LandlockPathBeneathAttr {
                allowed_access,
                parent_fd: grant.fd.as_raw_fd(),
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
fn configure_linux_seccomp_pre_exec(
    command: &mut Command,
    context: LinuxSeccompContext,
) -> Option<OwnedFd> {
    let supervisor_end = LISTENER_CHANNEL_PARENT.with(|slot| slot.borrow_mut().take());
    // SAFETY:
    // - The closure runs in the child post-fork/pre-exec.
    // - The seccomp BPF program is fully materialized in the parent process.
    // - Any failure returns `io::Error`, aborting spawn/exec in fail-closed mode.
    unsafe {
        command.pre_exec(move || apply_linux_seccomp_filter(&context));
    }
    supervisor_end
}

#[cfg(target_os = "linux")]
#[allow(unsafe_code)]
fn apply_linux_seccomp_filter(context: &LinuxSeccompContext) -> io::Result<()> {
    // SAFETY: prctl contract is satisfied for PR_SET_NO_NEW_PRIVS.
    let prctl_result = unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) };
    if prctl_result != 0 {
        return Err(io::Error::from_raw_os_error(Errno::last_raw()));
    }

    let Some(handover) = context.listener_channel_child.as_ref() else {
        return seccompiler::apply_filter(context.program.as_slice())
            .map_err(seccomp_apply_error_as_io_error);
    };

    // Install the notifying filter and hand the listener to the supervisor.
    //
    // Ordering is load-bearing: the filter is live from this point, so the
    // `sendmsg` below is itself subject to it. `sendmsg` is allowlisted for
    // exactly this reason — were it not, this call would block waiting for a
    // supervisor that is still waiting for this very message.
    let listener = crate::linux_notify::runtime::install_filter_with_listener(
        context.notify_program.as_slice(),
    )?;
    let send_result =
        crate::linux_notify::runtime::hand_over_listener(handover.as_raw_fd(), listener);
    // SAFETY: `listener` was just returned by seccomp and is not used again.
    unsafe { libc::close(listener) };
    send_result
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
    use std::os::fd::OwnedFd;
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

    #[cfg(target_os = "linux")]
    use super::LINUX_SYSTEM_READ_PATHS;
    use super::{
        apply_enforcement_steps, EnforcementStep, LinuxEnforcer, LinuxSandbox, PreparedLinuxSandbox,
    };
    #[cfg(target_os = "linux")]
    use super::{landlock_errno_to_io_error, seccomp_apply_error_as_io_error};
    #[cfg(target_os = "linux")]
    use nix::libc;

    /// The seccomp posture is deny-by-default: the escape-relevant syscall
    /// classes must never be reachable through the allowlist, with or without
    /// network access.
    #[cfg(target_os = "linux")]
    #[test]
    fn seccomp_allowlist_never_contains_escape_syscalls() {
        for net in [NetLevel::None, NetLevel::Open] {
            let allowed = super::linux_seccomp_allowed_syscalls(&net);
            for forbidden in super::linux_seccomp_forbidden_syscalls() {
                assert!(
                    !allowed.contains(&forbidden),
                    "syscall {forbidden} must never be allowed (net: {net:?})"
                );
            }
        }
    }

    /// Network syscalls are gated on the profile: absent under `NetLevel::None`,
    /// present once the profile grants network access.
    #[cfg(target_os = "linux")]
    #[test]
    fn seccomp_allowlist_gates_socket_syscalls_on_network_level() {
        let denied = super::linux_seccomp_allowed_syscalls(&NetLevel::None);
        let granted = super::linux_seccomp_allowed_syscalls(&NetLevel::Open);

        assert!(!denied.contains(&libc::SYS_socket));
        assert!(!denied.contains(&libc::SYS_connect));
        assert!(granted.contains(&libc::SYS_socket));
        assert!(granted.contains(&libc::SYS_connect));

        // Everything a process needs to start must be present regardless.
        for required in [
            libc::SYS_execve,
            libc::SYS_exit_group,
            libc::SYS_mmap,
            libc::SYS_mprotect,
            libc::SYS_brk,
            libc::SYS_futex,
            libc::SYS_read,
            libc::SYS_write,
            libc::SYS_openat,
            libc::SYS_close,
        ] {
            assert!(
                denied.contains(&required),
                "syscall {required} is required for any process to run"
            );
        }
    }

    /// The system read set must stay enumerated. Landlock cannot deny a path
    /// inside a granted one, so a coarse prefix silently grants everything
    /// nested under it — `/usr` would expose `/usr/local/etc`, and `/opt` would
    /// expose vendor software configuration.
    #[cfg(target_os = "linux")]
    #[test]
    fn system_read_paths_are_enumerated_not_coarse() {
        for coarse in [
            "/", "/usr", "/opt", "/etc", "/var", "/home", "/root", "/proc",
        ] {
            assert!(
                !LINUX_SYSTEM_READ_PATHS.contains(&coarse),
                "`{coarse}` must not be granted as a whole: everything beneath it \
                 becomes readable and Landlock cannot carve out exceptions"
            );
        }

        // Paths that are load-bearing rather than hardening: without them a
        // sandboxed process fails to start or cannot resolve names.
        for required in [
            "/bin",
            "/lib",
            "/usr/bin",
            "/usr/lib",
            "/etc/ld.so.cache",
            "/etc/resolv.conf",
            "/run/systemd/resolve",
        ] {
            assert!(
                LINUX_SYSTEM_READ_PATHS.contains(&required),
                "`{required}` must stay in the system read set"
            );
        }
    }

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
        ) -> Result<Option<OwnedFd>, Box<dyn std::error::Error + Send + Sync>> {
            self.calls
                .lock()
                .expect("lock calls")
                .push(EnforcementStep::Seccomp);
            Ok(None)
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
            read_isolation_enforced: None,
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
