//! Exact observation of syscall denials, via seccomp user notification.
//!
//! The sandbox denies a syscall by returning `EPERM` from the kernel filter.
//! That is correct enforcement but leaves no record: nothing reaches the parent,
//! so `audit.ndjson` cannot say what was refused.
//!
//! User notification moves the *decision* — not the enforcement — into
//! ClawCrate. The filter's mismatch action becomes `SECCOMP_RET_USER_NOTIF`, the
//! child blocks, and the supervisor records the attempt and returns the same
//! `EPERM` the kernel would have. The child observes identical behaviour; the
//! difference is that the refusal is now evidence.
//!
//! This is exact rather than inferred, because ClawCrate causes the denial it
//! records. It is also free of the TOCTOU hazard that makes user notification
//! unsuitable for path-based policy: the decision here is a function of the
//! syscall number, an immutable scalar in the notification, and never of a
//! pointer the child could rewrite.
//!
//! # Two invariants that hang the child if broken
//!
//! * **Every notification must be answered.** A notification nobody replies to
//!   blocks the child forever. The supervisor therefore runs for the child's
//!   whole lifetime and answers everything, and it uses `poll()` rather than
//!   blocking in `recv`, because only `poll` distinguishes "a notification is
//!   waiting" from "the child is gone".
//! * **The filter is installed before the listener fd is handed over.** The
//!   child sends the fd with `sendmsg`, which must therefore be allowlisted. If
//!   it is not, the child blocks in `sendmsg` waiting for a supervisor that is
//!   still waiting for that very `sendmsg` to arrive.
//!
//! Both are covered by tests. Every failure path here degrades to the plain
//! `EPERM` filter rather than risking a hang: losing the record is bad, hanging
//! a user's build is worse.

// The mechanism only exists on Linux, but the whole module is compiled
// everywhere so its logic tests run in both CI matrices. Off Linux the pieces
// below have no caller, which is expected rather than an oversight.
#![cfg_attr(not(target_os = "linux"), allow(dead_code))]

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

/// `SECCOMP_RET_USER_NOTIF`: suspend the syscall and notify the listener.
pub(crate) const SECCOMP_RET_USER_NOTIF: u32 = 0x7fc0_0000;
/// `SECCOMP_RET_ERRNO`: return the low 16 bits as an errno.
pub(crate) const SECCOMP_RET_ERRNO: u32 = 0x0005_0000;
/// `BPF_RET | BPF_K`: return a constant.
pub(crate) const BPF_RET_K: u16 = 0x06;

/// Upper bound on retained denial records, matching the egress denial buffer: a
/// process that hammers a blocked syscall must not grow this without limit.
pub(crate) const MAX_RECORDED_DENIALS: usize = 256;

/// A syscall the supervisor refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeniedSyscall {
    /// Syscall number, as reported by the kernel for the child's architecture.
    pub nr: i32,
    /// The process that attempted it — a descendant may differ from the child.
    pub pid: u32,
}

impl DeniedSyscall {
    /// The blocked resource, as recorded in the audit event.
    pub fn resource(&self) -> String {
        match syscall_name(self.nr) {
            Some(name) => format!("syscall:{name}"),
            None => format!("syscall:{}", self.nr),
        }
    }

    /// Human-readable explanation, as recorded in the audit event.
    pub fn reason_text(&self) -> String {
        "syscall not in the profile allowlist (seccomp)".to_string()
    }
}

#[derive(Debug, Default)]
struct DenialBuffer {
    denials: Vec<DeniedSyscall>,
    dropped: usize,
}

/// Shared, bounded record of refused syscalls, written by the supervisor thread
/// and drained by the CLI once the child has exited.
#[derive(Debug, Clone, Default)]
pub struct DeniedSyscallLog {
    inner: Arc<Mutex<DenialBuffer>>,
}

impl DeniedSyscallLog {
    fn record(&self, denial: DeniedSyscall) {
        // A poisoned lock means a previous record panicked. Recover rather than
        // propagate: the supervisor must keep answering notifications, because
        // the alternative is a child blocked forever.
        let mut buffer = match self.inner.lock() {
            Ok(buffer) => buffer,
            Err(poisoned) => poisoned.into_inner(),
        };
        // Repeats are common — a retry loop hits the same wall every pass — so
        // collapse them rather than bury the trail under identical entries.
        if buffer.denials.contains(&denial) {
            return;
        }
        if buffer.denials.len() >= MAX_RECORDED_DENIALS {
            buffer.dropped = buffer.dropped.saturating_add(1);
            return;
        }
        buffer.denials.push(denial);
    }

    /// Removes and returns every recorded denial, with the number of distinct
    /// records dropped after the buffer filled up.
    pub fn drain(&self) -> (Vec<DeniedSyscall>, usize) {
        let mut buffer = match self.inner.lock() {
            Ok(buffer) => buffer,
            Err(poisoned) => poisoned.into_inner(),
        };
        let dropped = buffer.dropped;
        buffer.dropped = 0;
        (std::mem::take(&mut buffer.denials), dropped)
    }
}

/// Rewrites a compiled filter's `EPERM` returns into user notifications.
///
/// `seccompiler` has no notify action, so the filter is built as usual and its
/// mismatch return is retargeted here. Only the exact constant the mismatch
/// action produces is touched, and the count is returned so the caller can
/// refuse to launch if the rewrite did not match what it expected — a silent
/// no-match would mean the supervisor waits for notifications that never come.
#[cfg(test)]
pub(crate) fn rewrite_errno_returns_to_user_notif(
    instructions: &mut [SockFilter],
    errno: u32,
) -> usize {
    let mut rewritten = 0usize;
    for instruction in instructions.iter_mut() {
        if let Some(replacement) = user_notif_replacement(instruction.code, instruction.k, errno) {
            instruction.k = replacement;
            rewritten += 1;
        }
    }
    rewritten
}

/// The decision behind the rewrite, isolated so both the Linux code (operating
/// on `libc::sock_filter`) and the tests (operating on the mirror type) share
/// exactly one definition of what may be retargeted.
///
/// Returns the replacement value, or `None` when the instruction must be left
/// alone. Only a return-constant carrying precisely this errno qualifies; a
/// comparison that happens to hold the same value is control flow, and
/// rewriting it would silently change what the filter allows.
pub(crate) fn user_notif_replacement(code: u16, k: u32, errno: u32) -> Option<u32> {
    let target = SECCOMP_RET_ERRNO | (errno & 0x0000_ffff);
    (code == BPF_RET_K && k == target).then_some(SECCOMP_RET_USER_NOTIF)
}

/// Mirror of `libc::sock_filter`, so the rewrite above is unit-testable on any
/// platform rather than only where `libc` exposes the type.
#[cfg(test)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(C)]
pub(crate) struct SockFilter {
    pub code: u16,
    pub jt: u8,
    pub jf: u8,
    pub k: u32,
}

/// Whether the supervisor should stop; shared with the polling thread.
#[derive(Debug, Clone, Default)]
pub(crate) struct SupervisorShutdown {
    flag: Arc<AtomicBool>,
}

impl SupervisorShutdown {
    pub(crate) fn request(&self) {
        self.flag.store(true, Ordering::SeqCst);
    }

    pub(crate) fn requested(&self) -> bool {
        self.flag.load(Ordering::SeqCst)
    }
}

/// Best-effort translation of a syscall number to its name, for readable audit
/// entries. Falls back to the number, which is never wrong, only less legible.
fn syscall_name(nr: i32) -> Option<&'static str> {
    // Deliberately short: these are the denials worth naming in a report, the
    // ones that read as an escape attempt rather than an ordinary failure.
    #[cfg(target_os = "linux")]
    {
        use nix::libc;
        let named: &[(i64, &'static str)] = &[
            (libc::SYS_ptrace, "ptrace"),
            (libc::SYS_mount, "mount"),
            (libc::SYS_umount2, "umount2"),
            (libc::SYS_reboot, "reboot"),
            (libc::SYS_kexec_load, "kexec_load"),
            (libc::SYS_init_module, "init_module"),
            (libc::SYS_delete_module, "delete_module"),
            (libc::SYS_swapon, "swapon"),
            (libc::SYS_swapoff, "swapoff"),
            (libc::SYS_setns, "setns"),
            (libc::SYS_unshare, "unshare"),
            (libc::SYS_pivot_root, "pivot_root"),
            (libc::SYS_chroot, "chroot"),
            (libc::SYS_bpf, "bpf"),
            (libc::SYS_perf_event_open, "perf_event_open"),
            (libc::SYS_seccomp, "seccomp"),
            (libc::SYS_keyctl, "keyctl"),
            (libc::SYS_add_key, "add_key"),
            (libc::SYS_request_key, "request_key"),
        ];
        named
            .iter()
            .find(|(number, _)| *number == nr as i64)
            .map(|(_, name)| *name)
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = nr;
        None
    }
}

#[cfg(target_os = "linux")]
pub(crate) mod runtime {
    use super::{DeniedSyscall, DeniedSyscallLog, SupervisorShutdown};
    use nix::libc;
    use std::io;
    use std::mem;
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
    use std::thread::JoinHandle;

    const SECCOMP_SET_MODE_FILTER: libc::c_uint = 1;
    const SECCOMP_FILTER_FLAG_NEW_LISTENER: libc::c_ulong = 1 << 3;

    // `_IOWR('!', 0, struct seccomp_notif)` and `_IOWR('!', 1, struct
    // seccomp_notif_resp)`. Both structures are fixed-size across Linux
    // architectures, so these encodings are architecture-independent.
    const SECCOMP_IOCTL_NOTIF_RECV: libc::c_ulong = 0xc050_2100;
    const SECCOMP_IOCTL_NOTIF_SEND: libc::c_ulong = 0xc018_2101;

    /// How long the parent waits for the child to hand over the listener.
    /// Bounded so a child that dies during setup cannot hang the run.
    const LISTENER_HANDOVER_TIMEOUT_SECONDS: i64 = 5;
    /// Poll slice; short enough to notice a requested shutdown promptly.
    const POLL_TIMEOUT_MILLIS: libc::c_int = 250;

    #[repr(C)]
    #[derive(Default)]
    struct SeccompData {
        nr: i32,
        arch: u32,
        instruction_pointer: u64,
        args: [u64; 6],
    }

    #[repr(C)]
    #[derive(Default)]
    struct SeccompNotif {
        id: u64,
        pid: u32,
        flags: u32,
        data: SeccompData,
    }

    #[repr(C)]
    #[derive(Default)]
    struct SeccompNotifResp {
        id: u64,
        val: i64,
        error: i32,
        flags: u32,
    }

    /// A connected pair used once, to move the listener fd out of the child.
    pub(crate) struct ListenerChannel {
        pub(crate) parent: OwnedFd,
        pub(crate) child: OwnedFd,
    }

    #[allow(unsafe_code)]
    pub(crate) fn listener_channel() -> io::Result<ListenerChannel> {
        let mut fds = [0 as RawFd; 2];
        // SAFETY: `fds` is a two-element array, which is what socketpair writes.
        //
        // `SOCK_CLOEXEC` closes both ends at `execve`. The child needs the
        // socket only in its pre-exec hook, so closing it at exec keeps the
        // sandboxed program from inheriting a channel to its own supervisor.
        let rc = unsafe {
            libc::socketpair(
                libc::AF_UNIX,
                libc::SOCK_STREAM | libc::SOCK_CLOEXEC,
                0,
                fds.as_mut_ptr(),
            )
        };
        if rc != 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: both descriptors were just created and are owned here.
        unsafe {
            Ok(ListenerChannel {
                parent: OwnedFd::from_raw_fd(fds[0]),
                child: OwnedFd::from_raw_fd(fds[1]),
            })
        }
    }

    /// Installs the filter and returns the notification listener.
    ///
    /// Runs in the child between fork and exec, so it allocates nothing.
    #[allow(unsafe_code)]
    pub(crate) fn install_filter_with_listener(
        instructions: &[libc::sock_filter],
    ) -> io::Result<RawFd> {
        let program = libc::sock_fprog {
            len: instructions.len() as u16,
            filter: instructions.as_ptr() as *mut libc::sock_filter,
        };
        // SAFETY: `program` points at a filter that outlives this call, and the
        // NEW_LISTENER flag makes seccomp return a descriptor rather than 0.
        let fd = unsafe {
            libc::syscall(
                libc::SYS_seccomp,
                SECCOMP_SET_MODE_FILTER,
                SECCOMP_FILTER_FLAG_NEW_LISTENER,
                &program as *const libc::sock_fprog,
            )
        };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(fd as RawFd)
    }

    /// Hands the listener to the parent and waits for it to be supervised.
    ///
    /// Called in the child, after the filter is live. The wait is the point:
    /// from the moment the filter is installed, any denied syscall suspends the
    /// child until someone answers, so the child must not run on until a
    /// supervisor exists. Without the handshake, a parent that failed to start
    /// one would leave the child blocked forever on its first denial — the
    /// filter cannot be taken back off.
    ///
    /// If the parent closes the channel instead of acknowledging, the read sees
    /// EOF and this fails, aborting the launch rather than proceeding
    /// unsupervised.
    #[allow(unsafe_code)]
    pub(crate) fn hand_over_listener(socket: RawFd, listener: RawFd) -> io::Result<()> {
        send_listener_fd(socket, listener)?;

        let mut acknowledgement = [0u8; 1];
        // SAFETY: reading one byte into a local buffer of that size.
        let read =
            unsafe { libc::read(socket, acknowledgement.as_mut_ptr() as *mut libc::c_void, 1) };
        if read == 1 {
            return Ok(());
        }
        if read < 0 {
            return Err(io::Error::last_os_error());
        }
        // EOF: the parent gave up before supervising.
        Err(io::Error::from_raw_os_error(libc::ECONNRESET))
    }

    #[allow(unsafe_code)]
    fn send_listener_fd(socket: RawFd, listener: RawFd) -> io::Result<()> {
        let mut payload: u8 = 0;
        let mut iov = libc::iovec {
            iov_base: &mut payload as *mut u8 as *mut libc::c_void,
            iov_len: 1,
        };
        let mut control = [0u8; 64];
        // SAFETY: msghdr is plain data; every pointer below refers to a local
        // that outlives the sendmsg call.
        unsafe {
            let mut message: libc::msghdr = mem::zeroed();
            message.msg_iov = &mut iov;
            message.msg_iovlen = 1;
            message.msg_control = control.as_mut_ptr() as *mut libc::c_void;
            message.msg_controllen = libc::CMSG_SPACE(mem::size_of::<RawFd>() as u32) as _;

            let header = libc::CMSG_FIRSTHDR(&message);
            if header.is_null() {
                return Err(io::Error::from_raw_os_error(libc::EINVAL));
            }
            (*header).cmsg_level = libc::SOL_SOCKET;
            (*header).cmsg_type = libc::SCM_RIGHTS;
            (*header).cmsg_len = libc::CMSG_LEN(mem::size_of::<RawFd>() as u32) as _;
            std::ptr::copy_nonoverlapping(&listener, libc::CMSG_DATA(header) as *mut RawFd, 1);

            if libc::sendmsg(socket, &message, 0) < 0 {
                return Err(io::Error::last_os_error());
            }
        }
        Ok(())
    }

    /// Receives the listener in the parent, giving up rather than blocking if
    /// the child never sends one.
    #[allow(unsafe_code)]
    fn receive_listener_fd(socket: RawFd) -> io::Result<OwnedFd> {
        let timeout = libc::timeval {
            tv_sec: LISTENER_HANDOVER_TIMEOUT_SECONDS,
            tv_usec: 0,
        };
        // SAFETY: setsockopt is given a correctly sized timeval.
        unsafe {
            libc::setsockopt(
                socket,
                libc::SOL_SOCKET,
                libc::SO_RCVTIMEO,
                &timeout as *const libc::timeval as *const libc::c_void,
                mem::size_of::<libc::timeval>() as libc::socklen_t,
            );
        }

        let mut payload: u8 = 0;
        let mut iov = libc::iovec {
            iov_base: &mut payload as *mut u8 as *mut libc::c_void,
            iov_len: 1,
        };
        let mut control = [0u8; 64];
        // SAFETY: as in `send_listener_fd`; all pointers refer to locals.
        unsafe {
            let mut message: libc::msghdr = mem::zeroed();
            message.msg_iov = &mut iov;
            message.msg_iovlen = 1;
            message.msg_control = control.as_mut_ptr() as *mut libc::c_void;
            message.msg_controllen = control.len() as _;

            if libc::recvmsg(socket, &mut message, 0) < 0 {
                return Err(io::Error::last_os_error());
            }
            let header = libc::CMSG_FIRSTHDR(&message);
            if header.is_null() || (*header).cmsg_type != libc::SCM_RIGHTS {
                return Err(io::Error::from_raw_os_error(libc::ENOMSG));
            }
            let mut listener: RawFd = -1;
            std::ptr::copy_nonoverlapping(
                libc::CMSG_DATA(header) as *const RawFd,
                &mut listener,
                1,
            );
            if listener < 0 {
                return Err(io::Error::from_raw_os_error(libc::EBADF));
            }
            Ok(OwnedFd::from_raw_fd(listener))
        }
    }

    /// Answers notifications for the child's lifetime, recording each one.
    pub(crate) struct NotifySupervisor {
        join: Option<JoinHandle<()>>,
        shutdown: SupervisorShutdown,
        log: DeniedSyscallLog,
    }

    impl NotifySupervisor {
        /// Takes over the listener the child sent and starts answering.
        ///
        /// Returns `Err` when no listener arrived, leaving the caller to run
        /// without denial records rather than with a stalled child.
        /// Starts supervising, without waiting for the child to exist.
        ///
        /// This must be called **before** `Command::spawn`. The child blocks in
        /// its pre-exec hook until acknowledged, and `spawn` does not return
        /// until the child execs — so a parent that only began supervising
        /// after `spawn` would be waiting for a child that is waiting for it.
        ///
        /// Returns immediately; the handover and acknowledgement happen on the
        /// supervisor thread.
        pub(crate) fn start(channel_parent: OwnedFd) -> io::Result<Self> {
            let log = DeniedSyscallLog::default();
            let shutdown = SupervisorShutdown::default();

            let thread_log = log.clone();
            let thread_shutdown = shutdown.clone();
            let join = std::thread::Builder::new()
                .name("clawcrate-seccomp-notify".to_string())
                .spawn(move || {
                    let Ok(listener) = receive_listener_fd(channel_parent.as_raw_fd()) else {
                        // Dropping the channel without acknowledging is the
                        // signal the child waits on: it aborts rather than
                        // running unsupervised behind a filter it cannot undo.
                        return;
                    };
                    if !acknowledge(channel_parent.as_raw_fd()) {
                        return;
                    }
                    supervise(listener, &thread_log, &thread_shutdown);
                })?;

            Ok(Self {
                join: Some(join),
                shutdown,
                log,
            })
        }

        pub(crate) fn log(&self) -> DeniedSyscallLog {
            self.log.clone()
        }
    }

    impl Drop for NotifySupervisor {
        fn drop(&mut self) {
            self.shutdown.request();
            if let Some(join) = self.join.take() {
                let _ = join.join();
            }
        }
    }

    /// Releases the child, now that someone is answering its notifications.
    #[allow(unsafe_code)]
    fn acknowledge(socket: RawFd) -> bool {
        let byte = [1u8; 1];
        // SAFETY: writing one byte from a local buffer of that size.
        let written = unsafe { libc::write(socket, byte.as_ptr() as *const libc::c_void, 1) };
        written == 1
    }

    #[allow(unsafe_code)]
    fn supervise(listener: OwnedFd, log: &DeniedSyscallLog, shutdown: &SupervisorShutdown) {
        let fd = listener.as_raw_fd();
        loop {
            if shutdown.requested() {
                return;
            }

            let mut poll_fd = libc::pollfd {
                fd,
                events: libc::POLLIN,
                revents: 0,
            };
            // SAFETY: a single, correctly initialised pollfd.
            let ready = unsafe { libc::poll(&mut poll_fd, 1, POLL_TIMEOUT_MILLIS) };
            if ready < 0 {
                let error = io::Error::last_os_error();
                if error.kind() == io::ErrorKind::Interrupted {
                    continue;
                }
                return;
            }
            if ready == 0 {
                continue;
            }
            // Every process holding the filter is gone; nothing left to answer.
            if poll_fd.revents & (libc::POLLHUP | libc::POLLERR | libc::POLLNVAL) != 0 {
                return;
            }
            if poll_fd.revents & libc::POLLIN == 0 {
                continue;
            }

            let mut request = SeccompNotif::default();
            // SAFETY: the ioctl fills a correctly sized, owned structure.
            let rc = unsafe {
                libc::ioctl(
                    fd,
                    SECCOMP_IOCTL_NOTIF_RECV,
                    &mut request as *mut SeccompNotif,
                )
            };
            if rc < 0 {
                let error = io::Error::last_os_error();
                // The attempting process died before we answered: nothing to
                // reply to, but keep serving whatever else is running.
                if matches!(error.raw_os_error(), Some(libc::ENOENT)) {
                    continue;
                }
                if error.kind() == io::ErrorKind::Interrupted {
                    continue;
                }
                return;
            }

            // Record before replying, so the trail cannot claim fewer denials
            // than the child actually experienced.
            log.record(DeniedSyscall {
                nr: request.data.nr,
                pid: request.pid,
            });

            let response = SeccompNotifResp {
                id: request.id,
                val: 0,
                // Exactly what the plain filter would have returned, so the
                // child cannot tell the two modes apart.
                error: -libc::EPERM,
                flags: 0,
            };
            // SAFETY: the ioctl reads a correctly sized, owned structure.
            let rc = unsafe {
                libc::ioctl(
                    fd,
                    SECCOMP_IOCTL_NOTIF_SEND,
                    &response as *const SeccompNotifResp,
                )
            };
            if rc < 0 {
                let error = io::Error::last_os_error();
                if matches!(error.raw_os_error(), Some(libc::ENOENT)) {
                    continue;
                }
                return;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{
        rewrite_errno_returns_to_user_notif, DeniedSyscall, DeniedSyscallLog, SockFilter,
        BPF_RET_K, MAX_RECORDED_DENIALS, SECCOMP_RET_ERRNO, SECCOMP_RET_USER_NOTIF,
    };

    const EPERM: u32 = 1;
    const SECCOMP_RET_ALLOW: u32 = 0x7fff_0000;

    fn ret(k: u32) -> SockFilter {
        SockFilter {
            code: BPF_RET_K,
            jt: 0,
            jf: 0,
            k,
        }
    }

    fn jeq(k: u32) -> SockFilter {
        SockFilter {
            code: 0x15,
            jt: 1,
            jf: 0,
            k,
        }
    }

    #[test]
    fn rewrites_only_the_mismatch_return() {
        let mut program = vec![
            jeq(60),
            ret(SECCOMP_RET_ALLOW),
            ret(SECCOMP_RET_ERRNO | EPERM),
        ];

        let rewritten = rewrite_errno_returns_to_user_notif(&mut program, EPERM);

        assert_eq!(rewritten, 1);
        assert_eq!(program[0], jeq(60), "comparisons must be untouched");
        assert_eq!(
            program[1].k, SECCOMP_RET_ALLOW,
            "allow returns must be untouched"
        );
        assert_eq!(program[2].k, SECCOMP_RET_USER_NOTIF);
    }

    #[test]
    fn never_rewrites_a_comparison_that_happens_to_hold_the_same_constant() {
        // A jump whose comparison value equals the errno return constant is not
        // a return. Rewriting it would corrupt the filter's control flow and
        // silently change what the sandbox allows.
        let constant = SECCOMP_RET_ERRNO | EPERM;
        let mut program = vec![jeq(constant), ret(SECCOMP_RET_ALLOW)];

        let rewritten = rewrite_errno_returns_to_user_notif(&mut program, EPERM);

        assert_eq!(rewritten, 0);
        assert_eq!(program[0], jeq(constant));
    }

    #[test]
    fn reports_no_rewrite_when_the_filter_denies_with_another_errno() {
        // The caller uses this count to refuse launching: a supervisor waiting
        // on notifications a filter never emits would answer nothing while the
        // audit trail quietly stayed empty.
        let mut program = vec![ret(SECCOMP_RET_ERRNO | 13), ret(SECCOMP_RET_ALLOW)];

        assert_eq!(rewrite_errno_returns_to_user_notif(&mut program, EPERM), 0);
    }

    #[test]
    fn denial_log_collapses_repeats_and_keeps_distinct_attempts() {
        let log = DeniedSyscallLog::default();
        log.record(DeniedSyscall { nr: 101, pid: 7 });
        log.record(DeniedSyscall { nr: 101, pid: 7 });
        log.record(DeniedSyscall { nr: 165, pid: 7 });
        // Same syscall from a different process is a distinct attempt.
        log.record(DeniedSyscall { nr: 101, pid: 8 });

        let (denials, dropped) = log.drain();

        assert_eq!(denials.len(), 3, "got {denials:?}");
        assert_eq!(dropped, 0);
        let (after, _) = log.drain();
        assert!(after.is_empty(), "drain must not replay records");
    }

    #[test]
    fn denial_log_is_bounded_and_counts_what_it_drops() {
        let log = DeniedSyscallLog::default();
        let overflow = 4usize;
        for index in 0..(MAX_RECORDED_DENIALS + overflow) {
            log.record(DeniedSyscall {
                nr: index as i32,
                pid: 1,
            });
        }

        let (denials, dropped) = log.drain();

        assert_eq!(denials.len(), MAX_RECORDED_DENIALS);
        assert_eq!(dropped, overflow);
    }

    #[test]
    fn denials_describe_themselves_for_the_audit_trail() {
        let denial = DeniedSyscall {
            nr: 999_999,
            pid: 3,
        };
        assert_eq!(
            denial.resource(),
            "syscall:999999",
            "an unknown number must still produce a usable resource"
        );
        assert!(denial.reason_text().contains("allowlist"));
    }
}
