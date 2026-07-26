#![deny(unsafe_code)]
#![deny(unsafe_op_in_unsafe_fn)]

use clawcrate_types::Platform;

pub const CRATE_NAME: &str = "clawcrate-sandbox";

/// Whether ClawCrate enforces filesystem **read** isolation in Direct Mode on
/// the given platform.
///
/// macOS enforces reads via the Seatbelt profile. Linux enforces reads via
/// Landlock read-allowlisting: the ruleset declares `ACCESS_FS_READ_FILE` and
/// `ACCESS_FS_READ_DIR` in `handled_access_fs` and grants them only on the
/// profile's read/write set plus a minimal system/toolchain allowlist, so paths
/// outside that set (`~/.ssh`, `~/.aws`, `$HOME` at large) are unreadable.
///
/// This is the single source of truth for the CLI read-isolation warning and
/// the `doctor` capability row.
pub const fn direct_mode_read_isolation_enforced(platform: Platform) -> bool {
    match platform {
        Platform::MacOS | Platform::Linux => true,
    }
}

#[cfg(target_os = "macos")]
pub mod darwin;
pub mod egress_proxy;
pub mod env_scrub;
pub mod linux;
pub mod linux_probe;
#[cfg(target_os = "macos")]
pub mod macos_probe;
pub(crate) mod path_normalize;
pub mod rlimits;
