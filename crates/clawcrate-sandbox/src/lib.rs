#![deny(unsafe_code)]
#![deny(unsafe_op_in_unsafe_fn)]

use clawcrate_types::Platform;

pub const CRATE_NAME: &str = "clawcrate-sandbox";

/// Whether ClawCrate enforces filesystem **read** isolation in Direct Mode on
/// the given platform.
///
/// macOS enforces reads via the Seatbelt profile. Linux Direct Mode currently
/// enforces write controls only — Landlock read-allowlisting is not yet wired
/// up (tracked in #272), so Replica Mode is the cross-platform mitigation for
/// read isolation on Linux. This is the single source of truth for the CLI
/// warning and the `doctor` capability row; flip the Linux arm when Landlock
/// read-allowlisting lands.
pub const fn direct_mode_read_isolation_enforced(platform: Platform) -> bool {
    match platform {
        Platform::MacOS => true,
        Platform::Linux => false,
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
