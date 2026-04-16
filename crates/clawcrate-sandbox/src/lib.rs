#![forbid(unsafe_code)]

pub const CRATE_NAME: &str = "clawcrate-sandbox";

#[cfg(target_os = "macos")]
pub mod darwin;
pub mod env_scrub;
pub mod linux;
pub mod linux_probe;
#[cfg(target_os = "macos")]
pub mod macos_probe;
pub mod rlimits;
