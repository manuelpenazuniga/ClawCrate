//! doctor module (extracted from main.rs; see #277).

use crate::{cli::*, output::*};
use anyhow::Result;
#[cfg(target_os = "linux")]
use clawcrate_sandbox::linux_probe::probe_linux_capabilities;
#[cfg(target_os = "macos")]
use clawcrate_sandbox::macos_probe::probe_macos_capabilities;
use clawcrate_types::{Platform, SystemCapabilities};
use comfy_table::{Cell, Table};

pub(crate) fn handle_doctor(args: DoctorArgs, output: &OutputOptions) -> Result<()> {
    let capabilities = probe_system_capabilities()?;
    verbose_log(
        output,
        1,
        format!("doctor capabilities loaded for {:?}", capabilities.platform),
    );

    if args.json {
        println!("{}", serde_json::to_string_pretty(&capabilities)?);
    } else {
        print_human_doctor(&capabilities, output);
    }

    Ok(())
}

#[cfg(target_os = "linux")]
pub(crate) fn probe_system_capabilities() -> Result<SystemCapabilities> {
    Ok(probe_linux_capabilities())
}

#[cfg(target_os = "macos")]
pub(crate) fn probe_system_capabilities() -> Result<SystemCapabilities> {
    Ok(probe_macos_capabilities())
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
pub(crate) fn probe_system_capabilities() -> Result<SystemCapabilities> {
    Err(anyhow!("unsupported platform for `doctor` command"))
}

pub(crate) fn print_human_doctor(capabilities: &SystemCapabilities, _output: &OutputOptions) {
    let mut table = Table::new();
    table.set_header(vec!["Capability", "Status"]);
    for (name, status) in doctor_rows(capabilities) {
        table.add_row(vec![Cell::new(name), Cell::new(status)]);
    }
    println!("{table}");
}

pub(crate) fn doctor_rows(capabilities: &SystemCapabilities) -> Vec<(String, String)> {
    let kernel_version = capabilities
        .kernel_version
        .clone()
        .unwrap_or_else(|| "unknown".to_string());
    let macos_version = if capabilities.platform == Platform::MacOS {
        capabilities
            .macos_version
            .clone()
            .unwrap_or_else(|| "unknown".to_string())
    } else {
        "n/a".to_string()
    };

    let landlock_status = if capabilities.platform == Platform::Linux {
        capabilities
            .landlock_abi
            .map(|abi| format!("✅ ABI {abi}"))
            .unwrap_or_else(|| "❌ unavailable".to_string())
    } else {
        "n/a".to_string()
    };

    let seccomp_status = if capabilities.platform == Platform::Linux {
        bool_status(capabilities.seccomp_available)
    } else {
        "n/a".to_string()
    };

    let seatbelt_status = if capabilities.platform == Platform::MacOS {
        bool_status(capabilities.seatbelt_available)
    } else {
        "n/a".to_string()
    };

    let user_namespaces_status = if capabilities.platform == Platform::Linux {
        bool_status(capabilities.user_namespaces)
    } else {
        "n/a".to_string()
    };

    vec![
        (
            "Platform".to_string(),
            platform_label(&capabilities.platform),
        ),
        ("Kernel Version".to_string(), kernel_version),
        ("macOS Version".to_string(), macos_version),
        ("Landlock ABI".to_string(), landlock_status),
        ("seccomp".to_string(), seccomp_status),
        ("Seatbelt".to_string(), seatbelt_status),
        ("User Namespaces".to_string(), user_namespaces_status),
    ]
}

pub(crate) fn bool_status(enabled: bool) -> String {
    if enabled {
        "✅ available".to_string()
    } else {
        "❌ unavailable".to_string()
    }
}

pub(crate) fn platform_label(platform: &Platform) -> String {
    match platform {
        Platform::Linux => "Linux".to_string(),
        Platform::MacOS => "macOS".to_string(),
    }
}
