use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Command;

use clawcrate_types::{Platform, SystemCapabilities};

#[derive(Debug, Clone)]
pub struct MacOsProbePaths {
    pub sandbox_exec: PathBuf,
    pub sw_vers: PathBuf,
    pub uname: PathBuf,
}

impl Default for MacOsProbePaths {
    fn default() -> Self {
        Self {
            sandbox_exec: PathBuf::from("/usr/bin/sandbox-exec"),
            sw_vers: PathBuf::from("/usr/bin/sw_vers"),
            uname: PathBuf::from("/usr/bin/uname"),
        }
    }
}

pub fn probe_macos_capabilities() -> SystemCapabilities {
    probe_macos_capabilities_with_paths(&MacOsProbePaths::default())
}

fn probe_macos_capabilities_with_paths(paths: &MacOsProbePaths) -> SystemCapabilities {
    let seatbelt_available = is_executable_file(&paths.sandbox_exec);
    let macos_version = read_trimmed_command_output(&paths.sw_vers, &["-productVersion"]);
    let kernel_version = read_trimmed_command_output(&paths.uname, &["-r"]);

    SystemCapabilities {
        platform: Platform::MacOS,
        landlock_abi: None,
        seccomp_available: false,
        seatbelt_available,
        user_namespaces: false,
        macos_version,
        kernel_version,
    }
}

fn is_executable_file(path: &Path) -> bool {
    let Ok(metadata) = fs::metadata(path) else {
        return false;
    };

    metadata.is_file() && (metadata.permissions().mode() & 0o111 != 0)
}

fn read_trimmed_command_output(binary: &Path, args: &[&str]) -> Option<String> {
    let output = Command::new(binary).args(args).output().ok()?;
    if !output.status.success() {
        return None;
    }

    let stdout = String::from_utf8(output.stdout).ok()?;
    let value = stdout.trim();
    if value.is_empty() {
        None
    } else {
        Some(value.to_string())
    }
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::os::unix::fs::PermissionsExt;
    use std::path::PathBuf;
    use std::time::{SystemTime, UNIX_EPOCH};

    use super::{probe_macos_capabilities_with_paths, MacOsProbePaths};
    use clawcrate_types::Platform;

    fn unique_tmp_dir(prefix: &str) -> PathBuf {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system time after unix epoch")
            .as_nanos();
        let dir = std::env::temp_dir().join(format!("{prefix}_{nanos}_{}", std::process::id()));
        fs::create_dir_all(&dir).expect("create temp test directory");
        dir
    }

    fn write_executable_script(path: &PathBuf, output: &str) {
        let script = format!("#!/bin/sh\necho \"{output}\"\n");
        fs::write(path, script).expect("write script");

        let mut perms = fs::metadata(path)
            .expect("read metadata for script")
            .permissions();
        perms.set_mode(0o755);
        fs::set_permissions(path, perms).expect("set script permissions");
    }

    fn write_non_executable_file(path: &PathBuf, content: &str) {
        fs::write(path, content).expect("write file");
        let mut perms = fs::metadata(path)
            .expect("read metadata for file")
            .permissions();
        perms.set_mode(0o644);
        fs::set_permissions(path, perms).expect("set file permissions");
    }

    #[test]
    fn probe_reports_seatbelt_and_versions_when_tools_are_available() {
        let tmp = unique_tmp_dir("clawcrate_macos_probe_ok");
        let sandbox_exec = tmp.join("sandbox-exec");
        let sw_vers = tmp.join("sw_vers");
        let uname = tmp.join("uname");

        write_executable_script(&sandbox_exec, "sandbox-exec");
        write_executable_script(&sw_vers, "14.5");
        write_executable_script(&uname, "23.5.0");

        let paths = MacOsProbePaths {
            sandbox_exec,
            sw_vers,
            uname,
        };

        let capabilities = probe_macos_capabilities_with_paths(&paths);
        assert_eq!(capabilities.platform, Platform::MacOS);
        assert!(capabilities.seatbelt_available);
        assert_eq!(capabilities.macos_version.as_deref(), Some("14.5"));
        assert_eq!(capabilities.kernel_version.as_deref(), Some("23.5.0"));
        assert_eq!(capabilities.landlock_abi, None);
        assert!(!capabilities.seccomp_available);
        assert!(!capabilities.user_namespaces);
    }

    #[test]
    fn probe_marks_seatbelt_unavailable_when_binary_is_not_executable() {
        let tmp = unique_tmp_dir("clawcrate_macos_probe_no_exec");
        let sandbox_exec = tmp.join("sandbox-exec");
        let sw_vers = tmp.join("sw_vers");
        let uname = tmp.join("uname");

        write_non_executable_file(&sandbox_exec, "sandbox-exec");
        write_executable_script(&sw_vers, "15.0");
        write_executable_script(&uname, "24.0.0");

        let paths = MacOsProbePaths {
            sandbox_exec,
            sw_vers,
            uname,
        };

        let capabilities = probe_macos_capabilities_with_paths(&paths);
        assert!(!capabilities.seatbelt_available);
        assert_eq!(capabilities.macos_version.as_deref(), Some("15.0"));
        assert_eq!(capabilities.kernel_version.as_deref(), Some("24.0.0"));
    }

    #[test]
    fn probe_ignores_empty_or_failing_version_commands() {
        let tmp = unique_tmp_dir("clawcrate_macos_probe_failures");
        let sandbox_exec = tmp.join("sandbox-exec");
        let sw_vers = tmp.join("sw_vers");
        let uname = tmp.join("uname");

        write_executable_script(&sandbox_exec, "sandbox-exec");
        write_executable_script(&sw_vers, "");
        fs::write(&uname, "#!/bin/sh\nexit 1\n").expect("write failing uname script");
        let mut perms = fs::metadata(&uname)
            .expect("read metadata for uname")
            .permissions();
        perms.set_mode(0o755);
        fs::set_permissions(&uname, perms).expect("set uname permissions");

        let paths = MacOsProbePaths {
            sandbox_exec,
            sw_vers,
            uname,
        };

        let capabilities = probe_macos_capabilities_with_paths(&paths);
        assert!(capabilities.seatbelt_available);
        assert_eq!(capabilities.macos_version, None);
        assert_eq!(capabilities.kernel_version, None);
    }
}
