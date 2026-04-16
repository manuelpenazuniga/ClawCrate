use std::fs;
use std::path::{Path, PathBuf};

use clawcrate_types::{Platform, SystemCapabilities};

#[derive(Debug, Clone)]
pub struct LinuxProbePaths {
    pub kernel_osrelease: PathBuf,
    pub seccomp_actions_avail: PathBuf,
    pub seccomp_legacy: PathBuf,
    pub user_max_user_namespaces: PathBuf,
    pub landlock_abi_paths: Vec<PathBuf>,
    pub kernel_config_path: Option<PathBuf>,
}

impl Default for LinuxProbePaths {
    fn default() -> Self {
        Self {
            kernel_osrelease: PathBuf::from("/proc/sys/kernel/osrelease"),
            seccomp_actions_avail: PathBuf::from("/proc/sys/kernel/seccomp/actions_avail"),
            seccomp_legacy: PathBuf::from("/proc/sys/kernel/seccomp"),
            user_max_user_namespaces: PathBuf::from("/proc/sys/user/max_user_namespaces"),
            landlock_abi_paths: vec![
                PathBuf::from("/sys/kernel/security/landlock/abi"),
                PathBuf::from("/sys/kernel/security/landlock/features/abi"),
                PathBuf::from("/sys/kernel/security/landlock/features"),
            ],
            kernel_config_path: None,
        }
    }
}

pub fn probe_linux_capabilities() -> SystemCapabilities {
    probe_linux_capabilities_with_paths(&LinuxProbePaths::default())
}

fn probe_linux_capabilities_with_paths(paths: &LinuxProbePaths) -> SystemCapabilities {
    let kernel_version = read_trimmed_file(&paths.kernel_osrelease);
    let landlock_abi = detect_landlock_abi(paths, kernel_version.as_deref());

    SystemCapabilities {
        platform: Platform::Linux,
        landlock_abi,
        seccomp_available: detect_seccomp(paths),
        seatbelt_available: false,
        user_namespaces: detect_user_namespaces(paths),
        macos_version: None,
        kernel_version,
    }
}

fn detect_seccomp(paths: &LinuxProbePaths) -> bool {
    if let Some(actions) = read_trimmed_file(&paths.seccomp_actions_avail) {
        return !actions.is_empty();
    }

    read_trimmed_file(&paths.seccomp_legacy)
        .and_then(|value| value.parse::<u64>().ok())
        .is_some_and(|value| value > 0)
}

fn detect_user_namespaces(paths: &LinuxProbePaths) -> bool {
    read_trimmed_file(&paths.user_max_user_namespaces)
        .and_then(|value| value.parse::<u64>().ok())
        .is_some_and(|value| value > 0)
}

fn detect_landlock_abi(paths: &LinuxProbePaths, kernel_version: Option<&str>) -> Option<u8> {
    for path in &paths.landlock_abi_paths {
        if let Some(content) = read_trimmed_file(path) {
            if let Some(abi) = parse_landlock_abi(&content) {
                return Some(abi);
            }
        }
    }

    let kernel = kernel_version?;
    if !kernel_is_at_least(kernel, 5, 13) {
        return None;
    }

    let kernel_config_path = paths
        .kernel_config_path
        .clone()
        .unwrap_or_else(|| PathBuf::from(format!("/boot/config-{kernel}")));
    let config_contents = read_trimmed_file(&kernel_config_path)?;
    if config_contents.contains("CONFIG_SECURITY_LANDLOCK=y") {
        return Some(1);
    }

    None
}

fn parse_landlock_abi(raw: &str) -> Option<u8> {
    let mut max_abi: Option<u8> = None;
    for token in raw
        .split(|c: char| !c.is_ascii_alphanumeric())
        .filter(|token| !token.is_empty())
    {
        if let Ok(value) = token.parse::<u8>() {
            max_abi = Some(match max_abi {
                Some(current) => current.max(value),
                None => value,
            });
            continue;
        }

        if let Some(suffix) = token.strip_prefix("abi") {
            if let Ok(value) = suffix.parse::<u8>() {
                max_abi = Some(match max_abi {
                    Some(current) => current.max(value),
                    None => value,
                });
            }
        }
    }

    max_abi
}

fn kernel_is_at_least(kernel_version: &str, required_major: u64, required_minor: u64) -> bool {
    let (major, minor) = parse_kernel_major_minor(kernel_version).unwrap_or((0, 0));
    (major, minor) >= (required_major, required_minor)
}

fn parse_kernel_major_minor(kernel_version: &str) -> Option<(u64, u64)> {
    let mut numbers = Vec::new();
    for part in kernel_version.split('.') {
        let digits: String = part.chars().take_while(|c| c.is_ascii_digit()).collect();
        if digits.is_empty() {
            break;
        }
        let value = digits.parse::<u64>().ok()?;
        numbers.push(value);
        if numbers.len() == 2 {
            break;
        }
    }

    if numbers.len() < 2 {
        return None;
    }

    Some((numbers[0], numbers[1]))
}

fn read_trimmed_file(path: &Path) -> Option<String> {
    fs::read_to_string(path)
        .ok()
        .map(|contents| contents.trim().to_string())
        .filter(|contents| !contents.is_empty())
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::path::PathBuf;
    use std::time::{SystemTime, UNIX_EPOCH};

    use super::{
        kernel_is_at_least, parse_landlock_abi, probe_linux_capabilities_with_paths,
        LinuxProbePaths,
    };

    fn unique_tmp_dir(prefix: &str) -> PathBuf {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system time after unix epoch")
            .as_nanos();
        let dir = std::env::temp_dir().join(format!("{prefix}_{nanos}_{}", std::process::id()));
        fs::create_dir_all(&dir).expect("create temp test directory");
        dir
    }

    fn write(path: &PathBuf, content: &str) {
        fs::write(path, content).expect("write file");
    }

    #[test]
    fn parses_landlock_abi_from_plain_and_tokenized_inputs() {
        assert_eq!(parse_landlock_abi("4"), Some(4));
        assert_eq!(parse_landlock_abi("abi1 abi2 abi3"), Some(3));
        assert_eq!(parse_landlock_abi("features: abi2\nabi4"), Some(4));
        assert_eq!(parse_landlock_abi("none"), None);
    }

    #[test]
    fn kernel_compatibility_check_works_with_suffixes() {
        assert!(kernel_is_at_least("6.8.0-40-generic", 5, 13));
        assert!(kernel_is_at_least("5.13.0", 5, 13));
        assert!(!kernel_is_at_least("5.12.19", 5, 13));
    }

    #[test]
    fn probe_reads_landlock_seccomp_and_userns_from_expected_files() {
        let tmp = unique_tmp_dir("clawcrate_linux_probe_all");
        let kernel = tmp.join("osrelease");
        let seccomp_actions = tmp.join("actions_avail");
        let seccomp_legacy = tmp.join("seccomp");
        let user_ns = tmp.join("max_user_namespaces");
        let landlock_abi = tmp.join("landlock_abi");

        write(&kernel, "6.8.0-40-generic\n");
        write(
            &seccomp_actions,
            "kill_process kill_thread trap errno user_notif trace log allow",
        );
        write(&seccomp_legacy, "2\n");
        write(&user_ns, "6191547\n");
        write(&landlock_abi, "4\n");

        let paths = LinuxProbePaths {
            kernel_osrelease: kernel,
            seccomp_actions_avail: seccomp_actions,
            seccomp_legacy,
            user_max_user_namespaces: user_ns,
            landlock_abi_paths: vec![landlock_abi],
            kernel_config_path: None,
        };

        let capabilities = probe_linux_capabilities_with_paths(&paths);
        assert_eq!(capabilities.landlock_abi, Some(4));
        assert!(capabilities.seccomp_available);
        assert!(capabilities.user_namespaces);
        assert_eq!(
            capabilities.kernel_version.as_deref(),
            Some("6.8.0-40-generic")
        );
    }

    #[test]
    fn probe_falls_back_to_kernel_config_for_landlock_when_abi_file_is_missing() {
        let tmp = unique_tmp_dir("clawcrate_linux_probe_kernel_config");
        let kernel = tmp.join("osrelease");
        let seccomp_actions = tmp.join("actions_avail");
        let seccomp_legacy = tmp.join("seccomp");
        let user_ns = tmp.join("max_user_namespaces");
        let kernel_config = tmp.join("kernel_config");

        write(&kernel, "5.15.0\n");
        write(&seccomp_actions, "allow");
        write(&seccomp_legacy, "2\n");
        write(&user_ns, "1\n");
        write(&kernel_config, "CONFIG_SECURITY_LANDLOCK=y\n");

        let paths = LinuxProbePaths {
            kernel_osrelease: kernel,
            seccomp_actions_avail: seccomp_actions,
            seccomp_legacy,
            user_max_user_namespaces: user_ns,
            landlock_abi_paths: vec![tmp.join("missing_abi_file")],
            kernel_config_path: Some(kernel_config),
        };

        let capabilities = probe_linux_capabilities_with_paths(&paths);
        assert_eq!(capabilities.landlock_abi, Some(1));
    }

    #[test]
    fn probe_reports_seccomp_via_legacy_switch_when_actions_file_missing() {
        let tmp = unique_tmp_dir("clawcrate_linux_probe_seccomp_legacy");
        let kernel = tmp.join("osrelease");
        let seccomp_actions = tmp.join("actions_avail_missing");
        let seccomp_legacy = tmp.join("seccomp");
        let user_ns = tmp.join("max_user_namespaces");

        write(&kernel, "5.4.0\n");
        write(&seccomp_legacy, "2\n");
        write(&user_ns, "0\n");

        let paths = LinuxProbePaths {
            kernel_osrelease: kernel,
            seccomp_actions_avail: seccomp_actions,
            seccomp_legacy,
            user_max_user_namespaces: user_ns,
            landlock_abi_paths: vec![tmp.join("missing_abi_file")],
            kernel_config_path: None,
        };

        let capabilities = probe_linux_capabilities_with_paths(&paths);
        assert!(capabilities.seccomp_available);
        assert!(!capabilities.user_namespaces);
    }
}
