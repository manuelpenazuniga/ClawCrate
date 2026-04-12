#![forbid(unsafe_code)]

use std::collections::HashSet;
use std::fs;
use std::path::{Path, PathBuf};

use clawcrate_types::{DefaultMode, NetLevel, ResolvedProfile, ResourceLimits};
use serde::Deserialize;

pub const BUILTIN_PROFILE_NAMES: [&str; 4] = ["safe", "build", "install", "open"];

#[derive(Debug, thiserror::Error)]
pub enum ProfileError {
    #[error("profile not found: {0}")]
    ProfileNotFound(String),
    #[error("failed to read profile file {path}: {source}")]
    ReadFile {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("failed to parse profile file {path}: {source}")]
    ParseFile {
        path: PathBuf,
        #[source]
        source: serde_yaml::Error,
    },
    #[error("invalid network value in {path}: {value}")]
    InvalidNetwork { path: PathBuf, value: String },
    #[error("invalid default_mode value in {path}: {value}")]
    InvalidDefaultMode { path: PathBuf, value: String },
    #[error("cyclic profile inheritance detected at {0}")]
    InheritanceCycle(String),
}

#[derive(Debug, Clone)]
pub struct ProfileResolver {
    profiles_dir: PathBuf,
}

impl Default for ProfileResolver {
    fn default() -> Self {
        let profiles_dir = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("..")
            .join("..")
            .join("profiles");
        Self { profiles_dir }
    }
}

impl ProfileResolver {
    pub fn new(profiles_dir: impl Into<PathBuf>) -> Self {
        Self {
            profiles_dir: profiles_dir.into(),
        }
    }

    pub fn profiles_dir(&self) -> &Path {
        &self.profiles_dir
    }

    pub fn resolve(&self, profile: &str) -> Result<ResolvedProfile, ProfileError> {
        if looks_like_path(profile) || Path::new(profile).exists() {
            return self.resolve_from_path(profile);
        }
        self.resolve_builtin(profile)
    }

    pub fn resolve_builtin(&self, name: &str) -> Result<ResolvedProfile, ProfileError> {
        let entry = ProfileEntry::Builtin(name.to_string());
        let inherited = self.resolve_entry(&entry, None, &mut HashSet::new())?;
        self.to_resolved_profile(inherited, entry.fallback_name())
    }

    pub fn resolve_from_path(
        &self,
        path: impl AsRef<Path>,
    ) -> Result<ResolvedProfile, ProfileError> {
        let entry = ProfileEntry::Path(path.as_ref().to_path_buf());
        let inherited = self.resolve_entry(&entry, None, &mut HashSet::new())?;
        self.to_resolved_profile(inherited, entry.fallback_name())
    }

    fn resolve_entry(
        &self,
        entry: &ProfileEntry,
        relative_to: Option<&Path>,
        visited: &mut HashSet<String>,
    ) -> Result<InheritedProfile, ProfileError> {
        let identity = entry.identity(relative_to, &self.profiles_dir);
        if !visited.insert(identity.clone()) {
            return Err(ProfileError::InheritanceCycle(identity));
        }

        let file_path = entry.file_path(relative_to, &self.profiles_dir);
        let profile = load_raw_profile(&file_path)?;

        let resolved = if let Some(base) = profile.extends.clone() {
            let base_entry = ProfileEntry::from_reference(&base);
            let base_profile = self.resolve_entry(&base_entry, file_path.parent(), visited)?;
            merge_profiles(
                base_profile,
                InheritedProfile::from_raw(profile, file_path.clone()),
            )
        } else {
            InheritedProfile::from_raw(profile, file_path.clone())
        };

        visited.remove(&identity);
        Ok(resolved)
    }

    fn to_resolved_profile(
        &self,
        inherited: InheritedProfile,
        fallback_name: String,
    ) -> Result<ResolvedProfile, ProfileError> {
        let path = inherited.source_path;
        let network = parse_network(inherited.network.as_deref(), &path)?;
        let default_mode = parse_default_mode(inherited.default_mode.as_deref(), &path)?;

        let fs_read = inherited
            .filesystem
            .read
            .unwrap_or_default()
            .into_iter()
            .map(PathBuf::from)
            .collect();
        let fs_write = inherited
            .filesystem
            .write
            .unwrap_or_default()
            .into_iter()
            .map(PathBuf::from)
            .collect();
        let fs_deny = inherited.filesystem.deny.unwrap_or_default();

        let env_scrub = inherited.environment.scrub.unwrap_or_default();
        let env_passthrough = inherited.environment.passthrough.unwrap_or_default();

        Ok(ResolvedProfile {
            name: inherited.name.unwrap_or(fallback_name),
            fs_read,
            fs_write,
            fs_deny,
            net: network,
            env_scrub,
            env_passthrough,
            resources: inherited.resources.to_limits(),
            default_mode,
        })
    }
}

#[derive(Debug, Clone)]
enum ProfileEntry {
    Builtin(String),
    Path(PathBuf),
}

impl ProfileEntry {
    fn from_reference(reference: &str) -> Self {
        if looks_like_path(reference) {
            return Self::Path(PathBuf::from(reference));
        }
        Self::Builtin(reference.to_string())
    }

    fn file_path(&self, relative_to: Option<&Path>, profiles_dir: &Path) -> PathBuf {
        match self {
            Self::Builtin(name) => profiles_dir.join(format!("{name}.yaml")),
            Self::Path(path) => {
                if path.is_absolute() {
                    return path.clone();
                }
                if let Some(base) = relative_to {
                    return base.join(path);
                }
                path.clone()
            }
        }
    }

    fn fallback_name(&self) -> String {
        match self {
            Self::Builtin(name) => name.clone(),
            Self::Path(path) => path
                .file_stem()
                .and_then(|it| it.to_str())
                .map_or_else(|| "custom".to_string(), |it| it.to_string()),
        }
    }

    fn identity(&self, relative_to: Option<&Path>, profiles_dir: &Path) -> String {
        self.file_path(relative_to, profiles_dir)
            .to_string_lossy()
            .to_string()
    }
}

#[derive(Debug, Clone, Deserialize, Default)]
#[serde(default, deny_unknown_fields)]
struct RawProfile {
    name: Option<String>,
    extends: Option<String>,
    default_mode: Option<String>,
    filesystem: RawFilesystem,
    network: Option<String>,
    environment: RawEnvironment,
    resources: RawResources,
}

#[derive(Debug, Clone, Deserialize, Default)]
#[serde(default, deny_unknown_fields)]
struct RawFilesystem {
    read: Option<Vec<String>>,
    write: Option<Vec<String>>,
    deny: Option<Vec<String>>,
}

#[derive(Debug, Clone, Deserialize, Default)]
#[serde(default, deny_unknown_fields)]
struct RawEnvironment {
    scrub: Option<Vec<String>>,
    passthrough: Option<Vec<String>>,
}

#[derive(Debug, Clone, Deserialize, Default)]
#[serde(default, deny_unknown_fields)]
struct RawResources {
    max_cpu_seconds: Option<u64>,
    max_memory_mb: Option<u64>,
    max_open_files: Option<u64>,
    max_processes: Option<u64>,
    max_output_bytes: Option<u64>,
}

#[derive(Debug, Clone)]
struct InheritedProfile {
    name: Option<String>,
    default_mode: Option<String>,
    filesystem: RawFilesystem,
    network: Option<String>,
    environment: RawEnvironment,
    resources: RawResources,
    source_path: PathBuf,
}

impl InheritedProfile {
    fn from_raw(raw: RawProfile, source_path: PathBuf) -> Self {
        Self {
            name: raw.name,
            default_mode: raw.default_mode,
            filesystem: raw.filesystem,
            network: raw.network,
            environment: raw.environment,
            resources: raw.resources,
            source_path,
        }
    }
}

impl RawResources {
    fn to_limits(&self) -> ResourceLimits {
        ResourceLimits {
            max_cpu_seconds: self.max_cpu_seconds.unwrap_or(120),
            max_memory_mb: self.max_memory_mb.unwrap_or(2048),
            max_open_files: self.max_open_files.unwrap_or(1024),
            max_processes: self.max_processes.unwrap_or(128),
            max_output_bytes: self.max_output_bytes.unwrap_or(2 * 1024 * 1024),
        }
    }
}

fn merge_profiles(base: InheritedProfile, overlay: InheritedProfile) -> InheritedProfile {
    InheritedProfile {
        name: overlay.name.or(base.name),
        default_mode: overlay.default_mode.or(base.default_mode),
        filesystem: RawFilesystem {
            read: overlay.filesystem.read.or(base.filesystem.read),
            write: overlay.filesystem.write.or(base.filesystem.write),
            deny: overlay.filesystem.deny.or(base.filesystem.deny),
        },
        network: overlay.network.or(base.network),
        environment: RawEnvironment {
            scrub: overlay.environment.scrub.or(base.environment.scrub),
            passthrough: overlay
                .environment
                .passthrough
                .or(base.environment.passthrough),
        },
        resources: RawResources {
            max_cpu_seconds: overlay
                .resources
                .max_cpu_seconds
                .or(base.resources.max_cpu_seconds),
            max_memory_mb: overlay
                .resources
                .max_memory_mb
                .or(base.resources.max_memory_mb),
            max_open_files: overlay
                .resources
                .max_open_files
                .or(base.resources.max_open_files),
            max_processes: overlay
                .resources
                .max_processes
                .or(base.resources.max_processes),
            max_output_bytes: overlay
                .resources
                .max_output_bytes
                .or(base.resources.max_output_bytes),
        },
        source_path: overlay.source_path,
    }
}

fn parse_default_mode(raw: Option<&str>, path: &Path) -> Result<DefaultMode, ProfileError> {
    match raw.map(normalize_string) {
        None => Ok(DefaultMode::Direct),
        Some(mode) if mode == "direct" => Ok(DefaultMode::Direct),
        Some(mode) if mode == "replica" => Ok(DefaultMode::Replica),
        Some(value) => Err(ProfileError::InvalidDefaultMode {
            path: path.to_path_buf(),
            value,
        }),
    }
}

fn parse_network(raw: Option<&str>, path: &Path) -> Result<NetLevel, ProfileError> {
    match raw.map(normalize_string) {
        None => Ok(NetLevel::None),
        Some(network) if network == "none" => Ok(NetLevel::None),
        Some(network) if network == "open" => Ok(NetLevel::Open),
        Some(value) => Err(ProfileError::InvalidNetwork {
            path: path.to_path_buf(),
            value,
        }),
    }
}

fn normalize_string(input: &str) -> String {
    input.trim().to_ascii_lowercase()
}

fn looks_like_path(reference: &str) -> bool {
    reference.ends_with(".yaml")
        || reference.ends_with(".yml")
        || reference.starts_with('.')
        || reference.starts_with('/')
        || reference.contains(std::path::MAIN_SEPARATOR)
}

fn load_raw_profile(path: &Path) -> Result<RawProfile, ProfileError> {
    if !path.exists() {
        return Err(ProfileError::ProfileNotFound(
            path.to_string_lossy().to_string(),
        ));
    }

    let content = fs::read_to_string(path).map_err(|source| ProfileError::ReadFile {
        path: path.to_path_buf(),
        source,
    })?;

    serde_yaml::from_str(&content).map_err(|source| ProfileError::ParseFile {
        path: path.to_path_buf(),
        source,
    })
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::path::{Path, PathBuf};
    use std::time::{SystemTime, UNIX_EPOCH};

    use super::ProfileResolver;
    use clawcrate_types::{DefaultMode, NetLevel};

    fn unique_tmp_dir(prefix: &str) -> PathBuf {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system time after unix epoch")
            .as_nanos();
        let dir = std::env::temp_dir().join(format!("{prefix}_{nanos}_{}", std::process::id()));
        fs::create_dir_all(&dir).expect("create temp test directory");
        dir
    }

    fn write(path: &Path, content: &str) {
        fs::write(path, content).expect("write test file");
    }

    #[test]
    fn loads_builtin_profiles() {
        let resolver = ProfileResolver::default();
        for profile in ["safe", "build", "install", "open"] {
            let resolved = resolver
                .resolve_builtin(profile)
                .expect("load built-in profile");
            assert_eq!(resolved.name, profile);
        }
    }

    #[test]
    fn resolves_custom_profile_extending_builtin() {
        let resolver = ProfileResolver::default();
        let tmp = unique_tmp_dir("clawcrate_profiles_extends_builtin");
        let custom = tmp.join("custom.yaml");

        write(
            &custom,
            r#"
name: custom-build
extends: build
filesystem:
  write:
    - "./custom-output"
environment:
  passthrough:
    - "MY_CUSTOM_VAR"
resources:
  max_cpu_seconds: 300
  max_memory_mb: 4096
"#,
        );

        let resolved = resolver
            .resolve_from_path(&custom)
            .expect("resolve custom profile");

        assert_eq!(resolved.name, "custom-build");
        assert_eq!(resolved.default_mode, DefaultMode::Direct);
        assert_eq!(resolved.net, NetLevel::None);
        assert!(resolved.fs_read.iter().any(|it| it == Path::new(".")));
        assert_eq!(resolved.fs_write, vec![PathBuf::from("./custom-output")]);
        assert_eq!(resolved.env_passthrough, vec!["MY_CUSTOM_VAR".to_string()]);
        assert_eq!(resolved.resources.max_cpu_seconds, 300);
        assert_eq!(resolved.resources.max_memory_mb, 4096);
        assert_eq!(resolved.resources.max_open_files, 4096);
    }

    #[test]
    fn resolves_custom_profile_extending_relative_path() {
        let resolver = ProfileResolver::default();
        let tmp = unique_tmp_dir("clawcrate_profiles_extends_relative");
        let base = tmp.join("base.yaml");
        let child = tmp.join("child.yaml");

        write(
            &base,
            r#"
name: base
default_mode: Direct
filesystem:
  read: ["."]
  write: ["./target"]
network: none
environment:
  scrub: ["AWS_*"]
  passthrough: ["HOME"]
resources:
  max_cpu_seconds: 100
  max_memory_mb: 200
  max_open_files: 300
  max_processes: 400
  max_output_bytes: 500
"#,
        );
        write(
            &child,
            r#"
name: child
extends: ./base.yaml
network: open
"#,
        );

        let resolved = resolver
            .resolve_from_path(&child)
            .expect("resolve child profile");

        assert_eq!(resolved.name, "child");
        assert_eq!(resolved.net, NetLevel::Open);
        assert_eq!(resolved.fs_write, vec![PathBuf::from("./target")]);
        assert_eq!(resolved.resources.max_cpu_seconds, 100);
    }
}
