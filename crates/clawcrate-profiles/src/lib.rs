#![forbid(unsafe_code)]

use std::collections::HashSet;
use std::fs;
use std::path::{Component, Path, PathBuf};

use clawcrate_types::{DefaultMode, NetLevel, ResolvedProfile, ResourceLimits};
use serde::Deserialize;

pub const BUILTIN_PROFILE_NAMES: [&str; 4] = ["safe", "build", "install", "open"];
const BUILTIN_SAFE_PROFILE: &str = include_str!("../../../profiles/safe.yaml");
const BUILTIN_BUILD_PROFILE: &str = include_str!("../../../profiles/build.yaml");
const BUILTIN_INSTALL_PROFILE: &str = include_str!("../../../profiles/install.yaml");
const BUILTIN_OPEN_PROFILE: &str = include_str!("../../../profiles/open.yaml");

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DetectedStack {
    Rust,
    Node,
    Python,
    Unknown,
}

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
    #[error("invalid filtered network config in {path}: {reason}")]
    InvalidFilteredNetwork { path: PathBuf, reason: String },
    #[error("invalid default_mode value in {path}: {value}")]
    InvalidDefaultMode { path: PathBuf, value: String },
    #[error("failed to parse community catalog {path}: {source}")]
    ParseCatalog {
        path: PathBuf,
        #[source]
        source: serde_yaml::Error,
    },
    #[error("invalid community catalog in {path}: {reason}")]
    InvalidCatalog { path: PathBuf, reason: String },
    #[error("cyclic profile inheritance detected at {0}")]
    InheritanceCycle(String),
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CommunityCatalog {
    pub version: u32,
    #[serde(default)]
    pub profiles: Vec<CommunityCatalogEntry>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CommunityCatalogEntry {
    pub id: String,
    pub title: String,
    pub path: PathBuf,
    #[serde(default)]
    pub owner: Option<String>,
    #[serde(default)]
    pub tags: Vec<String>,
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

    pub fn community_catalog_path(&self) -> PathBuf {
        self.profiles_dir.join("community").join("catalog.yaml")
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

    pub fn detect_stack(&self, workspace_root: impl AsRef<Path>) -> DetectedStack {
        detect_stack(workspace_root.as_ref())
    }

    pub fn resolve_auto(
        &self,
        workspace_root: impl AsRef<Path>,
    ) -> Result<ResolvedProfile, ProfileError> {
        let stack = detect_stack(workspace_root.as_ref());
        let mut resolved = match stack {
            DetectedStack::Unknown => self.resolve_builtin("safe")?,
            DetectedStack::Rust | DetectedStack::Node | DetectedStack::Python => {
                self.resolve_builtin("build")?
            }
        };
        apply_stack_overrides(&mut resolved, stack);
        Ok(resolved)
    }

    pub fn load_community_catalog(
        &self,
        catalog_path: impl AsRef<Path>,
    ) -> Result<CommunityCatalog, ProfileError> {
        let path = catalog_path.as_ref();
        let content = fs::read_to_string(path).map_err(|source| ProfileError::ReadFile {
            path: path.to_path_buf(),
            source,
        })?;

        serde_yaml::from_str(&content).map_err(|source| ProfileError::ParseCatalog {
            path: path.to_path_buf(),
            source,
        })
    }

    pub fn validate_community_catalog(
        &self,
        catalog_path: impl AsRef<Path>,
    ) -> Result<usize, ProfileError> {
        let catalog_path = catalog_path.as_ref();
        let catalog = self.load_community_catalog(catalog_path)?;
        if catalog.version != 1 {
            return Err(ProfileError::InvalidCatalog {
                path: catalog_path.to_path_buf(),
                reason: format!("unsupported version {}; expected 1", catalog.version),
            });
        }

        let catalog_dir = catalog_path.parent().unwrap_or_else(|| Path::new("."));
        let mut seen_ids = HashSet::new();
        let mut seen_paths = HashSet::new();

        for entry in &catalog.profiles {
            let normalized_id = normalize_string(&entry.id);
            if entry.id != normalized_id || !is_valid_catalog_id(&entry.id) {
                return Err(ProfileError::InvalidCatalog {
                    path: catalog_path.to_path_buf(),
                    reason: format!(
                        "entry id '{}' must be lowercase kebab-case [a-z0-9-]",
                        entry.id
                    ),
                });
            }
            if !seen_ids.insert(entry.id.clone()) {
                return Err(ProfileError::InvalidCatalog {
                    path: catalog_path.to_path_buf(),
                    reason: format!("duplicate entry id '{}'", entry.id),
                });
            }
            if entry.path.is_absolute() {
                return Err(ProfileError::InvalidCatalog {
                    path: catalog_path.to_path_buf(),
                    reason: format!("entry '{}' path must be relative", entry.id),
                });
            }
            if entry
                .path
                .components()
                .any(|component| matches!(component, Component::ParentDir))
            {
                return Err(ProfileError::InvalidCatalog {
                    path: catalog_path.to_path_buf(),
                    reason: format!("entry '{}' path cannot escape catalog directory", entry.id),
                });
            }
            if entry.path.extension().and_then(|it| it.to_str()) != Some("yaml") {
                return Err(ProfileError::InvalidCatalog {
                    path: catalog_path.to_path_buf(),
                    reason: format!("entry '{}' path must end in .yaml", entry.id),
                });
            }
            let normalized_path = normalize_catalog_relative_path(&entry.path);
            if !seen_paths.insert(normalized_path.clone()) {
                return Err(ProfileError::InvalidCatalog {
                    path: catalog_path.to_path_buf(),
                    reason: format!("duplicate profile path '{}'", entry.path.display()),
                });
            }

            let profile_path = catalog_dir.join(&normalized_path);
            self.resolve_from_path(&profile_path)?;
        }

        Ok(catalog.profiles.len())
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
        let profile = match entry {
            ProfileEntry::Builtin(name) => load_builtin_profile(name, &file_path)?,
            ProfileEntry::Path(_) => load_raw_profile(&file_path)?,
        };

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
        let network = parse_network(inherited.network.clone(), &path)?;
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
    network: Option<RawNetwork>,
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

#[derive(Debug, Clone, Deserialize)]
#[serde(untagged)]
enum RawNetwork {
    String(String),
    Config(RawNetworkConfig),
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawNetworkConfig {
    mode: String,
    #[serde(default)]
    allowed_domains: Vec<String>,
}

#[derive(Debug, Clone)]
struct InheritedProfile {
    name: Option<String>,
    default_mode: Option<String>,
    filesystem: RawFilesystem,
    network: Option<RawNetwork>,
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

fn parse_network(raw: Option<RawNetwork>, path: &Path) -> Result<NetLevel, ProfileError> {
    parse_network_config(raw, path)
}

fn parse_network_config(raw: Option<RawNetwork>, path: &Path) -> Result<NetLevel, ProfileError> {
    match raw {
        None => Ok(NetLevel::None),
        Some(RawNetwork::String(value)) => parse_network_mode_string(&value, path),
        Some(RawNetwork::Config(config)) => {
            let mode = normalize_string(&config.mode);
            match mode.as_str() {
                "none" => Ok(NetLevel::None),
                "open" => Ok(NetLevel::Open),
                "filtered" => {
                    let allowed_domains = normalize_allowed_domains(&config.allowed_domains);
                    if allowed_domains.is_empty() {
                        return Err(ProfileError::InvalidFilteredNetwork {
                            path: path.to_path_buf(),
                            reason: "allowed_domains must contain at least one domain rule"
                                .to_string(),
                        });
                    }
                    Ok(NetLevel::Filtered { allowed_domains })
                }
                _ => Err(ProfileError::InvalidNetwork {
                    path: path.to_path_buf(),
                    value: mode,
                }),
            }
        }
    }
}

fn parse_network_mode_string(raw: &str, path: &Path) -> Result<NetLevel, ProfileError> {
    let mode = normalize_string(raw);
    match mode.as_str() {
        "none" => Ok(NetLevel::None),
        "open" => Ok(NetLevel::Open),
        "filtered" => Err(ProfileError::InvalidFilteredNetwork {
            path: path.to_path_buf(),
            reason: "network: filtered requires object form with allowed_domains".to_string(),
        }),
        _ => Err(ProfileError::InvalidNetwork {
            path: path.to_path_buf(),
            value: mode,
        }),
    }
}

fn normalize_string(input: &str) -> String {
    input.trim().to_ascii_lowercase()
}

fn normalize_catalog_relative_path(path: &Path) -> PathBuf {
    let mut normalized = PathBuf::new();
    for component in path.components() {
        if matches!(component, Component::CurDir) {
            continue;
        }
        normalized.push(component.as_os_str());
    }
    normalized
}

fn normalize_allowed_domains(values: &[String]) -> Vec<String> {
    values
        .iter()
        .map(|value| normalize_string(value))
        .filter(|value| !value.is_empty())
        .collect()
}

fn is_valid_catalog_id(value: &str) -> bool {
    let bytes = value.as_bytes();
    if bytes.is_empty() {
        return false;
    }
    if bytes[0] == b'-' || bytes[bytes.len() - 1] == b'-' {
        return false;
    }

    bytes
        .iter()
        .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || *byte == b'-')
}

fn looks_like_path(reference: &str) -> bool {
    reference.ends_with(".yaml")
        || reference.ends_with(".yml")
        || reference.starts_with('.')
        || reference.starts_with('/')
        || reference.contains(std::path::MAIN_SEPARATOR)
}

fn load_builtin_profile(name: &str, source_path: &Path) -> Result<RawProfile, ProfileError> {
    let content = builtin_profile_content(name)
        .ok_or_else(|| ProfileError::ProfileNotFound(name.to_string()))?;
    serde_yaml::from_str(content).map_err(|source| ProfileError::ParseFile {
        path: source_path.to_path_buf(),
        source,
    })
}

fn builtin_profile_content(name: &str) -> Option<&'static str> {
    match name {
        "safe" => Some(BUILTIN_SAFE_PROFILE),
        "build" => Some(BUILTIN_BUILD_PROFILE),
        "install" => Some(BUILTIN_INSTALL_PROFILE),
        "open" => Some(BUILTIN_OPEN_PROFILE),
        _ => None,
    }
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

fn detect_stack(workspace_root: &Path) -> DetectedStack {
    if !workspace_root.is_dir() {
        return DetectedStack::Unknown;
    }

    if workspace_root.join("Cargo.toml").is_file() {
        return DetectedStack::Rust;
    }
    if workspace_root.join("package.json").is_file() {
        return DetectedStack::Node;
    }
    if workspace_root.join("pyproject.toml").is_file() {
        return DetectedStack::Python;
    }

    DetectedStack::Unknown
}

fn apply_stack_overrides(profile: &mut ResolvedProfile, stack: DetectedStack) {
    match stack {
        DetectedStack::Rust | DetectedStack::Unknown => {}
        DetectedStack::Node => {
            push_unique_path(&mut profile.fs_read, "~/.npm");
            push_unique_path(&mut profile.fs_read, "~/.pnpm-store");
            push_unique_path(&mut profile.fs_write, "./node_modules");
            push_unique_path(&mut profile.fs_write, "~/.npm");
            push_unique_path(&mut profile.fs_write, "~/.pnpm-store");
            push_unique_string(&mut profile.env_passthrough, "NPM_CONFIG_CACHE");
        }
        DetectedStack::Python => {
            push_unique_path(&mut profile.fs_read, "~/.cache/pip");
            push_unique_path(&mut profile.fs_write, "./.venv");
            push_unique_path(&mut profile.fs_write, "~/.cache/pip");
            push_unique_string(&mut profile.env_passthrough, "PIP_CACHE_DIR");
        }
    }
}

fn push_unique_path(values: &mut Vec<PathBuf>, candidate: &str) {
    let path = PathBuf::from(candidate);
    if values.iter().all(|existing| existing != &path) {
        values.push(path);
    }
}

fn push_unique_string(values: &mut Vec<String>, candidate: &str) {
    if values.iter().all(|existing| existing != candidate) {
        values.push(candidate.to_string());
    }
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::path::{Path, PathBuf};
    use std::time::{SystemTime, UNIX_EPOCH};

    use super::{DetectedStack, ProfileResolver};
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
    fn loads_builtin_profiles_without_repository_profiles_dir() {
        let missing_profiles_dir = unique_tmp_dir("clawcrate_profiles_missing_dir").join("missing");
        let resolver = ProfileResolver::new(&missing_profiles_dir);
        for profile in ["safe", "build", "install", "open"] {
            let resolved = resolver
                .resolve_builtin(profile)
                .expect("load embedded built-in profile");
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

    #[test]
    fn detects_stack_with_deterministic_priority() {
        let resolver = ProfileResolver::default();
        let tmp = unique_tmp_dir("clawcrate_profiles_detect_priority");
        write(
            &tmp.join("Cargo.toml"),
            "[package]\nname='demo'\nversion='0.1.0'\n",
        );
        write(&tmp.join("package.json"), "{ \"name\": \"demo\" }\n");
        write(&tmp.join("pyproject.toml"), "[project]\nname='demo'\n");

        let stack = resolver.detect_stack(&tmp);
        assert_eq!(stack, DetectedStack::Rust);
    }

    #[test]
    fn detects_node_when_only_package_json_exists() {
        let resolver = ProfileResolver::default();
        let tmp = unique_tmp_dir("clawcrate_profiles_detect_node");
        write(&tmp.join("package.json"), "{ \"name\": \"demo\" }\n");

        let stack = resolver.detect_stack(&tmp);
        assert_eq!(stack, DetectedStack::Node);
    }

    #[test]
    fn resolves_auto_with_safe_fallback_when_stack_is_unknown() {
        let resolver = ProfileResolver::default();
        let tmp = unique_tmp_dir("clawcrate_profiles_resolve_auto_safe");

        let profile = resolver.resolve_auto(&tmp).expect("resolve auto fallback");
        assert_eq!(profile.name, "safe");
        assert_eq!(profile.default_mode, DefaultMode::Direct);
        assert_eq!(profile.net, NetLevel::None);
        assert!(profile.fs_write.is_empty());
    }

    #[test]
    fn resolves_auto_with_node_overrides() {
        let resolver = ProfileResolver::default();
        let tmp = unique_tmp_dir("clawcrate_profiles_resolve_auto_node");
        write(&tmp.join("package.json"), "{ \"name\": \"demo\" }\n");

        let profile = resolver
            .resolve_auto(&tmp)
            .expect("resolve node auto profile");
        assert_eq!(profile.name, "build");
        assert!(profile
            .fs_write
            .iter()
            .any(|it| it == Path::new("./node_modules")));
        assert!(profile
            .env_passthrough
            .iter()
            .any(|it| it == "NPM_CONFIG_CACHE"));
    }

    #[test]
    fn resolves_auto_with_python_overrides() {
        let resolver = ProfileResolver::default();
        let tmp = unique_tmp_dir("clawcrate_profiles_resolve_auto_python");
        write(&tmp.join("pyproject.toml"), "[project]\nname='demo'\n");

        let profile = resolver
            .resolve_auto(&tmp)
            .expect("resolve python auto profile");
        assert_eq!(profile.name, "build");
        assert!(profile.fs_write.iter().any(|it| it == Path::new("./.venv")));
        assert!(profile
            .env_passthrough
            .iter()
            .any(|it| it == "PIP_CACHE_DIR"));
    }

    #[test]
    fn resolves_filtered_network_profile_with_allowed_domains() {
        let resolver = ProfileResolver::default();
        let tmp = unique_tmp_dir("clawcrate_profiles_filtered_network");
        let custom = tmp.join("filtered.yaml");

        write(
            &custom,
            r#"
name: filtered
network:
  mode: filtered
  allowed_domains:
    - "registry.npmjs.org"
    - "*.pkg.dev"
"#,
        );

        let profile = resolver
            .resolve_from_path(&custom)
            .expect("resolve filtered network profile");
        assert_eq!(
            profile.net,
            NetLevel::Filtered {
                allowed_domains: vec!["registry.npmjs.org".to_string(), "*.pkg.dev".to_string()]
            }
        );
    }

    #[test]
    fn filtered_network_requires_allowed_domains() {
        let resolver = ProfileResolver::default();
        let tmp = unique_tmp_dir("clawcrate_profiles_filtered_invalid");
        let custom = tmp.join("filtered-invalid.yaml");

        write(
            &custom,
            r#"
name: filtered-invalid
network:
  mode: filtered
"#,
        );

        let error = resolver
            .resolve_from_path(&custom)
            .expect_err("filtered network without allowed domains should fail");
        let message = error.to_string();
        assert!(message.contains("allowed_domains"));
    }

    #[test]
    fn validates_repository_community_catalog() {
        let resolver = ProfileResolver::default();
        let count = resolver
            .validate_community_catalog(resolver.community_catalog_path())
            .expect("validate bundled community catalog");
        assert!(count >= 1);
    }

    #[test]
    fn rejects_catalog_entry_with_parent_directory_escape() {
        let resolver = ProfileResolver::default();
        let tmp = unique_tmp_dir("clawcrate_profiles_catalog_path_escape");
        let catalog = tmp.join("catalog.yaml");

        write(
            &catalog,
            r#"
version: 1
profiles:
  - id: escaped-entry
    title: Escaped
    path: ../outside.yaml
"#,
        );

        let error = resolver
            .validate_community_catalog(&catalog)
            .expect_err("catalog path escape should fail");
        assert!(error.to_string().contains("cannot escape"));
    }

    #[test]
    fn rejects_catalog_entry_with_duplicate_id() {
        let resolver = ProfileResolver::default();
        let tmp = unique_tmp_dir("clawcrate_profiles_catalog_duplicate_id");
        let catalog = tmp.join("catalog.yaml");
        let first = tmp.join("one.yaml");
        let second = tmp.join("two.yaml");

        write(
            &first,
            r#"
name: one
extends: safe
"#,
        );
        write(
            &second,
            r#"
name: two
extends: safe
"#,
        );
        write(
            &catalog,
            r#"
version: 1
profiles:
  - id: duplicate
    title: One
    path: one.yaml
  - id: duplicate
    title: Two
    path: two.yaml
"#,
        );

        let error = resolver
            .validate_community_catalog(&catalog)
            .expect_err("duplicate catalog id should fail");
        assert!(error.to_string().contains("duplicate entry id"));
    }

    #[test]
    fn rejects_catalog_entry_with_duplicate_normalized_path_variants() {
        let resolver = ProfileResolver::default();
        let tmp = unique_tmp_dir("clawcrate_profiles_catalog_duplicate_path_variants");
        let catalog = tmp.join("catalog.yaml");
        let profile = tmp.join("one.yaml");

        write(
            &profile,
            r#"
name: one
extends: safe
"#,
        );
        write(
            &catalog,
            r#"
version: 1
profiles:
  - id: one
    title: One
    path: one.yaml
  - id: one-alt
    title: One Alt
    path: ./one.yaml
"#,
        );

        let error = resolver
            .validate_community_catalog(&catalog)
            .expect_err("duplicate normalized path variants should fail");
        assert!(error.to_string().contains("duplicate profile path"));
    }
}
