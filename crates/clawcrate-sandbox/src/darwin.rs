use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{SystemTime, UNIX_EPOCH};

use clawcrate_types::{ExecutionPlan, NetLevel};
use thiserror::Error;

use crate::env_scrub::scrub_environment;

#[derive(Debug, Clone)]
pub struct DarwinSandboxPaths {
    pub sandbox_exec: PathBuf,
    pub temp_root: PathBuf,
}

impl Default for DarwinSandboxPaths {
    fn default() -> Self {
        Self {
            sandbox_exec: PathBuf::from("/usr/bin/sandbox-exec"),
            temp_root: std::env::temp_dir().join("clawcrate").join("sbpl"),
        }
    }
}

#[derive(Debug, Clone)]
pub struct PreparedDarwinSandbox {
    pub execution_id: String,
    pub command: Vec<String>,
    pub cwd: PathBuf,
    pub fs_read: Vec<PathBuf>,
    pub fs_write: Vec<PathBuf>,
    pub fs_deny: Vec<String>,
    pub net: NetLevel,
    pub scrubbed_env: Vec<(String, String)>,
    pub scrubbed_keys: Vec<String>,
    pub sbpl_profile: String,
}

#[derive(Debug, Error)]
pub enum DarwinSandboxError {
    #[error("command is empty")]
    EmptyCommand,
    #[error("failed to create SBPL temp directory: {0}")]
    CreateTempDir(#[source] io::Error),
    #[error("failed to write SBPL profile file: {0}")]
    WriteProfile(#[source] io::Error),
    #[error("failed to spawn sandbox-exec process: {0}")]
    Spawn(#[source] io::Error),
}

pub struct DarwinSandbox {
    paths: DarwinSandboxPaths,
}

impl Default for DarwinSandbox {
    fn default() -> Self {
        Self::new_with_paths(DarwinSandboxPaths::default())
    }
}

impl DarwinSandbox {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn new_with_paths(paths: DarwinSandboxPaths) -> Self {
        Self { paths }
    }

    pub fn prepare(&self, plan: &ExecutionPlan) -> PreparedDarwinSandbox {
        self.prepare_with_env(plan, std::env::vars())
    }

    pub fn prepare_with_env<I>(&self, plan: &ExecutionPlan, env_vars: I) -> PreparedDarwinSandbox
    where
        I: IntoIterator<Item = (String, String)>,
    {
        let scrubbed = scrub_environment(
            env_vars,
            &plan.profile.env_scrub,
            &plan.profile.env_passthrough,
        );
        let home = home_from_env(&scrubbed.kept);

        let mut prepared = PreparedDarwinSandbox {
            execution_id: plan.id.clone(),
            command: plan.command.clone(),
            cwd: plan.cwd.clone(),
            fs_read: plan.profile.fs_read.clone(),
            fs_write: plan.profile.fs_write.clone(),
            fs_deny: plan.profile.fs_deny.clone(),
            net: plan.profile.net.clone(),
            scrubbed_env: scrubbed.kept,
            scrubbed_keys: scrubbed.removed,
            sbpl_profile: String::new(),
        };
        prepared.sbpl_profile = generate_sbpl_profile(&prepared, home.as_deref());
        prepared
    }

    pub fn launch(
        &self,
        prepared: &PreparedDarwinSandbox,
    ) -> Result<DarwinSandboxedChild, DarwinSandboxError> {
        if prepared.command.is_empty() {
            return Err(DarwinSandboxError::EmptyCommand);
        }

        fs::create_dir_all(&self.paths.temp_root).map_err(DarwinSandboxError::CreateTempDir)?;
        let sbpl_path = unique_sbpl_path(&self.paths.temp_root, &prepared.execution_id);
        fs::write(&sbpl_path, &prepared.sbpl_profile).map_err(DarwinSandboxError::WriteProfile)?;

        let mut command = Command::new(&self.paths.sandbox_exec);
        command.arg("-f").arg(&sbpl_path).arg("--");
        command.arg(&prepared.command[0]);
        command.args(&prepared.command[1..]);
        command.current_dir(&prepared.cwd);
        command.stdin(Stdio::null());
        command.stdout(Stdio::piped());
        command.stderr(Stdio::piped());
        command.env_clear();
        command.envs(prepared.scrubbed_env.iter().cloned());

        let child = command.spawn().map_err(DarwinSandboxError::Spawn)?;
        Ok(DarwinSandboxedChild {
            child,
            sbpl_profile_path: sbpl_path,
        })
    }
}

pub struct DarwinSandboxedChild {
    child: Child,
    sbpl_profile_path: PathBuf,
}

impl DarwinSandboxedChild {
    pub fn pid(&self) -> u32 {
        self.child.id()
    }

    pub fn child_mut(&mut self) -> &mut Child {
        &mut self.child
    }

    pub fn sbpl_profile_path(&self) -> &Path {
        &self.sbpl_profile_path
    }

    pub fn wait(&mut self) -> Result<std::process::ExitStatus, io::Error> {
        let status = self.child.wait()?;
        cleanup_sbpl_profile(&self.sbpl_profile_path);
        Ok(status)
    }

    pub fn wait_with_output(self) -> Result<std::process::Output, io::Error> {
        let output = self.child.wait_with_output()?;
        cleanup_sbpl_profile(&self.sbpl_profile_path);
        Ok(output)
    }
}

fn cleanup_sbpl_profile(path: &Path) {
    if let Err(error) = fs::remove_file(path) {
        if error.kind() != io::ErrorKind::NotFound {
            let _ = error;
        }
    }
}

fn unique_sbpl_path(temp_root: &Path, execution_id: &str) -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_nanos())
        .unwrap_or(0);
    temp_root.join(format!(
        "sbpl_{execution_id}_{}_{}.sb",
        std::process::id(),
        nanos
    ))
}

fn home_from_env(env: &[(String, String)]) -> Option<PathBuf> {
    env.iter()
        .find_map(|(key, value)| (key == "HOME" && !value.is_empty()).then(|| PathBuf::from(value)))
}

fn generate_sbpl_profile(prepared: &PreparedDarwinSandbox, home: Option<&Path>) -> String {
    let mut lines = vec![
        "(version 1)".to_string(),
        "(deny default)".to_string(),
        "(allow process-exec)".to_string(),
        "(allow process-fork)".to_string(),
        "(allow signal (target self))".to_string(),
        "(allow file-read-metadata)".to_string(),
        "(allow sysctl-read)".to_string(),
    ];

    match prepared.net {
        NetLevel::None => lines.push("(deny network*)".to_string()),
        NetLevel::Open => lines.push("(allow network*)".to_string()),
        NetLevel::Filtered { .. } => lines.push("(allow network*)".to_string()),
    }

    lines.extend(prepared.fs_read.iter().flat_map(|path| {
        let path_escaped = escape_sbpl_string(&path.to_string_lossy());
        [
            format!("(allow file-read* (literal \"{path_escaped}\"))"),
            format!("(allow file-read* (subpath \"{path_escaped}\"))"),
        ]
    }));

    lines.extend(prepared.fs_write.iter().flat_map(|path| {
        let path_escaped = escape_sbpl_string(&path.to_string_lossy());
        [
            format!("(allow file-read* (literal \"{path_escaped}\"))"),
            format!("(allow file-read* (subpath \"{path_escaped}\"))"),
            format!("(allow file-write* (literal \"{path_escaped}\"))"),
            format!("(allow file-write* (subpath \"{path_escaped}\"))"),
        ]
    }));

    for pattern in &prepared.fs_deny {
        let expanded = expand_tilde_pattern(pattern, home);
        let regex = escape_sbpl_regex(&glob_to_regex(&expanded));
        lines.push(format!("(deny file-read* (regex #\"{regex}\"))"));
        lines.push(format!("(deny file-write* (regex #\"{regex}\"))"));
    }

    for sensitive in sensitive_deny_paths(home) {
        let escaped = escape_sbpl_string(&sensitive.to_string_lossy());
        lines.push(format!("(deny file-read* (subpath \"{escaped}\"))"));
        lines.push(format!("(deny file-write* (subpath \"{escaped}\"))"));
    }

    lines.join("\n")
}

fn expand_tilde_pattern(pattern: &str, home: Option<&Path>) -> String {
    if let Some(relative) = pattern.strip_prefix("~/") {
        if let Some(home_path) = home {
            return home_path.join(relative).to_string_lossy().to_string();
        }
    }

    pattern.to_string()
}

fn sensitive_deny_paths(home: Option<&Path>) -> Vec<PathBuf> {
    let Some(home_path) = home else {
        return Vec::new();
    };

    vec![
        home_path.join(".ssh"),
        home_path.join(".aws"),
        home_path.join(".gnupg"),
        home_path.join(".docker"),
        home_path.join("Library").join("Keychains"),
        home_path.join("Library").join("Cookies"),
    ]
}

fn escape_sbpl_string(value: &str) -> String {
    value
        .replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace('\n', "\\n")
}

fn escape_sbpl_regex(value: &str) -> String {
    value.replace('\\', "\\\\").replace('"', "\\\"")
}

fn glob_to_regex(glob: &str) -> String {
    let mut regex = String::from("^");
    let mut chars = glob.chars().peekable();

    while let Some(ch) = chars.next() {
        match ch {
            '*' => {
                if matches!(chars.peek(), Some('*')) {
                    chars.next();
                    regex.push_str(".*");
                } else {
                    regex.push_str("[^/]*");
                }
            }
            '?' => regex.push_str("[^/]"),
            '.' | '+' | '(' | ')' | '{' | '}' | '[' | ']' | '^' | '$' | '|' | '\\' => {
                regex.push('\\');
                regex.push(ch);
            }
            other => regex.push(other),
        }
    }

    regex.push('$');
    regex
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::os::unix::fs::PermissionsExt;
    use std::path::{Path, PathBuf};
    use std::time::{SystemTime, UNIX_EPOCH};

    use chrono::Utc;
    use clawcrate_types::{
        Actor, DefaultMode, ExecutionPlan, NetLevel, ResolvedProfile, ResourceLimits, WorkspaceMode,
    };

    use super::{DarwinSandbox, DarwinSandboxError, DarwinSandboxPaths};

    fn unique_tmp_dir(prefix: &str) -> PathBuf {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system time after unix epoch")
            .as_nanos();
        let dir = std::env::temp_dir().join(format!("{prefix}_{nanos}_{}", std::process::id()));
        fs::create_dir_all(&dir).expect("create temp test directory");
        dir
    }

    fn make_executable(path: &PathBuf) {
        let mut perms = fs::metadata(path)
            .expect("read metadata for executable")
            .permissions();
        perms.set_mode(0o755);
        fs::set_permissions(path, perms).expect("set executable permissions");
    }

    fn shell_quote_single(path: &Path) -> String {
        format!("'{}'", path.to_string_lossy().replace('\'', "'\"'\"'"))
    }

    fn test_plan(command: Vec<String>, net: NetLevel) -> ExecutionPlan {
        ExecutionPlan {
            id: "exec-test".to_string(),
            command,
            cwd: PathBuf::from("/tmp/workspace"),
            profile: ResolvedProfile {
                name: "build".to_string(),
                fs_read: vec![
                    PathBuf::from("/tmp/workspace"),
                    PathBuf::from("/Applications/Xcode.app"),
                ],
                fs_write: vec![
                    PathBuf::from("/tmp/workspace"),
                    PathBuf::from("/tmp/build-output"),
                ],
                fs_deny: vec![
                    "**/*.pem".to_string(),
                    "~/.env*".to_string(),
                    "/private/tmp/secrets/*".to_string(),
                ],
                net,
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
        }
    }

    #[test]
    fn prepare_generates_sbpl_with_expected_sections() {
        let sandbox = DarwinSandbox::new();
        let plan = test_plan(
            vec!["/bin/echo".to_string(), "ok".to_string()],
            NetLevel::None,
        );
        let prepared = sandbox.prepare_with_env(
            &plan,
            vec![
                ("HOME".to_string(), "/tmp/home-user".to_string()),
                ("PATH".to_string(), "/usr/bin".to_string()),
                ("MY_SECRET_TOKEN".to_string(), "hidden".to_string()),
            ],
        );

        assert!(prepared.sbpl_profile.contains("(version 1)"));
        assert!(prepared.sbpl_profile.contains("(deny default)"));
        assert!(prepared.sbpl_profile.contains("(allow file-read-metadata)"));
        assert!(prepared.sbpl_profile.contains("(allow sysctl-read)"));
        assert!(prepared.sbpl_profile.contains("(deny network*)"));
        assert!(prepared
            .sbpl_profile
            .contains("(deny file-read* (subpath \"/tmp/home-user/.ssh\"))"));
        assert!(prepared
            .sbpl_profile
            .contains("(deny file-read* (subpath \"/tmp/home-user/Library/Keychains\"))"));
        assert!(prepared.sbpl_profile.contains("(regex #\""));
        assert!(prepared.sbpl_profile.contains("pem"));
        assert!(prepared
            .scrubbed_keys
            .contains(&"MY_SECRET_TOKEN".to_string()));
    }

    #[test]
    fn prepare_uses_allow_network_rule_when_profile_opens_network() {
        let sandbox = DarwinSandbox::new();
        let plan = test_plan(
            vec!["/bin/echo".to_string(), "ok".to_string()],
            NetLevel::Open,
        );
        let prepared = sandbox.prepare_with_env(
            &plan,
            vec![
                ("HOME".to_string(), "/tmp/home-user".to_string()),
                ("PATH".to_string(), "/usr/bin".to_string()),
            ],
        );

        assert!(prepared.sbpl_profile.contains("(allow network*)"));
        assert!(!prepared.sbpl_profile.contains("(deny network*)"));
    }

    #[test]
    fn launch_runs_sandbox_exec_with_sbpl_and_scrubbed_environment() {
        let tmp = unique_tmp_dir("clawcrate_darwin_launch");
        let fake_sandbox_exec = tmp.join("sandbox-exec");
        let args_log = tmp.join("args.log");
        let env_log = tmp.join("env.log");
        let script = format!(
            "#!/bin/sh\n\
set -eu\n\
args_log={}\n\
env_log={}\n\
printf '%s\\n' \"$@\" > \"$args_log\"\n\
env > \"$env_log\"\n\
if [ \"$1\" != \"-f\" ]; then exit 11; fi\n\
shift 2\n\
if [ \"$1\" != \"--\" ]; then exit 12; fi\n\
shift\n\
exec \"$@\"\n",
            shell_quote_single(&args_log),
            shell_quote_single(&env_log)
        );
        fs::write(&fake_sandbox_exec, script).expect("write fake sandbox-exec");
        make_executable(&fake_sandbox_exec);

        let sandbox = DarwinSandbox::new_with_paths(DarwinSandboxPaths {
            sandbox_exec: fake_sandbox_exec,
            temp_root: tmp.join("sbpl"),
        });

        let mut plan = test_plan(
            vec![
                "/bin/sh".to_string(),
                "-c".to_string(),
                "printf '%s' \"$HOME\"".to_string(),
            ],
            NetLevel::None,
        );
        let workspace = tmp.join("workspace");
        fs::create_dir_all(&workspace).expect("create workspace for launch test");
        plan.cwd = workspace;
        let prepared = sandbox.prepare_with_env(
            &plan,
            vec![
                ("HOME".to_string(), "/tmp/home-runner".to_string()),
                ("PATH".to_string(), "/usr/bin:/bin".to_string()),
                ("MY_SECRET_TOKEN".to_string(), "hidden".to_string()),
            ],
        );

        let child = sandbox.launch(&prepared).expect("launch should succeed");
        let sbpl_path = child.sbpl_profile_path().to_path_buf();
        let output = child.wait_with_output().expect("wait with output");

        assert!(output.status.success());
        let stdout = String::from_utf8(output.stdout).expect("utf8 stdout");
        assert_eq!(stdout, "/tmp/home-runner");
        assert!(
            !sbpl_path.exists(),
            "SBPL file should be removed after wait"
        );

        let args = fs::read_to_string(&args_log).expect("read args log");
        let args: Vec<&str> = args.lines().collect();
        assert_eq!(args[0], "-f");
        assert_eq!(args[2], "--");
        assert_eq!(args[3], "/bin/sh");

        let env_contents = fs::read_to_string(&env_log).expect("read env log");
        assert!(env_contents.contains("HOME=/tmp/home-runner"));
        assert!(!env_contents.contains("MY_SECRET_TOKEN=hidden"));
    }

    #[test]
    fn launch_rejects_empty_command() {
        let sandbox = DarwinSandbox::new();
        let plan = test_plan(Vec::new(), NetLevel::None);
        let prepared = sandbox.prepare_with_env(
            &plan,
            vec![
                ("HOME".to_string(), "/tmp/home-user".to_string()),
                ("PATH".to_string(), "/usr/bin".to_string()),
            ],
        );

        let result = sandbox.launch(&prepared);
        assert!(matches!(result, Err(DarwinSandboxError::EmptyCommand)));
    }
}
