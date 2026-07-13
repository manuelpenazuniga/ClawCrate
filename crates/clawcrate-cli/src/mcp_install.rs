//! `clawcrate mcp install` / `clawcrate mcp uninstall`: config-writers that route
//! an MCP client's server entry through `clawcrate mcp wrap`.
//!
//! Safety properties enforced here:
//! - `--dry-run` prints the exact change and writes nothing.
//! - A real write always creates a timestamped backup of the original config.
//! - Already-wrapped entries are refused (idempotent, no double-wrap).
//! - Only the target server entry is edited; sibling entries and unrelated
//!   top-level keys are preserved (JSON object key order is not guaranteed;
//!   Continue.dev YAML sequence order is preserved).
//! - Only structure (`command`/`args`) is read and edited. Environment blocks,
//!   tokens, or other entries are never inspected or logged.

use std::ffi::OsStr;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use anyhow::{anyhow, bail, Result};
use chrono::Utc;
use clap::{ArgAction, Args, ValueEnum};
use serde::Serialize;
use serde_json::{json, Value as JsonValue};
use serde_yaml::{Mapping as YamlMapping, Value as YamlValue};

use crate::OutputOptions;

/// The binary the wrapped entry invokes. Assumed to be on `PATH`, matching the
/// documented integration recipes.
const WRAP_BIN: &str = "clawcrate";
/// The subcommand prefix that identifies a ClawCrate-wrapped entry.
const WRAP_SUBCOMMAND: [&str; 2] = ["mcp", "wrap"];

#[derive(Clone, Copy, Debug, PartialEq, Eq, ValueEnum)]
pub(crate) enum McpClient {
    /// Cursor (`~/.cursor/mcp.json`).
    Cursor,
    /// Claude Desktop (`claude_desktop_config.json`).
    Claude,
    /// Continue.dev (`~/.continue/config.yaml`).
    Continue,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ConfigFormat {
    Json,
    Yaml,
}

impl McpClient {
    fn label(self) -> &'static str {
        match self {
            McpClient::Cursor => "cursor",
            McpClient::Claude => "claude",
            McpClient::Continue => "continue",
        }
    }

    fn format(self) -> ConfigFormat {
        match self {
            McpClient::Cursor | McpClient::Claude => ConfigFormat::Json,
            McpClient::Continue => ConfigFormat::Yaml,
        }
    }

    /// Platform-convention config path for this client.
    fn default_config_path(self) -> Result<PathBuf> {
        let home = home_dir()?;
        let path = match self {
            McpClient::Cursor => home.join(".cursor").join("mcp.json"),
            McpClient::Claude => claude_desktop_config_path(&home),
            McpClient::Continue => home.join(".continue").join("config.yaml"),
        };
        Ok(path)
    }
}

fn home_dir() -> Result<PathBuf> {
    std::env::var_os("HOME")
        .map(PathBuf::from)
        .filter(|p| !p.as_os_str().is_empty())
        .ok_or_else(|| {
            anyhow!("cannot determine home directory (HOME not set); pass --config <path>")
        })
}

#[cfg(target_os = "macos")]
fn claude_desktop_config_path(home: &Path) -> PathBuf {
    home.join("Library")
        .join("Application Support")
        .join("Claude")
        .join("claude_desktop_config.json")
}

#[cfg(not(target_os = "macos"))]
fn claude_desktop_config_path(home: &Path) -> PathBuf {
    home.join(".config")
        .join("Claude")
        .join("claude_desktop_config.json")
}

#[derive(Debug, Args)]
pub(crate) struct McpInstallArgs {
    /// MCP client whose config file will be edited.
    #[arg(long, value_enum)]
    client: McpClient,

    /// Name of the server entry to wrap (the object key for Cursor/Claude, or
    /// the `name:` field for Continue.dev).
    #[arg(long)]
    server_name: String,

    /// Profile passed to `clawcrate mcp wrap` (e.g. mcp-readonly). If omitted,
    /// `wrap` auto-detects a conservative profile.
    #[arg(long)]
    profile: Option<String>,

    /// Override the config file location (defaults to the client convention).
    #[arg(long)]
    config: Option<PathBuf>,

    /// Print the change without writing anything.
    #[arg(long, action = ArgAction::SetTrue)]
    dry_run: bool,

    /// Machine-readable JSON output.
    #[arg(long, action = ArgAction::SetTrue)]
    json: bool,

    /// Original MCP server command to wrap (after `--`). If omitted, the
    /// existing entry's command is wrapped in place.
    #[arg(last = true, num_args = 0..)]
    command: Vec<String>,
}

#[derive(Debug, Args)]
pub(crate) struct McpUninstallArgs {
    /// MCP client whose config file will be edited.
    #[arg(long, value_enum)]
    client: McpClient,

    /// Name of the wrapped server entry to restore.
    #[arg(long)]
    server_name: String,

    /// Override the config file location (defaults to the client convention).
    #[arg(long)]
    config: Option<PathBuf>,

    /// Print the change without writing anything.
    #[arg(long, action = ArgAction::SetTrue)]
    dry_run: bool,

    /// Machine-readable JSON output.
    #[arg(long, action = ArgAction::SetTrue)]
    json: bool,
}

/// A server entry's launch command, the only structure this module edits.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub(crate) struct ServerCommand {
    pub command: String,
    pub args: Vec<String>,
}

/// Build the `mcp wrap` arg vector that fronts `inner`.
pub(crate) fn build_wrapped_args(
    profile: Option<&str>,
    inner_command: &str,
    inner_args: &[String],
) -> Vec<String> {
    let mut args: Vec<String> = WRAP_SUBCOMMAND.iter().map(|s| (*s).to_string()).collect();
    if let Some(profile) = profile {
        args.push("--profile".to_string());
        args.push(profile.to_string());
    }
    args.push("--".to_string());
    args.push(inner_command.to_string());
    args.extend(inner_args.iter().cloned());
    args
}

/// True if `command`/`args` are already a ClawCrate `mcp wrap` invocation.
pub(crate) fn is_wrapped(command: &str, args: &[String]) -> bool {
    command_is_clawcrate(command)
        && args.len() >= WRAP_SUBCOMMAND.len()
        && args[0] == WRAP_SUBCOMMAND[0]
        && args[1] == WRAP_SUBCOMMAND[1]
}

fn command_is_clawcrate(command: &str) -> bool {
    command == WRAP_BIN
        || Path::new(command)
            .file_name()
            .is_some_and(|name| name == OsStr::new(WRAP_BIN))
}

/// Recover the original command/args from a wrapped arg vector by reading
/// everything after the `--` separator.
pub(crate) fn unwrap_inner(args: &[String]) -> Option<ServerCommand> {
    let separator = args.iter().position(|arg| arg == "--")?;
    let rest = args.get(separator + 1..)?;
    let (command, inner_args) = rest.split_first()?;
    Some(ServerCommand {
        command: command.clone(),
        args: inner_args.to_vec(),
    })
}

// ---------------------------------------------------------------------------
// Config document handling
// ---------------------------------------------------------------------------

enum ConfigDoc {
    Json(JsonValue),
    Yaml(YamlValue),
}

impl ConfigDoc {
    fn load(path: &Path, format: ConfigFormat) -> Result<Self> {
        let contents = match fs::read_to_string(path) {
            Ok(contents) => contents,
            Err(err) if err.kind() == io::ErrorKind::NotFound => String::new(),
            Err(err) => return Err(anyhow!("failed to read {}: {err}", path.display())),
        };
        match format {
            ConfigFormat::Json => {
                if contents.trim().is_empty() {
                    Ok(ConfigDoc::Json(json!({})))
                } else {
                    let value: JsonValue = serde_json::from_str(&contents)
                        .map_err(|err| anyhow!("failed to parse {}: {err}", path.display()))?;
                    Ok(ConfigDoc::Json(value))
                }
            }
            ConfigFormat::Yaml => {
                if contents.trim().is_empty() {
                    Ok(ConfigDoc::Yaml(YamlValue::Mapping(YamlMapping::new())))
                } else {
                    let value: YamlValue = serde_yaml::from_str(&contents)
                        .map_err(|err| anyhow!("failed to parse {}: {err}", path.display()))?;
                    Ok(ConfigDoc::Yaml(value))
                }
            }
        }
    }

    /// Read the target entry's launch command, if the entry exists.
    fn find_entry(&self, name: &str) -> Result<Option<ServerCommand>> {
        match self {
            ConfigDoc::Json(doc) => match doc.get("mcpServers").and_then(|s| s.get(name)) {
                Some(entry) => Ok(Some(json_entry_command(entry)?)),
                None => Ok(None),
            },
            ConfigDoc::Yaml(doc) => match yaml_find_entry(doc, name) {
                Some(entry) => Ok(Some(yaml_entry_command(entry)?)),
                None => Ok(None),
            },
        }
    }

    /// Serialize just the target entry, for a human-readable diff.
    fn render_entry(&self, name: &str) -> Option<String> {
        match self {
            ConfigDoc::Json(doc) => doc
                .get("mcpServers")
                .and_then(|s| s.get(name))
                .and_then(|entry| serde_json::to_string_pretty(entry).ok()),
            ConfigDoc::Yaml(doc) => {
                yaml_find_entry(doc, name).and_then(|entry| serde_yaml::to_string(entry).ok())
            }
        }
    }

    /// Overwrite the target entry's `command`/`args`, preserving sibling fields
    /// and unrelated entries. Creates the entry (and `mcpServers` container) if
    /// missing.
    fn set_entry(&mut self, name: &str, command: &str, args: &[String]) -> Result<()> {
        match self {
            ConfigDoc::Json(doc) => json_set_entry(doc, name, command, args),
            ConfigDoc::Yaml(doc) => yaml_set_entry(doc, name, command, args),
        }
    }

    fn write(&self, path: &Path) -> Result<()> {
        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() {
                fs::create_dir_all(parent)
                    .map_err(|err| anyhow!("failed to create {}: {err}", parent.display()))?;
            }
        }
        let serialized = match self {
            ConfigDoc::Json(doc) => {
                let mut s = serde_json::to_string_pretty(doc)
                    .map_err(|err| anyhow!("failed to serialize config: {err}"))?;
                s.push('\n');
                s
            }
            ConfigDoc::Yaml(doc) => serde_yaml::to_string(doc)
                .map_err(|err| anyhow!("failed to serialize config: {err}"))?,
        };
        // Write atomically: a truncated/partial write would corrupt the user's
        // client config. Write to a sibling temp file (same directory, so the
        // rename stays on one filesystem) and rename it over the target.
        let file_name = path
            .file_name()
            .and_then(OsStr::to_str)
            .ok_or_else(|| anyhow!("cannot derive temp name for {}", path.display()))?;
        let temp_path =
            path.with_file_name(format!("{file_name}.clawcrate-tmp-{}", std::process::id()));
        fs::write(&temp_path, serialized).map_err(|err| {
            anyhow!(
                "failed to write temporary config {}: {err}",
                temp_path.display()
            )
        })?;
        fs::rename(&temp_path, path).map_err(|err| {
            let _ = fs::remove_file(&temp_path);
            anyhow!("failed to replace config {}: {err}", path.display())
        })
    }
}

fn json_entry_command(entry: &JsonValue) -> Result<ServerCommand> {
    let command = entry
        .get("command")
        .and_then(JsonValue::as_str)
        .ok_or_else(|| anyhow!("server entry has no string `command` field"))?
        .to_string();
    let args = match entry.get("args") {
        None | Some(JsonValue::Null) => Vec::new(),
        Some(JsonValue::Array(items)) => items
            .iter()
            .map(|item| {
                item.as_str()
                    .map(str::to_string)
                    .ok_or_else(|| anyhow!("server `args` entries must be strings"))
            })
            .collect::<Result<Vec<_>>>()?,
        Some(_) => bail!("server `args` must be an array of strings"),
    };
    Ok(ServerCommand { command, args })
}

fn json_set_entry(doc: &mut JsonValue, name: &str, command: &str, args: &[String]) -> Result<()> {
    let root = doc
        .as_object_mut()
        .ok_or_else(|| anyhow!("config root must be a JSON object"))?;
    let servers = root
        .entry("mcpServers")
        .or_insert_with(|| json!({}))
        .as_object_mut()
        .ok_or_else(|| anyhow!("`mcpServers` must be a JSON object"))?;
    let entry = servers
        .entry(name)
        .or_insert_with(|| json!({}))
        .as_object_mut()
        .ok_or_else(|| anyhow!("server entry `{name}` must be a JSON object"))?;
    entry.insert("command".to_string(), json!(command));
    entry.insert("args".to_string(), json!(args));
    Ok(())
}

fn yaml_find_entry<'a>(doc: &'a YamlValue, name: &str) -> Option<&'a YamlValue> {
    doc.get("mcpServers")?
        .as_sequence()?
        .iter()
        .find(|item| item.get("name").and_then(YamlValue::as_str) == Some(name))
}

fn yaml_entry_command(entry: &YamlValue) -> Result<ServerCommand> {
    let command = entry
        .get("command")
        .and_then(YamlValue::as_str)
        .ok_or_else(|| anyhow!("server entry has no string `command` field"))?
        .to_string();
    let args = match entry.get("args") {
        None | Some(YamlValue::Null) => Vec::new(),
        Some(YamlValue::Sequence(items)) => items
            .iter()
            .map(|item| {
                item.as_str()
                    .map(str::to_string)
                    .ok_or_else(|| anyhow!("server `args` entries must be strings"))
            })
            .collect::<Result<Vec<_>>>()?,
        Some(_) => bail!("server `args` must be a sequence of strings"),
    };
    Ok(ServerCommand { command, args })
}

fn yaml_set_entry(doc: &mut YamlValue, name: &str, command: &str, args: &[String]) -> Result<()> {
    if doc.is_null() {
        *doc = YamlValue::Mapping(YamlMapping::new());
    }
    let root = doc
        .as_mapping_mut()
        .ok_or_else(|| anyhow!("Continue config root must be a mapping"))?;
    let servers = root
        .entry(YamlValue::String("mcpServers".to_string()))
        .or_insert_with(|| YamlValue::Sequence(Vec::new()))
        .as_sequence_mut()
        .ok_or_else(|| anyhow!("`mcpServers` must be a sequence"))?;

    let args_seq = YamlValue::Sequence(
        args.iter()
            .map(|arg| YamlValue::String(arg.clone()))
            .collect(),
    );

    if let Some(item) = servers
        .iter_mut()
        .find(|item| item.get("name").and_then(YamlValue::as_str) == Some(name))
    {
        let mapping = item
            .as_mapping_mut()
            .ok_or_else(|| anyhow!("server entry `{name}` must be a mapping"))?;
        mapping.insert(
            YamlValue::String("command".to_string()),
            YamlValue::String(command.to_string()),
        );
        mapping.insert(YamlValue::String("args".to_string()), args_seq);
        return Ok(());
    }

    let mut mapping = YamlMapping::new();
    mapping.insert(
        YamlValue::String("name".to_string()),
        YamlValue::String(name.to_string()),
    );
    mapping.insert(
        YamlValue::String("type".to_string()),
        YamlValue::String("stdio".to_string()),
    );
    mapping.insert(
        YamlValue::String("command".to_string()),
        YamlValue::String(command.to_string()),
    );
    mapping.insert(YamlValue::String("args".to_string()), args_seq);
    servers.push(YamlValue::Mapping(mapping));
    Ok(())
}

/// Copy the existing config to a timestamped sibling before overwriting it.
/// Returns `None` when there is nothing to back up (fresh config).
fn backup_existing(path: &Path) -> Result<Option<PathBuf>> {
    if !path.exists() {
        return Ok(None);
    }
    let stamp = Utc::now().format("%Y%m%dT%H%M%SZ");
    let file_name = path
        .file_name()
        .and_then(OsStr::to_str)
        .ok_or_else(|| anyhow!("cannot derive backup name for {}", path.display()))?;
    let backup = path.with_file_name(format!("{file_name}.clawcrate-backup-{stamp}"));
    fs::copy(path, &backup)
        .map_err(|err| anyhow!("failed to write backup {}: {err}", backup.display()))?;
    Ok(Some(backup))
}

// ---------------------------------------------------------------------------
// Command handlers
// ---------------------------------------------------------------------------

#[derive(Debug, Serialize)]
struct InstallReport {
    action: &'static str,
    client: &'static str,
    config: String,
    server_name: String,
    dry_run: bool,
    wrote: bool,
    backup: Option<String>,
    before: Option<ServerCommand>,
    after: ServerCommand,
}

pub(crate) fn handle_install(args: McpInstallArgs, output: &OutputOptions) -> Result<()> {
    let path = match &args.config {
        Some(path) => path.clone(),
        None => args.client.default_config_path()?,
    };
    let format = args.client.format();
    let mut doc = ConfigDoc::load(&path, format)?;
    let existing = doc.find_entry(&args.server_name)?;

    if let Some(entry) = &existing {
        if is_wrapped(&entry.command, &entry.args) {
            bail!(
                "server '{}' in {} is already wrapped by ClawCrate; run \
                 `clawcrate mcp uninstall` first",
                args.server_name,
                path.display()
            );
        }
    }

    let inner = if !args.command.is_empty() {
        ServerCommand {
            command: args.command[0].clone(),
            args: args.command[1..].to_vec(),
        }
    } else if let Some(entry) = existing.clone() {
        entry
    } else {
        bail!(
            "no command to wrap: server '{}' not found in {} and no `-- <command>` provided",
            args.server_name,
            path.display()
        );
    };

    let wrapped_args = build_wrapped_args(args.profile.as_deref(), &inner.command, &inner.args);
    let after = ServerCommand {
        command: WRAP_BIN.to_string(),
        args: wrapped_args.clone(),
    };

    let before_render = doc.render_entry(&args.server_name);
    doc.set_entry(&args.server_name, WRAP_BIN, &wrapped_args)?;
    let after_render = doc.render_entry(&args.server_name);

    let mut backup = None;
    let mut wrote = false;
    if !args.dry_run {
        backup = backup_existing(&path)?;
        doc.write(&path)?;
        wrote = true;
    }

    let report = InstallReport {
        action: "install",
        client: args.client.label(),
        config: path.display().to_string(),
        server_name: args.server_name.clone(),
        dry_run: args.dry_run,
        wrote,
        backup: backup.as_ref().map(|p| p.display().to_string()),
        before: existing,
        after,
    };

    emit_report(
        &report,
        args.json,
        before_render.as_deref(),
        after_render.as_deref(),
        output,
    )
}

pub(crate) fn handle_uninstall(args: McpUninstallArgs, output: &OutputOptions) -> Result<()> {
    let path = match &args.config {
        Some(path) => path.clone(),
        None => args.client.default_config_path()?,
    };
    let format = args.client.format();

    if !path.exists() {
        bail!("config not found: {}", path.display());
    }

    let mut doc = ConfigDoc::load(&path, format)?;
    let existing = doc.find_entry(&args.server_name)?.ok_or_else(|| {
        anyhow!(
            "server '{}' not found in {}",
            args.server_name,
            path.display()
        )
    })?;

    if !is_wrapped(&existing.command, &existing.args) {
        bail!(
            "server '{}' in {} is not wrapped by ClawCrate; nothing to uninstall",
            args.server_name,
            path.display()
        );
    }

    let restored = unwrap_inner(&existing.args).ok_or_else(|| {
        anyhow!(
            "could not recover the original command for '{}' (no `--` separator in wrapped args)",
            args.server_name
        )
    })?;

    let before_render = doc.render_entry(&args.server_name);
    doc.set_entry(&args.server_name, &restored.command, &restored.args)?;
    let after_render = doc.render_entry(&args.server_name);

    let mut backup = None;
    let mut wrote = false;
    if !args.dry_run {
        backup = backup_existing(&path)?;
        doc.write(&path)?;
        wrote = true;
    }

    let report = InstallReport {
        action: "uninstall",
        client: args.client.label(),
        config: path.display().to_string(),
        server_name: args.server_name.clone(),
        dry_run: args.dry_run,
        wrote,
        backup: backup.as_ref().map(|p| p.display().to_string()),
        before: Some(existing),
        after: restored,
    };

    emit_report(
        &report,
        args.json,
        before_render.as_deref(),
        after_render.as_deref(),
        output,
    )
}

fn emit_report(
    report: &InstallReport,
    json: bool,
    before_render: Option<&str>,
    after_render: Option<&str>,
    output: &OutputOptions,
) -> Result<()> {
    if json {
        println!("{}", serde_json::to_string_pretty(report)?);
        return Ok(());
    }

    let verb = if report.dry_run {
        "would rewrite"
    } else {
        "rewrote"
    };
    println!(
        "{verb} server '{}' ({}) in {}",
        report.server_name, report.client, report.config
    );
    println!();
    print_diff(before_render, after_render, output);

    if report.dry_run {
        println!();
        println!("dry run: no files were written.");
    } else {
        if let Some(backup) = &report.backup {
            println!();
            println!("backup written to {backup}");
        }
        println!("updated {}", report.config);
    }
    Ok(())
}

fn print_diff(before_render: Option<&str>, after_render: Option<&str>, output: &OutputOptions) {
    match before_render {
        Some(before) => {
            for line in before.lines() {
                print_diff_line('-', line, output);
            }
        }
        None => print_diff_line('-', "(new entry)", output),
    }
    if let Some(after) = after_render {
        for line in after.lines() {
            print_diff_line('+', line, output);
        }
    }
}

fn print_diff_line(marker: char, line: &str, output: &OutputOptions) {
    if output.color {
        let color = if marker == '-' { "31" } else { "32" };
        println!("\u{1b}[{color}m{marker} {line}\u{1b}[0m");
    } else {
        println!("{marker} {line}");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn s(values: &[&str]) -> Vec<String> {
        values.iter().map(|v| (*v).to_string()).collect()
    }

    #[test]
    fn build_wrapped_args_includes_profile_and_separator() {
        let args = build_wrapped_args(
            Some("mcp-readonly"),
            "npx",
            &s(&["-y", "@modelcontextprotocol/server-filesystem", "/Users/me"]),
        );
        assert_eq!(
            args,
            s(&[
                "mcp",
                "wrap",
                "--profile",
                "mcp-readonly",
                "--",
                "npx",
                "-y",
                "@modelcontextprotocol/server-filesystem",
                "/Users/me",
            ])
        );
    }

    #[test]
    fn build_wrapped_args_without_profile_omits_flag() {
        let args = build_wrapped_args(None, "node", &s(&["server.js"]));
        assert_eq!(args, s(&["mcp", "wrap", "--", "node", "server.js"]));
    }

    #[test]
    fn is_wrapped_detects_bare_and_pathed_binary() {
        assert!(is_wrapped("clawcrate", &s(&["mcp", "wrap", "--", "npx"])));
        assert!(is_wrapped(
            "/usr/local/bin/clawcrate",
            &s(&["mcp", "wrap", "--", "npx"])
        ));
        assert!(!is_wrapped("npx", &s(&["-y", "server"])));
        assert!(!is_wrapped("clawcrate", &s(&["run", "--", "echo"])));
    }

    #[test]
    fn unwrap_inner_recovers_original_command() {
        let wrapped = build_wrapped_args(Some("mcp-readonly"), "npx", &s(&["-y", "server"]));
        let inner = unwrap_inner(&wrapped).expect("should unwrap");
        assert_eq!(inner.command, "npx");
        assert_eq!(inner.args, s(&["-y", "server"]));
    }

    #[test]
    fn wrap_then_unwrap_is_lossless() {
        let original = ServerCommand {
            command: "node".to_string(),
            args: s(&["dist/server.js", "--flag", "value"]),
        };
        let wrapped = build_wrapped_args(Some("mcp-server"), &original.command, &original.args);
        let restored = unwrap_inner(&wrapped).expect("should unwrap");
        assert_eq!(restored, original);
    }

    fn install_args(
        config: &Path,
        server_name: &str,
        command: Vec<String>,
        dry_run: bool,
    ) -> McpInstallArgs {
        McpInstallArgs {
            client: McpClient::Cursor,
            server_name: server_name.to_string(),
            profile: Some("mcp-readonly".to_string()),
            config: Some(config.to_path_buf()),
            dry_run,
            json: false,
            command,
        }
    }

    fn uninstall_args(config: &Path, server_name: &str, dry_run: bool) -> McpUninstallArgs {
        McpUninstallArgs {
            client: McpClient::Cursor,
            server_name: server_name.to_string(),
            config: Some(config.to_path_buf()),
            dry_run,
            json: false,
        }
    }

    fn temp_path(name: &str) -> PathBuf {
        let mut dir = std::env::temp_dir();
        let unique = format!(
            "clawcrate-mcp-install-test-{}-{}-{}",
            std::process::id(),
            name,
            uuid::Uuid::now_v7()
        );
        dir.push(unique);
        std::fs::create_dir_all(&dir).expect("create temp dir");
        dir.join(name)
    }

    fn output() -> OutputOptions {
        OutputOptions {
            verbose: 0,
            color: false,
        }
    }

    #[test]
    fn dry_run_writes_nothing() {
        let path = temp_path("mcp.json");
        let args = install_args(
            &path,
            "filesystem",
            s(&[
                "npx",
                "-y",
                "@modelcontextprotocol/server-filesystem",
                "/tmp",
            ]),
            true,
        );
        handle_install(args, &output()).expect("dry run should succeed");
        assert!(!path.exists(), "dry run must not create the config file");
    }

    #[test]
    fn install_creates_entry_and_backup_and_is_idempotent() {
        let path = temp_path("mcp.json");
        let existing = r#"{
  "mcpServers": {
    "other": { "command": "node", "args": ["keep.js"] }
  }
}"#;
        std::fs::write(&path, existing).expect("seed config");

        let args = install_args(
            &path,
            "filesystem",
            s(&["npx", "-y", "server-filesystem", "/tmp"]),
            false,
        );
        handle_install(args, &output()).expect("install should succeed");

        let doc = ConfigDoc::load(&path, ConfigFormat::Json).expect("reload");
        let wrapped = doc
            .find_entry("filesystem")
            .expect("lookup")
            .expect("entry present");
        assert_eq!(wrapped.command, "clawcrate");
        assert!(is_wrapped(&wrapped.command, &wrapped.args));
        // unrelated entry preserved
        let other = doc.find_entry("other").expect("lookup").expect("present");
        assert_eq!(other.command, "node");
        // backup exists
        let parent = path.parent().unwrap();
        let has_backup = std::fs::read_dir(parent)
            .unwrap()
            .filter_map(Result::ok)
            .any(|e| {
                e.file_name()
                    .to_string_lossy()
                    .contains("mcp.json.clawcrate-backup-")
            });
        assert!(has_backup, "a timestamped backup must be written");

        // second install must refuse to double-wrap
        let again = install_args(&path, "filesystem", Vec::new(), false);
        let err = handle_install(again, &output()).expect_err("double-wrap must fail");
        assert!(err.to_string().contains("already wrapped"));
    }

    #[test]
    fn install_wraps_existing_entry_without_command_arg() {
        let path = temp_path("mcp.json");
        let existing = r#"{ "mcpServers": { "fs": { "command": "npx", "args": ["-y", "srv"] } } }"#;
        std::fs::write(&path, existing).expect("seed");
        let args = install_args(&path, "fs", Vec::new(), false);
        handle_install(args, &output()).expect("wrap in place");
        let doc = ConfigDoc::load(&path, ConfigFormat::Json).expect("reload");
        let entry = doc.find_entry("fs").unwrap().unwrap();
        let inner = unwrap_inner(&entry.args).unwrap();
        assert_eq!(inner.command, "npx");
        assert_eq!(inner.args, s(&["-y", "srv"]));
    }

    #[test]
    fn install_missing_entry_without_command_fails() {
        let path = temp_path("mcp.json");
        std::fs::write(&path, r#"{"mcpServers":{}}"#).expect("seed");
        let args = install_args(&path, "ghost", Vec::new(), false);
        let err = handle_install(args, &output()).expect_err("should fail");
        assert!(err.to_string().contains("no command to wrap"));
    }

    #[test]
    fn uninstall_restores_original_command() {
        let path = temp_path("mcp.json");
        std::fs::write(&path, r#"{"mcpServers":{}}"#).expect("seed");
        let install = install_args(
            &path,
            "filesystem",
            s(&["npx", "-y", "server-filesystem", "/tmp"]),
            false,
        );
        handle_install(install, &output()).expect("install");

        let uninstall = uninstall_args(&path, "filesystem", false);
        handle_uninstall(uninstall, &output()).expect("uninstall");

        let doc = ConfigDoc::load(&path, ConfigFormat::Json).expect("reload");
        let restored = doc.find_entry("filesystem").unwrap().unwrap();
        assert_eq!(restored.command, "npx");
        assert_eq!(restored.args, s(&["-y", "server-filesystem", "/tmp"]));
        assert!(!is_wrapped(&restored.command, &restored.args));
    }

    #[test]
    fn uninstall_unwrapped_entry_fails() {
        let path = temp_path("mcp.json");
        std::fs::write(
            &path,
            r#"{"mcpServers":{"fs":{"command":"npx","args":["srv"]}}}"#,
        )
        .expect("seed");
        let err = handle_uninstall(uninstall_args(&path, "fs", false), &output())
            .expect_err("should fail");
        assert!(err.to_string().contains("not wrapped"));
    }

    #[test]
    fn continue_yaml_list_is_wrapped_and_restored() {
        let path = temp_path("config.yaml");
        let existing = "mcpServers:\n  - name: Filesystem\n    type: stdio\n    command: npx\n    args:\n      - \"-y\"\n      - server-filesystem\n";
        std::fs::write(&path, existing).expect("seed");

        // install (wrap in place)
        let install = McpInstallArgs {
            client: McpClient::Continue,
            server_name: "Filesystem".to_string(),
            profile: Some("mcp-readonly".to_string()),
            config: Some(path.clone()),
            dry_run: false,
            json: false,
            command: Vec::new(),
        };
        handle_install(install, &output()).expect("wrap yaml");

        let doc = ConfigDoc::load(&path, ConfigFormat::Yaml).expect("reload");
        let entry = doc.find_entry("Filesystem").unwrap().unwrap();
        assert_eq!(entry.command, "clawcrate");
        assert!(is_wrapped(&entry.command, &entry.args));

        // uninstall restores original
        let uninstall = McpUninstallArgs {
            client: McpClient::Continue,
            server_name: "Filesystem".to_string(),
            config: Some(path.clone()),
            dry_run: false,
            json: false,
        };
        handle_uninstall(uninstall, &output()).expect("unwrap yaml");
        let doc = ConfigDoc::load(&path, ConfigFormat::Yaml).expect("reload");
        let restored = doc.find_entry("Filesystem").unwrap().unwrap();
        assert_eq!(restored.command, "npx");
        assert_eq!(restored.args, s(&["-y", "server-filesystem"]));
    }
}
