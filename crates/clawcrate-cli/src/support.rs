//! support module (extracted from main.rs; see #277).

use std::path::{Path, PathBuf};

use crate::output::*;
use anyhow::{anyhow, Result};
use chrono::Utc;
use clawcrate_audit::{ArtifactWriter, SqliteAuditIndex, DEFAULT_AUDIT_DB};
use clawcrate_capture::FsChange;
use clawcrate_sandbox::egress_proxy::{start_egress_proxy, EgressProxyConfig, EgressProxyHandle};
use clawcrate_types::{
    AuditEvent, AuditEventKind, ExecutionPlan, ExecutionResult, NetLevel, ResolvedProfile, Status,
};

pub(crate) fn runs_root() -> Result<PathBuf> {
    Ok(clawcrate_home_root()?.join("runs"))
}

pub(crate) fn clawcrate_home_root() -> Result<PathBuf> {
    if let Some(home) = std::env::var_os("HOME") {
        return Ok(PathBuf::from(home).join(".clawcrate"));
    }
    let cwd = std::env::current_dir()
        .map_err(|source| anyhow!("failed to resolve current dir: {source}"))?;
    Ok(cwd.join(".clawcrate"))
}

pub(crate) fn configure_optional_sqlite_index(output: &OutputOptions) -> Option<SqliteAuditIndex> {
    let explicit_path = std::env::var_os("CLAWCRATE_AUDIT_SQLITE_PATH").map(PathBuf::from);
    let enabled_by_flag = std::env::var("CLAWCRATE_AUDIT_SQLITE")
        .map(|value| matches!(value.as_str(), "1" | "true" | "TRUE" | "yes" | "YES"))
        .unwrap_or(false);
    let db_path = match explicit_path {
        Some(path) => path,
        None if enabled_by_flag => match clawcrate_home_root() {
            Ok(root) => root.join(DEFAULT_AUDIT_DB),
            Err(error) => {
                eprintln!("warning: failed to resolve default SQLite audit path: {error}");
                return None;
            }
        },
        None => return None,
    };

    match SqliteAuditIndex::open(&db_path) {
        Ok(index) => {
            verbose_log(
                output,
                1,
                format!(
                    "sqlite audit index enabled at {}",
                    index.db_path().display()
                ),
            );
            Some(index)
        }
        Err(error) => {
            eprintln!("warning: failed to initialize SQLite audit index: {error}");
            None
        }
    }
}

pub(crate) fn maybe_index_artifacts_in_sqlite(
    index: &mut Option<SqliteAuditIndex>,
    writer: &ArtifactWriter,
    output: &OutputOptions,
) {
    let Some(indexer) = index.as_mut() else {
        return;
    };

    match indexer.index_artifacts_dir(writer.artifacts_dir()) {
        Ok(indexed) => {
            verbose_log(
                output,
                2,
                format!(
                    "sqlite audit index updated: execution_id={}, events={}, has_result={}",
                    indexed.execution_id, indexed.event_count, indexed.has_result
                ),
            );
        }
        Err(error) => {
            eprintln!("warning: failed to index run artifacts in SQLite: {error}");
        }
    }
}

pub(crate) fn resolve_fs_diff_roots(plan: &ExecutionPlan) -> Vec<PathBuf> {
    plan.profile
        .fs_write
        .iter()
        .map(|path| resolve_execution_path(&plan.cwd, path))
        .collect()
}

pub(crate) fn resolve_execution_path(cwd: &Path, path: &Path) -> PathBuf {
    let expanded = expand_home(path);
    if expanded.is_absolute() {
        expanded
    } else {
        cwd.join(expanded)
    }
}

pub(crate) fn normalize_profile_filesystem_paths(
    profile: &mut ResolvedProfile,
    execution_cwd: &Path,
) {
    profile.fs_read = profile
        .fs_read
        .iter()
        .map(|path| resolve_execution_path(execution_cwd, path))
        .collect();
    profile.fs_write = profile
        .fs_write
        .iter()
        .map(|path| resolve_execution_path(execution_cwd, path))
        .collect();
}

pub(crate) fn maybe_start_filtered_egress_proxy(
    net: &NetLevel,
    env: &mut Vec<(String, String)>,
) -> Result<Option<EgressProxyHandle>> {
    let NetLevel::Filtered { allowed_domains } = net else {
        return Ok(None);
    };

    let proxy = start_egress_proxy(EgressProxyConfig::from_allowed_domains(
        allowed_domains.clone(),
    ))
    .map_err(|source| anyhow!("failed to start filtered egress proxy: {source}"))?;
    upsert_env_vars(env, &proxy.proxy_env_vars());
    Ok(Some(proxy))
}

pub(crate) fn upsert_env_vars(env: &mut Vec<(String, String)>, values: &[(String, String)]) {
    for (key, value) in values {
        env.retain(|(existing_key, _)| existing_key != key);
        env.push((key.clone(), value.clone()));
    }
}

pub(crate) fn expand_home(path: &Path) -> PathBuf {
    let path_str = path.to_string_lossy();
    if path_str == "~" {
        if let Some(home) = std::env::var_os("HOME") {
            return PathBuf::from(home);
        }
    }
    if let Some(rest) = path_str.strip_prefix("~/") {
        if let Some(home) = std::env::var_os("HOME") {
            return PathBuf::from(home).join(rest);
        }
    }
    path.to_path_buf()
}

pub(crate) fn command_basename(command: &str) -> String {
    Path::new(command)
        .file_name()
        .and_then(|value| value.to_str())
        .map_or_else(
            || command.to_ascii_lowercase(),
            |value| value.to_ascii_lowercase(),
        )
}

pub(crate) fn append_audit_event(writer: &ArtifactWriter, event: AuditEventKind) -> Result<()> {
    writer
        .append_audit_event(&AuditEvent {
            timestamp: Utc::now(),
            event,
        })
        .map_err(|source| anyhow!("failed to append audit event: {source}"))
}

pub(crate) fn persist_sandbox_error_result(
    writer: &ArtifactWriter,
    execution_id: &str,
    duration_ms: u64,
    error: &anyhow::Error,
) -> Result<()> {
    writer
        .write_fs_diff(&Vec::<FsChange>::new())
        .map_err(|source| anyhow!("failed to write empty fs-diff artifact: {source}"))?;

    let result = ExecutionResult {
        id: execution_id.to_string(),
        exit_code: None,
        status: Status::SandboxError(error.to_string()),
        duration_ms,
        artifacts_dir: writer.artifacts_dir().to_path_buf(),
    };
    writer
        .write_result(&result)
        .map_err(|source| anyhow!("failed to write sandbox error result: {source}"))?;
    Ok(())
}
