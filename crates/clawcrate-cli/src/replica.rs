//! replica module (extracted from main.rs; see #277).

use std::ffi::OsStr;
use std::io::{self, IsTerminal, Write};
use std::path::{Component, Path, PathBuf};

use crate::{cli::*, output::*, support::*};
use anyhow::{anyhow, Result};
use clawcrate_audit::ArtifactWriter;
use clawcrate_capture::{FsChange, FsChangeKind};
use clawcrate_types::{AuditEventKind, DefaultMode, ExecutionPlan, WorkspaceMode};
use ignore::gitignore::{Gitignore, GitignoreBuilder};

#[derive(Clone, Copy)]
pub(crate) struct ReplicaDefaultExclusionRule {
    pub(crate) pattern: &'static str,
    pub(crate) matcher: fn(&Path) -> bool,
}

pub(crate) const REPLICA_DEFAULT_EXCLUSION_RULES: [ReplicaDefaultExclusionRule; 3] = [
    ReplicaDefaultExclusionRule {
        pattern: ".env",
        matcher: matches_exact_dotenv,
    },
    ReplicaDefaultExclusionRule {
        pattern: ".env.*",
        matcher: matches_secret_dotenv_variant,
    },
    ReplicaDefaultExclusionRule {
        pattern: "**/.git/config",
        matcher: matches_git_config_path,
    },
];

#[derive(Debug)]
pub(crate) struct ReplicaIgnoreConfig {
    pub(crate) matcher: Gitignore,
    pub(crate) user_patterns: Vec<String>,
}

pub(crate) fn materialize_workspace_for_execution(
    plan: &ExecutionPlan,
    writer: &ArtifactWriter,
) -> Result<()> {
    let WorkspaceMode::Replica { source, copy } = &plan.mode else {
        return Ok(());
    };

    let ignore_config = load_replica_ignore_config(source)?;
    copy_workspace_with_default_exclusions(source, copy, &ignore_config)?;
    let mut excluded = REPLICA_DEFAULT_EXCLUSION_RULES
        .iter()
        .map(|rule| rule.pattern.to_string())
        .collect::<Vec<_>>();
    excluded.extend(ignore_config.user_patterns);
    append_audit_event(
        writer,
        AuditEventKind::ReplicaCreated {
            source: source.clone(),
            copy: copy.clone(),
            excluded,
        },
    )?;
    Ok(())
}

pub(crate) fn load_replica_ignore_config(source_root: &Path) -> Result<ReplicaIgnoreConfig> {
    let ignore_path = source_root.join(".clawcrateignore");
    let user_patterns = load_user_ignore_patterns(&ignore_path)?;

    let mut builder = GitignoreBuilder::new(source_root);
    if ignore_path.is_file() {
        if let Some(source) = builder.add(&ignore_path) {
            return Err(anyhow!(
                "failed to parse {}: {source}",
                ignore_path.display()
            ));
        }
    }

    let matcher = builder.build().map_err(|source| {
        anyhow!(
            "failed to build .clawcrateignore matcher from {}: {source}",
            ignore_path.display()
        )
    })?;

    Ok(ReplicaIgnoreConfig {
        matcher,
        user_patterns,
    })
}

pub(crate) fn load_user_ignore_patterns(ignore_path: &Path) -> Result<Vec<String>> {
    if !ignore_path.is_file() {
        return Ok(Vec::new());
    }

    let content = std::fs::read_to_string(ignore_path)
        .map_err(|source| anyhow!("failed to read {}: {source}", ignore_path.display()))?;
    Ok(content
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
        .map(ToString::to_string)
        .collect())
}

pub(crate) fn copy_workspace_with_default_exclusions(
    source: &Path,
    copy: &Path,
    ignore_config: &ReplicaIgnoreConfig,
) -> Result<()> {
    if !source.is_dir() {
        return Err(anyhow!(
            "replica source workspace does not exist or is not a directory: {}",
            source.display()
        ));
    }

    if copy.exists() {
        std::fs::remove_dir_all(copy).map_err(|source_error| {
            anyhow!(
                "failed to clean existing replica workspace at {}: {source_error}",
                copy.display()
            )
        })?;
    }
    std::fs::create_dir_all(copy).map_err(|source_error| {
        anyhow!(
            "failed to create replica workspace at {}: {source_error}",
            copy.display()
        )
    })?;

    copy_directory_recursive(source, copy, source, ignore_config)?;
    Ok(())
}

pub(crate) fn copy_directory_recursive(
    source_dir: &Path,
    target_dir: &Path,
    source_root: &Path,
    ignore_config: &ReplicaIgnoreConfig,
) -> Result<()> {
    for entry in std::fs::read_dir(source_dir).map_err(|source_error| {
        anyhow!(
            "failed to read source workspace directory {}: {source_error}",
            source_dir.display()
        )
    })? {
        let entry = entry.map_err(|source_error| {
            anyhow!(
                "failed to read source workspace entry in {}: {source_error}",
                source_dir.display()
            )
        })?;
        let source_path = entry.path();
        let relative_path = source_path
            .strip_prefix(source_root)
            .map_err(|source_error| {
                anyhow!("failed to compute relative source path: {source_error}")
            })?;

        let target_path = target_dir.join(entry.file_name());
        let file_type = entry.file_type().map_err(|source_error| {
            anyhow!(
                "failed to inspect source entry type {}: {source_error}",
                source_path.display()
            )
        })?;
        if should_exclude_replica_path(
            relative_path,
            file_type.is_dir(),
            source_root,
            ignore_config,
        ) {
            continue;
        }

        if file_type.is_dir() {
            std::fs::create_dir_all(&target_path).map_err(|source_error| {
                anyhow!(
                    "failed to create replica directory {}: {source_error}",
                    target_path.display()
                )
            })?;
            copy_directory_recursive(&source_path, &target_path, source_root, ignore_config)?;
            continue;
        }

        if file_type.is_file() {
            std::fs::copy(&source_path, &target_path).map_err(|source_error| {
                anyhow!(
                    "failed to copy source file {} to {}: {source_error}",
                    source_path.display(),
                    target_path.display()
                )
            })?;
            continue;
        }

        if file_type.is_symlink() {
            copy_symlink(&source_path, &target_path)?;
        }
    }

    Ok(())
}

#[cfg(unix)]
pub(crate) fn copy_symlink(source_path: &Path, target_path: &Path) -> Result<()> {
    use std::os::unix::fs::symlink;

    let link_target = std::fs::read_link(source_path).map_err(|source_error| {
        anyhow!(
            "failed to read symlink target for {}: {source_error}",
            source_path.display()
        )
    })?;
    symlink(&link_target, target_path).map_err(|source_error| {
        anyhow!(
            "failed to recreate symlink {} -> {}: {source_error}",
            target_path.display(),
            link_target.display()
        )
    })?;
    Ok(())
}

#[cfg(not(unix))]
pub(crate) fn copy_symlink(source_path: &Path, target_path: &Path) -> Result<()> {
    std::fs::copy(source_path, target_path).map_err(|source_error| {
        anyhow!(
            "failed to copy symlink-like path {} to {}: {source_error}",
            source_path.display(),
            target_path.display()
        )
    })?;
    Ok(())
}

pub(crate) fn should_exclude_replica_path(
    relative_path: &Path,
    is_dir: bool,
    source_root: &Path,
    ignore_config: &ReplicaIgnoreConfig,
) -> bool {
    if should_exclude_default_replica_path(relative_path) {
        return true;
    }

    let full_path = source_root.join(relative_path);
    ignore_config
        .matcher
        .matched_path_or_any_parents(&full_path, is_dir)
        .is_ignore()
}

pub(crate) fn should_exclude_default_replica_path(relative_path: &Path) -> bool {
    REPLICA_DEFAULT_EXCLUSION_RULES
        .iter()
        .any(|rule| (rule.matcher)(relative_path))
}

pub(crate) fn matches_exact_dotenv(relative_path: &Path) -> bool {
    relative_path.file_name() == Some(OsStr::new(".env"))
}

pub(crate) fn matches_secret_dotenv_variant(relative_path: &Path) -> bool {
    relative_path
        .file_name()
        .and_then(|name| name.to_str())
        .map(is_secret_env_filename)
        .unwrap_or(false)
}

pub(crate) fn matches_git_config_path(relative_path: &Path) -> bool {
    let mut components = relative_path.components().rev();
    matches!(
        (components.next(), components.next()),
        (Some(Component::Normal(config)), Some(Component::Normal(git_dir)))
            if config == OsStr::new("config") && git_dir == OsStr::new(".git")
    )
}

pub(crate) fn is_secret_env_filename(file_name: &str) -> bool {
    file_name == ".env" || file_name.starts_with(".env.")
}

#[derive(Debug, Clone)]
pub(crate) struct ReplicaSyncChange {
    pub(crate) relative_path: PathBuf,
    pub(crate) kind: FsChangeKind,
}

pub(crate) fn maybe_sync_back_replica(
    plan: &ExecutionPlan,
    writer: &ArtifactWriter,
    args: &CommandArgs,
    fs_diff: &[FsChange],
    output: &OutputOptions,
) -> Result<()> {
    let WorkspaceMode::Replica { source, copy } = &plan.mode else {
        return Ok(());
    };

    let ignore_config = load_replica_ignore_config(source)?;
    let sync_changes = collect_syncable_replica_changes(copy, source, fs_diff, &ignore_config);
    let changes = sync_changes.len();

    if changes == 0 {
        append_audit_event(
            writer,
            AuditEventKind::ReplicaSyncBack {
                approved: false,
                changes: 0,
            },
        )?;
        return Ok(());
    }

    if args.json {
        verbose_log(
            output,
            1,
            format!(
                "replica sync-back skipped for execution {} because --json is enabled",
                plan.id
            ),
        );
        append_audit_event(
            writer,
            AuditEventKind::ReplicaSyncBack {
                approved: false,
                changes,
            },
        )?;
        return Ok(());
    }

    if !is_replica_sync_back_interactive(io::stdin().is_terminal(), io::stdout().is_terminal()) {
        println!(
            "Replica sync-back skipped (non-interactive stdio). Pending changes remain in {}",
            copy.display()
        );
        verbose_log(
            output,
            1,
            format!(
                "replica sync-back skipped for execution {} due to non-interactive stdio",
                plan.id
            ),
        );
        append_audit_event(
            writer,
            AuditEventKind::ReplicaSyncBack {
                approved: false,
                changes,
            },
        )?;
        return Ok(());
    }

    let approved = prompt_replica_sync_back(changes, source)?;
    if approved {
        apply_replica_sync_back(source, copy, &sync_changes)?;
        println!(
            "Replica sync-back complete: {} change(s) applied to {}",
            changes,
            source.display()
        );
        verbose_log(
            output,
            1,
            format!(
                "replica sync-back approved: {} change(s) applied for execution {}",
                changes, plan.id
            ),
        );
    } else {
        println!(
            "Replica sync-back skipped. Pending changes remain in {}",
            copy.display()
        );
        verbose_log(
            output,
            1,
            format!(
                "replica sync-back declined: {} pending change(s) for execution {}",
                changes, plan.id
            ),
        );
    }

    append_audit_event(
        writer,
        AuditEventKind::ReplicaSyncBack { approved, changes },
    )?;
    Ok(())
}

pub(crate) fn is_replica_sync_back_interactive(
    stdin_is_terminal: bool,
    stdout_is_terminal: bool,
) -> bool {
    stdin_is_terminal && stdout_is_terminal
}

pub(crate) fn collect_syncable_replica_changes(
    copy_root: &Path,
    source_root: &Path,
    fs_diff: &[FsChange],
    ignore_config: &ReplicaIgnoreConfig,
) -> Vec<ReplicaSyncChange> {
    fs_diff
        .iter()
        .filter_map(|change| {
            let relative_path = change.path.strip_prefix(copy_root).ok()?;
            if relative_path.as_os_str().is_empty() {
                return None;
            }
            if should_exclude_replica_path(relative_path, false, source_root, ignore_config) {
                return None;
            }

            Some(ReplicaSyncChange {
                relative_path: relative_path.to_path_buf(),
                kind: change.kind,
            })
        })
        .collect()
}

pub(crate) fn prompt_replica_sync_back(changes: usize, source: &Path) -> Result<bool> {
    println!(
        "Replica run produced {changes} file change(s) eligible for sync-back to {}.",
        source.display()
    );
    print!("Sync back to the source workspace? [y/N]: ");
    io::stdout()
        .flush()
        .map_err(|source_error| anyhow!("failed to flush sync-back prompt: {source_error}"))?;

    let mut answer = String::new();
    io::stdin()
        .read_line(&mut answer)
        .map_err(|source_error| anyhow!("failed to read sync-back response: {source_error}"))?;
    let answer = answer.trim().to_ascii_lowercase();
    Ok(answer == "y" || answer == "yes")
}

pub(crate) fn apply_replica_sync_back(
    source_root: &Path,
    copy_root: &Path,
    changes: &[ReplicaSyncChange],
) -> Result<()> {
    for change in changes {
        let source_path = source_root.join(&change.relative_path);
        match change.kind {
            FsChangeKind::Created | FsChangeKind::Modified => {
                let replica_path = copy_root.join(&change.relative_path);
                if !replica_path.is_file() {
                    continue;
                }

                if let Some(parent) = source_path.parent() {
                    std::fs::create_dir_all(parent).map_err(|source_error| {
                        anyhow!(
                            "failed to prepare sync-back directory {}: {source_error}",
                            parent.display()
                        )
                    })?;
                }
                std::fs::copy(&replica_path, &source_path).map_err(|source_error| {
                    anyhow!(
                        "failed to sync-back file {} to {}: {source_error}",
                        replica_path.display(),
                        source_path.display()
                    )
                })?;
            }
            FsChangeKind::Deleted => {
                if source_path.exists() {
                    let metadata =
                        std::fs::symlink_metadata(&source_path).map_err(|source_error| {
                            anyhow!(
                                "failed to inspect sync-back delete path {}: {source_error}",
                                source_path.display()
                            )
                        })?;
                    if !metadata.file_type().is_dir() {
                        std::fs::remove_file(&source_path).map_err(|source_error| {
                            anyhow!(
                                "failed to remove sync-back file {}: {source_error}",
                                source_path.display()
                            )
                        })?;
                    }
                }
            }
        }
    }

    Ok(())
}

pub(crate) fn select_default_mode(default_mode: DefaultMode, args: &CommandArgs) -> DefaultMode {
    if args.replica {
        DefaultMode::Replica
    } else if args.direct {
        DefaultMode::Direct
    } else {
        default_mode
    }
}

pub(crate) fn materialize_workspace_mode(
    source_cwd: &Path,
    effective_mode: DefaultMode,
    execution_id: &str,
) -> WorkspaceMode {
    match effective_mode {
        DefaultMode::Direct => WorkspaceMode::Direct,
        DefaultMode::Replica => WorkspaceMode::Replica {
            source: source_cwd.to_path_buf(),
            copy: replica_temp_root()
                .join("clawcrate")
                .join(format!("exec_{execution_id}"))
                .join("workspace"),
        },
    }
}

pub(crate) fn replica_temp_root() -> PathBuf {
    let temp_root = std::env::temp_dir();
    std::fs::canonicalize(&temp_root).unwrap_or(temp_root)
}
