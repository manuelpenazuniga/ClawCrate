use std::ffi::OsStr;
use std::path::{Component, Path, PathBuf};

pub(crate) fn home_from_env_pairs(env: &[(String, String)]) -> Option<PathBuf> {
    env.iter()
        .find_map(|(key, value)| (key == "HOME" && !value.is_empty()).then(|| PathBuf::from(value)))
}

pub(crate) fn expand_home_path(path: &Path, home: Option<&Path>) -> PathBuf {
    let mut components = path.components();
    match components.next() {
        Some(Component::Normal(component)) if component == OsStr::new("~") => {
            if let Some(home_path) = home {
                let mut expanded = home_path.to_path_buf();
                for part in components {
                    expanded.push(part.as_os_str());
                }
                return expanded;
            }
        }
        _ => {}
    }

    path.to_path_buf()
}

pub(crate) fn resolve_path_with_home(cwd: &Path, path: &Path, home: Option<&Path>) -> PathBuf {
    let expanded = expand_home_path(path, home);
    let resolved = if expanded.is_absolute() {
        expanded
    } else {
        cwd.join(expanded)
    };
    lexically_clean(resolved)
}

/// Drop `.` components from a resolved path.
///
/// A profile that declares `fs_read: ["."]` resolves to `<cwd>/.`, because
/// joining does not normalize. macOS Seatbelt matches `subpath` textually, so
/// `(subpath "<cwd>/.")` does not match `<cwd>/file.txt` and the sandboxed
/// process cannot read its own workspace.
///
/// Rebuilding from `Path::components()` removes non-leading `.` components.
/// `..` is deliberately preserved rather than resolved: popping it lexically is
/// wrong when a component is a symlink, and could widen a grant to a directory
/// the profile never named. Leaving it in place fails closed instead.
fn lexically_clean(path: PathBuf) -> PathBuf {
    let mut cleaned = PathBuf::new();
    for component in path.components() {
        cleaned.push(component.as_os_str());
    }

    if cleaned.as_os_str().is_empty() {
        PathBuf::from(".")
    } else {
        cleaned
    }
}

pub(crate) fn normalize_paths(cwd: &Path, paths: &[PathBuf], home: Option<&Path>) -> Vec<PathBuf> {
    paths
        .iter()
        .map(|path| resolve_path_with_home(cwd, path, home))
        .collect()
}

#[cfg(target_os = "macos")]
pub(crate) fn normalize_path_patterns(
    cwd: &Path,
    patterns: &[String],
    home: Option<&Path>,
) -> Vec<String> {
    patterns
        .iter()
        .map(|pattern| resolve_path_with_home(cwd, Path::new(pattern), home))
        .map(|resolved| resolved.to_string_lossy().to_string())
        .collect()
}
