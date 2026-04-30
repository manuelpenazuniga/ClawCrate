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
    if expanded.is_absolute() {
        expanded
    } else {
        cwd.join(expanded)
    }
}

pub(crate) fn normalize_paths(cwd: &Path, paths: &[PathBuf], home: Option<&Path>) -> Vec<PathBuf> {
    paths
        .iter()
        .map(|path| resolve_path_with_home(cwd, path, home))
        .collect()
}

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
