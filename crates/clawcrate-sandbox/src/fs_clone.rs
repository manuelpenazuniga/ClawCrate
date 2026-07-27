//! Copy-on-write file cloning.
//!
//! Replica Mode materializes a filtered copy of the workspace before every
//! launch, which is the dominant cost for large trees. On filesystems that
//! support it, a CoW clone shares the underlying extents instead of duplicating
//! the data, so materialization becomes a metadata operation.
//!
//! **Copy-on-write only — never hardlinks.** A hardlink would make the replica
//! and the source share one inode, so an in-place write inside the sandbox
//! would silently modify the user's real file. Replica Mode grants write access
//! to the copy (the `install`, `mcp-server`, and `open` profiles all do), so
//! that would defeat the isolation the mode exists to provide. A CoW clone is
//! safe precisely because writes diverge.
//!
//! Every entry point is best-effort: when the filesystem does not support
//! cloning, or the source and target live on different filesystems, the caller
//! falls back to a regular copy.

use std::path::Path;

/// Attempt a copy-on-write clone of `source` to `target`.
///
/// Returns `true` when the clone succeeded and the target is complete. Returns
/// `false` when cloning is unsupported here, leaving no partial target behind,
/// so the caller must fall back to a regular copy.
///
/// `target` must not already exist.
pub fn try_clone_file(source: &Path, target: &Path) -> bool {
    clone_file_impl(source, target)
}

#[cfg(target_os = "macos")]
#[allow(unsafe_code)]
fn clone_file_impl(source: &Path, target: &Path) -> bool {
    use nix::libc;
    use std::ffi::CString;
    use std::os::unix::ffi::OsStrExt;

    let (Ok(source_c), Ok(target_c)) = (
        CString::new(source.as_os_str().as_bytes()),
        CString::new(target.as_os_str().as_bytes()),
    ) else {
        return false;
    };

    // SAFETY: both pointers are valid NUL-terminated C strings that outlive the
    // call, and `0` is a valid flag value for `clonefile(2)`.
    let result = unsafe { libc::clonefile(source_c.as_ptr(), target_c.as_ptr(), 0) };
    if result == 0 {
        // clonefile carries permissions and ownership across, so there is
        // nothing further to restore.
        return true;
    }

    // clonefile does not create the target on failure, so nothing to clean up.
    false
}

#[cfg(target_os = "linux")]
#[allow(unsafe_code)]
fn clone_file_impl(source: &Path, target: &Path) -> bool {
    use nix::libc;
    use std::fs::File;
    use std::os::fd::AsRawFd;

    let Ok(source_file) = File::open(source) else {
        return false;
    };
    let Ok(target_file) = File::create(target) else {
        return false;
    };

    // SAFETY: both descriptors are valid and open for the duration of the call;
    // FICLONE takes the source descriptor as its argument.
    let result = unsafe {
        libc::ioctl(
            target_file.as_raw_fd(),
            libc::FICLONE,
            source_file.as_raw_fd(),
        )
    };

    if result != 0 {
        // `File::create` already made an empty target; remove it so the caller's
        // fallback copy starts from a clean state.
        drop(target_file);
        let _ = std::fs::remove_file(target);
        return false;
    }

    // FICLONE clones data only. Without restoring the mode, an executable in the
    // workspace would lose its permission bits inside the replica and builds
    // that invoke it would break.
    if let Ok(metadata) = source_file.metadata() {
        let _ = target_file.set_permissions(metadata.permissions());
    }

    true
}

#[cfg(not(any(target_os = "macos", target_os = "linux")))]
fn clone_file_impl(_source: &Path, _target: &Path) -> bool {
    false
}

#[cfg(test)]
mod tests {
    use super::try_clone_file;
    use std::fs;
    use std::path::PathBuf;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn unique_tmp_dir(prefix: &str) -> PathBuf {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system time after unix epoch")
            .as_nanos();
        let dir = std::env::temp_dir().join(format!("{prefix}_{nanos}_{}", std::process::id()));
        fs::create_dir_all(&dir).expect("create temp test directory");
        dir
    }

    /// Whether the clone succeeds depends on the filesystem, so the contract
    /// under test is conditional: if it reports success the target must be a
    /// faithful, independent copy; if it reports failure it must leave nothing
    /// behind for the caller's fallback.
    #[test]
    fn clone_either_produces_a_faithful_copy_or_leaves_no_target() {
        let dir = unique_tmp_dir("clawcrate_fs_clone");
        let source = dir.join("source.txt");
        let target = dir.join("target.txt");
        fs::write(&source, b"clone me\n").expect("write source");

        if try_clone_file(&source, &target) {
            assert_eq!(
                fs::read(&target).expect("read clone"),
                b"clone me\n",
                "a successful clone must reproduce the contents"
            );

            // The clone must be an independent file: writing to it must not
            // change the source. This is the property a hardlink would violate.
            fs::write(&target, b"changed\n").expect("write clone");
            assert_eq!(
                fs::read(&source).expect("read source"),
                b"clone me\n",
                "writing to the clone must not modify the source"
            );
        } else {
            assert!(
                !target.exists(),
                "a failed clone must not leave a partial target behind"
            );
        }
    }

    #[test]
    fn clone_reports_failure_for_a_missing_source() {
        let dir = unique_tmp_dir("clawcrate_fs_clone_missing");
        let target = dir.join("target.txt");

        assert!(!try_clone_file(&dir.join("does-not-exist.txt"), &target));
        assert!(!target.exists());
    }
}
