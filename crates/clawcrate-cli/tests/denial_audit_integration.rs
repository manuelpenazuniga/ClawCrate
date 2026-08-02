//! End-to-end coverage that observed denials reach `audit.ndjson`.
//!
//! The seccomp notification work had a supervisor that recorded every refused
//! syscall correctly, unit tests that proved it, and no wiring from that record
//! into the artifact — so the events existed in memory and were thrown away
//! while the docs claimed they were recorded. Nothing caught it, because every
//! test inspected the in-memory log rather than the file a user reads.
//!
//! These tests inspect the file.

use std::fs;
use std::path::PathBuf;
use std::process::Command;
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

fn clawcrate_bin() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_clawcrate"))
}

/// Runs a command under the given profile and returns its `audit.ndjson`.
fn run_and_read_audit(command: &[&str]) -> String {
    let home = unique_tmp_dir("clawcrate_denial_audit_home");
    let workspace = unique_tmp_dir("clawcrate_denial_audit_workspace");

    let mut args = vec!["run", "--profile", "safe", "--approve-out-of-profile", "--"];
    args.extend_from_slice(command);

    let output = Command::new(clawcrate_bin())
        .args(&args)
        .current_dir(&workspace)
        .env("HOME", &home)
        .env("NO_COLOR", "1")
        .output()
        .expect("execute clawcrate run");

    let runs_root = home.join(".clawcrate/runs");
    let mut run_dirs: Vec<PathBuf> = fs::read_dir(&runs_root)
        .unwrap_or_else(|error| {
            panic!(
                "no runs directory at {}: {error}\nstdout:\n{}\nstderr:\n{}",
                runs_root.display(),
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            )
        })
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .collect();
    run_dirs.sort();

    // A private HOME means exactly one run exists; picking "the newest under
    // the real home" would let a concurrent run supply the evidence.
    assert_eq!(
        run_dirs.len(),
        1,
        "expected exactly one run, got {run_dirs:?}"
    );
    fs::read_to_string(run_dirs[0].join("audit.ndjson")).expect("read audit.ndjson")
}

/// Whether this machine can sandbox at all.
///
/// Docker Desktop's kernel ships without Landlock, and ClawCrate fails closed
/// without it, so the run aborts before any syscall is attempted. That is an
/// environment fact rather than a result, so the tests below step aside — but
/// only off CI. A capability test that quietly skips on the one machine that
/// gates merges is not a test.
fn sandbox_available_or_skip(what: &str) -> bool {
    let output = Command::new(clawcrate_bin())
        .args(["doctor", "--json"])
        .env("NO_COLOR", "1")
        .output()
        .expect("run clawcrate doctor");
    // Parsed rather than substring-matched: the report is pretty-printed, and a
    // check that silently never matches would skip everywhere, including CI.
    let report: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("parse doctor --json");
    let available = report
        .get("landlock_abi")
        .is_some_and(|value| !value.is_null());
    if !available {
        assert!(
            std::env::var_os("CI").is_none(),
            "{what} requires Landlock, and CI must not skip it"
        );
        eprintln!("skipping {what}: this kernel has no Landlock");
    }
    available
}

#[cfg(target_os = "linux")]
#[test]
fn refused_syscalls_reach_the_audit_artifact() {
    if !sandbox_available_or_skip("refused_syscalls_reach_the_audit_artifact") {
        return;
    }

    // `chroot(2)` is in no profile's allowlist. Driven through the interpreter
    // rather than a shell, because a shell would have to fork to reach an
    // external binary and RLIMIT_NPROC is per-UID: on a loaded runner the fork
    // fails and the syscall is never attempted.
    let audit = run_and_read_audit(&[
        "python3",
        "-c",
        "import os\ntry:\n    os.chroot('/')\nexcept OSError:\n    pass\n",
    ]);

    assert!(
        audit.contains("PermissionBlocked"),
        "a refused syscall must appear in audit.ndjson, got:\n{audit}"
    );
    assert!(
        audit.contains("syscall:chroot"),
        "the refused syscall should be named in audit.ndjson, got:\n{audit}"
    );
}

/// The inverse: a run that was refused nothing must not claim otherwise.
#[test]
fn a_clean_run_records_no_denials() {
    if !sandbox_available_or_skip("a_clean_run_records_no_denials") {
        return;
    }
    let audit = run_and_read_audit(&["/bin/echo", "ok"]);

    assert!(
        !audit.contains("PermissionBlocked"),
        "nothing was refused, so nothing may be recorded, got:\n{audit}"
    );
    assert!(
        audit.contains("ProcessExited"),
        "the run should still have produced an audit trail, got:\n{audit}"
    );
}
