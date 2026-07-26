//! Integration coverage for the Direct-Mode read-isolation gap surfaced by
//! #276. The golden suite strips the platform-conditional field to stay
//! platform-agnostic, so these tests assert the actual per-platform behavior.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

use serde_json::Value;

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

fn run_json(args: &[&str], cwd: &Path, home: &Path) -> Value {
    let output = Command::new(clawcrate_bin())
        .args(args)
        .current_dir(cwd)
        .env("HOME", home)
        .env("NO_COLOR", "1")
        .output()
        .expect("execute clawcrate command");
    assert!(
        output.status.success(),
        "clawcrate command failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).expect("parse json output")
}

#[test]
fn plan_json_has_no_read_isolation_gap_on_supported_platforms() {
    // `safe` is Direct Mode and restricts reads to the workspace. Both
    // supported platforms now enforce read isolation in Direct Mode — macOS via
    // Seatbelt, Linux via Landlock read-allowlisting (#272) — so the
    // gap field must be absent.
    let workspace = unique_tmp_dir("clawcrate_cli_it_read_iso_ws");
    let home = unique_tmp_dir("clawcrate_cli_it_read_iso_home");
    let plan = run_json(
        &[
            "plan",
            "--profile",
            "safe",
            "--json",
            "--",
            "/bin/echo",
            "hi",
        ],
        &workspace,
        &home,
    );

    let field = plan.get("read_isolation_enforced");
    assert!(
        field.is_none(),
        "Direct Mode read isolation is enforced on this platform; no gap field expected, got {field:?}"
    );
}

#[test]
fn plan_json_replica_mode_has_no_read_isolation_gap() {
    // Replica Mode enforces read isolation via the filtered copy on all
    // platforms, so the gap field must be absent regardless of OS.
    let workspace = unique_tmp_dir("clawcrate_cli_it_read_iso_replica_ws");
    let home = unique_tmp_dir("clawcrate_cli_it_read_iso_replica_home");
    let plan = run_json(
        &[
            "plan",
            "--profile",
            "safe",
            "--replica",
            "--json",
            "--",
            "/bin/echo",
            "hi",
        ],
        &workspace,
        &home,
    );

    assert!(
        plan.get("read_isolation_enforced").is_none(),
        "Replica Mode has no read-isolation gap on any platform, got {:?}",
        plan.get("read_isolation_enforced")
    );
}

#[test]
fn doctor_json_reports_read_isolation_capability() {
    let workspace = unique_tmp_dir("clawcrate_cli_it_read_iso_doctor_ws");
    let home = unique_tmp_dir("clawcrate_cli_it_read_iso_doctor_home");
    let doctor = run_json(&["doctor", "--json"], &workspace, &home);

    let enforced = doctor
        .get("read_isolation_enforced")
        .and_then(Value::as_bool)
        .expect("doctor JSON should carry read_isolation_enforced");

    // macOS enforces via Seatbelt; Linux via Landlock read-allowlisting (#272).
    assert!(
        enforced,
        "Direct-Mode read isolation should be reported as enforced on this platform"
    );
}
