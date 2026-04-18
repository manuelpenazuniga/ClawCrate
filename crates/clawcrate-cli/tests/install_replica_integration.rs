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

fn run_clawcrate_json(args: &[&str], cwd: &Path, home: &Path) -> Value {
    let output = Command::new(clawcrate_bin())
        .args(args)
        .current_dir(cwd)
        .env("HOME", home)
        .output()
        .expect("execute clawcrate command");

    assert!(
        output.status.success(),
        "clawcrate command failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    serde_json::from_slice(&output.stdout).expect("parse json output from clawcrate")
}

#[test]
fn install_profile_defaults_to_replica_in_plan_output() {
    let workspace = unique_tmp_dir("clawcrate_cli_it_install_plan_workspace");
    let home = unique_tmp_dir("clawcrate_cli_it_install_plan_home");
    fs::write(
        workspace.join("package.json"),
        "{ \"name\": \"demo\", \"version\": \"0.1.0\" }",
    )
    .expect("write package.json");

    let plan = run_clawcrate_json(
        &[
            "plan",
            "--profile",
            "install",
            "--json",
            "--",
            "/bin/sh",
            "-c",
            "echo plan",
        ],
        &workspace,
        &home,
    );

    let replica_mode = plan
        .get("mode")
        .and_then(|mode| mode.get("Replica"))
        .expect("plan mode should be Replica for install profile");
    let plan_source = PathBuf::from(
        replica_mode
            .get("source")
            .and_then(Value::as_str)
            .expect("replica source path"),
    );
    assert_eq!(
        fs::canonicalize(plan_source).expect("canonicalize replica source path"),
        fs::canonicalize(workspace).expect("canonicalize workspace path")
    );
}

#[test]
fn install_run_uses_replica_and_excludes_secret_env_files() {
    let workspace = unique_tmp_dir("clawcrate_cli_it_install_run_workspace");
    let home = unique_tmp_dir("clawcrate_cli_it_install_run_home");

    fs::write(
        workspace.join("package.json"),
        "{ \"name\": \"demo\", \"version\": \"0.1.0\" }",
    )
    .expect("write package.json");
    fs::write(workspace.join(".env"), "SECRET=top").expect("write .env");
    fs::write(workspace.join(".env.local"), "SECRET=local").expect("write .env.local");
    fs::write(workspace.join("public.txt"), "visible").expect("write public file");

    let summary = run_clawcrate_json(
        &[
            "run",
            "--profile",
            "install",
            "--json",
            "--",
            "/bin/sh",
            "-c",
            "test ! -f .env && test ! -f .env.local && test -f public.txt",
        ],
        &workspace,
        &home,
    );

    assert!(
        summary
            .get("result")
            .and_then(|result| result.get("status"))
            .is_some(),
        "run summary should include result.status"
    );

    let artifacts_dir = PathBuf::from(
        summary
            .get("result")
            .and_then(|result| result.get("artifacts_dir"))
            .and_then(Value::as_str)
            .expect("artifacts_dir in run summary"),
    );
    let plan_path = artifacts_dir.join("plan.json");
    let plan: Value =
        serde_json::from_str(&fs::read_to_string(&plan_path).expect("read plan artifact json"))
            .expect("parse plan artifact json");
    let replica = plan
        .get("mode")
        .and_then(|mode| mode.get("Replica"))
        .expect("plan mode should be Replica");
    let copy_path = PathBuf::from(
        replica
            .get("copy")
            .and_then(Value::as_str)
            .expect("replica copy path"),
    );

    assert!(
        !copy_path.join(".env").exists(),
        "replica copy should not contain .env"
    );
    assert!(
        !copy_path.join(".env.local").exists(),
        "replica copy should not contain .env.local"
    );
    assert!(
        copy_path.join("public.txt").exists(),
        "replica copy should contain non-secret files"
    );
}
