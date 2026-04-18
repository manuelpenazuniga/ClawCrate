use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::time::{SystemTime, UNIX_EPOCH};

use serde_json::{json, Value};

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

fn run_clawcrate(args: &[&str], cwd: &Path, home: &Path) -> Output {
    Command::new(clawcrate_bin())
        .args(args)
        .current_dir(cwd)
        .env("HOME", home)
        .env("NO_COLOR", "1")
        .output()
        .expect("execute clawcrate command")
}

fn run_clawcrate_json(args: &[&str], cwd: &Path, home: &Path) -> Value {
    let output = run_clawcrate(args, cwd, home);
    assert!(
        output.status.success(),
        "clawcrate command failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).expect("parse command json output")
}

fn run_clawcrate_text(args: &[&str], cwd: &Path, home: &Path) -> String {
    let output = run_clawcrate(args, cwd, home);
    assert!(
        output.status.success(),
        "clawcrate command failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout).expect("stdout is utf-8")
}

fn normalize_plan_json(mut plan: Value) -> String {
    plan["id"] = json!("<EXECUTION_ID>");
    plan["cwd"] = json!("<EXECUTION_CWD>");
    plan["created_at"] = json!("<CREATED_AT>");
    serde_json::to_string_pretty(&plan).expect("serialize normalized plan")
}

fn normalize_doctor_json(mut doctor: Value) -> String {
    doctor["platform"] = json!("<PLATFORM>");
    doctor["landlock_abi"] = json!("<LANDLOCK_ABI_OR_NULL>");
    doctor["seccomp_available"] = json!("<SECCOMP_BOOL>");
    doctor["seatbelt_available"] = json!("<SEATBELT_BOOL>");
    doctor["user_namespaces"] = json!("<USER_NAMESPACES_BOOL>");
    doctor["macos_version"] = json!("<MACOS_VERSION_OR_NULL>");
    doctor["kernel_version"] = json!("<KERNEL_VERSION_OR_NULL>");
    serde_json::to_string_pretty(&doctor).expect("serialize normalized doctor")
}

fn normalize_run_json(mut summary: Value) -> String {
    summary["backend"] = json!("<BACKEND>");
    summary["stdout_log"] = json!("<STDOUT_LOG>");
    summary["stderr_log"] = json!("<STDERR_LOG>");
    summary["scrubbed_env_vars"] = json!("<SCRUBBED_ENV_COUNT>");

    if let Some(result) = summary.get_mut("result").and_then(Value::as_object_mut) {
        result.insert("id".to_string(), json!("<EXECUTION_ID>"));
        result.insert("exit_code".to_string(), json!("<EXIT_CODE_OR_NULL>"));
        result.insert("status".to_string(), json!("<STATUS>"));
        result.insert("duration_ms".to_string(), json!("<DURATION_MS>"));
        result.insert("artifacts_dir".to_string(), json!("<ARTIFACTS_DIR>"));
    }

    serde_json::to_string_pretty(&summary).expect("serialize normalized run")
}

fn parse_human_table_rows(output: &str) -> BTreeMap<String, String> {
    let mut rows = BTreeMap::new();
    for line in output.lines() {
        let trimmed = line.trim();
        if !trimmed.starts_with('|') {
            continue;
        }
        let parts: Vec<&str> = trimmed.split('|').collect();
        if parts.len() < 4 {
            continue;
        }
        let key = parts[1].trim();
        let value = parts[2].trim();
        if key.is_empty() || key == "Field" || key == "Capability" {
            continue;
        }
        rows.insert(key.to_string(), value.to_string());
    }
    rows
}

fn normalized_rows(mut rows: BTreeMap<String, String>, replacements: &[(&str, &str)]) -> String {
    for (key, value) in replacements {
        if rows.contains_key(*key) {
            rows.insert((*key).to_string(), (*value).to_string());
        }
    }
    rows.into_iter()
        .map(|(key, value)| format!("{key}={value}\n"))
        .collect()
}

fn assert_golden(name: &str, actual: &str) {
    let base = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("golden");
    let path = base.join(format!("{name}.golden"));

    if std::env::var_os("UPDATE_GOLDEN").is_some() {
        fs::create_dir_all(&base).expect("create golden directory");
        fs::write(&path, actual).expect("write golden file");
        return;
    }

    let expected = fs::read_to_string(&path).unwrap_or_else(|error| {
        panic!(
            "missing golden file {}: {error}. Run with UPDATE_GOLDEN=1 to generate.",
            path.display()
        )
    });

    assert_eq!(
        expected,
        actual,
        "golden mismatch for {}. Run with UPDATE_GOLDEN=1 to refresh.",
        path.display()
    );
}

#[test]
fn plan_json_matches_golden() {
    let workspace = unique_tmp_dir("clawcrate_cli_golden_plan_json_workspace");
    let home = unique_tmp_dir("clawcrate_cli_golden_plan_json_home");

    let plan = run_clawcrate_json(
        &[
            "plan",
            "--profile",
            "safe",
            "--json",
            "--",
            "/bin/echo",
            "hello",
        ],
        &workspace,
        &home,
    );

    assert_golden("plan_json", &normalize_plan_json(plan));
}

#[test]
fn plan_text_matches_golden() {
    let workspace = unique_tmp_dir("clawcrate_cli_golden_plan_text_workspace");
    let home = unique_tmp_dir("clawcrate_cli_golden_plan_text_home");

    let output = run_clawcrate_text(
        &[
            "--no-color",
            "plan",
            "--profile",
            "safe",
            "--",
            "/bin/echo",
            "hello",
        ],
        &workspace,
        &home,
    );

    let normalized = normalized_rows(
        parse_human_table_rows(&output),
        &[
            ("Execution ID", "<EXECUTION_ID>"),
            ("Execution CWD", "<EXECUTION_CWD>"),
        ],
    );
    assert_golden("plan_text", &normalized);
}

#[test]
fn doctor_json_matches_golden() {
    let workspace = unique_tmp_dir("clawcrate_cli_golden_doctor_json_workspace");
    let home = unique_tmp_dir("clawcrate_cli_golden_doctor_json_home");

    let doctor = run_clawcrate_json(&["doctor", "--json"], &workspace, &home);
    assert_golden("doctor_json", &normalize_doctor_json(doctor));
}

#[test]
fn doctor_text_matches_golden() {
    let workspace = unique_tmp_dir("clawcrate_cli_golden_doctor_text_workspace");
    let home = unique_tmp_dir("clawcrate_cli_golden_doctor_text_home");

    let output = run_clawcrate_text(&["--no-color", "doctor"], &workspace, &home);
    let normalized = normalized_rows(
        parse_human_table_rows(&output),
        &[
            ("Platform", "<PLATFORM>"),
            ("Kernel Version", "<KERNEL_VERSION>"),
            ("macOS Version", "<MACOS_VERSION>"),
            ("Landlock ABI", "<LANDLOCK_STATUS>"),
            ("seccomp", "<SECCOMP_STATUS>"),
            ("Seatbelt", "<SEATBELT_STATUS>"),
            ("User Namespaces", "<USER_NAMESPACES_STATUS>"),
        ],
    );
    assert_golden("doctor_text", &normalized);
}

#[test]
fn run_json_matches_golden() {
    let workspace = unique_tmp_dir("clawcrate_cli_golden_run_json_workspace");
    let home = unique_tmp_dir("clawcrate_cli_golden_run_json_home");

    let run = run_clawcrate_json(
        &[
            "run",
            "--profile",
            "safe",
            "--json",
            "--",
            "/bin/sh",
            "-c",
            "echo hi",
        ],
        &workspace,
        &home,
    );

    assert_golden("run_json", &normalize_run_json(run));
}

#[test]
fn run_text_matches_golden() {
    let workspace = unique_tmp_dir("clawcrate_cli_golden_run_text_workspace");
    let home = unique_tmp_dir("clawcrate_cli_golden_run_text_home");

    let output = run_clawcrate_text(
        &[
            "--no-color",
            "run",
            "--profile",
            "safe",
            "--",
            "/bin/sh",
            "-c",
            "echo hi",
        ],
        &workspace,
        &home,
    );

    let normalized = normalized_rows(
        parse_human_table_rows(&output),
        &[
            ("Execution ID", "<EXECUTION_ID>"),
            ("Status", "<STATUS>"),
            ("Exit Code", "<EXIT_CODE_OR_NA>"),
            ("Duration", "<DURATION>"),
            ("Backend", "<BACKEND>"),
            ("Env Vars Scrubbed", "<SCRUBBED_ENV_COUNT>"),
            ("Artifacts Directory", "<ARTIFACTS_DIR>"),
            ("stdout.log", "<STDOUT_LOG>"),
            ("stderr.log", "<STDERR_LOG>"),
        ],
    );
    assert_golden("run_text", &normalized);
}
