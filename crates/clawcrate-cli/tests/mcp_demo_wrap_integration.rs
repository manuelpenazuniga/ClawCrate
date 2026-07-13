//! Integration coverage for the `examples/mcp-filesystem-demo` launcher.
//!
//! The demo wraps `@modelcontextprotocol/server-filesystem` behind
//! `clawcrate mcp wrap --profile mcp-readonly`. These tests assert the three
//! load-bearing invariants of that launcher — the profile, the wrapped command,
//! and the working directory — via `clawcrate plan`, a dry run that resolves the
//! sandbox policy WITHOUT launching the server. That keeps the test fully
//! deterministic and free of any npm/npx/network dependency in CI.
//!
//! `clawcrate mcp wrap` builds its plan through the same `build_execution_plan`
//! path the top-level `plan` command uses when `--profile` is explicit, so the
//! top-level plan is a faithful proxy for the wrap invocation. Do not "fix" this
//! into a real `mcp wrap` call — that would execute npx and require Node in CI.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
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

fn demo_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../examples/mcp-filesystem-demo")
}

/// The exact command the demo launcher wraps: the filesystem server with a
/// relative root argument.
const WRAPPED_COMMAND: [&str; 4] = [
    "npx",
    "--no-install",
    "@modelcontextprotocol/server-filesystem",
    ".",
];

#[test]
fn demo_launcher_plan_resolves_profile_command_and_workspace() {
    let workspace = unique_tmp_dir("clawcrate_cli_it_mcp_demo_workspace");
    let home = unique_tmp_dir("clawcrate_cli_it_mcp_demo_home");

    let mut args = vec!["plan", "--profile", "mcp-readonly", "--json", "--"];
    args.extend(WRAPPED_COMMAND);

    let output = Command::new(clawcrate_bin())
        .args(&args)
        .current_dir(&workspace)
        .env("HOME", &home)
        .env("NO_COLOR", "1")
        .output()
        .expect("execute clawcrate plan");

    assert!(
        output.status.success(),
        "clawcrate plan failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let plan: Value = serde_json::from_slice(&output.stdout).expect("parse plan json output");

    // Profile: the launcher wraps with mcp-readonly.
    assert_eq!(plan["profile"]["name"], json!("mcp-readonly"));

    // Command: the filesystem server launched with its root kept relative.
    assert_eq!(plan["command"], json!(WRAPPED_COMMAND));

    // Working directory: mcp-readonly defaults to Replica Mode, so the plan is
    // `{"Replica": {"source": <cwd>, "copy": <temp>}}`. The source canonicalizes
    // to the launcher's working directory; the wrapped server runs in the copy.
    let source = plan["mode"]["Replica"]["source"]
        .as_str()
        .expect("plan mode should be Replica with a source path");
    assert_eq!(
        fs::canonicalize(source).expect("canonicalize replica source"),
        fs::canonicalize(&workspace).expect("canonicalize workspace"),
    );

    // The policy guarantees the demo documents: no writes, no network.
    assert_eq!(plan["profile"]["net"], json!("None"));
    assert!(
        plan["profile"]["fs_write"]
            .as_array()
            .expect("fs_write should be an array")
            .is_empty(),
        "mcp-readonly must grant no write paths"
    );
}

#[test]
fn demo_launcher_script_matches_wrap_invocation() {
    let launcher = demo_dir().join("launcher.sh");
    let contents = fs::read_to_string(&launcher)
        .unwrap_or_else(|err| panic!("read {}: {err}", launcher.display()));

    assert!(
        contents.contains("clawcrate mcp wrap"),
        "launcher must invoke `clawcrate mcp wrap`"
    );
    assert!(
        contents.contains("--profile mcp-readonly"),
        "launcher must use the mcp-readonly profile"
    );
    assert!(
        contents.contains("npx --no-install @modelcontextprotocol/server-filesystem"),
        "launcher must run the filesystem server with --no-install (network: none profile)"
    );
    assert!(
        contents.contains("cd "),
        "launcher must cd into the workspace so the relative server root resolves"
    );
}

#[test]
fn demo_workspace_ships_fixture_and_planted_secrets() {
    let demo = demo_dir();
    // Benign, readable fixture files.
    assert!(demo.join("workspace/README.md").is_file());
    assert!(demo.join("workspace/src/index.js").is_file());
    // In-workspace secrets that must be excluded from the Replica copy.
    assert!(demo.join("workspace/.env").is_file());
    assert!(
        demo.join("workspace/.clawcrateignore").is_file(),
        ".clawcrateignore must ship so extra secrets are excluded on Linux"
    );
    // Out-of-root secret for the blocked-read story.
    assert!(demo.join("secret-vault/api-key.txt").is_file());
}
