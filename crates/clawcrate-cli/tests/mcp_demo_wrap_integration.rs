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

/// The exact command the demo launcher wraps: the filesystem server launched
/// from the copy installed inside the workspace, with a relative root argument.
/// `npx` cannot be used, because it reads its own launcher and package cache
/// from the Node installation, which the sandbox does not grant.
const WRAPPED_COMMAND: [&str; 3] = [
    "node",
    "node_modules/@modelcontextprotocol/server-filesystem/dist/index.js",
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
        contents.contains("node \"$SERVER_ENTRYPOINT\""),
        "launcher must run the server from the copy installed inside the workspace"
    );
    // Only executable lines matter here: the launcher's comments legitimately
    // explain why `npx` is unusable.
    let invokes_npx = contents
        .lines()
        .map(str::trim)
        .filter(|line| !line.starts_with('#'))
        .any(|line| line.contains("npx"));
    assert!(
        !invokes_npx,
        "launcher must not invoke npx: it reads files outside the sandbox's read set"
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

/// The launcher must always hand the server a root argument. It consumes the
/// first argument as the workspace to enter, so without a default the server
/// would be started with no path and refuse to run — the shape a GUI MCP client
/// produces when it invokes the launcher with no arguments at all.
#[test]
fn demo_launcher_always_passes_a_server_root() {
    let contents = fs::read_to_string(demo_dir().join("launcher.sh")).expect("read launcher");

    assert!(
        contents.contains("set -- ."),
        "launcher must default the server root to `.` when no extra paths are given"
    );

    // The default must be applied after the workspace argument is shifted off,
    // otherwise a one-argument invocation still reaches the server with none.
    let shift_at = contents
        .find("shift")
        .expect("launcher shifts the workspace argument");
    let default_at = contents
        .find("set -- .")
        .expect("launcher sets a default root");
    assert!(
        shift_at < default_at,
        "the default root must be applied after the workspace argument is shifted off"
    );
}

/// The demo's central claim rests on one detail that is easy to lose in an
/// edit: the live run must hand `secret-vault/` to the server as one of its own
/// allowed roots. If it does not, the server refuses the read under its own
/// policy, the demo still prints a refusal, and the whole thing quietly stops
/// demonstrating anything about the sandbox.
#[test]
fn demo_live_run_authorizes_the_server_to_reach_the_planted_secret() {
    let contents = fs::read_to_string(demo_dir().join("demo.sh")).expect("read demo.sh");

    assert!(
        contents.contains(r#"VAULT="$SCRIPT_DIR/secret-vault""#),
        "the demo must locate the vault outside the workspace"
    );
    assert!(
        contents.contains(r#"node "$SERVER_ENTRYPOINT" . "$VAULT""#),
        "the server must be started with the vault as an allowed root, or the          refusal proves only that the server polices itself"
    );

    let request_at = contents
        .find("secret-vault")
        .expect("the demo should request the planted secret");
    let vault_root_at = contents
        .find(r#"node "$SERVER_ENTRYPOINT" . "$VAULT""#)
        .expect("the demo should grant the vault as a root");
    assert!(
        vault_root_at < request_at || contents.matches("$VAULT").count() >= 2,
        "the vault must be both granted and requested"
    );

    // The recording is committed alongside, and a stale one is worse than none:
    // it would show a demo that no longer exists.
    assert!(
        demo_dir().join("demo.cast").is_file(),
        "the committed recording should be present"
    );
    assert!(
        demo_dir().join("record.py").is_file(),
        "the recorder should be committed so the cast can be regenerated"
    );
}

/// The committed recording must not carry the machine that produced it.
#[test]
fn demo_recording_does_not_leak_the_recording_machine() {
    let cast = fs::read_to_string(demo_dir().join("demo.cast")).expect("read demo.cast");

    assert!(
        !cast.contains("/Users/"),
        "the cast must not contain a home directory path"
    );
    assert!(
        !cast.contains("/home/"),
        "the cast must not contain a home directory path"
    );
    assert!(
        cast.contains("Hash chain valid"),
        "the recording should cover the audit verification, not stop before it"
    );
}
