use std::fs;
use std::io::Write;
use std::path::PathBuf;
use std::process::{Command, Stdio};
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

#[test]
fn mcp_wrap_relays_stdin_to_stdout_without_protocol_output() {
    let workspace = unique_tmp_dir("clawcrate_cli_it_mcp_wrap_workspace");
    let home = unique_tmp_dir("clawcrate_cli_it_mcp_wrap_home");
    let payload = b"Content-Length: 41\r\n\r\n{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":\"ok\"}";

    let mut child = Command::new(clawcrate_bin())
        .args(["mcp", "wrap", "--profile", "mcp-readonly", "--", "/bin/cat"])
        .current_dir(&workspace)
        .env("HOME", &home)
        .env("NO_COLOR", "1")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn clawcrate mcp wrap");

    child
        .stdin
        .as_mut()
        .expect("stdin pipe")
        .write_all(payload)
        .expect("write protocol payload");
    drop(child.stdin.take());

    let output = child.wait_with_output().expect("wait for mcp wrap");

    assert!(
        output.status.success(),
        "mcp wrap failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(output.stdout, payload);

    let runs_root = home.join(".clawcrate").join("runs");
    let run_dirs = fs::read_dir(&runs_root)
        .expect("read runs root")
        .collect::<Result<Vec<_>, _>>()
        .expect("collect run dirs");
    assert_eq!(run_dirs.len(), 1, "expected exactly one run artifact dir");

    let artifacts_dir = run_dirs[0].path();
    assert_eq!(
        fs::read(artifacts_dir.join("stdout.log")).expect("read stdout log"),
        payload
    );
    assert!(artifacts_dir.join("stderr.log").is_file());
    assert!(artifacts_dir.join("audit.ndjson").is_file());
    assert!(artifacts_dir.join("result.json").is_file());
    assert!(artifacts_dir.join("fs-diff.json").is_file());
}
