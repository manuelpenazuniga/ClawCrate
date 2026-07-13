//! Unit tests for clawcrate-cli internals (extracted from main.rs; see #277).

use anyhow::anyhow;
use std::fs;
use std::io;
#[cfg(unix)]
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use crate::{
    api::*, approval::*, bridge::*, cli::*, doctor::*, mcp::*, output::*, replica::*, run::*,
    support::*,
};
use chrono::Utc;
use clap::Parser;
use clawcrate_audit::ArtifactWriter;
use clawcrate_capture::{CaptureConfig, FsChange, FsChangeKind};
use clawcrate_profiles::ProfileResolver;
use clawcrate_types::{
    Actor, AuditEvent, AuditEventKind, DefaultMode, ExecutionPlan, NetLevel, Platform,
    ResolvedProfile, ResourceLimits, Status, SystemCapabilities, WorkspaceMode,
};
#[cfg(unix)]
use nix::sys::signal::Signal;
use tiny_http::{Header, Method};

fn unique_tmp_dir(prefix: &str) -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system time after unix epoch")
        .as_nanos();
    let dir = std::env::temp_dir().join(format!("{prefix}_{nanos}_{}", std::process::id()));
    fs::create_dir_all(&dir).expect("create temp test directory");
    dir
}

fn mock_plan(net: NetLevel, command: &[&str]) -> ExecutionPlan {
    let cwd = unique_tmp_dir("clawcrate_cli_approval_mock");
    ExecutionPlan {
        id: "exec-approval".to_string(),
        command: command.iter().map(|value| value.to_string()).collect(),
        cwd,
        profile: ResolvedProfile {
            name: "test".to_string(),
            fs_read: vec![PathBuf::from(".")],
            fs_write: vec![PathBuf::from("./target")],
            fs_deny: vec![],
            net,
            env_scrub: vec!["*_SECRET*".to_string()],
            env_passthrough: vec!["HOME".to_string(), "PATH".to_string()],
            resources: ResourceLimits {
                max_cpu_seconds: 60,
                max_memory_mb: 512,
                max_open_files: 1024,
                max_processes: 128,
                max_output_bytes: 2 * 1024 * 1024,
            },
            default_mode: DefaultMode::Direct,
        },
        mode: WorkspaceMode::Direct,
        actor: Actor::Human,
        created_at: Utc::now(),
    }
}

#[test]
fn parses_plan_command_with_profile_and_command() {
    let cli = Cli::parse_from([
        "clawcrate",
        "plan",
        "--profile",
        "build",
        "--",
        "cargo",
        "test",
    ]);

    match cli.command {
        Commands::Plan(args) => {
            assert_eq!(args.profile.as_deref(), Some("build"));
            assert_eq!(args.command, vec!["cargo".to_string(), "test".to_string()]);
            assert!(!args.json);
            assert!(!args.approve_out_of_profile);
        }
        _ => panic!("expected plan command"),
    }
}

#[test]
fn parses_mcp_wrap_command_with_profile_and_separator() {
    let cli = Cli::parse_from([
        "clawcrate",
        "mcp",
        "wrap",
        "--profile",
        "mcp-readonly",
        "--",
        "npx",
        "-y",
        "@modelcontextprotocol/server-filesystem",
        "/tmp",
    ]);

    match cli.command {
        Commands::Mcp(args) => match args.command {
            McpCommand::Wrap(args) => {
                assert_eq!(args.profile.as_deref(), Some("mcp-readonly"));
                assert_eq!(
                    args.command,
                    vec![
                        "npx".to_string(),
                        "-y".to_string(),
                        "@modelcontextprotocol/server-filesystem".to_string(),
                        "/tmp".to_string(),
                    ]
                );
                assert!(!args.replica);
                assert!(!args.direct);
            }
            other => panic!("expected mcp wrap command, got {other:?}"),
        },
        _ => panic!("expected mcp wrap command"),
    }
}

#[test]
fn mcp_wrap_requires_command_separator() {
    let error = Cli::try_parse_from([
        "clawcrate",
        "mcp",
        "wrap",
        "--profile",
        "mcp-readonly",
        "npx",
    ])
    .expect_err("mcp wrap must require -- before the wrapped command");
    let message = error.to_string();

    assert!(message.contains("unexpected argument"));
    assert!(message.contains("--"));
}

#[test]
fn mcp_wrap_requires_wrapped_command() {
    let error = Cli::try_parse_from([
        "clawcrate",
        "mcp",
        "wrap",
        "--profile",
        "mcp-readonly",
        "--",
    ])
    .expect_err("mcp wrap must require a command after --");
    let message = error.to_string();

    assert!(message.contains("required"));
    assert!(message.contains("<COMMAND>"));
}

#[test]
fn mcp_wrap_plan_resolves_selected_profile() {
    let cwd = unique_tmp_dir("clawcrate_mcp_wrap_plan_workspace");
    let resolver = ProfileResolver::default();
    let args = McpWrapArgs {
        profile: Some("mcp-readonly".to_string()),
        replica: false,
        direct: false,
        command: vec![
            "npx".to_string(),
            "-y".to_string(),
            "@modelcontextprotocol/server-filesystem".to_string(),
            cwd.display().to_string(),
        ],
    };

    let plan = build_mcp_wrap_plan(&resolver, &cwd, &args).expect("build mcp wrap plan");

    assert_eq!(plan.profile.name, "mcp-readonly");
    assert_eq!(plan.command, args.command);
    assert!(matches!(plan.mode, WorkspaceMode::Replica { .. }));
}

#[test]
fn parses_mcp_wrap_command_without_profile_for_auto_detection() {
    let cli = Cli::parse_from([
        "clawcrate",
        "mcp",
        "wrap",
        "--",
        "npx",
        "-y",
        "@modelcontextprotocol/server-filesystem",
        "/tmp",
    ]);

    match cli.command {
        Commands::Mcp(args) => match args.command {
            McpCommand::Wrap(args) => {
                assert_eq!(args.profile, None);
                assert_eq!(
                    args.command,
                    vec![
                        "npx".to_string(),
                        "-y".to_string(),
                        "@modelcontextprotocol/server-filesystem".to_string(),
                        "/tmp".to_string(),
                    ]
                );
            }
            other => panic!("expected mcp wrap command, got {other:?}"),
        },
        _ => panic!("expected mcp wrap command"),
    }
}

#[test]
fn mcp_shape_detector_accepts_official_stdio_server_package() {
    let command = vec![
        "npx".to_string(),
        "-y".to_string(),
        "@modelcontextprotocol/server-filesystem".to_string(),
        "/tmp".to_string(),
    ];

    assert_eq!(
        detect_stdio_mcp_server_shape(&command),
        Some(McpServerShapeDetection::OfficialPackage)
    );
}

#[test]
fn mcp_shape_detector_accepts_mcp_server_binary_with_stdio_hint() {
    let command = vec![
        "node".to_string(),
        "./dist/github-mcp-server.js".to_string(),
        "--transport".to_string(),
        "stdio".to_string(),
    ];

    assert_eq!(
        detect_stdio_mcp_server_shape(&command),
        Some(McpServerShapeDetection::ServerName)
    );
}

#[test]
fn mcp_shape_detector_accepts_python_mcp_server_names_with_underscores() {
    let command = vec![
        "uvx".to_string(),
        "mcp_server_postgres".to_string(),
        "--transport".to_string(),
        "stdio".to_string(),
    ];

    assert_eq!(
        detect_stdio_mcp_server_shape(&command),
        Some(McpServerShapeDetection::ServerName)
    );
}

#[test]
fn mcp_shape_detector_accepts_python_mcp_marker_with_stdio_hint() {
    let command = vec![
        "python".to_string(),
        "-m".to_string(),
        "git_mcp".to_string(),
        "--stdio".to_string(),
    ];

    assert_eq!(
        detect_stdio_mcp_server_shape(&command),
        Some(McpServerShapeDetection::MarkerWithStdio)
    );
}

#[test]
fn mcp_shape_detector_rejects_stdio_without_mcp_marker() {
    let command = vec![
        "node".to_string(),
        "./dist/jsonrpc-stdio-proxy.js".to_string(),
        "--transport".to_string(),
        "stdio".to_string(),
    ];

    assert_eq!(detect_stdio_mcp_server_shape(&command), None);
}

#[test]
fn mcp_shape_detector_rejects_near_miss_package_names() {
    let command = vec![
        "npx".to_string(),
        "-y".to_string(),
        "mcp-serverless-cli".to_string(),
        "--stdio".to_string(),
    ];

    assert_eq!(detect_stdio_mcp_server_shape(&command), None);
}

#[test]
fn mcp_wrap_plan_auto_selects_readonly_profile_for_detected_server() {
    let cwd = unique_tmp_dir("clawcrate_mcp_wrap_auto_profile_workspace");
    let resolver = ProfileResolver::default();
    let args = McpWrapArgs {
        profile: None,
        replica: false,
        direct: false,
        command: vec![
            "npx".to_string(),
            "-y".to_string(),
            "@modelcontextprotocol/server-filesystem".to_string(),
            cwd.display().to_string(),
        ],
    };

    let plan = build_mcp_wrap_plan(&resolver, &cwd, &args).expect("build mcp wrap plan");

    assert_eq!(plan.profile.name, AUTO_DETECTED_MCP_PROFILE);
    assert!(matches!(plan.mode, WorkspaceMode::Replica { .. }));
    assert!(plan.profile.fs_write.is_empty());
}

#[test]
fn mcp_wrap_plan_requires_explicit_profile_for_unknown_shape() {
    let cwd = unique_tmp_dir("clawcrate_mcp_wrap_unknown_profile_workspace");
    let resolver = ProfileResolver::default();
    let args = McpWrapArgs {
        profile: None,
        replica: false,
        direct: false,
        command: vec!["/bin/cat".to_string()],
    };

    let error = build_mcp_wrap_plan(&resolver, &cwd, &args)
        .expect_err("unknown shape must require explicit profile");
    let message = error.to_string();

    assert!(message.contains("could not auto-detect a stdio MCP server shape"));
    assert!(message.contains("--profile mcp-readonly"));
    assert!(message.contains("--profile mcp-server"));
}

#[test]
fn mcp_wrap_plan_honors_explicit_profile_for_unknown_shape() {
    let cwd = unique_tmp_dir("clawcrate_mcp_wrap_explicit_profile_workspace");
    let resolver = ProfileResolver::default();
    let args = McpWrapArgs {
        profile: Some("mcp-server".to_string()),
        replica: false,
        direct: false,
        command: vec!["/bin/cat".to_string()],
    };

    let plan = build_mcp_wrap_plan(&resolver, &cwd, &args).expect("build mcp wrap plan");

    assert_eq!(plan.profile.name, "mcp-server");
    assert_eq!(plan.command, args.command);
}

#[test]
fn mcp_relay_preserves_json_rpc_framing_bytes() {
    let tmp = unique_tmp_dir("clawcrate_mcp_relay_preserves");
    let log_path = tmp.join("stdout.log");
    let input = b"Content-Length: 41\r\n\r\n{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":\"ok\"}";
    let mut output = Vec::new();

    let stats = relay_stream_to_output_and_log(
        io::Cursor::new(input),
        &mut output,
        log_path.clone(),
        Arc::new(Mutex::new(1024)),
    )
    .expect("relay stream");

    assert_eq!(output, input);
    assert_eq!(fs::read(log_path).expect("read relay log"), input);
    assert_eq!(stats.written_bytes, input.len() as u64);
    assert_eq!(stats.dropped_bytes, 0);
}

#[test]
fn mcp_relay_truncates_log_without_truncating_client_output() {
    let tmp = unique_tmp_dir("clawcrate_mcp_relay_truncates_log");
    let log_path = tmp.join("stdout.log");
    let input = b"123456789";
    let mut output = Vec::new();

    let stats = relay_stream_to_output_and_log(
        io::Cursor::new(input),
        &mut output,
        log_path.clone(),
        Arc::new(Mutex::new(5)),
    )
    .expect("relay stream");

    assert_eq!(output, input);
    assert_eq!(fs::read(log_path).expect("read relay log"), b"12345");
    assert_eq!(stats.written_bytes, 5);
    assert_eq!(stats.dropped_bytes, 4);
}

#[test]
fn mcp_relay_treats_broken_pipe_as_clean_client_disconnect() {
    struct BrokenPipeWriter;

    impl io::Write for BrokenPipeWriter {
        fn write(&mut self, _buf: &[u8]) -> io::Result<usize> {
            Err(io::Error::new(io::ErrorKind::BrokenPipe, "closed"))
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    let tmp = unique_tmp_dir("clawcrate_mcp_relay_broken_pipe");
    let log_path = tmp.join("stdout.log");

    let stats = relay_stream_to_output_and_log(
        io::Cursor::new(b"server response"),
        BrokenPipeWriter,
        log_path.clone(),
        Arc::new(Mutex::new(1024)),
    )
    .expect("broken pipe should be treated as clean disconnect");

    assert_eq!(fs::read(log_path).expect("read relay log"), b"");
    assert_eq!(stats.written_bytes, 0);
    assert_eq!(stats.dropped_bytes, 0);
}

#[test]
fn parses_doctor_command_with_json() {
    let cli = Cli::parse_from(["clawcrate", "doctor", "--json"]);

    match cli.command {
        Commands::Doctor(args) => assert!(args.json),
        _ => panic!("expected doctor command"),
    }
}

#[test]
fn parses_api_command_with_bind_and_token() {
    let cli = Cli::parse_from([
        "clawcrate",
        "api",
        "--bind",
        "127.0.0.1:9999",
        "--token",
        "super-secret",
    ]);

    match cli.command {
        Commands::Api(args) => {
            assert_eq!(args.bind, "127.0.0.1:9999");
            assert_eq!(args.token.as_deref(), Some("super-secret"));
        }
        _ => panic!("expected api command"),
    }
}

#[test]
fn parses_bridge_pennyprompt_command() {
    let cli = Cli::parse_from(["clawcrate", "bridge", "pennyprompt", "--pretty"]);

    match cli.command {
        Commands::Bridge(args) => match args.target {
            BridgeTarget::Pennyprompt(config) => assert!(config.pretty),
        },
        _ => panic!("expected bridge command"),
    }
}

#[test]
fn parses_audit_export_command_with_format() {
    let cli = Cli::parse_from([
        "clawcrate",
        "audit",
        "export",
        "exec-123",
        "--format",
        "elastic",
    ]);

    match cli.command {
        Commands::Audit(args) => match args.command {
            AuditCommand::Export(config) => {
                assert_eq!(config.run_id, "exec-123");
                assert_eq!(config.format, AuditExportFormat::Elastic);
            }
        },
        _ => panic!("expected audit export command"),
    }
}

#[test]
fn parses_global_verbose_and_no_color_flags() {
    let cli = Cli::parse_from([
        "clawcrate",
        "--verbose",
        "--no-color",
        "plan",
        "--",
        "echo",
        "hello",
    ]);
    assert_eq!(cli.global.verbose, 1);
    assert!(cli.global.no_color);
}

#[test]
fn color_policy_respects_flag_env_and_tty() {
    assert!(!should_use_color(true, false, true));
    assert!(!should_use_color(false, true, true));
    assert!(!should_use_color(false, false, false));
    assert!(should_use_color(false, false, true));
}

fn sample_audit_export_content() -> String {
    let ts = chrono::DateTime::parse_from_rfc3339("2026-05-14T22:00:00Z")
        .unwrap()
        .with_timezone(&Utc);
    let started = AuditEvent {
        timestamp: ts,
        event: AuditEventKind::ProcessStarted {
            pid: 42,
            command: vec!["cat".to_string(), ".env".to_string()],
        },
    };
    let blocked = AuditEvent {
        timestamp: ts,
        event: AuditEventKind::PermissionBlocked {
            resource: "/workspace/.env".to_string(),
            reason: "profile denied read".to_string(),
        },
    };
    format!(
        "{}\n{}\n{}\n",
        serde_json::to_string(&started).unwrap(),
        serde_json::json!({
            "kind": "BlockSignature",
            "block_start": 0,
            "block_end": 1,
            "block_hash": "sha256:abc",
            "signature": "ed25519:def",
            "public_key_fingerprint": "SHA256:key",
        }),
        serde_json::to_string(&blocked).unwrap()
    )
}

#[test]
fn audit_export_json_is_native_passthrough() {
    let content = sample_audit_export_content();
    let exported = super::export_audit_content("exec-export", &content, AuditExportFormat::Json)
        .expect("export json");
    assert_eq!(exported, content);
}

#[test]
fn audit_export_cef_maps_events_and_high_severity() {
    let exported = super::export_audit_content(
        "exec-export",
        &sample_audit_export_content(),
        AuditExportFormat::Cef,
    )
    .expect("export cef");
    let lines = exported.lines().collect::<Vec<_>>();
    assert_eq!(lines.len(), 2, "BlockSignature rows are not audit events");
    assert!(lines[0].starts_with("CEF:0|ClawCrate|clawcrate|"));
    assert!(lines[0].contains("|process_started|process_started|2|"));
    assert!(lines[1].contains("|permission_blocked|permission_blocked|8|"));
    assert!(lines[1].contains("cs1=exec-export"));
    assert!(lines[1].contains("cs2=security"));
}

#[test]
fn audit_export_syslog_emits_rfc5424_like_lines() {
    let exported = super::export_audit_content(
        "exec-export",
        &sample_audit_export_content(),
        AuditExportFormat::Syslog,
    )
    .expect("export syslog");
    let lines = exported.lines().collect::<Vec<_>>();
    assert_eq!(lines.len(), 2);
    assert!(lines[0]
        .starts_with("<14>1 2026-05-14T22:00:00+00:00 - clawcrate exec-export process_started "));
    assert!(lines[1].starts_with(
        "<11>1 2026-05-14T22:00:00+00:00 - clawcrate exec-export permission_blocked "
    ));
    assert!(lines[1].contains("severity=\"high\""));
}

#[test]
fn audit_export_elastic_emits_bulk_ndjson_pairs() {
    let exported = super::export_audit_content(
        "exec-export",
        &sample_audit_export_content(),
        AuditExportFormat::Elastic,
    )
    .expect("export elastic");
    let lines = exported.lines().collect::<Vec<_>>();
    assert_eq!(lines.len(), 4);
    assert_eq!(
        serde_json::from_str::<serde_json::Value>(lines[0]).unwrap()["index"]["_index"],
        "clawcrate-audit"
    );
    let first_doc = serde_json::from_str::<serde_json::Value>(lines[1]).unwrap();
    assert_eq!(first_doc["run_id"], "exec-export");
    assert_eq!(first_doc["event"]["kind"], "process_started");
    let second_doc = serde_json::from_str::<serde_json::Value>(lines[3]).unwrap();
    assert_eq!(second_doc["event"]["severity"], "high");
    assert_eq!(second_doc["event"]["category"], "security");
}

#[test]
fn resolve_api_route_matches_supported_paths() {
    assert!(matches!(
        resolve_api_route(&Method::Get, "/v1/health"),
        Some(super::ApiRoute::Health)
    ));
    assert!(matches!(
        resolve_api_route(&Method::Get, "/v1/doctor"),
        Some(super::ApiRoute::Doctor)
    ));
    assert!(matches!(
        resolve_api_route(&Method::Post, "/v1/plan"),
        Some(super::ApiRoute::Plan)
    ));
    assert!(matches!(
        resolve_api_route(&Method::Post, "/v1/run?verbose=1"),
        Some(super::ApiRoute::Run)
    ));
    assert!(resolve_api_route(&Method::Delete, "/v1/run").is_none());
}

#[test]
fn extract_bearer_token_reads_authorization_header() {
    let header = Header::from_bytes("Authorization", "Bearer token-123")
        .expect("create authorization header");
    let missing = Header::from_bytes("X-Other", "value").expect("create random header");
    let headers = vec![missing, header];
    assert_eq!(extract_bearer_token(&headers).as_deref(), Some("token-123"));
}

#[test]
fn request_authorized_requires_exact_token_match() {
    let header = Header::from_bytes("Authorization", "Bearer token-123")
        .expect("create authorization header");
    let headers = vec![header];

    assert!(request_authorized(&headers, "token-123"));
    assert!(!request_authorized(&headers, "token-1234"));
    assert!(!request_authorized(&headers, "token-124"));
    assert!(!request_authorized(&headers, "token-12"));
}

#[test]
fn constant_time_compare_handles_length_and_content_mismatches() {
    assert!(constant_time_eq(b"abc", b"abc"));
    assert!(!constant_time_eq(b"abc", b"abd"));
    assert!(!constant_time_eq(b"abc", b"ab"));
    assert!(!constant_time_eq(b"ab", b"abc"));
}

#[test]
fn health_route_bypasses_delegated_worker_queue() {
    assert!(!api_route_uses_delegated_worker(ApiRoute::Health));
    assert!(api_route_uses_delegated_worker(ApiRoute::Doctor));
    assert!(api_route_uses_delegated_worker(ApiRoute::Plan));
    assert!(api_route_uses_delegated_worker(ApiRoute::Run));
}

#[test]
fn bounded_work_queue_enforces_capacity_and_closed_state() {
    let queue = BoundedWorkQueue::new(1);

    assert!(queue.try_enqueue(10usize).is_ok());
    assert_eq!(queue.len(), 1);
    assert!(matches!(
        queue.try_enqueue(20usize),
        Err(QueueEnqueueError::Full(20))
    ));

    assert_eq!(queue.dequeue_blocking(), Some(10usize));
    queue.close();
    assert!(matches!(
        queue.try_enqueue(30usize),
        Err(QueueEnqueueError::Closed(30))
    ));
    assert_eq!(queue.dequeue_blocking(), None);
}

#[test]
fn bounded_work_queue_allows_parallel_worker_processing() {
    let queue = Arc::new(BoundedWorkQueue::new(64));
    let active_workers = Arc::new(AtomicUsize::new(0));
    let max_active_workers = Arc::new(AtomicUsize::new(0));
    let completed = Arc::new(AtomicUsize::new(0));
    let worker_count = 4usize;
    let job_count = 16usize;

    let mut handles = Vec::new();
    for _ in 0..worker_count {
        let queue = Arc::clone(&queue);
        let active_workers = Arc::clone(&active_workers);
        let max_active_workers = Arc::clone(&max_active_workers);
        let completed = Arc::clone(&completed);

        handles.push(thread::spawn(move || {
            while queue.dequeue_blocking().is_some() {
                let active_now = active_workers.fetch_add(1, Ordering::SeqCst) + 1;
                max_active_workers.fetch_max(active_now, Ordering::SeqCst);

                thread::sleep(Duration::from_millis(20));

                active_workers.fetch_sub(1, Ordering::SeqCst);
                completed.fetch_add(1, Ordering::SeqCst);
            }
        }));
    }

    for job in 0..job_count {
        queue
            .try_enqueue(job)
            .expect("queue should accept work while below capacity");
    }

    let deadline = Instant::now() + Duration::from_secs(3);
    while completed.load(Ordering::SeqCst) < job_count && Instant::now() < deadline {
        thread::sleep(Duration::from_millis(5));
    }

    queue.close();
    for handle in handles {
        handle.join().expect("worker must join cleanly");
    }

    assert_eq!(
        completed.load(Ordering::SeqCst),
        job_count,
        "all queued jobs must complete"
    );
    assert!(
        max_active_workers.load(Ordering::SeqCst) > 1,
        "expected parallel servicing across multiple workers"
    );
}

#[test]
fn api_payload_serialization_fallback_is_valid_json() {
    struct FailingPayload;

    impl serde::Serialize for FailingPayload {
        fn serialize<S>(&self, _serializer: S) -> std::result::Result<S::Ok, S::Error>
        where
            S: serde::Serializer,
        {
            Err(serde::ser::Error::custom(
                "intentional serialization failure",
            ))
        }
    }

    let serialized = serialize_api_payload(&FailingPayload);
    let value: serde_json::Value =
        serde_json::from_slice(&serialized).expect("fallback payload must be valid json");

    assert_eq!(
        value.get("error").and_then(serde_json::Value::as_str),
        Some("failed to serialize API response")
    );
    assert_eq!(
        value.get("detail").and_then(serde_json::Value::as_str),
        Some("intentional serialization failure")
    );
}

#[test]
fn build_api_cli_args_enforces_command_and_flags() {
    let valid = ApiCommandRequest {
        profile: Some("build".to_string()),
        replica: false,
        direct: false,
        approve_out_of_profile: true,
        command: vec!["cargo".to_string(), "test".to_string()],
    };
    let run_args = build_api_cli_args("run", &valid).expect("build args");
    assert_eq!(
        run_args,
        vec![
            "run",
            "--json",
            "--profile",
            "build",
            "--approve-out-of-profile",
            "--",
            "cargo",
            "test",
        ]
    );

    let invalid = ApiCommandRequest {
        profile: None,
        replica: true,
        direct: true,
        approve_out_of_profile: false,
        command: vec!["echo".to_string(), "hello".to_string()],
    };
    assert!(build_api_cli_args("plan", &invalid).is_err());
}

#[test]
fn build_pennyprompt_cli_args_maps_supported_actions() {
    let doctor_request = PennyPromptBridgeRequest {
        action: "doctor".to_string(),
        profile: None,
        replica: false,
        direct: false,
        approve_out_of_profile: false,
        command: vec![],
    };
    assert_eq!(
        build_pennyprompt_cli_args("doctor", &doctor_request).expect("doctor args"),
        vec!["doctor", "--json"]
    );

    let run_request = PennyPromptBridgeRequest {
        action: "run".to_string(),
        profile: Some("build".to_string()),
        replica: false,
        direct: false,
        approve_out_of_profile: true,
        command: vec!["cargo".to_string(), "test".to_string()],
    };
    assert_eq!(
        build_pennyprompt_cli_args("run", &run_request).expect("run args"),
        vec![
            "run",
            "--json",
            "--profile",
            "build",
            "--approve-out-of-profile",
            "--",
            "cargo",
            "test",
        ]
    );
}

#[test]
fn build_pennyprompt_cli_args_rejects_invalid_action() {
    let request = PennyPromptBridgeRequest {
        action: "unknown".to_string(),
        profile: None,
        replica: false,
        direct: false,
        approve_out_of_profile: false,
        command: vec!["echo".to_string()],
    };
    assert!(build_pennyprompt_cli_args("unknown", &request).is_err());
}

#[test]
fn pennyprompt_bridge_returns_structured_error_for_unsupported_action() {
    let input = r#"{"action":"unsupported","command":["echo","hi"]}"#;
    let response = build_pennyprompt_bridge_response_with_executor(input, |_args| {
        panic!("executor should not run for unsupported actions");
    });

    assert!(!response.ok);
    assert_eq!(response.action, "unsupported");
    let error = response.error.expect("structured error response");
    assert!(error.message.contains("unsupported PennyPrompt action"));
    assert_eq!(error.exit_code, None);
    assert!(error.stdout.is_empty());
    assert!(error.stderr.is_empty());
}

#[test]
fn pennyprompt_bridge_returns_structured_error_for_invalid_payload_combinations() {
    let replica_direct_input =
        r#"{"action":"run","replica":true,"direct":true,"command":["echo","hi"]}"#;
    let replica_direct =
        build_pennyprompt_bridge_response_with_executor(replica_direct_input, |_args| {
            panic!("executor should not run for invalid payload");
        });
    assert!(!replica_direct.ok);
    assert_eq!(replica_direct.action, "run");
    let error = replica_direct.error.expect("structured error");
    assert!(error
        .message
        .contains("`replica` and `direct` cannot be enabled together"));

    let missing_command_input = r#"{"action":"plan"}"#;
    let missing_command =
        build_pennyprompt_bridge_response_with_executor(missing_command_input, |_args| {
            panic!("executor should not run for missing command");
        });
    assert!(!missing_command.ok);
    assert_eq!(missing_command.action, "plan");
    let error = missing_command.error.expect("structured error");
    assert!(error
        .message
        .contains("`command` must contain at least one element"));
}

#[test]
fn pennyprompt_bridge_validation_errors_serialize_as_json_response() {
    let malformed = build_pennyprompt_bridge_response_with_executor("not-json", |_args| {
        panic!("executor should not run for malformed JSON");
    });
    let serialized =
        serde_json::to_string(&malformed).expect("bridge error response must serialize");
    let value: serde_json::Value =
        serde_json::from_str(&serialized).expect("serialized response must be valid JSON");
    assert_eq!(
        value.get("ok").and_then(serde_json::Value::as_bool),
        Some(false)
    );
    assert_eq!(
        value.get("action").and_then(serde_json::Value::as_str),
        Some("unknown")
    );
}

#[test]
fn pennyprompt_bridge_stdin_read_failure_returns_structured_error_response() {
    let response = build_pennyprompt_bridge_response_from_input_result(
        Err(io::Error::other("simulated stdin failure")),
        |_args| panic!("executor should not run on stdin read failure"),
    );
    assert!(!response.ok);
    assert_eq!(response.action, "unknown");
    let error = response.error.expect("structured error");
    assert!(error
        .message
        .contains("failed to read PennyPrompt bridge payload from stdin"));
    assert!(error.message.contains("simulated stdin failure"));
    assert!(error.stdout.is_empty());
    assert!(error.stderr.is_empty());
    assert_eq!(error.exit_code, None);
}

#[test]
fn network_detector_identifies_obvious_network_commands() {
    assert!(command_appears_to_need_network(&[
        "curl".to_string(),
        "https://example.com".to_string()
    ]));
    assert!(command_appears_to_need_network(&[
        "git".to_string(),
        "clone".to_string(),
        "https://github.com/example/repo.git".to_string()
    ]));
    assert!(!command_appears_to_need_network(&[
        "echo".to_string(),
        "hello".to_string()
    ]));
}

#[test]
fn extract_host_parses_userinfo_and_scp_like_references() {
    assert_eq!(
        extract_host_from_reference("ssh://git@github.com/owner/repo.git"),
        Some("github.com".to_string())
    );
    assert_eq!(
        extract_host_from_reference("https://user:token@registry.npmjs.org/package"),
        Some("registry.npmjs.org".to_string())
    );
    assert_eq!(
        extract_host_from_reference("git@github.com:owner/repo.git"),
        Some("github.com".to_string())
    );
    assert_eq!(
        extract_host_from_reference("alice@github.com:owner/repo.git"),
        Some("github.com".to_string())
    );
    assert_eq!(
        extract_host_from_reference("--registry=https://registry.npmjs.org/"),
        Some("registry.npmjs.org".to_string())
    );
}

#[test]
fn approval_detection_flags_network_gap_for_none_profile() {
    let plan = mock_plan(
        NetLevel::None,
        &["curl", "https://registry.npmjs.org/some-package"],
    );
    let requests = detect_out_of_profile_requests(&plan);
    assert_eq!(requests.len(), 1);
    assert!(requests[0].contains("network mode is `none`"));
}

#[test]
fn approval_detection_honors_filtered_allowlist_hosts() {
    let allowed_plan = mock_plan(
        NetLevel::Filtered {
            allowed_domains: vec!["registry.npmjs.org".to_string()],
        },
        &["curl", "https://registry.npmjs.org/some-package"],
    );
    assert!(detect_out_of_profile_requests(&allowed_plan).is_empty());

    let denied_plan = mock_plan(
        NetLevel::Filtered {
            allowed_domains: vec!["registry.npmjs.org".to_string()],
        },
        &["curl", "https://evil.example.com/payload"],
    );
    let requests = detect_out_of_profile_requests(&denied_plan);
    assert_eq!(requests.len(), 1);
    assert!(requests[0].contains("evil.example.com"));
}

#[test]
fn approval_detection_flags_ambiguous_filtered_targets() {
    let curl_without_scheme = mock_plan(
        NetLevel::Filtered {
            allowed_domains: vec!["example.com".to_string()],
        },
        &["curl", "example.com"],
    );
    let requests = detect_out_of_profile_requests(&curl_without_scheme);
    assert_eq!(requests.len(), 1);
    assert!(requests[0].contains("host extraction was ambiguous"));

    let variable_target = mock_plan(
        NetLevel::Filtered {
            allowed_domains: vec!["example.com".to_string()],
        },
        &["curl", "$TARGET_URL"],
    );
    let requests = detect_out_of_profile_requests(&variable_target);
    assert_eq!(requests.len(), 1);
    assert!(requests[0].contains("host extraction was ambiguous"));
}

#[test]
fn approval_detection_flags_mixed_valid_and_ambiguous_filtered_targets() {
    let mixed_targets = mock_plan(
        NetLevel::Filtered {
            allowed_domains: vec!["registry.npmjs.org".to_string()],
        },
        &[
            "curl",
            "https://registry.npmjs.org/some-package",
            "$FALLBACK_URL",
        ],
    );
    let requests = detect_out_of_profile_requests(&mixed_targets);
    assert_eq!(requests.len(), 1);
    assert!(requests[0].contains("host extraction was ambiguous"));
}

#[test]
fn profile_default_mode_is_overridden_by_flags() {
    let args = CommandArgs {
        profile: None,
        replica: true,
        direct: false,
        json: false,
        approve_out_of_profile: false,
        command: vec!["echo".to_string(), "hello".to_string()],
    };
    assert_eq!(
        select_default_mode(DefaultMode::Direct, &args),
        DefaultMode::Replica
    );

    let args = CommandArgs {
        profile: None,
        replica: false,
        direct: true,
        json: false,
        approve_out_of_profile: false,
        command: vec!["echo".to_string(), "hello".to_string()],
    };
    assert_eq!(
        select_default_mode(DefaultMode::Replica, &args),
        DefaultMode::Direct
    );

    let args = CommandArgs {
        profile: None,
        replica: false,
        direct: false,
        json: false,
        approve_out_of_profile: false,
        command: vec!["echo".to_string(), "hello".to_string()],
    };
    assert_eq!(
        select_default_mode(DefaultMode::Replica, &args),
        DefaultMode::Replica
    );
}

#[test]
fn auto_detect_falls_back_to_safe_when_workspace_is_unknown() {
    let resolver = ProfileResolver::default();
    let cwd = unique_tmp_dir("clawcrate_cli_plan_safe");
    let args = CommandArgs {
        profile: None,
        replica: false,
        direct: false,
        json: false,
        approve_out_of_profile: false,
        command: vec!["echo".to_string(), "hello".to_string()],
    };

    let plan = build_execution_plan(&resolver, &cwd, &args).expect("build execution plan");
    assert_eq!(plan.profile.name, "safe");
    assert!(matches!(plan.mode, WorkspaceMode::Direct));
    assert_eq!(plan.cwd, cwd);
}

#[test]
fn install_profile_materializes_replica_mode() {
    let resolver = ProfileResolver::default();
    let cwd = unique_tmp_dir("clawcrate_cli_plan_replica");
    fs::write(
        cwd.join("package.json"),
        "{ \"name\": \"demo\", \"version\": \"0.1.0\" }",
    )
    .expect("write package json");

    let args = CommandArgs {
        profile: Some("install".to_string()),
        replica: false,
        direct: false,
        json: false,
        approve_out_of_profile: false,
        command: vec!["npm".to_string(), "install".to_string()],
    };

    let plan = build_execution_plan(&resolver, &cwd, &args).expect("build execution plan");
    match &plan.mode {
        WorkspaceMode::Replica { source, copy } => {
            assert_eq!(source, &cwd);
            assert!(copy.starts_with(replica_temp_root()));
            assert_eq!(plan.cwd, *copy);
        }
        WorkspaceMode::Direct => panic!("install profile must default to replica"),
    }
}

#[test]
fn install_profile_can_be_forced_to_direct_mode() {
    let resolver = ProfileResolver::default();
    let cwd = unique_tmp_dir("clawcrate_cli_plan_install_direct");
    fs::write(
        cwd.join("package.json"),
        "{ \"name\": \"demo\", \"version\": \"0.1.0\" }",
    )
    .expect("write package json");

    let args = CommandArgs {
        profile: Some("install".to_string()),
        replica: false,
        direct: true,
        json: false,
        approve_out_of_profile: false,
        command: vec!["npm".to_string(), "install".to_string()],
    };

    let plan = build_execution_plan(&resolver, &cwd, &args).expect("build execution plan");
    assert!(matches!(plan.mode, WorkspaceMode::Direct));
    assert_eq!(plan.cwd, cwd);
}

#[test]
fn build_profile_can_be_forced_to_replica_mode() {
    let resolver = ProfileResolver::default();
    let cwd = unique_tmp_dir("clawcrate_cli_plan_build_replica");
    fs::write(
        cwd.join("Cargo.toml"),
        "[package]\nname = \"demo\"\nversion = \"0.1.0\"\n",
    )
    .expect("write cargo toml");

    let args = CommandArgs {
        profile: Some("build".to_string()),
        replica: true,
        direct: false,
        json: false,
        approve_out_of_profile: false,
        command: vec!["cargo".to_string(), "check".to_string()],
    };

    let plan = build_execution_plan(&resolver, &cwd, &args).expect("build execution plan");
    match &plan.mode {
        WorkspaceMode::Replica { source, copy } => {
            assert_eq!(source, &cwd);
            assert!(copy.starts_with(replica_temp_root()));
            assert_eq!(plan.cwd, *copy);
        }
        WorkspaceMode::Direct => {
            panic!("--replica should override profile default direct mode")
        }
    }
}

#[test]
fn build_execution_plan_normalizes_profile_paths_in_direct_mode() {
    let resolver = ProfileResolver::default();
    let cwd = unique_tmp_dir("clawcrate_cli_plan_normalized_direct");

    let args = CommandArgs {
        profile: Some("install".to_string()),
        replica: false,
        direct: true,
        json: false,
        approve_out_of_profile: false,
        command: vec!["npm".to_string(), "install".to_string()],
    };

    let plan = build_execution_plan(&resolver, &cwd, &args).expect("build execution plan");
    assert!(matches!(plan.mode, WorkspaceMode::Direct));
    assert!(plan.profile.fs_read.iter().any(|path| path == &cwd));
    assert!(plan
        .profile
        .fs_write
        .iter()
        .any(|path| path == &cwd.join("node_modules")));
    assert!(plan
        .profile
        .fs_write
        .iter()
        .any(|path| path == &cwd.join(".venv")));
    assert!(plan
        .profile
        .fs_write
        .iter()
        .any(|path| path == &cwd.join("target")));

    if let Some(home) = std::env::var_os("HOME") {
        let home = PathBuf::from(home);
        assert!(plan
            .profile
            .fs_read
            .iter()
            .any(|path| path == &home.join(".npm")));
        assert!(plan
            .profile
            .fs_write
            .iter()
            .any(|path| path == &home.join(".npm")));
        assert!(plan
            .profile
            .fs_write
            .iter()
            .any(|path| path == &home.join(".cache/pip")));
    }
}

#[test]
fn build_execution_plan_normalizes_profile_paths_in_replica_mode() {
    let resolver = ProfileResolver::default();
    let cwd = unique_tmp_dir("clawcrate_cli_plan_normalized_replica");

    let args = CommandArgs {
        profile: Some("install".to_string()),
        replica: false,
        direct: false,
        json: false,
        approve_out_of_profile: false,
        command: vec!["npm".to_string(), "install".to_string()],
    };

    let plan = build_execution_plan(&resolver, &cwd, &args).expect("build execution plan");
    let copy = match &plan.mode {
        WorkspaceMode::Replica { copy, .. } => copy.clone(),
        WorkspaceMode::Direct => panic!("install should default to replica"),
    };

    assert_eq!(plan.cwd, copy);
    assert!(plan.profile.fs_read.iter().any(|path| path == &copy));
    assert!(plan
        .profile
        .fs_write
        .iter()
        .any(|path| path == &copy.join("node_modules")));
    assert!(plan
        .profile
        .fs_write
        .iter()
        .any(|path| path == &copy.join(".venv")));

    if let Some(home) = std::env::var_os("HOME") {
        let home = PathBuf::from(home);
        assert!(plan
            .profile
            .fs_read
            .iter()
            .any(|path| path == &home.join(".cargo")));
        assert!(plan
            .profile
            .fs_write
            .iter()
            .any(|path| path == &home.join(".cargo/registry")));
    }
}

#[test]
fn doctor_rows_render_linux_specific_capabilities() {
    let capabilities = SystemCapabilities {
        platform: Platform::Linux,
        landlock_abi: Some(4),
        seccomp_available: true,
        seatbelt_available: false,
        user_namespaces: true,
        macos_version: None,
        kernel_version: Some("6.8.12".to_string()),
    };

    let rows = doctor_rows(&capabilities);
    assert!(rows
        .iter()
        .any(|(name, value)| name == "Platform" && value == "Linux"));
    assert!(rows
        .iter()
        .any(|(name, value)| name == "Landlock ABI" && value == "✅ ABI 4"));
    assert!(rows
        .iter()
        .any(|(name, value)| name == "seccomp" && value == "✅ available"));
    assert!(rows
        .iter()
        .any(|(name, value)| name == "Seatbelt" && value == "n/a"));
}

#[test]
fn doctor_rows_render_macos_specific_capabilities() {
    let capabilities = SystemCapabilities {
        platform: Platform::MacOS,
        landlock_abi: None,
        seccomp_available: false,
        seatbelt_available: true,
        user_namespaces: false,
        macos_version: Some("14.5".to_string()),
        kernel_version: Some("23.5.0".to_string()),
    };

    let rows = doctor_rows(&capabilities);
    assert!(rows
        .iter()
        .any(|(name, value)| name == "Platform" && value == "macOS"));
    assert!(rows
        .iter()
        .any(|(name, value)| name == "macOS Version" && value == "14.5"));
    assert!(rows
        .iter()
        .any(|(name, value)| name == "Seatbelt" && value == "✅ available"));
    assert!(rows
        .iter()
        .any(|(name, value)| name == "Landlock ABI" && value == "n/a"));
}

#[test]
fn resolve_execution_path_expands_relative_and_home_paths() {
    let cwd = PathBuf::from("/tmp/workspace");
    let relative = resolve_execution_path(&cwd, Path::new("./target"));
    assert_eq!(relative, PathBuf::from("/tmp/workspace/./target"));

    if let Some(home) = std::env::var_os("HOME") {
        let expected = PathBuf::from(home).join(".cargo");
        let resolved = resolve_execution_path(&cwd, Path::new("~/.cargo"));
        assert_eq!(resolved, expected);
    }
}

#[test]
fn should_exclude_replica_defaults() {
    assert!(should_exclude_default_replica_path(Path::new(".env")));
    assert!(should_exclude_default_replica_path(Path::new(".env.local")));
    assert!(should_exclude_default_replica_path(Path::new(
        "nested/.env.production"
    )));
    assert!(should_exclude_default_replica_path(Path::new(
        ".git/config"
    )));
    assert!(should_exclude_default_replica_path(Path::new(
        "submodule/.git/config"
    )));
    assert!(should_exclude_default_replica_path(Path::new(
        "nested/repo/.git/config"
    )));
    assert!(!should_exclude_default_replica_path(Path::new(".git/HEAD")));
    assert!(!should_exclude_default_replica_path(Path::new(
        "src/main.rs"
    )));
}

#[test]
fn replica_copy_excludes_default_secret_files() {
    let source = unique_tmp_dir("clawcrate_cli_replica_source");
    fs::create_dir_all(source.join(".git")).expect("create .git");
    fs::create_dir_all(source.join("nested")).expect("create nested");

    fs::write(source.join(".env"), "SECRET=1").expect("write .env");
    fs::write(source.join(".env.local"), "SECRET=2").expect("write .env.local");
    fs::write(source.join(".git/config"), "token = hidden").expect("write .git/config");
    fs::write(source.join(".git/HEAD"), "ref: refs/heads/main").expect("write .git/HEAD");
    fs::create_dir_all(source.join("nested/repo/.git")).expect("create nested repo .git");
    fs::write(source.join("nested/repo/.git/config"), "nested = hidden")
        .expect("write nested repo .git/config");
    fs::write(source.join("nested/repo/.git/HEAD"), "ref: refs/heads/dev")
        .expect("write nested repo .git/HEAD");
    fs::write(source.join("nested/.env.production"), "SECRET=3")
        .expect("write nested .env.production");
    fs::write(source.join("nested/app.txt"), "visible").expect("write visible file");

    let replica_root = unique_tmp_dir("clawcrate_cli_replica_copy_root");
    let replica = replica_root.join("workspace");
    let ignore_config = load_replica_ignore_config(&source).expect("load ignore config");
    copy_workspace_with_default_exclusions(&source, &replica, &ignore_config)
        .expect("copy workspace");

    assert!(!replica.join(".env").exists());
    assert!(!replica.join(".env.local").exists());
    assert!(!replica.join(".git/config").exists());
    assert!(!replica.join("nested/repo/.git/config").exists());
    assert!(!replica.join("nested/.env.production").exists());
    assert!(replica.join(".git/HEAD").exists());
    assert!(replica.join("nested/repo/.git/HEAD").exists());
    assert_eq!(
        fs::read_to_string(replica.join("nested/app.txt")).expect("read copied file"),
        "visible"
    );
}

#[test]
fn replica_created_audit_exclusions_match_runtime_rules() {
    let source = unique_tmp_dir("clawcrate_cli_replica_audit_source");
    fs::create_dir_all(source.join("nested/repo/.git")).expect("create nested repo .git");
    fs::write(source.join(".clawcrateignore"), "*.tmp\ncache/\n").expect("write .clawcrateignore");
    fs::write(source.join("nested/repo/.git/config"), "nested = hidden")
        .expect("write nested repo .git/config");
    fs::write(source.join("nested/repo/.git/HEAD"), "ref: refs/heads/main")
        .expect("write nested repo .git/HEAD");

    let copy_root = unique_tmp_dir("clawcrate_cli_replica_audit_copy_root");
    let artifacts_dir = unique_tmp_dir("clawcrate_cli_replica_audit_artifacts");
    let writer = ArtifactWriter::from_artifacts_dir(artifacts_dir.join("run"))
        .expect("create artifact writer");

    let copy_path = copy_root.join("workspace");
    let mut plan = mock_plan(NetLevel::Open, &["/bin/echo", "ok"]);
    plan.mode = WorkspaceMode::Replica {
        source: source.clone(),
        copy: copy_path.clone(),
    };

    materialize_workspace_for_execution(&plan, &writer).expect("materialize replica workspace");

    let audit_content = fs::read_to_string(writer.audit_ndjson_path()).expect("read audit");
    let event = audit_content
        .lines()
        .map(|line| serde_json::from_str::<AuditEvent>(line).expect("parse audit event"))
        .find_map(|event| match event.event {
            AuditEventKind::ReplicaCreated { excluded, .. } => Some(excluded),
            _ => None,
        })
        .expect("find ReplicaCreated event");

    assert!(event.contains(&".env".to_string()));
    assert!(event.contains(&".env.*".to_string()));
    assert!(event.contains(&"**/.git/config".to_string()));
    assert!(event.contains(&"*.tmp".to_string()));
    assert!(event.contains(&"cache/".to_string()));
    assert!(!copy_path.join("nested/repo/.git/config").exists());
}

#[test]
fn replica_copy_applies_clawcrateignore_patterns() {
    let source = unique_tmp_dir("clawcrate_cli_replica_ignore_source");
    fs::create_dir_all(source.join("nested").join("tmp")).expect("create nested tmp");

    fs::write(source.join(".clawcrateignore"), "*.log\nnested/tmp/\n")
        .expect("write .clawcrateignore");
    fs::write(source.join("keep.txt"), "keep").expect("write keep file");
    fs::write(source.join("skip.log"), "skip").expect("write skipped log");
    fs::write(source.join("nested/tmp/skip.txt"), "skip").expect("write nested skip");
    fs::write(source.join("nested/keep.md"), "keep").expect("write nested keep");

    let replica_root = unique_tmp_dir("clawcrate_cli_replica_ignore_copy");
    let replica = replica_root.join("workspace");
    let ignore_config = load_replica_ignore_config(&source).expect("load ignore config");
    copy_workspace_with_default_exclusions(&source, &replica, &ignore_config)
        .expect("copy workspace with ignore rules");

    assert!(replica.join("keep.txt").exists());
    assert!(replica.join("nested/keep.md").exists());
    assert!(!replica.join("skip.log").exists());
    assert!(!replica.join("nested/tmp/skip.txt").exists());
}

#[test]
fn collect_syncable_replica_changes_filters_exclusions_and_outside_paths() {
    let source = unique_tmp_dir("clawcrate_cli_sync_source");
    let copy = unique_tmp_dir("clawcrate_cli_sync_copy");
    fs::write(source.join(".clawcrateignore"), "*.log\n").expect("write .clawcrateignore");

    let fs_diff = vec![
        FsChange {
            path: copy.join("keep.txt"),
            kind: FsChangeKind::Created,
            size_bytes: Some(10),
        },
        FsChange {
            path: copy.join("drop.log"),
            kind: FsChangeKind::Created,
            size_bytes: Some(8),
        },
        FsChange {
            path: copy.join(".env"),
            kind: FsChangeKind::Created,
            size_bytes: Some(6),
        },
        FsChange {
            path: source.join("outside.txt"),
            kind: FsChangeKind::Created,
            size_bytes: Some(5),
        },
    ];

    let ignore_config = load_replica_ignore_config(&source).expect("load ignore config");
    let changes = collect_syncable_replica_changes(&copy, &source, &fs_diff, &ignore_config);

    assert_eq!(changes.len(), 1);
    assert_eq!(changes[0].relative_path, PathBuf::from("keep.txt"));
    assert_eq!(changes[0].kind, FsChangeKind::Created);
}

#[test]
fn apply_replica_sync_back_applies_created_modified_and_deleted_files() {
    let source = unique_tmp_dir("clawcrate_cli_sync_apply_source");
    let copy = unique_tmp_dir("clawcrate_cli_sync_apply_copy");
    fs::create_dir_all(source.join("dir")).expect("create source dir");
    fs::create_dir_all(copy.join("dir")).expect("create copy dir");

    fs::write(source.join("dir/modified.txt"), "before").expect("write source modified before");
    fs::write(copy.join("dir/modified.txt"), "after").expect("write source modified after");

    fs::write(copy.join("new.txt"), "new").expect("write created file");
    fs::write(source.join("remove.txt"), "remove").expect("write deleted file");

    let changes = vec![
        ReplicaSyncChange {
            relative_path: PathBuf::from("dir/modified.txt"),
            kind: FsChangeKind::Modified,
        },
        ReplicaSyncChange {
            relative_path: PathBuf::from("new.txt"),
            kind: FsChangeKind::Created,
        },
        ReplicaSyncChange {
            relative_path: PathBuf::from("remove.txt"),
            kind: FsChangeKind::Deleted,
        },
    ];

    apply_replica_sync_back(&source, &copy, &changes).expect("apply sync-back");

    assert_eq!(
        fs::read_to_string(source.join("dir/modified.txt")).expect("read modified file"),
        "after"
    );
    assert_eq!(
        fs::read_to_string(source.join("new.txt")).expect("read new file"),
        "new"
    );
    assert!(!source.join("remove.txt").exists());
}

#[test]
fn replica_sync_back_interactive_requires_both_stdin_and_stdout_terminals() {
    assert!(is_replica_sync_back_interactive(true, true));
    assert!(!is_replica_sync_back_interactive(false, true));
    assert!(!is_replica_sync_back_interactive(true, false));
    assert!(!is_replica_sync_back_interactive(false, false));
}

#[test]
fn apply_replica_sync_back_does_not_remove_directories_for_deleted_changes() {
    let source = unique_tmp_dir("clawcrate_cli_sync_delete_dir_source");
    let copy = unique_tmp_dir("clawcrate_cli_sync_delete_dir_copy");
    fs::create_dir_all(source.join("keep-dir")).expect("create source directory");
    fs::write(source.join("keep-dir/file.txt"), "keep").expect("write keep file");
    fs::create_dir_all(copy.join("keep-dir")).expect("create copy directory");

    let changes = vec![ReplicaSyncChange {
        relative_path: PathBuf::from("keep-dir"),
        kind: FsChangeKind::Deleted,
    }];

    apply_replica_sync_back(&source, &copy, &changes).expect("apply sync-back");

    assert!(source.join("keep-dir").is_dir());
    assert!(source.join("keep-dir/file.txt").is_file());
}

#[test]
fn execution_status_maps_process_outcome() {
    let success = Command::new("/bin/sh")
        .arg("-c")
        .arg("exit 0")
        .status()
        .expect("run success command");
    let failure = Command::new("/bin/sh")
        .arg("-c")
        .arg("exit 3")
        .status()
        .expect("run failure command");

    assert_eq!(execution_status_from_exit_status(&success), Status::Success);
    assert_eq!(execution_status_from_exit_status(&failure), Status::Failed);
}

#[test]
fn execution_status_prefers_runtime_termination_reason() {
    let success = Command::new("/bin/sh")
        .arg("-c")
        .arg("exit 0")
        .status()
        .expect("run success command");

    assert_eq!(
        execution_status(&success, RunTermination::Interrupted),
        Status::Killed
    );
    assert_eq!(
        execution_status(&success, RunTermination::Timeout),
        Status::Timeout
    );
}

#[test]
fn monitored_child_timeout_preserves_output_capture() {
    let artifacts_dir = unique_tmp_dir("clawcrate_cli_timeout_capture");
    let capture_config = CaptureConfig {
        artifacts_dir,
        max_output_bytes: 1024,
    };

    let mut command = Command::new("/bin/sh");
    command
        .arg("-c")
        .arg("printf 'before-timeout'; sleep 2")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = command.spawn().expect("spawn timeout child");
    let stdout = child.stdout.take().expect("take stdout");
    let stderr = child.stderr.take().expect("take stderr");

    let result =
        run_monitored_child(&mut child, stdout, stderr, &capture_config, 1, None).expect("monitor");

    assert_eq!(result.termination, RunTermination::Timeout);
    assert_eq!(
        execution_status(&result.exit_status, result.termination),
        Status::Timeout
    );
    assert_eq!(
        fs::read_to_string(capture_config.stdout_log_path()).expect("read stdout"),
        "before-timeout"
    );
}

#[test]
fn monitored_child_repeated_interrupt_forces_fast_kill() {
    let artifacts_dir = unique_tmp_dir("clawcrate_cli_interrupt_escalation");
    let capture_config = CaptureConfig {
        artifacts_dir,
        max_output_bytes: 1024,
    };

    let mut command = Command::new("/bin/sh");
    command
        .arg("-c")
        .arg("trap '' TERM; while :; do :; done")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = command.spawn().expect("spawn interrupt child");
    let stdout = child.stdout.take().expect("take stdout");
    let stderr = child.stderr.take().expect("take stderr");

    let mut polls = 0usize;
    let started = Instant::now();
    let result = run_monitored_child_with_signal_poller(
        &mut child,
        stdout,
        stderr,
        &capture_config,
        0,
        None,
        &mut || {
            polls += 1;
            if polls <= 2 {
                1
            } else {
                0
            }
        },
    )
    .expect("monitor");

    assert_eq!(result.termination, RunTermination::Interrupted);
    assert!(
        started.elapsed() < Duration::from_secs(1),
        "repeated interrupt should avoid full grace wait"
    );
}

#[cfg(unix)]
#[test]
fn eligible_process_group_id_rejects_non_safe_group_targets() {
    assert_eq!(eligible_process_group_id(None), None);
    assert_eq!(eligible_process_group_id(Some(-7)), None);
    assert_eq!(eligible_process_group_id(Some(0)), None);
    assert_eq!(eligible_process_group_id(Some(1)), None);
    assert_eq!(eligible_process_group_id(Some(2)), Some(2));
    assert_eq!(eligible_process_group_id(Some(99)), Some(99));
}

#[cfg(unix)]
#[test]
fn signal_fallback_attempts_process_group_when_pid_signal_fails() {
    let result = send_unix_signal_with_group_fallback_impl(
        1234,
        Some(44),
        Signal::SIGTERM,
        |_pid, _signal| Err(anyhow!("pid failed")),
        |_pgid, _signal| Ok(()),
    );

    assert!(result.is_ok(), "process-group fallback should recover");
}

#[cfg(unix)]
#[test]
fn signal_fallback_returns_pid_error_when_no_safe_group_exists() {
    let result = send_unix_signal_with_group_fallback_impl(
        1234,
        Some(1),
        Signal::SIGTERM,
        |_pid, _signal| Err(anyhow!("pid failed")),
        |_pgid, _signal| Ok(()),
    );

    assert!(
        result.is_err(),
        "pid error should surface without safe fallback"
    );
}

#[cfg(unix)]
#[test]
fn signal_fallback_surfaces_combined_error_when_both_paths_fail() {
    let result = send_unix_signal_with_group_fallback_impl(
        1234,
        Some(44),
        Signal::SIGKILL,
        |_pid, _signal| Err(anyhow!("pid failed")),
        |_pgid, _signal| Err(anyhow!("group failed")),
    );

    let error = result.expect_err("both failures should return error");
    let message = error.to_string();
    assert!(message.contains("pid_error=pid failed"));
    assert!(message.contains("group_error=group failed"));
}

#[cfg(unix)]
#[test]
fn monitored_child_cleans_up_inherited_pipe_descendants() {
    let artifacts_dir = unique_tmp_dir("clawcrate_cli_pipe_inheritance_cleanup");
    let capture_config = CaptureConfig {
        artifacts_dir,
        max_output_bytes: 1024,
    };

    let mut command = Command::new("/bin/sh");
    command
        .arg("-c")
        .arg("sh -c 'sleep 5' & printf 'done'")
        .process_group(0)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = command.spawn().expect("spawn inherited-pipe child");
    let process_group_id = child.id() as i32;
    let stdout = child.stdout.take().expect("take stdout");
    let stderr = child.stderr.take().expect("take stderr");

    let started = Instant::now();
    let result = run_monitored_child_with_signal_poller(
        &mut child,
        stdout,
        stderr,
        &capture_config,
        0,
        Some(process_group_id),
        &mut || 0usize,
    )
    .expect("monitor");

    assert_eq!(result.termination, RunTermination::Exited);
    assert!(
        started.elapsed() < Duration::from_secs(4),
        "capture drain should not block for full descendant sleep"
    );
    assert_eq!(
        fs::read_to_string(capture_config.stdout_log_path()).expect("read stdout"),
        "done"
    );
}
