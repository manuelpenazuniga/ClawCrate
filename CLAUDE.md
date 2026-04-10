# CLAUDE.md — ClawCrate Development Guide

## Project Overview

ClawCrate is a secure execution runtime for AI agents. A single Rust binary per platform (~15-20MB) that sandboxes shell commands using native OS primitives: Landlock + seccomp on Linux, Seatbelt on macOS. No Docker, no VMs, no root required.

**This file is the source of truth for all development work.** Read it fully before writing any code.

**Specification document:** `docs/clawcrate-v3.1.1.md` contains the full project specification including architecture decisions, competitive landscape, and rationale for every design choice. This CLAUDE.md extracts the actionable implementation details.

---

## Core Architecture

```
clawcrate run --profile build -- cargo test
    │
    ├── Parse CLI args (clap)
    ├── Resolve profile (safe|build|install|open or custom YAML)
    ├── Auto-detect stack if no profile specified (Cargo.toml → rust, package.json → node)
    ├── Determine workspace mode: DefaultMode from profile + CLI flags (--replica/--direct)
    ├── Materialize WorkspaceMode: if Replica, create temp dir + filtered copy
    ├── Scrub environment variables (remove *_SECRET*, *_TOKEN, *_KEY, etc.)
    ├── Generate execution plan (plan.json)
    │
    ├── LAUNCH (platform-specific):
    │     Linux:  fork → set rlimits → apply Landlock → apply seccomp → exec
    │     macOS:  generate SBPL → exec via /usr/bin/sandbox-exec
    │
    ├── CAPTURE: pipe stdout/stderr, monitor child process
    ├── COLLECT: wait for exit, compute fs-diff (snapshot pre vs post)
    ├── WRITE ARTIFACTS: plan.json, result.json, stdout.log, stderr.log, audit.ndjson, fs-diff.json
    │
    └── Report result to user (human-readable or --json)
```

### Key Design Decisions — DO NOT DEVIATE

1. **Deny by default.** The sandboxed process starts with zero permissions and receives only what the profile grants. Never start permissive and restrict.

2. **Platform-native sandboxing only.** Linux uses Landlock + seccomp. macOS uses Seatbelt. No Docker, no VMs, no containers. The sandbox is kernel-level, irremovible from inside, and inherited by all child processes.

3. **`--` separates ClawCrate flags from the command.** Always `clawcrate run -- npm test`, never `clawcrate run "npm test"`. No shell parsing, no quoting ambiguity. `sh -c "..."` is the explicit escape hatch when the user needs pipes or redirects.

4. **Profiles, not YAML, as the primary UX.** `--profile safe` is the entry point. Custom YAML is the escape hatch for power users. The user buys peace of mind, not configuration files.

5. **`install` profile defaults to Replica Mode.** This is the highest-risk profile (postinstall scripts + network). `default_mode: Replica` is a property of the profile, not a flag the user remembers. Opt-out requires explicit `--direct`.

6. **Artifacts on disk, not database.** Each execution generates a directory under `~/.clawcrate/runs/exec_{id}/` with plain files: `plan.json`, `result.json`, `stdout.log`, `stderr.log`, `audit.ndjson`, `fs-diff.json`. SQLite is P2.

7. **`DefaultMode` and `WorkspaceMode` are separate types.** `DefaultMode { Direct, Replica }` is profile intent (no paths). `WorkspaceMode { Direct, Replica { source, copy } }` is materialized state with real paths. The profile never carries runtime state.

8. **`SandboxBackend::launch()`, not `apply()`.** Each backend decides its own launch strategy. Linux forks, applies sandbox in-process, then execs. macOS execs via `sandbox-exec` directly. The trait does not assume a fork+apply model.

9. **Landlock cannot deny intra-workspace.** If you grant `read` to `.`, you cannot deny `.env` inside it. On Linux, use Replica Mode for this. On macOS, Seatbelt's regex-based deny handles it natively. **Never promise intra-workspace deny on Linux without Replica Mode.**

10. **The alpha has no network filtering by domain.** Network is either `none` (blocked) or `open` (unrestricted). Domain-level filtering via egress proxy is P1. **Never claim the alpha filters by hostname.**

11. **ClawCrate sandboxes commands, not agents.** It integrates at the boundary where the agent delegates shell execution. It does not wrap the agent process itself.

---

## Tech Stack

### Rust Crates — Pin These Versions

```toml
# Core
serde = { version = "1", features = ["derive"] }
serde_json = "1"
serde_yaml = "0.9"
clap = { version = "4", features = ["derive"] }
anyhow = "1"
thiserror = "2"
chrono = { version = "0.4", features = ["serde"] }

# System
nix = { version = "0.29", features = ["process", "signal", "resource", "fs"] }

# Observability
tracing = "0.1"
tracing-subscriber = { version = "0.3", features = ["env-filter"] }

# Utilities
sha2 = "0.10"
walkdir = "2"
comfy-table = "7"
uuid = { version = "1", features = ["v7"] }

# Linux-only
[target.'cfg(target_os = "linux")'.dependencies]
landlock = "0.4"
seccompiler = "0.4"
```

### What is NOT in the stack

- No tokio in alpha (no async needed — fork/exec is sync, I/O is piped). Tokio enters in P1 for the egress proxy.
- No SQLite in alpha. Artifacts are plain files on disk.
- No Docker, containers, or VM dependencies.
- No wasmtime. WASI does not support native runtimes (Python, Node, git).
- No notify/inotify for fs-diff. We use snapshot pre/post with walkdir.
- No reqwest/hyper. ClawCrate makes no HTTP requests in alpha.

---

## Workspace Structure

```
clawcrate/
├── Cargo.toml                         # Workspace root — members = ["crates/*"]
├── rust-toolchain.toml                # Pin to stable
├── .cargo/
│   └── config.toml                    # musl target config for Linux static builds
├── crates/
│   ├── clawcrate-types/               # Shared types. No I/O. No business logic.
│   ├── clawcrate-profiles/            # Profile engine, presets, auto-detection
│   ├── clawcrate-sandbox/             # SandboxBackend trait + platform impls
│   ├── clawcrate-capture/             # stdout/stderr pipes + fs-diff snapshots
│   ├── clawcrate-audit/               # Artifact writer (ndjson, json)
│   └── clawcrate-cli/                 # Clap CLI — the only binary crate
├── profiles/
│   ├── safe.yaml
│   ├── build.yaml
│   ├── install.yaml
│   └── open.yaml
├── fixtures/
│   ├── malicious_postinstall/         # package.json with exfil postinstall
│   ├── exfiltration_attempt/          # Python script trying urllib to evil.com
│   ├── env_leak/                      # Script echoing AWS_SECRET_ACCESS_KEY
│   ├── sandbox_escape/                # Script trying to disable sandbox
│   ├── resource_exhaustion/           # Fork bomb, memory hog
│   └── benign_project/               # Working Node.js project for happy path
├── tests/
│   ├── integration/                   # Cross-platform integration tests
│   └── golden/                        # Snapshot tests for CLI output
├── docs/
│   ├── clawcrate-v3.1.1.md           # Full specification
│   ├── architecture.md
│   ├── profiles-reference.md
│   ├── kernel-requirements.md
│   └── integration-guide.md
└── scripts/
    ├── install.sh
    └── release.sh
```

---

## Crate Dependency Graph

```
clawcrate-cli
  └─→ clawcrate-sandbox
  │     ├─→ clawcrate-profiles
  │     │     └─→ clawcrate-types
  │     └─→ clawcrate-types
  ├─→ clawcrate-capture
  │     └─→ clawcrate-types
  └─→ clawcrate-audit
        └─→ clawcrate-types
```

**Rule: `clawcrate-types` has ZERO internal dependencies.** It is the leaf crate. Everything flows down from `clawcrate-cli`.

**Rule: `clawcrate-sandbox` contains ALL platform-specific code.** No `#[cfg(target_os)]` anywhere else.

---

## Module Specifications

### clawcrate-types

Shared types used across all crates. No business logic. No I/O. No platform-specific code.

```rust
// Profile intent — no paths, no runtime state
pub enum DefaultMode { Direct, Replica }

// Materialized workspace — has real paths
pub enum WorkspaceMode {
    Direct,
    Replica { source: PathBuf, copy: PathBuf },
}

pub struct ResolvedProfile {
    pub name: String,
    pub fs_read: Vec<PathBuf>,
    pub fs_write: Vec<PathBuf>,
    pub fs_deny: Vec<String>,          // Globs — enforcement platform-dependent
    pub net: NetLevel,
    pub env_scrub: Vec<String>,        // Patterns to remove: "*_SECRET*", "AWS_*", etc.
    pub env_passthrough: Vec<String>,  // Variables to keep: "HOME", "PATH", etc.
    pub resources: ResourceLimits,
    pub default_mode: DefaultMode,     // install → Replica, others → Direct
}

pub struct ExecutionPlan {
    pub id: String,                    // UUIDv7
    pub command: Vec<String>,
    pub cwd: PathBuf,
    pub profile: ResolvedProfile,
    pub mode: WorkspaceMode,           // Materialized from DefaultMode + CLI flags
    pub actor: Actor,
    pub created_at: DateTime<Utc>,
}

pub enum Actor { Human, Agent { name: String } }
pub enum NetLevel { None, Open }
pub struct ResourceLimits {
    pub max_cpu_seconds: u64,
    pub max_memory_mb: u64,
    pub max_open_files: u64,
    pub max_processes: u64,
    pub max_output_bytes: u64,
}

pub struct ExecutionResult {
    pub id: String,
    pub exit_code: Option<i32>,
    pub status: Status,
    pub duration_ms: u64,
    pub artifacts_dir: PathBuf,
}

pub enum Status { Success, Failed, Timeout, Killed, SandboxError(String) }

// Audit
pub struct AuditEvent {
    pub timestamp: DateTime<Utc>,
    pub event: AuditEventKind,
}
pub enum AuditEventKind {
    SandboxApplied { backend: String, capabilities: Vec<String> },
    EnvScrubbed { removed: Vec<String> },
    ProcessStarted { pid: u32, command: Vec<String> },
    ProcessExited { exit_code: i32, duration_ms: u64 },
    PermissionBlocked { resource: String, reason: String },
    ReplicaCreated { source: PathBuf, copy: PathBuf, excluded: Vec<String> },
    ReplicaSyncBack { approved: bool, changes: usize },
}

// System capabilities (from doctor)
pub struct SystemCapabilities {
    pub platform: Platform,
    pub landlock_abi: Option<u8>,      // None on macOS
    pub seccomp_available: bool,       // false on macOS
    pub seatbelt_available: bool,      // false on Linux
    pub user_namespaces: bool,
    pub macos_version: Option<String>,
    pub kernel_version: Option<String>,
}
pub enum Platform { Linux, MacOS }

// Errors — use thiserror
#[derive(thiserror::Error, Debug)]
pub enum ClawCrateError {
    #[error("Profile not found: {0}")]
    ProfileNotFound(String),
    #[error("Sandbox setup failed: {0}")]
    SandboxSetup(String),
    #[error("Command execution failed: {0}")]
    Execution(String),
    #[error("Replica mode failed: {0}")]
    Replica(String),
    #[error("System not supported: {0}")]
    Unsupported(String),
}
```

### clawcrate-profiles

Loads and resolves profiles. Auto-detects project stack.

Key responsibilities:
- Load built-in profiles from `profiles/*.yaml`
- Load custom profiles from `.clawcrate/*.yaml`
- Auto-detect stack: `Cargo.toml` → rust profile paths, `package.json` → node paths, `pyproject.toml` → python paths
- Resolve profile: merge base profile + stack-specific paths + custom overrides → `ResolvedProfile`
- Env scrub patterns: hardcoded defaults + profile overrides

Auto-detection priority:
1. `--profile <name>` → use that profile
2. `--profile <path.yaml>` → load custom YAML
3. No flag → auto-detect stack from workspace files, use `safe` as fallback

### clawcrate-sandbox

The core security crate. Contains the `SandboxBackend` trait and both platform implementations.

```rust
pub trait SandboxBackend: Send + Sync {
    fn prepare(&self, plan: &ExecutionPlan) -> anyhow::Result<SandboxConfig>;
    fn launch(
        &self,
        config: &SandboxConfig,
        command: &[String],
        capture: &CaptureConfig,
    ) -> anyhow::Result<SandboxedChild>;
    fn probe(&self) -> SystemCapabilities;
}

pub struct SandboxedChild {
    pub pid: u32,
    pub stdout: std::process::ChildStdout,
    pub stderr: std::process::ChildStderr,
}
```

**`clawcrate-sandbox/linux.rs`** — `LinuxSandbox`:
- `prepare()`: Build Landlock ruleset from `ResolvedProfile.fs_read/fs_write`. Build seccomp-bpf filter. Calculate rlimits.
- `launch()`: fork() → in child: set rlimits, apply Landlock (restrict_self), apply seccomp (MUST be last — it restricts own syscalls), exec. In parent: return SandboxedChild with piped stdout/stderr.
- `probe()`: Detect Landlock ABI version (try `landlock_create_ruleset` syscall), check `/proc/sys/kernel/seccomp`, check user namespace support.

**Order of sandbox application in Linux child process is critical:**
1. `setrlimit()` — resource limits (this uses syscalls that seccomp might block)
2. Landlock `restrict_self()` — filesystem restrictions
3. seccomp — syscall filtering (ALWAYS LAST — after this, the process can't change its own restrictions)

**`clawcrate-sandbox/darwin.rs`** — `DarwinSandbox`:
- `prepare()`: Generate SBPL (Sandbox Profile Language) string from `ResolvedProfile`. Handle path escaping carefully. Use `(deny default)` as base. Add allows for system paths, workspace, toolchain. Add denies for secrets. Handle `fs_deny` globs as Seatbelt regex.
- `launch()`: Write SBPL to temp file. Build args: `["/usr/bin/sandbox-exec", "-f", sbpl_path, "--", command...]`. Spawn process with piped stdout/stderr. Set env vars (scrubbed). Return SandboxedChild.
- `probe()`: Check `/usr/bin/sandbox-exec` exists and is executable. Read macOS version from `sw_vers`.

**SBPL generation rules (CRITICAL):**
- Always start with `(version 1)` and `(deny default)`
- `(allow file-read-metadata)` MUST be global (no path filter) — required for `getaddrinfo()` DNS resolution
- `(allow sysctl-read)` — required by many processes
- Use `(subpath ...)` for directory trees, `(literal ...)` for exact paths
- Use `(regex ...)` for glob patterns in `fs_deny` — escape special chars properly
- Last-match-wins: deny rules AFTER allow rules override them for nested paths
- Always deny `~/.ssh`, `~/.aws`, `~/.gnupg`, `~/.docker`, `~/Library/Keychains`, `~/Library/Cookies`
- For network blocked: `(deny network*)`
- For network open: omit network deny (default allow for network after removing `(deny default)` for network category... actually: add `(allow network*)` explicitly)

**`clawcrate-sandbox/env_scrub.rs`** — Cross-platform:
- Remove variables matching patterns: `AWS_*`, `*_SECRET*`, `*_PASSWORD*`, `*_KEY` (except `HOME`), `*_TOKEN`, `SSH_AUTH_SOCK`, `GOOGLE_APPLICATION_CREDENTIALS`, `DATABASE_URL`
- Keep: `HOME`, `PATH`, `USER`, `SHELL`, `TERM`, `LANG`, `LC_*`, `TMPDIR`, `XDG_*`
- Profile can override with `env_passthrough` and `env_scrub`
- Log every removed variable to audit (variable name only, NEVER the value)

**`clawcrate-sandbox/rlimits.rs`** — Cross-platform:
- `RLIMIT_CPU`: from `resources.max_cpu_seconds`
- `RLIMIT_AS`: from `resources.max_memory_mb` (converted to bytes)
- `RLIMIT_NOFILE`: from `resources.max_open_files`
- `RLIMIT_NPROC`: from `resources.max_processes`
- Applied via `nix::sys::resource::setrlimit`

**`clawcrate-sandbox/doctor.rs`** — Cross-platform:
- On Linux: detect Landlock ABI version, seccomp support, user namespace support, kernel version
- On macOS: detect `sandbox-exec` binary, macOS version, check if SIP is enabled
- Return `SystemCapabilities` struct
- Format as human-readable table with ✅/⚠️/❌

### clawcrate-capture

Handles stdout/stderr capture and filesystem diff.

**stdout/stderr capture:**
- Read from pipes in a background thread (or async with tokio in P1)
- Write to `stdout.log` and `stderr.log` in artifacts dir
- Optionally tee to terminal (default for interactive use)
- Respect `max_output_bytes` from resource limits — truncate if exceeded

**fs-diff (snapshot-based, NOT watcher-based):**
- Pre-execution: walk `fs_write` paths with `walkdir`, collect `(path, size, mtime, sha256)` tuples
- Post-execution: walk same paths again
- Diff: compare tuples → `FsChange { path, kind: Created|Modified|Deleted, size }`
- Write to `fs-diff.json`
- This is more reliable than inotify/FSEvents watchers for audit purposes

### clawcrate-audit

Writes audit artifacts to disk.

- `plan.json`: serialized `ExecutionPlan` (created before launch)
- `result.json`: serialized `ExecutionResult` (created after completion)
- `audit.ndjson`: one JSON line per `AuditEvent`, appended during execution
- `fs-diff.json`: from clawcrate-capture
- `stdout.log`, `stderr.log`: from clawcrate-capture
- Directory: `~/.clawcrate/runs/{execution_id}/`
- Execution ID: UUIDv7 (temporally sortable)

### clawcrate-cli

Clap CLI. The only binary crate.

```
USAGE:
    clawcrate <COMMAND>

COMMANDS:
    run       Execute a command inside a sandbox
    plan      Show execution plan without executing (dry-run)
    doctor    Check system sandboxing capabilities

OPTIONS (for run and plan):
    --profile <PROFILE>     Built-in name or path to YAML (default: auto-detect)
    --replica               Force Replica Mode (for profiles that default to Direct)
    --direct                Force Direct Mode (for profiles that default to Replica)
    --json                  Machine-readable JSON output

GLOBAL:
    --verbose               Enable debug logging (CLAWCRATE_LOG=debug)
    --help
    --version
```

Main flow in `run`:
1. Parse args
2. Load profile (clawcrate-profiles)
3. Determine workspace mode: `profile.default_mode` + `--replica`/`--direct` → `DefaultMode`
4. If Replica: create temp dir, copy workspace (excluding secrets), materialize `WorkspaceMode::Replica { source, copy }`
5. Scrub env vars (clawcrate-sandbox/env_scrub)
6. Create `ExecutionPlan`, write `plan.json`
7. Take pre-execution fs snapshot (clawcrate-capture)
8. Get backend: `#[cfg(target_os = "linux")] LinuxSandbox` / `#[cfg(target_os = "macos")] DarwinSandbox`
9. `backend.prepare(plan)` → `SandboxConfig`
10. `backend.launch(config, command, capture)` → `SandboxedChild`
11. Read stdout/stderr from pipes, write to logs
12. Wait for child exit
13. Take post-execution fs snapshot, compute diff
14. Write `result.json`, `audit.ndjson`, `fs-diff.json`
15. If Replica: show diff, ask for sync-back confirmation
16. Print summary to terminal (or JSON if `--json`)

---

## Development Roadmap — Step by Step

Follow this order exactly. Each phase builds on the previous. Do not skip ahead.

### Phase 1 — Week 1: Foundation (types, profiles, env scrub)

**Goal**: Workspace compiles. Profiles load. Env scrubbing works. `clawcrate plan` prints a plan.

#### Step 1.1: Scaffold workspace
- Create root `Cargo.toml` with `[workspace]` and all member crates
- Create `rust-toolchain.toml` pinning stable Rust
- Create every crate directory with minimal `Cargo.toml` and `lib.rs` (or `main.rs` for cli)
- Create `profiles/safe.yaml`, `profiles/build.yaml`, `profiles/install.yaml`, `profiles/open.yaml` with correct content
- Verify: `cargo check --workspace` passes

#### Step 1.2: clawcrate-types
- Define ALL types listed in Module Specifications above
- `#[derive(Debug, Clone, Serialize, Deserialize)]` on all types
- Define `ClawCrateError` with `thiserror`
- NO business logic, only types and trivial constructors
- Tests: serde roundtrip for all key types (`ExecutionPlan`, `ResolvedProfile`, `AuditEvent`)

#### Step 1.3: clawcrate-profiles
- Define profile YAML schema (match the built-in profiles)
- Implement YAML loading with `serde_yaml`
- Implement stack auto-detection: walk cwd for `Cargo.toml`, `package.json`, `pyproject.toml`
- Implement profile resolver: base profile + stack-specific paths → `ResolvedProfile`
- Implement env scrub pattern compilation (glob patterns → matched against env var names)
- Tests: load each built-in profile, auto-detect rust/node/python, scrub patterns match correctly

#### Step 1.4: clawcrate-sandbox (env_scrub + rlimits only)
- Implement `env_scrub.rs`: filter `std::env::vars()` against scrub patterns, return clean env map
- Implement `rlimits.rs`: apply rlimits from `ResourceLimits` via `nix::sys::resource::setrlimit`
- Tests: env scrub removes `AWS_SECRET_ACCESS_KEY`, keeps `HOME`. rlimits applied correctly.

#### Step 1.5: clawcrate-cli (plan command only)
- Set up clap with `run`, `plan`, `doctor` subcommands (only `plan` functional)
- `plan` command: parse args → load profile → resolve → print plan as human-readable table
- Use `comfy-table` for formatted output
- `--json` flag: print plan as JSON

**Milestone M1**: `clawcrate plan --profile build -- cargo test` prints a correct, readable plan. `cargo test --workspace` passes.

---

### Phase 2 — Week 2: Sandbox Backends

**Goal**: Both Linux and macOS sandbox backends pass security fixtures.

#### Step 2.1: clawcrate-sandbox/linux.rs
- Implement `LinuxSandbox::probe()`: detect Landlock ABI, seccomp, kernel version
- Implement `LinuxSandbox::prepare()`: build Landlock ruleset + seccomp filter from `ResolvedProfile`
- Implement `LinuxSandbox::launch()`: fork → rlimits → Landlock → seccomp → exec. Pipe stdout/stderr.
- Landlock rules: use `landlock` crate with `CompatLevel::BestEffort`. Map `fs_read` → `AccessFs::from_read(abi)`, `fs_write` → separate `ReadWrite` (NOT `from_all` — least privilege).
- seccomp: use `seccompiler`. Default profile allows: read, write, open, close, stat, fstat, mmap, mprotect, munmap, brk, ioctl, access, pipe, select, poll, dup, fork, vfork, execve, exit, getpid, getuid, getcwd, chdir, rename, unlink, mkdir, rmdir, socket (if net=Open), connect (if net=Open), clock_gettime, futex, and similar safe syscalls. Block: ptrace, mount, umount, reboot, kexec_load, swapon, swapoff, init_module, delete_module.
- Tests (Linux only): fixture that tries `cat ~/.ssh/id_rsa` → EACCES. Fixture that tries `strace` → EPERM.

#### Step 2.2: clawcrate-sandbox/darwin.rs
- Implement `DarwinSandbox::probe()`: check sandbox-exec binary, macOS version
- Implement `DarwinSandbox::prepare()`: generate SBPL string from `ResolvedProfile`
- Implement `DarwinSandbox::launch()`: write SBPL to temp file, spawn `/usr/bin/sandbox-exec -f <sbpl> -- <command>`, pipe stdout/stderr
- SBPL generation: follow the rules in Module Specifications above. **Test the generated SBPL manually** with `sandbox-exec -f profile.sb /bin/ls` before relying on automated tests.
- Tests (macOS only): fixture that tries `cat ~/.ssh/id_rsa` → Operation not permitted. Fixture that tries `cat .env` inside workspace → blocked (regex deny).

#### Step 2.3: clawcrate-sandbox/doctor.rs
- Implement `doctor` command that calls `backend.probe()` and formats result
- Show ✅/⚠️/❌ for each capability
- Show recommendations for missing capabilities

**Milestone M2**: `clawcrate doctor` reports system capabilities. Security fixtures pass on both platforms. Landmark test: a sandboxed process CANNOT read `~/.ssh/id_rsa`.

---

### Phase 3 — Week 3: Runner + Capture + fs-diff

**Goal**: `clawcrate run` works end-to-end. stdout/stderr captured. fs-diff generated.

#### Step 3.1: clawcrate-capture
- Implement stdout/stderr pipe reader (spawn reader threads, write to log files + optionally tee to terminal)
- Implement fs snapshot: `walk_and_hash(paths) → HashMap<PathBuf, FileMetadata>`
- Implement fs diff: `diff(pre, post) → Vec<FsChange>`
- Tests: create temp dir, add/modify/delete files, verify diff is correct

#### Step 3.2: clawcrate-audit
- Implement artifact directory creation: `~/.clawcrate/runs/{id}/`
- Implement writers: `write_plan()`, `write_result()`, `append_audit_event()`, `write_fs_diff()`
- `audit.ndjson` is append-only, one JSON line per event
- Tests: write and read back all artifact types

#### Step 3.3: Wire it all together in clawcrate-cli
- Implement `run` command with full pipeline (steps 1-16 from the CLI spec above)
- Handle signals: SIGINT → send SIGTERM to child → wait → collect
- Handle timeout: if child exceeds `max_cpu_seconds`, send SIGKILL
- Error handling: if sandbox setup fails, write error to result.json with `Status::SandboxError`

**Milestone M3**: `clawcrate run --profile build -- echo "hello"` executes, captures "hello" in stdout.log, writes all artifacts, and exits cleanly on both platforms.

---

### Phase 4 — Week 4: Replica Mode + Artifacts

**Goal**: Replica mode works. `install` profile auto-uses replica.

#### Step 4.1: Replica mode implementation
- Parse `.clawcrateignore` (same syntax as `.gitignore`)
- Default exclusions: `.env`, `.env.*`, `.git/config`
- Create temp directory: `/tmp/clawcrate/exec_{id}/workspace/`
- Copy workspace to temp, respecting exclusions. Use hardlinks where possible (same filesystem + supported).
- After execution: compute diff between temp copy and original workspace
- Show diff to user. **Sync-back requires explicit confirmation (y/n prompt).** Never automatic.
- If `--json` mode: include diff in output, skip interactive confirmation (assume no sync-back)

#### Step 4.2: DefaultMode → WorkspaceMode materialization
- In CLI: read `profile.default_mode`, check `--replica`/`--direct` flags
- Priority: CLI flag > profile default
- If Replica: create temp dir, copy, set `WorkspaceMode::Replica { source, copy }`
- If Direct: set `WorkspaceMode::Direct`
- Update `ExecutionPlan.cwd` to point to copy dir in Replica mode

#### Step 4.3: Test install profile
- Use `benign_project` fixture (Node.js project with package.json)
- `clawcrate run --profile install -- npm install` should:
  - Auto-use Replica (install's default_mode)
  - Copy workspace excluding `.env`
  - Run npm install in the copy
  - Show diff of `node_modules/` changes
  - Ask for sync-back confirmation
- Verify `.env` is NOT present in the copy

**Milestone M4**: `clawcrate run --profile install -- npm install` works with automatic Replica mode on both platforms. `.env` excluded from copy.

---

### Phase 5 — Week 5: Polish + Doctor + JSON

**Goal**: All three commands polished. JSON output works. Doctor is complete.

#### Step 5.1: CLI polish
- Error messages: always actionable. "Landlock not available (kernel 5.13+ required). Run `clawcrate doctor` for details."
- `--json` on all commands: plan, run, doctor
- `--verbose` sets `CLAWCRATE_LOG=debug`
- Respect `NO_COLOR` env var

#### Step 5.2: Doctor polish
- Pretty output with platform-specific sections
- On macOS: warn about sandbox-exec deprecation status, show macOS version
- On Linux: show Landlock ABI version with feature list, show kernel version
- Recommendations section: "Your system supports full sandboxing" or "Missing X — consider upgrading kernel"

#### Step 5.3: Golden tests
- Capture CLI output for `plan`, `run`, `doctor` commands
- Store as `tests/golden/*.txt`
- Compare on CI

**Milestone M5**: All three commands work. JSON output is valid. Doctor gives useful diagnostics. Golden tests pass.

---

### Phase 6 — Week 6: Docs + Cross-Platform Tests + Release

**Goal**: Publishable. A new user follows the README and runs their first sandbox in <5 minutes.

#### Step 6.1: Documentation
- `README.md`: marketing-grade, technically precise (already written)
- `docs/architecture.md`: crate map, data flow, platform differences
- `docs/profiles-reference.md`: every profile, every field, every default
- `docs/kernel-requirements.md`: Linux kernel table, macOS version table
- `docs/integration-guide.md`: how to use with OpenClaw, Claude Code, Codex, Cursor

#### Step 6.2: Cross-platform CI
- GitHub Actions with Linux (ubuntu-latest) and macOS (macos-latest) runners
- `cargo test --workspace` on both
- Security fixtures on both
- Golden tests on both
- `cargo clippy --workspace -- -D warnings` on both
- `cargo fmt --check` on both

#### Step 6.3: Release build
- Linux: `cross build --release --target x86_64-unknown-linux-musl`
- Linux ARM: `cross build --release --target aarch64-unknown-linux-musl`
- macOS ARM: `cargo build --release --target aarch64-apple-darwin`
- macOS Intel: `cargo build --release --target x86_64-apple-darwin`
- Create GitHub Release with all 4 binaries + SHA256 checksums
- Write `scripts/install.sh` that detects platform and downloads correct binary
- Write CHANGELOG.md

**Milestone M6 (Alpha Release)**: GitHub repo public. Binaries downloadable. New user runs first sandbox in <5 minutes on either platform.

---

## Coding Standards

### Error Handling
- Use `anyhow::Result` for application-level functions (CLI, orchestration)
- Use `thiserror` for library-level errors in `clawcrate-types`
- Never `.unwrap()` in production code. Use `.expect("reason")` only for truly impossible states.
- All errors must be actionable: tell the user what to do about it.

### Testing
- Unit tests in same file: `#[cfg(test)] mod tests { ... }`
- Integration tests in `tests/integration/`
- Golden tests in `tests/golden/`
- Platform-conditional tests: `#[cfg(target_os = "linux")]` / `#[cfg(target_os = "macos")]`
- Security fixtures are the most important tests. They must pass on EVERY commit.

### Formatting
- `cargo fmt` on every commit
- `cargo clippy -- -D warnings` must pass
- No `#[allow(clippy::...)]` without a comment explaining why

### Git
- Conventional commits: `feat:`, `fix:`, `test:`, `docs:`, `refactor:`, `chore:`
- One logical change per commit
- Feature branches off `main`

### Logging
- Use `tracing` macros: `tracing::info!()`, `tracing::warn!()`, `tracing::error!()`
- Structured fields: `execution_id`, `profile`, `backend`, `command`
- NEVER log: env var values, file contents, secret paths with actual home directory
- Log at `info`: execution start/end, sandbox applied, profile resolved
- Log at `debug`: SBPL generation details, Landlock rule construction, fs-diff details
- Log at `warn`: degraded sandbox (missing Landlock ABI), large replica copy, slow fs-diff
- Log at `error`: sandbox setup failure, child process crash, artifact write failure

---

## Key Implementation Warnings

### Landlock Gotchas
- `from_all(abi)` grants execute permission along with read/write. For write paths, use separate read+write access flags WITHOUT execute unless the path contains binaries the command needs to run.
- Landlock rules are ADDITIVE within a ruleset — you grant access, you don't deny it. The implicit deny is everything not explicitly allowed. This means you CANNOT deny `.env` inside a path you allowed with `read`.
- Always use `CompatLevel::BestEffort` so the sandbox works on older kernels with fewer features.
- After `restrict_self()`, the process cannot regain permissions. This is the whole point.

### Seatbelt/SBPL Gotchas
- `(deny default)` blocks EVERYTHING. You must explicitly allow every operation the process needs.
- `(allow file-read-metadata)` with NO path filter is required globally — without this, `getaddrinfo()` fails and any process that does DNS resolution breaks, even `curl`, `python`, `node`.
- Path escaping: SBPL uses Scheme-style strings. Backslashes and quotes need escaping. Test with paths containing spaces, special chars.
- `sandbox-exec` is invoked as a separate process. You exec into it — you don't fork+apply. The SBPL profile is passed via `-f <file>` (temp file) or `-p <string>` (inline). File is safer for complex profiles.
- sandbox-exec inherits the parent's env vars. Scrub BEFORE spawning.
- The SBPL temp file must survive until the process exits. Don't delete it in a cleanup handler that runs before the child is done.

### fs-diff Gotchas
- `walkdir` can race with the process if the process is still writing when you snapshot. Always wait for child exit BEFORE taking the post-snapshot.
- `.git` directories can be huge. Exclude `.git` from fs-diff paths by default (it's internal state, not user-visible output).
- Symlinks: decide once and document. Recommend: follow symlinks for read, don't follow for diff.

### Replica Mode Gotchas
- Hardlinks only work on the same filesystem. `/tmp` might be a different mount from the workspace. Detect and fall back to copy.
- On macOS APFS, hardlinks to directories are not supported (only files). Use `cp` for directories, hardlink for files.
- `.clawcrateignore` should support the same syntax as `.gitignore` — use an existing crate like `ignore` or `globset` rather than reimplementing.
- The replica temp directory MUST be cleaned up on exit, including on crash. Use a drop guard or `atexit` handler.

---

## Files to Never Modify Carelessly

- `profiles/*.yaml` — These define the default UX. Changes affect first impressions and security defaults.
- `clawcrate-types/src/lib.rs` — Type changes cascade through every crate. Be deliberate.
- `clawcrate-sandbox/darwin.rs` (SBPL generation) — Security-critical. Bugs here = sandbox bypass. Test exhaustively.
- `clawcrate-sandbox/linux.rs` (Landlock + seccomp) — Security-critical. Same.
- `clawcrate-sandbox/env_scrub.rs` — If you miss a pattern, secrets leak. Err on the side of removing too many vars, not too few.

---

## Quick Reference: Running During Development

```bash
# Build everything
cargo build --workspace

# Run all tests
cargo test --workspace

# Run only Linux-specific tests
cargo test --workspace -- --ignored linux  # if you tag Linux tests

# Plan a command (no execution)
cargo run -p clawcrate-cli -- plan --profile build -- echo "hello"

# Run a sandboxed command
cargo run -p clawcrate-cli -- run --profile safe -- echo "hello"

# Run doctor
cargo run -p clawcrate-cli -- doctor

# Run with verbose logging
CLAWCRATE_LOG=debug cargo run -p clawcrate-cli -- run --profile build -- cargo test

# Check artifacts from last run
ls -la ~/.clawcrate/runs/
cat ~/.clawcrate/runs/<latest>/plan.json | jq .
cat ~/.clawcrate/runs/<latest>/audit.ndjson

# Run specific crate tests
cargo test -p clawcrate-types
cargo test -p clawcrate-profiles
cargo test -p clawcrate-sandbox

# Clippy
cargo clippy --workspace -- -D warnings

# Format
cargo fmt --all

# Cross-compile Linux static binary (from macOS or Linux with cross)
cross build --release --target x86_64-unknown-linux-musl
```

---

## Timeline Risk Acknowledgment

This is a 6-week plan with narrow margins. The critical path is weeks 1-4 (types → sandbox backends → runner → replica). Weeks 5-6 (polish + docs) serve as buffer. If sandbox backends slip, polish absorbs the delay.

The main integration risk is SBPL generation for macOS — it can only be validated with real macOS CI runners, the profile language has quirks that only surface with real processes, and path escaping bugs are subtle. Budget extra time for this.
