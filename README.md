<p align="center">
  <h1 align="center">ClawCrate</h1>
  <p align="center"><strong>Secure execution for AI agents.</strong></p>
  <p align="center">
    Your agent runs free. Your secrets stay locked.
  </p>
</p>

<p align="center">
  <a href="#quickstart">Quickstart</a> •
  <a href="#why">Why</a> •
  <a href="#how-it-works">How It Works</a> •
  <a href="#profiles">Profiles</a> •
  <a href="#replica-mode">Replica Mode</a> •
  <a href="#cli-reference">CLI</a> •
  <a href="#architecture">Architecture</a> •
  <a href="#contributing">Contributing</a>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/language-Rust-orange?style=flat-square" />
  <img src="https://img.shields.io/badge/platforms-Linux%20%7C%20macOS-blue?style=flat-square" />
  <img src="https://img.shields.io/badge/license-MIT-green?style=flat-square" />
  <img src="https://img.shields.io/badge/status-alpha-yellow?style=flat-square" />
</p>

---

Your AI agent just ran `npm install` on a repo with a malicious postinstall script. That script read `~/.ssh/id_rsa`, `~/.aws/credentials`, and every `.env` file in your project. It POST'd everything to a server in Eastern Europe. You didn't know until someone used your AWS keys to spin up $14,000 in GPU instances.

**ClawCrate is a single Rust binary that sandboxes every command your AI agent executes.** Native kernel-level isolation on both Linux (Landlock + seccomp) and macOS (Seatbelt). No Docker. No VMs. No root. Overhead you can't measure.

```
Agent says: "run npm test"
    │
    ▼
clawcrate run --profile build -- npm test
    │
    ├── Sandbox applied (kernel-level, irremovible)
    ├── ~/.ssh, ~/.aws, Keychain → blocked
    ├── Env vars scrubbed (AWS_SECRET_ACCESS_KEY → gone)
    ├── Filesystem: read project, write only target/
    ├── Network: blocked
    │
    ▼
npm test runs normally. Your secrets never left the vault.
```

## Quickstart

```bash
# Install (macOS)
curl -fsSL https://raw.githubusercontent.com/manuelpenazuniga/ClawCrate/main/scripts/install.sh | sh

# Install (Linux)
curl -fsSL https://raw.githubusercontent.com/manuelpenazuniga/ClawCrate/main/scripts/install.sh | sh

# Run your first sandboxed command
clawcrate run --profile safe -- echo "hello from the sandbox"

# See what would happen without executing
clawcrate plan --profile build -- cargo test

# Check your system's sandboxing capabilities
clawcrate doctor
```

Your first sandboxed execution in under 60 seconds.

## Why

68.5% of OpenClaw users are on macOS. The rest are on Linux. All of them run AI agents that execute shell commands with full access to their machine.

Every `npm install`, `pip install`, `cargo build`, or `git clone` your agent runs inherits **all your permissions**. Your SSH keys, your AWS credentials, your API tokens, your browser cookies, your Keychain. If a dependency has a malicious postinstall script, or if the agent hallucinates a plausible-sounding package name that turns out to be malware — the damage is complete.

ClawCrate exists because:

- **Agents shouldn't decide their own limits.** The sandbox is external, kernel-enforced, inherited by all child processes, and impossible to remove from inside.
- **Filesystem isolation isn't enough.** Environment variables leak secrets too. ClawCrate scrubs `AWS_SECRET_ACCESS_KEY`, `GITHUB_TOKEN`, `SSH_AUTH_SOCK`, and dozens more — before the process even starts.
- **Docker is too heavy for this.** 500ms-2s startup, hundreds of MB, daemon dependency. ClawCrate adds <5ms.
- **macOS matters.** Two-thirds of the market. ClawCrate uses native Apple Silicon sandboxing — no VMs, no emulation, no performance loss.

### What ClawCrate is NOT

- **Not an agent.** It doesn't make decisions, rewrite prompts, or talk to LLMs.
- **Not a container runtime.** No images, no layers, no daemon.
- **Not a replacement for VMs.** If you need kernel-level isolation against kernel exploits, use a VM. ClawCrate is defense-in-depth at the process level.
- **Not magic.** If your agent has legitimate network access and legitimate credentials for an allowed domain, ClawCrate can't prevent misuse of that access.

## How It Works

```
clawcrate run --profile build -- cargo test --release
    │
    ├─ 1. RESOLVE PROFILE
    │     Profile "build" → read workspace + toolchain,
    │     write target/, network blocked, env scrubbed
    │
    ├─ 2. PLAN
    │     Generate execution plan with permissions granted/denied
    │     (visible via `clawcrate plan`)
    │
    ├─ 3. MATERIALIZE WORKSPACE
    │     Direct mode: run in-place
    │     Replica mode: copy workspace excluding .env, secrets
    │
    ├─ 4. SCRUB ENVIRONMENT
    │     Remove AWS_*, GITHUB_TOKEN, SSH_AUTH_SOCK, *_SECRET*, ...
    │
    ├─ 5. APPLY SANDBOX (kernel-level)
    │     Linux: Landlock (filesystem) + seccomp-bpf (syscalls) + rlimits
    │     macOS: Seatbelt SBPL profile (filesystem + network + process)
    │     → Irremovible. Inherited by all child processes.
    │
    ├─ 6. LAUNCH
    │     Linux: fork → apply sandbox in-process → exec
    │     macOS: exec via sandbox-exec with generated SBPL
    │
    ├─ 7. CAPTURE
    │     stdout/stderr piped to logs
    │     fs-diff: snapshot before vs after
    │
    └─ 8. ARTIFACTS
          ~/.clawcrate/runs/exec_{id}/
          ├── plan.json, result.json
          ├── stdout.log, stderr.log
          ├── audit.ndjson, fs-diff.json
```

## Profiles

ClawCrate ships four built-in profiles. No YAML required.

| Profile | Filesystem | Network | Env | Workspace Mode | Use Case |
|---------|-----------|---------|-----|---------------|----------|
| **safe** | Read: workspace | Blocked | Scrubbed | Direct | Tests (read-only), linting, analysis |
| **build** | Read: workspace + toolchain. Write: output dirs | Blocked | Scrubbed | Direct | Compilation, tests, coverage |
| **install** | Read: workspace. Write: dependency dirs | Open (with warning) | Scrubbed | **Replica (default)** | npm install, pip install, cargo fetch |
| **open** | Read/Write: workspace | Open | Partially scrubbed | Direct | General-purpose scripts |

```bash
# Safe: read-only, no network
clawcrate run --profile safe -- pytest -q

# Build: write to target/, no network
clawcrate run --profile build -- cargo test --release

# Install: network enabled, replica mode automatic
clawcrate run --profile install -- npm install express

# Open: full workspace access, network enabled
clawcrate run --profile open -- ./deploy.sh
```

> **`install` uses Replica Mode by default** because it's the highest-risk profile: postinstall scripts with network access. Use `--direct` to opt out (not recommended).

### Custom Profiles (YAML)

```yaml
# .clawcrate/custom.yaml
name: my-project
extends: build
filesystem:
  write: ["./custom-output"]
  deny: [".env", ".env.local"]   # macOS only (Seatbelt regex)
environment:
  passthrough: ["MY_CUSTOM_VAR"]
resources:
  max_cpu_seconds: 300
  max_memory_mb: 4096
```

```bash
clawcrate run --profile .clawcrate/custom.yaml -- make build
```

## Replica Mode

The most dangerous commands are the ones that need both write access and network access. `npm install` is the poster child: postinstall scripts can read your `.env` files and exfiltrate them.

**Replica Mode** creates a filtered copy of your workspace, runs the command there, and syncs changes back only with your explicit confirmation.

```bash
# install uses replica automatically
clawcrate run --profile install -- npm install express

# force replica on any profile
clawcrate run --replica --profile build -- cargo test

# force direct on install (you accept the risk)
clawcrate run --direct --profile install -- npm install
```

Replica copy exclusions: default `.env`, `.env.*`, `.git/config`, plus any rules in `.clawcrateignore`.

Mode precedence is explicit: `--replica` / `--direct` flags override the profile default mode. Without flags, the profile default applies (`install` => Replica, most others => Direct).

**Syncing changes back always requires explicit confirmation in interactive mode.**
When `--json` is enabled, sync-back is deterministically skipped (non-interactive behavior).

## CLI Reference

```
clawcrate [--verbose] [--no-color] run [--profile PROFILE] [--replica | --direct] [--approve-out-of-profile] -- COMMAND...
clawcrate [--verbose] [--no-color] plan [--profile PROFILE] [--replica | --direct] -- COMMAND...
clawcrate [--verbose] [--no-color] doctor
clawcrate [--verbose] [--no-color] api [--bind ADDR] [--token TOKEN]
clawcrate [--verbose] [--no-color] bridge pennyprompt [--pretty]
```

| Flag | Effect |
|------|--------|
| `--profile <name>` | Use built-in profile (safe, build, install, open) or path to YAML |
| `--replica` | Force Replica Mode (for profiles that default to Direct) |
| `--direct` | Force Direct Mode (for profiles that default to Replica) |
| `--approve-out-of-profile` | Bypass approval prompt for detected permission requests outside active profile |
| `--json` | Machine-readable output (for agent integration) |
| `--verbose` / `-v` | Show detailed diagnostic logs (error chain, execution stages) |
| `--no-color` | Disable ANSI colors in human-readable output |
| `api --bind <addr>` | Start local HTTP API (default `127.0.0.1:8787`) |
| `api --token <token>` | Set bearer token for API auth (or use `CLAWCRATE_API_TOKEN`) |
| `bridge pennyprompt` | One-shot JSON adapter for PennyPrompt shell dispatch |

`clawcrate run` forwards `SIGINT`/`SIGTERM` to the sandboxed child and still writes final artifacts (`result.json`, logs, `fs-diff.json`) before exit. It also enforces a runtime timeout based on profile `resources.max_cpu_seconds`.

Set `NO_COLOR=1` to disable ANSI colors via environment variable.

## Architecture

### Dual-Platform Native Sandboxing

| | Linux | macOS |
|---|-------|-------|
| **Mechanism** | Landlock LSM + seccomp-bpf | Seatbelt (sandbox-exec) |
| **Filesystem** | Path-hierarchy deny | Path + regex deny (intra-workspace) |
| **Syscalls** | seccomp-bpf per-syscall filtering | Seatbelt operation categories |
| **Network** | Blocked by default | Blocked by default |
| **Resources** | rlimits | rlimits |
| **Root required** | No (kernel 5.13+) | No |
| **Irremovible** | Yes | Yes |
| **Performance** | Native | Native (Apple Silicon, no VM) |

### Crate Structure

```
crates/
├── clawcrate-types/       Shared types, enums, errors
├── clawcrate-profiles/    Profile engine, presets, auto-detection
├── clawcrate-sandbox/     SandboxBackend trait + platform implementations
│   ├── linux.rs           Landlock + seccomp + rlimits
│   ├── darwin.rs          Seatbelt SBPL generator
│   ├── env_scrub.rs       Cross-platform env scrubbing
│   └── doctor.rs          System capability detection
├── clawcrate-capture/     stdout/stderr capture, fs-diff (snapshot pre/post)
├── clawcrate-audit/       Artifact generation (ndjson)
└── clawcrate-cli/         Clap CLI entry point
```

### Artifacts

Every execution generates a directory:

```
~/.clawcrate/runs/exec_a1b2c3/
├── plan.json       What was permitted and denied
├── result.json     Exit code, duration, status
├── stdout.log      Complete stdout
├── stderr.log      Complete stderr
├── audit.ndjson    Every sandbox decision, one JSON line per event
└── fs-diff.json    Files created, modified, deleted
```

## Compatibility

ClawCrate works with any agent that executes shell commands:

| Agent | Integration |
|-------|------------|
| OpenClaw | Wrap tool calls: `clawcrate run --profile build -- <command>` |
| Claude Code | Use as execution layer for shell tools |
| Codex (OpenAI) | Wrap in CI or local dev |
| Cursor | Wrap terminal commands |
| Gemini CLI | Same pattern |
| Any CLI agent | `clawcrate run --profile safe -- <anything>` |

ClawCrate integrates at the boundary where the agent delegates shell command execution — it doesn't wrap the agent itself.

## System Requirements

| Platform | Minimum | Recommended |
|----------|---------|-------------|
| **Linux** | Kernel 5.13+ (Landlock v1) | Kernel 6.7+ (Landlock v4, network control) |
| **macOS** | macOS 12+ (Monterey) | macOS 14+ (Sonoma) |

Run `clawcrate doctor` to check your system's capabilities.

## Roadmap

- [x] Project specification (v3.1.1)
- [ ] **Alpha** — `run`, `plan`, `doctor`, `api`, `bridge pennyprompt`. Profiles. Dual-platform sandbox. Replica mode. Artifacts.
- [ ] **P1** — Egress proxy (network filtering by domain). Approval workflow. Community profiles.
- [ ] **P2** — SQLite audit storage. API/bridge hardening and expanded integration contracts.
- [ ] **v1.0** — Production hardening. Windows (WSL2). Plugin system.

## Contributing

ClawCrate is MIT licensed. Contributions welcome.

```bash
git clone https://github.com/anthropic-ai/clawcrate.git
cd clawcrate
cargo build --workspace
cargo test --workspace
cargo clippy --workspace -- -D warnings
```

See [CLAUDE.md](CLAUDE.md) for the complete development guide with architecture decisions, coding standards, and step-by-step build instructions.
See [docs/WORKFLOW.md](docs/WORKFLOW.md) for the operational issue-to-PR workflow used in this repository.
See [CHANGELOG.md](CHANGELOG.md) for release notes and version history.
See [docs/release-checklist.md](docs/release-checklist.md) for the alpha release and tagging runbook.
See [docs/egress-proxy-threat-model.md](docs/egress-proxy-threat-model.md) for the post-alpha network-filtering design baseline.
See [docs/community-profiles.md](docs/community-profiles.md) for the community profile catalog schema and contribution workflow.
See [docs/wsl2-compatibility.md](docs/wsl2-compatibility.md) for the current WSL2 compatibility constraints report.
See [docs/architecture.md](docs/architecture.md), [docs/profiles-reference.md](docs/profiles-reference.md), [docs/kernel-requirements.md](docs/kernel-requirements.md), and [docs/integration-guide.md](docs/integration-guide.md) for the alpha technical docs pack.

## License

MIT — see [LICENSE](LICENSE).

---

<p align="center">
  <strong>Your agent runs free. Your secrets stay locked.</strong>
</p>
