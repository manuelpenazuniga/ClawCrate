# Integration Guide (Alpha)

This guide shows how to integrate ClawCrate as the execution boundary for agent/tooling workflows.

## Core Integration Rule

Always invoke commands with argument separation:

```bash
clawcrate run --profile <profile> -- <command> <arg1> <arg2>
```

Do not pass a shell command string unless you explicitly need shell features.

## Common Patterns

## Plan before execution

```bash
clawcrate plan --profile build --json -- cargo test
```

Use this to inspect mode, cwd, and profile policy without running the command.

## Run with machine-readable output

```bash
clawcrate run --profile safe --json -- cargo test
```

The JSON summary includes:

- `result.status`
- `result.exit_code`
- `result.artifacts_dir`
- capture metadata (`stdout_log`, `stderr_log`, truncation counters)

## Local API Surface (P2)

For tool-to-tool integrations, you can run an authenticated local API:

```bash
export CLAWCRATE_API_TOKEN="change-me"
clawcrate api --bind 127.0.0.1:8787
```

Supported endpoints:

- `GET /v1/health`
- `GET /v1/doctor`
- `POST /v1/plan`
- `POST /v1/run`

`POST` payload schema:

```json
{
  "profile": "build",
  "replica": false,
  "direct": false,
  "approve_out_of_profile": false,
  "command": ["cargo", "test"]
}
```

Authentication:

- header `Authorization: Bearer <token>`
- token source: `--token` or `CLAWCRATE_API_TOKEN`

## PennyPrompt Bridge (P2)

For one-shot shell dispatch integration, use:

```bash
echo '{"action":"run","profile":"build","command":["cargo","test"]}' | clawcrate bridge pennyprompt
```

Bridge input JSON:

```json
{
  "action": "run",
  "profile": "build",
  "replica": false,
  "direct": false,
  "approve_out_of_profile": false,
  "command": ["cargo", "test"]
}
```

Supported `action` values:

- `run`
- `plan`
- `doctor`

Bridge output is JSON with:

- `ok` (boolean)
- `action`
- `data` (delegated ClawCrate JSON payload on success)
- `error` (structured failure details when delegated command fails)

## Collect artifacts

Given `result.artifacts_dir`, consume:

- `plan.json`
- `result.json`
- `audit.ndjson`
- `fs-diff.json`
- `stdout.log`
- `stderr.log`

This keeps integrations deterministic and auditable.

## Profile Selection Strategy

Recommended default profile mapping:

- read-only/static checks: `safe`
- build/test workflows: `build`
- dependency install flows: `install`
- trusted unrestricted workspace tasks: `open`

`install` defaults to Replica mode by design.

## Replica Mode Integration Notes

- Interactive human mode: may prompt for sync-back confirmation.
- `--json` mode: sync-back is always skipped (deterministic non-interactive behavior).

For automation, use `--json` to avoid prompts.

## Verbosity and Color

Global flags:

- `-v` / `--verbose`: include diagnostic logs (stderr)
- `--no-color`: disable ANSI color in human output

Environment:

- `NO_COLOR=1` also disables ANSI color

## Error Handling Recommendations

If `clawcrate` exits non-zero:

1. Parse stderr for `error: ...` and optional hints.
2. Re-run with `--verbose` when deeper cause chain is needed.
3. If a run started, inspect `result.json` and `audit.ndjson` in artifacts.

## Wrapper Example (Shell Function)

```bash
cc_run() {
  local profile="$1"
  shift
  clawcrate run --profile "$profile" --json -- "$@"
}

# usage
cc_run build cargo test --release
```

## CI/Automation Example

```bash
set -euo pipefail

summary="$(clawcrate run --profile build --json -- cargo test)"
status="$(printf '%s' "$summary" | jq -r '.result.status')"

if [ "$status" != "Success" ]; then
  echo "clawcrate run failed with status=$status" >&2
  exit 1
fi
```

## Current Alpha Caveats

- Linux full kernel enforcement is tracked as ongoing work (issue `#69`).
- macOS and Linux differ in backend internals; keep your integration backend-agnostic by consuming `result` + artifacts.
- WSL2 is currently experimental/post-alpha; see [WSL2 compatibility spike](wsl2-compatibility.md).

## Post-Alpha Filtered Network Mode (P1)

Custom profiles can now express domain allowlist network policy:

```yaml
network:
  mode: filtered
  allowed_domains:
    - "registry.npmjs.org"
    - "*.pkg.dev"
```

In filtered mode, ClawCrate starts a local egress proxy and injects proxy env vars
(`HTTP_PROXY`, `HTTPS_PROXY`, `ALL_PROXY`) for the sandboxed command.

## Approval Workflow for Out-of-Profile Requests (P1)

When a command appears to request permissions outside the active profile,
`clawcrate run` now requires explicit approval.

- interactive mode: prompt (`Approve and continue? [y/N]`)
- non-interactive / `--json`: fail-closed by default
- automation override: `--approve-out-of-profile`

## Optional SQLite Audit Index (P2)

File artifacts remain the primary source of truth (`plan.json`, `result.json`, `audit.ndjson`).
For query-oriented integrations, you can enable optional SQLite indexing:

```bash
CLAWCRATE_AUDIT_SQLITE=1 clawcrate run --profile build --json -- cargo test
```

Optional custom path:

```bash
CLAWCRATE_AUDIT_SQLITE_PATH=/tmp/clawcrate-audit.db clawcrate run --profile safe --json -- echo ok
```

When enabled, ClawCrate upserts run metadata and audit events into SQLite after each run,
without changing artifact generation behavior.
