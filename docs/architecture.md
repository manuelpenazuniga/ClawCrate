# ClawCrate Architecture (Alpha)

This document describes the architecture currently implemented in the repository.

## Scope

Alpha command surface:

- `clawcrate plan`
- `clawcrate run`
- `clawcrate doctor`
- `clawcrate api`
- `clawcrate bridge pennyprompt`

Alpha architecture constraints:

- Native platform sandboxing only (Linux + macOS)
- No Docker or VM runtime in the execution path
- File-based artifacts (`plan.json`, `result.json`, logs, `audit.ndjson`, `fs-diff.json`)

## Workspace Layout

```
crates/
├── clawcrate-types      # Shared types and event models
├── clawcrate-profiles   # Profile loading, inheritance, stack auto-detect
├── clawcrate-sandbox    # Linux/macOS backend prep + launch
├── clawcrate-capture    # stdout/stderr capture + fs snapshot/diff
├── clawcrate-audit      # Artifact writer (json + ndjson)
└── clawcrate-cli        # CLI entrypoint and orchestration pipeline
```

Dependency direction is one-way from `clawcrate-cli` down into the leaf crates.

## Execution Pipeline (`run`)

`clawcrate-cli` orchestrates the full pipeline:

1. Parse CLI args and global output options (`--verbose`, `--no-color`, `NO_COLOR`).
2. Resolve profile (`safe`, `build`, `install`, `open`, or custom YAML path).
3. Materialize execution mode:
   - `DefaultMode` (profile intent) + CLI override (`--replica` / `--direct`)
   - into `WorkspaceMode` (`Direct` or `Replica { source, copy }`)
4. Write `plan.json`.
5. If `Replica`, copy workspace to a temp directory with exclusions:
   - defaults: `.env`, `.env.*`, `.git/config`
   - plus `.clawcrateignore` rules
6. Snapshot writable roots.
7. Launch sandbox backend and capture stdout/stderr with output budget.
8. Snapshot writable roots again and compute `fs-diff`.
9. Optionally prompt sync-back for Replica mode:
   - interactive: explicit confirmation
   - `--json`: deterministic no-sync behavior
10. Write final artifacts and print human/JSON summary.

## Planning Pipeline (`plan`)

`plan` runs steps 1-3 of the same resolution flow and emits an `ExecutionPlan`:

- text table (human mode), or
- full JSON object (`--json`).

This keeps plan and run behavior aligned.

## Doctor Pipeline (`doctor`)

`doctor` probes local platform capability signals:

- Linux:
  - kernel version
  - Landlock ABI (files + fallback checks)
  - seccomp availability
  - user namespaces availability
- macOS:
  - `sandbox-exec` presence/executability
  - macOS version (`sw_vers`)
  - kernel version (`uname -r`)

Output is table or JSON.

## Platform Backends

## Linux backend

Current backend path:

- profile/env prep
- launch flow and auditing
- named enforcement stages (`rlimits`, `landlock`, `seccomp`)

Important current state:

- Linux enforcement is active in runtime (`rlimits`, `landlock`, `seccomp`) and applied in launch pre-exec flow.
- Historical note: issue `#69` ("Implement real Linux enforcement") is closed.

## macOS backend

Current backend path:

- generate SBPL profile per execution
- execute command via `/usr/bin/sandbox-exec -f <profile>`
- cleanup temp SBPL profile after execution
- apply filesystem/network policy + sensitive path denies in generated policy

## Artifacts

Each run writes under:

`$HOME/.clawcrate/runs/<execution_id>/`

Files:

- `plan.json`
- `result.json`
- `stdout.log`
- `stderr.log`
- `audit.ndjson`
- `fs-diff.json`

The runtime treats the artifact directory as the source of truth for post-run inspection.

## Recorded Denials

`audit.ndjson` carries a `PermissionBlocked` event for each denial the runtime
can actually observe. What that covers differs by platform, and the difference
is a property of the operating systems rather than of the implementation:

| Denial | Linux | macOS |
| --- | --- | --- |
| Outbound connection refused by the egress proxy (`network: filtered`) | Recorded | Recorded |
| Syscall refused by the sandbox | Recorded | n/a |
| Filesystem read/write refused by the sandbox | **Not recorded** | Recorded, opt-in, **best-effort** |

No row is *complete*, and the word is avoided deliberately. Every record here
collapses repeated attempts into one entry and holds at most 256 distinct ones,
past which it counts what it dropped and writes that count to the trail. Syscall
capture additionally depends on the notification listener being established: if
it cannot be, the filter falls back to returning `EPERM` from the kernel, which
denies exactly as before and records nothing. What the first two rows do
guarantee is that an entry is **exact** — the resource and reason describe a
refusal ClawCrate itself issued, not one inferred from an error.

The egress proxy is ClawCrate's own code, so a refusal is recorded exactly, on
both platforms, at no extra cost. It carries the refused `host:port` and whether
the host missed the allowlist or the TLS SNI disagreed with the CONNECT target.

Linux syscall denials are exact for the same reason. The seccomp filter notifies
ClawCrate instead of returning `EPERM` from the kernel, so a supervisor thread
records the attempt and then returns that same `EPERM` itself. The child cannot
tell the two modes apart. The decision reads the syscall number — an immutable
scalar in the notification — so it carries none of the TOCTOU hazard that makes
user notification unsuitable for path-based policy.

macOS denials are recovered from the unified log, where the kernel writes a
message per sandbox denial. Querying it costs roughly a second per run, so
capture is opt-in via `CLAWCRATE_SEATBELT_VIOLATIONS=1`, alongside the other
enrichment switches (`CLAWCRATE_AUDIT_HASHCHAIN`, `CLAWCRATE_FSDIFF_FULLHASH`).
The log is system-wide, so denials are attributed to a run only on an exact PID
match; `sandbox-exec` execs the target command in place, so the PID ClawCrate
spawned is the one the kernel reports. Denials by processes the sandboxed
command itself spawned carry different PIDs and are not attributed.

**The macOS record is incomplete, and must not be read as an exhaustive list of
what the sandbox blocked.** The kernel does not report every denial: it appears
to apply a per-process reporting budget, so the first denials a process hits are
logged and later ones are frequently dropped. Measured against a sandboxed MCP
server reading a planted secret outside its workspace, the denial of the Node
binary at startup was reported in 5 of 5 runs while the later secret read was
reported in 5 of 8. The read was refused every time — enforcement is not in
question, only the reporting of it. Nothing in ClawCrate can close this gap;
querying later does not help, because the message is never written at all.

The practical consequence: a `PermissionBlocked` entry is evidence that a denial
happened, but its absence is not evidence that none did.

Linux filesystem denials are still not recorded, and this is deliberate.
Landlock surfaces a refusal to the child as `EACCES` and nowhere else; its
kernel audit records need `CAP_AUDIT_READ` and a 6.15+ kernel, which an
unprivileged tool cannot require. Recording them would mean giving up a property
the sandbox has on purpose, which is not a trade ClawCrate makes to improve its
own reporting.

Both denial records are bounded. Past the limit, records are counted rather than
stored, and the count is written to `audit.ndjson` as a
`clawcrate://denial-record-overflow` entry — a truncated trail that reads as
complete would be worse than one that states the gap.

## Current Architectural Notes

- Replica mode is first-class and default for `install`.
- `.clawcrateignore` is interpreted with gitignore-style matching.
- Golden output tests are in place for `plan`, `run`, and `doctor` (text + JSON).
- This document intentionally describes implemented behavior, not planned future behavior.
