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

- Enforcement steps are wired but currently no-op in `KernelEnforcer`.
- Tracked as technical gap in issue `#69` ("Implement real Linux enforcement").

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

## Current Architectural Notes

- Replica mode is first-class and default for `install`.
- `.clawcrateignore` is interpreted with gitignore-style matching.
- Golden output tests are in place for `plan`, `run`, and `doctor` (text + JSON).
- This document intentionally describes implemented behavior, not planned future behavior.
