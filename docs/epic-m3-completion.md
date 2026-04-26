# Epic Completion: M3 - Run + Capture + Audit

Status (as of 2026-04-26): ready to close epic `#4`.

## Objective

Deliver end-to-end command execution with logs, fs-diff, and artifacts.

## Done Criteria Check

1. `clawcrate run` executes with sandbox applied.
- Completed through `#28` with sandbox launch wiring integrated in the run
  execution path.

2. stdout/stderr and fs-diff are captured.
- Completed through `#25` (stream capture) and `#26` (snapshot + diff engine).
- Post-delivery hardening for runtime/capture edge cases completed in `#79` and
  `#80`.

3. All artifact files are emitted per execution.
- Completed through `#27` with required artifacts:
  `plan.json`, `result.json`, `stdout.log`, `stderr.log`, `audit.ndjson`, and
  `fs-diff.json`.

## Milestone Traceability (M3)

Closed milestone issues:

- `#25` Implement stdout/stderr capture with output limits
- `#26` Implement filesystem snapshot and diff engine
- `#27` Implement artifact writer (plan.json, result.json, audit.ndjson, fs-diff.json)
- `#28` Implement clawcrate run end-to-end pipeline
- `#29` Add signal handling and timeout behavior

Additional hardening closures applied after initial milestone delivery:

- `#79` Harden run interruption escalation and capture join edge cases
- `#80` Strengthen capture failure-path cleanup (thread join + child reap guarantees)

## Notes

- This document is a closure artifact for epic `#4` and is intentionally scoped
  to completion evidence only.
