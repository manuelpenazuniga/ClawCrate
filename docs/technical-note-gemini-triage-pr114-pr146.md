# Technical Note: Gemini Triage for PRs #114-#146

Status (as of 2026-04-26): completed triage log for the review wave covering
PRs `#114` to `#146` (subset: `#114`, `#115`, `#116`, `#118`, `#123`, `#124`,
`#125`, `#126`, `#127`, `#128`, `#129`, `#130`, `#131`, `#132`, `#133`,
`#134`, `#136`, `#137`, `#138`, `#139`, `#140`, `#141`, `#142`, `#143`,
`#144`, `#146`).

## Purpose

Track technical triage for Gemini Code Assist findings across merged PRs
`#114`-`#146` and record disposition per finding.

## Severity Summary

- Security-high/high concentration: process signaling, filtered-mode host
  ambiguity, egress proxy stream correctness, and Linux pre-exec safety/error
  paths.
- Medium concentration: robustness, concurrency behavior, fixture hygiene, and
  documentation consistency.

## Actionable Follow-ups Opened

| Issue | Topic | Intended Path |
|---|---|---|
| `#147` | Darwin SBPL cleanup on spawn failure | Runtime fix |
| `#148` | Prevent process-group broadcast signaling (`kill(-1, ...)`) | Runtime fix |
| `#149` | Close mixed-target filtered-network ambiguity bypass | Runtime fix |
| `#150` | Fix CONNECT buffering/TLS preface loss in egress proxy | Runtime fix |
| `#151` | Enforce RLIMIT hard limits alongside soft limits | Runtime fix |
| `#152` | Preserve Landlock errno before cleanup syscalls | Runtime fix |
| `#153` | Make seccomp `pre_exec` failure path async-signal-safe | Runtime fix |
| `#154` | Restore actual API worker-pool concurrency | Runtime fix |
| `#155` | Always emit structured bridge JSON on stdin read errors | Runtime fix |
| `#156` | Remove TOCTOU in SQLite audit NDJSON reads | Runtime fix |
| `#157` | Security fixture hygiene/dependency behavior | Test hardening |
| `#158` | Verify/complete end-to-end path expansion guarantees | Runtime + docs alignment |
| `#159` | Align docs triage/deferred notes for PR `#82`-`#100` | Docs fix |

## Deferred / Non-Blocking Bucket

Non-critical style/ergonomics suggestions from this wave are tracked in:

- issue `#160` (this triage tracker)
- `docs/technical-note-gemini-deferred-pr114-pr146.md`

## Completion Check

Done criteria from issue `#160`:

- Follow-up issues `#147`-`#159` opened with explicit scope and done criteria.
- Triage and deferred notes committed for PR wave `#114`-`#146`.
