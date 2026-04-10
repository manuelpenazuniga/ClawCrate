# AGENTS.md — ClawCrate context for Codex

This file is a concise, Codex-focused companion to `CLAUDE.md`.

## Primary Sources

- `CLAUDE.md` is the actionable source of truth for implementation.
- `clawcrate-v3.1.1.md` is the full product/spec document.
- `README.md` is external-facing positioning and usage docs.

## Project Summary

ClawCrate is a native sandbox runtime for AI-generated shell commands:

- Linux: Landlock + seccomp (+ rlimits)
- macOS: Seatbelt (`sandbox-exec`) (+ rlimits)
- No Docker, no VMs, no root required

Alpha scope: `run`, `plan`, `doctor`.

## Non-Negotiable Architecture Rules

1. Deny by default.
2. Use platform-native sandboxing only.
3. Command separation is always `clawcrate run -- COMMAND...`.
4. Profiles are the primary UX (`safe`, `build`, `install`, `open`).
5. `install` defaults to `Replica` mode.
6. Artifacts are filesystem-based (no SQLite in alpha).
7. Keep `DefaultMode` (profile intent) separate from `WorkspaceMode` (materialized paths).
8. Linux cannot reliably deny specific files inside an allowed workspace path; use Replica Mode for that.
9. Network in alpha is coarse-grained: `none` or `open` only.
10. ClawCrate sandboxes commands, not the whole agent process.

## Engineering Guardrails

- Keep `clawcrate-types` dependency-free and platform-agnostic.
- Keep all `#[cfg(target_os = ...)]` inside `clawcrate-sandbox`.
- No Tokio in alpha.
- No HTTP client stack in alpha runtime.
- Prefer simple file artifacts per execution:
  - `plan.json`
  - `result.json`
  - `stdout.log`
  - `stderr.log`
  - `audit.ndjson`
  - `fs-diff.json`
