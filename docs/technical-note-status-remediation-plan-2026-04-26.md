# Technical Note: Status Remediation Plan (2026-04-26)

## Purpose
Define an executable, priority-ordered plan to close all actionable gaps identified in `docs/status-2026-04-25.md`, with explicit issue mapping, dependency order, and release-closure criteria.

Issue reference: #172  
Program tracker: #171

## Scope
This plan covers:
- Security/runtime blockers
- Release/tag publication blockers
- Product scope/documentation consistency
- Release operations hardening
- Remaining hardening backlog from Gemini triage

This plan does not add new product scope beyond what is required to ship a coherent alpha release.

## Backlog Map
### P0 (Critical Path)
- #150 Fix egress proxy CONNECT buffering to avoid TLS preface loss
- #153 Make Linux seccomp pre_exec failure path async-signal-safe
- #165 Publish formal v0.1.0-alpha.0 tag and GitHub release assets
- #166 Reconcile alpha scope contract with exposed CLI surface (api/bridge)
- #171 Epic tracker for this remediation program

### P1 (Must close in same wave or explicitly defer with rationale)
- #151 Enforce RLIMIT hard limits alongside soft limits
- #152 Capture Landlock errno before cleanup to preserve failure provenance
- #154 Restore API worker pool concurrency
- #155 Always emit structured PennyPrompt bridge JSON on stdin read failures
- #156 Remove TOCTOU in SQLite audit NDJSON artifact reads
- #158 Verify and complete end-to-end profile path expansion
- #167 Docs sweep for stale #69 references + roadmap/status alignment
- #168 Refresh CLAUDE.md dependency/runtime notes
- #169 Add release preflight guardrails
- #170 Add install.sh smoke tests in CI
- #172 Publish this technical plan

### P2 (Close after P0/P1 if time allows)
- #157 Harden Linux security fixtures
- #159 Docs cleanup for Gemini notes (#82-#100)

## Dependency Graph (Execution Constraints)
1. Security correctness first:
   - `#150` and `#153` must complete before release cut.
2. Product contract before release notes:
   - `#166` must be decided before `#165` so release narrative is consistent.
3. Documentation consistency before publication:
   - `#167` and `#168` must complete before final release notes freeze.
4. Operational guardrails before repeated release attempts:
   - `#169` should land before final release cut command.
5. Installer confidence:
   - `#170` can run in parallel but must be green before public announcement.

## Detailed Execution Plan (Today)
### Phase A: Stabilize Runtime Blockers
Target issues: `#150`, `#153`

Checklist:
- Reproduce failing or risky paths locally.
- Implement minimal, test-backed fixes.
- Run `cargo fmt --check`, `cargo clippy --all-targets -- -D warnings`, targeted + workspace tests.
- Open PRs with `Closes #...`.
- Wait for CI green and merge.

Exit criteria:
- Both issues merged into `main`.
- No failing CI lanes on their merge commits.

### Phase B: Lock Scope Contract and Docs
Target issues: `#166`, `#167`, `#168`

Checklist:
- Decide one explicit alpha contract:
  - Option A: feature-gate `api` and `bridge`.
  - Option B: formally include `api` and `bridge` in alpha narrative.
- Update docs to remove stale references to open `#69`.
- Align dependency/runtime statements in `CLAUDE.md`.
- Validate docs consistency against current `main`.

Exit criteria:
- Single, non-contradictory alpha definition in repo docs.
- No stale references implying Linux enforcement is still pending.

### Phase C: Release Guardrails and Smoke
Target issues: `#169`, `#170`

Checklist:
- Add/adjust release preflight checks:
  - dirty tree detection
  - untracked file guard
  - required artifact preconditions
- Add installer smoke verification lane for Linux and macOS.
- Ensure guardrail failure messages are actionable.

Exit criteria:
- Release path fails fast on invalid state.
- Installer smoke path is reproducible and green.

### Phase D: Publish Alpha Release
Target issue: `#165`

Checklist:
- Ensure `main` is up-to-date and clean.
- Confirm P0 and required P1 docs/ops blockers are merged.
- Execute release runbook command:
  - `bash scripts/cut_release.sh --tag v0.1.0-alpha.0 --push`
- Verify:
  - tag exists on origin
  - GitHub release exists with expected assets
  - `scripts/install.sh` works against published release

Exit criteria:
- Release is publicly consumable end-to-end.
- Announcement-ready state reached.

### Phase E: Complete Remaining Hardening Wave
Target issues: `#151`, `#152`, `#154`, `#155`, `#156`, `#158`, then `#157`, `#159`

Checklist:
- Process in priority order with one issue per branch/PR.
- Keep PRs narrow and test-backed.
- Merge continuously to avoid large integration risk.

Exit criteria:
- All open remediation issues closed, or explicit defer notes documented.

## Branch and PR Conventions
- Branch naming: `issue/<id>-<short-slug>`
- Commit style: Conventional Commits (`fix:`, `docs:`, `refactor:`, `test:`, `chore:`)
- PR requirements:
  - clear summary
  - validation section
  - `Closes #<issue>`

## Risk Register (Execution)
- Release drift risk:
  - Mitigation: do not start new feature scope until `#165` is done.
- CI flake risk:
  - Mitigation: rerun with targeted logs and stabilize tests before merge.
- Documentation regression risk:
  - Mitigation: do a final grep sweep for stale references before release cut.
- Operational error risk during cut:
  - Mitigation: enforce `#169` preflight checks and smoke script first.

## Progress Tracking Protocol
- Use `#171` as single source of truth for checklist status.
- After each merge:
  - mark linked issue closed
  - sync `main`
  - update next issue owner/sequence
- If any item must be deferred:
  - create short rationale comment in `#171`
  - include impact and next target date

## Definition of Program Done
- `#150`, `#153`, `#165`, `#166` closed.
- `#167`, `#168`, `#169`, `#170`, `#172` closed.
- Remaining hardening issues from this wave either closed or explicitly deferred with rationale:
  - `#151`, `#152`, `#154`, `#155`, `#156`, `#157`, `#158`, `#159`.
- `#171` checklist complete and closed.
