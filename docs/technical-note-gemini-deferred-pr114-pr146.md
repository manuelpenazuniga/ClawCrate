# Technical Note: Deferred Gemini Recommendations for PRs #114-#146

Status (as of 2026-04-26): deferred/non-blocking recommendations documented.

## Purpose

Capture Gemini recommendations from PRs `#114`-`#146` that are intentionally
deferred because they are non-critical for the current execution order.

## Scope Source

- Review wave tracked in `#160`.
- Primary triage note:
  `docs/technical-note-gemini-triage-pr114-pr146.md`.

## Deferred Recommendations (Non-Blocking)

1. Idiomatic/refactor-only cleanups with no behavior change.
- Examples: replacing manual `match` with `?` when results are precomputed
  (PR `#140`), small trim/clone simplifications (PRs `#129`, `#133`), and
  in-place vector updates for path normalization internals (PR `#116`).

2. Documentation style and markdown consistency polish.
- Examples: heading capitalization and inline formatting consistency (PRs
  `#142`, `#143`, `#144`, `#146`), nested list indentation and relative-link
  polish (PR `#139`) where security/behavior guidance remains unchanged.

3. Low-risk readability wording improvements in threat-model text.
- Examples: authority-extraction terminology clarity and data-model wording
  consistency in egress proxy docs (PR `#136`).

## Why Deferred

- Security correctness and behavioral hardening work was prioritized first via
  issues `#147`-`#158`.
- Deferred items do not currently introduce direct security bypasses in shipped
  behavior.
- Batchable no-behavior-change cleanup is safer when separated from runtime
  hardening.

## Re-entry Criteria

Deferred items should be resumed when all of the following are true:

1. No open critical-path hardening issue is blocked by polish/refactor work.
2. The change set can be isolated as behavior-preserving cleanup.
3. CI is green before and after cleanup with no output contract drift.

## Related

- Triage tracker issue: `#160`
- Open hardening issues from this wave: `#147`-`#159`
