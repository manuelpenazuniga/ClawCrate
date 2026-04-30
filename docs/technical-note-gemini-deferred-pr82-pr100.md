# Technical Note: Deferred Gemini Recommendations for PRs #82-#100

Status (as of 2026-04-25): deferred/non-blocking recommendations documented.

## Purpose

Capture Gemini recommendations from PRs `#82`-`#100` that were intentionally
deferred because they are non-critical for the current execution order.

## Scope Source

- Review wave tracked in
  [Issue #112](https://github.com/manuelpenazuniga/ClawCrate/issues/112).
- Deferred bucket tracked in
  [Issue #113](https://github.com/manuelpenazuniga/ClawCrate/issues/113)
  (this note).

## Deferred Recommendations (Non-Blocking)

1. Replica copy micro-optimizations and idiomatic cleanup (for example:
   `target_path` allocation timing, helper signature polish).
2. Test utility refactors and cleanup (for example: `unique_tmp_dir`
   deduplication, selective `tempfile` migration, golden-map ordering cleanup
   where behavior is unchanged).
3. Documentation polish-only cleanups (for example: markdown heading hierarchy
   adjustments and structure-only edits that do not change security/behavioral
   guidance).

## Why Deferred

- Security correctness and behavioral hardening were prioritized first in the
  `#101`-`#111` execution set.
- Deferred items do not currently introduce direct security bypasses in shipped
  behavior.
- Most items are maintainability/style improvements that are safer to batch in
  dedicated cleanup PRs.

## Re-entry Criteria

Deferred items should be resumed when all of the following are true:

1. No open critical-path hardening issue is blocked by the cleanup work.
2. The change set can be isolated as behavior-preserving refactor/polish.
3. CI is green before and after refactor with no output contract drift.

## Recommended Handling

- Batch runtime code cleanups in a dedicated refactor PR with explicit
  "no-behavior-change" scope.
- Batch docs polish in a separate docs-only PR to avoid mixing with runtime
  security changes.
- Keep references to this note from future backlog grooming/status updates.

## Related

- Primary triage note:
  [docs/technical-note-gemini-triage-pr82-pr100.md](technical-note-gemini-triage-pr82-pr100.md)
- Tracking issues:
  [#112](https://github.com/manuelpenazuniga/ClawCrate/issues/112),
  [#113](https://github.com/manuelpenazuniga/ClawCrate/issues/113)
- Existing hardening context:
  [#69](https://github.com/manuelpenazuniga/ClawCrate/issues/69),
  [#75](https://github.com/manuelpenazuniga/ClawCrate/issues/75)
