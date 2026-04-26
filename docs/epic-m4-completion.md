# Epic Completion: M4 - Replica Mode

Status (as of 2026-04-26): ready to close epic `#5`.

## Objective

Ship secure replica workflows, including exclusions and explicit sync-back.

## Done Criteria Check

1. Install profile defaults to replica.
- Completed through `#34` with integration coverage, supported by mode
  materialization work in `#32`.

2. `.env*` and secret files are excluded from copy.
- Completed through `#30` and `.clawcrateignore` matching support in `#31`.
- Post-delivery exclusion hardening completed in `#75`.

3. Sync-back requires explicit confirmation.
- Completed through `#33` with interactive/non-interactive sync-back flow.
- Post-delivery sync safety hardening completed in `#106`.

## Milestone Traceability (M4)

Closed milestone issues:

- `#30` Implement replica copy engine with default exclusions
- `#31` Implement .clawcrateignore parser and matching
- `#32` Materialize DefaultMode -> WorkspaceMode in CLI
- `#33` Implement sync-back confirmation flow (--json non-interactive)
- `#34` Add integration tests for install defaulting to replica

Additional hardening closures applied after initial milestone delivery:

- `#75` Harden replica exclusions for nested .git/config and align audit metadata
- `#106` Harden replica sync-back interaction safety and delete semantics

## Notes

- This document is a closure artifact for epic `#5` and is intentionally scoped
  to completion evidence only.
