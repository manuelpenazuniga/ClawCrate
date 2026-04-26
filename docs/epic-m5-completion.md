# Epic Completion: M5 - Alpha Hardening + Release

Status (as of 2026-04-26): ready to close epic `#6`.

## Objective

Polish alpha UX, harden CI, and publish reproducible release artifacts.

## Done Criteria Check

1. CLI polish and golden tests are in place.
- Completed through `#35` (CLI polish) and `#36` (golden tests for
  plan/run/doctor).

2. Linux/macOS CI is green.
- CI matrix and security fixtures established in `#38`.
- Recent merge runs on `main` are green for CI workflow, including commits
  `e8ad2ca` (PR `#143`), `1d62748` (PR `#144`), and `2767738` (PR `#145`).

3. Alpha release artifacts and docs are published.
- Completed through `#39` (release artifacts + checksums) and `#40` (release
  checklist + tag execution).
- Alpha documentation pack completed in `#37`.

## Milestone Traceability (M5)

Closed milestone issues:

- `#35` Polish CLI errors, --verbose, and NO_COLOR support
- `#36` Add golden tests for plan, run, doctor
- `#37` Complete alpha docs pack
- `#38` Add Linux/macOS CI matrix with security fixtures
- `#39` Implement release artifacts + install script + checksums
- `#40` Execute alpha release checklist and tag release

Additional alpha documentation hardening after milestone delivery:

- `#81` Technical Note: Gemini review triage for merged PRs #57-#74
- `#110` Docs: tighten egress proxy threat model for DNS leakage, audit integrity, and HTTP flow
- `#111` Docs: keep WSL2 guidance fail-safe until Linux enforcement (#69) is implemented

## Notes

- This document is a closure artifact for epic `#6` and is intentionally scoped
  to completion evidence only.
