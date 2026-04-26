# Epic Completion: M2 - Sandbox Backends

Status (as of 2026-04-26): ready to close epic `#3`.

## Objective

Implement native Linux and macOS sandbox backends with capability diagnostics.

## Done Criteria Check

1. Linux backend enforces Landlock + seccomp policy.
- Completed through `#20`, hardening follow-ups `#119`, `#120`, `#121`, and
  enforcement closure `#69`.

2. macOS backend enforces Seatbelt profile.
- Completed through `#22` with supporting probe and validation in `#21` and
  security fixtures in `#24`.

3. `clawcrate doctor` reports capabilities clearly.
- Completed in `#23` with Linux/macOS capability probe wiring and diagnostics.

## Milestone Traceability (M2)

Closed milestone issues:

- `#19` Implement Linux capability probe (Landlock/seccomp/kernel)
- `#20` Implement Linux sandbox prepare + launch pipeline
- `#21` Implement macOS capability probe (sandbox-exec, OS version)
- `#22` Implement macOS SBPL generation + launch pipeline
- `#23` Implement clawcrate doctor command wiring
- `#24` Add security fixtures for both platforms
- `#69` Implement real Linux enforcement (rlimits + Landlock + seccomp)
- `#119` Linux enforcement: apply real rlimits in child pre-exec path
- `#120` Linux enforcement: implement Landlock ruleset materialization and restrict-self
- `#121` Linux enforcement: implement seccomp filter loading with fail-closed behavior
- `#122` Linux enforcement: add runtime fixtures validating effective deny behavior

## Notes

- This document is a closure artifact for epic `#3` and is intentionally scoped
  to completion evidence only.
