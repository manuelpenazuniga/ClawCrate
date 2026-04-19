# WSL2 Compatibility Spike (P3-01)

This note captures the current compatibility assessment for running ClawCrate under WSL2.

Status: post-alpha exploratory guidance. WSL2 is not part of current alpha support guarantees.

## Scope

This spike focuses on:

- Landlock/seccomp capability behavior in WSL2 Linux kernels.
- Practical constraints and safe operating guidance.
- Explicit unsupported or not-yet-validated areas.

Related issues:

- `#48` (this spike and constraints report)
- `#49` (WSL2 CI lane + baseline validation)
- `#69` (real Linux enforcement implementation gap)

## Assessment Method

Use `clawcrate doctor --json` inside WSL2 and gate behavior from reported capabilities:

- `landlock_abi`
- `seccomp_available`
- `user_namespaces`
- `kernel_version`

Example:

```bash
clawcrate doctor --json | jq .
```

## Capability Expectations in WSL2

WSL2 behavior varies by Windows version and WSL kernel build. Do not assume parity with native Linux.

### Landlock

- May be unavailable or partially available depending on kernel configuration.
- If `landlock_abi` is `null`, treat path-level Linux restrictions as unavailable.

### seccomp

- Often available, but still kernel/config dependent.
- If `seccomp_available` is `false`, syscall filtering guarantees are unavailable.

### user namespaces

- May be restricted by host policy.
- Treat as informational for now; not a standalone security guarantee.

## Current Risk Interpretation

Even when capabilities appear available in WSL2, current repo state must be considered:

- Linux enforcement internals are still tracked as active work in `#69`.
- WSL2 now has a dedicated CI execution path (`.github/workflows/wsl2-ci.yml`), currently configured as non-blocking while support is still experimental.

Result: WSL2 should be treated as experimental until real Linux enforcement (`#69`) and stable WSL2 CI confidence are both in place.

## Recommended Operational Policy (Current)

1. Run `clawcrate doctor --json` at startup and gate execution policy.
2. If `landlock_abi == null` or `seccomp_available == false`, restrict usage to lower-risk flows:
   - prefer `plan` over `run` for untrusted inputs
   - prefer `safe`/`build` with minimal write scope
   - use Replica mode for higher-risk operations
3. For strict security boundaries, prefer native Linux or VM isolation until WSL2 baseline is CI-validated.

## Known Unsupported / Not Yet Validated

- No formal support claim for production WSL2 security posture at this stage.
- Capability parity across Windows releases and custom WSL kernels is not guaranteed.

## Minimum Supported Behavior Baseline (Current)

Current WSL2 baseline is defined by the `WSL2 Compatibility` workflow:

1. WSL environment starts on `windows-latest` runner.
2. Rust toolchain installs inside WSL user space.
3. Workspace passes:
   - `cargo fmt --all -- --check`
   - `cargo clippy --workspace --all-targets -- -D warnings`
   - `cargo test --workspace`
4. `clawcrate doctor --json` runs in WSL2 and uploads `wsl2-doctor.json` artifact.

This lane is intentionally non-blocking right now (`continue-on-error: true`) to collect stability data while support remains experimental.
