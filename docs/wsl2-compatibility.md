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
- WSL2 has no dedicated CI lane yet (`#49`), so regressions are harder to detect.

Result: WSL2 should be treated as experimental until both `#69` and `#49` are complete.

## Recommended Operational Policy (Current)

1. Run `clawcrate doctor --json` at startup and gate execution policy.
2. If `landlock_abi == null` or `seccomp_available == false`, restrict usage to lower-risk flows:
   - prefer `plan` over `run` for untrusted inputs
   - prefer `safe`/`build` with minimal write scope
   - use Replica mode for higher-risk operations
3. For strict security boundaries, prefer native Linux or VM isolation until WSL2 baseline is CI-validated.

## Known Unsupported / Not Yet Validated

- No repository CI job currently validates WSL2 behavior.
- No formal support claim for production WSL2 security posture at this stage.
- Capability parity across Windows releases and custom WSL kernels is not guaranteed.

## Next Step (P3-02)

Issue `#49` should establish:

- a repeatable WSL2 CI lane
- minimum passing capability baseline
- explicit pass/fail criteria for WSL2 support claims
