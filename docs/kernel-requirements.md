# Kernel and Platform Requirements (Alpha)

This page describes current platform assumptions for alpha behavior.

## Supported Platforms

- Linux
- macOS
- WSL2 (experimental, post-alpha guidance only)

Other platforms currently return unsupported errors for `run`/`doctor`.

## Linux

## Minimum baseline

- Linux kernel 5.13+ is the practical baseline for Landlock availability.

## Capability checks used by `doctor`

`clawcrate doctor` reports:

- kernel version (`/proc/sys/kernel/osrelease`)
- Landlock ABI (from known sysfs paths, with fallback heuristics)
- seccomp availability
- user namespaces availability

## Current enforcement note

In the current alpha codebase, Linux launch stages are wired as:

- `rlimits`
- `landlock`
- `seccomp`

But the default `KernelEnforcer` implementation is currently no-op for those steps.
Tracked in issue `#69` ("Implement real Linux enforcement").

That means Linux capability detection is present, but full enforcement remains an active gap.

## macOS

## Minimum baseline

- macOS with `/usr/bin/sandbox-exec` available.

## Capability checks used by `doctor`

`clawcrate doctor` reports:

- seatbelt availability (`sandbox-exec` executable check)
- macOS version (`sw_vers -productVersion`)
- kernel version (`uname -r`)

## Enforcement path

Current backend behavior:

- generate SBPL profile per execution
- execute target command via `sandbox-exec`
- clean up temporary SBPL profile file after execution

## Resource Limits

The project includes rlimit mapping and application helpers in `clawcrate-sandbox::rlimits`.
These limits map profile resources to:

- CPU time
- virtual memory
- open files
- file size
- process count (platform conditional)

Integration into platform launch behavior is in progress and should be interpreted alongside issue `#69`.

## Replica Mode and Secret Handling

For high-risk operations, `install` defaults to Replica mode.

Replica copy exclusions currently include:

- `.env`
- `.env.*`
- `.git/config`
- additional `.clawcrateignore` rules

This filtering is cross-platform and independent of kernel-level deny semantics.

## Recommended Verification Command

Run this on target hosts:

```bash
clawcrate doctor --json
```

Use the JSON output in CI/automation to gate where specific profiles are allowed.

## WSL2 (Post-Alpha Spike Status)

WSL2 support is currently tracked as post-alpha roadmap scope.

Current position:

- treat WSL2 as experimental
- validate capability signals via `doctor --json`
- do not assume Landlock/seccomp parity with native Linux kernels
- monitor the dedicated WSL2 CI lane (`.github/workflows/wsl2-ci.yml`) for regression signals

Detailed constraints/workarounds report:

- [WSL2 Compatibility Spike](wsl2-compatibility.md)
