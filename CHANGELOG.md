# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html)
with alpha pre-release tags.

## [Unreleased]

### Added
- Linux filesystem **read isolation** via Landlock read-allowlisting: the
  ruleset now declares `ACCESS_FS_READ_FILE` / `ACCESS_FS_READ_DIR` and grants
  them only on the profile's read/write set plus a minimal system and toolchain
  allowlist. A sandboxed process can no longer read secrets outside its
  workspace (for example `~/.ssh/id_rsa` or `~/.aws/credentials`) in Direct
  Mode. A CI security fixture asserts this landmark on Linux, mirroring the
  existing macOS fixture.

### Changed
- `clawcrate doctor` now reports Direct-Mode read isolation as enforced on
  Linux, and `plan`/`run` no longer emit the Linux read-isolation warning
  introduced for the pre-enforcement gap.
- The Linux system read allowlist is enumerated instead of coarse. `/usr` and
  `/opt` are no longer granted as a whole (which would have exposed
  `/usr/local/etc` and vendor configuration, since Landlock cannot deny a path
  inside a granted one); the specific executable, library, shared-data,
  name-resolution, TLS-trust, loader, locale, device, and procfs entries are
  granted individually. `/run/systemd/resolve` was added, without which DNS
  resolution fails on systemd-resolved distributions for network-enabled
  profiles. A toolchain installed outside these prefixes must be declared by the
  profile, as the `build` profile already does for `~/.cargo` and `~/.rustup`.

## [0.2.0-alpha.0] - 2026-06-20

### Added
- Compliance Kit audit features:
  SHA-256 hash-chain audit lines, deterministic canonical JSON hashing,
  offline `clawcrate verify <run-id>`, Ed25519 block signatures, and
  SIEM-oriented audit export formats (`json`, `cef`, `syslog`, `elastic`).
- Compliance documentation mapping ClawCrate audit artifacts to EU AI Act
  Article 12/19/26 evidence boundaries and IETF Agent Audit Trail alignment.
- Hash-chain benchmark coverage for compute, append, and verification paths.
- Community profiles:
  `agent-inference-allowlist`, `mcp-server`, and `mcp-readonly`.
- `examples/agent-demo/` for a minimal agent flow delegating commands through
  ClawCrate.
- Structured roadmap/backlog docs for the `v0.2.0`, `v0.3.0`, and `v0.4.0`
  milestones.

### Changed
- Clarified Linux Direct Mode filesystem boundaries: current Linux Landlock
  enforcement focuses on write controls; Replica Mode is the supported path for
  excluding sensitive readable files before execution.
- Clarified `network: filtered` as proxy-mediated domain filtering with
  documented bypass caveats for tools that ignore proxy environment variables.
- Updated release planning around the MCP Server Firewall as the next active
  `v0.2.0` workstream after this Compliance Kit alpha.

### Fixed
- Internal audit-control environment variables (`CLAWCRATE_AUDIT_*`) are now
  always removed from the sandboxed child environment, even if a profile would
  otherwise pass through `CLAWCRATE_*`.

## [0.1.0-alpha.2] - 2026-04-30

### Fixed
- Process-group signal fallback for deterministic SIGINT handling under nested child trees.
- seccomp pre-exec errors now propagate correctly instead of being silently swallowed.
- Symlink-safe temp fixture cleanup in sandbox integration tests.
- Darwin-only path pattern normalization gated correctly so cross-platform clippy stays clean.

### Changed
- Centralized backend path normalization helpers (refactor, no behaviour change).
- Workspace crate versions aligned to `0.1.0-alpha.2` before tag cut.

## [0.1.0-alpha.1] - 2026-04-30

### Added
- Release automation workflow for multi-target binary artifacts and checksum publication.
- Install script with platform/architecture detection and SHA256 verification.

### Changed
- Reconciled alpha scope contract: documented command surface now explicitly includes `api` and `bridge pennyprompt` alongside `run`, `plan`, and `doctor`.

### Fixed
- Built-in profile names (`safe`, `build`, `install`, `open`) now resolve correctly in installed release binaries without requiring a local repository checkout.
- macOS Seatbelt SBPL generation now imports the system baseline profile to prevent trivial sandboxed commands from terminating as `Killed`.

## [0.1.0-alpha.0] - 2026-04-18

### Added
- Initial alpha command surface for `run`, `plan`, `doctor`, `api`, and `bridge pennyprompt`.
- Native sandbox backends:
  Linux: Landlock + seccomp + rlimits.
  macOS: Seatbelt (`sandbox-exec`) + rlimits.
- Built-in profiles: `safe`, `build`, `install`, `open`.
- Replica mode with `.clawcrateignore` support and explicit sync-back flow.
- Execution artifacts:
  `plan.json`, `result.json`, `stdout.log`, `stderr.log`, `audit.ndjson`, `fs-diff.json`.
- Linux/macOS CI matrix with integration and security fixtures.
- Golden CLI output tests for text and JSON modes.
