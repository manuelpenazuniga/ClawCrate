# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html)
with alpha pre-release tags.

## [Unreleased]

### Added
- Release automation workflow for multi-target binary artifacts and checksum publication.
- Install script with platform/architecture detection and SHA256 verification.

### Changed
- Reconciled alpha scope contract: documented command surface now explicitly includes `api` and `bridge pennyprompt` alongside `run`, `plan`, and `doctor`.

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
