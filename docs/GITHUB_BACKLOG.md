# GitHub Backlog (YAML-Driven)

This repository uses a YAML-driven backlog so planning data is maintained in one place and automation stays generic.

## Source of Truth

- [`docs/backlog.yaml`](/Volumes/MacMiniExt/dev/OpenSource Projects/ClawCrate/docs/backlog.yaml)

It defines:

- Labels
- Milestones
- Epics
- Issues

Each item has a stable ID (`id`) and generated issues include `backlog_id=<id>` in the body, making script runs idempotent.

## Automation Script

- [`scripts/create_github_backlog.sh`](/Volumes/MacMiniExt/dev/OpenSource Projects/ClawCrate/scripts/create_github_backlog.sh)

The script:

1. Creates/updates labels (`--force`)
2. Creates missing milestones
3. Creates epics
4. Creates regular issues linked to parent epic URL
5. Skips already-created items by checking `backlog_id=...`

## Requirements

- `gh` authenticated (`gh auth login`)
- `jq`
- `ruby` (used to parse YAML without extra dependencies)

## Usage

From repo root:

```bash
bash scripts/create_github_backlog.sh
```

Dry run:

```bash
bash scripts/create_github_backlog.sh --dry-run
```

Custom repository:

```bash
bash scripts/create_github_backlog.sh --repo owner/repo
```

Custom backlog file:

```bash
bash scripts/create_github_backlog.sh --config docs/backlog.yaml
```

## Backlog Scope (Current)

Milestones currently defined in `docs/backlog.yaml`:

- `M0 - Workspace Bootstrap`
- `M1 - Core Contracts + Plan`
- `M2 - Sandbox Backends`
- `M3 - Run + Capture + Audit`
- `M4 - Replica Mode`
- `M5 - Alpha Hardening + Release`
- `P1 - Network + Approvals`
- `P2 - Audit DB + API + Integrations`
- `P3 - WSL2`
