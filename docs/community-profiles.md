# Community Profile Catalog

This document defines how community-maintained profiles are organized, validated, and reviewed.

## Repository Structure

Community profiles live under `profiles/community/`:

```text
profiles/community/
├── catalog.yaml
├── npm-install-allowlist.yaml
└── pip-install-pypi-only.yaml
```

`catalog.yaml` is the source of truth for discoverable community profiles.

## Catalog Schema

`catalog.yaml` must follow this structure:

```yaml
version: 1
profiles:
  - id: npm-install-allowlist
    title: npm install with minimal registry allowlist
    path: npm-install-allowlist.yaml
    owner: "@clawcrate-community"
    tags: [node, install, filtered-network]
```

Rules enforced by `clawcrate-profiles` validation:

- `version` must be `1`.
- `id` must be lowercase kebab-case (`[a-z0-9-]`).
- `id` values must be unique.
- `path` must be a relative `.yaml` file inside `profiles/community/`.
- `path` values must be unique.
- Every listed profile must parse through the same strict profile schema as built-ins.

## Profile Schema Validation

Each community profile is validated by the same parser as built-in profiles:

- unknown keys are rejected (`deny_unknown_fields`)
- invalid `default_mode`, `network`, and filtered `allowed_domains` combinations fail
- inheritance (`extends`) is resolved and cycle-checked

Validation is executed in CI by `cargo test --workspace` through tests in `clawcrate-profiles`.

## Contribution Flow

1. Add or update profile YAML in `profiles/community/`.
2. Add/update entry in `profiles/community/catalog.yaml`.
3. Run local checks:
   - `cargo fmt --all`
   - `cargo clippy --workspace --all-targets -- -D warnings`
   - `cargo test --workspace`
4. Open PR with:
   - threat model note (what risk is reduced)
   - scope note (who should use this profile)
   - validation output (tests passing)

## Review Checklist

Maintainers should verify:

- the profile grants least privilege for filesystem + network
- filtered network domains are minimal and justified
- replica/direct default is aligned with risk level
- env scrub/pass-through values avoid secret leakage
- profile naming and metadata in catalog remain clear and searchable
