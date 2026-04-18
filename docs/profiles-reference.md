# Profiles Reference

This reference covers built-in and custom profiles as implemented in `clawcrate-profiles`.

## Built-in Profiles

Built-ins are loaded from `profiles/*.yaml`:

- `safe`
- `build`
- `install`
- `open`

## `safe`

- `default_mode`: `Direct`
- `network`: `none`
- Filesystem:
  - read: `.`
  - write: none
- Intended use:
  - read-only commands (lint/check/inspect)

## `build`

- `default_mode`: `Direct`
- `network`: `none`
- Filesystem:
  - read: workspace + toolchain/cache paths
  - write: `./target`, `./dist`, `./build`
- Intended use:
  - compilation and test workflows without network

## `install`

- `default_mode`: `Replica`
- `network`: `open`
- Filesystem:
  - broad read/write suitable for dependency installs
- Intended use:
  - package installs (`npm`, `pip`, `cargo` fetch/install flows)
- Security posture:
  - Replica mode default helps protect source workspace from secret file exposure

## `open`

- `default_mode`: `Direct`
- `network`: `open`
- Filesystem:
  - read/write workspace
- Intended use:
  - least restrictive profile for trusted tasks

## Mode Resolution Rules

Execution mode is resolved with this precedence:

1. CLI override flags (`--replica` or `--direct`)
2. Profile `default_mode`

Then materialized to runtime mode:

- `Direct`
- `Replica { source, copy }`

## Auto Detection (`--profile` omitted)

Resolver behavior:

- `Cargo.toml` found: treat as Rust stack
- `package.json` found: treat as Node stack
- `pyproject.toml` found: treat as Python stack
- none found: fallback to `safe`

Current auto profile selection:

- known stacks resolve from `build` with stack-specific path/env overrides
- unknown stack resolves to `safe`

## Custom Profiles (YAML)

A custom profile can be provided by file path:

```bash
clawcrate run --profile .clawcrate/custom.yaml -- make build
```

Supported fields:

```yaml
name: my-profile
extends: build
default_mode: direct   # direct | replica
filesystem:
  read: ["."]
  write: ["./target"]
  deny: []
network:
  mode: none           # none | open | filtered
  allowed_domains: []  # required when mode=filtered
environment:
  scrub: ["*_SECRET*", "AWS_*"]
  passthrough: ["HOME", "PATH"]
resources:
  max_cpu_seconds: 120
  max_memory_mb: 2048
  max_open_files: 1024
  max_processes: 128
  max_output_bytes: 2097152
```

`extends` supports:

- built-in name (for example `build`)
- relative YAML path
- absolute YAML path

Inheritance is merged field-by-field and cycle-checked.

`network` also supports shorthand string form for `none` and `open`:

```yaml
network: open
```

For filtered mode, object form is required:

```yaml
network:
  mode: filtered
  allowed_domains:
    - "registry.npmjs.org"
    - "*.pkg.dev"
```

## Validation Rules

Parser behavior includes:

- unknown YAML fields are rejected (`deny_unknown_fields`)
- invalid `network` values fail profile load
- `network.mode: filtered` without `allowed_domains` fails profile load
- invalid `default_mode` values fail profile load
- missing profile file fails with explicit path error

## Notes on Filesystem Deny

- `fs_deny` is currently consumed in macOS SBPL profile generation.
- Linux intra-workspace deny behavior depends on Landlock implementation status.
- For sensitive file filtering in alpha, use Replica mode + default exclusions + `.clawcrateignore`.
