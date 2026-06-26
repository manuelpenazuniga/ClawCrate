# Continue.dev MCP Wrap Recipe

This recipe shows how to launch a stdio MCP server through ClawCrate from
Continue.

Official Continue MCP references:

- <https://docs.continue.dev/customize/mcp-tools>
- <https://docs.continue.dev/customize/deep-dives/mcp>
- <https://docs.continue.dev/reference#mcpservers>

## Scope

Use this recipe for local stdio MCP servers, especially filesystem-style servers
that should inspect a Continue workspace without direct access to local secrets
or outbound network.

Continue configures MCP servers with `mcpServers` YAML blocks. ClawCrate wraps
the server process that Continue starts; Continue still owns MCP tool discovery,
approval, and logs.

## Locate Continue config

Continue's current config format is `config.yaml`. The CLI looks for:

```text
~/.continue/config.yaml
```

Older Continue installations used `config.json`, but Continue's current
reference documents `config.yaml` and marks `config.json` as deprecated. Keep
these examples in YAML unless you are deliberately maintaining a legacy Continue
config.

You can also launch the Continue CLI with an explicit config file:

```bash
cn --config ./my-config.yaml
```

The IDE extensions use the same `config.yaml` schema. This recipe uses inline
`mcpServers` entries because they are the smallest migration from a direct MCP
server launch. If you use standalone block files under `.continue/mcpServers/`,
keep the same `command` and `args` shape shown below and include Continue's
required block metadata.

## Before: direct MCP server launch

This Continue config runs the MCP server directly as the current user:

```yaml
mcpServers:
  - name: Filesystem
    type: stdio
    command: npx
    args:
      - "-y"
      - "@modelcontextprotocol/server-filesystem"
      - "/Users/you/project"
```

## After: launch through ClawCrate

Use a small launcher script that receives the workspace directory from Continue,
changes into that directory, then execs `clawcrate mcp wrap`.

For filesystem-style servers, start with `mcp-readonly`. It uses Replica mode,
filters common secret files before launch, scrubs sensitive environment
variables, grants no write paths, and blocks network access.

Create `~/bin/continue-filesystem-clawcrate`. The first argument is the directory
ClawCrate should materialize. Any remaining arguments are relative paths passed
to the filesystem MCP server; if no relative paths are provided, the server sees
the current workspace as `.`.

```sh
#!/bin/sh
set -eu

# Ensure common paths are available because GUI apps may not inherit shell profiles.
export PATH="/usr/local/bin:/opt/homebrew/bin:$HOME/.cargo/bin:$PATH"

TARGET_DIR="${1:?usage: continue-filesystem-clawcrate <workspace-dir> [relative-path ...]}"
shift

if [ "$#" -eq 0 ]; then
  set -- .
fi

cd "$TARGET_DIR"
exec clawcrate mcp wrap \
  --profile mcp-readonly \
  -- \
  npx --no-install @modelcontextprotocol/server-filesystem "$@"
```

Make it executable:

```bash
chmod +x ~/bin/continue-filesystem-clawcrate
```

Then point Continue at the launcher:

```yaml
mcpServers:
  - name: Filesystem
    type: stdio
    command: /Users/you/bin/continue-filesystem-clawcrate
    args:
      - /Users/you/project
```

Replace `/Users/you` with your actual macOS username and `/Users/you/project`
with the project directory you want Continue to expose through the filesystem
MCP server. Adjust the exported `PATH` if `command -v clawcrate`,
`command -v node`, or `command -v npx` points somewhere else.

To expose multiple directories, keep the first argument as the workspace root and
pass additional relative paths into the filesystem server:

```yaml
mcpServers:
  - name: Filesystem
    type: stdio
    command: /Users/you/bin/continue-filesystem-clawcrate
    args:
      - /Users/you/project
      - src
      - docs
```

## Write-capable servers

If the server must write inside its sandboxed workspace, use `mcp-server`
instead:

```yaml
mcpServers:
  - name: Filesystem
    type: stdio
    command: /Users/you/bin/continue-filesystem-clawcrate-writeable
    args:
      - /Users/you/project
```

The write-capable launcher should be identical except for
`--profile mcp-server`.

Use `mcp-server` only for servers that genuinely need write access. It still uses
Replica mode, secret filtering, environment scrubbing, and `network: none`.
Writes happen in the materialized Replica workspace. `clawcrate mcp wrap` records
them in `fs-diff.json`; it does not sync those writes back to the original
directory.

## First-run package installation

The MCP profiles block network access. That is the intended steady-state
behavior, but it means `npx` cannot download a package from npm while the server
is running inside ClawCrate. The launcher examples therefore use
`npx --no-install`, which runs only an already available package.

Before enabling the wrapped config, install the server outside ClawCrate so
`npx --no-install` can resolve it from a real local or global install, or point
Continue at a local server executable.

Global install:

```bash
npm install -g @modelcontextprotocol/server-filesystem
```

Project-local install:

```bash
cd ~/project
npm install --save-dev @modelcontextprotocol/server-filesystem
```

Then restart or reload Continue so it starts the wrapped MCP server.

## What ClawCrate enforces

With `mcp-readonly`:

- The wrapped server can read the materialized workspace copy.
- The wrapped server receives no workspace write paths.
- Common secrets such as `.env*`, `.git/config`, `.npmrc`, `.pypirc`, and
  `.netrc` are excluded from the Replica workspace.
- Sensitive environment variables such as `AWS_*`, `GITHUB_TOKEN`, `NPM_TOKEN`,
  `OPENAI_API_KEY`, `ANTHROPIC_API_KEY`, `*_SECRET*`, `*_PASSWORD*`,
  `*_TOKEN*`, and `*_KEY` are scrubbed before launch.
- Outbound network is blocked by the profile.

Avoid adding secrets to Continue MCP `env` entries for a server that should run
under `mcp-readonly`; ClawCrate is expected to remove sensitive environment
variables before launching the wrapped process. Servers that require API keys or
network access need a separate, deliberately reviewed profile.

This is defense in depth around Continue's normal MCP approval flow. The MCP
client still decides which tool calls to approve; ClawCrate constrains what the
server process can access after approval.

## Audit artifacts

Every wrapped server execution writes artifacts under:

```text
~/.clawcrate/runs/exec_<id>/
```

Important files:

- `plan.json`: command, profile, workspace mode, and materialized paths.
- `audit.ndjson`: sandbox application, environment scrubbing, process start,
  and process exit events.
- `stdout.log`: MCP JSON-RPC bytes forwarded to Continue.
- `stderr.log`: wrapped server diagnostics.
- `result.json`: exit status and artifact directory after the server exits.
- `fs-diff.json`: filesystem changes visible to ClawCrate.

For long-lived MCP servers, final `result.json` and `fs-diff.json` are written
after Continue stops or restarts the server. If startup fails, inspect the latest
`exec_<id>` directory and Continue's extension or CLI logs.

## Troubleshooting

For the CLI, run `cn` from a terminal so startup errors are visible on stderr.
For IDE extensions, inspect the editor's Continue output/log panel after
reloading the MCP server or restarting the extension host.

Common failure modes:

- `clawcrate` not found: use an absolute `command` path from
  `command -v clawcrate` inside the launcher.
- Server package download fails: install/cache the server before wrapping, or
  use a local executable.
- Files are not visible: make sure the launcher first argument is the directory
  you intend to expose, and use relative paths for any additional MCP server
  args.
- Writes fail under `mcp-readonly`: switch to `mcp-server` only if write access
  inside the Replica workspace is expected and acceptable.
- Network calls fail: this is expected for MCP profiles with `network: none`.

Stdio MCP servers must keep JSON-RPC on stdout. ClawCrate forwards stdout
without protocol-visible diagnostics; diagnostic logs from ClawCrate go to
stderr only when verbosity is enabled.
