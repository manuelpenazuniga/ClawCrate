# Cursor MCP Wrap Recipe

This recipe shows how to launch a stdio MCP server through ClawCrate from
Cursor.

Official Cursor MCP reference: <https://cursor.com/docs/mcp>

## Scope

Use this recipe for local stdio MCP servers, especially filesystem-style servers
that should inspect a Cursor workspace without direct access to local secrets or
outbound network.

Cursor supports MCP configuration through `mcp.json`. ClawCrate wraps the server
process that Cursor starts; Cursor still owns MCP tool discovery, approval, and
logs.

## Locate Cursor MCP config

Cursor documents two `mcp.json` locations:

- Project-specific: `.cursor/mcp.json` inside the project.
- Global: `~/.cursor/mcp.json` in your home directory.

Prefer project-specific config for workspace-local filesystem servers. Use global
config only for tools that should be available in every Cursor workspace.

Cursor also supports config interpolation such as `${workspaceFolder}` in
project config. The launcher below still changes into the target directory
explicitly so ClawCrate materializes Replica mode from the intended workspace and
the wrapped MCP server receives relative paths.

## Automated setup: `clawcrate mcp install`

Instead of hand-editing `mcp.json`, let ClawCrate rewrite the entry for you:

```bash
# Preview the change (writes nothing):
clawcrate mcp install --client cursor \
  --server-name filesystem \
  --profile mcp-readonly \
  --dry-run \
  -- npx -y @modelcontextprotocol/server-filesystem /Users/me/project

# Apply it (writes a timestamped backup first):
clawcrate mcp install --client cursor \
  --server-name filesystem \
  --profile mcp-readonly \
  -- npx -y @modelcontextprotocol/server-filesystem /Users/me/project
```

This rewrites only the named `filesystem` entry so Cursor launches
`clawcrate mcp wrap --profile mcp-readonly -- <original command>`. Other entries
are untouched. Running it again refuses to double-wrap. To restore the original
command:

```bash
clawcrate mcp uninstall --client cursor --server-name filesystem
```

Defaults to `~/.cursor/mcp.json`; pass `--config .cursor/mcp.json` to target a
project-local config. Use `--json` for machine-readable output.

> **For filesystem-style servers, prefer the launcher below.** `mcp install`
> rewrites `command`/`args` in place and does not set a working directory, so the
> wrapped server inherits whatever directory the client happens to run in — which
> is what `mcp-readonly` then materializes as the Replica. It also cannot wrap
> `npx`, which fails to start inside the sandbox (see below). Use `mcp install`
> for servers that do not need a specific workspace, and the launcher script for
> the ones that do.


## Before: direct MCP server launch

This Cursor config runs the MCP server directly as the current user:

```json
{
  "mcpServers": {
    "filesystem": {
      "command": "npx",
      "args": [
        "-y",
        "@modelcontextprotocol/server-filesystem",
        "${workspaceFolder}"
      ]
    }
  }
}
```

## After: launch through ClawCrate

Use a small launcher script that receives the workspace directory from Cursor,
changes into that directory, then execs `clawcrate mcp wrap`.

For filesystem-style servers, start with `mcp-readonly`. It uses Replica mode,
filters common secret files before launch, scrubs sensitive environment
variables, grants no write paths, and blocks network access.

Create `~/bin/cursor-filesystem-clawcrate`. The first argument is the directory
ClawCrate should materialize. Any remaining arguments are relative paths passed
to the filesystem MCP server; if no relative paths are provided, the server sees
the current workspace as `.`.

```sh
#!/bin/sh
set -eu

# Ensure common paths are available because GUI apps may not inherit shell profiles.
export PATH="/usr/local/bin:/opt/homebrew/bin:$HOME/.cargo/bin:$PATH"

TARGET_DIR="${1:?usage: cursor-filesystem-clawcrate <workspace-dir> [relative-path ...]}"
shift

if [ "$#" -eq 0 ]; then
  set -- .
fi

cd "$TARGET_DIR"
exec clawcrate mcp wrap \
  --profile mcp-readonly \
  -- \
  node node_modules/@modelcontextprotocol/server-filesystem/dist/index.js "$@"
```

> **Why not `npx`?** The sandbox grants read access to the workspace only, and
> `npx` must read its own launcher and package cache from the Node installation,
> which lies outside that set — so it cannot start. Installing the server into
> the workspace keeps everything it reads inside the sandbox, so the profile
> does not have to grant the Node installation as well. Verified end to end on
> macOS, where the wrapped server lists and reads the workspace while `.env`
> stays invisible. On Linux a distro-packaged `npx` may work, since the system
> read set already covers `/usr/bin` and `/usr/lib`; the workspace-local
> launcher was chosen because it behaves the same on both platforms.

Make it executable:

```bash
chmod +x ~/bin/cursor-filesystem-clawcrate
```

Then point Cursor at the launcher in `.cursor/mcp.json` or
`~/.cursor/mcp.json`:

```json
{
  "mcpServers": {
    "filesystem": {
      "command": "/Users/you/bin/cursor-filesystem-clawcrate",
      "args": ["${workspaceFolder}"]
    }
  }
}
```

Replace `/Users/you` with your actual macOS username. For global config, replace
`${workspaceFolder}` with the explicit project path you want to expose, for
example `/Users/you/project`. Adjust the exported `PATH` if
`command -v clawcrate`, `command -v node`, or `command -v npx` points somewhere
else.

To expose multiple directories, keep the first argument as the workspace root and
pass additional relative paths into the filesystem server:

```json
{
  "mcpServers": {
    "filesystem": {
      "command": "/Users/you/bin/cursor-filesystem-clawcrate",
      "args": ["${workspaceFolder}", "src", "docs"]
    }
  }
}
```

## Write-capable servers

If the server must write inside its sandboxed workspace, use `mcp-server`
instead:

```json
{
  "mcpServers": {
    "filesystem": {
      "command": "/Users/you/bin/cursor-filesystem-clawcrate-writeable",
      "args": []
    }
  }
}
```

The write-capable launcher should be identical except for
`--profile mcp-server`.

Use `mcp-server` only for servers that genuinely need write access. It still uses
Replica mode, secret filtering, environment scrubbing, and `network: none`.
Writes happen in the materialized Replica workspace. `clawcrate mcp wrap` records
them in `fs-diff.json`; it does not sync those writes back to the original
directory.

## First-run package installation

The MCP profiles block network access and grant read access to the workspace
only. The server must therefore be installed **into the workspace** before it is
wrapped, and launched from that copy.

The MCP profiles block network access and grant read access to the workspace
only. Install the server **into the workspace** before wrapping it, and launch it
from that copy:

```bash
cd ~/project
npm install @modelcontextprotocol/server-filesystem
```

That places the entrypoint at
`node_modules/@modelcontextprotocol/server-filesystem/dist/index.js`, which is
what the launcher above runs. Reinstall after upgrading the package.

> **The install itself is not sandboxed.** `npm install` runs as you, on the
> host, and a package's lifecycle scripts run with your privileges — the very
> risk ClawCrate exists to contain. Install from a trusted registry, and if you
> want that step contained too, run it under ClawCrate first:
> `clawcrate run --profile install -- npm install <pkg>` (Replica Mode, so
> review the diff and sync back deliberately).


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

Avoid putting secrets in Cursor MCP `env` or `envFile` entries for a server that
should run under `mcp-readonly`; ClawCrate is expected to remove sensitive
environment variables before launching the wrapped process. Servers that require
API keys or network access need a separate, deliberately reviewed profile.

This is defense in depth around Cursor's normal MCP approval flow. The MCP client
still decides which tool calls to approve; ClawCrate constrains what the server
process can access after approval.

## Audit artifacts

Every wrapped server execution writes artifacts under:

```text
~/.clawcrate/runs/exec_<id>/
```

Important files:

- `plan.json`: command, profile, workspace mode, and materialized paths.
- `audit.ndjson`: sandbox application, environment scrubbing, process start,
  and process exit events.
- `stdout.log`: MCP JSON-RPC bytes forwarded to Cursor.
- `stderr.log`: wrapped server diagnostics.
- `result.json`: exit status and artifact directory after the server exits.
- `fs-diff.json`: filesystem changes visible to ClawCrate.

For long-lived MCP servers, final `result.json` and `fs-diff.json` are written
after Cursor stops or restarts the server. If startup fails, inspect the latest
`exec_<id>` directory and Cursor's MCP logs.

## Troubleshooting

Cursor documents MCP server management under **Settings** -> **Features** ->
**Model Context Protocol**. Use that view to enable, disable, or reload a server.

For logs, open Cursor's output panel with `Cmd+Shift+U` on macOS or
`Ctrl+Shift+U` on Linux/Windows, then select **MCP Logs**.

Common failure modes:

- `clawcrate` not found: use an absolute `command` path from
  `command -v clawcrate` inside the launcher.
- Server package download fails: install/cache the server before wrapping, or
  use a local executable.
- Files are not visible: make sure the launcher `cd` target is the directory
  you intend to expose, and use relative paths in the MCP server args.
- Writes fail under `mcp-readonly`: switch to `mcp-server` only if write access
  inside the Replica workspace is expected and acceptable.
- Network calls fail: this is expected for MCP profiles with `network: none`.

Stdio MCP servers must keep JSON-RPC on stdout. ClawCrate forwards stdout
without protocol-visible diagnostics; diagnostic logs from ClawCrate go to
stderr only when verbosity is enabled.
