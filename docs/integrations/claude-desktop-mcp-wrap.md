# Claude Desktop MCP Wrap Recipe

This recipe shows how to launch a stdio MCP server through ClawCrate from
Claude Desktop.

Official MCP reference: <https://modelcontextprotocol.io/docs/develop/connect-local-servers>

## Scope

Use this recipe for local stdio MCP servers, especially filesystem-style servers
that should inspect a workspace without receiving direct access to local secrets
or outbound network.

This recipe is macOS-first. Claude Desktop also documents a Windows config path,
but ClawCrate's native sandbox runtime is currently Linux and macOS; use WSL2
only where that workflow has been validated for your setup.

## Locate the Claude Desktop config

In Claude Desktop, open **Settings...**, go to **Developer**, and choose
**Edit Config**. The relevant file is:

- macOS: `~/Library/Application Support/Claude/claude_desktop_config.json`
- Windows: `%APPDATA%\Claude\claude_desktop_config.json`

Claude Desktop must be fully restarted after editing this file.

## Automated setup: `clawcrate mcp install`

Instead of hand-editing the JSON, let ClawCrate rewrite the entry:

```bash
# Preview the change (writes nothing):
clawcrate mcp install --client claude \
  --server-name filesystem \
  --profile mcp-readonly \
  --dry-run \
  -- npx -y @modelcontextprotocol/server-filesystem /Users/you/Desktop

# Apply it (writes a timestamped backup first):
clawcrate mcp install --client claude \
  --server-name filesystem \
  --profile mcp-readonly \
  -- npx -y @modelcontextprotocol/server-filesystem /Users/you/Desktop
```

This rewrites only the named `filesystem` entry so Claude Desktop launches
`clawcrate mcp wrap --profile mcp-readonly -- <original command>`. Other entries
are preserved, and a second run refuses to double-wrap. To restore:

```bash
clawcrate mcp uninstall --client claude --server-name filesystem
```

Defaults to the macOS path above; pass `--config <path>` on other platforms or
for a non-standard location. Use `--json` for machine-readable output. Restart
Claude Desktop after the change.

> The `install` writer sets `command`/`args` directly. If you need the
> change-into-a-directory launcher behavior below, edit the entry to point at the
> launcher script instead.

## Before: direct MCP server launch

This is the shape shown by the upstream MCP local-server guide. The MCP server
runs directly as the current user:

```json
{
  "mcpServers": {
    "filesystem": {
      "command": "npx",
      "args": [
        "-y",
        "@modelcontextprotocol/server-filesystem",
        "/Users/you/Desktop",
        "/Users/you/Downloads"
      ]
    }
  }
}
```

## After: launch through ClawCrate

Claude Desktop does not provide a portable `cwd` setting in the MCP JSON. Use a
small launcher script that changes into the directory you want to expose, then
execs `clawcrate mcp wrap`.

For filesystem-style servers, start with `mcp-readonly`. It uses Replica mode,
filters common secret files before launch, scrubs sensitive environment
variables, grants no write paths, and blocks network access.

Create `~/bin/claude-filesystem-clawcrate`:

```sh
#!/bin/sh
set -eu

# Ensure common paths are available because macOS GUI apps do not inherit shell profiles.
export PATH="/usr/local/bin:/opt/homebrew/bin:$HOME/.cargo/bin:$PATH"

cd "$HOME/Desktop"
exec clawcrate mcp wrap \
  --profile mcp-readonly \
  -- \
  npx --no-install @modelcontextprotocol/server-filesystem .
```

Make it executable:

```bash
chmod +x ~/bin/claude-filesystem-clawcrate
```

Then point Claude Desktop at the launcher:

```json
{
  "mcpServers": {
    "filesystem": {
      "command": "/Users/you/bin/claude-filesystem-clawcrate",
      "args": []
    }
  }
}
```

Adjust the exported `PATH` if `command -v clawcrate`, `command -v node`, or
`command -v npx` points somewhere else. Replace `/Users/you` in the JSON path
with your actual macOS username.

To expose multiple directories, prefer one safe parent directory as the launcher
cwd, then pass relative paths into the filesystem server:

```sh
#!/bin/sh
set -eu

export PATH="/usr/local/bin:/opt/homebrew/bin:$HOME/.cargo/bin:$PATH"

cd "$HOME"
exec clawcrate mcp wrap \
  --profile mcp-readonly \
  -- \
  npx --no-install @modelcontextprotocol/server-filesystem Desktop Downloads
```

## Write-capable servers

If the server must write inside its sandboxed workspace, use `mcp-server`
instead:

```json
{
  "mcpServers": {
    "filesystem": {
      "command": "/Users/you/bin/claude-filesystem-clawcrate-writeable",
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

The MCP profiles block network access. That is the intended steady-state
behavior, but it means `npx` cannot download a package from npm while the server
is running inside ClawCrate. The launcher examples therefore use
`npx --no-install`, which runs only an already available package.

Before enabling the wrapped config, either install/cache the server outside
ClawCrate from the same launcher directory or point Claude Desktop at a local
server executable:

```bash
cd ~/Desktop
npx -y @modelcontextprotocol/server-filesystem .
```

Stop that command after it starts successfully, then restart Claude Desktop with
the wrapped configuration.

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

This is defense in depth around Claude Desktop's normal MCP approval flow. The
MCP client still decides which tool calls to approve; ClawCrate constrains what
the server process can access after approval.

## Audit artifacts

Every wrapped server execution writes artifacts under:

```text
~/.clawcrate/runs/exec_<id>/
```

Important files:

- `plan.json`: command, profile, workspace mode, and materialized paths.
- `audit.ndjson`: sandbox application, environment scrubbing, process start,
  and process exit events.
- `stdout.log`: MCP JSON-RPC bytes forwarded to Claude Desktop.
- `stderr.log`: wrapped server diagnostics.
- `result.json`: exit status and artifact directory after the server exits.
- `fs-diff.json`: filesystem changes visible to ClawCrate.

For long-lived MCP servers, final `result.json` and `fs-diff.json` are written
after Claude Desktop stops or restarts the server. If startup fails, inspect the
latest `exec_<id>` directory and Claude's MCP logs.

## Troubleshooting

Claude Desktop MCP logs are written to:

- macOS: `~/Library/Logs/Claude`
- Windows: `%APPDATA%\Claude\logs`

Useful macOS command:

```bash
tail -n 50 -f ~/Library/Logs/Claude/mcp*.log
```

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
