# ClawCrate — Sandboxed filesystem MCP server demo

This example wraps [`@modelcontextprotocol/server-filesystem`](https://github.com/modelcontextprotocol/servers/tree/main/src/filesystem)
behind `clawcrate mcp wrap --profile mcp-readonly`. The MCP server can read a
fixture workspace, but ClawCrate keeps secrets out of its reach, blocks writes,
scrubs sensitive environment variables, and blocks outbound network — all
enforced by the kernel, transparently to the MCP client.

## What this demo shows

Pointing the filesystem server at [`workspace/`](workspace) through the
`mcp-readonly` profile enforces five things:

1. **Normal reads work** — the server can read `workspace/README.md`,
   `workspace/docs/notes.md`, and `workspace/src/index.js`.
2. **Secret files are excluded** — `workspace/.env` and `workspace/.npmrc` are
   never present in the copy the server sees.
3. **Write attempts fail** — the profile grants no write paths.
4. **Environment is scrubbed** — secret env vars (`GITHUB_TOKEN`, `AWS_*`,
   `*_TOKEN*`, `*_KEY`, …) are removed before the server starts.
5. **Outbound network is blocked** — the server cannot open sockets.

A secret is also planted *outside* the workspace at
[`secret-vault/api-key.txt`](secret-vault/api-key.txt); it is unreachable
because it is neither copied into the Replica nor in the read allowlist.

## Prerequisites

| Requirement | Notes |
|-------------|-------|
| `clawcrate` | Install a [release](https://github.com/manuelpenazuniga/ClawCrate/releases) or build locally: `cargo build -p clawcrate-cli`. |
| Node.js + npm | Only needed to run the server *live* (step "Run it live"). Not needed for `demo.sh`. |

Run `clawcrate doctor` to confirm your platform supports sandboxing.

## Quickstart — policy preview (no network, no npm, no API key)

```bash
export ANTHROPIC_API_KEY=   # not needed
bash demo.sh
```

`demo.sh` uses `clawcrate plan` — a dry run that resolves the exact sandbox
policy **without launching the server**. It prints the profile, the Replica
workspace mode, the (empty) write set, the `network: none` level, and the
env-scrub count, then explains how each maps to the five guarantees above. It is
safe to run anywhere and repeatedly.

## Run it live (inside a real MCP client)

The `mcp-readonly` profile is `network: none`, so the package must be
installed/cached **before** entering the sandbox, and the launcher uses
`npx --no-install` at runtime:

```bash
# 1. Install the server outside ClawCrate (this step is allowed to use the network).
npm install -g @modelcontextprotocol/server-filesystem

# 2. Point your MCP client's server `command` at this demo's launcher.
#    With no arguments it exposes ./workspace; the server root stays relative (".").
examples/mcp-filesystem-demo/launcher.sh
```

[`launcher.sh`](launcher.sh) is the canonical wrap launcher — it `cd`s into the
workspace and execs `clawcrate mcp wrap --profile mcp-readonly -- npx --no-install @modelcontextprotocol/server-filesystem .`.
Configure it in your MCP client using the matching recipe:

- [Cursor MCP wrap recipe](../../docs/integrations/cursor-mcp-wrap.md)
- [Claude Desktop MCP wrap recipe](../../docs/integrations/claude-desktop-mcp-wrap.md)
- [Continue.dev MCP wrap recipe](../../docs/integrations/continue-dev-mcp-wrap.md)

The filesystem server argument is kept **relative** (`.`). Because the profile
defaults to Replica Mode, `.` resolves to the materialized Replica copy of the
workspace — never the live project directory. Do not pass an absolute path: it
would point outside the granted read root and the sandbox would deny it.

## What ClawCrate enforces (and how)

- **Reads** are limited to the Replica copy of the workspace.
- **Secret exclusion** is enforced cross-platform by *excluding the files from
  the Replica copy*: `.env` / `.env.*` and `**/.git/config` are excluded by
  ClawCrate's built-in rules, and `.npmrc` / `.netrc` / `.pypirc` are excluded
  by [`workspace/.clawcrateignore`](workspace/.clawcrateignore). This matters on
  Linux, where Landlock cannot deny a file inside a directory it granted read
  access to (see CLAUDE.md decision #9); on macOS, Seatbelt additionally denies
  those paths by regex.
- **Writes** are denied — the `mcp-readonly` profile grants no write paths, and
  `mcp wrap` never syncs a Replica back to the original workspace.
- **Environment scrubbing** removes matching secret variables before launch. The
  audit log records only the variable **names** that were removed, never values.
- **Network** is `none`: sockets are blocked (seccomp on Linux, `(deny network*)`
  on macOS). This is a hard block, not domain filtering.

## Audit artifacts

Every real wrapped run writes a durable, tamper-evident record under
`~/.clawcrate/runs/<run-id>/`:

```text
~/.clawcrate/runs/<run-id>/
├── plan.json      # resolved sandbox plan (profile, mode, command)
├── result.json    # exit status and duration
├── audit.ndjson   # ReplicaCreated, SandboxApplied, EnvScrubbed, ProcessStarted, ProcessExited
├── fs-diff.json   # file changes observed inside the Replica
├── stdout.log     # MCP JSON-RPC bytes relayed to the client
└── stderr.log     # server diagnostics
```

Inspect the newest run:

```bash
RUN=$(ls -t ~/.clawcrate/runs/ | head -1)
cat ~/.clawcrate/runs/"$RUN"/audit.ndjson
```

Enable hash chaining for a tamper-evident, verifiable record:

```bash
CLAWCRATE_AUDIT_HASHCHAIN=1 examples/mcp-filesystem-demo/launcher.sh
clawcrate verify "$(ls -t ~/.clawcrate/runs/ | head -1)"
```

## Files in this demo

```text
examples/mcp-filesystem-demo/
├── README.md               # this file
├── demo.sh                 # policy preview (clawcrate plan; no npm/network)
├── launcher.sh             # canonical mcp wrap launcher for real MCP clients
├── workspace/              # the fixture directory exposed to the server
│   ├── README.md, docs/notes.md, src/index.js   # benign, readable
│   ├── .env                # FIXTURE secret — excluded from the Replica
│   ├── .npmrc              # FIXTURE secret — excluded via .clawcrateignore
│   └── .clawcrateignore    # extra secret files to exclude from the Replica
└── secret-vault/
    └── api-key.txt         # FIXTURE secret OUTSIDE the workspace — unreachable
```

All secret values here are obviously fake and labelled `FIXTURE`; nothing real
is exposed.

## Notes and limitations

- The server runs inside a temporary **Replica copy** of the workspace, not your
  live project. Writes made by a write-capable profile land only in that copy.
- Secret exclusion on Linux depends on the Replica copy (not intra-workspace
  deny). Keep the `.clawcrateignore` up to date with any secret files you add.
- `network: none` is a hard block, not per-domain filtering.
