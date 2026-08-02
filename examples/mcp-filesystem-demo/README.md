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

### Watch it

[`demo.cast`](demo.cast) is a recording of `./demo.sh --live` on macOS:

```bash
asciinema play examples/mcp-filesystem-demo/demo.cast
```

It is a real capture, not a mock-up, produced by [`record.py`](record.py) —
regenerate it and compare rather than take it on trust. The recorder shortens
long waits (Node starting, the Replica materializing) and rewrites the recording
machine's home and checkout paths to placeholders; it never adds, drops or
reorders output.

### Two defences, doing two different jobs

`./demo.sh --live` exercises both, and the distinction is the point of the demo.

`workspace/.env` is **never in the sandbox**. Replica Mode filters it out before
the server starts, so there is nothing to read. This is deterministic: it
depends on what ClawCrate copied, not on catching an access in the act. The
`ReplicaCreated` event in `audit.ndjson` lists exactly what was withheld.

`secret-vault/` is **blocked by the kernel**. The live run hands that directory
to the server as one of its own allowed roots, so the server's policy permits
the read and it goes ahead and tries — and the sandbox refuses it anyway. That
separation matters: the block comes from ClawCrate, not from the server being
well behaved. Without it the demo would only prove that a cooperative server
cooperates.

### What the audit trail can and cannot tell you

An entry proves a denial happened; its absence does not prove none did. The
enforcement is not in question either way — the read fails every time — but what
the operating system is willing to *report* differs:

| Denial | Linux | macOS |
| --- | --- | --- |
| Outbound connection refused by the egress proxy | recorded, complete | recorded, complete |
| Syscall refused by the sandbox | recorded, complete | n/a |
| File read refused by the sandbox | **not recorded** | recorded, best-effort |

The two complete rows are decisions ClawCrate makes itself, so it records them
before returning the refusal. File denials are the kernel's own: Landlock tells
the child `EACCES` and nobody else, and macOS drops some of its sandbox reports.
Set `CLAWCRATE_SEATBELT_VIOLATIONS=1` to collect the macOS ones. See
[`docs/architecture.md`](../../docs/architecture.md#recorded-denials).

## Prerequisites

| Requirement | Notes |
|-------------|-------|
| `clawcrate` | Install a [release](https://github.com/manuelpenazuniga/ClawCrate/releases) or build locally: `cargo build -p clawcrate-cli`. |
| Node.js + npm | Only needed for the live run (`demo.sh --live` or a real MCP client). Not needed for the default policy preview. |

Run `clawcrate doctor` to confirm your platform supports sandboxing.

## Quickstart — policy preview (no network, no npm, no API key)

```bash
bash demo.sh          # policy preview: no Node.js, no network, no install
bash demo.sh --live   # start the real server in the sandbox and drive it
```

Without `--live`, `demo.sh` uses `clawcrate plan` — a dry run that resolves the
exact sandbox policy **without launching the server**. It prints the profile, the
Replica workspace mode, the (empty) write set, the `network: none` level, and the
env-scrub count, then explains how each maps to the five guarantees above. It is
safe to run anywhere and repeatedly.

With `--live`, it installs the server into the workspace, starts it through
`clawcrate mcp wrap`, and drives it over JSON-RPC. Expected output:

```text
  list_directory .   -> [FILE] README.md | [DIR] docs | [DIR] src | ...
  read README.md     -> '# Sample project ...'
  read .env          -> not visible
```

`.env` is absent from the listing and unreadable: Replica Mode excluded it before
the server started, so the secret never entered the sandbox.

## Run it live (inside a real MCP client)

The `mcp-readonly` profile is `network: none` and grants read access to the
workspace only, so the server is installed **into the workspace** and launched
from that copy:

```bash
# 1. Install the server into the workspace (this step is outside the sandbox,
#    so it may use the network).
cd examples/mcp-filesystem-demo/workspace
npm install @modelcontextprotocol/server-filesystem

# 2. Point your MCP client's server `command` at this demo's launcher.
#    With no arguments it exposes ./workspace; the server root stays relative (".").
examples/mcp-filesystem-demo/launcher.sh
```

**Why not `npx`?** `npx` must read its own launcher and package cache from the
Node installation, which is outside the workspace the sandbox grants — so it
cannot start. Installing into the workspace keeps everything the server reads
inside the sandbox, which is both the pattern that works and the narrower
grant.

[`launcher.sh`](launcher.sh) is the canonical wrap launcher — it `cd`s into the
workspace and execs `clawcrate mcp wrap --profile mcp-readonly -- node node_modules/@modelcontextprotocol/server-filesystem/dist/index.js .`.
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
├── demo.sh                 # policy preview, or the full story with --live
├── record.py               # regenerates demo.cast from a real run
├── demo.cast               # asciinema recording of ./demo.sh --live
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
