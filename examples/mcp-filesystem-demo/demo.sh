#!/usr/bin/env bash
# ClawCrate MCP filesystem demo.
#
# Shows exactly what `clawcrate mcp wrap --profile mcp-readonly` would enforce
# around @modelcontextprotocol/server-filesystem, using `clawcrate plan` — a
# dry run that resolves the sandbox policy WITHOUT launching the server. That
# means it needs no network, no npm package, and no API key, and it is safe to
# run anywhere and repeatedly.
#
# To actually run the server sandboxed inside a real MCP client, see the
# "Run it live" section of README.md and use ./launcher.sh.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WORKSPACE="$SCRIPT_DIR/workspace"

# Locate clawcrate: prefer an installed binary, fall back to the debug build.
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
DEBUG_BIN="$REPO_ROOT/target/debug/clawcrate"
if command -v clawcrate &>/dev/null; then
  CLAWCRATE_BIN="clawcrate"
elif [[ -x "$DEBUG_BIN" ]]; then
  CLAWCRATE_BIN="$DEBUG_BIN"
  echo "Note: using debug build at $DEBUG_BIN"
  echo "      Run 'cargo build -p clawcrate-cli' first if this is stale."
else
  echo "Error: clawcrate not found. Install from:" >&2
  echo "  https://github.com/manuelpenazuniga/ClawCrate/releases" >&2
  echo "Or build locally: cargo build -p clawcrate-cli" >&2
  exit 1
fi

echo ""
echo "=============================================================="
echo " ClawCrate — sandboxed filesystem MCP server (policy preview)"
echo "=============================================================="
echo ""
echo "Wrapping: npx --no-install @modelcontextprotocol/server-filesystem ."
echo "Profile:  mcp-readonly"
echo "Workspace exposed to the server: $WORKSPACE"
echo ""

# `plan` resolves the policy without executing anything.
cd "$WORKSPACE"
"$CLAWCRATE_BIN" plan \
  --profile mcp-readonly \
  -- \
  npx --no-install @modelcontextprotocol/server-filesystem .

cat <<'EXPLAIN'

What the plan above means for the wrapped server:

  - Normal reads work. The server can read the benign files in this workspace
    (README.md, docs/notes.md, src/index.js) from the Replica copy.

  - Secret files are excluded. Workspace Mode is Replica, so the server sees a
    filtered copy of the workspace. `.env` is excluded by ClawCrate's built-in
    rules; `.npmrc` (and `.netrc`, `.pypirc`) are excluded by this demo's
    workspace/.clawcrateignore. On Linux this exclusion is the only thing that
    guarantees the server never sees them (Landlock cannot deny a file inside a
    granted-read directory); on macOS Seatbelt also denies them by path.

  - Write attempts fail. Filesystem Write Paths is 0 — the profile grants no
    write access, so any write the server attempts is denied by the kernel.

  - Environment is scrubbed. 14 secret env patterns (AWS_*, GITHUB_TOKEN,
    *_TOKEN*, *_KEY, ...) are stripped before the server starts. Only the
    variable NAMES are recorded in the audit log, never the values.

  - Outbound network is blocked. Network is "none": the server cannot open
    sockets. (This is why the package must be installed BEFORE entering the
    sandbox and launched with `npx --no-install`.)

A secret is also planted OUTSIDE the workspace at secret-vault/api-key.txt. It
is neither copied into the Replica nor in the read allowlist, so the server
cannot reach it on either platform.

Run it live inside a real MCP client with ./launcher.sh (see README.md). After
a real wrapped run, inspect the audit artifacts under:

  ~/.clawcrate/runs/<run-id>/
    plan.json      result.json    fs-diff.json
    audit.ndjson   stdout.log     stderr.log

  ls -t ~/.clawcrate/runs/ | head -1        # newest run id
EXPLAIN
