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
SERVER_ENTRYPOINT="node_modules/@modelcontextprotocol/server-filesystem/dist/index.js"

# `--live` starts the real MCP server inside the sandbox and drives it over
# JSON-RPC. Without it the demo only previews the resolved policy, which needs
# no Node.js, no network, and no package install.
LIVE=0
if [ "${1:-}" = "--live" ]; then
  LIVE=1
fi

# Locate clawcrate: prefer a local build (release then debug) so local changes
# are exercised, then fall back to an installed binary.
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
RELEASE_BIN="$REPO_ROOT/target/release/clawcrate"
DEBUG_BIN="$REPO_ROOT/target/debug/clawcrate"
if [[ -x "$RELEASE_BIN" ]]; then
  CLAWCRATE_BIN="$RELEASE_BIN"
  echo "Note: using local release build at $RELEASE_BIN"
elif [[ -x "$DEBUG_BIN" ]]; then
  CLAWCRATE_BIN="$DEBUG_BIN"
  echo "Note: using local debug build at $DEBUG_BIN"
  echo "      Run 'cargo build -p clawcrate-cli' first if this is stale."
elif command -v clawcrate &>/dev/null; then
  CLAWCRATE_BIN="clawcrate"
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
echo "Wrapping: node <server entrypoint installed in the workspace> ."
echo "Profile:  mcp-readonly"
echo "Workspace exposed to the server: $WORKSPACE"
echo ""

# `plan` resolves the policy without executing anything.
cd "$WORKSPACE"
"$CLAWCRATE_BIN" plan \
  --profile mcp-readonly \
  -- \
  node ./node_modules/@modelcontextprotocol/server-filesystem/dist/index.js .

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
    sockets. (This is why the package must be installed into the workspace
    BEFORE entering the sandbox.)

A secret is also planted OUTSIDE the workspace at secret-vault/api-key.txt. It
is neither copied into the Replica nor in the read allowlist, so the server
cannot reach it on either platform.

Run it live with ./demo.sh --live (needs Node.js and npm), or from a real MCP
client with ./launcher.sh (see README.md). After a wrapped run, inspect the
audit artifacts under:

  ~/.clawcrate/runs/<run-id>/
    plan.json      result.json    fs-diff.json
    audit.ndjson   stdout.log     stderr.log

  ls -t ~/.clawcrate/runs/ | head -1        # newest run id
EXPLAIN

if [[ "$LIVE" -eq 0 ]]; then
  echo ""
  echo "Re-run with --live to start the server inside the sandbox and drive it."
  exit 0
fi

# ---------------------------------------------------------------------------
# Live run: start the real MCP server inside the sandbox and drive it.
# ---------------------------------------------------------------------------

if ! command -v node &>/dev/null || ! command -v npm &>/dev/null; then
  echo ""
  echo "Skipping the live run: Node.js and npm are required." >&2
  exit 0
fi

echo ""
echo "=============================================================="
echo " Live run — real MCP server inside the sandbox"
echo "=============================================================="

# The server must be installed INTO the workspace. The sandbox grants read
# access to the workspace only, so a launcher that reaches outside it (such as
# npx, which reads its own launcher and package cache from the Node install)
# cannot start. Installing here keeps everything the server reads inside the
# sandbox.
if [[ ! -f "$WORKSPACE/$SERVER_ENTRYPOINT" ]]; then
  echo "Installing @modelcontextprotocol/server-filesystem into the workspace..."
  (cd "$WORKSPACE" && npm install --silent --no-save @modelcontextprotocol/server-filesystem)
fi

echo ""
echo "Driving the sandboxed server over JSON-RPC..."
echo ""

{
  printf '%s\n' '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"clawcrate-demo","version":"0"}}}'
  printf '%s\n' '{"jsonrpc":"2.0","method":"notifications/initialized"}'
  printf '%s\n' '{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"list_directory","arguments":{"path":"."}}}'
  printf '%s\n' '{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"read_text_file","arguments":{"path":"README.md"}}}'
  printf '%s\n' '{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"read_text_file","arguments":{"path":".env"}}}'
  sleep 2
} | (cd "$WORKSPACE" && "$CLAWCRATE_BIN" mcp wrap --profile mcp-readonly -- \
      node "$SERVER_ENTRYPOINT" .) 2>/dev/null | python3 -c '
import sys, json
for line in sys.stdin:
    line = line.strip()
    if not line:
        continue
    try:
        message = json.loads(line)
    except ValueError:
        continue
    request_id = message.get("id")
    result = message.get("result", {})
    text = ""
    if result:
        content = result.get("content", [{}])
        text = content[0].get("text", "") if content else ""
    if request_id == 2:
        entries = " | ".join(text.splitlines())
        print(f"  list_directory .   -> {entries}")
    elif request_id == 3:
        print(f"  read README.md     -> {text.strip()!r}")
    elif request_id == 4:
        leaked = "API_TOKEN" in text
        state = "LEAKED" if leaked else "not visible"
        print(f"  read .env          -> {state}")
'

cat <<'LIVE_NOTE'

What just happened:

  - The server listed and read the workspace through the sandbox.
  - `.env` is not in the listing and cannot be read: Replica Mode excluded it
    before the server started, so the secret never entered the sandbox.
  - The server was launched from a copy installed inside the workspace. `npx`
    cannot be used here, because it reads its own launcher and package cache
    from the Node installation, which is outside the read set.

Inspect the run:

  RUN=$(ls -t ~/.clawcrate/runs/ | head -1)
  cat ~/.clawcrate/runs/"$RUN"/audit.ndjson
LIVE_NOTE
