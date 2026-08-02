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
# Deliberately outside the workspace: the sandbox materializes only the
# workspace, so nothing here is ever copied into the Replica.
VAULT="$SCRIPT_DIR/secret-vault"
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
  printf '%s\n' "{\"jsonrpc\":\"2.0\",\"id\":5,\"method\":\"tools/call\",\"params\":{\"name\":\"read_text_file\",\"arguments\":{\"path\":\"$VAULT/api-key.txt\"}}}"
  # Keep stdin open while the server starts and answers. Node startup plus
  # Replica materialization can take a while on a cold or loaded machine.
  sleep "${CLAWCRATE_DEMO_WAIT_SECONDS:-8}"
} | (cd "$WORKSPACE" && "$CLAWCRATE_BIN" mcp wrap --profile mcp-readonly -- \
      node "$SERVER_ENTRYPOINT" . "$VAULT") 2>/dev/null | python3 -c '
import sys, json

SECRET_MARKER = "API_TOKEN"
SECRET_MARKER_VAULT = "planted-secret-do-not-exfiltrate"
# Replies arrive as each call finishes, which is not the order that reads as a
# story. Collected by request id and printed in order once the server is done.
lines = {}


def call_result(message):
    # (text, is_error) for a tools/call reply, or (None, None) if malformed.
    if "error" in message:
        return message["error"].get("message", "no message"), True
    result = message.get("result")
    if not isinstance(result, dict):
        return None, None
    content = result.get("content") or []
    text = content[0].get("text", "") if content else ""
    # The filesystem server reports a refused or missing path as a result with
    # `isError`, not as a JSON-RPC error.
    return text, bool(result.get("isError"))


for line in sys.stdin:
    line = line.strip()
    if not line:
        continue
    try:
        message = json.loads(line)
    except ValueError:
        continue

    request_id = message.get("id")
    if request_id not in (2, 3, 4, 5):
        continue
    text, is_error = call_result(message)

    if request_id == 2:
        entries = " | ".join(text.splitlines()) if text and not is_error else "FAILED"
        lines[2] = f"  list_directory .   -> {entries}"
    elif request_id == 3:
        lines[3] = (
            f"  read README.md     -> {text.strip()[:56]!r}..."
            if text and not is_error
            else "  read README.md     -> FAILED (the workspace should be readable)"
        )
    elif request_id == 4:
        # Each outcome is reported distinctly. Collapsing them would make this
        # line unfalsifiable: a crashed server would look like an enforced
        # denial, which is exactly the claim the demo exists to demonstrate.
        if text is None:
            lines[4] = "  read .env          -> UNKNOWN (malformed response)"
        elif is_error:
            lines[4] = f"  read .env          -> not in the sandbox ({text.strip()[:40]})"
        elif SECRET_MARKER in text:
            lines[4] = f"  read .env          -> LEAKED ({text.strip()[:40]!r})"
        else:
            lines[4] = f"  read .env          -> UNEXPECTED ({text.strip()[:40]!r})"
    elif request_id == 5:
        # The server was handed this directory as one of its own allowed roots,
        # so its policy permits the read. Anything that stops it is the sandbox.
        if text is None:
            lines[5] = "  read secret-vault  -> UNKNOWN (malformed response)"
        elif is_error:
            lines[5] = f"  read secret-vault  -> blocked by the sandbox ({text.strip()[:40]})"
        elif SECRET_MARKER_VAULT in text:
            lines[5] = f"  read secret-vault  -> LEAKED ({text.strip()[:40]!r})"
        else:
            lines[5] = f"  read secret-vault  -> UNEXPECTED ({text.strip()[:40]!r})"

labels = {
    2: "list_directory .",
    3: "read README.md",
    4: "read .env",
    5: "read secret-vault",
}
for request_id in (2, 3, 4, 5):
    print(
        lines.get(
            request_id,
            f"  {labels[request_id]:<18} -> NO RESPONSE (the server did not reply; see stderr)",
        )
    )
'

cat <<'LIVE_NOTE'

What just happened — two different defences, doing two different jobs:

  1. `.env` was never in the sandbox. Replica Mode filtered it out before the
     server started, so there was nothing to read. This is deterministic: it
     depends on what ClawCrate copied, not on catching an access.

  2. `secret-vault/` was blocked by the kernel. The server was handed that
     directory as one of its own allowed roots, so its policy permitted the
     read and it went ahead and tried. The sandbox refused it anyway. That
     separation matters: the block came from ClawCrate, not from the server
     being well behaved.

LIVE_NOTE

# ---------------------------------------------------------------------------
# The audit trail, and whether it verifies.
# ---------------------------------------------------------------------------

RUN_DIR=$(ls -td "$HOME"/.clawcrate/runs/*/ 2>/dev/null | head -1)
RUN_ID=$(basename "${RUN_DIR%/}")

echo "Audit trail for run $RUN_ID:"
echo ""

python3 - "$RUN_DIR/audit.ndjson" <<'AUDIT'
import json
import sys

path = sys.argv[1]
excluded = []
blocked = []
try:
    with open(path, encoding="utf-8") as handle:
        for line in handle:
            line = line.strip()
            if not line:
                continue
            try:
                event = json.loads(line).get("event", {})
            except ValueError:
                continue
            if "ReplicaCreated" in event:
                excluded = event["ReplicaCreated"].get("excluded", [])
            elif "PermissionBlocked" in event:
                entry = event["PermissionBlocked"]
                blocked.append((entry.get("resource", "?"), entry.get("reason", "?")))
except OSError as error:
    print(f"  could not read the audit trail: {error}")
    raise SystemExit(0)

print(f"  excluded from the Replica -> {', '.join(excluded) if excluded else '(none)'}")
if blocked:
    for resource, reason in blocked:
        print(f"  PermissionBlocked        -> {resource}  ({reason})")
else:
    print("  PermissionBlocked        -> (none recorded for this run)")
AUDIT

cat <<'COVERAGE'

  What lands in `audit.ndjson` differs by platform, and the difference is a
  property of the operating systems rather than of ClawCrate:

    - Refused outbound connections are recorded exactly, on both platforms.
    - Refused syscalls are recorded exactly on Linux.
    - Refused file reads are recorded on macOS best-effort — the kernel drops
      some reports — and not at all on Linux, where Landlock tells the child
      `EACCES` and nobody else.

  So an entry proves a denial happened. Its absence does not prove none did.
  The block itself is not in question either way: the read failed every time.

COVERAGE

echo "Verifying the audit chain..."
echo ""
CLAWCRATE_AUDIT_HASHCHAIN=1 "$CLAWCRATE_BIN" verify "$RUN_ID" || true

cat <<'LIVE_NOTE'

Inspect the run yourself:

  RUN=$(ls -t ~/.clawcrate/runs/ | head -1)
  cat ~/.clawcrate/runs/"$RUN"/audit.ndjson
LIVE_NOTE
