#!/bin/sh
# Launch @modelcontextprotocol/server-filesystem sandboxed behind ClawCrate.
#
# This is the script a real MCP client (Cursor, Claude Desktop, Continue.dev)
# points its `command` at. It changes into the workspace directory, then execs
# `clawcrate mcp wrap --profile mcp-readonly`, so the filesystem server runs
# inside a read-only Replica of that directory with secrets filtered out and
# outbound network blocked.
#
# Usage:
#   launcher.sh [WORKSPACE_DIR] [RELATIVE_PATH ...]
#
# With no arguments it exposes this demo's ./workspace directory. The filesystem
# server arguments stay relative (default "."), which resolves to the
# materialized Replica workspace.
#
# The server is launched from a copy installed *inside* the workspace, not
# through `npx`. That is deliberate: the sandbox grants read access to the
# workspace only, and `npx` has to read its own launcher and package cache from
# outside it, so it cannot start. Installing the package into the workspace
# keeps everything the server reads inside the sandbox — which is both the only
# thing that works and the narrower grant.
#
#   cd <workspace> && npm install @modelcontextprotocol/server-filesystem
set -eu

# GUI apps do not inherit shell profiles; make common toolchains discoverable.
export PATH="/usr/local/bin:/opt/homebrew/bin:$HOME/.cargo/bin:$PATH"

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
SERVER_ENTRYPOINT="node_modules/@modelcontextprotocol/server-filesystem/dist/index.js"

# First argument is the workspace directory to expose; default to this demo's
# fixture workspace. Remaining arguments are relative paths for the server.
TARGET_DIR="${1:-$SCRIPT_DIR/workspace}"
if [ "$#" -gt 0 ]; then
  shift
fi
if [ "$#" -eq 0 ]; then
  set -- .
fi

cd "$TARGET_DIR"

if [ ! -f "$SERVER_ENTRYPOINT" ]; then
  echo "Error: $SERVER_ENTRYPOINT not found in $TARGET_DIR." >&2
  echo "Install the server into the workspace first:" >&2
  echo "  cd $TARGET_DIR && npm install @modelcontextprotocol/server-filesystem" >&2
  exit 1
fi

exec clawcrate mcp wrap \
  --profile mcp-readonly \
  -- \
  node "$SERVER_ENTRYPOINT" "$@"
