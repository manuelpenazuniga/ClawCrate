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
# The package must be installed/cached OUTSIDE ClawCrate first (the mcp-readonly
# profile is network: none, so `--no-install` cannot download it at runtime):
#
#   npm install -g @modelcontextprotocol/server-filesystem
set -eu

# GUI apps do not inherit shell profiles; make common toolchains discoverable.
export PATH="/usr/local/bin:/opt/homebrew/bin:$HOME/.cargo/bin:$PATH"

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

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
exec clawcrate mcp wrap \
  --profile mcp-readonly \
  -- \
  npx --no-install @modelcontextprotocol/server-filesystem "$@"
