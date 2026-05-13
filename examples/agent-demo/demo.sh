#!/usr/bin/env bash
# ClawCrate Agent Demo — runs both scenarios end to end.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Require ANTHROPIC_API_KEY
if [[ -z "${ANTHROPIC_API_KEY:-}" ]]; then
  echo "Error: ANTHROPIC_API_KEY is not set." >&2
  exit 1
fi

# Locate clawcrate: prefer installed binary, fall back to cargo-built debug binary.
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
DEBUG_BIN="$REPO_ROOT/target/debug/clawcrate"
if command -v clawcrate &>/dev/null; then
  export CLAWCRATE_BIN="clawcrate"
elif [[ -x "$DEBUG_BIN" ]]; then
  export CLAWCRATE_BIN="$DEBUG_BIN"
  echo "Note: using debug build at $DEBUG_BIN"
  echo "      Run 'cargo build -p clawcrate-cli' first if this is stale."
else
  echo "Error: clawcrate not found. Install from:" >&2
  echo "  https://github.com/manuelpenazuniga/ClawCrate/releases" >&2
  echo "Or build locally: cargo build -p clawcrate-cli" >&2
  exit 1
fi

echo "Using: $(CLAWCRATE_BIN="$CLAWCRATE_BIN" "$CLAWCRATE_BIN" --version 2>/dev/null || echo "$CLAWCRATE_BIN")"
echo ""

# Run the agent demo
cd "$SCRIPT_DIR"
python3 -m venv .venv --quiet
.venv/bin/pip install -q -r requirements.txt
.venv/bin/python3 agent.py
