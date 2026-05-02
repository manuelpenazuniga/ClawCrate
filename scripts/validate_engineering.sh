#!/usr/bin/env bash
set -euo pipefail

REPORT_DIR="${CLAWCRATE_VALIDATE_REPORT_DIR:-}"
KEEP_TMP=0

usage() {
  cat <<'EOF'
Usage:
  bash scripts/validate_engineering.sh [--report-dir <path>] [--keep-tmp]

Examples:
  bash scripts/validate_engineering.sh
  bash scripts/validate_engineering.sh --report-dir /tmp/clawcrate-engineering-validation
EOF
}

fail() {
  echo "error: $*" >&2
  exit 1
}

need_cmd() {
  command -v "$1" >/dev/null 2>&1 || fail "required command '$1' is not installed"
}

report() {
  echo "==> $*"
}

run_logged() {
  local label="$1"
  shift

  report "$label"
  "$@" >"$REPORT_DIR/${label}.stdout.log" 2>"$REPORT_DIR/${label}.stderr.log"
}

json_get() {
  local json_file="$1"
  local path="$2"

  python3 - "$json_file" "$path" <<'PY'
import json
import sys

with open(sys.argv[1], "r", encoding="utf-8") as handle:
    value = json.load(handle)

for key in sys.argv[2].split("."):
    value = value[key]

if isinstance(value, bool):
    print("true" if value else "false")
elif value is None:
    print("null")
else:
    print(value)
PY
}

validate_required_artifacts() {
  local artifacts_dir="$1"
  local required=(
    "plan.json"
    "result.json"
    "stdout.log"
    "stderr.log"
    "audit.ndjson"
    "fs-diff.json"
  )

  [[ -d "$artifacts_dir" ]] || fail "artifacts directory '$artifacts_dir' does not exist"

  local artifact
  for artifact in "${required[@]}"; do
    [[ -f "$artifacts_dir/$artifact" ]] || fail "missing required artifact '$artifact' in '$artifacts_dir'"
  done
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --report-dir)
      REPORT_DIR="${2:-}"
      shift 2
      ;;
    --keep-tmp)
      KEEP_TMP=1
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      usage >&2
      fail "unknown argument '$1'"
      ;;
  esac
done

for command_name in cargo find grep mktemp python3 sort; do
  need_cmd "$command_name"
done

[[ -f "Cargo.toml" ]] || fail "run this script from the repository root"

PRESERVE_TMP=0
TMP_ROOT="$(mktemp -d)"
if [[ -z "$REPORT_DIR" ]]; then
  REPORT_DIR="$TMP_ROOT/report"
  PRESERVE_TMP=1
fi
mkdir -p "$REPORT_DIR"

cleanup() {
  local exit_code=$?
  if [[ $exit_code -ne 0 ]]; then
    echo "error: engineering validation failed; inspect report dir: $REPORT_DIR" >&2
  fi

  if [[ $KEEP_TMP -eq 1 || $PRESERVE_TMP -eq 1 ]]; then
    echo "==> preserving temp directory: $TMP_ROOT" >&2
    return
  fi

  rm -rf "$TMP_ROOT"
}
trap cleanup EXIT

TMP_HOME="$TMP_ROOT/home"
WORKSPACE="$TMP_ROOT/workspace"
mkdir -p "$TMP_HOME" "$WORKSPACE"
printf 'engineering-smoke\n' > "$WORKSPACE/input.txt"

run_logged "cargo-fmt" cargo fmt --all -- --check
run_logged "cargo-clippy" cargo clippy --workspace --all-targets -- -D warnings
run_logged "cargo-test" cargo test --workspace
run_logged "cargo-build" cargo build --locked -p clawcrate-cli

BIN="$(pwd)/target/debug/clawcrate"
[[ -x "$BIN" ]] || fail "built binary not found at '$BIN'"

report "capturing local binary version"
"$BIN" --version > "$REPORT_DIR/version.txt"

report "running doctor, plan, and run from the local build"
(
  cd "$WORKSPACE"
  HOME="$TMP_HOME" "$BIN" doctor --json > "$REPORT_DIR/doctor.json"
  HOME="$TMP_HOME" "$BIN" plan --profile safe --json -- /bin/echo hello > "$REPORT_DIR/plan.json"
  HOME="$TMP_HOME" "$BIN" run --profile safe --json -- /bin/echo hello > "$REPORT_DIR/run.json"
)

ARTIFACTS_DIR="$(json_get "$REPORT_DIR/run.json" "result.artifacts_dir")"
RUN_STATUS="$(json_get "$REPORT_DIR/run.json" "result.status")"
[[ "$RUN_STATUS" == "Success" ]] || fail "run status is '$RUN_STATUS', expected 'Success'"

validate_required_artifacts "$ARTIFACTS_DIR"
grep -q "hello" "$ARTIFACTS_DIR/stdout.log" || fail "stdout.log does not contain the expected output"

find "$ARTIFACTS_DIR" -maxdepth 1 -type f | sort > "$REPORT_DIR/run-artifacts.txt"
mkdir -p "$REPORT_DIR/run-artifacts"
cp "$ARTIFACTS_DIR"/plan.json "$REPORT_DIR/run-artifacts/plan.json"
cp "$ARTIFACTS_DIR"/result.json "$REPORT_DIR/run-artifacts/result.json"
cp "$ARTIFACTS_DIR"/stdout.log "$REPORT_DIR/run-artifacts/stdout.log"
cp "$ARTIFACTS_DIR"/stderr.log "$REPORT_DIR/run-artifacts/stderr.log"
cp "$ARTIFACTS_DIR"/audit.ndjson "$REPORT_DIR/run-artifacts/audit.ndjson"
cp "$ARTIFACTS_DIR"/fs-diff.json "$REPORT_DIR/run-artifacts/fs-diff.json"

printf '%s\n' "$BIN" > "$REPORT_DIR/binary-path.txt"
printf '%s\n' "$TMP_HOME" > "$REPORT_DIR/tmp-home.txt"
printf '%s\n' "$WORKSPACE" > "$REPORT_DIR/workspace.txt"

report "engineering validation passed"
echo "==> report dir: $REPORT_DIR"
