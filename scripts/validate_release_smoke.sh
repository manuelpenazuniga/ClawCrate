#!/usr/bin/env bash
set -euo pipefail

REPO="${CLAWCRATE_REPO:-manuelpenazuniga/ClawCrate}"
VERSION="${CLAWCRATE_VERSION:-latest}"
REPORT_DIR="${CLAWCRATE_VALIDATE_REPORT_DIR:-}"
KEEP_TMP=0

usage() {
  cat <<'EOF'
Usage:
  bash scripts/validate_release_smoke.sh [--repo <owner/repo>] [--version <version|latest>] [--report-dir <path>] [--keep-tmp]

Examples:
  bash scripts/validate_release_smoke.sh
  bash scripts/validate_release_smoke.sh --version v0.1.0-alpha.2 --report-dir /tmp/clawcrate-release-smoke
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

fetch_to_file() {
  local url="$1"
  local out="$2"

  if command -v curl >/dev/null 2>&1; then
    curl -fsSL "$url" -o "$out"
    return
  fi

  if command -v wget >/dev/null 2>&1; then
    wget -qO "$out" "$url"
    return
  fi

  fail "curl or wget is required to download release assets"
}

fetch_text() {
  local url="$1"

  if command -v curl >/dev/null 2>&1; then
    curl -fsSL "$url"
    return
  fi

  if command -v wget >/dev/null 2>&1; then
    wget -qO- "$url"
    return
  fi

  fail "curl or wget is required to download release metadata"
}

resolve_tag() {
  if [[ "$VERSION" == "latest" ]]; then
    local api_url="https://api.github.com/repos/$REPO/releases/latest"
    local tag
    tag="$(
      fetch_text "$api_url" \
        | sed -n 's/.*"tag_name"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' \
        | head -n1
    )"
    [[ -n "$tag" ]] || fail "failed to resolve latest release tag for $REPO"
    printf '%s' "$tag"
    return
  fi

  case "$VERSION" in
    v*) printf '%s' "$VERSION" ;;
    *) printf 'v%s' "$VERSION" ;;
  esac
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
    --repo)
      REPO="${2:-}"
      shift 2
      ;;
    --version)
      VERSION="${2:-}"
      shift 2
      ;;
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

for command_name in awk bash find grep mktemp python3 sort tar; do
  need_cmd "$command_name"
done

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
    echo "error: release smoke validation failed; inspect report dir: $REPORT_DIR" >&2
  fi

  if [[ $KEEP_TMP -eq 1 || $PRESERVE_TMP -eq 1 ]]; then
    echo "==> preserving temp directory: $TMP_ROOT" >&2
    return
  fi

  rm -rf "$TMP_ROOT"
}
trap cleanup EXIT

TAG="$(resolve_tag)"
TMP_HOME="$TMP_ROOT/home"
WORKSPACE="$TMP_ROOT/workspace"
INSTALL_DIR="$TMP_HOME/.local/bin"
INSTALL_SCRIPT="$TMP_ROOT/install.sh"

mkdir -p "$TMP_HOME" "$WORKSPACE"
printf 'release-smoke\n' > "$WORKSPACE/input.txt"

report "downloading install.sh for $REPO@$TAG"
fetch_to_file "https://github.com/$REPO/releases/download/$TAG/install.sh" "$INSTALL_SCRIPT"
chmod +x "$INSTALL_SCRIPT"

report "installing release asset into isolated HOME"
HOME="$TMP_HOME" bash "$INSTALL_SCRIPT" \
  --repo "$REPO" \
  --version "$TAG" \
  --install-dir "$INSTALL_DIR" \
  >"$REPORT_DIR/install.stdout.log" \
  2>"$REPORT_DIR/install.stderr.log"

BIN="$INSTALL_DIR/clawcrate"
[[ -x "$BIN" ]] || fail "installed binary not found at '$BIN'"

report "capturing version"
"$BIN" --version > "$REPORT_DIR/version.txt"
ACTUAL_VERSION="$(awk '{print $2}' "$REPORT_DIR/version.txt")"
EXPECTED_VERSION="${TAG#v}"
[[ "$ACTUAL_VERSION" == "$EXPECTED_VERSION" ]] || fail "installed binary reports '$ACTUAL_VERSION' but release tag is '$TAG'"

report "running doctor, plan, and run"
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

printf '%s\n' "$TAG" > "$REPORT_DIR/tag.txt"
printf '%s\n' "$BIN" > "$REPORT_DIR/binary-path.txt"
printf '%s\n' "$TMP_HOME" > "$REPORT_DIR/tmp-home.txt"
printf '%s\n' "$WORKSPACE" > "$REPORT_DIR/workspace.txt"

report "release smoke validation passed for $REPO@$TAG"
echo "==> report dir: $REPORT_DIR"
