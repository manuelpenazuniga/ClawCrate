#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'EOF'
Usage:
  bash scripts/cut_release.sh --tag <vX.Y.Z[-alpha.N]> [--push] [--skip-verify]

Options:
  --tag           Release tag to create (required).
  --push          Push created tag to origin.
  --skip-verify   Skip cargo fmt/clippy/test gate.
EOF
}

TAG=""
PUSH=0
SKIP_VERIFY=0

while [[ $# -gt 0 ]]; do
  case "$1" in
    --tag)
      TAG="${2:-}"
      shift 2
      ;;
    --push)
      PUSH=1
      shift
      ;;
    --skip-verify)
      SKIP_VERIFY=1
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "error: unknown argument '$1'" >&2
      usage >&2
      exit 1
      ;;
  esac
done

if [[ -z "$TAG" ]]; then
  echo "error: --tag is required" >&2
  usage >&2
  exit 1
fi

if [[ ! "$TAG" =~ ^v[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.-]+)?$ ]]; then
  echo "error: tag '$TAG' does not look like semver (expected e.g. v0.1.0-alpha.0)" >&2
  exit 1
fi

require_cmd() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "error: required command '$1' is not installed" >&2
    exit 1
  fi
}

require_cmd git
require_cmd cargo

current_branch="$(git rev-parse --abbrev-ref HEAD)"
if [[ "$current_branch" != "main" ]]; then
  echo "error: release must be cut from 'main' (current: $current_branch)" >&2
  exit 1
fi

if [[ -n "$(git status --porcelain)" ]]; then
  echo "error: working tree is not clean; commit/stash changes first" >&2
  exit 1
fi

local_main="$(git rev-parse main)"
remote_main="$(git rev-parse origin/main)"
if [[ "$local_main" != "$remote_main" ]]; then
  echo "error: local main ($local_main) is not synchronized with origin/main ($remote_main)" >&2
  echo "hint: run 'git fetch --all --prune && git pull --ff-only'" >&2
  exit 1
fi

if git rev-parse -q --verify "refs/tags/$TAG" >/dev/null; then
  echo "error: tag '$TAG' already exists locally" >&2
  exit 1
fi

if [[ "$SKIP_VERIFY" -eq 0 ]]; then
  echo "==> Running release quality gate"
  cargo fmt --all -- --check
  cargo clippy --workspace --all-targets -- -D warnings
  cargo test --workspace
else
  echo "==> Skipping release quality gate (--skip-verify)"
fi

echo "==> Creating annotated tag $TAG"
git tag -a "$TAG" -m "Release $TAG"

if [[ "$PUSH" -eq 1 ]]; then
  echo "==> Pushing tag $TAG to origin"
  git push origin "$TAG"
  echo "==> Done. GitHub Release workflow should start from tag push."
else
  echo "==> Tag created locally."
  echo "    Push with: git push origin $TAG"
fi
