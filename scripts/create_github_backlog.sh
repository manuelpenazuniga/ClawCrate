#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'EOF'
Usage:
  bash scripts/create_github_backlog.sh [--repo owner/repo] [--config docs/backlog.yaml] [--dry-run]

Options:
  --repo       Target repository in owner/name format (defaults to current gh repo)
  --config     YAML backlog source file (default: docs/backlog.yaml)
  --dry-run    Print intended actions without creating/updating resources
EOF
}

require_tool() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "Error: required tool '$1' is not installed." >&2
    exit 1
  fi
}

markdown_list_from_json() {
  local json="$1"
  jq -r '.[] | "- " + .' <<<"$json"
}

build_epic_body() {
  local objective="$1"
  local done_when_json="$2"
  local done_when_md
  done_when_md="$(markdown_list_from_json "$done_when_json")"

  cat <<EOF
## Objective
$objective

## Done When
$done_when_md
EOF
}

build_task_body() {
  local scope="$1"
  local parent_epic_url="$2"
  local done_when_json="$3"
  local done_when_md
  done_when_md="$(markdown_list_from_json "$done_when_json")"

  cat <<EOF
## Scope
$scope

## Parent Epic
$parent_epic_url

## Done When
$done_when_md
EOF
}

REPO=""
CONFIG_FILE="docs/backlog.yaml"
DRY_RUN=0

while [[ $# -gt 0 ]]; do
  case "$1" in
    --repo)
      REPO="${2:-}"
      shift 2
      ;;
    --config)
      CONFIG_FILE="${2:-}"
      shift 2
      ;;
    --dry-run)
      DRY_RUN=1
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "Unknown argument: $1" >&2
      usage
      exit 1
      ;;
  esac
done

require_tool gh
require_tool jq
require_tool ruby

if ! gh auth status >/dev/null 2>&1; then
  echo "Error: gh is not authenticated. Run 'gh auth login' first." >&2
  exit 1
fi

if [[ ! -f "$CONFIG_FILE" ]]; then
  echo "Error: config file not found: $CONFIG_FILE" >&2
  exit 1
fi

CONFIG_JSON="$(
  ruby -ryaml -rjson -e 'puts JSON.generate(YAML.load_file(ARGV[0]))' "$CONFIG_FILE"
)"

if [[ -z "$REPO" ]]; then
  REPO="$(gh repo view --json nameWithOwner --jq '.nameWithOwner')"
fi

if [[ -z "$REPO" ]]; then
  echo "Error: could not detect repository. Use --repo owner/name." >&2
  exit 1
fi

echo "Target repo: $REPO"
echo "Config file: $CONFIG_FILE"
if [[ "$DRY_RUN" -eq 1 ]]; then
  echo "Mode: dry-run"
fi

ensure_label() {
  local name="$1"
  local color="$2"
  local description="$3"

  if [[ "$DRY_RUN" -eq 1 ]]; then
    echo "[dry-run] label: $name"
    return
  fi

  gh label create "$name" \
    --repo "$REPO" \
    --color "$color" \
    --description "$description" \
    --force >/dev/null
}

milestone_exists() {
  local title="$1"
  gh api "repos/$REPO/milestones?state=all&per_page=100" \
    --jq ".[] | select(.title == \"$title\") | .number" | head -n 1
}

ensure_milestone() {
  local title="$1"
  local description="$2"

  if [[ -n "$(milestone_exists "$title" || true)" ]]; then
    echo "Milestone exists: $title"
    return
  fi

  if [[ "$DRY_RUN" -eq 1 ]]; then
    echo "[dry-run] milestone: $title"
    return
  fi

  gh api -X POST "repos/$REPO/milestones" \
    -f "title=$title" \
    -f "description=$description" >/dev/null

  echo "Milestone created: $title"
}

find_issue_url_by_backlog_id() {
  local backlog_id="$1"
  gh issue list \
    --repo "$REPO" \
    --state all \
    --search "backlog_id=$backlog_id in:body" \
    --limit 1 \
    --json url \
    --jq '.[0].url // empty'
}

ensure_issue() {
  local backlog_id="$1"
  local milestone="$2"
  local title="$3"
  local labels_json="$4"
  local body="$5"

  local existing_url
  existing_url="$(find_issue_url_by_backlog_id "$backlog_id" || true)"
  if [[ -n "$existing_url" ]]; then
    echo "Issue exists: $backlog_id -> $existing_url" >&2
    echo "$existing_url"
    return
  fi

  local final_body
  final_body="$body

---
backlog_id=$backlog_id
"

  if [[ "$DRY_RUN" -eq 1 ]]; then
    local fake_url="https://github.com/$REPO/issues/$backlog_id"
    echo "[dry-run] issue: $backlog_id - $title" >&2
    echo "$fake_url"
    return
  fi

  local -a args
  args=(issue create --repo "$REPO" --title "$title" --milestone "$milestone" --body "$final_body")

  local label
  while IFS= read -r label; do
    [[ -z "$label" ]] && continue
    args+=(--label "$label")
  done < <(jq -r '.[]' <<<"$labels_json")

  local created_url
  created_url="$(gh "${args[@]}")"
  echo "Issue created: $backlog_id -> $created_url" >&2
  echo "$created_url"
}

DEFAULT_TASK_DONE_WHEN_JSON='[
  "Implementation is merged with tests for impacted crate(s).",
  "`cargo fmt`, `cargo clippy`, and `cargo test` pass for impacted workspace members.",
  "Docs are updated if behavior or CLI output changed."
]'

echo "Ensuring labels..."
while IFS= read -r label_item; do
  name="$(jq -r '.name' <<<"$label_item")"
  color="$(jq -r '.color' <<<"$label_item")"
  description="$(jq -r '.description // ""' <<<"$label_item")"
  ensure_label "$name" "$color" "$description"
done < <(jq -c '.labels[]' <<<"$CONFIG_JSON")

echo "Ensuring milestones..."
while IFS= read -r milestone_item; do
  title="$(jq -r '.title' <<<"$milestone_item")"
  description="$(jq -r '.description // ""' <<<"$milestone_item")"
  ensure_milestone "$title" "$description"
done < <(jq -c '.milestones[]' <<<"$CONFIG_JSON")

echo "Creating epics..."
while IFS= read -r epic_item; do
  backlog_id="$(jq -r '.id' <<<"$epic_item")"
  milestone="$(jq -r '.milestone' <<<"$epic_item")"
  title="$(jq -r '.title' <<<"$epic_item")"
  objective="$(jq -r '.objective' <<<"$epic_item")"
  labels_json="$(jq -c '.labels // []' <<<"$epic_item")"
  done_when_json="$(jq -c '.done_when // []' <<<"$epic_item")"

  body="$(build_epic_body "$objective" "$done_when_json")"
  ensure_issue "$backlog_id" "$milestone" "$title" "$labels_json" "$body" >/dev/null
done < <(jq -c '.epics[]' <<<"$CONFIG_JSON")

echo "Creating issues..."
while IFS= read -r issue_item; do
  backlog_id="$(jq -r '.id' <<<"$issue_item")"
  milestone="$(jq -r '.milestone' <<<"$issue_item")"
  title="$(jq -r '.title' <<<"$issue_item")"
  scope="$(jq -r '.scope' <<<"$issue_item")"
  epic_id="$(jq -r '.epic' <<<"$issue_item")"
  labels_json="$(jq -c '.labels // []' <<<"$issue_item")"
  done_when_json="$(jq -c '.done_when // []' <<<"$issue_item")"
  if [[ "$(jq -r 'length' <<<"$done_when_json")" == "0" ]]; then
    done_when_json="$DEFAULT_TASK_DONE_WHEN_JSON"
  fi

  parent_epic_url="$(find_issue_url_by_backlog_id "$epic_id" || true)"
  if [[ -z "$parent_epic_url" ]]; then
    parent_epic_url="(Epic not found yet, expected backlog_id=$epic_id)"
  fi

  body="$(build_task_body "$scope" "$parent_epic_url" "$done_when_json")"
  ensure_issue "$backlog_id" "$milestone" "$title" "$labels_json" "$body" >/dev/null
done < <(jq -c '.issues[]' <<<"$CONFIG_JSON")

echo "Backlog creation completed."
