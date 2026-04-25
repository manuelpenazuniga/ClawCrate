#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'EOF'
Usage:
  bash scripts/release.sh package --target <target-triple> --binary <binary-path> [--dist-dir <dir>]
  bash scripts/release.sh checksums [--dist-dir <dir>]

Commands:
  package    Create clawcrate-<target>.tar.gz from a built binary.
  checksums  Generate SHA256SUMS for all clawcrate-*.tar.gz files in the dist dir.
EOF
}

need_cmd() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "error: required tool '$1' is not installed" >&2
    exit 1
  fi
}

sha256_cmd() {
  if command -v sha256sum >/dev/null 2>&1; then
    echo "sha256sum"
    return
  fi
  if command -v shasum >/dev/null 2>&1; then
    echo "shasum -a 256"
    return
  fi
  echo ""
}

package_cmd() {
  local target=""
  local binary=""
  local dist_dir="dist"

  while [[ $# -gt 0 ]]; do
    case "$1" in
      --target)
        target="${2:-}"
        shift 2
        ;;
      --binary)
        binary="${2:-}"
        shift 2
        ;;
      --dist-dir)
        dist_dir="${2:-}"
        shift 2
        ;;
      *)
        echo "error: unknown argument for package: $1" >&2
        usage >&2
        exit 1
        ;;
    esac
  done

  if [[ -z "$target" || -z "$binary" ]]; then
    echo "error: package requires --target and --binary" >&2
    usage >&2
    exit 1
  fi

  if [[ ! -f "$binary" ]]; then
    echo "error: binary not found: $binary" >&2
    exit 1
  fi

  mkdir -p "$dist_dir"
  local archive_path="$dist_dir/clawcrate-${target}.tar.gz"

  (
    tmp_dir=""
    tmp_dir="$(mktemp -d "${TMPDIR:-/tmp}/clawcrate-release.XXXXXX")"
    trap 'rm -rf "$tmp_dir"' EXIT

    cp "$binary" "$tmp_dir/clawcrate"
    chmod 0755 "$tmp_dir/clawcrate"
    tar -C "$tmp_dir" -czf "$archive_path" clawcrate
  )
  echo "packaged: $archive_path"
}

checksums_cmd() {
  local dist_dir="dist"
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --dist-dir)
        dist_dir="${2:-}"
        shift 2
        ;;
      *)
        echo "error: unknown argument for checksums: $1" >&2
        usage >&2
        exit 1
        ;;
    esac
  done

  if [[ ! -d "$dist_dir" ]]; then
    echo "error: dist directory not found: $dist_dir" >&2
    exit 1
  fi

  local cmd
  cmd="$(sha256_cmd)"
  if [[ -z "$cmd" ]]; then
    echo "error: no SHA256 command found (sha256sum or shasum)" >&2
    exit 1
  fi

  shopt -s nullglob
  local archives=("$dist_dir"/clawcrate-*.tar.gz)
  shopt -u nullglob

  if [[ "${#archives[@]}" -eq 0 ]]; then
    echo "error: no release archives found under $dist_dir" >&2
    exit 1
  fi

  (
    cd "$dist_dir"
    rm -f SHA256SUMS
    if [[ "$cmd" == "sha256sum" ]]; then
      sha256sum clawcrate-*.tar.gz > SHA256SUMS
    else
      shasum -a 256 clawcrate-*.tar.gz > SHA256SUMS
    fi
  )

  echo "generated: $dist_dir/SHA256SUMS"
}

main() {
  if [[ $# -lt 1 ]]; then
    usage
    exit 1
  fi

  need_cmd tar
  need_cmd cp
  need_cmd chmod

  local command="$1"
  shift

  case "$command" in
    package)
      package_cmd "$@"
      ;;
    checksums)
      checksums_cmd "$@"
      ;;
    -h|--help)
      usage
      ;;
    *)
      echo "error: unknown command '$command'" >&2
      usage >&2
      exit 1
      ;;
  esac
}

main "$@"
