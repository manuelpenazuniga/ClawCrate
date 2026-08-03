#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'EOF'
Usage:
  bash scripts/release.sh package --target <target-triple> --binary <binary-path> [--dist-dir <dir>]
  bash scripts/release.sh checksums [--dist-dir <dir>]
  bash scripts/release.sh attach-local --tag <tag> --target <target-triple> [--dist-dir <dir>]

Commands:
  package       Create clawcrate-<target>.tar.gz from a built binary.
  checksums     Generate SHA256SUMS for all clawcrate-*.tar.gz files in the dist dir.
  attach-local  Build a target here, then upload it to an existing release and
                merge its line into the published SHA256SUMS.

`attach-local` exists because the installer requires a checksum entry and
refuses to install without one. Uploading an asset without updating SHA256SUMS
therefore does not produce an unverified install; it produces no install at all
for that platform. Doing both in one command is what keeps the manual step from
being left half-done.
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

# Prints the SHA-256 of a single file, using whichever tool this machine has.
# `sha256_cmd` above names the tool for the batch path; this wraps it for the
# one-file case so both paths agree on how a checksum is produced.
sha256_file() {
  local file="$1"
  local cmd
  cmd="$(sha256_cmd)"
  if [[ -z "$cmd" ]]; then
    echo "error: no SHA256 command found (sha256sum or shasum)" >&2
    exit 1
  fi
  # shellcheck disable=SC2086  # cmd may legitimately carry the `-a 256` flag.
  $cmd "$file" | awk '{print $1}'
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

attach_local_cmd() {
  local tag="" target="" dist_dir="dist"
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --tag)
        tag="${2:-}"
        shift 2
        ;;
      --target)
        target="${2:-}"
        shift 2
        ;;
      --dist-dir)
        dist_dir="${2:-}"
        shift 2
        ;;
      *)
        echo "error: unknown argument for attach-local: $1" >&2
        usage >&2
        exit 1
        ;;
    esac
  done

  if [[ -z "$tag" || -z "$target" ]]; then
    echo "error: attach-local requires --tag and --target" >&2
    usage >&2
    exit 1
  fi
  need_cmd cargo
  need_cmd gh

  local archive="clawcrate-${target}.tar.gz"

  echo "==> Building $target"
  cargo build --locked --release -p clawcrate-cli --target "$target"

  echo "==> Packaging $archive"
  package_cmd --target "$target" \
    --binary "target/${target}/release/clawcrate" \
    --dist-dir "$dist_dir"

  local checksum
  checksum="$(sha256_file "$dist_dir/$archive")"
  echo "==> sha256($archive) = $checksum"

  # Merge rather than regenerate: the published file covers the artifacts the
  # hosted runners built, which are not present here. Regenerating from this
  # machine's dist directory would silently drop every other platform's line
  # and break their installs instead of fixing this one.
  local published="$dist_dir/SHA256SUMS.published"
  echo "==> Fetching published SHA256SUMS for $tag"
  if ! gh release download "$tag" --pattern SHA256SUMS --output "$published" --clobber; then
    echo "error: $tag has no SHA256SUMS to merge into." >&2
    echo "       Nothing was uploaded. Every platform is currently uninstallable," >&2
    echo "       because the installer requires a checksum entry. Restore the file" >&2
    echo "       from the release workflow run before retrying." >&2
    exit 1
  fi

  # Same-name lines are replaced, so re-running after a rebuild corrects the
  # entry instead of leaving two contradictory ones.
  local merged="$dist_dir/SHA256SUMS"
  grep -v "  ${archive}\$" "$published" > "$merged" || true
  printf '%s  %s\n' "$checksum" "$archive" >> "$merged"
  LC_ALL=C sort -k2 -o "$merged" "$merged"
  rm -f "$published"

  # Uploaded in two steps, archive first, because `gh ... --clobber` deletes the
  # existing asset before sending the replacement. A failure partway through a
  # combined upload can therefore leave the release with no SHA256SUMS at all —
  # which does not merely break this platform, it makes every platform
  # uninstallable, since the installer refuses to proceed without one.
  #
  # Ordering it this way means the worst case is the state we started from: the
  # archive present but not yet listed, which fails closed for this platform
  # only. Learned the hard way on v0.3.0-alpha.0.
  echo "==> Uploading $archive"
  gh release upload "$tag" "$dist_dir/$archive" --clobber

  echo "==> Uploading the merged SHA256SUMS"
  gh release upload "$tag" "$merged" --clobber

  echo ""
  echo "==> Verifying every published asset against the published SHA256SUMS"
  local verify_dir="$dist_dir/verify"
  rm -rf "$verify_dir"
  mkdir -p "$verify_dir"
  (
    cd "$verify_dir"
    gh release download "$tag" --clobber >/dev/null
    if [[ "$(sha256_cmd)" == "sha256sum" ]]; then
      sha256sum -c SHA256SUMS
    else
      shasum -a 256 -c SHA256SUMS
    fi
  )

  echo ""
  echo "Attached $archive to $tag; all published assets verify."
  echo "Smoke test the installer from a clean machine before announcing:"
  echo "  curl -fsSL https://github.com/manuelpenazuniga/ClawCrate/releases/download/$tag/install.sh | bash"
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
    attach-local)
      attach_local_cmd "$@"
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
