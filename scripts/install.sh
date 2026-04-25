#!/usr/bin/env sh
set -eu

REPO="${CLAWCRATE_REPO:-manuelpenazuniga/ClawCrate}"
VERSION="${CLAWCRATE_VERSION:-latest}"
INSTALL_DIR="${CLAWCRATE_INSTALL_DIR:-$HOME/.local/bin}"
BIN_NAME="clawcrate"

usage() {
  cat <<'EOF'
Usage:
  sh install.sh [--version <version|latest>] [--install-dir <path>] [--repo <owner/repo>]

Examples:
  sh install.sh
  sh install.sh --version v0.1.0-alpha.0
  sh install.sh --install-dir "$HOME/bin"
EOF
}

while [ "$#" -gt 0 ]; do
  case "$1" in
    --version)
      VERSION="${2:-}"
      shift 2
      ;;
    --install-dir)
      INSTALL_DIR="${2:-}"
      shift 2
      ;;
    --repo)
      REPO="${2:-}"
      shift 2
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

need_cmd() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "error: required command '$1' is not installed" >&2
    exit 1
  fi
}

fetch_to_file() {
  url="$1"
  out="$2"
  if command -v curl >/dev/null 2>&1; then
    curl -fsSL "$url" -o "$out"
    return
  fi
  if command -v wget >/dev/null 2>&1; then
    wget -qO "$out" "$url"
    return
  fi
  echo "error: curl or wget is required to download artifacts" >&2
  exit 1
}

fetch_text() {
  url="$1"
  if command -v curl >/dev/null 2>&1; then
    curl -fsSL "$url"
    return
  fi
  if command -v wget >/dev/null 2>&1; then
    wget -qO- "$url"
    return
  fi
  echo "error: curl or wget is required to download release metadata" >&2
  exit 1
}

sha256_file() {
  file="$1"
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$file" | awk '{print $1}'
    return
  fi
  if command -v shasum >/dev/null 2>&1; then
    shasum -a 256 "$file" | awk '{print $1}'
    return
  fi
  if command -v openssl >/dev/null 2>&1; then
    openssl dgst -sha256 "$file" | awk '{print $2}'
    return
  fi
  echo "error: no SHA256 tool found (sha256sum/shasum/openssl)" >&2
  exit 1
}

detect_target() {
  os="$(uname -s)"
  arch="$(uname -m)"

  case "$os" in
    Linux) os_part="unknown-linux-musl" ;;
    Darwin) os_part="apple-darwin" ;;
    *)
      echo "error: unsupported OS '$os' (supported: Linux, Darwin)" >&2
      exit 1
      ;;
  esac

  case "$arch" in
    x86_64|amd64) arch_part="x86_64" ;;
    arm64|aarch64) arch_part="aarch64" ;;
    *)
      echo "error: unsupported architecture '$arch' (supported: x86_64, arm64/aarch64)" >&2
      exit 1
      ;;
  esac

  printf "%s-%s" "$arch_part" "$os_part"
}

resolve_tag() {
  if [ "$VERSION" = "latest" ]; then
    api_url="https://api.github.com/repos/$REPO/releases/latest"
    tag="$(
      fetch_text "$api_url" \
        | sed -n 's/.*"tag_name"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' \
        | head -n1
    )"
    if [ -z "$tag" ]; then
      echo "error: failed to resolve latest release tag for $REPO" >&2
      exit 1
    fi
    printf "%s" "$tag"
    return
  fi

  case "$VERSION" in
    v*) printf "%s" "$VERSION" ;;
    *) printf "v%s" "$VERSION" ;;
  esac
}

need_cmd tar
need_cmd awk
need_cmd grep

TARGET="$(detect_target)"
TAG="$(resolve_tag)"
ASSET_NAME="${BIN_NAME}-${TARGET}.tar.gz"
BASE_URL="https://github.com/$REPO/releases/download/$TAG"

TMP_DIR="$(mktemp -d)"
cleanup() {
  rm -rf "$TMP_DIR"
}
trap cleanup EXIT INT TERM

ARCHIVE_PATH="$TMP_DIR/$ASSET_NAME"
CHECKSUMS_PATH="$TMP_DIR/SHA256SUMS"

echo "==> Installing $BIN_NAME"
echo "    repo: $REPO"
echo "    tag: $TAG"
echo "    target: $TARGET"
echo "    install dir: $INSTALL_DIR"

fetch_to_file "$BASE_URL/$ASSET_NAME" "$ARCHIVE_PATH"
fetch_to_file "$BASE_URL/SHA256SUMS" "$CHECKSUMS_PATH"

expected_sum="$(
  awk -v asset="$ASSET_NAME" '
    NF >= 2 {
      filename = $2
      sub(/^[*]/, "", filename)
      if (filename == asset) {
        print $1
        exit
      }
    }
  ' "$CHECKSUMS_PATH"
)"
if [ -z "$expected_sum" ]; then
  echo "error: checksum entry not found for $ASSET_NAME" >&2
  exit 1
fi

actual_sum="$(sha256_file "$ARCHIVE_PATH")"
if [ "$expected_sum" != "$actual_sum" ]; then
  echo "error: checksum verification failed for $ASSET_NAME" >&2
  echo "expected: $expected_sum" >&2
  echo "actual:   $actual_sum" >&2
  exit 1
fi

mkdir -p "$INSTALL_DIR"
tar -xzf "$ARCHIVE_PATH" -C "$TMP_DIR"

if command -v install >/dev/null 2>&1; then
  install -m 0755 "$TMP_DIR/$BIN_NAME" "$INSTALL_DIR/$BIN_NAME"
else
  cp "$TMP_DIR/$BIN_NAME" "$INSTALL_DIR/$BIN_NAME"
  chmod 0755 "$INSTALL_DIR/$BIN_NAME"
fi

echo "==> Installed to $INSTALL_DIR/$BIN_NAME"
if ! command -v "$BIN_NAME" >/dev/null 2>&1; then
  echo "note: '$INSTALL_DIR' is not in PATH for this shell session." >&2
  echo "      add: export PATH=\"$INSTALL_DIR:\$PATH\"" >&2
fi

"$INSTALL_DIR/$BIN_NAME" --version
