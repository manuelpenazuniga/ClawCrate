# Alpha Release Checklist

This checklist is the operational guide for `M5-06`:
execute alpha release criteria and publish a tagged release with artifacts.

## 1. Preconditions

- Work from a clean local repository.
- Ensure `main` is synchronized with `origin/main`.
- Confirm the release issue is in scope:
  `https://github.com/manuelpenazuniga/ClawCrate/issues/40`.

Commands:

```bash
git fetch --all --prune
git switch main
git pull --ff-only
git status -sb
git rev-parse main origin/main
```

Expected:
- `git status -sb` shows `## main...origin/main`.
- `git rev-parse` returns the same commit hash twice.

## 2. Validate Release Criteria

Run the full quality gate before creating a tag:

```bash
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
```

Optional local packaging sanity check:

```bash
cargo build -p clawcrate-cli
bash scripts/release.sh package \
  --target x86_64-unknown-linux-musl \
  --binary target/debug/clawcrate \
  --dist-dir /tmp/clawcrate-dist-local
bash scripts/release.sh checksums --dist-dir /tmp/clawcrate-dist-local
```

Script hardening spot checks (`#109`):

```bash
# cut_release.sh rejects missing --tag value before shifting args
if bash scripts/cut_release.sh --tag --skip-verify; then
  echo "unexpected success"
  exit 1
fi

# release.sh cleans temporary package dir on failure
cargo build -p clawcrate-cli
tmp_root="$(mktemp -d)"
readonly_dist="$tmp_root/readonly-dist"
mkdir -p "$readonly_dist"
chmod 0555 "$readonly_dist"
before_tmp_dirs="$(find "${TMPDIR:-/tmp}" -maxdepth 1 -name 'clawcrate-release.*' | sort)"
if bash scripts/release.sh package \
  --target x86_64-unknown-linux-musl \
  --binary target/debug/clawcrate \
  --dist-dir "$readonly_dist"; then
  echo "unexpected success"
  exit 1
fi
after_tmp_dirs="$(find "${TMPDIR:-/tmp}" -maxdepth 1 -name 'clawcrate-release.*' | sort)"
if [ "$before_tmp_dirs" != "$after_tmp_dirs" ]; then
  echo "unexpected leftover clawcrate-release temp directory"
  exit 1
fi
chmod 0755 "$readonly_dist"
rm -rf "$tmp_root"
```

## 3. Update Changelog

- Update `[Unreleased]` in [`CHANGELOG.md`](../CHANGELOG.md).
- Add a new version section with date and key user-visible changes.

## 4. Create and Push Tag

Use the helper script:

```bash
bash scripts/cut_release.sh --tag v0.1.0-alpha.0 --push
```

What it enforces:
- clean working tree
- explicit dirty-entry output when tree is not clean
- `main` branch only
- local `main` equals `origin/main`
- remote tag collision check (fails if tag already exists on `origin`)
- required release artifact paths exist (`scripts/release.sh`, `scripts/install.sh`, `.github/workflows/release.yml`)
- local quality gate (`fmt`, `clippy`, `test`)
- annotated tag creation
- optional remote push

## 5. Publish Artifacts (GitHub Actions)

After tag push:
- Workflow [`Release`](../.github/workflows/release.yml) runs automatically.
- It builds and uploads:
  - `clawcrate-x86_64-unknown-linux-musl.tar.gz`
  - `clawcrate-aarch64-unknown-linux-musl.tar.gz`
  - `clawcrate-aarch64-apple-darwin.tar.gz`
  - `SHA256SUMS`
  - `scripts/install.sh`

## 5b. Attach the Intel macOS build (manual, from an Intel Mac)

`x86_64-apple-darwin` is **not** built by the hosted runners. Until it is, the
release is incomplete for Intel Macs and this step is not optional:
`install.sh` requires a checksum entry for the asset it downloads and exits
rather than installing without one. So an Intel user gets a hard failure, not an
unverified install — and uploading the tarball without merging its checksum
leaves them in exactly that state.

Run this on the Intel Mac, after the workflow above has finished:

```bash
bash scripts/release.sh attach-local --tag vX.Y.Z --target x86_64-apple-darwin
```

It builds the target, packages it, downloads the published `SHA256SUMS`, merges
this archive's line into it, and uploads both. It merges rather than
regenerating, because regenerating from a machine that only built one target
would drop every other platform's line and break their installs instead of
fixing this one. Re-running after a rebuild replaces the entry rather than
adding a second, contradictory one.

## 6. Post-Release Verification

- Confirm GitHub Release exists for the pushed tag.
- Verify all expected assets are attached, **including the manually attached
  `clawcrate-x86_64-apple-darwin.tar.gz`**.
- Confirm `SHA256SUMS` has one line per attached archive. A missing line means
  that platform cannot install at all.
- Smoke test installer:

```bash
curl -fsSL https://raw.githubusercontent.com/manuelpenazuniga/ClawCrate/main/scripts/install.sh | sh
clawcrate --version
```

- Close the release issue via merge automation (`Closes #40`) or manually if needed.
