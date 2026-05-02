# ClawCrate Validation Operator Runbook

Date: `2026-05-02`

Purpose:

- explain exactly what Codex automates,
- explain exactly what the operator should do,
- and provide a repeatable validation flow for macOS and Linux.

This document is operational. It is intended for direct execution, not for discussion.

---

## 1. Validation Split

ClawCrate validation is divided into two tracks.

### Track A: Public Release Validation

This validates what an external user actually installs from GitHub Releases.

It answers:

- does `install.sh` work,
- do the published binaries work,
- do built-in profiles work without a local repo checkout,
- and does the release produce the expected artifacts.

### Track B: Engineering Validation

This validates the current repository state before a release is cut.

It answers:

- is the repo internally healthy,
- do formatting, clippy, and tests pass,
- does the locally built binary behave correctly,
- and is `main` or a candidate branch safe to release.

These tracks must remain separate.

If they are mixed conceptually, it becomes easy to have a correct repository and a broken public release.

---

## 2. What Codex Automates

Codex now automates two important parts of the plan.

### 2.1 `scripts/validate_engineering.sh`

This script is for repository validation before a release.

It runs:

- `cargo fmt --all -- --check`
- `cargo clippy --workspace --all-targets -- -D warnings`
- `cargo test --workspace`
- `cargo build --locked -p clawcrate-cli`
- local smoke commands for `doctor`, `plan`, and `run`
- artifact verification for the smoke run

Use it from the repository root:

```bash
bash scripts/validate_engineering.sh --report-dir /tmp/clawcrate-engineering-validation
```

### 2.2 `scripts/validate_release_smoke.sh`

This script is for validating the public release that users download.

It:

- resolves the release tag,
- downloads the published `install.sh`,
- installs the release into an isolated temporary `HOME`,
- runs `--version`, `doctor`, `plan`, and `run`,
- verifies the command output,
- and checks that all expected artifacts exist.

Use it manually like this:

```bash
bash scripts/validate_release_smoke.sh \
  --repo manuelpenazuniga/ClawCrate \
  --version latest \
  --report-dir /tmp/clawcrate-release-smoke
```

It is also wired into the GitHub `Release` workflow, so each published tag will now re-validate the released installer path on both Ubuntu and macOS.

---

## 3. What You Still Need To Do

Codex cannot fully replace operator validation.

You still need to:

- review and merge the PR that introduces the validation automation,
- run the manual validation on real macOS hardware,
- run the manual validation on a real Linux machine or a controlled Linux environment,
- inspect results when there is a failure,
- and decide whether a release is acceptable for publication.

The key reason is simple:

- CI can validate a lot,
- but ClawCrate is a native sandbox product,
- so the final trust signal still depends on real platform behavior.

---

## 4. Operator Workflow

Follow this order.

1. Review and merge the validation PR from GitHub.
2. Run engineering validation from the repository root.
3. If engineering validation passes, run public release validation.
4. Perform manual validation on real macOS.
5. Perform manual validation on real Linux.
6. If both manual validations pass, treat the release flow as validated.

---

## 5. Step 1: Review And Merge The PR

When Codex provides the PR:

1. open the PR in GitHub,
2. confirm that it only changes:
   - `scripts/validate_release_smoke.sh`
   - `scripts/validate_engineering.sh`
   - `.github/workflows/release.yml`
   - `docs/validation-operator-runbook-2026-05-02.md`
3. verify that the release smoke script validates:
   - `--version`
   - `doctor`
   - `plan --profile safe`
   - `run --profile safe`
   - required artifacts
4. verify that the workflow uploads the smoke report even if validation fails
5. merge the PR manually from GitHub

Do not skip this review.

This change is small in code size, but it modifies release confidence directly.

---

## 6. Step 2: Run Engineering Validation Yourself

Run this from the repository root:

```bash
bash scripts/validate_engineering.sh --report-dir /tmp/clawcrate-engineering-validation
```

What this should do:

- validate formatting
- validate clippy
- validate the workspace tests
- build the CLI locally
- run `doctor`, `plan`, and `run`
- check that the expected artifacts exist

What you should inspect:

- that the script exits successfully
- that `/tmp/clawcrate-engineering-validation` exists
- that the directory contains:
  - `doctor.json`
  - `plan.json`
  - `run.json`
  - `version.txt`
  - `run-artifacts/`

If it fails, stop there and inspect the report directory before doing release validation.

---

## 7. Step 3: Run Public Release Validation Yourself

Run:

```bash
bash scripts/validate_release_smoke.sh \
  --repo manuelpenazuniga/ClawCrate \
  --version latest \
  --report-dir /tmp/clawcrate-release-smoke
```

What this should do:

- download the installer from the release assets
- install the public binary into a temporary isolated home
- run `doctor`, `plan`, and `run`
- verify output
- verify artifact generation

What you should inspect:

- that the script exits successfully
- that `/tmp/clawcrate-release-smoke` contains:
  - `install.stdout.log`
  - `install.stderr.log`
  - `version.txt`
  - `doctor.json`
  - `plan.json`
  - `run.json`
  - `run-artifacts/`

Critical expectation:

- the public release must work even if the repository is not checked out locally

This is the exact class of issue that already caused pain before.

---

## 8. Step 4: Manual Validation On Real macOS

This step matters because ClawCrate is explicitly not a VM-based system.

The product thesis depends on native macOS process execution under Seatbelt, especially on Apple Silicon.

### 8.1 Prepare A Clean Shell Session

Open a new terminal and verify what is currently in `PATH`:

```bash
which clawcrate || true
clawcrate --version || true
```

This is only to understand whether an older binary is already installed.

### 8.2 Create A Temporary Home

```bash
TMP_HOME="$(mktemp -d)"
echo "$TMP_HOME"
```

### 8.3 Install From The Latest Public Release

```bash
HOME="$TMP_HOME" sh -c 'curl -fsSL https://github.com/manuelpenazuniga/ClawCrate/releases/latest/download/install.sh | sh'
```

### 8.4 Verify That The Binary Exists

```bash
ls -l "$TMP_HOME/.local/bin/clawcrate"
```

### 8.5 Verify The Version

```bash
"$TMP_HOME/.local/bin/clawcrate" --version
```

The reported version must match the latest release tag.

### 8.6 Run `doctor`

```bash
HOME="$TMP_HOME" "$TMP_HOME/.local/bin/clawcrate" doctor
HOME="$TMP_HOME" "$TMP_HOME/.local/bin/clawcrate" doctor --json | tee "$TMP_HOME/doctor.json"
```

What to check:

- platform is macOS
- Seatbelt is reported as available
- the command succeeds without odd runtime failures

### 8.7 Run `plan`

```bash
HOME="$TMP_HOME" "$TMP_HOME/.local/bin/clawcrate" plan --profile safe -- echo hello
HOME="$TMP_HOME" "$TMP_HOME/.local/bin/clawcrate" plan --profile safe --json -- echo hello | tee "$TMP_HOME/plan.json"
```

What to check:

- the built-in profile resolves correctly
- the command does not require any repo-local path
- the command succeeds

### 8.8 Run `run`

```bash
HOME="$TMP_HOME" "$TMP_HOME/.local/bin/clawcrate" run --profile safe -- echo hello
HOME="$TMP_HOME" "$TMP_HOME/.local/bin/clawcrate" run --profile safe --json -- echo hello | tee "$TMP_HOME/run.json"
```

What to check:

- the command succeeds
- it does not terminate with `Killed`
- the result status is success

### 8.9 Inspect Artifacts

```bash
find "$TMP_HOME/.clawcrate/runs" -maxdepth 3 -type f | sort
LATEST_RUN="$(find "$TMP_HOME/.clawcrate/runs" -mindepth 1 -maxdepth 1 -type d | sort | tail -n 1)"
echo "$LATEST_RUN"
find "$LATEST_RUN" -maxdepth 2 -type f | sort
cat "$LATEST_RUN/stdout.log"
```

Required files:

- `plan.json`
- `result.json`
- `stdout.log`
- `stderr.log`
- `audit.ndjson`
- `fs-diff.json`

What to confirm:

- `stdout.log` contains the expected output
- nothing is silently missing

---

## 9. Step 5: Manual Validation On Real Linux

Repeat the same logic on Linux.

### 9.1 Confirm Platform Information

```bash
uname -a
```

Record this if there is a failure.

### 9.2 Create A Temporary Home

```bash
TMP_HOME="$(mktemp -d)"
echo "$TMP_HOME"
```

### 9.3 Install From The Latest Public Release

```bash
HOME="$TMP_HOME" sh -c 'curl -fsSL https://github.com/manuelpenazuniga/ClawCrate/releases/latest/download/install.sh | sh'
```

### 9.4 Verify The Binary

```bash
ls -l "$TMP_HOME/.local/bin/clawcrate"
"$TMP_HOME/.local/bin/clawcrate" --version
```

### 9.5 Run `doctor`

```bash
HOME="$TMP_HOME" "$TMP_HOME/.local/bin/clawcrate" doctor
HOME="$TMP_HOME" "$TMP_HOME/.local/bin/clawcrate" doctor --json | tee "$TMP_HOME/doctor.json"
```

What to check:

- platform is Linux
- capability reporting is coherent
- the command succeeds

### 9.6 Run `plan`

```bash
HOME="$TMP_HOME" "$TMP_HOME/.local/bin/clawcrate" plan --profile safe -- echo hello
HOME="$TMP_HOME" "$TMP_HOME/.local/bin/clawcrate" plan --profile safe --json -- echo hello | tee "$TMP_HOME/plan.json"
```

### 9.7 Run `run`

```bash
HOME="$TMP_HOME" "$TMP_HOME/.local/bin/clawcrate" run --profile safe -- echo hello
HOME="$TMP_HOME" "$TMP_HOME/.local/bin/clawcrate" run --profile safe --json -- echo hello | tee "$TMP_HOME/run.json"
```

### 9.8 Inspect Artifacts

```bash
find "$TMP_HOME/.clawcrate/runs" -maxdepth 3 -type f | sort
LATEST_RUN="$(find "$TMP_HOME/.clawcrate/runs" -mindepth 1 -maxdepth 1 -type d | sort | tail -n 1)"
echo "$LATEST_RUN"
find "$LATEST_RUN" -maxdepth 2 -type f | sort
cat "$LATEST_RUN/stdout.log"
```

What to confirm:

- required artifacts exist
- output is correct
- no path-resolution bug appears

---

## 10. If Something Fails

If any step fails, capture exactly this information and send it to Codex:

1. platform:

```bash
uname -a
```

2. version:

```bash
"$TMP_HOME/.local/bin/clawcrate" --version
```

3. the full output of:

- `doctor`
- `plan`
- `run`

4. the artifact listing:

```bash
find "$LATEST_RUN" -maxdepth 2 -type f | sort
```

5. the content of:

- `result.json`
- `stderr.log`

This is the minimum evidence required for fast diagnosis.

---

## 11. What “Good” Looks Like

The flow should be considered healthy only if all of this is true:

- engineering validation passes
- release smoke validation passes
- macOS manual validation passes
- Linux manual validation passes
- built-in profiles work with no local repo dependency
- version output matches the published release
- all expected artifacts exist
- the release path and the source path behave consistently

If even one of these fails, do not treat the release path as verified.
