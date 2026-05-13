# Codex Context - 2026-05-01

This document is a reentry context for Codex and other code-focused agents working on ClawCrate.

It is intentionally operational, not promotional.
It records:

- the current public and local state,
- the most important architectural invariants,
- the last critical fixes that changed behavior,
- the main technical notes that still matter,
- and the most rational next steps.

---

## 1. Snapshot

As of **2026-05-01**:

- Current branch expected for baseline work: `main`
- Current `main` commit at time of writing: `aeb27736078d4463b9814f932c553efd331ba920`
- Current workspace version in `Cargo.toml`: `0.1.0-alpha.2`
- Latest published GitHub Release: `v0.1.0-alpha.2`
- Latest release published at: `2026-04-30T21:58:51Z`
- Open GitHub issues: `0`
- Public install path: `https://github.com/manuelpenazuniga/ClawCrate/releases/latest/download/install.sh`

Important local-tree note at time of writing:

- The working tree is **not fully clean** because `docs/presentation-clawcrate-async-15-slides.md` is currently untracked.
- If the file is intended to remain in the repo, it should be committed before any future release cut.
- `scripts/cut_release.sh` requires a clean tree and will fail otherwise.

---

## 2. What ClawCrate Is Right Now

ClawCrate is a native command-execution sandbox for AI agents.

It is:

- a single Rust CLI per platform,
- an execution boundary around shell commands,
- native on Linux and macOS,
- deny-by-default,
- profile-driven,
- artifact-producing by default.

It is not:

- a VM,
- a container runtime,
- a model wrapper,
- or a full agent orchestration framework.

Current command surface implemented and documented:

- `clawcrate run`
- `clawcrate plan`
- `clawcrate doctor`
- `clawcrate api`
- `clawcrate bridge pennyprompt`

Current public positioning is broader than the original narrow alpha claim, because the repo now ships not only `run | plan | doctor` but also `api` and `bridge pennyprompt`, and the docs already reflect that.

---

## 3. Current Public Truth

The most important public-state fact is this:

- **Quickstart now works from the latest published release assets.**

That was not true earlier in the project history, but it is true now.

Verified release path:

1. `v0.1.0-alpha.2` was cut from synchronized `main`
2. GitHub Actions `Release` workflow completed successfully
3. Assets were published:
   - `clawcrate-aarch64-apple-darwin.tar.gz`
   - `clawcrate-x86_64-apple-darwin.tar.gz`
   - `clawcrate-aarch64-unknown-linux-musl.tar.gz`
   - `clawcrate-x86_64-unknown-linux-musl.tar.gz`
   - `install.sh`
   - `SHA256SUMS`
4. Smoke test from `releases/latest/download/install.sh` succeeded

The last validated smoke path was:

```bash
curl -fsSL https://github.com/manuelpenazuniga/ClawCrate/releases/latest/download/install.sh | sh
clawcrate --version
clawcrate doctor
clawcrate plan --profile safe -- echo hello
clawcrate run --profile safe -- echo hello
```

Observed status after `v0.1.0-alpha.2`:

- install: OK
- `--version`: OK, reports `0.1.0-alpha.2`
- `doctor`: OK
- `plan --profile safe`: OK
- `run --profile safe`: OK

This matters because it means the project has crossed the threshold from "repo looks solid" to "public install flow actually works."

---

## 4. Architecture Rules That Must Not Be Broken

These are the key invariants Codex should preserve unless the user explicitly wants an architectural change.

### 4.1 Deny by default

The sandbox starts with no permissions and receives only what the profile grants.

### 4.2 Platform-native sandboxing only

Linux:

- Landlock
- seccomp
- rlimits

macOS:

- Seatbelt via `sandbox-exec`
- rlimits

No Docker.
No VMs.
No root requirement.

### 4.3 Command boundary, not agent boundary

ClawCrate sandboxes the command that the agent wants to run.
It does not sandbox the entire agent process.

That is a deliberate design choice and a major product differentiator.

### 4.4 Profiles are the primary UX

Built-ins:

- `safe`
- `build`
- `install`
- `open`

Custom YAML is supported, but it is the escape hatch, not the primary interface.

### 4.5 `install` defaults to Replica mode

This is critical.
Do not casually change it.

The whole point is that installation workflows are high-risk because they often combine:

- write access,
- dependency execution,
- and network access.

### 4.6 `DefaultMode` and `WorkspaceMode` stay separate

Profile intent and runtime materialization are separate concepts.
That separation is a real architectural guardrail, not style preference.

### 4.7 File artifacts remain the source of truth

The execution record is filesystem-based:

- `plan.json`
- `result.json`
- `stdout.log`
- `stderr.log`
- `audit.ndjson`
- `fs-diff.json`

SQLite exists as optional post-alpha capability, but file artifacts remain the canonical execution evidence.

### 4.8 Linux limitation must remain explicit

Linux cannot reliably deny specific files inside an already-allowed workspace path the same way macOS Seatbelt regex deny can.

That is why Replica mode exists.
Do not overstate Linux intra-workspace deny guarantees.

---

## 5. What Changed Most Recently

The most important late-April fixes were not cosmetic.
They changed whether the public release was actually reliable.

### 5.1 Installed release binaries now resolve built-in profiles correctly

Recent issue/fix chain:

- problem: installed release binary could fail to resolve `safe|build|install|open`
- root cause: profile resolution depended on a compile-time repo path
- fix: built-in profile definitions are now embedded for release binaries

Practical effect:

- `clawcrate plan --profile safe -- ...` works from installed release assets
- no local source checkout is required for built-in profiles

### 5.2 macOS trivial runs no longer die as `Killed`

Recent issue/fix chain:

- problem: macOS sandboxed trivial commands could exit as `Killed`
- root cause: generated SBPL was missing baseline runtime allowances
- fix: generated Seatbelt profile now imports `system.sb`

Practical effect:

- trivial commands like `echo hello` now succeed under Seatbelt
- the release smoke path on macOS became trustworthy

### 5.3 Reported CLI version is now aligned with release versioning

Recent issue/fix chain:

- problem: release tag and CLI-reported version drifted apart
- root cause: release tag was bumped without bumping workspace package version first
- fix: workspace version bumped to `0.1.0-alpha.2` before cutting `v0.1.0-alpha.2`

Practical effect:

- `clawcrate --version` now matches the latest public release line

### 5.4 Release discipline improved in practice, not just on paper

Recent release sequence demonstrated the correct pattern:

1. merge functional fixes
2. merge release metadata/doc prep
3. merge version bump for next tag
4. cut tag from clean synchronized `main`
5. wait for release workflow
6. smoke test the published installer

That flow should now be treated as standard practice.

---

## 6. Operational Workflow Expected in This Repo

This repo follows an issue-first, PR-first workflow.

Important practical rule:

- Codex should not merge PRs directly.
- The user reviews and merges in GitHub.

Standard flow:

1. sync `main`
2. choose or create issue
3. create issue branch
4. implement only that scope
5. run validation
6. commit with conventional commit style
7. push branch
8. open PR with `Closes #...`
9. wait for user review and merge
10. sync `main` again

Useful commands:

```bash
git fetch --all --prune
git switch main
git pull --ff-only
git status -sb
gh issue list --state open
gh pr list --state open
```

Validation baseline:

```bash
cargo fmt --all
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
```

Release baseline:

```bash
bash scripts/cut_release.sh --tag v0.1.0-alpha.N --push
```

---

## 7. Technical Notes That Still Matter

These are the notes a new Codex session should remember before changing behavior.

### 7.1 The repo has exceeded the original narrow alpha scope

The current repo and docs effectively include:

- core alpha commands,
- community profiles,
- egress proxy / filtered network support,
- approval workflow,
- SQLite audit index,
- local API,
- PennyPrompt bridge,
- WSL2 compatibility reporting.

This is not necessarily bad, but it means:

- documentation and release notes must stay coherent,
- claims must be tied to implemented behavior,
- and "alpha" no longer means "minimal surface."

### 7.2 macOS matters strategically

This project is not trying to be Linux-only.

macOS support is a first-class product requirement because many local agent users are on Apple hardware.
ClawCrate's native Apple Silicon story is not fluff; it is part of the product thesis:

- no VM,
- no emulation,
- native process execution,
- native sandbox enforcement.

### 7.3 The release workflow is part of the product

For ClawCrate, installability is a core trust signal.

That means release work is not "ops afterthought."

If install script, version string, built-in profile resolution, or macOS Seatbelt trivial execution breaks, the public product is effectively broken.

### 7.4 The Gemini triage wave is closed

The document `docs/technical-note-gemini-disposition-pr163-pr190.md` records the disposition of Gemini findings across PRs `#163` to `#190`.

Important context:

- actionable follow-ups from that wave were turned into tracked issues
- those issues were executed and merged
- the tracker issue used for that remediation wave was closed

So that cleanup wave should be treated as completed, not still pending.

---

## 8. Current Inconsistencies and Documentation Drift

The repo is in a much stronger state than a week ago, but it is not perfectly tidy.

### 8.1 `CHANGELOG.md` is stale relative to `v0.1.0-alpha.2`

Current observed state:

- workspace version is `0.1.0-alpha.2`
- latest release tag is `v0.1.0-alpha.2`
- `CHANGELOG.md` has `0.1.0-alpha.1` as the latest explicit version section
- `[Unreleased]` is empty

Implication:

- public release notes are now slightly behind reality
- this should be corrected before the next release line

### 8.2 `docs/status-2026-04-30.md` is historically useful but no longer current

It was accurate around `alpha.0` / `alpha.1` transition territory, but now:

- latest public release is `alpha.2`
- no GitHub issues are open
- the install flow has been revalidated

That status doc should be treated as historical context, not current truth.

### 8.3 `docs/release-checklist.md` still contains older example wording

The current best public install path is:

```bash
https://github.com/manuelpenazuniga/ClawCrate/releases/latest/download/install.sh
```

If older references still point to raw `main` install script paths or older tag examples, they should eventually be normalized.

### 8.4 The working tree currently contains at least one untracked docs file

At time of writing:

- `docs/presentation-clawcrate-async-15-slides.md` is untracked

That is harmless for development but blocks release cutting until cleaned or committed.

---

## 9. What Comes Next

There are no open GitHub issues right now.
That means the next phase is not "pick next open issue."
It is "decide the next wave and create issues deliberately."

The most rational next work is:

### 9.1 Immediate documentation hygiene

Recommended issue candidates:

- add `0.1.0-alpha.2` section to `CHANGELOG.md`
- normalize any stale release-checklist or release-doc examples
- optionally create a rolling `docs/STATUS.md` or newer state snapshot

Reason:

- the product is now installable and releasable
- docs drift becomes the next trust leak

### 9.2 Demo and adoption assets

Recommended issue candidates:

- add `examples/agent-demo/`
- add a community profile for model-provider domains if filtered mode is being shown in demos
- add a concise submission/demo document in `docs/`

Reason:

- the core runtime is stable enough that the biggest ROI is now demonstration and integration proof

### 9.3 Performance evidence

Recommended issue candidate:

- add benchmark or repeatable measurement for the startup overhead claim

Reason:

- README currently makes a strong performance claim
- there is still no hard benchmark artifact backing it

### 9.4 API/runtime long-term hardening

Recommended issue candidates:

- evaluate whether `tiny_http` should remain for the `api` command
- decide whether to keep direct Landlock syscall path long-term or wrap it differently
- reduce or modularize `egress_proxy.rs` complexity over time

Reason:

- none of these are current release blockers
- all of them are relevant if the project moves toward broader external adoption

### 9.5 Public/private docs split

Recommended issue candidate:

- move critical spec knowledge from private/internal documents into public design docs if those facts are still needed for contributors

Reason:

- the original spec file is no longer part of the public tracked repo
- but some status and architecture reasoning still depends on that intellectual context

---

## 10. Recommended Next-Issue Order

If a new Codex session needs a pragmatic starting queue, use this order:

1. `docs`: add `0.1.0-alpha.2` changelog section and release-doc cleanup
2. `docs/examples`: create a minimal `examples/agent-demo/` or similar adoption artifact
3. `perf`: add benchmark or reproducible overhead measurement
4. `api`: evaluate HTTP stack and future hardening posture
5. `docs/architecture`: clarify public design knowledge that currently lives partly outside the tracked public docs

This order prioritizes:

- correctness of public truth,
- then adoption leverage,
- then medium-term engineering robustness.

---

## 11. Reentry Commands

If Codex needs to recover context quickly in a future session, these are the highest-signal commands:

```bash
git status -sb
git rev-parse HEAD
gh issue list --state open
gh pr list --state open
gh release view v0.1.0-alpha.2
sed -n '1,220p' README.md
sed -n '1,220p' CLAUDE.md
sed -n '1,220p' AGENTS.md
sed -n '1,220p' CHANGELOG.md
sed -n '1,240p' docs/WORKFLOW.md
sed -n '1,260p' docs/release-checklist.md
```

Highest-signal docs to read first:

- `CLAUDE.md`
- `AGENTS.md`
- `README.md`
- `docs/architecture.md`
- `docs/status-2026-04-30.md`
- `docs/technical-note-gemini-disposition-pr163-pr190.md`

---

## 12. Bottom Line

ClawCrate is no longer in the fragile phase where the repo looked stronger than the release.

As of **2026-05-01**, the important truth is:

- latest release is live,
- latest install flow works,
- built-in profiles resolve in installed binaries,
- macOS sandboxed trivial runs succeed,
- version string and release line are aligned,
- and there are no open issues left in GitHub.

The project's next bottleneck is no longer basic correctness.
It is disciplined prioritization of:

- docs truth,
- demo/adoption assets,
- and the next wave of production hardening.

