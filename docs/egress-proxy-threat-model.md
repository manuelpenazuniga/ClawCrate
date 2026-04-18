# Egress Proxy Design and Threat Model (P1)

This document defines the design baseline for issue `#41` (`P1-01`):
local egress proxy with domain controls, trust boundaries, and failure modes.

## Goals

- Add a `filtered` network mode beyond alpha's `none` and `open`.
- Enforce outbound access through a local proxy path where possible.
- Allow domains by policy (exact and wildcard), deny everything else.
- Emit auditable connection decisions for every attempt.
- Fail closed when policy/proxy state is invalid.

## Non-Goals (P1)

- Full TLS interception (MITM/decryption).
- Deep HTTP payload inspection.
- Arbitrary protocol filtering beyond HTTP/HTTPS bootstrap.
- Replacing existing alpha `none/open` modes.

## Current Alpha Baseline

- Network levels today: `none` and `open`.
- No domain-aware enforcement in alpha.
- `install` currently uses `open` with warning + Replica mode.

P1 introduces a new level:

- `filtered`: command egress must pass through local policy-aware proxy.

## High-Level Architecture

```text
clawcrate-cli
  ├─ resolve profile -> ExecutionPlan (NetLevel::Filtered + allowlist)
  ├─ start local egress proxy (outside sandbox process)
  ├─ pass proxy endpoint/token via env to sandboxed child
  └─ run command via platform backend

sandboxed child process
  ├─ HTTP_PROXY / HTTPS_PROXY / ALL_PROXY -> 127.0.0.1:<port>
  ├─ network policy: deny direct egress when backend can enforce loopback-only
  └─ outbound attempts -> local proxy -> remote target (if policy allows)
```

## Planned Data Model Changes

Add network policy structures in `clawcrate-types`:

- `NetLevel::Filtered`
- `NetworkPolicy`:
  - `allowed_domains: Vec<DomainRule>` (exact + wildcard)
  - `allow_plain_http: bool` (default `false`)
  - `allow_ip_literals: bool` (default `false`)
  - `on_bypass: BypassMode` (`FailClosed` default)
- `EgressDecision` audit payload fields:
  - requested host/port
  - resolved addresses (if any)
  - decision (`allowed|denied`)
  - deny reason
  - timing and bytes transferred

## Trust Boundaries

## Components and trust level

- **Sandboxed command + children**: untrusted.
- **Local egress proxy process**: trusted computing base (TCB), hardened input parser required.
- **ClawCrate orchestrator (`clawcrate-cli`)**: trusted.
- **Kernel sandbox backend (Landlock/seccomp/Seatbelt)**: trusted enforcement plane.
- **Remote DNS + remote servers**: untrusted.
- **Profile policy file**: trusted after parse/validation.

## Boundary transitions

1. User policy -> parsed profile (must validate strictly).
2. CLI -> proxy control channel (local only, authenticated token).
3. Untrusted process -> proxy listener (potential parser abuse).
4. Proxy -> internet (untrusted network I/O).
5. Proxy decisions -> audit artifacts (integrity required).

## Security Model

## Intended guarantees

- Deny-by-default domain policy for filtered mode.
- If policy cannot be loaded, command does not start.
- If proxy fails to start/health-check, command does not start.
- If proxy crashes mid-run, child is terminated and run is marked failed.
- All allow/deny decisions are emitted to `audit.ndjson`.

## Important caveat (platform capability)

Loopback-only kernel enforcement for child egress is platform-dependent.

- If backend supports loopback-only enforcement: direct bypass attempts fail at kernel boundary.
- If backend cannot enforce loopback-only: ClawCrate must either:
  - fail the run (`FailClosed`), or
  - explicitly degrade to best-effort mode with clear warning and audit flag.

Default for `filtered` should be `FailClosed`.

## Proxy Policy Flow (HTTPS)

1. Child sends `CONNECT host:443` to local proxy.
2. Proxy validates request syntax and policy match.
3. Proxy resolves/opens upstream connection when allowed.
4. Proxy optionally peeks TLS ClientHello SNI for consistency checks.
5. Proxy tunnels bytes and records final decision/outcome.

Deny conditions:

- host not in allowlist
- malformed CONNECT
- TLS SNI missing/mismatch (when strict SNI mode enabled)
- IP literal when `allow_ip_literals=false`
- proxy auth token invalid

## Threat Model (STRIDE-style)

| Threat | Example | Risk | Mitigation |
|---|---|---|---|
| Spoofing | process forges proxy control/auth | Medium | random per-run token, loopback bind only, reject unauth requests |
| Tampering | policy mutation during run | Medium | immutable in-memory snapshot, hash policy in plan/audit |
| Repudiation | actor denies blocked exfil attempt | Medium | append-only audit events with timestamps + decision reason |
| Information disclosure | proxy logs secrets | High | never log headers/body/env values, redact sensitive fields |
| Denial of service | malformed streams exhaust proxy | High | read/write timeouts, conn limits, bounded buffers |
| Elevation of privilege | bypass proxy via direct connect | High | loopback-only kernel net policy where available; else fail closed by default |

## Failure Modes and Expected Behavior

| Failure mode | Expected behavior |
|---|---|
| policy parse error | abort before launch (non-zero) |
| proxy bind failure | abort before launch (non-zero) |
| proxy startup timeout | abort before launch (non-zero) |
| proxy crash while child running | terminate child, write error result + audit |
| domain not allowed | deny request, keep process alive unless command fails itself |
| upstream DNS/connect timeout | fail that request; command behavior depends on tool retry logic |
| unknown protocol via proxy | deny (default) |
| backend cannot enforce bypass constraints | default fail-closed unless user opted into explicit best-effort |

## Residual Risks

- Domain fronting cannot be fully prevented without TLS interception.
- Wildcard allowlists can be over-broad if not curated.
- Some tooling may not honor proxy env vars; this is safe only when direct egress is kernel-blocked.
- HTTP (non-TLS) exposes host/path metadata to proxy logs; logging must stay minimal.

## Implementation Plan for P1-02

1. Add `NetLevel::Filtered` and `NetworkPolicy` types.
2. Add profile schema fields for domain allowlist.
3. Implement local proxy runtime (initially CONNECT + HTTPS path).
4. Wire `run` orchestration:
   - spawn proxy
   - inject env and auth token
   - monitor lifecycle
5. Add backend capability reporting for filtered-mode support in `doctor`.
6. Add integration tests:
   - allowed domain succeeds
   - denied domain blocked
   - proxy crash fails run
   - malformed proxy input handled safely
7. Extend audit schema/events with egress decisions.

## Open Decisions

- Strict SNI validation default: on or off?
- How to model best-effort downgrade in plan/result JSON.
- Exact wildcard semantics (`*.example.com` vs suffix match rules).
- Whether `allow_plain_http` remains opt-in forever.

## Acceptance Criteria (for this design issue)

- Architecture documented with component boundaries.
- Trust boundaries explicitly described.
- Failure modes and fail-closed behavior defined.
- Risks and residual limitations made explicit.
- Document aligned with alpha claim boundaries (no false domain-filtering claims for current release).
