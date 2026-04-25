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
  ├─ DNS path depends on client behavior:
  │    - proxy-aware clients send hostnames to proxy (preferred)
  │    - non-proxy DNS lookups may still hit local resolver metadata path
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
  - transport type (`connect-tunnel` or `plain-http`)

## Trust Boundaries

## Components and trust level

- **Sandboxed command + children**: untrusted.
- **Local egress proxy process**: trusted computing base (TCB), hardened input parser required.
- **ClawCrate orchestrator (`clawcrate-cli`)**: trusted.
- **Kernel sandbox backend (Landlock/seccomp/Seatbelt)**: trusted enforcement plane.
- **Remote DNS + remote servers**: untrusted.
- **Profile policy file**: trusted after parse/validation.
- **Run artifact store (`plan.json`, `result.json`, `audit.ndjson`)**: trusted only within
  ClawCrate-controlled write boundary; untrusted if world/group writable.

## Boundary transitions

1. User policy -> parsed profile (must validate strictly).
2. CLI -> proxy control channel (local only, authenticated token).
3. Untrusted process -> proxy listener (potential parser abuse).
4. Proxy -> internet (untrusted network I/O).
5. Proxy decisions -> audit artifacts (integrity required).

## Audit Integrity Boundary

`audit.ndjson` is authoritative only when all of the following are true:

- Artifact directory is created by ClawCrate with restrictive permissions.
- Sandboxed command cannot write or replace `audit.ndjson`.
- Audit writes are append-only from trusted process components.

Expected policy posture:

- Sandbox writes to artifact directory should be denied by default.
- If deployment cannot enforce that boundary, mark audit trust as degraded in
  `result.json` and avoid over-claiming tamper resistance.

## Security Model

## Intended guarantees

- Deny-by-default domain policy for filtered mode.
- If policy cannot be loaded, command does not start.
- If proxy fails to start/health-check, command does not start.
- If proxy crashes mid-run, child is terminated and run is marked failed.
- All allow/deny decisions are emitted to `audit.ndjson`.
- Audit claims are valid only up to local host compromise boundaries.

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

## Proxy Policy Flow (Plain HTTP)

`allow_plain_http` controls whether non-CONNECT HTTP requests are allowed in
filtered mode.

- `allow_plain_http=false` (default): deny plain HTTP bootstrap paths.
- `allow_plain_http=true`: proxy may permit HTTP methods (for example
  `GET http://host/path HTTP/1.1`) after allowlist checks.

When plain HTTP is allowed, policy checks still apply:

1. Parse absolute-form request target and `Host` header.
2. Resolve effective authority (`host:port`) and verify allowlist match.
3. Deny IP literals when `allow_ip_literals=false`.
4. Forward upstream only after policy pass.
5. Emit `EgressDecision` with `transport=plain-http`.

Notes:

- This enables domain-gated HTTP, not payload-level content filtering.
- Header/body values must not be persisted in audit logs.

## DNS Leakage Assumptions and Mitigations

Filtered mode reduces direct egress risk, but DNS metadata can still leak in
specific client and host configurations.

Primary leakage scenario:

- The sandboxed process performs local DNS lookups (for example via a loopback
  resolver such as `127.0.0.53`) before proxy mediation.

Assumptions:

- ClawCrate does not claim DNS privacy against the local host resolver path.
- Loopback-only egress controls limit remote bypass, but do not inherently hide
  query metadata from local resolver infrastructure.

Mitigations:

- Prefer proxy-aware clients that delegate hostname resolution to the proxy.
- Keep `filtered` default `FailClosed` when bypass constraints cannot be
  enforced.
- Emit audit signals when policy-relevant requests are denied/allowed, and
  document that audit coverage is request-level, not full resolver telemetry.

## Threat Model (STRIDE-style)

| Threat | Example | Risk | Mitigation |
|---|---|---|---|
| Spoofing | process forges proxy control/auth | Medium | random per-run token, loopback bind only, reject unauth requests |
| Tampering | policy mutation during run; local overwrite of audit files | Medium | immutable in-memory snapshot, hash policy in plan/audit, artifact dir write isolation |
| Repudiation | actor denies blocked exfil attempt | Medium | append-only audit events with timestamps + decision reason |
| Information disclosure | proxy logs secrets; local resolver sees queried domains | High | never log headers/body/env values, redact sensitive fields, document DNS metadata limits |
| Denial of service | malformed streams exhaust proxy | High | read/write timeouts, conn limits, bounded buffers |
| Elevation of privilege | bypass proxy via direct connect | High | loopback-only kernel net policy where available; else fail closed by default |

## Failure Modes and Expected Behavior

| Failure mode | Expected behavior |
|---|---|
| policy parse error | abort before launch (non-zero) |
| proxy bind failure | abort before launch (non-zero) |
| proxy startup timeout | abort before launch (non-zero) |
| proxy crash while child running | terminate child, write error result + audit |
| artifact write failure (`audit.ndjson`) | fail run as `SandboxError` (or explicit degraded audit state if policy allows) |
| domain not allowed | deny request, keep process alive unless command fails itself |
| upstream DNS/connect timeout | fail that request; command behavior depends on tool retry logic |
| unknown protocol via proxy | deny (default) |
| backend cannot enforce bypass constraints | default fail-closed unless user opted into explicit best-effort |

## Residual Risks

- Domain fronting cannot be fully prevented without TLS interception.
- Wildcard allowlists can be over-broad if not curated.
- Some tooling may not honor proxy env vars; this is safe only when direct egress is kernel-blocked.
- HTTP (non-TLS) exposes host/path metadata to proxy logs; logging must stay minimal.
- Local resolver infrastructure may still observe queried hostnames in some
  client/network stacks.

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
