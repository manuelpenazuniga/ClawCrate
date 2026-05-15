# IETF Agent Audit Trail Alignment

This document maps ClawCrate's `audit.ndjson` artifacts to
`draft-sharif-agent-audit-trail-00`, "Agent Audit Trail: A Standard Logging
Format for Autonomous AI Systems".

The draft is an active Internet-Draft, not an approved RFC. It can change or be
replaced. ClawCrate treats it as a useful interoperability target and evidence
model, not as a stable normative dependency.

## Draft Summary

`draft-sharif-agent-audit-trail-00` defines Agent Audit Trail (AAT), a JSON-based
format for autonomous AI agent audit records.

The draft's main design points are:

- One audit record per agent event.
- A mandatory record schema with identity, session, action, outcome, trust, and
  chain fields.
- Tamper-evident chaining through `prev_hash`.
- JSON Canonicalization Scheme (JCS, RFC 8785) before hashing.
- SHA-256 as the chain hash.
- Optional record-level ECDSA P-256 signatures.
- Export to JSONL, syslog, and CSV while preserving chain integrity.
- A session model with genesis, ordered records, and optional close records.

ClawCrate aligns with the evidence goals, canonical JSON requirement, and
SHA-256 tamper-evidence direction. It does not currently emit draft-conformant
AAT records.

## Current ClawCrate Audit Shape

ClawCrate writes one newline-delimited JSON file per run:

```text
~/.clawcrate/runs/<run-id>/audit.ndjson
```

Plain events have this logical shape:

```json
{
  "timestamp": "2026-05-14T22:00:00Z",
  "event": {
    "ProcessStarted": {
      "pid": 42,
      "command": ["cargo", "test"]
    }
  }
}
```

When `CLAWCRATE_AUDIT_HASHCHAIN=1` is enabled, each event line is extended with:

```json
{
  "previous_hash": "sha256:...",
  "current_hash": "sha256:..."
}
```

When `CLAWCRATE_AUDIT_SIGN=<path>` is enabled, ClawCrate may append
`BlockSignature` lines:

```json
{
  "kind": "BlockSignature",
  "block_start": 0,
  "block_end": 99,
  "block_hash": "sha256:...",
  "signature": "ed25519:...",
  "public_key_fingerprint": "SHA256:..."
}
```

`BlockSignature` lines are ClawCrate metadata rows, not `AuditEvent` rows.

## Field Mapping

| AAT field | Draft requirement | ClawCrate source | Alignment |
|---|---|---|---|
| `record_id` | Required UUIDv4 per record | Not present in `AuditEvent` | Gap |
| `timestamp` | Required RFC3339 timestamp | `AuditEvent.timestamp` | Aligned |
| `agent_id` | Required URI identifying agent instance | `plan.json.actor` can identify `Human` or `Agent { name }`, but not URI | Partial |
| `agent_version` | Required semantic version of agent software | Not present | Gap |
| `session_id` | Required UUIDv4 shared by all records in session | `ExecutionPlan.id` / run ID | Partial; run ID is session-like but not represented as `session_id` in every event |
| `action_type` | Required controlled vocabulary | Derived from `AuditEventKind` | Partial |
| `action_detail` | Required object by action type | Payload inside `AuditEventKind` variant | Partial |
| `outcome` | Required registry value | Derived from event type/result (`ProcessExited`, `PermissionBlocked`, approvals) | Partial |
| `trust_level` | Required `L0`-`L4` | Not present | Gap |
| `parent_record_id` | Required previous record ID or null for genesis | Not present | Gap |
| `prev_hash` | Required hash of previous canonical record or null for genesis | `previous_hash` when hash chain enabled | Partial; semantics differ |
| Optional `signature` | ECDSA P-256 signature field on each record | `BlockSignature` rows with Ed25519 signatures over blocks | Deliberate deviation |

## Action Mapping

ClawCrate events can be projected into the draft's action taxonomy, but the
native schema does not currently store `action_type` directly.

| ClawCrate `AuditEventKind` | Suggested AAT `action_type` | Suggested `outcome` |
|---|---|---|
| `SandboxApplied` | `lifecycle` | `success` |
| `EnvScrubbed` | `lifecycle` | `success` |
| `ProcessStarted` | `tool_call` | `success` |
| `ProcessExited { exit_code: 0 }` | `tool_response` | `success` |
| `ProcessExited { exit_code: nonzero }` | `tool_response` | `failure` |
| `PermissionBlocked` | `tool_call` or `error` | `denied` |
| `ReplicaCreated` | `lifecycle` | `success` |
| `ReplicaSyncBack { approved: true }` | `decision` | `success` |
| `ReplicaSyncBack { approved: false }` | `decision` | `denied` |
| `ApprovalDecision { approved: true }` | `decision` | `success` |
| `ApprovalDecision { approved: false }` | `decision` | `denied` |

This mapping is suitable for a future `clawcrate audit export --format aat`
adapter. It should not be treated as native conformance until the required AAT
fields are emitted.

## Hash Chain Alignment

### Aligned

ClawCrate aligns with the draft on these points:

- Uses SHA-256.
- Canonicalizes `AuditEvent` payloads before hashing.
- Uses RFC 8785-style deterministic JSON requirements: no insignificant
  whitespace, lexicographic object-key ordering, and no float fields in current
  audit events.
- Provides offline verification through:

  ```bash
  clawcrate verify <run-id>
  ```

### Different Semantics

The draft defines:

```text
prev_hash(N) = hex(SHA-256(JCS(record(N-1))))
```

ClawCrate currently computes:

```text
current_hash(N) = "sha256:" + hex(SHA-256(canonical_json(event(N)) || previous_hash(N)))
```

Then the next event stores:

```text
previous_hash(N+1) = current_hash(N)
```

Practical consequence:

- Both designs are tamper-evident ordered chains.
- The ClawCrate chain is not byte-for-byte compatible with draft AAT validators.
- A draft-conformant export would need to synthesize `record_id`,
  `parent_record_id`, `session_id`, `action_type`, `outcome`, `trust_level`, and
  draft-style `prev_hash` values over complete canonical AAT records.

### Genesis Value

The draft uses `prev_hash = null` for the genesis record.

ClawCrate uses an all-zero sentinel:

```text
sha256:0000000000000000000000000000000000000000000000000000000000000000
```

This was chosen to keep `previous_hash` typed as a string in chained
`audit.ndjson` rows. It is a deliberate schema simplification and a draft
deviation.

## Signing Alignment

### Draft

The current `-00` draft specifies optional record-level ECDSA P-256 signatures:

- Construct the record excluding `signature`.
- Serialize with JCS.
- Compute SHA-256.
- Sign with ECDSA P-256.
- Encode using Base64url.
- Add a `signature` field to the same record.

### ClawCrate

ClawCrate currently implements block signatures:

- Uses Ed25519 keys.
- Signs `block_hash`, not each full event record.
- Stores signatures in separate `BlockSignature` rows.
- Encodes as `ed25519:<base64>`.
- Verifies with:

  ```bash
  clawcrate verify <run-id> --pubkey <path>
  ```

### Rationale for the Deviation

ClawCrate chose Ed25519 block signatures for the alpha compliance kit because:

- Ed25519 has smaller keys and signatures.
- Key generation and verification are simpler for local CLI users.
- Signing every event would add more overhead and file size.
- Block signatures are enough to detect post-run tampering when the private key
  is protected.

This is not draft-conformant. It is an implementation trade-off. If draft
alignment becomes a hard compatibility requirement, ClawCrate should add an AAT
export/signing mode rather than silently changing the existing `audit.ndjson`
format.

## Export Alignment

The draft identifies JSONL and syslog as supported export directions.

ClawCrate currently supports:

```bash
clawcrate audit export <run-id> --format json
clawcrate audit export <run-id> --format cef
clawcrate audit export <run-id> --format syslog
clawcrate audit export <run-id> --format elastic
```

Alignment:

- `json` preserves native ClawCrate NDJSON, not AAT JSONL.
- `syslog` is directionally aligned with the draft's syslog export goal.
- `cef` and `elastic` are SIEM-oriented additions outside the draft.
- CSV is not implemented.
- Chain integrity is preserved by retaining the original `audit.ndjson` as the
  canonical artifact; SIEM exports are derived views.

## Deviations Summary

| Area | Draft | ClawCrate today | Rationale |
|---|---|---|---|
| Record schema | AAT mandatory fields | Native `AuditEvent` schema | Keep alpha artifacts simple and tied to command execution |
| Record IDs | `record_id` UUIDv4 per record | None | Not needed for current verifier; needed for AAT export |
| Session IDs | `session_id` in every record | Run ID in `plan.json` and artifact path | Avoid repeated fields in each event |
| Parent linkage | `parent_record_id` | Hash-only linkage | Simpler chain implementation |
| Genesis hash | `prev_hash = null` | All-zero `sha256:` sentinel | String-only field shape |
| Hash formula | Hash previous complete canonical record | Hash current canonical event plus previous hash | Tamper-evident but not draft validator compatible |
| Signature | Per-record ECDSA P-256 | Block-level Ed25519 | Lower operational complexity |
| Trust levels | Required `L0`-`L4` | Not represented | ClawCrate does not implement MCPS trust model |
| Privacy hashes | Optional `input_hash` / `output_hash` | Not represented | ClawCrate captures command logs separately; prompt/model payloads are outside scope |
| Tombstones | Draft supports tombstone records | Not implemented | Retention/deletion policy remains operator-managed |
| CSV export | Included in draft | Not implemented | Lower priority than CEF/Elastic/Syslog |

## Upgrade Path

Recommended path to full AAT interoperability:

1. Add `clawcrate audit export <run-id> --format aat-jsonl`.
2. Synthesize draft fields from existing artifacts:
   - `session_id` from run ID or a stable UUID stored in `plan.json`.
   - `agent_id` from `ExecutionPlan.actor`.
   - `agent_version` from caller metadata or ClawCrate integration metadata.
   - `action_type`, `action_detail`, and `outcome` from `AuditEventKind`.
   - `trust_level` from future profile/integration metadata, defaulting
     conservatively to `L0` when unknown.
3. Add per-record UUIDs during export or store them at write time in a future
   schema version.
4. Compute AAT-style `prev_hash` over complete canonical exported AAT records.
5. Add optional per-record ECDSA P-256 signing for AAT export mode.
6. Preserve native `audit.ndjson` compatibility and treat AAT JSONL as a derived
   interoperability artifact until a major schema version can be planned.
7. Track future draft revisions and update the export adapter, not historical
   run artifacts, when the draft changes.

## Compatibility Claim

The accurate claim today is:

> ClawCrate audit artifacts are inspired by and partially aligned with
> `draft-sharif-agent-audit-trail-00`: they provide JSON event records,
> RFC 8785-style canonicalization, SHA-256 tamper-evident chaining, optional
> signatures, offline verification, and SIEM export. They are not currently
> draft-conformant AAT records.

Do not claim that native `audit.ndjson` is AAT-compliant until ClawCrate emits
or exports the draft's mandatory fields and hash/signature semantics.

## References

- IETF Datatracker: `draft-sharif-agent-audit-trail-00`
  <https://datatracker.ietf.org/doc/html/draft-sharif-agent-audit-trail-00>
- Plaintext Internet-Draft archive:
  <https://www.ietf.org/archive/id/draft-sharif-agent-audit-trail-00.txt>
- RFC 8785, JSON Canonicalization Scheme:
  <https://www.rfc-editor.org/rfc/rfc8785>
