# ClawCrate EU AI Act Compliance Statement

**Audience:** enterprise evaluators, auditors, and compliance teams assessing
whether ClawCrate helps satisfy record-keeping obligations for high-risk AI
systems under Regulation (EU) 2024/1689 (the "EU AI Act").

**This is a statement of technical capability, not legal advice, and not a
certification of conformity.** See [Boundaries and Non-Claims](#boundaries-and-non-claims)
before relying on anything in this document.

For the detailed article-by-article technical mapping, see
[`eu-ai-act-compliance.md`](eu-ai-act-compliance.md). For how ClawCrate's audit
records relate to the IETF Agent Audit Trail draft, see
[`ietf-audit-trail-alignment.md`](ietf-audit-trail-alignment.md).

---

## Summary

ClawCrate is an execution-control and audit-evidence tool. When an AI agent or
AI-assisted workflow runs a shell command through ClawCrate:

```bash
clawcrate run --profile <profile> -- <command>...
```

ClawCrate sandboxes that command with native OS primitives (Linux Landlock +
seccomp, macOS Seatbelt) and writes a durable, timestamped, actor-attributed
audit record to disk. That record is the evidence an auditor can inspect after
the fact to reconstruct what a command did.

ClawCrate covers **one slice** of a deployer's obligations: the automatic
recording and retention of events for AI-invoked shell command execution. It
does not classify AI systems, run a risk-management program, or produce a legal
conformity assessment. Those remain the responsibility of the provider or
deployer.

---

## What ClawCrate provides for Article 12 (Record-Keeping)

Article 12 requires that high-risk AI systems technically allow the automatic
recording of events (logs) over the system's lifetime. For the command-execution
boundary ClawCrate controls, it provides:

- **Automatic event logging.** Every run writes `audit.ndjson` under
  `~/.clawcrate/runs/<run-id>/` without operator intervention. Recorded events
  include sandbox application, environment scrubbing, process start/exit,
  approval decisions, replica events, and blocked permission attempts.
- **Timestamps.** Each event carries an RFC 3339 timestamp; `plan.json` records
  a `created_at` for the run.
- **Actor attribution.** `plan.json` records an `actor` field distinguishing a
  `Human` caller from an `Agent { name }`, so events can be tied to the entity
  that invoked them.
- **Post-hoc investigability.** `plan.json`, `result.json`, `stdout.log`,
  `stderr.log`, and `fs-diff.json` together let an investigator reconstruct which
  command ran, under which policy, with which outcome, and which files changed —
  without re-running anything.

An evaluator should read this as: *for the shell commands your AI system runs
through ClawCrate, the "automatic, timestamped, attributable, investigable log"
requirement of Article 12 is met by design.* It does not extend to prompts,
model outputs, or application logic outside that command boundary.

## Tamper-evidence and evidence admissibility

Log records are only useful as evidence if they can be shown to be intact.
ClawCrate offers two opt-in integrity controls:

- **Hash chaining.** With `CLAWCRATE_AUDIT_HASHCHAIN=1`, each `audit.ndjson`
  event is linked to the previous one with a SHA-256 hash chain. Any insertion,
  deletion, or modification of an event breaks the chain.
- **Cryptographic signing.** With `CLAWCRATE_AUDIT_SIGN=<ed25519-key>`, ClawCrate
  appends Ed25519 block signatures over the chain, providing origin authenticity
  in addition to integrity.

Both are verified offline and independently of the writer:

```bash
clawcrate verify <run-id> --pubkey /secure/audit-signing.pub
```

This supports **tamper-evidence** (an auditor can detect after-the-fact
alteration) and strengthens **evidence admissibility** (records can be shown to
be unaltered since the run, provided the signing key was protected). ClawCrate
does not, by itself, establish legal admissibility in any given jurisdiction —
that depends on the deployer's key management, retention, and chain-of-custody
practices.

## Retention guidance for Article 19 (≥ 6 months)

Articles 19 and 26 require that automatically generated logs under the
provider's or deployer's control be retained for an appropriate period of **at
least six months**, unless other Union or national law provides otherwise.

ClawCrate emits durable file artifacts and stops there:

```text
~/.clawcrate/runs/<run-id>/
|-- plan.json
|-- result.json
|-- stdout.log
|-- stderr.log
|-- audit.ndjson
`-- fs-diff.json
```

**Retention is the deployer's responsibility.** ClawCrate does not delete,
rotate, back up, or forward artifacts. To meet the ≥ 6-month obligation, the
deployer must:

- Retain run artifacts for the applicable period.
- Store them where the sandboxed process cannot write to or delete them.
- Back them up or forward them to controlled, access-restricted storage.
- Ensure retention and deletion are compatible with GDPR and other applicable
  law.
- Document who controls the logs and where they live.

Recommended pattern: enable hash chaining (and signing) *before* the run,
verify during ingestion, and export to retention-controlled infrastructure with
`clawcrate audit export <run-id> --format <elastic|cef|syslog>`. Treat the
original `audit.ndjson` as canonical evidence and SIEM exports as derived views.

## Article 26 deployer obligations: exposing evidence to authorities

Article 26 requires deployers to operate high-risk AI systems according to
instructions, monitor operation, and keep logs under their control. ClawCrate
helps a deployer demonstrate, on request from a competent authority:

- Which command was run, under which profile/policy.
- Whether it was sandboxed (Linux Landlock/seccomp or macOS Seatbelt).
- Which environment variables were scrubbed **by name** (values are never
  logged).
- Whether filesystem- or network-sensitive behavior was blocked or approved.
- Whether the command changed files (`fs-diff.json`).
- Whether the audit chain still verifies after storage or transfer.

To expose this evidence to an authority, a deployer can hand over the run
artifact directory (or a SIEM export of it) together with the public
verification key, allowing the authority to run `clawcrate verify` independently.
ClawCrate cannot, on its own, show whether the AI system is high-risk, whether it
was used according to provider instructions, or whether human oversight was
adequate — those are governance determinations outside its boundary.

---

## Boundaries and Non-Claims

ClawCrate deliberately makes **narrow** claims. To avoid over-promising
conformity, the following are explicit **non-claims**:

- **ClawCrate is not a compliance certification.** Using it does not certify,
  attest, or guarantee that an AI system conforms to the EU AI Act.
- **ClawCrate provides technical evidence controls, not legal conformity.** It
  supplies record-keeping and tamper-evidence primitives; it does not perform or
  replace a conformity assessment, risk-management program, or legal review.
- **The deployer/provider remains responsible.** Classification of the AI
  system, retention policy, human oversight, data governance, transparency
  notices, incident reporting, and registration duties all remain the
  responsibility of the provider or deployer.
- **Coverage is limited to the command boundary.** ClawCrate records what
  happens inside the shell-command execution it controls. It does not record
  prompts, model outputs, model weights, ranking or human-review decisions, or
  application-layer business logic unless those systems write their own evidence
  and link it to the ClawCrate run ID.
- **Integrity controls are opt-in and key-dependent.** Hash chaining and signing
  must be enabled before a run, and their evidentiary strength depends on the
  deployer protecting signing keys and the artifact store.
- **This document is not legal advice.** Consult qualified counsel to determine
  your specific obligations.

ClawCrate's evidence is strongest when the sandboxed command cannot write to its
own artifact directory, artifact permissions are restrictive, hash chaining is
enabled before execution, signing keys live outside the command workspace, and
verification runs before logs enter long-term retention.

---

## References

- Technical article-by-article mapping:
  [`eu-ai-act-compliance.md`](eu-ai-act-compliance.md)
- IETF Agent Audit Trail alignment:
  [`ietf-audit-trail-alignment.md`](ietf-audit-trail-alignment.md)
- EU AI Act Service Desk, Article 12 (Record-keeping):
  <https://ai-act-service-desk.ec.europa.eu/en/ai-act/article-12>
- EU AI Act Service Desk, Article 19 (Automatically generated logs):
  <https://ai-act-service-desk.ec.europa.eu/en/ai-act/article-19>
- Regulation (EU) 2024/1689 on EUR-Lex:
  <http://data.europa.eu/eli/reg/2024/1689/oj>
