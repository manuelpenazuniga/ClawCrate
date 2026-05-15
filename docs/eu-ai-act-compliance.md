# EU AI Act Compliance Mapping

This document maps ClawCrate's audit and sandbox artifacts to selected EU AI
Act obligations for high-risk AI systems.

It is intentionally narrow. ClawCrate is an execution-control and audit-evidence
tool for shell commands. It does not classify AI systems, run a risk management
program, perform legal assessments, or replace organizational compliance work.

This is not legal advice.

## Scope

The relevant EU AI Act provisions for ClawCrate's domain are the provisions that
touch automatic event recording, log retention, and deployer/provider evidence
handling for high-risk AI systems:

- Article 12: high-risk AI systems must technically allow automatic recording of
  events (logs) over the system lifetime.
- Article 19: providers must keep automatically generated logs referred to in
  Article 12, to the extent those logs are under their control, for an
  appropriate period of at least six months unless other Union or national law
  provides otherwise.
- Article 26: deployers of high-risk AI systems must monitor operation and keep
  automatically generated logs under their control for an appropriate period of
  at least six months unless other applicable law provides otherwise.

ClawCrate helps with the execution-audit slice of those obligations when an AI
agent or AI-assisted workflow invokes shell commands through:

```bash
clawcrate run --profile <profile> -- <command>...
```

## Article 12 Mapping: Record-Keeping

| Article 12 need | ClawCrate support | Status |
|---|---|---|
| Automatic event recording | Each run writes `audit.ndjson` under `~/.clawcrate/runs/<run-id>/`. Events include sandbox application, environment scrubbing, process start/exit, approval decisions, replica events, and blocked permissions. | Covered for ClawCrate-managed command execution |
| Timestamps | Each `AuditEvent` includes an RFC3339 timestamp. `plan.json` also includes `created_at`. | Covered |
| Actor traceability | `plan.json` includes an `actor` field (`Human` or `Agent { name }`). | Covered when the caller supplies/uses the actor model correctly |
| Reconstruction of command context | `plan.json` records command, profile, filesystem policy, network policy, workspace mode, actor, and creation time. `result.json`, `stdout.log`, `stderr.log`, and `fs-diff.json` provide execution outcome and file-change evidence. | Covered for shell-command context, not full model reasoning |
| Tamper evidence | `CLAWCRATE_AUDIT_HASHCHAIN=1` adds SHA-256 hash-chain fields to `audit.ndjson`. `CLAWCRATE_AUDIT_SIGN=<ed25519-key>` can append Ed25519 `BlockSignature` entries. `clawcrate verify <run-id>` verifies hash chains, and `--pubkey` verifies block signatures. | Covered when enabled and keys are managed securely |
| Monitoring operation | `clawcrate audit export <run-id> --format cef\|syslog\|elastic` exports audit events to SIEM-compatible formats. | Covered for ClawCrate events |

Important boundary: ClawCrate records what happens inside the command execution
boundary it controls. It does not record prompts, model outputs, model weights,
ranking decisions, human-review decisions, or application-layer business logic
unless those systems write their own evidence and link it to the ClawCrate run
ID.

## Article 19 Mapping: Provider Log Retention

Article 19 is a retention obligation for providers of high-risk AI systems,
covering automatically generated logs referred to in Article 12 when those logs
are under the provider's control.

ClawCrate provides durable file artifacts:

```text
~/.clawcrate/runs/<run-id>/
|-- plan.json
|-- result.json
|-- stdout.log
|-- stderr.log
|-- audit.ndjson
`-- fs-diff.json
```

ClawCrate does not manage retention policy. The operator remains responsible
for:

- Retaining logs for the applicable period.
- Ensuring deletion/retention is compatible with GDPR and other applicable law.
- Backing up artifacts or forwarding them to controlled storage.
- Preventing unauthorized write/delete access to the artifact store.
- Documenting who controls the logs and where they are stored.

Recommended provider-side pattern:

1. Enable hash-chain logging for regulated runs:

   ```bash
   CLAWCRATE_AUDIT_HASHCHAIN=1 clawcrate run --profile safe -- <command>...
   ```

2. Enable signing for stronger evidence integrity:

   ```bash
   CLAWCRATE_AUDIT_HASHCHAIN=1 \
   CLAWCRATE_AUDIT_SIGN=/secure/audit-signing.key \
   clawcrate run --profile safe -- <command>...
   ```

3. Verify artifacts in CI or during ingestion:

   ```bash
   clawcrate verify <run-id> --pubkey /secure/audit-signing.pub
   ```

4. Export to controlled retention infrastructure:

   ```bash
   clawcrate audit export <run-id> --format elastic
   ```

## Article 26 Mapping: Deployer Operation and Retention

Article 26 contains deployer obligations for high-risk AI systems, including
operation according to instructions, monitoring, and log retention where logs
are under the deployer's control.

ClawCrate can help deployers show:

- Which command was run.
- Which profile/policy was used.
- Whether a command was sandboxed with Linux Landlock/seccomp or macOS Seatbelt.
- Which environment variables were scrubbed by name, without logging values.
- Whether filesystem or network-sensitive behavior was blocked or approved.
- Whether the command changed files.
- Whether the audit chain still verifies after storage or transfer.

ClawCrate cannot by itself show:

- Whether the AI system is high-risk under the EU AI Act.
- Whether the AI system was used according to its provider instructions.
- Whether human oversight was adequate.
- Whether input data was lawful, representative, or appropriate.
- Whether affected persons were informed where required.
- Whether a fundamental rights impact assessment was required or completed.

## What ClawCrate Does Not Cover

ClawCrate is not a complete EU AI Act compliance system. It does not cover:

- AI system classification.
- Risk management system design.
- Data governance controls.
- Technical documentation for the full AI system.
- Transparency notices.
- Human oversight procedures.
- Accuracy, robustness, and cybersecurity of the AI model or application.
- Post-market monitoring programs.
- Serious incident reporting.
- Conformity assessment.
- Registration duties.
- GDPR lawful-basis analysis, DPIAs, or data-subject rights workflows.

Those controls must be handled by the provider/deployer governance program.

## Recommended Deployment Pattern

For EU high-risk contexts, use ClawCrate as one control in a broader evidence
architecture:

1. Wrap every AI-agent shell command with `clawcrate run -- COMMAND...`.
2. Use the narrowest viable profile (`safe`, `build`, `install`, `open`, or a
   custom profile).
3. Prefer Replica Mode for install/build workflows that should not access
   secrets from the source workspace.
4. Enable `CLAWCRATE_AUDIT_HASHCHAIN=1` for regulated runs.
5. Enable `CLAWCRATE_AUDIT_SIGN` with keys stored outside the writable
   workspace.
6. Store public verification keys separately from run artifacts.
7. Export audit logs to a retention-controlled system using
   `clawcrate audit export`.
8. Link ClawCrate run IDs to application-level records such as request IDs,
   model versions, reviewer IDs, approval tickets, and incident records.
9. Periodically run `clawcrate verify <run-id> --pubkey <key>` over retained
   samples or during archive ingestion.
10. Document residual risks, especially local host compromise and incomplete
    visibility outside ClawCrate-managed command execution.

## Evidence Boundary

ClawCrate's evidence is strongest when:

- The sandboxed command cannot write to its own artifact directory.
- Artifact directories have restrictive filesystem permissions.
- Hash-chain logging is enabled before execution starts.
- Signing keys are kept outside the command workspace and outside the sandboxed
  process environment.
- Verification is performed before accepting logs into long-term retention.
- SIEM exports are treated as derived views, while original run artifacts remain
  the canonical evidence.

The evidence is weaker when:

- An attacker controls the host account that owns `~/.clawcrate`.
- Signing keys are stored in the same writable workspace as the command.
- Operators enable broad profiles such as `open` without compensating controls.
- The AI application performs important actions outside ClawCrate's command
  boundary.

## References

- EU AI Act Service Desk, Article 12: Record-keeping:
  <https://ai-act-service-desk.ec.europa.eu/en/ai-act/article-12>
- EU AI Act Service Desk, Article 19: Automatically generated logs:
  <https://ai-act-service-desk.ec.europa.eu/en/ai-act/article-19>
- Regulation (EU) 2024/1689 on EUR-Lex:
  <http://data.europa.eu/eli/reg/2024/1689/oj>
