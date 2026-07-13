//! verify module (extracted from main.rs; see #277).

use crate::{cli::*, output::*, support::*};
use anyhow::{anyhow, Result};
use clawcrate_audit::{verify_audit_chain_with_pubkey, VerifyChainError, AUDIT_NDJSON};

pub(crate) fn handle_verify(args: VerifyArgs, output: &OutputOptions) -> Result<()> {
    let run_dir = runs_root()?.join(&args.run_id);
    let audit_path = run_dir.join(AUDIT_NDJSON);

    let result = match verify_audit_chain_with_pubkey(&audit_path, args.pubkey.as_deref()) {
        Ok(r) => r,
        Err(VerifyChainError::NotFound { .. }) => {
            if args.json {
                println!(
                    "{}",
                    serde_json::json!({
                        "valid": false,
                        "events_checked": 0,
                        "signatures_checked": 0,
                        "tampered_at": null,
                        "run_id": args.run_id,
                        "error": format!("run '{}' not found", args.run_id)
                    })
                );
            } else {
                eprintln!("error: run '{}' not found", args.run_id);
                eprintln!("hint: list available runs with `ls ~/.clawcrate/runs/`");
            }
            std::process::exit(2);
        }
        Err(VerifyChainError::NoHashChain) => {
            if args.json {
                println!(
                    "{}",
                    serde_json::json!({
                        "valid": false,
                        "events_checked": 0,
                        "signatures_checked": 0,
                        "tampered_at": null,
                        "run_id": args.run_id,
                        "error": "audit.ndjson has no hash chain (re-run with CLAWCRATE_AUDIT_HASHCHAIN=1)"
                    })
                );
            } else {
                eprintln!(
                    "error: audit.ndjson for '{}' has no hash chain fields.",
                    args.run_id
                );
                eprintln!(
                    "hint: set CLAWCRATE_AUDIT_HASHCHAIN=1 before running to enable chaining."
                );
            }
            std::process::exit(3);
        }
        Err(VerifyChainError::Io(e)) => {
            return Err(anyhow!("failed to read audit.ndjson: {e}"));
        }
        Err(VerifyChainError::ReadPublicKey { path, source }) => {
            return Err(anyhow!(
                "failed to read Ed25519 public key {}: {source}",
                path.display()
            ));
        }
        Err(VerifyChainError::PublicKey { path, detail }) => {
            return Err(anyhow!(
                "failed to parse Ed25519 public key {}: {detail}",
                path.display()
            ));
        }
    };

    if args.json {
        let mut obj = serde_json::json!({
            "valid": result.valid,
            "events_checked": result.events_checked,
            "signatures_checked": result.signatures_checked,
            "tampered_at": result.tampered_at,
            "run_id": args.run_id,
        });
        if let Some(e) = &result.error {
            obj["error"] = serde_json::Value::String(e.clone());
        }
        println!("{obj}");
    } else {
        let green = output.color;
        let (check, cross) = if green {
            ("✅", "❌")
        } else {
            ("OK", "FAIL")
        };

        if result.valid {
            println!(
                "{check} Hash chain valid ({} events)",
                result.events_checked
            );
            if args.pubkey.is_some() {
                println!(
                    "{check} Signatures valid ({} block signature(s))",
                    result.signatures_checked
                );
            }
            println!("{check} No tampering detected");
            println!("   Run ID:      {}", args.run_id);
            if let Some(ts) = &result.first_event_ts {
                println!("   First event: {ts}");
            }
            if let Some(ts) = &result.last_event_ts {
                println!("   Last event:  {ts}");
            }
        } else {
            let at = result.tampered_at.unwrap_or(0);
            println!("{cross} Tampering detected at event #{at}");
            if let Some(e) = &result.error {
                println!("   {e}");
            }
            std::process::exit(1);
        }
    }

    Ok(())
}
