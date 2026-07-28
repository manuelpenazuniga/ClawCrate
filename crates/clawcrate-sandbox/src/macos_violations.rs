//! Recovery of Seatbelt denials from the macOS unified log.
//!
//! The kernel records every sandbox denial as a log message of the form
//!
//! ```text
//! Sandbox: cat(47036) deny(1) file-read-data /private/etc/hosts
//! ```
//!
//! which is readable without root. That makes it the one channel through which
//! ClawCrate can report what the kernel actually refused, rather than inferring
//! a denial from an error the child happened to surface.
//!
//! # This record is incomplete
//!
//! The kernel does not report every denial. It appears to apply a per-process
//! reporting budget: the first denials a process hits are logged and later ones
//! are frequently dropped. Measured against a sandboxed MCP server reading a
//! planted secret outside its workspace, the Node binary's own startup denial
//! was reported in 5 of 5 runs while the later secret read was reported in 5 of
//! 8 — and the misses are permanent, not late, so querying again does not
//! recover them. The read was refused every time; only the reporting is lossy.
//!
//! So a violation here proves a denial happened. The absence of one proves
//! nothing. Callers must not present this as an exhaustive list of what the
//! sandbox blocked.
//!
//! Two properties matter and are enforced below:
//!
//! * **Attribution.** The log is system-wide. Denials are attributed to a run
//!   only on an exact PID match, so unrelated system activity never lands in a
//!   user's audit trail. `sandbox-exec` execs the target command in place, so
//!   the PID ClawCrate spawned is the PID the kernel reports.
//! * **Cost.** Querying the log takes on the order of a second, which is not
//!   worth paying on every run, so capture is opt-in via
//!   [`SEATBELT_VIOLATIONS_ENV`].
//!
//! The parser is compiled on every platform so its tests run in Linux CI too;
//! only the `log show` invocation is macOS-specific.

use std::collections::HashSet;
use std::time::Duration;

/// Set to `1` (or `true`) to record Seatbelt denials in the audit trail.
pub const SEATBELT_VIOLATIONS_ENV: &str = "CLAWCRATE_SEATBELT_VIOLATIONS";

/// Upper bound on retained violations, mirroring the egress denial buffer: a
/// process denied in a loop must not grow this without limit.
const MAX_RECORDED_VIOLATIONS: usize = 256;

/// Longest window queried from the unified log. A long-lived process — an MCP
/// server, say — can outlive this, in which case only the tail is recovered and
/// [`SeatbeltViolationReport::window_truncated`] says so rather than letting the
/// report read as complete.
const MAX_LOOKBACK_SECONDS: u64 = 900;

/// Margin added to the queried window to absorb the delay between the kernel
/// emitting a denial and the log store making it visible.
const LOOKBACK_MARGIN_SECONDS: u64 = 2;

/// A single denial the kernel attributed to the sandboxed process.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct SeatbeltViolation {
    /// The refused sandbox operation, e.g. `file-read-data`.
    pub operation: String,
    /// What it was refused on: a path for file operations, a service name for
    /// `mach-lookup`, and so on. Empty when the message carried no target.
    pub target: String,
}

impl SeatbeltViolation {
    /// The blocked resource, as recorded in the audit event.
    pub fn resource(&self) -> String {
        if self.target.is_empty() {
            self.operation.clone()
        } else {
            self.target.clone()
        }
    }

    /// Human-readable explanation, as recorded in the audit event.
    pub fn reason_text(&self) -> String {
        format!("macOS Seatbelt denied {}", self.operation)
    }
}

/// The outcome of a log query.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SeatbeltViolationReport {
    /// Distinct denials, in the order first seen.
    pub violations: Vec<SeatbeltViolation>,
    /// Distinct denials observed past the retention cap.
    pub dropped: usize,
    /// Whether the queried window was shorter than the run, so that denials
    /// from before the window are missing.
    pub window_truncated: bool,
}

/// Whether Seatbelt denial capture is switched on.
pub fn violation_capture_enabled() -> bool {
    matches!(
        std::env::var(SEATBELT_VIOLATIONS_ENV).as_deref(),
        Ok("1") | Ok("true")
    )
}

/// Queries the unified log for denials attributed to `pid` within `window`.
///
/// Returns an empty report on any failure — a missing `log` binary, a query
/// error, unparseable output. Denial capture is a diagnostic enrichment, and
/// failing to read the log must never fail the run itself.
pub fn collect_violations(pid: u32, window: Duration) -> SeatbeltViolationReport {
    let requested = window.as_secs().saturating_add(LOOKBACK_MARGIN_SECONDS);
    let lookback = requested.clamp(1, MAX_LOOKBACK_SECONDS);
    let window_truncated = requested > MAX_LOOKBACK_SECONDS;

    let Some(output) = run_log_show(lookback) else {
        return SeatbeltViolationReport {
            window_truncated,
            ..Default::default()
        };
    };

    let mut report = parse_log_output(&output, pid);
    report.window_truncated = window_truncated;
    report
}

#[cfg(target_os = "macos")]
fn run_log_show(lookback_seconds: u64) -> Option<String> {
    use std::process::Command;

    let output = Command::new("/usr/bin/log")
        .args([
            "show",
            "--style",
            "compact",
            "--last",
            &format!("{lookback_seconds}s"),
            "--predicate",
            // Filtering server-side keeps the returned volume proportional to
            // actual denials rather than to total system log traffic.
            "senderImagePath CONTAINS[c] \"Sandbox\"",
        ])
        .output()
        .ok()?;

    if !output.status.success() {
        return None;
    }
    String::from_utf8(output.stdout).ok()
}

#[cfg(not(target_os = "macos"))]
fn run_log_show(_lookback_seconds: u64) -> Option<String> {
    None
}

/// Extracts the denials belonging to `pid`, discarding repeats.
fn parse_log_output(output: &str, pid: u32) -> SeatbeltViolationReport {
    let mut violations = Vec::new();
    let mut seen: HashSet<SeatbeltViolation> = HashSet::new();
    let mut dropped = 0usize;

    for line in output.lines() {
        let Some(violation) = parse_denial_line(line, pid) else {
            continue;
        };
        // The kernel already collapses bursts into "N duplicate reports"; this
        // collapses the rest, so one loop of denied reads does not bury the
        // audit trail under identical entries.
        if !seen.insert(violation.clone()) {
            continue;
        }
        if violations.len() >= MAX_RECORDED_VIOLATIONS {
            dropped = dropped.saturating_add(1);
            continue;
        }
        violations.push(violation);
    }

    SeatbeltViolationReport {
        violations,
        dropped,
        window_truncated: false,
    }
}

/// Parses one log line, returning the denial only when it belongs to `pid`.
///
/// Handles the two shapes the kernel emits:
///
/// ```text
/// Sandbox: cat(47036) deny(1) file-read-data /private/etc/hosts
/// 4 duplicate reports for Sandbox: cat(47036) deny(1) file-read-data /etc/x
/// ```
fn parse_denial_line(line: &str, pid: u32) -> Option<SeatbeltViolation> {
    const PREFIX: &str = "Sandbox: ";
    const DENY_MARKER: &str = ") deny(";

    // The compact log format prepends a timestamp, subsystem and sender, and a
    // duplicate-report line prepends a count; the payload starts at the last
    // `Sandbox: ` on the line.
    let prefix_at = line.rfind(PREFIX)?;
    let payload = &line[prefix_at + PREFIX.len()..];

    // `name(pid) deny(n) operation target`. Splitting on `) deny(` isolates the
    // PID without assuming the process name is free of parentheses.
    let deny_at = payload.find(DENY_MARKER)?;
    let before_deny = &payload[..deny_at];
    let pid_at = before_deny.rfind('(')?;
    let logged_pid: u32 = before_deny[pid_at + 1..].trim().parse().ok()?;
    if logged_pid != pid {
        return None;
    }

    let after_deny = &payload[deny_at + DENY_MARKER.len()..];
    let deny_close = after_deny.find(')')?;
    let tail = after_deny[deny_close + 1..].trim();
    if tail.is_empty() {
        return None;
    }

    let (operation, target) = match tail.split_once(char::is_whitespace) {
        Some((operation, target)) => (operation, target.trim()),
        None => (tail, ""),
    };

    Some(SeatbeltViolation {
        operation: operation.to_string(),
        target: target.to_string(),
    })
}

#[cfg(test)]
mod tests {
    use super::{parse_denial_line, parse_log_output, SeatbeltViolation, MAX_RECORDED_VIOLATIONS};

    /// Captured verbatim from `log show` after provoking a real denial.
    const REAL_LINE: &str = "2026-07-28 19:15:37.331 E  kernel[0:662448] (Sandbox) Sandbox: cat(47036) deny(1) file-read-data /private/etc/hosts";

    #[test]
    fn parses_a_real_denial_line() {
        let violation = parse_denial_line(REAL_LINE, 47036).expect("line should parse");
        assert_eq!(violation.operation, "file-read-data");
        assert_eq!(violation.target, "/private/etc/hosts");
        assert_eq!(violation.resource(), "/private/etc/hosts");
        assert_eq!(
            violation.reason_text(),
            "macOS Seatbelt denied file-read-data"
        );
    }

    #[test]
    fn never_attributes_another_process_denial_to_this_run() {
        // The unified log is system-wide. Attributing someone else's denial to
        // this run would put unrelated system activity into a user's audit
        // trail and invent evidence about what the sandbox blocked.
        assert!(parse_denial_line(REAL_LINE, 47037).is_none());
        assert!(parse_denial_line(REAL_LINE, 4703).is_none());
        assert!(parse_denial_line(REAL_LINE, 470360).is_none());

        let other =
            "kernel (Sandbox) Sandbox: imagent(688) deny(1) mach-lookup com.apple.contactsd";
        assert!(parse_denial_line(other, 47036).is_none());
        assert_eq!(
            parse_denial_line(other, 688).map(|v| v.operation),
            Some("mach-lookup".to_string())
        );
    }

    #[test]
    fn parses_duplicate_report_lines() {
        let line = "kernel (Sandbox) 4 duplicate reports for Sandbox: cat(47036) deny(1) file-read-data /private/etc/hosts";
        let violation = parse_denial_line(line, 47036).expect("duplicate line should parse");
        assert_eq!(violation.target, "/private/etc/hosts");
    }

    #[test]
    fn parses_targets_containing_spaces() {
        let line = "kernel (Sandbox) Sandbox: node(31) deny(1) file-read-data /Users/me/Application Support/x.db";
        let violation = parse_denial_line(line, 31).expect("line should parse");
        assert_eq!(violation.operation, "file-read-data");
        assert_eq!(
            violation.target, "/Users/me/Application Support/x.db",
            "a path with spaces must survive intact"
        );
    }

    #[test]
    fn ignores_lines_that_are_not_denials() {
        assert!(parse_denial_line("", 1).is_none());
        assert!(parse_denial_line("some unrelated log line", 1).is_none());
        assert!(
            parse_denial_line("Sandbox: cat(47036) allow(1) file-read-data /x", 47036).is_none()
        );
        // A denial with no operation carries nothing worth recording.
        assert!(parse_denial_line("Sandbox: cat(47036) deny(1) ", 47036).is_none());
    }

    #[test]
    fn deduplicates_repeated_denials_and_keeps_distinct_ones() {
        let output = "\
kernel (Sandbox) Sandbox: cat(9) deny(1) file-read-data /etc/hosts
kernel (Sandbox) Sandbox: cat(9) deny(1) file-read-data /etc/hosts
kernel (Sandbox) Sandbox: cat(9) deny(1) file-read-data /etc/passwd
kernel (Sandbox) Sandbox: other(10) deny(1) file-read-data /etc/shadow";

        let report = parse_log_output(output, 9);
        assert_eq!(
            report.violations,
            vec![
                SeatbeltViolation {
                    operation: "file-read-data".to_string(),
                    target: "/etc/hosts".to_string(),
                },
                SeatbeltViolation {
                    operation: "file-read-data".to_string(),
                    target: "/etc/passwd".to_string(),
                },
            ],
            "repeats collapse, distinct denials survive, other PIDs are excluded"
        );
        assert_eq!(report.dropped, 0);
    }

    #[test]
    fn bounds_retained_violations_and_counts_the_rest() {
        let overflow = 3usize;
        let output = (0..MAX_RECORDED_VIOLATIONS + overflow)
            .map(|index| {
                format!("kernel (Sandbox) Sandbox: cat(9) deny(1) file-read-data /etc/f{index}")
            })
            .collect::<Vec<_>>()
            .join("\n");

        let report = parse_log_output(&output, 9);
        assert_eq!(report.violations.len(), MAX_RECORDED_VIOLATIONS);
        assert_eq!(report.dropped, overflow);
    }
}
