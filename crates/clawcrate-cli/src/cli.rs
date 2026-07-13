//! cli module (extracted from main.rs; see #277).

use std::path::PathBuf;

use crate::mcp_install;
use clap::{ArgAction, Args, Parser, Subcommand, ValueEnum};

#[derive(Debug, Parser)]
#[command(
    name = "clawcrate",
    version,
    about = "Secure execution runtime for AI shell commands"
)]
pub(crate) struct Cli {
    #[command(flatten)]
    pub(crate) global: GlobalArgs,

    #[command(subcommand)]
    pub(crate) command: Commands,
}

#[derive(Debug, Args, Clone, Copy)]
pub(crate) struct GlobalArgs {
    /// Increase diagnostic verbosity (-v, -vv)
    #[arg(short = 'v', long, action = ArgAction::Count, global = true)]
    pub(crate) verbose: u8,

    /// Disable ANSI colors in human-readable output
    #[arg(long, action = ArgAction::SetTrue, global = true)]
    pub(crate) no_color: bool,
}

#[derive(Debug, Subcommand)]
pub(crate) enum Commands {
    /// Execute a command inside a sandbox
    Run(CommandArgs),
    /// Show execution plan without executing (dry-run)
    Plan(CommandArgs),
    /// Check system sandboxing capabilities
    Doctor(DoctorArgs),
    /// Serve local authenticated HTTP API for tool integrations
    Api(ApiArgs),
    /// Wrap stdio MCP servers in a ClawCrate profile
    Mcp(McpArgs),
    /// Integration bridges for external agent tooling
    Bridge(BridgeArgs),
    /// Verify the SHA-256 hash chain of a run's audit log
    Verify(VerifyArgs),
    /// Audit artifact utilities
    Audit(AuditArgs),
}

#[derive(Debug, Args)]
pub(crate) struct CommandArgs {
    /// Built-in profile name (safe/build/install/open) or YAML file path
    #[arg(long)]
    pub(crate) profile: Option<String>,

    /// Force replica mode
    #[arg(long, action = ArgAction::SetTrue, conflicts_with = "direct")]
    pub(crate) replica: bool,

    /// Force direct mode
    #[arg(long, action = ArgAction::SetTrue, conflicts_with = "replica")]
    pub(crate) direct: bool,

    /// Machine-readable JSON output
    #[arg(long, action = ArgAction::SetTrue)]
    pub(crate) json: bool,

    /// Auto-approve detected permission requests outside the active profile
    #[arg(long, action = ArgAction::SetTrue)]
    pub(crate) approve_out_of_profile: bool,

    /// Command to plan/execute (pass after --)
    #[arg(trailing_var_arg = true, num_args = 1.., required = true)]
    pub(crate) command: Vec<String>,
}

#[derive(Debug, Args)]
pub(crate) struct DoctorArgs {
    /// Machine-readable JSON output
    #[arg(long, action = ArgAction::SetTrue)]
    pub(crate) json: bool,
}

#[derive(Debug, Args)]
pub(crate) struct VerifyArgs {
    /// Run ID (directory name under ~/.clawcrate/runs/)
    pub(crate) run_id: String,

    /// Ed25519 public key PEM used to validate BlockSignature entries
    #[arg(long)]
    pub(crate) pubkey: Option<PathBuf>,

    /// Machine-readable JSON output
    #[arg(long, action = ArgAction::SetTrue)]
    pub(crate) json: bool,
}

#[derive(Debug, Args)]
pub(crate) struct AuditArgs {
    #[command(subcommand)]
    pub(crate) command: AuditCommand,
}

#[derive(Debug, Subcommand)]
pub(crate) enum AuditCommand {
    /// Export audit.ndjson to SIEM-friendly formats
    Export(AuditExportArgs),
}

#[derive(Debug, Args)]
pub(crate) struct AuditExportArgs {
    /// Run ID (directory name under ~/.clawcrate/runs/)
    pub(crate) run_id: String,

    /// Export format
    #[arg(long, value_enum, default_value_t = AuditExportFormat::Json)]
    pub(crate) format: AuditExportFormat,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub(crate) enum AuditExportFormat {
    /// ClawCrate native audit.ndjson passthrough
    Json,
    /// ArcSight Common Event Format
    Cef,
    /// RFC 5424 syslog lines
    Syslog,
    /// Elasticsearch/OpenSearch bulk NDJSON
    Elastic,
}

#[derive(Debug, Args)]
pub(crate) struct ApiArgs {
    /// Bind address for local API server
    #[arg(long, default_value = "127.0.0.1:8787")]
    pub(crate) bind: String,

    /// Bearer token for API authentication (fallback: CLAWCRATE_API_TOKEN)
    #[arg(long)]
    pub(crate) token: Option<String>,
}

#[derive(Debug, Args)]
pub(crate) struct McpArgs {
    #[command(subcommand)]
    pub(crate) command: McpCommand,
}

#[derive(Debug, Subcommand)]
pub(crate) enum McpCommand {
    /// Wrap a stdio MCP server command
    Wrap(McpWrapArgs),
    /// Rewrite an MCP client config to route a server through `clawcrate mcp wrap`
    Install(mcp_install::McpInstallArgs),
    /// Restore an MCP client config entry to its pre-wrap command
    Uninstall(mcp_install::McpUninstallArgs),
}

#[derive(Debug, Args)]
pub(crate) struct McpWrapArgs {
    /// MCP profile name or YAML file path, usually mcp-readonly or mcp-server.
    /// If omitted, a conservative MCP command-shape detector selects mcp-readonly.
    #[arg(long)]
    pub(crate) profile: Option<String>,

    /// Force replica mode
    #[arg(long, action = ArgAction::SetTrue, conflicts_with = "direct")]
    pub(crate) replica: bool,

    /// Force direct mode
    #[arg(long, action = ArgAction::SetTrue, conflicts_with = "replica")]
    pub(crate) direct: bool,

    /// MCP server command to launch (must be passed after --)
    #[arg(last = true, num_args = 1.., required = true)]
    pub(crate) command: Vec<String>,
}

#[derive(Debug, Args)]
pub(crate) struct BridgeArgs {
    #[command(subcommand)]
    pub(crate) target: BridgeTarget,
}

#[derive(Debug, Subcommand)]
pub(crate) enum BridgeTarget {
    /// One-shot JSON bridge compatible with PennyPrompt shell-dispatch flow
    Pennyprompt(PennyPromptBridgeArgs),
}

#[derive(Debug, Args)]
pub(crate) struct PennyPromptBridgeArgs {
    /// Pretty-print JSON output
    #[arg(long, action = ArgAction::SetTrue)]
    pub(crate) pretty: bool,
}
