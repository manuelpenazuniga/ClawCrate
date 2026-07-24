#![forbid(unsafe_code)]

mod mcp_install;

use anyhow::Result;
use clap::Parser;
use clawcrate_profiles::ProfileResolver;

mod api;
mod approval;
mod audit_export;
mod bridge;
mod cli;
mod doctor;
mod mcp;
mod output;
mod replica;
mod run;
mod support;
mod verify;

use crate::{
    api::*, audit_export::*, bridge::*, cli::*, doctor::*, mcp::*, output::*, run::*, verify::*,
};

fn main() {
    let cli = Cli::parse();
    let output = OutputOptions::from_global(&cli.global);
    if let Err(error) = run(cli, output) {
        print_cli_error(&error, output.verbose);
        std::process::exit(1);
    }
}

fn run(cli: Cli, output: OutputOptions) -> Result<()> {
    let resolver = ProfileResolver::default();

    match cli.command {
        Commands::Plan(args) => handle_plan(&resolver, args, &output),
        Commands::Run(args) => handle_run(&resolver, args, &output),
        Commands::Doctor(args) => handle_doctor(args, &output),
        Commands::Api(args) => handle_api(args, &output),
        Commands::Mcp(args) => handle_mcp(&resolver, args, &output),
        Commands::Bridge(args) => handle_bridge(args, &output),
        Commands::Verify(args) => handle_verify(args, &output),
        Commands::Audit(args) => handle_audit(args),
    }
}

#[cfg(test)]
mod tests;
