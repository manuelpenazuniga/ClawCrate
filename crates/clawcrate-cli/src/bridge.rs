//! bridge module (extracted from main.rs; see #277).

use std::io::{self, Read};

use crate::{api::*, cli::*, output::*};
use anyhow::{anyhow, Result};
use serde::{Deserialize, Serialize};

#[derive(Debug, Deserialize)]
pub(crate) struct PennyPromptBridgeRequest {
    pub(crate) action: String,
    pub(crate) profile: Option<String>,
    #[serde(default)]
    pub(crate) replica: bool,
    #[serde(default)]
    pub(crate) direct: bool,
    #[serde(default)]
    pub(crate) approve_out_of_profile: bool,
    #[serde(default)]
    pub(crate) command: Vec<String>,
}

#[derive(Debug, Serialize)]
pub(crate) struct PennyPromptBridgeResponse {
    pub(crate) ok: bool,
    pub(crate) action: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) data: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) error: Option<PennyPromptBridgeError>,
}

#[derive(Debug, Serialize)]
pub(crate) struct PennyPromptBridgeError {
    pub(crate) message: String,
    pub(crate) exit_code: Option<i32>,
    pub(crate) stdout: String,
    pub(crate) stderr: String,
}

pub(crate) fn handle_bridge(args: BridgeArgs, _output: &OutputOptions) -> Result<()> {
    match args.target {
        BridgeTarget::Pennyprompt(config) => handle_pennyprompt_bridge(config),
    }
}

pub(crate) fn handle_pennyprompt_bridge(config: PennyPromptBridgeArgs) -> Result<()> {
    let mut input = String::new();
    let read_result = io::stdin().read_to_string(&mut input).map(|_| input);
    let response =
        build_pennyprompt_bridge_response_from_input_result(read_result, execute_cli_json);

    if config.pretty {
        println!("{}", serde_json::to_string_pretty(&response)?);
    } else {
        println!("{}", serde_json::to_string(&response)?);
    }

    Ok(())
}

pub(crate) fn normalize_action(action: &str) -> String {
    action.trim().to_ascii_lowercase()
}

pub(crate) fn build_pennyprompt_bridge_response_with_executor<F>(
    input: &str,
    executor: F,
) -> PennyPromptBridgeResponse
where
    F: Fn(&[String]) -> std::result::Result<serde_json::Value, ApiCommandError>,
{
    if input.trim().is_empty() {
        return pennyprompt_validation_error_response(
            "unknown".to_string(),
            "missing PennyPrompt bridge payload: provide JSON on stdin".to_string(),
        );
    }

    let request = match serde_json::from_str::<PennyPromptBridgeRequest>(input) {
        Ok(request) => request,
        Err(source) => {
            return pennyprompt_validation_error_response(
                "unknown".to_string(),
                format!("invalid PennyPrompt bridge payload JSON: {source}"),
            );
        }
    };

    let action = normalize_action(&request.action);
    let delegated_args = match build_pennyprompt_cli_args(&action, &request) {
        Ok(args) => args,
        Err(error) => {
            return pennyprompt_validation_error_response(action, error.to_string());
        }
    };

    match executor(&delegated_args) {
        Ok(data) => PennyPromptBridgeResponse {
            ok: true,
            action,
            data: Some(data),
            error: None,
        },
        Err(error) => PennyPromptBridgeResponse {
            ok: false,
            action,
            data: None,
            error: Some(PennyPromptBridgeError {
                message: error.error,
                exit_code: error.exit_code,
                stdout: error.stdout,
                stderr: error.stderr,
            }),
        },
    }
}

pub(crate) fn build_pennyprompt_bridge_response_from_input_result<F>(
    input_result: io::Result<String>,
    executor: F,
) -> PennyPromptBridgeResponse
where
    F: Fn(&[String]) -> std::result::Result<serde_json::Value, ApiCommandError>,
{
    match input_result {
        Ok(input) => build_pennyprompt_bridge_response_with_executor(&input, executor),
        Err(source) => pennyprompt_validation_error_response(
            "unknown".to_string(),
            format!("failed to read PennyPrompt bridge payload from stdin: {source}"),
        ),
    }
}

pub(crate) fn pennyprompt_validation_error_response(
    action: String,
    message: String,
) -> PennyPromptBridgeResponse {
    PennyPromptBridgeResponse {
        ok: false,
        action,
        data: None,
        error: Some(PennyPromptBridgeError {
            message,
            exit_code: None,
            stdout: String::new(),
            stderr: String::new(),
        }),
    }
}

pub(crate) fn build_pennyprompt_cli_args(
    action: &str,
    request: &PennyPromptBridgeRequest,
) -> Result<Vec<String>> {
    match action {
        "doctor" => Ok(vec!["doctor".to_string(), "--json".to_string()]),
        "plan" | "run" => {
            let payload = ApiCommandRequest {
                profile: request.profile.clone(),
                replica: request.replica,
                direct: request.direct,
                approve_out_of_profile: request.approve_out_of_profile,
                command: request.command.clone(),
            };
            build_api_cli_args(action, &payload)
        }
        other => Err(anyhow!(
            "unsupported PennyPrompt action `{other}` (expected run, plan, or doctor)"
        )),
    }
}
