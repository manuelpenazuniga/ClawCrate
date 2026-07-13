//! api module (extracted from main.rs; see #277).

use std::collections::VecDeque;
use std::process::Command;
use std::sync::{Arc, Condvar, Mutex};
use std::thread;

use crate::{cli::*, output::*};
use anyhow::{anyhow, Result};
use serde::{Deserialize, Serialize};
use tiny_http::{Header, Method, Request, Response, Server, StatusCode};

#[derive(Debug, Deserialize)]
pub(crate) struct ApiCommandRequest {
    pub(crate) profile: Option<String>,
    #[serde(default)]
    pub(crate) replica: bool,
    #[serde(default)]
    pub(crate) direct: bool,
    #[serde(default)]
    pub(crate) approve_out_of_profile: bool,
    pub(crate) command: Vec<String>,
}

#[derive(Debug, Clone, Copy)]
pub(crate) enum ApiRoute {
    Health,
    Doctor,
    Plan,
    Run,
}

#[derive(Debug)]
pub(crate) struct ApiDelegatedRequest {
    pub(crate) request: Request,
    pub(crate) route: ApiRoute,
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum QueueEnqueueError<T> {
    Full(T),
    Closed(T),
}

#[derive(Debug)]
pub(crate) struct BoundedWorkQueue<T> {
    pub(crate) capacity: usize,
    pub(crate) state: Mutex<BoundedWorkQueueState<T>>,
    pub(crate) available: Condvar,
}

#[derive(Debug)]
pub(crate) struct BoundedWorkQueueState<T> {
    pub(crate) queue: VecDeque<T>,
    pub(crate) closed: bool,
}

impl<T> BoundedWorkQueue<T> {
    pub(crate) fn new(capacity: usize) -> Self {
        Self {
            capacity,
            state: Mutex::new(BoundedWorkQueueState {
                queue: VecDeque::new(),
                closed: false,
            }),
            available: Condvar::new(),
        }
    }

    pub(crate) fn try_enqueue(&self, item: T) -> Result<(), QueueEnqueueError<T>> {
        let mut state = match self.state.lock() {
            Ok(state) => state,
            Err(_) => return Err(QueueEnqueueError::Closed(item)),
        };
        if state.closed {
            return Err(QueueEnqueueError::Closed(item));
        }
        if state.queue.len() >= self.capacity {
            return Err(QueueEnqueueError::Full(item));
        }
        state.queue.push_back(item);
        self.available.notify_one();
        Ok(())
    }

    pub(crate) fn dequeue_blocking(&self) -> Option<T> {
        let mut state = self.state.lock().ok()?;
        loop {
            if let Some(item) = state.queue.pop_front() {
                return Some(item);
            }
            if state.closed {
                return None;
            }
            state = self.available.wait(state).ok()?;
        }
    }

    pub(crate) fn close(&self) {
        if let Ok(mut state) = self.state.lock() {
            state.closed = true;
            self.available.notify_all();
        }
    }

    #[cfg(test)]
    pub(crate) fn len(&self) -> usize {
        self.state
            .lock()
            .map(|state| state.queue.len())
            .unwrap_or(0)
    }
}

#[derive(Debug, Serialize)]
pub(crate) struct ApiCommandError {
    pub(crate) error: String,
    pub(crate) exit_code: Option<i32>,
    pub(crate) stdout: String,
    pub(crate) stderr: String,
}

pub(crate) const API_MAX_WORKERS: usize = 4;
const API_MAX_QUEUE_DEPTH: usize = 16;

pub(crate) fn handle_api(args: ApiArgs, output: &OutputOptions) -> Result<()> {
    let token = resolve_api_token(&args)?;
    let server = Server::http(&args.bind)
        .map_err(|source| anyhow!("failed to bind local API on {}: {source}", args.bind))?;
    let delegated_queue = Arc::new(BoundedWorkQueue::<ApiDelegatedRequest>::new(
        API_MAX_QUEUE_DEPTH,
    ));

    for _ in 0..API_MAX_WORKERS {
        let delegated_queue = Arc::clone(&delegated_queue);
        let output = *output;
        thread::spawn(move || {
            while let Some(delegated) = delegated_queue.dequeue_blocking() {
                handle_api_delegated_route(delegated.request, delegated.route, &output);
            }
        });
    }

    verbose_log(output, 1, format!("api server listening on {}", args.bind));
    println!("clawcrate api listening on http://{}", args.bind);

    for request in server.incoming_requests() {
        dispatch_api_request(request, &token, output, &delegated_queue);
    }
    delegated_queue.close();

    Ok(())
}

pub(crate) fn resolve_api_token(args: &ApiArgs) -> Result<String> {
    let token = args
        .token
        .clone()
        .or_else(|| std::env::var("CLAWCRATE_API_TOKEN").ok())
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
        .ok_or_else(|| {
            anyhow!(
                "missing API token: provide --token or set CLAWCRATE_API_TOKEN for `clawcrate api`"
            )
        })?;
    Ok(token)
}

pub(crate) fn dispatch_api_request(
    request: Request,
    token: &str,
    output: &OutputOptions,
    delegated_queue: &BoundedWorkQueue<ApiDelegatedRequest>,
) {
    if !request_authorized(request.headers(), token) {
        respond_api_json(
            request,
            401,
            &serde_json::json!({ "error": "unauthorized" }),
        );
        return;
    }

    let Some(route) = resolve_api_route(request.method(), request.url()) else {
        respond_api_json(request, 404, &serde_json::json!({ "error": "not found" }));
        return;
    };

    if !api_route_uses_delegated_worker(route) {
        respond_api_json(
            request,
            200,
            &serde_json::json!({
                "status": "ok",
                "version": env!("CARGO_PKG_VERSION")
            }),
        );
        return;
    }

    match delegated_queue.try_enqueue(ApiDelegatedRequest { request, route }) {
        Ok(()) => {}
        Err(QueueEnqueueError::Full(ApiDelegatedRequest { request, .. })) => {
            verbose_log(
                output,
                1,
                "api delegated request queue is full; returning 503",
            );
            respond_api_json(
                request,
                503,
                &serde_json::json!({ "error": "server busy", "detail": "too many in-flight API requests" }),
            );
        }
        Err(QueueEnqueueError::Closed(ApiDelegatedRequest { request, .. })) => {
            respond_api_json(
                request,
                503,
                &serde_json::json!({ "error": "server unavailable" }),
            );
        }
    }
}

pub(crate) fn api_route_uses_delegated_worker(route: ApiRoute) -> bool {
    matches!(route, ApiRoute::Doctor | ApiRoute::Plan | ApiRoute::Run)
}

pub(crate) fn handle_api_delegated_route(
    mut request: Request,
    route: ApiRoute,
    output: &OutputOptions,
) {
    match route {
        ApiRoute::Health => {
            respond_api_json(
                request,
                500,
                &serde_json::json!({ "error": "invalid delegated route" }),
            );
        }
        ApiRoute::Doctor => {
            let args = vec!["doctor".to_string(), "--json".to_string()];
            respond_api_with_cli_json(request, &args, output);
        }
        ApiRoute::Plan => {
            let payload = match parse_api_command_payload(&mut request) {
                Ok(payload) => payload,
                Err(error) => {
                    respond_api_json(request, 400, &serde_json::json!({ "error": error }));
                    return;
                }
            };
            let args = match build_api_cli_args("plan", &payload) {
                Ok(args) => args,
                Err(error) => {
                    respond_api_json(
                        request,
                        400,
                        &serde_json::json!({ "error": error.to_string() }),
                    );
                    return;
                }
            };
            respond_api_with_cli_json(request, &args, output);
        }
        ApiRoute::Run => {
            let payload = match parse_api_command_payload(&mut request) {
                Ok(payload) => payload,
                Err(error) => {
                    respond_api_json(request, 400, &serde_json::json!({ "error": error }));
                    return;
                }
            };
            let args = match build_api_cli_args("run", &payload) {
                Ok(args) => args,
                Err(error) => {
                    respond_api_json(
                        request,
                        400,
                        &serde_json::json!({ "error": error.to_string() }),
                    );
                    return;
                }
            };
            respond_api_with_cli_json(request, &args, output);
        }
    }
}

pub(crate) fn parse_api_command_payload(
    request: &mut Request,
) -> std::result::Result<ApiCommandRequest, String> {
    let mut body = String::new();
    request
        .as_reader()
        .read_to_string(&mut body)
        .map_err(|source| format!("failed to read request body: {source}"))?;
    serde_json::from_str::<ApiCommandRequest>(&body)
        .map_err(|source| format!("invalid JSON body: {source}"))
}

pub(crate) fn build_api_cli_args(action: &str, payload: &ApiCommandRequest) -> Result<Vec<String>> {
    if payload.command.is_empty() {
        return Err(anyhow!("`command` must contain at least one element"));
    }
    if payload.replica && payload.direct {
        return Err(anyhow!("`replica` and `direct` cannot be enabled together"));
    }

    let mut args = vec![action.to_string(), "--json".to_string()];
    if let Some(profile) = &payload.profile {
        args.push("--profile".to_string());
        args.push(profile.clone());
    }
    if payload.replica {
        args.push("--replica".to_string());
    }
    if payload.direct {
        args.push("--direct".to_string());
    }
    if action == "run" && payload.approve_out_of_profile {
        args.push("--approve-out-of-profile".to_string());
    }
    args.push("--".to_string());
    args.extend(payload.command.clone());

    Ok(args)
}

pub(crate) fn resolve_api_route(method: &Method, url: &str) -> Option<ApiRoute> {
    let path = url.split('?').next().unwrap_or(url);
    match (method, path) {
        (Method::Get, "/v1/health") => Some(ApiRoute::Health),
        (Method::Get, "/v1/doctor") => Some(ApiRoute::Doctor),
        (Method::Post, "/v1/plan") => Some(ApiRoute::Plan),
        (Method::Post, "/v1/run") => Some(ApiRoute::Run),
        _ => None,
    }
}

pub(crate) fn extract_bearer_token(headers: &[Header]) -> Option<String> {
    headers
        .iter()
        .find(|header| header.field.equiv("Authorization"))
        .and_then(|header| {
            let value = header.value.as_str();
            value
                .strip_prefix("Bearer ")
                .map(str::trim)
                .filter(|token| !token.is_empty())
        })
        .map(ToString::to_string)
}

pub(crate) fn request_authorized(headers: &[Header], expected_token: &str) -> bool {
    extract_bearer_token(headers)
        .as_deref()
        .map(|token| constant_time_eq(token.as_bytes(), expected_token.as_bytes()))
        .unwrap_or(false)
}

pub(crate) fn constant_time_eq(left: &[u8], right: &[u8]) -> bool {
    let max_len = left.len().max(right.len());
    let mut diff = left.len() ^ right.len();
    for idx in 0..max_len {
        let left_byte = left.get(idx).copied().unwrap_or(0);
        let right_byte = right.get(idx).copied().unwrap_or(0);
        diff |= usize::from(left_byte ^ right_byte);
    }
    diff == 0
}

pub(crate) fn respond_api_with_cli_json(request: Request, args: &[String], output: &OutputOptions) {
    match execute_cli_json(args) {
        Ok(value) => {
            respond_api_json(request, 200, &value);
        }
        Err(error) => {
            verbose_log(
                output,
                1,
                format!(
                    "api delegated command failed: args={:?}, error={}",
                    args, error.error
                ),
            );
            respond_api_json(request, 422, &error);
        }
    }
}

pub(crate) fn execute_cli_json(
    args: &[String],
) -> std::result::Result<serde_json::Value, ApiCommandError> {
    let exe = std::env::current_exe().map_err(|source| ApiCommandError {
        error: format!("failed to resolve clawcrate executable path: {source}"),
        exit_code: None,
        stdout: String::new(),
        stderr: String::new(),
    })?;

    let output = Command::new(exe)
        .args(args)
        .output()
        .map_err(|source| ApiCommandError {
            error: format!("failed to execute delegated clawcrate command: {source}"),
            exit_code: None,
            stdout: String::new(),
            stderr: String::new(),
        })?;

    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).to_string();
    if !output.status.success() {
        return Err(ApiCommandError {
            error: "delegated clawcrate command failed".to_string(),
            exit_code: output.status.code(),
            stdout,
            stderr,
        });
    }

    serde_json::from_str::<serde_json::Value>(&stdout).map_err(|source| ApiCommandError {
        error: format!("delegated clawcrate output was not valid JSON: {source}"),
        exit_code: output.status.code(),
        stdout,
        stderr,
    })
}

pub(crate) fn respond_api_json<T: Serialize>(request: Request, status_code: u16, payload: &T) {
    let body = serialize_api_payload(payload);
    let mut response = Response::from_data(body).with_status_code(StatusCode(status_code));
    if let Ok(header) = Header::from_bytes("Content-Type", "application/json; charset=utf-8") {
        response.add_header(header);
    }
    let _ = request.respond(response);
}

pub(crate) fn serialize_api_payload<T: Serialize>(payload: &T) -> Vec<u8> {
    match serde_json::to_vec(payload) {
        Ok(body) => body,
        Err(source) => serde_json::to_vec(&serde_json::json!({
            "error": "failed to serialize API response",
            "detail": source.to_string(),
        }))
        .unwrap_or_else(|_| b"{\"error\":\"failed to serialize API response\"}".to_vec()),
    }
}
