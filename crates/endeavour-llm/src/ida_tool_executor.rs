use std::str::FromStr;
use std::sync::Arc;

use async_trait::async_trait;
use endeavour_ida::{IdaClient, IdaError};
use serde::Serialize;
use serde_json::{json, Map, Value};

use crate::agentic::ToolExecutor;
use crate::types::{ToolCall, ToolDefinition, ToolResult};

const TOOL_DECOMPILE: &str = "decompile";
const TOOL_GET_FUNCTION_INFO: &str = "get_function_info";
const TOOL_GET_XREFS: &str = "get_xrefs";
const TOOL_GET_STRINGS: &str = "get_strings";
const TOOL_LIST_FUNCTIONS: &str = "list_functions";
const TOOL_GET_FUNCTION_LIST: &str = "get_function_list";
const TOOL_RENAME_FUNCTION: &str = "rename_function";
const TOOL_RENAME_VARIABLE: &str = "rename_variable";
const TOOL_SET_COMMENT: &str = "set_comment";

const FIELD_ADDR: &str = "addr";
const FIELD_QUERY: &str = "query";
const FIELD_PATTERN: &str = "pattern";
const FIELD_FILTER: &str = "filter";
const FIELD_COUNT: &str = "count";
const FIELD_NEW_NAME: &str = "new_name";
const FIELD_OLD_NAME: &str = "old_name";
const FIELD_COMMENT: &str = "comment";
const FIELD_MODE: &str = "mode";
const FIELD_CONFIDENCE: &str = "confidence";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
enum WriteMode {
    #[default]
    Auto,
    Review,
    DryRun,
}

/// IDA-backed implementation of the agentic tool executor.
#[derive(Clone)]
pub struct IdaToolExecutor {
    client: Arc<IdaClient>,
    default_write_mode: WriteMode,
}

impl IdaToolExecutor {
    /// Creates a new executor with Sprint 4 default write mode (`auto`).
    pub fn new(client: Arc<IdaClient>) -> Self {
        Self {
            client,
            default_write_mode: WriteMode::Auto,
        }
    }

    /// Creates a new executor with explicit default write mode.
    pub fn with_default_write_mode(client: Arc<IdaClient>, mode: &str) -> Result<Self, String> {
        let parsed_mode = parse_mode(mode)?;
        Ok(Self {
            client,
            default_write_mode: parsed_mode,
        })
    }

    /// Returns Sprint 4 LLM-callable tool definitions and parameter schemas.
    pub fn tool_definitions() -> Vec<ToolDefinition> {
        vec![
            ToolDefinition {
                name: TOOL_DECOMPILE.to_string(),
                description: "Decompile a function by address.".to_string(),
                parameters: object_schema(vec![(FIELD_ADDR, address_schema())], vec![FIELD_ADDR]),
            },
            ToolDefinition {
                name: TOOL_GET_FUNCTION_INFO.to_string(),
                description: "Get function metadata by name or address query.".to_string(),
                parameters: object_schema(vec![(FIELD_QUERY, string_schema())], vec![FIELD_QUERY]),
            },
            ToolDefinition {
                name: TOOL_GET_XREFS.to_string(),
                description: "List cross-references to an address.".to_string(),
                parameters: object_schema(vec![(FIELD_ADDR, address_schema())], vec![FIELD_ADDR]),
            },
            ToolDefinition {
                name: TOOL_GET_STRINGS.to_string(),
                description: "Search strings by regex pattern.".to_string(),
                parameters: object_schema(
                    vec![(FIELD_PATTERN, string_schema())],
                    vec![FIELD_PATTERN],
                ),
            },
            ToolDefinition {
                name: TOOL_LIST_FUNCTIONS.to_string(),
                description: "List functions with optional name filter and count.".to_string(),
                parameters: object_schema(
                    vec![
                        (FIELD_FILTER, string_schema()),
                        (FIELD_COUNT, integer_schema(1)),
                    ],
                    Vec::new(),
                ),
            },
            ToolDefinition {
                name: TOOL_GET_FUNCTION_LIST.to_string(),
                description: "Alias for list_functions.".to_string(),
                parameters: object_schema(
                    vec![
                        (FIELD_FILTER, string_schema()),
                        (FIELD_COUNT, integer_schema(1)),
                    ],
                    Vec::new(),
                ),
            },
            ToolDefinition {
                name: TOOL_RENAME_FUNCTION.to_string(),
                description: "Rename a function symbol at an address.".to_string(),
                parameters: write_schema(vec![
                    (FIELD_ADDR, address_schema()),
                    (FIELD_NEW_NAME, string_schema()),
                ]),
            },
            ToolDefinition {
                name: TOOL_RENAME_VARIABLE.to_string(),
                description: "Rename a global/data variable symbol by current name.".to_string(),
                parameters: write_schema(vec![
                    (FIELD_OLD_NAME, string_schema()),
                    (FIELD_NEW_NAME, string_schema()),
                ]),
            },
            ToolDefinition {
                name: TOOL_SET_COMMENT.to_string(),
                description: "Set a comment at an address.".to_string(),
                parameters: write_schema(vec![
                    (FIELD_ADDR, address_schema()),
                    (FIELD_COMMENT, string_schema()),
                ]),
            },
        ]
    }

    fn execute_read_tool<'a>(&'a self, tool_call: &'a ToolCall) -> ExecuteFuture<'a> {
        Box::pin(async move {
            match tool_call.name.as_str() {
                TOOL_DECOMPILE => {
                    let addr = match required_addr(&tool_call.input, FIELD_ADDR) {
                        Ok(addr) => addr,
                        Err(message) => return invalid_args(tool_call, &message),
                    };
                    match self.client.decompile(addr).await {
                        Ok(result) => ok_result(
                            tool_call,
                            "decompile_ok",
                            "Decompile succeeded",
                            json!(result),
                        ),
                        Err(err) => ida_error_result(tool_call, err),
                    }
                }
                TOOL_GET_FUNCTION_INFO => {
                    let query = match required_string(&tool_call.input, FIELD_QUERY) {
                        Ok(value) => value,
                        Err(message) => return invalid_args(tool_call, &message),
                    };
                    match self.client.lookup_function(&query).await {
                        Ok(result) => ok_result(
                            tool_call,
                            "function_info_ok",
                            "Function lookup completed",
                            json!({"function": result}),
                        ),
                        Err(err) => ida_error_result(tool_call, err),
                    }
                }
                TOOL_GET_XREFS => {
                    let addr = match required_addr(&tool_call.input, FIELD_ADDR) {
                        Ok(addr) => addr,
                        Err(message) => return invalid_args(tool_call, &message),
                    };
                    match self.client.xrefs_to(addr).await {
                        Ok(xrefs) => ok_result(
                            tool_call,
                            "xrefs_ok",
                            "Xrefs fetched",
                            json!({"xrefs": xrefs}),
                        ),
                        Err(err) => ida_error_result(tool_call, err),
                    }
                }
                TOOL_GET_STRINGS => {
                    let pattern = match required_string(&tool_call.input, FIELD_PATTERN) {
                        Ok(value) => value,
                        Err(message) => return invalid_args(tool_call, &message),
                    };
                    match self.client.find_strings(&pattern).await {
                        Ok(matches) => {
                            let data = matches
                                .into_iter()
                                .map(|(address, text)| json!({"address": address, "text": text}))
                                .collect::<Vec<_>>();
                            ok_result(
                                tool_call,
                                "strings_ok",
                                "String search completed",
                                json!({"matches": data}),
                            )
                        }
                        Err(err) => ida_error_result(tool_call, err),
                    }
                }
                TOOL_LIST_FUNCTIONS | TOOL_GET_FUNCTION_LIST => {
                    let filter = match optional_string(&tool_call.input, FIELD_FILTER) {
                        Ok(value) => value,
                        Err(message) => return invalid_args(tool_call, &message),
                    };
                    let count = match optional_u32(&tool_call.input, FIELD_COUNT) {
                        Ok(value) => value,
                        Err(message) => return invalid_args(tool_call, &message),
                    };
                    match self.client.list_functions(filter.as_deref(), count).await {
                        Ok(functions) => ok_result(
                            tool_call,
                            "function_list_ok",
                            "Function list fetched",
                            json!({"functions": functions}),
                        ),
                        Err(err) => ida_error_result(tool_call, err),
                    }
                }
                _ => error_result(
                    tool_call,
                    "unknown_tool",
                    &format!("Unknown tool '{}'.", tool_call.name),
                    json!({"tool": tool_call.name}),
                    false,
                ),
            }
        })
    }

    fn execute_write_tool<'a>(&'a self, tool_call: &'a ToolCall) -> ExecuteFuture<'a> {
        Box::pin(async move {
            let mode = match mode_from_input(&tool_call.input, self.default_write_mode) {
                Ok(mode) => mode,
                Err(message) => return invalid_args(tool_call, &message),
            };
            let confidence = match optional_confidence(&tool_call.input) {
                Ok(value) => value,
                Err(message) => return invalid_args(tool_call, &message),
            };

            if mode == WriteMode::DryRun {
                return ok_result(
                    tool_call,
                    "dry_run",
                    "Dry-run only; no change applied",
                    write_action_data(tool_call, mode, confidence),
                );
            }

            if mode == WriteMode::Review {
                return ok_result(
                    tool_call,
                    "review_queued",
                    "Write queued for review",
                    write_action_data(tool_call, mode, confidence),
                );
            }

            match tool_call.name.as_str() {
                TOOL_RENAME_FUNCTION => {
                    let addr = match required_addr(&tool_call.input, FIELD_ADDR) {
                        Ok(value) => value,
                        Err(message) => return invalid_args(tool_call, &message),
                    };
                    let new_name = match required_string(&tool_call.input, FIELD_NEW_NAME) {
                        Ok(value) => value,
                        Err(message) => return invalid_args(tool_call, &message),
                    };
                    match self.client.rename_function(addr, &new_name).await {
                        Ok(()) => ok_result(
                            tool_call,
                            "rename_function_ok",
                            "Function renamed",
                            json!({"addr": addr, "new_name": new_name, "confidence": confidence}),
                        ),
                        Err(err) => ida_error_result(tool_call, err),
                    }
                }
                TOOL_RENAME_VARIABLE => {
                    let old_name = match required_string(&tool_call.input, FIELD_OLD_NAME) {
                        Ok(value) => value,
                        Err(message) => return invalid_args(tool_call, &message),
                    };
                    let new_name = match required_string(&tool_call.input, FIELD_NEW_NAME) {
                        Ok(value) => value,
                        Err(message) => return invalid_args(tool_call, &message),
                    };
                    error_result(
                        tool_call,
                        "unsupported_tool",
                        "Variable rename is not supported by the current IDA client",
                        json!({"old_name": old_name, "new_name": new_name, "confidence": confidence}),
                        false,
                    )
                }
                TOOL_SET_COMMENT => {
                    let addr = match required_addr(&tool_call.input, FIELD_ADDR) {
                        Ok(value) => value,
                        Err(message) => return invalid_args(tool_call, &message),
                    };
                    let comment = match required_string(&tool_call.input, FIELD_COMMENT) {
                        Ok(value) => value,
                        Err(message) => return invalid_args(tool_call, &message),
                    };
                    match self.client.set_comment(addr, &comment).await {
                        Ok(()) => ok_result(
                            tool_call,
                            "set_comment_ok",
                            "Comment set",
                            json!({"addr": addr, "comment": comment, "confidence": confidence}),
                        ),
                        Err(err) => ida_error_result(tool_call, err),
                    }
                }
                _ => error_result(
                    tool_call,
                    "unknown_tool",
                    &format!("Unknown tool '{}'.", tool_call.name),
                    json!({"tool": tool_call.name}),
                    false,
                ),
            }
        })
    }
}

type ExecuteFuture<'a> =
    std::pin::Pin<Box<dyn std::future::Future<Output = ToolResult> + Send + 'a>>;

#[async_trait]
impl ToolExecutor for IdaToolExecutor {
    async fn execute(&self, tool_call: &ToolCall) -> ToolResult {
        if is_blocked_tool(&tool_call.name) {
            return error_result(
                tool_call,
                "tool_blocked",
                &format!(
                    "Tool '{}' is blocked for Sprint 4 and cannot be called by the LLM.",
                    tool_call.name
                ),
                json!({"tool": tool_call.name}),
                false,
            );
        }

        if is_read_only_tool(&tool_call.name) {
            return self.execute_read_tool(tool_call).await;
        }

        if is_write_tool(&tool_call.name) {
            return self.execute_write_tool(tool_call).await;
        }

        error_result(
            tool_call,
            "unknown_tool",
            &format!(
                "Unknown tool '{}'. Allowed tools: {}.",
                tool_call.name,
                allowed_tool_names().join(", ")
            ),
            json!({"tool": tool_call.name}),
            false,
        )
    }
}

#[derive(Debug, Serialize)]
struct ToolEnvelope {
    status: &'static str,
    code: String,
    message: String,
    data: Value,
    retryable: bool,
}

fn ok_result(tool_call: &ToolCall, code: &str, message: &str, data: Value) -> ToolResult {
    build_tool_result(
        tool_call,
        ToolEnvelope {
            status: "ok",
            code: code.to_string(),
            message: message.to_string(),
            data,
            retryable: false,
        },
        false,
    )
}

fn error_result(
    tool_call: &ToolCall,
    code: &str,
    message: &str,
    data: Value,
    retryable: bool,
) -> ToolResult {
    build_tool_result(
        tool_call,
        ToolEnvelope {
            status: "error",
            code: code.to_string(),
            message: message.to_string(),
            data,
            retryable,
        },
        true,
    )
}

fn ida_error_result(tool_call: &ToolCall, error: IdaError) -> ToolResult {
    match error {
        IdaError::ConnectionError(detail) => error_result(
            tool_call,
            "ida_connection_error",
            "Unable to connect to IDA bridge",
            json!({"error": detail}),
            true,
        ),
        IdaError::Timeout => error_result(
            tool_call,
            "ida_timeout",
            "IDA bridge request timed out",
            json!({}),
            true,
        ),
        IdaError::HttpError(err) => {
            let retryable = err.is_timeout() || err.is_connect();
            error_result(
                tool_call,
                "ida_http_error",
                "IDA bridge HTTP error",
                json!({"error": err.to_string()}),
                retryable,
            )
        }
        IdaError::IdaResponseError(detail) => error_result(
            tool_call,
            "ida_execution_error",
            "IDA reported execution failure",
            json!({"error": detail}),
            false,
        ),
        IdaError::DeserializationError(detail) => error_result(
            tool_call,
            "ida_parse_error",
            "IDA response parsing failed",
            json!({"error": detail}),
            false,
        ),
    }
}

fn invalid_args(tool_call: &ToolCall, message: &str) -> ToolResult {
    error_result(
        tool_call,
        "invalid_arguments",
        message,
        json!({"input": tool_call.input}),
        false,
    )
}

fn build_tool_result(tool_call: &ToolCall, envelope: ToolEnvelope, is_error: bool) -> ToolResult {
    let output = serde_json::to_value(&envelope).unwrap_or_else(|_| {
        json!({
            "status": if is_error { "error" } else { "ok" },
            "code": "serialization_error",
            "message": "Tool envelope serialization failed",
            "data": {},
            "retryable": false,
        })
    });
    let content = match serde_json::to_string(&output) {
        Ok(serialized) => serialized,
        Err(_) => "{}".to_string(),
    };

    ToolResult {
        tool_use_id: tool_call.id.clone(),
        output,
        display_summary: envelope.message,
        content,
        is_error,
    }
}

fn mode_from_input(input: &Value, default_mode: WriteMode) -> Result<WriteMode, String> {
    let maybe_mode = optional_string(input, FIELD_MODE)?;
    match maybe_mode {
        Some(raw_mode) => parse_mode(&raw_mode),
        None => Ok(default_mode),
    }
}

fn parse_mode(mode: &str) -> Result<WriteMode, String> {
    match mode {
        "auto" => Ok(WriteMode::Auto),
        "review" => Ok(WriteMode::Review),
        "dry_run" => Ok(WriteMode::DryRun),
        _ => Err(format!(
            "Invalid mode '{mode}'. Expected one of: auto, review, dry_run"
        )),
    }
}

fn optional_confidence(input: &Value) -> Result<Option<f64>, String> {
    let Some(value) = input.get(FIELD_CONFIDENCE) else {
        return Ok(None);
    };

    if value.is_null() {
        return Ok(None);
    }

    let confidence = value.as_f64().ok_or_else(|| {
        format!("Field '{FIELD_CONFIDENCE}' must be a number in the range [0.0, 1.0]")
    })?;

    if (0.0..=1.0).contains(&confidence) {
        Ok(Some(confidence))
    } else {
        Err(format!(
            "Field '{FIELD_CONFIDENCE}' must be in the range [0.0, 1.0]"
        ))
    }
}

fn required_string(input: &Value, key: &str) -> Result<String, String> {
    let value = input
        .get(key)
        .ok_or_else(|| format!("Missing required field '{key}'"))?;
    value
        .as_str()
        .map(ToString::to_string)
        .ok_or_else(|| format!("Field '{key}' must be a string"))
}

fn optional_string(input: &Value, key: &str) -> Result<Option<String>, String> {
    let Some(value) = input.get(key) else {
        return Ok(None);
    };
    if value.is_null() {
        return Ok(None);
    }
    value
        .as_str()
        .map(|v| Some(v.to_string()))
        .ok_or_else(|| format!("Field '{key}' must be a string"))
}

fn optional_u32(input: &Value, key: &str) -> Result<Option<u32>, String> {
    let Some(value) = input.get(key) else {
        return Ok(None);
    };
    if value.is_null() {
        return Ok(None);
    }
    let raw = value
        .as_u64()
        .ok_or_else(|| format!("Field '{key}' must be an integer"))?;
    u32::try_from(raw)
        .map(Some)
        .map_err(|_| format!("Field '{key}' is out of range for u32"))
}

fn required_addr(input: &Value, key: &str) -> Result<u64, String> {
    let value = input
        .get(key)
        .ok_or_else(|| format!("Missing required field '{key}'"))?;
    parse_address(value).ok_or_else(|| {
        format!("Field '{key}' must be a u64 number or address string (for example, 0x401000)")
    })
}

fn parse_address(value: &Value) -> Option<u64> {
    if let Some(number) = value.as_u64() {
        return Some(number);
    }

    let text = value.as_str()?.trim();
    if let Some(hex) = text.strip_prefix("0x").or_else(|| text.strip_prefix("0X")) {
        return u64::from_str_radix(hex, 16).ok();
    }
    u64::from_str(text).ok()
}

fn is_read_only_tool(name: &str) -> bool {
    matches!(
        name,
        TOOL_DECOMPILE
            | TOOL_GET_FUNCTION_INFO
            | TOOL_GET_XREFS
            | TOOL_GET_STRINGS
            | TOOL_LIST_FUNCTIONS
            | TOOL_GET_FUNCTION_LIST
    )
}

fn is_write_tool(name: &str) -> bool {
    matches!(
        name,
        TOOL_RENAME_FUNCTION | TOOL_RENAME_VARIABLE | TOOL_SET_COMMENT
    )
}

fn is_blocked_tool(name: &str) -> bool {
    matches!(name, "py_eval" | "patch_bytes" | "patch_asm") || name.starts_with("patch_")
}

fn allowed_tool_names() -> Vec<&'static str> {
    vec![
        TOOL_DECOMPILE,
        TOOL_GET_FUNCTION_INFO,
        TOOL_GET_XREFS,
        TOOL_GET_STRINGS,
        TOOL_LIST_FUNCTIONS,
        TOOL_GET_FUNCTION_LIST,
        TOOL_RENAME_FUNCTION,
        TOOL_RENAME_VARIABLE,
        TOOL_SET_COMMENT,
    ]
}

fn write_action_data(tool_call: &ToolCall, mode: WriteMode, confidence: Option<f64>) -> Value {
    json!({
        "tool": tool_call.name,
        "mode": mode_name(mode),
        "confidence": confidence,
        "input": tool_call.input,
    })
}

fn mode_name(mode: WriteMode) -> &'static str {
    match mode {
        WriteMode::Auto => "auto",
        WriteMode::Review => "review",
        WriteMode::DryRun => "dry_run",
    }
}

fn object_schema(properties: Vec<(&str, Value)>, required: Vec<&str>) -> Value {
    let mut props = Map::new();
    for (key, value) in properties {
        props.insert(key.to_string(), value);
    }

    let mut schema = Map::new();
    schema.insert("type".to_string(), Value::String("object".to_string()));
    schema.insert("properties".to_string(), Value::Object(props));
    schema.insert("additionalProperties".to_string(), Value::Bool(false));

    if !required.is_empty() {
        schema.insert(
            "required".to_string(),
            Value::Array(
                required
                    .into_iter()
                    .map(|field| Value::String(field.to_string()))
                    .collect(),
            ),
        );
    }

    Value::Object(schema)
}

fn write_schema(required_fields: Vec<(&str, Value)>) -> Value {
    let mut fields = required_fields;
    fields.push((FIELD_MODE, mode_schema()));
    fields.push((FIELD_CONFIDENCE, confidence_schema()));
    let required_names = fields
        .iter()
        .filter_map(|(name, _)| {
            if *name == FIELD_MODE || *name == FIELD_CONFIDENCE {
                None
            } else {
                Some(*name)
            }
        })
        .collect::<Vec<_>>();
    object_schema(fields, required_names)
}

fn string_schema() -> Value {
    json!({"type": "string"})
}

fn integer_schema(minimum: u64) -> Value {
    json!({"type": "integer", "minimum": minimum})
}

fn address_schema() -> Value {
    json!({
        "oneOf": [
            {"type": "integer", "minimum": 0},
            {"type": "string", "pattern": "^(0x|0X)?[0-9a-fA-F]+$"}
        ]
    })
}

fn mode_schema() -> Value {
    json!({"type": "string", "enum": ["auto", "review", "dry_run"]})
}

fn confidence_schema() -> Value {
    json!({"type": "number", "minimum": 0.0, "maximum": 1.0})
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use serde_json::json;

    use super::*;
    use crate::mock::MockIdaTransport;

    fn tool_call(name: &str, input: Value) -> ToolCall {
        ToolCall {
            id: "toolu_1".to_string(),
            name: name.to_string(),
            input,
            arguments_raw: None,
            parse_error: None,
            provider: Some("mock".to_string()),
            stream_index: Some(0),
        }
    }

    fn executor_with_transport(
        responses: Vec<endeavour_ida::Result<Value>>,
    ) -> (IdaToolExecutor, Arc<MockIdaTransport>) {
        let transport = Arc::new(MockIdaTransport::new(responses));
        let client = Arc::new(IdaClient::with_transport(
            "127.0.0.1",
            13337,
            transport.clone(),
        ));
        (IdaToolExecutor::new(client), transport)
    }

    fn call_methods(transport: &MockIdaTransport) -> Vec<String> {
        transport
            .calls()
            .into_iter()
            .map(|(method, _)| method)
            .collect()
    }

    fn parse_envelope(result: &ToolResult) -> Value {
        result.output.clone()
    }

    #[tokio::test]
    async fn read_tool_decompile_dispatches() {
        let (executor, transport) = executor_with_transport(vec![Ok(json!({
            "addr": "0x401000",
            "code": "int main() { return 0; }"
        }))]);

        let result = executor
            .execute(&tool_call(TOOL_DECOMPILE, json!({"addr": "0x401000"})))
            .await;

        assert!(!result.is_error);
        let envelope = parse_envelope(&result);
        assert_eq!(envelope.get("status").and_then(Value::as_str), Some("ok"));
        assert_eq!(
            envelope.get("code").and_then(Value::as_str),
            Some("decompile_ok")
        );
        assert_eq!(call_methods(&transport), vec!["decompile"]);
    }

    #[tokio::test]
    async fn read_tool_list_functions_dispatches() {
        let (executor, transport) = executor_with_transport(vec![Ok(json!([
            {"items": [{"addr": "0x401000", "name": "sub_401000", "size": "0x20"}]}
        ]))]);

        let result = executor
            .execute(&tool_call(
                TOOL_GET_FUNCTION_LIST,
                json!({"filter": "sub_*", "count": 10}),
            ))
            .await;

        assert!(!result.is_error);
        let envelope = parse_envelope(&result);
        assert_eq!(
            envelope.get("code").and_then(Value::as_str),
            Some("function_list_ok")
        );
        assert_eq!(call_methods(&transport), vec!["list_funcs"]);
    }

    #[tokio::test]
    async fn read_tool_get_function_info_dispatches() {
        let (executor, transport) = executor_with_transport(vec![Ok(json!([
            {"fn": {"addr": "0x401000", "name": "sub_401000", "size": "0x20"}}
        ]))]);

        let result = executor
            .execute(&tool_call(
                TOOL_GET_FUNCTION_INFO,
                json!({"query": "sub_401000"}),
            ))
            .await;

        assert!(!result.is_error);
        let envelope = parse_envelope(&result);
        assert_eq!(
            envelope.get("code").and_then(Value::as_str),
            Some("function_info_ok")
        );
        assert_eq!(call_methods(&transport), vec!["lookup_funcs"]);
    }

    #[tokio::test]
    async fn read_tool_get_xrefs_dispatches() {
        let (executor, transport) = executor_with_transport(vec![Ok(json!([
            {
                "xrefs": [
                    {"from_addr": "0x401100", "xref_type": "code"}
                ]
            }
        ]))]);

        let result = executor
            .execute(&tool_call(TOOL_GET_XREFS, json!({"addr": "0x401000"})))
            .await;

        assert!(!result.is_error);
        let envelope = parse_envelope(&result);
        assert_eq!(
            envelope.get("code").and_then(Value::as_str),
            Some("xrefs_ok")
        );
        assert_eq!(call_methods(&transport), vec!["xrefs_to"]);
    }

    #[tokio::test]
    async fn read_tool_get_strings_dispatches() {
        let (executor, transport) = executor_with_transport(vec![Ok(json!({
            "matches": [
                {"addr": "0x401100", "string": "objc_msgSend"}
            ]
        }))]);

        let result = executor
            .execute(&tool_call(TOOL_GET_STRINGS, json!({"pattern": "objc_.*"})))
            .await;

        assert!(!result.is_error);
        let envelope = parse_envelope(&result);
        assert_eq!(
            envelope.get("code").and_then(Value::as_str),
            Some("strings_ok")
        );
        assert_eq!(call_methods(&transport), vec!["find_regex"]);
    }

    #[tokio::test]
    async fn write_tool_auto_mode_executes() {
        let (executor, transport) = executor_with_transport(vec![Ok(json!({
            "func": [{"ok": true, "error": null}]
        }))]);

        let result = executor
            .execute(&tool_call(
                TOOL_RENAME_FUNCTION,
                json!({"addr": "0x401000", "new_name": "main", "confidence": 0.91}),
            ))
            .await;

        assert!(!result.is_error);
        let envelope = parse_envelope(&result);
        assert_eq!(
            envelope.get("code").and_then(Value::as_str),
            Some("rename_function_ok")
        );
        assert_eq!(call_methods(&transport), vec!["rename"]);
    }

    #[tokio::test]
    async fn write_tool_dry_run_does_not_execute() {
        let (executor, transport) = executor_with_transport(Vec::new());

        let result = executor
            .execute(&tool_call(
                TOOL_SET_COMMENT,
                json!({"addr": "0x401000", "comment": "entry", "mode": "dry_run"}),
            ))
            .await;

        assert!(!result.is_error);
        let envelope = parse_envelope(&result);
        assert_eq!(
            envelope.get("code").and_then(Value::as_str),
            Some("dry_run")
        );
        assert!(call_methods(&transport).is_empty());
    }

    #[tokio::test]
    async fn write_tool_rename_variable_executes() {
        let (executor, transport) = executor_with_transport(vec![Ok(json!({
            "data": [{"ok": true, "error": null}]
        }))]);

        let result = executor
            .execute(&tool_call(
                TOOL_RENAME_VARIABLE,
                json!({"old_name": "g_buf", "new_name": "global_buffer", "mode": "auto"}),
            ))
            .await;

        assert!(!result.is_error);
        let envelope = parse_envelope(&result);
        assert_eq!(
            envelope.get("code").and_then(Value::as_str),
            Some("rename_variable_ok")
        );
        assert_eq!(call_methods(&transport), vec!["rename"]);
    }

    #[tokio::test]
    async fn write_tool_set_comment_executes() {
        let (executor, transport) = executor_with_transport(vec![Ok(json!([
            {"ok": true, "error": null}
        ]))]);

        let result = executor
            .execute(&tool_call(
                TOOL_SET_COMMENT,
                json!({"addr": "0x401000", "comment": "entry"}),
            ))
            .await;

        assert!(!result.is_error);
        let envelope = parse_envelope(&result);
        assert_eq!(
            envelope.get("code").and_then(Value::as_str),
            Some("set_comment_ok")
        );
        assert_eq!(call_methods(&transport), vec!["set_comments"]);
    }

    #[tokio::test]
    async fn blocked_tool_is_rejected() {
        let (executor, _) = executor_with_transport(Vec::new());

        let result = executor
            .execute(&tool_call("py_eval", json!({"code": "print(1)"})))
            .await;

        assert!(result.is_error);
        let envelope = parse_envelope(&result);
        assert_eq!(
            envelope.get("code").and_then(Value::as_str),
            Some("tool_blocked")
        );
    }

    #[tokio::test]
    async fn unknown_tool_is_rejected() {
        let (executor, _) = executor_with_transport(Vec::new());

        let result = executor
            .execute(&tool_call("totally_unknown", json!({})))
            .await;

        assert!(result.is_error);
        let envelope = parse_envelope(&result);
        assert_eq!(
            envelope.get("code").and_then(Value::as_str),
            Some("unknown_tool")
        );
    }

    #[tokio::test]
    async fn invalid_arguments_are_non_retryable() {
        let (executor, _) = executor_with_transport(Vec::new());

        let result = executor
            .execute(&tool_call(TOOL_GET_XREFS, json!({"addr": "not-a-number"})))
            .await;

        assert!(result.is_error);
        let envelope = parse_envelope(&result);
        assert_eq!(
            envelope.get("code").and_then(Value::as_str),
            Some("invalid_arguments")
        );
        assert_eq!(
            envelope.get("retryable").and_then(Value::as_bool),
            Some(false)
        );
    }

    #[tokio::test]
    async fn ida_connection_error_is_retryable() {
        let (executor, _) =
            executor_with_transport(vec![Err(IdaError::ConnectionError("refused".to_string()))]);

        let result = executor
            .execute(&tool_call(TOOL_DECOMPILE, json!({"addr": "0x401000"})))
            .await;

        assert!(result.is_error);
        let envelope = parse_envelope(&result);
        assert_eq!(
            envelope.get("code").and_then(Value::as_str),
            Some("ida_connection_error")
        );
        assert_eq!(
            envelope.get("retryable").and_then(Value::as_bool),
            Some(true)
        );
    }

    #[test]
    fn tool_definitions_include_all_allowed_tools() {
        let defs = IdaToolExecutor::tool_definitions();
        let mut names = defs.into_iter().map(|tool| tool.name).collect::<Vec<_>>();
        names.sort();

        assert_eq!(
            names,
            vec![
                "decompile",
                "get_function_info",
                "get_function_list",
                "get_strings",
                "get_xrefs",
                "list_functions",
                "rename_function",
                "rename_variable",
                "set_comment",
            ]
        );
    }
}
