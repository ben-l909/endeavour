use std::collections::{HashMap, VecDeque};

use async_trait::async_trait;
use futures_util::{stream, StreamExt};
use reqwest::{Client, StatusCode};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::error::{LlmError, Result};
use crate::provider::{LlmProvider, ProviderStream};
use crate::types::{
    CompletionRequest, CompletionResponse, Role, StopReason, StreamChunk, StreamChunkKind,
    ToolCall, Usage,
};

const ANTHROPIC_API_URL: &str = "https://api.anthropic.com/v1/messages";
const ANTHROPIC_VERSION: &str = "2023-06-01";
const DEFAULT_ANTHROPIC_MODEL: &str = "claude-3-5-sonnet-20241022";

#[derive(Clone, Debug)]
pub struct AnthropicProvider {
    client: Client,
    api_key: String,
    model_override: Option<String>,
}

impl AnthropicProvider {
    pub fn new(api_key: String) -> Self {
        Self {
            client: Client::new(),
            api_key,
            model_override: None,
        }
    }

    pub fn with_model(mut self, model: impl Into<String>) -> Self {
        self.model_override = Some(model.into());
        self
    }

    fn resolved_model<'a>(&'a self, request: &'a CompletionRequest) -> &'a str {
        if let Some(model) = self.model_override.as_deref() {
            model
        } else if !request.model.is_empty() {
            request.model.as_str()
        } else {
            DEFAULT_ANTHROPIC_MODEL
        }
    }

    fn build_wire_request(&self, request: &CompletionRequest, stream: bool) -> AnthropicRequest {
        let mut system_blocks = Vec::new();
        let mut messages = Vec::new();

        for msg in &request.messages {
            match msg.role {
                Role::System => system_blocks.push(msg.content.clone()),
                Role::User => messages.push(AnthropicMessage {
                    role: "user".to_string(),
                    content: AnthropicMessageContent::Text(msg.content.clone()),
                }),
                Role::Assistant => messages.push(AnthropicMessage {
                    role: "assistant".to_string(),
                    content: AnthropicMessageContent::Text(msg.content.clone()),
                }),
                Role::ToolResult => {
                    if msg.tool_results.is_empty() {
                        messages.push(AnthropicMessage {
                            role: "user".to_string(),
                            content: AnthropicMessageContent::Text(msg.content.clone()),
                        });
                    } else {
                        let blocks = msg
                            .tool_results
                            .iter()
                            .map(|result| AnthropicInputContentBlock::ToolResult {
                                tool_use_id: result.tool_use_id.clone(),
                                content: result.display_summary.clone(),
                                is_error: result.is_error,
                            })
                            .collect();
                        messages.push(AnthropicMessage {
                            role: "user".to_string(),
                            content: AnthropicMessageContent::Blocks(blocks),
                        });
                    }
                }
            }
        }

        AnthropicRequest {
            model: self.resolved_model(request).to_string(),
            messages,
            max_tokens: request.max_tokens.unwrap_or(1024),
            temperature: request.temperature,
            stream,
            system: if system_blocks.is_empty() {
                None
            } else {
                Some(system_blocks.join("\n"))
            },
            tools: if request.tools.is_empty() {
                None
            } else {
                Some(
                    request
                        .tools
                        .iter()
                        .map(|tool| AnthropicToolDefinition {
                            name: tool.name.clone(),
                            description: tool.description.clone(),
                            input_schema: tool.parameters.clone(),
                        })
                        .collect(),
                )
            },
        }
    }

    async fn post(&self, payload: &AnthropicRequest) -> Result<reqwest::Response> {
        let response = self
            .client
            .post(ANTHROPIC_API_URL)
            .header("x-api-key", &self.api_key)
            .header("anthropic-version", ANTHROPIC_VERSION)
            .json(payload)
            .send()
            .await?;

        if response.status().is_success() {
            return Ok(response);
        }

        let status = response.status();
        let retry_after = parse_retry_after(response.headers().get("retry-after"));
        let body = response.text().await.unwrap_or_default();
        Err(map_anthropic_http_error(status, body, retry_after))
    }
}

#[async_trait]
impl LlmProvider for AnthropicProvider {
    async fn complete(&self, request: CompletionRequest) -> Result<CompletionResponse> {
        let payload = self.build_wire_request(&request, false);
        let response = self.post(&payload).await?;
        let body: AnthropicResponse = response.json().await?;
        let (content, tool_calls) = parse_completion_content(&body.content);

        Ok(CompletionResponse {
            model: body.model,
            content,
            stop_reason: body.stop_reason.as_deref().map(map_stop_reason),
            input_tokens: body.usage.as_ref().map(|u| u.input_tokens),
            output_tokens: body.usage.as_ref().map(|u| u.output_tokens),
            tool_calls,
        })
    }

    async fn stream(&self, request: CompletionRequest) -> Result<ProviderStream> {
        let payload = self.build_wire_request(&request, true);
        let response = self.post(&payload).await?;
        let bytes_stream = response
            .bytes_stream()
            .map(|item| item.map(|bytes| bytes.to_vec()));

        let initial_state = SseState {
            input: Box::pin(bytes_stream),
            buffer: String::new(),
            pending: VecDeque::new(),
            done: false,
            stream_state: AnthropicStreamState::default(),
        };

        let parsed = stream::unfold(initial_state, |mut state| async move {
            loop {
                if let Some(chunk) = state.pending.pop_front() {
                    return Some((Ok(chunk), state));
                }

                if state.done {
                    return None;
                }

                match state.input.next().await {
                    Some(Ok(bytes)) => {
                        state.buffer.push_str(&String::from_utf8_lossy(&bytes));
                        let (blocks, remainder) = split_sse_blocks(&state.buffer);
                        state.buffer = remainder;
                        for block in blocks {
                            if let Some(event) = parse_sse_event_block(&block) {
                                for chunk in sse_event_to_chunks(&event, &mut state.stream_state) {
                                    if matches!(chunk.kind, StreamChunkKind::Done { .. }) {
                                        state.done = true;
                                    }
                                    state.pending.push_back(chunk);
                                }
                            }
                        }
                    }
                    Some(Err(err)) => {
                        state.done = true;
                        return Some((Err(LlmError::Http(err)), state));
                    }
                    None => {
                        if !state.buffer.trim().is_empty() {
                            if let Some(event) = parse_sse_event_block(state.buffer.trim()) {
                                for chunk in sse_event_to_chunks(&event, &mut state.stream_state) {
                                    state.pending.push_back(chunk);
                                }
                            }
                            state.buffer.clear();
                            continue;
                        }
                        return None;
                    }
                }
            }
        });

        Ok(Box::pin(parsed))
    }
}

type BoxByteStream = std::pin::Pin<
    Box<dyn futures_core::Stream<Item = std::result::Result<Vec<u8>, reqwest::Error>> + Send>,
>;

struct SseState {
    input: BoxByteStream,
    buffer: String,
    pending: VecDeque<StreamChunk>,
    done: bool,
    stream_state: AnthropicStreamState,
}

#[derive(Debug)]
struct AnthropicStreamState {
    active_tool_use_by_index: HashMap<u64, ActiveToolUse>,
    usage: Usage,
}

impl Default for AnthropicStreamState {
    fn default() -> Self {
        Self {
            active_tool_use_by_index: HashMap::new(),
            usage: Usage {
                input_tokens: 0,
                output_tokens: 0,
            },
        }
    }
}

#[derive(Debug)]
struct ActiveToolUse {
    id: String,
    name: String,
    input_json: String,
}

fn parse_retry_after(header: Option<&reqwest::header::HeaderValue>) -> Option<u64> {
    header
        .and_then(|value| value.to_str().ok())
        .and_then(|text| text.parse::<u64>().ok())
}

pub(crate) fn map_anthropic_http_error(
    status: StatusCode,
    body: String,
    retry_after: Option<u64>,
) -> LlmError {
    match status {
        StatusCode::UNAUTHORIZED => LlmError::AuthFailed,
        StatusCode::TOO_MANY_REQUESTS => LlmError::RateLimited { retry_after },
        StatusCode::BAD_REQUEST if body.contains("context") || body.contains("max_tokens") => {
            LlmError::ContextWindowExceeded
        }
        _ => LlmError::AnthropicApi {
            status: status.as_u16(),
            body,
        },
    }
}

fn split_sse_blocks(input: &str) -> (Vec<String>, String) {
    let mut blocks = Vec::new();
    let mut cursor = 0usize;
    while let Some(rel_idx) = input[cursor..].find("\n\n") {
        let end = cursor + rel_idx;
        blocks.push(input[cursor..end].to_string());
        cursor = end + 2;
    }
    (blocks, input[cursor..].to_string())
}

pub(crate) fn parse_sse_event_block(block: &str) -> Option<SseEvent> {
    let mut event = None;
    let mut data_lines = Vec::new();

    for line in block.lines() {
        if let Some(value) = line.strip_prefix("event:") {
            event = Some(value.trim().to_string());
        } else if let Some(value) = line.strip_prefix("data:") {
            let payload = value.trim();
            if payload == "[DONE]" {
                return Some(SseEvent {
                    event,
                    data: Value::Null,
                    done_marker: true,
                });
            }
            data_lines.push(payload.to_string());
        }
    }

    if data_lines.is_empty() {
        return None;
    }

    let data = serde_json::from_str::<Value>(&data_lines.join("\n")).ok()?;
    Some(SseEvent {
        event,
        data,
        done_marker: false,
    })
}

fn sse_event_to_chunks(event: &SseEvent, state: &mut AnthropicStreamState) -> Vec<StreamChunk> {
    if event.done_marker {
        return vec![StreamChunk {
            kind: StreamChunkKind::Done {
                stop_reason: StopReason::EndTurn,
                usage: state.usage.clone(),
            },
            stop_reason: Some(StopReason::EndTurn),
        }];
    }

    if let Some(usage) = extract_usage(&event.data) {
        state.usage = usage;
    } else if let Some(message_usage) = event.data.get("message").and_then(extract_usage) {
        state.usage = message_usage;
    }

    let data_type = event
        .data
        .get("type")
        .and_then(Value::as_str)
        .or(event.event.as_deref());

    match data_type {
        Some("content_block_start") => {
            let index = event.data.get("index").and_then(Value::as_u64);
            let block = event.data.get("content_block");
            let block_type = block
                .and_then(|value| value.get("type"))
                .and_then(Value::as_str);
            if block_type != Some("tool_use") {
                return Vec::new();
            }

            let Some(index) = index else {
                return Vec::new();
            };
            let Some(id) = block
                .and_then(|value| value.get("id"))
                .and_then(Value::as_str)
                .map(ToString::to_string)
            else {
                return Vec::new();
            };
            let Some(name) = block
                .and_then(|value| value.get("name"))
                .and_then(Value::as_str)
                .map(ToString::to_string)
            else {
                return Vec::new();
            };

            let input_json = block
                .and_then(|value| value.get("input"))
                .filter(|value| !value.is_null())
                .and_then(|value| {
                    if matches!(value, Value::Object(map) if map.is_empty()) {
                        Some(String::new())
                    } else {
                        serde_json::to_string(value).ok()
                    }
                })
                .unwrap_or_default();

            state.active_tool_use_by_index.insert(
                index,
                ActiveToolUse {
                    id: id.clone(),
                    name,
                    input_json,
                },
            );

            vec![StreamChunk {
                kind: StreamChunkKind::ToolCallDelta {
                    tool_use_id: id,
                    input_delta: String::new(),
                },
                stop_reason: None,
            }]
        }
        Some("content_block_delta") => {
            let delta_type = event
                .data
                .get("delta")
                .and_then(|d| d.get("type"))
                .and_then(Value::as_str);

            if delta_type == Some("text_delta") {
                let text = event
                    .data
                    .get("delta")
                    .and_then(|d| d.get("text"))
                    .and_then(Value::as_str)
                    .unwrap_or_default()
                    .to_string();
                if text.is_empty() {
                    Vec::new()
                } else {
                    vec![StreamChunk {
                        kind: StreamChunkKind::TextDelta(text.clone()),
                        stop_reason: None,
                    }]
                }
            } else if delta_type == Some("input_json_delta") {
                let index = event.data.get("index").and_then(Value::as_u64);
                let partial_json = event
                    .data
                    .get("delta")
                    .and_then(|d| d.get("partial_json"))
                    .and_then(Value::as_str)
                    .unwrap_or_default()
                    .to_string();

                if let Some(index) = index {
                    if let Some(active_tool_use) = state.active_tool_use_by_index.get_mut(&index) {
                        active_tool_use.input_json.push_str(&partial_json);
                        return vec![StreamChunk {
                            kind: StreamChunkKind::ToolCallDelta {
                                tool_use_id: active_tool_use.id.clone(),
                                input_delta: partial_json.clone(),
                            },
                            stop_reason: None,
                        }];
                    }
                }
                Vec::new()
            } else {
                Vec::new()
            }
        }
        Some("content_block_stop") => {
            let index = event.data.get("index").and_then(Value::as_u64);
            let Some(index) = index else {
                return Vec::new();
            };
            let Some(active_tool_use) = state.active_tool_use_by_index.remove(&index) else {
                return Vec::new();
            };

            let input = if active_tool_use.input_json.trim().is_empty() {
                Value::Object(serde_json::Map::new())
            } else {
                serde_json::from_str(&active_tool_use.input_json)
                    .unwrap_or_else(|_| Value::Object(serde_json::Map::new()))
            };

            vec![StreamChunk {
                kind: StreamChunkKind::ToolCallComplete {
                    tool_use_id: active_tool_use.id,
                    name: active_tool_use.name,
                    input,
                },
                stop_reason: None,
            }]
        }
        Some("message_delta") => {
            let stop_reason = event
                .data
                .get("delta")
                .and_then(|d| d.get("stop_reason"))
                .and_then(Value::as_str)
                .map(ToString::to_string)
                .or_else(|| {
                    event
                        .data
                        .get("stop_reason")
                        .and_then(Value::as_str)
                        .map(ToString::to_string)
                });
            stop_reason
                .map(|reason| {
                    vec![StreamChunk {
                        kind: StreamChunkKind::Done {
                            stop_reason: map_stop_reason(&reason),
                            usage: state.usage.clone(),
                        },
                        stop_reason: Some(map_stop_reason(&reason)),
                    }]
                })
                .unwrap_or_default()
        }
        Some("message_stop") => vec![StreamChunk {
            kind: StreamChunkKind::Done {
                stop_reason: StopReason::EndTurn,
                usage: state.usage.clone(),
            },
            stop_reason: event
                .data
                .get("stop_reason")
                .and_then(Value::as_str)
                .map(map_stop_reason),
        }],
        _ => Vec::new(),
    }
}

fn parse_completion_content(
    content_blocks: &[AnthropicResponseContentBlock],
) -> (String, Vec<ToolCall>) {
    let mut text = String::new();
    let mut tool_calls = Vec::new();

    for block in content_blocks {
        match block {
            AnthropicResponseContentBlock::Text { text: block_text } => text.push_str(block_text),
            AnthropicResponseContentBlock::ToolUse { id, name, input } => {
                tool_calls.push(ToolCall {
                    id: id.clone(),
                    name: name.clone(),
                    input: input.clone(),
                    arguments_raw: serde_json::to_string(input).ok(),
                    parse_error: None,
                    provider: Some("anthropic".to_string()),
                    stream_index: None,
                });
            }
            AnthropicResponseContentBlock::Other => {}
        }
    }

    (text, tool_calls)
}

fn extract_usage(value: &Value) -> Option<Usage> {
    let usage = value.get("usage")?;
    let input_tokens = usage
        .get("input_tokens")
        .and_then(Value::as_u64)
        .and_then(|value| u32::try_from(value).ok());
    let output_tokens = usage
        .get("output_tokens")
        .and_then(Value::as_u64)
        .and_then(|value| u32::try_from(value).ok());

    if input_tokens.is_none() && output_tokens.is_none() {
        return None;
    }

    Some(Usage {
        input_tokens: input_tokens.unwrap_or(0),
        output_tokens: output_tokens.unwrap_or(0),
    })
}

fn map_stop_reason(reason: &str) -> StopReason {
    match reason {
        "end_turn" => StopReason::EndTurn,
        "tool_use" => StopReason::ToolUse,
        "max_tokens" => StopReason::MaxTokens,
        "stop_sequence" => StopReason::StopSequence,
        _ => StopReason::StopSequence,
    }
}

#[derive(Debug)]
pub(crate) struct SseEvent {
    event: Option<String>,
    data: Value,
    done_marker: bool,
}

#[derive(Debug, Serialize)]
pub(crate) struct AnthropicRequest {
    model: String,
    messages: Vec<AnthropicMessage>,
    max_tokens: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    temperature: Option<f32>,
    stream: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    system: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    tools: Option<Vec<AnthropicToolDefinition>>,
}

#[derive(Debug, Serialize)]
pub(crate) struct AnthropicMessage {
    role: String,
    content: AnthropicMessageContent,
}

#[derive(Debug, Serialize)]
#[serde(untagged)]
pub(crate) enum AnthropicMessageContent {
    Text(String),
    Blocks(Vec<AnthropicInputContentBlock>),
}

#[derive(Debug, Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub(crate) enum AnthropicInputContentBlock {
    ToolResult {
        tool_use_id: String,
        content: String,
        #[serde(skip_serializing_if = "is_false")]
        is_error: bool,
    },
}

#[derive(Debug, Serialize)]
pub(crate) struct AnthropicToolDefinition {
    name: String,
    description: String,
    input_schema: Value,
}

fn is_false(value: &bool) -> bool {
    !*value
}

#[derive(Debug, Deserialize)]
pub(crate) struct AnthropicResponse {
    model: String,
    content: Vec<AnthropicResponseContentBlock>,
    stop_reason: Option<String>,
    usage: Option<AnthropicUsage>,
}

#[derive(Debug, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub(crate) enum AnthropicResponseContentBlock {
    Text {
        text: String,
    },
    ToolUse {
        id: String,
        name: String,
        #[serde(default)]
        input: Value,
    },
    #[serde(other)]
    Other,
}

#[derive(Debug, Deserialize)]
pub(crate) struct AnthropicUsage {
    input_tokens: u32,
    output_tokens: u32,
}

#[cfg(test)]
mod tests {
    use reqwest::StatusCode;
    use serde_json::json;

    use super::{
        map_anthropic_http_error, parse_completion_content, parse_sse_event_block,
        sse_event_to_chunks, AnthropicProvider, AnthropicResponseContentBlock,
        AnthropicStreamState,
    };
    use crate::error::LlmError;
    use crate::types::{
        CompletionRequest, Message, Role, StopReason, StreamChunkKind, ToolDefinition, ToolResult,
    };

    #[test]
    fn maps_http_status_codes_to_typed_errors() {
        let auth = map_anthropic_http_error(StatusCode::UNAUTHORIZED, "bad key".to_string(), None);
        assert!(matches!(auth, LlmError::AuthFailed));

        let limited = map_anthropic_http_error(
            StatusCode::TOO_MANY_REQUESTS,
            "slow down".to_string(),
            Some(9),
        );
        assert!(matches!(
            limited,
            LlmError::RateLimited {
                retry_after: Some(9)
            }
        ));

        let context = map_anthropic_http_error(
            StatusCode::BAD_REQUEST,
            "context length exceeded".to_string(),
            None,
        );
        assert!(matches!(context, LlmError::ContextWindowExceeded));
    }

    #[test]
    fn parses_sse_event_and_data_lines() {
        let block = "event: content_block_delta\ndata: {\"type\":\"content_block_delta\",\"delta\":{\"type\":\"text_delta\",\"text\":\"hello\"}}";
        let event = parse_sse_event_block(block);
        assert!(event.is_some());
        let event = event.unwrap_or_else(|| unreachable!());
        assert_eq!(event.event.as_deref(), Some("content_block_delta"));
        let text = event
            .data
            .get("delta")
            .and_then(|d| d.get("text"))
            .and_then(serde_json::Value::as_str);
        assert_eq!(text, Some("hello"));
    }

    #[test]
    fn build_wire_request_includes_tools_only_when_present() {
        let provider = AnthropicProvider::new("test-key".to_string());
        let req_without_tools = CompletionRequest {
            model: "model".to_string(),
            messages: vec![Message {
                role: Role::User,
                content: "ping".to_string(),
                tool_results: Vec::new(),
            }],
            max_tokens: Some(32),
            temperature: None,
            tools: Vec::new(),
        };
        let wire_without_tools = provider.build_wire_request(&req_without_tools, false);
        let as_json = serde_json::to_value(&wire_without_tools).unwrap_or_else(|_| unreachable!());
        assert!(as_json.get("tools").is_none());

        let req_with_tools = CompletionRequest {
            tools: vec![ToolDefinition {
                name: "lookup".to_string(),
                description: "Lookup symbol".to_string(),
                parameters: json!({"type":"object","properties":{"addr":{"type":"string"}}}),
            }],
            ..req_without_tools
        };
        let wire_with_tools = provider.build_wire_request(&req_with_tools, false);
        let with_tools_json =
            serde_json::to_value(&wire_with_tools).unwrap_or_else(|_| unreachable!());
        assert_eq!(
            with_tools_json
                .get("tools")
                .and_then(|tools| tools.get(0))
                .and_then(|tool| tool.get("input_schema")),
            Some(&json!({"type":"object","properties":{"addr":{"type":"string"}}}))
        );
    }

    #[test]
    fn build_wire_request_maps_tool_results_to_tool_result_blocks() {
        let provider = AnthropicProvider::new("test-key".to_string());
        let request = CompletionRequest {
            model: "model".to_string(),
            messages: vec![Message {
                role: Role::ToolResult,
                content: String::new(),
                tool_results: vec![ToolResult {
                    tool_use_id: "toolu_123".to_string(),
                    output: json!({"status": "ok"}),
                    display_summary: "done".to_string(),
                    content: "done".to_string(),
                    is_error: false,
                }],
            }],
            max_tokens: Some(16),
            temperature: None,
            tools: Vec::new(),
        };

        let wire = provider.build_wire_request(&request, false);
        let wire_json = serde_json::to_value(&wire).unwrap_or_else(|_| unreachable!());
        assert_eq!(
            wire_json
                .get("messages")
                .and_then(|messages| messages.get(0))
                .and_then(|message| message.get("role"))
                .and_then(serde_json::Value::as_str),
            Some("user")
        );
        assert_eq!(
            wire_json
                .get("messages")
                .and_then(|messages| messages.get(0))
                .and_then(|message| message.get("content"))
                .and_then(|content| content.get(0))
                .and_then(|block| block.get("type"))
                .and_then(serde_json::Value::as_str),
            Some("tool_result")
        );
        assert_eq!(
            wire_json
                .get("messages")
                .and_then(|messages| messages.get(0))
                .and_then(|message| message.get("content"))
                .and_then(|content| content.get(0))
                .and_then(|block| block.get("tool_use_id"))
                .and_then(serde_json::Value::as_str),
            Some("toolu_123")
        );
    }

    #[test]
    fn parse_completion_content_handles_text_and_tool_use() {
        let blocks = vec![
            AnthropicResponseContentBlock::Text {
                text: "hello ".to_string(),
            },
            AnthropicResponseContentBlock::ToolUse {
                id: "toolu_1".to_string(),
                name: "lookup".to_string(),
                input: json!({"addr":"0x401000"}),
            },
            AnthropicResponseContentBlock::Text {
                text: "world".to_string(),
            },
        ];

        let (text, tool_calls) = parse_completion_content(&blocks);
        assert_eq!(text, "hello world");
        assert_eq!(tool_calls.len(), 1);
        assert_eq!(tool_calls[0].id, "toolu_1");
        assert_eq!(tool_calls[0].name, "lookup");
        assert_eq!(tool_calls[0].input, json!({"addr":"0x401000"}));
    }

    #[test]
    fn sse_tool_use_events_emit_deltas_completion_and_done() {
        let mut state = AnthropicStreamState::default();

        let start = parse_sse_event_block(
            "event: content_block_start\ndata: {\"type\":\"content_block_start\",\"index\":1,\"content_block\":{\"type\":\"tool_use\",\"id\":\"toolu_abc\",\"name\":\"get_weather\",\"input\":{}}}",
        )
        .unwrap_or_else(|| unreachable!());
        let start_chunks = sse_event_to_chunks(&start, &mut state);
        assert_eq!(start_chunks.len(), 1);
        assert!(matches!(
            start_chunks[0].kind,
            StreamChunkKind::ToolCallDelta { .. }
        ));

        let delta = parse_sse_event_block(
            "event: content_block_delta\ndata: {\"type\":\"content_block_delta\",\"index\":1,\"delta\":{\"type\":\"input_json_delta\",\"partial_json\":\"{\\\"location\\\":\\\"Paris\\\"}\"}}",
        )
        .unwrap_or_else(|| unreachable!());
        let delta_chunks = sse_event_to_chunks(&delta, &mut state);
        assert_eq!(delta_chunks.len(), 1);
        assert!(matches!(
            delta_chunks[0].kind,
            StreamChunkKind::ToolCallDelta { .. }
        ));

        let stop = parse_sse_event_block(
            "event: content_block_stop\ndata: {\"type\":\"content_block_stop\",\"index\":1}",
        )
        .unwrap_or_else(|| unreachable!());
        let stop_chunks = sse_event_to_chunks(&stop, &mut state);
        assert_eq!(stop_chunks.len(), 1);
        match &stop_chunks[0].kind {
            StreamChunkKind::ToolCallComplete {
                tool_use_id,
                name,
                input,
            } => {
                assert_eq!(tool_use_id, "toolu_abc");
                assert_eq!(name, "get_weather");
                assert_eq!(input, &json!({"location":"Paris"}));
            }
            _ => unreachable!(),
        }

        let message_delta = parse_sse_event_block(
            "event: message_delta\ndata: {\"type\":\"message_delta\",\"delta\":{\"stop_reason\":\"tool_use\"},\"usage\":{\"input_tokens\":10,\"output_tokens\":4}}",
        )
        .unwrap_or_else(|| unreachable!());
        let done_chunks = sse_event_to_chunks(&message_delta, &mut state);
        assert_eq!(done_chunks.len(), 1);
        match &done_chunks[0].kind {
            StreamChunkKind::Done { stop_reason, usage } => {
                assert_eq!(stop_reason, &StopReason::ToolUse);
                assert_eq!(usage.input_tokens, 10);
                assert_eq!(usage.output_tokens, 4);
            }
            _ => unreachable!(),
        }
        assert!(matches!(done_chunks[0].kind, StreamChunkKind::Done { .. }));
    }
}
