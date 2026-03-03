use std::collections::VecDeque;

use async_trait::async_trait;
use futures_util::{StreamExt, stream};
use reqwest::{Client, StatusCode};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::error::{LlmError, Result};
use crate::provider::{LlmProvider, ProviderStream};
use crate::types::{CompletionRequest, CompletionResponse, Role, StreamChunk};

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
                    content: msg.content.clone(),
                }),
                Role::Assistant => messages.push(AnthropicMessage {
                    role: "assistant".to_string(),
                    content: msg.content.clone(),
                }),
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

        let content = body
            .content
            .iter()
            .filter_map(|block| {
                if block.kind == "text" {
                    block.text.as_deref()
                } else {
                    None
                }
            })
            .collect::<Vec<_>>()
            .join("");

        Ok(CompletionResponse {
            model: body.model,
            content,
            stop_reason: body.stop_reason,
            input_tokens: body.usage.as_ref().map(|u| u.input_tokens),
            output_tokens: body.usage.as_ref().map(|u| u.output_tokens),
        })
    }

    async fn stream(&self, request: CompletionRequest) -> Result<ProviderStream> {
        let payload = self.build_wire_request(&request, true);
        let response = self.post(&payload).await?;
        let bytes_stream = response.bytes_stream().map(|item| item.map(|bytes| bytes.to_vec()));

        let initial_state = SseState {
            input: Box::pin(bytes_stream),
            buffer: String::new(),
            pending: VecDeque::new(),
            done: false,
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
                                if let Some(chunk) = sse_event_to_chunk(&event) {
                                    if chunk.done {
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
                                if let Some(chunk) = sse_event_to_chunk(&event) {
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

type BoxByteStream =
    std::pin::Pin<Box<dyn futures_core::Stream<Item = std::result::Result<Vec<u8>, reqwest::Error>> + Send>>;

struct SseState {
    input: BoxByteStream,
    buffer: String,
    pending: VecDeque<StreamChunk>,
    done: bool,
}

fn parse_retry_after(header: Option<&reqwest::header::HeaderValue>) -> Option<u64> {
    header
        .and_then(|value| value.to_str().ok())
        .and_then(|text| text.parse::<u64>().ok())
}

pub(crate) fn map_anthropic_http_error(status: StatusCode, body: String, retry_after: Option<u64>) -> LlmError {
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

fn sse_event_to_chunk(event: &SseEvent) -> Option<StreamChunk> {
    if event.done_marker {
        return Some(StreamChunk {
            delta: String::new(),
            done: true,
            stop_reason: Some("done".to_string()),
        });
    }

    let data_type = event
        .data
        .get("type")
        .and_then(Value::as_str)
        .or(event.event.as_deref());

    match data_type {
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
                    None
                } else {
                    Some(StreamChunk {
                        delta: text,
                        done: false,
                        stop_reason: None,
                    })
                }
            } else {
                None
            }
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
            stop_reason.map(|reason| StreamChunk {
                delta: String::new(),
                done: true,
                stop_reason: Some(reason),
            })
        }
        Some("message_stop") => Some(StreamChunk {
            delta: String::new(),
            done: true,
            stop_reason: event
                .data
                .get("stop_reason")
                .and_then(Value::as_str)
                .map(ToString::to_string),
        }),
        _ => None,
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
}

#[derive(Debug, Serialize)]
pub(crate) struct AnthropicMessage {
    role: String,
    content: String,
}

#[derive(Debug, Deserialize)]
pub(crate) struct AnthropicResponse {
    model: String,
    content: Vec<AnthropicContentBlock>,
    stop_reason: Option<String>,
    usage: Option<AnthropicUsage>,
}

#[derive(Debug, Deserialize)]
pub(crate) struct AnthropicContentBlock {
    #[serde(rename = "type")]
    kind: String,
    text: Option<String>,
}

#[derive(Debug, Deserialize)]
pub(crate) struct AnthropicUsage {
    input_tokens: u32,
    output_tokens: u32,
}

#[cfg(test)]
mod tests {
    use reqwest::StatusCode;

    use super::{map_anthropic_http_error, parse_sse_event_block};
    use crate::error::LlmError;

    #[test]
    fn maps_http_status_codes_to_typed_errors() {
        let auth = map_anthropic_http_error(StatusCode::UNAUTHORIZED, "bad key".to_string(), None);
        assert!(matches!(auth, LlmError::AuthFailed));

        let limited = map_anthropic_http_error(StatusCode::TOO_MANY_REQUESTS, "slow down".to_string(), Some(9));
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
}
