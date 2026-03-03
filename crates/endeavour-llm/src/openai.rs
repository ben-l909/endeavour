use std::collections::{BTreeMap, VecDeque};

use async_openai::{
    config::OpenAIConfig,
    error::OpenAIError,
    types::{
        ChatCompletionMessageToolCall, ChatCompletionRequestAssistantMessageArgs,
        ChatCompletionRequestMessage, ChatCompletionRequestSystemMessageArgs,
        ChatCompletionRequestToolMessageArgs, ChatCompletionRequestUserMessageArgs,
        ChatCompletionStreamOptions, ChatCompletionTool, ChatCompletionToolType,
        CreateChatCompletionRequest, CreateChatCompletionRequestArgs, FinishReason,
        FunctionObjectArgs,
    },
    Client,
};
use async_trait::async_trait;
use futures_util::{stream, StreamExt};
use serde_json::Value;

use crate::error::{LlmError, Result};
use crate::provider::{LlmProvider, ProviderStream};
use crate::types::{
    CompletionRequest, CompletionResponse, Message, Role, StopReason, StreamChunk, StreamChunkKind,
    ToolCall, Usage,
};

const DEFAULT_OPENAI_MODEL: &str = "gpt-4o-mini";

#[derive(Clone, Debug)]
/// OpenAI API provider.
///
/// Implements the LLM provider interface for OpenAI's GPT models.
pub struct OpenAiProvider {
    client: Client<OpenAIConfig>,
    model_override: Option<String>,
}

impl OpenAiProvider {
    /// Creates a new OpenAI provider with the given API key.
    pub fn new(api_key: String) -> Self {
        let config = OpenAIConfig::new().with_api_key(api_key);
        Self {
            client: Client::with_config(config),
            model_override: None,
        }
    }

    /// Sets a model override for all requests from this provider.
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
            DEFAULT_OPENAI_MODEL
        }
    }

    fn map_message(message: &Message) -> Result<Vec<ChatCompletionRequestMessage>> {
        match message.role {
            Role::System => ChatCompletionRequestSystemMessageArgs::default()
                .content(message.content.clone())
                .build()
                .map(ChatCompletionRequestMessage::from)
                .map(|msg| vec![msg])
                .map_err(|err| LlmError::OpenAi(err.to_string())),
            Role::User => ChatCompletionRequestUserMessageArgs::default()
                .content(message.content.clone())
                .build()
                .map(ChatCompletionRequestMessage::from)
                .map(|msg| vec![msg])
                .map_err(|err| LlmError::OpenAi(err.to_string())),
            Role::Assistant => ChatCompletionRequestAssistantMessageArgs::default()
                .content(message.content.clone())
                .build()
                .map(ChatCompletionRequestMessage::from)
                .map(|msg| vec![msg])
                .map_err(|err| LlmError::OpenAi(err.to_string())),
            Role::ToolResult => {
                if message.tool_results.is_empty() {
                    return Err(LlmError::OpenAi(
                        "tool result message requires at least one tool_result".to_string(),
                    ));
                }

                let mut mapped = Vec::with_capacity(message.tool_results.len());
                for tool_result in &message.tool_results {
                    let tool_message = ChatCompletionRequestToolMessageArgs::default()
                        .tool_call_id(tool_result.tool_use_id.clone())
                        .content(tool_result.display_summary.clone())
                        .build()
                        .map_err(|err| LlmError::OpenAi(err.to_string()))?;
                    mapped.push(ChatCompletionRequestMessage::from(tool_message));
                }

                Ok(mapped)
            }
        }
    }

    fn map_tools(request: &CompletionRequest) -> Result<Option<Vec<ChatCompletionTool>>> {
        if request.tools.is_empty() {
            return Ok(None);
        }

        let mut tools = Vec::with_capacity(request.tools.len());
        for tool in &request.tools {
            let function = FunctionObjectArgs::default()
                .name(tool.name.clone())
                .description(tool.description.clone())
                .parameters(tool.parameters.clone())
                .build()
                .map_err(|err| LlmError::OpenAi(err.to_string()))?;

            tools.push(ChatCompletionTool {
                r#type: ChatCompletionToolType::Function,
                function,
            });
        }

        Ok(Some(tools))
    }

    fn build_request(&self, request: &CompletionRequest) -> Result<CreateChatCompletionRequest> {
        let messages = request.messages.iter().try_fold(
            Vec::new(),
            |mut acc, message| -> Result<Vec<ChatCompletionRequestMessage>> {
                acc.extend(Self::map_message(message)?);
                Ok(acc)
            },
        )?;

        let mut builder = CreateChatCompletionRequestArgs::default();
        builder
            .model(self.resolved_model(request))
            .messages(messages);

        if let Some(max_tokens) = request.max_tokens {
            builder.max_tokens(max_tokens);
        }
        if let Some(temperature) = request.temperature {
            builder.temperature(temperature);
        }
        if let Some(tools) = Self::map_tools(request)? {
            builder.tools(tools);
        }

        builder
            .build()
            .map_err(|err| LlmError::OpenAi(err.to_string()))
    }
}

#[derive(Debug, Default)]
struct InFlightToolCall {
    id: Option<String>,
    name: Option<String>,
    arguments: String,
}

struct StreamState {
    input: async_openai::types::ChatCompletionResponseStream,
    pending: VecDeque<Result<StreamChunk>>,
    in_flight_tool_calls: BTreeMap<u32, InFlightToolCall>,
    pending_finish_reason: Option<FinishReason>,
    usage: Usage,
    done_emitted: bool,
}

impl StreamState {
    fn new(input: async_openai::types::ChatCompletionResponseStream) -> Self {
        Self {
            input,
            pending: VecDeque::new(),
            in_flight_tool_calls: BTreeMap::new(),
            pending_finish_reason: None,
            usage: Usage {
                input_tokens: 0,
                output_tokens: 0,
            },
            done_emitted: false,
        }
    }
}

fn finish_reason_to_stop_reason(reason: FinishReason) -> StopReason {
    let raw = match reason {
        FinishReason::ToolCalls => "tool_calls",
        FinishReason::Length => "length",
        FinishReason::Stop => "stop",
        FinishReason::ContentFilter | FinishReason::FunctionCall => "stop_sequence",
    };
    map_openai_stop_reason(raw)
}

fn map_openai_stop_reason(reason: &str) -> StopReason {
    match reason {
        "stop" => StopReason::EndTurn,
        "length" => StopReason::MaxTokens,
        "tool_calls" => StopReason::ToolUse,
        _ => StopReason::StopSequence,
    }
}

fn parse_tool_input(arguments: &str) -> Result<Value> {
    let payload = if arguments.is_empty() {
        "{}"
    } else {
        arguments
    };
    serde_json::from_str(payload).map_err(|err| {
        LlmError::OpenAi(format!(
            "failed to parse OpenAI tool call arguments as JSON: {err}"
        ))
    })
}

fn parse_tool_calls(tool_calls: &[ChatCompletionMessageToolCall]) -> Vec<ToolCall> {
    let mut mapped = Vec::with_capacity(tool_calls.len());
    for call in tool_calls {
        let parsed = parse_tool_input(&call.function.arguments);
        let (input, parse_error) = match parsed {
            Ok(input) => (input, None),
            Err(err) => (Value::Null, Some(err.to_string())),
        };
        mapped.push(ToolCall {
            id: call.id.clone(),
            name: call.function.name.clone(),
            input,
            arguments_raw: Some(call.function.arguments.clone()),
            parse_error,
            provider: Some("openai".to_string()),
            stream_index: None,
        });
    }
    mapped
}

fn emit_done(state: &mut StreamState, reason: FinishReason) {
    let stop_reason = finish_reason_to_stop_reason(reason);
    state.pending.push_back(Ok(StreamChunk {
        kind: StreamChunkKind::Done {
            stop_reason,
            usage: state.usage.clone(),
        },
        stop_reason: Some(stop_reason),
    }));
    state.done_emitted = true;
}

fn process_stream_chunk(
    state: &mut StreamState,
    chunk: async_openai::types::CreateChatCompletionStreamResponse,
) -> Result<()> {
    let has_usage = chunk.usage.is_some();
    if let Some(usage) = chunk.usage {
        state.usage = Usage {
            input_tokens: usage.prompt_tokens,
            output_tokens: usage.completion_tokens,
        };
    }

    if let Some(choice) = chunk.choices.first() {
        if let Some(text) = choice.delta.content.clone().filter(|s| !s.is_empty()) {
            state.pending.push_back(Ok(StreamChunk {
                kind: StreamChunkKind::TextDelta(text.clone()),
                stop_reason: None,
            }));
        }

        if let Some(tool_calls) = &choice.delta.tool_calls {
            for tool_call_chunk in tool_calls {
                let entry = state
                    .in_flight_tool_calls
                    .entry(tool_call_chunk.index)
                    .or_default();

                if let Some(id) = tool_call_chunk.id.clone() {
                    if let Some(existing_id) = &entry.id {
                        if existing_id != &id {
                            return Err(LlmError::OpenAi(format!(
                                "conflicting tool call id for index {}: {existing_id} vs {id}",
                                tool_call_chunk.index
                            )));
                        }
                    } else {
                        entry.id = Some(id);
                    }
                }

                if let Some(function) = &tool_call_chunk.function {
                    if let Some(name) = function.name.clone() {
                        if let Some(existing_name) = &entry.name {
                            if existing_name != &name {
                                return Err(LlmError::OpenAi(format!(
                                    "conflicting tool call name for index {}: {existing_name} vs {name}",
                                    tool_call_chunk.index
                                )));
                            }
                        } else {
                            entry.name = Some(name);
                        }
                    }

                    if let Some(arguments_delta) = function.arguments.clone() {
                        entry.arguments.push_str(&arguments_delta);
                        let tool_use_id = entry
                            .id
                            .clone()
                            .unwrap_or_else(|| format!("tool_call_{}", tool_call_chunk.index));
                        state.pending.push_back(Ok(StreamChunk {
                            kind: StreamChunkKind::ToolCallDelta {
                                tool_use_id,
                                input_delta: arguments_delta.clone(),
                            },
                            stop_reason: None,
                        }));
                    }
                }
            }
        }

        if let Some(finish_reason) = choice.finish_reason {
            state.pending_finish_reason = Some(finish_reason);

            if finish_reason == FinishReason::ToolCalls {
                for in_flight in state.in_flight_tool_calls.values() {
                    let tool_use_id = in_flight.id.clone().ok_or_else(|| {
                        LlmError::OpenAi(
                            "OpenAI stream finished tool call without an id".to_string(),
                        )
                    })?;
                    let name = in_flight.name.clone().ok_or_else(|| {
                        LlmError::OpenAi(
                            "OpenAI stream finished tool call without a function name".to_string(),
                        )
                    })?;
                    let input = parse_tool_input(&in_flight.arguments)?;

                    state.pending.push_back(Ok(StreamChunk {
                        kind: StreamChunkKind::ToolCallComplete {
                            tool_use_id,
                            name,
                            input,
                        },
                        stop_reason: None,
                    }));
                }
            }
        }
    }

    if !state.done_emitted && has_usage {
        if let Some(finish_reason) = state.pending_finish_reason.take() {
            emit_done(state, finish_reason);
        }
    }

    Ok(())
}

#[async_trait]
impl LlmProvider for OpenAiProvider {
    async fn complete(&self, request: CompletionRequest) -> Result<CompletionResponse> {
        let wire_request = self.build_request(&request)?;
        let response = self
            .client
            .chat()
            .create(wire_request)
            .await
            .map_err(map_openai_error)?;

        let first_choice = response.choices.first();
        let content = first_choice
            .and_then(|choice| choice.message.content.as_deref())
            .unwrap_or_default()
            .to_string();
        let stop_reason = first_choice
            .and_then(|choice| choice.finish_reason)
            .map(finish_reason_to_stop_reason);
        let tool_calls = first_choice
            .and_then(|choice| choice.message.tool_calls.as_ref())
            .map_or_else(Vec::new, |calls| parse_tool_calls(calls));

        Ok(CompletionResponse {
            model: response.model,
            content,
            stop_reason,
            input_tokens: response.usage.as_ref().map(|u| u.prompt_tokens),
            output_tokens: response.usage.as_ref().map(|u| u.completion_tokens),
            tool_calls,
        })
    }

    async fn stream(&self, request: CompletionRequest) -> Result<ProviderStream> {
        let mut wire_request = self.build_request(&request)?;
        wire_request.stream_options = Some(ChatCompletionStreamOptions {
            include_usage: true,
        });
        let stream = self
            .client
            .chat()
            .create_stream(wire_request)
            .await
            .map_err(map_openai_error)?;

        let initial_state = StreamState::new(stream);
        let mapped = stream::unfold(initial_state, |mut state| async move {
            loop {
                if let Some(chunk) = state.pending.pop_front() {
                    return Some((chunk, state));
                }

                match state.input.next().await {
                    Some(Ok(chunk)) => {
                        if let Err(err) = process_stream_chunk(&mut state, chunk) {
                            state.pending.push_back(Err(err));
                        }
                    }
                    Some(Err(err)) => {
                        return Some((Err(map_openai_error(err)), state));
                    }
                    None => {
                        if !state.done_emitted {
                            if let Some(finish_reason) = state.pending_finish_reason.take() {
                                emit_done(&mut state, finish_reason);
                                continue;
                            }
                        }
                        return None;
                    }
                }
            }
        });

        Ok(Box::pin(mapped))
    }
}

pub(crate) fn map_openai_error(error: OpenAIError) -> LlmError {
    let text = error.to_string().to_lowercase();
    if text.contains("401") || text.contains("unauthorized") || text.contains("invalid api key") {
        LlmError::AuthFailed
    } else if text.contains("429") || text.contains("rate limit") {
        LlmError::RateLimited { retry_after: None }
    } else if text.contains("context") || text.contains("maximum context") {
        LlmError::ContextWindowExceeded
    } else {
        LlmError::OpenAi(error.to_string())
    }
}

#[cfg(test)]
mod tests {
    use async_openai::types::{
        ChatCompletionRequestMessage, ChatCompletionToolType, FinishReason, FunctionCall,
    };
    use serde_json::json;

    use super::map_openai_error;
    use crate::error::LlmError;
    use crate::types::{Message, Role, StopReason, ToolResult};

    #[test]
    fn maps_openai_error_by_message() {
        let auth = map_openai_error(async_openai::error::OpenAIError::InvalidArgument(
            "401 unauthorized".to_string(),
        ));
        assert!(matches!(auth, LlmError::AuthFailed));

        let rate = map_openai_error(async_openai::error::OpenAIError::InvalidArgument(
            "429 rate limit".to_string(),
        ));
        assert!(matches!(rate, LlmError::RateLimited { .. }));
    }

    #[test]
    fn finish_reason_maps_to_stop_reason() {
        assert_eq!(
            super::finish_reason_to_stop_reason(FinishReason::Stop),
            StopReason::EndTurn
        );
        assert_eq!(
            super::finish_reason_to_stop_reason(FinishReason::ToolCalls),
            StopReason::ToolUse
        );
    }

    #[test]
    fn parses_openai_tool_calls_into_canonical_type() {
        let parsed =
            super::parse_tool_calls(&[async_openai::types::ChatCompletionMessageToolCall {
                id: "call_123".to_string(),
                r#type: ChatCompletionToolType::Function,
                function: FunctionCall {
                    name: "lookup_func".to_string(),
                    arguments: r#"{"address":"0x401000"}"#.to_string(),
                },
            }]);

        assert_eq!(parsed.len(), 1);
        assert_eq!(parsed[0].id, "call_123");
        assert_eq!(parsed[0].name, "lookup_func");
        assert_eq!(parsed[0].input, json!({"address": "0x401000"}));
        assert!(parsed[0].parse_error.is_none());
    }

    #[test]
    fn maps_tool_result_messages_to_openai_tool_role() {
        let message = Message {
            role: Role::ToolResult,
            content: String::new(),
            tool_results: vec![ToolResult {
                tool_use_id: "call_123".to_string(),
                output: json!({"status": "ok"}),
                display_summary: "ok".to_string(),
                content: "ok".to_string(),
                is_error: false,
            }],
        };

        let mapped = super::OpenAiProvider::map_message(&message);
        assert!(mapped.is_ok());
        let mapped = mapped.unwrap_or_else(|_| unreachable!());
        assert_eq!(mapped.len(), 1);
        assert!(matches!(
            mapped.first(),
            Some(ChatCompletionRequestMessage::Tool(_))
        ));
    }
}
