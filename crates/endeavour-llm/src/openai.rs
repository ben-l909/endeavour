use async_openai::{
    Client,
    config::OpenAIConfig,
    error::OpenAIError,
    types::{
        ChatCompletionRequestAssistantMessageArgs, ChatCompletionRequestMessage,
        ChatCompletionRequestSystemMessageArgs, ChatCompletionRequestUserMessageArgs,
        CreateChatCompletionRequestArgs,
    },
};
use async_trait::async_trait;
use futures_util::StreamExt;

use crate::error::{LlmError, Result};
use crate::provider::{LlmProvider, ProviderStream};
use crate::types::{CompletionRequest, CompletionResponse, Message, Role, StreamChunk};

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

    fn map_message(message: &Message) -> Result<ChatCompletionRequestMessage> {
        let mapped = match message.role {
            Role::System => ChatCompletionRequestSystemMessageArgs::default()
                .content(message.content.clone())
                .build()
                .map(ChatCompletionRequestMessage::from),
            Role::User => ChatCompletionRequestUserMessageArgs::default()
                .content(message.content.clone())
                .build()
                .map(ChatCompletionRequestMessage::from),
            Role::Assistant => ChatCompletionRequestAssistantMessageArgs::default()
                .content(message.content.clone())
                .build()
                .map(ChatCompletionRequestMessage::from),
        };

        mapped.map_err(|err| LlmError::OpenAi(err.to_string()))
    }

    fn build_request(&self, request: &CompletionRequest) -> Result<async_openai::types::CreateChatCompletionRequest> {
        let messages = request
            .messages
            .iter()
            .map(Self::map_message)
            .collect::<Result<Vec<_>>>()?;

        let mut builder = CreateChatCompletionRequestArgs::default();
        builder.model(self.resolved_model(request)).messages(messages);

        if let Some(max_tokens) = request.max_tokens {
            builder.max_tokens(max_tokens);
        }
        if let Some(temperature) = request.temperature {
            builder.temperature(temperature);
        }

        builder.build().map_err(|err| LlmError::OpenAi(err.to_string()))
    }
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
            .and_then(|choice| choice.finish_reason.as_ref())
            .map(|reason| format!("{reason:?}"));

        Ok(CompletionResponse {
            model: response.model,
            content,
            stop_reason,
            input_tokens: response.usage.as_ref().map(|u| u.prompt_tokens),
            output_tokens: response.usage.as_ref().map(|u| u.completion_tokens),
        })
    }

    async fn stream(&self, request: CompletionRequest) -> Result<ProviderStream> {
        let wire_request = self.build_request(&request)?;
        let stream = self
            .client
            .chat()
            .create_stream(wire_request)
            .await
            .map_err(map_openai_error)?;

        let mapped = stream.map(|item| {
            let chunk = item.map_err(map_openai_error)?;
            let first = chunk.choices.first();
            let delta = first
                .and_then(|choice| choice.delta.content.as_deref())
                .unwrap_or_default()
                .to_string();
            let stop_reason = first
                .and_then(|choice| choice.finish_reason.as_ref())
                .map(|reason| format!("{reason:?}"));

            Ok(StreamChunk {
                delta,
                done: stop_reason.is_some(),
                stop_reason,
            })
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
    use super::map_openai_error;
    use crate::error::LlmError;

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
}
