//! LLM provider abstraction layer supporting multiple AI backends.
//!
//! This crate provides a unified interface for interacting with different LLM providers
//! (Anthropic, OpenAI) with support for both completion and streaming responses.

mod agentic;
#[path = "anthropic_shim.rs"]
mod anthropic;
mod chunking;
mod context;
mod error;
mod ida_tool_executor;
/// Mock provider for testing LLM integrations.
pub mod mock;
mod oauth_refresh;
mod openai;
mod provider;
mod router;
mod types;

use endeavour_core::config::Config;

pub use agentic::{
    AgenticLoopConfig, AgenticLoopController, AgenticLoopCounters, AgenticLoopError,
    AgenticLoopEvent, AgenticLoopResult, AgenticLoopState, AgenticTerminationReason, AgenticTurn,
    ToolExecutor, Transcript, TranscriptContent, TranscriptEntry, TranscriptRecorder,
    TranscriptRole,
};
pub use anthropic::AnthropicProvider;
pub use chunking::{
    Chunk, FunctionChunker, DEFAULT_CHUNK_MAX_TOKENS, DEFAULT_CHUNK_OVERLAP_TOKENS,
};
pub use context::{
    estimate_text_tokens, BinaryMetadata, ContextBuilder, FunctionContext, FunctionXref,
    DEFAULT_MAX_CONTEXT_TOKENS, DEFAULT_SYSTEM_PROMPT,
};
pub use error::{LlmError, Result};
pub use ida_tool_executor::IdaToolExecutor;
pub use openai::OpenAiProvider;
pub use provider::{LlmProvider, ProviderStream};
pub use router::{
    BackendProvider, FallbackEvent, LlmRouter, ProviderSelection, RoutePlan, RouterCompletion,
    RouterNotice, TaskType,
};
pub use types::{
    CompletionRequest, CompletionResponse, Message, Role, StopReason, StreamChunk, StreamChunkKind,
    ToolCall, ToolDefinition, ToolResult, Usage,
};

/// Creates an LLM provider based on the provided configuration.
///
/// Selects the appropriate provider (Anthropic or OpenAI) based on the config's
/// `default_provider` setting or available API keys. Returns an error if no provider
/// is configured or if the specified provider is unsupported.
pub fn create_provider(config: &Config) -> Result<Box<dyn LlmProvider>> {
    let provider = config
        .default_provider
        .as_deref()
        .or_else(|| {
            if config.anthropic_api_key.is_some() {
                Some("anthropic")
            } else if config.openai_api_key.is_some() {
                Some("openai")
            } else {
                None
            }
        })
        .ok_or_else(|| LlmError::Configuration("No provider configured".to_string()))?;

    match provider {
        "anthropic" | "claude" => {
            let api_key = config
                .anthropic_api_key
                .clone()
                .ok_or(LlmError::AuthFailed)?;
            Ok(Box::new(AnthropicProvider::new(api_key)))
        }
        "openai" | "gpt" => {
            let api_key = config.openai_api_key.clone().ok_or(LlmError::AuthFailed)?;
            Ok(Box::new(OpenAiProvider::new(api_key)))
        }
        "auto" => {
            if config.anthropic_api_key.is_some() {
                let api_key = config
                    .anthropic_api_key
                    .clone()
                    .ok_or(LlmError::AuthFailed)?;
                Ok(Box::new(AnthropicProvider::new(api_key)))
            } else if config.openai_api_key.is_some() {
                let api_key = config.openai_api_key.clone().ok_or(LlmError::AuthFailed)?;
                Ok(Box::new(OpenAiProvider::new(api_key)))
            } else {
                Err(LlmError::Configuration(
                    "No provider configured".to_string(),
                ))
            }
        }
        "ollama" => Err(LlmError::Configuration(
            "Ollama support is not yet available; use auto, claude, or gpt".to_string(),
        )),
        other => Err(LlmError::Configuration(format!(
            "Unsupported provider: {other}"
        ))),
    }
}

#[cfg(test)]
mod tests {
    use endeavour_core::config::Config;

    use crate::{create_provider, LlmError};

    #[test]
    fn create_provider_returns_configuration_error_with_empty_config() {
        let config = Config::default();

        let result = create_provider(&config);

        assert!(matches!(
            result,
            Err(LlmError::Configuration(message)) if message == "No provider configured"
        ));
    }

    #[test]
    fn create_provider_returns_configuration_error_for_unsupported_provider() {
        let config = Config {
            default_provider: Some("invalid_provider".to_string()),
            ..Config::default()
        };

        let result = create_provider(&config);

        assert!(matches!(
            result,
            Err(LlmError::Configuration(message)) if message == "Unsupported provider: invalid_provider"
        ));
    }

    #[test]
    fn create_provider_returns_auth_failed_for_anthropic_without_api_key() {
        let config = Config {
            default_provider: Some("anthropic".to_string()),
            ..Config::default()
        };

        let result = create_provider(&config);

        assert!(matches!(result, Err(LlmError::AuthFailed)));
    }

    #[test]
    fn create_provider_returns_auth_failed_for_openai_without_api_key() {
        let config = Config {
            default_provider: Some("openai".to_string()),
            ..Config::default()
        };

        let result = create_provider(&config);

        assert!(matches!(result, Err(LlmError::AuthFailed)));
    }

    #[test]
    fn create_provider_succeeds_for_anthropic_with_api_key() {
        let config = Config {
            default_provider: Some("anthropic".to_string()),
            anthropic_api_key: Some("sk-ant-test-key".to_string()),
            ..Config::default()
        };

        let result = create_provider(&config);

        assert!(result.is_ok());
    }

    #[test]
    fn create_provider_succeeds_for_openai_with_api_key() {
        let config = Config {
            default_provider: Some("openai".to_string()),
            openai_api_key: Some("sk-openai-test-key".to_string()),
            ..Config::default()
        };

        let result = create_provider(&config);

        assert!(result.is_ok());
    }
}
