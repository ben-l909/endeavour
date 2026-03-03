//! LLM provider abstraction layer supporting multiple AI backends.
//!
//! This crate provides a unified interface for interacting with different LLM providers
//! (Anthropic, OpenAI) with support for both completion and streaming responses.

mod anthropic;
mod error;
/// Mock provider for testing LLM integrations.
pub mod mock;
mod openai;
mod provider;
mod types;

use endeavour_core::config::Config;

pub use anthropic::AnthropicProvider;
pub use error::{LlmError, Result};
pub use openai::OpenAiProvider;
pub use provider::{LlmProvider, ProviderStream};
pub use types::{CompletionRequest, CompletionResponse, Message, Role, StreamChunk};

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
        "anthropic" => {
            let api_key = config.anthropic_api_key.clone().ok_or(LlmError::AuthFailed)?;
            Ok(Box::new(AnthropicProvider::new(api_key)))
        }
        "openai" => {
            let api_key = config.openai_api_key.clone().ok_or(LlmError::AuthFailed)?;
            Ok(Box::new(OpenAiProvider::new(api_key)))
        }
        other => Err(LlmError::Configuration(format!("Unsupported provider: {other}"))),
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
