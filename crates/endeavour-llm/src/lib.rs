mod anthropic;
mod error;
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
        .ok_or_else(|| LlmError::OpenAi("No provider configured".to_string()))?;

    match provider {
        "anthropic" => {
            let api_key = config.anthropic_api_key.clone().ok_or(LlmError::AuthFailed)?;
            Ok(Box::new(AnthropicProvider::new(api_key)))
        }
        "openai" => {
            let api_key = config.openai_api_key.clone().ok_or(LlmError::AuthFailed)?;
            Ok(Box::new(OpenAiProvider::new(api_key)))
        }
        other => Err(LlmError::OpenAi(format!("Unsupported provider: {other}"))),
    }
}
