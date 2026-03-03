use thiserror::Error;

pub type Result<T> = std::result::Result<T, LlmError>;

#[derive(Error, Debug)]
pub enum LlmError {
    #[error("HTTP error: {0}")]
    Http(#[from] reqwest::Error),
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),
    #[error("Configuration error: {0}")]
    Configuration(String),
    #[error("OpenAI error: {0}")]
    OpenAi(String),
    #[error("Anthropic API error ({status}): {body}")]
    AnthropicApi { status: u16, body: String },
    #[error("Rate limited")]
    RateLimited { retry_after: Option<u64> },
    #[error("Authentication failed")]
    AuthFailed,
    #[error("Context window exceeded")]
    ContextWindowExceeded,
    #[error("Channel closed")]
    ChannelClosed,
}
