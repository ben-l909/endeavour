use thiserror::Error;

/// Result type for LLM operations.
pub type Result<T> = std::result::Result<T, LlmError>;

#[derive(Error, Debug)]
/// Errors that can occur during LLM operations.
pub enum LlmError {
    /// HTTP request error from the underlying HTTP client.
    #[error("HTTP error: {0}")]
    Http(#[from] reqwest::Error),
    /// JSON serialization/deserialization error.
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),
    /// Configuration error (missing or invalid provider settings).
    #[error("Configuration error: {0}")]
    Configuration(String),
    /// OpenAI-specific API error.
    #[error("OpenAI error: {0}")]
    OpenAi(String),
    /// Anthropic API error with HTTP status and response body.
    #[error("Anthropic API error ({status}): {body}")]
    AnthropicApi { /// HTTP status code.
        status: u16, /// Response body text.
        body: String,
    },
    /// Rate limit error with optional retry-after duration in seconds.
    #[error("Rate limited")]
    RateLimited { /// Seconds to wait before retrying (if provided).
        retry_after: Option<u64>,
    },
    /// Authentication failed (invalid or missing API key).
    #[error("Authentication failed")]
    AuthFailed,
    /// Context window size exceeded for the model.
    #[error("Context window exceeded")]
    ContextWindowExceeded,
    /// Communication channel closed unexpectedly.
    #[error("Channel closed")]
    ChannelClosed,
}
