use thiserror::Error;

/// Error variants returned by the IDA MCP client.
#[derive(Error, Debug)]
pub enum IdaError {
    /// Failed to establish a connection to the IDA MCP server.
    #[error("Connection failed: {0}")]
    ConnectionError(String),
    /// IDA returned an application-level error payload.
    #[error("IDA returned error: {0}")]
    IdaResponseError(String),
    /// Response payload shape did not match expected format.
    #[error("Invalid response format: {0}")]
    DeserializationError(String),
    /// Underlying HTTP error from reqwest.
    #[error("HTTP error: {0}")]
    HttpError(#[from] reqwest::Error),
    /// Request exceeded timeout.
    #[error("Request timeout")]
    Timeout,
}

/// Convenience result alias for the crate.
pub type Result<T> = std::result::Result<T, IdaError>;
