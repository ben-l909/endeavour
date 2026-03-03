use thiserror::Error;

/// Result alias for endeavour-ir operations.
pub type Result<T> = std::result::Result<T, IrError>;

/// Errors produced by endeavour-ir.
#[derive(Debug, Error)]
pub enum IrError {
    /// JSON deserialization failed for an IR payload.
    #[error("failed to deserialize IR JSON: {0}")]
    InvalidJson(#[from] serde_json::Error),

    /// Backend frontend bridge is unavailable.
    #[error("IR backend unavailable; ensure IDA/Hex-Rays is running and connected, then retry")]
    BackendUnavailable,
}
