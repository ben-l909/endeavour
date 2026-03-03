use thiserror::Error;

/// Error type for MBA operations.
#[derive(Debug, Error)]
pub enum Error {
    /// Placeholder error variant for unsupported operations.
    #[error("unsupported MBA operation: {0}")]
    Unsupported(&'static str),
}

/// Result alias used by MBA APIs.
pub type Result<T> = std::result::Result<T, Error>;
