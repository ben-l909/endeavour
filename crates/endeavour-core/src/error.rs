//! Error types used across the core domain model.

/// Core error variants used by Endeavour.
#[derive(thiserror::Error, Debug)]
pub enum Error {
    /// A Mach-O parse error with a descriptive message.
    #[error("Failed to parse Mach-O binary: {0}")]
    ParseError(String),
    /// A requested architecture is not supported.
    #[error("Unsupported architecture: {0}")]
    UnsupportedArch(String),
    /// A database operation failed.
    #[error("Database error: {0}")]
    DatabaseError(String),
    /// Communication with IDA MCP failed.
    #[error("IDA MCP error: {0}")]
    IdaError(String),
    /// A filesystem I/O operation failed.
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
}

/// Convenience result alias for core operations.
pub type Result<T> = std::result::Result<T, Error>;
