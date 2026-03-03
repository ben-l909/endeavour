use thiserror::Error;

pub type Result<T> = std::result::Result<T, ParseError>;

#[derive(Debug, Error)]
pub enum ParseError {
    #[error("failed to deserialize microcode JSON: {0}")]
    InvalidJson(#[from] serde_json::Error),
}
