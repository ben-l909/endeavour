//! Async JSON-RPC client for IDA Pro MCP.

/// HTTP/transport-backed IDA MCP client.
pub mod client;
/// Error types for the IDA MCP client.
pub mod error;
/// Shared request/response data types.
pub mod types;

pub use client::{HttpTransport, IdaClient, Transport};
pub use error::{IdaError, Result};
pub use types::{
    BasicBlock, CommentRequest, DecompileResult, DisasmInstruction, FunctionInfo, RenameRequest, XRef,
};
