use std::pin::Pin;

use async_trait::async_trait;
use futures_core::Stream;

use crate::error::Result;
use crate::types::{CompletionRequest, CompletionResponse, StreamChunk};

/// A pinned, boxed stream of completion chunks from an LLM provider.
pub type ProviderStream = Pin<Box<dyn Stream<Item = Result<StreamChunk>> + Send + 'static>>;

#[async_trait]
/// Trait for LLM provider implementations.
///
/// Defines the interface for interacting with different LLM backends.
/// Implementations must support both single completion requests and streaming responses.
#[async_trait]
pub trait LlmProvider: Send + Sync {
    /// Sends a completion request and returns the full response.
    async fn complete(&self, request: CompletionRequest) -> Result<CompletionResponse>;
    /// Sends a completion request and returns a stream of response chunks.
    async fn stream(&self, request: CompletionRequest) -> Result<ProviderStream>;
}
