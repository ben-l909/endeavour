use std::pin::Pin;

use async_trait::async_trait;
use futures_core::Stream;

use crate::error::Result;
use crate::types::{CompletionRequest, CompletionResponse, StreamChunk};

pub type ProviderStream = Pin<Box<dyn Stream<Item = Result<StreamChunk>> + Send + 'static>>;

#[async_trait]
pub trait LlmProvider: Send + Sync {
    async fn complete(&self, request: CompletionRequest) -> Result<CompletionResponse>;
    async fn stream(&self, request: CompletionRequest) -> Result<ProviderStream>;
}
