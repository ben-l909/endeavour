use std::collections::VecDeque;
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use tokio_stream::iter;

use crate::error::{LlmError, Result};
use crate::provider::{LlmProvider, ProviderStream};
use crate::types::{CompletionRequest, CompletionResponse, StreamChunk};

#[derive(Debug)]
pub enum MockResponse {
    Completion(Result<CompletionResponse>),
    Stream(Result<Vec<StreamChunk>>),
}

#[derive(Clone, Debug)]
pub struct MockProvider {
    responses: Arc<Mutex<VecDeque<MockResponse>>>,
}

impl MockProvider {
    pub fn new(responses: Vec<MockResponse>) -> Self {
        Self {
            responses: Arc::new(Mutex::new(responses.into_iter().collect())),
        }
    }

    pub fn enqueue(&self, response: MockResponse) -> Result<()> {
        let mut queue = self.responses.lock().map_err(|_| LlmError::ChannelClosed)?;
        queue.push_back(response);
        Ok(())
    }

    fn next_response(&self) -> Result<MockResponse> {
        let mut queue = self.responses.lock().map_err(|_| LlmError::ChannelClosed)?;
        queue.pop_front().ok_or(LlmError::ChannelClosed)
    }
}

#[async_trait]
impl LlmProvider for MockProvider {
    async fn complete(&self, _request: CompletionRequest) -> Result<CompletionResponse> {
        match self.next_response()? {
            MockResponse::Completion(result) => result,
            MockResponse::Stream(_) => Err(LlmError::ChannelClosed),
        }
    }

    async fn stream(&self, _request: CompletionRequest) -> Result<ProviderStream> {
        match self.next_response()? {
            MockResponse::Stream(Ok(chunks)) => Ok(Box::pin(iter(chunks.into_iter().map(Ok)))),
            MockResponse::Stream(Err(err)) => Err(err),
            MockResponse::Completion(_) => Err(LlmError::ChannelClosed),
        }
    }
}

#[cfg(test)]
mod tests {
    use futures_util::StreamExt;

    use super::{MockProvider, MockResponse};
    use crate::provider::LlmProvider;
    use crate::types::{CompletionRequest, CompletionResponse, Message, Role, StreamChunk};

    fn request() -> CompletionRequest {
        CompletionRequest {
            model: "test-model".to_string(),
            messages: vec![Message {
                role: Role::User,
                content: "hello".to_string(),
            }],
            max_tokens: Some(32),
            temperature: Some(0.0),
        }
    }

    #[tokio::test]
    async fn complete_returns_queued_response() {
        let provider = MockProvider::new(vec![MockResponse::Completion(Ok(CompletionResponse {
            model: "test-model".to_string(),
            content: "ok".to_string(),
            stop_reason: Some("stop".to_string()),
            input_tokens: Some(1),
            output_tokens: Some(1),
        }))]);

        let response = provider.complete(request()).await;
        assert!(response.is_ok());
        let response = response.unwrap_or_else(|_| unreachable!());
        assert_eq!(response.content, "ok");
    }

    #[tokio::test]
    async fn stream_returns_queued_chunks() {
        let provider = MockProvider::new(vec![MockResponse::Stream(Ok(vec![
            StreamChunk {
                delta: "he".to_string(),
                done: false,
                stop_reason: None,
            },
            StreamChunk {
                delta: "llo".to_string(),
                done: true,
                stop_reason: Some("stop".to_string()),
            },
        ]))]);

        let stream = provider.stream(request()).await;
        assert!(stream.is_ok());
        let mut stream = stream.unwrap_or_else(|_| unreachable!());
        let first = stream.next().await;
        assert!(first.is_some());
        let first = first.unwrap_or_else(|| unreachable!());
        assert!(first.is_ok());
        let first = first.unwrap_or_else(|_| unreachable!());
        assert_eq!(first.delta, "he");

        let second = stream.next().await;
        assert!(second.is_some());
        let second = second.unwrap_or_else(|| unreachable!());
        assert!(second.is_ok());
        let second = second.unwrap_or_else(|_| unreachable!());
        assert!(second.done);
    }

    #[tokio::test]
    async fn exhausted_queue_returns_channel_closed() {
        let provider = MockProvider::new(Vec::new());
        let response = provider.complete(request()).await;
        assert!(response.is_err());
    }
}
