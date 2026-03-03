use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
/// Role of a message in a conversation.
pub enum Role {
    /// System message that sets context or instructions.
    System,
    /// User message (input from the user).
    User,
    /// Assistant message (response from the LLM).
    Assistant,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
/// A single message in a conversation.
pub struct Message {
    /// The role of the message sender.
    pub role: Role,
    /// The text content of the message.
    pub content: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
/// A request for LLM completion.
pub struct CompletionRequest {
    /// The model identifier to use for completion.
    pub model: String,
    /// The conversation messages to send to the model.
    pub messages: Vec<Message>,
    /// Maximum number of tokens to generate (optional).
    pub max_tokens: Option<u32>,
    /// Sampling temperature for response randomness (optional, 0.0-2.0).
    pub temperature: Option<f32>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
/// The response from an LLM completion request.
pub struct CompletionResponse {
    /// The model that generated the response.
    pub model: String,
    /// The generated text content.
    pub content: String,
    /// The reason the model stopped generating (e.g., "stop", "max_tokens").
    pub stop_reason: Option<String>,
    /// Number of tokens in the input (if provided by the model).
    pub input_tokens: Option<u32>,
    /// Number of tokens in the output (if provided by the model).
    pub output_tokens: Option<u32>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
/// A chunk of streamed response data from an LLM.
pub struct StreamChunk {
    /// The incremental text content in this chunk.
    pub delta: String,
    /// Whether this is the final chunk in the stream.
    pub done: bool,
    /// The reason the stream ended (if this is the final chunk).
    pub stop_reason: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::{CompletionRequest, CompletionResponse, Message, Role, StreamChunk};

    #[test]
    fn constructs_common_types() {
        let req = CompletionRequest {
            model: "claude-3-5-sonnet-20241022".to_string(),
            messages: vec![Message {
                role: Role::User,
                content: "hello".to_string(),
            }],
            max_tokens: Some(128),
            temperature: Some(0.1),
        };

        assert_eq!(req.model, "claude-3-5-sonnet-20241022");
        assert_eq!(req.messages.len(), 1);

        let resp = CompletionResponse {
            model: "gpt-4o-mini".to_string(),
            content: "hi".to_string(),
            stop_reason: Some("stop".to_string()),
            input_tokens: Some(3),
            output_tokens: Some(2),
        };
        assert_eq!(resp.content, "hi");

        let chunk = StreamChunk {
            delta: "h".to_string(),
            done: false,
            stop_reason: None,
        };
        assert!(!chunk.done);
    }
}
