use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum Role {
    System,
    User,
    Assistant,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Message {
    pub role: Role,
    pub content: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct CompletionRequest {
    pub model: String,
    pub messages: Vec<Message>,
    pub max_tokens: Option<u32>,
    pub temperature: Option<f32>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CompletionResponse {
    pub model: String,
    pub content: String,
    pub stop_reason: Option<String>,
    pub input_tokens: Option<u32>,
    pub output_tokens: Option<u32>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct StreamChunk {
    pub delta: String,
    pub done: bool,
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
