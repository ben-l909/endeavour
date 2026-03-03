use crate::chunking::FunctionChunker;
use crate::types::{CompletionRequest, Message, Role, ToolDefinition};

const CHARS_PER_TOKEN_ESTIMATE: usize = 4;
pub const DEFAULT_MAX_CONTEXT_TOKENS: usize = 8_000;
pub const DEFAULT_SYSTEM_PROMPT: &str = "You are an expert reverse engineering assistant. Analyze binary context, reason carefully about code behavior, and use tools when needed to gather evidence before concluding.";

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct BinaryMetadata {
    pub name: String,
    pub architecture: Option<String>,
    pub compiler: Option<String>,
    pub file_format: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct FunctionXref {
    pub from_address: u64,
    pub xref_type: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct FunctionContext {
    pub function_name: Option<String>,
    pub address: Option<u64>,
    pub decompiled_code: String,
    pub xrefs: Vec<FunctionXref>,
    pub strings: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct ContextBuilder {
    model: String,
    max_tokens: Option<u32>,
    temperature: Option<f32>,
    max_context_tokens: usize,
    system_prompt: Option<String>,
    binary_metadata: Option<BinaryMetadata>,
    function_context: Option<FunctionContext>,
    tools: Vec<ToolDefinition>,
    history: Vec<Message>,
}

impl ContextBuilder {
    pub fn new(model: impl Into<String>) -> Self {
        Self {
            model: model.into(),
            max_tokens: None,
            temperature: None,
            max_context_tokens: DEFAULT_MAX_CONTEXT_TOKENS,
            system_prompt: None,
            binary_metadata: None,
            function_context: None,
            tools: Vec::new(),
            history: Vec::new(),
        }
    }

    pub fn with_max_tokens(mut self, max_tokens: u32) -> Self {
        self.max_tokens = Some(max_tokens);
        self
    }

    pub fn with_temperature(mut self, temperature: f32) -> Self {
        self.temperature = Some(temperature);
        self
    }

    pub fn with_max_context_tokens(mut self, max_context_tokens: usize) -> Self {
        self.max_context_tokens = max_context_tokens;
        self
    }

    pub fn with_system_prompt(mut self, system_prompt: impl Into<String>) -> Self {
        self.system_prompt = Some(system_prompt.into());
        self
    }

    pub fn with_binary_metadata(mut self, binary_metadata: BinaryMetadata) -> Self {
        self.binary_metadata = Some(binary_metadata);
        self
    }

    pub fn with_function_context(mut self, function_context: FunctionContext) -> Self {
        self.function_context = Some(function_context);
        self
    }

    pub fn with_tools(mut self, tools: Vec<ToolDefinition>) -> Self {
        self.tools = tools;
        self
    }

    pub fn with_history(mut self, history: Vec<Message>) -> Self {
        self.history = history;
        self
    }

    pub fn build(self) -> CompletionRequest {
        let system_prompt = self
            .system_prompt
            .unwrap_or_else(|| DEFAULT_SYSTEM_PROMPT.to_string());
        let system_message = Message {
            role: Role::System,
            content: system_prompt,
            tool_results: Vec::new(),
        };

        let binary_section = render_binary_metadata(self.binary_metadata.as_ref());
        let mut history = self.history;

        let fixed_tokens = estimate_message_tokens(&system_message)
            + estimate_tools_tokens(&self.tools)
            + estimate_text_tokens(&binary_section)
            + estimate_messages_tokens(&history);
        let available_for_function = self.max_context_tokens.saturating_sub(fixed_tokens);

        let function_section =
            render_function_context(self.function_context.as_ref(), available_for_function);
        let mut user_context = build_user_context_message(&binary_section, &function_section);

        let mut messages = vec![system_message.clone()];
        messages.extend(history.clone());
        if !user_context.is_empty() {
            messages.push(Message {
                role: Role::User,
                content: user_context.clone(),
                tool_results: Vec::new(),
            });
        }

        while estimate_request_tokens(&messages, &self.tools) > self.max_context_tokens
            && !history.is_empty()
        {
            history.remove(0);
            messages = vec![system_message.clone()];
            messages.extend(history.clone());
            if !user_context.is_empty() {
                messages.push(Message {
                    role: Role::User,
                    content: user_context.clone(),
                    tool_results: Vec::new(),
                });
            }
        }

        if estimate_request_tokens(&messages, &self.tools) > self.max_context_tokens
            && !function_section.is_empty()
        {
            let fixed_without_function = estimate_message_tokens(&system_message)
                + estimate_tools_tokens(&self.tools)
                + estimate_messages_tokens(&history)
                + estimate_text_tokens(&binary_section);
            let remaining_for_function = self
                .max_context_tokens
                .saturating_sub(fixed_without_function);
            let reduced_function =
                render_function_context(self.function_context.as_ref(), remaining_for_function);
            user_context = build_user_context_message(&binary_section, &reduced_function);

            messages = vec![system_message];
            messages.extend(history);
            if !user_context.is_empty() {
                messages.push(Message {
                    role: Role::User,
                    content: user_context,
                    tool_results: Vec::new(),
                });
            }
        }

        CompletionRequest {
            model: self.model,
            messages,
            max_tokens: self.max_tokens,
            temperature: self.temperature,
            tools: self.tools,
        }
    }
}

pub fn estimate_text_tokens(text: &str) -> usize {
    let char_count = text.chars().count();
    if char_count == 0 {
        return 0;
    }

    char_count.div_ceil(CHARS_PER_TOKEN_ESTIMATE)
}

fn estimate_message_tokens(message: &Message) -> usize {
    estimate_text_tokens(&message.content)
}

fn estimate_messages_tokens(messages: &[Message]) -> usize {
    messages.iter().map(estimate_message_tokens).sum()
}

fn estimate_tools_tokens(tools: &[ToolDefinition]) -> usize {
    tools
        .iter()
        .map(|tool| {
            estimate_text_tokens(&tool.name)
                + estimate_text_tokens(&tool.description)
                + estimate_text_tokens(&tool.parameters.to_string())
        })
        .sum()
}

fn estimate_request_tokens(messages: &[Message], tools: &[ToolDefinition]) -> usize {
    estimate_messages_tokens(messages) + estimate_tools_tokens(tools)
}

fn render_binary_metadata(metadata: Option<&BinaryMetadata>) -> String {
    let Some(metadata) = metadata else {
        return String::new();
    };

    let architecture = metadata.architecture.as_deref().unwrap_or("unknown");
    let compiler = metadata.compiler.as_deref().unwrap_or("unknown");
    let file_format = metadata.file_format.as_deref().unwrap_or("unknown");

    format!(
        "## Binary Metadata\n- Name: {}\n- Architecture: {}\n- Compiler: {}\n- Format: {}",
        metadata.name, architecture, compiler, file_format
    )
}

fn render_function_context(
    function_context: Option<&FunctionContext>,
    max_tokens: usize,
) -> String {
    let Some(function_context) = function_context else {
        return String::new();
    };

    let mut lines = Vec::new();
    lines.push("## Function Context".to_string());

    if let Some(name) = &function_context.function_name {
        lines.push(format!("- Function Name: {name}"));
    }
    if let Some(address) = function_context.address {
        lines.push(format!("- Address: 0x{address:08x}"));
    }

    lines.push("### Decompiled Code".to_string());
    lines.push("```c".to_string());

    let static_prefix = lines.join("\n");
    let static_suffix = "\n```\n### Cross-References\n### Strings";
    let overhead_tokens =
        estimate_text_tokens(&static_prefix) + estimate_text_tokens(static_suffix);
    let code_budget_tokens = max_tokens.saturating_sub(overhead_tokens);
    let code_budget_chars = code_budget_tokens.saturating_mul(CHARS_PER_TOKEN_ESTIMATE);

    let code = if code_budget_chars == 0 {
        "/* context omitted due to token budget */".to_string()
    } else {
        render_chunked_decompiled_code(&function_context.decompiled_code, code_budget_tokens)
    };

    lines.push(code);
    lines.push("```".to_string());

    lines.push("### Cross-References".to_string());
    if function_context.xrefs.is_empty() {
        lines.push("- none".to_string());
    } else {
        lines.extend(
            function_context
                .xrefs
                .iter()
                .map(|xref| match &xref.xref_type {
                    Some(xref_type) => {
                        format!("- 0x{:08x} ({xref_type})", xref.from_address)
                    }
                    None => format!("- 0x{:08x}", xref.from_address),
                }),
        );
    }

    lines.push("### Strings".to_string());
    if function_context.strings.is_empty() {
        lines.push("- none".to_string());
    } else {
        lines.extend(
            function_context
                .strings
                .iter()
                .map(|value| format!("- \"{value}\"")),
        );
    }

    lines.join("\n")
}

fn build_user_context_message(binary_section: &str, function_section: &str) -> String {
    let mut sections = Vec::new();
    if !binary_section.is_empty() {
        sections.push(binary_section.to_string());
    }
    if !function_section.is_empty() {
        sections.push(function_section.to_string());
    }

    sections.join("\n\n")
}

fn truncate_chars(value: &str, max_chars: usize) -> String {
    value.chars().take(max_chars).collect()
}

fn render_chunked_decompiled_code(decompiled_code: &str, code_budget_tokens: usize) -> String {
    if decompiled_code.is_empty() {
        return String::new();
    }

    let chunks = FunctionChunker::chunk(
        decompiled_code,
        code_budget_tokens.min(crate::chunking::DEFAULT_CHUNK_MAX_TOKENS),
        crate::chunking::DEFAULT_CHUNK_OVERLAP_TOKENS,
    );

    let mut remaining_tokens = code_budget_tokens;
    let mut selected_chunks = Vec::new();

    for chunk in chunks {
        let prefix = if chunk.total > 1 {
            format!(
                "/* chunk {}/{} lines {}-{} */\n",
                chunk.index + 1,
                chunk.total,
                chunk.line_start,
                chunk.line_end
            )
        } else {
            String::new()
        };

        let chunk_text = format!("{prefix}{}", chunk.text);
        let chunk_tokens = estimate_text_tokens(&chunk_text);

        if chunk_tokens > remaining_tokens {
            break;
        }

        selected_chunks.push(chunk_text);
        remaining_tokens = remaining_tokens.saturating_sub(chunk_tokens);
    }

    if selected_chunks.is_empty() {
        let mut fallback = truncate_chars(decompiled_code, code_budget_tokens.saturating_mul(4));
        if fallback.chars().count() < decompiled_code.chars().count() {
            fallback.push_str("\n/* ... truncated for context budget ... */");
        }
        return fallback;
    }

    selected_chunks.join("\n")
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::{
        BinaryMetadata, ContextBuilder, FunctionContext, FunctionXref, DEFAULT_MAX_CONTEXT_TOKENS,
    };
    use crate::{Message, Role, ToolDefinition};

    #[test]
    fn builds_hierarchical_request_with_tools_and_history() {
        let request = ContextBuilder::new("claude-sonnet")
            .with_system_prompt("system prompt")
            .with_binary_metadata(BinaryMetadata {
                name: "sample.bin".to_string(),
                architecture: Some("arm64".to_string()),
                compiler: Some("clang".to_string()),
                file_format: Some("mach-o".to_string()),
            })
            .with_function_context(FunctionContext {
                function_name: Some("sub_401000".to_string()),
                address: Some(0x401000),
                decompiled_code: "int x = 1;\nreturn x;".to_string(),
                xrefs: vec![FunctionXref {
                    from_address: 0x402000,
                    xref_type: Some("code".to_string()),
                }],
                strings: vec!["AES".to_string()],
            })
            .with_history(vec![Message {
                role: Role::Assistant,
                content: "previous assistant output".to_string(),
                tool_results: Vec::new(),
            }])
            .with_tools(vec![ToolDefinition {
                name: "decompile".to_string(),
                description: "decompile function".to_string(),
                parameters: json!({"type": "object"}),
            }])
            .build();

        assert_eq!(request.messages.len(), 3);
        assert_eq!(request.messages[0].role, Role::System);
        assert_eq!(request.messages[1].role, Role::Assistant);
        assert_eq!(request.messages[2].role, Role::User);
        assert!(request.messages[2].content.contains("## Binary Metadata"));
        assert!(request.messages[2].content.contains("## Function Context"));
        assert!(request.messages[2].content.contains("### Decompiled Code"));
        assert_eq!(request.tools.len(), 1);
    }

    #[test]
    fn truncates_function_context_when_budget_is_small() {
        let large_code = "A".repeat(2_400);
        let request = ContextBuilder::new("claude-sonnet")
            .with_system_prompt("system prompt")
            .with_max_context_tokens(200)
            .with_function_context(FunctionContext {
                function_name: Some("sub_401000".to_string()),
                address: Some(0x401000),
                decompiled_code: large_code,
                xrefs: Vec::new(),
                strings: Vec::new(),
            })
            .build();

        let user_message = request.messages.last();
        assert!(user_message.is_some());
        let user_message = user_message.unwrap_or_else(|| unreachable!());
        assert!(user_message
            .content
            .contains("truncated for context budget"));
    }

    #[test]
    fn renders_chunk_metadata_for_oversized_function_context() {
        let mut code = String::new();
        for i in 0..400 {
            code.push_str(&format!("    v{} = arg{} ^ 0x41414141;\n", i, i));
        }

        let request = ContextBuilder::new("claude-sonnet")
            .with_system_prompt("system prompt")
            .with_max_context_tokens(6_000)
            .with_function_context(FunctionContext {
                function_name: Some("sub_401000".to_string()),
                address: Some(0x401000),
                decompiled_code: code,
                xrefs: Vec::new(),
                strings: Vec::new(),
            })
            .build();

        let user_message = request.messages.last();
        assert!(user_message.is_some());
        let user_message = user_message.unwrap_or_else(|| unreachable!());

        assert!(user_message.content.contains("chunk 1/"));
        assert!(user_message.content.contains("lines"));
    }

    #[test]
    fn truncates_history_from_oldest_first() {
        let request = ContextBuilder::new("claude-sonnet")
            .with_system_prompt("stable prompt")
            .with_tools(vec![ToolDefinition {
                name: "decompile".to_string(),
                description: "decompile function".to_string(),
                parameters: json!({"type": "object", "properties": {"addr": {"type": "string"}}}),
            }])
            .with_max_context_tokens(120)
            .with_history(vec![
                Message {
                    role: Role::User,
                    content: "oldest message should be dropped first".repeat(10),
                    tool_results: Vec::new(),
                },
                Message {
                    role: Role::Assistant,
                    content: "newer message may remain".repeat(2),
                    tool_results: Vec::new(),
                },
            ])
            .build();

        assert!(request.messages.iter().all(|message| !message
            .content
            .contains("oldest message should be dropped first")));
        assert_eq!(request.messages[0].role, Role::System);
        assert_eq!(request.tools.len(), 1);
    }

    #[test]
    fn default_max_context_tokens_is_eight_thousand() {
        assert_eq!(DEFAULT_MAX_CONTEXT_TOKENS, 8_000);
    }
}
