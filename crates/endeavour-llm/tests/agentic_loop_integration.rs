use std::collections::HashSet;
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use endeavour_ida::IdaClient;
use endeavour_llm::mock::{MockIdaTransport, MockProvider, MockResponse};
use endeavour_llm::{
    AgenticLoopConfig, AgenticLoopController, AgenticTerminationReason, CompletionRequest,
    CompletionResponse, ContextBuilder, IdaToolExecutor, LlmError, Message, Role, StopReason,
    ToolCall, ToolExecutor, ToolResult,
};
use serde_json::{json, Value};
use tokio::sync::watch;

#[derive(Debug)]
struct RecordingToolExecutor {
    fail_tools: HashSet<String>,
    executed_tools: Mutex<Vec<String>>,
    cancel_after_calls: Option<usize>,
    cancel_sender: Option<watch::Sender<bool>>,
}

impl RecordingToolExecutor {
    fn new(fail_tools: HashSet<String>) -> Self {
        Self {
            fail_tools,
            executed_tools: Mutex::new(Vec::new()),
            cancel_after_calls: None,
            cancel_sender: None,
        }
    }

    fn with_cancellation(mut self, cancel_after_calls: usize, sender: watch::Sender<bool>) -> Self {
        self.cancel_after_calls = Some(cancel_after_calls);
        self.cancel_sender = Some(sender);
        self
    }

    fn executed_count(&self) -> usize {
        self.executed_tools.lock().map_or(0, |tools| tools.len())
    }
}

#[async_trait]
impl ToolExecutor for RecordingToolExecutor {
    async fn execute(&self, tool_call: &ToolCall) -> ToolResult {
        let call_count = if let Ok(mut tools) = self.executed_tools.lock() {
            tools.push(tool_call.name.clone());
            tools.len()
        } else {
            0
        };

        if self
            .cancel_after_calls
            .is_some_and(|target| call_count == target)
        {
            if let Some(sender) = self.cancel_sender.as_ref() {
                let _ = sender.send(true);
            }
        }

        if self.fail_tools.contains(&tool_call.name) {
            return ToolResult {
                tool_use_id: tool_call.id.clone(),
                output: json!({"status": "error", "tool": tool_call.name}),
                display_summary: format!("Tool execution failed: {}", tool_call.name),
                content: format!("Tool execution failed: {}", tool_call.name),
                is_error: true,
            };
        }

        ToolResult {
            tool_use_id: tool_call.id.clone(),
            output: json!({"status": "ok"}),
            display_summary: format!("Tool execution succeeded: {}", tool_call.name),
            content: format!("Tool execution succeeded: {}", tool_call.name),
            is_error: false,
        }
    }
}

fn tool_call(id: &str, name: &str, input: Value) -> ToolCall {
    ToolCall {
        id: id.to_string(),
        name: name.to_string(),
        input,
        arguments_raw: None,
        parse_error: None,
        provider: Some("mock".to_string()),
        stream_index: Some(0),
    }
}

fn completion_with_tools(text: &str, tool_calls: Vec<ToolCall>) -> CompletionResponse {
    CompletionResponse {
        model: "mock-model".to_string(),
        content: text.to_string(),
        stop_reason: Some(if tool_calls.is_empty() {
            StopReason::EndTurn
        } else {
            StopReason::ToolUse
        }),
        input_tokens: Some(7),
        output_tokens: Some(5),
        tool_calls,
    }
}

fn completion_text(text: &str) -> CompletionResponse {
    completion_with_tools(text, Vec::new())
}

fn context_builder() -> ContextBuilder {
    ContextBuilder::new("mock-model")
        .with_history(vec![Message {
            role: Role::User,
            content: "Analyze function 0x401000".to_string(),
            tool_results: Vec::new(),
        }])
        .with_tools(IdaToolExecutor::tool_definitions())
}

fn tool_results_from_request(request: &CompletionRequest) -> Vec<ToolResult> {
    request
        .messages
        .iter()
        .rev()
        .find(|message| message.role == Role::ToolResult)
        .map(|message| message.tool_results.clone())
        .unwrap_or_default()
}

#[tokio::test]
async fn qa013_happy_path_integration_three_turns() {
    let transport = Arc::new(MockIdaTransport::new(vec![
        Ok(json!({"addr": "0x401000", "code": "int f() { return 1; }"})),
        Ok(json!([{"xrefs": [{"from_addr": "0x401100", "xref_type": "code"}]}])),
    ]));
    let client = Arc::new(IdaClient::with_transport(
        "127.0.0.1",
        13337,
        transport.clone(),
    ));
    let executor = IdaToolExecutor::new(client);

    let provider = Arc::new(MockProvider::new(vec![
        MockResponse::Completion(Ok(completion_with_tools(
            "Initial analysis: need decompile.",
            vec![tool_call("tc-1", "decompile", json!({"addr": "0x401000"}))],
        ))),
        MockResponse::Completion(Ok(completion_with_tools(
            "Decompile reviewed; check xrefs.",
            vec![tool_call("tc-2", "get_xrefs", json!({"addr": "0x401000"}))],
        ))),
        MockResponse::Completion(Ok(completion_text(
            "Final analysis: converged without more tools.",
        ))),
    ]));

    let mut controller = AgenticLoopController::new(AgenticLoopConfig::default());
    let result = controller
        .run(provider.as_ref(), context_builder(), &executor, None)
        .await;

    assert!(result.is_ok());
    let result = result.unwrap_or_else(|_| unreachable!());
    assert_eq!(result.termination_reason, AgenticTerminationReason::Success);
    assert_eq!(result.transcript.len(), 3);
    assert_eq!(result.counters.step_count, 2);
    assert_eq!(
        result.final_text,
        "Final analysis: converged without more tools."
    );
    assert_eq!(provider.call_count(), 3);
    assert_eq!(provider.remaining_responses(), 0);
    assert_eq!(transport.call_count(), 2);
    assert_eq!(transport.calls_by_method("decompile"), 1);
    assert_eq!(transport.calls_by_method("xrefs_to"), 1);
    assert_eq!(transport.remaining_responses(), 0);
}

#[tokio::test]
async fn qa013_multi_tool_call_single_turn_dispatches_all_results() {
    let transport = Arc::new(MockIdaTransport::new(vec![
        Ok(json!({"addr": "0x401000", "code": "int f() { return 1; }"})),
        Ok(json!([{"xrefs": [{"from_addr": "0x401100", "xref_type": "code"}]}])),
        Ok(json!({"matches": [{"addr": "0x402000", "string": "AES"}]})),
    ]));
    let client = Arc::new(IdaClient::with_transport(
        "127.0.0.1",
        13337,
        transport.clone(),
    ));
    let executor = IdaToolExecutor::new(client);

    let provider = Arc::new(MockProvider::new(vec![
        MockResponse::Completion(Ok(completion_with_tools(
            "Gather everything in one round.",
            vec![
                tool_call("multi-1", "decompile", json!({"addr": "0x401000"})),
                tool_call("multi-2", "get_xrefs", json!({"addr": "0x401000"})),
                tool_call("multi-3", "get_strings", json!({"pattern": "AES"})),
            ],
        ))),
        MockResponse::Completion(Ok(completion_text("All evidence collected."))),
    ]));

    let mut controller = AgenticLoopController::new(AgenticLoopConfig::default());
    let result = controller
        .run(provider.as_ref(), context_builder(), &executor, None)
        .await;

    assert!(result.is_ok());
    let result = result.unwrap_or_else(|_| unreachable!());
    assert_eq!(result.termination_reason, AgenticTerminationReason::Success);
    assert_eq!(result.counters.step_count, 1);
    assert_eq!(transport.call_count(), 3);
    assert_eq!(transport.calls_by_method("decompile"), 1);
    assert_eq!(transport.calls_by_method("xrefs_to"), 1);
    assert_eq!(transport.calls_by_method("find_regex"), 1);

    let calls = provider.calls();
    assert_eq!(calls.len(), 2);
    let fed_back = tool_results_from_request(&calls[1]);
    assert_eq!(fed_back.len(), 3);
    assert_eq!(fed_back[0].tool_use_id, "multi-1");
    assert_eq!(fed_back[1].tool_use_id, "multi-2");
    assert_eq!(fed_back[2].tool_use_id, "multi-3");
}

#[tokio::test]
async fn qa013_max_iterations_enters_force_final_and_terminates() {
    let transport = Arc::new(MockIdaTransport::new(vec![
        Ok(json!({"addr": "0x401000", "code": "round one"})),
        Ok(json!({"addr": "0x401000", "code": "round two"})),
    ]));
    let client = Arc::new(IdaClient::with_transport(
        "127.0.0.1",
        13337,
        transport.clone(),
    ));
    let executor = IdaToolExecutor::new(client);

    let provider = Arc::new(MockProvider::new(vec![
        MockResponse::Completion(Ok(completion_with_tools(
            "tool round 1",
            vec![tool_call("max-1", "decompile", json!({"addr": "0x401000"}))],
        ))),
        MockResponse::Completion(Ok(completion_with_tools(
            "tool round 2",
            vec![tool_call("max-2", "decompile", json!({"addr": "0x401000"}))],
        ))),
        MockResponse::Completion(Ok(completion_with_tools(
            "violate force-final",
            vec![tool_call("max-3", "decompile", json!({"addr": "0x401000"}))],
        ))),
        MockResponse::Completion(Ok(completion_text("forced final answer"))),
    ]));

    let mut controller = AgenticLoopController::new(AgenticLoopConfig {
        max_steps: 2,
        ..AgenticLoopConfig::default()
    });
    let result = controller
        .run(provider.as_ref(), context_builder(), &executor, None)
        .await;

    assert!(result.is_ok());
    let result = result.unwrap_or_else(|_| unreachable!());
    assert_eq!(
        result.termination_reason,
        AgenticTerminationReason::MaxRounds
    );
    assert_eq!(result.counters.step_count, 2);
    assert_eq!(result.counters.force_final_violations, 1);
    assert_eq!(provider.call_count(), 4);
    assert_eq!(transport.call_count(), 2);
}

#[tokio::test]
async fn qa013_error_recovery_rate_limited_first_call_then_retry_success() {
    let provider = Arc::new(MockProvider::new(vec![
        MockResponse::Completion(Err(LlmError::RateLimited {
            retry_after: Some(1),
        })),
        MockResponse::Completion(Ok(completion_text("Recovered after retry."))),
    ]));

    let executor = RecordingToolExecutor::new(HashSet::new());
    let mut controller = AgenticLoopController::new(AgenticLoopConfig::default());
    let result = controller
        .run(provider.as_ref(), context_builder(), &executor, None)
        .await;

    assert!(result.is_ok());
    let result = result.unwrap_or_else(|_| unreachable!());
    assert_eq!(result.termination_reason, AgenticTerminationReason::Success);
    assert_eq!(provider.call_count(), 2);
    assert_eq!(result.counters.step_count, 0);
    assert_eq!(executor.executed_count(), 0);
}

#[tokio::test]
async fn qa013_tool_execution_error_wrapped_and_loop_continues() {
    let provider = Arc::new(MockProvider::new(vec![
        MockResponse::Completion(Ok(completion_with_tools(
            "Run two tools.",
            vec![
                tool_call("err-1", "decompile", json!({"addr": "0x401000"})),
                tool_call("err-2", "get_xrefs", json!({"addr": "0x401000"})),
            ],
        ))),
        MockResponse::Completion(Ok(completion_text("Continued after tool error."))),
    ]));

    let fail_tools = HashSet::from(["get_xrefs".to_string()]);
    let executor = RecordingToolExecutor::new(fail_tools);
    let mut controller = AgenticLoopController::new(AgenticLoopConfig::default());
    let result = controller
        .run(provider.as_ref(), context_builder(), &executor, None)
        .await;

    assert!(result.is_ok());
    let result = result.unwrap_or_else(|_| unreachable!());
    assert_eq!(result.termination_reason, AgenticTerminationReason::Success);
    assert_eq!(result.counters.step_count, 1);

    let calls = provider.calls();
    assert_eq!(calls.len(), 2);
    let fed_back = tool_results_from_request(&calls[1]);
    assert_eq!(fed_back.len(), 2);
    let failed = fed_back.iter().find(|result| result.tool_use_id == "err-2");
    assert!(failed.is_some());
    let failed = failed.unwrap_or_else(|| unreachable!());
    assert!(failed.is_error);
    assert!(failed.display_summary.contains("Tool execution failed"));
}

#[tokio::test]
async fn qa013_blocked_tool_rejected_and_loop_continues() {
    let transport = Arc::new(MockIdaTransport::new(Vec::new()));
    let client = Arc::new(IdaClient::with_transport(
        "127.0.0.1",
        13337,
        transport.clone(),
    ));
    let executor = IdaToolExecutor::new(client);

    let provider = Arc::new(MockProvider::new(vec![
        MockResponse::Completion(Ok(completion_with_tools(
            "Try blocked tool.",
            vec![tool_call(
                "blocked-1",
                "py_eval",
                json!({"code": "print(1)"}),
            )],
        ))),
        MockResponse::Completion(Ok(completion_text("Handled blocked tool and continued."))),
    ]));

    let mut controller = AgenticLoopController::new(AgenticLoopConfig::default());
    let result = controller
        .run(provider.as_ref(), context_builder(), &executor, None)
        .await;

    assert!(result.is_ok());
    let result = result.unwrap_or_else(|_| unreachable!());
    assert_eq!(result.termination_reason, AgenticTerminationReason::Success);
    assert_eq!(transport.call_count(), 0);

    let calls = provider.calls();
    assert_eq!(calls.len(), 2);
    let fed_back = tool_results_from_request(&calls[1]);
    assert_eq!(fed_back.len(), 1);
    assert!(fed_back[0].is_error);

    let envelope = fed_back[0].output.clone();
    assert_eq!(
        envelope.get("code").and_then(Value::as_str),
        Some("tool_blocked")
    );
}

#[tokio::test]
async fn qa013_cancellation_after_two_iterations_returns_partial_result() {
    let provider = Arc::new(MockProvider::new(vec![
        MockResponse::Completion(Ok(completion_with_tools(
            "round 1",
            vec![tool_call(
                "cancel-1",
                "decompile",
                json!({"addr": "0x401000"}),
            )],
        ))),
        MockResponse::Completion(Ok(completion_with_tools(
            "round 2",
            vec![tool_call(
                "cancel-2",
                "decompile",
                json!({"addr": "0x401000"}),
            )],
        ))),
        MockResponse::Completion(Ok(completion_text("unreached"))),
    ]));

    let (cancel_tx, cancel_rx) = watch::channel(false);
    let executor = RecordingToolExecutor::new(HashSet::new()).with_cancellation(2, cancel_tx);

    let mut controller = AgenticLoopController::new(AgenticLoopConfig::default());
    let result = controller
        .run(
            provider.as_ref(),
            context_builder(),
            &executor,
            Some(&cancel_rx),
        )
        .await;

    assert!(result.is_ok());
    let result = result.unwrap_or_else(|_| unreachable!());
    assert_eq!(
        result.termination_reason,
        AgenticTerminationReason::Cancelled
    );
    assert_eq!(provider.call_count(), 2);
    assert_eq!(result.counters.step_count, 2);
    assert_eq!(result.transcript.len(), 2);
}

#[tokio::test]
async fn qa013_duplicate_detection_and_stagnation_on_identical_calls() {
    let provider = Arc::new(MockProvider::new(vec![
        MockResponse::Completion(Ok(completion_with_tools(
            "repeat 1",
            vec![tool_call("dup-1", "decompile", json!({"addr": "0x401000"}))],
        ))),
        MockResponse::Completion(Ok(completion_with_tools(
            "repeat 2",
            vec![tool_call("dup-2", "decompile", json!({"addr": "0x401000"}))],
        ))),
        MockResponse::Completion(Ok(completion_with_tools(
            "repeat 3",
            vec![tool_call("dup-3", "decompile", json!({"addr": "0x401000"}))],
        ))),
        MockResponse::Completion(Ok(completion_with_tools(
            "repeat 4",
            vec![tool_call("dup-4", "decompile", json!({"addr": "0x401000"}))],
        ))),
    ]));

    let executor = RecordingToolExecutor::new(HashSet::new());
    let mut controller = AgenticLoopController::new(AgenticLoopConfig::default());
    let result = controller
        .run(provider.as_ref(), context_builder(), &executor, None)
        .await;

    assert!(result.is_ok());
    let result = result.unwrap_or_else(|_| unreachable!());
    assert_eq!(
        result.termination_reason,
        AgenticTerminationReason::NoConvergence
    );
    assert!(result.counters.duplicate_tool_call_count >= 1);
    assert!(result.counters.stagnation_count >= 3);
    assert_eq!(provider.call_count(), 4);
}
