use std::env;
use std::sync::Arc;

use anyhow::{anyhow, Context, Result};
use async_trait::async_trait;
use endeavour_core::store::SessionStore;
use endeavour_ida::IdaClient;
use endeavour_llm::mock::{MockIdaError, MockIdaTransport, MockProvider, MockResponse};
use endeavour_llm::{
    AgenticLoopConfig, AgenticLoopController, AgenticTerminationReason, AnthropicProvider,
    CompletionRequest, CompletionResponse, ContextBuilder, IdaToolExecutor, LlmProvider, Message,
    OpenAiProvider, ProviderStream, Role, StopReason, ToolCall, ToolResult,
};
use serde_json::{json, Value};
use tempfile::TempDir;
use uuid::Uuid;

struct MockSmokeHarness {
    provider: Arc<MockProvider>,
    transport: Arc<MockIdaTransport>,
    executor: IdaToolExecutor,
    context: ContextBuilder,
    _tempdir: TempDir,
    _store: SessionStore,
    _session_id: Uuid,
}

fn setup_mock_smoke_test(
    user_input: &str,
    llm_responses: Vec<MockResponse>,
    transport: Arc<MockIdaTransport>,
    max_steps: u32,
) -> Result<(MockSmokeHarness, AgenticLoopController)> {
    let tempdir = TempDir::new().context("failed to create temp dir for smoke test")?;
    let store_path = tempdir.path().join("e2e-smoke.db");
    let store = SessionStore::open(&store_path).context("failed to open e2e smoke store")?;
    let session = store
        .create_session("smoke_test_binary.exe", Uuid::new_v4())
        .context("failed to create smoke test session")?;

    let provider = Arc::new(MockProvider::new(llm_responses));
    let client = Arc::new(IdaClient::with_transport(
        "127.0.0.1",
        13337,
        transport.clone(),
    ));
    let executor = IdaToolExecutor::new(client);
    let context = ContextBuilder::new("claude-sonnet-4-5")
        .with_history(vec![Message {
            role: Role::User,
            content: user_input.to_string(),
            tool_results: Vec::new(),
        }])
        .with_tools(IdaToolExecutor::tool_definitions());

    let controller = AgenticLoopController::new(AgenticLoopConfig {
        max_steps,
        ..AgenticLoopConfig::default()
    });

    Ok((
        MockSmokeHarness {
            provider,
            transport,
            executor,
            context,
            _tempdir: tempdir,
            _store: store,
            _session_id: session.id,
        },
        controller,
    ))
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

fn tool_call(id: &str, name: &str, input: Value) -> ToolCall {
    ToolCall {
        id: id.to_string(),
        name: name.to_string(),
        input,
        arguments_raw: None,
        parse_error: None,
        provider: Some("anthropic".to_string()),
        stream_index: None,
    }
}

fn completion_with_tools(
    text: &str,
    input_tokens: u32,
    output_tokens: u32,
    tool_calls: Vec<ToolCall>,
) -> CompletionResponse {
    CompletionResponse {
        model: "claude-sonnet-4-5".to_string(),
        content: text.to_string(),
        stop_reason: Some(if tool_calls.is_empty() {
            StopReason::EndTurn
        } else {
            StopReason::ToolUse
        }),
        input_tokens: Some(input_tokens),
        output_tokens: Some(output_tokens),
        tool_calls,
    }
}

fn completion_text(text: &str, input_tokens: u32, output_tokens: u32) -> CompletionResponse {
    completion_with_tools(text, input_tokens, output_tokens, Vec::new())
}

#[tokio::test]
async fn e2e_smoke_rename_single_function() {
    let transport = Arc::new(
        MockIdaTransport::builder()
            .fixture(
                "decompile",
                "0x100004a20",
                json!({
                    "addr": "0x100004a20",
                    "code": "int sub_100004a20(int a1, int a2) {\\n  int v3;\\n  v3 = a1 ^ a2;\\n  return v3 ^ 0xDEADBEEF;\\n}"
                }),
            )
            .fixture(
                "rename",
                "{\"batch\":{\"func\":[{\"addr\":\"0x100004a20\",\"name\":\"xor_obfuscate\"}]}}",
                json!({
                    "func": [{
                        "addr": "0x100004a20",
                        "name": "xor_obfuscate",
                        "ok": true,
                        "error": null
                    }]
                }),
            )
            .build(),
    );

    let llm_responses = vec![
        MockResponse::Completion(Ok(completion_with_tools(
            "I'll decompile this function to understand what it does.",
            312,
            28,
            vec![tool_call(
                "toolu_smoke_001",
                "decompile",
                json!({ "addr": "0x100004a20" }),
            )],
        ))),
        MockResponse::Completion(Ok(completion_with_tools(
            "The function XORs two inputs with a constant. I'll rename it to xor_obfuscate.",
            487,
            42,
            vec![tool_call(
                "toolu_smoke_002",
                "rename_function",
                json!({ "addr": "0x100004a20", "new_name": "xor_obfuscate" }),
            )],
        ))),
        MockResponse::Completion(Ok(completion_text(
            "Done. Renamed sub_100004a20 to xor_obfuscate.",
            521,
            48,
        ))),
    ];

    let (harness, mut controller) = setup_mock_smoke_test(
        "Rename the function at 0x100004a20 to something meaningful.",
        llm_responses,
        transport,
        10,
    )
    .unwrap_or_else(|err| panic!("failed to build rename smoke harness: {err}"));

    let result = controller
        .run(
            harness.provider.as_ref(),
            harness.context,
            &harness.executor,
            None,
        )
        .await
        .unwrap_or_else(|err| panic!("rename smoke loop failed: {err}"));

    let calls = harness.provider.calls();
    let first_user_message = calls[0]
        .messages
        .iter()
        .find(|message| message.role == Role::User)
        .unwrap_or_else(|| panic!("expected user message in first LLM request"));
    assert!(first_user_message
        .content
        .contains("0x100004a20 to something meaningful"));
    assert_eq!(harness.transport.calls_by_method("decompile"), 1);

    let turn_two_tool_results = tool_results_from_request(&calls[1]);
    assert_eq!(turn_two_tool_results.len(), 1);
    assert_eq!(turn_two_tool_results[0].tool_use_id, "toolu_smoke_001");
    assert!(turn_two_tool_results[0].content.contains("DEADBEEF"));

    assert_eq!(harness.transport.calls_by_method("rename"), 1);
    assert!(result.final_text.contains("xor_obfuscate"));
    assert_eq!(result.termination_reason, AgenticTerminationReason::Success);
    assert_eq!(harness.provider.call_count(), 3);
    assert_eq!(harness.transport.call_count(), 2);
    assert_eq!(harness.provider.remaining_responses(), 0);
    assert_eq!(harness.transport.remaining_responses(), 0);
    assert_eq!(result.counters.step_count, 2);
    assert_eq!(result.usage_totals.input_tokens, 1320);
    assert_eq!(result.usage_totals.output_tokens, 118);
}

#[tokio::test]
async fn e2e_smoke_decompile_explain_read_only() {
    let transport = Arc::new(
        MockIdaTransport::builder()
            .fixture(
                "decompile",
                "0x100003b80",
                json!({
                    "addr": "0x100003b80",
                    "code": "void sub_100003b80(char *dst, const char *src, size_t n) {\\n  size_t i;\\n  for (i = 0; i < n; i++) {\\n    dst[i] = src[i] ^ 0x42;\\n  }\\n}"
                }),
            )
            .build(),
    );

    let llm_responses = vec![
        MockResponse::Completion(Ok(completion_with_tools(
            "Let me decompile this function first.",
            298,
            18,
            vec![tool_call(
                "toolu_explain_001",
                "decompile",
                json!({ "addr": "0x100003b80" }),
            )],
        ))),
        MockResponse::Completion(Ok(completion_text(
            "This function is a simple XOR cipher that copies and XORs each byte with 0x42.",
            412,
            72,
        ))),
    ];

    let (harness, mut controller) = setup_mock_smoke_test(
        "Explain what the function at 0x100003b80 does.",
        llm_responses,
        transport,
        10,
    )
    .unwrap_or_else(|err| panic!("failed to build explain smoke harness: {err}"));

    let result = controller
        .run(
            harness.provider.as_ref(),
            harness.context,
            &harness.executor,
            None,
        )
        .await
        .unwrap_or_else(|err| panic!("explain smoke loop failed: {err}"));

    let calls = harness.provider.calls();
    let first_user_message = calls[0]
        .messages
        .iter()
        .find(|message| message.role == Role::User)
        .unwrap_or_else(|| panic!("expected user message in first LLM request"));
    assert!(first_user_message
        .content
        .contains("function at 0x100003b80"));
    assert_eq!(harness.transport.calls_by_method("decompile"), 1);

    let turn_two_tool_results = tool_results_from_request(&calls[1]);
    assert_eq!(turn_two_tool_results.len(), 1);
    assert_eq!(turn_two_tool_results[0].tool_use_id, "toolu_explain_001");
    assert!(turn_two_tool_results[0].content.contains("0x42"));

    assert_eq!(harness.transport.calls_by_method("rename"), 0);
    assert_eq!(harness.transport.calls_by_method("set_comments"), 0);
    assert!(result.final_text.contains("XOR cipher"));
    assert_eq!(result.termination_reason, AgenticTerminationReason::Success);
    assert_eq!(harness.provider.call_count(), 2);
    assert_eq!(harness.transport.call_count(), 1);
    assert_eq!(result.counters.step_count, 1);
}

#[tokio::test]
async fn e2e_smoke_ida_disconnect_mid_pipeline() {
    let transport = Arc::new(
        MockIdaTransport::builder()
            .fixture(
                "decompile",
                "0x100004a20",
                json!({
                    "addr": "0x100004a20",
                    "code": "int sub_100004a20(int a1, int a2) { return a1 ^ a2; }"
                }),
            )
            .error("xrefs_to", "0x100004a20", MockIdaError::Connection)
            .build(),
    );

    let llm_responses = vec![
        MockResponse::Completion(Ok(completion_with_tools(
            "I'll decompile and inspect xrefs in parallel.",
            310,
            22,
            vec![
                tool_call("toolu_disc_001", "decompile", json!({ "addr": "0x100004a20" })),
                tool_call("toolu_disc_002", "get_xrefs", json!({ "addr": "0x100004a20" })),
            ],
        ))),
        MockResponse::Completion(Ok(completion_text(
            "IDA disconnected before xrefs completed, but the function appears to XOR two integers.",
            445,
            48,
        ))),
    ];

    let (harness, mut controller) = setup_mock_smoke_test(
        "Analyze function 0x100004a20 and explain its behavior.",
        llm_responses,
        transport,
        10,
    )
    .unwrap_or_else(|err| panic!("failed to build disconnect smoke harness: {err}"));

    let result = controller
        .run(
            harness.provider.as_ref(),
            harness.context,
            &harness.executor,
            None,
        )
        .await
        .unwrap_or_else(|err| panic!("disconnect smoke loop failed: {err}"));

    assert_eq!(harness.transport.call_count(), 2);

    let calls = harness.provider.calls();
    let turn_two_tool_results = tool_results_from_request(&calls[1]);
    assert_eq!(turn_two_tool_results.len(), 2);
    assert_eq!(turn_two_tool_results[0].tool_use_id, "toolu_disc_001");
    assert_eq!(turn_two_tool_results[1].tool_use_id, "toolu_disc_002");
    assert!(!turn_two_tool_results[0].is_error);
    assert!(turn_two_tool_results[1].is_error);
    assert!(turn_two_tool_results[1]
        .content
        .contains("mock connection failed"));

    assert_eq!(result.termination_reason, AgenticTerminationReason::Success);
    assert_eq!(harness.provider.call_count(), 2);
}

enum LiveProvider {
    Anthropic(AnthropicProvider),
    OpenAi(OpenAiProvider),
}

#[async_trait]
impl LlmProvider for LiveProvider {
    async fn complete(
        &self,
        request: CompletionRequest,
    ) -> endeavour_llm::Result<CompletionResponse> {
        match self {
            Self::Anthropic(provider) => provider.complete(request).await,
            Self::OpenAi(provider) => provider.complete(request).await,
        }
    }

    async fn stream(&self, request: CompletionRequest) -> endeavour_llm::Result<ProviderStream> {
        match self {
            Self::Anthropic(provider) => provider.stream(request).await,
            Self::OpenAi(provider) => provider.stream(request).await,
        }
    }
}

#[derive(Clone)]
struct Pricing {
    provider_label: &'static str,
    input_per_mtok: f64,
    output_per_mtok: f64,
}

fn live_provider_from_env() -> Result<(LiveProvider, String, Pricing)> {
    if let Ok(key) = env::var("ANTHROPIC_API_KEY") {
        let model =
            env::var("ENDEAVOUR_E2E_MODEL").unwrap_or_else(|_| "claude-sonnet-4-5".to_string());
        return Ok((
            LiveProvider::Anthropic(AnthropicProvider::new(key)),
            model,
            Pricing {
                provider_label: "Anthropic",
                input_per_mtok: 3.0,
                output_per_mtok: 15.0,
            },
        ));
    }

    if let Ok(key) = env::var("OPENAI_API_KEY") {
        let model = env::var("ENDEAVOUR_E2E_MODEL").unwrap_or_else(|_| "gpt-4o".to_string());
        return Ok((
            LiveProvider::OpenAi(OpenAiProvider::new(key)),
            model,
            Pricing {
                provider_label: "OpenAI",
                input_per_mtok: 2.5,
                output_per_mtok: 10.0,
            },
        ));
    }

    Err(anyhow!(
        "set ANTHROPIC_API_KEY or OPENAI_API_KEY to run live smoke harness"
    ))
}

fn parse_host_port(value: &str) -> Result<(String, u16)> {
    let (host, port) = value.trim().rsplit_once(':').ok_or_else(|| {
        anyhow!(
            "invalid ENDEAVOUR_LIVE_IDA_HOST '{}': expected host:port",
            value
        )
    })?;
    let parsed_port = port
        .parse::<u16>()
        .with_context(|| format!("invalid ENDEAVOUR_LIVE_IDA_HOST port '{}': not a u16", port))?;
    Ok((host.to_string(), parsed_port))
}

#[tokio::test]
#[ignore = "manual-only: requires live IDA bridge and real API key"]
async fn e2e_smoke_live_ida_manual_harness() {
    let (provider, model, pricing) =
        live_provider_from_env().unwrap_or_else(|err| panic!("live smoke setup failed: {err}"));
    let ida_endpoint =
        env::var("ENDEAVOUR_LIVE_IDA_HOST").unwrap_or_else(|_| "127.0.0.1:13337".to_string());
    let (host, port) =
        parse_host_port(&ida_endpoint).unwrap_or_else(|err| panic!("invalid live IDA host: {err}"));

    let client = Arc::new(IdaClient::new(&host, port));
    let functions = client
        .list_functions(Some("sub_*"), Some(1))
        .await
        .unwrap_or_else(|err| panic!("failed to query functions from live IDA: {err}"));
    let target = functions
        .first()
        .unwrap_or_else(|| panic!("no generic sub_* function found in live IDA"));
    let target_addr = target.address;

    let mut controller = AgenticLoopController::new(AgenticLoopConfig {
        max_steps: 8,
        ..AgenticLoopConfig::default()
    });
    let context = ContextBuilder::new(&model)
        .with_history(vec![Message {
            role: Role::User,
            content: format!(
                "Rename the function at 0x{target_addr:x} to something meaningful and explain the name choice in one sentence."
            ),
            tool_results: Vec::new(),
        }])
        .with_tools(IdaToolExecutor::tool_definitions());
    let executor = IdaToolExecutor::new(client);

    let result = controller
        .run(&provider, context, &executor, None)
        .await
        .unwrap_or_else(|err| panic!("live smoke agentic loop failed: {err}"));

    let saw_decompile = result
        .transcript
        .iter()
        .flat_map(|turn| turn.tool_calls.iter())
        .any(|call| call.name == "decompile");
    let saw_rename = result
        .transcript
        .iter()
        .flat_map(|turn| turn.tool_calls.iter())
        .any(|call| call.name == "rename_function");

    assert!(saw_decompile, "expected at least one decompile tool call");
    assert!(
        saw_rename,
        "expected at least one rename_function tool call"
    );
    assert_eq!(
        result.termination_reason,
        AgenticTerminationReason::Success,
        "live loop should converge"
    );

    let input_tokens = f64::from(result.usage_totals.input_tokens);
    let output_tokens = f64::from(result.usage_totals.output_tokens);
    let input_cost = (input_tokens / 1_000_000.0) * pricing.input_per_mtok;
    let output_cost = (output_tokens / 1_000_000.0) * pricing.output_per_mtok;
    let total_cost = input_cost + output_cost;

    println!("Provider: {} {}", pricing.provider_label, model);
    println!("Input tokens:  {}", result.usage_totals.input_tokens);
    println!("Output tokens: {}", result.usage_totals.output_tokens);
    println!("Estimated cost: ${total_cost:.6}");
    println!();
    println!(
        "Pass/Fail: {}",
        if total_cost <= 0.10 {
            "PASS (<= $0.10)"
        } else {
            "FAIL (> $0.10)"
        }
    );
}
