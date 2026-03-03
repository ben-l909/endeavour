use std::collections::{HashMap, VecDeque};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use async_trait::async_trait;
use endeavour_ida::{IdaError, Transport};
use serde_json::Value;
use tokio_stream::iter;

use crate::error::{LlmError, Result};
use crate::provider::{LlmProvider, ProviderStream};
use crate::types::{CompletionRequest, CompletionResponse, StreamChunk};

#[derive(Debug)]
/// A mock response that can be queued for testing.
pub enum MockResponse {
    /// A complete (non-streaming) response.
    Completion(Result<CompletionResponse>),
    /// A streaming response as a sequence of chunks.
    Stream(Result<Vec<StreamChunk>>),
}

#[derive(Clone, Debug)]
/// A mock LLM provider for testing.
///
/// Queues predefined responses that are returned in order when completion
/// or streaming methods are called.
pub struct MockProvider {
    responses: Arc<Mutex<VecDeque<MockResponse>>>,
    requests: Arc<Mutex<Vec<CompletionRequest>>>,
}

impl MockProvider {
    /// Creates a new mock provider with the given queued responses.
    pub fn new(responses: Vec<MockResponse>) -> Self {
        Self {
            responses: Arc::new(Mutex::new(responses.into_iter().collect())),
            requests: Arc::new(Mutex::new(Vec::new())),
        }
    }

    /// Returns number of completion/stream calls made.
    pub fn call_count(&self) -> usize {
        self.requests.lock().map_or(0, |requests| requests.len())
    }

    /// Returns captured requests sent to this provider.
    pub fn calls(&self) -> Vec<CompletionRequest> {
        self.requests
            .lock()
            .map_or_else(|_| Vec::new(), |requests| requests.clone())
    }

    /// Returns queued responses not yet consumed.
    pub fn remaining_responses(&self) -> usize {
        self.responses.lock().map_or(0, |queue| queue.len())
    }

    /// Enqueues an additional response to be returned on the next request.
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
    async fn complete(&self, request: CompletionRequest) -> Result<CompletionResponse> {
        let mut requests = self.requests.lock().map_err(|_| LlmError::ChannelClosed)?;
        requests.push(request);
        match self.next_response()? {
            MockResponse::Completion(result) => result,
            MockResponse::Stream(_) => Err(LlmError::ChannelClosed),
        }
    }

    async fn stream(&self, request: CompletionRequest) -> Result<ProviderStream> {
        let mut requests = self.requests.lock().map_err(|_| LlmError::ChannelClosed)?;
        requests.push(request);
        match self.next_response()? {
            MockResponse::Stream(Ok(chunks)) => Ok(Box::pin(iter(chunks.into_iter().map(Ok)))),
            MockResponse::Stream(Err(err)) => Err(err),
            MockResponse::Completion(_) => Err(LlmError::ChannelClosed),
        }
    }
}

type FixtureKey = (String, String);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
/// Injected error types for `MockIdaTransport`.
pub enum MockIdaError {
    /// Simulate bridge connection failure.
    Connection,
    /// Simulate JSON-RPC method not found (`-32601`).
    MethodNotFound,
    /// Simulate invalid/out-of-range address failure.
    AddressOutOfRange,
}

impl MockIdaError {
    fn into_ida_error(self, method: &str, arg: &str) -> IdaError {
        match self {
            Self::Connection => IdaError::ConnectionError(format!(
                "mock connection failed for method '{method}' ({arg})"
            )),
            Self::MethodNotFound => IdaError::IdaResponseError(format!(
                "{{\"code\":-32601,\"message\":\"Method not found\",\"method\":\"{method}\"}}"
            )),
            Self::AddressOutOfRange => IdaError::IdaResponseError(format!(
                "{{\"code\":1001,\"message\":\"Address out of range\",\"addr\":\"{arg}\"}}"
            )),
        }
    }
}

#[derive(Debug)]
/// Builder for configuring `MockIdaTransport` behavior.
pub struct MockIdaTransportBuilder {
    queued_responses: Vec<endeavour_ida::Result<Value>>,
    fixtures: HashMap<FixtureKey, Value>,
    errors: HashMap<FixtureKey, VecDeque<MockIdaError>>,
    fail_all: Option<MockIdaError>,
    uniform_delay: Option<Duration>,
    per_tool_delay: HashMap<String, Duration>,
    per_call_delay: HashMap<FixtureKey, Duration>,
    missing_fixture_error: Option<MockIdaError>,
    missing_fixture_default: Option<Value>,
}

impl Default for MockIdaTransportBuilder {
    fn default() -> Self {
        Self {
            queued_responses: Vec::new(),
            fixtures: HashMap::new(),
            errors: HashMap::new(),
            fail_all: None,
            uniform_delay: None,
            per_tool_delay: HashMap::new(),
            per_call_delay: HashMap::new(),
            missing_fixture_error: Some(MockIdaError::AddressOutOfRange),
            missing_fixture_default: None,
        }
    }
}

impl MockIdaTransportBuilder {
    /// Adds a deterministic fixture value for one `(method, arg)` pair.
    pub fn fixture(mut self, method: &str, arg: &str, response: Value) -> Self {
        self.fixtures
            .insert((method.to_string(), arg.to_string()), response);
        self
    }

    /// Injects an error for one `(method, arg)` pair.
    pub fn error(mut self, method: &str, arg: &str, error: MockIdaError) -> Self {
        let key = (method.to_string(), arg.to_string());
        self.errors.entry(key).or_default().push_back(error);
        self
    }

    /// Injects one error for every call.
    pub fn fail_all(mut self, error: MockIdaError) -> Self {
        self.fail_all = Some(error);
        self
    }

    /// Adds a uniform async delay (milliseconds) to every call.
    pub fn delay_ms(mut self, delay_ms: u64) -> Self {
        self.uniform_delay = Some(Duration::from_millis(delay_ms));
        self
    }

    /// Adds an async delay (milliseconds) to a specific tool method.
    pub fn delay_for_tool_ms(mut self, method: &str, delay_ms: u64) -> Self {
        self.per_tool_delay
            .insert(method.to_string(), Duration::from_millis(delay_ms));
        self
    }

    /// Adds an async delay (milliseconds) to a specific `(method, arg)` call key.
    pub fn delay_for_call_ms(mut self, method: &str, arg: &str, delay_ms: u64) -> Self {
        self.per_call_delay.insert(
            (method.to_string(), arg.to_string()),
            Duration::from_millis(delay_ms),
        );
        self
    }

    /// Sets the injected error when no fixture or queued response matches.
    pub fn missing_fixture_error(mut self, error: MockIdaError) -> Self {
        self.missing_fixture_error = Some(error);
        self.missing_fixture_default = None;
        self
    }

    /// Sets the fallback response when no fixture or queued response matches.
    pub fn missing_fixture_default(mut self, response: Value) -> Self {
        self.missing_fixture_default = Some(response);
        self.missing_fixture_error = None;
        self
    }

    /// Builds a `MockIdaTransport`.
    pub fn build(self) -> MockIdaTransport {
        MockIdaTransport {
            queued_responses: Mutex::new(self.queued_responses.into()),
            fixtures: Mutex::new(self.fixtures),
            errors: Mutex::new(self.errors),
            calls: Mutex::new(Vec::new()),
            fail_all: self.fail_all,
            uniform_delay: self.uniform_delay,
            per_tool_delay: self.per_tool_delay,
            per_call_delay: self.per_call_delay,
            missing_fixture_error: self.missing_fixture_error,
            missing_fixture_default: self.missing_fixture_default,
        }
    }
}

#[derive(Debug)]
/// Mock transport for IDA client tests and integration harnesses.
pub struct MockIdaTransport {
    queued_responses: Mutex<VecDeque<endeavour_ida::Result<Value>>>,
    fixtures: Mutex<HashMap<FixtureKey, Value>>,
    errors: Mutex<HashMap<FixtureKey, VecDeque<MockIdaError>>>,
    calls: Mutex<Vec<(String, Value)>>,
    fail_all: Option<MockIdaError>,
    uniform_delay: Option<Duration>,
    per_tool_delay: HashMap<String, Duration>,
    per_call_delay: HashMap<FixtureKey, Duration>,
    missing_fixture_error: Option<MockIdaError>,
    missing_fixture_default: Option<Value>,
}

impl MockIdaTransport {
    /// Creates a new builder.
    pub fn builder() -> MockIdaTransportBuilder {
        MockIdaTransportBuilder::default()
    }

    /// Creates a queue-backed mock transport for compatibility with existing tests.
    pub fn new(responses: Vec<endeavour_ida::Result<Value>>) -> Self {
        Self {
            queued_responses: Mutex::new(responses.into()),
            fixtures: Mutex::new(HashMap::new()),
            errors: Mutex::new(HashMap::new()),
            calls: Mutex::new(Vec::new()),
            fail_all: None,
            uniform_delay: None,
            per_tool_delay: HashMap::new(),
            per_call_delay: HashMap::new(),
            missing_fixture_error: Some(MockIdaError::AddressOutOfRange),
            missing_fixture_default: None,
        }
    }

    /// Returns all recorded calls.
    pub fn calls(&self) -> Vec<(String, Value)> {
        self.calls
            .lock()
            .map_or_else(|_| Vec::new(), |calls| calls.clone())
    }

    /// Returns the number of recorded calls.
    pub fn call_count(&self) -> usize {
        self.calls.lock().map_or(0, |calls| calls.len())
    }

    /// Returns number of calls recorded for a method.
    pub fn calls_by_method(&self, method: &str) -> usize {
        self.calls.lock().map_or(0, |calls| {
            calls.iter().filter(|(name, _)| name == method).count()
        })
    }

    /// Returns number of queued responses not consumed yet.
    pub fn remaining_responses(&self) -> usize {
        self.queued_responses
            .lock()
            .map_or(0, |responses| responses.len())
    }

    fn call_key(method: &str, params: &Value) -> FixtureKey {
        (method.to_string(), lookup_arg(params))
    }

    fn selected_delay(&self, key: &FixtureKey) -> Option<Duration> {
        self.per_call_delay
            .get(key)
            .copied()
            .or_else(|| self.per_tool_delay.get(&key.0).copied())
            .or(self.uniform_delay)
    }

    fn next_error_for(&self, key: &FixtureKey) -> Option<MockIdaError> {
        let mut guard = self.errors.lock().ok()?;
        let queue = guard.get_mut(key)?;
        queue.pop_front()
    }

    fn fixture_for(&self, key: &FixtureKey) -> Option<Value> {
        self.fixtures.lock().ok()?.get(key).cloned()
    }

    fn next_queued(&self) -> Option<endeavour_ida::Result<Value>> {
        self.queued_responses.lock().ok()?.pop_front()
    }

    fn missing_fixture_result(&self, method: &str, arg: &str) -> endeavour_ida::Result<Value> {
        if let Some(default) = self.missing_fixture_default.clone() {
            return Ok(default);
        }

        let error = self
            .missing_fixture_error
            .unwrap_or(MockIdaError::AddressOutOfRange);
        Err(error.into_ida_error(method, arg))
    }
}

#[async_trait]
impl Transport for MockIdaTransport {
    async fn call(&self, method: &str, params: Value) -> endeavour_ida::Result<Value> {
        let key = Self::call_key(method, &params);

        if let Some(delay) = self.selected_delay(&key) {
            tokio::time::sleep(delay).await;
        }

        if let Ok(mut calls) = self.calls.lock() {
            calls.push((method.to_string(), params));
        }

        if let Some(error) = self.fail_all {
            return Err(error.into_ida_error(method, &key.1));
        }

        if let Some(error) = self.next_error_for(&key) {
            return Err(error.into_ida_error(method, &key.1));
        }

        if let Some(response) = self.fixture_for(&key) {
            return Ok(response);
        }

        if let Some(response) = self.next_queued() {
            return response;
        }

        self.missing_fixture_result(method, &key.1)
    }
}

fn lookup_arg(params: &Value) -> String {
    if let Some(addr) = params.get("addr").and_then(value_as_lookup_token) {
        return addr;
    }
    if let Some(addr) = params
        .get("addrs")
        .and_then(Value::as_array)
        .and_then(|arr| arr.first())
        .and_then(value_as_lookup_token)
    {
        return addr;
    }
    if let Some(query) = params.get("query").and_then(value_as_lookup_token) {
        return query;
    }
    if let Some(query) = params
        .get("queries")
        .and_then(Value::as_array)
        .and_then(|arr| arr.first())
        .and_then(value_as_lookup_token)
    {
        return query;
    }
    if let Some(pattern) = params.get("pattern").and_then(value_as_lookup_token) {
        return pattern;
    }
    if let Some(filter) = params
        .get("queries")
        .and_then(Value::as_object)
        .and_then(|queries| queries.get("filter"))
        .and_then(value_as_lookup_token)
    {
        return filter;
    }
    serde_json::to_string(params).unwrap_or_default()
}

fn value_as_lookup_token(value: &Value) -> Option<String> {
    if let Some(text) = value.as_str() {
        return Some(text.to_string());
    }
    value.as_u64().map(|number| format!("0x{number:x}"))
}

#[cfg(test)]
mod tests {
    use std::time::{Duration, Instant};

    use futures_util::StreamExt;
    use serde_json::{json, Value};

    use super::{MockIdaError, MockIdaTransport, MockProvider, MockResponse};
    use crate::provider::LlmProvider;
    use crate::types::{
        CompletionRequest, CompletionResponse, Message, Role, StopReason, StreamChunk,
        StreamChunkKind,
    };
    use endeavour_ida::Transport;

    fn request() -> CompletionRequest {
        CompletionRequest {
            model: "test-model".to_string(),
            messages: vec![Message {
                role: Role::User,
                content: "hello".to_string(),
                tool_results: Vec::new(),
            }],
            max_tokens: Some(32),
            temperature: Some(0.0),
            tools: Vec::new(),
        }
    }

    #[tokio::test]
    async fn complete_returns_queued_response() {
        let provider = MockProvider::new(vec![MockResponse::Completion(Ok(CompletionResponse {
            model: "test-model".to_string(),
            content: "ok".to_string(),
            stop_reason: Some(StopReason::EndTurn),
            input_tokens: Some(1),
            output_tokens: Some(1),
            tool_calls: Vec::new(),
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
                kind: StreamChunkKind::TextDelta("he".to_string()),
                stop_reason: None,
            },
            StreamChunk {
                kind: StreamChunkKind::Done {
                    stop_reason: crate::types::StopReason::EndTurn,
                    usage: crate::types::Usage {
                        input_tokens: 1,
                        output_tokens: 1,
                    },
                },
                stop_reason: Some(crate::types::StopReason::EndTurn),
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
        match first.kind {
            StreamChunkKind::TextDelta(ref text) => assert_eq!(text, "he"),
            _ => unreachable!(),
        }

        let second = stream.next().await;
        assert!(second.is_some());
        let second = second.unwrap_or_else(|| unreachable!());
        assert!(second.is_ok());
        let second = second.unwrap_or_else(|_| unreachable!());
        assert!(matches!(second.kind, StreamChunkKind::Done { .. }));
    }

    #[tokio::test]
    async fn exhausted_queue_returns_channel_closed() {
        let provider = MockProvider::new(Vec::new());
        let response = provider.complete(request()).await;
        assert!(response.is_err());
    }

    #[tokio::test]
    async fn fixture_returns_expected_response() {
        let mock = MockIdaTransport::builder()
            .fixture(
                "decompile",
                "0x100004a20",
                json!({"addr": "0x100004a20", "code": "int f() { return 7; }"}),
            )
            .build();

        let response = mock.call("decompile", json!({"addr": "0x100004a20"})).await;

        assert!(response.is_ok());
        let response = response.unwrap_or_else(|_| unreachable!());
        assert_eq!(
            response.get("addr").and_then(Value::as_str),
            Some("0x100004a20")
        );
    }

    #[tokio::test]
    async fn error_injection_returns_expected_error_type() {
        let mock = MockIdaTransport::builder()
            .error("get_bytes", "0xdead", MockIdaError::MethodNotFound)
            .build();

        let response = mock.call("get_bytes", json!({"addrs": ["0xdead"]})).await;

        assert!(response.is_err());
        let message = response
            .err()
            .map(|err| err.to_string())
            .unwrap_or_default();
        assert!(message.contains("-32601"));
    }

    #[tokio::test]
    async fn fail_all_mode_overrides_fixture_responses() {
        let mock = MockIdaTransport::builder()
            .fixture(
                "decompile",
                "0x401000",
                json!({"addr": "0x401000", "code": "ok"}),
            )
            .fail_all(MockIdaError::Connection)
            .build();

        let response = mock.call("decompile", json!({"addr": "0x401000"})).await;

        assert!(response.is_err());
        let message = response
            .err()
            .map(|err| err.to_string())
            .unwrap_or_default();
        assert!(message.contains("Connection failed"));
    }

    #[tokio::test]
    async fn latency_simulation_adds_measurable_delay() {
        let mock = MockIdaTransport::builder()
            .delay_ms(50)
            .fixture(
                "decompile",
                "0x401000",
                json!({"addr": "0x401000", "code": "ok"}),
            )
            .build();

        let started = Instant::now();
        let response = mock.call("decompile", json!({"addr": "0x401000"})).await;
        let elapsed = started.elapsed();

        assert!(response.is_ok());
        assert!(elapsed >= Duration::from_millis(40));
    }

    #[tokio::test]
    async fn per_call_delay_overrides_uniform_delay() {
        let mock = MockIdaTransport::builder()
            .delay_ms(10)
            .delay_for_call_ms("decompile", "0x401001", 70)
            .fixture(
                "decompile",
                "0x401001",
                json!({"addr": "0x401001", "code": "ok"}),
            )
            .build();

        let started = Instant::now();
        let response = mock.call("decompile", json!({"addr": "0x401001"})).await;
        let elapsed = started.elapsed();

        assert!(response.is_ok());
        assert!(elapsed >= Duration::from_millis(55));
    }

    #[tokio::test]
    async fn missing_fixture_returns_configured_error_or_default() {
        let error_mock = MockIdaTransport::builder()
            .missing_fixture_error(MockIdaError::AddressOutOfRange)
            .build();
        let error_response = error_mock
            .call("decompile", json!({"addr": "0x404040"}))
            .await;
        assert!(error_response.is_err());

        let default_mock = MockIdaTransport::builder()
            .missing_fixture_default(json!({"ok": true, "source": "default"}))
            .build();
        let default_response = default_mock
            .call("decompile", json!({"addr": "0x404040"}))
            .await;
        assert!(default_response.is_ok());
        let default_response = default_response.unwrap_or_else(|_| unreachable!());
        assert_eq!(
            default_response.get("source").and_then(Value::as_str),
            Some("default")
        );
    }
}
