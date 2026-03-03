use std::str::FromStr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use async_trait::async_trait;
use serde_json::{json, Value};

use crate::error::{IdaError, Result};
use crate::types::{
    BasicBlock, CommentRequest, DecompileResult, DisasmInstruction, FunctionInfo, RenameRequest, XRef,
};

/// Abstract transport for IDA MCP requests.
#[async_trait]
pub trait Transport: Send + Sync {
    /// Sends a JSON-RPC method call and returns the decoded result payload.
    async fn call(&self, method: &str, params: Value) -> Result<Value>;
}

/// HTTP JSON-RPC transport for IDA MCP.
pub struct HttpTransport {
    base_url: String,
    client: reqwest::Client,
    next_id: AtomicU64,
}

impl HttpTransport {
    /// Creates a transport from host and port.
    pub fn new(host: &str, port: u16) -> Self {
        Self::from_client(format!("http://{host}:{port}"), reqwest::Client::new())
    }

    /// Creates a transport from an existing reqwest client.
    pub fn from_client(base_url: String, client: reqwest::Client) -> Self {
        Self {
            base_url,
            client,
            next_id: AtomicU64::new(1),
        }
    }
}

#[async_trait]
impl Transport for HttpTransport {
    async fn call(&self, method: &str, params: Value) -> Result<Value> {
        let request_id = self.next_id.fetch_add(1, Ordering::Relaxed);
        let body = json!({
            "jsonrpc": "2.0",
            "id": request_id,
            "method": method,
            "params": params,
        });
        let url = format!("{}/mcp", self.base_url.trim_end_matches('/'));

        let response = self.client.post(url).json(&body).send().await.map_err(|err| {
            if err.is_timeout() {
                IdaError::Timeout
            } else if err.is_connect() {
                IdaError::ConnectionError(err.to_string())
            } else {
                IdaError::HttpError(err)
            }
        })?;

        let payload: Value = response.json().await.map_err(|err| {
            if err.is_decode() {
                IdaError::DeserializationError(err.to_string())
            } else {
                IdaError::HttpError(err)
            }
        })?;

        if let Some(error) = payload.get("error") {
            return Err(IdaError::IdaResponseError(error.to_string()));
        }

        let result = payload
            .get("result")
            .cloned()
            .ok_or_else(|| IdaError::DeserializationError("Missing JSON-RPC result field".to_string()))?;

        normalize_result(result)
    }
}

/// High-level asynchronous IDA MCP client.
pub struct IdaClient {
    base_url: String,
    client: reqwest::Client,
    transport: Arc<dyn Transport>,
}

impl IdaClient {
    /// Creates a new IDA client for the given host and port.
    pub fn new(host: &str, port: u16) -> Self {
        let base_url = format!("http://{host}:{port}");
        let client = reqwest::Client::new();
        let transport = Arc::new(HttpTransport::from_client(base_url.clone(), client.clone()));
        Self {
            base_url,
            client,
            transport,
        }
    }

    /// Creates a client with a custom transport implementation.
    pub fn with_transport(host: &str, port: u16, transport: Arc<dyn Transport>) -> Self {
        Self {
            base_url: format!("http://{host}:{port}"),
            client: reqwest::Client::new(),
            transport,
        }
    }

    /// Returns configured base URL.
    pub fn base_url(&self) -> &str {
        &self.base_url
    }

    /// Returns the underlying reqwest client.
    pub fn http_client(&self) -> &reqwest::Client {
        &self.client
    }

    /// Decompiles a function at address.
    pub async fn decompile(&self, addr: u64) -> Result<DecompileResult> {
        let payload = self
            .transport
            .call("decompile", json!({ "addr": to_hex(addr) }))
            .await?;
        check_error_field(&payload)?;

        let pseudocode = payload
            .get("pseudocode")
            .or_else(|| payload.get("code"))
            .and_then(Value::as_str)
            .ok_or_else(|| IdaError::DeserializationError("Missing pseudocode/code in decompile response".to_string()))?;

        let address = payload
            .get("address")
            .or_else(|| payload.get("addr"))
            .and_then(parse_u64)
            .unwrap_or(addr);

        Ok(DecompileResult {
            address,
            pseudocode: pseudocode.to_string(),
        })
    }

    /// Disassembles a function into instruction rows.
    pub async fn disassemble(&self, addr: u64) -> Result<Vec<DisasmInstruction>> {
        let payload = self
            .transport
            .call("disasm", json!({ "addr": to_hex(addr) }))
            .await?;
        check_error_field(&payload)?;

        if let Some(instructions) = payload.get("instructions").and_then(Value::as_array) {
            let mut parsed = Vec::with_capacity(instructions.len());
            for ins in instructions {
                let instruction = parse_instruction_object(ins)?;
                parsed.push(instruction);
            }
            return Ok(parsed);
        }

        let lines = payload
            .get("asm")
            .and_then(|asm| asm.get("lines"))
            .or_else(|| payload.get("lines"))
            .and_then(Value::as_str)
            .ok_or_else(|| IdaError::DeserializationError("Missing asm.lines/lines in disasm response".to_string()))?;

        Ok(parse_disassembly_lines(lines))
    }

    /// Lists functions with optional filter and count.
    pub async fn list_functions(
        &self,
        filter: Option<&str>,
        count: Option<u32>,
    ) -> Result<Vec<FunctionInfo>> {
        let query = json!({
            "queries": {
                "filter": filter.unwrap_or(""),
                "count": count.unwrap_or(100),
                "offset": 0
            }
        });
        let payload = self.transport.call("list_funcs", query).await?;

        let pages = match payload.as_array() {
            Some(array) => array,
            None => {
                return Err(IdaError::DeserializationError(
                    "list_funcs response must be an array of pages".to_string(),
                ));
            }
        };

        let mut functions = Vec::new();
        for page in pages {
            check_error_field(page)?;
            let items = page
                .get("items")
                .or_else(|| page.get("functions"))
                .and_then(Value::as_array)
                .ok_or_else(|| IdaError::DeserializationError("Page missing items/functions".to_string()))?;
            for item in items {
                functions.push(parse_function(item)?);
            }
        }

        Ok(functions)
    }

    /// Looks up one function by name or address query.
    pub async fn lookup_function(&self, query: &str) -> Result<Option<FunctionInfo>> {
        let payload = self
            .transport
            .call("lookup_funcs", json!({ "queries": [query] }))
            .await?;
        let entries = payload
            .as_array()
            .ok_or_else(|| IdaError::DeserializationError("lookup_funcs response must be an array".to_string()))?;
        let first = entries
            .first()
            .ok_or_else(|| IdaError::DeserializationError("lookup_funcs response is empty".to_string()))?;

        check_error_field(first)?;
        let fn_value = first.get("fn").unwrap_or(&Value::Null);
        if fn_value.is_null() {
            return Ok(None);
        }

        Ok(Some(parse_function(fn_value)?))
    }

    /// Lists xrefs to a target address.
    pub async fn xrefs_to(&self, addr: u64) -> Result<Vec<XRef>> {
        let payload = self
            .transport
            .call("xrefs_to", json!({ "addrs": [to_hex(addr)] }))
            .await?;

        let top = payload
            .as_array()
            .and_then(|arr| arr.first())
            .ok_or_else(|| IdaError::DeserializationError("xrefs_to response must be a non-empty array".to_string()))?;
        check_error_field(top)?;

        let xrefs = top
            .get("xrefs")
            .and_then(Value::as_array)
            .ok_or_else(|| IdaError::DeserializationError("xrefs_to result missing xrefs".to_string()))?;

        let mut parsed = Vec::with_capacity(xrefs.len());
        for item in xrefs {
            let from_addr = item
                .get("from_addr")
                .or_else(|| item.get("addr"))
                .and_then(parse_u64)
                .ok_or_else(|| IdaError::DeserializationError("xref missing source address".to_string()))?;
            let xref_type = item
                .get("xref_type")
                .or_else(|| item.get("type"))
                .and_then(Value::as_str)
                .unwrap_or("unknown")
                .to_string();
            parsed.push(XRef {
                from_addr,
                to_addr: addr,
                xref_type,
            });
        }

        Ok(parsed)
    }

    /// Lists callees for a function address.
    pub async fn callees(&self, addr: u64) -> Result<Vec<FunctionInfo>> {
        let payload = self
            .transport
            .call("callees", json!({ "addrs": [to_hex(addr)] }))
            .await?;
        let top = payload
            .as_array()
            .and_then(|arr| arr.first())
            .ok_or_else(|| IdaError::DeserializationError("callees response must be a non-empty array".to_string()))?;
        check_error_field(top)?;
        let callees = top
            .get("callees")
            .and_then(Value::as_array)
            .ok_or_else(|| IdaError::DeserializationError("callees entry missing callees list".to_string()))?;
        let mut result = Vec::with_capacity(callees.len());
        for callee in callees {
            result.push(parse_function(callee)?);
        }
        Ok(result)
    }

    /// Builds call graph edges from a root function.
    pub async fn call_graph(&self, root: u64, max_depth: Option<u32>) -> Result<Vec<(u64, u64)>> {
        let mut params = json!({ "roots": [to_hex(root)] });
        if let Some(depth) = max_depth {
            params["max_depth"] = json!(depth);
        }
        let payload = self.transport.call("callgraph", params).await?;
        check_error_field(&payload)?;

        let edges = payload
            .get("edges")
            .and_then(Value::as_array)
            .ok_or_else(|| IdaError::DeserializationError("callgraph response missing edges".to_string()))?;
        let mut parsed = Vec::with_capacity(edges.len());
        for edge in edges {
            if let Some(pair) = edge.as_array() {
                if pair.len() >= 2 {
                    let src = parse_u64(&pair[0]).ok_or_else(|| {
                        IdaError::DeserializationError("callgraph edge source is invalid".to_string())
                    })?;
                    let dst = parse_u64(&pair[1]).ok_or_else(|| {
                        IdaError::DeserializationError("callgraph edge destination is invalid".to_string())
                    })?;
                    parsed.push((src, dst));
                    continue;
                }
            }
            let src = edge
                .get("src")
                .or_else(|| edge.get("from"))
                .and_then(parse_u64)
                .ok_or_else(|| IdaError::DeserializationError("callgraph edge source is missing".to_string()))?;
            let dst = edge
                .get("dst")
                .or_else(|| edge.get("to"))
                .and_then(parse_u64)
                .ok_or_else(|| IdaError::DeserializationError("callgraph edge destination is missing".to_string()))?;
            parsed.push((src, dst));
        }
        Ok(parsed)
    }

    /// Finds strings with regex search.
    pub async fn find_strings(&self, pattern: &str) -> Result<Vec<(u64, String)>> {
        let payload = self
            .transport
            .call("find_regex", json!({ "pattern": pattern }))
            .await?;
        check_error_field(&payload)?;

        let matches = payload
            .get("matches")
            .and_then(Value::as_array)
            .ok_or_else(|| IdaError::DeserializationError("find_regex response missing matches".to_string()))?;

        let mut results = Vec::with_capacity(matches.len());
        for m in matches {
            let address = m
                .get("addr")
                .and_then(parse_u64)
                .ok_or_else(|| IdaError::DeserializationError("match addr is missing".to_string()))?;
            let text = m
                .get("string")
                .and_then(Value::as_str)
                .ok_or_else(|| IdaError::DeserializationError("match string is missing".to_string()))?;
            results.push((address, text.to_string()));
        }

        Ok(results)
    }

    /// Renames a function symbol.
    pub async fn rename_function(&self, addr: u64, new_name: &str) -> Result<()> {
        let request = RenameRequest {
            addr: to_hex(addr),
            name: new_name.to_string(),
        };
        let payload = self
            .transport
            .call("rename", json!({ "batch": { "func": [request] } }))
            .await?;

        let result = payload
            .get("func")
            .and_then(Value::as_array)
            .and_then(|arr| arr.first())
            .ok_or_else(|| IdaError::DeserializationError("rename response missing func result".to_string()))?;

        if let Some(error) = result.get("error") {
            if !error.is_null() {
                return Err(IdaError::IdaResponseError(error.to_string()));
            }
        }

        let ok = result.get("ok").and_then(Value::as_bool).unwrap_or(false);
        if !ok {
            return Err(IdaError::IdaResponseError("Rename failed".to_string()));
        }

        Ok(())
    }

    /// Sets a comment at address.
    pub async fn set_comment(&self, addr: u64, comment: &str) -> Result<()> {
        let request = CommentRequest {
            addr: to_hex(addr),
            comment: comment.to_string(),
        };
        let payload = self
            .transport
            .call("set_comments", json!({ "items": [request] }))
            .await?;

        let result = payload
            .as_array()
            .and_then(|arr| arr.first())
            .ok_or_else(|| IdaError::DeserializationError("set_comments response must be non-empty array".to_string()))?;

        if let Some(error) = result.get("error") {
            if !error.is_null() {
                return Err(IdaError::IdaResponseError(error.to_string()));
            }
        }

        if !result.get("ok").and_then(Value::as_bool).unwrap_or(false) {
            return Err(IdaError::IdaResponseError("set_comment failed".to_string()));
        }
        Ok(())
    }

    /// Executes Python in IDA and returns raw JSON output.
    pub async fn py_eval(&self, code: &str) -> Result<Value> {
        self.transport.call("py_eval", json!({ "code": code })).await
    }

    /// Reads bytes at address.
    pub async fn get_bytes(&self, addr: u64, size: usize) -> Result<Vec<u8>> {
        let payload = self
            .transport
            .call(
                "get_bytes",
                json!({
                    "regions": [{ "addr": to_hex(addr), "size": size }]
                }),
            )
            .await?;

        let entry = payload
            .as_array()
            .and_then(|arr| arr.first())
            .or_else(|| payload.get("regions").and_then(Value::as_array).and_then(|arr| arr.first()))
            .ok_or_else(|| IdaError::DeserializationError("get_bytes response missing region entry".to_string()))?;
        check_error_field(entry)?;

        let raw = entry
            .get("bytes")
            .or_else(|| entry.get("data"))
            .and_then(Value::as_str)
            .ok_or_else(|| IdaError::DeserializationError("get_bytes result missing bytes/data field".to_string()))?;

        parse_hex_bytes(raw)
    }

    /// Reads CFG basic blocks for a function.
    pub async fn basic_blocks(&self, addr: u64) -> Result<Vec<BasicBlock>> {
        let payload = self
            .transport
            .call("basic_blocks", json!({ "addrs": [to_hex(addr)] }))
            .await?;

        let top = payload
            .as_array()
            .and_then(|arr| arr.first())
            .ok_or_else(|| IdaError::DeserializationError("basic_blocks response must be non-empty array".to_string()))?;
        check_error_field(top)?;

        let blocks = top
            .get("blocks")
            .and_then(Value::as_array)
            .ok_or_else(|| IdaError::DeserializationError("basic_blocks response missing blocks".to_string()))?;

        let mut parsed = Vec::with_capacity(blocks.len());
        for block in blocks {
            let start = block
                .get("start")
                .and_then(parse_u64)
                .ok_or_else(|| IdaError::DeserializationError("basic block start missing".to_string()))?;
            let end = block
                .get("end")
                .and_then(parse_u64)
                .ok_or_else(|| IdaError::DeserializationError("basic block end missing".to_string()))?;

            let succ_values = block
                .get("succs")
                .or_else(|| block.get("successors"))
                .and_then(Value::as_array)
                .ok_or_else(|| IdaError::DeserializationError("basic block successors missing".to_string()))?;
            let mut succs = Vec::with_capacity(succ_values.len());
            for succ in succ_values {
                let parsed_succ = parse_u64(succ).ok_or_else(|| {
                    IdaError::DeserializationError("invalid basic block successor address".to_string())
                })?;
                succs.push(parsed_succ);
            }

            parsed.push(BasicBlock { start, end, succs });
        }

        Ok(parsed)
    }
}

fn normalize_result(result: Value) -> Result<Value> {
    if let Some(content) = result.get("content").and_then(Value::as_array) {
        for item in content {
            if let Some(text) = item.get("text").and_then(Value::as_str) {
                if let Ok(decoded) = serde_json::from_str::<Value>(text) {
                    return Ok(decoded);
                }
                return Ok(Value::String(text.to_string()));
            }
        }
    }
    if let Some(structured) = result.get("structuredContent") {
        return Ok(structured.clone());
    }
    Ok(result)
}

fn parse_function(value: &Value) -> Result<FunctionInfo> {
    let address = value
        .get("address")
        .or_else(|| value.get("addr"))
        .and_then(parse_u64)
        .ok_or_else(|| IdaError::DeserializationError("function address missing".to_string()))?;
    let name = value
        .get("name")
        .and_then(Value::as_str)
        .ok_or_else(|| IdaError::DeserializationError("function name missing".to_string()))?;
    let size = value.get("size").and_then(parse_u64);
    Ok(FunctionInfo {
        address,
        name: name.to_string(),
        size,
    })
}

fn parse_instruction_object(value: &Value) -> Result<DisasmInstruction> {
    let address = value
        .get("address")
        .or_else(|| value.get("addr"))
        .and_then(parse_u64)
        .ok_or_else(|| IdaError::DeserializationError("instruction address missing".to_string()))?;
    let mnemonic = value
        .get("mnemonic")
        .and_then(Value::as_str)
        .ok_or_else(|| IdaError::DeserializationError("instruction mnemonic missing".to_string()))?;
    let operands = value.get("operands").and_then(Value::as_str).unwrap_or("");
    Ok(DisasmInstruction {
        address,
        mnemonic: mnemonic.to_string(),
        operands: operands.to_string(),
    })
}

fn parse_disassembly_lines(lines: &str) -> Vec<DisasmInstruction> {
    let mut result = Vec::new();
    let mut iter = lines.lines();
    if let Some(first) = iter.next() {
        if !(first.contains(" @ ") && first.contains('(') && first.contains(')')) {
            iter = lines.lines();
        }
    }

    for line in iter {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        let mut parts = trimmed.splitn(2, char::is_whitespace);
        let addr_text = match parts.next() {
            Some(value) => value.trim_end_matches(':'),
            None => continue,
        };
        let rest = match parts.next() {
            Some(value) => value.trim(),
            None => continue,
        };
        let address = match u64::from_str_radix(addr_text, 16).ok().or_else(|| parse_hex_or_decimal(addr_text)) {
            Some(value) => value,
            None => continue,
        };
        let mut insn = rest.splitn(2, char::is_whitespace);
        let mnemonic = insn.next().unwrap_or_default();
        let operands = insn.next().unwrap_or_default();
        result.push(DisasmInstruction {
            address,
            mnemonic: mnemonic.to_string(),
            operands: operands.to_string(),
        });
    }
    result
}

fn parse_u64(value: &Value) -> Option<u64> {
    if let Some(v) = value.as_u64() {
        return Some(v);
    }
    if let Some(s) = value.as_str() {
        return parse_hex_or_decimal(s);
    }
    None
}

fn parse_hex_or_decimal(text: &str) -> Option<u64> {
    let trimmed = text.trim();
    if let Some(hex) = trimmed.strip_prefix("0x").or_else(|| trimmed.strip_prefix("0X")) {
        return u64::from_str_radix(hex, 16).ok();
    }
    if let Ok(decimal) = u64::from_str(trimmed) {
        return Some(decimal);
    }
    if trimmed.chars().all(|c| c.is_ascii_hexdigit()) && trimmed.chars().any(|c| c.is_ascii_alphabetic()) {
        return u64::from_str_radix(trimmed, 16).ok();
    }
    None
}

fn parse_hex_bytes(text: &str) -> Result<Vec<u8>> {
    let cleaned = text.trim();
    if cleaned.is_empty() {
        return Ok(Vec::new());
    }

    let tokens: Vec<String> = if cleaned.contains(' ') || cleaned.contains(',') {
        cleaned
            .split(|c: char| c.is_ascii_whitespace() || c == ',')
            .filter(|token| !token.is_empty())
            .map(|token| token.trim_start_matches("0x").trim_start_matches("0X").to_string())
            .collect()
    } else {
        let dense = cleaned
            .trim_start_matches("0x")
            .trim_start_matches("0X")
            .to_string();
        if dense.len() % 2 != 0 {
            return Err(IdaError::DeserializationError("Invalid hex byte string length".to_string()));
        }
        dense
            .as_bytes()
            .chunks(2)
            .map(|pair| String::from_utf8_lossy(pair).to_string())
            .collect()
    };

    let mut bytes = Vec::with_capacity(tokens.len());
    for token in tokens {
        let byte = u8::from_str_radix(&token, 16)
            .map_err(|_| IdaError::DeserializationError(format!("Invalid byte token: {token}")))?;
        bytes.push(byte);
    }
    Ok(bytes)
}

fn check_error_field(value: &Value) -> Result<()> {
    if let Some(error) = value.get("error") {
        if !error.is_null() {
            return Err(IdaError::IdaResponseError(error.to_string()));
        }
    }
    Ok(())
}

fn to_hex(addr: u64) -> String {
    format!("0x{addr:x}")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::VecDeque;
    use std::sync::Mutex;

    /// Mock transport for unit testing client behavior.
    struct MockTransport {
        responses: Mutex<VecDeque<Result<Value>>>,
        calls: Mutex<Vec<(String, Value)>>,
    }

    impl MockTransport {
        /// Creates a mock transport with queued responses.
        fn new(responses: Vec<Result<Value>>) -> Self {
            Self {
                responses: Mutex::new(responses.into()),
                calls: Mutex::new(Vec::new()),
            }
        }

        /// Returns the first recorded call.
        fn first_call(&self) -> Option<(String, Value)> {
            let guard = self.calls.lock().ok()?;
            guard.first().cloned()
        }
    }

    #[async_trait]
    impl Transport for MockTransport {
        async fn call(&self, method: &str, params: Value) -> Result<Value> {
            if let Ok(mut calls) = self.calls.lock() {
                calls.push((method.to_string(), params));
            }
            let mut queue = self
                .responses
                .lock()
                .map_err(|_| IdaError::IdaResponseError("Mock lock poisoned".to_string()))?;
            queue
                .pop_front()
                .unwrap_or_else(|| Err(IdaError::IdaResponseError("No mock response queued".to_string())))
        }
    }

    #[tokio::test]
    async fn decompile_uses_hex_and_parses_payload() {
        let mock = Arc::new(MockTransport::new(vec![Ok(json!({
            "addr": "0x401000",
            "code": "int main() { return 0; }"
        }))]));
        let client = IdaClient::with_transport("127.0.0.1", 13337, mock.clone());

        let result = client.decompile(0x401000).await;
        assert!(result.is_ok());
        let result = match result {
            Ok(value) => value,
            Err(err) => panic!("unexpected error: {err}"),
        };
        assert_eq!(result.address, 0x401000);
        assert_eq!(result.pseudocode, "int main() { return 0; }");

        let call = mock.first_call();
        assert!(call.is_some());
        let (method, params) = call.unwrap_or_else(|| unreachable!());
        assert_eq!(method, "decompile");
        assert_eq!(params.get("addr").and_then(Value::as_str), Some("0x401000"));
    }

    #[tokio::test]
    async fn list_functions_parses_page_items() {
        let mock = Arc::new(MockTransport::new(vec![Ok(json!([
            {
                "items": [
                    {"addr": "0x401000", "name": "sub_401000", "size": "0x20"}
                ],
                "cursor": {"done": true}
            }
        ]))]));
        let client = IdaClient::with_transport("127.0.0.1", 13337, mock.clone());

        let funcs = client.list_functions(Some("sub_*"), Some(10)).await;
        assert!(funcs.is_ok());
        let funcs = match funcs {
            Ok(value) => value,
            Err(err) => panic!("unexpected error: {err}"),
        };
        assert_eq!(funcs.len(), 1);
        assert_eq!(funcs[0].address, 0x401000);
        assert_eq!(funcs[0].name, "sub_401000");
        assert_eq!(funcs[0].size, Some(0x20));
    }

    #[tokio::test]
    async fn rename_uses_hex_and_checks_success() {
        let mock = Arc::new(MockTransport::new(vec![Ok(json!({
            "func": [
                {"addr": "0x401000", "name": "main", "ok": true, "error": null}
            ]
        }))]));
        let client = IdaClient::with_transport("127.0.0.1", 13337, mock.clone());

        let renamed = client.rename_function(0x401000, "main").await;
        assert!(renamed.is_ok());

        let call = mock.first_call();
        assert!(call.is_some());
        let (method, params) = call.unwrap_or_else(|| unreachable!());
        assert_eq!(method, "rename");
        let addr = params
            .get("batch")
            .and_then(|batch| batch.get("func"))
            .and_then(Value::as_array)
            .and_then(|arr| arr.first())
            .and_then(|entry| entry.get("addr"))
            .and_then(Value::as_str);
        assert_eq!(addr, Some("0x401000"));
    }

    #[tokio::test]
    async fn returns_connection_error_for_refused_socket() {
        let client = IdaClient::new("127.0.0.1", 1);
        let result = client.decompile(0x401000).await;
        assert!(result.is_err());
        match result {
            Err(IdaError::ConnectionError(_)) | Err(IdaError::Timeout) => {}
            Err(other) => panic!("unexpected error type: {other}"),
            Ok(_) => panic!("expected error"),
        }
    }

    #[tokio::test]
    async fn returns_deserialization_error_for_invalid_shape() {
        let mock = Arc::new(MockTransport::new(vec![Ok(json!("not-an-object"))]));
        let client = IdaClient::with_transport("127.0.0.1", 13337, mock);

        let result = client.decompile(0x401000).await;
        assert!(matches!(result, Err(IdaError::DeserializationError(_))));
    }

    #[tokio::test]
    async fn returns_ida_error_for_error_payload() {
        let mock = Arc::new(MockTransport::new(vec![Ok(json!({
            "addr": "0x401000",
            "code": null,
            "error": "Decompilation failed"
        }))]));
        let client = IdaClient::with_transport("127.0.0.1", 13337, mock);

        let result = client.decompile(0x401000).await;
        assert!(matches!(result, Err(IdaError::IdaResponseError(_))));
    }
}
