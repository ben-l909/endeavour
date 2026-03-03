use std::collections::VecDeque;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use endeavour_ida::{IdaClient, IdaError, Result, Transport};
use serde_json::Value;

struct FixtureTransport {
    responses: Mutex<VecDeque<Result<Value>>>,
}

impl FixtureTransport {
    fn new(responses: Vec<Result<Value>>) -> Self {
        Self {
            responses: Mutex::new(responses.into()),
        }
    }
}

#[async_trait]
impl Transport for FixtureTransport {
    async fn call(&self, _method: &str, _params: Value) -> Result<Value> {
        let mut guard = self.responses.lock().map_err(|_| {
            IdaError::IdaResponseError("FixtureTransport lock poisoned".to_string())
        })?;
        guard.pop_front().unwrap_or_else(|| {
            Err(IdaError::IdaResponseError(
                "No fixture response queued".to_string(),
            ))
        })
    }
}

fn fixture_path(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/fixtures/ida_responses")
        .join(name)
}

fn load_fixture(name: &str) -> Value {
    let path = fixture_path(name);
    let data = std::fs::read_to_string(&path)
        .unwrap_or_else(|err| panic!("failed to read fixture {}: {err}", path.display()));
    serde_json::from_str::<Value>(&data)
        .unwrap_or_else(|err| panic!("failed to parse fixture {}: {err}", path.display()))
}

#[tokio::test]
async fn decompile_fixtures_parse_with_expected_shapes() {
    let transport = Arc::new(FixtureTransport::new(vec![
        Ok(load_fixture("decompile_success.json")),
        Ok(load_fixture("decompile_complex.json")),
        Ok(load_fixture("decompile_error.json")),
    ]));
    let client = IdaClient::with_transport("127.0.0.1", 13337, transport);

    let success = client
        .decompile(0x100004a20)
        .await
        .expect("success fixture should parse");
    assert_eq!(success.address, 0x100004a20);
    assert!(success.pseudocode.contains("parse_header"));

    let complex = client
        .decompile(0x1000075d0)
        .await
        .expect("complex fixture should parse");
    assert_eq!(complex.address, 0x1000075d0);
    assert!(complex.pseudocode.contains("mba_score_block"));
    assert!(complex.pseudocode.contains("for (i = 0; i < 8; ++i)"));

    let err = client.decompile(0xdeadbeef).await;
    assert!(matches!(err, Err(IdaError::IdaResponseError(_))));
}

#[tokio::test]
async fn search_fixtures_parse_with_expected_shapes() {
    let transport = Arc::new(FixtureTransport::new(vec![
        Ok(load_fixture("search_matches.json")),
        Ok(load_fixture("search_empty.json")),
    ]));
    let client = IdaClient::with_transport("127.0.0.1", 13337, transport);

    let matches = client
        .find_strings("https?://")
        .await
        .expect("matches fixture should parse");
    assert!(matches.len() >= 5);
    assert_eq!(matches[0].0, 0x100081020);
    assert!(matches
        .iter()
        .any(|(_, s)| s.contains("Authorization: Bearer")));

    let empty = client
        .find_strings("nomatch")
        .await
        .expect("empty fixture should parse");
    assert!(empty.is_empty());
}

#[tokio::test]
async fn list_function_fixtures_parse_with_expected_shapes() {
    let transport = Arc::new(FixtureTransport::new(vec![
        Ok(load_fixture("list_functions.json")),
        Ok(load_fixture("connection_test.json")),
    ]));
    let client = IdaClient::with_transport("127.0.0.1", 13337, transport);

    let listed = client
        .list_functions(None, Some(10))
        .await
        .expect("list_functions fixture should parse");
    assert_eq!(listed.len(), 10);
    assert_eq!(listed[0].name, "_start");
    assert_eq!(listed[9].name, "_teardown_context");

    let probe = client
        .list_functions(None, Some(1))
        .await
        .expect("connection fixture should parse");
    assert_eq!(probe.len(), 1);
    assert_eq!(probe[0].name, "_main");
}
