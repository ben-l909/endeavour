use std::path::PathBuf;
use std::sync::Arc;

use crate::repl::Repl;
use anyhow::{Context, Result};
use endeavour_ida::{IdaClient, Transport};

pub(crate) fn handle_connect(repl: &mut Repl, endpoint: Option<&str>) -> Result<()> {
    let endpoint = endpoint.unwrap_or("localhost:13337");
    let (host, port) = parse_host_port(endpoint)?;
    let normalized_endpoint = format!("{host}:{port}");

    let (client, functions) = connect_with_transport(
        &repl.runtime,
        &normalized_endpoint,
        Arc::new(endeavour_ida::HttpTransport::new(&host, port)),
    )?;

    repl.ida_client = Some(client);
    save_ida_endpoint(&normalized_endpoint)?;

    if let Some(function) = functions.first() {
        println!(
            "Connected to IDA at {normalized_endpoint}. Sample function: {} @ 0x{:x}",
            function.name, function.address
        );
    } else {
        println!("Connected to IDA at {normalized_endpoint}. No functions returned.");
    }

    Ok(())
}

pub(crate) fn handle_ida_status(repl: &Repl) -> Result<()> {
    let Some(client) = repl.ida_client.as_ref() else {
        println!("Not connected. Run: connect <host:port>");
        return Ok(());
    };

    let functions = repl
        .runtime
        .block_on(client.list_functions(None, Some(1)))
        .context("failed to query IDA status")?;

    if let Some(function) = functions.first() {
        println!(
            "IDA connection active (sample function: {} @ 0x{:x})",
            function.name, function.address
        );
    } else {
        println!("IDA connection active (no functions returned).");
    }

    Ok(())
}

pub(crate) fn parse_host_port(value: &str) -> Result<(String, u16)> {
    let trimmed = value.trim();
    let (host, port_text) = trimmed
        .rsplit_once(':')
        .with_context(|| format!("invalid host:port '{trimmed}'"))?;

    if host.is_empty() {
        return Err(anyhow::anyhow!("host must not be empty"));
    }

    let port = port_text
        .parse::<u16>()
        .with_context(|| format!("invalid port '{port_text}' in '{trimmed}'"))?;

    Ok((host.to_string(), port))
}

fn save_ida_endpoint(endpoint: &str) -> Result<()> {
    let path =
        PathBuf::from(std::env::var_os("HOME").context("HOME environment variable is not set")?)
            .join(".endeavour")
            .join("ida_endpoint");

    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("failed to create directory {}", parent.display()))?;
    }

    std::fs::write(&path, endpoint)
        .with_context(|| format!("failed to write IDA endpoint config at {}", path.display()))
}

pub(crate) fn connect_with_transport(
    runtime: &tokio::runtime::Runtime,
    endpoint: &str,
    transport: Arc<dyn Transport>,
) -> Result<(Arc<IdaClient>, Vec<endeavour_ida::FunctionInfo>)> {
    let (host, port) = parse_host_port(endpoint)?;
    let client = Arc::new(IdaClient::with_transport(&host, port, transport));

    let functions = runtime
        .block_on(client.list_functions(None, Some(1)))
        .with_context(|| format!("failed to connect to IDA at {host}:{port}"))?;

    Ok((client, functions))
}

#[cfg(test)]
mod tests {
    use super::connect_with_transport;
    use async_trait::async_trait;
    use endeavour_ida::{IdaClient, IdaError, Transport};
    use serde_json::{json, Value};
    use std::collections::VecDeque;
    use std::sync::{Arc, Mutex};

    struct MockTransport {
        responses: Mutex<VecDeque<std::result::Result<Value, IdaError>>>,
        calls: Mutex<Vec<(String, Value)>>,
    }

    impl MockTransport {
        fn new(responses: Vec<std::result::Result<Value, IdaError>>) -> Self {
            Self {
                responses: Mutex::new(responses.into()),
                calls: Mutex::new(Vec::new()),
            }
        }

        fn first_call_method(&self) -> Option<String> {
            let guard = self.calls.lock().ok()?;
            guard.first().map(|(method, _)| method.clone())
        }
    }

    #[async_trait]
    impl Transport for MockTransport {
        async fn call(
            &self,
            method: &str,
            params: Value,
        ) -> Result<Value, endeavour_ida::IdaError> {
            if let Ok(mut calls) = self.calls.lock() {
                calls.push((method.to_string(), params));
            }

            let mut queue = self.responses.lock().map_err(|_| {
                endeavour_ida::IdaError::IdaResponseError("mock lock poisoned".to_string())
            })?;

            queue.pop_front().unwrap_or_else(|| {
                Err(endeavour_ida::IdaError::IdaResponseError(
                    "no mock response queued".to_string(),
                ))
            })
        }
    }

    #[test]
    fn connect_commands_flow_uses_list_functions_with_mock_transport() {
        let runtime = tokio::runtime::Runtime::new();
        assert!(runtime.is_ok());
        let runtime = match runtime {
            Ok(value) => value,
            Err(err) => panic!("failed to create runtime: {err}"),
        };

        let mock = Arc::new(MockTransport::new(vec![Ok(json!([
            {
                "items": [
                    {"addr": "0x401000", "name": "sub_401000", "size": "0x10"}
                ],
                "cursor": {"done": true}
            }
        ]))]));

        let result = connect_with_transport(&runtime, "localhost:13337", mock.clone());
        assert!(result.is_ok());

        let method = mock.first_call_method();
        assert_eq!(method.as_deref(), Some("list_funcs"));

        let (client, functions) = match result {
            Ok(value) => value,
            Err(err) => panic!("unexpected error: {err}"),
        };

        let _typed: Arc<IdaClient> = client;
        assert_eq!(functions.len(), 1);
        assert_eq!(functions[0].name, "sub_401000");
    }
}
