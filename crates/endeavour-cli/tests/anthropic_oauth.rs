use std::io::{Read, Write};
use std::net::TcpListener;
use std::thread;

use endeavour_cli::auth::anthropic::AnthropicOAuthClient;

#[tokio::test]
async fn token_exchange_uses_expected_payload_and_parses_response() -> anyhow::Result<()> {
    let listener = TcpListener::bind("127.0.0.1:0")?;
    let address = listener.local_addr()?;
    let token_url = format!("http://{address}/v1/oauth/token");

    let server = thread::spawn(move || -> anyhow::Result<String> {
        let (mut stream, _) = listener.accept()?;
        let request = read_http_request(&mut stream)?;

        let response_body =
            r#"{"access_token":"access-123","refresh_token":"refresh-456","expires_in":3600}"#;
        let response = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
            response_body.len(),
            response_body
        );
        stream.write_all(response.as_bytes())?;
        Ok(request)
    });

    let client = AnthropicOAuthClient::with_endpoints(
        "9d1c250a-e61b-44d9-88ed-5944d1962f5e".to_string(),
        "https://claude.ai/oauth/authorize".to_string(),
        token_url,
        "https://console.anthropic.com/oauth/code/callback".to_string(),
        "org:create_api_key user:profile user:inference".to_string(),
    );

    let result = client
        .exchange_code_for_tokens(
            "auth-code-1".to_string(),
            "verifier-1".to_string(),
            "verifier-1".to_string(),
        )
        .await?;

    assert_eq!(result.access_token, "access-123");
    assert_eq!(result.refresh_token, "refresh-456");
    assert_eq!(result.expires_in, 3600);

    let request = server
        .join()
        .map_err(|_| anyhow::anyhow!("server thread panicked"))??;
    assert!(request.contains("POST /v1/oauth/token HTTP/1.1"));
    assert!(request.contains("\"grant_type\":\"authorization_code\""));
    assert!(request.contains("\"code\":\"auth-code-1\""));
    assert!(request.contains("\"state\":\"verifier-1\""));
    assert!(request.contains("\"client_id\":\"9d1c250a-e61b-44d9-88ed-5944d1962f5e\""));
    assert!(request.contains("\"code_verifier\":\"verifier-1\""));

    Ok(())
}

fn read_http_request(stream: &mut std::net::TcpStream) -> anyhow::Result<String> {
    let mut buffer = Vec::new();
    let mut chunk = [0u8; 2048];
    let mut header_end = None;
    let mut content_length = 0usize;

    loop {
        let bytes_read = stream.read(&mut chunk)?;
        if bytes_read == 0 {
            break;
        }

        buffer.extend_from_slice(&chunk[..bytes_read]);

        if header_end.is_none() {
            header_end = find_header_end(&buffer);
            if let Some(end) = header_end {
                let headers = std::str::from_utf8(&buffer[..end])?;
                content_length = parse_content_length(headers)?;
            }
        }

        if let Some(end) = header_end {
            let body_len = buffer.len().saturating_sub(end + 4);
            if body_len >= content_length {
                break;
            }
        }
    }

    String::from_utf8(buffer).map_err(anyhow::Error::from)
}

fn find_header_end(buffer: &[u8]) -> Option<usize> {
    buffer.windows(4).position(|window| window == b"\r\n\r\n")
}

fn parse_content_length(headers: &str) -> anyhow::Result<usize> {
    for line in headers.lines() {
        if let Some((name, value)) = line.split_once(':') {
            if name.eq_ignore_ascii_case("content-length") {
                let parsed = value.trim().parse::<usize>()?;
                return Ok(parsed);
            }
        }
    }
    Ok(0)
}
