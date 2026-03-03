use std::fmt;
use std::net::SocketAddr;
use std::process::Command;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use rand::RngCore;
use reqwest::Client;
use serde::Deserialize;
use sha2::{Digest, Sha256};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::sync::oneshot;

use crate::auth::storage::{set_token, AuthMethod, TokenRecord};

const OPENAI_PROVIDER_ID: &str = "openai";
const OPENAI_CLIENT_ID: &str = "app_EMoamEEZ73f0CkXaXp7hrann";
const OPENAI_AUTHORIZE_URL: &str = "https://auth.openai.com/oauth/authorize";
const OPENAI_TOKEN_URL: &str = "https://auth.openai.com/oauth/token";
const OPENAI_DEVICE_USERCODE_URL: &str = "https://auth.openai.com/api/accounts/deviceauth/usercode";
const OPENAI_DEVICE_TOKEN_URL: &str = "https://auth.openai.com/api/accounts/deviceauth/token";
const OPENAI_DEVICE_VERIFICATION_URL: &str = "https://auth.openai.com/codex/device";
const OPENAI_CALLBACK_ADDR: &str = "127.0.0.1:1455";
const OPENAI_CALLBACK_PATH: &str = "/callback";
const OPENAI_REDIRECT_URI: &str = "http://127.0.0.1:1455/callback";
const OPENAI_DEVICE_REDIRECT_URI: &str = "https://auth.openai.com/deviceauth/callback";
/// OpenAI OAuth sessions route compatible responses traffic through this endpoint.
pub const OPENAI_CODEX_REWRITE_ENDPOINT: &str = "https://chatgpt.com/backend-api/codex/responses";

/// OpenAI OAuth login error with user-facing message support.
#[derive(Debug)]
pub enum OpenAiOAuthError {
    /// Browser authorization was cancelled by the user.
    AuthorizationCancelled,
    /// Device flow timed out before approval.
    DeviceAuthorizationTimedOut,
    /// Any network or protocol-level failure.
    Other(String),
}

impl OpenAiOAuthError {
    /// Returns the exact user-facing error detail line.
    pub fn user_message(&self) -> &str {
        match self {
            Self::AuthorizationCancelled => "authorization cancelled",
            Self::DeviceAuthorizationTimedOut => "device authorization timed out",
            Self::Other(message) => message.as_str(),
        }
    }
}

impl fmt::Display for OpenAiOAuthError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.user_message())
    }
}

impl std::error::Error for OpenAiOAuthError {}

/// Executes OpenAI OAuth with browser PKCE and device-flow fallback.
pub async fn login(force_device_flow: bool) -> Result<(), OpenAiOAuthError> {
    let config = AuthConfig::default();
    let browser_opener: BrowserOpener = Arc::new(open_browser);
    login_with_config(&config, force_device_flow, browser_opener).await
}

type BrowserOpener = Arc<dyn Fn(&str) -> Result<(), OpenAiOAuthError> + Send + Sync>;

#[derive(Clone)]
struct AuthConfig {
    client_id: &'static str,
    authorize_url: &'static str,
    token_url: &'static str,
    device_usercode_url: &'static str,
    device_token_url: &'static str,
    callback_addr: &'static str,
    callback_path: &'static str,
    redirect_uri: &'static str,
    device_redirect_uri: &'static str,
    callback_timeout: Duration,
}

impl Default for AuthConfig {
    fn default() -> Self {
        Self {
            client_id: OPENAI_CLIENT_ID,
            authorize_url: OPENAI_AUTHORIZE_URL,
            token_url: OPENAI_TOKEN_URL,
            device_usercode_url: OPENAI_DEVICE_USERCODE_URL,
            device_token_url: OPENAI_DEVICE_TOKEN_URL,
            callback_addr: OPENAI_CALLBACK_ADDR,
            callback_path: OPENAI_CALLBACK_PATH,
            redirect_uri: OPENAI_REDIRECT_URI,
            device_redirect_uri: OPENAI_DEVICE_REDIRECT_URI,
            callback_timeout: Duration::from_secs(60),
        }
    }
}

#[derive(Debug, Deserialize)]
struct TokenResponse {
    access_token: String,
    refresh_token: String,
    expires_in: u64,
}

#[derive(Debug, Deserialize)]
struct DeviceUserCodeResponse {
    user_code: String,
    #[serde(default)]
    verification_uri: Option<String>,
    #[serde(default)]
    expires_in: Option<u64>,
    #[serde(default)]
    interval: Option<u64>,
}

#[derive(Debug, Deserialize)]
struct DeviceTokenPendingResponse {
    #[serde(default)]
    error: Option<String>,
}

#[derive(Debug, Deserialize)]
struct DeviceTokenApprovedResponse {
    authorization_code: String,
    code_verifier: String,
}

#[derive(Debug)]
struct CallbackPayload {
    code: String,
}

async fn login_with_config(
    config: &AuthConfig,
    force_device_flow: bool,
    browser_opener: BrowserOpener,
) -> Result<(), OpenAiOAuthError> {
    let client = Client::new();
    if force_device_flow {
        return run_device_flow(&client, config).await;
    }

    match run_browser_pkce_flow(&client, config, browser_opener).await {
        Ok(()) => Ok(()),
        Err(OpenAiOAuthError::Other(message)) if message == "browser unavailable" => {
            println!("Could not open a browser. Switching to device flow...");
            run_device_flow(&client, config).await
        }
        Err(err) => Err(err),
    }
}

async fn run_browser_pkce_flow(
    client: &Client,
    config: &AuthConfig,
    browser_opener: BrowserOpener,
) -> Result<(), OpenAiOAuthError> {
    let pkce_verifier = generate_code_verifier();
    let pkce_challenge = code_challenge_from_verifier(&pkce_verifier);
    let state = generate_state_token();

    let (callback_tx, callback_rx) =
        oneshot::channel::<Result<CallbackPayload, OpenAiOAuthError>>();
    let callback_addr = config
        .callback_addr
        .parse::<SocketAddr>()
        .map_err(|error| {
            OpenAiOAuthError::Other(format!(
                "invalid callback address '{}': {error}",
                config.callback_addr
            ))
        })?;
    let listener = TcpListener::bind(callback_addr).await.map_err(|error| {
        OpenAiOAuthError::Other(format!("failed to bind callback server: {error}"))
    })?;

    let callback_path = config.callback_path.to_string();
    let expected_state = state.clone();
    let callback_handle = tokio::spawn(async move {
        let result = wait_for_callback(listener, &callback_path, &expected_state).await;
        let _ = callback_tx.send(result);
    });

    let authorize_url = format!(
        "{}?client_id={}&response_type=code&redirect_uri={}&scope={}&code_challenge={}&code_challenge_method=S256&state={}",
        config.authorize_url,
        url_escape_component(config.client_id),
        url_escape_component(config.redirect_uri),
        url_escape_component("openid profile email offline_access"),
        url_escape_component(&pkce_challenge),
        url_escape_component(&state)
    );

    (browser_opener)(&authorize_url)?;
    println!("Waiting for authorization in browser... (Ctrl+C to cancel)");

    let callback = tokio::select! {
        result = callback_rx => {
            result
                .map_err(|_| OpenAiOAuthError::AuthorizationCancelled)?
                .map_err(|_| OpenAiOAuthError::AuthorizationCancelled)?
        }
        _ = tokio::time::sleep(config.callback_timeout) => {
            callback_handle.abort();
            return Err(OpenAiOAuthError::AuthorizationCancelled);
        }
    };

    let token = exchange_authorization_code(
        client,
        config.token_url,
        config.client_id,
        &callback.code,
        config.redirect_uri,
        &pkce_verifier,
    )
    .await?;
    persist_token(token)
}

async fn run_device_flow(client: &Client, config: &AuthConfig) -> Result<(), OpenAiOAuthError> {
    println!("Authenticating with OpenAI GPT (device flow)...");

    let start = client
        .post(config.device_usercode_url)
        .form(&[("client_id", config.client_id)])
        .send()
        .await
        .map_err(|error| {
            OpenAiOAuthError::Other(format!("failed to request device code: {error}"))
        })?
        .error_for_status()
        .map_err(|error| {
            OpenAiOAuthError::Other(format!("failed to request device code: {error}"))
        })?
        .json::<DeviceUserCodeResponse>()
        .await
        .map_err(|error| {
            OpenAiOAuthError::Other(format!("failed to parse device code response: {error}"))
        })?;

    let verification_uri = start
        .verification_uri
        .unwrap_or_else(|| OPENAI_DEVICE_VERIFICATION_URL.to_string());
    println!("Visit this URL and enter the code shown below:\n");
    println!("  URL:  {verification_uri}");
    println!("  Code: {}\n", start.user_code);
    println!("Waiting for authorization... (Ctrl+C to cancel)");

    let poll_interval = Duration::from_secs(start.interval.unwrap_or(5).max(1));
    let timeout = Duration::from_secs(start.expires_in.unwrap_or(600));
    let started_at = std::time::Instant::now();

    let device_exchange = loop {
        if started_at.elapsed() >= timeout {
            return Err(OpenAiOAuthError::DeviceAuthorizationTimedOut);
        }

        let response = client
            .post(config.device_token_url)
            .form(&[
                ("client_id", config.client_id),
                ("user_code", start.user_code.as_str()),
            ])
            .send()
            .await
            .map_err(|error| {
                OpenAiOAuthError::Other(format!(
                    "network error while waiting for authorization: {error}"
                ))
            })?;

        let body = response.text().await.map_err(|error| {
            OpenAiOAuthError::Other(format!("failed to read device poll response: {error}"))
        })?;
        if let Ok(approved) = serde_json::from_str::<DeviceTokenApprovedResponse>(&body) {
            break approved;
        }

        let pending =
            serde_json::from_str::<DeviceTokenPendingResponse>(&body).map_err(|error| {
                OpenAiOAuthError::Other(format!("failed to parse device poll response: {error}"))
            })?;

        match pending.error.as_deref() {
            Some("authorization_pending") => tokio::time::sleep(poll_interval).await,
            Some("slow_down") => tokio::time::sleep(poll_interval + Duration::from_secs(1)).await,
            Some("expired_token") => return Err(OpenAiOAuthError::DeviceAuthorizationTimedOut),
            Some("access_denied") => return Err(OpenAiOAuthError::AuthorizationCancelled),
            Some(other) => {
                return Err(OpenAiOAuthError::Other(format!(
                    "device authorization failed: {other}"
                )))
            }
            None => {
                return Err(OpenAiOAuthError::Other(
                    "device authorization failed: unknown response".to_string(),
                ))
            }
        }
    };

    let token = exchange_authorization_code(
        client,
        config.token_url,
        config.client_id,
        &device_exchange.authorization_code,
        config.device_redirect_uri,
        &device_exchange.code_verifier,
    )
    .await?;

    persist_token(token)
}

async fn exchange_authorization_code(
    client: &Client,
    token_url: &str,
    client_id: &str,
    code: &str,
    redirect_uri: &str,
    code_verifier: &str,
) -> Result<TokenResponse, OpenAiOAuthError> {
    client
        .post(token_url)
        .form(&[
            ("grant_type", "authorization_code"),
            ("code", code),
            ("redirect_uri", redirect_uri),
            ("client_id", client_id),
            ("code_verifier", code_verifier),
        ])
        .send()
        .await
        .map_err(|error| OpenAiOAuthError::Other(format!("token exchange failed: {error}")))?
        .error_for_status()
        .map_err(|error| OpenAiOAuthError::Other(format!("token exchange failed: {error}")))?
        .json::<TokenResponse>()
        .await
        .map_err(|error| {
            OpenAiOAuthError::Other(format!("failed to parse token response: {error}"))
        })
}

fn persist_token(token: TokenResponse) -> Result<(), OpenAiOAuthError> {
    let expires_at = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|error| {
            OpenAiOAuthError::Other(format!("failed to compute token expiry: {error}"))
        })?
        .as_secs()
        .saturating_add(token.expires_in)
        .to_string();

    set_token(
        OPENAI_PROVIDER_ID,
        TokenRecord {
            access_token: token.access_token,
            refresh_token: token.refresh_token,
            expires_at,
            method: AuthMethod::Oauth,
        },
    )
    .map_err(|error| OpenAiOAuthError::Other(format!("failed to persist token: {error}")))
}

async fn wait_for_callback(
    listener: TcpListener,
    callback_path: &str,
    expected_state: &str,
) -> Result<CallbackPayload, OpenAiOAuthError> {
    let (mut stream, _) = listener.accept().await.map_err(|error| {
        OpenAiOAuthError::Other(format!("failed to accept callback request: {error}"))
    })?;

    let mut buffer = [0_u8; 8192];
    let bytes_read = stream.read(&mut buffer).await.map_err(|error| {
        OpenAiOAuthError::Other(format!("failed to read callback request: {error}"))
    })?;
    let request = String::from_utf8_lossy(&buffer[..bytes_read]);
    let request_line = request
        .lines()
        .next()
        .ok_or_else(|| OpenAiOAuthError::Other("invalid callback request".to_string()))?;

    let mut parts = request_line.split_whitespace();
    let method = parts.next().unwrap_or("");
    let target = parts.next().unwrap_or("");

    if method != "GET" {
        write_response(
            &mut stream,
            "405 Method Not Allowed",
            "<html><body>Method not allowed.</body></html>",
        )
        .await?;
        return Err(OpenAiOAuthError::AuthorizationCancelled);
    }

    let (path, query) = target.split_once('?').unwrap_or((target, ""));
    if path != callback_path {
        write_response(
            &mut stream,
            "404 Not Found",
            "<html><body>Not found.</body></html>",
        )
        .await?;
        return Err(OpenAiOAuthError::AuthorizationCancelled);
    }

    let query_params = parse_query_string(query);
    if let Some(error) = query_params.get("error") {
        write_response(
            &mut stream,
            "200 OK",
            "<html><body>Authorization cancelled. You can return to endeavour.</body></html>",
        )
        .await?;
        if error == "access_denied" {
            return Err(OpenAiOAuthError::AuthorizationCancelled);
        }
        return Err(OpenAiOAuthError::Other(format!(
            "authorization failed: {error}"
        )));
    }

    let code = query_params.get("code").cloned().ok_or_else(|| {
        OpenAiOAuthError::Other("authorization code missing from callback".to_string())
    })?;
    let state = query_params.get("state").cloned().ok_or_else(|| {
        OpenAiOAuthError::Other("authorization state missing from callback".to_string())
    })?;

    if state != expected_state {
        write_response(
            &mut stream,
            "400 Bad Request",
            "<html><body>State mismatch. Close this tab and retry.</body></html>",
        )
        .await?;
        return Err(OpenAiOAuthError::Other(
            "authorization failed: security check failed".to_string(),
        ));
    }

    write_response(
        &mut stream,
        "200 OK",
        "<html><body>Authorization complete. You can return to endeavour.</body></html>",
    )
    .await?;

    Ok(CallbackPayload { code })
}

async fn write_response(
    stream: &mut tokio::net::TcpStream,
    status: &str,
    body: &str,
) -> Result<(), OpenAiOAuthError> {
    let response = format!(
        "HTTP/1.1 {status}\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        body.len(),
        body
    );
    stream
        .write_all(response.as_bytes())
        .await
        .map_err(|error| {
            OpenAiOAuthError::Other(format!("failed to write callback response: {error}"))
        })
}

fn open_browser(url: &str) -> Result<(), OpenAiOAuthError> {
    let spawn_result = if cfg!(target_os = "macos") {
        Command::new("open").arg(url).status()
    } else if cfg!(target_os = "windows") {
        Command::new("cmd").args(["/C", "start", "", url]).status()
    } else {
        Command::new("xdg-open").arg(url).status()
    };

    match spawn_result {
        Ok(status) if status.success() => Ok(()),
        Ok(_) | Err(_) => Err(OpenAiOAuthError::Other("browser unavailable".to_string())),
    }
}

fn generate_code_verifier() -> String {
    let mut bytes = [0_u8; 64];
    rand::rng().fill_bytes(&mut bytes);
    URL_SAFE_NO_PAD.encode(bytes)
}

fn generate_state_token() -> String {
    let mut bytes = [0_u8; 32];
    rand::rng().fill_bytes(&mut bytes);
    URL_SAFE_NO_PAD.encode(bytes)
}

fn code_challenge_from_verifier(verifier: &str) -> String {
    let digest = Sha256::digest(verifier.as_bytes());
    URL_SAFE_NO_PAD.encode(digest)
}

fn url_escape_component(value: &str) -> String {
    let mut encoded = String::with_capacity(value.len());
    for byte in value.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                encoded.push(char::from(byte))
            }
            b' ' => encoded.push_str("%20"),
            _ => {
                let _ = fmt::Write::write_fmt(&mut encoded, format_args!("%{byte:02X}"));
            }
        }
    }
    encoded
}

fn parse_query_string(query: &str) -> std::collections::HashMap<String, String> {
    let mut values = std::collections::HashMap::new();
    for pair in query.split('&').filter(|segment| !segment.is_empty()) {
        let (key, value) = pair.split_once('=').unwrap_or((pair, ""));
        values.insert(percent_decode(key), percent_decode(value));
    }
    values
}

fn percent_decode(input: &str) -> String {
    let mut output = String::with_capacity(input.len());
    let bytes = input.as_bytes();
    let mut index = 0;
    while index < bytes.len() {
        match bytes[index] {
            b'+' => {
                output.push(' ');
                index += 1;
            }
            b'%' if index + 2 < bytes.len() => {
                let h1 = bytes[index + 1] as char;
                let h2 = bytes[index + 2] as char;
                if let (Some(a), Some(b)) = (h1.to_digit(16), h2.to_digit(16)) {
                    output.push(char::from((a * 16 + b) as u8));
                    index += 3;
                } else {
                    output.push('%');
                    index += 1;
                }
            }
            value => {
                output.push(char::from(value));
                index += 1;
            }
        }
    }
    output
}

#[cfg(test)]
mod tests {
    use std::io::{Read, Write};
    use std::net::TcpListener as StdTcpListener;
    use std::sync::atomic::{AtomicU32, Ordering};
    use std::sync::Arc;
    use std::thread;

    use super::{
        code_challenge_from_verifier, login_with_config, parse_query_string, AuthConfig,
        BrowserOpener, DeviceTokenApprovedResponse, DeviceUserCodeResponse, OpenAiOAuthError,
    };
    use crate::auth::storage::get_token;

    fn config_with_base_urls(
        device_url: &'static str,
        device_token: &'static str,
        token_url: &'static str,
    ) -> AuthConfig {
        AuthConfig {
            device_usercode_url: device_url,
            device_token_url: device_token,
            token_url,
            callback_timeout: std::time::Duration::from_secs(5),
            ..AuthConfig::default()
        }
    }

    fn run_mock_server<F>(handler: F) -> String
    where
        F: Fn(String, String) -> String + Send + Sync + 'static,
    {
        let listener = StdTcpListener::bind("127.0.0.1:0").expect("bind mock server");
        let addr = listener.local_addr().expect("mock server addr");
        let handler = std::sync::Arc::new(handler);
        thread::spawn(move || {
            for stream in listener.incoming().take(4) {
                let mut stream = stream.expect("incoming stream");
                let mut bytes = [0_u8; 8192];
                let len = stream.read(&mut bytes).expect("read request");
                let request = String::from_utf8_lossy(&bytes[..len]).to_string();
                let mut lines = request.lines();
                let request_line = lines.next().unwrap_or("");
                let target = request_line.split_whitespace().nth(1).unwrap_or("/");
                let body = request.split("\r\n\r\n").nth(1).unwrap_or("").to_string();
                let payload = handler(target.to_string(), body);
                stream
                    .write_all(payload.as_bytes())
                    .expect("write response");
            }
        });
        format!("http://{addr}")
    }

    fn http_ok_json(body: &str) -> String {
        format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
            body.len(),
            body
        )
    }

    #[test]
    fn pkce_challenge_matches_rfc_vector() {
        let verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
        let expected = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";
        assert_eq!(code_challenge_from_verifier(verifier), expected);
    }

    #[test]
    fn device_flow_response_parsing_handles_optional_fields() {
        let parsed: DeviceUserCodeResponse = serde_json::from_str(
            r#"{"user_code":"ABCD-1234","verification_uri":"https://auth.openai.com/codex/device","expires_in":600,"interval":5}"#,
        )
        .expect("parse device usercode response");
        assert_eq!(parsed.user_code, "ABCD-1234");
        assert_eq!(
            parsed.verification_uri.as_deref(),
            Some("https://auth.openai.com/codex/device")
        );
        assert_eq!(parsed.expires_in, Some(600));
        assert_eq!(parsed.interval, Some(5));

        let approved: DeviceTokenApprovedResponse = serde_json::from_str(
            r#"{"authorization_code":"authz_code","code_verifier":"server_verifier"}"#,
        )
        .expect("parse approved device token payload");
        assert_eq!(approved.authorization_code, "authz_code");
        assert_eq!(approved.code_verifier, "server_verifier");
    }

    #[test]
    fn query_string_parser_decodes_values() {
        let parsed = parse_query_string("code=a%2Fb&state=xyz+123");
        assert_eq!(parsed.get("code").map(String::as_str), Some("a/b"));
        assert_eq!(parsed.get("state").map(String::as_str), Some("xyz 123"));
    }

    #[tokio::test]
    #[allow(clippy::await_holding_lock)]
    async fn device_flow_exchanges_and_persists_token_with_mock_endpoints() {
        let _guard = crate::auth::test_env_lock();
        let temp = tempfile::tempdir().expect("tempdir");
        std::env::set_var("XDG_CONFIG_HOME", temp.path());
        std::env::set_var("HOME", temp.path());

        let poll_count = Arc::new(AtomicU32::new(0));
        let poll_count_clone = Arc::clone(&poll_count);
        let server = run_mock_server(move |target, body| {
            if target == "/deviceauth/usercode" {
                return http_ok_json(
                    r#"{"user_code":"ABCD-1234","verification_uri":"https://auth.openai.com/codex/device","expires_in":30,"interval":1}"#,
                );
            }
            if target == "/deviceauth/token" {
                let current = poll_count_clone.fetch_add(1, Ordering::SeqCst) + 1;
                if current == 1 {
                    return http_ok_json(r#"{"error":"authorization_pending"}"#);
                }
                return http_ok_json(
                    r#"{"authorization_code":"device_auth_code","code_verifier":"server_verifier"}"#,
                );
            }
            if target == "/oauth/token" {
                assert!(body.contains("grant_type=authorization_code"));
                assert!(body.contains("code=device_auth_code"));
                assert!(body.contains("code_verifier=server_verifier"));
                return http_ok_json(
                    r#"{"access_token":"access_123","refresh_token":"refresh_123","expires_in":3600}"#,
                );
            }
            http_ok_json(r#"{"error":"unexpected_path"}"#)
        });

        let device_url = Box::leak(format!("{server}/deviceauth/usercode").into_boxed_str());
        let device_token = Box::leak(format!("{server}/deviceauth/token").into_boxed_str());
        let token_url = Box::leak(format!("{server}/oauth/token").into_boxed_str());
        let config = config_with_base_urls(device_url, device_token, token_url);

        let opener: BrowserOpener =
            Arc::new(|_| Err(OpenAiOAuthError::Other("browser unavailable".to_string())));
        login_with_config(&config, true, opener)
            .await
            .expect("device flow login should succeed");

        let stored = get_token("openai").expect("read token from auth store");
        assert!(stored.is_some());
        let record = stored.expect("token record");
        assert_eq!(record.access_token, "access_123");
        assert_eq!(record.refresh_token, "refresh_123");
        assert_eq!(record.method, crate::auth::storage::AuthMethod::Oauth);
        assert!(record.expires_at.parse::<u64>().is_ok());

        std::env::remove_var("XDG_CONFIG_HOME");
        std::env::remove_var("HOME");
    }

    #[tokio::test]
    #[allow(clippy::await_holding_lock)]
    async fn browser_pkce_callback_exchanges_and_persists_token_with_mock_endpoint() {
        let _guard = crate::auth::test_env_lock();
        let temp = tempfile::tempdir().expect("tempdir");
        std::env::set_var("XDG_CONFIG_HOME", temp.path());
        std::env::set_var("HOME", temp.path());

        let callback_probe = StdTcpListener::bind("127.0.0.1:0").expect("bind callback probe");
        let callback_port = callback_probe
            .local_addr()
            .expect("callback probe local addr")
            .port();
        drop(callback_probe);

        let server = run_mock_server(move |target, body| {
            if target == "/oauth/token" {
                assert!(body.contains("grant_type=authorization_code"));
                assert!(body.contains("code=browser_auth_code"));
                let expected_redirect =
                    format!("redirect_uri=http%3A%2F%2F127.0.0.1%3A{callback_port}%2Fcallback");
                assert!(body.contains(expected_redirect.as_str()));
                return http_ok_json(
                    r#"{"access_token":"browser_access","refresh_token":"browser_refresh","expires_in":3600}"#,
                );
            }
            http_ok_json(r#"{"error":"unexpected_path"}"#)
        });

        let token_url = Box::leak(format!("{server}/oauth/token").into_boxed_str());
        let callback_addr: &'static str =
            Box::leak(format!("127.0.0.1:{callback_port}").into_boxed_str());
        let redirect_uri: &'static str =
            Box::leak(format!("http://127.0.0.1:{callback_port}/callback").into_boxed_str());
        let config = AuthConfig {
            token_url,
            callback_addr,
            redirect_uri,
            callback_timeout: std::time::Duration::from_secs(5),
            ..AuthConfig::default()
        };

        let opener: BrowserOpener = Arc::new(move |url| {
            let parsed_state = url
                .split("state=")
                .nth(1)
                .and_then(|value| value.split('&').next())
                .unwrap_or("");
            let mut stream = None;
            for _ in 0..200 {
                match std::net::TcpStream::connect(callback_addr) {
                    Ok(connected) => {
                        stream = Some(connected);
                        break;
                    }
                    Err(_) => std::thread::sleep(std::time::Duration::from_millis(25)),
                }
            }
            let mut stream = stream.ok_or_else(|| {
                OpenAiOAuthError::Other("failed to connect callback server: timeout".to_string())
            })?;
            let request = format!(
                "GET /callback?code=browser_auth_code&state={parsed_state} HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n"
            );
            stream.write_all(request.as_bytes()).map_err(|error| {
                OpenAiOAuthError::Other(format!("failed to write callback request: {error}"))
            })?;
            Ok(())
        });

        login_with_config(&config, false, opener)
            .await
            .expect("browser flow login should succeed");

        let stored = get_token("openai").expect("read token from auth store");
        assert!(stored.is_some());
        let record = stored.expect("token record");
        assert_eq!(record.access_token, "browser_access");
        assert_eq!(record.refresh_token, "browser_refresh");
        assert_eq!(record.method, crate::auth::storage::AuthMethod::Oauth);
        assert!(record.expires_at.parse::<u64>().is_ok());

        std::env::remove_var("XDG_CONFIG_HOME");
        std::env::remove_var("HOME");
    }
}
