#![allow(clippy::await_holding_lock)]

use std::io::{Read, Write};
use std::net::TcpListener;
use std::sync::{Mutex, OnceLock};
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use endeavour_cli::auth::anthropic::{parse_callback_code, AnthropicOAuthClient};
use endeavour_cli::auth::refresh::{ensure_fresh_token, AuthProvider};
use endeavour_cli::auth::resolver::{AuthStatus, CredentialResolver};
use endeavour_cli::auth::storage::{get_token, set_token, AuthMethod, TokenRecord};
use endeavour_core::config::Config;
use reqwest::Client;
use tempfile::TempDir;

mod auth {
    pub mod storage {
        pub use endeavour_cli::auth::storage::*;
    }

    pub fn test_env_lock() -> std::sync::MutexGuard<'static, ()> {
        super::env_lock()
    }
}

mod openai_harness {
    #![allow(clippy::items_after_test_module)]
    #![allow(dead_code)]

    include!("../src/auth/openai_auth.rs");

    pub async fn run_browser_login_with_mock<F>(
        token_url: &'static str,
        callback_addr: &'static str,
        redirect_uri: &'static str,
        callback_timeout: std::time::Duration,
        opener: F,
    ) -> Result<(), OpenAiOAuthError>
    where
        F: Fn(&str) -> Result<(), OpenAiOAuthError> + Send + Sync + 'static,
    {
        let config = AuthConfig {
            token_url,
            callback_addr,
            redirect_uri,
            callback_timeout,
            ..AuthConfig::default()
        };
        let opener: BrowserOpener = std::sync::Arc::new(opener);
        login_with_config(&config, false, opener).await
    }
}

fn env_lock() -> std::sync::MutexGuard<'static, ()> {
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(()))
        .lock()
        .expect("env lock")
}

fn set_auth_env(temp: &TempDir) {
    std::env::set_var("HOME", temp.path());
    std::env::set_var("XDG_CONFIG_HOME", temp.path());
}

fn clear_auth_env() {
    std::env::remove_var("HOME");
    std::env::remove_var("XDG_CONFIG_HOME");
    std::env::remove_var("ANTHROPIC_API_KEY");
    std::env::remove_var("OPENAI_API_KEY");
    std::env::remove_var("ENDEAVOUR_AUTH_REFRESH_ANTHROPIC_ENDPOINT");
    std::env::remove_var("ENDEAVOUR_AUTH_REFRESH_OPENAI_ENDPOINT");
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system time before unix epoch")
        .as_secs()
}

fn read_http_request(stream: &mut std::net::TcpStream) -> String {
    let mut buffer = Vec::new();
    let mut chunk = [0_u8; 2048];
    let mut header_end = None;
    let mut content_length = 0_usize;

    loop {
        let bytes_read = stream.read(&mut chunk).expect("read http request");
        if bytes_read == 0 {
            break;
        }

        buffer.extend_from_slice(&chunk[..bytes_read]);

        if header_end.is_none() {
            header_end = buffer.windows(4).position(|window| window == b"\r\n\r\n");
            if let Some(end) = header_end {
                let headers = std::str::from_utf8(&buffer[..end]).expect("utf8 headers");
                for line in headers.lines() {
                    if let Some((name, value)) = line.split_once(':') {
                        if name.eq_ignore_ascii_case("content-length") {
                            content_length = value.trim().parse::<usize>().expect("content-length");
                        }
                    }
                }
            }
        }

        if let Some(end) = header_end {
            let body_len = buffer.len().saturating_sub(end + 4);
            if body_len >= content_length {
                break;
            }
        }
    }

    String::from_utf8(buffer).expect("utf8 request")
}

#[tokio::test]
async fn oauth_integration_anthropic_code_paste_flow_exchanges_and_stores_token() {
    let _guard = env_lock();
    let temp = tempfile::tempdir().expect("tempdir");
    set_auth_env(&temp);

    let listener = TcpListener::bind("127.0.0.1:0").expect("bind mock server");
    let address = listener.local_addr().expect("mock server addr");
    let token_url = format!("http://{address}/v1/oauth/token");

    let server = thread::spawn(move || {
        let (mut stream, _) = listener.accept().expect("accept token exchange");
        let request = read_http_request(&mut stream);

        let body = r#"{"access_token":"at_abc123","refresh_token":"rt_xyz789","expires_in":3600}"#;
        let response = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
            body.len(),
            body
        );
        stream
            .write_all(response.as_bytes())
            .expect("write token exchange response");
        request
    });

    let client = AnthropicOAuthClient::with_endpoints(
        "9d1c250a-e61b-44d9-88ed-5944d1962f5e".to_string(),
        "https://claude.ai/oauth/authorize".to_string(),
        token_url,
        "https://console.anthropic.com/oauth/code/callback".to_string(),
        "org:create_api_key user:profile user:inference".to_string(),
    );

    let verifier = "pkce-verifier-123".to_string();
    let parsed =
        parse_callback_code("auth-code-1#pkce-verifier-123").expect("parse callback paste");
    assert_eq!(parsed.state, verifier);

    let exchanged = client
        .exchange_code_for_tokens(parsed.code, parsed.state, verifier)
        .await
        .expect("token exchange success");

    let expires_at = (unix_now() + exchanged.expires_in).to_string();
    set_token(
        "anthropic",
        TokenRecord {
            access_token: exchanged.access_token,
            refresh_token: exchanged.refresh_token,
            expires_at,
            method: AuthMethod::Oauth,
        },
    )
    .expect("persist anthropic token");

    let request = server.join().expect("join mock server");
    assert!(request.contains("POST /v1/oauth/token HTTP/1.1"));
    assert!(request.contains("\"grant_type\":\"authorization_code\""));
    assert!(request.contains("\"code\":\"auth-code-1\""));
    assert!(request.contains("\"state\":\"pkce-verifier-123\""));
    assert!(request.contains("\"code_verifier\":\"pkce-verifier-123\""));

    let stored = get_token("anthropic")
        .expect("read auth store")
        .expect("anthropic token record");
    assert_eq!(stored.access_token, "at_abc123");
    assert_eq!(stored.refresh_token, "rt_xyz789");
    assert_eq!(stored.method, AuthMethod::Oauth);

    clear_auth_env();
}

#[tokio::test]
async fn oauth_integration_openai_localhost_callback_flow_stores_token() {
    let _guard = env_lock();
    let temp = tempfile::tempdir().expect("tempdir");
    set_auth_env(&temp);

    let callback_probe = TcpListener::bind("127.0.0.1:0").expect("bind callback probe");
    let callback_port = callback_probe
        .local_addr()
        .expect("callback local addr")
        .port();
    drop(callback_probe);

    let token_listener = TcpListener::bind("127.0.0.1:0").expect("bind token server");
    let token_address = token_listener.local_addr().expect("token server addr");

    let token_server = thread::spawn(move || {
        let (mut stream, _) = token_listener.accept().expect("accept token request");
        let request = read_http_request(&mut stream);
        let body = r#"{"access_token":"at_gpt123","refresh_token":"rt_gpt789","expires_in":3600}"#;
        let response = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
            body.len(),
            body
        );
        stream
            .write_all(response.as_bytes())
            .expect("write token response");
        request
    });

    let token_url: &'static str =
        Box::leak(format!("http://{token_address}/oauth/token").into_boxed_str());
    let callback_addr: &'static str =
        Box::leak(format!("127.0.0.1:{callback_port}").into_boxed_str());
    let redirect_uri: &'static str =
        Box::leak(format!("http://127.0.0.1:{callback_port}/callback").into_boxed_str());

    openai_harness::run_browser_login_with_mock(
        token_url,
        callback_addr,
        redirect_uri,
        Duration::from_secs(5),
        move |authorize_url| {
            let state = authorize_url
                .split("state=")
                .nth(1)
                .and_then(|value| value.split('&').next())
                .expect("state query param");

            let mut callback_stream = None;
            for _ in 0..200 {
                match std::net::TcpStream::connect(callback_addr) {
                    Ok(stream) => {
                        callback_stream = Some(stream);
                        break;
                    }
                    Err(_) => thread::sleep(Duration::from_millis(25)),
                }
            }
            let mut callback_stream = callback_stream.expect("connect callback listener");
            let request = format!(
                "GET /callback?code=gpt_code_abc&state={state} HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n"
            );
            callback_stream
                .write_all(request.as_bytes())
                .expect("write callback request");
            Ok(())
        },
    )
    .await
    .expect("openai browser flow succeeds");

    let token_request = token_server.join().expect("join token server");
    assert!(token_request.contains("POST /oauth/token HTTP/1.1"));
    assert!(token_request.contains("grant_type=authorization_code"));
    assert!(token_request.contains("code=gpt_code_abc"));

    let stored = get_token("openai")
        .expect("read auth store")
        .expect("openai token record");
    assert_eq!(stored.access_token, "at_gpt123");
    assert_eq!(stored.refresh_token, "rt_gpt789");
    assert_eq!(stored.method, AuthMethod::Oauth);

    clear_auth_env();
}

#[test]
fn oauth_integration_token_storage_round_trip_and_permissions() {
    let _guard = env_lock();
    let temp = tempfile::tempdir().expect("tempdir");
    set_auth_env(&temp);

    let token = TokenRecord {
        access_token: "at_roundtrip_test".to_string(),
        refresh_token: "rt_roundtrip_test".to_string(),
        expires_at: (unix_now() + 3600).to_string(),
        method: AuthMethod::Oauth,
    };
    set_token("anthropic", token.clone()).expect("write token");

    let round_trip = get_token("anthropic")
        .expect("read token")
        .expect("token exists");
    assert_eq!(round_trip, token);

    let auth_path = temp.path().join("endeavour").join("auth.json");
    assert!(auth_path.exists());

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;

        let mode = std::fs::metadata(auth_path)
            .expect("auth metadata")
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o600);
    }

    clear_auth_env();
}

#[test]
fn oauth_integration_token_storage_corrupt_file_returns_error() {
    let _guard = env_lock();
    let temp = tempfile::tempdir().expect("tempdir");
    set_auth_env(&temp);

    let auth_dir = temp.path().join("endeavour");
    std::fs::create_dir_all(&auth_dir).expect("create auth dir");
    let auth_path = auth_dir.join("auth.json");
    std::fs::write(auth_path, "{not valid json").expect("write corrupt auth file");

    let result = get_token("anthropic");
    assert!(result.is_err());

    clear_auth_env();
}

#[tokio::test]
async fn oauth_integration_token_refresh_expired_token_triggers_refresh() {
    let _guard = env_lock();
    let temp = tempfile::tempdir().expect("tempdir");
    set_auth_env(&temp);

    let listener = TcpListener::bind("127.0.0.1:0").expect("bind refresh server");
    let address = listener.local_addr().expect("refresh server addr");
    let endpoint = format!("http://{address}");
    std::env::set_var("ENDEAVOUR_AUTH_REFRESH_ANTHROPIC_ENDPOINT", endpoint);

    let server = thread::spawn(move || {
        let (mut stream, _) = listener.accept().expect("accept refresh request");
        let request = read_http_request(&mut stream);
        let body = r#"{"access_token":"at_new123","refresh_token":"rt_new789","expires_in":3600}"#;
        let response = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
            body.len(),
            body
        );
        stream
            .write_all(response.as_bytes())
            .expect("write refresh response");
        request
    });

    let expired = TokenRecord {
        access_token: "old_access".to_string(),
        refresh_token: "old_refresh".to_string(),
        expires_at: "1".to_string(),
        method: AuthMethod::Oauth,
    };

    let refreshed = ensure_fresh_token(&Client::new(), AuthProvider::Anthropic, expired)
        .await
        .expect("refresh succeeds");
    assert_eq!(refreshed.access_token, "at_new123");
    assert_eq!(refreshed.refresh_token, "rt_new789");

    let request = server.join().expect("join refresh server");
    assert!(request.contains("grant_type=refresh_token"));
    assert!(request.contains("refresh_token=old_refresh"));

    let stored = get_token("anthropic")
        .expect("read persisted token")
        .expect("persisted token exists");
    assert_eq!(stored.access_token, "at_new123");
    assert_eq!(stored.refresh_token, "rt_new789");

    clear_auth_env();
}

#[tokio::test]
async fn oauth_integration_token_refresh_failure_returns_reauth_prompt() {
    let _guard = env_lock();
    let temp = tempfile::tempdir().expect("tempdir");
    set_auth_env(&temp);

    let listener = TcpListener::bind("127.0.0.1:0").expect("bind refresh error server");
    let address = listener.local_addr().expect("refresh error server addr");
    let endpoint = format!("http://{address}");
    std::env::set_var("ENDEAVOUR_AUTH_REFRESH_ANTHROPIC_ENDPOINT", endpoint);

    let server = thread::spawn(move || {
        let (mut stream, _) = listener.accept().expect("accept refresh request");
        let _request = read_http_request(&mut stream);
        let body = r#"{"error":"invalid_grant"}"#;
        let response = format!(
            "HTTP/1.1 400 Bad Request\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
            body.len(),
            body
        );
        stream
            .write_all(response.as_bytes())
            .expect("write refresh error response");
    });

    let expired = TokenRecord {
        access_token: "old_access".to_string(),
        refresh_token: "old_refresh".to_string(),
        expires_at: "1".to_string(),
        method: AuthMethod::Oauth,
    };
    set_token("anthropic", expired.clone()).expect("persist old token");

    let error = ensure_fresh_token(&Client::new(), AuthProvider::Anthropic, expired)
        .await
        .expect_err("refresh failure should return reauth");
    assert_eq!(
        error.user_prompt(),
        "● Auth expired for Claude. Run '/login claude' to re-authenticate."
    );

    server.join().expect("join refresh error server");

    let stored = get_token("anthropic")
        .expect("read stored token")
        .expect("stored token exists");
    assert_eq!(stored.access_token, "old_access");
    assert_eq!(stored.refresh_token, "old_refresh");

    clear_auth_env();
}

#[test]
fn oauth_integration_credential_resolver_oauth_priority_over_env_var() {
    let _guard = env_lock();
    let temp = tempfile::tempdir().expect("tempdir");
    set_auth_env(&temp);

    set_token(
        "anthropic",
        TokenRecord {
            access_token: "oauth-token".to_string(),
            refresh_token: "oauth-refresh".to_string(),
            expires_at: (unix_now() + 3600).to_string(),
            method: AuthMethod::Oauth,
        },
    )
    .expect("persist oauth token");
    std::env::set_var("ANTHROPIC_API_KEY", "sk-env-key");

    let resolved = CredentialResolver::new(Config::default())
        .resolve("anthropic")
        .expect("resolve anthropic credentials");
    assert_eq!(resolved.token.as_deref(), Some("oauth-token"));
    assert_eq!(resolved.auth_status, AuthStatus::Oauth);
    assert!(!resolved.should_prompt);

    clear_auth_env();
}

#[test]
fn oauth_integration_credential_resolver_env_fallback_when_no_oauth() {
    let _guard = env_lock();
    let temp = tempfile::tempdir().expect("tempdir");
    set_auth_env(&temp);

    std::env::set_var("OPENAI_API_KEY", "sk-openai-env");

    let resolved = CredentialResolver::new(Config::default())
        .resolve("openai")
        .expect("resolve openai credentials");
    assert_eq!(resolved.token.as_deref(), Some("sk-openai-env"));
    assert_eq!(resolved.auth_status, AuthStatus::ApiKey);
    assert!(!resolved.should_prompt);

    clear_auth_env();
}

#[test]
fn oauth_integration_credential_resolver_no_credential_prompts() {
    let _guard = env_lock();
    let temp = tempfile::tempdir().expect("tempdir");
    set_auth_env(&temp);

    let resolved = CredentialResolver::new(Config::default())
        .resolve("anthropic")
        .expect("resolve anthropic credentials");
    assert!(resolved.token.is_none());
    assert_eq!(resolved.auth_status, AuthStatus::None);
    assert!(resolved.should_prompt);

    clear_auth_env();
}
