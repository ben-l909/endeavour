use std::fmt::{Display, Formatter};
use std::time::{SystemTime, UNIX_EPOCH};

use reqwest::Client;
use serde::{Deserialize, Serialize};

use crate::auth::storage::{set_token, AuthMethod, TokenRecord};

const OPENAI_CLIENT_ID: &str = "app_EMoamEEZ73f0CkXaXp7hrann";
const ANTHROPIC_CLIENT_ID: &str = "9d1c250a-e61b-44d9-88ed-5944d1962f5e";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthProvider {
    Anthropic,
    OpenAi,
}

impl AuthProvider {
    pub fn id(self) -> &'static str {
        match self {
            Self::Anthropic => "anthropic",
            Self::OpenAi => "openai",
        }
    }

    pub fn ux_name(self) -> &'static str {
        match self {
            Self::Anthropic => "Claude",
            Self::OpenAi => "GPT",
        }
    }

    pub fn login_slug(self) -> &'static str {
        match self {
            Self::Anthropic => "claude",
            Self::OpenAi => "gpt",
        }
    }

    fn token_url(self) -> String {
        let env_key = match self {
            Self::Anthropic => "ENDEAVOUR_AUTH_REFRESH_ANTHROPIC_ENDPOINT",
            Self::OpenAi => "ENDEAVOUR_AUTH_REFRESH_OPENAI_ENDPOINT",
        };
        if let Ok(value) = std::env::var(env_key) {
            if !value.trim().is_empty() {
                return value;
            }
        }
        match self {
            Self::Anthropic => "https://console.anthropic.com/v1/oauth/token".to_string(),
            Self::OpenAi => "https://auth.openai.com/oauth/token".to_string(),
        }
    }

    fn client_id(self) -> &'static str {
        match self {
            Self::Anthropic => ANTHROPIC_CLIENT_ID,
            Self::OpenAi => OPENAI_CLIENT_ID,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RefreshAuthExpired {
    provider: AuthProvider,
}

impl RefreshAuthExpired {
    pub fn new(provider: AuthProvider) -> Self {
        Self { provider }
    }

    pub fn user_prompt(&self) -> String {
        format!(
            "● Auth expired for {}. Run '/login {}' to re-authenticate.",
            self.provider.ux_name(),
            self.provider.login_slug()
        )
    }
}

impl Display for RefreshAuthExpired {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.user_prompt())
    }
}

impl std::error::Error for RefreshAuthExpired {}

#[derive(Debug, Deserialize)]
struct RefreshResponse {
    access_token: String,
    #[serde(default)]
    refresh_token: Option<String>,
    expires_in: u64,
}

#[derive(Debug, Serialize)]
struct RefreshRequest<'a> {
    grant_type: &'a str,
    refresh_token: &'a str,
    client_id: &'a str,
}

pub fn is_expired(expires_at: &str, now_unix_seconds: u64) -> bool {
    match expires_at.trim().parse::<u64>() {
        Ok(value) => value <= now_unix_seconds,
        Err(_) => true,
    }
}

pub async fn ensure_fresh_token(
    http: &Client,
    provider: AuthProvider,
    record: TokenRecord,
) -> Result<TokenRecord, RefreshAuthExpired> {
    if record.method == AuthMethod::ApiKey {
        return Ok(record);
    }

    let now = current_unix_seconds().map_err(|_| RefreshAuthExpired::new(provider))?;
    if !is_expired(&record.expires_at, now) {
        return Ok(record);
    }

    let refreshed = refresh_with_http(http, provider, &record.refresh_token)
        .await
        .map_err(|_| RefreshAuthExpired::new(provider))?;

    set_token(provider.id(), refreshed.clone()).map_err(|_| RefreshAuthExpired::new(provider))?;
    Ok(refreshed)
}

async fn refresh_with_http(
    http: &Client,
    provider: AuthProvider,
    refresh_token: &str,
) -> Result<TokenRecord, reqwest::Error> {
    let payload = RefreshRequest {
        grant_type: "refresh_token",
        refresh_token,
        client_id: provider.client_id(),
    };
    let response = http
        .post(provider.token_url())
        .form(&payload)
        .send()
        .await?
        .error_for_status()?
        .json::<RefreshResponse>()
        .await?;
    Ok(TokenRecord {
        access_token: response.access_token,
        refresh_token: response
            .refresh_token
            .filter(|token| !token.is_empty())
            .unwrap_or_else(|| refresh_token.to_string()),
        expires_at: current_unix_seconds()
            .unwrap_or(0)
            .saturating_add(response.expires_in)
            .to_string(),
        method: AuthMethod::Oauth,
    })
}

fn current_unix_seconds() -> Result<u64, std::time::SystemTimeError> {
    Ok(SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs())
}

#[cfg(test)]
mod tests {
    use std::io::{Read, Write};
    use std::net::TcpListener as StdTcpListener;
    use std::sync::{Mutex, OnceLock};
    use std::thread;

    use reqwest::Client;

    use super::{is_expired, AuthProvider, RefreshAuthExpired};
    use crate::auth::refresh::ensure_fresh_token;
    use crate::auth::storage::{get_token, AuthMethod, TokenRecord};

    fn env_lock() -> std::sync::MutexGuard<'static, ()> {
        static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
        LOCK.get_or_init(|| Mutex::new(()))
            .lock()
            .expect("env lock")
    }

    #[test]
    fn expiry_detection_uses_epoch_seconds() {
        assert!(is_expired("5", 5));
        assert!(is_expired("4", 5));
        assert!(!is_expired("6", 5));
        assert!(is_expired("not-a-timestamp", 5));
    }

    #[tokio::test]
    async fn api_key_tokens_are_never_refreshed() {
        let _guard = env_lock();
        let client = Client::new();
        let record = TokenRecord {
            access_token: "sk-live".to_string(),
            refresh_token: "ignored".to_string(),
            expires_at: "0".to_string(),
            method: AuthMethod::ApiKey,
        };

        let resolved = ensure_fresh_token(&client, AuthProvider::OpenAi, record.clone())
            .await
            .expect("api key records should bypass refresh");
        assert_eq!(resolved, record);
    }

    #[tokio::test]
    async fn refresh_failure_returns_reauth_prompt() {
        let _guard = env_lock();
        let listener = StdTcpListener::bind("127.0.0.1:0").expect("bind mock server");
        let addr = listener.local_addr().expect("mock server addr");
        thread::spawn(move || {
            if let Ok((mut stream, _)) = listener.accept() {
                let mut bytes = [0_u8; 4096];
                let _ = stream.read(&mut bytes);
                let body = "{\"error\":\"invalid_grant\"}";
                let response = format!(
                    "HTTP/1.1 400 Bad Request\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    body.len(),
                    body
                );
                let _ = stream.write_all(response.as_bytes());
            }
        });

        let provider = AuthProvider::OpenAi;
        let prompt = RefreshAuthExpired::new(provider).user_prompt();
        assert_eq!(
            prompt,
            "● Auth expired for GPT. Run '/login gpt' to re-authenticate."
        );

        let client = Client::new();
        let payload = [
            ("grant_type", "refresh_token"),
            ("refresh_token", "rt_invalid"),
            ("client_id", "app_EMoamEEZ73f0CkXaXp7hrann"),
        ];
        let res = client
            .post(format!("http://{addr}"))
            .form(&payload)
            .send()
            .await
            .expect("request should reach mock server");
        assert_eq!(res.status().as_u16(), 400);
    }

    #[tokio::test]
    async fn mock_refresh_endpoint_updates_token_record() {
        let _guard = env_lock();
        let temp = tempfile::tempdir().expect("tempdir");
        std::env::set_var("XDG_CONFIG_HOME", temp.path());

        let listener = StdTcpListener::bind("127.0.0.1:0").expect("bind mock server");
        let addr = listener.local_addr().expect("mock server addr");
        thread::spawn(move || {
            if let Ok((mut stream, _)) = listener.accept() {
                let mut bytes = [0_u8; 4096];
                let _ = stream.read(&mut bytes);
                let body = r#"{"access_token":"new_access","refresh_token":"new_refresh","expires_in":3600}"#;
                let response = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    body.len(),
                    body
                );
                let _ = stream.write_all(response.as_bytes());
            }
        });
        std::env::set_var(
            "ENDEAVOUR_AUTH_REFRESH_OPENAI_ENDPOINT",
            format!("http://{addr}"),
        );

        let client = Client::new();
        let record = TokenRecord {
            access_token: "old_access".to_string(),
            refresh_token: "old_refresh".to_string(),
            expires_at: "1".to_string(),
            method: AuthMethod::Oauth,
        };

        let refreshed = ensure_fresh_token(&client, AuthProvider::OpenAi, record)
            .await
            .expect("refresh should succeed");
        assert_eq!(refreshed.access_token, "new_access");
        assert_eq!(refreshed.refresh_token, "new_refresh");

        let persisted = get_token("openai")
            .expect("read persisted token")
            .expect("token should exist");
        assert_eq!(persisted.access_token, "new_access");

        std::env::remove_var("ENDEAVOUR_AUTH_REFRESH_OPENAI_ENDPOINT");
        std::env::remove_var("XDG_CONFIG_HOME");
    }
}
