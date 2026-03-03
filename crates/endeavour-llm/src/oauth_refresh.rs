use std::collections::HashMap;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use reqwest::Client;
use serde::{Deserialize, Serialize};

use crate::error::LlmError;

const OPENAI_CLIENT_ID: &str = "app_EMoamEEZ73f0CkXaXp7hrann";
const ANTHROPIC_CLIENT_ID: &str = "9d1c250a-e61b-44d9-88ed-5944d1962f5e";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ProviderAuth {
    Anthropic,
    OpenAi,
}

impl ProviderAuth {
    fn id(self) -> &'static str {
        match self {
            Self::Anthropic => "anthropic",
            Self::OpenAi => "openai",
        }
    }

    fn display(self) -> &'static str {
        match self {
            Self::Anthropic => "Claude",
            Self::OpenAi => "GPT",
        }
    }

    fn login_slug(self) -> &'static str {
        match self {
            Self::Anthropic => "claude",
            Self::OpenAi => "gpt",
        }
    }

    fn client_id(self) -> &'static str {
        match self {
            Self::Anthropic => ANTHROPIC_CLIENT_ID,
            Self::OpenAi => OPENAI_CLIENT_ID,
        }
    }

    fn refresh_url(self) -> String {
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

    fn reauth_prompt(self) -> String {
        format!(
            "● Auth expired for {}. Run '/login {}' to re-authenticate.",
            self.display(),
            self.login_slug()
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum CredentialMethod {
    ApiKey,
    OAuth,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct RequestCredential {
    pub token: String,
    pub method: CredentialMethod,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
enum AuthMethod {
    Oauth,
    ApiKey,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
struct TokenRecord {
    access_token: String,
    refresh_token: String,
    expires_at: String,
    method: AuthMethod,
}

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
struct AuthStore {
    #[serde(default)]
    providers: HashMap<String, TokenRecord>,
}

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

pub(crate) async fn credential_for_request(
    provider: ProviderAuth,
    configured_token: &str,
    http: &Client,
) -> Result<RequestCredential, LlmError> {
    let Some(mut store) = read_auth_store() else {
        return Ok(RequestCredential {
            token: configured_token.to_string(),
            method: CredentialMethod::ApiKey,
        });
    };
    let Some(record) = store.providers.get(provider.id()).cloned() else {
        return Ok(RequestCredential {
            token: configured_token.to_string(),
            method: CredentialMethod::ApiKey,
        });
    };
    if record.access_token != configured_token {
        return Ok(RequestCredential {
            token: configured_token.to_string(),
            method: CredentialMethod::ApiKey,
        });
    }

    match record.method {
        AuthMethod::ApiKey => Ok(RequestCredential {
            token: configured_token.to_string(),
            method: CredentialMethod::ApiKey,
        }),
        AuthMethod::Oauth => {
            if !is_expired(&record.expires_at) {
                return Ok(RequestCredential {
                    token: configured_token.to_string(),
                    method: CredentialMethod::OAuth,
                });
            }

            let refreshed = refresh_token(http, provider, &record)
                .await
                .map_err(|_| LlmError::Configuration(provider.reauth_prompt()))?;
            store
                .providers
                .insert(provider.id().to_string(), refreshed.clone());
            write_auth_store(&store)
                .map_err(|_| LlmError::Configuration(provider.reauth_prompt()))?;

            Ok(RequestCredential {
                token: refreshed.access_token,
                method: CredentialMethod::OAuth,
            })
        }
    }
}

fn is_expired(expires_at: &str) -> bool {
    let now = match SystemTime::now().duration_since(UNIX_EPOCH) {
        Ok(duration) => duration.as_secs(),
        Err(_) => return true,
    };
    match expires_at.trim().parse::<u64>() {
        Ok(value) => value <= now,
        Err(_) => true,
    }
}

async fn refresh_token(
    http: &Client,
    provider: ProviderAuth,
    record: &TokenRecord,
) -> Result<TokenRecord, reqwest::Error> {
    let payload = RefreshRequest {
        grant_type: "refresh_token",
        refresh_token: &record.refresh_token,
        client_id: provider.client_id(),
    };
    let refreshed = http
        .post(provider.refresh_url())
        .form(&payload)
        .send()
        .await?
        .error_for_status()?
        .json::<RefreshResponse>()
        .await?;
    Ok(TokenRecord {
        access_token: refreshed.access_token,
        refresh_token: refreshed
            .refresh_token
            .filter(|value| !value.trim().is_empty())
            .unwrap_or_else(|| record.refresh_token.clone()),
        expires_at: SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|duration| duration.as_secs())
            .unwrap_or(0)
            .saturating_add(refreshed.expires_in)
            .to_string(),
        method: AuthMethod::Oauth,
    })
}

fn auth_store_path() -> Option<PathBuf> {
    let base = match std::env::var_os("XDG_CONFIG_HOME") {
        Some(value) if !value.is_empty() => PathBuf::from(value),
        _ => PathBuf::from(std::env::var_os("HOME")?).join(".config"),
    };
    Some(base.join("endeavour").join("auth.json"))
}

fn read_auth_store() -> Option<AuthStore> {
    let path = auth_store_path()?;
    let payload = std::fs::read_to_string(path).ok()?;
    serde_json::from_str(&payload).ok()
}

fn write_auth_store(store: &AuthStore) -> std::io::Result<()> {
    let Some(path) = auth_store_path() else {
        return Err(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            "HOME is not set",
        ));
    };
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let mut payload = serde_json::to_vec_pretty(store).map_err(std::io::Error::other)?;
    payload.push(b'\n');
    std::fs::write(path, payload)
}

#[cfg(test)]
mod tests {
    use std::io::{Read, Write};
    use std::net::TcpListener as StdTcpListener;
    use std::sync::{Mutex, OnceLock};
    use std::thread;

    use reqwest::Client;

    use super::{credential_for_request, CredentialMethod, ProviderAuth};

    fn env_lock() -> std::sync::MutexGuard<'static, ()> {
        static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
        LOCK.get_or_init(|| Mutex::new(()))
            .lock()
            .expect("env lock")
    }

    #[tokio::test]
    async fn api_key_bypass_never_refreshes() {
        let _guard = env_lock();
        let temp = tempfile::tempdir().expect("tempdir");
        std::env::set_var("XDG_CONFIG_HOME", temp.path());
        std::fs::create_dir_all(temp.path().join("endeavour")).expect("create auth store dir");
        std::fs::write(
            temp.path().join("endeavour").join("auth.json"),
            r#"{"providers":{"openai":{"access_token":"sk-live","refresh_token":"rt","expires_at":"0","method":"api_key"}}}"#,
        )
        .expect("write auth store");

        let client = Client::new();
        let resolved = credential_for_request(ProviderAuth::OpenAi, "sk-live", &client)
            .await
            .expect("api key should bypass refresh");
        assert_eq!(resolved.token, "sk-live");
        assert_eq!(resolved.method, CredentialMethod::ApiKey);

        std::env::remove_var("XDG_CONFIG_HOME");
    }

    #[tokio::test]
    async fn expired_oauth_is_refreshed_and_persisted() {
        let _guard = env_lock();
        let temp = tempfile::tempdir().expect("tempdir");
        std::env::set_var("XDG_CONFIG_HOME", temp.path());
        std::fs::create_dir_all(temp.path().join("endeavour")).expect("create auth store dir");
        std::fs::write(
            temp.path().join("endeavour").join("auth.json"),
            r#"{"providers":{"openai":{"access_token":"old_access","refresh_token":"old_refresh","expires_at":"1","method":"oauth"}}}"#,
        )
        .expect("write auth store");

        let listener = StdTcpListener::bind("127.0.0.1:0").expect("bind mock endpoint");
        let addr = listener.local_addr().expect("mock endpoint addr");
        thread::spawn(move || {
            if let Ok((mut stream, _)) = listener.accept() {
                let mut request = [0_u8; 4096];
                let _ = stream.read(&mut request);
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
        let resolved = credential_for_request(ProviderAuth::OpenAi, "old_access", &client)
            .await
            .expect("refresh should succeed");
        assert_eq!(resolved.token, "new_access");
        assert_eq!(resolved.method, CredentialMethod::OAuth);

        let updated = std::fs::read_to_string(temp.path().join("endeavour").join("auth.json"))
            .expect("read updated auth store");
        assert!(updated.contains("new_access"));

        std::env::remove_var("ENDEAVOUR_AUTH_REFRESH_OPENAI_ENDPOINT");
        std::env::remove_var("XDG_CONFIG_HOME");
    }
}
