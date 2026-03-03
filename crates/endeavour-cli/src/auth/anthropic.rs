use std::fmt::{Display, Formatter};
use std::io::{self, Write};
use std::process::Command;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use base64::Engine;
use rand::Rng;
use reqwest::header::{HeaderMap, HeaderValue, AUTHORIZATION};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::auth::storage::{set_token, AuthMethod, TokenRecord};

/// Anthropic OAuth client ID used by Endeavour.
pub const ANTHROPIC_CLIENT_ID: &str = "9d1c250a-e61b-44d9-88ed-5944d1962f5e";
/// Anthropic authorization endpoint.
pub const ANTHROPIC_AUTH_URL: &str = "https://claude.ai/oauth/authorize";
/// Anthropic token exchange endpoint.
pub const ANTHROPIC_TOKEN_URL: &str = "https://console.anthropic.com/v1/oauth/token";
/// Anthropic OAuth redirect URI.
pub const ANTHROPIC_REDIRECT_URI: &str = "https://console.anthropic.com/oauth/code/callback";
/// Anthropic OAuth scopes required by Endeavour.
pub const ANTHROPIC_SCOPE: &str = "org:create_api_key user:profile user:inference";
/// Anthropic beta header value required for OAuth access tokens.
pub const ANTHROPIC_OAUTH_BETA: &str = "oauth-2025-04-20";

/// OAuth exchange result from the Anthropic token endpoint.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub struct AnthropicTokenResponse {
    /// OAuth access token used for provider API calls.
    pub access_token: String,
    /// OAuth refresh token used in later refresh flows.
    pub refresh_token: String,
    /// Lifetime of the access token in seconds.
    pub expires_in: u64,
}

#[derive(Debug, Deserialize, Serialize)]
struct AnthropicTokenExchangeRequest {
    grant_type: String,
    code: String,
    state: String,
    client_id: String,
    redirect_uri: String,
    code_verifier: String,
}

/// Parsed callback value from Anthropic's `code#state` format.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedCallbackCode {
    /// Authorization code used in token exchange.
    pub code: String,
    /// Callback state value (must equal PKCE verifier for Anthropic).
    pub state: String,
}

/// Error type for Anthropic OAuth login operations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AnthropicOAuthError {
    /// User cancelled authorization.
    AuthorizationCancelled,
    /// Authorization code input was malformed or rejected.
    InvalidAuthorizationCode,
    /// Network or HTTP transport error details.
    Network(String),
    /// Local I/O failure details.
    Io(String),
    /// Token persistence failure details.
    Storage(String),
    /// Unexpected response payload details.
    Response(String),
}

impl Display for AnthropicOAuthError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        let detail = match self {
            Self::AuthorizationCancelled => "authorization cancelled".to_string(),
            Self::InvalidAuthorizationCode => "invalid authorization code".to_string(),
            Self::Network(message) => message.clone(),
            Self::Io(message) => message.clone(),
            Self::Storage(message) => message.clone(),
            Self::Response(message) => message.clone(),
        };
        write!(f, "✗ error: Anthropic OAuth failed\n    ╰─ {detail}")
    }
}

impl std::error::Error for AnthropicOAuthError {}

/// Anthropic OAuth PKCE client used for manual login flow and token exchange.
#[derive(Debug, Clone)]
pub struct AnthropicOAuthClient {
    http_client: reqwest::Client,
    client_id: String,
    auth_url: String,
    token_url: String,
    redirect_uri: String,
    scope: String,
}

impl Default for AnthropicOAuthClient {
    fn default() -> Self {
        Self {
            http_client: reqwest::Client::new(),
            client_id: ANTHROPIC_CLIENT_ID.to_string(),
            auth_url: ANTHROPIC_AUTH_URL.to_string(),
            token_url: ANTHROPIC_TOKEN_URL.to_string(),
            redirect_uri: ANTHROPIC_REDIRECT_URI.to_string(),
            scope: ANTHROPIC_SCOPE.to_string(),
        }
    }
}

impl AnthropicOAuthClient {
    /// Creates a new Anthropic OAuth client with default production endpoints.
    pub fn new() -> Self {
        Self::default()
    }

    /// Creates a client with custom endpoints for tests.
    pub fn with_endpoints(
        client_id: String,
        auth_url: String,
        token_url: String,
        redirect_uri: String,
        scope: String,
    ) -> Self {
        Self {
            http_client: reqwest::Client::new(),
            client_id,
            auth_url,
            token_url,
            redirect_uri,
            scope,
        }
    }

    /// Runs Anthropic OAuth login with browser launch and manual code paste fallback.
    pub async fn login(&self) -> Result<(), AnthropicOAuthError> {
        let verifier = generate_code_verifier();
        let challenge = code_challenge_for_verifier(&verifier);
        let authorize_url = self.build_authorize_url(&challenge, &verifier)?;

        println!("Open this URL in your browser:\n  {authorize_url}");
        let _ = open_authorize_url_in_browser(&authorize_url);

        let pasted = prompt_for_authorization_code()?;
        let parsed = parse_callback_code(&pasted)?;
        if parsed.state != verifier {
            return Err(AnthropicOAuthError::InvalidAuthorizationCode);
        }

        let tokens = self
            .exchange_code_for_tokens(parsed.code, parsed.state, verifier)
            .await?;

        let expires_at = now_plus_seconds(tokens.expires_in)?;
        let record = TokenRecord {
            access_token: tokens.access_token,
            refresh_token: tokens.refresh_token,
            expires_at,
            method: AuthMethod::Oauth,
        };

        set_token("anthropic", record)
            .map_err(|err| AnthropicOAuthError::Storage(err.to_string()))?;
        Ok(())
    }

    /// Builds the provider authorization URL from PKCE challenge and state/verifier.
    pub fn build_authorize_url(
        &self,
        code_challenge: &str,
        state_verifier: &str,
    ) -> Result<String, AnthropicOAuthError> {
        let mut url = reqwest::Url::parse(&self.auth_url)
            .map_err(|err| AnthropicOAuthError::Response(err.to_string()))?;
        url.query_pairs_mut()
            .append_pair("client_id", &self.client_id)
            .append_pair("response_type", "code")
            .append_pair("redirect_uri", &self.redirect_uri)
            .append_pair("scope", &self.scope)
            .append_pair("code_challenge", code_challenge)
            .append_pair("code_challenge_method", "S256")
            .append_pair("state", state_verifier);
        Ok(url.to_string())
    }

    /// Exchanges an authorization code for access and refresh tokens.
    pub async fn exchange_code_for_tokens(
        &self,
        code: String,
        state: String,
        code_verifier: String,
    ) -> Result<AnthropicTokenResponse, AnthropicOAuthError> {
        let payload = AnthropicTokenExchangeRequest {
            grant_type: "authorization_code".to_string(),
            code,
            state,
            client_id: self.client_id.clone(),
            redirect_uri: self.redirect_uri.clone(),
            code_verifier,
        };

        let response = self
            .http_client
            .post(&self.token_url)
            .json(&payload)
            .send()
            .await
            .map_err(|err| AnthropicOAuthError::Network(err.to_string()))?;

        if response.status().is_client_error() {
            return Err(AnthropicOAuthError::InvalidAuthorizationCode);
        }

        let response = response
            .error_for_status()
            .map_err(|err| AnthropicOAuthError::Network(err.to_string()))?;

        response
            .json::<AnthropicTokenResponse>()
            .await
            .map_err(|err| AnthropicOAuthError::Response(err.to_string()))
    }
}

/// Generates an RFC-7636 PKCE code verifier using allowed URL-safe characters.
pub fn generate_code_verifier() -> String {
    const CHARSET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~";
    const VERIFIER_LENGTH: usize = 64;

    let mut rng = rand::rng();
    let mut verifier = String::with_capacity(VERIFIER_LENGTH);
    for _ in 0..VERIFIER_LENGTH {
        let idx = rng.random_range(0..CHARSET.len());
        verifier.push(char::from(CHARSET[idx]));
    }
    verifier
}

/// Computes RFC-7636 S256 PKCE code challenge for a verifier.
pub fn code_challenge_for_verifier(code_verifier: &str) -> String {
    let digest = Sha256::digest(code_verifier.as_bytes());
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(digest)
}

/// Parses Anthropic callback value in `code#state` format.
pub fn parse_callback_code(input: &str) -> Result<ParsedCallbackCode, AnthropicOAuthError> {
    let trimmed = input.trim();
    if trimmed.is_empty() {
        return Err(AnthropicOAuthError::AuthorizationCancelled);
    }

    let Some((code, state)) = trimmed.split_once('#') else {
        return Err(AnthropicOAuthError::InvalidAuthorizationCode);
    };

    if code.is_empty() || state.is_empty() {
        return Err(AnthropicOAuthError::InvalidAuthorizationCode);
    }

    Ok(ParsedCallbackCode {
        code: code.to_string(),
        state: state.to_string(),
    })
}

/// Builds HTTP headers required for Anthropic OAuth-authenticated API calls.
pub fn oauth_headers(access_token: &str) -> Result<HeaderMap, AnthropicOAuthError> {
    let mut headers = HeaderMap::new();

    let bearer = format!("Bearer {access_token}");
    let auth_value = HeaderValue::from_str(&bearer)
        .map_err(|err| AnthropicOAuthError::Response(err.to_string()))?;
    headers.insert(AUTHORIZATION, auth_value);

    let beta_value = HeaderValue::from_str(ANTHROPIC_OAUTH_BETA)
        .map_err(|err| AnthropicOAuthError::Response(err.to_string()))?;
    headers.insert("anthropic-beta", beta_value);

    Ok(headers)
}

fn prompt_for_authorization_code() -> Result<String, AnthropicOAuthError> {
    print!("Paste the authorization code: ");
    io::stdout()
        .flush()
        .map_err(|err| AnthropicOAuthError::Io(err.to_string()))?;

    let mut line = String::new();
    let bytes_read = io::stdin()
        .read_line(&mut line)
        .map_err(|err| AnthropicOAuthError::Io(err.to_string()))?;

    if bytes_read == 0 {
        return Err(AnthropicOAuthError::AuthorizationCancelled);
    }

    Ok(line)
}

fn open_authorize_url_in_browser(authorize_url: &str) -> bool {
    let result = Command::new("open").arg(authorize_url).status();
    match result {
        Ok(status) => status.success(),
        Err(_) => false,
    }
}

fn now_plus_seconds(expires_in: u64) -> Result<String, AnthropicOAuthError> {
    let now = SystemTime::now();
    let expires_at = now
        .checked_add(Duration::from_secs(expires_in))
        .ok_or_else(|| {
            AnthropicOAuthError::Response("token expiry timestamp overflow".to_string())
        })?;
    let duration = expires_at
        .duration_since(UNIX_EPOCH)
        .map_err(|err| AnthropicOAuthError::Response(err.to_string()))?;
    Ok(duration.as_secs().to_string())
}

#[cfg(test)]
mod tests {
    use super::{
        code_challenge_for_verifier, generate_code_verifier, parse_callback_code,
        AnthropicOAuthError,
    };

    #[test]
    fn verifier_generation_uses_valid_charset_and_length() {
        let verifier = generate_code_verifier();
        assert!((43..=128).contains(&verifier.len()));
        let valid = verifier
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '.' | '_' | '~'));
        assert!(valid);
    }

    #[test]
    fn challenge_matches_rfc7636_reference_value() {
        let verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
        let challenge = code_challenge_for_verifier(verifier);
        assert_eq!(challenge, "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM");
    }

    #[test]
    fn parse_callback_code_extracts_code_and_state() -> Result<(), AnthropicOAuthError> {
        let parsed = parse_callback_code("abc123#state456")?;
        assert_eq!(parsed.code, "abc123");
        assert_eq!(parsed.state, "state456");
        Ok(())
    }

    #[test]
    fn parse_callback_code_rejects_invalid_format() {
        let result = parse_callback_code("not-valid");
        assert_eq!(result, Err(AnthropicOAuthError::InvalidAuthorizationCode));
    }
}
