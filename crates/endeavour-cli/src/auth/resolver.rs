use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{anyhow, Result};
use endeavour_core::config::Config;

use crate::auth::refresh::is_expired;
use crate::auth::storage::{get_token, AuthMethod};

const ANTHROPIC_ENV_VAR: &str = "ANTHROPIC_API_KEY";
const OPENAI_ENV_VAR: &str = "OPENAI_API_KEY";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum AuthStatus {
    Oauth,
    ApiKey,
    #[default]
    None,
}

impl AuthStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Oauth => "oauth",
            Self::ApiKey => "api-key",
            Self::None => "none",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Credential {
    pub token: Option<String>,
    pub auth_status: AuthStatus,
    pub should_prompt: bool,
}

impl Credential {
    fn oauth(token: String) -> Self {
        Self {
            token: Some(token),
            auth_status: AuthStatus::Oauth,
            should_prompt: false,
        }
    }

    fn api_key(token: String) -> Self {
        Self {
            token: Some(token),
            auth_status: AuthStatus::ApiKey,
            should_prompt: false,
        }
    }

    fn prompt() -> Self {
        Self {
            token: None,
            auth_status: AuthStatus::None,
            should_prompt: true,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct AuthStatusSnapshot {
    pub anthropic: AuthStatus,
    pub openai: AuthStatus,
}

#[derive(Debug, Clone)]
pub struct CredentialResolver {
    config: Config,
    now_unix_seconds: u64,
}

impl CredentialResolver {
    pub fn new(config: Config) -> Self {
        Self {
            config,
            now_unix_seconds: current_unix_seconds(),
        }
    }

    pub fn resolve(&self, provider: &str) -> Result<Credential> {
        let provider = Provider::parse(provider)?;

        if let Some(record) = get_token(provider.id())? {
            let token = record.access_token.trim();
            if record.method == AuthMethod::Oauth
                && !token.is_empty()
                && !is_expired(&record.expires_at, self.now_unix_seconds)
            {
                return Ok(Credential::oauth(record.access_token));
            }
        }

        if let Ok(value) = std::env::var(provider.env_var()) {
            if !value.trim().is_empty() {
                return Ok(Credential::api_key(value));
            }
        }

        if let Some(value) = provider.config_key(&self.config) {
            if !value.trim().is_empty() {
                return Ok(Credential::api_key(value.to_string()));
            }
        }

        Ok(Credential::prompt())
    }
}

pub fn apply_resolved_credentials(config: &mut Config) -> Result<AuthStatusSnapshot> {
    let resolver = CredentialResolver::new(config.clone());

    let anthropic = resolver.resolve("anthropic")?;
    config.anthropic_api_key = anthropic.token;

    let openai = resolver.resolve("openai")?;
    config.openai_api_key = openai.token;

    Ok(AuthStatusSnapshot {
        anthropic: anthropic.auth_status,
        openai: openai.auth_status,
    })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Provider {
    Anthropic,
    OpenAi,
}

impl Provider {
    fn parse(value: &str) -> Result<Self> {
        match value.trim().to_ascii_lowercase().as_str() {
            "anthropic" | "claude" => Ok(Self::Anthropic),
            "openai" | "gpt" => Ok(Self::OpenAi),
            other => Err(anyhow!("unsupported provider '{other}'")),
        }
    }

    fn id(self) -> &'static str {
        match self {
            Self::Anthropic => "anthropic",
            Self::OpenAi => "openai",
        }
    }

    fn env_var(self) -> &'static str {
        match self {
            Self::Anthropic => ANTHROPIC_ENV_VAR,
            Self::OpenAi => OPENAI_ENV_VAR,
        }
    }

    fn config_key(self, config: &Config) -> Option<&str> {
        match self {
            Self::Anthropic => config.anthropic_api_key.as_deref(),
            Self::OpenAi => config.openai_api_key.as_deref(),
        }
    }
}

fn current_unix_seconds() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::{AuthStatus, CredentialResolver};
    use crate::auth::storage::{set_token, AuthMethod, TokenRecord};
    use endeavour_core::config::Config;

    #[test]
    fn resolves_env_var_when_oauth_missing() -> anyhow::Result<()> {
        let _guard = crate::auth::test_env_lock();
        let temp = tempfile::tempdir()?;
        std::env::set_var("HOME", temp.path());
        std::env::set_var("XDG_CONFIG_HOME", temp.path());
        std::env::set_var("ANTHROPIC_API_KEY", "sk-ant-env");

        let resolver = CredentialResolver::new(Config::default());
        let resolved = resolver.resolve("anthropic")?;

        assert_eq!(resolved.token.as_deref(), Some("sk-ant-env"));
        assert_eq!(resolved.auth_status, AuthStatus::ApiKey);
        assert!(!resolved.should_prompt);

        std::env::remove_var("ANTHROPIC_API_KEY");
        std::env::remove_var("XDG_CONFIG_HOME");
        std::env::remove_var("HOME");
        Ok(())
    }

    #[test]
    fn resolves_oauth_before_env_var() -> anyhow::Result<()> {
        let _guard = crate::auth::test_env_lock();
        let temp = tempfile::tempdir()?;
        std::env::set_var("HOME", temp.path());
        std::env::set_var("XDG_CONFIG_HOME", temp.path());
        std::env::set_var("OPENAI_API_KEY", "sk-openai-env");
        set_token(
            "openai",
            TokenRecord {
                access_token: "oauth-openai-token".to_string(),
                refresh_token: "refresh-openai-token".to_string(),
                expires_at: "4102444800".to_string(),
                method: AuthMethod::Oauth,
            },
        )?;

        let resolver = CredentialResolver::new(Config::default());
        let resolved = resolver.resolve("openai")?;

        assert_eq!(resolved.token.as_deref(), Some("oauth-openai-token"));
        assert_eq!(resolved.auth_status, AuthStatus::Oauth);
        assert!(!resolved.should_prompt);

        std::env::remove_var("OPENAI_API_KEY");
        std::env::remove_var("XDG_CONFIG_HOME");
        std::env::remove_var("HOME");
        Ok(())
    }

    #[test]
    fn resolves_none_when_no_credentials_exist() -> anyhow::Result<()> {
        let _guard = crate::auth::test_env_lock();
        let temp = tempfile::tempdir()?;
        std::env::set_var("HOME", temp.path());
        std::env::set_var("XDG_CONFIG_HOME", temp.path());
        std::env::remove_var("OPENAI_API_KEY");

        let resolver = CredentialResolver::new(Config::default());
        let resolved = resolver.resolve("openai")?;

        assert_eq!(resolved.token, None);
        assert_eq!(resolved.auth_status, AuthStatus::None);
        assert!(resolved.should_prompt);

        std::env::remove_var("XDG_CONFIG_HOME");
        std::env::remove_var("HOME");
        Ok(())
    }
}
