use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

const APP_DIRECTORY: &str = ".endeavour";
const CONFIG_FILE_NAME: &str = "config.toml";

/// Errors that can occur during configuration operations.
#[derive(thiserror::Error, Debug)]
pub enum ConfigError {
    /// HOME environment variable is not set.
    #[error("HOME environment variable is not set")]
    HomeDirMissing,
    /// I/O error while reading or writing configuration.
    #[error("config IO error: {0}")]
    Io(#[from] std::io::Error),
    /// Error serializing configuration to TOML format.
    #[error("config serialization error: {0}")]
    Serialize(#[from] toml::ser::Error),
    /// Error deserializing configuration from TOML format.
    #[error("config deserialization error: {0}")]
    Deserialize(#[from] toml::de::Error),
    /// Unknown configuration key provided.
    #[error("unknown config key: {0}")]
    InvalidKey(String),
    /// Invalid value for a configuration key.
    #[error("invalid value '{value}' for key '{key}'")]
    InvalidValue {
        /// The configuration key.
        key: String,
        /// The invalid value provided.
        value: String,
    },
}

/// Result type for configuration operations.
pub type Result<T> = std::result::Result<T, ConfigError>;

/// Configuration for Endeavour, storing API keys and provider preferences.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(default)]
pub struct Config {
    /// Anthropic API key for Claude models.
    pub anthropic_api_key: Option<String>,
    /// OpenAI API key for GPT models.
    pub openai_api_key: Option<String>,
    /// Default LLM provider ("anthropic" or "openai").
    pub default_provider: Option<String>,
}

impl Config {
    /// Load configuration from the default location (~/.endeavour/config.toml).
    pub fn load() -> Result<Self> {
        let path = config_path()?;
        Self::load_from_path(&path)
    }

    /// Save configuration to the default location (~/.endeavour/config.toml).
    pub fn save(&self) -> Result<()> {
        let path = config_path()?;
        self.save_to_path(&path)
    }

    /// Set a configuration value by key. Validates provider values.
    pub fn set(&mut self, key: &str, value: &str) -> Result<()> {
        match normalize_key(key)? {
            "anthropic-api-key" => {
                self.anthropic_api_key = Some(value.to_string());
            }
            "openai-api-key" => {
                self.openai_api_key = Some(value.to_string());
            }
            "default-provider" => {
                if matches!(value, "anthropic" | "openai") {
                    self.default_provider = Some(value.to_string());
                } else {
                    return Err(ConfigError::InvalidValue {
                        key: "default-provider".to_string(),
                        value: value.to_string(),
                    });
                }
            }
            _ => return Err(ConfigError::InvalidKey(key.to_string())),
        }

        Ok(())
    }

    /// Get a configuration value by key.
    pub fn get(&self, key: &str) -> Result<Option<&str>> {
        let value = match normalize_key(key)? {
            "anthropic-api-key" => self.anthropic_api_key.as_deref(),
            "openai-api-key" => self.openai_api_key.as_deref(),
            "default-provider" => self.default_provider.as_deref(),
            _ => return Err(ConfigError::InvalidKey(key.to_string())),
        };

        Ok(value)
    }

    fn load_from_path(path: &Path) -> Result<Self> {
        if !path.exists() {
            return Ok(Self::default());
        }

        let raw = std::fs::read_to_string(path)?;
        if raw.trim().is_empty() {
            return Ok(Self::default());
        }

        Ok(toml::from_str(&raw)?)
    }

    fn save_to_path(&self, path: &Path) -> Result<()> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }

        let serialized = toml::to_string_pretty(self)?;
        std::fs::write(path, serialized)?;
        Ok(())
    }
}

fn normalize_key(key: &str) -> Result<&str> {
    match key {
        "anthropic-api-key" | "anthropic_api_key" => Ok("anthropic-api-key"),
        "openai-api-key" | "openai_api_key" => Ok("openai-api-key"),
        "default-provider" | "default_provider" => Ok("default-provider"),
        _ => Err(ConfigError::InvalidKey(key.to_string())),
    }
}

fn config_path() -> Result<PathBuf> {
    let home = std::env::var_os("HOME").ok_or(ConfigError::HomeDirMissing)?;
    Ok(PathBuf::from(home)
        .join(APP_DIRECTORY)
        .join(CONFIG_FILE_NAME))
}

#[cfg(test)]
mod tests {
    use super::Config;

    #[test]
    fn load_missing_file_returns_default() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("missing-config.toml");
        let loaded = Config::load_from_path(&path).unwrap();
        assert_eq!(loaded, Config::default());
    }

    #[test]
    fn save_and_load_round_trip() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("config.toml");

        let mut cfg = Config::default();
        cfg.set("anthropic-api-key", "sk-ant-abcdef0123456789")
            .unwrap();
        cfg.set("openai-api-key", "sk-openai-abcdef0123456789")
            .unwrap();
        cfg.set("default-provider", "anthropic").unwrap();

        cfg.save_to_path(&path).unwrap();

        let loaded = Config::load_from_path(&path).unwrap();
        assert_eq!(loaded, cfg);
    }

    #[test]
    fn set_and_get_round_trip() {
        let mut cfg = Config::default();
        cfg.set("anthropic-api-key", "sk-ant-12345678-test")
            .unwrap();
        cfg.set("default-provider", "openai").unwrap();

        assert_eq!(
            cfg.get("anthropic-api-key").unwrap(),
            Some("sk-ant-12345678-test")
        );
        assert_eq!(cfg.get("default-provider").unwrap(), Some("openai"));
        assert!(cfg.get("openai-api-key").unwrap().is_none());
    }
}
