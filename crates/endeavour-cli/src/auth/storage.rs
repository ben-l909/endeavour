use std::collections::HashMap;
use std::ffi::OsString;
use std::fs::OpenOptions;
use std::io::Write;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

#[cfg(unix)]
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};

/// Authentication methods supported by the local auth store.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuthMethod {
    /// OAuth-based credential.
    Oauth,
    /// API key credential.
    ApiKey,
}

/// Provider token record stored in `auth.json`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TokenRecord {
    /// Access token value for provider requests.
    pub access_token: String,
    /// Refresh token used to renew the access token.
    pub refresh_token: String,
    /// UTC expiration timestamp in ISO8601 format.
    pub expires_at: String,
    /// Credential method metadata.
    pub method: AuthMethod,
}

/// Provider-indexed token store persisted at `$XDG_CONFIG_HOME/endeavour/auth.json`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuthStore {
    /// Map of provider ID to token metadata.
    #[serde(default)]
    pub providers: HashMap<String, TokenRecord>,
}

/// Reads the auth store JSON and returns an empty store when file is absent.
pub fn read_auth_store() -> Result<AuthStore> {
    let path = auth_store_path()?;
    read_auth_store_from_path(&path)
}

/// Writes the auth store JSON, creating parent directories and enforcing `0600` permissions.
pub fn write_auth_store(store: &AuthStore) -> Result<()> {
    let path = auth_store_path()?;
    write_auth_store_to_path(&path, store)
}

/// Gets a provider token record if present in the auth store.
pub fn get_token(provider: &str) -> Result<Option<TokenRecord>> {
    let store = read_auth_store()?;
    Ok(store.providers.get(provider).cloned())
}

/// Inserts or replaces a provider token record in the auth store.
pub fn set_token(provider: &str, record: TokenRecord) -> Result<()> {
    let mut store = read_auth_store()?;
    store.providers.insert(provider.to_string(), record);
    write_auth_store(&store)
}

/// Deletes a provider token record from the auth store.
pub fn delete_token(provider: &str) -> Result<()> {
    let mut store = read_auth_store()?;
    store.providers.remove(provider);
    write_auth_store(&store)
}

fn auth_store_path() -> Result<PathBuf> {
    let xdg_config_home = std::env::var_os("XDG_CONFIG_HOME");
    let home = std::env::var_os("HOME");
    auth_store_path_from_env(xdg_config_home, home)
}

fn auth_store_path_from_env(
    xdg_config_home: Option<OsString>,
    home: Option<OsString>,
) -> Result<PathBuf> {
    let base_dir = match xdg_config_home {
        Some(path) if !path.is_empty() => PathBuf::from(path),
        _ => {
            let home = home.context("HOME environment variable is not set")?;
            PathBuf::from(home).join(".config")
        }
    };

    Ok(base_dir.join("endeavour").join("auth.json"))
}

fn read_auth_store_from_path(path: &Path) -> Result<AuthStore> {
    let content = match std::fs::read_to_string(path) {
        Ok(content) => content,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(AuthStore::default()),
        Err(err) => {
            return Err(err)
                .with_context(|| format!("failed to read auth store at {}", path.display()));
        }
    };

    serde_json::from_str(&content)
        .with_context(|| format!("failed to parse auth store JSON at {}", path.display()))
}

fn write_auth_store_to_path(path: &Path, store: &AuthStore) -> Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).with_context(|| {
            format!("failed to create auth store directory {}", parent.display())
        })?;
    }

    let mut payload = serde_json::to_vec_pretty(store).context("failed to serialize auth store")?;
    payload.push(b'\n');

    let mut file = open_auth_store_file(path)?;
    file.write_all(&payload)
        .with_context(|| format!("failed to write auth store at {}", path.display()))?;

    set_auth_store_permissions(path)
}

#[cfg(unix)]
fn open_auth_store_file(path: &Path) -> Result<std::fs::File> {
    OpenOptions::new()
        .create(true)
        .truncate(true)
        .write(true)
        .mode(0o600)
        .open(path)
        .with_context(|| format!("failed to open auth store at {}", path.display()))
}

#[cfg(not(unix))]
fn open_auth_store_file(path: &Path) -> Result<std::fs::File> {
    OpenOptions::new()
        .create(true)
        .truncate(true)
        .write(true)
        .open(path)
        .with_context(|| format!("failed to open auth store at {}", path.display()))
}

#[cfg(unix)]
fn set_auth_store_permissions(path: &Path) -> Result<()> {
    let permissions = std::fs::Permissions::from_mode(0o600);
    std::fs::set_permissions(path, permissions)
        .with_context(|| format!("failed to set auth store permissions at {}", path.display()))
}

#[cfg(not(unix))]
fn set_auth_store_permissions(_path: &Path) -> Result<()> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{
        auth_store_path_from_env, read_auth_store_from_path, write_auth_store_to_path, AuthMethod,
        AuthStore, TokenRecord,
    };

    #[cfg(unix)]
    use std::os::unix::fs::PermissionsExt;

    #[test]
    fn round_trip_write_and_read_token() -> anyhow::Result<()> {
        let tempdir = tempfile::tempdir()?;
        let path = tempdir.path().join("auth.json");

        let mut store = AuthStore::default();
        store.providers.insert(
            "openai".to_string(),
            TokenRecord {
                access_token: "access-token".to_string(),
                refresh_token: "refresh-token".to_string(),
                expires_at: "2026-03-03T00:00:00Z".to_string(),
                method: AuthMethod::Oauth,
            },
        );

        write_auth_store_to_path(&path, &store)?;
        let read_back = read_auth_store_from_path(&path)?;

        assert_eq!(read_back, store);
        Ok(())
    }

    #[test]
    fn missing_file_returns_empty_store() -> anyhow::Result<()> {
        let tempdir = tempfile::tempdir()?;
        let path = tempdir.path().join("missing").join("auth.json");

        let store = read_auth_store_from_path(&path)?;
        assert!(store.providers.is_empty());

        Ok(())
    }

    #[test]
    fn write_creates_parent_directories() -> anyhow::Result<()> {
        let tempdir = tempfile::tempdir()?;
        let path = tempdir
            .path()
            .join("nested")
            .join("config")
            .join("endeavour")
            .join("auth.json");

        write_auth_store_to_path(&path, &AuthStore::default())?;
        assert!(path.exists());

        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn write_sets_0600_permissions() -> anyhow::Result<()> {
        let tempdir = tempfile::tempdir()?;
        let path = tempdir.path().join("auth.json");

        write_auth_store_to_path(&path, &AuthStore::default())?;
        let mode = std::fs::metadata(&path)?.permissions().mode() & 0o777;

        assert_eq!(mode, 0o600);
        Ok(())
    }

    #[test]
    fn invalid_json_returns_error() -> anyhow::Result<()> {
        let tempdir = tempfile::tempdir()?;
        let path = tempdir.path().join("auth.json");
        std::fs::write(&path, "{not-json")?;

        let result = read_auth_store_from_path(&path);
        assert!(result.is_err());

        Ok(())
    }

    #[test]
    fn xdg_path_resolution_uses_fallback_home_config() -> anyhow::Result<()> {
        let resolved = auth_store_path_from_env(None, Some("/tmp/home".into()))?;
        assert_eq!(
            resolved,
            std::path::PathBuf::from("/tmp/home/.config/endeavour/auth.json")
        );

        Ok(())
    }

    #[test]
    fn xdg_path_resolution_prefers_xdg_config_home() -> anyhow::Result<()> {
        let resolved = auth_store_path_from_env(Some("/tmp/xdg".into()), Some("/tmp/home".into()))?;
        assert_eq!(
            resolved,
            std::path::PathBuf::from("/tmp/xdg/endeavour/auth.json")
        );

        Ok(())
    }
}
