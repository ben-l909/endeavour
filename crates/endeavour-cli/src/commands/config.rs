use crate::repl::Repl;
use anyhow::{Context, Result};
use endeavour_core::config::Config;

pub(crate) fn handle_config_set(_repl: &Repl, key: &str, value: &str) -> Result<()> {
    let mut config = Config::load().context("failed to load config")?;
    config
        .set(key, value)
        .with_context(|| format!("failed to set config key '{key}'"))?;
    config.save().context("failed to save config")?;

    println!("Set {key} = {}", mask_config_value(key, value));
    Ok(())
}

pub(crate) fn handle_config_get(_repl: &Repl, key: &str) -> Result<()> {
    let config = Config::load().context("failed to load config")?;
    match config
        .get(key)
        .with_context(|| format!("failed to read config key '{key}'"))?
    {
        Some(value) => println!("{key} = {}", mask_config_value(key, value)),
        None => println!("{key} is not set"),
    }

    Ok(())
}

pub(crate) fn handle_config_list(_repl: &Repl) -> Result<()> {
    let config = Config::load().context("failed to load config")?;
    for key in ["anthropic-api-key", "openai-api-key", "default-provider"] {
        match config
            .get(key)
            .with_context(|| format!("failed to read config key '{key}'"))?
        {
            Some(value) => println!("{key} = {}", mask_config_value(key, value)),
            None => println!("{key} = <not set>"),
        }
    }

    Ok(())
}

fn mask_config_value(key: &str, value: &str) -> String {
    if is_api_key(key) {
        return format!("{}...", value.chars().take(8).collect::<String>());
    }

    value.to_string()
}

fn is_api_key(key: &str) -> bool {
    matches!(
        key,
        "anthropic-api-key" | "anthropic_api_key" | "openai-api-key" | "openai_api_key"
    )
}

#[cfg(test)]
mod tests {
    use super::mask_config_value;

    #[test]
    fn config_commands_mask_api_key_values() {
        assert_eq!(
            mask_config_value("openai-api-key", "sk-openai-1234567890"),
            "sk-opena..."
        );
        assert_eq!(
            mask_config_value("default-provider", "anthropic"),
            "anthropic"
        );
    }
}
