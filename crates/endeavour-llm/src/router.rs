use endeavour_core::config::Config;

use crate::{
    AnthropicProvider, CompletionRequest, CompletionResponse, LlmError, LlmProvider, OpenAiProvider,
};

const VALID_PROVIDERS: &str = "claude, gpt, auto, ollama";

/// Task categories used for automatic provider/model routing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TaskType {
    /// Deep analysis workloads.
    DeepAnalysis,
    /// Code-generation workloads.
    CodeGeneration,
    /// Fast rename workloads.
    FastRename,
    /// Summarization workloads.
    Summarize,
    /// Explain command workloads.
    Explain,
    /// Interactive chat workloads.
    Chat,
}

/// User-facing provider selection values.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProviderSelection {
    /// Force Anthropic/Claude.
    Claude,
    /// Force OpenAI/GPT.
    Gpt,
    /// Route automatically by task type.
    Auto,
    /// Reserved value for future Ollama support.
    Ollama,
}

/// Concrete backend provider used by the router.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BackendProvider {
    /// Anthropic backend.
    Anthropic,
    /// OpenAI backend.
    OpenAi,
}

/// Planned route selected by the router.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RoutePlan {
    /// Task type used for routing.
    pub task_type: TaskType,
    /// Requested provider mode.
    pub requested_provider: ProviderSelection,
    /// Selected backend provider.
    pub provider: BackendProvider,
    /// Selected model name.
    pub model: String,
    /// Whether the route came from auto-routing logic.
    pub auto_routed: bool,
}

/// Notice emitted while preparing routing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RouterNotice {
    /// Ollama was requested and transparently downgraded to auto-routing.
    OllamaNotImplemented,
}

/// Information about an executed fallback.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FallbackEvent {
    /// Primary provider that failed.
    pub primary_provider: BackendProvider,
    /// Fallback provider used for retry.
    pub fallback_provider: BackendProvider,
    /// Fallback model used for retry.
    pub fallback_model: String,
}

/// Result returned by router completion requests.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RouterCompletion {
    /// Provider response.
    pub response: CompletionResponse,
    /// Fallback metadata when fallback was used.
    pub fallback: Option<FallbackEvent>,
}

/// Router that resolves provider/model selection and applies fallback behavior.
#[derive(Debug, Clone)]
pub struct LlmRouter {
    config: Config,
    plan: RoutePlan,
    notice: Option<RouterNotice>,
    fallback_enabled: bool,
}

impl ProviderSelection {
    /// Parses a provider string into a provider selection.
    pub fn parse(value: &str) -> std::result::Result<Self, LlmError> {
        let normalized = value.trim().to_ascii_lowercase();
        match normalized.as_str() {
            "claude" | "anthropic" => Ok(Self::Claude),
            "gpt" | "openai" => Ok(Self::Gpt),
            "auto" => Ok(Self::Auto),
            "ollama" => Ok(Self::Ollama),
            _ => Err(LlmError::Configuration(format!(
                "unknown provider '{value}'\n    ╰─ valid providers: {VALID_PROVIDERS}"
            ))),
        }
    }
}

impl BackendProvider {
    /// Returns the lowercase display name used in CLI output.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Anthropic => "anthropic",
            Self::OpenAi => "openai",
        }
    }
}

impl LlmRouter {
    /// Builds an LLM router for the given task and provider selection.
    pub fn new(
        config: Config,
        task_type: TaskType,
        provider: Option<ProviderSelection>,
        fallback_enabled: bool,
    ) -> std::result::Result<Self, LlmError> {
        let requested = match provider {
            Some(value) => value,
            None => parse_default_provider(config.default_provider.as_deref())?,
        };

        let (effective, notice) = match requested {
            ProviderSelection::Ollama => (
                ProviderSelection::Auto,
                Some(RouterNotice::OllamaNotImplemented),
            ),
            other => (other, None),
        };

        let plan = build_route_plan(&config, task_type, requested, effective)?;

        Ok(Self {
            config,
            plan,
            notice,
            fallback_enabled,
        })
    }

    /// Returns the selected route plan.
    pub fn plan(&self) -> &RoutePlan {
        &self.plan
    }

    /// Returns any non-fatal routing notice.
    pub fn notice(&self) -> Option<RouterNotice> {
        self.notice
    }

    /// Executes a completion request with routing and optional rate-limit fallback.
    pub async fn complete(
        &self,
        mut request: CompletionRequest,
    ) -> std::result::Result<RouterCompletion, LlmError> {
        request.model = self.plan.model.clone();

        let primary = self.provider_for(self.plan.provider)?;
        match primary.complete(request.clone()).await {
            Ok(response) => Ok(RouterCompletion {
                response,
                fallback: None,
            }),
            Err(LlmError::RateLimited { retry_after }) if self.fallback_enabled => {
                let fallback_plan =
                    match fallback_route(&self.config, self.plan.provider, &self.plan.model) {
                        Some(plan) => plan,
                        None => return Err(LlmError::RateLimited { retry_after }),
                    };

                request.model = fallback_plan.model.clone();
                let fallback_provider = self.provider_for(fallback_plan.provider)?;
                let response = fallback_provider.complete(request).await?;
                Ok(RouterCompletion {
                    response,
                    fallback: Some(FallbackEvent {
                        primary_provider: self.plan.provider,
                        fallback_provider: fallback_plan.provider,
                        fallback_model: fallback_plan.model,
                    }),
                })
            }
            Err(err) => Err(err),
        }
    }

    fn provider_for(
        &self,
        provider: BackendProvider,
    ) -> std::result::Result<Box<dyn LlmProvider>, LlmError> {
        match provider {
            BackendProvider::Anthropic => {
                let api_key = self
                    .config
                    .anthropic_api_key
                    .clone()
                    .ok_or_else(|| missing_provider_error(ProviderSelection::Claude))?;
                Ok(Box::new(AnthropicProvider::new(api_key)))
            }
            BackendProvider::OpenAi => {
                let api_key = self
                    .config
                    .openai_api_key
                    .clone()
                    .ok_or_else(|| missing_provider_error(ProviderSelection::Gpt))?;
                Ok(Box::new(OpenAiProvider::new(api_key)))
            }
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct FallbackPlan {
    provider: BackendProvider,
    model: String,
}

fn parse_default_provider(value: Option<&str>) -> std::result::Result<ProviderSelection, LlmError> {
    match value {
        Some(raw) => ProviderSelection::parse(raw),
        None => Ok(ProviderSelection::Auto),
    }
}

fn build_route_plan(
    config: &Config,
    task_type: TaskType,
    requested: ProviderSelection,
    effective: ProviderSelection,
) -> std::result::Result<RoutePlan, LlmError> {
    match effective {
        ProviderSelection::Auto => {
            let (provider, model) = auto_route_for_task(config, task_type)?;
            Ok(RoutePlan {
                task_type,
                requested_provider: requested,
                provider,
                model,
                auto_routed: true,
            })
        }
        ProviderSelection::Claude => {
            if config.anthropic_api_key.is_none() {
                return Err(missing_provider_error(ProviderSelection::Claude));
            }

            let model = model_for_provider(config, task_type, BackendProvider::Anthropic);
            Ok(RoutePlan {
                task_type,
                requested_provider: requested,
                provider: BackendProvider::Anthropic,
                model,
                auto_routed: false,
            })
        }
        ProviderSelection::Gpt => {
            if config.openai_api_key.is_none() {
                return Err(missing_provider_error(ProviderSelection::Gpt));
            }

            let model = model_for_provider(config, task_type, BackendProvider::OpenAi);
            Ok(RoutePlan {
                task_type,
                requested_provider: requested,
                provider: BackendProvider::OpenAi,
                model,
                auto_routed: false,
            })
        }
        ProviderSelection::Ollama => Err(LlmError::Configuration(
            "internal routing error".to_string(),
        )),
    }
}

fn auto_route_for_task(
    config: &Config,
    task_type: TaskType,
) -> std::result::Result<(BackendProvider, String), LlmError> {
    let preferred = preferred_route(config, task_type);
    if provider_is_configured(config, preferred.0) {
        return Ok(preferred);
    }

    let alternate_provider = alternate_provider(preferred.0);
    if provider_is_configured(config, alternate_provider) {
        let fallback_model = equivalent_model(&preferred.1, alternate_provider);
        return Ok((alternate_provider, fallback_model));
    }

    Err(LlmError::Configuration(
        "no providers configured\n    ╰─ add a key with: config set anthropic-api-key <KEY>\n                   or: config set openai-api-key <KEY>".to_string(),
    ))
}

fn preferred_route(config: &Config, task_type: TaskType) -> (BackendProvider, String) {
    let default_model = default_model_for_task(task_type);
    let provider = preferred_provider_for_task(task_type);
    let model = task_override_model(config, task_type).unwrap_or_else(|| default_model.to_string());
    (provider, model)
}

fn task_override_model(config: &Config, task_type: TaskType) -> Option<String> {
    match task_type {
        TaskType::DeepAnalysis => config.routing.deep_analysis_model.clone(),
        TaskType::CodeGeneration => config.routing.code_generation_model.clone(),
        TaskType::FastRename => config.routing.fast_rename_model.clone(),
        TaskType::Summarize => config.routing.summarize_model.clone(),
        TaskType::Explain => config.routing.explain_model.clone(),
        TaskType::Chat => config.routing.chat_model.clone(),
    }
}

fn model_for_provider(config: &Config, task_type: TaskType, provider: BackendProvider) -> String {
    let (preferred_provider, model) = preferred_route(config, task_type);
    if preferred_provider == provider {
        model
    } else {
        equivalent_model(&model, provider)
    }
}

fn fallback_route(
    config: &Config,
    primary: BackendProvider,
    primary_model: &str,
) -> Option<FallbackPlan> {
    let provider = alternate_provider(primary);
    if !provider_is_configured(config, provider) {
        return None;
    }

    Some(FallbackPlan {
        provider,
        model: equivalent_model(primary_model, provider),
    })
}

fn default_model_for_task(task_type: TaskType) -> &'static str {
    match task_type {
        TaskType::DeepAnalysis => "claude-opus-4-5",
        TaskType::CodeGeneration => "gpt-4o",
        TaskType::FastRename | TaskType::Summarize | TaskType::Explain | TaskType::Chat => {
            "claude-sonnet-4-5"
        }
    }
}

fn preferred_provider_for_task(task_type: TaskType) -> BackendProvider {
    match task_type {
        TaskType::CodeGeneration => BackendProvider::OpenAi,
        TaskType::DeepAnalysis
        | TaskType::FastRename
        | TaskType::Summarize
        | TaskType::Explain
        | TaskType::Chat => BackendProvider::Anthropic,
    }
}

fn equivalent_model(model: &str, provider: BackendProvider) -> String {
    if matches!(provider, BackendProvider::Anthropic) {
        match model {
            "gpt-4o" => "claude-sonnet-4-5".to_string(),
            "gpt-4o-mini" => "claude-haiku-4-5".to_string(),
            _ => "claude-sonnet-4-5".to_string(),
        }
    } else {
        match model {
            "claude-opus-4-5" => "gpt-4o".to_string(),
            "claude-sonnet-4-5" | "claude-haiku-4-5" => "gpt-4o-mini".to_string(),
            _ => "gpt-4o-mini".to_string(),
        }
    }
}

fn provider_is_configured(config: &Config, provider: BackendProvider) -> bool {
    match provider {
        BackendProvider::Anthropic => config.anthropic_api_key.is_some(),
        BackendProvider::OpenAi => config.openai_api_key.is_some(),
    }
}

fn alternate_provider(provider: BackendProvider) -> BackendProvider {
    match provider {
        BackendProvider::Anthropic => BackendProvider::OpenAi,
        BackendProvider::OpenAi => BackendProvider::Anthropic,
    }
}

fn missing_provider_error(provider: ProviderSelection) -> LlmError {
    match provider {
        ProviderSelection::Claude => LlmError::Configuration(
            "provider 'claude' is not configured\n    ╰─ anthropic_api_key is not set\n       add it with: config set anthropic-api-key <KEY>".to_string(),
        ),
        ProviderSelection::Gpt => LlmError::Configuration(
            "provider 'gpt' is not configured\n    ╰─ openai_api_key is not set\n       add it with: config set openai-api-key <KEY>".to_string(),
        ),
        ProviderSelection::Auto | ProviderSelection::Ollama => {
            LlmError::Configuration("provider is not configured".to_string())
        }
    }
}

#[cfg(test)]
mod tests {
    use endeavour_core::config::RoutingConfig;

    use super::{BackendProvider, LlmRouter, ProviderSelection, RouterNotice, TaskType};
    use crate::LlmError;

    #[test]
    fn provider_parser_rejects_unknown_provider() {
        let parsed = ProviderSelection::parse("bedrock");
        assert!(matches!(
            parsed,
            Err(LlmError::Configuration(message))
                if message.contains("unknown provider 'bedrock'") && message.contains("valid providers")
        ));
    }

    #[test]
    fn auto_routes_explain_to_anthropic_by_default() {
        let router = LlmRouter::new(
            endeavour_core::config::Config {
                anthropic_api_key: Some("sk-ant-test".to_string()),
                ..endeavour_core::config::Config::default()
            },
            TaskType::Explain,
            Some(ProviderSelection::Auto),
            true,
        );
        assert!(router.is_ok());
        let router = match router {
            Ok(router) => router,
            Err(err) => panic!("unexpected router error: {err}"),
        };
        assert_eq!(router.plan().provider, BackendProvider::Anthropic);
        assert_eq!(router.plan().model, "claude-sonnet-4-5");
        assert!(router.plan().auto_routed);
    }

    #[test]
    fn auto_routes_to_openai_when_anthropic_key_missing() {
        let router = LlmRouter::new(
            endeavour_core::config::Config {
                openai_api_key: Some("sk-openai-test".to_string()),
                ..endeavour_core::config::Config::default()
            },
            TaskType::Explain,
            Some(ProviderSelection::Auto),
            true,
        );
        assert!(router.is_ok());
        let router = match router {
            Ok(router) => router,
            Err(err) => panic!("unexpected router error: {err}"),
        };
        assert_eq!(router.plan().provider, BackendProvider::OpenAi);
        assert_eq!(router.plan().model, "gpt-4o-mini");
    }

    #[test]
    fn ollama_selection_emits_notice_and_falls_back_to_auto() {
        let router = LlmRouter::new(
            endeavour_core::config::Config {
                anthropic_api_key: Some("sk-ant-test".to_string()),
                ..endeavour_core::config::Config::default()
            },
            TaskType::DeepAnalysis,
            Some(ProviderSelection::Ollama),
            true,
        );
        assert!(router.is_ok());
        let router = match router {
            Ok(router) => router,
            Err(err) => panic!("unexpected router error: {err}"),
        };
        assert_eq!(router.notice(), Some(RouterNotice::OllamaNotImplemented));
        assert!(router.plan().auto_routed);
    }

    #[test]
    fn explain_model_override_is_applied() {
        let router = LlmRouter::new(
            endeavour_core::config::Config {
                anthropic_api_key: Some("sk-ant-test".to_string()),
                routing: RoutingConfig {
                    explain_model: Some("claude-haiku-4-5".to_string()),
                    ..RoutingConfig::default()
                },
                ..endeavour_core::config::Config::default()
            },
            TaskType::Explain,
            Some(ProviderSelection::Auto),
            true,
        );
        assert!(router.is_ok());
        let router = match router {
            Ok(router) => router,
            Err(err) => panic!("unexpected router error: {err}"),
        };
        assert_eq!(router.plan().model, "claude-haiku-4-5");
    }
}
