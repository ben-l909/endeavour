use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::{collections::HashMap, collections::HashSet};

use crate::fmt;
use anyhow::{Context, Result};
use clap::Parser;
use endeavour_core::config::Config;
use endeavour_core::store::SessionStore;
use endeavour_core::{
    loader, NewReviewQueueRecord, NewTranscriptRecord, ReviewQueueRecord, Session,
};
use endeavour_ida::{DecompileResult, IdaClient, IdaError, Transport};
use endeavour_llm::{
    AgenticLoopConfig, AgenticLoopController, AnthropicProvider, CompletionRequest, ContextBuilder,
    FunctionContext, IdaToolExecutor, LlmError, LlmProvider, LlmRouter, Message, OpenAiProvider,
    ProviderSelection, Role, RouterNotice, TaskType, ToolCall, ToolResult, TranscriptContent,
    Usage,
};
use reedline::{DefaultPrompt, DefaultPromptSegment, FileBackedHistory, Reedline, Signal};
use serde::{Deserialize, Serialize};
use tokio::runtime::Runtime;

const HISTORY_CAPACITY: usize = 500;

pub struct Repl {
    editor: Reedline,
    store: SessionStore,
    active_session: Option<Session>,
    ida_client: Option<Arc<IdaClient>>,
    runtime: Runtime,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ErrorCategory {
    Input,
    Connectivity,
    Configuration,
    Provider,
    Internal,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct UserFacingError {
    category: ErrorCategory,
    summary: String,
    detail: String,
    recovery_hint: Option<String>,
}

impl UserFacingError {
    fn new(
        category: ErrorCategory,
        summary: impl Into<String>,
        detail: impl Into<String>,
        recovery_hint: Option<String>,
    ) -> Self {
        Self {
            category,
            summary: summary.into(),
            detail: detail.into(),
            recovery_hint,
        }
    }

    fn from_anyhow(err: &anyhow::Error) -> Self {
        if let Some(session_input) = extract_invalid_session_id_input(err) {
            return Self::new(
                ErrorCategory::Input,
                "invalid session ID",
                format!("'{session_input}' is not a valid UUID"),
                Some("run 'sessions' to list available session IDs".to_string()),
            );
        }

        if contains_error_text(err, "no active session") {
            return Self::new(
                ErrorCategory::Input,
                "no active session",
                "run 'session new' to start a session",
                None,
            );
        }

        if contains_error_text(err, "method not found") || contains_error_text(err, "-32601") {
            return Self::new(
                ErrorCategory::Connectivity,
                "IDA connection failed",
                "Method not found (code -32601). Check that the IDA MCP plugin is loaded.",
                None,
            );
        }

        if contains_error_text(err, "connection refused") {
            return Self::new(
                ErrorCategory::Connectivity,
                "IDA connection failed",
                "connection refused. Is IDA running with the MCP plugin?",
                None,
            );
        }

        if let Some(io_error) = find_error_in_chain::<std::io::Error>(err) {
            if io_error.kind() == std::io::ErrorKind::NotFound {
                return Self::new(
                    ErrorCategory::Input,
                    "file not found",
                    io_error.to_string(),
                    Some("check the path and try again".to_string()),
                );
            }
        }

        if let Some(llm_error) = find_error_in_chain::<LlmError>(err) {
            return match llm_error {
                LlmError::Configuration(message) => Self::new(
                    ErrorCategory::Configuration,
                    "configuration error",
                    message,
                    None,
                ),
                LlmError::AuthFailed => Self::new(
                    ErrorCategory::Provider,
                    "provider authentication failed",
                    "authentication failed",
                    Some("check your API key and retry".to_string()),
                ),
                LlmError::RateLimited { .. } => Self::new(
                    ErrorCategory::Provider,
                    "provider request failed",
                    "rate limit exceeded",
                    Some("retry shortly or use a fallback provider".to_string()),
                ),
                LlmError::ContextWindowExceeded => Self::new(
                    ErrorCategory::Provider,
                    "context window exceeded",
                    "input is too large for the selected model",
                    Some("try a smaller function or a model with larger context".to_string()),
                ),
                _ => Self::new(
                    ErrorCategory::Provider,
                    "provider request failed",
                    llm_error.to_string(),
                    None,
                ),
            };
        }

        if find_error_in_chain::<IdaError>(err).is_some() {
            return Self::new(
                ErrorCategory::Connectivity,
                "IDA request failed",
                err.to_string(),
                Some("run 'connect <host:port>' to reconnect".to_string()),
            );
        }

        Self::new(
            ErrorCategory::Internal,
            "command failed",
            err.to_string(),
            None,
        )
    }
}

impl From<anyhow::Error> for UserFacingError {
    fn from(value: anyhow::Error) -> Self {
        Self::from_anyhow(&value)
    }
}

#[derive(Debug, PartialEq, Eq)]
enum ReplCommand {
    Help,
    Analyze(String),
    Connect(Option<String>),
    IdaStatus,
    Decompile(String),
    Explain(ExplainCommand),
    Rename(RenameCommand),
    Review,
    Comment(String, String),
    Callgraph(String, Option<u32>),
    Search(String),
    Sessions,
    Session(String),
    Info,
    Findings,
    CacheStats,
    CacheClear,
    ConfigSet { key: String, value: String },
    ConfigGet(String),
    ConfigList,
    ShowTranscript(ShowTranscriptCommand),
    Quit,
}

#[derive(Debug, Clone, Parser, PartialEq, Eq)]
struct ExplainCommand {
    target: String,
    #[arg(long, default_value = "auto")]
    provider: String,
    #[arg(long)]
    no_fallback: bool,
}

#[derive(Debug, Clone, Parser, PartialEq, Eq)]
struct RenameCommand {
    target: Option<String>,
    new_name: Option<String>,
    #[arg(long, default_value_t = false)]
    llm: bool,
    #[arg(long, default_value_t = false)]
    all: bool,
    #[arg(long, default_value = "auto")]
    provider: String,
    #[arg(long)]
    no_fallback: bool,
}

#[derive(Debug, Clone, Parser, PartialEq, Eq)]
struct ShowTranscriptCommand {
    session_id: Option<String>,
    #[arg(long)]
    turn: Option<u32>,
}

#[derive(Debug, PartialEq, Eq)]
enum ParsedLine {
    Empty,
    Command(ReplCommand),
    Unknown(String),
    InvalidUsage(&'static str),
}

#[derive(Debug, Clone, Deserialize, Serialize)]
struct RenameLlmResponse {
    function_rename: FunctionRenamePayload,
    variable_renames: Vec<VariableRenamePayload>,
    comments: Vec<CommentPayload>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
struct FunctionRenamePayload {
    proposed_name: Option<String>,
    confidence: f64,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
struct VariableRenamePayload {
    current_name: String,
    proposed_name: String,
    confidence: f64,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
struct CommentPayload {
    addr: String,
    text: String,
    confidence: f64,
}

#[derive(Debug, Clone)]
enum RenameSuggestionKind {
    Function,
    Variable,
    Comment,
}

#[derive(Debug, Clone)]
struct RenameSuggestion {
    kind: RenameSuggestionKind,
    function_addr: u64,
    target_addr: u64,
    current_name: String,
    proposed_value: String,
    confidence: f64,
}

#[derive(Debug, Default, Clone, Copy)]
struct TierCounters {
    applied: u32,
    queued: u32,
    discarded: u32,
    errors: u32,
}

const RENAME_SYSTEM_PROMPT: &str = "You are an expert reverse engineering assistant focused on naming. Return only JSON matching this schema: {\"function_rename\": {\"proposed_name\": \"string | null\", \"confidence\": 0.0}, \"variable_renames\": [{\"current_name\": \"string\", \"proposed_name\": \"string\", \"confidence\": 0.0}], \"comments\": [{\"addr\": \"0x401000\", \"text\": \"string\", \"confidence\": 0.0}]}. Rules: top-level keys must be exactly function_rename, variable_renames, comments; confidence must be in [0,1]; proposed identifiers must match ^[a-zA-Z_][a-zA-Z0-9_]*$; comment addr must match ^0x[0-9a-f]+$; max 20 variable renames and max 10 comments. Return only the JSON object with no markdown or prose.";

impl Repl {
    pub fn new(store: SessionStore) -> Result<Self> {
        let runtime = Runtime::new().context("failed to initialize tokio runtime for REPL")?;

        Ok(Self {
            editor: Reedline::create(),
            store,
            active_session: None,
            ida_client: None,
            runtime,
        })
    }

    pub fn run(&mut self) -> Result<()> {
        let history_path = history_path()?;
        self.editor = create_editor(&history_path)?;

        println!("Welcome to endeavour REPL v{}", env!("CARGO_PKG_VERSION"));
        println!("Type 'help' to see available commands.");

        loop {
            let prompt = self.prompt();
            match self
                .editor
                .read_line(&prompt)
                .context("failed to read REPL input")?
            {
                Signal::Success(buffer) => match parse_command(buffer.trim()) {
                    ParsedLine::Empty => {}
                    ParsedLine::Command(ReplCommand::Help) => print_help(),
                    ParsedLine::Command(ReplCommand::Analyze(path)) => {
                        match self.handle_analyze(&path) {
                            Ok(()) => {}
                            Err(err) => self.render_user_error(UserFacingError::from(err)),
                        }
                    }
                    ParsedLine::Command(ReplCommand::Connect(target)) => {
                        match self.handle_connect(target.as_deref()) {
                            Ok(()) => {}
                            Err(err) => self.render_user_error(UserFacingError::from(err)),
                        }
                    }
                    ParsedLine::Command(ReplCommand::IdaStatus) => match self.handle_ida_status() {
                        Ok(()) => {}
                        Err(err) => self.render_user_error(UserFacingError::from(err)),
                    },
                    ParsedLine::Command(ReplCommand::Decompile(target)) => {
                        self.handle_decompile(&target);
                    }
                    ParsedLine::Command(ReplCommand::Explain(command)) => {
                        match self.handle_explain(&command) {
                            Ok(()) => {}
                            Err(err) => self.render_user_error(UserFacingError::from(err)),
                        }
                    }
                    ParsedLine::Command(ReplCommand::Rename(command)) => {
                        match self.handle_rename(&command) {
                            Ok(()) => {}
                            Err(err) => self.render_user_error(UserFacingError::from(err)),
                        }
                    }
                    ParsedLine::Command(ReplCommand::Review) => match self.handle_review() {
                        Ok(()) => {}
                        Err(err) => self.render_user_error(UserFacingError::from(err)),
                    },
                    ParsedLine::Command(ReplCommand::Comment(target, comment)) => {
                        match self.handle_comment(&target, &comment) {
                            Ok(()) => {}
                            Err(err) => self.render_user_error(UserFacingError::from(err)),
                        }
                    }
                    ParsedLine::Command(ReplCommand::Callgraph(target, max_depth)) => {
                        match self.handle_callgraph(&target, max_depth) {
                            Ok(()) => {}
                            Err(err) => self.render_user_error(UserFacingError::from(err)),
                        }
                    }
                    ParsedLine::Command(ReplCommand::Search(pattern)) => {
                        match self.handle_search(&pattern) {
                            Ok(()) => {}
                            Err(err) => self.render_user_error(UserFacingError::from(err)),
                        }
                    }
                    ParsedLine::Command(ReplCommand::Sessions) => match self.handle_sessions() {
                        Ok(()) => {}
                        Err(err) => self.render_user_error(UserFacingError::from(err)),
                    },
                    ParsedLine::Command(ReplCommand::Session(id)) => {
                        match self.handle_session_switch(&id) {
                            Ok(()) => {}
                            Err(err) => self.render_user_error(UserFacingError::from(err)),
                        }
                    }
                    ParsedLine::Command(ReplCommand::Info) => match self.handle_info() {
                        Ok(()) => {}
                        Err(err) => self.render_user_error(UserFacingError::from(err)),
                    },
                    ParsedLine::Command(ReplCommand::Findings) => match self.handle_findings() {
                        Ok(()) => {}
                        Err(err) => self.render_user_error(UserFacingError::from(err)),
                    },
                    ParsedLine::Command(ReplCommand::CacheStats) => {
                        match self.handle_cache_stats() {
                            Ok(()) => {}
                            Err(err) => self.render_user_error(UserFacingError::from(err)),
                        }
                    }
                    ParsedLine::Command(ReplCommand::CacheClear) => {
                        match self.handle_cache_clear() {
                            Ok(()) => {}
                            Err(err) => self.render_user_error(UserFacingError::from(err)),
                        }
                    }
                    ParsedLine::Command(ReplCommand::ConfigSet { key, value }) => {
                        match self.handle_config_set(&key, &value) {
                            Ok(()) => {}
                            Err(err) => self.render_user_error(UserFacingError::from(err)),
                        }
                    }
                    ParsedLine::Command(ReplCommand::ConfigGet(key)) => {
                        match self.handle_config_get(&key) {
                            Ok(()) => {}
                            Err(err) => self.render_user_error(UserFacingError::from(err)),
                        }
                    }
                    ParsedLine::Command(ReplCommand::ConfigList) => {
                        match self.handle_config_list() {
                            Ok(()) => {}
                            Err(err) => self.render_user_error(UserFacingError::from(err)),
                        }
                    }
                    ParsedLine::Command(ReplCommand::ShowTranscript(command)) => {
                        match self.handle_show_transcript(&command) {
                            Ok(()) => {}
                            Err(err) => self.render_user_error(UserFacingError::from(err)),
                        }
                    }
                    ParsedLine::Command(ReplCommand::Quit) => break,
                    ParsedLine::Unknown(cmd) => {
                        self.render_user_error(UserFacingError::new(
                            ErrorCategory::Input,
                            format!("unknown command '{cmd}'"),
                            "type 'help' to see available commands",
                            None,
                        ));
                    }
                    ParsedLine::InvalidUsage(usage) => {
                        self.render_user_error(UserFacingError::new(
                            ErrorCategory::Input,
                            "missing argument",
                            format!("usage: {usage}"),
                            None,
                        ));
                    }
                },
                Signal::CtrlC => {}
                Signal::CtrlD => break,
            }
        }

        Ok(())
    }

    fn prompt(&self) -> DefaultPrompt {
        let mut prompt_name = String::from("endeavour");

        if let Some(session) = &self.active_session {
            prompt_name.push('[');
            prompt_name.push_str(&session.name);
            prompt_name.push(']');
        }

        if self.ida_client.is_some() {
            prompt_name.push_str("[ida]");
        }

        DefaultPrompt::new(
            DefaultPromptSegment::Basic(prompt_name),
            DefaultPromptSegment::Basic("◆".to_string()),
        )
    }

    fn render_user_error(&self, error: UserFacingError) {
        let _ = error.category;
        println!("✗ error: {}", error.summary);
        println!("    ╰─ {}", error.detail);
        if let Some(hint) = error.recovery_hint {
            println!("    ╰─ hint: {hint}");
        }
    }

    fn handle_analyze(&mut self, input_path: &str) -> Result<()> {
        let path = PathBuf::from(input_path);
        let binary = loader::load_binary(&path)
            .with_context(|| format!("failed to load binary at {}", path.display()))?;

        let session_name = path
            .file_name()
            .and_then(|name| name.to_str())
            .map_or_else(|| path.display().to_string(), ToString::to_string);

        let session = self
            .store
            .create_session(&session_name, binary.uuid)
            .context("failed to create analysis session")?;

        println!(
            "Loaded {} and created session {} ({})",
            path.display(),
            session.name,
            session.id
        );

        self.active_session = Some(session);
        Ok(())
    }

    fn handle_connect(&mut self, endpoint: Option<&str>) -> Result<()> {
        let endpoint = endpoint.unwrap_or("localhost:13337");
        let (host, port) = parse_host_port(endpoint)?;
        let transport = Arc::new(endeavour_ida::HttpTransport::new(&host, port));

        self.handle_connect_with_transport(endpoint, transport)
    }

    fn handle_connect_with_transport(
        &mut self,
        endpoint: &str,
        transport: Arc<dyn Transport>,
    ) -> Result<()> {
        let (host, port) = parse_host_port(endpoint)?;
        let normalized_endpoint = format!("{host}:{port}");

        let (client, functions) = match connect_with_transport(
            &self.runtime,
            &normalized_endpoint,
            transport,
        ) {
            Ok(result) => result,
            Err(err) => {
                if let Some(connect_error) = classify_connect_error(&err) {
                    match connect_error {
                        ConnectError::MethodNotFound => print_error(
                            "IDA connection failed",
                            &["Method not found (code -32601). Check that the IDA MCP plugin is loaded."],
                        ),
                        ConnectError::ConnectionRefused => print_error(
                            "IDA connection failed",
                            &["connection refused. Is IDA running with the MCP plugin?"],
                        ),
                    }
                    return Ok(());
                }

                return Err(err);
            }
        };

        self.ida_client = Some(client);
        save_ida_endpoint(&normalized_endpoint)?;

        if let Some(function) = functions.first() {
            println!(
                "Connected to IDA at {normalized_endpoint}. Sample function: {} @ 0x{:x}",
                function.name, function.address
            );
        } else {
            println!("Connected to IDA at {normalized_endpoint}. No functions returned.");
        }

        Ok(())
    }

    fn handle_ida_status(&self) -> Result<()> {
        let Some(client) = self.ida_client.as_ref() else {
            println!("Not connected. Run: connect <host:port>");
            return Ok(());
        };

        let functions = self
            .runtime
            .block_on(client.list_functions(None, Some(1)))
            .context("failed to query IDA status")?;

        if let Some(function) = functions.first() {
            println!(
                "IDA connection active (sample function: {} @ 0x{:x})",
                function.name, function.address
            );
        } else {
            println!("IDA connection active (no functions returned).");
        }

        Ok(())
    }

    fn handle_decompile(&self, target: &str) {
        let Some(client) = self.ida_client.as_ref() else {
            println!("Not connected. Run: connect <host:port>");
            return;
        };

        let (address, function_name) =
            match resolve_target_address(&self.runtime, client.as_ref(), target) {
                Ok(value) => value,
                Err(_) => {
                    println!("No function at address");
                    return;
                }
            };

        let session_id = self.active_session.as_ref().map(|session| session.id);

        let cached_result = session_id
            .and_then(|id| {
                self.store
                    .get_cached_ida_result(id, "decompile", address)
                    .ok()
                    .flatten()
            })
            .and_then(|payload| serde_json::from_str::<DecompileResult>(&payload).ok());

        let result = if let Some(cached) = cached_result {
            cached
        } else {
            let fetched = match self.runtime.block_on(client.decompile(address)) {
                Ok(value) => value,
                Err(_) => {
                    println!("No function at address");
                    return;
                }
            };

            if let Some(id) = session_id {
                if let Ok(serialized) = serde_json::to_string(&fetched) {
                    let _ = self
                        .store
                        .cache_ida_result(id, "decompile", address, &serialized);
                }
            }

            fetched
        };

        println!("{}", render_decompile_result(&function_name, &result));
    }

    fn handle_explain(&self, command: &ExplainCommand) -> Result<()> {
        let Some(client) = self.ida_client.as_ref() else {
            println!("Not connected. Run: connect <host:port>");
            return Ok(());
        };

        let (address, function_name) =
            match resolve_target_address(&self.runtime, client.as_ref(), &command.target) {
                Ok(value) => value,
                Err(err) => {
                    println!("Failed to resolve target '{}': {err}", command.target);
                    return Ok(());
                }
            };

        let decompile_result = match self.runtime.block_on(client.decompile(address)) {
            Ok(value) => value,
            Err(err) if is_missing_function_error(&err) => {
                println!("No function at address");
                return Ok(());
            }
            Err(err) => {
                println!("Failed to decompile {}: {err}", fmt::format_addr(address));
                return Ok(());
            }
        };

        println!("Analyzing function at {}...", fmt::format_addr(address));

        let config = Config::load().context("failed to load config")?;
        let provider = match ProviderSelection::parse(&command.provider) {
            Ok(value) => Some(value),
            Err(LlmError::Configuration(message)) => {
                println!("✗ error: {message}");
                return Ok(());
            }
            Err(err) => {
                println!("✗ error: {}", format_llm_error(&err));
                return Ok(());
            }
        };

        let router = match LlmRouter::new(
            config.clone(),
            TaskType::Explain,
            provider,
            !command.no_fallback,
        ) {
            Ok(router) => router,
            Err(LlmError::Configuration(message)) => {
                println!("✗ error: {message}");
                return Ok(());
            }
            Err(err) => {
                println!("✗ error: {}", format_llm_error(&err));
                return Ok(());
            }
        };

        if matches!(router.notice(), Some(RouterNotice::OllamaNotImplemented)) {
            println!("  ● INFO  ollama support is planned but not yet available");
            println!("    ╰─ falling back to auto-routing");
        }

        if router.plan().auto_routed {
            println!(
                "  ● INFO  routing to {} via {} (task: explain)",
                router.plan().model,
                router.plan().provider.as_str()
            );
        } else {
            println!(
                "  ● INFO  using {} via {}",
                router.plan().model,
                router.plan().provider.as_str()
            );
        }

        let request = build_explain_request(&function_name, &decompile_result);
        let completion = match self.runtime.block_on(router.complete(request)) {
            Ok(value) => value,
            Err(LlmError::RateLimited { .. }) if command.no_fallback => {
                println!("✗ error: provider request failed (fallback disabled)");
                println!(
                    "    ╰─ {}: 429 rate limit exceeded",
                    router.plan().provider.as_str()
                );
                println!(
                    "       re-run without --no-fallback to use {} as fallback",
                    if router.plan().provider.as_str() == "anthropic" {
                        "openai"
                    } else {
                        "anthropic"
                    }
                );
                return Ok(());
            }
            Err(err) => {
                println!("Explain request failed: {}", format_llm_error(&err));
                return Ok(());
            }
        };

        if let Some(fallback) = &completion.fallback {
            println!(
                "▲ warn: {} rate limited. Falling back to {} via {}. (--no-fallback to disable)",
                fallback.primary_provider.as_str(),
                fallback.fallback_model,
                fallback.fallback_provider.as_str()
            );
        }

        println!(
            "{}",
            render_explain_result(
                &function_name,
                address,
                &completion.response.model,
                &completion.response.content,
            )
        );
        Ok(())
    }

    fn handle_rename(&mut self, command: &RenameCommand) -> Result<()> {
        if command.all {
            return self.handle_rename_all(command);
        }

        let Some(target) = command.target.as_deref() else {
            println!("Usage: rename <addr> <new_name> | rename --llm <addr> | rename --all");
            return Ok(());
        };

        let run_llm = command.llm || command.new_name.is_none();
        if run_llm {
            return self.handle_rename_llm_single(target, command);
        }

        let Some(new_name) = command.new_name.as_deref() else {
            println!("Usage: rename <addr> <new_name>");
            return Ok(());
        };

        self.handle_manual_rename(target, new_name)
    }

    fn handle_manual_rename(&self, target: &str, new_name: &str) -> Result<()> {
        let Some(client) = self.ida_client.as_ref() else {
            println!("Not connected. Run: connect <host:port>");
            return Ok(());
        };

        let (address, _) = match resolve_target_address(&self.runtime, client.as_ref(), target) {
            Ok(value) => value,
            Err(err) => {
                println!("{}", format_resolve_target_error(target, &err));
                return Ok(());
            }
        };

        match rename_symbol(&self.runtime, client.as_ref(), address, new_name) {
            Ok(()) => println!("Renamed {} → {}", fmt::format_addr(address), new_name),
            Err(err) => println!("Failed to rename function: {err}"),
        }

        Ok(())
    }

    fn handle_rename_llm_single(&mut self, target: &str, command: &RenameCommand) -> Result<()> {
        let Some(session) = self.active_session.as_ref() else {
            print_error(
                "no active session",
                &["Run 'analyze <path>' or 'session <id>' to set an active session first."],
            );
            return Ok(());
        };

        let Some(client) = self.ida_client.as_ref() else {
            print_error(
                "IDA Pro is not connected",
                &[
                    "'rename --llm' requires an active IDA connection.",
                    "Run 'connect' to connect, then retry.",
                ],
            );
            return Ok(());
        };

        let (function_addr, function_name) =
            match resolve_target_address(&self.runtime, client, target) {
                Ok(value) => value,
                Err(err) => {
                    println!("{}", format_resolve_target_error(target, &err));
                    return Ok(());
                }
            };

        let decompile_result = match self.runtime.block_on(client.decompile(function_addr)) {
            Ok(value) => value,
            Err(err) => {
                println!("✗ error: decompile failed: {err}");
                return Ok(());
            }
        };

        let config = Config::load().context("failed to load config")?;
        let provider_selection = match ProviderSelection::parse(&command.provider) {
            Ok(value) => Some(value),
            Err(LlmError::Configuration(message)) => {
                print_error(&message, &[]);
                return Ok(());
            }
            Err(err) => {
                print_error(&format_llm_error(&err), &[]);
                return Ok(());
            }
        };

        let router = match LlmRouter::new(
            config.clone(),
            TaskType::FastRename,
            provider_selection,
            !command.no_fallback,
        ) {
            Ok(value) => value,
            Err(LlmError::Configuration(message)) => {
                let lower = message.to_ascii_lowercase();
                if lower.contains("no providers configured") {
                    print_error(
                        "no LLM provider configured",
                        &["Run 'config set anthropic-api-key <key>' or 'config set openai-api-key <key>'."],
                    );
                } else {
                    print_error(&message, &[]);
                }
                return Ok(());
            }
            Err(err) => {
                print_error(&format_llm_error(&err), &[]);
                return Ok(());
            }
        };

        let provider = match build_provider_for_plan(&config, router.plan().provider) {
            Ok(value) => value,
            Err(message) => {
                print_error(&message, &[]);
                return Ok(());
            }
        };

        println!(
            "  Analyzing {} ({}) via {}...",
            function_name,
            fmt::format_addr(function_addr),
            router.plan().model
        );

        let llm_result_result = match &provider {
            RenameProvider::Anthropic(provider) => self.runtime.block_on(run_rename_agentic_loop(
                provider,
                client.clone(),
                &router.plan().model,
                function_addr,
                &function_name,
                &decompile_result.pseudocode,
            )),
            RenameProvider::OpenAi(provider) => self.runtime.block_on(run_rename_agentic_loop(
                provider,
                client.clone(),
                &router.plan().model,
                function_addr,
                &function_name,
                &decompile_result.pseudocode,
            )),
        };
        let llm_result = match llm_result_result {
            Ok(value) => value,
            Err(err) => {
                print_error("rename analysis failed", &[&format_llm_error(&err)]);
                return Ok(());
            }
        };

        let response = match parse_rename_json_payload(&llm_result.final_text) {
            Ok(value) => value,
            Err(message) => {
                print_error("LLM returned malformed JSON", &[&message]);
                return Ok(());
            }
        };

        persist_agentic_transcript(&self.store, session.id, &llm_result)?;

        let suggestions = match build_suggestions(
            function_addr,
            &function_name,
            response,
            &self.store,
            session.id,
        ) {
            Ok(value) => value,
            Err(message) => {
                print_error("LLM response failed validation", &[&message]);
                return Ok(());
            }
        };

        let counters = self.apply_suggestions_and_render(session.id, client, suggestions)?;
        println!(
            "\n  Applied: {}   Queued: {}   Discarded: {}",
            counters.applied, counters.queued, counters.discarded
        );
        if counters.queued > 0 {
            println!("\n  Run 'review' to inspect queued suggestions.");
        }

        Ok(())
    }

    fn handle_rename_all(&mut self, command: &RenameCommand) -> Result<()> {
        let Some(session) = self.active_session.as_ref() else {
            print_error(
                "no active session",
                &["Run 'analyze <path>' or 'session <id>' to set an active session first."],
            );
            return Ok(());
        };

        let Some(client) = self.ida_client.as_ref() else {
            print_error(
                "IDA Pro is not connected",
                &[
                    "'rename --llm' requires an active IDA connection.",
                    "Run 'connect' to connect, then retry.",
                ],
            );
            return Ok(());
        };

        let config = Config::load().context("failed to load config")?;
        let provider_selection = ProviderSelection::parse(&command.provider).ok();
        let router = match LlmRouter::new(
            config.clone(),
            TaskType::FastRename,
            provider_selection,
            !command.no_fallback,
        ) {
            Ok(value) => value,
            Err(err) => {
                print_error(&format_llm_error(&err), &[]);
                return Ok(());
            }
        };

        let provider = match build_provider_for_plan(&config, router.plan().provider) {
            Ok(value) => value,
            Err(message) => {
                print_error(&message, &[]);
                return Ok(());
            }
        };

        let all_functions = self.runtime.block_on(client.list_functions(None, None))?;
        let generic_functions: Vec<_> = all_functions
            .into_iter()
            .filter(|f| is_generic_function_name(&f.name))
            .collect();

        println!(
            "  Found {} functions with generic names. Starting LLM rename...\n",
            generic_functions.len()
        );

        let mut totals = TierCounters::default();
        let mut skipped = 0u32;

        for (index, function) in generic_functions.iter().enumerate() {
            let current = index as u32 + 1;
            let total = generic_functions.len() as u32;
            let decompile_result = match self.runtime.block_on(client.decompile(function.address)) {
                Ok(value) => value,
                Err(err) => {
                    totals.errors += 1;
                    println!(
                        "  [{}/{}]  {}  {}  ->  ✗ decompile failed: {}",
                        current,
                        total,
                        fmt::format_addr(function.address),
                        function.name,
                        err
                    );
                    continue;
                }
            };

            let llm_result_result = match &provider {
                RenameProvider::Anthropic(provider) => {
                    self.runtime.block_on(run_rename_agentic_loop(
                        provider,
                        client.clone(),
                        &router.plan().model,
                        function.address,
                        &function.name,
                        &decompile_result.pseudocode,
                    ))
                }
                RenameProvider::OpenAi(provider) => self.runtime.block_on(run_rename_agentic_loop(
                    provider,
                    client.clone(),
                    &router.plan().model,
                    function.address,
                    &function.name,
                    &decompile_result.pseudocode,
                )),
            };
            let llm_result = match llm_result_result {
                Ok(value) => value,
                Err(err) => {
                    totals.errors += 1;
                    println!(
                        "  [{}/{}]  {}  {}  ->  ✗ {}",
                        current,
                        total,
                        fmt::format_addr(function.address),
                        function.name,
                        format_llm_error(&err)
                    );
                    continue;
                }
            };

            let response = match parse_rename_json_payload(&llm_result.final_text) {
                Ok(value) => value,
                Err(_) => {
                    totals.errors += 1;
                    println!(
                        "  [{}/{}]  {}  {}  ->  ✗ error: malformed LLM response (saved to debug log)",
                        current,
                        total,
                        fmt::format_addr(function.address),
                        function.name,
                    );
                    continue;
                }
            };

            persist_agentic_transcript(&self.store, session.id, &llm_result)?;

            let suggestions = match build_suggestions(
                function.address,
                &function.name,
                response,
                &self.store,
                session.id,
            ) {
                Ok(value) => value,
                Err(_) => {
                    totals.errors += 1;
                    println!(
                        "  [{}/{}]  {}  {}  ->  ✗ error: malformed LLM response (saved to debug log)",
                        current,
                        total,
                        fmt::format_addr(function.address),
                        function.name,
                    );
                    continue;
                }
            };

            let function_result =
                self.apply_suggestions_without_detail(session.id, client, suggestions)?;
            totals.applied += function_result.applied;
            totals.queued += function_result.queued;
            totals.discarded += function_result.discarded;
            totals.errors += function_result.errors;

            if let Some((name, confidence, marker)) = function_result.function_line {
                println!(
                    "  [{}/{}]  {}  {}  ->  {}  ({:.2})  {}",
                    current,
                    total,
                    fmt::format_addr(function.address),
                    function.name,
                    name,
                    confidence,
                    marker
                );
            } else {
                skipped += 1;
                println!(
                    "  [{}/{}]  {}  {}  ->  (no rename suggested)",
                    current,
                    total,
                    fmt::format_addr(function.address),
                    function.name,
                );
            }
        }

        println!("\n  {}", "═".repeat(88));
        println!("\n  Batch complete.");
        if totals.errors > 0 {
            println!(
                "  Applied: {}   Queued: {}   Discarded: {}   Errors: {}   Skipped (no suggestion): {}",
                totals.applied, totals.queued, totals.discarded, totals.errors, skipped
            );
            println!(
                "\n  {} functions failed. Run 'findings' to see error details.",
                totals.errors
            );
        } else {
            println!(
                "  Applied: {}   Queued: {}   Discarded: {}   Skipped (no suggestion): {}",
                totals.applied, totals.queued, totals.discarded, skipped
            );
        }
        if totals.queued > 0 {
            println!(
                "\n  Run 'review' to inspect {} queued suggestions.",
                totals.queued
            );
        }

        Ok(())
    }

    fn handle_review(&mut self) -> Result<()> {
        let Some(session) = self.active_session.as_ref() else {
            print_error(
                "no active session",
                &["Run 'analyze <path>' or 'session <id>' to set an active session first."],
            );
            return Ok(());
        };

        loop {
            let pending = self.store.list_pending_review_queue(session.id)?;
            if pending.is_empty() {
                println!("\n  No pending suggestions. Queue is empty.");
                return Ok(());
            }

            println!("\n  Review Queue  ({} pending)", pending.len());
            println!("  {}", "═".repeat(88));
            println!("\n   #   Address       Current Name    Proposed Name     Confidence");
            println!("  {}", "─".repeat(84));
            for (index, item) in pending.iter().enumerate() {
                println!(
                    "  {:>2}   {:<12}  {:<14}  {:<16}  {:.2}",
                    index + 1,
                    fmt::format_addr(item.target_addr.unwrap_or(item.function_addr)),
                    truncate_for_review(&item.current_name, 14),
                    truncate_for_review(&item.proposed_value, 16),
                    item.confidence
                );
            }
            println!("\n  {}", "═".repeat(88));
            println!("\n  Commands: [a]ccept  [r]eject  [A]ccept all  [R]eject all  [q]uit");
            let input = read_prompt("  Enter number to select, or command: ")?;

            match input.as_str() {
                "q" => return Ok(()),
                "A" => {
                    let result = self.accept_all_review(session.id, &pending)?;
                    println!("\n  ✓ Accepted {} suggestions. Applied to IDA.", result.0);
                    if result.1 > 0 {
                        println!(
                            "  ✗ {} item was rejected by IDA — see transcript for details.",
                            result.1
                        );
                    }
                }
                "R" => {
                    let changed = self
                        .store
                        .update_all_review_queue_status(session.id, "pending", "rejected")?;
                    for item in &pending {
                        log_review_rejected(&self.store, session.id, item)?;
                    }
                    println!("\n  ✗ Rejected {} suggestions. Queue cleared.", changed);
                }
                "a" => {
                    if let Some(first) = pending.first() {
                        self.apply_review_item(session.id, first)?;
                    }
                }
                "r" => {
                    if let Some(first) = pending.first() {
                        self.store
                            .update_review_queue_status(first.id, "rejected")?;
                        log_review_rejected(&self.store, session.id, first)?;
                        println!(
                            "\n  ✗ Rejected: {}  ->  {}  at {}",
                            first.current_name,
                            first.proposed_value,
                            fmt::format_addr(first.target_addr.unwrap_or(first.function_addr))
                        );
                    }
                }
                _ => {
                    if let Ok(index) = input.parse::<usize>() {
                        if index == 0 || index > pending.len() {
                            println!(
                                "\n  Invalid selection. Enter a number between 1 and {}.",
                                pending.len()
                            );
                            continue;
                        }
                        let item = &pending[index - 1];
                        println!(
                            "\n  Selected: {}  ->  {}  ({:.2})",
                            item.current_name, item.proposed_value, item.confidence
                        );
                        let action = read_prompt("  [a]ccept  [r]eject  [s]kip: ")?;
                        match action.as_str() {
                            "a" => self.apply_review_item(session.id, item)?,
                            "r" => {
                                self.store.update_review_queue_status(item.id, "rejected")?;
                                log_review_rejected(&self.store, session.id, item)?;
                                println!(
                                    "\n  ✗ Rejected: {}  ->  {}  at {}",
                                    item.current_name,
                                    item.proposed_value,
                                    fmt::format_addr(
                                        item.target_addr.unwrap_or(item.function_addr)
                                    )
                                );
                            }
                            "s" => {}
                            _ => {
                                println!("\n  Unknown command. Use [a]ccept, [r]eject, or [s]kip.")
                            }
                        }
                    } else {
                        println!(
                            "\n  Unknown command. Use [a]ccept, [r]eject, [A]ccept all, [R]eject all, or [q]uit."
                        );
                    }
                }
            }
        }
    }

    fn apply_suggestions_and_render(
        &self,
        session_id: uuid::Uuid,
        client: &IdaClient,
        suggestions: Vec<RenameSuggestion>,
    ) -> Result<TierCounters> {
        let mut counters = TierCounters::default();
        let mut applied_lines = Vec::new();
        let mut queued_lines = Vec::new();

        for suggestion in suggestions {
            match classify_confidence(suggestion.confidence) {
                ConfidenceTier::Tier1 => {
                    if apply_suggestion(&self.runtime, client, &suggestion).is_ok() {
                        counters.applied += 1;
                        applied_lines.push(render_applied_line(&suggestion));
                    } else {
                        counters.errors += 1;
                        log_ida_rejected(&self.store, session_id, &suggestion)?;
                    }
                }
                ConfidenceTier::Tier2 => {
                    counters.queued += 1;
                    queue_suggestion(&self.store, session_id, &suggestion)?;
                    queued_lines.push(render_queued_line(&suggestion));
                }
                ConfidenceTier::Tier3 => {
                    counters.discarded += 1;
                    log_discarded(&self.store, session_id, &suggestion)?;
                }
            }
        }

        if !applied_lines.is_empty() || !queued_lines.is_empty() {
            println!();
        }
        for line in applied_lines {
            println!("{line}");
        }
        for line in queued_lines {
            println!("{line}");
        }

        Ok(counters)
    }

    fn apply_suggestions_without_detail(
        &self,
        session_id: uuid::Uuid,
        client: &IdaClient,
        suggestions: Vec<RenameSuggestion>,
    ) -> Result<BatchFunctionResult> {
        let mut counters = TierCounters::default();
        let mut function_line = None;

        for suggestion in suggestions {
            match classify_confidence(suggestion.confidence) {
                ConfidenceTier::Tier1 => {
                    if apply_suggestion(&self.runtime, client, &suggestion).is_ok() {
                        counters.applied += 1;
                        if matches!(suggestion.kind, RenameSuggestionKind::Function) {
                            function_line = Some((
                                suggestion.proposed_value.clone(),
                                suggestion.confidence,
                                "✓".to_string(),
                            ));
                        }
                    } else {
                        counters.errors += 1;
                        log_ida_rejected(&self.store, session_id, &suggestion)?;
                    }
                }
                ConfidenceTier::Tier2 => {
                    counters.queued += 1;
                    queue_suggestion(&self.store, session_id, &suggestion)?;
                    if matches!(suggestion.kind, RenameSuggestionKind::Function) {
                        function_line = Some((
                            suggestion.proposed_value.clone(),
                            suggestion.confidence,
                            "~".to_string(),
                        ));
                    }
                }
                ConfidenceTier::Tier3 => {
                    counters.discarded += 1;
                    log_discarded(&self.store, session_id, &suggestion)?;
                }
            }
        }

        Ok(BatchFunctionResult {
            applied: counters.applied,
            queued: counters.queued,
            discarded: counters.discarded,
            errors: counters.errors,
            function_line,
        })
    }

    fn apply_review_item(&self, session_id: uuid::Uuid, item: &ReviewQueueRecord) -> Result<()> {
        let Some(client) = self.ida_client.as_ref() else {
            print_error(
                "IDA Pro is not connected",
                &["Cannot apply rename. Run 'connect' first, then retry 'review'."],
            );
            return Ok(());
        };

        let result = match item.kind.as_str() {
            "function_rename" => self.runtime.block_on(client.rename_function(
                item.target_addr.unwrap_or(item.function_addr),
                &item.proposed_value,
            )),
            "variable_rename" => self.runtime.block_on(client.rename_local(
                item.function_addr,
                &item.current_name,
                &item.proposed_value,
            )),
            "comment" => self.runtime.block_on(client.set_comment(
                item.target_addr.unwrap_or(item.function_addr),
                &item.proposed_value,
            )),
            _ => Ok(()),
        };

        if result.is_err() {
            print_error(
                &format!(
                    "IDA rejected rename '{}' at {}",
                    item.proposed_value,
                    fmt::format_addr(item.target_addr.unwrap_or(item.function_addr))
                ),
                &[
                    "Name may already exist or contain invalid characters.",
                    "Suggestion logged to transcript.",
                ],
            );
            return Ok(());
        }

        self.store.update_review_queue_status(item.id, "accepted")?;
        println!(
            "\n  ✓ Applied: {}  ->  {}  at {}",
            item.current_name,
            item.proposed_value,
            fmt::format_addr(item.target_addr.unwrap_or(item.function_addr))
        );
        let _ = session_id;
        Ok(())
    }

    fn accept_all_review(
        &self,
        session_id: uuid::Uuid,
        pending: &[ReviewQueueRecord],
    ) -> Result<(u32, u32)> {
        let mut applied = 0u32;
        let mut failed = 0u32;

        for item in pending {
            let before = applied;
            self.apply_review_item(session_id, item)?;
            let is_pending = self
                .store
                .list_pending_review_queue(session_id)?
                .iter()
                .any(|entry| entry.id == item.id);
            if is_pending {
                failed += 1;
            } else if applied == before {
                applied += 1;
            }
        }

        Ok((applied, failed))
    }

    fn handle_comment(&self, target: &str, comment: &str) -> Result<()> {
        let Some(client) = self.ida_client.as_ref() else {
            println!("Not connected. Run: connect <host:port>");
            return Ok(());
        };

        let (address, _) = match resolve_target_address(&self.runtime, client.as_ref(), target) {
            Ok(value) => value,
            Err(err) => {
                println!("{}", format_resolve_target_error(target, &err));
                return Ok(());
            }
        };

        match set_symbol_comment(&self.runtime, client.as_ref(), address, comment) {
            Ok(()) => println!("Comment set at {}", fmt::format_addr(address)),
            Err(err) => println!("Failed to set comment: {err}"),
        }

        Ok(())
    }

    fn handle_cache_stats(&self) -> Result<()> {
        let Some(session) = &self.active_session else {
            println!("No active session. Use 'analyze <path>' or 'session <id>'.");
            return Ok(());
        };

        let stats = self
            .store
            .cache_stats(session.id)
            .with_context(|| format!("failed to get cache stats for session {}", session.id))?;

        println!("Cache entries: {}", stats.entry_count);
        if stats.methods.is_empty() {
            println!("Cached methods: (none)");
        } else {
            println!("Cached methods: {}", stats.methods.join(", "));
        }

        Ok(())
    }

    fn handle_cache_clear(&self) -> Result<()> {
        let Some(session) = &self.active_session else {
            println!("No active session. Use 'analyze <path>' or 'session <id>'.");
            return Ok(());
        };

        self.store
            .clear_ida_cache(session.id)
            .with_context(|| format!("failed to clear cache for session {}", session.id))?;

        println!("Cleared cache for session {}", session.id);
        Ok(())
    }

    fn handle_callgraph(&self, target: &str, max_depth: Option<u32>) -> Result<()> {
        let Some(client) = self.ida_client.as_ref() else {
            println!("Not connected. Run: connect <host:port>");
            return Ok(());
        };

        let depth = max_depth.unwrap_or(3);
        let output = render_callgraph_output(&self.runtime, client.as_ref(), target, depth)?;
        println!("{output}");
        Ok(())
    }

    fn handle_search(&self, pattern: &str) -> Result<()> {
        let Some(client) = self.ida_client.as_ref() else {
            println!("Not connected. Run: connect <host:port>");
            return Ok(());
        };

        let matches = fetch_search_results(&self.runtime, client.as_ref(), pattern)?;

        if matches.is_empty() {
            println!("No results");
            return Ok(());
        }

        println!("Found {} result(s)", matches.len());
        println!("{}", render_search_output(&matches));
        Ok(())
    }

    fn handle_sessions(&self) -> Result<()> {
        let sessions = self
            .store
            .list_sessions()
            .context("failed to list sessions")?;
        if sessions.is_empty() {
            println!("No sessions found.");
            return Ok(());
        }

        println!("ID                                   NAME                    BINARY ID                            CREATED");
        for session in sessions {
            println!(
                "{}  {:<22}  {}  {}",
                session.id, session.name, session.binary_id, session.created_at
            );
        }

        Ok(())
    }

    fn handle_session_switch(&mut self, id: &str) -> Result<()> {
        let session_id = id
            .parse()
            .with_context(|| format!("invalid session id: {id}"))?;
        let session = self
            .store
            .get_session(session_id)
            .with_context(|| format!("failed to load session {id}"))?;
        println!("Active session: {} ({})", session.name, session.id);
        self.active_session = Some(session);
        Ok(())
    }

    fn handle_info(&self) -> Result<()> {
        let Some(session) = &self.active_session else {
            println!("No active session. Use 'analyze <path>' or 'session <id>'.");
            return Ok(());
        };

        let findings = self
            .store
            .get_findings(session.id)
            .with_context(|| format!("failed to fetch findings for session {}", session.id))?;

        println!("Session: {}", session.name);
        println!("Session ID: {}", session.id);
        println!("Binary ID: {}", session.binary_id);
        println!("Findings: {}", findings.len());
        Ok(())
    }

    fn handle_findings(&self) -> Result<()> {
        let Some(session) = &self.active_session else {
            println!("No active session. Use 'analyze <path>' or 'session <id>'.");
            return Ok(());
        };

        let findings = self
            .store
            .get_findings(session.id)
            .with_context(|| format!("failed to fetch findings for session {}", session.id))?;

        if findings.is_empty() {
            println!("No findings for active session.");
            return Ok(());
        }

        println!("#   PASS                VERSION   KIND                   CONFIDENCE");
        for (index, finding) in findings.iter().enumerate() {
            println!(
                "{:<3} {:<19} {:<9} {:<22} {:.2}",
                index + 1,
                finding.pass_name,
                finding.pass_version,
                format!("{:?}", finding.kind),
                finding.confidence
            );
        }

        Ok(())
    }

    fn handle_config_set(&self, key: &str, value: &str) -> Result<()> {
        let mut config = Config::load().context("failed to load config")?;
        config
            .set(key, value)
            .with_context(|| format!("failed to set config key '{key}'"))?;
        config.save().context("failed to save config")?;

        println!("Set {key} = {}", mask_config_value(key, value));
        Ok(())
    }

    fn handle_config_get(&self, key: &str) -> Result<()> {
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

    fn handle_config_list(&self) -> Result<()> {
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

    fn handle_show_transcript(&self, command: &ShowTranscriptCommand) -> Result<()> {
        let session_id = if let Some(session_id) = &command.session_id {
            session_id
                .parse()
                .with_context(|| format!("invalid session id: {session_id}"))?
        } else if let Some(active_session) = &self.active_session {
            active_session.id
        } else {
            println!("No active session. Use 'session <id>' or pass show-transcript <session_id>.");
            return Ok(());
        };

        let entries = self
            .store
            .get_transcript_entries(session_id, command.turn)
            .with_context(|| format!("failed to load transcript for session {session_id}"))?;

        if entries.is_empty() {
            println!("  ● INFO  no transcript found for session {session_id}");
            return Ok(());
        }

        println!("{}", render_transcript_output(session_id, &entries));
        Ok(())
    }
}

#[derive(Debug)]
struct BatchFunctionResult {
    applied: u32,
    queued: u32,
    discarded: u32,
    errors: u32,
    function_line: Option<(String, f64, String)>,
}

enum RenameProvider {
    Anthropic(AnthropicProvider),
    OpenAi(OpenAiProvider),
}

#[derive(Debug, Clone, Copy)]
enum ConfidenceTier {
    Tier1,
    Tier2,
    Tier3,
}

fn classify_confidence(confidence: f64) -> ConfidenceTier {
    if confidence >= 0.7 {
        ConfidenceTier::Tier1
    } else if confidence >= 0.5 {
        ConfidenceTier::Tier2
    } else {
        ConfidenceTier::Tier3
    }
}

fn is_generic_function_name(name: &str) -> bool {
    name.starts_with("sub_") || name.starts_with("j_sub_") || name.starts_with("nullsub_")
}

fn is_valid_identifier(value: &str) -> bool {
    let mut chars = value.chars();
    let Some(first) = chars.next() else {
        return false;
    };
    if !(first == '_' || first.is_ascii_alphabetic()) {
        return false;
    }
    chars.all(|ch| ch == '_' || ch.is_ascii_alphanumeric())
}

fn parse_comment_addr(value: &str) -> Option<u64> {
    let normalized = value.trim();
    if !normalized.starts_with("0x") {
        return None;
    }
    if normalized
        .chars()
        .skip(2)
        .any(|ch| !ch.is_ascii_hexdigit() || ch.is_ascii_uppercase())
    {
        return None;
    }
    u64::from_str_radix(&normalized[2..], 16).ok()
}

fn truncate_for_review(value: &str, width: usize) -> String {
    let mut output = String::new();
    if value.chars().count() <= width {
        return value.to_string();
    }
    for ch in value.chars().take(width.saturating_sub(1)) {
        output.push(ch);
    }
    output.push('…');
    output
}

fn print_error(summary: &str, details: &[&str]) {
    println!("✗ error: {summary}");
    if let Some((first, rest)) = details.split_first() {
        println!("    ╰─ {first}");
        for detail in rest {
            println!("       {detail}");
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ConnectError {
    MethodNotFound,
    ConnectionRefused,
}

fn classify_connect_error(error: &anyhow::Error) -> Option<ConnectError> {
    for cause in error.chain() {
        if let Some(ida_error) = cause.downcast_ref::<IdaError>() {
            match ida_error {
                IdaError::IdaResponseError(message) if is_method_not_found_code(message) => {
                    return Some(ConnectError::MethodNotFound);
                }
                IdaError::ConnectionError(_) => return Some(ConnectError::ConnectionRefused),
                _ => {}
            }
        }
    }

    let lower = error.to_string().to_ascii_lowercase();
    if lower.contains("connection refused") {
        return Some(ConnectError::ConnectionRefused);
    }

    None
}

fn is_method_not_found_code(message: &str) -> bool {
    serde_json::from_str::<serde_json::Value>(message)
        .ok()
        .and_then(|payload| payload.get("code").and_then(serde_json::Value::as_i64))
        == Some(-32601)
}

fn contains_error_text(err: &anyhow::Error, needle: &str) -> bool {
    let needle = needle.to_ascii_lowercase();
    err.chain()
        .any(|cause| cause.to_string().to_ascii_lowercase().contains(&needle))
}

fn extract_invalid_session_id_input(err: &anyhow::Error) -> Option<String> {
    const PREFIX: &str = "invalid session id: ";
    for cause in err.chain() {
        let message = cause.to_string();
        if let Some(input) = message.strip_prefix(PREFIX) {
            return Some(input.trim().to_string());
        }
    }
    None
}

fn find_error_in_chain<T: std::error::Error + 'static>(err: &anyhow::Error) -> Option<&T> {
    err.chain().find_map(|cause| cause.downcast_ref::<T>())
}

fn read_prompt(prompt: &str) -> Result<String> {
    use std::io::Write;

    print!("{prompt}");
    std::io::stdout().flush()?;
    let mut buf = String::new();
    std::io::stdin().read_line(&mut buf)?;
    Ok(buf.trim().to_string())
}

fn build_provider_for_plan(
    config: &Config,
    provider: endeavour_llm::BackendProvider,
) -> std::result::Result<RenameProvider, String> {
    match provider {
        endeavour_llm::BackendProvider::Anthropic => config
            .anthropic_api_key
            .clone()
            .map(|api_key| RenameProvider::Anthropic(AnthropicProvider::new(api_key)))
            .ok_or_else(|| "no LLM provider configured".to_string()),
        endeavour_llm::BackendProvider::OpenAi => config
            .openai_api_key
            .clone()
            .map(|api_key| RenameProvider::OpenAi(OpenAiProvider::new(api_key)))
            .ok_or_else(|| "no LLM provider configured".to_string()),
    }
}

async fn run_rename_agentic_loop<P: LlmProvider>(
    provider: &P,
    client: Arc<IdaClient>,
    model: &str,
    function_addr: u64,
    function_name: &str,
    pseudocode: &str,
) -> std::result::Result<endeavour_llm::AgenticLoopResult, LlmError> {
    let tool_executor = IdaToolExecutor::new(client);
    let builder = ContextBuilder::new(model)
        .with_system_prompt(RENAME_SYSTEM_PROMPT)
        .with_history(vec![Message {
            role: Role::User,
            content: format!(
                "Analyze function {} at {} and propose names and comments.",
                function_name,
                fmt::format_addr(function_addr)
            ),
            tool_results: Vec::new(),
        }])
        .with_function_context(FunctionContext {
            function_name: Some(function_name.to_string()),
            address: Some(function_addr),
            decompiled_code: pseudocode.to_string(),
            xrefs: Vec::new(),
            strings: Vec::new(),
        })
        .with_temperature(0.1)
        .with_max_tokens(1_200)
        .with_tools(IdaToolExecutor::tool_definitions());

    let mut controller = AgenticLoopController::new(AgenticLoopConfig {
        max_steps: 4,
        ..AgenticLoopConfig::default()
    });

    controller
        .run(provider, builder, &tool_executor, None)
        .await
        .map_err(|err| LlmError::Configuration(err.to_string()))
}

fn parse_rename_json_payload(raw: &str) -> std::result::Result<RenameLlmResponse, String> {
    let value: serde_json::Value = serde_json::from_str(raw)
        .map_err(|_| "Expected rename schema at top level.".to_string())?;
    let object = value
        .as_object()
        .ok_or_else(|| "Expected rename schema at top level.".to_string())?;

    let mut keys = object.keys().cloned().collect::<Vec<_>>();
    keys.sort();
    if keys != ["comments", "function_rename", "variable_renames"] {
        return Err("Expected rename schema at top level.".to_string());
    }

    serde_json::from_value(value).map_err(|_| "Expected rename schema at top level.".to_string())
}

fn build_suggestions(
    function_addr: u64,
    function_name: &str,
    response: RenameLlmResponse,
    store: &SessionStore,
    session_id: uuid::Uuid,
) -> std::result::Result<Vec<RenameSuggestion>, String> {
    if !(0.0..=1.0).contains(&response.function_rename.confidence) {
        return Err(format!(
            "Field 'confidence' out of range (got: {}, expected: 0.0-1.0).",
            response.function_rename.confidence
        ));
    }

    let mut suggestions = Vec::new();
    if let Some(name) = response.function_rename.proposed_name {
        if is_valid_identifier(&name) {
            suggestions.push(RenameSuggestion {
                kind: RenameSuggestionKind::Function,
                function_addr,
                target_addr: function_addr,
                current_name: function_name.to_string(),
                proposed_value: name,
                confidence: response.function_rename.confidence,
            });
        } else {
            let _ = append_transcript_line(
                store,
                session_id,
                format!(
                    "[SKIPPED] invalid identifier for function rename: '{}'",
                    name
                ),
            );
        }
    }

    for variable in response.variable_renames.into_iter().take(20) {
        if !(0.0..=1.0).contains(&variable.confidence) {
            return Err(format!(
                "Field 'confidence' out of range (got: {}, expected: 0.0-1.0).",
                variable.confidence
            ));
        }
        if !is_valid_identifier(&variable.proposed_name) {
            let _ = append_transcript_line(
                store,
                session_id,
                format!(
                    "[SKIPPED] invalid identifier for variable rename: '{}'",
                    variable.proposed_name
                ),
            );
            continue;
        }
        suggestions.push(RenameSuggestion {
            kind: RenameSuggestionKind::Variable,
            function_addr,
            target_addr: function_addr,
            current_name: variable.current_name,
            proposed_value: variable.proposed_name,
            confidence: variable.confidence,
        });
    }

    for comment in response.comments.into_iter().take(10) {
        if !(0.0..=1.0).contains(&comment.confidence) {
            return Err(format!(
                "Field 'confidence' out of range (got: {}, expected: 0.0-1.0).",
                comment.confidence
            ));
        }
        let Some(addr) = parse_comment_addr(&comment.addr) else {
            let _ = append_transcript_line(
                store,
                session_id,
                format!("[SKIPPED] invalid comment address: '{}'", comment.addr),
            );
            continue;
        };
        suggestions.push(RenameSuggestion {
            kind: RenameSuggestionKind::Comment,
            function_addr,
            target_addr: addr,
            current_name: "comment".to_string(),
            proposed_value: comment.text,
            confidence: comment.confidence,
        });
    }

    suggestions.sort_by_key(|item| match item.kind {
        RenameSuggestionKind::Function => 0,
        RenameSuggestionKind::Comment => 1,
        RenameSuggestionKind::Variable => 2,
    });

    Ok(suggestions)
}

fn apply_suggestion(
    runtime: &Runtime,
    client: &IdaClient,
    suggestion: &RenameSuggestion,
) -> Result<()> {
    match suggestion.kind {
        RenameSuggestionKind::Function => runtime
            .block_on(client.rename_function(suggestion.target_addr, &suggestion.proposed_value))
            .map_err(anyhow::Error::from),
        RenameSuggestionKind::Variable => runtime
            .block_on(client.rename_local(
                suggestion.function_addr,
                &suggestion.current_name,
                &suggestion.proposed_value,
            ))
            .map_err(anyhow::Error::from),
        RenameSuggestionKind::Comment => runtime
            .block_on(client.set_comment(suggestion.target_addr, &suggestion.proposed_value))
            .map_err(anyhow::Error::from),
    }
}

fn queue_suggestion(
    store: &SessionStore,
    session_id: uuid::Uuid,
    suggestion: &RenameSuggestion,
) -> Result<()> {
    store.add_review_queue_entry(
        session_id,
        &NewReviewQueueRecord {
            kind: match suggestion.kind {
                RenameSuggestionKind::Function => "function_rename".to_string(),
                RenameSuggestionKind::Variable => "variable_rename".to_string(),
                RenameSuggestionKind::Comment => "comment".to_string(),
            },
            function_addr: suggestion.function_addr,
            target_addr: Some(suggestion.target_addr),
            current_name: suggestion.current_name.clone(),
            proposed_value: suggestion.proposed_value.clone(),
            confidence: suggestion.confidence,
        },
    )?;
    Ok(())
}

fn render_applied_line(suggestion: &RenameSuggestion) -> String {
    match suggestion.kind {
        RenameSuggestionKind::Comment => format!(
            "  ✓ {}  comment set: \"{}\"  ({:.2})",
            fmt::format_addr(suggestion.target_addr),
            suggestion.proposed_value,
            suggestion.confidence
        ),
        _ => format!(
            "  ✓ {}  {}  ->  {}  ({:.2})",
            fmt::format_addr(suggestion.target_addr),
            suggestion.current_name,
            suggestion.proposed_value,
            suggestion.confidence
        ),
    }
}

fn render_queued_line(suggestion: &RenameSuggestion) -> String {
    if matches!(suggestion.kind, RenameSuggestionKind::Comment) {
        format!(
            "  ~ {}  comment  ->  {}  ({:.2})  queued for review",
            fmt::format_addr(suggestion.target_addr),
            suggestion.proposed_value,
            suggestion.confidence
        )
    } else {
        format!(
            "  ~ {}  {}  ->  {}  ({:.2})  queued for review",
            fmt::format_addr(suggestion.target_addr),
            suggestion.current_name,
            suggestion.proposed_value,
            suggestion.confidence
        )
    }
}

fn persist_agentic_transcript(
    store: &SessionStore,
    session_id: uuid::Uuid,
    result: &endeavour_llm::AgenticLoopResult,
) -> Result<()> {
    let mut records = Vec::new();
    for turn in &result.transcript {
        records.push(NewTranscriptRecord {
            turn_number: turn.round,
            role: "llm".to_string(),
            timestamp: "0".to_string(),
            content_json: serde_json::to_string(&TranscriptContent::Message(Message {
                role: Role::Assistant,
                content: turn.assistant_text.clone(),
                tool_results: Vec::new(),
            }))?,
            usage_json: turn.usage.as_ref().map(serde_json::to_string).transpose()?,
            state: "llm_streaming".to_string(),
            tool_calls_json: Some(serde_json::to_string(&turn.tool_calls)?),
        });
    }
    if !records.is_empty() {
        store.add_transcript_entries(session_id, &records)?;
    }
    Ok(())
}

fn append_transcript_line(
    store: &SessionStore,
    session_id: uuid::Uuid,
    content: String,
) -> Result<()> {
    store.add_transcript_entries(
        session_id,
        &[NewTranscriptRecord {
            turn_number: 0,
            role: "system".to_string(),
            timestamp: "0".to_string(),
            content_json: serde_json::to_string(&TranscriptContent::Message(Message {
                role: Role::System,
                content,
                tool_results: Vec::new(),
            }))?,
            usage_json: None,
            state: "done_success".to_string(),
            tool_calls_json: None,
        }],
    )?;
    Ok(())
}

fn log_discarded(
    store: &SessionStore,
    session_id: uuid::Uuid,
    suggestion: &RenameSuggestion,
) -> Result<()> {
    append_transcript_line(
        store,
        session_id,
        format!(
            "[DISCARDED] {}  {}  ->  {}  ({:.2})",
            fmt::format_addr(suggestion.target_addr),
            suggestion.current_name,
            suggestion.proposed_value,
            suggestion.confidence
        ),
    )
}

fn log_ida_rejected(
    store: &SessionStore,
    session_id: uuid::Uuid,
    suggestion: &RenameSuggestion,
) -> Result<()> {
    append_transcript_line(
        store,
        session_id,
        format!(
            "[IDA_REJECTED] {}  {}  ->  {}  ({:.2})",
            fmt::format_addr(suggestion.target_addr),
            suggestion.current_name,
            suggestion.proposed_value,
            suggestion.confidence
        ),
    )
}

fn log_review_rejected(
    store: &SessionStore,
    session_id: uuid::Uuid,
    item: &ReviewQueueRecord,
) -> Result<()> {
    append_transcript_line(
        store,
        session_id,
        format!(
            "[REJECTED] {}  {}  ->  {}  ({:.2})",
            fmt::format_addr(item.target_addr.unwrap_or(item.function_addr)),
            item.current_name,
            item.proposed_value,
            item.confidence
        ),
    )
}

fn parse_command(line: &str) -> ParsedLine {
    if line.is_empty() {
        return ParsedLine::Empty;
    }

    let mut tokens = line.split_whitespace();
    let Some(command) = tokens.next() else {
        return ParsedLine::Empty;
    };

    match command {
        "help" => ParsedLine::Command(ReplCommand::Help),
        "analyze" => {
            let path_tokens: Vec<&str> = tokens.collect();
            if path_tokens.is_empty() {
                ParsedLine::InvalidUsage("analyze <path>")
            } else {
                ParsedLine::Command(ReplCommand::Analyze(path_tokens.join(" ")))
            }
        }
        "connect" => {
            let target = tokens.next().map(ToString::to_string);
            ParsedLine::Command(ReplCommand::Connect(target))
        }
        "ida-status" => ParsedLine::Command(ReplCommand::IdaStatus),
        "decompile" => match tokens.next() {
            Some(target) => ParsedLine::Command(ReplCommand::Decompile(target.to_string())),
            None => ParsedLine::InvalidUsage("decompile <addr>"),
        },
        "explain" => {
            let args = std::iter::once("explain")
                .chain(tokens)
                .map(ToString::to_string)
                .collect::<Vec<_>>();
            match ExplainCommand::try_parse_from(args) {
                Ok(command) => ParsedLine::Command(ReplCommand::Explain(command)),
                Err(_) => ParsedLine::InvalidUsage(
                    "explain <addr> [--provider <claude|gpt|auto|ollama>] [--no-fallback]",
                ),
            }
        }
        "rename" => {
            let args = std::iter::once("rename")
                .chain(tokens)
                .map(ToString::to_string)
                .collect::<Vec<_>>();
            match RenameCommand::try_parse_from(args) {
                Ok(command) => ParsedLine::Command(ReplCommand::Rename(command)),
                Err(_) => ParsedLine::InvalidUsage(
                    "rename <addr> <new_name> | rename --llm <addr> | rename --all [--provider <claude|gpt|auto|ollama>] [--no-fallback]",
                ),
            }
        }
        "review" => {
            if tokens.next().is_some() {
                ParsedLine::InvalidUsage("review")
            } else {
                ParsedLine::Command(ReplCommand::Review)
            }
        }
        "comment" => {
            let Some(target) = tokens.next() else {
                return ParsedLine::InvalidUsage("comment <addr> <text...>");
            };

            let comment_tokens: Vec<&str> = tokens.collect();
            if comment_tokens.is_empty() {
                ParsedLine::InvalidUsage("comment <addr> <text...>")
            } else {
                ParsedLine::Command(ReplCommand::Comment(
                    target.to_string(),
                    comment_tokens.join(" "),
                ))
            }
        }
        "callgraph" => {
            let Some(target) = tokens.next() else {
                return ParsedLine::InvalidUsage("callgraph <addr> [depth]");
            };

            let depth = match tokens.next() {
                Some(raw_depth) => match raw_depth.parse::<u32>() {
                    Ok(parsed) => Some(parsed),
                    Err(_) => return ParsedLine::InvalidUsage("callgraph <addr> [depth]"),
                },
                None => None,
            };

            if tokens.next().is_some() {
                ParsedLine::InvalidUsage("callgraph <addr> [depth]")
            } else {
                ParsedLine::Command(ReplCommand::Callgraph(target.to_string(), depth))
            }
        }
        "search" => {
            let pattern: Vec<&str> = tokens.collect();
            if pattern.is_empty() {
                ParsedLine::InvalidUsage("search <pattern>")
            } else {
                ParsedLine::Command(ReplCommand::Search(pattern.join(" ")))
            }
        }
        "sessions" => ParsedLine::Command(ReplCommand::Sessions),
        "session" => match tokens.next() {
            Some(id) => ParsedLine::Command(ReplCommand::Session(id.to_string())),
            None => ParsedLine::InvalidUsage("session <id>"),
        },
        "info" => ParsedLine::Command(ReplCommand::Info),
        "findings" => ParsedLine::Command(ReplCommand::Findings),
        "cache" => match tokens.next() {
            Some("stats") if tokens.next().is_none() => {
                ParsedLine::Command(ReplCommand::CacheStats)
            }
            Some("clear") if tokens.next().is_none() => {
                ParsedLine::Command(ReplCommand::CacheClear)
            }
            _ => ParsedLine::InvalidUsage("cache <stats|clear>"),
        },
        "config" => match tokens.next() {
            Some("set") => {
                let Some(key) = tokens.next() else {
                    return ParsedLine::InvalidUsage("config set <key> <value>");
                };

                let value_tokens: Vec<&str> = tokens.collect();
                if value_tokens.is_empty() {
                    ParsedLine::InvalidUsage("config set <key> <value>")
                } else {
                    ParsedLine::Command(ReplCommand::ConfigSet {
                        key: key.to_string(),
                        value: value_tokens.join(" "),
                    })
                }
            }
            Some("get") => match tokens.next() {
                Some(key) => ParsedLine::Command(ReplCommand::ConfigGet(key.to_string())),
                None => ParsedLine::InvalidUsage("config get <key>"),
            },
            Some("list") => {
                if tokens.next().is_some() {
                    ParsedLine::InvalidUsage("config list")
                } else {
                    ParsedLine::Command(ReplCommand::ConfigList)
                }
            }
            _ => ParsedLine::InvalidUsage("config <set|get|list> ..."),
        },
        "show-transcript" => {
            let args = std::iter::once("show-transcript")
                .chain(tokens)
                .map(ToString::to_string)
                .collect::<Vec<_>>();
            match ShowTranscriptCommand::try_parse_from(args) {
                Ok(command) => ParsedLine::Command(ReplCommand::ShowTranscript(command)),
                Err(_) => ParsedLine::InvalidUsage("show-transcript [session_id] [--turn <n>]"),
            }
        }
        "quit" | "exit" => ParsedLine::Command(ReplCommand::Quit),
        other => ParsedLine::Unknown(other.to_string()),
    }
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

fn create_editor(history_file: &Path) -> Result<Reedline> {
    let history = FileBackedHistory::with_file(HISTORY_CAPACITY, history_file.to_path_buf())
        .with_context(|| {
            format!(
                "failed to initialize history file at {}",
                history_file.display()
            )
        })?;

    Ok(Reedline::create().with_history(Box::new(history)))
}

fn history_path() -> Result<PathBuf> {
    let home = std::env::var_os("HOME").context("HOME environment variable is not set")?;
    let app_dir = PathBuf::from(home).join(".endeavour");
    std::fs::create_dir_all(&app_dir)
        .with_context(|| format!("failed to create directory {}", app_dir.display()))?;
    Ok(app_dir.join("history.txt"))
}

fn parse_host_port(value: &str) -> Result<(String, u16)> {
    let trimmed = value.trim();
    let (host, port_text) = trimmed
        .rsplit_once(':')
        .with_context(|| format!("invalid host:port '{trimmed}'"))?;

    if host.is_empty() {
        return Err(anyhow::anyhow!("host must not be empty"));
    }

    let port = port_text
        .parse::<u16>()
        .with_context(|| format!("invalid port '{port_text}' in '{trimmed}'"))?;

    Ok((host.to_string(), port))
}

fn save_ida_endpoint(endpoint: &str) -> Result<()> {
    let path =
        PathBuf::from(std::env::var_os("HOME").context("HOME environment variable is not set")?)
            .join(".endeavour")
            .join("ida_endpoint");

    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("failed to create directory {}", parent.display()))?;
    }

    std::fs::write(&path, endpoint)
        .with_context(|| format!("failed to write IDA endpoint config at {}", path.display()))
}

fn connect_with_transport(
    runtime: &Runtime,
    endpoint: &str,
    transport: Arc<dyn Transport>,
) -> Result<(Arc<IdaClient>, Vec<endeavour_ida::FunctionInfo>)> {
    let (host, port) = parse_host_port(endpoint)?;
    let client = Arc::new(IdaClient::with_transport(&host, port, transport));

    let functions = runtime
        .block_on(client.list_functions(None, Some(1)))
        .with_context(|| format!("failed to connect to IDA at {host}:{port}"))?;

    Ok((client, functions))
}

fn print_help() {
    println!("Available commands:");
    println!("  help                 Show this help message");
    println!("  analyze <path>       Load a Mach-O binary and create a session");
    println!("  connect [host:port]  Connect to IDA MCP (default: localhost:13337)");
    println!("  ida-status           Check IDA connection health");
    println!("  decompile <addr>     Decompile function (0x..., decimal, or sub_...)");
    println!("  explain <addr> [--provider <claude|gpt|auto|ollama>] [--no-fallback]");
    println!("  rename <addr> <new_name>  Manual rename");
    println!("  rename --llm <addr> [--provider <claude|gpt|auto|ollama>] [--no-fallback]");
    println!("  rename --all [--provider <claude|gpt|auto|ollama>] [--no-fallback]");
    println!("  review               Review queued medium-confidence suggestions");
    println!("  comment <addr> <text...>  Set comment at address");
    println!("  callgraph <addr> [depth]  Show call graph tree (default depth: 3)");
    println!("  search <pattern>     Search strings with regex pattern");
    println!("  sessions             List all sessions");
    println!("  session <id>         Switch active session");
    println!("  info                 Show active session info");
    println!("  findings             List findings in active session");
    println!("  cache stats          Show IDA cache stats for active session");
    println!("  cache clear          Clear IDA cache for active session");
    println!("  config set <k> <v>   Set config value in ~/.endeavour/config.toml");
    println!("  config get <k>       Get config value (API keys masked)");
    println!("  config list          List config keys and masked values");
    println!("  show-transcript [session_id] [--turn <n>]  Show stored agentic transcript");
    println!("  quit | exit          Exit the REPL");
}

fn render_transcript_output(
    session_id: uuid::Uuid,
    entries: &[endeavour_core::TranscriptRecord],
) -> String {
    let mut lines = Vec::new();
    let turn_count = entries
        .iter()
        .map(|entry| entry.turn_number)
        .collect::<std::collections::HashSet<_>>()
        .len();
    let total_tool_calls = entries
        .iter()
        .filter_map(|entry| parse_tool_calls(entry.tool_calls_json.as_deref()))
        .map(|calls| calls.len())
        .sum::<usize>();

    lines.push(format!("◆ Transcript: {}", session_id));
    lines.push(fmt::separator(fmt::Separator::Heavy, 78));
    lines.push(format!("  Rounds       {turn_count}"));
    lines.push(format!("  Tool calls   {total_tool_calls}"));
    lines.push(fmt::separator(fmt::Separator::Standard, 78));

    let mut current_turn = 0u32;
    for entry in entries {
        if entry.turn_number != current_turn {
            if current_turn != 0 {
                lines.push(String::new());
            }
            current_turn = entry.turn_number;
            lines.push(format!("◆ Round {}", entry.turn_number));
            lines.push(fmt::separator(fmt::Separator::Standard, 78));
        }

        match entry.role.as_str() {
            "llm" => {
                if let Some(message) = parse_transcript_message(&entry.content_json) {
                    for text_line in message.content.lines() {
                        lines.push(format!("  {text_line}"));
                    }
                }
                if let Some(tool_calls) = parse_tool_calls(entry.tool_calls_json.as_deref()) {
                    for tool_call in tool_calls {
                        lines.push(format!("  ▶ {}", format_tool_call(&tool_call)));
                    }
                }
                if let Some(usage) = parse_usage(entry.usage_json.as_deref()) {
                    lines.push(format!(
                        "  usage: input={} output={}",
                        usage.input_tokens, usage.output_tokens
                    ));
                }
            }
            "tool_executor" => {
                if let Some(tool_result) = parse_transcript_tool_result(&entry.content_json) {
                    if tool_result.is_error {
                        lines.push(format!("  ◀ ✗ {}", tool_result.content));
                    } else {
                        lines.push(format!("  ◀ {}", tool_result.content));
                    }
                }
            }
            "system" => {
                if let Some(message) = parse_transcript_message(&entry.content_json) {
                    lines.push(format!("  [state={}] {}", entry.state, message.content));
                }
            }
            _ => lines.push(format!("  {}", entry.content_json)),
        }
    }

    lines.join("\n")
}

fn parse_transcript_message(content_json: &str) -> Option<Message> {
    let content = serde_json::from_str::<TranscriptContent>(content_json).ok()?;
    match content {
        TranscriptContent::Message(message) => Some(message),
        TranscriptContent::ToolResult(_) => None,
    }
}

fn parse_transcript_tool_result(content_json: &str) -> Option<ToolResult> {
    let content = serde_json::from_str::<TranscriptContent>(content_json).ok()?;
    match content {
        TranscriptContent::ToolResult(result) => Some(result),
        TranscriptContent::Message(_) => None,
    }
}

fn parse_usage(usage_json: Option<&str>) -> Option<Usage> {
    serde_json::from_str::<Usage>(usage_json?).ok()
}

fn parse_tool_calls(tool_calls_json: Option<&str>) -> Option<Vec<ToolCall>> {
    serde_json::from_str::<Vec<ToolCall>>(tool_calls_json?).ok()
}

fn format_tool_call(tool_call: &ToolCall) -> String {
    let mut output = tool_call.name.clone();
    if let serde_json::Value::Object(map) = &tool_call.input {
        let mut keys = map.keys().cloned().collect::<Vec<_>>();
        keys.sort();
        for key in keys {
            if let Some(value) = map.get(&key) {
                output.push_str("  ");
                output.push_str(&key);
                output.push('=');
                output.push_str(&format_tool_arg_value(value));
            }
        }
    }
    output
}

fn format_tool_arg_value(value: &serde_json::Value) -> String {
    match value {
        serde_json::Value::String(text) => format!("\"{text}\""),
        _ => value.to_string(),
    }
}

#[cfg(test)]
fn render_decompile_output(runtime: &Runtime, client: &IdaClient, target: &str) -> Result<String> {
    let (address, function_name) = resolve_target_address(runtime, client, target)?;
    let result = runtime.block_on(client.decompile(address))?;

    Ok(render_decompile_result(&function_name, &result))
}

fn render_decompile_result(function_name: &str, result: &DecompileResult) -> String {
    let mut lines = vec![
        fmt::h2(format!(
            "{} @ {}",
            function_name,
            fmt::format_addr(result.address)
        )),
        fmt::separator(fmt::Separator::Standard, 88),
    ];

    for (index, line) in result.pseudocode.lines().enumerate() {
        lines.push(format!("{:>4} | {}", index + 1, line));
    }

    if result.pseudocode.is_empty() {
        lines.push("   1 |".to_string());
    }

    lines.join("\n")
}

fn build_explain_request(function_name: &str, result: &DecompileResult) -> CompletionRequest {
    let system_prompt = "You are an expert reverse engineer analyzing decompiled code. Explain what this function does, identify key behaviors, potential vulnerabilities, and suggest meaningful names for the function and its variables.";
    let user_prompt = format!(
        "Analyze function {function_name} at {address}.\n\nDecompiled pseudocode:\n```c\n{pseudocode}\n```",
        address = fmt::format_addr(result.address),
        pseudocode = result.pseudocode
    );

    CompletionRequest {
        model: "claude-sonnet-4-5".to_string(),
        messages: vec![
            Message {
                role: Role::System,
                content: system_prompt.to_string(),
                tool_results: Vec::new(),
            },
            Message {
                role: Role::User,
                content: user_prompt,
                tool_results: Vec::new(),
            },
        ],
        max_tokens: Some(1_200),
        temperature: Some(0.1),
        tools: Vec::new(),
    }
}

fn render_explain_result(function_name: &str, address: u64, model: &str, analysis: &str) -> String {
    let title = format!(
        "Function Analysis: {function_name} @ {}",
        fmt::format_addr(address)
    );
    let model_line = format!("Model: {model}");
    let body = if analysis.trim().is_empty() {
        "(No analysis text returned.)"
    } else {
        analysis.trim()
    };

    [
        fmt::h2(title),
        model_line,
        fmt::separator(fmt::Separator::Standard, 88),
        body.to_string(),
        fmt::separator(fmt::Separator::Standard, 88),
    ]
    .join("\n")
}

fn render_callgraph_output(
    runtime: &Runtime,
    client: &IdaClient,
    target: &str,
    depth: u32,
) -> Result<String> {
    let (root_addr, root_name) = resolve_target_address(runtime, client, target)?;
    let edges = runtime
        .block_on(client.call_graph(root_addr, Some(depth)))
        .with_context(|| {
            format!(
                "failed to fetch call graph for {}",
                fmt::format_addr(root_addr)
            )
        })?;

    let mut adjacency: HashMap<u64, Vec<u64>> = HashMap::new();
    let mut node_order = Vec::new();
    let mut seen_nodes = HashSet::new();
    seen_nodes.insert(root_addr);
    for (src, dst) in edges {
        let entry = adjacency.entry(src).or_default();
        if !entry.contains(&dst) {
            entry.push(dst);
        }
        if seen_nodes.insert(src) {
            node_order.push(src);
        }
        if seen_nodes.insert(dst) {
            node_order.push(dst);
        }
    }

    let mut name_cache = HashMap::new();
    name_cache.insert(root_addr, root_name.clone());
    for addr in node_order {
        if name_cache.contains_key(&addr) {
            continue;
        }

        let query = fmt::format_addr(addr);
        let name = runtime
            .block_on(client.lookup_function(&query))
            .ok()
            .and_then(|function| function.map(|item| item.name))
            .unwrap_or_else(|| format!("sub_{addr:x}"));
        name_cache.insert(addr, name);
    }

    let header = format!(
        "Call Graph: {} @ {} (depth={depth})",
        root_name,
        fmt::format_addr(root_addr)
    );
    let mut lines = vec![
        header.clone(),
        fmt::separator(fmt::Separator::Standard, header.chars().count()),
    ];

    let children = adjacency.get(&root_addr).cloned().unwrap_or_default();
    if children.is_empty() {
        lines.push("(no callees)".to_string());
        return Ok(lines.join("\n"));
    }

    let mut ancestors = HashSet::new();
    ancestors.insert(root_addr);
    render_callgraph_branch(
        root_addr,
        &children,
        &adjacency,
        &name_cache,
        "",
        &ancestors,
        &mut lines,
    );

    Ok(lines.join("\n"))
}

fn render_callgraph_branch(
    _parent: u64,
    children: &[u64],
    adjacency: &HashMap<u64, Vec<u64>>,
    names: &HashMap<u64, String>,
    prefix: &str,
    ancestors: &HashSet<u64>,
    lines: &mut Vec<String>,
) {
    for (index, child) in children.iter().enumerate() {
        let is_last = index + 1 == children.len();
        let branch = if is_last { "└── " } else { "├── " };
        let name = names
            .get(child)
            .cloned()
            .unwrap_or_else(|| format!("sub_{child:x}"));

        if ancestors.contains(child) {
            lines.push(format!(
                "{prefix}{branch}{name} @ {} [recursive]",
                fmt::format_addr(*child)
            ));
            continue;
        }

        lines.push(format!(
            "{prefix}{branch}{name} @ {}",
            fmt::format_addr(*child)
        ));

        let mut next_ancestors = ancestors.clone();
        next_ancestors.insert(*child);
        let child_prefix = if is_last {
            format!("{prefix}    ")
        } else {
            format!("{prefix}│   ")
        };

        if let Some(grandchildren) = adjacency.get(child) {
            render_callgraph_branch(
                *child,
                grandchildren,
                adjacency,
                names,
                &child_prefix,
                &next_ancestors,
                lines,
            );
        }
    }
}

fn resolve_target_address(
    runtime: &Runtime,
    client: &IdaClient,
    target: &str,
) -> Result<(u64, String)> {
    if let Some(address) = parse_decompile_target(target) {
        let query = fmt::format_addr(address);
        let name = runtime
            .block_on(client.lookup_function(&query))
            .ok()
            .and_then(|function| function.map(|item| item.name))
            .unwrap_or_else(|| format!("sub_{address:x}"));
        return Ok((address, name));
    }

    let function = runtime
        .block_on(client.lookup_function(target))
        .with_context(|| format!("failed to resolve function '{target}'"))?
        .with_context(|| format!("function '{target}' not found"))?;
    Ok((function.address, function.name))
}

fn format_resolve_target_error(target: &str, err: &anyhow::Error) -> String {
    if is_target_not_found_error(target, err) {
        return format!("No function at address {target}");
    }

    format!("Failed to resolve target '{target}': {err:#}")
}

fn is_target_not_found_error(target: &str, err: &anyhow::Error) -> bool {
    let expected = format!("function '{target}' not found");
    err.chain().any(|cause| cause.to_string() == expected)
}

fn parse_decompile_target(raw: &str) -> Option<u64> {
    let input = raw.trim();
    if let Some(hex) = input
        .strip_prefix("0x")
        .or_else(|| input.strip_prefix("0X"))
    {
        return u64::from_str_radix(hex, 16).ok();
    }

    if let Ok(value) = input.parse::<u64>() {
        return Some(value);
    }

    if let Some(suffix) = input.strip_prefix("sub_") {
        return u64::from_str_radix(suffix, 16).ok();
    }

    None
}

fn is_missing_function_error(error: &IdaError) -> bool {
    match error {
        IdaError::IdaResponseError(message) | IdaError::DeserializationError(message) => {
            message.to_ascii_lowercase().contains("not found")
        }
        _ => false,
    }
}

fn format_llm_error(error: &LlmError) -> String {
    match error {
        LlmError::AuthFailed => "Authentication failed; verify your API key".to_string(),
        LlmError::RateLimited { retry_after } => {
            if let Some(seconds) = retry_after {
                format!("rate limited; retry in {seconds}s")
            } else {
                "rate limited; retry later".to_string()
            }
        }
        LlmError::ContextWindowExceeded => {
            "prompt too large for the selected model context window".to_string()
        }
        _ => error.to_string(),
    }
}

fn fetch_search_results(
    runtime: &Runtime,
    client: &IdaClient,
    pattern: &str,
) -> Result<Vec<(u64, String)>> {
    runtime
        .block_on(client.find_strings(pattern))
        .with_context(|| format!("failed to search strings for pattern '{pattern}'"))
}

fn rename_symbol(runtime: &Runtime, client: &IdaClient, addr: u64, new_name: &str) -> Result<()> {
    runtime
        .block_on(client.rename_function(addr, new_name))
        .with_context(|| format!("failed to rename function at {}", fmt::format_addr(addr)))
}

fn set_symbol_comment(
    runtime: &Runtime,
    client: &IdaClient,
    addr: u64,
    comment: &str,
) -> Result<()> {
    runtime
        .block_on(client.set_comment(addr, comment))
        .with_context(|| format!("failed to set comment at {}", fmt::format_addr(addr)))
}

fn render_search_output(matches: &[(u64, String)]) -> String {
    let mut table = fmt::Table::new(vec![
        fmt::Column::new("Address", 18, fmt::Align::Left),
        fmt::Column::new("String", 76, fmt::Align::Left),
    ]);

    for (address, text) in matches {
        table.add_row(vec![fmt::format_addr(*address), text.clone()]);
    }

    table.render()
}

#[cfg(test)]
mod tests {
    use super::{
        build_explain_request, build_suggestions, classify_confidence, connect_with_transport,
        fetch_search_results, format_resolve_target_error, is_missing_function_error,
        parse_command, parse_decompile_target, parse_rename_json_payload, rename_symbol,
        render_callgraph_output, render_decompile_output, render_explain_result,
        render_search_output, render_transcript_output, resolve_target_address, set_symbol_comment,
        CommentPayload, ConfidenceTier, ExplainCommand, FunctionRenamePayload, ParsedLine, Repl,
        RenameCommand, RenameLlmResponse, ReplCommand, ShowTranscriptCommand,
        VariableRenamePayload,
    };
    use endeavour_core::store::SessionStore;
    use endeavour_core::TranscriptRecord;
    use endeavour_llm::mock::{MockIdaError, MockIdaTransport};
    use std::collections::VecDeque;
    use std::sync::{Arc, Mutex};

    use async_trait::async_trait;
    use endeavour_ida::{DecompileResult, IdaClient, IdaError, Transport};
    use endeavour_llm::{CompletionResponse, StopReason};
    use serde_json::{json, Value};
    use tokio::runtime::Runtime;

    #[test]
    fn parse_analyze_command_with_path() {
        assert_eq!(
            parse_command("analyze foo.bin"),
            ParsedLine::Command(ReplCommand::Analyze("foo.bin".to_string()))
        );
    }

    #[test]
    fn parse_connect_command_without_endpoint() {
        assert_eq!(
            parse_command("connect"),
            ParsedLine::Command(ReplCommand::Connect(None))
        );
    }

    #[test]
    fn parse_decompile_and_search_commands() {
        assert_eq!(
            parse_command("decompile 0x401000"),
            ParsedLine::Command(ReplCommand::Decompile("0x401000".to_string()))
        );
        assert_eq!(
            parse_command("explain 0x401000"),
            ParsedLine::Command(ReplCommand::Explain(ExplainCommand {
                target: "0x401000".to_string(),
                provider: "auto".to_string(),
                no_fallback: false,
            }))
        );
        assert_eq!(
            parse_command("search objc_msgSend"),
            ParsedLine::Command(ReplCommand::Search("objc_msgSend".to_string()))
        );
        assert_eq!(
            parse_command("cache stats"),
            ParsedLine::Command(ReplCommand::CacheStats)
        );
        assert_eq!(
            parse_command("cache clear"),
            ParsedLine::Command(ReplCommand::CacheClear)
        );
        assert_eq!(
            parse_command("rename 0x401000 main"),
            ParsedLine::Command(ReplCommand::Rename(RenameCommand {
                target: Some("0x401000".to_string()),
                new_name: Some("main".to_string()),
                llm: false,
                all: false,
                provider: "auto".to_string(),
                no_fallback: false,
            }))
        );
        assert_eq!(
            parse_command("comment 0x401000 this is a note"),
            ParsedLine::Command(ReplCommand::Comment(
                "0x401000".to_string(),
                "this is a note".to_string()
            ))
        );
    }

    #[test]
    fn parse_rename_and_comment_usage_errors() {
        assert_eq!(
            parse_command("rename 0x401000"),
            ParsedLine::Command(ReplCommand::Rename(RenameCommand {
                target: Some("0x401000".to_string()),
                new_name: None,
                llm: false,
                all: false,
                provider: "auto".to_string(),
                no_fallback: false,
            }))
        );
        assert_eq!(
            parse_command("comment 0x401000"),
            ParsedLine::InvalidUsage("comment <addr> <text...>")
        );

        assert_eq!(
            parse_command("rename --all"),
            ParsedLine::Command(ReplCommand::Rename(RenameCommand {
                target: None,
                new_name: None,
                llm: false,
                all: true,
                provider: "auto".to_string(),
                no_fallback: false,
            }))
        );
        assert_eq!(
            parse_command("review"),
            ParsedLine::Command(ReplCommand::Review)
        );
    }

    #[test]
    fn parse_rename_json_handles_schema_and_malformed_payloads() {
        let valid = r#"{
            "function_rename": {"proposed_name": "aes_init", "confidence": 0.94},
            "variable_renames": [{"current_name": "a1", "proposed_name": "src", "confidence": 0.83}],
            "comments": [{"addr": "0x401000", "text": "entry", "confidence": 0.77}]
        }"#;
        assert!(parse_rename_json_payload(valid).is_ok());

        let malformed = "```json {\"function_rename\":{}} ```";
        assert!(parse_rename_json_payload(malformed).is_err());

        let wrong_keys = r#"{"function_rename":{},"variable_renames":[],"extra":[]}"#;
        assert!(parse_rename_json_payload(wrong_keys).is_err());
    }

    #[test]
    fn build_suggestions_validates_entries_and_confidence_tiers() {
        let temp = tempfile::tempdir();
        assert!(temp.is_ok());
        let temp = temp.unwrap_or_else(|_| unreachable!());
        let store = SessionStore::open(&temp.path().join("rename-suggestions.db"));
        assert!(store.is_ok());
        let store = store.unwrap_or_else(|_| unreachable!());
        let session = store.create_session("test", uuid::Uuid::new_v4());
        assert!(session.is_ok());
        let session = session.unwrap_or_else(|_| unreachable!());

        let response = RenameLlmResponse {
            function_rename: FunctionRenamePayload {
                proposed_name: Some("aes_key_schedule_128".to_string()),
                confidence: 0.94,
            },
            variable_renames: vec![
                VariableRenamePayload {
                    current_name: "a1".to_string(),
                    proposed_name: "key_input".to_string(),
                    confidence: 0.93,
                },
                VariableRenamePayload {
                    current_name: "v3".to_string(),
                    proposed_name: "123invalid".to_string(),
                    confidence: 0.61,
                },
            ],
            comments: vec![
                CommentPayload {
                    addr: "0x401020".to_string(),
                    text: "entry point".to_string(),
                    confidence: 0.88,
                },
                CommentPayload {
                    addr: "BAD".to_string(),
                    text: "invalid".to_string(),
                    confidence: 0.55,
                },
            ],
        };

        let suggestions = build_suggestions(0x401000, "sub_401000", response, &store, session.id);
        assert!(suggestions.is_ok());
        let suggestions = suggestions.unwrap_or_else(|_| unreachable!());
        assert_eq!(suggestions.len(), 3);
        assert!(matches!(classify_confidence(0.70), ConfidenceTier::Tier1));
        assert!(matches!(classify_confidence(0.69), ConfidenceTier::Tier2));
        assert!(matches!(classify_confidence(0.49), ConfidenceTier::Tier3));
    }

    #[test]
    fn parse_config_commands() {
        assert_eq!(
            parse_command("config set anthropic-api-key sk-ant-1234567890"),
            ParsedLine::Command(ReplCommand::ConfigSet {
                key: "anthropic-api-key".to_string(),
                value: "sk-ant-1234567890".to_string(),
            })
        );
        assert_eq!(
            parse_command("config get default-provider"),
            ParsedLine::Command(ReplCommand::ConfigGet("default-provider".to_string()))
        );
        assert_eq!(
            parse_command("config list"),
            ParsedLine::Command(ReplCommand::ConfigList)
        );
    }

    #[test]
    fn parse_callgraph_command_with_and_without_depth() {
        assert_eq!(
            parse_command("callgraph sub_401000"),
            ParsedLine::Command(ReplCommand::Callgraph("sub_401000".to_string(), None))
        );
        assert_eq!(
            parse_command("callgraph 0x401000 5"),
            ParsedLine::Command(ReplCommand::Callgraph("0x401000".to_string(), Some(5)))
        );
    }

    #[test]
    fn parse_show_transcript_command_variants() {
        assert_eq!(
            parse_command("show-transcript"),
            ParsedLine::Command(ReplCommand::ShowTranscript(ShowTranscriptCommand {
                session_id: None,
                turn: None,
            }))
        );

        assert_eq!(
            parse_command("show-transcript 550e8400-e29b-41d4-a716-446655440000 --turn 2"),
            ParsedLine::Command(ReplCommand::ShowTranscript(ShowTranscriptCommand {
                session_id: Some("550e8400-e29b-41d4-a716-446655440000".to_string()),
                turn: Some(2),
            }))
        );
    }

    #[test]
    fn transcript_output_includes_rounds_tool_calls_and_results() {
        let session_id = uuid::Uuid::parse_str("550e8400-e29b-41d4-a716-446655440000");
        assert!(session_id.is_ok());
        let session_id = match session_id {
            Ok(value) => value,
            Err(err) => panic!("unexpected parse failure: {err}"),
        };

        let entries = vec![
            TranscriptRecord {
                id: uuid::Uuid::new_v4(),
                session_id,
                turn_number: 1,
                role: "llm".to_string(),
                timestamp: "1700000000".to_string(),
                content_json: "{\"kind\":\"message\",\"value\":{\"role\":\"assistant\",\"content\":\"Looking up the function\",\"tool_results\":[]}}".to_string(),
                usage_json: Some("{\"input_tokens\":12,\"output_tokens\":4}".to_string()),
                state: "llm_streaming".to_string(),
                tool_calls_json: Some("[{\"id\":\"tc1\",\"name\":\"decompile\",\"input\":{\"addr\":\"0x401000\"}}]".to_string()),
            },
            TranscriptRecord {
                id: uuid::Uuid::new_v4(),
                session_id,
                turn_number: 1,
                role: "tool_executor".to_string(),
                timestamp: "1700000001".to_string(),
                content_json: "{\"kind\":\"tool_result\",\"value\":{\"tool_use_id\":\"tc1\",\"content\":\"142 bytes of pseudocode returned\",\"output\":null,\"display_summary\":null,\"is_error\":false}}".to_string(),
                usage_json: None,
                state: "execute_tools".to_string(),
                tool_calls_json: None,
            },
        ];

        let rendered = render_transcript_output(session_id, &entries);
        assert!(rendered.contains("◆ Transcript:"));
        assert!(rendered.contains("◆ Round 1"));
        assert!(rendered.contains("▶ decompile  addr=\"0x401000\""));
        assert!(rendered.contains("◀ 142 bytes of pseudocode returned"));
        assert!(rendered.contains("usage: input=12 output=4"));
    }

    #[test]
    fn parses_decompile_targets() {
        assert_eq!(parse_decompile_target("0x401000"), Some(0x401000));
        assert_eq!(parse_decompile_target("4198400"), Some(4_198_400));
        assert_eq!(parse_decompile_target("sub_401000"), Some(0x401000));
    }

    struct MockTransport {
        responses: Mutex<VecDeque<std::result::Result<Value, IdaError>>>,
        calls: Mutex<Vec<(String, Value)>>,
    }

    impl MockTransport {
        fn new(responses: Vec<std::result::Result<Value, IdaError>>) -> Self {
            Self {
                responses: Mutex::new(responses.into()),
                calls: Mutex::new(Vec::new()),
            }
        }

        fn first_call_method(&self) -> Option<String> {
            let guard = self.calls.lock().ok()?;
            guard.first().map(|(method, _)| method.clone())
        }

        fn call_methods(&self) -> Vec<String> {
            if let Ok(guard) = self.calls.lock() {
                return guard.iter().map(|(method, _)| method.clone()).collect();
            }
            Vec::new()
        }
    }

    #[async_trait]
    impl Transport for MockTransport {
        async fn call(
            &self,
            method: &str,
            params: Value,
        ) -> Result<Value, endeavour_ida::IdaError> {
            if let Ok(mut calls) = self.calls.lock() {
                calls.push((method.to_string(), params));
            }

            let mut queue = self.responses.lock().map_err(|_| {
                endeavour_ida::IdaError::IdaResponseError("mock lock poisoned".to_string())
            })?;

            queue.pop_front().unwrap_or_else(|| {
                Err(endeavour_ida::IdaError::IdaResponseError(
                    "no mock response queued".to_string(),
                ))
            })
        }
    }

    #[test]
    fn connect_flow_uses_list_functions_with_mock_transport() {
        let runtime = Runtime::new();
        assert!(runtime.is_ok());
        let runtime = match runtime {
            Ok(value) => value,
            Err(err) => panic!("failed to create runtime: {err}"),
        };

        let mock = Arc::new(MockTransport::new(vec![Ok(json!([
            {
                "items": [
                    {"addr": "0x401000", "name": "sub_401000", "size": "0x10"}
                ],
                "cursor": {"done": true}
            }
        ]))]));

        let result = connect_with_transport(&runtime, "localhost:13337", mock.clone());
        assert!(result.is_ok());

        let method = mock.first_call_method();
        assert_eq!(method.as_deref(), Some("list_funcs"));

        let (client, functions) = match result {
            Ok(value) => value,
            Err(err) => panic!("unexpected error: {err}"),
        };

        let _typed: Arc<IdaClient> = client;
        assert_eq!(functions.len(), 1);
        assert_eq!(functions[0].name, "sub_401000");
    }

    #[test]
    fn connect_method_not_found_returns_ok_and_keeps_client_unset() {
        let tempdir = tempfile::tempdir();
        assert!(tempdir.is_ok());
        let tempdir = tempdir.unwrap_or_else(|_| unreachable!());

        let store = SessionStore::open(&tempdir.path().join("repl.db"));
        assert!(store.is_ok());
        let store = store.unwrap_or_else(|_| unreachable!());

        let mut repl = Repl::new(store);
        assert!(repl.is_ok());
        let mut repl = repl.unwrap_or_else(|_| unreachable!());

        let transport = Arc::new(
            MockIdaTransport::builder()
                .error("list_funcs", "", MockIdaError::MethodNotFound)
                .build(),
        );

        let result = repl.handle_connect_with_transport("localhost:13337", transport.clone());

        assert!(result.is_ok());
        assert!(repl.ida_client.is_none());
        assert_eq!(transport.calls_by_method("list_funcs"), 1);
    }

    #[test]
    fn connect_connection_refused_returns_ok_and_keeps_client_unset() {
        let tempdir = tempfile::tempdir();
        assert!(tempdir.is_ok());
        let tempdir = tempdir.unwrap_or_else(|_| unreachable!());

        let store = SessionStore::open(&tempdir.path().join("repl.db"));
        assert!(store.is_ok());
        let store = store.unwrap_or_else(|_| unreachable!());

        let mut repl = Repl::new(store);
        assert!(repl.is_ok());
        let mut repl = repl.unwrap_or_else(|_| unreachable!());

        let transport = Arc::new(
            MockIdaTransport::builder()
                .error("list_funcs", "", MockIdaError::Connection)
                .build(),
        );

        let result = repl.handle_connect_with_transport("localhost:13337", transport.clone());

        assert!(result.is_ok());
        assert!(repl.ida_client.is_none());
        assert_eq!(transport.calls_by_method("list_funcs"), 1);
    }

    #[test]
    fn decompile_output_renders_header_and_line_numbers() {
        let runtime = Runtime::new();
        assert!(runtime.is_ok());
        let runtime = match runtime {
            Ok(value) => value,
            Err(err) => panic!("failed to create runtime: {err}"),
        };

        let mock = Arc::new(MockTransport::new(vec![
            Ok(json!([
                {
                    "fn": {
                        "addr": "0x401000",
                        "name": "sub_401000",
                        "size": "0x20"
                    }
                }
            ])),
            Ok(json!({
                "addr": "0x401000",
                "code": "int x = 1;\nreturn x;"
            })),
        ]));

        let client = IdaClient::with_transport("127.0.0.1", 13337, mock.clone());
        let rendered = render_decompile_output(&runtime, &client, "sub_401000");
        assert!(rendered.is_ok());
        let rendered = match rendered {
            Ok(value) => value,
            Err(err) => panic!("unexpected error: {err}"),
        };

        assert!(rendered.contains("sub_401000 @ 0x00401000"));
        assert!(rendered.contains("   1 | int x = 1;"));
        assert!(rendered.contains("   2 | return x;"));

        assert_eq!(mock.call_methods(), vec!["lookup_funcs", "decompile"]);
    }

    #[test]
    fn search_command_fetches_and_renders_table() {
        let runtime = Runtime::new();
        assert!(runtime.is_ok());
        let runtime = match runtime {
            Ok(value) => value,
            Err(err) => panic!("failed to create runtime: {err}"),
        };

        let mock = Arc::new(MockTransport::new(vec![Ok(json!({
            "matches": [
                {"addr": "0x401000", "string": "objc_msgSend"},
                {"addr": "0x401010", "string": "NSLog"}
            ]
        }))]));
        let client = IdaClient::with_transport("127.0.0.1", 13337, mock.clone());

        let matches = fetch_search_results(&runtime, &client, "objc");
        assert!(matches.is_ok());
        let matches = match matches {
            Ok(value) => value,
            Err(err) => panic!("unexpected error: {err}"),
        };
        assert_eq!(matches.len(), 2);

        let rendered = render_search_output(&matches);
        assert!(rendered.contains("Address"));
        assert!(rendered.contains("String"));
        assert!(rendered.contains("objc_msgSend"));
        assert!(rendered.contains("NSLog"));

        assert_eq!(mock.first_call_method().as_deref(), Some("find_regex"));
    }

    #[test]
    fn callgraph_renders_tree_and_marks_recursive_edges() {
        let runtime = Runtime::new();
        assert!(runtime.is_ok());
        let runtime = match runtime {
            Ok(value) => value,
            Err(err) => panic!("failed to create runtime: {err}"),
        };

        let mock = Arc::new(MockTransport::new(vec![
            Ok(json!([
                {
                    "fn": {
                        "addr": "0x401000",
                        "name": "main",
                        "size": "0x30"
                    }
                }
            ])),
            Ok(json!({
                "edges": [
                    ["0x401000", "0x401100"],
                    ["0x401100", "0x401200"],
                    ["0x401200", "0x401000"],
                    ["0x401000", "0x402000"]
                ]
            })),
            Ok(json!([
                {
                    "fn": {
                        "addr": "0x401100",
                        "name": "sub_401100",
                        "size": "0x20"
                    }
                }
            ])),
            Ok(json!([
                {
                    "fn": {
                        "addr": "0x401200",
                        "name": "sub_401200",
                        "size": "0x20"
                    }
                }
            ])),
            Ok(json!([
                {
                    "fn": {
                        "addr": "0x402000",
                        "name": "objc_msgSend",
                        "size": "0x20"
                    }
                }
            ])),
        ]));

        let client = IdaClient::with_transport("127.0.0.1", 13337, mock.clone());
        let rendered = render_callgraph_output(&runtime, &client, "main", 3);
        assert!(rendered.is_ok());
        let rendered = match rendered {
            Ok(value) => value,
            Err(err) => panic!("unexpected error: {err}"),
        };

        assert!(rendered.contains("Call Graph: main @ 0x00401000 (depth=3)"));
        assert!(rendered.contains("sub_401100 @ 0x00401100"));
        assert!(rendered.contains("sub_401200 @ 0x00401200"));
        assert!(rendered.contains("[recursive]"));
        assert!(rendered.contains("objc_msgSend @ 0x00402000"));
        assert!(rendered.contains("├──") || rendered.contains("└──"));

        let methods = mock.call_methods();
        assert_eq!(methods.first().map(String::as_str), Some("lookup_funcs"));
        assert_eq!(methods.get(1).map(String::as_str), Some("callgraph"));
        assert_eq!(
            methods
                .iter()
                .filter(|method| method.as_str() == "lookup_funcs")
                .count(),
            4
        );
    }

    #[test]
    fn rename_symbol_calls_rename_method() {
        let runtime = Runtime::new();
        assert!(runtime.is_ok());
        let runtime = match runtime {
            Ok(value) => value,
            Err(err) => panic!("failed to create runtime: {err}"),
        };

        let mock = Arc::new(MockTransport::new(vec![Ok(
            json!({"func": [{"ok": true}]}),
        )]));
        let client = IdaClient::with_transport("127.0.0.1", 13337, mock.clone());

        let renamed = rename_symbol(&runtime, &client, 0x401000, "main");
        assert!(renamed.is_ok());
        assert_eq!(mock.first_call_method().as_deref(), Some("rename"));
    }

    #[test]
    fn set_symbol_comment_calls_set_comments_method() {
        let runtime = Runtime::new();
        assert!(runtime.is_ok());
        let runtime = match runtime {
            Ok(value) => value,
            Err(err) => panic!("failed to create runtime: {err}"),
        };

        let mock = Arc::new(MockTransport::new(vec![Ok(json!([{"ok": true}]))]));
        let client = IdaClient::with_transport("127.0.0.1", 13337, mock.clone());

        let commented = set_symbol_comment(&runtime, &client, 0x401000, "entry point");
        assert!(commented.is_ok());
        assert_eq!(mock.first_call_method().as_deref(), Some("set_comments"));
    }

    #[test]
    fn explain_flow_builds_prompt_and_renders_output() {
        let decompile = DecompileResult {
            address: 0x401000,
            pseudocode: "int parse(unsigned char *buf, int len) {\n  if (len < 4) return -1;\n  return buf[0];\n}".to_string(),
        };

        let request = build_explain_request("sub_401000", &decompile);
        assert_eq!(request.model, "claude-sonnet-4-5");

        let response = CompletionResponse {
            model: "test-model".to_string(),
            content: "This function parses a header, validates bounds, and dispatches by opcode. Suggested name: parse_packet.".to_string(),
            stop_reason: Some(StopReason::EndTurn),
            input_tokens: Some(100),
            output_tokens: Some(32),
            tool_calls: Vec::new(),
        };
        assert!(response.content.contains("Suggested name"));

        let rendered =
            render_explain_result("sub_401000", 0x401000, &response.model, &response.content);
        assert!(rendered.contains("Function Analysis: sub_401000 @ 0x00401000"));
        assert!(rendered.contains("Model: test-model"));
        assert!(rendered.contains("parses a header"));
    }

    #[test]
    fn missing_function_error_detection_matches_not_found_only() {
        assert!(is_missing_function_error(&IdaError::IdaResponseError(
            "Function not found".to_string()
        )));
        assert!(!is_missing_function_error(&IdaError::ConnectionError(
            "refused".to_string()
        )));
    }

    #[test]
    fn resolve_target_not_found_formats_no_function_message() {
        let runtime = Runtime::new();
        assert!(runtime.is_ok());
        let runtime = match runtime {
            Ok(value) => value,
            Err(err) => panic!("failed to create runtime: {err}"),
        };

        let mock = Arc::new(MockTransport::new(vec![Ok(json!([
            {
                "fn": null
            }
        ]))]));
        let client = IdaClient::with_transport("127.0.0.1", 13337, mock.clone());

        let target = "missing_symbol";
        let result = resolve_target_address(&runtime, &client, target);
        assert!(result.is_err());
        let err = match result {
            Ok(_) => panic!("expected resolve_target_address to fail"),
            Err(err) => err,
        };

        let message = format_resolve_target_error(target, &err);
        assert_eq!(message, "No function at address missing_symbol");
        assert_eq!(mock.first_call_method().as_deref(), Some("lookup_funcs"));
    }

    #[test]
    fn resolve_target_transport_error_preserves_context_message() {
        let runtime = Runtime::new();
        assert!(runtime.is_ok());
        let runtime = match runtime {
            Ok(value) => value,
            Err(err) => panic!("failed to create runtime: {err}"),
        };

        let mock = Arc::new(MockTransport::new(vec![Err(IdaError::IdaResponseError(
            "transport unavailable".to_string(),
        ))]));
        let client = IdaClient::with_transport("127.0.0.1", 13337, mock.clone());

        let target = "main";
        let result = resolve_target_address(&runtime, &client, target);
        assert!(result.is_err());
        let err = match result {
            Ok(_) => panic!("expected resolve_target_address to fail"),
            Err(err) => err,
        };

        let message = format_resolve_target_error(target, &err);
        assert!(message.contains("Failed to resolve target 'main'"));
        assert!(message.contains("failed to resolve function 'main'"));
        assert!(message.contains("IDA returned error: transport unavailable"));
        assert_eq!(mock.first_call_method().as_deref(), Some("lookup_funcs"));
    }
}
