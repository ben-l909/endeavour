use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::{collections::HashMap, collections::HashSet};

use crate::fmt;
use anyhow::{Context, Result};
use endeavour_core::config::Config;
use endeavour_core::store::SessionStore;
use endeavour_core::{loader, Session};
use endeavour_ida::{DecompileResult, IdaClient, IdaError, Transport};
use endeavour_llm::{create_provider, CompletionRequest, CompletionResponse, LlmError, LlmProvider, Message, Role};
use reedline::{DefaultPrompt, DefaultPromptSegment, FileBackedHistory, Reedline, Signal};
use tokio::runtime::Runtime;

const HISTORY_CAPACITY: usize = 500;

pub struct Repl {
    editor: Reedline,
    store: SessionStore,
    active_session: Option<Session>,
    ida_client: Option<Arc<IdaClient>>,
    runtime: Runtime,
}

#[derive(Debug, PartialEq, Eq)]
enum ReplCommand {
    Help,
    Analyze(String),
    Connect(Option<String>),
    IdaStatus,
    Decompile(String),
    Explain(String),
    Rename(String, String),
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
    Quit,
}

#[derive(Debug, PartialEq, Eq)]
enum ParsedLine {
    Empty,
    Command(ReplCommand),
    Unknown(String),
    InvalidUsage(&'static str),
}

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
                        self.handle_analyze(&path)?;
                    }
                    ParsedLine::Command(ReplCommand::Connect(target)) => {
                        self.handle_connect(target.as_deref())?;
                    }
                    ParsedLine::Command(ReplCommand::IdaStatus) => {
                        self.handle_ida_status()?;
                    }
                    ParsedLine::Command(ReplCommand::Decompile(target)) => {
                        self.handle_decompile(&target);
                    }
                    ParsedLine::Command(ReplCommand::Explain(target)) => {
                        self.handle_explain(&target)?;
                    }
                    ParsedLine::Command(ReplCommand::Rename(target, new_name)) => {
                        self.handle_rename(&target, &new_name)?;
                    }
                    ParsedLine::Command(ReplCommand::Comment(target, comment)) => {
                        self.handle_comment(&target, &comment)?;
                    }
                    ParsedLine::Command(ReplCommand::Callgraph(target, max_depth)) => {
                        self.handle_callgraph(&target, max_depth)?;
                    }
                    ParsedLine::Command(ReplCommand::Search(pattern)) => {
                        self.handle_search(&pattern)?;
                    }
                    ParsedLine::Command(ReplCommand::Sessions) => {
                        self.handle_sessions()?;
                    }
                    ParsedLine::Command(ReplCommand::Session(id)) => {
                        self.handle_session_switch(&id)?;
                    }
                    ParsedLine::Command(ReplCommand::Info) => {
                        self.handle_info()?;
                    }
                    ParsedLine::Command(ReplCommand::Findings) => {
                        self.handle_findings()?;
                    }
                    ParsedLine::Command(ReplCommand::CacheStats) => {
                        self.handle_cache_stats()?;
                    }
                    ParsedLine::Command(ReplCommand::CacheClear) => {
                        self.handle_cache_clear()?;
                    }
                    ParsedLine::Command(ReplCommand::ConfigSet { key, value }) => {
                        self.handle_config_set(&key, &value)?;
                    }
                    ParsedLine::Command(ReplCommand::ConfigGet(key)) => {
                        self.handle_config_get(&key)?;
                    }
                    ParsedLine::Command(ReplCommand::ConfigList) => {
                        self.handle_config_list()?;
                    }
                    ParsedLine::Command(ReplCommand::Quit) => break,
                    ParsedLine::Unknown(cmd) => {
                        println!("Unknown command: {cmd}. Type 'help' for available commands.");
                    }
                    ParsedLine::InvalidUsage(usage) => {
                        println!("Usage: {usage}");
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
        let normalized_endpoint = format!("{host}:{port}");

        let (client, functions) = connect_with_transport(
            &self.runtime,
            &normalized_endpoint,
            Arc::new(endeavour_ida::HttpTransport::new(&host, port)),
        )?;

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

        let (address, function_name) = match resolve_target_address(&self.runtime, client.as_ref(), target) {
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
                    let _ = self.store.cache_ida_result(id, "decompile", address, &serialized);
                }
            }

            fetched
        };

        println!("{}", render_decompile_result(&function_name, &result));
    }

    fn handle_explain(&self, target: &str) -> Result<()> {
        let Some(client) = self.ida_client.as_ref() else {
            println!("Not connected. Run: connect <host:port>");
            return Ok(());
        };

        let (address, function_name) = match resolve_target_address(&self.runtime, client.as_ref(), target) {
            Ok(value) => value,
            Err(err) => {
                println!("Failed to resolve target '{target}': {err}");
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
        let api_key_hint = explain_api_key_hint(&config);
        if !has_llm_api_key(&config) {
            println!("No API key configured. Run: {api_key_hint}");
            return Ok(());
        }

        let provider = match create_provider(&config) {
            Ok(provider) => provider,
            Err(LlmError::AuthFailed) => {
                println!("LLM provider authentication failed. Check your API key with: {api_key_hint}");
                return Ok(());
            }
            Err(err) => {
                println!("Failed to initialize LLM provider: {}", format_llm_error(&err));
                return Ok(());
            }
        };

        let request = build_explain_request(&config, &function_name, &decompile_result);
        let response = match complete_explain_request(&self.runtime, provider.as_ref(), request) {
            Ok(value) => value,
            Err(err) => {
                println!("Explain request failed: {}", format_llm_error(&err));
                return Ok(());
            }
        };

        println!("{}", render_explain_result(&function_name, address, &response.content));
        Ok(())
    }

    fn handle_rename(&self, target: &str, new_name: &str) -> Result<()> {
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
        "explain" => match tokens.next() {
            Some(target) => ParsedLine::Command(ReplCommand::Explain(target.to_string())),
            None => ParsedLine::InvalidUsage("explain <addr>"),
        },
        "rename" => {
            let Some(target) = tokens.next() else {
                return ParsedLine::InvalidUsage("rename <addr> <new_name>");
            };

            let Some(new_name) = tokens.next() else {
                return ParsedLine::InvalidUsage("rename <addr> <new_name>");
            };

            if tokens.next().is_some() {
                ParsedLine::InvalidUsage("rename <addr> <new_name>")
            } else {
                ParsedLine::Command(ReplCommand::Rename(target.to_string(), new_name.to_string()))
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
                ParsedLine::Command(ReplCommand::Comment(target.to_string(), comment_tokens.join(" ")))
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
            Some("stats") if tokens.next().is_none() => ParsedLine::Command(ReplCommand::CacheStats),
            Some("clear") if tokens.next().is_none() => ParsedLine::Command(ReplCommand::CacheClear),
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
    matches!(key, "anthropic-api-key" | "anthropic_api_key" | "openai-api-key" | "openai_api_key")
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
    let path = PathBuf::from(std::env::var_os("HOME").context("HOME environment variable is not set")?)
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
    println!("  explain <addr>       Analyze function behavior with LLM");
    println!("  rename <addr> <new_name>  Rename function at address");
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
    println!("  quit | exit          Exit the REPL");
}

#[cfg(test)]
fn render_decompile_output(runtime: &Runtime, client: &IdaClient, target: &str) -> Result<String> {
    let (address, function_name) = resolve_target_address(runtime, client, target)?;
    let result = runtime.block_on(client.decompile(address))?;

    Ok(render_decompile_result(&function_name, &result))
}

fn render_decompile_result(function_name: &str, result: &DecompileResult) -> String {
    let mut lines = vec![
        fmt::h2(format!("{} @ {}", function_name, fmt::format_addr(result.address))),
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

fn build_explain_request(config: &Config, function_name: &str, result: &DecompileResult) -> CompletionRequest {
    let system_prompt = "You are an expert reverse engineer analyzing decompiled code. Explain what this function does, identify key behaviors, potential vulnerabilities, and suggest meaningful names for the function and its variables.";
    let user_prompt = format!(
        "Analyze function {function_name} at {address}.\n\nDecompiled pseudocode:\n```c\n{pseudocode}\n```",
        address = fmt::format_addr(result.address),
        pseudocode = result.pseudocode
    );

    CompletionRequest {
        model: default_explain_model(config).to_string(),
        messages: vec![
            Message {
                role: Role::System,
                content: system_prompt.to_string(),
            },
            Message {
                role: Role::User,
                content: user_prompt,
            },
        ],
        max_tokens: Some(1_200),
        temperature: Some(0.1),
    }
}

fn default_explain_model(config: &Config) -> &'static str {
    match config.default_provider.as_deref() {
        Some("openai") => "gpt-4o-mini",
        Some("anthropic") => "claude-3-5-sonnet-20241022",
        _ if config.anthropic_api_key.is_some() => "claude-3-5-sonnet-20241022",
        _ => "gpt-4o-mini",
    }
}

fn complete_explain_request(
    runtime: &Runtime,
    provider: &dyn LlmProvider,
    request: CompletionRequest,
) -> std::result::Result<CompletionResponse, LlmError> {
    runtime.block_on(provider.complete(request))
}

fn render_explain_result(function_name: &str, address: u64, analysis: &str) -> String {
    let title = format!("Function Analysis: {function_name} @ {}", fmt::format_addr(address));
    let body = if analysis.trim().is_empty() {
        "(No analysis text returned.)"
    } else {
        analysis.trim()
    };

    [
        fmt::h2(title),
        fmt::separator(fmt::Separator::Standard, 88),
        body.to_string(),
        fmt::separator(fmt::Separator::Standard, 88),
    ]
    .join("\n")
}

fn render_callgraph_output(runtime: &Runtime, client: &IdaClient, target: &str, depth: u32) -> Result<String> {
    let (root_addr, root_name) = resolve_target_address(runtime, client, target)?;
    let edges = runtime
        .block_on(client.call_graph(root_addr, Some(depth)))
        .with_context(|| format!("failed to fetch call graph for {}", fmt::format_addr(root_addr)))?;

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
    let mut lines = vec![header.clone(), fmt::separator(fmt::Separator::Standard, header.chars().count())];

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

        lines.push(format!("{prefix}{branch}{name} @ {}", fmt::format_addr(*child)));

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

fn resolve_target_address(runtime: &Runtime, client: &IdaClient, target: &str) -> Result<(u64, String)> {
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
    if let Some(hex) = input.strip_prefix("0x").or_else(|| input.strip_prefix("0X")) {
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

fn has_llm_api_key(config: &Config) -> bool {
    config.anthropic_api_key.is_some() || config.openai_api_key.is_some()
}

fn explain_api_key_hint(config: &Config) -> String {
    match config.default_provider.as_deref() {
        Some("anthropic") => "config set anthropic_api_key <key>".to_string(),
        Some("openai") => "config set openai_api_key <key>".to_string(),
        _ => {
            "config set anthropic_api_key <key> or config set openai_api_key <key>".to_string()
        }
    }
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

fn fetch_search_results(runtime: &Runtime, client: &IdaClient, pattern: &str) -> Result<Vec<(u64, String)>> {
    runtime
        .block_on(client.find_strings(pattern))
        .with_context(|| format!("failed to search strings for pattern '{pattern}'"))
}

fn rename_symbol(runtime: &Runtime, client: &IdaClient, addr: u64, new_name: &str) -> Result<()> {
    runtime
        .block_on(client.rename_function(addr, new_name))
        .with_context(|| format!("failed to rename function at {}", fmt::format_addr(addr)))
}

fn set_symbol_comment(runtime: &Runtime, client: &IdaClient, addr: u64, comment: &str) -> Result<()> {
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
        build_explain_request, complete_explain_request, connect_with_transport,
        explain_api_key_hint, fetch_search_results, is_missing_function_error, parse_command, parse_decompile_target,
        rename_symbol, resolve_target_address, set_symbol_comment,
        format_resolve_target_error,
        render_callgraph_output, render_decompile_output, render_explain_result,
        render_search_output, ParsedLine, ReplCommand,
    };
    use std::collections::VecDeque;
    use std::sync::{Arc, Mutex};

    use async_trait::async_trait;
    use endeavour_core::config::Config;
    use endeavour_ida::{DecompileResult, IdaClient, IdaError, Transport};
    use endeavour_llm::mock::{MockProvider, MockResponse};
    use endeavour_llm::CompletionResponse;
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
            ParsedLine::Command(ReplCommand::Explain("0x401000".to_string()))
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
            ParsedLine::Command(ReplCommand::Rename("0x401000".to_string(), "main".to_string()))
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
            ParsedLine::InvalidUsage("rename <addr> <new_name>")
        );
        assert_eq!(
            parse_command("comment 0x401000"),
            ParsedLine::InvalidUsage("comment <addr> <text...>")
        );
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
        async fn call(&self, method: &str, params: Value) -> Result<Value, endeavour_ida::IdaError> {
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
            methods.iter().filter(|method| method.as_str() == "lookup_funcs").count(),
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

        let mock = Arc::new(MockTransport::new(vec![Ok(json!({"func": [{"ok": true}]}))]));
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
    fn explain_flow_uses_mock_provider_and_renders_output() {
        let runtime = Runtime::new();
        assert!(runtime.is_ok());
        let runtime = match runtime {
            Ok(value) => value,
            Err(err) => panic!("failed to create runtime: {err}"),
        };

        let provider = MockProvider::new(vec![MockResponse::Completion(Ok(CompletionResponse {
            model: "test-model".to_string(),
            content: "This function parses a header, validates bounds, and dispatches by opcode. Suggested name: parse_packet.".to_string(),
            stop_reason: Some("stop".to_string()),
            input_tokens: Some(100),
            output_tokens: Some(32),
        }))]);

        let config = Config {
            anthropic_api_key: Some("sk-ant-test".to_string()),
            openai_api_key: None,
            default_provider: Some("anthropic".to_string()),
        };

        let decompile = DecompileResult {
            address: 0x401000,
            pseudocode: "int parse(unsigned char *buf, int len) {\n  if (len < 4) return -1;\n  return buf[0];\n}".to_string(),
        };

        let request = build_explain_request(&config, "sub_401000", &decompile);
        let response = complete_explain_request(&runtime, &provider, request);
        assert!(response.is_ok());
        let response = match response {
            Ok(value) => value,
            Err(err) => panic!("unexpected llm error: {err}"),
        };
        assert!(response.content.contains("Suggested name"));

        let rendered = render_explain_result("sub_401000", 0x401000, &response.content);
        assert!(rendered.contains("Function Analysis: sub_401000 @ 0x00401000"));
        assert!(rendered.contains("parses a header"));
    }

    #[test]
    fn explain_api_key_hint_uses_default_provider() {
        let config = Config {
            anthropic_api_key: None,
            openai_api_key: None,
            default_provider: Some("openai".to_string()),
        };

        assert_eq!(explain_api_key_hint(&config), "config set openai_api_key <key>");
    }

    #[test]
    fn explain_api_key_hint_without_default_provider_lists_both() {
        let config = Config::default();

        assert_eq!(
            explain_api_key_hint(&config),
            "config set anthropic_api_key <key> or config set openai_api_key <key>"
        );
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
