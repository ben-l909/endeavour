use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::{collections::HashMap, collections::HashSet};

use crate::fmt;
use anyhow::{Context, Result};
use endeavour_core::config::Config;
use endeavour_core::store::SessionStore;
use endeavour_core::{loader, Session};
use endeavour_ida::{DecompileResult, IdaClient, Transport};
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

fn fetch_search_results(runtime: &Runtime, client: &IdaClient, pattern: &str) -> Result<Vec<(u64, String)>> {
    runtime
        .block_on(client.find_strings(pattern))
        .with_context(|| format!("failed to search strings for pattern '{pattern}'"))
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
        connect_with_transport, fetch_search_results, parse_command, parse_decompile_target,
        render_callgraph_output, render_decompile_output, render_search_output, ParsedLine,
        ReplCommand,
    };
    use std::collections::VecDeque;
    use std::sync::{Arc, Mutex};

    use async_trait::async_trait;
    use endeavour_ida::{IdaClient, IdaError, Transport};
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
}
