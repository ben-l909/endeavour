use std::io::IsTerminal;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use crate::commands;
use anyhow::{Context, Result};
use clap::Parser;
use endeavour_core::store::SessionStore;
use endeavour_core::Session;
use endeavour_ida::IdaClient;
use reedline::{DefaultPrompt, DefaultPromptSegment, FileBackedHistory, Reedline, Signal};
use tokio::runtime::Runtime;

const HISTORY_CAPACITY: usize = 500;

pub(crate) struct Repl {
    pub(crate) editor: Reedline,
    pub(crate) store: SessionStore,
    pub(crate) active_session: Option<Session>,
    pub(crate) ida_client: Option<Arc<IdaClient>>,
    pub(crate) runtime: Runtime,
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
    SessionNew,
    SessionCommandError(String),
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
pub(crate) struct ExplainCommand {
    pub(crate) target: String,
    #[arg(long, default_value = "auto")]
    pub(crate) provider: String,
    #[arg(long)]
    pub(crate) no_fallback: bool,
}

#[derive(Debug, Clone, Parser, PartialEq, Eq)]
pub(crate) struct RenameCommand {
    pub(crate) target: Option<String>,
    pub(crate) new_name: Option<String>,
    #[arg(long, default_value_t = false)]
    pub(crate) llm: bool,
    #[arg(long, default_value_t = false)]
    pub(crate) all: bool,
    #[arg(long, default_value = "auto")]
    pub(crate) provider: String,
    #[arg(long)]
    pub(crate) no_fallback: bool,
}

#[derive(Debug, Clone, Parser, PartialEq, Eq)]
pub(crate) struct ShowTranscriptCommand {
    pub(crate) session_id: Option<String>,
    #[arg(long)]
    pub(crate) turn: Option<u32>,
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

        if !std::io::stdin().is_terminal() {
            return self.run_scripted();
        }

        loop {
            let prompt = self.prompt();
            match self
                .editor
                .read_line(&prompt)
                .context("failed to read REPL input")?
            {
                Signal::Success(buffer) => {
                    if self.dispatch_line(parse_command(buffer.trim())) {
                        break;
                    }
                }
                Signal::CtrlC => {}
                Signal::CtrlD => break,
            }
        }

        Ok(())
    }

    fn run_scripted(&mut self) -> Result<()> {
        let stdin = std::io::stdin();
        let mut line = String::new();
        loop {
            line.clear();
            let bytes = stdin
                .read_line(&mut line)
                .context("failed to read REPL input")?;
            if bytes == 0 {
                break;
            }
            if self.dispatch_line(parse_command(line.trim())) {
                break;
            }
        }
        Ok(())
    }

    fn dispatch_line(&mut self, parsed: ParsedLine) -> bool {
        match parsed {
            ParsedLine::Empty => {}
            ParsedLine::Command(ReplCommand::Help) => print_help(),
            ParsedLine::Command(ReplCommand::Analyze(path)) => {
                if let Err(e) = commands::handle_analyze(self, &path) {
                    eprintln!("✗ error: {e}");
                }
            }
            ParsedLine::Command(ReplCommand::Connect(target)) => {
                if let Err(e) = commands::handle_connect(self, target.as_deref()) {
                    eprintln!("✗ error: {e}");
                }
            }
            ParsedLine::Command(ReplCommand::IdaStatus) => {
                if let Err(e) = commands::handle_ida_status(self) {
                    eprintln!("✗ error: {e}");
                }
            }
            ParsedLine::Command(ReplCommand::Decompile(target)) => {
                commands::handle_decompile(self, &target);
            }
            ParsedLine::Command(ReplCommand::Explain(command)) => {
                if let Err(e) = commands::handle_explain(self, &command) {
                    eprintln!("✗ error: {e}");
                }
            }
            ParsedLine::Command(ReplCommand::Rename(command)) => {
                if let Err(e) = commands::handle_rename(self, &command) {
                    eprintln!("✗ error: {e}");
                }
            }
            ParsedLine::Command(ReplCommand::Review) => {
                if let Err(e) = commands::handle_review(self) {
                    eprintln!("✗ error: {e}");
                }
            }
            ParsedLine::Command(ReplCommand::Comment(target, comment)) => {
                if let Err(e) = commands::handle_comment(self, &target, &comment) {
                    eprintln!("✗ error: {e}");
                }
            }
            ParsedLine::Command(ReplCommand::Callgraph(target, max_depth)) => {
                if let Err(e) = commands::handle_callgraph(self, &target, max_depth) {
                    eprintln!("✗ error: {e}");
                }
            }
            ParsedLine::Command(ReplCommand::Search(pattern)) => {
                if let Err(e) = commands::handle_search(self, &pattern) {
                    eprintln!("✗ error: {e}");
                }
            }
            ParsedLine::Command(ReplCommand::Sessions) => {
                if let Err(e) = commands::handle_sessions(self) {
                    eprintln!("✗ error: {e}");
                }
            }
            ParsedLine::Command(ReplCommand::Session(id)) => {
                if let Err(e) = commands::handle_session_switch(self, &id) {
                    eprintln!("✗ error: {e}");
                }
            }
            ParsedLine::Command(ReplCommand::SessionNew) => {
                if let Err(e) = commands::handle_session_new(self) {
                    eprintln!("✗ error: {e}");
                }
            }
            ParsedLine::Command(ReplCommand::SessionCommandError(subcommand)) => {
                println!("✗ error: unknown session subcommand '{subcommand}'");
                println!("    ╰─ valid subcommands: new, list, load <id>, info");
            }
            ParsedLine::Command(ReplCommand::Info) => {
                if let Err(e) = commands::handle_info(self) {
                    eprintln!("✗ error: {e}");
                }
            }
            ParsedLine::Command(ReplCommand::Findings) => {
                if let Err(e) = commands::handle_findings(self) {
                    eprintln!("✗ error: {e}");
                }
            }
            ParsedLine::Command(ReplCommand::CacheStats) => {
                if let Err(e) = commands::handle_cache_stats(self) {
                    eprintln!("✗ error: {e}");
                }
            }
            ParsedLine::Command(ReplCommand::CacheClear) => {
                if let Err(e) = commands::handle_cache_clear(self) {
                    eprintln!("✗ error: {e}");
                }
            }
            ParsedLine::Command(ReplCommand::ConfigSet { key, value }) => {
                if let Err(e) = commands::handle_config_set(self, &key, &value) {
                    eprintln!("✗ error: {e}");
                }
            }
            ParsedLine::Command(ReplCommand::ConfigGet(key)) => {
                if let Err(e) = commands::handle_config_get(self, &key) {
                    eprintln!("✗ error: {e}");
                }
            }
            ParsedLine::Command(ReplCommand::ConfigList) => {
                if let Err(e) = commands::handle_config_list(self) {
                    eprintln!("✗ error: {e}");
                }
            }
            ParsedLine::Command(ReplCommand::ShowTranscript(command)) => {
                if let Err(e) = commands::handle_show_transcript(self, &command) {
                    eprintln!("✗ error: {e}");
                }
            }
            ParsedLine::Command(ReplCommand::Quit) => return true,
            ParsedLine::Unknown(cmd) => {
                println!("Unknown command: {cmd}. Type 'help' for available commands.");
            }
            ParsedLine::InvalidUsage(usage) => {
                println!("Usage: {usage}");
            }
        }

        false
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
        "session" => {
            let Some(subcommand) = tokens.next() else {
                return ParsedLine::InvalidUsage("session <new|list|load|info> ...");
            };

            match subcommand {
                "new" if tokens.next().is_none() => ParsedLine::Command(ReplCommand::SessionNew),
                "list" if tokens.next().is_none() => ParsedLine::Command(ReplCommand::Sessions),
                "load" => match (tokens.next(), tokens.next()) {
                    (Some(id), None) => ParsedLine::Command(ReplCommand::Session(id.to_string())),
                    _ => ParsedLine::InvalidUsage("session load <id>"),
                },
                "info" if tokens.next().is_none() => ParsedLine::Command(ReplCommand::Info),
                candidate if tokens.next().is_none() => {
                    if uuid::Uuid::parse_str(candidate).is_ok() {
                        ParsedLine::Command(ReplCommand::Session(candidate.to_string()))
                    } else {
                        ParsedLine::Command(ReplCommand::SessionCommandError(candidate.to_string()))
                    }
                }
                other => ParsedLine::Command(ReplCommand::SessionCommandError(other.to_string())),
            }
        }
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
    println!("  session new          Create a new session (guided)");
    println!("  session list         List all sessions");
    println!("  session load <id>    Switch active session");
    println!("  session info         Show active session info");
    println!("  info                 Alias for session info");
    println!("  findings             List findings in active session");
    println!("  cache stats          Show IDA cache stats for active session");
    println!("  cache clear          Clear IDA cache for active session");
    println!("  config set <k> <v>   Set config value in ~/.endeavour/config.toml");
    println!("  config get <k>       Get config value (API keys masked)");
    println!("  config list          List config keys and masked values");
    println!("  show-transcript [session_id] [--turn <n>]  Show stored agentic transcript");
    println!("  quit | exit          Exit the REPL");
}

#[cfg(test)]
mod tests {
    use super::parse_command;
    use super::{ExplainCommand, ParsedLine, RenameCommand, ReplCommand, ShowTranscriptCommand};

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
}
