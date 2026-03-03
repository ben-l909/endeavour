use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use endeavour_core::store::SessionStore;
use endeavour_core::{loader, Session};
use reedline::{DefaultPrompt, DefaultPromptSegment, FileBackedHistory, Reedline, Signal};

const HISTORY_CAPACITY: usize = 500;

pub struct Repl {
    editor: Reedline,
    store: SessionStore,
    active_session: Option<Session>,
}

#[derive(Debug, PartialEq, Eq)]
enum ReplCommand {
    Help,
    Analyze(String),
    Sessions,
    Session(String),
    Info,
    Findings,
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
    pub fn new(store: SessionStore) -> Self {
        Self {
            editor: Reedline::create(),
            store,
            active_session: None,
        }
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
        let prompt_name = match &self.active_session {
            Some(session) => format!("[{}]", session.name),
            None => "endeavour".to_string(),
        };

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
        "sessions" => ParsedLine::Command(ReplCommand::Sessions),
        "session" => match tokens.next() {
            Some(id) => ParsedLine::Command(ReplCommand::Session(id.to_string())),
            None => ParsedLine::InvalidUsage("session <id>"),
        },
        "info" => ParsedLine::Command(ReplCommand::Info),
        "findings" => ParsedLine::Command(ReplCommand::Findings),
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
    println!("  sessions             List all sessions");
    println!("  session <id>         Switch active session");
    println!("  info                 Show active session info");
    println!("  findings             List findings in active session");
    println!("  quit | exit          Exit the REPL");
}

#[cfg(test)]
mod tests {
    use super::{parse_command, ParsedLine, ReplCommand};

    #[test]
    fn parse_analyze_command_with_path() {
        assert_eq!(
            parse_command("analyze foo.bin"),
            ParsedLine::Command(ReplCommand::Analyze("foo.bin".to_string()))
        );
    }
}
