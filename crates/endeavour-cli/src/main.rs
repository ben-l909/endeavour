use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use endeavour_core::store::SessionStore;
use endeavour_ida::IdaClient;
use tracing::info;
use uuid::Uuid;

pub mod fmt;
mod repl;

/// Endeavour Labs analysis CLI.
#[derive(Debug, Parser)]
#[command(name = "endeavour")]
#[command(version = env!("CARGO_PKG_VERSION"))]
#[command(about = "Endeavour Labs analysis CLI")]
struct Cli {
    #[arg(long, global = true, value_name = "PATH")]
    store_path: Option<PathBuf>,

    #[command(subcommand)]
    command: Option<Command>,
}

/// Supported top-level CLI commands.
#[derive(Debug, Subcommand)]
enum Command {
    /// Analyze a Mach-O binary.
    Analyze {
        /// Path to the binary file.
        path: PathBuf,
    },
    /// Manage analysis sessions.
    Sessions {
        #[command(subcommand)]
        command: Option<SessionsCommand>,
    },
    Repl,
    /// Connect to IDA Pro MCP.
    ConnectIda {
        /// MCP host in host:port format.
        #[arg(default_value = "localhost:13337")]
        host: String,
    },
}

/// Subcommands under `sessions`.
#[derive(Debug, Subcommand)]
enum SessionsCommand {
    List,
    /// Show details for a specific session.
    Show {
        /// Session UUID.
        id: String,
    },
}

fn main() -> Result<()> {
    tracing_subscriber::fmt::init();
    let cli = Cli::parse();
    dispatch(cli)
}

fn dispatch(cli: Cli) -> Result<()> {
    let Cli {
        store_path,
        command,
    } = cli;

    let store_path = resolve_store_path(store_path)?;

    match command {
        None | Some(Command::Repl) => handle_repl(store_path),
        Some(Command::Analyze { path }) => handle_analyze(path),
        Some(Command::Sessions { command: None }) => handle_sessions_list(store_path),
        Some(Command::Sessions {
            command: Some(SessionsCommand::List),
        }) => handle_sessions_list(store_path),
        Some(Command::Sessions {
            command: Some(SessionsCommand::Show { id }),
        }) => handle_sessions_show(store_path, id),
        Some(Command::ConnectIda { host }) => handle_connect_ida(host),
    }
}

fn handle_repl(store_path: PathBuf) -> Result<()> {
    info!(store_path = %store_path.display(), "starting repl mode");
    ensure_parent_dir(&store_path)?;

    let store = SessionStore::open(&store_path)
        .with_context(|| format!("failed to open store at {}", store_path.display()))?;

    let mut repl = repl::Repl::new(store)?;
    repl.run()
}

fn resolve_store_path(configured: Option<PathBuf>) -> Result<PathBuf> {
    match configured {
        Some(path) => Ok(path),
        None => Ok(default_endeavour_dir()?.join("store.db")),
    }
}

fn ensure_parent_dir(path: &Path) -> Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("failed to create directory {}", parent.display()))?;
    }
    Ok(())
}

fn default_endeavour_dir() -> Result<PathBuf> {
    let home = std::env::var_os("HOME").context("HOME environment variable is not set")?;
    let app_dir = PathBuf::from(home).join(".endeavour");
    std::fs::create_dir_all(&app_dir)
        .with_context(|| format!("failed to create directory {}", app_dir.display()))?;
    Ok(app_dir)
}

fn handle_analyze(path: PathBuf) -> Result<()> {
    info!(binary_path = %path.display(), "received analyze command");
    println!("analyze not implemented yet: {}", path.display());
    Ok(())
}

fn handle_sessions_list(store_path: PathBuf) -> Result<()> {
    info!("listing sessions");
    ensure_parent_dir(&store_path)?;

    let store = SessionStore::open(&store_path)
        .with_context(|| format!("failed to open store at {}", store_path.display()))?;
    let sessions = store.list_sessions().context("failed to list sessions")?;

    if sessions.is_empty() {
        println!("No sessions found.");
        return Ok(());
    }

    let mut table = fmt::Table::new(vec![
        fmt::Column::new("ID", 8, fmt::Align::Left),
        fmt::Column::new("Name", 24, fmt::Align::Left),
        fmt::Column::new("Binary", 8, fmt::Align::Left),
        fmt::Column::new("Created", 20, fmt::Align::Left),
        fmt::Column::new("Status", 6, fmt::Align::Left),
    ]);

    for session in sessions {
        let findings = store
            .get_findings(session.id)
            .with_context(|| format!("failed to fetch findings for session {}", session.id))?;
        let status = if findings.is_empty() {
            fmt::status_badge(fmt::Status::Info)
        } else {
            fmt::status_badge(fmt::Status::Pass)
        };
        table.add_row(vec![
            truncate_uuid(session.id),
            session.name,
            truncate_uuid(session.binary_id),
            session.created_at,
            status,
        ]);
    }

    println!("{}", table.render());
    Ok(())
}

fn handle_sessions_show(store_path: PathBuf, id: String) -> Result<()> {
    info!(session_id = %id, "showing session details");

    ensure_parent_dir(&store_path)?;

    let store = SessionStore::open(&store_path)
        .with_context(|| format!("failed to open store at {}", store_path.display()))?;

    let session_id = id
        .parse::<Uuid>()
        .with_context(|| format!("invalid session id: {id}"))?;
    let session = store
        .get_session(session_id)
        .with_context(|| format!("failed to load session {id}"))?;
    let findings = store
        .get_findings(session.id)
        .with_context(|| format!("failed to fetch findings for session {}", session.id))?;

    println!("Session: {}", session.name);
    println!("ID: {}", session.id);
    println!("Binary: {}", session.binary_id);
    println!("Created: {}", session.created_at);
    println!("Findings: {}", findings.len());
    Ok(())
}

fn truncate_uuid(id: Uuid) -> String {
    id.to_string().chars().take(8).collect()
}

fn handle_connect_ida(host: String) -> Result<()> {
    info!(host = %host, "connecting to ida mcp");

    let (host, port) = parse_host_port(&host)?;
    let endpoint = format!("{host}:{port}");
    let client = IdaClient::new(&host, port);
    let runtime = tokio::runtime::Runtime::new().context("failed to initialize tokio runtime")?;

    let functions = runtime
        .block_on(client.list_functions(None, Some(1)))
        .with_context(|| format!("failed to connect to IDA at {endpoint}"))?;

    save_ida_endpoint(&endpoint)?;

    if let Some(function) = functions.first() {
        println!(
            "Connected to IDA at {endpoint}. Sample function: {} @ 0x{:x}",
            function.name, function.address
        );
    } else {
        println!("Connected to IDA at {endpoint}. No functions returned.");
    }

    Ok(())
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
    let path = default_endeavour_dir()?.join("ida_endpoint");
    std::fs::write(&path, endpoint)
        .with_context(|| format!("failed to write IDA endpoint config at {}", path.display()))
}
