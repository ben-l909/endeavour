use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use endeavour_core::store::SessionStore;
use tracing::info;

mod repl;
pub mod fmt;

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
        Some(Command::Sessions { command: None }) => handle_sessions_list(),
        Some(Command::Sessions {
            command: Some(SessionsCommand::Show { id }),
        }) => handle_sessions_show(id),
        Some(Command::ConnectIda { host }) => handle_connect_ida(host),
    }
}

fn handle_repl(store_path: PathBuf) -> Result<()> {
    info!(store_path = %store_path.display(), "starting repl mode");
    ensure_parent_dir(&store_path)?;

    let store = SessionStore::open(&store_path)
        .with_context(|| format!("failed to open store at {}", store_path.display()))?;

    let mut repl = repl::Repl::new(store);
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

fn handle_sessions_list() -> Result<()> {
    info!("listing sessions");
    println!("sessions list not implemented yet");
    Ok(())
}

fn handle_sessions_show(id: String) -> Result<()> {
    info!(session_id = %id, "showing session details");
    println!("session show not implemented yet: {id}");
    Ok(())
}

fn handle_connect_ida(host: String) -> Result<()> {
    info!(host = %host, "connecting to ida mcp");
    println!("connect-ida not implemented yet: {host}");
    Ok(())
}
